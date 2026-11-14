//! 调试会话：attach/flash/断点/栈/变量，复用嵌入式调试器的核心库

use embedded_debugger_lib::cfi;
use embedded_debugger_lib::debuginfo::{load_elf, DebugInfo};
use embedded_debugger_lib::stepper;
use embedded_debugger_lib::variables::{self, LocalLoc, TypeKind};
use probe_rs::config::{Registry, TargetSelector};
use probe_rs::flashing::{download_file_with_options, DownloadOptions, ElfLoader, ElfOptions};
use probe_rs::{CoreInterface, CoreStatus, MemoryInterface, Permissions, Session};
use serde_json::{json, Value};
use std::io::Write;

/// 一个调试目标
pub struct Target {
    /// None 仅出现在 ed/bridge 请求把 Session 临时移入 AppState 的窗口期
    pub session: Option<Session>,
    /// launch 配置的芯片名（webview 桥接构建 AppState 用）
    pub chip: String,
    pub debug: Option<DebugInfo>,
    /// (file, line, addr)
    pub bps: Vec<(String, u32, u64)>,
    /// webview 桥接请求间持久的状态（RTT 会话、数据观察点）
    pub rtt: Option<probe_rs::rtt::Rtt>,
    pub watchpoints: Vec<embedded_debugger_lib::state::WpInfo>,
}

pub struct LaunchArgs {
    pub chip: String,
    pub elf: String,
    pub flash: bool,
    pub probe_index: usize,
    /// 探针序列号（优先于 probeIndex，多探针时用）
    pub probe_serial: Option<String>,
}

impl LaunchArgs {
    pub fn from_value(v: &Value) -> Result<Self, String> {
        Ok(Self {
            chip: v
                .get("chip")
                .and_then(|x| x.as_str())
                .ok_or("缺少 chip（芯片型号）")?
                .to_string(),
            elf: v.get("elf").and_then(|x| x.as_str()).unwrap_or("").to_string(),
            flash: v.get("flash").and_then(|x| x.as_bool()).unwrap_or(true),
            probe_index: v.get("probeIndex").and_then(|x| x.as_u64()).unwrap_or(0) as usize,
            probe_serial: v
                .get("probeSerial")
                .and_then(|x| x.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string()),
        })
    }
}

/// 与桌面版共用同一份自定义芯片目录（导入过的 .pack 描述两边通用）
fn registry_with_custom() -> Registry {
    let mut reg = Registry::from_builtin_families();
    if let Ok(appdata) = std::env::var("APPDATA") {
        let dir = std::path::Path::new(&appdata)
            .join("com.embedded.debugger")
            .join("custom-targets");
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for e in entries.flatten() {
                let p = e.path();
                if p.extension().is_some_and(|x| x == "yaml" || x == "yml") {
                    if let Ok(yaml) = std::fs::read_to_string(&p) {
                        let _ = reg.add_target_family_from_yaml(&yaml);
                    }
                }
            }
        }
    }
    reg
}

/// 列出当前连接的调试探针
pub fn list_probes() -> Vec<Value> {
    let lister = probe_rs::probe::list::Lister::new();
    lister
        .list_all()
        .iter()
        .enumerate()
        .map(|(i, p)| {
            json!({
                "index": i,
                "identifier": p.identifier,
                "serial": p.serial_number,
                "vid": p.vendor_id,
                "pid": p.product_id,
            })
        })
        .collect()
}

/// STM32 DBGMCU_IDCODE 的 DEV_ID → 系列名
fn stm32_family(dev_id: u32) -> Option<&'static str> {
    Some(match dev_id {
        0x413 => "STM32F405/407/415/417",
        0x419 => "STM32F42x/F43x",
        0x421 => "STM32F446",
        0x434 => "STM32F469/479",
        0x449 => "STM32F74x/75x",
        0x451 => "STM32F76x/77x",
        0x452 => "STM32F72x/73x",
        0x463 => "STM32F413/423",
        0x441 => "STM32F412",
        0x458 => "STM32F410",
        0x431 => "STM32F411",
        0x433 => "STM32F401xD/E",
        0x423 => "STM32F401xB/C",
        0x422 => "STM32F30x/F31x",
        0x432 => "STM32F37x/F38x",
        0x446 => "STM32F303xD/E",
        0x438 => "STM32F303x6/8",
        0x439 => "STM32F301/302/358",
        0x410 => "STM32F10x 大容量",
        0x414 => "STM32F10x 超大容量",
        0x400 => "STM32F10x 中容量",
        0x412 => "STM32F10x 小容量",
        0x418 => "STM32F105/107",
        0x420 | 0x428 => "STM32F100",
        0x415 => "STM32L47x/48x",
        0x461 => "STM32L49x/4Ax",
        0x435 => "STM32L43x/44x",
        0x462 => "STM32L45x/46x",
        0x464 => "STM32L41x/42x",
        0x470 | 0x472 => "STM32L4Rx/4Sx",
        0x417 => "STM32L0x2/0x3",
        0x447 => "STM32L0x0/0x1",
        0x450 => "STM32H743/750/753",
        0x480 => "STM32H7A3/7B3",
        0x483 => "STM32H72x/73x",
        0x468 => "STM32G431/441",
        0x469 => "STM32G47x/48x",
        0x460 => "STM32G07x/08x",
        0x466 => "STM32G03x/04x",
        0x467 => "STM32G0Bx/0Cx",
        _ => return None,
    })
}

/// 识别芯片：连上后读 DBGMCU_IDCODE（0xE0042000），给出 DEV_ID / 版本 / 系列
///
/// 三种结果要分开，界面才能给出对应提示：
/// - 连接/读取失败 → Err（探针或芯片问题）
/// - 读到 0 或全 1   → recognized=false，reason=no-idcode
/// - DEV_ID 不在表里 → recognized=false，reason=unknown-dev-id（但会带上 DEV_ID 供用户手动选）
pub fn identify_chip(cfg: &LaunchArgs) -> Result<Value, String> {
    let mut t = attach(cfg)?;
    let idcode = read_u32(&mut t, 0xE004_2000).unwrap_or(0);
    let dev_id = idcode & 0xFFF;
    let rev_id = idcode >> 16;
    let family = stm32_family(dev_id);
    let (recognized, reason) = if idcode == 0 || idcode == 0xFFFF_FFFF {
        (false, Some("no-idcode"))
    } else if family.is_none() {
        (false, Some("unknown-dev-id"))
    } else {
        (true, None)
    };
    Ok(json!({
        "chip": cfg.chip,
        "idcode": format!("0x{idcode:08X}"),
        "devId": dev_id,
        "devIdHex": format!("0x{dev_id:03X}"),
        "revId": rev_id,
        "family": family,
        "recognized": recognized,
        "reason": reason,
    }))
}

/// 列出芯片库（内置 + 导入的自定义芯片），供界面手动选择
pub fn list_chips(query: &str) -> Vec<Value> {
    let reg = registry_with_custom();
    let q = query.to_lowercase();
    let mut out: Vec<Value> = Vec::new();
    let mut families: Vec<_> = reg.families().iter().collect();
    families.sort_by(|a, b| a.name.cmp(&b.name));
    for fam in families {
        let mut variants: Vec<&str> = fam.variants.iter().map(|c| c.name.as_str()).collect();
        variants.sort();
        for name in variants {
            if !q.is_empty() && !name.to_lowercase().contains(&q) {
                continue;
            }
            out.push(json!({ "name": name, "family": fam.name }));
        }
    }
    out
}

/// 整片擦除（烧录前的兜底手段，也可用来恢复写坏的 Flash）
pub fn erase_chip(cfg: &LaunchArgs) -> Result<(), String> {
    let mut t = attach(cfg)?;
    let mut progress = probe_rs::flashing::FlashProgress::empty();
    probe_rs::flashing::erase_all(t.session.as_mut().ok_or("未连接目标")?, &mut progress, false)
        .map_err(|e| format!("擦除失败: {e}"))
}

/// 只烧录：烧完复位运行，不进入调试
pub fn flash_only(cfg: &LaunchArgs) -> Result<(), String> {
    let mut t = attach(cfg)?;
    reset_and_run(&mut t)?;
    Ok(())
}

/// 恢复：复位保持下握手再释放，用于目标进入低功耗/跑飞后 SWD 不响应
pub fn recover(serial: Option<String>) -> Result<Value, String> {
    let lister = probe_rs::probe::list::Lister::new();
    let probes = lister.list_all();
    if probes.is_empty() {
        return Err("未找到调试探针（请检查 USB 连接）".into());
    }
    let idx = match &serial {
        Some(s) => probes
            .iter()
            .position(|p| p.serial_number.as_deref() == Some(s.as_str()))
            .ok_or_else(|| format!("找不到序列号为 {s} 的调试探针"))?,
        None => 0,
    };
    let info = &probes[idx];
    let mut dev = info.open().map_err(|e| format!("打开探针失败: {e}"))?;
    let _ = dev.set_speed(1000);
    dev.attach_to_unspecified_under_reset()
        .map_err(|e| format!("复位下握手失败: {e:?}"))?;
    let _ = dev.detach();
    Ok(json!({ "probe": info.identifier, "serial": info.serial_number, "recovered": true }))
}

/// 只做 SWD 握手（attach_to_unspecified），不解析目标芯片，用来区分
/// 「探针/接线问题」和「芯片型号描述问题」
pub fn dp_check(serial: Option<String>) -> Result<Value, String> {
    let lister = probe_rs::probe::list::Lister::new();
    let probes = lister.list_all();
    if probes.is_empty() {
        return Err("未找到调试探针（请检查 USB 连接）".into());
    }
    let idx = match &serial {
        Some(s) => probes
            .iter()
            .position(|p| p.serial_number.as_deref() == Some(s.as_str()))
            .ok_or_else(|| format!("找不到序列号为 {s} 的调试探针"))?,
        None => 0,
    };
    let info = &probes[idx];
    let mut dev = info.open().map_err(|e| format!("打开探针失败: {e}"))?;
    let speed = dev.set_speed(1000).ok();
    dev.attach_to_unspecified()
        .map_err(|e| format!("SWD 握手失败: {e}"))?;
    Ok(json!({ "probe": info.identifier, "serial": info.serial_number, "speedKhz": speed, "swd": "ok" }))
}

/// 连不上时逐级降级重试，覆盖常见现场问题：
/// - 固件复用/关闭了 SWD 引脚 → 复位保持状态下连接
/// - SWD 走线长、探头时钟太快 → 降到 1 MHz / 100 kHz
fn attach_robust(
    info: &probe_rs::probe::DebugProbeInfo,
    sel: TargetSelector,
    reg: &Registry,
) -> Result<probe_rs::Session, String> {
    let mut last = String::new();
    // 总预算：失败时别让界面干等太久（正常连接 1~2 秒就成功）
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(12);
    for (speed, under_reset) in [
        (0u32, false),
        (0, true),
        (1000, false),
        (1000, true),
        (100, false),
        (100, true),
    ] {
        if std::time::Instant::now() > deadline && !last.is_empty() {
            break;
        }
        let mut dev = match info.open() {
            Ok(d) => d,
            Err(e) => {
                last = format!("打开探针失败: {e}");
                continue;
            }
        };
        if speed != 0 {
            let _ = dev.set_speed(speed);
        }
        let r = if under_reset {
            dev.attach_under_reset_with_registry(sel.clone(), Permissions::default(), reg)
        } else {
            dev.attach_with_registry(sel.clone(), Permissions::default(), reg)
        };
        match r {
            Ok(s) => return Ok(s),
            Err(e) => last = format!("{e:?}"),
        }
    }
    // 最后一招：先把目标按在复位里握手再释放，紧接着立刻 attach
    // （固件启动后把 SWD 引脚复用成普通 GPIO 时，只能靠抢在上电初始化前连上）
    if let Ok(mut dev) = info.open() {
        let _ = dev.set_speed(1000);
        if dev.attach_to_unspecified_under_reset().is_ok() {
            let _ = dev.detach();
            if let Ok(mut dev) = info.open() {
                let _ = dev.set_speed(1000);
                if let Ok(s) = dev.attach_with_registry(sel, Permissions::default(), reg) {
                    return Ok(s);
                }
            }
        }
    }
    Err(format!("{last}（已尝试常规/复位下连接与 1MHz、100kHz 降速）"))
}

pub fn attach(cfg: &LaunchArgs) -> Result<Target, String> {
    let lister = probe_rs::probe::list::Lister::new();
    let probes = lister.list_all();
    if probes.is_empty() {
        return Err("未找到调试探针（请检查 USB 连接）".into());
    }
    let idx = match &cfg.probe_serial {
        Some(serial) => probes
            .iter()
            .position(|p| p.serial_number.as_deref() == Some(serial.as_str()))
            .ok_or_else(|| format!("找不到序列号为 {serial} 的调试探针"))?,
        None => cfg.probe_index.min(probes.len() - 1),
    };
    let info = &probes[idx];
    // chip 留空 → 自动探测（复用桌面版 STM32 识别：通用 attach 后读 DBGMCU_IDCODE）
    let chip = if cfg.chip.trim().is_empty() {
        embedded_debugger_lib::commands::detect_chip(idx)
            .map_err(|e| format!("chip 未填写且自动识别失败: {e}"))?
            .chip
    } else {
        cfg.chip.trim().to_string()
    };
    let sel: TargetSelector = chip.clone().into();
    let reg = registry_with_custom();
    let mut session = attach_robust(info, sel, &reg)
        .map_err(|e| format!("连接 {chip} 失败: {e}"))?;

    if cfg.flash {
        if cfg.elf.is_empty() {
            return Err("烧录启动需要 elf 参数".into());
        }
        download_file_with_options(
            &mut session,
            &cfg.elf,
            ElfLoader(ElfOptions::default()),
            DownloadOptions::default(),
        )
        .map_err(|e| format!("烧录失败: {e}"))?;
    }

    let debug = if cfg.elf.is_empty() {
        None
    } else {
        Some(load_elf(&cfg.elf).map_err(|e| format!("符号解析失败: {e}"))?)
    };
    Ok(Target {
        session: Some(session),
        chip,
        debug,
        bps: Vec::new(),
        rtt: None,
        watchpoints: Vec::new(),
    })
}

pub fn read_regs16(core: &mut probe_rs::Core<'_>) -> Result<[u32; 16], String> {
    let mut regs = [0u32; 16];
    for (i, slot) in regs.iter_mut().enumerate() {
        let reg = core.registers().core_register(i);
        *slot = core
            .read_core_reg::<u32>(reg.id())
            .map_err(|e| format!("读 R{i} 失败: {e}"))?;
    }
    Ok(regs)
}

/// 当前停止点的调用栈（DAP stackTrace）
pub fn stack_frames(t: &mut Target) -> Result<Vec<DapFrame>, String> {
    let mut core = t.session.as_mut().ok_or("未连接目标")?.core(0).map_err(|e| e.to_string())?;
    if !core
        .status()
        .map_err(|e| e.to_string())?
        .is_halted()
    {
        return Err("目标运行中".into());
    }
    let regs = read_regs16(&mut core)?;
    let Some(debug) = &t.debug else {
        let pc = regs[15] as u64 & !1;
        return Ok(vec![DapFrame {
            id: 1,
            pc,
            name: format!("0x{:08x}", pc),
            file: None,
            line: None,
            cfa: regs[13] as u64,
        }]);
    };
    // 栈内存整块缓存: CFI 回溯只读栈上数据, 一次 USB 事务替代上百次逐字读
    let sp = regs[13] as u64 & !3;
    let mut cache_start = sp;
    let mut cache = vec![0u8; 512];
    if core.read_8(sp, &mut cache).is_err() {
        cache_start = u64::MAX;
    }
    let (frames, _h) = cfi::unwind(debug, regs, |addr: u64, buf: &mut [u8]| {
        if addr >= cache_start && (addr - cache_start) as usize + buf.len() <= cache.len() {
            let off = (addr - cache_start) as usize;
            buf.copy_from_slice(&cache[off..off + buf.len()]);
            return Ok(());
        }
        core.read_8(addr, buf).map_err(|e| e.to_string())
    });
    Ok(frames
        .into_iter()
        .enumerate()
        .map(|(i, f)| DapFrame {
            id: i + 1,
            pc: f.pc,
            name: f.func.unwrap_or_else(|| format!("0x{:08x}", f.pc)),
            file: f.file,
            line: f.line,
            cfa: f.cfa,
        })
        .collect())
}

#[derive(Clone)]
pub struct DapFrame {
    pub id: usize,
    pub pc: u64,
    pub name: String,
    pub file: Option<String>,
    pub line: Option<u32>,
    pub cfa: u64,
}

/// 局部变量位置解析（与桌面版 collect_locals 同源逻辑）
fn resolve_loc<'a>(loc: &'a LocalLoc, pc: u64) -> Option<&'a LocalLoc> {
    match loc {
        LocalLoc::List(entries) => {
            entries.iter().find(|e| pc >= e.start && pc < e.end).map(|e| &e.loc)
        }
        other => Some(other),
    }
}

fn read_var_bytes(
    core: &mut probe_rs::Core<'_>,
    loc: &LocalLoc,
    pc: u64,
    cfa: i64,
    regs: Option<&[u32; 16]>,
    size: usize,
) -> Result<Vec<u8>, String> {
    match loc {
        LocalLoc::Reg(r) => {
            let rs = regs.ok_or("寄存器值不可用（非当前帧）")?;
            Ok(rs.get(*r as usize).copied().unwrap_or(0).to_le_bytes().to_vec())
        }
        LocalLoc::AddrRegOff(r, off) => {
            let rs = regs.ok_or("寄存器值不可用（非当前帧）")?;
            let addr = (rs.get(*r as usize).copied().unwrap_or(0) as i64 + off) as u64;
            let mut b = vec![0u8; size];
            core.read_8(addr, &mut b).map_err(|e| e.to_string())?;
            Ok(b)
        }
        LocalLoc::AddrFbReg(off) => {
            let addr = (cfa + off) as u64;
            let mut b = vec![0u8; size];
            core.read_8(addr, &mut b).map_err(|e| e.to_string())?;
            Ok(b)
        }
        LocalLoc::AddrCfa => {
            let mut b = vec![0u8; size];
            core.read_8(cfa as u64, &mut b).map_err(|e| e.to_string())?;
            Ok(b)
        }
        LocalLoc::Const(v) => Ok(v.to_le_bytes()[..size.min(8)].to_vec()),
        LocalLoc::List(_) => Err("无有效位置".into()),
    }
}

/// 局部变量（顶层，不展开结构体成员——M2 做成员展开）
/// 一个变量：名字 + 类型 + 显示值；可展开时带地址与类型 id
pub struct VarOut {
    pub name: String,
    pub type_name: String,
    pub value: String,
    pub addr: Option<u64>,
    pub type_id: usize,
}

/// 结构体 / 数组 / 指针可以在变量树里展开
pub fn expandable(types: &[variables::TypeInfo], type_id: usize) -> bool {
    matches!(
        types.get(type_id).map(|t| &t.kind),
        Some(TypeKind::Struct { .. }) | Some(TypeKind::Array { .. }) | Some(TypeKind::Pointer { .. })
    )
}

fn loc_addr(loc: &LocalLoc, pc: u64, frame_base: i64, cfa: u64, regs: Option<&[u32; 16]>) -> Option<u64> {
    match loc {
        LocalLoc::AddrRegOff(r, off) => {
            regs.map(|rs| (rs.get(*r as usize).copied().unwrap_or(0) as i64 + *off) as u64)
        }
        LocalLoc::AddrFbReg(off) => Some((frame_base + *off) as u64),
        LocalLoc::AddrCfa => Some(cfa),
        LocalLoc::List(ranges) => ranges
            .iter()
            .find(|r| pc >= r.start && pc < r.end)
            .and_then(|r| loc_addr(&r.loc, pc, frame_base, cfa, regs)),
        _ => None,
    }
}

pub fn locals(t: &mut Target, frame: &DapFrame) -> Result<Vec<VarOut>, String> {
    let debug = t.debug.as_ref().ok_or("未加载符号")?;
    let mut core = t.session.as_mut().ok_or("未连接目标")?.core(0).map_err(|e| e.to_string())?;
    let regs = read_regs16(&mut core)?;
    let top = frame.id == 1;
    let regs_ref = if top { Some(&regs) } else { None };
    let fl = debug
        .func_locals(frame.pc & !1)
        .ok_or("该帧没有函数级调试信息")?;
    let frame_base = match &fl.frame_base {
        variables::FrameBase::Cfa => frame.cfa as i64,
        variables::FrameBase::Reg(r, off) => match regs_ref {
            Some(rs) => rs.get(*r as usize).copied().unwrap_or(0) as i64 + off,
            None => frame.cfa as i64,
        },
    };
    let mut out = Vec::new();
    for v in &fl.vars {
        let Some(loc) = resolve_loc(&v.loc, frame.pc & !1) else { continue };
        let ty = &debug.types[v.type_id];
        let size = ty.size.clamp(1, 256) as usize;
        match read_var_bytes(&mut core, loc, frame.pc & !1, frame_base, regs_ref, size) {
            Ok(bytes) => {
                let (value, _members) = variables::format_var(&debug.types, v.type_id, &bytes, false);
                let addr = loc_addr(loc, frame.pc & !1, frame_base, frame.cfa, regs_ref);
                out.push(VarOut {
                    name: v.name.clone(),
                    type_name: ty.name.clone(),
                    value,
                    addr,
                    type_id: v.type_id,
                });
            }
            Err(_) => out.push(VarOut {
                name: v.name.clone(),
                type_name: ty.name.clone(),
                value: "<不可用>".into(),
                addr: None,
                type_id: v.type_id,
            }),
        }
    }
    Ok(out)
}

/// 展开一个复合变量：结构体成员 / 数组元素 / 指针目标
pub fn children(t: &mut Target, addr: u64, type_id: usize) -> Result<Vec<VarOut>, String> {
    struct Child {
        name: String,
        addr: u64,
        type_id: usize,
        type_name: String,
        size: u64,
    }

    // 先在只读借用里把要读的子项算好，指针则记下目标类型，等释放借用后再解引用
    let (mut list, pointer) = {
        let debug = t.debug.as_ref().ok_or("未加载符号")?;
        let types = &debug.types;
        let info = types.get(type_id).ok_or("类型不存在")?;
        let meta = |tid: usize| {
            types
                .get(tid)
                .map(|t| (t.name.clone(), t.size.max(1)))
                .unwrap_or((String::new(), 4))
        };
        let mut list: Vec<Child> = Vec::new();
        let mut pointer: Option<(usize, String, u64)> = None;
        match &info.kind {
            TypeKind::Struct { members } => {
                for m in members.iter().take(100) {
                    let (name, size) = meta(m.type_id);
                    list.push(Child {
                        name: m.name.clone(),
                        addr: addr + m.offset,
                        type_id: m.type_id,
                        type_name: name,
                        size,
                    });
                }
            }
            TypeKind::Array { elem, count } => {
                let (name, elem_size) = meta(*elem);
                for i in 0..(*count).min(64) {
                    list.push(Child {
                        name: format!("[{i}]"),
                        addr: addr + i * elem_size,
                        type_id: *elem,
                        type_name: name.clone(),
                        size: elem_size,
                    });
                }
            }
            TypeKind::Pointer { target: Some(target) } => {
                let (name, size) = meta(*target);
                pointer = Some((*target, name, size));
            }
            _ => {}
        }
        (list, pointer)
    };

    if let Some((target, type_name, size)) = pointer {
        let mut buf = [0u8; 4];
        if core_read(t, addr, &mut buf).is_ok() {
            let ptr = u32::from_le_bytes(buf) as u64;
            if ptr != 0 {
                list.push(Child {
                    name: "*ptr".into(),
                    addr: ptr,
                    type_id: target,
                    type_name,
                    size,
                });
            }
        }
    }

    let types = t.debug.as_ref().map(|d| d.types.clone()).unwrap_or_default();
    let mut core = t.session.as_mut().ok_or("未连接目标")?.core(0).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for child in list {
        let size = (child.size as usize).clamp(1, 256);
        let mut buf = vec![0u8; size];
        let value = if core.read_8(child.addr, &mut buf).is_ok() {
            variables::format_var(&types, child.type_id, &buf, false).0
        } else {
            "<不可读>".into()
        };
        out.push(VarOut {
            name: child.name,
            type_name: child.type_name,
            value,
            addr: Some(child.addr),
            type_id: child.type_id,
        });
    }
    Ok(out)
}

/// 全局变量: 按地址排序后分块批量读（一次读一段连续内存, 替代逐变量读）
pub fn globals(t: &mut Target) -> Result<Vec<VarOut>, String> {
    let debug = t.debug.as_ref().ok_or("未加载符号")?;
    let mut sorted: Vec<&variables::VarEntry> = debug.vars.iter().collect();
    sorted.sort_by_key(|v| v.addr);
    let var_size = |v: &variables::VarEntry| debug.types[v.type_id].size.clamp(1, 256) as u64;
    let var_name = |v: &variables::VarEntry| debug.types[v.type_id].name.clone();

    let mut core = t.session.as_mut().ok_or("未连接目标")?.core(0).map_err(|e| e.to_string())?;
    const MAX_BLOCK: u64 = 2048;
    const MAX_GAP: u64 = 512;
    let mut out = Vec::new();
    let mut i = 0;
    while i < sorted.len() {
        let start = sorted[i].addr;
        let mut end = start + var_size(sorted[i]);
        let mut j = i + 1;
        while j < sorted.len() {
            let sz = var_size(sorted[j]);
            if sorted[j].addr >= end
                && sorted[j].addr + sz <= end + MAX_GAP
                && sorted[j].addr + sz - start <= MAX_BLOCK
            {
                end = sorted[j].addr + sz;
                j += 1;
            } else {
                break;
            }
        }
        let mut buf = vec![0u8; (end - start) as usize];
        let ok = core.read_8(start, &mut buf).is_ok();
        for k in i..j {
            let v = sorted[k];
            let sz = var_size(v) as usize;
            let name = var_name(v);
            let value = if ok {
                let off = (v.addr - start) as usize;
                if off + sz <= buf.len() {
                    let (val, _) = variables::format_var(&debug.types, v.type_id, &buf[off..off + sz], false);
                    val
                } else {
                    "<不可读>".into()
                }
            } else {
                "<不可读>".into()
            };
            out.push(VarOut {
                name: v.name.clone(),
                type_name: name,
                value,
                addr: Some(v.addr),
                type_id: v.type_id,
            });
        }
        i = j;
    }
    Ok(out)
}

/// 寄存器（名称 + 十六进制）
pub fn registers(t: &mut Target) -> Result<Vec<(String, String, String)>, String> {
    let mut core = t.session.as_mut().ok_or("未连接目标")?.core(0).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for reg in core.registers().all_registers() {
        if reg.size_in_bits() > 32 {
            continue;
        }
        if let Ok(v) = core.read_core_reg::<u32>(reg.id()) {
            out.push((reg.name().to_string(), "".into(), format!("0x{v:08x}")));
        }
    }
    Ok(out)
}

/// 断点重设（VS Code 按文件逐个发请求）: 只替换该文件的断点，其他文件保留；
/// 全部槽位清空后按记录确定式重编程（不依赖硬件回读）
pub fn set_breakpoints(t: &mut Target, file: &str, lines: &[u32]) -> Result<Vec<Value>, String> {
    let mut core = t.session.as_mut().ok_or("未连接目标")?.core(0).map_err(|e| e.to_string())?;
    let avail = core.available_breakpoint_units().map_err(|e| e.to_string())? as usize;

    // 1) 记录层: 移除该文件旧断点, 追加新解析结果
    t.bps.retain(|(f, _, _)| f != file);
    let mut verified: Vec<Value> = Vec::new();
    if let Some(debug) = &t.debug {
        let file_known = debug.find_file(file).is_some();
        for line in lines {
            if !file_known {
                verified.push(json!({ "verified": false, "line": line, "message": format!("符号文件里找不到源文件: {file}") }));
                continue;
            }
            match debug.resolve_line(file, *line) {
                // 返回吸附后的行号: VS Code 会把红点移到实际生效的行,
                // 源码与固件行号不一致时用户一眼可见
                Some((snapped, addr)) => {
                    t.bps.push((file.to_string(), snapped, addr));
                    verified.push(json!({ "verified": true, "line": snapped }));
                }
                None => verified.push(json!({ "verified": false, "line": line, "message": "该行无可执行代码" })),
            }
        }
    } else {
        for line in lines {
            verified.push(json!({ "verified": false, "line": line, "message": "未加载符号" }));
        }
    }
    if t.bps.len() > avail {
        let msg = format!("硬件断点槽已满（{avail} 个），多余断点未生效");
        t.bps.truncate(avail);
        verified.push(json!({ "verified": false, "message": msg }));
    }

    // 2) 硬件层: 清全部槽位, 按记录顺序重编程
    for u in 0..avail {
        let _ = probe_rs::CoreInterface::clear_hw_breakpoint(&mut core, u);
    }
    for (i, (_, _, addr)) in t.bps.iter().enumerate() {
        core.set_hw_breakpoint_unit(i, *addr)
            .map_err(|e| format!("断点 #{i} 设置失败: {e}"))?;
    }
    Ok(verified)
}

/// 复位会清掉 FPB 断点: 按我们自己的记录重新编程全部槽位
pub fn reapply_breakpoints(t: &mut Target) -> Result<(), String> {
    let mut core = t.session.as_mut().ok_or("未连接目标")?.core(0).map_err(|e| e.to_string())?;
    let avail = core.available_breakpoint_units().map_err(|e| e.to_string())? as usize;
    for u in 0..avail {
        let _ = probe_rs::CoreInterface::clear_hw_breakpoint(&mut core, u);
    }
    for (i, (_, _, addr)) in t.bps.iter().enumerate() {
        if i >= avail {
            break;
        }
        core.set_hw_breakpoint_unit(i, *addr)
            .map_err(|e| format!("断点 #{i} 重建失败: {e}"))?;
    }
    eprintln!("[reapply] avail={avail} 已重建 {} 个断点: {:02x?}", t.bps.len(), t.bps.iter().map(|b| b.2).collect::<Vec<_>>());
    Ok(())
}

/// 断点地址列表（单步引擎用）
pub fn bp_addrs(t: &Target) -> Vec<u64> {
    t.bps.iter().map(|(_, _, a)| *a).collect()
}

/// 当前是否停在断点上。只读 DHCSR，不读寄存器，轮询代价很小
pub fn halted(t: &mut Target) -> Result<bool, String> {
    let mut core = t.session.as_mut().ok_or("未连接目标")?.core(0).map_err(|e| e.to_string())?;
    let status = core.status().map_err(|e| e.to_string())?;
    Ok(matches!(status, CoreStatus::Halted(_)))
}

pub fn pc_of(t: &mut Target) -> Result<u64, String> {
    let mut core = t.session.as_mut().ok_or("未连接目标")?.core(0).map_err(|e| e.to_string())?;
    let reg = core.program_counter().id();
    Ok(core
        .read_core_reg::<u32>(reg)
        .map_err(|e| e.to_string())? as u64)
}

pub fn halt_target(t: &mut Target) -> Result<u64, String> {
    let mut core = t.session.as_mut().ok_or("未连接目标")?.core(0).map_err(|e| e.to_string())?;
    let h = core.halt(std::time::Duration::from_secs(2)).map_err(|e| e.to_string())?;
    Ok(h.pc as u64)
}

pub fn run_target(t: &mut Target) -> Result<(), String> {
    let mut core = t.session.as_mut().ok_or("未连接目标")?.core(0).map_err(|e| e.to_string())?;
    core.run().map_err(|e| e.to_string())
}

/// 继续运行: PC 正停在断点地址上时先单步跨过（否则 FPB 立即再次命中, 表现为"卡死"）
pub fn resume(t: &mut Target) -> Result<(), String> {
    let mut core = t.session.as_mut().ok_or("未连接目标")?.core(0).map_err(|e| e.to_string())?;
    let reg = core.program_counter().id();
    let pc = (core.read_core_reg::<u32>(reg).map_err(|e| e.to_string())? as u64) & !1;
    if t.bps.iter().any(|(_, _, a)| *a == pc) {
        core.step().map_err(|e| format!("跨过断点失败: {e}"))?;
    }
    core.run().map_err(|e| e.to_string())
}

/// 复位 → 重建用户断点 → 运行（停在用户断点上；无断点则自由运行）
pub fn reset_and_run(t: &mut Target) -> Result<(), String> {
    reset_and_halt(t)?;
    reapply_breakpoints(t)?;
    resume(t)
}

/// 运行到指定地址（临时硬件断点用空闲槽位，Keil "Run to main" 同款）
pub fn run_to_addr(t: &mut Target, addr: u64, timeout_secs: f64) -> Result<(), String> {
    let mut core = t.session.as_mut().ok_or("未连接目标")?.core(0).map_err(|e| e.to_string())?;
    let avail = core.available_breakpoint_units().map_err(|e| e.to_string())? as usize;
    let unit = t.bps.len();
    if unit >= avail {
        return Err(format!("硬件断点已用满（{avail} 个），无法运行到 main"));
    }
    core.set_hw_breakpoint_unit(unit, addr)
        .map_err(|e| format!("设临时断点失败: {e}"))?;
    if let Err(e) = core.run() {
        let _ = probe_rs::CoreInterface::clear_hw_breakpoint(&mut core, unit);
        return Err(format!("启动运行失败: {e}"));
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs_f64(timeout_secs);
    loop {
        let halted = core.status().map_err(|e| e.to_string())?.is_halted();
        if halted {
            let _ = probe_rs::CoreInterface::clear_hw_breakpoint(&mut core, unit);
            return Ok(());
        }
        if std::time::Instant::now() > deadline {
            let _ = probe_rs::CoreInterface::clear_hw_breakpoint(&mut core, unit);
            let _ = core.halt(std::time::Duration::from_secs(2));
            return Err("等待运行到 main 超时".into());
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

/// 复位 → 重建用户断点 → 直接运行（停在用户第一个断点上；由监视线程发 stopped 事件）
pub fn reset_and_run_to_user_bps(t: &mut Target) -> Result<(), String> {
    reset_and_halt(t)?;
    reapply_breakpoints(t)?;
    resume(t)
}

/// 烧录加载后: 复位 → 重建用户断点 → 运行到 main（无断点时的兜底; 用户断点保留）
pub fn run_to_main_after_reset(t: &mut Target) -> Result<(), String> {
    reset_and_halt(t)?;
    reapply_breakpoints(t)?;
    let main_addr = t
        .debug
        .as_ref()
        .and_then(|d| d.funcs.iter().find(|f| f.name == "main"))
        .map(|f| f.start & !1);
    let Some(addr) = main_addr else {
        return Ok(()); // 符号里没有 main, 停在复位点
    };
    run_to_addr(t, addr, 8.0)
}

/// DAP disassemble: 从指定地址反汇编 count 条 Thumb 指令
pub fn disassemble(
    t: &mut Target,
    memory_ref: &str,
    offset: i64,
    instr_offset: i64,
    count: usize,
) -> Result<Vec<Value>, String> {
    let hex = memory_ref.trim().trim_start_matches("0x").trim_start_matches("0X");
    let base = u64::from_str_radix(hex, 16).map_err(|e| format!("地址解析失败: {e}"))?;
    let start = ((base as i64) + offset + instr_offset * 2).max(0) as u64 & !1;
    let mut core = t.session.as_mut().ok_or("未连接目标")?.core(0).map_err(|e| e.to_string())?;
    let mut bytes = vec![0u8; count * 4 + 4];
    if core.read_8(start, &mut bytes).is_err() {
        bytes.fill(0);
    }
    use capstone::arch::{arm, BuildsCapstone};
    use capstone::Capstone;
    let cs = Capstone::new()
        .arm()
        .mode(arm::ArchMode::Thumb)
        .build()
        .map_err(|e| format!("反汇编器初始化失败: {e}"))?;
    let insns = cs
        .disasm_all(&bytes[..count * 4], start)
        .map_err(|e| format!("反汇编失败: {e}"))?;
    let mut out = Vec::new();
    for i in insns.iter().take(count) {
        out.push(json!({
            "address": format!("0x{:08x}", i.address() as u64),
            "instructionBytes": i.bytes().iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" "),
            "instruction": format!("{} {}", i.mnemonic().unwrap_or(""), i.op_str().unwrap_or(""))
                .trim_end().to_string(),
        }));
    }
    Ok(out)
}

/// 混合视图: 返回当前函数的反汇编, 按地址顺序并标注源码行
pub fn source_disassembly(t: &mut Target, file: &str, pc: u64) -> Result<Value, String> {
    let (func_name, func_range) = {
        let debug = t.debug.as_ref().ok_or("未加载符号")?;
        let func = debug.funcs.iter().find(|f| pc >= f.start && pc < f.end);
        (func.map(|f| f.name.clone()), func.map(|f| (f.start, f.end)))
    };

    let Some((start, end)) = func_range else {
        return Ok(json!({
            "file": file,
            "function": Value::Null,
            "startLine": Value::Null,
            "endLine": Value::Null,
            "rows": [],
        }));
    };

    let insns = disasm_range(t, start & !1, end, 4096)?;

    let debug = t.debug.as_ref().ok_or("未加载符号")?;
    let mut rows: Vec<(u32, u64, Vec<(u64, String)>)> = Vec::new();
    for (addr, text) in insns {
        let line = debug.addr_to_line(addr).map(|(_, l)| l).unwrap_or(0);
        match rows.last_mut() {
            Some((last_line, _, list)) if *last_line == line => list.push((addr, text)),
            _ => rows.push((line, addr, vec![(addr, text)])),
        }
    }

    let out: Vec<Value> = rows
        .iter()
        .map(|(line, addr, list)| {
            json!({
                "line": line,
                "address": format!("0x{:08x}", addr),
                "instructions": list
                    .iter()
                    .map(|(a, t)| json!({ "address": format!("0x{:08x}", a), "text": t }))
                    .collect::<Vec<_>>(),
            })
        })
        .collect();

    Ok(json!({
        "file": file,
        "function": func_name,
        "startLine": rows.first().map(|r| r.0),
        "endLine": rows.last().map(|r| r.0),
        "rows": out,
    }))
}

/// 反汇编 [start, end) 区间，最多 max 条
fn disasm_range(t: &mut Target, start: u64, end: u64, max: usize) -> Result<Vec<(u64, String)>, String> {
    let len = (end.saturating_sub(start)).min((max * 4) as u64) as usize;
    if len < 2 {
        return Ok(Vec::new());
    }
    let mut bytes = vec![0u8; len];
    {
        let mut core = t.session.as_mut().ok_or("未连接目标")?.core(0).map_err(|e| e.to_string())?;
        if core.read_8(start, &mut bytes).is_err() {
            return Ok(Vec::new());
        }
    }
    use capstone::arch::{arm, BuildsCapstone};
    use capstone::Capstone;
    let cs = Capstone::new()
        .arm()
        .mode(arm::ArchMode::Thumb)
        .build()
        .map_err(|e| format!("反汇编器初始化失败: {e}"))?;
    let insns = cs
        .disasm_all(&bytes, start)
        .map_err(|e| format!("反汇编失败: {e}"))?;
    let mut out = Vec::new();
    for i in insns.iter().take(max) {
        out.push((
            i.address() as u64,
            format!("{} {}", i.mnemonic().unwrap_or(""), i.op_str().unwrap_or(""))
                .trim_end()
                .to_string(),
        ));
    }
    Ok(out)
}

/// 单条指令（DAP instruction 粒度）
pub fn instruction_step(t: &mut Target) -> Result<u64, String> {
    let mut core = t.session.as_mut().ok_or("未连接目标")?.core(0).map_err(|e| e.to_string())?;
    if !core.status().map_err(|e| e.to_string())?.is_halted() {
        core.halt(std::time::Duration::from_secs(2)).map_err(|e| e.to_string())?;
    }
    let info = core.step().map_err(|e| e.to_string())?;
    Ok(info.pc)
}

pub fn reset_and_halt(t: &mut Target) -> Result<(), String> {
    let mut core = t.session.as_mut().ok_or("未连接目标")?.core(0).map_err(|e| e.to_string())?;
    core.reset_and_halt(std::time::Duration::from_secs(2))
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// 源码级单步（in/over/out），返回非致命提示
pub fn step(t: &mut Target, mode: &str) -> Result<Option<String>, String> {
    let bps = bp_addrs(t);
    // SWD 偶发传输错误（An ARM specific error）重试一次：
    // 先放弃旧 core 句柄重新拿（等价于重新同步调试口），再走一遍单步
    let attempt = |t: &mut Target| -> Result<stepper::StepResult, String> {
        let mut core = t.session.as_mut().ok_or("未连接目标")?.core(0).map_err(|e| e.to_string())?;
        stepper::step_line(&mut core, t.debug.as_ref(), mode, &bps)
    };
    match attempt(t) {
        Ok(r) => Ok(r.note),
        Err(e) if is_transient_dap_error(&e) => {
            eprintln!("[ed-dap] step transient error, retry once: {e}");
            let r = attempt(t)?;
            Ok(r.note)
        }
        Err(e) => Err(e),
    }
}

/// SWD 偶发传输错误的特征：单次重连后通常就恢复
fn is_transient_dap_error(msg: &str) -> bool {
    msg.contains("ARM specific")
        || msg.contains("Timeout")
        || msg.contains("超时")
        || msg.contains("DP error")
        || msg.contains("wait ACK")
}

/// 表达式路径的一段：.member / ->member / [index]
#[derive(Debug)]
enum PathStep {
    Member(String),
    Index(u64),
}

/// 解析 `var.a.b->c[2].d` 为 (根名, 步骤列表)。
/// 根名是第一个标识符；随后按出现顺序取 .name / ->name / [数字]。
fn parse_expr_path(expr: &str) -> Option<(String, Vec<PathStep>)> {
    let s = expr.trim();
    let mut chars = s.chars().peekable();
    // 根标识符
    let mut root = String::new();
    while let Some(&c) = chars.peek() {
        if c.is_alphanumeric() || c == '_' {
            root.push(c);
            chars.next();
        } else {
            break;
        }
    }
    if root.is_empty() || root.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        return None;
    }
    let mut steps = Vec::new();
    while let Some(&c) = chars.peek() {
        match c {
            '.' => {
                chars.next();
                let mut name = String::new();
                while let Some(&c2) = chars.peek() {
                    if c2.is_alphanumeric() || c2 == '_' {
                        name.push(c2);
                        chars.next();
                    } else {
                        break;
                    }
                }
                if name.is_empty() {
                    return None;
                }
                steps.push(PathStep::Member(name));
            }
            '-' => {
                chars.next();
                if chars.next() != Some('>') {
                    return None;
                }
                let mut name = String::new();
                while let Some(&c2) = chars.peek() {
                    if c2.is_alphanumeric() || c2 == '_' {
                        name.push(c2);
                        chars.next();
                    } else {
                        break;
                    }
                }
                if name.is_empty() {
                    return None;
                }
                steps.push(PathStep::Member(name));
            }
            '[' => {
                chars.next();
                let mut num = String::new();
                for c2 in chars.by_ref() {
                    if c2.is_ascii_digit() {
                        num.push(c2);
                    } else if c2 == ']' {
                        break;
                    } else {
                        return None;
                    }
                }
                steps.push(PathStep::Index(num.parse().ok()?));
            }
            _ => return None,
        }
    }
    Some((root, steps))
}

/// 沿类型链走一步。返回新地址 + 新类型 id。
/// 成员：addr += offset；Index：解引用指针或 addr += index * elem_size。
fn walk_step(
    types: &[variables::TypeInfo],
    addr: u64,
    type_id: usize,
    step: &PathStep,
    t: &mut Target,
) -> Result<(u64, usize), String> {
    let info = types.get(type_id).ok_or("类型不存在")?;
    match step {
        PathStep::Member(name) => match &info.kind {
            variables::TypeKind::Struct { members } => {
                let m = members
                    .iter()
                    .find(|m| m.name == *name)
                    .ok_or_else(|| format!("{} 里没有成员 {}", info.name, name))?;
                Ok((addr + m.offset, m.type_id))
            }
            variables::TypeKind::Pointer { target: Some(tid) } => {
                // -> 成员：先解引用指针，再在目标结构体里找成员
                let tinfo = types.get(*tid).ok_or("指针目标类型不存在")?;
                let members = match &tinfo.kind {
                    variables::TypeKind::Struct { members } => members,
                    _ => return Err(format!("{} 不是结构体指针", info.name)),
                };
                let m = members
                    .iter()
                    .find(|m| m.name == *name)
                    .ok_or_else(|| format!("{} 里没有成员 {}", tinfo.name, name))?;
                // 读指针值
                let psz = (info.size.max(1) as usize).min(8);
                let mut b = vec![0u8; psz];
                core_read(t, addr, &mut b)?;
                let mut target_addr = 0u64;
                for (i, byte) in b.iter().enumerate() {
                    target_addr |= (*byte as u64) << (i * 8);
                }
                Ok((target_addr + m.offset, m.type_id))
            }
            _ => Err(format!("{} 不是结构体或指针", info.name)),
        },
        PathStep::Index(idx) => match &info.kind {
            variables::TypeKind::Array { elem, count } => {
                if idx >= count {
                    return Err(format!("下标 {} 越界（数组长度 {}）", idx, count));
                }
                let esize = types.get(*elem).map(|e| e.size.max(1)).unwrap_or(4);
                Ok((addr + idx * esize, *elem))
            }
            variables::TypeKind::Pointer { target: Some(tid) } => {
                // 指针当下标：解引用 + elem 偏移
                let esize = types.get(*tid).map(|e| e.size.max(1)).unwrap_or(4);
                let psz = (info.size.max(1) as usize).min(8);
                let mut b = vec![0u8; psz];
                core_read(t, addr, &mut b)?;
                let mut target_addr = 0u64;
                for (i, byte) in b.iter().enumerate() {
                    target_addr |= (*byte as u64) << (i * 8);
                }
                Ok((target_addr + idx * esize, *tid))
            }
            _ => Err(format!("{} 不是数组或指针", info.name)),
        },
    }
}

/// evaluate: 全局/局部变量 + 成员/数组路径（a.b->c[i]）
pub fn evaluate(
    t: &mut Target,
    expr: &str,
    frame: Option<DapFrame>,
) -> Result<VarOut, String> {
    let expr = expr.trim().trim_start_matches('&').to_string();
    let (root, steps) = parse_expr_path(&expr)
        .ok_or_else(|| "支持的写法：变量名、a.b、p->next、arr[2]，及其组合（如 a.b[1].c）".to_string())?;

    let (mut addr, mut tid) = {
        let debug = t.debug.as_ref().ok_or("未加载符号")?;
        let g = debug
            .vars
            .iter()
            .find(|v| v.name == root)
            .map(|v| (Some(v.addr), v.type_id));
        match g {
            Some(x) => x,
            None => {
                // 局部变量（克隆所需数据避免借用冲突）
                let frame = frame.ok_or_else(|| format!("未找到变量: {root}"))?;
                let pc = frame.pc & !1;
                let fl = t
                    .debug
                    .as_ref()
                    .and_then(|d| d.func_locals(pc))
                    .cloned()
                    .ok_or_else(|| format!("未找到变量: {root}"))?;
                let v = fl.vars.iter().find(|v| v.name == root).ok_or_else(|| format!("未找到变量: {root}"))?.clone();
                let mut core = t.session.as_mut().ok_or("未连接目标")?.core(0).map_err(|e| e.to_string())?;
                let regs = read_regs16(&mut core)?;
                let loc = resolve_loc(&v.loc, pc).ok_or("变量已被优化")?;
                let frame_base = match &fl.frame_base {
                    variables::FrameBase::Cfa => frame.cfa as i64,
                    variables::FrameBase::Reg(r, off) => {
                        regs.get(*r as usize).copied().unwrap_or(0) as i64 + off
                    }
                };
                let addr = loc_addr(&loc, pc, frame_base, frame.cfa, Some(&regs));
                (addr, v.type_id)
            }
        }
    };

    // 沿路径逐段走（->成员/指针下标需要读内存，所以要 &mut t）
    if !steps.is_empty() && addr.is_none() {
        return Err(format!("{root} 已被优化，取不到地址"));
    }
    let mut cur = addr.unwrap_or(0);
    for step in &steps {
        let types_snapshot = t.debug.as_ref().map(|d| d.types.clone()).unwrap_or_default();
        let (na, nt) = walk_step(&types_snapshot, cur, tid, step, t)?;
        cur = na;
        tid = nt;
    }

    let (size, value, tname) = {
        let debug = t.debug.as_ref().ok_or("未加载符号")?;
        let size = debug.types[tid].size.max(1) as usize;
        (size, String::new(), debug.types[tid].name.clone())
    };
    let mut b = vec![0u8; size.min(4096)];
    core_read(t, cur, &mut b)?;
    let (value, _) = {
        let debug = t.debug.as_ref().ok_or("未加载符号")?;
        variables::format_var(&debug.types, tid, &b, false)
    };
    Ok(VarOut {
        name: expr,
        type_name: tname,
        value,
        addr: Some(cur),
        type_id: tid,
    })
}

fn core_read(t: &mut Target, addr: u64, buf: &mut [u8]) -> Result<(), String> {
    let mut core = t.session.as_mut().ok_or("未连接目标")?.core(0).map_err(|e| e.to_string())?;
    core.read_8(addr, buf).map_err(|e| e.to_string())
}

/// 读内存，返回小写十六进制字符串；不可读的字节用 ?? 占位
pub fn read_memory(t: &mut Target, addr: u64, len: usize) -> Result<String, String> {
    let len = len.clamp(1, 4096);
    let mut buf = vec![0u8; len];
    if core_read(t, addr, &mut buf).is_ok() {
        return Ok(buf.iter().map(|b| format!("{b:02x}")).collect());
    }

    let mut core = t.session.as_mut().ok_or("未连接目标")?.core(0).map_err(|e| e.to_string())?;
    let mut out = String::with_capacity(len * 2);
    for i in 0..len {
        match core.read_word_8(addr + i as u64) {
            Ok(b) => out.push_str(&format!("{b:02x}")),
            Err(_) => out.push_str("??"),
        }
    }
    Ok(out)
}

fn read_u32(t: &mut Target, addr: u64) -> Result<u32, String> {
    let mut buf = [0u8; 4];
    core_read(t, addr, &mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

fn read_reg_named(core: &mut probe_rs::Core<'_>, name: &str) -> Option<u32> {
    for reg in core.registers().all_registers() {
        if reg.name().eq_ignore_ascii_case(name) {
            if let Ok(v) = core.read_core_reg::<u32>(reg.id()) {
                return Some(v);
            }
        }
    }
    None
}

/// 写内存：data 是十六进制字符串（长度必须是偶数）
pub fn write_memory(t: &mut Target, addr: u64, data: &str) -> Result<(), String> {
    let cleaned: String = data.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.len() % 2 != 0 || cleaned.is_empty() {
        return Err("数据要写成十六进制且长度为偶数，例如 00112233".into());
    }
    let mut bytes = Vec::with_capacity(cleaned.len() / 2);
    for i in (0..cleaned.len()).step_by(2) {
        let byte = u8::from_str_radix(&cleaned[i..i + 2], 16)
            .map_err(|_| format!("不是合法的十六进制: {}", &cleaned[i..i + 2]))?;
        bytes.push(byte);
    }
    let size = bytes.len();
    let mut core = t.session.as_mut().ok_or("未连接目标")?.core(0).map_err(|e| e.to_string())?;
    core.write_8(addr, &bytes).map_err(|e| e.to_string())?;

    // 回读校验：Flash 只读区写不进去，别假装成功
    let mut check = vec![0u8; size];
    core.read_8(addr, &mut check).map_err(|e| e.to_string())?;
    if check != bytes {
        return Err("写入未生效：目标可能在 Flash 只读区（常量需要重新烧录才能改）".into());
    }
    Ok(())
}

/// 把字符串解析成整数：支持 0x 前缀十六进制、十进制、负数
pub fn parse_number(text: &str) -> Result<i64, String> {
    let t = text.trim();
    if t.is_empty() {
        return Err("值为空".into());
    }
    let (neg, body) = match t.strip_prefix('-') {
        Some(rest) => (true, rest.trim()),
        None => (false, t),
    };
    let parsed = if let Some(hex) = body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).map_err(|_| format!("不是合法的十六进制: {t}"))?
    } else {
        body.parse::<u64>().map_err(|_| format!("不是合法的数字: {t}"))?
    };
    Ok(if neg { -(parsed as i64) } else { parsed as i64 })
}

/// 按类型把值写进内存（整数 / 指针 / 枚举 / 浮点）
pub fn write_value(t: &mut Target, addr: u64, type_id: usize, value: &str) -> Result<(), String> {
    let (size, is_float) = {
        let debug = t.debug.as_ref().ok_or("未加载符号")?;
        let info = debug.types.get(type_id).ok_or("类型不存在")?;
        // 不引入 gimli 依赖，直接按类型名判断浮点
        let name = info.name.to_ascii_lowercase();
        let float = matches!(name.as_str(), "float" | "double" | "long double");
        (info.size.clamp(1, 8) as usize, float)
    };

    let mut bytes = if is_float && size == 4 {
        let v: f32 = value.trim().parse().map_err(|_| format!("不是合法的浮点数: {value}"))?;
        v.to_le_bytes().to_vec()
    } else if is_float && size == 8 {
        let v: f64 = value.trim().parse().map_err(|_| format!("不是合法的浮点数: {value}"))?;
        v.to_le_bytes().to_vec()
    } else {
        parse_number(value)?.to_le_bytes().to_vec()
    };
    bytes.resize(size, 0);

    let mut core = t.session.as_mut().ok_or("未连接目标")?.core(0).map_err(|e| e.to_string())?;
    core.write_8(addr, &bytes).map_err(|e| e.to_string())?;

    // 回读校验：Flash 里的 const 变量写不进去，别假装成功
    let mut check = vec![0u8; size];
    core.read_8(addr, &mut check).map_err(|e| e.to_string())?;
    if check != bytes {
        return Err("写入未生效：目标可能在 Flash 只读区（常量需要重新烧录才能改）".into());
    }
    Ok(())
}

/// 写一个 32 位内核寄存器（名字不区分大小写，支持 R0..R15/SP/LR/PC/MSP/PSP/XPSR 等）
pub fn write_register(t: &mut Target, name: &str, value: u32) -> Result<(), String> {
    let mut core = t.session.as_mut().ok_or("未连接目标")?.core(0).map_err(|e| e.to_string())?;
    for reg in core.registers().all_registers() {
        if reg.name().eq_ignore_ascii_case(name) {
            return core
                .write_core_reg(reg.id(), value)
                .map_err(|e| e.to_string());
        }
    }
    Err(format!("找不到寄存器 {name}"))
}

/// 把 CFSR/HFSR 解码成人能看懂的名字 + 说明
pub fn decode_fault(cfsr: u32, hfsr: u32) -> Vec<(&'static str, &'static str)> {
    let table: [(u32, &'static str, &'static str); 20] = [
        (0, "IACCVIOL", "取指访问违例（MPU/XN）"),
        (1, "DACCVIOL", "数据访问违例（MPU）"),
        (3, "MUNSTKERR", "异常返回出栈时出错"),
        (4, "MSTKERR", "异常进入压栈时出错"),
        (5, "MLSPERR", "浮点延迟压栈时出错"),
        (7, "MMARVALID", "MMFAR 中的地址有效"),
        (8, "IBUSERR", "取指总线错误"),
        (9, "PRECISERR", "精确数据总线错误（BFAR 有效）"),
        (10, "IMPRECISERR", "不精确数据总线错误（BFAR 无效）"),
        (11, "UNSTKERR", "异常返回出栈时总线错误"),
        (12, "STKERR", "异常进入压栈时总线错误"),
        (13, "LSPERR", "浮点延迟压栈时总线错误"),
        (15, "BFARVALID", "BFAR 中的地址有效"),
        (16, "UNDEFINSTR", "未定义指令"),
        (17, "INVSTATE", "非法状态（例如 Thumb 位为 0）"),
        (18, "INVPC", "非法 PC 装入"),
        (19, "NOCP", "协处理器不存在"),
        (20, "STKOF", "栈溢出"),
        (24, "UNALIGNED", "非对齐访问"),
        (25, "DIVBYZERO", "除零"),
    ];
    let mut out: Vec<(&'static str, &'static str)> = Vec::new();
    for (bit, name, text) in table {
        if cfsr & (1u32 << bit) != 0 {
            out.push((name, text));
        }
    }
    if hfsr & (1 << 1) != 0 {
        out.push(("VECTTBL", "取中断向量表时总线错误"));
    }
    if hfsr & (1 << 30) != 0 {
        out.push(("FORCED", "由可配置故障升级为 HardFault（看 CFSR）"));
    }
    if hfsr & (1 << 31) != 0 {
        out.push(("DEBUGEVT", "调试事件导致进入 HardFault"));
    }
    out
}

/// FreeRTOS 结构体布局：从 DWARF 类型表里按字段名取偏移，配置变了也能自适应
struct RtosLayout {
    tcb_top: u64,
    tcb_prio: u64,
    tcb_stack: u64,
    tcb_name: u64,
    tcb_name_len: usize,
    /// TCB 里的 xEventListItem（用来判断是不是在等某个事件）
    tcb_event: u64,
    list_size: u64,
    list_end: u64,
    item_next: u64,
    item_owner: u64,
    /// ListItem 的 pxContainer：非 0 表示挂在某个事件链表上
    item_container: u64,
}

fn member_offset(types: &[variables::TypeInfo], type_id: usize, name: &str) -> Option<u64> {
    match &types.get(type_id)?.kind {
        TypeKind::Struct { members } => members.iter().find(|m| m.name == name).map(|m| m.offset),
        _ => None,
    }
}

fn member_type(types: &[variables::TypeInfo], type_id: usize, name: &str) -> Option<usize> {
    match &types.get(type_id)?.kind {
        TypeKind::Struct { members } => members.iter().find(|m| m.name == name).map(|m| m.type_id),
        _ => None,
    }
}

fn pointer_target(types: &[variables::TypeInfo], type_id: usize) -> Option<usize> {
    match &types.get(type_id)?.kind {
        TypeKind::Pointer { target } => *target,
        _ => None,
    }
}

fn build_layout(types: &[variables::TypeInfo], tcb_id: usize, list_id: usize) -> Result<RtosLayout, String> {
    let need = |opt: Option<u64>, what: &str| {
        opt.ok_or_else(|| format!("字段 {what} 没找到（tcb={tcb_id}, list={list_id}）"))
    };
    let end_type = member_type(types, list_id, "xListEnd")
        .ok_or_else(|| format!("List_t 里没有 xListEnd（list type id={list_id}, name={}）", types.get(list_id).map(|t| t.name.clone()).unwrap_or_default()))?;
    // xListEnd 可能是 MiniListItem_t（只有 xItemValue/pxNext/pxPrevious），
    // 真正带 pvOwner 的是链表节点 xLIST_ITEM，顺着 pxNext 的指针类型找过去
    let node_type = member_type(types, end_type, "pxNext")
        .and_then(|ptr| pointer_target(types, ptr))
        .filter(|id| member_offset(types, *id, "pvOwner").is_some())
        .or_else(|| {
            types.iter().position(|t| {
                t.name == "xLIST_ITEM"
                    && matches!(&t.kind, TypeKind::Struct { members } if members.iter().any(|m| m.name == "pvOwner"))
            })
        })
        .unwrap_or(end_type);
    Ok(RtosLayout {
        tcb_top: need(member_offset(types, tcb_id, "pxTopOfStack"), "pxTopOfStack")?,
        tcb_prio: need(member_offset(types, tcb_id, "uxPriority"), "uxPriority")?,
        tcb_stack: need(member_offset(types, tcb_id, "pxStack"), "pxStack")?,
        tcb_name: need(member_offset(types, tcb_id, "pcTaskName"), "pcTaskName")?,
        tcb_name_len: {
            let name_type = member_type(types, tcb_id, "pcTaskName")
                .ok_or("pcTaskName 没有类型信息")?;
            match &types.get(name_type).map(|t| &t.kind) {
                Some(TypeKind::Array { count, .. }) => (*count as usize).min(32),
                _ => 16,
            }
        },
        list_size: types.get(list_id).map(|t| t.size).unwrap_or(0).max(1),
        list_end: need(member_offset(types, list_id, "xListEnd"), "xListEnd 偏移")?,
        tcb_event: member_offset(types, tcb_id, "xEventListItem").unwrap_or(0),
        item_container: member_offset(types, node_type, "pxContainer").unwrap_or(0),
        item_next: member_offset(types, end_type, "pxNext")
            .ok_or("xListEnd 里没有 pxNext")?,
        item_owner: member_offset(types, node_type, "pvOwner")
            .ok_or_else(|| format!("链表节点类型里没有 pvOwner（node type id={node_type}, name={}）", types.get(node_type).map(|t| t.name.clone()).unwrap_or_default()))?,
    })
}

fn read_ptr(t: &mut Target, addr: u64) -> u32 {
    read_u32(t, addr).unwrap_or(0)
}

/// 走一条 FreeRTOS 链表，返回每个节点的 pvOwner（TCB 地址）
fn walk_list(t: &mut Target, layout: &RtosLayout, list_addr: u64) -> Vec<u32> {
    let mut owners = Vec::new();
    if list_addr == 0 {
        return owners;
    }
    let count = read_ptr(t, list_addr);
    if count == 0 {
        return owners;
    }
    let end = list_addr + layout.list_end;
    let mut node = read_ptr(t, end + layout.item_next);
    for _ in 0..256 {
        if node == 0 || node == end as u32 {
            break;
        }
        let owner = read_ptr(t, node as u64 + layout.item_owner);
        if owner != 0 {
            owners.push(owner);
        }
        let next = read_ptr(t, node as u64 + layout.item_next);
        if next == node {
            break;
        }
        node = next;
    }
    owners
}

/// 任务所在的链表
#[derive(Clone, Copy)]
enum Bucket {
    Ready,
    Delayed,
    Suspended,
    Termination,
}

fn read_task(t: &mut Target, layout: &RtosLayout, tcb: u64, bucket: Bucket, is_current: bool) -> Value {
    let mut name = String::new();
    for i in 0..layout.tcb_name_len {
        match read_u32(t, tcb + layout.tcb_name + i as u64) {
            Ok(word) => {
                let byte = (word & 0xff) as u8;
                if byte == 0 {
                    break;
                }
                name.push(byte as char);
            }
            Err(_) => break,
        }
    }
    let priority = read_ptr(t, tcb + layout.tcb_prio);
    let top = read_ptr(t, tcb + layout.tcb_top);
    let base = read_ptr(t, tcb + layout.tcb_stack);
    let free = top.saturating_sub(base);

    // 历史最少剩余（等价于 uxTaskGetStackHighWaterMark）：
    // 创建任务时栈被填成 0xA5，从栈底往上找到第一处被写过的位置，就是历史最深用到的地方
    let mut min_free = free;
    let span = (free as usize).min(8192);
    if span >= 4 {
        let mut buf = vec![0u8; span];
        if core_read(t, base as u64, &mut buf).is_ok() {
            for i in 0..span / 4 {
                let word = u32::from_le_bytes([buf[i * 4], buf[i * 4 + 1], buf[i * 4 + 2], buf[i * 4 + 3]]);
                if word != 0xA5A5_A5A5 {
                    min_free = (i * 4) as u32;
                    break;
                }
            }
        }
    }

    // 是否挂在某个事件链表上（等队列/信号量）：决定"延时"还是"阻塞"、真挂起还是等事件
    let on_event = layout.tcb_event != 0
        && layout.item_container != 0
        && read_ptr(t, tcb + layout.tcb_event + layout.item_container) != 0;

    let (state, rank, detail) = match bucket {
        Bucket::Ready => {
            if is_current {
                ("运行中", 0, "当前正在运行")
            } else {
                ("就绪", 1, "在就绪链表里等待调度")
            }
        }
        Bucket::Delayed => {
            if on_event {
                ("阻塞", 3, "等事件（带超时），同时在延时链表里")
            } else {
                ("延时", 2, "vTaskDelay 之类的时间等待")
            }
        }
        Bucket::Suspended => {
            if on_event {
                ("阻塞", 3, "等事件（无超时），在挂起链表里")
            } else {
                ("挂起", 4, "被 vTaskSuspend 挂起")
            }
        }
        Bucket::Termination => ("等待删除", 5, "已退出，等空闲任务回收 TCB"),
    };

    json!({
        "name": name,
        "state": state,
        "stateRank": rank,
        "stateDetail": detail,
        "priority": priority,
        "tcb": format!("0x{tcb:08X}"),
        "stackTop": format!("0x{top:08X}"),
        "stackBase": format!("0x{base:08X}"),
        "stackFree": free,
        "stackMinFree": min_free
    })
}

/// FreeRTOS 任务视图：当前任务 + 就绪/延时链表里的任务
pub fn tasks_info(t: &mut Target) -> Result<Value, String> {
    let (layout, current_addr, ready_addr, ready_count, delayed, overflow, suspended, termination, total_addr) = {
        let debug = t.debug.as_ref().ok_or("未加载符号")?;
        let find = |name: &str| debug.vars.iter().find(|v| v.name == name);
        let cur = find("pxCurrentTCB").ok_or("找不到 pxCurrentTCB：固件可能没有使用 FreeRTOS")?;
        let ready = find("pxReadyTasksLists").ok_or("找不到 pxReadyTasksLists")?;
        let delayed = find("pxDelayedTaskList").map(|v| v.addr);
        let overflow = find("pxOverflowDelayedTaskList").map(|v| v.addr);
        let suspended = find("xSuspendedTaskList").map(|v| v.addr);
        let termination = find("xTasksWaitingTermination").map(|v| v.addr);
        let total = find("uxCurrentNumberOfTasks").map(|v| v.addr);

        let tcb_id = pointer_target(&debug.types, cur.type_id)
            .ok_or("pxCurrentTCB 的类型不是指针")?;
        let (list_id, count) = match debug.types.get(ready.type_id).map(|t| &t.kind) {
            Some(TypeKind::Array { elem, count }) => (*elem, *count),
            _ => return Err("pxReadyTasksLists 不是数组".into()),
        };
        let layout = build_layout(&debug.types, tcb_id, list_id)?;
        (layout, cur.addr, ready.addr, count, delayed, overflow, suspended, termination, total)
    };
    let current_tcb = read_ptr(t, current_addr);

    let mut tasks: Vec<Value> = Vec::new();
    let mut seen: Vec<u32> = Vec::new();

    // 就绪链表（按优先级分桶，数组元素就是 List_t）
    for i in 0..ready_count {
        let list_addr = ready_addr + i * layout.list_size;
        for owner in walk_list(t, &layout, list_addr) {
            if seen.contains(&owner) {
                continue;
            }
            seen.push(owner);
            tasks.push(read_task(t, &layout, owner as u64, Bucket::Ready, current_tcb == owner));
        }
    }

    // 延时/溢出延时链表
    for var in [delayed, overflow].into_iter().flatten() {
        let list_addr = read_ptr(t, var) as u64;
        for owner in walk_list(t, &layout, list_addr) {
            if seen.contains(&owner) {
                continue;
            }
            seen.push(owner);
            tasks.push(read_task(t, &layout, owner as u64, Bucket::Delayed, current_tcb == owner));
        }
    }

    // 挂起链表（vTaskSuspend 以及等事件且没设超时的任务都在这里）与待删除链表
    for (addr, bucket) in [(suspended, Bucket::Suspended), (termination, Bucket::Termination)] {
        let Some(addr) = addr else { continue };
        for owner in walk_list(t, &layout, addr) {
            if seen.contains(&owner) {
                continue;
            }
            seen.push(owner);
            tasks.push(read_task(t, &layout, owner as u64, bucket, current_tcb == owner));
        }
    }

    let total = total_addr.map(|a| read_ptr(t, a)).unwrap_or(0);
    Ok(json!({
        "available": true,
        "total": total,
        "listed": tasks.len(),
        "tasks": tasks
    }))
}

/// Cortex-M 故障寄存器 + 异常压栈现场（Keil 那种 HardFault 分析）
pub fn fault_info(t: &mut Target) -> Result<Value, String> {
    let cfsr = read_u32(t, 0xE000_ED28).unwrap_or(0);
    let hfsr = read_u32(t, 0xE000_ED2C).unwrap_or(0);
    let mmfar = read_u32(t, 0xE000_ED34).unwrap_or(0);
    let bfar = read_u32(t, 0xE000_ED38).unwrap_or(0);

    let decoded = decode_fault(cfsr, hfsr);
    let flags: Vec<Value> = decoded
        .iter()
        .map(|(name, text)| json!({ "name": name, "text": text }))
        .collect();

    // 异常压栈现场：EXC_RETURN 的 bit2 决定用 MSP 还是 PSP
    let mut frame = Value::Null;
    {
        let mut core = t.session.as_mut().ok_or("未连接目标")?.core(0).map_err(|e| e.to_string())?;
        let lr = read_reg_named(&mut core, "R14")
            .or_else(|| read_reg_named(&mut core, "LR"))
            .unwrap_or(0);
        if (lr & 0xFFFF_FFF0) == 0xFFFF_FFF0 {
            let use_psp = lr & 4 != 0;
            let base = if use_psp {
                read_reg_named(&mut core, "PSP").unwrap_or(0)
            } else {
                read_reg_named(&mut core, "MSP").unwrap_or(0)
            };
            if base != 0 {
                let mut buf = [0u8; 32];
                if core.read_8(base as u64, &mut buf).is_ok() {
                    let w = |i: usize| u32::from_le_bytes([buf[i * 4], buf[i * 4 + 1], buf[i * 4 + 2], buf[i * 4 + 3]]);
                    frame = json!({
                        "sp": base,
                        "fromPsp": use_psp,
                        "r0": w(0), "r1": w(1), "r2": w(2), "r3": w(3),
                        "r12": w(4), "lr": w(5), "pc": w(6), "xpsr": w(7)
                    });
                }
            }
        }
    }

    Ok(json!({
        "active": !flags.is_empty(),
        "cfsr": cfsr,
        "hfsr": hfsr,
        "mmfar": mmfar,
        "bfar": bfar,
        "flags": flags,
        "frame": frame
    }))
}

pub fn detach(t: &mut Target, resume: bool) -> Result<(), String> {
    if resume {
        let _ = run_target(t);
    }
    Ok(())
}

/// 静默关闭（进程退出前把 stdout 冲干净）
pub fn flush_stdout() {
    let _ = std::io::stdout().flush();
}

#[cfg(test)]
mod tests {
    use super::decode_fault;

    fn names(cfsr: u32, hfsr: u32) -> Vec<&'static str> {
        decode_fault(cfsr, hfsr).into_iter().map(|(n, _)| n).collect()
    }

    #[test]
    fn no_fault_decodes_to_nothing() {
        assert!(names(0, 0).is_empty());
    }

    #[test]
    fn precise_bus_fault() {
        // BFSR.PRECISERR(bit9) + BFSR.BFARVALID(bit15)
        assert_eq!(names(0x0000_8200, 0), vec!["PRECISERR", "BFARVALID"]);
    }

    #[test]
    fn forced_hardfault() {
        assert_eq!(names(0, 1 << 30), vec!["FORCED"]);
    }

    #[test]
    fn usage_faults() {
        // UFSR.DIVBYZERO(bit25) + UFSR.UNALIGNED(bit24)
        assert_eq!(names(0x0300_0000, 0), vec!["UNALIGNED", "DIVBYZERO"]);
    }
}
