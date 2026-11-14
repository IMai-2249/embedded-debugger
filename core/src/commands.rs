use crate::debuginfo;
use crate::state::{AppState, BpInfo, WpInfo};
use probe_rs::config::TargetSelector;
use probe_rs::flashing::{
    download_file_with_options, BinLoader, BinOptions, DownloadOptions, ElfLoader, ElfOptions,
    HexLoader,
};
use probe_rs::probe::list::Lister;
use probe_rs::{CoreStatus, HaltReason, MemoryInterface, Permissions, Session};
use probe_rs_target::MemoryRegion;
use serde::Serialize;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};


type Shared<'a> = &'a Arc<Mutex<AppState>>;

const MAX_MEM_READ: u32 = 4096;
const MAX_DISASM: u32 = 400;

// ---------- 数据结构 ----------

#[derive(Serialize, Clone)]
pub struct ProbeItem {
    index: usize,
    identifier: String,
    vendor_id: u16,
    product_id: u16,
    serial: Option<String>,
    probe_type: String,
}

#[derive(Serialize, Clone)]
pub struct RegionInfo {
    kind: String, // "flash" | "ram" | "generic"
    start: u64,
    size: u64,
}

#[derive(Serialize, Clone)]
pub struct CoreInfo {
    index: usize,
    kind: String,
}

#[derive(Serialize, Clone)]
pub struct TargetInfo {
    target: String,
    cores: Vec<CoreInfo>,
    regions: Vec<RegionInfo>,
}

#[derive(Serialize, Clone)]
pub struct RegItem {
    name: String,
    value: String, // 32bit hex
}

#[derive(Serialize, Clone)]
pub struct MemData {
    addr: u64,
    bytes: Vec<u8>,
}

#[derive(Serialize, Clone)]
pub struct DisasmLine {
    addr: u64,
    bytes: String,
    text: String,
}

#[derive(Serialize, Clone)]
pub struct StatusInfo {
    connected: bool,
    probe: String,
    chip: String,
    target: String,
    state: String,
    /// 暂停原因（人话）: 断点命中/单步/异常中断/调试器暂停…
    reason: String,
    halted: bool,
    pc: Option<String>,
    /// 当前 PC 对应的源码位置
    src_file: Option<String>,
    src_line: Option<u32>,
    /// 当前 PC 所在函数
    func: Option<String>,
    /// 当前 FreeRTOS 任务名
    task: Option<String>,
    /// 命中的观察点变量名
    watchpoint: Option<String>,
}

#[derive(Serialize, Clone)]
pub struct HaltInfo {
    pc: String,
}

#[derive(Serialize, Clone)]
pub struct SymbolSummary {
    elf: String,
    files: Vec<String>,
    funcs: usize,
    lines: usize,
}

#[derive(Serialize, Clone)]
pub struct VarInfo {
    name: String,
    type_name: String,
    addr: u64,
}

#[derive(Serialize, Clone)]
pub struct WatchValue {
    name: String,
    type_name: String,
    value: String,
    /// 可展开的成员/元素总数（标量为 0）
    count: u64,
    error: Option<String>,
}

#[derive(Serialize, Clone)]
pub struct StepInfo {
    pc: String,
    file: Option<String>,
    line: Option<u32>,
    func: Option<String>,
    /// 非致命提示（如循环等待超时），前端弹 toast
    note: Option<String>,
}

// ---------- 内部工具 ----------

fn lock<'a>(state: &'a Shared<'a>) -> Result<std::sync::MutexGuard<'a, AppState>, String> {
    state.lock().map_err(|_| "状态锁异常".to_string())
}

fn with_core<T>(
    state: &Shared,
    f: impl FnOnce(&mut probe_rs::Core) -> Result<T, String>,
) -> Result<T, String> {
    let mut guard = lock(&state)?;
    let session = guard.session.as_mut().ok_or("未连接目标")?;
    let mut core = session.core(0).map_err(|e| format!("获取内核失败: {e}"))?;
    f(&mut core)
}

fn status_text(st: &CoreStatus) -> String {
    match st {
        CoreStatus::Running => "运行中".into(),
        CoreStatus::Halted(r) => format!("已暂停({})", halt_reason_text(r)),
        CoreStatus::Sleeping => "休眠中".into(),
        CoreStatus::LockedUp => "LOCKUP(内核死锁)".into(),
        CoreStatus::Unknown => "未知".into(),
    }
}

fn halt_reason_text(r: &HaltReason) -> &'static str {
    match r {
        HaltReason::Breakpoint(_) => "断点命中",
        HaltReason::Watchpoint => "观察点命中",
        HaltReason::Step => "单步完成",
        HaltReason::Exception => "异常/中断",
        HaltReason::Request => "调试器暂停",
        HaltReason::External => "外部暂停",
        HaltReason::Multiple => "多重原因",
        _ => "未知原因",
    }
}



// ---------- STM32 自动识别 ----------

/// DEV_ID -> (型号前缀, Flash 容量寄存器地址候选)
fn stm32_dev_info(dev: u16) -> Option<(&'static str, &'static [u64])> {
    match dev {
        // STM32F1
        0x410 | 0x412 | 0x414 | 0x418 | 0x420 | 0x428 | 0x430 => {
            Some(("STM32F10", &[0x1FFFF7E0]))
        }
        // STM32F2
        0x411 => Some(("STM32F2", &[0x1FFFC000])),
        // STM32F4
        0x413 => Some(("STM32F40", &[0x1FF0F442, 0x1FF0F42C])),
        0x419 => Some(("STM32F42", &[0x1FF0F442, 0x1FF0F42C])),
        0x421 => Some(("STM32F446", &[0x1FF0F442, 0x1FF0F42C])),
        0x423 | 0x433 => Some(("STM32F401", &[0x1FF0F442, 0x1FF0F42C])),
        0x431 => Some(("STM32F411", &[0x1FF0F442, 0x1FF0F42C])),
        0x434 => Some(("STM32F469", &[0x1FF0F442, 0x1FF0F42C])),
        // STM32F3
        0x422 => Some(("STM32F3", &[0x1FFFF7CC])),
        0x432 => Some(("STM32F37", &[0x1FFFF7CC])),
        0x438 | 0x439 => Some(("STM32F3", &[0x1FFFF7CC])),
        // STM32F7
        0x449 => Some(("STM32F74", &[0x1FF0F442])),
        0x451 => Some(("STM32F76", &[0x1FF0F442])),
        0x452 => Some(("STM32F72", &[0x1FF0F442])),
        // STM32F0
        0x440 | 0x441 | 0x442 | 0x444 | 0x445 | 0x446 | 0x448 => {
            Some(("STM32F0", &[0x1FFFF7CC]))
        }
        // STM32L4 / L5
        0x461 | 0x462 | 0x464 | 0x470 | 0x471 | 0x472 => {
            Some(("STM32L4", &[0x1FFF75E0]))
        }
        0x475 | 0x476 | 0x482 => Some(("STM32L5", &[0x0FFE_0000])),
        // STM32G0 / G4
        0x460 | 0x466 | 0x467 => Some(("STM32G0", &[0x1FFF75E0])),
        0x468 | 0x469 => Some(("STM32G4", &[0x1FFF75E0])),
        // STM32H7
        0x450 | 0x480 | 0x483 | 0x484 => Some(("STM32H7", &[0x1FF1E880, 0x1FF0F442])),
        // STM32WB / WL
        0x494 | 0x495 => Some(("STM32WB", &[0x1FFF75E0])),
        0x496 | 0x497 => Some(("STM32WL", &[0x1FFF75E0])),
        _ => None,
    }
}

/// DEV_ID 无法区分同系列内的具体子型号（如 F765/F767/F769），给一个常见型号作为默认
fn stm32_preferred_model(dev: u16) -> Option<&'static str> {
    match dev {
        0x451 => Some("STM32F767"),
        0x449 => Some("STM32F746"),
        0x452 => Some("STM32F722"),
        0x413 => Some("STM32F407"),
        0x419 => Some("STM32F429"),
        0x421 => Some("STM32F446"),
        0x423 | 0x433 => Some("STM32F401"),
        0x431 => Some("STM32F411"),
        0x434 => Some("STM32F469"),
        0x411 => Some("STM32F207"),
        0x410 | 0x412 | 0x414 | 0x418 | 0x420 | 0x428 | 0x430 => Some("STM32F103"),
        0x422 | 0x432 => Some("STM32F303"),
        0x440 | 0x441 | 0x442 | 0x444 | 0x445 | 0x446 | 0x448 => Some("STM32F030"),
        0x461 | 0x462 | 0x464 | 0x470 | 0x471 | 0x472 => Some("STM32L476"),
        0x460 | 0x466 | 0x467 => Some("STM32G070"),
        0x468 | 0x469 => Some("STM32G431"),
        0x450 | 0x480 | 0x483 | 0x484 => Some("STM32H743"),
        0x494 | 0x495 => Some("STM32WB55"),
        0x496 | 0x497 => Some("STM32WLE5"),
        _ => None,
    }
}

/// 在 probe-rs 芯片库里找所有匹配型号（同前缀 + 同 Flash 容量），偏好型号排第一
fn find_stm32_variants(prefix: &str, dev_id: u16, flash_kb: Option<u32>) -> Vec<String> {
    let registry = probe_rs::config::Registry::from_builtin_families();
    let preferred_model = stm32_preferred_model(dev_id);
    let mut all: Vec<String> = Vec::new();
    for fam in registry.families() {
        for chip in &fam.variants {
            if !chip.name.starts_with(prefix) {
                continue;
            }
            // 取最大的 NVM 区域作为 Flash 容量（避免把 OTP/选项字节算进去）
            let flash: u64 = chip
                .memory_map
                .iter()
                .filter_map(|r| match r {
                    MemoryRegion::Nvm(n) => Some(n.range.end - n.range.start),
                    _ => None,
                })
                .max()
                .unwrap_or(0);
            let size_ok = flash_kb
                .map(|kb| flash / 1024 == kb as u64)
                .unwrap_or(true);
            if size_ok && !all.contains(&chip.name) {
                all.push(chip.name.clone());
            }
        }
    }
    // 偏好型号排第一
    if let Some(pm) = preferred_model {
        if let Some(pos) = all.iter().position(|n| n.starts_with(pm)) {
            let p = all.remove(pos);
            all.insert(0, p);
        }
    }
    all
}

/// 通过通用 Cortex-M 目标连接后读取芯片 ID，返回 (型号, 候选型号, DEV_ID, Flash KB)
fn detect_stm32_via_probe(
    info: &probe_rs::probe::DebugProbeInfo,
) -> Option<(String, Vec<String>, u16, Option<u32>)> {
    for generic in ["Cortex-M7", "Cortex-M4", "Cortex-M3", "Cortex-M0"] {
        let Ok(dev) = info.open() else { continue };
        let Ok(mut session) = dev.attach(generic, Permissions::default()) else {
            continue;
        };
        let dev_id = {
            let Ok(mut core) = session.core(0) else { continue };
            // 读 DBGMCU_IDCODE（不同系列地址不同）
            let mut id = 0u16;
            for addr in [0xE004_2000u64, 0x4001_5800, 0x5C00_1000] {
                if let Ok(v) = core.read_word_32(addr) {
                    let d = (v & 0xFFF) as u16;
                    if d != 0 && d != 0xFFF {
                        id = d;
                        break;
                    }
                }
            }
            let _ = core.run();
            id
        };
        drop(session);
        if dev_id == 0 {
            continue;
        }
        let Some((prefix, flash_addrs)) = stm32_dev_info(dev_id) else {
            return Some((String::new(), Vec::new(), dev_id, None));
        };
        let mut flash_kb = None;
        // 重新连接读 Flash 容量（上一次会话已释放）
        let Ok(dev2) = info.open() else { continue };
        if let Ok(mut s2) = dev2.attach(generic, Permissions::default()) {
            if let Ok(mut c2) = s2.core(0) {
                for a in flash_addrs {
                    if let Ok(v) = c2.read_word_16(*a) {
                        if v > 0 && v < 8192 {
                            flash_kb = Some(v as u32);
                            break;
                        }
                    }
                }
                let _ = c2.run();
            }
        }
        let variants = find_stm32_variants(prefix, dev_id, flash_kb);
        let first = variants.first().cloned().unwrap_or_default();
        return Some((first, variants, dev_id, flash_kb));
    }
    None
}

// ---------- 命令 ----------

pub fn list_probes() -> Vec<ProbeItem> {
    Lister::new()
        .list_all()
        .into_iter()
        .enumerate()
        .map(|(i, p)| ProbeItem {
            index: i,
            identifier: p.identifier.clone(),
            vendor_id: p.vendor_id,
            product_id: p.product_id,
            serial: p.serial_number.clone(),
            probe_type: p.probe_type(),
        })
        .collect()
}

pub fn search_chips(query: String) -> Vec<String> {
    let registry = crate::import::registry_with_custom();
    let q = query.to_lowercase();
    let mut names = Vec::new();
    for fam in registry.families() {
        for chip in &fam.variants {
            if q.is_empty() || chip.name.to_lowercase().contains(&q) {
                names.push(chip.name.clone());
                if names.len() >= 200 {
                    return names;
                }
            }
        }
    }
    names
}

pub fn connect(
    state: Shared,
    probe: usize,
    chip: String,
) -> Result<TargetInfo, String> {
    let probes = Lister::new().list_all();
    let info = probes
        .get(probe)
        .ok_or("探针不存在，请刷新列表")?
        .clone();
    let probe_desc = format!("{} ({:04x}:{:04x})", info.identifier, info.vendor_id, info.product_id);

    // 依次尝试: 用户指定型号 → STM32 自动识别 → probe-rs 自动识别
    let mut selectors: Vec<TargetSelector> = Vec::new();
    let name = chip.trim().to_string();
    if !name.is_empty() {
        selectors.push(name.clone().into());
    } else if let Some((detected, _, _, _)) = detect_stm32_via_probe(&info) {
        if !detected.is_empty() {
            selectors.push(detected.into());
        }
    }
    selectors.push(TargetSelector::Auto);

    let mut session: Option<Session> = None;
    let mut last_err = String::new();
    for sel in selectors {
        let dev = match info.open() {
            Ok(d) => d,
            Err(e) => return Err(format!("打开探针失败: {e}")),
        };
        let registry = crate::import::registry_with_custom();
        match dev.attach_with_registry(sel, Permissions::default(), &registry) {
            Ok(s) => {
                session = Some(s);
                break;
            }
            Err(e) => last_err = format!("{e}"),
        }
    }
    let mut session = session.ok_or_else(|| {
        if name.is_empty() {
            format!("无法自动识别芯片（{last_err}）。请在上方输入芯片型号，或点「芯片库」选择（如 STM32F767ZI）")
        } else {
            format!("attach 失败: {last_err}（检查 SWD 接线/供电，或换芯片名）")
        }
    })?;

    let target_name = session.target().name.clone();
    let cores = session
        .list_cores()
        .into_iter()
        .map(|(i, t)| CoreInfo { index: i, kind: format!("{t:?}") })
        .collect();
    let regions = session
        .target()
        .memory_map
        .iter()
        .map(|r| match r {
            MemoryRegion::Nvm(n) => RegionInfo {
                kind: "flash".into(),
                start: n.range.start,
                size: n.range.end - n.range.start,
            },
            MemoryRegion::Ram(m) => RegionInfo {
                kind: "ram".into(),
                start: m.range.start,
                size: m.range.end - m.range.start,
            },
            MemoryRegion::Generic(g) => RegionInfo {
                kind: "generic".into(),
                start: g.range.start,
                size: g.range.end - g.range.start,
            },
        })
        .collect();

    // 开启 HardFault 向量捕获（故障瞬间暂停）
    if let Ok(mut core) = session.core(0) {
        let _ = crate::fault::enable_vector_catch(&mut core);
    }

    let target_info = TargetInfo { target: target_name, cores, regions };

    let mut guard = lock(&state)?;
    // 丢弃旧会话（若有），接管新会话
    guard.session = Some(session);
    guard.chip = if name.is_empty() { target_info.target.clone() } else { name };
    guard.probe_desc = probe_desc;

    Ok(target_info)
}

pub fn disconnect(state: Shared) -> Result<(), String> {
    let mut guard = lock(&state)?;
    if let Some(session) = guard.session.as_mut() {
        if let Ok(mut core) = session.core(0) {
            crate::dwt::disable_all(&mut core);
        }
    }
    guard.session = None; // Session Drop 即 detach
    guard.watchpoints.clear();
    guard.rtt = None;
    Ok(())
}

pub fn get_status(state: Shared) -> StatusInfo {
    let mut guard = match lock(&state) {
        Ok(g) => g,
        Err(e) => {
            return StatusInfo {
                connected: false,
                probe: String::new(),
                chip: String::new(),
                target: String::new(),
                state: e,
                reason: String::new(),
                halted: false,
                pc: None,
                src_file: None,
                src_line: None,
                func: None,
                task: None,
                watchpoint: None,
            }
        }
    };
    let app = &mut *guard;
    let probe_desc = app.probe_desc.clone();
    let chip = app.chip.clone();
    let debug = app.debug.as_ref();

    let (connected, target, state_text, reason, halted, pc, pc_val, watchpoint) =
        match app.session.as_mut() {
        None => (
            false,
            String::new(),
            "未连接".to_string(),
            String::new(),
            false,
            None,
            None,
            None,
        ),
        Some(s) => {
            let target = s.target().name.to_string();
            match s.core(0) {
                Ok(mut core) => match core.status() {
                    Ok(st) => {
                        let halted = st.is_halted();
                        let mut reason = match &st {
                            CoreStatus::Halted(r) => halt_reason_text(r).to_string(),
                            _ => String::new(),
                        };
                        let pc_val = if halted {
                            let pc_reg = core.program_counter().id();
                            core.read_core_reg::<u32>(pc_reg).ok()
                        } else {
                            None
                        };
                        let pc = pc_val.map(|v| format!("0x{v:08x}"));
                        // 观察点命中: 以 DWT MATCHED 位为准(probe-rs 有时报 Multiple)
                        let mut watchpoint = None;
                        if halted {
                            let units = crate::dwt::matched_units(&mut core);
                            if !units.is_empty() {
                                watchpoint = app
                                    .watchpoints
                                    .iter()
                                    .find(|w| units.contains(&w.unit))
                                    .map(|w| w.name.clone());
                                crate::dwt::clear_matched(&mut core);
                                reason = "观察点命中".into();
                            }
                        }
                        (true, target, status_text(&st), reason, halted, pc, pc_val, watchpoint)
                    }
                    Err(e) => (
                        true,
                        target,
                        format!("状态读取失败: {e}"),
                        String::new(),
                        false,
                        None,
                        None,
                        None,
                    ),
                },
                Err(e) => (
                    true,
                    target,
                    format!("内核获取失败: {e}"),
                    String::new(),
                    false,
                    None,
                    None,
                    None,
                ),
            }
        }
    };

    // 当前任务名（FreeRTOS）: 缓存 1.5s，减少轮询时的 USB 读取
    let task = if let Some(d) = debug {
        let stale = app
            .last_task_at
            .map(|t| t.elapsed() > Duration::from_millis(1500))
            .unwrap_or(true);
        if stale {
            let t = app.session.as_mut().and_then(|s| {
                let mut core = s.core(0).ok()?;
                crate::rtos::current_task_name(d, &mut |addr, buf| {
                    core.read_8(addr, buf).map_err(|e| e.to_string())
                })
            });
            app.last_task = t.clone();
            app.last_task_at = Some(std::time::Instant::now());
            t
        } else {
            app.last_task.clone()
        }
    } else {
        None
    };

    // PC -> 源码位置
    let (src_file, src_line, func) = match (pc_val, debug) {
        (Some(pc), Some(d)) => {
            let loc = d.addr_to_line(pc as u64);
            (
                loc.map(|(f, _)| d.files[f].clone()),
                loc.map(|(_, l)| l),
                d.func_at(pc as u64).map(|f| f.name.clone()),
            )
        }
        _ => (None, None, None),
    };

    StatusInfo {
        connected,
        probe: probe_desc,
        chip,
        target,
        state: state_text,
        reason,
        halted,
        pc,
        src_file,
        src_line,
        func,
        task,
        watchpoint,
    }
}

pub fn halt(state: Shared) -> Result<HaltInfo, String> {
    with_core(&state, |core| {
        let info = core
            .halt(Duration::from_secs(2))
            .map_err(|e| format!("halt 失败: {e}"))?;
        Ok(HaltInfo { pc: format!("0x{:08x}", info.pc) })
    })
}

pub fn resume(state: Shared) -> Result<(), String> {
    with_core(&state, |core| {
        crate::fault::clear_faults(core);
        core.run().map_err(|e| format!("resume 失败: {e}"))
    })
}

pub fn reset(state: Shared, halt: bool) -> Result<HaltInfo, String> {
    with_core(&state, |core| {
        let info = if halt {
            core.reset_and_halt(Duration::from_secs(2))
                .map_err(|e| format!("复位(halt)失败: {e}"))?
        } else {
            core.reset().map_err(|e| format!("复位失败: {e}"))?;
            return Ok(HaltInfo { pc: String::new() });
        };
        Ok(HaltInfo { pc: format!("0x{:08x}", info.pc) })
    })
}

pub fn step(state: Shared) -> Result<HaltInfo, String> {
    with_core(&state, |core| {
        // 运行中先暂停再单步
        if !core
            .status()
            .map_err(|e| format!("读状态失败: {e}"))?
            .is_halted()
        {
            core.halt(Duration::from_secs(2))
                .map_err(|e| format!("halt 失败: {e}"))?;
        }
        let info = core.step().map_err(|e| format!("单步失败: {e}"))?;
        Ok(HaltInfo { pc: format!("0x{:08x}", info.pc) })
    })
}

pub fn read_registers(state: Shared) -> Result<Vec<RegItem>, String> {
    with_core(&state, |core| {
        let mut out = Vec::new();
        for reg in core.registers().all_registers() {
            if reg.size_in_bits() > 32 {
                continue;
            }
            match core.read_core_reg::<u32>(reg.id()) {
                Ok(v) => out.push(RegItem {
                    name: reg.name().to_string(),
                    value: format!("0x{:08x}", v),
                }),
                Err(_) => continue,
            }
        }
        Ok(out)
    })
}

pub fn read_memory(state: Shared, addr: u64, size: u32) -> Result<MemData, String> {
    let size = size.min(MAX_MEM_READ);
    with_core(&state, |core| {
        let mut bytes = vec![0u8; size as usize];
        core.read_8(addr, &mut bytes)
            .map_err(|e| format!("读内存失败: {e}"))?;
        Ok(MemData { addr, bytes })
    })
}

pub fn disasm(state: Shared, addr: u64, count: u32) -> Result<Vec<DisasmLine>, String> {
    let count = count.min(MAX_DISASM);
    let byte_len = (count * 4) as usize;
    with_core(&state, |core| {
        let mut bytes = vec![0u8; byte_len];
        core.read_8(addr, &mut bytes)
            .map_err(|e| format!("读取代码失败: {e}"))?;

        use capstone::arch::{arm, BuildsCapstone};
        use capstone::Capstone;
        let cs = Capstone::new()
            .arm()
            .mode(arm::ArchMode::Thumb)
            .build()
            .map_err(|e| format!("初始化反汇编器失败: {e}"))?;
        let insns = cs
            .disasm_all(&bytes, addr)
            .map_err(|e| format!("反汇编失败: {e}"))?;

        let mut out = Vec::new();
        for i in insns.iter() {
            let bytes_str = i
                .bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(" ");
            let text = format!(
                "{} {}",
                i.mnemonic().unwrap_or("(无法解码)"),
                i.op_str().unwrap_or("")
            );
            out.push(DisasmLine { addr: i.address(), bytes: bytes_str, text: text.trim_end().into() });
        }
        Ok(out)
    })
}

pub fn load_symbols(state: Shared, path: String) -> Result<SymbolSummary, String> {
    let info = debuginfo::load_elf(&path)?;
    let summary = SymbolSummary {
        elf: path,
        files: info.files.clone(),
        funcs: info.funcs.len(),
        lines: info.entries.len(),
    };
    let mut guard = lock(&state)?;
    let app = &mut *guard;
    // 换符号前清掉已装断点，避免看不见的悬空断点
    if let Some(session) = app.session.as_mut() {
        if let Ok(mut core) = session.core(0) {
            for bp in &app.breakpoints {
                let _ = core.clear_hw_breakpoint(bp.addr);
            }
        }
    }
    app.breakpoints.clear();
    app.watchpoints.clear();
    app.debug = Some(info);
    Ok(summary)
}

pub fn read_source(path: String) -> Result<String, String> {
    let meta = std::fs::metadata(&path).map_err(|e| format!("文件不可访问: {e}"))?;
    if meta.len() > 8 * 1024 * 1024 {
        return Err("文件过大（>8MB），拒绝加载".into());
    }
    std::fs::read_to_string(&path).map_err(|e| format!("读取源码失败: {e}"))
}

// ---------- 断点 ----------

pub fn set_breakpoint(state: Shared, file: String, line: u32) -> Result<BpInfo, String> {
    let mut guard = lock(&state)?;
    let app = &mut *guard;
    // 精确行优先；无代码则吸附到 ±40 行内最近的可执行行（同 Keil 体验）
    let (actual_line, addr) = {
        let debug = app
            .debug
            .as_ref()
            .ok_or("未加载符号文件，无法按源码行设断点")?;
        debug
            .resolve_line(&file, line)
            .ok_or("附近 40 行内没有可执行代码（该文件可能没有调试信息）")?
    };
    if app.breakpoints.iter().any(|b| b.addr == addr) {
        return Err("该位置已有断点".into());
    }
    {
        let session = app.session.as_mut().ok_or("未连接目标")?;
        let mut core = session.core(0).map_err(|e| format!("获取内核失败: {e}"))?;
        core.set_hw_breakpoint(addr)
            .map_err(|e| format!("设置断点失败: {e}（硬件断点数量有限，请先清除不用的断点）"))?;
    }
    let bp = BpInfo { addr, file, line: actual_line };
    app.breakpoints.push(bp.clone());
    Ok(bp)
}

pub fn clear_breakpoint(state: Shared, addr: u64) -> Result<(), String> {
    let mut guard = lock(&state)?;
    let app = &mut *guard;
    if let Some(session) = app.session.as_mut() {
        if let Ok(mut core) = session.core(0) {
            core.clear_hw_breakpoint(addr)
                .map_err(|e| format!("清除断点失败: {e}"))?;
        }
    }
    app.breakpoints.retain(|b| b.addr != addr);
    Ok(())
}

pub fn list_breakpoints(state: Shared) -> Result<Vec<BpInfo>, String> {
    let guard = lock(&state)?;
    Ok(guard.breakpoints.clone())
}

// ---------- 源码级单步 ----------

pub fn step_line(state: Shared, mode: String) -> Result<StepInfo, String> {
    let mut guard = lock(&state)?;
    let app = &mut *guard;
    let user_bps: Vec<u64> = app.breakpoints.iter().map(|b| b.addr).collect();
    let debug = app.debug.as_ref();
    let session = app.session.as_mut().ok_or("未连接目标")?;
    let mut core = session.core(0).map_err(|e| format!("获取内核失败: {e}"))?;

    let result = crate::stepper::step_line(&mut core, debug, mode.as_str(), &user_bps)?;
    Ok(make_step_info(debug, result.pc, result.note))
}

fn make_step_info(debug: Option<&crate::debuginfo::DebugInfo>, pc: u64, note: Option<String>) -> StepInfo {
    let loc = debug.and_then(|d| d.addr_to_line(pc));
    let file = match (loc, debug) {
        (Some((f, _)), Some(d)) => Some(d.files[f].clone()),
        _ => None,
    };
    StepInfo {
        pc: format!("0x{pc:08x}"),
        file,
        line: loc.map(|(_, l)| l),
        func: debug.and_then(|d| d.func_at(pc)).map(|f| f.name.clone()),
        note,
    }
}

/// 运行到光标处
pub fn run_to(state: Shared, file: String, line: u32) -> Result<StepInfo, String> {
    let mut guard = lock(&state)?;
    let app = &mut *guard;
    let user_bps: Vec<u64> = app.breakpoints.iter().map(|b| b.addr).collect();
    let debug = app.debug.as_ref();
    let session = app.session.as_mut().ok_or("未连接目标")?;
    let mut core = session.core(0).map_err(|e| format!("获取内核失败: {e}"))?;
    let result = crate::stepper::run_to_line(&mut core, debug, &file, line, &user_bps)?;
    Ok(make_step_info(debug, result.pc, result.note))
}

pub fn flash(state: Shared, path: String) -> Result<String, String> {
    let started = Instant::now();
    let lower = path.to_lowercase();
    let mut guard = lock(&state)?;
    let session = guard.session.as_mut().ok_or("未连接目标")?;
    // 通用调试型号（Cortex-M7 等免导入目标）没有 Flash 算法，无法烧录
    if session.target().flash_algorithms.is_empty() {
        return Err(
            "当前连接的是通用调试型号，不含 Flash 算法，无法烧录。\
             请点「芯片库 → 导入厂商芯片包 (.pack)」导入芯片描述，或选择具体型号后重新连接"
                .into(),
        );
    }
    let result = if lower.ends_with(".hex") {
        download_file_with_options(session, &path, HexLoader, DownloadOptions::default())
    } else if lower.ends_with(".bin") {
        download_file_with_options(session, &path, BinLoader(BinOptions::default()), DownloadOptions::default())
    } else {
        download_file_with_options(session, &path, ElfLoader(ElfOptions::default()), DownloadOptions::default())
    };
    result.map_err(|e| format!("烧录失败: {e}"))?;
    Ok(format!("烧录完成，耗时 {:.1}s", started.elapsed().as_secs_f32()))
}

// ---------- Watch 变量 ----------

pub fn list_variables(state: Shared, filter: String) -> Result<Vec<VarInfo>, String> {
    let guard = lock(&state)?;
    let debug = guard.debug.as_ref().ok_or("未加载符号文件")?;
    let f = filter.to_lowercase();
    let mut out: Vec<VarInfo> = debug
        .vars
        .iter()
        .filter(|v| f.is_empty() || v.name.to_lowercase().contains(&f))
        .map(|v| VarInfo {
            name: v.name.clone(),
            type_name: v.type_name.clone(),
            addr: v.addr,
        })
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out.truncate(300);
    Ok(out)
}

pub fn read_watches(state: Shared, names: Vec<String>) -> Result<Vec<WatchValue>, String> {
    let mut guard = lock(&state)?;
    let app = &mut *guard;
    let debug = app.debug.as_ref().ok_or("未加载符号文件")?;
    let session = app.session.as_mut().ok_or("未连接目标")?;
    let mut core = session.core(0).map_err(|e| format!("获取内核失败: {e}"))?;

    let mut out = Vec::new();
    for name in names {
        let var = debug.vars.iter().find(|v| v.name == name).cloned();
        match var {
            Some(var) => {
                let tsize = debug.types[var.type_id].size;
                let size = tsize.clamp(1, 256) as usize;
                let mut bytes = vec![0u8; size];
                let count = match &debug.types[var.type_id].kind {
                    crate::variables::TypeKind::Array { count, .. } => *count,
                    crate::variables::TypeKind::Struct { members } => members.len() as u64,
                    _ => 0,
                };
                match core.read_8(var.addr, &mut bytes) {
                    Ok(()) => {
                        let (value, _) =
                            crate::variables::format_var(&debug.types, var.type_id, &bytes, false);
                        out.push(WatchValue {
                            name,
                            type_name: var.type_name.clone(),
                            value,
                            count,
                            error: None,
                        });
                    }
                    Err(e) => out.push(WatchValue {
                        name,
                        type_name: var.type_name.clone(),
                        value: String::new(),
                        count,
                        error: Some(format!("读内存失败: {e}")),
                    }),
                }
            }
            None => out.push(WatchValue {
                name: name.clone(),
                type_name: String::new(),
                value: String::new(),
                count: 0,
                error: Some("符号不存在".into()),
            }),
        }
    }
    Ok(out)
}

/// 分页读取数组元素/结构体成员（Watch 面板展开与滚动加载）
pub fn read_watch_members(
    state: Shared,
    name: String,
    start: u32,
    limit: u32,
) -> Result<Vec<(String, String)>, String> {
    let limit = limit.min(200);
    let mut guard = lock(&state)?;
    let app = &mut *guard;
    let debug = app.debug.as_ref().ok_or("未加载符号文件")?;
    let var = debug
        .vars
        .iter()
        .find(|v| v.name == name)
        .cloned()
        .ok_or("符号不存在")?;
    let session = app.session.as_mut().ok_or("未连接目标")?;
    let mut core = session.core(0).map_err(|e| format!("获取内核失败: {e}"))?;
    let t = &debug.types[var.type_id];

    match &t.kind {
        crate::variables::TypeKind::Array { elem, count } => {
            let esize = debug.types[*elem].size.max(1);
            let start = (start as u64).min(*count);
            let n = (*count - start).min(limit as u64) as usize;
            let len = (n as u64 * esize) as usize;
            let mut bytes = vec![0u8; len.max(1)];
            core.read_8(var.addr + start * esize, &mut bytes)
                .map_err(|e| format!("读内存失败: {e}"))?;
            let mut out = Vec::with_capacity(n);
            for i in 0..n {
                let off = i * esize as usize;
                let end = (off + esize as usize).min(bytes.len());
                let (v, _) = crate::variables::format_var(
                    &debug.types,
                    *elem,
                    &bytes[off..end],
                    false,
                );
                out.push((format!("[{}]", start + i as u64), v));
            }
            Ok(out)
        }
        crate::variables::TypeKind::Struct { members } => {
            let size = t.size.clamp(1, 4096) as usize;
            let mut bytes = vec![0u8; size];
            core.read_8(var.addr, &mut bytes)
                .map_err(|e| format!("读内存失败: {e}"))?;
            let start = start as usize;
            let mut out = Vec::new();
            for m in members.iter().skip(start).take(limit as usize) {
                let off = m.offset as usize;
                let msize = debug.types[m.type_id].size as usize;
                let val = if msize > 0 && off + msize <= bytes.len() {
                    crate::variables::format_var(
                        &debug.types,
                        m.type_id,
                        &bytes[off..off + msize],
                        false,
                    )
                    .0
                } else if off < bytes.len() {
                    crate::variables::format_var(&debug.types, m.type_id, &bytes[off..], false).0
                } else {
                    "<越界>".into()
                };
                out.push((m.name.clone(), val));
            }
            Ok(out)
        }
        _ => Ok(Vec::new()),
    }
}

// ---------- 调用栈 ----------

#[derive(Serialize, Clone)]
pub struct FrameInfo {
    pc: String,
    func: Option<String>,
    file: Option<String>,
    line: Option<u32>,
}

#[derive(Serialize, Clone)]
pub struct CallStack {
    frames: Vec<FrameInfo>,
    /// true = CFI 不可用, 使用了栈扫描启发式
    heuristic: bool,
}

pub fn call_stack(state: Shared) -> Result<CallStack, String> {
    let mut guard = lock(&state)?;
    let app = &mut *guard;
    let debug = app.debug.as_ref().ok_or("未加载符号文件")?;
    let session = app.session.as_mut().ok_or("未连接目标")?;
    let mut core = session.core(0).map_err(|e| format!("获取内核失败: {e}"))?;
    if !core
        .status()
        .map_err(|e| format!("读状态失败: {e}"))?
        .is_halted()
    {
        return Err("目标运行中，暂停后才能查看调用栈".into());
    }
    let mut regs = [0u32; 16];
    for (i, slot) in regs.iter_mut().enumerate() {
        let reg = core.registers().core_register(i);
        *slot = core
            .read_core_reg::<u32>(reg.id())
            .map_err(|e| format!("读 R{i} 失败: {e}"))?;
    }
    let (frames, heuristic) = crate::cfi::unwind(debug, regs, |addr, buf| {
        core.read_8(addr, buf).map_err(|e| e.to_string())
    });
    Ok(CallStack {
        frames: frames
            .into_iter()
            .map(|f| FrameInfo {
                pc: format!("0x{:08x}", f.pc),
                func: f.func,
                file: f.file,
                line: f.line,
            })
            .collect(),
        heuristic,
    })
}

// ---------- FreeRTOS 任务感知 ----------

#[derive(Serialize, Clone)]
pub struct TaskItem {
    name: String,
    state: String,
    priority: u32,
    tcb: String,
    stack_base: String,
    stack_top: String,
    /// 栈上剩余 0xa5 填充字数（越小越危险）
    free_words: Option<u32>,
    current: bool,
    /// 任务当前停在哪
    pc: Option<String>,
    func: Option<String>,
}

#[derive(Serialize, Clone)]
pub struct RtosSnapshotInfo {
    current: Option<String>,
    tasks: Vec<TaskItem>,
}

pub fn rtos_tasks(state: Shared) -> Result<RtosSnapshotInfo, String> {
    let mut guard = lock(&state)?;
    let app = &mut *guard;
    let debug = app.debug.as_ref().ok_or("未加载符号文件")?;
    let session = app.session.as_mut().ok_or("未连接目标")?;
    let mut core = session.core(0).map_err(|e| format!("获取内核失败: {e}"))?;
    let mut snap = crate::rtos::snapshot(debug, &mut |addr, buf| {
        core.read_8(addr, buf).map_err(|e| e.to_string())
    })?;
    // 当前运行中的任务用实时 PC（保存帧是上次切出时的旧值）
    if core
        .status()
        .map_err(|e| format!("读状态失败: {e}"))?
        .is_halted()
    {
        if let Ok(pc) = core.read_core_reg::<u32>(core.program_counter().id()) {
            if let Some(t) = snap.tasks.iter_mut().find(|t| t.current) {
                t.pc = Some(pc);
                t.func = debug.func_at((pc & !1) as u64).map(|f| f.name.clone());
            }
        }
    }
    Ok(RtosSnapshotInfo {
        current: snap.current,
        tasks: snap
            .tasks
            .into_iter()
            .map(|t| TaskItem {
                name: t.name,
                state: t.state,
                priority: t.priority,
                tcb: format!("0x{:08x}", t.tcb),
                stack_base: format!("0x{:08x}", t.stack_base),
                stack_top: format!("0x{:08x}", t.stack_top),
                free_words: t.free_words,
                current: t.current,
                pc: t.pc.map(|p| format!("0x{p:08x}")),
                func: t.func,
            })
            .collect(),
    })
}

// ---------- 数据观察点 ----------

pub fn set_watchpoint(state: Shared, name: String, kind: String) -> Result<WpInfo, String> {
    let mut guard = lock(&state)?;
    let app = &mut *guard;
    let var = app
        .debug
        .as_ref()
        .ok_or("未加载符号文件")?
        .vars
        .iter()
        .find(|v| v.name == name)
        .cloned()
        .ok_or("符号不存在")?;
    if app.watchpoints.iter().any(|w| w.name == name) {
        return Err("该变量已有观察点".into());
    }
    let used: Vec<usize> = app.watchpoints.iter().map(|w| w.unit).collect();
    let unit = (0..crate::dwt::MAX_UNITS)
        .find(|u| !used.contains(u))
        .ok_or("观察点单元已用满（最多 4 个）")?;
    {
        let session = app.session.as_mut().ok_or("未连接目标")?;
        let mut core = session.core(0).map_err(|e| format!("获取内核失败: {e}"))?;
        crate::dwt::configure(&mut core, unit, var.addr as u32, &kind)?;
    }
    let wp = WpInfo {
        name,
        addr: var.addr,
        kind,
        unit,
    };
    app.watchpoints.push(wp.clone());
    Ok(wp)
}

pub fn clear_watchpoint(state: Shared, addr: u64) -> Result<(), String> {
    let mut guard = lock(&state)?;
    let app = &mut *guard;
    let unit = app
        .watchpoints
        .iter()
        .find(|w| w.addr == addr)
        .map(|w| w.unit);
    if let Some(unit) = unit {
        if let Some(session) = app.session.as_mut() {
            if let Ok(mut core) = session.core(0) {
                let _ = crate::dwt::disable(&mut core, unit);
            }
        }
    }
    app.watchpoints.retain(|w| w.addr != addr);
    Ok(())
}

pub fn list_watchpoints(state: Shared) -> Result<Vec<WpInfo>, String> {
    let guard = lock(&state)?;
    Ok(guard.watchpoints.clone())
}

// ---------- 局部变量 ----------

#[derive(Serialize, Clone)]
pub struct LocalValue {
    name: String,
    type_name: String,
    value: String,
    members: Vec<(String, String)>,
    error: Option<String>,
}

/// 解析 location list: 返回当前 PC 生效的规则
fn resolve_loc<'a>(
    loc: &'a crate::variables::LocalLoc,
    pc: u64,
) -> Option<&'a crate::variables::LocalLoc> {
    match loc {
        crate::variables::LocalLoc::List(entries) => entries
            .iter()
            .find(|e| pc >= e.start && pc < e.end)
            .map(|e| &e.loc),
        other => Some(other),
    }
}

/// 读取指定帧的局部变量
fn collect_locals(
    debug: &crate::debuginfo::DebugInfo,
    core: &mut probe_rs::Core<'_>,
    pc: u64,
    cfa: u64,
    regs: Option<&[u32; 16]>,
) -> Result<Vec<LocalValue>, String> {
    let fl = debug
        .func_locals(pc)
        .ok_or("该帧没有函数级调试信息")?;
    let frame_base = match &fl.frame_base {
        crate::variables::FrameBase::Cfa => cfa as i64,
        crate::variables::FrameBase::Reg(r, off) => match regs {
            Some(rs) if (*r as usize) < 16 => rs[*r as usize] as i64 + off,
            _ => cfa as i64,
        },
    };

    let mut out = Vec::new();
    for v in &fl.vars {
        // location list: 选当前 PC 对应的那段规则; 无有效段则跳过(已被优化)
        let Some(loc) = resolve_loc(&v.loc, pc) else { continue };
        let t = &debug.types[v.type_id];
        let size = t.size.clamp(1, 256) as usize;
        let res: Result<Vec<u8>, String> = match loc {
            crate::variables::LocalLoc::Reg(r) => match regs {
                Some(rs) if (*r as usize) < 16 => Ok(rs[*r as usize].to_le_bytes().to_vec()),
                _ => Err("寄存器值不可用（非当前帧）".into()),
            },
            crate::variables::LocalLoc::AddrRegOff(r, off) => match regs {
                Some(rs) if (*r as usize) < 16 => {
                    let addr = (rs[*r as usize] as i64 + off) as u32;
                    let mut b = vec![0u8; size];
                    core.read_8(addr as u64, &mut b)
                        .map(|_| b)
                        .map_err(|e| format!("读内存失败: {e}"))
                }
                _ => Err("寄存器值不可用（非当前帧）".into()),
            },
            crate::variables::LocalLoc::AddrFbReg(off) => {
                let addr = (frame_base + off) as u32;
                let mut b = vec![0u8; size];
                core.read_8(addr as u64, &mut b)
                    .map(|_| b)
                    .map_err(|e| format!("读内存失败: {e}"))
            }
            crate::variables::LocalLoc::AddrCfa => {
                let mut b = vec![0u8; size];
                core.read_8(cfa, &mut b)
                    .map(|_| b)
                    .map_err(|e| format!("读内存失败: {e}"))
            }
            crate::variables::LocalLoc::Const(v) => {
                let mut b = vec![0u8; size];
                let le = (*v as u64).to_le_bytes();
                let n = size.min(8);
                b[..n].copy_from_slice(&le[..n]);
                Ok(b)
            }
            crate::variables::LocalLoc::List(_) => Err("位置规则不支持".into()),
        };
        match res {
            Ok(bytes) => {
                let (value, members) =
                    crate::variables::format_var(&debug.types, v.type_id, &bytes, true);
                out.push(LocalValue {
                    name: v.name.clone(),
                    type_name: v.type_name.clone(),
                    value,
                    members,
                    error: None,
                });
            }
            Err(e) => out.push(LocalValue {
                name: v.name.clone(),
                type_name: v.type_name.clone(),
                value: String::new(),
                members: vec![],
                error: Some(e),
            }),
        }
    }
    out.truncate(100);
    Ok(out)
}

fn read_live_regs(core: &mut probe_rs::Core<'_>) -> Result<[u32; 16], String> {
    let mut regs = [0u32; 16];
    for (i, slot) in regs.iter_mut().enumerate() {
        *slot = core
            .read_core_reg::<u32>(core.registers().core_register(i).id())
            .map_err(|e| format!("读 R{i} 失败: {e}"))?;
    }
    Ok(regs)
}

/// 当前帧局部变量
pub fn local_vars(state: Shared) -> Result<Vec<LocalValue>, String> {
    let mut guard = lock(&state)?;
    let app = &mut *guard;
    let debug = app.debug.as_ref().ok_or("未加载符号文件")?;
    let session = app.session.as_mut().ok_or("未连接目标")?;
    let mut core = session.core(0).map_err(|e| format!("获取内核失败: {e}"))?;
    if !core
        .status()
        .map_err(|e| format!("读状态失败: {e}"))?
        .is_halted()
    {
        return Err("目标运行中，暂停后才能查看局部变量".into());
    }
    let regs = read_live_regs(&mut core)?;
    let pc = (regs[15] & !1) as u64;
    let cfa = crate::cfi::cfa_of(debug, pc, regs[13]);
    collect_locals(debug, &mut core, pc, cfa, Some(&regs))
}

/// 调用栈第 index 帧的局部变量（0 = 当前帧）
pub fn frame_locals(state: Shared, index: usize) -> Result<Vec<LocalValue>, String> {
    let mut guard = lock(&state)?;
    let app = &mut *guard;
    let debug = app.debug.as_ref().ok_or("未加载符号文件")?;
    let session = app.session.as_mut().ok_or("未连接目标")?;
    let mut core = session.core(0).map_err(|e| format!("获取内核失败: {e}"))?;
    if !core
        .status()
        .map_err(|e| format!("读状态失败: {e}"))?
        .is_halted()
    {
        return Err("目标运行中，暂停后才能查看局部变量".into());
    }
    let regs = read_live_regs(&mut core)?;
    let (frames, _) = crate::cfi::unwind(debug, regs, |addr, buf| {
        core.read_8(addr, buf).map_err(|e| e.to_string())
    });
    let f = frames.get(index).ok_or("调用栈帧不存在")?;
    let regs_opt = if index == 0 { Some(&regs) } else { None };
    collect_locals(debug, &mut core, f.pc, f.cfa, regs_opt)
}

/// 任意任务（帧 0）的局部变量
pub fn task_locals(state: Shared, name: String) -> Result<Vec<LocalValue>, String> {
    let mut guard = lock(&state)?;
    let app = &mut *guard;
    let debug = app.debug.as_ref().ok_or("未加载符号文件")?;
    let session = app.session.as_mut().ok_or("未连接目标")?;
    let mut core = session.core(0).map_err(|e| format!("获取内核失败: {e}"))?;

    let snap = crate::rtos::snapshot(debug, &mut |addr, buf| {
        core.read_8(addr, buf).map_err(|e| e.to_string())
    })?;
    let task = snap
        .tasks
        .iter()
        .find(|t| t.name == name)
        .ok_or("任务不存在")?;

    let regs = if task.current {
        if !core
            .status()
            .map_err(|e| format!("读状态失败: {e}"))?
            .is_halted()
        {
            return Err("查看当前任务局部变量需先暂停".into());
        }
        read_live_regs(&mut core)?
    } else {
        crate::rtos::task_regs(debug, task.tcb, &mut |addr, buf| {
            core.read_8(addr, buf).map_err(|e| e.to_string())
        })
        .ok_or("无法重建任务上下文（任务可能尚未启动）")?
    };

    let (frames, _) = crate::cfi::unwind(debug, regs, |addr, buf| {
        core.read_8(addr, buf).map_err(|e| e.to_string())
    });
    let f = frames.first().ok_or("无调用帧")?;
    collect_locals(debug, &mut core, f.pc, f.cfa, Some(&regs))
}

/// 任意任务的调用栈（从 TCB 保存的上下文回溯；当前任务用实时寄存器）
pub fn task_stack(state: Shared, name: String) -> Result<Vec<FrameInfo>, String> {
    let mut guard = lock(&state)?;
    let app = &mut *guard;
    let debug = app.debug.as_ref().ok_or("未加载符号文件")?;
    let session = app.session.as_mut().ok_or("未连接目标")?;
    let mut core = session.core(0).map_err(|e| format!("获取内核失败: {e}"))?;

    let snap = crate::rtos::snapshot(debug, &mut |addr, buf| {
        core.read_8(addr, buf).map_err(|e| e.to_string())
    })?;
    let task = snap
        .tasks
        .iter()
        .find(|t| t.name == name)
        .ok_or("任务不存在")?;

    let regs = if task.current {
        if !core
            .status()
            .map_err(|e| format!("读状态失败: {e}"))?
            .is_halted()
        {
            return Err("查看当前任务调用栈需先暂停".into());
        }
        read_live_regs(&mut core)?
    } else {
        crate::rtos::task_regs(debug, task.tcb, &mut |addr, buf| {
            core.read_8(addr, buf).map_err(|e| e.to_string())
        })
        .ok_or("无法重建任务上下文（任务可能尚未启动）")?
    };

    let (frames, _) = crate::cfi::unwind(debug, regs, |addr, buf| {
        core.read_8(addr, buf).map_err(|e| e.to_string())
    });
    Ok(frames
        .into_iter()
        .map(|f| FrameInfo {
            pc: format!("0x{:08x}", f.pc),
            func: f.func,
            file: f.file,
            line: f.line,
        })
        .collect())
}

// ---------- 故障诊断 ----------

#[derive(Serialize, Clone)]
pub struct FaultReport {
    active: bool,
    /// 故障原因（人话）
    flags: Vec<String>,
    /// 故障地址（MMFAR/BFAR）
    fault_addr: Option<String>,
    /// 压栈帧
    pc: Option<String>,
    lr: Option<String>,
    func: Option<String>,
    file: Option<String>,
    line: Option<u32>,
    /// 故障发生时所在任务（FreeRTOS）
    task: Option<String>,
    /// MSP / PSP
    stack: String,
}

pub fn fault_info(state: Shared) -> Result<Option<FaultReport>, String> {
    let mut guard = lock(&state)?;
    let app = &mut *guard;
    let debug = app.debug.as_ref();
    let session = app.session.as_mut().ok_or("未连接目标")?;
    let mut core = session.core(0).map_err(|e| format!("获取内核失败: {e}"))?;

    let faults = crate::fault::read_faults(&mut core);
    if !faults.active() {
        return Ok(None);
    }

    let mut pc = None;
    let mut lr = None;
    let mut func = None;
    let mut file = None;
    let mut line = None;
    let mut stack = String::new();

    if let Some(sf) = crate::fault::stacked_frame(&mut core) {
        pc = Some(format!("0x{:08x}", sf.pc));
        lr = Some(format!("0x{:08x}", sf.lr));
        stack = if sf.from_psp { "PSP(任务栈)".into() } else { "MSP(主栈)".into() };
        if let Some(d) = debug {
            if let Some((f, l)) = d.addr_to_line((sf.pc & !1) as u64) {
                file = Some(d.files[f].clone());
                line = Some(l);
            }
            func = d.func_at((sf.pc & !1) as u64).map(|f| f.name.clone());
        }
    }

    // 故障时所在任务
    let task = debug.and_then(|d| {
        crate::rtos::current_task_name(d, &mut |addr, buf| {
            core.read_8(addr, buf).map_err(|e| e.to_string())
        })
    });

    Ok(Some(FaultReport {
        active: true,
        flags: faults.flags(),
        fault_addr: faults.fault_addr().map(|a| format!("0x{a:08x}")),
        pc,
        lr,
        func,
        file,
        line,
        task,
        stack,
    }))
}

/// 从目标内存映射中找一个未映射地址（用于故障注入，不依赖具体芯片）
fn pick_unmapped(session: &Session) -> u32 {
    let ranges: Vec<(u64, u64)> = session
        .target()
        .memory_map
        .iter()
        .filter_map(|r| match r {
            MemoryRegion::Nvm(n) => Some((n.range.start, n.range.end)),
            MemoryRegion::Ram(m) => Some((m.range.start, m.range.end)),
            MemoryRegion::Generic(g) => Some((g.range.start, g.range.end)),
        })
        .collect();
    let mut addr = 0x1000_0000u64;
    while addr < 0xE000_0000 {
        if !ranges.iter().any(|(s, e)| addr >= *s && addr < *e) {
            return addr as u32;
        }
        addr += 0x1_0000;
    }
    0x3000_0000
}

/// 测试用: 注入一次真实 HardFault（PC 指向未映射地址并单步）
/// 不影响 Flash/代码, 测完复位即可恢复
pub fn inject_fault(state: Shared) -> Result<(), String> {
    let mut guard = lock(&state)?;
    let app = &mut *guard;
    let session = app.session.as_mut().ok_or("未连接目标")?;
    let bad = pick_unmapped(session);
    let mut core = session.core(0).map_err(|e| format!("获取内核失败: {e}"))?;
    if !core
        .status()
        .map_err(|e| format!("读状态失败: {e}"))?
        .is_halted()
    {
        core.halt(Duration::from_secs(2))
            .map_err(|e| format!("halt 失败: {e}"))?;
    }
    crate::fault::clear_faults(&mut core);
    let pc_reg = core.program_counter().id();
    core.write_core_reg::<u32>(pc_reg, bad | 1)
        .map_err(|e| format!("写 PC 失败: {e}"))?;
    // 单步一条指令: 取指总线错误 -> HardFault
    let _ = core.step();
    Ok(())
}

// ---------- RTT 日志 ----------

#[derive(Serialize, Clone)]
pub struct RttChannelInfo {
    index: usize,
    name: String,
    up: bool,
    size: usize,
}

#[derive(Serialize, Clone)]
pub struct RttChunk {
    channel: usize,
    data: String,
}

pub fn rtt_start(state: Shared) -> Result<Vec<RttChannelInfo>, String> {
    let mut guard = lock(&state)?;
    let app = &mut *guard;
    let session = app.session.as_mut().ok_or("未连接目标")?;
    let has_ram = session
        .target()
        .memory_map
        .iter()
        .any(|r| matches!(r, probe_rs::config::MemoryRegion::Ram(_)));
    let mut core = session.core(0).map_err(|e| format!("获取内核失败: {e}"))?;
    // 通用调试型号没有内存映射，按典型 RAM 区（0x20000000 + 256KB）扫描
    let scan = probe_rs::rtt::ScanRegion::Ranges(vec![0x2000_0000..0x2004_0000]);
    let rtt_result = if has_ram {
        probe_rs::rtt::Rtt::attach(&mut core)
    } else {
        probe_rs::rtt::Rtt::attach_region(&mut core, &scan)
    };
    let mut rtt = rtt_result.map_err(|e| format!("未找到 RTT 控制块（固件需集成 SEGGER RTT）: {e}"))?;
    let mut chans = Vec::new();
    for (i, ch) in rtt.up_channels.iter_mut().enumerate() {
        chans.push(RttChannelInfo {
            index: i,
            name: ch.name().unwrap_or("").to_string(),
            up: true,
            size: ch.buffer_size(),
        });
    }
    for (i, ch) in rtt.down_channels.iter_mut().enumerate() {
        chans.push(RttChannelInfo {
            index: i,
            name: ch.name().unwrap_or("").to_string(),
            up: false,
            size: ch.buffer_size(),
        });
    }
    app.rtt = Some(rtt);
    Ok(chans)
}

pub fn rtt_poll(state: Shared, limit: u32) -> Result<Vec<RttChunk>, String> {
    let mut guard = lock(&state)?;
    let app = &mut *guard;
    let session = app.session.as_mut().ok_or("未连接目标")?;
    let mut core = session.core(0).map_err(|e| format!("获取内核失败: {e}"))?;
    let rtt = app.rtt.as_mut().ok_or("RTT 未启动")?;
    let limit = limit.clamp(256, 65536) as usize;
    let mut out = Vec::new();
    let mut buf = vec![0u8; limit];
    for (i, ch) in rtt.up_channels.iter_mut().enumerate() {
        let mut chunk = Vec::new();
        loop {
            match ch.read(&mut core, &mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    chunk.extend_from_slice(&buf[..n]);
                    if chunk.len() >= limit {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        if !chunk.is_empty() {
            out.push(RttChunk {
                channel: i,
                data: String::from_utf8_lossy(&chunk).into_owned(),
            });
        }
    }
    Ok(out)
}

pub fn rtt_write(state: Shared, channel: usize, text: String) -> Result<(), String> {
    let mut guard = lock(&state)?;
    let app = &mut *guard;
    let session = app.session.as_mut().ok_or("未连接目标")?;
    let mut core = session.core(0).map_err(|e| format!("获取内核失败: {e}"))?;
    let rtt = app.rtt.as_mut().ok_or("RTT 未启动")?;
    let ch = rtt
        .down_channels
        .get_mut(channel)
        .ok_or("下行通道不存在")?;
    let n = ch
        .write(&mut core, text.as_bytes())
        .map_err(|e| format!("写 RTT 失败: {e}"))?;
    if n < text.len() {
        return Err(format!("只写入了 {n}/{} 字节（缓冲区满）", text.len()));
    }
    Ok(())
}

pub fn rtt_stop(state: Shared) -> Result<(), String> {
    let mut guard = lock(&state)?;
    guard.rtt = None;
    Ok(())
}

#[derive(Serialize, Clone)]
pub struct DetectResult {
    chip: String,
    /// 同系列同容量的全部候选（封装不同，无法从芯片读出）
    candidates: Vec<String>,
    dev_id: String,
    flash_kb: Option<u32>,
}

pub fn detect_chip(probe: usize) -> Result<DetectResult, String> {
    let probes = Lister::new().list_all();
    let info = probes.get(probe).ok_or("探针不存在，请刷新列表")?.clone();
    let (chip, candidates, dev_id, flash_kb) =
        detect_stm32_via_probe(&info).ok_or("自动识别失败：无法读取芯片 ID（检查接线/供电）")?;
    if chip.is_empty() {
        return Err(format!(
            "识别到 STM32 DEV_ID=0x{dev_id:03x}{}，但芯片库中没有匹配型号，请手动选择",
            flash_kb.map(|k| format!(" / {k}KB")).unwrap_or_default()
        ));
    }
    Ok(DetectResult {
        chip,
        candidates,
        dev_id: format!("0x{dev_id:03x}"),
        flash_kb,
    })
}


/// 芯片系列列表（芯片库浏览用）
pub fn list_chip_families() -> Vec<String> {
    let registry = crate::import::registry_with_custom();
    registry.families().iter().map(|f| f.name.clone()).collect()
}

/// 某个系列下的全部型号
pub fn list_family_variants(family: String) -> Vec<String> {
    let registry = crate::import::registry_with_custom();
    for fam in registry.families() {
        if fam.name == family {
            let mut names: Vec<String> = fam.variants.iter().map(|c| c.name.clone()).collect();
            names.sort();
            return names;
        }
    }
    Vec::new()
}
