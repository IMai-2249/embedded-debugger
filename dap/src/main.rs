//! 嵌入式调试器 VS Code 调试适配器
//!
//! DAP over stdio：VS Code 扩展拉起本进程，通过 Content-Length 帧协议通信。
//! 调试核心复用主工程的 Rust 模块（stepper/cfi/debuginfo/variables）。

mod protocol;
mod session;
mod svd;

use protocol::{read_message, Sender};
use serde_json::{json, Value};
use session::{LaunchArgs, Target};
use std::io::{self, BufReader};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

struct State {
    target: Option<Target>,
    chip: String,
    frames: Vec<session::DapFrame>,
    running: bool,
    /// launch(烧录) = 停在入口; attach = 保持运行
    stop_at_entry: bool,
    was_flashed: bool,
    /// 可展开变量的引用号 -> (地址, 类型 id)
    children: std::collections::HashMap<u64, (u64, usize)>,
    next_ref: u64,
    /// 反汇编缓存：(file, 函数入口) -> 完整响应。PC 在已缓存函数内移动时不再重新反汇编。
    disasm_cache: Option<((String, u64), Value)>,
    /// SVD 设备描述（svdLoad 加载后可用）
    svd: Option<svd::SvdDevice>,
}

fn main() {
    // 命令行模式：导入厂商 CMSIS-Pack（由编辑器扩展调用）
    // ed-dap.exe --import-pack <xxx.pack>
    let argv: Vec<String> = std::env::args().collect();
    if argv.len() >= 3 && argv[1] == "--import-pack" {
        match embedded_debugger_lib::import::import_pack_sync(&argv[2], &|_| {}) {
            Ok(result) => {
                let variants: usize = result.families.iter().map(|f| f.variants.len()).sum();
                println!(
                    "OK 导入 {}：{} 个系列 / {} 个型号",
                    result.pack,
                    result.families.len(),
                    variants
                );
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("导入失败: {e}");
                std::process::exit(1);
            }
        }
    }

    // ed-dap.exe --list-probes ：列出探针（JSON）
    if argv.len() >= 2 && argv[1] == "--list-probes" {
        println!("{}", serde_json::to_string(&session::list_probes()).unwrap_or_else(|_| "[]".into()));
        std::process::exit(0);
    }

    // ed-dap.exe --recover [serial] ：复位保持下握手再释放（目标跑飞/低功耗后的恢复）
    if argv.len() >= 2 && argv[1] == "--recover" {
        match session::recover(argv.get(2).cloned()) {
            Ok(v) => {
                println!("{}", serde_json::to_string(&v).unwrap_or_else(|_| "{}".into()));
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("恢复失败: {e}");
                std::process::exit(1);
            }
        }
    }

    // ed-dap.exe --dp-check ：只做 SWD 协议握手（不加载芯片描述），用于诊断连接问题
    if argv.len() >= 2 && argv[1] == "--dp-check" {
        match session::dp_check(argv.get(2).cloned()) {
            Ok(v) => {
                println!("{}", serde_json::to_string(&v).unwrap_or_else(|_| "{}".into()));
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("DP 诊断失败: {e}");
                std::process::exit(1);
            }
        }
    }

    // ed-dap.exe --list-chips [query] ：列出芯片库（JSON）
    if argv.len() >= 2 && argv[1] == "--list-chips" {
        let q = argv.get(2).map(|s| s.as_str()).unwrap_or("");
        let list = session::list_chips(q);
        println!("{}", serde_json::to_string(&list).unwrap_or_else(|_| "[]".into()));
        std::process::exit(0);
    }

    // ed-dap.exe --identify <chip> [serial] ：识别芯片（读 DBGMCU_IDCODE）
    if argv.len() >= 3 && argv[1] == "--identify" {
        let cfg = session::LaunchArgs {
            chip: argv[2].clone(),
            elf: String::new(),
            flash: false,
            probe_index: 0,
            probe_serial: argv.get(3).cloned(),
        };
        match session::identify_chip(&cfg) {
            Ok(info) => {
                println!("{}", serde_json::to_string(&info).unwrap_or_else(|_| "{}".into()));
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("识别失败: {e}");
                std::process::exit(1);
            }
        }
    }

    // ed-dap.exe --erase <chip> [serial] ：整片擦除
    if argv.len() >= 3 && argv[1] == "--erase" {
        let cfg = session::LaunchArgs {
            chip: argv[2].clone(),
            elf: String::new(),
            flash: false,
            probe_index: 0,
            probe_serial: argv.get(3).cloned(),
        };
        println!("正在整片擦除 {}", cfg.chip);
        match session::erase_chip(&cfg) {
            Ok(()) => {
                println!("擦除完成");
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(1);
            }
        }
    }

    // ed-dap.exe --flash <chip> <elf> [serial] ：只烧录，不调试
    if argv.len() >= 4 && argv[1] == "--flash" {
        let cfg = session::LaunchArgs {
            chip: argv[2].clone(),
            elf: argv[3].clone(),
            flash: true,
            probe_index: 0,
            probe_serial: argv.get(4).cloned(),
        };
        println!("正在烧录 {} → {}", cfg.elf, cfg.chip);
        match session::flash_only(&cfg) {
            Ok(()) => {
                println!("烧录完成，已复位运行");
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("烧录失败: {e}");
                std::process::exit(1);
            }
        }
    }

    let sender = Arc::new(Sender::new(Box::new(io::stdout())));
    let seq = Arc::new(AtomicU64::new(1));
    let state = Arc::new(Mutex::new(State {
        target: None,
        chip: String::new(),
        frames: Vec::new(),
        running: false,
        stop_at_entry: false,
        was_flashed: false,
        children: std::collections::HashMap::new(),
        next_ref: 100_000,
        disasm_cache: None,
        svd: None,
    }));

    // 停机监视: 运行中每 150ms 查一次状态, 停下即发 stopped 事件
    {
        let sender = sender.clone();
        let seq = seq.clone();
        let state = state.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_millis(150));
            let stopped = {
                let mut s = state.lock().unwrap();
                if !s.running {
                    continue;
                }
                let halted = s
                    .target
                    .as_mut()
                    .and_then(|t| t.session.core(0).ok())
                    .and_then(|mut c| c.status().ok())
                    .map(|st| st.is_halted())
                    .unwrap_or(false);
                if halted {
                    s.running = false;
                    true
                } else {
                    false
                }
            };
            if stopped {
                let is_bp = {
                    let mut s = state.lock().unwrap();
                    let pc = session::pc_of(s.target.as_mut().unwrap()).unwrap_or(0);
                    s.target
                        .as_ref()
                        .map(|t| t.bps.iter().any(|(_, _, a)| *a == (pc & !1)))
                        .unwrap_or(false)
                };
                event(&sender, &seq, "stopped", json!({
                    "reason": if is_bp { "breakpoint" } else { "pause" },
                    "description": if is_bp { "断点命中" } else { "已暂停" },
                    "threadId": 1,
                    "allThreadsStopped": true,
                }));
            }
        });
    }

    let stdin = io::stdin();
    let mut reader = BufReader::new(stdin.lock());

    loop {
        let Some(msg) = read_message(&mut reader) else { break };
        let typ = msg.get("type").and_then(|x| x.as_str()).unwrap_or("");
        if typ != "request" {
            continue;
        }
        let cmd = msg.get("command").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let _ = &cmd;
        let req_seq = msg.get("seq").and_then(|x| x.as_u64()).unwrap_or(0);
        let args = msg.get("arguments").cloned().unwrap_or(Value::Null);
        eprintln!("[ed-dap] REQ {} (seq {})", cmd, req_seq);

        match cmd.as_str() {
            "initialize" => {
                reply(&sender, &seq, req_seq, &cmd, true, Some(json!({
                    "supportsConfigurationDoneRequest": true,
                    "supportsTerminateRequest": true,
                    "supportsEvaluateForHovers": true,
                    "supportsSetVariable": true,
                    "supportsReadMemoryRequest": false,
                    "supportsRestartRequest": true,
                    "supportsDisassembleRequest": true,
                    "exceptionBreakpointFilters": [],
                    "supportedChecksumAlgorithms": [],
                })), None);
            }
            "launch" | "attach" => {
                let flash = args.get("flash").and_then(|x| x.as_bool()).unwrap_or(cmd == "launch");
                match LaunchArgs::from_value(&args).and_then(|cfg| session::attach(&cfg)) {
                    Ok(t) => {
                        let mut s = state.lock().unwrap();
                        s.chip = t.session.target().name.clone();
                        s.stop_at_entry = flash;
                        s.was_flashed = flash;
                        s.target = Some(t);
                        s.disasm_cache = None;
                        drop(s);
                        reply(&sender, &seq, req_seq, &cmd, true, None, None);
                        event(&sender, &seq, "initialized", json!({}));
                    }
                    Err(e) => {
                        reply(&sender, &seq, req_seq, &cmd, false, None, Some(e));
                    }
                }
            }
            "setBreakpoints" => {
                let r = with_target(&state, |t| {
                    let file = args
                        .pointer("/source/path")
                        .and_then(|x| x.as_str())
                        .ok_or("缺少 source.path")?
                        .to_string();
                    let lines: Vec<u32> = args
                        .get("breakpoints")
                        .and_then(|x| x.as_array())
                        .map(|a| a.iter().filter_map(|b| b.get("line").and_then(|l| l.as_u64())).map(|l| l as u32).collect())
                        .or_else(|| args.get("lines").and_then(|x| x.as_array()).map(|a| a.iter().filter_map(|l| l.as_u64()).map(|l| l as u32).collect()))
                        .unwrap_or_default();
                    Ok(session::set_breakpoints(t, &file, &lines)?)
                });
                match r {
                    Ok(bps) => reply(&sender, &seq, req_seq, &cmd, true, Some(json!({ "breakpoints": bps })), None),
                    Err(e) => reply(&sender, &seq, req_seq, &cmd, false, None, Some(e)),
                }
            }
            "ed/sourceDisassembly" => {
                let file = args
                    .get("file")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();
                let pc = args.get("pc").and_then(|x| x.as_u64()).unwrap_or(0);
                // 命中缓存（同一文件、PC 在已反汇编函数内）就直接回，跨函数单步不再等重反汇编
                let cached = state.lock().unwrap().disasm_cache.as_ref().and_then(|((f, entry), v)| {
                    if *f == file && pc >= *entry {
                        Some(v.clone())
                    } else {
                        None
                    }
                });
                if let Some(v) = cached {
                    reply(&sender, &seq, req_seq, &cmd, true, Some(v), None);
                    break;
                }
                let r = with_target(&state, |t| session::source_disassembly(t, &file, pc));
                match r {
                    Ok(v) => {
                        let entry = v
                            .get("rows")
                            .and_then(|rows| rows.get(0))
                            .and_then(|row| row.get("instructions"))
                            .and_then(|list| list.get(0))
                            .and_then(|ins| ins.get("address"))
                            .and_then(|a| a.as_str())
                            .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
                            .unwrap_or(pc);
                        state.lock().unwrap().disasm_cache = Some(((file, entry), v.clone()));
                        reply(&sender, &seq, req_seq, &cmd, true, Some(v), None);
                    }
                    Err(e) => reply(&sender, &seq, req_seq, &cmd, false, None, Some(e)),
                }
            }
            "ed/state" => {
                let r = with_target(&state, |t| session::halted(t));
                match r {
                    Ok(halted) => reply(
                        &sender,
                        &seq,
                        req_seq,
                        &cmd,
                        true,
                        Some(json!({ "halted": halted })),
                        None,
                    ),
                    Err(e) => reply(&sender, &seq, req_seq, &cmd, false, None, Some(e)),
                }
            }
            "ed/svdLoad" => {
                // args: { file } —— 读取并解析 SVD；芯片库同目录的 SVD 或用户指定路径
                let file = args.get("file").and_then(|x| x.as_str()).unwrap_or("").to_string();
                eprintln!("[ed-dap] svdLoad file={} ", file);
                match std::fs::read_to_string(&file) {
                    Ok(xml) => { eprintln!("[ed-dap] svdLoad read ok len={}", xml.len()); match svd::SvdDevice::parse(&xml) {
                        Ok(device) => {
                            let list: Vec<Value> = device
                                .peripherals
                                .iter()
                                .map(|p| json!({
                                    "name": p.name,
                                    "description": p.description,
                                    "baseAddress": format!("0x{:08X}", p.base_address),
                                    "registerCount": p.registers.len(),
                                }))
                                .collect();
                            let device_name = device.name.clone();
                            let count = device.peripherals.len();
                            state.lock().unwrap().svd = Some(device);
                            reply(&sender, &seq, req_seq, &cmd, true, Some(json!({
                                "device": device_name,
                                "peripheralCount": count,
                                "peripherals": list,
                            })), None);
                        }
                        Err(e) => { eprintln!("[ed-dap] svdLoad parse fail: {e}"); reply(&sender, &seq, req_seq, &cmd, false, None, Some(format!("SVD 解析失败: {e}"))); } }
                    },
                    Err(e) => { eprintln!("[ed-dap] svdLoad read fail: {e}"); reply(&sender, &seq, req_seq, &cmd, false, None, Some(format!("读不到 SVD 文件 {}: {e}", file))) },
                }
            }
            "ed/svdRead" => {
                // args: { peripheral } —— 读该外设全部寄存器当前值
                let pname = args.get("peripheral").and_then(|x| x.as_str()).unwrap_or("").to_string();
                let svd = state.lock().unwrap().svd.clone();
                let Some(device) = svd else {
                    reply(&sender, &seq, req_seq, &cmd, false, None, Some("SVD 未加载（先 ed/svdLoad）".to_string()));
                    break;
                };
                let Some(p) = device.peripheral(&pname).cloned() else {
                    reply(&sender, &seq, req_seq, &cmd, false, None, Some(format!("SVD 里没有外设 {pname}")));
                    break;
                };
                let r = with_target(&state, |t| {
                    let mut core = t.session.core(0).map_err(|e| e.to_string())?;
                    svd::read_peripheral(&mut core, &p)
                });
                match r {
                    Ok(v) => reply(&sender, &seq, req_seq, &cmd, true, Some(v), None),
                    Err(e) => reply(&sender, &seq, req_seq, &cmd, false, None, Some(e)),
                }
            }
            "ed/svdWrite" => {
                // args: { peripheral, register, value } —— 按寄存器名写值
                let pname = args.get("peripheral").and_then(|x| x.as_str()).unwrap_or("").to_string();
                let rname = args.get("register").and_then(|x| x.as_str()).unwrap_or("").to_string();
                let value = args.get("value").and_then(|x| x.as_u64()).unwrap_or(0);
                let svd = state.lock().unwrap().svd.clone();
                let Some(device) = svd else {
                    reply(&sender, &seq, req_seq, &cmd, false, None, Some("SVD 未加载".to_string()));
                    break;
                };
                let Some(p) = device.peripheral(&pname).cloned() else {
                    reply(&sender, &seq, req_seq, &cmd, false, None, Some(format!("SVD 里没有外设 {pname}")));
                    break;
                };
                let Some(reg) = p.registers.iter().find(|r| r.name == rname).cloned() else {
                    reply(&sender, &seq, req_seq, &cmd, false, None, Some(format!("{} 里没有寄存器 {}", pname, rname)));
                    break;
                };
                let addr = p.base_address + reg.offset;
                let r = with_target(&state, |t| {
                    use probe_rs::MemoryInterface;
                    let mut core = t.session.core(0).map_err(|e| e.to_string())?;
                    if reg.size == 8 {
                        core.write_8(addr, &[value as u8]).map_err(|e| e.to_string())
                    } else {
                        core.write_word_32(addr, value as u32).map_err(|e| e.to_string())
                    }
                });
                match r {
                    Ok(()) => reply(&sender, &seq, req_seq, &cmd, true, Some(json!({ "address": format!("0x{:08X}", addr) })), None),
                    Err(e) => reply(&sender, &seq, req_seq, &cmd, false, None, Some(e)),
                }
            }
            "ed/tasks" => {
                let r = with_target(&state, |t| session::tasks_info(t));
                match r {
                    Ok(v) => reply(&sender, &seq, req_seq, &cmd, true, Some(v), None),
                    Err(e) => reply(&sender, &seq, req_seq, &cmd, false, None, Some(e)),
                }
            }
            "ed/fault" => {
                let r = with_target(&state, |t| session::fault_info(t));
                match r {
                    Ok(v) => reply(&sender, &seq, req_seq, &cmd, true, Some(v), None),
                    Err(e) => reply(&sender, &seq, req_seq, &cmd, false, None, Some(e)),
                }
            }
            "ed/writeRegister" => {
                let name = args
                    .get("name")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();
                let value = args.get("value").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
                let r = with_target(&state, |t| session::write_register(t, &name, value));
                match r {
                    Ok(()) => reply(&sender, &seq, req_seq, &cmd, true, None, None),
                    Err(e) => reply(&sender, &seq, req_seq, &cmd, false, None, Some(e)),
                }
            }
            "ed/writeMemory" => {
                let addr = args.get("address").and_then(|x| x.as_u64()).unwrap_or(0);
                let data = args
                    .get("data")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();
                let r = with_target(&state, |t| session::write_memory(t, addr, &data));
                match r {
                    Ok(()) => reply(&sender, &seq, req_seq, &cmd, true, None, None),
                    Err(e) => reply(&sender, &seq, req_seq, &cmd, false, None, Some(e)),
                }
            }
            "ed/readMemory" => {
                let addr = args.get("address").and_then(|x| x.as_u64()).unwrap_or(0);
                let len = args.get("length").and_then(|x| x.as_u64()).unwrap_or(256) as usize;
                let r = with_target(&state, |t| session::read_memory(t, addr, len));
                match r {
                    Ok(data) => reply(
                        &sender,
                        &seq,
                        req_seq,
                        &cmd,
                        true,
                        Some(json!({ "address": addr, "data": data })),
                        None,
                    ),
                    Err(e) => reply(&sender, &seq, req_seq, &cmd, false, None, Some(e)),
                }
            }
            "configurationDone" => {
                reply(&sender, &seq, req_seq, &cmd, true, None, None);
                // 烧录启动: 复位 → 重建用户断点 → 运行。
                // 有断点: 直接停在用户断点上(监视线程发 stopped); 无断点: 停在 main 兜底
                let mut entry_desc = String::new();
                {
                    let mut s = state.lock().unwrap();
                    if s.stop_at_entry {
                        s.stop_at_entry = false;
                        if let Some(t) = &mut s.target {
                            if !t.bps.is_empty() {
                                match session::reset_and_run_to_user_bps(t) {
                                    Ok(()) => s.running = true,
                                    Err(e) => {
                                        eprintln!("run-to-bps 失败: {e}");
                                        entry_desc = "已复位并暂停".into();
                                    }
                                }
                            } else {
                                match session::run_to_main_after_reset(t) {
                                    Ok(()) => entry_desc = "已停在 main（无断点）".into(),
                                    Err(e) => {
                                        eprintln!("run-to-main 失败: {e}");
                                        entry_desc = "已复位并暂停".into();
                                    }
                                }
                            }
                        }
                    } else if let Some(t) = &mut s.target {
                        // 不烧录调试：连上就停住，直接看现场（要跑再按继续）
                        match session::halt_target(t) {
                            Ok(pc) => entry_desc = format!("已连接并暂停（PC=0x{pc:08X}，未烧录）"),
                            Err(e) => {
                                eprintln!("halt 失败: {e}");
                                let _ = session::run_target(t);
                                s.running = true;
                            }
                        }
                    }
                }
                if !entry_desc.is_empty() {
                    event(&sender, &seq, "stopped", json!({
                        "reason": "entry", "description": entry_desc, "threadId": 1, "allThreadsStopped": true
                    }));
                }
            }
            "threads" => {
                let name = state.lock().unwrap().chip.clone();
                reply(&sender, &seq, req_seq, &cmd, true, Some(json!({
                    "threads": [{ "id": 1, "name": if name.is_empty() { "Cortex-M".into() } else { name } }]
                })), None);
            }
            "stackTrace" => {
                let r = with_target(&state, |t| session::stack_frames(t));
                match r {
                    Ok(frames) => {
                        let body = json!({
                            "stackFrames": frames.iter().map(|f| json!({
                                "id": f.id,
                                "name": f.name,
                                "source": f.file.as_ref().map(|p| json!({
                                    "name": p.split(['\\', '/']).last().unwrap_or(p),
                                    "path": p,
                                })).unwrap_or(Value::Null),
                                "line": f.line.unwrap_or(1),
                                "column": 1,
                                "instructionPointerReference": format!("0x{:08x}", f.pc),
                            })).collect::<Vec<_>>(),
                            "totalFrames": frames.len(),
                        });
                        state.lock().unwrap().frames = frames;
                        reply(&sender, &seq, req_seq, &cmd, true, Some(body), None);
                    }
                    Err(e) => reply(&sender, &seq, req_seq, &cmd, false, None, Some(e)),
                }
            }
            "scopes" => {
                let frame = args.get("frameId").and_then(|x| x.as_u64()).unwrap_or(1) as usize;
                reply(&sender, &seq, req_seq, &cmd, true, Some(json!({
                    "scopes": [
                        { "name": "局部变量", "variablesReference": 1000 + frame, "expensive": false },
                        { "name": "全局变量", "variablesReference": 1, "expensive": true },
                        { "name": "寄存器", "variablesReference": 2, "expensive": true },
                    ]
                })), None);
            }
            "variables" => {
                let ref_id = args.get("variablesReference").and_then(|x| x.as_u64()).unwrap_or(0);
                // 先取帧（不能在 with_target 的锁内再锁 state —— 会死锁）
                let frame = if ref_id >= 1000 {
                    state.lock().unwrap().frames.iter().find(|f| f.id == (ref_id - 1000) as usize).cloned()
                } else {
                    None
                };
                // 展开子项：查表 -> 读内存
                if ref_id >= 100_000 {
                    let entry = state.lock().unwrap().children.get(&ref_id).copied();
                    let r = match entry {
                        Some((addr, type_id)) => with_target(&state, |t| {
                            let types = t.debug.as_ref().map(|d| d.types.clone()).unwrap_or_default();
                            session::children(t, addr, type_id).map(|vars| {
                                vars.into_iter()
                                    .map(|v| {
                                    let can = v.addr.is_some() && session::expandable(&types, v.type_id);
                                    (v, can)
                                })
                                    .collect::<Vec<_>>()
                            })
                        }),
                        None => Err("变量已失效（重新暂停后刷新）".to_string()),
                    };
                    match r {
                        Ok(vars) => {
                            let mut st = state.lock().unwrap();
                            let out: Vec<Value> = vars
                                .into_iter()
                                .map(|(v, can_expand)| {
                                    let reference = if can_expand {
                                        let id = st.next_ref;
                                        st.next_ref += 1;
                                        st.children.insert(id, (v.addr.unwrap_or(0), v.type_id));
                                        id
                                    } else {
                                        0
                                    };
                                    json!({
                                        "name": v.name, "type": v.type_name, "value": v.value,
                                        "variablesReference": reference
                                    })
                                })
                                .collect();
                            reply(&sender, &seq, req_seq, &cmd, true, Some(json!({ "variables": out })), None);
                        }
                        Err(e) => reply(&sender, &seq, req_seq, &cmd, false, None, Some(e)),
                    }
                } else {
                    let r = with_target(&state, |t| -> Result<Vec<(session::VarOut, bool)>, String> {
                        let types = t.debug.as_ref().map(|d| d.types.clone()).unwrap_or_default();
                        let vars: Vec<session::VarOut> = match ref_id {
                            1 => session::globals(t)?,
                            2 => session::registers(t)?
                                .into_iter()
                                .map(|(name, ty, value)| session::VarOut {
                                    name,
                                    type_name: ty,
                                    value,
                                    addr: None,
                                    type_id: usize::MAX,
                                })
                                .collect(),
                            r if r >= 1000 => session::locals(t, &frame.ok_or("帧已过期（重新暂停后刷新）")?)?,
                            _ => return Err("未知变量引用".into()),
                        };
                        Ok(vars
                            .into_iter()
                            .map(|v| {
                                let can = v.addr.is_some() && session::expandable(&types, v.type_id);
                                (v, can)
                            })
                            .collect::<Vec<_>>())
                    });
                    match r {
                        Ok(vars) => {
                            let mut st = state.lock().unwrap();
                            let out: Vec<Value> = vars
                                .into_iter()
                                .map(|(v, can_expand)| {
                                    let reference = if can_expand {
                                        let id = st.next_ref;
                                        st.next_ref += 1;
                                        st.children.insert(id, (v.addr.unwrap_or(0), v.type_id));
                                        id
                                    } else {
                                        0
                                    };
                                    json!({
                                        "name": v.name, "type": v.type_name, "value": v.value,
                                        "variablesReference": reference
                                    })
                                })
                                .collect();
                            reply(&sender, &seq, req_seq, &cmd, true, Some(json!({ "variables": out })), None);
                        }
                        Err(e) => reply(&sender, &seq, req_seq, &cmd, false, None, Some(e)),
                    }
                }
            }
            "setVariable" => {
                let ref_id = args.get("variablesReference").and_then(|x| x.as_u64()).unwrap_or(0);
                let name = args.get("name").and_then(|x| x.as_str()).unwrap_or("").to_string();
                let value = args.get("value").and_then(|x| x.as_str()).unwrap_or("").to_string();
                let frame = if (1000..100_000).contains(&ref_id) {
                    state.lock().unwrap().frames.iter().find(|f| f.id == (ref_id - 1000) as usize).cloned()
                } else {
                    None
                };
                let child = if ref_id >= 100_000 {
                    state.lock().unwrap().children.get(&ref_id).copied()
                } else {
                    None
                };

                let r = with_target(&state, |t| {
                    // 寄存器作用域
                    if ref_id == 2 {
                        let v = session::parse_number(&value)? as u32;
                        session::write_register(t, &name, v)?;
                        return Ok::<String, String>(format!("0x{v:08x}"));
                    }
                    let (addr, type_id) = if let Some((addr, type_id)) = child {
                        let kids = session::children(t, addr, type_id)?;
                        let target = kids
                            .into_iter()
                            .find(|k| k.name == name)
                            .ok_or_else(|| format!("找不到子变量 {name}"))?;
                        (target.addr.unwrap_or(0), target.type_id)
                    } else {
                        let var = session::evaluate(t, &name, frame.clone())?;
                        (
                            var.addr.ok_or("该变量没有固定地址（可能只在寄存器里）")?,
                            var.type_id,
                        )
                    };
                    session::write_value(t, addr, type_id, &value)?;
                    // 回读显示值
                    if let Some((paddr, ptype)) = child {
                        let kids = session::children(t, paddr, ptype)?;
                        Ok(kids
                            .into_iter()
                            .find(|k| k.name == name)
                            .map(|k| k.value)
                            .unwrap_or_else(|| value.clone()))
                    } else {
                        Ok(session::evaluate(t, &name, frame.clone())
                            .map(|v| v.value)
                            .unwrap_or_else(|_| value.clone()))
                    }
                });

                match r {
                    Ok(shown) => reply(
                        &sender,
                        &seq,
                        req_seq,
                        &cmd,
                        true,
                        Some(json!({ "value": shown })),
                        None,
                    ),
                    Err(e) => reply(&sender, &seq, req_seq, &cmd, false, None, Some(e)),
                }
            }
            "continue" => {
                {
                    let mut st = state.lock().unwrap();
                    st.children.clear();
                    st.next_ref = 100_000;
                }
                let r = with_target(&state, |t| session::resume(t));
                match r {
                    Ok(()) => {
                        state.lock().unwrap().running = true;
                        reply(&sender, &seq, req_seq, &cmd, true, Some(json!({ "allThreadsContinued": true })), None);
                    }
                    Err(e) => reply(&sender, &seq, req_seq, &cmd, false, None, Some(e)),
                }
            }
            "pause" => {
                {
                    let mut st = state.lock().unwrap();
                    st.children.clear();
                    st.next_ref = 100_000;
                }
                let r = with_target(&state, |t| session::halt_target(t));
                match r {
                    Ok(_) => {
                        state.lock().unwrap().running = false;
                        event(&sender, &seq, "stopped", json!({
                            "reason": "pause", "description": "已暂停", "threadId": 1, "allThreadsStopped": true
                        }));
                        reply(&sender, &seq, req_seq, &cmd, true, None, None);
                    }
                    Err(e) => reply(&sender, &seq, req_seq, &cmd, false, None, Some(e)),
                }
            }
            "next" | "stepIn" | "stepOut" => {
                {
                    let mut st = state.lock().unwrap();
                    st.children.clear();
                    st.next_ref = 100_000;
                }
                let mode = match cmd.as_str() {
                    "next" => "over",
                    "stepIn" => "in",
                    _ => "out",
                };
                let granularity = args.get("granularity").and_then(|x| x.as_str()).unwrap_or("statement");
                if granularity == "instruction" {
                    let r = with_target(&state, session::instruction_step);
                    match r {
                        Ok(_) => {
                            state.lock().unwrap().running = false;
                            event(&sender, &seq, "stopped", json!({
                                "reason": "step", "description": "单条指令",
                                "threadId": 1, "allThreadsStopped": true
                            }));
                            reply(&sender, &seq, req_seq, &cmd, true, None, None);
                        }
                        Err(e) => reply(&sender, &seq, req_seq, &cmd, false, None, Some(e)),
                    }
                    continue;
                }
                let r = with_target(&state, |t| session::step(t, mode));
                match r {
                    Ok(note) => {
                        state.lock().unwrap().running = false;
                        event(&sender, &seq, "stopped", json!({
                            "reason": "step", "description": note.unwrap_or_else(|| "单步".into()),
                            "threadId": 1, "allThreadsStopped": true
                        }));
                        reply(&sender, &seq, req_seq, &cmd, true, None, None);
                    }
                    Err(e) => reply(&sender, &seq, req_seq, &cmd, false, None, Some(e)),
                }
            }
            "evaluate" => {
                let expr = args.get("expression").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
                let frame_id = args.get("frameId").and_then(|x| x.as_u64()).unwrap_or(1) as usize;
                let frame = state.lock().unwrap().frames.iter().find(|f| f.id == frame_id).cloned();
                let r = with_target(&state, |t| {
                    let types = t.debug.as_ref().map(|d| d.types.clone()).unwrap_or_default();
                    session::evaluate(t, &expr, frame).map(|v| {
                        let can = v.addr.is_some() && session::expandable(&types, v.type_id);
                        (v, can)
                    })
                });
                match r {
                    Ok((v, can)) => {
                        let reference = if can {
                            let mut st = state.lock().unwrap();
                            let id = st.next_ref;
                            st.next_ref += 1;
                            st.children.insert(id, (v.addr.unwrap_or(0), v.type_id));
                            id
                        } else {
                            0
                        };
                        reply(&sender, &seq, req_seq, &cmd, true, Some(json!({
                            "result": v.value, "type": v.type_name, "variablesReference": reference
                        })), None)
                    }
                    Err(e) => reply(&sender, &seq, req_seq, &cmd, false, None, Some(e)),
                }
            }
            "disassemble" => {
                let r = with_target(&state, |t| {
                    session::disassemble(
                        t,
                        args.get("memoryReference").and_then(|x| x.as_str()).unwrap_or("0x0"),
                        args.get("offset").and_then(|x| x.as_i64()).unwrap_or(0),
                        args.get("instructionOffset").and_then(|x| x.as_i64()).unwrap_or(0),
                        args.get("instructionCount").and_then(|x| x.as_u64()).unwrap_or(20) as usize,
                    )
                });
                match r {
                    Ok(instructions) => reply(&sender, &seq, req_seq, &cmd, true, Some(json!({ "instructions": instructions })), None),
                    Err(e) => reply(&sender, &seq, req_seq, &cmd, false, None, Some(e)),
                }
            }
            "restart" | "reset" => {
                // 复位 → 重建用户断点 → 运行（有断点就停在断点上, 无断点自由运行）
                let r = with_target(&state, |t| session::reset_and_run(t));
                match r {
                    Ok(()) => {
                        let mut s = state.lock().unwrap();
                        s.running = true;
                        s.disasm_cache = None;
                        s.children.clear();
                        s.next_ref = 100_000;
                        drop(s);
                        reply(&sender, &seq, req_seq, &cmd, true, None, None);
                        // VSCode 的「重启」按钮要求一个生命周期信号：发 stopped 让界面知道
                        // 重启已完成、目标在跑（监视线程会在下次停下时再发 stopped）
                        event(&sender, &seq, "stopped", json!({
                            "reason": "restart", "description": "已复位并重新运行",
                            "threadId": 1, "allThreadsStopped": true
                        }));
                    }
                    Err(e) => reply(&sender, &seq, req_seq, &cmd, false, None, Some(e)),
                }
            }
            "instructionStep" => {
                {
                    let mut st = state.lock().unwrap();
                    st.children.clear();
                    st.next_ref = 100_000;
                }
                let r = with_target(&state, |t| {
                    let mut core = t.session.core(0).map_err(|e| e.to_string())?;
                    if !core.status().map_err(|e| e.to_string())?.is_halted() {
                        core.halt(std::time::Duration::from_secs(2)).map_err(|e| e.to_string())?;
                    }
                    core.step().map_err(|e| e.to_string()).map(|info| info.pc)
                });
                match r {
                    Ok(_pc) => {
                        state.lock().unwrap().running = false;
                        event(&sender, &seq, "stopped", json!({
                            "reason": "step", "description": "单条指令",
                            "threadId": 1, "allThreadsStopped": true
                        }));
                        reply(&sender, &seq, req_seq, &cmd, true, None, None);
                    }
                    Err(e) => reply(&sender, &seq, req_seq, &cmd, false, None, Some(e)),
                }
            }
            "disconnect" | "terminate" => {
                {
                    let mut s = state.lock().unwrap();
                    if let Some(t) = &mut s.target {
                        let _ = session::detach(t, true);
                    }
                    s.target = None;
                }
                reply(&sender, &seq, req_seq, &cmd, true, None, None);
                event(&sender, &seq, "terminated", json!({}));
                session::flush_stdout();
                std::process::exit(0);
            }
            other => {
                reply(&sender, &seq, req_seq, other, false, None, Some(format!("暂不支持的请求: {other}")));
            }
        }
    }
}

fn with_target<T>(
    state: &Arc<Mutex<State>>,
    f: impl FnOnce(&mut Target) -> Result<T, String>,
) -> Result<T, String> {
    let mut s = state.lock().unwrap();
    let t = s.target.as_mut().ok_or("未连接目标（先 launch/attach）")?;
    f(t)
}

fn next_seq(seq: &AtomicU64) -> u64 {
    seq.fetch_add(1, Ordering::SeqCst)
}

fn reply(
    sender: &Arc<Sender>,
    seq: &AtomicU64,
    request_seq: u64,
    command: &str,
    success: bool,
    body: Option<Value>,
    message: Option<String>,
) {
    let mut v = json!({
        "seq": next_seq(seq),
        "type": "response",
        "request_seq": request_seq,
        "success": success,
        "command": command,
    });
    if let Some(b) = body {
        v["body"] = b;
    }
    if let Some(m) = message {
        v["message"] = json!(m);
    }
    sender.send(&v);
}

fn event(sender: &Arc<Sender>, seq: &AtomicU64, event: &str, body: Value) {
    let v = json!({
        "seq": next_seq(seq),
        "type": "event",
        "event": event,
        "body": body,
    });
    sender.send(&v);
}
