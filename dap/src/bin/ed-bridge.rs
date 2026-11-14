//! ed-bridge: VS Code Webview 版嵌入式调试器的命令后端
//!
//! 协议（stdin/stdout 行 JSON）:
//!   → {"id":1,"cmd":"read_registers","args":{...}}
//!   ← {"id":1,"ok":true,"data":...} / {"id":1,"ok":false,"error":"..."}
//!   ← {"__event":"pack-import","payload":{...}}   (无 id 的主动事件)
//!
//! 直接复用桌面版的命令函数（commands::*, 纯 Rust），状态等价于 Tauri managed state。

use embedded_debugger_lib as edlib;
use embedded_debugger_lib::commands;
use embedded_debugger_lib::state::AppState;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::sync::{Arc, Mutex};

fn to_snake(k: &str) -> String {
    let mut out = String::with_capacity(k.len() + 4);
    for c in k.chars() {
        if c.is_ascii_uppercase() {
            out.push('_');
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

fn arg_str(args: &Value, key: &str) -> String {
    args.get(key)
        .or_else(|| args.get(&to_snake(key)))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

fn arg_u64(args: &Value, key: &str) -> u64 {
    args.get(key)
        .or_else(|| args.get(&to_snake(key)))
        .and_then(|v| v.as_u64())
        .unwrap_or(0)
}

fn arg_usize(args: &Value, key: &str) -> usize {
    arg_u64(args, key) as usize
}

fn arg_u32(args: &Value, key: &str) -> u32 {
    arg_u64(args, key) as u32
}

fn arg_bool(args: &Value, key: &str) -> bool {
    args.get(key)
        .or_else(|| args.get(&to_snake(key)))
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

fn arg_str_vec(args: &Value, key: &str) -> Vec<String> {
    args.get(key)
        .or_else(|| args.get(&to_snake(key)))
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default()
}

fn main() {
    let state: Arc<Mutex<AppState>> = Arc::new(Mutex::new(AppState::default()));
    let out = Mutex::new(std::io::stdout());
    let stdin = std::io::stdin();
    let mut reader = BufReader::new(stdin.lock());

    let send = |out: &Mutex<Box<dyn Write + Send>>, v: &Value| {
        let mut w = out.lock().unwrap();
        let _ = writeln!(w, "{}", v);
        let _ = w.flush();
    };
    // send 闭包与主线借用冲突 → 用局部宏
    macro_rules! emit {
        ($v:expr) => {{
            let mut w = out.lock().unwrap();
            let _ = writeln!(w, "{}", $v);
            let _ = w.flush();
        }};
    }

    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(msg) = serde_json::from_str::<Value>(line) else { continue };
        let id = msg.get("id").and_then(|x| x.as_u64()).unwrap_or(0);
        let cmd = msg.get("cmd").and_then(|x| x.as_str()).unwrap_or("").to_string();
        let args = msg.get("args").cloned().unwrap_or(json!({}));
        eprintln!("[ed-bridge] {} (id {})", cmd, id);

        // 桥接进程直接传状态引用（core 版命令不再依赖 tauri::State）
        macro_rules! j {
            ($v:expr) => {
                serde_json::to_value($v).unwrap_or(Value::Null)
            };
        }

        let result: Result<Value, String> = match cmd.as_str() {
            "list_probes" => Ok(j!(commands::list_probes())),
            "connect" => Ok(j!(commands::connect(
                &state,
                arg_usize(&args, "probe"),
                arg_str(&args, "chip")
            ))),
            "disconnect" => commands::disconnect(&state).map(|_| Value::Null),
            "get_status" => Ok(j!(commands::get_status(&state))),
            "halt" => Ok(j!(commands::halt(&state))),
            "resume" => commands::resume(&state).map(|_| Value::Null),
            "reset" => Ok(j!(commands::reset(&state, arg_bool(&args, "halt")))),
            "step" => Ok(j!(commands::step(&state))),
            "read_registers" => Ok(j!(commands::read_registers(&state))),
            "read_memory" => Ok(j!(commands::read_memory(
                &state,
                arg_u64(&args, "addr"),
                arg_u32(&args, "size")
            ))),
            "disasm" => Ok(j!(commands::disasm(
                &state,
                arg_u64(&args, "addr"),
                arg_u32(&args, "count")
            ))),
            "load_symbols" => Ok(j!(commands::load_symbols(&state, arg_str(&args, "path")))),
            "read_source" => Ok(j!(commands::read_source(arg_str(&args, "path")))),
            "set_breakpoint" => Ok(j!(commands::set_breakpoint(
                &state,
                arg_str(&args, "file"),
                arg_u32(&args, "line")
            ))),
            "clear_breakpoint" => commands::clear_breakpoint(&state, arg_u64(&args, "addr"))
                .map(|_| Value::Null),
            "list_breakpoints" => Ok(j!(commands::list_breakpoints(&state))),
            "step_line" => Ok(j!(commands::step_line(&state, arg_str(&args, "mode")))),
            "run_to" => Ok(j!(commands::run_to(
                &state,
                arg_str(&args, "file"),
                arg_u32(&args, "line")
            ))),
            "flash" => commands::flash(&state, arg_str(&args, "path")).map(|m| json!(m)),
            "list_variables" => Ok(j!(commands::list_variables(&state, arg_str(&args, "filter")))),
            "read_watches" => Ok(j!(commands::read_watches(
                &state,
                arg_str_vec(&args, "names")
            ))),
            "read_watch_members" => Ok(j!(commands::read_watch_members(
                &state,
                arg_str(&args, "name"),
                arg_u32(&args, "start"),
                arg_u32(&args, "limit")
            ))),
            "call_stack" => Ok(j!(commands::call_stack(&state))),
            "rtos_tasks" => Ok(j!(commands::rtos_tasks(&state))),
            "set_watchpoint" => Ok(j!(commands::set_watchpoint(
                &state,
                arg_str(&args, "name"),
                arg_str(&args, "kind")
            ))),
            "clear_watchpoint" => commands::clear_watchpoint(&state, arg_u64(&args, "addr"))
                .map(|_| Value::Null),
            "list_watchpoints" => Ok(j!(commands::list_watchpoints(&state))),
            "local_vars" => Ok(j!(commands::local_vars(&state))),
            "frame_locals" => Ok(j!(commands::frame_locals(&state, arg_usize(&args, "index")))),
            "task_locals" => Ok(j!(commands::task_locals(&state, arg_str(&args, "name")))),
            "task_stack" => Ok(j!(commands::task_stack(&state, arg_str(&args, "name")))),
            "fault_info" => Ok(j!(commands::fault_info(&state))),
            "inject_fault" => commands::inject_fault(&state).map(|_| Value::Null),
            "rtt_start" => Ok(j!(commands::rtt_start(&state))),
            "rtt_poll" => Ok(j!(commands::rtt_poll(&state, arg_u32(&args, "limit")))),
            "rtt_write" => commands::rtt_write(&state, arg_usize(&args, "channel"), arg_str(&args, "text"))
                .map(|_| Value::Null),
            "rtt_stop" => commands::rtt_stop(&state).map(|_| Value::Null),
            "detect_chip" => Ok(j!(commands::detect_chip(arg_usize(&args, "probe")))),
            "search_chips" => Ok(j!(commands::search_chips(arg_str(&args, "query")))),
            "list_chip_families" => Ok(j!(commands::list_chip_families())),
            "list_family_variants" => Ok(j!(commands::list_family_variants(arg_str(&args, "family")))),
            "import_target" => Ok(j!(edlib::import::import_target(&arg_str(&args, "path")))),
            "import_pack" => {
                // 进度以事件行转发给 webview
                let out_ref = &out;
                let progress = |p: edlib::import::PackImportProgress| {
                    emit!(json!({ "__event": "pack-import", "payload": p }));
                };
                let _ = out_ref;
                match edlib::import::import_pack_sync(&arg_str(&args, "path"), &progress) {
                    Ok(r) => Ok(j!(r)),
                    Err(e) => Err(e),
                }
            }
            other => Err(format!("未知命令: {other}")),
        };

        let resp = match result {
            Ok(data) => json!({ "id": id, "ok": true, "data": data }),
            Err(e) => json!({ "id": id, "ok": false, "error": e }),
        };
        emit!(resp);
    }
}
