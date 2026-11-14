//! webview 桥接命令分发（DAP 会话内）
//!
//! VS Code 扩展的 webview 面板发来的命令，在活动调试会话中转发为
//! `ed/bridge` custom request，到达这里。做法：把 Session/RTT/观察点
//! 临时移入 AppState，复用 core 的命令层（与桌面版同一套实现），
//! 完成后移回 Target —— DAP 侧状态机与停机监视线程全程无感。
//!
//! 命令分三类：
//! - 观察/控制：直通 core（停机后监视线程发 stopped，VSCode 自动联动）
//! - 断点/烧录/连接等 DAP 职责：拒绝，提示走 VSCode 原生流程
//! - 复位：由扩展层映射为 DAP restart（确保断点重放），此处不受理

use crate::session::Target;
use embedded_debugger_lib as edlib;
use embedded_debugger_lib::commands;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

fn j<T: serde::Serialize>(v: T) -> Value {
    serde_json::to_value(v).unwrap_or(Value::Null)
}

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

/// DAP 职责命令：由 VSCode 原生流程承接，webview 内不重复提供
const DAP_OWNED: &[&str] = &[
    "connect",
    "disconnect",
    "flash",
    "load_symbols",
    "pick_firmware",
    "pick_symbols",
    "pick_target_yaml",
    "pick_pack_file",
    "set_breakpoint",
    "clear_breakpoint",
    "reset",
    "step_line",
    "run_to",
    "save_text",
    "save_binary",
];

pub fn ed_bridge_cmd(t: &mut Target, cmd: &str, args: &Value) -> Result<Value, String> {
    if DAP_OWNED.contains(&cmd) {
        return Err(match cmd {
            "reset" => "复位请用调试工具栏的重启（断点会自动重放）".into(),
            "connect" => "已在调试会话中，无需重复连接".into(),
            "set_breakpoint" | "clear_breakpoint" => "请在编辑器行号旁点击设置断点（与调试会话联动）".into(),
            "flash" | "load_symbols" => "烧录与符号加载由 launch.json 配置完成".into(),
            _ => "该操作由 VSCode 调试流程承接".into(),
        });
    }

    // Session 等临时移入 AppState，复用 core 命令层；完成后移回
    let shared = Arc::new(Mutex::new(edlib::state::AppState {
        session: t.session.take(),
        chip: t.chip.clone(),
        debug: t.debug.take(),
        rtt: t.rtt.take(),
        watchpoints: std::mem::take(&mut t.watchpoints),
        ..Default::default()
    }));

    let result: Result<Value, String> = match cmd {
        // ---- 控制 ----
        "halt" => commands::halt(&shared).map(|v| j(v)),
        "resume" => commands::resume(&shared).map(|_| Value::Null),
        "step" => commands::step(&shared).map(|v| j(v)),
        "get_status" => Ok(j(commands::get_status(&shared))),
        // ---- 观察 ----
        "read_registers" => commands::read_registers(&shared).map(|v| j(v)),
        "read_memory" => {
            commands::read_memory(&shared, arg_u64(args, "addr"), arg_u32(args, "size")).map(|v| j(v))
        }
        "disasm" => {
            commands::disasm(&shared, arg_u64(args, "addr"), arg_u32(args, "count")).map(|v| j(v))
        }
        "read_source" => Ok(json!(commands::read_source(arg_str(args, "path"))?)),
        "list_variables" => commands::list_variables(&shared, arg_str(args, "filter")).map(|v| j(v)),
        "read_watches" => commands::read_watches(&shared, arg_str_vec(args, "names")).map(|v| j(v)),
        "read_watch_members" => commands::read_watch_members(
            &shared,
            arg_str(args, "name"),
            arg_u32(args, "start"),
            arg_u32(args, "limit"),
        )
        .map(|v| j(v)),
        "call_stack" => commands::call_stack(&shared).map(|v| j(v)),
        "local_vars" => commands::local_vars(&shared).map(|v| j(v)),
        "frame_locals" => commands::frame_locals(&shared, arg_usize(args, "index")).map(|v| j(v)),
        "task_locals" => commands::task_locals(&shared, arg_str(args, "name")).map(|v| j(v)),
        "task_stack" => commands::task_stack(&shared, arg_str(args, "name")).map(|v| j(v)),
        "rtos_tasks" => commands::rtos_tasks(&shared).map(|v| j(v)),
        "fault_info" => commands::fault_info(&shared).map(|v| j(v)),
        // ---- RTT ----
        "rtt_start" => commands::rtt_start(&shared).map(|v| j(v)),
        "rtt_poll" => commands::rtt_poll(&shared, arg_u32(args, "limit")).map(|v| j(v)),
        "rtt_write" => commands::rtt_write(&shared, arg_usize(args, "channel"), arg_str(args, "text"))
            .map(|_| Value::Null),
        "rtt_stop" => commands::rtt_stop(&shared).map(|_| Value::Null),
        // ---- 数据观察点（DAP 无此概念，core 全权管理） ----
        "set_watchpoint" => commands::set_watchpoint(&shared, arg_str(args, "name"), arg_str(args, "kind"))
            .map(|v| j(v)),
        "clear_watchpoint" => {
            commands::clear_watchpoint(&shared, arg_u64(args, "addr")).map(|_| Value::Null)
        }
        "list_watchpoints" => commands::list_watchpoints(&shared).map(|v| j(v)),
        // ---- 芯片库 / 导入（不依赖会话） ----
        "detect_chip" => commands::detect_chip(arg_usize(args, "probe")).map(|v| j(v)),
        "search_chips" => Ok(json!(commands::search_chips(arg_str(args, "query")))),
        "list_chip_families" => Ok(json!(commands::list_chip_families())),
        "list_family_variants" => Ok(json!(commands::list_family_variants(arg_str(args, "family")))),
        "import_target" => edlib::import::import_target(&arg_str(args, "path")).map(|v| j(v)),
        "import_pack" => edlib::import::import_pack_sync(&arg_str(args, "path"), &|_| {}).map(|v| j(v)),
        // ---- 断点只读展示（写操作走编辑器） ----
        "list_breakpoints" => Ok(json!(t
            .bps
            .iter()
            .map(|(f, l, a)| json!({ "addr": a, "file": f, "line": l }))
            .collect::<Vec<_>>())),
        other => Err(format!("未知命令: {other}")),
    };

    let mut st = shared.lock().unwrap();
    t.session = st.session.take();
    t.debug = st.debug.take();
    t.rtt = st.rtt.take();
    t.watchpoints = std::mem::take(&mut st.watchpoints);
    result
}
