// 源码级单步核心逻辑（独立于 Tauri，可在示例/测试中复用）
use crate::debuginfo::DebugInfo;
use probe_rs::{Core, CoreInterface, MemoryInterface};
use std::time::{Duration, Instant};

const MAX_STEPS: u32 = 20000;
/// 步进时间预算: 超过则停在当前位置并提示(该行可能是循环/等待)
const STEP_BUDGET: Duration = Duration::from_secs(5);
const WAIT_RETURN: Duration = Duration::from_secs(6);

pub struct StepResult {
    pub pc: u64,
    /// 非致命提示(超时/循环等), 前端弹 toast
    pub note: Option<String>,
}

fn read_pc(core: &mut Core<'_>) -> Result<u64, String> {
    let reg = core.program_counter().id();
    core.read_core_reg::<u32>(reg)
        .map(|v| v as u64)
        .map_err(|e| format!("读 PC 失败: {e}"))
}

fn read_lr(core: &mut Core<'_>) -> Result<u32, String> {
    let reg = core.return_address().id();
    core.read_core_reg::<u32>(reg)
        .map_err(|e| format!("读 LR 失败: {e}"))
}

/// 当前指令若是带链接的立即数调用(BL/BLX), 返回下一条指令地址
fn call_next_addr(core: &mut Core<'_>, pc: u64) -> Result<Option<u64>, String> {
    let mut buf = [0u8; 4];
    core.read_8(pc, &mut buf)
        .map_err(|e| format!("读指令失败: {e}"))?;
    use capstone::arch::{arm, BuildsCapstone};
    use capstone::Capstone;
    let cs = Capstone::new()
        .arm()
        .mode(arm::ArchMode::Thumb)
        .build()
        .map_err(|e| format!("反汇编器初始化失败: {e}"))?;
    let insns = cs
        .disasm_all(&buf, pc)
        .map_err(|e| format!("反汇编失败: {e}"))?;
    if let Some(i) = insns.iter().next() {
        let m = i.mnemonic().unwrap_or("");
        let op = i.op_str().unwrap_or("");
        let is_call = (m == "bl" || m == "blx") && (op.starts_with('#') || op.starts_with("0x"));
        if is_call {
            return Ok(Some(pc + i.bytes().len() as u64));
        }
    }
    Ok(None)
}

/// 设临时断点 → 运行 → 等待命中 → 清除临时断点（用户自己的断点不清）
/// 返回非致命提示(如超时后已强制暂停)
fn run_until(
    core: &mut Core<'_>,
    addr: u64,
    user_bps: &[u64],
) -> Result<Option<String>, String> {
    // 临时断点固定用用户断点之后的槽位, 不依赖硬件回读（部分探针回读不可靠）
    let avail = core.available_breakpoint_units().unwrap_or(6) as usize;
    let unit = user_bps.len();
    if unit >= avail {
        return Err(format!("硬件断点已用满（{avail} 个）"));
    }
    core.set_hw_breakpoint_unit(unit, addr)
        .map_err(|e| format!("设置临时断点失败: {e}"))?;
    core.run().map_err(|e| format!("运行失败: {e}"))?;
    let mut note = None;
    if let Err(e) = core.wait_for_core_halted(WAIT_RETURN) {
        // 超时: 强制暂停, 目标不会失控
        let _ = core.halt(Duration::from_secs(1));
        note = Some(format!("等待函数返回超时（{e}），已强制暂停在当前执行位置"));
    }
    let _ = probe_rs::CoreInterface::clear_hw_breakpoint(core, unit);
    Ok(note)
}

/// 运行到光标处: 在目标行设临时断点, 运行直到命中(或先命中其他断点)
pub fn run_to_line(
    core: &mut Core<'_>,
    debug: Option<&DebugInfo>,
    file: &str,
    line: u32,
    user_bps: &[u64],
) -> Result<StepResult, String> {
    let debug = debug.ok_or("未加载符号文件，无法按源码行运行")?;
    let (actual_line, addr) = debug
        .resolve_line(file, line)
        .ok_or("附近 40 行内没有可执行代码")?;
    let _ = actual_line;

    let pc = read_pc(core)?;
    if pc == addr {
        return Ok(StepResult {
            pc,
            note: Some("当前已在该行".into()),
        });
    }

    let avail = core.available_breakpoint_units().unwrap_or(6) as usize;
    let unit = user_bps.len();
    if unit >= avail {
        return Err(format!("硬件断点已用满（{avail} 个），无法运行到该行"));
    }
    core.set_hw_breakpoint_unit(unit, addr)
        .map_err(|e| format!("设置临时断点失败: {e}"))?;

    let halted = core
        .status()
        .map_err(|e| format!("读状态失败: {e}"))?
        .is_halted();
    let mut note = None;
    if halted {
        core.run().map_err(|e| format!("运行失败: {e}"))?;
    }
    if let Err(e) = core.wait_for_core_halted(WAIT_RETURN) {
        let _ = core.halt(Duration::from_secs(1));
        note = Some(format!("等待命中超时（{e}），已强制暂停"));
    }
    let _ = probe_rs::CoreInterface::clear_hw_breakpoint(core, unit);

    let pc = read_pc(core)?;
    if note.is_none() && pc != addr {
        note = Some("先命中了其他断点或异常，已停在当前位置".into());
    }
    Ok(StepResult { pc, note })
}

/// 源码级单步: mode = "in" | "over" | "out"
pub fn step_line(
    core: &mut Core<'_>,
    debug: Option<&DebugInfo>,
    mode: &str,
    user_bps: &[u64],
) -> Result<StepResult, String> {
    if !core
        .status()
        .map_err(|e| format!("读状态失败: {e}"))?
        .is_halted()
    {
        core.halt(Duration::from_secs(2))
            .map_err(|e| format!("halt 失败: {e}"))?;
    }

    let start_pc = read_pc(core)?;
    let start_line = debug.and_then(|d| d.addr_to_line(start_pc));
    let start_func = debug.and_then(|d| d.func_at(start_pc)).map(|f| (f.start, f.end));

    match mode {
        // 步过: 当前指令是函数调用 → 临时断点一步跨到返回处, 避免逐指令跑完被调函数
        "over" => {
            if let Ok(Some(next)) = call_next_addr(core, start_pc) {
                let note = run_until(core, next, user_bps)?;
                return Ok(StepResult { pc: read_pc(core)?, note });
            }
        }
        // 步出: LR 指向调用者返回地址 → 临时断点直接跑回去
        "out" => {
            let lr = read_lr(core)?;
            let target = (lr & !1) as u64;
            let valid = (lr & 1) == 1
                && lr != 0
                && lr != u32::MAX
                && debug.map_or(true, |d| {
                    d.addr_to_line(target).is_some() || d.func_at(target).is_some()
                });
            if valid {
                let note = run_until(core, target, user_bps)?;
                return Ok(StepResult { pc: read_pc(core)?, note });
            }
        }
        _ => {}
    }

    // 逐指令步进直到条件满足（步入 / 非调用的步过 / LR 不可用的步出）
    let deadline = Instant::now() + STEP_BUDGET;
    let mut pc = start_pc;
    for _ in 0..MAX_STEPS {
        let info = core.step().map_err(|e| format!("单步失败: {e}"))?;
        pc = info.pc;
        let cur_line = debug.and_then(|d| d.addr_to_line(pc));
        let cur_func = debug.and_then(|d| d.func_at(pc)).map(|f| (f.start, f.end));
        let done = match (debug.is_some(), start_line) {
            (true, Some(_)) => match mode {
                // 步过: 进入子函数则继续, 回到同函数且行号变化才停
                "over" => match (cur_func, start_func) {
                    (Some(c), Some(s)) if c.0 != s.0 => false,
                    _ => cur_line != start_line,
                },
                // 步出: 离开当前函数区间即停
                "out" => match start_func {
                    Some(s) => cur_func.map_or(true, |c| c.0 != s.0),
                    None => true,
                },
                // 步入: 源码行变化即停
                _ => cur_line != start_line,
            },
            // 无符号信息: 退化为指令单步
            _ => true,
        };
        if done {
            return Ok(StepResult { pc, note: None });
        }
        if Instant::now() >= deadline {
            return Ok(StepResult {
                pc,
                note: Some(
                    "5 秒内未走到下一行（该行是循环/等待），已停在当前位置；可用「单步」逐条指令观察"
                        .into(),
                ),
            });
        }
    }
    Ok(StepResult {
        pc,
        note: Some(format!(
            "步进超过 {MAX_STEPS} 条指令仍未到下一行（可能死循环），已停在当前位置"
        )),
    })
}
