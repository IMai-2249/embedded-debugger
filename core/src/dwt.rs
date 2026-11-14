// Cortex-M DWT 数据观察点（watchpoint）直接寄存器操作
use probe_rs::{Core, MemoryInterface};

pub const MAX_UNITS: usize = 4;

const DEMCR: u64 = 0xE000_EDFC;
const DWT_COMP: u64 = 0xE000_1020;
const DWT_MASK: u64 = 0xE000_1024;
const DWT_FUNCTION: u64 = 0xE000_1028;

fn unit_reg(base: u64, unit: usize) -> u64 {
    base + 0x10 * unit as u64
}

/// 配置第 unit 个比较器监视 addr（kind: "write" | "read" | "both"）
pub fn configure(core: &mut Core<'_>, unit: usize, addr: u32, kind: &str) -> Result<(), String> {
    let demcr = core
        .read_word_32(DEMCR)
        .map_err(|e| format!("读 DEMCR 失败: {e}"))?;
    if demcr & (1 << 24) == 0 {
        core.write_word_32(DEMCR, demcr | (1 << 24))
            .map_err(|e| format!("写 DEMCR 失败: {e}"))?;
    }
    let func: u32 = match kind {
        "read" => 0x5,
        "write" => 0x6,
        _ => 0x4,
    };
    core.write_word_32(unit_reg(DWT_COMP, unit), addr & !3)
        .map_err(|e| format!("写 DWT_COMP 失败: {e}"))?;
    core.write_word_32(unit_reg(DWT_MASK, unit), 0)
        .map_err(|e| format!("写 DWT_MASK 失败: {e}"))?;
    core.write_word_32(unit_reg(DWT_FUNCTION, unit), func)
        .map_err(|e| format!("写 DWT_FUNCTION 失败: {e}"))?;
    Ok(())
}

pub fn disable(core: &mut Core<'_>, unit: usize) -> Result<(), String> {
    core.write_word_32(unit_reg(DWT_FUNCTION, unit), 0)
        .map_err(|e| format!("关闭观察点失败: {e}"))
}

pub fn disable_all(core: &mut Core<'_>) {
    for u in 0..MAX_UNITS {
        let _ = disable(core, u);
    }
}

/// 返回命中的比较器编号（读取 DWT_FUNCTION 的 MATCHED 位）
pub fn matched_units(core: &mut Core<'_>) -> Vec<usize> {
    let mut out = Vec::new();
    for u in 0..MAX_UNITS {
        if let Ok(f) = core.read_word_32(unit_reg(DWT_FUNCTION, u)) {
            if (f >> 24) & 0xf != 0 {
                out.push(u);
            }
        }
    }
    out
}

/// 清除 MATCHED 位（保留使能），避免下次暂停误报
pub fn clear_matched(core: &mut Core<'_>) {
    for u in 0..MAX_UNITS {
        if let Ok(f) = core.read_word_32(unit_reg(DWT_FUNCTION, u)) {
            if (f >> 24) & 0xf != 0 {
                let _ = core.write_word_32(unit_reg(DWT_FUNCTION, u), f & 0xf);
            }
        }
    }
}
