// DWARF CFI (.debug_frame) 解析与 ARM Cortex-M 栈回溯
// 支持 Keil AC6 的 "armcc+" 私有 CIE 扩展（augmentation 数据长度前缀）
use crate::debuginfo::DebugInfo;
use std::collections::HashMap;

#[derive(Clone, Copy, Debug)]
pub enum RaRule {
    /// 返回地址保存在 CFA + n 处
    Offset(i64),
    /// 返回地址 = CFA + n
    ValOffset(i64),
    /// 返回地址在另一个寄存器里
    Register(u16),
    /// 返回地址未改变（仍在 LR）
    SameValue,
}

#[derive(Clone)]
pub struct CfiRow {
    pub start: u64,
    pub end: u64,
    /// (寄存器, 偏移); None = 规则未定义(按 SP+0 处理)
    pub cfa: Option<(u16, i64)>,
    pub ra: Option<RaRule>,
}

#[derive(Clone, Copy)]
enum Rule {
    Undefined,
    SameValue,
    Offset(i64),
    ValOffset(i64),
    Register(u16),
}

#[derive(Clone)]
struct State {
    cfa: Option<(u16, i64)>,
    rules: HashMap<u16, Rule>,
}

struct Cie {
    code_align: u64,
    data_align: i64,
    initial: State,
    /// CIE 是否带长度前缀的 augmentation 数据（armcc+ / z 系列）
    has_aug: bool,
}

pub struct Frame {
    pub pc: u64,
    pub func: Option<String>,
    pub file: Option<String>,
    pub line: Option<u32>,
    /// 该帧的 CFA（帧基址参考点）
    pub cfa: u64,
    /// 该帧的 SP
    pub sp: u64,
}

// ---------- 基础解码 ----------

fn uleb(data: &[u8], pos: &mut usize) -> Option<u64> {
    let mut result = 0u64;
    let mut shift = 0u32;
    loop {
        let b = *data.get(*pos)?;
        *pos += 1;
        result |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            return Some(result);
        }
        shift += 7;
        if shift > 63 {
            return None;
        }
    }
}

fn sleb(data: &[u8], pos: &mut usize) -> Option<i64> {
    let mut result = 0i64;
    let mut shift = 0u32;
    loop {
        let b = *data.get(*pos)?;
        *pos += 1;
        result |= ((b & 0x7f) as i64) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            if shift < 64 && (b & 0x40) != 0 {
                result |= -1i64 << shift;
            }
            return Some(result);
        }
        if shift > 63 {
            return None;
        }
    }
}

fn read_u32(data: &[u8], pos: &mut usize) -> Option<u32> {
    let b = data.get(*pos..*pos + 4)?;
    *pos += 4;
    Some(u32::from_le_bytes(b.try_into().ok()?))
}

fn skip_block(data: &[u8], pos: &mut usize) -> Option<()> {
    let len = uleb(data, pos)? as usize;
    *pos += len;
    if *pos > data.len() {
        return None;
    }
    Some(())
}

// ---------- CFI 解析 ----------

fn parse_cie(data: &[u8], start: usize, end: usize) -> Option<Cie> {
    let mut pos = start + 8; // 跳过 length + CIE_id
    let version = *data.get(pos)?;
    pos += 1;
    let aug_start = pos;
    while pos < end && *data.get(pos)? != 0 {
        pos += 1;
    }
    let aug = &data[aug_start..pos];
    pos += 1;
    let code_align = uleb(data, &mut pos)?;
    let data_align = sleb(data, &mut pos)?;
    if version == 1 {
        pos += 1;
    } else {
        let _ = uleb(data, &mut pos)?;
    }
    let has_aug = aug.first() == Some(&b'z') || aug == b"armcc+";
    if has_aug {
        let len = uleb(data, &mut pos)? as usize;
        pos += len;
        if pos > end {
            return None;
        }
    }
    // 执行 CIE 初始指令（只收集规则）
    let mut state = State {
        cfa: None,
        rules: HashMap::new(),
    };
    let mut stack: Vec<State> = Vec::new();
    let mut loc = 0u64;
    while pos < end {
        exec_one(
            data, &mut pos, code_align, data_align, &mut state, &mut stack, &mut loc,
        )?;
    }
    Some(Cie {
        code_align,
        data_align,
        initial: state,
        has_aug,
    })
}

/// 执行一条 CFI 指令; 返回 None 表示解析失败
fn exec_one(
    data: &[u8],
    pos: &mut usize,
    code_align: u64,
    data_align: i64,
    state: &mut State,
    stack: &mut Vec<State>,
    loc: &mut u64,
) -> Option<()> {
    let op = *data.get(*pos)?;
    *pos += 1;
    match op {
        0x00 => {} // nop
        0x01 => {
            *loc = read_u32(data, pos)? as u64;
        }
        0x02 => {
            let d = *data.get(*pos)? as u64;
            *pos += 1;
            *loc += d * code_align;
        }
        0x03 => {
            let b = data.get(*pos..*pos + 2)?;
            *pos += 2;
            *loc += u16::from_le_bytes(b.try_into().ok()?) as u64 * code_align;
        }
        0x04 => {
            *loc += read_u32(data, pos)? as u64 * code_align;
        }
        0x05 => {
            let reg = uleb(data, pos)? as u16;
            let off = uleb(data, pos)? as i64 * data_align;
            state.rules.insert(reg, Rule::Offset(off));
        }
        0x06 => {
            let reg = uleb(data, pos)? as u16;
            state.rules.remove(&reg);
        }
        0x07 => {
            let reg = uleb(data, pos)? as u16;
            state.rules.insert(reg, Rule::Undefined);
        }
        0x08 => {
            let reg = uleb(data, pos)? as u16;
            state.rules.insert(reg, Rule::SameValue);
        }
        0x09 => {
            let r1 = uleb(data, pos)? as u16;
            let r2 = uleb(data, pos)? as u16;
            state.rules.insert(r1, Rule::Register(r2));
        }
        0x0a => stack.push(state.clone()),
        0x0b => *state = stack.pop()?,
        0x0c => {
            let reg = uleb(data, pos)? as u16;
            let off = uleb(data, pos)? as i64;
            state.cfa = Some((reg, off));
        }
        0x0d => {
            let reg = uleb(data, pos)? as u16;
            let off = state.cfa.map(|c| c.1).unwrap_or(0);
            state.cfa = Some((reg, off));
        }
        0x0e => {
            let off = uleb(data, pos)? as i64;
            let reg = state.cfa.map(|c| c.0).unwrap_or(13);
            state.cfa = Some((reg, off));
        }
        0x0f => {
            skip_block(data, pos)?;
            state.cfa = None; // def_cfa_expression 暂不支持
        }
        0x10 => {
            let reg = uleb(data, pos)? as u16;
            skip_block(data, pos)?;
            state.rules.insert(reg, Rule::Undefined);
        }
        0x11 => {
            let reg = uleb(data, pos)? as u16;
            let off = sleb(data, pos)? * data_align;
            state.rules.insert(reg, Rule::Offset(off));
        }
        0x12 => {
            let reg = uleb(data, pos)? as u16;
            let off = sleb(data, pos)? * data_align;
            state.cfa = Some((reg, off));
        }
        0x13 => {
            let off = sleb(data, pos)? * data_align;
            let reg = state.cfa.map(|c| c.0).unwrap_or(13);
            state.cfa = Some((reg, off));
        }
        0x14 => {
            let reg = uleb(data, pos)? as u16;
            let off = uleb(data, pos)? as i64 * data_align;
            state.rules.insert(reg, Rule::ValOffset(off));
        }
        0x15 => {
            let reg = uleb(data, pos)? as u16;
            let off = sleb(data, pos)? * data_align;
            state.rules.insert(reg, Rule::ValOffset(off));
        }
        0x16 => {
            let reg = uleb(data, pos)? as u16;
            skip_block(data, pos)?;
            state.rules.insert(reg, Rule::Undefined);
        }
        0x2e => {
            let _ = uleb(data, pos)?; // GNU_args_size
        }
        0x2f => {
            let reg = uleb(data, pos)? as u16;
            let off = uleb(data, pos)? as i64;
            state.rules.insert(reg, Rule::Offset(-off));
        }
        op @ 0x40..=0x7f => {
            // advance_loc
            *loc += (op & 0x3f) as u64 * code_align;
        }
        op @ 0x80..=0xbf => {
            // offset reg, ULEB*data_align
            let reg = (op & 0x3f) as u16;
            let off = uleb(data, pos)? as i64 * data_align;
            state.rules.insert(reg, Rule::Offset(off));
        }
        op @ 0xc0..=0xff => {
            // restore reg
            let reg = (op & 0x3f) as u16;
            state.rules.remove(&reg);
        }
        _ => return None,
    }
    Some(())
}

/// 解析整个 .debug_frame, 生成按地址排序的规则行
pub fn load_cfi(data: &[u8]) -> Vec<CfiRow> {
    let mut rows = Vec::new();
    if data.len() < 8 {
        return rows;
    }

    // 第一遍: 收集 CIE
    let mut cies: HashMap<usize, Cie> = HashMap::new();
    let mut off = 0usize;
    while off + 8 <= data.len() {
        let len = match read_u32(data, &mut off) {
            Some(l) => l as usize,
            None => break,
        };
        if len == 0 {
            break;
        }
        let id_pos = off;
        let id = match read_u32(data, &mut off) {
            Some(v) => v,
            None => break,
        };
        let end = id_pos + len;
        if end > data.len() {
            break;
        }
        if id == 0xffff_ffff {
            match parse_cie(data, id_pos - 4, end) {
                Some(cie) => {
                    cies.insert(id_pos - 4, cie);
                }
                None => {
                    if std::env::var_os("CFI_DEBUG").is_some() {
                        eprintln!("CIE parse 失败 @{:#x}", id_pos - 4);
                    }
                }
            }
        }
        off = end;
    }

    // 第二遍: 解析 FDE, 生成行
    let mut off = 0usize;
    while off + 8 <= data.len() {
        let len = match read_u32(data, &mut off) {
            Some(l) => l as usize,
            None => break,
        };
        if len == 0 {
            break;
        }
        let id_pos = off;
        let id = match read_u32(data, &mut off) {
            Some(v) => v,
            None => break,
        };
        let end = id_pos + len;
        if end > data.len() {
            break;
        }
        if id != 0xffff_ffff {
            // FDE: CIE 指针是绝对偏移
            if let Some(cie) = cies.get(&(id as usize)) {
                match parse_fde(data, id_pos - 4, end, cie) {
                    Some(mut fde_rows) => rows.append(&mut fde_rows),
                    None => {
                        if std::env::var_os("CFI_DEBUG").is_some() {
                            eprintln!("FDE parse 失败 @{:#x} cie={:#x}", id_pos - 4, id);
                        }
                    }
                }
            }
        }
        off = end;
    }

    rows.sort_by_key(|r| r.start);
    rows
}

fn parse_fde(data: &[u8], start: usize, end: usize, cie: &Cie) -> Option<Vec<CfiRow>> {
    let mut pos = start + 8;
    let fde_start = read_u32(data, &mut pos)? as u64;
    let range = read_u32(data, &mut pos)? as u64;
    // 实测 armcc+ 的 FDE 不带 augmentation 数据前缀, 指令紧随其后
    let _ = cie.has_aug;
    let fde_end = fde_start + range;

    let mut state = cie.initial.clone();
    let mut stack: Vec<State> = Vec::new();
    let mut loc = fde_start;
    // 直接生成行: 每次 advance 结束当前行 [before, loc) 并应用当前状态
    let mut rows: Vec<CfiRow> = Vec::new();
    while pos < end {
        let before = loc;
        exec_one(
            data,
            &mut pos,
            cie.code_align,
            cie.data_align,
            &mut state,
            &mut stack,
            &mut loc,
        )?;
        if loc != before {
            rows.push(CfiRow {
                start: before,
                end: loc,
                cfa: state.cfa,
                ra: match state.rules.get(&14) {
                    Some(Rule::Offset(n)) => Some(RaRule::Offset(*n)),
                    Some(Rule::ValOffset(n)) => Some(RaRule::ValOffset(*n)),
                    Some(Rule::Register(r)) => Some(RaRule::Register(*r)),
                    Some(Rule::SameValue) => Some(RaRule::SameValue),
                    Some(Rule::Undefined) | None => None,
                },
            });
        }
    }
    if loc < fde_end {
        rows.push(CfiRow {
            start: loc,
            end: fde_end,
            cfa: state.cfa,
            ra: match state.rules.get(&14) {
                Some(Rule::Offset(n)) => Some(RaRule::Offset(*n)),
                Some(Rule::ValOffset(n)) => Some(RaRule::ValOffset(*n)),
                Some(Rule::Register(r)) => Some(RaRule::Register(*r)),
                Some(Rule::SameValue) => Some(RaRule::SameValue),
                Some(Rule::Undefined) | None => None,
            },
        });
    }
    Some(rows)
}

// ---------- 回溯 ----------

fn frame_at(info: &DebugInfo, pc: u64, cfa: u64, sp: u64) -> Frame {
    let loc = info.addr_to_line(pc);
    Frame {
        pc,
        func: info.func_at(pc).map(|f| f.name.clone()),
        file: loc.map(|(f, _)| info.files[f].clone()),
        line: loc.map(|(_, l)| l),
        cfa,
        sp,
    }
}

/// 计算某 PC 处的 CFA（无规则时按 SP）
pub fn cfa_of(info: &DebugInfo, pc: u64, sp: u32) -> u64 {
    info.cfi_row(pc)
        .and_then(|r| r.cfa)
        .map(|(reg, off)| {
            if reg == 13 {
                sp as i64 + off
            } else {
                sp as i64
            }
        })
        .unwrap_or(sp as i64) as u64
}

/// 栈回溯: 优先 DWARF CFI, 失败时回退到栈扫描(启发式)
pub fn unwind(
    info: &DebugInfo,
    mut regs: [u32; 16],
    mut read: impl FnMut(u64, &mut [u8]) -> Result<(), String>,
) -> (Vec<Frame>, bool) {
    let pc0 = (regs[15] & !1) as u64;
    let mut frames = vec![frame_at(info, pc0, cfa_of(info, pc0, regs[13]), regs[13] as u64)];
    let orig_sp = (regs[13] & !3) as u64;
    let orig_pc = (regs[15] & !1) as u64;

    for depth in 0..32 {
        let lookup = (regs[15] & !1) as u64;
        let row = info.cfi_row(lookup);
        let (cfa_rule, ra_rule) = match row {
            Some(r) => (r.cfa, r.ra),
            // 完全没有 FDE 的第一帧: 退化用 SP+0 + LR(通常仍有效)
            None if depth == 0 => (None, Some(RaRule::SameValue)),
            None => break,
        };
        // CFA: 未定义时按 SP+0 处理（叶子函数入口）
        let (cfa_reg, cfa_off) = cfa_rule.unwrap_or((13, 0));
        let cfa = if cfa_reg == 13 {
            regs[13] as i64 + cfa_off
        } else if (cfa_reg as usize) < 16 {
            regs[cfa_reg as usize] as i64 + cfa_off
        } else {
            break;
        };
        // 显式 undefined(armcc 表示 LR 已被调用污染) → 停止
        let rule = match ra_rule {
            Some(r) => r,
            None => break,
        };
        let ra = match rule {
            RaRule::Offset(n) => {
                let mut b = [0u8; 4];
                if read((cfa + n) as u64, &mut b).is_err() {
                    break;
                }
                u32::from_le_bytes(b)
            }
            RaRule::ValOffset(n) => (cfa + n) as u32,
            RaRule::Register(r) if (r as usize) < 16 => regs[r as usize],
            // SameValue 只对第一帧有效(此时 LR 还是 CPU 里的真实值);
            // 后续帧的 LR 已不可知, 无法继续回溯
            RaRule::SameValue if depth == 0 => regs[14],
            _ => break,
        };
        if ra == 0 || ra == u32::MAX || ra == 1 {
            break;
        }
        let next_pc = (ra & !1) as u64;
        // 防循环: 返回地址与当前 PC 相同则停止
        if next_pc == lookup {
            break;
        }
        let known = info.func_at(next_pc).is_some() || info.addr_to_line(next_pc).is_some();
        if !known && depth == 0 {
            // 第一帧回退值不可信(如 LR=0xffffffff), 直接结束
            break;
        }
        regs[13] = cfa as u32;
        regs[14] = ra;
        regs[15] = next_pc as u32;
        frames.push(frame_at(
            info,
            next_pc,
            cfa_of(info, next_pc, regs[13]),
            regs[13] as u64,
        ));
        if !known {
            break;
        }
    }

    if frames.len() <= 1 {
        let scanned = scan_stack(info, orig_pc, orig_sp, &mut read);
        if scanned.len() > frames.len() {
            return (scanned, true);
        }
    }
    (frames, false)
}

/// 启发式栈扫描: 在栈上找"看起来像返回地址"的字
fn scan_stack(
    info: &DebugInfo,
    pc: u64,
    mut addr: u64,
    read: &mut impl FnMut(u64, &mut [u8]) -> Result<(), String>,
) -> Vec<Frame> {
    let mut frames = vec![frame_at(info, pc, addr, addr)];
    let mut last_func = frames[0].func.clone();
    // 分块读栈(块读可被上层整块缓存命中) + 严格上限, 避免逐字扫描拖慢响应
    const SCAN_WORDS: usize = 128;
    const BLOCK: usize = 512;
    let mut served = 0usize;
    while served < SCAN_WORDS {
        let blen = (BLOCK).min((SCAN_WORDS - served) * 4);
        let mut buf = vec![0u8; blen];
        if read(addr, &mut buf).is_err() {
            break;
        }
        for k in 0..blen / 4 {
            let w = u32::from_le_bytes(buf[k * 4..k * 4 + 4].try_into().unwrap());
            if w & 1 == 1 && w != 0 && w != u32::MAX {
                let target = (w & !1) as u64;
                if let Some(f) = info.func_at(target) {
                    if last_func.as_deref() != Some(f.name.as_str()) {
                        frames.push(frame_at(info, target, addr + (k * 4) as u64, addr + (k * 4) as u64));
                        last_func = Some(f.name.clone());
                    }
                }
            }
            served += 1;
        }
        addr += blen as u64;
    }
    frames
}
