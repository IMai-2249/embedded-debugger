// DWARF 变量与类型解析: 全局/静态变量提取、类型布局、值格式化（支持跨 CU 类型引用）
use std::collections::HashMap;

use gimli::constants as dw;
use gimli::{
    AttributeValue, DebuggingInformationEntry, Dwarf, DwAte, EndianSlice, Reader as _,
    RunTimeEndian, Unit, UnitOffset,
};

type Rd<'a> = EndianSlice<'a, RunTimeEndian>;

#[derive(Clone)]
pub enum TypeKind {
    Base { encoding: DwAte },
    Pointer { target: Option<usize> },
    Struct { members: Vec<MemberInfo> },
    Array { elem: usize, count: u64 },
    Enum { variants: Vec<(String, i64)> },
    Unknown,
}

#[derive(Clone)]
pub struct MemberInfo {
    pub name: String,
    pub offset: u64,
    pub type_id: usize,
}

#[derive(Clone)]
pub struct TypeInfo {
    pub name: String,
    pub size: u64,
    pub kind: TypeKind,
}

/// location list 的一段有效范围
#[derive(Clone, Debug)]
pub struct LocRange {
    pub start: u64,
    pub end: u64,
    pub loc: LocalLoc,
}

/// 局部变量的位置规则
#[derive(Clone, Debug)]
pub enum LocalLoc {
    /// 值直接在寄存器中
    Reg(u16),
    /// 地址 = 寄存器 + 偏移 (DW_OP_breg)
    AddrRegOff(u16, i64),
    /// 地址 = 帧基址 + 偏移 (DW_OP_fbreg)
    AddrFbReg(i64),
    /// 地址 = CFA (DW_OP_call_frame_cfa)
    AddrCfa,
    /// location list: 按 PC 范围选择规则（GCC -O1 常见）
    List(Vec<LocRange>),
    /// 编译期常量（优化后的局部变量，DW_OP_litN/const + DW_OP_stack_value）
    Const(i64),
}

/// 函数的帧基址规则
#[derive(Clone, Debug)]
pub enum FrameBase {
    /// CFA
    Cfa,
    /// 寄存器 + 偏移
    Reg(u16, i64),
}

#[derive(Clone)]
pub struct LocalVar {
    pub name: String,
    pub type_id: usize,
    pub type_name: String,
    pub loc: LocalLoc,
}

#[derive(Clone)]
pub struct FuncLocals {
    pub start: u64,
    pub end: u64,
    pub frame_base: FrameBase,
    pub vars: Vec<LocalVar>,
}

#[derive(Clone)]
pub struct VarEntry {
    pub name: String,
    pub addr: u64,
    pub type_id: usize,
    pub type_name: String,
}

struct TypeCtx<'u, 'a> {
    dwarf: &'u Dwarf<Rd<'a>>,
    units: &'u [Unit<Rd<'a>>],
    starts: &'u [u64],
    cache: HashMap<u64, usize>,
    types: Vec<TypeInfo>,
}

impl<'u, 'a> TypeCtx<'u, 'a> {
    fn attr_name(
        &self,
        unit: &Unit<Rd<'a>>,
        entry: &DebuggingInformationEntry<Rd<'a>>,
    ) -> Option<String> {
        let v = entry.attr_value(dw::DW_AT_name)?;
        let s = self.dwarf.attr_string(unit, v).ok()?;
        Some(s.to_string_lossy().into_owned())
    }

    fn attr_udata(
        &self,
        entry: &DebuggingInformationEntry<Rd<'a>>,
        at: gimli::DwAt,
    ) -> Option<u64> {
        match entry.attr_value(at)? {
            AttributeValue::Udata(n) => Some(n),
            AttributeValue::Sdata(n) => Some(n.max(0) as u64),
            AttributeValue::Data1(n) => Some(n as u64),
            AttributeValue::Data2(n) => Some(n as u64),
            AttributeValue::Data4(n) => Some(n as u64),
            AttributeValue::Data8(n) => Some(n),
            _ => None,
        }
    }

    /// 成员偏移: 兼容常量形式和 Keil 的 DW_OP_plus_uconst 表达式形式
    fn attr_member_offset(&self, entry: &DebuggingInformationEntry<Rd<'a>>) -> Option<u64> {
        match entry.attr_value(dw::DW_AT_data_member_location)? {
            AttributeValue::Udata(n) => Some(n),
            AttributeValue::Sdata(n) => Some(n.max(0) as u64),
            AttributeValue::Exprloc(expr) => {
                let bytes = expr.0.to_slice().ok()?;
                let b = bytes.as_ref();
                let mut pos = 1usize;
                // DW_OP_plus_uconst = 0x23
                if b.first().copied() == Some(0x23) {
                    return uleb_simple(b, &mut pos);
                }
                None
            }
            _ => None,
        }
    }

    /// 类型引用 -> 全局(.debug_info 绝对)偏移
    fn type_abs(&self, start: u64, entry: &DebuggingInformationEntry<Rd<'a>>) -> Option<u64> {
        match entry.attr_value(dw::DW_AT_type)? {
            AttributeValue::UnitRef(off) => Some(start + off.0 as u64),
            AttributeValue::DebugInfoRef(off) => Some(off.0 as u64),
            _ => None,
        }
    }

    /// 按绝对偏移定位所属 CU
    fn unit_of(&self, abs: u64) -> Option<usize> {
        let idx = self.starts.partition_point(|&s| s <= abs).checked_sub(1)?;
        Some(idx)
    }

    fn type_id_at(&mut self, abs: u64) -> usize {
        if let Some(&id) = self.cache.get(&abs) {
            return id;
        }
        // 先占位, 防自引用类型无限递归
        let id = self.types.len();
        self.cache.insert(abs, id);
        self.types.push(TypeInfo {
            name: "?".into(),
            size: 0,
            kind: TypeKind::Unknown,
        });
        let info = self.build(abs).unwrap_or(TypeInfo {
            name: "?".into(),
            size: 0,
            kind: TypeKind::Unknown,
        });
        self.types[id] = info;
        id
    }

    fn build(&mut self, abs: u64) -> Option<TypeInfo> {
        let idx = self.unit_of(abs)?;
        let start = self.starts[idx];
        // Unit 未实现 Clone, 用 header + Arc<Abbreviations> 重建一个独立实例
        let unit = {
            let src = &self.units[idx];
            Unit::new_with_abbreviations(
                self.dwarf,
                src.header.clone(),
                src.abbreviations.clone(),
            )
            .ok()?
        };
        let off = UnitOffset((abs - start) as usize);
        let entry = unit.entry(off).ok()?;
        let tag = entry.tag();
        let name = self.attr_name(&unit, &entry);
        let size = self.attr_udata(&entry, dw::DW_AT_byte_size);
        let target = self.type_abs(start, &entry);

        match tag {
            dw::DW_TAG_base_type => {
                let encoding = match entry.attr_value(dw::DW_AT_encoding) {
                    Some(AttributeValue::Encoding(e)) => e,
                    _ => dw::DW_ATE_unsigned,
                };
                Some(TypeInfo {
                    name: name.unwrap_or_else(|| "?".into()),
                    size: size.unwrap_or(4),
                    kind: TypeKind::Base { encoding },
                })
            }
            dw::DW_TAG_pointer_type | dw::DW_TAG_reference_type => {
                let tid = target.map(|o| self.type_id_at(o));
                let name = match tid {
                    Some(t) => format!("{} *", self.types[t].name),
                    None => "void *".into(),
                };
                Some(TypeInfo {
                    name,
                    size: size.unwrap_or(4),
                    kind: TypeKind::Pointer { target: tid },
                })
            }
            dw::DW_TAG_typedef => {
                let t = target.map(|o| self.type_id_at(o))?;
                let mut info = self.types[t].clone();
                if let Some(n) = name {
                    info.name = n;
                }
                Some(info)
            }
            dw::DW_TAG_const_type | dw::DW_TAG_volatile_type | dw::DW_TAG_restrict_type => {
                let t = target.map(|o| self.type_id_at(o))?;
                Some(self.types[t].clone())
            }
            dw::DW_TAG_structure_type | dw::DW_TAG_union_type => {
                let mut raw: Vec<(String, u64, u64)> = Vec::new();
                {
                    let mut tree = unit.entries_tree(Some(off)).ok()?;
                    let root = tree.root().ok()?;
                    let mut children = root.children();
                    while let Ok(Some(child)) = children.next() {
                        let e = child.entry();
                        if e.tag() != dw::DW_TAG_member {
                            continue;
                        }
                        let mname = self.attr_name(&unit, e).unwrap_or_else(|| "<匿名>".into());
                        let moff = self.attr_member_offset(e).unwrap_or(0);
                        if let Some(mt) = self.type_abs(start, e) {
                            raw.push((mname, moff, mt));
                        }
                    }
                }
                let mut members = Vec::new();
                for (mname, moff, mt) in raw {
                    let mtid = self.type_id_at(mt);
                    members.push(MemberInfo {
                        name: mname,
                        offset: moff,
                        type_id: mtid,
                    });
                }
                let size = size.unwrap_or_else(|| {
                    members
                        .iter()
                        .map(|m| m.offset + self.types[m.type_id].size)
                        .max()
                        .unwrap_or(0)
                });
                let kind_name = if tag == dw::DW_TAG_union_type {
                    "union"
                } else {
                    "struct"
                };
                Some(TypeInfo {
                    name: format!(
                        "{} {}",
                        kind_name,
                        name.unwrap_or_else(|| "<匿名>".into())
                    ),
                    size,
                    kind: TypeKind::Struct { members },
                })
            }
            dw::DW_TAG_array_type => {
                let elem = target.map(|o| self.type_id_at(o))?;
                let dbg = std::env::var_os("DWARF_DEBUG").is_some();
                let count = {
                    let mut count = 0u64;
                    if let Ok(mut tree) = unit.entries_tree(Some(off)) {
                        if let Ok(root) = tree.root() {
                            let mut children = root.children();
                            while let Ok(Some(child)) = children.next() {
                                let e = child.entry();
                                if e.tag() != dw::DW_TAG_subrange_type {
                                    continue;
                                }
                                count = self
                                    .attr_udata(e, dw::DW_AT_count)
                                    .or_else(|| {
                                        self.attr_udata(e, dw::DW_AT_upper_bound).map(|u| u + 1)
                                    })
                                    .unwrap_or(0);
                                if dbg {
                                    eprintln!("[dwarf] subrange found, count={count}, ub={:?}, cnt={:?}",
                                        e.attr_value(dw::DW_AT_upper_bound).map(|v| format!("{v:?}")),
                                        e.attr_value(dw::DW_AT_count).map(|v| format!("{v:?}")));
                                }
                                break;
                            }
                        }
                    }
                    count
                };
                if dbg {
                    eprintln!("[dwarf] array at abs=0x{abs:x} count={count} elem={}", self.types[elem].name);
                }
                let elem_name = self.types[elem].name.clone();
                let size = size.unwrap_or(self.types[elem].size * count);
                Some(TypeInfo {
                    name: format!("{elem_name}[{count}]"),
                    size,
                    kind: TypeKind::Array { elem, count },
                })
            }
            dw::DW_TAG_enumeration_type => {
                let mut variants = Vec::new();
                {
                    let mut tree = unit.entries_tree(Some(off)).ok()?;
                    let root = tree.root().ok()?;
                    let mut children = root.children();
                    while let Ok(Some(child)) = children.next() {
                        let e = child.entry();
                        if e.tag() != dw::DW_TAG_enumerator {
                            continue;
                        }
                        let vname = self.attr_name(&unit, e).unwrap_or_else(|| "?".into());
                        let val = match e.attr_value(dw::DW_AT_const_value) {
                            Some(AttributeValue::Sdata(v)) => v,
                            Some(AttributeValue::Udata(v)) => v as i64,
                            _ => 0,
                        };
                        variants.push((vname, val));
                    }
                }
                Some(TypeInfo {
                    name: format!("enum {}", name.unwrap_or_else(|| "<匿名>".into())),
                    size: size.unwrap_or(4),
                    kind: TypeKind::Enum { variants },
                })
            }
            _ => Some(TypeInfo {
                name: name.unwrap_or_else(|| "?".into()),
                size: size.unwrap_or(0),
                kind: TypeKind::Unknown,
            }),
        }
    }
}

/// 收集所有 CU 中具有静态地址的变量(全局 + static 局部), 跨 CU 解析类型
pub fn collect_all_vars(dwarf: &Dwarf<Rd<'_>>) -> (Vec<VarEntry>, Vec<TypeInfo>, Vec<FuncLocals>) {
    // 第一遍: 建立 CU 表
    let mut units: Vec<Unit<Rd<'_>>> = Vec::new();
    let mut starts: Vec<u64> = Vec::new();
    let mut headers = dwarf.units();
    while let Ok(Some(header)) = headers.next() {
        let Ok(unit) = dwarf.unit(header) else { continue };
        let start = unit
            .header
            .offset()
            .to_debug_info_offset(&unit.header)
            .map(|o| o.0 as u64)
            .unwrap_or(0);
        starts.push(start);
        units.push(unit);
    }

    let mut ctx = TypeCtx {
        dwarf,
        units: &units,
        starts: &starts,
        cache: HashMap::new(),
        types: Vec::new(),
    };
    let mut vars = Vec::new();
    let mut locals: Vec<FuncLocals> = Vec::new();

    // 第二遍: 遍历各 CU 的 DIE 树收集变量
    for (idx, unit) in units.iter().enumerate() {
        let start = starts[idx];
        if let Ok(mut tree) = unit.entries_tree(None) {
            if let Ok(root) = tree.root() {
                walk(root, unit, start, &mut ctx, &mut vars, &mut locals);
            }
        }
    }

    (vars, ctx.types, locals)
}

fn walk<'a>(
    node: gimli::EntriesTreeNode<'_, '_, Rd<'a>>,
    unit: &Unit<Rd<'a>>,
    start: u64,
    ctx: &mut TypeCtx<'_, 'a>,
    out: &mut Vec<VarEntry>,
    locals: &mut Vec<FuncLocals>,
) {
    let entry = node.entry();
    if entry.tag() == dw::DW_TAG_subprogram {
        collect_func_locals(node, unit, start, ctx, locals);
        return; // 子树已由 collect_func_locals 处理(避免重复遍历)
    }
    if entry.tag() == dw::DW_TAG_variable {
        let name = ctx.attr_name(unit, entry);
        let type_abs = ctx.type_abs(start, entry);
        let addr = var_addr(entry, unit);
        if let (Some(name), Some(type_abs), Some(addr)) = (name, type_abs, addr) {
            if !name.starts_with('$') && addr != 0 {
                let tid = ctx.type_id_at(type_abs);
                out.push(VarEntry {
                    name,
                    addr,
                    type_id: tid,
                    type_name: ctx.types[tid].name.clone(),
                });
            }
        }
    }
    let mut children = node.children();
    while let Ok(Some(child)) = children.next() {
        walk(child, unit, start, ctx, out, locals);
    }
}

/// 收集一个函数的局部变量（含帧基址规则）
fn collect_func_locals<'a>(
    node: gimli::EntriesTreeNode<'_, '_, Rd<'a>>,
    unit: &Unit<Rd<'a>>,
    start: u64,
    ctx: &mut TypeCtx<'_, 'a>,
    locals: &mut Vec<FuncLocals>,
) {
    let entry = node.entry();
    let dbg = std::env::var_os("DWARF_DEBUG").is_some();
    // 函数地址范围
    let low = match entry.attr_value(dw::DW_AT_low_pc) {
        Some(AttributeValue::Addr(a)) => a,
        other => {
            if dbg {
                eprintln!("[dwarf] subprogram low_pc 形式不支持: {other:?} name={:?}",
                    entry.attr_value(dw::DW_AT_name).map(|v| format!("{v:?}")));
            }
            return; // 声明(无地址)跳过
        }
    };
    let end = match entry.attr_value(dw::DW_AT_high_pc) {
        Some(AttributeValue::Addr(a)) => a,
        Some(AttributeValue::Udata(n)) => low + n,
        _ => return,
    };
    // 帧基址
    let mut frame_base = FrameBase::Cfa;
    if let Some(AttributeValue::Exprloc(expr)) = entry.attr_value(dw::DW_AT_frame_base) {
        if let Ok(bytes) = expr.0.to_slice() {
            let b = bytes.as_ref();
            if let Some(&op) = b.first() {
                if op == 0x9c {
                    frame_base = FrameBase::Cfa;
                } else if (0x70..=0x8f).contains(&op) {
                    let mut pos = 1usize;
                    if let Some(off) = sleb_simple(b, &mut pos) {
                        frame_base = FrameBase::Reg((op - 0x70) as u16, off);
                    }
                }
            }
        }
    }

    let mut vars = Vec::new();
    let mut children = node.children();
    while let Ok(Some(child)) = children.next() {
        collect_locals_from(child, unit, start, ctx, &mut vars);
    }
    if dbg {
        eprintln!("[dwarf] 函数 0x{low:08x}-0x{end:08x} 帧基址={frame_base:?} 局部变量 {}", vars.len());
    }
    if !vars.is_empty() {
        locals.push(FuncLocals {
            start: low,
            end,
            frame_base,
            vars,
        });
    }
}

fn collect_locals_from<'a>(
    node: gimli::EntriesTreeNode<'_, '_, Rd<'a>>,
    unit: &Unit<Rd<'a>>,
    start: u64,
    ctx: &mut TypeCtx<'_, 'a>,
    out: &mut Vec<LocalVar>,
) {
    let entry = node.entry();
    match entry.tag() {
        dw::DW_TAG_variable => {
            let dbg = std::env::var_os("DWARF_DEBUG").is_some();
            let nm = ctx.attr_name(unit, entry);
            let ta = ctx.type_abs(start, entry);
            if dbg {
                eprintln!("[dwarf]   局部 var name={nm:?} type_abs={ta:?} loc_attr={:?}",
                    entry.attr_value(dw::DW_AT_location).map(|v| format!("{v:?}")));
            }
            if let (Some(name), Some(type_abs)) = (nm, ta) {
                let loc = match entry.attr_value(dw::DW_AT_location) {
                    Some(AttributeValue::Exprloc(expr)) => {
                        expr.0.to_slice().ok().and_then(|b| parse_local_loc(b.as_ref()))
                    }
                    Some(AttributeValue::LocationListsRef(off)) => {
                        let entries = parse_loclist(ctx.dwarf, unit, off);
                        if entries.is_empty() { None } else { Some(LocalLoc::List(entries)) }
                    }
                    Some(AttributeValue::DebugLocListsIndex(idx)) => ctx
                        .dwarf
                        .locations_offset(unit, idx)
                        .ok()
                        .and_then(|off| {
                            let entries = parse_loclist(ctx.dwarf, unit, off);
                            if entries.is_empty() { None } else { Some(LocalLoc::List(entries)) }
                        }),
                    _ => None,
                };
                if dbg {
                    eprintln!("[dwarf]   局部 var {name:?} loc={loc:?}");
                }
                if let Some(loc) = loc {
                    let tid = ctx.type_id_at(type_abs);
                    out.push(LocalVar {
                        name,
                        type_id: tid,
                        type_name: ctx.types[tid].name.clone(),
                        loc,
                    });
                }
            }
        }
        dw::DW_TAG_lexical_block => {
            let mut children = node.children();
            while let Ok(Some(child)) = children.next() {
                collect_locals_from(child, unit, start, ctx, out);
            }
        }
        _ => {}
    }
}

/// 解析 location list（DWARF4 .debug_loc / DWARF5 .debug_loclists）
fn parse_loclist<'a>(
    dwarf: &Dwarf<Rd<'a>>,
    unit: &Unit<Rd<'a>>,
    offset: gimli::LocationListsOffset<usize>,
) -> Vec<LocRange> {
    let mut out = Vec::new();
    let dbg = std::env::var_os("DWARF_DEBUG").is_some();
    match dwarf.locations(unit, offset) {
        Ok(mut iter) => loop {
            match iter.next() {
                Ok(Some(e)) => {
                    let bytes = e.data.0.to_slice().ok().map(|c| c.into_owned());
                    if dbg {
                        eprintln!(
                            "[dwarf]   loclist 段 0x{:08x}-0x{:08x} data={:02x?}",
                            e.range.begin, e.range.end, bytes.as_deref()
                        );
                    }
                    if let Some(b) = bytes {
                        if let Some(loc) = parse_local_loc(b.as_ref()) {
                            out.push(LocRange {
                                start: e.range.begin,
                                end: e.range.end,
                                loc,
                            });
                        }
                    }
                }
                Ok(None) => break,
                Err(err) => {
                    if dbg {
                        eprintln!("[dwarf]   loclist 迭代错误: {err}");
                    }
                    break;
                }
            }
        },
        Err(err) => {
            if dbg {
                eprintln!("[dwarf]   loclist 打开失败: {err}");
            }
        }
    }
    out
}

/// 解析局部变量位置表达式（支持 fbreg / breg / reg / call_frame_cfa）
fn parse_local_loc(b: &[u8]) -> Option<LocalLoc> {
    let &op = b.first()?;
    let mut pos = 1usize;
    // DW_OP_stack_value 表示"表达式的值就是变量值"
    let has_stack_value = |pos: usize| b.get(pos).copied() == Some(0x9f);
    match op {
        0x9c => Some(LocalLoc::AddrCfa),
        0x91 => sleb_simple(b, &mut pos).map(LocalLoc::AddrFbReg),
        op @ 0x70..=0x8f => {
            let reg = (op - 0x70) as u16;
            sleb_simple(b, &mut pos).map(|off| LocalLoc::AddrRegOff(reg, off))
        }
        op @ 0x50..=0x6f => Some(LocalLoc::Reg((op - 0x50) as u16)),
        // DW_OP_regx: ULEB 寄存器号
        0x90 => uleb_simple(b, &mut pos).map(|r| LocalLoc::Reg(r as u16)),
        // DW_OP_bregx: ULEB 寄存器号 + SLEB 偏移
        0x92 => {
            let r = uleb_simple(b, &mut pos)? as u16;
            sleb_simple(b, &mut pos).map(|off| LocalLoc::AddrRegOff(r, off))
        }
        // DW_OP_lit0..31 + stack_value = 常量
        op @ 0x30..=0x4f => {
            if has_stack_value(pos) {
                Some(LocalLoc::Const((op - 0x30) as i64))
            } else {
                None
            }
        }
        // DW_OP_const1u/1s/2u/2s/4u/4s/8u/8s + stack_value = 常量
        0x08..=0x0f => {
            let v: i64 = match op {
                0x08 => *b.get(pos)? as i64,
                0x09 => *b.get(pos)? as i8 as i64,
                0x0a => i16::from_le_bytes(b.get(pos..pos + 2)?.try_into().ok()?) as u16 as i64,
                0x0b => i16::from_le_bytes(b.get(pos..pos + 2)?.try_into().ok()?) as i64,
                0x0c => u32::from_le_bytes(b.get(pos..pos + 4)?.try_into().ok()?) as i64,
                0x0d => i32::from_le_bytes(b.get(pos..pos + 4)?.try_into().ok()?) as i64,
                0x0e => u64::from_le_bytes(b.get(pos..pos + 8)?.try_into().ok()?) as i64,
                0x0f => i64::from_le_bytes(b.get(pos..pos + 8)?.try_into().ok()?),
                _ => return None,
            };
            // 定位 stack_value：按操作码长度跳过数据
            let len = match op {
                0x08 | 0x09 => 1,
                0x0a | 0x0b => 2,
                0x0c | 0x0d => 4,
                _ => 8,
            };
            if has_stack_value(pos + len) {
                Some(LocalLoc::Const(v))
            } else {
                None
            }
        }
        _ => None,
    }
}

fn sleb_simple(data: &[u8], pos: &mut usize) -> Option<i64> {
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

fn var_addr<R: gimli::Reader>(
    entry: &DebuggingInformationEntry<R>,
    unit: &Unit<R>,
) -> Option<u64> {
    match entry.attr_value(dw::DW_AT_location)? {
        AttributeValue::Addr(a) => Some(a),
        AttributeValue::Exprloc(expr) => {
            // 直接解析 DW_OP_addr(0x03): 后面跟 address_size 字节小端地址
            let bytes = expr.0.to_slice().ok()?;
            let bytes = bytes.as_ref();
            if bytes.first().copied() == Some(0x03) {
                let addr_size = unit.encoding().address_size as usize;
                let data = bytes.get(1..1 + addr_size)?;
                let mut buf = [0u8; 8];
                buf[..addr_size].copy_from_slice(data);
                Some(u64::from_le_bytes(buf))
            } else {
                None
            }
        }
        _ => None,
    }
}

fn uleb_simple(data: &[u8], pos: &mut usize) -> Option<u64> {
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

// ---------- 值格式化 ----------

pub fn format_var(
    types: &[TypeInfo],
    tid: usize,
    bytes: &[u8],
    expand: bool,
) -> (String, Vec<(String, String)>) {
    let mut members = Vec::new();
    let value = fmt(types, tid, bytes, expand, &mut members);
    (value, members)
}

fn read_uint(bytes: &[u8], size: usize) -> u64 {
    let mut buf = [0u8; 8];
    let n = size.min(8).min(bytes.len());
    buf[..n].copy_from_slice(&bytes[..n]);
    u64::from_le_bytes(buf)
}

fn read_int(bytes: &[u8], size: usize) -> i64 {
    let v = read_uint(bytes, size);
    let bits = (size.min(8) * 8) as u32;
    if bits == 0 {
        return 0;
    }
    let shift = 64 - bits;
    ((v << shift) as i64) >> shift
}

fn format_base(enc: DwAte, size: u64, bytes: &[u8]) -> String {
    let n = size as usize;
    if enc == dw::DW_ATE_float {
        return match n {
            4 => f32::from_bits(read_uint(bytes, 4) as u32).to_string(),
            8 => f64::from_bits(read_uint(bytes, 8)).to_string(),
            _ => format!("0x{:x}", read_uint(bytes, n)),
        };
    }
    if enc == dw::DW_ATE_boolean {
        return if read_uint(bytes, n) != 0 {
            "true".into()
        } else {
            "false".into()
        };
    }
    if enc == dw::DW_ATE_signed_char || enc == dw::DW_ATE_unsigned_char || enc == dw::DW_ATE_UTF {
        let v = read_uint(bytes, n);
        let c = char::from_u32(v as u32).unwrap_or('?');
        return if c.is_ascii_graphic() || c == ' ' {
            format!("'{c}' (0x{v:02x})")
        } else {
            format!("0x{v:02x}")
        };
    }
    if enc == dw::DW_ATE_signed {
        return format!("{}", read_int(bytes, n));
    }
    if enc == dw::DW_ATE_unsigned || enc == dw::DW_ATE_address {
        return format!("{}", read_uint(bytes, n));
    }
    format!("0x{:x}", read_uint(bytes, n))
}

fn fmt(
    types: &[TypeInfo],
    tid: usize,
    bytes: &[u8],
    expand: bool,
    members: &mut Vec<(String, String)>,
) -> String {
    let t = &types[tid];
    match &t.kind {
        TypeKind::Base { encoding } => format_base(*encoding, t.size, bytes),
        TypeKind::Pointer { .. } => {
            if bytes.len() >= 4 {
                format!("0x{:08x}", read_uint(bytes, 4) as u32)
            } else {
                "?".into()
            }
        }
        TypeKind::Enum { variants } => {
            let v = read_int(bytes, t.size as usize);
            match variants.iter().find(|(_, val)| *val == v) {
                Some((name, _)) => format!("{name} ({v})"),
                None => format!("{v}"),
            }
        }
        TypeKind::Struct { members: ms } => {
            if !expand {
                return format!("{{{} 个成员}}", ms.len());
            }
            for m in ms.iter().take(32) {
                let off = m.offset as usize;
                let msize = types[m.type_id].size as usize;
                let val = if msize > 0 && off + msize <= bytes.len() {
                    fmt(types, m.type_id, &bytes[off..off + msize], false, members)
                } else if off < bytes.len() {
                    fmt(types, m.type_id, &bytes[off..], false, members)
                } else {
                    "<越界>".into()
                };
                members.push((m.name.clone(), val));
            }
            if ms.len() > 32 {
                members.push(("…".into(), format!("还有 {} 个成员", ms.len() - 32)));
            }
            format!("{{{} 个成员}}", ms.len())
        }
        TypeKind::Array { elem, count } => {
            if !expand {
                return format!("[{count}]");
            }
            let esize = types[*elem].size as usize;
            let n = (*count as usize).min(16);
            for i in 0..n {
                let off = i * esize;
                if esize > 0 && off + esize <= bytes.len() {
                    let v = fmt(types, *elem, &bytes[off..off + esize], false, members);
                    members.push((format!("[{i}]"), v));
                } else {
                    members.push((format!("[{i}]"), "<越界>".into()));
                }
            }
            if (*count as usize) > 16 {
                members.push(("…".into(), format!("还有 {} 项", *count as usize - 16)));
            }
            format!("[{count}]")
        }
        TypeKind::Unknown => {
            if t.size == 0 {
                "?".into()
            } else {
                format!("<{} 字节>", t.size)
            }
        }
    }
}
