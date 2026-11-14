// ELF/DWARF 解析：建立 地址 ↔ 源码行 双向映射 + 函数区间表
use std::borrow::Cow;
use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};

use gimli::{AttributeValue, Dwarf, EndianSlice, RunTimeEndian, SectionId};
use object::{Object, ObjectSection, ObjectSymbol, SymbolKind};

#[derive(Clone)]
pub struct LineEntry {
    pub addr: u64,
    /// 文件索引; usize::MAX 表示 end_sequence 边界行
    pub file: usize,
    pub line: u32,
}

#[derive(Clone)]
pub struct FuncRange {
    pub start: u64,
    pub end: u64,
    pub name: String,
}

pub struct DebugInfo {
    pub elf: String,
    pub files: Vec<String>,
    /// 按地址升序
    pub entries: Vec<LineEntry>,
    /// 按起始地址升序
    pub funcs: Vec<FuncRange>,
    /// (文件索引, 行号) -> 该行最小可执行地址
    pub line_index: HashMap<(usize, u32), u64>,
    /// 全局/静态变量（带静态地址）
    pub vars: Vec<crate::variables::VarEntry>,
    /// 类型表（各 CU 合并后）
    pub types: Vec<crate::variables::TypeInfo>,
    /// .debug_frame 展开后的 CFI 规则表（按地址排序）
    pub cfi: Vec<crate::cfi::CfiRow>,
    /// 各函数的局部变量表（按起始地址排序）
    pub locals: Vec<crate::variables::FuncLocals>,
}

impl DebugInfo {
    /// 地址 -> (文件索引, 行号)
    pub fn addr_to_line(&self, addr: u64) -> Option<(usize, u32)> {
        let idx = self.entries.partition_point(|e| e.addr <= addr).checked_sub(1)?;
        let e = &self.entries[idx];
        if e.file == usize::MAX {
            return None;
        }
        Some((e.file, e.line))
    }

    /// (文件, 行号) -> 地址
    /// 在符号表里查找与编辑器路径对应的文件。
    /// 比较时忽略大小写和斜杠方向；精确匹配失败时按路径后缀匹配（取最长），
    /// 最后在同名文件唯一时回退到文件名（构建机路径与本地源码目录不一致时）。
    pub fn find_file(&self, file: &str) -> Option<usize> {
        let target = normalize_key(file);
        if target.is_empty() {
            return None;
        }

        if let Some(i) = self.files.iter().position(|f| normalize_key(f) == target) {
            return Some(i);
        }

        let mut best: Option<(usize, usize)> = None;
        for (i, f) in self.files.iter().enumerate() {
            let key = normalize_key(f);
            if path_suffix_match(&key, &target) {
                let len = key.len().min(target.len());
                if best.map_or(true, |(_, l)| len > l) {
                    best = Some((i, len));
                }
            }
        }
        if let Some((i, _)) = best {
            return Some(i);
        }

        let base = target.rsplit('/').next().unwrap_or(&target);
        let mut matches = self.files.iter().enumerate().filter(|(_, f)| {
            let key = normalize_key(f);
            key == base || key.ends_with(&format!("/{base}"))
        });
        let first = matches.next();
        if let Some((i, _)) = first {
            if matches.next().is_none() {
                return Some(i);
            }
        }
        None
    }

    pub fn line_to_addr(&self, file: &str, line: u32) -> Option<(usize, u64)> {
        let fidx = self.find_file(file)?;
        self.line_index.get(&(fidx, line)).map(|a| (fidx, *a))
    }

    /// 解析行号: 精确行优先, 无代码则吸附到 ±40 行内最近的可执行行
    /// 返回 (实际行号, 地址)
    pub fn resolve_line(&self, file: &str, line: u32) -> Option<(u32, u64)> {
        let fidx = self.find_file(file)?;
        let lookup = |l: u32| self.line_index.get(&(fidx, l)).copied();
        if let Some(a) = lookup(line) {
            return Some((line, a));
        }
        for d in 1..=40u32 {
            if let Some(l) = line.checked_sub(d) {
                if let Some(a) = lookup(l) {
                    return Some((l, a));
                }
            }
            if let Some(a) = lookup(line + d) {
                return Some((line + d, a));
            }
        }
        None
    }

    /// 查找地址对应的 CFI 行
    pub fn cfi_row(&self, addr: u64) -> Option<&crate::cfi::CfiRow> {
        let idx = self
            .cfi
            .partition_point(|r| r.start <= addr)
            .checked_sub(1)?;
        let r = &self.cfi[idx];
        if addr < r.end {
            Some(r)
        } else {
            None
        }
    }

    /// 查找地址所在函数的局部变量表
    pub fn func_locals(&self, addr: u64) -> Option<&crate::variables::FuncLocals> {
        let idx = self
            .locals
            .partition_point(|l| l.start <= addr)
            .checked_sub(1)?;
        let l = &self.locals[idx];
        if addr < l.end {
            Some(l)
        } else {
            None
        }
    }

    /// 地址所属函数
    pub fn func_at(&self, addr: u64) -> Option<&FuncRange> {
        let idx = self.funcs.partition_point(|f| f.start <= addr).checked_sub(1)?;
        let f = &self.funcs[idx];
        if addr < f.end {
            Some(f)
        } else {
            None
        }
    }
}

/// 词法规范化路径（不访问磁盘，处理 . 与 ..）
/// 路径比较用: 统一斜杠方向并忽略大小写（Windows 构建常见 D:\ 与 d:/ 混用）
fn normalize_key(path: &str) -> String {
    let mut s = path.replace('\\', "/").to_lowercase();
    while s.ends_with('/') {
        s.pop();
    }
    s
}

/// 两条路径是否互为后缀（按路径分段对齐，避免 main.c 误配到 xmain.c）
fn path_suffix_match(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    if a.len() > b.len() && a.ends_with(b) {
        return a[..a.len() - b.len()].ends_with('/');
    }
    if b.len() > a.len() && b.ends_with(a) {
        return b[..b.len() - a.len()].ends_with('/');
    }
    false
}

fn normalize(path: &Path) -> String {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out.to_string_lossy().into_owned()
}

fn attr_string<R: gimli::Reader>(dwarf: &Dwarf<R>, unit: &gimli::Unit<R>, attr: AttributeValue<R>) -> String {
    match dwarf.attr_string(unit, attr) {
        Ok(s) => s.to_string_lossy().map(|c| c.into_owned()).unwrap_or_default(),
        Err(_) => String::new(),
    }
}

pub fn load_elf(path: &str) -> Result<DebugInfo, String> {
    let data = std::fs::read(path).map_err(|e| format!("读取 ELF 失败: {e}"))?;
    let obj = object::File::parse(&*data).map_err(|e| format!("解析 ELF 失败: {e}"))?;
    let endian = if obj.is_little_endian() { RunTimeEndian::Little } else { RunTimeEndian::Big };

    // 1) 函数区间（符号表）
    let mut funcs: Vec<FuncRange> = Vec::new();
    for sym in obj.symbols() {
        if sym.kind() != SymbolKind::Text || sym.size() == 0 {
            continue;
        }
        let name = match sym.name() {
            Ok(n) if !n.is_empty() => n,
            _ => continue,
        };
        let start = sym.address() & !1;
        funcs.push(FuncRange { start, end: start + sym.size(), name: name.to_string() });
    }
    funcs.sort_by_key(|f| f.start);
    funcs.dedup_by_key(|f| f.start);

    // 2) DWARF line 表
    let dwarf_cow = Dwarf::load(|id: SectionId| -> Result<Cow<[u8]>, gimli::Error> {
        Ok(obj
            .section_by_name(id.name())
            .and_then(|s| s.uncompressed_data().ok())
            .unwrap_or(Cow::Borrowed(&[])))
    })
    .map_err(|e| format!("读取 DWARF 失败: {e}"))?;
    #[allow(deprecated)]
    let dwarf = dwarf_cow.borrow(|section| EndianSlice::new(section, endian));

    let mut files: Vec<String> = Vec::new();
    let mut file_ids: HashMap<String, usize> = HashMap::new();
    let mut entries: Vec<LineEntry> = Vec::new();

    // 变量与类型（跨 CU 解析）
    let (mut all_vars, all_types, mut all_locals) = crate::variables::collect_all_vars(&dwarf);

    let mut units = dwarf.units();
    while let Some(header) = units.next().map_err(|e| format!("遍历 DWARF 单元失败: {e}"))? {
        let unit = dwarf.unit(header).map_err(|e| format!("解析 DWARF 单元失败: {e}"))?;
        let comp_dir = unit
            .comp_dir
            .as_ref()
            .map(|d| d.to_string_lossy().into_owned())
            .unwrap_or_default();

        let program = match &unit.line_program {
            Some(p) => p.clone(),
            None => continue,
        };
        let mut rows = program.rows();
        while let Some((header, row)) = rows.next_row().map_err(|e| format!("读取行表失败: {e}"))? {
            let addr = row.address();
            if row.end_sequence() {
                entries.push(LineEntry { addr, file: usize::MAX, line: 0 });
                continue;
            }
            let line = match row.line() {
                Some(l) => l.get() as u32,
                None => continue, // 行号 0: 无源码归属
            };
            let fe = match row.file(header) {
                Some(fe) => fe,
                None => continue,
            };
            let name = attr_string(&dwarf, &unit, fe.path_name());
            if name.is_empty() {
                continue;
            }
            let dir = header.directory(fe.directory_index()).map(|a| attr_string(&dwarf, &unit, a));

            // 拼接绝对路径: 绝对名直接用; 相对名拼 dir (绝对则替换) 再拼 comp_dir
            let name_path = Path::new(&name);
            let full = if name_path.is_absolute() {
                PathBuf::from(name_path)
            } else {
                let mut base = PathBuf::from(&comp_dir);
                if let Some(d) = dir.as_deref().filter(|d| !d.is_empty()) {
                    let dp = Path::new(d);
                    if dp.is_absolute() {
                        base = dp.to_path_buf();
                    } else {
                        base.push(dp);
                    }
                }
                base.push(name_path);
                base
            };
            let full = normalize(&full);

            let fidx = *file_ids.entry(full.clone()).or_insert_with(|| {
                files.push(full);
                files.len() - 1
            });
            entries.push(LineEntry { addr, file: fidx, line });
        }
    }

    entries.sort_by_key(|e| e.addr);

    // 3) 行 -> 地址索引（取该行最小地址）
    let mut line_index: HashMap<(usize, u32), u64> = HashMap::new();
    for e in &entries {
        if e.file == usize::MAX {
            continue;
        }
        line_index
            .entry((e.file, e.line))
            .and_modify(|a| {
                if e.addr < *a {
                    *a = e.addr;
                }
            })
            .or_insert(e.addr);
    }

    all_locals.sort_by_key(|l| l.start);

    // 变量去重（同名同址）并按名字排序
    all_vars.sort_by(|a, b| a.name.cmp(&b.name).then(a.addr.cmp(&b.addr)));
    all_vars.dedup_by(|a, b| a.name == b.name && a.addr == b.addr);

    // .debug_frame -> CFI 规则表
    let cfi = {
        let data = obj
            .section_by_name(".debug_frame")
            .and_then(|s| s.uncompressed_data().ok())
            .unwrap_or_default();
        crate::cfi::load_cfi(data.as_ref())
    };

    Ok(DebugInfo {
        elf: path.to_string(),
        files,
        entries,
        funcs,
        line_index,
        vars: all_vars,
        types: all_types,
        cfi,
        locals: all_locals,
    })
}
