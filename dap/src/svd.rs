//! CMSIS-SVD 解析：外设 → 寄存器 → 位域。
//!
//! 只取界面需要的字段；支持 derivedFrom 继承（STM32 的 SVD 大量使用）。
//! 用手写浅解析（按标签切），不引 XML 库——SVD 是机器生成的规整 XML。

use serde_json::json;
use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct SvdField {
    pub name: String,
    pub description: String,
    pub bit_offset: u32,
    pub bit_width: u32,
    pub access: String,
    /// enumeratedValues: 值 → 人话（如 1 → "接收非空"）
    pub enum_values: Vec<(u64, String)>,
}

#[derive(Clone, Debug)]
pub struct SvdRegister {
    pub name: String,
    pub description: String,
    pub offset: u64,
    pub size: u32,
    pub access: String,
    pub fields: Vec<SvdField>,
}

#[derive(Clone, Debug)]
pub struct SvdPeripheral {
    pub name: String,
    pub description: String,
    pub base_address: u64,
    pub registers: Vec<SvdRegister>,
}

/// <derivedFrom> 解析需要两遍：先收集所有外设定义，再按名继承
#[derive(Clone)]
pub struct SvdDevice {
    pub name: String,
    pub peripherals: Vec<SvdPeripheral>,
    by_name: HashMap<String, usize>,
}

fn text_of(block: &str, tag: &str) -> String {
    // SVD 里文本可能跨行带缩进，压成单行
    let start = match block.find(&format!("<{}>", tag)) {
        Some(i) => i + tag.len() + 2,
        None => return String::new(),
    };
    let end = match block[start..].find(&format!("</{}>", tag)) {
        Some(i) => start + i,
        None => return String::new(),
    };
    block[start..end]
        .lines()
        .map(|l| l.trim())
        .collect::<Vec<_>>()
        .join(" ")
        .trim()
        .to_string()
}

fn parse_num(s: &str) -> u64 {
    let t = s.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).unwrap_or(0)
    } else if t.contains('#') {
        // 二进制字面量 #1010，'#' 后的 x 是 don't care
        u64::from_str_radix(&t[1..].trim_end_matches(['x', 'X']), 2).unwrap_or(0)
    } else {
        t.parse().unwrap_or(0)
    }
}

fn each_block<'a>(xml: &'a str, tag: &str) -> Vec<&'a str> {
    let open = format!("<{}", tag); // 前缀匹配：<peripheral> 和 <peripheral derivedFrom=".."> 都算
    let close = format!("</{}>", tag);
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(start) = rest.find(&open) {
        // 开标签必须在下一个 '>' 处结束；防止 <peripherals> 被前缀 <peripheral 误吞
        let after = &rest[start + open.len()..];
        let Some(tag_end_rel) = after.find('>') else { break };
        let tail = &after[..tag_end_rel];
        if !tail.is_empty() && !tail.starts_with([' ', '\t', '\r', '\n']) {
            rest = &after[1..];
            continue;
        }
        let body_from = &after[tag_end_rel + 1..];
        let Some(end_rel) = body_from.find(&close) else { break };
        // 返回完整元素（含开标签，属性可从里面取）
        out.push(&rest[start..start + open.len() + tag_end_rel + 1 + end_rel + close.len()]);
        rest = &body_from[end_rel + close.len()..];
    }
    out
}

fn parse_fields(fields_xml: &str) -> Vec<SvdField> {
    let mut out = Vec::new();
    for f in each_block(fields_xml, "field") {
        let name = text_of(f, "name");
        if name.is_empty() {
            continue;
        }
        // 位域位置两种写法：bitOffset+bitWidth 或 lsb/msb 或 bitRange [7:4]
        let (offset, width) = if !text_of(f, "bitRange").is_empty() {
            let range = text_of(f, "bitRange");
            let inner = range.trim_matches(|c| c == '[' || c == ']');
            let mut it = inner.split(':');
            let msb: u32 = it.next().and_then(|s| s.trim().parse().ok()).unwrap_or(0);
            let lsb: u32 = it.next().and_then(|s| s.trim().parse().ok()).unwrap_or(0);
            (lsb, msb - lsb + 1)
        } else if !text_of(f, "lsb").is_empty() {
            let lsb = parse_num(&text_of(f, "lsb")) as u32;
            let msb = parse_num(&text_of(f, "msb")) as u32;
            (lsb, msb - lsb + 1)
        } else {
            (
                parse_num(&text_of(f, "bitOffset")) as u32,
                parse_num(&text_of(f, "bitWidth")) as u32,
            )
        };
        // enumeratedValues 可能出现在 field 内，或按 usage 集合两份（read/write），取并集
        let mut enum_values = Vec::new();
        for ev_block in each_block(f, "enumeratedValues") {
            for ev in each_block(ev_block, "enumeratedValue") {
                let vname = text_of(ev, "name");
                let vdesc = text_of(ev, "description");
                let vnum = {
                    let v = text_of(ev, "value");
                    if v.is_empty() {
                        continue;
                    }
                    parse_num(&v)
                };
                let label = if vdesc.is_empty() { vname.clone() } else { format!("{} {}", vname, vdesc) };
                if !enum_values.iter().any(|(n, _): &(u64, String)| *n == vnum) {
                    enum_values.push((vnum, label));
                }
            }
        }
        out.push(SvdField {
            name,
            description: text_of(f, "description"),
            bit_offset: offset,
            bit_width: width,
            access: text_of(f, "access"),
            enum_values,
        });
    }
    out.sort_by_key(|f| f.bit_offset);
    out
}

fn parse_registers(periph_xml: &str) -> Vec<SvdRegister> {
    let mut out = Vec::new();
    // 寄存器可能在 <registers> 里，也可能平铺（继承来的）；<cluster> 当寄存器组展开
    for regs_parent in each_block(periph_xml, "registers").iter().copied().chain(std::iter::repeat(periph_xml).take(1)) {
        for r in each_block(regs_parent, "register") {
            let name = text_of(r, "name");
            if name.is_empty() {
                continue;
            }
            // 数组寄存器 %s 形式（如 UART_DR[%s]）跳过维度展开，界面按单个显示
            out.push(SvdRegister {
                name: name.replace("[%s]", ""),
                description: text_of(r, "description"),
                offset: parse_num(&text_of(r, "addressOffset")),
                size: parse_num(&text_of(r, "size")).max(8) as u32,
                access: text_of(r, "access"),
                fields: parse_fields(r),
            });
        }
        for c in each_block(regs_parent, "cluster") {
            let cname = text_of(c, "name");
            let coff: u64 = parse_num(&text_of(c, "addressOffset"));
            for r in each_block(c, "register") {
                let name = text_of(r, "name");
                if name.is_empty() {
                    continue;
                }
                out.push(SvdRegister {
                    name: format!("{}.{}", cname.replace("[%s]", ""), name.replace("[%s]", "")),
                    description: text_of(r, "description"),
                    offset: coff + parse_num(&text_of(r, "addressOffset")),
                    size: parse_num(&text_of(r, "size")).max(8) as u32,
                    access: text_of(r, "access"),
                    fields: parse_fields(r),
                });
            }
        }
        if !out.is_empty() {
            break; // 已从 <registers> 取到，避免重复
        }
    }
    out.sort_by_key(|r| r.offset);
    out
}

impl SvdDevice {
    pub fn parse(xml: &str) -> Result<SvdDevice, String> {
        // 去掉 XML 注释，防止 <!-- <tag> --> 干扰
        let mut clean = String::with_capacity(xml.len());
        let mut rest = xml;
        while let Some(i) = rest.find("<!--") {
            clean.push_str(&rest[..i]);
            let after = &rest[i..];
            match after.find("-->") {
                Some(j) => rest = &after[j + 3..],
                None => {
                    rest = after;
                    break;
                }
            }
        }
        clean.push_str(rest);

        let device_name = text_of(&clean, "name");
        let mut raw: Vec<(String, String)> = Vec::new(); // (name, block)
        for p in each_block(&clean, "peripherals") {
            for block in each_block(p, "peripheral") {
                let name = text_of(block, "name");
                if !name.is_empty() {
                    raw.push((name, block.to_string()));
                }
            }
        }
        if raw.is_empty() {
            return Err("SVD 里没有外设定义".into());
        }

        // 两遍解析处理 derivedFrom
        let by_name: HashMap<String, String> = raw.iter().cloned().collect();
        let mut peripherals = Vec::new();
        for (name, block) in &raw {
            let derived = text_of_block_attr(block);
            let base_xml: String = match &derived {
                Some(base) => by_name.get(base).cloned().unwrap_or_default(),
                None => String::new(),
            };
            let src = if base_xml.is_empty() { block.as_str() } else { &base_xml };
            // baseAddress 永远用自己 block 的（继承只补寄存器定义）
            let base = {
                let own = text_of(block, "baseAddress");
                if own.is_empty() {
                    text_of(src, "baseAddress")
                } else {
                    own
                }
            };
            peripherals.push(SvdPeripheral {
                name: name.clone(),
                description: {
                    let d = text_of(block, "description");
                    if d.is_empty() {
                        text_of(src, "description")
                    } else {
                        d
                    }
                },
                base_address: parse_num(&base),
                registers: parse_registers(src),
            });
        }
        peripherals.sort_by(|a, b| a.name.cmp(&b.name));

        let mut by_name_map = HashMap::new();
        for (i, p) in peripherals.iter().enumerate() {
            by_name_map.insert(p.name.clone(), i);
        }
        Ok(SvdDevice {
            name: device_name,
            peripherals,
            by_name: by_name_map,
        })
    }

    pub fn peripheral(&self, name: &str) -> Option<&SvdPeripheral> {
        self.by_name.get(name).map(|&i| &self.peripherals[i])
    }
}

/// <peripheral derivedFrom="XXX"> 的属性提取（text_of 不处理属性）
fn text_of_block_attr(block: &str) -> Option<String> {
    let start = block.find("<peripheral ")?;
    let tag_end = block[start..].find('>')? + start;
    let tag = &block[start..tag_end];
    let key = "derivedFrom=\"";
    let i = tag.find(key)?;
    let rest = &tag[i + key.len()..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// 读一个外设的全部寄存器值（一次块读，连续段合并）
pub fn read_peripheral(
    core: &mut probe_rs::Core<'_>,
    p: &SvdPeripheral,
) -> Result<serde_json::Value, String> {
    use probe_rs::MemoryInterface;
    let mut regs = Vec::new();
    // 按偏移排序后合并连续段（页读比逐个读快一个数量级）
    let sorted = &p.registers;
    let mut i = 0;
    while i < sorted.len() {
        let start_off = sorted[i].offset;
        let mut end_off = start_off + (sorted[i].size / 8).max(4) as u64;
        let mut j = i + 1;
        while j < sorted.len() {
            let sz = (sorted[j].size / 8).max(4) as u64;
            if sorted[j].offset >= end_off && sorted[j].offset + sz - start_off <= 1024 {
                end_off = sorted[j].offset + sz;
                j += 1;
            } else {
                break;
            }
        }
        let mut buf = vec![0u8; (end_off - start_off) as usize];
        let ok = core.read_8(p.base_address + start_off, &mut buf).is_ok();
        for r in &sorted[i..j] {
            let sz = (r.size / 8).max(4) as usize;
            let off = (r.offset - start_off) as usize;
            let value = if ok && off + sz <= buf.len() {
                let mut v = 0u64;
                for (bi, b) in buf[off..off + sz].iter().enumerate() {
                    v |= (*b as u64) << (bi * 8);
                }
                v
            } else {
                u64::MAX // 读失败标记
            };
            regs.push(json!({
                "name": r.name,
                "description": r.description,
                "offset": r.offset,
                "address": format!("0x{:08X}", p.base_address + r.offset),
                "size": r.size,
                "access": r.access,
                "value": value,
                "ok": ok,
                "fields": r.fields.iter().map(|f| json!({
                    "name": f.name,
                    "description": f.description,
                    "bitOffset": f.bit_offset,
                    "bitWidth": f.bit_width,
                    "access": f.access,
                    "enum": f.enum_values,
                })).collect::<Vec<_>>(),
            }));
        }
        i = j;
    }
    Ok(json!({
        "name": p.name,
        "description": p.description,
        "baseAddress": format!("0x{:08X}", p.base_address),
        "registers": regs,
    }))
}
