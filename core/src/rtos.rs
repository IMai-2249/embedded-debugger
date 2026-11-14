// FreeRTOS 运行时感知: 当前任务、任务列表、栈水位
use crate::debuginfo::DebugInfo;
use crate::variables::TypeKind;

pub struct TaskInfo {
    pub name: String,
    pub state: String,
    pub priority: u32,
    pub tcb: u32,
    pub stack_base: u32,
    pub stack_top: u32,
    /// 栈上仍为 0xa5 填充字的数量（未使用栈深度）；None = 无法判断
    pub free_words: Option<u32>,
    pub current: bool,
    /// 任务当前停在哪（PC 与函数名）
    pub pc: Option<u32>,
    pub func: Option<String>,
}

pub struct RtosSnapshot {
    pub current: Option<String>,
    pub tasks: Vec<TaskInfo>,
}

struct Mem<'a> {
    read: &'a mut dyn FnMut(u64, &mut [u8]) -> Result<(), String>,
}

impl<'a> Mem<'a> {
    fn u32(&mut self, addr: u32) -> Option<u32> {
        let mut b = [0u8; 4];
        (self.read)(addr as u64, &mut b).ok()?;
        Some(u32::from_le_bytes(b))
    }
    fn bytes(&mut self, addr: u32, n: usize) -> Option<Vec<u8>> {
        let mut b = vec![0u8; n];
        (self.read)(addr as u64, &mut b).ok()?;
        Some(b)
    }
}

/// 解析 typedef 链找到结构体成员表
fn members_of(info: &DebugInfo, tid: usize) -> Option<&Vec<crate::variables::MemberInfo>> {
    for _ in 0..8 {
        match &info.types[tid].kind {
            TypeKind::Struct { members } => return Some(members),
            _ => return None,
        }
    }
    None
}

fn member_offset(info: &DebugInfo, tid: usize, name: &str) -> Option<u64> {
    members_of(info, tid)?.iter().find(|m| m.name == name).map(|m| m.offset)
}

fn member_type(info: &DebugInfo, tid: usize, name: &str) -> Option<usize> {
    members_of(info, tid)?.iter().find(|m| m.name == name).map(|m| m.type_id)
}

fn var_addr(info: &DebugInfo, name: &str) -> Option<u32> {
    info.vars.iter().find(|v| v.name == name).map(|v| v.addr as u32)
}

fn var_type(info: &DebugInfo, name: &str) -> Option<usize> {
    info.vars.iter().find(|v| v.name == name).map(|v| v.type_id)
}

/// 解引用指针/数组/typedef 得到元素类型
fn pointed_type(info: &DebugInfo, tid: usize) -> Option<usize> {
    match &info.types[tid].kind {
        TypeKind::Pointer { target } => *target,
        TypeKind::Array { elem, .. } => Some(*elem),
        _ => Some(tid),
    }
}

pub fn detect(info: &DebugInfo) -> bool {
    var_addr(info, "pxCurrentTCB").is_some() && var_addr(info, "pxReadyTasksLists").is_some()
}

fn read_cstr(mem: &mut Mem<'_>, addr: u32, max: usize) -> Option<String> {
    let bytes = mem.bytes(addr, max)?;
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(max);
    let s: String = bytes[..end].iter().map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '?' }).collect();
    Some(s)
}

pub fn snapshot(
    info: &DebugInfo,
    read: &mut dyn FnMut(u64, &mut [u8]) -> Result<(), String>,
) -> Result<RtosSnapshot, String> {
    if !detect(info) {
        return Err("未检测到 FreeRTOS（缺少 pxCurrentTCB / pxReadyTasksLists 符号）".into());
    }
    let mut mem = Mem { read };

    let cur_tcb_addr = var_addr(info, "pxCurrentTCB").unwrap();
    let cur_tcb = mem.u32(cur_tcb_addr).ok_or("读取 pxCurrentTCB 失败")?;

    // TCB 结构类型
    let tcb_type = var_type(info, "pxCurrentTCB")
        .and_then(|t| pointed_type(info, t))
        .ok_or("无法解析 TCB_t 类型")?;
    let name_off = member_offset(info, tcb_type, "pcTaskName").ok_or("TCB_t 缺少 pcTaskName")?;
    let prio_off = member_offset(info, tcb_type, "uxPriority").ok_or("TCB_t 缺少 uxPriority")?;
    let stack_off = member_offset(info, tcb_type, "pxStack").ok_or("TCB_t 缺少 pxStack")?;
    let top_off = member_offset(info, tcb_type, "pxTopOfStack").ok_or("TCB_t 缺少 pxTopOfStack")?;
    let name_len = member_type(info, tcb_type, "pcTaskName")
        .map(|t| match &info.types[t].kind {
            TypeKind::Array { count, .. } => (*count as usize).min(32),
            _ => 16,
        })
        .unwrap_or(16);

    // List_t / ListItem_t 成员偏移
    let list_type = var_type(info, "pxReadyTasksLists")
        .and_then(|t| pointed_type(info, t))
        .ok_or("无法解析 List_t 类型")?;
    let item_count_off = member_offset(info, list_type, "uxNumberOfItems").ok_or("List_t 缺少 uxNumberOfItems")?;
    let index_off = member_offset(info, list_type, "pxIndex").ok_or("List_t 缺少 pxIndex")?;
    let item_type = member_type(info, list_type, "pxIndex")
        .and_then(|t| pointed_type(info, t))
        .ok_or("无法解析 ListItem_t 类型")?;
    let next_off = member_offset(info, item_type, "pxNext").ok_or("ListItem_t 缺少 pxNext")?;
    let owner_off = member_offset(info, item_type, "pvOwner").ok_or("ListItem_t 缺少 pvOwner")?;

    let mut tasks: Vec<TaskInfo> = Vec::new();
    let mut seen: Vec<u32> = Vec::new();

    // 收集待遍历的链表: (列表地址, 状态名)
    let mut lists: Vec<(u32, &str)> = Vec::new();
    if let Some(base) = var_addr(info, "pxReadyTasksLists") {
        if let Some(t) = var_type(info, "pxReadyTasksLists") {
            if let TypeKind::Array { count, .. } = &info.types[t].kind {
                let elem_size = info.types[list_type].size as u32;
                for i in 0..*count as u32 {
                    lists.push((base + i * elem_size, "就绪"));
                }
            }
        }
    }
    for (sym, state) in [
        ("xDelayedTaskList1", "延时"),
        ("xDelayedTaskList2", "延时"),
        ("xPendingReadyList", "就绪"),
        ("xSuspendedTaskList", "挂起"),
        ("xTasksWaitingTermination", "待删除"),
    ] {
        if let Some(a) = var_addr(info, sym) {
            lists.push((a, state));
        }
    }

    for (list_addr, state) in lists {
        let count = match mem.u32(list_addr + item_count_off as u32) {
            Some(c) => c,
            None => continue,
        };
        if count == 0 {
            continue;
        }
        let index = match mem.u32(list_addr + index_off as u32) {
            Some(i) if i != 0 => i,
            _ => continue,
        };
        // 从 pxIndex.pxNext 开始遍历环形链表
        let mut cur = match mem.u32(index + next_off as u32) {
            Some(n) if n != 0 => n,
            _ => continue,
        };
        let mut guard = 0;
        while cur != index && guard < 64 {
            guard += 1;
            let owner = mem.u32(cur + owner_off as u32).unwrap_or(0);
            if owner != 0 && !seen.contains(&owner) {
                seen.push(owner);
                let name = read_cstr(&mut mem, owner + name_off as u32, name_len)
                    .unwrap_or_default();
                let priority = mem.u32(owner + prio_off as u32).unwrap_or(0);
                let stack_base = mem.u32(owner + stack_off as u32).unwrap_or(0);
                let stack_top = mem.u32(owner + top_off as u32).unwrap_or(0);
                let free_words = stack_watermark(&mut mem, stack_base);
                let pc = task_saved_pc(info, &mut mem, stack_top);
                let func = pc.and_then(|p| info.func_at((p & !1) as u64).map(|f| f.name.clone()));
                tasks.push(TaskInfo {
                    name,
                    state: state.to_string(),
                    priority,
                    tcb: owner,
                    stack_base,
                    stack_top,
                    free_words,
                    current: owner == cur_tcb,
                    pc,
                    func,
                });
            }
            cur = match mem.u32(cur + next_off as u32) {
                Some(n) if n != 0 => n,
                _ => break,
            };
        }
    }

    // 当前任务可能不在任何链表里（正在运行）
    let mut current_name = None;
    if cur_tcb != 0 {
        if let Some(t) = tasks.iter_mut().find(|t| t.tcb == cur_tcb) {
            t.current = true;
            t.state = "运行".into();
            current_name = Some(t.name.clone());
        } else {
            let name = read_cstr(&mut mem, cur_tcb + name_off as u32, name_len).unwrap_or_default();
            let priority = mem.u32(cur_tcb + prio_off as u32).unwrap_or(0);
            let stack_base = mem.u32(cur_tcb + stack_off as u32).unwrap_or(0);
            let stack_top = mem.u32(cur_tcb + top_off as u32).unwrap_or(0);
            let free_words = stack_watermark(&mut mem, stack_base);
            let pc = task_saved_pc(info, &mut mem, stack_top);
            let func = pc.and_then(|p| info.func_at((p & !1) as u64).map(|f| f.name.clone()));
            current_name = Some(name.clone());
            tasks.push(TaskInfo {
                name,
                state: "运行".into(),
                priority,
                tcb: cur_tcb,
                stack_base,
                stack_top,
                free_words,
                current: true,
                pc,
                func,
            });
        }
    }

    // 运行中的任务排最前
    tasks.sort_by(|a, b| b.current.cmp(&a.current).then(b.priority.cmp(&a.priority)));

    Ok(RtosSnapshot {
        current: current_name,
        tasks,
    })
}

/// 探测保存的异常帧: 扫描 xPSR(T 位) 并用 lr/pc 合法性校验
/// 返回 (r0偏移, lr偏移, pc偏移, xpsr偏移)
fn frame_layout(info: &DebugInfo, mem: &mut Mem<'_>, tos: u32) -> Option<(u32, u32, u32, u32)> {
    for xp in (36u32..=140).step_by(4) {
        let Some(xpsr) = mem.u32(tos + xp) else { continue };
        // xPSR 的 T 位
        if xpsr & 0x0100_0000 == 0 {
            continue;
        }
        let Some(pc) = mem.u32(tos + xp - 4) else { continue };
        let Some(lr) = mem.u32(tos + xp - 8) else { continue };
        if pc == 0 || info.func_at((pc & !1) as u64).is_none() {
            continue;
        }
        if lr & 1 != 1 || info.func_at((lr & !1) as u64).is_none() {
            continue;
        }
        return Some((xp - 28, xp - 8, xp - 4, xp));
    }
    None
}

/// 从任务保存的异常帧里读 PC
fn task_saved_pc(info: &DebugInfo, mem: &mut Mem<'_>, top_of_stack: u32) -> Option<u32> {
    let (_, _, pc_off, _) = frame_layout(info, mem, top_of_stack)?;
    mem.u32(top_of_stack + pc_off)
}

/// 重建非运行任务的寄存器上下文（用于回溯该任务的调用栈）
pub fn task_regs(
    info: &DebugInfo,
    tcb: u32,
    read: &mut dyn FnMut(u64, &mut [u8]) -> Result<(), String>,
) -> Option<[u32; 16]> {
    let mut mem = Mem { read };
    let tcb_type = var_type(info, "pxCurrentTCB")
        .and_then(|t| pointed_type(info, t))?;
    let top_off = member_offset(info, tcb_type, "pxTopOfStack")?;
    let tos = mem.u32(tcb + top_off as u32)?;
    if tos == 0 {
        return None;
    }
    let mut regs = [0u32; 16];
    // 软件帧: r4-r11
    for i in 0..8u32 {
        regs[4 + i as usize] = mem.u32(tos + i * 4)?;
    }
    let (r0_off, lr_off, pc_off, _) = frame_layout(info, &mut mem, tos)?;
    for i in 0..4u32 {
        regs[i as usize] = mem.u32(tos + r0_off + i * 4)?;
    }
    regs[12] = mem.u32(tos + r0_off + 16)?;
    regs[14] = mem.u32(tos + lr_off)?;
    regs[15] = mem.u32(tos + pc_off)? | 1; // 恢复 thumb 位
    regs[13] = tos + r0_off + 32;
    Some(regs)
}

/// 栈水位: 从栈底向上数连续的 0xa5 填充字（FreeRTOS 未使用栈）
fn stack_watermark(mem: &mut Mem<'_>, stack_base: u32) -> Option<u32> {
    if stack_base == 0 {
        return None;
    }
    let mut words = 0u32;
    let mut addr = stack_base;
    for _ in 0..2048 {
        match mem.u32(addr) {
            Some(w) if w == 0xa5a5_a5a5 => {
                words += 1;
                addr += 4;
            }
            _ => break,
        }
    }
    // 一个字都没找到 0xa5, 可能未开启填充, 返回 None
    if words == 0 {
        None
    } else {
        Some(words)
    }
}

/// 只读当前任务名（供状态栏轮询用，开销极小）
pub fn current_task_name(
    info: &DebugInfo,
    read: &mut dyn FnMut(u64, &mut [u8]) -> Result<(), String>,
) -> Option<String> {
    let var = info.vars.iter().find(|v| v.name == "pxCurrentTCB")?;
    let mut mem = Mem { read };
    let tcb = mem.u32(var.addr as u32)?;
    if tcb == 0 {
        return None;
    }
    let tcb_type = pointed_type(info, var.type_id)?;
    let name_off = member_offset(info, tcb_type, "pcTaskName")?;
    let name_len = member_type(info, tcb_type, "pcTaskName")
        .map(|t| match &info.types[t].kind {
            TypeKind::Array { count, .. } => (*count as usize).min(32),
            _ => 16,
        })
        .unwrap_or(16);
    read_cstr(&mut mem, tcb + name_off as u32, name_len)
}
