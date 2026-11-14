// Cortex-M 故障诊断: 向量捕获 + CFSR/HFSR 解码 + 压栈帧恢复
use probe_rs::{Core, MemoryInterface};

const CFSR: u64 = 0xE000_ED28;
const HFSR: u64 = 0xE000_ED2C;
const MMFAR: u64 = 0xE000_ED34;
const BFAR: u64 = 0xE000_ED38;

/// 打开 HardFault 向量捕获（故障瞬间暂停，而不是死等/锁死）
pub fn enable_vector_catch(core: &mut Core<'_>) -> Result<(), String> {
    core.enable_vector_catch(probe_rs::VectorCatchCondition::HardFault)
        .map_err(|e| format!("开启向量捕获失败: {e}"))
}

pub fn read_cfsr(core: &mut Core<'_>) -> u32 {
    core.read_word_32(CFSR).unwrap_or(0)
}

pub fn read_hfsr(core: &mut Core<'_>) -> u32 {
    core.read_word_32(HFSR).unwrap_or(0)
}

/// 清除故障标志（继续运行前调用，避免旧故障残留）
pub fn clear_faults(core: &mut Core<'_>) {
    let _ = core.write_word_32(CFSR, 0);
    let _ = core.write_word_32(HFSR, 0);
}

#[derive(Default)]
pub struct FaultInfo {
    pub cfsr: u32,
    pub hfsr: u32,
    pub mmfar: u32,
    pub bfar: u32,
}

impl FaultInfo {
    pub fn active(&self) -> bool {
        self.cfsr != 0 || self.hfsr != 0
    }

    pub fn fault_addr(&self) -> Option<u32> {
        if self.cfsr & (1 << 7) != 0 {
            Some(self.mmfar)
        } else if self.cfsr & (1 << 15) != 0 {
            Some(self.bfar)
        } else {
            None
        }
    }

    /// 人类可读的故障原因
    pub fn flags(&self) -> Vec<String> {
        let mut out = Vec::new();
        let c = self.cfsr;
        let mut add = |cond: bool, s: &str| {
            if cond {
                out.push(s.to_string());
            }
        };
        add(c & (1 << 0) != 0, "IACCVIOL: 取指访问违例（执行了不可执行区域）");
        add(c & (1 << 1) != 0, "DACCVIOL: 数据访问违例（MPU 保护）");
        add(c & (1 << 3) != 0, "MUNSTKERR: 异常返回出栈失败");
        add(c & (1 << 4) != 0, "MSTKERR: 异常入栈失败（可能栈溢出）");
        add(c & (1 << 8) != 0, "IBUSERR: 取指总线错误");
        add(c & (1 << 9) != 0, "PRECISERR: 精确数据总线错误（访问了非法地址）");
        add(c & (1 << 10) != 0, "IMPRECISERR: 非精确数据总线错误（写缓冲延迟）");
        add(c & (1 << 11) != 0, "UNSTKERR: 异常返回出栈总线错误");
        add(c & (1 << 12) != 0, "STKERR: 异常入栈总线错误（可能栈溢出）");
        add(c & (1 << 16) != 0, "UNDEFINSTR: 未定义指令");
        add(c & (1 << 17) != 0, "INVSTATE: 非法状态（跳转到非 Thumb 地址？）");
        add(c & (1 << 18) != 0, "INVPC: 非法 PC");
        add(c & (1 << 19) != 0, "NOCP: 协处理器未使能（FPU 未开启？）");
        add(c & (1 << 24) != 0, "UNALIGNED: 非对齐访问");
        add(c & (1 << 25) != 0, "DIVBYZERO: 除零");
        let h = self.hfsr;
        add(h & (1 << 30) != 0, "FORCED: 由其他故障升级而来");
        add(h & (1 << 1) != 0, "VECTTBL: 向量表读取错误");
        add(h & (1 << 31) != 0, "DEBUGEVT: 调试事件");
        out
    }
}

pub fn read_faults(core: &mut Core<'_>) -> FaultInfo {
    FaultInfo {
        cfsr: core.read_word_32(CFSR).unwrap_or(0),
        hfsr: core.read_word_32(HFSR).unwrap_or(0),
        mmfar: core.read_word_32(MMFAR).unwrap_or(0),
        bfar: core.read_word_32(BFAR).unwrap_or(0),
    }
}

/// 故障发生时的压栈帧（异常入口自动压入的寄存器）
pub struct StackedFrame {
    pub r0: u32,
    pub r1: u32,
    pub r2: u32,
    pub r3: u32,
    pub r12: u32,
    pub lr: u32,
    pub pc: u32,
    pub xpsr: u32,
    /// true = 用的是 PSP（任务栈）
    pub from_psp: bool,
}

fn read_reg_by_name(core: &mut Core<'_>, name: &str) -> Option<u32> {
    for reg in core.registers().all_registers() {
        if reg.name() == name {
            return core.read_core_reg::<u32>(reg.id()).ok();
        }
    }
    None
}

/// 从 EXC_RETURN 判断栈指针并读出压栈帧
pub fn stacked_frame(core: &mut Core<'_>) -> Option<StackedFrame> {
    let lr_reg = core.return_address().id();
    let exc_return = core.read_core_reg::<u32>(lr_reg).ok()?;
    // EXC_RETURN bit2: 1 = 使用 PSP
    let from_psp = exc_return & 0x4 != 0;
    let sp = if from_psp {
        read_reg_by_name(core, "PSP")?
    } else {
        read_reg_by_name(core, "MSP")?
    };
    let mut buf = [0u8; 32];
    core.read_8(sp as u64, &mut buf).ok()?;
    let w = |i: usize| u32::from_le_bytes(buf[i * 4..i * 4 + 4].try_into().unwrap());
    Some(StackedFrame {
        r0: w(0),
        r1: w(1),
        r2: w(2),
        r3: w(3),
        r12: w(4),
        lr: w(5),
        pc: w(6),
        xpsr: w(7),
        from_psp,
    })
}
