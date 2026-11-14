//! 目标架构抽象：按 probe-rs 报告的核心类型分派架构相关行为。
//!
//! 多架构路线：ARM Cortex-M 全链路已真机验证；RISC-V 反汇编引擎已就绪
//! （capstone 默认启用 arch_riscv），调试/断点/故障分析等链路待真机接入后
//! 在此分派，不在业务代码里散落架构判断。

use probe_rs::config::CoreType;
use probe_rs::Session;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Arch {
    /// Cortex-M（Thumb / Thumb-2 混编，半字对齐）
    ArmThumb,
    /// RV32（I/M/A/C/F/D，含压缩指令，4 字节对齐）
    Riscv32,
    /// 未知核心：按现状行为（Thumb）兜底并降级
    Unknown,
}

impl Arch {
    /// 从核心类型推断架构
    pub fn from_core_type(ct: CoreType) -> Arch {
        match ct {
            CoreType::Armv6m | CoreType::Armv7m | CoreType::Armv7em | CoreType::Armv8m => {
                Arch::ArmThumb
            }
            CoreType::Riscv => Arch::Riscv32,
            _ => Arch::Unknown,
        }
    }

    /// 从会话目标声明的第一个核心类型推断
    pub fn of_session(session: &Session) -> Arch {
        session
            .target()
            .cores
            .first()
            .map(|c| Arch::from_core_type(c.core_type))
            .unwrap_or(Arch::Unknown)
    }

    /// 构造反汇编器。未知架构按 Thumb 兜底（与历史行为一致）。
    pub fn capstone_builder(&self) -> Result<capstone::Capstone, capstone::Error> {
        use capstone::arch::{arm, riscv, BuildsCapstone};
        use capstone::Capstone;
        match self {
            Arch::Riscv32 => Capstone::new()
                .riscv()
                .mode(riscv::ArchMode::RiscV32)
                .build(),
            Arch::ArmThumb | Arch::Unknown => {
                Capstone::new().arm().mode(arm::ArchMode::Thumb).build()
            }
        }
    }

    /// 指令地址对齐掩码
    pub fn pc_align(&self) -> u64 {
        match self {
            Arch::Riscv32 => !3,
            _ => !1,
        }
    }

    /// 指令偏移步进（反汇编起点按指令数回退/前进时用）
    pub fn instr_step(&self) -> u64 {
        match self {
            Arch::Riscv32 => 4,
            _ => 2,
        }
    }

    /// 数据观察点/向量捕获依赖 Cortex-M 专属硬件单元（DWT/Demcr）
    pub fn has_dwt(&self) -> bool {
        matches!(self, Arch::ArmThumb)
    }
}
