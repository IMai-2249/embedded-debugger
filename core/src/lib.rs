//! 嵌入式调试器核心库
//!
//! 从桌面版（Tauri）拆出的纯 Rust 调试核心：probe-rs 连接调试、
//! ELF/DWARF 符号解析、源码级单步、CMSIS-Pack 导入。
//! 不依赖任何 GUI 框架，供 DAP 调试适配器（ed-dap）复用。

pub mod arch;
pub mod import;
pub mod commands;

pub mod debuginfo;
pub mod state;
pub mod stepper;
pub mod variables;
pub mod cfi;
pub mod rtos;
pub mod dwt;
pub mod fault;
