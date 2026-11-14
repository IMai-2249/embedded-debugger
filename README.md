# 嵌入式调试器 for VS Code

「嵌入式调试器」独立桌面版的 VS Code 扩展形态：**不绑定具体厂商、不绑定具体工程**，接上调试探针就能在 VS Code 里调试任何 Cortex-M 芯片。

基于 [probe-rs](https://probe.rs) 构建，CMSIS-DAP 免驱动，无需安装任何调试器驱动链。

![版本](https://img.shields.io/badge/version-0.2.0-blue) ![VS Code](https://img.shields.io/badge/VS%20Code-%5E1.85-007ACC) ![协议](https://img.shields.io/badge/license-MIT-green)

## 功能

- **与调试会话联动**：调试启动自动打开完整面板；面板里的寄存器/内存/反汇编/RTOS 任务/RTT 实时反映当前调试会话状态，停机/命中断点双向联动；未调试时可作为独立工具面板连接探针使用
- **源码级调试**：断点、单步（步入/步过/步出）、指令单步、运行到光标处、复位停在 main
- **反汇编**：Thumb 反汇编，与源码 PC 同步
- **寄存器 / 内存**：通用寄存器 + FPU 浮点、任意地址内存查看
- **调用栈**：基于 DWARF CFI 的栈回溯（兼容 Keil AC6 `armcc+` 与 GCC `.debug_frame`）
- **变量**：局部变量（当前帧/任意调用栈帧）、Watch 全局/静态变量（结构体展开）
- **RTOS 感知**：FreeRTOS 任务列表、任务调用栈与任务局部变量
- **芯片包导入**：直接导入厂商 CMSIS-Pack（.pack）或 probe-rs YAML 获得芯片支持

### 芯片支持（三级扩展，不绑定芯片）

1. **内置芯片库**：probe-rs 内置 240+ 系列 / 12000+ 型号（STM32 全系、GD32、CH32、nRF52 等）
2. **导入芯片描述**：probe-rs YAML 文件
3. **导入厂商芯片包**：CMSIS-Pack（.pack），含 Flash 烧录算法

导入的芯片描述存放于 `%APPDATA%/com.embedded.debugger/custom-targets/`，与桌面版共用。

## 使用

1. 调试探针接目标板 SWD（SWDIO/SWCLK/GND，可选 NRST）
2. 在工程 `.vscode/launch.json` 中添加配置（**chip 可留空**自动探测，当前支持 STM32 系列）：

```jsonc
{
  "type": "embedded-debugger",
  "request": "launch",
  "name": "烧录并调试",
  "chip": "STM32F767IGTx",   // 留空 "" 可自动探测
  "elf": "${workspaceFolder}/firmware.axf",
  "flash": true
}
```

3. F5 启动：烧录固件并停在入口，完整调试面板自动打开；`request: "attach"` 则不烧录直接附着。
4. 侧边栏「调试控制」面板提供运行/暂停/单步/复位按钮，`embedded-debugger.open-ui` 命令可打开完整调试界面（寄存器/内存/变量树/RTOS 任务）。

支持的调试探针：**CMSIS-DAP**（DAPLink 及兼容克隆）、**ST-Link**（V2/V3）、**J-Link**、**WCH-Link**、**CH347**、FTDI、Black Magic Probe 等 probe-rs 所支持的探针。

## 项目结构

```
core/        Rust 核心库（embedded-debugger）：probe-rs 调试、ELF/DWARF 解析、
             源码级单步引擎、FreeRTOS 感知、CMSIS-Pack 导入（无 GUI 依赖）
dap/         ed-dap：DAP over stdio 调试适配器 + ed-bridge 桥接进程
vscode/      VS Code 扩展（TypeScript + webview UI）
```

## 从源码构建

Windows 一键构建：

```powershell
.\build.ps1            # 编译并更新 vscode/bin（开发模式重载窗口生效）
.\build.ps1 -Install   # 打包 vsix 并直接安装
```

依赖：Node 20+ / Rust (MSVC toolchain)。`build.ps1` 已覆盖上述全流程；Linux/macOS 手动执行：

```bash
cargo build --release
cp target/release/ed-dap target/release/ed-bridge vscode/bin/
cd vscode && npm ci && npm run compile   # 扩展 TS 编译
npx @vscode/vsce package                 # 打包 vsix（可选）
```

> `vscode/webview-ui/` 为前端构建产物，直接随扩展分发；其源码见桌面版仓库。

## 多架构路线

- **Cortex-M**：全功能已真机验证（CherryUSB CMSIS-DAP + STM32F767，32 项自检）
- **RISC-V**：反汇编引擎已就绪（capstone RV32，含压缩指令），寄存器面板按目标描述自适应；调试/断点/观察点链路待真机接入
- 架构相关行为统一在 `core/src/arch.rs` 分派，业务代码不做架构假设

## 相关项目

- 同款调试器的独立桌面版：Tauri 2 + Vue 3，功能更全（RTT 日志、HardFault 分析、波形图），后续开源

## 许可证

[MIT](LICENSE)
