# 一键构建嵌入式调试器 VS Code 插件
# 用法:
#   .\build.ps1            编译 Rust 适配器并更新 vscode/bin（重载 VSCode 窗口生效）
#   .\build.ps1 -Vsix      额外打包 vsix（vscode/embedded-debugger-vscode-*.vsix）
#   .\build.ps1 -Install   打包后直接安装到默认 VSCode（code --install-extension）
param(
    [switch]$Vsix,
    [switch]$Install
)
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host "==> cargo build --release" -ForegroundColor Cyan
cargo build --release
if ($LASTEXITCODE -ne 0) { Write-Error "Rust 编译失败"; exit 1 }

New-Item -ItemType Directory -Force -Path vscode\bin | Out-Null
Copy-Item target\release\ed-dap.exe, target\release\ed-bridge.exe vscode\bin\ -Force
Write-Host "==> 已更新 vscode\bin\{ed-dap,ed-bridge}.exe" -ForegroundColor Green

if ($Vsix -or $Install) {
    Write-Host "==> vsce package" -ForegroundColor Cyan
    Push-Location vscode
    npx @vscode/vsce package
    if ($LASTEXITCODE -ne 0) { Pop-Location; Write-Error "打包失败"; exit 1 }
    $vsix = (Get-ChildItem *.vsix | Sort-Object LastWriteTime | Select-Object -Last 1).FullName
    Pop-Location
    Write-Host "==> 产物: $vsix" -ForegroundColor Green
    if ($Install) {
        code --install-extension $vsix --force
        Write-Host "==> 已安装，重载 VSCode 窗口生效" -ForegroundColor Green
    }
}

Write-Host ""
Write-Host "提示: 通过 vsix 安装的用户需 -Install 重装；仓库源码开发模式下重载窗口即可（bin/ 优先于 target/）。"
