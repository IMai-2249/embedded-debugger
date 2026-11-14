import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import { spawn, ChildProcessWithoutNullStreams } from 'child_process';

export function activate(context: vscode.ExtensionContext) {
  context.subscriptions.push(
    vscode.debug.registerDebugConfigurationProvider(
      'embedded-debugger',
      new ConfigProvider(),
    ),
    vscode.debug.registerDebugAdapterDescriptorFactory(
      'embedded-debugger',
      new AdapterFactory(context),
    ),
    vscode.commands.registerCommand('embedded-debugger.run', () => dreq('continue', { threadId: 1 })),
    vscode.commands.registerCommand('embedded-debugger.pause', () => dreq('pause', { threadId: 1 })),
    vscode.commands.registerCommand('embedded-debugger.step-in', () => dreq('stepIn', { threadId: 1 })),
    vscode.commands.registerCommand('embedded-debugger.step-over', () => dreq('next', { threadId: 1 })),
    vscode.commands.registerCommand('embedded-debugger.step-out', () => dreq('stepOut', { threadId: 1 })),
    vscode.commands.registerCommand('embedded-debugger.instruction-step', () => dreq('instructionStep')),
    vscode.commands.registerCommand('embedded-debugger.reset', () => dreq('reset')),
    vscode.commands.registerCommand('embedded-debugger.open-ui', () => openUi(context)),
    vscode.window.registerTreeDataProvider('embeddedDebugControls', new ControlsProvider()),
  );
}

export function deactivate() {
  /* 适配器/桥接进程由 VS Code 托管退出 */
}

function dreq(command: string, args?: unknown) {
  const s = vscode.debug.activeDebugSession;
  if (!s) {
    vscode.window.showWarningMessage('当前没有进行中的调试会话（先 F5 启动）');
    return;
  }
  void s.customRequest(command, args);
}

/** 调试控制面板：中文按钮，和桌面版工具栏同款习惯 */
class ControlsProvider implements vscode.TreeDataProvider<vscode.TreeItem> {
  getTreeItem(item: vscode.TreeItem): vscode.TreeItem {
    return item;
  }
  getChildren(): vscode.TreeItem[] {
    const items: vscode.TreeItem[] = [];
    if (!vscode.debug.activeDebugSession) {
      const hint = new vscode.TreeItem('未在调试（按 F5 启动）', vscode.TreeItemCollapsibleState.None);
      hint.description = '嵌入式调试器';
      items.push(hint);
    }
    const item = (label: string, cmd: string, desc: string) => {
      const t = new vscode.TreeItem(label, vscode.TreeItemCollapsibleState.None);
      t.description = desc;
      t.tooltip = label + '（' + desc + '）';
      t.command = { command: cmd, title: label };
      return t;
    };
    items.push(
      item('$(debug-continue) 运行 / 继续', 'embedded-debugger.run', 'F5'),
      item('$(debug-pause) 暂停', 'embedded-debugger.pause', 'F6'),
      item('$(debug-step-over) 步过（执行下一行，不进函数）', 'embedded-debugger.step-over', 'F10'),
      item('$(debug-step-into) 步入（进入函数）', 'embedded-debugger.step-in', 'F11'),
      item('$(debug-step-out) 步出（跳出当前函数）', 'embedded-debugger.step-out', 'Shift+F11'),
      item('$(circle-small) 单条指令', 'embedded-debugger.instruction-step', '汇编级单步'),
      item('$(debug-restart) 复位并停在 main', 'embedded-debugger.reset', 'F7'),
    );
    return items;
  }
}

/** 可执行文件查找顺序: launch 配置 adapterPath → 扩展内置 bin → 仓库构建输出 */
function findExe(ctx: vscode.ExtensionContext, exe: string, cfg?: { adapterPath?: string }): string {
  const wexe = process.platform === 'win32' ? exe + '.exe' : exe;
  const candidates = [
    cfg?.adapterPath,
    path.join(ctx.extensionPath, 'bin', wexe),
    path.join(ctx.extensionPath, '..', 'target', 'debug', wexe),
    path.join(ctx.extensionPath, '..', 'target', 'release', wexe),
  ].filter((p): p is string => !!p);
  const found = candidates.find((p) => fs.existsSync(p));
  if (!found) {
    throw new Error(
      '未找到 ' + exe + '。请在仓库根目录执行 cargo build -p ed-dap，或在 launch 配置中指定 adapterPath。',
    );
  }
  return found;
}

class AdapterFactory implements vscode.DebugAdapterDescriptorFactory {
  constructor(private readonly ctx: vscode.ExtensionContext) {}

  createDebugAdapterDescriptor(
    session: vscode.DebugSession,
  ): vscode.ProviderResult<vscode.DebugAdapterDescriptor> {
    const exe = findExe(this.ctx, 'ed-dap', session.configuration as { adapterPath?: string });
    return new vscode.DebugAdapterExecutable(exe);
  }
}

class ConfigProvider implements vscode.DebugConfigurationProvider {
  provideDebugConfigurations(
    _folder: vscode.WorkspaceFolder | undefined,
    _token?: vscode.CancellationToken,
  ): vscode.ProviderResult<vscode.DebugConfiguration[]> {
    return [
      {
        name: '嵌入式调试器: 烧录并调试',
        type: 'embedded-debugger',
        request: 'launch',
        chip: 'STM32F767IGTx',
        elf: '${workspaceFolder}/firmware.axf',
        flash: true,
      },
    ];
  }

  resolveDebugConfiguration(
    _folder: vscode.WorkspaceFolder | undefined,
    config: vscode.DebugConfiguration & { chip?: string; elf?: string },
    _token?: vscode.CancellationToken,
  ): vscode.ProviderResult<vscode.DebugConfiguration> {
    if (!config.type && !config.request) {
      throw new Error(
        '请先创建 launch.json（选择"嵌入式调试器"），填入芯片型号与固件路径。',
      );
    }
    if (!config.chip) {
      throw new Error('launch 配置缺少 chip（芯片型号，如 STM32F767IGTx）');
    }
    if (config.request === 'launch' && !config.flash && !config.elf) {
      vscode.window.showWarningMessage('未配置 elf：本次调试没有源码级符号（仅反汇编/内存）');
    }
    return config;
  }
}

// ---- 内嵌桌面版 UI: Webview + ed-bridge 桥接进程 ----
let uiPanel: vscode.WebviewPanel | undefined;
let bridgeProc: ChildProcessWithoutNullStreams | null = null;
let bridgeBuf = '';

function bridgePath(ctx: vscode.ExtensionContext): string {
  return findExe(ctx, 'ed-bridge');
}

function startBridge(ctx: vscode.ExtensionContext): ChildProcessWithoutNullStreams {
  if (bridgeProc) return bridgeProc;
  bridgeProc = spawn(bridgePath(ctx));
  bridgeProc.stdout.on('data', (chunk: Buffer) => {
    bridgeBuf += chunk.toString();
    let idx = bridgeBuf.indexOf('\n');
    while (idx >= 0) {
      const line = bridgeBuf.slice(0, idx);
      bridgeBuf = bridgeBuf.slice(idx + 1);
      if (line.trim()) {
        try {
          const msg = JSON.parse(line);
          if (uiPanel) void uiPanel.webview.postMessage({ __bridge: true, ...msg });
        } catch {
          /* 忽略非 JSON 行 */
        }
      }
      idx = bridgeBuf.indexOf('\n');
    }
  });
  bridgeProc.on('exit', () => {
    bridgeProc = null;
  });
  return bridgeProc;
}

function buildUiHtml(webview: vscode.Webview, ctx: vscode.ExtensionContext): string {
  const root = vscode.Uri.joinPath(ctx.extensionUri, 'webview-ui');
  let html = fs.readFileSync(path.join(ctx.extensionPath, 'webview-ui', 'index.html'), 'utf-8');
  html = html.replace(/(href|src)="([^"]+)"/g, (m0: string, attr: string, rel: string) => {
    if (/^(https?|vscode-webview|data):/.test(rel)) return m0;
    const uri = webview.asWebviewUri(vscode.Uri.joinPath(root, rel.replace(/^\.?\//, '')));
    return attr + '="' + uri.toString() + '"';
  });
  const csp =
    "default-src 'none'; img-src " +
    webview.cspSource +
    ' data: blob:; style-src ' +
    webview.cspSource +
    " 'unsafe-inline'; script-src " +
    webview.cspSource +
    '; font-src ' +
    webview.cspSource +
    ';';
  html = html.replace('<head>', '<head><meta http-equiv="Content-Security-Policy" content="' + csp + '">');
  return html;
}

const PICK_FILTERS: Record<string, Record<string, string[]>> = {
  pick_firmware: { 固件文件: ['elf', 'axf', 'hex', 'bin'] },
  pick_symbols: { 'ELF/AXF': ['elf', 'axf', 'out'] },
  pick_target_yaml: { 芯片描述: ['yaml', 'yml'] },
  pick_pack_file: { 'CMSIS 芯片包': ['pack', 'zip'] },
};

export function openUi(ctx: vscode.ExtensionContext) {
  if (uiPanel) {
    void uiPanel.reveal();
    return;
  }
  startBridge(ctx);
  uiPanel = vscode.window.createWebviewPanel(
    'embeddedDebuggerUI',
    '嵌入式调试器',
    vscode.ViewColumn.Beside,
    {
      enableScripts: true,
      retainContextWhenHidden: true,
      localResourceRoots: [vscode.Uri.joinPath(ctx.extensionUri, 'webview-ui')],
    },
  );
  uiPanel.webview.html = buildUiHtml(uiPanel.webview, ctx);
  uiPanel.onDidDispose(() => {
    uiPanel = undefined;
  });
  uiPanel.webview.onDidReceiveMessage((m: any) => {
    if (!m || m.__bridge !== true) return;
    const { id, cmd, args = {} } = m;
    if (PICK_FILTERS[cmd]) {
      void vscode.window
        .showOpenDialog({ canSelectMany: false, filters: PICK_FILTERS[cmd] })
        .then((uris) => {
          void uiPanel?.webview.postMessage({
            __bridge: true,
            id,
            ok: true,
            data: uris?.[0]?.fsPath ?? null,
          });
        });
      return;
    }
    if (cmd === 'save_text' || cmd === 'save_binary') {
      void vscode.window
        .showSaveDialog({ defaultUri: vscode.Uri.file(args.default_name ?? 'export.txt') })
        .then((uri) => {
          if (!uri) {
            void uiPanel?.webview.postMessage({ __bridge: true, id, ok: true, data: null });
            return;
          }
          try {
            if (cmd === 'save_text') {
              fs.writeFileSync(uri.fsPath, String(args.content ?? ''), 'utf-8');
            } else {
              fs.writeFileSync(uri.fsPath, Buffer.from(args.data ?? []));
            }
            void uiPanel?.webview.postMessage({ __bridge: true, id, ok: true, data: uri.fsPath });
          } catch (e) {
            void uiPanel?.webview.postMessage({ __bridge: true, id, ok: false, error: String(e) });
          }
        });
      return;
    }
    startBridge(ctx).stdin.write(JSON.stringify({ id, cmd, args }) + '\n');
  });
}
