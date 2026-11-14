use crate::debuginfo::DebugInfo;
use probe_rs::Session;

#[derive(Clone, serde::Serialize)]
pub struct BpInfo {
    pub addr: u64,
    pub file: String,
    pub line: u32,
}

/// 全局调试会话状态（Tauri managed state, Arc<Mutex<_>>）
#[derive(Default)]
pub struct AppState {
    pub session: Option<Session>,
    /// 连接时使用的芯片名（attach 成功的那个）
    pub chip: String,
    /// 探针描述（状态栏显示用）
    pub probe_desc: String,
    /// 已加载的 ELF/DWARF 调试信息
    pub debug: Option<DebugInfo>,
    /// 当前已设置的硬件断点
    pub breakpoints: Vec<BpInfo>,
    /// 当前已设置的数据观察点
    pub watchpoints: Vec<WpInfo>,
    /// RTT 会话（启动后保持）
    pub rtt: Option<probe_rs::rtt::Rtt>,
    /// 当前任务名缓存（减少轮询时的 USB 读取）
    pub last_task: Option<String>,
    pub last_task_at: Option<std::time::Instant>,
}

#[derive(Clone, serde::Serialize)]
pub struct WpInfo {
    pub name: String,
    pub addr: u64,
    /// "write" | "read" | "both"
    pub kind: String,
    pub unit: usize,
}
