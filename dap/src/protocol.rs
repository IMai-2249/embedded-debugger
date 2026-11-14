//! DAP 帧协议（Content-Length 头 + JSON 体，与 LSP 同构）

use serde_json::Value;
use std::io::{BufRead, Read, Write};
use std::sync::Mutex;

/// 从 stdio 读取一条 DAP 消息；流关闭返回 None
pub fn read_message(r: &mut impl BufRead) -> Option<Value> {
    let mut content_len = 0usize;
    loop {
        let mut line = String::new();
        let n = r.read_line(&mut line).ok()?;
        if n == 0 {
            return None;
        }
        let t = line.trim();
        if t.is_empty() {
            break;
        }
        if let Some(v) = t.strip_prefix("Content-Length:") {
            content_len = v.trim().parse().ok()?;
        }
    }
    if content_len == 0 {
        return None;
    }
    let mut buf = vec![0u8; content_len];
    r.read_exact(&mut buf).ok()?;
    serde_json::from_slice(&buf).ok()
}

/// 线程安全的 stdout 写出端
pub struct Sender {
    out: Mutex<Box<dyn Write + Send>>,
}

impl Sender {
    pub fn new(out: Box<dyn Write + Send>) -> Self {
        Self { out: Mutex::new(out) }
    }

    pub fn send(&self, v: &Value) {
        let body = v.to_string();
        let mut w = self.out.lock().unwrap();
        let _ = write!(w, "Content-Length: {}\r\n\r\n{}", body.len(), body);
        let _ = w.flush();
    }
}
