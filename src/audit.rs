//! Append-only JSONL audit log: the durable record of every action the agent
//! takes. Write failures warn but never fail the tool call.

use std::io::Write;
use std::path::PathBuf;

pub struct AuditLog {
    path: PathBuf,
}

impl AuditLog {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn default_path() -> PathBuf {
        PathBuf::from(shellexpand::tilde("~/.ssh-pty-mcp/audit.jsonl").into_owned())
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    pub fn log(&self, session_id: &str, tool: &str, data: serde_json::Value) {
        let line = serde_json::json!({
            "ts": chrono::Utc::now().to_rfc3339(),
            "session_id": session_id,
            "tool": tool,
            "data": data,
        });
        let result = (|| -> std::io::Result<()> {
            if let Some(parent) = self.path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)?;
            writeln!(f, "{line}")
        })();
        if let Err(e) = result {
            tracing::warn!(error = %e, path = ?self.path, "audit log write failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn appends_jsonl() {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::new(dir.path().join("sub/audit.jsonl"));
        log.log("s1", "ssh_run", serde_json::json!({"command": "ls"}));
        log.log("s1", "ssh_press", serde_json::json!({"key": "q"}));
        let text = std::fs::read_to_string(dir.path().join("sub/audit.jsonl")).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        let v: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(v["tool"], "ssh_run");
        assert_eq!(v["data"]["command"], "ls");
    }
}
