//! Named server registry: `~/.ssh-pty-mcp/servers.toml` (override with the
//! `SSH_PTY_MCP_SERVERS` env var). Merges below explicit ssh_open params and
//! above ~/.ssh/config.

use std::collections::HashMap;
use std::path::PathBuf;

use rmcp::schemars;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ServerEntry {
    pub host: Option<String>,
    pub port: Option<u16>,
    pub user: Option<String>,
    pub password: Option<String>,
    pub private_key: Option<String>,
    pub passphrase: Option<String>,
    pub proxy_jump: Option<String>,
    pub use_agent: Option<bool>,
    pub host_key_policy: Option<String>,
    pub mode: Option<String>,
    /// Allowlist regexes for mode="restricted".
    pub allow: Option<Vec<String>>,
}

#[derive(Debug, Default, Deserialize)]
pub struct ServersFile {
    #[serde(default)]
    pub servers: HashMap<String, ServerEntry>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct ServerSummary {
    pub name: String,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub user: Option<String>,
    pub proxy_jump: Option<String>,
    pub mode: Option<String>,
    pub source: String, // "servers.toml" | "~/.ssh/config"
}

pub fn servers_path() -> PathBuf {
    if let Ok(p) = std::env::var("SSH_PTY_MCP_SERVERS") {
        return PathBuf::from(p);
    }
    PathBuf::from(shellexpand::tilde("~/.ssh-pty-mcp/servers.toml").into_owned())
}

pub fn load() -> ServersFile {
    load_verbose().0
}

/// Load with diagnostics: the second element describes why the registry is
/// empty (missing file, unreadable, parse error) so callers can surface it
/// instead of a bare "not found".
pub fn load_verbose() -> (ServersFile, Option<String>) {
    let path = servers_path();
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return (ServersFile::default(), None);
        }
        Err(e) => {
            return (
                ServersFile::default(),
                Some(format!("cannot read {}: {e}", path.display())),
            );
        }
    };
    match parse_bytes(&bytes, &path) {
        Ok(f) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if f.servers.values().any(|e| e.password.is_some())
                    && let Ok(meta) = std::fs::metadata(&path)
                    && meta.permissions().mode() & 0o077 != 0
                {
                    tracing::warn!(
                        path = ?path,
                        "servers.toml contains passwords and is readable by group/others; chmod 600 recommended"
                    );
                }
            }
            (f, None)
        }
        Err(msg) => {
            tracing::warn!("{msg}");
            (ServersFile::default(), Some(msg))
        }
    }
}

/// Parse raw servers.toml bytes. Windows editors love BOMs: accept UTF-8 BOM
/// and UTF-16 (PowerShell 5.1 Out-File default is UTF-16LE).
fn parse_bytes(bytes: &[u8], path: &std::path::Path) -> Result<ServersFile, String> {
    let text = if bytes.starts_with(&[0xFF, 0xFE]) || bytes.starts_with(&[0xFE, 0xFF]) {
        let (units, le) = if bytes[0] == 0xFF {
            (&bytes[2..], true)
        } else {
            (&bytes[2..], false)
        };
        let u16s: Vec<u16> = units
            .chunks_exact(2)
            .map(|c| {
                if le {
                    u16::from_le_bytes([c[0], c[1]])
                } else {
                    u16::from_be_bytes([c[0], c[1]])
                }
            })
            .collect();
        String::from_utf16_lossy(&u16s)
    } else {
        let b = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
        String::from_utf8(b.to_vec())
            .map_err(|e| format!("{} is not valid UTF-8/UTF-16: {e}", path.display()))?
    };
    toml::from_str::<ServersFile>(&text)
        .map_err(|e| format!("failed to parse {}: {e}", path.display()))
}


/// Registry + ~/.ssh/config aliases, passwords redacted.
pub fn list_summaries() -> Vec<ServerSummary> {
    let mut out: Vec<ServerSummary> = load()
        .servers
        .into_iter()
        .map(|(name, e)| ServerSummary {
            name,
            host: e.host,
            port: e.port,
            user: e.user,
            proxy_jump: e.proxy_jump,
            mode: e.mode,
            source: "servers.toml".into(),
        })
        .collect();
    if let Some(cfg) = crate::connect::load_ssh_config() {
        for host in cfg.get_hosts() {
            let Some(pattern) = host.pattern.first().map(|p| p.pattern.clone()) else {
                continue;
            };
            if pattern == "*" || pattern.contains('*') || pattern.contains('?') {
                continue;
            }
            let params = cfg.query(&pattern);
            out.push(ServerSummary {
                name: pattern,
                host: params.host_name,
                port: params.port,
                user: params.user,
                proxy_jump: None,
                mode: None,
                source: "~/.ssh/config".into(),
            });
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    const TOML: &str = "[servers.box]\nhost = \"1.2.3.4\"\nuser = \"deploy\"\n";

    #[test]
    fn parses_plain_utf8() {
        let f = parse_bytes(TOML.as_bytes(), Path::new("x")).unwrap();
        assert_eq!(f.servers["box"].host.as_deref(), Some("1.2.3.4"));
    }

    #[test]
    fn parses_utf8_bom() {
        let mut b = vec![0xEF, 0xBB, 0xBF];
        b.extend_from_slice(TOML.as_bytes());
        assert!(parse_bytes(&b, Path::new("x")).is_ok());
    }

    #[test]
    fn parses_utf16le_bom() {
        let mut b = vec![0xFF, 0xFE];
        for u in TOML.encode_utf16() {
            b.extend_from_slice(&u.to_le_bytes());
        }
        let f = parse_bytes(&b, Path::new("x")).unwrap();
        assert_eq!(f.servers["box"].user.as_deref(), Some("deploy"));
    }

    #[test]
    fn garbage_reports_error() {
        let err = parse_bytes(b"[servers", Path::new("x")).unwrap_err();
        assert!(err.contains("failed to parse"));
    }
}

