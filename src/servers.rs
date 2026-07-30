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
    let path = servers_path();
    let Ok(text) = std::fs::read_to_string(&path) else {
        return ServersFile::default();
    };
    match toml::from_str::<ServersFile>(&text) {
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
            f
        }
        Err(e) => {
            tracing::warn!(path = ?path, error = %e, "failed to parse servers.toml");
            ServersFile::default()
        }
    }
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
