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
/// and UTF-16 (PowerShell 5.1 Out-File default is UTF-16LE). No-BOM UTF-16
/// (pwsh 7 `>` redirection with -Encoding unicode) is sniffed by its NUL
/// pattern after plain UTF-8 + TOML parsing fails.
fn parse_bytes(bytes: &[u8], path: &std::path::Path) -> Result<ServersFile, String> {
    let text: String = if let Some(rest) = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        String::from_utf8(rest.to_vec())
            .map_err(|e| format!("{} is not valid UTF-8: {e}", path.display()))?
    } else if bytes.starts_with(&[0xFF, 0xFE]) {
        decode_utf16(&bytes[2..], true)
    } else if bytes.starts_with(&[0xFE, 0xFF]) {
        decode_utf16(&bytes[2..], false)
    } else {
        // No BOM: strict UTF-8 first.
        match String::from_utf8(bytes.to_vec()) {
            Ok(s) => match toml::from_str::<ServersFile>(&s) {
                Ok(f) => return Ok(f),
                // UTF-16LE ASCII text is also valid UTF-8 (chars + NULs) but
                // fails TOML with "invalid key" — sniff and re-decode.
                Err(_) => match sniff_utf16(bytes) {
                    Some((units, le)) => decode_utf16(units, le),
                    None => s,
                },
            },
            Err(_) => match sniff_utf16(bytes) {
                Some((units, le)) => decode_utf16(units, le),
                None => {
                    return Err(format!(
                        "{} is not valid UTF-8 or UTF-16: {}",
                        path.display(),
                        String::from_utf8_lossy(&bytes[..bytes.len().min(64)])
                    ));
                }
            },
        }
    };
    toml::from_str::<ServersFile>(&text)
        .map_err(|e| format!("failed to parse {}: {e}", path.display()))
}

/// No-BOM UTF-16 sniff: ASCII text in UTF-16 has every other byte zero.
fn sniff_utf16(bytes: &[u8]) -> Option<(&[u8], bool)> {
    let sample = &bytes[..bytes.len().min(4096)];
    let even_nuls = sample.iter().step_by(2).filter(|&&b| b == 0).count();
    let odd_nuls = sample
        .iter()
        .skip(1)
        .step_by(2)
        .filter(|&&b| b == 0)
        .count();
    let pairs = sample.len() / 2;
    if odd_nuls > 32 && odd_nuls > even_nuls * 4 && odd_nuls * 2 > pairs {
        Some((bytes, true)) // little-endian: zeros at odd offsets
    } else if even_nuls > 32 && even_nuls > odd_nuls * 4 && even_nuls * 2 > pairs {
        Some((bytes, false)) // big-endian: zeros at even offsets
    } else {
        None
    }
}

fn decode_utf16(units: &[u8], le: bool) -> String {
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

/// Validate a server/session name: non-empty, no leading/trailing space, no
/// TOML-breaking characters.
pub fn validate_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.trim() != name {
        return Err("name must be non-empty and have no leading/trailing whitespace".into());
    }
    if name
        .chars()
        .any(|c| c.is_whitespace() || matches!(c, '[' | ']' | '"' | '=' | '#'))
    {
        return Err("name must not contain whitespace or the characters [ ] \" = #".into());
    }
    Ok(())
}

/// Fields for ssh_add_server; None fields are omitted from the entry.
pub struct AddServer<'a> {
    pub host: &'a str,
    pub port: Option<u16>,
    pub user: Option<&'a str>,
    pub password: Option<&'a str>,
    pub private_key: Option<&'a str>,
    pub passphrase: Option<&'a str>,
    pub proxy_jump: Option<&'a str>,
    pub mode: Option<&'a str>,
    pub allow: Vec<String>,
}

/// Append (or replace, with `overwrite`) a [servers.<name>] block in
/// servers.toml, preserving all other content. The file is normalized to
/// UTF-8 on write. Returns (overwritten, path).
pub fn add_server(
    name: &str,
    s: &AddServer<'_>,
    overwrite: bool,
) -> Result<(bool, PathBuf), String> {
    validate_name(name)?;
    let path = servers_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
    }
    let existing = match std::fs::read(&path) {
        Ok(b) => parse_text_bytes(&b, &path)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
    };
    let header = format!("[servers.{name}]");
    let block = entry_block(name, s);
    let (text, overwritten) = match existing.lines().position(|l| l.trim() == header) {
        Some(pos) => {
            if !overwrite {
                return Err(format!(
                    "server '{name}' already exists in {}; pass overwrite=true to replace it",
                    path.display()
                ));
            }
            let lines: Vec<&str> = existing.lines().collect();
            let mut end = lines.len();
            for (i, l) in lines.iter().enumerate().skip(pos + 1) {
                if l.trim_start().starts_with('[') {
                    end = i;
                    break;
                }
            }
            let mut out = lines[..pos].join("\n");
            if !out.is_empty() {
                out.push('\n');
            }
            out.push_str(&block);
            if end < lines.len() {
                out.push_str(&lines[end..].join("\n"));
                out.push('\n');
            }
            (out, true)
        }
        None => {
            let mut out = existing;
            if !out.is_empty() && !out.ends_with('\n') {
                out.push('\n');
            }
            out.push_str(&block);
            (out, false)
        }
    };
    // Atomic write; restrict perms when the entry carries a password.
    let tmp = path.with_extension("toml.tmp");
    std::fs::write(&tmp, text).map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if s.password.is_some() {
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
    }
    std::fs::rename(&tmp, &path).map_err(|e| format!("cannot replace {}: {e}", path.display()))?;
    Ok((overwritten, path))
}

fn entry_block(name: &str, s: &AddServer<'_>) -> String {
    let mut m = toml::map::Map::new();
    m.insert("host".into(), toml::Value::String(s.host.to_string()));
    if let Some(v) = s.port {
        m.insert("port".into(), toml::Value::Integer(v.into()));
    }
    if let Some(v) = s.user {
        m.insert("user".into(), toml::Value::String(v.to_string()));
    }
    if let Some(v) = s.password {
        m.insert("password".into(), toml::Value::String(v.to_string()));
    }
    if let Some(v) = s.private_key {
        m.insert("private_key".into(), toml::Value::String(v.to_string()));
    }
    if let Some(v) = s.passphrase {
        m.insert("passphrase".into(), toml::Value::String(v.to_string()));
    }
    if let Some(v) = s.proxy_jump {
        m.insert("proxy_jump".into(), toml::Value::String(v.to_string()));
    }
    if let Some(v) = s.mode {
        m.insert("mode".into(), toml::Value::String(v.to_string()));
    }
    if !s.allow.is_empty() {
        m.insert(
            "allow".into(),
            toml::Value::Array(
                s.allow
                    .iter()
                    .map(|a| toml::Value::String(a.clone()))
                    .collect(),
            ),
        );
    }
    format!(
        "[servers.{name}]\n{}",
        toml::to_string(&toml::Value::Table(m)).unwrap_or_default()
    )
}

/// Decode existing file bytes (BOM/UTF-16/no-BOM sniff) to editable text.
fn parse_text_bytes(bytes: &[u8], path: &std::path::Path) -> Result<String, String> {
    let text = if let Some(rest) = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        String::from_utf8(rest.to_vec())
            .map_err(|e| format!("{} is not valid UTF-8: {e}", path.display()))?
    } else if bytes.starts_with(&[0xFF, 0xFE]) {
        decode_utf16(&bytes[2..], true)
    } else if bytes.starts_with(&[0xFE, 0xFF]) {
        decode_utf16(&bytes[2..], false)
    } else {
        match String::from_utf8(bytes.to_vec()) {
            Ok(s) => s,
            Err(_) => sniff_utf16(bytes)
                .map(|(u, le)| decode_utf16(u, le))
                .unwrap_or_else(|| String::from_utf8_lossy(bytes).to_string()),
        }
    };
    Ok(text)
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
    fn parses_utf16le_no_bom() {
        let mut b = Vec::new();
        for u in TOML.encode_utf16() {
            b.extend_from_slice(&u.to_le_bytes());
        }
        let f = parse_bytes(&b, Path::new("x")).unwrap();
        assert_eq!(f.servers["box"].host.as_deref(), Some("1.2.3.4"));
    }

    #[test]
    fn parses_utf16be_no_bom() {
        let mut b = Vec::new();
        for u in TOML.encode_utf16() {
            b.extend_from_slice(&u.to_be_bytes());
        }
        let f = parse_bytes(&b, Path::new("x")).unwrap();
        assert_eq!(f.servers["box"].user.as_deref(), Some("deploy"));
    }

    #[test]
    fn garbage_reports_error() {
        let err = parse_bytes(b"[servers", Path::new("x")).unwrap_err();
        assert!(err.contains("failed to parse"));
    }

    #[test]
    fn add_server_append_and_overwrite() {
        // Isolate from the real registry via a temp dir.
        let dir = std::env::temp_dir().join(format!("spm-srv-test-{}", std::process::id()));
        std::fs::create_dir_all(dir.join(".ssh-pty-mcp")).unwrap();
        let cfg = dir.join(".ssh-pty-mcp/servers.toml");
        std::fs::write(&cfg, "# my hosts\n").unwrap();
        // SAFETY: no other test reads this env var; single-threaded concern.
        unsafe { std::env::set_var("SSH_PTY_MCP_SERVERS", &cfg) };
        let s = AddServer {
            host: "10.0.0.1",
            port: Some(2222),
            user: Some("root"),
            password: None,
            private_key: Some("~/.ssh/id_ed25519"),
            passphrase: None,
            proxy_jump: None,
            mode: Some("readonly"),
            allow: vec![],
        };
        let (ov, _) = add_server("box", &s, false).unwrap();
        assert!(!ov);
        // Appended, comment preserved.
        let text = std::fs::read_to_string(&cfg).unwrap();
        assert!(text.starts_with("# my hosts\n"));
        assert!(text.contains("[servers.box]"));
        assert!(text.contains("port = 2222"));
        // Duplicate without overwrite errors.
        let err = add_server("box", &s, false).unwrap_err();
        assert!(err.contains("already exists"), "{err}");
        // Overwrite replaces the block in place.
        let s2 = AddServer {
            host: "10.0.0.2",
            port: None,
            user: None,
            password: None,
            private_key: None,
            passphrase: None,
            proxy_jump: None,
            mode: None,
            allow: vec![],
        };
        let (ov, _) = add_server("box", &s2, true).unwrap();
        assert!(ov);
        let text = std::fs::read_to_string(&cfg).unwrap();
        assert!(text.starts_with("# my hosts\n"));
        assert!(text.contains("host = \"10.0.0.2\""));
        assert!(!text.contains("10.0.0.1"));
        // Reload parses the merged file.
        let f = parse_bytes(std::fs::read(&cfg).unwrap().as_slice(), &cfg).unwrap();
        assert_eq!(f.servers["box"].host.as_deref(), Some("10.0.0.2"));
        assert_eq!(f.servers["box"].mode.as_deref(), None);
        unsafe { std::env::remove_var("SSH_PTY_MCP_SERVERS") };
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_name_rejects_garbage() {
        assert!(validate_name("good-name_2").is_ok());
        assert!(validate_name("a b").is_err());
        assert!(validate_name("").is_err());
        assert!(validate_name(" a").is_err());
        assert!(validate_name("a[1]").is_err());
        assert!(validate_name("a\"b").is_err());
    }
}
