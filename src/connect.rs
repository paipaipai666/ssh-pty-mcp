//! SSH connect/auth/host-key layer. Patterns adapted from a production russh
//! 0.62.4 client (channel split, auth chain, keyboard-interactive loop).

use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use anyhow::{Context, bail};
use russh::MethodKind;
use russh::client::AuthResult;
use russh::keys::agent::AgentIdentity;
use russh::keys::agent::client::{AgentClient, AgentStream};
use russh::keys::{self, PrivateKeyWithHashAlg, ssh_key};
use ssh2_config::{ParseRule, SshConfig};

use crate::session::{self, Session, SessionManager, SessionMode, Shared, ShellKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostKeyPolicy {
    AcceptNew,
    Off,
}

#[derive(Debug, Clone)]
pub struct ConnectParams {
    pub host: String,
    /// 0 = unset (resolve via ssh config, else 22).
    pub port: u16,
    /// Empty = unset (resolve via ssh config).
    pub user: String,
    pub name: Option<String>,
    pub proxy_jump: Option<String>,
    pub mode: SessionMode,
    pub password: Option<String>,
    pub private_key: Option<String>,
    pub passphrase: Option<String>,
    pub use_agent: bool,
    pub use_ssh_config: bool,
    pub host_key_policy: HostKeyPolicy,
    pub cols: u16,
    pub rows: u16,
    pub connect_timeout: Duration,
}

pub struct ClientHandler {
    host: String,
    port: u16,
    policy: HostKeyPolicy,
}

impl russh::client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(&mut self, key: &ssh_key::PublicKey) -> Result<bool, Self::Error> {
        match self.policy {
            HostKeyPolicy::Off => Ok(true),
            HostKeyPolicy::AcceptNew => {
                match keys::known_hosts::check_known_hosts(&self.host, self.port, key) {
                    Ok(true) => Ok(true),
                    Ok(false) => {
                        // Unknown host: learn and accept (OpenSSH accept-new).
                        if let Err(e) =
                            keys::known_hosts::learn_known_hosts(&self.host, self.port, key)
                        {
                            tracing::warn!(error = %e, "failed to record host key");
                        }
                        Ok(true)
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, host = %self.host, "host key mismatch");
                        Ok(false)
                    }
                }
            }
        }
    }
}

pub struct Opened {
    pub session: Arc<Session>,
    pub auth_method: &'static str,
}

struct Resolved {
    host: String,
    port: u16,
    user: String,
    private_key: Option<String>,
    proxy_jump: Option<String>,
}

/// Load ~/.ssh/config (parse_default_file is unix-gated in ssh2-config).
pub fn load_ssh_config() -> Option<SshConfig> {
    #[cfg(unix)]
    {
        SshConfig::parse_default_file(ParseRule::STRICT).ok()
    }
    #[cfg(not(unix))]
    {
        let path = shellexpand::tilde("~/.ssh/config").into_owned();
        let file = std::fs::File::open(path).ok()?;
        let mut reader = std::io::BufReader::new(file);
        SshConfig::default()
            .parse(&mut reader, ParseRule::STRICT)
            .ok()
    }
}

fn resolve(params: &ConnectParams) -> anyhow::Result<Resolved> {
    let mut r = Resolved {
        host: params.host.clone(),
        port: params.port,
        user: params.user.clone(),
        private_key: params.private_key.clone(),
        proxy_jump: params.proxy_jump.clone(),
    };
    if params.use_ssh_config
        && let Some(cfg) = load_ssh_config()
    {
        let p = cfg.query(&params.host);
        if let Some(host_name) = p.host_name
            && !host_name.is_empty()
        {
            r.host = host_name;
        }
        if r.port == 0 {
            r.port = p.port.unwrap_or(0);
        }
        if r.user.is_empty()
            && let Some(u) = p.user
        {
            r.user = u;
        }
        if r.private_key.is_none()
            && let Some(files) = p.identity_file
            && let Some(first) = files.first()
        {
            r.private_key = Some(first.to_string_lossy().into_owned());
        }
        // ProxyJump lands in ssh2-config's ignored_fields bucket.
        if r.proxy_jump.is_none()
            && let Some(jump) = p.ignored_fields.get("proxyjump")
        {
            r.proxy_jump = jump.first().cloned();
        }
    }
    if r.port == 0 {
        r.port = 22;
    }
    if r.user.is_empty() {
        bail!("user is required (not supplied and not found in ~/.ssh/config)");
    }
    Ok(r)
}

async fn try_private_key(
    handle: &mut russh::client::Handle<ClientHandler>,
    user: &str,
    path: &str,
    passphrase: Option<&str>,
) -> anyhow::Result<bool> {
    let path = shellexpand::tilde(path).into_owned();
    let key = keys::load_secret_key(&path, passphrase)
        .with_context(|| format!("failed to load key {path}"))?;
    let hash_alg = if key.algorithm().is_rsa() {
        handle
            .best_supported_rsa_hash()
            .await
            .ok()
            .flatten()
            .flatten()
    } else {
        None
    };
    let key = PrivateKeyWithHashAlg::new(Arc::new(key), hash_alg);
    match handle.authenticate_publickey(user, key).await? {
        AuthResult::Success => Ok(true),
        AuthResult::Failure { .. } => Ok(false),
    }
}

type DynAgent = AgentClient<Box<dyn AgentStream + Send + Unpin>>;

pub async fn connect_agent() -> Option<DynAgent> {
    #[cfg(unix)]
    if let Ok(a) = AgentClient::connect_env().await {
        return Some(a.dynamic());
    }
    #[cfg(windows)]
    if let Ok(a) = AgentClient::connect_named_pipe(r"\\.\pipe\openssh-ssh-agent").await {
        return Some(a.dynamic());
    }
    None
}

async fn try_agent(
    handle: &mut russh::client::Handle<ClientHandler>,
    user: &str,
) -> anyhow::Result<bool> {
    let Some(agent) = connect_agent().await else {
        return Ok(false);
    };
    let mut agent = agent;
    let Ok(identities) = agent.request_identities().await else {
        return Ok(false);
    };
    // Cap attempts: OpenSSH servers default to MaxAuthTries 6.
    for identity in identities.into_iter().take(4) {
        let AgentIdentity::PublicKey { key, .. } = identity else {
            continue;
        };
        match handle
            .authenticate_publickey_with(user, key, None, &mut agent)
            .await
        {
            Ok(AuthResult::Success) => return Ok(true),
            _ => continue,
        }
    }
    Ok(false)
}

async fn try_keyboard_interactive(
    handle: &mut russh::client::Handle<ClientHandler>,
    user: &str,
    password: &str,
) -> anyhow::Result<bool> {
    use russh::client::KeyboardInteractiveAuthResponse as R;
    let mut response = handle
        .authenticate_keyboard_interactive_start(user, None::<String>)
        .await?;
    loop {
        match response {
            R::Success => return Ok(true),
            R::Failure { .. } => return Ok(false),
            R::InfoRequest { prompts, .. } => {
                let answers = prompts.iter().map(|_| password.to_string()).collect();
                response = handle
                    .authenticate_keyboard_interactive_respond(answers)
                    .await?;
            }
        }
    }
}

/// Full auth chain: private_key -> agent -> password -> keyboard-interactive.
/// Returns the method that succeeded.
async fn authenticate(
    handle: &mut russh::client::Handle<ClientHandler>,
    params: &ConnectParams,
    r: &Resolved,
) -> anyhow::Result<&'static str> {
    if let Some(path) = r
        .private_key
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        && try_private_key(handle, &r.user, path, params.passphrase.as_deref()).await?
    {
        return Ok("private_key");
    }
    if params.use_agent && try_agent(handle, &r.user).await? {
        return Ok("agent");
    }
    if let Some(password) = params.password.as_deref() {
        match handle.authenticate_password(&r.user, password).await? {
            AuthResult::Success => return Ok("password"),
            AuthResult::Failure {
                remaining_methods, ..
            } => {
                if remaining_methods.contains(&MethodKind::KeyboardInteractive)
                    && try_keyboard_interactive(handle, &r.user, password).await?
                {
                    return Ok("keyboard-interactive");
                }
            }
        }
    }
    bail!("authentication failed for {}@{}:{}", r.user, r.host, r.port)
}

/// Parse a proxy_jump spec: "user@host[:port]", "host[:port]", or an alias
/// resolved via servers.toml / ~/.ssh/config.
fn resolve_jump(spec: &str, base: &ConnectParams) -> Resolved {
    // servers.toml alias
    let entry = crate::servers::load().servers.remove(spec);
    if let Some(e) = entry {
        let mut r = Resolved {
            host: e.host.clone().unwrap_or_else(|| spec.to_string()),
            port: e.port.unwrap_or(22),
            user: e.user.clone().unwrap_or_else(|| base.user.clone()),
            private_key: e.private_key.clone(),
            proxy_jump: None,
        };
        if let Some(cfg) = load_ssh_config() {
            let p = cfg.query(&r.host);
            if let Some(hn) = p.host_name
                && !hn.is_empty()
            {
                r.host = hn;
            }
        }
        return r;
    }
    // ssh config alias
    if let Some(cfg) = load_ssh_config() {
        let p = cfg.query(spec);
        if p.host_name.as_deref().is_some_and(|h| !h.is_empty()) {
            return Resolved {
                host: p.host_name.unwrap(),
                port: p.port.unwrap_or(22),
                user: p.user.unwrap_or_else(|| base.user.clone()),
                private_key: p
                    .identity_file
                    .and_then(|f| f.first().map(|p| p.to_string_lossy().into_owned())),
                proxy_jump: None,
            };
        }
    }
    // user@host[:port] / host[:port]
    let (user, rest) = match spec.split_once('@') {
        Some((u, h)) => (u.to_string(), h),
        None => (base.user.clone(), spec),
    };
    let (host, port) = match rest.rsplit_once(':') {
        Some((h, p)) if p.parse::<u16>().is_ok() => (h.to_string(), p.parse().unwrap()),
        _ => (rest.to_string(), 22),
    };
    Resolved {
        host,
        port,
        user,
        private_key: base.private_key.clone(),
        proxy_jump: None,
    }
}

/// Connect, authenticate, open a PTY shell, spawn the pump, probe the shell.
pub async fn open(params: ConnectParams, manager: &SessionManager) -> anyhow::Result<Opened> {
    let r = resolve(&params)?;
    let target = format!("{}@{}:{}", r.user, r.host, r.port);

    let config = Arc::new(russh::client::Config {
        inactivity_timeout: None,
        keepalive_interval: Some(Duration::from_secs(15)),
        keepalive_max: 3,
        ..Default::default()
    });
    let handler = ClientHandler {
        host: r.host.clone(),
        port: r.port,
        policy: params.host_key_policy,
    };

    // ProxyJump: connect the bastion, then tunnel the target handshake through
    // a direct-tcpip channel on it.
    let (mut handle, bastion) = if let Some(jump) = r.proxy_jump.as_deref() {
        let jr = resolve_jump(jump, &params);
        let jtarget = format!("{}@{}:{}", jr.user, jr.host, jr.port);
        let jhandler = ClientHandler {
            host: jr.host.clone(),
            port: jr.port,
            policy: params.host_key_policy,
        };
        let mut bh = tokio::time::timeout(
            params.connect_timeout,
            russh::client::connect(config.clone(), (jr.host.as_str(), jr.port), jhandler),
        )
        .await
        .with_context(|| format!("connect to bastion {jtarget} timed out"))??;
        let bparams = ConnectParams {
            password: params.password.clone(),
            private_key: jr.private_key.clone().or(params.private_key.clone()),
            passphrase: params.passphrase.clone(),
            use_agent: params.use_agent,
            ..params.clone()
        };
        authenticate(&mut bh, &bparams, &jr)
            .await
            .with_context(|| format!("bastion {jtarget} auth failed"))?;
        let channel = bh
            .channel_open_direct_tcpip(r.host.clone(), r.port as u32, "127.0.0.1", 0)
            .await
            .with_context(|| format!("bastion cannot reach {target}"))?;
        let h = tokio::time::timeout(
            params.connect_timeout,
            russh::client::connect_stream(config, channel.into_stream(), handler),
        )
        .await
        .with_context(|| format!("ssh handshake to {target} via {jtarget} timed out"))??;
        (h, Some(Box::new(bh)))
    } else {
        let h = tokio::time::timeout(
            params.connect_timeout,
            russh::client::connect(config, (r.host.as_str(), r.port), handler),
        )
        .await
        .with_context(|| format!("connect to {target} timed out"))??;
        (h, None)
    };

    let auth_method = authenticate(&mut handle, &params, &r).await?;

    let channel = handle
        .channel_open_session()
        .await
        .context("open session channel")?;
    channel
        .request_pty(
            false,
            "xterm-256color",
            params.cols as u32,
            params.rows as u32,
            0,
            0,
            &[],
        )
        .await
        .context("request pty")?;
    channel
        .request_shell(false)
        .await
        .context("request shell")?;
    let (read_half, write_half) = channel.split();

    let shared = Arc::new(Shared::new(params.rows, params.cols));
    let alive = Arc::new(AtomicBool::new(true));
    let pump = session::spawn_pump(read_half, shared.clone(), alive.clone());

    let mut session = Session {
        id: manager.next_id(),
        target,
        name: params.name.clone(),
        mode: params.mode.clone(),
        shell_kind: ShellKind::Unknown,
        shared: shared.clone(),
        writer: tokio::sync::Mutex::new(write_half),
        handle,
        bastion,
        sftp: tokio::sync::Mutex::new(None),
        io_lock: tokio::sync::Mutex::new(()),
        reads: parking_lot::Mutex::new(Default::default()),
        write_locks: parking_lot::Mutex::new(Default::default()),
        alive,
        bracketed_paste: false,
        pump,
    };

    // Shell probes. Order matters:
    //   1. POSIX printf probe (\n; %s indirection defeats echo matching)
    //   2. pwsh-exclusive probe with \r — PSReadLine only submits on CR and
    //      can take ~20s to initialize on musl; POSIX shells syntax-error on
    //      `('a' + 'b')`, cmd echoes quotes intact (needle can't match)
    //   3. cmd `ver`
    let start = shared.inner.lock().stream.end_offset();
    {
        let w = session.writer.lock().await;
        let _ = w.data_bytes(&b"printf '__SPM_PROBE_%s__\n' ok\n"[..]).await;
    }
    let kind = if session::wait_stream_contains(
        &shared,
        start,
        b"__SPM_PROBE_ok__",
        Duration::from_secs(3),
    )
    .await
    {
        ShellKind::Posix
    } else {
        let p2 = shared.inner.lock().stream.end_offset();
        {
            let w = session.writer.lock().await;
            let _ = w.data_bytes(&b"echo ('__SPM_PROBE2_' + 'ok')\r"[..]).await;
        }
        if session::wait_stream_contains(&shared, p2, b"__SPM_PROBE2_ok__", Duration::from_secs(20))
            .await
        {
            ShellKind::PowerShell
        } else {
            let p3 = shared.inner.lock().stream.end_offset();
            {
                let w = session.writer.lock().await;
                let _ = w.data_bytes(&b"ver\r"[..]).await;
            }
            if session::wait_stream_contains(&shared, p3, b"Windows", Duration::from_secs(3)).await
            {
                ShellKind::Cmd
            } else {
                ShellKind::Unknown
            }
        }
    };
    session.shell_kind = kind;
    if kind == ShellKind::Posix {
        // Echo stays ON between commands: readline needs the tty ECHO flag to
        // display input and history recall (persistent stty -echo breaks
        // up-arrow and interactive editing). ssh_run toggles echo off around
        // each command instead (PRE handshake in tools.rs).
        // bash/zsh readline advertise bracketed paste via \x1b[?2004h in the
        // prompt redraw — enables paste-wrapped command delivery in ssh_run.
        let (bytes, _, _) = shared.inner.lock().stream.read(start);
        session.bracketed_paste = bytes.windows(7).any(|w| w == b"[?2004h");
        // Keep our internal scaffolding (stty/marker lines, all leading-space
        // prefixed) out of shell history so up-arrow recalls only real
        // commands. Leading space on this very line is pointless (not yet
        // active) but harmless.
        let w = session.writer.lock().await;
        let _ = w
            .data_bytes(
                &b" export HISTCONTROL=\"${HISTCONTROL:+$HISTCONTROL:}ignorespace\"; setopt HIST_IGNORE_SPACE 2>/dev/null\n"[..],
            )
            .await;
    }

    Ok(Opened {
        session: Arc::new(session),
        auth_method,
    })
}
