//! MCP tool layer: 13 tools over the session core. Tool descriptions carry
//! routing guidance — agent fluency depends on them.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use rmcp::handler::server::wrapper::Parameters;
use rmcp::{ErrorData as McpError, Json, schemars, tool, tool_router};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use crate::audit::AuditLog;
use crate::connect::{self, ConnectParams, HostKeyPolicy};
use crate::keys;
use crate::session::{
    self, Fingerprint, Session, SessionManager, ShellKind, WaitMode, find_marker, screen_text,
};

fn internal<E: std::fmt::Display>(e: E) -> McpError {
    McpError::internal_error(e.to_string(), None)
}

fn invalid<E: std::fmt::Display>(e: E) -> McpError {
    McpError::invalid_params(e.to_string(), None)
}

fn default_true() -> bool {
    true
}
fn default_cols() -> u16 {
    120
}
fn default_rows() -> u16 {
    32
}
fn default_connect_timeout() -> u64 {
    15000
}
fn default_run_timeout() -> u64 {
    30000
}
fn default_max_output() -> u64 {
    65536
}
fn default_expect_timeout() -> u64 {
    10000
}
fn default_settle() -> u64 {
    250
}
fn default_read_limit() -> u64 {
    262144
}
fn default_policy() -> String {
    "accept-new".into()
}
fn default_overwrite() -> String {
    "overwrite".into()
}
fn default_stream() -> String {
    "stream".into()
}
fn default_wait_none() -> String {
    "none".into()
}

// ── Params & outputs ────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SshOpenParams {
    /// Hostname, IP, or a Host alias from ~/.ssh/config.
    pub host: String,
    /// SSH port. Omit to use ~/.ssh/config or 22.
    #[serde(default)]
    pub port: Option<u16>,
    /// Login user. Omit to use ~/.ssh/config.
    #[serde(default)]
    pub user: Option<String>,
    /// Password auth (tried after key/agent). Never logged.
    #[serde(default)]
    pub password: Option<String>,
    /// Path to a private key file (~ allowed).
    #[serde(default)]
    pub private_key: Option<String>,
    /// Passphrase for the private key. Never logged.
    #[serde(default)]
    pub passphrase: Option<String>,
    /// Try the local SSH agent (SSH_AUTH_SOCK; Windows named pipe). Default true.
    #[serde(default = "default_true")]
    pub use_agent: bool,
    /// Resolve host/port/user/identity via ~/.ssh/config. Default true.
    #[serde(default = "default_true")]
    pub use_ssh_config: bool,
    /// "accept-new" (default, uses ~/.ssh/known_hosts) or "off".
    #[serde(default = "default_policy")]
    pub host_key_policy: String,
    #[serde(default = "default_cols")]
    pub cols: u16,
    #[serde(default = "default_rows")]
    pub rows: u16,
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_ms: u64,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct SshOpenOut {
    pub session_id: String,
    pub shell_kind: ShellKind,
    pub target: String,
    pub auth_method: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SessionParams {
    pub session_id: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct ClosedOut {
    pub closed: bool,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct ListEntry {
    pub session_id: String,
    pub target: String,
    pub shell_kind: ShellKind,
    pub alive: bool,
    pub idle_secs: u64,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct ListOut {
    pub sessions: Vec<ListEntry>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SshRunParams {
    pub session_id: String,
    /// Shell command. Runs in the persistent shell: cwd/env survive.
    pub command: String,
    #[serde(default = "default_run_timeout")]
    pub timeout_ms: u64,
    /// Keep at most this many bytes of output (tail). Default 65536.
    #[serde(default = "default_max_output")]
    pub max_output_bytes: u64,
    /// Strip ANSI escape sequences (colors, readline artifacts) from output.
    /// Default true; set false to preserve colors/control sequences.
    #[serde(default = "default_true")]
    pub strip_ansi: bool,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct SshRunOut {
    pub output: String,
    pub exit_code: Option<i64>,
    pub timed_out: bool,
    pub truncated: bool,
    /// Absolute stream offset at capture; pass to ssh_expect(from_offset).
    pub stream_offset: u64,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SshTypeParams {
    pub session_id: String,
    /// Text written verbatim to the PTY (no implicit newline).
    pub text: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct SeqOut {
    pub seq: u64,
    /// Absolute stream offset at this moment; pass to ssh_expect(from_offset).
    pub stream_offset: u64,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SshPressParams {
    pub session_id: String,
    /// Key spec, e.g. "q", "enter", "ctrl+c", "ctrl+x", "shift+tab", "up", "f5".
    pub key: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SshSignalParams {
    pub session_id: String,
    /// sigint | sigquit | sigterm | sigkill | sighup | sigtstp
    pub signal: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct SentOut {
    pub sent: bool,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SshExpectParams {
    pub session_id: String,
    /// Regex to wait for.
    pub pattern: String,
    /// "stream" (default): match raw output arriving after from_offset.
    /// "screen": match the rendered terminal screen.
    #[serde(default = "default_stream")]
    pub mode: String,
    /// Stream offset to start matching from — use the stream_offset returned
    /// by ssh_type/ssh_press/ssh_run to avoid missing output that arrived
    /// between the triggering action and this call. Default: current end.
    #[serde(default)]
    pub from_offset: Option<u64>,
    #[serde(default = "default_expect_timeout")]
    pub timeout_ms: u64,
    #[serde(default = "default_max_output")]
    pub max_bytes: u64,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct SshExpectOut {
    pub matched: bool,
    pub text: String,
    pub captures: Vec<String>,
    pub timed_out: bool,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SshScreenParams {
    pub session_id: String,
    /// Logical-clock anchor returned by ssh_type/ssh_press/ssh_run.
    #[serde(default)]
    pub since_seq: Option<u64>,
    /// "none": immediate. "change": wait for any new output. "quiet": wait for
    /// change then no output for settle_ms. Default "none".
    #[serde(default = "default_wait_none")]
    pub wait: String,
    #[serde(default = "default_settle")]
    pub settle_ms: u64,
    #[serde(default = "default_expect_timeout")]
    pub timeout_ms: u64,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct SshScreenOut {
    pub screen: String,
    pub seq: u64,
    pub idle_ms: u128,
    pub timed_out: bool,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FileReadParams {
    pub session_id: String,
    pub path: String,
    #[serde(default)]
    pub offset: u64,
    /// Max bytes to read. Default 262144.
    #[serde(default = "default_read_limit")]
    pub limit: u64,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct FileReadOut {
    pub content: String,
    pub size: u64,
    pub eof: bool,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FileWriteParams {
    pub session_id: String,
    pub path: String,
    pub content: String,
    /// "overwrite" (default; requires a prior full file_read) or "append".
    #[serde(default = "default_overwrite")]
    pub mode: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct FileWriteOut {
    pub bytes_written: u64,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TransferParams {
    pub session_id: String,
    pub local_path: String,
    pub remote_path: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct TransferOut {
    pub bytes: u64,
}

// ── Server ──────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct SshMcp {
    sessions: Arc<SessionManager>,
    audit: Arc<AuditLog>,
}

impl SshMcp {
    pub fn new(sessions: SessionManager, audit: Arc<AuditLog>) -> Self {
        Self {
            sessions: Arc::new(sessions),
            audit,
        }
    }

    async fn live_session(&self, id: &str) -> Result<Arc<Session>, McpError> {
        let session = self
            .sessions
            .get(id)
            .await
            .ok_or_else(|| invalid(format!("unknown session '{id}'; call ssh_open first")))?;
        session.check_alive().map_err(invalid)?;
        Ok(session)
    }

    /// Lazily establish (and cache) the SFTP subsystem for a session.
    async fn sftp(
        session: &Session,
    ) -> Result<tokio::sync::MutexGuard<'_, Option<russh_sftp::client::SftpSession>>, McpError>
    {
        let mut guard = session.sftp.lock().await;
        if guard.is_none() {
            let ch = session
                .handle
                .channel_open_session()
                .await
                .map_err(internal)?;
            ch.request_subsystem(false, "sftp")
                .await
                .map_err(internal)?;
            let s = russh_sftp::client::SftpSession::new(ch.into_stream())
                .await
                .map_err(internal)?;
            *guard = Some(s);
        }
        Ok(guard)
    }
}

fn tail_chars(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut start = s.len() - max;
    while !s.is_char_boundary(start) {
        start += 1;
    }
    s[start..].to_string()
}

static ANSI_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    // CSI (incl. private ?2004h/l), OSC terminated by BEL or ST.
    regex::Regex::new("\u{1b}\\[[0-9;?]*[ -/]*[@-~]|\u{1b}\\][^\u{7}\u{1b}]*(?:\u{7}|\u{1b}\\\\)").unwrap()
});

/// Wrap SFTP create/open failures: name the missing parent directory when
/// that is the actual cause (raw SFTP "no such file" is ambiguous).
fn create_error<E: std::fmt::Display>(e: E, real: &str) -> McpError {
    let msg = e.to_string();
    if msg.to_lowercase().contains("no such file")
        && let Some((parent, _)) = real.rsplit_once('/')
        && !parent.is_empty()
    {
        return invalid(format!(
            "cannot create {real}: parent directory does not exist ({parent})"
        ));
    }
    internal(msg)
}

/// Read-before-write guard: overwrite of an existing non-empty file requires
/// full read coverage tagged with the current (size, mtime) fingerprint.
fn guard_check(session: &Session, real: &str, fp: Fingerprint, tool: &str) -> Result<(), McpError> {
    let missing = {
        let reads = session.reads.lock();
        match reads.get(real) {
            Some(cov) => cov.missing((0, fp.0), fp),
            None => vec![(0, fp.0)],
        }
    };
    if missing.is_empty() {
        Ok(())
    } else {
        let ranges = missing
            .iter()
            .map(|(s, e)| format!("[{s}, {e})"))
            .collect::<Vec<_>>()
            .join(", ");
        Err(invalid(format!(
            "{tool} denied: {real} not fully read (missing {ranges}) or changed since read; run file_read first"
        )))
    }
}

#[tool_router(server_handler)]
impl SshMcp {
    #[tool(
        description = "Open a persistent SSH shell session (PTY). Auth order: explicit private_key, then SSH agent, then password. Returns session_id used by all other tools. The shell persists: cwd, env, and aliases survive across ssh_run calls."
    )]
    pub async fn ssh_open(
        &self,
        Parameters(p): Parameters<SshOpenParams>,
    ) -> Result<Json<SshOpenOut>, McpError> {
        let policy = match p.host_key_policy.as_str() {
            "accept-new" => HostKeyPolicy::AcceptNew,
            "off" => HostKeyPolicy::Off,
            other => {
                return Err(invalid(format!(
                    "host_key_policy must be \"accept-new\" or \"off\", got '{other}'"
                )));
            }
        };
        let opened = connect::open(
            ConnectParams {
                host: p.host,
                port: p.port.unwrap_or(0),
                user: p.user.unwrap_or_default(),
                password: p.password,
                private_key: p.private_key,
                passphrase: p.passphrase,
                use_agent: p.use_agent,
                use_ssh_config: p.use_ssh_config,
                host_key_policy: policy,
                cols: p.cols,
                rows: p.rows,
                connect_timeout: Duration::from_millis(p.connect_timeout_ms),
            },
            &self.sessions,
        )
        .await
        .map_err(internal)?;
        self.sessions.insert(opened.session.clone()).await;
        let s = &opened.session;
        self.audit.log(
            &s.id,
            "ssh_open",
            serde_json::json!({"target": s.target, "auth_method": opened.auth_method, "host_key_policy": p.host_key_policy}),
        );
        Ok(Json(SshOpenOut {
            session_id: s.id.clone(),
            shell_kind: s.shell_kind,
            target: s.target.clone(),
            auth_method: opened.auth_method.to_string(),
        }))
    }

    #[tool(
        description = "Close a session: terminates the shell channel and drops SFTP. Idempotent only for known ids."
    )]
    pub async fn ssh_close(
        &self,
        Parameters(p): Parameters<SessionParams>,
    ) -> Result<Json<ClosedOut>, McpError> {
        let session = self
            .sessions
            .remove(&p.session_id)
            .await
            .ok_or_else(|| invalid(format!("unknown session '{}'", p.session_id)))?;
        session.alive.store(false, Ordering::SeqCst);
        {
            let w = session.writer.lock().await;
            let _ = w.close().await;
        }
        session.pump.abort();
        self.audit
            .log(&session.id, "ssh_close", serde_json::json!({}));
        Ok(Json(ClosedOut { closed: true }))
    }

    #[tool(description = "List all open sessions with their targets, shell kind, and liveness.")]
    pub async fn ssh_list(&self) -> Result<Json<ListOut>, McpError> {
        let sessions = self
            .sessions
            .list()
            .await
            .into_iter()
            .map(|s| ListEntry {
                session_id: s.id.clone(),
                target: s.target.clone(),
                shell_kind: s.shell_kind,
                alive: s.alive.load(Ordering::SeqCst),
                idle_secs: s.shared.inner.lock().last_output_at.elapsed().as_secs(),
            })
            .collect();
        Ok(Json(ListOut { sessions }))
    }

    #[tool(
        description = "Run a command in the persistent shell and return clean output + exit code. Persistent shell: cwd/env/aliases survive across calls. For system monitoring prefer batch commands (top -b -n 1, ps aux --sort=-%cpu | head) over interactive TUIs. On timeout returns partial output with timed_out=true (the command keeps running — use ssh_type/ssh_press to interact)."
    )]
    pub async fn ssh_run(
        &self,
        Parameters(p): Parameters<SshRunParams>,
    ) -> Result<Json<SshRunOut>, McpError> {
        let session = self.live_session(&p.session_id).await?;
        if session.shell_kind != ShellKind::Posix {
            return Err(invalid(
                "ssh_run requires a POSIX-like shell (probe failed at open); use ssh_type + ssh_expect instead",
            ));
        }
        let _io = session.io_lock.lock().await;
        // Let any in-flight output/typing settle (avoids scaffolding colliding
        // with a line readline has not accepted yet).
        let _ = session::wait_screen(
            &session.shared,
            None,
            session::WaitMode::Quiet,
            Duration::from_millis(100),
            Duration::from_secs(1),
        )
        .await;
        let start = session.shared.inner.lock().stream.end_offset();
        let tok = format!("{:08x}", rand::random::<u32>());
        // Echo-toggle handshake (event-driven, no fixed sleeps):
        //   1. write `stty -echo` + PRE marker (leading space: not recorded in
        //      shell history); when PRE appears, stty has executed and the tty
        //      ECHO flag is off
        //   2. deliver the command — paste-wrapped when the shell advertised
        //      bracketed paste, so the shell PARSER handles heredocs instead
        //      of per-line readline reads (the byte-eating race)
        //   3. scaffold line (leading space, echo off → invisible, unrecorded)
        //      captures rc BEFORE `stty echo` clobbers $?, restores echo so
        //      interactive readline works between commands; if the command
        //      hangs, an agent ctrl+c kills it and the queued scaffold runs
        let pre_marker = format!("__SPM_PRE_{tok}__");
        {
            let w = session.writer.lock().await;
            // %s indirection: the echoed PRE line contains the format string,
            // only the real printf output contains the marker — the wait can
            // no longer return early on the echo (which would race stty).
            // PS1 is blanked (saved/restored via $__spm_ps1) so prompt redraws
            // cannot pollute the captured output region.
            w.data_bytes(
                format!(" __spm_ps1=$PS1; PS1=; stty -echo; printf '__SPM_PRE_%s__\\n' {tok}\n")
                    .into_bytes(),
            )
            .await
            .map_err(internal)?;
        }
        let pre_ok = session::wait_stream_contains(
            &session.shared,
            start,
            pre_marker.as_bytes(),
            Duration::from_millis(p.timeout_ms.min(5000)),
        )
        .await;
        if !pre_ok {
            return Err(internal(
                "shell did not acknowledge echo toggle (busy or non-POSIX); retry or use ssh_type/ssh_expect",
            ));
        }
        // Let the post-PRE prompt redraw finish so it cannot leak into the
        // captured output region.
        let _ = session::wait_screen(
            &session.shared,
            None,
            session::WaitMode::Quiet,
            Duration::from_millis(150),
            Duration::from_secs(2),
        )
        .await;
        let cmd_start = session.shared.inner.lock().stream.end_offset();
        {
            let w = session.writer.lock().await;
            if session.bracketed_paste {
                w.data_bytes(format!("\u{1b}[200~{}\u{1b}[201~\n", p.command).into_bytes())
                    .await
                    .map_err(internal)?;
            } else {
                w.data_bytes(format!("{}\n", p.command).into_bytes())
                    .await
                    .map_err(internal)?;
            }
            w.data_bytes(
                format!(" rc=$?; stty echo; PS1=$__spm_ps1; printf '\\n__SPM_{}_%d__\\n' $rc\n", tok)
                    .into_bytes(),
            )
            .await
            .map_err(internal)?;
        }

        let deadline = Instant::now() + Duration::from_millis(p.timeout_ms);
        let found = loop {
            {
                let st = session.shared.inner.lock();
                if let Some(hit) = find_marker(&st.stream, cmd_start, &tok) {
                    break Some(hit);
                }
                if st.eof {
                    break None;
                }
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break None;
            }
            let _ = tokio::time::timeout(remaining, session.shared.notify.notified()).await;
        };

        let (output, exit_code, timed_out, stream_offset) = {
            let st = session.shared.inner.lock();
            let (bytes, _, _) = st.stream.read(cmd_start);
            let offset = st.stream.end_offset();
            let (out, rc, to) = match found {
                Some((marker_abs, rc)) => {
                    let end = (marker_abs - cmd_start) as usize;
                    let mut out =
                        String::from_utf8_lossy(&bytes[..end.min(bytes.len())]).into_owned();
                    while out.starts_with('\r') || out.starts_with('\n') {
                        out.remove(0);
                    }
                    (out.trim_end().to_string(), Some(rc), false)
                }
                None => {
                    let out = String::from_utf8_lossy(&bytes).into_owned();
                    (out.trim_end().to_string(), None, true)
                }
            };
            (out, rc, to, offset)
        };
        let output = if p.strip_ansi {
            ANSI_RE.replace_all(&output, "").into_owned()
        } else {
            output
        };
        // Post-strip residue (CRs that followed removed escape sequences).
        let output = output.trim_start_matches(['\r', '\n']).trim_end().to_string();
        let truncated = output.len() > p.max_output_bytes as usize;
        let output = tail_chars(&output, p.max_output_bytes as usize);
        self.audit.log(
            &session.id,
            "ssh_run",
            serde_json::json!({"command": p.command, "exit_code": exit_code, "timed_out": timed_out}),
        );
        Ok(Json(SshRunOut {
            output,
            exit_code,
            timed_out,
            truncated,
            stream_offset,
        }))
    }

    #[tool(
        description = "Type text verbatim into the terminal (no implicit newline — include \\n to submit). Returns the seq anchor for ssh_screen(since_seq). Content is redacted in the audit log."
    )]
    pub async fn ssh_type(
        &self,
        Parameters(p): Parameters<SshTypeParams>,
    ) -> Result<Json<SeqOut>, McpError> {
        let session = self.live_session(&p.session_id).await?;
        let _io = session.io_lock.lock().await;
        let char_count = p.text.len();
        {
            let w = session.writer.lock().await;
            w.data_bytes(p.text.into_bytes()).await.map_err(internal)?;
        }
        self.audit.log(
            &session.id,
            "ssh_type",
            serde_json::json!({"chars": char_count}),
        );
        let (seq, stream_offset) = {
            let st = session.shared.inner.lock();
            (st.seq, st.stream.end_offset())
        };
        Ok(Json(SeqOut { seq, stream_offset }))
    }

    #[tool(
        description = "Virtual keyboard for TUI programs (top/htop/less/menus). Press a named key: \"q\", \"enter\", \"ctrl+c\", \"ctrl+x\", \"shift+tab\", \"up\", \"f5\"... Pair with ssh_screen: press -> ssh_screen(wait='quiet', since_seq=<returned seq>) -> decide."
    )]
    pub async fn ssh_press(
        &self,
        Parameters(p): Parameters<SshPressParams>,
    ) -> Result<Json<SeqOut>, McpError> {
        let session = self.live_session(&p.session_id).await?;
        let bytes = keys::map_key(&p.key).map_err(invalid)?;
        let _io = session.io_lock.lock().await;
        {
            let w = session.writer.lock().await;
            w.data_bytes(bytes).await.map_err(internal)?;
        }
        self.audit
            .log(&session.id, "ssh_press", serde_json::json!({"key": p.key}));
        let (seq, stream_offset) = {
            let st = session.shared.inner.lock();
            (st.seq, st.stream.end_offset())
        };
        Ok(Json(SeqOut { seq, stream_offset }))
    }

    #[tool(
        description = "Send a signal (sigint/sigquit/sigterm/sigkill/sighup/sigtstp) via the SSH protocol to the shell's foreground process group. Note: some servers/sudo contexts ignore SSH signal requests — fallback is ssh_press(\"ctrl+c\") or ssh_run(\"kill -<SIG> <pid>\")."
    )]
    pub async fn ssh_signal(
        &self,
        Parameters(p): Parameters<SshSignalParams>,
    ) -> Result<Json<SentOut>, McpError> {
        let session = self.live_session(&p.session_id).await?;
        let sig = match p.signal.to_ascii_lowercase().as_str() {
            "sigint" => russh::Sig::INT,
            "sigquit" => russh::Sig::QUIT,
            "sigterm" => russh::Sig::TERM,
            "sigkill" => russh::Sig::KILL,
            "sighup" => russh::Sig::HUP,
            "sigtstp" => russh::Sig::Custom("TSTP".into()),
            other => {
                return Err(invalid(format!(
                    "unknown signal '{other}' (sigint|sigquit|sigterm|sigkill|sighup|sigtstp)"
                )));
            }
        };
        let _io = session.io_lock.lock().await;
        {
            let w = session.writer.lock().await;
            w.signal(sig).await.map_err(internal)?;
        }
        self.audit.log(
            &session.id,
            "ssh_signal",
            serde_json::json!({"signal": p.signal}),
        );
        Ok(Json(SentOut { sent: true }))
    }

    #[tool(
        description = "Wait for a regex on the session. Use for prompts (password:, [y/n], menus). More precise than ssh_screen when you know what to wait for. mode=stream matches output arriving after this call; mode=screen matches the rendered screen. On timeout returns matched=false with whatever accumulated."
    )]
    pub async fn ssh_expect(
        &self,
        Parameters(p): Parameters<SshExpectParams>,
    ) -> Result<Json<SshExpectOut>, McpError> {
        let session = self.live_session(&p.session_id).await?;
        let re =
            regex::Regex::new(&p.pattern).map_err(|e| invalid(format!("invalid regex: {e}")))?;
        let screen_mode = match p.mode.as_str() {
            "stream" => false,
            "screen" => true,
            other => {
                return Err(invalid(format!(
                    "mode must be \"stream\" or \"screen\", got '{other}'"
                )));
            }
        };
        let start = p
            .from_offset
            .unwrap_or_else(|| session.shared.inner.lock().stream.end_offset());
        let deadline = Instant::now() + Duration::from_millis(p.timeout_ms);

        let (matched, text, captures, timed_out) = loop {
            enum Hit {
                No,
                Yes(String, usize, Vec<String>),
                Eof(String),
            }
            let step = {
                let st = session.shared.inner.lock();
                let hay = if screen_mode {
                    screen_text(&st.parser)
                } else {
                    let (bytes, _, _) = st.stream.read(start);
                    String::from_utf8_lossy(&bytes).into_owned()
                };
                if let Some(caps) = re.captures(&hay) {
                    let end = caps.get(0).unwrap().end();
                    let groups = (1..caps.len())
                        .map(|i| {
                            caps.get(i)
                                .map(|g| g.as_str().to_string())
                                .unwrap_or_default()
                        })
                        .collect();
                    Hit::Yes(hay, end, groups)
                } else if st.eof {
                    Hit::Eof(hay)
                } else {
                    Hit::No
                }
            };
            match step {
                Hit::Yes(hay, end, groups) => {
                    let text = if screen_mode {
                        hay
                    } else {
                        hay[..end].to_string()
                    };
                    break (true, text, groups, false);
                }
                Hit::Eof(hay) => {
                    break (
                        false,
                        tail_chars(&hay, p.max_bytes as usize),
                        Vec::new(),
                        false,
                    );
                }
                Hit::No => {}
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                let st = session.shared.inner.lock();
                let hay = if screen_mode {
                    screen_text(&st.parser)
                } else {
                    let (bytes, _, _) = st.stream.read(start);
                    String::from_utf8_lossy(&bytes).into_owned()
                };
                break (
                    false,
                    tail_chars(&hay, p.max_bytes as usize),
                    Vec::new(),
                    true,
                );
            }
            let _ = tokio::time::timeout(remaining, session.shared.notify.notified()).await;
        };
        Ok(Json(SshExpectOut {
            matched,
            text,
            captures,
            timed_out,
        }))
    }

    #[tool(
        description = "Returns the current rendered screen from the server-side terminal model — no SSH round-trip. The screen legitimately contains prior output (a real terminal keeps it until cleared): detect WHAT CHANGED with since_seq + wait, never by diffing screen text yourself. Typical loop: press/type -> ssh_screen(wait='quiet', since_seq=<returned seq>) -> decide. wait='change' returns on the first new byte; wait='none' snapshots immediately. On timeout returns the current screen with timed_out=true."
    )]
    pub async fn ssh_screen(
        &self,
        Parameters(p): Parameters<SshScreenParams>,
    ) -> Result<Json<SshScreenOut>, McpError> {
        let session = self.live_session(&p.session_id).await?;
        let mode = match p.wait.as_str() {
            "none" => WaitMode::None_,
            "change" => WaitMode::Change,
            "quiet" => WaitMode::Quiet,
            other => {
                return Err(invalid(format!(
                    "wait must be \"none\"|\"change\"|\"quiet\", got '{other}'"
                )));
            }
        };
        let (screen, seq, idle_ms, timed_out) = session::wait_screen(
            &session.shared,
            p.since_seq,
            mode,
            Duration::from_millis(p.settle_ms),
            Duration::from_millis(p.timeout_ms),
        )
        .await;
        Ok(Json(SshScreenOut {
            screen,
            seq,
            idle_ms,
            timed_out,
        }))
    }

    #[tool(
        description = "Read a remote text file via SFTP (offset/limit for large files). Prefer this over opening vim/nano in the terminal. Binary files are rejected — use ssh_download for those."
    )]
    pub async fn file_read(
        &self,
        Parameters(p): Parameters<FileReadParams>,
    ) -> Result<Json<FileReadOut>, McpError> {
        let session = self.live_session(&p.session_id).await?;
        let mut guard = Self::sftp(&session).await?;
        let sftp = guard.as_mut().unwrap();
        let real = sftp
            .canonicalize(&p.path)
            .await
            .unwrap_or_else(|_| p.path.clone());
        let meta = sftp
            .metadata(&real)
            .await
            .map_err(|e| invalid(format!("cannot stat {real}: {e}")))?;
        let fp: Fingerprint = (meta.size.unwrap_or(0), meta.mtime.unwrap_or(0));
        let mut file = sftp.open(&real).await.map_err(internal)?;
        file.seek(std::io::SeekFrom::Start(p.offset))
            .await
            .map_err(internal)?;
        let mut buf = vec![0u8; p.limit as usize];
        let mut got = 0usize;
        while got < buf.len() {
            let n = file.read(&mut buf[got..]).await.map_err(internal)?;
            if n == 0 {
                break;
            }
            got += n;
        }
        buf.truncate(got);
        let content = String::from_utf8(buf).map_err(|_| {
            invalid(format!(
                "{real} is not valid UTF-8 (binary file); use ssh_download"
            ))
        })?;
        session
            .reads
            .lock()
            .entry(real)
            .or_default()
            .record(p.offset, p.offset + got as u64, fp);
        Ok(Json(FileReadOut {
            content,
            size: fp.0,
            eof: p.offset + got as u64 >= fp.0,
        }))
    }

    #[tool(
        description = "Write a remote text file via SFTP. Prefer this over opening vim/nano in the terminal. mode=overwrite requires having read the full current file via file_read first — the server enforces this; partial reads are rejected with the missing byte ranges. overwrite on a NOT-YET-EXISTING file is allowed without any read. mode=append is always allowed and creates the file if missing. Parent directory must exist."
    )]
    pub async fn file_write(
        &self,
        Parameters(p): Parameters<FileWriteParams>,
    ) -> Result<Json<FileWriteOut>, McpError> {
        let session = self.live_session(&p.session_id).await?;
        let overwrite = match p.mode.as_str() {
            "overwrite" => true,
            "append" => false,
            other => {
                return Err(invalid(format!(
                    "mode must be \"overwrite\" or \"append\", got '{other}'"
                )));
            }
        };
        let mut guard = Self::sftp(&session).await?;
        let sftp = guard.as_mut().unwrap();
        let real = sftp
            .canonicalize(&p.path)
            .await
            .unwrap_or_else(|_| p.path.clone());
        let path_lock = session.write_lock_for(&real);
        let _wg = path_lock.lock().await;
        if overwrite && let Ok(meta) = sftp.metadata(&real).await {
            let fp: Fingerprint = (meta.size.unwrap_or(0), meta.mtime.unwrap_or(0));
            if fp.0 > 0 {
                guard_check(&session, &real, fp, "file_write")?;
            }
        }
        let mut file = if overwrite {
            sftp.create(&real)
                .await
                .map_err(|e| create_error(e, &real))?
        } else {
            // CREAT|APPEND|WRITE: create-if-missing, writes forced to end.
            sftp.open_with_flags(
                &real,
                russh_sftp::protocol::OpenFlags::CREATE
                    | russh_sftp::protocol::OpenFlags::APPEND
                    | russh_sftp::protocol::OpenFlags::WRITE,
            )
            .await
            .map_err(|e| create_error(e, &real))?
        };
        file.write_all(p.content.as_bytes())
            .await
            .map_err(internal)?;
        let _ = file.sync_all().await;
        self.audit.log(
            &session.id,
            "file_write",
            serde_json::json!({"path": real, "mode": p.mode, "bytes": p.content.len()}),
        );
        Ok(Json(FileWriteOut {
            bytes_written: p.content.len() as u64,
        }))
    }

    #[tool(
        description = "Upload a local file to the remote host via SFTP (binary-safe). Overwriting an existing remote file requires a prior full file_read of it (read-before-write guard)."
    )]
    pub async fn ssh_upload(
        &self,
        Parameters(p): Parameters<TransferParams>,
    ) -> Result<Json<TransferOut>, McpError> {
        let session = self.live_session(&p.session_id).await?;
        let mut guard = Self::sftp(&session).await?;
        let sftp = guard.as_mut().unwrap();
        let real = sftp
            .canonicalize(&p.remote_path)
            .await
            .unwrap_or_else(|_| p.remote_path.clone());
        let path_lock = session.write_lock_for(&real);
        let _wg = path_lock.lock().await;
        if let Ok(meta) = sftp.metadata(&real).await {
            let fp: Fingerprint = (meta.size.unwrap_or(0), meta.mtime.unwrap_or(0));
            if fp.0 > 0 {
                guard_check(&session, &real, fp, "ssh_upload")?;
            }
        }
        let mut local = tokio::fs::File::open(&p.local_path)
            .await
            .map_err(|e| invalid(format!("cannot open local file {}: {e}", p.local_path)))?;
        let mut remote = sftp
            .create(&real)
            .await
            .map_err(|e| create_error(e, &real))?;
        let bytes = tokio::io::copy(&mut local, &mut remote)
            .await
            .map_err(internal)?;
        self.audit.log(
            &session.id,
            "ssh_upload",
            serde_json::json!({"local_path": p.local_path, "remote_path": real, "bytes": bytes}),
        );
        Ok(Json(TransferOut { bytes }))
    }

    #[tool(
        description = "Download a remote file to the local machine via SFTP (binary-safe, no size limit, no guard)."
    )]
    pub async fn ssh_download(
        &self,
        Parameters(p): Parameters<TransferParams>,
    ) -> Result<Json<TransferOut>, McpError> {
        let session = self.live_session(&p.session_id).await?;
        let mut guard = Self::sftp(&session).await?;
        let sftp = guard.as_mut().unwrap();
        let real = sftp
            .canonicalize(&p.remote_path)
            .await
            .unwrap_or_else(|_| p.remote_path.clone());
        let mut remote = sftp.open(&real).await.map_err(internal)?;
        let mut local = tokio::fs::File::create(&p.local_path)
            .await
            .map_err(|e| invalid(format!("cannot create local file {}: {e}", p.local_path)))?;
        let bytes = tokio::io::copy(&mut remote, &mut local)
            .await
            .map_err(internal)?;
        self.audit.log(
            &session.id,
            "ssh_download",
            serde_json::json!({"remote_path": real, "local_path": p.local_path, "bytes": bytes}),
        );
        Ok(Json(TransferOut { bytes }))
    }
}
