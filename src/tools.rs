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
fn default_ready_timeout() -> u64 {
    2000
}
fn default_async_timeout() -> u64 {
    600_000
}

// ── Params & outputs ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct SshOpenParams {
    /// Hostname, IP, or a Host alias from ~/.ssh/config.
    pub host: String,
    /// SSH port. Omit to use ~/.ssh/config or 22.
    #[serde(default)]
    pub port: Option<u16>,
    /// Login user. Omit to use ~/.ssh/config.
    #[serde(default)]
    pub user: Option<String>,
    /// Optional alias for this session (must be unique). Usable anywhere
    /// session_id is accepted.
    #[serde(default)]
    pub name: Option<String>,
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
    pub name: Option<String>,
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
    pub name: Option<String>,
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
pub struct SshShellParams {
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
pub struct SshShellOut {
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
    /// by ssh_type/ssh_press/ssh_shell to avoid missing output that arrived
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
    /// Logical-clock anchor returned by ssh_type/ssh_press/ssh_shell.
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
    /// Return only the last N lines of the screen (e.g. 1 = just the prompt
    /// line). Default: full viewport.
    #[serde(default)]
    pub tail_lines: Option<u8>,
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

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SshCopyParams {
    pub from_session: String,
    pub from_path: String,
    pub to_session: String,
    pub to_path: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct TransferOut {
    pub bytes: u64,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SshExecParams {
    pub session_id: String,
    /// Command executed via a one-shot SSH exec channel (stateless: no cwd/env
    /// carryover, no interaction with the persistent shell).
    pub command: String,
    #[serde(default = "default_run_timeout")]
    pub timeout_ms: u64,
    #[serde(default = "default_max_output")]
    pub max_output_bytes: u64,
    #[serde(default = "default_true")]
    pub strip_ansi: bool,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct SshExecOut {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<i64>,
    pub timed_out: bool,
    pub truncated: bool,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SshReadyParams {
    pub session_id: String,
    #[serde(default = "default_ready_timeout")]
    pub probe_timeout_ms: u64,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct SshReadyOut {
    pub ready: bool,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SshShellAsyncParams {
    pub session_id: String,
    pub command: String,
    #[serde(default = "default_async_timeout")]
    pub timeout_ms: u64,
    #[serde(default = "default_max_output")]
    pub max_output_bytes: u64,
    #[serde(default = "default_true")]
    pub strip_ansi: bool,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct SshShellAsyncOut {
    pub task_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SshTaskStatusParams {
    pub task_id: String,
    /// Block up to this long waiting for completion. Default 0 (instant).
    #[serde(default)]
    pub wait_ms: u64,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SshTaskCancelParams {
    pub task_id: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct SshTaskCancelOut {
    pub cancelled: bool,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct SshTaskStatusOut {
    /// "running" | "done" | "error"
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timed_out: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FileEditParams {
    pub session_id: String,
    pub path: String,
    /// Exact text to find. Must match at least once; multiple matches are an
    /// error unless replace_all is set.
    pub old_string: String,
    pub new_string: String,
    #[serde(default)]
    pub replace_all: bool,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct FileEditOut {
    pub replacements: u64,
    /// The replaced region with ~2 lines of surrounding context.
    pub context: String,
}

// ── Server ──────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct SshMcp {
    sessions: Arc<SessionManager>,
    audit: Arc<AuditLog>,
    max_sessions: usize,
    tasks: Arc<tokio::sync::Mutex<std::collections::HashMap<String, TaskState>>>,
    next_task: Arc<std::sync::atomic::AtomicU64>,
}

enum TaskState {
    Running {
        abort: tokio::task::AbortHandle,
        session_id: String,
    },
    Done(Result<SshShellOut, String>),
}

impl SshMcp {
    pub fn new(sessions: SessionManager, audit: Arc<AuditLog>, max_sessions: usize) -> Self {
        Self {
            sessions: Arc::new(sessions),
            audit,
            max_sessions,
            tasks: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
            next_task: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    async fn find_session(&self, id_or_name: &str) -> Option<Arc<Session>> {
        match self.sessions.get(id_or_name).await {
            Some(s) => Some(s),
            None => self
                .sessions
                .list()
                .await
                .into_iter()
                .find(|s| s.name.as_deref() == Some(id_or_name)),
        }
    }

    async fn live_session(&self, id_or_name: &str) -> Result<Arc<Session>, McpError> {
        let session = self.find_session(id_or_name).await.ok_or_else(|| {
            invalid(format!(
                "unknown session '{id_or_name}'; call ssh_open first"
            ))
        })?;
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
    regex::Regex::new("\u{1b}\\[[0-9;?]*[ -/]*[@-~]|\u{1b}\\][^\u{7}\u{1b}]*(?:\u{7}|\u{1b}\\\\)")
        .unwrap()
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
        description = "Open a persistent SSH shell session (PTY). Auth order: explicit private_key, then SSH agent, then password. Returns session_id used by all other tools. The shell persists: cwd, env, and aliases survive across ssh_shell calls."
    )]
    pub async fn ssh_open(
        &self,
        Parameters(p): Parameters<SshOpenParams>,
    ) -> Result<Json<SshOpenOut>, McpError> {
        self.sessions.prune_dead().await;
        if self.sessions.list().await.len() >= self.max_sessions {
            return Err(invalid(format!(
                "session limit reached ({}); close unused sessions with ssh_close first",
                self.max_sessions
            )));
        }
        if let Some(name) = p.name.as_deref()
            && self
                .sessions
                .list()
                .await
                .iter()
                .any(|s| s.name.as_deref() == Some(name))
        {
            return Err(invalid(format!("session name '{name}' is already in use")));
        }
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
                name: p.name.clone(),
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
            name: s.name.clone(),
        }))
    }

    #[tool(
        description = "Close a session: terminates the shell channel and drops SFTP. Idempotent only for known ids."
    )]
    pub async fn ssh_close(
        &self,
        Parameters(p): Parameters<SessionParams>,
    ) -> Result<Json<ClosedOut>, McpError> {
        let found = self.find_session(&p.session_id).await;
        let Some(session) = found else {
            return Err(invalid(format!("unknown session '{}'", p.session_id)));
        };
        let session = self
            .sessions
            .remove(&session.id)
            .await
            .expect("resolved session must exist");
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
        self.sessions.prune_dead().await;
        let sessions = self
            .sessions
            .list()
            .await
            .into_iter()
            .map(|s| ListEntry {
                session_id: s.id.clone(),
                name: s.name.clone(),
                target: s.target.clone(),
                shell_kind: s.shell_kind,
                alive: s.alive.load(Ordering::SeqCst),
                idle_secs: s.shared.inner.lock().last_output_at.elapsed().as_secs(),
            })
            .collect();
        Ok(Json(ListOut { sessions }))
    }

    #[tool(
        description = "Run a command in the persistent shell and return clean output + exit code. Persistent shell: cwd/env/aliases survive across calls; `exit`/`logout` KILLS the whole session (open a new one). For system monitoring prefer batch commands (top -b -n 1, ps aux --sort=-%cpu | head) over interactive TUIs. PRECONDITION: the shell must be at a prompt — if you used ssh_type/ssh_press to start a long-running or interactive command (vi, passwd, ssh...), first confirm it finished via ssh_expect/ssh_screen, or use ssh_exec instead (stateless, never queues behind the shell). On timeout returns partial output with timed_out=true (the command keeps running)."
    )]
    pub async fn ssh_shell(
        &self,
        Parameters(p): Parameters<SshShellParams>,
    ) -> Result<Json<SshShellOut>, McpError> {
        let session = self.live_session(&p.session_id).await?;
        Self::run_core(
            &session,
            &self.audit,
            &p.command,
            p.timeout_ms,
            p.max_output_bytes,
            p.strip_ansi,
        )
        .await
        .map(Json)
    }

    /// Shared ssh_shell implementation, also driven by ssh_shell_async tasks.
    async fn run_core(
        session: &Arc<Session>,
        audit: &AuditLog,
        command: &str,
        timeout_ms: u64,
        max_output_bytes: u64,
        strip_ansi: bool,
    ) -> Result<SshShellOut, McpError> {
        if session.shell_kind != ShellKind::Posix {
            return Err(invalid(
                "ssh_shell requires a POSIX-like shell (probe failed at open); use ssh_type + ssh_expect instead",
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
            Duration::from_millis(timeout_ms.min(5000)),
        )
        .await;
        if !pre_ok {
            return Err(internal(
                "shell did not acknowledge echo toggle: it is busy or an interactive program (vi/passwd/ssh) is running — the scaffolding line may have been consumed by it; inspect with ssh_screen before retrying",
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
                w.data_bytes(format!("\u{1b}[200~{}\u{1b}[201~\n", command).into_bytes())
                    .await
                    .map_err(internal)?;
            } else {
                w.data_bytes(format!("{}\n", command).into_bytes())
                    .await
                    .map_err(internal)?;
            }
            w.data_bytes(
                format!(
                    " rc=$?; stty echo; PS1=$__spm_ps1; printf '\\n__SPM_{}_%d__\\n' $rc\n",
                    tok
                )
                .into_bytes(),
            )
            .await
            .map_err(internal)?;
        }

        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
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
        let output = if strip_ansi {
            ANSI_RE.replace_all(&output, "").into_owned()
        } else {
            output
        };
        // Post-strip residue (CRs that followed removed escape sequences).
        let output = output
            .trim_start_matches(['\r', '\n'])
            .trim_end()
            .to_string();
        let truncated = output.len() > max_output_bytes as usize;
        let output = tail_chars(&output, max_output_bytes as usize);
        audit.log(
            &session.id,
            "ssh_shell",
            serde_json::json!({"command": command, "exit_code": exit_code, "timed_out": timed_out}),
        );
        Ok(SshShellOut {
            output,
            exit_code,
            timed_out,
            truncated,
            stream_offset,
        })
    }

    #[tool(
        description = "Type text verbatim into the terminal (no implicit newline — include \\n to submit). Returns the seq anchor for ssh_screen(since_seq). Content is redacted in the audit log. If the text starts a long-running or interactive command, confirm it finished (ssh_expect/ssh_screen) before calling ssh_shell."
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
        description = "Send a signal (sigint/sigquit/sigterm/sigkill/sighup/sigtstp) via the SSH protocol to the shell's foreground process group. Note: some servers/sudo contexts ignore SSH signal requests — fallback is ssh_press(\"ctrl+c\") or ssh_shell(\"kill -<SIG> <pid>\")."
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
        let screen = match p.tail_lines {
            Some(n) if n > 0 => {
                let lines: Vec<&str> = screen.lines().collect();
                lines[lines.len().saturating_sub(n as usize)..].join("\n")
            }
            _ => screen,
        };
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
        description = "Write a remote text file via SFTP (UTF-8 text only — for binary content, stage it locally and use ssh_upload). Prefer this over opening vim/nano in the terminal. mode=overwrite requires having read the full current file via file_read first — the server enforces this; partial reads are rejected with the missing byte ranges. overwrite on a NOT-YET-EXISTING file is allowed without any read. mode=append is always allowed and creates the file if missing. Parent directory must exist."
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
            if meta.is_dir() {
                return Err(invalid(format!(
                    "{real} is a directory; specify a full file path"
                )));
            }
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
            if meta.is_dir() {
                return Err(invalid(format!(
                    "{real} is a directory; specify a full file path"
                )));
            }
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

    #[tool(
        description = "Execute a command via a one-shot SSH exec channel: stateless (no cwd/env carryover), protocol-level exit status, separate stdout/stderr, and completely isolated from the persistent shell (safe even while it runs an interactive program). Prefer this for simple read-only probes; use ssh_shell when you need shell state or features."
    )]
    pub async fn ssh_exec(
        &self,
        Parameters(p): Parameters<SshExecParams>,
    ) -> Result<Json<SshExecOut>, McpError> {
        let session = self.live_session(&p.session_id).await?;
        let channel = session
            .handle
            .channel_open_session()
            .await
            .map_err(internal)?;
        channel
            .exec(false, p.command.as_str())
            .await
            .map_err(internal)?;
        let (mut read, write) = channel.split();
        let deadline = Instant::now() + Duration::from_millis(p.timeout_ms);
        let (mut stdout, mut stderr, mut exit_code, mut timed_out) =
            (Vec::new(), Vec::new(), None, false);
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                timed_out = true;
                break;
            }
            match tokio::time::timeout(remaining, read.wait()).await {
                Err(_) => {
                    timed_out = true;
                    break;
                }
                Ok(Some(msg)) => match msg {
                    russh::ChannelMsg::Data { data } => stdout.extend_from_slice(&data),
                    russh::ChannelMsg::ExtendedData { data, ext: 1 } => {
                        stderr.extend_from_slice(&data)
                    }
                    russh::ChannelMsg::ExitStatus { exit_status } => {
                        exit_code = Some(exit_status as i64)
                    }
                    // Do NOT break on Eof: OpenSSH sends exit-status between
                    // Eof and Close when the command wrote to stderr.
                    russh::ChannelMsg::Close => break,
                    _ => {}
                },
                Ok(None) => break,
            }
        }
        if timed_out {
            let _ = write.close().await;
        }
        let clean = |bytes: Vec<u8>| -> String {
            let s = String::from_utf8_lossy(&bytes).into_owned();
            let s = if p.strip_ansi {
                ANSI_RE.replace_all(&s, "").into_owned()
            } else {
                s
            };
            tail_chars(s.trim_end(), p.max_output_bytes as usize)
        };
        let truncated = stdout.len() > p.max_output_bytes as usize
            || stderr.len() > p.max_output_bytes as usize;
        self.audit.log(
            &session.id,
            "ssh_exec",
            serde_json::json!({"command": p.command, "exit_code": exit_code, "timed_out": timed_out}),
        );
        Ok(Json(SshExecOut {
            stdout: clean(stdout),
            stderr: clean(stderr),
            exit_code,
            timed_out,
            truncated,
        }))
    }

    #[tool(
        description = "Probe whether the shell is at a prompt (ready to accept commands). Writes one harmless probe line; if the shell or a foreground program does not answer within probe_timeout_ms, returns ready=false. Use before ssh_type-driven interactive sequences."
    )]
    pub async fn ssh_ready(
        &self,
        Parameters(p): Parameters<SshReadyParams>,
    ) -> Result<Json<SshReadyOut>, McpError> {
        let session = self.live_session(&p.session_id).await?;
        let _io = session.io_lock.lock().await;
        let start = session.shared.inner.lock().stream.end_offset();
        let tok = format!("{:08x}", rand::random::<u32>());
        let marker = format!("__SPM_RDY_{tok}__");
        {
            let w = session.writer.lock().await;
            // %s indirection: echo of this line cannot false-positive the wait.
            w.data_bytes(format!(" printf '__SPM_RDY_%s__\\n' {tok}\n").into_bytes())
                .await
                .map_err(internal)?;
        }
        let ready = session::wait_stream_contains(
            &session.shared,
            start,
            marker.as_bytes(),
            Duration::from_millis(p.probe_timeout_ms),
        )
        .await;
        Ok(Json(SshReadyOut { ready }))
    }

    #[tool(
        description = "Start a command in the persistent shell without blocking; returns task_id. Poll with ssh_task_status (optionally with wait_ms), interrupt with ssh_task_cancel. Same semantics as ssh_shell (state persists, at-prompt precondition; `exit` in the command KILLS the whole session, not just the task); the task holds the shell until done, so avoid other ssh_shell calls in the meantime (ssh_exec, ssh_screen, ssh_expect, file tools remain usable)."
    )]
    pub async fn ssh_shell_async(
        &self,
        Parameters(p): Parameters<SshShellAsyncParams>,
    ) -> Result<Json<SshShellAsyncOut>, McpError> {
        let session = self.live_session(&p.session_id).await?;
        let task_id = format!("t{}", self.next_task.fetch_add(1, Ordering::SeqCst) + 1);
        let tasks = self.tasks.clone();
        let audit = self.audit.clone();
        let tid = task_id.clone();
        let command = p.command.clone();
        let sid = session.id.clone();
        let join = tokio::spawn(async move {
            let result = Self::run_core(
                &session,
                &audit,
                &command,
                p.timeout_ms,
                p.max_output_bytes,
                p.strip_ansi,
            )
            .await
            .map_err(|e| e.to_string());
            tasks.lock().await.insert(tid, TaskState::Done(result));
        });
        self.tasks.lock().await.insert(
            task_id.clone(),
            TaskState::Running {
                abort: join.abort_handle(),
                session_id: sid,
            },
        );
        Ok(Json(SshShellAsyncOut { task_id }))
    }

    #[tool(
        description = "Check a background task started by ssh_shell_async. With wait_ms > 0, blocks until the task completes or the wait elapses. Returns status running/done/error plus output and exit_code when finished."
    )]
    pub async fn ssh_task_status(
        &self,
        Parameters(p): Parameters<SshTaskStatusParams>,
    ) -> Result<Json<SshTaskStatusOut>, McpError> {
        let deadline = Instant::now() + Duration::from_millis(p.wait_ms);
        loop {
            {
                let tasks = self.tasks.lock().await;
                match tasks.get(&p.task_id) {
                    None => {
                        return Err(invalid(format!(
                            "unknown task '{}' (from ssh_shell_async)",
                            p.task_id
                        )));
                    }
                    Some(TaskState::Done(Ok(out))) => {
                        return Ok(Json(SshTaskStatusOut {
                            status: "done".into(),
                            output: Some(out.output.clone()),
                            exit_code: out.exit_code,
                            timed_out: Some(out.timed_out),
                            error: None,
                        }));
                    }
                    Some(TaskState::Done(Err(e))) => {
                        return Ok(Json(SshTaskStatusOut {
                            status: "error".into(),
                            output: None,
                            exit_code: None,
                            timed_out: None,
                            error: Some(e.clone()),
                        }));
                    }
                    Some(TaskState::Running { .. }) => {}
                }
            }
            if deadline.saturating_duration_since(Instant::now()).is_zero() {
                return Ok(Json(SshTaskStatusOut {
                    status: "running".into(),
                    output: None,
                    exit_code: None,
                    timed_out: None,
                    error: None,
                }));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    #[tool(
        description = "Cancel a running ssh_shell_async task: sends SIGINT (ctrl+c) to the remote foreground command and stops the local wait. The session stays alive and usable. A command ignoring SIGINT keeps running remotely — follow up with ssh_shell('kill -<SIG> <pid>') if needed."
    )]
    pub async fn ssh_task_cancel(
        &self,
        Parameters(p): Parameters<SshTaskCancelParams>,
    ) -> Result<Json<SshTaskCancelOut>, McpError> {
        let (abort, session_id) = {
            let tasks = self.tasks.lock().await;
            match tasks.get(&p.task_id) {
                None => return Err(invalid(format!("unknown task '{}'", p.task_id))),
                Some(TaskState::Running { abort, session_id }) => {
                    (abort.clone(), session_id.clone())
                }
                Some(TaskState::Done(_)) => {
                    return Ok(Json(SshTaskCancelOut { cancelled: false }));
                }
            }
        };
        // Interrupt the remote foreground command. The queued scaffold lines
        // then run, so the shell returns to a clean prompt state.
        abort.abort();
        if let Some(session) = self.find_session(&session_id).await {
            let w = session.writer.lock().await;
            let _ = w.data_bytes(&b"\x03"[..]).await;
        }
        self.tasks
            .lock()
            .await
            .insert(p.task_id.clone(), TaskState::Done(Err("cancelled".into())));
        self.audit.log(
            &session_id,
            "ssh_task_cancel",
            serde_json::json!({"task_id": p.task_id}),
        );
        Ok(Json(SshTaskCancelOut { cancelled: true }))
    }

    #[tool(
        description = "Copy a file directly between two SSH sessions (possibly different hosts), streamed through this server — no local disk staging. Overwriting an existing destination requires a prior full file_read of it on the destination session (read-before-write guard). Same-host copies are simpler via ssh_shell('cp -r a b')."
    )]
    pub async fn ssh_copy(
        &self,
        Parameters(p): Parameters<SshCopyParams>,
    ) -> Result<Json<TransferOut>, McpError> {
        let from = self.live_session(&p.from_session).await?;
        let to = self.live_session(&p.to_session).await?;

        // Same session: one SFTP lock, one code path.
        if from.id == to.id {
            let mut g = Self::sftp(&from).await?;
            let s = g.as_mut().unwrap();
            let real_from = s
                .canonicalize(&p.from_path)
                .await
                .unwrap_or_else(|_| p.from_path.clone());
            let real_to = s
                .canonicalize(&p.to_path)
                .await
                .unwrap_or_else(|_| p.to_path.clone());
            if real_from == real_to {
                return Err(invalid(format!(
                    "{real_from} and {real_to} are the same file; refusing to copy"
                )));
            }
            let path_lock = to.write_lock_for(&real_to);
            let _wg = path_lock.lock().await;
            if let Ok(meta) = s.metadata(&real_to).await {
                if meta.is_dir() {
                    return Err(invalid(format!(
                        "{real_to} is a directory; specify a full file path"
                    )));
                }
                let fp: Fingerprint = (meta.size.unwrap_or(0), meta.mtime.unwrap_or(0));
                if fp.0 > 0 {
                    guard_check(&to, &real_to, fp, "ssh_copy")?;
                }
            }
            let mut src = s.open(&real_from).await.map_err(internal)?;
            let mut dst = s
                .create(&real_to)
                .await
                .map_err(|e| create_error(e, &real_to))?;
            let bytes = tokio::io::copy(&mut src, &mut dst)
                .await
                .map_err(internal)?;
            self.audit.log(
                &from.id,
                "ssh_copy",
                serde_json::json!({"from": real_from, "to": real_to, "bytes": bytes}),
            );
            return Ok(Json(TransferOut { bytes }));
        }

        // Different sessions: take both SFTP locks in session-id order.
        let (first, second) = if from.id < to.id {
            (&from, &to)
        } else {
            (&to, &from)
        };
        let mut g1 = Self::sftp(first).await?;
        let mut g2 = Self::sftp(second).await?;
        let s1 = g1.as_mut().unwrap();
        let s2 = g2.as_mut().unwrap();
        let (sftp_from, sftp_to) = if from.id < to.id { (s1, s2) } else { (s2, s1) };
        let real_from = sftp_from
            .canonicalize(&p.from_path)
            .await
            .unwrap_or_else(|_| p.from_path.clone());
        let real_to = sftp_to
            .canonicalize(&p.to_path)
            .await
            .unwrap_or_else(|_| p.to_path.clone());
        // Same host (identical target) + same canonical path = same inode:
        // truncating the destination would destroy the source.
        if from.target == to.target && real_from == real_to {
            return Err(invalid(format!(
                "{real_from} and {real_to} are the same file; refusing to copy"
            )));
        }
        let path_lock = to.write_lock_for(&real_to);
        let _wg = path_lock.lock().await;
        if let Ok(meta) = sftp_to.metadata(&real_to).await {
            if meta.is_dir() {
                return Err(invalid(format!(
                    "{real_to} is a directory; specify a full file path"
                )));
            }
            let fp: Fingerprint = (meta.size.unwrap_or(0), meta.mtime.unwrap_or(0));
            if fp.0 > 0 {
                guard_check(&to, &real_to, fp, "ssh_copy")?;
            }
        }
        let mut src = sftp_from.open(&real_from).await.map_err(internal)?;
        let mut dst = sftp_to
            .create(&real_to)
            .await
            .map_err(|e| create_error(e, &real_to))?;
        let bytes = tokio::io::copy(&mut src, &mut dst)
            .await
            .map_err(internal)?;
        self.audit.log(
            &from.id,
            "ssh_copy",
            serde_json::json!({"from": real_from, "to_session": to.id, "to": real_to, "bytes": bytes}),
        );
        Ok(Json(TransferOut { bytes }))
    }

    #[tool(
        description = "Surgical text replacement in a remote file (like a local Edit tool): finds old_string exactly and replaces it. Requires the matched region to be covered by a prior file_read (read-before-write guard); replace_all additionally requires full-file coverage. Fails when old_string is absent or matches multiple times (unless replace_all). UTF-8 text only, 16 MiB cap."
    )]
    pub async fn file_edit(
        &self,
        Parameters(p): Parameters<FileEditParams>,
    ) -> Result<Json<FileEditOut>, McpError> {
        if p.old_string.is_empty() {
            return Err(invalid("old_string must not be empty"));
        }
        let session = self.live_session(&p.session_id).await?;
        let mut guard = Self::sftp(&session).await?;
        let sftp = guard.as_mut().unwrap();
        let real = sftp
            .canonicalize(&p.path)
            .await
            .unwrap_or_else(|_| p.path.clone());
        let path_lock = session.write_lock_for(&real);
        let _wg = path_lock.lock().await;
        let meta = sftp
            .metadata(&real)
            .await
            .map_err(|e| invalid(format!("cannot stat {real}: {e}")))?;
        let fp: Fingerprint = (meta.size.unwrap_or(0), meta.mtime.unwrap_or(0));
        if fp.0 > 16 * 1024 * 1024 {
            return Err(invalid(format!(
                "{real} is too large for file_edit (16 MiB cap); use ssh_shell with sed instead"
            )));
        }
        let data = sftp.read(&real).await.map_err(internal)?;
        let content = String::from_utf8(data)
            .map_err(|_| invalid(format!("{real} is not valid UTF-8; file_edit is text-only")))?;
        let matches: Vec<usize> = content
            .match_indices(&p.old_string)
            .map(|(i, _)| i)
            .collect();
        if matches.is_empty() {
            return Err(invalid(format!("old_string not found in {real}")));
        }
        if matches.len() > 1 && !p.replace_all {
            return Err(invalid(format!(
                "old_string matches {} times in {real}; pass replace_all=true or include more surrounding context",
                matches.len()
            )));
        }
        // Read-before-write guard: matched byte ranges must be read-covered
        // under the current fingerprint; replace_all = full-file coverage.
        let missing: Vec<(u64, u64)> = {
            let reads = session.reads.lock();
            let empty = crate::session::ReadCoverage::default();
            let cov = reads.get(&real).unwrap_or(&empty);
            if p.replace_all {
                cov.missing((0, fp.0), fp)
            } else {
                matches
                    .iter()
                    .flat_map(|&i| cov.missing((i as u64, (i + p.old_string.len()) as u64), fp))
                    .collect()
            }
        };
        if !missing.is_empty() {
            let ranges = missing
                .iter()
                .map(|(s, e)| format!("[{s}, {e})"))
                .collect::<Vec<_>>()
                .join(", ");
            return Err(invalid(format!(
                "file_edit denied: matched region of {real} not covered by prior file_read (missing {ranges}) or changed since read; read the region you intend to edit first"
            )));
        }
        let first = matches[0];
        let new_content = if p.replace_all {
            content.replace(&p.old_string, &p.new_string)
        } else {
            content.replacen(&p.old_string, &p.new_string, 1)
        };
        let mut file = sftp
            .create(&real)
            .await
            .map_err(|e| create_error(e, &real))?;
        file.write_all(new_content.as_bytes())
            .await
            .map_err(internal)?;
        let _ = file.sync_all().await;
        // Context: ±2 lines around the first replacement in the NEW content.
        let lines: Vec<&str> = new_content.lines().collect();
        let hit_line = new_content[..first].lines().count().saturating_sub(1);
        let lo = hit_line.saturating_sub(2);
        let hi = (hit_line + 3).min(lines.len());
        let context = lines[lo..hi].join("\n");
        self.audit.log(
            &session.id,
            "file_edit",
            serde_json::json!({"path": real, "replacements": matches.len(), "replace_all": p.replace_all}),
        );
        Ok(Json(FileEditOut {
            replacements: matches.len() as u64,
            context,
        }))
    }
}
