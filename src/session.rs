//! Session core: persistent PTY shell state, screen model, stream buffer,
//! wait-state machine, and the read-before-write coverage tracker.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use rmcp::schemars;
use russh::ChannelMsg;
use serde::Serialize;

use crate::ringbuf::RingBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ShellKind {
    Posix,
    Cmd,
    PowerShell,
    Unknown,
}

/// Per-session command policy, set at ssh_open.
#[derive(Debug, Clone, Default)]
pub enum SessionMode {
    /// Everything allowed (current behavior).
    #[default]
    Unrestricted,
    /// Mutating file tools blocked; commands matching the built-in dangerous
    /// list are refused.
    ReadOnly,
    /// Every command must match at least one allowlist regex.
    Restricted(Vec<regex::Regex>),
}

impl SessionMode {
    pub fn label(&self) -> &'static str {
        match self {
            SessionMode::Unrestricted => "unrestricted",
            SessionMode::ReadOnly => "readonly",
            SessionMode::Restricted(_) => "restricted",
        }
    }

    /// Built-in dangerous-command patterns for ReadOnly.
    pub fn dangerous() -> &'static regex::Regex {
        static RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
            regex::Regex::new(
                r"\b(rm|rmdir|mkfs\S*|dd|shutdown|reboot|halt|poweroff|init|kill|killall|pkill|systemctl|service|chmod|chown|chgrp|useradd|userdel|groupadd|groupdel|passwd|iptables|fdisk|parted|mount|umount|swapoff|crontab)\b",
            )
            .unwrap()
        });
        &RE
    }

    /// None = allowed; Some(reason) = refused.
    pub fn check(&self, command: &str) -> Option<String> {
        match self {
            SessionMode::Unrestricted => None,
            SessionMode::ReadOnly => SessionMode::dangerous().find(command).map(|m| {
                format!(
                    "blocked by session mode=readonly: matched dangerous pattern '{}'",
                    m.as_str()
                )
            }),
            SessionMode::Restricted(allow) => {
                if allow.iter().any(|re| re.is_match(command)) {
                    None
                } else {
                    Some(
                        "blocked by session mode=restricted: command matches no allowlist pattern"
                            .to_string(),
                    )
                }
            }
        }
    }
}

pub struct Shared {
    pub inner: Mutex<ScreenState>,
    pub notify: tokio::sync::Notify,
}

pub struct ScreenState {
    pub parser: vt100::Parser,
    pub stream: RingBuf,
    pub seq: u64,
    pub last_output_at: Instant,
    pub eof: bool,
}

impl Shared {
    pub fn new(rows: u16, cols: u16) -> Self {
        Self {
            inner: Mutex::new(ScreenState {
                parser: vt100::Parser::new(rows, cols, 0),
                stream: RingBuf::default(),
                seq: 0,
                last_output_at: Instant::now(),
                eof: false,
            }),
            notify: tokio::sync::Notify::new(),
        }
    }

    /// Pump-side ingest: one call per received byte batch.
    pub fn feed(&self, data: &[u8]) {
        {
            let mut st = self.inner.lock();
            st.stream.push(data);
            st.parser.process(data);
            st.seq += 1;
            st.last_output_at = Instant::now();
        }
        self.notify.notify_waiters();
    }

    pub fn mark_eof(&self) {
        {
            let mut st = self.inner.lock();
            st.eof = true;
        }
        self.notify.notify_waiters();
    }

    pub fn seq(&self) -> u64 {
        self.inner.lock().seq
    }
}

pub struct Session {
    pub id: String,
    pub target: String,       // "user@host:port"
    pub name: Option<String>, // optional human alias, usable anywhere session_id is
    pub mode: SessionMode,
    pub shell_kind: ShellKind,
    pub shared: Arc<Shared>,
    pub writer: tokio::sync::Mutex<russh::ChannelWriteHalf<russh::client::Msg>>,
    pub handle: russh::client::Handle<crate::connect::ClientHandler>,
    /// Bastion connection, kept alive for the session's lifetime (ProxyJump).
    pub bastion: Option<Box<russh::client::Handle<crate::connect::ClientHandler>>>,
    pub sftp: tokio::sync::Mutex<Option<russh_sftp::client::SftpSession>>,
    pub io_lock: tokio::sync::Mutex<()>,
    pub reads: Mutex<HashMap<String, ReadCoverage>>,
    /// Per-(session, path) write serialization: held across guard-check + write
    /// so a concurrent tool in THIS process cannot slip a modification between
    /// the fingerprint check and the write.
    pub write_locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    /// Shared with the pump task: set false on EOF/Close or ssh_close.
    pub alive: Arc<AtomicBool>,
    /// Remote shell advertised readline bracketed paste (`\x1b[?2004h`) at
    /// open. ssh_run pastes the user command as one buffer when true — the
    /// shell parser (not per-line readline reads) handles heredocs.
    pub bracketed_paste: bool,
    pub pump: tokio::task::JoinHandle<()>,
}

impl Session {
    pub fn check_alive(&self) -> Result<(), String> {
        if self.alive.load(Ordering::SeqCst) && !self.shared.inner.lock().eof {
            Ok(())
        } else {
            Err(format!(
                "session {} is closed or dead; open a new one with ssh_open",
                self.id
            ))
        }
    }

    pub fn write_lock_for(&self, path: &str) -> Arc<tokio::sync::Mutex<()>> {
        self.write_locks
            .lock()
            .entry(path.to_string())
            .or_default()
            .clone()
    }
}

#[derive(Default)]
pub struct SessionManager {
    sessions: tokio::sync::Mutex<HashMap<String, Arc<Session>>>,
    next: AtomicU64,
}

impl SessionManager {
    pub fn next_id(&self) -> String {
        format!("s{}", self.next.fetch_add(1, Ordering::SeqCst) + 1)
    }

    pub async fn insert(&self, session: Arc<Session>) {
        self.sessions
            .lock()
            .await
            .insert(session.id.clone(), session);
    }

    pub async fn get(&self, id: &str) -> Option<Arc<Session>> {
        self.sessions.lock().await.get(id).cloned()
    }

    pub async fn remove(&self, id: &str) -> Option<Arc<Session>> {
        self.sessions.lock().await.remove(id)
    }

    pub async fn list(&self) -> Vec<Arc<Session>> {
        self.sessions.lock().await.values().cloned().collect()
    }

    /// Drop sessions whose shell died (EOF/Close or killed). Their names and
    /// limit slots are released for reuse.
    pub async fn prune_dead(&self) {
        self.sessions
            .lock()
            .await
            .retain(|_, s| s.alive.load(Ordering::SeqCst));
    }
}

/// Spawn the pump: remote bytes -> screen model + stream buffer.
pub fn spawn_pump(
    mut read: russh::ChannelReadHalf,
    shared: Arc<Shared>,
    alive: Arc<AtomicBool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match read.wait().await {
                Some(ChannelMsg::Data { data }) => shared.feed(&data),
                Some(ChannelMsg::ExtendedData { data, ext: 1 }) => shared.feed(&data),
                Some(ChannelMsg::Eof | ChannelMsg::Close) | None => break,
                _ => {} // ChannelMsg is #[non_exhaustive]
            }
        }
        alive.store(false, Ordering::SeqCst);
        shared.mark_eof();
    })
}

// ── Wait-state machine ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitMode {
    None_,
    Change,
    Quiet,
}

/// Render the current screen: viewport text, trailing blank lines trimmed.
/// Scaffolding lines (our markers, stty/PS1 wrappers) are filtered at the
/// presentation layer — the vt100 model keeps everything; agents see a clean
/// terminal.
pub fn screen_text(parser: &vt100::Parser) -> String {
    parser
        .screen()
        .contents()
        .lines()
        .filter(|l| !is_scaffold_line(l))
        .collect::<Vec<_>>()
        .join("\n")
        .trim_end()
        .to_string()
}

fn is_scaffold_line(l: &str) -> bool {
    l.contains("__SPM_") || l.contains("__spm_ps1=") || l.contains("export HISTCONTROL=")
}

/// Wait on the screen model. Returns `(screen, seq, idle_ms, timed_out)`.
/// - `None_`: immediate snapshot.
/// - `Change`: block until `seq > since` (any new output).
/// - `Quiet`: block until changed AND no new bytes for `settle`.
pub async fn wait_screen(
    shared: &Shared,
    since: Option<u64>,
    mode: WaitMode,
    settle: Duration,
    timeout: Duration,
) -> (String, u64, u128, bool) {
    let deadline = Instant::now() + timeout;
    loop {
        let wait_for = {
            let st = shared.inner.lock();
            let changed = since.is_none_or(|s| st.seq > s);
            let idle = st.last_output_at.elapsed();
            let hit = match mode {
                WaitMode::None_ => true,
                WaitMode::Change => changed,
                WaitMode::Quiet => changed && idle >= settle,
            };
            if hit {
                return (screen_text(&st.parser), st.seq, idle.as_millis(), false);
            }
            let mut remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return (screen_text(&st.parser), st.seq, idle.as_millis(), true);
            }
            if mode == WaitMode::Quiet && changed && idle < settle {
                remaining = remaining.min(settle - idle);
            }
            remaining
        };
        let _ = tokio::time::timeout(wait_for, shared.notify.notified()).await;
    }
}

/// Block until the stream (from `from`) contains `needle` or the timeout hits.
pub async fn wait_stream_contains(
    shared: &Shared,
    from: u64,
    needle: &[u8],
    timeout: Duration,
) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        {
            let st = shared.inner.lock();
            let (bytes, _, _) = st.stream.read(from);
            if bytes.windows(needle.len()).any(|w| w == needle) {
                return true;
            }
            if st.eof {
                return false;
            }
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return false;
        }
        if tokio::time::timeout(remaining, shared.notify.notified())
            .await
            .is_err()
        {
            return false;
        }
    }
}

// ── Sentinel marker ─────────────────────────────────────────────────────────

/// Find `\n__SPM_<tok>_<rc>__` in the stream at/after `from`.
/// Returns `(abs offset of the line break preceding the marker, exit_code)`.
/// Scans ALL occurrences: with tty echo on, the echoed printf line itself
/// contains `__SPM_<tok>_` followed by `%d__` — that candidate is invalid
/// (no digits) and must not poison the search for the real marker output.
pub fn find_marker(buf: &RingBuf, from: u64, tok: &str) -> Option<(u64, i64)> {
    let (bytes, _, _) = buf.read(from);
    let pat = format!("__SPM_{tok}_");
    let mut search_from = 0;
    while let Some(rel) = bytes
        .get(search_from..)?
        .windows(pat.len())
        .position(|w| w == pat.as_bytes())
    {
        let pos = search_from + rel;
        let rest = &bytes[pos + pat.len()..];
        let digits = rest.iter().take_while(|b| b.is_ascii_digit()).count();
        let valid = digits > 0 && rest.len() >= digits + 2 && &rest[digits..digits + 2] == b"__";
        if valid {
            let rc: i64 = std::str::from_utf8(&rest[..digits]).ok()?.parse().ok()?;
            let mut start = pos;
            if start >= 2 && &bytes[start - 2..start] == b"\r\n" {
                start -= 2;
            } else if start >= 1 && bytes[start - 1] == b'\n' {
                start -= 1;
            }
            return Some((from + start as u64, rc));
        }
        search_from = pos + 1;
    }
    None
}

// ── Read-before-write coverage ──────────────────────────────────────────────

/// File stat fingerprint: (size, mtime). Reads only count for the exact
/// fingerprint observed at read time; any external change invalidates them.
pub type Fingerprint = (u64, u32);

#[derive(Debug, Default)]
pub struct ReadCoverage {
    /// Sorted, non-overlapping; coalesced within equal fingerprints.
    pub intervals: Vec<(u64, u64, Fingerprint)>,
}

impl ReadCoverage {
    pub fn record(&mut self, start: u64, end: u64, fp: Fingerprint) {
        if start >= end {
            return;
        }
        self.intervals.push((start, end, fp));
        self.intervals.sort_by_key(|i| i.0);
        // Coalesce adjacent/overlapping intervals with the same fingerprint.
        let mut out: Vec<(u64, u64, Fingerprint)> = Vec::with_capacity(self.intervals.len());
        for iv in self.intervals.drain(..) {
            if let Some(last) = out.last_mut()
                && last.2 == iv.2
                && iv.0 <= last.1
            {
                last.1 = last.1.max(iv.1);
                continue;
            }
            out.push(iv);
        }
        self.intervals = out;
    }

    /// Sub-ranges of `want` not covered by intervals tagged `fp`.
    pub fn missing(&self, want: (u64, u64), fp: Fingerprint) -> Vec<(u64, u64)> {
        let mut gaps = Vec::new();
        let mut cursor = want.0;
        for &(s, e, f) in &self.intervals {
            if f != fp || e <= cursor {
                continue;
            }
            if s > cursor {
                gaps.push((cursor, s.min(want.1)));
            }
            cursor = cursor.max(e);
            if cursor >= want.1 {
                return gaps;
            }
        }
        if cursor < want.1 {
            gaps.push((cursor, want.1));
        }
        gaps
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FP: Fingerprint = (100, 1_700_000_000);

    #[test]
    fn coverage_merges_and_reports_gap() {
        let mut c = ReadCoverage::default();
        c.record(0, 60, FP);
        c.record(80, 100, FP);
        assert_eq!(c.missing((0, 100), FP), vec![(60, 80)]);
        c.record(55, 85, FP); // bridges the gap
        assert!(c.missing((0, 100), FP).is_empty());
    }

    #[test]
    fn stale_fingerprint_does_not_count() {
        let mut c = ReadCoverage::default();
        c.record(0, 100, FP);
        let newer = (100, FP.1 + 60);
        assert_eq!(c.missing((0, 100), newer), vec![(0, 100)]);
    }

    #[test]
    fn empty_coverage_misses_everything() {
        let c = ReadCoverage::default();
        assert_eq!(c.missing((0, 42), FP), vec![(0, 42)]);
    }

    #[test]
    fn marker_parsing() {
        let mut b = RingBuf::default();
        b.push(b"total 3\r\n-rw-r--r--\r\n__SPM_deadbeef_0__\r\n");
        let (off, rc) = find_marker(&b, 0, "deadbeef").unwrap();
        assert_eq!(rc, 0);
        // offset points at the \r\n before the marker
        assert_eq!(&b.read(off).0[..2], b"\r\n");
        assert!(find_marker(&b, 0, "00badc0de").is_none());
    }

    #[test]
    fn marker_split_across_pushes() {
        let mut b = RingBuf::default();
        b.push(b"out\n__SPM_ab12");
        assert!(find_marker(&b, 0, "ab12cd34").is_none());
        b.push(b"cd34_127__\n");
        let (_, rc) = find_marker(&b, 0, "ab12cd34").unwrap();
        assert_eq!(rc, 127);
    }

    #[test]
    fn echoed_printf_line_does_not_poison_search() {
        // With tty echo on, the echoed marker line contains __SPM_<tok>_%d__
        // (invalid candidate) before the real marker output arrives.
        let mut b = RingBuf::default();
        b.push(b"printf '\\n__SPM_deadbeef_%d__\\n' $?\r\n\r\n__SPM_deadbeef_0__\r\n");
        let (off, rc) = find_marker(&b, 0, "deadbeef").unwrap();
        assert_eq!(rc, 0);
        // marker_start points at the \r\n before the REAL marker output,
        // i.e. past the echoed line
        assert!(off > 30, "should skip the echoed candidate, got {off}");
    }

    #[tokio::test(start_paused = true)]
    async fn wait_machine_modes() {
        let s2 = Arc::new(Shared::new(24, 80));
        let s3 = s2.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            s3.feed(b"hi");
            tokio::time::sleep(Duration::from_millis(50)).await;
            s3.feed(b"there");
        });
        let (_, seq, _, timed_out) = wait_screen(
            &s2,
            Some(s2.seq()),
            WaitMode::Change,
            Duration::from_millis(250),
            Duration::from_secs(5),
        )
        .await;
        assert!(!timed_out);
        assert!(seq >= 1);

        // Quiet waits for the settle window after the last byte.
        let s4 = s2.clone();
        let before = s4.seq();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            s4.feed(b"x");
            tokio::time::sleep(Duration::from_millis(10)).await;
            s4.feed(b"y");
        });
        let (_, seq, _, timed_out) = wait_screen(
            &s2,
            Some(before),
            WaitMode::Quiet,
            Duration::from_millis(250),
            Duration::from_secs(5),
        )
        .await;
        assert!(!timed_out);
        assert!(seq >= before + 2);

        // Timeout path.
        let (_, _, _, timed_out) = wait_screen(
            &s2,
            Some(s2.seq()),
            WaitMode::Change,
            Duration::from_millis(250),
            Duration::from_millis(100),
        )
        .await;
        assert!(timed_out);
    }
}
