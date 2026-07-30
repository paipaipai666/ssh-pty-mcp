//! Docker end-to-end test: drives the real tool layer against a real sshd.
//! Run with: SPM_E2E=1 cargo test --test ssh_e2e -- --nocapture
//! Self-skips when SPM_E2E is unset or docker is unavailable.

use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use rmcp::handler::server::wrapper::Parameters;
use ssh_pty_mcp::audit::AuditLog;
use ssh_pty_mcp::connect::{self, ConnectParams, HostKeyPolicy};
use ssh_pty_mcp::session::{SessionManager, ShellKind};
use ssh_pty_mcp::tools::*;

#[path = "common/mod.rs"]
mod common;
use common::{docker_ok, ssh_open_params, start_container};

fn params(port: u16) -> ConnectParams {
    ConnectParams {
        host: "127.0.0.1".into(),
        port,
        user: "test".into(),
        name: None,
        password: Some("testpass".into()),
        private_key: None,
        passphrase: None,
        use_agent: false,
        use_ssh_config: false,
        host_key_policy: HostKeyPolicy::Off,
        cols: 120,
        rows: 32,
        connect_timeout: Duration::from_secs(5),
    }
}

fn sid(id: &str) -> SessionParams {
    SessionParams {
        session_id: id.into(),
    }
}

async fn open_tool(mcp: &SshMcp, port: u16) -> String {
    let out = mcp
        .ssh_open(Parameters(ssh_open_params(port)))
        .await
        .expect("ssh_open");
    assert_eq!(
        out.0.shell_kind,
        ShellKind::Posix,
        "scenario 1: posix probe"
    );
    out.0.session_id
}

async fn run(mcp: &SshMcp, id: &str, command: &str) -> SshShellOut {
    mcp.ssh_shell(Parameters(SshShellParams {
        session_id: id.into(),
        command: command.into(),
        timeout_ms: 30000,
        max_output_bytes: 65536,
        strip_ansi: true,
    }))
    .await
    .unwrap_or_else(|e| panic!("ssh_shell({command}) failed: {e}"))
    .0
}

#[tokio::test]
async fn e2e() {
    if std::env::var("SPM_E2E").ok().as_deref() != Some("1") {
        eprintln!("skipping e2e (set SPM_E2E=1 to enable)");
        return;
    }
    if !docker_ok() {
        eprintln!("skipping e2e (docker unavailable)");
        return;
    }

    let (_container, port) = start_container();
    let manager = SessionManager::default();

    // Wait for sshd to accept connections (container takes a moment).
    let mut opened = None;
    for _ in 0..30 {
        match connect::open(params(port), &manager).await {
            Ok(o) => {
                opened = Some(o);
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(500)).await,
        }
    }
    let warmup = opened.expect("sshd never became ready");
    warmup
        .session
        .alive
        .store(false, std::sync::atomic::Ordering::SeqCst);
    warmup.session.pump.abort();

    let audit_dir = tempfile::tempdir().unwrap();
    let audit_path = audit_dir.path().join("audit.jsonl");
    let mcp = SshMcp::new(
        SessionManager::default(),
        Arc::new(AuditLog::new(audit_path.clone())),
        16,
    );
    let id = open_tool(&mcp, port).await;

    // Scenario 2: cwd persistence.
    let r = run(&mcp, &id, "cd /etc && pwd").await;
    assert_eq!(r.exit_code, Some(0));
    let r = run(&mcp, &id, "pwd").await;
    assert!(
        r.output.contains("/etc"),
        "scenario 2: cwd persists, got {:?}",
        r.output
    );

    // Scenario 3: env persistence.
    run(&mcp, &id, "export SPM_X=42").await;
    let r = run(&mcp, &id, "echo $SPM_X").await;
    assert!(
        r.output.contains("42"),
        "scenario 3: env persists, got {:?}",
        r.output
    );

    // Scenario 4: exit code.
    let r = run(&mcp, &id, "false").await;
    assert_eq!(r.exit_code, Some(1), "scenario 4: exit code propagates");

    // Scenario 4b: output is exactly the command output (no echo/scaffold).
    let r = run(&mcp, &id, "printf 'SPM_EXACT'").await;
    assert_eq!(
        r.output, "SPM_EXACT",
        "4b: byte-exact clean output, got {:?}",
        r.output
    );

    // Scenario 5: interactive prompt loop (type -> expect -> type -> expect).
    mcp.ssh_type(Parameters(SshTypeParams {
        session_id: id.clone(),
        text: "read -p 'Name? ' n; echo \"got $n\"\n".into(),
    }))
    .await
    .unwrap();
    let e = mcp
        .ssh_expect(Parameters(SshExpectParams {
            session_id: id.clone(),
            pattern: "Name\\?".into(),
            mode: "stream".into(),
            from_offset: None,
            timeout_ms: 10000,
            max_bytes: 65536,
        }))
        .await
        .unwrap()
        .0;
    assert!(e.matched, "scenario 5: prompt seen, got {:?}", e.text);
    mcp.ssh_type(Parameters(SshTypeParams {
        session_id: id.clone(),
        text: "bob\n".into(),
    }))
    .await
    .unwrap();
    let e = mcp
        .ssh_expect(Parameters(SshExpectParams {
            session_id: id.clone(),
            pattern: "got bob".into(),
            mode: "stream".into(),
            from_offset: None,
            timeout_ms: 10000,
            max_bytes: 65536,
        }))
        .await
        .unwrap()
        .0;
    assert!(e.matched, "scenario 5: answer echoed, got {:?}", e.text);

    // Scenario 6: TUI — top via screen + press.
    mcp.ssh_type(Parameters(SshTypeParams {
        session_id: id.clone(),
        text: "top\n".into(),
    }))
    .await
    .unwrap();
    let s = mcp
        .ssh_screen(Parameters(SshScreenParams {
            session_id: id.clone(),
            since_seq: None,
            wait: "quiet".into(),
            settle_ms: 1000,
            timeout_ms: 8000,
            tail_lines: None,
        }))
        .await
        .unwrap()
        .0;
    assert!(
        s.screen.to_lowercase().contains("load average"),
        "scenario 6: top on screen, got:\n{}",
        s.screen
    );
    mcp.ssh_press(Parameters(SshPressParams {
        session_id: id.clone(),
        key: "q".into(),
    }))
    .await
    .unwrap();
    let e = mcp
        .ssh_expect(Parameters(SshExpectParams {
            session_id: id.clone(),
            pattern: "\\$".into(),
            mode: "stream".into(),
            from_offset: None,
            timeout_ms: 10000,
            max_bytes: 65536,
        }))
        .await
        .unwrap()
        .0;
    assert!(
        e.matched,
        "scenario 6: back at prompt after q, got {:?}",
        e.text
    );

    // Scenario 7: SFTP roundtrip.
    let tmp = tempfile::tempdir().unwrap();
    mcp.file_write(Parameters(FileWriteParams {
        session_id: id.clone(),
        path: "/tmp/spm.txt".into(),
        content: "hello".into(),
        mode: "overwrite".into(),
    }))
    .await
    .expect("scenario 7: write new file");
    let r = mcp
        .file_read(Parameters(FileReadParams {
            session_id: id.clone(),
            path: "/tmp/spm.txt".into(),
            offset: 0,
            limit: 262144,
        }))
        .await
        .unwrap()
        .0;
    assert_eq!(r.content, "hello", "scenario 7: read back");
    let local = tmp.path().join("dl.txt");
    mcp.ssh_download(Parameters(TransferParams {
        session_id: id.clone(),
        local_path: local.to_string_lossy().into_owned(),
        remote_path: "/tmp/spm.txt".into(),
    }))
    .await
    .unwrap();
    assert_eq!(
        std::fs::read(&local).unwrap(),
        b"hello",
        "scenario 7: download"
    );
    mcp.ssh_upload(Parameters(TransferParams {
        session_id: id.clone(),
        local_path: local.to_string_lossy().into_owned(),
        remote_path: "/tmp/spm2.txt".into(),
    }))
    .await
    .expect("scenario 7: upload to new path");
    let r = mcp
        .file_read(Parameters(FileReadParams {
            session_id: id.clone(),
            path: "/tmp/spm2.txt".into(),
            offset: 0,
            limit: 262144,
        }))
        .await
        .unwrap()
        .0;
    assert_eq!(r.content, "hello", "scenario 7: upload verified");

    // Scenario 11: read-before-write guard.
    let guard_path = "/tmp/guard.txt";
    // (a) new path: write allowed without any read.
    mcp.file_write(Parameters(FileWriteParams {
        session_id: id.clone(),
        path: guard_path.into(),
        content: "hello world".into(),
        mode: "overwrite".into(),
    }))
    .await
    .expect("11a: new file write allowed");
    // (b) overwrite without read: denied.
    let err = mcp
        .file_write(Parameters(FileWriteParams {
            session_id: id.clone(),
            path: guard_path.into(),
            content: "x".into(),
            mode: "overwrite".into(),
        }))
        .await
        .err()
        .unwrap();
    assert!(
        err.message.contains("file_read"),
        "11b: denial mentions file_read, got {err}"
    );
    // (c) partial read: denied naming the missing range.
    mcp.file_read(Parameters(FileReadParams {
        session_id: id.clone(),
        path: guard_path.into(),
        offset: 0,
        limit: 5,
    }))
    .await
    .unwrap();
    let err = mcp
        .file_write(Parameters(FileWriteParams {
            session_id: id.clone(),
            path: guard_path.into(),
            content: "x".into(),
            mode: "overwrite".into(),
        }))
        .await
        .err()
        .unwrap();
    assert!(
        err.message.contains("[5, 11)"),
        "11c: missing range named, got {err}"
    );
    // (d) complete the read: overwrite succeeds.
    mcp.file_read(Parameters(FileReadParams {
        session_id: id.clone(),
        path: guard_path.into(),
        offset: 5,
        limit: 262144,
    }))
    .await
    .unwrap();
    mcp.file_write(Parameters(FileWriteParams {
        session_id: id.clone(),
        path: guard_path.into(),
        content: "updated!".into(),
        mode: "overwrite".into(),
    }))
    .await
    .expect("11d: overwrite after full read");
    // (e) append without any read on another existing file: allowed.
    mcp.file_write(Parameters(FileWriteParams {
        session_id: id.clone(),
        path: "/tmp/guard2.txt".into(),
        content: "base".into(),
        mode: "overwrite".into(),
    }))
    .await
    .unwrap();
    mcp.file_write(Parameters(FileWriteParams {
        session_id: id.clone(),
        path: "/tmp/guard2.txt".into(),
        content: "+more".into(),
        mode: "append".into(),
    }))
    .await
    .expect("11e: append allowed without read");
    // (f) external modification invalidates coverage.
    run(&mcp, &id, "echo EXT >> /tmp/guard.txt").await;
    let err = mcp
        .file_write(Parameters(FileWriteParams {
            session_id: id.clone(),
            path: guard_path.into(),
            content: "y".into(),
            mode: "overwrite".into(),
        }))
        .await
        .err()
        .unwrap();
    assert!(
        err.message.contains("file_read"),
        "11f: stale fingerprint denied, got {err}"
    );
    // (g) upload onto existing path without fresh full read: denied.
    let err = mcp
        .ssh_upload(Parameters(TransferParams {
            session_id: id.clone(),
            local_path: local.to_string_lossy().into_owned(),
            remote_path: guard_path.into(),
        }))
        .await
        .err()
        .unwrap();
    assert!(
        err.message.contains("file_read"),
        "11g: upload guard, got {err}"
    );

    // Scenario 13: ssh_expect from_offset anchors the wait to the triggering
    // action, so output that arrived BEFORE the expect call still matches.
    let typed = mcp
        .ssh_type(Parameters(SshTypeParams {
            session_id: id.clone(),
            text: "echo SPM_ANCHOR\n".into(),
        }))
        .await
        .unwrap()
        .0;
    // Wait until the output has definitively arrived (before the expect call).
    let arrived = mcp
        .ssh_screen(Parameters(SshScreenParams {
            session_id: id.clone(),
            since_seq: Some(typed.seq),
            wait: "change".into(),
            settle_ms: 250,
            timeout_ms: 5000,
            tail_lines: None,
        }))
        .await
        .unwrap()
        .0;
    assert!(!arrived.timed_out, "13: output arrived");
    let e = mcp
        .ssh_expect(Parameters(SshExpectParams {
            session_id: id.clone(),
            pattern: "SPM_ANCHOR".into(),
            mode: "stream".into(),
            from_offset: Some(typed.stream_offset),
            timeout_ms: 5000,
            max_bytes: 65536,
        }))
        .await
        .unwrap()
        .0;
    assert!(e.matched, "13: from_offset catches pre-arrived output");

    // Scenario 14: append creates a missing file; missing parent dir is named.
    mcp.file_write(Parameters(FileWriteParams {
        session_id: id.clone(),
        path: "/tmp/append_new.txt".into(),
        content: "created-by-append".into(),
        mode: "append".into(),
    }))
    .await
    .expect("14: append creates missing file");
    let r = mcp
        .file_read(Parameters(FileReadParams {
            session_id: id.clone(),
            path: "/tmp/append_new.txt".into(),
            offset: 0,
            limit: 262144,
        }))
        .await
        .unwrap()
        .0;
    assert_eq!(r.content, "created-by-append", "14: append content");
    let err = mcp
        .file_write(Parameters(FileWriteParams {
            session_id: id.clone(),
            path: "/tmp/no_such_dir_xyz/f.txt".into(),
            content: "x".into(),
            mode: "overwrite".into(),
        }))
        .await
        .err()
        .unwrap();
    assert!(
        err.message.contains("parent directory does not exist"),
        "14: parent dir named, got {err}"
    );

    // Scenario 15: ssh_press("up") recalls the previous command in readline.
    run(&mcp, &id, "echo SPM_HISTORY_MARK").await;
    let pressed = mcp
        .ssh_press(Parameters(SshPressParams {
            session_id: id.clone(),
            key: "up".into(),
        }))
        .await
        .unwrap()
        .0;
    let s = mcp
        .ssh_screen(Parameters(SshScreenParams {
            session_id: id.clone(),
            since_seq: Some(pressed.seq),
            wait: "quiet".into(),
            settle_ms: 500,
            timeout_ms: 5000,
            tail_lines: None,
        }))
        .await
        .unwrap()
        .0;
    assert!(
        s.screen.contains("echo SPM_HISTORY_MARK"),
        "15: up recalls last command, got:\n{}",
        s.screen
    );
    mcp.ssh_press(Parameters(SshPressParams {
        session_id: id.clone(),
        key: "ctrl+c".into(),
    }))
    .await
    .unwrap(); // discard the recalled line

    // Scenario 12: heredoc and multi-line commands survive ssh_shell (newline-joined sentinel).
    let r = run(&mcp, &id, "cat << EOF\nhello spm\nEOF").await;
    assert_eq!(r.exit_code, Some(0), "12: heredoc exit code, got {:?}", r);
    assert!(
        r.output.contains("hello spm"),
        "12: heredoc output, got {:?}",
        r.output
    );
    let r = run(&mcp, &id, "cd /tmp\npwd").await;
    assert!(
        r.output.contains("/tmp"),
        "12: multi-line output, got {:?}",
        r.output
    );
    let r = run(&mcp, &id, "pwd").await;
    assert!(
        r.output.contains("/tmp"),
        "12: cwd still persists after multi-line, got {:?}",
        r.output
    );
    let r = run(&mcp, &id, "cd /\nfalse").await;
    assert_eq!(
        r.exit_code,
        Some(1),
        "12: exit code of last line, got {:?}",
        r
    );

    // Scenario 17: ssh_exec — stateless, isolated from the persistent shell.
    let x = mcp
        .ssh_exec(Parameters(SshExecParams {
            session_id: id.clone(),
            command: "pwd".into(),
            timeout_ms: 10000,
            max_output_bytes: 65536,
            strip_ansi: true,
        }))
        .await
        .unwrap()
        .0;
    assert_eq!(
        x.stdout.trim(),
        "/home/test",
        "17: exec is stateless (shell cwd is /), got {:?}",
        x.stdout
    );
    let x = mcp
        .ssh_exec(Parameters(SshExecParams {
            session_id: id.clone(),
            command: "echo OUT; echo ERR >&2; exit 3".into(),
            timeout_ms: 10000,
            max_output_bytes: 65536,
            strip_ansi: true,
        }))
        .await
        .unwrap()
        .0;
    assert!(x.stdout.contains("OUT"), "17: stdout, got {:?}", x.stdout);
    assert!(
        x.stderr.contains("ERR"),
        "17: stderr separated, got {:?}",
        x.stderr
    );
    assert_eq!(
        x.exit_code,
        Some(3),
        "17: protocol exit status, full={:?}",
        (x.exit_code, x.timed_out, x.stdout.len(), x.stderr.len())
    );

    // Scenario 18: ssh_ready — true at prompt, false while a command runs.
    let r = mcp
        .ssh_ready(Parameters(SshReadyParams {
            session_id: id.clone(),
            probe_timeout_ms: 2000,
        }))
        .await
        .unwrap()
        .0;
    assert!(r.ready, "18: ready at prompt");
    mcp.ssh_type(Parameters(SshTypeParams {
        session_id: id.clone(),
        text: "sleep 2\n".into(),
    }))
    .await
    .unwrap();
    let r = mcp
        .ssh_ready(Parameters(SshReadyParams {
            session_id: id.clone(),
            probe_timeout_ms: 400,
        }))
        .await
        .unwrap()
        .0;
    assert!(!r.ready, "18: not ready during sleep");
    tokio::time::sleep(Duration::from_millis(2200)).await;
    let r = mcp
        .ssh_ready(Parameters(SshReadyParams {
            session_id: id.clone(),
            probe_timeout_ms: 2000,
        }))
        .await
        .unwrap()
        .0;
    assert!(r.ready, "18: ready again after sleep");

    // Scenario 19: ssh_screen tail_lines.
    let s = mcp
        .ssh_screen(Parameters(SshScreenParams {
            session_id: id.clone(),
            since_seq: None,
            wait: "none".into(),
            settle_ms: 250,
            timeout_ms: 5000,
            tail_lines: Some(1),
        }))
        .await
        .unwrap()
        .0;
    assert_eq!(
        s.screen.lines().count(),
        1,
        "19: exactly one line, got {:?}",
        s.screen
    );

    // Scenario 20: session naming.
    let mut named = ssh_open_params(port);
    named.name = Some("web1".into());
    let n1 = mcp
        .ssh_open(Parameters(named.clone()))
        .await
        .expect("20: named open");
    assert_eq!(n1.0.name.as_deref(), Some("web1"));
    let list = mcp.ssh_list().await.unwrap().0;
    assert!(
        list.sessions
            .iter()
            .any(|s| s.name.as_deref() == Some("web1")),
        "20: name in list"
    );
    let r = run(&mcp, "web1", "echo VIA_NAME").await;
    assert!(
        r.output.contains("VIA_NAME"),
        "20: run by alias, got {:?}",
        r.output
    );
    let err = mcp.ssh_open(Parameters(named)).await.err().unwrap();
    assert!(
        err.message.contains("already in use"),
        "20: duplicate name rejected, got {err}"
    );
    mcp.ssh_close(Parameters(SessionParams {
        session_id: "web1".into(),
    }))
    .await
    .expect("20: close by alias");

    // Scenario 21: async task.
    let a = mcp
        .ssh_shell_async(Parameters(SshShellAsyncParams {
            session_id: id.clone(),
            command: "sleep 2 && echo ASYNC_DONE".into(),
            timeout_ms: 30000,
            max_output_bytes: 65536,
            strip_ansi: true,
        }))
        .await
        .unwrap()
        .0;
    let st = mcp
        .ssh_task_status(Parameters(SshTaskStatusParams {
            task_id: a.task_id.clone(),
            wait_ms: 0,
        }))
        .await
        .unwrap()
        .0;
    assert_eq!(st.status, "running", "21: immediately running");
    let st = mcp
        .ssh_task_status(Parameters(SshTaskStatusParams {
            task_id: a.task_id.clone(),
            wait_ms: 8000,
        }))
        .await
        .unwrap()
        .0;
    assert_eq!(st.status, "done", "21: completes, got {st:?}");
    assert!(
        st.output.unwrap_or_default().contains("ASYNC_DONE"),
        "21: output captured"
    );
    assert_eq!(st.exit_code, Some(0));

    // Scenario 22: file_edit with read-before-write guard.
    mcp.file_write(Parameters(FileWriteParams {
        session_id: id.clone(),
        path: "/tmp/edit.txt".into(),
        content: "line1\nline2 TARGET\nline3\n".into(),
        mode: "overwrite".into(),
    }))
    .await
    .expect("22: seed file");
    let denied = mcp
        .file_edit(Parameters(FileEditParams {
            session_id: id.clone(),
            path: "/tmp/edit.txt".into(),
            old_string: "TARGET".into(),
            new_string: "HIT".into(),
            replace_all: false,
        }))
        .await
        .err()
        .unwrap();
    assert!(
        denied.message.contains("prior file_read"),
        "22: unread edit denied, got {denied}"
    );
    mcp.file_read(Parameters(FileReadParams {
        session_id: id.clone(),
        path: "/tmp/edit.txt".into(),
        offset: 0,
        limit: 262144,
    }))
    .await
    .unwrap();
    let e = mcp
        .file_edit(Parameters(FileEditParams {
            session_id: id.clone(),
            path: "/tmp/edit.txt".into(),
            old_string: "TARGET".into(),
            new_string: "HIT".into(),
            replace_all: false,
        }))
        .await
        .expect("22: edit after read")
        .0;
    assert_eq!(e.replacements, 1);
    assert!(
        e.context.contains("HIT"),
        "22: context shows replacement, got {:?}",
        e.context
    );
    let err = mcp
        .file_edit(Parameters(FileEditParams {
            session_id: id.clone(),
            path: "/tmp/edit.txt".into(),
            old_string: "MISSING".into(),
            new_string: "x".into(),
            replace_all: false,
        }))
        .await
        .err()
        .unwrap();
    assert!(
        err.message.contains("not found"),
        "22: absent old_string, got {err}"
    );
    // Multi-match: append duplicates, re-read, then replace_all.
    mcp.file_write(Parameters(FileWriteParams {
        session_id: id.clone(),
        path: "/tmp/edit.txt".into(),
        content: "same\nsame\n".into(),
        mode: "append".into(),
    }))
    .await
    .unwrap();
    let err = mcp
        .file_edit(Parameters(FileEditParams {
            session_id: id.clone(),
            path: "/tmp/edit.txt".into(),
            old_string: "same".into(),
            new_string: "diff".into(),
            replace_all: false,
        }))
        .await
        .err()
        .unwrap();
    assert!(
        err.message.contains("matches 2 times"),
        "22: multi-match rejected, got {err}"
    );
    mcp.file_read(Parameters(FileReadParams {
        session_id: id.clone(),
        path: "/tmp/edit.txt".into(),
        offset: 0,
        limit: 262144,
    }))
    .await
    .unwrap();
    let e = mcp
        .file_edit(Parameters(FileEditParams {
            session_id: id.clone(),
            path: "/tmp/edit.txt".into(),
            old_string: "same".into(),
            new_string: "diff".into(),
            replace_all: true,
        }))
        .await
        .expect("22: replace_all after full read")
        .0;
    assert_eq!(e.replacements, 2);

    // Scenario 23: dead sessions are pruned (alias + limit slot released).
    let mut mortal = ssh_open_params(port);
    mortal.name = Some("mortal".into());
    let m = mcp
        .ssh_open(Parameters(mortal.clone()))
        .await
        .expect("23: open mortal");
    let mid = m.0.session_id;
    // Kill the shell; ssh_shell will time out, but the pump marks the session dead.
    let _ = mcp
        .ssh_shell(Parameters(SshShellParams {
            session_id: mid.clone(),
            command: "exit 99".into(),
            timeout_ms: 3000,
            max_output_bytes: 65536,
            strip_ansi: true,
        }))
        .await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let list = mcp.ssh_list().await.unwrap().0;
    assert!(
        !list.sessions.iter().any(|s| s.session_id == mid),
        "23: dead session pruned from list"
    );
    mcp.ssh_open(Parameters(mortal))
        .await
        .expect("23: alias reusable after death");

    // Scenario 24: ssh_task_cancel interrupts without killing the session.
    let a = mcp
        .ssh_shell_async(Parameters(SshShellAsyncParams {
            session_id: id.clone(),
            command: "sleep 30 && echo NEVER".into(),
            timeout_ms: 60000,
            max_output_bytes: 65536,
            strip_ansi: true,
        }))
        .await
        .unwrap()
        .0;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let c = mcp
        .ssh_task_cancel(Parameters(SshTaskCancelParams {
            task_id: a.task_id.clone(),
        }))
        .await
        .unwrap()
        .0;
    assert!(c.cancelled, "24: cancel accepted");
    let st = mcp
        .ssh_task_status(Parameters(SshTaskStatusParams {
            task_id: a.task_id.clone(),
            wait_ms: 0,
        }))
        .await
        .unwrap()
        .0;
    assert_eq!(st.status, "error", "24: task marked cancelled, got {st:?}");
    let r = run(&mcp, &id, "echo ALIVE").await;
    assert!(
        r.output.contains("ALIVE"),
        "24: session survives cancel, got {:?}",
        r.output
    );

    // Scenario 25: ssh_copy — same-session and cross-session paths.
    mcp.file_write(Parameters(FileWriteParams {
        session_id: id.clone(),
        path: "/tmp/copy_src.txt".into(),
        content: "copy-payload".into(),
        mode: "overwrite".into(),
    }))
    .await
    .expect("25: seed");
    mcp.ssh_copy(Parameters(SshCopyParams {
        from_session: id.clone(),
        from_path: "/tmp/copy_src.txt".into(),
        to_session: id.clone(),
        to_path: "/tmp/copy_dst.txt".into(),
    }))
    .await
    .expect("25: same-session copy");
    let r = mcp
        .file_read(Parameters(FileReadParams {
            session_id: id.clone(),
            path: "/tmp/copy_dst.txt".into(),
            offset: 0,
            limit: 262144,
        }))
        .await
        .unwrap()
        .0;
    assert_eq!(r.content, "copy-payload", "25: same-session content");
    let s2 = open_tool(&mcp, port).await;
    mcp.ssh_copy(Parameters(SshCopyParams {
        from_session: id.clone(),
        from_path: "/tmp/copy_src.txt".into(),
        to_session: s2.clone(),
        to_path: "/tmp/copy_x.txt".into(),
    }))
    .await
    .expect("25: cross-session copy");
    let r = mcp
        .file_read(Parameters(FileReadParams {
            session_id: s2.clone(),
            path: "/tmp/copy_x.txt".into(),
            offset: 0,
            limit: 262144,
        }))
        .await
        .unwrap()
        .0;
    assert_eq!(r.content, "copy-payload", "25: cross-session content");
    mcp.ssh_close(Parameters(sid(&s2))).await.unwrap();

    // Scenario 26: ssh_exec handles heredoc natively (no readline involved).
    let x = mcp
        .ssh_exec(Parameters(SshExecParams {
            session_id: id.clone(),
            command: "cat << EOF\nhi spm\nEOF".into(),
            timeout_ms: 10000,
            max_output_bytes: 65536,
            strip_ansi: true,
        }))
        .await
        .unwrap()
        .0;
    assert!(
        x.stdout.contains("hi spm"),
        "26: exec heredoc, got {:?}",
        x.stdout
    );
    assert_eq!(x.exit_code, Some(0));

    // Scenario 27: ssh_copy self-copy is refused without data loss.
    mcp.file_write(Parameters(FileWriteParams {
        session_id: id.clone(),
        path: "/tmp/important.txt".into(),
        content: "important data".into(),
        mode: "overwrite".into(),
    }))
    .await
    .expect("27: seed");
    let err = mcp
        .ssh_copy(Parameters(SshCopyParams {
            from_session: id.clone(),
            from_path: "/tmp/important.txt".into(),
            to_session: id.clone(),
            to_path: "/tmp/important.txt".into(),
        }))
        .await
        .err()
        .unwrap();
    assert!(
        err.message.contains("same file"),
        "27: self-copy refused, got {err}"
    );
    let r = mcp
        .file_read(Parameters(FileReadParams {
            session_id: id.clone(),
            path: "/tmp/important.txt".into(),
            offset: 0,
            limit: 262144,
        }))
        .await
        .unwrap()
        .0;
    assert_eq!(r.content, "important data", "27: source intact");

    // Scenario 28: directory destinations get a clear error.
    let err = mcp
        .ssh_upload(Parameters(TransferParams {
            session_id: id.clone(),
            local_path: local.to_string_lossy().into_owned(),
            remote_path: "/tmp/".into(),
        }))
        .await
        .err()
        .unwrap();
    assert!(
        err.message.contains("directory"),
        "28: directory named, got {err}"
    );

    // Scenario 29: ssh_screen filters scaffolding from the presentation.
    run(&mcp, &id, "echo CLEAN_SCREEN").await;
    let s = mcp
        .ssh_screen(Parameters(SshScreenParams {
            session_id: id.clone(),
            since_seq: None,
            wait: "none".into(),
            settle_ms: 250,
            timeout_ms: 5000,
            tail_lines: None,
        }))
        .await
        .unwrap()
        .0;
    assert!(
        !s.screen.contains("__SPM_"),
        "29: no marker lines, got:\n{}",
        s.screen
    );
    assert!(
        !s.screen.contains("stty -echo"),
        "29: no stty lines, got:\n{}",
        s.screen
    );
    assert!(s.screen.contains("CLEAN_SCREEN"), "29: real output kept");

    // Scenario 30: hardlink self-copy is refused via dev:inode comparison.
    run(
        &mcp,
        &id,
        "echo data > /tmp/hl_a.txt && ln /tmp/hl_a.txt /tmp/hl_b.txt",
    )
    .await;
    let err = mcp
        .ssh_copy(Parameters(SshCopyParams {
            from_session: id.clone(),
            from_path: "/tmp/hl_a.txt".into(),
            to_session: id.clone(),
            to_path: "/tmp/hl_b.txt".into(),
        }))
        .await
        .err()
        .unwrap();
    assert!(
        err.message.contains("same file"),
        "30: hardlink refused, got {err}"
    );
    let r = mcp
        .file_read(Parameters(FileReadParams {
            session_id: id.clone(),
            path: "/tmp/hl_a.txt".into(),
            offset: 0,
            limit: 262144,
        }))
        .await
        .unwrap()
        .0;
    assert_eq!(r.content.trim(), "data", "30: source intact");

    // Scenario 31: ssh_exec timeout leaks the remote process; pkill cleans it.
    let x = mcp
        .ssh_exec(Parameters(SshExecParams {
            session_id: id.clone(),
            command: "sleep 30".into(),
            timeout_ms: 1500,
            max_output_bytes: 65536,
            strip_ansi: true,
        }))
        .await
        .unwrap()
        .0;
    assert!(x.timed_out, "31: exec times out");
    let check = mcp
        .ssh_exec(Parameters(SshExecParams {
            session_id: id.clone(),
            command: "ps aux | grep '[s]leep 30' | wc -l".into(),
            timeout_ms: 10000,
            max_output_bytes: 65536,
            strip_ansi: true,
        }))
        .await
        .unwrap()
        .0;
    assert!(
        check.stdout.trim().parse::<u32>().unwrap_or(0) >= 1,
        "31: leak visible, got {:?}",
        check.stdout
    );
    let clean = mcp
        .ssh_exec(Parameters(SshExecParams {
            session_id: id.clone(),
            command: "pkill -f 'sleep 30'".into(),
            timeout_ms: 10000,
            max_output_bytes: 65536,
            strip_ansi: true,
        }))
        .await
        .unwrap()
        .0;
    assert!(clean.exit_code == Some(0), "31: documented cleanup works");

    // Scenario 16: session limit is enforced.
    let limited = SshMcp::new(
        SessionManager::default(),
        Arc::new(AuditLog::new(audit_dir.path().join("audit2.jsonl"))),
        1,
    );
    let first = limited
        .ssh_open(Parameters(ssh_open_params(port)))
        .await
        .expect("16: first session under limit");
    let err = limited
        .ssh_open(Parameters(ssh_open_params(port)))
        .await
        .err()
        .unwrap();
    assert!(
        err.message.contains("session limit reached"),
        "16: limit error, got {err}"
    );
    limited
        .ssh_close(Parameters(SessionParams {
            session_id: first.0.session_id,
        }))
        .await
        .unwrap();
    limited
        .ssh_open(Parameters(ssh_open_params(port)))
        .await
        .expect("16: open succeeds again after close");

    // Scenario 10: audit log — records commands, never the password.
    mcp.ssh_close(Parameters(sid(&id))).await.unwrap();
    let log = std::fs::read_to_string(&audit_path).unwrap();
    assert!(
        log.contains("\"tool\":\"ssh_shell\""),
        "10: ssh_shell logged"
    );
    assert!(log.contains("cd /etc && pwd"), "10: command text logged");
    assert!(!log.contains("testpass"), "10: password never logged");

    // Scenario 8: closed session rejects further calls.
    let err = run_result(&mcp, &id, "pwd").await.err().unwrap();
    assert!(
        err.message.contains("unknown session"),
        "8: closed session errors, got {err}"
    );

    // Scenario 9: agent auth (self-skips without a reachable agent).
    if connect::connect_agent().await.is_some() {
        agent_auth_scenario(port, &_container.id).await;
    } else {
        eprintln!("scenario 9: no SSH agent reachable, skipping");
    }
}

async fn run_result(mcp: &SshMcp, id: &str, command: &str) -> Result<SshShellOut, rmcp::ErrorData> {
    mcp.ssh_shell(Parameters(SshShellParams {
        session_id: id.into(),
        command: command.into(),
        timeout_ms: 30000,
        max_output_bytes: 65536,
        strip_ansi: true,
    }))
    .await
    .map(|j| j.0)
}

async fn agent_auth_scenario(port: u16, container_id: &str) {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("id_ed25519");
    let keygen_out = Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-f"])
        .arg(&key)
        .output()
        .expect("ssh-keygen");
    assert!(
        keygen_out.status.success(),
        "ssh-keygen: {}",
        String::from_utf8_lossy(&keygen_out.stderr)
    );
    let add = Command::new("ssh-add").arg(&key).output().expect("ssh-add");
    if !add.status.success() {
        eprintln!(
            "scenario 9: ssh-add failed ({}), skipping",
            String::from_utf8_lossy(&add.stderr)
        );
        return;
    }
    struct RemoveKey(std::path::PathBuf);
    impl Drop for RemoveKey {
        fn drop(&mut self) {
            let _ = Command::new("ssh-add").arg("-d").arg(&self.0).status();
        }
    }
    let _guard = RemoveKey(key.clone());

    let pubkey = std::fs::read_to_string(key.with_extension("pub")).unwrap();
    let mut child = Command::new("docker")
        .args([
            "exec",
            "-i",
            container_id,
            "sh",
            "-c",
            "mkdir -p /home/test/.ssh && cat >> /home/test/.ssh/authorized_keys \
             && chmod 700 /home/test/.ssh && chmod 600 /home/test/.ssh/authorized_keys \
             && chown -R test:test /home/test/.ssh",
        ])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .expect("docker exec");
    use std::io::Write as _;
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(pubkey.as_bytes())
        .unwrap();
    assert!(child.wait().unwrap().success());

    let manager = SessionManager::default();
    let mut p = params(port);
    p.password = None;
    p.use_agent = true;
    let opened = connect::open(p, &manager)
        .await
        .expect("agent auth should succeed");
    assert_eq!(
        opened.auth_method, "agent",
        "scenario 9: authenticated via agent"
    );
    opened
        .session
        .alive
        .store(false, std::sync::atomic::Ordering::SeqCst);
    opened.session.pump.abort();
}
