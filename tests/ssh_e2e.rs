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

struct Container {
    id: String,
}

impl Drop for Container {
    fn drop(&mut self) {
        let _ = Command::new("docker").args(["rm", "-f", &self.id]).status();
    }
}

fn docker_ok() -> bool {
    Command::new("docker")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn run_docker(args: &[&str]) -> String {
    let out = Command::new("docker")
        .args(args)
        .output()
        .expect("spawn docker");
    assert!(
        out.status.success(),
        "docker {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

fn start_container() -> (Container, u16) {
    // Build best-effort: Docker Hub may be unreachable; a cached image is fine.
    let built = Command::new("docker")
        .args(["build", "-q", "-t", "spm-e2e", "tests/docker"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !built {
        let inspect = Command::new("docker")
            .args(["image", "inspect", "spm-e2e"])
            .output()
            .unwrap();
        assert!(
            inspect.status.success(),
            "docker build failed and no cached spm-e2e image"
        );
        eprintln!("docker build failed; using cached spm-e2e image");
    }
    let id = run_docker(&["run", "-d", "--rm", "-P", "spm-e2e"]);
    let port_line = run_docker(&["port", &id, "22/tcp"]);
    let port: u16 = port_line.rsplit(':').next().unwrap().parse().unwrap();
    (Container { id }, port)
}

fn params(port: u16) -> ConnectParams {
    ConnectParams {
        host: "127.0.0.1".into(),
        port,
        user: "test".into(),
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

fn ssh_open_params(port: u16) -> SshOpenParams {
    SshOpenParams {
        host: "127.0.0.1".into(),
        port: Some(port),
        user: Some("test".into()),
        password: Some("testpass".into()),
        private_key: None,
        passphrase: None,
        use_agent: false,
        use_ssh_config: false,
        host_key_policy: "off".into(),
        cols: 120,
        rows: 32,
        connect_timeout_ms: 5000,
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

async fn run(mcp: &SshMcp, id: &str, command: &str) -> SshRunOut {
    mcp.ssh_run(Parameters(SshRunParams {
        session_id: id.into(),
        command: command.into(),
        timeout_ms: 30000,
        max_output_bytes: 65536,
    }))
    .await
    .unwrap_or_else(|e| panic!("ssh_run({command}) failed: {e}"))
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

    // Scenario 12: heredoc and multi-line commands survive ssh_run (newline-joined sentinel).
    let r = run(&mcp, &id, "cat << EOF\nhello spm\nEOF").await;
    assert_eq!(r.exit_code, Some(0), "12: heredoc exit code, got {:?}", r);
    assert!(r.output.contains("hello spm"), "12: heredoc output, got {:?}", r.output);
    let r = run(&mcp, &id, "cd /tmp\npwd").await;
    assert!(r.output.contains("/tmp"), "12: multi-line output, got {:?}", r.output);
    let r = run(&mcp, &id, "pwd").await;
    assert!(r.output.contains("/tmp"), "12: cwd still persists after multi-line, got {:?}", r.output);
    let r = run(&mcp, &id, "cd /\nfalse").await;
    assert_eq!(r.exit_code, Some(1), "12: exit code of last line, got {:?}", r);

    // Scenario 10: audit log — records commands, never the password.
    mcp.ssh_close(Parameters(sid(&id))).await.unwrap();
    let log = std::fs::read_to_string(&audit_path).unwrap();
    assert!(log.contains("\"tool\":\"ssh_run\""), "10: ssh_run logged");
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

async fn run_result(mcp: &SshMcp, id: &str, command: &str) -> Result<SshRunOut, rmcp::ErrorData> {
    mcp.ssh_run(Parameters(SshRunParams {
        session_id: id.into(),
        command: command.into(),
        timeout_ms: 30000,
        max_output_bytes: 65536,
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
