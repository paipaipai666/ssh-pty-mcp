//! Shared E2E harness: docker container lifecycle + tool params.

use std::process::Command;

use ssh_pty_mcp::tools::SshOpenParams;

pub struct Container {
    pub id: String,
}

impl Drop for Container {
    fn drop(&mut self) {
        let _ = Command::new("docker").args(["rm", "-f", &self.id]).status();
    }
}

pub fn docker_ok() -> bool {
    Command::new("docker")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

pub fn run_docker(args: &[&str]) -> String {
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

pub fn start_container() -> (Container, u16) {
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

pub fn ssh_open_params(port: u16) -> SshOpenParams {
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
