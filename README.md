# ssh-pty-mcp

[![CI](https://github.com/paipaipai666/ssh-pty-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/paipaipai666/ssh-pty-mcp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

MCP server that gives AI agents **fluent SSH**: persistent PTY shell sessions
(`cd` / `export` / aliases survive across calls), a virtual keyboard for TUI
programs (top/htop/less/menus), a server-side rendered terminal screen model
with change/quiet wait semantics, expect-style pattern waits, and SFTP file
operations guarded by a read-before-write rule.

## Install

```sh
# from source
cargo install --path .
# or once published
cargo install ssh-pty-mcp
```

## MCP client config

```json
{
  "mcpServers": {
    "ssh-pty-mcp": {
      "command": "ssh-pty-mcp"
    }
  }
}
```

## Tools

| Tool | Purpose |
|---|---|
| `ssh_open` / `ssh_close` / `ssh_list` | Session lifecycle (key / SSH-agent / password auth, `~/.ssh/config` resolution, known_hosts accept-new, optional session alias) |
| `ssh_shell` | Run a command in the persistent shell; returns clean output + exit code |
| `ssh_shell_async` / `ssh_task_status` / `ssh_task_cancel` | Background a persistent-shell command; poll or cancel it |
| `ssh_exec` | One-shot stateless exec channel (protocol exit status, split stdout/stderr, isolated from the shell; safest path for multi-line/heredoc) |
| `ssh_ready` | Probe whether the shell is at a prompt |
| `ssh_type` / `ssh_press` / `ssh_signal` | Type text, press named keys (`ctrl+c`, `f5`, `up`...), send signals |
| `ssh_expect` / `ssh_screen` | Wait for a regex on stream/screen; read the rendered screen (full or `tail_lines`) |
| `file_read` / `file_write` / `file_edit` / `ssh_upload` / `ssh_download` / `ssh_copy` | SFTP file ops. `file_write(overwrite)`, overwrites via `ssh_upload`/`ssh_copy`, and `file_edit` require prior read coverage — enforced |

## Audit log

Every command the agent runs is appended to `~/.ssh-pty-mcp/audit.jsonl`
(override with `--audit-log <path>`). Typed text is redacted; passwords are
never logged.

## Named servers & ProxyJump

`~/.ssh-pty-mcp/servers.toml` (override with `SSH_PTY_MCP_SERVERS`):

```toml
[servers.prod]
host = "203.0.113.10"
port = 22
user = "deploy"
private_key = "~/.ssh/id_ed25519"   # or password = "..." (chmod 600!)
proxy_jump = "bastion"               # alias, or user@host[:port]
mode = "readonly"                    # unrestricted|readonly|restricted
allow = ["^df", "^ps"]               # allowlist regexes for restricted

[servers.bastion]
host = "198.51.100.5"
user = "jump"
```

Then: `ssh_open(server="prod")`. Merge order: explicit params > servers.toml >
~/.ssh/config (including its `ProxyJump`). `ssh_list_servers` shows all
configured servers (no secrets).

## Security modes

Per session, at `ssh_open`:

- `unrestricted` (default): everything allowed.
- `readonly`: mutating tools (`file_write`/`file_edit`/`ssh_upload`/`ssh_copy`)
  blocked; commands matching the built-in dangerous list (`rm`, `dd`, `mkfs`,
  `shutdown`, `systemctl`, `kill`, `chmod`...) refused in `ssh_shell`/`ssh_exec`.
- `restricted`: commands must match at least one `allow` regex.

## Windows targets

`ssh_shell` is POSIX-only (its sentinel pipeline depends on sh semantics).
Sessions probing as `cmd`/`powershell` get a precise error pointing to
`ssh_exec` — which works on Windows targets today (runs via `cmd /c`,
no readline involved): multi-line commands, clean output, protocol exit code.

## Local sandbox + WAN simulation

A disposable SSH target for agent testing (no real VPS needed):

```sh
docker build -t spm-e2e tests/docker
printf 'FROM spm-e2e\nRUN apk add --no-cache iproute2\n' | docker build -t spm-sandbox -f - .
docker run -d --name ssh-sandbox --cap-add NET_ADMIN -p 2222:22 spm-sandbox
# connect: 127.0.0.1:2222, user test, password testpass
```

Simulate real-world network conditions with `tc netem` (kernel-level,
transparent to SSH):

```sh
# 150ms base ± 40ms jitter (normal distribution)
docker exec ssh-sandbox tc qdisc add dev eth0 root netem delay 150ms 40ms distribution normal
# add 2% packet loss
docker exec ssh-sandbox tc qdisc change dev eth0 root netem delay 150ms 40ms loss 2%
# back to LAN
docker exec ssh-sandbox tc qdisc del dev eth0 root
```
