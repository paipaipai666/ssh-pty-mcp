# ssh-pty-mcp

MCP server that gives AI agents **fluent SSH**: persistent PTY shell sessions
(`cd` / `export` / aliases survive across calls), a virtual keyboard for TUI
programs (top/htop/less/menus), a server-side rendered terminal screen model
with change/quiet wait semantics, expect-style pattern waits, and SFTP file
operations guarded by a read-before-write rule.

## Install

```sh
cargo install --path .
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
| `ssh_open` / `ssh_close` / `ssh_list` | Session lifecycle (key / SSH-agent / password auth, `~/.ssh/config` resolution, known_hosts accept-new) |
| `ssh_run` | Run a command in the persistent shell; returns clean output + exit code |
| `ssh_type` / `ssh_press` / `ssh_signal` | Type text, press named keys (`ctrl+c`, `f5`, `up`...), send signals |
| `ssh_expect` / `ssh_screen` | Wait for a regex on stream/screen; read the rendered screen |
| `file_read` / `file_write` / `ssh_upload` / `ssh_download` | SFTP file ops. `file_write(overwrite)` and overwrites via `ssh_upload` require a prior full `file_read` — enforced |

## Audit log

Every command the agent runs is appended to `~/.ssh-pty-mcp/audit.jsonl`
(override with `--audit-log <path>`). Typed text is redacted; passwords are
never logged.

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
