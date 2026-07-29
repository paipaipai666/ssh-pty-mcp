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
