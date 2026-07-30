use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use rmcp::{ServiceExt, transport::stdio};
use tracing_subscriber::EnvFilter;

use ssh_pty_mcp::audit::AuditLog;
use ssh_pty_mcp::session::SessionManager;
use ssh_pty_mcp::tools::SshMcp;

/// MCP server giving AI agents fluent SSH: persistent PTY sessions, virtual
/// keyboard, screen model, SFTP.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// Log filter (tracing env-filter syntax). Logs go to stderr only.
    #[arg(long, default_value = "warn")]
    log_level: String,
    /// Audit log path (JSONL). Default: ~/.ssh-pty-mcp/audit.jsonl
    #[arg(long)]
    audit_log: Option<PathBuf>,
    /// Maximum concurrent SSH sessions.
    #[arg(long, default_value = "16")]
    max_sessions: usize,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(EnvFilter::new(&cli.log_level))
        .with_ansi(false)
        .init();

    let audit = Arc::new(AuditLog::new(
        cli.audit_log.unwrap_or_else(AuditLog::default_path),
    ));
    let server = SshMcp::new(SessionManager::default(), audit, cli.max_sessions);
    let service = server
        .serve(stdio())
        .await
        .context("failed to start MCP server")?;
    service.waiting().await?;
    Ok(())
}
