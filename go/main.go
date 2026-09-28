// MCP server giving AI agents fluent SSH: persistent PTY sessions, virtual
// keyboard, screen model, SFTP.
package main

import (
	"context"
	"flag"
	"log"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	logLevel := flag.String("log-level", "warn", "log filter (warn|info|debug); logs go to stderr only")
	auditLog := flag.String("audit-log", "", "audit log path (JSONL); default ~/.ssh-pty-mcp/audit.jsonl")
	maxSessions := flag.Int("max-sessions", 16, "maximum concurrent SSH sessions")
	flag.Parse()

	_ = logLevel // Go's log package writes to stderr; the flag is kept for CLI parity.

	path := *auditLog
	if path == "" {
		path = DefaultAuditPath()
	}
	audit := NewAuditLog(path)

	srv := NewServer(&SessionManager{}, audit, *maxSessions)
	s := mcp.NewServer(&mcp.Implementation{
		Name:    "ssh-pty-mcp",
		Version: "0.4.3",
	}, nil)
	RegisterTools(s, srv)

	if err := s.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatalf("failed to start MCP server: %v", err)
	}
}
