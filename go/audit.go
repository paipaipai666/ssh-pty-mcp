// Append-only JSONL audit log: the durable record of every action the
// agent takes. Write failures warn but never fail the tool call.
package main

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"time"
)

// AuditLog appends one JSON object per line.
type AuditLog struct {
	path string
}

// NewAuditLog returns an AuditLog writing to path.
func NewAuditLog(path string) *AuditLog { return &AuditLog{path: path} }

// DefaultAuditPath is ~/.ssh-pty-mcp/audit.jsonl.
func DefaultAuditPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "~"
	}
	return filepath.Join(home, ".ssh-pty-mcp", "audit.jsonl")
}

// Path returns the log file path.
func (a *AuditLog) Path() string { return a.path }

// Log appends one record. Never fails the caller.
func (a *AuditLog) Log(sessionID, tool string, data map[string]any) {
	rec := map[string]any{
		"ts":         time.Now().UTC().Format(time.RFC3339),
		"session_id": sessionID,
		"tool":       tool,
		"data":       data,
	}
	if dir := filepath.Dir(a.path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			log.Printf("audit mkdir failed: %v", err)
			return
		}
	}
	f, err := os.OpenFile(a.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		log.Printf("audit open failed: %v", err)
		return
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false) // keep && and < literal, like serde_json
	if err := enc.Encode(rec); err != nil {
		log.Printf("audit write failed: %v", err)
	}
}
