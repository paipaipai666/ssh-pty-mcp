// End-to-end smoke against an in-process SSH server (password auth + exec
// channel). The PTY shell path needs a real sshd; the Rust e2e used docker.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestExecAgainstInProcessSSHServer(t *testing.T) {
	// Host key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == "u" && string(pass) == "pw" {
				return nil, nil
			}
			return nil, fmt.Errorf("denied")
		},
	}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				_, chans, reqs, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					c.Close()
					return
				}
				go ssh.DiscardRequests(reqs)
				for ch := range chans {
					if ch.ChannelType() != "session" {
						ch.Reject(ssh.UnknownChannelType, "only session")
						continue
					}
					sch, inReqs, err := ch.Accept()
					if err != nil {
						continue
					}
					go handleSessionChannel(sch, inReqs)
				}
			}(conn)
		}
	}()

	// Client side through the real tool stack
	auditPath := t.TempDir() + "/audit.jsonl"
	srv := NewServer(&SessionManager{}, NewAuditLog(auditPath), 16)
	ctx := context.Background()
	_, openOut, err := srv.sshOpen(ctx, nil, SshOpenParams{
		Host:          "127.0.0.1",
		Port:          ptr(int(ln.Addr().(*net.TCPAddr).Port)),
		User:          "u",
		Password:      "pw",
		UseAgent:      ptr(false),
		HostKeyPolicy: "off",
		Mode:          "unrestricted",
	})
	if err != nil {
		t.Fatalf("ssh_open: %v", err)
	}
	if openOut.AuthMethod != "password" {
		t.Fatalf("auth_method=%q want password", openOut.AuthMethod)
	}
	sess := srv.sessions.Get(openOut.SessionID)
	if sess == nil {
		t.Fatal("session not registered")
	}
	defer sess.Close()

	// ssh_exec
	cmd := "echo hi"
	if runtime.GOOS == "windows" {
		cmd = "cmd /c echo hi"
	}
	_, execOut, err := srv.sshExec(ctx, nil, SshExecParams{
		SessionID: openOut.SessionID,
		Command:   cmd,
		TimeoutMS: 10000,
	})
	if err != nil {
		t.Fatalf("ssh_exec: %v", err)
	}
	if execOut.ExitCode == nil || *execOut.ExitCode != 0 {
		t.Fatalf("exit=%v", execOut.ExitCode)
	}
	if !strings.Contains(execOut.Stdout, "hi") {
		t.Fatalf("stdout=%q", execOut.Stdout)
	}

	// readonly mode refuses dangerous commands
	sess.Mode = modeReadOnly
	_, _, err = srv.sshExec(ctx, nil, SshExecParams{SessionID: openOut.SessionID, Command: "rm -rf /tmp/x"})
	if err == nil {
		t.Fatal("expected readonly refusal")
	}

	// audit trail recorded the actions
	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"ssh_open", "ssh_exec"} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("audit log missing %s:\n%s", want, data)
		}
	}
}

func handleSessionChannel(sch ssh.Channel, inReqs <-chan *ssh.Request) {
	for req := range inReqs {
		switch req.Type {
		case "exec":
			var payload struct{ Value string }
			ssh.Unmarshal(req.Payload, &payload)
			req.Reply(true, nil)
			var cmd *exec.Cmd
			if runtime.GOOS == "windows" {
				cmd = exec.Command("cmd", "/c", payload.Value)
			} else {
				cmd = exec.Command("sh", "-c", payload.Value)
			}
			out, err := cmd.CombinedOutput()
			sch.Write(out)
			code := uint32(0)
			if ee, ok := err.(*exec.ExitError); ok {
				code = uint32(ee.ExitCode())
			} else if err != nil {
				code = 255
			}
			sch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{code}))
			sch.Close()
			return
		case "pty-req", "shell":
			req.Reply(true, nil)
		default:
			req.Reply(false, nil)
		}
	}
}

func ptr[T any](v T) *T { return &v }
