// Docker end-to-end test: drives the real tool layer against a real sshd.
// Run with: SPM_E2E=1 go test -run TestE2EDocker -v .
// Self-skips when SPM_E2E is unset or docker is unavailable.
// Ported scenario-for-scenario from tests/ssh_e2e.rs.
package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func dockerOK() bool {
	out, err := exec.Command("docker", "--version").Output()
	return err == nil && len(out) > 0
}

func runDocker(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker %v failed: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

type e2eContainer struct{ id string }

func (c *e2eContainer) cleanup() {
	exec.Command("docker", "rm", "-f", c.id).Run() //nolint:errcheck
}

func startContainer(t *testing.T) (*e2eContainer, int) {
	t.Helper()
	// Build best-effort: a cached image is fine.
	built := exec.Command("docker", "build", "-q", "-t", "spm-e2e", "../tests/docker").Run() == nil
	if !built {
		if exec.Command("docker", "image", "inspect", "spm-e2e").Run() != nil {
			t.Fatal("docker build failed and no cached spm-e2e image")
		}
		t.Log("docker build failed; using cached spm-e2e image")
	}
	id := runDocker(t, "run", "-d", "--rm", "-P", "spm-e2e")
	portLine := runDocker(t, "port", id, "22/tcp")
	port, err := strconv.Atoi(portLine[strings.LastIndex(portLine, ":")+1:])
	if err != nil {
		t.Fatalf("parse port from %q: %v", portLine, err)
	}
	return &e2eContainer{id: id}, port
}

func e2eOpenParams(port int) SshOpenParams {
	return SshOpenParams{
		Host:          "127.0.0.1",
		Port:          ptr(port),
		User:          "test",
		Password:      "testpass",
		UseAgent:      ptr(false),
		UseSSHConfig:  ptr(false),
		HostKeyPolicy: "off",
	}
}

func e2eSID(id string) SessionParams { return SessionParams{SessionID: id} }

func e2eRun(t *testing.T, srv *Server, id, command string) SshShellOut {
	t.Helper()
	_, out, err := srv.sshShell(context.Background(), nil, SshShellParams{
		SessionID: id,
		Command:   command,
		TimeoutMS: 30000,
	})
	if err != nil {
		t.Fatalf("ssh_shell(%q) failed: %v", command, err)
	}
	return *out
}

func e2eOpenTool(t *testing.T, srv *Server, port int, mutate func(*SshOpenParams)) SshOpenOut {
	t.Helper()
	p := e2eOpenParams(port)
	if mutate != nil {
		mutate(&p)
	}
	_, out, err := srv.sshOpen(context.Background(), nil, p)
	if err != nil {
		t.Fatalf("ssh_open: %v", err)
	}
	if out.ShellKind != "posix" {
		t.Fatalf("shell_kind=%q want posix", out.ShellKind)
	}
	if out.AuthMethod != "password" {
		t.Fatalf("auth_method=%q want password", out.AuthMethod)
	}
	return out
}

func mustErrContains(t *testing.T, err error, sub, label string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: expected error containing %q, got nil", label, sub)
	}
	if !strings.Contains(err.Error(), sub) {
		t.Fatalf("%s: error %q missing %q", label, err.Error(), sub)
	}
}

func TestE2EDocker(t *testing.T) {
	if os.Getenv("SPM_E2E") != "1" {
		t.Skip("set SPM_E2E=1 to enable")
	}
	if !dockerOK() {
		t.Skip("docker unavailable")
	}
	ctx := context.Background()
	container, port := startContainer(t)
	defer container.cleanup()

	// Wait for sshd to accept connections.
	var warmup *Opened
	for i := 0; i < 30; i++ {
		p := e2eOpenParams(port)
		cp := &ConnectParams{
			Host: p.Host, Port: *p.Port, User: p.User, Password: p.Password,
			UseAgent: false, UseSSHConfig: false, HostKeyPolicy: HostKeyOff,
			Mode: modeUnrestricted, Cols: 120, Rows: 32, ConnectTimeout: 5 * time.Second,
		}
		if o, err := Open(cp, &SessionManager{}); err == nil {
			warmup = o
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if warmup == nil {
		t.Fatal("sshd never became ready")
	}
	warmup.Session.alive.Store(false)
	warmup.Session.Close()

	auditDir := t.TempDir()
	auditPath := filepath.Join(auditDir, "audit.jsonl")
	srv := NewServer(&SessionManager{}, NewAuditLog(auditPath), 16)
	opened := e2eOpenTool(t, srv, port, nil)
	id := opened.SessionID

	// Scenario 2: cwd persistence.
	r := e2eRun(t, srv, id, "cd /etc && pwd")
	if r.ExitCode == nil || *r.ExitCode != 0 {
		t.Fatalf("scenario 2: exit=%v", r.ExitCode)
	}
	if r := e2eRun(t, srv, id, "pwd"); !strings.Contains(r.Output, "/etc") {
		t.Fatalf("scenario 2: cwd persists, got %q", r.Output)
	}

	// Scenario 3: env persistence.
	e2eRun(t, srv, id, "export SPM_X=42")
	if r := e2eRun(t, srv, id, "echo $SPM_X"); !strings.Contains(r.Output, "42") {
		t.Fatalf("scenario 3: env persists, got %q", r.Output)
	}

	// Scenario 4: exit code.
	if r := e2eRun(t, srv, id, "false"); r.ExitCode == nil || *r.ExitCode != 1 {
		t.Fatalf("scenario 4: exit code propagates, got %v", r.ExitCode)
	}

	// Scenario 4b: byte-exact clean output.
	if r := e2eRun(t, srv, id, "printf 'SPM_EXACT'"); r.Output != "SPM_EXACT" {
		t.Fatalf("4b: byte-exact output, got %q", r.Output)
	}

	// Scenario 5: interactive prompt loop.
	if _, _, err := srv.sshType(ctx, nil, SshTypeParams{SessionID: id, Text: "read -p 'Name? ' n; echo \"got $n\"\n"}); err != nil {
		t.Fatal(err)
	}
	_, e5, err := srv.sshExpect(ctx, nil, SshExpectParams{SessionID: id, Pattern: "Name\\?", TimeoutMS: 10000})
	if err != nil || !e5.Matched {
		t.Fatalf("scenario 5: prompt seen: %+v %v", e5, err)
	}
	srv.sshType(ctx, nil, SshTypeParams{SessionID: id, Text: "bob\n"})
	_, e5b, err := srv.sshExpect(ctx, nil, SshExpectParams{SessionID: id, Pattern: "got bob", TimeoutMS: 10000})
	if err != nil || !e5b.Matched {
		t.Fatalf("scenario 5: answer echoed: %+v %v", e5b, err)
	}

	// Scenario 6: TUI — top via screen + press.
	srv.sshType(ctx, nil, SshTypeParams{SessionID: id, Text: "top\n"})
	_, s6, err := srv.sshScreen(ctx, nil, SshScreenParams{SessionID: id, Wait: "quiet", SettleMS: 1000, TimeoutMS: 8000})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.ToLower(s6.Screen), "load average") {
		t.Fatalf("scenario 6: top on screen, got:\n%s", s6.Screen)
	}
	srv.sshPress(ctx, nil, SshPressParams{SessionID: id, Key: "q"})
	_, e6, err := srv.sshExpect(ctx, nil, SshExpectParams{SessionID: id, Pattern: "\\$", TimeoutMS: 10000})
	if err != nil || !e6.Matched {
		t.Fatalf("scenario 6: back at prompt after q: %+v %v", e6, err)
	}

	// Scenario 7: SFTP roundtrip.
	tmp := t.TempDir()
	if _, _, err := srv.fileWrite(ctx, nil, FileWriteParams{SessionID: id, Path: "/tmp/spm.txt", Content: "hello", Mode: "overwrite"}); err != nil {
		t.Fatalf("scenario 7: write new file: %v", err)
	}
	_, fr, err := srv.fileRead(ctx, nil, FileReadParams{SessionID: id, Path: "/tmp/spm.txt"})
	if err != nil || fr.Content != "hello" {
		t.Fatalf("scenario 7: read back: %+v %v", fr, err)
	}
	local := filepath.Join(tmp, "dl.txt")
	if _, _, err := srv.sshDownload(ctx, nil, TransferParams{SessionID: id, LocalPath: local, RemotePath: "/tmp/spm.txt"}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(local); string(b) != "hello" {
		t.Fatalf("scenario 7: download, got %q", b)
	}
	if _, _, err := srv.sshUpload(ctx, nil, TransferParams{SessionID: id, LocalPath: local, RemotePath: "/tmp/spm2.txt"}); err != nil {
		t.Fatalf("scenario 7: upload: %v", err)
	}
	_, fr2, _ := srv.fileRead(ctx, nil, FileReadParams{SessionID: id, Path: "/tmp/spm2.txt"})
	if fr2.Content != "hello" {
		t.Fatalf("scenario 7: upload verified, got %q", fr2.Content)
	}

	// Scenario 11: read-before-write guard.
	guardPath := "/tmp/guard.txt"
	if _, _, err := srv.fileWrite(ctx, nil, FileWriteParams{SessionID: id, Path: guardPath, Content: "hello world", Mode: "overwrite"}); err != nil {
		t.Fatalf("11a: %v", err)
	}
	_, _, err = srv.fileWrite(ctx, nil, FileWriteParams{SessionID: id, Path: guardPath, Content: "x", Mode: "overwrite"})
	mustErrContains(t, err, "file_read", "11b")
	srv.fileRead(ctx, nil, FileReadParams{SessionID: id, Path: guardPath, Limit: 5})
	_, _, err = srv.fileWrite(ctx, nil, FileWriteParams{SessionID: id, Path: guardPath, Content: "x", Mode: "overwrite"})
	mustErrContains(t, err, "[5, 11)", "11c")
	srv.fileRead(ctx, nil, FileReadParams{SessionID: id, Path: guardPath, Offset: 5})
	if _, _, err := srv.fileWrite(ctx, nil, FileWriteParams{SessionID: id, Path: guardPath, Content: "updated!", Mode: "overwrite"}); err != nil {
		t.Fatalf("11d: %v", err)
	}
	srv.fileWrite(ctx, nil, FileWriteParams{SessionID: id, Path: "/tmp/guard2.txt", Content: "base", Mode: "overwrite"})
	if _, _, err := srv.fileWrite(ctx, nil, FileWriteParams{SessionID: id, Path: "/tmp/guard2.txt", Content: "+more", Mode: "append"}); err != nil {
		t.Fatalf("11e: %v", err)
	}
	e2eRun(t, srv, id, "echo EXT >> /tmp/guard.txt")
	_, _, err = srv.fileWrite(ctx, nil, FileWriteParams{SessionID: id, Path: guardPath, Content: "y", Mode: "overwrite"})
	mustErrContains(t, err, "file_read", "11f")
	_, _, err = srv.sshUpload(ctx, nil, TransferParams{SessionID: id, LocalPath: local, RemotePath: guardPath})
	mustErrContains(t, err, "file_read", "11g")

	// Scenario 13: from_offset anchors the wait.
	_, typed, err := srv.sshType(ctx, nil, SshTypeParams{SessionID: id, Text: "echo SPM_ANCHOR\n"})
	if err != nil {
		t.Fatal(err)
	}
	_, arrived, err := srv.sshScreen(ctx, nil, SshScreenParams{SessionID: id, SinceSeq: &typed.Seq, Wait: "change", TimeoutMS: 5000})
	if err != nil || arrived.TimedOut {
		t.Fatalf("13: output arrived: %+v %v", arrived, err)
	}
	_, e13, err := srv.sshExpect(ctx, nil, SshExpectParams{SessionID: id, Pattern: "SPM_ANCHOR", FromOffset: &typed.StreamOffset, TimeoutMS: 5000})
	if err != nil || !e13.Matched {
		t.Fatalf("13: from_offset catches pre-arrived output: %+v %v", e13, err)
	}

	// Scenario 14: append creates; missing parent named.
	if _, _, err := srv.fileWrite(ctx, nil, FileWriteParams{SessionID: id, Path: "/tmp/append_new.txt", Content: "created-by-append", Mode: "append"}); err != nil {
		t.Fatalf("14: %v", err)
	}
	_, fr14, _ := srv.fileRead(ctx, nil, FileReadParams{SessionID: id, Path: "/tmp/append_new.txt"})
	if fr14.Content != "created-by-append" {
		t.Fatalf("14: append content, got %q", fr14.Content)
	}
	_, _, err = srv.fileWrite(ctx, nil, FileWriteParams{SessionID: id, Path: "/tmp/no_such_dir_xyz/f.txt", Content: "x", Mode: "overwrite"})
	mustErrContains(t, err, "parent directory does not exist", "14")

	// Scenario 15: up-arrow history recall.
	e2eRun(t, srv, id, "echo SPM_HISTORY_MARK")
	_, pressed, err := srv.sshPress(ctx, nil, SshPressParams{SessionID: id, Key: "up"})
	if err != nil {
		t.Fatal(err)
	}
	_, s15, err := srv.sshScreen(ctx, nil, SshScreenParams{SessionID: id, SinceSeq: &pressed.Seq, Wait: "quiet", SettleMS: 500, TimeoutMS: 5000})
	if err != nil || !strings.Contains(s15.Screen, "echo SPM_HISTORY_MARK") {
		t.Fatalf("15: up recalls last command:\n%s\n%v", s15.Screen, err)
	}
	srv.sshPress(ctx, nil, SshPressParams{SessionID: id, Key: "ctrl+c"})

	// Scenario 12: heredoc and multi-line commands.
	if r := e2eRun(t, srv, id, "cat << EOF\nhello spm\nEOF"); r.ExitCode == nil || *r.ExitCode != 0 || !strings.Contains(r.Output, "hello spm") {
		t.Fatalf("12: heredoc, got %+v", r)
	}
	if r := e2eRun(t, srv, id, "cd /tmp\npwd"); !strings.Contains(r.Output, "/tmp") {
		t.Fatalf("12: multi-line, got %q", r.Output)
	}
	if r := e2eRun(t, srv, id, "pwd"); !strings.Contains(r.Output, "/tmp") {
		t.Fatalf("12: cwd persists, got %q", r.Output)
	}
	if r := e2eRun(t, srv, id, "cd /\nfalse"); r.ExitCode == nil || *r.ExitCode != 1 {
		t.Fatalf("12: exit of last line, got %v", r.ExitCode)
	}

	// Scenario 17: ssh_exec — stateless, split streams, protocol exit code.
	_, x17, err := srv.sshExec(ctx, nil, SshExecParams{SessionID: id, Command: "pwd", TimeoutMS: 10000})
	if err != nil || strings.TrimSpace(x17.Stdout) != "/home/test" {
		t.Fatalf("17: stateless exec, got %+v %v", x17, err)
	}
	_, x17b, err := srv.sshExec(ctx, nil, SshExecParams{SessionID: id, Command: "echo OUT; echo ERR >&2; exit 3", TimeoutMS: 10000})
	if err != nil || !strings.Contains(x17b.Stdout, "OUT") || !strings.Contains(x17b.Stderr, "ERR") || x17b.ExitCode == nil || *x17b.ExitCode != 3 {
		t.Fatalf("17: split/exit, got %+v %v", x17b, err)
	}

	// Scenario 18: ssh_ready.
	_, r18, err := srv.sshReady(ctx, nil, SshReadyParams{SessionID: id, ProbeTimeoutMS: 2000})
	if err != nil || !r18.Ready {
		t.Fatalf("18: ready at prompt: %+v %v", r18, err)
	}
	srv.sshType(ctx, nil, SshTypeParams{SessionID: id, Text: "sleep 2\n"})
	_, r18b, _ := srv.sshReady(ctx, nil, SshReadyParams{SessionID: id, ProbeTimeoutMS: 400})
	if r18b.Ready {
		t.Fatal("18: not ready during sleep")
	}
	time.Sleep(2200 * time.Millisecond)
	_, r18c, _ := srv.sshReady(ctx, nil, SshReadyParams{SessionID: id, ProbeTimeoutMS: 2000})
	if !r18c.Ready {
		t.Fatal("18: ready again after sleep")
	}

	// Scenario 19: tail_lines.
	one := 1
	_, s19, err := srv.sshScreen(ctx, nil, SshScreenParams{SessionID: id, Wait: "none", TailLines: &one, TimeoutMS: 5000})
	if err != nil || len(strings.Split(s19.Screen, "\n")) != 1 {
		t.Fatalf("19: exactly one line, got %q %v", s19.Screen, err)
	}

	// Scenario 20: session naming.
	n1 := e2eOpenTool(t, srv, port, func(p *SshOpenParams) { p.Name = "web1" })
	if n1.Name != "web1" {
		t.Fatalf("20: name, got %q", n1.Name)
	}
	_, list20, _ := srv.sshList(ctx, nil, struct{}{})
	found := false
	for _, s := range list20.Sessions {
		if s.Name == "web1" {
			found = true
		}
	}
	if !found {
		t.Fatal("20: name in list")
	}
	if r := e2eRun(t, srv, "web1", "echo VIA_NAME"); !strings.Contains(r.Output, "VIA_NAME") {
		t.Fatalf("20: run by alias, got %q", r.Output)
	}
	_, _, err = srv.sshOpen(ctx, nil, e2eOpenParamsWith(port, func(p *SshOpenParams) { p.Name = "web1" }))
	mustErrContains(t, err, "already in use", "20")
	if _, _, err := srv.sshClose(ctx, nil, e2eSID("web1")); err != nil {
		t.Fatalf("20: close by alias: %v", err)
	}

	// Scenario 21: async task.
	_, a21, err := srv.sshShellAsync(ctx, nil, SshShellAsyncParams{SessionID: id, Command: "sleep 2 && echo ASYNC_DONE", TimeoutMS: 30000})
	if err != nil {
		t.Fatal(err)
	}
	_, st21, _ := srv.sshTaskStatus(ctx, nil, SshTaskStatusParams{TaskID: a21.TaskID})
	if st21.Status != "running" {
		t.Fatalf("21: immediately running, got %+v", st21)
	}
	_, st21b, err := srv.sshTaskStatus(ctx, nil, SshTaskStatusParams{TaskID: a21.TaskID, WaitMS: 8000})
	if err != nil || st21b.Status != "done" || !strings.Contains(st21b.Output, "ASYNC_DONE") || st21b.ExitCode == nil || *st21b.ExitCode != 0 {
		t.Fatalf("21: completes, got %+v %v", st21b, err)
	}

	// Scenario 22: file_edit with the guard.
	srv.fileWrite(ctx, nil, FileWriteParams{SessionID: id, Path: "/tmp/edit.txt", Content: "line1\nline2 TARGET\nline3\n", Mode: "overwrite"})
	_, _, err = srv.fileEdit(ctx, nil, FileEditParams{SessionID: id, Path: "/tmp/edit.txt", OldString: "TARGET", NewString: "HIT"})
	mustErrContains(t, err, "prior file_read", "22 unread")
	srv.fileRead(ctx, nil, FileReadParams{SessionID: id, Path: "/tmp/edit.txt"})
	_, e22, err := srv.fileEdit(ctx, nil, FileEditParams{SessionID: id, Path: "/tmp/edit.txt", OldString: "TARGET", NewString: "HIT"})
	if err != nil || e22.Replacements != 1 || !strings.Contains(e22.Context, "HIT") {
		t.Fatalf("22: edit after read: %+v %v", e22, err)
	}
	_, _, err = srv.fileEdit(ctx, nil, FileEditParams{SessionID: id, Path: "/tmp/edit.txt", OldString: "MISSING", NewString: "x"})
	mustErrContains(t, err, "not found", "22 absent")
	srv.fileWrite(ctx, nil, FileWriteParams{SessionID: id, Path: "/tmp/edit.txt", Content: "same\nsame\n", Mode: "append"})
	_, _, err = srv.fileEdit(ctx, nil, FileEditParams{SessionID: id, Path: "/tmp/edit.txt", OldString: "same", NewString: "diff"})
	mustErrContains(t, err, "matches 2 times", "22 multi-match")
	srv.fileRead(ctx, nil, FileReadParams{SessionID: id, Path: "/tmp/edit.txt"})
	_, e22b, err := srv.fileEdit(ctx, nil, FileEditParams{SessionID: id, Path: "/tmp/edit.txt", OldString: "same", NewString: "diff", ReplaceAll: true})
	if err != nil || e22b.Replacements != 2 {
		t.Fatalf("22: replace_all: %+v %v", e22b, err)
	}

	// Scenario 23: dead sessions are pruned; alias reusable.
	m23 := e2eOpenTool(t, srv, port, func(p *SshOpenParams) { p.Name = "mortal" })
	mid := m23.SessionID
	srv.sshShell(ctx, nil, SshShellParams{SessionID: mid, Command: "exit 99", TimeoutMS: 3000})
	time.Sleep(500 * time.Millisecond)
	_, list23, _ := srv.sshList(ctx, nil, struct{}{})
	for _, s := range list23.Sessions {
		if s.SessionID == mid {
			t.Fatal("23: dead session pruned from list")
		}
	}
	e2eOpenTool(t, srv, port, func(p *SshOpenParams) { p.Name = "mortal" })

	// Scenario 24: task cancel interrupts without killing the session.
	_, a24, err := srv.sshShellAsync(ctx, nil, SshShellAsyncParams{SessionID: id, Command: "sleep 30 && echo NEVER", TimeoutMS: 60000})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	_, c24, err := srv.sshTaskCancel(ctx, nil, SshTaskCancelParams{TaskID: a24.TaskID})
	if err != nil || !c24.Cancelled {
		t.Fatalf("24: cancel accepted: %+v %v", c24, err)
	}
	_, st24, _ := srv.sshTaskStatus(ctx, nil, SshTaskStatusParams{TaskID: a24.TaskID})
	if st24.Status != "error" {
		t.Fatalf("24: task marked cancelled, got %+v", st24)
	}
	if r := e2eRun(t, srv, id, "echo ALIVE"); !strings.Contains(r.Output, "ALIVE") {
		t.Fatalf("24: session survives cancel, got %q", r.Output)
	}

	// Scenario 25: ssh_copy same- and cross-session.
	srv.fileWrite(ctx, nil, FileWriteParams{SessionID: id, Path: "/tmp/copy_src.txt", Content: "copy-payload", Mode: "overwrite"})
	if _, _, err := srv.sshCopy(ctx, nil, SshCopyParams{FromSession: id, FromPath: "/tmp/copy_src.txt", ToSession: id, ToPath: "/tmp/copy_dst.txt"}); err != nil {
		t.Fatalf("25: same-session copy: %v", err)
	}
	_, fr25, _ := srv.fileRead(ctx, nil, FileReadParams{SessionID: id, Path: "/tmp/copy_dst.txt"})
	if fr25.Content != "copy-payload" {
		t.Fatalf("25: same-session content, got %q", fr25.Content)
	}
	s2 := e2eOpenTool(t, srv, port, nil).SessionID
	if _, _, err := srv.sshCopy(ctx, nil, SshCopyParams{FromSession: id, FromPath: "/tmp/copy_src.txt", ToSession: s2, ToPath: "/tmp/copy_x.txt"}); err != nil {
		t.Fatalf("25: cross-session copy: %v", err)
	}
	_, fr25b, _ := srv.fileRead(ctx, nil, FileReadParams{SessionID: s2, Path: "/tmp/copy_x.txt"})
	if fr25b.Content != "copy-payload" {
		t.Fatalf("25: cross-session content, got %q", fr25b.Content)
	}
	srv.sshClose(ctx, nil, e2eSID(s2))

	// Scenario 26: ssh_exec heredoc.
	_, x26, err := srv.sshExec(ctx, nil, SshExecParams{SessionID: id, Command: "cat << EOF\nhi spm\nEOF", TimeoutMS: 10000})
	if err != nil || !strings.Contains(x26.Stdout, "hi spm") || x26.ExitCode == nil || *x26.ExitCode != 0 {
		t.Fatalf("26: exec heredoc, got %+v %v", x26, err)
	}

	// Scenario 27: self-copy refused without data loss.
	srv.fileWrite(ctx, nil, FileWriteParams{SessionID: id, Path: "/tmp/important.txt", Content: "important data", Mode: "overwrite"})
	_, _, err = srv.sshCopy(ctx, nil, SshCopyParams{FromSession: id, FromPath: "/tmp/important.txt", ToSession: id, ToPath: "/tmp/important.txt"})
	mustErrContains(t, err, "same file", "27")
	_, fr27, _ := srv.fileRead(ctx, nil, FileReadParams{SessionID: id, Path: "/tmp/important.txt"})
	if fr27.Content != "important data" {
		t.Fatalf("27: source intact, got %q", fr27.Content)
	}

	// Scenario 28: directory destination error.
	_, _, err = srv.sshUpload(ctx, nil, TransferParams{SessionID: id, LocalPath: local, RemotePath: "/tmp/"})
	mustErrContains(t, err, "directory", "28")

	// Scenario 29: screen filters scaffolding.
	e2eRun(t, srv, id, "echo CLEAN_SCREEN")
	_, s29, err := srv.sshScreen(ctx, nil, SshScreenParams{SessionID: id, Wait: "none", TimeoutMS: 5000})
	if err != nil || strings.Contains(s29.Screen, "__SPM_") || strings.Contains(s29.Screen, "stty -echo") || !strings.Contains(s29.Screen, "CLEAN_SCREEN") {
		t.Fatalf("29: filtered screen:\n%s\n%v", s29.Screen, err)
	}

	// Scenario 30: hardlink self-copy refused via dev:inode.
	e2eRun(t, srv, id, "echo data > /tmp/hl_a.txt && ln /tmp/hl_a.txt /tmp/hl_b.txt")
	_, _, err = srv.sshCopy(ctx, nil, SshCopyParams{FromSession: id, FromPath: "/tmp/hl_a.txt", ToSession: id, ToPath: "/tmp/hl_b.txt"})
	mustErrContains(t, err, "same file", "30")
	_, fr30, _ := srv.fileRead(ctx, nil, FileReadParams{SessionID: id, Path: "/tmp/hl_a.txt"})
	if strings.TrimSpace(fr30.Content) != "data" {
		t.Fatalf("30: source intact, got %q", fr30.Content)
	}

	// Scenario 31: exec timeout. Unlike the Rust build (documented leak),
	// x/crypto's channel close makes OpenSSH clean up the remote child, so
	// no leak is visible.
	_, x31, err := srv.sshExec(ctx, nil, SshExecParams{SessionID: id, Command: "sleep 30", TimeoutMS: 1500})
	if err != nil || !x31.TimedOut {
		t.Fatalf("31: exec times out, got %+v %v", x31, err)
	}
	_, check, _ := srv.sshExec(ctx, nil, SshExecParams{SessionID: id, Command: "ps aux | grep '[s]leep 30' | wc -l", TimeoutMS: 10000})
	n, _ := strconv.Atoi(strings.TrimSpace(check.Stdout))
	if n != 0 {
		t.Fatalf("31: remote process cleaned up after timeout, got %q", check.Stdout)
	}

	e2eScenario32to39(t, srv, id, port, container, local, auditPath)
}

func e2eOpenParamsWith(port int, mutate func(*SshOpenParams)) SshOpenParams {
	p := e2eOpenParams(port)
	if mutate != nil {
		mutate(&p)
	}
	return p
}

func e2eScenario32to39(t *testing.T, srv *Server, id string, port int, container *e2eContainer, local, auditPath string) {
	ctx := context.Background()

	// Scenario 32: servers.toml registry + ssh_list_servers.
	tomlDir := t.TempDir()
	tomlPath := filepath.Join(tomlDir, "servers.toml")
	os.WriteFile(tomlPath, []byte(fmt.Sprintf("[servers.sbx]\nhost = \"127.0.0.1\"\nport = %d\nuser = \"test\"\npassword = \"testpass\"\n", port)), 0o644)
	oldEnv, hadEnv := os.LookupEnv("SSH_PTY_MCP_SERVERS")
	os.Setenv("SSH_PTY_MCP_SERVERS", tomlPath)
	defer func() {
		if hadEnv {
			os.Setenv("SSH_PTY_MCP_SERVERS", oldEnv)
		} else {
			os.Unsetenv("SSH_PTY_MCP_SERVERS")
		}
	}()
	_, listed, err := srv.sshListServers(ctx, nil, struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	sbx := false
	for _, s := range listed.Servers {
		if s.Name == "sbx" && s.Port != nil && *s.Port == port {
			sbx = true
		}
	}
	if !sbx {
		t.Fatal("32: sbx listed")
	}
	_, open32, err := srv.sshOpen(ctx, nil, e2eOpenParamsWith(port, func(p *SshOpenParams) { p.Server = "sbx" }))
	if err != nil {
		t.Fatalf("32: open via registry: %v", err)
	}
	if r := e2eRun(t, srv, open32.SessionID, "echo VIA_REGISTRY"); !strings.Contains(r.Output, "VIA_REGISTRY") {
		t.Fatalf("32: registry session works, got %q", r.Output)
	}
	srv.sshClose(ctx, nil, e2eSID(open32.SessionID))

	// Scenario 33: ProxyJump through a bastion to an unpublished container.
	targetID := runDocker(t, "run", "-d", "--rm", "spm-e2e")
	target := &e2eContainer{id: targetID}
	defer target.cleanup()
	targetIP := runDocker(t, "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", targetID)
	os.WriteFile(tomlPath, []byte(fmt.Sprintf("[servers.bastion]\nhost = \"127.0.0.1\"\nport = %d\nuser = \"test\"\npassword = \"testpass\"\n", port)), 0o644)
	var jumped SshOpenOut
	for i := 0; i < 15; i++ {
		_, out, err := srv.sshOpen(ctx, nil, e2eOpenParamsWith(port, func(p *SshOpenParams) {
			p.Host = targetIP
			p.Port = ptr(22)
			p.ProxyJump = "bastion"
		}))
		if err == nil {
			jumped = out
			break
		}
		time.Sleep(600 * time.Millisecond)
	}
	if jumped.SessionID == "" {
		t.Fatal("33: open via proxyjump never succeeded")
	}
	if r := e2eRun(t, srv, jumped.SessionID, "hostname"); !strings.Contains(r.Output, targetID[:12]) {
		t.Fatalf("33: landed on target behind bastion, got %q", r.Output)
	}
	srv.sshClose(ctx, nil, e2eSID(jumped.SessionID))

	// Scenario 37: proxy_jump via an OPEN SESSION alias.
	_, jumpbox, err := srv.sshOpen(ctx, nil, e2eOpenParamsWith(port, func(p *SshOpenParams) { p.Name = "jumpbox" }))
	if err != nil {
		t.Fatalf("37: open jumpbox session: %v", err)
	}
	var jumped2 SshOpenOut
	for i := 0; i < 15; i++ {
		_, out, err := srv.sshOpen(ctx, nil, e2eOpenParamsWith(port, func(p *SshOpenParams) {
			p.Host = targetIP
			p.Port = ptr(22)
			p.ProxyJump = "jumpbox"
		}))
		if err == nil {
			jumped2 = out
			break
		}
		time.Sleep(600 * time.Millisecond)
	}
	if jumped2.SessionID == "" {
		t.Fatal("37: open via session-alias jump never succeeded")
	}
	if r := e2eRun(t, srv, jumped2.SessionID, "hostname"); !strings.Contains(r.Output, targetID[:12]) {
		t.Fatalf("37: landed on target via session-alias jump, got %q", r.Output)
	}
	srv.sshClose(ctx, nil, e2eSID(jumped2.SessionID))
	srv.sshClose(ctx, nil, e2eSID(jumpbox.SessionID))

	// Scenario 38: host-key change is REFUSED under accept-new.
	{
		ca, pa := startContainer(t)
		_, learn, err := srv.sshOpen(ctx, nil, e2eOpenParamsWith(pa, func(p *SshOpenParams) { p.HostKeyPolicy = "accept-new" }))
		if err != nil {
			t.Fatalf("38: learn sandbox key: %v", err)
		}
		srv.sshClose(ctx, nil, e2eSID(learn.SessionID))
		ca.cleanup()
		pbind := fmt.Sprintf("127.0.0.1:%d:22", pa)
		var b string
		for i := 0; i < 20; i++ {
			out, err := exec.Command("docker", "run", "-d", "--rm", "-p", pbind, "--entrypoint", "sh", "spm-e2e", "-c",
				"rm -f /etc/ssh/ssh_host_*; ssh-keygen -A >/dev/null; exec /usr/sbin/sshd -D -e").Output()
			if err == nil {
				b = strings.TrimSpace(string(out))
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
		if b == "" {
			t.Fatal("38: start fresh-key container")
		}
		cb := &e2eContainer{id: b}
		defer cb.cleanup()
		var refused error
		for i := 0; i < 20; i++ {
			_, _, err := srv.sshOpen(ctx, nil, e2eOpenParamsWith(pa, func(p *SshOpenParams) { p.HostKeyPolicy = "accept-new" }))
			if err != nil {
				refused = err
				break
			}
			time.Sleep(700 * time.Millisecond)
		}
		if refused == nil {
			t.Fatal("38: changed key must be refused")
		}
		t.Logf("38: refusal message: %v", refused)
		time.Sleep(1500 * time.Millisecond)
		var off SshOpenOut
		for i := 0; i < 10; i++ {
			_, out, err := srv.sshOpen(ctx, nil, e2eOpenParamsWith(pa, func(p *SshOpenParams) { p.HostKeyPolicy = "off" }))
			if err == nil {
				off = out
				break
			}
			t.Logf("38: off retry: %v", err)
			time.Sleep(700 * time.Millisecond)
		}
		if off.SessionID == "" {
			t.Fatal("38: off policy still opens after key change")
		}
		srv.sshClose(ctx, nil, e2eSID(off.SessionID))
		home, err := os.UserHomeDir()
		if err == nil {
			kh := filepath.Join(home, ".ssh", "known_hosts")
			if text, err := os.ReadFile(kh); err == nil {
				needle := fmt.Sprintf("[127.0.0.1]:%d", pa)
				var kept []string
				for _, l := range strings.Split(string(text), "\n") {
					if !strings.Contains(l, needle) {
						kept = append(kept, l)
					}
				}
				os.WriteFile(kh, []byte(strings.Join(kept, "\n")), 0o600)
			}
		}
	}

	// Scenario 34: readonly mode.
	_, ro, err := srv.sshOpen(ctx, nil, e2eOpenParamsWith(port, func(p *SshOpenParams) { p.Mode = "readonly" }))
	if err != nil {
		t.Fatalf("34: readonly open: %v", err)
	}
	roid := ro.SessionID
	_, _, err = srv.sshShell(ctx, nil, SshShellParams{SessionID: roid, Command: "rm -rf /tmp/anything", TimeoutMS: 10000})
	mustErrContains(t, err, "readonly", "34 rm")
	if r := e2eRun(t, srv, roid, "df -h /"); r.ExitCode == nil || *r.ExitCode != 0 {
		t.Fatal("34: read-only command allowed")
	}
	_, _, err = srv.fileWrite(ctx, nil, FileWriteParams{SessionID: roid, Path: "/tmp/ro.txt", Content: "x", Mode: "overwrite"})
	mustErrContains(t, err, "readonly", "34 file_write")
	_, _, err = srv.sshExec(ctx, nil, SshExecParams{SessionID: roid, Command: "kill -9 1", TimeoutMS: 10000})
	mustErrContains(t, err, "readonly", "34 exec")
	srv.sshClose(ctx, nil, e2eSID(roid))

	// Scenario 35: restricted mode allowlist.
	_, rs, err := srv.sshOpen(ctx, nil, e2eOpenParamsWith(port, func(p *SshOpenParams) {
		p.Mode = "restricted"
		p.Allow = []string{"^df"}
	}))
	if err != nil {
		t.Fatalf("35: restricted open: %v", err)
	}
	rsid := rs.SessionID
	if r := e2eRun(t, srv, rsid, "df -h /"); r.ExitCode == nil || *r.ExitCode != 0 {
		t.Fatal("35: allowlisted command allowed")
	}
	_, _, err = srv.sshShell(ctx, nil, SshShellParams{SessionID: rsid, Command: "ls /tmp", TimeoutMS: 10000})
	mustErrContains(t, err, "restricted", "35 blocked")
	srv.sshClose(ctx, nil, e2eSID(rsid))

	// Scenario 36: PowerShell container (best-effort image).
	builtWin := exec.Command("docker", "build", "-q", "-t", "spm-e2e-win", "-f", "../tests/docker/Dockerfile.win", "../tests/docker").Run() == nil
	winImage := builtWin || exec.Command("docker", "image", "inspect", "spm-e2e-win").Run() == nil
	if winImage {
		wid := runDocker(t, "run", "-d", "--rm", "-P", "spm-e2e-win")
		wc := &e2eContainer{id: wid}
		defer wc.cleanup()
		wportLine := runDocker(t, "port", wid, "22/tcp")
		wport, _ := strconv.Atoi(wportLine[strings.LastIndex(wportLine, ":")+1:])
		var w SshOpenOut
		for i := 0; i < 20; i++ {
			_, out, err := srv.sshOpen(ctx, nil, e2eOpenParams(wport))
			if err == nil {
				w = out
				break
			}
			time.Sleep(700 * time.Millisecond)
		}
		if w.SessionID == "" {
			t.Fatal("36: open powershell session")
		}
		if w.ShellKind != "powershell" {
			t.Fatalf("36: probe detects PowerShell, got %q", w.ShellKind)
		}
		_, _, err := srv.sshShell(ctx, nil, SshShellParams{SessionID: w.SessionID, Command: "Get-Location", TimeoutMS: 10000})
		mustErrContains(t, err, "ssh_exec", "36 refusal")
		_, x36, err := srv.sshExec(ctx, nil, SshExecParams{SessionID: w.SessionID, Command: "Write-Output 'hi from pwsh'; (Get-Location).Path", TimeoutMS: 15000})
		if err != nil || !strings.Contains(x36.Stdout, "hi from pwsh") || !strings.Contains(x36.Stdout, "/home/test") {
			t.Fatalf("36: exec on pwsh, got %+v %v", x36, err)
		}
		_, _, err = srv.sshShellAsync(ctx, nil, SshShellAsyncParams{SessionID: w.SessionID, Command: "Get-Date", TimeoutMS: 10000})
		mustErrContains(t, err, "ssh_exec", "36b")
		_, rdy, err := srv.sshReady(ctx, nil, SshReadyParams{SessionID: w.SessionID, ProbeTimeoutMS: 45000})
		if err != nil || !rdy.Ready {
			t.Fatalf("36c: ssh_ready true on PowerShell: %+v %v", rdy, err)
		}
		srv.sshClose(ctx, nil, e2eSID(w.SessionID))
	} else {
		t.Log("scenario 36: spm-e2e-win image unavailable, skipping")
	}

	// Scenario 39: ssh_add_server writes a usable registry entry.
	addParams := func() SshAddServerParams {
		return SshAddServerParams{Name: "added", Host: "127.0.0.1", Port: ptr(port), User: "test", Password: "testpass"}
	}
	_, ad, err := srv.sshAddServer(ctx, nil, addParams())
	if err != nil || ad.Overwritten {
		t.Fatalf("39: add server: %+v %v", ad, err)
	}
	_, _, err = srv.sshAddServer(ctx, nil, addParams())
	mustErrContains(t, err, "already exists", "39 dup")
	_, o39, err := srv.sshOpen(ctx, nil, e2eOpenParamsWith(port, func(p *SshOpenParams) { p.Server = "added" }))
	if err != nil {
		t.Fatalf("39: open via added server: %v", err)
	}
	srv.sshClose(ctx, nil, e2eSID(o39.SessionID))

	// Scenario 16: session limit is enforced.
	limited := NewServer(&SessionManager{}, NewAuditLog(filepath.Join(a2e2eDir(t), "audit2.jsonl")), 1)
	_, first, err := limited.sshOpen(ctx, nil, e2eOpenParams(port))
	if err != nil {
		t.Fatalf("16: first session under limit: %v", err)
	}
	_, _, err = limited.sshOpen(ctx, nil, e2eOpenParams(port))
	mustErrContains(t, err, "session limit reached", "16")
	limited.sshClose(ctx, nil, e2eSID(first.SessionID))
	if _, _, err := limited.sshOpen(ctx, nil, e2eOpenParams(port)); err != nil {
		t.Fatalf("16: open succeeds again after close: %v", err)
	}

	// Scenario 10: audit log records commands, never the password.
	srv.sshClose(ctx, nil, e2eSID(id))
	logText, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(logText), `"tool":"ssh_shell"`) || !strings.Contains(string(logText), "cd /etc && pwd") {
		t.Fatalf("10: audit entries missing:\n%s", logText)
	}
	if strings.Contains(string(logText), "testpass") {
		t.Fatal("10: password never logged")
	}

	// Scenario 8: closed session rejects further calls.
	_, _, err = srv.sshShell(ctx, nil, SshShellParams{SessionID: id, Command: "pwd", TimeoutMS: 30000})
	mustErrContains(t, err, "unknown session", "8")

	// Scenario 9: agent auth (self-skips without a reachable agent).
	e2eAgentScenario(t, port, container.id)
}

func a2e2eDir(t *testing.T) string { return t.TempDir() }

func e2eAgentScenario(t *testing.T, port int, containerID string) {
	dir, err := os.MkdirTemp("", "spm-agent")
	if err != nil {
		t.Skip("agent scenario: no temp dir")
	}
	defer os.RemoveAll(dir)
	key := filepath.Join(dir, "id_ed25519")
	if out, err := exec.Command("ssh-keygen", "-t", "ed25519", "-N", "", "-f", key).CombinedOutput(); err != nil {
		t.Logf("scenario 9: ssh-keygen failed (%v), skipping: %s", err, out)
		return
	}
	if out, err := exec.Command("ssh-add", key).CombinedOutput(); err != nil {
		t.Logf("scenario 9: ssh-add failed (%v), skipping: %s", err, out)
		return
	}
	defer exec.Command("ssh-add", "-d", key).Run()
	pubkey, _ := os.ReadFile(key + ".pub")
	cmd := exec.Command("docker", "exec", "-i", containerID, "sh", "-c",
		"mkdir -p /home/test/.ssh && cat >> /home/test/.ssh/authorized_keys && chmod 700 /home/test/.ssh && chmod 600 /home/test/.ssh/authorized_keys && chown -R test:test /home/test/.ssh")
	cmd.Stdin = strings.NewReader(string(pubkey))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Logf("scenario 9: installing pubkey failed (%v): %s, skipping", err, out)
		return
	}
	p := e2eOpenParams(port)
	p.Password = ""
	p.UseAgent = ptr(true)
	cp := &ConnectParams{
		Host: p.Host, Port: *p.Port, User: p.User, Password: p.Password,
		UseAgent: true, UseSSHConfig: false, HostKeyPolicy: HostKeyOff,
		Mode: modeUnrestricted, Cols: 120, Rows: 32, ConnectTimeout: 5 * time.Second,
	}
	o, err := Open(cp, &SessionManager{})
	if err != nil {
		t.Fatalf("scenario 9: agent auth should succeed: %v", err)
	}
	if o.AuthMethod != "agent" {
		t.Fatalf("scenario 9: authenticated via agent, got %q", o.AuthMethod)
	}
	o.Session.Close()
}
