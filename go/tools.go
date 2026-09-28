// MCP tool layer: 22 tools over the session core. Tool descriptions carry
// routing guidance — agent fluency depends on them.
package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// Server is the MCP server state.
type Server struct {
	sessions    *SessionManager
	audit       *AuditLog
	maxSessions int

	tasksMu  sync.Mutex
	tasks    map[string]*taskEntry
	nextTask atomic.Uint64
}

type taskEntry struct {
	mu        sync.Mutex
	sessionID string
	done      bool
	result    *SshShellOut
	err       string
	cancelled bool
}

// NewServer wires the tool layer.
func NewServer(sessions *SessionManager, audit *AuditLog, maxSessions int) *Server {
	return &Server{
		sessions:    sessions,
		audit:       audit,
		maxSessions: maxSessions,
		tasks:       map[string]*taskEntry{},
	}
}

func invalid(msg string) error {
	return &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: msg}
}

func internalErr(err error) error {
	return &jsonrpc.Error{Code: jsonrpc.CodeInternalError, Message: err.Error()}
}

func internalMsg(msg string) error {
	return &jsonrpc.Error{Code: jsonrpc.CodeInternalError, Message: msg}
}

func (srv *Server) liveSession(idOrName string) (*Session, error) {
	s := srv.sessions.Find(idOrName)
	if s == nil {
		return nil, invalid(fmt.Sprintf("unknown session '%s'; call ssh_open first", idOrName))
	}
	if err := s.CheckAlive(); err != nil {
		return nil, invalid(err.Error())
	}
	return s, nil
}

// ── Param / output types ────────────────────────────────────────────────────

type SshOpenParams struct {
	Server         string   `json:"server,omitempty" jsonschema:"Named server from ~/.ssh-pty-mcp/servers.toml. Explicit params below override registry values."`
	Host           string   `json:"host,omitempty" jsonschema:"Hostname, IP, or a Host alias from ~/.ssh/config. Optional when server provides one."`
	Port           *int     `json:"port,omitempty" jsonschema:"SSH port. Omit to use ~/.ssh/config or 22."`
	User           string   `json:"user,omitempty" jsonschema:"Login user. Omit to use ~/.ssh/config."`
	Name           string   `json:"name,omitempty" jsonschema:"Optional alias for this session (must be unique). Usable anywhere session_id is accepted."`
	ProxyJump      string   `json:"proxy_jump,omitempty" jsonschema:"ProxyJump spec: the name/id of an existing open session (reused as the jump host, no second connection), an alias from servers.toml / ~/.ssh/config, or user@host[:port]."`
	Mode           string   `json:"mode,omitempty" jsonschema:"Command policy: unrestricted (default), readonly (mutating tools blocked + built-in dangerous command list refused), restricted (commands must match allow regexes)."`
	Allow          []string `json:"allow,omitempty" jsonschema:"Allowlist regexes for mode=restricted."`
	Password       string   `json:"password,omitempty" jsonschema:"Password auth (tried after key/agent). Never logged."`
	PrivateKey     string   `json:"private_key,omitempty" jsonschema:"Path to a private key file (~ allowed)."`
	Passphrase     string   `json:"passphrase,omitempty" jsonschema:"Passphrase for the private key. Never logged."`
	UseAgent       *bool    `json:"use_agent,omitempty" jsonschema:"Try the local SSH agent (SSH_AUTH_SOCK; Windows named pipe). Default true."`
	UseSSHConfig   *bool    `json:"use_ssh_config,omitempty" jsonschema:"Resolve host/port/user/identity via ~/.ssh/config. Default true."`
	HostKeyPolicy  string   `json:"host_key_policy,omitempty" jsonschema:"accept-new (default, uses ~/.ssh/known_hosts) or off."`
	Cols           int      `json:"cols,omitempty" jsonschema:"PTY columns. Default 120."`
	Rows           int      `json:"rows,omitempty" jsonschema:"PTY rows. Default 32."`
	ConnectTimeout int64    `json:"connect_timeout_ms,omitempty" jsonschema:"Connect timeout in milliseconds. Default 15000."`
}

type SshOpenOut struct {
	SessionID  string `json:"session_id"`
	ShellKind  string `json:"shell_kind"`
	Target     string `json:"target"`
	AuthMethod string `json:"auth_method"`
	Name       string `json:"name,omitempty"`
	Mode       string `json:"mode"`
}

type SessionParams struct {
	SessionID string `json:"session_id"`
}

type ClosedOut struct {
	Closed bool `json:"closed"`
}

type ListEntry struct {
	SessionID string `json:"session_id"`
	Name      string `json:"name,omitempty"`
	Target    string `json:"target"`
	ShellKind string `json:"shell_kind"`
	Alive     bool   `json:"alive"`
	IdleSecs  int64  `json:"idle_secs"`
}

type ListOut struct {
	Sessions []ListEntry `json:"sessions"`
}

type SshAddServerParams struct {
	Name       string   `json:"name" jsonschema:"Registry name, usable as ssh_open(server=...) and as a proxy_jump hop. Must not be empty or contain whitespace/[ ] \\\" = #."`
	Host       string   `json:"host" jsonschema:"Hostname or IP."`
	Port       *int     `json:"port,omitempty"`
	User       string   `json:"user,omitempty"`
	Password   string   `json:"password,omitempty" jsonschema:"Stored in plaintext — prefer private_key. File gets chmod 600 on Unix when a password is present."`
	PrivateKey string   `json:"private_key,omitempty"`
	Passphrase string   `json:"passphrase,omitempty"`
	ProxyJump  string   `json:"proxy_jump,omitempty"`
	Mode       string   `json:"mode,omitempty" jsonschema:"unrestricted (default), readonly, or restricted."`
	Allow      []string `json:"allow,omitempty" jsonschema:"Allowlist regexes, used when mode=restricted."`
	Overwrite  bool     `json:"overwrite" jsonschema:"Replace an existing entry with the same name instead of erroring."`
}

type AddServerOut struct {
	Name        string `json:"name"`
	Path        string `json:"path"`
	Overwritten bool   `json:"overwritten"`
}

type ListServersOut struct {
	Servers   []ServerSummary `json:"servers"`
	LoadError string          `json:"load_error,omitempty"`
}

type SshShellParams struct {
	SessionID      string `json:"session_id"`
	Command        string `json:"command" jsonschema:"Shell command. Runs in the persistent shell: cwd/env survive."`
	TimeoutMS      int64  `json:"timeout_ms,omitempty" jsonschema:"Command timeout in milliseconds. Default 30000. On timeout returns partial output with timed_out=true (the command keeps running)."`
	MaxOutputBytes int64  `json:"max_output_bytes,omitempty" jsonschema:"Keep at most this many bytes of output (tail). Default 65536."`
	StripANSI      *bool  `json:"strip_ansi,omitempty" jsonschema:"Strip ANSI escape sequences (colors, readline artifacts) from output. Default true; set false to preserve colors/control sequences."`
}

type SshShellOut struct {
	Output       string `json:"output"`
	ExitCode     *int64 `json:"exit_code,omitempty"`
	TimedOut     bool   `json:"timed_out"`
	Truncated    bool   `json:"truncated"`
	StreamOffset int64  `json:"stream_offset"`
}

type SshTypeParams struct {
	SessionID string `json:"session_id"`
	Text      string `json:"text" jsonschema:"Text written verbatim to the PTY (no implicit newline — include \\n to submit)."`
}

type SeqOut struct {
	Seq          uint64 `json:"seq"`
	StreamOffset int64  `json:"stream_offset"`
}

type SshPressParams struct {
	SessionID string `json:"session_id"`
	Key       string `json:"key" jsonschema:"Key spec, e.g. q, enter, ctrl+c, ctrl+x, shift+tab, up, f5."`
}

type SshSignalParams struct {
	SessionID string `json:"session_id"`
	Signal    string `json:"signal" jsonschema:"sigint | sigquit | sigterm | sigkill | sighup | sigtstp"`
}

type SentOut struct {
	Sent bool `json:"sent"`
}

type SshExpectParams struct {
	SessionID  string `json:"session_id"`
	Pattern    string `json:"pattern" jsonschema:"Regex to wait for."`
	Mode       string `json:"mode,omitempty" jsonschema:"stream (default): match raw output arriving after from_offset. screen: match the rendered terminal screen."`
	FromOffset *int64 `json:"from_offset,omitempty" jsonschema:"Stream offset to start matching from — use the stream_offset returned by ssh_type/ssh_press/ssh_shell to avoid missing output that arrived between the triggering action and this call. Default: current end."`
	TimeoutMS  int64  `json:"timeout_ms,omitempty" jsonschema:"Wait timeout in milliseconds. Default 10000."`
	MaxBytes   int64  `json:"max_bytes,omitempty" jsonschema:"Max bytes of accumulated output returned on timeout/EOF. Default 65536."`
}

type SshExpectOut struct {
	Matched  bool     `json:"matched"`
	Text     string   `json:"text"`
	Captures []string `json:"captures"`
	TimedOut bool     `json:"timed_out"`
}

type SshScreenParams struct {
	SessionID string  `json:"session_id"`
	SinceSeq  *uint64 `json:"since_seq,omitempty" jsonschema:"Logical-clock anchor returned by ssh_type/ssh_press/ssh_shell."`
	Wait      string  `json:"wait,omitempty" jsonschema:"none: immediate. change: wait for any new output. quiet: wait for change then no output for settle_ms. Default none."`
	SettleMS  int64   `json:"settle_ms,omitempty" jsonschema:"Quiet-settle window in milliseconds. Default 250."`
	TimeoutMS int64   `json:"timeout_ms,omitempty" jsonschema:"Wait timeout in milliseconds. Default 10000."`
	TailLines *int    `json:"tail_lines,omitempty" jsonschema:"Return only the last N lines of the screen (e.g. 1 = just the prompt line). Default: full viewport."`
}

type SshScreenOut struct {
	Screen   string `json:"screen"`
	Seq      uint64 `json:"seq"`
	IdleMS   int64  `json:"idle_ms"`
	TimedOut bool   `json:"timed_out"`
}

type FileReadParams struct {
	SessionID string `json:"session_id"`
	Path      string `json:"path"`
	Offset    int64  `json:"offset,omitempty" jsonschema:"Byte offset to start reading from. Default 0."`
	Limit     int64  `json:"limit,omitempty" jsonschema:"Max bytes to read. Default 262144."`
}

type FileReadOut struct {
	Content string `json:"content"`
	Size    int64  `json:"size"`
	EOF     bool   `json:"eof"`
}

type FileWriteParams struct {
	SessionID string `json:"session_id"`
	Path      string `json:"path"`
	Content   string `json:"content" jsonschema:"UTF-8 text only — for binary content, stage it locally and use ssh_upload."`
	Mode      string `json:"mode,omitempty" jsonschema:"overwrite (default; requires a prior full file_read) or append."`
}

type FileWriteOut struct {
	BytesWritten int64 `json:"bytes_written"`
}

type TransferParams struct {
	SessionID  string `json:"session_id"`
	LocalPath  string `json:"local_path"`
	RemotePath string `json:"remote_path"`
}

type SshCopyParams struct {
	FromSession string `json:"from_session"`
	FromPath    string `json:"from_path"`
	ToSession   string `json:"to_session"`
	ToPath      string `json:"to_path"`
}

type TransferOut struct {
	Bytes int64 `json:"bytes"`
}

type SshExecParams struct {
	SessionID      string `json:"session_id"`
	Command        string `json:"command" jsonschema:"Command executed via a one-shot SSH exec channel (stateless: no cwd/env carryover, no interaction with the persistent shell)."`
	TimeoutMS      int64  `json:"timeout_ms,omitempty" jsonschema:"Timeout in milliseconds. Default 30000."`
	MaxOutputBytes int64  `json:"max_output_bytes,omitempty" jsonschema:"Max bytes kept per stream (tail). Default 65536."`
	StripANSI      *bool  `json:"strip_ansi,omitempty" jsonschema:"Strip ANSI escape sequences. Default true."`
}

type SshExecOut struct {
	Stdout    string `json:"stdout"`
	Stderr    string `json:"stderr"`
	ExitCode  *int64 `json:"exit_code,omitempty"`
	TimedOut  bool   `json:"timed_out"`
	Truncated bool   `json:"truncated"`
}

type SshReadyParams struct {
	SessionID      string `json:"session_id"`
	ProbeTimeoutMS int64  `json:"probe_timeout_ms,omitempty" jsonschema:"How long to wait for the shell to answer, in milliseconds. Default 2000."`
}

type SshReadyOut struct {
	Ready bool `json:"ready"`
}

type SshShellAsyncParams struct {
	SessionID      string `json:"session_id"`
	Command        string `json:"command"`
	TimeoutMS      int64  `json:"timeout_ms,omitempty" jsonschema:"Command timeout in milliseconds. Default 600000."`
	MaxOutputBytes int64  `json:"max_output_bytes,omitempty" jsonschema:"Keep at most this many bytes of output (tail). Default 65536."`
	StripANSI      *bool  `json:"strip_ansi,omitempty"`
}

type SshShellAsyncOut struct {
	TaskID string `json:"task_id"`
}

type SshTaskStatusParams struct {
	TaskID string `json:"task_id"`
	WaitMS int64  `json:"wait_ms,omitempty" jsonschema:"Block up to this long waiting for completion. Default 0 (instant)."`
}

type SshTaskCancelParams struct {
	TaskID string `json:"task_id"`
}

type SshTaskCancelOut struct {
	Cancelled bool `json:"cancelled"`
}

type SshTaskStatusOut struct {
	Status   string `json:"status"`
	Output   string `json:"output,omitempty"`
	ExitCode *int64 `json:"exit_code,omitempty"`
	TimedOut *bool  `json:"timed_out,omitempty"`
	Error    string `json:"error,omitempty"`
}

type FileEditParams struct {
	SessionID  string `json:"session_id"`
	Path       string `json:"path"`
	OldString  string `json:"old_string" jsonschema:"Exact text to find. Must match at least once; multiple matches are an error unless replace_all is set."`
	NewString  string `json:"new_string"`
	ReplaceAll bool   `json:"replace_all,omitempty"`
}

type FileEditOut struct {
	Replacements int64  `json:"replacements"`
	Context      string `json:"context"`
}

// ── Shared helpers ──────────────────────────────────────────────────────────

var ansiRe = regexp.MustCompile("\x1b\\[[0-9;?]*[ -/]*[@-~]|\x1b\\][^\x07\x1b]*(?:\x07|\x1b\\\\)")

func tailChars(s string, max int) string {
	if len(s) <= max {
		return s
	}
	start := len(s) - max
	for start < len(s) && !utf8.RuneStart(s[start]) {
		start++
	}
	return s[start:]
}

func stripANSI(s string) string {
	return ansiRe.ReplaceAllString(s, "")
}

func trimOutput(s string) string {
	return strings.TrimRightFunc(strings.TrimLeft(s, "\r\n"), unicode.IsSpace)
}

func randToken() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		binary.LittleEndian.PutUint32(b[:], uint32(time.Now().UnixNano()))
	}
	return fmt.Sprintf("%08x", binary.LittleEndian.Uint32(b[:]))
}

func defaultTrue(p *bool) bool { return p == nil || *p }

func int64Or(p *int64, d int64) int64 {
	if p == nil || *p == 0 {
		return d
	}
	return *p
}

func intOrZero(v int, d int) int {
	if v == 0 {
		return d
	}
	return v
}

// checkMutation gates mutating file tools in readonly mode.
func checkMutation(s *Session, tool string) error {
	if s.Mode.Label() == "readonly" {
		return invalid(fmt.Sprintf("blocked by session mode=readonly: %s is a mutating operation", tool))
	}
	return nil
}

// guardCheck enforces the read-before-write rule: overwrite of an existing
// non-empty file requires full read coverage tagged with the current
// (size, mtime) fingerprint.
func guardCheck(s *Session, real string, fp Fingerprint, tool string) error {
	cov := s.Coverage(real)
	missing := cov.Missing(interval{0, fp.Size, fp}, fp)
	if len(missing) == 0 {
		return nil
	}
	ranges := make([]string, len(missing))
	for i, g := range missing {
		ranges[i] = fmt.Sprintf("[%d, %d)", g.start, g.end)
	}
	return invalid(fmt.Sprintf("%s denied: %s not fully read (missing %s) or changed since read; run file_read first",
		tool, real, strings.Join(ranges, ", ")))
}

func realPath(sc *sftp.Client, path string) string {
	if real, err := sc.RealPath(path); err == nil {
		return real
	}
	return path
}

// devInode returns the dev:inode identity of a remote path via a one-shot
// exec channel (SFTP v3 attributes carry no inode).
func devInode(s *Session, path string) string {
	q := strings.ReplaceAll(path, "'", `'\''`)
	cmd := fmt.Sprintf("stat -c '%%d:%%i' -- '%s' 2>/dev/null || stat -f '%%d:%%i' -- '%s'", q, q)
	out, _, err := execCollect(s, cmd, 10*time.Second)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// execCollect runs a command on a one-shot exec channel and returns
// (stdout, stderr, error). No PTY, protocol-level exit when available.
func execCollect(s *Session, cmd string, timeout time.Duration) ([]byte, []byte, error) {
	sess, err := s.Client.NewSession()
	if err != nil {
		return nil, nil, err
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		sess.Close()
		return nil, nil, err
	}
	stderr, err := sess.StderrPipe()
	if err != nil {
		sess.Close()
		return nil, nil, err
	}
	if err := sess.Start(cmd); err != nil {
		sess.Close()
		return nil, nil, err
	}
	var outBuf, errBuf []byte
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		outBuf, _ = io.ReadAll(stdout)
	}()
	go func() {
		defer wg.Done()
		errBuf, _ = io.ReadAll(stderr)
	}()
	waitDone := make(chan error, 1)
	go func() { waitDone <- sess.Wait() }()
	var waitErr error
	select {
	case waitErr = <-waitDone:
	case <-time.After(timeout):
		sess.Close()
		<-waitDone
		waitErr = errors.New("timeout")
	}
	wg.Wait()
	return outBuf, errBuf, waitErr
}

// ── runCore ─────────────────────────────────────────────────────────────────

// runCore is the shared ssh_shell implementation, also driven by
// ssh_shell_async tasks.
func (srv *Server) runCore(s *Session, command string, timeout time.Duration, maxOutput int64, strip bool) (*SshShellOut, error) {
	if blocked, reason := s.Mode.Check(command); blocked {
		return nil, invalid(reason)
	}
	if s.Shell != ShellPosix {
		return nil, invalid(fmt.Sprintf("ssh_shell requires a POSIX-like shell (this session is %s); use ssh_exec for one-shot commands or ssh_type + ssh_expect for interactive work", s.Shell))
	}
	s.ioMu.Lock()
	defer s.ioMu.Unlock()
	// Let any in-flight output/typing settle.
	waitScreen(s.Shared, nil, WaitQuiet, 100*time.Millisecond, time.Second)

	start := s.Shared.EndOffset()
	tok := randToken()
	preMarker := fmt.Sprintf("__SPM_PRE_%s__", tok)
	// Echo-toggle handshake (event-driven, no fixed sleeps). %s indirection:
	// the echoed PRE line contains the format string, only the real printf
	// output contains the marker.
	if err := s.Write([]byte(fmt.Sprintf(" __spm_ps1=$PS1; PS1=; stty -echo; printf '__SPM_PRE_%%s__\\n' %s\n", tok))); err != nil {
		return nil, internalErr(err)
	}
	preTimeout := timeout
	if preTimeout > 5*time.Second {
		preTimeout = 5 * time.Second
	}
	if !waitStreamContains(s.Shared, start, []byte(preMarker), preTimeout) {
		return nil, internalMsg("shell did not acknowledge echo toggle: it is busy or an interactive program (vi/passwd/ssh) is running — the scaffolding line may have been consumed by it; inspect with ssh_screen before retrying")
	}
	// Let the post-PRE prompt redraw finish so it cannot leak into the
	// captured output region.
	waitScreen(s.Shared, nil, WaitQuiet, 150*time.Millisecond, 2*time.Second)

	cmdStart := s.Shared.EndOffset()
	if s.bracketedPaste {
		if err := s.Write([]byte("\x1b[200~" + command + "\x1b[201~\n")); err != nil {
			return nil, internalErr(err)
		}
	} else {
		if err := s.Write([]byte(command + "\n")); err != nil {
			return nil, internalErr(err)
		}
	}
	// Scaffold line (leading space, echo off → invisible, unrecorded)
	// captures rc BEFORE `stty echo` clobbers $?.
	if err := s.Write([]byte(fmt.Sprintf(" rc=$?; stty echo; PS1=$__spm_ps1; printf '\\n__SPM_%s_%%d__\\n' $rc\n", tok))); err != nil {
		return nil, internalErr(err)
	}

	deadline := time.Now().Add(timeout)
	var markerOff int64
	var rc int64
	found := false
	for {
		b, _, _ := s.Shared.ReadStream(cmdStart)
		if off, code, ok := findMarker(b, cmdStart, tok); ok {
			markerOff, rc, found = off, code, true
			break
		}
		if s.Shared.EOF() {
			break
		}
		if remaining := time.Until(deadline); remaining > 0 {
			waitNotify(s.Shared, remaining)
		} else {
			break
		}
	}

	b, endOffset, _ := s.Shared.ReadStream(cmdStart)
	output := ""
	var exitCode *int64
	timedOut := false
	if found {
		end := markerOff - cmdStart
		if end > int64(len(b)) {
			end = int64(len(b))
		}
		output = string(b[:end])
		for len(output) > 0 && (output[0] == '\r' || output[0] == '\n') {
			output = output[1:]
		}
		output = strings.TrimRightFunc(output, unicode.IsSpace)
		exitCode = &rc
	} else {
		output = strings.TrimRightFunc(string(b), unicode.IsSpace)
		timedOut = true
	}
	if strip {
		output = stripANSI(output)
	}
	// Post-strip residue (CRs that followed removed escape sequences).
	output = trimOutput(output)
	truncated := int64(len(output)) > maxOutput
	output = tailChars(output, int(maxOutput))
	srv.audit.Log(s.ID, "ssh_shell", map[string]any{
		"command":   command,
		"exit_code": exitCode,
		"timed_out": timedOut,
	})
	return &SshShellOut{
		Output:       output,
		ExitCode:     exitCode,
		TimedOut:     timedOut,
		Truncated:    truncated,
		StreamOffset: endOffset,
	}, nil
}

// waitNotify sleeps until the shared state broadcasts or the timeout elapses.
func waitNotify(s *Shared, d time.Duration) {
	ch := s.NotifyChan()
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ch:
	case <-timer.C:
	}
}

// ── ssh_open ────────────────────────────────────────────────────────────────

func (srv *Server) sshOpen(ctx context.Context, req *mcp.CallToolRequest, p SshOpenParams) (*mcp.CallToolResult, SshOpenOut, error) {
	srv.sessions.PruneDead()
	if len(srv.sessions.List()) >= srv.maxSessions {
		return nil, SshOpenOut{}, invalid(fmt.Sprintf("session limit reached (%d); close unused sessions with ssh_close first", srv.maxSessions))
	}
	if p.Name != "" {
		if strings.TrimSpace(p.Name) == "" {
			return nil, SshOpenOut{}, invalid("session name must not be empty or whitespace")
		}
		for _, s := range srv.sessions.List() {
			if s.Name == p.Name {
				return nil, SshOpenOut{}, invalid(fmt.Sprintf("session name '%s' is already in use", p.Name))
			}
		}
	}
	var policy HostKeyPolicy
	switch p.HostKeyPolicy {
	case "", "accept-new":
		policy = HostKeyAcceptNew
	case "off":
		policy = HostKeyOff
	default:
		return nil, SshOpenOut{}, invalid(fmt.Sprintf("host_key_policy must be \"accept-new\" or \"off\", got '%s'", p.HostKeyPolicy))
	}
	// Merge order: explicit params > servers.toml > ~/.ssh/config.
	var entry *ServerEntry
	if p.Server != "" {
		file, problem := LoadServersVerbose()
		e, ok := file.Servers[p.Server]
		switch {
		case ok:
			entry = &e
		case problem != nil:
			return nil, SshOpenOut{}, invalid(fmt.Sprintf("server '%s' not found in %s (registry broken: %s); call ssh_list_servers", p.Server, ServersPath(), *problem))
		default:
			detail := ""
			if _, err := os.Stat(ServersPath()); errors.Is(err, os.ErrNotExist) {
				detail = " (file does not exist)"
			}
			return nil, SshOpenOut{}, invalid(fmt.Sprintf("server '%s' not found in %s%s; call ssh_list_servers", p.Server, ServersPath(), detail))
		}
	}
	host := p.Host
	if host == "" && entry != nil {
		host = entry.Host
	}
	if host == "" {
		return nil, SshOpenOut{}, invalid("host is required (not supplied, not in servers.toml entry)")
	}
	modeStr := p.Mode
	if modeStr == "" && entry != nil {
		modeStr = entry.Mode
	}
	allow := p.Allow
	if len(allow) == 0 && entry != nil {
		allow = entry.Allow
	}
	if modeStr == "" {
		modeStr = "unrestricted"
	}
	var mode SessionMode
	switch modeStr {
	case "unrestricted":
		mode = modeUnrestricted
	case "readonly":
		mode = modeReadOnly
	case "restricted":
		if len(allow) == 0 {
			return nil, SshOpenOut{}, invalid("mode=restricted requires `allow` regexes (or `allow` in the servers.toml entry)")
		}
		var err error
		mode, err = ModeRestricted(allow)
		if err != nil {
			return nil, SshOpenOut{}, invalid(err.Error())
		}
	default:
		return nil, SshOpenOut{}, invalid(fmt.Sprintf("mode must be unrestricted|readonly|restricted, got '%s'", modeStr))
	}
	port := 0
	if p.Port != nil {
		port = *p.Port
	} else if entry != nil && entry.Port != nil {
		port = *entry.Port
	}
	pickStr := func(explicit string, e *ServerEntry, get func(*ServerEntry) string) string {
		if explicit != "" {
			return explicit
		}
		if e != nil {
			return get(e)
		}
		return ""
	}
	user := pickStr(p.User, entry, func(e *ServerEntry) string { return e.User })
	proxyJump := pickStr(p.ProxyJump, entry, func(e *ServerEntry) string { return e.ProxyJump })
	password := pickStr(p.Password, entry, func(e *ServerEntry) string { return e.Password })
	privateKey := pickStr(p.PrivateKey, entry, func(e *ServerEntry) string { return e.PrivateKey })
	passphrase := pickStr(p.Passphrase, entry, func(e *ServerEntry) string { return e.Passphrase })
	useAgent := defaultTrue(p.UseAgent)
	if entry != nil && entry.UseAgent != nil {
		useAgent = *entry.UseAgent
	}
	cp := &ConnectParams{
		Host:           host,
		Port:           port,
		User:           user,
		Name:           p.Name,
		ProxyJump:      proxyJump,
		Mode:           mode,
		Password:       password,
		PrivateKey:     privateKey,
		Passphrase:     passphrase,
		UseAgent:       useAgent,
		UseSSHConfig:   defaultTrue(p.UseSSHConfig),
		HostKeyPolicy:  policy,
		Cols:           intOrZero(p.Cols, 120),
		Rows:           intOrZero(p.Rows, 32),
		ConnectTimeout: time.Duration(int64Or(&p.ConnectTimeout, 15000)) * time.Millisecond,
	}
	opened, err := Open(cp, srv.sessions)
	if err != nil {
		return nil, SshOpenOut{}, internalErr(err)
	}
	srv.sessions.Insert(opened.Session)
	s := opened.Session
	srv.audit.Log(s.ID, "ssh_open", map[string]any{
		"target":          s.Target,
		"auth_method":     opened.AuthMethod,
		"host_key_policy": p.HostKeyPolicy,
	})
	return nil, SshOpenOut{
		SessionID:  s.ID,
		ShellKind:  s.Shell.String(),
		Target:     s.Target,
		AuthMethod: opened.AuthMethod,
		Name:       s.Name,
		Mode:       s.Mode.Label(),
	}, nil
}

// ── ssh_close / ssh_list ────────────────────────────────────────────────────

func (srv *Server) sshClose(ctx context.Context, req *mcp.CallToolRequest, p SessionParams) (*mcp.CallToolResult, ClosedOut, error) {
	s := srv.sessions.Find(p.SessionID)
	if s == nil {
		return nil, ClosedOut{}, invalid(fmt.Sprintf("unknown session '%s'", p.SessionID))
	}
	s = srv.sessions.Remove(s.ID)
	s.Close()
	srv.audit.Log(s.ID, "ssh_close", map[string]any{})
	return nil, ClosedOut{Closed: true}, nil
}

func (srv *Server) sshList(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, ListOut, error) {
	srv.sessions.PruneDead()
	entries := []ListEntry{}
	for _, s := range srv.sessions.List() {
		entries = append(entries, ListEntry{
			SessionID: s.ID,
			Name:      s.Name,
			Target:    s.Target,
			ShellKind: s.Shell.String(),
			Alive:     s.alive.Load(),
			IdleSecs:  int64(time.Since(s.Shared.LastOutputAt()) / time.Second),
		})
	}
	return nil, ListOut{Sessions: entries}, nil
}

// ── servers registry tools ──────────────────────────────────────────────────

func (srv *Server) sshListServers(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, ListServersOut, error) {
	_, problem := LoadServersVerbose()
	out := ListServersOut{Servers: ListServerSummaries()}
	if problem != nil {
		out.LoadError = *problem
	}
	return nil, out, nil
}

func (srv *Server) sshAddServer(ctx context.Context, req *mcp.CallToolRequest, p SshAddServerParams) (*mcp.CallToolResult, AddServerOut, error) {
	if err := ValidateServerName(p.Name); err != nil {
		return nil, AddServerOut{}, invalid(err.Error())
	}
	if strings.TrimSpace(p.Host) == "" {
		return nil, AddServerOut{}, invalid("host must not be empty")
	}
	if p.Mode != "" && !map[string]bool{"unrestricted": true, "readonly": true, "restricted": true}[p.Mode] {
		return nil, AddServerOut{}, invalid(fmt.Sprintf("mode must be \"unrestricted\", \"readonly\", or \"restricted\", got '%s'", p.Mode))
	}
	overwritten, path, err := AddServer(p.Name, AddServerFields{
		Host:       p.Host,
		Port:       p.Port,
		User:       p.User,
		Password:   p.Password,
		PrivateKey: p.PrivateKey,
		Passphrase: p.Passphrase,
		ProxyJump:  p.ProxyJump,
		Mode:       p.Mode,
		Allow:      p.Allow,
	}, p.Overwrite)
	if err != nil {
		return nil, AddServerOut{}, invalid(err.Error())
	}
	srv.audit.Log("config", "ssh_add_server", map[string]any{"name": p.Name, "path": path, "overwritten": overwritten})
	return nil, AddServerOut{Name: p.Name, Path: path, Overwritten: overwritten}, nil
}

// ── ssh_shell family ────────────────────────────────────────────────────────

func (srv *Server) sshShell(ctx context.Context, req *mcp.CallToolRequest, p SshShellParams) (*mcp.CallToolResult, *SshShellOut, error) {
	s, err := srv.liveSession(p.SessionID)
	if err != nil {
		return nil, nil, err
	}
	out, err := srv.runCore(s, p.Command,
		time.Duration(int64Or(&p.TimeoutMS, 30000))*time.Millisecond,
		int64Or(&p.MaxOutputBytes, 65536),
		defaultTrue(p.StripANSI))
	if err != nil {
		return nil, nil, err
	}
	return nil, out, nil
}

func (srv *Server) sshShellAsync(ctx context.Context, req *mcp.CallToolRequest, p SshShellAsyncParams) (*mcp.CallToolResult, SshShellAsyncOut, error) {
	s, err := srv.liveSession(p.SessionID)
	if err != nil {
		return nil, SshShellAsyncOut{}, err
	}
	if s.Shell != ShellPosix {
		return nil, SshShellAsyncOut{}, invalid(fmt.Sprintf("ssh_shell_async requires a POSIX-like shell (this session is %s); use ssh_exec for one-shot commands or ssh_type + ssh_expect for interactive work", s.Shell))
	}
	taskID := fmt.Sprintf("t%d", srv.nextTask.Add(1))
	entry := &taskEntry{sessionID: s.ID}
	srv.tasksMu.Lock()
	srv.tasks[taskID] = entry
	srv.tasksMu.Unlock()
	go func() {
		out, err := srv.runCore(s, p.Command,
			time.Duration(int64Or(&p.TimeoutMS, 600000))*time.Millisecond,
			int64Or(&p.MaxOutputBytes, 65536),
			defaultTrue(p.StripANSI))
		entry.mu.Lock()
		defer entry.mu.Unlock()
		if entry.cancelled {
			return
		}
		entry.done = true
		if err != nil {
			entry.err = err.Error()
		} else {
			entry.result = out
		}
	}()
	return nil, SshShellAsyncOut{TaskID: taskID}, nil
}

func (srv *Server) sshTaskStatus(ctx context.Context, req *mcp.CallToolRequest, p SshTaskStatusParams) (*mcp.CallToolResult, SshTaskStatusOut, error) {
	deadline := time.Now().Add(time.Duration(p.WaitMS) * time.Millisecond)
	for {
		srv.tasksMu.Lock()
		entry, ok := srv.tasks[p.TaskID]
		srv.tasksMu.Unlock()
		if !ok {
			return nil, SshTaskStatusOut{}, invalid(fmt.Sprintf("unknown task '%s' (from ssh_shell_async)", p.TaskID))
		}
		entry.mu.Lock()
		if entry.done {
			out := SshTaskStatusOut{}
			if entry.err != "" {
				out.Status = "error"
				out.Error = entry.err
			} else {
				out.Status = "done"
				out.Output = entry.result.Output
				out.ExitCode = entry.result.ExitCode
				out.TimedOut = &entry.result.TimedOut
			}
			entry.mu.Unlock()
			return nil, out, nil
		}
		entry.mu.Unlock()
		if !time.Now().Before(deadline) {
			return nil, SshTaskStatusOut{Status: "running"}, nil
		}
		select {
		case <-time.After(100 * time.Millisecond):
		case <-ctx.Done():
			return nil, SshTaskStatusOut{Status: "running"}, nil
		}
	}
}

func (srv *Server) sshTaskCancel(ctx context.Context, req *mcp.CallToolRequest, p SshTaskCancelParams) (*mcp.CallToolResult, SshTaskCancelOut, error) {
	srv.tasksMu.Lock()
	entry, ok := srv.tasks[p.TaskID]
	srv.tasksMu.Unlock()
	if !ok {
		return nil, SshTaskCancelOut{}, invalid(fmt.Sprintf("unknown task '%s'", p.TaskID))
	}
	entry.mu.Lock()
	if entry.done {
		entry.mu.Unlock()
		return nil, SshTaskCancelOut{Cancelled: false}, nil
	}
	entry.cancelled = true
	entry.done = true
	entry.err = "cancelled"
	sessionID := entry.sessionID
	entry.mu.Unlock()
	// Interrupt the remote foreground command; the queued scaffold lines
	// then run, returning the shell to a clean prompt state.
	if s := srv.sessions.Find(sessionID); s != nil {
		_ = s.Write([]byte{0x03})
	}
	srv.audit.Log(sessionID, "ssh_task_cancel", map[string]any{"task_id": p.TaskID})
	return nil, SshTaskCancelOut{Cancelled: true}, nil
}

// ── ssh_exec ────────────────────────────────────────────────────────────────

func (srv *Server) sshExec(ctx context.Context, req *mcp.CallToolRequest, p SshExecParams) (*mcp.CallToolResult, SshExecOut, error) {
	s, err := srv.liveSession(p.SessionID)
	if err != nil {
		return nil, SshExecOut{}, err
	}
	if blocked, reason := s.Mode.Check(p.Command); blocked {
		return nil, SshExecOut{}, invalid(reason)
	}
	timeout := time.Duration(int64Or(&p.TimeoutMS, 30000)) * time.Millisecond
	maxOut := int64Or(&p.MaxOutputBytes, 65536)
	sess, err := s.Client.NewSession()
	if err != nil {
		return nil, SshExecOut{}, internalErr(err)
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		sess.Close()
		return nil, SshExecOut{}, internalErr(err)
	}
	stderr, err := sess.StderrPipe()
	if err != nil {
		sess.Close()
		return nil, SshExecOut{}, internalErr(err)
	}
	if err := sess.Start(p.Command); err != nil {
		sess.Close()
		return nil, SshExecOut{}, internalErr(err)
	}
	var outBuf, errBuf []byte
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); outBuf, _ = io.ReadAll(stdout) }()
	go func() { defer wg.Done(); errBuf, _ = io.ReadAll(stderr) }()
	waitDone := make(chan error, 1)
	go func() { waitDone <- sess.Wait() }()
	timedOut := false
	var waitErr error
	select {
	case waitErr = <-waitDone:
	case <-time.After(timeout):
		timedOut = true
		sess.Close()
		<-waitDone
	}
	wg.Wait()
	truncated := int64(len(outBuf)) > maxOut || int64(len(errBuf)) > maxOut
	var exitCode *int64
	if !timedOut {
		var ee *ssh.ExitError
		var em *ssh.ExitMissingError
		switch {
		case errors.As(waitErr, &ee):
			code := int64(ee.ExitStatus())
			exitCode = &code
		case errors.As(waitErr, &em):
			// Server omitted exit status.
		case waitErr == nil:
			code := int64(0)
			exitCode = &code
		}
	}
	clean := func(b []byte) string {
		str := strings.TrimRightFunc(string(b), unicode.IsSpace)
		if defaultTrue(p.StripANSI) {
			str = stripANSI(str)
		}
		return tailChars(str, int(maxOut))
	}
	srv.audit.Log(s.ID, "ssh_exec", map[string]any{
		"command":   p.Command,
		"exit_code": exitCode,
		"timed_out": timedOut,
	})
	return nil, SshExecOut{
		Stdout:    clean(outBuf),
		Stderr:    clean(errBuf),
		ExitCode:  exitCode,
		TimedOut:  timedOut,
		Truncated: truncated,
	}, nil
}

// ── keyboard / signals ──────────────────────────────────────────────────────

func (srv *Server) sshType(ctx context.Context, req *mcp.CallToolRequest, p SshTypeParams) (*mcp.CallToolResult, SeqOut, error) {
	s, err := srv.liveSession(p.SessionID)
	if err != nil {
		return nil, SeqOut{}, err
	}
	s.ioMu.Lock()
	defer s.ioMu.Unlock()
	if err := s.Write([]byte(p.Text)); err != nil {
		return nil, SeqOut{}, internalErr(err)
	}
	srv.audit.Log(s.ID, "ssh_type", map[string]any{"chars": len(p.Text)})
	return nil, SeqOut{Seq: s.Shared.Seq(), StreamOffset: s.Shared.EndOffset()}, nil
}

func (srv *Server) sshPress(ctx context.Context, req *mcp.CallToolRequest, p SshPressParams) (*mcp.CallToolResult, SeqOut, error) {
	s, err := srv.liveSession(p.SessionID)
	if err != nil {
		return nil, SeqOut{}, err
	}
	b, err := MapKey(p.Key)
	if err != nil {
		return nil, SeqOut{}, invalid(err.Error())
	}
	s.ioMu.Lock()
	defer s.ioMu.Unlock()
	if err := s.Write(b); err != nil {
		return nil, SeqOut{}, internalErr(err)
	}
	srv.audit.Log(s.ID, "ssh_press", map[string]any{"key": p.Key})
	return nil, SeqOut{Seq: s.Shared.Seq(), StreamOffset: s.Shared.EndOffset()}, nil
}

func (srv *Server) sshSignal(ctx context.Context, req *mcp.CallToolRequest, p SshSignalParams) (*mcp.CallToolResult, SentOut, error) {
	s, err := srv.liveSession(p.SessionID)
	if err != nil {
		return nil, SentOut{}, err
	}
	var sig ssh.Signal
	switch strings.ToLower(p.Signal) {
	case "sigint":
		sig = ssh.SIGINT
	case "sigquit":
		sig = ssh.SIGQUIT
	case "sigterm":
		sig = ssh.SIGTERM
	case "sigkill":
		sig = ssh.SIGKILL
	case "sighup":
		sig = ssh.SIGHUP
	case "sigtstp":
		sig = ssh.Signal("TSTP")
	default:
		return nil, SentOut{}, invalid(fmt.Sprintf("unknown signal '%s' (sigint|sigquit|sigterm|sigkill|sighup|sigtstp)", p.Signal))
	}
	s.ioMu.Lock()
	defer s.ioMu.Unlock()
	if err := s.Channel.Signal(sig); err != nil {
		return nil, SentOut{}, internalErr(err)
	}
	srv.audit.Log(s.ID, "ssh_signal", map[string]any{"signal": p.Signal})
	return nil, SentOut{Sent: true}, nil
}

// ── expect / screen / ready ─────────────────────────────────────────────────

func (srv *Server) sshExpect(ctx context.Context, req *mcp.CallToolRequest, p SshExpectParams) (*mcp.CallToolResult, SshExpectOut, error) {
	s, err := srv.liveSession(p.SessionID)
	if err != nil {
		return nil, SshExpectOut{}, err
	}
	re, err := regexp.Compile(p.Pattern)
	if err != nil {
		return nil, SshExpectOut{}, invalid(fmt.Sprintf("invalid regex: %v", err))
	}
	screenMode := false
	switch p.Mode {
	case "", "stream":
	case "screen":
		screenMode = true
	default:
		return nil, SshExpectOut{}, invalid(fmt.Sprintf("mode must be \"stream\" or \"screen\", got '%s'", p.Mode))
	}
	start := s.Shared.EndOffset()
	if p.FromOffset != nil {
		start = *p.FromOffset
	}
	maxBytes := int64Or(&p.MaxBytes, 65536)
	deadline := time.Now().Add(time.Duration(int64Or(&p.TimeoutMS, 10000)) * time.Millisecond)
	haystack := func() string {
		if screenMode {
			s.Shared.mu.Lock()
			defer s.Shared.mu.Unlock()
			return screenText(s.Shared.st.parser)
		}
		b, _, _ := s.Shared.ReadStream(start)
		return string(b)
	}
	for {
		hay := haystack()
		if loc := re.FindStringSubmatchIndex(hay); loc != nil {
			groups := []string{}
			for i := 1; i < len(loc); i += 2 {
				if loc[i] < 0 {
					groups = append(groups, "")
				} else {
					groups = append(groups, hay[loc[i-1]:loc[i]])
				}
			}
			text := hay
			if !screenMode {
				text = hay[:loc[1]]
			}
			return nil, SshExpectOut{Matched: true, Text: text, Captures: groups}, nil
		}
		if s.Shared.EOF() {
			return nil, SshExpectOut{Matched: false, Text: tailChars(hay, int(maxBytes)), Captures: []string{}}, nil
		}
		if remaining := time.Until(deadline); remaining > 0 {
			waitNotify(s.Shared, remaining)
		} else {
			hay := haystack()
			return nil, SshExpectOut{Matched: false, Text: tailChars(hay, int(maxBytes)), Captures: []string{}, TimedOut: true}, nil
		}
	}
}

func (srv *Server) sshScreen(ctx context.Context, req *mcp.CallToolRequest, p SshScreenParams) (*mcp.CallToolResult, SshScreenOut, error) {
	s, err := srv.liveSession(p.SessionID)
	if err != nil {
		return nil, SshScreenOut{}, err
	}
	var mode WaitMode
	switch p.Wait {
	case "", "none":
		mode = WaitNone
	case "change":
		mode = WaitChange
	case "quiet":
		mode = WaitQuiet
	default:
		return nil, SshScreenOut{}, invalid(fmt.Sprintf("wait must be \"none\"|\"change\"|\"quiet\", got '%s'", p.Wait))
	}
	screen, seq, idle, timedOut := waitScreen(s.Shared, p.SinceSeq, mode,
		time.Duration(int64Or(&p.SettleMS, 250))*time.Millisecond,
		time.Duration(int64Or(&p.TimeoutMS, 10000))*time.Millisecond)
	if p.TailLines != nil && *p.TailLines > 0 {
		lines := strings.Split(screen, "\n")
		n := *p.TailLines
		if n < len(lines) {
			lines = lines[len(lines)-n:]
		}
		screen = strings.Join(lines, "\n")
	}
	return nil, SshScreenOut{Screen: screen, Seq: seq, IdleMS: idle.Milliseconds(), TimedOut: timedOut}, nil
}

func (srv *Server) sshReady(ctx context.Context, req *mcp.CallToolRequest, p SshReadyParams) (*mcp.CallToolResult, SshReadyOut, error) {
	s, err := srv.liveSession(p.SessionID)
	if err != nil {
		return nil, SshReadyOut{}, err
	}
	s.ioMu.Lock()
	defer s.ioMu.Unlock()
	start := s.Shared.EndOffset()
	tok := randToken()
	probeTimeout := time.Duration(int64Or(&p.ProbeTimeoutMS, 2000)) * time.Millisecond
	var probe, needle []byte
	switch s.Shell {
	case ShellPowerShell:
		probe = []byte(fmt.Sprintf("echo ('__SPM_RDY_' + '%s')\r", tok))
		needle = []byte(fmt.Sprintf("__SPM_RDY_%s", tok))
	case ShellCmd:
		probe = []byte("ver\r")
		needle = []byte("Windows")
	default: // Posix and Unknown
		probe = []byte(fmt.Sprintf(" printf '__SPM_RDY_%%s__\\n' %s\n", tok))
		needle = []byte(fmt.Sprintf("__SPM_RDY_%s", tok))
	}
	if err := s.Write(probe); err != nil {
		return nil, SshReadyOut{}, internalErr(err)
	}
	ready := waitStreamContains(s.Shared, start, needle, probeTimeout)
	return nil, SshReadyOut{Ready: ready}, nil
}

// ── file tools ──────────────────────────────────────────────────────────────

func (srv *Server) fileRead(ctx context.Context, req *mcp.CallToolRequest, p FileReadParams) (*mcp.CallToolResult, FileReadOut, error) {
	s, err := srv.liveSession(p.SessionID)
	if err != nil {
		return nil, FileReadOut{}, err
	}
	sc, err := s.SFTP()
	if err != nil {
		return nil, FileReadOut{}, internalErr(err)
	}
	real := realPath(sc, p.Path)
	fi, err := sc.Stat(real)
	if err != nil {
		return nil, FileReadOut{}, invalid(fmt.Sprintf("cannot stat %s: %v", real, err))
	}
	fp := Fingerprint{Size: uint64(fi.Size()), Mtime: uint32(fi.ModTime().Unix())}
	f, err := sc.Open(real)
	if err != nil {
		return nil, FileReadOut{}, internalErr(err)
	}
	defer f.Close()
	limit := int64Or(&p.Limit, 262144)
	buf := make([]byte, limit)
	got := int64(0)
	for got < limit {
		n, err := f.ReadAt(buf[got:limit], p.Offset+got)
		got += int64(n)
		if err != nil {
			break
		}
	}
	content := buf[:got]
	if !utf8.Valid(content) {
		return nil, FileReadOut{}, invalid(fmt.Sprintf("%s is not valid UTF-8 (binary file); use ssh_download", real))
	}
	s.Coverage(real).Record(uint64(p.Offset), uint64(p.Offset)+uint64(got), fp)
	return nil, FileReadOut{
		Content: string(content),
		Size:    int64(fp.Size),
		EOF:     p.Offset+got >= int64(fp.Size),
	}, nil
}

func (srv *Server) fileWrite(ctx context.Context, req *mcp.CallToolRequest, p FileWriteParams) (*mcp.CallToolResult, FileWriteOut, error) {
	s, err := srv.liveSession(p.SessionID)
	if err != nil {
		return nil, FileWriteOut{}, err
	}
	if err := checkMutation(s, "file_write"); err != nil {
		return nil, FileWriteOut{}, err
	}
	overwrite := true
	switch p.Mode {
	case "", "overwrite":
	case "append":
		overwrite = false
	default:
		return nil, FileWriteOut{}, invalid(fmt.Sprintf("mode must be \"overwrite\" or \"append\", got '%s'", p.Mode))
	}
	sc, err := s.SFTP()
	if err != nil {
		return nil, FileWriteOut{}, internalErr(err)
	}
	real := realPath(sc, p.Path)
	pathLock := s.WriteLockFor(real)
	pathLock.Lock()
	defer pathLock.Unlock()
	if overwrite {
		if fi, err := sc.Stat(real); err == nil {
			if fi.IsDir() {
				return nil, FileWriteOut{}, invalid(fmt.Sprintf("%s is a directory; specify a full file path", real))
			}
			fp := Fingerprint{Size: uint64(fi.Size()), Mtime: uint32(fi.ModTime().Unix())}
			if fp.Size > 0 {
				if err := guardCheck(s, real, fp, "file_write"); err != nil {
					return nil, FileWriteOut{}, err
				}
			}
		}
	}
	var f *sftp.File
	if overwrite {
		f, err = sc.Create(real)
		if err != nil {
			return nil, FileWriteOut{}, createError(err, real)
		}
	} else {
		// CREAT|APPEND|WRITE: create-if-missing, writes forced to end.
		f, err = sc.OpenFile(real, os.O_CREATE|os.O_APPEND|os.O_WRONLY)
		if err != nil {
			return nil, FileWriteOut{}, createError(err, real)
		}
	}
	if _, err := f.Write([]byte(p.Content)); err != nil {
		f.Close()
		return nil, FileWriteOut{}, internalErr(err)
	}
	_ = f.Sync()
	f.Close()
	srv.audit.Log(s.ID, "file_write", map[string]any{"path": real, "mode": p.Mode, "bytes": len(p.Content)})
	return nil, FileWriteOut{BytesWritten: int64(len(p.Content))}, nil
}

// readSFTPFile reads a remote file whole via SFTP.
func readSFTPFile(sc *sftp.Client, path string) ([]byte, error) {
	f, err := sc.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

// createError wraps SFTP create/open failures: name the missing parent
// directory when that is the actual cause.
func createError(err error, real string) error {
	// pkg/sftp normalises SSH_FX_NO_SUCH_FILE to os.ErrNotExist; keep the
	// StatusError check for servers/paths that return it un-normalised.
	var se *sftp.StatusError
	isNoSuch := errors.Is(err, os.ErrNotExist) ||
		(errors.As(err, &se) && se.FxCode() == sftp.ErrSSHFxNoSuchFile) ||
		strings.Contains(strings.ToLower(err.Error()), "no such file")
	if isNoSuch {
		if i := strings.LastIndex(real, "/"); i > 0 {
			return invalid(fmt.Sprintf("cannot create %s: parent directory does not exist (%s)", real, real[:i]))
		}
	}
	return internalErr(err)
}

func (srv *Server) fileEdit(ctx context.Context, req *mcp.CallToolRequest, p FileEditParams) (*mcp.CallToolResult, FileEditOut, error) {
	if p.OldString == "" {
		return nil, FileEditOut{}, invalid("old_string must not be empty")
	}
	s, err := srv.liveSession(p.SessionID)
	if err != nil {
		return nil, FileEditOut{}, err
	}
	if err := checkMutation(s, "file_edit"); err != nil {
		return nil, FileEditOut{}, err
	}
	sc, err := s.SFTP()
	if err != nil {
		return nil, FileEditOut{}, internalErr(err)
	}
	real := realPath(sc, p.Path)
	pathLock := s.WriteLockFor(real)
	pathLock.Lock()
	defer pathLock.Unlock()
	fi, err := sc.Stat(real)
	if err != nil {
		return nil, FileEditOut{}, invalid(fmt.Sprintf("cannot stat %s: %v", real, err))
	}
	fp := Fingerprint{Size: uint64(fi.Size()), Mtime: uint32(fi.ModTime().Unix())}
	if fp.Size > 16*1024*1024 {
		return nil, FileEditOut{}, invalid(fmt.Sprintf("%s is too large for file_edit (16 MiB cap); use ssh_shell with sed instead", real))
	}
	data, err := readSFTPFile(sc, real)
	if err != nil {
		return nil, FileEditOut{}, internalErr(err)
	}
	if !utf8.Valid(data) {
		return nil, FileEditOut{}, invalid(fmt.Sprintf("%s is not valid UTF-8; file_edit is text-only", real))
	}
	content := string(data)
	var matches []int
	for i := 0; i+len(p.OldString) <= len(content); {
		j := strings.Index(content[i:], p.OldString)
		if j < 0 {
			break
		}
		matches = append(matches, i+j)
		i = i + j + 1
	}
	if len(matches) == 0 {
		return nil, FileEditOut{}, invalid(fmt.Sprintf("old_string not found in %s", real))
	}
	if len(matches) > 1 && !p.ReplaceAll {
		return nil, FileEditOut{}, invalid(fmt.Sprintf("old_string matches %d times in %s; pass replace_all=true or include more surrounding context", len(matches), real))
	}
	// Read-before-write guard: matched byte ranges must be read-covered
	// under the current fingerprint; replace_all = full-file coverage.
	cov := s.Coverage(real)
	var missing []interval
	if p.ReplaceAll {
		missing = cov.Missing(interval{0, fp.Size, fp}, fp)
	} else {
		for _, i := range matches {
			missing = append(missing, cov.Missing(interval{uint64(i), uint64(i + len(p.OldString)), fp}, fp)...)
		}
	}
	if len(missing) > 0 {
		ranges := make([]string, len(missing))
		for i, g := range missing {
			ranges[i] = fmt.Sprintf("[%d, %d)", g.start, g.end)
		}
		return nil, FileEditOut{}, invalid(fmt.Sprintf("file_edit denied: matched region of %s not covered by prior file_read (missing %s) or changed since read; read the region you intend to edit first", real, strings.Join(ranges, ", ")))
	}
	first := matches[0]
	var newContent string
	if p.ReplaceAll {
		newContent = strings.ReplaceAll(content, p.OldString, p.NewString)
	} else {
		newContent = strings.Replace(content, p.OldString, p.NewString, 1)
	}
	f, err := sc.Create(real)
	if err != nil {
		return nil, FileEditOut{}, createError(err, real)
	}
	if _, err := f.Write([]byte(newContent)); err != nil {
		f.Close()
		return nil, FileEditOut{}, internalErr(err)
	}
	_ = f.Sync()
	f.Close()
	// Context: ±2 lines around the first replacement in the NEW content.
	lines := strings.Split(newContent, "\n")
	hitLine := len(strings.Split(newContent[:first], "\n")) - 1
	if hitLine < 0 {
		hitLine = 0
	}
	lo := hitLine - 2
	if lo < 0 {
		lo = 0
	}
	hi := hitLine + 3
	if hi > len(lines) {
		hi = len(lines)
	}
	ctxLines := strings.Join(lines[lo:hi], "\n")
	srv.audit.Log(s.ID, "file_edit", map[string]any{"path": real, "replacements": len(matches), "replace_all": p.ReplaceAll})
	return nil, FileEditOut{Replacements: int64(len(matches)), Context: ctxLines}, nil
}

func (srv *Server) sshUpload(ctx context.Context, req *mcp.CallToolRequest, p TransferParams) (*mcp.CallToolResult, TransferOut, error) {
	s, err := srv.liveSession(p.SessionID)
	if err != nil {
		return nil, TransferOut{}, err
	}
	if err := checkMutation(s, "ssh_upload"); err != nil {
		return nil, TransferOut{}, err
	}
	sc, err := s.SFTP()
	if err != nil {
		return nil, TransferOut{}, internalErr(err)
	}
	real := realPath(sc, p.RemotePath)
	pathLock := s.WriteLockFor(real)
	pathLock.Lock()
	defer pathLock.Unlock()
	if fi, err := sc.Stat(real); err == nil {
		if fi.IsDir() {
			return nil, TransferOut{}, invalid(fmt.Sprintf("%s is a directory; specify a full file path", real))
		}
		fp := Fingerprint{Size: uint64(fi.Size()), Mtime: uint32(fi.ModTime().Unix())}
		if fp.Size > 0 {
			if err := guardCheck(s, real, fp, "ssh_upload"); err != nil {
				return nil, TransferOut{}, err
			}
		}
	}
	local, err := os.Open(p.LocalPath)
	if err != nil {
		return nil, TransferOut{}, invalid(fmt.Sprintf("cannot open local file %s: %v", p.LocalPath, err))
	}
	defer local.Close()
	remote, err := sc.Create(real)
	if err != nil {
		return nil, TransferOut{}, createError(err, real)
	}
	bytes, err := io.Copy(remote, local)
	remote.Close()
	if err != nil {
		return nil, TransferOut{}, internalErr(err)
	}
	srv.audit.Log(s.ID, "ssh_upload", map[string]any{"local_path": p.LocalPath, "remote_path": real, "bytes": bytes})
	return nil, TransferOut{Bytes: bytes}, nil
}

func (srv *Server) sshDownload(ctx context.Context, req *mcp.CallToolRequest, p TransferParams) (*mcp.CallToolResult, TransferOut, error) {
	s, err := srv.liveSession(p.SessionID)
	if err != nil {
		return nil, TransferOut{}, err
	}
	sc, err := s.SFTP()
	if err != nil {
		return nil, TransferOut{}, internalErr(err)
	}
	real := realPath(sc, p.RemotePath)
	remote, err := sc.Open(real)
	if err != nil {
		return nil, TransferOut{}, internalErr(err)
	}
	defer remote.Close()
	local, err := os.Create(p.LocalPath)
	if err != nil {
		return nil, TransferOut{}, invalid(fmt.Sprintf("cannot create local file %s: %v", p.LocalPath, err))
	}
	bytes, err := io.Copy(local, remote)
	local.Close()
	if err != nil {
		return nil, TransferOut{}, internalErr(err)
	}
	srv.audit.Log(s.ID, "ssh_download", map[string]any{"remote_path": real, "local_path": p.LocalPath, "bytes": bytes})
	return nil, TransferOut{Bytes: bytes}, nil
}

func (srv *Server) sshCopy(ctx context.Context, req *mcp.CallToolRequest, p SshCopyParams) (*mcp.CallToolResult, TransferOut, error) {
	from, err := srv.liveSession(p.FromSession)
	if err != nil {
		return nil, TransferOut{}, err
	}
	to, err := srv.liveSession(p.ToSession)
	if err != nil {
		return nil, TransferOut{}, err
	}
	if err := checkMutation(to, "ssh_copy"); err != nil {
		return nil, TransferOut{}, err
	}
	if from.ID == to.ID {
		sc, err := from.SFTP()
		if err != nil {
			return nil, TransferOut{}, internalErr(err)
		}
		realFrom := realPath(sc, p.FromPath)
		realTo := realPath(sc, p.ToPath)
		if realFrom == realTo {
			return nil, TransferOut{}, invalid(fmt.Sprintf("%s and %s are the same file; refusing to copy", realFrom, realTo))
		}
		// Hardlinks share an inode across different paths.
		if a, b := devInode(from, realFrom), devInode(from, realTo); a != "" && a == b {
			return nil, TransferOut{}, invalid(fmt.Sprintf("%s and %s are the same file (hardlink); refusing to copy", realFrom, realTo))
		}
		pathLock := to.WriteLockFor(realTo)
		pathLock.Lock()
		defer pathLock.Unlock()
		if fi, err := sc.Stat(realTo); err == nil {
			if fi.IsDir() {
				return nil, TransferOut{}, invalid(fmt.Sprintf("%s is a directory; specify a full file path", realTo))
			}
			fp := Fingerprint{Size: uint64(fi.Size()), Mtime: uint32(fi.ModTime().Unix())}
			if fp.Size > 0 {
				if err := guardCheck(to, realTo, fp, "ssh_copy"); err != nil {
					return nil, TransferOut{}, err
				}
			}
		}
		src, err := sc.Open(realFrom)
		if err != nil {
			return nil, TransferOut{}, internalErr(err)
		}
		defer src.Close()
		dst, err := sc.Create(realTo)
		if err != nil {
			return nil, TransferOut{}, createError(err, realTo)
		}
		bytes, err := io.Copy(dst, src)
		dst.Close()
		if err != nil {
			return nil, TransferOut{}, internalErr(err)
		}
		srv.audit.Log(from.ID, "ssh_copy", map[string]any{"from": realFrom, "to": realTo, "bytes": bytes})
		return nil, TransferOut{Bytes: bytes}, nil
	}

	// Different sessions: two independent SFTP clients, no shared locks.
	scFrom, err := from.SFTP()
	if err != nil {
		return nil, TransferOut{}, internalErr(err)
	}
	scTo, err := to.SFTP()
	if err != nil {
		return nil, TransferOut{}, internalErr(err)
	}
	realFrom := realPath(scFrom, p.FromPath)
	realTo := realPath(scTo, p.ToPath)
	if from.Target == to.Target && realFrom == realTo {
		return nil, TransferOut{}, invalid(fmt.Sprintf("%s and %s are the same file; refusing to copy", realFrom, realTo))
	}
	if from.Target == to.Target {
		if a, b := devInode(from, realFrom), devInode(to, realTo); a != "" && a == b {
			return nil, TransferOut{}, invalid(fmt.Sprintf("%s and %s are the same file (hardlink); refusing to copy", realFrom, realTo))
		}
	}
	pathLock := to.WriteLockFor(realTo)
	pathLock.Lock()
	defer pathLock.Unlock()
	if fi, err := scTo.Stat(realTo); err == nil {
		if fi.IsDir() {
			return nil, TransferOut{}, invalid(fmt.Sprintf("%s is a directory; specify a full file path", realTo))
		}
		fp := Fingerprint{Size: uint64(fi.Size()), Mtime: uint32(fi.ModTime().Unix())}
		if fp.Size > 0 {
			if err := guardCheck(to, realTo, fp, "ssh_copy"); err != nil {
				return nil, TransferOut{}, err
			}
		}
	}
	src, err := scFrom.Open(realFrom)
	if err != nil {
		return nil, TransferOut{}, internalErr(err)
	}
	defer src.Close()
	dst, err := scTo.Create(realTo)
	if err != nil {
		return nil, TransferOut{}, createError(err, realTo)
	}
	bytes, err := io.Copy(dst, src)
	dst.Close()
	if err != nil {
		return nil, TransferOut{}, internalErr(err)
	}
	srv.audit.Log(from.ID, "ssh_copy", map[string]any{"from": realFrom, "to_session": to.ID, "to": realTo, "bytes": bytes})
	return nil, TransferOut{Bytes: bytes}, nil
}

// ── registration ────────────────────────────────────────────────────────────

// addTool registers a typed handler without the SDK's strict input
// validation: the Rust build (schemars defaults) accepted unknown argument
// fields, and rejecting them would be a contract change. Missing required
// fields surface as handler-level invalid-params errors instead.
func addTool[In, Out any](s *mcp.Server, t *mcp.Tool, h func(context.Context, *mcp.CallToolRequest, In) (*mcp.CallToolResult, Out, error)) {
	tt := *t
	if tt.InputSchema == nil {
		schema, err := jsonschema.ForType(reflect.TypeFor[In](), &jsonschema.ForOptions{})
		if err != nil {
			panic(fmt.Sprintf("AddTool: tool %q: input schema: %v", t.Name, err))
		}
		tt.InputSchema = schema
	}
	s.AddTool(&tt, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var in In
		if req.Params.Arguments != nil {
			if err := json.Unmarshal(req.Params.Arguments, &in); err != nil {
				var errRes mcp.CallToolResult
				errRes.SetError(fmt.Errorf("validating \"arguments\": %v", err))
				return &errRes, nil
			}
		}
		res, out, err := h(ctx, req, in)
		if err != nil {
			var wireErr *jsonrpc.Error
			if errors.As(err, &wireErr) {
				return nil, wireErr
			}
			var errRes mcp.CallToolResult
			errRes.SetError(err)
			return &errRes, nil
		}
		if res == nil {
			res = &mcp.CallToolResult{}
		}
		outBytes, err := json.Marshal(out)
		if err != nil {
			return nil, fmt.Errorf("marshaling output: %w", err)
		}
		res.StructuredContent = outBytes
		if res.Content == nil {
			res.Content = []mcp.Content{&mcp.TextContent{Text: string(outBytes)}}
		}
		return res, nil
	})
}

// RegisterTools wires all tools into the MCP server.
func RegisterTools(s *mcp.Server, srv *Server) {
	addTool(s, &mcp.Tool{
		Name:        "ssh_open",
		Description: "Open a persistent SSH shell session (PTY). Auth order: explicit private_key, then SSH agent, then password. Returns session_id used by all other tools. The shell persists: cwd, env, and aliases survive across ssh_shell calls.",
	}, srv.sshOpen)
	addTool(s, &mcp.Tool{
		Name:        "ssh_close",
		Description: "Close a session: terminates the shell channel and drops SFTP. Idempotent only for known ids.",
	}, srv.sshClose)
	addTool(s, &mcp.Tool{
		Name:        "ssh_list_servers",
		Description: "List configured servers from ~/.ssh-pty-mcp/servers.toml and Host aliases from ~/.ssh/config (passwords never shown). Open one with ssh_open(server=\"name\").",
	}, srv.sshListServers)
	addTool(s, &mcp.Tool{
		Name:        "ssh_add_server",
		Description: "Add or replace a server in ~/.ssh-pty-mcp/servers.toml (the file ssh_open(server=...) reads). Other entries are preserved; existing content keeps its encoding but is normalized to UTF-8 on write. Use this instead of hand-editing config: it validates the name and mode and keeps the file parseable. Pass overwrite=true to replace an existing entry; passwords are stored in plaintext (chmod 600 on Unix).",
	}, srv.sshAddServer)
	addTool(s, &mcp.Tool{
		Name:        "ssh_list",
		Description: "List all open sessions with their targets, shell kind, and liveness.",
	}, srv.sshList)
	addTool(s, &mcp.Tool{
		Name:        "ssh_shell",
		Description: "Run a command in the persistent shell and return clean output + exit code. Persistent shell: cwd/env/aliases survive across calls; `exit`/`logout` KILLS the whole session (open a new one). For system monitoring prefer batch commands (top -b -n 1, ps aux --sort=-%cpu | head) over interactive TUIs. PRECONDITION: the shell must be at a prompt — if you used ssh_type/ssh_press to start a long-running or interactive command (vi, passwd, ssh...), first confirm it finished via ssh_expect/ssh_screen, or use ssh_exec instead (stateless, never queues behind the shell). On timeout returns partial output with timed_out=true (the command keeps running).",
	}, srv.sshShell)
	addTool(s, &mcp.Tool{
		Name:        "ssh_type",
		Description: "Type text verbatim into the terminal (no implicit newline — include \\n to submit). Returns the seq anchor for ssh_screen(since_seq). Content is redacted in the audit log. If the text starts a long-running or interactive command, confirm it finished (ssh_expect/ssh_screen) before calling ssh_shell.",
	}, srv.sshType)
	addTool(s, &mcp.Tool{
		Name:        "ssh_press",
		Description: "Virtual keyboard for TUI programs (top/htop/less/menus). Press a named key: \"q\", \"enter\", \"ctrl+c\", \"ctrl+x\", \"shift+tab\", \"up\", \"f5\"... Pair with ssh_screen: press -> ssh_screen(wait='quiet', since_seq=<returned seq>) -> decide.",
	}, srv.sshPress)
	addTool(s, &mcp.Tool{
		Name:        "ssh_signal",
		Description: "Send a signal (sigint/sigquit/sigterm/sigkill/sighup/sigtstp) via the SSH protocol to the shell's foreground process group. Note: some servers/sudo contexts ignore SSH signal requests — fallback is ssh_press(\"ctrl+c\") or ssh_shell(\"kill -<SIG> <pid>\").",
	}, srv.sshSignal)
	addTool(s, &mcp.Tool{
		Name:        "ssh_expect",
		Description: "Wait for a regex on the session. Use for prompts (password:, [y/n], menus). More precise than ssh_screen when you know what to wait for. mode=stream matches output arriving after this call; mode=screen matches the rendered screen. On timeout returns matched=false with whatever accumulated.",
	}, srv.sshExpect)
	addTool(s, &mcp.Tool{
		Name:        "ssh_screen",
		Description: "Returns the current rendered screen from the server-side terminal model — no SSH round-trip. The screen legitimately contains prior output (a real terminal keeps it until cleared): detect WHAT CHANGED with since_seq + wait, never by diffing screen text yourself. Typical loop: press/type -> ssh_screen(wait='quiet', since_seq=<returned seq>) -> decide. wait='change' returns on the first new byte; wait='none' snapshots immediately. On timeout returns the current screen with timed_out=true.",
	}, srv.sshScreen)
	addTool(s, &mcp.Tool{
		Name:        "file_read",
		Description: "Read a remote text file via SFTP (offset/limit for large files). Prefer this over opening vim/nano in the terminal. Binary files are rejected — use ssh_download for those.",
	}, srv.fileRead)
	addTool(s, &mcp.Tool{
		Name:        "file_write",
		Description: "Write a remote text file via SFTP (UTF-8 text only — for binary content, stage it locally and use ssh_upload). Prefer this over opening vim/nano in the terminal. mode=overwrite requires having read the full current file via file_read first — the server enforces this; partial reads are rejected with the missing byte ranges. overwrite on a NOT-YET-EXISTING file is allowed without any read. mode=append is always allowed and creates the file if missing. Parent directory must exist.",
	}, srv.fileWrite)
	addTool(s, &mcp.Tool{
		Name:        "ssh_upload",
		Description: "Upload a local file to the remote host via SFTP (binary-safe). Overwriting an existing remote file requires a prior full file_read of it (read-before-write guard).",
	}, srv.sshUpload)
	addTool(s, &mcp.Tool{
		Name:        "ssh_download",
		Description: "Download a remote file to the local machine via SFTP (binary-safe, no size limit, no guard).",
	}, srv.sshDownload)
	addTool(s, &mcp.Tool{
		Name:        "ssh_exec",
		Description: "Execute a command via a one-shot SSH exec channel: stateless (no cwd/env carryover), protocol-level exit status, separate stdout/stderr, and completely isolated from the persistent shell (safe even while it runs an interactive program). Prefer this for simple read-only probes; use ssh_shell when you need shell state or features. On timeout the local channel closes but the REMOTE process may keep running (OpenSSH does not deliver signals to pty-less execs) — clean up with ssh_exec(\"pkill -f '<cmd>'\") or ssh_shell('kill -<SIG> <pid>').",
	}, srv.sshExec)
	addTool(s, &mcp.Tool{
		Name:        "ssh_ready",
		Description: "Probe whether the shell is at a prompt (ready to accept commands). Writes one harmless probe line; if the shell or a foreground program does not answer within probe_timeout_ms, returns ready=false. Use before ssh_type-driven interactive sequences.",
	}, srv.sshReady)
	addTool(s, &mcp.Tool{
		Name:        "ssh_shell_async",
		Description: "Start a command in the persistent shell without blocking; returns task_id. Poll with ssh_task_status (optionally with wait_ms), interrupt with ssh_task_cancel. Same semantics as ssh_shell (state persists, at-prompt precondition; `exit` in the command KILLS the whole session, not just the task); the task holds the shell until done, so avoid other ssh_shell calls in the meantime (ssh_exec, ssh_screen, ssh_expect, file tools remain usable).",
	}, srv.sshShellAsync)
	addTool(s, &mcp.Tool{
		Name:        "ssh_task_status",
		Description: "Check a background task started by ssh_shell_async. With wait_ms > 0, blocks until the task completes or the wait elapses. Returns status running/done/error plus output and exit_code when finished.",
	}, srv.sshTaskStatus)
	addTool(s, &mcp.Tool{
		Name:        "ssh_task_cancel",
		Description: "Cancel a running ssh_shell_async task: sends SIGINT (ctrl+c) to the remote foreground command and stops the local wait. The session stays alive and usable. A command ignoring SIGINT keeps running remotely — follow up with ssh_shell('kill -<SIG> <pid>') if needed.",
	}, srv.sshTaskCancel)
	addTool(s, &mcp.Tool{
		Name:        "ssh_copy",
		Description: "Copy a file directly between two SSH sessions (possibly different hosts), streamed through this server — no local disk staging. Overwriting an existing destination requires a prior full file_read of it on the destination session (read-before-write guard). Same-host copies are simpler via ssh_shell('cp -r a b').",
	}, srv.sshCopy)
	addTool(s, &mcp.Tool{
		Name:        "file_edit",
		Description: "Surgical text replacement in a remote file (like a local Edit tool): finds old_string exactly and replaces it. Requires the matched region to be covered by a prior file_read (read-before-write guard); replace_all additionally requires full-file coverage. Fails when old_string is absent or matches multiple times (unless replace_all). UTF-8 text only, 16 MiB cap.",
	}, srv.fileEdit)
}
