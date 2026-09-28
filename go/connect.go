// SSH connect/auth/host-key layer: ~/.ssh/config resolution, the staged
// auth chain (private_key → agent → password → keyboard-interactive),
// accept-new host keys, and ProxyJump chains.
package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	sshconfig "github.com/kevinburke/ssh_config"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// HostKeyPolicy controls unknown/changed host key handling.
type HostKeyPolicy int

const (
	// HostKeyAcceptNew learns unknown host keys (OpenSSH accept-new).
	HostKeyAcceptNew HostKeyPolicy = iota
	// HostKeyOff trusts any key.
	HostKeyOff
)

// ConnectParams is everything ssh_open needs to dial.
type ConnectParams struct {
	Host           string
	Port           int // 0 = unset (resolve via ssh config, else 22)
	User           string
	Name           string
	ProxyJump      string
	Mode           SessionMode
	Password       string // empty = unset
	PrivateKey     string
	Passphrase     string
	UseAgent       bool
	UseSSHConfig   bool
	HostKeyPolicy  HostKeyPolicy
	Cols, Rows     int
	ConnectTimeout time.Duration
}

// Opened is a freshly opened session plus the auth method that succeeded.
type Opened struct {
	Session    *Session
	AuthMethod string
}

type resolved struct {
	host       string
	port       int
	user       string
	privateKey string
	proxyJump  string
}

// sshCfgQuery is one alias's effective ssh-config view.
type sshCfgQuery struct {
	HostName     string
	Port         *int
	User         string
	IdentityFile string
	ProxyJump    string
}

// loadSSHConfig reads ~/.ssh/config (nil when missing/broken).
func loadSSHConfig() *sshconfig.Config {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	f, err := os.Open(filepath.Join(home, ".ssh", "config"))
	if err != nil {
		return nil
	}
	defer f.Close()
	cfg, err := sshconfig.Decode(f)
	if err != nil {
		return nil
	}
	return cfg
}

// querySSHConfig resolves an alias through ~/.ssh/config.
func querySSHConfig(alias string) sshCfgQuery {
	cfg := loadSSHConfig()
	if cfg == nil {
		return sshCfgQuery{}
	}
	get := func(key string) string {
		v, _ := cfg.Get(alias, key)
		return v
	}
	q := sshCfgQuery{
		HostName:     get("HostName"),
		User:         get("User"),
		IdentityFile: get("IdentityFile"),
		ProxyJump:    get("ProxyJump"),
	}
	if p := get("Port"); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			q.Port = &n
		}
	}
	return q
}

// sshConfigAliases lists concrete Host aliases (patterns with wildcards
// skipped, matching the Rust summary behavior).
func sshConfigAliases(cfg *sshconfig.Config) []string {
	if cfg == nil {
		return nil
	}
	var out []string
	for _, h := range cfg.Hosts {
		for _, p := range h.Patterns {
			s := p.String()
			if s == "*" || strings.ContainsAny(s, "*?") {
				continue
			}
			out = append(out, s)
		}
	}
	return out
}

// resolve merges ~/.ssh/config below explicit params.
func resolve(params *ConnectParams) (resolved, error) {
	r := resolved{
		host:       params.Host,
		port:       params.Port,
		user:       params.User,
		privateKey: params.PrivateKey,
		proxyJump:  params.ProxyJump,
	}
	if params.UseSSHConfig {
		if cfg := loadSSHConfig(); cfg != nil {
			q := querySSHConfig(params.Host)
			if q.HostName != "" {
				r.host = q.HostName
			}
			if r.port == 0 && q.Port != nil {
				r.port = *q.Port
			}
			if r.user == "" && q.User != "" {
				r.user = q.User
			}
			if r.privateKey == "" && q.IdentityFile != "" {
				r.privateKey = q.IdentityFile
			}
			if r.proxyJump == "" && q.ProxyJump != "" {
				r.proxyJump = q.ProxyJump
			}
		}
	}
	if r.port == 0 {
		r.port = 22
	}
	if r.user == "" {
		return r, errors.New("user is required (not supplied and not found in ~/.ssh/config)")
	}
	return r, nil
}

func expandHome(path string) string {
	if path == "~" || strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(home, path[1:])
		}
	}
	return path
}

func knownHostsPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".ssh", "known_hosts")
}

// hostKeyCallback implements the accept-new policy: known keys must match,
// unknown keys are learned into ~/.ssh/known_hosts.
func hostKeyCallback(policy HostKeyPolicy, host string, port int) ssh.HostKeyCallback {
	if policy == HostKeyOff {
		return ssh.InsecureIgnoreHostKey()
	}
	khPath := knownHostsPath()
	checker, err := knownhosts.New(khPath)
	if err != nil {
		// Missing known_hosts: start an empty accept-new file.
		checker = func(h string, a net.Addr, k ssh.PublicKey) error {
			return &knownhosts.KeyError{Want: nil}
		}
	}
	return func(addr string, remote net.Addr, key ssh.PublicKey) error {
		err := checker(addr, remote, key)
		if err == nil {
			return nil
		}
		var ke *knownhosts.KeyError
		if errors.As(err, &ke) && len(ke.Want) == 0 {
			// Unknown host: learn and accept (OpenSSH accept-new).
			line := knownhosts.Line([]string{knownhosts.Normalize(fmt.Sprintf("%s:%d", host, port))}, key)
			if dir := filepath.Dir(khPath); dir != "" {
				if err := os.MkdirAll(dir, 0o700); err != nil {
					log.Printf("known_hosts mkdir failed: %v", err)
				}
			}
			f, err := os.OpenFile(khPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
			if err != nil {
				log.Printf("failed to record host key: %v", err)
				return nil // still accept, like the Rust warn-and-accept
			}
			fmt.Fprintf(f, "%s\n", line)
			f.Close()
			return nil
		}
		log.Printf("host key mismatch for %s", host)
		return err
	}
}

// connectOne dials addr and authenticates with exactly one candidate method,
// so the successful method is known. Retried per auth stage by authenticate.
func connectOne(addr string, cfg *ssh.ClientConfig) (*ssh.Client, error) {
	conn, err := net.DialTimeout("tcp", addr, cfg.Timeout)
	if err != nil {
		return nil, err
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return ssh.NewClient(c, chans, reqs), nil
}

// authenticate runs the full auth chain on a fresh connection per stage:
// private_key → agent → password → keyboard-interactive. Returns the method
// that succeeded. Multi-stage connects mirror russh's sequential Handle
// authentication (x/crypto/ssh does not report which AuthMethod won).
func authenticate(r resolved, params *ConnectParams) (*ssh.Client, string, error) {
	target := net.JoinHostPort(r.host, strconv.Itoa(r.port))
	timeout := params.ConnectTimeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	mk := func(methods ...ssh.AuthMethod) *ssh.ClientConfig {
		return &ssh.ClientConfig{
			User:            r.user,
			Auth:            methods,
			HostKeyCallback: hostKeyCallback(params.HostKeyPolicy, r.host, r.port),
			Timeout:         timeout,
		}
	}
	var lastErr error

	// Stage 1: explicit private key.
	if path := strings.TrimSpace(r.privateKey); path != "" {
		keyPath := expandHome(path)
		var signer ssh.Signer
		var err error
		if params.Passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(mustRead(keyPath), []byte(params.Passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey(mustRead(keyPath))
		}
		if err == nil {
			client, err := connectOne(target, mk(ssh.PublicKeys(signer)))
			if err == nil {
				return client, "private_key", nil
			}
			lastErr = err
		} else {
			log.Printf("failed to load key %s: %v", keyPath, err)
		}
	}

	// Stage 2: SSH agent (cap attempts: servers default MaxAuthTries 6).
	if params.UseAgent {
		if signers, err := agentSigners(); err == nil && len(signers) > 0 {
			if len(signers) > 4 {
				signers = signers[:4]
			}
			client, err := connectOne(target, mk(ssh.PublicKeys(signers...)))
			if err == nil {
				return client, "agent", nil
			}
			lastErr = err
		}
	}

	// Stage 3: password.
	if params.Password != "" {
		client, err := connectOne(target, mk(ssh.Password(params.Password)))
		if err == nil {
			return client, "password", nil
		}
		lastErr = err
		// Some servers only offer keyboard-interactive: retry with the
		// password answering every prompt.
		client, err = connectOne(target, mk(keyboardInteractive(params.Password)))
		if err == nil {
			return client, "keyboard-interactive", nil
		}
		lastErr = err
	}

	if lastErr != nil {
		return nil, "", fmt.Errorf("authentication failed for %s@%s: %w", r.user, target, lastErr)
	}
	return nil, "", fmt.Errorf("authentication failed for %s@%s: no usable credentials", r.user, target)
}

func mustRead(path string) []byte {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return b
}

// keyboardInteractive answers every server prompt with the password,
// mirroring the Russh loop.
func keyboardInteractive(password string) ssh.AuthMethod {
	return ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) ([]string, error) {
		answers := make([]string, len(questions))
		for i := range questions {
			answers[i] = password
		}
		return answers, nil
	})
}

// resolveJump parses a proxy_jump hop: "user@host[:port]", "host[:port]",
// or an alias via servers.toml / ~/.ssh/config.
func resolveJump(spec string, base *ConnectParams) resolved {
	// servers.toml alias
	if e, ok := LoadServers().Servers[spec]; ok {
		host := e.Host
		if host == "" {
			host = spec
		}
		port := 22
		if e.Port != nil {
			port = *e.Port
		}
		user := e.User
		if user == "" {
			user = base.User
		}
		if q := querySSHConfig(host); q.HostName != "" {
			host = q.HostName
		}
		return resolved{host: host, port: port, user: user, privateKey: e.PrivateKey}
	}
	// ssh config alias
	q := querySSHConfig(spec)
	if q.HostName != "" {
		port := 22
		if q.Port != nil {
			port = *q.Port
		}
		user := q.User
		if user == "" {
			user = base.User
		}
		return resolved{host: q.HostName, port: port, user: user, privateKey: q.IdentityFile}
	}
	// user@host[:port] / host[:port]
	user := base.User
	rest := spec
	if i := strings.LastIndex(spec, "@"); i >= 0 {
		user = spec[:i]
		rest = spec[i+1:]
	}
	host, port := rest, 22
	if i := strings.LastIndex(rest, ":"); i >= 0 {
		if p, err := strconv.Atoi(rest[i+1:]); err == nil {
			host = rest[:i]
			port = p
		}
	}
	return resolved{host: host, port: port, user: user, privateKey: base.PrivateKey}
}

// Open connects, authenticates, opens a PTY shell, spawns the pump, probes
// the shell kind, and returns the ready session.
func Open(params *ConnectParams, manager *SessionManager) (*Opened, error) {
	r, err := resolve(params)
	if err != nil {
		return nil, err
	}
	target := fmt.Sprintf("%s@%s:%d", r.user, r.host, r.port)

	// ProxyJump: tunnel the target handshake through a chain of
	// direct-tcpip channels. Each hop may name an existing open session (by
	// name or id), a servers.toml / ~/.ssh/config alias, or user@host[:port].
	// Every intermediate connection stays alive for the session's lifetime.
	var client *ssh.Client
	var authMethod string
	var owned []io.Closer
	var keptShared []*Session // pins borrowed bastion sessions (and their clients) alive
	if jump := strings.TrimSpace(r.proxyJump); jump != "" {
		hops := strings.Split(jump, ",")
		clean := hops[:0]
		for _, h := range hops {
			if h = strings.TrimSpace(h); h != "" {
				clean = append(clean, h)
			}
		}
		if len(clean) == 0 {
			return nil, errors.New("proxy_jump is empty")
		}
		type hopClient struct {
			client *ssh.Client
			from   *Session // non-nil when borrowed from an existing session
		}
		chain := []hopClient{}
		for i, hop := range clean {
			var via *Session
			for _, s := range manager.List() {
				if (s.Name == hop || s.ID == hop) && s.alive.Load() {
					via = s
					break
				}
			}
			if via != nil {
				via.borrowed.Add(1)
				keptShared = append(keptShared, via)
				chain = append(chain, hopClient{client: via.Client, from: via})
				continue
			}
			jr := resolveJump(hop, params)
			jtarget := fmt.Sprintf("%s@%s:%d", jr.user, jr.host, jr.port)
			jparams := *params
			if jr.privateKey != "" {
				jparams.PrivateKey = jr.privateKey
			}
			var bh *ssh.Client
			if i == 0 {
				bh, _, err = dialOne(jr, &jparams)
			} else {
				prev := chain[len(chain)-1].client
				bh, _, err = dialThrough(prev, jr, &jparams)
			}
			if err != nil {
				return nil, fmt.Errorf("hop %d (%s): %w", i, jtarget, err)
			}
			owned = append(owned, bh)
			chain = append(chain, hopClient{client: bh})
		}
		last := chain[len(chain)-1].client
		client, authMethod, err = dialThrough(last, r, params)
		if err != nil {
			return nil, fmt.Errorf("bastion cannot reach %s: %w", target, err)
		}
	} else {
		client, authMethod, err = dialOne(r, params)
		if err != nil {
			return nil, err
		}
	}

	sess, stdin, stdout, stderr, err := openShell(client, params)
	if err != nil {
		client.Close()
		return nil, err
	}

	shared := NewShared(params.Rows, params.Cols)
	s := &Session{
		ID:       manager.NextID(),
		Target:   target,
		Name:     params.Name,
		Mode:     params.Mode,
		Shared:   shared,
		Client:   client,
		Channel:  sess,
		Stdin:    stdin,
		Stdout:   stdout,
		Stderr:   stderr,
		bastions: owned,
	}
	s.alive.Store(true)

	// Pump: remote bytes -> screen model + stream buffer (stdout + stderr).
	go pumpChannel(s, shared, &s.alive)

	// Terminal-reply writer: answers DSR/DA queries the pump detected.
	go func() {
		for b := range shared.RespCh() {
			_ = s.Write(b)
		}
	}()

	// Keepalive: russh used 15s interval, 3 misses. A failed SendRequest
	// means the connection is gone — close so liveness surfaces.
	go keepalive(client, &s.alive)

	// Shell probes. Order matters (POSIX printf → pwsh CR probe → cmd ver).
	start := shared.EndOffset()
	_ = s.Write([]byte("printf '__SPM_PROBE_%s__\\n' ok\n"))
	kind := ShellUnknown
	if waitStreamContains(shared, start, []byte("__SPM_PROBE_ok__"), 3*time.Second) {
		kind = ShellPosix
	} else {
		p2 := shared.EndOffset()
		_ = s.Write([]byte("echo ('__SPM_PROBE2_' + 'ok')\r"))
		if waitStreamContains(shared, p2, []byte("__SPM_PROBE2_ok__"), 20*time.Second) {
			kind = ShellPowerShell
		} else {
			p3 := shared.EndOffset()
			_ = s.Write([]byte("ver\r"))
			if waitStreamContains(shared, p3, []byte("Windows"), 3*time.Second) {
				kind = ShellCmd
			}
		}
	}
	s.Shell = kind
	if kind == ShellPosix {
		// bash/zsh readline advertise bracketed paste via \x1b[?2004h in the
		// prompt redraw — enables paste-wrapped command delivery in runCore.
		b, _, _ := shared.ReadStream(start)
		s.bracketedPaste = bytes.Contains(b, []byte("[?2004h"))
		// Keep internal scaffolding out of shell history.
		_ = s.Write([]byte(" export HISTCONTROL=\"${HISTCONTROL:+$HISTCONTROL:}ignorespace\"; setopt HIST_IGNORE_SPACE 2>/dev/null\n"))
	}

	return &Opened{Session: s, AuthMethod: authMethod}, nil
}

// dialOne connects directly and authenticates hop-by-hop.
func dialOne(r resolved, params *ConnectParams) (client *ssh.Client, method string, err error) {
	return authenticate(r, params)
}

// dialThrough tunnels an SSH connection over prev's direct-tcpip channel.
func dialThrough(prev *ssh.Client, r resolved, params *ConnectParams) (client *ssh.Client, method string, err error) {
	target := net.JoinHostPort(r.host, strconv.Itoa(r.port))
	conn, err := prev.Dial("tcp", target)
	if err != nil {
		return nil, "", fmt.Errorf("unreachable through previous hop: %w", err)
	}
	// Authenticate staged over the tunneled connection.
	return authenticateOver(conn, target, r, params)
}

// authenticateOver runs the staged auth chain on an established transport.
func authenticateOver(conn net.Conn, addr string, r resolved, params *ConnectParams) (*ssh.Client, string, error) {
	timeout := params.ConnectTimeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	defer conn.SetDeadline(time.Time{})

	// Staged attempts need a fresh handshake each; over a stream that means
	// reconnecting — but streams allow only one handshake. So build the
	// candidate list in one config, ordered like the Rust chain.
	var methods []ssh.AuthMethod
	if path := strings.TrimSpace(r.privateKey); path != "" {
		keyPath := expandHome(path)
		var signer ssh.Signer
		var err error
		if params.Passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(mustRead(keyPath), []byte(params.Passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey(mustRead(keyPath))
		}
		if err != nil {
			log.Printf("failed to load key %s: %v", keyPath, err)
		} else {
			methods = append(methods, ssh.PublicKeys(signer))
		}
	}
	if params.UseAgent {
		if signers, err := agentSigners(); err == nil && len(signers) > 0 {
			if len(signers) > 4 {
				signers = signers[:4]
			}
			methods = append(methods, ssh.PublicKeys(signers...))
		}
	}
	if params.Password != "" {
		methods = append(methods, ssh.Password(params.Password), keyboardInteractive(params.Password))
	}
	if len(methods) == 0 {
		return nil, "", fmt.Errorf("authentication failed for %s@%s: no usable credentials", r.user, addr)
	}
	cfg := &ssh.ClientConfig{
		User:            r.user,
		Auth:            methods,
		HostKeyCallback: hostKeyCallback(params.HostKeyPolicy, r.host, r.port),
		Timeout:         timeout,
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		return nil, "", err
	}
	// ponytail: over tunneled hops we cannot stage one-method-per-connection;
	// the auth_method label falls back to "unknown" at the tool layer.
	return ssh.NewClient(c, chans, reqs), "unknown", nil
}

// openShell opens the session channel, requests a PTY and a shell. All
// pipes must be acquired before Shell() starts the remote process.
func openShell(client *ssh.Client, params *ConnectParams) (*ssh.Session, io.WriteCloser, io.Reader, io.Reader, error) {
	sess, err := client.NewSession()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("open session channel: %w", err)
	}
	modes := ssh.TerminalModes{}
	if err := sess.RequestPty("xterm-256color", params.Rows, params.Cols, modes); err != nil {
		sess.Close()
		return nil, nil, nil, nil, fmt.Errorf("request pty: %w", err)
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		sess.Close()
		return nil, nil, nil, nil, fmt.Errorf("stdin pipe: %w", err)
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		sess.Close()
		return nil, nil, nil, nil, fmt.Errorf("stdout pipe: %w", err)
	}
	stderr, err := sess.StderrPipe()
	if err != nil {
		sess.Close()
		return nil, nil, nil, nil, fmt.Errorf("stderr pipe: %w", err)
	}
	if err := sess.Shell(); err != nil {
		sess.Close()
		return nil, nil, nil, nil, fmt.Errorf("request shell: %w", err)
	}
	return sess, stdin, stdout, stderr, nil
}

// pumpChannel moves remote bytes into the screen model + stream buffer.
func pumpChannel(s *Session, shared *Shared, alive *atomic.Bool) {
	feed := func(r io.Reader) {
		buf := make([]byte, 32*1024)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				batch := buf[:n]
				if reply := terminalReply(batch); reply != nil {
					shared.EnqueueResponse(reply)
				}
				shared.Feed(batch)
			}
			if err != nil {
				return
			}
		}
	}
	done := make(chan struct{}, 2)
	go func() { feed(s.Stdout); done <- struct{}{} }()
	go func() { feed(s.Stderr); done <- struct{}{} }()
	<-done // stdout ending means the channel is done
	alive.Store(false)
	shared.MarkEOF()
}

// keepalive mirrors russh's keepalive_interval=15s, keepalive_max=3.
func keepalive(client *ssh.Client, alive *atomic.Bool) {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	misses := 0
	for range t.C {
		if !alive.Load() {
			return
		}
		_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
		if err != nil {
			misses++
			if misses >= 3 {
				alive.Store(false)
				client.Close()
				return
			}
		} else {
			misses = 0
		}
	}
}
