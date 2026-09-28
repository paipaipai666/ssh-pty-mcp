// Session core: persistent PTY shell state, screen model, stream buffer,
// wait-state machine, and the read-before-write coverage tracker.
package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/charmbracelet/x/vt"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// ShellKind is the detected remote shell family.
type ShellKind int

const (
	ShellUnknown ShellKind = iota
	ShellPosix
	ShellCmd
	ShellPowerShell
)

func (k ShellKind) String() string {
	switch k {
	case ShellPosix:
		return "posix"
	case ShellCmd:
		return "cmd"
	case ShellPowerShell:
		return "powershell"
	default:
		return "unknown"
	}
}

// SessionMode is the per-session command policy, set at ssh_open.
type SessionMode struct {
	kind  string // "unrestricted" | "readonly" | "restricted"
	allow []*regexp.Regexp
}

var (
	modeUnrestricted = SessionMode{kind: "unrestricted"}
	modeReadOnly     = SessionMode{kind: "readonly"}
)

// ModeRestricted builds a restricted mode from allowlist patterns.
func ModeRestricted(allow []string) (SessionMode, error) {
	res := make([]*regexp.Regexp, 0, len(allow))
	for _, a := range allow {
		re, err := regexp.Compile(a)
		if err != nil {
			return SessionMode{}, fmt.Errorf("invalid allow regex: %v", err)
		}
		res = append(res, re)
	}
	return SessionMode{kind: "restricted", allow: res}, nil
}

// Label returns the mode name.
func (m SessionMode) Label() string { return m.kind }

var dangerousRe = regexp.MustCompile(`\b(rm|rmdir|mkfs\S*|dd|shutdown|reboot|halt|poweroff|init|kill|killall|pkill|systemctl|service|chmod|chown|chgrp|useradd|userdel|groupadd|groupdel|passwd|iptables|fdisk|parted|mount|umount|swapoff|crontab)\b`)

// Check returns (blocked, reason). Unrestricted never blocks.
func (m SessionMode) Check(command string) (bool, string) {
	switch m.kind {
	case "readonly":
		if hit := dangerousRe.FindString(command); hit != "" {
			return true, fmt.Sprintf("blocked by session mode=readonly: matched dangerous pattern '%s'", hit)
		}
	case "restricted":
		for _, re := range m.allow {
			if re.MatchString(command) {
				return false, ""
			}
		}
		return true, "blocked by session mode=restricted: command matches no allowlist pattern"
	}
	return false, ""
}

// screenState is everything the pump mutates and readers poll.
type screenState struct {
	parser       *vt.Emulator
	stream       *RingBuf
	seq          uint64
	lastOutputAt time.Time
	eof          bool
}

// Shared is the pump↔readers rendezvous: screen model + stream buffer +
// change notification. Methods are safe for concurrent use.
type Shared struct {
	mu     sync.Mutex
	st     screenState
	notify chan struct{} // replaced on each broadcast; captured under mu
	respCh chan []byte   // terminal-query replies for the response writer
}

// NewShared creates the pump-side state for a rows×cols terminal.
func NewShared(rows, cols int) *Shared {
	return &Shared{
		st: screenState{
			parser:       newEmulator(rows, cols),
			stream:       NewRingBuf(1 << 20),
			lastOutputAt: time.Now(),
		},
		notify: make(chan struct{}),
		respCh: make(chan []byte, 16),
	}
}

func newEmulator(rows, cols int) *vt.Emulator {
	em := vt.NewEmulator(cols, rows)
	em.SetScrollbackSize(0) // match vt100::Parser::new(rows, cols, 0)
	// The emulator answers terminal queries (DSR/DA/mode reports) by writing
	// to its input pipe, which blocks without a reader — deadlock inside
	// Feed. We answer queries ourselves in the pump (terminalReply), so
	// discard what the emulator generates.
	go io.Copy(io.Discard, em)
	return em
}

// NotifyChan returns the current broadcast channel; it is replaced (and the
// old one closed) on every state change. Capture under lock, then select.
func (s *Shared) NotifyChan() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.notify
}

// EnqueueResponse queues a terminal reply for the session writer.
func (s *Shared) EnqueueResponse(b []byte) {
	select {
	case s.respCh <- b:
	default:
	}
}

// RespCh returns the response-writer queue.
func (s *Shared) RespCh() <-chan []byte { return s.respCh }

// Feed ingests one byte batch from the remote host.
func (s *Shared) Feed(data []byte) {
	s.mu.Lock()
	s.st.stream.Push(data)
	_, _ = s.st.parser.Write(data)
	s.st.seq++
	s.st.lastOutputAt = time.Now()
	ch := s.notify
	s.notify = make(chan struct{})
	s.mu.Unlock()
	close(ch)
}

// MarkEOF flags the stream as ended and wakes all waiters.
func (s *Shared) MarkEOF() {
	s.mu.Lock()
	s.st.eof = true
	ch := s.notify
	s.notify = make(chan struct{})
	s.mu.Unlock()
	close(ch)
}

// Seq returns the current logical output clock.
func (s *Shared) Seq() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st.seq
}

// LastOutputAt returns when the newest byte arrived.
func (s *Shared) LastOutputAt() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st.lastOutputAt
}

// EndOffset returns the absolute stream offset one past the newest byte.
func (s *Shared) EndOffset() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st.stream.EndOffset()
}

// ReadStream returns stream bytes [from, end).
func (s *Shared) ReadStream(from int64) ([]byte, int64, *int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st.stream.Read(from)
}

// EOF reports whether the stream ended.
func (s *Shared) EOF() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st.eof
}

// WaitMode selects the wait semantics.
type WaitMode int

const (
	WaitNone WaitMode = iota
	WaitChange
	WaitQuiet
)

// screenText renders the current screen, trailing blank lines trimmed and
// scaffolding lines filtered. (vt's Emulator.String trims whitespace at both
// ends; the Rust version trimmed the end only — cosmetic difference on an
// indented first screen line.)
func screenText(e *vt.Emulator) string {
	raw := e.String()
	lines := strings.Split(raw, "\n")
	kept := make([]string, 0, len(lines))
	for _, l := range lines {
		if !isScaffoldLine(l) {
			kept = append(kept, l)
		}
	}
	return strings.TrimRightFunc(strings.Join(kept, "\n"), unicode.IsSpace)
}

func isScaffoldLine(l string) bool {
	return strings.Contains(l, "__SPM_") ||
		strings.Contains(l, "__spm_ps1=") ||
		strings.Contains(l, "export HISTCONTROL=")
}

// waitScreen waits on the screen model and returns
// (screen, seq, idle, timedOut). since=nil means "no anchor" (changed=true).
func waitScreen(s *Shared, since *uint64, mode WaitMode, settle, timeout time.Duration) (string, uint64, time.Duration, bool) {
	deadline := time.Now().Add(timeout)
	for {
		var waitFor time.Duration
		var result *struct {
			screen string
			seq    uint64
			idle   time.Duration
		}
		var timedOut bool
		var ch chan struct{}

		s.mu.Lock()
		st := s.st
		changed := since == nil || st.seq > *since
		idle := time.Since(st.lastOutputAt)
		hit := false
		switch mode {
		case WaitNone:
			hit = true
		case WaitChange:
			hit = changed
		case WaitQuiet:
			hit = changed && idle >= settle
		}
		if hit {
			result = &struct {
				screen string
				seq    uint64
				idle   time.Duration
			}{screenText(st.parser), st.seq, idle}
		} else {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				timedOut = true
				result = &struct {
					screen string
					seq    uint64
					idle   time.Duration
				}{screenText(st.parser), st.seq, idle}
			} else {
				if mode == WaitQuiet && changed && idle < settle {
					if r := settle - idle; r < remaining {
						remaining = r
					}
				}
				waitFor = remaining
				ch = s.notify
			}
		}
		s.mu.Unlock()

		if result != nil {
			return result.screen, result.seq, result.idle, timedOut
		}
		timer := time.NewTimer(waitFor)
		select {
		case <-ch:
			timer.Stop()
		case <-timer.C:
		}
	}
}

// waitStreamContains blocks until the stream (from `from`) contains needle
// or the timeout hits. Returns false on EOF/timeout.
func waitStreamContains(s *Shared, from int64, needle []byte, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		var ch chan struct{}
		var waitFor time.Duration
		hit := false

		s.mu.Lock()
		b, _, _ := s.st.stream.Read(from)
		if bytes.Contains(b, needle) {
			hit = true
		} else if s.st.eof {
			s.mu.Unlock()
			return false
		} else {
			waitFor = time.Until(deadline)
			if waitFor <= 0 {
				s.mu.Unlock()
				return false
			}
			ch = s.notify
		}
		s.mu.Unlock()

		if hit {
			return true
		}
		timer := time.NewTimer(waitFor)
		select {
		case <-ch:
			timer.Stop()
		case <-timer.C:
			return false
		}
	}
}

// findMarker finds `\n__SPM_<tok>_<rc>__` in b (whose absolute offset of
// element 0 is `from`). Returns (abs offset of the line break preceding the
// marker, exit code). Scans ALL occurrences: with tty echo on, the echoed
// printf line itself contains `__SPM_<tok>_` followed by `%d__` — that
// candidate is invalid (no digits) and must not poison the search for the
// real marker output.
func findMarker(b []byte, from int64, tok string) (int64, int64, bool) {
	pat := "__SPM_" + tok + "_"
	searchFrom := 0
	for searchFrom <= len(b) {
		rel := bytes.Index(b[searchFrom:], []byte(pat))
		if rel < 0 {
			return 0, 0, false
		}
		pos := searchFrom + rel
		rest := b[pos+len(pat):]
		digits := 0
		for digits < len(rest) && rest[digits] >= '0' && rest[digits] <= '9' {
			digits++
		}
		valid := digits > 0 && len(rest) >= digits+2 && string(rest[digits:digits+2]) == "__"
		if valid {
			rc, err := strconv.ParseInt(string(rest[:digits]), 10, 64)
			if err != nil {
				return 0, 0, false
			}
			start := pos
			if start >= 2 && string(b[start-2:start]) == "\r\n" {
				start -= 2
			} else if start >= 1 && b[start-1] == '\n' {
				start--
			}
			return from + int64(start), rc, true
		}
		searchFrom = pos + 1
	}
	return 0, 0, false
}

// terminalReply detects terminal query sequences in a remote→local byte
// batch and builds the reply a real terminal would send:
//
//	\x1b[6n      DSR (cursor position) -> \x1b[1;1R
//	\x1b[?6n     DECXCPR             -> \x1b[?1;1R
//	\x1b[c       DA1 (device attrs)  -> \x1b[?62c  (VT220)
//	\x1b[?1;2c   DA2                 -> \x1b[?62;1;2;6;9;15;22c
//
// Unknown queries are ignored (a wrong reply is worse than silence).
func terminalReply(data []byte) []byte {
	hasEsc := bytes.Contains(data, []byte("\x1b[")) || bytes.Contains(data, []byte("\x1b?"))
	if !hasEsc {
		return nil
	}
	var out []byte
	i := 0
	for i < len(data) {
		if data[i] == 0x1b && i+1 < len(data) && data[i+1] == '[' {
			j := i + 2
			q := false
			if j < len(data) && data[j] == '?' {
				q = true
				j++
			}
			start := j
			for j < len(data) && data[j] >= 0x30 && data[j] <= 0x3f {
				j++
			}
			finalByte := byte(0)
			if j < len(data) {
				finalByte = data[j]
			}
			if finalByte >= 0x40 && finalByte <= 0x7e {
				params := data[start:j]
				switch {
				case !q && finalByte == 'n' && string(params) == "6":
					out = append(out, "\x1b[1;1R"...)
				case q && finalByte == 'n' && string(params) == "6":
					out = append(out, "\x1b[?1;1R"...)
				case !q && finalByte == 'c' && len(params) == 0:
					out = append(out, "\x1b[?62c"...)
				case q && finalByte == 'c' && string(params) == "1;2":
					out = append(out, "\x1b[?62;1;2;6;9;15;22c"...)
				}
				i = j + 1
				continue
			}
		}
		i++
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// Fingerprint is a file stat fingerprint: (size, mtime). Reads only count
// for the exact fingerprint observed at read time.
type Fingerprint struct {
	Size  uint64
	Mtime uint32
}

// ReadCoverage tracks read-covered byte ranges, coalesced per fingerprint.
type ReadCoverage struct {
	// Sorted, non-overlapping; coalesced within equal fingerprints.
	intervals []interval
}

type interval struct {
	start, end uint64
	fp         Fingerprint
}

// Record adds [start, end) as read under fingerprint fp.
func (c *ReadCoverage) Record(start, end uint64, fp Fingerprint) {
	if start >= end {
		return
	}
	c.intervals = append(c.intervals, interval{start, end, fp})
	sortIntervals(c.intervals)
	out := c.intervals[:0]
	for _, iv := range c.intervals {
		if len(out) > 0 {
			last := &out[len(out)-1]
			if last.fp == iv.fp && iv.start <= last.end {
				if iv.end > last.end {
					last.end = iv.end
				}
				continue
			}
		}
		out = append(out, iv)
	}
	c.intervals = out
}

func sortIntervals(ivs []interval) {
	for i := 1; i < len(ivs); i++ {
		for j := i; j > 0 && ivs[j].start < ivs[j-1].start; j-- {
			ivs[j], ivs[j-1] = ivs[j-1], ivs[j]
		}
	}
}

// Missing returns sub-ranges of want not covered by intervals tagged fp.
func (c *ReadCoverage) Missing(want interval, fp Fingerprint) []interval {
	var gaps []interval
	cursor := want.start
	for _, iv := range c.intervals {
		if iv.fp != fp || iv.end <= cursor {
			continue
		}
		if iv.start > cursor {
			end := iv.start
			if want.end < end {
				end = want.end
			}
			gaps = append(gaps, interval{cursor, end, fp})
		}
		if iv.end > cursor {
			cursor = iv.end
		}
		if cursor >= want.end {
			return gaps
		}
	}
	if cursor < want.end {
		gaps = append(gaps, interval{cursor, want.end, fp})
	}
	return gaps
}

// Session is one open SSH shell with its PTY state.
type Session struct {
	ID       string
	Target   string // "user@host:port"
	Name     string
	Mode     SessionMode
	Shell    ShellKind
	Shared   *Shared
	Client   *ssh.Client
	Channel  *ssh.Session
	Stdin    io.WriteCloser // PTY input (serializes via writeMu)
	Stdout   io.Reader      // PTY output streams, set at open
	Stderr   io.Reader
	bastions []io.Closer

	writeMu sync.Mutex // serializes writes to Channel
	ioMu    sync.Mutex // serializes whole operations (run/type/press)

	sftpMu sync.Mutex
	sftp   *sftp.Client

	readsMu    sync.Mutex
	reads      map[string]*ReadCoverage
	writeLocks map[string]*sync.Mutex

	alive          atomic.Bool
	bracketedPaste bool
	borrowed       atomic.Int32 // shared-bastion references; >0 keeps the client open on Close
	closeOnce      sync.Once
}

// SFTP lazily establishes (and caches) the SFTP subsystem for the session.
func (s *Session) SFTP() (*sftp.Client, error) {
	s.sftpMu.Lock()
	defer s.sftpMu.Unlock()
	if s.sftp != nil {
		return s.sftp, nil
	}
	c, err := sftp.NewClient(s.Client)
	if err != nil {
		return nil, err
	}
	s.sftp = c
	return c, nil
}

// CheckAlive errors when the session is closed or the shell died.
func (s *Session) CheckAlive() error {
	if s.alive.Load() && !s.Shared.EOF() {
		return nil
	}
	return fmt.Errorf("session %s is closed or dead; open a new one with ssh_open", s.ID)
}

// WriteLockFor returns the per-(session, path) write serialization lock.
func (s *Session) WriteLockFor(path string) *sync.Mutex {
	s.readsMu.Lock()
	defer s.readsMu.Unlock()
	if s.writeLocks == nil {
		s.writeLocks = map[string]*sync.Mutex{}
	}
	m, ok := s.writeLocks[path]
	if !ok {
		m = &sync.Mutex{}
		s.writeLocks[path] = m
	}
	return m
}

// Coverage returns (creating if needed) the read coverage for path.
func (s *Session) Coverage(path string) *ReadCoverage {
	s.readsMu.Lock()
	defer s.readsMu.Unlock()
	if s.reads == nil {
		s.reads = map[string]*ReadCoverage{}
	}
	c, ok := s.reads[path]
	if !ok {
		c = &ReadCoverage{}
		s.reads[path] = c
	}
	return c
}

// Write sends bytes to the PTY, serialized with terminal replies.
func (s *Session) Write(b []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.Stdin == nil {
		return errors.New("session has no stdin")
	}
	_, err := s.Stdin.Write(b)
	return err
}

// Close terminates the channel and drops SFTP. Idempotent. When another
// session borrows this one as a shared ProxyJump host, the SSH client stays
// open (the borrower keeps it alive), matching the Rust Arc<Bastion> hold.
func (s *Session) Close() {
	s.closeOnce.Do(func() {
		s.alive.Store(false)
		if s.sftp != nil {
			_ = s.sftp.Close()
		}
		if s.Channel != nil {
			_ = s.Channel.Close()
		}
		for _, b := range s.bastions {
			_ = b.Close()
		}
		if s.Client != nil && s.borrowed.Load() == 0 {
			_ = s.Client.Close()
		}
		if s.Shared != nil && s.Shared.st.parser != nil {
			_ = s.Shared.st.parser.Close() // ends the input-pipe drain goroutine
		}
		s.Shared.MarkEOF()
	})
}

// SessionManager owns the live sessions.
type SessionManager struct {
	mu       sync.Mutex
	sessions map[string]*Session
	next     atomic.Uint64
}

// NextID allocates the next session id ("s1", "s2", ...).
func (m *SessionManager) NextID() string {
	return fmt.Sprintf("s%d", m.next.Add(1))
}

// Insert registers a session.
func (m *SessionManager) Insert(s *Session) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sessions == nil {
		m.sessions = map[string]*Session{}
	}
	m.sessions[s.ID] = s
}

// Get returns a session by id.
func (m *SessionManager) Get(id string) *Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sessions[id]
}

// Remove drops a session by id.
func (m *SessionManager) Remove(id string) *Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.sessions[id]
	delete(m.sessions, id)
	return s
}

// List returns all sessions.
func (m *SessionManager) List() []*Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		out = append(out, s)
	}
	return out
}

// PruneDead drops sessions whose shell died, releasing names and limit slots.
func (m *SessionManager) PruneDead() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, s := range m.sessions {
		if !s.alive.Load() {
			delete(m.sessions, id)
		}
	}
}

// Find resolves an id or a session name.
func (m *SessionManager) Find(idOrName string) *Session {
	if s := m.Get(idOrName); s != nil {
		return s
	}
	for _, s := range m.List() {
		if s.Name == idOrName {
			return s
		}
	}
	return nil
}

var errClosed = errors.New("closed")

// utf16Decode converts UTF-16 code units to runes.
func utf16Decode(u16 []uint16) []rune {
	return utf16.Decode(u16)
}

func decodeValidUTF8(b []byte) (string, error) {
	if !utf8.Valid(b) {
		return "", errClosed // caller wraps with path context
	}
	return string(b), nil
}
