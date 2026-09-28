package main

import (
	"testing"
	"time"
)

var testFP = Fingerprint{Size: 100, Mtime: 1_700_000_000}

func TestCoverageMergesAndReportsGap(t *testing.T) {
	c := &ReadCoverage{}
	c.Record(0, 60, testFP)
	c.Record(80, 100, testFP)
	got := c.Missing(interval{0, 100, testFP}, testFP)
	if len(got) != 1 || got[0].start != 60 || got[0].end != 80 {
		t.Fatalf("got %v", got)
	}
	c.Record(55, 85, testFP) // bridges the gap
	if got := c.Missing(interval{0, 100, testFP}, testFP); len(got) != 0 {
		t.Fatalf("expected full coverage, got %v", got)
	}
}

func TestStaleFingerprintDoesNotCount(t *testing.T) {
	c := &ReadCoverage{}
	c.Record(0, 100, testFP)
	newer := Fingerprint{Size: 100, Mtime: testFP.Mtime + 60}
	got := c.Missing(interval{0, 100, newer}, newer)
	if len(got) != 1 || got[0].start != 0 || got[0].end != 100 {
		t.Fatalf("got %v", got)
	}
}

func TestEmptyCoverageMissesEverything(t *testing.T) {
	c := &ReadCoverage{}
	got := c.Missing(interval{0, 42, testFP}, testFP)
	if len(got) != 1 || got[0].start != 0 || got[0].end != 42 {
		t.Fatalf("got %v", got)
	}
}

func TestMarkerParsing(t *testing.T) {
	b := NewRingBuf(1024)
	b.Push([]byte("total 3\r\n-rw-r--r--\r\n__SPM_deadbeef_0__\r\n"))
	data, _, _ := b.Read(0)
	off, rc, ok := findMarker(data, 0, "deadbeef")
	if !ok || rc != 0 {
		t.Fatalf("rc=%d ok=%v", rc, ok)
	}
	rest, _, _ := b.Read(off)
	if string(rest[:2]) != "\r\n" {
		t.Fatalf("offset should point at the \\r\\n before the marker, got %q", rest[:2])
	}
	if _, _, ok := findMarker(data, 0, "00badc0de"); ok {
		t.Fatal("must not match a different token")
	}
}

func TestEchoedPrintfLineDoesNotPoisonSearch(t *testing.T) {
	b := NewRingBuf(4096)
	b.Push([]byte("printf '\\n__SPM_deadbeef_%d__\\n' $?\r\n\r\n__SPM_deadbeef_0__\r\n"))
	data, _, _ := b.Read(0)
	off, rc, ok := findMarker(data, 0, "deadbeef")
	if !ok || rc != 0 {
		t.Fatalf("rc=%d ok=%v", rc, ok)
	}
	if off <= 30 {
		t.Fatalf("should skip the echoed candidate, got %d", off)
	}
}

func TestTerminalReply(t *testing.T) {
	if got := terminalReply([]byte("plain output")); got != nil {
		t.Fatalf("expected nil, got %q", got)
	}
	if got := terminalReply([]byte("\x1b[6n")); string(got) != "\x1b[1;1R" {
		t.Fatalf("DSR reply: %q", got)
	}
	if got := terminalReply([]byte("\x1b[?6n")); string(got) != "\x1b[?1;1R" {
		t.Fatalf("DECXCPR reply: %q", got)
	}
	if got := terminalReply([]byte("\x1b[c")); string(got) != "\x1b[?62c" {
		t.Fatalf("DA1 reply: %q", got)
	}
	if got := terminalReply([]byte("\x1b[?1;2c")); string(got) != "\x1b[?62;1;2;6;9;15;22c" {
		t.Fatalf("DA2 reply: %q", got)
	}
}

// TestFeedTerminalQueryDoesNotDeadlock: the vt emulator answers DSR/DA
// queries via its input pipe; without a draining reader, Feed would block
// forever holding the Shared mutex (found by the pwsh docker e2e).
func TestFeedTerminalQueryDoesNotDeadlock(t *testing.T) {
	s := NewShared(24, 80)
	done := make(chan struct{})
	go func() {
		s.Feed([]byte("\x1b[6n")) // DSR cursor position report
		s.Feed([]byte("\x1b[c"))  // DA1 device attributes
		s.Feed([]byte("hello"))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Feed deadlocked on a terminal query")
	}
	if s.Seq() != 3 {
		t.Fatalf("seq=%d want 3", s.Seq())
	}
}

func TestWaitMachineModes(t *testing.T) {
	s := NewShared(24, 80)
	go func() {
		time.Sleep(50 * time.Millisecond)
		s.Feed([]byte("hi"))
		time.Sleep(50 * time.Millisecond)
		s.Feed([]byte("there"))
	}()
	since := s.Seq()
	_, seq, _, timedOut := waitScreen(s, &since, WaitChange, 250*time.Millisecond, 5*time.Second)
	if timedOut || seq < 1 {
		t.Fatalf("change wait: seq=%d timedOut=%v", seq, timedOut)
	}

	before := s.Seq()
	go func() {
		time.Sleep(10 * time.Millisecond)
		s.Feed([]byte("x"))
		time.Sleep(10 * time.Millisecond)
		s.Feed([]byte("y"))
	}()
	_, seq, _, timedOut = waitScreen(s, &before, WaitQuiet, 250*time.Millisecond, 5*time.Second)
	if timedOut || seq < before+2 {
		t.Fatalf("quiet wait: seq=%d before=%d timedOut=%v", seq, before, timedOut)
	}

	since = s.Seq()
	_, _, _, timedOut = waitScreen(s, &since, WaitChange, 250*time.Millisecond, 100*time.Millisecond)
	if !timedOut {
		t.Fatal("expected timeout")
	}
}
