package main

import (
	"bytes"
	"testing"
)

func TestReadLiveRange(t *testing.T) {
	b := NewRingBuf(16)
	b.Push([]byte("hello"))
	b.Push([]byte(" world"))
	data, end, trunc := b.Read(0)
	if trunc != nil {
		t.Fatalf("unexpected truncation: %v", *trunc)
	}
	if end != 11 || string(data) != "hello world" {
		t.Fatalf("got %q end=%d", data, end)
	}
}

func TestWrapReportsTruncation(t *testing.T) {
	b := NewRingBuf(8)
	b.Push([]byte("01234567"))
	b.Push([]byte("89"))
	data, end, trunc := b.Read(0)
	if trunc == nil || *trunc != 2 {
		t.Fatalf("expected truncation at 2, got %v", trunc)
	}
	if end != 10 || string(data) != "23456789" {
		t.Fatalf("got %q end=%d", data, end)
	}
}

func TestReadAtEndIsEmpty(t *testing.T) {
	b := NewRingBuf(8)
	b.Push([]byte("abc"))
	data, end, trunc := b.Read(3)
	if len(data) != 0 || end != 3 || trunc != nil {
		t.Fatalf("got %q end=%d trunc=%v", data, end, trunc)
	}
}

func TestMarkerSplitAcrossPushes(t *testing.T) {
	b := NewRingBuf(1024)
	b.Push([]byte("out\n__SPM_ab12"))
	if data, _, _ := b.Read(0); findMarkerOK(data, "ab12cd34") {
		t.Fatal("marker must not match before complete")
	}
	b.Push([]byte("cd34_127__\n"))
	data, _, _ := b.Read(0)
	_, rc, ok := findMarker(data, 0, "ab12cd34")
	if !ok || rc != 127 {
		t.Fatalf("rc=%d ok=%v", rc, ok)
	}
}

func findMarkerOK(data []byte, tok string) bool {
	_, _, ok := findMarker(data, 0, tok)
	return ok
}

func TestRingBufBytes(t *testing.T) {
	b := NewRingBuf(1024)
	b.Push([]byte("total 3\r\n__SPM_deadbeef_0__\r\n"))
	data, _, _ := b.Read(0)
	if !bytes.Contains(data, []byte("__SPM_deadbeef_0__")) {
		t.Fatal("content missing")
	}
}
