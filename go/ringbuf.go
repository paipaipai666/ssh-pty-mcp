// Bounded byte buffer addressed by absolute stream offsets.
//
// The pump goroutine appends every byte the remote host sends; readers ask
// for [from, end) by absolute offset. When the buffer wraps, readers learn
// the gap via truncated_from instead of silently losing bytes.
package main

import "fmt"

// RingBuf is a fixed-capacity byte buffer addressed by absolute offsets.
type RingBuf struct {
	base int64
	buf  []byte // len(buf) <= cap; logical: buf[base : base+len(buf)]
	cap_ int
}

// NewRingBuf creates a RingBuf holding at most cap bytes.
func NewRingBuf(cap int) *RingBuf {
	return &RingBuf{cap_: cap}
}

// BaseOffset returns the absolute offset of the first retained byte.
func (r *RingBuf) BaseOffset() int64 { return r.base }

// EndOffset returns the absolute offset one past the newest byte.
func (r *RingBuf) EndOffset() int64 { return r.base + int64(len(r.buf)) }

// Push appends data, discarding the oldest bytes past capacity (one at a
// time, mirroring the Rust implementation's truncation granularity).
func (r *RingBuf) Push(data []byte) {
	r.buf = append(r.buf, data...)
	for len(r.buf) > r.cap_ {
		r.buf = r.buf[1:]
		r.base++
		if len(r.buf) == 0 {
			r.buf = r.buf[:0] // keep backing array bounded
		} else if r.base%4096 == 0 && len(r.buf) < cap(r.buf)/2 {
			b := make([]byte, len(r.buf), r.cap_)
			copy(b, r.buf)
			r.buf = b
		}
	}
}

// Read returns (bytes, endOffset, truncatedFrom) for [from, end).
// truncatedFrom is Some(base) when bytes before base are gone.
func (r *RingBuf) Read(from int64) ([]byte, int64, *int64) {
	var trunc *int64
	start := from
	if start < r.base {
		v := r.base
		trunc = &v
		start = r.base
	}
	if start > r.EndOffset() {
		return nil, r.EndOffset(), trunc
	}
	n := int64(len(r.buf)) - (start - r.base)
	out := make([]byte, int(n))
	copy(out, r.buf[start-r.base:])
	return out, r.EndOffset(), trunc
}

func (r *RingBuf) String() string {
	return fmt.Sprintf("RingBuf{base:%d len:%d cap:%d}", r.base, len(r.buf), r.cap_)
}
