//! Bounded byte buffer addressed by absolute stream offsets.
//!
//! The pump task appends every byte the remote host sends; readers ask for
//! `[from, end)` by absolute offset. When the buffer wraps, readers learn the
//! gap via `truncated_from` instead of silently losing bytes.

use std::collections::VecDeque;

#[derive(Debug)]
pub struct RingBuf {
    base: u64,
    buf: VecDeque<u8>,
    cap: usize,
}

impl Default for RingBuf {
    fn default() -> Self {
        Self::new(1_048_576)
    }
}

impl RingBuf {
    pub fn new(cap: usize) -> Self {
        Self {
            base: 0,
            buf: VecDeque::new(),
            cap,
        }
    }

    /// Absolute offset of the first retained byte.
    pub fn base_offset(&self) -> u64 {
        self.base
    }

    /// Absolute offset one past the newest byte.
    pub fn end_offset(&self) -> u64 {
        self.base + self.buf.len() as u64
    }

    pub fn push(&mut self, data: &[u8]) {
        self.buf.extend(data);
        while self.buf.len() > self.cap {
            self.buf.pop_front();
            self.base += 1;
        }
    }

    /// Read `[from, end)`. Returns `(bytes, end_offset, truncated_from)`;
    /// `truncated_from` is `Some(base)` when bytes before `base` are gone.
    pub fn read(&self, from: u64) -> (Vec<u8>, u64, Option<u64>) {
        let end = self.end_offset();
        let (start, truncated) = if from < self.base {
            (self.base, Some(self.base))
        } else {
            (from, None)
        };
        if start >= end {
            return (Vec::new(), end, truncated);
        }
        let skip = (start - self.base) as usize;
        let out: Vec<u8> = self.buf.iter().skip(skip).copied().collect();
        (out, end, truncated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_live_range() {
        let mut b = RingBuf::new(16);
        b.push(b"hello ");
        b.push(b"world");
        let (bytes, end, trunc) = b.read(6);
        assert_eq!(bytes, b"world");
        assert_eq!(end, 11);
        assert_eq!(trunc, None);
    }

    #[test]
    fn wrap_reports_truncation() {
        let mut b = RingBuf::new(8);
        b.push(b"0123456789"); // keeps "23456789", base = 2
        assert_eq!(b.base_offset(), 2);
        let (bytes, end, trunc) = b.read(0);
        assert_eq!(bytes, b"23456789");
        assert_eq!(end, 10);
        assert_eq!(trunc, Some(2));
    }

    #[test]
    fn read_at_end_is_empty() {
        let mut b = RingBuf::new(4);
        b.push(b"ab");
        let (bytes, end, trunc) = b.read(2);
        assert!(bytes.is_empty());
        assert_eq!(end, 2);
        assert_eq!(trunc, None);
    }
}
