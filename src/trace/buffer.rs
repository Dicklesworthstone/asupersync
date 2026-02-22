//! Ring buffer for trace events.
//!
//! The trace buffer stores recent events in a fixed-size ring buffer,
//! allowing efficient capture without unbounded memory growth.

use super::event::TraceEvent;
use parking_lot::Mutex;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// A ring buffer for storing trace events.
///
/// When the buffer is full, old events are overwritten.
#[derive(Debug)]
pub struct TraceBuffer {
    events: Vec<Option<TraceEvent>>,
    head: usize,
    len: usize,
}

impl TraceBuffer {
    /// Creates a new trace buffer with the given capacity.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            events: (0..capacity).map(|_| None).collect(),
            head: 0,
            len: 0,
        }
    }

    /// Returns the capacity of the buffer.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.events.len()
    }

    /// Returns the number of events in the buffer.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns true if the buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns true if the buffer is full.
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.len == self.events.len()
    }

    /// Pushes an event into the buffer.
    ///
    /// If the buffer is full, the oldest event is overwritten.
    pub fn push(&mut self, event: TraceEvent) {
        let idx = (self.head + self.len) % self.events.len();
        self.events[idx] = Some(event);

        if self.len < self.events.len() {
            self.len += 1;
        } else {
            // Buffer is full, advance head
            self.head = (self.head + 1) % self.events.len();
        }
    }

    /// Returns an iterator over events in order (oldest to newest).
    pub fn iter(&self) -> impl Iterator<Item = &TraceEvent> {
        (0..self.len).filter_map(move |i| {
            let idx = (self.head + i) % self.events.len();
            self.events[idx].as_ref()
        })
    }

    /// Clears all events from the buffer.
    pub fn clear(&mut self) {
        for event in &mut self.events {
            *event = None;
        }
        self.head = 0;
        self.len = 0;
    }

    /// Returns the most recent event.
    #[must_use]
    pub fn last(&self) -> Option<&TraceEvent> {
        if self.len == 0 {
            None
        } else {
            let idx = (self.head + self.len - 1) % self.events.len();
            self.events[idx].as_ref()
        }
    }
}

impl Default for TraceBuffer {
    fn default() -> Self {
        Self::new(1024)
    }
}

/// Thread-safe handle for sharing a trace buffer across tasks.
///
/// This wraps a [`TraceBuffer`] in a mutex and adds a monotonically increasing
/// sequence counter for event ordering.
#[derive(Debug, Clone)]
pub struct TraceBufferHandle {
    inner: Arc<TraceBufferInner>,
}

#[derive(Debug)]
struct TraceBufferInner {
    buffer: Mutex<TraceBuffer>,
    next_seq: AtomicU64,
    total_pushed: AtomicU64,
}

impl TraceBufferHandle {
    /// Creates a new trace buffer handle with the given capacity.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Arc::new(TraceBufferInner {
                buffer: Mutex::new(TraceBuffer::new(capacity)),
                next_seq: AtomicU64::new(0),
                total_pushed: AtomicU64::new(0),
            }),
        }
    }

    /// Allocates and returns the next trace sequence number.
    #[must_use]
    pub fn next_seq(&self) -> u64 {
        self.inner.next_seq.fetch_add(1, Ordering::Relaxed)
    }

    /// Pushes a trace event into the buffer.
    pub fn push_event(&self, event: TraceEvent) {
        {
            let mut buffer = self.inner.buffer.lock();
            buffer.push(event);
        }
        self.inner.total_pushed.fetch_add(1, Ordering::Relaxed);
    }

    /// Returns a snapshot of buffered events in order (oldest to newest).
    #[must_use]
    pub fn snapshot(&self) -> Vec<TraceEvent> {
        let buffer = self.inner.buffer.lock();
        buffer.iter().cloned().collect()
    }

    /// Returns the current number of buffered events.
    #[must_use]
    pub fn len(&self) -> usize {
        let buffer = self.inner.buffer.lock();
        buffer.len()
    }

    /// Returns the total number of events pushed since creation.
    ///
    /// This includes events that may no longer be present in the ring buffer
    /// due to capacity eviction.
    #[must_use]
    pub fn total_pushed(&self) -> u64 {
        self.inner.total_pushed.load(Ordering::Relaxed)
    }

    /// Returns true if the buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::event::{TraceData, TraceEventKind};
    use crate::types::Time;

    fn make_event(seq: u64) -> TraceEvent {
        TraceEvent::new(
            seq,
            Time::ZERO,
            TraceEventKind::UserTrace,
            TraceData::Message(format!("event {seq}")),
        )
    }

    #[test]
    fn push_and_iterate() {
        let mut buf = TraceBuffer::new(4);
        buf.push(make_event(1));
        buf.push(make_event(2));
        buf.push(make_event(3));

        let seqs: Vec<_> = buf.iter().map(|e| e.seq).collect();
        assert_eq!(seqs, vec![1, 2, 3]);
    }

    #[test]
    fn overflow_wraps() {
        let mut buf = TraceBuffer::new(3);
        buf.push(make_event(1));
        buf.push(make_event(2));
        buf.push(make_event(3));
        buf.push(make_event(4)); // Overwrites 1
        buf.push(make_event(5)); // Overwrites 2

        let seqs: Vec<_> = buf.iter().map(|e| e.seq).collect();
        assert_eq!(seqs, vec![3, 4, 5]);
    }

    #[test]
    fn trace_buffer_debug() {
        let buf = TraceBuffer::new(4);
        let dbg = format!("{buf:?}");
        assert!(dbg.contains("TraceBuffer"));
    }

    #[test]
    fn trace_buffer_new_capacity() {
        let buf = TraceBuffer::new(16);
        assert_eq!(buf.capacity(), 16);
        assert_eq!(buf.len(), 0);
        assert!(buf.is_empty());
        assert!(!buf.is_full());
    }

    #[test]
    fn trace_buffer_capacity_clamps_to_one() {
        let buf = TraceBuffer::new(0);
        assert_eq!(buf.capacity(), 1);
    }

    #[test]
    fn trace_buffer_is_full() {
        let mut buf = TraceBuffer::new(2);
        assert!(!buf.is_full());
        buf.push(make_event(1));
        assert!(!buf.is_full());
        buf.push(make_event(2));
        assert!(buf.is_full());
    }

    #[test]
    fn trace_buffer_clear() {
        let mut buf = TraceBuffer::new(4);
        buf.push(make_event(1));
        buf.push(make_event(2));
        assert_eq!(buf.len(), 2);
        buf.clear();
        assert_eq!(buf.len(), 0);
        assert!(buf.is_empty());
        assert!(buf.last().is_none());
    }

    #[test]
    fn trace_buffer_last_empty() {
        let buf = TraceBuffer::new(4);
        assert!(buf.last().is_none());
    }

    #[test]
    fn trace_buffer_last_returns_newest() {
        let mut buf = TraceBuffer::new(4);
        buf.push(make_event(10));
        buf.push(make_event(20));
        buf.push(make_event(30));
        assert_eq!(buf.last().unwrap().seq, 30);
    }

    #[test]
    fn trace_buffer_default() {
        let buf = TraceBuffer::default();
        assert_eq!(buf.capacity(), 1024);
        assert!(buf.is_empty());
    }

    #[test]
    fn trace_buffer_iter_empty() {
        let buf = TraceBuffer::new(4);
        assert_eq!(buf.iter().count(), 0);
    }

    #[test]
    fn trace_buffer_handle_debug() {
        let handle = TraceBufferHandle::new(8);
        let dbg = format!("{handle:?}");
        assert!(dbg.contains("TraceBufferHandle"));
    }

    #[test]
    fn trace_buffer_handle_clone() {
        let handle = TraceBufferHandle::new(8);
        handle.push_event(make_event(1));
        let handle2 = handle;
        // Cloned handle shares the same buffer
        assert_eq!(handle2.len(), 1);
    }

    #[test]
    fn trace_buffer_handle_next_seq_increments() {
        let handle = TraceBufferHandle::new(4);
        assert_eq!(handle.next_seq(), 0);
        assert_eq!(handle.next_seq(), 1);
        assert_eq!(handle.next_seq(), 2);
    }

    #[test]
    fn trace_buffer_handle_push_and_snapshot() {
        let handle = TraceBufferHandle::new(4);
        handle.push_event(make_event(10));
        handle.push_event(make_event(20));
        let snap = handle.snapshot();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].seq, 10);
        assert_eq!(snap[1].seq, 20);
    }

    #[test]
    fn trace_buffer_handle_len_and_is_empty() {
        let handle = TraceBufferHandle::new(4);
        assert!(handle.is_empty());
        assert_eq!(handle.len(), 0);
        assert_eq!(handle.total_pushed(), 0);
        handle.push_event(make_event(1));
        assert!(!handle.is_empty());
        assert_eq!(handle.len(), 1);
        assert_eq!(handle.total_pushed(), 1);
    }

    #[test]
    fn trace_buffer_handle_snapshot_empty() {
        let handle = TraceBufferHandle::new(4);
        let snap = handle.snapshot();
        assert!(snap.is_empty());
    }

    #[test]
    fn trace_buffer_handle_total_pushed_tracks_evictions() {
        let handle = TraceBufferHandle::new(2);
        handle.push_event(make_event(1));
        handle.push_event(make_event(2));
        handle.push_event(make_event(3));
        assert_eq!(handle.total_pushed(), 3);
        assert_eq!(handle.len(), 2);
        let snap = handle.snapshot();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].seq, 2);
        assert_eq!(snap[1].seq, 3);
    }
}
