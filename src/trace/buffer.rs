//! Ring buffer for trace events.
//!
//! The trace buffer stores recent events in a fixed-size ring buffer,
//! allowing efficient capture without unbounded memory growth.

use super::event::TraceEvent;

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
}
