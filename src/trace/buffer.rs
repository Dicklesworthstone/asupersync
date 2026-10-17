//! Ring buffer for trace events.
//!
//! The trace buffer stores recent events in a fixed-size ring buffer,
//! allowing efficient capture without unbounded memory growth.

use super::event::TraceEvent;
use crate::types::Severity;
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

/// A ring buffer for storing trace events.
///
/// When the buffer is full, old events are overwritten.
///
/// The backing storage grows lazily: `events` is empty on construction and
/// only grows (by appending) up to `capacity` as events are actually pushed.
/// Once it reaches `capacity` the ring wraps in place. This avoids eagerly
/// allocating and zero-initializing `capacity` slots for a buffer that may
/// never record anything — a real cost at the default 4096-slot capacity,
/// since every `RuntimeState` (including the thousands built by lab-runtime
/// tests) constructs one whether or not tracing is enabled. `capacity` is the
/// invariant modulus for all ring arithmetic; `events.len()` is only the
/// current physical high-water mark during the growth phase, during which
/// `head == 0` and `len == events.len()` always hold.
#[derive(Debug)]
pub struct TraceBuffer {
    events: Vec<Option<TraceEvent>>,
    capacity: usize,
    head: usize,
    len: usize,
}

impl TraceBuffer {
    /// Creates a new trace buffer with the given capacity.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            events: Vec::new(),
            capacity,
            head: 0,
            len: 0,
        }
    }

    /// Returns the capacity of the buffer.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
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
        self.len == self.capacity
    }

    /// Pushes an event into the buffer.
    ///
    /// If the buffer is full, the oldest event is overwritten.
    pub fn push(&mut self, event: TraceEvent) {
        if self.events.len() < self.capacity {
            // Growth phase: the physical ring has not yet reached `capacity`,
            // so it has never wrapped. `head` is therefore still 0 and the
            // next logical slot is exactly the back of the Vec — append it
            // instead of pre-reserving all `capacity` slots up front.
            debug_assert_eq!(self.head, 0);
            debug_assert_eq!(self.len, self.events.len());
            self.events.push(Some(event));
            self.len += 1;
            return;
        }

        let idx = (self.head + self.len) % self.capacity;
        self.events[idx] = Some(event);

        if self.len < self.capacity {
            self.len += 1;
        } else {
            // Buffer is full, advance head
            self.head = (self.head + 1) % self.capacity;
        }
    }

    /// Returns an iterator over events in order (oldest to newest).
    pub fn iter(&self) -> impl Iterator<Item = &TraceEvent> {
        (0..self.len).filter_map(move |i| {
            let idx = (self.head + i) % self.capacity;
            self.events[idx].as_ref()
        })
    }

    /// Clears all events from the buffer.
    pub fn clear(&mut self) {
        self.events.clear();
        self.head = 0;
        self.len = 0;
    }

    /// Returns the most recent event.
    #[must_use]
    pub fn last(&self) -> Option<&TraceEvent> {
        if self.len == 0 {
            None
        } else {
            let idx = (self.head + self.len - 1) % self.capacity;
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
    /// Terminal outcome of each task completion, keyed by its Complete
    /// event's sequence. Set only while a schedule capture is enabled
    /// (br-asupersync-bi2462.8), written under the `buffer` lock and bounded
    /// like the ring.
    completion_outcomes: OnceLock<Mutex<VecDeque<(u64, Severity)>>>,
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
                completion_outcomes: OnceLock::new(),
            }),
        }
    }

    /// Keeps the terminal outcome of every later task completion, recorded
    /// through [`Self::record_completion_event`], for schedule capture.
    pub(crate) fn enable_completion_outcomes(&self) {
        let _ = self.inner.completion_outcomes.get_or_init(Default::default);
    }

    /// [`Self::record_event`] for a task's Complete event. While completion
    /// outcomes are kept, `outcome` is recorded under the same sequence and
    /// the same lock, so a snapshot never sees one without the other.
    pub(crate) fn record_completion_event<F>(&self, outcome: Severity, build: F)
    where
        F: FnOnce(u64) -> TraceEvent,
    {
        let mut buffer = self.inner.buffer.lock();
        let seq = self.inner.next_seq.fetch_add(1, Ordering::Relaxed);
        buffer.push(build(seq));
        self.inner.total_pushed.fetch_add(1, Ordering::Relaxed);
        if let Some(outcomes) = self.inner.completion_outcomes.get() {
            let mut outcomes = outcomes.lock();
            // Every kept outcome belongs to a Complete event, so the newest
            // `capacity` outcomes cover every Complete event still retained.
            if outcomes.len() >= buffer.capacity().max(1) {
                outcomes.pop_front();
            }
            outcomes.push_back((seq, outcome));
        }
    }

    /// [`Self::snapshot_with_stats`] plus the kept completion outcomes, all
    /// sampled under one lock. The outcomes are empty unless enabled.
    pub(crate) fn snapshot_with_outcomes(&self) -> (Vec<TraceEvent>, u64, Vec<(u64, Severity)>) {
        let buffer = self.inner.buffer.lock();
        let mut events: Vec<TraceEvent> = buffer.iter().cloned().collect();
        let total_pushed = self.inner.total_pushed.load(Ordering::Relaxed);
        let outcomes = self
            .inner
            .completion_outcomes
            .get()
            .map(|outcomes| outcomes.lock().iter().copied().collect())
            .unwrap_or_default();
        drop(buffer);
        events.sort_by_key(|event| event.seq);
        (events, total_pushed, outcomes)
    }

    /// Allocates and returns the next trace sequence number.
    ///
    /// Callers that are about to push onto this shared handle should prefer
    /// [`record_event`](Self::record_event) so sequence allocation and buffer
    /// insertion cannot be interleaved by another producer.
    #[must_use]
    pub fn next_seq(&self) -> u64 {
        self.inner.next_seq.fetch_add(1, Ordering::Relaxed)
    }

    /// Pushes a pre-built trace event into the buffer.
    ///
    /// This preserves the event's existing sequence number and advances the
    /// handle's allocator past it. The latter matters when importing a replay
    /// prefix before recording new events. Callers that need a fresh sequence
    /// number from this handle should prefer [`record_event`](Self::record_event).
    pub fn push_event(&self, event: TraceEvent) {
        self.inner
            .next_seq
            .fetch_max(event.seq.saturating_add(1), Ordering::Relaxed);
        {
            let mut buffer = self.inner.buffer.lock();
            buffer.push(event);
            self.inner.total_pushed.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Builds and pushes a trace event while holding the buffer lock.
    ///
    /// This keeps sequence allocation and insertion serialized so concurrent
    /// producers cannot insert seq `N + 1` ahead of seq `N`.
    ///
    /// The builder runs while the buffer lock is held, so it should stay
    /// lightweight and must not re-enter the same trace handle.
    pub fn record_event<F>(&self, build: F)
    where
        F: FnOnce(u64) -> TraceEvent,
    {
        let mut buffer = self.inner.buffer.lock();
        let seq = self.inner.next_seq.fetch_add(1, Ordering::Relaxed);
        buffer.push(build(seq));
        self.inner.total_pushed.fetch_add(1, Ordering::Relaxed);
    }

    /// Returns a snapshot of buffered events in seq order (oldest to
    /// newest).
    ///
    /// br-asupersync-xh4efw: insertion order and seq order can differ —
    /// optional `TaskAdmitted` observer events allocate their seq at admission
    /// (via [`next_seq`](Self::next_seq)) but are pushed at deferred dispatch,
    /// after later-sequenced events may already be in the ring. `Spawn`
    /// witnesses are recorded immediately when task admission succeeds. The
    /// snapshot sorts by seq so consumers observe the per-task causal
    /// contract (a task's Spawn seq precedes its Complete seq). Seqs may
    /// have gaps (an allocated-but-abandoned spawn effect never pushes);
    /// seq is an ordering key, not a dense index.
    #[must_use]
    pub fn snapshot(&self) -> Vec<TraceEvent> {
        self.snapshot_with_stats().0
    }

    /// Samples retained events and the lifetime insertion count at one boundary.
    /// The insertion count must advance under the same lock as the ring write:
    /// otherwise a concurrent snapshot could mistake an eviction for a full trace.
    pub(crate) fn snapshot_with_stats(&self) -> (Vec<TraceEvent>, u64) {
        let buffer = self.inner.buffer.lock();
        let mut events: Vec<TraceEvent> = buffer.iter().cloned().collect();
        let total_pushed = self.inner.total_pushed.load(Ordering::Relaxed);
        drop(buffer);
        events.sort_by_key(|event| event.seq);
        (events, total_pushed)
    }

    /// Returns the current number of buffered events.
    #[must_use]
    pub fn len(&self) -> usize {
        let buffer = self.inner.buffer.lock();
        buffer.len()
    }

    /// Returns the configured buffer capacity.
    #[must_use]
    pub fn capacity(&self) -> usize {
        let buffer = self.inner.buffer.lock();
        buffer.capacity()
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
#[path = "buffer_inline_tests.rs"]
mod tests;
