//! Ring buffer for trace events.
//!
//! The trace buffer stores recent events in a fixed-size ring buffer,
//! allowing efficient capture without unbounded memory growth.

use super::event::TraceEvent;
use crate::types::{Budget, CancelReason, Severity, TaskId};
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
    /// Capture-only witnesses bracketing task cancellation publication. The
    /// flag can become visible before its canonical Request event is pushed,
    /// so the event's sequence alone is not a safe replay boundary.
    cancellation_publications: OnceLock<Mutex<CancellationPublications>>,
}

#[derive(Debug, Clone)]
pub(crate) struct CancellationPublication {
    pub(crate) task: TaskId,
    pub(crate) start_sequence: u64,
    pub(crate) end_sequence: Option<u64>,
    pub(crate) request_sequence: Option<u64>,
    pub(crate) cleanup_budget: Option<Budget>,
    pub(crate) unsupported_mutation: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct TerminalCancellationState {
    pub(crate) requested: bool,
    pub(crate) reason: Option<CancelReason>,
}

#[derive(Debug, Default)]
struct CancellationPublications {
    spans: VecDeque<CancellationPublication>,
    dropped_spans: u64,
    /// Every entry is atomically paired with its canonical Complete event.
    /// None records that no authoritative task-Cx witness was supplied.
    terminals: VecDeque<(u64, Option<TerminalCancellationState>)>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct CancellationPublicationSnapshot {
    pub(crate) spans: Vec<CancellationPublication>,
    pub(crate) dropped_spans: u64,
    pub(crate) terminals: Vec<(u64, Option<TerminalCancellationState>)>,
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
                cancellation_publications: OnceLock::new(),
            }),
        }
    }

    /// Keeps the terminal outcome of every later task completion, recorded
    /// through [`Self::record_completion_event`], for schedule capture.
    pub(crate) fn enable_completion_outcomes(&self) {
        let _ = self.inner.completion_outcomes.get_or_init(Default::default);
    }

    pub(crate) fn enable_cancellation_publications(&self) {
        let _ = self
            .inner
            .cancellation_publications
            .get_or_init(Default::default);
    }

    pub(crate) fn cancellation_capture_enabled(&self) -> bool {
        self.inner.cancellation_publications.get().is_some()
    }

    /// Starts a witness before either the task record or its Cx is mutated.
    /// Disabled captures do not acquire a lock, reserve a sequence, or allocate.
    /// An interrupted publisher leaves an unfinished witness, which a checked
    /// cancellation projection refuses. All witness access uses buffer -> spans
    /// lock order, shared with the snapshot boundary.
    pub(crate) fn begin_cancellation_publication(&self, task: TaskId) -> Option<u64> {
        let publications = self.inner.cancellation_publications.get()?;
        let buffer = self.inner.buffer.lock();
        let mut publications = publications.lock();
        let start_sequence = self.inner.next_seq.fetch_add(1, Ordering::Relaxed);
        if publications.spans.len() >= buffer.capacity() {
            publications.spans.pop_front();
            publications.dropped_spans = publications.dropped_spans.saturating_add(1);
        }
        publications.spans.push_back(CancellationPublication {
            task,
            start_sequence,
            end_sequence: None,
            request_sequence: None,
            cleanup_budget: None,
            unsupported_mutation: false,
        });
        Some(start_sequence)
    }

    /// Finishes after the canonical request has been recorded. A no-op request
    /// needs no retained witness; strengthening without a new canonical request
    /// remains explicit unsupported evidence rather than silently disappearing.
    pub(crate) fn finish_cancellation_publication(
        &self,
        start_sequence: Option<u64>,
        request_sequence: Option<u64>,
        cleanup_budget: Option<Budget>,
        unsupported_mutation: bool,
    ) {
        let (Some(start_sequence), Some(publications)) = (
            start_sequence,
            self.inner.cancellation_publications.get(),
        ) else {
            return;
        };
        let _buffer = self.inner.buffer.lock();
        let mut publications = publications.lock();
        let Some(index) = publications
            .spans
            .iter()
            .position(|span| span.start_sequence == start_sequence)
        else {
            // The bounded witness store already counted this eviction.
            return;
        };
        if request_sequence.is_none() && !unsupported_mutation {
            publications.spans.remove(index);
            return;
        }
        let end_sequence = self.inner.next_seq.fetch_add(1, Ordering::Relaxed);
        let span = &mut publications.spans[index];
        span.end_sequence = Some(end_sequence);
        span.request_sequence = request_sequence;
        span.cleanup_budget = cleanup_budget;
        span.unsupported_mutation = unsupported_mutation;
    }

    /// [`Self::record_event`] for a task's Complete event. While completion
    /// outcomes are kept, `outcome` is recorded under the same sequence and
    /// the same lock, so a snapshot never sees one without the other.
    pub(crate) fn record_completion_event<F>(&self, outcome: Severity, build: F)
    where
        F: FnOnce(u64) -> TraceEvent,
    {
        self.record_completion_event_with_cancellation(outcome, None, build);
    }

    /// Pairs an authoritative terminal task-Cx witness with Complete. The
    /// caller samples the Cx before taking the trace lock; neither sampling
    /// nor reason cloning occurs when cancellation capture is disabled.
    pub(crate) fn record_completion_event_with_cancellation<F>(
        &self,
        outcome: Severity,
        cancellation: Option<TerminalCancellationState>,
        build: F,
    ) where
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
        if let Some(publications) = self.inner.cancellation_publications.get() {
            let mut publications = publications.lock();
            if publications.terminals.len() >= buffer.capacity() {
                publications.terminals.pop_front();
            }
            publications.terminals.push_back((seq, cancellation));
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

    /// A coherent capture boundary for events, outcomes, and publication spans.
    /// A publisher cannot finish its witness between the event snapshot and
    /// the metadata snapshot, nor hide an in-flight mutation from this receipt.
    pub(crate) fn snapshot_with_cancellation_publications(
        &self,
    ) -> (
        Vec<TraceEvent>,
        u64,
        Vec<(u64, Severity)>,
        CancellationPublicationSnapshot,
    ) {
        let buffer = self.inner.buffer.lock();
        let mut events: Vec<TraceEvent> = buffer.iter().cloned().collect();
        let total_pushed = self.inner.total_pushed.load(Ordering::Relaxed);
        let outcomes = self
            .inner
            .completion_outcomes
            .get()
            .map(|outcomes| outcomes.lock().iter().copied().collect())
            .unwrap_or_default();
        let publications = self
            .inner
            .cancellation_publications
            .get()
            .map(|publications| {
                let publications = publications.lock();
                CancellationPublicationSnapshot {
                    spans: publications.spans.iter().cloned().collect(),
                    dropped_spans: publications.dropped_spans,
                    terminals: publications.terminals.iter().cloned().collect(),
                }
            })
            .unwrap_or_default();
        drop(buffer);
        events.sort_by_key(|event| event.seq);
        (events, total_pushed, outcomes, publications)
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
