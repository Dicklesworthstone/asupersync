//! Buffered combinators for streams of futures.
//!
//! `Buffered` preserves output order, while `BufferUnordered` yields results
//! as soon as futures complete.

use super::{Stream, StreamTelemetrySnapshot};
use std::collections::{HashSet, VecDeque};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Wake, Waker};

/// Cooperative budget for admitting new futures from the source stream.
///
/// Without this cap, large buffer limits plus always-ready upstream streams can
/// monopolize one executor turn while filling the in-flight queue.
const BUFFERED_ADMISSION_BUDGET: usize = 1024;

/// Cooperative budget for polling buffered futures in a single call.
///
/// Without this cap, large in-flight buffers can monopolize one executor turn
/// when every future is ready or repeatedly returns `Poll::Pending`.
///
/// A partial scan is only allowed to return a bare `Poll::Pending` once every
/// in-flight future has been polled at least once (with its own child waker,
/// see [`EntryWakes`]). Until then the combinator self-wakes so unpolled
/// futures cannot be stranded — but it must NOT self-wake merely because the
/// buffer is larger than the budget, or an all-pending buffer turns into a
/// permanent busy-poll loop. A future woken outside the scan window is found
/// by its child waker's id and polled on the next poll.
const BUFFERED_POLL_BUDGET: usize = 1024;

/// Per-entry wake routing for the buffering combinators.
///
/// Every buffered future is polled with its own child waker, which records the
/// entry's id and then wakes the task. A buffer larger than the per-poll scan
/// budget polls only a window of its entries each time, and a future's wake
/// consumes its registration: woken while outside the window, it used to sit
/// unpolled with nothing left to wake the task, so the stream parked forever.
/// The woken ids say which entries to poll regardless of the window.
pub(super) struct EntryWakes {
    shared: Arc<WakeShared>,
    next_id: u64,
}

struct WakeShared {
    /// The polling task's current waker; a child wake is forwarded to it.
    parent: Mutex<Option<Waker>>,
    /// Ids of the entries woken since the last poll took them.
    woken: Mutex<Vec<u64>>,
}

struct EntryWake {
    id: u64,
    shared: Arc<WakeShared>,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Wake for EntryWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        lock(&self.shared.woken).push(self.id);
        let parent = lock(&self.shared.parent).clone();
        if let Some(parent) = parent {
            parent.wake();
        }
    }
}

impl EntryWakes {
    pub(super) fn new() -> Self {
        Self {
            shared: Arc::new(WakeShared {
                parent: Mutex::new(None),
                woken: Mutex::new(Vec::new()),
            }),
            next_id: 0,
        }
    }

    /// Makes `waker` (the polling task's) the target of every child wake.
    pub(super) fn set_parent(&self, waker: &Waker) {
        let mut parent = lock(&self.shared.parent);
        if !parent
            .as_ref()
            .is_some_and(|current| current.will_wake(waker))
        {
            *parent = Some(waker.clone());
        }
    }

    /// A fresh id and child waker for a newly admitted entry. Ids increase in
    /// admission order.
    pub(super) fn child(&mut self) -> (u64, Waker) {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let waker = Waker::from(Arc::new(EntryWake {
            id,
            shared: Arc::clone(&self.shared),
        }));
        (id, waker)
    }

    /// The ids woken since the last call, ascending and without duplicates.
    pub(super) fn take_woken(&self) -> Vec<u64> {
        let mut ids = std::mem::take(&mut *lock(&self.shared.woken));
        ids.sort_unstable();
        ids.dedup();
        ids
    }

    /// Returns ids this poll did not get to, for the next poll.
    pub(super) fn requeue(&self, ids: &[u64]) {
        lock(&self.shared.woken).extend_from_slice(ids);
    }
}

struct BufferedEntry<Fut: Future> {
    fut: Fut,
    output: Option<Fut::Output>,
    /// Admission id; consecutive across the queue, which only pops its front.
    id: u64,
    /// This entry's child waker (see [`EntryWakes`]).
    waker: Waker,
    /// Polled at least once, so its child waker is registered wherever the
    /// future waits. Unpolled entries keep the self-wake loop alive.
    polled: bool,
}

impl<Fut: Future> BufferedEntry<Fut> {
    #[inline]
    fn new(fut: Fut, id: u64, waker: Waker) -> Self {
        Self {
            fut,
            output: None,
            id,
            waker,
            polled: false,
        }
    }

    /// Polls the future with its own child waker, keeping a ready output.
    #[inline]
    fn poll_entry(&mut self) -> bool
    where
        Fut: Unpin,
    {
        self.polled = true;
        let mut cx = Context::from_waker(&self.waker);
        if let Poll::Ready(output) = Pin::new(&mut self.fut).poll(&mut cx) {
            self.output = Some(output);
            return true;
        }
        false
    }
}

/// A stream that buffers and polls futures, preserving order.
///
/// Created by [`StreamExt::buffered`](super::StreamExt::buffered).
#[must_use = "streams do nothing unless polled"]
pub struct Buffered<S>
where
    S: Stream,
    S::Item: Future,
{
    stream: S,
    in_flight: VecDeque<BufferedEntry<S::Item>>,
    limit: usize,
    done: bool,
    next_poll_index: usize,
    /// Monotonic waker epoch. Incremented whenever the polling task's waker
    /// changes so newly admitted / not-yet-scanned entries can be detected.
    poll_epoch: u64,
    /// Waker the current `poll_epoch` corresponds to.
    epoch_waker: Option<Waker>,
    /// Per-entry wake routing.
    wakes: EntryWakes,
}

impl<S> Buffered<S>
where
    S: Stream,
    S::Item: Future,
{
    /// Creates a new `Buffered` stream with the given limit.
    #[inline]
    pub(crate) fn new(stream: S, limit: usize) -> Self {
        assert!(limit > 0, "buffered limit must be non-zero");
        Self {
            stream,
            // `limit` may be a huge "unbounded" value: reserving it up front
            // overflowed the capacity (usize::MAX) or aborted the allocation.
            in_flight: VecDeque::with_capacity(limit.min(BUFFERED_ADMISSION_BUDGET)),
            limit,
            done: false,
            next_poll_index: 0,
            poll_epoch: 0,
            epoch_waker: None,
            wakes: EntryWakes::new(),
        }
    }

    /// Refreshes the waker epoch when the polling task's waker changes.
    ///
    /// Returns the epoch that entries admitted *before* this poll should be
    /// compared against: a fresh entry is stamped one below the current epoch
    /// so it always reads as "not yet polled under the current waker" until it
    /// is actually scanned.
    #[inline]
    fn refresh_epoch(&mut self, cx: &Context<'_>) {
        match &self.epoch_waker {
            Some(w) if w.will_wake(cx.waker()) => {}
            _ => {
                self.poll_epoch = self.poll_epoch.wrapping_add(1);
                self.epoch_waker = Some(cx.waker().clone());
            }
        }
    }

    /// Returns a reference to the underlying stream.
    #[inline]
    pub fn get_ref(&self) -> &S {
        &self.stream
    }

    /// Returns a mutable reference to the underlying stream.
    #[inline]
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    /// Consumes the combinator, returning the underlying stream.
    #[inline]
    pub fn into_inner(self) -> S {
        self.stream
    }

    /// Returns an opt-in redacted telemetry snapshot for this combinator.
    ///
    /// The caller supplies `combinator_id` so the runtime needs no ambient
    /// registration. See [`StreamTelemetrySnapshot`] for field semantics and
    /// the determinism contract.
    #[inline]
    #[must_use]
    pub fn telemetry_snapshot(&self, combinator_id: u64) -> StreamTelemetrySnapshot {
        StreamTelemetrySnapshot {
            combinator_id,
            combinator_kind: "buffered",
            limit: self.limit,
            in_flight: self.in_flight.len(),
            available: self.limit.saturating_sub(self.in_flight.len()),
            ready_results: self
                .in_flight
                .iter()
                .filter(|entry| entry.output.is_some())
                .count(),
            waker_epoch: self.poll_epoch,
            closed: self.done,
        }
    }
}

impl<S> Unpin for Buffered<S>
where
    S: Stream + Unpin,
    S::Item: Future + Unpin,
{
}

impl<S> Stream for Buffered<S>
where
    S: Stream + Unpin,
    S::Item: Future + Unpin,
{
    type Item = <S::Item as Future>::Output;

    #[inline]
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.refresh_epoch(cx);
        self.wakes.set_parent(cx.waker());
        let mut budget_exhausted = false;
        let mut admitted_this_poll = 0usize;
        while !self.done && self.in_flight.len() < self.limit {
            if admitted_this_poll >= BUFFERED_ADMISSION_BUDGET {
                budget_exhausted = true;
                break;
            }
            match Pin::new(&mut self.stream).poll_next(cx) {
                Poll::Ready(Some(fut)) => {
                    let (id, waker) = self.wakes.child();
                    self.in_flight.push_back(BufferedEntry::new(fut, id, waker));
                    admitted_this_poll += 1;
                }
                Poll::Ready(None) => {
                    self.done = true;
                    break;
                }
                Poll::Pending => break,
            }
        }

        if matches!(self.in_flight.front(), Some(front) if front.output.is_some()) {
            let mut entry = self.in_flight.pop_front().expect("front exists");
            self.next_poll_index = self.next_poll_index.saturating_sub(1);
            if self.in_flight.is_empty() {
                self.next_poll_index = 0;
            } else {
                self.next_poll_index %= self.in_flight.len();
            }
            return Poll::Ready(entry.output.take());
        }

        let len = self.in_flight.len();
        let woken = self.wakes.take_woken();
        if len > BUFFERED_POLL_BUDGET {
            // The window below reaches only part of the buffer, so first poll
            // the entries whose own wakers fired, wherever they sit. Ids are
            // consecutive from the front; an id below it already finished.
            let front_id = self.in_flight.front().map_or(0, |front| front.id);
            for (polled, id) in woken.iter().enumerate() {
                if polled >= BUFFERED_POLL_BUDGET {
                    self.wakes.requeue(&woken[polled..]);
                    budget_exhausted = true;
                    break;
                }
                let index = id
                    .checked_sub(front_id)
                    .and_then(|offset| usize::try_from(offset).ok());
                if let Some(entry) = index.and_then(|index| self.in_flight.get_mut(index))
                    && entry.id == *id
                    && entry.output.is_none()
                {
                    entry.poll_entry();
                }
            }
        }
        if len > 0 {
            let mut index = self.next_poll_index.min(len.saturating_sub(1));
            let scan_budget = len.min(BUFFERED_POLL_BUDGET);
            for _ in 0..scan_budget {
                if let Some(entry) = self.in_flight.get_mut(index)
                    && entry.output.is_none()
                {
                    entry.poll_entry();
                }
                index += 1;
                if index >= len {
                    index = 0;
                }
            }
            self.next_poll_index = index;
            // Self-wake ONLY while never-polled entries remain (buffer larger
            // than the per-poll scan budget). Once every pending future has
            // been polled, a bare Pending is safe: each one wakes its own child
            // waker on progress. A blanket `len > BUFFERED_POLL_BUDGET`
            // self-wake would busy-loop forever on an all-pending oversized
            // buffer (br fresh-eyes: buffered-busy-poll).
            if self
                .in_flight
                .iter()
                .any(|e| e.output.is_none() && !e.polled)
            {
                budget_exhausted = true;
            }
        }

        if matches!(self.in_flight.front(), Some(front) if front.output.is_some()) {
            let mut entry = self.in_flight.pop_front().expect("front exists");
            self.next_poll_index = self.next_poll_index.saturating_sub(1);
            if self.in_flight.is_empty() {
                self.next_poll_index = 0;
            } else {
                self.next_poll_index %= self.in_flight.len();
            }
            return Poll::Ready(entry.output.take());
        }

        if self.done && self.in_flight.is_empty() {
            Poll::Ready(None)
        } else {
            if budget_exhausted {
                cx.waker().wake_by_ref();
            }
            Poll::Pending
        }
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        let (lower, upper) = self.stream.size_hint();
        let in_flight = self.in_flight.len();

        let lower = lower.saturating_add(in_flight);
        let upper = upper.and_then(|u| u.checked_add(in_flight));

        (lower, upper)
    }
}

/// A stream that buffers and polls futures, yielding results as they complete.
///
/// Created by [`StreamExt::buffer_unordered`](super::StreamExt::buffer_unordered).
#[must_use = "streams do nothing unless polled"]
pub struct BufferUnordered<S>
where
    S: Stream,
    S::Item: Future,
{
    stream: S,
    in_flight: VecDeque<UnorderedEntry<S::Item>>,
    limit: usize,
    done: bool,
    /// Monotonic waker epoch (see `Buffered::refresh_epoch`).
    poll_epoch: u64,
    /// Waker the current `poll_epoch` corresponds to.
    epoch_waker: Option<Waker>,
    /// Per-entry wake routing.
    wakes: EntryWakes,
}

/// A pending future with its child waker, so an oversized `BufferUnordered`
/// (limit > `BUFFERED_POLL_BUDGET`) can tell a never-polled entry from one
/// whose waker is registered, and find the entry a wake names.
struct UnorderedEntry<Fut> {
    fut: Fut,
    /// Admission id, to find the entry a child wake names.
    id: u64,
    /// This entry's child waker (see [`EntryWakes`]).
    waker: Waker,
    /// Polled at least once (see [`BufferedEntry::polled`]).
    polled: bool,
}

impl<Fut: Future + Unpin> UnorderedEntry<Fut> {
    /// Polls the future with its own child waker.
    #[inline]
    fn poll_entry(&mut self) -> Poll<Fut::Output> {
        self.polled = true;
        let mut cx = Context::from_waker(&self.waker);
        Pin::new(&mut self.fut).poll(&mut cx)
    }
}

impl<S> fmt::Debug for Buffered<S>
where
    S: Stream,
    S::Item: Future,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Buffered")
            .field("in_flight", &self.in_flight.len())
            .field("limit", &self.limit)
            .field("done", &self.done)
            .finish_non_exhaustive()
    }
}

impl<S> fmt::Debug for BufferUnordered<S>
where
    S: Stream,
    S::Item: Future,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BufferUnordered")
            .field("in_flight", &self.in_flight.len())
            .field("limit", &self.limit)
            .field("done", &self.done)
            .finish_non_exhaustive()
    }
}

impl<S> BufferUnordered<S>
where
    S: Stream,
    S::Item: Future,
{
    /// Creates a new `BufferUnordered` stream with the given limit.
    #[inline]
    pub(crate) fn new(stream: S, limit: usize) -> Self {
        assert!(limit > 0, "buffer_unordered limit must be non-zero");
        Self {
            stream,
            in_flight: VecDeque::with_capacity(limit.min(BUFFERED_ADMISSION_BUDGET)),
            limit,
            done: false,
            poll_epoch: 0,
            epoch_waker: None,
            wakes: EntryWakes::new(),
        }
    }

    /// Refreshes the waker epoch when the polling task's waker changes.
    #[inline]
    fn refresh_epoch(&mut self, cx: &Context<'_>) {
        match &self.epoch_waker {
            Some(w) if w.will_wake(cx.waker()) => {}
            _ => {
                self.poll_epoch = self.poll_epoch.wrapping_add(1);
                self.epoch_waker = Some(cx.waker().clone());
            }
        }
    }

    /// Returns a reference to the underlying stream.
    #[inline]
    pub fn get_ref(&self) -> &S {
        &self.stream
    }

    /// Returns a mutable reference to the underlying stream.
    #[inline]
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    /// Consumes the combinator, returning the underlying stream.
    #[inline]
    pub fn into_inner(self) -> S {
        self.stream
    }

    /// Returns an opt-in redacted telemetry snapshot for this combinator.
    ///
    /// The caller supplies `combinator_id` so the runtime needs no ambient
    /// registration. See [`StreamTelemetrySnapshot`] for field semantics and
    /// the determinism contract. `ready_results` is structurally zero here:
    /// completions are yielded in the poll that observes them, never parked
    /// behind head-of-line ordering.
    #[inline]
    #[must_use]
    pub fn telemetry_snapshot(&self, combinator_id: u64) -> StreamTelemetrySnapshot {
        StreamTelemetrySnapshot {
            combinator_id,
            combinator_kind: "buffer_unordered",
            limit: self.limit,
            in_flight: self.in_flight.len(),
            available: self.limit.saturating_sub(self.in_flight.len()),
            ready_results: 0,
            waker_epoch: self.poll_epoch,
            closed: self.done,
        }
    }
}

impl<S> Unpin for BufferUnordered<S>
where
    S: Stream + Unpin,
    S::Item: Future + Unpin,
{
}

impl<S> Stream for BufferUnordered<S>
where
    S: Stream + Unpin,
    S::Item: Future + Unpin,
{
    type Item = <S::Item as Future>::Output;

    #[inline]
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.refresh_epoch(cx);
        self.wakes.set_parent(cx.waker());
        let mut budget_exhausted = false;
        let mut admitted_this_poll = 0usize;
        while !self.done && self.in_flight.len() < self.limit {
            if admitted_this_poll >= BUFFERED_ADMISSION_BUDGET {
                budget_exhausted = true;
                break;
            }
            match Pin::new(&mut self.stream).poll_next(cx) {
                Poll::Ready(Some(fut)) => {
                    let (id, waker) = self.wakes.child();
                    self.in_flight.push_back(UnorderedEntry {
                        fut,
                        id,
                        waker,
                        polled: false,
                    });
                    admitted_this_poll += 1;
                }
                Poll::Ready(None) => {
                    self.done = true;
                    break;
                }
                Poll::Pending => break,
            }
        }

        let len = self.in_flight.len();
        let woken = self.wakes.take_woken();
        if len > BUFFERED_POLL_BUDGET && !woken.is_empty() {
            // The rotation below reaches only part of the buffer, so first
            // poll the entries whose own wakers fired, wherever they sit.
            let mut pending: HashSet<u64> = woken.into_iter().collect();
            let mut polled = 0usize;
            let mut index = 0usize;
            while index < self.in_flight.len() && !pending.is_empty() {
                if polled >= BUFFERED_POLL_BUDGET {
                    budget_exhausted = true;
                    break;
                }
                let entry = &mut self.in_flight[index];
                if pending.remove(&entry.id) {
                    polled += 1;
                    if let Poll::Ready(output) = entry.poll_entry() {
                        self.in_flight.remove(index);
                        let rest: Vec<u64> = pending.into_iter().collect();
                        self.wakes.requeue(&rest);
                        return Poll::Ready(Some(output));
                    }
                }
                index += 1;
            }
            // Ids not found finished earlier; ids not reached wait for the
            // next poll.
            if budget_exhausted {
                let rest: Vec<u64> = pending.into_iter().collect();
                self.wakes.requeue(&rest);
            }
        }
        let poll_budget = len.min(BUFFERED_POLL_BUDGET);
        for _ in 0..poll_budget {
            let mut entry = self.in_flight.pop_front().expect("length checked");
            match entry.poll_entry() {
                Poll::Ready(output) => return Poll::Ready(Some(output)),
                Poll::Pending => {
                    // Its child waker is registered; rotate to the back.
                    self.in_flight.push_back(entry);
                }
            }
        }
        // Self-wake only while never-polled entries remain (buffer larger
        // than the per-poll budget). Once every future has been polled, a bare
        // Pending is safe: each one wakes its own child waker on progress. A
        // blanket `len > BUFFERED_POLL_BUDGET` self-wake busy-loops forever on
        // an all-pending oversized buffer (br fresh-eyes: buffered-busy-poll).
        if self.in_flight.iter().any(|e| !e.polled) {
            budget_exhausted = true;
        }

        if self.done && self.in_flight.is_empty() {
            Poll::Ready(None)
        } else {
            if budget_exhausted {
                cx.waker().wake_by_ref();
            }
            Poll::Pending
        }
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        let (lower, upper) = self.stream.size_hint();
        let in_flight = self.in_flight.len();

        let lower = lower.saturating_add(in_flight);
        let upper = upper.and_then(|u| u.checked_add(in_flight));

        (lower, upper)
    }
}

#[cfg(test)]
#[path = "buffered_inline_tests.rs"]
mod tests;
