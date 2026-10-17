//! Order-preserving buffered combinator for streams of fallible futures.
//!
//! `TryBuffered` is the `Result`-aware sibling of
//! [`Buffered`](super::Buffered): it runs up to `limit` futures concurrently,
//! yields their outputs in source order, and stops at the first `Err`.

use super::buffered::EntryWakes;
use super::{Stream, StreamTelemetrySnapshot};
use std::collections::VecDeque;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

/// Cooperative budget for admitting new futures from the source stream.
///
/// Without this cap, large buffer limits plus always-ready upstream streams can
/// monopolize one executor turn while filling the in-flight queue.
const TRY_BUFFERED_ADMISSION_BUDGET: usize = 1024;

/// Cooperative budget for polling buffered futures in a single call.
///
/// Without this cap, large in-flight buffers can monopolize one executor turn
/// when every future is ready or repeatedly returns `Poll::Pending`.
///
/// A partial scan is only allowed to return a bare `Poll::Pending` once every
/// in-flight future has been polled at least once (with its own child waker,
/// see `EntryWakes` in `buffered.rs`). Until then the combinator self-wakes so
/// unpolled futures cannot be stranded — but it must NOT self-wake merely
/// because the buffer is larger than the budget, or an all-pending buffer
/// turns into a permanent busy-poll loop. A future woken outside the scan
/// window is found by its child waker's id and polled on the next poll.
const TRY_BUFFERED_POLL_BUDGET: usize = 1024;

struct TryBufferedEntry<Fut: Future> {
    fut: Fut,
    output: Option<Fut::Output>,
    /// Admission id; consecutive across the queue, which only pops its front.
    id: u64,
    /// This entry's child waker.
    waker: Waker,
    /// Polled at least once, so its child waker is registered wherever the
    /// future waits. Unpolled entries keep the self-wake loop alive.
    polled: bool,
}

impl<Fut: Future> TryBufferedEntry<Fut> {
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
    fn poll_entry(&mut self)
    where
        Fut: Unpin,
    {
        self.polled = true;
        let mut cx = Context::from_waker(&self.waker);
        if let Poll::Ready(output) = Pin::new(&mut self.fut).poll(&mut cx) {
            self.output = Some(output);
        }
    }
}

/// A stream that buffers fallible futures in order and short-circuits on `Err`.
///
/// Created by [`StreamExt::try_buffered`](super::StreamExt::try_buffered).
///
/// # Ordering and short-circuit interaction
///
/// Outputs are yielded in **source order**, not completion order. The first
/// `Err` *in source order* is the one that terminates the stream. A future that
/// fails early but sits later in the queue does not pre-empt an earlier `Ok`:
/// the earlier `Ok` is yielded first, and the `Err` surfaces when the cursor
/// reaches it. This is what makes the combinator deterministic — the terminating
/// error does not depend on completion timing.
///
/// # Cancel-safety boundary
///
/// The in-flight futures are plain futures owned by this combinator, not region
/// tasks. When the stream terminates on an `Err`, or when the combinator itself
/// is dropped, the remaining in-flight futures are **dropped, not drained**.
/// This matches [`Buffered`](super::Buffered), and it is the deliberate
/// difference from
/// [`try_for_each_concurrent`](super::try_for_each_concurrent), which owns real
/// region tasks and can therefore drain them. If the per-item work holds
/// obligations or needs a bounded cleanup path, use the concurrent `for_each`
/// family instead of this combinator.
#[must_use = "streams do nothing unless polled"]
pub struct TryBuffered<S>
where
    S: Stream,
    S::Item: Future,
{
    stream: S,
    in_flight: VecDeque<TryBufferedEntry<S::Item>>,
    limit: usize,
    /// Source stream reported end-of-stream.
    done: bool,
    /// An `Err` has already been yielded; the stream is terminated.
    failed: bool,
    next_poll_index: usize,
    /// Monotonic waker epoch. Incremented whenever the polling task's waker
    /// changes so newly admitted / not-yet-scanned entries can be detected.
    poll_epoch: u64,
    /// Waker the current `poll_epoch` corresponds to.
    epoch_waker: Option<Waker>,
    /// Per-entry wake routing.
    wakes: EntryWakes,
}

impl<S> TryBuffered<S>
where
    S: Stream,
    S::Item: Future,
{
    /// Creates a new `TryBuffered` stream with the given limit.
    #[inline]
    pub(crate) fn new(stream: S, limit: usize) -> Self {
        assert!(limit > 0, "try_buffered limit must be non-zero");
        Self {
            stream,
            // `limit` may be a huge "unbounded" value: reserving it up front
            // overflowed the capacity (usize::MAX) or aborted the allocation.
            in_flight: VecDeque::with_capacity(limit.min(TRY_BUFFERED_ADMISSION_BUDGET)),
            limit,
            done: false,
            failed: false,
            next_poll_index: 0,
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

    /// Number of futures currently in flight.
    #[inline]
    #[must_use]
    pub fn in_flight_len(&self) -> usize {
        self.in_flight.len()
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
    /// the determinism contract. `closed` is true once no further futures will
    /// be admitted: the source is exhausted *or* the stream already yielded
    /// its terminal `Err`.
    #[inline]
    #[must_use]
    pub fn telemetry_snapshot(&self, combinator_id: u64) -> StreamTelemetrySnapshot {
        StreamTelemetrySnapshot {
            combinator_id,
            combinator_kind: "try_buffered",
            limit: self.limit,
            in_flight: self.in_flight.len(),
            available: self.limit.saturating_sub(self.in_flight.len()),
            ready_results: self
                .in_flight
                .iter()
                .filter(|entry| entry.output.is_some())
                .count(),
            waker_epoch: self.poll_epoch,
            closed: self.done || self.failed,
        }
    }
}

impl<S> Unpin for TryBuffered<S>
where
    S: Stream + Unpin,
    S::Item: Future + Unpin,
{
}

impl<S> fmt::Debug for TryBuffered<S>
where
    S: Stream,
    S::Item: Future,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TryBuffered")
            .field("in_flight", &self.in_flight.len())
            .field("limit", &self.limit)
            .field("done", &self.done)
            .field("failed", &self.failed)
            .finish_non_exhaustive()
    }
}

impl<S, T, E> Stream for TryBuffered<S>
where
    S: Stream + Unpin,
    S::Item: Future<Output = Result<T, E>> + Unpin,
{
    type Item = Result<T, E>;

    #[inline]
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // A yielded `Err` is terminal. Report end-of-stream without touching
        // the source again; the in-flight queue was already released.
        if self.failed {
            return Poll::Ready(None);
        }

        self.refresh_epoch(cx);
        self.wakes.set_parent(cx.waker());
        let mut budget_exhausted = false;

        // An `Err` already waiting at the front ends the stream on this poll:
        // admitting first would take more items from the source only to drop
        // them unpolled.
        let front_failed = matches!(
            self.in_flight.front(),
            Some(TryBufferedEntry {
                output: Some(Err(_)),
                ..
            })
        );
        let mut admitted_this_poll = 0usize;
        while !front_failed && !self.done && self.in_flight.len() < self.limit {
            if admitted_this_poll >= TRY_BUFFERED_ADMISSION_BUDGET {
                budget_exhausted = true;
                break;
            }
            match Pin::new(&mut self.stream).poll_next(cx) {
                Poll::Ready(Some(fut)) => {
                    let (id, waker) = self.wakes.child();
                    self.in_flight
                        .push_back(TryBufferedEntry::new(fut, id, waker));
                    admitted_this_poll += 1;
                }
                Poll::Ready(None) => {
                    self.done = true;
                    break;
                }
                Poll::Pending => break,
            }
        }

        if let Some(item) = self.take_ready_front() {
            return Poll::Ready(Some(item));
        }

        let len = self.in_flight.len();
        let woken = self.wakes.take_woken();
        if len > TRY_BUFFERED_POLL_BUDGET {
            // The window below reaches only part of the buffer, so first poll
            // the entries whose own wakers fired, wherever they sit. Ids are
            // consecutive from the front; an id below it already finished.
            let front_id = self.in_flight.front().map_or(0, |front| front.id);
            for (polled, id) in woken.iter().enumerate() {
                if polled >= TRY_BUFFERED_POLL_BUDGET {
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
            let scan_budget = len.min(TRY_BUFFERED_POLL_BUDGET);
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
            if self
                .in_flight
                .iter()
                .any(|e| e.output.is_none() && !e.polled)
            {
                budget_exhausted = true;
            }
        }

        if let Some(item) = self.take_ready_front() {
            return Poll::Ready(Some(item));
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
        if self.failed {
            return (0, Some(0));
        }
        let (_lower, upper) = self.stream.size_hint();
        let buffered = self.in_flight.len();
        // The lower bound is deliberately 0: any in-flight future may resolve
        // to `Err`, which terminates the stream immediately, so no minimum item
        // count can be promised. The upper bound still holds - short-circuiting
        // can only yield fewer items, never more.
        (0, upper.and_then(|u| u.checked_add(buffered)))
    }
}

impl<S, T, E> TryBuffered<S>
where
    S: Stream + Unpin,
    S::Item: Future<Output = Result<T, E>> + Unpin,
{
    /// Pops the front entry when its output is ready.
    ///
    /// On `Err` this marks the stream terminated and releases every remaining
    /// in-flight future, so the error is the last item the stream produces.
    #[inline]
    fn take_ready_front(&mut self) -> Option<Result<T, E>> {
        if !matches!(self.in_flight.front(), Some(front) if front.output.is_some()) {
            return None;
        }
        let mut entry = self.in_flight.pop_front().expect("front exists");
        let output = entry.output.take().expect("front output checked");

        if output.is_err() {
            // Short-circuit: drop the remaining in-flight futures. They are
            // plain futures, not region tasks, so dropping is the only
            // available disposal - see the type-level cancel-safety note.
            self.failed = true;
            self.in_flight.clear();
            self.next_poll_index = 0;
            return Some(output);
        }

        self.next_poll_index = self.next_poll_index.saturating_sub(1);
        if self.in_flight.is_empty() {
            self.next_poll_index = 0;
        } else {
            self.next_poll_index %= self.in_flight.len();
        }
        Some(output)
    }
}

#[cfg(test)]
#[path = "try_buffered_inline_tests.rs"]
mod tests;
