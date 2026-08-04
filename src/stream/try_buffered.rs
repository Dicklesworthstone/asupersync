//! Order-preserving buffered combinator for streams of fallible futures.
//!
//! `TryBuffered` is the `Result`-aware sibling of
//! [`Buffered`](super::Buffered): it runs up to `limit` futures concurrently,
//! yields their outputs in source order, and stops at the first `Err`.

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
/// in-flight future has been polled at least once with the current task's waker
/// (tracked via a waker epoch). Until then the combinator self-wakes so unpolled
/// futures cannot be stranded — but it must NOT self-wake merely because the
/// buffer is larger than the budget, or an all-pending buffer turns into a
/// permanent busy-poll loop.
const TRY_BUFFERED_POLL_BUDGET: usize = 1024;

struct TryBufferedEntry<Fut: Future> {
    fut: Fut,
    output: Option<Fut::Output>,
    /// Waker epoch this entry was last polled under. Entries whose epoch lags
    /// the combinator's current epoch have not registered the current task
    /// waker and keep the self-wake loop alive until scanned.
    seen_epoch: u64,
}

impl<Fut: Future> TryBufferedEntry<Fut> {
    #[inline]
    fn new(fut: Fut, stale_epoch: u64) -> Self {
        Self {
            fut,
            output: None,
            seen_epoch: stale_epoch,
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
            in_flight: VecDeque::with_capacity(limit),
            limit,
            done: false,
            failed: false,
            next_poll_index: 0,
            poll_epoch: 0,
            epoch_waker: None,
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
        let epoch = self.poll_epoch;
        // Fresh entries are stamped one epoch behind so they read as "not yet
        // polled under the current waker" until the scan reaches them.
        let stale = epoch.wrapping_sub(1);
        let mut budget_exhausted = false;

        let mut admitted_this_poll = 0usize;
        while !self.done && self.in_flight.len() < self.limit {
            if admitted_this_poll >= TRY_BUFFERED_ADMISSION_BUDGET {
                budget_exhausted = true;
                break;
            }
            match Pin::new(&mut self.stream).poll_next(cx) {
                Poll::Ready(Some(fut)) => {
                    self.in_flight.push_back(TryBufferedEntry::new(fut, stale));
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
        if len > 0 {
            let mut index = self.next_poll_index.min(len.saturating_sub(1));
            let scan_budget = len.min(TRY_BUFFERED_POLL_BUDGET);
            for _ in 0..scan_budget {
                if let Some(entry) = self.in_flight.get_mut(index) {
                    if entry.output.is_none() {
                        if let Poll::Ready(output) = Pin::new(&mut entry.fut).poll(cx) {
                            entry.output = Some(output);
                        }
                        entry.seen_epoch = epoch;
                    }
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
                .any(|e| e.output.is_none() && e.seen_epoch != epoch)
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
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::future_not_send
    )]
    use super::*;
    use crate::stream::iter;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::task::Wake;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    struct TrackWaker(Arc<AtomicBool>);

    impl Wake for TrackWaker {
        fn wake(self: Arc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    /// A future that reports `Pending` for `delay` polls, then resolves.
    ///
    /// Used to make completion order differ from source order, so the
    /// order-preservation contract is actually exercised rather than
    /// accidentally satisfied by everything being ready at once.
    #[derive(Debug)]
    struct DelayedResult {
        delay: usize,
        value: Option<Result<usize, &'static str>>,
    }

    impl DelayedResult {
        fn new(delay: usize, value: Result<usize, &'static str>) -> Self {
            Self {
                delay,
                value: Some(value),
            }
        }
    }

    impl Future for DelayedResult {
        type Output = Result<usize, &'static str>;

        fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            if self.delay > 0 {
                self.delay -= 1;
                return Poll::Pending;
            }
            Poll::Ready(self.value.take().expect("DelayedResult polled after ready"))
        }
    }

    /// Drives the stream until it yields an item or ends, with a poll ceiling
    /// so a hang fails loudly instead of spinning.
    fn next_item<S>(stream: &mut S) -> Option<S::Item>
    where
        S: Stream + Unpin,
    {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut pending_polls = 0usize;
        loop {
            match Pin::new(&mut *stream).poll_next(&mut cx) {
                Poll::Ready(item) => return item,
                Poll::Pending => {
                    pending_polls += 1;
                    assert!(
                        pending_polls <= 512,
                        "try_buffered stream made no progress after {pending_polls} pending polls",
                    );
                }
            }
        }
    }

    fn drain<S>(stream: &mut S) -> Vec<S::Item>
    where
        S: Stream + Unpin,
    {
        let mut out = Vec::new();
        while let Some(item) = next_item(stream) {
            out.push(item);
        }
        out
    }

    #[test]
    fn try_buffered_yields_all_ok_in_source_order() {
        init_test("try_buffered_yields_all_ok_in_source_order");
        // Completion order is deliberately the REVERSE of source order.
        let futures = vec![
            DelayedResult::new(6, Ok(1)),
            DelayedResult::new(4, Ok(2)),
            DelayedResult::new(2, Ok(3)),
            DelayedResult::new(0, Ok(4)),
        ];
        let mut stream = TryBuffered::new(iter(futures), 4);
        let collected = drain(&mut stream);
        let values: Vec<usize> = collected.iter().map(|r| *r.as_ref().unwrap()).collect();
        crate::assert_with_log!(
            values == vec![1, 2, 3, 4],
            "source order preserved despite reversed completion order",
            vec![1, 2, 3, 4],
            values
        );
        crate::test_complete!("try_buffered_yields_all_ok_in_source_order");
    }

    #[test]
    fn try_buffered_short_circuits_on_first_error_in_source_order() {
        init_test("try_buffered_short_circuits_on_first_error_in_source_order");
        // Item 3 fails but completes FIRST; item 1 is Ok but completes last.
        // Source order must decide, so 1 is still yielded before the failure.
        let futures = vec![
            DelayedResult::new(8, Ok(1)),
            DelayedResult::new(0, Err("boom")),
            DelayedResult::new(0, Ok(3)),
        ];
        let mut stream = TryBuffered::new(iter(futures), 3);
        let collected = drain(&mut stream);
        crate::assert_with_log!(
            collected.len() == 2,
            "exactly the leading Ok plus the terminating Err",
            2,
            collected.len()
        );
        crate::assert_with_log!(
            collected[0] == Ok(1),
            "leading Ok yielded before the earlier-completing Err",
            Ok::<usize, &str>(1),
            collected[0]
        );
        crate::assert_with_log!(
            collected[1] == Err("boom"),
            "error terminates the stream",
            Err::<usize, &str>("boom"),
            collected[1]
        );
        crate::test_complete!("try_buffered_short_circuits_on_first_error_in_source_order");
    }

    #[test]
    fn try_buffered_releases_in_flight_futures_on_error() {
        init_test("try_buffered_releases_in_flight_futures_on_error");
        let dropped = Arc::new(AtomicUsize::new(0));

        struct CountingDrop {
            counter: Arc<AtomicUsize>,
            value: Option<Result<usize, &'static str>>,
            delay: usize,
        }
        impl Future for CountingDrop {
            type Output = Result<usize, &'static str>;
            fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
                if self.delay > 0 {
                    self.delay -= 1;
                    return Poll::Pending;
                }
                Poll::Ready(self.value.take().expect("polled after ready"))
            }
        }
        impl Drop for CountingDrop {
            fn drop(&mut self) {
                self.counter.fetch_add(1, Ordering::SeqCst);
            }
        }

        let futures = vec![
            CountingDrop {
                counter: dropped.clone(),
                value: Some(Err("fail-first")),
                delay: 0,
            },
            CountingDrop {
                counter: dropped.clone(),
                value: Some(Ok(2)),
                delay: 64,
            },
            CountingDrop {
                counter: dropped.clone(),
                value: Some(Ok(3)),
                delay: 64,
            },
        ];
        let mut stream = TryBuffered::new(iter(futures), 3);
        let first = next_item(&mut stream).expect("error item");
        crate::assert_with_log!(
            first == Err("fail-first"),
            "first item is the error",
            Err::<usize, &str>("fail-first"),
            first
        );
        crate::assert_with_log!(
            stream.in_flight_len() == 0,
            "in-flight futures released at short-circuit",
            0,
            stream.in_flight_len()
        );
        // The failing future plus the two still-pending futures are all gone.
        crate::assert_with_log!(
            dropped.load(Ordering::SeqCst) == 3,
            "every future dropped once the stream short-circuited",
            3,
            dropped.load(Ordering::SeqCst)
        );
        crate::assert_with_log!(
            next_item(&mut stream).is_none(),
            "stream is terminated after the error",
            true,
            next_item(&mut stream).is_none()
        );
        crate::test_complete!("try_buffered_releases_in_flight_futures_on_error");
    }

    #[test]
    fn try_buffered_reports_end_of_stream_after_error() {
        init_test("try_buffered_reports_end_of_stream_after_error");
        let futures = vec![DelayedResult::new(0, Err("done"))];
        let mut stream = TryBuffered::new(iter(futures), 2);
        let _ = next_item(&mut stream);
        let hint = stream.size_hint();
        crate::assert_with_log!(
            hint == (0, Some(0)),
            "terminated stream advertises an empty size hint",
            (0usize, Some(0usize)),
            hint
        );
        for _ in 0..3 {
            crate::assert_with_log!(
                next_item(&mut stream).is_none(),
                "repeated polls stay terminated",
                true,
                true
            );
        }
        crate::test_complete!("try_buffered_reports_end_of_stream_after_error");
    }

    #[test]
    fn try_buffered_yields_after_budget_on_always_ready_stream() {
        init_test("try_buffered_yields_after_budget_on_always_ready_stream");
        // More futures available than the admission budget allows in one poll.
        // They stay Pending so no output can be yielded and the poll outcome is
        // decided purely by the admission budget.
        let futures: Vec<_> = (0..TRY_BUFFERED_ADMISSION_BUDGET + 5)
            .map(|i| DelayedResult::new(4096, Ok(i)))
            .collect();
        let mut stream = TryBuffered::new(iter(futures), TRY_BUFFERED_ADMISSION_BUDGET + 16);
        let woke = Arc::new(AtomicBool::new(false));
        let waker = Waker::from(Arc::new(TrackWaker(woke.clone())));
        let mut cx = Context::from_waker(&waker);

        let first = Pin::new(&mut stream).poll_next(&mut cx);
        // The buffer limit is deliberately above the admission budget, so the
        // only thing that can stop admission mid-source is the budget itself.
        crate::assert_with_log!(
            matches!(first, Poll::Pending),
            "first poll yields cooperatively at the admission budget",
            "Poll::Pending",
            first
        );
        crate::assert_with_log!(
            stream.in_flight_len() == TRY_BUFFERED_ADMISSION_BUDGET,
            "admitted exactly the admission budget",
            TRY_BUFFERED_ADMISSION_BUDGET,
            stream.in_flight_len()
        );
        crate::assert_with_log!(
            woke.load(Ordering::SeqCst),
            "self-wake requested so the yield is not a stall",
            true,
            woke.load(Ordering::SeqCst)
        );
        crate::test_complete!("try_buffered_yields_after_budget_on_always_ready_stream");
    }

    #[test]
    #[should_panic(expected = "try_buffered limit must be non-zero")]
    fn try_buffered_rejects_zero_limit() {
        let futures: Vec<DelayedResult> = Vec::new();
        let _ = TryBuffered::new(iter(futures), 0);
    }

    #[test]
    fn try_buffered_empty_source_completes_immediately() {
        init_test("try_buffered_empty_source_completes_immediately");
        let futures: Vec<DelayedResult> = Vec::new();
        let mut stream = TryBuffered::new(iter(futures), 4);
        crate::assert_with_log!(
            next_item(&mut stream).is_none(),
            "empty source ends the stream",
            true,
            true
        );
        crate::test_complete!("try_buffered_empty_source_completes_immediately");
    }

    /// Spec: the type-level docs on [`TryBuffered`] plus the
    /// `TRY_BUFFERED_ADMISSION_BUDGET` / `TRY_BUFFERED_POLL_BUDGET` constants.
    /// These MUST clauses hold across every admission / drain cycle.
    mod try_buffered_conformance {
        use super::*;

        #[test]
        fn concurrency_never_exceeds_limit() {
            init_test("try_buffered_conformance::concurrency_never_exceeds_limit");
            let futures: Vec<_> = (0..32).map(|i| DelayedResult::new(3, Ok(i))).collect();
            let mut stream = TryBuffered::new(iter(futures), 4);
            let waker = noop_waker();
            let mut cx = Context::from_waker(&waker);
            let mut observed_max = 0usize;
            for _ in 0..2048 {
                let poll = Pin::new(&mut stream).poll_next(&mut cx);
                observed_max = observed_max.max(stream.in_flight_len());
                crate::assert_with_log!(
                    stream.in_flight_len() <= 4,
                    "in-flight count never exceeds the limit",
                    "<= 4",
                    stream.in_flight_len()
                );
                if matches!(poll, Poll::Ready(None)) {
                    break;
                }
            }
            crate::assert_with_log!(
                observed_max > 1,
                "the limit was actually exercised, not trivially satisfied",
                "> 1",
                observed_max
            );
            crate::test_complete!("try_buffered_conformance::concurrency_never_exceeds_limit");
        }

        #[test]
        fn all_pending_buffer_does_not_busy_poll() {
            init_test("try_buffered_conformance::all_pending_buffer_does_not_busy_poll");
            // Every future stays Pending for longer than the test polls, so
            // after the first scan every entry has been seen under the current
            // waker and the combinator must STOP self-waking. A regression here
            // turns an idle buffer into a 100% CPU spin.
            let futures: Vec<_> = (0..4).map(|i| DelayedResult::new(4096, Ok(i))).collect();
            let mut stream = TryBuffered::new(iter(futures), 4);
            let woke = Arc::new(AtomicBool::new(false));
            let waker = Waker::from(Arc::new(TrackWaker(woke.clone())));
            let mut cx = Context::from_waker(&waker);

            let _ = Pin::new(&mut stream).poll_next(&mut cx);
            woke.store(false, Ordering::SeqCst);
            let second = Pin::new(&mut stream).poll_next(&mut cx);
            crate::assert_with_log!(
                matches!(second, Poll::Pending),
                "all-pending buffer reports Pending",
                "Poll::Pending",
                second
            );
            crate::assert_with_log!(
                !woke.load(Ordering::SeqCst),
                "no self-wake once every entry was scanned under this waker",
                false,
                woke.load(Ordering::SeqCst)
            );
            crate::test_complete!(
                "try_buffered_conformance::all_pending_buffer_does_not_busy_poll"
            );
        }
    }

    /// AC5 lifecycle proof for `TryBuffered`: the snapshot exposes head-of-line
    /// pressure (a completed `Err` parked behind a pending `Ok`), and `closed`
    /// turns true on the terminal `Err` even though the source was never
    /// exhausted.
    #[test]
    fn telemetry_snapshot_reports_parked_results_and_terminal_err() {
        init_test("telemetry_snapshot_reports_parked_results_and_terminal_err");
        // Source order: a delayed Ok, then an immediate Err. The Err completes
        // first but must wait behind the Ok, which is exactly the parked-result
        // state the snapshot needs to make visible.
        let mut stream = TryBuffered::new(
            iter(vec![
                DelayedResult::new(1, Ok(1)),
                DelayedResult::new(0, Err("boom")),
            ]),
            2,
        );

        let fresh = stream.telemetry_snapshot(11);
        let expected_fresh = StreamTelemetrySnapshot {
            combinator_id: 11,
            combinator_kind: "try_buffered",
            limit: 2,
            in_flight: 0,
            available: 2,
            ready_results: 0,
            waker_epoch: 0,
            closed: false,
        };
        crate::assert_with_log!(
            fresh == expected_fresh,
            "fresh combinator reports empty pressure",
            expected_fresh,
            fresh
        );

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // First poll: both admitted; the Err completes and parks behind the
        // still-pending Ok.
        let first = Pin::new(&mut stream).poll_next(&mut cx);
        crate::assert_with_log!(
            matches!(first, Poll::Pending),
            "first poll is pending on the head-of-line future",
            "Poll::Pending",
            first
        );
        let parked = stream.telemetry_snapshot(11);
        crate::assert_with_log!(
            parked.in_flight == 2 && parked.ready_results == 1 && !parked.closed,
            "the completed Err is parked behind head-of-line order",
            (2usize, 1usize, false),
            (parked.in_flight, parked.ready_results, parked.closed)
        );

        // The Ok resolves and is yielded in source order.
        let second = Pin::new(&mut stream).poll_next(&mut cx);
        crate::assert_with_log!(
            matches!(second, Poll::Ready(Some(Ok(1)))),
            "the head-of-line Ok is yielded first",
            "Poll::Ready(Some(Ok(1)))",
            second
        );

        // The parked Err becomes the terminal item; the snapshot must report
        // the combinator closed although the source was never polled to None.
        let third = Pin::new(&mut stream).poll_next(&mut cx);
        crate::assert_with_log!(
            matches!(third, Poll::Ready(Some(Err("boom")))),
            "the parked Err terminates the stream",
            "Poll::Ready(Some(Err(\"boom\")))",
            third
        );
        let terminal = stream.telemetry_snapshot(11);
        crate::assert_with_log!(
            terminal.closed && terminal.in_flight == 0 && terminal.available == 2,
            "terminal-Err snapshot is closed and empty",
            (true, 0usize, 2usize),
            (terminal.closed, terminal.in_flight, terminal.available)
        );
        crate::test_complete!("telemetry_snapshot_reports_parked_results_and_terminal_err");
    }
}
