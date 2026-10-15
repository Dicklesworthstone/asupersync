//! Ordered collection of concurrent, region-owned stream work.
//!
//! Unlike buffering plain futures, these terminals use the stream task driver:
//! non-success stops admission and cancels and joins the remaining items before
//! returning. Successes are indexed by input order, not completion order.
//!
//! Bead: asupersync-dx-core-api-v2-u1z5hn.8 (bounded stream task composition).

use crate::cx::{ChildRegionError, ChildRegionSpec, Cx};
use crate::stream::{Stream, StreamExt, try_for_each_concurrent};
use crate::types::Outcome;
use parking_lot::Mutex;
use std::convert::Infallible;
use std::future::Future;
use std::sync::Arc;

/// An item failure or failure of the explicit stream cleanup boundary.
#[derive(Debug)]
#[non_exhaustive]
pub enum ScopedStreamError<E> {
    /// An item returned an application error.
    Item(E),
    /// The runtime refused region creation or could not confirm its closure.
    Region(ChildRegionError),
    /// A finalizer or other runtime-owned cleanup operation failed.
    Cleanup(crate::error::Error),
}

impl<E: std::fmt::Display> std::fmt::Display for ScopedStreamError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Item(error) => write!(f, "stream item failed: {error}"),
            Self::Region(error) => write!(f, "stream region failed: {error}"),
            Self::Cleanup(error) => write!(f, "stream cleanup failed: {error}"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for ScopedStreamError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Item(error) => Some(error),
            Self::Region(error) => Some(error),
            Self::Cleanup(error) => Some(error),
        }
    }
}

/// Executes fallible stream work inside one independently owned child region.
///
/// Unlike [`try_for_each_concurrent`], returning waits for the WHOLE work
/// subtree: direct item tasks, their descendants, and registered finalizers.
/// After direct work finishes, leftover descendants are cancelled, not allowed
/// to outlive the operation. On failure or owner cancellation the subtree is
/// cancelled BEFORE joining direct items, which may await descendant cleanup.
/// Unrelated work in the caller's region is neither cancelled nor awaited.
///
/// The existing stream driver still owns admission, wakeups, source/clone-panic
/// containment, and direct joins. `limit` bounds direct item tasks, not arbitrary
/// descendants they spawn. This adds one child region, not a coordinator task
/// or one region per item. The source may borrow and need not be `Send`.
/// Factories must use their supplied child `Cx` for work covered by this scope;
/// a captured outer context can deliberately spawn outside the boundary.
///
/// A finalizer or descendant panic wins over a direct result. Explicit finalizer
/// failure/cancellation is also reported; cancellation caused only by closing
/// leftover descendants does not replace an otherwise successful direct result.
/// Cleanup failure takes precedence over an item error. Runtime loss is a typed
/// region error, never a successful quiescence claim. The owner is checked again
/// after close so cancellation during cleanup cannot become success.
///
/// Dropping this future requests subtree close through its owned region handle;
/// it cannot synchronously wait for cleanup. Uncooperative callbacks, panicking
/// destructors and abort-on-panic builds retain the existing runtime boundaries.
/// The original shared-region stream APIs are unchanged.
///
/// # Panics
/// Panics if `limit` is zero, before opening a region or polling the source.
pub async fn try_for_each_concurrent_scoped<S, F, Fut, E>(
    cx: &Cx,
    stream: S,
    limit: usize,
    f: F,
) -> Outcome<(), ScopedStreamError<E>>
where
    S: Stream + Unpin,
    S::Item: Send + 'static,
    F: FnMut(Cx, S::Item) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = Result<(), E>> + Send + 'static,
    E: Send + 'static,
{
    assert!(limit > 0, "scoped stream concurrency limit must be non-zero");
    if cx.is_cancel_requested() {
        return Outcome::Cancelled(scoped_cancel_reason(cx));
    }
    // Observe mint completion even if cancellation arrives while opening. An
    // admitted region must be owned and closed, not merely abandoned on return.
    let region = match cx.open_child_region(ChildRegionSpec::inherit()).await {
        Ok(region) => region,
        Err(error) => return Outcome::Err(ScopedStreamError::Region(error)),
    };
    let work = region.for_each_stream(cx, stream, limit, f).await;
    let close = match region.close_with_outcome().await {
        Ok(close) => close,
        Err(error) => return Outcome::Err(ScopedStreamError::Region(error)),
    };
    let outcome = scoped_outcome(work, close);
    // A cancelled owner gets its own reason back, also when the stream driver
    // saw the cancellation while items ran: the driver reports that one with a
    // generic reason, so the same cancellation read differently depending on
    // whether it landed before the call, during the run or during close.
    if matches!(outcome, Outcome::Ok(()) | Outcome::Cancelled(_)) && cx.is_cancel_requested() {
        Outcome::Cancelled(scoped_cancel_reason(cx))
    } else {
        outcome
    }
}

/// Infallible item work with the subtree cleanup contract of
/// [`try_for_each_concurrent_scoped`]. Region and cleanup failures remain typed.
///
/// # Panics
/// Panics if `limit` is zero.
pub async fn for_each_concurrent_scoped<S, F, Fut>(
    cx: &Cx,
    stream: S,
    limit: usize,
    mut f: F,
) -> Outcome<(), ScopedStreamError<Infallible>>
where
    S: Stream + Unpin,
    S::Item: Send + 'static,
    F: FnMut(Cx, S::Item) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    try_for_each_concurrent_scoped(cx, stream, limit, move |child, item| {
        let future = f(child, item);
        async move {
            future.await;
            Ok(())
        }
    })
    .await
}

fn scoped_cancel_reason(cx: &Cx) -> crate::types::CancelReason {
    cx.cancel_reason().unwrap_or_else(|| {
        crate::types::CancelReason::user("scoped stream owner cancelled")
    })
}

pub(super) fn scoped_outcome<E>(
    work: Outcome<(), E>,
    close: crate::record::region::RegionCloseOutcome,
) -> Outcome<(), ScopedStreamError<E>> {
    // The region's aggregate includes cancellations we deliberately requested.
    // Its separate finalizer outcome distinguishes failed cleanup from that
    // expected consequence. Descendant panics must still be surfaced,
    // including one in a nested region, which reaches this region's receipt
    // apart from its own outcome (br-asupersync-b834ta).
    let cleanup = match (close.cleanup_outcome, close.descendant_panic) {
        (Some(Outcome::Panicked(payload)), _) | (_, Some(payload)) => {
            Some(Outcome::Panicked(payload))
        }
        (cleanup, None) => cleanup,
    };
    match (work, close.outcome, cleanup) {
        (_, _, Some(Outcome::Panicked(payload)))
        | (_, Outcome::Panicked(payload), _)
        | (Outcome::Panicked(payload), _, _) => Outcome::Panicked(payload),
        (_, _, Some(Outcome::Cancelled(reason))) => Outcome::Cancelled(reason),
        (_, _, Some(Outcome::Err(error))) => Outcome::Err(ScopedStreamError::Cleanup(error)),
        (Outcome::Ok(()), Outcome::Err(error), _) => {
            Outcome::Err(ScopedStreamError::Cleanup(error))
        }
        (Outcome::Ok(()), _, _) => Outcome::Ok(()),
        (Outcome::Err(error), _, _) => Outcome::Err(ScopedStreamError::Item(error)),
        (Outcome::Cancelled(reason), _, _) => Outcome::Cancelled(reason),
    }
}

/// Maps a stream concurrently and collects results in input order.
///
/// Each item runs as a region-owned task. At most `limit` items run at once;
/// successful values are retained until the complete collection is returned.
/// This bounds concurrent work, NOT total result memory: a finite source with
/// N items retains O(N) values. Bound an untrusted source with `StreamExt::take`
/// or use `for_each_concurrent` when its results need not be retained.
///
/// The factory is cloned per admitted item, as with `for_each_concurrent`.
/// Neither input nor output values need to be `Clone`. The source itself may
/// borrow caller state and need not be `Send`; the item tasks are `Send + 'static`.
/// A result must remain valid after its item task exits: returning a value does
/// not transfer a runtime obligation's holder liability to the collecting task.
///
/// Cancellation and panics are still possible with an infallible item function.
/// For fallible work, use [`try_map_collect_concurrent`].
///
/// # Panics
/// Panics if `limit` is zero.
pub async fn map_collect_concurrent<S, F, Fut, T>(
    cx: &Cx,
    stream: S,
    limit: usize,
    mut f: F,
) -> Outcome<Vec<T>, Infallible>
where
    S: Stream + Unpin,
    S::Item: Send + 'static,
    F: FnMut(Cx, S::Item) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    try_map_collect_concurrent(cx, stream, limit, move |item_cx, item| {
        let future = f(item_cx, item);
        async move { Ok(future.await) }
    })
    .await
}

/// Maps fallible work concurrently, returning ordered results only on success.
///
/// Input-order output does not impose input-order failure observation. The
/// first non-success observed by `try_for_each_concurrent` stops admission;
/// all remaining members are cancelled and joined. A panic during that drain
/// takes precedence over the initiating failure. Completed successes are
/// discarded after drain on failure, rather than returned as a partial success.
///
/// A slow early item does not prevent later completions from freeing task slots.
/// Only short result-placement sections are synchronized; no user factory,
/// asynchronous work, or result destructor is deliberately invoked under that
/// lock. The existing stream driver supplies wakeups and cooperative admission
/// yields; this adapter starts no separate coordinator task.
///
/// Dropping the collecting future requests cancellation through its JoinSet;
/// it cannot synchronously join tasks. The enclosing region remains the final
/// cleanup barrier after abandonment. Effects already committed by successful
/// item tasks are not rolled back. Returned resource-bearing values need their
/// own lifetime/transfer contract, just as for a direct task join.
///
/// ```no_run
/// # async fn example(cx: &asupersync::Cx) {
/// use asupersync::combinator::stream_collect::try_map_collect_concurrent;
/// use asupersync::stream::iter;
/// use asupersync::Outcome;
/// let result = try_map_collect_concurrent(cx, iter([3, 1, 2]), 2,
///     |_item_cx, n| async move { Ok::<_, &'static str>(n * 10) }).await;
/// assert!(matches!(result, Outcome::Ok(values) if values == [30, 10, 20]));
/// # }
/// ```
///
/// # Panics
/// Panics if `limit` is zero. Unwinding panics from source polling or factory
/// cloning are instead reported as `Panicked` after draining owned tasks.
/// Panicking destructors and abort-on-panic builds remain outside that guarantee.
pub async fn try_map_collect_concurrent<S, F, Fut, T, E>(
    cx: &Cx,
    stream: S,
    limit: usize,
    mut f: F,
) -> Outcome<Vec<T>, E>
where
    S: Stream + Unpin,
    S::Item: Send + 'static,
    F: FnMut(Cx, S::Item) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = Result<T, E>> + Send + 'static,
    T: Send + 'static,
    E: Send + 'static,
{
    let results = Results::new();
    let writer = results.clone();
    let outcome = try_for_each_concurrent(cx, stream.enumerate(), limit, move |item_cx, (index, item)| {
        let writer = writer.clone();
        let future = f(item_cx, item);
        async move {
            writer.store(index, future.await?);
            Ok(())
        }
    })
    .await;
    results.finish(outcome)
}

/// Maps and collects in source order, then closes the complete work subtree.
///
/// This combines [`try_map_collect_concurrent`]'s ordering with
/// [`try_for_each_concurrent_scoped`]'s descendant/finalizer barrier. Successful
/// values stay owned by the collector during cleanup. They are returned only
/// if both direct work and cleanup succeed; otherwise they are dropped AFTER
/// cleanup, outside the result lock. A successful mapper cannot hide a later
/// descendant or finalizer panic behind its already-staged value.
///
/// `limit` bounds direct tasks, not result memory or descendants: N successful
/// inputs retain O(N) values. Returned values must remain valid after their
/// item's task AND this operation's region have closed. Returning a value does
/// not transfer live obligations or extend a region-owned resource's lifetime.
/// Dropping this future requests subtree close but cannot synchronously drain.
///
/// ```no_run
/// # async fn example(cx: &asupersync::Cx) {
/// use asupersync::combinator::stream_collect::try_map_collect_concurrent_scoped;
/// use asupersync::stream::iter;
/// use asupersync::Outcome;
/// let result = try_map_collect_concurrent_scoped(cx, iter([3, 1, 2]), 2,
///     |_child, n| async move { Ok::<_, &'static str>(n * 10) }).await;
/// assert!(matches!(result, Outcome::Ok(values) if values == [30, 10, 20]));
/// # }
/// ```
///
/// # Panics
/// Panics if `limit` is zero. Source/clone unwind containment and cleanup
/// precedence follow [`try_for_each_concurrent_scoped`].
pub async fn try_map_collect_concurrent_scoped<S, F, Fut, T, E>(
    cx: &Cx,
    stream: S,
    limit: usize,
    mut f: F,
) -> Outcome<Vec<T>, ScopedStreamError<E>>
where
    S: Stream + Unpin,
    S::Item: Send + 'static,
    F: FnMut(Cx, S::Item) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = Result<T, E>> + Send + 'static,
    T: Send + 'static,
    E: Send + 'static,
{
    let results = Results::new();
    let writer = results.clone();
    let outcome = try_for_each_concurrent_scoped(
        cx,
        stream.enumerate(),
        limit,
        move |child, (index, item)| {
            let writer = writer.clone();
            let future = f(child, item);
            async move {
                writer.store(index, future.await?);
                Ok(())
            }
        },
    ).await;
    results.finish(outcome)
}

/// Infallible mapping with ordered results and complete subtree cleanup.
///
/// See [`try_map_collect_concurrent_scoped`] for result lifetime and memory
/// bounds. Runtime admission and cleanup can fail even if mapping is infallible.
///
/// # Panics
/// Panics if `limit` is zero.
pub async fn map_collect_concurrent_scoped<S, F, Fut, T>(
    cx: &Cx,
    stream: S,
    limit: usize,
    mut f: F,
) -> Outcome<Vec<T>, ScopedStreamError<Infallible>>
where
    S: Stream + Unpin,
    S::Item: Send + 'static,
    F: FnMut(Cx, S::Item) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    try_map_collect_concurrent_scoped(cx, stream, limit, move |child, item| {
        let future = f(child, item);
        async move { Ok(future.await) }
    }).await
}

// Both collection modes use this one result-placement and retirement path.
// Cloning the handle shares storage; it never adds a Clone bound to T.
struct Results<T>(Arc<Mutex<Vec<Option<T>>>>);

impl<T> Clone for Results<T> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<T> Results<T> {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(Vec::new())))
    }

    fn store(&self, index: usize, value: T) {
        let mut slots = self.0.lock();
        if slots.len() <= index {
            slots.resize_with(index.checked_add(1).expect("stream result index overflow"), || None);
        }
        // Each source index is admitted once. Never overwrite a previous T.
        assert!(slots[index].is_none(), "duplicate stream result index");
        slots[index] = Some(value);
    }

    fn finish<E>(self, outcome: Outcome<(), E>) -> Outcome<Vec<T>, E> {
        // No user destructor may run under the result lock. Callers finish only
        // after their selected task-only or full-subtree barrier has resolved.
        let slots = std::mem::take(&mut *self.0.lock());
        match outcome {
            Outcome::Ok(()) => Outcome::Ok(slots.into_iter().map(|slot| {
                slot.expect("successful stream collection has every admitted result")
            }).collect()),
            Outcome::Err(error) => Outcome::Err(error),
            Outcome::Cancelled(reason) => Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => Outcome::Panicked(payload),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::pedantic, clippy::nursery, clippy::future_not_send)]

    use super::*;
    use crate::lab::run_async_under_lab;
    use crate::runtime::yield_now;
    #[cfg(not(target_arch = "wasm32"))]
    use crate::runtime::RuntimeBuilder;
    use crate::stream::iter;
    use std::sync::atomic::{AtomicUsize, Ordering};

    async fn ordered(cx: Cx) {
        let completed = Arc::new(AtomicUsize::new(0));
        let child_completed = Arc::clone(&completed);
        let outcome = map_collect_concurrent(&cx, iter(0..4), 4, move |_child, index| {
            let completed = Arc::clone(&child_completed);
            async move {
                if index == 0 {
                    while completed.load(Ordering::SeqCst) < 3 {
                        yield_now().await;
                    }
                } else {
                    completed.fetch_add(1, Ordering::SeqCst);
                }
                Box::new(index * 10)
            }
        }).await;
        let Outcome::Ok(values) = outcome else { panic!("maps must succeed") };
        assert_eq!(completed.load(Ordering::SeqCst), 3, "later inputs finished first");
        assert_eq!(values.into_iter().map(|value| *value).collect::<Vec<_>>(), [0, 10, 20, 30]);
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn collection_restores_order_after_out_of_order_native_completions() {
        let runtime = RuntimeBuilder::current_thread().build().unwrap();
        runtime.block_on(runtime.handle().spawn(async {
            ordered(Cx::current().expect("native parent context")).await;
        }));
    }

    #[test]
    fn collection_restores_order_under_lab_schedules() {
        for seed in [0xC011, 0xC012, 0xC013] {
            let ((), report) = run_async_under_lab(seed, ordered);
            assert!(report.quiescent && report.invariant_violations.is_empty());
        }
    }

    #[test]
    fn collection_bounds_overlapping_work_and_visits_each_input_once() {
        let ((), report) = run_async_under_lab(0xC014, |cx| async move {
            let running = Arc::new(AtomicUsize::new(0));
            let peak = Arc::new(AtomicUsize::new(0));
            let seen: Arc<Vec<AtomicUsize>> = Arc::new((0..24).map(|_| AtomicUsize::new(0)).collect());
            let factory_running = Arc::clone(&running);
            let factory_peak = Arc::clone(&peak);
            let factory_seen = Arc::clone(&seen);
            let outcome = map_collect_concurrent(&cx, iter(0..24), 3, move |_child, index| {
                let running = Arc::clone(&factory_running);
                let peak = Arc::clone(&factory_peak);
                let seen = Arc::clone(&factory_seen);
                async move {
                    let live = running.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(live, Ordering::SeqCst);
                    seen[index].fetch_add(1, Ordering::SeqCst);
                    yield_now().await;
                    yield_now().await;
                    running.fetch_sub(1, Ordering::SeqCst);
                    index
                }
            }).await;
            assert!(matches!(outcome, Outcome::Ok(values) if values == (0..24).collect::<Vec<_>>()));
            assert_eq!(running.load(Ordering::SeqCst), 0);
            assert!((2..=3).contains(&peak.load(Ordering::SeqCst)), "real bounded overlap");
            assert!(seen.iter().all(|count| count.load(Ordering::SeqCst) == 1));
        });
        assert!(report.quiescent && report.invariant_violations.is_empty());
    }

    #[test]
    fn collection_accepts_non_clone_values() {
        struct NotClone(usize);
        let ((), report) = run_async_under_lab(0xC015, |cx| async move {
            let source = iter([NotClone(7), NotClone(9)]);
            let outcome = map_collect_concurrent(&cx, source, 2, |_child, value| async move { value }).await;
            let Outcome::Ok(values) = outcome else { panic!("maps must succeed") };
            assert_eq!(values.iter().map(|value| value.0).collect::<Vec<_>>(), [7, 9]);
        });
        assert!(report.quiescent && report.invariant_violations.is_empty());
    }

    #[test]
    fn collection_accepts_borrowed_non_send_source_and_reports_missing_runtime() {
        let cx = Cx::for_testing();
        let local = std::rc::Rc::new(std::cell::Cell::new(0));
        let source = iter([7]).inspect(|_| local.set(local.get() + 1));
        let mut work = Box::pin(map_collect_concurrent(&cx, source, 1,
            |_child, value| async move { value }));
        let mut task = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(matches!(work.as_mut().poll(&mut task), std::task::Poll::Ready(Outcome::Panicked(_))));
        drop(work);
        assert_eq!(local.get(), 1, "source was polled without adding Send or static bounds");
    }

    #[test]
    fn collection_empty_input_has_no_factory_calls_and_zero_limit_is_rejected() {
        async fn unexpected(_child: Cx, _item: u8) -> u8 {
            panic!("empty source must not spawn")
        }
        let cx = Cx::for_testing();
        let mut empty = Box::pin(map_collect_concurrent(&cx, iter([] as [u8; 0]), 1, unexpected));
        let mut task = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(matches!(empty.as_mut().poll(&mut task), std::task::Poll::Ready(Outcome::Ok(values)) if values.is_empty()));
        let mut zero = Box::pin(map_collect_concurrent(&cx, iter([1]), 0, |_child, item| async move { item }));
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| zero.as_mut().poll(&mut task))).is_err());
    }

    #[test]
    fn collection_failure_drains_parked_members_and_drops_completed_values() {
        struct Value(Arc<AtomicUsize>);
        impl Drop for Value {
            fn drop(&mut self) { self.0.fetch_add(1, Ordering::SeqCst); }
        }
        let ((), report) = run_async_under_lab(0xC016, |cx| async move {
            let started = Arc::new(AtomicUsize::new(0));
            let cleaned = Arc::new(AtomicUsize::new(0));
            let drops = Arc::new(AtomicUsize::new(0));
            let outer_cleaned = Arc::clone(&cleaned);
            let outer_drops = Arc::clone(&drops);
            let outcome = try_map_collect_concurrent(&cx, iter(0..4), 4, move |child, index| {
                let started = Arc::clone(&started);
                let cleaned = Arc::clone(&cleaned);
                let drops = Arc::clone(&drops);
                async move {
                    if index == 0 {
                        while started.load(Ordering::SeqCst) < 3 { yield_now().await; }
                        // Let the successful item leave its value in the collector.
                        yield_now().await;
                        return Err("map failed");
                    }
                    started.fetch_add(1, Ordering::SeqCst);
                    if index == 1 { return Ok(Value(drops)); }
                    child.cancelled().await;
                    yield_now().await;
                    cleaned.fetch_add(1, Ordering::SeqCst);
                    Err("drained")
                }
            }).await;
            assert!(matches!(outcome, Outcome::Err("map failed")));
            assert_eq!(outer_cleaned.load(Ordering::SeqCst), 2, "observed before parent region close");
            assert_eq!(outer_drops.load(Ordering::SeqCst), 1, "completed output was retired");
        });
        assert!(report.quiescent && report.invariant_violations.is_empty());
    }
}

#[cfg(test)]
mod scoped_tests {
    #![allow(clippy::pedantic, clippy::nursery, clippy::future_not_send)]

    use super::*;
    use crate::channel::{mpsc, oneshot};
    use crate::cx::ChildRegion;
    use crate::lab::run_async_under_lab;
    use crate::runtime::spawn_mailbox::{RegionCommand, RegisterRegionFinalizer};
    use crate::runtime::{TaskHandle, yield_now};
    use crate::stream::iter;
    use crate::sync::Notify;
    use std::future::poll_fn;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    #[derive(Default)]
    struct Progress {
        holding: AtomicBool,
        finished: AtomicUsize,
        changed: Notify,
    }

    async fn descendant(
        cx: Cx,
        sender: mpsc::Sender<()>,
        progress: Arc<Progress>,
        panic_after_cleanup: bool,
    ) {
        let permit = sender.reserve_checked(&cx).await.unwrap();
        progress.holding.store(true, Ordering::SeqCst);
        progress.changed.notify_waiters();
        cx.cancelled().await;
        // Neither handle destruction nor an immediate return can stand in for
        // the asynchronous cleanup that the outer operation must wait for.
        yield_now().await;
        yield_now().await;
        drop(permit);
        progress.finished.fetch_add(1, Ordering::SeqCst);
        if panic_after_cleanup {
            panic!("scoped descendant cleanup panic");
        }
    }

    async fn subtree_journey(cx: Cx, fail: bool, panic_descendant: bool) {
        let progress = Arc::new(Progress::default());
        let regions: Arc<Mutex<Vec<ChildRegion>>> = Arc::new(Mutex::new(Vec::new()));
        let retained: Arc<Mutex<Vec<TaskHandle<()>>>> = Arc::new(Mutex::new(Vec::new()));
        let (sender, mut receiver) = mpsc::channel(1);
        let outer_region = cx.region_id();
        let unrelated_done = Arc::new(AtomicBool::new(false));
        let observe_unrelated = Arc::clone(&unrelated_done);
        let mut unrelated = cx.spawn(move |child| async move {
            child.cancelled().await;
            observe_unrelated.store(true, Ordering::SeqCst);
        }).unwrap();
        let observe = Arc::clone(&progress);
        let keep_regions = Arc::clone(&regions);
        let keep_handles = Arc::clone(&retained);
        let send = sender.clone();
        let result = try_for_each_concurrent_scoped(
            &cx,
            iter(0..if fail { 2 } else { 1 }),
            2,
            move |child, index| {
                let progress = Arc::clone(&observe);
                let regions = Arc::clone(&keep_regions);
                let retained = Arc::clone(&keep_handles);
                let sender = send.clone();
                async move {
                    assert_ne!(child.region_id(), outer_region, "work has its own boundary");
                    if index == 1 {
                        progress.changed.wait_until(|| progress.holding.load(Ordering::SeqCst)).await;
                        return Err("item failure");
                    }
                    let nested = child.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
                    let mut handle = nested.cx().spawn({
                        let progress = Arc::clone(&progress);
                        move |grandchild| descendant(grandchild, sender, progress, panic_descendant)
                    }).unwrap();
                    progress.changed.wait_until(|| progress.holding.load(Ordering::SeqCst)).await;
                    if fail {
                        // The direct item cannot finish until its descendant
                        // gets REGION cancellation. A direct-task-only abort
                        // followed by joining this item would deadlock here.
                        let _ = poll_fn(|task| handle.poll_join(task)).await;
                        drop(nested);
                    } else {
                        // Retain both handles outside the item so their Drop
                        // cannot accidentally satisfy the subtree-close claim.
                        retained.lock().push(handle);
                        regions.lock().push(nested);
                    }
                    Ok(())
                }
            },
        ).await;
        if panic_descendant {
            assert!(matches!(result, Outcome::Panicked(ref p) if format!("{p:?}").contains("scoped descendant cleanup panic")));
        } else if fail {
            assert!(matches!(result, Outcome::Err(ScopedStreamError::Item("item failure"))));
        } else {
            assert!(matches!(result, Outcome::Ok(())), "{result:?}");
        }
        assert!(progress.holding.load(Ordering::SeqCst), "non-vacuous checked permit witness");
        assert_eq!(progress.finished.load(Ordering::SeqCst), 1, "before parent region closes");
        assert_eq!(sender.telemetry_snapshot(1).reserved_uncommitted_obligations, 0);
        assert_eq!(receiver.try_recv(), Err(mpsc::RecvError::Empty));
        sender.try_reserve().unwrap().abort();
        for handle in retained.lock().iter_mut() {
            assert!(!matches!(handle.try_join(), Ok(None)), "descendant actually retired");
        }
        assert!(!unrelated_done.load(Ordering::SeqCst), "parent sibling was not cancelled");
        unrelated.abort();
        let _ = unrelated.join(&cx).await;
        assert!(unrelated_done.load(Ordering::SeqCst));
        drop(regions);
    }

    #[test]
    fn scoped_success_and_failure_drain_nested_descendants_under_lab() {
        for fail in [false, true] {
            let ((), report) = run_async_under_lab(0x5C010, move |cx| subtree_journey(cx, fail, false));
            assert!(report.quiescent && report.invariant_violations.is_empty());
        }
    }

    #[test]
    fn scoped_descendant_panic_is_not_hidden_by_successful_item() {
        let ((), report) = run_async_under_lab(0x5C011, |cx| subtree_journey(cx, false, true));
        assert!(report.quiescent && report.invariant_violations.is_empty());
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn scoped_subtree_barrier_runs_on_native_runtime() {
        for fail in [false, true] {
            let passed = Arc::new(AtomicBool::new(false));
            let observed = Arc::clone(&passed);
            let runtime = crate::runtime::RuntimeBuilder::current_thread().build().unwrap();
            runtime.block_on(runtime.handle().spawn(async move {
                let cx = Cx::current().unwrap();
                crate::time::timeout(
                    cx.now(),
                    std::time::Duration::from_secs(10),
                    subtree_journey(cx, fail, false),
                ).await.expect("scoped subtree drain timed out");
                observed.store(true, Ordering::SeqCst);
            }));
            assert!(passed.load(Ordering::SeqCst), "native body reached all post-return assertions");
        }
    }

    #[test]
    fn scoped_finalizer_runs_before_return_and_its_panic_is_reported() {
        for panic_finalizer in [false, true] {
            let ((), report) = run_async_under_lab(0x5C012, move |cx| async move {
                let finalized = Arc::new(AtomicUsize::new(0));
                let observe = Arc::clone(&finalized);
                let outcome = for_each_concurrent_scoped(&cx, iter([()]), 1, move |child, ()| {
                    let finalized = Arc::clone(&observe);
                    async move {
                        let (ack, mut acknowledged) = oneshot::channel();
                        let request = RegisterRegionFinalizer::new(child.region_id(), move || {
                            finalized.fetch_add(1, Ordering::SeqCst);
                            if panic_finalizer { panic!("scoped finalizer panic"); }
                        }, ack);
                        child.spawn_gateway_handle().unwrap()
                            .enqueue_region_command(RegionCommand::RegisterFinalizer(request)).unwrap();
                        acknowledged.recv_uninterruptible().await.unwrap().unwrap();
                    }
                }).await;
                assert_eq!(finalized.load(Ordering::SeqCst), 1);
                if panic_finalizer {
                    assert!(matches!(outcome, Outcome::Panicked(ref p) if format!("{p:?}").contains("scoped finalizer panic")));
                } else {
                    assert!(matches!(outcome, Outcome::Ok(())), "{outcome:?}");
                }
            });
            assert!(report.quiescent && report.invariant_violations.is_empty());
        }
    }

    #[test]
    fn scoped_cancellation_and_abandonment_close_the_subtree() {
        for abandon in [false, true] {
            let ((), report) = run_async_under_lab(0x5C013, move |cx| async move {
                let progress = Arc::new(Progress::default());
                let (sender, _receiver) = mpsc::channel(1);
                let observe = Arc::clone(&progress);
                let send = sender.clone();
                let returned = Arc::new(AtomicBool::new(false));
                let did_return = Arc::clone(&returned);
                let mut driver = cx.spawn(move |owner| async move {
                    let signal = Arc::clone(&observe);
                    let mut work = Box::pin(try_for_each_concurrent_scoped(
                        &owner, iter([()]), 1, move |item_cx, ()| {
                            let progress = Arc::clone(&observe);
                            let sender = send.clone();
                            async move {
                                let mut nested = item_cx.spawn(move |child| descendant(child, sender, progress, false)).unwrap();
                                let _ = poll_fn(|task| nested.poll_join(task)).await;
                                Ok::<(), ()>(())
                            }
                        },
                    ));
                    if abandon {
                        let mut ready = std::pin::pin!(signal.changed.wait_until(|| {
                            signal.holding.load(Ordering::SeqCst)
                        }));
                        poll_fn(|task| {
                            assert!(work.as_mut().poll(task).is_pending());
                            ready.as_mut().poll(task)
                        }).await;
                        drop(work);
                    } else {
                        let result = work.as_mut().await;
                        assert!(matches!(result, Outcome::Cancelled(_)));
                        assert_eq!(signal.finished.load(Ordering::SeqCst), 1);
                    }
                    did_return.store(true, Ordering::SeqCst);
                }).unwrap();
                progress.changed.wait_until(|| progress.holding.load(Ordering::SeqCst)).await;
                if !abandon { driver.abort(); }
                let _ = driver.join(&cx).await;
                assert!(returned.load(Ordering::SeqCst));
                for _ in 0..256 {
                    if progress.finished.load(Ordering::SeqCst) == 1 { break; }
                    yield_now().await;
                }
                assert_eq!(progress.finished.load(Ordering::SeqCst), 1);
                assert_eq!(sender.telemetry_snapshot(1).reserved_uncommitted_obligations, 0);
            });
            assert!(report.quiescent && report.invariant_violations.is_empty());
        }
    }

    #[test]
    fn scoped_refusal_does_not_poll_source_or_invoke_factory() {
        let cx = Cx::for_testing();
        let polls = std::cell::Cell::new(0);
        let source = iter([()]).inspect(|_| polls.set(polls.get() + 1));
        let mut work = Box::pin(for_each_concurrent_scoped(&cx, source, 1, |_, ()| async {
            panic!("refused factory must not run");
        }));
        let mut task = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(matches!(work.as_mut().poll(&mut task), std::task::Poll::Ready(Outcome::Err(ScopedStreamError::Region(_)))));
        drop(work);
        assert_eq!(polls.get(), 0);
    }

    async fn scoped_collection_journey(cx: Cx) {
        struct Value(usize); // Deliberately not Clone.
        let progress: Arc<Vec<Arc<Progress>>> = Arc::new(
            (0..4).map(|_| Arc::new(Progress::default())).collect(),
        );
        let retained: Arc<Mutex<Vec<TaskHandle<()>>>> = Arc::new(Mutex::new(Vec::new()));
        let completed = Arc::new(AtomicUsize::new(0));
        let (sender, _receiver) = mpsc::channel(4);
        let signals = Arc::clone(&progress);
        let keep = Arc::clone(&retained);
        let later_completed = Arc::clone(&completed);
        let send = sender.clone();
        let outcome = map_collect_concurrent_scoped(&cx, iter(0..4), 2, move |child, index| {
            let progress = Arc::clone(&signals[index]);
            let keep = Arc::clone(&keep);
            let completed = Arc::clone(&later_completed);
            let sender = send.clone();
            async move {
                let handle = child.spawn({
                    let progress = Arc::clone(&progress);
                    move |desc| descendant(desc, sender, progress, false)
                }).unwrap();
                progress.changed.wait_until(|| progress.holding.load(Ordering::SeqCst)).await;
                keep.lock().push(handle);
                if index == 0 {
                    while completed.load(Ordering::SeqCst) == 0 { yield_now().await; }
                }
                completed.fetch_add(1, Ordering::SeqCst);
                Value(index * 10)
            }
        }).await;
        let Outcome::Ok(values) = outcome else { panic!("scoped collection failed") };
        assert_eq!(values.into_iter().map(|value| value.0).collect::<Vec<_>>(), [0, 10, 20, 30]);
        assert_eq!(completed.load(Ordering::SeqCst), 4);
        assert!(progress.iter().all(|p| p.holding.load(Ordering::SeqCst)));
        assert!(progress.iter().all(|p| p.finished.load(Ordering::SeqCst) == 1));
        assert_eq!(sender.telemetry_snapshot(1).reserved_uncommitted_obligations, 0);
        for handle in retained.lock().iter_mut() {
            assert!(!matches!(handle.try_join(), Ok(None)), "all descendants retired before output");
        }
    }

    #[test]
    fn scoped_collection_preserves_order_and_drains_every_descendant() {
        for seed in [0x5C014, 0x5C015] {
            let ((), report) = run_async_under_lab(seed, scoped_collection_journey);
            assert!(report.quiescent && report.invariant_violations.is_empty());
        }
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn scoped_ordered_collection_has_a_native_cleanup_barrier() {
        let passed = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&passed);
        let runtime = crate::runtime::RuntimeBuilder::current_thread().build().unwrap();
        runtime.block_on(runtime.handle().spawn(async move {
            let cx = Cx::current().unwrap();
            crate::time::timeout(cx.now(), std::time::Duration::from_secs(10),
                scoped_collection_journey(cx)).await.expect("scoped collection timed out");
            observed.store(true, Ordering::SeqCst);
        }));
        assert!(passed.load(Ordering::SeqCst));
    }

    #[test]
    fn scoped_outputs_are_discarded_only_after_failed_subtree_cleanup() {
        struct Value {
            progress: Arc<Progress>,
            finalized: Arc<AtomicBool>,
            early: Arc<AtomicBool>,
            drops: Arc<AtomicUsize>,
        }
        impl Drop for Value {
            fn drop(&mut self) {
                if self.progress.finished.load(Ordering::SeqCst) != 1
                    || !self.finalized.load(Ordering::SeqCst)
                {
                    self.early.store(true, Ordering::SeqCst);
                }
                self.drops.fetch_add(1, Ordering::SeqCst);
            }
        }
        for panic_finalizer in [false, true] {
            let ((), report) = run_async_under_lab(0x5C016, move |cx| async move {
                let progress = Arc::new(Progress::default());
                let finalized = Arc::new(AtomicBool::new(false));
                let early = Arc::new(AtomicBool::new(false));
                let drops = Arc::new(AtomicUsize::new(0));
                let value_ready = Arc::new(AtomicBool::new(false));
                let changed = Arc::new(Notify::new());
                let retained = Arc::new(Mutex::new(None));
                let (sender, _receiver) = mpsc::channel(1);
                let signals = (Arc::clone(&progress), Arc::clone(&finalized),
                    Arc::clone(&early), Arc::clone(&drops), Arc::clone(&retained));
                let outcome = try_map_collect_concurrent_scoped(
                    &cx, iter(0..if panic_finalizer { 1 } else { 2 }), 2,
                    move |child, index| {
                        let (progress, finalized, early, drops, retained) = signals.clone();
                        let sender = sender.clone();
                        let ready = Arc::clone(&value_ready);
                        let changed = Arc::clone(&changed);
                        async move {
                            if index == 1 {
                                changed.wait_until(|| ready.load(Ordering::SeqCst)).await;
                                return Err("scoped map failed");
                            }
                            let handle = child.spawn({
                                let progress = Arc::clone(&progress);
                                move |desc| descendant(desc, sender, progress, false)
                            }).unwrap();
                            *retained.lock() = Some(handle);
                            progress.changed.wait_until(|| progress.holding.load(Ordering::SeqCst)).await;
                            let (ack, mut acknowledged) = oneshot::channel();
                            let finish = Arc::clone(&finalized);
                            let request = RegisterRegionFinalizer::new(child.region_id(), move || {
                                finish.store(true, Ordering::SeqCst);
                                if panic_finalizer { panic!("collected value finalizer failed"); }
                            }, ack);
                            child.spawn_gateway_handle().unwrap()
                                .enqueue_region_command(RegionCommand::RegisterFinalizer(request)).unwrap();
                            acknowledged.recv_uninterruptible().await.unwrap().unwrap();
                            let value = Value { progress, finalized, early, drops };
                            ready.store(true, Ordering::SeqCst);
                            changed.notify_waiters();
                            Ok(value)
                        }
                    },
                ).await;
                if panic_finalizer {
                    assert!(matches!(outcome, Outcome::Panicked(_)));
                } else {
                    assert!(matches!(outcome, Outcome::Err(ScopedStreamError::Item("scoped map failed"))));
                }
                assert_eq!(progress.finished.load(Ordering::SeqCst), 1);
                assert!(finalized.load(Ordering::SeqCst));
                assert_eq!(drops.load(Ordering::SeqCst), 1);
                assert!(!early.load(Ordering::SeqCst), "output survived through descendant and finalizer cleanup");
                assert!(!matches!(retained.lock().as_mut().unwrap().try_join(), Ok(None)));
            });
            assert!(report.quiescent && report.invariant_violations.is_empty());
        }
    }

    #[test]
    fn scoped_source_panic_cancels_descendants_before_waiting_for_their_parent() {
        let ((), report) = run_async_under_lab(0x5C017, |cx| async move {
            let progress = Arc::new(Progress::default());
            let source_signal = Arc::clone(&progress);
            let source = iter([0, 1]).then(move |index| {
                let progress = Arc::clone(&source_signal);
                Box::pin(async move {
                    if index == 1 {
                        progress.changed.wait_until(|| progress.holding.load(Ordering::SeqCst)).await;
                        panic!("scoped source failed with a parked subtree");
                    }
                })
            });
            let (sender, _receiver) = mpsc::channel(1);
            let child_signal = Arc::clone(&progress);
            let outcome = try_map_collect_concurrent_scoped(&cx, source, 2, move |item, ()| {
                let progress = Arc::clone(&child_signal);
                let sender = sender.clone();
                async move {
                    let mut nested = item.spawn(move |desc| descendant(desc, sender, progress, false)).unwrap();
                    let _ = poll_fn(|task| nested.poll_join(task)).await;
                    Ok::<_, ()>(7)
                }
            }).await;
            assert!(matches!(outcome, Outcome::Panicked(ref p) if format!("{p:?}").contains("scoped source failed")));
            assert!(progress.holding.load(Ordering::SeqCst));
            assert_eq!(progress.finished.load(Ordering::SeqCst), 1);
        });
        assert!(report.quiescent && report.invariant_violations.is_empty());
    }

    #[test]
    fn scoped_collection_pre_cancel_refuses_before_source_poll() {
        let cx = Cx::for_testing();
        cx.cancel_fast(crate::types::CancelKind::User);
        let polls = std::cell::Cell::new(0);
        let source = iter([7]).inspect(|_| polls.set(polls.get() + 1));
        let mut work = Box::pin(map_collect_concurrent_scoped(&cx, source, 1,
            |_child, item| async move { item }));
        let mut task = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(matches!(work.as_mut().poll(&mut task), std::task::Poll::Ready(Outcome::Cancelled(_))));
        drop(work);
        assert_eq!(polls.get(), 0);
    }

    /// An owner cancelled while an item runs gets its own reason back, as it
    /// does when cancelled before the call. The stream driver used to report
    /// that case as a generic User cancellation.
    #[test]
    fn scoped_owner_cancelled_mid_run_gets_its_own_reason() {
        let ((), report) = run_async_under_lab(0x5C016, |cx| async move {
            let parked = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let observed = Arc::new(Mutex::new(None));
            let (park, record) = (Arc::clone(&parked), Arc::clone(&observed));
            let mut driver = cx
                .spawn(move |owner| async move {
                    let result = try_for_each_concurrent_scoped(
                        &owner,
                        iter([()]),
                        1,
                        move |item_cx, ()| {
                            let parked = Arc::clone(&park);
                            async move {
                                parked.store(true, Ordering::SeqCst);
                                item_cx.cancelled().await;
                                Ok::<(), ()>(())
                            }
                        },
                    )
                    .await;
                    *record.lock() = Some(match result {
                        Outcome::Cancelled(reason) => Ok(reason.kind()),
                        other => Err(format!("{other:?}")),
                    });
                })
                .unwrap();
            while !parked.load(Ordering::SeqCst) {
                yield_now().await;
            }
            driver.abort_with_reason(crate::types::CancelReason::new(
                crate::types::CancelKind::Shutdown,
            ));
            let _ = driver.join(&cx).await;
            assert_eq!(
                observed.lock().take(),
                Some(Ok(crate::types::CancelKind::Shutdown)),
                "the owner's own reason, not the driver's generic one"
            );
        });
        assert!(report.quiescent && report.invariant_violations.is_empty());
    }
}
