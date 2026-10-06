//! Ordered collection of concurrent, region-owned stream work.
//!
//! Unlike buffering plain futures, these terminals use the stream task driver:
//! non-success stops admission and cancels and joins the remaining items before
//! returning. Successes are indexed by input order, not completion order.
//!
//! Bead: asupersync-dx-core-api-v2-u1z5hn.8 (bounded stream task composition).

use crate::cx::Cx;
use crate::stream::{Stream, StreamExt, try_for_each_concurrent};
use crate::types::Outcome;
use parking_lot::Mutex;
use std::convert::Infallible;
use std::future::Future;
use std::sync::Arc;

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
/// Panics if `limit` is zero. As with the underlying stream driver, a panic in
/// source polling or factory cloning is not an item-task result.
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
    let results = Arc::new(Mutex::new(Vec::<Option<T>>::new()));
    let writer = Arc::clone(&results);
    let outcome = try_for_each_concurrent(cx, stream.enumerate(), limit, move |item_cx, (index, item)| {
        let writer = Arc::clone(&writer);
        let future = f(item_cx, item);
        async move {
            let value = future.await?;
            {
                let mut slots = writer.lock();
                if slots.len() <= index {
                    slots.resize_with(index.checked_add(1).expect("stream result index overflow"), || None);
                }
                // Each Enumerate index is admitted once. No previous T is
                // destroyed here; there are no public writers to these slots.
                assert!(slots[index].is_none(), "duplicate stream result index");
                slots[index] = Some(value);
            }
            Ok(())
        }
    })
    .await;
    // Take the values out before visiting or destroying any of them. A T may
    // have a reentrant destructor, and no user destructor belongs under a lock.
    let slots = std::mem::take(&mut *results.lock());
    match outcome {
        Outcome::Ok(()) => Outcome::Ok(slots.into_iter().map(|slot| {
            slot.expect("successful stream collection has every admitted result")
        }).collect()),
        Outcome::Err(error) => Outcome::Err(error),
        Outcome::Cancelled(reason) => Outcome::Cancelled(reason),
        Outcome::Panicked(payload) => Outcome::Panicked(payload),
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
