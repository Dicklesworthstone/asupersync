//! Bounded output pipelines over region-owned concurrent stream work.
//!
//! A mapped output keeps its task slot until checked channel publication.
//! Unlike collecting a `Vec`, this permits a long-lived source without retaining
//! every result. The destination consumer must run concurrently with the sender.
//!
//! Bead: asupersync-dx-core-api-v2-u1z5hn.8 (bounded stream task composition).

use super::stream_collect::{ScopedStreamError, try_for_each_concurrent_scoped};
use crate::channel::mpsc::{CheckedSendError, Sender};
use crate::cx::Cx;
use crate::stream::Stream;
use crate::types::Outcome;
use std::future::Future;

/// A mapping failure or a checked refusal to publish its output.
#[derive(Debug)]
#[non_exhaustive]
pub enum StreamSendError<E, T> {
    /// The item mapper failed before producing an output.
    Map(E),
    /// The channel or runtime refused publication, retaining that output.
    Delivery(CheckedSendError<T>),
}

impl<E: std::fmt::Display, T> std::fmt::Display for StreamSendError<E, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Map(error) => write!(f, "stream mapping failed: {error}"),
            Self::Delivery(error) => write!(f, "stream output refused: {error}"),
        }
    }
}

impl<E, T> std::error::Error for StreamSendError<E, T>
where
    E: std::error::Error + 'static,
    T: std::fmt::Debug + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Map(error) => Some(error),
            Self::Delivery(error) => Some(error),
        }
    }
}

/// Maps an asynchronous source concurrently into a bounded MPSC destination.
///
/// At most `limit` direct tasks own input, mapping work, or an unpublished
/// output. A task waiting for destination capacity STILL occupies its slot:
/// backpressure therefore reaches the source instead of growing a result vector.
/// With destination capacity C, this operation retains at most `limit` outputs
/// outside the channel, plus the channel's C queued values. This is an item-count
/// bound, not a byte bound on user values, mapper allocations, descendants, or
/// values retained by the consumer. No extra producer/coordinator task is spawned.
///
/// Publication order is unconstrained. The destination must be consumed
/// concurrently; awaiting this operation before draining a full channel cannot
/// make progress. The caller retains the sender, so success does not close the
/// channel or mean that the consumer processed its contents.
///
/// Each mapper receives its admitted child context. Checked sends use that
/// context's authoritative obligation admission and preserve the rejected value
/// in a `Delivery` error. The first observed failure stops new admission, cancels
/// the work subtree, and joins direct tasks, descendants, and finalizers before
/// returning, following [`try_for_each_concurrent_scoped`]. Cleanup failure may
/// supersede the original item error. Other unpublished outputs are discarded
/// during drain; this is not a recovery log for every item.
///
/// Already accepted outputs are never rolled back, even on later failure. They
/// may be received BEFORE subtree cleanup finishes and must not depend on a
/// mapper-owned obligation or region resource remaining live. Moving a value
/// through this API does not transfer runtime holder liability. Dropping the
/// operation requests subtree close but cannot synchronously await it. Effects
/// using a captured outer context are outside this operation's cleanup boundary.
///
/// The source may borrow caller state and need not be `Send`. The mapper is
/// cloned per item; its inputs, future, outputs and errors are `Send + 'static`.
/// No `Clone` bound is added to inputs or outputs.
///
/// # Panics
/// Panics if `limit` is zero. Source and factory-clone unwinds take the scoped
/// driver's drain path; non-cooperative work, arbitrary panicking destructors,
/// and abort-on-panic builds retain that driver's documented limitations.
pub async fn try_map_send_concurrent_scoped<S, F, Fut, T, E>(
    cx: &Cx,
    stream: S,
    limit: usize,
    sender: &Sender<T>,
    mut map: F,
) -> Outcome<(), ScopedStreamError<StreamSendError<E, T>>>
where
    S: Stream + Unpin,
    S::Item: Send + 'static,
    F: FnMut(Cx, S::Item) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = Result<T, E>> + Send + 'static,
    T: Send + 'static,
    E: Send + 'static,
{
    let sender = sender.clone();
    try_for_each_concurrent_scoped(cx, stream, limit, move |child, item| {
        let sender = sender.clone();
        let mapped = map(child.clone(), item);
        async move {
            let value = mapped.await.map_err(StreamSendError::Map)?;
            sender
                .send_checked(&child, value)
                .await
                .map_err(StreamSendError::Delivery)
        }
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::mpsc::{self, RecvError, SendError};
    use crate::lab::run_async_under_lab;
    use crate::runtime::yield_now;
    use crate::stream::{StreamExt, iter};
    use std::future::poll_fn;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Debug)]
    struct Value {
        index: usize,
        live: Arc<AtomicUsize>,
    }

    impl Value {
        fn new(index: usize, live: Arc<AtomicUsize>) -> Self {
            live.fetch_add(1, Ordering::SeqCst);
            Self { index, live }
        }
    }

    impl Drop for Value {
        fn drop(&mut self) {
            self.live.fetch_sub(1, Ordering::SeqCst);
        }
    }

    async fn settle_turns() {
        for _ in 0..32 {
            yield_now().await;
        }
    }

    async fn backpressure(cx: Cx) {
        const LIMIT: usize = 3;
        const CAPACITY: usize = 2;
        const ITEMS: usize = 37;
        let (sender, mut receiver) = mpsc::channel(CAPACITY);
        let producer_sender = sender.clone();
        let live = Arc::new(AtomicUsize::new(0));
        let mapper_live = Arc::clone(&live);
        let reads = Arc::new(AtomicUsize::new(0));
        let source_reads = Arc::clone(&reads);
        let polls = Arc::new(AtomicUsize::new(0));
        let producer_polls = Arc::clone(&polls);
        let mut producer = cx.spawn(move |child| async move {
            let source = iter(0..ITEMS).inspect(move |_| {
                source_reads.fetch_add(1, Ordering::SeqCst);
            });
            let mut work = Box::pin(try_map_send_concurrent_scoped(
                &child, source, LIMIT, &producer_sender,
                move |_mapper, index| {
                    let live = Arc::clone(&mapper_live);
                    async move {
                        yield_now().await;
                        Ok::<_, &'static str>(Value::new(index, live))
                    }
                },
            ));
            poll_fn(|task| {
                producer_polls.fetch_add(1, Ordering::SeqCst);
                work.as_mut().poll(task)
            }).await
        }).expect("spawn producer");

        let mut reached = false;
        for _ in 0..10_000 {
            if sender.telemetry_snapshot(1).send_waiter_count == LIMIT {
                reached = true;
                break;
            }
            yield_now().await;
        }
        assert!(reached, "all direct tasks must reach channel backpressure");
        assert_eq!(receiver.len(), CAPACITY);
        assert_eq!(reads.load(Ordering::SeqCst), CAPACITY + LIMIT);
        assert_eq!(live.load(Ordering::SeqCst), CAPACITY + LIMIT);
        settle_turns().await;
        let before = polls.load(Ordering::SeqCst);
        settle_turns().await;
        assert_eq!(polls.load(Ordering::SeqCst), before, "idle producer must not spin");
        assert_eq!(reads.load(Ordering::SeqCst), CAPACITY + LIMIT);

        let mut seen = vec![0; ITEMS];
        for _ in 0..ITEMS {
            let value = receiver.recv(&cx).await.expect("streamed output");
            seen[value.index] += 1;
            drop(value);
        }
        assert!(matches!(producer.join(&cx).await, Ok(Outcome::Ok(()))));
        assert!(seen.iter().all(|count| *count == 1));
        assert_eq!(live.load(Ordering::SeqCst), 0);
        assert_eq!(reads.load(Ordering::SeqCst), ITEMS);
        let state = sender.telemetry_snapshot(1);
        assert_eq!(state.send_waiter_count, 0);
        assert_eq!(state.reserved_uncommitted_obligations, 0);
        assert!(!receiver.is_closed(), "caller retains its destination sender");
        assert!(matches!(receiver.try_recv(), Err(RecvError::Empty)));
    }

    #[test]
    fn output_backpressure_bounds_live_values_and_source_reads_in_lab() {
        for seed in [0x5E01, 0x5E02, 0x5E03] {
            let ((), report) = run_async_under_lab(seed, backpressure);
            assert!(report.quiescent && report.invariant_violations.is_empty());
        }
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn output_backpressure_bounds_live_values_and_source_reads_on_native_runtime() {
        let runtime = crate::runtime::RuntimeBuilder::current_thread().build().unwrap();
        runtime.block_on(runtime.handle().spawn(async {
            backpressure(Cx::current().expect("native context")).await;
        }));
    }

    #[test]
    fn disconnected_destination_returns_the_non_clone_output() {
        let ((), report) = run_async_under_lab(0x5E04, |cx| async move {
            let (sender, receiver) = mpsc::channel(1);
            drop(receiver);
            let live = Arc::new(AtomicUsize::new(0));
            let mapper_live = Arc::clone(&live);
            let outcome = try_map_send_concurrent_scoped(
                &cx, iter([7]), 1, &sender,
                move |_child, index| {
                    let live = Arc::clone(&mapper_live);
                    async move { Ok::<_, &'static str>(Value::new(index, live)) }
                },
            ).await;
            match outcome {
                Outcome::Err(ScopedStreamError::Item(StreamSendError::Delivery(
                    CheckedSendError::Channel(SendError::Disconnected(value)),
                ))) => {
                    assert_eq!(value.index, 7);
                    assert_eq!(live.load(Ordering::SeqCst), 1);
                    drop(value);
                }
                other => panic!("expected rejected output, got {other:?}"),
            }
            assert_eq!(live.load(Ordering::SeqCst), 0);
            assert_eq!(sender.telemetry_snapshot(1).reserved_uncommitted_obligations, 0);
        });
        assert!(report.quiescent && report.invariant_violations.is_empty());
    }

    #[test]
    fn map_failure_does_not_rollback_already_accepted_output() {
        let ((), report) = run_async_under_lab(0x5E05, |cx| async move {
            let (sender, mut receiver) = mpsc::channel(4);
            let calls = Arc::new(AtomicUsize::new(0));
            let map_calls = Arc::clone(&calls);
            let outcome = try_map_send_concurrent_scoped(
                &cx, iter(0..5), 1, &sender,
                move |_child, item| {
                    map_calls.fetch_add(1, Ordering::SeqCst);
                    async move {
                        if item == 1 { Err("map failed") } else { Ok(item) }
                    }
                },
            ).await;
            assert!(matches!(outcome,
                Outcome::Err(ScopedStreamError::Item(StreamSendError::Map("map failed")))));
            assert_eq!(calls.load(Ordering::SeqCst), 2);
            assert_eq!(receiver.try_recv(), Ok(0));
            assert_eq!(receiver.try_recv(), Err(RecvError::Empty));
        });
        assert!(report.quiescent && report.invariant_violations.is_empty());
    }

    #[test]
    fn map_failure_interrupts_sibling_blocked_on_full_output() {
        let ((), report) = run_async_under_lab(0x5E06, |cx| async move {
            let (sender, mut receiver) = mpsc::channel(1);
            sender.try_send(99).unwrap();
            let watch = sender.clone();
            let outcome = try_map_send_concurrent_scoped(
                &cx, iter([0, 1]), 2, &sender,
                move |_child, item| {
                    let watch = watch.clone();
                    async move {
                        if item == 0 { return Ok(0); }
                        for _ in 0..10_000 {
                            if watch.telemetry_snapshot(1).send_waiter_count == 1 {
                                return Err("map failed behind backpressure");
                            }
                            yield_now().await;
                        }
                        panic!("sibling never reached capacity wait");
                    }
                },
            ).await;
            assert!(matches!(outcome, Outcome::Err(ScopedStreamError::Item(
                StreamSendError::Map("map failed behind backpressure")))));
            assert_eq!(receiver.try_recv(), Ok(99));
            assert_eq!(receiver.try_recv(), Err(RecvError::Empty));
            assert_eq!(sender.telemetry_snapshot(1).send_waiter_count, 0);
            assert_eq!(sender.telemetry_snapshot(1).reserved_uncommitted_obligations, 0);
        });
        assert!(report.quiescent && report.invariant_violations.is_empty());
    }

    #[test]
    fn runtime_refusal_does_not_poll_a_borrowed_source() {
        let cx = Cx::for_testing();
        let calls = std::cell::Cell::new(0);
        let source = iter([1]).inspect(|_| calls.set(calls.get() + 1));
        let (sender, _receiver) = mpsc::channel(1);
        let mut work = Box::pin(try_map_send_concurrent_scoped(
            &cx, source, 1, &sender, |_child, item| async move { Ok::<_, ()>(item) },
        ));
        let mut task = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(matches!(work.as_mut().poll(&mut task),
            std::task::Poll::Ready(Outcome::Err(ScopedStreamError::Region(_)))));
        drop(work);
        assert_eq!(calls.get(), 0);
    }
}
