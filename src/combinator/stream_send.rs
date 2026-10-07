//! Bounded output pipelines over region-owned concurrent stream work.
//!
//! A mapped output keeps its task slot until checked channel publication.
//! Unlike collecting a `Vec`, this permits a long-lived source without retaining
//! every result. The destination consumer must run concurrently with the sender.
//!
//! Bead: asupersync-dx-core-api-v2-u1z5hn.8 (bounded stream task composition).

use super::stream_collect::{ScopedStreamError, try_for_each_concurrent_scoped};
use crate::channel::mpsc::{CheckedSendError, SendError, Sender};
use crate::cx::Cx;
use crate::stream::{Stream, StreamExt};
use crate::sync::Notify;
use crate::types::Outcome;
use std::future::{Future, poll_fn};
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Poll;

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
    map: F,
) -> Outcome<(), ScopedStreamError<StreamSendError<E, T>>>
where
    S: Stream + Unpin,
    S::Item: Send + 'static,
    F: FnMut(Cx, S::Item) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = Result<T, E>> + Send + 'static,
    T: Send + 'static,
    E: Send + 'static,
{
    drive(cx, stream, limit, sender, map, false).await
}

/// Concurrent mapping with bounded, source-order output publication.
///
/// This has [`try_map_send_concurrent_scoped`]'s subtree-drain and checked-send
/// contract, but an output cannot reserve channel capacity until its predecessor
/// has been accepted. Completed outputs waiting for their turn STILL occupy
/// direct-task slots. A stalled early mapper therefore stops read-ahead after
/// `limit` inputs instead of growing an unbounded reorder buffer. The tradeoff
/// is head-of-line blocking, not additional retained-result memory.
///
/// Mapping failures are observed without waiting for the failed item's turn.
/// A failed/cancelled predecessor never authorizes a successor to publish: the
/// driver cancels the subtree, and independent cancellation wakeups retire the
/// parked successors. There is no polling loop or output-order coordinator task.
/// The successfully published outputs of this operation form a source-order
/// prefix, including on failure. Other senders may interleave their own values.
///
/// Output publication is not transactional with later subtree cleanup. Already
/// accepted values remain visible, and other unpublished values are discarded
/// during cancellation/drain. Destination closure is detected when publication
/// is attempted; it does not forcibly interrupt an unfinished mapper. The item
/// and resource-lifetime bounds of the unordered variant apply unchanged.
///
/// ```no_run
/// # async fn example(cx: &asupersync::Cx) {
/// use asupersync::{Outcome, channel::mpsc, stream::iter};
/// use asupersync::combinator::stream_send::try_map_send_ordered_concurrent_scoped;
/// let (sender, mut receiver) = mpsc::channel(2);
/// let mut producer = cx.spawn(move |owner| async move {
///     try_map_send_ordered_concurrent_scoped(
///         &owner, iter([3, 1, 2]), 2, &sender,
///         |_child, n| async move { Ok::<_, &'static str>(n * 10) },
///     ).await
/// }).expect("spawn producer");
/// // Consume concurrently: do not join the producer before draining its output.
/// let mut values = Vec::new();
/// while let Ok(value) = receiver.recv(cx).await { values.push(value); }
/// assert!(matches!(producer.join(cx).await, Ok(Outcome::Ok(()))));
/// assert_eq!(values, [30, 10, 20]);
/// # }
/// ```
///
/// # Panics
/// Panics if `limit` is zero.
pub async fn try_map_send_ordered_concurrent_scoped<S, F, Fut, T, E>(
    cx: &Cx,
    stream: S,
    limit: usize,
    sender: &Sender<T>,
    map: F,
) -> Outcome<(), ScopedStreamError<StreamSendError<E, T>>>
where
    S: Stream + Unpin,
    S::Item: Send + 'static,
    F: FnMut(Cx, S::Item) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = Result<T, E>> + Send + 'static,
    T: Send + 'static,
    E: Send + 'static,
{
    drive(cx, stream, limit, sender, map, true).await
}

/// One publication edge, not a linked list: completed predecessors are freed
/// when the direct successors finish. At most O(limit) edges remain owned.
#[derive(Default)]
struct Published {
    committed: AtomicBool,
    changed: Notify,
}

impl Published {
    fn publish(&self) {
        self.committed.store(true, Ordering::Release);
        self.changed.notify_waiters();
    }

    async fn wait(&self, cx: &Cx) -> bool {
        if self.committed.load(Ordering::Acquire) {
            return true;
        }
        let mut changed = pin!(self.changed.wait_until(|| {
            self.committed.load(Ordering::Acquire)
        }));
        let mut cancelled = pin!(cx.cancelled());
        poll_fn(|task| {
            if cancelled.as_mut().poll(task).is_ready() {
                Poll::Ready(false)
            } else {
                changed.as_mut().poll(task).map(|()| true)
            }
        }).await
    }
}

async fn drive<S, F, Fut, T, E>(
    cx: &Cx,
    stream: S,
    limit: usize,
    sender: &Sender<T>,
    mut map: F,
    ordered: bool,
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
    let mut previous = None;
    let stream = stream.map(move |item| {
        let published = ordered.then(|| Arc::new(Published::default()));
        let predecessor = std::mem::replace(&mut previous, published.clone());
        (item, predecessor, published)
    });
    try_for_each_concurrent_scoped(cx, stream, limit, move |child, (item, before, after)| {
        let sender = sender.clone();
        let mapped = map(child.clone(), item);
        async move {
            let value = mapped.await.map_err(StreamSendError::Map)?;
            if let Some(before) = before {
                if !before.wait(&child).await {
                    return Err(StreamSendError::Delivery(CheckedSendError::Channel(
                        SendError::Cancelled(value),
                    )));
                }
            }
            sender
                .send_checked(&child, value)
                .await
                .map_err(StreamSendError::Delivery)?;
            // Do not reserve before this item's turn: later reservations could
            // otherwise consume every slot and prevent the predecessor sending.
            // Only acceptance, never Drop or an error, opens the successor gate.
            if let Some(after) = after {
                after.publish();
            }
            Ok(())
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

#[cfg(test)]
mod ordered_tests {
    use super::*;
    use crate::channel::mpsc::{self, RecvError};
    use crate::lab::run_async_under_lab;
    use crate::runtime::yield_now;
    use crate::stream::iter;
    use crate::sync::{OwnedSemaphorePermit, Semaphore};
    use std::sync::atomic::AtomicUsize;
    use std::task::{Context, Wake, Waker};

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

    async fn turns() {
        for _ in 0..32 { yield_now().await; }
    }

    async fn ordered_pressure(cx: Cx) {
        const LIMIT: usize = 4;
        const CAPACITY: usize = 2;
        const ITEMS: usize = 41;
        let (sender, mut receiver) = mpsc::channel(CAPACITY);
        let destination = sender.clone();
        let release_head = Arc::new(Semaphore::new(0));
        let head_gate = Arc::clone(&release_head);
        let live = Arc::new(AtomicUsize::new(0));
        let mapper_live = Arc::clone(&live);
        let reads = Arc::new(AtomicUsize::new(0));
        let source_reads = Arc::clone(&reads);
        let polls = Arc::new(AtomicUsize::new(0));
        let driver_polls = Arc::clone(&polls);
        let mut producer = cx.spawn(move |child| async move {
            let source = iter(0..ITEMS).inspect(move |_| {
                source_reads.fetch_add(1, Ordering::SeqCst);
            });
            let mut work = Box::pin(try_map_send_ordered_concurrent_scoped(
                &child, source, LIMIT, &destination,
                move |mapper, index| {
                    let gate = Arc::clone(&head_gate);
                    let live = Arc::clone(&mapper_live);
                    async move {
                        if index == 0 {
                            let _permit = OwnedSemaphorePermit::acquire(gate, &mapper, 1)
                                .await.map_err(|_| "head cancelled")?;
                        }
                        Ok::<_, &'static str>(Value::new(index, live))
                    }
                },
            ));
            poll_fn(|task| {
                driver_polls.fetch_add(1, Ordering::SeqCst);
                work.as_mut().poll(task)
            }).await
        }).unwrap();

        let mut staged = false;
        for _ in 0..10_000 {
            if live.load(Ordering::SeqCst) == LIMIT - 1 {
                staged = true;
                break;
            }
            yield_now().await;
        }
        assert!(staged, "later mappers must finish while the head is blocked");
        assert!(receiver.is_empty(), "no successor can bypass the blocked first input");
        assert_eq!(reads.load(Ordering::SeqCst), LIMIT);
        assert_eq!(sender.telemetry_snapshot(1).reserved_uncommitted_obligations, 0);
        turns().await;
        let before = polls.load(Ordering::SeqCst);
        turns().await;
        assert_eq!(polls.load(Ordering::SeqCst), before);
        assert_eq!(reads.load(Ordering::SeqCst), LIMIT, "no unbounded reorder read-ahead");

        release_head.add_permits(1);
        let mut full = false;
        for _ in 0..10_000 {
            if receiver.len() == CAPACITY
                && live.load(Ordering::SeqCst) == CAPACITY + LIMIT
                && sender.telemetry_snapshot(1).send_waiter_count == 1
            {
                full = true;
                break;
            }
            yield_now().await;
        }
        assert!(full, "destination pressure must retain the remaining task slots");
        assert_eq!(reads.load(Ordering::SeqCst), CAPACITY + LIMIT);
        assert_eq!(sender.telemetry_snapshot(1).send_waiter_count, 1,
            "only the head output may wait for channel capacity");
        for index in 0..ITEMS {
            let value = receiver.recv(&cx).await.unwrap();
            assert_eq!(value.index, index);
            drop(value);
        }
        assert!(matches!(producer.join(&cx).await, Ok(Outcome::Ok(()))));
        assert_eq!(live.load(Ordering::SeqCst), 0);
        assert_eq!(sender.telemetry_snapshot(1).send_waiter_count, 0);
    }

    #[test]
    fn ordered_publication_bounds_reorder_and_destination_pressure_in_lab() {
        for seed in [0x5E10, 0x5E11, 0x5E12] {
            let ((), report) = run_async_under_lab(seed, ordered_pressure);
            assert!(report.quiescent && report.invariant_violations.is_empty());
        }
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn ordered_publication_bounds_reorder_and_destination_pressure_on_native_runtime() {
        let runtime = crate::runtime::RuntimeBuilder::current_thread().build().unwrap();
        runtime.block_on(runtime.handle().spawn(async {
            ordered_pressure(Cx::current().unwrap()).await;
        }));
    }

    #[test]
    fn later_map_failure_does_not_wait_for_its_output_turn_or_publish_a_suffix() {
        let ((), report) = run_async_under_lab(0x5E13, |cx| async move {
            let (sender, mut receiver) = mpsc::channel(4);
            let head_started = Arc::new(Published::default());
            let tail_mapped = Arc::new(Published::default());
            let cleaned = Arc::new(AtomicUsize::new(0));
            let map_cleaned = Arc::clone(&cleaned);
            let live = Arc::new(AtomicUsize::new(0));
            let map_live = Arc::clone(&live);
            let outcome = try_map_send_ordered_concurrent_scoped(
                &cx, iter(0..3), 3, &sender,
                move |child, index| {
                    let head = Arc::clone(&head_started);
                    let tail = Arc::clone(&tail_mapped);
                    let cleaned = Arc::clone(&map_cleaned);
                    let live = Arc::clone(&map_live);
                    async move {
                        match index {
                            0 => {
                                head.publish();
                                child.cancelled().await;
                                yield_now().await;
                                cleaned.fetch_add(1, Ordering::SeqCst);
                                Err("head drained")
                            }
                            1 => {
                                assert!(head.wait(&child).await);
                                assert!(tail.wait(&child).await);
                                Err("middle mapper failed")
                            }
                            _ => {
                                let value = Value::new(index, live);
                                tail.publish();
                                Ok(value)
                            }
                        }
                    }
                },
            ).await;
            assert!(matches!(outcome, Outcome::Err(ScopedStreamError::Item(
                StreamSendError::Map("middle mapper failed")))));
            assert_eq!(cleaned.load(Ordering::SeqCst), 1, "joined before caller region close");
            assert_eq!(live.load(Ordering::SeqCst), 0, "staged successor was discarded");
            assert!(matches!(receiver.try_recv(), Err(RecvError::Empty)));
        });
        assert!(report.quiescent && report.invariant_violations.is_empty());
    }

    async fn cancellation_drains(cx: Cx) {
        let (sender, mut receiver) = mpsc::channel(1);
        sender.try_send(usize::MAX).unwrap();
        let destination = sender.clone();
        let (resource, resource_receiver) = mpsc::channel::<()>(1);
        let descendant_resource = resource.clone();
        let holding = Arc::new(AtomicBool::new(false));
        let descendant_holding = Arc::clone(&holding);
        let cleaned = Arc::new(AtomicUsize::new(0));
        let descendant_cleaned = Arc::clone(&cleaned);
        let at_return = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&at_return);
        let observed_cleaned = Arc::clone(&cleaned);
        let handles = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let retained = Arc::clone(&handles);
        let prepared = Arc::new(AtomicUsize::new(0));
        let mapped = Arc::clone(&prepared);
        let mut producer = cx.spawn(move |child| async move {
            let outcome = try_map_send_ordered_concurrent_scoped(
                &child, iter([0, 1]), 2, &destination,
                move |mapper, index| {
                    let resource = descendant_resource.clone();
                    let holding = Arc::clone(&descendant_holding);
                    let cleaned = Arc::clone(&descendant_cleaned);
                    let handles = Arc::clone(&retained);
                    let prepared = Arc::clone(&mapped);
                    async move {
                        if index == 0 {
                            let handle = mapper.spawn(move |grandchild| async move {
                                let permit = resource.reserve_checked(&grandchild).await.unwrap();
                                holding.store(true, Ordering::SeqCst);
                                grandchild.cancelled().await;
                                yield_now().await;
                                yield_now().await;
                                drop(permit);
                                cleaned.fetch_add(1, Ordering::SeqCst);
                            }).unwrap();
                            // A retained join cannot provide accidental drop cancellation.
                            handles.lock().push(handle);
                        }
                        prepared.fetch_add(1, Ordering::SeqCst);
                        Ok::<_, &'static str>(index)
                    }
                },
            ).await;
            assert!(outcome.is_cancelled());
            observed.store(observed_cleaned.load(Ordering::SeqCst), Ordering::SeqCst);
        }).unwrap();

        let mut parked = false;
        for _ in 0..10_000 {
            if prepared.load(Ordering::SeqCst) == 2
                && holding.load(Ordering::SeqCst)
                && sender.telemetry_snapshot(1).send_waiter_count == 1
            {
                parked = true;
                break;
            }
            yield_now().await;
        }
        assert!(parked, "head output, successor and resource-owning descendant must be pending");
        assert_eq!(resource.telemetry_snapshot(1).reserved_uncommitted_obligations, 1);
        producer.abort();
        let joined = producer.join(&cx).await;
        assert!(matches!(joined, Ok(()) | Err(crate::runtime::JoinError::Cancelled(_))));
        assert_eq!(at_return.load(Ordering::SeqCst), 1, "subtree was drained before return");
        assert_eq!(cleaned.load(Ordering::SeqCst), 1);
        assert_eq!(sender.telemetry_snapshot(1).send_waiter_count, 0);
        assert_eq!(sender.telemetry_snapshot(1).reserved_uncommitted_obligations, 0);
        assert_eq!(resource.telemetry_snapshot(1).reserved_uncommitted_obligations, 0);
        resource.try_reserve().unwrap().abort();
        assert_eq!(receiver.try_recv(), Ok(usize::MAX));
        assert_eq!(receiver.try_recv(), Err(RecvError::Empty));
        assert!(handles.lock().iter().all(|handle| handle.is_finished()));
        drop(resource_receiver);
    }

    #[test]
    fn cancellation_drains_order_waiters_and_checked_descendants_in_lab() {
        let ((), report) = run_async_under_lab(0x5E14, cancellation_drains);
        assert!(report.quiescent && report.invariant_violations.is_empty());
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn cancellation_drains_order_waiters_and_checked_descendants_on_native_runtime() {
        let runtime = crate::runtime::RuntimeBuilder::current_thread().build().unwrap();
        runtime.block_on(runtime.handle().spawn(async {
            cancellation_drains(Cx::current().unwrap()).await;
        }));
    }

    #[test]
    fn checked_admission_refusal_keeps_output_without_publishing() {
        use crate::runtime::obligation_mailbox::ObligationAdmissionError;
        let ((), report) = run_async_under_lab(0x5E15, |cx| async move {
            let (sender, mut receiver) = mpsc::channel(1);
            let outcome = try_map_send_ordered_concurrent_scoped(
                &cx, iter([7]), 1, &sender,
                |child, value| async move {
                    // Private fault injection: the mapper is still a real task,
                    // but its checked-send admission capability has been revoked.
                    child.revoke_obligation_admission();
                    Ok::<_, ()>(Box::new(value))
                },
            ).await;
            assert!(matches!(outcome, Outcome::Err(ScopedStreamError::Item(
                StreamSendError::Delivery(CheckedSendError::Admission {
                    error: ObligationAdmissionError::HolderNotLive, value,
                })
            )) if *value == 7));
            assert!(matches!(receiver.try_recv(), Err(RecvError::Empty)));
            assert_eq!(sender.telemetry_snapshot(1).reserved_uncommitted_obligations, 0);
        });
        assert!(report.quiescent && report.invariant_violations.is_empty());
    }

    #[derive(Default)]
    struct Wakes(AtomicUsize);

    impl Wake for Wakes {
        fn wake(self: Arc<Self>) { self.wake_by_ref(); }
        fn wake_by_ref(self: &Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
    }

    #[test]
    fn order_wait_migrates_wakers_and_cleans_up_on_cancellation_or_drop() {
        for cancel in [false, true] {
            let cx = Cx::for_testing();
            let gate = Published::default();
            let first = Arc::new(Wakes::default());
            let second = Arc::new(Wakes::default());
            let first_waker = Waker::from(Arc::clone(&first));
            let second_waker = Waker::from(Arc::clone(&second));
            let mut first_task = Context::from_waker(&first_waker);
            let mut second_task = Context::from_waker(&second_waker);
            let mut waiting = Box::pin(gate.wait(&cx));
            assert!(waiting.as_mut().poll(&mut first_task).is_pending());
            assert!(waiting.as_mut().poll(&mut second_task).is_pending());
            assert_eq!(Arc::strong_count(&first), 2);
            if cancel {
                cx.cancel_fast(crate::types::CancelKind::User);
                assert_eq!(first.0.load(Ordering::SeqCst), 0);
                assert!(second.0.load(Ordering::SeqCst) > 0);
                assert_eq!(waiting.as_mut().poll(&mut second_task), Poll::Ready(false));
                assert_eq!(gate.changed.waiter_count(), 0);
                assert_eq!(Arc::strong_count(&second), 2);
            }
            drop(waiting);
            assert_eq!(gate.changed.waiter_count(), 0);
            assert_eq!(Arc::strong_count(&second), 2);
        }
    }

    #[test]
    fn completed_predecessor_is_not_lost_before_or_after_wait_registration() {
        for prepublished in [false, true] {
            let cx = Cx::for_testing();
            let gate = Published::default();
            let count = Arc::new(Wakes::default());
            let waker = Waker::from(Arc::clone(&count));
            let mut task = Context::from_waker(&waker);
            if prepublished { gate.publish(); }
            let mut wait = Box::pin(gate.wait(&cx));
            if !prepublished {
                assert!(wait.as_mut().poll(&mut task).is_pending());
                gate.publish();
                assert!(count.0.load(Ordering::SeqCst) > 0);
            }
            assert_eq!(wait.as_mut().poll(&mut task), Poll::Ready(true));
            assert_eq!(gate.changed.waiter_count(), 0);
            assert_eq!(Arc::strong_count(&count), 2);
        }
    }
}
