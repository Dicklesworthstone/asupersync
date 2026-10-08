//! Receiver closure must stop upstream work, not wait for its next output.
#![allow(clippy::pedantic, clippy::nursery, clippy::future_not_send)]

use super::*;
use crate::channel::{mpsc, oneshot};
use crate::lab::run_async_under_lab;
use crate::runtime::yield_now;
use crate::stream::iter;
use std::pin::Pin;
use std::sync::atomic::AtomicUsize;
use std::task::{Context, Waker};

struct IdleSource {
    prefix: bool,
    polls: Arc<AtomicUsize>,
}

impl Stream for IdleSource {
    type Item = usize;

    fn poll_next(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<usize>> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        if self.prefix {
            self.prefix = false;
            Poll::Ready(Some(7))
        } else { Poll::Pending }
    }
}

async fn idle_closure(cx: Cx, ordered: bool, drop_receiver: bool, prefix: bool) {
    let (sender, receiver) = mpsc::channel(2);
    let mut receiver = Some(receiver);
    let destination = sender.clone();
    let polls = Arc::new(AtomicUsize::new(0));
    let source_polls = Arc::clone(&polls);
    let mut producer = cx.spawn(move |owner| async move {
        let result = drive(
            &owner, IdleSource { prefix, polls: source_polls }, 2, &destination,
            |_child, item| async move { Ok::<_, ()>(item) }, ordered,
        ).await;
        assert!(!owner.is_cancel_requested());
        result
    }).unwrap();
    let mut parked = false;
    for _ in 0..1000 {
        if polls.load(Ordering::SeqCst) > usize::from(prefix)
            && (!prefix || receiver.as_ref().unwrap().len() == 1)
        {
            parked = true;
            break;
        }
        yield_now().await;
    }
    assert!(parked, "input is idle after any accepted prefix");
    for _ in 0..32 { yield_now().await; }
    let before = polls.load(Ordering::SeqCst);
    for _ in 0..32 { yield_now().await; }
    assert_eq!(polls.load(Ordering::SeqCst), before, "no periodic upstream polling");
    if drop_receiver { drop(receiver.take()); } else { receiver.as_mut().unwrap().close(); }
    let outcome = producer.join(&cx).await.unwrap();
    assert!(matches!(outcome, Outcome::Err(ScopedStreamError::Item(StreamSendError::DestinationClosed))));
    assert!(polls.load(Ordering::SeqCst) <= before + 1);
    assert!(!cx.is_cancel_requested());
    assert_eq!(sender.telemetry_snapshot(1).send_waiter_count, 0);
    assert_eq!(sender.telemetry_snapshot(1).reserved_uncommitted_obligations, 0);
    if let Some(mut receiver) = receiver {
        if prefix { assert_eq!(receiver.try_recv(), Ok(7)); }
        assert_eq!(receiver.try_recv(), Err(mpsc::RecvError::Disconnected));
    }
}

#[test]
fn receiver_close_and_drop_interrupt_idle_sources_with_or_without_a_prefix_in_lab() {
    for ordered in [false, true] {
        for drop_receiver in [false, true] {
            for prefix in [false, true] {
                let ((), report) = run_async_under_lab(0x5801, move |cx| idle_closure(cx, ordered, drop_receiver, prefix));
                assert!(report.quiescent && report.invariant_violations.is_empty());
            }
        }
    }
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn receiver_closure_interrupts_idle_sources_on_native_runtime() {
    for ordered in [false, true] {
        let runtime = crate::runtime::RuntimeBuilder::current_thread().build().unwrap();
        runtime.block_on(runtime.handle().spawn(async move {
            idle_closure(Cx::current().unwrap(), ordered, false, true).await;
        }));
    }
}

async fn busy_closure(cx: Cx, ordered: bool, owner_cancel: bool, panic_cleanup: bool) {
    let (sender, mut receiver) = mpsc::channel(1);
    sender.try_send(99usize).unwrap();
    let destination = sender.clone();
    let (resource, _resource_receiver) = mpsc::channel::<()>(1);
    let mapped_resource = resource.clone();
    let holding = Arc::new(AtomicBool::new(false));
    let mapped_holding = Arc::clone(&holding);
    let cleaned = Arc::new(AtomicUsize::new(0));
    let child_cleaned = Arc::clone(&cleaned);
    let prepared = Arc::new(AtomicUsize::new(0));
    let child_prepared = Arc::clone(&prepared);
    let handles = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let child_handles = Arc::clone(&handles);
    let at_return = Arc::new(AtomicUsize::new(0));
    let recorded = Arc::clone(&at_return);
    let recorded_cleaned = Arc::clone(&cleaned);
    let mut producer = cx.spawn(move |owner| async move {
        let outcome = drive(
            &owner, iter([0usize, 1]), 2, &destination,
            move |mapper, index| {
                let resource = mapped_resource.clone();
                let holding = Arc::clone(&mapped_holding);
                let cleaned = Arc::clone(&child_cleaned);
                let prepared = Arc::clone(&child_prepared);
                let handles = Arc::clone(&child_handles);
                async move {
                    prepared.fetch_add(1, Ordering::SeqCst);
                    if index == 0 {
                        let (done, mut completed) = oneshot::channel();
                        let grandchild = mapper.spawn(move |grandchild| async move {
                            let permit = resource.reserve_checked(&grandchild).await.unwrap();
                            holding.store(true, Ordering::Release);
                            grandchild.cancelled().await;
                            yield_now().await;
                            yield_now().await;
                            drop(permit);
                            cleaned.fetch_add(1, Ordering::SeqCst);
                            done.send_blocking(()).unwrap();
                            if panic_cleanup { panic!("closed pipeline cleanup panic"); }
                        }).unwrap();
                        handles.lock().push(grandchild);
                        // Completion requires descendant cancellation, not
                        // dropping this mapper's future or its join handle.
                        completed.recv_uninterruptible().await.unwrap();
                    }
                    Ok::<_, &'static str>(index)
                }
            }, ordered,
        ).await;
        recorded.store(recorded_cleaned.load(Ordering::SeqCst), Ordering::SeqCst);
        if panic_cleanup {
            assert!(matches!(outcome, Outcome::Panicked(ref p) if p.message().contains("closed pipeline cleanup panic")));
        } else if owner_cancel {
            assert!(outcome.is_cancelled(), "owner cancellation must not become a delivery error");
            let _ = owner.checkpoint();
        } else {
            // A delivery failure already selected by the driver keeps its
            // value; otherwise the independent closure observation explains it.
            assert!(matches!(outcome,
                Outcome::Err(ScopedStreamError::Item(StreamSendError::DestinationClosed))
                | Outcome::Err(ScopedStreamError::Item(StreamSendError::Delivery(
                    CheckedSendError::Channel(SendError::Disconnected(_))
                )))
            ));
            assert!(!owner.is_cancel_requested());
        }
    }).unwrap();
    let mut parked = false;
    for _ in 0..1000 {
        if holding.load(Ordering::Acquire) && prepared.load(Ordering::SeqCst) == 2
            && (ordered || sender.telemetry_snapshot(1).send_waiter_count == 1)
        {
            parked = true;
            break;
        }
        yield_now().await;
    }
    assert!(parked, "mapper, successor, and checked descendant are all waiting");
    assert_eq!(resource.telemetry_snapshot(1).reserved_uncommitted_obligations, 1);
    if owner_cancel { producer.abort(); }
    receiver.close();
    let result = producer.join(&cx).await;
    assert!(matches!(result, Ok(()) | Err(crate::runtime::JoinError::Cancelled(_))));
    assert_eq!(at_return.load(Ordering::SeqCst), 1, "drained before returning to caller");
    assert_eq!(resource.telemetry_snapshot(1).reserved_uncommitted_obligations, 0);
    assert_eq!(sender.telemetry_snapshot(1).send_waiter_count, 0);
    assert!(handles.lock().iter().all(|handle| handle.is_finished()));
    resource.try_reserve().unwrap().abort();
    assert_eq!(receiver.try_recv(), Ok(99));
    assert_eq!(receiver.try_recv(), Err(mpsc::RecvError::Disconnected));
    assert!(!cx.is_cancel_requested());
}

#[test]
fn receiver_closure_drains_mappers_order_gates_and_checked_descendants_in_lab() {
    for ordered in [false, true] {
        let ((), report) = run_async_under_lab(0x5802, move |cx| busy_closure(cx, ordered, false, false));
        assert!(report.quiescent && report.invariant_violations.is_empty());
    }
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn receiver_closure_drains_busy_pipeline_on_native_runtime() {
    for ordered in [false, true] {
        let runtime = crate::runtime::RuntimeBuilder::current_thread().build().unwrap();
        runtime.block_on(runtime.handle().spawn(async move {
            busy_closure(Cx::current().unwrap(), ordered, false, false).await;
        }));
    }
}

#[test]
fn owner_cancellation_and_cleanup_panics_are_not_hidden_by_receiver_closure() {
    // Ordered output ensures the closure is the wake source: no channel send
    // is waiting until the head mapper's descendant has finished cleanup.
    for (owner_cancel, panic_cleanup) in [(true, false), (false, true)] {
        let ((), report) = run_async_under_lab(0x5803, move |cx| busy_closure(cx, true, owner_cancel, panic_cleanup));
        assert!(report.quiescent && report.invariant_violations.is_empty());
    }
}

#[test]
fn preclosed_destination_refuses_without_polling_source_or_mapper() {
    for ordered in [false, true] {
        let cx = Cx::for_testing();
        let reads = std::cell::Cell::new(0);
        let source = iter([1u8]).inspect(|_| reads.set(reads.get() + 1));
        let (sender, receiver) = mpsc::channel::<u8>(1);
        drop(receiver);
        async fn never_map(_: Cx, _: u8) -> Result<u8, ()> {
            panic!("mapper must not be admitted");
        }
        let mut producer = Box::pin(drive(&cx, source, 2, &sender, never_map, ordered));
        let result = producer.as_mut().poll(&mut Context::from_waker(Waker::noop()));
        assert!(matches!(result,
            Poll::Ready(Outcome::<(), ScopedStreamError<StreamSendError<(), u8>>>::Err(
                ScopedStreamError::Item(StreamSendError::DestinationClosed)
            ))
        ));
        drop(producer);
        assert_eq!(reads.get(), 0);
    }
}

#[test]
fn closure_during_region_mint_is_observed_before_source_admission() {
    let ((), report) = run_async_under_lab(0x5804, |cx| async move {
        let reads = AtomicUsize::new(0);
        let source = iter([1]).inspect(|_| { reads.fetch_add(1, Ordering::SeqCst); });
        let (sender, mut receiver) = mpsc::channel(1);
        let mut producer = Box::pin(try_map_send_concurrent_scoped(
            &cx, source, 2, &sender, |_child, value| async move { Ok::<_, ()>(value) },
        ));
        poll_fn(|task| {
            assert!(producer.as_mut().poll(task).is_pending(), "mint command is not yet serviced");
            Poll::Ready(())
        }).await;
        receiver.close();
        assert!(matches!(producer.await,
            Outcome::Err(ScopedStreamError::Item(StreamSendError::DestinationClosed))));
        assert_eq!(reads.load(Ordering::SeqCst), 0);
    });
    assert!(report.quiescent && report.invariant_violations.is_empty());
}

/// A queue source whose items can become ready while the producer is parked.
struct QueueSource {
    queue: Arc<parking_lot::Mutex<std::collections::VecDeque<usize>>>,
    waker: Arc<parking_lot::Mutex<Option<Waker>>>,
    reads: Arc<AtomicUsize>,
}

impl Stream for QueueSource {
    type Item = usize;

    fn poll_next(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<Option<usize>> {
        if let Some(item) = self.queue.lock().pop_front() {
            self.reads.fetch_add(1, Ordering::SeqCst);
            return Poll::Ready(Some(item));
        }
        *self.waker.lock() = Some(task.waker().clone());
        Poll::Pending
    }
}

/// An item that becomes ready in the same turn as the receiver closes stays in
/// the source (br-asupersync-buy8cp). The producer used to poll its work before
/// its closure stop, so it took the item, and could run its mapper, only to
/// drop it with `DestinationClosed`; up to `limit` items of a borrowed source
/// were lost to their caller that way.
#[test]
fn an_item_ready_when_the_receiver_closes_stays_in_the_source() {
    for ordered in [false, true] {
        let ((), report) = run_async_under_lab(0x5805, move |cx| async move {
            let queue = Arc::new(parking_lot::Mutex::new(std::collections::VecDeque::new()));
            let waker = Arc::new(parking_lot::Mutex::new(None::<Waker>));
            let reads = Arc::new(AtomicUsize::new(0));
            let mapped = Arc::new(AtomicUsize::new(0));
            let source = QueueSource {
                queue: Arc::clone(&queue),
                waker: Arc::clone(&waker),
                reads: Arc::clone(&reads),
            };
            let (sender, mut receiver) = mpsc::channel(2);
            let destination = sender.clone();
            let mapper_calls = Arc::clone(&mapped);
            let mut producer = cx
                .spawn(move |owner| async move {
                    drive(
                        &owner,
                        source,
                        2,
                        &destination,
                        move |_child, item| {
                            mapper_calls.fetch_add(1, Ordering::SeqCst);
                            async move { Ok::<_, ()>(item) }
                        },
                        ordered,
                    )
                    .await
                })
                .unwrap();
            let mut parked = false;
            for _ in 0..1000 {
                if waker.lock().is_some() {
                    parked = true;
                    break;
                }
                yield_now().await;
            }
            assert!(parked, "the producer waits on its empty source");
            // In one turn: an item becomes ready, its waker fires, and the
            // receiver closes.
            queue.lock().push_back(5);
            let pending = waker.lock().take();
            if let Some(pending) = pending {
                pending.wake();
            }
            receiver.close();
            let outcome = producer.join(&cx).await.unwrap();
            assert!(matches!(
                outcome,
                Outcome::Err(ScopedStreamError::Item(StreamSendError::DestinationClosed))
            ));
            assert_eq!(
                reads.load(Ordering::SeqCst),
                0,
                "no source item was taken after the close"
            );
            assert_eq!(
                mapped.load(Ordering::SeqCst),
                0,
                "no mapper ran after the close"
            );
            assert_eq!(
                queue.lock().pop_front(),
                Some(5),
                "the item is still in the source"
            );
            assert_eq!(
                sender
                    .telemetry_snapshot(1)
                    .reserved_uncommitted_obligations,
                0
            );
        });
        assert!(report.quiescent && report.invariant_violations.is_empty());
    }
}
