use super::*;
use crate::types::CancelKind;
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{OnceLock, Weak};
use std::task::{Context, Wake, Waker};

#[derive(Default)]
struct Counter(AtomicUsize);
impl Wake for Counter {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}
fn wake_counter() -> (Arc<Counter>, Waker) {
    let counter = Arc::new(Counter::default());
    let waker = Waker::from(Arc::clone(&counter));
    (counter, waker)
}

#[test]
fn capacity_includes_reservations_and_unacknowledged_items() {
    let cx = Cx::for_testing();
    let (tx, rx) = channel(2);
    let permit = tx.try_reserve(&cx).unwrap();
    tx.try_send(&cx, 7).unwrap();
    let delivery = rx.try_recv_with_ack(&cx).unwrap();
    let stats = tx.stats();
    assert_eq!(
        (
            stats.queued,
            stats.reserved,
            stats.in_flight,
            stats.unfinished()
        ),
        (0, 1, 1, 2)
    );
    assert_eq!(tx.try_send(&cx, 9).unwrap_err().error, QueueError::Full);
    assert_eq!(delivery.ack(), 7);
    tx.try_send(&cx, 9).unwrap();
    permit.send(11).unwrap();
    assert_eq!(rx.try_recv_with_ack(&cx).unwrap().ack(), 9);
    assert_eq!(rx.try_recv_with_ack(&cx).unwrap().ack(), 11);
    assert_eq!(tx.stats().unfinished(), 0);
}

#[test]
fn nonclone_send_only_payload_returns_with_identity_and_mutations() {
    struct Job(Cell<u8>);
    fn send_sync<T: Send + Sync>() {}
    send_sync::<Sender<Job>>();
    send_sync::<Receiver<Job>>();
    let cx = Cx::for_testing();
    let (tx, rx) = channel(1);
    tx.try_send(&cx, Job(Cell::new(4)))
        .unwrap_or_else(|_| panic!("send job"));
    let first = rx.try_recv_with_ack(&cx).unwrap();
    let sequence = first.sequence();
    first.0.set(8);
    drop(first);
    let second = rx.try_recv_with_ack(&cx).unwrap();
    assert_eq!(second.sequence(), sequence);
    assert_eq!(second.attempts(), 2);
    assert_eq!(second.ack().0.get(), 8);
}

#[test]
fn retries_are_fifo_at_the_tail_and_never_need_a_free_credit() {
    let cx = Cx::for_testing();
    let (tx, rx) = channel(2);
    tx.try_send(&cx, 1).unwrap();
    tx.try_send(&cx, 2).unwrap();
    let item = rx.try_recv_with_ack(&cx).unwrap();
    assert_eq!(tx.stats().unfinished(), 2);
    item.nack();
    assert_eq!(rx.try_recv_with_ack(&cx).unwrap().ack(), 2);
    assert_eq!(rx.try_recv_with_ack(&cx).unwrap().ack(), 1);
}

#[test]
fn sealed_queue_drains_preissued_permits_and_redeliveries_before_eof() {
    let cx = Cx::for_testing();
    let (tx, rx) = channel(1);
    let permit = tx.try_reserve(&cx).unwrap();
    rx.close();
    assert!(matches!(tx.try_reserve(&cx), Err(QueueError::Closed)));
    drop(tx);
    assert!(matches!(rx.try_recv_with_ack(&cx), Err(QueueError::Empty)));
    permit.send(42).unwrap();
    let item = rx.try_recv_with_ack(&cx).unwrap();
    assert!(matches!(rx.try_recv_with_ack(&cx), Err(QueueError::Empty)));
    drop(item);
    assert_eq!(rx.try_recv_with_ack(&cx).unwrap().ack(), 42);
    assert!(matches!(rx.try_recv_with_ack(&cx), Err(QueueError::Closed)));
}

#[test]
fn aborting_last_reservation_wakes_receiver_to_true_eof() {
    let cx = Cx::for_testing();
    let (tx, rx) = channel::<u8>(1);
    let permit = tx.try_reserve(&cx).unwrap();
    drop(tx);
    let (counter, waker) = wake_counter();
    let mut context = Context::from_waker(&waker);
    let mut receiving = Box::pin(rx.recv_with_ack(&cx));
    assert!(receiving.as_mut().poll(&mut context).is_pending());
    permit.abort();
    assert!(counter.0.load(Ordering::SeqCst) > 0);
    assert!(matches!(
        receiving.as_mut().poll(&mut context),
        Poll::Ready(Err(QueueError::Closed))
    ));
    drop(receiving);
    assert_eq!(rx.shared.changed.waiter_count(), 0);
}

#[test]
fn parked_sends_and_receives_observe_task_cancellation_and_retire_waits() {
    for send in [false, true] {
        let cx = Cx::for_testing();
        let (tx, rx) = channel(1);
        let (counter, waker) = wake_counter();
        let mut context = Context::from_waker(&waker);
        if send {
            tx.try_send(&cx, 1).unwrap();
            let mut pending = Box::pin(tx.reserve(&cx));
            assert!(pending.as_mut().poll(&mut context).is_pending());
            assert_eq!(tx.shared.changed.waiter_count(), 1);
            cx.cancel_fast(CancelKind::User);
            assert!(counter.0.load(Ordering::SeqCst) > 0);
            assert!(matches!(
                pending.as_mut().poll(&mut context),
                Poll::Ready(Err(QueueError::Cancelled))
            ));
            drop(pending);
            assert_eq!(tx.stats().queued, 1);
            assert_eq!(tx.stats().reserved, 0);
        } else {
            let mut pending = Box::pin(rx.recv_with_ack(&cx));
            assert!(pending.as_mut().poll(&mut context).is_pending());
            assert_eq!(tx.shared.changed.waiter_count(), 1);
            cx.cancel_fast(CancelKind::User);
            assert!(counter.0.load(Ordering::SeqCst) > 0);
            assert!(matches!(
                pending.as_mut().poll(&mut context),
                Poll::Ready(Err(QueueError::Cancelled))
            ));
            drop(pending);
            assert_eq!(tx.stats().unfinished(), 0);
        }
        assert_eq!(tx.shared.changed.waiter_count(), 0);
    }
}

#[test]
fn cancelling_one_wait_does_not_remove_another_workers_wake() {
    let cx = Cx::for_testing();
    let (tx, rx) = channel(1);
    let peer = rx.clone();
    let mut abandoned = Box::pin(rx.recv_with_ack(&cx));
    let mut retained = Box::pin(peer.recv_with_ack(&cx));
    let (counter, waker) = wake_counter();
    let mut context = Context::from_waker(&waker);
    assert!(abandoned.as_mut().poll(&mut context).is_pending());
    assert!(retained.as_mut().poll(&mut context).is_pending());
    assert_eq!(tx.shared.changed.waiter_count(), 2);
    drop(abandoned);
    assert_eq!(tx.shared.changed.waiter_count(), 1);
    tx.try_send(&cx, 7).unwrap();
    assert!(counter.0.load(Ordering::SeqCst) > 0);
    match retained.as_mut().poll(&mut context) {
        Poll::Ready(Ok(item)) => assert_eq!(item.ack(), 7),
        _ => panic!("the remaining receiver must be notified"),
    }
}

#[test]
fn send_refusals_and_abandoned_receiver_return_the_original_payload() {
    let cx = Cx::for_testing();
    let (tx, rx) = channel(1);
    let permit = tx.try_reserve(&cx).unwrap();
    let value = Box::new(73);
    let address = std::ptr::from_ref(&*value);
    let error = tx.try_send(&cx, value).unwrap_err();
    assert_eq!(error.error, QueueError::Full);
    assert_eq!(std::ptr::from_ref(&*error.value), address);
    drop(rx);
    let error = permit.send(error.value).unwrap_err();
    assert_eq!(error.error, QueueError::Closed);
    assert_eq!(std::ptr::from_ref(&*error.value), address);
    assert_eq!(tx.stats().unfinished(), 0);
}

struct Probe {
    shared: Arc<OnceLock<Weak<Shared<Probe>>>>,
    drops: Arc<AtomicUsize>,
}
impl Drop for Probe {
    fn drop(&mut self) {
        if let Some(shared) = self.shared.get().and_then(Weak::upgrade) {
            assert!(
                shared.state.try_lock().is_some(),
                "payload retired under queue lock"
            );
        }
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}
#[test]
fn last_receiver_and_outstanding_delivery_destroy_payloads_outside_lock() {
    let cx = Cx::for_testing();
    let (tx, rx) = channel(2);
    let shared = Arc::new(OnceLock::new());
    assert!(shared.set(Arc::downgrade(&tx.shared)).is_ok());
    let drops = Arc::new(AtomicUsize::new(0));
    for _ in 0..2 {
        tx.try_send(
            &cx,
            Probe {
                shared: Arc::clone(&shared),
                drops: Arc::clone(&drops),
            },
        )
        .unwrap_or_else(|_| panic!("probe enqueue"));
    }
    let delivery = rx.try_recv_with_ack(&cx).unwrap();
    drop(rx);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(tx.stats().in_flight, 1);
    drop(delivery);
    assert_eq!(drops.load(Ordering::SeqCst), 2);
    assert_eq!(tx.stats().unfinished(), 0);
}

struct PanickingWake;
impl Wake for PanickingWake {
    fn wake(self: Arc<Self>) {
        panic!("hostile notification");
    }
}
#[test]
fn panicking_waiter_cannot_hide_published_item_or_strand_peer() {
    let cx = Cx::for_testing();
    let (tx, rx) = channel(1);
    let bad = Waker::from(Arc::new(PanickingWake));
    let (counter, good) = wake_counter();
    let mut first = Box::pin(rx.recv_with_ack(&cx));
    let mut second = Box::pin(rx.recv_with_ack(&cx));
    assert!(
        first
            .as_mut()
            .poll(&mut Context::from_waker(&bad))
            .is_pending()
    );
    assert!(
        second
            .as_mut()
            .poll(&mut Context::from_waker(&good))
            .is_pending()
    );
    tx.try_send(&cx, 19).unwrap();
    assert!(counter.0.load(Ordering::SeqCst) > 0);
    assert_eq!(rx.try_recv_with_ack(&cx).unwrap().ack(), 19);
}

#[test]
fn exhausted_sequence_refuses_without_leaking_a_slot() {
    let cx = Cx::for_testing();
    let (tx, rx) = channel::<u8>(1);
    tx.shared.state.lock().sequence = u64::MAX;
    assert!(matches!(
        tx.try_reserve(&cx),
        Err(QueueError::SequenceExhausted)
    ));
    assert_eq!(rx.stats().unfinished(), 0);
}

#[test]
fn multi_producer_multi_worker_redelivery_never_duplicates_acknowledgement() {
    let (tx, rx) = channel::<i32>(3);
    let acknowledged = Arc::new(Mutex::new(Vec::new()));
    let mut workers = Vec::new();
    for _ in 0..4 {
        let rx = rx.clone();
        let acknowledged = Arc::clone(&acknowledged);
        workers.push(std::thread::spawn(move || {
            let cx = Cx::for_testing();
            loop {
                match futures_lite::future::block_on(rx.recv_with_ack(&cx)) {
                    Ok(item) => {
                        if item.attempts() == 1 {
                            item.nack();
                        } else {
                            acknowledged.lock().push(item.ack());
                        }
                    }
                    Err(QueueError::Closed) => break,
                    Err(error) => panic!("unexpected receive error: {error}"),
                }
            }
        }));
    }
    let mut producers = Vec::new();
    for producer in 0..4 {
        let tx = tx.clone();
        producers.push(std::thread::spawn(move || {
            let cx = Cx::for_testing();
            for sequence in 0..32 {
                futures_lite::future::block_on(tx.send(&cx, producer * 32 + sequence)).unwrap();
                assert!(tx.stats().unfinished() <= 3);
            }
        }));
    }
    drop(tx);
    for producer in producers {
        producer.join().unwrap();
    }
    for worker in workers {
        worker.join().unwrap();
    }
    let mut acknowledged = acknowledged.lock();
    acknowledged.sort_unstable();
    assert_eq!(*acknowledged, (0..128).collect::<Vec<_>>());
    assert_eq!(rx.stats().unfinished(), 0);
}
