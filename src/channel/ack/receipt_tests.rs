use super::*;
use crate::types::CancelKind;
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Wake, Waker};

fn take<T>(receipt: &mut Receipt<T>) -> Settlement<T> {
    receipt.try_take().unwrap().expect("actual terminal publication")
}

#[test]
fn receipt_is_not_an_enqueue_receive_or_nack_acknowledgement() {
    let cx = Cx::for_testing();
    let (tx, rx) = channel(1);
    let mut receipt = tx.try_send_tracked(&cx, 7).unwrap();
    assert!(receipt.try_take().unwrap().is_none());
    let delivery = rx.try_recv_with_ack(&cx).unwrap();
    assert_eq!(delivery.sequence(), receipt.sequence());
    assert_eq!(delivery.deliveries(), 1);
    assert!(receipt.try_take().unwrap().is_none());
    delivery.nack();
    assert!(receipt.try_take().unwrap().is_none());
    assert_eq!(rx.try_recv_with_ack(&cx).unwrap().ack(), 7);
    let result = take(&mut receipt);
    assert_eq!((result.sequence, result.attempts, result.deliveries), (receipt.sequence(), 2, 2));
    assert!(matches!(result.outcome, SettlementOutcome::Acknowledged));
    assert_eq!(receipt.try_take().unwrap_err(), ReceiptError::Closed);
    assert_eq!(tx.stats().unfinished(), 0);
}

#[test]
fn rejection_returns_the_same_mutated_allocation_and_is_not_successful_drain() {
    let cx = Cx::for_testing();
    let (tx, rx) = channel(1);
    let value = Box::new(41);
    let address = std::ptr::from_ref(&*value);
    let mut receipt = tx.try_send_tracked(&cx, value).unwrap();
    let mut delivery = rx.try_recv_with_ack(&cx).unwrap();
    **delivery = 73;
    delivery.reject().unwrap();
    let result = take(&mut receipt);
    match result.outcome {
        SettlementOutcome::Rejected(value) => {
            assert_eq!(*value, 73);
            assert_eq!(std::ptr::from_ref(&*value), address);
        }
        other => panic!("expected explicit rejection, got {other:?}"),
    }
    assert!(tx.stats().rejected);
    assert!(!tx.stats().abandoned);
    assert_eq!(tx.stats().unfinished(), 0);
    assert_eq!(futures_lite::future::block_on(tx.close_and_drain(&cx)), Err(QueueError::Rejected));
    assert_eq!(futures_lite::future::block_on(tx.wait_drained(&cx)), Err(QueueError::Rejected));
}

#[test]
fn untracked_rejection_refuses_with_the_original_guard() {
    let cx = Cx::for_testing();
    let (tx, rx) = channel(1);
    tx.try_send(&cx, 17).unwrap();
    let delivery = rx.try_recv_with_ack(&cx).unwrap();
    let sequence = delivery.sequence();
    let delivery = delivery.reject().unwrap_err();
    assert_eq!(delivery.sequence(), sequence);
    assert_eq!(*delivery, 17);
    assert_eq!(tx.stats().in_flight, 1);
    assert!(!tx.stats().rejected);
    delivery.nack();
    assert_eq!(rx.try_recv_with_ack(&cx).unwrap().ack(), 17);
}

#[test]
fn receiver_abandonment_returns_queued_and_outstanding_payloads_separately() {
    let cx = Cx::for_testing();
    let (tx, rx) = channel(2);
    let mut first = tx.try_send_tracked(&cx, String::from("in flight")).unwrap();
    let mut second = tx.try_send_tracked(&cx, String::from("still queued")).unwrap();
    let held = rx.try_recv_with_ack(&cx).unwrap();
    drop(rx);
    let queued = take(&mut second);
    assert_eq!(queued.deliveries, 0);
    assert!(matches!(queued.outcome, SettlementOutcome::Abandoned(value) if value == "still queued"));
    assert!(first.try_take().unwrap().is_none());
    assert_eq!(tx.stats().in_flight, 1);
    drop(held);
    let held = take(&mut first);
    assert_eq!(held.deliveries, 1);
    assert!(matches!(held.outcome, SettlementOutcome::Abandoned(value) if value == "in flight"));
    assert_eq!(futures_lite::future::block_on(tx.wait_drained(&cx)), Err(QueueError::Abandoned));
}

#[test]
fn dropped_receipt_does_not_cancel_or_requeue_submitted_work() {
    let cx = Cx::for_testing();
    let (tx, rx) = channel(1);
    let receipt = tx.try_send_tracked(&cx, 29).unwrap();
    let sequence = receipt.sequence();
    drop(receipt);
    let delivery = rx.try_recv_with_ack(&cx).unwrap();
    assert_eq!((delivery.sequence(), delivery.deliveries()), (sequence, 1));
    assert_eq!(delivery.ack(), 29);
    assert_eq!(futures_lite::future::block_on(tx.close_and_drain(&cx)), Ok(()));
}

#[test]
fn cancelled_and_dropped_borrowing_waits_preserve_the_terminal_receipt() {
    let cx = Cx::for_testing();
    let observer = Cx::for_testing();
    let (tx, rx) = channel(1);
    let mut receipt = tx.try_send_tracked(&cx, 31).unwrap();
    {
        let mut wait = Box::pin(receipt.wait(&observer));
        assert!(wait.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
    }
    {
        let mut wait = Box::pin(receipt.wait(&observer));
        let mut task = Context::from_waker(Waker::noop());
        assert!(wait.as_mut().poll(&mut task).is_pending());
        observer.cancel_fast(CancelKind::User);
        assert!(matches!(wait.as_mut().poll(&mut task), Poll::Ready(Err(ReceiptError::Cancelled))));
    }
    assert_eq!(rx.try_recv_with_ack(&cx).unwrap().ack(), 31);
    let result = futures_lite::future::block_on(receipt.wait(&cx)).unwrap();
    assert!(matches!(result.outcome, SettlementOutcome::Acknowledged));
}

#[test]
fn preclose_permit_can_publish_tracked_work_and_refusal_returns_unpublished_value() {
    let cx = Cx::for_testing();
    let (tx, rx) = channel(1);
    let permit = tx.try_reserve(&cx).unwrap();
    let value = Box::new(5);
    let address = std::ptr::from_ref(&*value);
    let error = tx.try_send_tracked(&cx, value).unwrap_err();
    assert_eq!(error.error, QueueError::Full);
    assert_eq!(std::ptr::from_ref(&*error.value), address);
    tx.close();
    drop(tx);
    let mut receipt = permit.send_tracked(error.value).unwrap();
    assert_eq!(*rx.try_recv_with_ack(&cx).unwrap().ack(), 5);
    assert!(matches!(take(&mut receipt).outcome, SettlementOutcome::Acknowledged));
    assert!(matches!(rx.try_recv_with_ack(&cx), Err(QueueError::Closed)));
}

struct Reenter {
    shared: Arc<Shared<u8>>,
    wakes: Arc<AtomicUsize>,
}
impl Wake for Reenter {
    fn wake(self: Arc<Self>) {
        assert!(self.shared.state.try_lock().is_some(), "receipt callback ran under queue lock");
        assert_eq!(self.shared.stats().unfinished(), 0);
        self.wakes.fetch_add(1, Ordering::SeqCst);
        panic!("one hostile receipt wake must not undo acknowledgement");
    }
}

#[test]
fn receipt_wake_runs_after_physical_commit_and_outside_the_queue_lock() {
    let cx = Cx::for_testing();
    let (tx, rx) = channel(1);
    let mut receipt = tx.try_send_tracked(&cx, 42_u8).unwrap();
    let wakes = Arc::new(AtomicUsize::new(0));
    let waker = Waker::from(Arc::new(Reenter { shared: Arc::clone(&tx.shared), wakes: Arc::clone(&wakes) }));
    let mut wait = Box::pin(receipt.wait_uninterruptible());
    assert!(wait.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
    assert_eq!(rx.try_recv_with_ack(&cx).unwrap().ack(), 42);
    assert_eq!(wakes.load(Ordering::SeqCst), 1);
    assert!(matches!(wait.as_mut().poll(&mut Context::from_waker(&waker)), Poll::Ready(Ok(_))));
}

struct Bomb { value: u8, explode: bool }
impl Drop for Bomb {
    fn drop(&mut self) { assert!(!self.explode, "untracked payload drop sentinel"); }
}

#[test]
fn one_untracked_destructor_panic_cannot_suppress_later_abandonment_receipts() {
    let cx = Cx::for_testing();
    let (tx, rx) = channel(3);
    tx.try_send(&cx, Bomb { value: 0, explode: true }).unwrap_or_else(|_| panic!("send bomb"));
    let mut first = tx.try_send_tracked(&cx, Bomb { value: 1, explode: false }).unwrap_or_else(|_| panic!("send one"));
    let mut second = tx.try_send_tracked(&cx, Bomb { value: 2, explode: false }).unwrap_or_else(|_| panic!("send two"));
    let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(rx)));
    assert!(failure.is_err());
    for (receipt, expected) in [(&mut first, 1), (&mut second, 2)] {
        assert!(matches!(take(receipt).outcome, SettlementOutcome::Abandoned(value) if value.value == expected));
    }
    assert_eq!(tx.stats().unfinished(), 0);
    assert!(tx.stats().abandoned);
}

#[test]
fn independent_receipts_follow_identity_not_acknowledgement_order() {
    let cx = Cx::for_testing();
    let (tx, rx) = channel(3);
    let mut receipts = (0..3).map(|value| tx.try_send_tracked(&cx, value).unwrap()).collect::<Vec<_>>();
    let a = rx.try_recv_with_ack(&cx).unwrap();
    let b = rx.try_recv_with_ack(&cx).unwrap();
    let c = rx.try_recv_with_ack(&cx).unwrap();
    assert_eq!(c.ack(), 2);
    assert_eq!(a.ack(), 0);
    assert!(receipts[1].try_take().unwrap().is_none());
    b.reject().unwrap();
    for (index, receipt) in receipts.iter_mut().enumerate() {
        let result = take(receipt);
        assert_eq!(result.sequence, receipt.sequence());
        if index == 1 { assert!(matches!(result.outcome, SettlementOutcome::Rejected(1))); }
        else { assert!(matches!(result.outcome, SettlementOutcome::Acknowledged)); }
    }
}

#[test]
fn send_only_nonclone_payloads_and_debug_do_not_require_or_reveal_payload_traits() {
    struct Job(Cell<u8>);
    fn assert_send<T: Send>() {}
    assert_send::<Receipt<Job>>();
    assert_send::<Settlement<Job>>();
    let cx = Cx::for_testing();
    let (tx, rx) = channel(1);
    let mut receipt = tx.try_send_tracked(&cx, Job(Cell::new(99))).unwrap_or_else(|_| panic!("send job"));
    rx.try_recv_with_ack(&cx).unwrap().reject().unwrap();
    let result = take(&mut receipt);
    let debug = format!("{receipt:?} {result:?}");
    assert!(!debug.contains("99"));
    assert!(matches!(result.outcome, SettlementOutcome::Rejected(value) if value.0.get() == 99));
}

#[test]
fn acknowledgement_after_worker_cancellation_still_publishes_terminal_receipt() {
    let cx = Cx::for_testing();
    let (tx, rx) = channel(1);
    let mut receipt = futures_lite::future::block_on(tx.send_tracked(&cx, 83)).unwrap();
    let delivery = rx.try_recv_with_ack(&cx).unwrap();
    cx.cancel_fast(CancelKind::User);
    assert_eq!(delivery.ack(), 83);
    assert!(matches!(take(&mut receipt).outcome, SettlementOutcome::Acknowledged));
    assert_eq!(tx.stats().unfinished(), 0);
}
