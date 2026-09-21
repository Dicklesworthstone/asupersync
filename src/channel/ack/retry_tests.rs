use super::*;
use crate::lab::{LabConfig, LabRuntime};
use crate::types::{Budget, CancelKind, CancelReason};
use std::num::NonZeroU64;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Wake, Waker};

fn limited(deliveries: u64) -> RetryPolicy {
    RetryPolicy::limited(NonZeroU64::new(deliveries).unwrap())
}

fn take<T>(receipt: &mut Receipt<T>) -> Settlement<T> {
    receipt.try_take().unwrap().expect("terminal receipt must be published")
}

fn run_case<F, Fut>(factory: F)
where
    F: FnOnce(Cx) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let mut lab = LabRuntime::new(LabConfig::new(0xac_3030).max_steps(16384));
    let root = lab.state.create_root_region(Budget::INFINITE);
    let region = lab.state.region(root).unwrap();
    let mut limits = region.limits();
    limits.max_obligations = Some(1);
    region.set_limits(limits);
    let (task, mut join) = lab.state.create_task(root, Budget::INFINITE, async move {
        factory(Cx::current().expect("registered receipt test owner")).await;
    }).unwrap();
    lab.scheduler.lock().schedule(task, 0);
    lab.run_until_idle();
    join.try_join().unwrap().expect("retry lifecycle completes within step bound");
    assert_eq!(lab.state.live_task_count(), 0);
    assert_eq!(lab.state.pending_obligation_count(), 0);
    assert!(lab.run_until_quiescent_with_report().lab_test_passed());
    let (tasks, wakes) = lab.state.cancel_request(root, &CancelReason::user("receipt test complete"), None).into_parts();
    assert!(tasks.is_empty());
    wakes.dispatch();
    lab.state.advance_region_state(root);
    assert!(lab.state.region(root).is_none());
    assert!(lab.run_until_quiescent_with_report().lab_test_passed());
}

#[test]
fn limit_includes_first_delivery_and_preserves_all_mutations_on_exhaustion() {
    for limit in [1, 2, 3, 8] {
        let cx = Cx::for_testing();
        let (tx, rx) = channel(1);
        let value = Box::new(0_u64);
        let address = std::ptr::from_ref(&*value);
        let mut receipt = tx.try_send_tracked_with_policy(&cx, value, limited(limit)).unwrap();
        assert_eq!(receipt.retry_policy(), limited(limit));
        for attempt in 1..=limit {
            let mut item = rx.try_recv_with_ack(&cx).unwrap();
            assert_eq!((item.attempts(), item.deliveries()), (attempt, attempt));
            assert_eq!(item.sequence(), receipt.sequence());
            assert_eq!(item.retry_policy(), limited(limit));
            **item += 1;
            assert_eq!(tx.stats().unfinished(), 1);
            if attempt % 2 == 0 { item.nack(); }
            else { drop(item); }
            if attempt != limit {
                assert_eq!(tx.stats().queued, 1);
                assert!(receipt.try_take().unwrap().is_none());
            }
        }
        let result = take(&mut receipt);
        assert_eq!((result.attempts, result.deliveries), (limit, limit));
        match result.outcome {
            SettlementOutcome::RetryExhausted(value) => {
                assert_eq!(*value, limit);
                assert_eq!(std::ptr::from_ref(&*value), address);
            }
            other => panic!("expected returned exhausted payload, got {other:?}"),
        }
        assert_eq!(tx.stats().unfinished(), 0);
        assert!(tx.stats().rejected);
        assert!(!tx.stats().abandoned);
        assert_eq!(futures_lite::future::block_on(tx.close_and_drain(&cx)), Err(QueueError::Rejected));
    }
}

#[test]
fn acknowledgement_on_the_last_allowed_delivery_is_still_success() {
    for limit in 1..=4 {
        let cx = Cx::for_testing();
        let (tx, rx) = channel(1);
        let mut receipt = tx.try_send_tracked_with_policy(&cx, 41, limited(limit)).unwrap();
        for _ in 1..limit { rx.try_recv_with_ack(&cx).unwrap().nack(); }
        assert_eq!(rx.try_recv_with_ack(&cx).unwrap().ack(), 41);
        let result = take(&mut receipt);
        assert_eq!(result.deliveries, limit);
        assert!(matches!(result.outcome, SettlementOutcome::Acknowledged));
        assert!(!tx.stats().rejected);
        assert_eq!(futures_lite::future::block_on(tx.close_and_drain(&cx)), Ok(()));
    }
}

#[test]
fn checked_admission_refusals_do_not_spend_the_worker_delivery_allowance() {
    run_case(|cx| async move {
        let (blocker, _keeper) = channel::<()>(1);
        let held_quota = blocker.try_reserve(&cx).unwrap();
        let (tx, rx) = channel(1);
        let mut receipt = tx.try_send_tracked_with_policy(&Cx::for_testing(), 17, limited(1)).unwrap();
        for _ in 0..16 {
            assert!(matches!(rx.try_recv_with_ack(&cx),
                Err(QueueError::Admission(ObligationAdmissionError::LimitReached { limit: 1, .. }))));
            assert_eq!((tx.stats().queued, tx.stats().in_flight), (1, 0));
            assert!(!tx.stats().rejected);
            assert!(receipt.try_take().unwrap().is_none());
        }
        drop(held_quota);
        let delivery = rx.try_recv_with_ack(&cx).unwrap();
        assert_eq!((delivery.attempts(), delivery.deliveries()), (17, 1));
        assert_eq!(delivery.obligation.as_ref().unwrap().kind(), ObligationKind::Ack);
        drop(delivery);
        let result = receipt.wait(&cx).await.unwrap();
        assert_eq!((result.attempts, result.deliveries), (17, 1));
        assert!(matches!(result.outcome, SettlementOutcome::RetryExhausted(17)));
        assert_eq!(tx.close_and_drain(&cx).await, Err(QueueError::Rejected));
    });
}

#[test]
fn cancelled_receiver_never_spends_the_first_delivery() {
    let live = Cx::for_testing();
    let cancelled = Cx::for_testing();
    let (tx, rx) = channel(1);
    let mut receipt = tx.try_send_tracked_with_policy(&live, 23, limited(1)).unwrap();
    cancelled.cancel_fast(CancelKind::User);
    assert!(matches!(rx.try_recv_with_ack(&cancelled), Err(QueueError::Cancelled)));
    assert!(receipt.try_take().unwrap().is_none());
    let delivery = rx.try_recv_with_ack(&live).unwrap();
    assert_eq!((delivery.attempts(), delivery.deliveries()), (1, 1));
    assert_eq!(delivery.ack(), 23);
    assert!(matches!(take(&mut receipt).outcome, SettlementOutcome::Acknowledged));
}

#[test]
fn ordinary_tracked_and_untracked_sends_keep_unlimited_retries() {
    let cx = Cx::for_testing();
    let (tx, rx) = channel(2);
    tx.try_send(&cx, 5).unwrap();
    let mut receipt = tx.try_send_tracked(&cx, 7).unwrap();
    assert_eq!(receipt.retry_policy().max_deliveries(), None);
    for _ in 0..32 {
        let item = rx.try_recv_with_ack(&cx).unwrap();
        assert_eq!(item.retry_policy(), RetryPolicy::unlimited());
        item.nack();
    }
    assert!(receipt.try_take().unwrap().is_none());
    assert_eq!(rx.try_recv_with_ack(&cx).unwrap().ack(), 5);
    assert_eq!(rx.try_recv_with_ack(&cx).unwrap().ack(), 7);
    assert_eq!(take(&mut receipt).deliveries, 17);
    assert_eq!(futures_lite::future::block_on(tx.close_and_drain(&cx)), Ok(()));
}

#[test]
fn poisoned_item_returns_to_tail_then_leaves_without_suppressing_healthy_work() {
    let cx = Cx::for_testing();
    let (tx, rx) = channel(2);
    let mut poison = tx.try_send_tracked_with_policy(&cx, "bad", limited(2)).unwrap();
    let mut healthy = tx.try_send_tracked(&cx, "good").unwrap();
    let bad = rx.try_recv_with_ack(&cx).unwrap();
    assert_eq!(*bad, "bad");
    bad.nack();
    assert_eq!(rx.try_recv_with_ack(&cx).unwrap().ack(), "good");
    assert!(matches!(take(&mut healthy).outcome, SettlementOutcome::Acknowledged));
    rx.try_recv_with_ack(&cx).unwrap().nack();
    assert!(matches!(take(&mut poison).outcome, SettlementOutcome::RetryExhausted("bad")));
    tx.try_send(&cx, "next").unwrap();
    assert_eq!(rx.try_recv_with_ack(&cx).unwrap().ack(), "next");
    assert!(tx.stats().rejected, "later successes cannot erase rejected work");
}

#[test]
fn receiver_abandonment_wins_over_the_retry_limit_but_explicit_ack_is_not_revoked() {
    for acknowledge in [false, true] {
        let cx = Cx::for_testing();
        let (tx, rx) = channel(1);
        let mut receipt = tx.try_send_tracked_with_policy(&cx, 31, limited(1)).unwrap();
        let item = rx.try_recv_with_ack(&cx).unwrap();
        drop(rx);
        if acknowledge { assert_eq!(item.ack(), 31); }
        else { drop(item); }
        let result = take(&mut receipt);
        if acknowledge {
            assert!(matches!(result.outcome, SettlementOutcome::Acknowledged));
            assert!(!tx.stats().abandoned);
        } else {
            assert!(matches!(result.outcome, SettlementOutcome::Abandoned(31)));
            assert!(tx.stats().abandoned);
        }
        assert!(!tx.stats().rejected);
    }
}

struct Retire { drops: Arc<AtomicUsize> }
impl Drop for Retire {
    fn drop(&mut self) { self.drops.fetch_add(1, Ordering::SeqCst); }
}

#[test]
fn relinquished_receipt_does_not_disable_exhaustion_or_retain_the_payload() {
    let cx = Cx::for_testing();
    let (tx, rx) = channel(1);
    let drops = Arc::new(AtomicUsize::new(0));
    let receipt = tx.try_send_tracked_with_policy(&cx, Retire { drops: Arc::clone(&drops) }, limited(1))
        .unwrap_or_else(|_| panic!("admit tracked payload"));
    drop(receipt);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    drop(rx.try_recv_with_ack(&cx).unwrap());
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(tx.stats().unfinished(), 0);
    assert!(tx.stats().rejected);
}

#[test]
fn maximum_delivery_limit_never_wraps_into_a_fresh_allowance() {
    let cx = Cx::for_testing();
    let (tx, rx) = channel(1);
    let mut receipt = tx.try_send_tracked_with_policy(&cx, 47, limited(u64::MAX)).unwrap();
    {
        let mut state = tx.shared.state.lock();
        let item = state.ready.front_mut().unwrap();
        item.attempts = u64::MAX;
        item.deliveries = u64::MAX - 1;
    }
    let item = rx.try_recv_with_ack(&cx).unwrap();
    assert_eq!((item.attempts(), item.deliveries()), (u64::MAX, u64::MAX));
    drop(item);
    let result = take(&mut receipt);
    assert_eq!((result.attempts, result.deliveries), (u64::MAX, u64::MAX));
    assert!(matches!(result.outcome, SettlementOutcome::RetryExhausted(47)));
}

#[test]
fn sealed_preissued_permit_keeps_its_policy_and_eof_waits_for_exhaustion() {
    let cx = Cx::for_testing();
    let (tx, rx) = channel(1);
    let permit = tx.try_reserve(&cx).unwrap();
    tx.close();
    drop(tx);
    let mut receipt = permit.send_tracked_with_policy(53, limited(1)).unwrap();
    let item = rx.try_recv_with_ack(&cx).unwrap();
    assert!(matches!(rx.try_recv_with_ack(&cx), Err(QueueError::Empty)));
    assert!(receipt.try_take().unwrap().is_none());
    drop(item);
    assert!(matches!(rx.try_recv_with_ack(&cx), Err(QueueError::Closed)));
    assert!(matches!(take(&mut receipt).outcome, SettlementOutcome::RetryExhausted(53)));
}

#[derive(Default)]
struct Counter(AtomicUsize);
impl Wake for Counter {
    fn wake(self: Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
}

#[test]
fn exhausted_delivery_wakes_a_producer_blocked_by_unacknowledged_capacity() {
    let cx = Cx::for_testing();
    let (tx, rx) = channel(1);
    let mut receipt = tx.try_send_tracked_with_policy(&cx, 59, limited(1)).unwrap();
    let item = rx.try_recv_with_ack(&cx).unwrap();
    let counter = Arc::new(Counter::default());
    let waker = Waker::from(Arc::clone(&counter));
    let mut pending = Box::pin(tx.reserve(&cx));
    assert!(pending.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
    drop(item);
    assert!(counter.0.load(Ordering::SeqCst) > 0);
    let permit = match pending.as_mut().poll(&mut Context::from_waker(&waker)) {
        Poll::Ready(Ok(permit)) => permit,
        other => panic!("released item credit must be reservable: {other:?}"),
    };
    drop(pending);
    permit.send(61).unwrap();
    assert_eq!(rx.try_recv_with_ack(&cx).unwrap().ack(), 61);
    assert!(matches!(take(&mut receipt).outcome, SettlementOutcome::RetryExhausted(59)));
    assert_eq!(tx.shared.changed.waiter_count(), 0);
}

#[test]
fn checked_handoff_preserves_retry_allowance_and_receipt_after_source_task_exit() {
    run_case(|cx| async move {
        let (tx, rx) = channel(1);
        let mut receipt = tx.try_send_tracked_with_policy(&cx, 67_u8, limited(1)).unwrap();
        let (ready, mut context) = oneshot::channel();
        let (deliver, mut incoming) = oneshot::channel::<Delivery<u8>>();
        let mut destination = cx.spawn(move |destination| async move {
            ready.send_blocking(destination.clone()).unwrap();
            let item = incoming.recv_uninterruptible().await.unwrap();
            assert_eq!(item.obligation.as_ref().unwrap().holder(), destination.task_id());
            assert_eq!(item.retry_policy(), limited(1));
            assert_eq!(item.deliveries(), 1);
            item.nack();
        }).unwrap();
        let destination_cx = context.recv_uninterruptible().await.unwrap();
        let worker_rx = rx.clone();
        let mut source = cx.spawn(move |source| async move {
            worker_rx.recv_with_ack(&source).await.unwrap().try_transfer(&destination_cx).unwrap()
        }).unwrap();
        let item = source.join(&cx).await.unwrap();
        assert_eq!(item.sequence(), receipt.sequence());
        assert!(receipt.try_take().unwrap().is_none());
        deliver.send_blocking(item).unwrap();
        destination.join(&cx).await.unwrap();
        let result = receipt.wait(&cx).await.unwrap();
        assert_eq!((result.sequence, result.deliveries), (receipt.sequence(), 1));
        assert!(matches!(result.outcome, SettlementOutcome::RetryExhausted(67)));
        assert_eq!(tx.close_and_drain(&cx).await, Err(QueueError::Rejected));
    });
}
