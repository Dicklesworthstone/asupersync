use super::*;
use crate::channel::oneshot;
use crate::lab::{LabConfig, LabRuntime};
use crate::types::{Budget, CancelKind, CancelReason};
use std::task::{Context, Waker};

fn run_case<F, Fut>(limit: usize, factory: F)
where
    F: FnOnce(Cx) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let mut lab = LabRuntime::new(LabConfig::new(0xac_2026).max_steps(16384));
    let root = lab.state.create_root_region(Budget::INFINITE);
    let region = lab.state.region(root).unwrap();
    let mut limits = region.limits();
    limits.max_obligations = Some(limit);
    region.set_limits(limits);
    let (task, mut join) = lab
        .state
        .create_task(root, Budget::INFINITE, async move {
            factory(Cx::current().expect("registered queue owner")).await;
        })
        .unwrap();
    lab.scheduler.lock().schedule(task, 0);
    lab.run_until_idle();
    join.try_join()
        .unwrap()
        .expect("queue lifecycle completes within step bound");
    assert_eq!(lab.state.live_task_count(), 0);
    assert_eq!(lab.state.pending_obligation_count(), 0);
    assert!(lab.run_until_quiescent_with_report().lab_test_passed());
    let (tasks, wakes) = lab
        .state
        .cancel_request(root, &CancelReason::user("queue test complete"), None)
        .into_parts();
    assert!(tasks.is_empty());
    wakes.dispatch();
    lab.state.advance_region_state(root);
    assert!(lab.state.region(root).is_none());
    assert!(lab.run_until_quiescent_with_report().lab_test_passed());
}

#[test]
fn checked_send_and_ack_refusals_leave_physical_ownership_intact() {
    run_case(0, |cx| async move {
        let (tx, rx) = channel(2);
        let error = tx.try_send(&cx, Box::new(7)).unwrap_err();
        assert!(matches!(
            error.error,
            QueueError::Admission(ObligationAdmissionError::LimitReached { limit: 0, .. })
        ));
        assert_eq!(tx.stats().unfinished(), 0);
        // A deliberately untracked fixture seeds the receive-side admission test.
        let fixture = Cx::for_testing();
        tx.try_send(&fixture, error.value).unwrap();
        assert!(matches!(
            rx.try_recv_with_ack(&cx),
            Err(QueueError::Admission(
                ObligationAdmissionError::LimitReached { limit: 0, .. }
            ))
        ));
        let stats = tx.stats();
        assert_eq!((stats.queued, stats.reserved, stats.in_flight), (1, 0, 0));
        assert_eq!(*rx.try_recv_with_ack(&fixture).unwrap().ack(), 7);
    });
}

#[test]
fn ack_and_send_credits_share_the_actual_runtime_region_quota() {
    run_case(1, |cx| async move {
        let (tx, rx) = channel(2);
        let permit = tx.try_reserve(&cx).unwrap();
        assert_eq!(
            permit.obligation.as_ref().unwrap().kind(),
            ObligationKind::SendPermit
        );
        tx.try_send(&Cx::for_testing(), 13).unwrap();
        assert!(matches!(
            rx.try_recv_with_ack(&cx),
            Err(QueueError::Admission(
                ObligationAdmissionError::LimitReached { limit: 1, .. }
            ))
        ));
        drop(permit);
        let delivery = rx.try_recv_with_ack(&cx).unwrap();
        assert_eq!(
            delivery.obligation.as_ref().unwrap().kind(),
            ObligationKind::Ack
        );
        assert_eq!(delivery.obligation.as_ref().unwrap().holder(), cx.task_id());
        assert_eq!(delivery.ack(), 13);
        tx.close_and_drain(&cx).await.unwrap();
    });
}

#[test]
fn handoff_moves_liability_before_the_original_holder_exits_at_full_quota() {
    run_case(1, |cx| async move {
        let (tx, rx) = channel(1);
        tx.try_send(&cx, 51).unwrap();
        let (ready, mut context) = oneshot::channel();
        let (deliver, mut incoming) = oneshot::channel::<Delivery<u8>>();
        let mut destination = cx
            .spawn(move |destination| async move {
                ready.send_blocking(destination.clone()).unwrap();
                let delivery = incoming.recv_uninterruptible().await.unwrap();
                assert_eq!(
                    delivery.obligation.as_ref().unwrap().holder(),
                    destination.task_id()
                );
                assert_eq!(
                    delivery.obligation.as_ref().unwrap().kind(),
                    ObligationKind::Ack
                );
                assert_eq!(delivery.attempts(), 1);
                delivery.ack()
            })
            .unwrap();
        let destination_cx = context.recv_uninterruptible().await.unwrap();
        let worker_rx = rx.clone();
        let mut source = cx
            .spawn(move |source| async move {
                let delivery = worker_rx.recv_with_ack(&source).await.unwrap();
                delivery.try_transfer(&destination_cx).unwrap()
            })
            .unwrap();
        // Source terminates BEFORE destination acknowledges. The live Ack now
        // belongs to destination; no source-completion leak is acceptable.
        let delivery = source.join(&cx).await.unwrap();
        assert_eq!(tx.stats().in_flight, 1);
        deliver.send_blocking(delivery).unwrap();
        assert_eq!(destination.join(&cx).await.unwrap(), 51);
        tx.close_and_drain(&cx).await.unwrap();
    });
}

#[test]
fn refused_transfer_returns_original_guard_and_never_changes_item_credit() {
    run_case(1, |cx| async move {
        let (tx, rx) = channel(1);
        let permit = tx.try_reserve(&cx).unwrap();
        let failure = permit.try_transfer(&cx).unwrap_err();
        assert_eq!(failure.error, ObligationTransferError::SameHolder);
        assert_eq!(tx.stats().reserved, 1);
        failure.guard.send(3).unwrap();
        let delivery = rx.try_recv_with_ack(&cx).unwrap();
        let sequence = delivery.sequence();
        let failure = delivery.try_transfer(&cx).unwrap_err();
        assert_eq!(failure.error, ObligationTransferError::SameHolder);
        assert_eq!(failure.guard.sequence(), sequence);
        assert_eq!(tx.stats().in_flight, 1);
        assert_eq!(failure.guard.ack(), 3);
        tx.close_and_drain(&cx).await.unwrap();
    });
}

#[test]
fn untracked_transfer_never_fabricates_destination_tracking() {
    let cx = Cx::for_testing();
    let (tx, rx) = channel(1);
    let permit = tx.try_reserve(&cx).unwrap();
    let failure = permit.try_transfer(&cx).unwrap_err();
    assert_eq!(failure.error, ObligationTransferError::SourceNotChecked);
    failure.guard.send(17).unwrap();
    let failure = rx
        .try_recv_with_ack(&cx)
        .unwrap()
        .try_transfer(&cx)
        .unwrap_err();
    assert_eq!(failure.error, ObligationTransferError::SourceNotChecked);
    assert_eq!(failure.guard.ack(), 17);
}

#[test]
fn drain_wait_is_resumable_and_cannot_confuse_delivery_with_acknowledgement() {
    let cx = Cx::for_testing();
    let (tx, rx) = channel(1);
    let permit = tx.try_reserve(&cx).unwrap();
    let mut context = Context::from_waker(Waker::noop());
    for _ in 0..3 {
        let mut drain = Box::pin(tx.close_and_drain(&cx));
        assert!(drain.as_mut().poll(&mut context).is_pending());
        drop(drain);
        assert_eq!(tx.shared.changed.waiter_count(), 0);
    }
    permit.send(91).unwrap();
    let item = rx.try_recv_with_ack(&cx).unwrap();
    let mut drain = Box::pin(tx.wait_drained(&cx));
    assert!(drain.as_mut().poll(&mut context).is_pending());
    item.nack();
    assert!(drain.as_mut().poll(&mut context).is_pending());
    assert_eq!(rx.try_recv_with_ack(&cx).unwrap().ack(), 91);
    assert!(matches!(
        drain.as_mut().poll(&mut context),
        Poll::Ready(Ok(()))
    ));
}

#[test]
fn last_receiver_abandonment_is_not_reported_as_successful_drain() {
    for in_flight in [false, true] {
        let cx = Cx::for_testing();
        let (tx, rx) = channel(1);
        tx.try_send(&cx, 7).unwrap();
        let held = if in_flight {
            Some(rx.try_recv_with_ack(&cx).unwrap())
        } else {
            None
        };
        drop(rx);
        let mut drain = Box::pin(tx.close_and_drain(&cx));
        let mut context = Context::from_waker(Waker::noop());
        if in_flight {
            assert!(drain.as_mut().poll(&mut context).is_pending());
        }
        drop(held);
        assert!(matches!(
            drain.as_mut().poll(&mut context),
            Poll::Ready(Err(QueueError::Abandoned))
        ));
        assert!(tx.stats().abandoned);
        assert_eq!(tx.stats().unfinished(), 0);
    }
}

#[test]
fn cancelled_drain_keeps_admission_closed_and_all_unfinished_work() {
    let cx = Cx::for_testing();
    let (tx, rx) = channel(1);
    tx.try_send(&cx, 33).unwrap();
    let mut drain = Box::pin(tx.close_and_drain(&cx));
    let mut context = Context::from_waker(Waker::noop());
    assert!(drain.as_mut().poll(&mut context).is_pending());
    cx.cancel_fast(CancelKind::User);
    assert!(matches!(
        drain.as_mut().poll(&mut context),
        Poll::Ready(Err(QueueError::Cancelled))
    ));
    drop(drain);
    assert_eq!(tx.stats().queued, 1);
    assert!(tx.stats().admission_closed);
    let live = Cx::for_testing();
    assert_eq!(rx.try_recv_with_ack(&live).unwrap().ack(), 33);
    futures_lite::future::block_on(tx.wait_drained(&live)).unwrap();
}
