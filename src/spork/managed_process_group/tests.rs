//! Live group admission, cancellation and task-lifetime journeys under Lab.

use super::*;
use crate::lab::{LabConfig, LabRuntime};
use crate::spork::process_group::GroupEventKind;
use crate::types::Budget;
use std::cell::Cell;
use std::marker::PhantomPinned;
use std::task::Wake;

fn run_case<F, Fut>(seed: u64, factory: F)
where
    F: FnOnce(Cx) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    crate::test_utils::init_test_logging();
    let mut lab = LabRuntime::new(LabConfig::new(seed).max_steps(200_000));
    let root = lab.state.create_root_region(Budget::INFINITE);
    let (task, mut join) = lab.state.create_task(root, Budget::INFINITE, async move {
        factory(Cx::current().expect("registered group test parent")).await;
    }).unwrap();
    lab.scheduler.lock().schedule(task, 0);
    lab.run_until_idle();
    assert!(join.try_join().unwrap().is_some(), "public group journey must finish");
    assert_eq!(lab.state.live_task_count(), 0);
    assert_eq!(lab.state.pending_obligation_count(), 0);
    assert_eq!(lab.state.leak_count(), 0);
    let gateway = lab.state.obligation_gateway().unwrap();
    let mailbox = gateway.mailbox();
    assert_eq!(mailbox.stats().leaked, 0);
    assert_eq!(mailbox.open_tickets(), 0);
    if lab.state.region(root).is_some() {
        let (tasks, wakes) = lab.state.cancel_request(root, &CancelReason::user("group test complete"), None).into_parts();
        assert!(tasks.is_empty());
        wakes.dispatch();
        lab.state.advance_region_state(root);
    }
    assert!(lab.state.region(root).is_none());
    assert!(lab.run_until_quiescent_with_report().lab_test_passed());
}

fn config(members: usize, requests: usize) -> ManagedProcessGroupConfig {
    ManagedProcessGroupConfig::new(members, 1, requests, 4)
}

async fn owner<M: Send + 'static>(cx: &Cx, config: ManagedProcessGroupConfig) -> ManagedProcessGroup<M> {
    ManagedProcessGroup::open(cx, GroupName::new("workers").unwrap(), NodeId::new("local"), config).await.unwrap()
}

fn report(exit: ManagedProcessGroupExit) -> ManagedGroupReport {
    let report = exit.task_outcome.expect("controller published its real result");
    assert_eq!(report.settlement_failures, 0);
    assert!(report.state_error.is_none());
    let close = exit.close.expect("actual group region reached finalizer barrier");
    assert!(close.cleanup_outcome.is_none());
    assert!(close.descendant_panic.is_none());
    report
}

#[test]
fn membership_payloads_need_send_but_not_clone_sync_or_unpin() {
    struct Message { _value: Cell<u8>, _pin: PhantomPinned }
    fn send<T: Send>() {}
    fn send_sync<T: Send + Sync>() {}
    send::<ManagedProcessGroup<Message>>();
    send::<ManagedGroupMembership<Message>>();
    send_sync::<ProcessGroupClient<Message>>();
}

#[test]
fn invalid_config_and_detached_context_fail_before_readiness() {
    let cx = Cx::for_testing();
    for (limits, expected_config) in [
        (ManagedProcessGroupConfig::new(1, 0, 1, 1), true),
        (ManagedProcessGroupConfig::new(1, 1, 0, 1), true),
        (ManagedProcessGroupConfig::new(1, 1, 1, 0), true),
        (config(1, 1), false),
    ] {
        let mut opening = Box::pin(ManagedProcessGroup::<()>::open(
            &cx, GroupName::new("workers").unwrap(), NodeId::new("local"), limits,
        ));
        let result = opening.as_mut().poll(&mut Context::from_waker(Waker::noop()));
        if expected_config { assert!(matches!(result, Poll::Ready(Err(ManagedGroupError::InvalidConfig)))); }
        else { assert!(matches!(result, Poll::Ready(Err(ManagedGroupError::RuntimeRequired)))); }
    }
}

#[test]
fn abandoned_join_is_withdrawn_before_its_credit_is_reused() {
    for published in [false, true] {
        run_case(0x6700_0001 + u64::from(published), move |cx| async move {
            let owner = owner::<()>(&cx, config(1, 2)).await;
            let client = owner.client();
            let mut opening = Box::pin(client.join(&cx));
            poll_fn(|task| {
                assert!(opening.as_mut().poll(task).is_pending());
                Poll::Ready(())
            }).await;
            let mut cursor = GroupEventCursor::new();
            if published {
                let joined = client.next_events(&cx, cursor).await.unwrap();
                assert_eq!(joined.batch.len(), 1);
                assert!(matches!(joined.batch.events()[0].kind(), GroupEventKind::Joined));
                cursor = joined.batch.next_cursor();
                assert_eq!(client.members(&cx).unwrap().len(), 1);
                assert_eq!(client.outstanding_requests(), 1, "unclaimed success retains credit");
            }
            drop(opening);
            if published {
                let departed = client.next_events(&cx, cursor).await.unwrap();
                assert!(matches!(departed.batch.events()[0].kind(), GroupEventKind::Left));
            } else {
                // A new admission uses the other bounded request slot. FIFO
                // controller processing must discard the abandoned request.
                let mut member = client.join(&cx).await.unwrap();
                assert_eq!(member.generation(), 0);
                member.leave(&cx).await.unwrap();
            }
            assert!(client.members(&cx).unwrap().is_empty());
            assert_eq!(client.outstanding_requests(), 0);
            let report = report(owner.shutdown().await);
            assert_eq!(report.joined, 1);
            assert_eq!(report.left, 1);
        });
    }
}

#[test]
fn full_waiting_broadcast_does_not_block_out_of_band_leave() {
    run_case(0x6700_0003, |cx| async move {
        let owner = owner::<u32>(&cx, config(1, 1)).await;
        let client = owner.client();
        let mut member = client.join(&cx).await.unwrap();
        assert!(client.broadcast(&cx, &7, BroadcastBackpressurePolicy::Wait).await.unwrap().is_all_delivered());
        let mut waiting = Box::pin(client.broadcast(&cx, &8, BroadcastBackpressurePolicy::Wait));
        poll_fn(|task| {
            assert!(waiting.as_mut().poll(task).is_pending(), "mailbox is truly full and reserve is parked");
            Poll::Ready(())
        }).await;
        assert_eq!(client.outstanding_requests(), 1);
        assert!(matches!(client.join(&cx).await, Err(ManagedGroupError::Busy)));
        let left = member.leave(&cx).await.unwrap();
        assert!(matches!(left.kind(), GroupEventKind::Left));
        let delivery = waiting.await.unwrap();
        assert_eq!(delivery.recipients[0].status, ManagedGroupRecipientStatus::Departed);
        assert_eq!(client.outstanding_requests(), 0);
        assert!(matches!(member.recv(&cx).await, Err(ManagedGroupRecvError::Departed(_))));
        let report = report(owner.shutdown().await);
        assert_eq!((report.joined, report.left, report.down), (1, 1, 0));
    });
}

#[test]
fn task_down_wakes_all_members_beyond_one_scan_quantum() {
    for seed in [0x6700_0065, 0x6700_0066] {
        run_case(seed, |cx| async move {
            const COUNT: usize = SCAN_QUANTUM + 2;
            let owner = owner::<()>(&cx, ManagedProcessGroupConfig::new(COUNT, 1, 4, COUNT * 3)).await;
            let client = owner.client();
            let mut tasks = Vec::new();
            let mut guards = Vec::new();
            for _ in 0..COUNT {
                let client = client.clone();
                let (sender, mut receiver) = mpsc::channel(1);
                tasks.push(cx.spawn(move |cx| async move {
                    let member = client.join(&cx).await.unwrap();
                    sender.send(&cx, member).await.unwrap();
                    cx.cancelled().await;
                    let _ = cx.checkpoint();
                }).unwrap());
                // Keep the actual task's guard elsewhere, so its own stack
                // retirement cannot turn this into a guard-Drop leave test.
                guards.push(receiver.recv(&cx).await.unwrap());
            }
            assert_eq!(client.members(&cx).unwrap().len(), COUNT);
            let mut cursor = client.events(&cx, GroupEventCursor::new()).unwrap().batch.next_cursor();
            tasks[0].abort();
            tasks[COUNT - 1].abort();
            let mut down = Vec::new();
            while down.len() < 2 {
                let batch = client.next_events(&cx, cursor).await.unwrap();
                cursor = batch.batch.next_cursor();
                for event in batch.batch.events() {
                    if matches!(event.kind(), GroupEventKind::Down(_)) { down.push(event.member().clone()); }
                }
            }
            assert!(down.contains(guards[0].id()));
            assert!(down.contains(guards[COUNT - 1].id()));
            assert!(!guards[0].is_active());
            assert!(!guards[COUNT - 1].is_active());
            assert_eq!(client.members(&cx).unwrap().len(), COUNT - 2);
            let report = report(owner.shutdown().await);
            assert_eq!(report.joined, COUNT as u64);
            assert_eq!(report.down, COUNT as u64);
            for task in &tasks { task.abort(); }
            for mut task in tasks {
                assert!(matches!(task.join(&cx).await, Ok(()) | Err(JoinError::Cancelled(_))));
            }
            assert!(guards.iter().all(|guard| !guard.is_active()));
        });
    }
}

#[derive(Debug)]
struct PanicClone { armed: Arc<AtomicBool> }
impl Clone for PanicClone {
    fn clone(&self) -> Self {
        assert!(!self.armed.swap(false, Ordering::AcqRel), "intentional message clone panic");
        Self { armed: Arc::clone(&self.armed) }
    }
}

#[test]
fn a_panicking_message_clone_returns_checked_capacity_before_next_broadcast() {
    run_case(0x6700_0007, |cx| async move {
        let owner = owner::<PanicClone>(&cx, config(1, 2)).await;
        let client = owner.client();
        let mut member = client.join(&cx).await.unwrap();
        let value = PanicClone { armed: Arc::new(AtomicBool::new(true)) };
        let mut sending = Box::pin(client.broadcast(&cx, &value, BroadcastBackpressurePolicy::Skip));
        let panic = catch_unwind(AssertUnwindSafe(|| {
            sending.as_mut().poll(&mut Context::from_waker(Waker::noop()))
        }));
        assert!(panic.is_err());
        drop(sending);
        assert_eq!(client.outstanding_requests(), 0);
        assert!(client.broadcast(&cx, &value, BroadcastBackpressurePolicy::Error).await.unwrap().is_all_delivered());
        member.recv(&cx).await.unwrap();
        member.leave(&cx).await.unwrap();
        report(owner.shutdown().await);
    });
}

#[test]
fn event_retention_reports_the_exact_gap_and_never_grows_under_churn() {
    run_case(0x6700_0008, |cx| async move {
        let owner = owner::<()>(&cx, ManagedProcessGroupConfig::new(1, 1, 2, 3)).await;
        let client = owner.client();
        for generation in 0..10 {
            let mut member = client.join(&cx).await.unwrap();
            assert_eq!(member.generation(), generation);
            member.leave(&cx).await.unwrap();
        }
        let events = client.events(&cx, GroupEventCursor::new()).unwrap();
        assert_eq!(events.skipped, 17);
        assert_eq!(events.first_retained.next_sequence(), 17);
        assert_eq!(events.batch.len(), 3);
        assert_eq!(events.batch.next_cursor().next_sequence(), 20);
        assert_eq!(client.shared.state.lock().events.len(), 3);
        let report = report(owner.shutdown().await);
        assert_eq!((report.joined, report.left), (10, 10));
        assert!(client.events(&cx, GroupEventCursor::from_next_sequence(20)).unwrap().closed);
    });
}

#[test]
fn callbacks_contain_panicking_waker_and_panic_payload_destructors() {
    struct Payload;
    impl Drop for Payload { fn drop(&mut self) { panic!("hostile panic payload destructor"); } }
    struct HostileWake;
    impl Wake for HostileWake { fn wake(self: Arc<Self>) { std::panic::panic_any(Payload); } }
    impl Drop for HostileWake { fn drop(&mut self) { panic!("hostile retained waker destructor"); } }

    // Test the two paths separately: a panicking wake does not also own the
    // final hostile Waker Arc, so its payload containment is directly witnessed.
    let handle = Arc::new(HostileWake);
    let waker = Waker::from(Arc::clone(&handle));
    let slot = WakeSlot::default();
    slot.register(&waker);
    slot.notify();
    drop(slot);
    drop(waker);
    callback(|| drop(handle));
    let retained = WakeSlot::default();
    let last = Waker::from(Arc::new(HostileWake));
    retained.register(&last);
    drop(last);
    drop(retained); // The slot contains the final hostile Waker Arc.
    callback(|| std::panic::panic_any(Payload));
}
