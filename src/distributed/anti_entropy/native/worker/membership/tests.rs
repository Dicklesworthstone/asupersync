use super::*;
use super::super::{Shared, State, SymbolRepairWorkerSnapshot, SymbolRepairWorkerStatus};
use crate::distributed::membership::authority::{
    MembershipApplied, MembershipControlError, MembershipControllerLimits, MembershipFloor,
};
use crate::runtime::RuntimeBuilder;
use crate::security::{AuthKey, AuthenticationTag};
use crate::sync::Notify;
use crate::types::{Budget, RegionId, TaskId};
use parking_lot::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::task::{Wake, Waker};
use std::time::Duration;

fn controller() -> OwnedMembershipController {
    OwnedMembershipController::new(
        NodeId::new("authority"), 7, AuthKey::from_seed(42),
        ["source", "other"].map(|node| MembershipFloor {
            node: NodeId::new(node), incarnation: 0, sequence: 0,
        }).to_vec(),
        MembershipControllerLimits { max_members: 2, max_lease_ids: 8 },
        TimerDriverHandle::with_virtual_clock(Arc::new(crate::time::VirtualClock::new())),
    ).unwrap()
}

// Independent wire construction, not MembershipUpdate::authenticated_bytes:
// magic/version, bounded labels, epoch/incarnation/sequence, kind, domain MAC.
fn wire(node: &str, incarnation: u64, sequence: u64, kind: u8) -> Vec<u8> {
    let mut bytes = b"ASUPMBR\0".to_vec();
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.push(9);
    bytes.extend_from_slice(b"authority");
    bytes.extend_from_slice(&7u64.to_le_bytes());
    bytes.push(u8::try_from(node.len()).unwrap());
    bytes.extend_from_slice(node.as_bytes());
    bytes.extend_from_slice(&incarnation.to_le_bytes());
    bytes.extend_from_slice(&sequence.to_le_bytes());
    bytes.push(kind);
    let tag = AuthenticationTag::compute_for_domain_payload(
        &AuthKey::from_seed(42), b"asupersync.membership-authority.v1", &bytes,
    );
    bytes.extend_from_slice(tag.as_bytes());
    bytes
}

fn apply(controller: &OwnedMembershipController, incarnation: u64, sequence: u64, kind: u8) {
    assert!(matches!(
        controller.apply_authenticated(&NodeId::new("authority"), &wire("source", incarnation, sequence, kind)),
        Ok(MembershipApplied::Applied { revoked: 0 }),
    ));
}

fn handle() -> SymbolRepairWorkerHandle {
    SymbolRepairWorkerHandle {
        shared: Arc::new(Shared {
            state: Mutex::new(State {
                snapshot: SymbolRepairWorkerSnapshot {
                    status: SymbolRepairWorkerStatus::Prepared,
                    pending: false, rounds_started: 0, rounds_finished: 0,
                    successful_rounds: 0, last_round: None,
                },
                stop: false,
            }),
            changed: Notify::new(),
        }),
    }
}

fn bridge(controller: &OwnedMembershipController, worker: &SymbolRepairWorkerHandle) -> SymbolRepairMembership {
    let observer = controller.observe_member(&NodeId::new("source")).unwrap();
    SymbolRepairMembership {
        baseline: observer.snapshot(), observer, worker: worker.clone(),
        initial_repair: false, scheduled: 0, coalesced: 0, last_trigger: None,
    }
}

fn step<F: Future>(mut future: Pin<&mut F>, task: &mut Context<'_>) {
    // The bridge deliberately yields after each changed observation. Extra
    // manual polls here do not manufacture a wake or a production transition.
    for _ in 0..3 { assert!(future.as_mut().poll(task).is_pending()); }
}

#[derive(Default)]
struct WakeCount(AtomicUsize);
impl Wake for WakeCount {
    fn wake(self: Arc<Self>) { self.wake_by_ref(); }
    fn wake_by_ref(self: &Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
}

#[test]
fn authenticated_bursts_trigger_once_and_rejected_replays_never_add_hints() {
    let membership = controller();
    apply(&membership, 1, 1, 0);
    let worker = handle();
    let trigger = bridge(&membership, &worker);
    let owner = Cx::for_testing();
    let mut run = Box::pin(trigger.run(&owner));
    let mut task = Context::from_waker(Waker::noop());
    step(run.as_mut(), &mut task);
    assert!(!worker.snapshot().pending);

    // Both changes occur before another bridge poll.
    apply(&membership, 1, 2, 1);
    apply(&membership, 1, 3, 0);
    step(run.as_mut(), &mut task);
    assert!(worker.snapshot().pending);
    assert_eq!(membership.observe_member(&NodeId::new("source")).unwrap()
        .snapshot().last_alive_transition.unwrap().sequence, 3);

    assert_eq!(membership.apply_authenticated(&NodeId::new("authority"), &wire("source", 1, 3, 0)).unwrap(),
        MembershipApplied::Duplicate);
    apply(&membership, 1, 4, 0); // Alive heartbeat, not a recovery.
    membership.apply_authenticated(&NodeId::new("authority"), &wire("other", 1, 1, 0)).unwrap();
    let mut forged = wire("source", 2, 5, 0);
    *forged.last_mut().unwrap() ^= 1;
    assert!(matches!(membership.apply_authenticated(&NodeId::new("authority"), &forged),
        Err(OwnedMembershipError::Control(MembershipControlError::Authentication))));
    assert!(matches!(membership.apply_authenticated(&NodeId::new("intruder"), &wire("source", 2, 5, 0)),
        Err(OwnedMembershipError::Control(MembershipControlError::Authority))));
    assert!(matches!(membership.apply_authenticated(&NodeId::new("authority"), &wire("source", 1, 2, 1)),
        Err(OwnedMembershipError::Control(MembershipControlError::Stale))));
    step(run.as_mut(), &mut task);

    // New incarnation while an earlier request is pending uses the existing
    // worker's one-slot coalescing path, never another queue.
    apply(&membership, 2, 5, 0);
    step(run.as_mut(), &mut task);
    worker.stop();
    let Poll::Ready(report) = run.as_mut().poll(&mut task) else { panic!("stop must wake the trigger"); };
    assert_eq!(report.stop, SymbolRepairMembershipStop::WorkerClosed);
    assert_eq!((report.scheduled, report.coalesced), (1, 1));
    assert_eq!(report.last_trigger.unwrap(), MembershipStamp {
        incarnation: 2, sequence: 5, kind: MembershipKind::Alive,
    });
    assert_eq!(worker.snapshot().status, SymbolRepairWorkerStatus::Stopping);
    drop(run);
    assert!(owner.inner.read().cancel_waker_registrations.is_empty());
}

#[test]
fn initial_policy_and_transitions_before_first_poll_preserve_the_constructor_boundary() {
    for initial in [false, true] {
        let membership = controller();
        apply(&membership, 1, 1, 0);
        let worker = handle();
        let owner = Cx::for_testing();
        let mut run = Box::pin(bridge(&membership, &worker).with_initial_repair(initial).run(&owner));
        let mut task = Context::from_waker(Waker::noop());
        step(run.as_mut(), &mut task);
        assert_eq!(worker.snapshot().pending, initial);
        worker.stop();
        let Poll::Ready(report) = run.as_mut().poll(&mut task) else { panic!("stopping"); };
        assert_eq!(report.scheduled, u64::from(initial));
        assert_eq!(report.coalesced, 0);
    }

    let membership = controller();
    let worker = handle();
    let trigger = bridge(&membership, &worker);
    // The first authenticated admission after construction is new work, even
    // when it arrives before the trigger's first poll.
    apply(&membership, 1, 1, 0);
    let owner = Cx::for_testing();
    let mut run = Box::pin(trigger.run(&owner));
    let mut task = Context::from_waker(Waker::noop());
    step(run.as_mut(), &mut task);
    assert!(worker.snapshot().pending);
    worker.stop();
    let Poll::Ready(report) = run.as_mut().poll(&mut task) else { panic!("stopping"); };
    assert_eq!((report.scheduled, report.coalesced), (1, 0));
}

#[test]
fn terminal_membership_and_controller_close_cannot_publish_stale_recovery() {
    let membership = controller();
    assert!(matches!(membership.observe_member(&NodeId::new("unprovisioned")),
        Err(OwnedMembershipError::Control(MembershipControlError::UnknownMember))));
    apply(&membership, 1, 1, 0);
    let worker = handle();
    let trigger = bridge(&membership, &worker);
    apply(&membership, 1, 2, 2);
    assert!(matches!(membership.apply_authenticated(&NodeId::new("authority"), &wire("source", 1, 3, 0)),
        Err(OwnedMembershipError::Control(MembershipControlError::Terminal))));
    apply(&membership, 2, 3, 0);
    membership.close();
    let owner = Cx::for_testing();
    let mut run = Box::pin(trigger.run(&owner));
    let Poll::Ready(report) = run.as_mut().poll(&mut Context::from_waker(Waker::noop())) else {
        panic!("closed controller must refuse before a hint");
    };
    assert_eq!(report.stop, SymbolRepairMembershipStop::ControllerClosed);
    assert_eq!((report.scheduled, report.coalesced), (0, 0));
    assert!(!worker.snapshot().pending);
    assert_eq!(worker.snapshot().status, SymbolRepairWorkerStatus::Prepared);
}

#[test]
fn dropped_bridge_releases_both_notify_waits_and_cancellation_registrations() {
    let membership = controller();
    apply(&membership, 1, 1, 0);
    let worker = handle();
    let owner = Cx::for_testing();
    let counter = Arc::new(WakeCount::default());
    let waker = Waker::from(counter.clone());
    let mut task = Context::from_waker(&waker);
    let mut run = Box::pin(bridge(&membership, &worker).run(&owner));
    assert!(run.as_mut().poll(&mut task).is_pending());
    assert_eq!(worker.shared.changed.waiter_count(), 1);
    assert!(Arc::strong_count(&counter) > 2, "the parked waits retain the task waker");
    drop(run);
    assert_eq!(worker.shared.changed.waiter_count(), 0);
    assert!(owner.inner.read().cancel_waker_registrations.is_empty());
    assert_eq!(Arc::strong_count(&counter), 2, "membership/worker/cancellation waits all release the waker");
    assert!(!membership.observe_member(&NodeId::new("source")).unwrap().snapshot().closed);
    assert_eq!(worker.snapshot().status, SymbolRepairWorkerStatus::Prepared);
}

#[test]
fn a_new_polling_context_cannot_resume_a_parked_bridge_after_cancellation() {
    let membership = controller();
    let worker = handle();
    let owner = Cx::for_testing();
    let first = Cx::for_testing();
    let later = Cx::for_testing();
    let reason = CancelReason::user("new polling task stopped");
    let mut run = Box::pin(bridge(&membership, &worker).run(&owner));
    let mut task = Context::from_waker(Waker::noop());
    {
        let _ambient = Cx::set_current(Some(first.clone()));
        assert!(run.as_mut().poll(&mut task).is_pending());
    }
    later.cancel_with_reason(reason.clone());
    {
        let _ambient = Cx::set_current(Some(later.clone()));
        let Poll::Ready(report) = run.as_mut().poll(&mut task) else { panic!("later cancellation must win"); };
        assert_eq!(report.stop, SymbolRepairMembershipStop::Cancelled(reason));
        assert_eq!(report.scheduled, 0);
    }
    drop(run);
    assert!(owner.checkpoint().is_ok());
    assert!(first.checkpoint().is_ok());
    for cx in [owner, first, later] {
        assert!(cx.inner.read().cancel_waker_registrations.is_empty());
    }
}

#[test]
fn trigger_deadlines_preserve_same_clock_absolute_time_and_translate_foreign_remaining_time() {
    for shared in [false, true] {
        let owner_clock = Arc::new(crate::time::VirtualClock::starting_at(Time::from_nanos(1_000)));
        let owner_timer = TimerDriverHandle::with_virtual_clock(owner_clock.clone());
        let owner = Cx::new_with_drivers(RegionId::new_for_test(0, 1), TaskId::new_for_test(91, 0),
            Budget::INFINITE, None, None, None, Some(owner_timer.clone()), None);
        let (poller_timer, deadline) = if shared {
            (owner_timer, Time::from_nanos(1_007))
        } else {
            (TimerDriverHandle::with_virtual_clock(Arc::new(
                crate::time::VirtualClock::starting_at(Time::from_nanos(10)),
            )), Time::from_nanos(17))
        };
        let poller = Cx::new_with_drivers(RegionId::new_for_test(0, 1), TaskId::new_for_test(92, 0),
            Budget::INFINITE.with_deadline(deadline), None, None, None, Some(poller_timer), None);
        let _ambient = Cx::set_current(Some(poller.clone()));
        let mut control = Control::new(&owner);
        let mut task = Context::from_waker(Waker::noop());
        assert!(control.check(&mut task).is_none());
        assert_eq!(control.deadline, Some(Time::from_nanos(1_007)));
        owner_clock.advance(3);
        assert!(control.check(&mut task).is_none());
        assert_eq!(control.deadline, Some(Time::from_nanos(1_007)));
        owner_clock.advance(4);
        assert_eq!(control.check(&mut task), Some(CancelReason::deadline()));
        drop(control);
        assert!(owner.inner.read().cancel_waker_registrations.is_empty());
        assert!(poller.inner.read().cancel_waker_registrations.is_empty());
    }
}

#[test]
fn native_parked_trigger_cancellation_returns_its_typed_report_and_leaves_services_owned() {
    for workers in [1, 2] {
        for cancel_poller in [false, true] {
            let runtime = if workers == 1 { RuntimeBuilder::current_thread().build().unwrap() }
                else { RuntimeBuilder::multi_thread().worker_threads(workers).build().unwrap() };
            let membership = controller();
            apply(&membership, 1, 1, 0);
            let worker = handle();
            let trigger = bridge(&membership, &worker);
            let owner = runtime.request_cx_with_budget(Budget::INFINITE);
            let reason = CancelReason::user("native membership trigger stopped");
            let (parked_tx, parked_rx) = mpsc::channel::<Cx>();
            let stopper = {
                let owner = owner.clone();
                let reason = reason.clone();
                std::thread::spawn(move || {
                    let poller = parked_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                    if cancel_poller { poller.cancel_with_reason(reason); }
                    else { owner.cancel_with_reason(reason); }
                    poller
                })
            };
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let owner_for_task = owner.clone();
                let mut task = cx.spawn(move |body| async move {
                    let mut run = std::pin::pin!(trigger.run(&owner_for_task));
                    let mut witnessed = false;
                    poll_fn(|task| {
                        let result = run.as_mut().poll(task);
                        if result.is_pending() && !witnessed {
                            witnessed = true;
                            parked_tx.send(body.clone()).unwrap();
                        }
                        result
                    }).await
                }).unwrap();
                let report = crate::time::timeout(
                    cx.now(),
                    Duration::from_secs(5),
                    task.join(&cx),
                )
                .await
                .expect("parked membership trigger must observe cancellation")
                .expect("cooperative cancellation preserves the trigger receipt");
                assert_eq!(report.stop, SymbolRepairMembershipStop::Cancelled(reason));
                assert_eq!((report.scheduled, report.coalesced), (0, 0));
                assert!(cx.checkpoint().is_ok());
            });
            let poller = stopper.join().unwrap();
            assert!(owner.inner.read().cancel_waker_registrations.is_empty());
            assert!(poller.inner.read().cancel_waker_registrations.is_empty());
            assert_eq!(worker.shared.changed.waiter_count(), 0);
            assert_eq!(worker.snapshot().status, SymbolRepairWorkerStatus::Prepared);
            assert!(!membership.observe_member(&NodeId::new("source")).unwrap().snapshot().closed);
            assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
            assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
        }
    }
}
