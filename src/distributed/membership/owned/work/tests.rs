use super::*;
use crate::distributed::membership::{MembershipEvent, MembershipKind};
use crate::distributed::membership::authority::{MembershipControllerLimits, MembershipFloor, MembershipUpdate};
use crate::runtime::RuntimeBuilder;
use crate::security::AuthKey;
use crate::sync::Notify;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

const BUDGET: Duration = Duration::from_secs(10);
fn statement(incarnation: u64, sequence: u64, kind: MembershipKind) -> Vec<u8> {
    MembershipUpdate { event: MembershipEvent { node: NodeId::new("worker"), incarnation, kind }, sequence }
        .authenticated_bytes(&NodeId::new("authority"), 7, &AuthKey::from_seed(42)).unwrap()
}
fn controller(cx: &Cx) -> OwnedMembershipController {
    controller_with_timer(cx.timer_driver().unwrap())
}
fn controller_with_timer(timer: crate::time::TimerDriverHandle) -> OwnedMembershipController {
    let owner = OwnedMembershipController::new(NodeId::new("authority"), 7, AuthKey::from_seed(42),
        vec![MembershipFloor { node: NodeId::new("worker"), incarnation: 0, sequence: 0 }],
        MembershipControllerLimits { max_members: 1, max_lease_ids: 32 }, timer).unwrap();
    owner.apply_authenticated(&NodeId::new("authority"), &statement(1, 1, MembershipKind::Alive)).unwrap();
    owner
}
fn native<F, Fut>(f: F)
where F: FnOnce(Cx) -> Fut + Send + 'static, Fut: Future<Output = ()> + Send + 'static,
{
    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    runtime.block_on(async move {
        let cx = Cx::current().unwrap();
        let mut task = cx.spawn(f).unwrap();
        crate::time::timeout(cx.now(), BUDGET, task.join(&cx)).await.expect("test watchdog").expect("test task");
    });
    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
    assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
}

#[derive(Default)]
struct Witness { parked: AtomicBool, dropped: AtomicBool, changed: Notify }
struct Retire(Arc<Witness>);
impl Drop for Retire {
    fn drop(&mut self) { self.0.dropped.store(true, Ordering::Release); self.0.changed.notify_waiters(); }
}
async fn cancellable(cx: Cx, witness: Arc<Witness>) -> usize {
    let _retire = Retire(Arc::clone(&witness));
    let mut cancelled = std::pin::pin!(cx.cancelled());
    poll_fn(|task| {
        let state = cancelled.as_mut().poll(task);
        if state.is_pending() && !witness.parked.swap(true, Ordering::AcqRel) { witness.changed.notify_waiters(); }
        state
    }).await;
    let _ = cx.checkpoint(); // Preserve this explicit cancellation/cleanup value.
    41
}

#[test]
fn clean_body_returns_from_a_distinct_closed_region_and_commits() {
    native(|cx| async move {
        let owner = controller(&cx);
        let parent = cx.region_id();
        let report = owner.run_scoped(&cx, &NodeId::new("worker"), 1, BUDGET,
            ChildRegionSpec::inherit(), |child| async move { child.region_id() }).await.unwrap();
        assert!(report.is_success(), "{report:?}");
        let child = report.task.unwrap();
        assert_ne!(child, parent);
        assert_eq!(report.close.unwrap().region_id, child);
        assert!(matches!(report.lease, Ok(OwnedLeaseStatus::Released)));
        assert_eq!(owner.live_leases(), 0); assert!(!cx.is_cancel_requested());
    });
}

#[test]
fn application_error_is_preserved_as_a_body_value_not_hidden_by_runtime_success() {
    native(|cx| async move {
        let report = controller(&cx).run_scoped(&cx, &NodeId::new("worker"), 1, BUDGET,
            ChildRegionSpec::inherit(), |_| async { Err::<(), _>("application refusal") }).await.unwrap();
        assert!(report.is_success()); // API does not interpret T.
        assert_eq!(report.task.unwrap(), Err("application refusal"));
    });
}

#[test]
fn denied_membership_never_invokes_the_factory() {
    native(|cx| async move {
        let owner = controller(&cx);
        let calls = Arc::new(AtomicUsize::new(0)); let seen = Arc::clone(&calls);
        let result = owner.run_scoped(&cx, &NodeId::new("unknown"), 1, BUDGET,
            ChildRegionSpec::inherit(), move |_| { seen.fetch_add(1, Ordering::SeqCst); async {} }).await;
        assert!(matches!(result, Err(MembershipWorkError::Lease(_))));
        assert_eq!(calls.load(Ordering::SeqCst), 0); assert_eq!(owner.live_leases(), 0);
    });
}

fn retired_case(status: OwnedLeaseStatus) {
    native(move |cx| async move {
        let owner = controller(&cx); let witness = Arc::new(Witness::default());
        let observer = Arc::clone(&witness); let updates = owner.clone();
        let mut authority = cx.spawn(move |_| async move {
            observer.changed.wait_until(|| observer.parked.load(Ordering::Acquire)).await;
            match status {
                OwnedLeaseStatus::Revoked => { updates.apply_authenticated(&NodeId::new("authority"), &statement(1, 2, MembershipKind::Dead)).unwrap(); }
                OwnedLeaseStatus::Superseded => { updates.apply_authenticated(&NodeId::new("authority"), &statement(2, 2, MembershipKind::Alive)).unwrap(); }
                OwnedLeaseStatus::Closed => updates.close(),
                _ => unreachable!(),
            }
        }).unwrap();
        let body = Arc::clone(&witness);
        let report = owner.run_scoped(&cx, &NodeId::new("worker"), 1, BUDGET,
            ChildRegionSpec::inherit(), move |child| cancellable(child, body)).await.unwrap();
        authority.join(&cx).await.unwrap();
        assert!(matches!(report.trigger, MembershipWorkTrigger::LeaseEnded(actual) if actual == status));
        assert!(!report.is_success()); assert_eq!(report.task.unwrap(), 41);
        assert!(report.close.is_ok());
        assert!(witness.dropped.load(Ordering::Acquire), "future destructor precedes output");
        assert!(matches!(report.lease, Ok(actual) if actual == status));
        assert_eq!(owner.live_leases(), 0); assert!(!cx.is_cancel_requested());
    });
}
#[test]
fn authenticated_revocation_cancels_and_drains_body_but_not_parent() { retired_case(OwnedLeaseStatus::Revoked); }
#[test]
fn newer_incarnation_stops_old_body_without_cancelling_parent() { retired_case(OwnedLeaseStatus::Superseded); }
#[test]
fn controller_close_drains_existing_work() { retired_case(OwnedLeaseStatus::Closed); }

#[test]
fn expiry_stops_a_parked_body_without_an_external_expiry_driver() {
    native(|cx| async move {
        let owner = controller(&cx); let witness = Arc::new(Witness::default()); let body = Arc::clone(&witness);
        let report = owner.run_scoped(&cx, &NodeId::new("worker"), 1, Duration::from_millis(100),
            ChildRegionSpec::inherit(), move |child| cancellable(child, body)).await.unwrap();
        assert!(witness.parked.load(Ordering::Acquire)); assert!(witness.dropped.load(Ordering::Acquire));
        assert!(matches!(report.trigger, MembershipWorkTrigger::LeaseEnded(OwnedLeaseStatus::Expired)));
        assert!(matches!(report.lease, Ok(OwnedLeaseStatus::Expired))); assert!(report.close.is_ok());
        assert_eq!(owner.live_leases(), 0); assert!(!report.is_success());
    });
}

#[test]
fn unrelated_ambient_cancellation_keeps_scoped_work_parked_until_its_owner_stops_it() {
    native(|cx| async move {
        let owner = controller(&cx);
        let witness = Arc::new(Witness::default());
        let body = Arc::clone(&witness);
        let node = NodeId::new("worker");
        let mut run = Box::pin(owner.run_scoped(
            &cx, &node, 1, BUDGET, ChildRegionSpec::inherit(),
            move |child| cancellable(child, body),
        ));
        {
            let mut parked = std::pin::pin!(witness.changed.wait_until(|| witness.parked.load(Ordering::Acquire)));
            poll_fn(|task| {
                assert!(run.as_mut().poll(task).is_pending());
                parked.as_mut().poll(task)
            }).await;
        }
        let timer = cx.timer_driver().unwrap();
        let pending_timers = timer.pending_count();
        assert!(pending_timers > 0, "the lease deadline is armed");
        assert_eq!(owner.live_leases(), 1);
        let unrelated = Cx::for_testing();
        unrelated.cancel_with(crate::types::CancelKind::User, Some("unrelated ambient task"));
        eprintln!("scenario=membership_work_unrelated_ambient_cancel state=parked live_leases=1 pending_timers={pending_timers}");
        poll_fn(|task| {
            let _ambient = Cx::set_current(Some(unrelated.clone()));
            for poll_index in 1..=3 {
                // Old code completes the Sleep at poll 1, then panics at poll 2.
                assert!(run.as_mut().poll(task).is_pending(), "poll {poll_index}");
            }
            Poll::Ready(())
        }).await;
        assert_eq!(timer.pending_count(), pending_timers);
        assert_eq!(owner.live_leases(), 1);
        assert!(!cx.is_cancel_requested());
        assert!(!witness.dropped.load(Ordering::Acquire));

        owner.close();
        let report = run.await.unwrap();
        assert!(matches!(report.trigger, MembershipWorkTrigger::LeaseEnded(OwnedLeaseStatus::Closed)));
        assert_eq!(report.task.unwrap(), 41);
        assert!(report.close.is_ok());
        assert!(matches!(report.lease, Ok(OwnedLeaseStatus::Closed)));
        assert!(witness.dropped.load(Ordering::Acquire));
        assert_eq!(owner.live_leases(), 0);
        assert_eq!(timer.pending_count() + 1, pending_timers);
        assert!(!cx.is_cancel_requested());
        eprintln!("scenario=membership_work_unrelated_ambient_cancel poll_count=3 terminal=Closed task=41 child_drained=true live_leases=0");
    });
}

#[test]
fn early_lease_timer_fire_rearms_before_repoll_and_still_expires_native_work() {
    native(|cx| async move {
        let clock = Arc::new(crate::time::VirtualClock::new());
        let timer = crate::time::TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
        let owner = controller_with_timer(timer.clone());
        let witness = Arc::new(Witness::default());
        let body = Arc::clone(&witness);
        let node = NodeId::new("worker");
        let deadline = Time::from_millis(100);
        let mut run = Box::pin(owner.run_scoped(
            &cx, &node, 1, Duration::from_millis(100), ChildRegionSpec::inherit(),
            move |child| cancellable(child, body),
        ));
        {
            let mut parked = std::pin::pin!(witness.changed.wait_until(|| witness.parked.load(Ordering::Acquire)));
            poll_fn(|task| {
                assert!(run.as_mut().poll(task).is_pending());
                parked.as_mut().poll(task)
            }).await;
        }
        assert_eq!(timer.pending_count(), 1);
        // Inject a latched timer wake while the owner's next time observation
        // remains before expiry. This reproduces the early-fire boundary
        // without requiring the runtime to enable wheel coalescing globally.
        clock.advance_to(deadline);
        assert_eq!(timer.process_timers(), 1);
        clock.set(Time::ZERO);
        eprintln!("scenario=membership_work_early_timer state=parked clock_ns=0 deadline_ns={} timer_fired=1", deadline.as_nanos());
        poll_fn(|task| {
            assert!(run.as_mut().poll(task).is_pending());
            assert!(run.as_mut().poll(task).is_pending(), "completed Sleep must be reset before reuse");
            Poll::Ready(())
        }).await;
        assert_eq!(timer.pending_count(), 1, "the expiry wake source is rearmed");
        assert_eq!(owner.live_leases(), 1);
        assert!(!witness.dropped.load(Ordering::Acquire));

        clock.advance_to(deadline);
        assert_eq!(timer.process_timers(), 1);
        let report = run.await.unwrap();
        assert!(matches!(report.trigger, MembershipWorkTrigger::LeaseEnded(OwnedLeaseStatus::Expired)));
        assert_eq!(report.task.unwrap(), 41);
        assert!(report.close.is_ok());
        assert!(matches!(report.lease, Ok(OwnedLeaseStatus::Expired)));
        assert!(witness.dropped.load(Ordering::Acquire));
        assert_eq!(owner.live_leases(), 0);
        assert_eq!(timer.pending_count(), 0);
        assert!(!cx.is_cancel_requested());
        eprintln!("scenario=membership_work_early_timer poll_count=2 terminal=Expired task=41 child_drained=true live_leases=0 pending_timers=0");
    });
}

#[test]
fn returned_body_does_not_abandon_its_running_descendants() {
    native(|cx| async move {
        let witness = Arc::new(Witness::default()); let seen = Arc::clone(&witness);
        let report = controller(&cx).run_scoped(&cx, &NodeId::new("worker"), 1, BUDGET,
            ChildRegionSpec::inherit(), move |child| async move {
                let body = Arc::clone(&seen);
                // Intentionally retain no join handle: region ownership is the backstop.
                let _task = child.spawn(move |descendant| cancellable(descendant, body)).unwrap();
                seen.changed.wait_until(|| seen.parked.load(Ordering::Acquire)).await;
                7
            }).await.unwrap();
        assert_eq!(report.task.unwrap(), 7); assert!(report.close.is_ok());
        assert!(witness.dropped.load(Ordering::Acquire)); assert!(!cx.is_cancel_requested());
    });
}

#[test]
fn body_panic_is_retained_and_the_lease_is_not_committed() {
    native(|cx| async move {
        let witness = Arc::new(Witness::default()); let seen = Arc::clone(&witness);
        let report = controller(&cx).run_scoped(&cx, &NodeId::new("worker"), 1, BUDGET,
            ChildRegionSpec::inherit(), move |_| async move {
                let _retire = Retire(seen); panic!("membership body sentinel");
            }).await.unwrap();
        assert!(matches!(report.task, Err(MembershipWorkTaskError::Join(JoinError::Panicked(_)))));
        assert!(report.close.is_ok()); assert!(!report.is_success());
        assert!(matches!(report.lease, Ok(OwnedLeaseStatus::Dropped)));
        assert!(witness.dropped.load(Ordering::Acquire));
    });
}

#[test]
fn owner_cancellation_drains_child_and_preserves_the_explicit_report() {
    native(|cx| async move {
        let owner = controller(&cx); let running = owner.clone();
        let witness = Arc::new(Witness::default()); let body = Arc::clone(&witness);
        let mut holder = cx.spawn(move |holder_cx| async move {
            let report = running.run_scoped(&holder_cx, &NodeId::new("worker"), 1, BUDGET,
                ChildRegionSpec::inherit(), move |child| cancellable(child, body)).await.unwrap();
            assert!(holder_cx.checkpoint().is_err()); // Caller explicitly accepts cancellation.
            report
        }).unwrap();
        witness.changed.wait_until(|| witness.parked.load(Ordering::Acquire)).await;
        holder.abort();
        let report = holder.join(&cx).await.unwrap();
        assert!(matches!(report.trigger, MembershipWorkTrigger::ParentCancelled(_)));
        assert!(!report.is_success()); assert!(report.close.is_ok());
        assert!(witness.dropped.load(Ordering::Acquire)); assert_eq!(owner.live_leases(), 0);
        assert!(!cx.is_cancel_requested(), "outer parent stays live");
    });
}

#[test]
fn dropping_runner_requests_child_cleanup_without_a_false_drain_receipt() {
    native(|cx| async move {
        let owner = controller(&cx); let witness = Arc::new(Witness::default()); let body = Arc::clone(&witness);
        let node = NodeId::new("worker");
        let mut run = Box::pin(owner.run_scoped(&cx, &node, 1, BUDGET,
            ChildRegionSpec::inherit(), move |child| cancellable(child, body)));
        {
            let mut started = std::pin::pin!(witness.changed.wait_until(|| witness.parked.load(Ordering::Acquire)));
            poll_fn(|task| {
                assert!(run.as_mut().poll(task).is_pending());
                started.as_mut().poll(task)
            }).await;
        }
        drop(run);
        assert_eq!(owner.live_leases(), 0);
        witness.changed.wait_until(|| witness.dropped.load(Ordering::Acquire)).await;
        assert!(!cx.is_cancel_requested());
    });
}

#[test]
fn report_debug_omits_application_payload() {
    native(|cx| async move {
        let report = controller(&cx).run_scoped(&cx, &NodeId::new("worker"), 1, BUDGET,
            ChildRegionSpec::inherit(), |_| async { "private-application-body" }).await.unwrap();
        assert!(report.is_success()); assert!(!format!("{report:?}").contains("private-application-body"));
    });
}
