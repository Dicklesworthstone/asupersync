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
    let owner = OwnedMembershipController::new(NodeId::new("authority"), 7, AuthKey::from_seed(42),
        vec![MembershipFloor { node: NodeId::new("worker"), incarnation: 0, sequence: 0 }],
        MembershipControllerLimits { max_members: 1, max_lease_ids: 32 }, cx.timer_driver().unwrap()).unwrap();
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
