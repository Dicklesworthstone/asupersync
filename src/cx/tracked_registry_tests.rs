#![allow(clippy::pedantic, clippy::nursery)]

use super::*;
use crate::lab::{LabConfig, LabRuntime};
use crate::runtime::TaskHandle;
use crate::runtime::obligation_mailbox::{ObligationGateway, apply_obligation_posts};
use crate::types::{Budget, CancelKind};
use std::sync::atomic::{AtomicUsize, Ordering};

pub(super) fn fixture(limit: usize) -> (LabRuntime, Cx, TaskHandle<()>) {
    crate::test_utils::init_test_logging();
    let mut lab = LabRuntime::new(LabConfig::new(0x100_1ea5e).max_steps(512));
    let root = lab.state.create_root_region(Budget::INFINITE);
    let region = lab.state.create_child_region(root, Budget::INFINITE).unwrap();
    assert!(lab.state.set_region_limits(
        region,
        crate::record::region::RegionLimits {
            max_obligations: Some(limit),
            ..crate::record::region::RegionLimits::UNLIMITED
        },
    ));
    let (task, handle) = lab.state.create_task(region, Budget::INFINITE, async {}).unwrap();
    let cx = lab.state.task(task).unwrap().cx.clone().unwrap();
    (lab, cx, handle)
}

pub(super) fn flush(lab: &mut LabRuntime) {
    let mailbox = Arc::clone(lab.state.obligation_gateway().unwrap().mailbox());
    apply_obligation_posts(&mut lab.state, &mailbox, usize::MAX);
}

pub(super) fn finish(mut lab: LabRuntime, cx: &Cx, mut handle: TaskHandle<()>, reserved: u64) {
    flush(&mut lab);
    assert_eq!(lab.state.pending_obligation_count(), 0);
    lab.scheduler.lock().schedule(cx.task_id(), 0);
    let report = lab.run_until_quiescent_with_report();
    assert!(report.invariant_violations.is_empty());
    assert!(report.oracle_report.all_passed(), "{:?}", report.oracle_report.failures());
    assert!(handle.try_join().unwrap().is_some());
    let mailbox = Arc::clone(lab.state.obligation_gateway().unwrap().mailbox());
    let stats = mailbox.stats();
    assert_eq!(stats.reserved, reserved);
    assert_eq!(stats.committed + stats.aborted, reserved);
    assert_eq!(stats.posted, stats.applied);
    assert_eq!(stats.leaked, 0);
    assert_eq!(stats.refused, 0);
    assert_eq!(mailbox.open_tickets(), 0);
    assert_eq!(lab.state.leak_count(), 0);
}

#[test]
fn registered_name_is_visible_and_accounted_until_release() {
    let (mut lab, cx, handle) = fixture(1);
    let registry = TrackedNameRegistry::new();
    let lease = registry.register(&cx, "worker").unwrap();
    assert_eq!(registry.whereis("worker"), Some(cx.task_id()));
    assert_eq!(lease.name(), "worker");
    assert_eq!(lease.holder(), cx.task_id());
    assert_eq!(lease.region(), cx.region_id());
    assert_eq!(lease.acquired_at(), cx.now());
    assert_eq!(lease.obligation.as_ref().unwrap().kind(), ObligationKind::Lease);
    flush(&mut lab);
    assert_eq!(lab.state.pending_obligation_count(), 1);
    lease.release().unwrap();
    assert_eq!(registry.whereis("worker"), None);
    finish(lab, &cx, handle, 1);
}

#[test]
fn dropping_or_aborting_name_removes_discovery_and_returns_quota() {
    for explicitly_abort in [false, true] {
        let (lab, cx, handle) = fixture(1);
        let registry = TrackedNameRegistry::new();
        let lease = registry.register(&cx, "worker").unwrap();
        let first_ticket = lease.obligation_ticket();
        if explicitly_abort { lease.abort().unwrap(); } else { drop(lease); }
        assert_eq!(registry.whereis("worker"), None);
        // No mailbox drain: the same single credit must already be available.
        let next = registry.register(&cx, "worker").unwrap();
        assert_ne!(next.obligation_ticket(), first_ticket);
        next.release().unwrap();
        finish(lab, &cx, handle, 2);
    }
}

#[test]
fn quota_refusal_never_publishes_a_name() {
    let (lab, cx, handle) = fixture(0);
    let registry = TrackedNameRegistry::new();
    assert!(matches!(
        registry.register(&cx, "worker"),
        Err(TrackedNameError::Admission(ObligationAdmissionError::LimitReached {
            limit: 0, live: 0,
        }))
    ));
    assert_eq!(registry.whereis("worker"), None);
    finish(lab, &cx, handle, 0);
}

#[test]
fn name_collision_returns_unused_credit_without_displacing_owner() {
    let (lab, cx, handle) = fixture(2);
    let registry = TrackedNameRegistry::new();
    let first = registry.register(&cx, "worker").unwrap();
    assert!(matches!(registry.register(&cx, "worker"),
        Err(TrackedNameError::Registry(NameLeaseError::NameTaken { .. }))));
    assert_eq!(registry.whereis("worker"), Some(first.holder()));
    let other = registry.register(&cx, "other").unwrap();
    first.release().unwrap();
    other.release().unwrap();
    finish(lab, &cx, handle, 3);
}

#[test]
fn stateless_and_cancelled_contexts_fail_closed() {
    let registry = TrackedNameRegistry::new();
    assert!(matches!(registry.register(&Cx::for_testing(), "worker"),
        Err(TrackedNameError::RuntimeRequired)));
    let (lab, cx, handle) = fixture(1);
    cx.cancel_fast(CancelKind::User);
    assert!(matches!(registry.register(&cx, "worker"), Err(TrackedNameError::Cancelled)));
    assert_eq!(registry.whereis("worker"), None);
    // This test only inspects admission; do not demand a successful task outcome
    // from the deliberately cancelled holder.
    drop(handle);
    assert_eq!(lab.state.obligation_gateway().unwrap().mailbox().stats().posted, 0);
}

#[test]
fn registry_clones_share_names_and_guard_keeps_registry_alive() {
    let (lab, cx, handle) = fixture(1);
    let registry = TrackedNameRegistry::new();
    let observer = registry.clone();
    let capability = registry.capability();
    let lease = registry.register(&cx, "worker").unwrap();
    drop(registry);
    assert_eq!(observer.whereis("worker"), Some(cx.task_id()));
    drop(capability);
    lease.release().unwrap();
    assert_eq!(observer.whereis("worker"), None);
    finish(lab, &cx, handle, 1);
}

#[test]
fn admission_and_settlement_notifications_run_outside_registry_lock() {
    let (lab, cx, handle) = fixture(1);
    let registry = TrackedNameRegistry::new();
    let observed_registry = registry.clone();
    let calls = Arc::new(AtomicUsize::new(0));
    let observed_calls = Arc::clone(&calls);
    let liveness = Arc::new(());
    let gateway = Arc::new(ObligationGateway::new(
        Arc::clone(lab.state.obligation_gateway().unwrap().mailbox()),
        Arc::new(move || {
            assert!(observed_registry.inner.try_lock().is_some(), "notification under name lock");
            assert_eq!(observed_registry.whereis("worker"), None);
            observed_calls.fetch_add(1, Ordering::SeqCst);
        }),
        Arc::downgrade(&liveness),
    ));
    let cx = cx.with_obligation_gateway(Some(gateway), None);
    let lease = registry.register(&cx, "worker").unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    lease.release().unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    finish(lab, &cx, handle, 1);
}

#[test]
fn cancellation_from_admission_notifier_rolls_back_before_publication() {
    let (mut lab, cx, handle) = fixture(1);
    let registry = TrackedNameRegistry::new();
    let cancel_cx = cx.clone();
    let liveness = Arc::new(());
    let gateway = Arc::new(ObligationGateway::new(
        Arc::clone(lab.state.obligation_gateway().unwrap().mailbox()),
        Arc::new(move || { cancel_cx.cancel_fast(CancelKind::User); }),
        Arc::downgrade(&liveness),
    ));
    let cx = cx.with_obligation_gateway(Some(gateway), None);
    assert!(matches!(registry.register(&cx, "worker"), Err(TrackedNameError::Cancelled)));
    assert_eq!(registry.whereis("worker"), None);
    flush(&mut lab);
    assert_eq!(lab.state.pending_obligation_count(), 0);
    assert_eq!(lab.state.leak_count(), 0);
    let stats = lab.state.obligation_gateway().unwrap().mailbox().stats();
    assert_eq!(stats.reserved, 1);
    assert_eq!(stats.aborted, 1);
    drop(handle);
}

#[test]
fn notifier_panics_do_not_strand_names_or_quota() {
    for panic_at in [0, 1] {
        let (lab, cx, handle) = fixture(1);
        let registry = TrackedNameRegistry::new();
        let observed_registry = registry.clone();
        let calls = Arc::new(AtomicUsize::new(0));
        let observed_calls = Arc::clone(&calls);
        let liveness = Arc::new(());
        let gateway = Arc::new(ObligationGateway::new(
            Arc::clone(lab.state.obligation_gateway().unwrap().mailbox()),
            Arc::new(move || {
                assert!(observed_registry.inner.try_lock().is_some());
                if observed_calls.fetch_add(1, Ordering::SeqCst) == panic_at {
                    panic!("planted name notification panic");
                }
            }),
            Arc::downgrade(&liveness),
        ));
        let cx = cx.with_obligation_gateway(Some(gateway), None);
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            registry.register(&cx, "worker").unwrap().release().unwrap();
        }));
        assert!(outcome.is_err());
        assert_eq!(registry.whereis("worker"), None);
        registry.register(&cx, "worker").unwrap().release().unwrap();
        finish(lab, &cx, handle, 2);
    }
}

#[test]
fn retaining_guard_beyond_holder_completion_is_a_runtime_leak() {
    let (mut lab, cx, mut handle) = fixture(1);
    lab.state.set_obligation_leak_response(crate::runtime::config::ObligationLeakResponse::Silent);
    let registry = TrackedNameRegistry::new();
    // Keep allocation alive just as forget would, but recover it after the
    // audit so this regression does not permanently leak test heap memory.
    let retained = std::mem::ManuallyDrop::new(registry.register(&cx, "worker").unwrap());
    flush(&mut lab);
    assert_eq!(lab.state.pending_obligation_count(), 1);
    lab.scheduler.lock().schedule(cx.task_id(), 0);
    let _report = lab.run_until_quiescent_with_report();
    assert!(!matches!(handle.try_join(), Ok(None)), "holder must terminate");
    assert_eq!(lab.state.leak_count(), 1);
    assert_eq!(registry.whereis("worker"), Some(cx.task_id()));
    // Late physical cleanup must not rewrite the already chosen leak outcome.
    let result = std::mem::ManuallyDrop::into_inner(retained).release();
    assert!(matches!(result, Err(TrackedNameError::SettlementRejected)));
    assert_eq!(registry.whereis("worker"), None);
    assert_eq!(lab.state.leak_count(), 1);
}
