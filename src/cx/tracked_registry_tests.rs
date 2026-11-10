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

/// A released name is free only once its quota credit is back. Release used to
/// remove the name, publish the wake and only then return the credit, so a
/// contender registering in between got LimitReached at quota one, although
/// the only credit was being returned with the name (br-asupersync-xphg21).
/// The releaser is held inside that window by a thread that keeps the
/// registry's waiter lock, which the release takes to publish the change.
#[test]
fn a_released_name_is_free_only_with_its_quota_returned() {
    let (lab, cx, handle) = fixture(1);
    let names = TrackedNameRegistry::new();
    let owner = names.register(&cx, "worker").unwrap();
    let (held_tx, held_rx) = std::sync::mpsc::channel();
    let (open_tx, open_rx) = std::sync::mpsc::channel::<()>();
    let gate = {
        let names = names.clone();
        std::thread::spawn(move || {
            let waiters = names.waiters.lock();
            held_tx.send(()).unwrap();
            // The gate also opens on its own, so a path that does need the
            // waiter lock cannot hang the test.
            let _ = open_rx.recv_timeout(std::time::Duration::from_secs(5));
            drop(waiters);
        })
    };
    held_rx.recv().unwrap();
    let contender = {
        let (names, cx) = (names.clone(), cx.clone());
        std::thread::spawn(move || {
            while names.whereis("worker").is_some() {
                std::thread::yield_now();
            }
            let attempt = names.register(&cx, "worker");
            let refused = attempt.as_ref().err().map(|error| format!("{error:?}"));
            let _ = open_tx.send(());
            if let Ok(lease) = attempt {
                lease.release().unwrap();
            }
            refused
        })
    };
    owner.release().unwrap();
    gate.join().unwrap();
    assert_eq!(
        contender.join().unwrap(),
        None,
        "the contender found the name free but its quota still held"
    );
    finish(lab, &cx, handle, 2);
}

#[test]
fn lease_transfer_rebinds_name_to_child_task_without_leak_or_settlement_rejection() {
    let (mut lab, parent_cx, mut parent_handle) = fixture(2);
    let region = parent_cx.region_id();
    let (child_task, child_handle) = lab
        .state
        .create_task(region, Budget::INFINITE, async {})
        .unwrap();
    let child_cx = lab.state.task(child_task).unwrap().cx.clone().unwrap();

    let names = TrackedNameRegistry::new();
    let mut lease = names.register(&parent_cx, "service").unwrap();
    assert_eq!(names.whereis("service"), Some(parent_cx.task_id()));
    assert_eq!(names.whereis_cx(&parent_cx, "service").unwrap(), Some(parent_cx.task_id()));
    assert_eq!(lease.holder(), parent_cx.task_id());

    // Transfer lease to child
    lease.try_transfer(&child_cx).expect("transfer must succeed within same runtime");
    assert_eq!(names.whereis("service"), Some(child_cx.task_id()));
    assert_eq!(names.whereis_cx(&child_cx, "service").unwrap(), Some(child_cx.task_id()));
    assert_eq!(lease.holder(), child_cx.task_id());
    assert_eq!(lease.region(), child_cx.region_id());

    // Parent completes and is retired
    flush(&mut lab);
    lab.scheduler.lock().schedule(parent_cx.task_id(), 0);
    let _steps = lab.run_until_idle();
    assert!(parent_handle.try_join().unwrap().is_some());
    // Parent completed without leaking the lease obligation because ownership was transferred!
    assert_eq!(lab.state.leak_count(), 0);

    // Child releases lease
    lease.release().expect("child lease release must succeed without settlement rejection");
    assert_eq!(names.whereis("service"), None);

    // Child completes and verifies all invariants and stats
    finish(lab, &child_cx, child_handle, 1);
}

/// Review r28-e8 of dfba198ce (C3-M1): a lease cannot be moved into the root
/// region, which every acquisition path refuses (`UnscopedRegion`). It used to
/// transfer, leaving a name and its obligation held by an unscoped task
/// (`block_on`, `RuntimeHandle::spawn`). The refusal leaves the lease where it
/// was.
#[test]
fn lease_transfer_to_a_root_region_task_is_refused_and_keeps_the_lease() {
    crate::test_utils::init_test_logging();
    let mut lab = LabRuntime::new(LabConfig::new(0x100_1ea5f).max_steps(512));
    let root = lab.state.create_root_region(Budget::INFINITE);
    assert_eq!(root.as_u64(), 0, "the root region is the sentinel");
    let region = lab
        .state
        .create_child_region(root, Budget::INFINITE)
        .unwrap();
    let (task, handle) = lab
        .state
        .create_task(region, Budget::INFINITE, async {})
        .unwrap();
    let cx = lab.state.task(task).unwrap().cx.clone().unwrap();
    let (root_task, mut root_handle) = lab
        .state
        .create_task(root, Budget::INFINITE, async {})
        .unwrap();
    let root_cx = lab.state.task(root_task).unwrap().cx.clone().unwrap();

    let names = TrackedNameRegistry::new();
    let mut lease = names.register(&cx, "service").unwrap();
    let refused = lease.try_transfer(&root_cx);
    assert!(
        matches!(refused, Err(TrackedNameError::UnscopedRegion)),
        "{refused:?}"
    );
    assert_eq!(lease.holder(), cx.task_id());
    assert_eq!(lease.region(), cx.region_id());
    assert_eq!(names.whereis("service"), Some(cx.task_id()));
    lease.release().unwrap();

    flush(&mut lab);
    lab.scheduler.lock().schedule(root_task, 0);
    let _steps = lab.run_until_idle();
    assert!(root_handle.try_join().unwrap().is_some());
    finish(lab, &cx, handle, 1);
}

#[test]
fn lease_transfer_refusals_preserve_ownership_and_cross_region_handoff_returns_quota() {
    for materialized in [false, true] {
        let (mut lab, source, source_handle) = fixture(1);
        let target_region = lab
            .state
            .create_child_region(source.region_id(), Budget::INFINITE)
            .unwrap();
        assert!(lab.state.set_region_limits(
            target_region,
            crate::record::region::RegionLimits {
                max_obligations: Some(0),
                ..crate::record::region::RegionLimits::UNLIMITED
            },
        ));
        let (target_id, mut target_handle) = lab
            .state
            .create_task(target_region, Budget::INFINITE, async {})
            .unwrap();
        let target = lab.state.task(target_id).unwrap().cx.clone().unwrap();
        let names = TrackedNameRegistry::new();
        let mut lease = names.register(&source, "service").unwrap();
        let original_ticket = lease.obligation_ticket();
        if materialized {
            flush(&mut lab);
        }

        assert_eq!(
            lease.try_transfer(&source),
            Err(TrackedNameError::Transfer(ObligationTransferError::SameHolder))
        );
        assert_eq!(
            lease.try_transfer(&target),
            Err(TrackedNameError::Transfer(
                ObligationTransferError::Destination(ObligationAdmissionError::LimitReached {
                    limit: 0,
                    live: 0,
                })
            ))
        );
        assert_eq!(lease.obligation_ticket(), original_ticket);
        assert_eq!(lease.holder(), source.task_id());
        assert_eq!(lease.region(), source.region_id());
        assert_eq!(names.whereis("service"), Some(source.task_id()));
        assert_eq!(
            lab.state.region(source.region_id()).unwrap().pending_obligations(),
            1
        );
        assert_eq!(
            lab.state.region(target_region).unwrap().pending_obligations(),
            0
        );

        assert!(lab.state.set_region_limits(
            target_region,
            crate::record::region::RegionLimits {
                max_obligations: Some(1),
                ..crate::record::region::RegionLimits::UNLIMITED
            },
        ));
        lease.try_transfer(&target).unwrap();
        assert_ne!(lease.obligation_ticket(), original_ticket);
        assert_eq!(lease.holder(), target_id);
        assert_eq!(lease.region(), target_region);
        assert_eq!(names.whereis("service"), Some(target_id));
        assert_eq!(
            lab.state.region(source.region_id()).unwrap().pending_obligations(),
            0
        );
        assert_eq!(
            lab.state.region(target_region).unwrap().pending_obligations(),
            1
        );
        // Handoff returns the source quota synchronously, before mailbox drain.
        names.register(&source, "source-reused").unwrap().release().unwrap();
        lease.release().unwrap();
        assert_eq!(names.whereis("service"), None);

        flush(&mut lab);
        lab.scheduler.lock().schedule(target_id, 0);
        let _steps = lab.run_until_idle();
        assert!(target_handle.try_join().unwrap().is_some());
        finish(lab, &source, source_handle, 2);
    }
}

#[test]
fn lease_transfer_validates_name_incarnation_before_moving_runtime_credit() {
    for replace_name in [false, true] {
        let (mut lab, source, source_handle) = fixture(2);
        let (target_id, mut target_handle) = lab
            .state
            .create_task(source.region_id(), Budget::INFINITE, async {})
            .unwrap();
        let target = lab.state.task(target_id).unwrap().cx.clone().unwrap();
        let names = TrackedNameRegistry::new();
        let mut lease = names.register(&source, "service").unwrap();
        let original_ticket = lease.obligation_ticket();

        // Inject a missing or replaced private entry. Replacement has the same
        // holder, region and virtual timestamp; only its incarnation differs.
        names.inner.lock().force_unregister("service").unwrap();
        let replacement = replace_name.then(|| names.register(&source, "service").unwrap());
        let posted_before = lab.state.obligation_gateway().unwrap().mailbox().stats().posted;
        let result = lease.try_transfer(&target);
        if replace_name {
            assert!(matches!(
                result,
                Err(TrackedNameError::Registry(NameLeaseError::PermissionDenied { .. }))
            ));
        } else {
            assert!(matches!(
                result,
                Err(TrackedNameError::Registry(NameLeaseError::NotFound { .. }))
            ));
        }
        assert_eq!(lease.obligation_ticket(), original_ticket);
        assert_eq!(lease.holder(), source.task_id());
        assert_eq!(lease.region(), source.region_id());
        assert_eq!(lease.obligation.as_ref().unwrap().holder(), source.task_id());
        assert_eq!(
            lab.state.obligation_gateway().unwrap().mailbox().stats().posted,
            posted_before,
            "a registry refusal must not enqueue an irreversible handoff"
        );

        assert!(matches!(lease.abort(), Err(TrackedNameError::Registry(_))));
        assert_eq!(
            names.whereis("service"),
            replacement.as_ref().map(TrackedNameLease::holder)
        );
        if let Some(replacement) = replacement {
            replacement.release().unwrap();
        }
        flush(&mut lab);
        lab.scheduler.lock().schedule(target_id, 0);
        let _steps = lab.run_until_idle();
        assert!(target_handle.try_join().unwrap().is_some());
        finish(lab, &source, source_handle, 1 + u64::from(replace_name));
    }
}

#[test]
fn lease_transfer_notifier_panic_preserves_committed_owner_and_safe_cleanup() {
    for drop_while_unwinding in [false, true] {
        let (mut lab, source, source_handle) = fixture(1);
        let (target_id, mut target_handle) = lab
            .state
            .create_task(source.region_id(), Budget::INFINITE, async {})
            .unwrap();
        let target = lab.state.task(target_id).unwrap().cx.clone().unwrap();
        let names = TrackedNameRegistry::new();
        let mut lease = names.register(&source, "service").unwrap();
        let observed_names = names.clone();
        let notifications = Arc::new(Mutex::new(Vec::new()));
        let observed = Arc::clone(&notifications);
        let liveness = Arc::new(());
        let gateway = Arc::new(ObligationGateway::new(
            Arc::clone(lab.state.obligation_gateway().unwrap().mailbox()),
            Arc::new(move || {
                assert!(
                    observed_names.inner.try_lock().is_some(),
                    "notification held the name lock"
                );
                let holder = observed_names.whereis("service");
                let first = {
                    let mut seen = observed.lock();
                    seen.push(holder);
                    seen.len() == 1
                };
                if first {
                    panic!("planted transfer notification panic");
                }
            }),
            Arc::downgrade(&liveness),
        ));
        let target = target.with_obligation_gateway(Some(gateway), None);
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            lease.try_transfer(&target)
        }))
        .expect_err("the accepted transfer invokes its notifier");
        assert_eq!(
            panic.downcast_ref::<&str>(),
            Some(&"planted transfer notification panic")
        );
        let owner = lease.obligation.as_ref().map(|token| (token.holder(), token.region()));
        let lease_owner = (lease.holder(), lease.region());
        let expected_owner = (target.task_id(), target.region_id());

        // Keep an old-code failure inside catch_unwind as well: its missing
        // token used to make Drop panic. Do not let that known broken state
        // turn this regression's diagnostic into a double-panic process abort.
        let cleanup = if drop_while_unwinding && owner == Some(expected_owner) {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                let _lease = lease;
                panic!("planted owner unwind after committed transfer");
            }))
        } else {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(lease)))
        };
        assert_eq!(owner, Some(expected_owner), "the name guard lost its runtime credit");
        assert_eq!(lease_owner, expected_owner);
        if drop_while_unwinding {
            assert_eq!(
                cleanup.unwrap_err().downcast_ref::<&str>(),
                Some(&"planted owner unwind after committed transfer")
            );
            assert_eq!(*notifications.lock(), vec![Some(target_id)]);
        } else {
            assert!(cleanup.is_ok(), "dropping the guard caused a secondary panic");
            assert_eq!(*notifications.lock(), vec![Some(target_id), None]);
        }
        assert_eq!(names.whereis("service"), None);
        assert_eq!(
            lab.state.region(source.region_id()).unwrap().pending_obligations(),
            0
        );
        flush(&mut lab);
        lab.scheduler.lock().schedule(target_id, 0);
        let _steps = lab.run_until_idle();
        assert!(target_handle.try_join().unwrap().is_some());
        finish(lab, &source, source_handle, 1);
    }
}

#[test]
fn lease_transfer_drops_source_gateway_captures_after_registry_unlock() {
    struct DropProbe {
        names: TrackedNameRegistry,
        unlocked: Arc<Mutex<Option<bool>>>,
    }

    impl Drop for DropProbe {
        fn drop(&mut self) {
            *self.unlocked.lock() = Some(self.names.inner.try_lock().is_some());
        }
    }

    let (mut lab, source, source_handle) = fixture(1);
    let (target_id, mut target_handle) = lab
        .state
        .create_task(source.region_id(), Budget::INFINITE, async {})
        .unwrap();
    let target = lab.state.task(target_id).unwrap().cx.clone().unwrap();
    let names = TrackedNameRegistry::new();
    let unlocked = Arc::new(Mutex::new(None));
    let probe = DropProbe {
        names: names.clone(),
        unlocked: Arc::clone(&unlocked),
    };
    let liveness = Arc::new(());
    let gateway = Arc::new(ObligationGateway::new(
        Arc::clone(lab.state.obligation_gateway().unwrap().mailbox()),
        Arc::new(move || {
            let _keep_probe_alive = &probe;
        }),
        Arc::downgrade(&liveness),
    ));
    let weak_gateway = Arc::downgrade(&gateway);
    let custom_source = source.clone().with_obligation_gateway(Some(gateway), None);
    let mut lease = names.register(&custom_source, "service").unwrap();
    assert_eq!(weak_gateway.strong_count(), 1);

    // Keep transfer at the region gate after its source gateway is upgraded.
    // The source Cx then disappears before prepare_transfer can return, making
    // the transfer's temporary Arc responsible for the notifier captures.
    let (transfer, retained) = lab
        .state
        .region(source.region_id())
        .unwrap()
        .with_obligation_accounting(|_, _| {
            let transfer = std::thread::spawn(move || {
                let result = lease.try_transfer(&target);
                (result, lease)
            });
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while weak_gateway.strong_count() == 1 && std::time::Instant::now() < deadline {
                std::thread::yield_now();
            }
            let retained = weak_gateway.strong_count() > 1;
            drop(custom_source);
            (transfer, retained)
        });
    let (result, lease) = transfer.join().unwrap();
    let cleanup = lease.abort();
    assert!(retained, "the transfer never reached its source-gateway upgrade");
    result.unwrap();
    cleanup.unwrap();
    assert_eq!(
        *unlocked.lock(),
        Some(true),
        "last-owner destruction of notifier captures ran under the registry lock"
    );
    assert_eq!(weak_gateway.strong_count(), 0);
    assert_eq!(names.whereis("service"), None);

    flush(&mut lab);
    lab.scheduler.lock().schedule(target_id, 0);
    let _steps = lab.run_until_idle();
    assert!(target_handle.try_join().unwrap().is_some());
    finish(lab, &source, source_handle, 1);
}
