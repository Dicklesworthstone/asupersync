//! Cross-module obligation lifecycle coverage for registry, cancellation, and ledger drains.

use asupersync::cancel::symbol_cancel::SymbolCancelToken;
use asupersync::cx::registry::{NameCollisionPolicy, NameLeaseError, NameRegistry};
use asupersync::obligation::ledger::{LedgerError, ObligationLedger};
use asupersync::record::{ObligationAbortReason, ObligationKind};
use asupersync::types::{CancelKind, CancelReason, ObjectId, RegionId, TaskId, Time};
use asupersync::util::DetRng;
use std::sync::{Arc, Barrier, Mutex};

fn region(index: u32) -> RegionId {
    RegionId::new_for_test(index, 0)
}

fn task(index: u32) -> TaskId {
    TaskId::new_for_test(index, 0)
}

fn at(nanos: u64) -> Time {
    Time::from_nanos(nanos)
}

fn reason(
    kind: CancelKind,
    origin_region: RegionId,
    origin_task: TaskId,
    now: Time,
) -> CancelReason {
    CancelReason::with_origin(kind, origin_region, now).with_task(origin_task)
}

#[test]
fn cx_name_lease_cancel_aborts_tracked_obligation() {
    let mut registry = NameRegistry::new();
    let mut ledger = ObligationLedger::new();
    let owner_region = region(10);
    let owner_task = task(11);

    let mut lease = registry
        .register("session/alpha", owner_task, owner_region, at(10))
        .expect("name lease should register");
    let token = ledger.acquire(ObligationKind::Lease, owner_task, owner_region, at(10));

    assert_eq!(registry.whereis("session/alpha"), Some(owner_task));
    assert_eq!(token.kind(), ObligationKind::Lease);
    assert_eq!(token.holder(), owner_task);
    assert_eq!(token.region(), owner_region);
    assert_eq!(ledger.pending_for_region(owner_region), 1);
    assert_eq!(ledger.pending_for_task(owner_task), 1);

    let mut rng = DetRng::new(0xace1);
    let cancel_token = SymbolCancelToken::new(ObjectId::new_for_test(1), &mut rng);
    let cancel_reason = reason(CancelKind::Timeout, owner_region, owner_task, at(20));

    assert!(cancel_token.cancel(&cancel_reason, at(20)));
    assert!(cancel_token.is_cancelled());
    assert_eq!(
        cancel_token.reason().expect("cancel reason").kind,
        CancelKind::Timeout
    );

    registry
        .unregister_owned_and_grant(&lease, at(21))
        .expect("cancel drain should remove active registry lease");
    lease.abort().expect("cancel drain should abort name lease");
    let held_for = ledger.abort(token, at(22), ObligationAbortReason::Cancel);

    assert_eq!(held_for, 12);
    assert!(!registry.is_registered("session/alpha"));
    assert!(registry.is_empty());
    assert!(ledger.is_region_clean(owner_region));
    assert!(ledger.check_leaks().is_clean());

    let stats = ledger.stats();
    assert_eq!(stats.total_acquired, 1);
    assert_eq!(stats.total_aborted, 1);
    assert!(stats.is_clean());
}

#[test]
fn hierarchical_cancel_chain_drains_ledger_regions_by_id() {
    let mut ledger = ObligationLedger::new();
    let parent_region = region(20);
    let child_region = region(21);
    let leaf_region = region(22);
    let parent_task = task(20);
    let child_task = task(21);
    let leaf_task = task(22);

    let parent_token = ledger.acquire(
        ObligationKind::SendPermit,
        parent_task,
        parent_region,
        at(1),
    );
    let child_token = ledger.acquire(ObligationKind::Ack, child_task, child_region, at(2));
    let leaf_token = ledger.acquire(ObligationKind::Lease, leaf_task, leaf_region, at(3));
    let pending_ids = [parent_token.id(), child_token.id(), leaf_token.id()];

    assert_eq!(ledger.pending_count(), 3);
    assert_eq!(
        ledger.pending_ids_for_region(parent_region),
        vec![pending_ids[0]]
    );
    assert_eq!(
        ledger.pending_ids_for_region(child_region),
        vec![pending_ids[1]]
    );
    assert_eq!(
        ledger.pending_ids_for_region(leaf_region),
        vec![pending_ids[2]]
    );

    let mut rng = DetRng::new(0x5eed);
    let root_cancel = SymbolCancelToken::new(ObjectId::new_for_test(2), &mut rng);
    let child_cancel = root_cancel.child(&mut rng);
    let leaf_cancel = child_cancel.child(&mut rng);
    let shutdown = reason(CancelKind::Shutdown, parent_region, parent_task, at(10));

    assert!(root_cancel.cancel(&shutdown, at(10)));
    assert_eq!(
        root_cancel.reason().expect("root reason").kind,
        CancelKind::Shutdown
    );
    assert_eq!(
        child_cancel.reason().expect("child reason").kind,
        CancelKind::ParentCancelled
    );
    assert_eq!(
        leaf_cancel.reason().expect("leaf reason").kind,
        CancelKind::ParentCancelled
    );

    for (drain_region, drain_at) in [(leaf_region, 11), (child_region, 12), (parent_region, 13)] {
        for obligation in ledger.pending_ids_for_region(drain_region) {
            ledger
                .try_abort_by_id(obligation, at(drain_at), ObligationAbortReason::Cancel)
                .expect("cancel drain should tolerate ID-based resolution");
        }
    }

    assert!(ledger.is_region_clean(parent_region));
    assert!(ledger.is_region_clean(child_region));
    assert!(ledger.is_region_clean(leaf_region));
    assert!(ledger.check_leaks().is_clean());

    let stats = ledger.stats();
    assert_eq!(stats.total_acquired, 3);
    assert_eq!(stats.total_aborted, 3);
    assert!(stats.is_clean());
}

#[test]
fn resource_exhaustion_cleans_registry_and_rejects_late_ledger_acquire() {
    let mut registry = NameRegistry::new();
    let mut ledger = ObligationLedger::new();
    let owner_region = region(30);
    let owner_task = task(30);
    let waiter_region = region(31);
    let waiter_task = task(31);

    let mut lease = registry
        .register("scarce/name", owner_task, owner_region, at(10))
        .expect("initial scarce resource owner should register");
    let token = ledger.acquire(ObligationKind::Lease, owner_task, owner_region, at(10));

    let wait_result = registry.register_with_policy(
        "scarce/name",
        waiter_task,
        waiter_region,
        at(30),
        NameCollisionPolicy::Wait { deadline: at(20) },
    );
    assert!(matches!(
        wait_result,
        Err(NameLeaseError::WaitBudgetExceeded { name }) if name == "scarce/name"
    ));
    assert_eq!(registry.waiter_count(), 0);

    let mut rng = DetRng::new(0xface);
    let cancel_token = SymbolCancelToken::new(ObjectId::new_for_test(3), &mut rng);
    let resource_failure = reason(
        CancelKind::ResourceUnavailable,
        owner_region,
        owner_task,
        at(31),
    );

    assert!(cancel_token.cancel(&resource_failure, at(31)));
    registry
        .unregister_owned_and_grant(&lease, at(32))
        .expect("resource cleanup should remove active registry lease");
    lease
        .abort()
        .expect("resource cleanup should abort name lease");
    ledger.abort(token, at(33), ObligationAbortReason::Cancel);
    ledger.mark_region_finalized(owner_region);

    let late = ledger.try_acquire(ObligationKind::Lease, owner_task, owner_region, at(34));
    assert!(matches!(
        late,
        Err(LedgerError::RegionFinalized {
            region,
            ..
        }) if region == owner_region
    ));
    assert!(!registry.is_registered("scarce/name"));
    assert!(ledger.is_region_finalized(owner_region));
    assert!(ledger.stats().is_clean());
}

#[test]
fn concurrent_registry_cancel_and_ledger_abort_paths_converge_cleanly() {
    let registry = Arc::new(Mutex::new(NameRegistry::new()));
    let ledger = Arc::new(Mutex::new(ObligationLedger::new()));
    let barrier = Arc::new(Barrier::new(2));

    let mut rng = DetRng::new(0xcafe);
    let cancel_a = SymbolCancelToken::new(ObjectId::new_for_test(40), &mut rng);
    let cancel_b = SymbolCancelToken::new(ObjectId::new_for_test(41), &mut rng);

    let mut handles = Vec::new();
    for (name, owner_region, owner_task, cancel_token, base_time) in [
        ("task/a", region(40), task(40), cancel_a, 100),
        ("task/b", region(41), task(41), cancel_b, 200),
    ] {
        let registry = Arc::clone(&registry);
        let ledger = Arc::clone(&ledger);
        let barrier = Arc::clone(&barrier);

        handles.push(std::thread::spawn(move || {
            let mut lease = registry
                .lock()
                .expect("registry mutex should not be poisoned")
                .register(name, owner_task, owner_region, at(base_time))
                .expect("unique name should register");
            let token = ledger
                .lock()
                .expect("ledger mutex should not be poisoned")
                .acquire(
                    ObligationKind::Lease,
                    owner_task,
                    owner_region,
                    at(base_time),
                );

            barrier.wait();

            let cancel_reason = reason(
                CancelKind::ParentCancelled,
                owner_region,
                owner_task,
                at(base_time + 10),
            );
            cancel_token.cancel(&cancel_reason, at(base_time + 10));
            registry
                .lock()
                .expect("registry mutex should not be poisoned")
                .unregister_owned_and_grant(&lease, at(base_time + 11))
                .expect("owner should remove its own lease during cleanup");
            lease
                .abort()
                .expect("cancel cleanup should abort name lease");
            ledger
                .lock()
                .expect("ledger mutex should not be poisoned")
                .abort(token, at(base_time + 12), ObligationAbortReason::Cancel);
        }));
    }

    for handle in handles {
        handle.join().expect("worker should complete cleanly");
    }

    let registry = registry
        .lock()
        .expect("registry mutex should not be poisoned");
    assert!(registry.is_empty());

    let ledger = ledger.lock().expect("ledger mutex should not be poisoned");
    let stats = ledger.stats();
    assert_eq!(stats.total_acquired, 2);
    assert_eq!(stats.total_aborted, 2);
    assert!(stats.is_clean());
    assert!(ledger.check_leaks().is_clean());
}
