#![allow(missing_docs)]

mod common;

use asupersync::cx::Cx;
use asupersync::lab::{
    CancellationRecord, DualRunHarness, DualRunScenarioIdentity, LabConfig, LabRuntime,
    LoserDrainRecord, NormalizedSemantics, ObligationBalanceRecord, ResourceSurfaceRecord,
    SeedPlan, TerminalOutcome, assert_dual_run_passes, capture_region_close, run_live_adapter,
};
use asupersync::runtime::{Runtime, RuntimeBuilder, yield_now};
use asupersync::sync::{AcquireError, Mutex, Semaphore};
use asupersync::types::Budget;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

const MUTEX_EXCLUSION_CONTRACT_VERSION: &str = "sync.mutex.exclusion.v1";
const SEMAPHORE_CANCEL_RECOVERY_CONTRACT_VERSION: &str = "sync.semaphore.cancel_recovery.v1";
const MUTEX_WAITER_TASKS: usize = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MutexObservation {
    waiters_before_release: usize,
    lock_acquisitions: usize,
    tasks_completed: usize,
    max_inflight: usize,
    final_value: usize,
}

impl MutexObservation {
    fn to_semantics(self) -> NormalizedSemantics {
        NormalizedSemantics {
            terminal_outcome: TerminalOutcome::ok(),
            cancellation: CancellationRecord::none(),
            loser_drain: LoserDrainRecord::not_applicable(),
            region_close: capture_region_close(true, true),
            obligation_balance: ObligationBalanceRecord::zero(),
            resource_surface: ResourceSurfaceRecord::empty("sync.mutex.exclusion")
                .with_counter("waiters_before_release", self.waiters_before_release as i64)
                .with_counter("lock_acquisitions", self.lock_acquisitions as i64)
                .with_counter("tasks_completed", self.tasks_completed as i64)
                .with_counter("max_inflight", self.max_inflight as i64)
                .with_counter("final_value", self.final_value as i64),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SemaphoreObservation {
    cancelled_waiters: usize,
    recovered_acquisitions: usize,
    available_after_cancel: usize,
    final_available_permits: usize,
}

impl SemaphoreObservation {
    fn to_semantics(self) -> NormalizedSemantics {
        NormalizedSemantics {
            terminal_outcome: TerminalOutcome::ok(),
            cancellation: CancellationRecord::none(),
            loser_drain: LoserDrainRecord::not_applicable(),
            region_close: capture_region_close(true, true),
            obligation_balance: ObligationBalanceRecord::zero(),
            resource_surface: ResourceSurfaceRecord::empty("sync.semaphore.cancel_recovery")
                .with_counter("cancelled_waiters", self.cancelled_waiters as i64)
                .with_counter("recovered_acquisitions", self.recovered_acquisitions as i64)
                .with_counter("available_after_cancel", self.available_after_cancel as i64)
                .with_counter(
                    "final_available_permits",
                    self.final_available_permits as i64,
                ),
        }
    }
}

fn sync_identity(
    scenario_id: &str,
    surface_id: &str,
    surface_contract_version: &str,
    description: &str,
    seed: u64,
) -> DualRunScenarioIdentity {
    let seed_plan = SeedPlan::inherit(seed, format!("seed.{scenario_id}.v1"));
    DualRunScenarioIdentity::phase1(
        scenario_id,
        surface_id,
        surface_contract_version,
        description,
        seed_plan.canonical_seed,
    )
    .with_seed_plan(seed_plan)
}

fn mutex_identity() -> DualRunScenarioIdentity {
    sync_identity(
        "phase1.sync.mutex.exclusion",
        "sync.mutex.exclusion",
        MUTEX_EXCLUSION_CONTRACT_VERSION,
        "Mutex differential pilot preserves exclusion and waiter accounting",
        0x51A0_C001,
    )
}

fn semaphore_identity() -> DualRunScenarioIdentity {
    sync_identity(
        "phase1.sync.semaphore.cancel_recovery",
        "sync.semaphore.cancel_recovery",
        SEMAPHORE_CANCEL_RECOVERY_CONTRACT_VERSION,
        "Semaphore differential pilot preserves waiter cancellation cleanup and permit recovery",
        0x51A0_C011,
    )
}

fn live_mutex_observation() -> MutexObservation {
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("build live current-thread runtime");
    runtime.block_on(runtime.handle().spawn(async {
        let handle = Runtime::current_handle().expect("runtime handle inside live mutex pilot");
        let mutex = Arc::new(Mutex::new(0usize));
        let initial_guard = mutex.try_lock().expect("seeded mutex lock");
        let lock_acquisitions = Arc::new(AtomicUsize::new(0));
        let tasks_completed = Arc::new(AtomicUsize::new(0));
        let inflight = Arc::new(AtomicUsize::new(0));
        let max_inflight = Arc::new(AtomicUsize::new(0));
        let mut joins = Vec::new();

        for _ in 0..MUTEX_WAITER_TASKS {
            let mutex = Arc::clone(&mutex);
            let lock_acquisitions = Arc::clone(&lock_acquisitions);
            let tasks_completed = Arc::clone(&tasks_completed);
            let inflight = Arc::clone(&inflight);
            let max_inflight = Arc::clone(&max_inflight);
            joins.push(handle.spawn(async move {
                let cx = Cx::for_testing();
                let mut guard = mutex.lock(&cx).await.expect("mutex waiter acquires lock");
                let current = inflight.fetch_add(1, Ordering::SeqCst) + 1;
                max_inflight.fetch_max(current, Ordering::SeqCst);
                *guard += 1;
                lock_acquisitions.fetch_add(1, Ordering::SeqCst);
                yield_now().await;
                inflight.fetch_sub(1, Ordering::SeqCst);
                tasks_completed.fetch_add(1, Ordering::SeqCst);
            }));
        }

        let mut spins = 0usize;
        while mutex.waiters() < MUTEX_WAITER_TASKS && spins < 32 {
            yield_now().await;
            spins += 1;
        }
        let waiters_before_release = mutex.waiters();
        drop(initial_guard);

        for join in joins {
            join.await;
        }

        let final_value = {
            let guard = mutex.try_lock().expect("final mutex lock");
            *guard
        };

        MutexObservation {
            waiters_before_release,
            lock_acquisitions: lock_acquisitions.load(Ordering::SeqCst),
            tasks_completed: tasks_completed.load(Ordering::SeqCst),
            max_inflight: max_inflight.load(Ordering::SeqCst),
            final_value,
        }
    }))
}

fn lab_mutex_observation(seed: u64) -> MutexObservation {
    let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(2_000));
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let mutex = Arc::new(Mutex::new(0usize));
    let initial_guard = mutex.try_lock().expect("seeded mutex lock");
    let lock_acquisitions = Arc::new(AtomicUsize::new(0));
    let tasks_completed = Arc::new(AtomicUsize::new(0));
    let inflight = Arc::new(AtomicUsize::new(0));
    let max_inflight = Arc::new(AtomicUsize::new(0));

    for _ in 0..MUTEX_WAITER_TASKS {
        let mutex = Arc::clone(&mutex);
        let lock_acquisitions = Arc::clone(&lock_acquisitions);
        let tasks_completed = Arc::clone(&tasks_completed);
        let inflight = Arc::clone(&inflight);
        let max_inflight = Arc::clone(&max_inflight);
        let (task_id, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                let cx = Cx::for_testing();
                let mut guard = mutex.lock(&cx).await.expect("mutex waiter acquires lock");
                let current = inflight.fetch_add(1, Ordering::SeqCst) + 1;
                max_inflight.fetch_max(current, Ordering::SeqCst);
                *guard += 1;
                lock_acquisitions.fetch_add(1, Ordering::SeqCst);
                yield_now().await;
                inflight.fetch_sub(1, Ordering::SeqCst);
                tasks_completed.fetch_add(1, Ordering::SeqCst);
            })
            .expect("create lab mutex task");
        runtime.scheduler.lock().schedule(task_id, 0);
    }

    let mut steps = 0usize;
    while mutex.waiters() < MUTEX_WAITER_TASKS && steps < 32 {
        runtime.step_for_test();
        steps += 1;
    }
    let waiters_before_release = mutex.waiters();
    drop(initial_guard);

    runtime.run_until_quiescent();
    let violations = runtime.check_invariants();
    assert!(
        violations.is_empty(),
        "lab mutex pilot invariants violated: {violations:?}"
    );

    let final_value = {
        let guard = mutex.try_lock().expect("final mutex lock");
        *guard
    };

    MutexObservation {
        waiters_before_release,
        lock_acquisitions: lock_acquisitions.load(Ordering::SeqCst),
        tasks_completed: tasks_completed.load(Ordering::SeqCst),
        max_inflight: max_inflight.load(Ordering::SeqCst),
        final_value,
    }
}

fn live_semaphore_observation() -> SemaphoreObservation {
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("build live current-thread runtime");
    runtime.block_on(runtime.handle().spawn(async {
        let handle = Runtime::current_handle().expect("runtime handle inside live semaphore pilot");
        let semaphore = Arc::new(Semaphore::new(1));
        let held = semaphore.try_acquire(1).expect("seeded semaphore permit");
        let cancel_cx = Cx::for_testing();
        let waiter_cx = cancel_cx.clone();
        let cancelled_waiters = Arc::new(AtomicUsize::new(0));
        let waiter_result = Arc::clone(&cancelled_waiters);
        let semaphore_for_waiter = Arc::clone(&semaphore);

        let waiter = handle.spawn(async move {
            match semaphore_for_waiter.acquire(&waiter_cx, 1).await {
                Err(AcquireError::Cancelled) => {
                    waiter_result.fetch_add(1, Ordering::SeqCst);
                }
                Ok(_permit) => panic!("cancelled waiter unexpectedly acquired semaphore"),
                Err(err) => panic!("unexpected semaphore acquire error: {err:?}"),
            }
        });

        for _ in 0..8 {
            yield_now().await;
        }
        cancel_cx.set_cancel_requested(true);
        drop(held);
        waiter.await;
        let available_after_cancel = semaphore.available_permits();

        let recovered_acquisitions = semaphore
            .try_acquire(1)
            .map(|permit| {
                drop(permit);
                1usize
            })
            .unwrap_or(0);

        SemaphoreObservation {
            cancelled_waiters: cancelled_waiters.load(Ordering::SeqCst),
            recovered_acquisitions,
            available_after_cancel,
            final_available_permits: semaphore.available_permits(),
        }
    }))
}

fn lab_semaphore_observation(seed: u64) -> SemaphoreObservation {
    let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(2_000));
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let semaphore = Arc::new(Semaphore::new(1));
    let held = semaphore.try_acquire(1).expect("seeded semaphore permit");
    let cancel_cx = Cx::for_testing();
    let waiter_cx = cancel_cx.clone();
    let cancelled_waiters = Arc::new(AtomicUsize::new(0));

    let semaphore_for_waiter = Arc::clone(&semaphore);
    let waiter_result = Arc::clone(&cancelled_waiters);
    let (task_id, _) = runtime
        .state
        .create_task(region, Budget::INFINITE, async move {
            match semaphore_for_waiter.acquire(&waiter_cx, 1).await {
                Err(AcquireError::Cancelled) => {
                    waiter_result.fetch_add(1, Ordering::SeqCst);
                }
                Ok(_permit) => panic!("cancelled waiter unexpectedly acquired semaphore"),
                Err(err) => panic!("unexpected semaphore acquire error: {err:?}"),
            }
        })
        .expect("create lab semaphore task");
    runtime.scheduler.lock().schedule(task_id, 0);

    for _ in 0..8 {
        runtime.step_for_test();
    }
    cancel_cx.set_cancel_requested(true);
    drop(held);
    runtime.run_until_quiescent();

    let violations = runtime.check_invariants();
    assert!(
        violations.is_empty(),
        "lab semaphore pilot invariants violated: {violations:?}"
    );

    let available_after_cancel = semaphore.available_permits();
    let recovered_acquisitions = semaphore
        .try_acquire(1)
        .map(|permit| {
            drop(permit);
            1usize
        })
        .unwrap_or(0);

    SemaphoreObservation {
        cancelled_waiters: cancelled_waiters.load(Ordering::SeqCst),
        recovered_acquisitions,
        available_after_cancel,
        final_available_permits: semaphore.available_permits(),
    }
}

fn make_mutex_live_result(identity: &DualRunScenarioIdentity) -> asupersync::lab::LiveRunResult {
    run_live_adapter(identity, |_config, witness| {
        let observation = live_mutex_observation();
        witness.set_outcome(TerminalOutcome::ok());
        witness.set_region_close(capture_region_close(true, true));
        witness.set_obligation_balance(ObligationBalanceRecord::zero());
        witness.record_counter(
            "waiters_before_release",
            observation.waiters_before_release as i64,
        );
        witness.record_counter("lock_acquisitions", observation.lock_acquisitions as i64);
        witness.record_counter("tasks_completed", observation.tasks_completed as i64);
        witness.record_counter("max_inflight", observation.max_inflight as i64);
        witness.record_counter("final_value", observation.final_value as i64);
    })
}

fn make_semaphore_live_result(
    identity: &DualRunScenarioIdentity,
) -> asupersync::lab::LiveRunResult {
    run_live_adapter(identity, |_config, witness| {
        let observation = live_semaphore_observation();
        witness.set_outcome(TerminalOutcome::ok());
        witness.set_region_close(capture_region_close(true, true));
        witness.set_obligation_balance(ObligationBalanceRecord::zero());
        witness.record_counter("cancelled_waiters", observation.cancelled_waiters as i64);
        witness.record_counter(
            "recovered_acquisitions",
            observation.recovered_acquisitions as i64,
        );
        witness.record_counter(
            "available_after_cancel",
            observation.available_after_cancel as i64,
        );
        witness.record_counter(
            "final_available_permits",
            observation.final_available_permits as i64,
        );
    })
}

#[test]
fn mutex_dual_run_pilot_preserves_exclusion_and_waiter_accounting() {
    common::init_test_logging();
    let identity = mutex_identity();
    let live_result = make_mutex_live_result(&identity);

    let result = DualRunHarness::from_identity(identity)
        .lab(move |config| lab_mutex_observation(config.seed).to_semantics())
        .live_result(move |_seed, _entropy| live_result)
        .run();

    assert_dual_run_passes(&result);
    assert_eq!(
        result.live.semantics.resource_surface.counters["max_inflight"],
        1
    );
    assert_eq!(
        result.live.semantics.resource_surface.counters["waiters_before_release"],
        MUTEX_WAITER_TASKS as i64
    );
    assert_eq!(
        result.live.semantics.resource_surface.counters["final_value"],
        2
    );
}

#[test]
fn semaphore_dual_run_pilot_preserves_waiter_cancel_cleanup_and_permit_recovery() {
    common::init_test_logging();
    let identity = semaphore_identity();
    let live_result = make_semaphore_live_result(&identity);

    let result = DualRunHarness::from_identity(identity)
        .lab(move |config| lab_semaphore_observation(config.seed).to_semantics())
        .live_result(move |_seed, _entropy| live_result)
        .run();

    assert_dual_run_passes(&result);
    assert_eq!(
        result.live.semantics.resource_surface.counters["cancelled_waiters"],
        1
    );
    assert_eq!(
        result.live.semantics.resource_surface.counters["recovered_acquisitions"],
        1
    );
    assert_eq!(
        result.live.semantics.resource_surface.counters["available_after_cancel"],
        1
    );
    assert_eq!(
        result.live.semantics.resource_surface.counters["final_available_permits"],
        1
    );
}
