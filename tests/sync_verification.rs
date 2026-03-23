#![allow(missing_docs)]

mod common;

use asupersync::cx::Cx;
use asupersync::lab::{
    CancellationRecord, DualRunHarness, DualRunScenarioIdentity, LabConfig, LabRuntime,
    LoserDrainRecord, NormalizedSemantics, ObligationBalanceRecord, ResourceSurfaceRecord,
    SeedPlan, TerminalOutcome, assert_dual_run_passes, capture_region_close, run_live_adapter,
};
use asupersync::runtime::{Runtime, RuntimeBuilder, yield_now};
use asupersync::sync::{AcquireError, GenericPool, Mutex, Pool, PoolConfig, Semaphore};
use asupersync::types::Budget;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

const MUTEX_EXCLUSION_CONTRACT_VERSION: &str = "sync.mutex.exclusion.v1";
const SEMAPHORE_CANCEL_RECOVERY_CONTRACT_VERSION: &str = "sync.semaphore.cancel_recovery.v1";
const POOL_WAITER_HANDOFF_CONTRACT_VERSION: &str = "sync.pool.waiter_handoff.v1";
const MUTEX_WAITER_TASKS: usize = 2;
const POOL_WAITER_TASKS: usize = 2;

fn counter_i64(value: usize) -> i64 {
    i64::try_from(value).expect("sync verification counters should fit in i64")
}

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
                .with_counter(
                    "waiters_before_release",
                    counter_i64(self.waiters_before_release),
                )
                .with_counter("lock_acquisitions", counter_i64(self.lock_acquisitions))
                .with_counter("tasks_completed", counter_i64(self.tasks_completed))
                .with_counter("max_inflight", counter_i64(self.max_inflight))
                .with_counter("final_value", counter_i64(self.final_value)),
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
                .with_counter("cancelled_waiters", counter_i64(self.cancelled_waiters))
                .with_counter(
                    "recovered_acquisitions",
                    counter_i64(self.recovered_acquisitions),
                )
                .with_counter(
                    "available_after_cancel",
                    counter_i64(self.available_after_cancel),
                )
                .with_counter(
                    "final_available_permits",
                    counter_i64(self.final_available_permits),
                ),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PoolObservation {
    waiters_before_release: usize,
    waiters_after_first_handoff: usize,
    active_after_first_handoff: usize,
    waiters_after_second_handoff: usize,
    active_after_second_handoff: usize,
    total_acquisitions: usize,
    tasks_completed: usize,
    final_waiters: usize,
    final_active: usize,
    final_idle: usize,
    final_total: usize,
}

impl PoolObservation {
    fn to_semantics(self) -> NormalizedSemantics {
        NormalizedSemantics {
            terminal_outcome: TerminalOutcome::ok(),
            cancellation: CancellationRecord::none(),
            loser_drain: LoserDrainRecord::not_applicable(),
            region_close: capture_region_close(true, true),
            obligation_balance: ObligationBalanceRecord::zero(),
            resource_surface: ResourceSurfaceRecord::empty("sync.pool.waiter_handoff")
                .with_counter(
                    "waiters_before_release",
                    counter_i64(self.waiters_before_release),
                )
                .with_counter(
                    "waiters_after_first_handoff",
                    counter_i64(self.waiters_after_first_handoff),
                )
                .with_counter(
                    "active_after_first_handoff",
                    counter_i64(self.active_after_first_handoff),
                )
                .with_counter(
                    "waiters_after_second_handoff",
                    counter_i64(self.waiters_after_second_handoff),
                )
                .with_counter(
                    "active_after_second_handoff",
                    counter_i64(self.active_after_second_handoff),
                )
                .with_counter("total_acquisitions", counter_i64(self.total_acquisitions))
                .with_counter("tasks_completed", counter_i64(self.tasks_completed))
                .with_counter("final_waiters", counter_i64(self.final_waiters))
                .with_counter("final_active", counter_i64(self.final_active))
                .with_counter("final_idle", counter_i64(self.final_idle))
                .with_counter("final_total", counter_i64(self.final_total)),
        }
    }
}

type PoolFactoryFuture = Pin<Box<dyn Future<Output = Result<u32, std::io::Error>> + Send>>;
type TestPool = GenericPool<u32, fn() -> PoolFactoryFuture>;

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

fn pool_identity() -> DualRunScenarioIdentity {
    sync_identity(
        "phase1.sync.pool.waiter_handoff",
        "sync.pool.waiter_handoff",
        POOL_WAITER_HANDOFF_CONTRACT_VERSION,
        "Pool differential pilot preserves one-at-a-time waiter wakeup and return accounting",
        0x51A0_C021,
    )
}

fn pool_factory() -> PoolFactoryFuture {
    Box::pin(async { Ok(42u32) })
}

fn make_test_pool() -> TestPool {
    GenericPool::new(pool_factory, PoolConfig::with_max_size(1))
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

        let recovered_acquisitions = semaphore.try_acquire(1).map_or(0, |permit| {
            drop(permit);
            1usize
        });

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
    let recovered_acquisitions = semaphore.try_acquire(1).map_or(0, |permit| {
        drop(permit);
        1usize
    });

    SemaphoreObservation {
        cancelled_waiters: cancelled_waiters.load(Ordering::SeqCst),
        recovered_acquisitions,
        available_after_cancel,
        final_available_permits: semaphore.available_permits(),
    }
}

fn live_pool_observation() -> PoolObservation {
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("build live current-thread runtime");
    runtime.block_on(runtime.handle().spawn(async {
        let handle = Runtime::current_handle().expect("runtime handle inside live pool pilot");
        let pool = Arc::new(make_test_pool());
        let seed_cx = Cx::for_testing();
        let held = pool.acquire(&seed_cx).await.expect("seeded pool acquire");
        let total_acquisitions = Arc::new(AtomicUsize::new(0));
        let tasks_completed = Arc::new(AtomicUsize::new(0));
        let release_first_handoff = Arc::new(AtomicUsize::new(0));
        let waiters_after_first_handoff = Arc::new(AtomicUsize::new(0));
        let active_after_first_handoff = Arc::new(AtomicUsize::new(0));
        let waiters_after_second_handoff = Arc::new(AtomicUsize::new(0));
        let active_after_second_handoff = Arc::new(AtomicUsize::new(0));
        let mut joins = Vec::new();

        for _ in 0..POOL_WAITER_TASKS {
            let pool = Arc::clone(&pool);
            let total_acquisitions = Arc::clone(&total_acquisitions);
            let tasks_completed = Arc::clone(&tasks_completed);
            let release_first_handoff = Arc::clone(&release_first_handoff);
            let waiters_after_first_handoff = Arc::clone(&waiters_after_first_handoff);
            let active_after_first_handoff = Arc::clone(&active_after_first_handoff);
            let waiters_after_second_handoff = Arc::clone(&waiters_after_second_handoff);
            let active_after_second_handoff = Arc::clone(&active_after_second_handoff);
            joins.push(handle.spawn(async move {
                let cx = Cx::for_testing();
                let acquired = pool
                    .acquire(&cx)
                    .await
                    .expect("pool waiter acquires resource");
                let order = total_acquisitions.fetch_add(1, Ordering::SeqCst) + 1;
                let stats = pool.stats();
                if order == 1 {
                    waiters_after_first_handoff.store(stats.waiters, Ordering::SeqCst);
                    active_after_first_handoff.store(stats.active, Ordering::SeqCst);
                    while release_first_handoff.load(Ordering::SeqCst) == 0 {
                        yield_now().await;
                    }
                } else {
                    waiters_after_second_handoff.store(stats.waiters, Ordering::SeqCst);
                    active_after_second_handoff.store(stats.active, Ordering::SeqCst);
                }
                drop(acquired);
                tasks_completed.fetch_add(1, Ordering::SeqCst);
            }));
        }

        let mut spins = 0usize;
        while pool.stats().waiters < POOL_WAITER_TASKS && spins < 64 {
            yield_now().await;
            spins += 1;
        }
        let waiters_before_release = pool.stats().waiters;
        drop(held);

        let mut spins = 0usize;
        while total_acquisitions.load(Ordering::SeqCst) < 1 && spins < 128 {
            yield_now().await;
            spins += 1;
        }
        release_first_handoff.store(1, Ordering::SeqCst);

        for join in joins {
            join.await;
        }

        let final_stats = pool.stats();
        PoolObservation {
            waiters_before_release,
            waiters_after_first_handoff: waiters_after_first_handoff.load(Ordering::SeqCst),
            active_after_first_handoff: active_after_first_handoff.load(Ordering::SeqCst),
            waiters_after_second_handoff: waiters_after_second_handoff.load(Ordering::SeqCst),
            active_after_second_handoff: active_after_second_handoff.load(Ordering::SeqCst),
            total_acquisitions: total_acquisitions.load(Ordering::SeqCst),
            tasks_completed: tasks_completed.load(Ordering::SeqCst),
            final_waiters: final_stats.waiters,
            final_active: final_stats.active,
            final_idle: final_stats.idle,
            final_total: final_stats.total,
        }
    }))
}

fn lab_pool_observation(seed: u64) -> PoolObservation {
    let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(4_000));
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let pool = Arc::new(make_test_pool());
    let held = futures_lite::future::block_on(pool.acquire(&Cx::for_testing()))
        .expect("seeded lab pool acquire");
    let total_acquisitions = Arc::new(AtomicUsize::new(0));
    let tasks_completed = Arc::new(AtomicUsize::new(0));
    let release_first_handoff = Arc::new(AtomicUsize::new(0));
    let waiters_after_first_handoff = Arc::new(AtomicUsize::new(0));
    let active_after_first_handoff = Arc::new(AtomicUsize::new(0));
    let waiters_after_second_handoff = Arc::new(AtomicUsize::new(0));
    let active_after_second_handoff = Arc::new(AtomicUsize::new(0));

    for _ in 0..POOL_WAITER_TASKS {
        let pool = Arc::clone(&pool);
        let total_acquisitions = Arc::clone(&total_acquisitions);
        let tasks_completed = Arc::clone(&tasks_completed);
        let release_first_handoff = Arc::clone(&release_first_handoff);
        let waiters_after_first_handoff = Arc::clone(&waiters_after_first_handoff);
        let active_after_first_handoff = Arc::clone(&active_after_first_handoff);
        let waiters_after_second_handoff = Arc::clone(&waiters_after_second_handoff);
        let active_after_second_handoff = Arc::clone(&active_after_second_handoff);
        let (task_id, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                let cx = Cx::for_testing();
                let acquired = pool
                    .acquire(&cx)
                    .await
                    .expect("pool waiter acquires resource");
                let order = total_acquisitions.fetch_add(1, Ordering::SeqCst) + 1;
                let stats = pool.stats();
                if order == 1 {
                    waiters_after_first_handoff.store(stats.waiters, Ordering::SeqCst);
                    active_after_first_handoff.store(stats.active, Ordering::SeqCst);
                    while release_first_handoff.load(Ordering::SeqCst) == 0 {
                        yield_now().await;
                    }
                } else {
                    waiters_after_second_handoff.store(stats.waiters, Ordering::SeqCst);
                    active_after_second_handoff.store(stats.active, Ordering::SeqCst);
                }
                drop(acquired);
                tasks_completed.fetch_add(1, Ordering::SeqCst);
            })
            .expect("create lab pool task");
        runtime.scheduler.lock().schedule(task_id, 0);
    }

    let mut steps = 0usize;
    while pool.stats().waiters < POOL_WAITER_TASKS && steps < 64 {
        runtime.step_for_test();
        steps += 1;
    }
    let waiters_before_release = pool.stats().waiters;
    drop(held);

    let mut steps = 0usize;
    while total_acquisitions.load(Ordering::SeqCst) < 1 && steps < 256 {
        runtime.step_for_test();
        steps += 1;
    }
    release_first_handoff.store(1, Ordering::SeqCst);
    runtime.run_until_quiescent();

    let violations = runtime.check_invariants();
    assert!(
        violations.is_empty(),
        "lab pool pilot invariants violated: {violations:?}"
    );

    let final_stats = pool.stats();
    PoolObservation {
        waiters_before_release,
        waiters_after_first_handoff: waiters_after_first_handoff.load(Ordering::SeqCst),
        active_after_first_handoff: active_after_first_handoff.load(Ordering::SeqCst),
        waiters_after_second_handoff: waiters_after_second_handoff.load(Ordering::SeqCst),
        active_after_second_handoff: active_after_second_handoff.load(Ordering::SeqCst),
        total_acquisitions: total_acquisitions.load(Ordering::SeqCst),
        tasks_completed: tasks_completed.load(Ordering::SeqCst),
        final_waiters: final_stats.waiters,
        final_active: final_stats.active,
        final_idle: final_stats.idle,
        final_total: final_stats.total,
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
            counter_i64(observation.waiters_before_release),
        );
        witness.record_counter(
            "lock_acquisitions",
            counter_i64(observation.lock_acquisitions),
        );
        witness.record_counter("tasks_completed", counter_i64(observation.tasks_completed));
        witness.record_counter("max_inflight", counter_i64(observation.max_inflight));
        witness.record_counter("final_value", counter_i64(observation.final_value));
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
        witness.record_counter(
            "cancelled_waiters",
            counter_i64(observation.cancelled_waiters),
        );
        witness.record_counter(
            "recovered_acquisitions",
            counter_i64(observation.recovered_acquisitions),
        );
        witness.record_counter(
            "available_after_cancel",
            counter_i64(observation.available_after_cancel),
        );
        witness.record_counter(
            "final_available_permits",
            counter_i64(observation.final_available_permits),
        );
    })
}

fn make_pool_live_result(identity: &DualRunScenarioIdentity) -> asupersync::lab::LiveRunResult {
    run_live_adapter(identity, |_config, witness| {
        let observation = live_pool_observation();
        witness.set_outcome(TerminalOutcome::ok());
        witness.set_region_close(capture_region_close(true, true));
        witness.set_obligation_balance(ObligationBalanceRecord::zero());
        witness.record_counter(
            "waiters_before_release",
            counter_i64(observation.waiters_before_release),
        );
        witness.record_counter(
            "waiters_after_first_handoff",
            counter_i64(observation.waiters_after_first_handoff),
        );
        witness.record_counter(
            "active_after_first_handoff",
            counter_i64(observation.active_after_first_handoff),
        );
        witness.record_counter(
            "waiters_after_second_handoff",
            counter_i64(observation.waiters_after_second_handoff),
        );
        witness.record_counter(
            "active_after_second_handoff",
            counter_i64(observation.active_after_second_handoff),
        );
        witness.record_counter(
            "total_acquisitions",
            counter_i64(observation.total_acquisitions),
        );
        witness.record_counter("tasks_completed", counter_i64(observation.tasks_completed));
        witness.record_counter("final_waiters", counter_i64(observation.final_waiters));
        witness.record_counter("final_active", counter_i64(observation.final_active));
        witness.record_counter("final_idle", counter_i64(observation.final_idle));
        witness.record_counter("final_total", counter_i64(observation.final_total));
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
        counter_i64(MUTEX_WAITER_TASKS)
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

#[test]
fn pool_dual_run_pilot_preserves_one_at_a_time_waiter_handoff() {
    common::init_test_logging();
    let identity = pool_identity();
    let live_result = make_pool_live_result(&identity);

    let result = DualRunHarness::from_identity(identity)
        .lab(move |config| lab_pool_observation(config.seed).to_semantics())
        .live_result(move |_seed, _entropy| live_result)
        .run();

    assert_dual_run_passes(&result);
    assert_eq!(
        result.live.semantics.resource_surface.counters["waiters_before_release"],
        counter_i64(POOL_WAITER_TASKS)
    );
    assert_eq!(
        result.live.semantics.resource_surface.counters["waiters_after_first_handoff"],
        1
    );
    assert_eq!(
        result.live.semantics.resource_surface.counters["active_after_first_handoff"],
        1
    );
    assert_eq!(
        result.live.semantics.resource_surface.counters["waiters_after_second_handoff"],
        0
    );
    assert_eq!(
        result.live.semantics.resource_surface.counters["active_after_second_handoff"],
        1
    );
    assert_eq!(
        result.live.semantics.resource_surface.counters["total_acquisitions"],
        counter_i64(POOL_WAITER_TASKS)
    );
    assert_eq!(
        result.live.semantics.resource_surface.counters["tasks_completed"],
        counter_i64(POOL_WAITER_TASKS)
    );
    assert_eq!(
        result.live.semantics.resource_surface.counters["final_waiters"],
        0
    );
    assert_eq!(
        result.live.semantics.resource_surface.counters["final_active"],
        0
    );
    assert_eq!(
        result.live.semantics.resource_surface.counters["final_idle"],
        1
    );
    assert_eq!(
        result.live.semantics.resource_surface.counters["final_total"],
        1
    );
}
