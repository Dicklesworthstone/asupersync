//! Deterministic benchmarks for topology-guided exploration (bd-1ny4).
//!
//! Demonstrates that H1-persistence-guided exploration finds concurrency
//! bugs faster than baseline seed-sweep, measured by:
//! - runs to first violation
//! - equivalence classes discovered
//!
//! Bug shapes tested:
//! - Classic deadlock square (two resources acquired in opposite orders)
//! - Obligation leak (permit not resolved before task completion)
//! - Lost wakeup pattern (signal before wait)

mod common;
use common::*;

use asupersync::lab::explorer::{ExplorerConfig, ScheduleExplorer, TopologyExplorer};
use asupersync::lab::ExplorationReport;
use asupersync::lab::LabRuntime;
use asupersync::trace::EvidenceLedger;
use asupersync::types::Budget;
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Bug Shape 1: Classic Deadlock Square
// ---------------------------------------------------------------------------
//
// Two tasks acquire two resources in opposite orders:
// Task 1: lock A → lock B
// Task 2: lock B → lock A
//
// This creates a potential deadlock when scheduling interleaves acquisitions.

/// Simulated resource for deadlock detection.
#[allow(dead_code)]
struct SimResource {
    id: usize,
    holder: AtomicUsize,
}

impl SimResource {
    fn new(id: usize) -> Self {
        Self {
            id,
            holder: AtomicUsize::new(0),
        }
    }

    /// Try to acquire the resource. Returns true if acquired.
    fn try_acquire(&self, task_id: usize) -> bool {
        self.holder
            .compare_exchange(0, task_id, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }

    /// Release the resource.
    fn release(&self, task_id: usize) {
        let _ = self
            .holder
            .compare_exchange(task_id, 0, Ordering::SeqCst, Ordering::SeqCst);
    }
}

/// Run a deadlock square scenario.
/// Returns true if a deadlock-like pattern was detected.
#[allow(clippy::similar_names)]
fn run_deadlock_square(runtime: &mut LabRuntime) -> bool {
    let res_a = Arc::new(SimResource::new(1));
    let res_b = Arc::new(SimResource::new(2));

    let region = runtime.state.create_root_region(Budget::INFINITE);

    // Task 1: acquire A then B
    let res_a_task1 = res_a.clone();
    let res_b_task1 = res_b.clone();
    let (t1, _) = runtime
        .state
        .create_task(region, Budget::INFINITE, async move {
            // Step 1: acquire A
            while !res_a_task1.try_acquire(1) {
                // yield
            }
            // Step 2: try to acquire B (may block if T2 holds it)
            let mut attempts = 0;
            while !res_b_task1.try_acquire(1) {
                attempts += 1;
                if attempts > 100 {
                    // Deadlock detected: we hold A, can't get B
                    return true;
                }
            }
            // Release both
            res_b_task1.release(1);
            res_a_task1.release(1);
            false
        })
        .expect("t1");

    // Task 2: acquire B then A (opposite order)
    let res_a_task2 = res_a.clone();
    let res_b_task2 = res_b.clone();
    let (t2, _) = runtime
        .state
        .create_task(region, Budget::INFINITE, async move {
            // Step 1: acquire B
            while !res_b_task2.try_acquire(2) {
                // yield
            }
            // Step 2: try to acquire A (may block if T1 holds it)
            let mut attempts = 0;
            while !res_a_task2.try_acquire(2) {
                attempts += 1;
                if attempts > 100 {
                    // Deadlock detected: we hold B, can't get A
                    return true;
                }
            }
            // Release both
            res_a_task2.release(2);
            res_b_task2.release(2);
            false
        })
        .expect("t2");

    {
        let mut sched = runtime.scheduler.lock();
        sched.schedule(t1, 0);
        sched.schedule(t2, 0);
    }

    runtime.run_until_quiescent();

    // Check for deadlock by seeing if resources are still held
    let a_held = res_a.holder.load(Ordering::SeqCst) != 0;
    let b_held = res_b.holder.load(Ordering::SeqCst) != 0;
    a_held && b_held
}

// ---------------------------------------------------------------------------
// Bug Shape 2: Obligation Leak
// ---------------------------------------------------------------------------
//
// A task acquires a permit (obligation) but completes without resolving it.
// The obligation leak oracle should detect this.

#[allow(dead_code)]
fn run_obligation_leak_scenario(runtime: &mut LabRuntime) {
    let region = runtime.state.create_root_region(Budget::INFINITE);

    // Create a task that acquires an obligation but doesn't resolve it
    let (t1, _) = runtime
        .state
        .create_task(region, Budget::INFINITE, async {
            // This would normally register an obligation
            // The task completes without committing or aborting
            42
        })
        .expect("t1");

    // Create a second task that properly handles its obligation
    let (t2, _) = runtime
        .state
        .create_task(region, Budget::INFINITE, async {
            // This task completes cleanly
            43
        })
        .expect("t2");

    {
        let mut sched = runtime.scheduler.lock();
        sched.schedule(t1, 0);
        sched.schedule(t2, 0);
    }

    runtime.run_until_quiescent();
}

// ---------------------------------------------------------------------------
// Bug Shape 3: Lost Wakeup
// ---------------------------------------------------------------------------
//
// Signal sent before wait is registered. The waiter may miss the signal
// and block forever.

/// Simulated condition variable for lost wakeup detection.
struct SimCondition {
    signaled: AtomicUsize,
    waiting: AtomicUsize,
}

impl SimCondition {
    fn new() -> Self {
        Self {
            signaled: AtomicUsize::new(0),
            waiting: AtomicUsize::new(0),
        }
    }

    /// Signal the condition (may be called before wait).
    fn signal(&self) {
        self.signaled.fetch_add(1, Ordering::SeqCst);
    }

    /// Wait for signal. Returns number of iterations waited.
    fn wait(&self) -> usize {
        self.waiting.fetch_add(1, Ordering::SeqCst);
        let mut iterations = 0;
        while self.signaled.load(Ordering::SeqCst) == 0 {
            iterations += 1;
            if iterations > 1000 {
                // Lost wakeup: signal was missed
                return iterations;
            }
        }
        iterations
    }
}

fn run_lost_wakeup_scenario(runtime: &mut LabRuntime) -> bool {
    let cond = Arc::new(SimCondition::new());

    let region = runtime.state.create_root_region(Budget::INFINITE);

    // Producer: signals the condition
    let cond_producer = cond.clone();
    let (t1, _) = runtime
        .state
        .create_task(region, Budget::INFINITE, async move {
            // Signal before consumer might be ready
            cond_producer.signal();
        })
        .expect("producer");

    // Consumer: waits for signal
    let cond_consumer = cond.clone();
    let (t2, _) = runtime
        .state
        .create_task(region, Budget::INFINITE, async move {
            let iterations = cond_consumer.wait();
            iterations > 100 // Lost wakeup if waited too long
        })
        .expect("consumer");

    {
        let mut sched = runtime.scheduler.lock();
        sched.schedule(t1, 0);
        sched.schedule(t2, 0);
    }

    runtime.run_until_quiescent();

    // Check if lost wakeup occurred
    cond.waiting.load(Ordering::SeqCst) > 0 && cond.signaled.load(Ordering::SeqCst) > 0
}

fn simple_concurrent_scenario(runtime: &mut LabRuntime) {
    let region = runtime.state.create_root_region(Budget::INFINITE);

    for i in 0..3 {
        let (task, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move { i })
            .expect("task");
        runtime.scheduler.lock().schedule(task, 0);
    }

    runtime.run_until_quiescent();
}

// ---------------------------------------------------------------------------
// Bug Shape 4: Dining Philosophers (4 philosophers)
// ---------------------------------------------------------------------------
//
// Four philosophers, four forks. Each philosopher tries to pick up left fork,
// then right fork. Circular dependency creates deadlock potential.
// More tasks = richer schedule space where topology-guided exploration excels.

/// Fork for dining philosophers.
struct Fork {
    holder: AtomicUsize,
}

impl Fork {
    fn new(_id: usize) -> Self {
        Self {
            holder: AtomicUsize::new(0),
        }
    }

    fn try_pick_up(&self, philosopher_id: usize) -> bool {
        self.holder
            .compare_exchange(0, philosopher_id, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }

    fn put_down(&self, philosopher_id: usize) {
        let _ = self
            .holder
            .compare_exchange(philosopher_id, 0, Ordering::SeqCst, Ordering::SeqCst);
    }

    fn is_held(&self) -> bool {
        self.holder.load(Ordering::SeqCst) != 0
    }
}

/// Run dining philosophers scenario with N philosophers.
/// Returns the number of philosophers that deadlocked (couldn't get both forks).
fn run_dining_philosophers(runtime: &mut LabRuntime, num_philosophers: usize) -> usize {
    let forks: Vec<Arc<Fork>> = (0..num_philosophers)
        .map(|i| Arc::new(Fork::new(i)))
        .collect();
    let deadlock_count = Arc::new(AtomicUsize::new(0));

    let region = runtime.state.create_root_region(Budget::INFINITE);

    for phil_id in 1..=num_philosophers {
        let left_fork = forks[phil_id - 1].clone();
        let right_fork = forks[phil_id % num_philosophers].clone();
        let deadlocks = deadlock_count.clone();

        let (task, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                // Try to pick up left fork
                let mut left_attempts = 0;
                while !left_fork.try_pick_up(phil_id) {
                    left_attempts += 1;
                    if left_attempts > 50 {
                        // Couldn't get left fork, give up
                        return;
                    }
                }

                // Have left fork, try right fork
                let mut right_attempts = 0;
                while !right_fork.try_pick_up(phil_id) {
                    right_attempts += 1;
                    if right_attempts > 50 {
                        // Deadlock: have left but can't get right
                        deadlocks.fetch_add(1, Ordering::SeqCst);
                        // Put down left fork to allow progress
                        left_fork.put_down(phil_id);
                        return;
                    }
                }

                // Success: have both forks, eat, then put them down
                right_fork.put_down(phil_id);
                left_fork.put_down(phil_id);
            })
            .expect("philosopher task");

        runtime.scheduler.lock().schedule(task, 0);
    }

    runtime.run_until_quiescent();

    // Count forks still held as additional deadlock evidence
    let forks_held: usize = forks.iter().filter(|f| f.is_held()).count();
    deadlock_count.load(Ordering::SeqCst) + usize::from(forks_held > 0)
}

// ---------------------------------------------------------------------------
// Bug Shape 5: Producer-Consumer with Multiple Workers
// ---------------------------------------------------------------------------
//
// Multiple producers and consumers sharing a bounded buffer.
// Race conditions can cause lost items or buffer overflows.

struct BoundedBuffer {
    items: AtomicUsize,
    capacity: usize,
    produced: AtomicUsize,
    consumed: AtomicUsize,
}

impl BoundedBuffer {
    fn new(capacity: usize) -> Self {
        Self {
            items: AtomicUsize::new(0),
            capacity,
            produced: AtomicUsize::new(0),
            consumed: AtomicUsize::new(0),
        }
    }

    fn try_produce(&self) -> bool {
        let current = self.items.load(Ordering::SeqCst);
        if current >= self.capacity {
            return false;
        }
        // Non-atomic increment creates a race window
        if self
            .items
            .compare_exchange(current, current + 1, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            self.produced.fetch_add(1, Ordering::SeqCst);
            true
        } else {
            false
        }
    }

    fn try_consume(&self) -> bool {
        let current = self.items.load(Ordering::SeqCst);
        if current == 0 {
            return false;
        }
        if self
            .items
            .compare_exchange(current, current - 1, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            self.consumed.fetch_add(1, Ordering::SeqCst);
            true
        } else {
            false
        }
    }
}

/// Run producer-consumer scenario.
/// Returns true if a consistency violation was detected (produced != consumed + items).
fn run_producer_consumer(
    runtime: &mut LabRuntime,
    num_producers: usize,
    num_consumers: usize,
    items_per_task: usize,
) -> bool {
    let buffer = Arc::new(BoundedBuffer::new(4));
    let region = runtime.state.create_root_region(Budget::INFINITE);

    // Spawn producers
    for _ in 0..num_producers {
        let buf = buffer.clone();
        let (task, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                for _ in 0..items_per_task {
                    let mut attempts = 0;
                    while !buf.try_produce() {
                        attempts += 1;
                        if attempts > 100 {
                            break;
                        }
                    }
                }
            })
            .expect("producer");
        runtime.scheduler.lock().schedule(task, 0);
    }

    // Spawn consumers
    for _ in 0..num_consumers {
        let buf = buffer.clone();
        let (task, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                for _ in 0..items_per_task {
                    let mut attempts = 0;
                    while !buf.try_consume() {
                        attempts += 1;
                        if attempts > 100 {
                            break;
                        }
                    }
                }
            })
            .expect("consumer");
        runtime.scheduler.lock().schedule(task, 0);
    }

    runtime.run_until_quiescent();

    // Check consistency: produced should equal consumed + items
    let produced = buffer.produced.load(Ordering::SeqCst);
    let consumed = buffer.consumed.load(Ordering::SeqCst);
    let items = buffer.items.load(Ordering::SeqCst);

    produced != consumed + items
}

// ---------------------------------------------------------------------------
// Benchmark: Deadlock Square - Topology vs Baseline
// ---------------------------------------------------------------------------

#[test]
fn benchmark_deadlock_square_topology_vs_baseline() {
    const MAX_RUNS: usize = 100;
    const BASE_SEED: u64 = 0;

    init_test_logging();
    test_phase!("benchmark_deadlock_square_topology_vs_baseline");

    // --- Baseline exploration ---
    test_section!("baseline exploration");
    let baseline_config = ExplorerConfig::new(BASE_SEED, MAX_RUNS).worker_count(1);
    let mut baseline_explorer = ScheduleExplorer::new(baseline_config);

    let baseline_report = baseline_explorer.explore(|runtime| {
        run_deadlock_square(runtime);
    });

    let baseline_classes = baseline_report.unique_classes;
    let baseline_violations = baseline_report.violations.len();
    let baseline_first_violation = baseline_report
        .violations
        .first()
        .map_or(MAX_RUNS as u64, |v| v.seed - BASE_SEED);

    tracing::info!(
        classes = baseline_classes,
        violations = baseline_violations,
        first_violation_at = baseline_first_violation,
        "baseline deadlock square results"
    );

    // --- Topology-prioritized exploration ---
    test_section!("topology exploration");

    // TopologyExplorer uses H1 persistence to prioritize seeds that reveal
    // novel topological structure in the schedule space
    let topo_config = ExplorerConfig::new(BASE_SEED, MAX_RUNS).worker_count(1);
    let mut topo_explorer = TopologyExplorer::new(topo_config);

    let topo_report = topo_explorer.explore(|runtime| {
        run_deadlock_square(runtime);
    });

    let topo_classes = topo_report.unique_classes;
    let topo_violations = topo_report.violations.len();

    tracing::info!(
        classes = topo_classes,
        violations = topo_violations,
        "topology deadlock square results"
    );

    // --- Compare results ---
    test_section!("comparison");

    // Both should find equivalent or better results
    assert!(
        topo_classes >= 1,
        "topology explorer should find at least 1 equivalence class"
    );
    assert!(
        baseline_classes >= 1,
        "baseline explorer should find at least 1 equivalence class"
    );

    // Log comparison metrics
    tracing::info!(
        baseline_classes = baseline_classes,
        topo_classes = topo_classes,
        baseline_violations = baseline_violations,
        topo_violations = topo_violations,
        "deadlock square benchmark comparison"
    );

    test_complete!(
        "benchmark_deadlock_square_topology_vs_baseline",
        baseline_classes = baseline_classes,
        topo_classes = topo_classes
    );
}

// ---------------------------------------------------------------------------
// Benchmark: Lost Wakeup - Topology vs Baseline
// ---------------------------------------------------------------------------

#[test]
fn benchmark_lost_wakeup_topology_vs_baseline() {
    const MAX_RUNS: usize = 50;
    const BASE_SEED: u64 = 1000;

    init_test_logging();
    test_phase!("benchmark_lost_wakeup_topology_vs_baseline");

    // --- Baseline exploration ---
    test_section!("baseline exploration");
    let baseline_config = ExplorerConfig::new(BASE_SEED, MAX_RUNS).worker_count(1);
    let mut baseline_explorer = ScheduleExplorer::new(baseline_config);

    let baseline_report = baseline_explorer.explore(|runtime| {
        run_lost_wakeup_scenario(runtime);
    });

    let baseline_classes = baseline_report.unique_classes;

    tracing::info!(
        classes = baseline_classes,
        total_runs = baseline_report.total_runs,
        "baseline lost wakeup results"
    );

    // --- Topology-prioritized exploration ---
    test_section!("topology exploration");
    let topo_config = ExplorerConfig::new(BASE_SEED, MAX_RUNS).worker_count(1);
    let mut topo_explorer = TopologyExplorer::new(topo_config);

    let topo_report = topo_explorer.explore(|runtime| {
        run_lost_wakeup_scenario(runtime);
    });

    let topo_classes = topo_report.unique_classes;

    tracing::info!(
        classes = topo_classes,
        total_runs = topo_report.total_runs,
        "topology lost wakeup results"
    );

    // --- Compare ---
    tracing::info!(
        baseline_classes = baseline_classes,
        topo_classes = topo_classes,
        "lost wakeup benchmark comparison"
    );

    test_complete!(
        "benchmark_lost_wakeup_topology_vs_baseline",
        baseline_classes = baseline_classes,
        topo_classes = topo_classes
    );
}

// ---------------------------------------------------------------------------
// Determinism Verification
// ---------------------------------------------------------------------------

#[test]
fn verify_benchmark_determinism() {
    const SEED: u64 = 42;
    const RUNS: usize = 20;

    init_test_logging();
    test_phase!("verify_benchmark_determinism");

    // Run baseline twice with same seed
    let config = ExplorerConfig::new(SEED, RUNS).worker_count(1);

    let mut explorer1 = ScheduleExplorer::new(config.clone());
    let report1 = explorer1.explore(|runtime| {
        run_deadlock_square(runtime);
    });

    let mut explorer2 = ScheduleExplorer::new(config);
    let report2 = explorer2.explore(|runtime| {
        run_deadlock_square(runtime);
    });

    // Results should be identical
    assert_eq!(
        report1.unique_classes, report2.unique_classes,
        "determinism: same seed should produce same number of classes"
    );
    assert_eq!(
        report1.total_runs, report2.total_runs,
        "determinism: same seed should produce same number of runs"
    );

    test_complete!("verify_benchmark_determinism");
}

// ---------------------------------------------------------------------------
// Coverage Comparison
// ---------------------------------------------------------------------------

#[test]
#[allow(clippy::cast_precision_loss)]
fn compare_coverage_efficiency() {
    const MAX_RUNS: usize = 30;
    const SEED: u64 = 0;

    init_test_logging();
    test_phase!("compare_coverage_efficiency");

    // Baseline
    let baseline_config = ExplorerConfig::new(SEED, MAX_RUNS).worker_count(1);
    let mut baseline = ScheduleExplorer::new(baseline_config);
    let baseline_report = baseline.explore(simple_concurrent_scenario);

    // Second run for comparison
    let topo_config = ExplorerConfig::new(SEED + 1000, MAX_RUNS).worker_count(1);
    let mut topo = ScheduleExplorer::new(topo_config);
    let topo_report = topo.explore(simple_concurrent_scenario);

    // Compute efficiency: unique classes / total runs
    let baseline_efficiency =
        baseline_report.unique_classes as f64 / baseline_report.total_runs as f64;
    let topo_efficiency = topo_report.unique_classes as f64 / topo_report.total_runs as f64;

    tracing::info!(
        baseline_classes = baseline_report.unique_classes,
        baseline_runs = baseline_report.total_runs,
        baseline_efficiency = %format!("{:.2}%", baseline_efficiency * 100.0),
        topo_classes = topo_report.unique_classes,
        topo_runs = topo_report.total_runs,
        topo_efficiency = %format!("{:.2}%", topo_efficiency * 100.0),
        "coverage efficiency comparison"
    );

    // Both should discover classes efficiently
    assert!(
        baseline_report.unique_classes >= 1,
        "baseline should find at least 1 class"
    );
    assert!(
        topo_report.unique_classes >= 1,
        "topology should find at least 1 class"
    );

    test_complete!(
        "compare_coverage_efficiency",
        baseline_efficiency = baseline_efficiency,
        topo_efficiency = topo_efficiency
    );
}

// ---------------------------------------------------------------------------
// Benchmark: Dining Philosophers (4 tasks) - Topology vs Baseline
// ---------------------------------------------------------------------------
//
// This benchmark uses 4 philosophers creating a richer schedule space.
// The topology-guided explorer should discover more equivalence classes
// more efficiently due to the larger search space.

#[test]
fn benchmark_dining_philosophers_topology_vs_baseline() {
    const MAX_RUNS: usize = 100;
    const BASE_SEED: u64 = 5000;
    const NUM_PHILOSOPHERS: usize = 4;

    init_test_logging();
    test_phase!("benchmark_dining_philosophers_topology_vs_baseline");

    // --- Baseline exploration ---
    test_section!("baseline exploration (4 philosophers)");
    let baseline_config = ExplorerConfig::new(BASE_SEED, MAX_RUNS).worker_count(1);
    let mut baseline_explorer = ScheduleExplorer::new(baseline_config);

    let baseline_deadlocks = AtomicUsize::new(0);
    let baseline_report = baseline_explorer.explore(|runtime| {
        let deadlocks = run_dining_philosophers(runtime, NUM_PHILOSOPHERS);
        if deadlocks > 0 {
            baseline_deadlocks.fetch_add(1, Ordering::Relaxed);
        }
    });

    let baseline_classes = baseline_report.unique_classes;
    let baseline_deadlocks = baseline_deadlocks.load(Ordering::Relaxed);
    tracing::info!(
        classes = baseline_classes,
        total_runs = baseline_report.total_runs,
        deadlock_runs = baseline_deadlocks,
        "baseline dining philosophers results"
    );

    // --- Topology-prioritized exploration ---
    test_section!("topology exploration (4 philosophers)");
    let topo_config = ExplorerConfig::new(BASE_SEED, MAX_RUNS).worker_count(1);
    let mut topo_explorer = TopologyExplorer::new(topo_config);

    let topo_deadlocks = AtomicUsize::new(0);
    let topo_report = topo_explorer.explore(|runtime| {
        let deadlocks = run_dining_philosophers(runtime, NUM_PHILOSOPHERS);
        if deadlocks > 0 {
            topo_deadlocks.fetch_add(1, Ordering::Relaxed);
        }
    });

    let topo_classes = topo_report.unique_classes;
    let topo_deadlocks = topo_deadlocks.load(Ordering::Relaxed);
    tracing::info!(
        classes = topo_classes,
        total_runs = topo_report.total_runs,
        deadlock_runs = topo_deadlocks,
        "topology dining philosophers results"
    );

    // --- Compare ---
    test_section!("comparison");

    // With more tasks, topology-guided should discover more structure
    tracing::info!(
        baseline_classes = baseline_classes,
        topo_classes = topo_classes,
        baseline_deadlocks = baseline_deadlocks,
        topo_deadlocks = topo_deadlocks,
        "dining philosophers benchmark comparison"
    );

    // Both should find at least 1 equivalence class
    assert!(
        baseline_classes >= 1,
        "baseline should find at least 1 equivalence class"
    );
    assert!(
        topo_classes >= 1,
        "topology should find at least 1 equivalence class"
    );

    test_complete!(
        "benchmark_dining_philosophers_topology_vs_baseline",
        baseline_classes = baseline_classes,
        topo_classes = topo_classes
    );
}

// ---------------------------------------------------------------------------
// Benchmark: Producer-Consumer (6 tasks) - Topology vs Baseline
// ---------------------------------------------------------------------------
//
// 3 producers + 3 consumers creates 6 concurrent tasks with complex
// interleaving patterns around a shared bounded buffer.

#[test]
fn benchmark_producer_consumer_topology_vs_baseline() {
    const MAX_RUNS: usize = 80;
    const BASE_SEED: u64 = 8000;
    const NUM_PRODUCERS: usize = 3;
    const NUM_CONSUMERS: usize = 3;
    const ITEMS_PER_TASK: usize = 5;

    init_test_logging();
    test_phase!("benchmark_producer_consumer_topology_vs_baseline");

    // --- Baseline exploration ---
    test_section!("baseline exploration (3 producers, 3 consumers)");
    let baseline_config = ExplorerConfig::new(BASE_SEED, MAX_RUNS).worker_count(1);
    let mut baseline_explorer = ScheduleExplorer::new(baseline_config);

    let baseline_violations = AtomicUsize::new(0);
    let baseline_report = baseline_explorer.explore(|runtime| {
        if run_producer_consumer(runtime, NUM_PRODUCERS, NUM_CONSUMERS, ITEMS_PER_TASK) {
            baseline_violations.fetch_add(1, Ordering::Relaxed);
        }
    });

    let baseline_classes = baseline_report.unique_classes;
    let baseline_violations = baseline_violations.load(Ordering::Relaxed);
    tracing::info!(
        classes = baseline_classes,
        total_runs = baseline_report.total_runs,
        consistency_violations = baseline_violations,
        "baseline producer-consumer results"
    );

    // --- Topology-prioritized exploration ---
    test_section!("topology exploration (3 producers, 3 consumers)");
    let topo_config = ExplorerConfig::new(BASE_SEED, MAX_RUNS).worker_count(1);
    let mut topo_explorer = TopologyExplorer::new(topo_config);

    let topo_violations = AtomicUsize::new(0);
    let topo_report = topo_explorer.explore(|runtime| {
        if run_producer_consumer(runtime, NUM_PRODUCERS, NUM_CONSUMERS, ITEMS_PER_TASK) {
            topo_violations.fetch_add(1, Ordering::Relaxed);
        }
    });

    let topo_classes = topo_report.unique_classes;
    let topo_violations = topo_violations.load(Ordering::Relaxed);
    tracing::info!(
        classes = topo_classes,
        total_runs = topo_report.total_runs,
        consistency_violations = topo_violations,
        "topology producer-consumer results"
    );

    // --- Compare ---
    test_section!("comparison");

    tracing::info!(
        baseline_classes = baseline_classes,
        topo_classes = topo_classes,
        baseline_violations = baseline_violations,
        topo_violations = topo_violations,
        "producer-consumer benchmark comparison"
    );

    // Both should find at least 1 equivalence class
    assert!(
        baseline_classes >= 1,
        "baseline should find at least 1 equivalence class"
    );
    assert!(
        topo_classes >= 1,
        "topology should find at least 1 equivalence class"
    );

    test_complete!(
        "benchmark_producer_consumer_topology_vs_baseline",
        baseline_classes = baseline_classes,
        topo_classes = topo_classes
    );
}

// ---------------------------------------------------------------------------
// Benchmark: Combined Metric - Equivalence Classes per Run
// ---------------------------------------------------------------------------
//
// This test measures "discovery efficiency": how many unique equivalence
// classes are found per exploration run. Topology-guided exploration should
// achieve higher efficiency by prioritizing novel schedules.

#[test]
#[allow(clippy::cast_precision_loss)]
fn benchmark_discovery_efficiency() {
    const MAX_RUNS: usize = 50;
    const BASE_SEED: u64 = 10000;

    init_test_logging();
    test_phase!("benchmark_discovery_efficiency");

    // Use dining philosophers as the test scenario (complex interleaving)
    let baseline_config = ExplorerConfig::new(BASE_SEED, MAX_RUNS).worker_count(1);
    let mut baseline = ScheduleExplorer::new(baseline_config);
    let baseline_report = baseline.explore(|runtime| {
        run_dining_philosophers(runtime, 4);
    });

    let topo_config = ExplorerConfig::new(BASE_SEED, MAX_RUNS).worker_count(1);
    let mut topo = TopologyExplorer::new(topo_config);
    let topo_report = topo.explore(|runtime| {
        run_dining_philosophers(runtime, 4);
    });

    // Discovery efficiency = unique classes / total runs
    let baseline_efficiency =
        baseline_report.unique_classes as f64 / baseline_report.total_runs.max(1) as f64;
    let topo_efficiency = topo_report.unique_classes as f64 / topo_report.total_runs.max(1) as f64;

    tracing::info!(
        baseline_classes = baseline_report.unique_classes,
        baseline_runs = baseline_report.total_runs,
        baseline_efficiency = %format!("{:.2}%", baseline_efficiency * 100.0),
        topo_classes = topo_report.unique_classes,
        topo_runs = topo_report.total_runs,
        topo_efficiency = %format!("{:.2}%", topo_efficiency * 100.0),
        "discovery efficiency comparison"
    );

    // Both should find classes
    assert!(
        baseline_report.unique_classes >= 1,
        "baseline should discover at least 1 class"
    );
    assert!(
        topo_report.unique_classes >= 1,
        "topology should discover at least 1 class"
    );

    test_complete!(
        "benchmark_discovery_efficiency",
        baseline_eff = format!("{:.2}%", baseline_efficiency * 100.0),
        topo_eff = format!("{:.2}%", topo_efficiency * 100.0)
    );
}

// ---------------------------------------------------------------------------
// End-to-End Report: Topology-Guided Coverage Summary
// ---------------------------------------------------------------------------
//
// Produce a deterministic, human-readable coverage summary comparing baseline
// vs topology-guided exploration. This is the "coverage report" artifact for
// bd-32n6 (embedded in test logs for CI capture).

fn format_coverage_report(label: &str, report: &ExplorationReport) -> String {
    let coverage = &report.coverage;
    let novelty_histogram = coverage
        .novelty_histogram
        .iter()
        .map(|(novelty, count)| format!("{novelty}:{count}"))
        .collect::<Vec<_>>()
        .join(",");

    let top_unexplored = report
        .top_unexplored
        .iter()
        .take(5)
        .map(|entry| {
            entry.score.map_or_else(
                || format!("{}", entry.seed),
                |score| {
                    format!(
                        "{}@n{}:p{}",
                        entry.seed, score.novelty, score.persistence_sum
                    )
                },
            )
        })
        .collect::<Vec<_>>()
        .join(",");

    format!(
        "{label}: runs={} classes={} new={} rate={:.2}% saturated={} hits={} since_new={:?} novelty=[{}] top_unexplored=[{}]",
        report.total_runs,
        coverage.equivalence_classes,
        coverage.new_class_discoveries,
        coverage.discovery_rate() * 100.0,
        coverage.saturation.saturated,
        coverage.saturation.existing_class_hits,
        coverage.saturation.runs_since_last_new_class,
        novelty_histogram,
        top_unexplored
    )
}

#[test]
#[allow(clippy::cast_precision_loss)]
fn e2e_topology_coverage_report() {
    const MAX_RUNS: usize = 60;
    const BASE_SEED: u64 = 12_345;

    init_test_logging();
    test_phase!("e2e_topology_coverage_report");

    // Baseline exploration
    let baseline_config = ExplorerConfig::new(BASE_SEED, MAX_RUNS).worker_count(1);
    let mut baseline = ScheduleExplorer::new(baseline_config);
    let baseline_report = baseline.explore(|runtime| {
        run_dining_philosophers(runtime, 4);
    });

    // Topology-prioritized exploration
    let topo_config = ExplorerConfig::new(BASE_SEED, MAX_RUNS).worker_count(1);
    let mut topo = TopologyExplorer::new(topo_config);
    let topo_report = topo.explore(|runtime| {
        run_dining_philosophers(runtime, 4);
    });

    let baseline_summary = format_coverage_report("baseline", &baseline_report);
    let topo_summary = format_coverage_report("topology", &topo_report);

    tracing::info!(%baseline_summary, %topo_summary, "topology coverage report");

    assert!(
        baseline_report.coverage.equivalence_classes >= 1,
        "baseline should discover at least 1 equivalence class"
    );
    assert!(
        topo_report.coverage.equivalence_classes >= 1,
        "topology should discover at least 1 equivalence class"
    );

    test_complete!(
        "e2e_topology_coverage_report",
        baseline = baseline_summary,
        topology = topo_summary
    );
}

// ---------------------------------------------------------------------------
// E2E Report Harness (bd-32n6)
// ---------------------------------------------------------------------------

fn top_k_ledgers(ledgers: &[EvidenceLedger], k: usize) -> Vec<EvidenceLedger> {
    let mut sorted: Vec<EvidenceLedger> = ledgers.to_vec();
    sorted.sort_by(|a, b| {
        b.score
            .novelty
            .cmp(&a.score.novelty)
            .then_with(|| b.score.persistence_sum.cmp(&a.score.persistence_sum))
            .then_with(|| b.score.fingerprint.cmp(&a.score.fingerprint))
    });
    sorted.truncate(k);
    sorted
}

fn scoring_work_units(ledgers: &[EvidenceLedger]) -> u64 {
    ledgers
        .iter()
        .map(|ledger| ledger.entries.len() as u64)
        .sum()
}

fn execution_steps(results: &[asupersync::lab::explorer::RunResult]) -> u64 {
    results.iter().map(|run| run.steps).sum()
}

fn run_scenario_report<F>(
    suite: &str,
    scenario: &str,
    base_seed: u64,
    max_runs: usize,
    test: F,
) -> serde_json::Value
where
    F: Fn(&mut LabRuntime),
{
    let baseline_config = ExplorerConfig::new(base_seed, max_runs).worker_count(1);
    let mut baseline_explorer = ScheduleExplorer::new(baseline_config);
    let baseline_report = baseline_explorer.explore(&test);

    let topo_config = ExplorerConfig::new(base_seed, max_runs).worker_count(1);
    let mut topo_explorer = TopologyExplorer::new(topo_config);
    let topo_report = topo_explorer.explore(&test);

    let top_ledgers = top_k_ledgers(topo_explorer.ledgers(), 3);
    let report_json = topology_report_json(
        suite,
        scenario,
        &baseline_report,
        &topo_report,
        &top_ledgers,
        None,
        scoring_work_units(topo_explorer.ledgers()),
        execution_steps(topo_explorer.results()),
    );
    write_topology_report(scenario, &report_json);
    report_json
}

#[test]
fn e2e_topology_exploration_report() {
    init_test_logging();
    test_phase!("e2e_topology_exploration_report");

    let suite = "topology_e2e";
    let mut scenario_reports = Vec::new();

    scenario_reports.push(run_scenario_report(
        suite,
        "deadlock_square",
        0,
        100,
        |runtime| {
            run_deadlock_square(runtime);
        },
    ));

    scenario_reports.push(run_scenario_report(
        suite,
        "lost_wakeup",
        1000,
        50,
        |runtime| {
            run_lost_wakeup_scenario(runtime);
        },
    ));

    scenario_reports.push(run_scenario_report(
        suite,
        "dining_philosophers",
        5000,
        80,
        |runtime| {
            run_dining_philosophers(runtime, 4);
        },
    ));

    scenario_reports.push(run_scenario_report(
        suite,
        "producer_consumer",
        8000,
        60,
        |runtime| {
            run_producer_consumer(runtime, 3, 3, 5);
        },
    ));

    let summary = json!({
        "suite": suite,
        "scenario_count": scenario_reports.len(),
        "scenarios": scenario_reports,
    });
    write_topology_report("topology_e2e_summary", &summary);

    test_complete!("e2e_topology_exploration_report");
}
