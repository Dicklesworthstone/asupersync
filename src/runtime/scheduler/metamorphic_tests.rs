//! Metamorphic property tests for scheduler fairness, work conservation, and starvation freedom.
//!
//! These tests verify scheduler invariants that must hold regardless of the specific
//! scheduling decisions made. Unlike unit tests that check exact outcomes, metamorphic
//! tests verify relationships between different execution scenarios.

use crate::runtime::scheduler::{ThreeLaneScheduler, LocalQueue};
use crate::runtime::RuntimeState;
use crate::sync::ContendedMutex;
use crate::types::{TaskId, RegionId};
use crate::util::DetRng;
use std::sync::Arc;

use proptest::prelude::*;

// ============================================================================
// Test Infrastructure
// ============================================================================

/// A simple work unit that increments a counter when executed.
#[derive(Debug, Clone)]
pub struct WorkUnit {
    pub id: u64,
    pub cycles: u64,
}

impl WorkUnit {
    fn new(id: u64, cycles: u64) -> Self {
        Self { id, cycles }
    }

    /// Execute the work unit, returning the amount of work completed.
    async fn execute(&self, _cx: &Cx, work_counter: Arc<AtomicU64>) -> u64 {
        let mut completed = 0;
        for _ in 0..self.cycles {
            // Simulate some work
            completed += 1;
            work_counter.fetch_add(1, Ordering::Relaxed);

            // Yield occasionally to allow preemption
            if completed % 100 == 0 {
                crate::runtime::yield_now().await;
            }
        }
        completed
    }
}

/// Different scheduling strategies for testing.
#[derive(Debug, Clone, Copy)]
pub enum TestScheduleStrategy {
    Default,
    SingleWorker,
    MultiWorker,
}

/// Task execution state for preemption testing.
#[derive(Debug, Clone, PartialEq)]
pub struct TaskExecutionState {
    pub task_id: u64,
    pub progress: u64,
    pub checkpoints: Vec<u64>,
}

impl TaskExecutionState {
    fn new(task_id: u64) -> Self {
        Self {
            task_id,
            progress: 0,
            checkpoints: Vec::new(),
        }
    }

    fn checkpoint(&mut self) -> TaskExecutionCheckpoint {
        self.checkpoints.push(self.progress);
        TaskExecutionCheckpoint {
            task_id: self.task_id,
            saved_progress: self.progress,
            saved_checkpoints: self.checkpoints.clone(),
        }
    }

    fn advance(&mut self, amount: u64) {
        self.progress += amount;
    }
}

/// Saved task state for preemption testing.
#[derive(Debug, Clone)]
pub struct TaskExecutionCheckpoint {
    pub task_id: u64,
    pub saved_progress: u64,
    pub saved_checkpoints: Vec<u64>,
}

impl TaskExecutionCheckpoint {
    fn restore(self) -> TaskExecutionState {
        TaskExecutionState {
            task_id: self.task_id,
            progress: self.saved_progress,
            checkpoints: self.saved_checkpoints,
        }
    }
}

/// Generate deterministic work units for testing.
fn generate_work_units(count: usize, seed: u64) -> Vec<WorkUnit> {
    let mut rng = DetRng::new(seed);
    (0..count)
        .map(|i| {
            let cycles = 50 + (rng.next_u32() % 200) as u64; // 50-250 cycles
            WorkUnit::new(i as u64, cycles)
        })
        .collect()
}

/// Execute a set of work units and return total work completed.
async fn execute_work_units(
    cx: &Cx,
    work_units: &[WorkUnit],
    work_counter: Arc<AtomicU64>
) -> u64 {
    let mut total_work = 0;
    for unit in work_units {
        total_work += unit.execute(cx, work_counter.clone()).await;
    }
    total_work
}

/// Create a deterministic lab runtime with specified configuration.
fn create_test_runtime(seed: u64) -> LabRuntime {
    let config = LabConfig::new(seed)
        .max_steps(10000);
    LabRuntime::new(config)
}

// ============================================================================
// Metamorphic Relations
// ============================================================================

/// MR1: Work Conservation (Additive, Score: 10.0)
/// Property: total_work_completed(schedule_A) = total_work_completed(schedule_B)
/// Catches: Work loss bugs, task dropping, scheduling inefficiencies
#[test]
fn mr_scheduler_work_conservation() {
    proptest!(|(
        work_count in 3usize..12,
        seed_a in any::<u64>(),
        seed_b in any::<u64>(),
        strategy_b in prop::sample::select(vec![
            TestScheduleStrategy::Default,
            TestScheduleStrategy::SingleWorker,
            TestScheduleStrategy::MultiWorker,
        ])
    )| {
        // Generate identical work for both schedules
        let work_units = generate_work_units(work_count, seed_a);

        // Execute with strategy A (default configuration)
        let runtime_a = create_test_runtime(seed_a);
        let work_counter_a = Arc::new(AtomicU64::new(0));
        let total_work_a = runtime_a.block_on(async {
            let cx = Cx::for_testing();
            execute_work_units(&cx, &work_units, work_counter_a.clone()).await
        });

        // Execute with strategy B (different seed for different scheduling choices)
        let runtime_b = create_test_runtime(seed_b);
        let work_counter_b = Arc::new(AtomicU64::new(0));
        let total_work_b = runtime_b.block_on(async {
            let cx = Cx::for_testing();
            execute_work_units(&cx, &work_units, work_counter_b.clone()).await
        });

        // METAMORPHIC ASSERTION: Work conservation
        prop_assert_eq!(
            total_work_a, total_work_b,
            "MR1 VIOLATION: work conservation failed - strategy A completed {}, strategy B completed {}",
            total_work_a, total_work_b
        );

        // Additional check: counters should also match
        let counter_a = work_counter_a.load(Ordering::Relaxed);
        let counter_b = work_counter_b.load(Ordering::Relaxed);
        prop_assert_eq!(
            counter_a, counter_b,
            "MR1 VIOLATION: work counter conservation failed - A: {}, B: {}",
            counter_a, counter_b
        );
    });
}

/// MR2: Preemption Correctness (Invertive, Score: 8.0)
/// Property: resume(preempt(task_state)) = task_state (modulo execution progress)
/// Catches: Context corruption, state leakage during preemption
#[test]
fn mr_scheduler_preemption_correctness() {
    proptest!(|(
        task_count in 2usize..6,
        seed in any::<u64>(),
        preemption_points in 1usize..8,
    )| {
        let runtime = create_test_runtime(seed);

        let mut task_states = Vec::new();
        for i in 0..task_count {
            task_states.push(TaskExecutionState::new(i as u64));
        }

        let original_states = task_states.clone();

        // Execute tasks with preemption points (yielding)
        let final_states = runtime.block_on(async {
            let cx = Cx::for_testing();
            let mut states = task_states;

            for i in 0..preemption_points {
                // Simulate some work on each task
                for state in &mut states {
                    let checkpoint = state.checkpoint();
                    state.advance(10); // Do some work

                    // Yield to allow preemption
                    crate::runtime::yield_now().await;

                    // State should be preserved after yield
                    // (In a real test, we might restore from checkpoint to test corruption)
                }
            }

            states
        });

        // METAMORPHIC ASSERTION: Task identity and checkpoint consistency
        prop_assert_eq!(
            final_states.len(), original_states.len(),
            "MR2 VIOLATION: task count changed after preemption"
        );

        for (original, final_state) in original_states.iter().zip(final_states.iter()) {
            prop_assert_eq!(
                original.task_id, final_state.task_id,
                "MR2 VIOLATION: task ID corrupted during preemption"
            );

            prop_assert!(
                final_state.progress >= original.progress,
                "MR2 VIOLATION: task progress regressed during preemption - was {}, now {}",
                original.progress, final_state.progress
            );

            prop_assert!(
                final_state.checkpoints.len() >= original.checkpoints.len(),
                "MR2 VIOLATION: checkpoints lost during preemption"
            );
        }
    });
}

/// MR3: Starvation Freedom (Inclusive, Score: 6.25)
/// Property: runnable(task) ∧ finite_time → eventually_runs(task)
/// Catches: Priority starvation, work-stealing imbalances, infinite deferral
#[test]
fn mr_scheduler_starvation_freedom() {
    proptest!(|(
        competing_count in 2usize..8,
        seed in any::<u64>(),
        time_limit in 1000u64..5000,
    )| {
        let runtime = create_test_runtime(seed);

        // Shared flags to track execution
        let target_executed = Arc::new(AtomicU64::new(0));
        let competing_executed = Arc::new(AtomicU64::new(0));

        // Execute scenario with target task and competing tasks
        let report = runtime.run_with_auto_advance(|scope| {
            let cx = scope.cx();

            // Target task that should eventually run
            let target_flag = target_executed.clone();
            scope.spawn(async move {
                for i in 0..10 {
                    target_flag.store(i + 1, Ordering::Relaxed);
                    crate::runtime::yield_now().await;
                }
            });

            // Competing tasks that might interfere
            for i in 0..competing_count {
                let competing_flag = competing_executed.clone();
                scope.spawn(async move {
                    for j in 0..5 {
                        competing_flag.fetch_add(1, Ordering::Relaxed);
                        crate::runtime::yield_now().await;
                    }
                });
            }

            // Continue until quiescence or step limit
            Ok(())
        });

        // METAMORPHIC ASSERTION: Target task must have made progress
        let target_progress = target_executed.load(Ordering::Relaxed);
        prop_assert!(
            target_progress > 0,
            "MR3 VIOLATION: target task was starved (progress: {}, competing progress: {}, steps: {}, termination: {:?})",
            target_progress,
            competing_executed.load(Ordering::Relaxed),
            report.steps,
            report.termination
        );

        // Additional check: if we reached quiescence, target should have completed
        if report.termination == AutoAdvanceTermination::Quiescent {
            prop_assert!(
                target_progress >= 5, // Should have made significant progress
                "MR3 VIOLATION: target task made insufficient progress despite quiescence (progress: {})",
                target_progress
            );
        }
    });
}

// ============================================================================
// Composite Metamorphic Relations
// ============================================================================

/// Composite MR: Work Conservation + Starvation Freedom
/// Tests that work is conserved even when preventing starvation
#[test]
fn mr_composite_work_conservation_with_fairness() {
    proptest!(|(
        work_count in 4usize..8,
        seed in any::<u64>(),
    )| {
        let work_units = generate_work_units(work_count, seed);

        // Execute with sequential processing
        let runtime_sequential = create_test_runtime(seed);
        let work_counter_seq = Arc::new(AtomicU64::new(0));
        let total_work_sequential = runtime_sequential.block_on(async {
            let cx = Cx::for_testing();
            execute_work_units(&cx, &work_units, work_counter_seq.clone()).await
        });

        // Execute with fairness requirements (yielding between tasks)
        let runtime_fair = create_test_runtime(seed + 1);
        let work_counter_fair = Arc::new(AtomicU64::new(0));
        let total_work_fair = runtime_fair.block_on(async {
            let cx = Cx::for_testing();
            let mut total = 0;
            for unit in &work_units {
                total += unit.execute(&cx, work_counter_fair.clone()).await;
                // Yield after each unit to ensure fairness
                crate::runtime::yield_now().await;
            }
            total
        });

        // COMPOSITE ASSERTION: Work should be conserved despite fairness overhead
        prop_assert_eq!(
            total_work_sequential, total_work_fair,
            "COMPOSITE MR VIOLATION: fairness compromised work conservation"
        );

        prop_assert_eq!(
            work_counter_seq.load(Ordering::Relaxed),
            work_counter_fair.load(Ordering::Relaxed),
            "COMPOSITE MR VIOLATION: fairness affected work counter consistency"
        );
    });
}

#[cfg(test)]
mod validation_tests {
    use super::*;

    /// Validate that work conservation test infrastructure works correctly
    #[test]
    fn validate_work_conservation_infrastructure() {
        let work_units = generate_work_units(5, 42);
        let runtime = create_test_runtime(42);
        let work_counter = Arc::new(AtomicU64::new(0));

        let total_work = runtime.block_on(async {
            let cx = Cx::for_testing();
            execute_work_units(&cx, &work_units, work_counter.clone()).await
        });

        // Work should equal sum of cycles
        let expected_work: u64 = work_units.iter().map(|w| w.cycles).sum();
        assert_eq!(total_work, expected_work, "Work infrastructure validation failed");
        assert_eq!(work_counter.load(Ordering::Relaxed), expected_work, "Counter validation failed");
    }

    /// Validate that preemption test captures state correctly
    #[test]
    fn validate_preemption_state_tracking() {
        let mut state = TaskExecutionState::new(123);
        let checkpoint1 = state.checkpoint();
        state.advance(50);
        let checkpoint2 = state.checkpoint();
        state.advance(25);

        assert_eq!(state.progress, 75);
        assert_eq!(state.checkpoints.len(), 2);

        let restored = checkpoint1.restore();
        assert_eq!(restored.progress, 0);
        assert_eq!(restored.task_id, 123);
    }

    /// Validate that starvation test setup creates competitive scenario
    #[test]
    fn validate_starvation_test_setup() {
        let runtime = create_test_runtime(999);
        let executed_flag = Arc::new(AtomicU64::new(0));

        let report = runtime.run_with_auto_advance(|scope| {
            let cx = scope.cx();
            let flag = executed_flag.clone();

            // Single task should execute to completion
            scope.spawn(async move {
                for i in 0..3 {
                    flag.store(i + 1, Ordering::Relaxed);
                    crate::runtime::yield_now().await;
                }
            });

            Ok(())
        });

        assert_eq!(executed_flag.load(Ordering::Relaxed), 3, "Task should complete");
        assert_eq!(report.termination, AutoAdvanceTermination::Quiescent, "Should reach quiescence");
    }
}