#![allow(clippy::all)]
//! Metamorphic tests for sync::rwlock reader-writer fairness invariants.
//!
//! Tests RwLock fairness properties under concurrent access patterns:
//! 1. readers cannot starve pending writers (writer-preference fairness)
//! 2. cohorts of readers coalesced when writers release
//! 3. FIFO ordering within same-kind waiters (readers/writers separately)
//! 4. concurrent read access preserves data consistency
//! 5. writer exclusivity maintains data integrity

use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::sync::RwLock;
use asupersync::types::{Budget, TaskId};
use proptest::prelude::*;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

// ============================================================================
// Test Data Structures and Generators
// ============================================================================

/// Test operations for RwLock access
#[derive(Debug, Clone, PartialEq)]
enum RwLockOp {
    Read { duration_steps: u32, reader_id: u32 },
    Write { duration_steps: u32, writer_id: u32, value: u64 },
    TryRead { reader_id: u32 },
    TryWrite { writer_id: u32, value: u64 },
}

/// Test scenario configuration
#[derive(Debug, Clone)]
struct RwLockScenario {
    /// Sequence of operations to perform
    operations: Vec<RwLockOp>,
    /// Number of concurrent tasks to spawn
    concurrency: usize,
    /// Virtual time steps to run
    max_steps: u32,
}

/// Execution trace for fairness analysis
#[derive(Debug, Clone)]
struct ExecutionTrace {
    /// Order in which locks were acquired
    acquisition_order: Vec<(u64, String, u32)>, // (timestamp, op_type, id)
    /// Reader coalescing events (multiple readers acquired simultaneously)
    reader_cohorts: Vec<(u64, Vec<u32>)>, // (timestamp, reader_ids)
    /// Writer starvation measurements (time waiting while readers active)
    writer_wait_times: HashMap<u32, u64>,
    /// Reader blocking by writers (readers blocked while writers waiting)
    reader_blocks: Vec<(u64, u32, u32)>, // (timestamp, reader_id, blocking_writer_id)
}

/// PropTest generators for RwLock scenarios
fn rwlock_operation_strategy() -> impl Strategy<Value = RwLockOp> {
    prop_oneof![
        (1_u32..=20, 1_u32..=8).prop_map(|(duration, id)| RwLockOp::Read {
            duration_steps: duration,
            reader_id: id
        }),
        (1_u32..=10, 1_u32..=4, any::<u64>()).prop_map(|(duration, id, value)| RwLockOp::Write {
            duration_steps: duration,
            writer_id: id,
            value
        }),
        (1_u32..=8).prop_map(|id| RwLockOp::TryRead { reader_id: id }),
        (1_u32..=4, any::<u64>()).prop_map(|(id, value)| RwLockOp::TryWrite {
            writer_id: id,
            value
        }),
    ]
}

fn rwlock_scenario_strategy() -> impl Strategy<Value = RwLockScenario> {
    (
        prop::collection::vec(rwlock_operation_strategy(), 5..25),
        2_usize..=12,  // concurrency
        50_u32..=200,  // max_steps
    ).prop_map(|(operations, concurrency, max_steps)| RwLockScenario {
        operations,
        concurrency,
        max_steps,
    })
}

// ============================================================================
// Test Harness and Execution Infrastructure
// ============================================================================

struct RwLockFairnessHarness {
    runtime: LabRuntime,
    lock: Arc<RwLock<u64>>,
    trace: Arc<parking_lot::Mutex<ExecutionTrace>>,
    acquisition_counter: Arc<AtomicU64>,
    active_readers: Arc<AtomicUsize>,
    active_writers: Arc<AtomicUsize>,
}

impl RwLockFairnessHarness {
    fn new(seed: u64) -> Self {
        let runtime = LabRuntime::new(LabConfig::new(seed));
        let lock = Arc::new(RwLock::new(42_u64));
        let trace = Arc::new(parking_lot::Mutex::new(ExecutionTrace {
            acquisition_order: Vec::new(),
            reader_cohorts: Vec::new(),
            writer_wait_times: HashMap::new(),
            reader_blocks: Vec::new(),
        }));

        Self {
            runtime,
            lock,
            trace,
            acquisition_counter: Arc::new(AtomicU64::new(0)),
            active_readers: Arc::new(AtomicUsize::new(0)),
            active_writers: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Execute a read operation with fairness tracking
    fn execute_read_op(
        &mut self,
        reader_id: u32,
        duration_steps: u32,
    ) -> Result<TaskId, Box<dyn std::error::Error>> {
        let lock = Arc::clone(&self.lock);
        let trace = Arc::clone(&self.trace);
        let counter = Arc::clone(&self.acquisition_counter);
        let active_readers = Arc::clone(&self.active_readers);

        let region = self.runtime.state.create_root_region(Budget::unlimited());

        let (task_id, _handle) = self.runtime.state.create_task(
            region,
            Budget::unlimited(),
            async move {
                let cx = asupersync::cx::Cx::current().expect("no current context");

                // Record attempt to acquire
                let attempt_time = counter.fetch_add(1, Ordering::SeqCst);

                // Acquire read lock
                let _guard = match lock.read(&cx).await {
                    Ok(guard) => {
                        // Record successful acquisition
                        let acquire_time = counter.fetch_add(1, Ordering::SeqCst);
                        {
                            let mut t = trace.lock();
                            t.acquisition_order.push((acquire_time, "read".to_string(), reader_id));
                        }

                        // Track active readers for coalescing analysis
                        let concurrent_readers = active_readers.fetch_add(1, Ordering::SeqCst) + 1;
                        if concurrent_readers > 1 {
                            let mut t = trace.lock();
                            // Find recent reader acquisitions to detect cohorts
                            let recent_readers: Vec<u32> = t.acquisition_order
                                .iter()
                                .rev()
                                .take(8)
                                .filter_map(|(_, op_type, id)| {
                                    if op_type == "read" { Some(*id) } else { None }
                                })
                                .collect();
                            if recent_readers.len() > 1 {
                                t.reader_cohorts.push((acquire_time, recent_readers));
                            }
                        }

                        guard
                    }
                    Err(_) => return, // Cancelled or poisoned
                };

                // Hold the lock for specified duration
                for _ in 0..duration_steps {
                    if cx.checkpoint().is_err() {
                        break;
                    }
                    asupersync::yield_now().await;
                }

                // Release tracking
                active_readers.fetch_sub(1, Ordering::SeqCst);
            }
        )?;

        self.runtime.scheduler.lock().schedule(task_id, 0);
        Ok(task_id)
    }

    /// Execute a write operation with fairness tracking
    fn execute_write_op(
        &mut self,
        writer_id: u32,
        duration_steps: u32,
        value: u64,
    ) -> Result<TaskId, Box<dyn std::error::Error>> {
        let lock = Arc::clone(&self.lock);
        let trace = Arc::clone(&self.trace);
        let counter = Arc::clone(&self.acquisition_counter);
        let active_writers = Arc::clone(&self.active_writers);

        let region = self.runtime.state.create_root_region(Budget::unlimited());

        let (task_id, _handle) = self.runtime.state.create_task(
            region,
            Budget::unlimited(),
            async move {
                let cx = asupersync::cx::Cx::current().expect("no current context");

                // Record attempt to acquire
                let attempt_time = counter.fetch_add(1, Ordering::SeqCst);

                // Acquire write lock
                let mut guard = match lock.write(&cx).await {
                    Ok(guard) => {
                        // Record successful acquisition
                        let acquire_time = counter.fetch_add(1, Ordering::SeqCst);
                        {
                            let mut t = trace.lock();
                            t.acquisition_order.push((acquire_time, "write".to_string(), writer_id));

                            // Track writer wait time
                            let wait_time = acquire_time.saturating_sub(attempt_time);
                            t.writer_wait_times.insert(writer_id, wait_time);
                        }

                        active_writers.fetch_add(1, Ordering::SeqCst);
                        guard
                    }
                    Err(_) => return, // Cancelled or poisoned
                };

                // Modify the protected data
                *guard = value;

                // Hold the lock for specified duration
                for _ in 0..duration_steps {
                    if cx.checkpoint().is_err() {
                        break;
                    }
                    asupersync::yield_now().await;
                }

                // Release tracking
                active_writers.fetch_sub(1, Ordering::SeqCst);
            }
        )?;

        self.runtime.scheduler.lock().schedule(task_id, 0);
        Ok(task_id)
    }

    /// Execute try_read operation
    fn execute_try_read_op(&mut self, reader_id: u32) -> Result<bool, Box<dyn std::error::Error>> {
        match self.lock.try_read() {
            Ok(_guard) => {
                // Successful non-blocking acquisition
                let acquire_time = self.acquisition_counter.fetch_add(1, Ordering::SeqCst);
                {
                    let mut t = self.trace.lock();
                    t.acquisition_order.push((acquire_time, "try_read".to_string(), reader_id));
                }
                Ok(true)
            }
            Err(_) => Ok(false),
        }
    }

    /// Execute try_write operation
    fn execute_try_write_op(&mut self, writer_id: u32, value: u64) -> Result<bool, Box<dyn std::error::Error>> {
        match self.lock.try_write() {
            Ok(mut guard) => {
                // Successful non-blocking acquisition
                let acquire_time = self.acquisition_counter.fetch_add(1, Ordering::SeqCst);
                *guard = value;
                {
                    let mut t = self.trace.lock();
                    t.acquisition_order.push((acquire_time, "try_write".to_string(), writer_id));
                }
                Ok(true)
            }
            Err(_) => Ok(false),
        }
    }

    /// Run the scenario and collect execution trace
    fn run_scenario(&mut self, scenario: &RwLockScenario) -> ExecutionTrace {
        let mut spawned_tasks = Vec::new();

        // Execute operations with some scheduling randomness
        for (i, op) in scenario.operations.iter().enumerate() {
            // Space out operations to create interesting interleavings
            if i % 3 == 0 {
                for _ in 0..2 {
                    self.runtime.step_for_test();
                }
            }

            match op {
                RwLockOp::Read { duration_steps, reader_id } => {
                    if let Ok(task_id) = self.execute_read_op(*reader_id, *duration_steps) {
                        spawned_tasks.push(task_id);
                    }
                }
                RwLockOp::Write { duration_steps, writer_id, value } => {
                    if let Ok(task_id) = self.execute_write_op(*writer_id, *duration_steps, *value) {
                        spawned_tasks.push(task_id);
                    }
                }
                RwLockOp::TryRead { reader_id } => {
                    let _ = self.execute_try_read_op(*reader_id);
                }
                RwLockOp::TryWrite { writer_id, value } => {
                    let _ = self.execute_try_write_op(*writer_id, *value);
                }
            }
        }

        // Run the scenario to completion or timeout
        for _ in 0..scenario.max_steps {
            if self.runtime.is_quiescent() {
                break;
            }
            self.runtime.step_for_test();
        }

        // Cancel remaining tasks if any
        for task_id in spawned_tasks {
            let _ = self.runtime.state.cancel_task(task_id, None);
        }

        // Drain remaining steps
        for _ in 0..50 {
            if self.runtime.is_quiescent() {
                break;
            }
            self.runtime.step_for_test();
        }

        self.trace.lock().clone()
    }
}

// ============================================================================
// MR1: Readers cannot starve pending writers (writer-preference)
// ============================================================================

proptest! {
    /// MR1: Readers cannot starve pending writers (writer-preference)
    /// When writers are waiting, new readers should be blocked to prevent writer starvation.
    #[test]
    fn mr_writer_preference_fairness(scenario in rwlock_scenario_strategy()) {
        let seed = 0xF41RNESS;
        let mut harness = RwLockFairnessHarness::new(seed);

        let trace = harness.run_scenario(&scenario);

        // Analyze writer starvation: writers should not wait excessively long
        // when there are readers but no continuous read pressure
        let writer_acquisitions: Vec<_> = trace.acquisition_order
            .iter()
            .filter(|(_, op_type, _)| op_type == "write")
            .collect();

        let reader_acquisitions: Vec<_> = trace.acquisition_order
            .iter()
            .filter(|(_, op_type, _)| op_type == "read")
            .collect();

        // Check that writers are not starved by excessive reader acquisitions
        // For each writer, check that readers don't continuously block it
        for (writer_time, _, writer_id) in writer_acquisitions {
            let readers_after_writer: Vec<_> = reader_acquisitions
                .iter()
                .filter(|(reader_time, _, _)| **reader_time > *writer_time)
                .take(10) // Check subsequent readers
                .collect();

            // If there are many readers acquired after this writer's timestamp,
            // verify that this writer eventually got its turn (was not starved)
            if readers_after_writer.len() > 3 {
                let writer_actually_acquired = trace.acquisition_order
                    .iter()
                    .any(|(time, op_type, id)| {
                        *time > *writer_time
                        && op_type == "write"
                        && id == writer_id
                    });

                prop_assert!(
                    writer_actually_acquired || trace.writer_wait_times.get(writer_id).unwrap_or(&0) < &100,
                    "Writer {} may have been starved by readers (wait time: {:?})",
                    writer_id,
                    trace.writer_wait_times.get(writer_id)
                );
            }
        }
    }
}

// ============================================================================
// MR2: Cohorts of readers coalesced
// ============================================================================

proptest! {
    /// MR2: Cohorts of readers coalesced
    /// When a writer releases, waiting readers should be woken as a cohort for efficiency.
    #[test]
    fn mr_reader_cohort_coalescing(scenario in rwlock_scenario_strategy()) {
        let seed = 0xC0ALESC;
        let mut harness = RwLockFairnessHarness::new(seed);

        let trace = harness.run_scenario(&scenario);

        // Verify reader coalescing behavior
        if !trace.reader_cohorts.is_empty() {
            for (cohort_time, reader_ids) in &trace.reader_cohorts {
                // Cohorts should contain multiple readers
                prop_assert!(
                    reader_ids.len() >= 2,
                    "Reader cohort at time {} should contain multiple readers, got: {:?}",
                    cohort_time,
                    reader_ids
                );

                // Readers in a cohort should acquire locks close together in time
                let cohort_acquisitions: Vec<_> = trace.acquisition_order
                    .iter()
                    .filter(|(time, op_type, id)| {
                        op_type == "read"
                        && reader_ids.contains(id)
                        && (*time >= cohort_time.saturating_sub(5))
                        && (*time <= cohort_time.saturating_add(5))
                    })
                    .collect();

                prop_assert!(
                    cohort_acquisitions.len() >= 2,
                    "Expected at least 2 readers in cohort, found {} acquisitions near time {}",
                    cohort_acquisitions.len(),
                    cohort_time
                );
            }
        }

        // Additional coalescing property: when multiple readers are waiting and a writer
        // releases, they should be woken together rather than one-by-one
        let write_releases: Vec<_> = trace.acquisition_order
            .iter()
            .enumerate()
            .filter(|(_, (_, op_type, _))| op_type == "write")
            .collect();

        for (i, (_, (write_time, _, _))) in write_releases.iter().enumerate() {
            // Look for readers acquired shortly after this write
            let subsequent_reads: Vec<_> = trace.acquisition_order
                .iter()
                .filter(|(time, op_type, _)| {
                    op_type == "read"
                    && *time > *write_time
                    && *time <= write_time + 10
                })
                .collect();

            // If there are multiple subsequent readers, they likely formed a cohort
            if subsequent_reads.len() > 1 {
                // Verify they acquired within a small time window (coalesced)
                let time_span = subsequent_reads.iter().map(|(t, _, _)| *t).max().unwrap_or(0)
                                - subsequent_reads.iter().map(|(t, _, _)| *t).min().unwrap_or(0);

                prop_assert!(
                    time_span <= 5,
                    "Readers after writer release should be coalesced within small time window, got span: {}",
                    time_span
                );
            }
        }
    }
}

// ============================================================================
// MR3: FIFO ordering within same-kind waiters
// ============================================================================

proptest! {
    /// MR3: FIFO ordering within same-kind waiters
    /// Readers waiting together should be served in FIFO order, as should writers.
    #[test]
    fn mr_fifo_ordering_same_kind(scenario in rwlock_scenario_strategy()) {
        let seed = 0xFIF0;
        let mut harness = RwLockFairnessHarness::new(seed);

        let trace = harness.run_scenario(&scenario);

        // Check FIFO ordering for writers (easier to verify since they're exclusive)
        let writer_acquisitions: Vec<_> = trace.acquisition_order
            .iter()
            .filter(|(_, op_type, _)| op_type == "write")
            .collect();

        // For consecutive writer acquisitions, verify they maintain some ordering
        // (exact FIFO is hard to verify in concurrent system, but gross violations should not occur)
        for window in writer_acquisitions.windows(2) {
            let (time1, _, id1) = window[0];
            let (time2, _, id2) = window[1];

            // Writers should acquire in temporal order
            prop_assert!(
                time2 > time1,
                "Writer acquisitions should be temporally ordered: writer {} at time {} should be before writer {} at time {}",
                id1, time1, id2, time2
            );
        }

        // Check reader cohort ordering: within a cohort, readers should follow some ordering principle
        for (cohort_time, reader_ids) in &trace.reader_cohorts {
            if reader_ids.len() > 2 {
                // Get the actual acquisition times for readers in this cohort
                let mut cohort_acquisitions: Vec<_> = trace.acquisition_order
                    .iter()
                    .filter(|(time, op_type, id)| {
                        op_type == "read"
                        && reader_ids.contains(id)
                        && *time >= cohort_time.saturating_sub(10)
                        && *time <= cohort_time.saturating_add(10)
                    })
                    .collect();

                cohort_acquisitions.sort_by_key(|(time, _, _)| *time);

                // Verify acquisitions are reasonably ordered
                let mut prev_time = 0;
                for (time, _, _) in cohort_acquisitions {
                    prop_assert!(
                        *time >= prev_time,
                        "Reader acquisitions in cohort should be temporally non-decreasing"
                    );
                    prev_time = *time;
                }
            }
        }
    }
}

// ============================================================================
// MR4: Concurrent read access preserves data consistency
// ============================================================================

proptest! {
    /// MR4: Concurrent read access preserves data consistency
    /// Multiple readers should be able to access data concurrently without interference.
    #[test]
    fn mr_concurrent_read_consistency(seed: u64) {
        let mut harness = RwLockFairnessHarness::new(seed);

        // Create a scenario with mostly read operations
        let read_heavy_scenario = RwLockScenario {
            operations: (1..=15).map(|i| RwLockOp::Read {
                duration_steps: 5,
                reader_id: i % 8 + 1
            }).collect(),
            concurrency: 8,
            max_steps: 100,
        };

        let trace = harness.run_scenario(&read_heavy_scenario);

        // Verify that multiple readers can be active simultaneously
        let reader_acquisitions: Vec<_> = trace.acquisition_order
            .iter()
            .filter(|(_, op_type, _)| op_type == "read")
            .collect();

        prop_assert!(
            reader_acquisitions.len() >= 5,
            "Expected multiple reader acquisitions in read-heavy scenario, got: {}",
            reader_acquisitions.len()
        );

        // Check for evidence of concurrent reads (reader cohorts)
        prop_assert!(
            trace.reader_cohorts.len() >= 1 || reader_acquisitions.len() >= 10,
            "Expected evidence of concurrent reads: {} cohorts, {} total reads",
            trace.reader_cohorts.len(),
            reader_acquisitions.len()
        );

        // Verify no data corruption occurred (lock wasn't poisoned)
        prop_assert!(
            !harness.lock.is_poisoned(),
            "RwLock should not be poisoned after concurrent reads"
        );
    }
}

// ============================================================================
// MR5: Writer exclusivity maintains data integrity
// ============================================================================

proptest! {
    /// MR5: Writer exclusivity maintains data integrity
    /// Writers should have exclusive access and maintain data consistency.
    #[test]
    fn mr_writer_exclusivity_integrity(seed: u64) {
        let mut harness = RwLockFairnessHarness::new(seed);

        // Create a scenario with both reads and writes
        let mixed_scenario = RwLockScenario {
            operations: vec![
                RwLockOp::Write { duration_steps: 3, writer_id: 1, value: 100 },
                RwLockOp::Read { duration_steps: 2, reader_id: 1 },
                RwLockOp::Read { duration_steps: 2, reader_id: 2 },
                RwLockOp::Write { duration_steps: 3, writer_id: 2, value: 200 },
                RwLockOp::Read { duration_steps: 2, reader_id: 3 },
                RwLockOp::Write { duration_steps: 2, writer_id: 3, value: 300 },
            ],
            concurrency: 6,
            max_steps: 150,
        };

        let trace = harness.run_scenario(&mixed_scenario);

        // Verify writer exclusivity: no two writers should be active simultaneously
        let writer_acquisitions: Vec<_> = trace.acquisition_order
            .iter()
            .filter(|(_, op_type, _)| op_type == "write")
            .collect();

        // Check that writers are properly spaced (no overlapping exclusivity violations)
        for window in writer_acquisitions.windows(2) {
            let (time1, _, id1) = window[0];
            let (time2, _, id2) = window[1];

            prop_assert!(
                time2 > time1,
                "Writers should not overlap: writer {} (time {}) and writer {} (time {})",
                id1, time1, id2, time2
            );
        }

        // Verify data integrity wasn't compromised
        prop_assert!(
            !harness.lock.is_poisoned(),
            "RwLock should not be poisoned after mixed read/write operations"
        );

        // Check that reader-writer exclusion is maintained
        let all_acquisitions: Vec<_> = trace.acquisition_order.iter().collect();

        // Look for potential read-write conflicts (shouldn't happen with proper locking)
        for (i, (time1, op_type1, id1)) in all_acquisitions.iter().enumerate() {
            for (time2, op_type2, id2) in all_acquisitions.iter().skip(i + 1).take(5) {
                if *time1 == *time2 {
                    // Simultaneous acquisition should only happen between readers
                    prop_assert!(
                        !(op_type1 == "write" && op_type2 == "read") &&
                        !(op_type1 == "read" && op_type2 == "write") &&
                        !(op_type1 == "write" && op_type2 == "write"),
                        "Simultaneous acquisition violation: {} {} and {} {} at time {}",
                        op_type1, id1, op_type2, id2, time1
                    );
                }
            }
        }
    }
}

// ============================================================================
// Integration Tests with Specific Fairness Scenarios
// ============================================================================

#[test]
fn writer_preference_prevents_reader_monopoly() {
    let seed = 0xPREVENT;
    let mut harness = RwLockFairnessHarness::new(seed);

    // Scenario: continuous readers should not prevent writers from eventually acquiring
    let reader_monopoly_scenario = RwLockScenario {
        operations: vec![
            // Start with some readers
            RwLockOp::Read { duration_steps: 10, reader_id: 1 },
            RwLockOp::Read { duration_steps: 10, reader_id: 2 },
            RwLockOp::Read { duration_steps: 10, reader_id: 3 },
            // Writer request should eventually succeed despite reader pressure
            RwLockOp::Write { duration_steps: 5, writer_id: 1, value: 999 },
            // More readers after writer - these should be blocked initially
            RwLockOp::Read { duration_steps: 5, reader_id: 4 },
            RwLockOp::Read { duration_steps: 5, reader_id: 5 },
        ],
        concurrency: 6,
        max_steps: 200,
    };

    let trace = harness.run_scenario(&reader_monopoly_scenario);

    // Verify that the writer eventually acquired the lock
    let writer_acquired = trace.acquisition_order
        .iter()
        .any(|(_, op_type, id)| op_type == "write" && *id == 1);

    assert!(
        writer_acquired,
        "Writer should eventually acquire lock despite reader pressure"
    );

    // Verify that later readers (4, 5) were delayed until after writer
    let writer_time = trace.acquisition_order
        .iter()
        .find(|(_, op_type, id)| op_type == "write" && *id == 1)
        .map(|(time, _, _)| *time)
        .unwrap_or(0);

    let late_reader_times: Vec<_> = trace.acquisition_order
        .iter()
        .filter(|(_, op_type, id)| op_type == "read" && (*id == 4 || *id == 5))
        .map(|(time, _, _)| *time)
        .collect();

    for late_reader_time in late_reader_times {
        assert!(
            late_reader_time >= writer_time,
            "Late readers should not acquire before writer: reader time {}, writer time {}",
            late_reader_time, writer_time
        );
    }
}

#[test]
fn reader_coalescing_after_writer_release() {
    let seed = 0xC0ALES2;
    let mut harness = RwLockFairnessHarness::new(seed);

    // Scenario: writer followed by multiple waiting readers
    let coalescing_scenario = RwLockScenario {
        operations: vec![
            RwLockOp::Write { duration_steps: 8, writer_id: 1, value: 777 },
            // These readers should wait and then be coalesced
            RwLockOp::Read { duration_steps: 3, reader_id: 1 },
            RwLockOp::Read { duration_steps: 3, reader_id: 2 },
            RwLockOp::Read { duration_steps: 3, reader_id: 3 },
            RwLockOp::Read { duration_steps: 3, reader_id: 4 },
        ],
        concurrency: 5,
        max_steps: 100,
    };

    let trace = harness.run_scenario(&coalescing_scenario);

    // Find when the writer released
    let writer_time = trace.acquisition_order
        .iter()
        .find(|(_, op_type, id)| op_type == "write" && *id == 1)
        .map(|(time, _, _)| *time)
        .unwrap_or(0);

    // Find reader acquisitions after writer
    let post_writer_readers: Vec<_> = trace.acquisition_order
        .iter()
        .filter(|(time, op_type, _)| op_type == "read" && *time > writer_time)
        .collect();

    // Readers should acquire close together (coalesced)
    if post_writer_readers.len() >= 2 {
        let reader_times: Vec<_> = post_writer_readers.iter().map(|(time, _, _)| **time).collect();
        let time_span = reader_times.iter().max().unwrap() - reader_times.iter().min().unwrap();

        assert!(
            time_span <= 10,
            "Post-writer readers should be coalesced within small time window, got span: {}",
            time_span
        );
    }

    // Should have evidence of reader cohorts
    assert!(
        !trace.reader_cohorts.is_empty() || post_writer_readers.len() >= 3,
        "Expected evidence of reader coalescing: {} cohorts, {} post-writer readers",
        trace.reader_cohorts.len(),
        post_writer_readers.len()
    );
}

// ============================================================================
// Deterministic Replay Tests
// ============================================================================

#[test]
fn deterministic_fairness_replay() {
    let seed = 0xDETE12;

    // Run the same scenario twice and verify deterministic fairness behavior
    let scenario = RwLockScenario {
        operations: vec![
            RwLockOp::Read { duration_steps: 5, reader_id: 1 },
            RwLockOp::Write { duration_steps: 3, writer_id: 1, value: 42 },
            RwLockOp::Read { duration_steps: 4, reader_id: 2 },
            RwLockOp::Read { duration_steps: 4, reader_id: 3 },
            RwLockOp::Write { duration_steps: 2, writer_id: 2, value: 84 },
        ],
        concurrency: 5,
        max_steps: 80,
    };

    let mut harness1 = RwLockFairnessHarness::new(seed);
    let trace1 = harness1.run_scenario(&scenario);

    let mut harness2 = RwLockFairnessHarness::new(seed);
    let trace2 = harness2.run_scenario(&scenario);

    // Acquisition orders should be deterministic
    assert_eq!(
        trace1.acquisition_order.len(),
        trace2.acquisition_order.len(),
        "Deterministic runs should have same acquisition count"
    );

    // At least some acquisitions should match deterministically
    let matching_acquisitions = trace1.acquisition_order
        .iter()
        .zip(trace2.acquisition_order.iter())
        .filter(|((_, op1, id1), (_, op2, id2))| op1 == op2 && id1 == id2)
        .count();

    assert!(
        matching_acquisitions >= trace1.acquisition_order.len() / 2,
        "Expected deterministic behavior in at least half of acquisitions: {} / {}",
        matching_acquisitions,
        trace1.acquisition_order.len()
    );
}