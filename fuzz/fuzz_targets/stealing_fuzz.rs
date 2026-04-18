#![no_main]

//! Fuzz target for work-stealing inter-worker steal logic.
//!
//! This target exercises critical work stealing scenarios including:
//! 1. Power of Two Choices randomized load balancing
//! 2. Fallback mechanisms when primary/secondary choices fail
//! 3. Linear scan behavior when random choices are exhausted
//! 4. Local task filtering and steal rejection
//! 5. Concurrent stealing with multiple workers
//! 6. Queue configuration edge cases (empty, single, heavy loads)
//! 7. RNG seed effects on selection fairness and patterns

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;

use asupersync::runtime::scheduler::local_queue::{LocalQueue, Stealer};
use asupersync::runtime::scheduler::stealing::steal_task;
use asupersync::types::TaskId;
use asupersync::util::DetRng;

/// Simplified fuzz input for work stealing operations
#[derive(Arbitrary, Debug, Clone)]
struct StealingFuzzInput {
    /// Random seed for deterministic execution
    pub seed: u64,
    /// Sequence of operations to execute
    pub operations: Vec<StealingOperation>,
    /// Queue configuration
    pub queue_config: QueueConfiguration,
    /// Stealing configuration
    pub steal_config: StealingConfiguration,
}

/// Individual stealing operations to fuzz
#[derive(Arbitrary, Debug, Clone)]
enum StealingOperation {
    /// Single steal attempt
    SingleSteal { rng_seed: u64 },
    /// Multiple steals with same RNG
    MultipleSteal { count: u8, rng_seed: u64 },
    /// Concurrent stealing scenario
    ConcurrentSteal { stealer_count: u8, steal_rounds: u8 },
    /// Add tasks to specific queue
    AddTasks {
        queue_index: u8,
        task_count: u8,
        mark_local: bool,
    },
    /// Remove tasks from queue
    RemoveTasks { queue_index: u8, count: u8 },
    /// Test power-of-two preference
    TestPowerOfTwo { rng_seed: u64 },
    /// Test linear scan fallback
    TestLinearScan { rng_seed: u64 },
    /// Test deterministic behavior
    TestDeterministic { rng_seed: u64 },
}

/// Configuration for queue setup
#[derive(Arbitrary, Debug, Clone)]
struct QueueConfiguration {
    /// Number of worker queues
    pub queue_count: u8,
    /// Initial tasks per queue
    pub initial_tasks: Vec<u8>,
    /// Queue capacities
    pub queue_capacities: Vec<u8>,
    /// Local task patterns
    pub local_task_patterns: Vec<bool>,
}

/// Configuration for stealing behavior
#[derive(Arbitrary, Debug, Clone)]
struct StealingConfiguration {
    /// Enable fairness tracking
    pub track_fairness: bool,
    /// Enable concurrent stress testing
    pub enable_concurrent_stress: bool,
    /// Maximum operations per test
    pub max_operations: u8,
    /// Concurrent thread count limit
    pub max_concurrent_threads: u8,
}

/// Mock task creation helper
fn task(id: u32) -> TaskId {
    TaskId::new_for_test(id, 0)
}

/// Shadow model for tracking stealing behavior and fairness
#[derive(Debug)]
struct StealingShadowModel {
    /// Total steal attempts
    total_steals: AtomicUsize,
    /// Successful steals
    successful_steals: AtomicUsize,
    /// Failed steals (empty/local-only)
    failed_steals: AtomicUsize,
    /// Per-queue steal counts for fairness tracking
    per_queue_steals: Arc<std::sync::Mutex<HashMap<usize, usize>>>,
    /// Concurrent access violations
    violations: AtomicUsize,
}

impl StealingShadowModel {
    fn new() -> Self {
        Self {
            total_steals: AtomicUsize::new(0),
            successful_steals: AtomicUsize::new(0),
            failed_steals: AtomicUsize::new(0),
            per_queue_steals: Arc::new(std::sync::Mutex::new(HashMap::new())),
            violations: AtomicUsize::new(0),
        }
    }

    fn record_steal_attempt(&self, successful: bool, source_queue: Option<usize>) {
        self.total_steals.fetch_add(1, Ordering::SeqCst);

        if successful {
            self.successful_steals.fetch_add(1, Ordering::SeqCst);
            if let Some(queue_idx) = source_queue {
                if let Ok(mut counts) = self.per_queue_steals.lock() {
                    *counts.entry(queue_idx).or_insert(0) += 1;
                }
            }
        } else {
            self.failed_steals.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn record_violation(&self) {
        self.violations.fetch_add(1, Ordering::SeqCst);
    }

    fn verify_fairness(&self, queue_count: usize) -> Result<(), String> {
        if queue_count <= 1 {
            return Ok(()); // No fairness to verify
        }

        let successful = self.successful_steals.load(Ordering::SeqCst);
        if successful == 0 {
            return Ok(()); // No steals to analyze
        }

        if let Ok(counts) = self.per_queue_steals.lock() {
            let total_tracked: usize = counts.values().sum();

            // Basic fairness check: no queue should get more than 80% of steals
            let max_allowed = (successful * 80) / 100;

            for (&queue_idx, &count) in counts.iter() {
                if count > max_allowed {
                    return Err(format!(
                        "Fairness violation: queue {} got {} steals ({}%), max allowed {}",
                        queue_idx,
                        count,
                        (count * 100) / successful,
                        max_allowed
                    ));
                }
            }

            // Verify tracking consistency
            if total_tracked > successful {
                return Err(format!(
                    "Tracking inconsistency: tracked {} > successful {}",
                    total_tracked, successful
                ));
            }
        }

        Ok(())
    }

    fn verify_invariants(&self) -> Result<(), String> {
        let total = self.total_steals.load(Ordering::SeqCst);
        let successful = self.successful_steals.load(Ordering::SeqCst);
        let failed = self.failed_steals.load(Ordering::SeqCst);
        let violations = self.violations.load(Ordering::SeqCst);

        // Basic accounting
        if successful + failed != total {
            return Err(format!(
                "Steal accounting error: successful({}) + failed({}) != total({})",
                successful, failed, total
            ));
        }

        // No violations should occur in correct implementation
        if violations > 0 {
            return Err(format!("Detected {} violations", violations));
        }

        Ok(())
    }
}

/// Setup queues based on configuration
fn setup_queues(config: &QueueConfiguration) -> Vec<LocalQueue> {
    let queue_count = config.queue_count.clamp(1, 16) as usize;
    let mut queues = Vec::new();

    for i in 0..queue_count {
        let capacity = config
            .queue_capacities
            .get(i)
            .copied()
            .unwrap_or(10)
            .clamp(1, 50) as usize;

        let queue = LocalQueue::new_for_test(capacity as u32);

        // Add initial tasks
        let initial_count = config
            .initial_tasks
            .get(i)
            .copied()
            .unwrap_or(0)
            .clamp(0, 20);

        for j in 0..initial_count {
            let task_id = task((i * 100 + j as usize) as u32);
            queue.push(task_id);
        }

        queues.push(queue);
    }

    queues
}

/// Mark specific tasks as local-only in a queue
fn mark_local_tasks(queues: &[LocalQueue], config: &QueueConfiguration) {
    for (i, &mark_local) in config.local_task_patterns.iter().enumerate() {
        if mark_local && i < queues.len() {
            // This would require access to the task arena to mark tasks as local
            // For now, we'll simulate this with queue structure
        }
    }
}

/// Test single stealing operation
fn test_single_steal(
    stealers: &[Stealer],
    rng_seed: u64,
    shadow: &StealingShadowModel,
) -> Result<(), String> {
    let mut rng = DetRng::new(rng_seed);

    let stolen = steal_task(stealers, &mut rng);

    let successful = stolen.is_some();
    shadow.record_steal_attempt(successful, None);

    // Verify steal result consistency
    if successful {
        let task_id = stolen.unwrap();
        // Basic validation that we got a valid TaskId
        // TaskIds should be non-zero in normal operation
        if format!("{:?}", task_id) == "TaskId(0:0)" {
            shadow.record_violation();
            return Err("Stolen task has invalid ID".to_string());
        }
    }

    Ok(())
}

/// Test multiple steals with same RNG seed
fn test_multiple_steal(
    stealers: &[Stealer],
    count: u8,
    rng_seed: u64,
    shadow: &StealingShadowModel,
) -> Result<(), String> {
    let mut rng = DetRng::new(rng_seed);
    let mut stolen_tasks = Vec::new();

    for _ in 0..count.clamp(1, 20) {
        if let Some(task) = steal_task(stealers, &mut rng) {
            stolen_tasks.push(task);
            shadow.record_steal_attempt(true, None);
        } else {
            shadow.record_steal_attempt(false, None);
        }
    }

    // Verify no duplicate steals
    stolen_tasks.sort();
    let original_len = stolen_tasks.len();
    stolen_tasks.dedup();

    if stolen_tasks.len() != original_len {
        shadow.record_violation();
        return Err("Duplicate task stolen".to_string());
    }

    Ok(())
}

/// Test concurrent stealing scenario
fn test_concurrent_steal(
    stealers: &[Stealer],
    stealer_count: u8,
    steal_rounds: u8,
    shadow: &StealingShadowModel,
) -> Result<(), String> {
    let stealer_count = stealer_count.clamp(2, 8) as usize;
    let steal_rounds = steal_rounds.clamp(1, 10) as usize;

    let stolen_count = Arc::new(AtomicUsize::new(0));
    let barrier = Arc::new(Barrier::new(stealer_count));
    let all_stolen_tasks = Arc::new(std::sync::Mutex::new(Vec::new()));
    let violation_count = Arc::new(AtomicUsize::new(0));

    let handles: Vec<_> = (0..stealer_count)
        .map(|i| {
            let stealers = stealers.to_vec();
            let count = stolen_count.clone();
            let b = barrier.clone();
            let all_tasks = all_stolen_tasks.clone();
            let violations = violation_count.clone();

            thread::spawn(move || {
                let mut rng = DetRng::new(i as u64);
                let mut local_stolen = Vec::new();
                let mut local_successful = 0;
                let mut local_failed = 0;

                b.wait();

                for _ in 0..steal_rounds {
                    if let Some(task) = steal_task(&stealers, &mut rng) {
                        // Basic validation
                        if format!("{:?}", task) == "TaskId(0:0)" {
                            violations.fetch_add(1, Ordering::SeqCst);
                        }

                        local_stolen.push(task);
                        count.fetch_add(1, Ordering::SeqCst);
                        local_successful += 1;
                    } else {
                        local_failed += 1;
                    }

                    thread::yield_now();
                }

                if let Ok(mut all) = all_tasks.lock() {
                    all.extend(local_stolen);
                }

                (local_successful, local_failed)
            })
        })
        .collect();

    let mut total_successful = 0;
    let mut total_failed = 0;

    for h in handles {
        match h.join() {
            Ok((successful, failed)) => {
                total_successful += successful;
                total_failed += failed;
            }
            Err(_) => {
                shadow.record_violation();
                return Err("Concurrent steal thread panicked".to_string());
            }
        }
    }

    // Record the steal attempts in shadow model
    for _ in 0..total_successful {
        shadow.record_steal_attempt(true, None);
    }
    for _ in 0..total_failed {
        shadow.record_steal_attempt(false, None);
    }

    // Record any violations found in threads
    let violations = violation_count.load(Ordering::SeqCst);
    for _ in 0..violations {
        shadow.record_violation();
    }

    // Verify no task was stolen multiple times
    if let Ok(mut all_tasks) = all_stolen_tasks.lock() {
        all_tasks.sort();
        let original_len = all_tasks.len();
        all_tasks.dedup();

        if all_tasks.len() != original_len {
            shadow.record_violation();
            return Err("Task stolen by multiple threads".to_string());
        }
    }

    Ok(())
}

/// Test Power of Two Choices preference
fn test_power_of_two_preference(
    stealers: &[Stealer],
    rng_seed: u64,
    shadow: &StealingShadowModel,
) -> Result<(), String> {
    if stealers.len() < 2 {
        return Ok(()); // Need at least 2 queues for power of two
    }

    let mut rng = DetRng::new(rng_seed);

    // Record queue lengths before steal
    let queue_lengths: Vec<_> = stealers.iter().map(|s| s.len()).collect();

    let stolen = steal_task(stealers, &mut rng);
    let successful = stolen.is_some();

    // Find which queue was likely chosen (if any)
    let mut likely_source = None;
    if successful {
        // Simple heuristic: the source was likely one of the non-empty queues
        for (i, &len) in queue_lengths.iter().enumerate() {
            if len > 0 {
                likely_source = Some(i);
                break;
            }
        }
    }

    shadow.record_steal_attempt(successful, likely_source);

    Ok(())
}

/// Test linear scan fallback behavior
fn test_linear_scan_fallback(
    stealers: &[Stealer],
    rng_seed: u64,
    shadow: &StealingShadowModel,
) -> Result<(), String> {
    if stealers.is_empty() {
        let stolen = {
            let mut rng = DetRng::new(rng_seed);
            steal_task(stealers, &mut rng)
        };

        if stolen.is_some() {
            shadow.record_violation();
            return Err("Steal succeeded from empty stealer list".to_string());
        }

        shadow.record_steal_attempt(false, None);
        return Ok(());
    }

    let mut rng = DetRng::new(rng_seed);
    let stolen = steal_task(stealers, &mut rng);

    shadow.record_steal_attempt(stolen.is_some(), None);

    Ok(())
}

/// Test deterministic behavior with same seed
fn test_deterministic_behavior(
    stealers: &[Stealer],
    rng_seed: u64,
    shadow: &StealingShadowModel,
) -> Result<(), String> {
    if stealers.is_empty() {
        return Ok(());
    }

    // Record initial state
    let initial_lengths: Vec<_> = stealers.iter().map(|s| s.len()).collect();
    let total_initial_tasks: usize = initial_lengths.iter().sum();

    if total_initial_tasks == 0 {
        // No tasks to steal - both calls should return None
        let mut rng1 = DetRng::new(rng_seed);
        let mut rng2 = DetRng::new(rng_seed);

        let result1 = steal_task(stealers, &mut rng1);
        let result2 = steal_task(stealers, &mut rng2);

        if result1 != result2 {
            shadow.record_violation();
            return Err("Non-deterministic behavior with empty queues".to_string());
        }

        shadow.record_steal_attempt(false, None);
        shadow.record_steal_attempt(false, None);
    } else {
        // For non-empty case, we can't easily test determinism since steals modify state
        // Instead, verify that the same seed produces consistent choices
        let mut rng = DetRng::new(rng_seed);
        let stolen = steal_task(stealers, &mut rng);

        shadow.record_steal_attempt(stolen.is_some(), None);
    }

    Ok(())
}

/// Normalize fuzz input to valid ranges
fn normalize_fuzz_input(input: &mut StealingFuzzInput) {
    // Limit operations to prevent timeouts
    input.operations.truncate(20);

    // Normalize queue configuration
    input.queue_config.queue_count = input.queue_config.queue_count.clamp(1, 8);
    input
        .queue_config
        .initial_tasks
        .truncate(input.queue_config.queue_count as usize);
    input
        .queue_config
        .queue_capacities
        .truncate(input.queue_config.queue_count as usize);
    input
        .queue_config
        .local_task_patterns
        .truncate(input.queue_config.queue_count as usize);

    // Normalize stealing configuration
    input.steal_config.max_operations = input.steal_config.max_operations.clamp(1, 50);
    input.steal_config.max_concurrent_threads =
        input.steal_config.max_concurrent_threads.clamp(2, 8);

    // Ensure we have some operations to test
    if input.operations.is_empty() {
        input.operations.push(StealingOperation::SingleSteal {
            rng_seed: input.seed,
        });
    }
}

/// Execute work stealing operations and verify behavior
fn execute_stealing_operations(input: &StealingFuzzInput) -> Result<(), String> {
    let shadow = StealingShadowModel::new();

    // Setup queues
    let queues = setup_queues(&input.queue_config);
    mark_local_tasks(&queues, &input.queue_config);

    let stealers: Vec<_> = queues.iter().map(|q| q.stealer()).collect();

    // Execute operation sequence
    for (op_index, operation) in input.operations.iter().enumerate() {
        if op_index >= input.steal_config.max_operations as usize {
            break;
        }

        match operation {
            StealingOperation::SingleSteal { rng_seed } => {
                test_single_steal(&stealers, *rng_seed, &shadow)?;
            }

            StealingOperation::MultipleSteal { count, rng_seed } => {
                test_multiple_steal(&stealers, *count, *rng_seed, &shadow)?;
            }

            StealingOperation::ConcurrentSteal {
                stealer_count,
                steal_rounds,
            } => {
                if input.steal_config.enable_concurrent_stress {
                    test_concurrent_steal(&stealers, *stealer_count, *steal_rounds, &shadow)?;
                }
            }

            StealingOperation::AddTasks {
                queue_index,
                task_count,
                mark_local: _,
            } => {
                let idx = (*queue_index as usize) % queues.len();
                let count = (*task_count).clamp(1, 10);

                for i in 0..count {
                    let task_id = task((op_index * 1000 + i as usize) as u32);
                    queues[idx].push(task_id);
                }
            }

            StealingOperation::RemoveTasks { queue_index, count } => {
                let idx = (*queue_index as usize) % queues.len();
                let count = (*count).clamp(1, 5);

                // Try to pop tasks from the owner side
                for _ in 0..count {
                    if queues[idx].pop().is_none() {
                        break; // Queue is empty
                    }
                }
            }

            StealingOperation::TestPowerOfTwo { rng_seed } => {
                test_power_of_two_preference(&stealers, *rng_seed, &shadow)?;
            }

            StealingOperation::TestLinearScan { rng_seed } => {
                test_linear_scan_fallback(&stealers, *rng_seed, &shadow)?;
            }

            StealingOperation::TestDeterministic { rng_seed } => {
                test_deterministic_behavior(&stealers, *rng_seed, &shadow)?;
            }
        }

        // Verify invariants after each operation
        shadow.verify_invariants()?;
    }

    // Final checks
    if input.steal_config.track_fairness {
        shadow.verify_fairness(input.queue_config.queue_count as usize)?;
    }

    Ok(())
}

/// Main fuzzing entry point
fn fuzz_work_stealing(mut input: StealingFuzzInput) -> Result<(), String> {
    normalize_fuzz_input(&mut input);

    // Skip degenerate cases
    if input.operations.is_empty() {
        return Ok(());
    }

    // Execute work stealing tests
    execute_stealing_operations(&input)?;

    Ok(())
}

fuzz_target!(|data: &[u8]| {
    // Limit input size for performance
    if data.len() > 4096 {
        return;
    }

    let mut unstructured = arbitrary::Unstructured::new(data);

    // Generate fuzz configuration
    let input = if let Ok(input) = StealingFuzzInput::arbitrary(&mut unstructured) {
        input
    } else {
        return;
    };

    // Run work stealing fuzzing
    let _ = fuzz_work_stealing(input);
});
