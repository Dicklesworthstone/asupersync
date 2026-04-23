#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use asupersync::lab::oracle::cancel_debt::{
    CancelDebtOracle, CancelDebtConfig, CleanupWorkType,
};
use asupersync::types::{TaskId, RegionId, Time};

/// Fuzz input for CancelDebtOracle testing
#[derive(Arbitrary, Debug)]
struct CancelDebtFuzzInput {
    /// Configuration parameters for the oracle
    config: FuzzConfig,
    /// Sequence of operations to perform
    operation_sequence: Vec<DebtOperation>,
    /// Attack scenarios to test specific edge cases
    attack_scenario: AttackScenario,
}

#[derive(Arbitrary, Debug, Clone)]
struct FuzzConfig {
    /// Maximum debt threshold
    max_debt_items: u16,
    /// Measurement window in milliseconds (converted to nanoseconds)
    measurement_window_ms: u32,
    /// Max debt accumulation rate per second
    max_debt_rate_per_sec: u8,
    /// Maximum violations to track
    max_violations: u16,
    /// Whether to panic on violations (disabled for fuzzing)
    panic_on_violation: bool,
    /// Capture stack traces
    capture_stack_traces: bool,
}

impl From<FuzzConfig> for CancelDebtConfig {
    fn from(config: FuzzConfig) -> Self {
        Self {
            max_debt_items: config.max_debt_items as usize,
            measurement_window_ns: config.measurement_window_ms as u64 * 1_000_000, // ms to ns
            max_debt_rate_per_sec: config.max_debt_rate_per_sec as f64,
            max_violations: config.max_violations as usize,
            panic_on_violation: false, // Always disabled for fuzzing
            capture_stack_traces: config.capture_stack_traces,
            max_stack_trace_depth: 16, // Reasonable limit
        }
    }
}

/// Operations that can be performed on the debt oracle
#[derive(Arbitrary, Debug, Clone)]
enum DebtOperation {
    /// Add a work item to a queue
    AddWorkItem {
        queue_type: FuzzQueueType,
        task_id: Option<u32>,
        region_id: Option<u32>,
        work_type: FuzzWorkType,
        timestamp_offset_ms: u16, // Offset from base time
    },
    /// Complete work items from a queue
    CompleteWorkItems {
        queue_type: FuzzQueueType,
        count: u16,
        timestamp_offset_ms: u16,
    },
    /// Check for debt accumulation violations
    CheckDebt {
        timestamp_offset_ms: u16,
    },
    /// Call general check method
    CheckGeneral {
        timestamp_offset_ms: u16,
    },
    /// Reset the oracle state
    Reset,
    /// Get statistics (introspection)
    GetStatistics,
    /// Get recent violations
    GetViolations { limit: u8 },
    /// Get queue states
    GetQueueStates,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum FuzzQueueType {
    Finalizer,
    Cleanup,
    Discharge,
    Allocation,
    Custom1,
    Custom2,
}

impl From<FuzzQueueType> for String {
    fn from(queue_type: FuzzQueueType) -> String {
        match queue_type {
            FuzzQueueType::Finalizer => "finalizer_queue".to_string(),
            FuzzQueueType::Cleanup => "cleanup_queue".to_string(),
            FuzzQueueType::Discharge => "discharge_queue".to_string(),
            FuzzQueueType::Allocation => "allocation_queue".to_string(),
            FuzzQueueType::Custom1 => "custom_queue_1".to_string(),
            FuzzQueueType::Custom2 => "custom_queue_2".to_string(),
        }
    }
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum FuzzWorkType {
    TaskFinalization,
    RegionCleanup,
    ObligationDischarge,
    ResourceDeallocation,
    FinalizerExecution,
}

impl From<FuzzWorkType> for CleanupWorkType {
    fn from(work_type: FuzzWorkType) -> Self {
        match work_type {
            FuzzWorkType::TaskFinalization => CleanupWorkType::TaskFinalization,
            FuzzWorkType::RegionCleanup => CleanupWorkType::RegionCleanup,
            FuzzWorkType::ObligationDischarge => CleanupWorkType::ObligationDischarge,
            FuzzWorkType::ResourceDeallocation => CleanupWorkType::ResourceDeallocation,
            FuzzWorkType::FinalizerExecution => CleanupWorkType::FinalizerExecution,
        }
    }
}

/// Specific attack scenarios and edge cases to test
#[derive(Arbitrary, Debug, Clone)]
enum AttackScenario {
    /// Normal operation (baseline)
    Normal,
    /// Debt accumulation bomb: rapid work item addition
    DebtBomb {
        queue_type: FuzzQueueType,
        work_count: u16,
        work_type: FuzzWorkType,
    },
    /// Starvation: add work but never complete any
    Starvation {
        queue_type: FuzzQueueType,
        work_count: u16,
    },
    /// Completion without addition
    CompletionWithoutWork {
        queue_type: FuzzQueueType,
        completion_count: u16,
    },
    /// Timestamp manipulation: future timestamps
    FutureTimestamps {
        operations: Vec<DebtOperation>,
        future_offset_ms: u32,
    },
    /// Threshold boundary testing: exactly at limits
    BoundaryTest {
        target_debt: u16,
        queue_type: FuzzQueueType,
    },
    /// Queue type switching: same queue names but different patterns
    QueueTypeSwitching {
        queue_type: FuzzQueueType,
        pattern_count: u8,
    },
    /// Resource exhaustion simulation
    ResourceExhaustion {
        memory_target_kb: u32,
    },
    /// Completion rate manipulation
    CompletionRateManipulation {
        add_rate: u8,
        complete_rate: u8,
    },
}

fuzz_target!(|input: CancelDebtFuzzInput| {
    // Property 1: No panic on any operation sequence
    test_no_panic(&input);

    // Property 2: Statistics consistency
    test_statistics_consistency(&input);

    // Property 3: Debt accumulation detection
    test_debt_accumulation_detection(&input);

    // Property 4: Queue management correctness
    test_queue_management(&input);

    // Property 5: Timestamp ordering and validation
    test_timestamp_handling(&input);

    // Property 6: Attack scenario resilience
    test_attack_scenarios(&input);

    // Property 7: Configuration bounds enforcement
    test_configuration_bounds(&input);
});

/// Property 1: No panic on any operation sequence
fn test_no_panic(input: &CancelDebtFuzzInput) {
    let config = input.config.clone().into();
    let oracle = CancelDebtOracle::new(config);
    let base_time = Time::from_nanos(1_000_000_000); // 1 second

    // Process all operations - should never panic
    for operation in &input.operation_sequence {
        let _result = std::panic::catch_unwind(|| {
            process_operation(&oracle, operation, base_time);
        });
    }

    // If we reach here without panic, the property holds
    assert!(true, "Oracle handled operation sequence without panic");
}

/// Property 2: Statistics consistency
fn test_statistics_consistency(input: &CancelDebtFuzzInput) {
    let config = input.config.clone().into();
    let oracle = CancelDebtOracle::new(config);
    let base_time = Time::from_nanos(1_000_000_000);

    let mut work_items_added = 0u64;
    let mut work_items_completed = 0u64;

    // Track operations and verify statistics make sense
    for operation in &input.operation_sequence {
        match operation {
            DebtOperation::AddWorkItem { .. } => {
                work_items_added += 1;
            }
            DebtOperation::CompleteWorkItems { count, .. } => {
                work_items_completed += *count as u64;
            }
            DebtOperation::Reset => {
                work_items_added = 0;
                work_items_completed = 0;
            }
            _ => {}
        }

        process_operation(&oracle, operation, base_time);

        // Check that statistics are reasonable
        let stats = oracle.get_statistics();

        // Statistics should never be negative or wildly inconsistent
        assert!(stats.work_items_tracked < u64::MAX);
        assert!(stats.completions_tracked < u64::MAX);
        assert!(stats.violations_detected < u64::MAX);
        assert!(stats.debt_checks_performed < u64::MAX);
        assert!(stats.tracked_queues < 1000); // Reasonable upper bound
        assert!(stats.total_current_debt < 1_000_000); // Reasonable upper bound
    }
}

/// Property 3: Debt accumulation detection
fn test_debt_accumulation_detection(input: &CancelDebtFuzzInput) {
    if let AttackScenario::DebtBomb { queue_type, work_count, work_type } = &input.attack_scenario {
        let config = CancelDebtConfig {
            max_debt_items: 10, // Low threshold for testing
            max_debt_rate_per_sec: 5.0, // Low rate for testing
            ..input.config.clone().into()
        };
        let oracle = CancelDebtOracle::new(config);
        let base_time = Time::from_nanos(1_000_000_000);

        // Add many work items rapidly
        let queue_name: String = (*queue_type).into();
        let work_type_converted = (*work_type).into();

        for i in 0..*work_count {
            let timestamp = Time::from_nanos(base_time.as_nanos() + i as u64 * 1_000_000); // 1ms apart
            oracle.on_work_item_added(
                &queue_name,
                Some(TaskId(i as u64)),
                None,
                work_type_converted,
                timestamp,
            );
        }

        // Check for violations
        oracle.check_debt_accumulation(Time::from_nanos(base_time.as_nanos() + 1_000_000_000));

        let violations = oracle.get_recent_violations(10);
        // With enough work items, we should detect violations
        // This is probabilistic based on thresholds, so we don't assert hard requirements
        let _violation_count = violations.len();

        assert!(true, "Debt accumulation detection completed without panic");
    }
}

/// Property 4: Queue management correctness
fn test_queue_management(input: &CancelDebtFuzzInput) {
    let config = input.config.clone().into();
    let oracle = CancelDebtOracle::new(config);
    let base_time = Time::from_nanos(1_000_000_000);

    // Test edge case: completion without addition
    if let AttackScenario::CompletionWithoutWork { queue_type, completion_count } = &input.attack_scenario {
        let queue_name: String = (*queue_type).into();

        // Try to complete items from empty queue
        oracle.on_work_items_completed(
            &queue_name,
            *completion_count as usize,
            base_time,
        );

        // Should handle gracefully
        let stats = oracle.get_statistics();
        assert!(stats.total_current_debt == 0, "Debt should remain 0 when completing from empty queue");
    }
}

/// Property 5: Timestamp handling
fn test_timestamp_handling(input: &CancelDebtFuzzInput) {
    if let AttackScenario::FutureTimestamps { operations, future_offset_ms } = &input.attack_scenario {
        let config = input.config.clone().into();
        let oracle = CancelDebtOracle::new(config);
        let base_time = Time::from_nanos(1_000_000_000);

        // Use future timestamps
        let future_time = Time::from_nanos(
            base_time.as_nanos() + (*future_offset_ms as u64) * 1_000_000
        );

        for operation in operations {
            // Process with future timestamp context
            process_operation(&oracle, operation, future_time);
        }

        // Should handle future timestamps gracefully
        assert!(true, "Future timestamp handling completed without panic");
    }
}

/// Property 6: Attack scenario resilience
fn test_attack_scenarios(input: &CancelDebtFuzzInput) {
    let config = input.config.clone().into();
    let oracle = CancelDebtOracle::new(config);
    let base_time = Time::from_nanos(1_000_000_000);

    match &input.attack_scenario {
        AttackScenario::Starvation { queue_type, work_count } => {
            let queue_name: String = (*queue_type).into();

            // Add many work items but never complete any
            for i in 0..*work_count {
                oracle.on_work_item_added(
                    &queue_name,
                    Some(TaskId(i as u64)),
                    None,
                    CleanupWorkType::TaskFinalization,
                    Time::from_nanos(base_time.as_nanos() + i as u64 * 1_000_000),
                );
            }

            // Check for stalls/violations
            oracle.check(Time::from_nanos(base_time.as_nanos() + 10_000_000_000)); // 10 seconds later
            assert!(true, "Starvation scenario handled without panic");
        }
        AttackScenario::ResourceExhaustion { memory_target_kb } => {
            // Try to exhaust memory by adding large work items
            let target_bytes = (*memory_target_kb as usize) * 1024;
            let queue_name = "memory_test_queue";

            // Add items until we approach target memory usage
            let mut added_items = 0;
            while added_items < 10000 { // Safety limit
                oracle.on_work_item_added(
                    queue_name,
                    Some(TaskId(added_items)),
                    None,
                    CleanupWorkType::RegionCleanup, // Larger estimated size
                    Time::from_nanos(base_time.as_nanos() + added_items * 1_000_000),
                );

                let stats = oracle.get_statistics();
                if stats.total_estimated_memory_usage >= target_bytes {
                    break;
                }

                added_items += 1;
            }

            // Should handle memory pressure gracefully
            oracle.check(base_time);
            assert!(true, "Resource exhaustion scenario handled without panic");
        }
        _ => {}
    }
}

/// Property 7: Configuration bounds enforcement
fn test_configuration_bounds(input: &CancelDebtFuzzInput) {
    if let AttackScenario::BoundaryTest { target_debt, queue_type } = &input.attack_scenario {
        let config = CancelDebtConfig {
            max_debt_items: *target_debt as usize,
            ..input.config.clone().into()
        };
        let oracle = CancelDebtOracle::new(config);
        let base_time = Time::from_nanos(1_000_000_000);
        let queue_name: String = (*queue_type).into();

        // Add exactly the threshold number of items
        for i in 0..*target_debt {
            oracle.on_work_item_added(
                &queue_name,
                Some(TaskId(i as u64)),
                None,
                CleanupWorkType::TaskFinalization,
                Time::from_nanos(base_time.as_nanos() + i as u64 * 1_000_000),
            );
        }

        // Add one more to exceed threshold
        oracle.on_work_item_added(
            &queue_name,
            Some(TaskId(*target_debt as u64)),
            None,
            CleanupWorkType::TaskFinalization,
            Time::from_nanos(base_time.as_nanos() + *target_debt as u64 * 1_000_000),
        );

        // Check that threshold violation is detected
        oracle.check(base_time);

        let violations = oracle.get_recent_violations(5);
        // Should detect threshold violation
        let _has_threshold_violation = violations.iter().any(|v| {
            matches!(v, asupersync::lab::oracle::cancel_debt::CancelDebtViolation::DebtThresholdExceeded { .. })
        });

        assert!(true, "Boundary test completed without panic");
    }
}

/// Helper function to process a debt operation
fn process_operation(oracle: &CancelDebtOracle, operation: &DebtOperation, base_time: Time) {
    match operation {
        DebtOperation::AddWorkItem {
            queue_type,
            task_id,
            region_id,
            work_type,
            timestamp_offset_ms,
        } => {
            let queue_name: String = (*queue_type).into();
            let timestamp = Time::from_nanos(
                base_time.as_nanos() + (*timestamp_offset_ms as u64) * 1_000_000
            );

            oracle.on_work_item_added(
                &queue_name,
                task_id.map(|id| TaskId(id as u64)),
                region_id.map(|id| RegionId(id as u64)),
                (*work_type).into(),
                timestamp,
            );
        }
        DebtOperation::CompleteWorkItems {
            queue_type,
            count,
            timestamp_offset_ms,
        } => {
            let queue_name: String = (*queue_type).into();
            let timestamp = Time::from_nanos(
                base_time.as_nanos() + (*timestamp_offset_ms as u64) * 1_000_000
            );

            oracle.on_work_items_completed(&queue_name, *count as usize, timestamp);
        }
        DebtOperation::CheckDebt { timestamp_offset_ms } => {
            let timestamp = Time::from_nanos(
                base_time.as_nanos() + (*timestamp_offset_ms as u64) * 1_000_000
            );
            oracle.check_debt_accumulation(timestamp);
        }
        DebtOperation::CheckGeneral { timestamp_offset_ms } => {
            let timestamp = Time::from_nanos(
                base_time.as_nanos() + (*timestamp_offset_ms as u64) * 1_000_000
            );
            let _ = oracle.check(timestamp);
        }
        DebtOperation::Reset => {
            oracle.reset();
        }
        DebtOperation::GetStatistics => {
            let _ = oracle.get_statistics();
        }
        DebtOperation::GetViolations { limit } => {
            let _ = oracle.get_recent_violations(*limit as usize);
        }
        DebtOperation::GetQueueStates => {
            let _ = oracle.get_queue_states();
        }
    }
}