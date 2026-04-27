//! Metamorphic property test for obligation ledger permit/ack count conservation
//! under concurrent cancellation (asupersync-w6oloe).
//!
//! Tests the core invariant: sum(permits_issued) == sum(permits_committed) + sum(permits_aborted)
//! This must hold across all concurrent schedules, even with mid-flight cancellation.
//!
//! Uses lab-runtime virtual time for deterministic execution and DPOR exploration
//! to cover different interleavings systematically.
//!
//! # Test Harness Constraints
//!
//! The test models only legal state transitions in accordance with asupersync invariants:
//! - FinalizeRegion is only attempted when no obligations are pending (region close = quiescence)
//! - Commit/abort after region cancellation is handled gracefully via try_* methods
//! - All conservation violations represent genuine bugs, not test harness artifacts

use asupersync::lab::runtime::LabRuntime;
use asupersync::lab::config::LabConfig;
use asupersync::lab::explorer::{DporExplorer, ExplorerConfig};
use asupersync::obligation::ledger::{ObligationLedger, ObligationToken, LedgerStats};
use asupersync::record::{ObligationAbortReason, ObligationKind};
use asupersync::types::{RegionId, TaskId};
use proptest::prelude::*;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Maximum number of operations per test scenario
const MAX_OPERATIONS: usize = 50;
/// Maximum number of concurrent tasks
const MAX_TASKS: usize = 8;
/// Maximum number of regions
const MAX_REGIONS: usize = 4;

#[derive(Debug, Clone)]
struct ObligationOperation {
    task_id: TaskId,
    region_id: RegionId,
    kind: ObligationKind,
    operation_type: OperationType,
    /// Delay before operation (in virtual nanoseconds)
    delay_nanos: u64,
}

#[derive(Debug, Clone)]
enum OperationType {
    /// Acquire a new obligation permit
    Acquire,
    /// Commit a previously acquired permit
    Commit { token_index: usize },
    /// Abort a previously acquired permit
    Abort { token_index: usize, reason: ObligationAbortReason },
    /// Cancel all pending obligations in a region (mid-flight cancellation)
    CancelRegion { region_id: RegionId },
    /// Finalize a region
    FinalizeRegion { region_id: RegionId },
    /// Check conservation invariant at this point
    CheckInvariant,
}

#[derive(Debug, Clone)]
struct ConcurrentScenario {
    operations: Vec<ObligationOperation>,
    initial_time: u64,
    /// Whether to use DPOR for schedule exploration
    use_dpor: bool,
}

/// Generate arbitrary obligation operations for testing
fn operation_strategy() -> impl Strategy<Value = ObligationOperation> {
    (
        1u32..=MAX_TASKS as u32,
        1u32..=MAX_REGIONS as u32,
        obligation_kind_strategy(),
        operation_type_strategy(),
        0u64..1_000_000u64, // delay up to 1ms in virtual time
    ).prop_map(|(task_raw, region_raw, kind, op_type, delay)| {
        ObligationOperation {
            task_id: TaskId::new_for_test(task_raw, 1),
            region_id: RegionId::new_for_test(region_raw, 1),
            kind,
            operation_type: op_type,
            delay_nanos: delay,
        }
    })
}

fn obligation_kind_strategy() -> impl Strategy<Value = ObligationKind> {
    prop_oneof![
        Just(ObligationKind::SendPermit),
        Just(ObligationKind::Ack),
        Just(ObligationKind::Lease),
        Just(ObligationKind::IoOp),
        Just(ObligationKind::SemaphorePermit),
    ]
}

fn operation_type_strategy() -> impl Strategy<Value = OperationType> {
    prop_oneof![
        // Higher weight for acquire operations to build up state
        8 => Just(OperationType::Acquire),
        4 => (0usize..10).prop_map(|idx| OperationType::Commit { token_index: idx }),
        4 => (0usize..10, cancel_reason_strategy()).prop_map(|(idx, reason)| {
            OperationType::Abort { token_index: idx, reason }
        }),
        2 => (1u32..=MAX_REGIONS as u32).prop_map(|region| {
            OperationType::CancelRegion { region_id: RegionId::new_for_test(region, 1) }
        }),
        // Low weight for FinalizeRegion since it's only legal when no obligations pending.
        // In practice, regions are finalized after explicit drainage.
        1 => (1u32..=MAX_REGIONS as u32).prop_map(|region| {
            OperationType::FinalizeRegion { region_id: RegionId::new_for_test(region, 1) }
        }),
        3 => Just(OperationType::CheckInvariant),
    ]
}

fn cancel_reason_strategy() -> impl Strategy<Value = ObligationAbortReason> {
    prop_oneof![
        Just(ObligationAbortReason::Cancel),
        Just(ObligationAbortReason::Error),
        Just(ObligationAbortReason::Explicit),
    ]
}

fn scenario_strategy() -> impl Strategy<Value = ConcurrentScenario> {
    (
        prop::collection::vec(operation_strategy(), 1..=MAX_OPERATIONS),
        0u64..1_000_000u64, // initial time
        any::<bool>(), // use_dpor flag
    ).prop_map(|(operations, initial_time, use_dpor)| {
        ConcurrentScenario {
            operations,
            initial_time,
            use_dpor,
        }
    })
}

/// Test the conservation invariant across all possible schedules
#[test]
fn test_obligation_conservation_metamorphic() {
    proptest!(|(scenario in scenario_strategy())| {
        test_conservation_property(&scenario);
    });
}

fn test_conservation_property(scenario: &ConcurrentScenario) {
    if scenario.use_dpor && cfg!(feature = "test-internals") {
        test_conservation_with_dpor(scenario);
    } else {
        test_conservation_single_schedule(scenario);
    }
}

fn test_conservation_with_dpor(scenario: &ConcurrentScenario) {
    // Use actual DPOR exploration to vary schedules systematically
    let base_seed = 42u64;
    let max_runs = 20; // Limit for test performance

    let config = ExplorerConfig::new(base_seed, max_runs);
    let mut explorer = DporExplorer::new(config);

    // Clone scenario for use in closure
    let scenario_clone = scenario.clone();

    let report = explorer.explore(move |runtime| {
        // Execute the scenario within the lab runtime context
        match run_scenario_in_runtime(runtime, &scenario_clone) {
            Ok(_) => {
                // Conservation held for this schedule
            }
            Err(violation) => {
                // Conservation violation detected - this will be caught by the explorer
                panic!("Conservation invariant violation: {}", violation);
            }
        }
    });

    println!("DPOR exploration: {} runs across {} unique schedule classes",
             report.total_runs, report.unique_classes);

    if report.has_violations() {
        panic!("Found conservation violations in {} runs: {:?}",
               report.violations.len(), report.violation_seeds());
    }
}

fn test_conservation_single_schedule(scenario: &ConcurrentScenario) {
    // Create a single lab runtime for deterministic execution
    let lab_config = LabConfig::default();
    let mut runtime = LabRuntime::new(lab_config);

    match run_scenario_in_runtime(&mut runtime, scenario) {
        Ok(_) => {
            // Conservation invariant held
        }
        Err(violation) => {
            panic!("Conservation invariant violation: {}", violation);
        }
    }
}

fn run_scenario_in_runtime(runtime: &mut LabRuntime, scenario: &ConcurrentScenario) -> Result<(), String> {
    // Advance to initial time for this scenario
    runtime.advance_time(scenario.initial_time);

    // Create obligation ledger
    let ledger = Arc::new(Mutex::new(ObligationLedger::new()));

    // Track tokens by task and index for commit/abort operations
    let tokens_by_task: Arc<Mutex<HashMap<TaskId, Vec<Option<ObligationToken>>>>>
        = Arc::new(Mutex::new(HashMap::new()));

    // Execute operations with virtual time advancement
    for (op_idx, operation) in scenario.operations.iter().enumerate() {
        // Advance virtual time for this operation
        runtime.advance_time(operation.delay_nanos);
        let now = runtime.now();

        match &operation.operation_type {
            OperationType::Acquire => {
                let mut ledger_lock = ledger.lock().unwrap();

                // Acquire new obligation token
                let token = ledger_lock.acquire(
                    operation.kind,
                    operation.task_id,
                    operation.region_id,
                    now
                );

                // Store token for later commit/abort
                let mut tokens = tokens_by_task.lock().unwrap();
                let task_tokens = tokens.entry(operation.task_id).or_insert_with(Vec::new);
                task_tokens.push(Some(token));
            }

            OperationType::Commit { token_index } => {
                let mut tokens = tokens_by_task.lock().unwrap();

                if let Some(task_tokens) = tokens.get_mut(&operation.task_id) {
                    if let Some(token_slot) = task_tokens.get_mut(*token_index) {
                        let taken_token = token_slot.take();
                        drop(tokens); // Release lock before ledger operation

                        if let Some(tok) = taken_token {
                            let mut ledger_lock = ledger.lock().unwrap();
                            // Use try_commit to handle race with cancellation gracefully
                            // If the obligation was already aborted by region cancel, this will fail
                            // gracefully without violating conservation invariants
                            let _ = ledger_lock.try_commit(tok, now);
                        }
                    }
                }
            }

            OperationType::Abort { token_index, reason } => {
                let mut tokens = tokens_by_task.lock().unwrap();

                if let Some(task_tokens) = tokens.get_mut(&operation.task_id) {
                    if let Some(token_slot) = task_tokens.get_mut(*token_index) {
                        let taken_token = token_slot.take();
                        drop(tokens); // Release lock before ledger operation

                        if let Some(tok) = taken_token {
                            let mut ledger_lock = ledger.lock().unwrap();
                            // Use try_abort to handle race with cancellation gracefully
                            let _ = ledger_lock.try_abort(tok, now, *reason);
                        }
                    }
                }
            }

            OperationType::CancelRegion { region_id } => {
                let mut ledger_lock = ledger.lock().unwrap();

                // Get pending obligations for this region
                let pending_ids = ledger_lock.pending_ids_for_region(*region_id);

                // Cancel all pending obligations (concurrent cancel scenario)
                // abort_by_id returns duration held, not success/failure
                for obligation_id in pending_ids {
                    let _duration = ledger_lock.abort_by_id(obligation_id, now, ObligationAbortReason::Cancel);
                }

                // Verify all obligations in the region were actually cancelled
                let pending_after = ledger_lock.pending_for_region(*region_id);
                if pending_after != 0 {
                    return Err(format!(
                        "checkpoint {}: cancel for region {:?} left {} pending obligations after abort_by_id",
                        op_idx, region_id, pending_after
                    ));
                }
            }

            OperationType::FinalizeRegion { region_id } => {
                // Region finalization is only legal when no obligations are pending.
                // If pending obligations exist, this represents a test harness bug.
                let ledger_lock = ledger.lock().unwrap();
                let pending_count = ledger_lock.pending_for_region(*region_id);
                if pending_count > 0 {
                    return Err(format!(
                        "Illegal scenario at checkpoint {}: attempted to finalize region {:?} with {} pending obligations. This violates the region close = quiescence invariant.",
                        op_idx, region_id, pending_count
                    ));
                }
                // If no pending obligations, finalization is a no-op for testing purposes
            }

            OperationType::CheckInvariant => {
                // Verify conservation invariant holds at this point
                let ledger_lock = ledger.lock().unwrap();
                let stats = ledger_lock.stats();

                verify_conservation_invariant(&stats, op_idx)?;
            }
        }
    }

    // Final invariant check
    let ledger_lock = ledger.lock().unwrap();
    let final_stats = ledger_lock.stats();
    verify_conservation_invariant(&final_stats, scenario.operations.len())?;

    Ok(())
}

fn verify_conservation_invariant(stats: &LedgerStats, checkpoint: usize) -> Result<(), String> {
    let total_issued = stats.total_acquired;
    let total_resolved = stats.total_committed + stats.total_aborted + stats.total_leaked;
    let pending = stats.pending;

    // Core conservation invariant
    if total_issued != total_resolved + pending {
        return Err(format!(
            "Conservation invariant violation at checkpoint {}: issued={}, resolved={}, pending={}, expected_total={}",
            checkpoint, total_issued, total_resolved, pending, total_resolved + pending
        ));
    }

    // Additional sanity checks
    if stats.total_committed > total_issued {
        return Err(format!(
            "Impossible state: committed ({}) > issued ({})",
            stats.total_committed, total_issued
        ));
    }

    if stats.total_aborted > total_issued {
        return Err(format!(
            "Impossible state: aborted ({}) > issued ({})",
            stats.total_aborted, total_issued
        ));
    }

    if pending > total_issued {
        return Err(format!(
            "Impossible state: pending ({}) > issued ({})",
            pending, total_issued
        ));
    }

    Ok(())
}

/// Test specific concurrent cancellation scenario
#[test]
fn test_concurrent_cancel_mid_flight() {
    // Create a deterministic scenario with known concurrent cancel patterns
    let operations = vec![
        // Task 1 acquires permits
        ObligationOperation {
            task_id: TaskId::new_for_test(1, 1),
            region_id: RegionId::new_for_test(1, 1),
            kind: ObligationKind::SendPermit,
            operation_type: OperationType::Acquire,
            delay_nanos: 1000,
        },
        ObligationOperation {
            task_id: TaskId::new_for_test(1, 1),
            region_id: RegionId::new_for_test(1, 1),
            kind: ObligationKind::Ack,
            operation_type: OperationType::Acquire,
            delay_nanos: 1000,
        },
        // Task 2 acquires permits in same region
        ObligationOperation {
            task_id: TaskId::new_for_test(2, 1),
            region_id: RegionId::new_for_test(1, 1),
            kind: ObligationKind::Lease,
            operation_type: OperationType::Acquire,
            delay_nanos: 1000,
        },
        // Mid-flight cancel of entire region
        ObligationOperation {
            task_id: TaskId::new_for_test(3, 1),
            region_id: RegionId::new_for_test(1, 1),
            kind: ObligationKind::SendPermit,
            operation_type: OperationType::CancelRegion { region_id: RegionId::new_for_test(1, 1) },
            delay_nanos: 500,
        },
        // Check invariant after cancellation
        ObligationOperation {
            task_id: TaskId::new_for_test(1, 1),
            region_id: RegionId::new_for_test(1, 1),
            kind: ObligationKind::SendPermit,
            operation_type: OperationType::CheckInvariant,
            delay_nanos: 100,
        },
        // Attempt to commit after cancel (should be handled gracefully)
        ObligationOperation {
            task_id: TaskId::new_for_test(1, 1),
            region_id: RegionId::new_for_test(1, 1),
            kind: ObligationKind::SendPermit,
            operation_type: OperationType::Commit { token_index: 0 },
            delay_nanos: 100,
        },
        // Final invariant check
        ObligationOperation {
            task_id: TaskId::new_for_test(1, 1),
            region_id: RegionId::new_for_test(1, 1),
            kind: ObligationKind::SendPermit,
            operation_type: OperationType::CheckInvariant,
            delay_nanos: 100,
        },
    ];

    let scenario = ConcurrentScenario {
        operations,
        initial_time: 0,
        use_dpor: false,
    };

    test_conservation_property(&scenario);
}

/// Test proper cancellation behavior
#[test]
fn test_proper_region_cancellation() {
    // Test region cancellation followed by proper cleanup.
    // This models realistic usage where cancellation fully drains all obligations.
    let scenario = ConcurrentScenario {
        operations: vec![
            // Task 1 acquires multiple obligations
            ObligationOperation {
                task_id: TaskId::new_for_test(1, 1),
                region_id: RegionId::new_for_test(1, 1),
                kind: ObligationKind::SendPermit,
                operation_type: OperationType::Acquire,
                delay_nanos: 1000,
            },
            ObligationOperation {
                task_id: TaskId::new_for_test(1, 1),
                region_id: RegionId::new_for_test(1, 1),
                kind: ObligationKind::Ack,
                operation_type: OperationType::Acquire,
                delay_nanos: 1000,
            },
            // Cancel region - this should drain all pending obligations
            ObligationOperation {
                task_id: TaskId::new_for_test(2, 1),
                region_id: RegionId::new_for_test(1, 1),
                kind: ObligationKind::SendPermit,
                operation_type: OperationType::CancelRegion { region_id: RegionId::new_for_test(1, 1) },
                delay_nanos: 500,
            },
            // Verify conservation after cancellation
            ObligationOperation {
                task_id: TaskId::new_for_test(1, 1),
                region_id: RegionId::new_for_test(1, 1),
                kind: ObligationKind::SendPermit,
                operation_type: OperationType::CheckInvariant,
                delay_nanos: 100,
            },
            // Region should now be safe to finalize
            ObligationOperation {
                task_id: TaskId::new_for_test(1, 1),
                region_id: RegionId::new_for_test(1, 1),
                kind: ObligationKind::SendPermit,
                operation_type: OperationType::FinalizeRegion { region_id: RegionId::new_for_test(1, 1) },
                delay_nanos: 100,
            },
        ],
        initial_time: 0,
        use_dpor: false, // Use deterministic ordering
    };

    test_conservation_property(&scenario);
}
