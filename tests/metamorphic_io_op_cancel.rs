#![allow(warnings)]
#![allow(clippy::all)]
//! Metamorphic Testing: runtime::io_op cancel-safety invariants
//!
//! Tests the fundamental metamorphic properties of IoOp lifecycle management
//! and cancel-safety guarantees. These properties must hold regardless of
//! specific input values and operation sequences.
//!
//! Key metamorphic relations tested:
//! 1. Temporal monotonicity (submit time ≤ resolution time, accurate duration)
//! 2. State transition consistency (all resolution paths lead to resolved state)
//! 3. Resource counting invariant (pending obligations tracked correctly)
//! 4. Trace event ordering (reserve precedes resolution events)
//! 5. Abort reason preservation (abort reasons preserved in trace events)
//! 6. Cross-method equivalence (cancel ≡ abort(Cancel))
//! 7. into_raw escape hatch (disarms drop guard, preserves obligation)

use asupersync::record::ObligationAbortReason;
use asupersync::runtime::io_op::IoOp;
use asupersync::runtime::state::RuntimeState;
use asupersync::trace::event::{TraceData, TraceEventKind};
use asupersync::types::{Budget, ObligationId, RegionId, TaskId, Time};
use proptest::prelude::*;

/// Generate arbitrary time values for testing
fn arb_time() -> impl Strategy<Value = u64> {
    0u64..=1_000_000u64 // 0 to 1M nanoseconds
}

/// Generate arbitrary time intervals (submit_time, resolution_time)
fn arb_time_interval() -> impl Strategy<Value = (u64, u64)> {
    (arb_time(), arb_time()).prop_map(|(t1, t2)| {
        if t1 <= t2 {
            (t1, t2)
        } else {
            (t2, t1) // Ensure submit_time <= resolution_time
        }
    })
}

/// Generate arbitrary abort reasons for testing
fn arb_abort_reason() -> impl Strategy<Value = ObligationAbortReason> {
    prop_oneof![
        Just(ObligationAbortReason::Cancel),
        Just(ObligationAbortReason::Explicit),
        Just(ObligationAbortReason::Error),
    ]
}

/// Generate arbitrary optional descriptions
fn arb_description() -> impl Strategy<Value = Option<String>> {
    prop_oneof![
        Just(None),
        Just(Some("test io op".to_string())),
        Just(Some("metamorphic test".to_string())),
        Just(Some("cancel safety test".to_string())),
        Just(Some(String::new())),
    ]
}

/// Test operation types for IoOp resolution
#[derive(Debug, Clone, Copy)]
enum ResolutionOperation {
    Complete,
    Cancel,
    Abort(ObligationAbortReason),
    IntoRaw,
}

impl Arbitrary for ResolutionOperation {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        prop_oneof![
            Just(ResolutionOperation::Complete),
            Just(ResolutionOperation::Cancel),
            arb_abort_reason().prop_map(ResolutionOperation::Abort),
            Just(ResolutionOperation::IntoRaw),
        ]
        .boxed()
    }
}

/// Helper to create a test task in a region
fn create_test_task(state: &mut RuntimeState, region: RegionId) -> TaskId {
    let (task_id, _handle) = state
        .create_task(region, Budget::INFINITE, async {})
        .expect("task creation should succeed");
    task_id
}

/// Helper to find obligation trace events
fn find_obligation_events(
    state: &RuntimeState,
    obligation: ObligationId,
) -> (
    Option<TraceEventKind>,
    Option<TraceEventKind>,
    Option<u64>,
    Option<ObligationAbortReason>,
) {
    let events = state.trace.snapshot();
    let mut reserve_event = None;
    let mut resolution_event = None;
    let mut duration = None;
    let mut abort_reason = None;

    for event in events {
        if let TraceData::Obligation {
            obligation: event_obligation,
            duration_ns,
            abort_reason: event_abort_reason,
            ..
        } = &event.data
        {
            if *event_obligation == obligation {
                match event.kind {
                    TraceEventKind::ObligationReserve => {
                        reserve_event = Some(event.kind);
                    }
                    TraceEventKind::ObligationCommit | TraceEventKind::ObligationAbort => {
                        resolution_event = Some(event.kind);
                        duration = *duration_ns;
                        abort_reason = *event_abort_reason;
                    }
                    _ => {}
                }
            }
        }
    }

    (reserve_event, resolution_event, duration, abort_reason)
}

/// Metamorphic Relation 1: Temporal Monotonicity
///
/// For any IoOp lifecycle, submit_time ≤ resolution_time, and
/// duration = resolution_time - submit_time (when resolved).
#[test]
fn mr_temporal_monotonicity() {
    fn property(time_interval: (u64, u64), operation: ResolutionOperation) -> bool {
        let (submit_time, resolution_time) = time_interval;

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let task_id = create_test_task(&mut state, root);

        state.now = Time::from_nanos(submit_time);
        let mut op = IoOp::submit(&mut state, task_id, root, Some("temporal test".into()))
            .expect("submit should succeed");
        let obligation_id = op.id();

        state.now = Time::from_nanos(resolution_time);

        let expected_duration = resolution_time - submit_time;

        match operation {
            ResolutionOperation::Complete => {
                let duration = op.complete(&mut state).expect("complete should succeed");
                assert_eq!(
                    duration, expected_duration,
                    "Duration mismatch for complete operation"
                );
            }
            ResolutionOperation::Cancel => {
                let duration = op.cancel(&mut state).expect("cancel should succeed");
                assert_eq!(
                    duration, expected_duration,
                    "Duration mismatch for cancel operation"
                );
            }
            ResolutionOperation::Abort(reason) => {
                let duration = op.abort(&mut state, reason).expect("abort should succeed");
                assert_eq!(
                    duration, expected_duration,
                    "Duration mismatch for abort operation"
                );
            }
            ResolutionOperation::IntoRaw => {
                let raw_id = op.into_raw();
                assert_eq!(
                    raw_id, obligation_id,
                    "into_raw should return correct obligation id"
                );
                // Complete the obligation externally to verify duration tracking
                let duration = state
                    .abort_obligation(raw_id, ObligationAbortReason::Cancel)
                    .expect("external abort should succeed");
                assert_eq!(
                    duration, expected_duration,
                    "Duration mismatch for external resolution"
                );
            }
        }

        // Verify temporal monotonicity holds
        assert!(
            submit_time <= resolution_time,
            "Submit time must precede or equal resolution time"
        );

        true
    }

    proptest!(|(
        time_interval in arb_time_interval(),
        operation in any::<ResolutionOperation>(),
    )| {
        prop_assert!(property(time_interval, operation));
    });
}

/// Metamorphic Relation 2: State Transition Consistency
///
/// All resolution operations (complete, cancel, abort) must result in
/// the IoOp handle being marked as resolved.
#[test]
fn mr_state_transition_consistency() {
    fn property(operation: ResolutionOperation, description: Option<String>) -> bool {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let task_id = create_test_task(&mut state, root);

        state.now = Time::from_nanos(100);
        let mut op =
            IoOp::submit(&mut state, task_id, root, description).expect("submit should succeed");

        // Initially not resolved
        assert!(
            !op.is_resolved(),
            "IoOp should not be resolved after submit"
        );

        state.now = Time::from_nanos(200);

        let is_into_raw = matches!(operation, ResolutionOperation::IntoRaw);

        match operation {
            ResolutionOperation::Complete => {
                op.complete(&mut state).expect("complete should succeed");
                assert!(op.is_resolved(), "IoOp should be resolved after complete");
            }
            ResolutionOperation::Cancel => {
                op.cancel(&mut state).expect("cancel should succeed");
                assert!(op.is_resolved(), "IoOp should be resolved after cancel");
            }
            ResolutionOperation::Abort(reason) => {
                op.abort(&mut state, reason).expect("abort should succeed");
                assert!(op.is_resolved(), "IoOp should be resolved after abort");
            }
            ResolutionOperation::IntoRaw => {
                let _raw_id = op.into_raw();
                // Note: op is consumed by into_raw(), so we can't check is_resolved() or use op again
                // The important invariant is that into_raw() disarms the drop guard
                return true; // Exit early since op is consumed
            }
        }

        // Attempting to resolve again should fail (only for non-into_raw cases)
        if !is_into_raw {
            let second_result = op.complete(&mut state);
            assert!(second_result.is_err(), "Second resolution should fail");

            if let Err(err) = second_result {
                use asupersync::error::ErrorKind;
                assert_eq!(
                    err.kind(),
                    ErrorKind::ObligationAlreadyResolved,
                    "Second resolution should fail with ObligationAlreadyResolved"
                );
            }
        }

        true
    }

    proptest!(|(
        operation in any::<ResolutionOperation>(),
        description in arb_description(),
    )| {
        prop_assert!(property(operation, description));
    });
}

/// Metamorphic Relation 3: Resource Counting Invariant
///
/// pending_obligation_count increases by 1 on submit and decreases by 1
/// on resolution (except for into_raw, which preserves the pending count).
#[test]
fn mr_resource_counting_invariant() {
    fn property(resolution_operations: Vec<ResolutionOperation>) -> bool {
        if resolution_operations.is_empty() || resolution_operations.len() > 10 {
            return true; // Skip invalid cases
        }

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let task_id = create_test_task(&mut state, root);

        let initial_count = state.pending_obligation_count();
        let mut raw_obligations = Vec::new();

        // Process each operation individually to avoid ownership issues
        let mut current_pending = initial_count;

        for (i, operation) in resolution_operations.into_iter().enumerate() {
            // Submit phase
            state.now = Time::from_nanos((i * 100) as u64);
            let mut op = IoOp::submit(&mut state, task_id, root, Some(format!("op_{i}")))
                .expect("submit should succeed");
            current_pending += 1;

            // Count should increase by 1 after submit
            assert_eq!(
                state.pending_obligation_count(),
                current_pending,
                "Pending count should increase by 1 after submit {}",
                i
            );

            // Resolution phase
            state.now = Time::from_nanos((100 + i * 100) as u64);

            match operation {
                ResolutionOperation::Complete => {
                    op.complete(&mut state).expect("complete should succeed");
                    current_pending -= 1;
                }
                ResolutionOperation::Cancel => {
                    op.cancel(&mut state).expect("cancel should succeed");
                    current_pending -= 1;
                }
                ResolutionOperation::Abort(reason) => {
                    op.abort(&mut state, reason).expect("abort should succeed");
                    current_pending -= 1;
                }
                ResolutionOperation::IntoRaw => {
                    let raw_id = op.into_raw();
                    raw_obligations.push(raw_id);
                    // into_raw should NOT decrease the pending count yet
                    // current_pending stays the same
                }
            }

            // Verify the count after resolution
            assert_eq!(
                state.pending_obligation_count(),
                current_pending,
                "Pending count should match expected after resolution {}",
                i
            );
        }

        // Clean up raw obligations
        for raw_id in raw_obligations {
            state
                .abort_obligation(raw_id, ObligationAbortReason::Cancel)
                .expect("cleanup should succeed");
        }

        // Final count should return to initial
        assert_eq!(
            state.pending_obligation_count(),
            initial_count,
            "Final count should match initial count"
        );

        true
    }

    proptest!(|(
        resolution_operations in prop::collection::vec(any::<ResolutionOperation>(), 1..=5),
    )| {
        prop_assert!(property(resolution_operations));
    });
}

/// Metamorphic Relation 4: Trace Event Ordering
///
/// For any IoOp lifecycle, the ObligationReserve event must precede
/// the ObligationCommit/ObligationAbort event.
#[test]
fn mr_trace_event_ordering() {
    fn property(time_interval: (u64, u64), operation: ResolutionOperation) -> bool {
        let (submit_time, resolution_time) = time_interval;

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let task_id = create_test_task(&mut state, root);

        state.now = Time::from_nanos(submit_time);
        let mut op = IoOp::submit(
            &mut state,
            task_id,
            root,
            Some("trace ordering test".into()),
        )
        .expect("submit should succeed");
        let obligation_id = op.id();

        state.now = Time::from_nanos(resolution_time);

        match operation {
            ResolutionOperation::Complete => {
                op.complete(&mut state).expect("complete should succeed");
            }
            ResolutionOperation::Cancel => {
                op.cancel(&mut state).expect("cancel should succeed");
            }
            ResolutionOperation::Abort(reason) => {
                op.abort(&mut state, reason).expect("abort should succeed");
            }
            ResolutionOperation::IntoRaw => {
                let raw_id = op.into_raw();
                state
                    .abort_obligation(raw_id, ObligationAbortReason::Cancel)
                    .expect("external abort should succeed");
            }
        }

        let (reserve_event, resolution_event, duration, _abort_reason) =
            find_obligation_events(&state, obligation_id);

        // Both events should exist
        assert!(reserve_event.is_some(), "Reserve event should exist");
        assert!(resolution_event.is_some(), "Resolution event should exist");

        // Duration should match expected value
        if let Some(dur) = duration {
            let expected_duration = resolution_time - submit_time;
            assert_eq!(
                dur, expected_duration,
                "Duration should match time difference"
            );
        }

        // Verify event ordering by checking the trace timeline
        let events = state.trace.snapshot();
        let mut reserve_timestamp = None;
        let mut resolution_timestamp = None;

        for event in events {
            if let TraceData::Obligation {
                obligation: event_obligation,
                ..
            } = &event.data
            {
                if *event_obligation == obligation_id {
                    match event.kind {
                        TraceEventKind::ObligationReserve => {
                            reserve_timestamp = Some(event.time);
                        }
                        TraceEventKind::ObligationCommit | TraceEventKind::ObligationAbort => {
                            resolution_timestamp = Some(event.time);
                        }
                        _ => {}
                    }
                }
            }
        }

        if let (Some(reserve_time), Some(resolution_time)) =
            (reserve_timestamp, resolution_timestamp)
        {
            assert!(
                reserve_time <= resolution_time,
                "Reserve event should precede or occur at same time as resolution event"
            );
        }

        true
    }

    proptest!(|(
        time_interval in arb_time_interval(),
        operation in any::<ResolutionOperation>(),
    )| {
        prop_assert!(property(time_interval, operation));
    });
}

/// Metamorphic Relation 5: Abort Reason Preservation
///
/// When aborting with a specific reason, that exact reason must be
/// preserved in the trace events.
#[test]
fn mr_abort_reason_preservation() {
    fn property(abort_reason: ObligationAbortReason, description: Option<String>) -> bool {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let task_id = create_test_task(&mut state, root);

        state.now = Time::from_nanos(50);
        let mut op =
            IoOp::submit(&mut state, task_id, root, description).expect("submit should succeed");
        let obligation_id = op.id();

        state.now = Time::from_nanos(150);
        op.abort(&mut state, abort_reason)
            .expect("abort should succeed");

        let (_reserve_event, resolution_event, _duration, trace_abort_reason) =
            find_obligation_events(&state, obligation_id);

        // Should have an abort event
        assert_eq!(
            resolution_event,
            Some(TraceEventKind::ObligationAbort),
            "Should have abort event"
        );

        // Abort reason should be preserved exactly
        assert_eq!(
            trace_abort_reason,
            Some(abort_reason),
            "Abort reason should be preserved in trace event"
        );

        true
    }

    proptest!(|(
        abort_reason in arb_abort_reason(),
        description in arb_description(),
    )| {
        prop_assert!(property(abort_reason, description));
    });
}

/// Metamorphic Relation 6: Cross-Method Equivalence
///
/// op.cancel() should be equivalent to op.abort(Cancel) in terms of
/// final state and trace events.
#[test]
fn mr_cross_method_equivalence() {
    fn property(time_interval: (u64, u64), use_cancel_method: bool) -> bool {
        let (submit_time, resolution_time) = time_interval;

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let task_id = create_test_task(&mut state, root);

        state.now = Time::from_nanos(submit_time);
        let mut op = IoOp::submit(&mut state, task_id, root, Some("equivalence test".into()))
            .expect("submit should succeed");
        let obligation_id = op.id();

        state.now = Time::from_nanos(resolution_time);

        let duration = if use_cancel_method {
            op.cancel(&mut state).expect("cancel should succeed")
        } else {
            op.abort(&mut state, ObligationAbortReason::Cancel)
                .expect("abort should succeed")
        };

        // Both methods should produce the same duration
        let expected_duration = resolution_time - submit_time;
        assert_eq!(duration, expected_duration, "Duration should be consistent");

        // Both methods should result in resolved state
        assert!(op.is_resolved(), "IoOp should be resolved");

        // Both methods should produce equivalent trace events
        let (_reserve_event, resolution_event, trace_duration, abort_reason) =
            find_obligation_events(&state, obligation_id);

        assert_eq!(
            resolution_event,
            Some(TraceEventKind::ObligationAbort),
            "Should have abort event"
        );
        assert_eq!(
            trace_duration,
            Some(expected_duration),
            "Trace duration should match"
        );
        assert_eq!(
            abort_reason,
            Some(ObligationAbortReason::Cancel),
            "Abort reason should be Cancel"
        );

        true
    }

    proptest!(|(
        time_interval in arb_time_interval(),
        use_cancel_method in any::<bool>(),
    )| {
        prop_assert!(property(time_interval, use_cancel_method));
    });
}

/// Metamorphic Relation 7: into_raw Escape Hatch
///
/// into_raw() should disarm the drop guard (making the handle resolved)
/// but preserve the obligation in the pending state for external resolution.
#[test]
fn mr_into_raw_escape_hatch() {
    fn property(time_interval: (u64, u64), external_resolution: ResolutionOperation) -> bool {
        let (submit_time, external_resolution_time) = time_interval;

        // Skip into_raw for external resolution (would be recursive)
        if matches!(external_resolution, ResolutionOperation::IntoRaw) {
            return true;
        }

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let task_id = create_test_task(&mut state, root);

        state.now = Time::from_nanos(submit_time);
        let initial_count = state.pending_obligation_count();

        let op = IoOp::submit(&mut state, task_id, root, Some("into_raw test".into()))
            .expect("submit should succeed");
        let obligation_id = op.id();

        // Pending count should increase
        assert_eq!(
            state.pending_obligation_count(),
            initial_count + 1,
            "Pending count should increase after submit"
        );

        // Call into_raw
        let raw_id = op.into_raw();

        // Note: op is consumed by into_raw(), so we can't check is_resolved() afterwards
        // The important invariant is that into_raw disarms the drop guard
        assert_eq!(
            raw_id, obligation_id,
            "into_raw should return correct obligation id"
        );

        // Obligation should still be pending
        assert_eq!(
            state.pending_obligation_count(),
            initial_count + 1,
            "Pending count should remain after into_raw"
        );

        // External resolution should work
        state.now = Time::from_nanos(external_resolution_time);
        let expected_duration = external_resolution_time - submit_time;

        let duration = match external_resolution {
            ResolutionOperation::Complete => state
                .commit_obligation(raw_id)
                .expect("external complete should succeed"),
            ResolutionOperation::Cancel => state
                .abort_obligation(raw_id, ObligationAbortReason::Cancel)
                .expect("external cancel should succeed"),
            ResolutionOperation::Abort(reason) => state
                .abort_obligation(raw_id, reason)
                .expect("external abort should succeed"),
            ResolutionOperation::IntoRaw => unreachable!("filtered out above"),
        };

        assert_eq!(
            duration, expected_duration,
            "External resolution duration should be correct"
        );
        assert_eq!(
            state.pending_obligation_count(),
            initial_count,
            "Pending count should return to initial after external resolution"
        );

        true
    }

    proptest!(|(
        time_interval in arb_time_interval(),
        external_resolution in any::<ResolutionOperation>(),
    )| {
        prop_assert!(property(time_interval, external_resolution));
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_io_op_lifecycle() {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let task_id = create_test_task(&mut state, root);

        // Test basic submit-complete cycle
        state.now = Time::from_nanos(100);
        let mut op = IoOp::submit(&mut state, task_id, root, Some("basic test".into()))
            .expect("submit should succeed");
        assert!(!op.is_resolved());

        state.now = Time::from_nanos(200);
        let duration = op.complete(&mut state).expect("complete should succeed");
        assert_eq!(duration, 100);
        assert!(op.is_resolved());
    }

    #[test]
    fn test_obligation_id_consistency() {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let task_id = create_test_task(&mut state, root);

        let op = IoOp::submit(&mut state, task_id, root, None).expect("submit should succeed");
        let id1 = op.id();
        let id2 = op.id();
        assert_eq!(id1, id2, "id() should be consistent");

        let raw_id = op.into_raw();
        assert_eq!(id1, raw_id, "into_raw should return same id");
    }

    #[test]
    fn test_trace_event_structure() {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let task_id = create_test_task(&mut state, root);

        state.now = Time::from_nanos(10);
        let mut op = IoOp::submit(&mut state, task_id, root, Some("trace test".into()))
            .expect("submit should succeed");
        let obligation_id = op.id();

        state.now = Time::from_nanos(40);
        op.cancel(&mut state).expect("cancel should succeed");

        let events = state.trace.snapshot();
        let obligation_events: Vec<_> = events
            .into_iter()
            .filter(|e| {
                if let TraceData::Obligation { obligation, .. } = &e.data {
                    *obligation == obligation_id
                } else {
                    false
                }
            })
            .collect();

        assert_eq!(
            obligation_events.len(),
            2,
            "Should have reserve and abort events"
        );

        // First should be reserve
        assert_eq!(obligation_events[0].kind, TraceEventKind::ObligationReserve);
        // Second should be abort
        assert_eq!(obligation_events[1].kind, TraceEventKind::ObligationAbort);
    }
}
