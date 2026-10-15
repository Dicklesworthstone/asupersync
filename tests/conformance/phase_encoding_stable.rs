#![allow(
    clippy::pedantic,
    clippy::nursery,
    clippy::expect_fun_call,
    clippy::map_unwrap_or,
    clippy::cast_possible_wrap
)]

use asupersync::record::region::RegionState;
use asupersync::record::task::TaskPhase;

#[test]
fn region_state_wire_encoding_stable() {
    // These mappings MUST NOT CHANGE.
    // They are stored stably in tracing ledgers and artifacts.
    let expected_mappings = vec![
        (RegionState::Open, 0),
        (RegionState::Closing, 1),
        (RegionState::Draining, 2),
        (RegionState::Finalizing, 3),
        (RegionState::Closed, 4),
    ];

    for (state, expected_val) in expected_mappings {
        let val = state.as_u8();
        assert_eq!(
            val, expected_val,
            "RegionState::{state:?} must encode to {expected_val}"
        );
        let decoded = RegionState::from_u8(val).expect("should decode successfully");
        assert_eq!(
            decoded, state,
            "RegionState from_u8({val}) must decode back to {state:?}"
        );
    }

    assert!(
        RegionState::from_u8(5).is_none(),
        "invalid region state u8 should not decode"
    );
}

#[test]
fn task_phase_wire_encoding_stable() {
    // These mappings MUST NOT CHANGE.
    // They are stored stably in tracing ledgers and artifacts.
    let expected_mappings = vec![
        (TaskPhase::Created, 0),
        (TaskPhase::Running, 1),
        (TaskPhase::CancelRequested, 2),
        (TaskPhase::Cancelling, 3),
        (TaskPhase::Finalizing, 4),
        (TaskPhase::Completed, 5),
    ];

    for (phase, expected_val) in expected_mappings {
        let val = phase.as_u8();
        assert_eq!(
            val, expected_val,
            "TaskPhase::{phase:?} must encode to {expected_val}"
        );
        let decoded = TaskPhase::from_u8(val).expect("should decode successfully");
        assert_eq!(
            decoded, phase,
            "TaskPhase from_u8({val}) must decode back to {phase:?}"
        );
    }

    assert!(
        TaskPhase::from_u8(6).is_none(),
        "invalid task phase u8 should not decode"
    );
}
