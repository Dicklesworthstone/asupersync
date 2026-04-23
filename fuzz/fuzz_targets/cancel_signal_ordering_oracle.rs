#![no_main]

use arbitrary::Arbitrary;
use asupersync::lab::oracle::cancel_signal_ordering::{CancelOrderingConfig, CancelOrderingOracle};
use asupersync::types::{CancelReason, RegionId, TaskId, Time};
use libfuzzer_sys::fuzz_target;

const MAX_OPERATIONS: usize = 96;
const MAX_TASK_COMPONENT: u32 = 63;
const MAX_REGION_COMPONENT: u32 = 63;

#[derive(Arbitrary, Debug, Clone)]
struct FuzzInput {
    config: FuzzConfig,
    operations: Vec<Operation>,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
struct FuzzConfig {
    max_ordering_window_ns: u32,
    max_violations: u16,
}

#[derive(Arbitrary, Debug, Clone)]
enum Operation {
    Spawn {
        parent_task: IdPair,
        child_task: IdPair,
        parent_region: IdPair,
        child_region: IdPair,
        same_region: bool,
    },
    Cancel {
        task: IdPair,
        region: IdPair,
        reason: ReasonKind,
        advance_ns: u32,
    },
    Check {
        advance_ns: u32,
    },
    Snapshot,
    Reset,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
struct IdPair {
    index: u8,
    generation: u8,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum ReasonKind {
    User,
    Timeout,
    ParentCancelled,
    Shutdown,
    RaceLost,
}

fn normalize_input(input: &mut FuzzInput) {
    input.operations.truncate(MAX_OPERATIONS);
    input.config.max_violations = input.config.max_violations.clamp(1, 64);
    input.config.max_ordering_window_ns =
        input.config.max_ordering_window_ns.clamp(1, 1_000_000_000);
}

fn map_task_id(raw: IdPair) -> TaskId {
    TaskId::new_for_test(
        u32::from(raw.index).min(MAX_TASK_COMPONENT),
        u32::from(raw.generation).min(MAX_TASK_COMPONENT),
    )
}

fn map_region_id(raw: IdPair) -> RegionId {
    RegionId::new_for_test(
        u32::from(raw.index).min(MAX_REGION_COMPONENT),
        u32::from(raw.generation).min(MAX_REGION_COMPONENT),
    )
}

fn map_reason(kind: ReasonKind) -> CancelReason {
    match kind {
        ReasonKind::User => CancelReason::user("fuzz-user"),
        ReasonKind::Timeout => CancelReason::timeout(),
        ReasonKind::ParentCancelled => CancelReason::parent_cancelled(),
        ReasonKind::Shutdown => CancelReason::shutdown(),
        ReasonKind::RaceLost => CancelReason::race_lost(),
    }
}

fn advance(now: &mut Time, nanos: u32) {
    *now = Time::from_nanos(now.as_nanos().saturating_add(u64::from(nanos)));
}

fn assert_consistency(oracle: &CancelOrderingOracle, max_violations: usize, expected_signals: u64) {
    let stats = oracle.get_statistics();
    let tracked = oracle.tracked_signals();
    let all_violations = oracle.get_recent_violations(usize::MAX);

    assert_eq!(stats.signals_processed, expected_signals);
    assert_eq!(stats.tracked_signals, tracked.len());
    assert_eq!(stats.total_violations, all_violations.len());
    assert!(stats.total_violations <= max_violations);
    assert!(oracle.get_recent_violations(3).len() <= 3);
    assert!(tracked
        .windows(2)
        .all(|pair| pair[0].task_id <= pair[1].task_id));
}

fn run_fuzz_case(mut input: FuzzInput) {
    normalize_input(&mut input);

    let config = CancelOrderingConfig {
        max_ordering_window_ns: u64::from(input.config.max_ordering_window_ns),
        max_violations: usize::from(input.config.max_violations),
        panic_on_violation: false,
        capture_stack_traces: false,
        max_stack_trace_depth: 0,
    };
    let oracle = CancelOrderingOracle::new(config);

    let mut now = Time::ZERO;
    let mut expected_signals = 0u64;

    for operation in input.operations {
        match operation {
            Operation::Spawn {
                parent_task,
                child_task,
                parent_region,
                child_region,
                same_region,
            } => {
                let parent_region = map_region_id(parent_region);
                let child_region = if same_region {
                    parent_region
                } else {
                    map_region_id(child_region)
                };
                oracle.on_task_spawned(
                    map_task_id(parent_task),
                    map_task_id(child_task),
                    parent_region,
                    child_region,
                );
            }
            Operation::Cancel {
                task,
                region,
                reason,
                advance_ns,
            } => {
                advance(&mut now, advance_ns);
                oracle.on_cancel_signal(
                    map_task_id(task),
                    map_region_id(region),
                    now,
                    map_reason(reason),
                );
                expected_signals = expected_signals.saturating_add(1);
            }
            Operation::Check { advance_ns } => {
                advance(&mut now, advance_ns);
                let _ = oracle.check(now);
            }
            Operation::Snapshot => {
                let _ = oracle.tracked_signals();
                let _ = oracle.get_recent_violations(8);
            }
            Operation::Reset => {
                oracle.reset();
                now = Time::ZERO;
                expected_signals = 0;
            }
        }

        assert_consistency(
            &oracle,
            usize::from(input.config.max_violations),
            expected_signals,
        );
    }

    let _ = oracle.check(now);
    assert_consistency(
        &oracle,
        usize::from(input.config.max_violations),
        expected_signals,
    );
}

fuzz_target!(|input: FuzzInput| {
    run_fuzz_case(input);
});
