#![allow(clippy::all)]
//! Metamorphic tests for compiled supervision restart planning.
//!
//! These tests exercise the pure planning APIs in `src/supervision.rs`:
//! `restart_plan_for_failure`, `child_start_order_names`, and
//! `child_stop_order_names`. They intentionally avoid pretending that the
//! multi-child live restart loop is already wired; the contract under test is
//! deterministic plan generation from compiled topology + outcome severity.

use asupersync::cx::{Cx, Scope};
use asupersync::runtime::{RuntimeState, SpawnError};
use asupersync::supervision::{
    ChildSpec, RestartConfig, RestartPolicy, SupervisionStrategy, SupervisorBuilder,
};
use asupersync::types::{Budget, CancelReason, Outcome, RegionId, TaskId, policy::FailFast};
use asupersync::util::ArenaIndex;
use proptest::prelude::*;
use std::time::Duration;

fn noop_start(
    _scope: &Scope<'static, FailFast>,
    _state: &mut RuntimeState,
    _cx: &Cx,
) -> Result<TaskId, SpawnError> {
    Ok(TaskId::from_arena(ArenaIndex::new(0, 0)))
}

fn restartable_child(name: String) -> ChildSpec {
    ChildSpec::new(name, noop_start)
        .with_restart(SupervisionStrategy::Restart(RestartConfig::new(
            3,
            Duration::from_secs(60),
        )))
        .with_shutdown_budget(Budget::INFINITE)
}

fn compile_restartable_supervisor(
    child_count: usize,
    policy: RestartPolicy,
) -> asupersync::supervision::CompiledSupervisor {
    let mut builder = SupervisorBuilder::new("metamorphic_supervisor").with_restart_policy(policy);
    for index in 0..child_count {
        builder = builder.child(restartable_child(format!("child_{index}")));
    }
    builder.compile().expect("compile restartable supervisor")
}

fn names(children: Vec<asupersync::supervision::ChildName>) -> Vec<String> {
    children.into_iter().map(|name| name.to_string()).collect()
}

fn err_outcome() -> Outcome<(), ()> {
    Outcome::Err(())
}

fn cancelled_outcome() -> Outcome<(), ()> {
    Outcome::Cancelled(CancelReason::user("metamorphic cancel"))
}

fn panicked_outcome() -> Outcome<(), ()> {
    Outcome::Panicked(asupersync::types::PanicPayload::new("metamorphic panic"))
}

fn build_expected_range(start: usize, end: usize) -> Vec<String> {
    (start..end).map(|index| format!("child_{index}")).collect()
}

proptest! {
    #[test]
    fn mr1_one_for_one_isolates_failed_child(child_count in 2usize..7, failed_idx in 0usize..16) {
        let failed_idx = failed_idx % child_count;
        let supervisor = compile_restartable_supervisor(child_count, RestartPolicy::OneForOne);
        let failed_child = format!("child_{failed_idx}");

        let plan = supervisor
            .restart_plan_for_failure(&failed_child, &err_outcome())
            .expect("Err outcome should restart the failed child");

        prop_assert_eq!(names(plan.cancel_order), vec![failed_child.clone()]);
        prop_assert_eq!(names(plan.restart_order), vec![failed_child]);
    }

    #[test]
    fn mr2_rest_for_one_restarts_suffix(child_count in 3usize..8, failed_idx in 0usize..16) {
        let failed_idx = failed_idx % child_count;
        let supervisor = compile_restartable_supervisor(child_count, RestartPolicy::RestForOne);
        let failed_child = format!("child_{failed_idx}");
        let expected = build_expected_range(failed_idx, child_count);
        let mut expected_cancel = expected.clone();
        expected_cancel.reverse();

        let plan = supervisor
            .restart_plan_for_failure(&failed_child, &err_outcome())
            .expect("Err outcome should restart the suffix");

        prop_assert_eq!(names(plan.cancel_order), expected_cancel);
        prop_assert_eq!(names(plan.restart_order), expected);
    }

    #[test]
    fn mr3_one_for_all_restarts_entire_topology(child_count in 2usize..7, failed_idx in 0usize..16) {
        let failed_idx = failed_idx % child_count;
        let supervisor = compile_restartable_supervisor(child_count, RestartPolicy::OneForAll);
        let failed_child = format!("child_{failed_idx}");
        let expected = build_expected_range(0, child_count);
        let mut expected_cancel = expected.clone();
        expected_cancel.reverse();

        let plan = supervisor
            .restart_plan_for_failure(&failed_child, &err_outcome())
            .expect("Err outcome should restart all children");

        prop_assert_eq!(names(plan.cancel_order), expected_cancel);
        prop_assert_eq!(names(plan.restart_order), expected);
    }

    #[test]
    fn mr4_monotone_severity_blocks_restart_for_stronger_failures(
        policy in prop_oneof![
            Just(RestartPolicy::OneForOne),
            Just(RestartPolicy::OneForAll),
            Just(RestartPolicy::RestForOne),
        ],
        child_count in 2usize..7,
        failed_idx in 0usize..16,
    ) {
        let failed_idx = failed_idx % child_count;
        let supervisor = compile_restartable_supervisor(child_count, policy);
        let failed_child = format!("child_{failed_idx}");

        let ok: Outcome<(), ()> = Outcome::Ok(());
        prop_assert!(supervisor.restart_plan_for_failure(&failed_child, &ok).is_none());
        prop_assert!(supervisor.restart_plan_for_failure(&failed_child, &cancelled_outcome()).is_none());
        prop_assert!(supervisor.restart_plan_for_failure(&failed_child, &panicked_outcome()).is_none());
        prop_assert!(supervisor.restart_plan_for_failure(&failed_child, &err_outcome()).is_some());
    }

    #[test]
    fn mr5_stop_order_is_reverse_of_start_order(child_count in 2usize..7) {
        let supervisor = compile_restartable_supervisor(child_count, RestartPolicy::OneForAll);
        let start = supervisor.child_start_order_names();
        let stop = supervisor.child_stop_order_names();

        let expected_stop: Vec<&str> = start.iter().rev().copied().collect();
        prop_assert_eq!(stop, expected_stop);
    }
}

#[test]
fn per_child_stop_and_escalate_strategies_never_produce_restart_plan() {
    let supervisor = SupervisorBuilder::new("strategy_gate")
        .with_restart_policy(RestartPolicy::OneForAll)
        .child(restartable_child("restartable".to_string()))
        .child(ChildSpec::new("stopper", noop_start).with_restart(SupervisionStrategy::Stop))
        .child(ChildSpec::new("escalator", noop_start).with_restart(SupervisionStrategy::Escalate))
        .compile()
        .expect("compile strategy gate supervisor");

    let err = err_outcome();
    assert!(
        supervisor
            .restart_plan_for_failure("restartable", &err)
            .is_some()
    );
    assert!(
        supervisor
            .restart_plan_for_failure("stopper", &err)
            .is_none()
    );
    assert!(
        supervisor
            .restart_plan_for_failure("escalator", &err)
            .is_none()
    );
}

#[test]
fn start_positions_track_insertion_order_without_dependencies() {
    let supervisor = compile_restartable_supervisor(4, RestartPolicy::OneForOne);

    assert_eq!(supervisor.child_start_pos("child_0"), Some(0));
    assert_eq!(supervisor.child_start_pos("child_1"), Some(1));
    assert_eq!(supervisor.child_start_pos("child_2"), Some(2));
    assert_eq!(supervisor.child_start_pos("child_3"), Some(3));
    assert_eq!(supervisor.child_start_pos("missing"), None);
}

#[test]
fn test_context_helper_produces_distinct_region_slots() {
    fn test_cx(slot: u32) -> Cx {
        Cx::new(
            RegionId::from_arena(ArenaIndex::new(0, slot)),
            TaskId::from_arena(ArenaIndex::new(0, slot)),
            Budget::INFINITE,
        )
    }

    let left = test_cx(1);
    let right = test_cx(2);
    assert_ne!(left.region_id(), right.region_id());
    assert_ne!(left.task_id(), right.task_id());
}
