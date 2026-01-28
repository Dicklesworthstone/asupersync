//! Built-in meta-mutations for testing the oracle suite.

use crate::lab::oracle::{CapabilityKind, OracleViolation};
use crate::record::ObligationKind;
use crate::types::{Budget, CancelReason};

use super::runner::MetaHarness;

pub const INVARIANT_TASK_LEAK: &str = "task_leak";
pub const INVARIANT_OBLIGATION_LEAK: &str = "obligation_leak";
pub const INVARIANT_QUIESCENCE: &str = "quiescence";
pub const INVARIANT_LOSER_DRAIN: &str = "loser_drain";
pub const INVARIANT_FINALIZER: &str = "finalizer";
pub const INVARIANT_REGION_TREE: &str = "region_tree";
pub const INVARIANT_AMBIENT_AUTHORITY: &str = "ambient_authority";
pub const INVARIANT_DEADLINE_MONOTONE: &str = "deadline_monotone";
pub const INVARIANT_CANCELLATION_PROTOCOL: &str = "cancellation_protocol";

pub const ALL_ORACLE_INVARIANTS: &[&str] = &[
    INVARIANT_TASK_LEAK,
    INVARIANT_QUIESCENCE,
    INVARIANT_CANCELLATION_PROTOCOL,
    INVARIANT_LOSER_DRAIN,
    INVARIANT_OBLIGATION_LEAK,
    INVARIANT_AMBIENT_AUTHORITY,
    INVARIANT_FINALIZER,
    INVARIANT_REGION_TREE,
    INVARIANT_DEADLINE_MONOTONE,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BuiltinMutation {
    TaskLeak,
    ObligationLeak,
    Quiescence,
    LoserDrain,
    Finalizer,
    RegionTreeMultipleRoots,
    AmbientAuthoritySpawnWithoutCapability,
    DeadlineMonotoneChildUnbounded,
    CancelPropagationMissingChild,
}

pub fn builtin_mutations() -> Vec<BuiltinMutation> {
    vec![
        BuiltinMutation::TaskLeak,
        BuiltinMutation::ObligationLeak,
        BuiltinMutation::Quiescence,
        BuiltinMutation::LoserDrain,
        BuiltinMutation::Finalizer,
        BuiltinMutation::RegionTreeMultipleRoots,
        BuiltinMutation::AmbientAuthoritySpawnWithoutCapability,
        BuiltinMutation::DeadlineMonotoneChildUnbounded,
        BuiltinMutation::CancelPropagationMissingChild,
    ]
}

impl BuiltinMutation {
    pub fn name(self) -> &'static str {
        match self {
            Self::TaskLeak => "mutation_task_leak",
            Self::ObligationLeak => "mutation_obligation_leak",
            Self::Quiescence => "mutation_quiescence",
            Self::LoserDrain => "mutation_loser_drain",
            Self::Finalizer => "mutation_finalizer",
            Self::RegionTreeMultipleRoots => "mutation_region_tree_multiple_roots",
            Self::AmbientAuthoritySpawnWithoutCapability => {
                "mutation_ambient_authority_spawn_without_capability"
            }
            Self::DeadlineMonotoneChildUnbounded => "mutation_deadline_child_unbounded",
            Self::CancelPropagationMissingChild => "mutation_cancel_missing_child",
        }
    }

    pub fn invariant(self) -> &'static str {
        match self {
            Self::TaskLeak => INVARIANT_TASK_LEAK,
            Self::ObligationLeak => INVARIANT_OBLIGATION_LEAK,
            Self::Quiescence => INVARIANT_QUIESCENCE,
            Self::LoserDrain => INVARIANT_LOSER_DRAIN,
            Self::Finalizer => INVARIANT_FINALIZER,
            Self::RegionTreeMultipleRoots => INVARIANT_REGION_TREE,
            Self::AmbientAuthoritySpawnWithoutCapability => INVARIANT_AMBIENT_AUTHORITY,
            Self::DeadlineMonotoneChildUnbounded => INVARIANT_DEADLINE_MONOTONE,
            Self::CancelPropagationMissingChild => INVARIANT_CANCELLATION_PROTOCOL,
        }
    }

    pub fn apply_baseline(self, harness: &mut MetaHarness) {
        let now = harness.now();
        match self {
            Self::TaskLeak => {
                let region = harness.next_region();
                let task = harness.next_task();
                harness.oracles.task_leak.on_spawn(task, region, now);
                harness.oracles.task_leak.on_complete(task, now);
                harness.oracles.task_leak.on_region_close(region, now);
            }
            Self::ObligationLeak => {
                let region = harness.create_root_region();
                let task = harness.create_runtime_task(region);
                let obligation = harness
                    .runtime
                    .state
                    .create_obligation(ObligationKind::SendPermit, task, region, None)
                    .expect("create obligation");
                harness
                    .runtime
                    .state
                    .commit_obligation(obligation)
                    .expect("commit obligation");
                harness.close_region(region);
                harness
                    .oracles
                    .obligation_leak
                    .snapshot_from_state(&harness.runtime.state, now);
            }
            Self::Quiescence => {
                let parent = harness.next_region();
                let child = harness.next_region();
                harness.oracles.quiescence.on_region_create(parent, None);
                harness
                    .oracles
                    .quiescence
                    .on_region_create(child, Some(parent));
                harness.oracles.quiescence.on_region_close(child, now);
                harness.oracles.quiescence.on_region_close(parent, now);
            }
            Self::LoserDrain => {
                let region = harness.next_region();
                let winner = harness.next_task();
                let loser = harness.next_task();
                let race_id =
                    harness
                        .oracles
                        .loser_drain
                        .on_race_start(region, vec![winner, loser], now);
                harness.oracles.loser_drain.on_task_complete(winner, now);
                harness.oracles.loser_drain.on_task_complete(loser, now);
                harness
                    .oracles
                    .loser_drain
                    .on_race_complete(race_id, winner, now);
            }
            Self::Finalizer => {
                let region = harness.next_region();
                let finalizer = harness.next_finalizer();
                harness
                    .oracles
                    .finalizer
                    .on_register(finalizer, region, now);
                harness.oracles.finalizer.on_run(finalizer, now);
                harness.oracles.finalizer.on_region_close(region, now);
            }
            Self::RegionTreeMultipleRoots => {
                let root = harness.next_region();
                let child = harness.next_region();
                harness
                    .oracles
                    .region_tree
                    .on_region_create(root, None, now);
                harness
                    .oracles
                    .region_tree
                    .on_region_create(child, Some(root), now);
            }
            Self::AmbientAuthoritySpawnWithoutCapability => {
                let region = harness.next_region();
                let task = harness.next_task();
                let child = harness.next_task();
                harness
                    .oracles
                    .ambient_authority
                    .on_task_created(task, region, None, now);
                harness
                    .oracles
                    .ambient_authority
                    .on_spawn_effect(task, child, now);
            }
            Self::DeadlineMonotoneChildUnbounded => {
                let parent = harness.next_region();
                let child = harness.next_region();
                let parent_budget = Budget::with_deadline_secs(10);
                let child_budget = Budget::with_deadline_secs(5);
                harness.oracles.deadline_monotone.on_region_create(
                    parent,
                    None,
                    &parent_budget,
                    now,
                );
                harness.oracles.deadline_monotone.on_region_create(
                    child,
                    Some(parent),
                    &child_budget,
                    now,
                );
            }
            Self::CancelPropagationMissingChild => {
                let parent = harness.next_region();
                let child = harness.next_region();
                harness
                    .oracles
                    .cancellation_protocol
                    .on_region_create(parent, None);
                harness
                    .oracles
                    .cancellation_protocol
                    .on_region_create(child, Some(parent));
                harness.oracles.cancellation_protocol.on_region_cancel(
                    parent,
                    CancelReason::shutdown(),
                    now,
                );
                harness.oracles.cancellation_protocol.on_region_cancel(
                    child,
                    CancelReason::parent_cancelled(),
                    now,
                );
            }
        }
    }

    pub fn apply_mutation(self, harness: &mut MetaHarness) {
        let now = harness.now();
        match self {
            Self::TaskLeak => {
                let region = harness.next_region();
                let task = harness.next_task();
                harness.oracles.task_leak.on_spawn(task, region, now);
                harness.oracles.task_leak.on_region_close(region, now);
            }
            Self::ObligationLeak => {
                let region = harness.create_root_region();
                let task = harness.create_runtime_task(region);
                let _obligation = harness
                    .runtime
                    .state
                    .create_obligation(ObligationKind::SendPermit, task, region, None)
                    .expect("create obligation");
                harness.close_region(region);
                harness
                    .oracles
                    .obligation_leak
                    .snapshot_from_state(&harness.runtime.state, now);
            }
            Self::Quiescence => {
                let parent = harness.next_region();
                let child = harness.next_region();
                harness.oracles.quiescence.on_region_create(parent, None);
                harness
                    .oracles
                    .quiescence
                    .on_region_create(child, Some(parent));
                harness.oracles.quiescence.on_region_close(parent, now);
            }
            Self::LoserDrain => {
                let region = harness.next_region();
                let winner = harness.next_task();
                let loser = harness.next_task();
                let race_id =
                    harness
                        .oracles
                        .loser_drain
                        .on_race_start(region, vec![winner, loser], now);
                harness.oracles.loser_drain.on_task_complete(winner, now);
                harness
                    .oracles
                    .loser_drain
                    .on_race_complete(race_id, winner, now);
            }
            Self::Finalizer => {
                let region = harness.next_region();
                let finalizer = harness.next_finalizer();
                harness
                    .oracles
                    .finalizer
                    .on_register(finalizer, region, now);
                harness.oracles.finalizer.on_region_close(region, now);
            }
            Self::RegionTreeMultipleRoots => {
                let root_a = harness.next_region();
                let root_b = harness.next_region();
                harness
                    .oracles
                    .region_tree
                    .on_region_create(root_a, None, now);
                harness
                    .oracles
                    .region_tree
                    .on_region_create(root_b, None, now);
            }
            Self::AmbientAuthoritySpawnWithoutCapability => {
                let region = harness.next_region();
                let task = harness.next_task();
                let child = harness.next_task();
                harness
                    .oracles
                    .ambient_authority
                    .on_task_created(task, region, None, now);
                harness.oracles.ambient_authority.on_capability_revoked(
                    task,
                    CapabilityKind::Spawn,
                    now,
                );
                harness
                    .oracles
                    .ambient_authority
                    .on_spawn_effect(task, child, now);
            }
            Self::DeadlineMonotoneChildUnbounded => {
                let parent = harness.next_region();
                let child = harness.next_region();
                let parent_budget = Budget::with_deadline_secs(10);
                let child_budget = Budget::INFINITE;
                harness.oracles.deadline_monotone.on_region_create(
                    parent,
                    None,
                    &parent_budget,
                    now,
                );
                harness.oracles.deadline_monotone.on_region_create(
                    child,
                    Some(parent),
                    &child_budget,
                    now,
                );
            }
            Self::CancelPropagationMissingChild => {
                let parent = harness.next_region();
                let child = harness.next_region();
                harness
                    .oracles
                    .cancellation_protocol
                    .on_region_create(parent, None);
                harness
                    .oracles
                    .cancellation_protocol
                    .on_region_create(child, Some(parent));
                harness.oracles.cancellation_protocol.on_region_cancel(
                    parent,
                    CancelReason::shutdown(),
                    now,
                );
            }
        }
    }
}

pub fn invariant_from_violation(violation: &OracleViolation) -> &'static str {
    match violation {
        OracleViolation::TaskLeak(_) => INVARIANT_TASK_LEAK,
        OracleViolation::ObligationLeak(_) => INVARIANT_OBLIGATION_LEAK,
        OracleViolation::Quiescence(_) => INVARIANT_QUIESCENCE,
        OracleViolation::LoserDrain(_) => INVARIANT_LOSER_DRAIN,
        OracleViolation::Finalizer(_) => INVARIANT_FINALIZER,
        OracleViolation::RegionTree(_) => INVARIANT_REGION_TREE,
        OracleViolation::AmbientAuthority(_) => INVARIANT_AMBIENT_AUTHORITY,
        OracleViolation::DeadlineMonotone(_) => INVARIANT_DEADLINE_MONOTONE,
        OracleViolation::CancellationProtocol(_) => INVARIANT_CANCELLATION_PROTOCOL,
    }
}
