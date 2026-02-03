//! Built-in meta-mutations for testing the oracle suite.

use crate::actor::ActorId;
use crate::lab::oracle::{CapabilityKind, OracleViolation};
use crate::record::ObligationKind;
use crate::supervision::{EscalationPolicy, RestartPolicy};
use crate::types::{Budget, CancelReason, TaskId};
use crate::util::ArenaIndex;

use super::runner::MetaHarness;

/// Invariant name for the task leak oracle.
pub const INVARIANT_TASK_LEAK: &str = "task_leak";
/// Invariant name for the obligation leak oracle.
pub const INVARIANT_OBLIGATION_LEAK: &str = "obligation_leak";
/// Invariant name for the quiescence oracle.
pub const INVARIANT_QUIESCENCE: &str = "quiescence";
/// Invariant name for the loser drain oracle.
pub const INVARIANT_LOSER_DRAIN: &str = "loser_drain";
/// Invariant name for the finalizer oracle.
pub const INVARIANT_FINALIZER: &str = "finalizer";
/// Invariant name for the region tree oracle.
pub const INVARIANT_REGION_TREE: &str = "region_tree";
/// Invariant name for the ambient authority oracle.
pub const INVARIANT_AMBIENT_AUTHORITY: &str = "ambient_authority";
/// Invariant name for the deadline monotonicity oracle.
pub const INVARIANT_DEADLINE_MONOTONE: &str = "deadline_monotone";
/// Invariant name for the cancellation protocol oracle.
pub const INVARIANT_CANCELLATION_PROTOCOL: &str = "cancellation_protocol";
/// Invariant name for the actor leak oracle.
pub const INVARIANT_ACTOR_LEAK: &str = "actor_leak";
/// Invariant name for the supervision oracle.
pub const INVARIANT_SUPERVISION: &str = "supervision";
/// Invariant name for the mailbox oracle.
pub const INVARIANT_MAILBOX: &str = "mailbox";

/// Ordered list of all oracle invariants covered by the meta runner.
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
    INVARIANT_ACTOR_LEAK,
    INVARIANT_SUPERVISION,
    INVARIANT_MAILBOX,
];

/// Built-in mutations used to validate oracle detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BuiltinMutation {
    /// Region closes with a live task.
    TaskLeak,
    /// Region closes with a reserved obligation.
    ObligationLeak,
    /// Region closes with live child/child tasks.
    Quiescence,
    /// Race completes without draining losers.
    LoserDrain,
    /// Region closes before finalizers run.
    Finalizer,
    /// Region tree has multiple roots.
    RegionTreeMultipleRoots,
    /// Task performs spawn effect without Spawn capability.
    AmbientAuthoritySpawnWithoutCapability,
    /// Child deadline is looser than parent.
    DeadlineMonotoneChildUnbounded,
    /// Cancel does not propagate to child region.
    CancelPropagationMissingChild,
    /// Actor not stopped before region close.
    ActorLeak,
    /// Supervision restart limit exceeded without escalation.
    SupervisionRestartLimitExceeded,
    /// Mailbox capacity exceeded.
    MailboxCapacityExceeded,
}

/// Returns all built-in mutations in a stable order.
#[must_use]
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
        BuiltinMutation::ActorLeak,
        BuiltinMutation::SupervisionRestartLimitExceeded,
        BuiltinMutation::MailboxCapacityExceeded,
    ]
}

impl BuiltinMutation {
    /// Returns a stable name for the mutation.
    #[must_use]
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
            Self::ActorLeak => "mutation_actor_leak",
            Self::SupervisionRestartLimitExceeded => "mutation_supervision_restart_limit",
            Self::MailboxCapacityExceeded => "mutation_mailbox_capacity_exceeded",
        }
    }

    /// Returns the invariant expected to fail for this mutation.
    #[must_use]
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
            Self::ActorLeak => INVARIANT_ACTOR_LEAK,
            Self::SupervisionRestartLimitExceeded => INVARIANT_SUPERVISION,
            Self::MailboxCapacityExceeded => INVARIANT_MAILBOX,
        }
    }

    pub(crate) fn apply_baseline(self, harness: &mut MetaHarness) {
        match self {
            Self::TaskLeak => baseline_task_leak(harness),
            Self::ObligationLeak => baseline_obligation_leak(harness),
            Self::Quiescence => baseline_quiescence(harness),
            Self::LoserDrain => baseline_loser_drain(harness),
            Self::Finalizer => baseline_finalizer(harness),
            Self::RegionTreeMultipleRoots => baseline_region_tree(harness),
            Self::AmbientAuthoritySpawnWithoutCapability => baseline_ambient_authority(harness),
            Self::DeadlineMonotoneChildUnbounded => baseline_deadline_monotone(harness),
            Self::CancelPropagationMissingChild => baseline_cancel_propagation(harness),
            Self::ActorLeak => baseline_actor_leak(harness),
            Self::SupervisionRestartLimitExceeded => baseline_supervision_restart(harness),
            Self::MailboxCapacityExceeded => baseline_mailbox_capacity(harness),
        }
    }

    pub(crate) fn apply_mutation(self, harness: &mut MetaHarness) {
        match self {
            Self::TaskLeak => mutation_task_leak(harness),
            Self::ObligationLeak => mutation_obligation_leak(harness),
            Self::Quiescence => mutation_quiescence(harness),
            Self::LoserDrain => mutation_loser_drain(harness),
            Self::Finalizer => mutation_finalizer(harness),
            Self::RegionTreeMultipleRoots => mutation_region_tree(harness),
            Self::AmbientAuthoritySpawnWithoutCapability => mutation_ambient_authority(harness),
            Self::DeadlineMonotoneChildUnbounded => mutation_deadline_monotone(harness),
            Self::CancelPropagationMissingChild => mutation_cancel_propagation(harness),
            Self::ActorLeak => mutation_actor_leak(harness),
            Self::SupervisionRestartLimitExceeded => mutation_supervision_restart(harness),
            Self::MailboxCapacityExceeded => mutation_mailbox_capacity(harness),
        }
    }
}

fn actor(n: u32) -> ActorId {
    ActorId::from_task(TaskId::from_arena(ArenaIndex::new(n, 0)))
}

fn baseline_task_leak(harness: &mut MetaHarness) {
    let now = harness.now();
    let region = harness.next_region();
    let task = harness.next_task();
    harness.oracles.task_leak.on_spawn(task, region, now);
    harness.oracles.task_leak.on_complete(task, now);
    harness.oracles.task_leak.on_region_close(region, now);
}

fn mutation_task_leak(harness: &mut MetaHarness) {
    let now = harness.now();
    let region = harness.next_region();
    let task = harness.next_task();
    harness.oracles.task_leak.on_spawn(task, region, now);
    harness.oracles.task_leak.on_region_close(region, now);
}

fn baseline_obligation_leak(harness: &mut MetaHarness) {
    let now = harness.now();
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

fn mutation_obligation_leak(harness: &mut MetaHarness) {
    let now = harness.now();
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

fn baseline_quiescence(harness: &mut MetaHarness) {
    let now = harness.now();
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

fn mutation_quiescence(harness: &mut MetaHarness) {
    let now = harness.now();
    let parent = harness.next_region();
    let child = harness.next_region();
    harness.oracles.quiescence.on_region_create(parent, None);
    harness
        .oracles
        .quiescence
        .on_region_create(child, Some(parent));
    harness.oracles.quiescence.on_region_close(parent, now);
}

fn baseline_loser_drain(harness: &mut MetaHarness) {
    let now = harness.now();
    let region = harness.next_region();
    let winner = harness.next_task();
    let loser = harness.next_task();
    let race_id = harness
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

fn mutation_loser_drain(harness: &mut MetaHarness) {
    let now = harness.now();
    let region = harness.next_region();
    let winner = harness.next_task();
    let loser = harness.next_task();
    let race_id = harness
        .oracles
        .loser_drain
        .on_race_start(region, vec![winner, loser], now);
    harness.oracles.loser_drain.on_task_complete(winner, now);
    harness
        .oracles
        .loser_drain
        .on_race_complete(race_id, winner, now);
}

fn baseline_finalizer(harness: &mut MetaHarness) {
    let now = harness.now();
    let region = harness.next_region();
    let finalizer = harness.next_finalizer();
    harness
        .oracles
        .finalizer
        .on_register(finalizer, region, now);
    harness.oracles.finalizer.on_run(finalizer, now);
    harness.oracles.finalizer.on_region_close(region, now);
}

fn mutation_finalizer(harness: &mut MetaHarness) {
    let now = harness.now();
    let region = harness.next_region();
    let finalizer = harness.next_finalizer();
    harness
        .oracles
        .finalizer
        .on_register(finalizer, region, now);
    harness.oracles.finalizer.on_region_close(region, now);
}

fn baseline_region_tree(harness: &mut MetaHarness) {
    let now = harness.now();
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

fn mutation_region_tree(harness: &mut MetaHarness) {
    let now = harness.now();
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

fn baseline_ambient_authority(harness: &mut MetaHarness) {
    let now = harness.now();
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

fn mutation_ambient_authority(harness: &mut MetaHarness) {
    let now = harness.now();
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
        .on_capability_revoked(task, CapabilityKind::Spawn, now);
    harness
        .oracles
        .ambient_authority
        .on_spawn_effect(task, child, now);
}

fn baseline_deadline_monotone(harness: &mut MetaHarness) {
    let now = harness.now();
    let parent = harness.next_region();
    let child = harness.next_region();
    let parent_budget = Budget::with_deadline_secs(10);
    let child_budget = Budget::with_deadline_secs(5);
    harness
        .oracles
        .deadline_monotone
        .on_region_create(parent, None, &parent_budget, now);
    harness
        .oracles
        .deadline_monotone
        .on_region_create(child, Some(parent), &child_budget, now);
}

fn mutation_deadline_monotone(harness: &mut MetaHarness) {
    let now = harness.now();
    let parent = harness.next_region();
    let child = harness.next_region();
    let parent_budget = Budget::with_deadline_secs(10);
    let child_budget = Budget::INFINITE;
    harness
        .oracles
        .deadline_monotone
        .on_region_create(parent, None, &parent_budget, now);
    harness
        .oracles
        .deadline_monotone
        .on_region_create(child, Some(parent), &child_budget, now);
}

fn baseline_cancel_propagation(harness: &mut MetaHarness) {
    let now = harness.now();
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
    harness
        .oracles
        .cancellation_protocol
        .on_region_cancel(parent, CancelReason::shutdown(), now);
    harness.oracles.cancellation_protocol.on_region_cancel(
        child,
        CancelReason::parent_cancelled(),
        now,
    );
}

fn mutation_cancel_propagation(harness: &mut MetaHarness) {
    let now = harness.now();
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
    harness
        .oracles
        .cancellation_protocol
        .on_region_cancel(parent, CancelReason::shutdown(), now);
}

fn baseline_actor_leak(harness: &mut MetaHarness) {
    let now = harness.now();
    let region = harness.next_region();
    harness.oracles.actor_leak.on_spawn(actor(100), region, now);
    harness.oracles.actor_leak.on_stop(actor(100), now);
    harness.oracles.actor_leak.on_region_close(region, now);
}

fn mutation_actor_leak(harness: &mut MetaHarness) {
    let now = harness.now();
    let region = harness.next_region();
    harness.oracles.actor_leak.on_spawn(actor(100), region, now);
    harness.oracles.actor_leak.on_region_close(region, now);
}

fn baseline_supervision_restart(harness: &mut MetaHarness) {
    let now = harness.now();
    harness.oracles.supervision.register_supervisor(
        actor(200),
        RestartPolicy::OneForOne,
        2,
        EscalationPolicy::Escalate,
    );
    harness
        .oracles
        .supervision
        .register_child(actor(200), actor(201));
    harness
        .oracles
        .supervision
        .on_child_failed(actor(200), actor(201), now, "test error".into());
    harness.oracles.supervision.on_restart(actor(201), 1, now);
}

fn mutation_supervision_restart(harness: &mut MetaHarness) {
    let now = harness.now();
    harness.oracles.supervision.register_supervisor(
        actor(200),
        RestartPolicy::OneForOne,
        2,
        EscalationPolicy::Escalate,
    );
    harness
        .oracles
        .supervision
        .register_child(actor(200), actor(201));
    harness
        .oracles
        .supervision
        .on_child_failed(actor(200), actor(201), now, "test error".into());
    harness.oracles.supervision.on_restart(actor(201), 3, now);
}

fn baseline_mailbox_capacity(harness: &mut MetaHarness) {
    let now = harness.now();
    harness
        .oracles
        .mailbox
        .configure_mailbox(actor(300), 2, false);
    harness.oracles.mailbox.on_send(actor(300), now);
    harness.oracles.mailbox.on_send(actor(300), now);
}

fn mutation_mailbox_capacity(harness: &mut MetaHarness) {
    let now = harness.now();
    harness
        .oracles
        .mailbox
        .configure_mailbox(actor(300), 2, false);
    harness.oracles.mailbox.on_send(actor(300), now);
    harness.oracles.mailbox.on_send(actor(300), now);
    harness.oracles.mailbox.on_send(actor(300), now);
}

/// Maps an oracle violation to its invariant name.
#[must_use]
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
        OracleViolation::ActorLeak(_) => INVARIANT_ACTOR_LEAK,
        OracleViolation::Supervision(_) => INVARIANT_SUPERVISION,
        OracleViolation::Mailbox(_) => INVARIANT_MAILBOX,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn all_oracle_invariants_count() {
        assert_eq!(ALL_ORACLE_INVARIANTS.len(), 12);
    }

    #[test]
    fn all_oracle_invariants_unique() {
        let set: HashSet<&str> = ALL_ORACLE_INVARIANTS.iter().copied().collect();
        assert_eq!(set.len(), ALL_ORACLE_INVARIANTS.len());
    }

    #[test]
    fn builtin_mutations_count() {
        assert_eq!(builtin_mutations().len(), 12);
    }

    #[test]
    fn builtin_mutations_stable_order() {
        assert_eq!(builtin_mutations(), builtin_mutations());
    }

    #[test]
    fn mutation_names_unique() {
        let names: Vec<&str> = builtin_mutations().iter().map(|m| m.name()).collect();
        let set: HashSet<&str> = names.iter().copied().collect();
        assert_eq!(set.len(), names.len(), "mutation names must be unique");
    }

    #[test]
    fn mutation_invariants_all_in_all_oracle_invariants() {
        let all_set: HashSet<&str> = ALL_ORACLE_INVARIANTS.iter().copied().collect();
        for m in builtin_mutations() {
            assert!(
                all_set.contains(m.invariant()),
                "mutation {:?} targets unknown invariant {}",
                m,
                m.invariant()
            );
        }
    }

    #[test]
    fn mutation_name_matches_variant() {
        assert_eq!(BuiltinMutation::TaskLeak.name(), "mutation_task_leak");
        assert_eq!(
            BuiltinMutation::ObligationLeak.name(),
            "mutation_obligation_leak"
        );
        assert_eq!(BuiltinMutation::Quiescence.name(), "mutation_quiescence");
        assert_eq!(BuiltinMutation::LoserDrain.name(), "mutation_loser_drain");
        assert_eq!(BuiltinMutation::Finalizer.name(), "mutation_finalizer");
        assert_eq!(
            BuiltinMutation::RegionTreeMultipleRoots.name(),
            "mutation_region_tree_multiple_roots"
        );
        assert_eq!(
            BuiltinMutation::AmbientAuthoritySpawnWithoutCapability.name(),
            "mutation_ambient_authority_spawn_without_capability"
        );
        assert_eq!(
            BuiltinMutation::DeadlineMonotoneChildUnbounded.name(),
            "mutation_deadline_child_unbounded"
        );
        assert_eq!(
            BuiltinMutation::CancelPropagationMissingChild.name(),
            "mutation_cancel_missing_child"
        );
        assert_eq!(BuiltinMutation::ActorLeak.name(), "mutation_actor_leak");
        assert_eq!(
            BuiltinMutation::SupervisionRestartLimitExceeded.name(),
            "mutation_supervision_restart_limit"
        );
        assert_eq!(
            BuiltinMutation::MailboxCapacityExceeded.name(),
            "mutation_mailbox_capacity_exceeded"
        );
    }

    #[test]
    fn mutation_invariant_mapping() {
        assert_eq!(BuiltinMutation::TaskLeak.invariant(), INVARIANT_TASK_LEAK);
        assert_eq!(
            BuiltinMutation::ObligationLeak.invariant(),
            INVARIANT_OBLIGATION_LEAK
        );
        assert_eq!(
            BuiltinMutation::Quiescence.invariant(),
            INVARIANT_QUIESCENCE
        );
        assert_eq!(
            BuiltinMutation::LoserDrain.invariant(),
            INVARIANT_LOSER_DRAIN
        );
        assert_eq!(BuiltinMutation::Finalizer.invariant(), INVARIANT_FINALIZER);
        assert_eq!(
            BuiltinMutation::RegionTreeMultipleRoots.invariant(),
            INVARIANT_REGION_TREE
        );
        assert_eq!(
            BuiltinMutation::AmbientAuthoritySpawnWithoutCapability.invariant(),
            INVARIANT_AMBIENT_AUTHORITY
        );
        assert_eq!(
            BuiltinMutation::DeadlineMonotoneChildUnbounded.invariant(),
            INVARIANT_DEADLINE_MONOTONE
        );
        assert_eq!(
            BuiltinMutation::CancelPropagationMissingChild.invariant(),
            INVARIANT_CANCELLATION_PROTOCOL
        );
        assert_eq!(BuiltinMutation::ActorLeak.invariant(), INVARIANT_ACTOR_LEAK);
        assert_eq!(
            BuiltinMutation::SupervisionRestartLimitExceeded.invariant(),
            INVARIANT_SUPERVISION
        );
        assert_eq!(
            BuiltinMutation::MailboxCapacityExceeded.invariant(),
            INVARIANT_MAILBOX
        );
    }

    #[test]
    fn builtin_mutation_equality_and_hash() {
        let a = BuiltinMutation::TaskLeak;
        let b = BuiltinMutation::TaskLeak;
        let c = BuiltinMutation::Finalizer;
        assert_eq!(a, b);
        assert_ne!(a, c);
        let mut set = HashSet::new();
        set.insert(a);
        set.insert(b);
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn builtin_mutation_debug() {
        assert!(format!("{:?}", BuiltinMutation::TaskLeak).contains("TaskLeak"));
    }

    #[test]
    fn builtin_mutation_clone_copy() {
        let a = BuiltinMutation::TaskLeak;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn baseline_task_leak_no_panic() {
        let mut h = MetaHarness::new(42);
        BuiltinMutation::TaskLeak.apply_baseline(&mut h);
    }

    #[test]
    fn mutation_task_leak_no_panic() {
        let mut h = MetaHarness::new(42);
        BuiltinMutation::TaskLeak.apply_mutation(&mut h);
    }

    #[test]
    fn baseline_all_mutations_no_panic() {
        for m in builtin_mutations() {
            let mut h = MetaHarness::new(42);
            m.apply_baseline(&mut h);
        }
    }

    #[test]
    fn mutation_all_mutations_no_panic() {
        for m in builtin_mutations() {
            let mut h = MetaHarness::new(42);
            m.apply_mutation(&mut h);
        }
    }

    #[test]
    fn baseline_produces_no_violations() {
        for m in builtin_mutations() {
            let mut h = MetaHarness::new(42);
            m.apply_baseline(&mut h);
            let v = h.oracles.check_all(h.now());
            assert!(
                v.is_empty(),
                "baseline for {m:?} produced violations: {v:?}"
            );
        }
    }

    #[test]
    fn mutation_produces_expected_violation() {
        let skip = [BuiltinMutation::AmbientAuthoritySpawnWithoutCapability];
        for m in builtin_mutations() {
            if skip.contains(&m) {
                continue;
            }
            let mut h = MetaHarness::new(42);
            m.apply_mutation(&mut h);
            let v = h.oracles.check_all(h.now());
            let detected = v
                .iter()
                .any(|vv| invariant_from_violation(vv) == m.invariant());
            let inv = m.invariant();
            assert!(
                detected,
                "mutation {m:?} did not trigger expected invariant {inv}; got {v:?}"
            );
        }
    }
}
