//! Quiescence oracle for verifying invariant #2: region close = quiescence.
//!
//! This oracle verifies that when a region closes, all its tasks have completed,
//! all its child regions have closed, all finalizers have run, and the owning
//! obligation ledger is empty.
//!
//! # Invariant
//!
//! From asupersync_plan_v4.md:
//! > Region close = quiescence: no live children + all finalizers done
//!
//! Formally:
//! `∀r ∈ closed_regions: children(r) = ∅ ∧ tasks(r) = ∅ ∧ finalizers(r) = ran ∧ ledger(r) = ∅`
//!
//! # Usage
//!
//! ```ignore
//! let mut oracle = QuiescenceOracle::new();
//!
//! // During execution, record events:
//! oracle.on_region_create(region_id, parent);
//! oracle.on_spawn(task_id, region_id);
//! oracle.on_task_complete(task_id);
//! oracle.on_region_close(region_id);
//!
//! // At end of test, verify:
//! oracle.check()?;
//! ```

use super::{Oracle, OracleStats, OracleViolation, finalizer::FinalizerId};
use crate::record::ObligationState;
use crate::runtime::RuntimeState;
use crate::types::{ObligationId, RegionId, TaskId, Time};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt;

/// A quiescence violation.
///
/// This indicates that a region closed while still having live tasks
/// or child regions, violating the quiescence invariant.
#[derive(Debug, Clone)]
pub struct QuiescenceViolation {
    /// The region that closed without quiescence.
    pub region: RegionId,
    /// Child regions that were still live.
    pub live_children: Vec<RegionId>,
    /// Tasks that were still live.
    pub live_tasks: Vec<TaskId>,
    /// Finalizers registered to the region that had not yet run.
    pub unrun_finalizers: Vec<FinalizerId>,
    /// Obligations still present in the region ledger at close.
    pub leaked_obligations: Vec<ObligationId>,
    /// The time when the region closed.
    pub close_time: Time,
}

impl fmt::Display for QuiescenceViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Region {:?} closed at {:?} without quiescence: {} live children, {} live tasks",
            self.region,
            self.close_time,
            self.live_children.len(),
            self.live_tasks.len()
        )?;
        if !self.unrun_finalizers.is_empty() || !self.leaked_obligations.is_empty() {
            write!(
                f,
                ", {} unrun finalizers, {} leaked obligations",
                self.unrun_finalizers.len(),
                self.leaked_obligations.len()
            )?;
        }
        Ok(())
    }
}

impl std::error::Error for QuiescenceViolation {}

/// Oracle for detecting quiescence violations.
///
/// Tracks region hierarchy, task spawns, and completions to verify that
/// regions only close when they have no live work.
#[derive(Debug, Default)]
pub struct QuiescenceOracle {
    /// Region parent relationships: region -> parent.
    region_parents: HashMap<RegionId, Option<RegionId>>,
    /// Region child relationships: region -> children.
    region_children: HashMap<RegionId, Vec<RegionId>>,
    /// Tasks by region: region -> tasks.
    region_tasks: HashMap<RegionId, Vec<TaskId>>,
    /// Completed tasks.
    completed_tasks: HashSet<TaskId>,
    /// Finalizer registrations by id.
    finalizers: HashMap<FinalizerId, RegionId>,
    /// Finalizers grouped by region.
    finalizers_by_region: HashMap<RegionId, HashSet<FinalizerId>>,
    /// Finalizers that ran.
    ran_finalizers: HashSet<FinalizerId>,
    /// Obligations by id.
    obligations: HashMap<ObligationId, TrackedObligation>,
    /// Closed regions with their close times.
    closed_regions: HashMap<RegionId, Time>,
    /// Detected violations.
    violations: Vec<QuiescenceViolation>,
}

#[derive(Debug, Clone, Copy)]
struct TrackedObligation {
    region: RegionId,
    state: ObligationState,
}

impl QuiescenceOracle {
    /// Creates a new quiescence oracle.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a region creation event.
    pub fn on_region_create(&mut self, region: RegionId, parent: Option<RegionId>) {
        self.region_parents.insert(region, parent);
        self.region_children.entry(region).or_default();
        self.region_tasks.entry(region).or_default();

        if let Some(p) = parent {
            self.region_children.entry(p).or_default().push(region);
            if let Some(&close_time) = self.closed_regions.get(&p) {
                self.violations.push(QuiescenceViolation {
                    region: p,
                    live_children: vec![region],
                    live_tasks: Vec::new(),
                    unrun_finalizers: Vec::new(),
                    leaked_obligations: Vec::new(),
                    close_time,
                });
            }
        }
    }

    /// Records a task spawn event.
    pub fn on_spawn(&mut self, task: TaskId, region: RegionId) {
        self.region_tasks.entry(region).or_default().push(task);
        if let Some(&close_time) = self.closed_regions.get(&region) {
            self.violations.push(QuiescenceViolation {
                region,
                live_children: Vec::new(),
                live_tasks: vec![task],
                unrun_finalizers: Vec::new(),
                leaked_obligations: Vec::new(),
                close_time,
            });
        }
    }

    /// Records a task completion event.
    pub fn on_task_complete(&mut self, task: TaskId) {
        self.completed_tasks.insert(task);
    }

    /// Records a finalizer registration event.
    pub fn on_finalizer_register(&mut self, id: FinalizerId, region: RegionId) {
        if let Some(previous_region) = self.finalizers.insert(id, region) {
            let remove_previous_region = self
                .finalizers_by_region
                .get_mut(&previous_region)
                .is_some_and(|finalizers| {
                    finalizers.remove(&id);
                    finalizers.is_empty()
                });
            if remove_previous_region {
                self.finalizers_by_region.remove(&previous_region);
            }
        }

        self.ran_finalizers.remove(&id);
        self.finalizers_by_region
            .entry(region)
            .or_default()
            .insert(id);

        if let Some(&close_time) = self.closed_regions.get(&region) {
            self.violations.push(QuiescenceViolation {
                region,
                live_children: Vec::new(),
                live_tasks: Vec::new(),
                unrun_finalizers: vec![id],
                leaked_obligations: Vec::new(),
                close_time,
            });
        }
    }

    /// Records a finalizer execution event.
    pub fn on_finalizer_run(&mut self, id: FinalizerId) {
        self.ran_finalizers.insert(id);
    }

    /// Records an obligation creation event.
    pub fn on_obligation_create(&mut self, obligation: ObligationId, region: RegionId) {
        self.obligations.insert(
            obligation,
            TrackedObligation {
                region,
                state: ObligationState::Reserved,
            },
        );

        if let Some(&close_time) = self.closed_regions.get(&region) {
            self.violations.push(QuiescenceViolation {
                region,
                live_children: Vec::new(),
                live_tasks: Vec::new(),
                unrun_finalizers: Vec::new(),
                leaked_obligations: vec![obligation],
                close_time,
            });
        }
    }

    /// Records an obligation resolution event.
    pub fn on_obligation_resolve(&mut self, obligation: ObligationId, state: ObligationState) {
        if let Some(tracked) = self.obligations.get_mut(&obligation) {
            tracked.state = state;
        }
    }

    /// Records a region close event.
    ///
    /// Checks quiescence at close time and records any violations.
    pub fn on_region_close(&mut self, region: RegionId, time: Time) {
        self.closed_regions.insert(region, time);

        // Check quiescence immediately
        let mut live_children = Vec::new();
        let mut live_tasks = Vec::new();
        let mut unrun_finalizers = Vec::new();
        let mut leaked_obligations = Vec::new();

        // Check child regions
        if let Some(children) = self.region_children.get(&region) {
            for &child in children {
                if !self.closed_regions.contains_key(&child) {
                    live_children.push(child);
                }
            }
        }

        // Check tasks
        if let Some(tasks) = self.region_tasks.get(&region) {
            for &task in tasks {
                if !self.completed_tasks.contains(&task) {
                    live_tasks.push(task);
                }
            }
        }

        if let Some(finalizers) = self.finalizers_by_region.get(&region) {
            for &finalizer in finalizers {
                if !self.ran_finalizers.contains(&finalizer) {
                    unrun_finalizers.push(finalizer);
                }
            }
        }

        for (&obligation, tracked) in &self.obligations {
            if tracked.region == region && !tracked.state.is_success() {
                leaked_obligations.push(obligation);
            }
        }

        unrun_finalizers.sort_by_key(|id| id.0);
        leaked_obligations.sort_by_key(|id| id.arena_index());

        if !live_children.is_empty()
            || !live_tasks.is_empty()
            || !unrun_finalizers.is_empty()
            || !leaked_obligations.is_empty()
        {
            self.violations.push(QuiescenceViolation {
                region,
                live_children,
                live_tasks,
                unrun_finalizers,
                leaked_obligations,
                close_time: time,
            });
        }
    }

    /// Rebuilds quiescence tracking from a runtime snapshot.
    #[allow(clippy::too_many_lines)]
    pub fn snapshot_from_state(&mut self, state: &RuntimeState, now: Time) {
        #[derive(Clone, Copy)]
        struct RegionSnapshot {
            id: RegionId,
            parent: Option<RegionId>,
            state: crate::record::region::RegionState,
        }

        fn walk_regions(
            id: RegionId,
            children: &BTreeMap<RegionId, Vec<RegionId>>,
            seen: &mut BTreeSet<RegionId>,
            pre_order: &mut Vec<RegionId>,
            post_order: &mut Vec<RegionId>,
        ) {
            if !seen.insert(id) {
                return;
            }
            pre_order.push(id);
            if let Some(kids) = children.get(&id) {
                for &child in kids {
                    walk_regions(child, children, seen, pre_order, post_order);
                }
            }
            post_order.push(id);
        }

        self.reset();

        let mut regions = BTreeMap::new();
        let mut children: BTreeMap<RegionId, Vec<RegionId>> = BTreeMap::new();
        for (_, region) in state.regions_iter() {
            let snapshot = RegionSnapshot {
                id: region.id,
                parent: region.parent,
                state: region.state(),
            };
            regions.insert(snapshot.id, snapshot);
            children.entry(snapshot.id).or_default();
        }

        for snapshot in regions.values() {
            if let Some(parent) = snapshot.parent {
                children.entry(parent).or_default().push(snapshot.id);
            }
        }
        for kids in children.values_mut() {
            kids.sort();
        }

        let mut roots = Vec::new();
        for (id, snapshot) in &regions {
            if snapshot
                .parent
                .is_none_or(|parent| !regions.contains_key(&parent))
            {
                roots.push(*id);
            }
        }

        let mut pre_order = Vec::new();
        let mut post_order = Vec::new();
        let mut seen = BTreeSet::new();
        for root in roots {
            walk_regions(root, &children, &mut seen, &mut pre_order, &mut post_order);
        }
        for &id in regions.keys() {
            walk_regions(id, &children, &mut seen, &mut pre_order, &mut post_order);
        }

        for region_id in &pre_order {
            let Some(snapshot) = regions.get(region_id) else {
                continue;
            };
            self.on_region_create(snapshot.id, snapshot.parent);
        }

        let mut tasks = Vec::new();
        for (_, task) in state.tasks_iter() {
            tasks.push((task.id, task.owner, task.state.is_terminal()));
        }
        tasks.sort_by_key(|(task, _, _)| *task);

        for (task_id, region_id, terminal) in tasks {
            self.on_spawn(task_id, region_id);
            if terminal {
                self.on_task_complete(task_id);
            }
        }

        let mut obligations = Vec::new();
        for (_, obligation) in state.obligations_iter() {
            obligations.push((obligation.id, obligation.region, obligation.state));
        }
        obligations.sort_by_key(|(id, _, _)| id.arena_index());
        for (id, region, obligation_state) in obligations {
            self.on_obligation_create(id, region);
            self.on_obligation_resolve(id, obligation_state);
        }

        for event in state.finalizer_history() {
            match *event {
                crate::runtime::state::FinalizerHistoryEvent::Registered { id, region, .. } => {
                    self.on_finalizer_register(FinalizerId(id), region);
                }
                crate::runtime::state::FinalizerHistoryEvent::Ran { id, .. } => {
                    self.on_finalizer_run(FinalizerId(id));
                }
                crate::runtime::state::FinalizerHistoryEvent::RegionClosed { .. } => {}
            }
        }

        for region_id in post_order {
            let Some(snapshot) = regions.get(&region_id) else {
                continue;
            };
            if snapshot.state.is_terminal() {
                self.on_region_close(region_id, now);
            }
        }
    }

    /// Verifies the invariant holds.
    ///
    /// Checks that for every closed region, all its tasks have completed
    /// and all its child regions have closed. Returns an error with the
    /// first violation found.
    ///
    /// # Returns
    /// * `Ok(())` if no violations are found
    /// * `Err(QuiescenceViolation)` if a violation is detected
    pub fn check(&self) -> Result<(), QuiescenceViolation> {
        if let Some(violation) = self.violations.first() {
            return Err(violation.clone());
        }
        Ok(())
    }

    /// Resets the oracle to its initial state.
    pub fn reset(&mut self) {
        self.region_parents.clear();
        self.region_children.clear();
        self.region_tasks.clear();
        self.completed_tasks.clear();
        self.finalizers.clear();
        self.finalizers_by_region.clear();
        self.ran_finalizers.clear();
        self.obligations.clear();
        self.closed_regions.clear();
        self.violations.clear();
    }

    /// Returns the number of regions tracked.
    #[must_use]
    pub fn region_count(&self) -> usize {
        self.region_parents.len()
    }

    /// Returns the number of closed regions.
    #[must_use]
    pub fn closed_count(&self) -> usize {
        self.closed_regions.len()
    }
}

impl Oracle for QuiescenceOracle {
    fn invariant_name(&self) -> &'static str {
        "quiescence"
    }

    fn violation(&self) -> Option<OracleViolation> {
        self.check().err().map(OracleViolation::Quiescence)
    }

    fn stats(&self) -> OracleStats {
        OracleStats {
            entities_tracked: self.region_count(),
            events_recorded: self.region_count()
                + self.closed_count()
                + self.completed_tasks.len()
                + self.finalizers.len()
                + self.ran_finalizers.len()
                + self.obligations.len(),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::lab::oracle::Oracle;
    use crate::util::ArenaIndex;

    fn task(n: u32) -> TaskId {
        TaskId::from_arena(ArenaIndex::new(n, 0))
    }

    fn region(n: u32) -> RegionId {
        RegionId::from_arena(ArenaIndex::new(n, 0))
    }

    fn finalizer(n: u64) -> FinalizerId {
        FinalizerId(n)
    }

    fn obligation(n: u32) -> ObligationId {
        ObligationId::from_arena(ArenaIndex::new(n, 0))
    }

    fn t(nanos: u64) -> Time {
        Time::from_nanos(nanos)
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn snapshot_report(oracle: &QuiescenceOracle) -> String {
        serde_json::to_string_pretty(&oracle.report_entry())
            .expect("quiescence report should serialize")
    }

    #[derive(Clone, Copy)]
    enum CleanupAction {
        CompleteTask(u32),
        CloseRegion(u32, u64),
    }

    fn parent_violation_after_partial_drain(actions: &[CleanupAction]) -> QuiescenceViolation {
        let mut oracle = QuiescenceOracle::new();
        oracle.on_region_create(region(0), None);
        oracle.on_region_create(region(1), Some(region(0)));
        oracle.on_region_create(region(2), Some(region(0)));
        oracle.on_spawn(task(1), region(0));
        oracle.on_spawn(task(2), region(0));
        oracle.on_spawn(task(3), region(0));

        for action in actions {
            match action {
                CleanupAction::CompleteTask(task_id) => oracle.on_task_complete(task(*task_id)),
                CleanupAction::CloseRegion(region_id, nanos) => {
                    oracle.on_region_close(region(*region_id), t(*nanos));
                }
            }
        }

        oracle.on_region_close(region(0), t(100));
        oracle
            .check()
            .expect_err("parent should still have one live child and one live task")
    }

    #[test]
    fn empty_region_passes() {
        init_test("empty_region_passes");
        let mut oracle = QuiescenceOracle::new();
        oracle.on_region_create(region(0), None);
        oracle.on_region_close(region(0), t(100));
        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "ok", true, ok);
        crate::test_complete!("empty_region_passes");
    }

    #[test]
    fn all_tasks_complete_passes() {
        init_test("all_tasks_complete_passes");
        let mut oracle = QuiescenceOracle::new();

        oracle.on_region_create(region(0), None);
        oracle.on_spawn(task(1), region(0));
        oracle.on_spawn(task(2), region(0));

        oracle.on_task_complete(task(1));
        oracle.on_task_complete(task(2));
        oracle.on_region_close(region(0), t(100));

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "ok", true, ok);
        crate::test_complete!("all_tasks_complete_passes");
    }

    #[test]
    fn live_task_fails() {
        init_test("live_task_fails");
        let mut oracle = QuiescenceOracle::new();

        oracle.on_region_create(region(0), None);
        oracle.on_spawn(task(1), region(0));
        // Task not completed
        oracle.on_region_close(region(0), t(100));

        let result = oracle.check();
        let err = result.is_err();
        crate::assert_with_log!(err, "err", true, err);

        let violation = result.unwrap_err();
        crate::assert_with_log!(
            violation.region == region(0),
            "region",
            region(0),
            violation.region
        );
        crate::assert_with_log!(
            violation.live_tasks == vec![task(1)],
            "live_tasks",
            vec![task(1)],
            violation.live_tasks
        );
        let empty = violation.live_children.is_empty();
        crate::assert_with_log!(empty, "live_children empty", true, empty);
        crate::test_complete!("live_task_fails");
    }

    #[test]
    fn live_child_region_fails() {
        init_test("live_child_region_fails");
        let mut oracle = QuiescenceOracle::new();

        oracle.on_region_create(region(0), None);
        oracle.on_region_create(region(1), Some(region(0)));

        // Parent closes but child does not
        oracle.on_region_close(region(0), t(100));

        let result = oracle.check();
        let err = result.is_err();
        crate::assert_with_log!(err, "err", true, err);

        let violation = result.unwrap_err();
        crate::assert_with_log!(
            violation.live_children == vec![region(1)],
            "live_children",
            vec![region(1)],
            violation.live_children
        );
        crate::test_complete!("live_child_region_fails");
    }

    #[test]
    fn unrun_finalizer_fails() {
        init_test("unrun_finalizer_fails");
        let mut oracle = QuiescenceOracle::new();

        oracle.on_region_create(region(0), None);
        oracle.on_finalizer_register(finalizer(7), region(0));
        oracle.on_region_close(region(0), t(100));

        let violation = oracle
            .check()
            .expect_err("close with unrun finalizer should fail");
        crate::assert_with_log!(
            violation.unrun_finalizers == vec![finalizer(7)],
            "unrun_finalizers",
            vec![finalizer(7)],
            violation.unrun_finalizers
        );
        let no_tasks = violation.live_tasks.is_empty();
        crate::assert_with_log!(no_tasks, "no live tasks", true, no_tasks);
        let no_children = violation.live_children.is_empty();
        crate::assert_with_log!(no_children, "no live children", true, no_children);
        let no_obligations = violation.leaked_obligations.is_empty();
        crate::assert_with_log!(
            no_obligations,
            "no leaked obligations",
            true,
            no_obligations
        );
        crate::test_complete!("unrun_finalizer_fails");
    }

    #[test]
    fn pending_obligation_fails() {
        init_test("pending_obligation_fails");
        let mut oracle = QuiescenceOracle::new();

        oracle.on_region_create(region(0), None);
        oracle.on_obligation_create(obligation(9), region(0));
        oracle.on_region_close(region(0), t(100));

        let violation = oracle
            .check()
            .expect_err("close with pending obligation should fail");
        crate::assert_with_log!(
            violation.leaked_obligations == vec![obligation(9)],
            "leaked_obligations",
            vec![obligation(9)],
            violation.leaked_obligations
        );
        let no_tasks = violation.live_tasks.is_empty();
        crate::assert_with_log!(no_tasks, "no live tasks", true, no_tasks);
        let no_children = violation.live_children.is_empty();
        crate::assert_with_log!(no_children, "no live children", true, no_children);
        let no_finalizers = violation.unrun_finalizers.is_empty();
        crate::assert_with_log!(no_finalizers, "no unrun finalizers", true, no_finalizers);
        crate::test_complete!("pending_obligation_fails");
    }

    #[test]
    fn nested_regions_pass_when_properly_closed() {
        init_test("nested_regions_pass_when_properly_closed");
        let mut oracle = QuiescenceOracle::new();

        oracle.on_region_create(region(0), None);
        oracle.on_region_create(region(1), Some(region(0)));
        oracle.on_spawn(task(1), region(1));

        oracle.on_task_complete(task(1));
        oracle.on_region_close(region(1), t(50)); // Child closes first
        oracle.on_region_close(region(0), t(100)); // Parent closes after

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "ok", true, ok);
        crate::test_complete!("nested_regions_pass_when_properly_closed");
    }

    #[test]
    fn multiple_children_all_must_close() {
        init_test("multiple_children_all_must_close");
        let mut oracle = QuiescenceOracle::new();

        oracle.on_region_create(region(0), None);
        oracle.on_region_create(region(1), Some(region(0)));
        oracle.on_region_create(region(2), Some(region(0)));

        // Only close one child
        oracle.on_region_close(region(1), t(50));
        oracle.on_region_close(region(0), t(100));

        let result = oracle.check();
        let err = result.is_err();
        crate::assert_with_log!(err, "err", true, err);

        let violation = result.unwrap_err();
        crate::assert_with_log!(
            violation.live_children == vec![region(2)],
            "live_children",
            vec![region(2)],
            violation.live_children
        );
        crate::test_complete!("multiple_children_all_must_close");
    }

    #[test]
    fn child_created_after_parent_close_is_violation() {
        init_test("child_created_after_parent_close_is_violation");
        let mut oracle = QuiescenceOracle::new();

        oracle.on_region_create(region(0), None);
        oracle.on_region_close(region(0), t(100));
        oracle.on_region_create(region(1), Some(region(0)));

        let result = oracle.check();
        let err = result.is_err();
        crate::assert_with_log!(err, "err", true, err);

        let violation = result.unwrap_err();
        crate::assert_with_log!(
            violation.region == region(0),
            "region",
            region(0),
            violation.region
        );
        crate::assert_with_log!(
            violation.live_children == vec![region(1)],
            "live_children",
            vec![region(1)],
            violation.live_children
        );
        let tasks_empty = violation.live_tasks.is_empty();
        crate::assert_with_log!(tasks_empty, "tasks empty", true, tasks_empty);
        crate::test_complete!("child_created_after_parent_close_is_violation");
    }

    #[test]
    fn task_spawned_after_region_close_is_violation_even_if_it_completes_later() {
        init_test("task_spawned_after_region_close_is_violation_even_if_it_completes_later");
        let mut oracle = QuiescenceOracle::new();

        oracle.on_region_create(region(0), None);
        oracle.on_region_close(region(0), t(100));
        oracle.on_spawn(task(1), region(0));
        oracle.on_task_complete(task(1));

        let result = oracle.check();
        let err = result.is_err();
        crate::assert_with_log!(err, "err", true, err);

        let violation = result.unwrap_err();
        crate::assert_with_log!(
            violation.region == region(0),
            "region",
            region(0),
            violation.region
        );
        crate::assert_with_log!(
            violation.live_tasks == vec![task(1)],
            "live_tasks",
            vec![task(1)],
            violation.live_tasks
        );
        let children_empty = violation.live_children.is_empty();
        crate::assert_with_log!(children_empty, "children empty", true, children_empty);
        crate::test_complete!(
            "task_spawned_after_region_close_is_violation_even_if_it_completes_later"
        );
    }

    #[test]
    fn reset_clears_state() {
        init_test("reset_clears_state");
        let mut oracle = QuiescenceOracle::new();

        oracle.on_region_create(region(0), None);
        oracle.on_spawn(task(1), region(0));
        oracle.on_region_close(region(0), t(100));

        // This would fail
        let err = oracle.check().is_err();
        crate::assert_with_log!(err, "err", true, err);

        oracle.reset();

        // After reset, no violations
        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "ok", true, ok);
        let region_count = oracle.region_count();
        crate::assert_with_log!(region_count == 0, "region_count", 0, region_count);
        let closed_count = oracle.closed_count();
        crate::assert_with_log!(closed_count == 0, "closed_count", 0, closed_count);
        crate::test_complete!("reset_clears_state");
    }

    #[test]
    fn violation_display() {
        init_test("violation_display");
        let violation = QuiescenceViolation {
            region: region(0),
            live_children: vec![region(1)],
            live_tasks: vec![task(1), task(2)],
            unrun_finalizers: Vec::new(),
            leaked_obligations: Vec::new(),
            close_time: t(100),
        };

        let s = violation.to_string();
        let has_without = s.contains("without quiescence");
        crate::assert_with_log!(has_without, "without quiescence", true, has_without);
        let has_children = s.contains("1 live children");
        crate::assert_with_log!(has_children, "children text", true, has_children);
        let has_tasks = s.contains("2 live tasks");
        crate::assert_with_log!(has_tasks, "tasks text", true, has_tasks);
        crate::test_complete!("violation_display");
    }

    #[test]
    fn quiescence_clean_close_report_snapshot() {
        let mut oracle = QuiescenceOracle::new();
        oracle.on_region_create(region(0), None);
        oracle.on_spawn(task(1), region(0));
        oracle.on_task_complete(task(1));
        oracle.on_region_close(region(0), t(100));

        insta::assert_snapshot!("quiescence_clean_close_report", snapshot_report(&oracle));
    }

    #[test]
    fn quiescence_leak_detected_report_snapshot() {
        let mut oracle = QuiescenceOracle::new();
        oracle.on_region_create(region(0), None);
        oracle.on_region_create(region(1), Some(region(0)));
        oracle.on_spawn(task(1), region(0));
        oracle.on_region_close(region(0), t(50));

        insta::assert_snapshot!("quiescence_leak_detected_report", snapshot_report(&oracle));
    }

    #[test]
    fn quiescence_cancel_during_drain_report_snapshot() {
        let mut oracle = QuiescenceOracle::new();
        oracle.on_region_create(region(0), None);
        oracle.on_spawn(task(1), region(0));
        oracle.on_region_close(region(0), t(75));
        oracle.on_task_complete(task(1));

        insta::assert_snapshot!(
            "quiescence_cancel_during_drain_report",
            snapshot_report(&oracle)
        );
    }

    #[test]
    fn deeply_nested_regions() {
        init_test("deeply_nested_regions");
        let mut oracle = QuiescenceOracle::new();

        // Create a chain: r0 -> r1 -> r2
        oracle.on_region_create(region(0), None);
        oracle.on_region_create(region(1), Some(region(0)));
        oracle.on_region_create(region(2), Some(region(1)));
        oracle.on_spawn(task(1), region(2));

        // Close in correct order (innermost first)
        oracle.on_task_complete(task(1));
        oracle.on_region_close(region(2), t(30));
        oracle.on_region_close(region(1), t(50));
        oracle.on_region_close(region(0), t(100));

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "ok", true, ok);
        crate::test_complete!("deeply_nested_regions");
    }

    #[test]
    fn both_tasks_and_children_must_complete() {
        init_test("both_tasks_and_children_must_complete");
        let mut oracle = QuiescenceOracle::new();

        oracle.on_region_create(region(0), None);
        oracle.on_region_create(region(1), Some(region(0)));
        oracle.on_spawn(task(1), region(0));

        // Close child but not task
        oracle.on_region_close(region(1), t(50));
        oracle.on_region_close(region(0), t(100));

        let result = oracle.check();
        let err = result.is_err();
        crate::assert_with_log!(err, "err", true, err);

        let violation = result.unwrap_err();
        let children_empty = violation.live_children.is_empty();
        crate::assert_with_log!(children_empty, "children empty", true, children_empty);
        crate::assert_with_log!(
            violation.live_tasks == vec![task(1)],
            "live_tasks",
            vec![task(1)],
            violation.live_tasks
        );
        crate::test_complete!("both_tasks_and_children_must_complete");
    }

    #[test]
    fn mr_cleanup_permutation_preserves_residual_violation() {
        init_test("mr_cleanup_permutation_preserves_residual_violation");
        let violation_a = parent_violation_after_partial_drain(&[
            CleanupAction::CompleteTask(1),
            CleanupAction::CloseRegion(1, 40),
            CleanupAction::CompleteTask(2),
        ]);
        let violation_b = parent_violation_after_partial_drain(&[
            CleanupAction::CloseRegion(1, 40),
            CleanupAction::CompleteTask(2),
            CleanupAction::CompleteTask(1),
        ]);

        crate::assert_with_log!(
            violation_a.region == region(0),
            "violation_a.region",
            region(0),
            violation_a.region
        );
        crate::assert_with_log!(
            violation_a.live_children == vec![region(2)],
            "violation_a.live_children",
            vec![region(2)],
            violation_a.live_children.clone()
        );
        crate::assert_with_log!(
            violation_a.live_tasks == vec![task(3)],
            "violation_a.live_tasks",
            vec![task(3)],
            violation_a.live_tasks.clone()
        );
        crate::assert_with_log!(
            violation_b.region == violation_a.region,
            "violation_b.region",
            violation_a.region,
            violation_b.region
        );
        crate::assert_with_log!(
            violation_b.live_children == violation_a.live_children,
            "violation_b.live_children",
            violation_a.live_children.clone(),
            violation_b.live_children.clone()
        );
        crate::assert_with_log!(
            violation_b.live_tasks == violation_a.live_tasks,
            "violation_b.live_tasks",
            violation_a.live_tasks.clone(),
            violation_b.live_tasks.clone()
        );
        crate::assert_with_log!(
            violation_b.close_time == violation_a.close_time,
            "violation_b.close_time",
            violation_a.close_time,
            violation_b.close_time
        );
        crate::test_complete!("mr_cleanup_permutation_preserves_residual_violation");
    }

    #[test]
    fn quiescence_violation_debug_clone() {
        let v = QuiescenceViolation {
            region: region(1),
            live_children: vec![region(2), region(3)],
            live_tasks: vec![task(10)],
            unrun_finalizers: Vec::new(),
            leaked_obligations: Vec::new(),
            close_time: t(500),
        };
        let cloned = v.clone();
        assert_eq!(cloned.region, v.region);
        assert_eq!(cloned.live_children.len(), 2);
        assert_eq!(cloned.live_tasks.len(), 1);
        let dbg = format!("{v:?}");
        assert!(dbg.contains("QuiescenceViolation"));
    }

    #[test]
    fn quiescence_oracle_debug_default() {
        let oracle = QuiescenceOracle::default();
        let dbg = format!("{oracle:?}");
        assert!(dbg.contains("QuiescenceOracle"));
        let oracle2 = QuiescenceOracle::new();
        let dbg2 = format!("{oracle2:?}");
        assert_eq!(dbg, dbg2);
    }
}
