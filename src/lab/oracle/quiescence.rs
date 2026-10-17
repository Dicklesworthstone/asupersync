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

        // The runtime removes a region from its table in the same walk that
        // closes it, so the history is the only record of a real close.
        // Checked here, it was never checked at all (br-asupersync-iwbef2).
        let mut closed_away = Vec::new();
        for event in state.finalizer_history() {
            match *event {
                crate::runtime::state::FinalizerHistoryEvent::Registered { id, region, .. } => {
                    self.on_finalizer_register(FinalizerId(id), region);
                }
                crate::runtime::state::FinalizerHistoryEvent::Ran { id, .. } => {
                    self.on_finalizer_run(FinalizerId(id));
                }
                crate::runtime::state::FinalizerHistoryEvent::RegionClosed { region, time } => {
                    if regions
                        .get(&region)
                        .is_none_or(|snapshot| !snapshot.state.is_terminal())
                    {
                        closed_away.push((region, time));
                    }
                }
            }
        }
        for (region, time) in closed_away {
            self.on_region_close(region, time);
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
#[path = "quiescence_inline_tests.rs"]
mod tests;
