//! Obligation leak oracle.
//!
//! Tracks obligation lifecycle events and ensures that all obligations are
//! resolved before their owning region closes.

use crate::record::{ObligationKind, ObligationState};
use crate::runtime::RuntimeState;
use crate::types::{ObligationId, RegionId, TaskId, Time};
use std::collections::HashMap;
use std::fmt;

/// Diagnostic record for a leaked obligation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObligationLeak {
    /// The leaked obligation id.
    pub obligation: ObligationId,
    /// The kind of obligation (permit/ack/lease/io).
    pub kind: ObligationKind,
    /// The task that held the obligation.
    pub holder: TaskId,
    /// The region that owned the obligation.
    pub region: RegionId,
}

impl fmt::Display for ObligationLeak {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?} {:?} holder={:?} region={:?}",
            self.obligation, self.kind, self.holder, self.region
        )
    }
}

/// Violation raised when a region closes with unresolved obligations.
#[derive(Debug, Clone)]
pub struct ObligationLeakViolation {
    /// The region that closed.
    pub region: RegionId,
    /// Leaked obligations for the region.
    pub leaked: Vec<ObligationLeak>,
    /// Time when the region closed.
    pub region_close_time: Time,
}

impl fmt::Display for ObligationLeakViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "region={:?} leaked={} at {:?}",
            self.region,
            self.leaked.len(),
            self.region_close_time
        )
    }
}

impl std::error::Error for ObligationLeakViolation {}

#[derive(Debug, Clone)]
struct ObligationSnapshot {
    kind: ObligationKind,
    holder: TaskId,
    region: RegionId,
    state: ObligationState,
}

/// Oracle that tracks obligation lifecycle events and checks for leaks.
#[derive(Debug, Default)]
pub struct ObligationLeakOracle {
    obligations: HashMap<ObligationId, ObligationSnapshot>,
    region_closes: Vec<(RegionId, Time)>,
}

impl ObligationLeakOracle {
    /// Creates a new obligation leak oracle.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Resets the oracle to its initial state.
    pub fn reset(&mut self) {
        self.obligations.clear();
        self.region_closes.clear();
    }

    /// Records an obligation creation event.
    pub fn on_create(
        &mut self,
        id: ObligationId,
        kind: ObligationKind,
        holder: TaskId,
        region: RegionId,
    ) {
        self.obligations.insert(
            id,
            ObligationSnapshot {
                kind,
                holder,
                region,
                state: ObligationState::Reserved,
            },
        );
    }

    /// Records an obligation resolution event (commit/abort).
    pub fn on_resolve(&mut self, id: ObligationId, state: ObligationState) {
        if let Some(snapshot) = self.obligations.get_mut(&id) {
            snapshot.state = state;
        }
    }

    /// Records a region close event for leak checking.
    pub fn on_region_close(&mut self, region: RegionId, time: Time) {
        self.region_closes.push((region, time));
    }

    /// Builds oracle state from a runtime snapshot.
    pub fn snapshot_from_state(&mut self, state: &RuntimeState, now: Time) {
        self.reset();

        for (_, obligation) in state.obligations.iter() {
            self.obligations.insert(
                obligation.id,
                ObligationSnapshot {
                    kind: obligation.kind,
                    holder: obligation.holder,
                    region: obligation.region,
                    state: obligation.state,
                },
            );
        }

        for (_, region) in state.regions.iter() {
            if region.state.is_terminal() {
                self.region_closes.push((region.id, now));
            }
        }
    }

    /// Checks for leaked obligations at region close.
    pub fn check(&self, _now: Time) -> Result<(), ObligationLeakViolation> {
        for (region, close_time) in &self.region_closes {
            let mut leaked = Vec::new();
            for (id, snapshot) in &self.obligations {
                if snapshot.region == *region && snapshot.state == ObligationState::Reserved {
                    leaked.push(ObligationLeak {
                        obligation: *id,
                        kind: snapshot.kind,
                        holder: snapshot.holder,
                        region: snapshot.region,
                    });
                }
            }

            if !leaked.is_empty() {
                return Err(ObligationLeakViolation {
                    region: *region,
                    leaked,
                    region_close_time: *close_time,
                });
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::ObligationRecord;
    use crate::record::TaskRecord;
    use crate::types::{Budget, ObligationId, RegionId, TaskId};
    use crate::util::ArenaIndex;

    #[test]
    fn detects_leak_on_region_close() {
        let mut oracle = ObligationLeakOracle::new();

        let region = RegionId::from_arena(ArenaIndex::new(0, 0));
        let task = TaskId::from_arena(ArenaIndex::new(1, 0));
        let obligation = ObligationId::from_arena(ArenaIndex::new(2, 0));

        oracle.on_create(obligation, ObligationKind::SendPermit, task, region);
        oracle.on_region_close(region, Time::ZERO);

        let err = oracle.check(Time::ZERO).expect_err("expected leak");
        assert_eq!(err.region, region);
        assert_eq!(err.leaked.len(), 1);
        assert_eq!(err.leaked[0].obligation, obligation);
    }

    #[test]
    fn snapshot_from_state_catches_reserved_obligation() {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);

        let task_idx = state.tasks.insert(TaskRecord::new(
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            root,
            Budget::INFINITE,
        ));
        let task_id = TaskId::from_arena(task_idx);
        state.tasks.get_mut(task_idx).unwrap().id = task_id;

        let obl_idx = state.obligations.insert(ObligationRecord::new(
            ObligationId::from_arena(ArenaIndex::new(0, 0)),
            ObligationKind::Ack,
            task_id,
            root,
        ));
        let obl_id = ObligationId::from_arena(obl_idx);
        state.obligations.get_mut(obl_idx).unwrap().id = obl_id;

        let mut oracle = ObligationLeakOracle::new();
        oracle.snapshot_from_state(&state, Time::ZERO);
        oracle.on_region_close(root, Time::ZERO);

        let err = oracle.check(Time::ZERO).expect_err("expected leak");
        assert_eq!(err.leaked.len(), 1);
        assert_eq!(err.leaked[0].obligation, obl_id);
    }

    #[test]
    fn resolved_obligation_is_not_leak() {
        let mut oracle = ObligationLeakOracle::new();

        let region = RegionId::from_arena(ArenaIndex::new(0, 0));
        let task = TaskId::from_arena(ArenaIndex::new(1, 0));
        let obligation = ObligationId::from_arena(ArenaIndex::new(2, 0));

        oracle.on_create(obligation, ObligationKind::Lease, task, region);
        oracle.on_resolve(obligation, ObligationState::Committed);
        oracle.on_region_close(region, Time::ZERO);

        assert!(oracle.check(Time::ZERO).is_ok());
    }
}
