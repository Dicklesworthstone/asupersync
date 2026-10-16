//! Obligation leak oracle.
//!
//! Tracks obligation lifecycle events and ensures that all obligations are
//! resolved before their owning region closes. Runtime snapshots also retain
//! explicit leak diagnoses made when a holder completes, including after its
//! region record has been reclaimed.

use crate::record::{ObligationKind, ObligationState};
use crate::runtime::RuntimeState;
use crate::types::{ObligationId, RegionId, TaskId, Time};
use std::collections::BTreeMap;
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

/// Violation raised for an explicitly diagnosed leak or a region closing with
/// unresolved obligations.
#[derive(Debug, Clone)]
pub struct ObligationLeakViolation {
    /// The region owning the leaked obligations.
    pub region: RegionId,
    /// Leaked obligations for the region.
    pub leaked: Vec<ObligationLeak>,
    /// Time when the region closed, or the earliest recorded leak time when
    /// the diagnosis does not come from an observed region close.
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
        )?;
        // Name every leaked record (kind and holder) so the report row is
        // actionable on its own, mirroring the runtime's
        // `InvariantViolation::ObligationLeak` rendering.
        if !self.leaked.is_empty() {
            write!(f, " leaks=[")?;
            for (index, leak) in self.leaked.iter().enumerate() {
                if index > 0 {
                    write!(f, "; ")?;
                }
                write!(f, "{leak}")?;
            }
            write!(f, "]")?;
        }
        Ok(())
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
    obligations: BTreeMap<ObligationId, ObligationSnapshot>,
    region_closes: Vec<(RegionId, Time)>,
    violations: Vec<ObligationLeakViolation>,
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
        self.violations.clear();
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

        let mut leaked = Vec::new();
        for (id, snapshot) in &self.obligations {
            if snapshot.region == region && !snapshot.state.is_success() {
                leaked.push(ObligationLeak {
                    obligation: *id,
                    kind: snapshot.kind,
                    holder: snapshot.holder,
                    region: snapshot.region,
                });
            }
        }
        leaked.sort_by_key(|leak| leak.obligation);

        if !leaked.is_empty() {
            self.violations.push(ObligationLeakViolation {
                region,
                leaked,
                region_close_time: time,
            });
        }
    }

    /// Builds oracle state from a runtime snapshot.
    pub fn snapshot_from_state(&mut self, state: &RuntimeState, now: Time) {
        self.reset();

        let mut recorded_leaks: BTreeMap<RegionId, (Time, Vec<ObligationLeak>)> = BTreeMap::new();
        for (_, obligation) in state.obligations_iter() {
            self.obligations.insert(
                obligation.id,
                ObligationSnapshot {
                    kind: obligation.kind,
                    holder: obligation.holder,
                    region: obligation.region,
                    state: obligation.state,
                },
            );
            if obligation.state == ObligationState::Leaked {
                let diagnosed_at = obligation.resolved_at.unwrap_or(now);
                let (first_diagnosis, leaked) = recorded_leaks
                    .entry(obligation.region)
                    .or_insert_with(|| (diagnosed_at, Vec::new()));
                *first_diagnosis = (*first_diagnosis).min(diagnosed_at);
                leaked.push(ObligationLeak {
                    obligation: obligation.id,
                    kind: obligation.kind,
                    holder: obligation.holder,
                    region: obligation.region,
                });
            }
        }

        let mut closed_regions = Vec::new();
        for (_, region) in state.regions_iter() {
            if region.state().is_terminal() {
                closed_regions.push(region.id);
            }
        }
        closed_regions.sort();

        for region in closed_regions {
            self.on_region_close(region, now);
            // The actual close already reports every non-successful record
            // in this region, including any prior explicit leak diagnosis.
            recorded_leaks.remove(&region);
        }
        for (region, (diagnosed_at, mut leaked)) in recorded_leaks {
            leaked.sort_by_key(|leak| leak.obligation);
            self.violations.push(ObligationLeakViolation {
                region,
                leaked,
                region_close_time: diagnosed_at,
            });
        }
    }

    /// Returns the number of tracked obligations.
    #[must_use]
    pub fn obligation_count(&self) -> usize {
        self.obligations.len()
    }

    /// Returns the number of closed regions tracked.
    #[must_use]
    pub fn closed_region_count(&self) -> usize {
        self.region_closes.len()
    }

    /// Checks for explicitly diagnosed leaks and unresolved obligations at
    /// region close. A live pending obligation in an open region is permitted.
    pub fn check(&self, _now: Time) -> Result<(), ObligationLeakViolation> {
        if let Some(violation) = self
            .violations
            .iter()
            .min_by_key(|violation| (violation.region, violation.region_close_time))
        {
            return Err(violation.clone());
        }

        Ok(())
    }
}

#[cfg(test)]
#[path = "obligation_leak_inline_tests.rs"]
mod tests;
