//! Finalizer oracle for verifying that all registered finalizers run.
//!
//! This oracle verifies that every finalizer registered within a region
//! has executed before the region closes.
//!
//! # Invariant
//!
//! From asupersync_plan_v4.md:
//! > Region close = quiescence: no live children + all finalizers done
//!
//! Formally: `∀r ∈ closed_regions: ∀f ∈ finalizers(r): f.ran = true`
//!
//! # Usage
//!
//! ```ignore
//! let mut oracle = FinalizerOracle::new();
//!
//! // During execution, record events:
//! oracle.on_register(finalizer_id, region_id, time);
//! oracle.on_run(finalizer_id, time);
//! oracle.on_region_close(region_id, time);
//!
//! // At end of test, verify:
//! oracle.check()?;
//! ```

use crate::types::{RegionId, Time};
use std::collections::{HashMap, HashSet};
use std::fmt;

/// Unique identifier for a finalizer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FinalizerId(pub u64);

impl fmt::Display for FinalizerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Finalizer({})", self.0)
    }
}

/// A finalizer violation.
///
/// This indicates that a region closed while some registered finalizers
/// had not yet run, violating the quiescence invariant.
#[derive(Debug, Clone)]
pub struct FinalizerViolation {
    /// The region that closed with unrun finalizers.
    pub region: RegionId,
    /// The finalizers that did not run.
    pub unrun_finalizers: Vec<FinalizerId>,
    /// The time when the region closed.
    pub region_close_time: Time,
}

impl fmt::Display for FinalizerViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Region {} closed at {} with {} unrun finalizer(s): {:?}",
            self.region,
            self.region_close_time,
            self.unrun_finalizers.len(),
            self.unrun_finalizers
        )
    }
}

impl std::error::Error for FinalizerViolation {}

/// Record of a finalizer registration.
#[derive(Debug, Clone)]
struct FinalizerRecord {
    #[allow(dead_code)] // retained for debug diagnostics
    id: FinalizerId,
    region: RegionId,
    registered_at: Time,
}

/// Oracle for detecting finalizer violations.
///
/// Tracks finalizer registrations, executions, and region closes to verify
/// that all finalizers run before their region closes.
#[derive(Debug, Default)]
pub struct FinalizerOracle {
    /// Registered finalizers: id -> record.
    finalizers: HashMap<FinalizerId, FinalizerRecord>,
    /// Finalizers by region: region -> finalizer ids.
    finalizers_by_region: HashMap<RegionId, HashSet<FinalizerId>>,
    /// Finalizers that have run.
    ran_finalizers: HashSet<FinalizerId>,
    /// Region close records: region -> close_time.
    region_closes: HashMap<RegionId, Time>,
    /// Violations captured at the moment a region closes.
    violations: Vec<FinalizerViolation>,
    /// Next finalizer ID for auto-generation.
    next_id: u64,
}

impl FinalizerOracle {
    /// Creates a new finalizer oracle.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Generates a unique finalizer ID.
    pub fn generate_id(&mut self) -> FinalizerId {
        let id = FinalizerId(self.next_id);
        self.next_id = self
            .next_id
            .checked_add(1)
            .expect("finalizer oracle id counter exhausted");
        id
    }

    /// Records a finalizer registration event.
    ///
    /// Called when a finalizer is registered with a region.
    pub fn on_register(&mut self, id: FinalizerId, region: RegionId, time: Time) {
        if self
            .finalizers
            .get(&id)
            .is_some_and(|existing| existing.region == region && existing.registered_at == time)
        {
            self.finalizers_by_region
                .entry(region)
                .or_default()
                .insert(id);
            return;
        }

        if let Some(previous) = self.finalizers.insert(
            id,
            FinalizerRecord {
                id,
                region,
                registered_at: time,
            },
        ) {
            let remove_previous_region = self
                .finalizers_by_region
                .get_mut(&previous.region)
                .is_some_and(|finalizers| {
                    finalizers.remove(&id);
                    finalizers.is_empty()
                });
            if remove_previous_region {
                self.finalizers_by_region.remove(&previous.region);
            }
        }

        // A fresh registration must require a fresh run, even if the same ID
        // had already completed in an earlier lifecycle.
        self.ran_finalizers.remove(&id);
        self.finalizers_by_region
            .entry(region)
            .or_default()
            .insert(id);
    }

    /// Records a finalizer execution event.
    ///
    /// Called when a finalizer runs.
    pub fn on_run(&mut self, id: FinalizerId, _time: Time) {
        self.ran_finalizers.insert(id);
    }

    /// Records a region close event.
    ///
    /// Called when a region reaches the Closed state.
    pub fn on_region_close(&mut self, region: RegionId, time: Time) {
        self.region_closes.insert(region, time);

        let Some(finalizers) = self.finalizers_by_region.get(&region) else {
            return;
        };

        let mut unrun = Vec::new();
        for &finalizer_id in finalizers {
            if !self.ran_finalizers.contains(&finalizer_id) {
                unrun.push(finalizer_id);
            }
        }
        unrun.sort_by_key(|id| id.0);

        if !unrun.is_empty() {
            self.violations.push(FinalizerViolation {
                region,
                unrun_finalizers: unrun,
                region_close_time: time,
            });
        }
    }

    /// Verifies the invariant holds.
    ///
    /// Checks that for every closed region, all registered finalizers have run.
    /// Returns an error with the first violation found.
    ///
    /// # Returns
    /// * `Ok(())` if no violations are found
    /// * `Err(FinalizerViolation)` if a violation is detected
    pub fn check(&self) -> Result<(), FinalizerViolation> {
        if let Some(violation) = self
            .violations
            .iter()
            .min_by_key(|violation| (violation.region, violation.region_close_time))
        {
            return Err(violation.clone());
        }

        Ok(())
    }

    /// Resets the oracle to its initial state.
    pub fn reset(&mut self) {
        self.finalizers.clear();
        self.finalizers_by_region.clear();
        self.ran_finalizers.clear();
        self.region_closes.clear();
        self.violations.clear();
        // Don't reset next_id to avoid ID collisions across tests
    }

    /// Returns the number of registered finalizers.
    #[must_use]
    pub fn registered_count(&self) -> usize {
        self.finalizers.len()
    }

    /// Returns the number of finalizers that have run.
    #[must_use]
    pub fn ran_count(&self) -> usize {
        self.ran_finalizers.len()
    }

    /// Returns the number of regions that have closed.
    #[must_use]
    pub fn closed_region_count(&self) -> usize {
        self.region_closes.len()
    }
}

#[cfg(test)]
#[path = "finalizer_inline_tests.rs"]
mod tests;
