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
    id: FinalizerId,
    region: RegionId,
    #[allow(dead_code)]
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
        self.next_id += 1;
        id
    }

    /// Records a finalizer registration event.
    ///
    /// Called when a finalizer is registered with a region.
    pub fn on_register(&mut self, id: FinalizerId, region: RegionId, time: Time) {
        self.finalizers.insert(
            id,
            FinalizerRecord {
                id,
                region,
                registered_at: time,
            },
        );
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
        for (&region, &close_time) in &self.region_closes {
            let Some(finalizers) = self.finalizers_by_region.get(&region) else {
                continue; // No finalizers registered for this region
            };

            let mut unrun = Vec::new();

            for &finalizer_id in finalizers {
                if !self.ran_finalizers.contains(&finalizer_id) {
                    unrun.push(finalizer_id);
                }
            }

            if !unrun.is_empty() {
                return Err(FinalizerViolation {
                    region,
                    unrun_finalizers: unrun,
                    region_close_time: close_time,
                });
            }
        }

        Ok(())
    }

    /// Resets the oracle to its initial state.
    pub fn reset(&mut self) {
        self.finalizers.clear();
        self.finalizers_by_region.clear();
        self.ran_finalizers.clear();
        self.region_closes.clear();
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::ArenaIndex;

    fn region(n: u32) -> RegionId {
        RegionId::from_arena(ArenaIndex::new(n, 0))
    }

    fn t(nanos: u64) -> Time {
        Time::from_nanos(nanos)
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn no_finalizers_passes() {
        init_test("no_finalizers_passes");
        let oracle = FinalizerOracle::new();
        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "oracle ok", true, ok);
        crate::test_complete!("no_finalizers_passes");
    }

    #[test]
    fn all_finalizers_run_passes() {
        init_test("all_finalizers_run_passes");
        let mut oracle = FinalizerOracle::new();

        let f1 = oracle.generate_id();
        let f2 = oracle.generate_id();

        oracle.on_register(f1, region(0), t(10));
        oracle.on_register(f2, region(0), t(20));

        oracle.on_run(f1, t(50));
        oracle.on_run(f2, t(60));

        oracle.on_region_close(region(0), t(100));

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "oracle ok", true, ok);
        crate::test_complete!("all_finalizers_run_passes");
    }

    #[test]
    fn unrun_finalizer_fails() {
        init_test("unrun_finalizer_fails");
        let mut oracle = FinalizerOracle::new();

        let f1 = oracle.generate_id();
        let f2 = oracle.generate_id();

        oracle.on_register(f1, region(0), t(10));
        oracle.on_register(f2, region(0), t(20));

        // Only f1 runs
        oracle.on_run(f1, t(50));

        oracle.on_region_close(region(0), t(100));

        let result = oracle.check();
        let err = result.is_err();
        crate::assert_with_log!(err, "result err", true, err);

        let violation = result.unwrap_err();
        crate::assert_with_log!(
            violation.region == region(0),
            "violation region",
            region(0),
            violation.region
        );
        crate::assert_with_log!(
            violation.unrun_finalizers == vec![f2],
            "unrun finalizers",
            vec![f2],
            violation.unrun_finalizers
        );
        crate::assert_with_log!(
            violation.region_close_time == t(100),
            "region close time",
            t(100),
            violation.region_close_time
        );
        crate::test_complete!("unrun_finalizer_fails");
    }

    #[test]
    fn no_finalizers_run_all_fail() {
        init_test("no_finalizers_run_all_fail");
        let mut oracle = FinalizerOracle::new();

        let f1 = oracle.generate_id();
        let f2 = oracle.generate_id();

        oracle.on_register(f1, region(0), t(10));
        oracle.on_register(f2, region(0), t(20));

        // No finalizers run
        oracle.on_region_close(region(0), t(100));

        let result = oracle.check();
        let err = result.is_err();
        crate::assert_with_log!(err, "result err", true, err);

        let violation = result.unwrap_err();
        let count = violation.unrun_finalizers.len();
        crate::assert_with_log!(count == 2, "unrun finalizers", 2, count);
        crate::test_complete!("no_finalizers_run_all_fail");
    }

    #[test]
    fn multiple_regions_independent() {
        init_test("multiple_regions_independent");
        let mut oracle = FinalizerOracle::new();

        // Region 0: finalizer runs
        let f1 = oracle.generate_id();
        oracle.on_register(f1, region(0), t(10));
        oracle.on_run(f1, t(50));
        oracle.on_region_close(region(0), t(100));

        // Region 1: finalizer does NOT run
        let f2 = oracle.generate_id();
        oracle.on_register(f2, region(1), t(20));
        oracle.on_region_close(region(1), t(100));

        let result = oracle.check();
        let err = result.is_err();
        crate::assert_with_log!(err, "result err", true, err);

        let violation = result.unwrap_err();
        crate::assert_with_log!(
            violation.region == region(1),
            "violation region",
            region(1),
            violation.region
        );
        crate::assert_with_log!(
            violation.unrun_finalizers == vec![f2],
            "unrun finalizers",
            vec![f2],
            violation.unrun_finalizers
        );
        crate::test_complete!("multiple_regions_independent");
    }

    #[test]
    fn region_without_close_not_checked() {
        init_test("region_without_close_not_checked");
        let mut oracle = FinalizerOracle::new();

        let f1 = oracle.generate_id();
        oracle.on_register(f1, region(0), t(10));
        // f1 never runs, but region never closes either

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "oracle ok", true, ok);
        crate::test_complete!("region_without_close_not_checked");
    }

    #[test]
    fn reset_clears_state() {
        init_test("reset_clears_state");
        let mut oracle = FinalizerOracle::new();

        let f1 = oracle.generate_id();
        oracle.on_register(f1, region(0), t(10));
        oracle.on_region_close(region(0), t(100));

        // Would fail
        let err = oracle.check().is_err();
        crate::assert_with_log!(err, "oracle err", true, err);

        oracle.reset();

        // After reset, no violations
        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "oracle ok", true, ok);
        let registered = oracle.registered_count();
        crate::assert_with_log!(registered == 0, "registered count", 0, registered);
        let ran = oracle.ran_count();
        crate::assert_with_log!(ran == 0, "ran count", 0, ran);
        crate::test_complete!("reset_clears_state");
    }

    #[test]
    fn violation_display() {
        init_test("violation_display");
        let violation = FinalizerViolation {
            region: region(0),
            unrun_finalizers: vec![FinalizerId(1), FinalizerId(2)],
            region_close_time: t(100),
        };

        let s = violation.to_string();
        let has_region = s.contains("Region");
        crate::assert_with_log!(has_region, "contains Region", true, has_region);
        let has_unrun = s.contains("unrun finalizer");
        crate::assert_with_log!(has_unrun, "contains unrun", true, has_unrun);
        let has_two = s.contains('2');
        crate::assert_with_log!(has_two, "contains 2", true, has_two);
        crate::test_complete!("violation_display");
    }
}
