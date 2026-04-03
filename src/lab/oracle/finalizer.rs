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
        self.next_id += 1;
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
    fn check_reports_regions_and_finalizers_in_stable_order() {
        init_test("check_reports_regions_and_finalizers_in_stable_order");
        let mut oracle = FinalizerOracle::new();

        let region0_f1 = oracle.generate_id();
        let region0_f0 = oracle.generate_id();
        let region1_f0 = oracle.generate_id();

        oracle.on_register(region1_f0, region(1), t(10));
        oracle.on_region_close(region(1), t(200));

        oracle.on_register(region0_f1, region(0), t(20));
        oracle.on_register(region0_f0, region(0), t(30));
        oracle.on_region_close(region(0), t(100));

        let violation = oracle
            .check()
            .expect_err("lower region id should be reported first");
        crate::assert_with_log!(
            violation.region == region(0),
            "violation region",
            region(0),
            violation.region
        );
        crate::assert_with_log!(
            violation.unrun_finalizers == vec![region0_f1, region0_f0],
            "sorted unrun finalizers",
            vec![region0_f1, region0_f0],
            violation.unrun_finalizers
        );
        crate::assert_with_log!(
            violation.region_close_time == t(100),
            "region close time",
            t(100),
            violation.region_close_time
        );
        crate::test_complete!("check_reports_regions_and_finalizers_in_stable_order");
    }

    #[test]
    fn finalizer_run_after_close_still_violates() {
        init_test("finalizer_run_after_close_still_violates");
        let mut oracle = FinalizerOracle::new();

        let finalizer = oracle.generate_id();
        oracle.on_register(finalizer, region(0), t(10));
        oracle.on_region_close(region(0), t(100));
        oracle.on_run(finalizer, t(110));

        let violation = oracle
            .check()
            .expect_err("running a finalizer after close must not erase the violation");
        crate::assert_with_log!(
            violation.region == region(0),
            "violation region",
            region(0),
            violation.region
        );
        crate::assert_with_log!(
            violation.unrun_finalizers == vec![finalizer],
            "unrun finalizers",
            vec![finalizer],
            violation.unrun_finalizers
        );
        crate::assert_with_log!(
            violation.region_close_time == t(100),
            "region close time",
            t(100),
            violation.region_close_time
        );
        crate::test_complete!("finalizer_run_after_close_still_violates");
    }

    #[test]
    fn reregistered_finalizer_moves_out_of_previous_region() {
        init_test("reregistered_finalizer_moves_out_of_previous_region");
        let mut oracle = FinalizerOracle::new();

        let finalizer = oracle.generate_id();
        oracle.on_register(finalizer, region(0), t(10));
        oracle.on_register(finalizer, region(1), t(20));

        oracle.on_region_close(region(0), t(30));

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "oracle ok", true, ok);
        crate::test_complete!("reregistered_finalizer_moves_out_of_previous_region");
    }

    #[test]
    fn reregistered_finalizer_requires_a_fresh_run() {
        init_test("reregistered_finalizer_requires_a_fresh_run");
        let mut oracle = FinalizerOracle::new();

        let finalizer = oracle.generate_id();
        oracle.on_register(finalizer, region(0), t(10));
        oracle.on_run(finalizer, t(20));

        oracle.on_register(finalizer, region(1), t(30));
        oracle.on_region_close(region(1), t(40));

        let violation = oracle
            .check()
            .expect_err("re-registering a finalizer must require a new run");
        crate::assert_with_log!(
            violation.region == region(1),
            "violation region",
            region(1),
            violation.region
        );
        crate::assert_with_log!(
            violation.unrun_finalizers == vec![finalizer],
            "unrun finalizers",
            vec![finalizer],
            violation.unrun_finalizers
        );
        crate::assert_with_log!(
            violation.region_close_time == t(40),
            "region close time",
            t(40),
            violation.region_close_time
        );
        crate::test_complete!("reregistered_finalizer_requires_a_fresh_run");
    }

    #[test]
    fn exact_duplicate_registration_preserves_completed_state() {
        init_test("exact_duplicate_registration_preserves_completed_state");
        let mut oracle = FinalizerOracle::new();

        let finalizer = oracle.generate_id();
        oracle.on_register(finalizer, region(0), t(10));
        oracle.on_run(finalizer, t(20));

        // Duplicate event for the same registration should be idempotent.
        oracle.on_register(finalizer, region(0), t(10));
        oracle.on_region_close(region(0), t(30));

        let ok = oracle.check().is_ok();
        crate::assert_with_log!(ok, "oracle ok", true, ok);
        let ran = oracle.ran_count();
        crate::assert_with_log!(ran == 1, "ran count", 1, ran);
        crate::test_complete!("exact_duplicate_registration_preserves_completed_state");
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

    // --- wave 76 trait coverage ---

    #[test]
    fn finalizer_id_debug_clone_copy_eq_hash() {
        use std::collections::HashSet;
        let id = FinalizerId(42);
        let id2 = id; // Copy
        let id3 = id;
        assert_eq!(id, id2);
        assert_eq!(id, id3);
        assert_ne!(id, FinalizerId(99));
        let dbg = format!("{id:?}");
        assert!(dbg.contains("42"));
        let mut set = HashSet::new();
        set.insert(id);
        assert!(set.contains(&id2));
    }

    #[test]
    fn finalizer_violation_debug_clone() {
        let v = FinalizerViolation {
            region: region(0),
            unrun_finalizers: vec![FinalizerId(1), FinalizerId(2)],
            region_close_time: t(100),
        };
        let v2 = v.clone();
        assert_eq!(v.region, v2.region);
        assert_eq!(v.unrun_finalizers, v2.unrun_finalizers);
        let dbg = format!("{v:?}");
        assert!(dbg.contains("FinalizerViolation"));
    }
}
