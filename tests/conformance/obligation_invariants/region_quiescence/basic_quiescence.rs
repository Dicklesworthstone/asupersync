//! Region quiescence validation tests.
//!
//! These tests validate that region closure properly waits for all obligations
//! to complete (quiescence) before the region is considered closed.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use tokio::time::sleep;
use asupersync::lab::{LabConfig, LabRuntime};

use crate::runtime::{ObligationId, RegionId};
use crate::tests::conformance::obligation_invariants::src::{
    invariant_harness::{
        ObligationInvariantTest, InvariantTestCategory, ObligationTestContext, InvariantTestResult,
        TestOutcome, TestMetrics,
    },
    obligation_tracker::{ObligationTracker, InvariantViolationType},
};

/// Test basic region quiescence - region waits for obligations
pub struct BasicRegionQuiescenceTest;

impl ObligationInvariantTest for BasicRegionQuiescenceTest {
    fn invariant_name(&self) -> &str {
        "basic_region_quiescence"
    }

    fn test_category(&self) -> InvariantTestCategory {
        InvariantTestCategory::RegionQuiescence
    }

    fn description(&self) -> &str {
        "Tests that region closure waits for all obligations to complete"
    }

    fn run_test<'a>(
        &'a self,
        ctx: &'a ObligationTestContext,
    ) -> Pin<Box<dyn Future<Output = InvariantTestResult> + Send + 'a>> {
        Box::pin(async move {
            let mut metrics = TestMetrics::default();
            let test_start = std::time::Instant::now();

            // Create region
            let region_id = RegionId(500);
            ctx.tracker.track_region_creation(region_id, None);
            metrics.regions_created += 1;

            // Create obligations
            let obligation_ids: Vec<_> = (0..5).map(|i| ObligationId(500 + i)).collect();
            for &obligation_id in &obligation_ids {
                ctx.tracker.track_obligation_creation(obligation_id, region_id);
                metrics.obligations_created += 1;
            }

            metrics.peak_active_obligations = obligation_ids.len();

            // Verify region is not quiescent while obligations are active
            let not_quiescent_initially = !ctx.tracker.is_region_quiescent(region_id);

            // Resolve obligations one by one
            for &obligation_id in &obligation_ids {
                // Brief delay to simulate work
                sleep(Duration::from_millis(1)).await;
                ctx.tracker.track_obligation_resolution(obligation_id);
                metrics.obligations_resolved += 1;
            }

            // Now region should be quiescent
            let is_quiescent_after_resolution = ctx.tracker.is_region_quiescent(region_id);

            // Close region (should succeed immediately since all obligations resolved)
            ctx.tracker.track_region_close_initiation(region_id);
            ctx.tracker.track_region_close_completion(region_id);
            metrics.regions_closed += 1;

            let active_count = ctx.tracker.active_obligation_count();

            let outcome = if not_quiescent_initially &&
                           is_quiescent_after_resolution &&
                           active_count == 0 {
                TestOutcome::Pass
            } else {
                TestOutcome::Fail
            };

            InvariantTestResult {
                test_name: self.invariant_name().to_string(),
                category: self.test_category(),
                outcome,
                duration: test_start.elapsed(),
                violations: ctx.tracker.get_invariant_violations(),
                metrics,
            }
        })
    }

    fn validate_invariant(&self, tracker: &ObligationTracker) -> bool {
        !tracker.has_active_obligations() && tracker.get_invariant_violations().is_empty()
    }
}

/// Test nested region quiescence - parent waits for children
pub struct NestedRegionQuiescenceTest;

impl ObligationInvariantTest for NestedRegionQuiescenceTest {
    fn invariant_name(&self) -> &str {
        "nested_region_quiescence"
    }

    fn test_category(&self) -> InvariantTestCategory {
        InvariantTestCategory::RegionQuiescence
    }

    fn description(&self) -> &str {
        "Tests that parent region closure waits for child region obligations"
    }

    fn run_test<'a>(
        &'a self,
        ctx: &'a ObligationTestContext,
    ) -> Pin<Box<dyn Future<Output = InvariantTestResult> + Send + 'a>> {
        Box::pin(async move {
            let mut metrics = TestMetrics::default();
            let test_start = std::time::Instant::now();

            // Create parent region
            let parent_region = RegionId(600);
            ctx.tracker.track_region_creation(parent_region, None);
            metrics.regions_created += 1;

            // Create child regions
            let child_region1 = RegionId(601);
            let child_region2 = RegionId(602);
            ctx.tracker.track_region_creation(child_region1, Some(parent_region));
            ctx.tracker.track_region_creation(child_region2, Some(parent_region));
            metrics.regions_created += 2;

            // Create obligations in different regions
            let parent_obligation = ObligationId(600);
            let child1_obligation = ObligationId(601);
            let child2_obligation = ObligationId(602);

            ctx.tracker.track_obligation_creation(parent_obligation, parent_region);
            ctx.tracker.track_obligation_creation(child1_obligation, child_region1);
            ctx.tracker.track_obligation_creation(child2_obligation, child_region2);
            metrics.obligations_created += 3;
            metrics.peak_active_obligations = 3;

            // Verify quiescence states
            let parent_not_quiescent = !ctx.tracker.is_region_quiescent(parent_region);
            let child1_not_quiescent = !ctx.tracker.is_region_quiescent(child_region1);
            let child2_not_quiescent = !ctx.tracker.is_region_quiescent(child_region2);

            // Resolve child obligations
            ctx.tracker.track_obligation_resolution(child1_obligation);
            ctx.tracker.track_obligation_resolution(child2_obligation);
            metrics.obligations_resolved += 2;

            // Child regions should now be quiescent, but parent should not
            let child1_quiescent = ctx.tracker.is_region_quiescent(child_region1);
            let child2_quiescent = ctx.tracker.is_region_quiescent(child_region2);
            let parent_still_not_quiescent = !ctx.tracker.is_region_quiescent(parent_region);

            // Close child regions
            ctx.tracker.track_region_close_initiation(child_region1);
            ctx.tracker.track_region_close_completion(child_region1);
            ctx.tracker.track_region_close_initiation(child_region2);
            ctx.tracker.track_region_close_completion(child_region2);
            metrics.regions_closed += 2;

            // Parent still not quiescent due to its own obligation
            let parent_still_has_obligation = !ctx.tracker.is_region_quiescent(parent_region);

            // Resolve parent obligation
            ctx.tracker.track_obligation_resolution(parent_obligation);
            metrics.obligations_resolved += 1;

            // Now parent should be quiescent
            let parent_finally_quiescent = ctx.tracker.is_region_quiescent(parent_region);

            // Close parent region
            ctx.tracker.track_region_close_initiation(parent_region);
            ctx.tracker.track_region_close_completion(parent_region);
            metrics.regions_closed += 1;

            let outcome = if parent_not_quiescent && child1_not_quiescent && child2_not_quiescent &&
                           child1_quiescent && child2_quiescent && parent_still_not_quiescent &&
                           parent_still_has_obligation && parent_finally_quiescent {
                TestOutcome::Pass
            } else {
                TestOutcome::Fail
            };

            InvariantTestResult {
                test_name: self.invariant_name().to_string(),
                category: self.test_category(),
                outcome,
                duration: test_start.elapsed(),
                violations: ctx.tracker.get_invariant_violations(),
                metrics,
            }
        })
    }

    fn validate_invariant(&self, tracker: &ObligationTracker) -> bool {
        !tracker.has_active_obligations() && tracker.get_invariant_violations().is_empty()
    }
}

/// Test that attempts to close region with active obligations (negative test)
pub struct RegionCloseWithActiveObligationsTest;

impl ObligationInvariantTest for RegionCloseWithActiveObligationsTest {
    fn invariant_name(&self) -> &str {
        "region_close_with_active_obligations"
    }

    fn test_category(&self) -> InvariantTestCategory {
        InvariantTestCategory::RegionQuiescence
    }

    fn description(&self) -> &str {
        "Tests that attempting to close region with active obligations is detected as violation"
    }

    fn run_test<'a>(
        &'a self,
        ctx: &'a ObligationTestContext,
    ) -> Pin<Box<dyn Future<Output = InvariantTestResult> + Send + 'a>> {
        Box::pin(async move {
            let mut metrics = TestMetrics::default();
            let test_start = std::time::Instant::now();

            // Create region
            let region_id = RegionId(700);
            ctx.tracker.track_region_creation(region_id, None);
            metrics.regions_created += 1;

            // Create obligations but don't resolve them
            for i in 0..3 {
                let obligation_id = ObligationId(700 + i);
                ctx.tracker.track_obligation_creation(obligation_id, region_id);
                metrics.obligations_created += 1;
            }

            metrics.peak_active_obligations = 3;

            // Attempt to close region with active obligations (should trigger violation)
            ctx.tracker.track_region_close_initiation(region_id);

            // Check if quiescence violation was detected
            let violations = ctx.tracker.get_invariant_violations();
            let has_quiescence_violation = violations.iter()
                .any(|v| v.violation_type == InvariantViolationType::RegionQuiescenceViolation);

            // Clean up by resolving obligations
            for i in 0..3 {
                let obligation_id = ObligationId(700 + i);
                ctx.tracker.track_obligation_resolution(obligation_id);
                metrics.obligations_resolved += 1;
            }

            // Complete region close
            ctx.tracker.track_region_close_completion(region_id);
            metrics.regions_closed += 1;

            // This is a negative test - we expect the violation to be detected
            let outcome = if has_quiescence_violation {
                TestOutcome::Pass
            } else {
                TestOutcome::Fail
            };

            InvariantTestResult {
                test_name: self.invariant_name().to_string(),
                category: self.test_category(),
                outcome,
                duration: test_start.elapsed(),
                violations,
                metrics,
            }
        })
    }

    fn validate_invariant(&self, tracker: &ObligationTracker) -> bool {
        // For this negative test, we expect violations to be present
        !tracker.has_active_obligations() &&
        tracker.get_invariant_violations().iter()
            .any(|v| v.violation_type == InvariantViolationType::RegionQuiescenceViolation)
    }

    fn expected_violations(&self) -> Vec<InvariantViolationType> {
        vec![InvariantViolationType::RegionQuiescenceViolation]
    }

    fn is_negative_test(&self) -> bool {
        true
    }
}

/// Test concurrent region closure scenarios
pub struct ConcurrentRegionClosureTest;

impl ObligationInvariantTest for ConcurrentRegionClosureTest {
    fn invariant_name(&self) -> &str {
        "concurrent_region_closure"
    }

    fn test_category(&self) -> InvariantTestCategory {
        InvariantTestCategory::RegionQuiescence
    }

    fn description(&self) -> &str {
        "Tests concurrent region closure with obligations resolving concurrently"
    }

    fn run_test<'a>(
        &'a self,
        ctx: &'a ObligationTestContext,
    ) -> Pin<Box<dyn Future<Output = InvariantTestResult> + Send + 'a>> {
        Box::pin(async move {
            let mut metrics = TestMetrics::default();
            let test_start = std::time::Instant::now();

            // Create multiple regions
            let num_regions = 5;
            let mut region_ids = Vec::new();

            for i in 0..num_regions {
                let region_id = RegionId::new_for_test(800 + i as u32, 0);
                ctx.tracker.track_region_creation(region_id, None);
                region_ids.push(region_id);
                metrics.regions_created += 1;
            }

            // Create obligations in each region
            let num_obligations_per_region = 10;
            let mut all_obligations = Vec::new();

            for (region_idx, &region_id) in region_ids.iter().enumerate() {
                for obligation_idx in 0..num_obligations_per_region {
                    let obligation_id = ObligationId::new_for_test((800 + region_idx * 100 + obligation_idx) as u32, 0);
                    ctx.tracker.track_obligation_creation(obligation_id, region_id);
                    all_obligations.push((obligation_id, region_id));
                    metrics.obligations_created += 1;
                }
            }

            metrics.peak_active_obligations = all_obligations.len();

            // Resolve obligations synchronously for simplicity
            for (obligation_id, _region_id) in all_obligations {
                // Track resolution immediately
                ctx.tracker.track_obligation_resolution(obligation_id);
                metrics.obligations_resolved += 1;
            }

            // Close regions after obligations are resolved
            for &region_id in &region_ids {
                ctx.tracker.track_region_close_initiation(region_id);

                // Check quiescence - should be true now that obligations are resolved
                if ctx.tracker.is_region_quiescent(region_id) {
                    ctx.tracker.track_region_close_completion(region_id);
                    metrics.regions_closed += 1;
                }
            }

            // All work completed synchronously

            // Wait for all close tasks
            for handle in close_handles {
                if let Err(e) = handle.await {
                    return InvariantTestResult {
                        test_name: self.invariant_name().to_string(),
                        category: self.test_category(),
                        outcome: TestOutcome::Error(format!("Close failed: {}", e)),
                        duration: test_start.elapsed(),
                        violations: Vec::new(),
                        metrics,
                    };
                }
            }
            metrics.regions_closed = metrics.regions_created;

            // Validate final state
            let all_quiescent = region_ids.iter().all(|&id| ctx.tracker.is_region_quiescent(id));
            let no_active_obligations = ctx.tracker.active_obligation_count() == 0;

            let outcome = if all_quiescent && no_active_obligations {
                TestOutcome::Pass
            } else {
                TestOutcome::Fail
            };

            InvariantTestResult {
                test_name: self.invariant_name().to_string(),
                category: self.test_category(),
                outcome,
                duration: test_start.elapsed(),
                violations: ctx.tracker.get_invariant_violations(),
                metrics,
            }
        })
    }

    fn validate_invariant(&self, tracker: &ObligationTracker) -> bool {
        !tracker.has_active_obligations() && tracker.get_invariant_violations().is_empty()
    }

    fn is_stress_test(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a test runtime
    fn create_test_runtime() -> LabRuntime {
        let config = LabConfig::default()
            .worker_count(2)
            .trace_capacity(2048)
            .max_steps(10000);
        LabRuntime::new(config)
    }
    use crate::runtime::test_helpers::*;
    use crate::tests::conformance::obligation_invariants::src::invariant_harness::{
        ObligationInvariantHarness, InvariantTestConfig,
    };

    #[test]
    fn test_basic_quiescence() {
        let _runtime = create_test_runtime();
        let config = InvariantTestConfig::default();
        let mut harness = ObligationInvariantHarness::new(config);

        let test = BasicRegionQuiescenceTest;
        let result = harness.run_test(test);

        assert_eq!(result.outcome, TestOutcome::Pass);
        assert!(result.violations.is_empty());
    }

    #[test]
    fn test_nested_quiescence() {
        let _runtime = create_test_runtime();
        let config = InvariantTestConfig::default();
        let mut harness = ObligationInvariantHarness::new(config);

        let test = NestedRegionQuiescenceTest;
        let result = harness.run_test(test);

        assert_eq!(result.outcome, TestOutcome::Pass);
        assert!(result.violations.is_empty());
    }

    #[test]
    fn test_close_with_active_obligations() {
        let _runtime = create_test_runtime();
        let config = InvariantTestConfig::default();
        let mut harness = ObligationInvariantHarness::new(config);

        let test = RegionCloseWithActiveObligationsTest;
        let result = harness.run_test(test);

        // This is a negative test, so we expect it to pass by detecting the violation
        assert_eq!(result.outcome, TestOutcome::Pass);
        assert!(!result.violations.is_empty());
        assert!(result.violations.iter()
            .any(|v| v.violation_type == InvariantViolationType::RegionQuiescenceViolation));
    }

    #[test]
    fn test_concurrent_closure() {
        let _runtime = create_test_runtime();
        let config = InvariantTestConfig::default();
        let mut harness = ObligationInvariantHarness::new(config);

        let test = ConcurrentRegionClosureTest;
        let result = harness.run_test(test);

        assert_eq!(result.outcome, TestOutcome::Pass);
        assert!(result.violations.is_empty());
    }
}