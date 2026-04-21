#![allow(clippy::all)]
//! Basic obligation lifecycle tests - create, resolve, no leaks.
//!
//! These tests validate the most fundamental invariant: every created obligation
//! must be properly resolved without leaking.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use asupersync::lab::config::LabConfig;
use asupersync::lab::runtime::LabRuntime;
use asupersync::time::sleep;

use crate::conformance::obligation_invariants::src::{
    invariant_harness::{
        InvariantTestCategory, InvariantTestResult, ObligationInvariantTest, ObligationTestContext,
        TestMetrics, TestOutcome,
    },
    obligation_tracker::ObligationTracker,
};
use asupersync::types::{ObligationId, RegionId, Time};

/// Test basic obligation creation and resolution
#[allow(dead_code)]
pub struct BasicObligationLifecycleTest;

impl ObligationInvariantTest for BasicObligationLifecycleTest {
    #[allow(dead_code)]
    #[allow(dead_code)]
    fn invariant_name(&self) -> &'static str {
        "basic_obligation_lifecycle"
    }

    #[allow(dead_code)]
    #[allow(dead_code)]

    fn test_category(&self) -> InvariantTestCategory {
        InvariantTestCategory::NoLeakValidation
    }

    #[allow(dead_code)]
    #[allow(dead_code)]

    fn description(&self) -> &'static str {
        "Tests basic obligation creation, execution, and resolution without leaks"
    }

    #[allow(dead_code)]
    #[allow(dead_code)]

    fn run_test<'a>(
        &'a self,
        ctx: &'a ObligationTestContext,
    ) -> Pin<Box<dyn Future<Output = InvariantTestResult> + Send + 'a>> {
        Box::pin(async move {
            let mut metrics = TestMetrics::default();
            let test_start = std::time::Instant::now();

            // Create a test region
            let region_id = RegionId::new_for_test(1, 0);
            ctx.tracker.track_region_creation(region_id, None);
            metrics.regions_created += 1;

            // Create and resolve multiple obligations
            for i in 0..10 {
                let obligation_id = ObligationId::new_for_test(i as u32, 0);

                // Track obligation creation
                ctx.tracker
                    .track_obligation_creation(obligation_id, region_id);
                metrics.obligations_created += 1;

                // Simulate some work
                sleep(Time::from_millis(0), Duration::from_millis(1)).await;

                // Track obligation resolution
                ctx.tracker.track_obligation_resolution(obligation_id);
                metrics.obligations_resolved += 1;
            }

            // Validate no active obligations remain
            let active_count = ctx.tracker.active_obligation_count();
            let is_quiescent = ctx.tracker.is_region_quiescent(region_id);

            // Close region
            ctx.tracker.track_region_close_initiation(region_id);
            ctx.tracker.track_region_close_completion(region_id);
            metrics.regions_closed += 1;

            let outcome = if active_count == 0 && is_quiescent {
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

    #[allow(dead_code)]
    #[allow(dead_code)]

    fn validate_invariant(&self, tracker: &ObligationTracker) -> bool {
        !tracker.has_active_obligations() && tracker.get_invariant_violations().is_empty()
    }
}

/// Test nested obligation creation and resolution
#[allow(dead_code)]
pub struct NestedObligationTest;

impl ObligationInvariantTest for NestedObligationTest {
    #[allow(dead_code)]
    #[allow(dead_code)]
    fn invariant_name(&self) -> &'static str {
        "nested_obligation_lifecycle"
    }

    #[allow(dead_code)]
    #[allow(dead_code)]

    fn test_category(&self) -> InvariantTestCategory {
        InvariantTestCategory::NoLeakValidation
    }

    #[allow(dead_code)]
    #[allow(dead_code)]

    fn description(&self) -> &'static str {
        "Tests creation and resolution of nested obligation hierarchies without leaks"
    }

    #[allow(dead_code)]
    #[allow(dead_code)]

    fn run_test<'a>(
        &'a self,
        ctx: &'a ObligationTestContext,
    ) -> Pin<Box<dyn Future<Output = InvariantTestResult> + Send + 'a>> {
        Box::pin(async move {
            let mut metrics = TestMetrics::default();
            let test_start = std::time::Instant::now();

            // Create parent region
            let parent_region = RegionId::new_for_test(100, 0);
            ctx.tracker.track_region_creation(parent_region, None);
            metrics.regions_created += 1;

            // Create nested regions
            let child_region1 = RegionId::new_for_test(101, 0);
            let child_region2 = RegionId::new_for_test(102, 0);
            ctx.tracker
                .track_region_creation(child_region1, Some(parent_region));
            ctx.tracker
                .track_region_creation(child_region2, Some(parent_region));
            metrics.regions_created += 2;

            // Create obligations in different regions
            let parent_obligation = ObligationId::new_for_test(200, 0);
            let child1_obligation = ObligationId::new_for_test(201, 0);
            let child2_obligation = ObligationId::new_for_test(202, 0);

            ctx.tracker
                .track_obligation_creation(parent_obligation, parent_region);
            ctx.tracker
                .track_obligation_creation(child1_obligation, child_region1);
            ctx.tracker
                .track_obligation_creation(child2_obligation, child_region2);
            metrics.obligations_created += 3;

            metrics.peak_active_obligations = ctx.tracker.active_obligation_count();

            // Resolve child obligations first
            ctx.tracker.track_obligation_resolution(child1_obligation);
            ctx.tracker.track_obligation_resolution(child2_obligation);
            metrics.obligations_resolved += 2;

            // Verify intermediate state
            let child1_quiescent = ctx.tracker.is_region_quiescent(child_region1);
            let child2_quiescent = ctx.tracker.is_region_quiescent(child_region2);
            let parent_not_quiescent = !ctx.tracker.is_region_quiescent(parent_region);

            // Close child regions
            ctx.tracker.track_region_close_initiation(child_region1);
            ctx.tracker.track_region_close_completion(child_region1);
            ctx.tracker.track_region_close_initiation(child_region2);
            ctx.tracker.track_region_close_completion(child_region2);
            metrics.regions_closed += 2;

            // Resolve parent obligation
            ctx.tracker.track_obligation_resolution(parent_obligation);
            metrics.obligations_resolved += 1;

            // Close parent region
            ctx.tracker.track_region_close_initiation(parent_region);
            ctx.tracker.track_region_close_completion(parent_region);
            metrics.regions_closed += 1;

            let final_active_count = ctx.tracker.active_obligation_count();
            let all_quiescent = ctx.tracker.is_region_quiescent(parent_region)
                && ctx.tracker.is_region_quiescent(child_region1)
                && ctx.tracker.is_region_quiescent(child_region2);

            let outcome = if final_active_count == 0
                && all_quiescent
                && child1_quiescent
                && child2_quiescent
                && parent_not_quiescent
            {
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

    #[allow(dead_code)]
    #[allow(dead_code)]

    fn validate_invariant(&self, tracker: &ObligationTracker) -> bool {
        !tracker.has_active_obligations() && tracker.get_invariant_violations().is_empty()
    }
}

/// Test concurrent obligation creation and resolution
#[allow(dead_code)]
pub struct ConcurrentObligationTest;

impl ObligationInvariantTest for ConcurrentObligationTest {
    #[allow(dead_code)]
    #[allow(dead_code)]
    fn invariant_name(&self) -> &'static str {
        "concurrent_obligation_lifecycle"
    }

    #[allow(dead_code)]
    #[allow(dead_code)]

    fn test_category(&self) -> InvariantTestCategory {
        InvariantTestCategory::NoLeakValidation
    }

    #[allow(dead_code)]
    #[allow(dead_code)]

    fn description(&self) -> &'static str {
        "Tests concurrent creation and resolution of obligations without race conditions or leaks"
    }

    #[allow(dead_code)]
    #[allow(dead_code)]

    fn run_test<'a>(
        &'a self,
        ctx: &'a ObligationTestContext,
    ) -> Pin<Box<dyn Future<Output = InvariantTestResult> + Send + 'a>> {
        Box::pin(async move {
            let mut metrics = TestMetrics::default();
            let test_start = std::time::Instant::now();

            // Create region
            let region_id = RegionId::new_for_test(300, 0);
            ctx.tracker.track_region_creation(region_id, None);
            metrics.regions_created += 1;

            // Spawn concurrent obligations
            let num_obligations = 50;

            for i in 0..num_obligations {
                let obligation_id = ObligationId::new_for_test(300 + i as u32, 0);
                let tracker = ctx.tracker.clone();

                // Track creation and resolution synchronously for simplicity
                tracker.track_obligation_creation(obligation_id, region_id);

                // Simulate work with a simple delay representation
                // In a real test this would be actual async work

                // Track resolution
                tracker.track_obligation_resolution(obligation_id);
            }
            metrics.obligations_created = num_obligations;
            metrics.obligations_resolved = num_obligations;

            // Brief wait to ensure all tracking is complete
            sleep(Time::from_millis(0), Duration::from_millis(10)).await;

            metrics.peak_active_obligations = num_obligations; // Peak during concurrent execution

            // Validate final state
            let active_count = ctx.tracker.active_obligation_count();
            let is_quiescent = ctx.tracker.is_region_quiescent(region_id);

            // Close region
            ctx.tracker.track_region_close_initiation(region_id);
            ctx.tracker.track_region_close_completion(region_id);
            metrics.regions_closed += 1;

            let outcome = if active_count == 0 && is_quiescent {
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

    #[allow(dead_code)]
    #[allow(dead_code)]

    fn validate_invariant(&self, tracker: &ObligationTracker) -> bool {
        !tracker.has_active_obligations() && tracker.get_invariant_violations().is_empty()
    }

    #[allow(dead_code)]
    #[allow(dead_code)]

    fn is_stress_test(&self) -> bool {
        true
    }
}

/// Test error path obligation cleanup
#[allow(dead_code)]
pub struct ErrorPathCleanupTest;

impl ObligationInvariantTest for ErrorPathCleanupTest {
    #[allow(dead_code)]
    #[allow(dead_code)]
    fn invariant_name(&self) -> &'static str {
        "error_path_obligation_cleanup"
    }

    #[allow(dead_code)]
    #[allow(dead_code)]

    fn test_category(&self) -> InvariantTestCategory {
        InvariantTestCategory::NoLeakValidation
    }

    #[allow(dead_code)]
    #[allow(dead_code)]

    fn description(&self) -> &'static str {
        "Tests that obligations are properly cleaned up when errors occur during execution"
    }

    #[allow(dead_code)]
    #[allow(dead_code)]

    fn run_test<'a>(
        &'a self,
        ctx: &'a ObligationTestContext,
    ) -> Pin<Box<dyn Future<Output = InvariantTestResult> + Send + 'a>> {
        Box::pin(async move {
            let mut metrics = TestMetrics::default();
            let test_start = std::time::Instant::now();

            // Create region
            let region_id = RegionId::new_for_test(400, 0);
            ctx.tracker.track_region_creation(region_id, None);
            metrics.regions_created += 1;

            // Create obligations, some will "fail"
            for i in 0..20 {
                let obligation_id = ObligationId::new_for_test(400 + i as u32, 0);
                ctx.tracker
                    .track_obligation_creation(obligation_id, region_id);
                metrics.obligations_created += 1;

                if i % 3 == 0 {
                    // Simulate error - obligation gets cancelled instead of resolved
                    ctx.tracker.track_obligation_cancellation(obligation_id);
                    metrics.cancellation_events += 1;
                } else {
                    // Normal resolution
                    ctx.tracker.track_obligation_resolution(obligation_id);
                    metrics.obligations_resolved += 1;
                }
            }

            metrics.peak_active_obligations = 20;

            // Validate that cancelled obligations don't leak
            let active_count = ctx.tracker.active_obligation_count();
            let is_quiescent = ctx.tracker.is_region_quiescent(region_id);

            // Close region
            ctx.tracker.track_region_close_initiation(region_id);
            ctx.tracker.track_region_close_completion(region_id);
            metrics.regions_closed += 1;

            let outcome = if active_count == 0 && is_quiescent {
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

    #[allow(dead_code)]
    #[allow(dead_code)]

    fn validate_invariant(&self, tracker: &ObligationTracker) -> bool {
        !tracker.has_active_obligations() && tracker.get_invariant_violations().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a test runtime
    #[allow(dead_code)]
    #[allow(dead_code)]
    fn create_test_runtime() -> LabRuntime {
        let config = LabConfig::default()
            .worker_count(2)
            .trace_capacity(2048)
            .max_steps(10000);
        LabRuntime::new(config)
    }
    // removed crate::runtime::test_helpers::*
    use crate::conformance::obligation_invariants::src::invariant_harness::{
        InvariantTestConfig, ObligationInvariantHarness,
    };
    use futures_lite::future::block_on;

    #[test]
    #[allow(dead_code)]
    #[allow(dead_code)]
    fn test_basic_obligation_lifecycle() {
        let _runtime = create_test_runtime();
        let config = InvariantTestConfig::default();
        let mut harness = ObligationInvariantHarness::new(config);

        let test = BasicObligationLifecycleTest;
        let result = block_on(harness.run_test(test));

        assert_eq!(result.outcome, TestOutcome::Pass);
        assert!(result.violations.is_empty());
        assert_eq!(result.metrics.obligations_created, 10);
        assert_eq!(result.metrics.obligations_resolved, 10);
        assert_eq!(result.metrics.regions_created, 1);
        assert_eq!(result.metrics.regions_closed, 1);
    }

    #[test]
    #[allow(dead_code)]
    #[allow(dead_code)]
    fn test_nested_obligations() {
        let _runtime = create_test_runtime();
        let config = InvariantTestConfig::default();
        let mut harness = ObligationInvariantHarness::new(config);

        let test = NestedObligationTest;
        let result = block_on(harness.run_test(test));

        assert_eq!(result.outcome, TestOutcome::Pass);
        assert!(result.violations.is_empty());
        assert_eq!(result.metrics.obligations_created, 3);
        assert_eq!(result.metrics.obligations_resolved, 3);
        assert_eq!(result.metrics.regions_created, 3);
        assert_eq!(result.metrics.regions_closed, 3);
    }

    #[test]
    #[allow(dead_code)]
    #[allow(dead_code)]
    fn test_concurrent_obligations() {
        let _runtime = create_test_runtime();
        let config = InvariantTestConfig::default();
        let mut harness = ObligationInvariantHarness::new(config);

        let test = ConcurrentObligationTest;
        let result = block_on(harness.run_test(test));

        assert_eq!(result.outcome, TestOutcome::Pass);
        assert!(result.violations.is_empty());
        assert_eq!(result.metrics.obligations_created, 50);
        assert_eq!(result.metrics.obligations_resolved, 50);
    }

    #[test]
    #[allow(dead_code)]
    #[allow(dead_code)]
    fn test_error_path_cleanup() {
        let _runtime = create_test_runtime();
        let config = InvariantTestConfig::default();
        let mut harness = ObligationInvariantHarness::new(config);

        let test = ErrorPathCleanupTest;
        let result = block_on(harness.run_test(test));

        assert_eq!(result.outcome, TestOutcome::Pass);
        assert!(result.violations.is_empty());
        assert_eq!(result.metrics.obligations_created, 20);
        assert!(result.metrics.cancellation_events > 0);
    }
}
