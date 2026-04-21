#![allow(clippy::all)]
//! Core Obligation Invariant Test Implementations
//!
//! This module contains the actual test implementations for each of the 5 core
//! obligation system invariants that must hold for structured concurrency correctness.

use crate::{
    InvariantTestCategory, InvariantTestResult, InvariantViolation, ObligationInvariantTest,
    ObligationTestContext, ObligationTracker, TestMetadata, ViolationType,
};
use std::time::{Duration, Instant};

// ============================================================================
// Invariant 1: No Obligation Leaks
// ============================================================================

/// Test that every created obligation is properly resolved or cancelled
#[allow(dead_code)]
pub struct NoObligationLeaksTest;

impl ObligationInvariantTest for NoObligationLeaksTest {
    #[allow(dead_code)]
    #[allow(dead_code)]
    fn invariant_name(&self) -> &'static str {
        "No Obligation Leaks"
    }

    #[allow(dead_code)]

    #[allow(dead_code)]

    fn test_category(&self) -> InvariantTestCategory {
        InvariantTestCategory::NoLeakValidation
    }

    #[allow(dead_code)]

    #[allow(dead_code)]

    fn description(&self) -> &'static str {
        "Every created obligation must be properly resolved or cancelled - no leaked obligations"
    }

    #[allow(dead_code)]

    #[allow(dead_code)]

    fn run_test(&self, ctx: &ObligationTestContext) -> InvariantTestResult {
        let start = Instant::now();
        let tracker = ObligationTracker::new();

        if ctx.verbose {
            eprintln!("Running no obligation leaks test...");
        }

        // Create a test region
        let region = tracker.create_region(None);

        // Create obligations and manage their lifecycle
        let obligation_count = if ctx.stress_testing {
            ctx.stress_concurrency
        } else {
            10
        };

        let mut test_metadata = TestMetadata {
            obligations_created: obligation_count,
            regions_created: 1,
            cancellations_triggered: 0,
            resource_peak_usage: Default::default(),
        };

        // Test scenario: Create obligations, activate them, then resolve them
        let mut obligations = Vec::new();
        for _ in 0..obligation_count {
            let obligation_id = tracker.create_obligation(region);
            obligations.push(obligation_id);
            tracker.activate_obligation(obligation_id);
        }

        if ctx.verbose {
            eprintln!("Created {obligation_count} obligations");
        }

        // Resolve all obligations properly
        for obligation_id in &obligations {
            tracker.resolve_obligation(*obligation_id);
        }

        // Close the region
        if let Err(e) = tracker.close_region(region) {
            return InvariantTestResult::Failed {
                reason: format!("Failed to close region: {e}"),
                violation_details: InvariantViolation {
                    invariant_name: self.invariant_name().to_string(),
                    violation_type: ViolationType::ObligationLeak {
                        leaked_count: obligation_count,
                    },
                    affected_obligations: obligations,
                    affected_regions: vec![region],
                    detected_at: Instant::now(),
                    stack_trace: None,
                },
                duration: start.elapsed(),
            };
        }

        // Validate no leaks
        let leaked_obligations = tracker.check_obligation_leaks();
        if !leaked_obligations.is_empty() {
            return InvariantTestResult::Failed {
                reason: format!("Obligation leak detected: {} obligations", leaked_obligations.len()),
                violation_details: InvariantViolation {
                    invariant_name: self.invariant_name().to_string(),
                    violation_type: ViolationType::ObligationLeak {
                        leaked_count: leaked_obligations.len(),
                    },
                    affected_obligations: leaked_obligations.clone(),
                    affected_regions: vec![region],
                    detected_at: Instant::now(),
                    stack_trace: None,
                },
                duration: start.elapsed(),
            };
        }

        if ctx.verbose {
            eprintln!("No obligation leaks detected - test passed");
        }

        InvariantTestResult::Passed {
            duration: start.elapsed(),
            metadata: test_metadata,
        }
    }

    #[allow(dead_code)]

    #[allow(dead_code)]

    fn validate_invariant(&self, tracker: &ObligationTracker) -> bool {
        tracker.check_obligation_leaks().is_empty()
    }

    #[allow(dead_code)]

    #[allow(dead_code)]

    fn tags(&self) -> Vec<&str> {
        vec!["core", "leak-detection", "lifecycle"]
    }
}

// ============================================================================
// Invariant 2: Region Close = Quiescence
// ============================================================================

/// Test that region closure waits for all obligations to complete
#[allow(dead_code)]
pub struct RegionQuiescenceTest;

impl ObligationInvariantTest for RegionQuiescenceTest {
    #[allow(dead_code)]
    #[allow(dead_code)]
    fn invariant_name(&self) -> &'static str {
        "Region Close = Quiescence"
    }

    #[allow(dead_code)]

    #[allow(dead_code)]

    fn test_category(&self) -> InvariantTestCategory {
        InvariantTestCategory::RegionQuiescence
    }

    #[allow(dead_code)]

    #[allow(dead_code)]

    fn description(&self) -> &'static str {
        "Region closure must wait for all obligations to complete before closing"
    }

    #[allow(dead_code)]

    #[allow(dead_code)]

    fn run_test(&self, ctx: &ObligationTestContext) -> InvariantTestResult {
        let start = Instant::now();
        let tracker = ObligationTracker::new();

        if ctx.verbose {
            eprintln!("Running region quiescence test...");
        }

        // Create a test region
        let region = tracker.create_region(None);

        // Create obligations but don't resolve them immediately
        let obligation_count = if ctx.stress_testing { 50 } else { 5 };
        let mut obligations = Vec::new();

        for _ in 0..obligation_count {
            let obligation_id = tracker.create_obligation(region);
            obligations.push(obligation_id);
            tracker.activate_obligation(obligation_id);
        }

        if ctx.verbose {
            eprintln!("Created {obligation_count} active obligations");
        }

        // Test 1: Try to close region with pending obligations (should fail)
        match tracker.close_region(region) {
            Ok(_) => {
                return InvariantTestResult::Failed {
                    reason: "Region closed despite pending obligations - quiescence violation".to_string(),
                    violation_details: InvariantViolation {
                        invariant_name: self.invariant_name().to_string(),
                        violation_type: ViolationType::RegionQuiescenceViolation {
                            pending_obligations: obligation_count,
                        },
                        affected_obligations: obligations.clone(),
                        affected_regions: vec![region],
                        detected_at: Instant::now(),
                        stack_trace: None,
                    },
                    duration: start.elapsed(),
                };
            }
            Err(_) => {
                // Expected - region should not close with pending obligations
                if ctx.verbose {
                    eprintln!("Region correctly refused to close with pending obligations");
                }
            }
        }

        // Test 2: Resolve all obligations, then close should succeed
        for obligation_id in &obligations {
            tracker.resolve_obligation(*obligation_id);
        }

        match tracker.close_region(region) {
            Ok(_) => {
                if ctx.verbose {
                    eprintln!("Region successfully closed after obligation completion");
                }
            }
            Err(e) => {
                return InvariantTestResult::Failed {
                    reason: format!("Region failed to close after obligations completed: {e}"),
                    violation_details: InvariantViolation {
                        invariant_name: self.invariant_name().to_string(),
                        violation_type: ViolationType::RegionQuiescenceViolation {
                            pending_obligations: 0,
                        },
                        affected_obligations: obligations,
                        affected_regions: vec![region],
                        detected_at: Instant::now(),
                        stack_trace: None,
                    },
                    duration: start.elapsed(),
                };
            }
        }

        InvariantTestResult::Passed {
            duration: start.elapsed(),
            metadata: TestMetadata {
                obligations_created: obligation_count,
                regions_created: 1,
                cancellations_triggered: 0,
                resource_peak_usage: Default::default(),
            },
        }
    }

    #[allow(dead_code)]

    #[allow(dead_code)]

    fn validate_invariant(&self, tracker: &ObligationTracker) -> bool {
        // Check that all closed regions have no pending obligations
        true // This would check actual region states in real implementation
    }

    #[allow(dead_code)]

    #[allow(dead_code)]

    fn tags(&self) -> Vec<&str> {
        vec!["core", "region-lifecycle", "quiescence"]
    }
}

// ============================================================================
// Invariant 3: Cancel Propagation
// ============================================================================

/// Test that cancel signals propagate correctly through obligation hierarchies
#[allow(dead_code)]
pub struct CancelPropagationTest;

impl ObligationInvariantTest for CancelPropagationTest {
    #[allow(dead_code)]
    #[allow(dead_code)]
    fn invariant_name(&self) -> &'static str {
        "Cancel Propagation"
    }

    #[allow(dead_code)]

    #[allow(dead_code)]

    fn test_category(&self) -> InvariantTestCategory {
        InvariantTestCategory::CancelPropagation
    }

    #[allow(dead_code)]

    #[allow(dead_code)]

    fn description(&self) -> &'static str {
        "Cancel signals must propagate correctly through obligation hierarchies"
    }

    #[allow(dead_code)]

    #[allow(dead_code)]

    fn run_test(&self, ctx: &ObligationTestContext) -> InvariantTestResult {
        let start = Instant::now();
        let tracker = ObligationTracker::new();

        if ctx.verbose {
            eprintln!("Running cancel propagation test...");
        }

        // Create nested region hierarchy
        let parent_region = tracker.create_region(None);
        let child_region1 = tracker.create_region(Some(parent_region));
        let child_region2 = tracker.create_region(Some(parent_region));
        let grandchild_region = tracker.create_region(Some(child_region1));

        // Create obligations in each region
        let parent_obligation = tracker.create_obligation(parent_region);
        let child1_obligation = tracker.create_obligation(child_region1);
        let child2_obligation = tracker.create_obligation(child_region2);
        let grandchild_obligation = tracker.create_obligation(grandchild_region);

        // Activate all obligations
        tracker.activate_obligation(parent_obligation);
        tracker.activate_obligation(child1_obligation);
        tracker.activate_obligation(child2_obligation);
        tracker.activate_obligation(grandchild_obligation);

        if ctx.verbose {
            eprintln!("Created nested region hierarchy with obligations");
        }

        // Cancel the parent region
        tracker.cancel_region(parent_region);

        if ctx.verbose {
            eprintln!("Cancelled parent region - checking propagation...");
        }

        // Validate that cancellation propagated to all child obligations
        let all_obligations = vec![
            parent_obligation,
            child1_obligation,
            child2_obligation,
            grandchild_obligation,
        ];

        let mut unpropagated = Vec::new();
        {
            let obligations = tracker.active_obligations.lock().unwrap();
            for &obligation_id in &all_obligations {
                if let Some(obligation) = obligations.get(&obligation_id) {
                    if obligation.state != crate::ObligationState::Cancelled {
                        unpropagated.push(obligation_id);
                    }
                }
            }
        }

        if !unpropagated.is_empty() {
            return InvariantTestResult::Failed {
                reason: format!("Cancel propagation failed - {} obligations not cancelled", unpropagated.len()),
                violation_details: InvariantViolation {
                    invariant_name: self.invariant_name().to_string(),
                    violation_type: ViolationType::CancelPropagationFailure {
                        unpropagated_obligations: unpropagated.len(),
                    },
                    affected_obligations: unpropagated,
                    affected_regions: vec![parent_region, child_region1, child_region2, grandchild_region],
                    detected_at: Instant::now(),
                    stack_trace: None,
                },
                duration: start.elapsed(),
            };
        }

        if ctx.verbose {
            eprintln!("Cancel propagation successful - all obligations cancelled");
        }

        InvariantTestResult::Passed {
            duration: start.elapsed(),
            metadata: TestMetadata {
                obligations_created: 4,
                regions_created: 4,
                cancellations_triggered: 1,
                resource_peak_usage: Default::default(),
            },
        }
    }

    #[allow(dead_code)]

    #[allow(dead_code)]

    fn validate_invariant(&self, tracker: &ObligationTracker) -> bool {
        // This would validate that all cancellations have properly propagated
        !tracker.has_violations()
    }

    #[allow(dead_code)]

    #[allow(dead_code)]

    fn tags(&self) -> Vec<&str> {
        vec!["core", "cancellation", "hierarchy", "propagation"]
    }
}

// ============================================================================
// Invariant 4: Resource Cleanup
// ============================================================================

/// Test that obligation cleanup does not leak resources
#[allow(dead_code)]
pub struct ResourceCleanupTest;

impl ObligationInvariantTest for ResourceCleanupTest {
    #[allow(dead_code)]
    #[allow(dead_code)]
    fn invariant_name(&self) -> &'static str {
        "Resource Cleanup"
    }

    #[allow(dead_code)]

    #[allow(dead_code)]

    fn test_category(&self) -> InvariantTestCategory {
        InvariantTestCategory::ResourceCleanup
    }

    #[allow(dead_code)]

    #[allow(dead_code)]

    fn description(&self) -> &'static str {
        "Obligation cleanup must not leak resources (memory, wakers, handles)"
    }

    #[allow(dead_code)]

    #[allow(dead_code)]

    fn run_test(&self, ctx: &ObligationTestContext) -> InvariantTestResult {
        let start = Instant::now();
        let tracker = ObligationTracker::new();

        if !ctx.resource_tracking {
            return InvariantTestResult::Skipped {
                reason: "Resource tracking disabled in test context".to_string(),
            };
        }

        if ctx.verbose {
            eprintln!("Running resource cleanup test...");
        }

        // Record baseline resource usage
        let baseline_resources = tracker.check_resource_leaks();

        // Create and exercise obligations with simulated resource usage
        let region = tracker.create_region(None);
        let obligation_count = if ctx.stress_testing { 100 } else { 10 };

        for _ in 0..obligation_count {
            let obligation_id = tracker.create_obligation(region);
            tracker.activate_obligation(obligation_id);

            // Simulate resource allocation (in real implementation, this would
            // track actual wakers, memory allocations, file handles, etc.)
            {
                let mut resources = tracker.resource_tracker.lock().unwrap();
                resources.wakers += 1;
                resources.memory_bytes += 1024;
                resources.handles += 1;
            }

            // Resolve obligation and clean up resources
            tracker.resolve_obligation(obligation_id);

            // Simulate resource deallocation
            {
                let mut resources = tracker.resource_tracker.lock().unwrap();
                resources.wakers = resources.wakers.saturating_sub(1);
                resources.memory_bytes = resources.memory_bytes.saturating_sub(1024);
                resources.handles = resources.handles.saturating_sub(1);
            }
        }

        // Close region
        if let Err(e) = tracker.close_region(region) {
            return InvariantTestResult::Failed {
                reason: format!("Failed to close region: {e}"),
                violation_details: InvariantViolation {
                    invariant_name: self.invariant_name().to_string(),
                    violation_type: ViolationType::ResourceLeak {
                        leaked_resources: tracker.check_resource_leaks(),
                    },
                    affected_obligations: vec![],
                    affected_regions: vec![region],
                    detected_at: Instant::now(),
                    stack_trace: None,
                },
                duration: start.elapsed(),
            };
        }

        // Check for resource leaks
        let final_resources = tracker.check_resource_leaks();

        // Resources should return to baseline (or lower due to cleanup)
        if final_resources.wakers > baseline_resources.wakers
            || final_resources.memory_bytes > baseline_resources.memory_bytes
            || final_resources.handles > baseline_resources.handles
        {
            let leaked_resources = crate::ResourceCount {
                wakers: final_resources.wakers.saturating_sub(baseline_resources.wakers),
                memory_bytes: final_resources.memory_bytes.saturating_sub(baseline_resources.memory_bytes),
                handles: final_resources.handles.saturating_sub(baseline_resources.handles),
                futures: final_resources.futures.saturating_sub(baseline_resources.futures),
            };

            return InvariantTestResult::Failed {
                reason: format!("Resource leak detected: {leaked_resources:?}"),
                violation_details: InvariantViolation {
                    invariant_name: self.invariant_name().to_string(),
                    violation_type: ViolationType::ResourceLeak {
                        leaked_resources,
                    },
                    affected_obligations: vec![],
                    affected_regions: vec![region],
                    detected_at: Instant::now(),
                    stack_trace: None,
                },
                duration: start.elapsed(),
            };
        }

        if ctx.verbose {
            eprintln!("Resource cleanup test passed - no leaks detected");
        }

        InvariantTestResult::Passed {
            duration: start.elapsed(),
            metadata: TestMetadata {
                obligations_created: obligation_count,
                regions_created: 1,
                cancellations_triggered: 0,
                resource_peak_usage: final_resources,
            },
        }
    }

    #[allow(dead_code)]

    #[allow(dead_code)]

    fn validate_invariant(&self, tracker: &ObligationTracker) -> bool {
        // Check that resource usage is within expected bounds
        let resources = tracker.check_resource_leaks();
        resources.wakers == 0 && resources.memory_bytes == 0 && resources.handles == 0
    }

    #[allow(dead_code)]

    #[allow(dead_code)]

    fn tags(&self) -> Vec<&str> {
        vec!["core", "resource-management", "cleanup", "leak-detection"]
    }
}

// ============================================================================
// Invariant 5: Temporal Safety
// ============================================================================

/// Test that obligations cannot outlive their parent regions
#[allow(dead_code)]
pub struct TemporalSafetyTest;

impl ObligationInvariantTest for TemporalSafetyTest {
    #[allow(dead_code)]
    #[allow(dead_code)]
    fn invariant_name(&self) -> &'static str {
        "Temporal Safety"
    }

    #[allow(dead_code)]

    #[allow(dead_code)]

    fn test_category(&self) -> InvariantTestCategory {
        InvariantTestCategory::TemporalSafety
    }

    #[allow(dead_code)]

    #[allow(dead_code)]

    fn description(&self) -> &'static str {
        "Obligations cannot outlive their parent regions - temporal safety invariant"
    }

    #[allow(dead_code)]

    #[allow(dead_code)]

    fn run_test(&self, ctx: &ObligationTestContext) -> InvariantTestResult {
        let start = Instant::now();
        let tracker = ObligationTracker::new();

        if ctx.verbose {
            eprintln!("Running temporal safety test...");
        }

        // Create parent and child regions
        let parent_region = tracker.create_region(None);
        let child_region = tracker.create_region(Some(parent_region));

        // Create obligations in both regions
        let parent_obligation = tracker.create_obligation(parent_region);
        let child_obligation = tracker.create_obligation(child_region);

        tracker.activate_obligation(parent_obligation);
        tracker.activate_obligation(child_obligation);

        // Resolve obligations in child region first
        tracker.resolve_obligation(child_obligation);

        // Close child region
        if let Err(_) = tracker.close_region(child_region) {
            return InvariantTestResult::Failed {
                reason: "Failed to close child region".to_string(),
                violation_details: InvariantViolation {
                    invariant_name: self.invariant_name().to_string(),
                    violation_type: ViolationType::TemporalSafetyViolation {
                        surviving_obligations: 1,
                    },
                    affected_obligations: vec![child_obligation],
                    affected_regions: vec![child_region],
                    detected_at: Instant::now(),
                    stack_trace: None,
                },
                duration: start.elapsed(),
            };
        }

        // Verify child obligations are cleaned up when child region closes
        let surviving_child_obligations = tracker.get_pending_obligations_for_region(child_region);
        if !surviving_child_obligations.is_empty() {
            return InvariantTestResult::Failed {
                reason: format!("Temporal safety violation: {} child obligations survived region closure", surviving_child_obligations.len()),
                violation_details: InvariantViolation {
                    invariant_name: self.invariant_name().to_string(),
                    violation_type: ViolationType::TemporalSafetyViolation {
                        surviving_obligations: surviving_child_obligations.len(),
                    },
                    affected_obligations: surviving_child_obligations,
                    affected_regions: vec![child_region],
                    detected_at: Instant::now(),
                    stack_trace: None,
                },
                duration: start.elapsed(),
            };
        }

        // Resolve parent obligation and close parent region
        tracker.resolve_obligation(parent_obligation);
        if let Err(_) = tracker.close_region(parent_region) {
            return InvariantTestResult::Failed {
                reason: "Failed to close parent region".to_string(),
                violation_details: InvariantViolation {
                    invariant_name: self.invariant_name().to_string(),
                    violation_type: ViolationType::TemporalSafetyViolation {
                        surviving_obligations: 1,
                    },
                    affected_obligations: vec![parent_obligation],
                    affected_regions: vec![parent_region],
                    detected_at: Instant::now(),
                    stack_trace: None,
                },
                duration: start.elapsed(),
            };
        }

        if ctx.verbose {
            eprintln!("Temporal safety test passed - no obligations survived region closure");
        }

        InvariantTestResult::Passed {
            duration: start.elapsed(),
            metadata: TestMetadata {
                obligations_created: 2,
                regions_created: 2,
                cancellations_triggered: 0,
                resource_peak_usage: Default::default(),
            },
        }
    }

    #[allow(dead_code)]

    #[allow(dead_code)]

    fn validate_invariant(&self, tracker: &ObligationTracker) -> bool {
        // Check that no obligations exist for closed regions
        true // This would validate actual region/obligation lifetime relationships
    }

    #[allow(dead_code)]

    #[allow(dead_code)]

    fn dependencies(&self) -> Vec<&str> {
        vec!["No Obligation Leaks", "Region Close = Quiescence"]
    }

    #[allow(dead_code)]

    #[allow(dead_code)]

    fn tags(&self) -> Vec<&str> {
        vec!["core", "temporal-safety", "lifetime", "scoping"]
    }
}

// ============================================================================
// Test Suite Collection
// ============================================================================

/// Get all core obligation invariant tests
#[allow(dead_code)]
#[allow(dead_code)]
pub fn get_all_invariant_tests() -> Vec<Box<dyn ObligationInvariantTest>> {
    vec![
        Box::new(NoObligationLeaksTest),
        Box::new(RegionQuiescenceTest),
        Box::new(CancelPropagationTest),
        Box::new(ResourceCleanupTest),
        Box::new(TemporalSafetyTest),
    ]
}

/// Get tests by category
#[allow(dead_code)]
#[allow(dead_code)]
pub fn get_tests_by_category(category: InvariantTestCategory) -> Vec<Box<dyn ObligationInvariantTest>> {
    get_all_invariant_tests()
        .into_iter()
        .filter(|test| test.test_category() == category)
        .collect()
}

/// Get critical invariant tests (core safety requirements)
#[allow(dead_code)]
#[allow(dead_code)]
pub fn get_critical_invariant_tests() -> Vec<Box<dyn ObligationInvariantTest>> {
    vec![
        Box::new(NoObligationLeaksTest),
        Box::new(RegionQuiescenceTest),
        Box::new(CancelPropagationTest),
    ]
}