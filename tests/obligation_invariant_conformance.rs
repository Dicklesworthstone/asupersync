//! Integration test for obligation invariant conformance.
//!
//! This test validates all structured concurrency obligation invariants
//! to ensure the runtime maintains correctness guarantees.

use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::types::{Budget, ObligationId, RegionId};
use asupersync::util::ArenaIndex;

#[path = "conformance/mod.rs"]
mod conformance;

use conformance::obligation_invariants::{
    ObligationTracker, InvariantViolationType, ResourceHandle, WakerHandle,
};

/// Helper to create a test runtime for conformance testing
fn create_test_runtime() -> LabRuntime {
    let config = LabConfig::default()
        .worker_count(2)
        .trace_capacity(2048)
        .max_steps(10000);
    LabRuntime::new(config)
}

#[test]
fn test_basic_obligation_lifecycle_conformance() {
    let mut runtime = create_test_runtime();
    let tracker = ObligationTracker::new();

    // Create region
    let root_region = runtime.state.create_root_region(Budget::INFINITE);
    tracker.track_region_creation(root_region, None);

    // Test basic obligation lifecycle
    for i in 0..5 {
        let obligation_id = ObligationId::new_for_test(i as u32, 0);

        // Track creation and resolution
        tracker.track_obligation_creation(obligation_id, root_region);
        tracker.track_obligation_resolution(obligation_id);
    }

    // Validate state
    assert!(!tracker.has_active_obligations());
    assert!(tracker.is_region_quiescent(root_region));
    assert!(tracker.get_invariant_violations().is_empty());

    // Clean close
    tracker.track_region_close_initiation(root_region);
    tracker.track_region_close_completion(root_region);

    let violations = tracker.validate_invariants();
    assert!(violations.is_empty(), "Found violations: {:?}", violations);
}

#[test]
fn test_nested_obligation_conformance() {
    let mut runtime = create_test_runtime();
    let tracker = ObligationTracker::new();

    // Create parent region
    let parent_region = runtime.state.create_root_region(Budget::INFINITE);
    tracker.track_region_creation(parent_region, None);

    // Create child region (simulated)
    let child_region = RegionId::from_arena(ArenaIndex::new(100, 0));
    tracker.track_region_creation(child_region, Some(parent_region));

    // Create obligations in different regions
    let parent_obligation = ObligationId::new_for_test(1, 0);
    let child_obligation = ObligationId::new_for_test(2, 0);

    tracker.track_obligation_creation(parent_obligation, parent_region);
    tracker.track_obligation_creation(child_obligation, child_region);

    // Verify initial state
    assert!(!tracker.is_region_quiescent(parent_region));
    assert!(!tracker.is_region_quiescent(child_region));

    // Resolve child first
    tracker.track_obligation_resolution(child_obligation);
    assert!(tracker.is_region_quiescent(child_region));
    assert!(!tracker.is_region_quiescent(parent_region)); // Still has own obligation

    // Close child region
    tracker.track_region_close_initiation(child_region);
    tracker.track_region_close_completion(child_region);

    // Resolve parent
    tracker.track_obligation_resolution(parent_obligation);
    assert!(tracker.is_region_quiescent(parent_region));

    // Close parent region
    tracker.track_region_close_initiation(parent_region);
    tracker.track_region_close_completion(parent_region);

    let violations = tracker.validate_invariants();
    assert!(violations.is_empty(), "Found violations: {:?}", violations);
}

#[test]
fn test_region_quiescence_violation_detection() {
    let mut runtime = create_test_runtime();
    let tracker = ObligationTracker::new();

    // Create region
    let region = runtime.state.create_root_region(Budget::INFINITE);
    tracker.track_region_creation(region, None);

    // Create obligation but don't resolve
    let obligation = ObligationId::new_for_test(1, 0);
    tracker.track_obligation_creation(obligation, region);

    // Try to close region with active obligation (should detect violation)
    tracker.track_region_close_initiation(region);

    // Check that violation was detected
    let violations = tracker.get_invariant_violations();
    assert!(!violations.is_empty(), "Expected quiescence violation to be detected");

    let has_quiescence_violation = violations.iter()
        .any(|v| matches!(v.violation_type, InvariantViolationType::RegionQuiescenceViolation));
    assert!(has_quiescence_violation, "Expected RegionQuiescenceViolation");

    // Clean up
    tracker.track_obligation_resolution(obligation);
    tracker.track_region_close_completion(region);
}

#[test]
fn test_obligation_cancellation_propagation() {
    let tracker = ObligationTracker::new();

    // Create parent and child obligations
    let region = RegionId::from_arena(ArenaIndex::new(1, 0));
    let parent_obligation = ObligationId::new_for_test(1, 0);
    let child_obligation = ObligationId::new_for_test(2, 0);

    tracker.track_region_creation(region, None);
    tracker.track_obligation_creation(parent_obligation, region);
    tracker.track_obligation_creation(child_obligation, region);

    // Cancel parent - should not affect independent child
    tracker.track_obligation_cancellation(parent_obligation);

    // Resolve child normally
    tracker.track_obligation_resolution(child_obligation);

    // Close region
    tracker.track_region_close_initiation(region);
    tracker.track_region_close_completion(region);

    let violations = tracker.validate_invariants();
    assert!(violations.is_empty(), "Found violations: {:?}", violations);
}

#[test]
fn test_resource_leak_detection() {
    let tracker = ObligationTracker::new();
    let region = RegionId::from_arena(ArenaIndex::new(1, 0));
    let obligation = ObligationId::new_for_test(1, 0);

    tracker.track_region_creation(region, None);
    tracker.track_obligation_creation(obligation, region);

    // Allocate a resource
    let resource = ResourceHandle::WakerRegistration(WakerHandle {
        id: 12345,
        registration_time: 1000000,
    });
    tracker.track_resource_allocation(obligation, resource.clone());

    // Resolve obligation without cleaning up resource (should detect leak)
    tracker.track_obligation_resolution(obligation);

    let violations = tracker.get_invariant_violations();
    assert!(!violations.is_empty(), "Expected resource leak to be detected");

    let has_resource_leak = violations.iter()
        .any(|v| matches!(v.violation_type, InvariantViolationType::ResourceLeak));
    assert!(has_resource_leak, "Expected ResourceLeak violation");
}

#[test]
fn test_stress_concurrent_obligations() {
    let mut runtime = create_test_runtime();
    let tracker = ObligationTracker::new();

    let region = runtime.state.create_root_region(Budget::INFINITE);
    tracker.track_region_creation(region, None);

    // Create many obligations
    let num_obligations = 100;
    let mut obligations = Vec::new();

    for i in 0..num_obligations {
        let obligation_id = ObligationId::new_for_test(i as u32, 0);
        tracker.track_obligation_creation(obligation_id, region);
        obligations.push(obligation_id);
    }

    // Resolve all obligations
    for obligation_id in obligations {
        tracker.track_obligation_resolution(obligation_id);
    }

    // Validate final state
    assert!(tracker.is_region_quiescent(region));
    assert!(!tracker.has_active_obligations());

    tracker.track_region_close_initiation(region);
    tracker.track_region_close_completion(region);

    let violations = tracker.validate_invariants();
    assert!(violations.is_empty(), "Found violations: {:?}", violations);
}

#[test]
fn test_invariant_tracker_reset() {
    let tracker = ObligationTracker::new();

    // Create some state
    let region = RegionId::from_arena(ArenaIndex::new(1, 0));
    let obligation = ObligationId::new_for_test(1, 0);

    tracker.track_region_creation(region, None);
    tracker.track_obligation_creation(obligation, region);

    // Verify state exists
    assert!(tracker.has_active_obligations());

    // Reset and verify clean state
    tracker.reset();
    assert!(!tracker.has_active_obligations());
    assert!(tracker.get_invariant_violations().is_empty());
    assert_eq!(tracker.active_obligation_count(), 0);
}

#[test]
fn test_comprehensive_invariant_validation() {
    let mut runtime = create_test_runtime();
    let tracker = ObligationTracker::new();

    // Test scenario: nested regions, multiple obligations, mixed resolution patterns
    let root_region = runtime.state.create_root_region(Budget::INFINITE);
    let child_region1 = RegionId::from_arena(ArenaIndex::new(100, 0));
    let child_region2 = RegionId::from_arena(ArenaIndex::new(101, 0));

    // Set up region hierarchy
    tracker.track_region_creation(root_region, None);
    tracker.track_region_creation(child_region1, Some(root_region));
    tracker.track_region_creation(child_region2, Some(root_region));

    // Create obligations across regions
    let root_obligations: Vec<_> = (0..3).map(|i| {
        let id = ObligationId::new_for_test(i as u32, 0);
        tracker.track_obligation_creation(id, root_region);
        id
    }).collect();

    let child1_obligations: Vec<_> = (10..13).map(|i| {
        let id = ObligationId::new_for_test(i as u32, 0);
        tracker.track_obligation_creation(id, child_region1);
        id
    }).collect();

    let child2_obligations: Vec<_> = (20..22).map(|i| {
        let id = ObligationId::new_for_test(i as u32, 0);
        tracker.track_obligation_creation(id, child_region2);
        id
    }).collect();

    // Verify active state
    assert!(!tracker.is_region_quiescent(root_region));
    assert!(!tracker.is_region_quiescent(child_region1));
    assert!(!tracker.is_region_quiescent(child_region2));

    // Resolve child obligations first
    for &obligation in &child1_obligations {
        tracker.track_obligation_resolution(obligation);
    }
    for &obligation in &child2_obligations {
        tracker.track_obligation_resolution(obligation);
    }

    // Child regions should be quiescent, root should not
    assert!(tracker.is_region_quiescent(child_region1));
    assert!(tracker.is_region_quiescent(child_region2));
    assert!(!tracker.is_region_quiescent(root_region));

    // Close child regions
    tracker.track_region_close_initiation(child_region1);
    tracker.track_region_close_completion(child_region1);
    tracker.track_region_close_initiation(child_region2);
    tracker.track_region_close_completion(child_region2);

    // Resolve root obligations
    for &obligation in &root_obligations {
        tracker.track_obligation_resolution(obligation);
    }

    // Now root should be quiescent
    assert!(tracker.is_region_quiescent(root_region));

    // Close root region
    tracker.track_region_close_initiation(root_region);
    tracker.track_region_close_completion(root_region);

    // Final validation
    let violations = tracker.validate_invariants();
    assert!(violations.is_empty(), "Found violations: {:?}", violations);
    assert!(!tracker.has_active_obligations());
    assert_eq!(tracker.active_obligation_count(), 0);
}