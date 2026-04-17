//! Integration tests for Runtime Resource Cleanup Verification Engine
//!
//! This test suite validates that the resource cleanup verifier properly
//! integrates with the runtime and enforces the "region close = quiescence"
//! invariant across different resource types and scenarios.

use asupersync::runtime::RuntimeBuilder;
use asupersync::runtime::resource_cleanup_verifier::{
    ResourceCleanupVerifier, ResourceCleanupViolation, ViolationSeverity,
};
use asupersync::runtime::resource_monitor::ResourceType;
use asupersync::types::{RegionId, TaskId};

/// Test helper to create a test runtime with resource verification enabled.
fn create_test_runtime() -> asupersync::runtime::Runtime {
    RuntimeBuilder::new()
        .build()
        .expect("Failed to build runtime for testing")
}

/// Test basic resource tracking and cleanup verification.
#[test]
fn test_resource_tracking_integration() {
    let rt = create_test_runtime();

    rt.block_on(async {
        let verifier = ResourceCleanupVerifier::new();
        let region = RegionId::from_raw(1);

        // Track a file descriptor resource
        let resource_id = verifier.track_resource(
            ResourceType::FileDescriptor,
            region,
            None,
            Some("test_fd".to_string()),
            "Integration test file descriptor".to_string(),
        );

        // Verify resource is tracked
        let resources = verifier.resources_for_region(region);
        assert_eq!(resources.len(), 1);
        assert_eq!(resources[0].id, resource_id);

        // Mark as cleaned and verify region close
        verifier.mark_resource_cleaned(resource_id);
        let result = verifier.verify_region_close(region);

        assert!(result.is_ok(), "Region close should succeed after cleanup");

        let stats = verifier.stats();
        assert_eq!(stats.total_tracked, 1);
        assert_eq!(stats.cleaned_count, 1);
        assert_eq!(stats.leak_count, 0);
    });
}

/// Test resource leak detection during region close.
#[test]
fn test_resource_leak_detection() {
    let rt = create_test_runtime();

    rt.block_on(async {
        let verifier = ResourceCleanupVerifier::new();
        let region = RegionId::from_raw(2);

        // Track resources but don't clean them up
        let fd_id = verifier.track_resource(
            ResourceType::FileDescriptor,
            region,
            None,
            Some("leaked_fd".to_string()),
            "Test file descriptor leak".to_string(),
        );

        let mem_id = verifier.track_resource(
            ResourceType::Memory,
            region,
            None,
            None,
            "Test memory leak".to_string(),
        );

        // Attempt region close without cleanup
        let result = verifier.verify_region_close(region);
        assert!(
            result.is_err(),
            "Region close should fail with resource leaks"
        );

        let violations = result.unwrap_err();
        assert_eq!(violations.len(), 2);

        // Verify violation details
        let fd_violation = violations
            .iter()
            .find(|v| v.resource.id == fd_id)
            .expect("File descriptor violation");
        let mem_violation = violations
            .iter()
            .find(|v| v.resource.id == mem_id)
            .expect("Memory violation");

        // File descriptors are critical, memory is medium
        assert!(matches!(
            fd_violation.severity,
            ViolationSeverity::High | ViolationSeverity::Critical
        ));
        assert!(matches!(
            mem_violation.severity,
            ViolationSeverity::Medium | ViolationSeverity::High
        ));

        // Check statistics
        let stats = verifier.stats();
        assert_eq!(stats.total_tracked, 2);
        assert_eq!(stats.cleaned_count, 0);
        assert_eq!(stats.leak_count, 2);
        assert_eq!(stats.cleanup_success_rate(), 0.0);
    });
}

/// Test mixed scenarios with partial cleanup.
#[test]
fn test_partial_cleanup_scenarios() {
    let rt = create_test_runtime();

    rt.block_on(async {
        let verifier = ResourceCleanupVerifier::new();
        let region = RegionId::from_raw(3);

        // Track multiple resource types
        let resources = vec![
            verifier.track_resource(
                ResourceType::FileDescriptor,
                region,
                None,
                Some("fd1".to_string()),
                "File descriptor 1".to_string(),
            ),
            verifier.track_resource(
                ResourceType::Memory,
                region,
                None,
                None,
                "Memory allocation 1".to_string(),
            ),
            verifier.track_resource(
                ResourceType::NetworkConnection,
                region,
                None,
                Some("tcp://127.0.0.1:8080".to_string()),
                "Network connection 1".to_string(),
            ),
            verifier.track_resource(
                ResourceType::FileDescriptor,
                region,
                None,
                Some("fd2".to_string()),
                "File descriptor 2".to_string(),
            ),
        ];

        // Clean up only some resources (alternating pattern)
        verifier.mark_resource_cleaned(resources[0]); // fd1 cleaned
        // resources[1] (memory) not cleaned
        verifier.mark_resource_cleaned(resources[2]); // network cleaned
        // resources[3] (fd2) not cleaned

        // Verify region close detects leaks
        let result = verifier.verify_region_close(region);
        assert!(result.is_err(), "Should detect partial cleanup failures");

        let violations = result.unwrap_err();
        assert_eq!(violations.len(), 2); // Memory and fd2

        // Check that violations are for the uncleaned resources
        let leaked_ids: Vec<_> = violations.iter().map(|v| v.resource.id).collect();
        assert!(leaked_ids.contains(&resources[1])); // Memory leak
        assert!(leaked_ids.contains(&resources[3])); // fd2 leak

        let stats = verifier.stats();
        assert_eq!(stats.total_tracked, 4);
        assert_eq!(stats.cleaned_count, 2);
        assert_eq!(stats.leak_count, 2);
        assert_eq!(stats.cleanup_success_rate(), 50.0);
    });
}

/// Test cleanup pending state behavior.
#[test]
fn test_cleanup_pending_state() {
    let rt = create_test_runtime();

    rt.block_on(async {
        let verifier = ResourceCleanupVerifier::new();
        let region = RegionId::from_raw(4);

        let resource_id = verifier.track_resource(
            ResourceType::Memory,
            region,
            None,
            None,
            "Cleanup pending test".to_string(),
        );

        // Mark cleanup as pending but not complete
        verifier.mark_cleanup_pending(resource_id);

        // Region close should still fail since cleanup is not complete
        let result = verifier.verify_region_close(region);
        assert!(
            result.is_err(),
            "Cleanup pending should still fail region close"
        );

        let violations = result.unwrap_err();
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].resource.id, resource_id);
    });
}

/// Test multiple regions with independent resource tracking.
#[test]
fn test_multiple_regions() {
    let rt = create_test_runtime();

    rt.block_on(async {
        let verifier = ResourceCleanupVerifier::new();
        let region1 = RegionId::from_raw(10);
        let region2 = RegionId::from_raw(20);

        // Track resources in different regions
        let r1_resources = vec![
            verifier.track_resource(
                ResourceType::FileDescriptor,
                region1,
                None,
                Some("r1_fd1".to_string()),
                "Region 1 FD 1".to_string(),
            ),
            verifier.track_resource(
                ResourceType::Memory,
                region1,
                None,
                None,
                "Region 1 Memory".to_string(),
            ),
        ];

        let r2_resources = vec![verifier.track_resource(
            ResourceType::NetworkConnection,
            region2,
            None,
            Some("r2_net1".to_string()),
            "Region 2 Network".to_string(),
        )];

        // Clean up region 1 resources
        for &resource_id in &r1_resources {
            verifier.mark_resource_cleaned(resource_id);
        }

        // Leave region 2 resources uncleaned

        // Verify region 1 closes cleanly
        let r1_result = verifier.verify_region_close(region1);
        assert!(r1_result.is_ok(), "Region 1 should close cleanly");

        // Verify region 2 has violations
        let r2_result = verifier.verify_region_close(region2);
        assert!(r2_result.is_err(), "Region 2 should have violations");

        let r2_violations = r2_result.unwrap_err();
        assert_eq!(r2_violations.len(), 1);
        assert_eq!(r2_violations[0].resource.id, r2_resources[0]);

        // Check final statistics
        let stats = verifier.stats();
        assert_eq!(stats.total_tracked, 3);
        assert_eq!(stats.cleaned_count, 2);
        assert_eq!(stats.leak_count, 1);
        assert_eq!(stats.regions_verified, 2);
    });
}

/// Test empty regions (no resources tracked).
#[test]
fn test_empty_region_close() {
    let rt = create_test_runtime();

    rt.block_on(async {
        let verifier = ResourceCleanupVerifier::new();
        let region = RegionId::from_raw(100);

        // Close region without any resources tracked
        let result = verifier.verify_region_close(region);
        assert!(result.is_ok(), "Empty region should close without issues");

        let stats = verifier.stats();
        assert_eq!(stats.total_tracked, 0);
        assert_eq!(stats.regions_verified, 1);
    });
}

/// Test resource attribution to tasks.
#[test]
fn test_resource_task_attribution() {
    let rt = create_test_runtime();

    rt.block_on(async {
        let verifier = ResourceCleanupVerifier::new();
        let region = RegionId::from_raw(200);
        let task = TaskId::from_raw(123);

        // Track resource with task attribution
        let resource_id = verifier.track_resource(
            ResourceType::FileDescriptor,
            region,
            Some(task),
            Some("task_fd".to_string()),
            "Task-allocated file descriptor".to_string(),
        );

        // Verify task attribution is preserved
        let resources = verifier.resources_for_region(region);
        assert_eq!(resources.len(), 1);
        assert_eq!(resources[0].allocating_task, Some(task));

        // Test leak detection includes task information
        let result = verifier.verify_region_close(region);
        assert!(result.is_err());

        let violations = result.unwrap_err();
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].resource.allocating_task, Some(task));
    });
}

/// Test statistics accumulation across multiple operations.
#[test]
fn test_statistics_accumulation() {
    let rt = create_test_runtime();

    rt.block_on(async {
        let verifier = ResourceCleanupVerifier::new();

        // Simulate multiple region lifecycles
        for region_num in 1..=5 {
            let region = RegionId::from_raw(region_num);

            // Track 2-4 resources per region
            let resource_count = 2 + (region_num % 3) as usize;
            let mut resources = Vec::new();

            for i in 0..resource_count {
                let resource_id = verifier.track_resource(
                    if i % 2 == 0 {
                        ResourceType::Memory
                    } else {
                        ResourceType::FileDescriptor
                    },
                    region,
                    None,
                    Some(format!("r{}_{}", region_num, i)),
                    format!("Region {} resource {}", region_num, i),
                );
                resources.push(resource_id);
            }

            // Clean up half the resources (rounded down)
            let cleanup_count = resource_count / 2;
            for i in 0..cleanup_count {
                verifier.mark_resource_cleaned(resources[i]);
            }

            // Close region (will detect leaks for uncleaned resources)
            let _result = verifier.verify_region_close(region);
        }

        // Verify accumulated statistics
        let stats = verifier.stats();
        assert_eq!(stats.regions_verified, 5);
        assert!(stats.total_tracked > 0);
        assert!(stats.cleaned_count > 0);
        assert!(stats.leak_count > 0);
        assert!(stats.cleanup_success_rate() > 0.0);
        assert!(stats.cleanup_success_rate() < 100.0);
    });
}

/// Test violation severity classification.
#[test]
fn test_violation_severity() {
    let rt = create_test_runtime();

    rt.block_on(async {
        let verifier = ResourceCleanupVerifier::new();
        let region = RegionId::from_raw(300);

        // Track different resource types to test severity classification
        let fd_id = verifier.track_resource(
            ResourceType::FileDescriptor,
            region,
            None,
            Some("severity_fd".to_string()),
            "File descriptor for severity test".to_string(),
        );

        let mem_id = verifier.track_resource(
            ResourceType::Memory,
            region,
            None,
            None,
            "Memory for severity test".to_string(),
        );

        let net_id = verifier.track_resource(
            ResourceType::NetworkConnection,
            region,
            None,
            Some("severity_net".to_string()),
            "Network connection for severity test".to_string(),
        );

        // Don't clean up any resources and verify region close
        let result = verifier.verify_region_close(region);
        assert!(result.is_err());

        let violations = result.unwrap_err();
        assert_eq!(violations.len(), 3);

        // Check that file descriptor has higher severity than memory
        let fd_violation = violations.iter().find(|v| v.resource.id == fd_id).unwrap();
        let mem_violation = violations.iter().find(|v| v.resource.id == mem_id).unwrap();
        let net_violation = violations.iter().find(|v| v.resource.id == net_id).unwrap();

        // File descriptors should be high/critical severity
        assert!(matches!(
            fd_violation.severity,
            ViolationSeverity::High | ViolationSeverity::Critical
        ));

        // Memory should be medium/high severity
        assert!(matches!(
            mem_violation.severity,
            ViolationSeverity::Medium | ViolationSeverity::High
        ));

        // Network connections should be low/medium severity
        assert!(matches!(
            net_violation.severity,
            ViolationSeverity::Low | ViolationSeverity::Medium
        ));
    });
}
