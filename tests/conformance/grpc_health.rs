#![allow(warnings)]
#![allow(clippy::all)]
//! gRPC Health Checking Protocol v1 Conformance Tests
//!
//! This module implements metamorphic testing for the gRPC Health Checking
//! Protocol as specified in grpc/grpc-proto/grpc/health/v1/health.proto.
//!
//! Tests validate conformance to RFC behavior under various state mutations,
//! service registration patterns, and concurrent access scenarios.

use proptest::prelude::*;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use asupersync::grpc::health::{
    HealthCheckRequest, HealthCheckResponse, HealthReporter, HealthService, ServingStatus,
};
use asupersync::grpc::status::{Code, Status};

/// Maximum number of services for property-based testing
const MAX_SERVICES: usize = 20;

/// Maximum number of operations in a sequence
const MAX_OPERATIONS: usize = 50;

/// Test service names for deterministic testing
const SERVICE_NAMES: &[&str] = &[
    "auth.v1.AuthService",
    "user.v2.UserService",
    "payment.v1.PaymentService",
    "inventory.v1.InventoryService",
    "notification.v1.NotificationService",
    "analytics.v1.AnalyticsService",
    "search.v1.SearchService",
    "recommendation.v1.RecommendationService",
];

/// All possible serving statuses for property testing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
enum TestServingStatus {
    Unknown,
    Serving,
    NotServing,
    ServiceUnknown,
}

#[allow(dead_code)]

impl TestServingStatus {
    #[allow(dead_code)]
    fn to_serving_status(self) -> ServingStatus {
        match self {
            Self::Unknown => ServingStatus::Unknown,
            Self::Serving => ServingStatus::Serving,
            Self::NotServing => ServingStatus::NotServing,
            Self::ServiceUnknown => ServingStatus::ServiceUnknown,
        }
    }
}

impl Arbitrary for TestServingStatus {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    #[allow(dead_code)]

    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        prop_oneof![
            Just(TestServingStatus::Unknown),
            Just(TestServingStatus::Serving),
            Just(TestServingStatus::NotServing),
            Just(TestServingStatus::ServiceUnknown),
        ]
        .boxed()
    }
}

/// Health service operation for metamorphic testing
#[derive(Debug, Clone)]
#[allow(dead_code)]
enum HealthOperation {
    SetStatus { service: String, status: TestServingStatus },
    ClearStatus { service: String },
    ClearAll,
    Check { service: String },
    Watch { service: String },
    SetServerStatus { status: TestServingStatus },
}

impl Arbitrary for HealthOperation {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    #[allow(dead_code)]

    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        let service_names = SERVICE_NAMES.iter().map(|&s| s.to_string()).collect::<Vec<_>>();

        prop_oneof![
            (prop::sample::select(service_names.clone()), any::<TestServingStatus>())
                .prop_map(|(service, status)| HealthOperation::SetStatus { service, status }),
            prop::sample::select(service_names.clone())
                .prop_map(|service| HealthOperation::ClearStatus { service }),
            Just(HealthOperation::ClearAll),
            prop::sample::select(service_names.clone())
                .prop_map(|service| HealthOperation::Check { service }),
            prop::sample::select(service_names.clone())
                .prop_map(|service| HealthOperation::Watch { service }),
            any::<TestServingStatus>()
                .prop_map(|status| HealthOperation::SetServerStatus { status }),
        ]
        .boxed()
    }
}

/// Test context for health service conformance testing
#[derive(Debug)]
#[allow(dead_code)]
struct HealthTestContext {
    service: HealthService,
    initial_operations: Vec<HealthOperation>,
}

#[allow(dead_code)]

impl HealthTestContext {
    #[allow(dead_code)]
    fn new(operations: Vec<HealthOperation>) -> Self {
        let service = HealthService::new();
        Self {
            service,
            initial_operations: operations,
        }
    }

    #[allow(dead_code)]

    fn apply_operations(&self, ops: &[HealthOperation]) -> HashMap<String, ServingStatus> {
        let mut expected_statuses = HashMap::new();

        for op in ops {
            match op {
                HealthOperation::SetStatus { service, status } => {
                    let serving_status = status.to_serving_status();
                    self.service.set_status(service, serving_status);
                    expected_statuses.insert(service.clone(), serving_status);
                }
                HealthOperation::ClearStatus { service } => {
                    self.service.clear_status(service);
                    expected_statuses.remove(service);
                }
                HealthOperation::ClearAll => {
                    self.service.clear();
                    expected_statuses.clear();
                }
                HealthOperation::SetServerStatus { status } => {
                    let serving_status = status.to_serving_status();
                    self.service.set_server_status(serving_status);
                    expected_statuses.insert("".to_string(), serving_status);
                }
                HealthOperation::Check { .. } | HealthOperation::Watch { .. } => {
                    // Read-only operations don't change state
                }
            }
        }

        expected_statuses
    }

    #[allow(dead_code)]

    fn compute_server_status(&self, service_statuses: &HashMap<String, ServingStatus>) -> ServingStatus {
        // Server status computation per gRPC health protocol
        if let Some(explicit_status) = service_statuses.get("") {
            *explicit_status
        } else if service_statuses.is_empty() {
            ServingStatus::ServiceUnknown
        } else if service_statuses.iter()
            .filter(|(k, _)| !k.is_empty()) // Exclude explicit server status
            .all(|(_, status)| status.is_healthy())
        {
            ServingStatus::Serving
        } else {
            ServingStatus::NotServing
        }
    }
}

impl Arbitrary for HealthTestContext {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    #[allow(dead_code)]

    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        prop::collection::vec(any::<HealthOperation>(), 1..MAX_OPERATIONS)
            .prop_map(HealthTestContext::new)
            .boxed()
    }
}

/// MR1: Check Operation Idempotence
///
/// For any sequence of read operations (check calls), the service state
/// should remain unchanged. Multiple checks of the same service should
/// return consistent results.
#[allow(dead_code)]
fn mr_check_operation_idempotence(ctx: &HealthTestContext) {
    // Apply initial operations to establish state
    let expected_statuses = ctx.apply_operations(&ctx.initial_operations);
    let initial_version = ctx.service.version();

    // Collect all services mentioned in operations
    let mut services_to_check: HashSet<String> = ctx.initial_operations
        .iter()
        .filter_map(|op| match op {
            HealthOperation::SetStatus { service, .. } |
            HealthOperation::ClearStatus { service } |
            HealthOperation::Check { service } |
            HealthOperation::Watch { service } => Some(service.clone()),
            _ => None,
        })
        .collect();

    // Always check server status (empty string)
    services_to_check.insert("".to_string());

    // Perform multiple check operations
    let mut check_results = Vec::new();
    for service in &services_to_check {
        let request = HealthCheckRequest::new(service);
        let result = ctx.service.check(&request);
        check_results.push((service.clone(), result));

        // Check again immediately - should get same result
        let result2 = ctx.service.check(&request);
        match (&result, &result2) {
            (Ok(resp1), Ok(resp2)) => assert_eq!(
                resp1.status, resp2.status,
                "Check idempotence violation: service '{}' returned different statuses on repeated calls",
                service
            ),
            (Err(err1), Err(err2)) => assert_eq!(
                err1.code(), err2.code(),
                "Check idempotence violation: service '{}' returned different error codes on repeated calls",
                service
            ),
            _ => panic!(
                "Check idempotence violation: service '{}' switched between success/error on repeated calls",
                service
            ),
        }
    }

    // Version should not change from read operations
    assert_eq!(
        ctx.service.version(), initial_version,
        "Check operations must not modify service version"
    );

    // Verify check results match expected statuses
    for (service, result) in check_results {
        match result {
            Ok(response) => {
                if service.is_empty() {
                    // Server status check
                    let expected_server_status = ctx.compute_server_status(&expected_statuses);
                    assert_eq!(
                        response.status, expected_server_status,
                        "Server status check returned {} but expected {}",
                        response.status, expected_server_status
                    );
                } else {
                    // Individual service check
                    if let Some(&expected_status) = expected_statuses.get(&service) {
                        assert_eq!(
                            response.status, expected_status,
                            "Service '{}' check returned {} but expected {}",
                            service, response.status, expected_status
                        );
                    } else {
                        panic!("Service '{}' check succeeded but service not registered", service);
                    }
                }
            }
            Err(status) => {
                if service.is_empty() {
                    panic!("Server status check should never fail");
                } else {
                    assert_eq!(
                        status.code(), Code::NotFound,
                        "Check for unregistered service '{}' should return NOT_FOUND",
                        service
                    );
                    assert!(
                        !expected_statuses.contains_key(&service),
                        "Service '{}' check failed but service is registered",
                        service
                    );
                }
            }
        }
    }
}

/// MR2: Watch Status Change Detection
///
/// When a service status changes, all watchers for that service must
/// observe the change. Watchers for other services must not observe
/// unrelated changes.
#[allow(dead_code)]
fn mr_watch_status_change_detection(ctx: &HealthTestContext) {
    // Apply initial operations
    let _initial_statuses = ctx.apply_operations(&ctx.initial_operations);

    // Get a stable service name from operations or use a default
    let target_service = ctx.initial_operations
        .iter()
        .find_map(|op| match op {
            HealthOperation::SetStatus { service, .. } => Some(service.clone()),
            _ => None,
        })
        .unwrap_or_else(|| SERVICE_NAMES[0].to_string());

    let other_service = SERVICE_NAMES[1].to_string();

    // Set up initial state
    ctx.service.set_status(&target_service, ServingStatus::Serving);
    ctx.service.set_status(&other_service, ServingStatus::Serving);

    // Create watchers
    let mut target_watcher = ctx.service.watch(&target_service);
    let mut other_watcher = ctx.service.watch(&other_service);
    let mut server_watcher = ctx.service.watch("");

    // Capture initial states
    let initial_target_status = target_watcher.status();
    let initial_other_status = other_watcher.status();
    let initial_server_status = server_watcher.status();

    // Change target service status
    ctx.service.set_status(&target_service, ServingStatus::NotServing);

    // Check watcher responses
    let target_changed = target_watcher.changed();
    let other_changed = other_watcher.changed();
    let server_changed = server_watcher.changed();

    // Target service watcher must detect change
    assert!(
        target_changed,
        "Target service watcher failed to detect status change"
    );
    assert_eq!(
        target_watcher.status(), ServingStatus::NotServing,
        "Target service watcher reports incorrect status after change"
    );

    // Other service watcher must not detect unrelated change
    assert!(
        !other_changed,
        "Other service watcher incorrectly detected unrelated status change"
    );
    assert_eq!(
        other_watcher.status(), initial_other_status,
        "Other service watcher status changed despite no updates to that service"
    );

    // Server watcher should detect change (aggregate status changed)
    assert!(
        server_changed,
        "Server watcher failed to detect aggregate status change"
    );
    assert_eq!(
        server_watcher.status(), ServingStatus::NotServing,
        "Server watcher reports incorrect aggregate status"
    );

    // Reset and test the inverse
    ctx.service.set_status(&target_service, ServingStatus::Serving);

    let target_changed_back = target_watcher.changed();
    let other_still_unchanged = other_watcher.changed();
    let server_changed_back = server_watcher.changed();

    assert!(
        target_changed_back,
        "Target service watcher failed to detect status restoration"
    );
    assert!(
        !other_still_unchanged,
        "Other service watcher incorrectly detected change during target restoration"
    );
    assert!(
        server_changed_back,
        "Server watcher failed to detect aggregate status restoration"
    );
}

/// MR3: Status Code Error Semantics
///
/// The gRPC health check protocol must return appropriate status codes:
/// - NOT_FOUND for unregistered services
/// - OK for registered services (regardless of health status)
/// - Server status checks never return NOT_FOUND
#[allow(dead_code)]
fn mr_status_code_error_semantics(ctx: &HealthTestContext) {
    // Apply initial operations
    let expected_statuses = ctx.apply_operations(&ctx.initial_operations);

    // Test registered services
    for (service, _) in &expected_statuses {
        if !service.is_empty() { // Skip explicit server status entries
            let request = HealthCheckRequest::new(service);
            let result = ctx.service.check(&request);

            assert!(
                result.is_ok(),
                "Check for registered service '{}' should succeed, got error: {:?}",
                service, result.err()
            );
        }
    }

    // Test unregistered services
    let unregistered_services = SERVICE_NAMES.iter()
        .filter(|&&name| !expected_statuses.contains_key(name))
        .take(3); // Test a few unregistered services

    for &service in unregistered_services {
        let request = HealthCheckRequest::new(service);
        let result = ctx.service.check(&request);

        assert!(
            result.is_err(),
            "Check for unregistered service '{}' should fail",
            service
        );

        let error = result.unwrap_err();
        assert_eq!(
            error.code(), Code::NotFound,
            "Check for unregistered service '{}' should return NOT_FOUND, got {:?}",
            service, error.code()
        );

        assert!(
            error.message().contains(service),
            "Error message should mention the service name: {}",
            error.message()
        );
    }

    // Test server status check (should never return NOT_FOUND)
    let server_request = HealthCheckRequest::server();
    let server_result = ctx.service.check(&server_request);

    assert!(
        server_result.is_ok(),
        "Server status check should never fail, got error: {:?}",
        server_result.err()
    );

    let server_response = server_result.unwrap();
    match server_response.status {
        ServingStatus::ServiceUnknown | ServingStatus::Serving | ServingStatus::NotServing => {
            // All valid server status responses
        }
        status => panic!(
            "Server status check returned invalid status: {:?}", status
        ),
    }
}

/// MR4: Per-Service Independence
///
/// Changes to one service's status must not affect other services' statuses
/// (except for server aggregate status). Service registrations and
/// deregistrations must be independent.
#[allow(dead_code)]
fn mr_per_service_independence(ctx: &HealthTestContext) {
    // Set up multiple services with known statuses
    let service_a = SERVICE_NAMES[0];
    let service_b = SERVICE_NAMES[1];
    let service_c = SERVICE_NAMES[2];

    ctx.service.set_status(service_a, ServingStatus::Serving);
    ctx.service.set_status(service_b, ServingStatus::NotServing);
    ctx.service.set_status(service_c, ServingStatus::Unknown);

    // Capture initial state
    let initial_a = ctx.service.get_status(service_a);
    let initial_b = ctx.service.get_status(service_b);
    let initial_c = ctx.service.get_status(service_c);

    // Apply context operations which may modify services
    let _final_statuses = ctx.apply_operations(&ctx.initial_operations);

    // Check which services were actually modified by the operations
    let mut modified_services = HashSet::new();
    for op in &ctx.initial_operations {
        match op {
            HealthOperation::SetStatus { service, .. } |
            HealthOperation::ClearStatus { service } => {
                modified_services.insert(service.clone());
            }
            HealthOperation::ClearAll => {
                modified_services.insert(service_a.to_string());
                modified_services.insert(service_b.to_string());
                modified_services.insert(service_c.to_string());
            }
            _ => {} // Read operations don't modify state
        }
    }

    // Verify independence: unmodified services should retain their status
    if !modified_services.contains(service_a) {
        assert_eq!(
            ctx.service.get_status(service_a), initial_a,
            "Service '{}' status changed despite not being modified", service_a
        );
    }

    if !modified_services.contains(service_b) {
        assert_eq!(
            ctx.service.get_status(service_b), initial_b,
            "Service '{}' status changed despite not being modified", service_b
        );
    }

    if !modified_services.contains(service_c) {
        assert_eq!(
            ctx.service.get_status(service_c), initial_c,
            "Service '{}' status changed despite not being modified", service_c
        );
    }

    // Test version independence: changes to one service should not affect
    // watch versions of other services
    let test_service = SERVICE_NAMES[3];
    ctx.service.set_status(test_service, ServingStatus::Serving);

    let mut watcher_a = ctx.service.watch(service_a);
    let mut watcher_test = ctx.service.watch(test_service);

    // Change unrelated service
    ctx.service.set_status(test_service, ServingStatus::NotServing);

    let a_changed = watcher_a.changed();
    let test_changed = watcher_test.changed();

    assert!(
        !a_changed,
        "Watcher for service '{}' incorrectly detected change to unrelated service '{}'",
        service_a, test_service
    );
    assert!(
        test_changed,
        "Watcher for service '{}' failed to detect its own status change",
        test_service
    );
}

/// MR5: Shutdown and Cleanup Semantics
///
/// Health reporters must properly clean up service registrations on drop.
/// Multiple reporters for the same service must coordinate correctly,
/// with only the final reporter drop clearing the service status.
#[allow(dead_code)]
fn mr_shutdown_cleanup_semantics(ctx: &HealthTestContext) {
    let test_service = "cleanup.test.Service";

    // Apply initial operations first
    let _initial_statuses = ctx.apply_operations(&ctx.initial_operations);

    // Test single reporter cleanup
    {
        let reporter = HealthReporter::new(ctx.service.clone(), test_service);
        reporter.set_serving();

        assert_eq!(
            ctx.service.get_status(test_service),
            Some(ServingStatus::Serving),
            "Reporter failed to set service status"
        );

        assert!(
            ctx.service.is_serving(test_service),
            "Service should report as serving after reporter.set_serving()"
        );
    } // Reporter dropped here

    // Service should be cleared after reporter drop
    assert_eq!(
        ctx.service.get_status(test_service),
        None,
        "Service status not cleared after reporter drop"
    );

    assert!(
        !ctx.service.is_serving(test_service),
        "Service should not report as serving after cleanup"
    );

    // Test multiple reporter coordination
    let shared_service = "shared.test.Service";
    let initial_version = ctx.service.version();

    {
        let reporter_a = HealthReporter::new(ctx.service.clone(), shared_service);
        let reporter_b = HealthReporter::new(ctx.service.clone(), shared_service);

        reporter_a.set_serving();
        let version_after_set = ctx.service.version();
        assert!(
            version_after_set > initial_version,
            "Version should increment when setting service status"
        );

        // Drop first reporter - service should remain
        drop(reporter_a);
        assert_eq!(
            ctx.service.get_status(shared_service),
            Some(ServingStatus::Serving),
            "Shared service status cleared prematurely on non-final reporter drop"
        );

        // Version should not change on non-final drop
        assert_eq!(
            ctx.service.version(), version_after_set,
            "Version should not increment on non-final reporter drop"
        );

        // Second reporter can still modify status
        reporter_b.set_not_serving();
        assert_eq!(
            ctx.service.get_status(shared_service),
            Some(ServingStatus::NotServing),
            "Remaining reporter should still control service status"
        );

    } // Final reporter dropped here

    // Service should be cleared after final reporter drop
    assert_eq!(
        ctx.service.get_status(shared_service),
        None,
        "Shared service status not cleared after final reporter drop"
    );

    // Test cleanup ordering with concurrent operations
    let concurrent_service = "concurrent.test.Service";
    let service_arc = Arc::new(ctx.service.clone());

    // Create reporter in main thread
    let reporter = HealthReporter::new((*service_arc).clone(), concurrent_service);
    reporter.set_serving();

    // Spawn thread that will create replacement reporter
    let service_for_thread = service_arc.clone();
    let handle = thread::spawn(move || {
        thread::sleep(Duration::from_millis(1)); // Small delay
        let replacement = HealthReporter::new((*service_for_thread).clone(), concurrent_service);
        replacement.set_not_serving();
        replacement // Return so it's not dropped immediately
    });

    // Drop original reporter
    drop(reporter);

    // Wait for replacement
    let replacement = handle.join().expect("Thread should complete");

    // Service should still exist (controlled by replacement)
    assert_eq!(
        service_arc.get_status(concurrent_service),
        Some(ServingStatus::NotServing),
        "Concurrent reporter replacement should preserve service registration"
    );

    // Final cleanup
    drop(replacement);
    assert_eq!(
        service_arc.get_status(concurrent_service),
        None,
        "Service should be cleared after final concurrent reporter drop"
    );
}

// Property-based test runners for each metamorphic relation

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    #[allow(dead_code)]
    fn test_mr_check_operation_idempotence(ctx in any::<HealthTestContext>()) {
        mr_check_operation_idempotence(&ctx);
    }

    #[test]
    #[allow(dead_code)]
    fn test_mr_watch_status_change_detection(ctx in any::<HealthTestContext>()) {
        mr_watch_status_change_detection(&ctx);
    }

    #[test]
    #[allow(dead_code)]
    fn test_mr_status_code_error_semantics(ctx in any::<HealthTestContext>()) {
        mr_status_code_error_semantics(&ctx);
    }

    #[test]
    #[allow(dead_code)]
    fn test_mr_per_service_independence(ctx in any::<HealthTestContext>()) {
        mr_per_service_independence(&ctx);
    }

    #[test]
    #[allow(dead_code)]
    fn test_mr_shutdown_cleanup_semantics(ctx in any::<HealthTestContext>()) {
        mr_shutdown_cleanup_semantics(&ctx);
    }
}

// Additional focused conformance tests

#[cfg(test)]
mod conformance_tests {
    use super::*;

    #[test]
    #[allow(dead_code)]
    fn conformance_health_check_protocol_basic_contract() {
        let service = HealthService::new();

        // Server status with no services should be SERVICE_UNKNOWN
        let request = HealthCheckRequest::server();
        let response = service.check(&request).expect("Server check should succeed");
        assert_eq!(response.status, ServingStatus::ServiceUnknown);

        // Add a healthy service
        service.set_status("test.Service", ServingStatus::Serving);
        let response = service.check(&request).expect("Server check should succeed");
        assert_eq!(response.status, ServingStatus::Serving);

        // Check specific service
        let service_request = HealthCheckRequest::new("test.Service");
        let response = service.check(&service_request).expect("Service check should succeed");
        assert_eq!(response.status, ServingStatus::Serving);

        // Check unregistered service
        let unknown_request = HealthCheckRequest::new("unknown.Service");
        let result = service.check(&unknown_request);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), Code::NotFound);
    }

    #[test]
    #[allow(dead_code)]
    fn conformance_watch_protocol_basic_contract() {
        let service = HealthService::new();
        service.set_status("test.Service", ServingStatus::Serving);

        let mut watcher = service.watch("test.Service");
        assert_eq!(watcher.status(), ServingStatus::Serving);

        // No change initially
        assert!(!watcher.changed());

        // Change status
        service.set_status("test.Service", ServingStatus::NotServing);
        assert!(watcher.changed());
        assert_eq!(watcher.status(), ServingStatus::NotServing);

        // No change after polling
        assert!(!watcher.changed());
    }

    #[test]
    #[allow(dead_code)]
    fn conformance_service_unknown_semantics() {
        let service = HealthService::new();

        // Unknown service watcher reports SERVICE_UNKNOWN
        let mut watcher = service.watch("unknown.Service");
        assert_eq!(watcher.status(), ServingStatus::ServiceUnknown);

        // Registration changes to actual status
        service.set_status("unknown.Service", ServingStatus::Serving);
        assert!(watcher.changed());
        assert_eq!(watcher.status(), ServingStatus::Serving);

        // Deregistration returns to SERVICE_UNKNOWN
        service.clear_status("unknown.Service");
        assert!(watcher.changed());
        assert_eq!(watcher.status(), ServingStatus::ServiceUnknown);
    }

    #[test]
    #[allow(dead_code)]
    fn conformance_aggregate_server_status_computation() {
        let service = HealthService::new();

        // Empty: SERVICE_UNKNOWN
        let request = HealthCheckRequest::server();
        let response = service.check(&request).unwrap();
        assert_eq!(response.status, ServingStatus::ServiceUnknown);

        // All healthy: SERVING
        service.set_status("a", ServingStatus::Serving);
        service.set_status("b", ServingStatus::Serving);
        let response = service.check(&request).unwrap();
        assert_eq!(response.status, ServingStatus::Serving);

        // Any unhealthy: NOT_SERVING
        service.set_status("c", ServingStatus::NotServing);
        let response = service.check(&request).unwrap();
        assert_eq!(response.status, ServingStatus::NotServing);

        // Explicit server status overrides
        service.set_server_status(ServingStatus::Serving);
        let response = service.check(&request).unwrap();
        assert_eq!(response.status, ServingStatus::Serving);
    }
}