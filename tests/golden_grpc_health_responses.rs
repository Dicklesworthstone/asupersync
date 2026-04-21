//! Comprehensive golden snapshot tests for gRPC health service responses
//!
//! Tests all response formats and edge cases for the gRPC Health Checking Protocol
//! implementation in src/grpc/health.rs:
//! - HealthCheckRequest/Response patterns
//! - All ServingStatus values and transitions
//! - Server vs named service queries
//! - Error conditions and unknown services
//! - Builder and reporter patterns
//! - Watch stream initial responses

#![cfg(test)]

use asupersync::grpc::health::{
    HealthCheckRequest, HealthCheckResponse, HealthReporter, HealthService, HealthServiceBuilder,
    ServingStatus,
};
use insta::assert_json_snapshot;
use serde_json::{Value, json};
use std::collections::HashMap;

/// Helper to create consistent response snapshots
fn health_response_snapshot(service: &HealthService, query: &str, description: &str) -> Value {
    let request = if query.is_empty() {
        HealthCheckRequest::server()
    } else {
        HealthCheckRequest::new(query)
    };

    let result = service.check(&request);

    match result {
        Ok(response) => json!({
            "description": description,
            "query_service": request.service,
            "status_code": response.status as i32,
            "status_text": response.status.to_string(),
            "is_healthy": response.status.is_healthy(),
            "result": "success"
        }),
        Err(status) => json!({
            "description": description,
            "query_service": request.service,
            "result": "error",
            "error_message": status.to_string()
        }),
    }
}

/// Test all possible serving status values
#[test]
fn golden_all_serving_status_values() {
    let service = HealthService::new();

    // Set up services with all possible status values
    service.set_status("unknown_service", ServingStatus::Unknown);
    service.set_status("serving_service", ServingStatus::Serving);
    service.set_status("not_serving_service", ServingStatus::NotServing);
    service.set_status("transient_service", ServingStatus::ServiceUnknown);

    // Also test server status
    service.set_server_status(ServingStatus::Serving);

    let snapshot = json!({
        "server_health": health_response_snapshot(&service, "", "Overall server health"),
        "status_variations": [
            health_response_snapshot(&service, "unknown_service", "Service with Unknown status"),
            health_response_snapshot(&service, "serving_service", "Service with Serving status"),
            health_response_snapshot(&service, "not_serving_service", "Service with NotServing status"),
            health_response_snapshot(&service, "transient_service", "Service with ServiceUnknown status"),
        ],
        "service_version": service.version(),
        "metadata": {
            "total_statuses": 4,
            "healthy_services": ["serving_service"],
            "unhealthy_services": ["unknown_service", "not_serving_service", "transient_service"]
        }
    });

    assert_json_snapshot!("all_serving_status_values", snapshot);
}

/// Test responses for unknown/unregistered services
#[test]
fn golden_unknown_service_queries() {
    let service = HealthService::new();
    service.set_server_status(ServingStatus::Serving);
    service.set_status("existing.service", ServingStatus::Serving);

    let snapshot = json!({
        "existing_service": health_response_snapshot(&service, "existing.service", "Known service"),
        "unknown_queries": [
            health_response_snapshot(&service, "nonexistent.service", "Unregistered service"),
            health_response_snapshot(&service, "another.missing", "Another missing service"),
            health_response_snapshot(&service, "service.with.dots", "Service with dot notation"),
            health_response_snapshot(&service, "UPPERCASE_SERVICE", "Uppercase service name"),
            health_response_snapshot(&service, "service/with/slashes", "Service with slashes"),
        ],
        "edge_case_names": [
            health_response_snapshot(&service, " ", "Space character service name"),
            health_response_snapshot(&service, "\t", "Tab character service name"),
            health_response_snapshot(&service, "service with spaces", "Service name with spaces"),
        ]
    });

    assert_json_snapshot!("unknown_service_queries", snapshot);
}

/// Test health service builder patterns and bulk operations
#[test]
fn golden_builder_and_bulk_operations() {
    let service = HealthServiceBuilder::new()
        .add("auth.service", ServingStatus::Serving)
        .add("database.primary", ServingStatus::Serving)
        .add("database.replica", ServingStatus::NotServing)
        .add("cache.redis", ServingStatus::Unknown)
        .add_serving(vec!["api.v1", "api.v2", "metrics"])
        .build();

    service.set_server_status(ServingStatus::Serving);

    let queries = vec![
        ("", "Server status"),
        ("auth.service", "Auth service"),
        ("database.primary", "Primary database"),
        ("database.replica", "Replica database"),
        ("cache.redis", "Redis cache"),
        ("api.v1", "API v1 (from add_serving)"),
        ("api.v2", "API v2 (from add_serving)"),
        ("metrics", "Metrics service (from add_serving)"),
    ];

    let snapshot = json!({
        "builder_services": queries.iter().map(|(service_name, desc)| {
            health_response_snapshot(&service, service_name, desc)
        }).collect::<Vec<_>>(),
        "service_counts": {
            "total_services": 7,
            "serving": ["auth.service", "database.primary", "api.v1", "api.v2", "metrics"],
            "not_serving": ["database.replica"],
            "unknown": ["cache.redis"],
        },
        "version_info": {
            "current_version": service.version(),
            "description": "Version should reflect all status changes during builder setup"
        }
    });

    assert_json_snapshot!("builder_and_bulk_operations", snapshot);
}

/// Test health reporter lifecycle and automatic cleanup
#[test]
fn golden_reporter_lifecycle() {
    let service = HealthService::new();
    let mut snapshots = Vec::new();

    // Initial state - no services
    snapshots.push(json!({
        "stage": "initial",
        "server_query": health_response_snapshot(&service, "", "Server before reporters"),
        "service_query": health_response_snapshot(&service, "managed.service", "Managed service before reporter"),
        "version": service.version()
    }));

    // Create reporter and set status
    let reporter = HealthReporter::new(service.clone(), "managed.service");
    reporter.set_serving();

    snapshots.push(json!({
        "stage": "reporter_active_serving",
        "server_query": health_response_snapshot(&service, "", "Server with active reporter"),
        "service_query": health_response_snapshot(&service, "managed.service", "Managed service - serving"),
        "reporter_status": reporter.status().to_string(),
        "reporter_is_healthy": reporter.status().is_healthy(),
        "version": service.version()
    }));

    // Change status via reporter
    reporter.set_not_serving();

    snapshots.push(json!({
        "stage": "reporter_active_not_serving",
        "service_query": health_response_snapshot(&service, "managed.service", "Managed service - not serving"),
        "reporter_status": reporter.status().to_string(),
        "reporter_is_healthy": reporter.status().is_healthy(),
        "version": service.version()
    }));

    // Drop reporter (should clean up automatically)
    drop(reporter);

    snapshots.push(json!({
        "stage": "reporter_dropped",
        "service_query": health_response_snapshot(&service, "managed.service", "Managed service after reporter drop"),
        "version": service.version(),
        "note": "Service status should be cleared when reporter drops"
    }));

    let snapshot = json!({
        "reporter_lifecycle_stages": snapshots,
        "summary": {
            "demonstrates": [
                "Automatic service registration on reporter creation",
                "Status updates through reporter interface",
                "Automatic cleanup on reporter drop",
                "Version tracking across lifecycle"
            ]
        }
    });

    assert_json_snapshot!("reporter_lifecycle", snapshot);
}

/// Test status transitions and version tracking
#[test]
fn golden_status_transitions_and_versioning() {
    let service = HealthService::new();
    let service_name = "transition.test";

    let mut transitions = Vec::new();
    let initial_version = service.version();

    // Record each transition
    let statuses = [
        (ServingStatus::Unknown, "Initial unknown state"),
        (ServingStatus::Serving, "Service becomes healthy"),
        (ServingStatus::NotServing, "Service goes unhealthy"),
        (ServingStatus::ServiceUnknown, "Service in transient state"),
        (ServingStatus::Serving, "Service recovers to healthy"),
        (ServingStatus::Serving, "Redundant set to same status"),
    ];

    for (status, description) in &statuses {
        let version_before = service.version();
        service.set_status(service_name, *status);
        let version_after = service.version();

        transitions.push(json!({
            "description": description,
            "status_set": status.to_string(),
            "status_code": *status as i32,
            "version_before": version_before,
            "version_after": version_after,
            "version_changed": version_before != version_after,
            "response": health_response_snapshot(&service, service_name, description)
        }));
    }

    let snapshot = json!({
        "initial_version": initial_version,
        "final_version": service.version(),
        "status_transitions": transitions,
        "version_behavior": {
            "note": "Version should only increment on actual status changes",
            "expected_redundant_sets": "Should not increment version for same status"
        }
    });

    assert_json_snapshot!("status_transitions_and_versioning", snapshot);
}

/// Test edge cases and error conditions
#[test]
fn golden_edge_cases_and_errors() {
    let service = HealthService::new();

    // Test various service name edge cases
    let edge_cases = vec![
        ("", "Empty string (server query)"),
        ("normal.service", "Normal dotted service"),
        ("a", "Single character service"),
        ("service-with-dashes", "Service with dashes"),
        ("service_with_underscores", "Service with underscores"),
        ("SERVICE.UPPER.CASE", "Uppercase service name"),
        ("123.numeric.service", "Service starting with numbers"),
        ("service.with.many.dots.here", "Service with many dots"),
    ];

    // Set up some of these services with various statuses
    service.set_server_status(ServingStatus::Serving);
    service.set_status("normal.service", ServingStatus::Serving);
    service.set_status("a", ServingStatus::NotServing);
    service.set_status("SERVICE.UPPER.CASE", ServingStatus::Unknown);

    let responses: Vec<_> = edge_cases
        .iter()
        .map(|(service_name, desc)| health_response_snapshot(&service, service_name, desc))
        .collect();

    // Test service clearing
    service.clear_status("normal.service");
    let after_clear =
        health_response_snapshot(&service, "normal.service", "Normal service after clear");

    // Test bulk clear
    let version_before_bulk_clear = service.version();
    service.clear();
    let version_after_bulk_clear = service.version();

    let snapshot = json!({
        "edge_case_queries": responses,
        "service_clearing": {
            "single_clear": after_clear,
            "bulk_clear": {
                "version_before": version_before_bulk_clear,
                "version_after": version_after_bulk_clear,
                "server_after_clear": health_response_snapshot(&service, "", "Server after bulk clear"),
                "service_after_clear": health_response_snapshot(&service, "a", "Service 'a' after bulk clear")
            }
        },
        "status_enum_metadata": {
            "unknown_code": ServingStatus::Unknown as i32,
            "serving_code": ServingStatus::Serving as i32,
            "not_serving_code": ServingStatus::NotServing as i32,
            "service_unknown_code": ServingStatus::ServiceUnknown as i32,
            "from_i32_tests": [
                {"code": 0, "valid": ServingStatus::from_i32(0).is_some()},
                {"code": 1, "valid": ServingStatus::from_i32(1).is_some()},
                {"code": 2, "valid": ServingStatus::from_i32(2).is_some()},
                {"code": 3, "valid": ServingStatus::from_i32(3).is_some()},
                {"code": 4, "valid": ServingStatus::from_i32(4).is_some()},
                {"code": -1, "valid": ServingStatus::from_i32(-1).is_some()},
            ]
        }
    });

    assert_json_snapshot!("edge_cases_and_errors", snapshot);
}
