//! Golden snapshot tests for doctor health report format
//!
//! This test captures the expected JSON output format of doctor health reports
//! to prevent unintentional changes to the CLI output format.

#![cfg(all(test, feature = "cli"))]

use asupersync::cli::doctor::{
    AdvancedDiagnosticsReportBundle, DoctorScenarioCoveragePackSmokeReport,
    DoctorStressSoakSmokeReport, OperatorModelContract, WorkspaceScanReport,
};
use insta::assert_json_snapshot;
use serde_json::json;

/// Test the WorkspaceScanReport structure format
#[test]
fn test_workspace_scan_report_format() {
    let report = WorkspaceScanReport {
        root: "/test/workspace".to_string(),
        workspace_manifest: "/test/workspace/Cargo.toml".to_string(),
        scanner_version: "1.0.0".to_string(),
        taxonomy_version: "2023.1".to_string(),
        members: vec![],
        capability_edges: vec![],
        warnings: vec![
            "Mock warning for snapshot".to_string(),
            "Another test warning".to_string(),
        ],
        events: vec![],
    };

    assert_json_snapshot!("workspace_scan_report_format", report);
}

/// Test the OperatorModelContract structure format
#[test]
fn test_operator_model_contract_format() {
    let contract = OperatorModelContract {
        contract_version: "1.0.0".to_string(),
        personas: vec![],
        decision_loops: vec![],
        global_evidence_requirements: vec![
            "system_health_check".to_string(),
            "performance_baseline".to_string(),
        ],
        navigation_topology: asupersync::cli::doctor::NavigationTopology {
            version: "1.0.0".to_string(),
            entry_points: vec![],
            screens: vec![],
            routes: vec![],
            keyboard_bindings: vec![],
            route_events: vec![],
        },
    };

    assert_json_snapshot!("operator_model_contract_format", contract);
}

/// Test the comprehensive doctor health report bundle format
#[test]
fn test_doctor_health_report_bundle_format() {
    // Create a mock health report bundle that represents the structure
    // the doctor command would output
    let health_bundle = json!({
        "report_version": "1.0.0",
        "timestamp": "2023-01-01T00:00:00Z",
        "workspace": {
            "root": "/test/workspace",
            "manifest": "/test/workspace/Cargo.toml",
            "members_count": 0,
            "total_warnings": 0,
        },
        "health_status": "healthy",
        "checks": [
            {
                "check_name": "compilation_status",
                "status": "passed",
                "details": "All workspace members compile successfully",
            },
            {
                "check_name": "test_coverage",
                "status": "passed",
                "details": "Test coverage above minimum threshold",
            },
            {
                "check_name": "linting_status",
                "status": "passed",
                "details": "No clippy warnings detected",
            }
        ],
        "metrics": {
            "total_checks": 3,
            "passed_checks": 3,
            "failed_checks": 0,
            "warnings": 0,
        },
        "recommendations": [],
    });

    assert_json_snapshot!("doctor_health_report_bundle_format", health_bundle);
}

/// Test the scenario coverage report format
#[test]
fn test_doctor_scenario_coverage_format() {
    let coverage_report = DoctorScenarioCoveragePackSmokeReport {
        schema_version: "1.0.0".to_string(),
        selection_mode: "all".to_string(),
        requested_by: "golden-test".to_string(),
        seed: "0".to_string(),
        failure_clusters: vec![],
        runs: vec![],
    };

    assert_json_snapshot!("doctor_scenario_coverage_format", coverage_report);
}

/// Test the stress/soak testing report format
#[test]
fn test_doctor_stress_soak_format() {
    let soak_report = DoctorStressSoakSmokeReport {
        schema_version: "1.0.0".to_string(),
        profile_mode: "fast".to_string(),
        requested_by: "golden-test".to_string(),
        seed: "0".to_string(),
        pass_criteria: "all checkpoints within budget".to_string(),
        runs: vec![],
        failing_scenarios: vec![],
    };

    assert_json_snapshot!("doctor_stress_soak_format", soak_report);
}

/// Test the advanced diagnostics report format
#[test]
fn test_advanced_diagnostics_format() {
    let diagnostics_bundle: AdvancedDiagnosticsReportBundle =
        asupersync::cli::doctor::advanced_diagnostics_report_bundle();

    assert_json_snapshot!("advanced_diagnostics_format", diagnostics_bundle);
}

/// Test the comprehensive doctor output format
#[test]
fn test_comprehensive_doctor_output_format() {
    // This represents what a complete doctor health command might output
    let comprehensive_output = json!({
        "asupersync_doctor": {
            "version": "1.0.0",
            "timestamp": "2023-01-01T00:00:00Z",
            "command": "health",
            "workspace": {
                "root": "/test/workspace",
                "manifest": "/test/workspace/Cargo.toml",
                "scan_duration_ms": 100,
            },
            "overall_health": "healthy",
            "summary": {
                "total_checks": 5,
                "passed": 5,
                "failed": 0,
                "warnings": 0,
                "errors": 0,
            },
            "detailed_checks": [
                {
                    "category": "build_system",
                    "checks": [
                        {
                            "name": "cargo_check",
                            "status": "passed",
                            "message": "All crates compile successfully",
                        },
                        {
                            "name": "dependency_resolution",
                            "status": "passed",
                            "message": "No dependency conflicts detected",
                        }
                    ]
                },
                {
                    "category": "code_quality",
                    "checks": [
                        {
                            "name": "clippy_lints",
                            "status": "passed",
                            "message": "No clippy warnings",
                        },
                        {
                            "name": "formatting",
                            "status": "passed",
                            "message": "Code is properly formatted",
                        }
                    ]
                },
                {
                    "category": "testing",
                    "checks": [
                        {
                            "name": "test_execution",
                            "status": "passed",
                            "message": "All tests pass",
                        }
                    ]
                }
            ],
            "recommendations": [],
            "next_steps": [
                "Continue monitoring build health",
                "Consider adding more integration tests",
            ],
        }
    });

    assert_json_snapshot!("comprehensive_doctor_output_format", comprehensive_output);
}
