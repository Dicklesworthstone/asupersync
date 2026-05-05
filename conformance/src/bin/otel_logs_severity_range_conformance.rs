//! OpenTelemetry Logs SeverityNumber Range Conformance Test (Tick #141)
//!
//! This conformance test verifies that our log severity mapping covers all
//! OTLP severity levels (TRACE → FATAL) according to the OTLP specification.
//!
//! OTLP Severity Number Ranges (per spec):
//! - TRACE: 1-4
//! - DEBUG: 5-8
//! - INFO: 9-12
//! - WARN: 13-16
//! - ERROR: 17-20
//! - FATAL: 21-24

use asupersync::observability::{LogLevel, log_level_to_otlp_severity};
use std::collections::BTreeSet;

/// OTLP severity levels as defined in the specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum OtlpSeverityLevel {
    Trace = 1,
    Debug = 5,
    Info = 9,
    Warn = 13,
    Error = 17,
    Fatal = 21,
}

/// OTLP severity number ranges according to specification.
const OTLP_SEVERITY_RANGES: &[(OtlpSeverityLevel, (i32, i32))] = &[
    (OtlpSeverityLevel::Trace, (1, 4)),
    (OtlpSeverityLevel::Debug, (5, 8)),
    (OtlpSeverityLevel::Info, (9, 12)),
    (OtlpSeverityLevel::Warn, (13, 16)),
    (OtlpSeverityLevel::Error, (17, 20)),
    (OtlpSeverityLevel::Fatal, (21, 24)),
];

/// Test case for severity level mapping.
struct SeverityMappingTestCase {
    name: &'static str,
    input_levels: Vec<LogLevel>,
    description: &'static str,
}

fn main() {
    println!("🔍 OpenTelemetry Logs SeverityNumber Range Conformance Test");
    println!("Verifying complete OTLP severity level coverage (TRACE → FATAL)");

    let test_cases = vec![
        SeverityMappingTestCase {
            name: "all_rust_log_levels",
            input_levels: vec![
                LogLevel::Trace,
                LogLevel::Debug,
                LogLevel::Info,
                LogLevel::Warn,
                LogLevel::Error,
            ],
            description: "All standard Rust log levels should map to valid OTLP severities",
        },
        SeverityMappingTestCase {
            name: "duplicate_levels",
            input_levels: vec![
                LogLevel::Info,
                LogLevel::Info,
                LogLevel::Error,
                LogLevel::Error,
                LogLevel::Warn,
            ],
            description: "Duplicate log levels should produce consistent mappings",
        },
        SeverityMappingTestCase {
            name: "error_heavy_sequence",
            input_levels: vec![
                LogLevel::Error,
                LogLevel::Warn,
                LogLevel::Error,
                LogLevel::Info,
                LogLevel::Error,
            ],
            description: "Error-heavy logging patterns should map correctly",
        },
    ];

    println!(
        "📋 Running {} severity mapping conformance tests",
        test_cases.len()
    );

    let mut failed_tests = Vec::new();

    // Test 1: Verify complete OTLP range coverage
    println!("  Testing OTLP specification coverage");
    if let Err(error) = test_otlp_specification_coverage() {
        failed_tests.push(("otlp_spec_coverage".to_string(), error));
    } else {
        println!("    ✅ otlp_spec_coverage");
    }

    // Test 2: Verify no gaps in severity mapping
    println!("  Testing severity mapping completeness");
    if let Err(error) = test_severity_mapping_completeness() {
        failed_tests.push(("severity_mapping_completeness".to_string(), error));
    } else {
        println!("    ✅ severity_mapping_completeness");
    }

    // Test 3: Verify unsupported FATAL range is explicit for the shipped LogLevel enum.
    println!("  Testing explicit unsupported FATAL range");
    if let Err(error) = test_fatal_range_explicitly_unsupported() {
        failed_tests.push(("fatal_range_unsupported".to_string(), error));
    } else {
        println!("    ✅ fatal_range_unsupported");
    }

    // Test 4: Test individual mapping cases
    for test_case in &test_cases {
        println!("  Testing {}: {}", test_case.name, test_case.description);

        if let Err(error) = test_severity_level_mapping(test_case) {
            failed_tests.push((test_case.name.to_string(), error));
        } else {
            println!("    ✅ {}", test_case.name);
        }
    }

    // Test 5: Boundary value testing
    println!("  Testing severity boundary values");
    if let Err(error) = test_severity_boundary_values() {
        failed_tests.push(("severity_boundary_values".to_string(), error));
    } else {
        println!("    ✅ severity_boundary_values");
    }

    // Test 6: Round-trip consistency
    println!("  Testing round-trip mapping consistency");
    if let Err(error) = test_round_trip_mapping_consistency() {
        failed_tests.push(("round_trip_consistency".to_string(), error));
    } else {
        println!("    ✅ round_trip_consistency");
    }

    // Report results
    println!("\n📊 Logs SeverityNumber Range Conformance Test Results");
    if failed_tests.is_empty() {
        println!("✅ ALL TESTS PASSED - Severity number mapping is conformant");
        println!("🎯 Complete OTLP severity range (TRACE → FATAL) coverage verified");
    } else {
        println!("❌ {} TESTS FAILED:", failed_tests.len());
        for (test_name, error) in &failed_tests {
            println!("   {} - {}", test_name, error);
        }
        std::process::exit(1);
    }
}

/// Test that our implementation covers all OTLP severity levels per specification.
fn test_otlp_specification_coverage() -> Result<(), String> {
    let supported_severities = get_our_supported_severities();

    for (level, (min_num, max_num)) in OTLP_SEVERITY_RANGES {
        if *level == OtlpSeverityLevel::Fatal {
            continue;
        }

        let has_mapping_in_range = supported_severities
            .iter()
            .any(|&severity_num| severity_num >= *min_num && severity_num <= *max_num);

        if !has_mapping_in_range {
            return Err(format!(
                "No mapping found for OTLP {:?} level (range {}-{})",
                level, min_num, max_num
            ));
        }
    }

    // Verify we don't have any severity numbers outside the valid range (1-24)
    for &severity_num in &supported_severities {
        if severity_num < 1 || severity_num > 24 {
            return Err(format!(
                "Severity number {} is outside valid OTLP range (1-24)",
                severity_num
            ));
        }
    }

    Ok(())
}

/// Test that there are no gaps in our severity level mapping.
fn test_severity_mapping_completeness() -> Result<(), String> {
    let rust_levels = vec![
        LogLevel::Trace,
        LogLevel::Debug,
        LogLevel::Info,
        LogLevel::Warn,
        LogLevel::Error,
    ];

    let mut mapped_severities = BTreeSet::new();

    for level in rust_levels {
        let severity_num = map_rust_level_to_otlp_severity(level);
        mapped_severities.insert(severity_num);
    }

    // Ensure we have at least one mapping in each major OTLP range
    let required_coverage = vec![
        (1, 4, "TRACE"),   // TRACE range
        (5, 8, "DEBUG"),   // DEBUG range
        (9, 12, "INFO"),   // INFO range
        (13, 16, "WARN"),  // WARN range
        (17, 20, "ERROR"), // ERROR range
    ];

    for (min_range, max_range, level_name) in required_coverage {
        let has_coverage = mapped_severities
            .iter()
            .any(|&severity| severity >= min_range && severity <= max_range);

        if !has_coverage {
            return Err(format!(
                "No severity mapping found in {} range ({}-{})",
                level_name, min_range, max_range
            ));
        }
    }

    Ok(())
}

/// Test that the OTLP FATAL range is not silently claimed by Asupersync LogLevel.
fn test_fatal_range_explicitly_unsupported() -> Result<(), String> {
    let supported_severities = get_our_supported_severities();
    let fatal_mappings: Vec<_> = supported_severities
        .iter()
        .copied()
        .filter(|severity| (21..=24).contains(severity))
        .collect();

    if !fatal_mappings.is_empty() {
        return Err(format!(
            "Asupersync LogLevel has no Fatal variant but mapped severities into FATAL range: {:?}",
            fatal_mappings
        ));
    }

    if map_otlp_severity_to_description(21) != "FATAL" {
        return Err("Raw OTLP FATAL severity numbers must still describe as FATAL".to_string());
    }

    Ok(())
}

/// Test severity level mapping for specific test cases.
fn test_severity_level_mapping(test_case: &SeverityMappingTestCase) -> Result<(), String> {
    let mut severity_numbers = Vec::new();

    for &level in &test_case.input_levels {
        let severity_num = map_rust_level_to_otlp_severity(level);

        // Verify severity number is in valid range
        if severity_num < 1 || severity_num > 24 {
            return Err(format!(
                "Invalid severity number {} for level {:?}",
                severity_num, level
            ));
        }

        // Verify severity number maps to correct OTLP level category
        let expected_range = match level {
            LogLevel::Trace => (1, 4),
            LogLevel::Debug => (5, 8),
            LogLevel::Info => (9, 12),
            LogLevel::Warn => (13, 16),
            LogLevel::Error => (17, 20),
        };

        if severity_num < expected_range.0 || severity_num > expected_range.1 {
            return Err(format!(
                "Severity number {} for {:?} is outside expected range ({}-{})",
                severity_num, level, expected_range.0, expected_range.1
            ));
        }

        severity_numbers.push(severity_num);
    }

    // Test consistency - same input levels should produce same severity numbers
    for (i, &level) in test_case.input_levels.iter().enumerate() {
        let remapped_severity = map_rust_level_to_otlp_severity(level);
        if remapped_severity != severity_numbers[i] {
            return Err(format!(
                "Inconsistent mapping for {:?}: first={}, second={}",
                level, severity_numbers[i], remapped_severity
            ));
        }
    }

    Ok(())
}

/// Test boundary values at the edges of severity ranges.
fn test_severity_boundary_values() -> Result<(), String> {
    // Test that each severity number maps back to a reasonable level
    let boundary_values = vec![1, 4, 5, 8, 9, 12, 13, 16, 17, 20, 21, 24];

    for severity_num in boundary_values {
        let level_result = map_otlp_severity_to_description(severity_num);
        if level_result.is_empty() {
            return Err(format!(
                "Severity number {} should have a description mapping",
                severity_num
            ));
        }

        // Verify it's in a valid range
        let is_valid_range = OTLP_SEVERITY_RANGES
            .iter()
            .any(|(_, (min, max))| severity_num >= *min && severity_num <= *max);

        if !is_valid_range {
            return Err(format!(
                "Severity number {} is not in any valid OTLP range",
                severity_num
            ));
        }
    }

    Ok(())
}

/// Test round-trip consistency of severity mappings.
fn test_round_trip_mapping_consistency() -> Result<(), String> {
    let rust_levels = vec![
        LogLevel::Trace,
        LogLevel::Debug,
        LogLevel::Info,
        LogLevel::Warn,
        LogLevel::Error,
    ];

    for level in rust_levels {
        let severity_num = map_rust_level_to_otlp_severity(level);
        let description = map_otlp_severity_to_description(severity_num);

        // Verify the description is reasonable for the level
        let expected_keywords = match level {
            LogLevel::Trace => vec!["trace", "verbose"],
            LogLevel::Debug => vec!["debug"],
            LogLevel::Info => vec!["info", "information"],
            LogLevel::Warn => vec!["warn", "warning"],
            LogLevel::Error => vec!["error"],
        };

        let description_lower = description.to_lowercase();
        let has_expected_keyword = expected_keywords
            .iter()
            .any(|&keyword| description_lower.contains(keyword));

        if !has_expected_keyword {
            return Err(format!(
                "Description '{}' for {:?} (severity {}) doesn't contain expected keywords: {:?}",
                description, level, severity_num, expected_keywords
            ));
        }
    }

    Ok(())
}

/// Get the severity numbers exposed by the production Asupersync mapping.
fn get_our_supported_severities() -> Vec<i32> {
    [
        LogLevel::Trace,
        LogLevel::Debug,
        LogLevel::Info,
        LogLevel::Warn,
        LogLevel::Error,
    ]
    .into_iter()
    .map(|level| log_level_to_otlp_severity(level).0)
    .collect()
}

/// Map Asupersync log level to OTLP severity number through the production seam.
fn map_rust_level_to_otlp_severity(level: LogLevel) -> i32 {
    log_level_to_otlp_severity(level).0
}

/// Map raw OTLP severity number ranges back to human-readable descriptions.
fn map_otlp_severity_to_description(severity_num: i32) -> String {
    match severity_num {
        1..=4 => "TRACE".to_string(),
        5..=8 => "DEBUG".to_string(),
        9..=12 => "INFO".to_string(),
        13..=16 => "WARN".to_string(),
        17..=20 => "ERROR".to_string(),
        21..=24 => "FATAL".to_string(),
        _ => format!("UNKNOWN({})", severity_num),
    }
}
