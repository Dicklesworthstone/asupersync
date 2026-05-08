//! OpenTelemetry Baggage Propagation Conformance Guard
//!
//! This binary exercises local W3C baggage header generation and roundtrip
//! behavior, but it must not claim differential conformance until an independent
//! live reference is wired.

use clap::{Arg, Command};
use opentelemetry::Context;
use opentelemetry::baggage::{BaggageExt, KeyValueMetadata};
use opentelemetry::propagation::{Extractor, Injector, TextMapPropagator};
use opentelemetry_sdk::propagation::BaggagePropagator;
use std::collections::HashMap;

const OTEL_BAGGAGE_REFERENCE_UNIMPLEMENTED: &str =
    "live independent OpenTelemetry baggage reference is not wired";

/// Conformance test result tracking
#[derive(Debug, Clone, PartialEq)]
enum ConformanceTestResult {
    Fail { reason: String },
    ExpectedFailure { reason: String },
}

#[derive(Debug, PartialEq)]
enum RequirementLevel {
    Must,   // W3C baggage spec MUST clause
    Should, // W3C baggage spec SHOULD clause
}

/// Test cases for baggage propagation conformance
struct BaggagePropagationTestCase {
    name: &'static str,
    description: &'static str,
    baggage_entries: Vec<BaggageEntry>,
    requirement_level: RequirementLevel,
}

/// Individual baggage entry for testing
#[derive(Clone, Debug)]
struct BaggageEntry {
    key: String,
    value: String,
    metadata: Option<String>,
}

/// Simple carrier implementation for headers
#[derive(Debug, Default)]
struct HeaderCarrier {
    headers: HashMap<String, String>,
}

impl Injector for HeaderCarrier {
    fn set(&mut self, key: &str, value: String) {
        self.headers.insert(key.to_string(), value);
    }
}

impl Extractor for HeaderCarrier {
    fn get(&self, key: &str) -> Option<&str> {
        self.headers.get(key).map(|s| s.as_str())
    }

    fn keys(&self) -> Vec<&str> {
        self.headers.keys().map(|s| s.as_str()).collect()
    }
}

fn main() {
    env_logger::init();

    let matches = Command::new("otel_baggage_propagation_conformance")
        .version("0.1.0")
        .about("OpenTelemetry Baggage Propagation fail-closed conformance guard")
        .arg(
            Arg::new("test")
                .help("Test to run")
                .value_parser([
                    "basic-baggage-headers",
                    "baggage-with-metadata",
                    "multiple-baggage-entries",
                    "url-encoding-handling",
                    "size-limits-truncation",
                    "invalid-character-handling",
                    "empty-values-handling",
                    "baggage-roundtrip",
                    "w3c-header-format",
                    "report",
                    "all",
                ])
                .default_value("all"),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .help("Verbose output")
                .action(clap::ArgAction::SetTrue),
        )
        .get_matches();

    let test_name = matches.get_one::<String>("test").unwrap();
    let verbose = matches.get_flag("verbose");

    match test_name.as_str() {
        "basic-baggage-headers" => exit_if_not_pass(
            "basic-baggage-headers",
            run_basic_baggage_headers_test(verbose),
        ),
        "baggage-with-metadata" => exit_if_not_pass(
            "baggage-with-metadata",
            run_baggage_with_metadata_test(verbose),
        ),
        "multiple-baggage-entries" => exit_if_not_pass(
            "multiple-baggage-entries",
            run_multiple_baggage_entries_test(verbose),
        ),
        "url-encoding-handling" => exit_if_not_pass(
            "url-encoding-handling",
            run_url_encoding_handling_test(verbose),
        ),
        "size-limits-truncation" => exit_if_not_pass(
            "size-limits-truncation",
            run_size_limits_truncation_test(verbose),
        ),
        "invalid-character-handling" => exit_if_not_pass(
            "invalid-character-handling",
            run_invalid_character_handling_test(verbose),
        ),
        "empty-values-handling" => exit_if_not_pass(
            "empty-values-handling",
            run_empty_values_handling_test(verbose),
        ),
        "baggage-roundtrip" => {
            exit_if_not_pass("baggage-roundtrip", run_baggage_roundtrip_test(verbose))
        }
        "w3c-header-format" => {
            exit_if_not_pass("w3c-header-format", run_w3c_header_format_test(verbose))
        }
        "report" => {
            generate_compliance_report();
            return;
        }
        "all" => run_all_tests(verbose),
        _ => {
            eprintln!("Unknown test: {}", test_name);
            std::process::exit(1);
        }
    }
}

fn exit_if_not_pass(test_name: &str, result: ConformanceTestResult) {
    let exit_code = exit_code_for_result(&result);
    if exit_code == 0 {
        return;
    }

    match result {
        ConformanceTestResult::Fail { reason } => {
            eprintln!("{test_name}: FAIL - {reason}");
        }
        ConformanceTestResult::ExpectedFailure { reason } => {
            eprintln!("{test_name}: XFAIL - {reason}");
        }
    }

    std::process::exit(exit_code);
}

fn run_all_tests(verbose: bool) {
    println!("=== OpenTelemetry Baggage Propagation Conformance Guard ===\n");

    let mut total = 0;
    let passed = 0;
    let mut failed = 0;
    let mut xfail = 0;

    // Define test cases
    let test_cases = vec![
        BaggagePropagationTestCase {
            name: "basic-baggage-headers",
            description: "Basic baggage key=value pairs produce a W3C baggage header",
            requirement_level: RequirementLevel::Must,
            baggage_entries: vec![
                BaggageEntry {
                    key: "userId".to_string(),
                    value: "alice".to_string(),
                    metadata: None,
                },
                BaggageEntry {
                    key: "sessionId".to_string(),
                    value: "abc123".to_string(),
                    metadata: None,
                },
                BaggageEntry {
                    key: "tier".to_string(),
                    value: "premium".to_string(),
                    metadata: None,
                },
            ],
        },
        BaggagePropagationTestCase {
            name: "baggage-with-metadata",
            description: "Baggage entries with metadata serialize to W3C format",
            requirement_level: RequirementLevel::Must,
            baggage_entries: vec![
                BaggageEntry {
                    key: "userId".to_string(),
                    value: "alice".to_string(),
                    metadata: Some("sensitive".to_string()),
                },
                BaggageEntry {
                    key: "region".to_string(),
                    value: "us-west".to_string(),
                    metadata: Some("datacenter=pdx;priority=high".to_string()),
                },
            ],
        },
        BaggagePropagationTestCase {
            name: "multiple-baggage-entries",
            description: "Multiple baggage entries serialize with comma separation",
            requirement_level: RequirementLevel::Must,
            baggage_entries: vec![
                BaggageEntry {
                    key: "key1".to_string(),
                    value: "value1".to_string(),
                    metadata: None,
                },
                BaggageEntry {
                    key: "key2".to_string(),
                    value: "value2".to_string(),
                    metadata: Some("meta2".to_string()),
                },
                BaggageEntry {
                    key: "key3".to_string(),
                    value: "value3".to_string(),
                    metadata: None,
                },
                BaggageEntry {
                    key: "key4".to_string(),
                    value: "value4".to_string(),
                    metadata: Some("meta4".to_string()),
                },
            ],
        },
        BaggagePropagationTestCase {
            name: "url-encoding-handling",
            description: "Special characters in baggage are URL-encoded locally",
            requirement_level: RequirementLevel::Must,
            baggage_entries: vec![
                BaggageEntry {
                    key: "encoded key".to_string(),
                    value: "encoded=value&test".to_string(),
                    metadata: None,
                },
                BaggageEntry {
                    key: "special".to_string(),
                    value: "hello,world;test".to_string(),
                    metadata: Some("meta=data".to_string()),
                },
                BaggageEntry {
                    key: "unicode".to_string(),
                    value: "café".to_string(),
                    metadata: None,
                },
            ],
        },
        BaggagePropagationTestCase {
            name: "size-limits-truncation",
            description: "Baggage size limits are exercised by local propagation",
            requirement_level: RequirementLevel::Should,
            baggage_entries: vec![
                BaggageEntry {
                    key: "large_key".to_string(),
                    value: "x".repeat(1000), // Large value to test size limits
                    metadata: None,
                },
                BaggageEntry {
                    key: "normal".to_string(),
                    value: "normal_value".to_string(),
                    metadata: None,
                },
            ],
        },
        BaggagePropagationTestCase {
            name: "invalid-character-handling",
            description: "Invalid characters are exercised by local propagation",
            requirement_level: RequirementLevel::Must,
            baggage_entries: vec![
                BaggageEntry {
                    key: "control".to_string(),
                    value: "value\twith\tcontrol".to_string(),
                    metadata: None,
                },
                BaggageEntry {
                    key: "newline".to_string(),
                    value: "value\nwith\nnewline".to_string(),
                    metadata: None,
                },
            ],
        },
        BaggagePropagationTestCase {
            name: "empty-values-handling",
            description: "Empty baggage values are exercised by local propagation",
            requirement_level: RequirementLevel::Must,
            baggage_entries: vec![
                BaggageEntry {
                    key: "empty_value".to_string(),
                    value: "".to_string(),
                    metadata: None,
                },
                BaggageEntry {
                    key: "space_value".to_string(),
                    value: " ".to_string(),
                    metadata: None,
                },
                BaggageEntry {
                    key: "normal".to_string(),
                    value: "normal".to_string(),
                    metadata: None,
                },
            ],
        },
        BaggagePropagationTestCase {
            name: "baggage-roundtrip",
            description: "Baggage inject→extract roundtrip preserves data",
            requirement_level: RequirementLevel::Must,
            baggage_entries: vec![BaggageEntry {
                key: "roundtrip_key".to_string(),
                value: "roundtrip_value".to_string(),
                metadata: Some("roundtrip_meta".to_string()),
            }],
        },
        BaggagePropagationTestCase {
            name: "w3c-header-format",
            description: "W3C baggage header format local guard",
            requirement_level: RequirementLevel::Must,
            baggage_entries: vec![BaggageEntry {
                key: "format_test".to_string(),
                value: "format_value".to_string(),
                metadata: Some("prop1=val1;prop2=val2".to_string()),
            }],
        },
    ];

    println!(
        "📋 Running {} Baggage Propagation conformance tests\n",
        test_cases.len()
    );

    for test_case in &test_cases {
        total += 1;

        print!(
            "  Testing {}: {} ... ",
            test_case.name, test_case.description
        );

        let result = run_baggage_propagation_conformance_test(test_case, verbose);

        match &result {
            ConformanceTestResult::Fail { reason } => {
                failed += 1;
                println!("❌ FAIL");
                if verbose {
                    println!("    Reason: {}", reason);
                }
            }
            ConformanceTestResult::ExpectedFailure { reason } => {
                xfail += 1;
                println!("⚠️ XFAIL");
                if verbose {
                    println!("    Expected failure: {}", reason);
                }
            }
        }

        // Output structured JSON for CI parsing
        eprintln!(
            "{{\"test\":\"{}\",\"status\":\"{}\",\"level\":\"{:?}\"}}",
            test_case.name,
            match &result {
                ConformanceTestResult::Fail { .. } => "FAIL",
                ConformanceTestResult::ExpectedFailure { .. } => "XFAIL",
            },
            test_case.requirement_level
        );
    }

    // Generate compliance report
    println!("\n📊 OpenTelemetry Baggage Propagation Conformance Results");
    println!("┌─────────────────────────────────────┐");
    println!("│          CONFORMANCE REPORT         │");
    println!("├─────────────────────────────────────┤");
    println!("│  📋 Total: {}                      │", total);
    println!("│  ✅ Passed: {}                     │", passed);
    println!("│  ❌ Failed: {}                     │", failed);
    println!("│  ⚠️ Expected: {}                   │", xfail);
    println!("│                                     │");
    let score = if total > 0 {
        (passed as f64 / total as f64) * 100.0
    } else {
        0.0
    };
    println!("│  🎯 Score: {:.1}%                   │", score);
    println!("└─────────────────────────────────────┘");

    println!("\n{}", final_status_line(total, failed, xfail));

    if exit_code_for_summary(total, failed, xfail) != 0 {
        eprintln!("\nLive reference unavailable; refusing to claim baggage conformance");
        std::process::exit(exit_code_for_summary(total, failed, xfail));
    } else {
        println!("🎯 W3C baggage header output matches the independent reference");
    }
}

fn exit_code_for_result(result: &ConformanceTestResult) -> i32 {
    match result {
        ConformanceTestResult::Fail { .. } | ConformanceTestResult::ExpectedFailure { .. } => 1,
    }
}

fn exit_code_for_summary(total: usize, failed: usize, expected_failures: usize) -> i32 {
    if total == 0 || failed > 0 || expected_failures > 0 {
        1
    } else {
        0
    }
}

fn final_status_line(total: usize, failed: usize, expected_failures: usize) -> String {
    if total == 0 {
        "NO TESTS EXECUTED".to_string()
    } else if failed > 0 {
        format!("FAILURES PRESENT ({failed} failed, {expected_failures} expected failures)")
    } else if expected_failures > 0 {
        format!("NO FAILURES; PARTIAL COVERAGE ({expected_failures} expected failures)")
    } else {
        "✅ ALL TESTS PASSED - live baggage reference matched".to_string()
    }
}

/// Run conformance test for a single test case
fn run_baggage_propagation_conformance_test(
    test_case: &BaggagePropagationTestCase,
    verbose: bool,
) -> ConformanceTestResult {
    let our_header = match generate_our_baggage_header(test_case, verbose) {
        Ok(header) => header,
        Err(e) => {
            return ConformanceTestResult::Fail {
                reason: format!("Failed to generate our baggage header: {}", e),
            };
        }
    };

    if verbose {
        println!("\n    Our header: '{}'", our_header);
    }

    if !test_case.baggage_entries.is_empty() && our_header.is_empty() {
        return ConformanceTestResult::Fail {
            reason: "local baggage propagation produced no baggage header".to_string(),
        };
    }

    live_baggage_reference_unavailable(test_case.name)
}

fn live_baggage_reference_unavailable(test_name: &str) -> ConformanceTestResult {
    ConformanceTestResult::ExpectedFailure {
        reason: format!(
            "{OTEL_BAGGAGE_REFERENCE_UNIMPLEMENTED} for '{test_name}'; refusing synthetic self-comparison"
        ),
    }
}

/// Generate baggage header using our implementation
fn generate_our_baggage_header(
    test_case: &BaggagePropagationTestCase,
    _verbose: bool,
) -> Result<String, String> {
    let propagator = BaggagePropagator::new();

    let context = context_with_test_baggage(test_case);

    // Inject into carrier
    let mut carrier = HeaderCarrier::default();
    propagator.inject_context(&context, &mut carrier);

    // Get baggage header
    Ok(carrier
        .headers
        .get("baggage")
        .unwrap_or(&String::new())
        .clone())
}

fn context_with_test_baggage(test_case: &BaggagePropagationTestCase) -> Context {
    let baggage = test_case
        .baggage_entries
        .iter()
        .map(|entry| {
            KeyValueMetadata::new(
                entry.key.clone(),
                entry.value.clone(),
                entry.metadata.as_deref().unwrap_or(""),
            )
        })
        .collect::<Vec<_>>();

    Context::current_with_baggage(baggage)
}

/// Test roundtrip: inject baggage → extract baggage → compare
fn test_baggage_roundtrip(
    test_case: &BaggagePropagationTestCase,
    _verbose: bool,
) -> Result<(), String> {
    let propagator = BaggagePropagator::new();

    let original_context = context_with_test_baggage(test_case);

    // Inject into carrier
    let mut carrier = HeaderCarrier::default();
    propagator.inject_context(&original_context, &mut carrier);

    // Extract from carrier
    let extracted_context = propagator.extract(&carrier);

    // Compare baggage entries
    let extracted_baggage = extracted_context.baggage();

    for entry in &test_case.baggage_entries {
        let Some((extracted_value, extracted_metadata)) =
            extracted_baggage.get_with_metadata(&entry.key)
        else {
            return Err(format!("Roundtrip failed for key '{}': missing", entry.key));
        };

        if extracted_value.as_str() != entry.value.trim() {
            return Err(format!(
                "Roundtrip failed for key '{}': original={:?}, extracted={:?}",
                entry.key, entry.value, extracted_value
            ));
        }

        let expected_metadata = entry.metadata.as_deref().unwrap_or("").trim();
        if extracted_metadata.as_str() != expected_metadata {
            return Err(format!(
                "Roundtrip metadata failed for key '{}': original={:?}, extracted={:?}",
                entry.key, expected_metadata, extracted_metadata
            ));
        }
    }

    Ok(())
}

/// Individual test runners for specific test cases
fn run_basic_baggage_headers_test(verbose: bool) -> ConformanceTestResult {
    let test_case = BaggagePropagationTestCase {
        name: "basic-baggage-headers",
        description: "Basic baggage headers",
        requirement_level: RequirementLevel::Must,
        baggage_entries: vec![BaggageEntry {
            key: "userId".to_string(),
            value: "alice".to_string(),
            metadata: None,
        }],
    };

    run_baggage_propagation_conformance_test(&test_case, verbose)
}

fn run_baggage_with_metadata_test(verbose: bool) -> ConformanceTestResult {
    let test_case = BaggagePropagationTestCase {
        name: "baggage-with-metadata",
        description: "Baggage with metadata",
        requirement_level: RequirementLevel::Must,
        baggage_entries: vec![BaggageEntry {
            key: "userId".to_string(),
            value: "alice".to_string(),
            metadata: Some("sensitive".to_string()),
        }],
    };

    run_baggage_propagation_conformance_test(&test_case, verbose)
}

fn run_multiple_baggage_entries_test(verbose: bool) -> ConformanceTestResult {
    let test_case = BaggagePropagationTestCase {
        name: "multiple-baggage-entries",
        description: "Multiple baggage entries",
        requirement_level: RequirementLevel::Must,
        baggage_entries: vec![
            BaggageEntry {
                key: "key1".to_string(),
                value: "value1".to_string(),
                metadata: None,
            },
            BaggageEntry {
                key: "key2".to_string(),
                value: "value2".to_string(),
                metadata: None,
            },
        ],
    };

    run_baggage_propagation_conformance_test(&test_case, verbose)
}

fn run_url_encoding_handling_test(verbose: bool) -> ConformanceTestResult {
    let test_case = BaggagePropagationTestCase {
        name: "url-encoding-handling",
        description: "URL encoding handling",
        requirement_level: RequirementLevel::Must,
        baggage_entries: vec![BaggageEntry {
            key: "special".to_string(),
            value: "hello,world".to_string(),
            metadata: None,
        }],
    };

    run_baggage_propagation_conformance_test(&test_case, verbose)
}

fn run_size_limits_truncation_test(verbose: bool) -> ConformanceTestResult {
    let test_case = BaggagePropagationTestCase {
        name: "size-limits-truncation",
        description: "Size limits and truncation",
        requirement_level: RequirementLevel::Should,
        baggage_entries: vec![BaggageEntry {
            key: "large".to_string(),
            value: "x".repeat(100),
            metadata: None,
        }],
    };

    run_baggage_propagation_conformance_test(&test_case, verbose)
}

fn run_invalid_character_handling_test(verbose: bool) -> ConformanceTestResult {
    let test_case = BaggagePropagationTestCase {
        name: "invalid-character-handling",
        description: "Invalid character handling",
        requirement_level: RequirementLevel::Must,
        baggage_entries: vec![BaggageEntry {
            key: "control".to_string(),
            value: "value\twith\ttab".to_string(),
            metadata: None,
        }],
    };

    run_baggage_propagation_conformance_test(&test_case, verbose)
}

fn run_empty_values_handling_test(verbose: bool) -> ConformanceTestResult {
    let test_case = BaggagePropagationTestCase {
        name: "empty-values-handling",
        description: "Empty values handling",
        requirement_level: RequirementLevel::Must,
        baggage_entries: vec![BaggageEntry {
            key: "empty".to_string(),
            value: "".to_string(),
            metadata: None,
        }],
    };

    run_baggage_propagation_conformance_test(&test_case, verbose)
}

fn run_baggage_roundtrip_test(verbose: bool) -> ConformanceTestResult {
    let test_case = BaggagePropagationTestCase {
        name: "baggage-roundtrip",
        description: "Baggage roundtrip",
        requirement_level: RequirementLevel::Must,
        baggage_entries: vec![BaggageEntry {
            key: "roundtrip".to_string(),
            value: "test".to_string(),
            metadata: None,
        }],
    };

    let header_result = run_baggage_propagation_conformance_test(&test_case, verbose);
    match header_result {
        ConformanceTestResult::ExpectedFailure { .. } => {
            if let Err(reason) = test_baggage_roundtrip(&test_case, verbose) {
                ConformanceTestResult::Fail { reason }
            } else {
                live_baggage_reference_unavailable(test_case.name)
            }
        }
        other => other,
    }
}

fn run_w3c_header_format_test(verbose: bool) -> ConformanceTestResult {
    let test_case = BaggagePropagationTestCase {
        name: "w3c-header-format",
        description: "W3C header format",
        requirement_level: RequirementLevel::Must,
        baggage_entries: vec![BaggageEntry {
            key: "format".to_string(),
            value: "test".to_string(),
            metadata: Some("prop=val".to_string()),
        }],
    };

    run_baggage_propagation_conformance_test(&test_case, verbose)
}

/// Generate comprehensive compliance report
fn generate_compliance_report() {
    println!("=== OpenTelemetry Baggage Propagation Compliance Report ===\n");

    println!("## Coverage Matrix");
    println!();
    println!("| Test Case | Requirement Level | Status | Description |");
    println!("|-----------|--------------------|--------|-------------|");
    println!("| basic-baggage-headers | MUST | XFAIL | Live independent reference not wired |");
    println!("| baggage-with-metadata | MUST | XFAIL | Live independent reference not wired |");
    println!("| multiple-baggage-entries | MUST | XFAIL | Live independent reference not wired |");
    println!("| url-encoding-handling | MUST | XFAIL | Live independent reference not wired |");
    println!("| size-limits-truncation | SHOULD | XFAIL | Live independent reference not wired |");
    println!(
        "| invalid-character-handling | MUST | XFAIL | Live independent reference not wired |"
    );
    println!("| empty-values-handling | MUST | XFAIL | Live independent reference not wired |");
    println!("| baggage-roundtrip | MUST | XFAIL | Live independent reference not wired |");
    println!("| w3c-header-format | MUST | XFAIL | Live independent reference not wired |");
    println!();

    println!("## Specification Coverage");
    println!();
    println!("### Local baggage header generation: available");
    println!("### Local baggage roundtrip guard: available");
    println!("### Live independent reference: unavailable");
    println!("### Overall score: unavailable");
    println!();

    println!("## Known Divergences");
    println!();
    println!("- {OTEL_BAGGAGE_REFERENCE_UNIMPLEMENTED}");
    println!();

    println!(
        "⚠️ **XFAIL** - Baggage propagation local checks run, but independent parity is not proven"
    );
}

#[cfg(test)]
mod tests {
    use super::{
        BaggageEntry, BaggagePropagationTestCase, ConformanceTestResult,
        OTEL_BAGGAGE_REFERENCE_UNIMPLEMENTED, RequirementLevel, exit_code_for_result,
        exit_code_for_summary, final_status_line, generate_our_baggage_header,
        run_basic_baggage_headers_test,
    };

    #[test]
    fn exit_code_is_nonzero_for_expected_failure_results() {
        let result = ConformanceTestResult::ExpectedFailure {
            reason: "known divergence".to_string(),
        };

        assert_eq!(exit_code_for_result(&result), 1);
    }

    #[test]
    fn exit_code_is_zero_only_for_clean_summary() {
        assert_eq!(exit_code_for_summary(9, 0, 0), 0);
        assert_eq!(exit_code_for_summary(0, 0, 0), 1);
        assert_eq!(exit_code_for_summary(9, 1, 0), 1);
        assert_eq!(exit_code_for_summary(9, 0, 1), 1);
    }

    #[test]
    fn final_status_line_reports_partial_coverage_for_xfail_only() {
        let status = final_status_line(9, 0, 1);

        assert!(status.contains("NO FAILURES; PARTIAL COVERAGE"));
        assert!(!status.contains("ALL TESTS PASSED"));
    }

    #[test]
    fn final_status_line_reports_zero_coverage() {
        assert_eq!(final_status_line(0, 0, 0), "NO TESTS EXECUTED");
    }

    #[test]
    fn final_status_line_reports_true_all_pass() {
        assert!(final_status_line(9, 0, 0).contains("ALL TESTS PASSED"));
    }

    #[test]
    fn baggage_runner_xfails_without_live_reference() {
        let result = run_basic_baggage_headers_test(false);

        match result {
            ConformanceTestResult::ExpectedFailure { reason } => {
                assert!(reason.contains(OTEL_BAGGAGE_REFERENCE_UNIMPLEMENTED));
            }
            other => panic!("expected XFAIL while baggage reference is unwired, got {other:?}"),
        }
    }

    #[test]
    fn local_header_generation_preserves_baggage_metadata() {
        let test_case = BaggagePropagationTestCase {
            name: "metadata-local-guard",
            description: "metadata local guard",
            requirement_level: RequirementLevel::Must,
            baggage_entries: vec![BaggageEntry {
                key: "userId".to_string(),
                value: "alice".to_string(),
                metadata: Some("sensitive".to_string()),
            }],
        };

        let header = generate_our_baggage_header(&test_case, false).unwrap();

        assert!(header.contains("userId=alice;sensitive"));
    }
}
