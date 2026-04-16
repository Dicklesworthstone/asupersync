//! RFC 6330 RaptorQ Conformance Test Runner CLI
//!
//! Command-line interface for executing RFC 6330 conformance tests and generating
//! compliance reports for the asupersync RaptorQ implementation.
//!
//! # Usage
//!
//! ```bash
//! # Run all conformance tests
//! cargo run --bin raptorq_rfc6330_conformance -- --run-all
//!
//! # Run tests for specific section
//! cargo run --bin raptorq_rfc6330_conformance -- --section 5.3
//!
//! # Run only MUST clause tests
//! cargo run --bin raptorq_rfc6330_conformance -- --level must
//!
//! # Generate coverage report
//! cargo run --bin raptorq_rfc6330_conformance -- --generate-report
//!
//! # Run with CI mode (JSON-line output)
//! cargo run --bin raptorq_rfc6330_conformance -- --run-all --ci-mode
//! ```

use clap::{Arg, ArgAction, Command};
use std::path::PathBuf;
use std::process;
use std::time::Duration;

// Import conformance types
use asupersync_conformance::raptorq_rfc6330::{
    ConformanceContext, ConformanceRunner, CoverageMatrix, ConformanceResult,
    TestExecution, generate_jsonl_logs, RequirementLevel, TestCategory,
    ConformanceStatus
};

// All conformance types are now imported from the main module

fn main() {
    let matches = Command::new("raptorq_rfc6330_conformance")
        .version("1.0.0")
        .author("asupersync contributors")
        .about("RFC 6330 RaptorQ Conformance Test Runner")
        .arg(
            Arg::new("run-all")
                .long("run-all")
                .help("Run all registered conformance tests")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("section")
                .long("section")
                .value_name("SECTION")
                .help("Run tests for specific RFC section (e.g., '5.3')")
                .value_parser(clap::value_parser!(String)),
        )
        .arg(
            Arg::new("level")
                .long("level")
                .value_name("LEVEL")
                .help("Run tests for specific requirement level")
                .value_parser(["must", "should", "may"]),
        )
        .arg(
            Arg::new("category")
                .long("category")
                .value_name("CATEGORY")
                .help("Run tests for specific category")
                .value_parser(["unit", "integration", "edge", "performance", "differential"]),
        )
        .arg(
            Arg::new("generate-report")
                .long("generate-report")
                .help("Generate conformance coverage report")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("ci-mode")
                .long("ci-mode")
                .help("Enable CI mode with JSON-line output")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .help("Enable verbose output")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("timeout")
                .long("timeout")
                .value_name("SECONDS")
                .help("Test timeout in seconds")
                .value_parser(clap::value_parser!(u64))
                .default_value("30"),
        )
        .arg(
            Arg::new("fixtures")
                .long("fixtures")
                .value_name("PATH")
                .help("Path to reference implementation fixtures")
                .value_parser(clap::value_parser!(PathBuf)),
        )
        .arg(
            Arg::new("seed")
                .long("seed")
                .value_name("SEED")
                .help("Random seed for reproducible testing")
                .value_parser(clap::value_parser!(u64))
                .default_value("42"),
        )
        .arg(
            Arg::new("threshold")
                .long("threshold")
                .value_name("SCORE")
                .help("Minimum conformance score required (0.0-1.0)")
                .value_parser(clap::value_parser!(f64))
                .default_value("0.95"),
        )
        .get_matches();

    // Build conformance context from CLI arguments
    let context = ConformanceContext {
        timeout: Duration::from_secs(matches.get_one::<u64>("timeout").copied().unwrap_or(30)),
        enable_differential: matches.contains_id("fixtures"),
        fixtures_path: matches.get_one::<PathBuf>("fixtures").cloned(),
        random_seed: matches.get_one::<u64>("seed").copied().unwrap_or(42),
        verbose: matches.get_flag("verbose"),
    };

    // Initialize conformance runner with all registered tests
    let mut runner = ConformanceRunner::with_context(context);
    register_all_tests(&mut runner);

    let ci_mode = matches.get_flag("ci-mode");
    let verbose = matches.get_flag("verbose");

    if verbose && !ci_mode {
        println!("RFC 6330 RaptorQ Conformance Test Runner");
        println!("Registered tests: {}", runner.test_count());
        println!("MUST tests: {}", runner.test_count_by_level(RequirementLevel::Must));
        println!("SHOULD tests: {}", runner.test_count_by_level(RequirementLevel::Should));
        println!("MAY tests: {}", runner.test_count_by_level(RequirementLevel::May));
        println!();
    }

    // Execute tests based on CLI arguments
    let executions = if matches.get_flag("run-all") {
        if !ci_mode && verbose {
            println!("Running all conformance tests...");
        }
        runner.run_all_tests()
    } else if let Some(section) = matches.get_one::<String>("section") {
        if !ci_mode && verbose {
            println!("Running tests for section {section}...");
        }
        runner.run_section_tests(section)
    } else if let Some(level_str) = matches.get_one::<String>("level") {
        let level = match level_str.as_str() {
            "must" => RequirementLevel::Must,
            "should" => RequirementLevel::Should,
            "may" => RequirementLevel::May,
            _ => {
                eprintln!("Error: Invalid requirement level: {level_str}");
                process::exit(1);
            }
        };
        if !ci_mode && verbose {
            println!("Running {:?} level tests...", level);
        }
        runner.run_level_tests(level)
    } else if let Some(category_str) = matches.get_one::<String>("category") {
        let category = match category_str.as_str() {
            "unit" => TestCategory::Unit,
            "integration" => TestCategory::Integration,
            "edge" => TestCategory::EdgeCase,
            "performance" => TestCategory::Performance,
            "differential" => TestCategory::Differential,
            _ => {
                eprintln!("Error: Invalid test category: {category_str}");
                process::exit(1);
            }
        };
        if !ci_mode && verbose {
            println!("Running {category:?} category tests...");
        }
        runner.run_category_tests(category)
    } else if matches.get_flag("generate-report") {
        // Generate report from all tests
        if !ci_mode && verbose {
            println!("Generating conformance coverage report...");
        }
        runner.run_all_tests()
    } else {
        eprintln!("Error: Must specify --run-all, --section, --level, --category, or --generate-report");
        process::exit(1);
    };

    // Generate coverage matrix
    let coverage = CoverageMatrix::from_results(&executions);

    // Output results based on mode
    if ci_mode {
        // CI mode: JSON-line output
        let jsonl_logs = generate_jsonl_logs(&executions);
        print!("{jsonl_logs}");

        // Summary line for CI parsing
        println!(
            "{{\"summary\":{{\"score\":{:.3},\"status\":\"{}\",\"total\":{},\"passing\":{},\"failing\":{}}}}}",
            coverage.overall_score(),
            coverage.overall_status(),
            coverage.overall.total_requirements,
            coverage.overall.passing_requirements,
            coverage.overall.failed_requirements,
        );
    } else if matches.get_flag("generate-report") {
        // Generate detailed conformance report
        generate_detailed_report(&coverage, &executions);
    } else {
        // Standard test execution output
        print_test_results(&executions, &coverage, verbose);
    }

    // Check conformance threshold and exit appropriately
    let threshold = matches.get_one::<f64>("threshold").copied().unwrap_or(0.95);
    if coverage.overall_score() < threshold {
        if !ci_mode {
            eprintln!();
            eprintln!(
                "❌ Conformance threshold not met: {:.1}% < {:.1}%",
                coverage.overall_score() * 100.0,
                threshold * 100.0
            );
        }
        process::exit(1);
    } else if !ci_mode && verbose {
        println!();
        println!(
            "✅ Conformance threshold met: {:.1}% >= {:.1}%",
            coverage.overall_score() * 100.0,
            threshold * 100.0
        );
    }
}

/// Register all available RFC 6330 conformance tests
fn register_all_tests(runner: &mut ConformanceRunner) {
    // TODO: Register actual conformance test implementations
    // This is where we'll add all the P0, P1, P2, P3 priority tests
    // from the test priority matrix

    // Example test registrations (these would be real implementations):
    // runner.register_test(LookupTableV0Test);
    // runner.register_test(LookupTableV1Test);
    // runner.register_test(SystematicIndexTest);
    // runner.register_test(TupleGenerationTest);
    // ... etc

    if runner.test_count() == 0 {
        eprintln!("Warning: No conformance tests registered yet");
        eprintln!("This CLI framework is ready - tests need to be implemented");
    }
}

/// Print test execution results in human-readable format
fn print_test_results(
    executions: &[TestExecution],
    coverage: &CoverageMatrix,
    verbose: bool,
) {
    let mut passed = 0;
    let mut failed = 0;
    let mut skipped = 0;
    let mut xfail = 0;

    println!("RFC 6330 Conformance Test Results");
    println!("=================================");

    for execution in executions {
        let status = match &execution.result {
            ConformanceResult::Pass => {
                passed += 1;
                "PASS"
            }
            ConformanceResult::Fail { .. } => {
                failed += 1;
                "FAIL"
            }
            ConformanceResult::Skipped { .. } => {
                skipped += 1;
                "SKIP"
            }
            ConformanceResult::ExpectedFailure { .. } => {
                xfail += 1;
                "XFAIL"
            }
        };

        if verbose || matches!(execution.result, ConformanceResult::Fail { .. }) {
            println!(
                "[{status:>5}] {}: {}",
                execution.rfc_clause,
                execution.description,
            );

            if let ConformanceResult::Fail { reason, details } = &execution.result {
                println!("        Reason: {reason}");
                if let Some(details) = details {
                    println!("        Details: {details}");
                }
            }
        }
    }

    println!();
    println!("Summary:");
    println!("  Total:   {}", executions.len());
    println!("  Passed:  {passed}");
    println!("  Failed:  {failed}");
    println!("  Skipped: {skipped}");
    println!("  XFail:   {xfail}");
    println!();
    println!(
        "Conformance Score: {:.1}% ({})",
        coverage.overall_score() * 100.0,
        coverage.overall_status()
    );
}

/// Generate detailed conformance coverage report
fn generate_detailed_report(coverage: &CoverageMatrix, executions: &[TestExecution]) {
    println!("# RFC 6330 Conformance Coverage Report");
    println!();
    println!("**Generated:** {}", chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"));
    println!("**Implementation:** asupersync RaptorQ module");
    println!("**RFC Version:** RFC 6330 - RaptorQ Forward Error Correction Scheme");
    println!();

    // Overall summary
    println!("## Executive Summary");
    println!();
    println!(
        "**Conformance Score:** {:.1}% ({})",
        coverage.overall_score() * 100.0,
        coverage.overall_status()
    );
    println!(
        "**MUST Clause Coverage:** {}/{} ({:.1}%)",
        coverage.overall.must_passing,
        coverage.overall.must_requirements,
        if coverage.overall.must_requirements > 0 {
            coverage.overall.must_passing as f64 / coverage.overall.must_requirements as f64 * 100.0
        } else {
            100.0
        }
    );
    println!(
        "**SHOULD Clause Coverage:** {}/{} ({:.1}%)",
        coverage.overall.should_passing,
        coverage.overall.should_requirements,
        if coverage.overall.should_requirements > 0 {
            coverage.overall.should_passing as f64 / coverage.overall.should_requirements as f64 * 100.0
        } else {
            100.0
        }
    );
    println!();

    // Section-by-section breakdown
    println!("## Section Coverage Matrix");
    println!();
    println!("| Section | MUST (pass/total) | SHOULD (pass/total) | MAY (pass/total) | Score | Status |");
    println!("|---------|-------------------|---------------------|------------------|-------|--------|");

    for section in coverage.sections.values() {
        println!(
            "| §{} | {}/{} | {}/{} | {}/{} | {:.1}% | {} |",
            section.section,
            section.must_passing,
            section.must_total,
            section.should_passing,
            section.should_total,
            section.may_passing,
            section.may_total,
            section.score * 100.0,
            section.status
        );
    }

    println!();

    // Failed tests
    let failed_tests: Vec<_> = executions
        .iter()
        .filter(|e| matches!(e.result, ConformanceResult::Fail { .. }))
        .collect();

    if !failed_tests.is_empty() {
        println!("## Failed Tests");
        println!();
        for test in failed_tests {
            if let ConformanceResult::Fail { reason, details } = &test.result {
                println!("### {}", test.rfc_clause);
                println!("- **Section:** {}", test.section);
                println!("- **Level:** {}", test.level);
                println!("- **Description:** {}", test.description);
                println!("- **Failure Reason:** {reason}");
                if let Some(details) = details {
                    println!("- **Details:** {details}");
                }
                println!();
            }
        }
    }

    // Conformance recommendations
    println!("## Conformance Recommendations");
    println!();
    match coverage.overall_status() {
        ConformanceStatus::Conformant => {
            println!("✅ **RFC 6330 Conformant** - Implementation meets conformance requirements.");
        }
        ConformanceStatus::PartiallyConformant => {
            println!("⚠️ **Partially Conformant** - Some MUST clauses are not satisfied.");
            println!();
            println!("**Action Required:**");
            for section in coverage.failing_sections() {
                println!(
                    "- Fix section {} ({}) - {}/{} MUST clauses passing",
                    section.section,
                    section.title,
                    section.must_passing,
                    section.must_total
                );
            }
        }
        ConformanceStatus::NonConformant => {
            println!("❌ **Non-Conformant** - Implementation fails RFC 6330 conformance.");
            println!();
            println!("**Critical Action Required:**");
            for section in coverage.failing_sections() {
                println!(
                    "- Address section {} ({}) failures - {}/{} MUST clauses passing",
                    section.section,
                    section.title,
                    section.must_passing,
                    section.must_total
                );
            }
        }
    }
}