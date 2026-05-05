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

use clap::{Arg, ArgAction, ArgMatches, Command};
use std::path::PathBuf;
use std::process;
use std::time::Duration;

// Import conformance types
use asupersync_conformance::raptorq_rfc6330::{
    ConformanceContext, ConformanceResult, ConformanceRunner, ConformanceStatus, CoverageMatrix,
    EvidenceSummary, RequirementLevel, TestCategory, TestExecution,
    generate_jsonl_logs_with_command,
};
use asupersync_conformance::rfc6330_tests;

// All conformance types are now imported from the main module

fn main() {
    let matches = cli_command().get_matches();
    let context = conformance_context_from_matches(&matches);
    let runner = registered_runner(context);

    let ci_mode = matches.get_flag("ci-mode");
    let verbose = matches.get_flag("verbose");

    if verbose && !ci_mode {
        println!("RFC 6330 RaptorQ Conformance Test Runner");
        println!("Registered tests: {}", runner.test_count());
        println!(
            "MUST tests: {}",
            runner.test_count_by_level(RequirementLevel::Must)
        );
        println!(
            "SHOULD tests: {}",
            runner.test_count_by_level(RequirementLevel::Should)
        );
        println!(
            "MAY tests: {}",
            runner.test_count_by_level(RequirementLevel::May)
        );
        println!();
    }

    let executions =
        selected_executions(&runner, &matches, ci_mode, verbose).unwrap_or_else(|message| {
            eprintln!("{message}");
            process::exit(1);
        });

    // Generate coverage matrix
    let coverage = CoverageMatrix::from_results(&executions);
    let quality_gate_failure = evidence_quality_gate_failure(&executions);

    // Output results based on mode
    if ci_mode {
        // CI mode: JSON-line output
        let command = command_for_matches(&matches);
        let jsonl_logs = generate_jsonl_logs_with_command(&executions, &command);
        print!("{jsonl_logs}");

        // Summary line for CI parsing
        let evidence_summary = EvidenceSummary::from_executions(&executions);
        println!(
            "{{\"summary\":{{\"score\":{:.3},\"status\":\"{}\",\"total\":{},\"passing\":{},\"failing\":{},\"evidence_quality\":{{\"live_checked\":{},\"fixture_only\":{},\"blocked\":{},\"unsupported\":{},\"expected_fail\":{},\"failed\":{}}},\"test_status\":{{\"passed\":{},\"skipped\":{}}}}}}}",
            coverage.overall_score(),
            coverage.overall_status(),
            coverage.overall.total_requirements,
            coverage.overall.passing_requirements,
            coverage.overall.failed_requirements,
            evidence_summary.live_checked,
            evidence_summary.fixture_only,
            evidence_summary.blocked,
            evidence_summary.unsupported,
            evidence_summary.expected_fail,
            evidence_summary.failed,
            evidence_summary.passed,
            evidence_summary.skipped,
        );
    } else if matches.get_flag("generate-report") {
        // Generate detailed conformance report
        generate_detailed_report(&coverage, &executions);
    } else {
        // Standard test execution output
        print_test_results(&executions, &coverage, verbose);
    }

    if let Some(message) = quality_gate_failure {
        eprintln!();
        eprintln!("Evidence quality gate failed: {message}");
        process::exit(1);
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

fn command_for_matches(matches: &ArgMatches) -> String {
    let mut parts = vec!["raptorq_rfc6330_conformance".to_string()];

    if matches.get_flag("run-all") {
        parts.push("--run-all".to_string());
    }
    if let Some(section) = matches.get_one::<String>("section") {
        parts.push("--section".to_string());
        parts.push(section.clone());
    }
    if let Some(level) = matches.get_one::<String>("level") {
        parts.push("--level".to_string());
        parts.push(level.clone());
    }
    if let Some(category) = matches.get_one::<String>("category") {
        parts.push("--category".to_string());
        parts.push(category.clone());
    }
    if matches.get_flag("generate-report") {
        parts.push("--generate-report".to_string());
    }
    if matches.get_flag("ci-mode") {
        parts.push("--ci-mode".to_string());
    }

    parts.join(" ")
}

fn cli_command() -> Command {
    Command::new("raptorq_rfc6330_conformance")
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
}

fn conformance_context_from_matches(matches: &ArgMatches) -> ConformanceContext {
    ConformanceContext {
        timeout: Duration::from_secs(matches.get_one::<u64>("timeout").copied().unwrap_or(30)),
        enable_differential: matches.get_one::<PathBuf>("fixtures").is_some(),
        fixtures_path: matches.get_one::<PathBuf>("fixtures").cloned(),
        random_seed: matches.get_one::<u64>("seed").copied().unwrap_or(42),
        verbose: matches.get_flag("verbose"),
    }
}

fn registered_runner(context: ConformanceContext) -> ConformanceRunner {
    let mut runner = ConformanceRunner::with_context(context);
    register_all_tests(&mut runner);
    runner
}

fn selected_executions(
    runner: &ConformanceRunner,
    matches: &ArgMatches,
    ci_mode: bool,
    verbose: bool,
) -> Result<Vec<TestExecution>, String> {
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
                return Err(format!("Error: Invalid requirement level: {level_str}"));
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
                return Err(format!("Error: Invalid test category: {category_str}"));
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
        return Err(
            "Error: Must specify --run-all, --section, --level, --category, or --generate-report"
                .to_string(),
        );
    };

    Ok(executions)
}

/// Register all available RFC 6330 conformance tests
fn register_all_tests(runner: &mut ConformanceRunner) {
    rfc6330_tests::register_all_tests(runner);
}

fn evidence_quality_gate_failure(executions: &[TestExecution]) -> Option<String> {
    if executions.is_empty() {
        return Some(
            "zero RFC6330 tests selected; refusing to report empty conformance".to_string(),
        );
    }

    let summary = EvidenceSummary::from_executions(executions);
    if summary.live_checked == 0 && summary.fixture_only == executions.len() {
        return Some(
            "all selected RFC6330 evidence is fixture_only; no production seam was checked"
                .to_string(),
        );
    }

    None
}

/// Print test execution results in human-readable format
fn print_test_results(executions: &[TestExecution], coverage: &CoverageMatrix, verbose: bool) {
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
            ConformanceResult::Blocked { .. } => {
                skipped += 1;
                "BLOCKED"
            }
            ConformanceResult::Unsupported { .. } => {
                skipped += 1;
                "UNSUPPORTED"
            }
        };

        if verbose
            || matches!(
                execution.result,
                ConformanceResult::Fail { .. }
                    | ConformanceResult::Blocked { .. }
                    | ConformanceResult::Unsupported { .. }
            )
        {
            println!(
                "[{status:>5}] {}: {}",
                execution.rfc_clause, execution.description,
            );

            match &execution.result {
                ConformanceResult::Fail { reason, details } => {
                    println!("        Reason: {reason}");
                    if let Some(details) = details {
                        println!("        Details: {details}");
                    }
                }
                ConformanceResult::Blocked { reason, blocker_id }
                | ConformanceResult::Unsupported { reason, blocker_id } => {
                    println!("        Reason: {reason}");
                    println!("        Blocker: {blocker_id}");
                }
                _ => {}
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
    let evidence_summary = EvidenceSummary::from_executions(executions);
    println!("Evidence Quality:");
    println!("  Live checked:  {}", evidence_summary.live_checked);
    println!("  Fixture only:  {}", evidence_summary.fixture_only);
    println!("  Blocked:       {}", evidence_summary.blocked);
    println!("  Unsupported:   {}", evidence_summary.unsupported);
    println!("  Expected fail: {}", evidence_summary.expected_fail);
    println!("  Failed:        {}", evidence_summary.failed);
    if let Some(message) = evidence_quality_gate_failure(executions) {
        println!("Evidence Quality Gate: FAIL - {message}");
    } else {
        println!("Evidence Quality Gate: PASS");
    }
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
    println!(
        "**Generated:** {}",
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
    );
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
    if let Some(message) = evidence_quality_gate_failure(executions) {
        println!("**Evidence Quality Gate:** FAIL - {message}");
    } else {
        println!("**Evidence Quality Gate:** PASS");
    }
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
            coverage.overall.should_passing as f64 / coverage.overall.should_requirements as f64
                * 100.0
        } else {
            100.0
        }
    );
    println!();

    // Section-by-section breakdown
    println!("## Section Coverage Matrix");
    println!();
    println!(
        "| Section | MUST (pass/total) | SHOULD (pass/total) | MAY (pass/total) | Score | Status |"
    );
    println!(
        "|---------|-------------------|---------------------|------------------|-------|--------|"
    );

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

    let evidence_summary = EvidenceSummary::from_executions(executions);
    println!("## Evidence Quality");
    println!();
    println!("| Live checked | Fixture only | Blocked | Unsupported | Expected fail | Failed |");
    println!("|--------------|--------------|---------|-------------|---------------|--------|");
    println!(
        "| {} | {} | {} | {} | {} | {} |",
        evidence_summary.live_checked,
        evidence_summary.fixture_only,
        evidence_summary.blocked,
        evidence_summary.unsupported,
        evidence_summary.expected_fail,
        evidence_summary.failed
    );
    println!();

    // Failed tests
    let failed_tests: Vec<_> = executions
        .iter()
        .filter(|e| {
            matches!(
                e.result,
                ConformanceResult::Fail { .. }
                    | ConformanceResult::Blocked { .. }
                    | ConformanceResult::Unsupported { .. }
            )
        })
        .collect();

    if !failed_tests.is_empty() {
        println!("## Non-Passing Tests");
        println!();
        for test in failed_tests {
            println!("### {}", test.rfc_clause);
            println!("- **Section:** {}", test.section);
            println!("- **Level:** {}", test.level);
            println!("- **Evidence kind:** {}", test.evidence.evidence_kind);
            println!("- **Test status:** {}", test.evidence.test_status);
            println!("- **Description:** {}", test.description);
            match &test.result {
                ConformanceResult::Fail { reason, details } => {
                    println!("- **Failure Reason:** {reason}");
                    if let Some(details) = details {
                        println!("- **Details:** {details}");
                    }
                }
                ConformanceResult::Blocked { reason, blocker_id }
                | ConformanceResult::Unsupported { reason, blocker_id } => {
                    println!("- **Reason:** {reason}");
                    println!("- **Blocker:** {blocker_id}");
                }
                _ => {}
            }
            println!();
        }
    }

    println!("## Registered Test Executions");
    println!();
    println!(
        "| RFC Clause | Section | Level | Category | Status | Evidence | Production Seam | Fixture | Description |"
    );
    println!(
        "|------------|---------|-------|----------|--------|----------|-----------------|---------|-------------|"
    );

    for test in executions {
        println!(
            "| {} | {} | {} | {:?} | {} | {} | {} | {} | {} |",
            test.rfc_clause,
            test.section,
            test.level,
            test.category,
            test.result.description(),
            test.evidence.evidence_kind,
            test.evidence.production_seam_path.as_deref().unwrap_or(""),
            test.evidence.fixture_reference.as_deref().unwrap_or(""),
            test.description.replace('|', "\\|")
        );
    }
    println!();

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
                    section.section, section.title, section.must_passing, section.must_total
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
                    section.section, section.title, section.must_passing, section.must_total
                );
            }
        }
    }
}

#[cfg(test)]
mod cli_contract {
    include!("../../tests/raptorq_rfc6330_cli_contract.rs");
}
