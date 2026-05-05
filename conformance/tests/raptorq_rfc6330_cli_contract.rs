use super::*;
use asupersync_conformance::raptorq_rfc6330::{
    EvidenceKind, EvidenceMetadata, EvidenceSummary, TestStatus, generate_jsonl_logs_with_command,
};
use serde_json::Value;
use std::time::{Duration, SystemTime};

fn matches(args: &[&str]) -> ArgMatches {
    let argv = std::iter::once("raptorq_rfc6330_conformance").chain(args.iter().copied());
    cli_command()
        .try_get_matches_from(argv)
        .expect("CLI args should parse")
}

fn executions(args: &[&str]) -> Vec<TestExecution> {
    let matches = matches(args);
    let context = conformance_context_from_matches(&matches);
    let runner = registered_runner(context);
    selected_executions(
        &runner,
        &matches,
        matches.get_flag("ci-mode"),
        matches.get_flag("verbose"),
    )
    .expect("CLI args should select tests")
}

fn counts(executions: &[TestExecution]) -> (usize, usize, usize) {
    let coverage = CoverageMatrix::from_results(executions);
    (
        coverage.overall.total_requirements,
        coverage.overall.passing_requirements,
        coverage.overall.failed_requirements,
    )
}

#[test]
fn run_all_ci_mode_reports_real_registered_tests() {
    let records = executions(&["--run-all", "--ci-mode"]);

    assert_eq!(records.len(), 6, "RFC6330 CLI must run the live registry");
    assert_eq!(counts(&records), (6, 6, 0));
    assert!(
        records
            .iter()
            .all(|line| line.evidence.evidence_kind == EvidenceKind::LiveChecked),
        "registered RFC6330 tests must be live implementation checks, not fixture-only claims"
    );
    assert!(
        records
            .iter()
            .all(|line| line.evidence.production_seam_path.is_some()),
        "every live RFC6330 record must name the production seam it exercised"
    );
    assert!(
        records
            .iter()
            .any(|line| line.rfc_clause == "RFC6330-5.5.1")
    );
    assert!(
        records
            .iter()
            .any(|line| line.rfc_clause == "RFC6330-5.3.1")
    );
}

#[test]
fn ci_jsonl_carries_evidence_quality_contract_fields() {
    let records = executions(&["--section", "5.3", "--ci-mode"]);
    let jsonl = generate_jsonl_logs_with_command(
        &records,
        "raptorq_rfc6330_conformance --section 5.3 --ci-mode",
    );
    let line: Value = serde_json::from_str(jsonl.lines().next().expect("one JSONL row"))
        .expect("JSONL row should parse");

    assert_eq!(line["clause_id"], "RFC6330-5.3.1");
    assert_eq!(line["requirement_level"], "Must");
    assert_eq!(line["evidence_kind"], "live_checked");
    assert_eq!(line["test_status"], "pass");
    assert_eq!(line["fixture_reference"], "RFC6330_TUPLE_TEST_VECTORS");
    assert_eq!(
        line["production_seam_path"],
        "src/raptorq/rfc6330.rs::try_tuple"
    );
    assert_eq!(
        line["command"],
        "raptorq_rfc6330_conformance --section 5.3 --ci-mode"
    );
}

#[test]
fn evidence_summary_counts_each_quality_state_separately() {
    let records = vec![
        synthetic_execution(
            "live",
            EvidenceKind::LiveChecked,
            TestStatus::Pass,
            ConformanceResult::Pass,
        ),
        synthetic_execution(
            "fixture",
            EvidenceKind::FixtureOnly,
            TestStatus::Pass,
            ConformanceResult::Pass,
        ),
        synthetic_execution(
            "blocked",
            EvidenceKind::Blocked,
            TestStatus::Blocked,
            ConformanceResult::Blocked {
                reason: "fixture server unavailable".to_string(),
                blocker_id: "asupersync-test-blocker".to_string(),
            },
        ),
        synthetic_execution(
            "unsupported",
            EvidenceKind::Unsupported,
            TestStatus::Unsupported,
            ConformanceResult::Unsupported {
                reason: "clause outside current RaptorQ support tier".to_string(),
                blocker_id: "asupersync-test-unsupported".to_string(),
            },
        ),
        synthetic_execution(
            "expected",
            EvidenceKind::ExpectedFail,
            TestStatus::ExpectedFail,
            ConformanceResult::ExpectedFailure {
                reason: "documented fixture-only divergence".to_string(),
                discrepancy_id: "asupersync-test-xfail".to_string(),
            },
        ),
        synthetic_execution(
            "failed",
            EvidenceKind::Failed,
            TestStatus::Fail,
            ConformanceResult::Fail {
                reason: "live check failed".to_string(),
                details: None,
            },
        ),
    ];

    let summary = EvidenceSummary::from_executions(&records);
    assert_eq!(summary.live_checked, 1);
    assert_eq!(summary.fixture_only, 1);
    assert_eq!(summary.blocked, 1);
    assert_eq!(summary.unsupported, 1);
    assert_eq!(summary.expected_fail, 1);
    assert_eq!(summary.failed, 1);
    assert_eq!(summary.passed, 2);
    assert_eq!(summary.skipped, 0);

    let jsonl = generate_jsonl_logs_with_command(&records, "raptorq_rfc6330_conformance --ci-mode");
    for expected_kind in [
        "live_checked",
        "fixture_only",
        "blocked",
        "unsupported",
        "expected_fail",
        "failed",
    ] {
        assert!(
            jsonl.contains(&format!("\"evidence_kind\":\"{expected_kind}\"")),
            "JSONL must include {expected_kind} evidence rows"
        );
    }
}

#[test]
fn cli_filters_select_registered_tests() {
    let cases: &[(&[&str], (usize, usize, usize), &str)] = &[
        (
            &["--section", "5.3", "--ci-mode"],
            (1, 1, 0),
            "RFC6330-5.3.1",
        ),
        (
            &["--level", "must", "--ci-mode"],
            (6, 6, 0),
            "RFC6330-5.1.1",
        ),
        (
            &["--category", "unit", "--ci-mode"],
            (5, 5, 0),
            "RFC6330-5.5.1-V3",
        ),
        (
            &["--category", "differential", "--ci-mode"],
            (1, 1, 0),
            "RFC6330-5.3.1",
        ),
    ];

    for (args, expected_counts, expected_clause) in cases.iter().copied() {
        let records = executions(args);

        assert_eq!(counts(&records), expected_counts, "args {args:?}");
        assert!(
            records
                .iter()
                .any(|line| line.rfc_clause == expected_clause),
            "args {args:?} should include {expected_clause}"
        );
    }
}

#[test]
fn generate_report_selects_registered_test_executions() {
    let records = executions(&["--generate-report"]);

    assert_eq!(counts(&records), (6, 6, 0));
    assert!(
        records
            .iter()
            .any(|line| line.rfc_clause == "RFC6330-5.5.1")
    );
    assert!(
        records
            .iter()
            .any(|line| line.rfc_clause == "RFC6330-5.3.1")
    );
}

fn synthetic_execution(
    name: &str,
    evidence_kind: EvidenceKind,
    test_status: TestStatus,
    result: ConformanceResult,
) -> TestExecution {
    TestExecution {
        test_name: name.to_string(),
        rfc_clause: format!("RFC6330-TEST-{name}"),
        section: "test".to_string(),
        level: RequirementLevel::Must,
        category: TestCategory::Unit,
        description: format!("{name} evidence fixture"),
        evidence: EvidenceMetadata {
            evidence_kind,
            test_status,
            blocker_id: matches!(
                evidence_kind,
                EvidenceKind::Blocked | EvidenceKind::Unsupported | EvidenceKind::ExpectedFail
            )
            .then(|| format!("asupersync-{name}")),
            fixture_reference: (evidence_kind == EvidenceKind::FixtureOnly)
                .then(|| "RFC6330_TEST_FIXTURE".to_string()),
            production_seam_path: (evidence_kind == EvidenceKind::LiveChecked)
                .then(|| "src/raptorq/rfc6330.rs::test_seam".to_string()),
        },
        result,
        duration: Duration::from_millis(1),
        timestamp: SystemTime::UNIX_EPOCH,
    }
}
