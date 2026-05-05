use super::*;

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
            .any(|line| line.rfc_clause == "RFC6330-5.5.1")
    );
    assert!(
        records
            .iter()
            .any(|line| line.rfc_clause == "RFC6330-5.3.1")
    );
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
