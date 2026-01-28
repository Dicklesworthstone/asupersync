mod common;
use common::*;

use asupersync::lab::meta::{builtin_mutations, MetaRunner};

#[test]
fn meta_coverage_report_includes_all_invariants() {
    init_test_logging();
    test_phase!("meta_coverage_report_includes_all_invariants");

    let runner = MetaRunner::new(DEFAULT_TEST_SEED);
    let report = runner.run(builtin_mutations());
    let coverage = report.coverage();
    let missing = coverage.missing_invariants();

    assert!(
        missing.is_empty(),
        "missing invariants: {:?}\n{}",
        missing,
        coverage.to_text()
    );

    let text = coverage.to_text();
    assert!(text.contains("task_leak"));
    let json = coverage.to_json();
    assert!(json.get("invariants").is_some());

    test_complete!("meta_coverage_report_includes_all_invariants");
}
