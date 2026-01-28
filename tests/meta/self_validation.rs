mod common;
use common::*;

use asupersync::lab::meta::{BuiltinMutation, MetaRunner};

#[test]
fn meta_runner_reports_missing_invariants_when_empty() {
    init_test_logging();
    test_phase!("meta_runner_reports_missing_invariants_when_empty");

    let runner = MetaRunner::new(DEFAULT_TEST_SEED);
    let report = runner.run(Vec::<BuiltinMutation>::new());
    let missing = report.coverage().missing_invariants();
    assert!(
        !missing.is_empty(),
        "expected missing invariants when no mutations are supplied"
    );

    test_complete!("meta_runner_reports_missing_invariants_when_empty");
}
