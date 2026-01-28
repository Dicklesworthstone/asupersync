mod common;
use common::*;

use asupersync::lab::meta::{builtin_mutations, MetaRunner};

#[test]
fn meta_oracles_trip_on_mutations() {
    init_test_logging();
    test_phase!("meta_oracles_trip_on_mutations");

    let runner = MetaRunner::new(DEFAULT_TEST_SEED);
    let report = runner.run(builtin_mutations());
    let failures = report.failures();
    assert!(
        failures.is_empty(),
        "meta oracle failures:\n{}",
        report.to_text()
    );

    test_complete!("meta_oracles_trip_on_mutations");
}
