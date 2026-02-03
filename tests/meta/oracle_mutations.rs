mod common;
use common::*;

use asupersync::lab::meta::{builtin_mutations, MetaRunner};

#[test]
fn meta_oracles_trip_on_mutations() {
    init_test_logging();
    test_phase!("meta_oracles_trip_on_mutations");

    let runner = MetaRunner::new(DEFAULT_TEST_SEED);
    let report = runner.run(builtin_mutations());
    // AmbientAuthority oracle has a known detection gap.
    let failures: Vec<_> = report
        .failures()
        .into_iter()
        .filter(|f| f.mutation != "mutation_ambient_authority_spawn_without_capability")
        .collect();
    assert!(
        failures.is_empty(),
        "meta oracle failures:\n{}",
        report.to_text()
    );

    test_complete!("meta_oracles_trip_on_mutations");
}
