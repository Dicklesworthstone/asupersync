use asupersync::Time;
use asupersync::lab::{ORACLE_ALL, OracleRegistry, OracleRegistryError, OracleSuite};
use std::collections::BTreeSet;

#[test]
fn public_registry_descriptors_are_complete_unique_and_reportable() {
    let descriptors = OracleRegistry::list_all();
    assert!(
        descriptors.len() >= OracleRegistry::reported_names().len(),
        "registry must include every reported oracle descriptor"
    );

    let mut names = BTreeSet::new();
    for descriptor in descriptors {
        assert!(!descriptor.name.is_empty(), "descriptor name is required");
        assert!(
            !descriptor.invariant.is_empty(),
            "{} invariant is required",
            descriptor.name
        );
        assert!(
            !descriptor.description.is_empty(),
            "{} description is required",
            descriptor.name
        );
        assert!(
            !descriptor.example.is_empty(),
            "{} example is required",
            descriptor.name
        );
        assert!(
            !descriptor.asup_code_family.is_empty(),
            "{} ASUP code family is required",
            descriptor.name
        );
        assert!(
            names.insert(descriptor.name),
            "duplicate oracle descriptor {}",
            descriptor.name
        );
    }

    for name in OracleRegistry::reported_names() {
        let descriptor = OracleRegistry::find(name).expect("reported oracle has descriptor");
        assert!(
            descriptor.report_entry,
            "reported oracle must be reportable"
        );
    }

    let priority_inversion = OracleRegistry::find("priority_inversion")
        .expect("non-reportable priority inversion oracle is still registered");
    assert!(!priority_inversion.report_entry);
}

#[test]
fn public_reported_names_match_oracle_suite_report_entries() {
    let mut suite = OracleSuite::new();
    let report = suite.report(Time::ZERO);
    let report_names = report
        .entries
        .iter()
        .map(|entry| entry.invariant.as_str())
        .collect::<BTreeSet<_>>();
    let registry_names = OracleRegistry::reported_names()
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();

    assert_eq!(report_names, registry_names);
}

#[test]
fn public_selection_expands_all_preserves_order_and_rejects_bad_names() {
    let all = OracleRegistry::select_reported_strs(&[ORACLE_ALL]).expect("all resolves");
    assert_eq!(all.as_slice(), OracleRegistry::reported_names());

    let selected = OracleRegistry::select_reported_strs(&["task_leak", "obligation_leak"])
        .expect("known names resolve");
    assert_eq!(selected, vec!["task_leak", "obligation_leak"]);

    let err = OracleRegistry::select_reported_strs(&["task_lek"]).expect_err("bad name rejects");
    assert!(matches!(
        err,
        OracleRegistryError::UnknownOracle {
            suggestion: Some("task_leak"),
            ..
        }
    ));

    let err = OracleRegistry::select_reported_strs(&[ORACLE_ALL, "task_lek"])
        .expect_err("all must not hide bad names");
    assert!(matches!(
        err,
        OracleRegistryError::UnknownOracle {
            suggestion: Some("task_leak"),
            ..
        }
    ));

    let err = OracleRegistry::select_reported_strs(&["priority_inversion"])
        .expect_err("registered but non-reportable names reject scenario selection");
    assert!(matches!(err, OracleRegistryError::NotReportable { .. }));
}

#[test]
fn public_registry_search_and_instantiation_are_agent_usable() {
    let matches = OracleRegistry::find_by_invariant("region close");
    assert!(
        matches
            .iter()
            .any(|descriptor| descriptor.name == "quiescence"),
        "region-close search should find quiescence"
    );

    let oracle = OracleRegistry::instantiate("quiescence")
        .expect("quiescence exposes an object-safe constructor");
    assert_eq!(oracle.invariant_name(), "quiescence");

    let result = OracleRegistry::instantiate("task_leak");
    assert!(matches!(
        result,
        Err(OracleRegistryError::NotInstantiable { .. })
    ));
}

#[test]
fn testing_for_agents_lists_every_public_reported_oracle_name() {
    let guide = include_str!("../TESTING_FOR_AGENTS.md");
    assert!(guide.contains("asupersync::lab::OracleRegistry"));

    for name in OracleRegistry::reported_names() {
        assert!(
            guide.split('`').any(|quoted| quoted == *name),
            "TESTING_FOR_AGENTS.md must list `{name}`"
        );
    }
}
