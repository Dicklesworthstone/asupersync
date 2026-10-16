    #![allow(clippy::pedantic, clippy::nursery)]

    use super::*;
    use crate::lab::oracle::OracleSuite;
    use crate::types::Time;
    use std::collections::BTreeSet;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn registry_descriptors_are_complete_and_unique() {
        init_test("registry_descriptors_are_complete_and_unique");
        let mut names = BTreeSet::new();
        for descriptor in OracleRegistry::list_all() {
            assert!(!descriptor.name.is_empty());
            assert!(!descriptor.invariant.is_empty());
            assert!(!descriptor.description.is_empty());
            assert!(!descriptor.example.is_empty());
            assert!(!descriptor.asup_code_family.is_empty());
            assert!(
                names.insert(descriptor.name),
                "duplicate {}",
                descriptor.name
            );
        }
        assert!(OracleRegistry::contains(INVARIANT_PRIORITY_INVERSION));
        crate::test_complete!("registry_descriptors_are_complete_and_unique");
    }

    #[test]
    fn registry_reported_names_match_oracle_suite_report() {
        init_test("registry_reported_names_match_oracle_suite_report");
        let mut suite = OracleSuite::new();
        let report = suite.report(Time::ZERO);
        let report_names = report
            .entries
            .iter()
            .map(|entry| entry.invariant.as_str())
            .collect::<BTreeSet<_>>();
        let registry_names = OracleRegistry::reported_descriptors()
            .map(|descriptor| descriptor.name)
            .collect::<BTreeSet<_>>();
        assert_eq!(report_names, registry_names);
        crate::test_complete!("registry_reported_names_match_oracle_suite_report");
    }

    #[test]
    fn registry_selection_expands_all_and_rejects_unknowns() {
        init_test("registry_selection_expands_all_and_rejects_unknowns");
        let all = OracleRegistry::select_reported_strs(&[ORACLE_ALL]).expect("all resolves");
        assert_eq!(all.len(), OracleRegistry::reported_names().len());

        let selected =
            OracleRegistry::select_reported_strs(&[INVARIANT_TASK_LEAK, INVARIANT_OBLIGATION_LEAK])
                .expect("known names resolve");
        assert_eq!(
            selected,
            vec![INVARIANT_TASK_LEAK, INVARIANT_OBLIGATION_LEAK]
        );

        let err = OracleRegistry::select_reported_strs(&["task_lek"])
            .expect_err("unknown oracle rejects");
        assert!(matches!(
            err,
            OracleRegistryError::UnknownOracle {
                suggestion: Some(INVARIANT_TASK_LEAK),
                ..
            }
        ));

        let err = OracleRegistry::select_reported_strs(&[ORACLE_ALL, "task_lek"])
            .expect_err("all should not hide unknown oracle names");
        assert!(matches!(
            err,
            OracleRegistryError::UnknownOracle {
                suggestion: Some(INVARIANT_TASK_LEAK),
                ..
            }
        ));
        crate::test_complete!("registry_selection_expands_all_and_rejects_unknowns");
    }

    #[test]
    fn registry_finds_quiescence_by_invariant_text_and_instantiates_it() {
        init_test("registry_finds_quiescence_by_invariant_text_and_instantiates_it");
        let matches = OracleRegistry::find_by_invariant("region close");
        assert!(matches.iter().any(|d| d.name == INVARIANT_QUIESCENCE));

        let oracle = OracleRegistry::instantiate(INVARIANT_QUIESCENCE)
            .expect("quiescence has object-safe constructor");
        assert_eq!(oracle.invariant_name(), INVARIANT_QUIESCENCE);

        let err = match OracleRegistry::instantiate(INVARIANT_TASK_LEAK) {
            Ok(_) => panic!("task_leak constructor is not adapted yet"),
            Err(err) => err,
        };
        assert!(matches!(err, OracleRegistryError::NotInstantiable { .. }));
        crate::test_complete!("registry_finds_quiescence_by_invariant_text_and_instantiates_it");
    }

    #[test]
    fn testing_for_agents_lists_reported_registry_names() {
        init_test("testing_for_agents_lists_reported_registry_names");
        let docs = include_str!("../../../TESTING_FOR_AGENTS.md");
        assert!(docs.contains("asupersync::lab::OracleRegistry"));
        for name in OracleRegistry::reported_names() {
            assert!(
                docs.contains(&format!("`{name}`")),
                "TESTING_FOR_AGENTS.md must list `{name}`"
            );
        }
        crate::test_complete!("testing_for_agents_lists_reported_registry_names");
    }
