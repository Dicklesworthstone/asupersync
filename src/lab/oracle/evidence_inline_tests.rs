    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::lab::oracle::{OracleEntryReport, OracleReport};

    fn make_clean_report() -> OracleReport {
        OracleReport {
            entries: vec![
                OracleEntryReport {
                    invariant: "task_leak".into(),
                    passed: true,
                    violation: None,
                    stats: OracleStats {
                        entities_tracked: 5,
                        events_recorded: 10,
                    },
                },
                OracleEntryReport {
                    invariant: "obligation_leak".into(),
                    passed: true,
                    violation: None,
                    stats: OracleStats {
                        entities_tracked: 3,
                        events_recorded: 6,
                    },
                },
            ],
            total: 2,
            passed: 2,
            failed: 0,
            check_time_nanos: 42,
        }
    }

    fn make_violation_report() -> OracleReport {
        OracleReport {
            entries: vec![
                OracleEntryReport {
                    invariant: "task_leak".into(),
                    passed: false,
                    violation: Some("leaked 2 tasks".into()),
                    stats: OracleStats {
                        entities_tracked: 5,
                        events_recorded: 10,
                    },
                },
                OracleEntryReport {
                    invariant: "quiescence".into(),
                    passed: true,
                    violation: None,
                    stats: OracleStats {
                        entities_tracked: 2,
                        events_recorded: 4,
                    },
                },
                OracleEntryReport {
                    invariant: "obligation_leak".into(),
                    passed: false,
                    violation: Some("leaked 1 obligation".into()),
                    stats: OracleStats {
                        entities_tracked: 1,
                        events_recorded: 2,
                    },
                },
            ],
            total: 3,
            passed: 1,
            failed: 2,
            check_time_nanos: 100,
        }
    }

    // -- EvidenceStrength classification --

    #[test]
    fn strength_from_log10_bf() {
        assert_eq!(
            EvidenceStrength::from_log10_bf(-1.0),
            EvidenceStrength::Against
        );
        assert_eq!(
            EvidenceStrength::from_log10_bf(0.0),
            EvidenceStrength::Negligible
        );
        assert_eq!(
            EvidenceStrength::from_log10_bf(0.49),
            EvidenceStrength::Negligible
        );
        assert_eq!(
            EvidenceStrength::from_log10_bf(0.5),
            EvidenceStrength::Positive
        );
        assert_eq!(
            EvidenceStrength::from_log10_bf(1.29),
            EvidenceStrength::Positive
        );
        assert_eq!(
            EvidenceStrength::from_log10_bf(1.3),
            EvidenceStrength::Strong
        );
        assert_eq!(
            EvidenceStrength::from_log10_bf(2.19),
            EvidenceStrength::Strong
        );
        assert_eq!(
            EvidenceStrength::from_log10_bf(2.2),
            EvidenceStrength::VeryStrong
        );
        assert_eq!(
            EvidenceStrength::from_log10_bf(5.0),
            EvidenceStrength::VeryStrong
        );
    }

    #[test]
    fn strength_labels() {
        assert_eq!(EvidenceStrength::Against.label(), "against");
        assert_eq!(EvidenceStrength::Negligible.label(), "negligible");
        assert_eq!(EvidenceStrength::Positive.label(), "positive");
        assert_eq!(EvidenceStrength::Strong.label(), "strong");
        assert_eq!(EvidenceStrength::VeryStrong.label(), "very strong");
    }

    #[test]
    fn strength_display() {
        assert_eq!(format!("{}", EvidenceStrength::Strong), "strong");
    }

    // -- BayesFactor --

    #[test]
    fn bayes_factor_from_log_likelihoods() {
        let bf = BayesFactor::from_log_likelihoods(-0.5, -3.0, "test".into());
        assert!((bf.log10_bf - 2.5).abs() < 1e-10);
        assert_eq!(bf.strength, EvidenceStrength::VeryStrong);
    }

    #[test]
    fn bayes_factor_value() {
        let bf = BayesFactor::from_log_likelihoods(0.0, -2.0, "test".into());
        // log10_bf = 2.0, so value = 100.0
        assert!((bf.value() - 100.0).abs() < 1e-6);
    }

    #[test]
    fn bayes_factor_value_clamped() {
        // Extreme value should not produce infinity.
        let bf = BayesFactor {
            log10_bf: 1000.0,
            hypothesis: "extreme".into(),
            strength: EvidenceStrength::VeryStrong,
        };
        assert!(bf.value().is_finite());
    }

    // -- DetectionModel --

    #[test]
    fn detection_model_default() {
        let m = DetectionModel::default();
        assert!((m.per_entity_detection_rate - 0.9).abs() < 1e-10);
        assert!((m.false_positive_rate - 0.001).abs() < 1e-10);
    }

    #[test]
    fn detection_model_p_detection_single_entity() {
        let m = DetectionModel::default();
        let p = m.p_detection_given_violation(1);
        assert!((p - 0.9).abs() < 1e-10);
    }

    #[test]
    fn detection_model_p_detection_multiple_entities() {
        let m = DetectionModel::default();
        // With 2 entities: 1 - (1 - 0.9)^2 = 1 - 0.01 = 0.99
        let p = m.p_detection_given_violation(2);
        assert!((p - 0.99).abs() < 1e-10);
    }

    #[test]
    fn detection_model_p_detection_zero_entities_uses_one() {
        let m = DetectionModel::default();
        let p = m.p_detection_given_violation(0);
        assert!(
            (p - 0.9).abs() < 1e-10,
            "zero entities should be treated as 1"
        );
    }

    #[test]
    fn detection_model_p_pass_given_clean() {
        let m = DetectionModel::default();
        assert!((m.p_pass_given_clean() - 0.999).abs() < 1e-10);
    }

    #[test]
    fn detection_model_p_pass_given_violation() {
        let m = DetectionModel::default();
        // (1 - 0.9)^1 = 0.1
        assert!((m.p_pass_given_violation(1) - 0.1).abs() < 1e-10);
        // (1 - 0.9)^2 = 0.01
        assert!((m.p_pass_given_violation(2) - 0.01).abs() < 1e-10);
    }

    // -- structural_contribution --

    #[test]
    fn structural_contribution_zero_events() {
        let s = structural_contribution(&OracleStats {
            entities_tracked: 0,
            events_recorded: 0,
        });
        assert!((s - 0.0_f64.log10()).abs() < 1e-10 || (s - (1.0_f64).log10()).abs() < 1e-10);
        // log10(1 + 0/100) = log10(1) = 0
        assert!(s.abs() < 1e-10);
    }

    #[test]
    fn structural_contribution_increases_with_events() {
        let s1 = structural_contribution(&OracleStats {
            entities_tracked: 0,
            events_recorded: 10,
        });
        let s2 = structural_contribution(&OracleStats {
            entities_tracked: 0,
            events_recorded: 100,
        });
        assert!(s2 > s1);
    }

    #[test]
    fn clean_entry_stays_against_violation_even_with_many_events() {
        let report = OracleReport {
            entries: vec![OracleEntryReport {
                invariant: "task_leak".into(),
                passed: true,
                violation: None,
                stats: OracleStats {
                    entities_tracked: 1,
                    events_recorded: 1_000_000,
                },
            }],
            total: 1,
            passed: 1,
            failed: 0,
            check_time_nanos: 7,
        };

        let ledger = EvidenceLedger::from_report(&report);
        let entry = &ledger.entries[0];

        assert!(
            entry.bayes_factor.log10_bf < 0.0,
            "clean pass must remain evidence against violation even with large event counts"
        );
        assert!(
            entry.log_likelihoods.structural < 0.0,
            "clean pass should record structural support in the clean direction"
        );
        assert_eq!(entry.bayes_factor.strength, EvidenceStrength::Against);
        assert!(
            entry.evidence_lines[0].intuition.contains("against"),
            "clean intuition should explicitly describe evidence against violation"
        );
    }

    // -- EvidenceLedger from clean report --

    #[test]
    fn ledger_from_clean_report() {
        let report = make_clean_report();
        let ledger = EvidenceLedger::from_report(&report);

        assert_eq!(ledger.entries.len(), 2);
        assert_eq!(ledger.summary.total_invariants, 2);
        assert_eq!(ledger.summary.violations_detected, 0);
        assert!(ledger.summary.strongest_violation.is_none());
        assert!((ledger.summary.aggregate_log10_bf).abs() < 1e-10);
        assert_eq!(ledger.check_time_nanos, 42);
    }

    #[test]
    fn ledger_clean_entries_have_negative_bf() {
        let report = make_clean_report();
        let ledger = EvidenceLedger::from_report(&report);

        for entry in &ledger.entries {
            assert!(entry.passed);
            // BF for "violation" should be < 1 (log10 < 0) since oracle passed.
            assert!(
                entry.bayes_factor.log10_bf < 0.0,
                "clean entry '{inv}' should have BF < 1, got log10_bf={bf}",
                inv = entry.invariant,
                bf = entry.bayes_factor.log10_bf,
            );
            assert_eq!(entry.bayes_factor.strength, EvidenceStrength::Against);
        }
    }

    #[test]
    fn ledger_clean_evidence_lines() {
        let report = make_clean_report();
        let ledger = EvidenceLedger::from_report(&report);

        for entry in &ledger.entries {
            assert!(
                !entry.evidence_lines.is_empty(),
                "entry should have evidence lines"
            );
            // Check first line references the equation.
            assert!(
                entry.evidence_lines[0]
                    .equation
                    .contains("P(pass | violated)")
            );
        }
    }

    // -- EvidenceLedger from violation report --

    #[test]
    fn ledger_from_violation_report() {
        let report = make_violation_report();
        let ledger = EvidenceLedger::from_report(&report);

        assert_eq!(ledger.entries.len(), 3);
        assert_eq!(ledger.summary.total_invariants, 3);
        assert_eq!(ledger.summary.violations_detected, 2);
        assert!(ledger.summary.strongest_violation.is_some());
        assert!(ledger.summary.aggregate_log10_bf > 0.0);
    }

    #[test]
    fn ledger_violation_entries_have_positive_bf() {
        let report = make_violation_report();
        let ledger = EvidenceLedger::from_report(&report);

        for entry in ledger.entries.iter().filter(|e| !e.passed) {
            assert!(
                entry.bayes_factor.log10_bf > 0.0,
                "violation entry '{inv}' should have BF > 1, got log10_bf={bf}",
                inv = entry.invariant,
                bf = entry.bayes_factor.log10_bf,
            );
        }
    }

    #[test]
    fn ledger_violation_evidence_lines() {
        let report = make_violation_report();
        let ledger = EvidenceLedger::from_report(&report);

        let task_entry = ledger
            .entries
            .iter()
            .find(|e| e.invariant == "task_leak")
            .unwrap();
        assert!(!task_entry.passed);
        assert!(
            task_entry.evidence_lines[0]
                .equation
                .contains("P(violation_observed | violated)")
        );
    }

    // -- violations_by_strength --

    #[test]
    fn violations_by_strength_ordering() {
        let report = make_violation_report();
        let ledger = EvidenceLedger::from_report(&report);
        let violations = ledger.violations_by_strength();

        assert_eq!(violations.len(), 2);
        // Stronger evidence (more entities) should come first.
        assert!(violations[0].bayes_factor.log10_bf >= violations[1].bayes_factor.log10_bf);
    }

    // -- clean_by_confidence --

    #[test]
    fn clean_by_confidence_ordering() {
        let report = make_violation_report();
        let ledger = EvidenceLedger::from_report(&report);
        let clean = ledger.clean_by_confidence();

        assert_eq!(clean.len(), 1);
        assert_eq!(clean[0].invariant, "quiescence");
    }

    // -- text output --

    #[test]
    fn ledger_to_text_contains_header() {
        let report = make_clean_report();
        let ledger = EvidenceLedger::from_report(&report);
        let text = ledger.to_text();

        assert!(text.contains("EVIDENCE LEDGER"));
        assert!(text.contains("Invariants examined: 2"));
        assert!(text.contains("Violations detected: 0"));
        assert!(text.contains("CLEAN INVARIANTS"));
    }

    #[test]
    fn ledger_to_text_violations_section() {
        let report = make_violation_report();
        let ledger = EvidenceLedger::from_report(&report);
        let text = ledger.to_text();

        assert!(text.contains("VIOLATIONS"));
        assert!(text.contains("[FAIL] task_leak"));
        assert!(text.contains("[FAIL] obligation_leak"));
        assert!(text.contains("[PASS] quiescence"));
    }

    #[test]
    fn ledger_to_text_evidence_lines() {
        let report = make_violation_report();
        let ledger = EvidenceLedger::from_report(&report);
        let text = ledger.to_text();

        assert!(text.contains("BF ="));
        assert!(text.contains("log₁₀(BF)"));
    }

    // -- JSON serialization --

    #[test]
    fn ledger_json_roundtrip() {
        let report = make_violation_report();
        let ledger = EvidenceLedger::from_report(&report);
        let json = serde_json::to_string(&ledger).unwrap();
        let deserialized: EvidenceLedger = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.entries.len(), ledger.entries.len());
        assert_eq!(
            deserialized.summary.violations_detected,
            ledger.summary.violations_detected
        );
        assert_eq!(deserialized.check_time_nanos, ledger.check_time_nanos);
    }

    #[test]
    fn ledger_to_json_structure() {
        let report = make_clean_report();
        let ledger = EvidenceLedger::from_report(&report);
        let json = ledger.to_json();

        assert!(json["entries"].is_array());
        assert!(json["summary"].is_object());
        assert_eq!(json["summary"]["total_invariants"], 2);
        assert_eq!(json["check_time_nanos"], 42);
    }

    // -- custom detection model --

    #[test]
    fn custom_detection_model() {
        let model = DetectionModel {
            per_entity_detection_rate: 0.5,
            false_positive_rate: 0.01,
        };
        let report = make_violation_report();
        let ledger = EvidenceLedger::from_report_with_model(&report, &model);

        // With lower detection rate, BF for violations should be smaller.
        let default_ledger = EvidenceLedger::from_report(&report);
        for (custom, default) in ledger
            .entries
            .iter()
            .zip(default_ledger.entries.iter())
            .filter(|(_, d)| !d.passed)
        {
            assert!(
                custom.bayes_factor.log10_bf < default.bayes_factor.log10_bf,
                "lower detection rate should produce weaker evidence"
            );
        }
    }

    // -- log-likelihood contributions --

    #[test]
    fn log_likelihood_components_sum_to_total() {
        let report = make_violation_report();
        let ledger = EvidenceLedger::from_report(&report);

        for entry in &ledger.entries {
            let expected_total = entry.log_likelihoods.structural + entry.log_likelihoods.detection;
            assert!(
                (entry.log_likelihoods.total - expected_total).abs() < 1e-10,
                "total should equal structural + detection"
            );
        }
    }

    // -- integration with OracleSuite --

    #[test]
    fn ledger_from_oracle_suite() {
        let mut suite = super::super::OracleSuite::new();
        let report = suite.report(crate::types::Time::ZERO);
        let ledger = EvidenceLedger::from_report(&report);

        // 24 core oracles; 4 more with messaging-fabric feature.
        #[cfg(not(feature = "messaging-fabric"))]
        assert_eq!(ledger.entries.len(), 24);
        #[cfg(feature = "messaging-fabric")]
        assert_eq!(ledger.entries.len(), 28);
        assert_eq!(ledger.summary.violations_detected, 0);
        // All should show evidence against violation.
        for entry in &ledger.entries {
            assert!(entry.passed);
            assert_eq!(entry.bayes_factor.strength, EvidenceStrength::Against);
        }
    }

    // -- EvidenceEntry struct --

    #[test]
    fn evidence_entry_fields() {
        let report = make_violation_report();
        let ledger = EvidenceLedger::from_report(&report);

        let task_entry = &ledger.entries[0];
        assert_eq!(task_entry.invariant, "task_leak");
        assert!(!task_entry.passed);
        assert!(!task_entry.evidence_lines.is_empty());
        assert!(task_entry.bayes_factor.log10_bf.is_finite());
        assert!(task_entry.log_likelihoods.total.is_finite());
    }

    // -- EvidenceSummary --

    #[test]
    fn evidence_summary_strongest_violation() {
        let report = make_violation_report();
        let ledger = EvidenceLedger::from_report(&report);

        // task_leak has 5 entities, obligation_leak has 1 — task_leak should be strongest.
        assert_eq!(
            ledger.summary.strongest_violation.as_deref(),
            Some("task_leak")
        );
    }

    #[test]
    fn evidence_summary_strongest_clean() {
        let report = make_violation_report();
        let ledger = EvidenceLedger::from_report(&report);

        assert_eq!(
            ledger.summary.strongest_clean.as_deref(),
            Some("quiescence")
        );
    }
