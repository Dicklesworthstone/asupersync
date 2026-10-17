    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::lab::oracle::{OracleEntryReport, OracleReport, OracleStats};

    fn make_clean_report(invariants: &[&str]) -> OracleReport {
        let entries = invariants
            .iter()
            .map(|inv| OracleEntryReport {
                invariant: inv.to_string(),
                passed: true,
                violation: None,
                stats: OracleStats {
                    entities_tracked: 5,
                    events_recorded: 10,
                },
            })
            .collect::<Vec<_>>();
        let total = entries.len();
        OracleReport {
            entries,
            total,
            passed: total,
            failed: 0,
            check_time_nanos: 0,
        }
    }

    fn make_violation_report(invariants: &[&str], violated: &[&str]) -> OracleReport {
        let entries = invariants
            .iter()
            .map(|inv| {
                let is_violated = violated.contains(inv);
                OracleEntryReport {
                    invariant: inv.to_string(),
                    passed: !is_violated,
                    violation: if is_violated {
                        Some("test violation".into())
                    } else {
                        None
                    },
                    stats: OracleStats {
                        entities_tracked: 5,
                        events_recorded: 10,
                    },
                }
            })
            .collect::<Vec<_>>();
        let total = entries.len();
        let failed = entries.iter().filter(|e| !e.passed).count();
        OracleReport {
            entries,
            total,
            passed: total - failed,
            failed,
            check_time_nanos: 0,
        }
    }

    // -- EProcessConfig --

    #[test]
    fn config_default_valid() {
        assert!(EProcessConfig::default().validate().is_ok());
    }

    #[test]
    fn config_threshold() {
        let config = EProcessConfig::default();
        assert!((config.threshold() - 20.0).abs() < 1e-10);
    }

    #[test]
    fn config_invalid_p0() {
        let c = EProcessConfig {
            p0: 0.0,
            ..EProcessConfig::default()
        };
        assert!(c.validate().is_err());
        let c = EProcessConfig {
            p0: 1.0,
            ..EProcessConfig::default()
        };
        assert!(c.validate().is_err());
        let c = EProcessConfig {
            p0: -0.1,
            ..EProcessConfig::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn config_invalid_lambda() {
        let c = EProcessConfig {
            lambda: -2000.0,
            ..EProcessConfig::default()
        };
        assert!(c.validate().is_err());
        let c = EProcessConfig {
            lambda: 2000.0,
            ..EProcessConfig::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn config_invalid_alpha() {
        let c = EProcessConfig {
            alpha: 0.0,
            ..EProcessConfig::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn config_invalid_max_evalue() {
        // max_evalue must be >= 1.0 and finite
        let c = EProcessConfig {
            max_evalue: 0.0,
            ..EProcessConfig::default()
        };
        assert!(c.validate().is_err());

        let c = EProcessConfig {
            max_evalue: -1.0,
            ..EProcessConfig::default()
        };
        assert!(c.validate().is_err());

        let c = EProcessConfig {
            max_evalue: f64::NAN,
            ..EProcessConfig::default()
        };
        assert!(c.validate().is_err());

        let c = EProcessConfig {
            max_evalue: f64::INFINITY,
            ..EProcessConfig::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn config_max_evalue_below_threshold() {
        // max_evalue < 1/alpha makes rejection impossible
        let c = EProcessConfig {
            alpha: 0.05,
            max_evalue: 10.0, // threshold is 20
            ..EProcessConfig::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn config_lambda_bounds_correct_for_large_p0() {
        // With p0=0.6, correct bounds are (-2.5, 1.667)
        // lambda=1.5 should be valid (factor at x=0: 1 - 1.5*0.6 = 0.1 > 0)
        let c = EProcessConfig {
            p0: 0.6,
            lambda: 1.5,
            alpha: 0.05,
            max_evalue: 1e15,
        };
        assert!(c.validate().is_ok());

        // lambda=1.7 should be invalid (factor at x=0: 1 - 1.7*0.6 = -0.02 < 0)
        let c = EProcessConfig {
            p0: 0.6,
            lambda: 1.7,
            alpha: 0.05,
            max_evalue: 1e15,
        };
        assert!(
            c.validate().is_err(),
            "lambda=1.7 with p0=0.6 should be rejected (negative factor)"
        );
    }

    // -- EValue --

    #[test]
    fn evalue_rejects() {
        let ev = EValue {
            value: 25.0,
            time: 0,
        };
        assert!(ev.rejects_at(0.05)); // 1/0.05 = 20, 25 >= 20
        assert!(!ev.rejects_at(0.01)); // 1/0.01 = 100, 25 < 100
    }

    // -- EProcess core --

    #[test]
    fn eprocess_starts_at_one() {
        let ep = EProcess::new("test", EProcessConfig::default());
        assert!((ep.current - 1.0).abs() < 1e-10);
        assert_eq!(ep.observations, 0);
        assert!(!ep.rejected);
    }

    #[test]
    fn eprocess_clean_observations_decrease() {
        let mut ep = EProcess::new("test", EProcessConfig::default());
        // Under H0 with no violations, e-value should decrease slightly.
        for _ in 0..10 {
            ep.observe(false);
        }
        assert!(
            ep.current < 1.0,
            "clean observations should decrease e-value, got {}",
            ep.current
        );
        assert_eq!(ep.observations, 10);
        assert_eq!(ep.violations_observed, 0);
        assert!(!ep.rejected);
    }

    #[test]
    fn eprocess_violations_increase() {
        let mut ep = EProcess::new("test", EProcessConfig::default());
        ep.observe(true);
        assert!(
            ep.current > 1.0,
            "violation should increase e-value, got {}",
            ep.current
        );
        assert_eq!(ep.violations_observed, 1);
    }

    #[test]
    fn eprocess_many_violations_reject() {
        let mut ep = EProcess::new("test", EProcessConfig::default());
        // With repeated violations, should eventually reject.
        for _ in 0..20 {
            ep.observe(true);
        }
        assert!(ep.rejected, "repeated violations should cause rejection");
        assert!(ep.rejection_time.is_some());
    }

    #[test]
    fn eprocess_rejection_is_sticky() {
        let mut ep = EProcess::new("test", EProcessConfig::default());
        for _ in 0..20 {
            ep.observe(true);
        }
        let rejection_time = ep.rejection_time;
        assert!(ep.rejected);

        // Further clean observations don't un-reject.
        for _ in 0..100 {
            ep.observe(false);
        }
        assert!(ep.rejected, "rejection should be sticky");
        assert_eq!(
            ep.rejection_time, rejection_time,
            "rejection time should not change"
        );
    }

    #[test]
    fn eprocess_history_recorded() {
        let mut ep = EProcess::new("test", EProcessConfig::default());
        ep.observe(false);
        ep.observe(true);
        ep.observe(false);
        assert_eq!(ep.history.len(), 3);
        assert_eq!(ep.history[0].time, 0);
        assert_eq!(ep.history[1].time, 1);
        assert_eq!(ep.history[2].time, 2);
    }

    #[test]
    fn eprocess_no_history() {
        let mut ep = EProcess::new_without_history("test", EProcessConfig::default());
        ep.observe(false);
        ep.observe(true);
        assert!(ep.history.is_empty());
    }

    #[test]
    fn eprocess_reset() {
        let mut ep = EProcess::new("test", EProcessConfig::default());
        ep.observe(true);
        ep.observe(true);
        assert!(ep.current > 1.0);
        ep.reset();
        assert!((ep.current - 1.0).abs() < 1e-10);
        assert_eq!(ep.observations, 0);
        assert_eq!(ep.violations_observed, 0);
        assert!(!ep.rejected);
        assert!(ep.history.is_empty());
    }

    #[test]
    fn eprocess_empirical_rate() {
        let mut ep = EProcess::new("test", EProcessConfig::default());
        ep.observe(false);
        ep.observe(true);
        ep.observe(false);
        ep.observe(true);
        assert!((ep.empirical_rate() - 0.5).abs() < 1e-10);
    }

    #[test]
    fn eprocess_empirical_rate_zero_observations() {
        let ep = EProcess::new("test", EProcessConfig::default());
        assert!((ep.empirical_rate()).abs() < 1e-10);
    }

    #[test]
    fn eprocess_log10_evalue() {
        let mut ep = EProcess::new("test", EProcessConfig::default());
        ep.current = 100.0;
        assert!((ep.log10_e_value() - 2.0).abs() < 1e-10);
    }

    #[test]
    fn eprocess_evalue_capped() {
        let mut ep = EProcess::new("test", EProcessConfig::default());
        // Drive e-value very high.
        for _ in 0..1000 {
            ep.observe(true);
        }
        assert!(
            ep.current <= ep.config.max_evalue,
            "e-value should be capped"
        );
        assert!(ep.current.is_finite());
    }

    // -- EProcessMonitor --

    #[test]
    fn monitor_standard_has_three_invariants() {
        let monitor = EProcessMonitor::standard();
        assert_eq!(monitor.processes.len(), 3);
        assert!(monitor.process("task_leak").is_some());
        assert!(monitor.process("obligation_leak").is_some());
        assert!(monitor.process("quiescence").is_some());
    }

    #[test]
    fn monitor_all_invariants_has_spork_invariants_too() {
        let monitor = EProcessMonitor::all_invariants();
        let expected = if cfg!(feature = "messaging-fabric") {
            28
        } else {
            24
        };
        assert_eq!(monitor.processes.len(), expected);
        assert!(monitor.process("reply_linearity").is_some());
        assert!(monitor.process("registry_lease").is_some());
        assert!(monitor.process("down_order").is_some());
        assert!(monitor.process("supervisor_quiescence").is_some());
    }

    #[test]
    fn monitor_all_invariants_rejects_every_reported_oracle() {
        // observe_report skips entries without an e-process, so an oracle the
        // monitor does not track can never have its violations rejected.
        let mut suite = crate::lab::oracle::OracleSuite::new();
        let report = suite.report(crate::types::Time::ZERO);
        let names: Vec<&str> = report
            .entries
            .iter()
            .map(|entry| entry.invariant.as_str())
            .collect();
        assert_eq!(
            EProcessMonitor::all_invariants().processes.len(),
            names.len()
        );
        #[cfg(feature = "messaging-fabric")]
        for fabric in [
            "fabric_publish",
            "fabric_reply",
            "fabric_quiescence",
            "fabric_redelivery",
        ] {
            assert!(names.contains(&fabric), "suite does not report {fabric}");
        }

        for name in &names {
            let mut monitor = EProcessMonitor::all_invariants();
            for _ in 0..20 {
                monitor.observe_report(&make_violation_report(&names, &[name]));
            }
            assert_eq!(
                monitor.rejected_invariants(),
                vec![*name],
                "violations of {name} were not rejected"
            );
        }
    }

    #[test]
    fn monitor_observe_report_clean() {
        let mut monitor = EProcessMonitor::standard();
        let report = make_clean_report(&["task_leak", "obligation_leak", "quiescence"]);

        for _ in 0..10 {
            monitor.observe_report(&report);
        }

        assert!(!monitor.any_rejected());
        assert!(monitor.rejected_invariants().is_empty());

        // All e-values should be < 1 (evidence against violation).
        for ep in &monitor.processes {
            assert!(
                ep.current < 1.0,
                "clean reports should decrease e-value for '{}'",
                ep.invariant
            );
        }
    }

    #[test]
    fn monitor_observe_report_violation() {
        let mut monitor = EProcessMonitor::standard();
        let invariants = ["task_leak", "obligation_leak", "quiescence"];

        // Feed 20 reports with task_leak violated.
        for _ in 0..20 {
            let report = make_violation_report(&invariants, &["task_leak"]);
            monitor.observe_report(&report);
        }

        assert!(monitor.any_rejected());
        let rejected = monitor.rejected_invariants();
        assert!(rejected.contains(&"task_leak"));
        assert!(!rejected.contains(&"obligation_leak"));
        assert!(!rejected.contains(&"quiescence"));
    }

    #[test]
    fn monitor_observe_raw() {
        let mut monitor = EProcessMonitor::standard();

        assert!(monitor.observe("task_leak", true));
        assert!(monitor.observe("task_leak", false));
        assert!(!monitor.observe("nonexistent", true));

        let ep = monitor.process("task_leak").unwrap();
        assert_eq!(ep.observations, 2);
        assert_eq!(ep.violations_observed, 1);
    }

    #[test]
    fn monitor_results() {
        let mut monitor = EProcessMonitor::standard();
        let report = make_clean_report(&["task_leak", "obligation_leak", "quiescence"]);
        monitor.observe_report(&report);

        let results = monitor.results();
        assert_eq!(results.len(), 3);
        for r in &results {
            assert_eq!(r.observations, 1);
            assert!(!r.rejected);
        }
    }

    #[test]
    fn monitor_reset() {
        let mut monitor = EProcessMonitor::standard();
        monitor.observe("task_leak", true);
        monitor.observe("task_leak", true);
        monitor.reset();

        for ep in &monitor.processes {
            assert!((ep.current - 1.0).abs() < 1e-10);
            assert_eq!(ep.observations, 0);
        }
    }

    #[test]
    fn monitor_to_text() {
        let mut monitor = EProcessMonitor::standard();
        let report = make_clean_report(&["task_leak", "obligation_leak", "quiescence"]);
        monitor.observe_report(&report);

        let text = monitor.to_text();
        assert!(text.contains("E-Process Monitor"));
        assert!(text.contains("task_leak"));
        assert!(text.contains("monitoring"));
    }

    #[test]
    fn monitor_to_json() {
        let monitor = EProcessMonitor::standard();
        let json = monitor.to_json();
        assert!(json["processes"].is_array());
        assert!(json["config"].is_object());
    }

    #[test]
    fn monitor_json_roundtrip() {
        let mut monitor = EProcessMonitor::standard();
        let report = make_clean_report(&["task_leak", "obligation_leak", "quiescence"]);
        monitor.observe_report(&report);
        monitor.observe_report(&report);

        let json_str = serde_json::to_string(&monitor).unwrap();
        let deserialized: EProcessMonitor = serde_json::from_str(&json_str).unwrap();

        assert_eq!(deserialized.processes.len(), monitor.processes.len());
        for (orig, deser) in monitor.processes.iter().zip(deserialized.processes.iter()) {
            assert_eq!(orig.invariant, deser.invariant);
            assert!((orig.current - deser.current).abs() < 1e-10);
            assert_eq!(orig.observations, deser.observations);
        }
    }

    // -- Martingale property --

    #[test]
    fn eprocess_martingale_under_null() {
        // Under H0, the e-process should not grow systematically.
        // Run many trials and check the average final e-value is ≈ 1.
        let n_trials: u32 = 1000;
        let n_obs: u32 = 50;
        let config = EProcessConfig::default();
        let p0 = config.p0;

        let mut sum_final_e = 0.0;
        let mut rng_state: u64 = 42;

        for _ in 0..n_trials {
            let mut ep = EProcess::new_without_history("test", config.clone());
            for _ in 0..n_obs {
                // Simple PRNG for deterministic test.
                rng_state = rng_state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                let u = f64::from((rng_state >> 33) as u32) / f64::from(1_u32 << 31);
                let violated = u < p0;
                ep.observe(violated);
            }
            sum_final_e += ep.current;
        }

        let avg_e = sum_final_e / f64::from(n_trials);
        // Under H0, E[E_T] ≤ 1 (supermartingale). Allow slack for finite samples.
        assert!(
            avg_e < 2.0,
            "average e-value under H0 should be ≤ 1 (got {avg_e:.4})"
        );
    }

    #[test]
    fn eprocess_detects_elevated_rate() {
        // Under H1 with violation rate 10%, should reject quickly.
        let config = EProcessConfig::default();
        let mut ep = EProcess::new("test", config);

        // Use a deterministic 10% violation pattern to avoid RNG flakiness.
        for i in 0..100 {
            let violated = i % 10 == 0;
            ep.observe(violated);
        }

        assert!(
            ep.rejected,
            "elevated violation rate (10%) should be detected within 100 observations"
        );
    }

    // -- Early stopping validity --

    #[test]
    fn early_stopping_valid() {
        // The key property: stopping when E_t first exceeds 1/α should give
        // type-I error ≤ α. Test over many null trials.
        let n_trials: u32 = 10_000;
        let n_obs: u32 = 100;
        let config = EProcessConfig {
            alpha: 0.05,
            ..EProcessConfig::default()
        };
        let p0 = config.p0;

        let mut false_rejections: u32 = 0;
        let mut rng_state: u64 = 999;

        for _ in 0..n_trials {
            let mut ep = EProcess::new_without_history("test", config.clone());
            for _ in 0..n_obs {
                rng_state = rng_state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                let u = f64::from((rng_state >> 33) as u32) / f64::from(1_u32 << 31);
                let violated = u < p0;
                ep.observe(violated);
            }
            if ep.rejected {
                false_rejections += 1;
            }
        }

        let fpr = f64::from(false_rejections) / f64::from(n_trials);
        // By Ville's inequality, FPR ≤ α = 0.05. Allow generous slack.
        assert!(
            fpr < 0.10,
            "false positive rate under optional stopping should be ≤ α, got {fpr:.4}"
        );
    }

    // -- NaN / Inf rejection --

    #[test]
    fn validate_rejects_nan_p0() {
        let config = EProcessConfig {
            p0: f64::NAN,
            ..EProcessConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_rejects_nan_lambda() {
        let config = EProcessConfig {
            lambda: f64::NAN,
            ..EProcessConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_rejects_nan_alpha() {
        let config = EProcessConfig {
            alpha: f64::NAN,
            ..EProcessConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_rejects_inf_p0() {
        let config = EProcessConfig {
            p0: f64::INFINITY,
            ..EProcessConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_rejects_neg_inf_lambda() {
        let config = EProcessConfig {
            lambda: f64::NEG_INFINITY,
            ..EProcessConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    #[should_panic(expected = "EProcessConfig validation failed")]
    fn constructor_panics_on_nan_config() {
        let config = EProcessConfig {
            p0: f64::NAN,
            ..EProcessConfig::default()
        };
        let _ep = EProcess::new("test", config);
    }

    // -- Integration with OracleSuite --

    #[test]
    fn monitor_with_oracle_suite() {
        let mut suite = crate::lab::oracle::OracleSuite::new();
        let report = suite.report(crate::types::Time::ZERO);

        let mut monitor = EProcessMonitor::all_invariants();
        for _ in 0..10 {
            monitor.observe_report(&report);
        }

        assert!(
            !monitor.any_rejected(),
            "clean suite should not trigger rejection"
        );
        for r in monitor.results() {
            assert!(!r.rejected);
            assert!(
                r.e_value < 1.0,
                "clean: e-value should be < 1 for {}",
                r.invariant
            );
        }
    }
