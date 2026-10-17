    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    fn make_baseline_stats(gauss_ops: usize, inactivated: usize) -> DecodeStats {
        DecodeStats {
            gauss_ops,
            inactivated,
            dense_core_rows: gauss_ops / 2,
            dense_core_cols: gauss_ops / 3,
            pivots_selected: inactivated,
            peel_frontier_peak: 4,
            policy_mode: Some("stable"),
            ..Default::default()
        }
    }

    #[test]
    fn monitor_starts_in_calibrating_state() {
        let mut monitor = RegressionMonitor::new();
        let stats = make_baseline_stats(10, 3);
        let report = monitor.check(&stats);
        assert_eq!(
            report.overall_verdict,
            RegressionVerdict::Calibrating,
            "should be calibrating before min samples"
        );
        for metric in TRACKED_METRICS {
            assert!(
                (monitor.e_value(metric).expect("tracked metric") - 1.0).abs() < f64::EPSILON,
                "pre-calibration check should not mutate e-value for {metric}"
            );
        }
    }

    #[test]
    fn check_only_warmup_marks_monitor_calibrated() {
        let mut monitor = RegressionMonitor::new();

        for i in 0..(MIN_CALIBRATION_SAMPLES + 5) {
            let stats = make_baseline_stats(10 + i % 3, 3 + i % 2);
            let _ = monitor.check(&stats);
        }

        assert!(
            monitor.is_calibrated(),
            "check-only warmup should flip the public calibration state once all metrics are calibrated"
        );
        assert!(
            TRACKED_METRICS
                .iter()
                .all(|metric| monitor.threshold(metric).is_some()),
            "every tracked metric should expose a threshold after check-only warmup"
        );
    }

    #[test]
    fn regression_log_lines_render_one_line_per_metric() {
        let report = RegressionReport {
            schema_version: G8_SCHEMA_VERSION,
            replay_ref: G8_REPLAY_REF,
            metrics: vec![MetricRegressionResult {
                metric: "gauss_ops".to_string(),
                value: 12.0,
                threshold: Some(15.0),
                e_value: 1.25,
                calibration_n: 10,
                exceeds_threshold: false,
                verdict: RegressionVerdict::Accept,
            }],
            overall_verdict: RegressionVerdict::Accept,
            total_observations: 11,
            regressed_count: 0,
            warning_count: 0,
            regime_state: Some("stable".to_string()),
        };

        let lines = regression_log_lines(&report);

        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("\"metric\":\"gauss_ops\""));
        assert!(lines[0].contains("\"verdict\":\"accept\""));
        assert!(lines[0].contains("\"regime_state\":\"stable\""));
    }

    #[test]
    fn regression_log_lines_escape_string_fields() {
        let regime_state = "retuned\\fallback\"line\nbreak".to_string();
        let metric = "gauss\"ops\nburst".to_string();
        let report = RegressionReport {
            schema_version: G8_SCHEMA_VERSION,
            replay_ref: G8_REPLAY_REF,
            metrics: vec![MetricRegressionResult {
                metric: metric.clone(),
                value: 12.0,
                threshold: Some(15.0),
                e_value: 1.25,
                calibration_n: 10,
                exceeds_threshold: false,
                verdict: RegressionVerdict::Accept,
            }],
            overall_verdict: RegressionVerdict::Accept,
            total_observations: 11,
            regressed_count: 0,
            warning_count: 0,
            regime_state: Some(regime_state.clone()),
        };

        let lines = regression_log_lines(&report);
        let parsed: serde_json::Value =
            serde_json::from_str(&lines[0]).expect("rendered line must stay valid JSON");

        assert_eq!(parsed["metric"].as_str(), Some(metric.as_str()));
        assert_eq!(parsed["regime_state"].as_str(), Some(regime_state.as_str()));
    }

    #[test]
    fn monitor_transitions_to_accept_after_calibration() {
        let mut monitor = RegressionMonitor::new();

        // Calibrate with baseline observations.
        for i in 0..MIN_CALIBRATION_SAMPLES + 5 {
            let stats = make_baseline_stats(10 + i % 3, 3);
            monitor.calibrate(&stats);
        }
        assert!(
            monitor.is_calibrated(),
            "should be calibrated after {} samples",
            MIN_CALIBRATION_SAMPLES + 5
        );

        // Check a normal observation.
        let stats = make_baseline_stats(11, 3);
        let report = monitor.check(&stats);
        assert_eq!(
            report.overall_verdict,
            RegressionVerdict::Accept,
            "normal observation should be accepted"
        );
    }

    #[test]
    fn monitor_detects_warning_on_threshold_exceedance() {
        let mut monitor = RegressionMonitor::new();

        // Calibrate with small values.
        for i in 0..(MIN_CALIBRATION_SAMPLES + 5) {
            let stats = make_baseline_stats(10 + i % 2, 3);
            monitor.calibrate(&stats);
        }

        // Check with a much larger value.
        let stats = make_baseline_stats(1000, 3);
        let report = monitor.check(&stats);
        assert!(
            matches!(
                report.overall_verdict,
                RegressionVerdict::Warning | RegressionVerdict::Regressed
            ),
            "large deviation should trigger warning or regression, got {:?}",
            report.overall_verdict
        );
    }

    #[test]
    fn monitor_accumulates_evidence_for_regression() {
        let mut monitor = RegressionMonitor::new();

        // Calibrate with small values.
        for i in 0..(MIN_CALIBRATION_SAMPLES + 5) {
            let stats = make_baseline_stats(10 + i % 2, 3);
            monitor.calibrate(&stats);
        }

        // Feed many anomalous observations to accumulate e-value evidence.
        let mut any_regressed = false;
        for _ in 0..200 {
            let stats = make_baseline_stats(1000, 100);
            let report = monitor.check(&stats);
            if report.overall_verdict == RegressionVerdict::Regressed {
                any_regressed = true;
                break;
            }
        }

        assert!(
            any_regressed,
            "sustained large deviation should trigger regression detection"
        );
        assert!(monitor.any_regressed());
        assert!(!monitor.regressed_metrics().is_empty());
    }

    #[test]
    fn pre_calibration_checks_do_not_dilute_later_regression_evidence() {
        let mut clean = RegressionMonitor::new();
        let mut with_prechecks = RegressionMonitor::new();

        for i in 0..MIN_CALIBRATION_SAMPLES {
            let stats = make_baseline_stats(10 + i % 2, 3);
            clean.calibrate(&stats);
            let report = with_prechecks.check(&stats);
            assert_eq!(
                report.overall_verdict,
                RegressionVerdict::Calibrating,
                "warmup observations fed via check() must remain calibration-only until activation"
            );
        }

        let anomaly = make_baseline_stats(1_000, 100);
        let clean_report = clean.check(&anomaly);
        let prechecked_report = with_prechecks.check(&anomaly);

        assert_eq!(
            clean_report.overall_verdict, prechecked_report.overall_verdict,
            "pre-calibration checks should not change the first live verdict"
        );
        for metric in TRACKED_METRICS {
            let clean_e = clean.e_value(metric).expect("tracked metric");
            let prechecked_e = with_prechecks.e_value(metric).expect("tracked metric");
            assert!(
                (clean_e - prechecked_e).abs() < f64::EPSILON,
                "pre-calibration checks should not dilute e-process evidence for {metric}: clean={clean_e}, prechecked={prechecked_e}"
            );
        }
    }

    #[test]
    fn metamorphic_decode_tolerance_bound_is_monotone_at_threshold_edge() {
        fn calibrated_monitor() -> RegressionMonitor {
            let mut monitor = RegressionMonitor::new();
            for i in 0..(MIN_CALIBRATION_SAMPLES + 5) {
                let stats = make_baseline_stats(10 + i % 3, 3);
                monitor.calibrate(&stats);
            }
            monitor
        }

        let threshold_probe = calibrated_monitor();
        let threshold = threshold_probe
            .threshold("gauss_ops")
            .expect("gauss_ops threshold should be calibrated");

        let tolerated_value = threshold.floor().max(10.0) as usize;
        let violating_value = (threshold.ceil() as usize).saturating_add(1);

        let mut tolerated_stats = make_baseline_stats(10, 3);
        tolerated_stats.gauss_ops = tolerated_value;
        let mut violating_stats = tolerated_stats.clone();
        violating_stats.gauss_ops = violating_value;

        let tolerated_report = calibrated_monitor().check(&tolerated_stats);
        let violating_report = calibrated_monitor().check(&violating_stats);

        let tolerated_metric = tolerated_report
            .metrics
            .iter()
            .find(|metric| metric.metric == "gauss_ops")
            .expect("gauss_ops metric missing from tolerated report");
        let violating_metric = violating_report
            .metrics
            .iter()
            .find(|metric| metric.metric == "gauss_ops")
            .expect("gauss_ops metric missing from violating report");

        assert!(
            !tolerated_metric.exceeds_threshold,
            "value {tolerated_value} should remain within threshold {threshold}"
        );
        assert_eq!(
            tolerated_metric.verdict,
            RegressionVerdict::Accept,
            "within-threshold observation should be accepted"
        );
        assert!(
            violating_metric.exceeds_threshold,
            "value {violating_value} should exceed threshold {threshold}"
        );
        assert!(
            matches!(
                violating_metric.verdict,
                RegressionVerdict::Warning | RegressionVerdict::Regressed
            ),
            "threshold violation should escalate verdict, got {:?}",
            violating_metric.verdict
        );
        assert!(
            (violating_report.overall_verdict as u8) >= (tolerated_report.overall_verdict as u8),
            "crossing the learned tolerance bound must not lower overall severity"
        );
    }

    #[test]
    fn monitor_stable_workload_no_false_alarm() {
        let mut monitor = RegressionMonitor::new();

        // Calibrate.
        for i in 0..(MIN_CALIBRATION_SAMPLES + 5) {
            let stats = make_baseline_stats(10 + i % 3, 3 + i % 2);
            monitor.calibrate(&stats);
        }

        // Check 100 normal observations — no false alarm.
        for i in 0..100 {
            let stats = make_baseline_stats(10 + i % 3, 3 + i % 2);
            let report = monitor.check(&stats);
            assert_ne!(
                report.overall_verdict,
                RegressionVerdict::Regressed,
                "stable workload should not trigger false alarm at check {i}"
            );
        }

        assert!(
            !monitor.any_regressed(),
            "stable workload should have no regressions"
        );
    }

    #[test]
    fn monitor_reset_evidence_clears_e_processes() {
        let mut monitor = RegressionMonitor::new();

        // Calibrate and force regression.
        for i in 0..(MIN_CALIBRATION_SAMPLES + 5) {
            let stats = make_baseline_stats(10, 3 + i % 2);
            monitor.calibrate(&stats);
        }
        for _ in 0..200 {
            let stats = make_baseline_stats(1000, 100);
            let _ = monitor.check(&stats);
        }

        // Reset evidence.
        monitor.reset_evidence();
        assert!(
            !monitor.any_regressed(),
            "reset should clear regression state"
        );

        // Normal observations should be accepted.
        let stats = make_baseline_stats(11, 3);
        let report = monitor.check(&stats);
        assert_ne!(
            report.overall_verdict,
            RegressionVerdict::Regressed,
            "post-reset should not show regression"
        );
    }

    #[test]
    fn regression_report_schema_and_replay_ref() {
        let mut monitor = RegressionMonitor::new();

        for i in 0..(MIN_CALIBRATION_SAMPLES + 5) {
            let stats = make_baseline_stats(10 + i, 3);
            monitor.calibrate(&stats);
        }

        let stats = make_baseline_stats(10, 3);
        let report = monitor.check(&stats);
        assert_eq!(report.schema_version, G8_SCHEMA_VERSION);
        assert_eq!(report.replay_ref, G8_REPLAY_REF);
        assert_eq!(report.metrics.len(), TRACKED_METRICS.len());
    }

    #[test]
    fn verdict_ordering_is_correct() {
        assert!((RegressionVerdict::Accept as u8) < (RegressionVerdict::Calibrating as u8));
        assert!((RegressionVerdict::Calibrating as u8) < (RegressionVerdict::Warning as u8));
        assert!((RegressionVerdict::Warning as u8) < (RegressionVerdict::Regressed as u8));
    }

    #[test]
    fn e_value_and_threshold_accessors() {
        let mut monitor = RegressionMonitor::new();

        // Before calibration.
        assert!(monitor.threshold("gauss_ops").is_none());

        for i in 0..(MIN_CALIBRATION_SAMPLES + 5) {
            let stats = make_baseline_stats(10 + i, 3);
            monitor.calibrate(&stats);
        }

        // After calibration.
        assert!(monitor.threshold("gauss_ops").is_some());
        assert!(monitor.e_value("gauss_ops").is_some());
    }

    #[test]
    fn regime_state_covariate_captured() {
        let mut monitor = RegressionMonitor::new();

        for i in 0..(MIN_CALIBRATION_SAMPLES + 5) {
            let stats = make_baseline_stats(10 + i, 3);
            monitor.calibrate(&stats);
        }

        let mut stats = make_baseline_stats(10, 3);
        stats.policy_mode = Some("retuned");
        let report = monitor.check(&stats);
        assert_eq!(
            report.regime_state,
            Some("retuned".to_string()),
            "regime state should be captured from DecodeStats"
        );
    }

    #[test]
    fn deterministic_replay_produces_identical_reports() {
        let observations: Vec<DecodeStats> = (0..50)
            .map(|i| make_baseline_stats(10 + i % 5, 3 + i % 3))
            .collect();

        let mut mon_a = RegressionMonitor::new();
        let mut mon_b = RegressionMonitor::new();

        // Calibrate both.
        for obs in observations.iter().take(MIN_CALIBRATION_SAMPLES + 5) {
            mon_a.calibrate(obs);
            mon_b.calibrate(obs);
        }

        // Check remaining.
        for obs in observations.iter().skip(MIN_CALIBRATION_SAMPLES + 5) {
            let report_a = mon_a.check(obs);
            let report_b = mon_b.check(obs);

            assert_eq!(
                report_a.overall_verdict, report_b.overall_verdict,
                "deterministic replay violated"
            );
            for (ra, rb) in report_a.metrics.iter().zip(report_b.metrics.iter()) {
                assert_eq!(ra.metric, rb.metric);
                assert!(
                    (ra.e_value - rb.e_value).abs() < f64::EPSILON,
                    "expected {}, got {}",
                    rb.e_value,
                    ra.e_value
                );
                assert_eq!(ra.verdict, rb.verdict);
            }
        }
    }
