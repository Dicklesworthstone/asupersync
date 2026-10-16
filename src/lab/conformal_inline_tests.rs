    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::lab::OracleStats;

    fn make_clean_report(entities: usize, events: usize) -> OracleReport {
        OracleReport {
            entries: vec![OracleEntryReport {
                invariant: "test_oracle".to_string(),
                passed: true,
                violation: None,
                stats: OracleStats {
                    entities_tracked: entities,
                    events_recorded: events,
                },
            }],
            total: 1,
            passed: 1,
            failed: 0,
            check_time_nanos: 0,
        }
    }

    fn make_violated_report(entities: usize, events: usize) -> OracleReport {
        OracleReport {
            entries: vec![OracleEntryReport {
                invariant: "test_oracle".to_string(),
                passed: false,
                violation: Some("test violation".to_string()),
                stats: OracleStats {
                    entities_tracked: entities,
                    events_recorded: events,
                },
            }],
            total: 1,
            passed: 0,
            failed: 1,
            check_time_nanos: 0,
        }
    }

    #[test]
    fn conformal_quantile_empty() {
        assert!(conformal_quantile(&[], 0.05).is_infinite());
    }

    #[test]
    fn conformal_quantile_single() {
        // n=1, alpha=0.05: rank = ceil(0.95*2) = ceil(1.9) = 2 > n=1, so no
        // finite score attains 95% coverage with a single calibration point
        // (alpha < 1/(n+1) = 0.5) — the threshold is +inf (cover everything).
        let scores = [0.5];
        assert!(conformal_quantile(&scores, 0.05).is_infinite());

        // n=1, alpha=0.5: rank = ceil(0.5*2) = 1 <= n, so the single score is
        // the (finite) threshold.
        let q = conformal_quantile(&scores, 0.5);
        assert!((q - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn conformal_quantile_sorted() {
        let scores = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0];
        // (1-0.05)(10+1) = 10.45, ceil = 11 > n=10 => +inf (no finite score
        // attains 95% coverage; clamping to the max would only give 10/11).
        assert!(conformal_quantile(&scores, 0.05).is_infinite());

        let q80 = conformal_quantile(&scores, 0.20);
        // (1-0.20)(10+1) = 8.8, ceil = 9 <= n=10, -1 = 8 => scores[8] = 0.9
        assert!((q80 - 0.9).abs() < f64::EPSILON);
    }

    #[test]
    fn conformal_quantile_infinite_when_rank_exceeds_n() {
        // br-asupersync-mdym3s boundary: the finite-sample guarantee needs the
        // ceil((n+1)(1-alpha))-th order statistic; when that rank exceeds n the
        // threshold must be +inf, not the largest score. Both levels below are
        // clearly non-integer to avoid float-edge fragility.
        let twenty: Vec<f64> = (1..=20).map(f64::from).collect();
        // n=20, alpha=0.05: rank = ceil(0.95*21) = ceil(19.95) = 20 == n =>
        // finite (the 20th order statistic).
        let q = conformal_quantile(&twenty, 0.05);
        assert!(
            (q - 20.0).abs() < f64::EPSILON,
            "rank==n is finite, got {q}"
        );

        // n=20, alpha=0.04: rank = ceil(0.96*21) = ceil(20.16) = 21 > n => +inf.
        assert!(
            conformal_quantile(&twenty, 0.04).is_infinite(),
            "rank>n must be +inf to preserve >= 1-alpha coverage"
        );
    }

    #[test]
    fn calibrator_starts_uncalibrated() {
        let cal = ConformalCalibrator::default_calibrator();
        assert!(!cal.is_calibrated());
        assert_eq!(cal.calibration_samples(), 0);
    }

    #[test]
    fn calibrator_becomes_calibrated() {
        let config = ConformalConfig::new(0.10).min_samples(3);
        let mut cal = ConformalCalibrator::new(config);

        for _ in 0..3 {
            cal.calibrate(&make_clean_report(10, 50));
        }
        assert!(cal.is_calibrated());
        assert_eq!(cal.calibration_samples(), 3);
    }

    #[test]
    fn predict_returns_none_before_calibrated() {
        let config = ConformalConfig::new(0.10).min_samples(5);
        let mut cal = ConformalCalibrator::new(config);

        // First 4 reports: not yet calibrated.
        for _ in 0..4 {
            assert!(cal.predict(&make_clean_report(10, 50)).is_none());
        }
        // 5th: completes calibration, but returns None to avoid testing
        // the calibration-completing observation against a set that
        // includes it (exchangeability requirement).
        let report = cal.predict(&make_clean_report(10, 50));
        assert!(
            report.is_none(),
            "calibration-completing observation must be skipped"
        );

        // 6th: now truly post-calibration — returns a prediction.
        let report = cal.predict(&make_clean_report(10, 50));
        assert!(
            report.is_some(),
            "post-calibration observation should produce prediction"
        );
    }

    #[test]
    fn clean_observations_are_conforming() {
        let config = ConformalConfig::new(0.10).min_samples(3);
        let mut cal = ConformalCalibrator::new(config);

        // Calibrate with clean reports.
        for _ in 0..5 {
            cal.calibrate(&make_clean_report(10, 50));
        }

        // New clean observation should be conforming.
        let report = cal.predict(&make_clean_report(10, 50)).unwrap();
        assert_eq!(report.prediction_sets.len(), 1);
        assert!(
            report.prediction_sets[0].conforming,
            "clean observation should be conforming"
        );
    }

    #[test]
    fn sparse_calibration_uses_infinite_threshold_for_high_coverage() {
        let config = ConformalConfig::new(0.05).min_samples(3);
        let mut cal = ConformalCalibrator::new(config);

        for _ in 0..3 {
            cal.calibrate(&make_clean_report(10, 50));
        }

        let report = cal.predict(&make_violated_report(10_000, 50_000)).unwrap();
        assert_eq!(report.prediction_sets.len(), 1);
        let prediction = &report.prediction_sets[0];
        assert!(
            prediction.threshold.is_infinite(),
            "n=3 alpha=0.05 requires +inf threshold, got {}",
            prediction.threshold
        );
        assert!(
            prediction.conforming,
            "high-coverage sparse calibration must cover all scores"
        );
    }

    #[test]
    fn violation_is_anomalous() {
        let config = ConformalConfig::new(0.10).min_samples(3);
        let mut cal = ConformalCalibrator::new(config);

        // Calibrate with clean reports.
        for _ in 0..10 {
            cal.calibrate(&make_clean_report(10, 50));
        }

        // Violated observation should be anomalous.
        let report = cal.predict(&make_violated_report(10, 50)).unwrap();
        assert!(!report.prediction_sets[0].conforming);
    }

    #[test]
    fn coverage_tracking() {
        let config = ConformalConfig::new(0.10).min_samples(3);
        let mut cal = ConformalCalibrator::new(config);

        // Calibrate.
        for _ in 0..5 {
            cal.calibrate(&make_clean_report(10, 50));
        }

        // Predict multiple clean observations.
        for _ in 0..10 {
            let _ = cal.predict(&make_clean_report(10, 50));
        }

        let rates = cal.coverage_rates();
        let rate = rates.get("test_oracle").copied().unwrap_or(0.0);
        assert!(
            rate >= 0.8,
            "coverage rate should be high for clean data, got {rate:.2}"
        );
    }

    #[test]
    fn calibration_report_text_output() {
        let config = ConformalConfig::new(0.05).min_samples(3);
        let mut cal = ConformalCalibrator::new(config);

        for _ in 0..5 {
            cal.calibrate(&make_clean_report(10, 50));
        }
        let report = cal.predict(&make_clean_report(10, 50)).unwrap();
        let text = report.to_text();

        assert!(text.contains("CONFORMAL CALIBRATION REPORT"));
        assert!(text.contains("95.0%"));
        assert!(text.contains("alpha=0.050"));
        assert!(text.contains("test_oracle"));
    }

    #[test]
    fn calibration_report_json_roundtrip() {
        let config = ConformalConfig::new(0.05).min_samples(3);
        let mut cal = ConformalCalibrator::new(config);

        for _ in 0..5 {
            cal.calibrate(&make_clean_report(10, 50));
        }
        let report = cal.predict(&make_clean_report(10, 50)).unwrap();
        let json = report.to_json();

        assert!(json.is_object());
        assert_eq!(json["alpha"], 0.05);
        assert!(json["well_calibrated"].as_bool().unwrap());
        assert!(json["prediction_sets"].is_array());
    }

    #[test]
    fn well_calibrated_with_clean_data() {
        let config = ConformalConfig::new(0.10).min_samples(3);
        let mut cal = ConformalCalibrator::new(config);

        for _ in 0..5 {
            cal.calibrate(&make_clean_report(10, 50));
        }

        let mut last_report = None;
        for _ in 0..20 {
            last_report = cal.predict(&make_clean_report(10, 50));
        }
        let report = last_report.unwrap();
        assert!(report.is_well_calibrated());
        assert!(report.miscalibrated_invariants().is_empty());
    }

    #[test]
    fn violation_rates_tracked() {
        let config = ConformalConfig::new(0.10).min_samples(2);
        let mut cal = ConformalCalibrator::new(config);

        cal.calibrate(&make_clean_report(10, 50));
        cal.calibrate(&make_violated_report(10, 50));
        cal.calibrate(&make_clean_report(10, 50));

        let rates = cal.violation_rates();
        let rate = rates.get("test_oracle").copied().unwrap_or(0.0);
        assert!(
            (rate - 1.0 / 3.0).abs() < 0.01,
            "expected ~0.33 violation rate, got {rate:.3}"
        );
    }

    #[test]
    fn conformity_score_clean_is_low() {
        let cal = InvariantCalibration::default();
        let entry = OracleEntryReport {
            invariant: "test".to_string(),
            passed: true,
            violation: None,
            stats: OracleStats {
                entities_tracked: 10,
                events_recorded: 50,
            },
        };
        let score = conformity_score(&entry, &cal);
        assert!(score < 1.0, "clean score should be < 1.0, got {score}");
    }

    #[test]
    fn conformity_score_violation_is_high() {
        let cal = InvariantCalibration::default();
        let entry = OracleEntryReport {
            invariant: "test".to_string(),
            passed: false,
            violation: Some("leak".to_string()),
            stats: OracleStats {
                entities_tracked: 10,
                events_recorded: 50,
            },
        };
        let score = conformity_score(&entry, &cal);
        assert!(
            score >= 1.0,
            "violation score should be >= 1.0, got {score}"
        );
    }

    #[test]
    fn deterministic_calibration() {
        let run = || {
            let config = ConformalConfig::new(0.05).min_samples(3);
            let mut cal = ConformalCalibrator::new(config);
            for i in 0..5 {
                cal.calibrate(&make_clean_report(10 + i, 50 + i * 5));
            }
            cal.predict(&make_clean_report(10, 50))
        };

        let r1 = run().unwrap();
        let r2 = run().unwrap();
        assert_eq!(r1.prediction_sets.len(), r2.prediction_sets.len());
        for (a, b) in r1.prediction_sets.iter().zip(r2.prediction_sets.iter()) {
            assert!((a.score - b.score).abs() < f64::EPSILON);
            assert_eq!(a.threshold, b.threshold);
            assert_eq!(a.conforming, b.conforming);
        }
    }

    // ========================================================================
    // HealthThresholdCalibrator tests
    // ========================================================================

    #[test]
    fn health_threshold_uncalibrated_returns_none() {
        let config = HealthThresholdConfig::new(0.05, ThresholdMode::Upper).min_samples(5);
        let cal = HealthThresholdCalibrator::new(config);
        assert!(cal.check("queue_depth", 10.0).is_none());
        assert!(!cal.is_metric_calibrated("queue_depth"));
    }

    #[test]
    fn health_threshold_upper_normal_conforming() {
        let config = HealthThresholdConfig::new(0.05, ThresholdMode::Upper).min_samples(5);
        let mut cal = HealthThresholdCalibrator::new(config);

        // Calibrate with queue depths 1..=10.
        for i in 1..=10 {
            cal.calibrate("queue_depth", f64::from(i));
        }
        assert!(cal.is_metric_calibrated("queue_depth"));

        // A value within the calibration range should be conforming.
        let result = cal.check("queue_depth", 5.0).unwrap();
        assert!(result.conforming, "normal depth should be conforming");
    }

    #[test]
    fn health_threshold_upper_extreme_anomalous() {
        let config = HealthThresholdConfig::new(0.05, ThresholdMode::Upper).min_samples(5);
        let mut cal = HealthThresholdCalibrator::new(config);

        // Calibrate with small queue depths.
        for i in 1..=20 {
            cal.calibrate("queue_depth", f64::from(i));
        }

        // A value far above the calibration range should be anomalous.
        let result = cal.check("queue_depth", 1000.0).unwrap();
        assert!(
            !result.conforming,
            "extreme depth should be anomalous, got threshold={:.2}",
            result.threshold
        );
    }

    #[test]
    fn health_threshold_two_sided_normal_conforming() {
        let config = HealthThresholdConfig::new(0.05, ThresholdMode::TwoSided).min_samples(5);
        let mut cal = HealthThresholdCalibrator::new(config);

        // Calibrate with values centered around 50.
        for v in [48.0, 50.0, 52.0, 49.0, 51.0, 50.0, 48.0, 52.0, 49.0, 51.0] {
            cal.calibrate("latency", v);
        }

        // A value near the median should be conforming.
        let result = cal.check("latency", 50.0).unwrap();
        assert!(result.conforming, "near-median value should be conforming");
    }

    #[test]
    fn health_threshold_two_sided_extreme_anomalous() {
        let config = HealthThresholdConfig::new(0.20, ThresholdMode::TwoSided).min_samples(5);
        let mut cal = HealthThresholdCalibrator::new(config);

        // Calibrate with values centered around 50.
        for v in [48.0, 50.0, 52.0, 49.0, 51.0, 50.0, 48.0, 52.0, 49.0, 51.0] {
            cal.calibrate("latency", v);
        }

        // A value far from the median should be anomalous.
        let result = cal.check("latency", 500.0).unwrap();
        assert!(
            !result.conforming,
            "far-from-median value should be anomalous"
        );
    }

    #[test]
    fn health_threshold_adaptive_grows_with_data() {
        let config = HealthThresholdConfig::new(0.20, ThresholdMode::Upper).min_samples(5);
        let mut cal = HealthThresholdCalibrator::new(config);

        // Phase 1: calibrate with small values.
        for i in 1..=10 {
            cal.calibrate("metric", f64::from(i));
        }
        let t1 = cal.threshold("metric").unwrap();

        // Phase 2: add larger values.
        for i in 11..=20 {
            cal.calibrate("metric", f64::from(i));
        }
        let t2 = cal.threshold("metric").unwrap();

        assert!(
            t2 >= t1,
            "threshold should grow as calibration expands, t1={t1}, t2={t2}"
        );
    }

    #[test]
    fn health_threshold_coverage_tracking() {
        let config = HealthThresholdConfig::new(0.10, ThresholdMode::Upper).min_samples(5);
        let mut cal = HealthThresholdCalibrator::new(config);

        for i in 1..=20 {
            cal.calibrate("depth", f64::from(i));
        }

        // Check several normal values.
        for i in 1..=10 {
            let _ = cal.check_and_track("depth", f64::from(i));
        }

        let rates = cal.coverage_rates();
        let rate = rates.get("depth").copied().unwrap_or(0.0);
        assert!(
            rate >= 0.8,
            "coverage rate for normal data should be high, got {rate:.2}"
        );
    }

    #[test]
    fn health_threshold_multiple_metrics() {
        let config = HealthThresholdConfig::new(0.05, ThresholdMode::Upper).min_samples(3);
        let mut cal = HealthThresholdCalibrator::new(config);

        for i in 1..=10 {
            cal.calibrate("queue_depth", f64::from(i));
            cal.calibrate("restart_rate", f64::from(i) * 0.01);
        }

        assert!(cal.is_metric_calibrated("queue_depth"));
        assert!(cal.is_metric_calibrated("restart_rate"));

        let results = cal.check_all(&[("queue_depth", 5.0), ("restart_rate", 0.05)]);
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.conforming));
    }

    #[test]
    fn health_threshold_any_anomalous() {
        let config = HealthThresholdConfig::new(0.20, ThresholdMode::Upper).min_samples(3);
        let mut cal = HealthThresholdCalibrator::new(config);

        for i in 1..=10 {
            cal.calibrate("queue_depth", f64::from(i));
        }

        assert!(!cal.any_anomalous(&[("queue_depth", 5.0)]));
        assert!(cal.any_anomalous(&[("queue_depth", 10000.0)]));
    }

    #[test]
    fn health_threshold_display() {
        let config = HealthThresholdConfig::new(0.05, ThresholdMode::Upper).min_samples(3);
        let mut cal = HealthThresholdCalibrator::new(config);

        for i in 1..=10 {
            cal.calibrate("queue_depth", f64::from(i));
        }

        let result = cal.check("queue_depth", 5.0).unwrap();
        let display = format!("{result}");
        assert!(display.contains("queue_depth"));
        assert!(display.contains("OK") || display.contains("ANOMALOUS"));
    }

    #[test]
    fn health_threshold_deterministic() {
        let run = || {
            let config = HealthThresholdConfig::new(0.05, ThresholdMode::Upper).min_samples(3);
            let mut cal = HealthThresholdCalibrator::new(config);
            for i in 1..=10 {
                cal.calibrate("m", f64::from(i));
            }
            cal.check("m", 7.5).unwrap()
        };

        let r1 = run();
        let r2 = run();
        assert_eq!(r1.threshold, r2.threshold);
        assert!((r1.nonconformity_score - r2.nonconformity_score).abs() < f64::EPSILON);
        assert_eq!(r1.conforming, r2.conforming);
    }

    #[test]
    fn health_threshold_ignores_non_finite_calibration_values() {
        let config = HealthThresholdConfig::new(0.20, ThresholdMode::Upper).min_samples(3);
        let mut cal = HealthThresholdCalibrator::new(config);

        for i in 1..=10 {
            cal.calibrate("metric", f64::from(i));
        }
        cal.calibrate("metric", f64::NAN);
        cal.calibrate("metric", f64::INFINITY);
        cal.calibrate("metric", f64::NEG_INFINITY);

        let counts = cal.metric_counts();
        assert_eq!(counts.get("metric"), Some(&10));
        let threshold = cal
            .threshold("metric")
            .expect("metric should be calibrated");
        assert!(threshold.is_finite());
    }

    #[test]
    fn health_threshold_non_finite_check_is_anomalous() {
        let config = HealthThresholdConfig::new(0.20, ThresholdMode::Upper).min_samples(3);
        let mut cal = HealthThresholdCalibrator::new(config);
        for i in 1..=10 {
            cal.calibrate("metric", f64::from(i));
        }

        let result = cal
            .check("metric", f64::NAN)
            .expect("metric should be calibrated");
        assert!(!result.conforming);
        assert!(result.nonconformity_score.is_infinite());
        assert!(result.threshold.is_finite());
    }

    #[test]
    fn health_threshold_metric_counts() {
        let config = HealthThresholdConfig::new(0.05, ThresholdMode::Upper).min_samples(3);
        let mut cal = HealthThresholdCalibrator::new(config);

        cal.calibrate("a", 1.0);
        cal.calibrate("a", 2.0);
        cal.calibrate("b", 10.0);

        let counts = cal.metric_counts();
        assert_eq!(counts.get("a"), Some(&2));
        assert_eq!(counts.get("b"), Some(&1));
    }

    // ========================================================================
    // Deterministic observability: conformal coverage diagnostics (bd-npn8e)
    // ========================================================================

    #[test]
    fn obs_conformal_coverage_guarantee_holds() {
        // Verify the finite-sample coverage guarantee:
        // P(new observation conforming) ≥ 1 - alpha under exchangeability.
        let alpha = 0.10;
        let config = ConformalConfig::new(alpha).min_samples(10);
        let mut cal = ConformalCalibrator::new(config);

        // Calibrate with clean reports (10 samples).
        for i in 0..10 {
            cal.calibrate(&make_clean_report(10 + i, 50 + i * 3));
        }

        // Predict on 100 clean observations. Coverage should be ≥ (1 - alpha).
        let mut conforming_count = 0;
        let total = 100;
        for _ in 0..total {
            if let Some(report) = cal.predict(&make_clean_report(10, 50)) {
                if report.prediction_sets.iter().all(|ps| ps.conforming) {
                    conforming_count += 1;
                }
            }
        }

        let coverage = f64::from(conforming_count) / f64::from(total);
        assert!(
            coverage >= 1.0 - alpha - 0.05,
            "coverage {coverage:.2} should be ≥ {:.2}",
            1.0 - alpha - 0.05
        );
    }

    #[test]
    fn obs_health_threshold_coverage_guarantee_holds() {
        let alpha = 0.10;
        let config = HealthThresholdConfig::new(alpha, ThresholdMode::Upper).min_samples(20);
        let mut cal = HealthThresholdCalibrator::new(config);

        // Calibrate with values 1..=20.
        for i in 1..=20 {
            cal.calibrate("depth", f64::from(i));
        }

        // Check 50 values within the calibration range.
        let mut conforming = 0;
        let total = 50;
        for i in 0..total {
            let value = f64::from((i % 20) + 1);
            if let Some(result) = cal.check("depth", value) {
                if result.conforming {
                    conforming += 1;
                }
            }
        }

        let coverage = f64::from(conforming) / f64::from(total);
        assert!(
            coverage >= 1.0 - alpha - 0.05,
            "health threshold coverage {coverage:.2} should be ≥ {:.2}",
            1.0 - alpha - 0.05
        );
    }

    #[test]
    fn obs_conformal_anomaly_detection_deterministic() {
        // Same calibration + prediction sequence must produce identical results.
        let run = || {
            let config = ConformalConfig::new(0.05).min_samples(5);
            let mut cal = ConformalCalibrator::new(config);

            for i in 0..8 {
                cal.calibrate(&make_clean_report(10 + i, 50 + i * 3));
            }

            let clean = cal.predict(&make_clean_report(10, 50)).unwrap();
            let anomalous = cal.predict(&make_violated_report(10, 50)).unwrap();
            (clean, anomalous)
        };

        let (c1, a1) = run();
        let (c2, a2) = run();

        // Clean predictions must be identical.
        assert_eq!(c1.prediction_sets.len(), c2.prediction_sets.len());
        for (p1, p2) in c1.prediction_sets.iter().zip(c2.prediction_sets.iter()) {
            assert!((p1.score - p2.score).abs() < f64::EPSILON);
            assert_eq!(p1.threshold, p2.threshold);
            assert_eq!(p1.conforming, p2.conforming);
        }

        // Anomalous predictions must be identical.
        assert_eq!(a1.prediction_sets.len(), a2.prediction_sets.len());
        for (p1, p2) in a1.prediction_sets.iter().zip(a2.prediction_sets.iter()) {
            assert!((p1.score - p2.score).abs() < f64::EPSILON);
            assert_eq!(p1.conforming, p2.conforming);
        }
    }

    #[test]
    fn obs_conformal_report_well_calibrated_diagnostics() {
        let config = ConformalConfig::new(0.05).min_samples(5);
        let mut cal = ConformalCalibrator::new(config);

        // Calibrate.
        for i in 0..10 {
            cal.calibrate(&make_clean_report(10 + i, 50 + i * 2));
        }

        // Predict many clean observations.
        let mut last_report = None;
        for _ in 0..30 {
            last_report = cal.predict(&make_clean_report(10, 50));
        }

        let report = last_report.unwrap();

        // Should be well-calibrated.
        assert!(report.is_well_calibrated());
        assert!(report.miscalibrated_invariants().is_empty());

        // Report text should contain expected fields.
        let text = report.to_text();
        assert!(text.contains("CONFORMAL CALIBRATION REPORT"));
        assert!(text.contains("WELL-CALIBRATED"));

        // JSON roundtrip.
        let json = report.to_json();
        assert!(json["well_calibrated"].as_bool().unwrap());
        assert_eq!(json["alpha"], 0.05);
    }

    #[test]
    fn conformal_config_debug_clone_default() {
        let c = ConformalConfig::default();
        let dbg = format!("{c:?}");
        assert!(dbg.contains("ConformalConfig"));

        let c2 = c;
        assert!((c2.alpha - 0.05).abs() < f64::EPSILON);
        assert_eq!(c2.min_calibration_samples, 5);
    }

    #[test]
    #[should_panic(expected = "alpha must be finite and in (0, 1)")]
    fn conformal_config_rejects_invalid_alpha() {
        let _ = ConformalConfig::new(1.0);
    }

    #[test]
    #[should_panic(expected = "min_calibration_samples must be > 0")]
    fn conformal_calibrator_rejects_zero_min_samples() {
        let mut cfg = ConformalConfig::new(0.05);
        cfg.min_calibration_samples = 0;
        let _ = ConformalCalibrator::new(cfg);
    }

    #[test]
    #[should_panic(expected = "min_calibration_samples must be > 0")]
    fn conformal_config_builder_rejects_zero_min_samples() {
        let _ = ConformalConfig::new(0.05).min_samples(0);
    }

    #[test]
    #[should_panic(expected = "alpha must be finite and in (0, 1)")]
    fn health_threshold_config_rejects_invalid_alpha() {
        let _ = HealthThresholdConfig::new(0.0, ThresholdMode::Upper);
    }

    #[test]
    #[should_panic(expected = "min_calibration_samples must be > 0")]
    fn health_threshold_calibrator_rejects_zero_min_samples() {
        let mut cfg = HealthThresholdConfig::new(0.05, ThresholdMode::Upper);
        cfg.min_calibration_samples = 0;
        let _ = HealthThresholdCalibrator::new(cfg);
    }

    #[test]
    #[should_panic(expected = "min_calibration_samples must be > 0")]
    fn health_threshold_config_builder_rejects_zero_min_samples() {
        let _ = HealthThresholdConfig::new(0.05, ThresholdMode::Upper).min_samples(0);
    }

    #[test]
    fn conformity_score_debug_clone_copy_eq() {
        let s = ConformityScore {
            value: 0.42,
            violated: false,
        };
        let dbg = format!("{s:?}");
        assert!(dbg.contains("ConformityScore"));

        let s2 = s;
        assert_eq!(s, s2);

        // Copy
        let s3 = s;
        assert_eq!(s, s3);
    }

    #[test]
    fn threshold_mode_debug_clone_copy_eq() {
        let m = ThresholdMode::Upper;
        let dbg = format!("{m:?}");
        assert!(dbg.contains("Upper"));

        let m2 = m;
        assert_eq!(m, m2);

        let m3 = m;
        assert_eq!(m, m3);

        assert_ne!(ThresholdMode::Upper, ThresholdMode::TwoSided);
    }

    #[test]
    fn coverage_tracker_debug_clone() {
        let t = CoverageTracker {
            total: 10,
            covered: 9,
        };
        let dbg = format!("{t:?}");
        assert!(dbg.contains("CoverageTracker"));

        let t2 = t;
        assert_eq!(t2.total, 10);
        assert_eq!(t2.covered, 9);
    }

    // ===================================================================
    // br-asupersync-9u4ext: tightened tolerance from 5pp absolute to
    // alpha/5 (1pp at the default alpha=0.05).
    // ===================================================================

    fn report_with(alpha: f64, total: usize, covered: usize) -> CalibrationReport {
        CalibrationReport {
            prediction_sets: Vec::new(),
            coverage: BTreeMap::new(),
            overall_coverage: CoverageTracker { total, covered },
            alpha,
            calibration_samples: total,
        }
    }

    #[test]
    fn _9u4ext_tolerance_is_alpha_derived() {
        let r = report_with(0.05, 1, 1);
        // alpha=0.05 → tolerance = 0.05/5 = 0.01.
        assert!((r.calibration_tolerance() - 0.01).abs() < 1e-12);
        let r = report_with(0.20, 1, 1);
        // alpha=0.20 → tolerance = 0.04.
        assert!((r.calibration_tolerance() - 0.04).abs() < 1e-12);
    }

    #[test]
    fn _9u4ext_well_calibrated_strict_at_default_alpha() {
        // 90% coverage with alpha=0.05 (95% target) was historically
        // accepted (5pp slack). With the tightened tolerance it is
        // now rejected — operators get the calibration guarantee
        // they actually requested.
        let r = report_with(0.05, 100, 90);
        assert!(
            !r.is_well_calibrated(),
            "90% coverage at alpha=0.05 should now be flagged miscalibrated"
        );
        // 94% coverage is exactly at target - 0.01 = 0.94.
        let r = report_with(0.05, 100, 94);
        assert!(r.is_well_calibrated(), "94% should sit on the new boundary");
    }

    #[test]
    fn _9u4ext_well_calibrated_target_met() {
        // 95% coverage at alpha=0.05 → exactly target, well within.
        let r = report_with(0.05, 1000, 950);
        assert!(r.is_well_calibrated());
    }
