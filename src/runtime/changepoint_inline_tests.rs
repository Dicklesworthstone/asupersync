    use super::*;

    fn feed_page_hinkley(
        detector: &mut PageHinkleyDetector,
        samples: &[i64],
    ) -> Option<ChangePointDetection> {
        samples
            .iter()
            .copied()
            .find_map(|sample| detector.update(MetricSample::from_units(sample)))
    }

    fn feed_cusum(detector: &mut CusumDetector, samples: &[i64]) -> Option<ChangePointDetection> {
        samples
            .iter()
            .copied()
            .find_map(|sample| detector.update(MetricSample::from_units(sample)))
    }

    #[test]
    fn metric_sample_uses_deterministic_micro_units() {
        let sample = MetricSample::from_units(42);

        assert_eq!(sample.as_micro_units(), 42 * MetricSample::SCALE);
        assert_eq!(sample.as_units(), 42);
        assert_eq!(MetricSample::from_micro_units(1_500_000).as_units(), 1);
    }

    #[test]
    fn page_hinkley_detects_step_increase_after_stable_prefix() {
        let mut detector = PageHinkleyDetector::new(
            RuntimeMetricSeries::ReadyQueueDepth,
            PageHinkleyConfig {
                tolerance: MetricSample::from_micro_units(0),
                threshold: 10 * MetricSample::SCALE,
                reset_after_detection: false,
            },
        );
        let detection = feed_page_hinkley(&mut detector, &[10, 10, 10, 10, 10, 18, 18, 18, 18, 18])
            .expect("step increase should cross threshold");

        assert_eq!(detection.series, RuntimeMetricSeries::ReadyQueueDepth);
        assert_eq!(detection.detector, ChangePointDetectorKind::PageHinkley);
        assert_eq!(detection.direction, ChangeDirection::Increase);
        assert_eq!(detection.sample_index, 7);
        assert!(detection.statistic >= detection.threshold);
    }

    #[test]
    fn page_hinkley_reset_uses_epoch_local_mean_denominator() {
        let mut detector = PageHinkleyDetector::new(
            RuntimeMetricSeries::ReadyQueueDepth,
            PageHinkleyConfig {
                tolerance: MetricSample::from_micro_units(0),
                threshold: 6 * MetricSample::SCALE,
                reset_after_detection: true,
            },
        );

        assert!(detector.update(MetricSample::from_units(0)).is_none());
        let detection = detector
            .update(MetricSample::from_units(20))
            .expect("the first regime shift must cross the threshold");
        assert_eq!(detection.sample_index, 2);
        assert_eq!(detection.statistic, 10 * MetricSample::SCALE);

        assert!(
            detector.update(MetricSample::from_units(30)).is_none(),
            "a fresh epoch seeded at 20 has statistic 5, below threshold 6"
        );
        let snapshot = detector.snapshot();
        assert_eq!(
            snapshot.sample_count, 3,
            "snapshot count remains lifetime-wide"
        );
        assert_eq!(snapshot.mean, MetricSample::from_units(25));
        assert_eq!(snapshot.statistic, 5 * MetricSample::SCALE);
        assert_eq!(detector.mean_sample_count, 2);
    }

    #[test]
    fn page_hinkley_post_reset_epoch_matches_fresh_detector() {
        let config = PageHinkleyConfig {
            tolerance: MetricSample::from_micro_units(0),
            threshold: 6 * MetricSample::SCALE,
            reset_after_detection: true,
        };
        let mut reset_detector =
            PageHinkleyDetector::new(RuntimeMetricSeries::ReadyQueueDepth, config);
        let mut fresh_detector =
            PageHinkleyDetector::new(RuntimeMetricSeries::ReadyQueueDepth, config);

        assert!(reset_detector.update(MetricSample::from_units(0)).is_none());
        assert!(
            reset_detector
                .update(MetricSample::from_units(20))
                .is_some()
        );
        assert!(
            fresh_detector
                .update(MetricSample::from_units(20))
                .is_none()
        );

        assert_eq!(
            reset_detector.update(MetricSample::from_units(30)),
            fresh_detector.update(MetricSample::from_units(30))
        );
        assert_eq!(
            reset_detector.mean_sample_count,
            fresh_detector.mean_sample_count
        );
        assert_eq!(
            reset_detector.mean_micro_units,
            fresh_detector.mean_micro_units
        );
        assert_eq!(reset_detector.cumulative, fresh_detector.cumulative);
        assert_eq!(reset_detector.min_cumulative, fresh_detector.min_cumulative);
        assert_eq!(reset_detector.sample_count, 3);
        assert_eq!(fresh_detector.sample_count, 2);

        let reset_detection = reset_detector
            .update(MetricSample::from_units(31))
            .expect("continued epoch must cross at statistic 9");
        let fresh_detection = fresh_detector
            .update(MetricSample::from_units(31))
            .expect("fresh detector must cross at the same epoch statistic");
        assert_eq!(reset_detection.statistic, fresh_detection.statistic);
        assert_eq!(reset_detection.sample, fresh_detection.sample);
        assert_eq!(reset_detection.sample_index, 4);
        assert_eq!(fresh_detection.sample_index, 3);
        assert_eq!(
            reset_detector.mean_sample_count,
            fresh_detector.mean_sample_count
        );
        assert_eq!(
            reset_detector.mean_micro_units,
            fresh_detector.mean_micro_units
        );
        assert_eq!(reset_detector.cumulative, fresh_detector.cumulative);
        assert_eq!(reset_detector.min_cumulative, fresh_detector.min_cumulative);
    }

    #[test]
    fn page_hinkley_stays_quiet_for_steady_series() {
        let mut detector = PageHinkleyDetector::new(
            RuntimeMetricSeries::WakeToRunLatencyMicros,
            PageHinkleyConfig::conservative(),
        );
        let detection = feed_page_hinkley(&mut detector, &[40, 40, 41, 40, 41, 40, 41, 40]);

        assert!(detection.is_none());
        assert_eq!(detector.snapshot().sample_count, 8);
    }

    #[test]
    fn cusum_detects_known_upward_shift() {
        let mut detector = CusumDetector::new(
            RuntimeMetricSeries::CancelStreakReward,
            CusumConfig::upward(MetricSample::from_units(10), 6 * MetricSample::SCALE),
        );
        let detection = feed_cusum(&mut detector, &[10, 10, 11, 14, 14, 14])
            .expect("upward shift should cross threshold");

        assert_eq!(detection.detector, ChangePointDetectorKind::Cusum);
        assert_eq!(detection.direction, ChangeDirection::Increase);
        assert_eq!(detection.sample_index, 5);
        assert!(detection.statistic >= detection.threshold);
        assert_eq!(detector.snapshot().statistic, 0);
    }

    #[test]
    fn cusum_detects_known_downward_shift() {
        let mut detector = CusumDetector::new(
            RuntimeMetricSeries::DrainRate,
            CusumConfig::downward(MetricSample::from_units(20), 8 * MetricSample::SCALE),
        );
        let detection = feed_cusum(&mut detector, &[20, 19, 18, 15, 15, 15])
            .expect("downward shift should cross threshold");

        assert_eq!(detection.series, RuntimeMetricSeries::DrainRate);
        assert_eq!(detection.direction, ChangeDirection::Decrease);
        assert_eq!(detection.sample_index, 5);
    }

    #[test]
    fn detector_snapshots_are_byte_identical_for_same_series() {
        let samples = [3, 3, 4, 9, 9, 10, 10];
        let mut left = PageHinkleyDetector::new(
            RuntimeMetricSeries::Custom(7),
            PageHinkleyConfig::conservative(),
        );
        let mut right = PageHinkleyDetector::new(
            RuntimeMetricSeries::Custom(7),
            PageHinkleyConfig::conservative(),
        );

        for sample in samples {
            let left_detection = left.update(MetricSample::from_units(sample));
            let right_detection = right.update(MetricSample::from_units(sample));
            assert_eq!(left_detection, right_detection);
            assert_eq!(left.snapshot(), right.snapshot());
        }
    }

    #[test]
    fn page_hinkley_detection_delay_within_documented_window() {
        // (prefix_value, prefix_len, post_value, threshold_units, max_delay)
        let cases = [
            (10_i64, 5_usize, 18_i64, 10_i64, 4_u64),
            (5, 6, 25, 8, 3),
            (100, 8, 130, 20, 4),
        ];
        for (prefix, prefix_len, post, threshold_units, max_delay) in cases {
            let mut detector = PageHinkleyDetector::new(
                RuntimeMetricSeries::ReadyQueueDepth,
                PageHinkleyConfig {
                    tolerance: MetricSample::from_micro_units(0),
                    threshold: threshold_units * MetricSample::SCALE,
                    reset_after_detection: false,
                },
            );
            // A stable prefix must never trigger.
            for _ in 0..prefix_len {
                assert!(detector.update(MetricSample::from_units(prefix)).is_none());
            }
            // The shift must be detected, strictly after the prefix and within the window.
            let prefix_count = u64::try_from(prefix_len).expect("prefix length fits in u64");
            let mut detected_at = None;
            for step in 1..=(max_delay + 2) {
                if let Some(detection) = detector.update(MetricSample::from_units(post)) {
                    assert_eq!(detection.direction, ChangeDirection::Increase);
                    assert_eq!(detection.sample_index, prefix_count + step);
                    detected_at = Some(step);
                    break;
                }
            }
            let delay = detected_at.expect("post-shift samples should cross threshold");
            assert!(
                delay <= max_delay,
                "delay {delay} exceeded documented window {max_delay}"
            );
        }
    }

    #[test]
    fn page_hinkley_detects_gradual_drift() {
        let mut detector = PageHinkleyDetector::new(
            RuntimeMetricSeries::WakeToRunLatencyMicros,
            PageHinkleyConfig {
                tolerance: MetricSample::from_micro_units(0),
                threshold: 5 * MetricSample::SCALE,
                reset_after_detection: false,
            },
        );
        // Ramp upward by 0.5 units per sample: the lagging running mean opens a
        // growing positive gap that Page-Hinkley accumulates.
        let mut detection = None;
        for step in 0..40_i64 {
            let value = MetricSample::from_micro_units(40 * MetricSample::SCALE + step * 500_000);
            if let Some(found) = detector.update(value) {
                detection = Some(found);
                break;
            }
        }
        let detection = detection.expect("a sustained upward drift must eventually be detected");
        assert_eq!(detection.direction, ChangeDirection::Increase);
    }

    #[test]
    fn steady_corpus_yields_no_false_positives() {
        // Bounded jitter in micro-units: spikes exceed the conservative tolerance
        // (50_000) yet the per-cycle drift is strongly negative, so the run-up
        // above the cumulative floor never approaches the 3.0-unit threshold.
        const JITTER: [i64; 8] = [
            40_000, -90_000, 10_000, -50_000, 80_000, -20_000, -100_000, 30_000,
        ];
        let series = [
            RuntimeMetricSeries::ReadyQueueDepth,
            RuntimeMetricSeries::WakeToRunLatencyMicros,
            RuntimeMetricSeries::DrainRate,
        ];
        // Each (series, phase) pair is a deterministic steady-workload seed.
        for (seed, metric) in series.into_iter().enumerate() {
            let base = 50_i64 * MetricSample::SCALE;
            let mut detector = PageHinkleyDetector::new(metric, PageHinkleyConfig::conservative());
            for index in 0..256_usize {
                let jitter = JITTER[(index + seed) % JITTER.len()];
                let value = MetricSample::from_micro_units(base + jitter);
                assert!(
                    detector.update(value).is_none(),
                    "steady seed {seed} produced a false positive at index {index}"
                );
            }
        }
    }

    #[test]
    fn monitor_disabled_by_default_suppresses_detection() {
        let detector = PageHinkleyDetector::new(
            RuntimeMetricSeries::ReadyQueueDepth,
            PageHinkleyConfig {
                tolerance: MetricSample::from_micro_units(0),
                threshold: 10 * MetricSample::SCALE,
                reset_after_detection: false,
            },
        );
        let mut monitor = ChangePointMonitor::new().with_detector(detector);
        assert!(!monitor.is_enabled());
        assert_eq!(monitor.len(), 1);
        assert!(!monitor.is_empty());

        // While disabled, even an obvious step yields nothing and advances no state.
        for value in [10, 10, 10, 10, 10, 30, 30, 30, 30, 30] {
            assert!(
                monitor
                    .observe(
                        RuntimeMetricSeries::ReadyQueueDepth,
                        MetricSample::from_units(value)
                    )
                    .is_none()
            );
        }

        // Enabling resumes detection on the freshly observed step.
        monitor.set_enabled(true);
        let mut fired = false;
        for value in [10, 10, 10, 10, 10, 30, 30, 30, 30, 30] {
            if monitor
                .observe(
                    RuntimeMetricSeries::ReadyQueueDepth,
                    MetricSample::from_units(value),
                )
                .is_some()
            {
                fired = true;
                break;
            }
        }
        assert!(fired, "enabled monitor must detect the step");
    }

    #[test]
    fn monitor_routes_per_series_and_replays_identically() {
        fn build() -> ChangePointMonitor {
            ChangePointMonitor::new()
                .with_detector(PageHinkleyDetector::new(
                    RuntimeMetricSeries::ReadyQueueDepth,
                    PageHinkleyConfig {
                        tolerance: MetricSample::from_micro_units(0),
                        threshold: 10 * MetricSample::SCALE,
                        reset_after_detection: true,
                    },
                ))
                .with_detector(CusumDetector::new(
                    RuntimeMetricSeries::DrainRate,
                    CusumConfig::downward(MetricSample::from_units(20), 8 * MetricSample::SCALE),
                ))
                .enable()
        }

        // Interleaved (series, value) stream: a rising ready-queue and a falling
        // drain-rate, routed to their respective detectors.
        let stream = [
            (RuntimeMetricSeries::ReadyQueueDepth, 10),
            (RuntimeMetricSeries::DrainRate, 20),
            (RuntimeMetricSeries::ReadyQueueDepth, 10),
            (RuntimeMetricSeries::DrainRate, 19),
            (RuntimeMetricSeries::ReadyQueueDepth, 18),
            (RuntimeMetricSeries::DrainRate, 15),
            (RuntimeMetricSeries::ReadyQueueDepth, 18),
            (RuntimeMetricSeries::DrainRate, 15),
            (RuntimeMetricSeries::ReadyQueueDepth, 18),
            (RuntimeMetricSeries::DrainRate, 15),
        ];

        let run = |mut monitor: ChangePointMonitor| {
            stream
                .iter()
                .filter_map(|&(series, value)| {
                    monitor.observe(series, MetricSample::from_units(value))
                })
                .collect::<Vec<_>>()
        };

        let first = run(build());
        let second = run(build());
        assert_eq!(
            first, second,
            "replay from a fresh monitor must be byte-identical"
        );
        assert!(
            !first.is_empty(),
            "the interleaved stream should trigger at least one detector"
        );
        for detection in &first {
            assert!(
                matches!(
                    detection.series,
                    RuntimeMetricSeries::ReadyQueueDepth | RuntimeMetricSeries::DrainRate
                ),
                "unexpected routed series {:?}",
                detection.series
            );
            if detection.series == RuntimeMetricSeries::ReadyQueueDepth {
                assert_eq!(detection.detector, ChangePointDetectorKind::PageHinkley);
                assert_eq!(detection.direction, ChangeDirection::Increase);
            } else {
                assert_eq!(detection.detector, ChangePointDetectorKind::Cusum);
                assert_eq!(detection.direction, ChangeDirection::Decrease);
            }
        }
    }

    #[test]
    fn monitor_config_default_is_disabled_and_empty() {
        let config = ChangePointMonitorConfig::default();
        assert!(!config.enabled);
        assert!(config.is_empty());

        let mut monitor = config.build_monitor();
        assert!(!monitor.is_enabled());
        assert!(monitor.is_empty());
        assert!(
            monitor
                .observe(
                    RuntimeMetricSeries::ReadyQueueDepth,
                    MetricSample::from_units(100)
                )
                .is_none()
        );
    }

    #[test]
    fn conservative_scheduler_profile_is_installed_but_off() {
        let config = ChangePointMonitorConfig::conservative_scheduler_defaults();
        assert!(!config.enabled);
        assert_eq!(config.len(), 4);
        assert_eq!(
            config
                .series
                .iter()
                .map(|series| (series.series(), series.kind()))
                .collect::<Vec<_>>(),
            vec![
                (
                    RuntimeMetricSeries::ReadyQueueDepth,
                    ChangePointDetectorKind::PageHinkley
                ),
                (
                    RuntimeMetricSeries::WakeToRunLatencyMicros,
                    ChangePointDetectorKind::PageHinkley
                ),
                (
                    RuntimeMetricSeries::CancelStreakReward,
                    ChangePointDetectorKind::PageHinkley
                ),
                (
                    RuntimeMetricSeries::DrainRate,
                    ChangePointDetectorKind::PageHinkley
                ),
            ]
        );

        let mut monitor = config.build_monitor();
        let before = monitor.snapshots();
        for value in [10, 10, 10, 10, 10, 30, 30, 30, 30, 30] {
            assert!(
                monitor
                    .observe(
                        RuntimeMetricSeries::ReadyQueueDepth,
                        MetricSample::from_units(value)
                    )
                    .is_none()
            );
        }
        assert_eq!(
            monitor.snapshots(),
            before,
            "disabled config must not advance detector state"
        );
    }

    #[test]
    fn enabled_scheduler_profile_detects_without_custom_wiring() {
        let mut monitor = ChangePointMonitorConfig::conservative_scheduler_defaults()
            .enable()
            .build_monitor();
        assert!(monitor.is_enabled());
        assert_eq!(monitor.len(), 4);

        let detection = [10, 10, 10, 10, 10, 30, 30, 30, 30, 30]
            .into_iter()
            .find_map(|value| {
                monitor.observe(
                    RuntimeMetricSeries::ReadyQueueDepth,
                    MetricSample::from_units(value),
                )
            });
        assert!(
            detection.is_some(),
            "enabled conservative profile should detect a large step"
        );
        let Some(detection) = detection else {
            return;
        };

        assert_eq!(detection.series, RuntimeMetricSeries::ReadyQueueDepth);
        assert_eq!(detection.detector, ChangePointDetectorKind::PageHinkley);
        assert_eq!(detection.direction, ChangeDirection::Increase);
    }

    #[test]
    fn custom_config_can_install_cusum_profile() {
        let config = ChangePointMonitorConfig::disabled()
            .with_series(ChangePointSeriesConfig::cusum(
                RuntimeMetricSeries::DrainRate,
                CusumConfig::downward(MetricSample::from_units(20), 8 * MetricSample::SCALE),
            ))
            .enable();
        let mut monitor = config.build_monitor();

        let detection = [20, 19, 18, 15, 15, 15].into_iter().find_map(|value| {
            monitor.observe(
                RuntimeMetricSeries::DrainRate,
                MetricSample::from_units(value),
            )
        });
        assert!(
            detection.is_some(),
            "custom CUSUM profile should detect a falling drain rate"
        );
        let Some(detection) = detection else {
            return;
        };

        assert_eq!(detection.detector, ChangePointDetectorKind::Cusum);
        assert_eq!(detection.direction, ChangeDirection::Decrease);
    }
