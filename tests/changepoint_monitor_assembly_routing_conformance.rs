//! Conformance: `ChangePointMonitor` assembly + routing + fixed-point `MetricSample`.
//!
//! Pins the previously zero-integration-coverage "profile -> detector -> monitor"
//! assembly surface of the change-point substrate (bead yj2nxx.1): the fixed-point
//! sample arithmetic that AC2 leans on for replay determinism, and the
//! off-by-default structural posture AC6 requires. These public functions had no
//! exercise in `tests/` (verified by per-symbol grep before authoring):
//!
//!   * `MetricSample::{as_micro_units, as_units}` — fixed-point accessors,
//!   * `ChangePointSeriesConfig::build_detector` — fresh-detector materialiser,
//!   * `ChangePointMonitor::{new, with_detector}` — empty-builder + chaining,
//!   * `ChangePointMonitor::observe` routing across registration order.
//!
//! Every assertion is oracle-free (the type's own documented algebra is the
//! reference), uses only the public crate surface, and needs no cargo features.
//! It is intentionally disjoint from `tests/changepoint_detector_arl_proofs.rs`
//! (which pins detector ARL / replay determinism) and from the scheduler-wiring
//! integration lane.

use asupersync::runtime::changepoint::{
    ChangeDirection, ChangePointDetectorKind, ChangePointMonitor, ChangePointMonitorConfig,
    ChangePointSeriesConfig, CusumConfig, CusumDetector, MetricSample, PageHinkleyConfig,
    PageHinkleyDetector, RuntimeMetricSeries, SeriesDetector,
};

const SCALE: i64 = MetricSample::SCALE;

/// The exact firing recipe proven in the `ChangePointMonitor` rustdoc example:
/// a Page-Hinkley detector with zero tolerance and a `10`-unit threshold that
/// resets nothing, deterministically alarms on a step from `10` to `18`.
fn doctest_page_hinkley() -> PageHinkleyDetector {
    PageHinkleyDetector::new(
        RuntimeMetricSeries::ReadyQueueDepth,
        PageHinkleyConfig {
            tolerance: MetricSample::from_micro_units(0),
            threshold: 10 * SCALE,
            reset_after_detection: false,
        },
    )
}

// ---------------------------------------------------------------------------
// MetricSample: fixed-point arithmetic (AC2 determinism substrate)
// ---------------------------------------------------------------------------

#[test]
fn metric_sample_micro_units_round_trips_exactly() {
    // `from_micro_units` is the identity store; `as_micro_units` reads it back
    // with no rescaling, so the round-trip is exact across the whole i64 range.
    for micro in [
        i64::MIN,
        -SCALE - 1,
        -SCALE,
        -1,
        0,
        1,
        SCALE,
        SCALE + 1,
        i64::MAX,
    ] {
        assert_eq!(
            MetricSample::from_micro_units(micro).as_micro_units(),
            micro,
            "micro-unit store/read must be lossless for {micro}"
        );
    }
}

#[test]
fn metric_sample_unit_round_trips_within_scale() {
    // `from_units` multiplies by SCALE (saturating); `as_units` divides back.
    // For magnitudes that do not saturate, the whole-unit round-trip is exact and
    // the micro-unit view is the literal product.
    for units in [-9_000_000_000_i64, -42, -1, 0, 1, 7, 1_000, 9_000_000_000] {
        let sample = MetricSample::from_units(units);
        assert_eq!(
            sample.as_units(),
            units,
            "whole-unit round trip for {units}"
        );
        assert_eq!(
            sample.as_micro_units(),
            units * SCALE,
            "micro-unit view is units * SCALE for {units}"
        );
    }
}

#[test]
fn metric_sample_as_units_rounds_toward_zero() {
    // Documented contract: `as_units` returns the whole-unit component rounded
    // toward zero (truncating integer division), symmetric about zero.
    let cases = [
        (0_i64, 0_i64),
        (999_999, 0),
        (-999_999, 0),
        (SCALE, 1),
        (-SCALE, -1),
        (SCALE + 500_000, 1),
        (-(SCALE + 500_000), -1),
        (2 * SCALE, 2),
        (-2 * SCALE, -2),
    ];
    for (micro, whole) in cases {
        assert_eq!(
            MetricSample::from_micro_units(micro).as_units(),
            whole,
            "as_units({micro}) must truncate toward zero to {whole}"
        );
    }
}

#[test]
fn metric_sample_from_units_saturates_and_matches_from_impl() {
    // `from_units` uses saturating multiplication, so extreme whole-unit inputs
    // clamp to the i64 bounds rather than wrapping.
    assert_eq!(
        MetricSample::from_units(i64::MAX).as_micro_units(),
        i64::MAX,
        "huge positive units saturate to i64::MAX"
    );
    assert_eq!(
        MetricSample::from_units(i64::MIN).as_micro_units(),
        i64::MIN,
        "huge negative units saturate to i64::MIN"
    );
    // `From<i64>` is documented to defer to `from_units`.
    for units in [-3_i64, 0, 5, 1_234] {
        assert_eq!(
            MetricSample::from(units),
            MetricSample::from_units(units),
            "From<i64> must equal from_units for {units}"
        );
    }
}

#[test]
fn metric_sample_ordering_tracks_micro_units() {
    // The derived Ord is over the raw micro-unit field, so comparisons agree with
    // the integer ordering of `as_micro_units`.
    let ascending = [
        MetricSample::from_micro_units(i64::MIN),
        MetricSample::from_units(-2),
        MetricSample::from_micro_units(-1),
        MetricSample::from_micro_units(0),
        MetricSample::from_micro_units(1),
        MetricSample::from_units(2),
        MetricSample::from_micro_units(i64::MAX),
    ];
    for window in ascending.windows(2) {
        assert!(
            window[0] < window[1],
            "{:?} must order before {:?}",
            window[0].as_micro_units(),
            window[1].as_micro_units()
        );
        assert!(window[0].as_micro_units() < window[1].as_micro_units());
    }
}

// ---------------------------------------------------------------------------
// ChangePointSeriesConfig::build_detector — fresh, faithful, pure
// ---------------------------------------------------------------------------

#[test]
fn build_detector_preserves_series_kind_and_starts_fresh() {
    let rows = [
        ChangePointSeriesConfig::page_hinkley(
            RuntimeMetricSeries::WakeToRunLatencyMicros,
            PageHinkleyConfig::conservative(),
        ),
        ChangePointSeriesConfig::cusum(
            RuntimeMetricSeries::DrainRate,
            CusumConfig::upward(MetricSample::from_units(4), 7 * SCALE),
        ),
    ];
    for row in rows {
        let detector = row.build_detector();
        assert_eq!(detector.series(), row.series(), "series carried verbatim");
        assert_eq!(detector.kind(), row.kind(), "kind carried verbatim");
        let snapshot = detector.snapshot();
        assert_eq!(
            snapshot.sample_count, 0,
            "a built detector has consumed 0 samples"
        );
        assert_eq!(snapshot.series, row.series());
        assert_eq!(snapshot.detector, row.kind());
    }
}

#[test]
fn build_detector_equals_from_conversion() {
    // `From<ChangePointSeriesConfig> for SeriesDetector` is documented to defer to
    // `build_detector`; SeriesDetector derives Eq so the two must be identical.
    let rows = [
        ChangePointSeriesConfig::page_hinkley(
            RuntimeMetricSeries::ReadyQueueDepth,
            PageHinkleyConfig::conservative(),
        ),
        ChangePointSeriesConfig::cusum(
            RuntimeMetricSeries::CancelStreakReward,
            CusumConfig::downward(MetricSample::from_units(0), 3 * SCALE),
        ),
    ];
    for row in rows {
        assert_eq!(
            SeriesDetector::from(row),
            row.build_detector(),
            "From conversion must equal build_detector"
        );
    }
}

#[test]
fn build_detector_is_pure_and_independent() {
    // The profile row is a copyable template: building twice yields equal fresh
    // detectors, and advancing one built detector cannot disturb another build.
    let row = ChangePointSeriesConfig::cusum(
        RuntimeMetricSeries::ReadyQueueDepth,
        CusumConfig::upward(MetricSample::from_units(10), SCALE),
    );
    let first = row.build_detector();
    let second = row.build_detector();
    assert_eq!(
        first, second,
        "two builds from one template are byte-identical"
    );

    let mut live = row.build_detector();
    let fired = live.update(MetricSample::from_units(100));
    assert!(
        fired.is_some(),
        "control: the chosen sample crosses the threshold"
    );

    // A subsequently built detector is unaffected by `live`'s advance.
    let after = row.build_detector();
    assert_eq!(
        after.snapshot().sample_count,
        0,
        "build_detector must not share mutable state across builds"
    );
    assert_eq!(
        after, second,
        "post-advance build still equals the original build"
    );
}

// ---------------------------------------------------------------------------
// ChangePointMonitor: empty builder + registration-order assembly
// ---------------------------------------------------------------------------

#[test]
fn new_monitor_is_empty_disabled_and_equals_default() {
    let monitor = ChangePointMonitor::new();
    assert!(monitor.is_empty(), "fresh monitor holds no detectors");
    assert_eq!(monitor.len(), 0);
    assert!(!monitor.is_enabled(), "off by default is structural");
    assert!(monitor.snapshots().is_empty());
    assert_eq!(
        ChangePointMonitor::default(),
        ChangePointMonitor::new(),
        "Default and new() agree on the empty disabled monitor"
    );
}

#[test]
fn with_detector_preserves_registration_order_across_into_paths() {
    // All four `impl Into<SeriesDetector>` source types register the same way and
    // keep insertion order in `snapshots()`.
    let monitor = ChangePointMonitor::new()
        .with_detector(PageHinkleyDetector::new(
            RuntimeMetricSeries::ReadyQueueDepth,
            PageHinkleyConfig::conservative(),
        ))
        .with_detector(CusumDetector::new(
            RuntimeMetricSeries::WakeToRunLatencyMicros,
            CusumConfig::upward(MetricSample::from_units(0), SCALE),
        ))
        .with_detector(ChangePointSeriesConfig::cusum(
            RuntimeMetricSeries::CancelStreakReward,
            CusumConfig::downward(MetricSample::from_units(0), SCALE),
        ))
        .with_detector(SeriesDetector::Cusum(CusumDetector::new(
            RuntimeMetricSeries::DrainRate,
            CusumConfig::upward(MetricSample::from_units(0), SCALE),
        )));

    assert_eq!(monitor.len(), 4);
    assert!(!monitor.is_empty());
    let snapshots = monitor.snapshots();
    let series: Vec<_> = snapshots.iter().map(|s| s.series).collect();
    assert_eq!(
        series,
        vec![
            RuntimeMetricSeries::ReadyQueueDepth,
            RuntimeMetricSeries::WakeToRunLatencyMicros,
            RuntimeMetricSeries::CancelStreakReward,
            RuntimeMetricSeries::DrainRate,
        ],
        "snapshots follow registration order"
    );
    let kinds: Vec<_> = snapshots.iter().map(|s| s.detector).collect();
    assert_eq!(
        kinds,
        vec![
            ChangePointDetectorKind::PageHinkley,
            ChangePointDetectorKind::Cusum,
            ChangePointDetectorKind::Cusum,
            ChangePointDetectorKind::Cusum,
        ],
        "each Into path materialises the expected detector kind"
    );
    // Nothing has been observed yet: every detector is fresh.
    assert!(snapshots.iter().all(|s| s.sample_count == 0));
}

#[test]
fn assembly_is_equivalent_across_config_builder_and_register() {
    // Three independent ways to assemble the same two-detector profile must yield
    // PartialEq-equal monitors, and the enabled/disabled flag must distinguish.
    let row_a = ChangePointSeriesConfig::page_hinkley(
        RuntimeMetricSeries::ReadyQueueDepth,
        PageHinkleyConfig::conservative(),
    );
    let row_b = ChangePointSeriesConfig::cusum(
        RuntimeMetricSeries::DrainRate,
        CusumConfig::upward(MetricSample::from_units(5), 2 * SCALE),
    );

    let via_config = ChangePointMonitorConfig::disabled()
        .with_series(row_a)
        .with_series(row_b)
        .build_monitor();

    let via_chain = ChangePointMonitor::new()
        .with_detector(row_a)
        .with_detector(row_b);

    let via_register = {
        let mut monitor = ChangePointMonitor::new();
        monitor.register(row_a.build_detector());
        monitor.register(row_b.build_detector());
        monitor.set_enabled(false);
        monitor
    };

    assert_eq!(
        via_config, via_chain,
        "config.build_monitor == chained builder"
    );
    assert_eq!(
        via_chain, via_register,
        "chained builder == imperative register"
    );

    let enabled_config = ChangePointMonitorConfig::disabled()
        .with_series(row_a)
        .with_series(row_b)
        .enable()
        .build_monitor();
    let enabled_chain = ChangePointMonitor::new()
        .with_detector(row_a)
        .with_detector(row_b)
        .enable();
    assert_eq!(enabled_config, enabled_chain, "enabled assemblies agree");
    assert_ne!(
        enabled_config, via_config,
        "the enabled flag is part of monitor identity"
    );
}

// ---------------------------------------------------------------------------
// ChangePointMonitor::observe — disabled inertness + series routing
// ---------------------------------------------------------------------------

#[test]
fn disabled_monitor_is_inert_and_advances_no_state() {
    // Off by default is *structural*: a disabled monitor short-circuits before
    // touching any detector, so the firing recipe yields nothing and leaves the
    // detector with zero consumed samples.
    let mut monitor = ChangePointMonitor::new().with_detector(doctest_page_hinkley());
    assert!(!monitor.is_enabled());
    for value in [10, 10, 10, 10, 10, 18, 18, 18, 18, 18] {
        let got = monitor.observe(
            RuntimeMetricSeries::ReadyQueueDepth,
            MetricSample::from_units(value),
        );
        assert!(
            got.is_none(),
            "a disabled monitor never reports a detection"
        );
    }
    assert_eq!(
        monitor.snapshots()[0].sample_count,
        0,
        "a disabled observe must not advance detector state"
    );
}

#[test]
fn enabled_monitor_routes_samples_only_to_matching_series() {
    // PH on ready-queue-depth, CUSUM on drain-rate; a sample for an unregistered
    // series advances nothing, and each registered sample advances only its own
    // detector.
    let mut monitor = ChangePointMonitor::new()
        .with_detector(doctest_page_hinkley())
        .with_detector(CusumDetector::new(
            RuntimeMetricSeries::DrainRate,
            CusumConfig::upward(MetricSample::from_units(0), SCALE),
        ))
        .enable();

    let count_for = |m: &ChangePointMonitor, series: RuntimeMetricSeries| -> u64 {
        m.snapshots()
            .into_iter()
            .find(|s| s.series == series)
            .map(|s| s.sample_count)
            .expect("detector registered for series")
    };

    // No detector serves WakeToRunLatencyMicros: routing is a no-op.
    assert!(
        monitor
            .observe(
                RuntimeMetricSeries::WakeToRunLatencyMicros,
                MetricSample::from_units(999),
            )
            .is_none()
    );
    assert_eq!(count_for(&monitor, RuntimeMetricSeries::ReadyQueueDepth), 0);
    assert_eq!(count_for(&monitor, RuntimeMetricSeries::DrainRate), 0);

    // A ready-queue sample advances only the PH detector.
    assert!(
        monitor
            .observe(
                RuntimeMetricSeries::ReadyQueueDepth,
                MetricSample::from_units(10),
            )
            .is_none()
    );
    assert_eq!(count_for(&monitor, RuntimeMetricSeries::ReadyQueueDepth), 1);
    assert_eq!(count_for(&monitor, RuntimeMetricSeries::DrainRate), 0);

    // A drain-rate jump advances only the CUSUM detector and crosses immediately.
    let fired = monitor.observe(
        RuntimeMetricSeries::DrainRate,
        MetricSample::from_units(100),
    );
    let fired = fired.expect("upward jump crosses the CUSUM threshold");
    assert_eq!(fired.series, RuntimeMetricSeries::DrainRate);
    assert_eq!(fired.detector, ChangePointDetectorKind::Cusum);
    assert_eq!(fired.direction, ChangeDirection::Increase);
    assert_eq!(count_for(&monitor, RuntimeMetricSeries::ReadyQueueDepth), 1);
    assert_eq!(count_for(&monitor, RuntimeMetricSeries::DrainRate), 1);
}

#[test]
fn observe_returns_first_in_registration_order_and_advances_all_matching() {
    // Two CUSUM detectors on the same series with distinct thresholds both cross
    // on one big jump. `observe` returns the *first-registered* receipt and still
    // advances every matching detector.
    let build = |first_threshold: i64, second_threshold: i64| {
        ChangePointMonitor::new()
            .with_detector(CusumDetector::new(
                RuntimeMetricSeries::ReadyQueueDepth,
                CusumConfig::upward(MetricSample::from_units(10), first_threshold),
            ))
            .with_detector(CusumDetector::new(
                RuntimeMetricSeries::ReadyQueueDepth,
                CusumConfig::upward(MetricSample::from_units(10), second_threshold),
            ))
            .enable()
    };

    // Order A: low threshold registered first -> its receipt wins.
    let mut monitor = build(SCALE, 2 * SCALE);
    let fired = monitor
        .observe(
            RuntimeMetricSeries::ReadyQueueDepth,
            MetricSample::from_units(100),
        )
        .expect("the jump crosses both detectors");
    assert_eq!(
        fired.threshold, SCALE,
        "the first-registered detector's receipt is returned"
    );
    let counts: Vec<_> = monitor.snapshots().iter().map(|s| s.sample_count).collect();
    assert_eq!(counts, vec![1, 1], "both matching detectors advanced");

    // Order B: high threshold registered first -> winner follows registration,
    // not threshold magnitude.
    let mut swapped = build(2 * SCALE, SCALE);
    let fired = swapped
        .observe(
            RuntimeMetricSeries::ReadyQueueDepth,
            MetricSample::from_units(100),
        )
        .expect("the jump crosses both detectors");
    assert_eq!(
        fired.threshold,
        2 * SCALE,
        "winner is registration-order, independent of threshold value"
    );
    let counts: Vec<_> = swapped.snapshots().iter().map(|s| s.sample_count).collect();
    assert_eq!(counts, vec![1, 1], "both matching detectors advanced");
}

// ---------------------------------------------------------------------------
// Conservative scheduler profile — off-by-default structure (AC6)
// ---------------------------------------------------------------------------

#[test]
fn conservative_scheduler_defaults_build_disabled_and_inert() {
    let mut monitor = ChangePointMonitorConfig::conservative_scheduler_defaults().build_monitor();
    assert!(
        !monitor.is_enabled(),
        "conservative profile is disabled until opt-in"
    );
    assert_eq!(
        monitor.len(),
        4,
        "the four design-note series are installed"
    );

    let snapshots = monitor.snapshots();
    let series: Vec<_> = snapshots.iter().map(|s| s.series).collect();
    assert_eq!(
        series,
        vec![
            RuntimeMetricSeries::ReadyQueueDepth,
            RuntimeMetricSeries::WakeToRunLatencyMicros,
            RuntimeMetricSeries::CancelStreakReward,
            RuntimeMetricSeries::DrainRate,
        ],
        "deterministic registration order"
    );
    assert!(
        snapshots
            .iter()
            .all(|s| s.detector == ChangePointDetectorKind::PageHinkley),
        "all conservative rows are Page-Hinkley"
    );

    // Feeding large steps while disabled changes nothing.
    for series in [
        RuntimeMetricSeries::ReadyQueueDepth,
        RuntimeMetricSeries::WakeToRunLatencyMicros,
        RuntimeMetricSeries::CancelStreakReward,
        RuntimeMetricSeries::DrainRate,
    ] {
        for value in [0, 0, 0, 1_000, 1_000, 1_000] {
            assert!(
                monitor
                    .observe(series, MetricSample::from_units(value))
                    .is_none()
            );
        }
    }
    assert!(
        monitor.snapshots().iter().all(|s| s.sample_count == 0),
        "a disabled conservative monitor consumes no samples"
    );

    // Opting in flips only the enabled flag; the installed profile is unchanged.
    let enabled = ChangePointMonitorConfig::conservative_scheduler_defaults()
        .enable()
        .build_monitor();
    assert!(enabled.is_enabled());
    assert_eq!(enabled.len(), 4);
}
