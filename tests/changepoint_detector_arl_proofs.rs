//! Robust-lane conformance proofs for the pure change-point detector substrate
//! (`asupersync::runtime::changepoint`), bead `yj2nxx.1`.
//!
//! The detector module already carries strong `#[cfg(test)]` unit tests, but
//! those live in the library's lib-unittest binary, which is routinely red in
//! this shared tree whenever a peer's in-progress `#[cfg(test)]` code fails to
//! compile. That makes the substrate's ARL / determinism guarantees *unrunnable*
//! exactly when they matter. This integration crate re-establishes those proofs
//! through the public API only (`cargo test --test changepoint_detector_arl_proofs`),
//! which links the library in non-test mode and is immune to peer `cfg(test)`
//! breakage.
//!
//! Coverage is intentionally *distinct* from (not a copy of) the inline suite:
//!
//! * AC1 — detection delay vs. shift magnitude / threshold expressed as
//!   metamorphic monotonicity relations (no brittle exact-index pinning), plus
//!   the documented direction/series invariants.
//! * AC2 — determinism proven by mid-stream *cloning*: a detector cloned after
//!   `M` samples must evolve byte-identically to its origin over an identical
//!   tail, and a full `ChangePointMonitor` replay must produce a byte-identical
//!   receipt trace.
//! * AC4 — multi-seed steady-workload soak driven by a deterministic LCG with
//!   jitter strictly below the conservative tolerance/drift, proving zero
//!   false-positive resets at default params over thousands of samples.
//! * AC6 — the conservative scheduler profile is structurally off-by-default and
//!   freezes detector state while disabled.

use asupersync::runtime::RuntimeState;
use asupersync::runtime::changepoint::{
    ChangeDirection, ChangePointDetection, ChangePointDetectorKind, ChangePointMonitor,
    ChangePointMonitorConfig, ChangePointSeriesConfig, CusumConfig, CusumDetector, MetricSample,
    PageHinkleyConfig, PageHinkleyDetector, RuntimeMetricSeries,
};
use asupersync::runtime::scheduler::ThreeLaneScheduler;
use asupersync::sync::ContendedMutex;
use asupersync::types::Budget;
use std::sync::Arc;

/// Tiny deterministic LCG (PCG-style multiplier + odd increment) with an output
/// xorshift mix. No `rand`, no clock, no float — replay-exact across machines.
struct Lcg(u64);

impl Lcg {
    fn new(seed: u64) -> Self {
        // Avoid the zero fixed point; any nonzero seed gives a full-period stream.
        Self(seed ^ 0x9E37_79B9_7F4A_7C15)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let x = self.0;
        x ^ (x >> 31)
    }

    /// Symmetric jitter in `[-range, +range]` micro-units.
    fn jitter(&mut self, range: i64) -> i64 {
        debug_assert!(range > 0);
        let range_u64 = u64::try_from(range).expect("jitter range must be positive");
        let span = range_u64
            .checked_mul(2)
            .and_then(|value| value.checked_add(1))
            .expect("jitter span must fit u64");
        let offset = i64::try_from(self.next_u64() % span).expect("jitter offset must fit i64");
        offset - range
    }
}

const SCALE: i64 = MetricSample::SCALE;

/// AC4 — Page-Hinkley at conservative defaults stays silent across many seeds.
///
/// Jitter amplitude (0.04 units) is held strictly below the conservative
/// tolerance (0.05 units); the `-tolerance` term gives the cumulative sum a
/// guaranteed downward drift, so the run-up above its floor cannot approach the
/// 3.0-unit threshold. We do not merely assert this — we run 16 independent
/// seeds of 1,500 samples each and require zero detections.
#[test]
fn page_hinkley_steady_multiseed_soak_never_alarms() {
    let base = 50 * SCALE;
    let jitter_range = 40_000; // 0.04 units, below the 0.05-unit tolerance
    for seed in 0..16u64 {
        let mut rng = Lcg::new(seed);
        let mut detector = PageHinkleyDetector::new(
            RuntimeMetricSeries::ReadyQueueDepth,
            PageHinkleyConfig::conservative(),
        );
        for index in 0..1_500usize {
            let value = MetricSample::from_micro_units(base + rng.jitter(jitter_range));
            assert!(
                detector.update(value).is_none(),
                "seed {seed} produced a false positive at sample {index}"
            );
        }
        // State advanced over the full soak, yet never alarmed.
        assert_eq!(detector.snapshot().sample_count, 1_500);
    }
}

/// AC4 — CUSUM is *provably* quiet when every residual is non-positive.
///
/// With jitter bounded below the drift slack, `x - baseline - drift < 0` on every
/// sample, so the one-sided statistic is clamped to zero forever, regardless of
/// seed. This is a deterministic guarantee (not just an empirical soak).
#[test]
fn cusum_steady_below_drift_is_provably_quiet() {
    let base = 50 * SCALE;
    let jitter_range = 40_000; // 0.04 units, strictly below the 0.05-unit drift
    for seed in 0..16u64 {
        let mut rng = Lcg::new(seed.wrapping_mul(2_654_435_761));
        let mut up = CusumDetector::new(
            RuntimeMetricSeries::DrainRate,
            CusumConfig::upward(MetricSample::from_micro_units(base), 6 * SCALE),
        );
        let mut down = CusumDetector::new(
            RuntimeMetricSeries::DrainRate,
            CusumConfig::downward(MetricSample::from_micro_units(base), 6 * SCALE),
        );
        for index in 0..1_500usize {
            let value = MetricSample::from_micro_units(base + rng.jitter(jitter_range));
            assert!(
                up.update(value).is_none(),
                "upward CUSUM seed {seed} false-positive at {index}"
            );
            assert!(
                down.update(value).is_none(),
                "downward CUSUM seed {seed} false-positive at {index}"
            );
        }
        assert_eq!(up.snapshot().statistic, 0);
        assert_eq!(down.snapshot().statistic, 0);
    }
}

/// AC1 (metamorphic) — a larger Page-Hinkley step is detected no later than a
/// smaller one. We pin only the qualitative relation, not exact indices.
#[test]
fn page_hinkley_step_detection_delay_is_monotone_in_magnitude() {
    let prefix_value = 10i64;
    let prefix_len = 6usize;
    let threshold_units = 8i64;
    let post_values = [14i64, 18, 26, 50, 120];

    let delay_for = |post: i64| -> u64 {
        let mut detector = PageHinkleyDetector::new(
            RuntimeMetricSeries::ReadyQueueDepth,
            PageHinkleyConfig {
                tolerance: MetricSample::from_micro_units(0),
                threshold: threshold_units * SCALE,
                reset_after_detection: false,
            },
        );
        // A constant prefix produces centered==0 every step: never triggers.
        for _ in 0..prefix_len {
            assert!(
                detector
                    .update(MetricSample::from_units(prefix_value))
                    .is_none(),
                "stable prefix must not trigger"
            );
        }
        for step in 1..=64u64 {
            if let Some(detection) = detector.update(MetricSample::from_units(post)) {
                assert_eq!(detection.direction, ChangeDirection::Increase);
                assert_eq!(detection.detector, ChangePointDetectorKind::PageHinkley);
                assert_eq!(detection.series, RuntimeMetricSeries::ReadyQueueDepth);
                assert!(detection.statistic >= detection.threshold);
                return step;
            }
        }
        panic!("post-shift to {post} never crossed the threshold");
    };

    let delays: Vec<u64> = post_values.iter().map(|&v| delay_for(v)).collect();
    for window in delays.windows(2) {
        assert!(
            window[1] <= window[0],
            "larger step must not detect later: delays={delays:?}"
        );
    }
}

/// AC3 slice — a scheduler-facing change-point receipt resets stale adaptive
/// cancel-streak learning to priors without perturbing non-adaptive metrics.
#[test]
fn changepoint_receipt_resets_adaptive_cancel_streak_controller() {
    let state = Arc::new(ContendedMutex::new("runtime_state", RuntimeState::new()));
    let root = {
        let mut runtime_state = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        runtime_state.create_root_region(Budget::INFINITE)
    };
    let mut scheduler = ThreeLaneScheduler::new_with_options(1, &state, 16, true, 1);
    scheduler.set_adaptive_cancel_streak(true, 1);
    let mut worker = scheduler.take_workers().into_iter().next().expect("worker");

    for index in 0..8u32 {
        let task_id = {
            let mut runtime_state = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            runtime_state
                .create_task(root, Budget::INFINITE, async move {
                    let _ = index;
                })
                .expect("task create")
                .0
        };
        scheduler.inject_ready(task_id, 50);
        assert!(worker.run_once(), "ready task {index} should execute");
    }

    let trained = worker.preemption_metrics().clone();
    assert!(
        trained.adaptive_epochs > 0,
        "fixture should train at least one adaptive epoch before reset"
    );
    assert!(
        trained.ready_dispatches > 0,
        "fixture should exercise the normal ready dispatch path"
    );

    let mut monitor = ChangePointMonitorConfig::conservative_scheduler_defaults()
        .enable()
        .build_monitor();
    let detection = [10, 10, 10, 10, 10, 34, 34, 34, 34, 34]
        .into_iter()
        .find_map(|value| {
            monitor.observe(
                RuntimeMetricSeries::ReadyQueueDepth,
                MetricSample::from_units(value),
            )
        })
        .expect("workload flip should produce a deterministic changepoint receipt");

    assert!(
        worker.apply_changepoint_detection_to_adaptive_cancel_streak(detection),
        "known runtime series should reset an enabled adaptive policy"
    );
    let reset = worker.preemption_metrics();
    assert_eq!(reset.adaptive_epochs, 0);
    assert_eq!(reset.adaptive_current_limit, 16);
    assert_eq!(reset.adaptive_reward_ema, 0.5);
    assert_eq!(reset.adaptive_e_value, 1.0);
    assert_eq!(
        reset.ready_dispatches, trained.ready_dispatches,
        "reset must not rewrite non-adaptive dispatch counters"
    );

    let custom_detection = ChangePointDetection {
        series: RuntimeMetricSeries::Custom(7),
        ..detection
    };
    assert!(
        !worker.apply_changepoint_detection_to_adaptive_cancel_streak(custom_detection),
        "caller-defined custom series should not reset scheduler policy implicitly"
    );
}

/// AC1 (metamorphic) — CUSUM detection delay is monotone non-decreasing in the
/// threshold `h`, in both directions. With a constant post-shift sample the
/// statistic grows linearly, so a higher bar always takes at least as long.
#[test]
fn cusum_detection_delay_is_monotone_in_threshold() {
    fn delay(direction: ChangeDirection, baseline: i64, shifted: i64, threshold_units: i64) -> u64 {
        let config = match direction {
            ChangeDirection::Increase => {
                CusumConfig::upward(MetricSample::from_units(baseline), threshold_units * SCALE)
            }
            ChangeDirection::Decrease => {
                CusumConfig::downward(MetricSample::from_units(baseline), threshold_units * SCALE)
            }
        };
        let mut detector = CusumDetector::new(RuntimeMetricSeries::CancelStreakReward, config);
        for step in 1..=512u64 {
            if let Some(detection) = detector.update(MetricSample::from_units(shifted)) {
                assert_eq!(detection.direction, direction);
                assert_eq!(detection.detector, ChangePointDetectorKind::Cusum);
                return step;
            }
        }
        panic!("constant shift never crossed threshold {threshold_units}");
    }

    let thresholds = [4i64, 8, 16, 32];
    // Upward: baseline 10 -> shifted 20.
    let up: Vec<u64> = thresholds
        .iter()
        .map(|&h| delay(ChangeDirection::Increase, 10, 20, h))
        .collect();
    // Downward: baseline 20 -> shifted 10.
    let down: Vec<u64> = thresholds
        .iter()
        .map(|&h| delay(ChangeDirection::Decrease, 20, 10, h))
        .collect();

    for series in [&up, &down] {
        for window in series.windows(2) {
            assert!(
                window[1] >= window[0],
                "higher threshold must not detect sooner: {series:?}"
            );
        }
    }
}

/// AC2 — determinism by mid-stream cloning. A detector cloned after `M` samples
/// must evolve byte-identically to its origin over an identical tail: every
/// per-sample receipt and every snapshot must match. This is strictly stronger
/// than feeding two independent fresh detectors, because it also proves the
/// clone captured *all* hidden state (running mean, cumulative floor, counters).
#[test]
fn page_hinkley_midstream_clone_evolves_byte_identically() {
    let mut origin = PageHinkleyDetector::new(
        RuntimeMetricSeries::WakeToRunLatencyMicros,
        PageHinkleyConfig {
            tolerance: MetricSample::from_micro_units(20_000),
            threshold: 4 * SCALE,
            reset_after_detection: true,
        },
    );

    let mut rng = Lcg::new(0xC0FFEE);
    // Warm the origin through a rising, occasionally-resetting prefix.
    for _ in 0..37 {
        let value = MetricSample::from_micro_units(30 * SCALE + rng.jitter(2_500_000));
        let _ = origin.update(value);
    }

    let mut clone = origin.clone();
    assert_eq!(origin, clone, "clone must equal its origin");
    assert_eq!(origin.snapshot(), clone.snapshot());

    // Drive both with an identical deterministic tail; require lockstep.
    let mut tail_rng = Lcg::new(0xBADF00D);
    for step in 0..200 {
        let value = MetricSample::from_micro_units(30 * SCALE + tail_rng.jitter(3_000_000));
        let a = origin.update(value);
        let b = clone.update(value);
        assert_eq!(a, b, "divergent receipt at tail step {step}");
        assert_eq!(
            origin.snapshot(),
            clone.snapshot(),
            "divergent snapshot at tail step {step}"
        );
    }
    assert_eq!(origin, clone, "states must remain identical after replay");
}

/// AC2 / AC7 — a full `ChangePointMonitor` replayed from a fresh build over the
/// same seeded stream emits a byte-identical receipt trace.
#[test]
fn monitor_replay_trace_is_byte_identical() {
    fn build() -> ChangePointMonitor {
        ChangePointMonitorConfig::disabled()
            .with_series(ChangePointSeriesConfig::page_hinkley(
                RuntimeMetricSeries::ReadyQueueDepth,
                PageHinkleyConfig {
                    tolerance: MetricSample::from_micro_units(0),
                    threshold: 6 * SCALE,
                    reset_after_detection: true,
                },
            ))
            .with_series(ChangePointSeriesConfig::cusum(
                RuntimeMetricSeries::DrainRate,
                CusumConfig::downward(MetricSample::from_units(20), 5 * SCALE),
            ))
            .enable()
            .build_monitor()
    }

    fn fmt(detection: &ChangePointDetection) -> String {
        format!(
            "{series}|{detector:?}|{direction:?}|idx={idx}|stat={stat}|thr={thr}",
            series = detection.series.as_str(),
            detector = detection.detector,
            direction = detection.direction,
            idx = detection.sample_index,
            stat = detection.statistic,
            thr = detection.threshold,
        )
    }

    // Deterministic interleaved stream: a rising ready-queue and a falling drain.
    let mut rng = Lcg::new(0x5EED);
    let stream: Vec<(RuntimeMetricSeries, MetricSample)> = (0..120)
        .map(|i| {
            let half_step = i64::from(i / 2);
            if i % 2 == 0 {
                let ramp = 10 * SCALE + half_step * 250_000 + rng.jitter(200_000);
                (
                    RuntimeMetricSeries::ReadyQueueDepth,
                    MetricSample::from_micro_units(ramp),
                )
            } else {
                let fall = 20 * SCALE - half_step * 250_000 + rng.jitter(200_000);
                (
                    RuntimeMetricSeries::DrainRate,
                    MetricSample::from_micro_units(fall),
                )
            }
        })
        .collect();

    let run = |mut monitor: ChangePointMonitor| -> Vec<String> {
        stream
            .iter()
            .filter_map(|&(series, sample)| monitor.observe(series, sample).map(|d| fmt(&d)))
            .collect()
    };

    let first = run(build());
    let second = run(build());
    assert_eq!(first, second, "replay trace must be byte-identical");
    assert!(
        !first.is_empty(),
        "the rising/falling stream must trigger at least one detector"
    );
    // Every emitted receipt belongs to one of the two routed series.
    for line in &first {
        assert!(
            line.starts_with("ready_queue_depth|") || line.starts_with("drain_rate|"),
            "unexpected routed series in trace line: {line}"
        );
    }
}

/// AC6 — the conservative scheduler profile is structurally off-by-default: a
/// monitor built from it is disabled, suppresses an obvious step, and does not
/// advance any detector state until explicitly enabled.
#[test]
fn conservative_profile_is_off_by_default_and_freezes_state() {
    let config = ChangePointMonitorConfig::conservative_scheduler_defaults();
    assert!(!config.enabled, "profile must ship disabled");
    assert_eq!(config.len(), 4);

    let mut monitor = config.build_monitor();
    assert!(!monitor.is_enabled());
    let frozen = monitor.snapshots();

    let step = [10, 10, 10, 10, 10, 80, 80, 80, 80, 80];
    for &value in &step {
        assert!(
            monitor
                .observe(
                    RuntimeMetricSeries::ReadyQueueDepth,
                    MetricSample::from_units(value)
                )
                .is_none(),
            "disabled monitor must not detect"
        );
    }
    assert_eq!(
        monitor.snapshots(),
        frozen,
        "disabled monitor must not advance detector state"
    );

    // Enabling the same profile resumes detection on a fresh step.
    let mut enabled = ChangePointMonitorConfig::conservative_scheduler_defaults()
        .enable()
        .build_monitor();
    let fired = step.iter().any(|&value| {
        enabled
            .observe(
                RuntimeMetricSeries::ReadyQueueDepth,
                MetricSample::from_units(value),
            )
            .is_some()
    });
    assert!(fired, "enabled conservative profile must detect the step");
}
