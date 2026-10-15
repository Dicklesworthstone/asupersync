//! Conformance: deterministic queueing-theoretic pool sizing (bead eeexl1.5).
//!
//! `src/runtime/pool_sizing.rs` is pure policy/math — it never resizes a pool,
//! opens connections, or samples the clock — yet its public sizing surface had
//! zero `tests/` exercise (verified by per-symbol grep). This crate pins that
//! surface oracle-free: the reference for each assertion is the closed-form
//! queueing relation the module documents (Little's law `R = lambda * S`,
//! square-root staffing `k ~= R + beta*sqrt(R)`, Erlang-C utilization), computed
//! independently in the test, plus monotonicity, edge-case partitions, and
//! determinism.
//!
//! Functions pinned: `PoolWorkloadEstimate::{offered_load_ppm, service_cv2_ppm}`,
//! `square_root_staffing_size`, `pool_sizing_candidate_metrics`,
//! `recommend_pool_size`, `explain_pool_sizing`.
//!
//! Public API only; no cargo features.

use asupersync::runtime::pool_sizing::{
    POOL_SIZING_SCALE, PoolSizingBounds, PoolSizingReason, PoolSizingTarget, PoolWorkloadEstimate,
    explain_pool_sizing, pool_sizing_candidate_metrics, recommend_pool_size,
    square_root_staffing_size,
};

const SCALE: u128 = POOL_SIZING_SCALE as u128;

/// Build a workload estimate from a fixed-point arrival rate (jobs/sec * SCALE),
/// a mean service time in microseconds, and a service-time variance.
fn est(arrival_ppm: u64, service_micros: u64, variance: u128) -> PoolWorkloadEstimate {
    PoolWorkloadEstimate::new(arrival_ppm, service_micros, variance)
}

// ---------------------------------------------------------------------------
// Little's law: offered load R = arrival_rate * mean_service
// ---------------------------------------------------------------------------

#[test]
fn offered_load_is_littles_law_product() {
    // R[ppm] = arrival_rate_per_sec_ppm * service_time_mean_micros / SCALE.
    let cases: [(u64, u64); 6] = [
        (2 * POOL_SIZING_SCALE, 500_000),       // 2/s * 0.5s = 1.0 worker
        (POOL_SIZING_SCALE, POOL_SIZING_SCALE), // 1/s * 1s(=1e6us) = 1.0
        (10 * POOL_SIZING_SCALE, 100_000),      // 10/s * 0.1s = 1.0
        (0, 1_000_000),                         // no arrivals => no load
        (3 * POOL_SIZING_SCALE, 4_000_000),     // 3/s * 4s = 12.0
        (7 * POOL_SIZING_SCALE, 250_000),       // 7/s * 0.25s = 1.75
    ];
    for (arrival_ppm, service_micros) in cases {
        let expected = u128::from(arrival_ppm) * u128::from(service_micros) / SCALE;
        assert_eq!(
            u128::from(est(arrival_ppm, service_micros, 0).offered_load_ppm()),
            expected,
            "offered load must equal arrival*service/SCALE for ({arrival_ppm},{service_micros})"
        );
    }
}

#[test]
fn offered_load_is_zero_without_arrivals_or_service() {
    assert_eq!(est(0, 1_000_000, 9_999).offered_load_ppm(), 0);
    assert_eq!(est(5 * POOL_SIZING_SCALE, 0, 9_999).offered_load_ppm(), 0);
}

// ---------------------------------------------------------------------------
// Squared coefficient of variation: CV^2 = variance / mean^2
// ---------------------------------------------------------------------------

#[test]
fn service_cv2_is_variance_over_mean_squared() {
    // CV^2[ppm] = variance * SCALE / mean^2 (0 when mean is 0).
    let cases: [(u64, u128); 5] = [
        (1_000, 1_000_000), // var = mean^2 => CV^2 = 1.0 (exponential-like)
        (1_000, 0),         // deterministic service => CV^2 = 0
        (0, 12_345),        // mean 0 => guarded to 0
        (2_000, 4_000_000), // 4e6 / 4e6 = 1.0
        (500, 125_000),     // 125000 / 250000 = 0.5
    ];
    for (mean, variance) in cases {
        let expected = if mean == 0 {
            0
        } else {
            let mean = u128::from(mean);
            let mean_squared = mean * mean;
            variance * SCALE / mean_squared
        };
        assert_eq!(
            u128::from(est(POOL_SIZING_SCALE, mean, variance).service_cv2_ppm()),
            expected,
            "CV^2 must equal variance*SCALE/mean^2 for (mean={mean}, var={variance})"
        );
    }
}

// ---------------------------------------------------------------------------
// Square-root staffing hint
// ---------------------------------------------------------------------------

#[test]
fn square_root_staffing_zero_for_no_load_and_covers_offered_load() {
    let target = PoolSizingTarget::conservative_wait_probability();

    // No offered load => no staffing hint.
    assert_eq!(square_root_staffing_size(est(0, 500_000, 0), target), 0);
    assert_eq!(
        square_root_staffing_size(est(POOL_SIZING_SCALE, 0, 0), target),
        0
    );

    // For positive load the hint never under-staffs below the raw offered load:
    // staffing workers * SCALE >= offered_load_ppm (utilization <= 100% at hint).
    for arrival_mult in [1u64, 2, 5, 13] {
        let e = est(arrival_mult * POOL_SIZING_SCALE, 500_000, 0);
        let staffing = square_root_staffing_size(e, target);
        assert!(
            (staffing as u128) * SCALE >= u128::from(e.offered_load_ppm()),
            "staffing {staffing} must cover offered load {}",
            e.offered_load_ppm()
        );
    }
}

#[test]
fn square_root_staffing_is_nondecreasing_in_load() {
    let target = PoolSizingTarget::conservative_wait_probability();
    let mut prev = 0usize;
    for arrival_mult in [1u64, 2, 4, 8, 16, 32] {
        let staffing =
            square_root_staffing_size(est(arrival_mult * POOL_SIZING_SCALE, 500_000, 0), target);
        assert!(
            staffing >= prev,
            "staffing must be non-decreasing as offered load rises (got {staffing} after {prev})"
        );
        prev = staffing;
    }
}

// ---------------------------------------------------------------------------
// Candidate metrics: utilization = R/k, plus saturation/idle edges
// ---------------------------------------------------------------------------

#[test]
fn candidate_metrics_edge_partitions() {
    let scale_u32 = POOL_SIZING_SCALE as u32;

    // size 0: fully saturated sentinel regardless of load.
    let busy = est(2 * POOL_SIZING_SCALE, 500_000, 0); // R = 1.0
    let zero = pool_sizing_candidate_metrics(busy, 0);
    assert_eq!(
        zero.utilization_ppm, scale_u32,
        "0 workers => 100% utilization"
    );
    assert_eq!(
        zero.wait_probability_ppm, scale_u32,
        "0 workers => certain wait"
    );
    assert_eq!(
        zero.mean_wait_micros,
        u64::MAX,
        "0 workers => unbounded wait"
    );
    assert_eq!(zero.offered_load_ppm, busy.offered_load_ppm());

    // No offered load: every metric collapses to zero for any positive size.
    let idle = pool_sizing_candidate_metrics(est(0, 500_000, 0), 4);
    assert_eq!(idle.utilization_ppm, 0);
    assert_eq!(idle.wait_probability_ppm, 0);
    assert_eq!(idle.mean_wait_micros, 0);

    // Overload (offered load >= capacity): saturated sentinel.
    let heavy = est(10 * POOL_SIZING_SCALE, 500_000, 0); // R = 5.0
    let over = pool_sizing_candidate_metrics(heavy, 3); // capacity 3 < 5
    assert_eq!(over.utilization_ppm, scale_u32);
    assert_eq!(over.wait_probability_ppm, scale_u32);
    assert_eq!(over.mean_wait_micros, u64::MAX);

    // Underload: utilization is exactly R/k (no variability factor on util).
    let under = pool_sizing_candidate_metrics(busy, 4); // R = 1.0, k = 4
    let expected_util = u128::from(busy.offered_load_ppm()) * SCALE / (4u128 * SCALE); // = 250_000
    assert_eq!(u128::from(under.utilization_ppm), expected_util);
    assert!(under.utilization_ppm < scale_u32);
    assert!(under.wait_probability_ppm < scale_u32);
    assert!(under.mean_wait_micros < u64::MAX);
}

#[test]
fn candidate_metrics_utilization_strictly_decreases_with_more_servers() {
    let busy = est(4 * POOL_SIZING_SCALE, 500_000, 0); // R = 2.0
    let mut prev_util = u32::MAX;
    let mut prev_wait = u32::MAX;
    // Scan strictly-above-load sizes; each added server lowers utilization.
    for size in 3..=10usize {
        let m = pool_sizing_candidate_metrics(busy, size);
        assert!(
            m.utilization_ppm < prev_util,
            "utilization must strictly fall as servers grow (size {size}: {} !< {prev_util})",
            m.utilization_ppm
        );
        assert!(
            m.wait_probability_ppm <= prev_wait,
            "wait probability must be non-increasing as servers grow"
        );
        prev_util = m.utilization_ppm;
        prev_wait = m.wait_probability_ppm;
    }
}

// ---------------------------------------------------------------------------
// recommend_pool_size: reason partition, bounds, determinism
// ---------------------------------------------------------------------------

#[test]
fn recommend_no_load_returns_floor() {
    let bounds = PoolSizingBounds::new(2, 16);
    let rec = recommend_pool_size(
        est(0, 500_000, 0),
        bounds,
        PoolSizingTarget::conservative_wait_probability(),
    );
    assert_eq!(rec.recommended_size, 2, "no load => recommend the floor");
    assert_eq!(rec.reason, PoolSizingReason::NoObservedLoad);
    assert!(
        rec.target_met,
        "the floor vacuously meets the target under no load"
    );
    assert_eq!(rec.square_root_staffing_size, 0);
}

#[test]
fn recommend_clamps_inverted_bounds_and_stays_in_range() {
    // Inverted bounds: ceiling clamps up to the floor.
    let inverted = recommend_pool_size(
        est(2 * POOL_SIZING_SCALE, 500_000, 0),
        PoolSizingBounds::new(8, 4),
        PoolSizingTarget::conservative_wait_probability(),
    );
    assert_eq!(inverted.bounds.min_size, 8);
    assert_eq!(inverted.bounds.max_size, 8, "max<min must clamp up to min");
    assert_eq!(inverted.recommended_size, 8);

    // Recommended size always lands within the resolved bounds.
    for arrival_mult in [1u64, 3, 9, 40] {
        let rec = recommend_pool_size(
            est(arrival_mult * POOL_SIZING_SCALE, 500_000, 0),
            PoolSizingBounds::new(1, 12),
            PoolSizingTarget::conservative_wait_probability(),
        );
        assert!(
            rec.recommended_size >= 1 && rec.recommended_size <= 12,
            "recommendation {} must stay within [1,12]",
            rec.recommended_size
        );
    }
}

#[test]
fn recommend_reason_partition_target_met_clamped_and_unmet() {
    let target = PoolSizingTarget::conservative_wait_probability();

    // Light load with a high floor: square-root hint is below the floor, the
    // floor already meets the target => ClampedToFloor.
    let clamped = recommend_pool_size(
        est(2 * POOL_SIZING_SCALE, 500_000, 0),
        PoolSizingBounds::new(10, 32),
        target,
    );
    assert_eq!(clamped.recommended_size, 10);
    assert_eq!(clamped.reason, PoolSizingReason::ClampedToFloor);
    assert!(clamped.target_met);
    assert!(
        clamped.square_root_staffing_size < clamped.bounds.min_size,
        "ClampedToFloor implies the staffing hint sat below the floor"
    );

    // Moderate load with a low floor and ample ceiling: a candidate above the
    // floor meets the target => TargetMet.
    let met = recommend_pool_size(
        est(6 * POOL_SIZING_SCALE, 500_000, 0),
        PoolSizingBounds::new(1, 64),
        target,
    );
    assert_eq!(met.reason, PoolSizingReason::TargetMet);
    assert!(met.target_met);
    assert!(met.recommended_size >= 1 && met.recommended_size <= 64);

    // Crushing load with a tiny ceiling and a strict target: nothing satisfies
    // it, so the ceiling is returned with target_met == false.
    let strict = PoolSizingTarget::MaxWaitProbabilityPpm(1_000); // 0.1%
    let unmet = recommend_pool_size(
        est(100 * POOL_SIZING_SCALE, 500_000, 0),
        PoolSizingBounds::new(1, 4),
        strict,
    );
    assert_eq!(
        unmet.recommended_size, 4,
        "unmet target clamps to the ceiling"
    );
    assert_eq!(unmet.reason, PoolSizingReason::TargetUnmetAtCeiling);
    assert!(!unmet.target_met);
}

#[test]
fn recommend_is_pure_and_deterministic() {
    let e = est(5 * POOL_SIZING_SCALE, 400_000, 250_000);
    let bounds = PoolSizingBounds::new(2, 24);
    let target = PoolSizingTarget::MaxMeanWaitMicros(50_000);
    let a = recommend_pool_size(e, bounds, target);
    let b = recommend_pool_size(e, bounds, target);
    assert_eq!(
        a, b,
        "recommend_pool_size must be a pure function of its inputs"
    );
}

// ---------------------------------------------------------------------------
// explain_pool_sizing diagnostic string
// ---------------------------------------------------------------------------

#[test]
fn explain_reports_size_bounds_reason_and_unmet_warning() {
    let target = PoolSizingTarget::conservative_wait_probability();

    let met = recommend_pool_size(
        est(6 * POOL_SIZING_SCALE, 500_000, 0),
        PoolSizingBounds::new(1, 64),
        target,
    );
    let met_text = explain_pool_sizing(est(6 * POOL_SIZING_SCALE, 500_000, 0), met);
    assert!(
        met_text.contains(&format!("recommend {} workers", met.recommended_size)),
        "explanation must state the recommended size: {met_text}"
    );
    assert!(
        met_text.contains(&format!(
            "bounds {}..={}",
            met.bounds.min_size, met.bounds.max_size
        )),
        "explanation must state the resolved bounds: {met_text}"
    );
    assert!(
        met_text.contains("first candidate meeting the target"),
        "explanation must carry the TargetMet reason text: {met_text}"
    );
    assert!(
        !met_text.contains("WARNING"),
        "a met recommendation must not warn: {met_text}"
    );

    let strict = PoolSizingTarget::MaxWaitProbabilityPpm(1_000);
    let unmet = recommend_pool_size(
        est(100 * POOL_SIZING_SCALE, 500_000, 0),
        PoolSizingBounds::new(1, 4),
        strict,
    );
    let unmet_text = explain_pool_sizing(est(100 * POOL_SIZING_SCALE, 500_000, 0), unmet);
    assert!(
        unmet_text.contains("WARNING: target NOT met at the configured ceiling"),
        "an unmet recommendation must warn: {unmet_text}"
    );
}
