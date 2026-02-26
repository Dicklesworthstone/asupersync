//! Compositional Latency Algebra via (min,+) Tropical Semiring Network Calculus.
//!
//! Provides compositional end-to-end latency estimates for compositions
//! of asupersync's concurrency combinators (join, race, timeout). Users can ask
//! "what is the worst-case latency of this combinator DAG?" and receive a
//! model-based estimate with per-node provenance.
//!
//! # Mathematical Foundation
//!
//! Network Calculus (Le Boudec & Thiran, 2001) uses the (min,+) dioid
//! (tropical semiring) to compute deterministic performance guarantees:
//!
//! ```text
//! Arrival curve   alpha(t) : upper bound on cumulative arrivals in [s, s+t]
//! Service curve   beta(t)  : lower bound on cumulative service in [s, s+t]
//!
//! Delay bound     d* = inf { t >= 0 : alpha(t) <= beta(t) }
//!                    = h(alpha, beta)           (horizontal deviation)
//!
//! Backlog bound   b* = sup_t { alpha(t) - beta(t) }
//!                    = v(alpha, beta)           (vertical deviation)
//! ```
//!
//! # Combinator Composition Rules
//!
//! ```text
//! Sequential (pipeline):   beta_total = beta_1 (x) beta_2   (min-plus convolution)
//! Parallel join:           d_join     = max(d_1, d_2)        (waits for slowest)
//! Parallel race:           d_race     = min(d_1, d_2)        (first to finish wins)
//! Timeout:                 d_timeout  = min(d_inner, tau)     (deadline caps delay)
//! ```
//!
//! # Piecewise-Linear Representation
//!
//! Both arrival and service curves are represented as piecewise-linear functions
//! defined by ordered breakpoints. Each segment covers the interval
//! `[start, next_start)` with value `burst + rate * (t - start)`:
//!
//! ```text
//!           rate_1             rate_2
//!    burst +------+      +----------->
//!          |      |      |
//!    ------+      +------+
//!          0    start_1  start_2
//! ```
//!
//! Curves are always non-negative and non-decreasing (wide-sense increasing),
//! which is a fundamental requirement of network calculus.
//!
//! # Tropical Semiring Properties
//!
//! The (min,+) convolution satisfies:
//!
//! ```text
//! Associativity:   (f (x) g) (x) h = f (x) (g (x) h)
//! Commutativity:   f (x) g = g (x) f
//! Identity:        f (x) delta_0 = f        where delta_0(0)=0, delta_0(t)=inf for t>0
//! Isotonicity:     f <= g  =>  f (x) h <= g (x) h
//! ```
//!
//! These properties guarantee that sequential pipeline composition is
//! order-independent at the delay-bound level, matching the PIPELINE-ASSOC
//! law from `combinator::laws`.
//!
//! # Integration with Plan DAG
//!
//! The [`LatencyAnalyzer`] walks a [`PlanDag`] bottom-up, computing per-node
//! latency estimates. Each leaf node requires an [`ArrivalCurve`] and
//! [`ServiceCurve`] annotation. The analyzer composes these according to the
//! combinator semantics and produces a [`LatencyAnalysis`] with per-node
//! provenance.
//!
//! # Numerical Approximation Note
//!
//! This implementation uses discrete breakpoint sampling for convolution and
//! deviation operators. Results are deterministic and useful for planning, but
//! are not a formal proof object.

use super::{PlanDag, PlanId, PlanNode};
use std::collections::BTreeMap;
use std::fmt;

// ============================================================================
// Piecewise-linear curve infrastructure
// ============================================================================

/// A single segment of a piecewise-linear curve.
///
/// Represents the function `f(t) = burst + rate * (t - start)` for
/// `t >= start`. The segment is valid until the next segment's start point.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Segment {
    /// Start of this segment's domain (inclusive).
    pub start: f64,
    /// Rate of increase (slope) within this segment.
    pub rate: f64,
    /// Value at the start point.
    pub burst: f64,
}

impl Segment {
    /// Creates a new segment.
    #[must_use]
    #[inline]
    pub fn new(start: f64, rate: f64, burst: f64) -> Self {
        Self { start, rate, burst }
    }

    /// Evaluates this segment at time `t`.
    ///
    /// Returns `burst + rate * (t - start)` for `t >= start`.
    /// For `t < start`, returns `burst` (left-continuous extension).
    #[must_use]
    #[inline]
    pub fn eval_at(&self, t: f64) -> f64 {
        if t <= self.start {
            self.burst
        } else {
            self.rate.mul_add(t - self.start, self.burst)
        }
    }
}

/// Piecewise-linear curve for arrival/service modeling.
///
/// Segments are stored in strictly increasing order of `start`. The curve
/// is left-continuous and non-decreasing. For `t` before the first segment,
/// the curve evaluates to `0.0`.
///
/// # Invariants
///
/// - Segments are sorted by `start` in strictly increasing order.
/// - All `rate` values are non-negative (non-decreasing curve).
/// - All `burst` values are non-negative.
/// - The curve is continuous: each segment's end value equals the next
///   segment's burst value.
#[derive(Debug, Clone, PartialEq)]
pub struct PiecewiseLinearCurve {
    segments: Vec<Segment>,
}

impl PiecewiseLinearCurve {
    /// Creates an empty curve (identically zero).
    #[must_use]
    pub fn zero() -> Self {
        Self {
            segments: vec![Segment::new(0.0, 0.0, 0.0)],
        }
    }

    /// Creates a curve from a validated segment list.
    ///
    /// Returns `None` if segments are empty, not sorted by `start`,
    /// contain negative rates/bursts, or are discontinuous.
    #[must_use]
    pub fn from_segments(segments: Vec<Segment>) -> Option<Self> {
        if segments.is_empty() {
            return None;
        }

        // Validate ordering, non-negativity, and continuity.
        for i in 0..segments.len() {
            if segments[i].rate < 0.0 || segments[i].burst < 0.0 {
                return None;
            }
            if segments[i].start < 0.0 {
                return None;
            }
            if i > 0 {
                if segments[i].start <= segments[i - 1].start {
                    return None;
                }
                // Continuity check: end of previous segment == burst of next.
                let prev = &segments[i - 1];
                let expected = prev
                    .rate
                    .mul_add(segments[i].start - prev.start, prev.burst);
                if (expected - segments[i].burst).abs() > 1e-9 {
                    return None;
                }
            }
        }

        Some(Self { segments })
    }

    /// Creates a constant-rate (affine) curve: `f(t) = burst + rate * t`.
    ///
    /// This is the most common form for token-bucket arrival curves
    /// and rate-latency service curves.
    #[must_use]
    pub fn affine(rate: f64, burst: f64) -> Self {
        debug_assert!(rate >= 0.0 && burst >= 0.0);
        Self {
            segments: vec![Segment::new(0.0, rate, burst)],
        }
    }

    /// Creates a rate-latency service curve: `beta(t) = rate * max(0, t - latency)`.
    ///
    /// This is the canonical service curve for a server with processing
    /// rate `rate` and worst-case startup latency `latency`.
    ///
    /// ```text
    ///        0          for t < latency
    /// beta = |
    ///        rate*(t-T) for t >= latency
    /// ```
    #[must_use]
    pub fn rate_latency(rate: f64, latency: f64) -> Self {
        debug_assert!(rate >= 0.0 && latency >= 0.0);
        if latency.abs() < f64::EPSILON {
            return Self::affine(rate, 0.0);
        }
        Self {
            segments: vec![
                Segment::new(0.0, 0.0, 0.0),
                Segment::new(latency, rate, 0.0),
            ],
        }
    }

    /// Creates a staircase curve with uniform step size.
    ///
    /// Useful for modeling periodic batch arrivals or discrete service
    /// opportunities.
    #[must_use]
    pub fn staircase(step_size: f64, period: f64, num_steps: usize) -> Self {
        debug_assert!(step_size > 0.0 && period > 0.0 && num_steps > 0);
        // Approximate staircase with piecewise-linear segments.
        // Each step is a steep ramp over a tiny epsilon, then flat.
        let mut segments = Vec::with_capacity(num_steps * 2);
        let epsilon = period * 1e-6;
        let steep_rate = step_size / epsilon;

        #[allow(clippy::cast_precision_loss)]
        for i in 0..num_steps {
            let fi = i as f64;
            let t = fi * period;
            let base = fi * step_size;

            if i == 0 {
                // First segment: steep ramp from 0.
                segments.push(Segment::new(0.0, steep_rate, 0.0));
                segments.push(Segment::new(epsilon, 0.0, step_size));
            } else {
                // Steep ramp for the step.
                segments.push(Segment::new(t, steep_rate, base));
                segments.push(Segment::new(t + epsilon, 0.0, base + step_size));
            }
        }

        Self { segments }
    }

    /// Evaluates the curve at time `t`.
    ///
    /// Uses binary search to find the active segment, then evaluates
    /// the segment's affine function.
    #[must_use]
    pub fn eval(&self, t: f64) -> f64 {
        if t < 0.0 {
            return 0.0;
        }
        if self.segments.is_empty() {
            return 0.0;
        }

        // Binary search for the last segment with start <= t.
        let idx = match self
            .segments
            .binary_search_by(|s| s.start.partial_cmp(&t).unwrap_or(std::cmp::Ordering::Less))
        {
            Ok(i) => i,
            Err(i) => {
                if i == 0 {
                    return 0.0;
                }
                i - 1
            }
        };

        self.segments[idx].eval_at(t)
    }

    /// Returns the number of segments.
    #[must_use]
    #[inline]
    pub fn segment_count(&self) -> usize {
        self.segments.len()
    }

    /// Returns a reference to the segments.
    #[must_use]
    #[inline]
    pub fn segments(&self) -> &[Segment] {
        &self.segments
    }

    /// Returns the asymptotic rate (slope of the last segment).
    #[must_use]
    #[inline]
    pub fn asymptotic_rate(&self) -> f64 {
        self.segments.last().map_or(0.0, |s| s.rate)
    }
}

// ============================================================================
// (min,+) Convolution — the core tropical semiring operation
// ============================================================================

/// Computes the (min,+) convolution of two piecewise-linear curves.
///
/// ```text
/// (f (x) g)(t) = inf_{0 <= s <= t} { f(s) + g(t - s) }
/// ```
///
/// For piecewise-linear curves, the result is also piecewise-linear.
/// The algorithm samples at all breakpoints of both curves and computes
/// the infimum numerically.
///
/// # Complexity
///
/// O(n * m) where n, m are the segment counts of the two curves.
/// For typical combinator DAGs this is small (< 100 segments).
#[must_use]
pub fn min_plus_convolution(
    f: &PiecewiseLinearCurve,
    g: &PiecewiseLinearCurve,
) -> PiecewiseLinearCurve {
    // Collect breakpoints from both curves.
    let f_breaks: Vec<f64> = f.segments.iter().map(|s| s.start).collect();
    let g_breaks: Vec<f64> = g.segments.iter().map(|s| s.start).collect();

    // Generate candidate evaluation points.
    // Sum-breakpoints: for each pair (f_break, g_break), the sum
    // is a potential breakpoint of the convolution.
    let mut all_t: Vec<f64> = Vec::new();
    for &fb in &f_breaks {
        for &gb in &g_breaks {
            all_t.push(fb + gb);
        }
    }
    // Also include original breakpoints and some intermediate points.
    all_t.extend_from_slice(&f_breaks);
    all_t.extend_from_slice(&g_breaks);
    all_t.push(0.0);

    // Find the maximum time we need to consider.
    let t_max = f_breaks
        .last()
        .copied()
        .unwrap_or(0.0)
        .max(g_breaks.last().copied().unwrap_or(0.0))
        .mul_add(2.0, 1.0);
    // Add samples at regular intervals for better approximation.
    let num_samples: u32 = 64;
    for i in 0..=num_samples {
        all_t.push(t_max * f64::from(i) / f64::from(num_samples));
    }

    all_t.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    all_t.dedup_by(|a, b| (*a - *b).abs() < 1e-12);
    all_t.retain(|&t| t >= 0.0);

    if all_t.is_empty() {
        return PiecewiseLinearCurve::zero();
    }

    // For each candidate t, compute inf_{0<=s<=t} { f(s) + g(t-s) }.
    let mut points: Vec<(f64, f64)> = Vec::with_capacity(all_t.len());

    for &t in &all_t {
        let val = convolution_at(f, g, t, &f_breaks, &g_breaks);
        points.push((t, val));
    }

    // Build piecewise-linear approximation from the sampled points.
    build_curve_from_points(&points)
}

/// Evaluates the convolution at a single point by minimizing over candidate splits.
fn convolution_at(
    f: &PiecewiseLinearCurve,
    g: &PiecewiseLinearCurve,
    t: f64,
    f_breaks: &[f64],
    g_breaks: &[f64],
) -> f64 {
    let mut min_val = f64::INFINITY;

    // Evaluate at all breakpoints of f that are <= t.
    for &s in f_breaks {
        if s <= t + 1e-12 {
            let val = f.eval(s) + g.eval(t - s);
            if val < min_val {
                min_val = val;
            }
        }
    }

    // Evaluate at t - g_break for all breakpoints of g that are <= t.
    for &gb in g_breaks {
        if gb <= t + 1e-12 {
            let s = t - gb;
            if s >= -1e-12 {
                let val = f.eval(s.max(0.0)) + g.eval(gb);
                if val < min_val {
                    min_val = val;
                }
            }
        }
    }

    // Also check endpoints.
    let val_0 = f.eval(0.0) + g.eval(t);
    if val_0 < min_val {
        min_val = val_0;
    }
    let val_t = f.eval(t) + g.eval(0.0);
    if val_t < min_val {
        min_val = val_t;
    }

    min_val
}

/// Builds a piecewise-linear curve from sorted (t, value) sample points.
fn build_curve_from_points(points: &[(f64, f64)]) -> PiecewiseLinearCurve {
    if points.is_empty() {
        return PiecewiseLinearCurve::zero();
    }

    let mut segments = Vec::new();

    for i in 0..points.len() {
        let (t, v) = points[i];
        let rate = if i + 1 < points.len() {
            let (t_next, v_next) = points[i + 1];
            let dt = t_next - t;
            if dt > 1e-12 {
                ((v_next - v) / dt).max(0.0)
            } else {
                0.0
            }
        } else {
            // Last segment: use the rate from the previous interval.
            if i > 0 {
                let (t_prev, v_prev) = points[i - 1];
                let dt = t - t_prev;
                if dt > 1e-12 {
                    ((v - v_prev) / dt).max(0.0)
                } else {
                    0.0
                }
            } else {
                0.0
            }
        };

        segments.push(Segment::new(t, rate, v));
    }

    // Simplify: merge consecutive segments with the same rate.
    let mut simplified = Vec::with_capacity(segments.len());
    for seg in &segments {
        if let Some(last) = simplified.last() {
            let last: &Segment = last;
            if (last.rate - seg.rate).abs() < 1e-9 {
                // Same rate, skip this breakpoint.
                continue;
            }
        }
        simplified.push(*seg);
    }

    PiecewiseLinearCurve {
        segments: if simplified.is_empty() {
            vec![Segment::new(0.0, 0.0, 0.0)]
        } else {
            simplified
        },
    }
}

// ============================================================================
// Horizontal and vertical deviation
// ============================================================================

/// Computes the horizontal deviation (worst-case delay bound).
///
/// ```text
/// h(alpha, beta) = sup_t { inf { d >= 0 : alpha(t) <= beta(t + d) } }
/// ```
///
/// This is the maximum horizontal distance between the arrival curve
/// and the service curve. It represents the worst-case delay experienced
/// by any bit/unit of work.
///
/// Returns `f64::INFINITY` if the system is unstable (arrival rate exceeds
/// service rate asymptotically).
#[must_use]
pub fn horizontal_deviation(alpha: &PiecewiseLinearCurve, beta: &PiecewiseLinearCurve) -> f64 {
    // Stability check: asymptotic arrival rate must not exceed service rate.
    let alpha_rate = alpha.asymptotic_rate();
    let beta_rate = beta.asymptotic_rate();
    if alpha_rate > beta_rate + 1e-12 {
        return f64::INFINITY;
    }

    // Sample at all breakpoints of alpha and beta, plus extra points.
    let mut sample_times: Vec<f64> = Vec::new();
    for seg in alpha.segments() {
        sample_times.push(seg.start);
    }
    for seg in beta.segments() {
        sample_times.push(seg.start);
    }

    // Add intermediate samples for better accuracy.
    let t_max = sample_times
        .last()
        .copied()
        .unwrap_or(0.0)
        .mul_add(2.0, 10.0);
    let num_extra: u32 = 256;
    for i in 0..=num_extra {
        sample_times.push(t_max * f64::from(i) / f64::from(num_extra));
    }

    sample_times.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    sample_times.dedup_by(|a, b| (*a - *b).abs() < 1e-12);

    let mut max_delay = 0.0_f64;

    for &t in &sample_times {
        let alpha_t = alpha.eval(t);
        if alpha_t <= 1e-12 {
            continue;
        }

        // Find the smallest d >= 0 such that beta(t + d) >= alpha(t).
        let d = find_delay_for_value(beta, t, alpha_t);
        if d > max_delay {
            max_delay = d;
        }
    }

    max_delay
}

/// Finds the smallest `d >= 0` such that `curve(t + d) >= target`.
///
/// Uses a combination of breakpoint analysis and binary search.
fn find_delay_for_value(curve: &PiecewiseLinearCurve, t: f64, target: f64) -> f64 {
    // If curve(t) already >= target, delay is 0.
    if curve.eval(t) >= target - 1e-12 {
        return 0.0;
    }

    // Binary search for the delay.
    let mut lo = 0.0_f64;
    let mut hi = 1.0_f64;

    // First, find an upper bound where curve(t + hi) >= target.
    // Doubles hi until we overshoot, or declares instability at 1e15.
    loop {
        if curve.eval(t + hi) >= target - 1e-12 {
            break;
        }
        hi *= 2.0;
        if hi > 1e15 {
            return f64::INFINITY;
        }
    }

    // Binary search within [lo, hi].
    for _ in 0..64 {
        let mid = f64::midpoint(lo, hi);
        if curve.eval(t + mid) >= target - 1e-12 {
            hi = mid;
        } else {
            lo = mid;
        }
    }

    hi
}

/// Computes the vertical deviation (worst-case backlog bound).
///
/// ```text
/// v(alpha, beta) = sup_t { alpha(t) - beta(t) }
/// ```
///
/// This is the maximum vertical distance between the arrival curve
/// and the service curve. It represents the worst-case buffer
/// occupancy / queue length.
///
/// Returns `f64::INFINITY` if the system is unstable.
#[must_use]
pub fn vertical_deviation(alpha: &PiecewiseLinearCurve, beta: &PiecewiseLinearCurve) -> f64 {
    // Stability check.
    let alpha_rate = alpha.asymptotic_rate();
    let beta_rate = beta.asymptotic_rate();
    if alpha_rate > beta_rate + 1e-12 {
        return f64::INFINITY;
    }

    // Sample at all breakpoints plus extras.
    let mut sample_times: Vec<f64> = Vec::new();
    for seg in alpha.segments() {
        sample_times.push(seg.start);
    }
    for seg in beta.segments() {
        sample_times.push(seg.start);
    }

    let t_max = sample_times
        .last()
        .copied()
        .unwrap_or(0.0)
        .mul_add(2.0, 10.0);
    let num_extra: u32 = 256;
    for i in 0..=num_extra {
        sample_times.push(t_max * f64::from(i) / f64::from(num_extra));
    }

    sample_times.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    sample_times.dedup_by(|a, b| (*a - *b).abs() < 1e-12);

    let mut max_backlog = 0.0_f64;

    for &t in &sample_times {
        let diff = alpha.eval(t) - beta.eval(t);
        if diff > max_backlog {
            max_backlog = diff;
        }
    }

    max_backlog
}

// ============================================================================
// (min,+) Deconvolution
// ============================================================================

/// Computes the (min,+) deconvolution of two piecewise-linear curves.
///
/// ```text
/// (f (/) g)(t) = sup_{s >= 0} { f(t + s) - g(s) }
/// ```
///
/// The deconvolution is used to compute the output arrival curve when
/// data passes through a server:
///
/// ```text
/// alpha_out <= alpha_in (/) beta
/// ```
///
/// This is the tightest arrival curve for the output traffic.
#[must_use]
pub fn min_plus_deconvolution(
    f: &PiecewiseLinearCurve,
    g: &PiecewiseLinearCurve,
) -> PiecewiseLinearCurve {
    // Collect candidate evaluation points.
    let f_breaks: Vec<f64> = f.segments.iter().map(|s| s.start).collect();
    let g_breaks: Vec<f64> = g.segments.iter().map(|s| s.start).collect();

    let t_max = f_breaks
        .last()
        .copied()
        .unwrap_or(0.0)
        .max(g_breaks.last().copied().unwrap_or(0.0))
        .mul_add(2.0, 1.0);

    let mut all_t: Vec<f64> = Vec::new();
    all_t.extend_from_slice(&f_breaks);
    all_t.extend_from_slice(&g_breaks);
    all_t.push(0.0);

    let num_samples: u32 = 64;
    for i in 0..=num_samples {
        all_t.push(t_max * f64::from(i) / f64::from(num_samples));
    }

    all_t.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    all_t.dedup_by(|a, b| (*a - *b).abs() < 1e-12);
    all_t.retain(|&t| t >= 0.0);

    let s_max = g_breaks.last().copied().unwrap_or(0.0).mul_add(2.0, 10.0);
    let mut candidate_s: Vec<f64> = Vec::new();
    candidate_s.extend_from_slice(&g_breaks);
    candidate_s.push(0.0);
    let s_samples: u32 = 64;
    for i in 0..=s_samples {
        candidate_s.push(s_max * f64::from(i) / f64::from(s_samples));
    }
    candidate_s.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    candidate_s.dedup_by(|a, b| (*a - *b).abs() < 1e-12);

    let mut points: Vec<(f64, f64)> = Vec::with_capacity(all_t.len());

    for &t in &all_t {
        let mut sup_val = f64::NEG_INFINITY;
        for &s in &candidate_s {
            let val = f.eval(t + s) - g.eval(s);
            if val > sup_val {
                sup_val = val;
            }
        }
        // Deconvolution result should be non-negative for valid curves.
        points.push((t, sup_val.max(0.0)));
    }

    build_curve_from_points(&points)
}

// ============================================================================
// Arrival and service curve types
// ============================================================================

/// Arrival curve: an upper bound on the cumulative number of units
/// arriving in any interval of length `t`.
///
/// ```text
/// A(s + t) - A(s) <= alpha(t)   for all s, t >= 0
/// ```
///
/// Common arrival curve models:
/// - **Token bucket**: `alpha(t) = sigma + rho * t` (burst `sigma`, rate `rho`)
/// - **Leaky bucket**: `alpha(t) = rho * t` (no burst, constant rate)
/// - **Staircase**: periodic batch arrivals
#[derive(Debug, Clone, PartialEq)]
pub struct ArrivalCurve(pub PiecewiseLinearCurve);

impl ArrivalCurve {
    /// Creates a token-bucket arrival curve: `alpha(t) = burst + rate * t`.
    ///
    /// Models a source that can send at most `burst` units instantaneously,
    /// then sustains at most `rate` units per time unit.
    #[must_use]
    pub fn token_bucket(rate: f64, burst: f64) -> Self {
        Self(PiecewiseLinearCurve::affine(rate, burst))
    }

    /// Creates a constant-rate arrival curve: `alpha(t) = rate * t`.
    #[must_use]
    pub fn constant_rate(rate: f64) -> Self {
        Self(PiecewiseLinearCurve::affine(rate, 0.0))
    }

    /// Creates an arrival curve from a raw piecewise-linear curve.
    #[must_use]
    pub fn from_curve(curve: PiecewiseLinearCurve) -> Self {
        Self(curve)
    }

    /// Evaluates the arrival curve at time `t`.
    #[must_use]
    #[inline]
    pub fn eval(&self, t: f64) -> f64 {
        self.0.eval(t)
    }

    /// Returns the underlying piecewise-linear curve.
    #[must_use]
    #[inline]
    pub fn curve(&self) -> &PiecewiseLinearCurve {
        &self.0
    }

    /// Returns the asymptotic arrival rate.
    #[must_use]
    #[inline]
    pub fn asymptotic_rate(&self) -> f64 {
        self.0.asymptotic_rate()
    }
}

/// Service curve: a lower bound on the cumulative service provided
/// in any busy period of length `t`.
///
/// ```text
/// S(t) >= inf_{0 <= s <= t} { A(s) + beta(t - s) }
///       = (A (x) beta)(t)
/// ```
///
/// Common service curve models:
/// - **Rate-latency**: `beta(t) = rate * max(0, t - latency)`
/// - **Constant rate**: `beta(t) = rate * t` (zero latency)
/// - **Strict priority**: derived from scheduling analysis
#[derive(Debug, Clone, PartialEq)]
pub struct ServiceCurve(pub PiecewiseLinearCurve);

impl ServiceCurve {
    /// Creates a rate-latency service curve.
    ///
    /// Models a server that provides no service for the first `latency`
    /// time units (scheduling/setup delay), then serves at constant `rate`.
    ///
    /// ```text
    /// beta(t) = rate * max(0, t - latency)
    /// ```
    #[must_use]
    pub fn rate_latency(rate: f64, latency: f64) -> Self {
        Self(PiecewiseLinearCurve::rate_latency(rate, latency))
    }

    /// Creates a constant-rate service curve (zero latency).
    #[must_use]
    pub fn constant_rate(rate: f64) -> Self {
        Self(PiecewiseLinearCurve::affine(rate, 0.0))
    }

    /// Creates a service curve from a raw piecewise-linear curve.
    #[must_use]
    pub fn from_curve(curve: PiecewiseLinearCurve) -> Self {
        Self(curve)
    }

    /// Evaluates the service curve at time `t`.
    #[must_use]
    #[inline]
    pub fn eval(&self, t: f64) -> f64 {
        self.0.eval(t)
    }

    /// Returns the underlying piecewise-linear curve.
    #[must_use]
    #[inline]
    pub fn curve(&self) -> &PiecewiseLinearCurve {
        &self.0
    }

    /// Returns the asymptotic service rate.
    #[must_use]
    #[inline]
    pub fn asymptotic_rate(&self) -> f64 {
        self.0.asymptotic_rate()
    }

    /// Computes the sequential composition (tandem) of two service curves.
    ///
    /// When two servers are in series (pipeline), the combined service
    /// curve is the (min,+) convolution:
    ///
    /// ```text
    /// beta_total = beta_1 (x) beta_2
    /// ```
    ///
    /// This follows from the service curve composition theorem
    /// (Le Boudec & Thiran, Theorem 1.4.6).
    #[must_use]
    pub fn sequential(&self, other: &Self) -> Self {
        Self(min_plus_convolution(&self.0, &other.0))
    }

    /// Scales a service curve by a concurrency factor.
    ///
    /// Models a bulkhead with `n` concurrent slots serving requests
    /// that individually have this service curve. The aggregate service
    /// rate scales linearly, while per-request latency is unchanged.
    #[must_use]
    pub fn scale(&self, factor: f64) -> Self {
        debug_assert!(factor > 0.0);
        let scaled_segments: Vec<Segment> = self
            .0
            .segments
            .iter()
            .map(|s| Segment::new(s.start, s.rate * factor, s.burst * factor))
            .collect();
        Self(PiecewiseLinearCurve {
            segments: scaled_segments,
        })
    }
}

// ============================================================================
// Latency bound result
// ============================================================================

/// Per-node contribution to the overall latency bound.
///
/// Provides provenance: which DAG node contributed how much delay,
/// enabling engineers to identify bottlenecks.
#[derive(Debug, Clone)]
pub struct BoundContribution {
    /// The plan DAG node responsible for this contribution.
    pub node_id: PlanId,
    /// Delay contributed by this node (seconds).
    pub delay: f64,
    /// Human-readable description of why this delay exists.
    pub description: String,
}

impl fmt::Display for BoundContribution {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "node[{}]: {:.6}s — {}",
            self.node_id.index(),
            self.delay,
            self.description
        )
    }
}

/// Latency estimate result with full provenance.
///
/// Contains the computed delay and backlog estimates, the
/// system utilization, and a per-node breakdown showing which parts
/// of the combinator DAG dominate the latency.
#[derive(Debug, Clone)]
pub struct LatencyBound {
    /// Estimated end-to-end delay (seconds).
    ///
    /// This is the horizontal deviation `h(alpha, beta)`:
    /// ```text
    /// d* = sup_t { inf { d >= 0 : alpha(t) <= beta(t + d) } }
    /// ```
    pub delay: f64,

    /// Estimated backlog bound (units of work).
    ///
    /// This is the vertical deviation `v(alpha, beta)`:
    /// ```text
    /// b* = sup_t { alpha(t) - beta(t) }
    /// ```
    pub backlog: f64,

    /// System utilization: `rho = arrival_rate / service_rate`.
    ///
    /// Must be `< 1.0` for bounded delay. Values `>= 1.0` indicate
    /// an unstable system.
    pub utilization: f64,

    /// Per-node breakdown of delay contributions.
    ///
    /// Sorted by contribution magnitude (largest first) so engineers
    /// can immediately identify the bottleneck.
    pub provenance: Vec<BoundContribution>,
}

impl LatencyBound {
    /// Returns `true` if the system is stable (finite delay bound).
    #[must_use]
    #[inline]
    pub fn is_stable(&self) -> bool {
        self.delay.is_finite() && self.utilization < 1.0
    }

    /// Returns the dominant bottleneck node, if any.
    #[must_use]
    pub fn bottleneck(&self) -> Option<&BoundContribution> {
        self.provenance.first()
    }

    /// Returns a human-readable summary of the latency bound.
    #[must_use]
    pub fn summary(&self) -> String {
        if !self.is_stable() {
            return format!(
                "UNSTABLE: utilization={:.2}%, delay=INF",
                self.utilization * 100.0
            );
        }
        let bottleneck = self
            .bottleneck()
            .map(|b| format!(", bottleneck=node[{}]", b.node_id.index()))
            .unwrap_or_default();
        format!(
            "delay<={:.6}s, backlog<={:.2}, util={:.1}%{}",
            self.delay,
            self.backlog,
            self.utilization * 100.0,
            bottleneck
        )
    }
}

impl fmt::Display for LatencyBound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Latency Bound Analysis")?;
        writeln!(f, "  delay    <= {:.6}s", self.delay)?;
        writeln!(f, "  backlog  <= {:.2} units", self.backlog)?;
        writeln!(f, "  util     =  {:.1}%", self.utilization * 100.0)?;
        if !self.provenance.is_empty() {
            writeln!(f, "  provenance:")?;
            for contrib in &self.provenance {
                writeln!(f, "    {contrib}")?;
            }
        }
        Ok(())
    }
}

// ============================================================================
// Node annotations for DAG analysis
// ============================================================================

/// Curve annotations for a leaf node in the plan DAG.
///
/// Each leaf must be annotated with arrival and service curves before
/// the analyzer can compute latency bounds.
#[derive(Debug, Clone)]
pub struct NodeCurves {
    /// Arrival curve for work entering this node.
    pub arrival: ArrivalCurve,
    /// Service curve for this node's processing capability.
    pub service: ServiceCurve,
}

impl NodeCurves {
    /// Creates a new curve annotation.
    #[must_use]
    pub fn new(arrival: ArrivalCurve, service: ServiceCurve) -> Self {
        Self { arrival, service }
    }

    /// Computes the delay bound for this single node.
    #[must_use]
    pub fn delay_bound(&self) -> f64 {
        horizontal_deviation(self.arrival.curve(), self.service.curve())
    }

    /// Computes the backlog bound for this single node.
    #[must_use]
    pub fn backlog_bound(&self) -> f64 {
        vertical_deviation(self.arrival.curve(), self.service.curve())
    }

    /// Computes the utilization for this node.
    #[must_use]
    pub fn utilization(&self) -> f64 {
        let service_rate = self.service.asymptotic_rate();
        if service_rate <= 1e-15 {
            return f64::INFINITY;
        }
        self.arrival.asymptotic_rate() / service_rate
    }
}

// ============================================================================
// Per-node latency result (internal)
// ============================================================================

/// Internal per-node analysis result.
#[derive(Debug, Clone)]
struct NodeLatency {
    /// Delay bound from this node downward.
    delay: f64,
    /// Backlog bound.
    backlog: f64,
    /// Effective arrival curve seen at this node's output.
    output_arrival: ArrivalCurve,
    /// Effective service curve of this node.
    effective_service: ServiceCurve,
    /// Provenance contributions from this subtree.
    contributions: Vec<BoundContribution>,
}

// ============================================================================
// Latency analysis report
// ============================================================================

/// Full latency analysis report for a plan DAG.
///
/// Contains per-node latency bounds and the overall end-to-end bound
/// computed at the root.
#[derive(Debug, Clone)]
pub struct LatencyAnalysis {
    /// Per-node delay bounds, keyed by `PlanId` index.
    pub node_delays: BTreeMap<usize, f64>,
    /// Per-node backlog bounds, keyed by `PlanId` index.
    pub node_backlogs: BTreeMap<usize, f64>,
    /// End-to-end bound at the root node (if root is set).
    pub root_bound: Option<LatencyBound>,
}

impl LatencyAnalysis {
    /// Returns the delay bound for a specific node.
    #[must_use]
    pub fn delay_at(&self, id: PlanId) -> Option<f64> {
        self.node_delays.get(&id.index()).copied()
    }

    /// Returns the backlog bound for a specific node.
    #[must_use]
    pub fn backlog_at(&self, id: PlanId) -> Option<f64> {
        self.node_backlogs.get(&id.index()).copied()
    }

    /// Returns the end-to-end delay bound, if available.
    #[must_use]
    pub fn end_to_end_delay(&self) -> Option<f64> {
        self.root_bound.as_ref().map(|b| b.delay)
    }

    /// Returns a human-readable summary.
    #[must_use]
    pub fn summary(&self) -> String {
        self.root_bound.as_ref().map_or_else(
            || format!("{} nodes analyzed, no root bound", self.node_delays.len()),
            |bound| {
                format!(
                    "{} nodes analyzed, e2e: {}",
                    self.node_delays.len(),
                    bound.summary()
                )
            },
        )
    }
}

impl fmt::Display for LatencyAnalysis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Latency Analysis ({} nodes)", self.node_delays.len())?;
        for (&idx, &delay) in &self.node_delays {
            let backlog = self.node_backlogs.get(&idx).copied().unwrap_or(0.0);
            writeln!(
                f,
                "  node[{idx}]: delay<={delay:.6}s, backlog<={backlog:.2}"
            )?;
        }
        if let Some(bound) = &self.root_bound {
            writeln!(f, "  --- end-to-end ---")?;
            write!(f, "{bound}")?;
        }
        Ok(())
    }
}

// ============================================================================
// Latency analyzer
// ============================================================================

/// Analyzer that walks a [`PlanDag`] and computes compositional
/// latency estimates using network calculus.
///
/// # Usage
///
/// 1. Create an analyzer with [`LatencyAnalyzer::new`].
/// 2. Annotate leaf nodes with arrival/service curves via [`annotate`].
/// 3. Call [`analyze`] to compute bounds for the entire DAG.
///
/// ```ignore
/// use asupersync::plan::{PlanDag, latency_algebra::*};
///
/// let mut dag = PlanDag::new();
/// let a = dag.leaf("service_a");
/// let b = dag.leaf("service_b");
/// let joined = dag.join(vec![a, b]);
/// dag.set_root(joined);
///
/// let mut analyzer = LatencyAnalyzer::new();
/// analyzer.annotate(a, NodeCurves::new(
///     ArrivalCurve::token_bucket(100.0, 50.0),
///     ServiceCurve::rate_latency(200.0, 0.001),
/// ));
/// analyzer.annotate(b, NodeCurves::new(
///     ArrivalCurve::token_bucket(80.0, 30.0),
///     ServiceCurve::rate_latency(150.0, 0.002),
/// ));
///
/// let analysis = analyzer.analyze(&dag);
/// println!("{}", analysis.summary());
/// ```
///
/// [`annotate`]: LatencyAnalyzer::annotate
/// [`analyze`]: LatencyAnalyzer::analyze
#[derive(Debug, Clone)]
pub struct LatencyAnalyzer {
    /// Curve annotations for leaf nodes.
    annotations: BTreeMap<usize, NodeCurves>,
    /// Default arrival curve for unannotated leaves.
    default_arrival: Option<ArrivalCurve>,
    /// Default service curve for unannotated leaves.
    default_service: Option<ServiceCurve>,
}

impl LatencyAnalyzer {
    /// Creates a new latency analyzer with no annotations.
    #[must_use]
    pub fn new() -> Self {
        Self {
            annotations: BTreeMap::new(),
            default_arrival: None,
            default_service: None,
        }
    }

    /// Creates a new analyzer with default curves for unannotated leaves.
    ///
    /// Any leaf node without an explicit annotation will use these defaults.
    /// This is useful for quick what-if analysis where most leaves have
    /// similar characteristics.
    #[must_use]
    pub fn with_defaults(arrival: ArrivalCurve, service: ServiceCurve) -> Self {
        Self {
            annotations: BTreeMap::new(),
            default_arrival: Some(arrival),
            default_service: Some(service),
        }
    }

    /// Annotates a leaf node with arrival and service curves.
    ///
    /// Replaces any existing annotation for this node.
    pub fn annotate(&mut self, id: PlanId, curves: NodeCurves) {
        self.annotations.insert(id.index(), curves);
    }

    /// Removes an annotation for a node.
    pub fn remove_annotation(&mut self, id: PlanId) {
        self.annotations.remove(&id.index());
    }

    /// Analyzes the entire DAG and returns a [`LatencyAnalysis`].
    ///
    /// Performs a bottom-up traversal computing per-node latency bounds.
    /// The composition rules are:
    ///
    /// - **Leaf**: delay from annotated arrival/service curves.
    /// - **Join**: `d = max(d_children)` — waits for all children.
    /// - **Race**: `d = min(d_children)` — first finisher wins.
    /// - **Timeout**: `d = min(d_child, timeout_duration)` — deadline caps delay.
    ///
    /// Returns `None` for nodes with missing annotations and no defaults.
    #[must_use]
    pub fn analyze(&self, dag: &PlanDag) -> LatencyAnalysis {
        let mut cache: BTreeMap<usize, NodeLatency> = BTreeMap::new();
        let mut node_delays = BTreeMap::new();
        let mut node_backlogs = BTreeMap::new();

        // Analyze all nodes (not just reachable from root) for completeness.
        for idx in 0..dag.node_count() {
            let id = PlanId::new(idx);
            let result = self.analyze_node(dag, id, &mut cache);
            node_delays.insert(idx, result.delay);
            node_backlogs.insert(idx, result.backlog);
        }

        // Build root bound with provenance.
        let root_bound = dag.root().map(|root_id| {
            let root_result = cache
                .get(&root_id.index())
                .cloned()
                .unwrap_or_else(|| NodeLatency {
                    delay: f64::INFINITY,
                    backlog: f64::INFINITY,
                    output_arrival: ArrivalCurve::constant_rate(0.0),
                    effective_service: ServiceCurve::constant_rate(0.0),
                    contributions: Vec::new(),
                });

            let utilization = {
                let svc_rate = root_result.effective_service.asymptotic_rate();
                if svc_rate <= 1e-15 {
                    f64::INFINITY
                } else {
                    root_result.output_arrival.asymptotic_rate() / svc_rate
                }
            };

            let mut provenance = root_result.contributions;
            // Sort by delay contribution, largest first (bottleneck at top).
            provenance.sort_by(|a, b| {
                b.delay
                    .partial_cmp(&a.delay)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });

            LatencyBound {
                delay: root_result.delay,
                backlog: root_result.backlog,
                utilization,
                provenance,
            }
        });

        LatencyAnalysis {
            node_delays,
            node_backlogs,
            root_bound,
        }
    }

    /// Recursively analyzes a single node, using memoization.
    fn analyze_node(
        &self,
        dag: &PlanDag,
        id: PlanId,
        cache: &mut BTreeMap<usize, NodeLatency>,
    ) -> NodeLatency {
        if let Some(existing) = cache.get(&id.index()) {
            return existing.clone();
        }

        let result = dag.node(id).map_or_else(
            || NodeLatency {
                delay: f64::INFINITY,
                backlog: f64::INFINITY,
                output_arrival: ArrivalCurve::constant_rate(0.0),
                effective_service: ServiceCurve::constant_rate(0.0),
                contributions: vec![BoundContribution {
                    node_id: id,
                    delay: f64::INFINITY,
                    description: "missing node".to_string(),
                }],
            },
            |node| match node.clone() {
                PlanNode::Leaf { label } => self.analyze_leaf(id, &label),
                PlanNode::Join { children } => self.analyze_join(dag, id, &children, cache),
                PlanNode::Race { children } => self.analyze_race(dag, id, &children, cache),
                PlanNode::Timeout { child, duration } => {
                    self.analyze_timeout(dag, id, child, duration, cache)
                }
            },
        );

        cache.insert(id.index(), result.clone());
        result
    }

    /// Analyzes a leaf node using its annotation or defaults.
    fn analyze_leaf(&self, id: PlanId, label: &str) -> NodeLatency {
        let curves = self.annotations.get(&id.index()).cloned().or_else(|| {
            match (&self.default_arrival, &self.default_service) {
                (Some(a), Some(s)) => Some(NodeCurves::new(a.clone(), s.clone())),
                _ => None,
            }
        });

        curves.map_or_else(
            || NodeLatency {
                delay: f64::INFINITY,
                backlog: f64::INFINITY,
                output_arrival: ArrivalCurve::constant_rate(0.0),
                effective_service: ServiceCurve::constant_rate(0.0),
                contributions: vec![BoundContribution {
                    node_id: id,
                    delay: f64::INFINITY,
                    description: format!("leaf \"{label}\": no annotation"),
                }],
            },
            |curves| {
                let delay = curves.delay_bound();
                let backlog = curves.backlog_bound();
                let description = format!("leaf \"{label}\": delay={delay:.6}s");

                NodeLatency {
                    delay,
                    backlog,
                    output_arrival: ArrivalCurve::from_curve(min_plus_deconvolution(
                        curves.arrival.curve(),
                        curves.service.curve(),
                    )),
                    effective_service: curves.service.clone(),
                    contributions: vec![BoundContribution {
                        node_id: id,
                        delay,
                        description,
                    }],
                }
            },
        )
    }

    /// Analyzes a join node: `d_join = max(d_children)`.
    ///
    /// Join semantics: all children must complete before the join
    /// finishes. The worst-case delay is therefore the maximum delay
    /// across all children.
    ///
    /// For the combined service curve, we use the minimum of children's
    /// service curves (the bottleneck determines throughput).
    fn analyze_join(
        &self,
        dag: &PlanDag,
        id: PlanId,
        children: &[PlanId],
        cache: &mut BTreeMap<usize, NodeLatency>,
    ) -> NodeLatency {
        if children.is_empty() {
            return NodeLatency {
                delay: 0.0,
                backlog: 0.0,
                output_arrival: ArrivalCurve::constant_rate(0.0),
                effective_service: ServiceCurve::constant_rate(f64::INFINITY),
                contributions: vec![BoundContribution {
                    node_id: id,
                    delay: 0.0,
                    description: "empty join (trivial)".to_string(),
                }],
            };
        }

        let child_results: Vec<NodeLatency> = children
            .iter()
            .map(|c| self.analyze_node(dag, *c, cache))
            .collect();

        // Join delay = max of children's delays.
        let delay = child_results
            .iter()
            .map(|r| r.delay)
            .fold(0.0_f64, f64::max);

        // Join backlog = max of children's backlogs.
        let backlog = child_results
            .iter()
            .map(|r| r.backlog)
            .fold(0.0_f64, f64::max);

        // Rate-envelope approximation: use the bottleneck child's service
        // asymptotic rate as the join throughput proxy.
        let min_rate_child = child_results.iter().enumerate().min_by(|(_, a), (_, b)| {
            a.effective_service
                .asymptotic_rate()
                .partial_cmp(&b.effective_service.asymptotic_rate())
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let effective_service = min_rate_child.map_or_else(
            || ServiceCurve::constant_rate(0.0),
            |(_, r)| r.effective_service.clone(),
        );

        // Rate-envelope approximation: for join we use the dominant output
        // arrival-rate child as an aggregate proxy.
        let max_rate_child = child_results.iter().enumerate().max_by(|(_, a), (_, b)| {
            a.output_arrival
                .asymptotic_rate()
                .partial_cmp(&b.output_arrival.asymptotic_rate())
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let output_arrival = max_rate_child.map_or_else(
            || ArrivalCurve::constant_rate(0.0),
            |(_, r)| r.output_arrival.clone(),
        );

        // Collect provenance from all children.
        let mut contributions: Vec<BoundContribution> = child_results
            .iter()
            .flat_map(|r| r.contributions.iter().cloned())
            .collect();

        contributions.push(BoundContribution {
            node_id: id,
            delay,
            description: format!("join of {} children: max delay={delay:.6}s", children.len()),
        });

        NodeLatency {
            delay,
            backlog,
            output_arrival,
            effective_service,
            contributions,
        }
    }

    /// Analyzes a race node: `d_race = min(d_children)`.
    ///
    /// Race semantics: the first child to complete wins. The worst-case
    /// delay is the minimum of children's delays (even in the worst case,
    /// the fastest child determines the bound).
    ///
    /// For the combined service curve, we use the maximum of children's
    /// service curves (the fastest server dominates).
    fn analyze_race(
        &self,
        dag: &PlanDag,
        id: PlanId,
        children: &[PlanId],
        cache: &mut BTreeMap<usize, NodeLatency>,
    ) -> NodeLatency {
        if children.is_empty() {
            return NodeLatency {
                delay: f64::INFINITY,
                backlog: 0.0,
                output_arrival: ArrivalCurve::constant_rate(0.0),
                effective_service: ServiceCurve::constant_rate(0.0),
                contributions: vec![BoundContribution {
                    node_id: id,
                    delay: f64::INFINITY,
                    description: "empty race (deadlock)".to_string(),
                }],
            };
        }

        let child_results: Vec<NodeLatency> = children
            .iter()
            .map(|c| self.analyze_node(dag, *c, cache))
            .collect();

        // Race delay = min of children's delays.
        let delay = child_results
            .iter()
            .map(|r| r.delay)
            .fold(f64::INFINITY, f64::min);

        // Backlog = min as well (winner's backlog).
        let backlog = child_results
            .iter()
            .map(|r| r.backlog)
            .fold(f64::INFINITY, f64::min);

        // Rate-envelope approximation: fastest child's service curve proxy.
        let max_rate_child = child_results.iter().enumerate().max_by(|(_, a), (_, b)| {
            a.effective_service
                .asymptotic_rate()
                .partial_cmp(&b.effective_service.asymptotic_rate())
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let effective_service = max_rate_child.map_or_else(
            || ServiceCurve::constant_rate(0.0),
            |(_, r)| r.effective_service.clone(),
        );

        // Winner-takes-output approximation: use min-delay child's output curve.
        let min_delay_child = child_results.iter().enumerate().min_by(|(_, a), (_, b)| {
            a.delay
                .partial_cmp(&b.delay)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let output_arrival = min_delay_child.map_or_else(
            || ArrivalCurve::constant_rate(0.0),
            |(_, r)| r.output_arrival.clone(),
        );

        // Only include the winner's provenance chain.
        let winner_idx = child_results
            .iter()
            .enumerate()
            .min_by(|(_, a), (_, b)| {
                a.delay
                    .partial_cmp(&b.delay)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map_or(0, |(i, _)| i);

        let mut contributions: Vec<BoundContribution> =
            child_results[winner_idx].contributions.clone();

        contributions.push(BoundContribution {
            node_id: id,
            delay,
            description: format!(
                "race of {} children: min delay={delay:.6}s (winner=child[{winner_idx}])",
                children.len()
            ),
        });

        NodeLatency {
            delay,
            backlog,
            output_arrival,
            effective_service,
            contributions,
        }
    }

    /// Analyzes a timeout node: `d_timeout = min(d_child, timeout)`.
    ///
    /// Timeout semantics: the child's delay is capped by the timeout
    /// duration. This corresponds to the TIMEOUT-MIN law from
    /// `combinator::laws`: `timeout(d1, timeout(d2, f)) = timeout(min(d1,d2), f)`.
    fn analyze_timeout(
        &self,
        dag: &PlanDag,
        id: PlanId,
        child: PlanId,
        duration: std::time::Duration,
        cache: &mut BTreeMap<usize, NodeLatency>,
    ) -> NodeLatency {
        let child_result = self.analyze_node(dag, child, cache);
        let timeout_secs = duration.as_secs_f64();

        // Timeout caps the delay.
        let delay = child_result.delay.min(timeout_secs);

        // Backlog is also capped: at the timeout point, the maximum
        // arrivals are alpha(timeout), and service is beta(timeout).
        let backlog = if child_result.delay <= timeout_secs {
            // Child finishes before timeout: use child's backlog.
            child_result.backlog
        } else {
            // Timeout fires: backlog is whatever accumulated up to timeout.
            child_result
                .backlog
                .min(child_result.output_arrival.eval(timeout_secs))
        };

        let mut contributions = child_result.contributions;
        contributions.push(BoundContribution {
            node_id: id,
            delay,
            description: format!("timeout({timeout_secs:.6}s): capped delay={delay:.6}s"),
        });

        NodeLatency {
            delay,
            backlog,
            output_arrival: child_result.output_arrival,
            effective_service: child_result.effective_service,
            contributions,
        }
    }
}

impl Default for LatencyAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Convenience: standalone delay bound for simple cases
// ============================================================================

/// Computes the worst-case delay bound for a single server.
///
/// This is a convenience function for the common case of a single
/// arrival/service curve pair without a full DAG.
///
/// ```text
/// d* = h(alpha, beta) = sup_t { inf { d >= 0 : alpha(t) <= beta(t+d) } }
/// ```
///
/// For the special case of affine curves:
/// - `alpha(t) = sigma + rho * t` (token bucket)
/// - `beta(t) = R * max(0, t - T)` (rate-latency)
///
/// The closed-form delay bound is: `d* = T + sigma / R` (when `rho < R`).
#[must_use]
pub fn delay_bound(arrival: &ArrivalCurve, service: &ServiceCurve) -> f64 {
    horizontal_deviation(arrival.curve(), service.curve())
}

/// Computes the worst-case backlog bound for a single server.
///
/// ```text
/// b* = v(alpha, beta) = sup_t { alpha(t) - beta(t) }
/// ```
///
/// For affine curves: `b* = sigma + rho * T` (when `rho < R`).
#[must_use]
pub fn backlog_bound(arrival: &ArrivalCurve, service: &ServiceCurve) -> f64 {
    vertical_deviation(arrival.curve(), service.curve())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // Tolerance for floating-point comparisons.
    const EPS: f64 = 1e-3;

    fn approx_eq(a: f64, b: f64) -> bool {
        (a - b).abs() < EPS || (a.is_infinite() && b.is_infinite() && a.signum() == b.signum())
    }

    // -----------------------------------------------------------------------
    // Piecewise-linear curve basics
    // -----------------------------------------------------------------------

    #[test]
    fn zero_curve_evaluates_to_zero() {
        let c = PiecewiseLinearCurve::zero();
        assert!(approx_eq(c.eval(0.0), 0.0));
        assert!(approx_eq(c.eval(1.0), 0.0));
        assert!(approx_eq(c.eval(100.0), 0.0));
    }

    #[test]
    fn affine_curve_evaluates_correctly() {
        // f(t) = 10 + 5*t
        let c = PiecewiseLinearCurve::affine(5.0, 10.0);
        assert!(approx_eq(c.eval(0.0), 10.0));
        assert!(approx_eq(c.eval(1.0), 15.0));
        assert!(approx_eq(c.eval(2.0), 20.0));
        assert!(approx_eq(c.eval(10.0), 60.0));
    }

    #[test]
    fn rate_latency_curve_has_zero_before_latency() {
        // beta(t) = 100 * max(0, t - 0.5)
        let c = PiecewiseLinearCurve::rate_latency(100.0, 0.5);
        assert!(approx_eq(c.eval(0.0), 0.0));
        assert!(approx_eq(c.eval(0.25), 0.0));
        assert!(approx_eq(c.eval(0.5), 0.0));
        assert!(approx_eq(c.eval(1.0), 50.0));
        assert!(approx_eq(c.eval(1.5), 100.0));
    }

    #[test]
    fn from_segments_rejects_unsorted() {
        let segments = vec![Segment::new(1.0, 1.0, 0.0), Segment::new(0.0, 1.0, 0.0)];
        assert!(PiecewiseLinearCurve::from_segments(segments).is_none());
    }

    #[test]
    fn from_segments_rejects_negative_rate() {
        let segments = vec![Segment::new(0.0, -1.0, 0.0)];
        assert!(PiecewiseLinearCurve::from_segments(segments).is_none());
    }

    #[test]
    fn from_segments_rejects_discontinuity() {
        // First segment ends at 5.0, second starts at 10.0 (gap of 5.0).
        let segments = vec![
            Segment::new(0.0, 1.0, 0.0),
            Segment::new(5.0, 2.0, 10.0), // Should be 5.0 at start=5.0
        ];
        assert!(PiecewiseLinearCurve::from_segments(segments).is_none());
    }

    #[test]
    fn from_segments_accepts_valid_continuous_curve() {
        // f(t) = t for [0,1), then f(t) = 1 + 2*(t-1) for [1, ...)
        let segments = vec![Segment::new(0.0, 1.0, 0.0), Segment::new(1.0, 2.0, 1.0)];
        let c = PiecewiseLinearCurve::from_segments(segments).unwrap();
        assert!(approx_eq(c.eval(0.5), 0.5));
        assert!(approx_eq(c.eval(1.0), 1.0));
        assert!(approx_eq(c.eval(2.0), 3.0));
    }

    #[test]
    fn negative_time_evaluates_to_zero() {
        let c = PiecewiseLinearCurve::affine(1.0, 5.0);
        assert!(approx_eq(c.eval(-1.0), 0.0));
        assert!(approx_eq(c.eval(-100.0), 0.0));
    }

    // -----------------------------------------------------------------------
    // Horizontal deviation (delay bound)
    // -----------------------------------------------------------------------

    #[test]
    fn delay_bound_affine_token_bucket_rate_latency() {
        // Classic network calculus example:
        //   alpha(t) = sigma + rho * t   (token bucket: sigma=50, rho=100)
        //   beta(t)  = R * max(0, t-T)   (rate-latency: R=200, T=0.01)
        //
        // Closed form: d* = T + sigma/R = 0.01 + 50/200 = 0.26
        let alpha = ArrivalCurve::token_bucket(100.0, 50.0);
        let beta = ServiceCurve::rate_latency(200.0, 0.01);

        let d = delay_bound(&alpha, &beta);
        assert!(approx_eq(d, 0.26), "expected ~0.26, got {d}");
    }

    #[test]
    fn delay_bound_equal_rates_burst_only() {
        // alpha(t) = 10 + 5*t, beta(t) = 5*t
        // Delay is infinite because arrival has burst but service has no
        // headroom above the rate. The gap alpha(t) - beta(t) = 10 never closes.
        // Actually, when rates are equal, delay = inf { d : 10 + 5*t <= 5*(t+d) }
        //   = inf { d : 10 <= 5d } = 2.0
        let alpha = ArrivalCurve::token_bucket(5.0, 10.0);
        let beta = ServiceCurve::constant_rate(5.0);

        let d = delay_bound(&alpha, &beta);
        assert!(approx_eq(d, 2.0), "expected ~2.0, got {d}");
    }

    #[test]
    fn delay_bound_unstable_system() {
        // Arrival rate exceeds service rate: delay is infinite.
        let alpha = ArrivalCurve::constant_rate(200.0);
        let beta = ServiceCurve::constant_rate(100.0);

        let d = delay_bound(&alpha, &beta);
        assert!(d.is_infinite(), "expected infinite, got {d}");
    }

    #[test]
    fn delay_bound_zero_burst_zero_latency() {
        // alpha(t) = rho*t, beta(t) = R*t where R > rho.
        // Delay should be 0 (or very close).
        let alpha = ArrivalCurve::constant_rate(50.0);
        let beta = ServiceCurve::constant_rate(100.0);

        let d = delay_bound(&alpha, &beta);
        assert!(d < EPS, "expected ~0, got {d}");
    }

    // -----------------------------------------------------------------------
    // Vertical deviation (backlog bound)
    // -----------------------------------------------------------------------

    #[test]
    fn backlog_bound_token_bucket_rate_latency() {
        // alpha(t) = 50 + 100*t, beta(t) = 200*max(0, t - 0.01)
        // Closed form: b* = sigma + rho*T = 50 + 100*0.01 = 51
        let alpha = ArrivalCurve::token_bucket(100.0, 50.0);
        let beta = ServiceCurve::rate_latency(200.0, 0.01);

        let b = backlog_bound(&alpha, &beta);
        assert!(approx_eq(b, 51.0), "expected ~51.0, got {b}");
    }

    #[test]
    fn backlog_bound_unstable_system() {
        let alpha = ArrivalCurve::constant_rate(200.0);
        let beta = ServiceCurve::constant_rate(100.0);

        let b = backlog_bound(&alpha, &beta);
        assert!(b.is_infinite(), "expected infinite, got {b}");
    }

    // -----------------------------------------------------------------------
    // (min,+) convolution properties
    // -----------------------------------------------------------------------

    #[test]
    fn convolution_identity() {
        // Convolution with the zero curve (delta_0 approximation).
        // For a constant-rate curve, convolving with itself should yield
        // a curve with doubled latency characteristics.
        let f = PiecewiseLinearCurve::affine(10.0, 0.0);
        let g = PiecewiseLinearCurve::affine(10.0, 0.0);

        let conv = min_plus_convolution(&f, &g);
        // (f (x) g)(t) = inf_{0<=s<=t} { 10s + 10(t-s) } = 10t
        // For affine functions with same rate and zero burst, convolution is the function itself.
        assert!(
            approx_eq(conv.eval(1.0), 10.0),
            "expected ~10.0, got {}",
            conv.eval(1.0)
        );
    }

    #[test]
    fn convolution_commutativity() {
        // f (x) g = g (x) f
        let f = PiecewiseLinearCurve::affine(5.0, 10.0);
        let g = PiecewiseLinearCurve::rate_latency(8.0, 0.5);

        let fg = min_plus_convolution(&f, &g);
        let gf = min_plus_convolution(&g, &f);

        // Check at several points.
        for &t in &[0.0, 0.5, 1.0, 2.0, 5.0, 10.0] {
            assert!(
                approx_eq(fg.eval(t), gf.eval(t)),
                "commutativity failed at t={t}: fg={}, gf={}",
                fg.eval(t),
                gf.eval(t)
            );
        }
    }

    #[test]
    fn convolution_rate_latency_sum() {
        // For two rate-latency curves:
        //   beta_1(t) = R * max(0, t - T1)
        //   beta_2(t) = R * max(0, t - T2)
        // The convolution is:
        //   (beta_1 (x) beta_2)(t) = R * max(0, t - T1 - T2)
        // (Theorem 3.1.3, Le Boudec & Thiran)
        let beta1 = ServiceCurve::rate_latency(100.0, 0.1);
        let beta2 = ServiceCurve::rate_latency(100.0, 0.2);

        let combined = beta1.sequential(&beta2);

        // Expected: rate=100, latency=0.3
        // At t=0.5: 100 * (0.5 - 0.3) = 20.0
        assert!(
            approx_eq(combined.eval(0.3), 0.0),
            "expected ~0.0 at t=0.3, got {}",
            combined.eval(0.3)
        );
        assert!(
            approx_eq(combined.eval(0.5), 20.0),
            "expected ~20.0 at t=0.5, got {}",
            combined.eval(0.5)
        );
        assert!(
            approx_eq(combined.eval(1.0), 70.0),
            "expected ~70.0 at t=1.0, got {}",
            combined.eval(1.0)
        );
    }

    #[test]
    fn convolution_associativity() {
        // (f (x) g) (x) h = f (x) (g (x) h)
        let f = PiecewiseLinearCurve::rate_latency(10.0, 0.1);
        let g = PiecewiseLinearCurve::rate_latency(15.0, 0.2);
        let h = PiecewiseLinearCurve::rate_latency(20.0, 0.05);

        let fg_h = min_plus_convolution(&min_plus_convolution(&f, &g), &h);
        let f_gh = min_plus_convolution(&f, &min_plus_convolution(&g, &h));

        for &t in &[0.0, 0.5, 1.0, 2.0, 5.0] {
            assert!(
                approx_eq(fg_h.eval(t), f_gh.eval(t)),
                "associativity failed at t={t}: (fg)h={}, f(gh)={}",
                fg_h.eval(t),
                f_gh.eval(t)
            );
        }
    }

    // -----------------------------------------------------------------------
    // Service curve scaling
    // -----------------------------------------------------------------------

    #[test]
    fn service_curve_scaling() {
        let beta = ServiceCurve::rate_latency(100.0, 0.01);
        let scaled = beta.scale(3.0);

        // Rate should triple, latency unchanged.
        assert!(approx_eq(scaled.eval(0.01), 0.0));
        assert!(approx_eq(scaled.eval(0.02), 3.0)); // 300 * 0.01
        assert!(approx_eq(scaled.eval(0.11), 30.0)); // 300 * 0.1
    }

    // -----------------------------------------------------------------------
    // PlanDag integration: join
    // -----------------------------------------------------------------------

    #[test]
    fn dag_join_takes_max_delay() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("fast");
        let b = dag.leaf("slow");
        let joined = dag.join(vec![a, b]);
        dag.set_root(joined);

        let mut analyzer = LatencyAnalyzer::new();
        // fast: delay ~0.05s
        analyzer.annotate(
            a,
            NodeCurves::new(
                ArrivalCurve::token_bucket(100.0, 10.0),
                ServiceCurve::rate_latency(200.0, 0.0),
            ),
        );
        // slow: delay ~0.26s (T=0.01 + sigma/R = 50/200)
        analyzer.annotate(
            b,
            NodeCurves::new(
                ArrivalCurve::token_bucket(100.0, 50.0),
                ServiceCurve::rate_latency(200.0, 0.01),
            ),
        );

        let analysis = analyzer.analyze(&dag);

        // Join should take the max (slow's delay).
        let root_delay = analysis.end_to_end_delay().unwrap();
        let slow_delay = analysis.delay_at(b).unwrap();
        assert!(
            approx_eq(root_delay, slow_delay),
            "join delay {root_delay} should equal slow delay {slow_delay}"
        );
        // The join delay should be approximately 0.26.
        assert!(
            (root_delay - 0.26).abs() < 0.05,
            "expected join delay ~0.26, got {root_delay}"
        );
    }

    #[test]
    fn dag_join_empty_children_is_zero() {
        let mut dag = PlanDag::new();
        let joined = dag.join(vec![]);
        dag.set_root(joined);

        let analyzer = LatencyAnalyzer::new();
        let analysis = analyzer.analyze(&dag);

        assert!(approx_eq(analysis.end_to_end_delay().unwrap(), 0.0));
    }

    // -----------------------------------------------------------------------
    // PlanDag integration: race
    // -----------------------------------------------------------------------

    #[test]
    fn dag_race_takes_min_delay() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("fast");
        let b = dag.leaf("slow");
        let raced = dag.race(vec![a, b]);
        dag.set_root(raced);

        let mut analyzer = LatencyAnalyzer::new();
        analyzer.annotate(
            a,
            NodeCurves::new(
                ArrivalCurve::token_bucket(100.0, 10.0),
                ServiceCurve::rate_latency(200.0, 0.0),
            ),
        );
        analyzer.annotate(
            b,
            NodeCurves::new(
                ArrivalCurve::token_bucket(100.0, 50.0),
                ServiceCurve::rate_latency(200.0, 0.01),
            ),
        );

        let analysis = analyzer.analyze(&dag);

        let root_delay = analysis.end_to_end_delay().unwrap();
        let fast_delay = analysis.delay_at(a).unwrap();
        assert!(
            approx_eq(root_delay, fast_delay),
            "race delay {root_delay} should equal fast delay {fast_delay}"
        );
        assert!(
            root_delay < 0.1,
            "race delay should be small, got {root_delay}"
        );
    }

    #[test]
    fn dag_race_empty_children_is_infinite() {
        let mut dag = PlanDag::new();
        let raced = dag.race(vec![]);
        dag.set_root(raced);

        let analyzer = LatencyAnalyzer::new();
        let analysis = analyzer.analyze(&dag);

        assert!(analysis.end_to_end_delay().unwrap().is_infinite());
    }

    // -----------------------------------------------------------------------
    // PlanDag integration: timeout
    // -----------------------------------------------------------------------

    #[test]
    fn dag_timeout_caps_delay() {
        let mut dag = PlanDag::new();
        let slow = dag.leaf("slow");
        let timed = dag.timeout(slow, Duration::from_millis(100));
        dag.set_root(timed);

        let mut analyzer = LatencyAnalyzer::new();
        // Slow service: delay ~1.0s.
        analyzer.annotate(
            slow,
            NodeCurves::new(
                ArrivalCurve::token_bucket(100.0, 100.0),
                ServiceCurve::rate_latency(200.0, 0.5),
            ),
        );

        let analysis = analyzer.analyze(&dag);
        let root_delay = analysis.end_to_end_delay().unwrap();

        // Timeout of 100ms should cap the delay.
        assert!(
            root_delay <= 0.1 + EPS,
            "timeout should cap delay to 0.1s, got {root_delay}"
        );
    }

    #[test]
    fn dag_timeout_passthrough_when_child_is_fast() {
        let mut dag = PlanDag::new();
        let fast = dag.leaf("fast");
        let timed = dag.timeout(fast, Duration::from_secs(10));
        dag.set_root(timed);

        let mut analyzer = LatencyAnalyzer::new();
        // Fast service: delay ~0.05s (well under 10s timeout).
        analyzer.annotate(
            fast,
            NodeCurves::new(
                ArrivalCurve::token_bucket(100.0, 10.0),
                ServiceCurve::rate_latency(200.0, 0.0),
            ),
        );

        let analysis = analyzer.analyze(&dag);
        let root_delay = analysis.end_to_end_delay().unwrap();
        let child_delay = analysis.delay_at(fast).unwrap();

        assert!(
            approx_eq(root_delay, child_delay),
            "with generous timeout, delay should match child: root={root_delay}, child={child_delay}"
        );
    }

    // -----------------------------------------------------------------------
    // Nested timeout collapsing (TIMEOUT-MIN law)
    // -----------------------------------------------------------------------

    #[test]
    fn nested_timeout_min_law() {
        // TIMEOUT-MIN: timeout(d1, timeout(d2, f)) ~ timeout(min(d1,d2), f)
        let mut dag = PlanDag::new();
        let leaf = dag.leaf("task");
        let inner_timeout = dag.timeout(leaf, Duration::from_millis(500));
        let outer_timeout = dag.timeout(inner_timeout, Duration::from_millis(200));
        dag.set_root(outer_timeout);

        let mut analyzer = LatencyAnalyzer::new();
        analyzer.annotate(
            leaf,
            NodeCurves::new(
                ArrivalCurve::token_bucket(100.0, 200.0),
                ServiceCurve::rate_latency(200.0, 1.0), // Slow: ~2s delay.
            ),
        );

        let analysis = analyzer.analyze(&dag);
        let root_delay = analysis.end_to_end_delay().unwrap();

        // min(500ms, 200ms) = 200ms should dominate.
        assert!(
            root_delay <= 0.2 + EPS,
            "nested timeouts should collapse to min: got {root_delay}"
        );
    }

    // -----------------------------------------------------------------------
    // Complex DAG: join of races with timeouts
    // -----------------------------------------------------------------------

    #[test]
    fn complex_dag_join_race_timeout() {
        // Structure:
        //   join(
        //     race(a, b),
        //     timeout(c, 0.5s)
        //   )
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let c = dag.leaf("c");
        let race_ab = dag.race(vec![a, b]);
        let timeout_c = dag.timeout(c, Duration::from_millis(500));
        let root = dag.join(vec![race_ab, timeout_c]);
        dag.set_root(root);

        let mut analyzer = LatencyAnalyzer::new();
        // a: fast (~0.05s)
        analyzer.annotate(
            a,
            NodeCurves::new(
                ArrivalCurve::token_bucket(100.0, 10.0),
                ServiceCurve::rate_latency(200.0, 0.0),
            ),
        );
        // b: moderate (~0.26s)
        analyzer.annotate(
            b,
            NodeCurves::new(
                ArrivalCurve::token_bucket(100.0, 50.0),
                ServiceCurve::rate_latency(200.0, 0.01),
            ),
        );
        // c: slow (~2.0s, will be capped by timeout)
        analyzer.annotate(
            c,
            NodeCurves::new(
                ArrivalCurve::token_bucket(100.0, 200.0),
                ServiceCurve::rate_latency(200.0, 1.0),
            ),
        );

        let analysis = analyzer.analyze(&dag);
        let root_delay = analysis.end_to_end_delay().unwrap();

        // race(a, b) delay = min(0.05, 0.26) ~ 0.05
        // timeout(c, 0.5) delay = min(2.0, 0.5) = 0.5
        // join delay = max(0.05, 0.5) = 0.5
        assert!(
            (root_delay - 0.5).abs() < 0.1,
            "expected root delay ~0.5, got {root_delay}"
        );
    }

    // -----------------------------------------------------------------------
    // Default curves for unannotated leaves
    // -----------------------------------------------------------------------

    #[test]
    fn default_curves_used_for_unannotated_leaves() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("annotated");
        let b = dag.leaf("unannotated");
        let joined = dag.join(vec![a, b]);
        dag.set_root(joined);

        let mut analyzer = LatencyAnalyzer::with_defaults(
            ArrivalCurve::token_bucket(50.0, 20.0),
            ServiceCurve::rate_latency(100.0, 0.005),
        );
        // Only annotate 'a'.
        analyzer.annotate(
            a,
            NodeCurves::new(
                ArrivalCurve::token_bucket(100.0, 10.0),
                ServiceCurve::rate_latency(200.0, 0.0),
            ),
        );

        let analysis = analyzer.analyze(&dag);

        // Both nodes should have finite delays.
        assert!(analysis.delay_at(a).unwrap().is_finite());
        assert!(analysis.delay_at(b).unwrap().is_finite());
        assert!(analysis.end_to_end_delay().unwrap().is_finite());
    }

    #[test]
    fn missing_annotation_no_defaults_gives_infinity() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("no_annotation");
        dag.set_root(a);

        let analyzer = LatencyAnalyzer::new();
        let analysis = analyzer.analyze(&dag);

        assert!(analysis.delay_at(a).unwrap().is_infinite());
    }

    // -----------------------------------------------------------------------
    // Provenance and bottleneck identification
    // -----------------------------------------------------------------------

    #[test]
    fn provenance_identifies_bottleneck() {
        let mut dag = PlanDag::new();
        let fast = dag.leaf("fast");
        let slow = dag.leaf("slow");
        let joined = dag.join(vec![fast, slow]);
        dag.set_root(joined);

        let mut analyzer = LatencyAnalyzer::new();
        analyzer.annotate(
            fast,
            NodeCurves::new(
                ArrivalCurve::constant_rate(10.0),
                ServiceCurve::constant_rate(100.0),
            ),
        );
        analyzer.annotate(
            slow,
            NodeCurves::new(
                ArrivalCurve::token_bucket(100.0, 500.0),
                ServiceCurve::rate_latency(200.0, 0.1),
            ),
        );

        let analysis = analyzer.analyze(&dag);
        let bound = analysis.root_bound.as_ref().unwrap();

        // The bottleneck should be the slow node.
        assert!(!bound.provenance.is_empty());
        let top = bound.bottleneck().unwrap();
        assert!(
            top.delay > 0.1,
            "bottleneck delay should be significant, got {}",
            top.delay
        );
    }

    #[test]
    fn latency_bound_display_format() {
        let bound = LatencyBound {
            delay: 0.123_456,
            backlog: 42.0,
            utilization: 0.75,
            provenance: vec![BoundContribution {
                node_id: PlanId::new(0),
                delay: 0.123_456,
                description: "test node".to_string(),
            }],
        };

        let display = format!("{bound}");
        assert!(display.contains("0.123456s"));
        assert!(display.contains("42.00"));
        assert!(display.contains("75.0%"));
        assert!(display.contains("test node"));
    }

    #[test]
    fn latency_bound_summary_stable() {
        let bound = LatencyBound {
            delay: 0.5,
            backlog: 100.0,
            utilization: 0.6,
            provenance: vec![BoundContribution {
                node_id: PlanId::new(3),
                delay: 0.5,
                description: "slow".to_string(),
            }],
        };
        let s = bound.summary();
        assert!(s.contains("delay<="));
        assert!(s.contains("bottleneck=node[3]"));
    }

    #[test]
    fn latency_bound_summary_unstable() {
        let bound = LatencyBound {
            delay: f64::INFINITY,
            backlog: f64::INFINITY,
            utilization: 1.5,
            provenance: vec![],
        };
        let s = bound.summary();
        assert!(s.contains("UNSTABLE"));
    }

    // -----------------------------------------------------------------------
    // NodeCurves standalone
    // -----------------------------------------------------------------------

    #[test]
    fn node_curves_utilization() {
        let curves = NodeCurves::new(
            ArrivalCurve::constant_rate(80.0),
            ServiceCurve::constant_rate(100.0),
        );
        assert!(approx_eq(curves.utilization(), 0.8));
    }

    #[test]
    fn node_curves_utilization_zero_service() {
        let curves = NodeCurves::new(
            ArrivalCurve::constant_rate(80.0),
            ServiceCurve::constant_rate(0.0),
        );
        assert!(curves.utilization().is_infinite());
    }

    // -----------------------------------------------------------------------
    // Deconvolution
    // -----------------------------------------------------------------------

    #[test]
    fn deconvolution_token_bucket_rate_latency() {
        // Output arrival curve through a rate-latency server.
        // For alpha(t) = sigma + rho*t through beta(t) = R*max(0, t-T),
        // output: alpha_out(t) = sigma + rho*T + rho*t (burstiness increases by rho*T).
        let alpha = PiecewiseLinearCurve::affine(100.0, 50.0); // rho=100, sigma=50
        let beta = PiecewiseLinearCurve::rate_latency(200.0, 0.01); // R=200, T=0.01

        let output = min_plus_deconvolution(&alpha, &beta);

        // At t=0: output(0) = sup_{s>=0} { alpha(s) - beta(s) }
        //       = sup_{s>=0} { (50 + 100s) - 200*max(0, s-0.01) }
        // The sup occurs at s = T = 0.01: (50 + 1) - 0 = 51
        let val_0 = output.eval(0.0);
        assert!(
            (val_0 - 51.0).abs() < 2.0,
            "deconvolution at t=0: expected ~51, got {val_0}"
        );
    }

    // -----------------------------------------------------------------------
    // Staircase curve
    // -----------------------------------------------------------------------

    #[test]
    fn staircase_curve_step_values() {
        let c = PiecewiseLinearCurve::staircase(10.0, 1.0, 3);
        // After each period, the value should jump by step_size.
        // At t=0.5 (mid first period): ~10.0 (stepped up immediately).
        assert!(c.eval(0.5) >= 9.0 && c.eval(0.5) <= 11.0);
        // At t=1.5 (mid second period): ~20.0.
        assert!(c.eval(1.5) >= 19.0 && c.eval(1.5) <= 21.0);
    }

    // -----------------------------------------------------------------------
    // Algebraic property: race(join(a,b), join(a,c)) delay relationships
    // -----------------------------------------------------------------------

    #[test]
    fn race_join_distributivity_delay() {
        // Verify that d(race(join(a,b), join(a,c))) <= d(join(a, race(b,c)))
        // (The delay of the LHS is at most the delay of the RHS.)
        let mut dag_lhs = PlanDag::new();
        let a1 = dag_lhs.leaf("a");
        let b = dag_lhs.leaf("b");
        let a2 = dag_lhs.leaf("a_copy");
        let c = dag_lhs.leaf("c");
        let lhs_join_with_b = dag_lhs.join(vec![a1, b]);
        let lhs_join_with_c = dag_lhs.join(vec![a2, c]);
        let race_root = dag_lhs.race(vec![lhs_join_with_b, lhs_join_with_c]);
        dag_lhs.set_root(race_root);

        let mut dag_rhs = PlanDag::new();
        let a3 = dag_rhs.leaf("a");
        let b2 = dag_rhs.leaf("b");
        let c2 = dag_rhs.leaf("c");
        let race_bc = dag_rhs.race(vec![b2, c2]);
        let join_root = dag_rhs.join(vec![a3, race_bc]);
        dag_rhs.set_root(join_root);

        let a_curves = NodeCurves::new(
            ArrivalCurve::token_bucket(100.0, 30.0),
            ServiceCurve::rate_latency(200.0, 0.005),
        );
        let b_curves = NodeCurves::new(
            ArrivalCurve::token_bucket(80.0, 50.0),
            ServiceCurve::rate_latency(150.0, 0.01),
        );
        let c_curves = NodeCurves::new(
            ArrivalCurve::token_bucket(60.0, 10.0),
            ServiceCurve::rate_latency(120.0, 0.002),
        );

        let mut analyzer_lhs = LatencyAnalyzer::new();
        analyzer_lhs.annotate(a1, a_curves.clone());
        analyzer_lhs.annotate(b, b_curves.clone());
        analyzer_lhs.annotate(a2, a_curves.clone());
        analyzer_lhs.annotate(c, c_curves.clone());

        let mut analyzer_rhs = LatencyAnalyzer::new();
        analyzer_rhs.annotate(a3, a_curves);
        analyzer_rhs.annotate(b2, b_curves);
        analyzer_rhs.annotate(c2, c_curves);

        let lhs_delay = analyzer_lhs.analyze(&dag_lhs).end_to_end_delay().unwrap();
        let rhs_delay = analyzer_rhs.analyze(&dag_rhs).end_to_end_delay().unwrap();

        // The distributivity law holds at the delay level:
        // race(join(a,b), join(a,c)) delay <= join(a, race(b,c)) delay.
        assert!(
            lhs_delay <= rhs_delay + EPS,
            "distributivity: lhs={lhs_delay} should be <= rhs={rhs_delay}"
        );
    }

    // -----------------------------------------------------------------------
    // Analysis Display
    // -----------------------------------------------------------------------

    #[test]
    fn analysis_summary_format() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        dag.set_root(a);

        let mut analyzer = LatencyAnalyzer::new();
        analyzer.annotate(
            a,
            NodeCurves::new(
                ArrivalCurve::constant_rate(10.0),
                ServiceCurve::constant_rate(20.0),
            ),
        );

        let analysis = analyzer.analyze(&dag);
        let summary = analysis.summary();
        assert!(summary.contains("nodes analyzed"));
    }

    #[test]
    fn analysis_display_includes_all_nodes() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let joined = dag.join(vec![a, b]);
        dag.set_root(joined);

        let analyzer = LatencyAnalyzer::with_defaults(
            ArrivalCurve::constant_rate(10.0),
            ServiceCurve::constant_rate(20.0),
        );

        let analysis = analyzer.analyze(&dag);
        let display = format!("{analysis}");
        assert!(display.contains("node[0]"));
        assert!(display.contains("node[1]"));
        assert!(display.contains("node[2]"));
    }

    // -----------------------------------------------------------------------
    // Edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn single_leaf_dag_analysis() {
        let mut dag = PlanDag::new();
        let leaf = dag.leaf("single");
        dag.set_root(leaf);

        let mut analyzer = LatencyAnalyzer::new();
        analyzer.annotate(
            leaf,
            NodeCurves::new(
                ArrivalCurve::token_bucket(50.0, 25.0),
                ServiceCurve::rate_latency(100.0, 0.01),
            ),
        );

        let analysis = analyzer.analyze(&dag);
        let delay = analysis.end_to_end_delay().unwrap();

        // Expected: T + sigma/R = 0.01 + 25/100 = 0.26
        assert!(
            (delay - 0.26).abs() < 0.05,
            "single leaf delay expected ~0.26, got {delay}"
        );
    }

    #[test]
    fn dag_with_no_root_has_no_bound() {
        let mut dag = PlanDag::new();
        let _a = dag.leaf("orphan");
        // No root set.

        let analyzer = LatencyAnalyzer::with_defaults(
            ArrivalCurve::constant_rate(10.0),
            ServiceCurve::constant_rate(20.0),
        );

        let analysis = analyzer.analyze(&dag);
        assert!(analysis.root_bound.is_none());
        // But per-node delays should still be computed.
        assert!(!analysis.node_delays.is_empty());
    }

    #[test]
    fn deeply_nested_timeouts() {
        // timeout(100ms, timeout(200ms, timeout(50ms, leaf)))
        // Effective timeout: min(100, 200, 50) = 50ms
        let mut dag = PlanDag::new();
        let leaf = dag.leaf("task");
        let t1 = dag.timeout(leaf, Duration::from_millis(50));
        let t2 = dag.timeout(t1, Duration::from_millis(200));
        let t3 = dag.timeout(t2, Duration::from_millis(100));
        dag.set_root(t3);

        let mut analyzer = LatencyAnalyzer::new();
        analyzer.annotate(
            leaf,
            NodeCurves::new(
                ArrivalCurve::token_bucket(100.0, 500.0),
                ServiceCurve::rate_latency(200.0, 5.0), // Very slow: ~7.5s.
            ),
        );

        let analysis = analyzer.analyze(&dag);
        let delay = analysis.end_to_end_delay().unwrap();

        assert!(
            delay <= 0.05 + EPS,
            "deeply nested timeouts should collapse to min(50ms): got {delay}"
        );
    }

    #[test]
    fn wide_join_many_children() {
        let mut dag = PlanDag::new();
        let children: Vec<PlanId> = (0..20).map(|i| dag.leaf(format!("child_{i}"))).collect();
        let joined = dag.join(children.clone());
        dag.set_root(joined);

        let mut analyzer = LatencyAnalyzer::new();
        for (i, &child) in children.iter().enumerate() {
            let i_u32 = u32::try_from(i).expect("test uses small child index");
            let burst = f64::from(i_u32).mul_add(5.0, 10.0);
            analyzer.annotate(
                child,
                NodeCurves::new(
                    ArrivalCurve::token_bucket(100.0, burst),
                    ServiceCurve::rate_latency(200.0, 0.001),
                ),
            );
        }

        let analysis = analyzer.analyze(&dag);
        let delay = analysis.end_to_end_delay().unwrap();

        // The slowest child has burst=10+19*5=105, delay ~ 0.001 + 105/200 = 0.526.
        assert!(delay.is_finite());
        assert!(
            delay > 0.4,
            "wide join should be dominated by slowest child, got {delay}"
        );
    }

    #[test]
    fn wide_race_many_children() {
        let mut dag = PlanDag::new();
        let children: Vec<PlanId> = (0..20).map(|i| dag.leaf(format!("child_{i}"))).collect();
        let raced = dag.race(children.clone());
        dag.set_root(raced);

        let mut analyzer = LatencyAnalyzer::new();
        for (i, &child) in children.iter().enumerate() {
            let i_u32 = u32::try_from(i).expect("test uses small child index");
            let burst = f64::from(i_u32).mul_add(5.0, 10.0);
            analyzer.annotate(
                child,
                NodeCurves::new(
                    ArrivalCurve::token_bucket(100.0, burst),
                    ServiceCurve::rate_latency(200.0, 0.001),
                ),
            );
        }

        let analysis = analyzer.analyze(&dag);
        let delay = analysis.end_to_end_delay().unwrap();

        // The fastest child has burst=10, delay ~ 0.001 + 10/200 = 0.051.
        assert!(delay.is_finite());
        assert!(
            delay < 0.15,
            "wide race should be dominated by fastest child, got {delay}"
        );
    }

    // -----------------------------------------------------------------------
    // Monotonicity: adding more work increases delay
    // -----------------------------------------------------------------------

    #[test]
    fn delay_monotonic_in_burst() {
        // Increasing burst should increase delay.
        let service = ServiceCurve::rate_latency(200.0, 0.01);
        let d1 = delay_bound(&ArrivalCurve::token_bucket(100.0, 10.0), &service);
        let d2 = delay_bound(&ArrivalCurve::token_bucket(100.0, 50.0), &service);
        let d3 = delay_bound(&ArrivalCurve::token_bucket(100.0, 100.0), &service);

        assert!(d1 <= d2 + EPS, "d1={d1} should be <= d2={d2}");
        assert!(d2 <= d3 + EPS, "d2={d2} should be <= d3={d3}");
    }

    #[test]
    fn delay_monotonic_in_latency() {
        // Increasing server latency should increase delay.
        let arrival = ArrivalCurve::token_bucket(100.0, 50.0);
        let d1 = delay_bound(&arrival, &ServiceCurve::rate_latency(200.0, 0.0));
        let d2 = delay_bound(&arrival, &ServiceCurve::rate_latency(200.0, 0.1));
        let d3 = delay_bound(&arrival, &ServiceCurve::rate_latency(200.0, 0.5));

        assert!(d1 <= d2 + EPS, "d1={d1} should be <= d2={d2}");
        assert!(d2 <= d3 + EPS, "d2={d2} should be <= d3={d3}");
    }

    // -----------------------------------------------------------------------
    // Isotonicity of convolution
    // -----------------------------------------------------------------------

    #[test]
    fn convolution_isotone() {
        // If f <= g pointwise, then f (x) h <= g (x) h pointwise.
        let f = PiecewiseLinearCurve::affine(5.0, 0.0);
        let g = PiecewiseLinearCurve::affine(10.0, 0.0);
        let h = PiecewiseLinearCurve::rate_latency(8.0, 0.1);

        let fh = min_plus_convolution(&f, &h);
        let gh = min_plus_convolution(&g, &h);

        for &t in &[0.0, 0.5, 1.0, 2.0, 5.0] {
            assert!(
                fh.eval(t) <= gh.eval(t) + EPS,
                "isotonicity failed at t={t}: fh={} > gh={}",
                fh.eval(t),
                gh.eval(t)
            );
        }
    }
}
