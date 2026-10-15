//! Fuzz target for `src/plan/latency_algebra.rs` — PiecewiseLinearCurve algebra.
//!
//! Exercises:
//!   - `Segment::new` + `Segment::eval_at` for any (start, rate, burst)
//!     triple — must never panic on any finite f64 (NaN inputs may
//!     legitimately propagate; we filter them out).
//!   - `PiecewiseLinearCurve::from_segments` — construction with
//!     arbitrary segment lists.
//!   - `affine`, `rate_latency`, `staircase` constructors — must
//!     produce a curve whose `segment_count()` and `asymptotic_rate()`
//!     are well-defined.
//!   - `min_plus_convolution`, `horizontal_deviation`,
//!     `vertical_deviation`, `min_plus_deconvolution` — algebraic
//!     operations on two curves.
//!
//! No-panic property is the primary invariant; algebra-level
//! invariants (commutativity of min-plus convolution, etc.) are
//! noted but not asserted because they require numerical tolerance
//! handling that's better expressed in property tests.

#![no_main]

use arbitrary::Arbitrary;
use asupersync::plan::latency_algebra::{
    PiecewiseLinearCurve, Segment, horizontal_deviation, min_plus_convolution,
    min_plus_deconvolution, vertical_deviation,
};
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
struct SegInput {
    start: i32,
    rate: i32,
    burst: i32,
}

impl SegInput {
    fn into_segment(self) -> Segment {
        // Map to bounded f64 to avoid NaN/infinity from raw bit
        // patterns; the algebra is meant to operate on physical
        // quantities (bytes, seconds), so we cap to a sane range.
        let start = (self.start as f64) / 1000.0;
        let rate = (self.rate as f64).abs() / 1000.0;
        let burst = (self.burst as f64).abs() / 1000.0;
        Segment::new(start.max(0.0), rate, burst)
    }
}

#[derive(Debug, Arbitrary)]
struct Input {
    a_segs: Vec<SegInput>,
    b_segs: Vec<SegInput>,
    eval_t: i32,
}

fuzz_target!(|input: Input| {
    // Bound segment counts: very long lists exercise allocator more
    // than algorithm and slow the corpus.
    let a_segs: Vec<Segment> = input
        .a_segs
        .into_iter()
        .take(16)
        .map(SegInput::into_segment)
        .collect();
    let b_segs: Vec<Segment> = input
        .b_segs
        .into_iter()
        .take(16)
        .map(SegInput::into_segment)
        .collect();

    // Constructor 1: from_segments. May return None for invalid
    // segment lists (out-of-order start times, etc.) — that's fine.
    let a_curve = match PiecewiseLinearCurve::from_segments(a_segs) {
        Some(c) => c,
        None => PiecewiseLinearCurve::zero(),
    };
    let b_curve = match PiecewiseLinearCurve::from_segments(b_segs) {
        Some(c) => c,
        None => PiecewiseLinearCurve::zero(),
    };

    // Eval at an arbitrary time point.
    let t = (input.eval_t as f64) / 1000.0;
    observe_scalar(a_curve.eval(t), "a_curve.eval");
    observe_scalar(b_curve.eval(t), "b_curve.eval");

    // Static-shape constructors must not panic on any positive params.
    observe_curve(PiecewiseLinearCurve::affine(1.0, 0.0), "affine");
    observe_curve(PiecewiseLinearCurve::rate_latency(1.0, 0.0), "rate_latency");
    observe_curve(PiecewiseLinearCurve::staircase(1.0, 1.0, 4), "staircase");

    // Inspectors.
    assert!(
        a_curve.segment_count() > 0,
        "curve inspector returned an empty segment count"
    );
    observe_scalar(a_curve.asymptotic_rate(), "a_curve.asymptotic_rate");
    observe_segments(a_curve.segments(), "a_curve.segments");

    // Algebra: must not panic. Numerical results may overflow to
    // f64::INFINITY, which is acceptable (caller's responsibility to
    // check); the contract is "no panic, no UB".
    observe_curve(
        min_plus_convolution(&a_curve, &b_curve),
        "min_plus_convolution",
    );
    observe_curve(
        min_plus_deconvolution(&a_curve, &b_curve),
        "min_plus_deconvolution",
    );
    observe_bounded_deviation(
        horizontal_deviation(&a_curve, &b_curve),
        "horizontal_deviation",
    );
    observe_bounded_deviation(vertical_deviation(&a_curve, &b_curve), "vertical_deviation");

    // Self-deviation reflexivity: deviation between identical curves
    // should be finite and non-negative (or 0 in the degenerate case).
    let self_h = horizontal_deviation(&a_curve, &a_curve);
    let self_v = vertical_deviation(&a_curve, &a_curve);
    if self_h.is_finite() {
        assert!(
            self_h >= -1e-9,
            "self-horizontal-deviation should be non-negative: got {self_h}"
        );
    }
    if self_v.is_finite() {
        assert!(
            self_v >= -1e-9,
            "self-vertical-deviation should be non-negative: got {self_v}"
        );
    }
});

fn observe_curve(curve: PiecewiseLinearCurve, context: &str) {
    assert!(
        curve.segment_count() > 0,
        "{context} produced an empty curve"
    );
    observe_scalar(curve.asymptotic_rate(), context);
    observe_segments(curve.segments(), context);
}

fn observe_segments(segments: &[Segment], context: &str) {
    assert!(!segments.is_empty(), "{context} exposed no segments");

    let mut previous_start = None;
    for segment in segments {
        observe_scalar(segment.start, context);
        observe_scalar(segment.rate, context);
        observe_scalar(segment.burst, context);

        if let Some(previous_start) = previous_start {
            assert!(
                segment.start > previous_start,
                "{context} segment starts must increase strictly"
            );
        }
        previous_start = Some(segment.start);
    }
}

fn observe_scalar(value: f64, context: &str) {
    assert!(value.is_finite(), "{context} produced a non-finite value");
    assert!(
        value >= -1e-9,
        "{context} produced a negative value: {value}"
    );
}

fn observe_bounded_deviation(value: f64, context: &str) {
    assert!(
        value.is_finite() || value.is_infinite() && value.is_sign_positive(),
        "{context} produced invalid deviation: {value}"
    );
    if value.is_finite() {
        assert!(
            value >= -1e-9,
            "{context} produced negative deviation: {value}"
        );
    }
}
