//! RaptorQ GF(256) dual-kernel dispatch decision — policy-gate conformance.
//!
//! bd-3uox5 (RAPTORQ-RFC6330). The GF(256) backend chooses between sequential
//! and fused dual-lane execution through a deterministic policy surface in
//! `raptorq::gf256`:
//!   - `dual_mul_kernel_decision` / `dual_mul_kernel_decision_detail`
//!   - `dual_addmul_kernel_decision` / `dual_addmul_kernel_decision_detail`
//!   - the active policy is observable via `dual_kernel_policy_snapshot()`.
//!
//! All four decision functions, the `DualKernelDecision`/`Detail::is_fused`
//! helpers, and the `as_str` reason labels had ZERO integration coverage, so
//! nothing pinned the documented gate ordering (window -> lane-floor (addmul
//! only) -> ratio -> eligible) that the SIMD dispatch — and the structured
//! forensic logs operators read — depend on.
//!
//! The decision functions read a process-global policy that varies by
//! architecture and `ASUPERSYNC_GF256_DUAL_POLICY` env, so this harness is
//! oracle-free WITHOUT pinning concrete window values:
//!   - a pure `expected()` recompute mirrors the production gate ordering
//!     exactly (saturating arithmetic and the `WindowDisabledByProfile`
//!     special case included) and is itself golden-tested against synthetic
//!     policies so every one of the nine reasons + both decisions is exercised;
//!   - the live decision functions are then proven equal to that recompute fed
//!     the PUBLIC snapshot over a wide length grid (holds on any machine);
//!   - plus machine-independent structural laws the dispatch relies on:
//!     convenience-fn == detail.decision, `is_fused` consistency, symmetry in
//!     lane order, reason <=> decision agreement, determinism, and stable
//!     pairwise-distinct reason labels.
//!
//! Repro: `cargo test --test raptorq_dual_kernel_decision_policy_conformance`

use asupersync::raptorq::gf256::{
    DualKernelDecision, DualKernelDecisionDetail, DualKernelDecisionReason, DualKernelMode,
    DualKernelModeFallbackReason, DualKernelPolicySnapshot, dual_addmul_kernel_decision,
    dual_addmul_kernel_decision_detail, dual_kernel_policy_snapshot, dual_mul_kernel_decision,
    dual_mul_kernel_decision_detail,
};

use DualKernelDecision::{Fused, Sequential};
use DualKernelDecisionReason as Reason;

/// A wide, magnitude-diverse grid of lane lengths: zeros, small/odd/power-of-two
/// boundaries, mid sizes, and the saturating extremes. The recompute differential
/// must agree on every pair regardless of the active window.
const LENS: &[usize] = &[
    0,
    1,
    2,
    3,
    4,
    7,
    8,
    15,
    16,
    17,
    31,
    32,
    33,
    63,
    64,
    65,
    100,
    127,
    128,
    129,
    255,
    256,
    257,
    1000,
    4096,
    65_535,
    65_536,
    usize::MAX - 1,
    usize::MAX,
];

/// The gate parameters the production policy carries, lifted out of the public
/// snapshot so the recompute below stays decoupled from concrete defaults.
#[derive(Clone, Copy)]
struct GateParams {
    mode: DualKernelMode,
    mul_min_total: usize,
    mul_max_total: usize,
    addmul_min_total: usize,
    addmul_max_total: usize,
    addmul_min_lane: usize,
    max_lane_ratio: usize,
}

impl GateParams {
    fn from_snapshot(s: &DualKernelPolicySnapshot) -> Self {
        Self {
            mode: s.mode,
            mul_min_total: s.mul_min_total,
            mul_max_total: s.mul_max_total,
            addmul_min_total: s.addmul_min_total,
            addmul_max_total: s.addmul_max_total,
            addmul_min_lane: s.addmul_min_lane,
            max_lane_ratio: s.max_lane_ratio,
        }
    }
}

/// Mirror of `window_gate_reason`: the `usize::MAX`/`0` sentinel disables the
/// window before the `min > max` invalid-config check.
fn window_reason(total: usize, min_total: usize, max_total: usize) -> Option<Reason> {
    if min_total == usize::MAX && max_total == 0 {
        Some(Reason::WindowDisabledByProfile)
    } else if min_total > max_total {
        Some(Reason::InvalidWindowConfiguration)
    } else if total < min_total {
        Some(Reason::TotalBelowWindow)
    } else if total > max_total {
        Some(Reason::TotalAboveWindow)
    } else {
        None
    }
}

/// Mirror of `lane_ratio_within`: requires a non-empty short lane whose length,
/// scaled (saturating) by the ratio, still covers the long lane.
fn lane_ratio_within(len_a: usize, len_b: usize, max_ratio: usize) -> bool {
    let lo = len_a.min(len_b);
    let hi = len_a.max(len_b);
    lo > 0 && lo.saturating_mul(max_ratio) >= hi
}

/// Pure recompute of the dual-kernel decision for a lane pair under explicit
/// gate parameters. `is_addmul` selects the addmul window + the extra
/// lane-floor gate that the mul path omits. Mirrors `gf256.rs` gate ordering.
fn expected(
    p: &GateParams,
    is_addmul: bool,
    len_a: usize,
    len_b: usize,
) -> DualKernelDecisionDetail {
    let (decision, reason) = match p.mode {
        DualKernelMode::Sequential => (Sequential, Reason::ForcedSequentialMode),
        DualKernelMode::Fused => (Fused, Reason::ForcedFusedMode),
        DualKernelMode::Auto => {
            let total = len_a.saturating_add(len_b);
            let (min_total, max_total) = if is_addmul {
                (p.addmul_min_total, p.addmul_max_total)
            } else {
                (p.mul_min_total, p.mul_max_total)
            };
            if let Some(reason) = window_reason(total, min_total, max_total) {
                (Sequential, reason)
            } else if is_addmul && len_a.min(len_b) < p.addmul_min_lane {
                (Sequential, Reason::LaneBelowMinFloor)
            } else if !lane_ratio_within(len_a, len_b, p.max_lane_ratio) {
                (Sequential, Reason::LaneRatioExceeded)
            } else {
                (Fused, Reason::EligibleAutoWindow)
            }
        }
    };
    DualKernelDecisionDetail { decision, reason }
}

/// Every `(reason, label)` pair the structured-log surface emits, kept here as a
/// golden so a refactor of any `as_str` body is caught.
const REASON_LABELS: &[(DualKernelDecisionReason, &str)] = &[
    (Reason::ForcedSequentialMode, "forced-sequential-mode"),
    (Reason::ForcedFusedMode, "forced-fused-mode"),
    (
        Reason::WindowDisabledByProfile,
        "window-disabled-by-profile",
    ),
    (
        Reason::InvalidWindowConfiguration,
        "invalid-window-configuration",
    ),
    (Reason::TotalBelowWindow, "total-below-window"),
    (Reason::TotalAboveWindow, "total-above-window"),
    (Reason::LaneBelowMinFloor, "lane-below-min-floor"),
    (Reason::LaneRatioExceeded, "lane-ratio-exceeded"),
    (Reason::EligibleAutoWindow, "eligible-auto-window"),
];

// ---------------------------------------------------------------------------
// 1. The recompute oracle itself models the documented gate ordering.
// ---------------------------------------------------------------------------

#[test]
fn recompute_oracle_mirrors_documented_gate_ordering() {
    // A sane, permissive auto window used as the base for the gate scenarios.
    let auto = GateParams {
        mode: DualKernelMode::Auto,
        mul_min_total: 0,
        mul_max_total: 100_000,
        addmul_min_total: 0,
        addmul_max_total: 100_000,
        addmul_min_lane: 0,
        max_lane_ratio: 1_000,
    };

    // Forced modes ignore the lengths entirely.
    for mode in [DualKernelMode::Sequential, DualKernelMode::Fused] {
        let p = GateParams { mode, ..auto };
        let (want_decision, want_reason) = match mode {
            DualKernelMode::Sequential => (Sequential, Reason::ForcedSequentialMode),
            DualKernelMode::Fused => (Fused, Reason::ForcedFusedMode),
            DualKernelMode::Auto => unreachable!(),
        };
        for &(a, b) in &[(0usize, 0usize), (7, 9), (40_000, 1)] {
            let got = expected(&p, false, a, b);
            assert_eq!(
                got.decision, want_decision,
                "forced mode {mode:?} ({a},{b})"
            );
            assert_eq!(got.reason, want_reason, "forced mode {mode:?} ({a},{b})");
        }
    }

    // Window disabled by profile (sentinel) — checked before invalid-config.
    let disabled = GateParams {
        mul_min_total: usize::MAX,
        mul_max_total: 0,
        addmul_min_total: usize::MAX,
        addmul_max_total: 0,
        ..auto
    };
    assert_eq!(
        expected(&disabled, false, 50, 50).reason,
        Reason::WindowDisabledByProfile
    );
    assert_eq!(expected(&disabled, false, 50, 50).decision, Sequential);

    // Invalid window configuration (min > max but not the disabled sentinel).
    let invalid = GateParams {
        mul_min_total: 100,
        mul_max_total: 50,
        ..auto
    };
    assert_eq!(
        expected(&invalid, false, 60, 0).reason,
        Reason::InvalidWindowConfiguration
    );

    // Below / above the window.
    let windowed = GateParams {
        mul_min_total: 64,
        mul_max_total: 128,
        ..auto
    };
    assert_eq!(
        expected(&windowed, false, 10, 10).reason,
        Reason::TotalBelowWindow
    );
    assert_eq!(
        expected(&windowed, false, 300, 300).reason,
        Reason::TotalAboveWindow
    );
    assert_eq!(
        expected(&windowed, false, 50, 50).reason,
        Reason::EligibleAutoWindow
    );
    assert_eq!(expected(&windowed, false, 50, 50).decision, Fused);

    // Lane-floor gate is ADDMUL-ONLY: identical lanes in-window with a tiny
    // short lane trip the floor for addmul but the mul path skips it.
    let floored = GateParams {
        addmul_min_total: 0,
        addmul_max_total: 100_000,
        addmul_min_lane: 32,
        max_lane_ratio: 1_000,
        mul_min_total: 0,
        mul_max_total: 100_000,
        mode: DualKernelMode::Auto,
    };
    assert_eq!(
        expected(&floored, true, 16, 16).reason,
        Reason::LaneBelowMinFloor,
        "addmul enforces the lane floor"
    );
    assert_eq!(
        expected(&floored, false, 16, 16).reason,
        Reason::EligibleAutoWindow,
        "mul has no lane floor — same lanes are eligible"
    );

    // Lane-ratio gate: a lopsided pair within the window but beyond the ratio.
    let ratio = GateParams {
        mul_min_total: 0,
        mul_max_total: 100_000,
        addmul_min_lane: 0,
        max_lane_ratio: 2,
        ..auto
    };
    assert_eq!(
        expected(&ratio, false, 1, 100).reason,
        Reason::LaneRatioExceeded
    );
    assert_eq!(expected(&ratio, false, 1, 100).decision, Sequential);
    // A zero short lane also fails the ratio (lo == 0).
    assert_eq!(
        expected(&ratio, false, 0, 5).reason,
        Reason::LaneRatioExceeded
    );
    // Balanced lanes within the ratio are eligible.
    assert_eq!(
        expected(&ratio, false, 10, 10).reason,
        Reason::EligibleAutoWindow
    );
}

// ---------------------------------------------------------------------------
// 2/3. Live decision functions equal the recompute fed the public snapshot.
// ---------------------------------------------------------------------------

#[test]
fn mul_decision_matches_active_policy_recompute() {
    let params = GateParams::from_snapshot(&dual_kernel_policy_snapshot());
    for &a in LENS {
        for &b in LENS {
            let got = dual_mul_kernel_decision_detail(a, b);
            let want = expected(&params, false, a, b);
            assert_eq!(got, want, "dual_mul decision mismatch at ({a},{b})");
        }
    }
}

#[test]
fn addmul_decision_matches_active_policy_recompute() {
    let params = GateParams::from_snapshot(&dual_kernel_policy_snapshot());
    for &a in LENS {
        for &b in LENS {
            let got = dual_addmul_kernel_decision_detail(a, b);
            let want = expected(&params, true, a, b);
            assert_eq!(got, want, "dual_addmul decision mismatch at ({a},{b})");
        }
    }
}

// ---------------------------------------------------------------------------
// 4. Machine-independent structural laws of the public surface.
// ---------------------------------------------------------------------------

#[test]
fn convenience_decision_agrees_with_detail_and_is_fused_helpers() {
    for &a in LENS {
        for &b in LENS {
            let mul_detail = dual_mul_kernel_decision_detail(a, b);
            let mul_decision = dual_mul_kernel_decision(a, b);
            assert_eq!(
                mul_decision, mul_detail.decision,
                "mul convenience fn must equal detail.decision at ({a},{b})"
            );
            // `is_fused` on both the decision and the detail must agree with the
            // structural `== Fused` check.
            assert_eq!(mul_decision.is_fused(), mul_decision == Fused);
            assert_eq!(mul_detail.is_fused(), mul_detail.decision == Fused);
            assert_eq!(mul_detail.is_fused(), mul_decision.is_fused());

            let addmul_detail = dual_addmul_kernel_decision_detail(a, b);
            let addmul_decision = dual_addmul_kernel_decision(a, b);
            assert_eq!(
                addmul_decision, addmul_detail.decision,
                "addmul convenience fn must equal detail.decision at ({a},{b})"
            );
            assert_eq!(addmul_decision.is_fused(), addmul_decision == Fused);
            assert_eq!(addmul_detail.is_fused(), addmul_detail.decision == Fused);
        }
    }
}

#[test]
fn decisions_are_symmetric_in_lane_order() {
    // Every gate (saturating total, min/max lane floor, min/max ratio) is
    // symmetric in the two lane lengths, so swapping the arguments must produce
    // a byte-identical decision detail.
    for &a in LENS {
        for &b in LENS {
            assert_eq!(
                dual_mul_kernel_decision_detail(a, b),
                dual_mul_kernel_decision_detail(b, a),
                "mul decision not symmetric for ({a},{b})"
            );
            assert_eq!(
                dual_addmul_kernel_decision_detail(a, b),
                dual_addmul_kernel_decision_detail(b, a),
                "addmul decision not symmetric for ({a},{b})"
            );
        }
    }
}

#[test]
fn reason_determines_decision() {
    // Fused is selected exactly when the reason is an eligible/forced-fused
    // label; every other reason forces Sequential. This binds the two fields of
    // the detail so a future reason cannot be emitted with the wrong decision.
    let fused_reasons = [Reason::EligibleAutoWindow, Reason::ForcedFusedMode];
    for &a in LENS {
        for &b in LENS {
            for detail in [
                dual_mul_kernel_decision_detail(a, b),
                dual_addmul_kernel_decision_detail(a, b),
            ] {
                let reason_is_fused = fused_reasons.contains(&detail.reason);
                assert_eq!(
                    detail.decision == Fused,
                    reason_is_fused,
                    "reason {:?} <=> Fused mismatch at ({a},{b})",
                    detail.reason
                );
            }
        }
    }
}

#[test]
fn decisions_and_snapshot_are_deterministic() {
    let snap = dual_kernel_policy_snapshot();
    for _ in 0..3 {
        assert_eq!(
            snap,
            dual_kernel_policy_snapshot(),
            "snapshot must be stable"
        );
    }
    for &a in &[0usize, 1, 16, 64, 4096, usize::MAX] {
        for &b in &[0usize, 1, 16, 64, 4096, usize::MAX] {
            let mul = dual_mul_kernel_decision_detail(a, b);
            let addmul = dual_addmul_kernel_decision_detail(a, b);
            for _ in 0..3 {
                assert_eq!(mul, dual_mul_kernel_decision_detail(a, b));
                assert_eq!(addmul, dual_addmul_kernel_decision_detail(a, b));
            }
        }
    }
}

#[test]
fn reason_labels_are_stable_and_pairwise_distinct() {
    use std::collections::BTreeSet;

    let mut seen = BTreeSet::new();
    for &(reason, label) in REASON_LABELS {
        assert_eq!(reason.as_str(), label, "reason label drift for {reason:?}");
        assert!(seen.insert(label), "duplicate reason label {label:?}");
    }
    assert_eq!(seen.len(), REASON_LABELS.len(), "all nine labels distinct");

    // The mode-fallback reason shares the structured-log namespace and must not
    // collide with any decision-reason label.
    let fallback = DualKernelModeFallbackReason::UnknownRequestedMode.as_str();
    assert_eq!(fallback, "unknown-requested-mode");
    assert!(
        !seen.contains(fallback),
        "fallback label collides with a decision reason"
    );
}
