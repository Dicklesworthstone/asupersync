//! RaptorQ G7 governance decision-contract conformance.
//!
//! Bead bd-3uox5 (RAPTORQ-RFC6330). Pins the production governance-projection
//! surface in `raptorq::decision_contract` that had ZERO integration coverage:
//! `evaluate_governance`, `is_runtime_fallback_reason`, and the
//! `RaptorQDecisionContract::state_posterior_permille` posterior normalization.
//!
//! These are deterministic, ambient-free projections of a runtime snapshot onto
//! a fixed decision contract — exactly the "no hidden ambient behavior /
//! deterministic testing" surface the program cares about. The properties are
//! structural invariants and cross-function consistency relations, so no oracle
//! is needed:
//!   * the permille posterior is a probability distribution — it sums to exactly
//!     1000 and every component is in `[0, 1000]`, for ANY snapshot;
//!   * `confidence_score + uncertainty_score == 1000`;
//!   * `evaluate_governance(s)` equals `RaptorQDecisionContract::new().telemetry(s)`
//!     and is deterministic (same snapshot → byte-identical telemetry);
//!   * whenever the deterministic fallback fires, the emitted reason is a
//!     canonical runtime fallback reason (`is_runtime_fallback_reason` agrees),
//!     and `"none"` is never one;
//!   * the chosen action is always a member of the contract's action set.
//!
//! A seeded sweep drives a wide range of snapshots (including out-of-range
//! permille inputs that exercise the clamp, budget exhaustion, and the
//! `block_schur_loss == u32::MAX` "unavailable" sentinel).
//!
//! Repro: `cargo test -p asupersync --test raptorq_governance_contract_conformance`

use asupersync::raptorq::decision_contract::{
    G7_RUNTIME_FALLBACK_REASONS, GovernanceSnapshot, RaptorQDecisionContract, evaluate_governance,
    is_runtime_fallback_reason,
};

const ACTIONS: [&str; 4] = ["continue", "canary_hold", "rollback", "fallback"];

/// A representative grid of snapshots. Permille fields include 0, mid, the 1000
/// boundary, and 5000 (out of range → must be clamped). Losses span the trivial
/// and the `u32::MAX` "unavailable" sentinel.
fn snapshot_grid() -> Vec<GovernanceSnapshot> {
    let permille_vals = [0usize, 250, 500, 1000, 5000];
    let loss_vals = [0u32, 50, 250, u32::MAX];
    let mut out = Vec::new();
    // Drive each permille axis independently against a moving baseline so the
    // grid stays bounded while still covering extremes on every field.
    for (i, &p) in permille_vals.iter().enumerate() {
        for &budget in &[false, true] {
            for &bsl in &loss_vals {
                out.push(GovernanceSnapshot {
                    n_rows: 16 + i,
                    n_cols: 16 + i,
                    density_permille: p,
                    rank_deficit_permille: permille_vals[(i + 1) % permille_vals.len()],
                    inactivation_pressure_permille: permille_vals[(i + 2) % permille_vals.len()],
                    overhead_ratio_permille: permille_vals[(i + 3) % permille_vals.len()],
                    budget_exhausted: budget,
                    baseline_loss: loss_vals[i % loss_vals.len()],
                    high_support_loss: loss_vals[(i + 1) % loss_vals.len()],
                    block_schur_loss: bsl,
                });
            }
        }
    }
    out
}

#[test]
fn posterior_permille_is_a_normalized_distribution() {
    for s in snapshot_grid() {
        let posterior = RaptorQDecisionContract::state_posterior_permille(&s);

        // Every component in the canonical 0..=1000 range.
        for (idx, &p) in posterior.iter().enumerate() {
            assert!(
                p <= 1000,
                "posterior[{idx}] = {p} exceeds the 1000 permille scale (snapshot={s:?})"
            );
        }

        // Largest-remainder normalization must distribute EXACTLY 1000.
        let total: u32 = posterior.iter().map(|&p| u32::from(p)).sum();
        assert_eq!(
            total, 1000,
            "posterior must sum to exactly 1000 permille (got {total}, snapshot={s:?})"
        );
    }
}

#[test]
fn posterior_permille_is_deterministic() {
    for s in snapshot_grid() {
        let a = RaptorQDecisionContract::state_posterior_permille(&s);
        let b = RaptorQDecisionContract::state_posterior_permille(&s);
        assert_eq!(
            a, b,
            "state_posterior_permille not deterministic (snapshot={s:?})"
        );
    }
}

#[test]
fn evaluate_governance_equals_contract_telemetry_and_is_deterministic() {
    let contract = RaptorQDecisionContract::new();
    for s in snapshot_grid() {
        let via_free_fn = evaluate_governance(&s);
        let via_contract = contract.telemetry(&s);

        // The free function is exactly the canonical contract's telemetry.
        assert_eq!(
            via_free_fn, via_contract,
            "evaluate_governance != RaptorQDecisionContract::new().telemetry (snapshot={s:?})"
        );

        // Determinism: re-evaluating yields byte-identical telemetry.
        assert_eq!(
            via_free_fn,
            evaluate_governance(&s),
            "evaluate_governance not deterministic (snapshot={s:?})"
        );

        // The telemetry's posterior matches the standalone projection.
        assert_eq!(
            via_free_fn.state_posterior_permille,
            RaptorQDecisionContract::state_posterior_permille(&s),
            "telemetry posterior diverged from state_posterior_permille (snapshot={s:?})"
        );
    }
}

#[test]
fn confidence_and_uncertainty_partition_1000() {
    for s in snapshot_grid() {
        let t = evaluate_governance(&s);
        assert!(
            t.confidence_score <= 1000,
            "confidence out of range (snapshot={s:?})"
        );
        assert!(
            t.uncertainty_score <= 1000,
            "uncertainty out of range (snapshot={s:?})"
        );
        assert_eq!(
            u32::from(t.confidence_score) + u32::from(t.uncertainty_score),
            1000,
            "confidence + uncertainty must equal 1000 (snapshot={s:?})"
        );
    }
}

#[test]
fn chosen_action_is_in_the_action_set() {
    for s in snapshot_grid() {
        let t = evaluate_governance(&s);
        assert!(
            ACTIONS.contains(&t.chosen_action),
            "chosen_action {:?} is not a contract action (snapshot={s:?})",
            t.chosen_action
        );
    }
}

/// Cross-function consistency: whenever the deterministic fallback fires, the
/// emitted reason MUST be classifiable by `is_runtime_fallback_reason`, and the
/// non-fallback sentinel `"none"` must never classify as one.
#[test]
fn emitted_fallback_reason_agrees_with_runtime_classifier() {
    for s in snapshot_grid() {
        let t = evaluate_governance(&s);
        if t.deterministic_fallback_triggered {
            assert_ne!(
                t.deterministic_fallback_reason, "none",
                "fallback triggered but reason is \"none\" (snapshot={s:?})"
            );
            assert!(
                is_runtime_fallback_reason(t.deterministic_fallback_reason),
                "emitted fallback reason {:?} is not a runtime fallback reason (snapshot={s:?})",
                t.deterministic_fallback_reason
            );
        } else {
            assert_eq!(
                t.deterministic_fallback_reason, "none",
                "fallback not triggered but reason != \"none\" (snapshot={s:?})"
            );
        }
    }
}

/// `is_runtime_fallback_reason` exactly classifies the canonical set: every
/// registered reason is recognized, and obvious non-members are rejected.
#[test]
fn is_runtime_fallback_reason_classifies_canonical_set() {
    assert!(
        !G7_RUNTIME_FALLBACK_REASONS.is_empty(),
        "the canonical runtime fallback reason set must be non-empty"
    );
    for &reason in G7_RUNTIME_FALLBACK_REASONS {
        assert!(
            is_runtime_fallback_reason(reason),
            "registered reason {reason:?} must be recognized"
        );
        assert_ne!(
            reason, "none",
            "\"none\" must not be a runtime fallback reason"
        );
    }

    for junk in [
        "none",
        "",
        "continue",
        "rollback",
        "HEALTHY",
        "fallback_reason_unknown",
    ] {
        assert!(
            !is_runtime_fallback_reason(junk),
            "{junk:?} must not classify as a runtime fallback reason"
        );
    }
}
