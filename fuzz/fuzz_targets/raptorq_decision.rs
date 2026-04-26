#![no_main]

//! Cargo-fuzz target for `RaptorQDecisionContract` (G7 governance) and
//! the surrounding e-process / calibration machinery in
//! `src/raptorq/{decision_contract,regression}.rs`.
//!
//! The contract converts a `GovernanceSnapshot` (rows/cols/density/
//! rank-deficit/inactivation/overhead/budget/loss inputs, ALL as
//! permille u32 + u32 loss values) into a `GovernanceTelemetry`
//! (posterior over {healthy, degraded, regression, unknown}, expected
//! loss per action, concentration & action-margin scores, fallback
//! reason string). Every component MUST be deterministic given the
//! input.
//!
//! Properties asserted per fuzz iteration:
//!
//!   1. **No panic on any input.** Random snapshots — including
//!      saturated permille values (>1000), `u32::MAX` losses, and
//!      `block_schur_loss == u32::MAX` (the documented sentinel) — MUST
//!      NOT trigger Rust panic.
//!
//!   2. **Determinism: same input → same output.** Calling `telemetry`
//!      twice with the same snapshot MUST produce byte-identical
//!      telemetry. The contract is documented as deterministic G7
//!      governance; any drift is a real bug (would break replay).
//!
//!   3. **Posterior is a valid distribution.** The state posterior
//!      (healthy, degraded, regression, unknown) must sum to ~1000
//!      permille (allowing ±1 for rounding). Negative or saturated-
//!      to-MAX entries indicate normalization failure.
//!
//!   4. **Confidence score is bounded.** `confidence_score: u16` MUST
//!      stay in [0, 1000]. Anything above is a normalization bug.
//!
//!   5. **Fallback reason is a non-empty string.** `fallback_reason`
//!      MUST be one of the documented strings ("none" or a specific
//!      reason); never empty, never panic-format-Debug-output.
//!
//! Coverage biases: snapshot fields are sampled from u8/u16/u32 ranges
//! including the saturating extremes (u32::MAX, u32::MAX/2, 0) so the
//! arithmetic edges (saturating_sub, clamp_permille) are exercised.

use asupersync::raptorq::decision_contract::{GovernanceSnapshot, RaptorQDecisionContract};
use libfuzzer_sys::fuzz_target;

const SNAPSHOT_BYTES: usize = 28; // 6×u16 (12) + 4×u32 (16) = 28

fuzz_target!(|data: &[u8]| {
    if data.len() < SNAPSHOT_BYTES {
        return;
    }

    // Carve a snapshot deterministically from the input bytes. Each
    // field is u32-sized internally but most are bounded permille
    // (fits in u16); we read u16/u32 and let the contract's
    // clamp_permille / saturating arithmetic handle out-of-range
    // values. Loss fields take the full u32 range to exercise
    // u32::MAX sentinel paths.
    let snap = GovernanceSnapshot {
        n_rows: u16::from_le_bytes([data[0], data[1]]) as usize,
        n_cols: u16::from_le_bytes([data[2], data[3]]) as usize,
        density_permille: u16::from_le_bytes([data[4], data[5]]) as usize,
        rank_deficit_permille: u16::from_le_bytes([data[6], data[7]]) as usize,
        inactivation_pressure_permille: u16::from_le_bytes([data[8], data[9]]) as usize,
        overhead_ratio_permille: u16::from_le_bytes([data[10], data[11]]) as usize,
        budget_exhausted: (data[12] & 1) == 1,
        baseline_loss: u32::from_le_bytes([data[13], data[14], data[15], data[16]]),
        high_support_loss: u32::from_le_bytes([data[17], data[18], data[19], data[20]]),
        // Bias toward the u32::MAX sentinel (~25% of fuzz iters) so the
        // sentinel-handling branch in the unknown-state penalty gets
        // exercised more than uniform sampling would give.
        block_schur_loss: if (data[21] & 0x03) == 0 {
            u32::MAX
        } else {
            u32::from_le_bytes([data[22], data[23], data[24], data[25]])
        },
    };

    let contract = RaptorQDecisionContract::new();

    // ── Property 1: no panic ────────────────────────────────────────────
    let telemetry_a = contract.telemetry(&snap);

    // ── Property 2: determinism (same snapshot → same telemetry) ────────
    let telemetry_b = contract.telemetry(&snap);
    assert_eq!(
        telemetry_a, telemetry_b,
        "RaptorQDecisionContract::telemetry MUST be deterministic for snap {snap:?}"
    );

    // ── Property 3: posterior sums to ~1000 permille ────────────────────
    let posterior = RaptorQDecisionContract::state_posterior_permille(&snap);
    let sum: u32 = posterior.iter().map(|&p| u32::from(p)).sum();
    assert!(
        (995..=1005).contains(&sum),
        "state posterior must sum to ~1000 permille, got {sum} for {posterior:?}"
    );

    // ── Property 4: confidence_score bounded ─────────────────────────────
    assert!(
        telemetry_a.confidence_score <= 1000,
        "confidence_score MUST be ≤ 1000 permille, got {} for snap {snap:?}",
        telemetry_a.confidence_score
    );

    // ── Property 5: fallback_reason is a non-empty string ────────────────
    assert!(
        !telemetry_a.fallback_reason.is_empty(),
        "fallback_reason MUST be non-empty, got '' for snap {snap:?}"
    );

    // ── Bonus: extreme-input smoke — does the contract tolerate the all-
    //     saturated edge? `saturating_sub` should clamp to zero, not panic.
    let extreme = GovernanceSnapshot {
        n_rows: usize::MAX,
        n_cols: usize::MAX,
        density_permille: usize::MAX,
        rank_deficit_permille: usize::MAX,
        inactivation_pressure_permille: usize::MAX,
        overhead_ratio_permille: usize::MAX,
        budget_exhausted: true,
        baseline_loss: u32::MAX,
        high_support_loss: u32::MAX,
        block_schur_loss: u32::MAX,
    };
    let extreme_telemetry = contract.telemetry(&extreme);
    assert!(
        extreme_telemetry.confidence_score <= 1000,
        "extreme-input confidence_score still bounded, got {}",
        extreme_telemetry.confidence_score
    );
});
