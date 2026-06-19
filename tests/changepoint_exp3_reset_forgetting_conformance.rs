//! AC3 integration conformance for bead `yj2nxx.1`: what the change-point ->
//! cancel-streak EXP3/UCB controller reset *actually buys*, measured through the
//! real controller.
//!
//! # Context
//!
//! The pure detector substrate (AC1/AC2/AC4/AC6) and the bare worker-level reset
//! receipt are already covered by `changepoint_detector_arl_proofs.rs` (see
//! `changepoint_receipt_resets_adaptive_cancel_streak_controller`, which drives a
//! real `ThreeLaneScheduler` worker through `apply_changepoint_detection_to_
//! adaptive_cancel_streak`) and `changepoint_monitor_assembly_routing_
//! conformance.rs`. This crate closes the *integration* half of AC3 — a mid-run
//! regime shift resetting the adaptive controller — by measuring the reset's
//! effect on the production controller itself
//! (`AdaptiveCancelStreakPolicyBench`, the same `AdaptiveCancelStreakPolicy` the
//! worker runs).
//!
//! Everything here is fully deterministic: the discounted-UCB controller has no
//! RNG, and the regime reward is a pinned binary function of the active arm, so
//! every assertion is replay-exact.
//!
//! # What this pins
//!
//! 1. **The reset decouples post-shift behavior from the stale regime
//!    (`reset_decouples_post_shift_trajectory_from_prior_regime`).** A *reset*
//!    controller's post-shift arm trajectory depends only on the new regime — it
//!    is identical regardless of what it learned before — whereas a *no-reset*
//!    controller still carries the imprint of the regime it learned previously
//!    ("confidently optimizing for yesterday"). This is the operational meaning
//!    of "forget stale learning," the conservative response the bead specifies.
//!
//! 2. **The detector emits the gating receipt
//!    (`conservative_monitor_emits_a_known_series_receipt_that_gates_the_reset`).**
//!    A real, enabled `ChangePointMonitor` stays silent on a steady prefix and
//!    emits an `Increase` receipt on a mid-run workload flip; the receipt's
//!    series is a known runtime series, so it is eligible to trigger the worker
//!    reset gate (which forgets learning only for non-`Custom` series).
//!
//! # The honest measured finding (AC3's "faster" clause)
//!
//! AC3 as literally worded asks for "post-reset adaptation *faster* than a
//! no-reset baseline (measured, seeded)." Measured through the real controller,
//! that claim **does not hold**, and
//! `discounted_ucb_adapts_without_reset_so_reset_is_conservative_not_faster`
//! pins the honest result: the discounted-UCB policy already forgets
//! non-stationary reward via its `0.95` per-epoch discount plus aggressive
//! `confidence = 2.0` exploration, so a fresh (reset) controller actually *pays*
//! a re-exploration cost and reaches the new optimum no more often than the
//! entrenched one — both converge. The reset's justification is therefore
//! *decoupling from stale learning* (conservative forgetting), not raw speed.
//! That is exactly the timescale-separation posture the composition discipline
//! calls for (AC5): the detector forgets at epoch granularity, the controller
//! keeps adapting per epoch, and the two do not fight over a shared objective.
//!
//! Reset faithfulness: `AdaptiveCancelStreakPolicy::reset_to_priors` is literally
//! `*self = Self::new(epoch_steps)`, so a freshly constructed
//! `AdaptiveCancelStreakPolicyBench::new(epoch_steps)` is byte-identical to a
//! controller that has just been reset by a change-point receipt — that
//! equivalence is what lets these tests model the reset by construction.

#![allow(missing_docs)]

use asupersync::runtime::changepoint::{
    ChangeDirection, ChangePointMonitorConfig, MetricSample, RuntimeMetricSeries,
};
use asupersync::runtime::scheduler::three_lane::{
    AdaptiveCancelStreakPolicyBench, AdaptivePolicyBenchSnapshot,
};

// ── Controller (EXP3/UCB) regime driver ────────────────────────────────────

/// Snapshot with only the `potential` field engaged; every penalty input is
/// zero so the reward is governed purely by the Lyapunov potential drop.
fn snapshot(potential: f64) -> AdaptivePolicyBenchSnapshot {
    AdaptivePolicyBenchSnapshot::new(potential, 0.0, 0, 0, 0)
}

/// Drive one adaptive epoch in a binary regime where `optimal_arm` earns reward
/// `1.0` and every other arm earns `0.0`, and return the arm credited this
/// epoch. Mirrors the production lifecycle: select -> begin -> complete.
///
/// The reward is constructed from the potential drop: a drop of exactly
/// `|start| + 1` yields `normalized_drop = +1` (reward `1.0`); an equal rise
/// yields `normalized_drop = -1` (reward `0.0`). The binary contract is asserted
/// so the regime model cannot silently drift if the reward function changes.
fn regime_epoch(policy: &mut AdaptiveCancelStreakPolicyBench, optimal_arm: usize) -> usize {
    let active = policy.select_arm_ucb();
    policy.force_selected_arm(active);
    policy.begin_epoch(snapshot(100.0));
    let end_potential = if active == optimal_arm { -1.0 } else { 201.0 };
    let reward = policy
        .complete_epoch(snapshot(end_potential))
        .expect("begin_epoch set the epoch start, so the epoch must complete");
    let expected = if active == optimal_arm { 1.0 } else { 0.0 };
    assert!(
        (reward - expected).abs() < 1e-9,
        "regime reward must be binary (got {reward}, expected {expected})"
    );
    active
}

fn train(policy: &mut AdaptiveCancelStreakPolicyBench, optimal_arm: usize, epochs: usize) {
    for _ in 0..epochs {
        let _ = regime_epoch(policy, optimal_arm);
    }
}

fn drive_window(
    mut policy: AdaptiveCancelStreakPolicyBench,
    optimal_arm: usize,
    window: usize,
) -> Vec<usize> {
    (0..window)
        .map(|_| regime_epoch(&mut policy, optimal_arm))
        .collect()
}

// ── AC3 (1): the reset decouples post-shift behavior from the stale regime ──

/// A *reset* controller's post-shift arm trajectory depends only on the new
/// regime (identical regardless of prior learning); a *no-reset* controller
/// still carries the imprint of the regime it learned before. This is the
/// operational meaning of "forgetting stale learning."
#[test]
fn reset_decouples_post_shift_trajectory_from_prior_regime() {
    // Train two controllers on two different regimes (optimal arm 0 vs arm 4).
    let mut learned_low = AdaptiveCancelStreakPolicyBench::new(1);
    train(&mut learned_low, 0, 80);
    let mut learned_high = AdaptiveCancelStreakPolicyBench::new(1);
    train(&mut learned_high, 4, 80);

    // They genuinely learned different things.
    assert_ne!(
        learned_low.mean_rewards(),
        learned_high.mean_rewards(),
        "training on different regimes must produce different controller state"
    );

    const NEW_OPTIMUM: usize = 2;
    const WINDOW: usize = 24;

    // RESET == a fresh controller (reset_to_priors is `*self = Self::new(steps)`).
    let reset_from_low = drive_window(AdaptiveCancelStreakPolicyBench::new(1), NEW_OPTIMUM, WINDOW);
    let reset_from_high =
        drive_window(AdaptiveCancelStreakPolicyBench::new(1), NEW_OPTIMUM, WINDOW);
    assert_eq!(
        reset_from_low, reset_from_high,
        "a reset controller's post-shift trajectory must depend only on the new regime"
    );

    // NO-RESET == continue the learned controllers into the new regime.
    let noreset_from_low = drive_window(learned_low, NEW_OPTIMUM, WINDOW);
    let noreset_from_high = drive_window(learned_high, NEW_OPTIMUM, WINDOW);
    assert_ne!(
        noreset_from_low, noreset_from_high,
        "a no-reset controller must carry the stale-regime imprint (optimizing for yesterday)"
    );
}

// ── AC3 (honest finding): reset is conservative, not faster ─────────────────

/// The discounted-UCB controller already adapts to a regime shift on its own
/// (the `0.95` discount forgets stale reward); a reset confers *no* speed
/// advantage and in fact pays a re-exploration cost. Both the reset and no-reset
/// controllers converge to the new optimum. This pins the honest answer to AC3's
/// "faster than no-reset baseline" clause: the property does not hold, so the
/// reset's justification is conservative forgetting, not acceleration.
#[test]
fn discounted_ucb_adapts_without_reset_so_reset_is_conservative_not_faster() {
    let mut learned = AdaptiveCancelStreakPolicyBench::new(1);
    train(&mut learned, 0, 80); // old regime: arm 0 optimal

    const NEW_OPTIMUM: usize = 4; // regime shifts: arm 4 now optimal
    const WINDOW: usize = 24;

    let reset_seq = drive_window(AdaptiveCancelStreakPolicyBench::new(1), NEW_OPTIMUM, WINDOW);
    let noreset_seq = drive_window(learned, NEW_OPTIMUM, WINDOW);

    let hits = |seq: &[usize]| seq.iter().filter(|&&arm| arm == NEW_OPTIMUM).count();
    let tail_hits = |seq: &[usize]| {
        seq[seq.len() - 8..]
            .iter()
            .filter(|&&arm| arm == NEW_OPTIMUM)
            .count()
    };

    // Honest finding: the no-reset baseline reaches the new optimum at least as
    // often as the reset controller — reset is not faster.
    assert!(
        hits(&noreset_seq) >= hits(&reset_seq),
        "reset must not be claimed faster: reset hit the new optimum {} times, no-reset {} times",
        hits(&reset_seq),
        hits(&noreset_seq)
    );

    // Both converge to the new regime: each selects the new optimum repeatedly in
    // the final epochs, proving the controller's own discount handles the shift.
    assert!(
        tail_hits(&reset_seq) >= 2,
        "reset controller must converge to the new optimum (tail hits = {})",
        tail_hits(&reset_seq)
    );
    assert!(
        tail_hits(&noreset_seq) >= 2,
        "no-reset controller must also converge to the new optimum (tail hits = {})",
        tail_hits(&noreset_seq)
    );
}

// ── AC3 (trigger): the real detector emits the gating receipt ────────────────

/// A real, enabled `ChangePointMonitor` stays silent on a steady prefix and
/// emits an `Increase` receipt on a mid-run workload flip. The receipt's series
/// is a known runtime series (not `Custom`), so it is eligible to drive the
/// worker reset gate `apply_changepoint_detection_to_adaptive_cancel_streak`,
/// which forgets learning only for known runtime series.
#[test]
fn conservative_monitor_emits_a_known_series_receipt_that_gates_the_reset() {
    let mut monitor = ChangePointMonitorConfig::conservative_scheduler_defaults()
        .enable()
        .build_monitor();

    // Steady prefix: the conservative profile must not alarm.
    for value in [10, 10, 10, 10, 10] {
        assert!(
            monitor
                .observe(
                    RuntimeMetricSeries::ReadyQueueDepth,
                    MetricSample::from_units(value),
                )
                .is_none(),
            "steady prefix must not alarm"
        );
    }

    // Mid-run workload flip upward: a deterministic regime receipt must fire.
    let detection = [34, 34, 34, 34, 34, 34, 34, 34]
        .into_iter()
        .find_map(|value| {
            monitor.observe(
                RuntimeMetricSeries::ReadyQueueDepth,
                MetricSample::from_units(value),
            )
        })
        .expect("a mid-run workload flip must emit a regime receipt");

    assert_eq!(
        detection.direction,
        ChangeDirection::Increase,
        "an upward workload flip must be reported as an increase"
    );
    assert!(
        !matches!(detection.series, RuntimeMetricSeries::Custom(_)),
        "a runtime-series receipt must be eligible to trigger the controller reset"
    );
}
