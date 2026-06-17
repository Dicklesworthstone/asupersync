//! Integration proof for the managed pool-sizing controller, the advisory
//! divergence detector, and the galaxy-brain transparency card
//! (br-asupersync-adaptive-control-plane-yj2nxx.2).
//!
//! These exercise the public `asupersync::runtime::pool_sizing` surface end to
//! end. They live as a standalone integration test (one small crate linking the
//! lib in non-test mode) so the proof is immune to unrelated peer `#[cfg(test)]`
//! breakage in the shared tree, which reds `cargo test --lib` tree-wide.
//!
//! Coverage maps to the bead's acceptance criteria:
//!   * AC2 — advisory mode warns on deliberate undersizing, never resizes.
//!   * AC3 — managed mode follows a load ramp within bounds, action count bounded.
//!   * AC4 — deterministic lab replay: identical inputs => identical trajectory.
//!   * AC5 — configured floor/ceiling always win over the recommendation.
//!   * AC6 — galaxy-brain card substitutes the live values.
//!   * AC7 — a regime reset clears the estimate without resizing the pool.

use asupersync::runtime::pool_sizing::{
    DEFAULT_DIVERGENCE_WARN_BPS, ManagedPoolSizingController, PoolSizingAction, PoolSizingBounds,
    PoolSizingDivergenceDirection, PoolSizingMode, PoolSizingObservation, PoolSizingPolicy,
    PoolSizingTarget, pool_sizing_divergence,
};

/// One-second observation window with `arrivals/sec` arrivals and a fixed mean
/// service time, so the EWMA tracks the requested load directly.
fn window(arrivals_per_second: u64, service_micros: u64) -> PoolSizingObservation {
    let total_service = u128::from(arrivals_per_second) * u128::from(service_micros);
    PoolSizingObservation::new(
        1_000_000,
        arrivals_per_second,
        arrivals_per_second,
        total_service,
        total_service * u128::from(service_micros),
    )
}

#[test]
fn ac2_advisory_mode_warns_on_undersizing_without_resizing() {
    let policy = PoolSizingPolicy::advisory(PoolSizingBounds::new(1, 32));
    let mut controller = ManagedPoolSizingController::new(policy, 1_000_000, 2);
    assert_eq!(controller.mode(), PoolSizingMode::Advisory);

    let decision = controller.observe(window(40, 500_000), 1);
    assert_eq!(
        decision.action,
        PoolSizingAction::ObserveOnly,
        "advisory mode must never resize"
    );
    assert_eq!(
        controller.current_size(),
        2,
        "advisory mode left the pool size alone"
    );

    let divergence = controller
        .divergence()
        .expect("a 2-worker pool under R=20 load must diverge >=2x");
    assert_eq!(
        divergence.direction,
        PoolSizingDivergenceDirection::Undersized
    );
    assert!(divergence.factor_bps >= DEFAULT_DIVERGENCE_WARN_BPS);
    assert!(divergence.recommended_size >= 2 * divergence.actual_size);
}

#[test]
fn ac2_divergence_is_silent_at_the_recommended_size() {
    // Drive a managed controller to convergence under a steady load, then build
    // an advisory controller already sitting at that converged size: it must not
    // warn, because it matches the recommendation.
    let bounds = PoolSizingBounds::new(1, 64);
    let target = PoolSizingTarget::MaxWaitProbabilityPpm(100_000);
    let mut probe =
        ManagedPoolSizingController::new(PoolSizingPolicy::managed(bounds, target), 1_000_000, 1);
    for epoch in 1..=6 {
        probe.observe(window(16, 500_000), epoch);
    }
    let converged = probe.current_size();

    let mut at_target =
        ManagedPoolSizingController::new(PoolSizingPolicy::advisory(bounds), 1_000_000, converged);
    at_target.observe(window(16, 500_000), 1);
    assert_eq!(
        at_target.divergence(),
        None,
        "a pool already at the recommended size of {converged} must not warn"
    );
}

#[test]
fn ac3_managed_mode_follows_ramp_within_bounds_no_flap() {
    let policy = PoolSizingPolicy::managed(
        PoolSizingBounds::new(1, 32),
        PoolSizingTarget::MaxWaitProbabilityPpm(100_000),
    );
    let mut controller = ManagedPoolSizingController::new(policy, 1_000_000, 1);

    let ramp = [4_u64, 8, 12, 16, 20, 20, 20, 20];
    let mut sizes = Vec::new();
    for (i, arrivals) in ramp.iter().enumerate() {
        controller.observe(window(*arrivals, 500_000), (i as u64) + 1);
        let size = controller.current_size();
        assert!((1..=32).contains(&size), "size {size} stayed within bounds");
        sizes.push(size);
    }

    for pair in sizes.windows(2) {
        assert!(
            pair[1] >= pair[0],
            "managed size must not shrink during an up-ramp"
        );
    }
    assert!(*sizes.last().unwrap() > 1, "the pool scaled up under load");

    let resizes = controller.applied_resizes();
    // Steady load => no further action (hysteresis holds).
    controller.observe(window(20, 500_000), 100);
    controller.observe(window(20, 500_000), 101);
    assert_eq!(
        controller.applied_resizes(),
        resizes,
        "steady-state load must not flap the pool"
    );
    assert!(
        resizes <= ramp.len() as u64,
        "resize count {resizes} is bounded by the ramp length, no flapping"
    );
}

#[test]
fn ac4_managed_controller_is_deterministic_under_replay() {
    let policy = PoolSizingPolicy::managed(
        PoolSizingBounds::new(1, 32),
        PoolSizingTarget::MaxWaitProbabilityPpm(100_000),
    );
    let ramp = [3_u64, 9, 15, 21, 21, 21, 7, 7];
    let run = || {
        let mut controller = ManagedPoolSizingController::new(policy, 400_000, 1);
        let mut trace = Vec::new();
        for (i, arrivals) in ramp.iter().enumerate() {
            controller.observe(window(*arrivals, 400_000), (i as u64) + 1);
            trace.push(controller.current_size());
        }
        (
            trace,
            controller.applied_resizes(),
            controller.last_resize_epoch(),
        )
    };
    assert_eq!(run(), run(), "identical inputs must replay identically");
}

#[test]
fn ac5_floor_and_ceiling_always_win() {
    // Crushing load can never exceed the ceiling.
    let policy = PoolSizingPolicy::managed(
        PoolSizingBounds::new(4, 8),
        PoolSizingTarget::MaxWaitProbabilityPpm(10_000),
    );
    let mut hot = ManagedPoolSizingController::new(policy, 1_000_000, 4);
    for epoch in 1..=8 {
        hot.observe(window(5_000, 1_000_000), epoch);
        assert!(hot.current_size() <= 8, "ceiling must always win");
        assert!(hot.current_size() >= 4, "floor must always hold");
    }
    assert_eq!(hot.current_size(), 8, "saturating load pins at the ceiling");

    // A trickle of load can never drop below the floor.
    let mut cold = ManagedPoolSizingController::new(policy, 1_000_000, 8);
    for epoch in 1..=4 {
        cold.observe(window(1, 1_000), epoch);
        assert!(
            cold.current_size() >= 4,
            "floor must hold under near-idle load"
        );
    }
}

#[test]
fn ac6_galaxy_brain_card_names_the_inputs() {
    let policy = PoolSizingPolicy::advisory(PoolSizingBounds::new(1, 32));
    let mut controller = ManagedPoolSizingController::new(policy, 1_000_000, 1);
    controller.observe(window(16, 400_000), 1);
    let card = controller.explain();
    for needle in [
        "pool-sizing card",
        "offered load R =",
        "square-root staffing",
        "P(wait)",
        "utilization",
    ] {
        assert!(card.contains(needle), "card missing {needle:?}:\n{card}");
    }

    let cold = ManagedPoolSizingController::new(policy, 1_000_000, 1).explain();
    assert!(cold.contains("no observed load"), "cold-start card: {cold}");
}

#[test]
fn ac7_regime_reset_clears_estimate_without_resizing() {
    let policy = PoolSizingPolicy::managed(
        PoolSizingBounds::new(1, 32),
        PoolSizingTarget::MaxWaitProbabilityPpm(100_000),
    );
    let mut controller = ManagedPoolSizingController::new(policy, 1_000_000, 1);
    for epoch in 1..=4 {
        controller.observe(window(16, 500_000), epoch);
    }
    let size_before = controller.current_size();
    assert!(size_before > 1);

    controller.reset_estimator();
    assert_eq!(
        controller.estimate(),
        None,
        "reset clears the EWMA estimate"
    );
    assert_eq!(
        controller.current_size(),
        size_before,
        "a regime reset must not itself resize the pool"
    );
}

#[test]
fn divergence_free_function_matches_two_x_rule() {
    // 2x exactly trips; 1.5x does not.
    assert!(pool_sizing_divergence(8, 4, DEFAULT_DIVERGENCE_WARN_BPS).is_some());
    assert!(pool_sizing_divergence(4, 8, DEFAULT_DIVERGENCE_WARN_BPS).is_some());
    assert!(pool_sizing_divergence(6, 4, DEFAULT_DIVERGENCE_WARN_BPS).is_none());
    assert!(pool_sizing_divergence(7, 7, DEFAULT_DIVERGENCE_WARN_BPS).is_none());
}
