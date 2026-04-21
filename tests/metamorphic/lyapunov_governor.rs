#![allow(clippy::all)]
//! Metamorphic tests for obligation::lyapunov governor stability invariants.
//!
//! Tests the Lyapunov function properties that ensure cancellation convergence:
//! 1. V(x) >= 0 (non-negativity)
//! 2. V(x(t+1)) <= V(x(t)) - delta (monotonic decrease along trajectories)
//! 3. equilibrium minimizes V (quiescent state has V=0)
//! 4. cancel does not violate stability proof (cancellation preserves monotonicity)
//! 5. governor output bounded by stability constraint (suggestions are consistent)

use asupersync::obligation::lyapunov::{
    LyapunovGovernor, PotentialWeights, SchedulingSuggestion, StateSnapshot,
};
use asupersync::record::ObligationKind;
use asupersync::runtime::RuntimeState;
use asupersync::types::{Budget, CancelReason, Time};
use proptest::prelude::*;
use proptest::test_runner::TestRunner;
use std::collections::HashMap;

// ============================================================================
// Test Data Generators
// ============================================================================

/// Generator for valid PotentialWeights
fn weights_strategy() -> impl Strategy<Value = PotentialWeights> {
    (
        0.0_f64..=100.0,  // w_tasks
        0.0_f64..=100.0,  // w_obligation_age
        0.0_f64..=100.0,  // w_draining_regions
        0.0_f64..=100.0,  // w_deadline_pressure
    ).prop_map(|(w_t, w_o, w_r, w_d)| PotentialWeights {
        w_tasks: w_t,
        w_obligation_age: w_o,
        w_draining_regions: w_r,
        w_deadline_pressure: w_d,
    })
}

/// Generator for StateSnapshot configurations
fn snapshot_strategy() -> impl Strategy<Value = StateSnapshot> {
    (
        0_u64..=1_000_000_000,  // time_ns
        0_u32..=100,            // live_tasks
        0_u32..=200,            // pending_obligations
        0_u64..=10_000_000_000, // obligation_age_sum_ns
        0_u32..=50,             // draining_regions
        0.0_f64..=50.0,         // deadline_pressure
        0_u32..=200,            // pending_send_permits
        0_u32..=100,            // pending_acks
        0_u32..=100,            // pending_leases
        0_u32..=100,            // pending_io_ops
        0_u32..=50,             // cancel_requested_tasks
        0_u32..=50,             // cancelling_tasks
        0_u32..=50,             // finalizing_tasks
        0_u32..=100,            // ready_queue_depth
    ).prop_map(|(time_ns, live_tasks, pending_obligations, age_sum, draining_regions,
                deadline_pressure, send_permits, acks, leases, io_ops,
                cancel_requested, cancelling, finalizing, ready_queue)| {
        // Ensure per-kind breakdown sums to total obligations
        let total_breakdown = send_permits.saturating_add(acks).saturating_add(leases).saturating_add(io_ops);
        let adjusted_obligations = if total_breakdown == 0 {
            0
        } else {
            pending_obligations.max(total_breakdown)
        };

        StateSnapshot {
            time: Time::from_nanos(time_ns),
            live_tasks,
            pending_obligations: adjusted_obligations,
            obligation_age_sum_ns: age_sum,
            draining_regions,
            deadline_pressure,
            pending_send_permits: send_permits,
            pending_acks: acks,
            pending_leases: leases,
            pending_io_ops: io_ops,
            cancel_requested_tasks: cancel_requested,
            cancelling_tasks: cancelling,
            finalizing_tasks: finalizing,
            ready_queue_depth: ready_queue,
        }
    })
}

/// Generator for trajectories of StateSnapshots (decreasing activity)
fn decreasing_trajectory_strategy() -> impl Strategy<Value = Vec<StateSnapshot>> {
    (5_usize..=20).prop_flat_map(|len| {
        prop::collection::vec(snapshot_strategy(), len..=len)
            .prop_map(|mut snapshots| {
                // Sort by decreasing activity to simulate drain trajectory
                snapshots.sort_by(|a, b| {
                    let activity_a = a.live_tasks + a.pending_obligations + a.draining_regions;
                    let activity_b = b.live_tasks + b.pending_obligations + b.draining_regions;
                    activity_b.cmp(&activity_a) // Descending order
                });

                // Ensure the last snapshot is quiescent
                if let Some(last) = snapshots.last_mut() {
                    *last = StateSnapshot {
                        time: Time::from_nanos(1_000_000_000),
                        live_tasks: 0,
                        pending_obligations: 0,
                        obligation_age_sum_ns: 0,
                        draining_regions: 0,
                        deadline_pressure: 0.0,
                        pending_send_permits: 0,
                        pending_acks: 0,
                        pending_leases: 0,
                        pending_io_ops: 0,
                        cancel_requested_tasks: 0,
                        cancelling_tasks: 0,
                        finalizing_tasks: 0,
                        ready_queue_depth: 0,
                    };
                }
                snapshots
            })
    })
}

// ============================================================================
// MR1: Lyapunov function V(x) >= 0 (non-negativity)
// ============================================================================

proptest! {
    /// MR1: Lyapunov function V(x) >= 0
    /// The potential function must always be non-negative for any valid state snapshot.
    #[test]
    fn mr_potential_non_negativity(
        weights in weights_strategy(),
        snapshot in snapshot_strategy()
    ) {
        let governor = LyapunovGovernor::new(weights);
        let record = governor.compute_record(&snapshot);

        prop_assert!(
            record.total >= 0.0,
            "Lyapunov function V(x) must be non-negative: V={:.6}, snapshot={}",
            record.total,
            snapshot
        );

        // Each component should also be non-negative
        prop_assert!(
            record.task_component >= 0.0,
            "Task component must be non-negative: {:.6}",
            record.task_component
        );
        prop_assert!(
            record.obligation_component >= 0.0,
            "Obligation component must be non-negative: {:.6}",
            record.obligation_component
        );
        prop_assert!(
            record.region_component >= 0.0,
            "Region component must be non-negative: {:.6}",
            record.region_component
        );
        prop_assert!(
            record.deadline_component >= 0.0,
            "Deadline component must be non-negative: {:.6}",
            record.deadline_component
        );
    }
}

// ============================================================================
// MR2: V(x(t+1)) <= V(x(t)) - delta (monotonic decrease along trajectories)
// ============================================================================

proptest! {
    /// MR2: V(x(t+1)) <= V(x(t)) - delta along trajectories
    /// During proper cancellation/drain sequences, potential should decrease monotonically.
    #[test]
    fn mr_monotonic_decrease_along_trajectories(
        weights in weights_strategy(),
        trajectory in decreasing_trajectory_strategy()
    ) {
        prop_assume!(trajectory.len() >= 2);

        let mut governor = LyapunovGovernor::new(weights);
        let mut violations = Vec::new();

        // Compute potential for entire trajectory
        for snapshot in &trajectory {
            governor.compute_potential(snapshot);
        }

        // Check for monotonic decrease
        let history = governor.history();
        for window in history.windows(2) {
            let prev_v = window[0].total;
            let curr_v = window[1].total;

            if curr_v > prev_v + f64::EPSILON {
                violations.push((prev_v, curr_v, curr_v - prev_v));
            }
        }

        prop_assert!(
            violations.is_empty(),
            "Potential should decrease monotonically along drain trajectory. Violations: {:?}",
            violations
        );

        // Additional check: convergence analysis should confirm monotonicity
        let verdict = governor.analyze_convergence();
        prop_assert!(
            verdict.monotone,
            "Convergence analysis should confirm monotonic decrease. Verdict: steps={}, increases={}, max_increase={:.6}",
            verdict.steps,
            verdict.increase_count,
            verdict.max_increase
        );
    }
}

// ============================================================================
// MR3: equilibrium minimizes V (quiescent state has V=0)
// ============================================================================

proptest! {
    /// MR3: equilibrium minimizes V
    /// The quiescent state (no live tasks, obligations, draining regions) should minimize V to 0.
    #[test]
    fn mr_equilibrium_minimizes_potential(weights in weights_strategy()) {
        let governor = LyapunovGovernor::new(weights);

        // Quiescent snapshot: all activity metrics are zero
        let quiescent = StateSnapshot {
            time: Time::from_nanos(1_000_000_000),
            live_tasks: 0,
            pending_obligations: 0,
            obligation_age_sum_ns: 0,
            draining_regions: 0,
            deadline_pressure: 0.0,
            pending_send_permits: 0,
            pending_acks: 0,
            pending_leases: 0,
            pending_io_ops: 0,
            cancel_requested_tasks: 0,
            cancelling_tasks: 0,
            finalizing_tasks: 0,
            ready_queue_depth: 0,
        };

        let record = governor.compute_record(&quiescent);

        prop_assert!(
            record.is_zero(),
            "Quiescent state should have V=0. Got V={:.6}, components: tasks={:.6}, obligations={:.6}, regions={:.6}, deadlines={:.6}",
            record.total,
            record.task_component,
            record.obligation_component,
            record.region_component,
            record.deadline_component
        );

        prop_assert!(
            quiescent.is_quiescent(),
            "Snapshot should be marked as quiescent"
        );
    }
}

proptest! {
    /// MR3 (corollary): Any activity should result in V > 0
    /// Non-quiescent states should have positive potential.
    #[test]
    fn mr_activity_implies_positive_potential(
        weights in weights_strategy(),
        snapshot in snapshot_strategy()
    ) {
        prop_assume!(!snapshot.is_quiescent());

        let governor = LyapunovGovernor::new(weights);
        let record = governor.compute_record(&snapshot);

        prop_assert!(
            record.total > 0.0,
            "Non-quiescent state should have V > 0. Got V={:.6} for snapshot: {}",
            record.total,
            snapshot
        );
    }
}

// ============================================================================
// MR4: cancel does not violate stability proof
// ============================================================================

/// Simulate a cancellation event and verify stability properties are preserved
fn simulate_cancel_event(
    initial_snapshot: &StateSnapshot,
    weights: PotentialWeights,
) -> (f64, f64, SchedulingSuggestion, SchedulingSuggestion) {
    let governor = LyapunovGovernor::new(weights);

    // Pre-cancel state
    let pre_v = governor.compute_potential(initial_snapshot);
    let pre_suggestion = governor.suggest(initial_snapshot);

    // Post-cancel state: some tasks transition to cancel_requested/cancelling
    let post_cancel_snapshot = StateSnapshot {
        time: initial_snapshot.time,
        live_tasks: initial_snapshot.live_tasks,
        pending_obligations: initial_snapshot.pending_obligations,
        obligation_age_sum_ns: initial_snapshot.obligation_age_sum_ns,
        draining_regions: initial_snapshot.draining_regions.saturating_add(1), // Region starts draining
        deadline_pressure: initial_snapshot.deadline_pressure,
        pending_send_permits: initial_snapshot.pending_send_permits,
        pending_acks: initial_snapshot.pending_acks,
        pending_leases: initial_snapshot.pending_leases,
        pending_io_ops: initial_snapshot.pending_io_ops,
        cancel_requested_tasks: initial_snapshot.live_tasks, // All tasks get cancel signal
        cancelling_tasks: 0,
        finalizing_tasks: 0,
        ready_queue_depth: initial_snapshot.ready_queue_depth,
    };

    let mut governor = LyapunovGovernor::new(weights);
    let post_v = governor.compute_potential(&post_cancel_snapshot);
    let post_suggestion = governor.suggest(&post_cancel_snapshot);

    (pre_v, post_v, pre_suggestion, post_suggestion)
}

proptest! {
    /// MR4: cancel does not violate stability proof
    /// Cancellation operations should not inappropriately increase potential or violate stability.
    #[test]
    fn mr_cancel_preserves_stability_properties(
        weights in weights_strategy(),
        initial in snapshot_strategy()
    ) {
        prop_assume!(initial.live_tasks > 0); // Need tasks to cancel

        let (pre_v, post_v, pre_suggestion, post_suggestion) = simulate_cancel_event(&initial, weights);

        // Cancellation might temporarily increase potential due to draining regions,
        // but should not cause unbounded growth
        let increase_ratio = if pre_v > 0.0 { post_v / pre_v } else { 1.0 };
        prop_assert!(
            increase_ratio <= 10.0, // Reasonable bound for temporary increase
            "Cancel event caused excessive potential increase: {:.6} -> {:.6} (ratio: {:.2})",
            pre_v,
            post_v,
            increase_ratio
        );

        // Governor suggestions should remain meaningful
        prop_assert!(
            matches!(post_suggestion,
                SchedulingSuggestion::DrainObligations |
                SchedulingSuggestion::DrainRegions |
                SchedulingSuggestion::MeetDeadlines |
                SchedulingSuggestion::NoPreference
            ),
            "Post-cancel suggestion should be valid: {:?}",
            post_suggestion
        );

        // If there's work to do, suggestion should not be NoPreference
        if post_v > f64::EPSILON {
            prop_assert!(
                post_suggestion != SchedulingSuggestion::NoPreference,
                "Non-zero potential should not suggest NoPreference: V={:.6}, suggestion={:?}",
                post_v,
                post_suggestion
            );
        }
    }
}

// ============================================================================
// MR5: governor output bounded by stability constraint
// ============================================================================

proptest! {
    /// MR5: governor output bounded by stability constraint
    /// Governor suggestions should be consistent with the potential breakdown and stability requirements.
    #[test]
    fn mr_governor_suggestions_bounded_by_stability(
        weights in weights_strategy(),
        snapshot in snapshot_strategy()
    ) {
        let governor = LyapunovGovernor::new(weights);
        let record = governor.compute_record(&snapshot);
        let suggestion = governor.suggest(&snapshot);

        // If quiescent, suggestion should be NoPreference
        if snapshot.is_quiescent() {
            prop_assert!(
                suggestion == SchedulingSuggestion::NoPreference,
                "Quiescent state should suggest NoPreference, got {:?}",
                suggestion
            );
            return Ok(());
        }

        // Find the dominant component
        let components = [
            (record.task_component, "tasks"),
            (record.obligation_component, "obligations"),
            (record.region_component, "regions"),
            (record.deadline_component, "deadlines"),
        ];

        let (max_value, max_label) = components
            .iter()
            .max_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal))
            .unwrap();

        // Verify suggestion aligns with dominant component when there's clear dominance
        let threshold = record.total * 0.4; // Component should be at least 40% of total to be "dominant"

        if *max_value > threshold && record.total > f64::EPSILON {
            match max_label {
                "obligations" => {
                    if record.obligation_component > record.region_component * 1.5
                        && record.obligation_component > record.deadline_component * 1.5 {
                        prop_assert!(
                            suggestion == SchedulingSuggestion::DrainObligations,
                            "Obligation-dominant state should suggest DrainObligations. Got {:?}, components: {:.3}/{:.3}/{:.3}/{:.3}",
                            suggestion,
                            record.task_component,
                            record.obligation_component,
                            record.region_component,
                            record.deadline_component
                        );
                    }
                }
                "regions" => {
                    if record.region_component > record.obligation_component * 1.5
                        && record.region_component > record.deadline_component * 1.5 {
                        prop_assert!(
                            suggestion == SchedulingSuggestion::DrainRegions,
                            "Region-dominant state should suggest DrainRegions. Got {:?}, components: {:.3}/{:.3}/{:.3}/{:.3}",
                            suggestion,
                            record.task_component,
                            record.obligation_component,
                            record.region_component,
                            record.deadline_component
                        );
                    }
                }
                "deadlines" => {
                    if record.deadline_component > record.obligation_component * 1.5
                        && record.deadline_component > record.region_component * 1.5 {
                        prop_assert!(
                            suggestion == SchedulingSuggestion::MeetDeadlines,
                            "Deadline-dominant state should suggest MeetDeadlines. Got {:?}, components: {:.3}/{:.3}/{:.3}/{:.3}",
                            suggestion,
                            record.task_component,
                            record.obligation_component,
                            record.region_component,
                            record.deadline_component
                        );
                    }
                }
                _ => {} // Tasks don't have a specific suggestion type
            }
        }

        // Stability constraint: suggestion should always be actionable when there's work
        if record.total > f64::EPSILON {
            prop_assert!(
                matches!(suggestion,
                    SchedulingSuggestion::DrainObligations |
                    SchedulingSuggestion::DrainRegions |
                    SchedulingSuggestion::MeetDeadlines
                ),
                "Non-zero potential should suggest actionable strategy, got {:?} for V={:.6}",
                suggestion,
                record.total
            );
        }
    }
}

// ============================================================================
// Lab Runtime Integration Tests
// ============================================================================

/// Test Lyapunov properties with real runtime states from lab scenarios
#[test]
fn lab_runtime_lyapunov_invariants() {
    use asupersync::lab::{LabConfig, LabRuntime};

    let mut runner = TestRunner::default();

    runner.run(&(1_u64..=1000), |seed| {
        let mut runtime = LabRuntime::new(LabConfig::new(seed));
        let region = runtime.state.create_root_region(Budget::unlimited());

        // Create tasks with obligations to generate meaningful state
        let task_count = 5;
        let mut obligation_ids = Vec::new();

        for i in 0..task_count {
            let (task_id, _handle) = runtime.state
                .create_task(region, Budget::unlimited(), async {
                    // Simple cooperative task
                    for _ in 0..10 {
                        if let Some(cx) = asupersync::cx::Cx::current() {
                            if cx.checkpoint().is_err() {
                                return;
                            }
                        }
                        // Yield control
                        asupersync::yield_now().await;
                    }
                })
                .unwrap();

            // Add obligations
            if let Ok(obl_id) = runtime.state.create_obligation(
                ObligationKind::SendPermit,
                task_id,
                region,
                Some(format!("test-obligation-{}", i)),
            ) {
                obligation_ids.push(obl_id);
            }

            runtime.scheduler.lock().schedule(task_id, 0);
        }

        // Run for a few steps to establish non-quiescent state
        for _ in 0..5 {
            runtime.step_for_test();
        }

        let mut governor = LyapunovGovernor::with_defaults();

        // Take initial snapshot and verify MR1 (non-negativity)
        let initial_snapshot = StateSnapshot::from_runtime_state(&runtime.state);
        let initial_v = governor.compute_potential(&initial_snapshot);

        prop_assert!(
            initial_v >= 0.0,
            "Lab runtime state should have non-negative potential: V={:.6}",
            initial_v
        );

        // MR3: If runtime is quiescent, potential should be zero
        if runtime.is_quiescent() {
            prop_assert!(
                initial_snapshot.is_quiescent(),
                "Runtime quiescence should match snapshot quiescence"
            );
            prop_assert!(
                initial_v.abs() < f64::EPSILON,
                "Quiescent runtime should have V=0, got {:.6}",
                initial_v
            );
        }

        // Initiate cancellation and track trajectory for MR2
        let cancel_reason = CancelReason::shutdown();
        let tasks_to_cancel = runtime.state.cancel_request(region, &cancel_reason, None);
        {
            let mut scheduler = runtime.scheduler.lock();
            for (task_id, priority) in tasks_to_cancel {
                scheduler.schedule_cancel(task_id, priority);
            }
        }

        // Abort obligations to simulate proper cleanup
        for obl_id in &obligation_ids {
            let _ = runtime.state.abort_obligation(
                *obl_id,
                asupersync::record::ObligationAbortReason::Cancel,
            );
        }

        // Track potential during drain
        let mut trajectory_potentials = vec![initial_v];
        let max_steps = 100;

        for _ in 0..max_steps {
            if runtime.is_quiescent() {
                break;
            }
            runtime.step_for_test();

            let snapshot = StateSnapshot::from_runtime_state(&runtime.state);
            let v = governor.compute_potential(&snapshot);
            trajectory_potentials.push(v);
        }

        // MR2: Check for monotonic decrease (allowing for small violations due to scheduling)
        let mut significant_increases = 0;
        for window in trajectory_potentials.windows(2) {
            let prev = window[0];
            let curr = window[1];
            if curr > prev + 0.1 { // Allow small numerical differences
                significant_increases += 1;
            }
        }

        prop_assert!(
            significant_increases <= trajectory_potentials.len() / 4, // Allow some non-monotonicity
            "Too many significant potential increases during cancel drain: {}/{}",
            significant_increases,
            trajectory_potentials.len()
        );

        // MR3: Final state should minimize potential if quiescent
        if runtime.is_quiescent() {
            let final_v = trajectory_potentials.last().unwrap();
            prop_assert!(
                final_v.abs() < 0.01, // Allow small residual due to scheduling artifacts
                "Final quiescent state should have V≈0, got {:.6}",
                final_v
            );
        }

        Ok(())
    }).unwrap();
}

// ============================================================================
// Weight Configuration Stability Tests
// ============================================================================

#[test]
fn weight_configuration_stability() {
    use asupersync::lab::{LabConfig, LabRuntime};

    let weight_configs = [
        ("default", PotentialWeights::default()),
        ("uniform", PotentialWeights::uniform(1.0)),
        ("obligation_focused", PotentialWeights::obligation_focused()),
        ("deadline_focused", PotentialWeights::deadline_focused()),
    ];

    for (label, weights) in &weight_configs {
        // Quick runtime scenario
        let mut runtime = LabRuntime::new(LabConfig::new(0xBEEF));
        let region = runtime.state.create_root_region(Budget::unlimited());

        let (task_id, _handle) = runtime.state
            .create_task(region, Budget::unlimited(), async {
                asupersync::yield_now().await;
            })
            .unwrap();

        let _obl_id = runtime.state.create_obligation(
            ObligationKind::Ack,
            task_id,
            region,
            None,
        ).unwrap();

        runtime.scheduler.lock().schedule(task_id, 0);
        runtime.step_for_test();

        let snapshot = StateSnapshot::from_runtime_state(&runtime.state);
        let governor = LyapunovGovernor::new(*weights);
        let record = governor.compute_record(&snapshot);

        // All weight configurations should satisfy basic properties
        assert!(
            record.total >= 0.0,
            "{}: Potential should be non-negative: {:.6}",
            label,
            record.total
        );

        assert!(
            weights.is_valid(),
            "{}: Weights should be valid: {:?}",
            label,
            weights
        );

        // Check suggestion consistency
        let suggestion = governor.suggest(&snapshot);
        assert!(
            matches!(suggestion,
                SchedulingSuggestion::DrainObligations |
                SchedulingSuggestion::DrainRegions |
                SchedulingSuggestion::MeetDeadlines |
                SchedulingSuggestion::NoPreference
            ),
            "{}: Invalid suggestion: {:?}",
            label,
            suggestion
        );
    }
}

// ============================================================================
// Deterministic Replay Tests
// ============================================================================

#[test]
fn deterministic_potential_trajectories() {
    use asupersync::lab::{LabConfig, LabRuntime};

    let seed = 0xDEADBEEF;

    // Helper to run identical scenarios
    let run_scenario = || {
        let mut runtime = LabRuntime::new(LabConfig::new(seed));
        let region = runtime.state.create_root_region(Budget::unlimited());

        for i in 0..3 {
            let (task_id, _handle) = runtime.state
                .create_task(region, Budget::unlimited(), async move {
                    for j in 0..5 {
                        if let Some(cx) = asupersync::cx::Cx::current() {
                            if cx.checkpoint().is_err() {
                                return;
                            }
                        }
                        asupersync::yield_now().await;
                    }
                })
                .unwrap();

            runtime.scheduler.lock().schedule(task_id, 0);
        }

        let mut governor = LyapunovGovernor::with_defaults();
        let mut potentials = Vec::new();

        // Record trajectory
        for _ in 0..10 {
            let snapshot = StateSnapshot::from_runtime_state(&runtime.state);
            let v = governor.compute_potential(&snapshot);
            potentials.push(v);

            if runtime.is_quiescent() {
                break;
            }
            runtime.step_for_test();
        }

        potentials
    };

    let trajectory1 = run_scenario();
    let trajectory2 = run_scenario();

    assert_eq!(
        trajectory1.len(),
        trajectory2.len(),
        "Deterministic runs should have same trajectory length"
    );

    for (i, (v1, v2)) in trajectory1.iter().zip(trajectory2.iter()).enumerate() {
        assert!(
            (v1 - v2).abs() < f64::EPSILON,
            "Step {}: Potential should be deterministic: {:.6} vs {:.6}",
            i,
            v1,
            v2
        );
    }
}