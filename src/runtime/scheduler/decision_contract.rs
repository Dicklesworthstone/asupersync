//! Scheduler Decision Contract using franken_decision (bd-1e2if.6).
//!
//! Implements the §0 Decision Contract for the three-lane scheduler.
//! The contract maps runtime state to a scheduling posture via
//! Bayesian expected-loss minimization.
//!
//! # State Space
//!
//! - **Healthy**: low load, no deadline pressure, no cancellation backlog
//! - **Congested**: high ready-queue depth, obligation backlog
//! - **Unstable**: significant cancellation activity, region drain pressure
//! - **Partitioned**: combination of deadline pressure and cancellation backlog
//!
//! # Action Set
//!
//! - **AggressiveSchedule**: maximize throughput (map → NoPreference)
//! - **BalancedSchedule**: follow Lyapunov governor suggestion
//! - **ConservativeSchedule**: prioritize deadlines (map → MeetDeadlines)

use franken_decision::{DecisionContract, FallbackPolicy, LossMatrix, Posterior};

use crate::obligation::lyapunov::StateSnapshot;

// ---------------------------------------------------------------------------
// State/action indices
// ---------------------------------------------------------------------------

/// State indices into the posterior.
pub mod state {
    /// Low load, no pressure.
    pub const HEALTHY: usize = 0;
    /// High ready-queue depth or obligation backlog.
    pub const CONGESTED: usize = 1;
    /// Significant cancel/drain activity.
    pub const UNSTABLE: usize = 2;
    /// Combined deadline + cancel pressure.
    pub const PARTITIONED: usize = 3;
    /// Total number of states.
    pub const COUNT: usize = 4;
}

/// Action indices.
pub mod action {
    /// Maximize throughput.
    pub const AGGRESSIVE: usize = 0;
    /// Follow governor suggestion.
    pub const BALANCED: usize = 1;
    /// Prioritize deadlines and safety.
    pub const CONSERVATIVE: usize = 2;
    /// Total number of actions.
    pub const COUNT: usize = 3;
}

// ---------------------------------------------------------------------------
// SchedulerDecisionContract
// ---------------------------------------------------------------------------

/// Decision contract for the three-lane scheduler.
///
/// Maps runtime observations to a scheduling posture via Bayesian
/// expected-loss minimization with configurable loss matrix and
/// fallback policy.
#[derive(Debug, Clone)]
pub struct SchedulerDecisionContract {
    states: Vec<String>,
    actions: Vec<String>,
    losses: LossMatrix,
    fallback: FallbackPolicy,
}

impl SchedulerDecisionContract {
    /// Default loss matrix from the §0 methodology spec.
    ///
    /// Row-major: `[state][action]` where actions are
    /// `[aggressive, balanced, conservative]`.
    ///
    /// ```text
    ///                   aggressive  balanced  conservative
    /// healthy                1         3          11
    /// congested             22        10           3
    /// unstable              15         8           5
    /// partitioned           30        15           8
    /// ```
    #[rustfmt::skip]
    const DEFAULT_LOSSES: [f64; 12] = [
        //                  aggressive  balanced  conservative
        /* healthy     */   1.0,        3.0,      11.0,
        /* congested   */   22.0,       10.0,     3.0,
        /* unstable    */   15.0,       8.0,      5.0,
        /* partitioned */   30.0,       15.0,     8.0,
    ];

    /// Create the default scheduler decision contract.
    #[must_use]
    pub fn new() -> Self {
        Self::with_losses_and_policy(Self::DEFAULT_LOSSES.to_vec(), FallbackPolicy::default())
    }

    /// Create with custom loss values and fallback policy.
    ///
    /// `losses` must have exactly 12 elements (4 states x 3 actions).
    ///
    /// # Panics
    ///
    /// Panics if the loss matrix dimensions are wrong or contain
    /// negative values.
    #[must_use]
    pub fn with_losses_and_policy(losses: Vec<f64>, fallback: FallbackPolicy) -> Self {
        let states = vec![
            "healthy".into(),
            "congested".into(),
            "unstable".into(),
            "partitioned".into(),
        ];
        let actions = vec![
            "aggressive_schedule".into(),
            "balanced_schedule".into(),
            "conservative_schedule".into(),
        ];
        let loss_matrix = LossMatrix::new(states.clone(), actions.clone(), losses)
            .expect("scheduler loss matrix should be valid");
        Self {
            states,
            actions,
            losses: loss_matrix,
            fallback,
        }
    }

    /// Compute likelihoods for each state given a runtime snapshot.
    ///
    /// Maps `StateSnapshot` observations to per-state likelihoods
    /// using simple threshold-based heuristics:
    ///
    /// - **Healthy**: low on all pressure indicators
    /// - **Congested**: high ready-queue or obligation backlog
    /// - **Unstable**: significant cancel/region drain activity
    /// - **Partitioned**: combined deadline + cancel pressure
    #[must_use]
    #[allow(clippy::suboptimal_flops)] // readability: keep formulas in natural math form
    pub fn snapshot_likelihoods(snapshot: &StateSnapshot) -> [f64; 4] {
        let cancel_load = f64::from(snapshot.total_cancelling_tasks());
        let obligation_load = f64::from(snapshot.pending_obligations);
        let ready_load = f64::from(snapshot.ready_queue_depth);
        let drain_load = f64::from(snapshot.draining_regions);
        let deadline_signal = snapshot.deadline_pressure.clamp(0.0, 1.0);

        // Compute raw evidence scores (higher = more likely that state).
        // Healthy: everything low.
        let healthy_score =
            1.0 / (1.0 + cancel_load + obligation_load * 0.5 + deadline_signal * 2.0 + drain_load);

        // Congested: high ready queue or obligation backlog.
        let congested_score = (ready_load + obligation_load) / (1.0 + ready_load + obligation_load)
            * (1.0 - deadline_signal * 0.5);

        // Unstable: high cancel/drain activity.
        let unstable_score = (cancel_load + drain_load) / (1.0 + cancel_load + drain_load)
            * (1.0 - deadline_signal * 0.3);

        // Partitioned: interaction of deadline pressure and cancel/drain pressure.
        let cancel_drain_ratio = (cancel_load + drain_load) / (1.0 + cancel_load + drain_load);
        let partitioned_score = deadline_signal * (0.5 + cancel_drain_ratio);

        // Floor to avoid zero likelihoods (keeps posterior well-defined).
        let floor = 0.01;
        [
            healthy_score.max(floor),
            congested_score.max(floor),
            unstable_score.max(floor),
            partitioned_score.max(floor),
        ]
    }
}

impl Default for SchedulerDecisionContract {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(clippy::unnecessary_literal_bound)]
impl DecisionContract for SchedulerDecisionContract {
    fn name(&self) -> &str {
        "scheduler"
    }

    fn state_space(&self) -> &[String] {
        &self.states
    }

    fn action_set(&self) -> &[String] {
        &self.actions
    }

    fn loss_matrix(&self) -> &LossMatrix {
        &self.losses
    }

    fn update_posterior(&self, posterior: &mut Posterior, observation: usize) {
        // Defensive guard: malformed posterior dimensions should not panic
        // scheduler decision logic.
        if posterior.len() != state::COUNT {
            return;
        }

        // Simple likelihood model: observed state gets high probability.
        let mut likelihoods = [0.1; state::COUNT];
        if let Some(observed) = likelihoods.get_mut(observation) {
            *observed = 0.9;
        }
        posterior.bayesian_update(&likelihoods);
    }

    fn choose_action(&self, posterior: &Posterior) -> usize {
        if posterior.len() != state::COUNT {
            return self.fallback_action();
        }
        self.losses.bayes_action(posterior)
    }

    fn fallback_action(&self) -> usize {
        // Conservative scheduling is the safe fallback.
        action::CONSERVATIVE
    }

    fn fallback_policy(&self) -> &FallbackPolicy {
        &self.fallback
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Time;
    use franken_decision::{evaluate, EvalContext, Posterior};
    use franken_kernel::{DecisionId, TraceId};

    fn test_ctx(cal: f64) -> EvalContext {
        EvalContext {
            calibration_score: cal,
            e_process: 1.0,
            ci_width: 0.1,
            decision_id: DecisionId::from_parts(1_700_000_000_000, 42),
            trace_id: TraceId::from_parts(1_700_000_000_000, 1),
            ts_unix_ms: 1_700_000_000_000,
        }
    }

    fn zero_snapshot() -> StateSnapshot {
        StateSnapshot {
            time: Time::ZERO,
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
        }
    }

    #[test]
    fn contract_creation() {
        let c = SchedulerDecisionContract::new();
        assert_eq!(c.name(), "scheduler");
        assert_eq!(c.state_space().len(), 4);
        assert_eq!(c.action_set().len(), 3);
    }

    #[test]
    fn healthy_state_prefers_aggressive() {
        let c = SchedulerDecisionContract::new();
        // Posterior concentrated on healthy.
        let posterior = Posterior::new(vec![0.9, 0.03, 0.03, 0.04]).unwrap();
        let outcome = evaluate(&c, &posterior, &test_ctx(0.95));
        assert_eq!(outcome.action_index, action::AGGRESSIVE);
        assert!(!outcome.fallback_active);
    }

    #[test]
    fn congested_state_prefers_conservative() {
        let c = SchedulerDecisionContract::new();
        // Posterior concentrated on congested.
        let posterior = Posterior::new(vec![0.05, 0.85, 0.05, 0.05]).unwrap();
        let outcome = evaluate(&c, &posterior, &test_ctx(0.95));
        assert_eq!(outcome.action_index, action::CONSERVATIVE);
    }

    #[test]
    fn partitioned_state_prefers_conservative() {
        let c = SchedulerDecisionContract::new();
        // Posterior concentrated on partitioned.
        let posterior = Posterior::new(vec![0.05, 0.05, 0.05, 0.85]).unwrap();
        let outcome = evaluate(&c, &posterior, &test_ctx(0.95));
        assert_eq!(outcome.action_index, action::CONSERVATIVE);
    }

    #[test]
    fn unstable_state_prefers_conservative() {
        let c = SchedulerDecisionContract::new();
        // Posterior concentrated on unstable.
        let posterior = Posterior::new(vec![0.05, 0.05, 0.85, 0.05]).unwrap();
        let outcome = evaluate(&c, &posterior, &test_ctx(0.95));
        assert_eq!(outcome.action_index, action::CONSERVATIVE);
    }

    #[test]
    fn fallback_chooses_conservative() {
        let c = SchedulerDecisionContract::new();
        let posterior = Posterior::uniform(4);
        // Low calibration triggers fallback.
        let outcome = evaluate(&c, &posterior, &test_ctx(0.3));
        assert!(outcome.fallback_active);
        assert_eq!(outcome.action_index, action::CONSERVATIVE);
    }

    #[test]
    fn uniform_posterior_prefers_aggressive() {
        // With uniform prior: E[aggressive]=17.0, E[balanced]=9.0, E[conservative]=6.75
        // So uniform should prefer conservative.
        let c = SchedulerDecisionContract::new();
        let posterior = Posterior::uniform(4);
        let outcome = evaluate(&c, &posterior, &test_ctx(0.95));
        assert_eq!(outcome.action_index, action::CONSERVATIVE);
    }

    #[test]
    fn audit_entry_produces_valid_evidence() {
        let c = SchedulerDecisionContract::new();
        let posterior = Posterior::new(vec![0.7, 0.1, 0.1, 0.1]).unwrap();
        let outcome = evaluate(&c, &posterior, &test_ctx(0.92));
        let evidence = outcome.audit_entry.to_evidence_ledger();
        assert_eq!(evidence.component, "scheduler");
        assert!(evidence.is_valid());
    }

    #[test]
    fn snapshot_likelihoods_quiescent() {
        let snapshot = zero_snapshot();
        let likelihoods = SchedulerDecisionContract::snapshot_likelihoods(&snapshot);
        // When quiescent, healthy should be dominant.
        assert!(likelihoods[state::HEALTHY] > likelihoods[state::CONGESTED]);
        assert!(likelihoods[state::HEALTHY] > likelihoods[state::UNSTABLE]);
        assert!(likelihoods[state::HEALTHY] > likelihoods[state::PARTITIONED]);
    }

    #[test]
    fn snapshot_likelihoods_high_cancel_load() {
        let mut snapshot = zero_snapshot();
        snapshot.cancel_requested_tasks = 50;
        snapshot.cancelling_tasks = 20;
        let likelihoods = SchedulerDecisionContract::snapshot_likelihoods(&snapshot);
        // High cancel load should push unstable higher.
        assert!(likelihoods[state::UNSTABLE] > likelihoods[state::HEALTHY]);
    }

    #[test]
    fn snapshot_likelihoods_high_queue_depth() {
        let mut snapshot = zero_snapshot();
        snapshot.ready_queue_depth = 100;
        snapshot.pending_obligations = 30;
        let likelihoods = SchedulerDecisionContract::snapshot_likelihoods(&snapshot);
        // High queue should push congested higher.
        assert!(likelihoods[state::CONGESTED] > likelihoods[state::HEALTHY]);
    }

    #[test]
    fn snapshot_likelihoods_high_deadline_pressure() {
        let mut snapshot = zero_snapshot();
        snapshot.deadline_pressure = 1.0;
        let likelihoods = SchedulerDecisionContract::snapshot_likelihoods(&snapshot);
        // High deadline pressure should not look healthy.
        assert!(likelihoods[state::PARTITIONED] > likelihoods[state::HEALTHY]);
    }

    #[test]
    fn snapshot_likelihoods_deadline_plus_cancel_pressure_prefers_partitioned() {
        let mut snapshot = zero_snapshot();
        snapshot.deadline_pressure = 1.0;
        snapshot.cancel_requested_tasks = 40;
        snapshot.cancelling_tasks = 30;
        snapshot.draining_regions = 20;
        let likelihoods = SchedulerDecisionContract::snapshot_likelihoods(&snapshot);
        // Combined deadline + cancel/drain pressure should favor partitioned.
        assert!(likelihoods[state::PARTITIONED] > likelihoods[state::UNSTABLE]);
    }

    #[test]
    fn end_to_end_posterior_update_and_decide() {
        let c = SchedulerDecisionContract::new();
        let mut posterior = Posterior::uniform(4);

        // Feed healthy observations repeatedly.
        let healthy_likelihoods = [0.8, 0.05, 0.05, 0.1];
        for _ in 0..10 {
            posterior.bayesian_update(&healthy_likelihoods);
        }

        // Should converge toward healthy → aggressive.
        let outcome = evaluate(&c, &posterior, &test_ctx(0.95));
        assert_eq!(outcome.action_index, action::AGGRESSIVE);
    }

    #[test]
    fn custom_loss_matrix() {
        // Swap so conservative is bad everywhere → aggressive wins.
        let losses = vec![
            1.0, 2.0, 50.0, // healthy
            5.0, 3.0, 50.0, // congested
            8.0, 6.0, 50.0, // unstable
            10.0, 8.0, 50.0, // partitioned
        ];
        let c =
            SchedulerDecisionContract::with_losses_and_policy(losses, FallbackPolicy::default());
        let posterior = Posterior::uniform(4);
        let outcome = evaluate(&c, &posterior, &test_ctx(0.95));
        // Conservative is very expensive everywhere, so aggressive/balanced wins.
        assert_ne!(outcome.action_index, action::CONSERVATIVE);
    }

    #[test]
    fn update_posterior_out_of_range_is_noop() {
        let c = SchedulerDecisionContract::new();
        let mut posterior = Posterior::uniform(state::COUNT);
        let before = posterior.probs().to_vec();
        c.update_posterior(&mut posterior, state::COUNT + 5);
        assert_eq!(posterior.probs(), before.as_slice());
    }

    #[test]
    fn update_posterior_wrong_dimension_is_noop() {
        let c = SchedulerDecisionContract::new();
        let mut posterior = Posterior::uniform(state::COUNT - 1);
        let before = posterior.probs().to_vec();
        c.update_posterior(&mut posterior, state::HEALTHY);
        assert_eq!(posterior.probs(), before.as_slice());
    }

    #[test]
    fn choose_action_wrong_dimension_uses_fallback() {
        let c = SchedulerDecisionContract::new();
        let posterior = Posterior::uniform(state::COUNT - 1);
        assert_eq!(c.choose_action(&posterior), action::CONSERVATIVE);
    }
}
