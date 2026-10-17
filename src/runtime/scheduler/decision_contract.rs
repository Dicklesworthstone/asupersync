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
    #[inline]
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
    #[inline]
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
    #[inline]
    #[allow(clippy::suboptimal_flops)] // readability: keep formulas in natural math form
    pub fn snapshot_likelihoods(snapshot: &StateSnapshot) -> [f64; 4] {
        let cancel_load = f64::from(snapshot.total_cancelling_tasks());
        // Age matters as much as count here: a single obligation that has
        // stayed pending across multiple governor snapshots is stronger
        // evidence of congestion than a freshly reserved permit.
        let obligation_age_load = (snapshot.obligation_age_sum_ns as f64 / 100_000_000.0).ln_1p();
        let obligation_load = f64::from(snapshot.pending_obligations) + obligation_age_load;
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

        // Keep likelihoods in [floor, 1.0] so callers can treat them as
        // bounded evidentiary strengths without additional clipping.
        let floor = 0.01;
        let clamp_likelihood = |score: f64| score.clamp(floor, 1.0);
        [
            clamp_likelihood(healthy_score),
            clamp_likelihood(congested_score),
            clamp_likelihood(unstable_score),
            clamp_likelihood(partitioned_score),
        ]
    }
}

impl Default for SchedulerDecisionContract {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

#[allow(clippy::unnecessary_literal_bound)]
impl DecisionContract for SchedulerDecisionContract {
    #[inline]
    fn name(&self) -> &str {
        "scheduler"
    }

    #[inline]
    fn state_space(&self) -> &[String] {
        &self.states
    }

    #[inline]
    fn action_set(&self) -> &[String] {
        &self.actions
    }

    #[inline]
    fn loss_matrix(&self) -> &LossMatrix {
        &self.losses
    }

    #[inline]
    fn update_posterior(
        &self,
        posterior: &mut Posterior,
        observation: usize,
    ) -> Result<(), franken_decision::UpdatePosteriorError> {
        // br-asupersync-u5uhpt: surface the malformed-input condition as a
        // typed error so callers can re-initialise instead of letting a
        // stale posterior drive subsequent choose_action calls. Scheduler
        // decision logic still must not panic, so we never modify the
        // posterior on the error path.
        if posterior.len() != state::COUNT {
            return Err(franken_decision::UpdatePosteriorError::LengthMismatch {
                expected: state::COUNT,
                actual: posterior.len(),
            });
        }
        if observation >= state::COUNT {
            return Err(
                franken_decision::UpdatePosteriorError::ObservationOutOfRange {
                    observation,
                    state_count: state::COUNT,
                },
            );
        }

        // Simple likelihood model: observed state gets high probability.
        let mut likelihoods = [0.1; state::COUNT];
        likelihoods[observation] = 0.9;
        posterior.bayesian_update(&likelihoods);
        Ok(())
    }

    #[inline]
    fn choose_action(&self, posterior: &Posterior) -> usize {
        if posterior.len() != state::COUNT {
            return self.fallback_action();
        }
        self.losses.bayes_action(posterior)
    }

    #[inline]
    fn fallback_action(&self) -> usize {
        // Conservative scheduling is the safe fallback.
        action::CONSERVATIVE
    }

    #[inline]
    fn fallback_policy(&self) -> &FallbackPolicy {
        &self.fallback
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[path = "decision_contract_inline_tests.rs"]
mod tests;
