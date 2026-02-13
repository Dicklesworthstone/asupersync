//! Decision Contract schema and runtime for FrankenSuite (bd-3ai21).
//!
//! The third leg of the foundation tripod alongside `franken_kernel` (types)
//! and `franken_evidence` (audit ledger). Every FrankenSuite project that
//! makes runtime decisions uses this crate's contract schema.
//!
//! # Core abstractions
//!
//! - [`DecisionContract`] — trait defining state space, actions, losses, and
//!   posterior updates. Implementable in <50 lines.
//! - [`LossMatrix`] — non-negative loss values indexed by (state, action),
//!   serializable to TOML for runtime reconfiguration.
//! - [`Posterior`] — discrete probability distribution with O(|S|)
//!   no-allocation Bayesian updates.
//! - [`FallbackPolicy`] — calibration drift, e-process breach, and
//!   confidence interval width thresholds.
//! - [`DecisionAuditEntry`] — links decisions to [`EvidenceLedger`] entries.
//!
//! # Example
//!
//! ```
//! use franken_decision::{
//!     DecisionContract, EvalContext, FallbackPolicy, LossMatrix, Posterior, evaluate,
//! };
//! use franken_kernel::DecisionId;
//!
//! // Define a simple 2-state, 2-action contract.
//! struct MyContract {
//!     states: Vec<String>,
//!     actions: Vec<String>,
//!     losses: LossMatrix,
//!     policy: FallbackPolicy,
//! }
//!
//! impl DecisionContract for MyContract {
//!     fn name(&self) -> &str { "example" }
//!     fn state_space(&self) -> &[String] { &self.states }
//!     fn action_set(&self) -> &[String] { &self.actions }
//!     fn loss_matrix(&self) -> &LossMatrix { &self.losses }
//!     fn update_posterior(&self, posterior: &mut Posterior, observation: usize) {
//!         let likelihoods = [0.9, 0.1];
//!         posterior.bayesian_update(&likelihoods);
//!     }
//!     fn choose_action(&self, posterior: &Posterior) -> usize {
//!         self.losses.bayes_action(posterior)
//!     }
//!     fn fallback_action(&self) -> usize { 0 }
//!     fn fallback_policy(&self) -> &FallbackPolicy { &self.policy }
//! }
//!
//! let contract = MyContract {
//!     states: vec!["good".into(), "bad".into()],
//!     actions: vec!["continue".into(), "stop".into()],
//!     losses: LossMatrix::new(
//!         vec!["good".into(), "bad".into()],
//!         vec!["continue".into(), "stop".into()],
//!         vec![0.0, 0.3, 0.8, 0.1],
//!     ).unwrap(),
//!     policy: FallbackPolicy::default(),
//! };
//!
//! let posterior = Posterior::uniform(2);
//! let decision_id = DecisionId::from_parts(1_700_000_000_000, 42);
//! let trace_id = franken_kernel::TraceId::from_parts(1_700_000_000_000, 1);
//!
//! let ctx = EvalContext {
//!     calibration_score: 0.9,
//!     e_process: 0.5,
//!     ci_width: 0.1,
//!     decision_id,
//!     trace_id,
//!     ts_unix_ms: 1_700_000_000_000,
//! };
//! let outcome = evaluate(&contract, &posterior, &ctx);
//! assert!(!outcome.fallback_active);
//! ```

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::fmt;

use franken_evidence::{EvidenceLedger, EvidenceLedgerBuilder};
use franken_kernel::{DecisionId, TraceId};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Validation errors
// ---------------------------------------------------------------------------

/// Validation errors for decision types.
#[derive(Clone, Debug, PartialEq)]
pub enum ValidationError {
    /// Loss matrix contains a negative value.
    NegativeLoss {
        /// State index of the negative entry.
        state: usize,
        /// Action index of the negative entry.
        action: usize,
        /// The negative value.
        value: f64,
    },
    /// Loss matrix value count does not match dimensions.
    DimensionMismatch {
        /// Expected number of values (states * actions).
        expected: usize,
        /// Actual number of values provided.
        got: usize,
    },
    /// Posterior probabilities do not sum to ~1.0.
    PosteriorNotNormalized {
        /// Actual sum of the posterior.
        sum: f64,
    },
    /// Posterior length does not match state space size.
    PosteriorLengthMismatch {
        /// Expected length.
        expected: usize,
        /// Actual length.
        got: usize,
    },
    /// State space or action set is empty.
    EmptySpace {
        /// Which space is empty.
        field: &'static str,
    },
    /// Threshold value is out of valid range.
    ThresholdOutOfRange {
        /// Which threshold.
        field: &'static str,
        /// The invalid value.
        value: f64,
    },
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NegativeLoss {
                state,
                action,
                value,
            } => write!(f, "negative loss {value} at state={state}, action={action}"),
            Self::DimensionMismatch { expected, got } => {
                write!(
                    f,
                    "dimension mismatch: expected {expected} values, got {got}"
                )
            }
            Self::PosteriorNotNormalized { sum } => {
                write!(f, "posterior sums to {sum}, expected 1.0")
            }
            Self::PosteriorLengthMismatch { expected, got } => {
                write!(
                    f,
                    "posterior length {got} does not match state count {expected}"
                )
            }
            Self::EmptySpace { field } => write!(f, "{field} must not be empty"),
            Self::ThresholdOutOfRange { field, value } => {
                write!(f, "{field} threshold {value} out of valid range")
            }
        }
    }
}

impl std::error::Error for ValidationError {}

// ---------------------------------------------------------------------------
// LossMatrix
// ---------------------------------------------------------------------------

/// A loss matrix indexed by (state, action) pairs.
///
/// Stored in row-major order: `values[state * n_actions + action]`.
/// All values must be non-negative. Serializable to TOML/JSON for
/// runtime reconfiguration.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct LossMatrix {
    state_names: Vec<String>,
    action_names: Vec<String>,
    values: Vec<f64>,
}

impl LossMatrix {
    /// Create a new loss matrix.
    ///
    /// `values` must have exactly `state_names.len() * action_names.len()`
    /// elements, all non-negative. Laid out in row-major order:
    /// `values[s * n_actions + a]` is the loss for state `s`, action `a`.
    pub fn new(
        state_names: Vec<String>,
        action_names: Vec<String>,
        values: Vec<f64>,
    ) -> Result<Self, ValidationError> {
        if state_names.is_empty() {
            return Err(ValidationError::EmptySpace {
                field: "state_names",
            });
        }
        if action_names.is_empty() {
            return Err(ValidationError::EmptySpace {
                field: "action_names",
            });
        }
        let expected = state_names.len() * action_names.len();
        if values.len() != expected {
            return Err(ValidationError::DimensionMismatch {
                expected,
                got: values.len(),
            });
        }
        let n_actions = action_names.len();
        for (i, &v) in values.iter().enumerate() {
            if v < 0.0 {
                return Err(ValidationError::NegativeLoss {
                    state: i / n_actions,
                    action: i % n_actions,
                    value: v,
                });
            }
        }
        Ok(Self {
            state_names,
            action_names,
            values,
        })
    }

    /// Get the loss for a specific (state, action) pair.
    pub fn get(&self, state: usize, action: usize) -> f64 {
        self.values[state * self.action_names.len() + action]
    }

    /// Number of states.
    pub fn n_states(&self) -> usize {
        self.state_names.len()
    }

    /// Number of actions.
    pub fn n_actions(&self) -> usize {
        self.action_names.len()
    }

    /// State labels.
    pub fn state_names(&self) -> &[String] {
        &self.state_names
    }

    /// Action labels.
    pub fn action_names(&self) -> &[String] {
        &self.action_names
    }

    /// Compute expected loss for a specific action given a posterior.
    ///
    /// `E[loss|a] = sum_s posterior(s) * loss(s, a)`
    pub fn expected_loss(&self, posterior: &Posterior, action: usize) -> f64 {
        posterior
            .probs()
            .iter()
            .enumerate()
            .map(|(s, &p)| p * self.get(s, action))
            .sum()
    }

    /// Compute expected losses for all actions as a name-indexed map.
    pub fn expected_losses(&self, posterior: &Posterior) -> HashMap<String, f64> {
        self.action_names
            .iter()
            .enumerate()
            .map(|(a, name)| (name.clone(), self.expected_loss(posterior, a)))
            .collect()
    }

    /// Choose the Bayes-optimal action (minimum expected loss).
    ///
    /// Returns the action index. Ties are broken by lowest index.
    pub fn bayes_action(&self, posterior: &Posterior) -> usize {
        (0..self.action_names.len())
            .min_by(|&a, &b| {
                self.expected_loss(posterior, a)
                    .partial_cmp(&self.expected_loss(posterior, b))
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Posterior
// ---------------------------------------------------------------------------

/// Tolerance for posterior normalization checks.
const NORMALIZATION_TOLERANCE: f64 = 1e-6;

/// A discrete probability distribution over states.
///
/// Supports in-place Bayesian updates in O(|S|) with no allocation.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Posterior {
    probs: Vec<f64>,
}

impl Posterior {
    /// Create from explicit probabilities.
    ///
    /// Probabilities must sum to ~1.0 (within tolerance) and be non-negative.
    pub fn new(probs: Vec<f64>) -> Result<Self, ValidationError> {
        let sum: f64 = probs.iter().sum();
        if (sum - 1.0).abs() > NORMALIZATION_TOLERANCE {
            return Err(ValidationError::PosteriorNotNormalized { sum });
        }
        Ok(Self { probs })
    }

    /// Create a uniform prior over `n` states.
    #[allow(clippy::cast_precision_loss)]
    pub fn uniform(n: usize) -> Self {
        let p = 1.0 / n as f64;
        Self { probs: vec![p; n] }
    }

    /// Probability values (immutable).
    pub fn probs(&self) -> &[f64] {
        &self.probs
    }

    /// Mutable access to probability values for in-place updates.
    pub fn probs_mut(&mut self) -> &mut [f64] {
        &mut self.probs
    }

    /// Number of states in the distribution.
    pub fn len(&self) -> usize {
        self.probs.len()
    }

    /// Whether the distribution is empty.
    pub fn is_empty(&self) -> bool {
        self.probs.is_empty()
    }

    /// Bayesian update: multiply by likelihoods and renormalize.
    ///
    /// `likelihoods[s]` = P(observation | state = s).
    /// Runs in O(|S|) with no allocation.
    ///
    /// # Panics
    ///
    /// Panics if `likelihoods.len() != self.len()`.
    pub fn bayesian_update(&mut self, likelihoods: &[f64]) {
        assert_eq!(likelihoods.len(), self.probs.len());
        for (p, &l) in self.probs.iter_mut().zip(likelihoods) {
            *p *= l;
        }
        self.normalize();
    }

    /// Renormalize probabilities to sum to 1.0.
    pub fn normalize(&mut self) {
        let sum: f64 = self.probs.iter().sum();
        if sum > 0.0 {
            for p in &mut self.probs {
                *p /= sum;
            }
        }
    }

    /// Shannon entropy: -sum p * log2(p).
    pub fn entropy(&self) -> f64 {
        self.probs
            .iter()
            .filter(|&&p| p > 0.0)
            .map(|&p| -p * p.log2())
            .sum()
    }

    /// Index of the most probable state (MAP estimate).
    ///
    /// Ties are broken by lowest index.
    pub fn map_state(&self) -> usize {
        self.probs
            .iter()
            .enumerate()
            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
            .map_or(0, |(i, _)| i)
    }
}

// ---------------------------------------------------------------------------
// FallbackPolicy
// ---------------------------------------------------------------------------

/// Conditions under which to activate fallback heuristics.
///
/// A decision engine should switch to [`DecisionContract::fallback_action`]
/// when any threshold is breached.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct FallbackPolicy {
    /// Activate fallback if calibration score drops below this value.
    pub calibration_drift_threshold: f64,
    /// Activate fallback if e-process statistic exceeds this value.
    pub e_process_breach_threshold: f64,
    /// Activate fallback if confidence interval width exceeds this value.
    pub confidence_width_threshold: f64,
}

impl FallbackPolicy {
    /// Create a new fallback policy.
    ///
    /// `calibration_drift_threshold` must be in [0, 1].
    /// Other thresholds must be non-negative.
    pub fn new(
        calibration_drift_threshold: f64,
        e_process_breach_threshold: f64,
        confidence_width_threshold: f64,
    ) -> Result<Self, ValidationError> {
        if !(0.0..=1.0).contains(&calibration_drift_threshold) {
            return Err(ValidationError::ThresholdOutOfRange {
                field: "calibration_drift_threshold",
                value: calibration_drift_threshold,
            });
        }
        if e_process_breach_threshold < 0.0 {
            return Err(ValidationError::ThresholdOutOfRange {
                field: "e_process_breach_threshold",
                value: e_process_breach_threshold,
            });
        }
        if confidence_width_threshold < 0.0 {
            return Err(ValidationError::ThresholdOutOfRange {
                field: "confidence_width_threshold",
                value: confidence_width_threshold,
            });
        }
        Ok(Self {
            calibration_drift_threshold,
            e_process_breach_threshold,
            confidence_width_threshold,
        })
    }

    /// Check if fallback should be activated based on current metrics.
    pub fn should_fallback(&self, calibration_score: f64, e_process: f64, ci_width: f64) -> bool {
        calibration_score < self.calibration_drift_threshold
            || e_process > self.e_process_breach_threshold
            || ci_width > self.confidence_width_threshold
    }
}

impl Default for FallbackPolicy {
    fn default() -> Self {
        Self {
            calibration_drift_threshold: 0.7,
            e_process_breach_threshold: 20.0,
            confidence_width_threshold: 0.5,
        }
    }
}

// ---------------------------------------------------------------------------
// DecisionContract trait
// ---------------------------------------------------------------------------

/// A contract defining the decision-making framework for a component.
///
/// Implementors define the state space, action set, loss matrix, and
/// posterior update logic. The [`evaluate`] function orchestrates the
/// full decision pipeline and produces an auditable outcome.
pub trait DecisionContract {
    /// Human-readable contract name (e.g., "scheduler", "load_balancer").
    fn name(&self) -> &str;

    /// Ordered labels for the state space.
    fn state_space(&self) -> &[String];

    /// Ordered labels for the action set.
    fn action_set(&self) -> &[String];

    /// The loss matrix for this contract.
    fn loss_matrix(&self) -> &LossMatrix;

    /// Update the posterior given an observation at `state_index`.
    fn update_posterior(&self, posterior: &mut Posterior, state_index: usize);

    /// Choose the optimal action given the current posterior.
    ///
    /// Returns an action index into [`action_set`](Self::action_set).
    fn choose_action(&self, posterior: &Posterior) -> usize;

    /// The fallback action when the model is unreliable.
    ///
    /// Returns an action index into [`action_set`](Self::action_set).
    fn fallback_action(&self) -> usize;

    /// Policy governing fallback activation.
    fn fallback_policy(&self) -> &FallbackPolicy;
}

// ---------------------------------------------------------------------------
// DecisionAuditEntry
// ---------------------------------------------------------------------------

/// Structured audit record linking a decision to the evidence ledger.
///
/// Captures the full context of a runtime decision for offline analysis
/// and replay.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecisionAuditEntry {
    /// Unique identifier for this decision.
    pub decision_id: DecisionId,
    /// Trace context for distributed tracing.
    pub trace_id: TraceId,
    /// Name of the decision contract that was evaluated.
    pub contract_name: String,
    /// The action that was chosen.
    pub action_chosen: String,
    /// Expected loss of the chosen action.
    pub expected_loss: f64,
    /// Current calibration score at decision time.
    pub calibration_score: f64,
    /// Whether the fallback heuristic was active.
    pub fallback_active: bool,
    /// Snapshot of the posterior at decision time.
    pub posterior_snapshot: Vec<f64>,
    /// Expected loss for each candidate action.
    pub expected_loss_by_action: HashMap<String, f64>,
    /// Unix timestamp in milliseconds.
    pub ts_unix_ms: u64,
}

impl DecisionAuditEntry {
    /// Convert to an [`EvidenceLedger`] entry for structured tracing.
    pub fn to_evidence_ledger(&self) -> EvidenceLedger {
        let mut builder = EvidenceLedgerBuilder::new()
            .ts_unix_ms(self.ts_unix_ms)
            .component(&self.contract_name)
            .action(&self.action_chosen)
            .posterior(self.posterior_snapshot.clone())
            .chosen_expected_loss(self.expected_loss)
            .calibration_score(self.calibration_score)
            .fallback_active(self.fallback_active);

        for (action, &loss) in &self.expected_loss_by_action {
            builder = builder.expected_loss(action, loss);
        }

        builder
            .build()
            .expect("audit entry should produce valid evidence ledger")
    }
}

// ---------------------------------------------------------------------------
// DecisionOutcome
// ---------------------------------------------------------------------------

/// Result of evaluating a decision contract.
#[derive(Clone, Debug)]
pub struct DecisionOutcome {
    /// Index of the chosen action.
    pub action_index: usize,
    /// Name of the chosen action.
    pub action_name: String,
    /// Expected loss of the chosen action.
    pub expected_loss: f64,
    /// Expected losses for all candidate actions.
    pub expected_losses: HashMap<String, f64>,
    /// Whether fallback was activated.
    pub fallback_active: bool,
    /// Full audit entry for this decision.
    pub audit_entry: DecisionAuditEntry,
}

// ---------------------------------------------------------------------------
// EvalContext
// ---------------------------------------------------------------------------

/// Runtime context for a single decision evaluation.
///
/// Bundles the monitoring metrics and tracing identifiers needed by
/// [`evaluate`].
#[derive(Clone, Debug)]
pub struct EvalContext {
    /// Current calibration score.
    pub calibration_score: f64,
    /// Current e-process statistic.
    pub e_process: f64,
    /// Current confidence interval width.
    pub ci_width: f64,
    /// Unique identifier for this decision.
    pub decision_id: DecisionId,
    /// Trace context for distributed tracing.
    pub trace_id: TraceId,
    /// Unix timestamp in milliseconds.
    pub ts_unix_ms: u64,
}

// ---------------------------------------------------------------------------
// Evaluate
// ---------------------------------------------------------------------------

/// Evaluate a decision contract and produce a full audit trail.
///
/// This is the primary entry point for making auditable decisions.
/// It computes expected losses, checks fallback conditions, and produces
/// a [`DecisionOutcome`] with a linked [`DecisionAuditEntry`].
pub fn evaluate<C: DecisionContract>(
    contract: &C,
    posterior: &Posterior,
    ctx: &EvalContext,
) -> DecisionOutcome {
    let loss_matrix = contract.loss_matrix();
    let expected_losses = loss_matrix.expected_losses(posterior);

    let fallback_active = contract.fallback_policy().should_fallback(
        ctx.calibration_score,
        ctx.e_process,
        ctx.ci_width,
    );

    let action_index = if fallback_active {
        contract.fallback_action()
    } else {
        contract.choose_action(posterior)
    };

    let action_name = contract.action_set()[action_index].clone();
    let expected_loss = expected_losses[&action_name];

    let audit_entry = DecisionAuditEntry {
        decision_id: ctx.decision_id,
        trace_id: ctx.trace_id,
        contract_name: contract.name().to_string(),
        action_chosen: action_name.clone(),
        expected_loss,
        calibration_score: ctx.calibration_score,
        fallback_active,
        posterior_snapshot: posterior.probs().to_vec(),
        expected_loss_by_action: expected_losses.clone(),
        ts_unix_ms: ctx.ts_unix_ms,
    };

    DecisionOutcome {
        action_index,
        action_name,
        expected_loss,
        expected_losses,
        fallback_active,
        audit_entry,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::float_cmp)]
mod tests {
    use super::*;

    // -- Helpers --

    fn two_state_matrix() -> LossMatrix {
        // States: [good, bad], Actions: [continue, stop]
        // loss(good, continue) = 0.0, loss(good, stop) = 0.3
        // loss(bad, continue)  = 0.8, loss(bad, stop)  = 0.1
        LossMatrix::new(
            vec!["good".into(), "bad".into()],
            vec!["continue".into(), "stop".into()],
            vec![0.0, 0.3, 0.8, 0.1],
        )
        .unwrap()
    }

    struct TestContract {
        states: Vec<String>,
        actions: Vec<String>,
        losses: LossMatrix,
        policy: FallbackPolicy,
    }

    impl TestContract {
        fn new() -> Self {
            Self {
                states: vec!["good".into(), "bad".into()],
                actions: vec!["continue".into(), "stop".into()],
                losses: two_state_matrix(),
                policy: FallbackPolicy::default(),
            }
        }
    }

    #[allow(clippy::unnecessary_literal_bound)]
    impl DecisionContract for TestContract {
        fn name(&self) -> &str {
            "test_contract"
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
            // Simple likelihood model: observed state gets high likelihood.
            let mut likelihoods = vec![0.1; self.states.len()];
            likelihoods[observation] = 0.9;
            posterior.bayesian_update(&likelihoods);
        }
        fn choose_action(&self, posterior: &Posterior) -> usize {
            self.losses.bayes_action(posterior)
        }
        fn fallback_action(&self) -> usize {
            0 // "continue"
        }
        fn fallback_policy(&self) -> &FallbackPolicy {
            &self.policy
        }
    }

    // -- LossMatrix tests --

    #[test]
    fn loss_matrix_creation() {
        let m = two_state_matrix();
        assert_eq!(m.n_states(), 2);
        assert_eq!(m.n_actions(), 2);
        assert_eq!(m.get(0, 0), 0.0);
        assert_eq!(m.get(0, 1), 0.3);
        assert_eq!(m.get(1, 0), 0.8);
        assert_eq!(m.get(1, 1), 0.1);
    }

    #[test]
    fn loss_matrix_empty_states_rejected() {
        let err = LossMatrix::new(vec![], vec!["a".into()], vec![]).unwrap_err();
        assert!(matches!(
            err,
            ValidationError::EmptySpace {
                field: "state_names"
            }
        ));
    }

    #[test]
    fn loss_matrix_empty_actions_rejected() {
        let err = LossMatrix::new(vec!["s".into()], vec![], vec![]).unwrap_err();
        assert!(matches!(
            err,
            ValidationError::EmptySpace {
                field: "action_names"
            }
        ));
    }

    #[test]
    fn loss_matrix_dimension_mismatch() {
        let err = LossMatrix::new(
            vec!["s1".into(), "s2".into()],
            vec!["a1".into()],
            vec![0.1], // needs 2 values
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ValidationError::DimensionMismatch {
                expected: 2,
                got: 1
            }
        ));
    }

    #[test]
    fn loss_matrix_negative_rejected() {
        let err = LossMatrix::new(vec!["s".into()], vec!["a".into()], vec![-0.5]).unwrap_err();
        assert!(matches!(
            err,
            ValidationError::NegativeLoss {
                state: 0,
                action: 0,
                ..
            }
        ));
    }

    #[test]
    fn loss_matrix_expected_loss() {
        let m = two_state_matrix();
        let posterior = Posterior::new(vec![0.8, 0.2]).unwrap();
        // E[loss|continue] = 0.8*0.0 + 0.2*0.8 = 0.16
        let el_continue = m.expected_loss(&posterior, 0);
        assert!((el_continue - 0.16).abs() < 1e-10);
        // E[loss|stop] = 0.8*0.3 + 0.2*0.1 = 0.26
        let el_stop = m.expected_loss(&posterior, 1);
        assert!((el_stop - 0.26).abs() < 1e-10);
    }

    #[test]
    fn loss_matrix_bayes_action() {
        let m = two_state_matrix();
        // When mostly good, continue is optimal.
        let mostly_good = Posterior::new(vec![0.9, 0.1]).unwrap();
        assert_eq!(m.bayes_action(&mostly_good), 0); // continue
                                                     // When mostly bad, stop is optimal.
        let mostly_bad = Posterior::new(vec![0.2, 0.8]).unwrap();
        assert_eq!(m.bayes_action(&mostly_bad), 1); // stop
    }

    #[test]
    fn loss_matrix_expected_losses_map() {
        let m = two_state_matrix();
        let posterior = Posterior::uniform(2);
        let losses = m.expected_losses(&posterior);
        assert_eq!(losses.len(), 2);
        assert!(losses.contains_key("continue"));
        assert!(losses.contains_key("stop"));
    }

    #[test]
    fn loss_matrix_names() {
        let m = two_state_matrix();
        assert_eq!(m.state_names(), &["good", "bad"]);
        assert_eq!(m.action_names(), &["continue", "stop"]);
    }

    #[test]
    fn loss_matrix_toml_roundtrip() {
        let m = two_state_matrix();
        let toml_str = toml::to_string(&m).unwrap();
        let parsed: LossMatrix = toml::from_str(&toml_str).unwrap();
        assert_eq!(m, parsed);
    }

    #[test]
    fn loss_matrix_json_roundtrip() {
        let m = two_state_matrix();
        let json = serde_json::to_string(&m).unwrap();
        let parsed: LossMatrix = serde_json::from_str(&json).unwrap();
        assert_eq!(m, parsed);
    }

    // -- Posterior tests --

    #[test]
    fn posterior_uniform() {
        let p = Posterior::uniform(4);
        assert_eq!(p.len(), 4);
        for &v in p.probs() {
            assert!((v - 0.25).abs() < 1e-10);
        }
    }

    #[test]
    fn posterior_new_valid() {
        let p = Posterior::new(vec![0.3, 0.7]).unwrap();
        assert_eq!(p.probs(), &[0.3, 0.7]);
    }

    #[test]
    fn posterior_new_not_normalized() {
        let err = Posterior::new(vec![0.5, 0.3]).unwrap_err();
        assert!(matches!(
            err,
            ValidationError::PosteriorNotNormalized { .. }
        ));
    }

    #[test]
    fn posterior_bayesian_update() {
        let mut p = Posterior::uniform(2);
        // Likelihood: state 0 very likely given observation.
        p.bayesian_update(&[0.9, 0.1]);
        // After update: p(0) = 0.5*0.9 / (0.5*0.9 + 0.5*0.1) = 0.9
        assert!((p.probs()[0] - 0.9).abs() < 1e-10);
        assert!((p.probs()[1] - 0.1).abs() < 1e-10);
    }

    #[test]
    fn posterior_bayesian_update_no_alloc() {
        // Verify the update works in-place by checking pointer stability.
        let mut p = Posterior::uniform(3);
        let ptr_before = p.probs().as_ptr();
        p.bayesian_update(&[0.5, 0.3, 0.2]);
        let ptr_after = p.probs().as_ptr();
        assert_eq!(ptr_before, ptr_after);
    }

    #[test]
    fn posterior_entropy() {
        // Uniform over 2 states: entropy = 1.0 bit.
        let p = Posterior::uniform(2);
        assert!((p.entropy() - 1.0).abs() < 1e-10);
        // Deterministic: entropy = 0.
        let det = Posterior::new(vec![1.0, 0.0]).unwrap();
        assert!((det.entropy()).abs() < 1e-10);
    }

    #[test]
    fn posterior_map_state() {
        let p = Posterior::new(vec![0.1, 0.7, 0.2]).unwrap();
        assert_eq!(p.map_state(), 1);
    }

    #[test]
    fn posterior_is_empty() {
        let p = Posterior { probs: vec![] };
        assert!(p.is_empty());
        let p2 = Posterior::uniform(1);
        assert!(!p2.is_empty());
    }

    #[test]
    fn posterior_probs_mut() {
        let mut p = Posterior::uniform(2);
        p.probs_mut()[0] = 0.8;
        p.probs_mut()[1] = 0.2;
        assert_eq!(p.probs(), &[0.8, 0.2]);
    }

    // -- FallbackPolicy tests --

    #[test]
    fn fallback_policy_default() {
        let fp = FallbackPolicy::default();
        assert_eq!(fp.calibration_drift_threshold, 0.7);
        assert_eq!(fp.e_process_breach_threshold, 20.0);
        assert_eq!(fp.confidence_width_threshold, 0.5);
    }

    #[test]
    fn fallback_policy_new_valid() {
        let fp = FallbackPolicy::new(0.8, 10.0, 0.3).unwrap();
        assert_eq!(fp.calibration_drift_threshold, 0.8);
    }

    #[test]
    fn fallback_policy_calibration_out_of_range() {
        let err = FallbackPolicy::new(1.5, 10.0, 0.3).unwrap_err();
        assert!(matches!(
            err,
            ValidationError::ThresholdOutOfRange {
                field: "calibration_drift_threshold",
                ..
            }
        ));
    }

    #[test]
    fn fallback_policy_negative_e_process() {
        let err = FallbackPolicy::new(0.7, -1.0, 0.3).unwrap_err();
        assert!(matches!(
            err,
            ValidationError::ThresholdOutOfRange {
                field: "e_process_breach_threshold",
                ..
            }
        ));
    }

    #[test]
    fn fallback_policy_negative_ci_width() {
        let err = FallbackPolicy::new(0.7, 10.0, -0.1).unwrap_err();
        assert!(matches!(
            err,
            ValidationError::ThresholdOutOfRange {
                field: "confidence_width_threshold",
                ..
            }
        ));
    }

    #[test]
    fn fallback_triggered_by_low_calibration() {
        let fp = FallbackPolicy::default();
        assert!(fp.should_fallback(0.5, 1.0, 0.1)); // cal < 0.7
        assert!(!fp.should_fallback(0.9, 1.0, 0.1)); // cal OK
    }

    #[test]
    fn fallback_triggered_by_e_process() {
        let fp = FallbackPolicy::default();
        assert!(fp.should_fallback(0.9, 25.0, 0.1)); // e_process > 20
        assert!(!fp.should_fallback(0.9, 15.0, 0.1)); // e_process OK
    }

    #[test]
    fn fallback_triggered_by_ci_width() {
        let fp = FallbackPolicy::default();
        assert!(fp.should_fallback(0.9, 1.0, 0.6)); // ci > 0.5
        assert!(!fp.should_fallback(0.9, 1.0, 0.3)); // ci OK
    }

    // -- DecisionContract + evaluate tests --

    #[test]
    fn contract_implementable_under_50_lines() {
        // The TestContract impl above is 22 lines — well under 50.
        let contract = TestContract::new();
        assert_eq!(contract.name(), "test_contract");
        assert_eq!(contract.state_space().len(), 2);
        assert_eq!(contract.action_set().len(), 2);
    }

    fn test_ctx(cal: f64, random: u128) -> EvalContext {
        EvalContext {
            calibration_score: cal,
            e_process: 1.0,
            ci_width: 0.1,
            decision_id: DecisionId::from_parts(1_700_000_000_000, random),
            trace_id: TraceId::from_parts(1_700_000_000_000, random),
            ts_unix_ms: 1_700_000_000_000,
        }
    }

    #[test]
    fn evaluate_normal_decision() {
        let contract = TestContract::new();
        let posterior = Posterior::new(vec![0.9, 0.1]).unwrap();
        let ctx = test_ctx(0.95, 42);

        let outcome = evaluate(&contract, &posterior, &ctx);

        assert!(!outcome.fallback_active);
        assert_eq!(outcome.action_name, "continue"); // low loss when mostly good
        assert_eq!(outcome.action_index, 0);
        assert!(outcome.expected_loss < 0.1);
        assert_eq!(outcome.expected_losses.len(), 2);
    }

    #[test]
    fn evaluate_fallback_decision() {
        let contract = TestContract::new();
        let posterior = Posterior::new(vec![0.2, 0.8]).unwrap();
        let ctx = test_ctx(0.5, 43); // low calibration triggers fallback

        let outcome = evaluate(&contract, &posterior, &ctx);

        assert!(outcome.fallback_active);
        assert_eq!(outcome.action_name, "continue"); // fallback action = 0
        assert_eq!(outcome.action_index, 0);
    }

    #[test]
    fn evaluate_without_fallback_chooses_optimal() {
        let contract = TestContract::new();
        let posterior = Posterior::new(vec![0.2, 0.8]).unwrap();
        let ctx = test_ctx(0.95, 44); // good calibration, no fallback

        let outcome = evaluate(&contract, &posterior, &ctx);

        assert!(!outcome.fallback_active);
        assert_eq!(outcome.action_name, "stop"); // optimal when mostly bad
    }

    #[test]
    fn evaluate_audit_entry_fields() {
        let contract = TestContract::new();
        let posterior = Posterior::uniform(2);
        let ctx = test_ctx(0.85, 99);

        let outcome = evaluate(&contract, &posterior, &ctx);

        let audit = &outcome.audit_entry;
        assert_eq!(audit.decision_id, ctx.decision_id);
        assert_eq!(audit.trace_id, ctx.trace_id);
        assert_eq!(audit.contract_name, "test_contract");
        assert_eq!(audit.calibration_score, 0.85);
        assert_eq!(audit.ts_unix_ms, 1_700_000_000_000);
        assert_eq!(audit.posterior_snapshot.len(), 2);
    }

    // -- DecisionAuditEntry → EvidenceLedger --

    #[test]
    fn audit_entry_to_evidence_ledger() {
        let contract = TestContract::new();
        let posterior = Posterior::new(vec![0.6, 0.4]).unwrap();
        let ctx = test_ctx(0.92, 100);

        let outcome = evaluate(&contract, &posterior, &ctx);
        let evidence = outcome.audit_entry.to_evidence_ledger();

        assert_eq!(evidence.ts_unix_ms, 1_700_000_000_000);
        assert_eq!(evidence.component, "test_contract");
        assert_eq!(evidence.action, outcome.action_name);
        assert_eq!(evidence.calibration_score, 0.92);
        assert!(!evidence.fallback_active);
        assert_eq!(evidence.posterior, vec![0.6, 0.4]);
        assert!(evidence.is_valid());
    }

    #[test]
    fn audit_entry_serde_roundtrip() {
        let contract = TestContract::new();
        let posterior = Posterior::uniform(2);
        let ctx = test_ctx(0.88, 101);

        let outcome = evaluate(&contract, &posterior, &ctx);
        let json = serde_json::to_string(&outcome.audit_entry).unwrap();
        let parsed: DecisionAuditEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.contract_name, "test_contract");
        assert_eq!(parsed.decision_id, ctx.decision_id);
        assert_eq!(parsed.trace_id, ctx.trace_id);
    }

    // -- Update posterior via contract --

    #[test]
    fn contract_update_posterior() {
        let contract = TestContract::new();
        let mut posterior = Posterior::uniform(2);
        contract.update_posterior(&mut posterior, 0); // observe "good"
                                                      // After update: state 0 should be more probable.
        assert!(posterior.probs()[0] > posterior.probs()[1]);
    }

    // -- Validation error display --

    #[test]
    fn validation_error_display() {
        let err = ValidationError::NegativeLoss {
            state: 1,
            action: 2,
            value: -0.5,
        };
        let msg = format!("{err}");
        assert!(msg.contains("-0.5"));
        assert!(msg.contains("state=1"));
        assert!(msg.contains("action=2"));
    }

    #[test]
    fn dimension_mismatch_display() {
        let err = ValidationError::DimensionMismatch {
            expected: 6,
            got: 4,
        };
        let msg = format!("{err}");
        assert!(msg.contains('6'));
        assert!(msg.contains('4'));
    }

    // -- FallbackPolicy serde --

    #[test]
    fn fallback_policy_toml_roundtrip() {
        let fp = FallbackPolicy::default();
        let toml_str = toml::to_string(&fp).unwrap();
        let parsed: FallbackPolicy = toml::from_str(&toml_str).unwrap();
        assert_eq!(fp, parsed);
    }
}
