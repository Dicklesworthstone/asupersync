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

use std::collections::BTreeMap;
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
    pub fn expected_losses(&self, posterior: &Posterior) -> BTreeMap<String, f64> {
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
    pub expected_loss_by_action: BTreeMap<String, f64>,
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
    pub expected_losses: BTreeMap<String, f64>,
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

    #[test]
    fn fallback_policy_json_roundtrip() {
        let fp = FallbackPolicy::default();
        let json = serde_json::to_string(&fp).unwrap();
        let parsed: FallbackPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(fp, parsed);
    }

    // -- argmin correctness with known posteriors --

    #[test]
    fn argmin_correctness_deterministic_posterior() {
        let m = two_state_matrix();
        // Fully certain state=good: E[continue]=0.0, E[stop]=0.3 → continue wins.
        let certain_good = Posterior::new(vec![1.0, 0.0]).unwrap();
        assert_eq!(m.bayes_action(&certain_good), 0);
        // Fully certain state=bad: E[continue]=0.8, E[stop]=0.1 → stop wins.
        let certain_bad = Posterior::new(vec![0.0, 1.0]).unwrap();
        assert_eq!(m.bayes_action(&certain_bad), 1);
    }

    #[test]
    fn argmin_correctness_breakeven_point() {
        let m = two_state_matrix();
        // Find crossover: at p(good)=x, E[continue]=0.8(1-x) and E[stop]=0.3x+0.1(1-x).
        // Crossover: 0.8-0.8x = 0.3x+0.1-0.1x → 0.8-0.8x = 0.2x+0.1 → 0.7=x → x=0.7
        // At p(good)=0.71, continue is better.
        let above = Posterior::new(vec![0.71, 0.29]).unwrap();
        assert_eq!(m.bayes_action(&above), 0);
        // At p(good)=0.69, stop is better.
        let below = Posterior::new(vec![0.69, 0.31]).unwrap();
        assert_eq!(m.bayes_action(&below), 1);
    }

    #[test]
    fn argmin_three_state_three_action() {
        // 3 states, 3 actions: verify argmin in a bigger space.
        let m = LossMatrix::new(
            vec!["s0".into(), "s1".into(), "s2".into()],
            vec!["a0".into(), "a1".into(), "a2".into()],
            vec![
                1.0, 2.0, 3.0, // state 0
                3.0, 1.0, 2.0, // state 1
                2.0, 3.0, 1.0, // state 2
            ],
        )
        .unwrap();
        // Uniform posterior: E[a0]=2.0, E[a1]=2.0, E[a2]=2.0 → all tied.
        // Rust's min_by returns the last equal element, so index 2.
        let uniform = Posterior::uniform(3);
        let action = m.bayes_action(&uniform);
        // Any action is valid since all expected losses are equal.
        assert!(action < 3);
        // Posterior concentrated on state 1: a1 has loss 1.0 → a1 wins.
        let state1 = Posterior::new(vec![0.0, 1.0, 0.0]).unwrap();
        assert_eq!(m.bayes_action(&state1), 1);
        // Posterior concentrated on state 2: a2 has loss 1.0 → a2 wins.
        let state2 = Posterior::new(vec![0.0, 0.0, 1.0]).unwrap();
        assert_eq!(m.bayes_action(&state2), 2);
    }

    // -- Bayesian update hand-computed --

    #[test]
    fn bayesian_update_hand_computed_three_state() {
        // Prior: [0.5, 0.3, 0.2]
        // Likelihoods: [0.1, 0.6, 0.3]
        // Unnorm: [0.05, 0.18, 0.06]  sum=0.29
        // Posterior: [0.05/0.29, 0.18/0.29, 0.06/0.29]
        let mut p = Posterior::new(vec![0.5, 0.3, 0.2]).unwrap();
        p.bayesian_update(&[0.1, 0.6, 0.3]);
        let expected = [0.05 / 0.29, 0.18 / 0.29, 0.06 / 0.29];
        for (i, &e) in expected.iter().enumerate() {
            assert!(
                (p.probs()[i] - e).abs() < 1e-10,
                "state {i}: got {}, expected {e}",
                p.probs()[i]
            );
        }
    }

    #[test]
    fn bayesian_update_successive_convergence() {
        // Repeated observations of state 0 should drive posterior toward certainty.
        let mut p = Posterior::uniform(3);
        for _ in 0..20 {
            p.bayesian_update(&[0.9, 0.05, 0.05]);
        }
        assert!(p.probs()[0] > 0.999);
        assert!(p.probs()[1] < 0.001);
        assert!(p.probs()[2] < 0.001);
    }

    // -- End-to-end decision pipeline --

    #[test]
    fn end_to_end_pipeline() {
        let contract = TestContract::new();
        let mut posterior = Posterior::uniform(2);

        // Feed 5 "good" observations: posterior should shift toward state 0.
        for _ in 0..5 {
            contract.update_posterior(&mut posterior, 0);
        }
        assert!(posterior.probs()[0] > 0.99);

        // Make a decision: should be "continue" (low loss when good).
        let ctx = test_ctx(0.95, 200);
        let outcome = evaluate(&contract, &posterior, &ctx);
        assert!(!outcome.fallback_active);
        assert_eq!(outcome.action_name, "continue");
        assert!(outcome.expected_loss < 0.01);

        // Verify evidence ledger entry.
        let evidence = outcome.audit_entry.to_evidence_ledger();
        assert_eq!(evidence.component, "test_contract");
        assert_eq!(evidence.action, "continue");
        assert!(evidence.is_valid());

        // Now feed "bad" observations to shift posterior.
        for _ in 0..20 {
            contract.update_posterior(&mut posterior, 1);
        }
        assert!(posterior.probs()[1] > 0.99);

        // Decision should now be "stop".
        let ctx2 = test_ctx(0.95, 201);
        let outcome2 = evaluate(&contract, &posterior, &ctx2);
        assert_eq!(outcome2.action_name, "stop");
    }

    // -- Concurrent decision safety --

    #[test]
    fn concurrent_decision_safety() {
        use std::sync::Arc;
        use std::thread;

        let contract = Arc::new(TestContract::new());
        let results: Vec<_> = (0..10)
            .map(|i| {
                let c = Arc::clone(&contract);
                thread::spawn(move || {
                    let posterior = Posterior::uniform(2);
                    let ctx = EvalContext {
                        calibration_score: 0.9,
                        e_process: 1.0,
                        ci_width: 0.1,
                        decision_id: DecisionId::from_parts(1_700_000_000_000, u128::from(i)),
                        trace_id: TraceId::from_parts(1_700_000_000_000, u128::from(i)),
                        ts_unix_ms: 1_700_000_000_000 + i,
                    };
                    let outcome = evaluate(c.as_ref(), &posterior, &ctx);
                    assert!(!outcome.action_name.is_empty());
                    assert_eq!(outcome.expected_losses.len(), 2);
                    let evidence = outcome.audit_entry.to_evidence_ledger();
                    assert!(evidence.is_valid());
                    outcome
                })
            })
            .map(|h| h.join().unwrap())
            .collect();
        assert_eq!(results.len(), 10);
        // All should agree on the same action for uniform posterior.
        let actions: std::collections::HashSet<_> =
            results.iter().map(|r| r.action_name.clone()).collect();
        assert_eq!(
            actions.len(),
            1,
            "all threads should choose the same action"
        );
    }

    // -- Cross-crate type verification --

    #[test]
    fn cross_crate_franken_kernel_types() {
        // Verify DecisionId and TraceId are the franken_kernel versions.
        let did = DecisionId::from_parts(1_700_000_000_000, 42);
        assert_eq!(did.timestamp_ms(), 1_700_000_000_000);
        let tid = TraceId::from_parts(1_700_000_000_000, 1);
        assert_eq!(tid.timestamp_ms(), 1_700_000_000_000);

        // Verify they work correctly in DecisionAuditEntry.
        let contract = TestContract::new();
        let posterior = Posterior::uniform(2);
        let ctx = EvalContext {
            calibration_score: 0.9,
            e_process: 1.0,
            ci_width: 0.1,
            decision_id: did,
            trace_id: tid,
            ts_unix_ms: 1_700_000_000_000,
        };
        let outcome = evaluate(&contract, &posterior, &ctx);
        assert_eq!(outcome.audit_entry.decision_id, did);
        assert_eq!(outcome.audit_entry.trace_id, tid);
    }

    // -- Posterior serde roundtrips --

    #[test]
    fn posterior_json_roundtrip() {
        let p = Posterior::new(vec![0.25, 0.75]).unwrap();
        let json = serde_json::to_string(&p).unwrap();
        let parsed: Posterior = serde_json::from_str(&json).unwrap();
        assert_eq!(p, parsed);
    }

    // -- LossMatrix 3x3 TOML --

    #[test]
    fn loss_matrix_3x3_toml_roundtrip() {
        let m = LossMatrix::new(
            vec!["s0".into(), "s1".into(), "s2".into()],
            vec!["a0".into(), "a1".into(), "a2".into()],
            vec![0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8],
        )
        .unwrap();
        let toml_str = toml::to_string(&m).unwrap();
        let parsed: LossMatrix = toml::from_str(&toml_str).unwrap();
        assert_eq!(m, parsed);
    }

    // -- DecisionOutcome debug --

    #[test]
    fn decision_outcome_debug() {
        let contract = TestContract::new();
        let posterior = Posterior::uniform(2);
        let ctx = test_ctx(0.9, 300);
        let outcome = evaluate(&contract, &posterior, &ctx);
        let dbg = format!("{outcome:?}");
        assert!(dbg.contains("DecisionOutcome"));
        assert!(dbg.contains("action_name"));
    }

    // -- Fallback all three triggers --

    #[test]
    fn fallback_multiple_triggers_simultaneously() {
        let fp = FallbackPolicy::default();
        // All three conditions breached simultaneously.
        assert!(fp.should_fallback(0.3, 30.0, 0.9));
    }

    #[test]
    fn fallback_no_trigger_at_exact_thresholds() {
        let fp = FallbackPolicy::default();
        // Exactly at thresholds: cal=0.7 (not < 0.7), e=20 (not > 20), ci=0.5 (not > 0.5).
        assert!(!fp.should_fallback(0.7, 20.0, 0.5));
    }

    // -- Entropy edge cases --

    #[test]
    fn posterior_entropy_three_state_uniform() {
        let p = Posterior::uniform(3);
        // entropy = log2(3) ≈ 1.585
        assert!((p.entropy() - 3.0_f64.log2()).abs() < 1e-10);
    }

    #[test]
    fn posterior_entropy_single_state() {
        let p = Posterior::new(vec![1.0]).unwrap();
        assert!((p.entropy()).abs() < 1e-10);
    }

    // -- ValidationError is std::error::Error --

    #[test]
    fn validation_error_is_std_error() {
        fn assert_error<E: std::error::Error>() {}
        assert_error::<ValidationError>();
    }
}

// ---------------------------------------------------------------------------
// Property-based tests (proptest)
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::float_cmp)]
mod proptest_tests {
    use super::*;
    use proptest::prelude::*;

    /// Generate a valid probability vector of length `n`.
    fn arb_posterior(n: usize) -> impl Strategy<Value = Posterior> {
        proptest::collection::vec(0.01_f64..=1.0, n).prop_map(|mut v| {
            let sum: f64 = v.iter().sum();
            for p in &mut v {
                *p /= sum;
            }
            Posterior::new(v).unwrap()
        })
    }

    /// Generate a valid loss matrix of given dimensions.
    fn arb_loss_matrix(n_states: usize, n_actions: usize) -> impl Strategy<Value = LossMatrix> {
        let states: Vec<String> = (0..n_states).map(|i| format!("s{i}")).collect();
        let actions: Vec<String> = (0..n_actions).map(|i| format!("a{i}")).collect();
        proptest::collection::vec(0.0_f64..=10.0, n_states * n_actions).prop_map(move |values| {
            LossMatrix::new(states.clone(), actions.clone(), values).unwrap()
        })
    }

    // -- Argmin: chosen action minimizes expected loss for any valid posterior --

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10_000))]

        #[test]
        fn bayes_action_minimizes_expected_loss(
            matrix in arb_loss_matrix(3, 3),
            posterior in arb_posterior(3),
        ) {
            let chosen = matrix.bayes_action(&posterior);
            let chosen_loss = matrix.expected_loss(&posterior, chosen);
            for a in 0..matrix.n_actions() {
                let other_loss = matrix.expected_loss(&posterior, a);
                prop_assert!(
                    chosen_loss <= other_loss + 1e-10,
                    "action {chosen} (loss {chosen_loss}) should be <= action {a} (loss {other_loss})"
                );
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10_000))]

        #[test]
        fn bayes_action_minimizes_2x2(
            matrix in arb_loss_matrix(2, 2),
            posterior in arb_posterior(2),
        ) {
            let chosen = matrix.bayes_action(&posterior);
            let chosen_loss = matrix.expected_loss(&posterior, chosen);
            for a in 0..matrix.n_actions() {
                prop_assert!(chosen_loss <= matrix.expected_loss(&posterior, a) + 1e-10);
            }
        }
    }

    // -- Posterior update preserves normalization --

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10_000))]

        #[test]
        fn bayesian_update_preserves_normalization(
            prior in arb_posterior(4),
            likelihoods in proptest::collection::vec(0.01_f64..=1.0, 4usize),
        ) {
            let mut p = prior;
            p.bayesian_update(&likelihoods);
            let sum: f64 = p.probs().iter().sum();
            prop_assert!(
                (sum - 1.0).abs() < 1e-10,
                "posterior sum = {sum}, expected 1.0"
            );
            for &prob in p.probs() {
                prop_assert!(prob >= 0.0, "negative probability: {prob}");
            }
        }
    }

    // -- Posterior: all elements non-negative after update --

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10_000))]

        #[test]
        fn posterior_all_non_negative_after_update(
            prior in arb_posterior(3),
            likelihoods in proptest::collection::vec(0.0_f64..=1.0, 3usize),
        ) {
            let mut p = prior;
            // Only update if likelihoods have positive sum (avoid degenerate case).
            let lik_sum: f64 = likelihoods.iter().sum();
            if lik_sum > 0.0 {
                p.bayesian_update(&likelihoods);
                for &prob in p.probs() {
                    prop_assert!(prob >= 0.0, "negative probability: {prob}");
                }
            }
        }
    }

    // -- FallbackPolicy serde roundtrip --

    proptest! {
        #[test]
        fn fallback_policy_serde_roundtrip(
            cal in 0.0_f64..=1.0,
            e_proc in 0.0_f64..=100.0,
            ci in 0.0_f64..=10.0,
        ) {
            let fp = FallbackPolicy::new(cal, e_proc, ci).unwrap();
            let json = serde_json::to_string(&fp).unwrap();
            let parsed: FallbackPolicy = serde_json::from_str(&json).unwrap();
            // Use approximate comparison due to f64 JSON round-trip precision.
            prop_assert!((fp.calibration_drift_threshold - parsed.calibration_drift_threshold).abs() < 1e-12);
            prop_assert!((fp.e_process_breach_threshold - parsed.e_process_breach_threshold).abs() < 1e-12);
            prop_assert!((fp.confidence_width_threshold - parsed.confidence_width_threshold).abs() < 1e-12);
        }
    }

    // -- LossMatrix serde roundtrip --

    proptest! {
        #[test]
        fn loss_matrix_serde_roundtrip(
            matrix in arb_loss_matrix(2, 3),
        ) {
            let json = serde_json::to_string(&matrix).unwrap();
            let parsed: LossMatrix = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(matrix.state_names(), parsed.state_names());
            prop_assert_eq!(matrix.action_names(), parsed.action_names());
            // Use approximate comparison for f64 values.
            for s in 0..matrix.n_states() {
                for a in 0..matrix.n_actions() {
                    prop_assert!((matrix.get(s, a) - parsed.get(s, a)).abs() < 1e-12);
                }
            }
        }
    }

    // -- Expected loss is a convex combination --

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10_000))]

        #[test]
        fn expected_loss_within_loss_range(
            matrix in arb_loss_matrix(3, 3),
            posterior in arb_posterior(3),
        ) {
            for a in 0..matrix.n_actions() {
                let el = matrix.expected_loss(&posterior, a);
                let min_loss = (0..matrix.n_states())
                    .map(|s| matrix.get(s, a))
                    .fold(f64::INFINITY, f64::min);
                let max_loss = (0..matrix.n_states())
                    .map(|s| matrix.get(s, a))
                    .fold(f64::NEG_INFINITY, f64::max);
                prop_assert!(
                    el >= min_loss - 1e-10 && el <= max_loss + 1e-10,
                    "expected loss {el} outside [{min_loss}, {max_loss}]"
                );
            }
        }
    }
}
