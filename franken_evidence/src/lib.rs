//! Canonical EvidenceLedger schema for FrankenSuite decision tracing (bd-qaaxt.1).
//!
//! Every FrankenSuite decision produces an [`EvidenceLedger`] entry explaining
//! *what* was decided, *why*, and *how confident* the system was.  All
//! FrankenSuite projects import this crate — no forking allowed.
//!
//! # Schema
//!
//! ```text
//! EvidenceLedger
//! ├── ts_unix_ms          : u64       (millisecond timestamp)
//! ├── component           : String    (producing subsystem)
//! ├── action              : String    (decision taken)
//! ├── posterior            : Vec<f64>  (probability distribution, sums to ~1.0)
//! ├── expected_loss_by_action : BTreeMap<String, f64>  (loss per candidate action)
//! ├── chosen_expected_loss : f64      (loss of the selected action)
//! ├── calibration_score   : f64       (calibration quality, [0, 1])
//! ├── fallback_active     : bool      (true if fallback heuristic fired)
//! └── top_features        : Vec<(String, f64)>  (most influential features)
//! ```
//!
//! # Builder
//!
//! ```
//! use franken_evidence::EvidenceLedgerBuilder;
//!
//! let entry = EvidenceLedgerBuilder::new()
//!     .ts_unix_ms(1700000000000)
//!     .component("scheduler")
//!     .action("preempt")
//!     .posterior(vec![0.7, 0.2, 0.1])
//!     .expected_loss("preempt", 0.05)
//!     .expected_loss("continue", 0.3)
//!     .expected_loss("defer", 0.15)
//!     .chosen_expected_loss(0.05)
//!     .calibration_score(0.92)
//!     .fallback_active(false)
//!     .top_feature("queue_depth", 0.45)
//!     .top_feature("priority_gap", 0.30)
//!     .build()
//!     .expect("valid entry");
//! ```

#![forbid(unsafe_code)]

pub mod export;
pub mod render;

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};

// ---------------------------------------------------------------------------
// Core struct
// ---------------------------------------------------------------------------

/// A single evidence-ledger entry recording a FrankenSuite decision.
///
/// All fields use short serde names for compact JSONL serialization.
#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct EvidenceLedger {
    /// Millisecond Unix timestamp of the decision.
    #[serde(rename = "ts")]
    pub ts_unix_ms: u64,

    /// Subsystem that produced the evidence (e.g. "scheduler", "supervisor").
    #[serde(rename = "c")]
    pub component: String,

    /// Action that was chosen (e.g. "preempt", "restart").
    #[serde(rename = "a")]
    pub action: String,

    /// Posterior probability distribution over candidate outcomes.
    /// Must sum to approximately 1.0 (tolerance: 1e-6).
    #[serde(rename = "p")]
    pub posterior: Vec<f64>,

    /// Expected loss for each candidate action.
    #[serde(rename = "el")]
    pub expected_loss_by_action: BTreeMap<String, f64>,

    /// Expected loss of the *chosen* action.
    #[serde(rename = "cel")]
    pub chosen_expected_loss: f64,

    /// Calibration quality score in [0, 1].
    /// 1.0 = perfectly calibrated predictions.
    #[serde(rename = "cal")]
    pub calibration_score: f64,

    /// Whether a fallback heuristic was used instead of the primary model.
    #[serde(rename = "fb")]
    pub fallback_active: bool,

    /// Most influential features for this decision, sorted by importance.
    #[serde(rename = "tf")]
    pub top_features: Vec<(String, f64)>,
}

#[derive(Deserialize)]
struct EvidenceLedgerRepr {
    #[serde(rename = "ts")]
    ts_unix_ms: u64,
    #[serde(rename = "c")]
    component: String,
    #[serde(rename = "a")]
    action: String,
    #[serde(rename = "p")]
    posterior: Vec<f64>,
    #[serde(rename = "el")]
    expected_loss_by_action: BTreeMap<String, f64>,
    #[serde(rename = "cel")]
    chosen_expected_loss: f64,
    #[serde(rename = "cal")]
    calibration_score: f64,
    #[serde(rename = "fb")]
    fallback_active: bool,
    #[serde(rename = "tf")]
    top_features: Vec<(String, f64)>,
}

impl From<EvidenceLedgerRepr> for EvidenceLedger {
    fn from(repr: EvidenceLedgerRepr) -> Self {
        Self {
            ts_unix_ms: repr.ts_unix_ms,
            component: repr.component,
            action: repr.action,
            posterior: repr.posterior,
            expected_loss_by_action: repr.expected_loss_by_action,
            chosen_expected_loss: repr.chosen_expected_loss,
            calibration_score: repr.calibration_score,
            fallback_active: repr.fallback_active,
            top_features: repr.top_features,
        }
    }
}

impl<'de> Deserialize<'de> for EvidenceLedger {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let entry = Self::from(EvidenceLedgerRepr::deserialize(deserializer)?);
        let errors = entry.validate();
        if errors.is_empty() {
            Ok(entry)
        } else {
            Err(serde::de::Error::custom(format!(
                "invalid evidence ledger: {}",
                errors
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("; ")
            )))
        }
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validation error for an [`EvidenceLedger`] entry.
#[derive(Clone, Debug, PartialEq)]
pub enum ValidationError {
    /// `posterior` does not sum to ~1.0. Contains the actual sum.
    PosteriorNotNormalized {
        /// Actual sum of the posterior vector.
        sum: f64,
    },
    /// `posterior` is empty.
    PosteriorEmpty,
    /// `posterior` contains a negative or non-finite probability.
    InvalidPosteriorProbability {
        /// Index of the invalid probability.
        index: usize,
        /// The invalid probability value.
        value: f64,
    },
    /// An expected-loss value is non-finite.
    InvalidExpectedLoss {
        /// The action whose loss is invalid.
        action: String,
        /// The invalid loss value.
        value: f64,
    },
    /// `calibration_score` is outside [0, 1].
    CalibrationOutOfRange {
        /// The out-of-range value.
        value: f64,
    },
    /// An expected-loss value is negative.
    NegativeExpectedLoss {
        /// The action whose loss is negative.
        action: String,
        /// The negative loss value.
        value: f64,
    },
    /// `chosen_expected_loss` is negative.
    NegativeChosenExpectedLoss {
        /// The negative loss value.
        value: f64,
    },
    /// `chosen_expected_loss` is non-finite.
    InvalidChosenExpectedLoss {
        /// The invalid loss value.
        value: f64,
    },
    /// `expected_loss_by_action` is populated but does not include the chosen action.
    ChosenActionMissingExpectedLoss {
        /// The chosen action that is missing from the map.
        action: String,
    },
    /// `chosen_expected_loss` disagrees with the chosen action's mapped loss.
    ChosenExpectedLossMismatch {
        /// The chosen action whose loss disagrees.
        action: String,
        /// The value recorded in `chosen_expected_loss`.
        chosen: f64,
        /// The value recorded in `expected_loss_by_action`.
        mapped: f64,
    },
    /// `component` is empty.
    EmptyComponent,
    /// `action` is empty.
    EmptyAction,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PosteriorNotNormalized { sum } => {
                write!(f, "posterior sums to {sum}, expected ~1.0")
            }
            Self::PosteriorEmpty => write!(f, "posterior must not be empty"),
            Self::InvalidPosteriorProbability { index, value } => {
                write!(
                    f,
                    "posterior[{index}] must be finite and non-negative, got {value}"
                )
            }
            Self::InvalidExpectedLoss { action, value } => {
                write!(
                    f,
                    "expected_loss for '{action}' must be finite, got {value}"
                )
            }
            Self::CalibrationOutOfRange { value } => {
                write!(f, "calibration_score {value} not in [0, 1]")
            }
            Self::NegativeExpectedLoss { action, value } => {
                write!(f, "expected_loss for '{action}' is negative: {value}")
            }
            Self::NegativeChosenExpectedLoss { value } => {
                write!(f, "chosen_expected_loss is negative: {value}")
            }
            Self::InvalidChosenExpectedLoss { value } => {
                write!(f, "chosen_expected_loss must be finite, got {value}")
            }
            Self::ChosenActionMissingExpectedLoss { action } => {
                write!(
                    f,
                    "expected_loss_by_action is missing the chosen action '{action}'"
                )
            }
            Self::ChosenExpectedLossMismatch {
                action,
                chosen,
                mapped,
            } => {
                write!(
                    f,
                    "chosen_expected_loss {chosen} disagrees with expected_loss_by_action['{action}']={mapped}"
                )
            }
            Self::EmptyComponent => write!(f, "component must not be empty"),
            Self::EmptyAction => write!(f, "action must not be empty"),
        }
    }
}

impl std::error::Error for ValidationError {}

impl EvidenceLedger {
    /// Validate all invariants and return any violations.
    ///
    /// - `posterior` must be non-empty and sum to ~1.0 (tolerance 1e-6).
    /// - Posterior entries must be finite and non-negative.
    /// - `calibration_score` must be in [0, 1].
    /// - All expected losses must be finite and non-negative.
    /// - `component` and `action` must be non-empty.
    pub fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();

        if self.component.is_empty() {
            errors.push(ValidationError::EmptyComponent);
        }
        if self.action.is_empty() {
            errors.push(ValidationError::EmptyAction);
        }

        if self.posterior.is_empty() {
            errors.push(ValidationError::PosteriorEmpty);
        } else {
            let mut posterior_has_invalid_entry = false;
            for (index, &value) in self.posterior.iter().enumerate() {
                if !value.is_finite() || value < 0.0 {
                    errors.push(ValidationError::InvalidPosteriorProbability { index, value });
                    posterior_has_invalid_entry = true;
                }
            }
            if !posterior_has_invalid_entry {
                let sum: f64 = self.posterior.iter().sum();
                if (sum - 1.0).abs() > 1e-6 {
                    errors.push(ValidationError::PosteriorNotNormalized { sum });
                }
            }
        }

        if !(0.0..=1.0).contains(&self.calibration_score) {
            errors.push(ValidationError::CalibrationOutOfRange {
                value: self.calibration_score,
            });
        }

        let chosen_expected_loss_valid = if !self.chosen_expected_loss.is_finite() {
            errors.push(ValidationError::InvalidChosenExpectedLoss {
                value: self.chosen_expected_loss,
            });
            false
        } else if self.chosen_expected_loss < 0.0 {
            errors.push(ValidationError::NegativeChosenExpectedLoss {
                value: self.chosen_expected_loss,
            });
            false
        } else {
            true
        };

        for (action, &loss) in &self.expected_loss_by_action {
            if !loss.is_finite() {
                errors.push(ValidationError::InvalidExpectedLoss {
                    action: action.clone(),
                    value: loss,
                });
            } else if loss < 0.0 {
                errors.push(ValidationError::NegativeExpectedLoss {
                    action: action.clone(),
                    value: loss,
                });
            }
        }

        if let Some(&mapped) = self.expected_loss_by_action.get(&self.action) {
            if chosen_expected_loss_valid
                && mapped.is_finite()
                && mapped >= 0.0
                && (mapped - self.chosen_expected_loss).abs() > 1e-12
            {
                errors.push(ValidationError::ChosenExpectedLossMismatch {
                    action: self.action.clone(),
                    chosen: self.chosen_expected_loss,
                    mapped,
                });
            }
        } else if !self.expected_loss_by_action.is_empty() {
            errors.push(ValidationError::ChosenActionMissingExpectedLoss {
                action: self.action.clone(),
            });
        }

        errors
    }

    /// Returns `true` if this entry passes all validation checks.
    pub fn is_valid(&self) -> bool {
        self.validate().is_empty()
    }
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Builder error returned when a required field is missing.
#[derive(Clone, Debug, PartialEq)]
pub enum BuilderError {
    /// A required field was not set.
    MissingField {
        /// Name of the missing field.
        field: &'static str,
    },
    /// The constructed entry failed validation.
    Validation(Vec<ValidationError>),
}

impl fmt::Display for BuilderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingField { field } => {
                write!(f, "EvidenceLedger builder missing required field: {field}")
            }
            Self::Validation(errors) => {
                write!(f, "EvidenceLedger validation failed: ")?;
                for (i, e) in errors.iter().enumerate() {
                    if i > 0 {
                        write!(f, "; ")?;
                    }
                    write!(f, "{e}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for BuilderError {}

/// Ergonomic builder for [`EvidenceLedger`] entries.
///
/// All fields except `fallback_active` (defaults to `false`) are required.
#[derive(Clone, Debug, Default)]
#[must_use]
pub struct EvidenceLedgerBuilder {
    ts_unix_ms: Option<u64>,
    component: Option<String>,
    action: Option<String>,
    posterior: Option<Vec<f64>>,
    expected_loss_by_action: BTreeMap<String, f64>,
    chosen_expected_loss: Option<f64>,
    calibration_score: Option<f64>,
    fallback_active: bool,
    top_features: Vec<(String, f64)>,
}

impl EvidenceLedgerBuilder {
    /// Create a new builder with all fields unset.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the millisecond Unix timestamp.
    pub fn ts_unix_ms(mut self, ts: u64) -> Self {
        self.ts_unix_ms = Some(ts);
        self
    }

    /// Set the producing component/subsystem name.
    pub fn component(mut self, component: impl Into<String>) -> Self {
        self.component = Some(component.into());
        self
    }

    /// Set the chosen action.
    pub fn action(mut self, action: impl Into<String>) -> Self {
        self.action = Some(action.into());
        self
    }

    /// Set the posterior probability distribution.
    pub fn posterior(mut self, posterior: Vec<f64>) -> Self {
        self.posterior = Some(posterior);
        self
    }

    /// Add an expected-loss entry for a candidate action.
    pub fn expected_loss(mut self, action: impl Into<String>, loss: f64) -> Self {
        self.expected_loss_by_action.insert(action.into(), loss);
        self
    }

    /// Set the expected loss of the chosen action.
    pub fn chosen_expected_loss(mut self, loss: f64) -> Self {
        self.chosen_expected_loss = Some(loss);
        self
    }

    /// Set the calibration score (must be in [0, 1]).
    pub fn calibration_score(mut self, score: f64) -> Self {
        self.calibration_score = Some(score);
        self
    }

    /// Set whether the fallback heuristic was active.
    pub fn fallback_active(mut self, active: bool) -> Self {
        self.fallback_active = active;
        self
    }

    /// Add a top-feature entry (feature name + importance weight).
    pub fn top_feature(mut self, name: impl Into<String>, weight: f64) -> Self {
        self.top_features.push((name.into(), weight));
        self
    }

    /// Consume the builder and produce a validated [`EvidenceLedger`].
    ///
    /// Returns [`BuilderError::MissingField`] if any required field is unset,
    /// or [`BuilderError::Validation`] if invariants are violated.
    pub fn build(self) -> Result<EvidenceLedger, BuilderError> {
        let entry = EvidenceLedger {
            ts_unix_ms: self.ts_unix_ms.ok_or(BuilderError::MissingField {
                field: "ts_unix_ms",
            })?,
            component: self
                .component
                .ok_or(BuilderError::MissingField { field: "component" })?,
            action: self
                .action
                .ok_or(BuilderError::MissingField { field: "action" })?,
            posterior: self
                .posterior
                .ok_or(BuilderError::MissingField { field: "posterior" })?,
            expected_loss_by_action: self.expected_loss_by_action,
            chosen_expected_loss: self
                .chosen_expected_loss
                .ok_or(BuilderError::MissingField {
                    field: "chosen_expected_loss",
                })?,
            calibration_score: self.calibration_score.ok_or(BuilderError::MissingField {
                field: "calibration_score",
            })?,
            fallback_active: self.fallback_active,
            top_features: self.top_features,
        };

        let errors = entry.validate();
        if errors.is_empty() {
            Ok(entry)
        } else {
            Err(BuilderError::Validation(errors))
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::float_cmp)]
mod tests {
    use super::*;

    fn valid_builder() -> EvidenceLedgerBuilder {
        EvidenceLedgerBuilder::new()
            .ts_unix_ms(1_700_000_000_000)
            .component("scheduler")
            .action("preempt")
            .posterior(vec![0.7, 0.2, 0.1])
            .expected_loss("preempt", 0.05)
            .expected_loss("continue", 0.3)
            .expected_loss("defer", 0.15)
            .chosen_expected_loss(0.05)
            .calibration_score(0.92)
            .fallback_active(false)
            .top_feature("queue_depth", 0.45)
            .top_feature("priority_gap", 0.30)
    }

    fn expect_validation(result: Result<EvidenceLedger, BuilderError>) -> Vec<ValidationError> {
        match result.unwrap_err() {
            BuilderError::Validation(errors) => errors,
            BuilderError::MissingField { field } => {
                panic!("expected Validation error, got MissingField({field})")
            }
        }
    }

    #[test]
    fn builder_produces_valid_entry() {
        let entry = valid_builder().build().expect("should build");
        assert!(entry.is_valid());
        assert_eq!(entry.ts_unix_ms, 1_700_000_000_000);
        assert_eq!(entry.component, "scheduler");
        assert_eq!(entry.action, "preempt");
        assert_eq!(entry.posterior, vec![0.7, 0.2, 0.1]);
        assert!(!entry.fallback_active);
        assert_eq!(entry.top_features.len(), 2);
    }

    #[test]
    fn serde_roundtrip_json() {
        let entry = valid_builder().build().unwrap();
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: EvidenceLedger = serde_json::from_str(&json).unwrap();
        assert_eq!(entry.ts_unix_ms, parsed.ts_unix_ms);
        assert_eq!(entry.component, parsed.component);
        assert_eq!(entry.action, parsed.action);
        assert_eq!(entry.posterior, parsed.posterior);
        assert_eq!(entry.calibration_score, parsed.calibration_score);
        assert_eq!(entry.chosen_expected_loss, parsed.chosen_expected_loss);
        assert_eq!(entry.fallback_active, parsed.fallback_active);
        assert_eq!(entry.top_features, parsed.top_features);
    }

    #[test]
    fn serde_uses_short_field_names() {
        let entry = valid_builder().build().unwrap();
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"ts\":"));
        assert!(json.contains("\"c\":"));
        assert!(json.contains("\"a\":"));
        assert!(json.contains("\"p\":"));
        assert!(json.contains("\"el\":"));
        assert!(json.contains("\"cel\":"));
        assert!(json.contains("\"cal\":"));
        assert!(json.contains("\"fb\":"));
        assert!(json.contains("\"tf\":"));
        // Must NOT contain long field names.
        assert!(!json.contains("\"ts_unix_ms\":"));
        assert!(!json.contains("\"component\":"));
        assert!(!json.contains("\"posterior\":"));
    }

    #[test]
    fn validation_posterior_not_normalized() {
        let errors = expect_validation(
            valid_builder()
                .posterior(vec![0.5, 0.2, 0.1]) // sums to 0.8
                .build(),
        );
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ValidationError::PosteriorNotNormalized { .. }))
        );
    }

    #[test]
    fn validation_posterior_empty() {
        let errors = expect_validation(valid_builder().posterior(vec![]).build());
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ValidationError::PosteriorEmpty))
        );
    }

    #[test]
    fn validation_negative_posterior_probability() {
        let errors = expect_validation(valid_builder().posterior(vec![-0.1, 0.2, 0.9]).build());
        assert!(errors.iter().any(|e| matches!(
            e,
            ValidationError::InvalidPosteriorProbability { index: 0, value }
                if *value == -0.1
        )));
    }

    #[test]
    fn validation_non_finite_posterior_probability() {
        let errors = expect_validation(valid_builder().posterior(vec![f64::NAN, 0.2, 0.8]).build());
        assert!(errors.iter().any(|e| matches!(
            e,
            ValidationError::InvalidPosteriorProbability { index: 0, value }
                if value.is_nan()
        )));
    }

    #[test]
    fn validation_calibration_out_of_range() {
        let errors = expect_validation(valid_builder().calibration_score(1.5).build());
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ValidationError::CalibrationOutOfRange { .. }))
        );
    }

    #[test]
    fn validation_negative_expected_loss() {
        let errors = expect_validation(valid_builder().expected_loss("bad_action", -0.1).build());
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ValidationError::NegativeExpectedLoss { .. }))
        );
    }

    #[test]
    fn validation_non_finite_expected_loss() {
        let errors = expect_validation(
            valid_builder()
                .expected_loss("bad_action", f64::NAN)
                .build(),
        );
        assert!(errors.iter().any(|e| matches!(
            e,
            ValidationError::InvalidExpectedLoss { action, value }
                if action == "bad_action" && value.is_nan()
        )));
    }

    #[test]
    fn validation_negative_chosen_expected_loss() {
        let errors = expect_validation(valid_builder().chosen_expected_loss(-0.01).build());
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ValidationError::NegativeChosenExpectedLoss { .. }))
        );
    }

    #[test]
    fn validation_non_finite_chosen_expected_loss() {
        let errors = expect_validation(valid_builder().chosen_expected_loss(f64::INFINITY).build());
        assert!(errors.iter().any(|e| matches!(
            e,
            ValidationError::InvalidChosenExpectedLoss { value } if value.is_infinite()
        )));
    }

    #[test]
    fn validation_missing_chosen_action_expected_loss() {
        let errors = expect_validation(valid_builder().action("restart").build());
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ValidationError::ChosenActionMissingExpectedLoss { .. }))
        );
    }

    #[test]
    fn validation_chosen_expected_loss_mismatch() {
        let errors = expect_validation(valid_builder().expected_loss("preempt", 0.20).build());
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ValidationError::ChosenExpectedLossMismatch { .. }))
        );
    }

    #[test]
    fn validation_empty_component() {
        let errors = expect_validation(valid_builder().component("").build());
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ValidationError::EmptyComponent))
        );
    }

    #[test]
    fn validation_empty_action() {
        let errors = expect_validation(valid_builder().action("").build());
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ValidationError::EmptyAction))
        );
    }

    #[test]
    fn builder_missing_required_field() {
        let result = EvidenceLedgerBuilder::new()
            .component("x")
            .action("y")
            .posterior(vec![1.0])
            .chosen_expected_loss(0.0)
            .calibration_score(0.5)
            .build();
        let err = result.unwrap_err();
        assert!(matches!(
            err,
            BuilderError::MissingField {
                field: "ts_unix_ms"
            }
        ));
    }

    #[test]
    fn builder_default_fallback_is_false() {
        let entry = valid_builder().build().unwrap();
        assert!(!entry.fallback_active);
    }

    #[test]
    fn builder_fallback_active_true() {
        let entry = valid_builder().fallback_active(true).build().unwrap();
        assert!(entry.fallback_active);
    }

    #[test]
    fn posterior_tolerance_accepts_near_one() {
        // Sum = 1.0 - 5e-7 (within 1e-6 tolerance).
        let entry = valid_builder()
            .posterior(vec![0.5, 0.3, 0.199_999_5])
            .build();
        assert!(entry.is_ok());
    }

    #[test]
    fn posterior_tolerance_rejects_beyond() {
        // Sum = 0.9 (well outside tolerance).
        let result = valid_builder().posterior(vec![0.5, 0.3, 0.1]).build();
        assert!(result.is_err());
    }

    #[test]
    fn derive_clone_and_debug() {
        let entry = valid_builder().build().unwrap();
        let cloned = entry.clone();
        assert_eq!(format!("{entry:?}"), format!("{cloned:?}"));
    }

    #[test]
    fn jsonl_compact_output() {
        let entry = valid_builder().build().unwrap();
        let line = serde_json::to_string(&entry).unwrap();
        // JSONL: single line, no embedded newlines.
        assert!(!line.contains('\n'));
        // Should be reasonably compact (under 300 bytes for this test entry).
        assert!(
            line.len() < 300,
            "JSONL line too large: {} bytes",
            line.len()
        );
    }

    #[test]
    fn compact_json_snapshot() {
        let entry = valid_builder().build().unwrap();
        let line = serde_json::to_string(&entry).unwrap();
        insta::assert_snapshot!("evidence_ledger_compact_json", line);
    }

    #[test]
    fn deserialize_from_known_json() {
        let json = r#"{"ts":1700000000000,"c":"test","a":"act","p":[0.6,0.4],"el":{"act":0.1},"cel":0.1,"cal":0.8,"fb":false,"tf":[["feat",0.9]]}"#;
        let entry: EvidenceLedger = serde_json::from_str(json).unwrap();
        assert_eq!(entry.ts_unix_ms, 1_700_000_000_000);
        assert_eq!(entry.component, "test");
        assert_eq!(entry.action, "act");
        assert_eq!(entry.posterior, vec![0.6, 0.4]);
        assert_eq!(entry.calibration_score, 0.8);
        assert!(!entry.fallback_active);
        assert_eq!(entry.top_features, vec![("feat".to_string(), 0.9)]);
    }

    #[test]
    fn deserialize_invalid_json_rejected() {
        let json = r#"{"ts":1700000000000,"c":"test","a":"act","p":[0.6,0.4],"el":{"act":-0.1},"cel":-0.1,"cal":0.8,"fb":false,"tf":[["feat",0.9]]}"#;
        let err = serde_json::from_str::<EvidenceLedger>(json).unwrap_err();
        assert!(err.to_string().contains("invalid evidence ledger"));
    }

    #[test]
    fn validation_error_display() {
        let err = ValidationError::PosteriorNotNormalized { sum: 0.5 };
        let msg = format!("{err}");
        assert!(msg.contains("0.5"));
        assert!(msg.contains("~1.0"));
    }

    #[test]
    fn builder_error_display() {
        let err = BuilderError::MissingField { field: "component" };
        let msg = format!("{err}");
        assert!(msg.contains("component"));
    }
}
