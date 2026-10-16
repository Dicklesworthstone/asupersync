#![allow(clippy::all)]
//! Canonical structured test logging schema for RaptorQ test runs.
//!
//! Defines versioned, serializable log entry types for both unit tests and E2E
//! pipeline tests. Every RaptorQ test path emits entries conforming to these
//! schemas so that failures are forensically diagnosable from a single artifact
//! bundle.
//!
//! # Schema versions
//!
//! | Schema | Constant | Purpose |
//! |--------|----------|---------|
//! | `raptorq-e2e-log-v1` | [`E2E_LOG_SCHEMA_VERSION`] | Full pipeline E2E reports |
//! | `raptorq-unit-log-v1` | [`UNIT_LOG_SCHEMA_VERSION`] | Lightweight unit test entries |
//!
//! # Required fields (contract)
//!
//! Every log entry — unit or E2E — MUST include:
//! - `schema_version`: exact match to the corresponding constant
//! - `scenario_id`: canonical scenario identifier (e.g. `RQ-E2E-SYSTEMATIC-ONLY`)
//! - `seed`: deterministic root seed for reproducibility
//! - `repro_command`: a shell command that reproduces the exact test case
//!
//! E2E entries additionally require: `run_id`, `replay_id`, `profile`,
//! `phase_markers`, `assertion_id`, `unit_sentinel`, plus nested config/loss/
//! symbols/outcome/proof sub-objects.
//!
//! # Contract validation
//!
//! [`validate_e2e_log_json`] and [`validate_unit_log_json`] check that a
//! serialized JSON entry satisfies the schema contract. They return a list of
//! violations (empty = pass). Schema contract tests call these validators and
//! fail the run if any required field is missing or has the wrong type/version.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

// ============================================================================
// Schema version constants
// ============================================================================

/// Schema version for full E2E pipeline log entries.
pub const E2E_LOG_SCHEMA_VERSION: &str = "raptorq-e2e-log-v1";

/// Schema version for lightweight unit test log entries.
pub const UNIT_LOG_SCHEMA_VERSION: &str = "raptorq-unit-log-v1";

/// Valid profile markers for E2E test runs.
pub const VALID_PROFILES: &[&str] = &["fast", "full", "forensics"];

/// Valid outcome markers for unit test log entries.
pub const VALID_UNIT_OUTCOMES: &[&str] = &[
    "pending",
    "ok",
    "fail",
    "decode_failure",
    "symbol_mismatch",
    "error",
    "cancelled",
];

/// Required phase marker set for E2E log entries.
pub const REQUIRED_PHASE_MARKERS: &[&str] = &["encode", "loss", "decode", "proof", "report"];

const GOVERNANCE_STATE_KEYS: &[&str] = &["healthy", "degraded", "regression", "unknown"];
const GOVERNANCE_ACTION_KEYS: &[&str] = &["continue", "canary_hold", "rollback", "fallback"];
const GOVERNANCE_PERMILLE_SCALE: u64 = 1000;

// ============================================================================
// E2E log entry — full pipeline report
// ============================================================================

/// Full structured log entry for an E2E RaptorQ pipeline test run.
///
/// Captures every dimension needed for failure forensics: configuration, loss
/// pattern, symbol counts, decode outcome, proof statistics, and repro context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct E2eLogEntry {
    /// Schema version string — must equal [`E2E_LOG_SCHEMA_VERSION`].
    pub schema_version: String,
    /// Human-readable scenario name (e.g. `"systematic_only"`).
    pub scenario: String,
    /// Canonical scenario identifier (e.g. `"RQ-E2E-SYSTEMATIC-ONLY"`).
    pub scenario_id: String,
    /// Replay catalog reference (e.g. `"replay:rq-e2e-systematic-only-v1"`).
    pub replay_id: String,
    /// Profile marker: `"fast"`, `"full"`, or `"forensics"`.
    pub profile: String,
    /// Linked unit test sentinel (file::function).
    pub unit_sentinel: String,
    /// Assertion identifier for traceability.
    pub assertion_id: String,
    /// Deterministic run identifier derived from replay_id + seed + params.
    pub run_id: String,
    /// Shell command to reproduce this exact test case.
    pub repro_command: String,
    /// Ordered phase markers tracking pipeline stages executed.
    pub phase_markers: Vec<String>,
    /// Encoding/decoding configuration.
    pub config: LogConfigReport,
    /// Loss pattern applied during the test.
    pub loss: LogLossReport,
    /// Symbol generation and reception counts.
    pub symbols: LogSymbolReport,
    /// Decode outcome (success/failure with reason).
    pub outcome: LogOutcomeReport,
    /// Decode proof statistics and hash.
    pub proof: LogProofReport,
}

/// Encoding/decoding configuration captured in a log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfigReport {
    /// Symbol size in bytes.
    pub symbol_size: u16,
    /// Maximum block size.
    pub max_block_size: usize,
    /// Repair overhead ratio.
    pub repair_overhead: f64,
    /// Minimum overhead for decoder.
    pub min_overhead: usize,
    /// Deterministic seed for this block.
    pub seed: u64,
    /// Source symbols per block (K).
    pub block_k: usize,
    /// Number of blocks.
    pub block_count: usize,
    /// Total data length in bytes.
    pub data_len: usize,
}

/// Loss pattern description in a log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogLossReport {
    /// Loss kind: `"none"`, `"random"`, `"burst"`, or `"insufficient"`.
    pub kind: String,
    /// Loss-pattern seed (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seed: Option<u64>,
    /// Drop rate in per-mille (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub drop_per_mille: Option<u16>,
    /// Number of symbols dropped.
    pub drop_count: usize,
    /// Number of symbols kept.
    pub keep_count: usize,
    /// Burst start index (if burst loss).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub burst_start: Option<usize>,
    /// Burst length (if burst loss).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub burst_len: Option<usize>,
}

/// Symbol generation and reception counts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogSymbolCounts {
    /// Total symbols.
    pub total: usize,
    /// Source symbols.
    pub source: usize,
    /// Repair symbols.
    pub repair: usize,
}

/// Symbol report with generated and received counts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogSymbolReport {
    /// Symbols generated by the encoder.
    pub generated: LogSymbolCounts,
    /// Symbols received by the decoder (after loss).
    pub received: LogSymbolCounts,
}

/// Decode outcome report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogOutcomeReport {
    /// Whether decoding succeeded.
    pub success: bool,
    /// Rejection reason (if decode failed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reject_reason: Option<String>,
    /// Number of bytes successfully decoded.
    pub decoded_bytes: usize,
}

/// Decode proof statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogProofReport {
    /// Content hash of the proof.
    pub hash: u64,
    /// Proof summary size in bytes.
    pub summary_bytes: usize,
    /// Proof outcome string.
    pub outcome: String,
    /// Total received symbols (equations).
    pub received_total: usize,
    /// Source symbols received.
    pub received_source: usize,
    /// Repair symbols received.
    pub received_repair: usize,
    /// Symbols solved by peeling.
    pub peeling_solved: usize,
    /// Symbols resolved by inactivation.
    pub inactivated: usize,
    /// Pivot selections during elimination.
    pub pivots: usize,
    /// Row operations during Gaussian elimination.
    pub row_ops: usize,
    /// Total equations used in decoding.
    pub equations_used: usize,
}

// ============================================================================
// E2E Log Entry methods
// ============================================================================

impl E2eLogEntry {
    /// Serialize to JSON string.
    ///
    /// br-asupersync-zmzwof: gated to `cfg(test)` because the only callers
    /// are inside this module's test suite — keeping it `pub` on the prod
    /// crate surface invites accidental serialization of test-only schemas.
    #[cfg(any(test, feature = "test-internals"))]
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Serialize to pretty-printed JSON string.
    #[cfg(any(test, feature = "test-internals"))]
    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

// ============================================================================
// Unit test log entry — lightweight
// ============================================================================

/// Lightweight structured log entry for RaptorQ unit tests.
///
/// Contains the minimum fields needed for failure triage and deterministic
/// replay without the full pipeline context of an E2E entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnitLogEntry {
    /// Schema version string — must equal [`UNIT_LOG_SCHEMA_VERSION`].
    pub schema_version: String,
    /// Canonical scenario identifier.
    pub scenario_id: String,
    /// Deterministic seed.
    pub seed: u64,
    /// Encoded parameter set description (e.g. `"symbol_size=256,k=16"`).
    pub parameter_set: String,
    /// Replay catalog reference.
    pub replay_ref: String,
    /// Shell command to reproduce this test case.
    pub repro_command: String,
    /// Test outcome: one of [`VALID_UNIT_OUTCOMES`].
    pub outcome: String,
    /// Artifact path for forensic artifacts (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_path: Option<String>,
    /// Decode statistics (if decode was attempted).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decode_stats: Option<UnitDecodeStats>,
}

/// Lightweight decode statistics for unit test log entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnitDecodeStats {
    /// Source symbol count (K).
    pub k: usize,
    /// Loss percentage applied.
    pub loss_pct: usize,
    /// Number of symbols dropped.
    pub dropped: usize,
    /// Symbols solved by peeling.
    pub peeled: usize,
    /// Symbols resolved by inactivation.
    pub inactivated: usize,
    /// Gaussian elimination operations.
    pub gauss_ops: usize,
    /// Pivots selected during elimination.
    pub pivots: usize,
    /// Number of equation indices pushed into peel queue.
    pub peel_queue_pushes: usize,
    /// Number of equation indices popped from peel queue.
    pub peel_queue_pops: usize,
    /// Maximum queue depth seen during peel propagation.
    pub peel_frontier_peak: usize,
    /// Dense-core row count sent to elimination.
    pub dense_core_rows: usize,
    /// Dense-core column count sent to elimination.
    pub dense_core_cols: usize,
    /// Zero-information rows dropped before elimination.
    pub dense_core_dropped_rows: usize,
    /// Deterministic fallback reason recorded by decode pipeline.
    pub fallback_reason: String,
    /// True when hard-regime elimination was activated.
    pub hard_regime_activated: bool,
    /// Deterministic hard-regime branch label (`markowitz`/`block_schur_low_rank`).
    pub hard_regime_branch: String,
    /// Number of conservative hard-regime fallback transitions.
    pub hard_regime_fallbacks: usize,
    /// Deterministic conservative fallback reason for accelerated hard-regime paths.
    pub conservative_fallback_reason: String,
    /// Optional G7 governance decision payload captured alongside decode stats.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub governance: Option<UnitGovernanceDecision>,
}

/// Structured G7 governance decision payload embedded in unit decode logs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnitGovernanceDecision {
    /// Posterior mass over canonical G7 states in permille.
    pub state_posterior: BTreeMap<String, u16>,
    /// Expected-loss terms for the canonical G7 actions.
    pub expected_loss_terms: BTreeMap<String, u32>,
    /// Action chosen by the runtime governance contract.
    pub chosen_action: String,
    /// Top evidence contributors with deterministic ordering and weights.
    pub top_evidence_contributors: Vec<UnitGovernanceContributor>,
    /// Confidence score in the canonical 0..=1000 range.
    pub confidence_score: u16,
    /// Uncertainty score in the canonical 0..=1000 range.
    pub uncertainty_score: u16,
    /// Deterministic fallback trigger summary.
    pub deterministic_fallback_trigger: UnitFallbackTrigger,
    /// Canonical replay pointer for the governance decision.
    pub replay_ref: String,
}

/// A single surfaced governance evidence contributor.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnitGovernanceContributor {
    /// Contributor name from the contract artifact/runtime.
    pub name: String,
    /// Relative contributor weight in permille.
    pub contribution_permille: u16,
}

/// Deterministic fallback trigger summary for governance logs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnitFallbackTrigger {
    /// Whether the fallback trigger fired.
    pub fired: bool,
    /// Canonical reason string, or `"none"`.
    pub reason: String,
}

impl From<&crate::raptorq::decision_contract::GovernanceTelemetry> for UnitGovernanceDecision {
    fn from(telemetry: &crate::raptorq::decision_contract::GovernanceTelemetry) -> Self {
        let state_posterior = GOVERNANCE_STATE_KEYS
            .iter()
            .copied()
            .zip(telemetry.state_posterior_permille)
            .map(|(name, value)| (name.to_string(), value))
            .collect();
        let expected_loss_terms = GOVERNANCE_ACTION_KEYS
            .iter()
            .copied()
            .zip(telemetry.expected_loss_terms)
            .map(|(name, value)| (name.to_string(), value))
            .collect();
        let top_evidence_contributors = telemetry
            .top_evidence_contributors
            .iter()
            .map(|contributor| UnitGovernanceContributor {
                name: contributor.name.to_string(),
                contribution_permille: contributor.contribution_permille,
            })
            .collect();

        Self {
            state_posterior,
            expected_loss_terms,
            chosen_action: telemetry.chosen_action.to_string(),
            top_evidence_contributors,
            confidence_score: telemetry.confidence_score,
            uncertainty_score: telemetry.uncertainty_score,
            deterministic_fallback_trigger: UnitFallbackTrigger {
                fired: telemetry.deterministic_fallback_triggered,
                reason: telemetry.deterministic_fallback_reason.to_string(),
            },
            replay_ref: telemetry.replay_ref.to_string(),
        }
    }
}

// ============================================================================
// Builders
// ============================================================================

impl UnitLogEntry {
    /// Create a new unit log entry with required fields.
    #[must_use]
    pub fn new(
        scenario_id: &str,
        seed: u64,
        parameter_set: &str,
        replay_ref: &str,
        repro_command: &str,
        outcome: &str,
    ) -> Self {
        let scenario_id = scenario_id.trim();
        assert!(
            !scenario_id.is_empty(),
            "UnitLogEntry::new requires a non-empty scenario_id"
        );
        let parameter_set = parameter_set.trim();
        assert!(
            !parameter_set.is_empty(),
            "UnitLogEntry::new requires a non-empty parameter_set"
        );
        let replay_ref = replay_ref.trim();
        assert!(
            !replay_ref.is_empty(),
            "UnitLogEntry::new requires a non-empty replay_ref"
        );
        let repro_command = repro_command.trim();
        assert!(
            !repro_command.is_empty(),
            "UnitLogEntry::new requires a non-empty repro command"
        );
        assert!(
            repro_command.contains("rch exec --"),
            "UnitLogEntry::new requires an rch-backed repro command"
        );
        let outcome = outcome.trim();
        assert!(
            !outcome.is_empty(),
            "UnitLogEntry::new requires a non-empty outcome"
        );
        assert!(
            VALID_UNIT_OUTCOMES.contains(&outcome),
            "UnitLogEntry::new requires a recognized outcome"
        );
        Self {
            schema_version: UNIT_LOG_SCHEMA_VERSION.to_string(),
            scenario_id: scenario_id.to_string(),
            seed,
            parameter_set: parameter_set.to_string(),
            replay_ref: replay_ref.to_string(),
            repro_command: repro_command.to_string(),
            outcome: outcome.to_string(),
            artifact_path: None,
            decode_stats: None,
        }
    }

    /// Set the artifact path.
    #[must_use]
    pub fn with_artifact_path(mut self, path: &str) -> Self {
        let path = path.trim();
        assert!(
            !path.is_empty(),
            "UnitLogEntry::with_artifact_path requires a non-empty artifact path"
        );
        self.artifact_path = Some(path.to_string());
        self
    }

    /// Set decode statistics.
    #[must_use]
    pub fn with_decode_stats(mut self, stats: UnitDecodeStats) -> Self {
        self.decode_stats = Some(stats);
        self
    }

    /// Serialize to JSON string.
    ///
    /// br-asupersync-zmzwof: gated to `cfg(test)` (see `E2eLogEntry::to_json`).
    #[cfg(any(test, feature = "test-internals"))]
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Serialize to pretty-printed JSON string.
    #[cfg(any(test, feature = "test-internals"))]
    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Format as a single-line context string for panic messages.
    ///
    /// Compatible with the legacy `builder_failure_context()` format but
    /// richer: includes repro command and schema version.
    #[must_use]
    pub fn to_context_string(&self) -> String {
        format!(
            "schema={} scenario_id={} seed={} parameter_set={} replay_ref={} outcome={} repro='{}'",
            self.schema_version,
            self.scenario_id,
            self.seed,
            self.parameter_set,
            self.replay_ref,
            self.outcome,
            self.repro_command,
        )
    }
}

// ============================================================================
// Contract validation
// ============================================================================

/// Validate a JSON string against the E2E log entry schema contract.
///
/// Returns a list of violations. An empty list means the entry is valid.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn validate_e2e_log_json(json: &str) -> Vec<String> {
    let mut violations = Vec::new();

    let value: serde_json::Value = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(e) => {
            violations.push(format!("invalid JSON: {e}"));
            return violations;
        }
    };

    // Schema version
    match value.get("schema_version").and_then(|v| v.as_str()) {
        Some(v) if v == E2E_LOG_SCHEMA_VERSION => {}
        Some(v) => violations.push(format!(
            "schema_version mismatch: expected '{E2E_LOG_SCHEMA_VERSION}', got '{v}'"
        )),
        None => violations.push("missing required field: schema_version".to_string()),
    }

    // Required string fields
    for field in &[
        "scenario",
        "scenario_id",
        "replay_id",
        "profile",
        "unit_sentinel",
        "assertion_id",
        "run_id",
        "repro_command",
    ] {
        match value.get(*field) {
            Some(raw) if raw.as_str().is_some_and(|text| text.trim().is_empty()) => {
                violations.push(format!("required field '{field}' is empty"));
            }
            Some(raw) if raw.as_str().is_some() => {}
            Some(raw) if raw.is_null() => {
                violations.push(format!("missing required field: {field}"));
            }
            Some(_) => violations.push(format!("{field} must be a string")),
            None => violations.push(format!("missing required field: {field}")),
        }
    }

    // Profile must be one of the valid values
    if let Some(profile) = value.get("profile").and_then(|v| v.as_str()) {
        if !profile.trim().is_empty() && !VALID_PROFILES.contains(&profile) {
            violations.push(format!(
                "invalid profile '{profile}': expected one of {VALID_PROFILES:?}"
            ));
        }
    }

    // Repro command must include rch exec, must START with the rch exec
    // prefix (no shell prologue), and must NOT contain shell metacharacters
    // that would let an eval-based replay tool be hijacked
    // (br-asupersync-zmzwof). The schema validator is run on operator-
    // configured forensic logs, so trust boundary is operator-trustworthy
    // → defensive shell-meta rejection prevents accidental footguns.
    if let Some(cmd) = value.get("repro_command").and_then(|v| v.as_str()) {
        let trimmed = cmd.trim();
        if !trimmed.is_empty() {
            validate_repro_command(trimmed, &mut violations);
        }
    }

    // Phase markers
    match value.get("phase_markers").and_then(|v| v.as_array()) {
        Some(markers) => {
            if markers.len() != REQUIRED_PHASE_MARKERS.len() {
                violations.push(format!(
                    "phase_markers: expected {} markers, got {}",
                    REQUIRED_PHASE_MARKERS.len(),
                    markers.len()
                ));
            }
            match markers
                .iter()
                .map(serde_json::Value::as_str)
                .collect::<Option<Vec<_>>>()
            {
                Some(actual) => {
                    if actual.as_slice() != REQUIRED_PHASE_MARKERS {
                        violations.push(format!(
                            "phase_markers mismatch: expected {REQUIRED_PHASE_MARKERS:?}, got {actual:?}",
                        ));
                    }
                }
                None => violations.push("phase_markers must be an array of strings".to_string()),
            }
        }
        None => violations.push("missing required field: phase_markers".to_string()),
    }

    // Required sub-objects
    for section in &["config", "loss", "symbols", "outcome", "proof"] {
        if !value
            .get(*section)
            .is_some_and(serde_json::Value::is_object)
        {
            violations.push(format!("missing or non-object required section: {section}"));
        }
    }

    // Config sub-object required fields
    if let Some(config) = value.get("config") {
        validate_required_unsigned_integer_field(config, "symbol_size", "config", &mut violations);
        validate_required_unsigned_integer_field(config, "seed", "config", &mut violations);
        validate_required_unsigned_integer_field(config, "block_k", "config", &mut violations);
        validate_required_unsigned_integer_field(config, "data_len", "config", &mut violations);
        validate_required_unsigned_integer_field(
            config,
            "max_block_size",
            "config",
            &mut violations,
        );
        validate_required_unsigned_integer_field(config, "min_overhead", "config", &mut violations);
        validate_required_unsigned_integer_field(config, "block_count", "config", &mut violations);
        validate_required_number_field(config, "repair_overhead", "config", &mut violations);
    }

    // Loss sub-object required fields
    if let Some(loss) = value.get("loss") {
        validate_required_string_field(loss, "kind", "loss", &mut violations);
        validate_required_unsigned_integer_field(loss, "drop_count", "loss", &mut violations);
        validate_required_unsigned_integer_field(loss, "keep_count", "loss", &mut violations);
        validate_optional_unsigned_integer_field(loss, "seed", "loss", &mut violations);
        validate_optional_unsigned_integer_field(loss, "drop_per_mille", "loss", &mut violations);
        validate_optional_unsigned_integer_field(loss, "burst_start", "loss", &mut violations);
        validate_optional_unsigned_integer_field(loss, "burst_len", "loss", &mut violations);
    }

    // Symbols sub-object required fields
    if let Some(symbols) = value.get("symbols") {
        for subsection in &["generated", "received"] {
            match symbols.get(*subsection) {
                Some(counts) if counts.is_object() => {
                    validate_required_unsigned_integer_field(
                        counts,
                        "total",
                        &format!("symbols.{subsection}"),
                        &mut violations,
                    );
                    validate_required_unsigned_integer_field(
                        counts,
                        "source",
                        &format!("symbols.{subsection}"),
                        &mut violations,
                    );
                    validate_required_unsigned_integer_field(
                        counts,
                        "repair",
                        &format!("symbols.{subsection}"),
                        &mut violations,
                    );
                }
                _ => violations.push(format!("symbols.{subsection} is missing or non-object")),
            }
        }
    }

    // Outcome sub-object required fields
    if let Some(outcome) = value.get("outcome") {
        validate_required_bool_field(outcome, "success", "outcome", &mut violations);
        validate_required_unsigned_integer_field(
            outcome,
            "decoded_bytes",
            "outcome",
            &mut violations,
        );
        validate_optional_string_field(outcome, "reject_reason", "outcome", &mut violations);
    }

    // Proof sub-object required fields
    if let Some(proof) = value.get("proof") {
        validate_required_unsigned_integer_field(proof, "hash", "proof", &mut violations);
        validate_required_unsigned_integer_field(proof, "summary_bytes", "proof", &mut violations);
        validate_required_string_field(proof, "outcome", "proof", &mut violations);
        validate_required_unsigned_integer_field(proof, "received_total", "proof", &mut violations);
        validate_required_unsigned_integer_field(
            proof,
            "received_source",
            "proof",
            &mut violations,
        );
        validate_required_unsigned_integer_field(
            proof,
            "received_repair",
            "proof",
            &mut violations,
        );
        validate_required_unsigned_integer_field(proof, "peeling_solved", "proof", &mut violations);
        validate_required_unsigned_integer_field(proof, "inactivated", "proof", &mut violations);
        validate_required_unsigned_integer_field(proof, "pivots", "proof", &mut violations);
        validate_required_unsigned_integer_field(proof, "row_ops", "proof", &mut violations);
        validate_required_unsigned_integer_field(proof, "equations_used", "proof", &mut violations);
    }

    violations
}

/// Validate a JSON string against the unit test log entry schema contract.
///
/// Returns a list of violations. An empty list means the entry is valid.
#[must_use]
pub fn validate_unit_log_json(json: &str) -> Vec<String> {
    let mut violations = Vec::new();

    let value: serde_json::Value = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(e) => {
            violations.push(format!("invalid JSON: {e}"));
            return violations;
        }
    };

    // Schema version
    match value.get("schema_version").and_then(|v| v.as_str()) {
        Some(v) if v == UNIT_LOG_SCHEMA_VERSION => {}
        Some(v) => violations.push(format!(
            "schema_version mismatch: expected '{UNIT_LOG_SCHEMA_VERSION}', got '{v}'"
        )),
        None => violations.push("missing required field: schema_version".to_string()),
    }

    // Required string fields
    for field in &["scenario_id", "parameter_set", "replay_ref", "outcome"] {
        match value.get(*field) {
            Some(raw) if raw.as_str().is_some_and(|text| text.trim().is_empty()) => {
                violations.push(format!("required field '{field}' is empty"));
            }
            Some(raw) if raw.as_str().is_some() => {}
            Some(raw) if raw.is_null() => {
                violations.push(format!("missing required field: {field}"));
            }
            Some(_) => violations.push(format!("{field} must be a string")),
            None => violations.push(format!("missing required field: {field}")),
        }
    }

    // Seed must be present and numeric
    match value.get("seed") {
        Some(seed) if seed.as_u64().is_some() => {}
        Some(seed) if seed.is_null() => violations.push("missing required field: seed".to_string()),
        Some(_) => violations.push("seed must be an unsigned integer".to_string()),
        None => violations.push("missing required field: seed".to_string()),
    }

    // Repro command must be present and satisfy the same hardened
    // `rch exec` contract as the E2E schema (br-asupersync-zmzwof).
    match value.get("repro_command") {
        Some(cmd) if cmd.as_str().is_some_and(|text| text.trim().is_empty()) => {
            violations.push("required field 'repro_command' is empty".to_string());
        }
        Some(cmd) if cmd.as_str().is_some() => {
            let trimmed = cmd.as_str().expect("guarded by is_some");
            validate_repro_command(trimmed.trim(), &mut violations);
        }
        Some(cmd) if cmd.is_null() => {
            violations.push("missing required field: repro_command".to_string());
        }
        Some(_) => violations.push("repro_command must be a string".to_string()),
        None => violations.push("missing required field: repro_command".to_string()),
    }

    // Outcome must be a recognized value
    if let Some(outcome) = value.get("outcome").and_then(|v| v.as_str()) {
        if !outcome.trim().is_empty() && !VALID_UNIT_OUTCOMES.contains(&outcome) {
            violations.push(format!(
                "unrecognized outcome '{outcome}': expected one of {VALID_UNIT_OUTCOMES:?}"
            ));
        }
    }

    validate_optional_non_empty_string_field(&value, "artifact_path", &mut violations);

    if let Some(decode_stats) = value.get("decode_stats") {
        if decode_stats.is_object() {
            for field in &[
                "k",
                "loss_pct",
                "dropped",
                "peeled",
                "inactivated",
                "gauss_ops",
                "pivots",
                "peel_queue_pushes",
                "peel_queue_pops",
                "peel_frontier_peak",
                "dense_core_rows",
                "dense_core_cols",
                "dense_core_dropped_rows",
                "hard_regime_fallbacks",
            ] {
                validate_decode_stats_unsigned_integer_field(decode_stats, field, &mut violations);
            }
            for field in &[
                "fallback_reason",
                "hard_regime_branch",
                "conservative_fallback_reason",
            ] {
                validate_decode_stats_string_field(decode_stats, field, &mut violations);
            }
            validate_decode_stats_bool_field(
                decode_stats,
                "hard_regime_activated",
                &mut violations,
            );
            validate_decode_stats_governance_field(decode_stats, &mut violations);
        } else {
            violations.push("decode_stats must be an object".to_string());
        }
    }

    violations
}

fn validate_repro_command(trimmed: &str, violations: &mut Vec<String>) {
    if !trimmed.contains("rch exec --") {
        violations
            .push("repro_command must include 'rch exec --' for remote execution".to_string());
    }
    if !(trimmed.starts_with("rch exec --") || trimmed.starts_with("rch exec ")) {
        violations.push(
            "repro_command must START with 'rch exec' (no shell prologue) — \
             prefixing other commands enables shell-metacharacter injection if \
             a replay tool eval's the command (br-asupersync-zmzwof)"
                .to_string(),
        );
    }
    // Reject unquoted shell metacharacters that change command structure.
    // We allow `--` (the rch arg separator) and `=` and `/` in paths, but
    // reject sequencing operators, redirection, command substitution,
    // and process substitution.
    const SHELL_META: &[char] = &[';', '|', '&', '`', '\n', '\r'];
    if let Some(bad) = trimmed.chars().find(|c| SHELL_META.contains(c)) {
        violations.push(format!(
            "repro_command contains shell metacharacter {bad:?} — would enable \
             shell injection if eval'd by a replay tool (br-asupersync-zmzwof)"
        ));
    }
    // Reject `$(` and `${` (command substitution / parameter expansion).
    if trimmed.contains("$(") || trimmed.contains("${") {
        violations.push(
            "repro_command contains shell substitution ($( or ${) — \
             would enable injection if eval'd (br-asupersync-zmzwof)"
                .to_string(),
        );
    }
}

fn validate_required_unsigned_integer_field(
    parent: &serde_json::Value,
    field: &str,
    path: &str,
    violations: &mut Vec<String>,
) {
    match parent.get(field) {
        Some(value) if value.as_u64().is_some() => {}
        Some(value) if value.is_null() => {
            violations.push(format!("{path}.{field} is missing or null"));
        }
        Some(_) => violations.push(format!("{path}.{field} must be an unsigned integer")),
        None => violations.push(format!("{path}.{field} is missing or null")),
    }
}

fn validate_required_number_field(
    parent: &serde_json::Value,
    field: &str,
    path: &str,
    violations: &mut Vec<String>,
) {
    match parent.get(field) {
        Some(value) if value.is_number() => {}
        Some(value) if value.is_null() => {
            violations.push(format!("{path}.{field} is missing or null"));
        }
        Some(_) => violations.push(format!("{path}.{field} must be a number")),
        None => violations.push(format!("{path}.{field} is missing or null")),
    }
}

fn validate_required_string_field(
    parent: &serde_json::Value,
    field: &str,
    path: &str,
    violations: &mut Vec<String>,
) {
    match parent.get(field) {
        Some(value) if value.as_str().is_some_and(|text| !text.trim().is_empty()) => {}
        Some(value) if value.is_null() => {
            violations.push(format!("{path}.{field} is missing or null"));
        }
        Some(value) if value.as_str().is_some() => {
            violations.push(format!("{path}.{field} must be a non-empty string"));
        }
        Some(_) => violations.push(format!("{path}.{field} must be a string")),
        None => violations.push(format!("{path}.{field} is missing or null")),
    }
}

fn validate_required_bool_field(
    parent: &serde_json::Value,
    field: &str,
    path: &str,
    violations: &mut Vec<String>,
) {
    match parent.get(field) {
        Some(value) if value.is_boolean() => {}
        Some(value) if value.is_null() => {
            violations.push(format!("{path}.{field} is missing or null"));
        }
        Some(_) => violations.push(format!("{path}.{field} must be a boolean")),
        None => violations.push(format!("{path}.{field} is missing or null")),
    }
}

fn validate_optional_unsigned_integer_field(
    parent: &serde_json::Value,
    field: &str,
    path: &str,
    violations: &mut Vec<String>,
) {
    if let Some(value) = parent.get(field) {
        if !value.is_null() && value.as_u64().is_none() {
            violations.push(format!("{path}.{field} must be an unsigned integer"));
        }
    }
}

fn validate_optional_string_field(
    parent: &serde_json::Value,
    field: &str,
    path: &str,
    violations: &mut Vec<String>,
) {
    if let Some(value) = parent.get(field) {
        if !value.is_null() && value.as_str().is_none() {
            violations.push(format!("{path}.{field} must be a string"));
        }
    }
}

fn validate_optional_non_empty_string_field(
    parent: &serde_json::Value,
    field: &str,
    violations: &mut Vec<String>,
) {
    if let Some(value) = parent.get(field) {
        match value {
            serde_json::Value::Null => {}
            serde_json::Value::String(text) if !text.trim().is_empty() => {}
            serde_json::Value::String(_) => {
                violations.push(format!("{field} must be a non-empty string when present"));
            }
            _ => violations.push(format!("{field} must be a string when present")),
        }
    }
}

fn validate_decode_stats_unsigned_integer_field(
    decode_stats: &serde_json::Value,
    field: &str,
    violations: &mut Vec<String>,
) {
    match decode_stats.get(field) {
        Some(value) if value.as_u64().is_some() => {}
        Some(value) if value.is_null() => {
            violations.push(format!("decode_stats.{field} is missing or null"));
        }
        Some(_) => violations.push(format!("decode_stats.{field} must be an unsigned integer")),
        None => violations.push(format!("decode_stats.{field} is missing or null")),
    }
}

fn validate_decode_stats_string_field(
    decode_stats: &serde_json::Value,
    field: &str,
    violations: &mut Vec<String>,
) {
    match decode_stats.get(field) {
        Some(value) if value.as_str().is_some() => {}
        Some(value) if value.is_null() => {
            violations.push(format!("decode_stats.{field} is missing or null"));
        }
        Some(_) => violations.push(format!("decode_stats.{field} must be a string")),
        None => violations.push(format!("decode_stats.{field} is missing or null")),
    }
}

fn validate_decode_stats_bool_field(
    decode_stats: &serde_json::Value,
    field: &str,
    violations: &mut Vec<String>,
) {
    match decode_stats.get(field) {
        Some(value) if value.is_boolean() => {}
        Some(value) if value.is_null() => {
            violations.push(format!("decode_stats.{field} is missing or null"));
        }
        Some(_) => violations.push(format!("decode_stats.{field} must be a boolean")),
        None => violations.push(format!("decode_stats.{field} is missing or null")),
    }
}

fn validate_decode_stats_governance_field(
    decode_stats: &serde_json::Value,
    violations: &mut Vec<String>,
) {
    let Some(governance) = decode_stats.get("governance") else {
        return;
    };
    if governance.is_null() {
        return;
    }
    let Some(governance) = governance.as_object() else {
        violations.push("decode_stats.governance must be an object".to_string());
        return;
    };

    validate_governance_map_field(
        governance,
        "state_posterior",
        GOVERNANCE_STATE_KEYS,
        "unsigned integer",
        violations,
    );
    validate_governance_permille_sum_field(
        governance,
        "state_posterior",
        GOVERNANCE_STATE_KEYS,
        violations,
    );
    validate_governance_map_field(
        governance,
        "expected_loss_terms",
        GOVERNANCE_ACTION_KEYS,
        "unsigned integer",
        violations,
    );
    validate_governance_canonical_action_field(governance, "chosen_action", violations);
    validate_governance_permille_field(governance, "confidence_score", violations);
    validate_governance_permille_field(governance, "uncertainty_score", violations);
    validate_governance_score_complement(governance, violations);
    validate_governance_string_field(governance, "replay_ref", violations);

    match governance.get("top_evidence_contributors") {
        Some(serde_json::Value::Array(items)) => {
            if items.len() != 3 {
                violations.push(
                    "decode_stats.governance.top_evidence_contributors must contain exactly 3 items"
                        .to_string(),
                );
            }
            for (index, contributor) in items.iter().enumerate() {
                let Some(contributor) = contributor.as_object() else {
                    violations.push(format!(
                        "decode_stats.governance.top_evidence_contributors[{index}] must be an object"
                    ));
                    continue;
                };
                validate_governance_string_field_in(
                    contributor,
                    &format!("top_evidence_contributors[{index}].name"),
                    violations,
                );
                validate_governance_unsigned_integer_field_in(
                    contributor,
                    &format!("top_evidence_contributors[{index}].contribution_permille"),
                    violations,
                );
            }
            validate_governance_contributor_consistency(items, violations);
        }
        Some(_) => violations
            .push("decode_stats.governance.top_evidence_contributors must be an array".to_string()),
        None => violations.push(
            "decode_stats.governance.top_evidence_contributors is missing or null".to_string(),
        ),
    }

    match governance.get("deterministic_fallback_trigger") {
        Some(serde_json::Value::Object(trigger)) => {
            validate_governance_bool_field_in(
                trigger,
                "deterministic_fallback_trigger.fired",
                violations,
            );
            validate_governance_string_field_in(
                trigger,
                "deterministic_fallback_trigger.reason",
                violations,
            );
        }
        Some(_) => violations.push(
            "decode_stats.governance.deterministic_fallback_trigger must be an object".to_string(),
        ),
        None => violations.push(
            "decode_stats.governance.deterministic_fallback_trigger is missing or null".to_string(),
        ),
    }

    validate_governance_fallback_consistency(governance, violations);
}

fn validate_governance_map_field(
    governance: &serde_json::Map<String, serde_json::Value>,
    field: &str,
    required_keys: &[&str],
    value_description: &str,
    violations: &mut Vec<String>,
) {
    match governance.get(field) {
        Some(serde_json::Value::Object(map)) => {
            for key in required_keys {
                if let Some(value) = map.get(*key) {
                    match value {
                        serde_json::Value::Number(number) if number.as_u64().is_some() => {}
                        serde_json::Value::Null => violations.push(format!(
                            "decode_stats.governance.{field}.{key} is missing or null"
                        )),
                        _ => violations.push(format!(
                            "decode_stats.governance.{field}.{key} must be a {value_description}"
                        )),
                    }
                } else {
                    violations.push(format!(
                        "decode_stats.governance.{field}.{key} is missing or null"
                    ));
                }
            }
        }
        Some(_) => violations.push(format!("decode_stats.governance.{field} must be an object")),
        None => violations.push(format!(
            "decode_stats.governance.{field} is missing or null"
        )),
    }
}

fn validate_governance_string_field(
    governance: &serde_json::Map<String, serde_json::Value>,
    field: &str,
    violations: &mut Vec<String>,
) {
    validate_governance_string_field_in(governance, field, violations);
}

fn validate_governance_permille_sum_field(
    governance: &serde_json::Map<String, serde_json::Value>,
    field: &str,
    required_keys: &[&str],
    violations: &mut Vec<String>,
) {
    let Some(map) = governance.get(field).and_then(serde_json::Value::as_object) else {
        return;
    };

    let mut total = 0u64;
    for key in required_keys {
        let Some(value) = map.get(*key).and_then(serde_json::Value::as_u64) else {
            return;
        };
        total = total.saturating_add(value);
    }

    if total != GOVERNANCE_PERMILLE_SCALE {
        violations.push(format!(
            "decode_stats.governance.{field} values must sum to {GOVERNANCE_PERMILLE_SCALE}"
        ));
    }
}

fn validate_governance_permille_field(
    governance: &serde_json::Map<String, serde_json::Value>,
    field: &str,
    violations: &mut Vec<String>,
) {
    validate_governance_unsigned_integer_field(governance, field, violations);

    let Some(value) = governance.get(field).and_then(serde_json::Value::as_u64) else {
        return;
    };
    if value > GOVERNANCE_PERMILLE_SCALE {
        violations.push(format!(
            "decode_stats.governance.{field} must be <= {GOVERNANCE_PERMILLE_SCALE}"
        ));
    }
}

fn validate_governance_score_complement(
    governance: &serde_json::Map<String, serde_json::Value>,
    violations: &mut Vec<String>,
) {
    let Some(confidence) = governance
        .get("confidence_score")
        .and_then(serde_json::Value::as_u64)
    else {
        return;
    };
    let Some(uncertainty) = governance
        .get("uncertainty_score")
        .and_then(serde_json::Value::as_u64)
    else {
        return;
    };

    if confidence.saturating_add(uncertainty) != GOVERNANCE_PERMILLE_SCALE {
        violations.push(
            "decode_stats.governance.confidence_score + uncertainty_score must equal 1000"
                .to_string(),
        );
    }
}

fn validate_governance_canonical_action_field(
    governance: &serde_json::Map<String, serde_json::Value>,
    field: &str,
    violations: &mut Vec<String>,
) {
    validate_governance_string_field(governance, field, violations);

    let Some(action) = governance.get(field).and_then(serde_json::Value::as_str) else {
        return;
    };
    if action.trim().is_empty() {
        return;
    }
    if action != action.trim() || !GOVERNANCE_ACTION_KEYS.contains(&action) {
        violations.push(format!(
            "decode_stats.governance.{field} must be one of {GOVERNANCE_ACTION_KEYS:?}"
        ));
    }
}

fn validate_governance_unsigned_integer_field(
    governance: &serde_json::Map<String, serde_json::Value>,
    field: &str,
    violations: &mut Vec<String>,
) {
    validate_governance_unsigned_integer_field_in(governance, field, violations);
}

fn validate_governance_string_field_in(
    map: &serde_json::Map<String, serde_json::Value>,
    field: &str,
    violations: &mut Vec<String>,
) {
    let key = field.rsplit('.').next().unwrap_or(field);
    if let Some(value) = map.get(key) {
        match value {
            serde_json::Value::String(text) if text.trim().is_empty() => violations.push(format!(
                "decode_stats.governance.{field} must be a non-empty string"
            )),
            serde_json::Value::String(text) if text != text.trim() => violations.push(format!(
                "decode_stats.governance.{field} must not have leading or trailing whitespace"
            )),
            serde_json::Value::String(_) => {}
            serde_json::Value::Null => violations.push(format!(
                "decode_stats.governance.{field} is missing or null"
            )),
            _ => violations.push(format!("decode_stats.governance.{field} must be a string")),
        }
    } else {
        violations.push(format!(
            "decode_stats.governance.{field} is missing or null"
        ));
    }
}

fn validate_governance_unsigned_integer_field_in(
    map: &serde_json::Map<String, serde_json::Value>,
    field: &str,
    violations: &mut Vec<String>,
) {
    let key = field.rsplit('.').next().unwrap_or(field);
    if let Some(value) = map.get(key) {
        match value {
            serde_json::Value::Number(number) if number.as_u64().is_some() => {}
            serde_json::Value::Null => violations.push(format!(
                "decode_stats.governance.{field} is missing or null"
            )),
            _ => violations.push(format!(
                "decode_stats.governance.{field} must be an unsigned integer"
            )),
        }
    } else {
        violations.push(format!(
            "decode_stats.governance.{field} is missing or null"
        ));
    }
}

fn validate_governance_contributor_consistency(
    items: &[serde_json::Value],
    violations: &mut Vec<String>,
) {
    let mut names = BTreeSet::new();
    let mut total = 0u64;

    for (index, contributor) in items.iter().enumerate() {
        let Some(contributor) = contributor.as_object() else {
            return;
        };

        let Some(name) = contributor
            .get("name")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
        else {
            return;
        };
        if !name.is_empty() && !names.insert(name.to_string()) {
            violations.push(format!(
                "decode_stats.governance.top_evidence_contributors[{index}].name must be distinct"
            ));
        }

        let Some(weight) = contributor
            .get("contribution_permille")
            .and_then(serde_json::Value::as_u64)
        else {
            return;
        };
        total = total.saturating_add(weight);
    }

    if total != GOVERNANCE_PERMILLE_SCALE {
        violations.push(
            "decode_stats.governance.top_evidence_contributors contribution_permille values must sum to 1000"
                .to_string(),
        );
    }
}

fn validate_governance_bool_field_in(
    map: &serde_json::Map<String, serde_json::Value>,
    field: &str,
    violations: &mut Vec<String>,
) {
    let key = field.rsplit('.').next().unwrap_or(field);
    if let Some(value) = map.get(key) {
        match value {
            serde_json::Value::Bool(_) => {}
            serde_json::Value::Null => violations.push(format!(
                "decode_stats.governance.{field} is missing or null"
            )),
            _ => violations.push(format!("decode_stats.governance.{field} must be a boolean")),
        }
    } else {
        violations.push(format!(
            "decode_stats.governance.{field} is missing or null"
        ));
    }
}

fn validate_governance_fallback_consistency(
    governance: &serde_json::Map<String, serde_json::Value>,
    violations: &mut Vec<String>,
) {
    let Some(chosen_action) = governance
        .get("chosen_action")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
    else {
        return;
    };

    let Some(trigger) = governance
        .get("deterministic_fallback_trigger")
        .and_then(serde_json::Value::as_object)
    else {
        return;
    };

    let Some(fired) = trigger.get("fired").and_then(serde_json::Value::as_bool) else {
        return;
    };
    let Some(reason) = trigger
        .get("reason")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
    else {
        return;
    };

    if fired {
        if chosen_action != "fallback" {
            violations.push(
                "decode_stats.governance.deterministic_fallback_trigger.fired requires chosen_action to be 'fallback'"
                    .to_string(),
            );
        }
        if reason.is_empty() || reason == "none" {
            violations.push(
                "decode_stats.governance.deterministic_fallback_trigger.reason must be a non-empty non-'none' string when fired is true"
                    .to_string(),
            );
        } else if !crate::raptorq::decision_contract::is_runtime_fallback_reason(reason) {
            violations.push(format!(
                "decode_stats.governance.deterministic_fallback_trigger.reason must be one of {:?} when fired is true",
                crate::raptorq::decision_contract::G7_RUNTIME_FALLBACK_REASONS
            ));
        }
    } else if reason != "none" {
        violations.push(
            "decode_stats.governance.deterministic_fallback_trigger.reason must be 'none' when fired is false"
                .to_string(),
        );
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[path = "test_log_schema_inline_tests.rs"]
mod tests;
