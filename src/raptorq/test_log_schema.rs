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

// ============================================================================
// Schema version constants
// ============================================================================

/// Schema version for full E2E pipeline log entries.
pub const E2E_LOG_SCHEMA_VERSION: &str = "raptorq-e2e-log-v1";

/// Schema version for lightweight unit test log entries.
pub const UNIT_LOG_SCHEMA_VERSION: &str = "raptorq-unit-log-v1";

/// Valid profile markers for E2E test runs.
pub const VALID_PROFILES: &[&str] = &["fast", "full", "forensics"];

/// Required phase marker set for E2E log entries.
pub const REQUIRED_PHASE_MARKERS: &[&str] = &["encode", "loss", "decode", "proof", "report"];

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
    /// Test outcome: `"ok"`, `"fail"`, `"decode_failure"`, `"symbol_mismatch"`.
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
        outcome: &str,
    ) -> Self {
        Self {
            schema_version: UNIT_LOG_SCHEMA_VERSION.to_string(),
            scenario_id: scenario_id.to_string(),
            seed,
            parameter_set: parameter_set.to_string(),
            replay_ref: replay_ref.to_string(),
            repro_command: String::new(),
            outcome: outcome.to_string(),
            artifact_path: None,
            decode_stats: None,
        }
    }

    /// Set the repro command.
    #[must_use]
    pub fn with_repro_command(mut self, cmd: &str) -> Self {
        self.repro_command = cmd.to_string();
        self
    }

    /// Set the artifact path.
    #[must_use]
    pub fn with_artifact_path(mut self, path: &str) -> Self {
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
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Serialize to pretty-printed JSON string.
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
        match value.get(*field).and_then(|v| v.as_str()) {
            Some("") => {
                violations.push(format!("required field '{field}' is empty"));
            }
            Some(_) => {}
            None => violations.push(format!("missing required field: {field}")),
        }
    }

    // Profile must be one of the valid values
    if let Some(profile) = value.get("profile").and_then(|v| v.as_str()) {
        if !VALID_PROFILES.contains(&profile) {
            violations.push(format!(
                "invalid profile '{profile}': expected one of {VALID_PROFILES:?}"
            ));
        }
    }

    // Repro command must include rch exec
    if let Some(cmd) = value.get("repro_command").and_then(|v| v.as_str()) {
        if !cmd.contains("rch exec --") {
            violations
                .push("repro_command must include 'rch exec --' for remote execution".to_string());
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
        for field in &["symbol_size", "seed", "block_k", "data_len"] {
            if value_missing_or_null(config, field) {
                violations.push(format!("config.{field} is missing or null"));
            }
        }
    }

    // Loss sub-object required fields
    if let Some(loss) = value.get("loss") {
        if value_missing_or_null(loss, "kind") {
            violations.push("loss.kind is missing or null".to_string());
        }
    }

    // Outcome sub-object required fields
    if let Some(outcome) = value.get("outcome") {
        if value_missing_or_null(outcome, "success") {
            violations.push("outcome.success is missing or null".to_string());
        }
    }

    // Proof sub-object required fields
    if let Some(proof) = value.get("proof") {
        for field in &["hash", "outcome", "peeling_solved", "inactivated", "pivots"] {
            if value_missing_or_null(proof, field) {
                violations.push(format!("proof.{field} is missing or null"));
            }
        }
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
        match value.get(*field).and_then(|v| v.as_str()) {
            Some("") => {
                violations.push(format!("required field '{field}' is empty"));
            }
            Some(_) => {}
            None => violations.push(format!("missing required field: {field}")),
        }
    }

    // Seed must be present and numeric
    if value_missing_or_null(&value, "seed") {
        violations.push("missing required field: seed".to_string());
    }

    // Repro command must be present (can be empty for builder tests, but should exist)
    if value.get("repro_command").is_none() {
        violations.push("missing required field: repro_command".to_string());
    }

    // Outcome must be a recognized value
    if let Some(outcome) = value.get("outcome").and_then(|v| v.as_str()) {
        let valid_outcomes = [
            "ok",
            "fail",
            "decode_failure",
            "symbol_mismatch",
            "error",
            "cancelled",
        ];
        if !valid_outcomes.contains(&outcome) {
            violations.push(format!(
                "unrecognized outcome '{outcome}': expected one of {valid_outcomes:?}"
            ));
        }
    }

    violations
}

/// Helper: check if a field is missing or null in a JSON value.
fn value_missing_or_null(parent: &serde_json::Value, field: &str) -> bool {
    parent.get(field).is_none_or(serde_json::Value::is_null)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_log_entry_roundtrip() {
        let entry = UnitLogEntry::new(
            "RQ-U-BUILDER-SEND-TRANSMIT",
            42,
            "symbol_size=256,data_len=1024",
            "replay:rq-u-builder-send-transmit-v1",
            "ok",
        )
        .with_repro_command(
            "rch exec -- cargo test --lib raptorq::tests::sender_encodes_and_transmits -- --nocapture",
        );

        let json = entry.to_json().expect("serialize");
        let parsed: UnitLogEntry = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.schema_version, UNIT_LOG_SCHEMA_VERSION);
        assert_eq!(parsed.scenario_id, "RQ-U-BUILDER-SEND-TRANSMIT");
        assert_eq!(parsed.seed, 42);
    }

    #[test]
    fn unit_log_entry_context_string() {
        let entry = UnitLogEntry::new(
            "RQ-U-TEST",
            99,
            "k=8,symbol_size=32",
            "replay:rq-u-test-v1",
            "ok",
        )
        .with_repro_command("rch exec -- cargo test foo");

        let ctx = entry.to_context_string();
        assert!(ctx.contains("scenario_id=RQ-U-TEST"));
        assert!(ctx.contains("seed=99"));
        assert!(ctx.contains("replay_ref=replay:rq-u-test-v1"));
    }

    #[test]
    fn validate_unit_log_valid() {
        let entry = UnitLogEntry::new(
            "RQ-U-ROUNDTRIP",
            1000,
            "k=16,symbol_size=32",
            "replay:rq-u-roundtrip-v1",
            "ok",
        )
        .with_repro_command("rch exec -- cargo test roundtrip");

        let json = entry.to_json().expect("serialize");
        let violations = validate_unit_log_json(&json);
        assert!(
            violations.is_empty(),
            "unexpected violations: {violations:?}"
        );
    }

    #[test]
    fn validate_unit_log_missing_fields() {
        let json = r#"{"schema_version": "raptorq-unit-log-v1", "seed": 42}"#;
        let violations = validate_unit_log_json(json);
        assert!(
            violations.iter().any(|v| v.contains("scenario_id")),
            "should flag missing scenario_id"
        );
        assert!(
            violations.iter().any(|v| v.contains("parameter_set")),
            "should flag missing parameter_set"
        );
    }

    #[test]
    fn validate_unit_log_wrong_schema_version() {
        let json = r#"{
            "schema_version": "wrong-version",
            "scenario_id": "RQ-U-TEST",
            "seed": 42,
            "parameter_set": "k=8",
            "replay_ref": "replay:test-v1",
            "repro_command": "cargo test",
            "outcome": "ok"
        }"#;
        let violations = validate_unit_log_json(json);
        assert!(
            violations.iter().any(|v| v.contains("schema_version")),
            "should flag wrong schema version"
        );
    }

    #[test]
    fn validate_unit_log_bad_outcome() {
        let entry = UnitLogEntry {
            schema_version: UNIT_LOG_SCHEMA_VERSION.to_string(),
            scenario_id: "RQ-U-TEST".to_string(),
            seed: 42,
            parameter_set: "k=8".to_string(),
            replay_ref: "replay:test-v1".to_string(),
            repro_command: "cargo test".to_string(),
            outcome: "unknown_outcome".to_string(),
            artifact_path: None,
            decode_stats: None,
        };
        let json = entry.to_json().expect("serialize");
        let violations = validate_unit_log_json(&json);
        assert!(
            violations
                .iter()
                .any(|v| v.contains("unrecognized outcome")),
            "should flag unrecognized outcome"
        );
    }

    #[test]
    fn validate_e2e_log_missing_sections() {
        let json = r#"{"schema_version": "raptorq-e2e-log-v1", "scenario_id": "TEST"}"#;
        let violations = validate_e2e_log_json(json);
        // Should flag missing config, loss, symbols, outcome, proof
        assert!(
            violations.iter().any(|v| v.contains("config")),
            "should flag missing config"
        );
        assert!(
            violations.iter().any(|v| v.contains("proof")),
            "should flag missing proof"
        );
    }

    #[test]
    fn validate_e2e_log_invalid_profile() {
        let json = r#"{
            "schema_version": "raptorq-e2e-log-v1",
            "scenario": "test",
            "scenario_id": "RQ-E2E-TEST",
            "replay_id": "replay:test-v1",
            "profile": "invalid_profile",
            "unit_sentinel": "test::fn",
            "assertion_id": "E2E-TEST",
            "run_id": "run-1",
            "repro_command": "rch exec -- cargo test",
            "phase_markers": ["encode", "loss", "decode", "proof", "report"],
            "config": {"symbol_size": 64, "seed": 42, "block_k": 16, "data_len": 1024, "max_block_size": 1024, "repair_overhead": 1.0, "min_overhead": 0, "block_count": 1},
            "loss": {"kind": "none", "drop_count": 0, "keep_count": 16},
            "symbols": {"generated": {"total": 16, "source": 16, "repair": 0}, "received": {"total": 16, "source": 16, "repair": 0}},
            "outcome": {"success": true, "decoded_bytes": 1024},
            "proof": {"hash": 123, "summary_bytes": 100, "outcome": "success", "received_total": 16, "received_source": 16, "received_repair": 0, "peeling_solved": 16, "inactivated": 0, "pivots": 0, "row_ops": 0, "equations_used": 16}
        }"#;
        let violations = validate_e2e_log_json(json);
        assert!(
            violations.iter().any(|v| v.contains("invalid profile")),
            "should flag invalid profile: {violations:?}"
        );
    }

    #[test]
    fn e2e_log_entry_full_roundtrip() {
        let entry = E2eLogEntry {
            schema_version: E2E_LOG_SCHEMA_VERSION.to_string(),
            scenario: "systematic_only".to_string(),
            scenario_id: "RQ-E2E-SYSTEMATIC-ONLY".to_string(),
            replay_id: "replay:rq-e2e-systematic-only-v1".to_string(),
            profile: "fast".to_string(),
            unit_sentinel: "raptorq::tests::edge_cases::repair_zero_only_source".to_string(),
            assertion_id: "E2E-ROUNDTRIP-SYSTEMATIC".to_string(),
            run_id: "replay:rq-e2e-systematic-only-v1-seed42-k16-len1024".to_string(),
            repro_command: "rch exec -- cargo test --test raptorq_conformance e2e_pipeline_reports_are_deterministic -- --nocapture".to_string(),
            phase_markers: REQUIRED_PHASE_MARKERS.iter().map(|s| (*s).to_string()).collect(),
            config: LogConfigReport {
                symbol_size: 64,
                max_block_size: 1024,
                repair_overhead: 1.0,
                min_overhead: 0,
                seed: 42,
                block_k: 16,
                block_count: 1,
                data_len: 1024,
            },
            loss: LogLossReport {
                kind: "none".to_string(),
                seed: None,
                drop_per_mille: None,
                drop_count: 0,
                keep_count: 16,
                burst_start: None,
                burst_len: None,
            },
            symbols: LogSymbolReport {
                generated: LogSymbolCounts { total: 16, source: 16, repair: 0 },
                received: LogSymbolCounts { total: 16, source: 16, repair: 0 },
            },
            outcome: LogOutcomeReport {
                success: true,
                reject_reason: None,
                decoded_bytes: 1024,
            },
            proof: LogProofReport {
                hash: 12345,
                summary_bytes: 200,
                outcome: "success".to_string(),
                received_total: 16,
                received_source: 16,
                received_repair: 0,
                peeling_solved: 16,
                inactivated: 0,
                pivots: 0,
                row_ops: 0,
                equations_used: 16,
            },
        };

        let json = serde_json::to_string(&entry).expect("serialize");
        let violations = validate_e2e_log_json(&json);
        assert!(
            violations.is_empty(),
            "full E2E entry should pass validation: {violations:?}"
        );

        let parsed: E2eLogEntry = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.schema_version, E2E_LOG_SCHEMA_VERSION);
        assert_eq!(parsed.scenario_id, "RQ-E2E-SYSTEMATIC-ONLY");
    }

    #[test]
    fn unit_log_with_decode_stats() {
        let entry = UnitLogEntry::new(
            "RQ-U-SEED-SWEEP",
            5042,
            "k=16,symbol_size=32",
            "replay:rq-u-seed-sweep-structured-v1",
            "ok",
        )
        .with_repro_command(
            "rch exec -- cargo test --test raptorq_perf_invariants seed_sweep_structured_logging -- --nocapture",
        )
        .with_decode_stats(UnitDecodeStats {
            k: 16,
            loss_pct: 25,
            dropped: 4,
            peeled: 10,
            inactivated: 2,
            gauss_ops: 8,
            pivots: 2,
            peel_queue_pushes: 12,
            peel_queue_pops: 10,
            peel_frontier_peak: 4,
            dense_core_rows: 5,
            dense_core_cols: 3,
            dense_core_dropped_rows: 1,
            fallback_reason: "peeling_exhausted_to_dense_core".to_string(),
        });

        let json = entry.to_json().expect("serialize");
        let violations = validate_unit_log_json(&json);
        assert!(
            violations.is_empty(),
            "unit entry with stats should pass: {violations:?}"
        );

        let parsed: UnitLogEntry = serde_json::from_str(&json).expect("deserialize");
        let stats = parsed.decode_stats.expect("should have stats");
        assert_eq!(stats.k, 16);
        assert_eq!(stats.dropped, 4);
    }
}
