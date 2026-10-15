//! ATP transfer oracles and crashpack infrastructure.
//!
//! This module implements ATP-L2 requirements for deterministic failure reproduction:
//!
//! - **Transfer oracles**: Validate manifest integrity, journal consistency,
//!   quiescence, obligation leaks, path outcome consistency
//! - **Crashpacks**: Serializable failure artifacts for reproduction
//! - **Evidence ledger**: Record seeds, oracle failures, and artifact paths
//! - **Replay coordination**: Bridge lab models to deterministic replay
//!
//! # Quick Start
//!
//! ```ignore
//! use asupersync::lab::crashpack::{TransferOracle, CrashpackBuilder};
//!
//! // Create oracle for transfer validation
//! let oracle = TransferOracle::new("manifest_integrity");
//! let result = oracle.validate_transfer(&transfer_state);
//!
//! // Build crashpack on failure
//! if result.has_violations() {
//!     let crashpack = CrashpackBuilder::new()
//!         .with_oracle_result(result)
//!         .with_trace(&trace_buffer)
//!         .build()?;
//!
//!     crashpack.emit_atp_trace("failure_artifacts/")?;
//! }
//! ```

pub mod agent_proof;
pub mod evidence_ledger;
pub mod oracle;
pub mod replay;

// Re-export key types for convenience
pub use agent_proof::{
    AgentProofError, AgentTaskProofBundle, AgentTaskProofBundleBuilder, BlockerRecord,
    CommandRecord, CommitRecord, FileReservationRecord, RchRecord, ReplayInstructions,
    ReplaySafetyLevel, ValidationFrontierRecord,
};
pub use evidence_ledger::{AtpEvidenceEntry, AtpEvidenceLedger, EvidenceSummary};
pub use oracle::{AtpOracleChecks, AtpOracleResult, AtpTransferOracle, AtpTransferState};
pub use replay::{
    AtpReplayCoordinator, AtpReplayResult, ReplayError, TraceMinimizer, TraceMinimizerConfig,
};

use crate::lab::oracle::OracleStats;
use crate::lab::oracle::evidence::{
    BayesFactor, EvidenceEntry, EvidenceLine, EvidenceStrength, LogLikelihoodContributions,
};
use crate::trace::{TraceBuffer, TraceData, TraceEvent, TraceEventKind};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// ATP crashpack schema version for serialization compatibility.
pub const ATP_CRASHPACK_SCHEMA_VERSION: u32 = 1;

/// Transfer oracle for ATP-specific validation checks.
#[derive(Debug, Clone)]
pub struct TransferOracle {
    oracle_name: String,
    manifest_checks: bool,
    journal_checks: bool,
    quiescence_checks: bool,
    obligation_checks: bool,
    path_consistency_checks: bool,
}

impl TransferOracle {
    /// Create a new transfer oracle with the given name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            oracle_name: name.into(),
            manifest_checks: true,
            journal_checks: true,
            quiescence_checks: true,
            obligation_checks: true,
            path_consistency_checks: true,
        }
    }

    /// Enable/disable manifest integrity checks.
    pub fn with_manifest_checks(mut self, enabled: bool) -> Self {
        self.manifest_checks = enabled;
        self
    }

    /// Enable/disable journal consistency checks.
    pub fn with_journal_checks(mut self, enabled: bool) -> Self {
        self.journal_checks = enabled;
        self
    }

    /// Validate a transfer operation with configured checks.
    pub fn validate_transfer(&self, state: &TransferState) -> TransferOracleResult {
        let mut violations = Vec::new();
        let mut stats = OracleStats {
            entities_tracked: 0,
            events_recorded: 0,
        };

        if self.manifest_checks {
            if let Some(violation) = self.check_manifest_integrity(state) {
                violations.push(violation);
                stats.entities_tracked += 1;
            }
            stats.events_recorded += 1;
        }

        if self.journal_checks {
            if let Some(violation) = self.check_journal_consistency(state) {
                violations.push(violation);
                stats.entities_tracked += 1;
            }
            stats.events_recorded += 1;
        }

        if self.quiescence_checks {
            if let Some(violation) = self.check_quiescence(state) {
                violations.push(violation);
                stats.entities_tracked += 1;
            }
            stats.events_recorded += 1;
        }

        if self.obligation_checks {
            if let Some(violation) = self.check_obligation_leaks(state) {
                violations.push(violation);
                stats.entities_tracked += 1;
            }
            stats.events_recorded += 1;
        }

        if self.path_consistency_checks {
            if let Some(violation) = self.check_path_consistency(state) {
                violations.push(violation);
                stats.entities_tracked += 1;
            }
            stats.events_recorded += 1;
        }

        let passed = stats.entities_tracked == 0;
        TransferOracleResult {
            oracle_name: self.oracle_name.clone(),
            violations,
            stats,
            passed,
        }
    }

    fn check_manifest_integrity(&self, state: &TransferState) -> Option<TransferViolation> {
        // Check that manifest hash matches expected
        if state.manifest_hash != state.expected_manifest_hash {
            return Some(TransferViolation {
                violation_type: "manifest_integrity".to_string(),
                description: format!(
                    "Manifest hash mismatch: expected {}, got {}",
                    state.expected_manifest_hash, state.manifest_hash
                ),
                severity: ViolationSeverity::High,
                evidence: BTreeMap::from([
                    (
                        "expected_hash".to_string(),
                        state.expected_manifest_hash.clone(),
                    ),
                    ("actual_hash".to_string(), state.manifest_hash.clone()),
                ]),
            });
        }
        None
    }

    fn check_journal_consistency(&self, state: &TransferState) -> Option<TransferViolation> {
        // Check journal entry ordering and completeness
        if state.journal_gaps > 0 {
            return Some(TransferViolation {
                violation_type: "journal_consistency".to_string(),
                description: format!(
                    "Journal has {} gaps or ordering violations",
                    state.journal_gaps
                ),
                severity: ViolationSeverity::High,
                evidence: BTreeMap::from([(
                    "gap_count".to_string(),
                    state.journal_gaps.to_string(),
                )]),
            });
        }
        None
    }

    fn check_quiescence(&self, state: &TransferState) -> Option<TransferViolation> {
        // Ensure no pending operations during transfer
        if state.pending_operations > 0 {
            return Some(TransferViolation {
                violation_type: "quiescence".to_string(),
                description: format!(
                    "Transfer attempted with {} pending operations",
                    state.pending_operations
                ),
                severity: ViolationSeverity::Medium,
                evidence: BTreeMap::from([(
                    "pending_count".to_string(),
                    state.pending_operations.to_string(),
                )]),
            });
        }
        None
    }

    fn check_obligation_leaks(&self, state: &TransferState) -> Option<TransferViolation> {
        // Check for leaked obligations that should have been cleaned up
        if state.leaked_obligations > 0 {
            return Some(TransferViolation {
                violation_type: "obligation_leak".to_string(),
                description: format!("Found {} leaked obligations", state.leaked_obligations),
                severity: ViolationSeverity::High,
                evidence: BTreeMap::from([(
                    "leak_count".to_string(),
                    state.leaked_obligations.to_string(),
                )]),
            });
        }
        None
    }

    fn check_path_consistency(&self, state: &TransferState) -> Option<TransferViolation> {
        // Validate path outcome consistency
        if !state.path_outcomes_consistent {
            return Some(TransferViolation {
                violation_type: "path_consistency".to_string(),
                description: "Path outcomes are inconsistent across replicas".to_string(),
                severity: ViolationSeverity::High,
                evidence: BTreeMap::new(),
            });
        }
        None
    }
}

/// State snapshot for transfer oracle validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferState {
    pub manifest_hash: String,
    pub expected_manifest_hash: String,
    pub journal_gaps: u32,
    pub pending_operations: u32,
    pub leaked_obligations: u32,
    pub path_outcomes_consistent: bool,
}

impl TransferState {
    pub fn new() -> Self {
        Self {
            manifest_hash: String::new(),
            expected_manifest_hash: String::new(),
            journal_gaps: 0,
            pending_operations: 0,
            leaked_obligations: 0,
            path_outcomes_consistent: true,
        }
    }
}

impl Default for TransferState {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of transfer oracle validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferOracleResult {
    pub oracle_name: String,
    pub violations: Vec<TransferViolation>,
    pub stats: OracleStats,
    pub passed: bool,
}

impl TransferOracleResult {
    pub fn has_violations(&self) -> bool {
        !self.violations.is_empty()
    }

    pub fn high_severity_violations(&self) -> Vec<&TransferViolation> {
        self.violations
            .iter()
            .filter(|v| matches!(v.severity, ViolationSeverity::High))
            .collect()
    }
}

/// Specific violation found by transfer oracle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferViolation {
    pub violation_type: String,
    pub description: String,
    pub severity: ViolationSeverity,
    pub evidence: BTreeMap<String, String>,
}

/// Severity classification for violations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ViolationSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Builder for ATP crashpacks containing failure artifacts.
#[derive(Debug, Default)]
pub struct CrashpackBuilder {
    oracle_results: Vec<TransferOracleResult>,
    trace_buffer: Option<TraceBuffer>,
    seeds: BTreeMap<String, u64>,
    artifact_paths: Vec<String>,
    metadata: BTreeMap<String, String>,
}

impl CrashpackBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_oracle_result(mut self, result: TransferOracleResult) -> Self {
        self.oracle_results.push(result);
        self
    }

    pub fn with_trace(mut self, trace: TraceBuffer) -> Self {
        self.trace_buffer = Some(trace);
        self
    }

    pub fn with_seed(mut self, name: impl Into<String>, seed: u64) -> Self {
        self.seeds.insert(name.into(), seed);
        self
    }

    pub fn with_artifact_path(mut self, path: impl Into<String>) -> Self {
        let path = path.into();
        if !self.artifact_paths.contains(&path) {
            self.artifact_paths.push(path); // ubs:ignore - pushing to vector, not path join
        }
        self
    }

    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    pub fn build(self) -> Result<AtpCrashpack, CrashpackError> {
        Ok(AtpCrashpack {
            schema_version: ATP_CRASHPACK_SCHEMA_VERSION,
            oracle_results: self.oracle_results,
            trace_events: self
                .trace_buffer
                .as_ref()
                .map(|buf| buf.iter().cloned().collect())
                .unwrap_or_default(),
            seeds: self.seeds,
            artifact_paths: self.artifact_paths,
            metadata: self.metadata,
        })
    }
}

/// Serializable crashpack containing all failure reproduction artifacts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtpCrashpack {
    pub schema_version: u32,
    pub oracle_results: Vec<TransferOracleResult>,
    pub trace_events: Vec<TraceEvent>,
    pub seeds: BTreeMap<String, u64>,
    pub artifact_paths: Vec<String>,
    pub metadata: BTreeMap<String, String>,
}

impl AtpCrashpack {
    /// Emit ATP trace artifacts to the specified directory.
    pub fn emit_atp_trace(&self, output_dir: impl AsRef<Path>) -> Result<(), CrashpackError> {
        let output_dir = output_dir.as_ref();
        std::fs::create_dir_all(output_dir)?;

        // Emit transfer.atp-trace
        let trace_path = output_dir.join("transfer.atp-trace");
        let trace_data = serde_json::to_string_pretty(&self.trace_events)?;
        std::fs::write(&trace_path, trace_data)?;

        // Emit journal digest
        let journal_data = self.generate_journal_digest()?;
        let journal_digest = journal_digest_ref(&journal_data);
        let journal_path = output_dir.join("journal");
        std::fs::write(&journal_path, &journal_data)?;

        let journal_digest_path = output_dir.join("journal.digest");
        std::fs::write(
            &journal_digest_path,
            format!("digest: {journal_digest}\nbytes: {}\n", journal_data.len()),
        )?;

        // Emit deterministic evidence ledger before the manifest so the
        // manifest can point at the exact ledger artifact.
        let evidence_ledger_path = output_dir.join("evidence-ledger.json");
        let evidence_ledger = self.generate_evidence_ledger();
        std::fs::write(&evidence_ledger_path, evidence_ledger.export_json()?)?;

        // Emit manifest after the journal so it can point at the exact digest.
        let manifest_path = output_dir.join("manifest");
        let manifest_data = self.generate_manifest(&journal_digest)?;
        std::fs::write(&manifest_path, manifest_data)?;

        // Emit pathlog, quiclog, repairlog
        self.emit_specialized_logs(output_dir)?;

        // Generate replay command
        let replay_cmd = self.generate_replay_command()?;
        let replay_path = output_dir.join("replay_command.sh");
        std::fs::write(&replay_path, replay_cmd)?;

        Ok(())
    }

    fn generate_manifest(&self, journal_digest: &str) -> Result<String, CrashpackError> {
        let mut manifest = format!(
            "# ATP Crashpack Manifest\nschema_version: {}\nviolations: {}\njournal_digest: {journal_digest}\njournal_digest_artifact: journal.digest\nevidence_ledger: evidence-ledger.json\n",
            self.schema_version,
            self.oracle_results
                .iter()
                .map(|r| r.violations.len())
                .sum::<usize>()
        );

        for (key, value) in &self.metadata {
            manifest.push_str(&format!("metadata.{key}: {value}\n"));
        }

        if !self.seeds.is_empty() {
            manifest.push_str("seeds:\n");
            for (name, seed) in &self.seeds {
                manifest.push_str(&format!("  {name}: {seed}\n"));
            }
        }

        if !self.artifact_paths.is_empty() {
            manifest.push_str("artifact_paths:\n");
            for path in &self.artifact_paths {
                manifest.push_str(&format!("  - {path}\n"));
            }
        }

        Ok(manifest)
    }

    fn generate_journal_digest(&self) -> Result<String, CrashpackError> {
        let mut journal = String::from("# ATP Journal Digest\n");

        for result in &self.oracle_results {
            journal.push_str(&format!("oracle: {}\n", result.oracle_name));
            journal.push_str(&format!(
                "  events_recorded: {}\n",
                result.stats.events_recorded
            ));
            journal.push_str(&format!(
                "  entities_tracked: {}\n",
                result.stats.entities_tracked
            ));
            journal.push_str(&format!("  passed: {}\n", result.passed));
            if !result.violations.is_empty() {
                journal.push_str("  violations:\n");
                for violation in &result.violations {
                    journal.push_str(&format!("    - type: {}\n", violation.violation_type));
                    journal.push_str(&format!("      severity: {:?}\n", violation.severity));
                    journal.push_str(&format!("      description: {}\n", violation.description));
                    if !violation.evidence.is_empty() {
                        journal.push_str("      evidence:\n");
                        for (key, value) in &violation.evidence {
                            journal.push_str(&format!("        {key}: {value}\n"));
                        }
                    }
                }
            }
        }

        Ok(journal)
    }

    fn generate_evidence_ledger(&self) -> AtpEvidenceLedger {
        let mut ledger = AtpEvidenceLedger::new();

        for (name, seed) in &self.seeds {
            ledger.record_seed(name.clone(), *seed);
        }

        for (key, value) in &self.metadata {
            ledger.add_metadata(key.clone(), value.clone());
        }

        for artifact in [
            "transfer.atp-trace",
            "manifest",
            "journal",
            "journal.digest",
            "evidence-ledger.json",
            "pathlog",
            "quiclog",
            "repairlog",
            "replay_command.sh",
        ] {
            ledger.record_artifact_path(PathBuf::from(artifact));
        }

        for artifact in &self.artifact_paths {
            ledger.record_artifact_path(PathBuf::from(artifact));
        }

        for result in &self.oracle_results {
            ledger.record_oracle_result(
                result.oracle_name.clone(),
                evidence_for_oracle_result(result),
                Some(PathBuf::from("transfer.atp-trace")),
            );
        }

        ledger
    }

    fn emit_specialized_logs(&self, output_dir: &Path) -> Result<(), CrashpackError> {
        self.write_specialized_log(output_dir, "pathlog", is_atp_path_event)?;
        self.write_specialized_log(output_dir, "quiclog", is_atp_quic_event)?;
        self.write_specialized_log(output_dir, "repairlog", is_atp_repair_event)?;

        Ok(())
    }

    fn write_specialized_log(
        &self,
        output_dir: &Path,
        file_name: &str,
        include: impl Fn(&TraceEvent) -> bool,
    ) -> Result<(), CrashpackError> {
        let log = atp_specialized_log(&self.trace_events, include);
        std::fs::write(output_dir.join(file_name), log)?;
        Ok(())
    }
}

pub(crate) fn atp_specialized_log(
    trace_events: &[TraceEvent],
    include: impl Fn(&TraceEvent) -> bool,
) -> String {
    trace_events
        .iter()
        .filter(|event| include(event))
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n")
}

pub(crate) fn is_atp_path_event(event: &TraceEvent) -> bool {
    matches!(
        event.kind,
        TraceEventKind::Spawn
            | TraceEventKind::Schedule
            | TraceEventKind::Yield
            | TraceEventKind::Wake
            | TraceEventKind::Poll
            | TraceEventKind::Complete
            | TraceEventKind::RegionCreated
            | TraceEventKind::RegionCloseBegin
            | TraceEventKind::RegionCloseComplete
            | TraceEventKind::RegionCancelled
            | TraceEventKind::Checkpoint
    ) || message_contains_any(event, &["path", "route", "racing"])
}

pub(crate) fn is_atp_quic_event(event: &TraceEvent) -> bool {
    message_contains_any(event, &["quic", "udp", "packet", "connection id"])
}

pub(crate) fn is_atp_repair_event(event: &TraceEvent) -> bool {
    message_contains_any(event, &["repair", "raptorq", "fec", "symbol"])
}

fn message_contains_any(event: &TraceEvent, needles: &[&str]) -> bool {
    let TraceData::Message(message) = &event.data else {
        return false;
    };
    let message = message.to_ascii_lowercase();
    needles.iter().any(|needle| message.contains(needle))
}

impl AtpCrashpack {
    fn generate_replay_command(&self) -> Result<String, CrashpackError> {
        let mut cmd = String::from("#!/bin/bash\n");
        cmd.push_str("# ATP Replay Command\n");
        cmd.push_str("# Generated by ATP crashpack\n\n");

        // Add seed information
        for (name, seed) in &self.seeds {
            cmd.push_str(&format!(
                "export ATP_SEED_{}={}\n",
                seed_env_suffix(name),
                seed
            ));
        }

        cmd.push_str("\n# Replay command\n");
        cmd.push_str(
            "asupersync atp replay --trace-file transfer.atp-trace --manifest manifest \
             --journal-digest journal.digest --evidence-ledger evidence-ledger.json \
             --pathlog pathlog --quiclog quiclog --repairlog repairlog --validate-oracles",
        );

        // Add oracle flags
        for result in &self.oracle_results {
            cmd.push_str(&format!(" --oracle {}", shell_arg(&result.oracle_name)));
        }

        cmd.push('\n');
        Ok(cmd)
    }
}

fn seed_env_suffix(name: &str) -> String {
    let mut suffix = String::with_capacity(name.len());
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            suffix.push(ch.to_ascii_uppercase());
        } else {
            suffix.push('_');
        }
    }

    let suffix = suffix.trim_matches('_');
    if suffix.is_empty() {
        "SEED".to_string()
    } else {
        suffix.to_string()
    }
}

fn shell_arg(raw: &str) -> String {
    if !raw.is_empty() && raw.bytes().all(shell_safe_byte) {
        return raw.to_string();
    }

    let mut quoted = String::with_capacity(raw.len() + 2);
    quoted.push('\'');
    for ch in raw.chars() {
        if ch == '\'' {
            quoted.push_str("'\"'\"'");
        } else {
            quoted.push(ch);
        }
    }
    quoted.push('\'');
    quoted
}

fn shell_safe_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'_' | b'-' | b'.' | b'/' | b':' | b'@' | b'%' | b'+' | b'=' | b','
        )
}

fn journal_digest_ref(journal_data: &str) -> String {
    let digest = Sha256::digest(journal_data.as_bytes());
    format!("sha256:{}", hex::encode(digest))
}

fn evidence_for_oracle_result(result: &TransferOracleResult) -> EvidenceEntry {
    let log10_bf = if result.passed {
        -1.0
    } else {
        result
            .violations
            .iter()
            .map(|violation| severity_log10_bf(&violation.severity))
            .reduce(f64::max)
            .unwrap_or(0.5)
    };

    let strength = EvidenceStrength::from_log10_bf(log10_bf);
    let max_severity = result
        .violations
        .iter()
        .max_by_key(|violation| severity_rank(&violation.severity))
        .map_or("none", |violation| severity_label(&violation.severity));

    EvidenceEntry {
        invariant: result.oracle_name.clone(),
        passed: result.passed,
        bayes_factor: BayesFactor {
            log10_bf,
            hypothesis: format!("{} violation", result.oracle_name),
            strength,
        },
        log_likelihoods: LogLikelihoodContributions {
            structural: log10_bf / 2.0,
            detection: log10_bf / 2.0,
            total: log10_bf,
        },
        evidence_lines: vec![EvidenceLine {
            equation: "BF = P(oracle evidence | violation) / P(oracle evidence | clean)"
                .to_string(),
            substitution: format!(
                "passed={}, violations={}, events_recorded={}, entities_tracked={}, max_severity={max_severity}",
                result.passed,
                result.violations.len(),
                result.stats.events_recorded,
                result.stats.entities_tracked
            ),
            intuition: if result.passed {
                format!(
                    "{} produced deterministic clean evidence",
                    result.oracle_name
                )
            } else {
                format!(
                    "{} reported {} deterministic violation(s)",
                    result.oracle_name,
                    result.violations.len()
                )
            },
        }],
    }
}

fn severity_log10_bf(severity: &ViolationSeverity) -> f64 {
    match severity {
        ViolationSeverity::Low => 0.6,
        ViolationSeverity::Medium => 1.0,
        ViolationSeverity::High => 1.6,
        ViolationSeverity::Critical => 2.4,
    }
}

fn severity_label(severity: &ViolationSeverity) -> &'static str {
    match severity {
        ViolationSeverity::Low => "low",
        ViolationSeverity::Medium => "medium",
        ViolationSeverity::High => "high",
        ViolationSeverity::Critical => "critical",
    }
}

fn severity_rank(severity: &ViolationSeverity) -> u8 {
    match severity {
        ViolationSeverity::Low => 0,
        ViolationSeverity::Medium => 1,
        ViolationSeverity::High => 2,
        ViolationSeverity::Critical => 3,
    }
}

/// Errors during crashpack operations.
#[derive(Debug, Error)]
pub enum CrashpackError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Invalid crashpack format: {0}")]
    InvalidFormat(String),
}
