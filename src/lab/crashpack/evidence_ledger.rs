//! Evidence ledger for ATP transfer oracles and failure tracking.
//!
//! Extends the existing evidence infrastructure in `lab/oracle/evidence.rs`
//! with ATP-specific failure recording and artifact path management.

use crate::lab::oracle::evidence::{EvidenceEntry, EvidenceStrength};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Evidence ledger for ATP transfer operations and failures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtpEvidenceLedger {
    /// Schema version for compatibility.
    pub schema_version: u32,
    /// Recorded evidence entries with timestamps.
    pub entries: Vec<AtpEvidenceEntry>,
    /// Seeds used for deterministic reproduction.
    pub seeds: BTreeMap<String, u64>,
    /// Paths to artifact files for this evidence session.
    pub artifact_paths: Vec<PathBuf>,
    /// Session metadata.
    pub metadata: BTreeMap<String, String>,
}

impl AtpEvidenceLedger {
    /// Create a new empty evidence ledger.
    pub fn new() -> Self {
        Self {
            schema_version: 1,
            entries: Vec::new(),
            seeds: BTreeMap::new(),
            artifact_paths: Vec::new(),
            metadata: BTreeMap::new(),
        }
    }

    /// Record evidence of oracle success or failure.
    ///
    /// The default timestamp is the zero-based ledger entry index. ATP evidence
    /// artifacts must be stable across deterministic replay, so callers that
    /// have a replay-clock timestamp should use [`Self::record_oracle_result_at`]
    /// rather than reading wall-clock time here.
    pub fn record_oracle_result(
        &mut self,
        oracle_name: impl Into<String>,
        evidence: EvidenceEntry,
        artifact_path: Option<PathBuf>,
    ) {
        let timestamp = u64::try_from(self.entries.len()).unwrap_or(u64::MAX);
        self.record_oracle_result_at(oracle_name, evidence, artifact_path, timestamp);
    }

    /// Record evidence of oracle success or failure with a deterministic timestamp.
    pub fn record_oracle_result_at(
        &mut self,
        oracle_name: impl Into<String>,
        evidence: EvidenceEntry,
        artifact_path: Option<PathBuf>,
        timestamp: u64,
    ) {
        self.record_optional_artifact_path(artifact_path.as_ref());
        let entry = AtpEvidenceEntry {
            oracle_name: oracle_name.into(),
            evidence,
            artifact_path,
            timestamp,
        };

        self.entries.push(entry);
    }

    /// Record an artifact path for this evidence session.
    pub fn record_artifact_path(&mut self, artifact_path: impl Into<PathBuf>) {
        let artifact_path = artifact_path.into();
        if !self.artifact_paths.contains(&artifact_path) {
            self.artifact_paths.push(artifact_path); // ubs:ignore - pushing to vector, not path join
        }
    }

    fn record_optional_artifact_path(&mut self, artifact_path: Option<&PathBuf>) {
        if let Some(path) = artifact_path {
            self.record_artifact_path(path.clone());
        }
    }

    /// Record a seed used for deterministic reproduction.
    pub fn record_seed(&mut self, name: impl Into<String>, seed: u64) {
        self.seeds.insert(name.into(), seed);
    }

    /// Add metadata about this evidence session.
    pub fn add_metadata(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.metadata.insert(key.into(), value.into());
    }

    /// Get all entries with violations (evidence strength against hypothesis).
    pub fn violation_entries(&self) -> Vec<&AtpEvidenceEntry> {
        self.entries
            .iter()
            .filter(|entry| {
                matches!(
                    entry.evidence.bayes_factor.strength,
                    EvidenceStrength::Positive
                        | EvidenceStrength::Strong
                        | EvidenceStrength::VeryStrong
                )
            })
            .collect()
    }

    /// Get summary of evidence strengths.
    pub fn evidence_summary(&self) -> EvidenceSummary {
        let mut summary = EvidenceSummary::default();

        for entry in &self.entries {
            match entry.evidence.bayes_factor.strength {
                EvidenceStrength::Against => summary.against += 1,
                EvidenceStrength::Negligible => summary.negligible += 1,
                EvidenceStrength::Positive => summary.positive += 1,
                EvidenceStrength::Strong => summary.strong += 1,
                EvidenceStrength::VeryStrong => summary.very_strong += 1,
            }
        }

        summary.total = self.entries.len();
        summary
    }

    /// Export evidence ledger to JSON format.
    pub fn export_json(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }

    /// Import evidence ledger from JSON format.
    pub fn import_json(json: &str) -> serde_json::Result<Self> {
        serde_json::from_str(json)
    }
}

impl Default for AtpEvidenceLedger {
    fn default() -> Self {
        Self::new()
    }
}

/// Single evidence entry in the ATP ledger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtpEvidenceEntry {
    /// Name of the oracle that produced this evidence.
    pub oracle_name: String,
    /// The evidence record with Bayes factors and explanations.
    pub evidence: EvidenceEntry,
    /// Optional path to artifacts related to this evidence.
    pub artifact_path: Option<PathBuf>,
    /// Deterministic logical timestamp when this evidence was recorded.
    pub timestamp: u64,
}

/// Summary statistics for evidence entries.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct EvidenceSummary {
    /// Total evidence entries recorded.
    pub total: usize,
    /// Entries with evidence against the violation hypothesis.
    pub against: usize,
    /// Entries with negligible evidence for the violation hypothesis.
    pub negligible: usize,
    /// Entries with positive evidence for the violation hypothesis.
    pub positive: usize,
    /// Entries with strong evidence for the violation hypothesis.
    pub strong: usize,
    /// Entries with very strong evidence for the violation hypothesis.
    pub very_strong: usize,
}

impl EvidenceSummary {
    /// Get the number of entries indicating violations.
    pub fn violation_count(&self) -> usize {
        self.positive + self.strong + self.very_strong
    }

    /// Check if there are any high-confidence violations.
    pub fn has_strong_violations(&self) -> bool {
        self.strong > 0 || self.very_strong > 0
    }

    /// Get a human-readable summary.
    pub fn summary_text(&self) -> String {
        format!(
            "Evidence: {} total, {} violations ({} strong+), {} against, {} negligible",
            self.total,
            self.violation_count(),
            self.strong + self.very_strong,
            self.against,
            self.negligible
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lab::oracle::evidence::{BayesFactor, EvidenceLine, LogLikelihoodContributions};

    fn evidence_entry(
        invariant: &str,
        passed: bool,
        log10_bf: f64,
        strength: EvidenceStrength,
    ) -> EvidenceEntry {
        EvidenceEntry {
            invariant: invariant.to_string(),
            passed,
            bayes_factor: BayesFactor {
                log10_bf,
                hypothesis: format!("{invariant} violation"),
                strength,
            },
            log_likelihoods: LogLikelihoodContributions {
                structural: log10_bf / 2.0,
                detection: log10_bf / 2.0,
                total: log10_bf,
            },
            evidence_lines: vec![EvidenceLine {
                equation: "BF = P(data | violation) / P(data | clean)".to_string(),
                substitution: format!("log10_bf={log10_bf}"),
                intuition: format!("{strength} evidence for {invariant}"),
            }],
        }
    }

    #[test]
    fn default_recording_uses_deterministic_entry_index_timestamps() {
        let mut ledger = AtpEvidenceLedger::new();

        ledger.record_oracle_result(
            "manifest_integrity",
            evidence_entry("manifest_integrity", true, -2.0, EvidenceStrength::Against),
            None,
        );
        ledger.record_oracle_result(
            "journal_consistency",
            evidence_entry("journal_consistency", false, 1.4, EvidenceStrength::Strong),
            None,
        );

        assert_eq!(ledger.entries[0].timestamp, 0);
        assert_eq!(ledger.entries[1].timestamp, 1);

        let exported_once = ledger.export_json().expect("ledger serializes");
        let exported_twice = ledger
            .export_json()
            .expect("ledger serializes deterministically");
        assert_eq!(exported_once, exported_twice);
    }

    #[test]
    fn explicit_recording_preserves_logical_timestamp_and_dedupes_artifacts() {
        let mut ledger = AtpEvidenceLedger::new();
        let artifact_path = PathBuf::from("artifacts/transfer.atp-trace");

        ledger.record_oracle_result_at(
            "proof_bundle_validity",
            evidence_entry(
                "proof_bundle_validity",
                false,
                2.4,
                EvidenceStrength::VeryStrong,
            ),
            Some(artifact_path.clone()),
            42,
        );
        ledger.record_oracle_result_at(
            "path_consistency",
            evidence_entry("path_consistency", false, 1.1, EvidenceStrength::Positive),
            Some(artifact_path.clone()),
            43,
        );

        assert_eq!(ledger.entries[0].timestamp, 42);
        assert_eq!(ledger.entries[1].timestamp, 43);
        assert_eq!(ledger.artifact_paths, vec![artifact_path]);
    }

    #[test]
    fn summary_and_violation_entries_are_strength_based() {
        let mut ledger = AtpEvidenceLedger::new();
        ledger.record_oracle_result(
            "clean",
            evidence_entry("clean", true, -1.0, EvidenceStrength::Against),
            None,
        );
        ledger.record_oracle_result(
            "weak",
            evidence_entry("weak", true, 0.2, EvidenceStrength::Negligible),
            None,
        );
        ledger.record_oracle_result(
            "strong",
            evidence_entry("strong", false, 1.8, EvidenceStrength::Strong),
            None,
        );

        let summary = ledger.evidence_summary();
        assert_eq!(summary.total, 3);
        assert_eq!(summary.against, 1);
        assert_eq!(summary.negligible, 1);
        assert_eq!(summary.strong, 1);
        assert_eq!(summary.violation_count(), 1);
        assert!(summary.has_strong_violations());

        let violations = ledger.violation_entries();
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].oracle_name, "strong");
    }

    #[test]
    fn json_roundtrip_preserves_seeds_artifacts_and_metadata() {
        let mut ledger = AtpEvidenceLedger::new();
        ledger.record_seed("lab", 7);
        ledger.add_metadata("transfer_id", "tx-123");
        ledger.record_oracle_result(
            "manifest_integrity",
            evidence_entry(
                "manifest_integrity",
                false,
                2.5,
                EvidenceStrength::VeryStrong,
            ),
            Some(PathBuf::from("artifacts/manifest")),
        );

        let json = ledger.export_json().expect("ledger serializes");
        let roundtrip = AtpEvidenceLedger::import_json(&json).expect("ledger deserializes");

        assert_eq!(roundtrip.schema_version, 1);
        assert_eq!(roundtrip.seeds.get("lab"), Some(&7));
        assert_eq!(
            roundtrip.metadata.get("transfer_id"),
            Some(&"tx-123".to_string())
        );
        assert_eq!(
            roundtrip.artifact_paths,
            vec![PathBuf::from("artifacts/manifest")]
        );
        assert_eq!(roundtrip.entries[0].timestamp, 0);
    }
}
