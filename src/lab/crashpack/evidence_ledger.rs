//! Evidence ledger for ATP transfer oracles and failure tracking.
//!
//! Extends the existing evidence infrastructure in `lab/oracle/evidence.rs`
//! with ATP-specific failure recording and artifact path management.

use crate::lab::oracle::evidence::{EvidenceStrength, EvidenceEntry};
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
    pub fn record_oracle_result(
        &mut self,
        oracle_name: impl Into<String>,
        evidence: EvidenceEntry,
        artifact_path: Option<PathBuf>,
    ) {
        // Store artifact path if provided
        if let Some(ref path) = artifact_path {
            if !self.artifact_paths.contains(path) {
                self.artifact_paths.push(path.clone());
            }
        }

        let entry = AtpEvidenceEntry {
            oracle_name: oracle_name.into(),
            evidence,
            artifact_path,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };

        self.entries.push(entry);
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
    /// Unix timestamp when this evidence was recorded.
    pub timestamp: u64,
}

/// Summary statistics for evidence entries.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct EvidenceSummary {
    pub total: usize,
    pub against: usize,
    pub negligible: usize,
    pub positive: usize,
    pub strong: usize,
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