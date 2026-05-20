//! ATP transfer oracles for manifest, journal, and proof bundle validation.
//!
//! Implements specific oracles required by ATP-L2:
//! - Manifest integrity oracle
//! - Journal consistency oracle
//! - Quiescence oracle
//! - Obligation leak oracle
//! - Path outcome consistency oracle
//! - Proof bundle validity oracle

use crate::lab::oracle::evidence::{EvidenceStrength, OracleEvidence};
use crate::lab::oracle::{OracleReport, OracleStats};
use crate::lab::crashpack::evidence_ledger::AtpEvidenceLedger;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Composite ATP oracle that runs all transfer validation checks.
#[derive(Debug, Clone)]
pub struct AtpTransferOracle {
    pub name: String,
    pub enabled_checks: AtpOracleChecks,
}

impl AtpTransferOracle {
    /// Create a new ATP transfer oracle with all checks enabled.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            enabled_checks: AtpOracleChecks::all(),
        }
    }

    /// Create an oracle with only basic checks enabled.
    pub fn basic() -> Self {
        Self {
            name: "atp_basic_transfer".to_string(),
            enabled_checks: AtpOracleChecks::basic(),
        }
    }

    /// Run all enabled oracle checks against the transfer state.
    pub fn validate(&self, state: &AtpTransferState) -> AtpOracleResult {
        let mut evidence_ledger = AtpEvidenceLedger::new();
        let mut stats = OracleStats::default();
        let mut passed = true;

        // Manifest integrity check
        if self.enabled_checks.manifest_integrity {
            let evidence = self.check_manifest_integrity(state);
            let oracle_passed = matches!(evidence.strength(), EvidenceStrength::Against | EvidenceStrength::Negligible);

            evidence_ledger.record_oracle_result("manifest_integrity", evidence, None);
            stats.checks += 1;

            if !oracle_passed {
                stats.violations += 1;
                passed = false;
            }
        }

        // Journal consistency check
        if self.enabled_checks.journal_consistency {
            let evidence = self.check_journal_consistency(state);
            let oracle_passed = matches!(evidence.strength(), EvidenceStrength::Against | EvidenceStrength::Negligible);

            evidence_ledger.record_oracle_result("journal_consistency", evidence, None);
            stats.checks += 1;

            if !oracle_passed {
                stats.violations += 1;
                passed = false;
            }
        }

        // Quiescence check
        if self.enabled_checks.quiescence {
            let evidence = self.check_quiescence(state);
            let oracle_passed = matches!(evidence.strength(), EvidenceStrength::Against | EvidenceStrength::Negligible);

            evidence_ledger.record_oracle_result("quiescence", evidence, None);
            stats.checks += 1;

            if !oracle_passed {
                stats.violations += 1;
                passed = false;
            }
        }

        // Obligation leak check
        if self.enabled_checks.obligation_leak {
            let evidence = self.check_obligation_leak(state);
            let oracle_passed = matches!(evidence.strength(), EvidenceStrength::Against | EvidenceStrength::Negligible);

            evidence_ledger.record_oracle_result("obligation_leak", evidence, None);
            stats.checks += 1;

            if !oracle_passed {
                stats.violations += 1;
                passed = false;
            }
        }

        // Path consistency check
        if self.enabled_checks.path_consistency {
            let evidence = self.check_path_consistency(state);
            let oracle_passed = matches!(evidence.strength(), EvidenceStrength::Against | EvidenceStrength::Negligible);

            evidence_ledger.record_oracle_result("path_consistency", evidence, None);
            stats.checks += 1;

            if !oracle_passed {
                stats.violations += 1;
                passed = false;
            }
        }

        // Proof bundle validity check
        if self.enabled_checks.proof_bundle_validity {
            let evidence = self.check_proof_bundle_validity(state);
            let oracle_passed = matches!(evidence.strength(), EvidenceStrength::Against | EvidenceStrength::Negligible);

            evidence_ledger.record_oracle_result("proof_bundle_validity", evidence, None);
            stats.checks += 1;

            if !oracle_passed {
                stats.violations += 1;
                passed = false;
            }
        }

        AtpOracleResult {
            oracle_name: self.name.clone(),
            evidence_ledger,
            stats,
            passed,
        }
    }

    fn check_manifest_integrity(&self, state: &AtpTransferState) -> OracleEvidence {
        let hash_match = state.manifest_hash == state.expected_manifest_hash;

        if hash_match {
            // Evidence against violation (manifest is correct)
            OracleEvidence::new(
                "manifest_integrity".to_string(),
                -2.0, // Strong evidence against violation
                vec![
                    format!("P(hash_match | manifest_correct) = 0.999"),
                    format!("P(hash_match | manifest_corrupted) = 0.001"),
                    format!("Observed: hash_match = true"),
                    format!("Conclusion: Very strong evidence that manifest is correct"),
                ],
            )
        } else {
            // Evidence for violation (manifest is corrupted)
            OracleEvidence::new(
                "manifest_integrity".to_string(),
                3.0, // Very strong evidence for violation
                vec![
                    format!("P(hash_mismatch | manifest_correct) = 0.001"),
                    format!("P(hash_mismatch | manifest_corrupted) = 0.999"),
                    format!("Observed: expected={}, actual={}", state.expected_manifest_hash, state.manifest_hash),
                    format!("Conclusion: Very strong evidence of manifest corruption"),
                ],
            )
        }
    }

    fn check_journal_consistency(&self, state: &AtpTransferState) -> OracleEvidence {
        let has_gaps = state.journal_gaps > 0;

        if !has_gaps {
            OracleEvidence::new(
                "journal_consistency".to_string(),
                -1.5, // Strong evidence against violation
                vec![
                    format!("P(no_gaps | journal_consistent) = 0.95"),
                    format!("P(no_gaps | journal_inconsistent) = 0.05"),
                    format!("Observed: journal_gaps = 0"),
                    format!("Conclusion: Strong evidence that journal is consistent"),
                ],
            )
        } else {
            let log_bf = (state.journal_gaps as f64).log10() + 1.0;
            OracleEvidence::new(
                "journal_consistency".to_string(),
                log_bf, // Evidence strength scales with gap count
                vec![
                    format!("P(gaps | journal_consistent) = 0.01"),
                    format!("P(gaps | journal_inconsistent) = 0.9"),
                    format!("Observed: journal_gaps = {}", state.journal_gaps),
                    format!("Conclusion: Evidence of journal inconsistency (gaps detected)"),
                ],
            )
        }
    }

    fn check_quiescence(&self, state: &AtpTransferState) -> OracleEvidence {
        let has_pending = state.pending_operations > 0;

        if !has_pending {
            OracleEvidence::new(
                "quiescence".to_string(),
                -1.0, // Positive evidence against violation
                vec![
                    format!("P(no_pending | quiescent) = 0.9"),
                    format!("P(no_pending | not_quiescent) = 0.1"),
                    format!("Observed: pending_operations = 0"),
                    format!("Conclusion: Positive evidence of quiescence"),
                ],
            )
        } else {
            let log_bf = (state.pending_operations as f64 / 10.0).log10() + 0.5;
            OracleEvidence::new(
                "quiescence".to_string(),
                log_bf,
                vec![
                    format!("P(pending | quiescent) = 0.05"),
                    format!("P(pending | not_quiescent) = 0.8"),
                    format!("Observed: pending_operations = {}", state.pending_operations),
                    format!("Conclusion: Evidence against quiescence (operations still pending)"),
                ],
            )
        }
    }

    fn check_obligation_leak(&self, state: &AtpTransferState) -> OracleEvidence {
        let has_leaks = state.leaked_obligations > 0;

        if !has_leaks {
            OracleEvidence::new(
                "obligation_leak".to_string(),
                -1.5, // Strong evidence against violation
                vec![
                    format!("P(no_leaks | correct_cleanup) = 0.95"),
                    format!("P(no_leaks | obligation_leak) = 0.05"),
                    format!("Observed: leaked_obligations = 0"),
                    format!("Conclusion: Strong evidence of correct obligation cleanup"),
                ],
            )
        } else {
            let log_bf = (state.leaked_obligations as f64).log10() + 1.5;
            OracleEvidence::new(
                "obligation_leak".to_string(),
                log_bf,
                vec![
                    format!("P(leaks | correct_cleanup) = 0.01"),
                    format!("P(leaks | obligation_leak) = 0.95"),
                    format!("Observed: leaked_obligations = {}", state.leaked_obligations),
                    format!("Conclusion: Strong evidence of obligation leak"),
                ],
            )
        }
    }

    fn check_path_consistency(&self, state: &AtpTransferState) -> OracleEvidence {
        if state.path_outcomes_consistent {
            OracleEvidence::new(
                "path_consistency".to_string(),
                -1.0,
                vec![
                    format!("P(consistent | correct_paths) = 0.9"),
                    format!("P(consistent | inconsistent_paths) = 0.1"),
                    format!("Observed: path_outcomes_consistent = true"),
                    format!("Conclusion: Positive evidence of path consistency"),
                ],
            )
        } else {
            OracleEvidence::new(
                "path_consistency".to_string(),
                2.0, // Strong evidence for violation
                vec![
                    format!("P(inconsistent | correct_paths) = 0.05"),
                    format!("P(inconsistent | inconsistent_paths) = 0.8"),
                    format!("Observed: path_outcomes_consistent = false"),
                    format!("Conclusion: Strong evidence of path inconsistency"),
                ],
            )
        }
    }

    fn check_proof_bundle_validity(&self, state: &AtpTransferState) -> OracleEvidence {
        if state.proof_bundle_valid {
            OracleEvidence::new(
                "proof_bundle_validity".to_string(),
                -1.2,
                vec![
                    format!("P(valid_bundle | correct_proof) = 0.92"),
                    format!("P(valid_bundle | invalid_proof) = 0.08"),
                    format!("Observed: proof_bundle_valid = true"),
                    format!("Conclusion: Strong evidence of valid proof bundle"),
                ],
            )
        } else {
            OracleEvidence::new(
                "proof_bundle_validity".to_string(),
                1.8, // Strong evidence for violation
                vec![
                    format!("P(invalid_bundle | correct_proof) = 0.02"),
                    format!("P(invalid_bundle | invalid_proof) = 0.9"),
                    format!("Observed: proof_bundle_valid = false"),
                    format!("Conclusion: Strong evidence of invalid proof bundle"),
                ],
            )
        }
    }
}

/// Configuration for which ATP oracle checks to enable.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct AtpOracleChecks {
    pub manifest_integrity: bool,
    pub journal_consistency: bool,
    pub quiescence: bool,
    pub obligation_leak: bool,
    pub path_consistency: bool,
    pub proof_bundle_validity: bool,
}

impl AtpOracleChecks {
    /// Enable all oracle checks.
    pub fn all() -> Self {
        Self {
            manifest_integrity: true,
            journal_consistency: true,
            quiescence: true,
            obligation_leak: true,
            path_consistency: true,
            proof_bundle_validity: true,
        }
    }

    /// Enable only basic checks (manifest, journal, quiescence).
    pub fn basic() -> Self {
        Self {
            manifest_integrity: true,
            journal_consistency: true,
            quiescence: true,
            obligation_leak: false,
            path_consistency: false,
            proof_bundle_validity: false,
        }
    }
}

/// Complete state snapshot for ATP oracle validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtpTransferState {
    // Manifest integrity
    pub manifest_hash: String,
    pub expected_manifest_hash: String,

    // Journal consistency
    pub journal_gaps: u32,

    // Quiescence
    pub pending_operations: u32,

    // Obligation tracking
    pub leaked_obligations: u32,

    // Path consistency
    pub path_outcomes_consistent: bool,

    // Proof bundle validity
    pub proof_bundle_valid: bool,

    // Additional metadata
    pub metadata: BTreeMap<String, String>,
}

impl AtpTransferState {
    pub fn new() -> Self {
        Self {
            manifest_hash: String::new(),
            expected_manifest_hash: String::new(),
            journal_gaps: 0,
            pending_operations: 0,
            leaked_obligations: 0,
            path_outcomes_consistent: true,
            proof_bundle_valid: true,
            metadata: BTreeMap::new(),
        }
    }

    /// Create a clean state (no violations expected).
    pub fn clean() -> Self {
        Self {
            manifest_hash: "clean_hash_123".to_string(),
            expected_manifest_hash: "clean_hash_123".to_string(),
            journal_gaps: 0,
            pending_operations: 0,
            leaked_obligations: 0,
            path_outcomes_consistent: true,
            proof_bundle_valid: true,
            metadata: BTreeMap::new(),
        }
    }
}

impl Default for AtpTransferState {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of ATP oracle validation with evidence ledger.
#[derive(Debug, Clone)]
pub struct AtpOracleResult {
    pub oracle_name: String,
    pub evidence_ledger: AtpEvidenceLedger,
    pub stats: OracleStats,
    pub passed: bool,
}

impl AtpOracleResult {
    /// Get summary of evidence strength distribution.
    pub fn evidence_summary(&self) -> String {
        let summary = self.evidence_ledger.evidence_summary();
        summary.summary_text()
    }

    /// Check if there are any high-confidence violations.
    pub fn has_strong_violations(&self) -> bool {
        self.evidence_ledger.evidence_summary().has_strong_violations()
    }
}