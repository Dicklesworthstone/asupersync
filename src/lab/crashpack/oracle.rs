//! ATP transfer oracles for manifest, journal, and proof bundle validation.
//!
//! Implements specific oracles required by ATP-L2:
//! - Manifest integrity oracle
//! - Journal consistency oracle
//! - Quiescence oracle
//! - Obligation leak oracle
//! - Path outcome consistency oracle
//! - Proof bundle validity oracle

use crate::lab::crashpack::evidence_ledger::AtpEvidenceLedger;
use crate::lab::oracle::OracleStats;
use crate::lab::oracle::evidence::{
    BayesFactor, EvidenceEntry, EvidenceLine, EvidenceStrength, LogLikelihoodContributions,
};
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
        let mut stats = OracleStats {
            entities_tracked: 0,
            events_recorded: 0,
        };
        let mut passed = true;

        // Manifest integrity check
        if self.enabled_checks.manifest_integrity {
            let evidence = self.check_manifest_integrity(state);
            let oracle_passed = matches!(
                evidence.bayes_factor.strength,
                EvidenceStrength::Against | EvidenceStrength::Negligible
            );

            evidence_ledger.record_oracle_result("manifest_integrity", evidence, None);
            stats.events_recorded += 1;

            if !oracle_passed {
                stats.entities_tracked += 1;
                passed = false;
            }
        }

        // Journal consistency check
        if self.enabled_checks.journal_consistency {
            let evidence = self.check_journal_consistency(state);
            let oracle_passed = matches!(
                evidence.bayes_factor.strength,
                EvidenceStrength::Against | EvidenceStrength::Negligible
            );

            evidence_ledger.record_oracle_result("journal_consistency", evidence, None);
            stats.events_recorded += 1;

            if !oracle_passed {
                stats.entities_tracked += 1;
                passed = false;
            }
        }

        // Quiescence check
        if self.enabled_checks.quiescence {
            let evidence = self.check_quiescence(state);
            let oracle_passed = matches!(
                evidence.bayes_factor.strength,
                EvidenceStrength::Against | EvidenceStrength::Negligible
            );

            evidence_ledger.record_oracle_result("quiescence", evidence, None);
            stats.events_recorded += 1;

            if !oracle_passed {
                stats.entities_tracked += 1;
                passed = false;
            }
        }

        // Final exposure check
        if self.enabled_checks.final_exposure {
            let evidence = self.check_final_exposure(state);
            let oracle_passed = matches!(
                evidence.bayes_factor.strength,
                EvidenceStrength::Against | EvidenceStrength::Negligible
            );

            evidence_ledger.record_oracle_result("final_exposure", evidence, None);
            stats.events_recorded += 1;

            if !oracle_passed {
                stats.entities_tracked += 1;
                passed = false;
            }
        }

        // Cancellation drain check
        if self.enabled_checks.cancellation_drain {
            let evidence = self.check_cancellation_drain(state);
            let oracle_passed = matches!(
                evidence.bayes_factor.strength,
                EvidenceStrength::Against | EvidenceStrength::Negligible
            );

            evidence_ledger.record_oracle_result("cancellation_drain", evidence, None);
            stats.events_recorded += 1;

            if !oracle_passed {
                stats.entities_tracked += 1;
                passed = false;
            }
        }

        // Obligation leak check
        if self.enabled_checks.obligation_leak {
            let evidence = self.check_obligation_leak(state);
            let oracle_passed = matches!(
                evidence.bayes_factor.strength,
                EvidenceStrength::Against | EvidenceStrength::Negligible
            );

            evidence_ledger.record_oracle_result("obligation_leak", evidence, None);
            stats.events_recorded += 1;

            if !oracle_passed {
                stats.entities_tracked += 1;
                passed = false;
            }
        }

        // Path consistency check
        if self.enabled_checks.path_consistency {
            let evidence = self.check_path_consistency(state);
            let oracle_passed = matches!(
                evidence.bayes_factor.strength,
                EvidenceStrength::Against | EvidenceStrength::Negligible
            );

            evidence_ledger.record_oracle_result("path_consistency", evidence, None);
            stats.events_recorded += 1;

            if !oracle_passed {
                stats.entities_tracked += 1;
                passed = false;
            }
        }

        // Proof bundle validity check
        if self.enabled_checks.proof_bundle_validity {
            let evidence = self.check_proof_bundle_validity(state);
            let oracle_passed = matches!(
                evidence.bayes_factor.strength,
                EvidenceStrength::Against | EvidenceStrength::Negligible
            );

            evidence_ledger.record_oracle_result("proof_bundle_validity", evidence, None);
            stats.events_recorded += 1;

            if !oracle_passed {
                stats.entities_tracked += 1;
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

    fn check_manifest_integrity(&self, state: &AtpTransferState) -> EvidenceEntry {
        let hash_match = state.manifest_hash == state.expected_manifest_hash;

        if hash_match {
            // Evidence against violation (manifest is correct)
            EvidenceEntry {
                invariant: "manifest_integrity".to_string(),
                passed: true,
                bayes_factor: BayesFactor {
                    log10_bf: -2.0, // Strong evidence against violation
                    hypothesis: "manifest corruption".to_string(),
                    strength: EvidenceStrength::from_log10_bf(-2.0),
                },
                log_likelihoods: LogLikelihoodContributions {
                    structural: -1.0,
                    detection: -1.0,
                    total: -2.0,
                },
                evidence_lines: vec![EvidenceLine {
                    equation:
                        "P(hash_match | manifest_correct) / P(hash_match | manifest_corrupted)"
                            .to_string(),
                    substitution: "0.999 / 0.001 = 999".to_string(),
                    intuition: "Very strong evidence that manifest is correct".to_string(),
                }],
            }
        } else {
            // Evidence for violation (manifest is corrupted)
            EvidenceEntry {
                invariant: "manifest_integrity".to_string(),
                passed: false,
                bayes_factor: BayesFactor {
                    log10_bf: 3.0, // Very strong evidence for violation
                    hypothesis: "manifest corruption".to_string(),
                    strength: EvidenceStrength::VeryStrong,
                },
                log_likelihoods: LogLikelihoodContributions {
                    structural: 1.5,
                    detection: 1.5,
                    total: 3.0,
                },
                evidence_lines: vec![
                    EvidenceLine {
                        equation: "P(hash_mismatch | manifest_correct) / P(hash_mismatch | manifest_corrupted)".to_string(),
                        substitution: "0.001 / 0.999 = 0.001".to_string(),
                        intuition: format!("Very strong evidence of manifest corruption: expected={}, actual={}",
                                         state.expected_manifest_hash, state.manifest_hash),
                    },
                ],
            }
        }
    }

    fn check_journal_consistency(&self, state: &AtpTransferState) -> EvidenceEntry {
        let has_gaps = state.journal_gaps > 0;

        if !has_gaps {
            EvidenceEntry {
                invariant: "journal_consistency".to_string(),
                passed: true,
                bayes_factor: BayesFactor {
                    log10_bf: -1.5,
                    hypothesis: "journal inconsistency".to_string(),
                    strength: EvidenceStrength::from_log10_bf(-1.5),
                },
                log_likelihoods: LogLikelihoodContributions {
                    structural: -0.7,
                    detection: -0.8,
                    total: -1.5,
                },
                evidence_lines: vec![EvidenceLine {
                    equation: "P(no_gaps | journal_consistent) / P(no_gaps | journal_inconsistent)"
                        .to_string(),
                    substitution: "0.95 / 0.05 = 19".to_string(),
                    intuition: "Strong evidence that journal is consistent".to_string(),
                }],
            }
        } else {
            let log_bf = (state.journal_gaps as f64).log10() + 1.0;
            EvidenceEntry {
                invariant: "journal_consistency".to_string(),
                passed: false,
                bayes_factor: BayesFactor {
                    log10_bf: log_bf,
                    hypothesis: "journal inconsistency".to_string(),
                    strength: EvidenceStrength::from_log10_bf(log_bf),
                },
                log_likelihoods: LogLikelihoodContributions {
                    structural: log_bf / 2.0,
                    detection: log_bf / 2.0,
                    total: log_bf,
                },
                evidence_lines: vec![EvidenceLine {
                    equation: "P(gaps | journal_consistent) / P(gaps | journal_inconsistent)"
                        .to_string(),
                    substitution: format!("0.01 / 0.9 = {:.3}", 10.0_f64.powf(log_bf)),
                    intuition: format!(
                        "Evidence of journal inconsistency: {} gaps detected",
                        state.journal_gaps
                    ),
                }],
            }
        }
    }

    fn check_quiescence(&self, state: &AtpTransferState) -> EvidenceEntry {
        let has_pending = state.pending_operations > 0;

        if !has_pending {
            EvidenceEntry {
                invariant: "quiescence".to_string(),
                passed: true,
                bayes_factor: BayesFactor {
                    log10_bf: -1.0,
                    hypothesis: "non-quiescence".to_string(),
                    strength: EvidenceStrength::from_log10_bf(-1.0),
                },
                log_likelihoods: LogLikelihoodContributions {
                    structural: -0.5,
                    detection: -0.5,
                    total: -1.0,
                },
                evidence_lines: vec![EvidenceLine {
                    equation: "P(no_pending | quiescent) / P(no_pending | not_quiescent)"
                        .to_string(),
                    substitution: "0.9 / 0.1 = 9".to_string(),
                    intuition: "Positive evidence of quiescence".to_string(),
                }],
            }
        } else {
            let log_bf = (state.pending_operations as f64 / 10.0).log10() + 0.5;
            EvidenceEntry {
                invariant: "quiescence".to_string(),
                passed: false,
                bayes_factor: BayesFactor {
                    log10_bf: log_bf,
                    hypothesis: "non-quiescence".to_string(),
                    strength: EvidenceStrength::from_log10_bf(log_bf),
                },
                log_likelihoods: LogLikelihoodContributions {
                    structural: log_bf / 2.0,
                    detection: log_bf / 2.0,
                    total: log_bf,
                },
                evidence_lines: vec![EvidenceLine {
                    equation: "P(pending | quiescent) / P(pending | not_quiescent)".to_string(),
                    substitution: format!("0.05 / 0.8 = {:.3}", 10.0_f64.powf(log_bf)),
                    intuition: format!(
                        "Evidence against quiescence: {} operations pending",
                        state.pending_operations
                    ),
                }],
            }
        }
    }

    fn check_final_exposure(&self, state: &AtpTransferState) -> EvidenceEntry {
        let exposures = state.unverified_final_exposures;

        if exposures == 0 {
            EvidenceEntry {
                invariant: "final_exposure".to_string(),
                passed: true,
                bayes_factor: BayesFactor {
                    log10_bf: -1.4,
                    hypothesis: "unverified final exposure".to_string(),
                    strength: EvidenceStrength::from_log10_bf(-1.4),
                },
                log_likelihoods: LogLikelihoodContributions {
                    structural: -0.7,
                    detection: -0.7,
                    total: -1.4,
                },
                evidence_lines: vec![EvidenceLine {
                    equation:
                        "P(no_exposure | verified_publish) / P(no_exposure | premature_publish)"
                            .to_string(),
                    substitution: "0.97 / 0.03 = 32.3".to_string(),
                    intuition: "Strong evidence that final exposure waited for verification"
                        .to_string(),
                }],
            }
        } else {
            let log_bf = (exposures as f64).log10() + 1.7;
            EvidenceEntry {
                invariant: "final_exposure".to_string(),
                passed: false,
                bayes_factor: BayesFactor {
                    log10_bf: log_bf,
                    hypothesis: "unverified final exposure".to_string(),
                    strength: EvidenceStrength::from_log10_bf(log_bf),
                },
                log_likelihoods: LogLikelihoodContributions {
                    structural: log_bf / 2.0,
                    detection: log_bf / 2.0,
                    total: log_bf,
                },
                evidence_lines: vec![EvidenceLine {
                    equation: "P(exposure | verified_publish) / P(exposure | premature_publish)"
                        .to_string(),
                    substitution: format!("0.005 / 0.9 = {:.3}", 10.0_f64.powf(log_bf)),
                    intuition: format!(
                        "Strong evidence of unverified final exposure: {exposures} exposure(s)"
                    ),
                }],
            }
        }
    }

    fn check_cancellation_drain(&self, state: &AtpTransferState) -> EvidenceEntry {
        let pending_drains = state.pending_cancellation_drains;

        if pending_drains == 0 {
            EvidenceEntry {
                invariant: "cancellation_drain".to_string(),
                passed: true,
                bayes_factor: BayesFactor {
                    log10_bf: -1.3,
                    hypothesis: "undrained cancellation".to_string(),
                    strength: EvidenceStrength::from_log10_bf(-1.3),
                },
                log_likelihoods: LogLikelihoodContributions {
                    structural: -0.6,
                    detection: -0.7,
                    total: -1.3,
                },
                evidence_lines: vec![EvidenceLine {
                    equation:
                        "P(no_pending_drains | cancel_correct) / P(no_pending_drains | cancel_leak)"
                            .to_string(),
                    substitution: "0.96 / 0.04 = 24".to_string(),
                    intuition: "Strong evidence that cancellation drained before replay close"
                        .to_string(),
                }],
            }
        } else {
            let log_bf = (pending_drains as f64).log10() + 1.5;
            EvidenceEntry {
                invariant: "cancellation_drain".to_string(),
                passed: false,
                bayes_factor: BayesFactor {
                    log10_bf: log_bf,
                    hypothesis: "undrained cancellation".to_string(),
                    strength: EvidenceStrength::from_log10_bf(log_bf),
                },
                log_likelihoods: LogLikelihoodContributions {
                    structural: log_bf / 2.0,
                    detection: log_bf / 2.0,
                    total: log_bf,
                },
                evidence_lines: vec![EvidenceLine {
                    equation:
                        "P(pending_drains | cancel_correct) / P(pending_drains | cancel_leak)"
                            .to_string(),
                    substitution: format!("0.02 / 0.85 = {:.3}", 10.0_f64.powf(log_bf)),
                    intuition: format!(
                        "Strong evidence of undrained cancellation: {pending_drains} pending drain(s)"
                    ),
                }],
            }
        }
    }

    fn check_obligation_leak(&self, state: &AtpTransferState) -> EvidenceEntry {
        let has_leaks = state.leaked_obligations > 0;

        if !has_leaks {
            EvidenceEntry {
                invariant: "obligation_leak".to_string(),
                passed: true,
                bayes_factor: BayesFactor {
                    log10_bf: -1.5,
                    hypothesis: "obligation leak".to_string(),
                    strength: EvidenceStrength::from_log10_bf(-1.5),
                },
                log_likelihoods: LogLikelihoodContributions {
                    structural: -0.7,
                    detection: -0.8,
                    total: -1.5,
                },
                evidence_lines: vec![EvidenceLine {
                    equation: "P(no_leaks | correct_cleanup) / P(no_leaks | obligation_leak)"
                        .to_string(),
                    substitution: "0.95 / 0.05 = 19".to_string(),
                    intuition: "Strong evidence of correct obligation cleanup".to_string(),
                }],
            }
        } else {
            let log_bf = (state.leaked_obligations as f64).log10() + 1.5;
            EvidenceEntry {
                invariant: "obligation_leak".to_string(),
                passed: false,
                bayes_factor: BayesFactor {
                    log10_bf: log_bf,
                    hypothesis: "obligation leak".to_string(),
                    strength: EvidenceStrength::from_log10_bf(log_bf),
                },
                log_likelihoods: LogLikelihoodContributions {
                    structural: log_bf / 2.0,
                    detection: log_bf / 2.0,
                    total: log_bf,
                },
                evidence_lines: vec![EvidenceLine {
                    equation: "P(leaks | correct_cleanup) / P(leaks | obligation_leak)".to_string(),
                    substitution: format!("0.01 / 0.95 = {:.3}", 10.0_f64.powf(log_bf)),
                    intuition: format!(
                        "Strong evidence of obligation leak: {} leaked",
                        state.leaked_obligations
                    ),
                }],
            }
        }
    }

    fn check_path_consistency(&self, state: &AtpTransferState) -> EvidenceEntry {
        if state.path_outcomes_consistent {
            EvidenceEntry {
                invariant: "path_consistency".to_string(),
                passed: true,
                bayes_factor: BayesFactor {
                    log10_bf: -1.0,
                    hypothesis: "path inconsistency".to_string(),
                    strength: EvidenceStrength::from_log10_bf(-1.0),
                },
                log_likelihoods: LogLikelihoodContributions {
                    structural: -0.5,
                    detection: -0.5,
                    total: -1.0,
                },
                evidence_lines: vec![EvidenceLine {
                    equation: "P(consistent | correct_paths) / P(consistent | inconsistent_paths)"
                        .to_string(),
                    substitution: "0.9 / 0.1 = 9".to_string(),
                    intuition: "Positive evidence of path consistency".to_string(),
                }],
            }
        } else {
            EvidenceEntry {
                invariant: "path_consistency".to_string(),
                passed: false,
                bayes_factor: BayesFactor {
                    log10_bf: 2.0,
                    hypothesis: "path inconsistency".to_string(),
                    strength: EvidenceStrength::Strong,
                },
                log_likelihoods: LogLikelihoodContributions {
                    structural: 1.0,
                    detection: 1.0,
                    total: 2.0,
                },
                evidence_lines: vec![EvidenceLine {
                    equation:
                        "P(inconsistent | correct_paths) / P(inconsistent | inconsistent_paths)"
                            .to_string(),
                    substitution: "0.05 / 0.8 = 100".to_string(),
                    intuition: "Strong evidence of path inconsistency".to_string(),
                }],
            }
        }
    }

    fn check_proof_bundle_validity(&self, state: &AtpTransferState) -> EvidenceEntry {
        if state.proof_bundle_valid {
            EvidenceEntry {
                invariant: "proof_bundle_validity".to_string(),
                passed: true,
                bayes_factor: BayesFactor {
                    log10_bf: -1.2,
                    hypothesis: "invalid proof bundle".to_string(),
                    strength: EvidenceStrength::from_log10_bf(-1.2),
                },
                log_likelihoods: LogLikelihoodContributions {
                    structural: -0.6,
                    detection: -0.6,
                    total: -1.2,
                },
                evidence_lines: vec![EvidenceLine {
                    equation: "P(valid_bundle | correct_proof) / P(valid_bundle | invalid_proof)"
                        .to_string(),
                    substitution: "0.92 / 0.08 = 11.5".to_string(),
                    intuition: "Strong evidence of valid proof bundle".to_string(),
                }],
            }
        } else {
            EvidenceEntry {
                invariant: "proof_bundle_validity".to_string(),
                passed: false,
                bayes_factor: BayesFactor {
                    log10_bf: 1.8,
                    hypothesis: "invalid proof bundle".to_string(),
                    strength: EvidenceStrength::Strong,
                },
                log_likelihoods: LogLikelihoodContributions {
                    structural: 0.9,
                    detection: 0.9,
                    total: 1.8,
                },
                evidence_lines: vec![EvidenceLine {
                    equation:
                        "P(invalid_bundle | correct_proof) / P(invalid_bundle | invalid_proof)"
                            .to_string(),
                    substitution: "0.02 / 0.9 = 63".to_string(),
                    intuition: "Strong evidence of invalid proof bundle".to_string(),
                }],
            }
        }
    }
}

/// Configuration for which ATP oracle checks to enable.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct AtpOracleChecks {
    pub manifest_integrity: bool,
    pub journal_consistency: bool,
    pub quiescence: bool,
    pub final_exposure: bool,
    pub cancellation_drain: bool,
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
            final_exposure: true,
            cancellation_drain: true,
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
            final_exposure: false,
            cancellation_drain: false,
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

    // Final exposure
    pub unverified_final_exposures: u32,

    // Cancellation drain
    pub pending_cancellation_drains: u32,

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
            unverified_final_exposures: 0,
            pending_cancellation_drains: 0,
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
            unverified_final_exposures: 0,
            pending_cancellation_drains: 0,
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
        self.evidence_ledger
            .evidence_summary()
            .has_strong_violations()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lab::oracle::evidence::EvidenceStrength;

    #[test]
    fn clean_transfer_passes_all_enabled_oracles() {
        let result = AtpTransferOracle::new("clean_transfer").validate(&AtpTransferState::clean());
        let summary = result.evidence_ledger.evidence_summary();

        assert!(
            result.passed,
            "clean transfer should not be classified as a violation"
        );
        assert_eq!(result.stats.events_recorded, 8);
        assert_eq!(result.stats.entities_tracked, 0);
        assert_eq!(summary.total, 8);
        assert_eq!(summary.against, 8);
        assert_eq!(summary.violation_count(), 0);
        assert!(!result.has_strong_violations());
    }

    #[test]
    fn clean_basic_oracle_records_only_basic_checks_as_passing() {
        let result = AtpTransferOracle::basic().validate(&AtpTransferState::clean());
        let summary = result.evidence_ledger.evidence_summary();

        assert!(result.passed);
        assert_eq!(result.stats.events_recorded, 3);
        assert_eq!(summary.total, 3);
        assert_eq!(summary.against, 3);
        assert_eq!(summary.violation_count(), 0);
    }

    #[test]
    fn corrupted_transfer_fails_with_violation_strength() {
        let mut state = AtpTransferState::clean();
        state.manifest_hash = "tampered".to_string();
        state.journal_gaps = 2;
        state.unverified_final_exposures = 1;
        state.pending_cancellation_drains = 2;
        state.leaked_obligations = 1;
        state.proof_bundle_valid = false;

        let result = AtpTransferOracle::new("corrupted_transfer").validate(&state);
        let summary = result.evidence_ledger.evidence_summary();

        assert!(!result.passed);
        assert_eq!(result.stats.events_recorded, 8);
        assert_eq!(result.stats.entities_tracked, 6);
        assert_eq!(summary.against, 2);
        assert_eq!(summary.violation_count(), 6);
        assert!(result.has_strong_violations());
    }

    #[test]
    fn final_exposure_and_cancellation_drain_have_dedicated_evidence_entries() {
        let mut state = AtpTransferState::clean();
        state.unverified_final_exposures = 2;
        state.pending_cancellation_drains = 3;

        let result = AtpTransferOracle::new("publish_and_cancel").validate(&state);

        assert!(!result.passed);
        assert_eq!(result.stats.events_recorded, 8);
        assert_eq!(result.stats.entities_tracked, 2);

        let final_exposure = result
            .evidence_ledger
            .entries
            .iter()
            .find(|entry| entry.oracle_name == "final_exposure")
            .expect("final exposure entry is recorded");
        assert!(!final_exposure.evidence.passed);
        assert_eq!(final_exposure.evidence.invariant, "final_exposure");
        assert!(
            final_exposure.evidence.evidence_lines[0]
                .intuition
                .contains("2 exposure(s)")
        );

        let cancellation_drain = result
            .evidence_ledger
            .entries
            .iter()
            .find(|entry| entry.oracle_name == "cancellation_drain")
            .expect("cancellation drain entry is recorded");
        assert!(!cancellation_drain.evidence.passed);
        assert_eq!(cancellation_drain.evidence.invariant, "cancellation_drain");
        assert!(
            cancellation_drain.evidence.evidence_lines[0]
                .intuition
                .contains("3 pending drain(s)")
        );
    }

    #[test]
    fn negative_log_bayes_factor_maps_to_against_violation() {
        for entry in &AtpTransferOracle::new("polarity")
            .validate(&AtpTransferState::clean())
            .evidence_ledger
            .entries
        {
            assert_eq!(
                entry.evidence.bayes_factor.strength,
                EvidenceStrength::Against,
                "{} should provide evidence against violation",
                entry.oracle_name
            );
        }
    }
}
