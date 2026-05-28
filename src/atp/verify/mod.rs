//! ATP proof bundle verification and validation.
//!
//! This module provides offline verification capabilities for ATP proof bundles,
//! enabling independent validation of transfer completeness and integrity without
//! access to the original transfer infrastructure.

use crate::atp::proof::replay::ReplayableEventKind;
use crate::atp::proof::{AtpProofBundle, ProofStrength};
use crate::atp::verifier::{AtpVerifier, VerificationError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

/// Offline verification result for ATP proof bundles.
#[derive(Debug, Clone, PartialEq)]
pub struct AtpVerificationResult {
    /// Overall verification status.
    pub status: VerificationStatus,
    /// Verification timestamp (microseconds since UNIX epoch).
    pub verified_at_micros: u64,
    /// Verification report details.
    pub report: VerificationReport,
    /// Individual verification checks performed.
    pub checks: Vec<VerificationCheck>,
    /// Warnings encountered during verification.
    pub warnings: Vec<VerificationWarning>,
    /// Errors encountered during verification.
    pub errors: Vec<VerificationError>,
}

/// Overall verification status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationStatus {
    /// Verification passed completely.
    Passed,
    /// Verification passed with warnings.
    PassedWithWarnings,
    /// Verification failed.
    Failed,
    /// Verification could not be completed.
    Inconclusive,
}

impl VerificationStatus {
    /// Whether this status indicates successful verification.
    #[must_use]
    pub const fn is_success(self) -> bool {
        matches!(self, Self::Passed | Self::PassedWithWarnings)
    }

    /// Whether this status indicates failure.
    #[must_use]
    pub const fn is_failure(self) -> bool {
        matches!(self, Self::Failed)
    }
}

/// Detailed verification report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerificationReport {
    /// Transfer summary information.
    pub transfer_summary: TransferSummary,
    /// Content integrity assessment.
    pub content_integrity: ContentIntegrityReport,
    /// Proof strength assessment.
    pub proof_strength: ProofStrengthReport,
    /// Policy compliance assessment.
    pub policy_compliance: PolicyComplianceReport,
    /// Replay capability assessment.
    pub replay_capability: ReplayCapabilityReport,
}

/// Transfer operation summary from proof bundle.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TransferSummary {
    /// Transfer session identifier.
    pub transfer_id: String,
    /// Source peer identifier.
    pub source_peer: String,
    /// Destination peer identifier.
    pub destination_peer: String,
    /// Transfer completion ratio (0.0 to 1.0).
    pub completion_ratio: f64,
    /// Total bytes transferred.
    pub bytes_transferred: u64,
    /// Number of objects transferred.
    pub objects_transferred: usize,
    /// Transfer duration (if available).
    pub duration_millis: Option<u64>,
    /// Primary transport protocol used.
    pub primary_protocol: String,
}

/// Content integrity verification report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContentIntegrityReport {
    /// Manifest verification status.
    pub manifest_verified: bool,
    /// Chunk verification coverage (0.0 to 1.0).
    pub chunk_verification_coverage: f64,
    /// Number of verification stages passed.
    pub verification_stages_passed: usize,
    /// Total verification stages expected.
    pub verification_stages_total: usize,
    /// Repair operation integrity.
    pub repair_integrity: Option<RepairIntegrityReport>,
}

/// Repair operation integrity assessment.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RepairIntegrityReport {
    /// RaptorQ decode operations verified.
    pub raptorq_verified: bool,
    /// Repair group consistency verified.
    pub repair_groups_verified: bool,
    /// Overhead efficiency assessment.
    pub overhead_efficiency: f64,
    /// Repair activation justification verified.
    pub repair_justification_verified: bool,
}

/// Proof strength verification report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProofStrengthReport {
    /// Calculated proof strength level.
    pub calculated_strength: ProofStrength,
    /// Required proof strength level.
    pub required_strength: ProofStrength,
    /// Whether strength requirements are met.
    pub requirements_met: bool,
    /// Available evidence types.
    pub evidence_types: Vec<String>,
    /// Missing evidence types (if any).
    pub missing_evidence: Vec<String>,
}

/// Policy compliance verification report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyComplianceReport {
    /// Whether all policy requirements are satisfied.
    pub compliant: bool,
    /// Individual policy check results.
    pub policy_checks: BTreeMap<String, PolicyCheckResult>,
    /// Violated policies (if any).
    pub violations: Vec<PolicyViolation>,
}

/// Individual policy check result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyCheckResult {
    /// Policy name or identifier.
    pub policy_name: String,
    /// Check status.
    pub status: VerificationStatus,
    /// Check description.
    pub description: String,
    /// Additional check details.
    pub details: BTreeMap<String, String>,
}

/// Policy violation description.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyViolation {
    /// Violated policy name.
    pub policy_name: String,
    /// Violation severity.
    pub severity: ViolationSeverity,
    /// Violation description.
    pub description: String,
    /// Remediation suggestion.
    pub remediation: Option<String>,
}

/// Policy violation severity levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ViolationSeverity {
    /// Informational violation.
    Info,
    /// Warning-level violation.
    Warning,
    /// Error-level violation.
    Error,
    /// Critical violation.
    Critical,
}

/// Replay capability assessment.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReplayCapabilityReport {
    /// Whether replay is supported.
    pub replay_supported: bool,
    /// Number of replay pointers available.
    pub replay_pointers_count: usize,
    /// Event coverage assessment.
    pub event_coverage: f64,
    /// Missing replay data (if any).
    pub missing_replay_data: Vec<String>,
}

/// Individual verification check performed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerificationCheck {
    /// Check name or identifier.
    pub check_name: String,
    /// Check category.
    pub category: VerificationCategory,
    /// Check result status.
    pub status: VerificationStatus,
    /// Check description.
    pub description: String,
    /// Check execution time (microseconds).
    pub duration_micros: u64,
    /// Additional check metadata.
    pub metadata: BTreeMap<String, String>,
}

/// Categories of verification checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationCategory {
    /// Bundle format and structure checks.
    BundleFormat,
    /// Content integrity checks.
    ContentIntegrity,
    /// Cryptographic verification checks.
    Cryptographic,
    /// Policy compliance checks.
    PolicyCompliance,
    /// Semantic consistency checks.
    SemanticConsistency,
    /// Replay capability checks.
    ReplayCapability,
}

/// Verification warning (non-fatal issues).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerificationWarning {
    /// Warning code or identifier.
    pub code: String,
    /// Warning message.
    pub message: String,
    /// Warning category.
    pub category: VerificationCategory,
    /// Additional warning context.
    pub context: BTreeMap<String, String>,
}

/// ATP proof bundle verifier.
#[derive(Debug, Clone)]
pub struct AtpBundleVerifier {
    /// Underlying ATP verifier for content checks.
    pub verifier: AtpVerifier,
    /// Verification policy configuration.
    pub policy: VerificationPolicy,
}

/// Verification policy configuration.
#[derive(Debug, Clone, PartialEq)]
pub struct VerificationPolicy {
    /// Whether to require all verification stages.
    pub require_all_stages: bool,
    /// Minimum chunk verification coverage required.
    pub min_chunk_coverage: f64,
    /// Whether to strictly validate replay pointers.
    pub strict_replay_validation: bool,
    /// Custom policy requirements.
    pub custom_policies: BTreeMap<String, String>,
}

impl Default for VerificationPolicy {
    fn default() -> Self {
        Self {
            require_all_stages: true,
            min_chunk_coverage: 0.95, // Require 95% chunk coverage
            strict_replay_validation: false,
            custom_policies: BTreeMap::new(),
        }
    }
}

impl AtpBundleVerifier {
    /// Create a new bundle verifier with default policy.
    #[must_use]
    pub fn new() -> Self {
        Self {
            verifier: AtpVerifier::default(),
            policy: VerificationPolicy::default(),
        }
    }

    /// Create a verifier with custom policy.
    #[must_use]
    pub fn with_policy(policy: VerificationPolicy) -> Self {
        Self {
            verifier: AtpVerifier::default(),
            policy,
        }
    }

    /// Verify an ATP proof bundle offline.
    pub fn verify_bundle(&self, bundle: &AtpProofBundle) -> AtpVerificationResult {
        let start_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;

        let mut checks = Vec::new();
        let mut warnings = Vec::new();
        let mut errors = Vec::new();

        // 1. Bundle format validation
        match self.verify_bundle_format(bundle) {
            Ok(check) => checks.push(check),
            Err(err) => {
                errors.push(err);
                checks.push(VerificationCheck {
                    check_name: "bundle_format".to_string(),
                    category: VerificationCategory::BundleFormat,
                    status: VerificationStatus::Failed,
                    description: "Bundle format validation failed".to_string(),
                    duration_micros: 0,
                    metadata: BTreeMap::new(),
                });
            }
        }

        // 2. Content integrity validation
        let content_integrity = self.verify_content_integrity(bundle, &mut checks, &mut warnings);

        // 3. Proof strength validation
        let proof_strength = self.verify_proof_strength(bundle, &mut checks);

        // 4. Policy compliance validation
        let policy_compliance = self.verify_policy_compliance(bundle, &mut checks, &mut warnings);

        // 5. Replay capability validation
        let replay_capability = self.verify_replay_capability(bundle, &mut checks, &mut warnings);

        // Generate transfer summary
        let transfer_summary = self.generate_transfer_summary(bundle);

        // Determine overall status
        let status = if !errors.is_empty() || checks.iter().any(|c| c.status.is_failure()) {
            VerificationStatus::Failed
        } else if !warnings.is_empty()
            || checks
                .iter()
                .any(|c| matches!(c.status, VerificationStatus::PassedWithWarnings))
        {
            VerificationStatus::PassedWithWarnings
        } else {
            VerificationStatus::Passed
        };

        let report = VerificationReport {
            transfer_summary,
            content_integrity,
            proof_strength,
            policy_compliance,
            replay_capability,
        };

        AtpVerificationResult {
            status,
            verified_at_micros: start_time,
            report,
            checks,
            warnings,
            errors,
        }
    }

    fn verify_bundle_format(
        &self,
        bundle: &AtpProofBundle,
    ) -> Result<VerificationCheck, VerificationError> {
        let start = SystemTime::now();

        // Validate the bundle itself
        bundle
            .validate()
            .map_err(|e| VerificationError::InvalidManifest {
                reason: format!("Bundle validation failed: {e}"),
            })?;

        let duration = start.elapsed().unwrap_or_default().as_micros() as u64;

        Ok(VerificationCheck {
            check_name: "bundle_format".to_string(),
            category: VerificationCategory::BundleFormat,
            status: VerificationStatus::Passed,
            description: "Bundle format and structure validation".to_string(),
            duration_micros: duration,
            metadata: BTreeMap::from([
                ("version".to_string(), bundle.version.0.to_string()),
                ("transfer_id".to_string(), bundle.transfer_id.clone()),
            ]),
        })
    }

    fn verify_content_integrity(
        &self,
        bundle: &AtpProofBundle,
        checks: &mut Vec<VerificationCheck>,
        warnings: &mut Vec<VerificationWarning>,
    ) -> ContentIntegrityReport {
        // Verify manifest if commit record is present
        let manifest_verified = if let Some(ref commit) = bundle.commit_record {
            match self.verifier.verify_commit(commit) {
                Ok(_) => {
                    checks.push(VerificationCheck {
                        check_name: "manifest_commit".to_string(),
                        category: VerificationCategory::ContentIntegrity,
                        status: VerificationStatus::Passed,
                        description: "Manifest commit verification".to_string(),
                        duration_micros: 0,
                        metadata: BTreeMap::new(),
                    });
                    true
                }
                Err(_) => {
                    checks.push(VerificationCheck {
                        check_name: "manifest_commit".to_string(),
                        category: VerificationCategory::ContentIntegrity,
                        status: VerificationStatus::Failed,
                        description: "Manifest commit verification failed".to_string(),
                        duration_micros: 0,
                        metadata: BTreeMap::new(),
                    });
                    false
                }
            }
        } else {
            warnings.push(VerificationWarning {
                code: "missing_commit_record".to_string(),
                message: "No commit record available for verification".to_string(),
                category: VerificationCategory::ContentIntegrity,
                context: BTreeMap::new(),
            });
            false
        };

        // Calculate chunk verification coverage
        let chunk_coverage = bundle.chunk_bitmap.completion_ratio();
        if chunk_coverage < self.policy.min_chunk_coverage {
            warnings.push(VerificationWarning {
                code: "low_chunk_coverage".to_string(),
                message: format!(
                    "Chunk coverage {:.2}% below required {:.2}%",
                    chunk_coverage * 100.0,
                    self.policy.min_chunk_coverage * 100.0
                ),
                category: VerificationCategory::ContentIntegrity,
                context: BTreeMap::new(),
            });
        }

        // Count verification stages
        let verification_stages_passed = bundle.verification_evidence.len();
        let verification_stages_total = if self.policy.require_all_stages { 8 } else { 2 }; // Minimum chunk + manifest

        // Verify repair integrity if present
        let repair_integrity =
            if bundle.raptorq_metadata.is_some() || !bundle.repair_groups.is_empty() {
                Some(self.verify_repair_integrity(bundle, checks))
            } else {
                None
            };

        ContentIntegrityReport {
            manifest_verified,
            chunk_verification_coverage: chunk_coverage,
            verification_stages_passed,
            verification_stages_total,
            repair_integrity,
        }
    }

    fn verify_repair_integrity(
        &self,
        bundle: &AtpProofBundle,
        checks: &mut Vec<VerificationCheck>,
    ) -> RepairIntegrityReport {
        let raptorq_verified = if let Some(ref metadata) = bundle.raptorq_metadata {
            // Validate RaptorQ metadata consistency
            let valid = metadata.decode_success_rate >= 0.0
                && metadata.decode_success_rate <= 1.0
                && metadata.average_overhead_ratio >= 0.0;

            checks.push(VerificationCheck {
                check_name: "raptorq_metadata".to_string(),
                category: VerificationCategory::ContentIntegrity,
                status: if valid {
                    VerificationStatus::Passed
                } else {
                    VerificationStatus::Failed
                },
                description: "RaptorQ metadata validation".to_string(),
                duration_micros: 0,
                metadata: BTreeMap::from([
                    (
                        "success_rate".to_string(),
                        metadata.decode_success_rate.to_string(),
                    ),
                    (
                        "overhead_ratio".to_string(),
                        metadata.average_overhead_ratio.to_string(),
                    ),
                ]),
            });

            valid
        } else {
            false
        };

        let repair_groups_verified = !bundle.repair_groups.is_empty()
            && bundle
                .repair_groups
                .iter()
                .all(|group| !group.covered_objects.is_empty() && group.redundancy_factor >= 1.0);

        if !bundle.repair_groups.is_empty() {
            checks.push(VerificationCheck {
                check_name: "repair_groups".to_string(),
                category: VerificationCategory::ContentIntegrity,
                status: if repair_groups_verified {
                    VerificationStatus::Passed
                } else {
                    VerificationStatus::Failed
                },
                description: "Repair groups validation".to_string(),
                duration_micros: 0,
                metadata: BTreeMap::from([(
                    "group_count".to_string(),
                    bundle.repair_groups.len().to_string(),
                )]),
            });
        }

        let overhead_efficiency = bundle
            .raptorq_metadata
            .as_ref()
            .map_or(1.0, |m| m.average_overhead_ratio);

        let repair_justification_verified = bundle.repair_groups.iter().any(|g| g.repair_activated)
            == bundle
                .raptorq_metadata
                .as_ref()
                .is_some_and(|m| m.repair_symbols_used > 0);

        RepairIntegrityReport {
            raptorq_verified,
            repair_groups_verified,
            overhead_efficiency,
            repair_justification_verified,
        }
    }

    fn verify_proof_strength(
        &self,
        bundle: &AtpProofBundle,
        checks: &mut Vec<VerificationCheck>,
    ) -> ProofStrengthReport {
        let calculated_strength = bundle.calculate_proof_strength();
        let required_strength = bundle.metadata.required_proof_strength;
        let requirements_met = calculated_strength >= required_strength;

        let mut evidence_types = Vec::new();
        let mut missing_evidence = Vec::new();

        // Check available evidence
        if !bundle.verification_evidence.is_empty() {
            evidence_types.push("verification_stages".to_string());
        }

        if bundle.raptorq_metadata.is_some() {
            evidence_types.push("raptorq_decode".to_string());
        }

        if !bundle.peer_identity.key_fingerprints.is_empty() {
            evidence_types.push("peer_authentication".to_string());
        }

        if bundle.extensions.contains_key("cryptographic_signatures") {
            evidence_types.push("cryptographic_signatures".to_string());
        }

        // Determine missing evidence based on required strength
        match required_strength {
            ProofStrength::Enhanced => {
                if bundle.raptorq_metadata.is_none() && bundle.repair_groups.is_empty() {
                    missing_evidence.push("repair_evidence".to_string());
                }
                if bundle.peer_identity.key_fingerprints.is_empty() {
                    missing_evidence.push("peer_authentication".to_string());
                }
            }
            ProofStrength::Cryptographic
                if !bundle.extensions.contains_key("cryptographic_signatures") =>
            {
                missing_evidence.push("cryptographic_signatures".to_string());
            }
            ProofStrength::Cryptographic | ProofStrength::Basic => {}
        }

        checks.push(VerificationCheck {
            check_name: "proof_strength".to_string(),
            category: VerificationCategory::PolicyCompliance,
            status: if requirements_met {
                VerificationStatus::Passed
            } else {
                VerificationStatus::Failed
            },
            description: "Proof strength validation".to_string(),
            duration_micros: 0,
            metadata: BTreeMap::from([
                ("calculated".to_string(), format!("{calculated_strength:?}")),
                ("required".to_string(), format!("{required_strength:?}")),
                ("met".to_string(), requirements_met.to_string()),
            ]),
        });

        ProofStrengthReport {
            calculated_strength,
            required_strength,
            requirements_met,
            evidence_types,
            missing_evidence,
        }
    }

    fn verify_policy_compliance(
        &self,
        bundle: &AtpProofBundle,
        checks: &mut Vec<VerificationCheck>,
        warnings: &mut Vec<VerificationWarning>,
    ) -> PolicyComplianceReport {
        let mut policy_checks = BTreeMap::new();
        let mut violations = Vec::new();

        // Check repair evidence policy
        if bundle.metadata.require_repair_evidence {
            let has_repair = bundle.raptorq_metadata.is_some() || !bundle.repair_groups.is_empty();
            let status = if has_repair {
                VerificationStatus::Passed
            } else {
                VerificationStatus::Failed
            };

            if !has_repair {
                violations.push(PolicyViolation {
                    policy_name: "repair_evidence_required".to_string(),
                    severity: ViolationSeverity::Error,
                    description: "Policy requires repair evidence but none found".to_string(),
                    remediation: Some(
                        "Ensure RaptorQ metadata or repair groups are included".to_string(),
                    ),
                });
            }

            policy_checks.insert(
                "repair_evidence".to_string(),
                PolicyCheckResult {
                    policy_name: "repair_evidence_required".to_string(),
                    status,
                    description: "Verify repair evidence requirement".to_string(),
                    details: BTreeMap::from([("required".to_string(), "true".to_string())]),
                },
            );
        }

        // Check mailbox evidence policy
        if bundle.metadata.require_mailbox_evidence {
            let has_mailbox = bundle.path_summary.relay_used
                || bundle.extensions.contains_key("mailbox_evidence");
            let status = if has_mailbox {
                VerificationStatus::Passed
            } else {
                VerificationStatus::Failed
            };

            if !has_mailbox {
                violations.push(PolicyViolation {
                    policy_name: "mailbox_evidence_required".to_string(),
                    severity: ViolationSeverity::Warning,
                    description: "Policy requires mailbox evidence but none found".to_string(),
                    remediation: Some(
                        "Include relay usage evidence or mailbox artifacts".to_string(),
                    ),
                });
            }

            policy_checks.insert(
                "mailbox_evidence".to_string(),
                PolicyCheckResult {
                    policy_name: "mailbox_evidence_required".to_string(),
                    status,
                    description: "Verify mailbox evidence requirement".to_string(),
                    details: BTreeMap::from([("required".to_string(), "true".to_string())]),
                },
            );
        }

        let compliant = violations
            .iter()
            .all(|v| v.severity < ViolationSeverity::Error);

        // Add policy compliance warnings
        for violation in &violations {
            if violation.severity == ViolationSeverity::Warning {
                warnings.push(VerificationWarning {
                    code: violation.policy_name.clone(),
                    message: violation.description.clone(),
                    category: VerificationCategory::PolicyCompliance,
                    context: BTreeMap::from([(
                        "severity".to_string(),
                        format!("{:?}", violation.severity),
                    )]),
                });
            }
        }

        checks.push(VerificationCheck {
            check_name: "policy_compliance".to_string(),
            category: VerificationCategory::PolicyCompliance,
            status: if compliant {
                VerificationStatus::Passed
            } else {
                VerificationStatus::Failed
            },
            description: "Policy compliance validation".to_string(),
            duration_micros: 0,
            metadata: BTreeMap::from([
                ("violations".to_string(), violations.len().to_string()),
                ("compliant".to_string(), compliant.to_string()),
            ]),
        });

        PolicyComplianceReport {
            compliant,
            policy_checks,
            violations,
        }
    }

    fn verify_replay_capability(
        &self,
        bundle: &AtpProofBundle,
        checks: &mut Vec<VerificationCheck>,
        warnings: &mut Vec<VerificationWarning>,
    ) -> ReplayCapabilityReport {
        let replay_pointers_count = bundle.replay_pointers.len();
        let replay_supported = replay_pointers_count > 0;

        let mut missing_replay_data = Vec::new();

        // Check for essential replay components
        if !bundle.journal.is_complete {
            missing_replay_data.push("incomplete_journal".to_string());
        }

        if bundle.replay_pointers.is_empty() {
            missing_replay_data.push("replay_pointers".to_string());
        }

        let (event_coverage, invalid_pointer_count) = self.replay_event_coverage(bundle);
        if invalid_pointer_count > 0 {
            missing_replay_data.push("invalid_replay_pointer".to_string());
            warnings.push(VerificationWarning {
                code: "invalid_replay_pointer".to_string(),
                message: format!("{invalid_pointer_count} replay pointer(s) failed validation"),
                category: VerificationCategory::ReplayCapability,
                context: BTreeMap::new(),
            });
        }

        if !replay_supported {
            warnings.push(VerificationWarning {
                code: "no_replay_capability".to_string(),
                message: "No replay pointers available for deterministic reconstruction"
                    .to_string(),
                category: VerificationCategory::ReplayCapability,
                context: BTreeMap::new(),
            });
        }

        checks.push(VerificationCheck {
            check_name: "replay_capability".to_string(),
            category: VerificationCategory::ReplayCapability,
            status: if replay_supported {
                VerificationStatus::Passed
            } else {
                VerificationStatus::PassedWithWarnings
            },
            description: "Replay capability assessment".to_string(),
            duration_micros: 0,
            metadata: BTreeMap::from([
                (
                    "pointers_count".to_string(),
                    replay_pointers_count.to_string(),
                ),
                (
                    "event_coverage".to_string(),
                    format!("{:.2}", event_coverage),
                ),
            ]),
        });

        ReplayCapabilityReport {
            replay_supported,
            replay_pointers_count,
            event_coverage,
            missing_replay_data,
        }
    }

    fn replay_event_coverage(&self, bundle: &AtpProofBundle) -> (f64, usize) {
        use std::collections::HashSet;

        if bundle.replay_pointers.is_empty() {
            return (0.0, 0);
        }

        let required = [
            ReplayableEventKind::SessionStart,
            ReplayableEventKind::ChunkTransfer,
            ReplayableEventKind::VerificationStage,
            ReplayableEventKind::SessionEnd,
        ];
        let all_kinds = [
            ReplayableEventKind::SessionStart,
            ReplayableEventKind::PeerAuth,
            ReplayableEventKind::PathSetup,
            ReplayableEventKind::ChunkTransfer,
            ReplayableEventKind::RepairSymbol,
            ReplayableEventKind::RaptorQDecode,
            ReplayableEventKind::VerificationStage,
            ReplayableEventKind::JournalWrite,
            ReplayableEventKind::SessionEnd,
            ReplayableEventKind::Error,
        ];

        let mut covered = HashSet::new();
        let mut total_events = 0u64;
        let mut invalid_pointer_count = 0usize;
        for pointer in bundle.replay_pointers.values() {
            if pointer.validate().is_err() {
                invalid_pointer_count += 1;
                continue;
            }
            total_events = total_events.saturating_add(pointer.event_count());
            let pointer_kinds = pointer.event_filter.as_ref().map_or_else(
                || all_kinds.to_vec(),
                |filter| {
                    let mut kinds = if filter.include_kinds.is_empty() {
                        all_kinds.to_vec()
                    } else {
                        filter.include_kinds.clone()
                    };
                    kinds.retain(|kind| !filter.exclude_kinds.contains(kind));
                    kinds
                },
            );
            covered.extend(pointer_kinds);
        }

        if total_events == 0 {
            return (0.0, invalid_pointer_count);
        }

        let critical_covered = required
            .iter()
            .filter(|kind| covered.contains(kind))
            .count() as f64;
        let critical_ratio = critical_covered / required.len() as f64;
        let journal_factor = if bundle.journal.is_complete {
            1.0
        } else {
            0.75
        };
        (critical_ratio * journal_factor, invalid_pointer_count)
    }

    fn generate_transfer_summary(&self, bundle: &AtpProofBundle) -> TransferSummary {
        TransferSummary {
            transfer_id: bundle.transfer_id.clone(),
            source_peer: bundle.peer_identity.source_peer_id.clone(),
            destination_peer: bundle.peer_identity.destination_peer_id.clone(),
            completion_ratio: bundle.chunk_bitmap.completion_ratio(),
            bytes_transferred: bundle.journal.size_bytes, // Approximate
            objects_transferred: bundle.object_roots.len(),
            duration_millis: bundle
                .journal
                .finalized_at_micros
                .and_then(|end| end.checked_sub(bundle.journal.created_at_micros))
                .map(|duration_micros| duration_micros / 1000),
            primary_protocol: bundle.path_summary.primary_protocol.clone(),
        }
    }
}

impl Default for AtpBundleVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for VerificationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Passed => write!(f, "PASSED"),
            Self::PassedWithWarnings => write!(f, "PASSED_WITH_WARNINGS"),
            Self::Failed => write!(f, "FAILED"),
            Self::Inconclusive => write!(f, "INCONCLUSIVE"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atp::object::{ContentId, Object};
    use crate::atp::proof::serde_types::SerializableContentId;
    use crate::atp::proof::{
        AtpProofBundle, AtpProofBundleBuilder, ChunkBitmap, PeerIdentityInfo, ProofStrength,
        TransferJournal, TransferPathSummary,
    };
    use crate::atp::verifier::{VerificationEvidence, VerificationStage};

    fn create_test_bundle() -> AtpProofBundle {
        let manifest_root = crate::atp::manifest::MerkleRoot::new([1; 32]);
        let object_id = Object::file(b"test".to_vec()).id;
        let mut chunk_bitmap = ChunkBitmap::new(10);
        chunk_bitmap.mark_received(0);

        AtpProofBundleBuilder::new("test-transfer")
            .manifest_root(manifest_root)
            .object_roots(vec![object_id])
            .chunk_bitmap(chunk_bitmap)
            .peer_identity(PeerIdentityInfo {
                source_peer_id: "source".to_string(),
                destination_peer_id: "dest".to_string(),
                auth_method: "ed25519".to_string(),
                key_fingerprints: vec!["key1".to_string()],
                authenticated_at_micros: 12345,
                mutual_auth: true,
            })
            .path_summary(TransferPathSummary {
                primary_protocol: "quic".to_string(),
                fallback_protocols: vec![],
                rtt_millis: Some(50.0),
                bandwidth_bps: Some(1_000_000),
                relay_used: false,
                relay_nodes: vec![],
                path_setup_duration_millis: 100,
                path_switches: 0,
            })
            .journal(TransferJournal {
                digest: SerializableContentId::from(&ContentId::from_bytes(b"journal")),
                format_version: 1,
                entry_count: 10,
                size_bytes: 1024,
                is_complete: true,
                created_at_micros: 12345,
                finalized_at_micros: Some(12400),
            })
            .add_verification_evidence(VerificationEvidence {
                stage: VerificationStage::ChunkHash,
                summary: "chunk verified".to_string(),
                digest: Some(ContentId::from_bytes(b"chunk")),
            })
            .add_verification_evidence(VerificationEvidence {
                stage: VerificationStage::Manifest,
                summary: "manifest verified".to_string(),
                digest: Some(ContentId::from_bytes(b"manifest")),
            })
            .build()
            .expect("test bundle should build")
    }

    #[test]
    fn bundle_verifier_basic_verification() {
        let bundle = create_test_bundle();
        let verifier = AtpBundleVerifier::new();

        let result = verifier.verify_bundle(&bundle);

        assert!(result.status.is_success());
        assert!(!result.checks.is_empty());
        assert_eq!(result.report.transfer_summary.transfer_id, "test-transfer");
    }

    #[test]
    fn verification_policy_enforcement() {
        let mut bundle = create_test_bundle();
        bundle.metadata.required_proof_strength = ProofStrength::Enhanced;
        bundle.metadata.require_repair_evidence = true;

        let verifier = AtpBundleVerifier::new();
        let result = verifier.verify_bundle(&bundle);

        // Should fail because we require enhanced proof strength and repair evidence
        // but the test bundle only has basic evidence
        assert!(result.status.is_failure());
        assert!(!result.report.policy_compliance.violations.is_empty());
    }

    #[test]
    fn verification_with_warnings() {
        let mut bundle = create_test_bundle();
        bundle.journal.is_complete = false; // Incomplete journal

        let verifier = AtpBundleVerifier::new();
        let result = verifier.verify_bundle(&bundle);

        assert_eq!(result.status, VerificationStatus::PassedWithWarnings);
        assert!(!result.warnings.is_empty());
    }

    #[test]
    fn verification_status_methods() {
        assert!(VerificationStatus::Passed.is_success());
        assert!(VerificationStatus::PassedWithWarnings.is_success());
        assert!(!VerificationStatus::Failed.is_success());
        assert!(!VerificationStatus::Inconclusive.is_success());

        assert!(VerificationStatus::Failed.is_failure());
        assert!(!VerificationStatus::Passed.is_failure());
    }

    #[test]
    fn custom_verification_policy() {
        let policy = VerificationPolicy {
            require_all_stages: false,
            min_chunk_coverage: 0.5, // Lower requirement
            strict_replay_validation: true,
            custom_policies: BTreeMap::new(),
        };

        let verifier = AtpBundleVerifier::with_policy(policy);
        let bundle = create_test_bundle();

        let result = verifier.verify_bundle(&bundle);
        assert!(result.status.is_success()); // Should pass with relaxed policy
    }
}
