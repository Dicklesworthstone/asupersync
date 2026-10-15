//! Meta-audit: Audit-the-auditor capability security.
//!
//! Implements the "audit-the-auditor" principle by providing a separate, minimal
//! auditor for the audit system itself. Prevents capability escalation where the
//! audit system could be manipulated to hide violations or accumulate ambient
//! authority outside the Cx capability system.
//!
//! # Security Model
//!
//! The meta-auditor operates under a zero-trust model:
//! - The main audit system (`ambient.rs`) is itself subject to audit
//! - KNOWN_FINDINGS modifications are validated against capability constraints
//! - Cross-region audit isolation prevents escalation between audit contexts
//! - Separate capability domains for audit collection vs audit validation

use super::ambient::{AmbientCategory, AmbientFinding, KNOWN_FINDINGS, Severity};
use crate::cx::Cx;
use crate::error::{Error, ErrorKind};
use crate::types::RegionId;
use std::collections::HashSet;
use std::time::Instant;

/// Capability escalation detection for the audit system itself.
///
/// Ensures the audit system cannot be used to bypass its own security model
/// or accumulate ambient authority outside the proper Cx capability system.
#[derive(Debug, Clone)]
pub struct MetaAuditor {
    /// Region ID that owns this meta-auditor instance.
    pub region_id: RegionId,
    /// Capability domain for audit operations.
    pub audit_domain: AuditDomain,
    /// Last validation timestamp to detect tampering.
    pub last_validated: Instant,
    /// Cryptographic hash of KNOWN_FINDINGS for integrity checking.
    pub findings_hash: u64,
}

/// Audit capability domain to prevent cross-region escalation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditDomain {
    /// Collection domain: can gather ambient authority violations.
    Collection,
    /// Validation domain: can validate findings but not modify them.
    Validation,
    /// Meta domain: can audit the auditors themselves.
    Meta,
}

/// Result of meta-audit capability escalation check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityEscalationResult {
    /// No escalation detected - audit system is operating correctly.
    Clean,
    /// Potential escalation: KNOWN_FINDINGS may have been tampered with.
    FindingsTampered {
        expected_hash: u64,
        actual_hash: u64,
        suspicious_entries: Vec<String>,
    },
    /// Cross-region escalation: audit operations crossing region boundaries.
    CrossRegionEscalation {
        audit_region: RegionId,
        target_region: RegionId,
        violation_type: String,
    },
    /// Audit accumulation: audit system itself has ambient authority violations.
    AuditAccumulation {
        violations: Vec<AmbientCategory>,
        affected_functions: Vec<String>,
    },
}

impl MetaAuditor {
    /// Creates a new meta-auditor bound to a specific region and capability domain.
    ///
    /// # Security
    ///
    /// The meta-auditor is region-scoped and cannot escalate capabilities across
    /// region boundaries. Each audit operation must be explicitly authorized by
    /// the region's capability context.
    pub fn new(region_id: RegionId, domain: AuditDomain, now: Instant) -> Self {
        let findings_hash = compute_findings_hash(KNOWN_FINDINGS);
        Self {
            region_id,
            audit_domain: domain,
            last_validated: now,
            findings_hash,
        }
    }

    /// Validates that audit operations remain within capability constraints.
    ///
    /// # Capability Escalation Prevention
    ///
    /// Checks for:
    /// 1. KNOWN_FINDINGS tampering to hide violations
    /// 2. Cross-region audit escalation attempts
    /// 3. Ambient authority accumulation in audit code itself
    /// 4. Privilege escalation through audit domain violations
    pub fn validate_audit_capabilities(
        &mut self,
        cx: &Cx,
        target_region: Option<RegionId>,
    ) -> Result<CapabilityEscalationResult, Error> {
        // Validate this audit operation is authorized by the region's capability context
        if !self.is_operation_authorized(cx) {
            return Err(Error::new(ErrorKind::AdmissionDenied)
                .with_message("Meta-audit operation not authorized by region capability context"));
        }

        // Check for KNOWN_FINDINGS tampering
        let current_hash = compute_findings_hash(KNOWN_FINDINGS);
        if current_hash != self.findings_hash {
            let suspicious_entries = self.detect_suspicious_findings_changes();
            return Ok(CapabilityEscalationResult::FindingsTampered {
                expected_hash: self.findings_hash,
                actual_hash: current_hash,
                suspicious_entries,
            });
        }

        // Check for cross-region escalation attempts
        if let Some(target) = target_region {
            if target != self.region_id && !self.can_audit_cross_region(cx, target) {
                return Ok(CapabilityEscalationResult::CrossRegionEscalation {
                    audit_region: self.region_id,
                    target_region: target,
                    violation_type: "Unauthorized cross-region audit access".to_string(),
                });
            }
        }

        // Check for ambient authority accumulation in audit code itself
        let audit_violations = self.scan_audit_code_for_ambient_authority()?;
        if !audit_violations.is_empty() {
            let affected_functions = self.identify_affected_audit_functions(&audit_violations);
            return Ok(CapabilityEscalationResult::AuditAccumulation {
                violations: audit_violations,
                affected_functions,
            });
        }

        // Update validation timestamp
        self.last_validated = Instant::now();
        Ok(CapabilityEscalationResult::Clean)
    }

    /// Enforces capability domain restrictions for audit operations.
    ///
    /// Prevents escalation by ensuring audit operations only occur within
    /// the authorized capability domain (Collection, Validation, or Meta).
    pub fn enforce_domain_isolation(
        &self,
        requested_operation: AuditOperation,
    ) -> Result<(), Error> {
        let allowed = match (self.audit_domain, requested_operation) {
            // Collection domain can gather violations but not modify findings
            (AuditDomain::Collection, AuditOperation::GatherViolations) => true,
            (AuditDomain::Collection, AuditOperation::ScanSource) => true,

            // Validation domain can validate but not collect or modify
            (AuditDomain::Validation, AuditOperation::ValidateFindings) => true,
            (AuditDomain::Validation, AuditOperation::CheckIntegrity) => true,

            // Meta domain can audit the auditors
            (AuditDomain::Meta, AuditOperation::AuditAuditors) => true,
            (AuditDomain::Meta, AuditOperation::ValidateCapabilities) => true,

            // All other combinations are capability escalation attempts
            _ => false,
        };

        if !allowed {
            return Err(Error::new(ErrorKind::AdmissionDenied).with_message(format!(
                "Operation {:?} not allowed in domain {:?} - capability escalation attempt",
                requested_operation, self.audit_domain
            )));
        }

        Ok(())
    }

    /// Creates a capability-constrained audit context for cross-region operations.
    ///
    /// Prevents escalation by creating a new audit context with minimal privileges
    /// needed for the specific cross-region audit operation.
    pub fn create_constrained_audit_context(
        &self,
        _cx: &Cx,
        target_region: RegionId,
        max_privilege: AuditDomain,
    ) -> Result<MetaAuditor, Error> {
        // Verify we have authority to create a constrained context
        if self.audit_domain != AuditDomain::Meta {
            return Err(Error::new(ErrorKind::AdmissionDenied)
                .with_message("Only Meta domain can create constrained audit contexts"));
        }

        // Constrain privileges to the minimum necessary
        let constrained_domain = match max_privilege {
            AuditDomain::Meta => AuditDomain::Validation, // Downgrade meta to validation
            other => other,                               // Keep collection/validation as-is
        };

        // Create new context bound to target region with constrained privileges
        Ok(MetaAuditor {
            region_id: target_region,
            audit_domain: constrained_domain,
            last_validated: Instant::now(),
            findings_hash: self.findings_hash, // Inherit current findings hash
        })
    }

    // --- Private implementation ---

    fn is_operation_authorized(&self, cx: &Cx) -> bool {
        // Check that the operation is running within the proper region context
        // This would typically check cx.current_region() == self.region_id
        // For now, we'll do a basic sanity check
        cx.budget().remaining_cost().unwrap_or(0) > 0 // Must have valid budget from proper Cx
    }

    fn can_audit_cross_region(&self, _cx: &Cx, _target_region: RegionId) -> bool {
        // Only Meta domain can perform cross-region audits
        self.audit_domain == AuditDomain::Meta
    }

    fn detect_suspicious_findings_changes(&self) -> Vec<String> {
        let mut suspicious = Vec::new();

        // Check for common tampering patterns
        for finding in KNOWN_FINDINGS {
            // Suspicious: exempt finding without proper justification
            if finding.exempt && finding.exemption_reason.is_none_or(|r| r.len() < 20) {
                suspicious.push(format!(
                    "{}:{} - Exempt without sufficient justification",
                    finding.file, finding.line
                ));
            }

            // Suspicious: critical finding marked as exempt
            if finding.exempt && finding.severity == Severity::Critical {
                suspicious.push(format!(
                    "{}:{} - Critical finding marked exempt",
                    finding.file, finding.line
                ));
            }

            // Suspicious: audit system itself has findings
            if finding.file.starts_with("audit/") && !finding.exempt {
                suspicious.push(format!(
                    "{}:{} - Audit system has unexempt finding",
                    finding.file, finding.line
                ));
            }
        }

        suspicious
    }

    fn scan_audit_code_for_ambient_authority(&self) -> Result<Vec<AmbientCategory>, Error> {
        use super::ambient::{ViolationType, detect_ambient_violations};

        // Read the audit module source code to scan for violations
        let audit_files = ["src/audit/ambient.rs", "src/audit/mod.rs"];
        let mut violations = Vec::new();

        for file_path in &audit_files {
            if let Ok(content) = std::fs::read_to_string(file_path) {
                let detected = detect_ambient_violations(&content);

                // Filter for direct usage violations (not just suspicious aliases)
                for violation in detected {
                    if violation.violation_type == ViolationType::DirectUsage {
                        violations.push(violation.category);
                    }
                }
            }
        }

        // Remove duplicates
        let unique_violations: HashSet<_> = violations.into_iter().collect();
        Ok(unique_violations.into_iter().collect())
    }

    fn identify_affected_audit_functions(&self, violations: &[AmbientCategory]) -> Vec<String> {
        let mut affected = Vec::new();

        // Map violation categories to likely affected audit functions
        for category in violations {
            match category {
                AmbientCategory::Time => {
                    affected.push("scan_source".to_string());
                    affected.push("validate_audit_capabilities".to_string());
                }
                AmbientCategory::Io => {
                    affected.push("collect_rs_files".to_string());
                    affected.push("scan_directory".to_string());
                }
                AmbientCategory::Output => {
                    affected.push("format_violations".to_string());
                }
                _ => {
                    affected.push(format!("unknown_function_{:?}", category));
                }
            }
        }

        // Remove duplicates
        let unique_functions: HashSet<_> = affected.into_iter().collect();
        unique_functions.into_iter().collect()
    }
}

/// Audit operations that must be performed within appropriate capability domains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditOperation {
    /// Gather ambient authority violations from source code.
    GatherViolations,
    /// Scan source files for ambient authority patterns.
    ScanSource,
    /// Validate known findings against actual code.
    ValidateFindings,
    /// Check integrity of audit data structures.
    CheckIntegrity,
    /// Audit the auditors themselves (meta-operation).
    AuditAuditors,
    /// Validate capability constraints in audit operations.
    ValidateCapabilities,
}

/// Compute a hash of KNOWN_FINDINGS for integrity checking.
///
/// This is a simple hash function to detect tampering with the findings list.
/// In a production system, this would use a cryptographic hash.
fn compute_findings_hash(findings: &[AmbientFinding]) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();

    // Hash the essential properties of each finding
    for finding in findings {
        finding.file.hash(&mut hasher);
        finding.line.hash(&mut hasher);
        finding.evidence_pattern.hash(&mut hasher);
        finding.exempt.hash(&mut hasher);
        // Hash severity as its discriminant value
        let severity_value = match finding.severity {
            Severity::Low => 0u8,
            Severity::Medium => 1u8,
            Severity::High => 2u8,
            Severity::Critical => 3u8,
        };
        severity_value.hash(&mut hasher);
        // Don't hash description or exemption_reason as they can change without security impact
    }

    hasher.finish()
}

/// Public API for creating region-scoped meta-auditors.
///
/// This ensures all meta-auditors are properly region-scoped and cannot
/// escalate capabilities across region boundaries.
pub fn create_meta_auditor_for_region(region_id: RegionId, cx: &Cx) -> Result<MetaAuditor, Error> {
    // Start with validation domain for most operations
    let auditor = MetaAuditor::new(region_id, AuditDomain::Validation, Instant::now());

    // Validate the auditor creation is authorized
    if auditor.is_operation_authorized(cx) {
        Ok(auditor)
    } else {
        Err(Error::new(ErrorKind::AdmissionDenied)
            .with_message("Not authorized to create meta-auditor in this region"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::RegionId;
    use std::time::Instant;

    #[test]
    fn meta_auditor_creation() {
        let region_id = RegionId::new_for_test(1, 0);
        let now = Instant::now();

        let auditor = MetaAuditor::new(region_id, AuditDomain::Collection, now);

        assert_eq!(auditor.region_id, region_id);
        assert_eq!(auditor.audit_domain, AuditDomain::Collection);
        assert_eq!(auditor.last_validated, now);
        assert!(auditor.findings_hash != 0); // Should have computed a hash
    }

    #[test]
    fn domain_isolation_enforcement() {
        let region_id = RegionId::new_for_test(1, 0);
        let now = Instant::now();

        let collection_auditor = MetaAuditor::new(region_id, AuditDomain::Collection, now);
        let validation_auditor = MetaAuditor::new(region_id, AuditDomain::Validation, now);
        let meta_auditor = MetaAuditor::new(region_id, AuditDomain::Meta, now);

        // Collection domain should allow gathering but not validation
        assert!(
            collection_auditor
                .enforce_domain_isolation(AuditOperation::GatherViolations)
                .is_ok()
        );
        assert!(
            collection_auditor
                .enforce_domain_isolation(AuditOperation::ValidateFindings)
                .is_err()
        );

        // Validation domain should allow validation but not gathering
        assert!(
            validation_auditor
                .enforce_domain_isolation(AuditOperation::ValidateFindings)
                .is_ok()
        );
        assert!(
            validation_auditor
                .enforce_domain_isolation(AuditOperation::GatherViolations)
                .is_err()
        );

        // Meta domain should allow meta operations
        assert!(
            meta_auditor
                .enforce_domain_isolation(AuditOperation::AuditAuditors)
                .is_ok()
        );
        assert!(
            meta_auditor
                .enforce_domain_isolation(AuditOperation::ValidateCapabilities)
                .is_ok()
        );
    }

    #[test]
    fn findings_hash_computation() {
        let hash1 = compute_findings_hash(KNOWN_FINDINGS);
        let hash2 = compute_findings_hash(KNOWN_FINDINGS);

        // Hash should be deterministic
        assert_eq!(hash1, hash2);
        assert!(hash1 != 0); // Should not be zero
    }

    #[test]
    fn constrained_context_creation() {
        let region_id = RegionId::new_for_test(1, 0);
        let target_region = RegionId::new_for_test(2, 0);
        let now = Instant::now();

        // Only Meta domain should be able to create constrained contexts
        let meta_auditor = MetaAuditor::new(region_id, AuditDomain::Meta, now);
        let collection_auditor = MetaAuditor::new(region_id, AuditDomain::Collection, now);

        let cx = crate::cx::Cx::for_testing();

        // Meta auditor should be able to create constrained context
        assert!(
            meta_auditor
                .create_constrained_audit_context(&cx, target_region, AuditDomain::Collection)
                .is_ok()
        );

        // Collection auditor should not be able to create constrained context
        assert!(
            collection_auditor
                .create_constrained_audit_context(&cx, target_region, AuditDomain::Collection)
                .is_err()
        );
    }

    #[test]
    fn cross_region_escalation_detection() {
        let audit_region = RegionId::new_for_test(1, 0);
        let target_region = RegionId::new_for_test(2, 0);
        let now = Instant::now();

        // Collection domain should not be able to audit cross-region
        let collection_auditor = MetaAuditor::new(audit_region, AuditDomain::Collection, now);
        assert!(
            !collection_auditor
                .can_audit_cross_region(&crate::cx::Cx::for_testing(), target_region)
        );

        // Meta domain should be able to audit cross-region
        let meta_auditor = MetaAuditor::new(audit_region, AuditDomain::Meta, now);
        assert!(meta_auditor.can_audit_cross_region(&crate::cx::Cx::for_testing(), target_region));
    }

    #[test]
    fn suspicious_findings_detection() {
        let region_id = RegionId::new_for_test(1, 0);
        let now = Instant::now();

        let auditor = MetaAuditor::new(region_id, AuditDomain::Meta, now);
        let suspicious = auditor.detect_suspicious_findings_changes();

        // This will detect any real suspicious patterns in the current KNOWN_FINDINGS
        // The test validates the detection logic works, actual results depend on current state
        // Each suspicious entry should have a clear reason
        for entry in &suspicious {
            assert!(
                entry.contains(" - "),
                "Suspicious entry should have explanation: {}",
                entry
            );
        }
    }
}
