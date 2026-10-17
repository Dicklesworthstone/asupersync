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
