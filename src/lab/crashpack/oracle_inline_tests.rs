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
