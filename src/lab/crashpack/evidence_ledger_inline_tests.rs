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
