    use super::*;
    use crate::asupersync::atp::quota::{QuotaLimit, RetentionRule};

    fn digest(byte: u8) -> ObjectDigest {
        ObjectDigest::new([byte; 32])
    }

    fn record(
        record_id: &str,
        collection: AtpdStateCollection,
        bytes: u64,
        updated_epoch_secs: u64,
        sensitivity: StateSensitivity,
    ) -> AtpdStateRecord {
        AtpdStateRecord::new(
            record_id,
            collection,
            digest(bytes as u8),
            format!("{collection}:{record_id}"),
            bytes,
            RetentionClock::new(0, updated_epoch_secs),
            sensitivity,
        )
        .with_field("payload_digest")
    }

    #[test]
    fn schema_covers_every_required_collection() {
        let mut state = AtpdPersistentState::new();
        state.ensure_required_collections();

        assert!(state.covers_required_collections());
        assert_eq!(required_collections().len(), 14);
    }

    #[test]
    fn migration_rejects_future_schema() {
        let mut snapshot = AtpdPersistentState::new();
        snapshot.schema_version = AtpdSchemaVersion(ATPD_STATE_SCHEMA_VERSION + 1);

        assert_eq!(
            AtpdPersistentState::restore(snapshot).unwrap_err(), // ubs:ignore - test oracle
            AtpdStateError::UnsupportedSchema(AtpdSchemaVersion(ATPD_STATE_SCHEMA_VERSION + 1))
        );
    }

    #[test]
    fn quota_exhaustion_blocks_insert_without_mutating_state() {
        let mut state = AtpdPersistentState::new();
        state
            .quota_ledger
            .set_limit(QuotaBucket::Cache, QuotaLimit::new(10, 1));
        state
            .insert_record(record(
                "cache-a",
                AtpdStateCollection::Cache,
                8,
                10,
                StateSensitivity::PrivateContent,
            ))
            .unwrap(); // ubs:ignore - test oracle

        let err = state
            .insert_record(record(
                "cache-b",
                AtpdStateCollection::Cache,
                1,
                11,
                StateSensitivity::PrivateContent,
            ))
            .unwrap_err();

        assert!(matches!(
            err,
            AtpdStateError::Quota(QuotaError::Exhausted { .. })
        ));
        assert_eq!(
            state
                .records
                .get(&AtpdStateCollection::Cache)
                .map(BTreeMap::len),
            Some(1)
        );
    }

    #[test]
    fn integrity_report_detects_corrupt_quota_accounting() {
        let mut state = AtpdPersistentState::new();
        state.ensure_required_collections();
        state
            .records
            .entry(AtpdStateCollection::Cache)
            .or_default()
            .insert(
                "unaccounted".to_string(),
                record(
                    "unaccounted",
                    AtpdStateCollection::Cache,
                    9,
                    10,
                    StateSensitivity::PrivateContent,
                ),
            );

        let report = state.integrity_report();
        assert!(report.missing_collections.is_empty());
        assert_eq!(
            report.quota_mismatches,
            vec![AtpdQuotaMismatch {
                bucket: QuotaBucket::Cache,
                expected: QuotaUsage {
                    bytes: 9,
                    records: 1
                },
                actual: QuotaUsage::default(),
            }]
        );
    }

    #[test]
    fn retention_expires_old_records_and_releases_quota() {
        let mut state = AtpdPersistentState::new();
        state
            .retention_policy
            .set_rule(QuotaBucket::Traces, RetentionRule::max_age(10));
        state
            .insert_record(record(
                "trace-old",
                AtpdStateCollection::Traces,
                5,
                80,
                StateSensitivity::Internal,
            ))
            .unwrap(); // ubs:ignore - test oracle
        state
            .insert_record(record(
                "trace-new",
                AtpdStateCollection::Traces,
                7,
                95,
                StateSensitivity::Internal,
            ))
            .unwrap(); // ubs:ignore - test oracle

        assert_eq!(
            state.apply_retention(100).unwrap(),
            vec!["traces:trace-old".to_string()]
        );
        assert_eq!(state.quota_ledger.usage(QuotaBucket::Traces).bytes, 7);
    }

    #[test]
    fn redacted_export_hides_sensitive_payloads() {
        let mut state = AtpdPersistentState::new();
        state
            .insert_record(
                record(
                    "identity-a",
                    AtpdStateCollection::Identities,
                    32,
                    10,
                    StateSensitivity::KeyMaterial,
                )
                .with_export_policy(StateExportPolicy::ExplicitPolicyRequired),
            )
            .unwrap(); // ubs:ignore - test oracle

        let export = state.export(AtpdExportMode::Redacted, false).unwrap(); // ubs:ignore - test oracle
        assert_eq!(export.records.len(), 1);
        assert!(export.records[0].redacted);
        assert!(export.records[0].payload_digest.ends_with("..."));
    }

    #[test]
    fn diagnostics_export_is_always_redacted_without_policy() {
        let mut state = AtpdPersistentState::new();
        state
            .insert_record(
                record(
                    "diagnostic-a",
                    AtpdStateCollection::Diagnostics,
                    16,
                    10,
                    StateSensitivity::Internal,
                )
                .with_export_policy(StateExportPolicy::ExplicitPolicyRequired),
            )
            .unwrap(); // ubs:ignore - test oracle

        let export = state.privacy_safe_diagnostics_export().unwrap(); // ubs:ignore - test oracle
        assert_eq!(export.mode, "redacted");
        assert!(export.records[0].redacted);
    }

    #[test]
    fn full_export_requires_policy_and_still_respects_record_policy() {
        let mut state = AtpdPersistentState::new();
        state
            .insert_record(
                record(
                    "public-setting",
                    AtpdStateCollection::Settings,
                    1,
                    10,
                    StateSensitivity::Public,
                )
                .with_export_policy(StateExportPolicy::ExplicitPolicyRequired),
            )
            .unwrap(); // ubs:ignore - test oracle

        assert_eq!(
            state.export(AtpdExportMode::Full, false).unwrap_err(), // ubs:ignore - test oracle
            AtpdStateError::PolicyRequiredForFullExport
        );
        let export = state.export(AtpdExportMode::Full, true).unwrap(); // ubs:ignore - test oracle
        assert!(!export.records[0].redacted);
        assert!(!export.records[0].payload_digest.ends_with("..."));
    }

    #[test]
    fn full_export_with_policy_can_include_private_metadata_digest() {
        let mut state = AtpdPersistentState::new();
        state
            .insert_record(
                record(
                    "cache-private",
                    AtpdStateCollection::Cache,
                    2,
                    10,
                    StateSensitivity::PrivateContent,
                )
                .with_export_policy(StateExportPolicy::ExplicitPolicyRequired),
            )
            .unwrap(); // ubs:ignore - test oracle

        let export = state.export(AtpdExportMode::Full, true).unwrap(); // ubs:ignore - test oracle
        assert!(!export.records[0].redacted);
    }

    #[test]
    fn consent_records_restore_and_snapshot_deterministically() {
        let mut state = AtpdPersistentState::new();
        state.ensure_required_collections();
        state
            .insert_record(record(
                "consent-a",
                AtpdStateCollection::ConsentRecords,
                9,
                10,
                StateSensitivity::GrantSecret,
            ))
            .unwrap(); // ubs:ignore - test oracle

        let restored = AtpdPersistentState::restore(state.clone()).unwrap(); // ubs:ignore - test oracle
        assert_eq!(
            state.deterministic_snapshot_json().unwrap(),
            restored.deterministic_snapshot_json().unwrap()
        );
    }

    #[test]
    fn quarantine_cleanup_uses_retention_policy() {
        let mut state = AtpdPersistentState::new();
        state
            .retention_policy
            .set_rule(QuotaBucket::Quarantine, RetentionRule::max_age(1));
        state
            .insert_record(record(
                "quarantine-a",
                AtpdStateCollection::Quarantine,
                64,
                10,
                StateSensitivity::Quarantine,
            ))
            .unwrap(); // ubs:ignore - test oracle

        assert_eq!(
            state.expired_record_ids(12),
            vec!["quarantine:quarantine-a".to_string()]
        );
    }
