    use super::*;
    use crate::atp::grant::GrantOperation;
    use crate::atp::policy::{
        Capability, CapabilityAction, ResourceScope, ScopeConstraints, TemporalScope,
    };
    use crate::net::atp::protocol::PeerId;
    use std::collections::HashSet;
    use std::time::Duration;
    use tempfile::tempdir;

    fn create_test_grant_info_with_id(grant_id: &str) -> GrantInfo {
        let mut actions = HashSet::new();
        actions.insert(CapabilityAction::Read);

        let capability = Capability::new(
            grant_id.to_string(),
            PeerId::test(1),
            PeerId::test(2),
            ResourceScope::Any,
            actions,
            TemporalScope::expires_in(Duration::from_secs(3600)),
            ScopeConstraints::default(),
        );

        GrantInfo::new(capability)
    }

    fn create_test_grant_info() -> GrantInfo {
        create_test_grant_info_with_id("test-grant-123")
    }

    #[test]
    fn storage_stores_and_retrieves_grants() {
        let temp_dir = tempdir().expect("tempdir"); // ubs:ignore - test oracle
        let mut storage = GrantStorage::new(temp_dir.path()).expect("create storage"); // ubs:ignore - test oracle

        let grant_info = create_test_grant_info();
        let grant_id = grant_info.capability.grant_id.clone();

        // Store grant
        storage
            .store_grant(grant_info.clone())
            .expect("store grant"); // ubs:ignore - test oracle

        // Retrieve grant
        let retrieved = storage.get_grant(&grant_id).expect("get grant"); // ubs:ignore - test oracle
        assert_eq!(
            retrieved.capability.grant_id,
            grant_info.capability.grant_id
        );
        assert_eq!(retrieved.capability.subject, grant_info.capability.subject);
    }

    #[test]
    fn storage_prevents_duplicate_grants() {
        let temp_dir = tempdir().expect("tempdir"); // ubs:ignore - test oracle
        let mut storage = GrantStorage::new(temp_dir.path()).expect("create storage"); // ubs:ignore - test oracle

        let grant_info = create_test_grant_info();

        // Store grant
        storage
            .store_grant(grant_info.clone())
            .expect("store grant"); // ubs:ignore - test oracle

        // Try to store again - should fail
        let result = storage.store_grant(grant_info);
        assert!(matches!(
            result,
            Outcome::Err(GrantError::AlreadyExists { .. })
        ));
    }

    #[test]
    fn storage_uses_collision_resistant_file_paths() {
        let temp_dir = tempdir().expect("tempdir"); // ubs:ignore - test oracle
        let mut storage = GrantStorage::new(temp_dir.path()).expect("create storage"); // ubs:ignore - test oracle

        let first = create_test_grant_info_with_id("grant/a");
        let second = create_test_grant_info_with_id("grant_a");
        let first_path = storage.grant_file_path(&first.capability.grant_id);
        let second_path = storage.grant_file_path(&second.capability.grant_id);

        assert_ne!(first_path, second_path);

        storage.store_grant(first.clone()).expect("store first"); // ubs:ignore - test oracle
        storage.store_grant(second.clone()).expect("store second"); // ubs:ignore - test oracle

        assert!(first_path.exists());
        assert!(second_path.exists());

        let reloaded = GrantStorage::new(temp_dir.path()).expect("reload storage"); // ubs:ignore - test oracle
        assert!(reloaded.get_grant(&first.capability.grant_id).is_ok());
        assert!(reloaded.get_grant(&second.capability.grant_id).is_ok());
    }

    #[test]
    fn storage_rejects_update_with_mismatched_grant_id() {
        let temp_dir = tempdir().expect("tempdir"); // ubs:ignore - test oracle
        let mut storage = GrantStorage::new(temp_dir.path()).expect("create storage"); // ubs:ignore - test oracle
        let grant_info = create_test_grant_info();
        let grant_id = grant_info.capability.grant_id.clone();

        storage.store_grant(grant_info).expect("store grant"); // ubs:ignore - test oracle

        let mismatched = create_test_grant_info_with_id("different-grant-id");
        let result = storage.update_grant(&grant_id, mismatched);

        assert!(matches!(
            result,
            Outcome::Err(GrantError::ValidationFailed { .. })
        ));
        assert!(storage.get_grant(&grant_id).is_ok());
        assert!(matches!(
            storage.get_grant("different-grant-id"),
            Outcome::Err(GrantError::NotFound { .. })
        ));
    }

    #[test]
    fn storage_lists_grants_with_filters() {
        let temp_dir = tempdir().expect("tempdir"); // ubs:ignore - test oracle
        let mut storage = GrantStorage::new(temp_dir.path()).expect("create storage"); // ubs:ignore - test oracle

        let grant_info = create_test_grant_info();
        storage
            .store_grant(grant_info.clone())
            .expect("store grant"); // ubs:ignore - test oracle

        // Query by subject
        let query = GrantQuery {
            subject: Some(grant_info.capability.subject),
            ..Default::default()
        };

        let results = storage.list_grants(&query).expect("list grants"); // ubs:ignore - test oracle
        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0].capability.grant_id,
            grant_info.capability.grant_id
        );

        // Query by different subject
        let query = GrantQuery {
            subject: Some(PeerId::test(99)),
            ..Default::default()
        };

        let results = storage.list_grants(&query).expect("list grants"); // ubs:ignore - test oracle
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn storage_tracks_audit_records() {
        let temp_dir = tempdir().expect("tempdir"); // ubs:ignore - test oracle
        let mut storage = GrantStorage::new(temp_dir.path()).expect("create storage"); // ubs:ignore - test oracle

        let grant_info = create_test_grant_info();
        let grant_id = grant_info.capability.grant_id.clone();
        storage.store_grant(grant_info).expect("store grant"); // ubs:ignore - test oracle

        // Add audit record
        let audit_record = GrantAuditRecord {
            grant_id: grant_id.clone(),
            operation: GrantOperation::Used,
            actor: PeerId::test(1),
            target: None,
            timestamp: SystemTime::now(),
            context: HashMap::new(),
            capability_summary: "test summary".to_string(),
        };

        storage
            .add_audit_record(audit_record.clone())
            .expect("add audit record"); // ubs:ignore - test oracle

        // Retrieve audit records
        let records = storage
            .get_audit_records(&grant_id)
            .expect("get audit records"); // ubs:ignore - test oracle
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].operation, GrantOperation::Used);

        // Check global audit records
        let global_records = storage.get_global_audit_records();
        assert_eq!(global_records.len(), 1);
    }

    #[test]
    fn storage_rejects_audit_records_for_missing_grants() {
        let temp_dir = tempdir().expect("tempdir"); // ubs:ignore - test oracle
        let mut storage = GrantStorage::new(temp_dir.path()).expect("create storage"); // ubs:ignore - test oracle

        let result = storage.add_audit_record(GrantAuditRecord {
            grant_id: "missing-grant".to_string(),
            operation: GrantOperation::Used,
            actor: PeerId::test(1),
            target: None,
            timestamp: SystemTime::now(),
            context: HashMap::new(),
            capability_summary: "missing".to_string(),
        });

        assert!(matches!(result, Outcome::Err(GrantError::NotFound { .. })));
        assert!(storage.get_global_audit_records().is_empty());
    }

    #[test]
    fn storage_persists_across_instances() {
        let temp_dir = tempdir().expect("tempdir"); // ubs:ignore - test oracle
        let grant_info = create_test_grant_info();
        let grant_id = grant_info.capability.grant_id.clone();

        // Create storage and store grant
        {
            let mut storage = GrantStorage::new(temp_dir.path()).expect("create storage"); // ubs:ignore - test oracle
            storage
                .store_grant(grant_info.clone())
                .expect("store grant"); // ubs:ignore - test oracle
        }

        // Create new storage instance and verify grant is still there
        {
            let storage = GrantStorage::new(temp_dir.path()).expect("create storage"); // ubs:ignore - test oracle
            let retrieved = storage.get_grant(&grant_id).expect("get grant"); // ubs:ignore - test oracle
            assert_eq!(
                retrieved.capability.grant_id,
                grant_info.capability.grant_id
            );
        }
    }

    #[test]
    fn storage_persists_grant_specific_audit_records_across_instances() {
        let temp_dir = tempdir().expect("tempdir"); // ubs:ignore - test oracle
        let grant_info = create_test_grant_info();
        let grant_id = grant_info.capability.grant_id.clone();

        {
            let mut storage = GrantStorage::new(temp_dir.path()).expect("create storage"); // ubs:ignore - test oracle
            storage.store_grant(grant_info).expect("store grant"); // ubs:ignore - test oracle
            storage
                .add_audit_record(GrantAuditRecord {
                    grant_id: grant_id.clone(),
                    operation: GrantOperation::Used,
                    actor: PeerId::test(1),
                    target: None,
                    timestamp: SystemTime::now(),
                    context: HashMap::new(),
                    capability_summary: "used".to_string(),
                })
                .expect("add audit record"); // ubs:ignore - test oracle
        }

        let storage = GrantStorage::new(temp_dir.path()).expect("reload storage"); // ubs:ignore - test oracle
        let records = storage
            .get_audit_records(&grant_id)
            .expect("get persisted audit records"); // ubs:ignore - test oracle
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].operation, GrantOperation::Used);
        assert_eq!(storage.get_global_audit_records().len(), 1);
    }

    #[test]
    fn storage_rejects_malformed_grant_file_on_startup() {
        let temp_dir = tempdir().expect("tempdir"); // ubs:ignore - test oracle
        let grants_dir = temp_dir.path().join("grants");
        std::fs::create_dir_all(&grants_dir).expect("create grants dir"); // ubs:ignore - test oracle
        std::fs::write(grants_dir.join("bad.json"), "{not valid json")
            .expect("write malformed grant"); // ubs:ignore - test oracle

        let result = GrantStorage::new(temp_dir.path());

        assert!(matches!(result, Outcome::Err(GrantError::Storage(_))));
    }

    #[test]
    fn storage_rejects_duplicate_grant_ids_on_startup() {
        let temp_dir = tempdir().expect("tempdir"); // ubs:ignore - test oracle
        let grants_dir = temp_dir.path().join("grants");
        std::fs::create_dir_all(&grants_dir).expect("create grants dir"); // ubs:ignore - test oracle

        let record = GrantRecord {
            grant_info: create_test_grant_info_with_id("duplicate-grant"),
            audit_records: Vec::new(),
            storage_metadata: StorageMetadata::default(),
        };
        let serialized = serde_json::to_string_pretty(&record).expect("serialize record"); // ubs:ignore - test oracle

        std::fs::write(grants_dir.join("first.json"), &serialized).expect("write first grant"); // ubs:ignore - test oracle
        std::fs::write(grants_dir.join("second.json"), serialized).expect("write second grant"); // ubs:ignore - test oracle

        let result = GrantStorage::new(temp_dir.path());

        assert!(matches!(
            result,
            Outcome::Err(GrantError::Storage(message)) if message.contains("duplicate grant id")
        ));
    }

    #[test]
    fn storage_rejects_malformed_audit_log_on_startup() {
        let temp_dir = tempdir().expect("tempdir"); // ubs:ignore - test oracle
        std::fs::write(temp_dir.path().join("audit.jsonl"), "not json\n")
            .expect("write malformed audit log"); // ubs:ignore - test oracle

        let result = GrantStorage::new(temp_dir.path());

        assert!(matches!(result, Outcome::Err(GrantError::Storage(_))));
    }

    #[test]
    fn storage_calculates_stats() {
        let temp_dir = tempdir().expect("tempdir"); // ubs:ignore - test oracle
        let mut storage = GrantStorage::new(temp_dir.path()).expect("create storage"); // ubs:ignore - test oracle

        let grant_info = create_test_grant_info();
        storage.store_grant(grant_info).expect("store grant"); // ubs:ignore - test oracle

        let stats = storage.get_stats();
        assert_eq!(stats.total_grants, 1);
        assert_eq!(stats.unique_subjects, 1);
        assert_eq!(stats.unique_issuers, 1);
        assert_eq!(stats.total_usage, 0);
    }

    #[test]
    fn storage_stats_saturate_total_usage() {
        let temp_dir = tempdir().expect("tempdir"); // ubs:ignore - test oracle
        let mut storage = GrantStorage::new(temp_dir.path()).expect("create storage"); // ubs:ignore - test oracle

        let mut first = create_test_grant_info_with_id("first-grant");
        first.usage_count = u64::MAX;
        storage.store_grant(first).expect("store first grant"); // ubs:ignore - test oracle

        let mut second = create_test_grant_info_with_id("second-grant");
        second.usage_count = 1;
        storage.store_grant(second).expect("store second grant"); // ubs:ignore - test oracle

        let stats = storage.get_stats();
        assert_eq!(stats.total_usage, u64::MAX);
    }
