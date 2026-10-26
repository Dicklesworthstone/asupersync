    use super::*;
    use crate::cli::output::OutputFormat;
    use crate::test_utils::run_test_with_cx;

    #[test]
    fn test_workflow_coordinator_creation() {
        run_test_with_cx(|_cx| async move {
            let coordinator = AtpWorkflowCoordinator::new(OutputFormat::Json);
            assert!(coordinator.is_ok());
        });
    }

    #[test]
    fn workflow_explicit_policy_reaches_both_cache_owners() {
        let root = tempfile::tempdir().unwrap();
        let mut policy = TrustPolicy::local();
        policy.add_authorized_scope("ci:allowed".to_string());
        let mut coordinator = AtpWorkflowCoordinator::with_trust_policy(
            OutputFormat::Json,
            root.path().join("state"),
            policy,
        )
        .unwrap();
        let content = b"scoped cache and seeding content";
        let hash = coordinator.compute_content_hash(content);
        let key = CacheKey::new(
            "manifest".to_string(),
            hash.clone(),
            Some("ci:allowed".to_string()),
        );
        coordinator.cache.put(key.clone(), content).unwrap();
        assert_eq!(
            coordinator.cache.get(&key).unwrap().as_deref(),
            Some(content.as_slice())
        );
        coordinator
            .seeding_service
            .authorize_manifest(
                "manifest".to_string(),
                "ci:allowed".to_string(),
                "high".to_string(),
            )
            .unwrap();
        coordinator
            .seeding_service
            .add_seeded_content("manifest", &hash, content)
            .unwrap();
        assert!(
            coordinator
                .seeding_service
                .get_seeded_content("manifest", &hash, &[])
                .is_err()
        );
        assert_eq!(
            coordinator
                .seeding_service
                .get_seeded_content("manifest", &hash, &["ci:allowed".to_string()])
                .unwrap()
                .as_deref(),
            Some(content.as_slice())
        );
        coordinator
            .seeding_service
            .authorize_manifest(
                "foreign".to_string(),
                "ci:denied".to_string(),
                "high".to_string(),
            )
            .unwrap();
        assert!(matches!(
            coordinator
                .seeding_service
                .add_seeded_content("foreign", &hash, content),
            Err(crate::atp::seeding::SeedingError::CacheError(
                crate::atp::cache::CacheError::TrustViolation(_)
            ))
        ));
    }

    #[test]
    fn workflow_explicit_policy_refuses_shared_storage_before_creating_a_root() {
        let root = tempfile::tempdir().unwrap();
        let state = root.path().join("state");
        let error = AtpWorkflowCoordinator::with_trust_policy(
            OutputFormat::Json,
            &state,
            TrustPolicy::shared(),
        )
        .err()
        .expect("workflow copies do not implement encrypted shared storage");
        assert_eq!(error.error_type, "trust_policy_error");
        assert!(!state.exists());
    }

    #[test]
    fn test_content_hash_computation() {
        run_test_with_cx(|_cx| async move {
            let coordinator = AtpWorkflowCoordinator::new(OutputFormat::Json).unwrap();
            let content = b"test content";
            let hash1 = coordinator.compute_content_hash(content);
            let hash2 = coordinator.compute_content_hash(content);
            assert_eq!(hash1, hash2);
            // The persisted artifact format stores the bare lowercase hex
            // SHA-256 digest (64 chars), compared verbatim against
            // `artifact.content_hash` on restore; a `sha256:` prefix would
            // change that on-disk format.
            assert_eq!(hash1.len(), 64, "bare hex SHA-256: {hash1}");
            assert!(
                hash1
                    .chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
            );
            assert_eq!(
                hash1, "6ae8a75555209fd6c44157c0aed8016e763ff435a19cf186f76863140143ff72",
                "SHA-256 of b\"test content\""
            );
        });
    }

    #[test]
    fn test_retention_duration_parsing() {
        run_test_with_cx(|_cx| async move {
            let coordinator = AtpWorkflowCoordinator::new(OutputFormat::Json).unwrap();

            let duration_7d = coordinator.parse_retention_duration("7d");
            assert_eq!(duration_7d, Some(Duration::from_secs(7 * 24 * 60 * 60)));

            let duration_permanent = coordinator.parse_retention_duration("permanent");
            assert_eq!(duration_permanent, None);

            let duration_invalid = coordinator.parse_retention_duration("invalid");
            assert_eq!(duration_invalid, None);
        });
    }
