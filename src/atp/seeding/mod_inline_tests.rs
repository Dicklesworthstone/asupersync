    use super::*;
    use crate::atp::cache::{AtpCache, CacheConfig};

    #[test]
    fn seeding_config_defaults() {
        let config = SeedingConfig::default();
        assert!(!config.enabled); // Should be disabled by default
        assert!(config.require_explicit_grants); // Should require grants by default
        assert_eq!(config.priority_levels.len(), 3);
    }

    #[test]
    fn seeding_priority_configurations() {
        let high = SeedingPriority::high();
        let normal = SeedingPriority::normal();
        let low = SeedingPriority::low();

        assert!(high.priority > normal.priority);
        assert!(normal.priority > low.priority);
        assert!(high.bandwidth_ratio > normal.bandwidth_ratio);
        assert!(normal.bandwidth_ratio > low.bandwidth_ratio);
    }

    #[test]
    fn manifest_authorization_validity() {
        let mut auth = ManifestAuthorization::new(
            "manifest123".to_string(),
            "scope456".to_string(),
            "high".to_string(),
        );

        assert!(auth.is_valid());

        // Set expiration in the past
        auth.expires_at = Some(SystemTime::UNIX_EPOCH);
        assert!(!auth.is_valid());

        // Deactivate
        auth.expires_at = None;
        auth.active = false;
        assert!(!auth.is_valid());
    }

    #[test]
    fn seeding_service_authorization() {
        let config = SeedingConfig {
            enabled: true,
            ..SeedingConfig::default()
        };
        let cache = AtpCache::new(CacheConfig::default());
        let mut service = AtpSeedingService::new(config, cache);

        // Should not be authorized initially
        assert!(!service.is_authorized("manifest123"));

        // Authorize manifest
        let result = service.authorize_manifest(
            "manifest123".to_string(),
            "scope456".to_string(),
            "high".to_string(),
        );
        assert!(result.is_ok());

        // Should now be authorized
        assert!(service.is_authorized("manifest123"));

        // Revoke authorization
        let result = service.revoke_manifest("manifest123");
        assert!(result.is_ok());
        assert!(!service.is_authorized("manifest123"));
    }

    #[test]
    fn seeding_service_disabled_by_default() {
        let config = SeedingConfig::default(); // Disabled by default
        let cache = AtpCache::new(CacheConfig::default());
        let mut service = AtpSeedingService::new(config, cache);

        // Should fail when seeding is disabled
        let result = service.authorize_manifest(
            "manifest123".to_string(),
            "scope456".to_string(),
            "high".to_string(),
        );
        assert!(matches!(result, Err(SeedingError::SeedingDisabled)));
    }

    #[test]
    fn seeding_session_management() {
        let config = SeedingConfig {
            enabled: true,
            max_concurrent_connections: Some(2),
            ..SeedingConfig::default()
        };
        let cache = AtpCache::new(CacheConfig::default());
        let mut service = AtpSeedingService::new(config, cache);

        // Authorize a manifest first
        service
            .authorize_manifest(
                "manifest123".to_string(),
                "scope456".to_string(),
                "high".to_string(),
            )
            .unwrap();

        // Start session
        let session_id = service
            .start_session(
                "peer1".to_string(),
                "manifest123".to_string(),
                vec!["scope456".to_string()],
            )
            .unwrap();

        assert!(service.active_sessions.contains_key(&session_id));
        assert_eq!(service.metrics().sessions_started, 1);

        // End session
        service.end_session(&session_id).unwrap();
        assert!(!service.active_sessions.contains_key(&session_id));
        assert_eq!(service.metrics().sessions_completed, 1);
    }

    #[test]
    fn grant_verification_cannot_be_bypassed() {
        let config = SeedingConfig {
            enabled: true,
            require_explicit_grants: false, // Even when disabled, security should still work
            ..SeedingConfig::default()
        };
        let cache = AtpCache::new(CacheConfig::default());
        let mut service = AtpSeedingService::new(config, cache);

        // Authorize a manifest with private scope
        service
            .authorize_manifest(
                "manifest123".to_string(),
                "private-scope".to_string(),
                "high".to_string(),
            )
            .unwrap();

        // Try to access without proper grants - should be denied
        let result =
            service.get_seeded_content("manifest123", "content456", &["wrong-scope".to_string()]);
        assert!(matches!(result, Err(SeedingError::InsufficientGrants(_))));

        // Try to start session without proper grants - should be denied
        let result = service.start_session(
            "peer1".to_string(),
            "manifest123".to_string(),
            vec!["wrong-scope".to_string()],
        );
        assert!(matches!(result, Err(SeedingError::InsufficientGrants(_))));

        // Public content should still be accessible
        service
            .authorize_manifest(
                "public-manifest".to_string(),
                "public".to_string(),
                "high".to_string(),
            )
            .unwrap();

        let result =
            service.get_seeded_content("public-manifest", "content789", &["any-scope".to_string()]);
        // Should not fail due to grants (will fail due to missing cache content)
        assert!(matches!(
            result,
            Ok(None) | Err(SeedingError::CacheError(_))
        ));
    }
