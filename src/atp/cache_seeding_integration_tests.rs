//! Integration tests for ATP cache and seeding system.

#[cfg(test)]
mod tests {
    use crate::atp::cache::{AtpCache, CacheConfig, CacheKey};
    use crate::atp::seeding::{AtpSeedingService, SeedingConfig};
    use std::time::Duration;

    #[test]
    fn cache_basic_integration() {
        let config = CacheConfig::default();
        let cache = AtpCache::new(config);

        // Test that cache is created successfully
        assert_eq!(cache.metrics().entry_count, 0);
        assert_eq!(cache.metrics().total_bytes, 0);
    }

    #[test]
    fn cache_key_creation() {
        let key = CacheKey::new(
            "manifest123".to_string(),
            "content456".to_string(),
            Some("scope789".to_string()),
        );

        assert_eq!(key.manifest_hash, "manifest123");
        assert_eq!(key.content_hash, "content456");
        assert_eq!(key.grant_scope, Some("scope789".to_string()));
        assert_eq!(key.as_index_key(), "manifest123:content456:scope789");
    }

    #[test]
    fn seeding_service_creation() {
        let config = SeedingConfig::default();
        let cache = AtpCache::new(CacheConfig::default());
        let service = AtpSeedingService::new(config, cache);

        // Test that seeding service is created successfully
        assert_eq!(service.metrics().sessions_started, 0);
        assert_eq!(service.authorized_manifests().len(), 0);
    }

    #[test]
    fn seeding_disabled_by_default() {
        let config = SeedingConfig::default();
        assert!(!config.enabled); // Should be disabled by default for security
        assert!(config.require_explicit_grants); // Should require grants by default
    }

    #[test]
    fn cache_config_defaults() {
        let config = CacheConfig::default();
        assert_eq!(config.max_size_bytes, 1_073_741_824); // 1 GiB
        assert_eq!(config.max_entries, 10_000);
        assert_eq!(config.default_ttl, Duration::from_secs(24 * 60 * 60)); // 24 hours
        assert!(!config.allow_plaintext_shared); // Should be secure by default
    }
}
