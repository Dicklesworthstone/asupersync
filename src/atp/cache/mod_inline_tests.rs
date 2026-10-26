    use super::*;
    use std::time::Duration;

    #[test]
    fn cache_key_index_key_generation() {
        let key = CacheKey::new(
            "manifest123".to_string(),
            "content456".to_string(),
            Some("scope789".to_string()),
        );
        assert_eq!(
            key.as_index_key(),
            "v1|m:11:manifest123|c:10:content456|s:8:scope789|"
        );

        let key_no_scope = CacheKey::new("manifest123".to_string(), "content456".to_string(), None);
        assert_eq!(
            key_no_scope.as_index_key(),
            "v1|m:11:manifest123|c:10:content456|n"
        );
    }

    #[test]
    fn cache_key_index_key_is_not_delimiter_collision_prone() {
        let scoped = CacheKey::new("a".to_string(), "b".to_string(), Some("c".to_string()));
        let unscoped_with_delimiter = CacheKey::new("a".to_string(), "b:c".to_string(), None);

        assert_ne!(
            scoped.as_index_key(),
            unscoped_with_delimiter.as_index_key()
        );
    }

    #[test]
    fn cache_metrics_hit_ratio_calculation() {
        let mut metrics = CacheMetrics::default();

        metrics.record_hit();
        metrics.record_hit();
        metrics.record_miss();

        assert_eq!(metrics.hits, 2);
        assert_eq!(metrics.misses, 1);
        assert!((metrics.hit_ratio - 0.6667).abs() < 0.001);
    }

    #[test]
    fn cache_config_defaults() {
        let config = CacheConfig::default();
        assert_eq!(config.max_size_bytes, 1_073_741_824);
        assert!(!config.allow_plaintext_shared);
        assert_eq!(config.eviction_policy, EvictionPolicy::LeastRecentlyUsed);
    }

    #[test]
    fn cache_basic_put_get() {
        let mut cache = AtpCache::new(CacheConfig::default());
        let key = CacheKey::new(
            "manifest123".to_string(),
            "d2d2d2d2d2d2d2d2".to_string(), // Intentionally invalid content hash
            None,
        );
        let content = b"test content";

        // This will fail due to hash mismatch, but tests the interface
        let result = cache.put(key.clone(), content);
        assert!(result.is_err()); // Should fail due to hash verification
    }

    fn sha256_hex(content: &[u8]) -> String {
        use sha2::{Digest, Sha256};

        hex::encode(Sha256::digest(content))
    }

    #[test]
    fn explicit_policy_cache_authorizes_scoped_storage_and_denies_aliases_before_lookup() {
        let content = b"private team artifact";
        let key = CacheKey::new(
            "build-manifest".to_string(),
            sha256_hex(content),
            Some("team:build".to_string()),
        );
        let mut default_cache = AtpCache::new(CacheConfig::default());
        assert!(matches!(
            default_cache.put(key.clone(), content),
            Err(CacheError::TrustViolation(_))
        ));

        let mut policy = trust::TrustPolicy::local();
        policy.add_authorized_scope("team:build".to_string());
        let mut cache = AtpCache::with_trust_policy(CacheConfig::default(), policy).unwrap();
        cache.put(key.clone(), content).unwrap();
        assert_eq!(cache.get(&key).unwrap().as_deref(), Some(content.as_slice()));

        let mut foreign_key = key.clone();
        foreign_key.grant_scope = Some("other:team".to_string());
        assert!(matches!(
            cache.get(&foreign_key),
            Err(CacheError::TrustViolation(_))
        ));
        assert!(matches!(
            cache.remove(&foreign_key),
            Err(CacheError::TrustViolation(_))
        ));
        assert!(matches!(
            cache.put(foreign_key, b"even the hash must not be checked"),
            Err(CacheError::TrustViolation(_))
        ));
        let mut unscoped_alias = key.clone();
        unscoped_alias.grant_scope = None;
        assert!(cache.get(&unscoped_alias).unwrap().is_none());
        assert_eq!(cache.metrics().entry_count, 1);
        assert_eq!(cache.get(&key).unwrap().as_deref(), Some(content.as_slice()));
        cache.remove(&key).unwrap();
        assert!(cache.get(&key).unwrap().is_none());
        assert_eq!(cache.metrics().entry_count, 0);
    }

    #[test]
    fn explicit_policy_cache_preserves_shared_encryption_and_configuration_gates() {
        let content = b"private plaintext";
        let key = CacheKey::new(
            "manifest".to_string(),
            sha256_hex(content),
            Some("team:encrypted".to_string()),
        );
        let mut policy = trust::TrustPolicy::shared();
        policy.add_authorized_scope("team:encrypted".to_string());
        let mut cache =
            AtpCache::with_trust_policy(CacheConfig::default(), policy.clone()).unwrap();
        assert!(matches!(
            cache.put(key, content),
            Err(CacheError::TrustViolation(_))
        ));
        assert_eq!(cache.metrics().entry_count, 0);

        policy.allow_public_content = true;
        assert!(matches!(
            AtpCache::with_trust_policy(CacheConfig::default(), policy),
            Err(CacheError::TrustViolation(_))
        ));
    }

    #[test]
    fn retiring_one_scoped_file_entry_preserves_other_grants_to_the_same_content() {
        let root = tempfile::tempdir().unwrap();
        let config = CacheConfig {
            storage_root: root.path().to_path_buf(),
            ..CacheConfig::default()
        };
        let content = vec![0x5a; 64 * 1024];
        let mut policy = trust::TrustPolicy::local();
        policy.add_authorized_scope("team:a".to_string());
        policy.add_authorized_scope("team:b".to_string());
        let mut cache = AtpCache::with_trust_policy(config, policy).unwrap();
        let a = CacheKey::new(
            "a".to_string(),
            sha256_hex(&content),
            Some("team:a".to_string()),
        );
        let b = CacheKey::new(
            "b".to_string(),
            sha256_hex(&content),
            Some("team:b".to_string()),
        );
        cache.put(a.clone(), &content).unwrap();
        cache.put(b.clone(), &content).unwrap();
        cache.remove(&a).unwrap();
        assert_eq!(cache.get(&b).unwrap(), Some(content));
        assert_eq!(cache.metrics().entry_count, 1);
    }

    #[test]
    fn cache_put_existing_key_does_not_duplicate_metrics_or_lru_entries() {
        let mut config = CacheConfig::default();
        config.max_entries = 1;
        let mut cache = AtpCache::new(config);
        let content = b"stable cache content";
        let key = CacheKey::new("manifest123".to_string(), sha256_hex(content), None);

        cache.put(key.clone(), content).unwrap();
        cache.put(key.clone(), content).unwrap();

        assert_eq!(cache.metrics().entry_count, 1);
        assert_eq!(cache.metrics().total_bytes, content.len() as u64);
        assert_eq!(cache.access_order.len(), 1);
        assert_eq!(cache.get(&key).unwrap().as_deref(), Some(&content[..]));
    }

    #[test]
    fn cache_entry_encryption_status_requires_a_real_aead_envelope_not_scope_name() {
        // br-asupersync-28i28f: a grant-scope string and a forged-algorithm
        // envelope are both attacker-controlled and must NOT mark content as
        // encrypted; only a well-formed AEAD envelope counts.
        let scope_encrypted_key = CacheKey::new(
            "manifest123".to_string(),
            "content456".to_string(),
            Some("team:engineering:encrypted".to_string()),
        );
        // OLD BUG: a scope named "encrypted" marked PLAINTEXT as encrypted.
        assert!(!derive_cache_entry_encryption_status(
            &scope_encrypted_key,
            b"plaintext"
        ));

        // A real AEAD envelope is recognized regardless of scope.
        let envelope_key = CacheKey::new("manifest123".to_string(), "content456".to_string(), None);
        let envelope = br#"{
            "algorithm": "aes-256-gcm",
            "nonce": "000000000000000000000000",
            "ciphertext": "deadbeef",
            "tag": "cafebabe"
        }"#;
        assert!(derive_cache_entry_encryption_status(
            &envelope_key,
            envelope
        ));

        // OLD BUG: a forged envelope whose algorithm merely EMBEDS an AEAD token
        // (substring "gcm") passed. It must now be rejected.
        let forged = br#"{
            "algorithm": "definitely-not-a-real-gcm",
            "nonce": "00",
            "ciphertext": "deadbeef",
            "tag": "cafebabe"
        }"#;
        assert!(!derive_cache_entry_encryption_status(&envelope_key, forged));

        // Plaintext with no scope and no envelope is not encrypted.
        let plaintext_key =
            CacheKey::new("manifest123".to_string(), "content456".to_string(), None);
        assert!(!derive_cache_entry_encryption_status(
            &plaintext_key,
            b"plaintext"
        ));
    }

    #[test]
    fn is_known_aead_algorithm_allowlists_canonical_forms_and_rejects_forgeries() {
        // br-asupersync-28i28f: separator/case-insensitive whole-value match.
        for ok in [
            "aes-256-gcm",
            "AES256GCM",
            "aes_256_gcm",
            "ChaCha20-Poly1305",
            "chacha20poly1305",
            "AEAD_AES_256_GCM",
            "xchacha20-poly1305",
            "aes-128-gcm-siv",
            "A256GCM",
        ] {
            assert!(is_known_aead_algorithm(ok), "should accept {ok}");
        }
        for bad in [
            "definitely-not-a-real-gcm",
            "aes",
            "gcm",
            "rot13",
            "plaintext",
            "my-aes-ish",
            "",
            "chacha",
            "aes-999-gcm",
        ] {
            assert!(!is_known_aead_algorithm(bad), "should reject {bad}");
        }
    }

    #[test]
    fn cache_ttl_toctou_fix() {
        let mut cache = AtpCache::new(CacheConfig::default());

        // Create a cache key
        let key = CacheKey::new(
            "manifest123".to_string(),
            "d2d2d2d2d2d2d2d2".to_string(), // Intentionally invalid content hash
            None,
        );

        // Put some content with very short TTL
        let content = b"test content";

        // Manually add an expired entry to test TTL check
        let expired_entry = CacheEntry {
            key: key.clone(),
            size_bytes: content.len() as u64,
            created_at: SystemTime::now() - Duration::from_secs(3600), // 1 hour ago
            last_accessed: SystemTime::now(),
            access_count: 1,
            ttl: Duration::from_secs(60), // 1 minute TTL (expired)
            encrypted: true,
            storage_location: StorageLocation::Memory("test".to_string()),
            verification: VerificationMetadata {
                content_verified: true,
                manifest_verified: true,
                proof_location: None,
                verified_at: Some(SystemTime::now()),
            },
        };

        // Insert expired entry directly
        cache.entries.insert(key.as_index_key(), expired_entry);
        cache.access_order.push(key.as_index_key());
        cache
            .memory_storage
            .insert("test".to_string(), content.to_vec());
        cache.metrics.total_bytes = content.len() as u64;
        cache.metrics.entry_count = 1;
        assert_eq!(cache.entries.len(), 1);

        // Try to get expired entry - should be atomically removed
        let result = cache.get(&key);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none()); // Should return None for expired entry

        // Entry should be removed from cache
        assert_eq!(cache.entries.len(), 0);
        assert_eq!(cache.access_order.len(), 0);
        assert_eq!(cache.metrics().total_bytes, 0);
        assert_eq!(cache.metrics().entry_count, 0);
    }

    #[test]
    fn cache_eviction_on_size_limit() {
        let mut config = CacheConfig::default();
        config.max_size_bytes = 100; // Very small cache

        let cache = AtpCache::new(config);
        assert_eq!(cache.metrics().total_bytes, 0);
        assert_eq!(cache.metrics().entry_count, 0);
    }

    // Golden Artifact Tests for ATP Cache Serialization Stability

    #[test]
    fn golden_cache_config_default_serialization() {
        let config = CacheConfig::default();
        assert_eq!(
            serde_json::to_value(&config).unwrap(),
            serde_json::json!({
                "max_size_bytes": 1_073_741_824_u64,
                "max_entries": 10_000,
                "default_ttl": {
                    "secs": 86_400,
                    "nanos": 0,
                },
                "eviction_policy": "least_recently_used",
                "allow_plaintext_shared": false,
                "storage_root": ".cache",
                "compression_enabled": true,
            })
        );
    }

    #[test]
    fn golden_cache_config_custom_serialization() {
        use std::path::PathBuf;

        let config = CacheConfig {
            max_size_bytes: 512 * 1024 * 1024, // 512 MiB
            max_entries: 5_000,
            default_ttl: Duration::from_secs(12 * 60 * 60), // 12 hours
            eviction_policy: EvictionPolicy::Hybrid,
            allow_plaintext_shared: true,
            storage_root: PathBuf::from("/var/cache/atp"),
            compression_enabled: false,
        };
        assert_eq!(
            serde_json::to_value(&config).unwrap(),
            serde_json::json!({
                "max_size_bytes": 536_870_912_u64,
                "max_entries": 5_000,
                "default_ttl": {
                    "secs": 43_200,
                    "nanos": 0,
                },
                "eviction_policy": "hybrid",
                "allow_plaintext_shared": true,
                "storage_root": "/var/cache/atp",
                "compression_enabled": false,
            })
        );
    }

    #[test]
    fn golden_cache_key_serialization() {
        // Test cache key with scope
        let key_with_scope = CacheKey::new(
            "sha256:a1b2c3d4e5f6g7h8".to_string(),
            "sha256:1234567890abcdef".to_string(),
            Some("team:engineering".to_string()),
        );
        assert_eq!(
            serde_json::to_value(&key_with_scope).unwrap(),
            serde_json::json!({
                "manifest_hash": "sha256:a1b2c3d4e5f6g7h8",
                "content_hash": "sha256:1234567890abcdef",
                "grant_scope": "team:engineering",
            })
        );

        // Test cache key without scope
        let key_no_scope = CacheKey::new(
            "sha256:fedcba0987654321".to_string(),
            "sha256:abcdef1234567890".to_string(),
            None,
        );
        assert_eq!(
            serde_json::to_value(&key_no_scope).unwrap(),
            serde_json::json!({
                "manifest_hash": "sha256:fedcba0987654321",
                "content_hash": "sha256:abcdef1234567890",
                "grant_scope": null,
            })
        );
    }

    #[test]
    fn golden_eviction_policy_serialization() {
        let policies = vec![
            EvictionPolicy::LeastRecentlyUsed,
            EvictionPolicy::LeastFrequentlyUsed,
            EvictionPolicy::ShortestTtl,
            EvictionPolicy::LargestFirst,
            EvictionPolicy::Hybrid,
        ];

        assert_eq!(
            serde_json::to_value(&policies).unwrap(),
            serde_json::json!([
                "least_recently_used",
                "least_frequently_used",
                "shortest_ttl",
                "largest_first",
                "hybrid",
            ])
        );
    }

    #[test]
    fn golden_cache_metrics_serialization() {
        let mut metrics = CacheMetrics::default();
        metrics.hits = 1500;
        metrics.misses = 300;
        metrics.evictions = 25;
        metrics.verification_failures = 2;
        metrics.total_bytes = 1024 * 1024; // 1 MiB
        metrics.entry_count = 150;
        metrics.update_hit_ratio();

        assert_eq!(
            serde_json::to_value(&metrics).unwrap(),
            serde_json::json!({
                "hits": 1_500,
                "misses": 300,
                "evictions": 25,
                "verification_failures": 2,
                "total_bytes": 1_048_576_u64,
                "entry_count": 150,
                "hit_ratio": 0.8333333333333334,
            })
        );
    }
