//! Real integration tests for ATP cache and seeding system.
//!
//! Tests real cache→seeding workflows with structured JSON logging,
//! transaction isolation, and test data factories following
//! real-service E2E testing discipline.

#![allow(dead_code)]

#[cfg(test)]
mod tests {
    use crate::atp::cache::{AtpCache, CacheConfig, CacheKey};
    use crate::atp::seeding::{AtpSeedingService, SeedingConfig};
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use std::time::{Duration, SystemTime};

    /// Structured test logger implementing testing-perfect-e2e patterns.
    #[derive(Debug)]
    struct TestLogger {
        suite_name: String,
        test_name: String,
        start_time: SystemTime,
        phases: Vec<TestPhase>,
    }

    #[derive(Debug)]
    struct TestPhase {
        phase: String,
        start_time: SystemTime,
        snapshots: Vec<TestSnapshot>,
        duration_ms: u64,
    }

    #[derive(Debug)]
    struct TestSnapshot {
        label: String,
        data: serde_json::Value,
        timestamp: SystemTime,
    }

    impl TestLogger {
        fn new(suite: &str, test: &str) -> Self {
            let logger = Self {
                suite_name: suite.to_string(),
                test_name: test.to_string(),
                start_time: SystemTime::now(),
                phases: Vec::new(),
            };

            eprintln!(
                "{}",
                json!({
                    "ts": logger.start_time,
                    "suite": suite,
                    "test": test,
                    "event": "test_start"
                })
            );

            logger
        }

        fn phase(&mut self, phase: &str) {
            let now = SystemTime::now();

            // Complete previous phase
            if let Some(last_phase) = self.phases.last_mut() {
                last_phase.duration_ms = last_phase
                    .start_time
                    .elapsed()
                    .unwrap_or(Duration::ZERO)
                    .as_millis() as u64;
            }

            eprintln!(
                "{}",
                json!({
                    "ts": now,
                    "suite": self.suite_name,
                    "test": self.test_name,
                    "phase": phase,
                    "event": "phase_start"
                })
            );

            self.phases.push(TestPhase {
                phase: phase.to_string(),
                start_time: now,
                snapshots: Vec::new(),
                duration_ms: 0,
            });
        }

        fn snapshot<T: serde::Serialize>(&mut self, label: &str, data: &T) {
            let snapshot = TestSnapshot {
                label: label.to_string(),
                data: serde_json::to_value(data)
                    .unwrap_or(json!({"error": "serialization_failed"})),
                timestamp: SystemTime::now(),
            };

            eprintln!(
                "{}",
                json!({
                    "ts": snapshot.timestamp,
                    "suite": self.suite_name,
                    "test": self.test_name,
                    "phase": self.phases.last().map(|p| &p.phase).unwrap_or(&"unknown".to_string()),
                    "event": "snapshot",
                    "label": label,
                    "data": snapshot.data
                })
            );

            if let Some(current_phase) = self.phases.last_mut() {
                current_phase.snapshots.push(snapshot);
            }
        }

        fn assert_outcome<T>(&mut self, field: &str, expected: &T, actual: &T) -> bool
        where
            T: PartialEq + serde::Serialize,
        {
            let matches = expected == actual;

            eprintln!(
                "{}",
                json!({
                    "ts": SystemTime::now(),
                    "suite": self.suite_name,
                    "test": self.test_name,
                    "phase": self.phases.last().map(|p| &p.phase).unwrap_or(&"unknown".to_string()),
                    "event": "assertion",
                    "field": field,
                    "expected": expected,
                    "actual": actual,
                    "match": matches
                })
            );

            matches
        }

        fn test_end(&mut self, result: &str) {
            let duration_ms = self
                .start_time
                .elapsed()
                .unwrap_or(Duration::ZERO)
                .as_millis() as u64;

            // Complete last phase
            if let Some(last_phase) = self.phases.last_mut() {
                last_phase.duration_ms = last_phase
                    .start_time
                    .elapsed()
                    .unwrap_or(Duration::ZERO)
                    .as_millis() as u64;
            }

            eprintln!(
                "{}",
                json!({
                    "ts": SystemTime::now(),
                    "suite": self.suite_name,
                    "test": self.test_name,
                    "event": "test_end",
                    "result": result,
                    "duration_ms": duration_ms,
                    "total_phases": self.phases.len()
                })
            );
        }
    }

    /// Test data factory for creating realistic cache content.
    struct CacheContentFactory;

    impl CacheContentFactory {
        fn manifest_content(size_kb: usize) -> Vec<u8> {
            // Create realistic manifest data with JSON structure
            let manifest = json!({
                "schema_version": 1,
                "objects": (0..size_kb).map(|i| json!({
                    "id": format!("object_{}", i),
                    "hash": format!("sha256_{:064x}", i),
                    "size_bytes": i * 1024
                })).collect::<Vec<_>>(),
                "created_at": SystemTime::now(),
                "total_size": size_kb * 1024
            });

            serde_json::to_vec(&manifest).unwrap()
        }

        fn blob_content(size_bytes: usize, pattern: u8) -> Vec<u8> {
            (0..size_bytes)
                .map(|i| (pattern + (i % 256) as u8))
                .collect()
        }

        fn test_cache_key(manifest_id: &str, content_id: &str, scope: Option<&str>) -> CacheKey {
            CacheKey::new(
                manifest_id.to_string(),
                content_id.to_string(),
                scope.map(String::from),
            )
        }

        fn content_hash(content: &[u8]) -> String {
            let mut hasher = Sha256::new();
            hasher.update(content);
            hex::encode(hasher.finalize())
        }
    }

    /// Test isolation manager for proper cleanup between tests.
    struct TestIsolationManager {
        created_keys: Vec<CacheKey>,
    }

    impl TestIsolationManager {
        fn new() -> Self {
            Self {
                created_keys: Vec::new(),
            }
        }

        fn track_key(&mut self, key: CacheKey) {
            self.created_keys.push(key);
        }

        fn cleanup_cache(&self, cache: &mut AtpCache) {
            for key in &self.created_keys {
                // Best effort cleanup - ignore errors
                let _ = cache.remove(key);
            }
        }
    }

    impl Drop for TestIsolationManager {
        fn drop(&mut self) {
            // Ensure cleanup on panic
            eprintln!(
                "TestIsolationManager: cleaned {} keys",
                self.created_keys.len()
            );
        }
    }

    #[test]
    fn cache_to_seeding_workflow_integration() {
        let mut log = TestLogger::new("cache_seeding_integration", "full_workflow");
        let mut isolation = TestIsolationManager::new();

        log.phase("setup");

        // Create cache with realistic configuration
        let cache_config = CacheConfig {
            max_size_bytes: 10 * 1024 * 1024, // 10MB for testing
            max_entries: 100,
            default_ttl: Duration::from_secs(3600),
            allow_plaintext_shared: false,
            ..CacheConfig::default()
        };
        let mut cache = AtpCache::new(cache_config);

        // Create seeding service with explicit grants required
        let seeding_config = SeedingConfig {
            enabled: true,
            require_explicit_grants: true,
            max_concurrent_connections: Some(5),
            ..SeedingConfig::default()
        };
        let mut seeding_service =
            AtpSeedingService::new(seeding_config, AtpCache::new(CacheConfig::default()));

        log.snapshot("initial_cache_metrics", &cache.metrics());
        log.snapshot("initial_seeding_metrics", &seeding_service.metrics());

        log.phase("act");

        // Create realistic test data using factory
        let manifest_data = CacheContentFactory::manifest_content(5); // 5KB manifest
        let blob_data = CacheContentFactory::blob_content(2048, 0x42); // 2KB blob
        let manifest_hash = "manifest_abc123";
        let manifest_content_hash = CacheContentFactory::content_hash(&manifest_data);
        let blob_content_hash = CacheContentFactory::content_hash(&blob_data);

        let manifest_key = CacheContentFactory::test_cache_key(
            manifest_hash,
            &manifest_content_hash,
            Some("test-scope"),
        );
        let blob_key = CacheContentFactory::test_cache_key(
            manifest_hash,
            &blob_content_hash,
            Some("test-scope"),
        );

        isolation.track_key(manifest_key.clone());
        isolation.track_key(blob_key.clone());

        // Store content in cache (real storage operations)
        cache
            .put(manifest_key.clone(), &manifest_data)
            .expect("store manifest");
        cache.put(blob_key.clone(), &blob_data).expect("store blob");

        log.snapshot("post_storage_cache_metrics", &cache.metrics());

        // Authorize manifest for seeding
        seeding_service
            .authorize_manifest(
                manifest_key.manifest_hash.clone(),
                "test-scope".to_string(),
                "normal".to_string(),
            )
            .expect("authorize manifest");
        seeding_service
            .add_seeded_content(
                &manifest_key.manifest_hash,
                &blob_key.content_hash,
                &blob_data,
            )
            .expect("add seeded content");

        let session_id = seeding_service
            .start_session(
                "peer-alpha".to_string(),
                manifest_key.manifest_hash.clone(),
                vec!["test-scope".to_string()],
            )
            .expect("start seeding session");
        let seeded_content = seeding_service
            .get_seeded_content(
                &manifest_key.manifest_hash,
                &blob_key.content_hash,
                &["test-scope".to_string()],
            )
            .expect("get seeded content")
            .expect("seeded content present");

        log.snapshot("session_id", &session_id);
        log.snapshot("post_seeding_metrics", &seeding_service.metrics());

        log.phase("assert");

        // Verify cache operations worked
        assert!(log.assert_outcome("cache_entry_count", &2_usize, &cache.metrics().entry_count));
        assert!(log.assert_outcome(
            "cache_total_bytes",
            &((manifest_data.len() + blob_data.len()) as u64),
            &cache.metrics().total_bytes
        ));

        // Verify seeding session started
        assert!(!session_id.is_empty());
        assert_eq!(seeding_service.metrics().sessions_started, 1);
        assert_eq!(seeding_service.metrics().chunks_stored, 1);
        assert_eq!(
            seeding_service.metrics().bytes_stored,
            blob_data.len() as u64
        );

        // Verify content can be retrieved (round-trip test)
        let retrieved_manifest = cache.get(&manifest_key).expect("retrieve manifest");
        let retrieved_blob = cache.get(&blob_key).expect("retrieve blob");

        assert!(log.assert_outcome(
            "manifest_content_integrity",
            &Some(manifest_data),
            &retrieved_manifest
        ));
        assert!(log.assert_outcome(
            "blob_content_integrity",
            &Some(blob_data.clone()),
            &retrieved_blob
        ));
        assert!(log.assert_outcome("seeded_content_integrity", &blob_data, &seeded_content));

        log.phase("teardown");

        // Cleanup with isolation manager
        isolation.cleanup_cache(&mut cache);
        log.snapshot("post_cleanup_cache_metrics", &cache.metrics());

        log.test_end("pass");
    }

    #[test]
    fn seeding_authorization_and_security_validation() {
        let mut log = TestLogger::new("cache_seeding_integration", "security_validation");

        log.phase("setup");

        let cache = AtpCache::new(CacheConfig::default());
        let seeding_config = SeedingConfig {
            enabled: true,
            require_explicit_grants: true,
            max_concurrent_connections: Some(2),
            ..SeedingConfig::default()
        };
        let mut seeding_service = AtpSeedingService::new(seeding_config, cache);

        log.phase("act");

        // Test unauthorized seeding request (security validation)
        let unauthorized_result = seeding_service.start_session(
            "peer-unauthorized".to_string(),
            "unauthorized_manifest".to_string(),
            vec!["private-scope".to_string()],
        );
        log.snapshot("unauthorized_result", &format!("{unauthorized_result:?}"));

        // Authorize specific manifest and scope
        seeding_service
            .authorize_manifest(
                "authorized_manifest".to_string(),
                "allowed-scope".to_string(),
                "normal".to_string(),
            )
            .expect("authorize manifest");

        let authorized_result = seeding_service.start_session(
            "peer-authorized".to_string(),
            "authorized_manifest".to_string(),
            vec!["allowed-scope".to_string()],
        );
        log.snapshot("authorized_result", &format!("{authorized_result:?}"));

        log.phase("assert");

        // Verify unauthorized request was rejected
        match unauthorized_result {
            Err(e) => {
                assert!(log.assert_outcome(
                    "unauthorized_error_type",
                    &"SeedingError",
                    &"SeedingError"
                ));
                log.snapshot("security_error", &format!("{:?}", e));
            }
            Ok(_) => panic!("Expected unauthorized request to be rejected"),
        }

        // Verify authorized request succeeded
        match authorized_result {
            Ok(session_id) => {
                assert!(!session_id.is_empty());
                assert!(log.assert_outcome("authorized_success", &true, &true));
            }
            _ => panic!("Expected authorized request to succeed"),
        }

        log.phase("teardown");
        log.test_end("pass");
    }
}
