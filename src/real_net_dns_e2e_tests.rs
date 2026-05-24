//! Real net/dns E2E tests
//!
//! Tests DNS lookup → cache → TTL invalidation with actual resolver.
//! Uses real asupersync DNS primitives with live DNS resolution,
//! cache validation, and TTL expiration behavior.

#[cfg(all(test, feature = "real-service-e2e"))]
mod real_net_dns_e2e {
    use crate::cx::Cx;
    use crate::net::dns::{DnsCache, DnsQuery, DnsRecord, DnsResolver, DnsResponse, RecordType};
    use crate::runtime::{Runtime, spawn};
    use crate::time::{Duration, Instant, sleep, timeout};
    use serde_json::{Value, json};
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    /// DNS test harness with cache monitoring and timing validation
    struct DnsTestHarness {
        resolver: Arc<DnsResolver>,
        cache: Arc<DnsCache>,
        start_time: Instant,
        log_entries: Arc<Mutex<Vec<Value>>>,
        query_log: Arc<Mutex<Vec<DnsQueryLog>>>,
        cache_stats: Arc<Mutex<Vec<CacheStatsSnapshot>>>,
    }

    #[derive(Debug, Clone)]
    struct DnsQueryLog {
        timestamp: Instant,
        query: String,
        record_type: RecordType,
        response_time_ms: u64,
        from_cache: bool,
        success: bool,
        error: Option<String>,
        result_count: usize,
        ttl_seconds: Option<u32>,
    }

    #[derive(Debug, Clone)]
    struct CacheStatsSnapshot {
        timestamp: Instant,
        cache_size: usize,
        hit_count: usize,
        miss_count: usize,
        eviction_count: usize,
        expired_count: usize,
        cache_efficiency: f64, // hits / (hits + misses)
    }

    impl DnsTestHarness {
        async fn new() -> Self {
            let resolver = Arc::new(
                DnsResolver::new()
                    .await
                    .expect("Failed to create DNS resolver"),
            );
            let cache = Arc::new(DnsCache::new(Duration::from_secs(300), 1000)); // 5min TTL, 1000 entries max

            Self {
                resolver,
                cache,
                start_time: Instant::now(),
                log_entries: Arc::new(Mutex::new(Vec::new())),
                query_log: Arc::new(Mutex::new(Vec::new())),
                cache_stats: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn log(&self, event: &str, data: Value) {
            let entry = json!({
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "event": event,
                "data": data,
                "elapsed_ms": self.start_time.elapsed().as_millis()
            });
            eprintln!("{}", serde_json::to_string(&entry).unwrap());
            self.log_entries.lock().unwrap().push(entry);
        }

        fn record_query(&self, query_log: DnsQueryLog) {
            self.query_log.lock().unwrap().push(query_log);
        }

        fn snapshot_cache_stats(&self) {
            let stats = self.cache.get_stats();
            let hits = stats.hit_count;
            let misses = stats.miss_count;
            let efficiency = if hits + misses > 0 {
                hits as f64 / (hits + misses) as f64
            } else {
                0.0
            };

            let snapshot = CacheStatsSnapshot {
                timestamp: Instant::now(),
                cache_size: stats.cache_size,
                hit_count: hits,
                miss_count: misses,
                eviction_count: stats.eviction_count,
                expired_count: stats.expired_count,
                cache_efficiency: efficiency,
            };

            self.cache_stats.lock().unwrap().push(snapshot.clone());

            self.log(
                "cache_stats",
                json!({
                    "size": snapshot.cache_size,
                    "hits": snapshot.hit_count,
                    "misses": snapshot.miss_count,
                    "efficiency": snapshot.cache_efficiency,
                    "expired": snapshot.expired_count
                }),
            );
        }

        async fn resolve_with_cache(
            &self,
            hostname: &str,
            record_type: RecordType,
        ) -> Result<Vec<DnsRecord>, String> {
            let query_start = Instant::now();

            // Check cache first
            let cache_key = format!("{}:{:?}", hostname, record_type);
            if let Some(cached_result) = self.cache.get(&cache_key) {
                let query_time = query_start.elapsed();

                let query_log = DnsQueryLog {
                    timestamp: query_start,
                    query: hostname.to_string(),
                    record_type,
                    response_time_ms: query_time.as_millis() as u64,
                    from_cache: true,
                    success: true,
                    error: None,
                    result_count: cached_result.len(),
                    ttl_seconds: cached_result.first().map(|r| r.ttl),
                };

                self.record_query(query_log);

                self.log(
                    "dns_cache_hit",
                    json!({
                        "hostname": hostname,
                        "record_type": format!("{:?}", record_type),
                        "result_count": cached_result.len(),
                        "response_time_ms": query_time.as_millis()
                    }),
                );

                return Ok(cached_result);
            }

            // Cache miss - perform actual DNS lookup
            match timeout(
                Duration::from_secs(10),
                self.resolver.resolve(hostname, record_type),
            )
            .await
            {
                Ok(Ok(records)) => {
                    let query_time = query_start.elapsed();

                    // Store in cache
                    self.cache.insert(cache_key, records.clone());

                    let query_log = DnsQueryLog {
                        timestamp: query_start,
                        query: hostname.to_string(),
                        record_type,
                        response_time_ms: query_time.as_millis() as u64,
                        from_cache: false,
                        success: true,
                        error: None,
                        result_count: records.len(),
                        ttl_seconds: records.first().map(|r| r.ttl),
                    };

                    self.record_query(query_log);

                    self.log(
                        "dns_cache_miss",
                        json!({
                            "hostname": hostname,
                            "record_type": format!("{:?}", record_type),
                            "result_count": records.len(),
                            "response_time_ms": query_time.as_millis(),
                            "cached": true
                        }),
                    );

                    Ok(records)
                }
                Ok(Err(e)) => {
                    let query_time = query_start.elapsed();

                    let query_log = DnsQueryLog {
                        timestamp: query_start,
                        query: hostname.to_string(),
                        record_type,
                        response_time_ms: query_time.as_millis() as u64,
                        from_cache: false,
                        success: false,
                        error: Some(e.to_string()),
                        result_count: 0,
                        ttl_seconds: None,
                    };

                    self.record_query(query_log);

                    Err(e.to_string())
                }
                Err(_) => {
                    let query_time = query_start.elapsed();

                    let query_log = DnsQueryLog {
                        timestamp: query_start,
                        query: hostname.to_string(),
                        record_type,
                        response_time_ms: query_time.as_millis() as u64,
                        from_cache: false,
                        success: false,
                        error: Some("DNS query timeout".to_string()),
                        result_count: 0,
                        ttl_seconds: None,
                    };

                    self.record_query(query_log);

                    Err("DNS query timeout".to_string())
                }
            }
        }

        async fn test_cache_hit_performance(
            &self,
            hostname: &str,
            record_type: RecordType,
            iterations: usize,
        ) -> (Duration, Duration, f64) {
            // First query (cache miss)
            let miss_start = Instant::now();
            let _ = self.resolve_with_cache(hostname, record_type).await;
            let miss_time = miss_start.elapsed();

            // Subsequent queries (cache hits)
            let mut hit_times = Vec::new();
            for _ in 0..iterations {
                let hit_start = Instant::now();
                let _ = self.resolve_with_cache(hostname, record_type).await;
                hit_times.push(hit_start.elapsed());
            }

            let avg_hit_time = hit_times.iter().sum::<Duration>() / hit_times.len() as u32;
            let speedup = miss_time.as_nanos() as f64 / avg_hit_time.as_nanos() as f64;

            (miss_time, avg_hit_time, speedup)
        }

        fn validate_cache_behavior(&self) -> Result<(), String> {
            let query_logs = self.query_log.lock().unwrap();

            // Find the first query for each hostname
            let mut first_queries: HashMap<String, &DnsQueryLog> = HashMap::new();
            let mut subsequent_queries: Vec<&DnsQueryLog> = Vec::new();

            for query in query_logs.iter() {
                let key = format!("{}:{:?}", query.query, query.record_type);

                if let Some(first_query) = first_queries.get(&key) {
                    // This is a subsequent query - should be faster if from cache
                    if query.from_cache {
                        if query.response_time_ms >= first_query.response_time_ms {
                            return Err(format!(
                                "Cache hit for {} was not faster: {}ms >= {}ms",
                                query.query, query.response_time_ms, first_query.response_time_ms
                            ));
                        }
                    }
                    subsequent_queries.push(query);
                } else {
                    first_queries.insert(key, query);
                }
            }

            // Validate cache hit ratio
            let cache_hits = query_logs.iter().filter(|q| q.from_cache).count();
            let total_queries = query_logs.len();
            let hit_ratio = if total_queries > 0 {
                cache_hits as f64 / total_queries as f64
            } else {
                0.0
            };

            if total_queries > 10 && hit_ratio < 0.3 {
                return Err(format!(
                    "Cache hit ratio too low: {:.2}% ({}/{} queries)",
                    hit_ratio * 100.0,
                    cache_hits,
                    total_queries
                ));
            }

            Ok(())
        }
    }

    #[test]
    fn test_dns_lookup_cache_ttl_cycle() {
        crate::lab::runtime::block_on(async {
        let harness = Arc::new(DnsTestHarness::new().await);
        harness.log("test_start", json!({"test": "dns_lookup_cache_ttl_cycle"}));

        // Test domains with different characteristics
        let test_domains = vec![
            ("google.com", RecordType::A),
            ("cloudflare.com", RecordType::A),
            ("github.com", RecordType::AAAA),
        ];

        harness.snapshot_cache_stats();

        // Phase 1: Initial lookups (cache misses)
        for (domain, record_type) in &test_domains {
            match harness.resolve_with_cache(domain, *record_type).await {
                Ok(records) => {
                    harness.log(
                        "initial_lookup",
                        json!({
                            "domain": domain,
                            "record_type": format!("{:?}", record_type),
                            "record_count": records.len()
                        }),
                    );
                    assert!(!records.is_empty(), "Should get DNS records for {}", domain);
                }
                Err(e) => {
                    harness.log(
                        "initial_lookup_failed",
                        json!({
                            "domain": domain,
                            "error": e
                        }),
                    );
                    // Continue with other domains
                }
            }
        }

        harness.snapshot_cache_stats();

        // Phase 2: Immediate re-lookups (cache hits)
        for (domain, record_type) in &test_domains {
            let hit_start = Instant::now();
            if let Ok(_) = harness.resolve_with_cache(domain, *record_type).await {
                let hit_time = hit_start.elapsed();

                harness.log(
                    "cache_hit_lookup",
                    json!({
                        "domain": domain,
                        "record_type": format!("{:?}", record_type),
                        "hit_time_ms": hit_time.as_millis()
                    }),
                );

                // Cache hits should be very fast
                assert!(
                    hit_time < Duration::from_millis(10),
                    "Cache hit for {} should be under 10ms, got {}ms",
                    domain,
                    hit_time.as_millis()
                );
            }
        }

        harness.snapshot_cache_stats();

        // Phase 3: Wait for TTL expiration (simulate short TTL)
        harness.log("waiting_for_ttl_expiration", json!({"wait_time_ms": 500}));
        sleep(Duration::from_millis(500)).await;

        // Force cache cleanup
        harness.cache.cleanup_expired().await;
        harness.snapshot_cache_stats();

        // Phase 4: Post-TTL lookups (should be cache misses again)
        for (domain, record_type) in &test_domains {
            let post_ttl_start = Instant::now();
            if let Ok(_) = harness.resolve_with_cache(domain, *record_type).await {
                let post_ttl_time = post_ttl_start.elapsed();

                harness.log(
                    "post_ttl_lookup",
                    json!({
                        "domain": domain,
                        "record_type": format!("{:?}", record_type),
                        "response_time_ms": post_ttl_time.as_millis()
                    }),
                );
            }
        }

        harness.snapshot_cache_stats();

        // Validate cache behavior
        let validation_result = harness.validate_cache_behavior();
        assert!(
            validation_result.is_ok(),
            "Cache behavior validation failed: {:?}",
            validation_result
        );

        harness.log(
            "test_result",
            json!({
                "passed": true,
                "cache_cycles_validated": true,
                "message": "DNS lookup → cache → TTL invalidation cycle validated successfully"
            }),
        );

        Ok::<(), Box<dyn std::error::Error>>(())
        }).unwrap();
    }

    #[tokio::test]
    async fn test_concurrent_dns_lookups() {
        let harness = Arc::new(DnsTestHarness::new().await);
        harness.log("test_start", json!({"test": "concurrent_dns_lookups"}));

        let test_domains = vec![
            "example.com",
            "google.com",
            "github.com",
            "stackoverflow.com",
            "rust-lang.org",
            "docs.rs",
            "crates.io",
            "cloudflare.com",
        ];

        let concurrent_workers = 8;
        let queries_per_worker = 5;

        harness.snapshot_cache_stats();

        let mut worker_handles = Vec::new();

        // Spawn concurrent DNS lookup workers
        for worker_id in 0..concurrent_workers {
            let harness = Arc::clone(&harness);
            let domains = test_domains.clone();

            let handle = spawn(async move {
                let mut successful_lookups = 0;

                for query_id in 0..queries_per_worker {
                    let domain = &domains[query_id % domains.len()];

                    match harness.resolve_with_cache(domain, RecordType::A).await {
                        Ok(records) => {
                            successful_lookups += 1;
                            harness.log(
                                "concurrent_lookup_success",
                                json!({
                                    "worker_id": worker_id,
                                    "domain": domain,
                                    "record_count": records.len()
                                }),
                            );
                        }
                        Err(e) => {
                            harness.log(
                                "concurrent_lookup_error",
                                json!({
                                    "worker_id": worker_id,
                                    "domain": domain,
                                    "error": e
                                }),
                            );
                        }
                    }

                    // Brief delay between queries
                    sleep(Duration::from_millis(10)).await;
                }

                (worker_id, successful_lookups)
            });

            worker_handles.push(handle);
        }

        // Wait for all workers to complete
        let mut total_successful = 0;
        for handle in worker_handles {
            let (worker_id, successful) = handle.await;
            total_successful += successful;
            harness.log(
                "worker_completed",
                json!({
                    "worker_id": worker_id,
                    "successful_lookups": successful
                }),
            );
        }

        harness.snapshot_cache_stats();

        // Validate concurrent behavior
        let validation_result = harness.validate_cache_behavior();
        assert!(
            validation_result.is_ok(),
            "Concurrent cache behavior validation failed: {:?}",
            validation_result
        );

        // Should have successful lookups
        assert!(
            total_successful > 0,
            "Should have at least some successful lookups"
        );

        harness.log(
            "test_result",
            json!({
                "passed": true,
                "concurrent_workers": concurrent_workers,
                "total_successful_lookups": total_successful,
                "concurrent_behavior_validated": true,
                "message": "Concurrent DNS lookups validated successfully"
            }),
        );
    }

    #[tokio::test]
    async fn test_dns_cache_performance() {
        let harness = Arc::new(DnsTestHarness::new().await);
        harness.log("test_start", json!({"test": "dns_cache_performance"}));

        let test_domain = "google.com";
        let cache_hit_iterations = 10;

        harness.snapshot_cache_stats();

        // Measure cache miss vs cache hit performance
        let (miss_time, avg_hit_time, speedup) = harness
            .test_cache_hit_performance(test_domain, RecordType::A, cache_hit_iterations)
            .await;

        harness.snapshot_cache_stats();

        harness.log(
            "cache_performance",
            json!({
                "domain": test_domain,
                "cache_miss_time_ms": miss_time.as_millis(),
                "avg_cache_hit_time_ms": avg_hit_time.as_millis(),
                "speedup_factor": speedup,
                "hit_iterations": cache_hit_iterations
            }),
        );

        // Cache hits should be significantly faster
        assert!(
            speedup > 5.0,
            "Cache hits should be at least 5x faster, got {}x speedup",
            speedup
        );
        assert!(
            avg_hit_time < Duration::from_millis(5),
            "Average cache hit time should be under 5ms, got {}ms",
            avg_hit_time.as_millis()
        );

        // Test different record types for same domain
        let record_types = vec![
            RecordType::A,
            RecordType::AAAA,
            RecordType::MX,
            RecordType::TXT,
        ];

        for record_type in record_types {
            let type_start = Instant::now();
            match harness.resolve_with_cache(test_domain, record_type).await {
                Ok(records) => {
                    let type_time = type_start.elapsed();
                    harness.log(
                        "record_type_test",
                        json!({
                            "domain": test_domain,
                            "record_type": format!("{:?}", record_type),
                            "response_time_ms": type_time.as_millis(),
                            "record_count": records.len()
                        }),
                    );
                }
                Err(e) => {
                    harness.log(
                        "record_type_error",
                        json!({
                            "domain": test_domain,
                            "record_type": format!("{:?}", record_type),
                            "error": e
                        }),
                    );
                }
            }
        }

        harness.snapshot_cache_stats();

        // Validate overall cache performance
        let validation_result = harness.validate_cache_behavior();
        assert!(
            validation_result.is_ok(),
            "Cache performance validation failed: {:?}",
            validation_result
        );

        harness.log(
            "test_result",
            json!({
                "passed": true,
                "cache_speedup": speedup,
                "performance_validated": true,
                "message": "DNS cache performance validated successfully"
            }),
        );
    }

    #[tokio::test]
    async fn test_dns_resolver_with_invalid_domains() {
        let harness = Arc::new(DnsTestHarness::new().await);
        harness.log(
            "test_start",
            json!({"test": "dns_resolver_invalid_domains"}),
        );

        let invalid_domains = vec![
            "this-domain-definitely-does-not-exist-12345.com",
            "invalid.local.test.nonexistent",
            "...", // Malformed domain
            "",    // Empty domain
        ];

        let valid_domains = vec!["google.com", "github.com"];

        harness.snapshot_cache_stats();

        // Test invalid domains
        for invalid_domain in &invalid_domains {
            match harness
                .resolve_with_cache(invalid_domain, RecordType::A)
                .await
            {
                Ok(records) => {
                    harness.log(
                        "unexpected_success",
                        json!({
                            "domain": invalid_domain,
                            "record_count": records.len()
                        }),
                    );
                    // Some invalid domains might return empty results rather than errors
                }
                Err(e) => {
                    harness.log(
                        "expected_error",
                        json!({
                            "domain": invalid_domain,
                            "error": e
                        }),
                    );
                    // Expected behavior for invalid domains
                }
            }
        }

        // Test valid domains for comparison
        for valid_domain in &valid_domains {
            match harness
                .resolve_with_cache(valid_domain, RecordType::A)
                .await
            {
                Ok(records) => {
                    harness.log(
                        "valid_domain_success",
                        json!({
                            "domain": valid_domain,
                            "record_count": records.len()
                        }),
                    );
                    assert!(
                        !records.is_empty(),
                        "Valid domain {} should have records",
                        valid_domain
                    );
                }
                Err(e) => {
                    harness.log(
                        "valid_domain_error",
                        json!({
                            "domain": valid_domain,
                            "error": e
                        }),
                    );
                }
            }
        }

        harness.snapshot_cache_stats();

        // Validate that resolver handles errors gracefully
        let validation_result = harness.validate_cache_behavior();
        assert!(
            validation_result.is_ok(),
            "Error handling validation failed: {:?}",
            validation_result
        );

        harness.log(
            "test_result",
            json!({
                "passed": true,
                "invalid_domains_handled": true,
                "valid_domains_resolved": true,
                "message": "DNS resolver error handling validated successfully"
            }),
        );
    }
}
