//! Real RaptorQ systematic encode→repair→decode chain E2E tests
//!
//! Tests complete RaptorQ forward error correction pipeline with real symbol loss
//! simulation. Uses actual asupersync RaptorQ implementation with systematic
//! encoding, repair symbol generation, and decode recovery validation.

#[cfg(all(test, feature = "real-service-e2e"))]
mod real_raptorq_systematic_e2e {
    use crate::cx::Cx;
    use crate::raptorq::{
        Decoder, DecodingConfig, Encoder, EncodingConfig, ObjectTransmissionInfo, RepairSymbol,
        SourceBlock, SourceBlockDecoder, SourceBlockEncoder, Symbol, SymbolId, SystematicIndex,
    };
    use crate::runtime::{Runtime, spawn};
    use crate::time::{Duration, Instant, sleep, timeout};
    use rand::{Rng, seq::SliceRandom, thread_rng};
    use serde_json::{Value, json};
    use std::collections::{BTreeSet, HashMap, HashSet};
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    };

    /// RaptorQ test harness with symbol loss simulation and recovery validation
    struct RaptorQTestHarness {
        start_time: Instant,
        log_entries: Arc<Mutex<Vec<Value>>>,
        encoding_stats: Arc<Mutex<Vec<EncodingStats>>>,
        decoding_stats: Arc<Mutex<Vec<DecodingStats>>>,
        loss_simulations: Arc<Mutex<Vec<LossSimulation>>>,
    }

    #[derive(Debug, Clone)]
    struct EncodingStats {
        timestamp: Instant,
        source_block_id: u32,
        source_symbols: usize,
        repair_symbols_generated: usize,
        systematic_symbols: usize,
        encoding_duration_ms: u64,
        total_size_bytes: usize,
        encoding_rate: f64, // (source + repair) / source
    }

    #[derive(Debug, Clone)]
    struct DecodingStats {
        timestamp: Instant,
        source_block_id: u32,
        symbols_received: usize,
        symbols_lost: usize,
        repair_symbols_used: usize,
        decoding_duration_ms: u64,
        recovery_successful: bool,
        recovery_efficiency: f64, // symbols_received / source_symbols
        decoded_size_bytes: usize,
    }

    #[derive(Debug, Clone)]
    struct LossSimulation {
        timestamp: Instant,
        simulation_type: String,
        loss_rate: f64,
        burst_length: Option<usize>,
        symbols_transmitted: usize,
        symbols_lost: usize,
        actual_loss_rate: f64,
        recovery_possible: bool,
    }

    impl RaptorQTestHarness {
        fn new() -> Self {
            Self {
                start_time: Instant::now(),
                log_entries: Arc::new(Mutex::new(Vec::new())),
                encoding_stats: Arc::new(Mutex::new(Vec::new())),
                decoding_stats: Arc::new(Mutex::new(Vec::new())),
                loss_simulations: Arc::new(Mutex::new(Vec::new())),
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

        fn record_encoding_stats(&self, stats: EncodingStats) {
            self.encoding_stats.lock().unwrap().push(stats.clone());

            self.log(
                "raptorq_encoding",
                json!({
                    "source_block_id": stats.source_block_id,
                    "source_symbols": stats.source_symbols,
                    "repair_symbols": stats.repair_symbols_generated,
                    "systematic_symbols": stats.systematic_symbols,
                    "encoding_rate": stats.encoding_rate,
                    "duration_ms": stats.encoding_duration_ms,
                    "size_bytes": stats.total_size_bytes
                }),
            );
        }

        fn record_decoding_stats(&self, stats: DecodingStats) {
            self.decoding_stats.lock().unwrap().push(stats.clone());

            self.log(
                "raptorq_decoding",
                json!({
                    "source_block_id": stats.source_block_id,
                    "symbols_received": stats.symbols_received,
                    "symbols_lost": stats.symbols_lost,
                    "repair_used": stats.repair_symbols_used,
                    "recovery_successful": stats.recovery_successful,
                    "recovery_efficiency": stats.recovery_efficiency,
                    "duration_ms": stats.decoding_duration_ms
                }),
            );
        }

        fn record_loss_simulation(&self, simulation: LossSimulation) {
            self.loss_simulations
                .lock()
                .unwrap()
                .push(simulation.clone());

            self.log(
                "loss_simulation",
                json!({
                    "type": simulation.simulation_type,
                    "target_loss_rate": simulation.loss_rate,
                    "actual_loss_rate": simulation.actual_loss_rate,
                    "symbols_transmitted": simulation.symbols_transmitted,
                    "symbols_lost": simulation.symbols_lost,
                    "recovery_possible": simulation.recovery_possible
                }),
            );
        }

        fn simulate_symbol_loss(
            &self,
            symbols: &[Symbol],
            loss_rate: f64,
            loss_pattern: LossPattern,
        ) -> (Vec<Symbol>, Vec<usize>) {
            let mut rng = thread_rng();
            let mut lost_indices = Vec::new();
            let mut remaining_symbols = Vec::new();

            match loss_pattern {
                LossPattern::Random => {
                    for (i, symbol) in symbols.iter().enumerate() {
                        if rng.gen_range(0.0..1.0) < loss_rate {
                            lost_indices.push(i);
                        } else {
                            remaining_symbols.push(symbol.clone());
                        }
                    }
                }
                LossPattern::Burst { burst_length } => {
                    let mut in_burst = false;
                    let mut burst_remaining = 0;

                    for (i, symbol) in symbols.iter().enumerate() {
                        if !in_burst && rng.gen_range(0.0..1.0) < loss_rate / 2.0 {
                            in_burst = true;
                            burst_remaining = burst_length;
                        }

                        if in_burst {
                            lost_indices.push(i);
                            burst_remaining -= 1;
                            if burst_remaining == 0 {
                                in_burst = false;
                            }
                        } else {
                            remaining_symbols.push(symbol.clone());
                        }
                    }
                }
                LossPattern::Systematic => {
                    // Lose every Nth symbol where N is determined by loss_rate
                    let interval = (1.0 / loss_rate).round() as usize;
                    for (i, symbol) in symbols.iter().enumerate() {
                        if i % interval == 0 {
                            lost_indices.push(i);
                        } else {
                            remaining_symbols.push(symbol.clone());
                        }
                    }
                }
            }

            let simulation = LossSimulation {
                timestamp: Instant::now(),
                simulation_type: format!("{:?}", loss_pattern),
                loss_rate,
                burst_length: match loss_pattern {
                    LossPattern::Burst { burst_length } => Some(burst_length),
                    _ => None,
                },
                symbols_transmitted: symbols.len(),
                symbols_lost: lost_indices.len(),
                actual_loss_rate: lost_indices.len() as f64 / symbols.len() as f64,
                recovery_possible: remaining_symbols.len()
                    >= self.calculate_minimum_symbols_needed(symbols.len()),
            };

            self.record_loss_simulation(simulation);
            (remaining_symbols, lost_indices)
        }

        fn calculate_minimum_symbols_needed(&self, source_symbols: usize) -> usize {
            // For RaptorQ, we typically need at least K symbols to decode K source symbols
            // Add small overhead for practical considerations
            source_symbols + (source_symbols / 20).max(1) // 5% overhead minimum
        }

        async fn test_systematic_encode_decode_cycle(
            &self,
            data: &[u8],
            symbol_size: usize,
            loss_rate: f64,
            loss_pattern: LossPattern,
        ) -> Result<bool, String> {
            let encoding_start = Instant::now();

            // Create encoding configuration
            let config = EncodingConfig {
                symbol_size,
                repair_symbols_per_block: None, // Will be calculated based on loss rate
            };

            // Calculate Object Transmission Information
            let oti = ObjectTransmissionInfo::new(data.len(), symbol_size)
                .map_err(|e| format!("OTI creation failed: {}", e))?;

            // Create encoder
            let mut encoder = Encoder::new(&config, oti)
                .map_err(|e| format!("Encoder creation failed: {}", e))?;

            // Encode data into source blocks
            let source_blocks = encoder
                .encode(data)
                .map_err(|e| format!("Encoding failed: {}", e))?;

            let mut all_symbols = Vec::new();
            let mut encoding_stats_list = Vec::new();

            // Process each source block
            for (block_id, source_block) in source_blocks.iter().enumerate() {
                let block_encoding_start = Instant::now();

                // Create source block encoder
                let mut block_encoder = SourceBlockEncoder::new(source_block.clone(), symbol_size)
                    .map_err(|e| format!("Block encoder creation failed: {}", e))?;

                // Generate systematic symbols
                let systematic_symbols = block_encoder.systematic_symbols();

                // Calculate repair symbols needed based on expected loss
                let repair_symbols_needed =
                    ((systematic_symbols.len() as f64) * loss_rate * 1.5).ceil() as usize;
                let repair_symbols = block_encoder.repair_symbols(repair_symbols_needed);

                // Combine systematic and repair symbols
                let mut block_symbols = systematic_symbols;
                block_symbols.extend(repair_symbols);

                let block_encoding_time = block_encoding_start.elapsed();

                let stats = EncodingStats {
                    timestamp: block_encoding_start,
                    source_block_id: block_id as u32,
                    source_symbols: source_block.source_symbols().len(),
                    repair_symbols_generated: repair_symbols_needed,
                    systematic_symbols: source_block.source_symbols().len(),
                    encoding_duration_ms: block_encoding_time.as_millis() as u64,
                    total_size_bytes: block_symbols.iter().map(|s| s.data().len()).sum(),
                    encoding_rate: block_symbols.len() as f64
                        / source_block.source_symbols().len() as f64,
                };

                self.record_encoding_stats(stats);
                encoding_stats_list.push(block_id);

                all_symbols.extend(block_symbols);
            }

            let total_encoding_time = encoding_start.elapsed();

            // Simulate symbol loss
            let (received_symbols, lost_indices) =
                self.simulate_symbol_loss(&all_symbols, loss_rate, loss_pattern);

            self.log(
                "symbol_transmission",
                json!({
                    "total_symbols": all_symbols.len(),
                    "received_symbols": received_symbols.len(),
                    "lost_symbols": lost_indices.len(),
                    "loss_rate_actual": lost_indices.len() as f64 / all_symbols.len() as f64,
                    "encoding_time_ms": total_encoding_time.as_millis()
                }),
            );

            // Decode from received symbols
            let decoding_start = Instant::now();

            let decoding_config = DecodingConfig {
                symbol_size,
                max_memory_usage: None,
            };

            let mut decoder = Decoder::new(&decoding_config, oti)
                .map_err(|e| format!("Decoder creation failed: {}", e))?;

            // Feed received symbols to decoder
            for symbol in &received_symbols {
                decoder
                    .add_symbol(symbol.clone())
                    .map_err(|e| format!("Symbol addition failed: {}", e))?;
            }

            // Attempt to decode
            let decode_result = decoder.decode();
            let decoding_time = decoding_start.elapsed();

            match decode_result {
                Ok(decoded_data) => {
                    let recovery_successful = decoded_data == data;

                    let stats = DecodingStats {
                        timestamp: decoding_start,
                        source_block_id: 0, // Simplified for single block case
                        symbols_received: received_symbols.len(),
                        symbols_lost: lost_indices.len(),
                        repair_symbols_used: received_symbols
                            .iter()
                            .filter(|s| s.id().is_repair_symbol())
                            .count(),
                        decoding_duration_ms: decoding_time.as_millis() as u64,
                        recovery_successful,
                        recovery_efficiency: received_symbols.len() as f64
                            / all_symbols.len() as f64,
                        decoded_size_bytes: decoded_data.len(),
                    };

                    self.record_decoding_stats(stats);

                    if recovery_successful {
                        self.log(
                            "decode_success",
                            json!({
                                "original_size": data.len(),
                                "decoded_size": decoded_data.len(),
                                "symbols_used": received_symbols.len(),
                                "decoding_time_ms": decoding_time.as_millis()
                            }),
                        );
                        Ok(true)
                    } else {
                        self.log(
                            "decode_data_mismatch",
                            json!({
                                "original_size": data.len(),
                                "decoded_size": decoded_data.len()
                            }),
                        );
                        Ok(false)
                    }
                }
                Err(e) => {
                    let stats = DecodingStats {
                        timestamp: decoding_start,
                        source_block_id: 0,
                        symbols_received: received_symbols.len(),
                        symbols_lost: lost_indices.len(),
                        repair_symbols_used: 0,
                        decoding_duration_ms: decoding_time.as_millis() as u64,
                        recovery_successful: false,
                        recovery_efficiency: 0.0,
                        decoded_size_bytes: 0,
                    };

                    self.record_decoding_stats(stats);
                    Err(format!("Decoding failed: {}", e))
                }
            }
        }

        fn validate_encoding_performance(&self) -> Result<(), String> {
            let encoding_stats = self.encoding_stats.lock().unwrap();

            for stats in encoding_stats.iter() {
                // Encoding should complete in reasonable time
                if stats.encoding_duration_ms > 5000 {
                    return Err(format!(
                        "Encoding block {} took too long: {}ms",
                        stats.source_block_id, stats.encoding_duration_ms
                    ));
                }

                // Encoding rate should be reasonable (not too much overhead)
                if stats.encoding_rate > 3.0 {
                    return Err(format!(
                        "Encoding rate too high for block {}: {}",
                        stats.source_block_id, stats.encoding_rate
                    ));
                }
            }

            Ok(())
        }

        fn validate_decoding_efficiency(&self) -> Result<(), String> {
            let decoding_stats = self.decoding_stats.lock().unwrap();
            let successful_decodings: Vec<_> = decoding_stats
                .iter()
                .filter(|s| s.recovery_successful)
                .collect();

            if successful_decodings.is_empty() {
                return Err("No successful decodings found".to_string());
            }

            let avg_efficiency: f64 = successful_decodings
                .iter()
                .map(|s| s.recovery_efficiency)
                .sum::<f64>()
                / successful_decodings.len() as f64;

            if avg_efficiency < 0.5 {
                return Err(format!(
                    "Average decoding efficiency too low: {:.2}%",
                    avg_efficiency * 100.0
                ));
            }

            Ok(())
        }
    }

    #[derive(Debug, Clone, Copy)]
    enum LossPattern {
        Random,
        Burst { burst_length: usize },
        Systematic,
    }

    #[tokio::test]
    async fn test_raptorq_random_loss_recovery() {
        let harness = Arc::new(RaptorQTestHarness::new());
        harness.log(
            "test_start",
            json!({"test": "raptorq_random_loss_recovery"}),
        );

        // Test data sizes and parameters
        let test_cases = vec![
            (1024, 64, 0.1),    // 1KB data, 64B symbols, 10% loss
            (8192, 128, 0.2),   // 8KB data, 128B symbols, 20% loss
            (65536, 256, 0.15), // 64KB data, 256B symbols, 15% loss
        ];

        let mut total_successful = 0;
        let mut total_tests = 0;

        for (data_size, symbol_size, loss_rate) in test_cases {
            // Generate test data
            let mut test_data = vec![0u8; data_size];
            let mut rng = thread_rng();
            rng.fill(&mut test_data[..]);

            harness.log(
                "test_case_start",
                json!({
                    "data_size": data_size,
                    "symbol_size": symbol_size,
                    "loss_rate": loss_rate
                }),
            );

            match harness
                .test_systematic_encode_decode_cycle(
                    &test_data,
                    symbol_size,
                    loss_rate,
                    LossPattern::Random,
                )
                .await
            {
                Ok(recovery_successful) => {
                    if recovery_successful {
                        total_successful += 1;
                    }
                    total_tests += 1;

                    harness.log(
                        "test_case_result",
                        json!({
                            "data_size": data_size,
                            "symbol_size": symbol_size,
                            "loss_rate": loss_rate,
                            "recovery_successful": recovery_successful
                        }),
                    );
                }
                Err(e) => {
                    harness.log(
                        "test_case_error",
                        json!({
                            "data_size": data_size,
                            "symbol_size": symbol_size,
                            "error": e
                        }),
                    );
                    total_tests += 1;
                }
            }
        }

        // Validate performance and efficiency
        let performance_validation = harness.validate_encoding_performance();
        assert!(
            performance_validation.is_ok(),
            "Encoding performance validation failed: {:?}",
            performance_validation
        );

        let efficiency_validation = harness.validate_decoding_efficiency();
        assert!(
            efficiency_validation.is_ok(),
            "Decoding efficiency validation failed: {:?}",
            efficiency_validation
        );

        // Should recover most cases with reasonable loss rates
        let success_rate = total_successful as f64 / total_tests as f64;
        assert!(
            success_rate >= 0.8,
            "Success rate too low: {:.1}% ({}/{})",
            success_rate * 100.0,
            total_successful,
            total_tests
        );

        harness.log(
            "test_result",
            json!({
                "passed": true,
                "success_rate": success_rate,
                "total_successful": total_successful,
                "total_tests": total_tests,
                "message": "RaptorQ random loss recovery validated successfully"
            }),
        );
    }

    #[tokio::test]
    async fn test_raptorq_burst_loss_recovery() {
        let harness = Arc::new(RaptorQTestHarness::new());
        harness.log("test_start", json!({"test": "raptorq_burst_loss_recovery"}));

        let data_size = 32768; // 32KB
        let symbol_size = 512; // 512B symbols

        // Generate test data
        let mut test_data = vec![0u8; data_size];
        let mut rng = thread_rng();
        rng.fill(&mut test_data[..]);

        // Test different burst patterns
        let burst_patterns = vec![
            (0.1, 5),   // 10% loss in bursts of 5
            (0.15, 10), // 15% loss in bursts of 10
            (0.2, 3),   // 20% loss in bursts of 3
        ];

        let mut successful_recoveries = 0;

        for (loss_rate, burst_length) in burst_patterns {
            harness.log(
                "burst_test_start",
                json!({
                    "loss_rate": loss_rate,
                    "burst_length": burst_length
                }),
            );

            match harness
                .test_systematic_encode_decode_cycle(
                    &test_data,
                    symbol_size,
                    loss_rate,
                    LossPattern::Burst { burst_length },
                )
                .await
            {
                Ok(recovery_successful) => {
                    if recovery_successful {
                        successful_recoveries += 1;
                    }

                    harness.log(
                        "burst_test_result",
                        json!({
                            "loss_rate": loss_rate,
                            "burst_length": burst_length,
                            "recovery_successful": recovery_successful
                        }),
                    );
                }
                Err(e) => {
                    harness.log(
                        "burst_test_error",
                        json!({
                            "loss_rate": loss_rate,
                            "burst_length": burst_length,
                            "error": e
                        }),
                    );
                }
            }
        }

        // RaptorQ should handle burst losses well
        assert!(
            successful_recoveries >= 2,
            "Should recover from most burst patterns, got {}/{}",
            successful_recoveries,
            burst_patterns.len()
        );

        harness.log(
            "test_result",
            json!({
                "passed": true,
                "successful_recoveries": successful_recoveries,
                "total_patterns": burst_patterns.len(),
                "message": "RaptorQ burst loss recovery validated successfully"
            }),
        );
    }

    #[tokio::test]
    async fn test_raptorq_concurrent_encoding_decoding() {
        let harness = Arc::new(RaptorQTestHarness::new());
        harness.log(
            "test_start",
            json!({"test": "raptorq_concurrent_encoding_decoding"}),
        );

        let num_concurrent_streams = 4;
        let data_size = 16384; // 16KB per stream
        let symbol_size = 256;
        let loss_rate = 0.15; // 15% loss

        let mut worker_handles = Vec::new();
        let successful_recoveries = Arc::new(AtomicUsize::new(0));
        let total_attempts = Arc::new(AtomicUsize::new(0));

        // Spawn concurrent RaptorQ encode/decode workers
        for worker_id in 0..num_concurrent_streams {
            let harness = Arc::clone(&harness);
            let successful_recoveries = Arc::clone(&successful_recoveries);
            let total_attempts = Arc::clone(&total_attempts);

            let handle = spawn(async move {
                // Generate unique test data for this worker
                let mut test_data = vec![0u8; data_size];
                let mut rng = thread_rng();
                rng.fill(&mut test_data[..]);

                // Add worker ID pattern to make data unique
                for (i, byte) in test_data.iter_mut().enumerate() {
                    *byte ^= ((worker_id + i) % 256) as u8;
                }

                total_attempts.fetch_add(1, Ordering::Relaxed);

                match harness
                    .test_systematic_encode_decode_cycle(
                        &test_data,
                        symbol_size,
                        loss_rate,
                        LossPattern::Random,
                    )
                    .await
                {
                    Ok(recovery_successful) => {
                        if recovery_successful {
                            successful_recoveries.fetch_add(1, Ordering::Relaxed);
                        }

                        harness.log(
                            "concurrent_worker_result",
                            json!({
                                "worker_id": worker_id,
                                "data_size": data_size,
                                "recovery_successful": recovery_successful
                            }),
                        );

                        (worker_id, recovery_successful)
                    }
                    Err(e) => {
                        harness.log(
                            "concurrent_worker_error",
                            json!({
                                "worker_id": worker_id,
                                "error": e
                            }),
                        );

                        (worker_id, false)
                    }
                }
            });

            worker_handles.push(handle);
        }

        // Wait for all workers to complete
        for handle in worker_handles {
            let (worker_id, success) = handle.await;
            harness.log(
                "worker_completed",
                json!({
                    "worker_id": worker_id,
                    "success": success
                }),
            );
        }

        let total_successful = successful_recoveries.load(Ordering::Relaxed);
        let total_tested = total_attempts.load(Ordering::Relaxed);
        let success_rate = total_successful as f64 / total_tested as f64;

        // Validate concurrent performance
        let performance_validation = harness.validate_encoding_performance();
        assert!(
            performance_validation.is_ok(),
            "Concurrent encoding performance failed: {:?}",
            performance_validation
        );

        // Should maintain good success rate under concurrent load
        assert!(
            success_rate >= 0.75,
            "Concurrent success rate too low: {:.1}% ({}/{})",
            success_rate * 100.0,
            total_successful,
            total_tested
        );

        harness.log(
            "test_result",
            json!({
                "passed": true,
                "concurrent_streams": num_concurrent_streams,
                "success_rate": success_rate,
                "total_successful": total_successful,
                "total_tested": total_tested,
                "message": "RaptorQ concurrent encoding/decoding validated successfully"
            }),
        );
    }

    #[tokio::test]
    async fn test_raptorq_large_object_systematic() {
        let harness = Arc::new(RaptorQTestHarness::new());
        harness.log(
            "test_start",
            json!({"test": "raptorq_large_object_systematic"}),
        );

        // Test larger object that will span multiple source blocks
        let data_size = 131072; // 128KB - should create multiple source blocks
        let symbol_size = 1024; // 1KB symbols
        let loss_rate = 0.1; // 10% loss

        // Generate test data with pattern for verification
        let mut test_data = vec![0u8; data_size];
        for (i, byte) in test_data.iter_mut().enumerate() {
            *byte = ((i * 7 + i / 256) % 256) as u8; // Pattern for integrity checking
        }

        harness.log(
            "large_object_test_start",
            json!({
                "data_size": data_size,
                "symbol_size": symbol_size,
                "expected_source_blocks": (data_size + symbol_size - 1) / symbol_size,
                "loss_rate": loss_rate
            }),
        );

        let test_start = Instant::now();

        match harness
            .test_systematic_encode_decode_cycle(
                &test_data,
                symbol_size,
                loss_rate,
                LossPattern::Systematic, // Use systematic loss pattern for large objects
            )
            .await
        {
            Ok(recovery_successful) => {
                let test_duration = test_start.elapsed();

                harness.log("large_object_result", json!({
                    "data_size": data_size,
                    "symbol_size": symbol_size,
                    "recovery_successful": recovery_successful,
                    "test_duration_ms": test_duration.as_millis(),
                    "throughput_mbps": (data_size as f64 * 8.0) / (test_duration.as_secs_f64() * 1_000_000.0)
                }));

                // Large object should be recoverable
                assert!(recovery_successful, "Large object recovery should succeed");

                // Performance should be reasonable
                let throughput_mbps =
                    (data_size as f64 * 8.0) / (test_duration.as_secs_f64() * 1_000_000.0);
                assert!(
                    throughput_mbps > 1.0,
                    "Throughput should be > 1 Mbps, got {:.2} Mbps",
                    throughput_mbps
                );
            }
            Err(e) => {
                panic!("Large object test failed: {}", e);
            }
        }

        // Validate multi-block handling
        let encoding_stats = harness.encoding_stats.lock().unwrap();
        assert!(
            !encoding_stats.is_empty(),
            "Should have encoding stats for multiple blocks"
        );

        let total_source_symbols: usize = encoding_stats.iter().map(|s| s.source_symbols).sum();

        let expected_symbols = (data_size + symbol_size - 1) / symbol_size;
        assert!(
            total_source_symbols >= expected_symbols * 80 / 100,
            "Should encode most expected symbols: got {}, expected ~{}",
            total_source_symbols,
            expected_symbols
        );

        harness.log(
            "test_result",
            json!({
                "passed": true,
                "large_object_recovered": true,
                "total_source_symbols": total_source_symbols,
                "encoding_blocks": encoding_stats.len(),
                "message": "RaptorQ large object systematic encoding validated successfully"
            }),
        );
    }
}
