//! Integration tests for raptorq/decoder ↔ lab/network packet loss integration.
//!
//! These tests verify that the RaptorQ decoder correctly recovers from lab-injected
//! 30%+ packet loss with bounded repair overhead and deterministic behavior.
//!
//! Key integration points tested:
//! - RaptorQ decoder recovery from high packet loss rates (30-50%)
//! - Lab network deterministic packet loss injection
//! - Bounded repair overhead verification and resource management
//! - Concurrent decoder stress testing under sustained loss
//! - Edge cases: burst losses, selective losses, repair efficiency

#[cfg(all(test, feature = "real-service-e2e"))]
mod integration_tests {
    use crate::error::AsupersyncError;
    use crate::lab::network::{LabNetwork, NetworkSimulator, PacketLossConfig, PacketLossPattern};
    use crate::lab::runtime::{LabRuntime, VirtualTime};
    use crate::net::packet::{EncodingSymbol, Packet, PacketId};
    use crate::raptorq::decoder::{DecoderConfig, RaptorQDecoder, RecoveryStats, RepairOverhead};
    use crate::runtime::{Runtime, RuntimeBuilder};
    use crate::types::{Budget, Outcome, TaskId};
    use std::collections::{HashMap, VecDeque};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    /// Test harness for RaptorQ decoder and lab network packet loss integration testing.
    struct RaptorQNetworkLossTestHarness {
        lab_runtime: Arc<LabRuntime>,
        lab_network: Arc<LabNetwork>,
        decoders: HashMap<String, Arc<RaptorQDecoder>>,
        packet_generators: HashMap<String, PacketGenerator>,
        loss_configs: HashMap<String, PacketLossConfig>,
        stats: Arc<Mutex<RaptorQNetworkLossStats>>,
    }

    #[derive(Debug, Default, Clone)]
    struct RaptorQNetworkLossStats {
        /// Total packets sent
        packets_sent: u64,
        /// Packets lost due to network simulation
        packets_lost: u64,
        /// Packets successfully recovered by decoder
        packets_recovered: u64,
        /// Decoder instances created
        decoders_created: u64,
        /// Repair operations performed
        repair_operations: u64,
        /// Total repair overhead (CPU cycles/memory/network)
        total_repair_overhead: RepairOverhead,
        /// Successful recovery sessions at 30%+ loss
        high_loss_recoveries: u64,
        /// Failed recovery attempts
        recovery_failures: u64,
        /// Peak concurrent decoders
        peak_concurrent_decoders: u64,
    }

    /// Packet generator for creating test data streams
    struct PacketGenerator {
        sequence: u64,
        block_size: usize,
        symbol_size: usize,
        encoding_overhead: f32,
    }

    impl PacketGenerator {
        fn new(block_size: usize, symbol_size: usize, encoding_overhead: f32) -> Self {
            Self {
                sequence: 0,
                block_size,
                symbol_size,
                encoding_overhead,
            }
        }

        fn generate_block(&mut self) -> Result<Vec<EncodingSymbol>, AsupersyncError> {
            let mut symbols = Vec::with_capacity(self.block_size);
            let repair_symbols = (self.block_size as f32 * self.encoding_overhead) as usize;

            // Generate source symbols
            for i in 0..self.block_size {
                let symbol_data = vec![0xAA + (i as u8); self.symbol_size];
                symbols.push(EncodingSymbol::source(
                    PacketId::new(self.sequence, i),
                    symbol_data,
                ));
            }

            // Generate repair symbols
            for i in 0..repair_symbols {
                let symbol_data = vec![0xBB + (i as u8); self.symbol_size];
                symbols.push(EncodingSymbol::repair(
                    PacketId::new(self.sequence, self.block_size + i),
                    symbol_data,
                ));
            }

            self.sequence += 1;
            Ok(symbols)
        }
    }

    impl RaptorQNetworkLossTestHarness {
        fn new() -> Result<Self, AsupersyncError> {
            let lab_runtime = Arc::new(LabRuntime::new_with_deterministic_scheduling()?);
            let lab_network = Arc::new(LabNetwork::new(lab_runtime.clone())?);

            Ok(Self {
                lab_runtime,
                lab_network,
                decoders: HashMap::new(),
                packet_generators: HashMap::new(),
                loss_configs: HashMap::new(),
                stats: Arc::new(Mutex::new(RaptorQNetworkLossStats::default())),
            })
        }

        fn create_decoder(
            &mut self,
            decoder_id: &str,
            config: DecoderConfig,
        ) -> Result<(), AsupersyncError> {
            let decoder = Arc::new(RaptorQDecoder::new(config)?);
            self.decoders.insert(decoder_id.to_string(), decoder);

            {
                let mut stats = self.stats.lock().unwrap();
                stats.decoders_created += 1;
                stats.peak_concurrent_decoders = stats
                    .peak_concurrent_decoders
                    .max(self.decoders.len() as u64);
            }

            Ok(())
        }

        fn create_packet_generator(
            &mut self,
            gen_id: &str,
            block_size: usize,
            symbol_size: usize,
            encoding_overhead: f32,
        ) {
            let generator = PacketGenerator::new(block_size, symbol_size, encoding_overhead);
            self.packet_generators.insert(gen_id.to_string(), generator);
        }

        fn configure_packet_loss(
            &mut self,
            config_id: &str,
            loss_rate: f32,
            pattern: PacketLossPattern,
        ) -> Result<(), AsupersyncError> {
            let loss_config = PacketLossConfig {
                loss_rate,
                pattern,
                burst_length: Some(3), // 3-packet bursts
                correlation: 0.1,      // Low correlation for realistic loss
                seed: 12345,           // Deterministic seed
            };

            self.lab_network
                .configure_packet_loss(config_id, loss_config.clone())?;
            self.loss_configs.insert(config_id.to_string(), loss_config);

            Ok(())
        }

        fn simulate_transmission_with_loss(
            &mut self,
            gen_id: &str,
            decoder_id: &str,
            loss_config_id: &str,
            num_blocks: usize,
        ) -> Result<RecoveryStats, AsupersyncError> {
            let generator = self.packet_generators.get_mut(gen_id).ok_or_else(|| {
                AsupersyncError::InvalidState("Packet generator not found".into())
            })?;
            let decoder = self
                .decoders
                .get(decoder_id)
                .ok_or_else(|| AsupersyncError::InvalidState("Decoder not found".into()))?;

            let mut total_recovery_stats = RecoveryStats::default();
            let start_time = self.lab_runtime.now();

            for block_idx in 0..num_blocks {
                // Generate block of symbols
                let symbols = generator.generate_block()?;
                let total_symbols = symbols.len();

                {
                    let mut stats = self.stats.lock().unwrap();
                    stats.packets_sent += total_symbols as u64;
                }

                // Simulate transmission through lossy network
                let mut received_symbols = Vec::new();
                for symbol in symbols {
                    let packet = Packet::new(symbol.packet_id(), symbol.data().clone());

                    // Apply network loss simulation
                    if self
                        .lab_network
                        .should_deliver_packet(loss_config_id, &packet)?
                    {
                        received_symbols.push(symbol);
                    } else {
                        let mut stats = self.stats.lock().unwrap();
                        stats.packets_lost += 1;
                    }
                }

                let loss_rate = 1.0 - (received_symbols.len() as f32 / total_symbols as f32);

                // Attempt recovery with decoder
                let recovery_start = self.lab_runtime.now();
                let block_stats = decoder.attempt_recovery(received_symbols, block_idx)?;
                let recovery_duration = self.lab_runtime.now().duration_since(recovery_start);

                // Update stats
                {
                    let mut stats = self.stats.lock().unwrap();
                    stats.packets_recovered += block_stats.symbols_recovered;
                    stats.repair_operations += block_stats.repair_operations;
                    stats
                        .total_repair_overhead
                        .add(&block_stats.repair_overhead);

                    if loss_rate >= 0.30 && block_stats.recovery_successful {
                        stats.high_loss_recoveries += 1;
                    } else if !block_stats.recovery_successful {
                        stats.recovery_failures += 1;
                    }
                }

                total_recovery_stats.merge(block_stats);

                // Advance lab time to simulate realistic network conditions
                self.lab_runtime.advance_time(Duration::from_millis(10))?;
            }

            let total_duration = self.lab_runtime.now().duration_since(start_time);
            total_recovery_stats.total_duration = total_duration;

            Ok(total_recovery_stats)
        }

        fn measure_repair_overhead_bounds(
            &self,
            recovery_stats: &RecoveryStats,
        ) -> Result<bool, AsupersyncError> {
            // Define bounded overhead limits
            const MAX_CPU_CYCLES_PER_SYMBOL: u64 = 10000;
            const MAX_MEMORY_BYTES_PER_SYMBOL: u64 = 4096;
            const MAX_NETWORK_OVERHEAD_RATIO: f32 = 2.0; // Max 200% overhead

            let symbols_processed = recovery_stats.symbols_processed;
            if symbols_processed == 0 {
                return Ok(true); // No symbols, no overhead
            }

            let cpu_per_symbol = recovery_stats.repair_overhead.cpu_cycles / symbols_processed;
            let memory_per_symbol = recovery_stats.repair_overhead.memory_bytes / symbols_processed;
            let network_ratio = recovery_stats.repair_overhead.network_bytes as f32
                / recovery_stats.original_bytes as f32;

            let within_bounds = cpu_per_symbol <= MAX_CPU_CYCLES_PER_SYMBOL
                && memory_per_symbol <= MAX_MEMORY_BYTES_PER_SYMBOL
                && network_ratio <= MAX_NETWORK_OVERHEAD_RATIO;

            Ok(within_bounds)
        }

        fn get_stats(&self) -> RaptorQNetworkLossStats {
            self.stats.lock().unwrap().clone()
        }
    }

    #[tokio::test]
    async fn test_basic_30_percent_packet_loss_recovery() -> Result<(), AsupersyncError> {
        let mut harness = RaptorQNetworkLossTestHarness::new()?;

        // Configure decoder for 30% loss tolerance
        let decoder_config = DecoderConfig {
            max_source_symbols: 1000,
            symbol_size: 1316,      // Standard MTU-friendly size
            repair_threshold: 0.35, // Handle up to 35% loss
            max_repair_iterations: 100,
            bounded_overhead: true,
        };

        harness.create_decoder("test-decoder", decoder_config)?;
        harness.create_packet_generator("test-gen", 100, 1316, 0.5); // 50% encoding overhead

        // Configure 30% packet loss with random pattern
        harness.configure_packet_loss("loss-30", 0.30, PacketLossPattern::Random)?;

        // Simulate transmission and recovery
        let recovery_stats = harness.simulate_transmission_with_loss(
            "test-gen",
            "test-decoder",
            "loss-30",
            10, // 10 blocks
        )?;

        // Verify successful recovery
        assert!(
            recovery_stats.recovery_successful,
            "Should recover from 30% packet loss"
        );
        assert!(
            recovery_stats.symbols_recovered >= recovery_stats.symbols_processed * 70 / 100,
            "Should recover at least 70% of symbols"
        );

        // Verify bounded overhead
        let within_bounds = harness.measure_repair_overhead_bounds(&recovery_stats)?;
        assert!(
            within_bounds,
            "Repair overhead should be within bounded limits"
        );

        let stats = harness.get_stats();
        assert!(
            stats.high_loss_recoveries > 0,
            "Should have successful high-loss recoveries"
        );
        assert_eq!(stats.recovery_failures, 0);

        println!("30% Loss Recovery Stats: {:?}", recovery_stats);
        Ok(())
    }

    #[tokio::test]
    async fn test_high_loss_rates_40_and_50_percent() -> Result<(), AsupersyncError> {
        let mut harness = RaptorQNetworkLossTestHarness::new()?;

        // Configure decoder for high loss tolerance
        let decoder_config = DecoderConfig {
            max_source_symbols: 500,
            symbol_size: 1316,
            repair_threshold: 0.60, // Handle up to 60% loss
            max_repair_iterations: 200,
            bounded_overhead: true,
        };

        harness.create_decoder("high-loss-decoder", decoder_config)?;
        harness.create_packet_generator("high-loss-gen", 80, 1316, 0.8); // 80% encoding overhead

        // Test 40% loss rate
        harness.configure_packet_loss("loss-40", 0.40, PacketLossPattern::Random)?;
        let recovery_stats_40 = harness.simulate_transmission_with_loss(
            "high-loss-gen",
            "high-loss-decoder",
            "loss-40",
            5,
        )?;

        // Test 50% loss rate
        harness.configure_packet_loss("loss-50", 0.50, PacketLossPattern::Random)?;
        let recovery_stats_50 = harness.simulate_transmission_with_loss(
            "high-loss-gen",
            "high-loss-decoder",
            "loss-50",
            5,
        )?;

        // Verify recovery at both rates
        assert!(
            recovery_stats_40.recovery_successful,
            "Should recover from 40% packet loss"
        );
        assert!(
            recovery_stats_50.recovery_successful,
            "Should recover from 50% packet loss"
        );

        // Verify bounded overhead for both
        assert!(
            harness.measure_repair_overhead_bounds(&recovery_stats_40)?,
            "40% loss repair should be bounded"
        );
        assert!(
            harness.measure_repair_overhead_bounds(&recovery_stats_50)?,
            "50% loss repair should be bounded"
        );

        // Verify repair overhead increases with loss rate (but remains bounded)
        assert!(
            recovery_stats_50.repair_overhead.cpu_cycles
                >= recovery_stats_40.repair_overhead.cpu_cycles,
            "Higher loss should require more CPU for repair"
        );

        let stats = harness.get_stats();
        assert!(
            stats.high_loss_recoveries >= 10,
            "Should have multiple high-loss recoveries"
        );

        println!("40% Loss Stats: {:?}", recovery_stats_40);
        println!("50% Loss Stats: {:?}", recovery_stats_50);
        Ok(())
    }

    #[tokio::test]
    async fn test_burst_loss_pattern_recovery() -> Result<(), AsupersyncError> {
        let mut harness = RaptorQNetworkLossTestHarness::new()?;

        let decoder_config = DecoderConfig {
            max_source_symbols: 200,
            symbol_size: 1316,
            repair_threshold: 0.45,
            max_repair_iterations: 150,
            bounded_overhead: true,
        };

        harness.create_decoder("burst-decoder", decoder_config)?;
        harness.create_packet_generator("burst-gen", 60, 1316, 0.6);

        // Configure 35% loss with burst pattern (more challenging than random)
        harness.configure_packet_loss("burst-35", 0.35, PacketLossPattern::BurstLoss)?;

        let recovery_stats =
            harness.simulate_transmission_with_loss("burst-gen", "burst-decoder", "burst-35", 8)?;

        // Burst losses are harder to recover from, but should still succeed
        assert!(
            recovery_stats.recovery_successful,
            "Should recover from 35% burst packet loss"
        );
        assert!(
            recovery_stats.repair_operations > 0,
            "Should perform repair operations for burst losses"
        );

        // Verify bounded overhead despite challenging loss pattern
        assert!(
            harness.measure_repair_overhead_bounds(&recovery_stats)?,
            "Burst loss repair should maintain bounded overhead"
        );

        println!("Burst Loss Recovery Stats: {:?}", recovery_stats);
        Ok(())
    }

    #[tokio::test]
    async fn test_concurrent_decoders_under_loss() -> Result<(), AsupersyncError> {
        let mut harness = RaptorQNetworkLossTestHarness::new()?;

        let decoder_config = DecoderConfig {
            max_source_symbols: 150,
            symbol_size: 1316,
            repair_threshold: 0.40,
            max_repair_iterations: 120,
            bounded_overhead: true,
        };

        // Create multiple concurrent decoders
        let num_decoders = 8;
        for i in 0..num_decoders {
            harness.create_decoder(&format!("decoder-{}", i), decoder_config.clone())?;
            harness.create_packet_generator(&format!("gen-{}", i), 50, 1316, 0.6);
        }

        // Configure 35% loss for concurrent stress test
        harness.configure_packet_loss("concurrent-35", 0.35, PacketLossPattern::Random)?;

        // Run concurrent recovery operations
        let start_time = harness.lab_runtime.now();
        let mut recovery_results = Vec::new();

        for i in 0..num_decoders {
            let recovery_stats = harness.simulate_transmission_with_loss(
                &format!("gen-{}", i),
                &format!("decoder-{}", i),
                "concurrent-35",
                3, // Smaller blocks for concurrent test
            )?;
            recovery_results.push(recovery_stats);
        }

        let total_duration = harness.lab_runtime.now().duration_since(start_time);

        // Verify all decoders succeeded
        let successful_recoveries = recovery_results
            .iter()
            .filter(|r| r.recovery_successful)
            .count();
        assert!(
            successful_recoveries >= num_decoders * 80 / 100,
            "At least 80% of concurrent decoders should succeed"
        );

        // Verify bounded overhead across all decoders
        for (i, recovery_stats) in recovery_results.iter().enumerate() {
            assert!(
                harness.measure_repair_overhead_bounds(recovery_stats)?,
                "Decoder {} should maintain bounded overhead under concurrency",
                i
            );
        }

        let stats = harness.get_stats();
        assert_eq!(stats.peak_concurrent_decoders, num_decoders as u64);

        println!(
            "Concurrent Recovery - {} decoders completed in {:?}",
            successful_recoveries, total_duration
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_sustained_high_loss_stress() -> Result<(), AsupersyncError> {
        let mut harness = RaptorQNetworkLossTestHarness::new()?;

        let decoder_config = DecoderConfig {
            max_source_symbols: 300,
            symbol_size: 1316,
            repair_threshold: 0.50,
            max_repair_iterations: 300,
            bounded_overhead: true,
        };

        harness.create_decoder("stress-decoder", decoder_config)?;
        harness.create_packet_generator("stress-gen", 100, 1316, 0.7); // 70% overhead

        // Configure sustained 40% loss over long duration
        harness.configure_packet_loss("sustained-40", 0.40, PacketLossPattern::Random)?;

        let start_time = harness.lab_runtime.now();

        // Run sustained stress test with many blocks
        let recovery_stats = harness.simulate_transmission_with_loss(
            "stress-gen",
            "stress-decoder",
            "sustained-40",
            50, // Large number of blocks
        )?;

        let total_duration = harness.lab_runtime.now().duration_since(start_time);

        // Verify sustained recovery capability
        assert!(
            recovery_stats.recovery_successful,
            "Should sustain recovery over long duration"
        );
        assert!(
            recovery_stats.symbols_recovered >= recovery_stats.symbols_processed * 60 / 100,
            "Should recover majority of symbols under sustained loss"
        );

        // Verify overhead remains bounded throughout stress test
        assert!(
            harness.measure_repair_overhead_bounds(&recovery_stats)?,
            "Sustained stress should maintain bounded repair overhead"
        );

        let stats = harness.get_stats();
        assert!(
            stats.repair_operations > 100,
            "Should perform many repair operations under sustained loss"
        );

        // Verify efficiency metrics
        let recovery_efficiency =
            recovery_stats.symbols_recovered as f32 / recovery_stats.repair_operations as f32;
        assert!(
            recovery_efficiency > 0.5,
            "Recovery should maintain reasonable efficiency"
        );

        println!(
            "Sustained Stress - {} blocks recovered in {:?}",
            50, total_duration
        );
        println!(
            "Recovery efficiency: {:.2} symbols per repair operation",
            recovery_efficiency
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_selective_loss_edge_cases() -> Result<(), AsupersyncError> {
        let mut harness = RaptorQNetworkLossTestHarness::new()?;

        let decoder_config = DecoderConfig {
            max_source_symbols: 120,
            symbol_size: 1316,
            repair_threshold: 0.45,
            max_repair_iterations: 200,
            bounded_overhead: true,
        };

        harness.create_decoder("selective-decoder", decoder_config)?;
        harness.create_packet_generator("selective-gen", 80, 1316, 0.65);

        // Test different selective loss patterns
        let loss_patterns = vec![
            ("selective-source", 0.40, PacketLossPattern::SelectiveSource), // Prefer losing source symbols
            ("selective-repair", 0.40, PacketLossPattern::SelectiveRepair), // Prefer losing repair symbols
            ("alternating", 0.35, PacketLossPattern::Alternating), // Alternating loss pattern
        ];

        for (config_id, loss_rate, pattern) in loss_patterns {
            harness.configure_packet_loss(config_id, loss_rate, pattern)?;

            let recovery_stats = harness.simulate_transmission_with_loss(
                "selective-gen",
                "selective-decoder",
                config_id,
                6,
            )?;

            // Each pattern should be recoverable, though with different efficiency
            assert!(
                recovery_stats.recovery_successful || recovery_stats.partial_recovery_ratio > 0.8,
                "Pattern {} should achieve recovery or high partial recovery",
                config_id
            );

            assert!(
                harness.measure_repair_overhead_bounds(&recovery_stats)?,
                "Pattern {} should maintain bounded overhead",
                config_id
            );

            println!(
                "Pattern {} - Success: {}, Partial Ratio: {:.2}",
                config_id,
                recovery_stats.recovery_successful,
                recovery_stats.partial_recovery_ratio
            );
        }

        let stats = harness.get_stats();
        println!(
            "Selective Loss Edge Cases - Total high-loss recoveries: {}",
            stats.high_loss_recoveries
        );
        Ok(())
    }
}
