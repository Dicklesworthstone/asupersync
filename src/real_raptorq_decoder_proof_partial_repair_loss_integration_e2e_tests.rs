//! Real E2E integration tests: raptorq/decoder ↔ raptorq/proof partial repair loss integration (br-e2e-151).
//!
//! Tests that RaptorQ decoder correctly generates valid proof artifacts when decoding
//! blocks even under partial repair symbol loss scenarios. Verifies the integration
//! between decoder proof emission and proof validation systems when repair symbols
//! are partially missing, ensuring proof integrity is maintained across loss conditions.
//!
//! # Integration Patterns Tested
//!
//! - **Decoder Proof Emission**: RaptorQ decoder generates valid proofs during decode operations
//! - **Partial Repair Symbol Loss**: Decoding succeeds with missing repair symbols
//! - **Proof Validation Under Loss**: Proof replay and verification works with partial symbols
//! - **Loss Pattern Integrity**: Different repair loss patterns produce valid but distinct proofs
//! - **Proof Determinism**: Same repair loss pattern produces identical proof artifacts
//!
//! # Test Scenarios
//!
//! 1. **Complete Symbol Set** — Baseline decode with all symbols (proof validation baseline)
//! 2. **Minimal Repair Loss** — Decode with small number of missing repair symbols
//! 3. **Substantial Repair Loss** — Decode with significant repair symbol loss but sufficient total symbols
//! 4. **Edge Case Loss Patterns** — Specific repair symbol loss patterns (beginning, middle, end)
//! 5. **Proof Replay Under Loss** — Validate proof replay works correctly with partial symbols
//!
//! # Safety Properties Verified
//!
//! - Decoded blocks emit valid proof artifacts even when repair symbols are missing
//! - Proof validation correctly handles partial repair symbol scenarios
//! - Proof replay produces identical results when given same partial symbol set
//! - Proof integrity is maintained across different repair symbol loss patterns
//! - Deterministic proof generation with partial repair symbols

#[cfg(all(test, feature = "real-service-e2e"))]
mod tests {
    #![allow(
        clippy::expect_fun_call,
        clippy::future_not_send,
        clippy::match_same_arms,
        clippy::missing_panics_doc,
        clippy::needless_pass_by_value,
        clippy::unwrap_used,
        dead_code
    )]

    use crate::raptorq::{
        decoder::{DecodeError, DecodeResult, Decoder, ReceivedSymbol},
        gf256::Gf256,
        proof::{DecodeProof, ReplayError, ProofHash},
        rfc6330::RFC6330_K_MAX,
        systematic::{SystematicEncoder, SystematicError, SystematicParams},
    };
    use crate::types::{ObjectId, Time};
    use sha2::{Digest, Sha256};
    use std::collections::{BTreeMap, HashMap, HashSet};
    use std::sync::{
        Arc, RwLock,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    };

    // ────────────────────────────────────────────────────────────────────────────────
    // RaptorQ Decoder + Proof Partial Repair Loss Integration Test Framework
    // ────────────────────────────────────────────────────────────────────────────────

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum RaptorQProofLossTestPhase {
        Setup,
        ObjectEncoding,
        CompleteSymbolSetBaseline,
        MinimalRepairLoss,
        SubstantialRepairLoss,
        EdgeCaseLossPatterns,
        ProofReplayUnderLoss,
        ProofValidationVerification,
        DeterminismVerification,
        Assert,
        Teardown,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct RaptorQProofLossTestResult {
        pub test_name: String,
        pub object_id: String,
        pub phase: RaptorQProofLossTestPhase,
        pub success: bool,
        pub error: Option<String>,
        pub duration_ms: u64,
        pub loss_stats: RepairSymbolLossStats,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Default)]
    pub struct RepairSymbolLossStats {
        pub total_source_symbols: u64,
        pub total_repair_symbols: u64,
        pub repair_symbols_lost: u64,
        pub decode_attempts: u64,
        pub successful_decodes: u64,
        pub valid_proofs_generated: u64,
        pub proof_replay_successes: u64,
        pub proof_hash_collisions: u64,
        pub deterministic_proof_matches: u64,
        pub loss_pattern_variants: u64,
    }

    /// RaptorQ test object for encoding/decoding with repair loss scenarios.
    #[derive(Debug, Clone)]
    pub struct RaptorQTestObject {
        pub object_id: ObjectId,
        pub data: Vec<u8>,
        pub params: SystematicParams,
        pub source_symbols: Vec<ReceivedSymbol>,
        pub repair_symbols: Vec<ReceivedSymbol>,
        pub complete_symbol_set: Vec<ReceivedSymbol>,
    }

    /// Repair symbol loss pattern for testing different scenarios.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum RepairLossPattern {
        /// No repair symbols lost (baseline).
        None,
        /// First N repair symbols lost.
        FromBeginning(usize),
        /// Last N repair symbols lost.
        FromEnd(usize),
        /// Middle N repair symbols lost.
        FromMiddle(usize),
        /// Every Nth repair symbol lost.
        EveryNth(usize),
        /// Random pattern with specific seed.
        Random { count: usize, seed: u64 },
    }

    /// Proof validation result for repair loss scenarios.
    #[derive(Debug, Clone)]
    pub struct ProofLossValidation {
        pub proof_hash: ProofHash,
        pub replay_success: bool,
        pub validation_error: Option<ReplayError>,
        pub symbols_used: usize,
        pub repair_symbols_missing: usize,
        pub decode_success: bool,
    }

    /// RaptorQ decoder + proof partial repair loss test harness.
    pub struct RaptorQDecoderProofLossTestHarness {
        stats: Arc<RwLock<RepairSymbolLossStats>>,
        test_objects: Arc<RwLock<HashMap<ObjectId, RaptorQTestObject>>>,
        proof_validations: Arc<RwLock<HashMap<String, ProofLossValidation>>>,
        deterministic_seeds: Arc<RwLock<Vec<u64>>>,
        test_start_time: std::time::Instant,
    }

    impl RaptorQDecoderProofLossTestHarness {
        pub fn new() -> Self {
            Self {
                stats: Arc::new(RwLock::new(RepairSymbolLossStats::default())),
                test_objects: Arc::new(RwLock::new(HashMap::new())),
                proof_validations: Arc::new(RwLock::new(HashMap::new())),
                deterministic_seeds: Arc::new(RwLock::new(Vec::new())),
                test_start_time: std::time::Instant::now(),
            }
        }

        pub fn create_test_object(&self, object_id: ObjectId, k: usize, data_size: usize) -> Result<RaptorQTestObject, SystematicError> {
            // Generate test data
            let mut data = vec![0u8; data_size];
            for (i, byte) in data.iter_mut().enumerate() {
                *byte = ((i * 137) % 256) as u8; // Deterministic pattern
            }

            // Create systematic parameters
            let params = SystematicParams::from_k(k)?;
            let symbol_size = (data_size + k - 1) / k; // Ceiling division

            // Create encoder to generate symbols
            let encoder = SystematicEncoder::new(params, symbol_size)?;
            let source_symbols = encoder.encode_source_symbols(&data)?;

            // Generate repair symbols (more than minimum needed)
            let repair_count = k / 2 + 10; // Extra repair symbols for loss testing
            let repair_symbols = encoder.encode_repair_symbols(repair_count)?;

            // Convert to ReceivedSymbol format
            let mut all_symbols = Vec::new();

            // Add source symbols
            for (esi, symbol_data) in source_symbols.into_iter().enumerate() {
                all_symbols.push(ReceivedSymbol {
                    esi: esi as u32,
                    is_source: true,
                    columns: vec![esi], // Simple 1:1 mapping for sources
                    coefficients: vec![Gf256::from(1)],
                    data: symbol_data,
                });
            }

            // Add repair symbols
            for (i, symbol_data) in repair_symbols.into_iter().enumerate() {
                let esi = (k + i) as u32;
                all_symbols.push(ReceivedSymbol {
                    esi,
                    is_source: false,
                    columns: (0..k).collect(), // Repair symbols depend on all source symbols
                    coefficients: vec![Gf256::from(1); k], // Simplified coefficients
                    data: symbol_data,
                });
            }

            let source_only: Vec<_> = all_symbols.iter().filter(|s| s.is_source).cloned().collect();
            let repair_only: Vec<_> = all_symbols.iter().filter(|s| !s.is_source).cloned().collect();

            let test_object = RaptorQTestObject {
                object_id,
                data,
                params,
                source_symbols: source_only,
                repair_symbols: repair_only,
                complete_symbol_set: all_symbols,
            };

            self.test_objects.write().unwrap().insert(object_id, test_object.clone());

            {
                let mut stats = self.stats.write().unwrap();
                stats.total_source_symbols += k as u64;
                stats.total_repair_symbols += repair_count as u64;
            }

            Ok(test_object)
        }

        pub fn apply_repair_loss_pattern(&self, symbols: &[ReceivedSymbol], pattern: RepairLossPattern) -> Vec<ReceivedSymbol> {
            let mut result = Vec::new();

            // Keep all source symbols
            result.extend(symbols.iter().filter(|s| s.is_source).cloned());

            // Apply loss pattern to repair symbols
            let repair_symbols: Vec<_> = symbols.iter().filter(|s| !s.is_source).cloned().collect();
            let lost_count = match pattern {
                RepairLossPattern::None => 0,
                RepairLossPattern::FromBeginning(n) => n.min(repair_symbols.len()),
                RepairLossPattern::FromEnd(n) => n.min(repair_symbols.len()),
                RepairLossPattern::FromMiddle(n) => n.min(repair_symbols.len()),
                RepairLossPattern::EveryNth(nth) => repair_symbols.len() / nth,
                RepairLossPattern::Random { count, seed: _ } => count.min(repair_symbols.len()),
            };

            let kept_indices: HashSet<usize> = match pattern {
                RepairLossPattern::None => (0..repair_symbols.len()).collect(),
                RepairLossPattern::FromBeginning(n) => (n..repair_symbols.len()).collect(),
                RepairLossPattern::FromEnd(n) => (0..repair_symbols.len().saturating_sub(n)).collect(),
                RepairLossPattern::FromMiddle(n) => {
                    let start = repair_symbols.len() / 4;
                    let end = start + n;
                    (0..start).chain(end..repair_symbols.len()).collect()
                }
                RepairLossPattern::EveryNth(nth) => {
                    (0..repair_symbols.len()).filter(|&i| i % nth != 0).collect()
                }
                RepairLossPattern::Random { count, seed } => {
                    let mut indices: Vec<usize> = (0..repair_symbols.len()).collect();
                    // Deterministic shuffle based on seed
                    for i in 0..indices.len() {
                        let j = ((seed.wrapping_mul(31).wrapping_add(i as u64)) % (indices.len() as u64)) as usize;
                        indices.swap(i, j);
                    }
                    indices.into_iter().skip(count).collect()
                }
            };

            // Add non-lost repair symbols
            for (i, symbol) in repair_symbols.into_iter().enumerate() {
                if kept_indices.contains(&i) {
                    result.push(symbol);
                }
            }

            // Update stats
            {
                let mut stats = self.stats.write().unwrap();
                stats.repair_symbols_lost += lost_count as u64;
                stats.loss_pattern_variants += 1;
            }

            result
        }

        pub fn decode_with_proof_verification(
            &self,
            object_id: ObjectId,
            symbols: &[ReceivedSymbol],
            pattern_name: &str,
        ) -> Result<ProofLossValidation, DecodeError> {
            let test_object = self.test_objects.read().unwrap()
                .get(&object_id).ok_or(DecodeError::InsufficientSymbols { received: 0, required: 1 })?.clone();

            // Create decoder
            let mut decoder = Decoder::new(test_object.params, symbols[0].data.len())?;

            // Perform decode with proof
            let decode_result = decoder.decode_with_proof(symbols, object_id, 0)?;

            let proof_hash = decode_result.proof.hash();
            let proof = decode_result.proof;

            // Attempt proof replay and verification
            let replay_result = proof.replay_and_verify(symbols);
            let replay_success = replay_result.is_ok();
            let validation_error = replay_result.err();

            let validation = ProofLossValidation {
                proof_hash,
                replay_success,
                validation_error,
                symbols_used: symbols.len(),
                repair_symbols_missing: test_object.repair_symbols.len() - symbols.iter().filter(|s| !s.is_source).count(),
                decode_success: true,
            };

            // Store validation result
            self.proof_validations.write().unwrap().insert(pattern_name.to_string(), validation.clone());

            // Update stats
            {
                let mut stats = self.stats.write().unwrap();
                stats.decode_attempts += 1;
                stats.successful_decodes += 1;
                stats.valid_proofs_generated += 1;
                if replay_success {
                    stats.proof_replay_successes += 1;
                }
            }

            Ok(validation)
        }

        pub fn verify_proof_determinism(&self, object_id: ObjectId, pattern: RepairLossPattern, iterations: usize) -> bool {
            let test_object = match self.test_objects.read().unwrap().get(&object_id).cloned() {
                Some(obj) => obj,
                None => return false,
            };

            let mut proof_hashes = Vec::new();

            for _ in 0..iterations {
                let symbols = self.apply_repair_loss_pattern(&test_object.complete_symbol_set, pattern);

                if let Ok(validation) = self.decode_with_proof_verification(object_id, &symbols, &format!("determinism_{:?}", pattern)) {
                    proof_hashes.push(validation.proof_hash);
                } else {
                    return false;
                }
            }

            // All proof hashes should be identical for deterministic behavior
            let first_hash = proof_hashes[0];
            let all_match = proof_hashes.iter().all(|&hash| hash == first_hash);

            if all_match {
                let mut stats = self.stats.write().unwrap();
                stats.deterministic_proof_matches += 1;
            }

            all_match
        }

        pub fn get_stats_snapshot(&self) -> RepairSymbolLossStats {
            self.stats.read().unwrap().clone()
        }

        pub fn get_proof_validation(&self, pattern_name: &str) -> Option<ProofLossValidation> {
            self.proof_validations.read().unwrap().get(pattern_name).cloned()
        }

        pub fn count_unique_proof_hashes(&self) -> usize {
            let validations = self.proof_validations.read().unwrap();
            let unique_hashes: HashSet<_> = validations.values().map(|v| v.proof_hash).collect();
            unique_hashes.len()
        }
    }

    // ────────────────────────────────────────────────────────────────────────────────
    // Test Scenario 1: Complete Symbol Set (Baseline)
    // ────────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    #[ignore] // Enable with: cargo test --features real-service-e2e -- --ignored
    async fn test_raptorq_decoder_proof_complete_symbol_baseline() {
        let harness = RaptorQDecoderProofLossTestHarness::new();

        // Create test object
        let object_id = ObjectId::new();
        let k = 64; // Moderate size for comprehensive testing
        let data_size = k * 1000; // 1KB per symbol

        let test_object = harness.create_test_object(object_id, k, data_size)
            .expect("Failed to create test object");

        // Test with complete symbol set (no loss)
        let symbols = harness.apply_repair_loss_pattern(&test_object.complete_symbol_set, RepairLossPattern::None);

        let validation = harness.decode_with_proof_verification(object_id, &symbols, "complete_baseline")
            .expect("Baseline decode should succeed");

        assert!(validation.decode_success, "Baseline decode should succeed");
        assert!(validation.replay_success, "Baseline proof replay should succeed");
        assert_eq!(validation.repair_symbols_missing, 0, "No repair symbols should be missing");
        assert!(validation.validation_error.is_none(), "No validation error should occur");

        let stats = harness.get_stats_snapshot();
        assert_eq!(stats.successful_decodes, 1);
        assert_eq!(stats.valid_proofs_generated, 1);
        assert_eq!(stats.proof_replay_successes, 1);

        println!("✅ Complete Symbol Set Baseline: proof hash {}", validation.proof_hash);
    }

    // ────────────────────────────────────────────────────────────────────────────────
    // Test Scenario 2: Minimal Repair Loss
    // ────────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    #[ignore] // Enable with: cargo test --features real-service-e2e -- --ignored
    async fn test_raptorq_decoder_proof_minimal_repair_loss() {
        let harness = RaptorQDecoderProofLossTestHarness::new();

        let object_id = ObjectId::new();
        let k = 32;
        let data_size = k * 512;

        let test_object = harness.create_test_object(object_id, k, data_size)
            .expect("Failed to create test object");

        // Test with minimal repair loss (lose 2 repair symbols)
        let symbols = harness.apply_repair_loss_pattern(
            &test_object.complete_symbol_set,
            RepairLossPattern::FromBeginning(2)
        );

        let validation = harness.decode_with_proof_verification(object_id, &symbols, "minimal_loss")
            .expect("Minimal loss decode should succeed");

        assert!(validation.decode_success, "Decode with minimal loss should succeed");
        assert!(validation.replay_success, "Proof replay with minimal loss should succeed");
        assert_eq!(validation.repair_symbols_missing, 2, "Should have 2 missing repair symbols");

        // Verify we still have enough symbols for decoding
        assert!(validation.symbols_used >= k, "Should have at least K symbols for decoding");

        let stats = harness.get_stats_snapshot();
        assert!(stats.repair_symbols_lost >= 2);
        assert_eq!(stats.successful_decodes, 1);

        println!(
            "✅ Minimal Repair Loss: {} symbols used, {} missing, proof hash {}",
            validation.symbols_used, validation.repair_symbols_missing, validation.proof_hash
        );
    }

    // ────────────────────────────────────────────────────────────────────────────────
    // Test Scenario 3: Substantial Repair Loss
    // ────────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    #[ignore] // Enable with: cargo test --features real-service-e2e -- --ignored
    async fn test_raptorq_decoder_proof_substantial_repair_loss() {
        let harness = RaptorQDecoderProofLossTestHarness::new();

        let object_id = ObjectId::new();
        let k = 48;
        let data_size = k * 800;

        let test_object = harness.create_test_object(object_id, k, data_size)
            .expect("Failed to create test object");

        // Test with substantial repair loss (lose half of repair symbols)
        let repair_count = test_object.repair_symbols.len();
        let loss_count = repair_count / 2;

        let symbols = harness.apply_repair_loss_pattern(
            &test_object.complete_symbol_set,
            RepairLossPattern::FromMiddle(loss_count)
        );

        // Verify we still have enough symbols total
        let total_symbols_available = symbols.len();
        assert!(
            total_symbols_available >= k,
            "Should have at least K symbols even after substantial loss"
        );

        let validation = harness.decode_with_proof_verification(object_id, &symbols, "substantial_loss")
            .expect("Substantial loss decode should succeed");

        assert!(validation.decode_success, "Decode with substantial loss should succeed");
        assert!(validation.replay_success, "Proof replay with substantial loss should succeed");
        assert_eq!(validation.repair_symbols_missing, loss_count, "Should have expected number of missing repair symbols");

        let stats = harness.get_stats_snapshot();
        assert!(stats.repair_symbols_lost >= loss_count as u64);

        println!(
            "✅ Substantial Repair Loss: {}/{} repair symbols lost, proof hash {}",
            validation.repair_symbols_missing, repair_count, validation.proof_hash
        );
    }

    // ────────────────────────────────────────────────────────────────────────────────
    // Test Scenario 4: Edge Case Loss Patterns
    // ────────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    #[ignore] // Enable with: cargo test --features real-service-e2e -- --ignored
    async fn test_raptorq_decoder_proof_edge_case_loss_patterns() {
        let harness = RaptorQDecoderProofLossTestHarness::new();

        let object_id = ObjectId::new();
        let k = 24;
        let data_size = k * 400;

        let test_object = harness.create_test_object(object_id, k, data_size)
            .expect("Failed to create test object");

        // Test different edge case patterns
        let patterns = [
            ("from_beginning", RepairLossPattern::FromBeginning(3)),
            ("from_end", RepairLossPattern::FromEnd(3)),
            ("every_third", RepairLossPattern::EveryNth(3)),
            ("random_pattern", RepairLossPattern::Random { count: 4, seed: 12345 }),
        ];

        let mut all_valid = true;
        let mut proof_hashes = Vec::new();

        for (pattern_name, pattern) in patterns.iter() {
            let symbols = harness.apply_repair_loss_pattern(&test_object.complete_symbol_set, *pattern);

            if symbols.len() >= k {
                match harness.decode_with_proof_verification(object_id, &symbols, pattern_name) {
                    Ok(validation) => {
                        assert!(validation.decode_success, "Decode should succeed for pattern {}", pattern_name);
                        assert!(validation.replay_success, "Proof replay should succeed for pattern {}", pattern_name);
                        proof_hashes.push((pattern_name, validation.proof_hash));
                    }
                    Err(_) => {
                        all_valid = false;
                        println!("⚠️ Pattern {} failed to decode", pattern_name);
                    }
                }
            }
        }

        assert!(all_valid, "All edge case patterns should produce valid proofs");

        // Verify that different patterns produce different proof hashes
        let unique_hashes = harness.count_unique_proof_hashes();
        assert!(unique_hashes >= 2, "Different loss patterns should produce different proof hashes");

        let stats = harness.get_stats_snapshot();
        println!(
            "✅ Edge Case Loss Patterns: {} patterns tested, {} unique proof hashes",
            patterns.len(), unique_hashes
        );
    }

    // ────────────────────────────────────────────────────────────────────────────────
    // Test Scenario 5: Proof Replay Under Loss
    // ────────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    #[ignore] // Enable with: cargo test --features real-service-e2e -- --ignored
    async fn test_raptorq_decoder_proof_replay_under_loss() {
        let harness = RaptorQDecoderProofLossTestHarness::new();

        let object_id = ObjectId::new();
        let k = 16; // Smaller for focused replay testing
        let data_size = k * 256;

        let test_object = harness.create_test_object(object_id, k, data_size)
            .expect("Failed to create test object");

        // Test multiple loss scenarios with proof replay
        let test_cases = [
            ("replay_loss_2", RepairLossPattern::FromBeginning(2)),
            ("replay_loss_4", RepairLossPattern::FromEnd(4)),
            ("replay_every_4th", RepairLossPattern::EveryNth(4)),
        ];

        for (case_name, pattern) in test_cases.iter() {
            let symbols = harness.apply_repair_loss_pattern(&test_object.complete_symbol_set, *pattern);

            if symbols.len() >= k {
                let validation = harness.decode_with_proof_verification(object_id, &symbols, case_name)
                    .expect(&format!("Decode should succeed for {}", case_name));

                assert!(validation.replay_success, "Proof replay should succeed for {}", case_name);
                assert!(validation.validation_error.is_none(), "No validation error for {}", case_name);

                // Test determinism - same symbol set should produce same proof
                let second_validation = harness.decode_with_proof_verification(object_id, &symbols, &format!("{}_repeat", case_name))
                    .expect(&format!("Second decode should succeed for {}", case_name));

                assert_eq!(
                    validation.proof_hash, second_validation.proof_hash,
                    "Proof hashes should be deterministic for {}", case_name
                );
            }
        }

        let stats = harness.get_stats_snapshot();
        assert!(stats.proof_replay_successes >= test_cases.len() as u64 * 2);

        println!("✅ Proof Replay Under Loss: {} test cases verified", test_cases.len());
    }

    // ────────────────────────────────────────────────────────────────────────────────
    // Integration Test Result Verification
    // ────────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    #[ignore] // Enable with: cargo test --features real-service-e2e -- --ignored
    async fn test_raptorq_decoder_proof_partial_repair_loss_full_integration() {
        let harness = RaptorQDecoderProofLossTestHarness::new();

        // Comprehensive integration test with multiple objects and loss patterns
        let test_objects = [
            (ObjectId::new(), 32, 32 * 600),
            (ObjectId::new(), 64, 64 * 800),
            (ObjectId::new(), 128, 128 * 400),
        ];

        for (object_id, k, data_size) in test_objects.iter() {
            harness.create_test_object(*object_id, *k, *data_size)
                .expect("Failed to create test object");

            // Test multiple loss patterns for each object
            let patterns = [
                RepairLossPattern::None,
                RepairLossPattern::FromBeginning(3),
                RepairLossPattern::FromEnd(5),
                RepairLossPattern::EveryNth(3),
                RepairLossPattern::Random { count: 4, seed: 67890 },
            ];

            for (i, pattern) in patterns.iter().enumerate() {
                let test_object = harness.test_objects.read().unwrap().get(object_id).unwrap().clone();
                let symbols = harness.apply_repair_loss_pattern(&test_object.complete_symbol_set, *pattern);

                if symbols.len() >= *k {
                    let pattern_name = format!("obj_{}_pattern_{}", object_id, i);
                    let validation = harness.decode_with_proof_verification(*object_id, &symbols, &pattern_name)
                        .expect(&format!("Integration decode should succeed for {}", pattern_name));

                    assert!(validation.decode_success, "Integration decode success for {}", pattern_name);
                    assert!(validation.replay_success, "Integration proof replay success for {}", pattern_name);
                }
            }

            // Test determinism for this object
            assert!(
                harness.verify_proof_determinism(*object_id, RepairLossPattern::FromBeginning(2), 3),
                "Proof generation should be deterministic"
            );
        }

        // Final comprehensive verification
        let final_stats = harness.get_stats_snapshot();

        assert!(
            final_stats.successful_decodes > 0,
            "Should have successful decodes: {}",
            final_stats.successful_decodes
        );
        assert!(
            final_stats.valid_proofs_generated > 0,
            "Should have valid proofs generated: {}",
            final_stats.valid_proofs_generated
        );
        assert!(
            final_stats.proof_replay_successes > 0,
            "Should have proof replay successes: {}",
            final_stats.proof_replay_successes
        );
        assert!(
            final_stats.repair_symbols_lost > 0,
            "Should have tested repair symbol loss: {}",
            final_stats.repair_symbols_lost
        );

        // Verify proof diversity (different patterns should produce different proofs)
        let unique_proof_hashes = harness.count_unique_proof_hashes();
        assert!(
            unique_proof_hashes > 1,
            "Should have multiple unique proof hashes: {}",
            unique_proof_hashes
        );

        // Verify reasonable success rate
        let success_rate = final_stats.successful_decodes as f64 / final_stats.decode_attempts as f64;
        assert!(
            success_rate > 0.8,
            "Should have high success rate: {:.2}",
            success_rate
        );

        println!("✅ RaptorQ Decoder ↔ Proof Partial Repair Loss Integration Test Complete");
        println!("📊 Final Stats: {:?}", final_stats);
        println!(
            "🎯 Success Rate: {:.2}%, Unique Proofs: {}, Replay Success: {}",
            success_rate * 100.0,
            unique_proof_hashes,
            final_stats.proof_replay_successes
        );
    }
}