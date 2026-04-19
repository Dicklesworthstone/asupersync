//! RaptorQ Decoder Metamorphic Testing (asupersync-1ucsnc)
//!
//! Focused metamorphic testing for RaptorQ decoder under systematic erasure patterns.
//! Tests verify decoder-specific invariants with deterministic lab runtime:
//! 1. Adding more than K encoded symbols never degrades decode success (monotone)
//! 2. Receiving exact systematic prefix (K source symbols) always decodes via identity path
//! 3. Symbol permutation preserves decoded payload
//! 4. Any K-subset from [0..N) suffices to decode with high probability per RFC 6330
//! 5. Partial decode failure + additional repair symbols converges to success
//!
//! Uses proptest with lab-runtime fixed seeds for deterministic, reproducible results.

#[macro_use]
mod common;

#[cfg(feature = "tls")]
mod raptorq_decoder_metamorphic_tests {
    use crate::common::init_test_logging;
    use asupersync::config::RaptorQConfig;
    use asupersync::cx::Cx;
    use asupersync::raptorq::builder::RaptorQSenderBuilder;
    use asupersync::raptorq::decoder::{InactivationDecoder, ReceivedSymbol};
    use asupersync::security::AuthenticatedSymbol;
    use asupersync::transport::sink::SymbolSink;
    use asupersync::types::ObjectId;
    use asupersync::util::DetRng;
    use proptest::prelude::*;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    // ============================================================================
    // Test Infrastructure with Lab Runtime
    // ============================================================================

    /// Deterministic symbol sink for lab runtime testing
    #[derive(Debug)]
    pub struct DeterministicSink {
        symbols: Vec<AuthenticatedSymbol>,
        seed: u64,
    }

    impl DeterministicSink {
        fn new(seed: u64) -> Self {
            Self {
                symbols: Vec::new(),
                seed,
            }
        }

        pub fn symbols(&self) -> &[AuthenticatedSymbol] {
            &self.symbols
        }
    }

    impl SymbolSink for DeterministicSink {
        fn poll_send(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            symbol: AuthenticatedSymbol,
        ) -> Poll<Result<(), asupersync::transport::error::SinkError>> {
            self.symbols.push(symbol);
            Poll::Ready(Ok(()))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), asupersync::transport::error::SinkError>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), asupersync::transport::error::SinkError>> {
            Poll::Ready(Ok(()))
        }

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), asupersync::transport::error::SinkError>> {
            Poll::Ready(Ok(()))
        }
    }

    impl Unpin for DeterministicSink {}

    fn generate_deterministic_data(size: usize, seed: u64) -> Vec<u8> {
        let mut rng = DetRng::new(seed);
        (0..size).map(|_| rng.next_u32() as u8).collect()
    }

    fn seed_for_block(object_id: ObjectId, sbn: u8) -> u64 {
        let obj = object_id.as_u128();
        let hi = (obj >> 64) as u64;
        let lo = obj as u64;
        let mut seed = hi ^ lo.rotate_left(13);
        seed ^= u64::from(sbn) << 56;
        if seed == 0 { 1 } else { seed }
    }

    fn symbols_to_received_symbols(
        symbols: &[AuthenticatedSymbol],
        k: usize,
    ) -> Vec<ReceivedSymbol> {
        let Some(first) = symbols.first() else {
            return Vec::new();
        };

        let first_symbol = first.symbol();
        let seed = seed_for_block(first_symbol.object_id(), first_symbol.sbn());
        let decoder = InactivationDecoder::new(k, first_symbol.len(), seed);
        let mut received = Vec::with_capacity(symbols.len());

        for auth_symbol in symbols {
            let symbol = auth_symbol.symbol();
            assert_eq!(
                symbol.object_id(),
                first_symbol.object_id(),
                "metamorphic helper requires a single object per decode set"
            );
            assert_eq!(
                symbol.sbn(),
                first_symbol.sbn(),
                "metamorphic helper requires a single source block per decode set"
            );

            let row = match symbol.kind() {
                asupersync::types::SymbolKind::Source => {
                    ReceivedSymbol::source(symbol.esi(), symbol.data().to_vec())
                }
                asupersync::types::SymbolKind::Repair => {
                    let (columns, coefficients) = decoder.repair_equation(symbol.esi());
                    ReceivedSymbol::repair(
                        symbol.esi(),
                        columns,
                        coefficients,
                        symbol.data().to_vec(),
                    )
                }
            };
            received.push(row);
        }

        received
    }

    fn create_test_decoder(
        symbols: &[AuthenticatedSymbol],
        k: usize,
        symbol_size: usize,
    ) -> InactivationDecoder {
        let first_symbol = symbols
            .first()
            .expect("metamorphic decode sets must contain at least one symbol")
            .symbol();
        let seed = seed_for_block(first_symbol.object_id(), first_symbol.sbn());
        InactivationDecoder::new(k, symbol_size, seed)
    }

    fn reconstruct_original_data(source_symbols: &[Vec<u8>], original_len: usize) -> Vec<u8> {
        source_symbols
            .iter()
            .flatten()
            .copied()
            .take(original_len)
            .collect()
    }

    // ============================================================================
    // MR 1: Symbol Addition Monotonicity
    // ============================================================================

    #[test]
    fn mr1_symbol_addition_monotonicity() {
        init_test_logging();
        test_phase!("mr1_symbol_addition_monotonicity");

        proptest!(|(
            data_size in 256usize..512,
            seed in 1000u64..2000u64,
            extra_symbols in 1usize..5,
        )| {
            test_section!("encoding_phase");

            let data = generate_deterministic_data(data_size, seed);
            let object_id = ObjectId::new_for_test(seed);

            let config = RaptorQConfig {
                encoding: asupersync::config::EncodingConfig {
                    repair_overhead: 1.20, // 20% overhead for extra symbols
                    symbol_size: 512,
                    ..Default::default()
                },
                ..Default::default()
            };

            let sink = DeterministicSink::new(seed);
            let mut sender = RaptorQSenderBuilder::new()
                .config(config.clone())
                .transport(sink)
                .build()
                .expect("sender build");

            let cx = Cx::for_testing();
            let send_outcome = sender
                .send_object(&cx, object_id, &data)
                .expect("encoding should succeed");
            let symbols = sender.transport_mut().symbols().to_vec();

            test_section!("decoder_setup");

            let k = send_outcome.source_symbols;
            let symbol_size = config.encoding.symbol_size as usize;
            let decoder = create_test_decoder(&symbols, k, symbol_size);

            // Test with minimal symbol count (K + small overhead)
            let minimal_count = std::cmp::min(symbols.len(), k + 2);
            let minimal_symbols = symbols_to_received_symbols(&symbols[..minimal_count], k);

            // Test with additional symbols
            let extended_count = std::cmp::min(symbols.len(), minimal_count + extra_symbols);
            let extended_symbols = symbols_to_received_symbols(&symbols[..extended_count], k);

            test_section!("decode_testing");

            let minimal_result = decoder.decode(&minimal_symbols);
            let extended_result = decoder.decode(&extended_symbols);

            // MR1 ASSERTION: Adding symbols should never degrade success
            match minimal_result {
                Ok(minimal_decoded) => {
                    let minimal_data = reconstruct_original_data(&minimal_decoded.source, data.len());

                    match extended_result {
                        Ok(extended_decoded) => {
                            let extended_data =
                                reconstruct_original_data(&extended_decoded.source, data.len());
                            prop_assert_eq!(
                                &minimal_data, &extended_data,
                                "MR1 VIOLATION: adding {} symbols changed decode result",
                                extra_symbols
                            );
                            prop_assert_eq!(
                                &minimal_data, &data,
                                "MR1 VIOLATION: decode result doesn't match original"
                            );
                        }
                        Err(e) => {
                            prop_assert!(
                                false,
                                "MR1 VIOLATION: adding {} symbols degraded decode success: {:?}",
                                extra_symbols, e
                            );
                        }
                    }
                }
                Err(_) => {
                    // Minimal failed - extended may succeed (this is allowed monotonicity)
                    // We don't assert anything here as additional symbols might help
                }
            }
        });

        test_complete!("mr1_symbol_addition_monotonicity");
    }

    // ============================================================================
    // MR 2: Systematic Prefix Identity Path
    // ============================================================================

    #[test]
    fn mr2_systematic_prefix_identity_path() {
        init_test_logging();
        test_phase!("mr2_systematic_prefix_identity_path");

        proptest!(|(
            data_size in 256usize..512,
            seed in 2000u64..3000u64,
        )| {
            test_section!("systematic_encoding");

            let data = generate_deterministic_data(data_size, seed);
            let object_id = ObjectId::new_for_test(seed);

            let config = RaptorQConfig {
                encoding: asupersync::config::EncodingConfig {
                    repair_overhead: 1.10, // Minimal overhead for systematic test
                    symbol_size: 512,
                    ..Default::default()
                },
                ..Default::default()
            };

            let sink = DeterministicSink::new(seed);
            let mut sender = RaptorQSenderBuilder::new()
                .config(config.clone())
                .transport(sink)
                .build()
                .expect("sender build");

            let cx = Cx::for_testing();
            let send_outcome = sender
                .send_object(&cx, object_id, &data)
                .expect("encoding should succeed");
            let symbols = sender.transport_mut().symbols().to_vec();

            test_section!("systematic_prefix_test");

            let k = send_outcome.source_symbols;
            let symbol_size = config.encoding.symbol_size as usize;
            let decoder = create_test_decoder(&symbols, k, symbol_size);

            // Test with exactly K systematic symbols (should always decode via identity)
            let systematic_result = if symbols.len() >= k {
                let systematic_symbols = symbols_to_received_symbols(&symbols[..k], k);
                let result = decoder.decode(&systematic_symbols);

                // MR2 ASSERTION: K source symbols should always decode via identity
                match &result {
                    Ok(decoded) => {
                        let reconstructed =
                            reconstruct_original_data(&decoded.source, data.len());
                        prop_assert_eq!(
                            &reconstructed, &data,
                            "MR2 VIOLATION: systematic prefix failed identity decode"
                        );
                    }
                    Err(e) => {
                        prop_assert!(
                            false,
                            "MR2 VIOLATION: systematic prefix decode failed: {:?}",
                            e
                        );
                    }
                }
                Some(result)
            } else {
                None
            };

            test_section!("mixed_symbol_comparison");

            // Compare with mixed source+repair symbols for same result
            if symbols.len() >= k + 3 {
                let mixed_symbols = symbols_to_received_symbols(&symbols[..k + 3], k);
                let mixed_result = decoder.decode(&mixed_symbols);

                if let (Some(Ok(sys_decoded)), Ok(mixed_decoded)) =
                    (systematic_result.as_ref(), &mixed_result)
                {
                    let sys_data = reconstruct_original_data(&sys_decoded.source, data.len());
                    let mixed_data = reconstruct_original_data(&mixed_decoded.source, data.len());
                    prop_assert_eq!(
                        &sys_data, &mixed_data,
                        "MR2 VIOLATION: systematic vs mixed symbol sets differ"
                    );
                }
            }
        });

        test_complete!("mr2_systematic_prefix_identity_path");
    }

    // ============================================================================
    // MR 3: Symbol Permutation Invariance
    // ============================================================================

    #[test]
    fn mr3_symbol_permutation_invariance() {
        init_test_logging();
        test_phase!("mr3_symbol_permutation_invariance");

        proptest!(|(
            data_size in 256usize..384,
            seed in 3000u64..4000u64,
            shuffle_seed in any::<u64>(),
        )| {
            test_section!("encoding_for_permutation");

            let data = generate_deterministic_data(data_size, seed);
            let object_id = ObjectId::new_for_test(seed);

            let config = RaptorQConfig::default();
            let sink = DeterministicSink::new(seed);
            let mut sender = RaptorQSenderBuilder::new()
                .config(config.clone())
                .transport(sink)
                .build()
                .expect("sender build");

            let cx = Cx::for_testing();
            let send_outcome = sender
                .send_object(&cx, object_id, &data)
                .expect("encoding should succeed");
            let symbols = sender.transport_mut().symbols().to_vec();

            test_section!("permutation_testing");

            let k = send_outcome.source_symbols;
            let symbol_size = config.encoding.symbol_size as usize;
            let decoder = create_test_decoder(&symbols, k, symbol_size);

            // Create original symbol order
            let symbol_count = std::cmp::min(symbols.len(), k + 5);
            let original_symbols = symbols_to_received_symbols(&symbols[..symbol_count], k);

            // Create permuted symbol order
            let mut permuted_symbols = original_symbols.clone();
            let mut rng = DetRng::new(shuffle_seed);
            for i in (1..permuted_symbols.len()).rev() {
                let j = (rng.next_u32() as usize) % (i + 1);
                permuted_symbols.swap(i, j);
            }

            test_section!("decode_comparison");

            let original_result = decoder.decode(&original_symbols);
            let permuted_result = decoder.decode(&permuted_symbols);

            // MR3 ASSERTION: Symbol permutation should preserve decode result
            match (original_result, permuted_result) {
                (Ok(orig_decoded), Ok(perm_decoded)) => {
                    let orig_data = reconstruct_original_data(&orig_decoded.source, data.len());
                    let perm_data = reconstruct_original_data(&perm_decoded.source, data.len());
                    prop_assert_eq!(
                        &orig_data, &perm_data,
                        "MR3 VIOLATION: symbol permutation changed decode result"
                    );
                    prop_assert_eq!(
                        &orig_data, &data,
                        "MR3 VIOLATION: original decode failed identity"
                    );
                }
                (Ok(_), Err(e)) => {
                    prop_assert!(
                        false,
                        "MR3 VIOLATION: permutation caused decode failure: {:?}",
                        e
                    );
                }
                (Err(_), Ok(_)) => {
                    prop_assert!(false, "MR3 VIOLATION: permutation improved decode success");
                }
                (Err(_), Err(_)) => {
                    // Both failed - consistent behavior
                }
            }
        });

        test_complete!("mr3_symbol_permutation_invariance");
    }

    // ============================================================================
    // MR 4: K-Subset Decode Sufficiency (RFC 6330)
    // ============================================================================

    #[test]
    fn mr4_k_subset_decode_sufficiency() {
        init_test_logging();
        test_phase!("mr4_k_subset_decode_sufficiency");

        proptest!(|(
            data_size in 256usize..384,
            seed in 4000u64..5000u64,
            subset_seed in any::<u64>(),
        )| {
            test_section!("encoding_for_subsets");

            let data = generate_deterministic_data(data_size, seed);
            let object_id = ObjectId::new_for_test(seed);

            let config = RaptorQConfig {
                encoding: asupersync::config::EncodingConfig {
                    repair_overhead: 1.50, // High overhead for subset testing
                    symbol_size: 512,
                    ..Default::default()
                },
                ..Default::default()
            };

            let sink = DeterministicSink::new(seed);
            let mut sender = RaptorQSenderBuilder::new()
                .config(config.clone())
                .transport(sink)
                .build()
                .expect("sender build");

            let cx = Cx::for_testing();
            let send_outcome = sender
                .send_object(&cx, object_id, &data)
                .expect("encoding should succeed");
            let symbols = sender.transport_mut().symbols().to_vec();

            test_section!("k_subset_selection");

            let k = send_outcome.source_symbols;
            let symbol_size = config.encoding.symbol_size as usize;
            let decoder = create_test_decoder(&symbols, k, symbol_size);

            // Test multiple random K-subsets from available symbols
            if symbols.len() >= k + 10 {
                let mut rng = DetRng::new(subset_seed);
                let mut subset_results = Vec::new();

                for subset_id in 0..3 {
                    test_section!(format!("subset_{}", subset_id));

                    // Select random K symbols from available set
                    let mut selected_indices: Vec<usize> = (0..symbols.len()).collect();

                    // Fisher-Yates shuffle for random selection
                    for i in (1..selected_indices.len()).rev() {
                        let j = (rng.next_u32() as usize) % (i + 1);
                        selected_indices.swap(i, j);
                    }
                    selected_indices.truncate(k);
                    selected_indices.sort(); // Deterministic ordering

                    let subset_auth_symbols: Vec<_> = selected_indices
                        .iter()
                        .map(|&idx| symbols[idx].clone())
                        .collect();

                    let subset_symbols = symbols_to_received_symbols(&subset_auth_symbols, k);
                    let subset_result = decoder.decode(&subset_symbols);

                    subset_results.push((subset_id, subset_result));
                }

                test_section!("k_subset_verification");

                // MR4 ASSERTION: Any K-subset should decode successfully with high probability
                let mut successful_decodes = Vec::new();
                for (subset_id, result) in &subset_results {
                    match result {
                        Ok(decoded) => {
                            let decoded_data =
                                reconstruct_original_data(&decoded.source, data.len());
                            prop_assert_eq!(
                                &decoded_data, &data,
                                "MR4 VIOLATION: K-subset {} decode failed identity",
                                subset_id
                            );
                            successful_decodes.push(decoded_data);
                        }
                        Err(e) => {
                            // Some K-subsets may fail due to unlucky selection,
                            // but most should succeed per RFC 6330
                            eprintln!("K-subset {} failed (may be acceptable): {:?}", subset_id, e);
                        }
                    }
                }

                // All successful decodes should produce identical results
                if successful_decodes.len() > 1 {
                    for (i, decoded) in successful_decodes.iter().enumerate() {
                        prop_assert_eq!(
                            &successful_decodes[0], decoded,
                            "MR4 VIOLATION: K-subset {} produced different result",
                            i
                        );
                    }
                }

                // With high repair overhead, we expect good decode success rate
                let success_rate = successful_decodes.len() as f64 / subset_results.len() as f64;
                prop_assert!(
                    success_rate >= 0.5, // At least 50% success rate expected with high overhead
                    "MR4 VIOLATION: K-subset success rate too low: {:.2}",
                    success_rate
                );
            }
        });

        test_complete!("mr4_k_subset_decode_sufficiency");
    }

    // ============================================================================
    // MR 5: Repair Symbol Convergence
    // ============================================================================

    #[test]
    fn mr5_repair_symbol_convergence() {
        init_test_logging();
        test_phase!("mr5_repair_symbol_convergence");

        proptest!(|(
            data_size in 256usize..384,
            seed in 5000u64..6000u64,
            convergence_steps in 2usize..6,
        )| {
            test_section!("convergence_encoding");

            let data = generate_deterministic_data(data_size, seed);
            let object_id = ObjectId::new_for_test(seed);

            let config = RaptorQConfig {
                encoding: asupersync::config::EncodingConfig {
                    repair_overhead: 1.40, // High overhead for convergence testing
                    symbol_size: 512,
                    ..Default::default()
                },
                ..Default::default()
            };

            let sink = DeterministicSink::new(seed);
            let mut sender = RaptorQSenderBuilder::new()
                .config(config.clone())
                .transport(sink)
                .build()
                .expect("sender build");

            let cx = Cx::for_testing();
            let send_outcome = sender
                .send_object(&cx, object_id, &data)
                .expect("encoding should succeed");
            let symbols = sender.transport_mut().symbols().to_vec();

            test_section!("convergence_testing");

            let k = send_outcome.source_symbols;
            let symbol_size = config.encoding.symbol_size as usize;
            let decoder = create_test_decoder(&symbols, k, symbol_size);

            // Test convergence by gradually adding repair symbols
            let mut convergence_results = Vec::new();

            for step in 1..=convergence_steps {
                test_section!(format!("convergence_step_{}", step));

                // Start with insufficient symbols, then add more
                let symbol_count = std::cmp::min(symbols.len(), k - 2 + step * 2);
                let step_symbols = symbols_to_received_symbols(&symbols[..symbol_count], k);
                let step_result = decoder.decode(&step_symbols);

                convergence_results.push((step, symbol_count, step_result));
            }

            test_section!("convergence_analysis");

            // MR5 ASSERTION: Adding repair symbols should converge to success
            let mut success_found = false;
            let mut first_success_step = None;

            for (step, _symbol_count, result) in &convergence_results {
                match result {
                    Ok(decoded) => {
                        let decoded_data = reconstruct_original_data(&decoded.source, data.len());
                        prop_assert_eq!(
                            &decoded_data, &data,
                            "MR5 VIOLATION: convergence step {} failed identity",
                            step
                        );

                        if !success_found {
                            success_found = true;
                            first_success_step = Some(*step);
                        }
                    }
                    Err(_) => {
                        // Early steps may fail - this is expected
                        if success_found {
                            prop_assert!(
                                false,
                                "MR5 VIOLATION: step {} failed after step {} succeeded",
                                step,
                                first_success_step.expect("success step must exist")
                            );
                        }
                    }
                }
            }

            // With sufficient repair overhead, we should eventually converge
            prop_assert!(
                success_found,
                "MR5 VIOLATION: no convergence found with {} steps",
                convergence_steps
            );

            test_section!("monotonic_convergence_check");

            // Once successful, all subsequent steps should also succeed (monotonicity)
            if let Some(first_success) = first_success_step {
                for (step, _, result) in &convergence_results {
                    if *step >= first_success {
                        prop_assert!(
                            result.is_ok(),
                            "MR5 VIOLATION: step {} failed after convergence at step {}",
                            step, first_success
                        );
                    }
                }
            }
        });

        test_complete!("mr5_repair_symbol_convergence");
    }

    // ============================================================================
    // Composite Metamorphic Relation: All Properties Together
    // ============================================================================

    #[test]
    fn mr_composite_decoder_invariants() {
        init_test_logging();
        test_phase!("mr_composite_decoder_invariants");

        proptest!(|(
            data_size in 256usize..384,
            seed in 6000u64..7000u64,
            shuffle_seed in any::<u64>(),
        )| {
            test_section!("composite_encoding");

            let data = generate_deterministic_data(data_size, seed);
            let object_id = ObjectId::new_for_test(seed);

            let config = RaptorQConfig {
                encoding: asupersync::config::EncodingConfig {
                    repair_overhead: 1.30,
                    symbol_size: 512,
                    ..Default::default()
                },
                ..Default::default()
            };

            let sink = DeterministicSink::new(seed);
            let mut sender = RaptorQSenderBuilder::new()
                .config(config.clone())
                .transport(sink)
                .build()
                .expect("sender build");

            let cx = Cx::for_testing();
            let send_outcome = sender
                .send_object(&cx, object_id, &data)
                .expect("encoding should succeed");
            let symbols = sender.transport_mut().symbols().to_vec();

            test_section!("composite_transformation");

            let k = send_outcome.source_symbols;
            let symbol_size = config.encoding.symbol_size as usize;
            let decoder = create_test_decoder(&symbols, k, symbol_size);

            // Apply multiple transformations: abundance + permutation + subset selection
            let abundant_count = std::cmp::min(symbols.len(), k + 8);
            let mut received_symbols = symbols_to_received_symbols(&symbols[..abundant_count], k);

            // Shuffle the abundant set
            let mut rng = DetRng::new(shuffle_seed);
            for i in (1..received_symbols.len()).rev() {
                let j = (rng.next_u32() as usize) % (i + 1);
                received_symbols.swap(i, j);
            }

            test_section!("composite_decode");

            let composite_result = decoder.decode(&received_symbols);

            // COMPOSITE ASSERTION: All metamorphic properties hold together
            match composite_result {
                Ok(decoded) => {
                    let reconstructed = reconstruct_original_data(&decoded.source, data.len());
                    prop_assert_eq!(
                        &reconstructed, &data,
                        "COMPOSITE MR VIOLATION: identity failed under abundance+shuffle+subset"
                    );
                }
                Err(e) => {
                    prop_assert!(
                        false,
                        "COMPOSITE MR VIOLATION: abundant+shuffled+subset symbols failed: {:?}",
                        e
                    );
                }
            }
        });

        test_complete!("mr_composite_decoder_invariants");
    }
}

#[cfg(not(feature = "tls"))]
mod raptorq_disabled_tests {
    #[test]
    fn mr_tests_require_tls_feature_for_lab_runtime() {
        println!("RaptorQ decoder metamorphic tests require 'tls' feature for lab runtime");
    }
}
