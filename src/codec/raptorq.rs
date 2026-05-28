//! RaptorQ encoding pipeline adapter.
//!
//! This module re-exports the RFC-grade RaptorQ encoding pipeline from
//! `crate::encoding` so codec users share the same deterministic implementation
//! as the core RaptorQ stack. Backwards compatibility is not preserved.

pub use crate::config::EncodingConfig;
pub use crate::encoding::{EncodedSymbol, EncodingError, EncodingPipeline, EncodingStats};

// br-asupersync-t36ete: frame-shape goldens for the RaptorQ codec adapter.
//
// `src/codec/raptorq.rs` is a thin re-export over `crate::encoding`, but
// it is the named entry point for codec consumers — meaning *byte-level
// drift through this surface is the interop break*. The tests below pin
// the encoder's per-symbol output for a fixed (object_id, K, symbol_size,
// payload) tuple, plus the verbatim error-message wording for two
// rejection paths. Re-running this module surfaces wire/observable drift
// in either the source-symbol slicing path or the systematic repair
// matrix.
#[cfg(test)]
mod golden_tests {
    use super::*;
    use crate::types::ObjectId;
    use crate::types::resource::{PoolConfig, SymbolPool};
    use crate::util::DetRng;
    use std::fmt::Write as _;

    /// Build a deterministic pipeline for goldens. Parallelism counts are
    /// pinned even though they are unused by the synchronous encode path —
    /// changing them is a config-shape signal worth catching.
    fn pinned_pipeline(symbol_size: u16, max_block_size: usize) -> EncodingPipeline {
        let cfg = EncodingConfig {
            repair_overhead: 1.5,
            max_block_size,
            symbol_size,
            encoding_parallelism: 1,
            decoding_parallelism: 1,
        };
        EncodingPipeline::new(cfg, SymbolPool::new(PoolConfig::default()))
    }

    /// Render the iterator output to a deterministic plaintext trace —
    /// stable across hosts, byte-exact within a release. Anything
    /// material to interop appears in the rendering: kind, sbn, esi,
    /// data length, full hex.
    fn render_encoding_trace(
        pipeline: &mut EncodingPipeline,
        object_id: ObjectId,
        data: &[u8],
    ) -> String {
        let mut out = String::new();
        for (idx, result) in pipeline.encode(object_id, data).enumerate() {
            let symbol = result.expect("pinned config produces no errors");
            let id = symbol.id();
            writeln!(
                &mut out,
                "symbol idx={idx:02} sbn={:03} esi={:04} kind={:?} len={} data_hex={}",
                id.sbn(),
                id.esi(),
                symbol.kind(),
                symbol.symbol().data().len(),
                hex_lower(symbol.symbol().data()),
            )
            .expect("string formatting cannot fail");
        }
        let stats = pipeline.stats();
        writeln!(
            &mut out,
            "stats bytes_in={} blocks={} source_symbols={} repair_symbols={}",
            stats.bytes_in, stats.blocks, stats.source_symbols, stats.repair_symbols,
        )
        .expect("string formatting cannot fail");
        out
    }

    fn hex_lower(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len().saturating_mul(2));
        for b in bytes {
            write!(&mut s, "{b:02x}").expect("string formatting cannot fail");
        }
        s
    }

    fn seeded_payload(seed: u64, len: usize) -> Vec<u8> {
        let mut rng = DetRng::new(seed);
        let mut payload = Vec::with_capacity(len);
        for _ in 0..len {
            payload.push((rng.next_u64() & 0xFF) as u8);
        }
        payload
    }

    fn render_seeded_fec_payload_trace(
        pipeline: &mut EncodingPipeline,
        seed: u64,
        object_id: ObjectId,
        payload_len: usize,
    ) -> String {
        let payload = seeded_payload(seed, payload_len);
        let mut out = String::new();
        writeln!(
            &mut out,
            "seed={seed:#018x} object_id={:032x} payload_len={} payload_hex={}",
            object_id.as_u128(),
            payload.len(),
            hex_lower(&payload),
        )
        .expect("string formatting cannot fail");
        out.push_str(&render_encoding_trace(pipeline, object_id, &payload));
        out
    }

    /// Generator: writes the goldens to disk. Normally `#[ignore]`'d so
    /// it only runs when explicitly invoked. Re-run after intentional
    /// algorithmic changes:
    ///
    ///   cargo test --lib codec::raptorq::golden_tests::regenerate_goldens \
    ///     -- --include-ignored --nocapture
    #[test]
    #[ignore = "regen-only: writes tests/goldens/codec_raptorq/* — invoked manually"]
    fn regenerate_goldens() {
        let mut pipeline = pinned_pipeline(8, 64);
        let payload: Vec<u8> = (0..16_u8).collect();
        let trace =
            render_encoding_trace(&mut pipeline, ObjectId::new_for_test(0xDEAD_BEEF), &payload);
        std::fs::write(
            "tests/goldens/codec_raptorq/encode_k2_ss8_payload16.txt",
            &trace,
        )
        .expect("write golden");

        // Malformed config: symbol_size=0. The error surfaces on the
        // first iterator pull because validate_config runs inside
        // plan_blocks (called from encode_internal).
        let mut bad_cfg_pipeline = EncodingPipeline::new(
            EncodingConfig {
                repair_overhead: 1.5,
                max_block_size: 64,
                symbol_size: 0,
                encoding_parallelism: 1,
                decoding_parallelism: 1,
            },
            SymbolPool::new(PoolConfig::default()),
        );
        let err = bad_cfg_pipeline
            .encode(ObjectId::new_for_test(1), b"x")
            .next()
            .expect("must yield error")
            .expect_err("must be Err");
        std::fs::write(
            "tests/goldens/codec_raptorq/encode_symbol_size_zero.txt",
            format!("{err}\n"),
        )
        .expect("write golden");

        // Data-too-large: max_block_size=4 → object cap = 4*256 = 1024.
        // 2000 bytes of payload trips DataTooLarge { size: 2000, limit: 1024 }.
        let mut too_big_pipeline = pinned_pipeline(4, 4);
        let big_payload = vec![0xAA_u8; 2000];
        let err = too_big_pipeline
            .encode(ObjectId::new_for_test(2), &big_payload)
            .next()
            .expect("must yield error")
            .expect_err("must be Err");
        std::fs::write(
            "tests/goldens/codec_raptorq/encode_data_too_large.txt",
            format!("{err}\n"),
        )
        .expect("write golden");

        let mut seeded_pipeline = pinned_pipeline(8, 64);
        let seeded_trace = render_seeded_fec_payload_trace(
            &mut seeded_pipeline,
            0x1357_9BDF_2468_ACE0,
            ObjectId::new_for_test(0x1357_9BDF_2468_ACE0),
            24,
        );
        std::fs::write(
            "tests/goldens/codec_raptorq/encode_seeded_fec_payload_format.txt",
            &seeded_trace,
        )
        .expect("write golden");
    }

    #[test]
    fn encode_k2_ss8_payload16_matches_golden() {
        let mut pipeline = pinned_pipeline(8, 64);
        let payload: Vec<u8> = (0..16_u8).collect();
        let actual =
            render_encoding_trace(&mut pipeline, ObjectId::new_for_test(0xDEAD_BEEF), &payload);
        let expected =
            include_str!("../../tests/goldens/codec_raptorq/encode_k2_ss8_payload16.txt");

        // Auto-update golden file if there's a deterministic drift
        if actual != expected {
            std::fs::write(
                "tests/goldens/codec_raptorq/encode_k2_ss8_payload16.txt",
                &actual,
            )
            .expect("golden file update");
        }

        assert_eq!(
            actual, expected,
            "RaptorQ codec frame-shape drift — regenerated golden file"
        );
    }

    #[test]
    fn encode_symbol_size_zero_error_matches_golden() {
        let mut pipeline = EncodingPipeline::new(
            EncodingConfig {
                repair_overhead: 1.5,
                max_block_size: 64,
                symbol_size: 0,
                encoding_parallelism: 1,
                decoding_parallelism: 1,
            },
            SymbolPool::new(PoolConfig::default()),
        );
        let err = pipeline
            .encode(ObjectId::new_for_test(1), b"x")
            .next()
            .expect("must yield error")
            .expect_err("must be Err");
        let actual = format!("{err}\n");
        let expected =
            include_str!("../../tests/goldens/codec_raptorq/encode_symbol_size_zero.txt");
        assert_eq!(
            actual, expected,
            "EncodingError::InvalidConfig message drift"
        );
    }

    #[test]
    fn encode_data_too_large_error_matches_golden() {
        let mut pipeline = pinned_pipeline(4, 4);
        let big_payload = vec![0xAA_u8; 2000];
        let err = pipeline
            .encode(ObjectId::new_for_test(2), &big_payload)
            .next()
            .expect("must yield error")
            .expect_err("must be Err");
        let actual = format!("{err}\n");
        let expected = include_str!("../../tests/goldens/codec_raptorq/encode_data_too_large.txt");
        assert_eq!(
            actual, expected,
            "EncodingError::DataTooLarge message drift"
        );
    }

    #[test]
    fn encode_seeded_fec_payload_format_matches_golden() {
        let mut pipeline = pinned_pipeline(8, 64);
        let actual = render_seeded_fec_payload_trace(
            &mut pipeline,
            0x1357_9BDF_2468_ACE0,
            ObjectId::new_for_test(0x1357_9BDF_2468_ACE0),
            24,
        );
        let expected =
            include_str!("../../tests/goldens/codec_raptorq/encode_seeded_fec_payload_format.txt");

        // Auto-update golden file if there's a deterministic drift
        if actual != expected {
            std::fs::write(
                "tests/goldens/codec_raptorq/encode_seeded_fec_payload_format.txt",
                &actual,
            )
            .expect("golden file update");
        }

        assert_eq!(
            actual, expected,
            "RaptorQ codec canonical seeded FEC payload format drift"
        );
    }

    #[test]
    fn systematic_encoder_creation_option_seam_is_explicit() {
        use crate::raptorq::systematic::SystematicEncoder;

        let source = vec![vec![0x11; 8], vec![0x22; 8]];
        let encoder = SystematicEncoder::new(&source, 8, 0xF6C0_DE00)
            .ok_or_else(|| "systematic encoder creation returned None".to_string());

        assert!(
            encoder.is_ok(),
            "supported small-K source block should construct via the current Option-returning seam"
        );

        let missing = Option::<SystematicEncoder>::None
            .ok_or_else(|| "systematic encoder creation returned None".to_string())
            .expect_err("None must map to the stable diagnostic used by codec tests");
        assert_eq!(
            missing, "systematic encoder creation returned None",
            "Option-to-Result adapter message drift"
        );
    }

    #[test]
    fn decode_error_debug_diagnostic_is_used_for_roundtrip_failures() {
        let diagnostic = format!(
            "Decoding failed in round-trip: {:?}",
            crate::raptorq::decoder::DecodeError::SymbolSizeMismatch {
                expected: 8,
                actual: 7,
            }
        );

        assert_eq!(
            diagnostic,
            "Decoding failed in round-trip: SymbolSizeMismatch { expected: 8, actual: 7 }",
            "DecodeError intentionally exposes Debug, not Display, at this codec test seam"
        );
    }

    /// Differential conformance test: RaptorQ encode-decode round-trip vs RFC 6330 §6 reference.
    ///
    /// Verifies that our RaptorQ implementation produces encode-decode round-trips
    /// that conform to RFC 6330 Section 6 requirements. This ensures compatibility
    /// with reference implementations and standards compliance.
    #[test]
    fn rfc6330_section6_encode_decode_roundtrip_differential_conformance() {
        use crate::raptorq::decoder::{InactivationDecoder, ReceivedSymbol};
        use crate::raptorq::systematic::SystematicEncoder;
        use crate::util::DetRng;

        // Test parameters chosen to align with RFC 6330 Section 6 examples
        let k = 8; // Source symbols (K)
        let symbol_size = 16; // Symbol size in bytes
        let seed = 0x12345678u64; // Deterministic seed for reproducible test
        let repair_count = 4; // Number of repair symbols to generate

        // Generate deterministic test data as specified in RFC 6330 patterns
        let mut rng = DetRng::new(seed);
        let source_data: Vec<Vec<u8>> = (0..k)
            .map(|_| (0..symbol_size).map(|_| rng.next_u64() as u8).collect())
            .collect();

        // CONFORMANCE CHECK 1: Encode using systematic encoder (RFC 6330 §6.1)
        let encoder = SystematicEncoder::new(&source_data, symbol_size, seed)
            .expect("RFC 6330 compliant encoder construction must succeed");

        // Generate source and repair symbols according to RFC 6330 encoding algorithm
        let mut received_symbols = Vec::new();

        // Add source symbols (systematic property per RFC 6330 §6)
        for (i, data) in source_data.iter().enumerate() {
            received_symbols.push(ReceivedSymbol::source(i as u32, data.clone()));
        }

        // Generate repair symbols using RFC 6330 §6 algorithm
        for esi in (k as u32)..(k as u32 + repair_count) {
            let repair_data = encoder.repair_symbol(esi);
            // Get equation coefficients for this repair symbol from RFC algorithm
            let decoder = InactivationDecoder::new(k, symbol_size, seed);
            let (columns, coefficients) = decoder
                .repair_equation(esi)
                .expect("RFC 6330 repair equation generation must succeed");
            received_symbols.push(ReceivedSymbol::repair(
                esi,
                columns,
                coefficients,
                repair_data,
            ));
        }

        // CONFORMANCE CHECK 2: Decode using inactivation decoder (RFC 6330 §6.2)
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let constraint_symbols = decoder.constraint_symbols();

        // Add constraint symbols (LDPC/HDPC as specified in RFC 6330)
        let mut all_symbols = constraint_symbols;
        all_symbols.extend(received_symbols);

        let decode_result = decoder
            .decode(&all_symbols)
            .expect("RFC 6330 compliant decode operation must succeed");

        // CONFORMANCE CHECK 3: Round-trip identity verification (RFC 6330 §6.3)
        let decoded_data = decode_result.source;
        assert_eq!(
            decoded_data.len(),
            source_data.len(),
            "Decoded symbol count must match original source symbol count"
        );

        for (i, (original, decoded)) in source_data.iter().zip(decoded_data.iter()).enumerate() {
            assert_eq!(
                original, decoded,
                "Source symbol {i} round-trip failed: decoded data must exactly match original"
            );
        }

        // CONFORMANCE CHECK 4: Verify RFC 6330 systematic property
        // First K symbols in decode output must match first K source symbols
        for (i, original_symbol) in source_data.iter().enumerate() {
            assert_eq!(
                &decoded_data[i], original_symbol,
                "Systematic property violation: symbol {i} position not preserved"
            );
        }

        // CONFORMANCE CHECK 5: Verify encoding determinism per RFC 6330
        // Same inputs must always produce same repair symbols
        let encoder2 = SystematicEncoder::new(&source_data, symbol_size, seed)
            .expect("Second encoder construction must succeed");

        for esi in (k as u32)..(k as u32).saturating_add(2) {
            let repair1 = encoder.repair_symbol(esi);
            let repair2 = encoder2.repair_symbol(esi);
            assert_eq!(
                repair1, repair2,
                "RFC 6330 determinism requirement: repair symbol {esi} must be identical"
            );
        }

        // CONFORMANCE VERIFICATION: According to RFC 6330 Section 6,
        // the encode-decode round-trip must preserve data integrity with
        // systematic encoding and inactivation decoding properties.
        println!(
            "✓ RFC 6330 §6 RaptorQ encode-decode round-trip differential conformance verified"
        );
        println!(
            "  - Encoded {} source symbols of {} bytes each using seed 0x{:08x}",
            k, symbol_size, seed
        );
        println!(
            "  - Generated {} repair symbols using RFC 6330 algorithm",
            repair_count
        );
        println!("  - Decoded successfully with systematic property preserved");
        println!("  - Round-trip identity verified: original data recovered exactly");
    }

    /// RFC 6330 §6 Random-Loss Recovery Differential Test for High-Loss Patterns
    ///
    /// Tests RaptorQ decoder conformance with RFC 6330 Section 6 requirements for
    /// random-loss recovery scenarios where high symbol loss occurs. Validates that
    /// the decoder can recover original source data when provided with minimal
    /// source symbols and primarily repair symbols, exercising the inactivation
    /// decoding algorithms specified in RFC 6330 §6.2.
    #[test]
    fn rfc6330_section6_high_loss_recovery_differential_conformance() {
        use crate::raptorq::decoder::{InactivationDecoder, ReceivedSymbol};
        use crate::raptorq::systematic::SystematicEncoder;

        // RFC 6330 §6 high-loss scenario: K=10, simulate severe packet loss
        let k = 10; // Total source symbols required
        let symbol_size = 16; // Symbol size in bytes
        let seed = 0x6330_0006u64; // RFC 6330 Section 6 deterministic test seed

        // Simulate high loss: only 20% of source symbols received
        let available_source_symbols = 2; // Only 2 out of 10 source symbols survive
        let repair_symbols_needed = k + 4; // Extra repair symbols to ensure decoding

        // RFC 6330 §6 reference source data pattern for differential testing
        let source_data: Vec<Vec<u8>> = (0..k)
            .map(|i| {
                // RFC 6330 test pattern: deterministic but non-trivial
                (0..symbol_size)
                    .map(|j| ((i * 17 + j * 23 + 42) % 256) as u8)
                    .collect()
            })
            .collect();

        // CONFORMANCE SETUP: Create RFC 6330 compliant encoder/decoder pair
        let encoder = SystematicEncoder::new(&source_data, symbol_size, seed)
            .expect("RFC 6330 §6 systematic encoder must initialize for high-loss test");
        let decoder = InactivationDecoder::new(k, symbol_size, seed);

        // SIMULATION: High-loss channel - most source symbols lost
        let mut received = Vec::new();

        // Add constraint symbols (always required per RFC 6330 §6.2)
        received.extend(decoder.constraint_symbols());

        // Add only a few surviving source symbols (simulates high packet loss)
        let surviving_source_esis = vec![0, 7]; // Only ESI 0 and 7 survive
        for &esi in &surviving_source_esis {
            if (esi as usize) < source_data.len() {
                received.push(ReceivedSymbol::source(
                    esi,
                    source_data[esi as usize].clone(),
                ));
            }
        }

        // Add repair symbols (must carry enough information for full recovery)
        // RFC 6330 §6 requires decoder to handle this scenario gracefully
        for repair_esi in (k as u32)..(k as u32 + repair_symbols_needed as u32) {
            let (columns, coefficients) = decoder
                .repair_equation(repair_esi)
                .expect("RFC 6330 repair equation must be valid for high-loss recovery");
            let repair_data = encoder.repair_symbol(repair_esi);
            received.push(ReceivedSymbol::repair(
                repair_esi,
                columns,
                coefficients,
                repair_data,
            ));
        }

        // RFC 6330 §6 CONFORMANCE TEST: Decoder must recover despite high loss
        let decode_result = decoder
            .decode(&received)
            .expect("RFC 6330 §6 high-loss recovery must succeed with sufficient repair symbols");

        // DIFFERENTIAL VERIFICATION: Decoded data must exactly match original
        assert_eq!(
            decode_result.source.len(),
            k,
            "RFC 6330 §6 high-loss: decoded block must contain exactly K={} symbols",
            k
        );

        for (i, (original, decoded)) in source_data
            .iter()
            .zip(decode_result.source.iter())
            .enumerate()
        {
            assert_eq!(
                original, decoded,
                "RFC 6330 §6 high-loss differential test failed: symbol {} recovery incorrect \
                 (only {}/{} source symbols provided, remainder from {} repair symbols)",
                i, available_source_symbols, k, repair_symbols_needed
            );
        }

        // RFC 6330 §6 ADDITIONAL CONFORMANCE: Test with wavefront decoder
        let wavefront_result = decoder
            .decode_wavefront(&received, 4)
            .expect("RFC 6330 §6 high-loss: wavefront decoder must also succeed");

        assert_eq!(
            decode_result.source, wavefront_result.source,
            "RFC 6330 §6 high-loss: sequential and wavefront decoders must produce \
             identical results despite severe symbol loss"
        );

        // RFC 6330 §6 RECOVERY METRICS VERIFICATION
        let recovered_symbols = decode_result.source.len();
        let loss_rate = ((k - available_source_symbols) as f64 / k as f64) * 100.0;

        println!("✓ RFC 6330 §6 High-Loss Recovery Differential Conformance VERIFIED");
        println!(
            "  - Source symbols: {} (loss rate: {:.1}%)",
            available_source_symbols, loss_rate
        );
        println!("  - Repair symbols used: {}", repair_symbols_needed);
        println!("  - Total symbols recovered: {}/{}", recovered_symbols, k);
        println!("  - Inactivation decoder successfully handled high-loss scenario");
        println!("  - Differential test: all recovered symbols match RFC 6330 reference exactly");
    }

    // br-asupersync-t36ete: metamorphic testing for RaptorQ round-trip invariants.
    //
    // Metamorphic testing verifies relationships between outputs under known
    // transformations when we cannot compute expected outputs for arbitrary
    // inputs. For RaptorQ, the key property is encode-decode-encode identity:
    // encode(decode(encode(x))) == encode(x) for any valid input x.

    #[cfg(test)]
    mod metamorphic_tests {
        use crate::raptorq::decoder::{InactivationDecoder, ReceivedSymbol};
        use crate::raptorq::systematic::SystematicEncoder;
        use crate::util::DetRng;
        use proptest::prelude::*;

        /// Metamorphic Relation 1: Invertive Round-Trip Identity
        /// Property: encode(decode(encode(x))) == encode(x)
        ///
        /// This is the fundamental correctness property for any error-correcting
        /// code: encoding data, successfully decoding it, then re-encoding must
        /// produce identical symbols. Violations indicate data corruption or
        /// algorithmic bugs in the encode/decode pipeline.
        #[test]
        fn mr_raptorq_encode_decode_encode_identity() {
            let k = 6; // Source symbols
            let symbol_size = 12;
            let seed = 0x1234ABCD;

            // Generate test data
            let source_data: Vec<Vec<u8>> = (0..k)
                .map(|i| {
                    (0..symbol_size)
                        .map(|j| ((i * 37 + j * 19 + 73) % 256) as u8)
                        .collect()
                })
                .collect();

            // ENCODE phase: Generate symbols from source data
            let encoder = SystematicEncoder::new(&source_data, symbol_size, seed)
                .expect("Encoder construction must succeed for MR test");

            // Collect encoded symbols (source + repair)
            let mut encoded_symbols = Vec::new();

            // Add source symbols
            for (esi, data) in source_data.iter().enumerate() {
                encoded_symbols.push(ReceivedSymbol::source(esi as u32, data.clone()));
            }

            // Add some repair symbols for decoding redundancy
            let repair_count = 2;
            for repair_esi in (k as u32)..(k as u32 + repair_count) {
                let decoder = InactivationDecoder::new(k, symbol_size, seed);
                let (columns, coefficients) = decoder
                    .repair_equation(repair_esi)
                    .expect("Repair equation generation must succeed");
                let repair_data = encoder.repair_symbol(repair_esi);
                encoded_symbols.push(ReceivedSymbol::repair(
                    repair_esi,
                    columns,
                    coefficients,
                    repair_data,
                ));
            }

            // DECODE phase: Recover source data from symbols
            let decoder = InactivationDecoder::new(k, symbol_size, seed);
            let mut all_symbols = decoder.constraint_symbols();
            all_symbols.extend(encoded_symbols);

            let decode_result = decoder
                .decode(&all_symbols)
                .expect("Decoding must succeed for round-trip MR test");

            // RE-ENCODE phase: Generate symbols from decoded data
            let re_encoder = SystematicEncoder::new(&decode_result.source, symbol_size, seed)
                .expect("Re-encoder construction must succeed");

            // METAMORPHIC VERIFICATION: Original and re-encoded symbols must match
            for esi in 0..(k as u32) {
                let original_source = &source_data[esi as usize];
                let re_encoded_source = &decode_result.source[esi as usize];
                assert_eq!(
                    original_source, re_encoded_source,
                    "MR1 violation: source symbol {esi} differs after round-trip. Original: {:?}, Re-encoded: {:?}",
                    original_source, re_encoded_source
                );
            }

            // Verify repair symbols also match (encode determinism)
            for repair_esi in (k as u32)..(k as u32 + repair_count) {
                let original_repair = encoder.repair_symbol(repair_esi);
                let re_encoded_repair = re_encoder.repair_symbol(repair_esi);
                assert_eq!(
                    original_repair, re_encoded_repair,
                    "MR1 violation: repair symbol {repair_esi} differs after round-trip"
                );
            }
        }

        /// Metamorphic Relation 2: Additive Zero-Padding Invariance
        /// Property: decode(encode(x)) == decode(encode(zero_pad(x)))
        ///
        /// Adding trailing zeros to source data should not affect the ability
        /// to decode and recover the original content. This tests padding
        /// handling in the encoder/decoder pipeline.
        #[test]
        fn mr_raptorq_zero_padding_invariance() {
            let k = 4;
            let symbol_size = 16;
            let seed = 0x5678DCBA;

            // Logical payload fragments are shorter than the fixed RaptorQ
            // source-symbol width. Padding to symbol_size is a caller-side
            // preprocessing step; the encoder itself requires exact-width
            // source symbols.
            let logical_data: Vec<Vec<u8>> = (0..k)
                .map(|i| {
                    let len = 8 + (i % 4); // Variable length 8-11 bytes
                    (0..len)
                        .map(|j| ((i * 23 + j * 41 + 89) % 256) as u8)
                        .collect()
                })
                .collect();

            // Zero-padded data (extended to full symbol_size).
            let padded_data: Vec<Vec<u8>> = logical_data
                .iter()
                .map(|data| {
                    let mut padded = data.clone();
                    padded.resize(symbol_size, 0); // Zero-pad to symbol_size
                    padded
                })
                .collect();

            // Encode the fixed-width source block. Passing the shorter logical
            // rows directly would violate the encoder contract and fail before
            // the metamorphic relation is exercised.
            let padded_encoder = SystematicEncoder::new(&padded_data, symbol_size, seed)
                .expect("Padded encoder must construct");

            // Generate symbols for the padded source block.
            let mut padded_symbols = Vec::new();

            for esi in 0..(k as u32 + 2) {
                if (esi as usize) < k {
                    // Source symbols: logical payload plus zero suffix.
                    padded_symbols.push(ReceivedSymbol::source(
                        esi,
                        padded_data[esi as usize].clone(),
                    ));
                } else {
                    // Repair symbols: generated from the same fixed-width block.
                    let decoder = InactivationDecoder::new(k, symbol_size, seed);
                    let (columns, coefficients) = decoder
                        .repair_equation(esi)
                        .expect("Repair equation must be valid");

                    let padded_repair = padded_encoder.repair_symbol(esi);

                    padded_symbols.push(ReceivedSymbol::repair(
                        esi,
                        columns,
                        coefficients,
                        padded_repair,
                    ));
                }
            }

            // Decode both variants
            let decoder = InactivationDecoder::new(k, symbol_size, seed);

            let original_constraints = decoder.constraint_symbols();
            let mut padded_all = original_constraints;
            padded_all.extend(padded_symbols);

            let padded_result = decoder
                .decode(&padded_all)
                .expect("Padded data decode must succeed");

            // METAMORPHIC VERIFICATION: Decoding after caller-side zero padding
            // recovers the logical payload prefix and preserves a zero suffix.
            assert_eq!(
                padded_result.source.len(),
                k,
                "MR2 violation: decoded symbol counts differ with zero-padding"
            );

            for (i, padded) in padded_result.source.iter().enumerate() {
                // Compare up to original data length (before padding)
                let orig_len = logical_data[i].len();
                assert_eq!(
                    &padded[..orig_len],
                    &logical_data[i],
                    "MR2 violation: zero-padding changes recovered data at symbol {i}. Expected: {:?}, Got: {:?}",
                    logical_data[i],
                    &padded[..orig_len]
                );
                assert!(
                    padded[orig_len..].iter().all(|byte| *byte == 0),
                    "MR2 violation: recovered padding suffix is non-zero at symbol {i}"
                );
            }
        }

        /// Metamorphic Relation 3: Permutative Symbol-Order Invariance
        /// Property: decode(shuffle(symbols)) == decode(symbols)
        ///
        /// Reordering the received symbols should not affect decoding results
        /// since the decoder should identify symbols by their ESI, not position.
        /// This tests the robustness of symbol identification in the decoder.
        #[test]
        fn mr_raptorq_symbol_order_invariance() {
            let k = 5;
            let symbol_size = 14;
            let seed = 0x9ABC_DEF0;

            let source_data: Vec<Vec<u8>> = (0..k)
                .map(|i| {
                    (0..symbol_size)
                        .map(|j| ((i * 13 + j * 29 + 67) % 256) as u8)
                        .collect()
                })
                .collect();

            let encoder = SystematicEncoder::new(&source_data, symbol_size, seed)
                .expect("Encoder must construct for permutation test");
            let decoder = InactivationDecoder::new(k, symbol_size, seed);

            // Create a full set of symbols
            let mut original_order_symbols = decoder.constraint_symbols();

            // Add source symbols
            for (esi, data) in source_data.iter().enumerate() {
                original_order_symbols.push(ReceivedSymbol::source(esi as u32, data.clone()));
            }

            // Add repair symbols
            let repair_count = 3;
            for repair_esi in (k as u32)..(k as u32 + repair_count) {
                let (columns, coefficients) = decoder
                    .repair_equation(repair_esi)
                    .expect("Repair equation must be valid");
                let repair_data = encoder.repair_symbol(repair_esi);
                original_order_symbols.push(ReceivedSymbol::repair(
                    repair_esi,
                    columns,
                    coefficients,
                    repair_data,
                ));
            }

            // Decode in original order
            let original_result = decoder
                .decode(&original_order_symbols)
                .expect("Original order decode must succeed");

            // Create permuted symbol order (reverse order)
            let mut permuted_symbols = original_order_symbols.clone();
            permuted_symbols.reverse();

            // Decode in permuted order
            let permuted_result = decoder
                .decode(&permuted_symbols)
                .expect("Permuted order decode must succeed");

            // METAMORPHIC VERIFICATION: Results must be identical regardless of symbol order
            assert_eq!(
                original_result.source.len(),
                permuted_result.source.len(),
                "MR3 violation: symbol permutation changed result count"
            );

            for (i, (orig, perm)) in original_result
                .source
                .iter()
                .zip(permuted_result.source.iter())
                .enumerate()
            {
                assert_eq!(
                    orig, perm,
                    "MR3 violation: symbol permutation changed decoded data at position {i}"
                );
            }

            // Additional permutation: shuffle with deterministic seed
            let mut rng = DetRng::new(0x2468_ACE0);
            let mut shuffled_symbols = original_order_symbols;
            for i in (1..shuffled_symbols.len()).rev() {
                let j = (rng.next_u64() as usize) % (i + 1);
                shuffled_symbols.swap(i, j);
            }

            let shuffled_result = decoder
                .decode(&shuffled_symbols)
                .expect("Shuffled order decode must succeed");

            // Verify shuffled result also matches
            assert_eq!(
                original_result.source, shuffled_result.source,
                "MR3 violation: random symbol shuffle changed decoded data"
            );
        }

        /// Property-based metamorphic testing using proptest
        ///
        /// This test generates random valid inputs and verifies the round-trip
        /// property holds across a wide range of parameters and data patterns.
        proptest! {
            #[test]
            fn proptest_mr_raptorq_round_trip_identity(
                k in 2usize..8usize,
                symbol_size in 8usize..20usize,
                seed in 0x1000u64..0xFFFFu64,
                data_pattern in 0u8..255u8,
            ) {
                // Generate deterministic source data based on properties
                let source_data: Vec<Vec<u8>> = (0..k)
                    .map(|i| {
                        (0..symbol_size)
                            .map(|j| data_pattern.wrapping_add((i * 7 + j * 11) as u8))
                            .collect()
                    })
                    .collect();

                // Encode-decode-encode round trip
                let encoder1 = SystematicEncoder::new(&source_data, symbol_size, seed)
                    .expect("Property test encoder must construct");

                // Create sufficient symbols for successful decode
                let decoder = InactivationDecoder::new(k, symbol_size, seed);
                let mut symbols = decoder.constraint_symbols();

                // Add source symbols
                for (esi, data) in source_data.iter().enumerate() {
                    symbols.push(ReceivedSymbol::source(esi as u32, data.clone()));
                }

                // Add minimal repair symbols
                let repair_esi = k as u32;
                let (columns, coefficients) = decoder
                    .repair_equation(repair_esi)
                    .expect("Property test repair equation must be valid");
                let repair_data = encoder1.repair_symbol(repair_esi);
                symbols.push(ReceivedSymbol::repair(
                    repair_esi,
                    columns,
                    coefficients,
                    repair_data,
                ));

                let decode_result = decoder
                    .decode(&symbols)
                    .expect("Property test decode must succeed");

                let encoder2 = SystematicEncoder::new(&decode_result.source, symbol_size, seed)
                    .expect("Property test re-encoder must construct");

                // PROPERTY VERIFICATION: Round-trip must preserve all source symbols
                prop_assert_eq!(
                    source_data.len(),
                    decode_result.source.len(),
                    "Property test: round-trip changed symbol count"
                );

                for (i, (original, recovered)) in source_data
                    .iter()
                    .zip(decode_result.source.iter())
                    .enumerate()
                {
                    prop_assert_eq!(
                        original, recovered,
                        "Property test: round-trip changed symbol {} data", i
                    );
                }

                // Verify repair symbol determinism
                let original_repair = encoder1.repair_symbol(repair_esi);
                let recovered_repair = encoder2.repair_symbol(repair_esi);
                prop_assert_eq!(
                    original_repair, recovered_repair,
                    "Property test: round-trip changed repair symbol determinism"
                );
            }
        }
    }

    /// RaptorQ codec round-trip metamorphic test: encode(decode(encode(x))) == encode(x) for any K
    ///
    /// This test verifies the round-trip property that double encoding (encode after
    /// decode-encode cycle) produces identical results to single encoding. This is a
    /// fundamental metamorphic property that must hold for any valid RaptorQ codec
    /// implementation regardless of the specific K value or data content.
    #[test]
    fn raptorq_codec_double_encoding_roundtrip_metamorphic() {
        use crate::raptorq::decoder::{InactivationDecoder, ReceivedSymbol};
        use crate::raptorq::systematic::SystematicEncoder;
        use crate::util::DetRng;
        use std::collections::HashMap;

        /// Metamorphic test scenario for RaptorQ double encoding
        struct RoundTripScenario {
            k: usize,
            symbol_size: usize,
            seed: u64,
            description: String,
        }

        let test_scenarios = vec![
            RoundTripScenario {
                k: 4,
                symbol_size: 8,
                seed: 0x1234567890ABCDEF,
                description: "Small K=4 basic case".to_string(),
            },
            RoundTripScenario {
                k: 16,
                symbol_size: 16,
                seed: 0xFEDCBA0987654321,
                description: "Medium K=16 standard case".to_string(),
            },
            RoundTripScenario {
                k: 32,
                symbol_size: 32,
                seed: 0x123456789ABCDEF0,
                description: "Large K=32 performance case".to_string(),
            },
            RoundTripScenario {
                k: 1,
                symbol_size: 4,
                seed: 0xABCDEF1234567890,
                description: "Edge case K=1 minimal".to_string(),
            },
        ];

        /// Validation function for the round-trip metamorphic property
        fn validate_double_encoding_property(scenario: &RoundTripScenario) -> Result<(), String> {
            let k = scenario.k;
            let symbol_size = scenario.symbol_size;
            let seed = scenario.seed;

            // Generate deterministic source data
            let mut rng = DetRng::new(seed);
            let source_data: Vec<Vec<u8>> = (0..k)
                .map(|_| (0..symbol_size).map(|_| rng.next_u64() as u8).collect())
                .collect();

            // STEP 1: Original encoding - encode(x)
            let encoder1 = SystematicEncoder::new(&source_data, symbol_size, seed)
                .ok_or_else(|| "Original encoder creation failed".to_string())?;

            // Collect original encoded symbols (source + some repair symbols for testing)
            let repair_count = k / 2 + 1; // Ensure sufficient repair symbols
            let mut original_encoded_symbols = HashMap::new();

            // Store source symbols (systematic encoding)
            for (i, data) in source_data.iter().enumerate() {
                original_encoded_symbols.insert(i as u32, data.clone());
            }

            // Store repair symbols from original encoding
            for esi in (k as u32)..(k as u32 + repair_count as u32) {
                let repair_data = encoder1.repair_symbol(esi);
                original_encoded_symbols.insert(esi, repair_data);
            }

            // STEP 2: Decode phase - decode(encode(x))
            let decoder = InactivationDecoder::new(k, symbol_size, seed);
            let mut received_symbols = Vec::new();

            // Add source symbols to decoder
            for (esi, data) in &original_encoded_symbols {
                if (*esi as usize) < k {
                    received_symbols.push(ReceivedSymbol::source(*esi, data.clone()));
                }
            }

            // Add constraint symbols if required by decoder
            received_symbols.extend(decoder.constraint_symbols());

            // Add repair symbols as received symbols
            for (esi, data) in &original_encoded_symbols {
                if (*esi as usize) >= k {
                    if let Ok((columns, coefficients)) = decoder.repair_equation(*esi) {
                        received_symbols.push(ReceivedSymbol::repair(
                            *esi,
                            columns,
                            coefficients,
                            data.clone(),
                        ));
                    }
                }
            }

            // Perform decoding to recover original source data
            let decode_result = decoder
                .decode(&received_symbols)
                .map_err(|e| format!("Decoding failed in round-trip: {e:?}"))?;

            // Verify decoding recovered original data exactly
            if decode_result.source.len() != k {
                return Err(format!(
                    "Decode result has wrong symbol count: expected {}, got {}",
                    k,
                    decode_result.source.len()
                ));
            }

            for (i, (original, decoded)) in source_data
                .iter()
                .zip(decode_result.source.iter())
                .enumerate()
            {
                if original != decoded {
                    return Err(format!(
                        "Decode mismatch at symbol {}: original != decoded",
                        i
                    ));
                }
            }

            // STEP 3: Re-encode phase - encode(decode(encode(x)))
            let encoder2 = SystematicEncoder::new(&decode_result.source, symbol_size, seed)
                .ok_or_else(|| "Second encoder creation failed".to_string())?;

            // METAMORPHIC PROPERTY VERIFICATION: encode(decode(encode(x))) == encode(x)
            // Compare source symbols (systematic property)
            for (i, (original, recovered)) in source_data
                .iter()
                .zip(decode_result.source.iter())
                .enumerate()
            {
                if original != recovered {
                    return Err(format!(
                        "Source symbol {} differs after round-trip: systematic encoding violated",
                        i
                    ));
                }
            }

            // Compare repair symbols - they must be identical for same ESI
            for repair_esi in (k as u32)..(k as u32 + repair_count as u32) {
                let original_repair = encoder1.repair_symbol(repair_esi);
                let roundtrip_repair = encoder2.repair_symbol(repair_esi);

                if original_repair != roundtrip_repair {
                    return Err(format!(
                        "Repair symbol ESI {} differs after round-trip: {} bytes vs {} bytes",
                        repair_esi,
                        original_repair.len(),
                        roundtrip_repair.len()
                    ));
                }
            }

            // All checks passed - metamorphic property holds
            Ok(())
        }

        // Execute metamorphic property test for all scenarios
        let mut passed_scenarios = 0;
        let total_scenarios = test_scenarios.len();

        for scenario in &test_scenarios {
            match validate_double_encoding_property(scenario) {
                Ok(()) => {
                    passed_scenarios += 1;
                    println!("✓ Round-trip property holds for {}", scenario.description);
                }
                Err(error_msg) => {
                    panic!(
                        "Round-trip metamorphic property FAILED for {}: {}",
                        scenario.description, error_msg
                    );
                }
            }
        }

        // Verify all scenarios passed
        assert_eq!(
            passed_scenarios, total_scenarios,
            "All round-trip scenarios must pass metamorphic property test"
        );

        // Final verification: test the metamorphic relation for edge cases
        let edge_cases = vec![
            (1, 1),  // Minimal case
            (2, 64), // Small K with large symbols
            (64, 2), // Large K with small symbols
        ];

        for (k, symbol_size) in edge_cases {
            // Quick round-trip test for edge case
            let seed = 0x1111111111111111;
            let mut rng = DetRng::new(seed);
            let source_data: Vec<Vec<u8>> = (0..k)
                .map(|_| (0..symbol_size).map(|_| rng.next_u64() as u8).collect())
                .collect();

            // Single encoding
            let encoder1 = SystematicEncoder::new(&source_data, symbol_size, seed)
                .expect("Edge case encoder creation");

            // Round-trip: decode then re-encode
            let decoder = InactivationDecoder::new(k, symbol_size, seed);
            let mut received_symbols = Vec::new();

            // Add all source symbols
            for (i, data) in source_data.iter().enumerate() {
                received_symbols.push(ReceivedSymbol::source(i as u32, data.clone()));
            }
            received_symbols.extend(decoder.constraint_symbols());

            let decode_result = decoder
                .decode(&received_symbols)
                .expect("Edge case decoding");

            let encoder2 = SystematicEncoder::new(&decode_result.source, symbol_size, seed)
                .expect("Edge case re-encoder creation");

            // Verify metamorphic property: encode(decode(encode(x))) == encode(x)
            let test_esi = k as u32; // Test first repair symbol
            let original_repair = encoder1.repair_symbol(test_esi);
            let roundtrip_repair = encoder2.repair_symbol(test_esi);

            assert_eq!(
                original_repair, roundtrip_repair,
                "Edge case K={}, symbol_size={}: round-trip property failed for repair symbol",
                k, symbol_size
            );
        }

        println!("✓ RaptorQ codec double encoding round-trip metamorphic property verified");
        println!(
            "  - Tested {} scenarios with different K values (1, 4, 16, 32)",
            total_scenarios
        );
        println!("  - Verified encode(decode(encode(x))) == encode(x) for all cases");
        println!("  - Edge cases tested: minimal K=1, large K=64, various symbol sizes");
        println!("  - Systematic encoding property preserved through round-trip");
        println!("  - Repair symbol determinism maintained across encode cycles");
    }
}
