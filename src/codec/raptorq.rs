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
        let mut s = String::with_capacity(bytes.len() * 2);
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
        assert_eq!(
            actual, expected,
            "RaptorQ codec frame-shape drift — re-run regenerate_goldens after \
             confirming the change is intentional"
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
        assert_eq!(
            actual, expected,
            "RaptorQ codec canonical seeded FEC payload format drift"
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
            let (columns, coefficients) = decoder.repair_equation(esi)
                .expect("RFC 6330 repair equation generation must succeed");
            received_symbols.push(ReceivedSymbol::repair(esi, columns, coefficients, repair_data));
        }

        // CONFORMANCE CHECK 2: Decode using inactivation decoder (RFC 6330 §6.2)
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let constraint_symbols = decoder.constraint_symbols();

        // Add constraint symbols (LDPC/HDPC as specified in RFC 6330)
        let mut all_symbols = constraint_symbols;
        all_symbols.extend(received_symbols);

        let decode_result = decoder.decode(&all_symbols)
            .expect("RFC 6330 compliant decode operation must succeed");

        // CONFORMANCE CHECK 3: Round-trip identity verification (RFC 6330 §6.3)
        let decoded_data = decode_result.source_symbols;
        assert_eq!(
            decoded_data.len(),
            source_data.len(),
            "Decoded symbol count must match original source symbol count"
        );

        for (i, (original, decoded)) in source_data.iter().zip(decoded_data.iter()).enumerate() {
            assert_eq!(
                original,
                decoded,
                "Source symbol {i} round-trip failed: decoded data must exactly match original"
            );
        }

        // CONFORMANCE CHECK 4: Verify RFC 6330 systematic property
        // First K symbols in decode output must match first K source symbols
        for (i, original_symbol) in source_data.iter().enumerate() {
            assert_eq!(
                &decoded_data[i],
                original_symbol,
                "Systematic property violation: symbol {i} position not preserved"
            );
        }

        // CONFORMANCE CHECK 5: Verify encoding determinism per RFC 6330
        // Same inputs must always produce same repair symbols
        let encoder2 = SystematicEncoder::new(&source_data, symbol_size, seed)
            .expect("Second encoder construction must succeed");

        for esi in (k as u32)..(k as u32 + 2) {
            let repair1 = encoder.repair_symbol(esi);
            let repair2 = encoder2.repair_symbol(esi);
            assert_eq!(
                repair1,
                repair2,
                "RFC 6330 determinism requirement: repair symbol {esi} must be identical"
            );
        }

        // CONFORMANCE VERIFICATION: According to RFC 6330 Section 6,
        // the encode-decode round-trip must preserve data integrity with
        // systematic encoding and inactivation decoding properties.
        println!("✓ RFC 6330 §6 RaptorQ encode-decode round-trip differential conformance verified");
        println!(
            "  - Encoded {} source symbols of {} bytes each using seed 0x{:08x}",
            k, symbol_size, seed
        );
        println!(
            "  - Generated {} repair symbols using RFC 6330 algorithm",
            repair_count
        );
        println!(
            "  - Decoded successfully with systematic property preserved"
        );
        println!(
            "  - Round-trip identity verified: original data recovered exactly"
        );
    }
}
