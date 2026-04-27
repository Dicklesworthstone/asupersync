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
    use crate::raptorq::decoder::{InactivationDecoder, ReceivedSymbol};
    use crate::raptorq::systematic::SystematicParams;
    use crate::types::ObjectId;
    use crate::types::resource::{PoolConfig, SymbolPool};
    use insta::assert_json_snapshot;
    use serde::Serialize;
    use std::fmt::Write as _;

    const CANONICAL_SYMBOL_SIZE: usize = 8;
    const CANONICAL_MAX_BLOCK_SIZE: usize = 4096;

    #[derive(Serialize)]
    struct CanonicalPacketGolden {
        sbn: u8,
        esi: u32,
        kind: &'static str,
        data_hex: String,
    }

    #[derive(Serialize)]
    struct CanonicalVectorGolden {
        case_name: String,
        payload_size: usize,
        symbol_size: usize,
        k: usize,
        k_prime: usize,
        seed: u64,
        packet_count: usize,
        source_symbols: usize,
        repair_symbols: usize,
        requested_repairs: usize,
        packets: Vec<CanonicalPacketGolden>,
    }

    /// Build a deterministic pipeline for goldens. Parallelism counts are
    /// pinned even though they are unused by the synchronous encode path —
    /// changing them is a config-shape signal worth catching.
    fn pinned_pipeline(symbol_size: u16, max_block_size: usize) -> EncodingPipeline {
        pinned_pipeline_with_overhead(symbol_size, max_block_size, 1.5)
    }

    fn pinned_pipeline_with_overhead(
        symbol_size: u16,
        max_block_size: usize,
        repair_overhead: f64,
    ) -> EncodingPipeline {
        let cfg = EncodingConfig {
            repair_overhead,
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

    fn deterministic_payload(payload_size: usize, salt: u8) -> Vec<u8> {
        (0..payload_size)
            .map(|idx| salt.wrapping_add((idx as u8).wrapping_mul(37)))
            .collect()
    }

    fn seed_for_block(object_id: ObjectId, sbn: u8) -> u64 {
        let hi = object_id.high();
        let lo = object_id.low();
        let mut seed = hi ^ lo.rotate_left(13);
        seed ^= u64::from(sbn) << 56;
        if seed == 0 { 1 } else { seed }
    }

    fn encoded_symbols_to_received(
        encoded: &[EncodedSymbol],
        decoder: &InactivationDecoder,
        k: usize,
    ) -> Vec<ReceivedSymbol> {
        encoded
            .iter()
            .map(|encoded_symbol| {
                let symbol = encoded_symbol.symbol();
                match symbol.kind() {
                    crate::types::SymbolKind::Source => {
                        ReceivedSymbol::source(symbol.esi(), symbol.data().to_vec())
                    }
                    crate::types::SymbolKind::Repair => {
                        let (columns, coefficients) =
                            decoder.repair_equation(symbol.esi()).unwrap_or_else(|err| {
                                panic!(
                                    "repair equation for K={k}, ESI={} failed: {err:?}",
                                    symbol.esi()
                                )
                            });
                        ReceivedSymbol::repair(
                            symbol.esi(),
                            columns,
                            coefficients,
                            symbol.data().to_vec(),
                        )
                    }
                }
            })
            .collect()
    }

    fn flatten_source_symbols(source: &[Vec<u8>], original_len: usize) -> Vec<u8> {
        source
            .iter()
            .flatten()
            .copied()
            .take(original_len)
            .collect()
    }

    fn canonical_roundtrip_case(
        case_name: &str,
        object_value: u64,
        expected_k: usize,
        payload_size: usize,
    ) -> CanonicalVectorGolden {
        let payload = deterministic_payload(payload_size, object_value as u8);
        let object_id = ObjectId::new_for_test(object_value);
        let params = SystematicParams::for_source_block(expected_k, CANONICAL_SYMBOL_SIZE);
        let requested_repairs = params.s + params.h;
        let mut pipeline = pinned_pipeline(CANONICAL_SYMBOL_SIZE as u16, CANONICAL_MAX_BLOCK_SIZE);
        let encoded: Vec<_> = pipeline
            .encode_with_repair(object_id, &payload, requested_repairs)
            .collect::<Result<Vec<_>, _>>()
            .expect("canonical golden encode should succeed");
        let stats = pipeline.stats();

        assert_eq!(
            payload_size.div_ceil(CANONICAL_SYMBOL_SIZE),
            expected_k,
            "{case_name} fixture drifted away from its expected source-symbol count"
        );
        assert_eq!(
            stats.blocks, 1,
            "{case_name} must stay single-block so packet bytes remain canonical"
        );
        assert_eq!(
            stats.source_symbols, expected_k,
            "{case_name} emitted unexpected source-symbol count"
        );
        assert_eq!(
            stats.repair_symbols, requested_repairs,
            "{case_name} emitted unexpected repair-symbol count"
        );

        let seed = seed_for_block(object_id, 0);
        let decoder = InactivationDecoder::new(expected_k, CANONICAL_SYMBOL_SIZE, seed);
        let decoded = decoder
            .decode(&encoded_symbols_to_received(&encoded, &decoder, expected_k))
            .expect("canonical golden roundtrip should decode");
        let recovered = flatten_source_symbols(&decoded.source, payload.len());
        assert_eq!(
            recovered, payload,
            "{case_name} decode must recover the exact original payload"
        );

        CanonicalVectorGolden {
            case_name: case_name.to_string(),
            payload_size,
            symbol_size: CANONICAL_SYMBOL_SIZE,
            k: expected_k,
            k_prime: decoder.params().k_prime,
            seed,
            packet_count: encoded.len(),
            source_symbols: stats.source_symbols,
            repair_symbols: stats.repair_symbols,
            requested_repairs,
            packets: encoded
                .into_iter()
                .map(|encoded_symbol| {
                    let id = encoded_symbol.id();
                    CanonicalPacketGolden {
                        sbn: id.sbn(),
                        esi: id.esi(),
                        kind: match encoded_symbol.kind() {
                            crate::types::SymbolKind::Source => "source",
                            crate::types::SymbolKind::Repair => "repair",
                        },
                        data_hex: hex_lower(encoded_symbol.symbol().data()),
                    }
                })
                .collect(),
        }
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
    fn encode_decode_roundtrip_canonical_vectors() {
        // br-asupersync-c12bcb: pin both sides of the lower K'=10 ladder
        // boundary (K=10/11) and the larger K'=257/263 transition
        // (K=257/258), while keeping K=1 as the smallest legal block.
        let vectors = [
            ("k1_payload7", 0xC12B_CB01, 1usize, 7usize),
            ("k10_payload80", 0xC12B_CB0A, 10, 80),
            ("k11_payload81", 0xC12B_CB0B, 11, 81),
            ("k256_payload2048", 0xC12B_CC00, 256, 2048),
            ("k257_payload2056", 0xC12B_CC01, 257, 2056),
            ("k258_payload2057", 0xC12B_CC02, 258, 2057),
        ]
        .into_iter()
        .map(|(case_name, object_value, expected_k, payload_size)| {
            canonical_roundtrip_case(case_name, object_value, expected_k, payload_size)
        })
        .collect::<Vec<_>>();

        assert_json_snapshot!("raptorq_encode_decode_roundtrip_canonical_vectors", vectors);
    }
}
