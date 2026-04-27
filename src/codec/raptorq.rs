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
}
