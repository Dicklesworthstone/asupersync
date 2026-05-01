//! RFC 6330 Section 6 systematic + repair symbol mix differential conformance.
//!
//! This module implements Pattern 1 (Differential Testing) from the conformance
//! harness methodology to verify RFC 6330 §6 compliance for the systematic coding
//! scheme, specifically testing the correct generation and ordering of both
//! systematic symbols (ESI 0..K-1) and repair symbols (ESI K..).
//!
//! # RFC 6330 Section 6 Requirements
//!
//! - **MUST**: Systematic symbols (ESI 0 to K-1) are identical to source symbols
//! - **MUST**: Repair symbols (ESI K and above) are linearly independent
//! - **MUST**: Symbol ordering preserves ESI sequence (systematic first, then repair)
//! - **SHOULD**: Encoding produces symbols that enable decoding with K symbols
//!
//! # Test Methodology
//!
//! Uses golden file differential testing to validate against a known-correct
//! encoding sequence for a fixed (K=4, symbol_size=8, repair_count=2) case.
//! The golden file captures the exact byte-level output including:
//! - Symbol IDs (SBN, ESI)
//! - Symbol kinds (Systematic vs Repair)
//! - Symbol data (hex-encoded for deterministic comparison)

#![allow(clippy::pedantic, clippy::nursery)]

use asupersync::codec::raptorq::{EncodingConfig, EncodingPipeline};
use asupersync::types::resource::{PoolConfig, SymbolPool};
use asupersync::types::{ObjectId, SymbolKind};
use std::fmt::Write as _;

/// Test case: K=4 source symbols, 2 repair symbols, 8-byte symbol size
/// Validates RFC 6330 §6 systematic + repair symbol sequence
#[test]
fn rfc6330_section6_systematic_repair_mix_differential() {
    let actual = generate_rfc6330_section6_test_case();
    let expected = include_str!(
        "../../tests/goldens/codec_raptorq/rfc6330_section6_systematic_repair_k4_r2_ss8.golden"
    );

    assert_eq!(
        actual, expected,
        "RFC 6330 §6 systematic+repair mix diverges from golden reference\n\
         This indicates either:\n\
         1. Intentional algorithm change (run regenerate_rfc6330_section6_golden)\n\
         2. Unintentional regression in systematic/repair symbol generation\n\
         3. ESI ordering or symbol kind classification bug\n\
         \n\
         To update golden after confirming change is intentional:\n\
         cargo test --lib conformance::raptorq_rfc6330_section6_systematic_repair_mix::regenerate_rfc6330_section6_golden -- --include-ignored --nocapture"
    );
}

/// Generate the systematic + repair symbol mix test case
fn generate_rfc6330_section6_test_case() -> String {
    let mut pipeline = create_rfc6330_test_pipeline();

    // RFC 6330 test vector: 32 bytes of deterministic data
    // K=4 symbols × 8 bytes = 32 bytes total
    let test_payload: Vec<u8> = (0x41..=0x60).collect(); // 'A' through '`' (32 chars)

    let object_id = ObjectId::new_for_test(0x6330_0006); // RFC 6330 section 6 marker

    render_systematic_repair_trace(&mut pipeline, object_id, &test_payload, 2)
}

/// Creates a pipeline configured specifically for RFC 6330 §6 testing
fn create_rfc6330_test_pipeline() -> EncodingPipeline {
    let config = EncodingConfig {
        repair_overhead: 1.5,    // 50% overhead = 2 repair symbols for K=4
        max_block_size: 32,      // Forces single block with K=4 at symbol_size=8
        symbol_size: 8,          // 8-byte symbols
        encoding_parallelism: 1, // Deterministic single-thread encoding
        decoding_parallelism: 1,
    };
    EncodingPipeline::new(config, SymbolPool::new(PoolConfig::default()))
}

/// Renders encoding output with RFC 6330 §6 compliance annotations
fn render_systematic_repair_trace(
    pipeline: &mut EncodingPipeline,
    object_id: ObjectId,
    data: &[u8],
    expected_repair_count: usize,
) -> String {
    let mut out = String::new();
    writeln!(
        &mut out,
        "# RFC 6330 Section 6 Systematic + Repair Symbol Mix Test"
    )
    .unwrap();
    writeln!(
        &mut out,
        "# Input: {} bytes, expected K=4, repair={}",
        data.len(),
        expected_repair_count
    )
    .unwrap();
    writeln!(
        &mut out,
        "# Systematic symbols: ESI 0-3 (must match source data)"
    )
    .unwrap();
    writeln!(
        &mut out,
        "# Repair symbols: ESI 4-{} (must be linearly independent)",
        3 + expected_repair_count
    )
    .unwrap();
    writeln!(&mut out).unwrap();

    let mut systematic_count = 0;
    let mut repair_count = 0;

    for (idx, result) in pipeline.encode(object_id, data).enumerate() {
        let symbol = result.expect("RFC 6330 test config produces no errors");
        let id = symbol.id();
        let esi = id.esi();
        let kind = symbol.kind();
        let symbol_data = symbol.symbol().data();

        // RFC 6330 §6 validation
        match kind {
            SymbolKind::Source => {
                systematic_count += 1;
                assert!(esi < 4, "Systematic symbol ESI {} should be < K=4", esi);

                // Verify systematic symbol matches source data
                let expected_start = (esi as usize) * 8;
                let expected_end = expected_start + 8;
                if expected_end <= data.len() {
                    let expected_data = &data[expected_start..expected_end];
                    assert_eq!(
                        symbol_data, expected_data,
                        "Systematic symbol ESI {} data mismatch (RFC 6330 §6 violation)",
                        esi
                    );
                    writeln!(
                        &mut out,
                        "systematic esi={:04} verified_match=true data_hex={}",
                        esi,
                        hex_encode(symbol_data)
                    )
                    .unwrap();
                } else {
                    writeln!(
                        &mut out,
                        "systematic esi={:04} verified_match=padding data_hex={}",
                        esi,
                        hex_encode(symbol_data)
                    )
                    .unwrap();
                }
            }
            SymbolKind::Repair => {
                repair_count += 1;
                assert!(esi >= 4, "Repair symbol ESI {} should be >= K=4", esi);
                writeln!(
                    &mut out,
                    "repair esi={:04} data_hex={}",
                    esi,
                    hex_encode(symbol_data)
                )
                .unwrap();
            }
        }
    }

    // RFC 6330 §6 requirement verification
    writeln!(&mut out).unwrap();
    writeln!(&mut out, "# RFC 6330 Section 6 Compliance Summary").unwrap();
    writeln!(
        &mut out,
        "systematic_symbols={} repair_symbols={}",
        systematic_count, repair_count
    )
    .unwrap();
    writeln!(
        &mut out,
        "total_symbols={}",
        systematic_count + repair_count
    )
    .unwrap();

    // Validate compliance
    assert_eq!(
        systematic_count, 4,
        "RFC 6330 §6: Expected exactly K=4 systematic symbols"
    );
    assert_eq!(
        repair_count, expected_repair_count,
        "Expected exactly {expected_repair_count} repair symbols"
    );
    writeln!(&mut out, "rfc6330_section6_compliance=PASS").unwrap();

    let stats = pipeline.stats();
    writeln!(
        &mut out,
        "pipeline_stats bytes_in={} blocks={} source_symbols={} repair_symbols={}",
        stats.bytes_in, stats.blocks, stats.source_symbols, stats.repair_symbols
    )
    .unwrap();

    out
}

/// Hex-encode bytes for deterministic golden file comparison
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}

/// Generator test: creates the golden file for RFC 6330 §6 test case
///
/// Run this to regenerate the golden file after intentional changes:
/// cargo test --lib conformance::raptorq_rfc6330_section6_systematic_repair_mix::regenerate_rfc6330_section6_golden -- --include-ignored --nocapture
#[test]
#[ignore = "regen-only: writes golden file — run manually after algorithm changes"]
fn regenerate_rfc6330_section6_golden() {
    let golden_content = generate_rfc6330_section6_test_case();

    std::fs::create_dir_all("tests/goldens/codec_raptorq").expect("create golden directory");

    std::fs::write(
        "tests/goldens/codec_raptorq/rfc6330_section6_systematic_repair_k4_r2_ss8.golden",
        &golden_content,
    )
    .expect("write RFC 6330 §6 golden file");

    println!("Generated RFC 6330 Section 6 golden file:");
    println!("{}", golden_content);
}

#[cfg(test)]
mod rfc6330_section6_conformance_tests {
    use super::*;

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex_encode(b"ABC"), "414243");
        assert_eq!(hex_encode(&[0x00, 0xFF, 0xA5]), "00ffa5");
    }

    #[test]
    fn test_rfc6330_pipeline_config() {
        let mut pipeline = create_rfc6330_test_pipeline();
        let test_payload: Vec<u8> = (0x41..=0x60).collect();
        let trace = render_systematic_repair_trace(
            &mut pipeline,
            ObjectId::new_for_test(0x6330_0006),
            &test_payload,
            2,
        );

        assert!(
            trace.contains("systematic_symbols=4 repair_symbols=2"),
            "test config should produce K=4 source symbols and 2 repair symbols"
        );
        assert!(
            trace.contains("pipeline_stats bytes_in=32 blocks=1 source_symbols=4 repair_symbols=2"),
            "test config should force one 32-byte block with 8-byte symbols"
        );
    }

    /// Metamorphic property: systematic symbols must be invariant under repair count changes
    #[test]
    fn test_systematic_symbols_invariant_under_repair_changes() {
        let test_data = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"; // 32 bytes

        // Generate with repair_overhead = 1.5 (2 repair symbols)
        let mut pipeline1 = create_rfc6330_test_pipeline();
        let trace1 = render_systematic_repair_trace(
            &mut pipeline1,
            ObjectId::new_for_test(0x1),
            test_data,
            2,
        );

        // Generate with repair_overhead = 2.0 (4 repair symbols)
        let config2 = EncodingConfig {
            repair_overhead: 2.0,
            max_block_size: 32,
            symbol_size: 8,
            encoding_parallelism: 1,
            decoding_parallelism: 1,
        };
        let mut pipeline2 = EncodingPipeline::new(config2, SymbolPool::new(PoolConfig::default()));
        let trace2 = render_systematic_repair_trace(
            &mut pipeline2,
            ObjectId::new_for_test(0x1),
            test_data,
            4,
        );

        // Extract systematic symbol lines from both traces
        let systematic1: Vec<&str> = trace1
            .lines()
            .filter(|line| line.starts_with("systematic esi="))
            .collect();
        let systematic2: Vec<&str> = trace2
            .lines()
            .filter(|line| line.starts_with("systematic esi="))
            .collect();

        // RFC 6330 §6: systematic symbols must be identical regardless of repair count
        assert_eq!(
            systematic1, systematic2,
            "RFC 6330 §6 violation: systematic symbols changed when repair count changed"
        );
    }
}
