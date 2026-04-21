//! Fuzz target for `src/codec/raptorq.rs` RaptorQ codec frame splitter.
//!
//! Focus:
//! 1. EncodingPipeline::encode method handles arbitrary input data without crashing
//! 2. Symbol splitting respects block boundaries and configuration limits
//! 3. Empty payloads, oversized payloads, and edge cases fail gracefully
//! 4. Generated symbols have consistent metadata and no buffer corruption

#![no_main]

use arbitrary::Arbitrary;
use asupersync::codec::raptorq::{EncodingConfig, EncodingPipeline};
use asupersync::types::resource::{PoolConfig, SymbolPool};
use asupersync::types::{ObjectId, SymbolKind};
use libfuzzer_sys::fuzz_target;

const MAX_SYMBOL_SIZE: u16 = 1024;
const MAX_MAX_BLOCK_SIZE: usize = 8192;
const MAX_PAYLOAD_SIZE: usize = 65536;
const MAX_REPAIR_OVERHEAD: f64 = 10.0;
const MIN_REPAIR_OVERHEAD: f64 = 0.0;

#[derive(Arbitrary, Debug)]
enum Scenario {
    BasicEncoding {
        symbol_size: u16,
        max_block_size: u16,
        repair_overhead: u8,
        payload: Vec<u8>,
        object_id_raw: u64,
    },
    EmptyPayload {
        symbol_size: u16,
        max_block_size: u16,
        repair_overhead: u8,
        object_id_raw: u64,
    },
    OversizedPayload {
        symbol_size: u16,
        max_block_size: u16,
        repair_overhead: u8,
        oversize_factor: u8,
        object_id_raw: u64,
    },
    EdgeCaseSymbolSizes {
        symbol_size: u8, // Will test very small symbol sizes
        max_block_size: u16,
        repair_overhead: u8,
        payload: Vec<u8>,
        object_id_raw: u64,
    },
    RepairSymbolCount {
        symbol_size: u16,
        max_block_size: u16,
        repair_overhead: u8,
        explicit_repair_count: u16,
        payload: Vec<u8>,
        object_id_raw: u64,
    },
}

fuzz_target!(|scenario: Scenario| match scenario {
    Scenario::BasicEncoding {
        symbol_size,
        max_block_size,
        repair_overhead,
        payload,
        object_id_raw,
    } => fuzz_basic_encoding(symbol_size, max_block_size, repair_overhead, payload, object_id_raw),
    Scenario::EmptyPayload {
        symbol_size,
        max_block_size,
        repair_overhead,
        object_id_raw,
    } => fuzz_empty_payload(symbol_size, max_block_size, repair_overhead, object_id_raw),
    Scenario::OversizedPayload {
        symbol_size,
        max_block_size,
        repair_overhead,
        oversize_factor,
        object_id_raw,
    } => fuzz_oversized_payload(
        symbol_size,
        max_block_size,
        repair_overhead,
        oversize_factor,
        object_id_raw
    ),
    Scenario::EdgeCaseSymbolSizes {
        symbol_size,
        max_block_size,
        repair_overhead,
        payload,
        object_id_raw,
    } => fuzz_edge_case_symbol_sizes(
        symbol_size,
        max_block_size,
        repair_overhead,
        payload,
        object_id_raw
    ),
    Scenario::RepairSymbolCount {
        symbol_size,
        max_block_size,
        repair_overhead,
        explicit_repair_count,
        payload,
        object_id_raw,
    } => fuzz_repair_symbol_count(
        symbol_size,
        max_block_size,
        repair_overhead,
        explicit_repair_count,
        payload,
        object_id_raw
    ),
});

fn fuzz_basic_encoding(
    symbol_size: u16,
    max_block_size: u16,
    repair_overhead: u8,
    payload: Vec<u8>,
    object_id_raw: u64,
) {
    let config = sanitize_config(symbol_size, max_block_size, repair_overhead);
    let mut pipeline = create_pipeline(config);
    let payload = sanitize_payload(payload);
    let object_id = ObjectId::new_for_test(object_id_raw);

    // Basic encoding should not crash
    let result = pipeline.encode(object_id, &payload);

    // Collect all symbols and validate basic properties
    let symbols: Result<Vec<_>, _> = result.collect();

    match symbols {
        Ok(symbols) => {
            // Validate symbol properties
            for symbol in &symbols {
                // Symbol data should not be empty (unless original payload was empty and no source symbols)
                let symbol_data = symbol.symbol().data();
                assert!(symbol_data.len() <= config.symbol_size as usize);

                // Symbol should have valid kind
                let kind = symbol.symbol().id().kind();
                assert!(matches!(kind, SymbolKind::Source | SymbolKind::Repair));
            }

            // If payload was not empty, we should have at least one source symbol
            if !payload.is_empty() {
                let source_count = symbols.iter()
                    .filter(|s| s.symbol().id().kind() == SymbolKind::Source)
                    .count();
                assert!(source_count > 0, "Non-empty payload should generate at least one source symbol");
            }
        }
        Err(_) => {
            // Encoding errors are acceptable for invalid configurations or edge cases
        }
    }
}

fn fuzz_empty_payload(
    symbol_size: u16,
    max_block_size: u16,
    repair_overhead: u8,
    object_id_raw: u64,
) {
    let config = sanitize_config(symbol_size, max_block_size, repair_overhead);
    let mut pipeline = create_pipeline(config);
    let object_id = ObjectId::new_for_test(object_id_raw);

    // Empty payload encoding should not crash
    let result = pipeline.encode(object_id, &[]);
    let symbols: Result<Vec<_>, _> = result.collect();

    match symbols {
        Ok(symbols) => {
            // Empty payload should produce no symbols
            assert!(symbols.is_empty(), "Empty payload should produce no symbols");
        }
        Err(_) => {
            // Configuration errors are acceptable
        }
    }
}

fn fuzz_oversized_payload(
    symbol_size: u16,
    max_block_size: u16,
    repair_overhead: u8,
    oversize_factor: u8,
    object_id_raw: u64,
) {
    let config = sanitize_config(symbol_size, max_block_size, repair_overhead);
    let mut pipeline = create_pipeline(config);
    let object_id = ObjectId::new_for_test(object_id_raw);

    // Create payload that exceeds reasonable limits
    let base_size = config.max_block_size.min(4096);
    let oversize = base_size.saturating_mul((oversize_factor as usize + 1).min(8));
    let payload = vec![0u8; oversize.min(MAX_PAYLOAD_SIZE)];

    // Oversized payload should either succeed or fail gracefully
    let result = pipeline.encode(object_id, &payload);
    let symbols: Result<Vec<_>, _> = result.collect();

    match symbols {
        Ok(symbols) => {
            // If it succeeds, symbols should be valid
            for symbol in &symbols {
                let symbol_data = symbol.symbol().data();
                assert!(symbol_data.len() <= config.symbol_size as usize);
            }
        }
        Err(_) => {
            // Encoding errors are expected for oversized payloads
        }
    }
}

fn fuzz_edge_case_symbol_sizes(
    symbol_size: u8,
    max_block_size: u16,
    repair_overhead: u8,
    payload: Vec<u8>,
    object_id_raw: u64,
) {
    // Test very small symbol sizes (which should fail)
    let symbol_size = symbol_size.clamp(0, 16) as u16;
    let config = sanitize_config(symbol_size, max_block_size, repair_overhead);
    let mut pipeline = create_pipeline(config);
    let payload = sanitize_payload(payload);
    let object_id = ObjectId::new_for_test(object_id_raw);

    let result = pipeline.encode(object_id, &payload);
    let symbols: Result<Vec<_>, _> = result.collect();

    match symbols {
        Ok(symbols) => {
            // If it succeeds with tiny symbol size, validate constraints
            for symbol in &symbols {
                let symbol_data = symbol.symbol().data();
                assert!(symbol_data.len() <= config.symbol_size as usize);
            }
        }
        Err(_) => {
            // Edge case symbol sizes should often fail gracefully
        }
    }
}

fn fuzz_repair_symbol_count(
    symbol_size: u16,
    max_block_size: u16,
    repair_overhead: u8,
    explicit_repair_count: u16,
    payload: Vec<u8>,
    object_id_raw: u64,
) {
    let config = sanitize_config(symbol_size, max_block_size, repair_overhead);
    let mut pipeline = create_pipeline(config);
    let payload = sanitize_payload(payload);
    let object_id = ObjectId::new_for_test(object_id_raw);
    let repair_count = explicit_repair_count.clamp(0, 32) as usize;

    // Test explicit repair count encoding
    let result = pipeline.encode_with_repair(object_id, &payload, repair_count);
    let symbols: Result<Vec<_>, _> = result.collect();

    match symbols {
        Ok(symbols) => {
            let source_count = symbols.iter()
                .filter(|s| s.symbol().id().kind() == SymbolKind::Source)
                .count();
            let _repair_count_actual = symbols.iter()
                .filter(|s| s.symbol().id().kind() == SymbolKind::Repair)
                .count();

            // Basic sanity checks
            for symbol in &symbols {
                let symbol_data = symbol.symbol().data();
                assert!(symbol_data.len() <= config.symbol_size as usize);
            }

            // If we have a non-empty payload, we should have source symbols
            if !payload.is_empty() {
                assert!(source_count > 0, "Non-empty payload should generate source symbols");
            }
        }
        Err(_) => {
            // Encoding errors are acceptable
        }
    }
}

fn sanitize_config(symbol_size: u16, max_block_size: u16, repair_overhead: u8) -> EncodingConfig {
    let symbol_size = symbol_size.clamp(1, MAX_SYMBOL_SIZE).max(1);
    let max_block_size = (max_block_size as usize).clamp(
        symbol_size as usize,
        MAX_MAX_BLOCK_SIZE
    );
    let repair_overhead = (repair_overhead as f64 / 255.0)
        * (MAX_REPAIR_OVERHEAD - MIN_REPAIR_OVERHEAD)
        + MIN_REPAIR_OVERHEAD;

    EncodingConfig {
        symbol_size,
        max_block_size,
        repair_overhead,
        encoding_parallelism: 1,
        decoding_parallelism: 1,
    }
}

fn create_pipeline(config: EncodingConfig) -> EncodingPipeline {
    let pool = SymbolPool::new(PoolConfig::default());
    EncodingPipeline::new(config, pool)
}

fn sanitize_payload(mut payload: Vec<u8>) -> Vec<u8> {
    payload.truncate(MAX_PAYLOAD_SIZE);
    payload
}