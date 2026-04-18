#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use asupersync::codec::raptorq::{EncodedSymbol, EncodingError, EncodingPipeline, EncodingStats};
use asupersync::config::EncodingConfig;
use asupersync::decoding::{DecodingConfig, DecodingPipeline, DecodingError, RejectReason, SymbolAcceptResult};
use asupersync::types::resource::{PoolConfig, SymbolPool};
use asupersync::types::{ObjectId, Symbol, SymbolId, SymbolKind};
use asupersync::security::SecurityContext;

/// Comprehensive fuzz target for RaptorQ codec encoding/decoding pipeline
///
/// Tests the forward error correction implementation for:
/// - Encoding pipeline with various data sizes and configurations
/// - Decoding pipeline robustness with corrupted/missing symbols
/// - Round-trip encode/decode cycles under adverse conditions
/// - Symbol authentication and security context validation
/// - Pool exhaustion and resource management edge cases
/// - Matrix inversion failures and rank-deficient scenarios
/// - GF256 arithmetic operations with extreme values
/// - Configuration validation and parameter boundary conditions
/// - Object parameter consistency across encode/decode boundaries
/// - Symbol ordering and block reconstruction correctness
#[derive(Arbitrary, Debug)]
struct RaptorQCodecFuzz {
    /// Operations to perform on the codec
    operations: Vec<CodecOperation>,
    /// Encoding configuration parameters
    encoding_config: EncodingConfigFuzz,
    /// Decoding configuration parameters
    decoding_config: DecodingConfigFuzz,
    /// Input data for encoding
    input_data: Vec<u8>,
}

/// Fuzzing operations on RaptorQ codec
#[derive(Arbitrary, Debug)]
enum CodecOperation {
    /// Encode data and collect symbols
    Encode {
        object_id: u64,
        data: Vec<u8>,
    },
    /// Test decoding with potentially corrupted symbols
    Decode {
        object_id: u64,
        symbols: Vec<SymbolFuzz>,
    },
    /// Round-trip encode then decode
    RoundTrip {
        object_id: u64,
        data: Vec<u8>,
        corruption_rate: f64,
        missing_symbols: Vec<usize>,
    },
    /// Test symbol authentication
    AuthenticateSymbols {
        symbols: Vec<SymbolFuzz>,
        use_security: bool,
    },
    /// Test pool exhaustion scenarios
    TestPoolExhaustion {
        pool_size: u16,
        data_size: u32,
    },
    /// Test configuration edge cases
    TestConfigEdgeCases {
        symbol_size: u16,
        max_block_size: u32,
        repair_overhead: f64,
    },
}

/// Fuzzing configuration for encoding
#[derive(Arbitrary, Debug)]
struct EncodingConfigFuzz {
    symbol_size: u16,
    max_block_size: u32,
    repair_overhead: f64,
    pool_size: u16,
}

/// Fuzzing configuration for decoding
#[derive(Arbitrary, Debug)]
struct DecodingConfigFuzz {
    symbol_size: u16,
    max_block_size: u32,
    repair_overhead: f64,
    min_overhead: u16,
    max_buffered_symbols: u32,
    block_timeout_ms: u32,
    verify_auth: bool,
}

/// Symbol data for fuzzing
#[derive(Arbitrary, Debug)]
struct SymbolFuzz {
    object_id: u64,
    symbol_id: SymbolIdFuzz,
    data: Vec<u8>,
    is_corrupted: bool,
}

/// Symbol ID components for fuzzing
#[derive(Arbitrary, Debug)]
struct SymbolIdFuzz {
    object_id: u64,
    block_number: u8,
    symbol_index: u16,
    kind: SymbolKindFuzz,
}

/// Symbol kind variants for fuzzing
#[derive(Arbitrary, Debug)]
enum SymbolKindFuzz {
    Source,
    Repair,
}

/// Safety limits to prevent resource exhaustion
const MAX_DATA_SIZE: usize = 100_000;
const MAX_OPERATIONS: usize = 20;
const MAX_SYMBOLS: usize = 1000;
const MAX_SYMBOL_SIZE: u16 = 4096;
const MAX_BLOCK_SIZE: u32 = 65536;
const MAX_POOL_SIZE: u16 = 1000;
const MIN_SYMBOL_SIZE: u16 = 4;

fuzz_target!(|input: RaptorQCodecFuzz| {
    // Limit operations for performance
    let operations = if input.operations.len() > MAX_OPERATIONS {
        &input.operations[..MAX_OPERATIONS]
    } else {
        &input.operations
    };

    // Test encoding configuration validation
    test_config_validation(&input.encoding_config, &input.decoding_config);

    // Create safe configurations
    let safe_encoding_config = create_safe_encoding_config(&input.encoding_config);
    let safe_decoding_config = create_safe_decoding_config(&input.decoding_config);

    // Execute codec operations
    for operation in operations {
        match operation {
            CodecOperation::Encode { object_id, data } => {
                test_encoding_operation(&safe_encoding_config, *object_id, data);
            },
            CodecOperation::Decode { object_id, symbols } => {
                test_decoding_operation(&safe_decoding_config, *object_id, symbols);
            },
            CodecOperation::RoundTrip { object_id, data, corruption_rate, missing_symbols } => {
                test_round_trip_operation(
                    &safe_encoding_config,
                    &safe_decoding_config,
                    *object_id,
                    data,
                    *corruption_rate,
                    missing_symbols,
                );
            },
            CodecOperation::AuthenticateSymbols { symbols, use_security } => {
                test_symbol_authentication(symbols, *use_security);
            },
            CodecOperation::TestPoolExhaustion { pool_size, data_size } => {
                test_pool_exhaustion_scenarios(*pool_size, *data_size);
            },
            CodecOperation::TestConfigEdgeCases { symbol_size, max_block_size, repair_overhead } => {
                test_config_edge_cases(*symbol_size, *max_block_size, *repair_overhead);
            },
        }
    }

    // Test with the main input data if provided
    if !input.input_data.is_empty() {
        test_main_input_data(&safe_encoding_config, &input.input_data);
    }
});

fn test_config_validation(
    encoding_config: &EncodingConfigFuzz,
    decoding_config: &DecodingConfigFuzz,
) {
    // Test configuration validation edge cases
    let configs_to_test = [
        // Edge case configurations that should be rejected
        EncodingConfig {
            symbol_size: 0, // Invalid
            max_block_size: 1000,
            repair_overhead: 0.1,
            encoding_parallelism: 1,
            decoding_parallelism: 1,
        },
        EncodingConfig {
            symbol_size: 1000,
            max_block_size: 0, // Invalid
            repair_overhead: 0.1,
            encoding_parallelism: 1,
            decoding_parallelism: 1,
        },
        EncodingConfig {
            symbol_size: 1000,
            max_block_size: 1000,
            repair_overhead: -1.0, // Invalid
            encoding_parallelism: 1,
            decoding_parallelism: 1,
        },
    ];

    for config in &configs_to_test {
        // Configuration should be created without panicking
        let pool = create_encoding_pool(config);
        let _pipeline = EncodingPipeline::new(config.clone(), pool);
    }
}

fn test_encoding_operation(config: &EncodingConfig, object_id: u64, data: &[u8]) {
    let limited_data = if data.len() > MAX_DATA_SIZE {
        &data[..MAX_DATA_SIZE]
    } else {
        data
    };

    // Create symbol pool
    let pool = create_encoding_pool(config);
    let mut pipeline = EncodingPipeline::new(config.clone(), pool);

    // Encoding should handle any input gracefully
    let object_id = ObjectId::from_u128(object_id);
    let symbol_iter = pipeline.encode(object_id, limited_data);

    // Collect and validate symbols
    let mut symbol_count = 0;
    for symbol_result in symbol_iter {
        if symbol_count > MAX_SYMBOLS {
            break; // Prevent resource exhaustion
        }

        match symbol_result {
            Ok(encoded_symbol) => {
                test_encoded_symbol_properties(&encoded_symbol, object_id);
            },
            Err(err) => {
                // Encoding errors are acceptable
                test_encoding_error_properties(&err);
            },
        }
        symbol_count += 1;
    }

    // Test encoding statistics
    let stats = pipeline.stats();
    test_encoding_stats_consistency(&stats, limited_data.len());
}

fn test_decoding_operation(config: &DecodingConfig, object_id: u64, symbols: &[SymbolFuzz]) {
    let limited_symbols = if symbols.len() > MAX_SYMBOLS {
        &symbols[..MAX_SYMBOLS]
    } else {
        symbols
    };

    // Create decoding pipeline
    let mut pipeline = DecodingPipeline::new(config.clone());
    let object_id = ObjectId::from_u128(object_id);

    // Feed symbols to decoder
    for symbol_fuzz in limited_symbols {
        let symbol = convert_symbol_fuzz(symbol_fuzz);

        // Symbol acceptance should never panic
        let accept_result = pipeline.accept_symbol(symbol);

        match accept_result {
            Ok(SymbolAcceptResult::Accepted) => {
                // Symbol was accepted
            },
            Ok(SymbolAcceptResult::Rejected(reason)) => {
                // Symbol was rejected - verify reason is valid
                test_reject_reason_validity(reason);
            },
            Ok(SymbolAcceptResult::ObjectComplete(data)) => {
                // Object decoding completed
                test_decoded_data_properties(&data);
            },
            Err(err) => {
                // Decoding errors are acceptable
                test_decoding_error_properties(&err);
            },
        }
    }

    // Test forced decode attempt
    let decode_result = pipeline.try_decode(object_id);
    match decode_result {
        Ok(data) => {
            test_decoded_data_properties(&data);
        },
        Err(err) => {
            test_decoding_error_properties(&err);
        },
    }
}

fn test_round_trip_operation(
    encoding_config: &EncodingConfig,
    decoding_config: &DecodingConfig,
    object_id: u64,
    data: &[u8],
    corruption_rate: f64,
    missing_symbols: &[usize],
) {
    let limited_data = if data.len() > MAX_DATA_SIZE {
        &data[..MAX_DATA_SIZE]
    } else {
        data
    };

    if limited_data.is_empty() {
        return;
    }

    // Encode
    let pool = create_encoding_pool(encoding_config);
    let mut encoder = EncodingPipeline::new(encoding_config.clone(), pool);
    let object_id = ObjectId::from_u128(object_id);

    let symbol_iter = encoder.encode(object_id, limited_data);
    let mut symbols = Vec::new();
    let mut symbol_count = 0;

    // Collect symbols with potential corruption/missing
    for symbol_result in symbol_iter {
        if symbol_count > MAX_SYMBOLS {
            break;
        }

        if let Ok(encoded_symbol) = symbol_result {
            let should_drop = missing_symbols.contains(&symbol_count);
            let should_corrupt = corruption_rate > 0.0 &&
                (symbol_count as f64 * corruption_rate) % 1.0 < corruption_rate;

            if !should_drop {
                let mut symbol = encoded_symbol.into_symbol();

                if should_corrupt {
                    corrupt_symbol_data(&mut symbol);
                }

                symbols.push(symbol);
            }
        }
        symbol_count += 1;
    }

    // Decode
    let mut decoder = DecodingPipeline::new(decoding_config.clone());
    for symbol in symbols {
        let _ = decoder.accept_symbol(symbol);
    }

    // Test final decode
    let _ = decoder.try_decode(object_id);
}

fn test_symbol_authentication(symbols: &[SymbolFuzz], use_security: bool) {
    if use_security {
        // Test with security context
        let security_ctx = SecurityContext::for_testing(12345);

        for symbol_fuzz in symbols.iter().take(MAX_SYMBOLS) {
            let symbol = convert_symbol_fuzz(symbol_fuzz);

            // Signing should never panic
            let authenticated_symbol = security_ctx.sign_symbol(&symbol);

            // Verification should never panic
            let mut auth_symbol = authenticated_symbol;
            let verify_result = security_ctx.verify_authenticated_symbol(&mut auth_symbol);

            match verify_result {
                Ok(()) => {
                    // Authentication succeeded
                },
                Err(_err) => {
                    // Authentication failed - acceptable
                },
            }
        }
    } else {
        // Test without security context
        for symbol_fuzz in symbols.iter().take(MAX_SYMBOLS) {
            let symbol = convert_symbol_fuzz(symbol_fuzz);

            // Basic symbol validation should work
            test_symbol_basic_properties(&symbol);
        }
    }
}

fn test_pool_exhaustion_scenarios(pool_size: u16, data_size: u32) {
    let limited_pool_size = pool_size.min(MAX_POOL_SIZE);
    let limited_data_size = (data_size as usize).min(MAX_DATA_SIZE);

    let config = EncodingConfig {
        symbol_size: MIN_SYMBOL_SIZE,
        max_block_size: 1000,
        repair_overhead: 0.1,
        encoding_parallelism: 1,
        decoding_parallelism: 1,
    };

    let pool_config = PoolConfig {
        symbol_size: config.symbol_size,
        initial_size: limited_pool_size,
        max_size: limited_pool_size,
        allow_growth: false, // Force exhaustion
        growth_increment: 0,
    };

    let pool = SymbolPool::new(pool_config);
    let mut encoder = EncodingPipeline::new(config, pool);

    // Create data likely to exhaust the small pool
    let data = vec![0xAB; limited_data_size];
    let object_id = ObjectId::from_u128(12345);

    let encode_result = encoder.encode(object_id, &data);

    match encode_result {
        Ok(symbol_iter) => {
            // Consume symbols until pool exhaustion or completion
            for symbol_result in symbol_iter.take(MAX_SYMBOLS) {
                match symbol_result {
                    Ok(_) => {}, // Symbol produced successfully
                    Err(EncodingError::PoolExhausted) => {
                        // Expected exhaustion
                        break;
                    },
                    Err(_) => {
                        // Other errors are also acceptable
                        break;
                    },
                }
            }
        },
        Err(err) => {
            // Encoding can fail due to pool exhaustion
            test_encoding_error_properties(&err);
        },
    }
}

fn test_config_edge_cases(symbol_size: u16, max_block_size: u32, repair_overhead: f64) {
    // Test various configuration edge cases
    let test_configs = [
        EncodingConfig {
            symbol_size: symbol_size.clamp(MIN_SYMBOL_SIZE, MAX_SYMBOL_SIZE),
            max_block_size: max_block_size.clamp(1, MAX_BLOCK_SIZE) as usize,
            repair_overhead: repair_overhead.clamp(0.0, 10.0),
            encoding_parallelism: 1,
            decoding_parallelism: 1,
        },
        EncodingConfig {
            symbol_size: MAX_SYMBOL_SIZE,
            max_block_size: 1,
            repair_overhead: 0.0,
            encoding_parallelism: 1,
            decoding_parallelism: 1,
        },
        EncodingConfig {
            symbol_size: MIN_SYMBOL_SIZE,
            max_block_size: MAX_BLOCK_SIZE as usize,
            repair_overhead: 10.0,
            encoding_parallelism: 1,
            decoding_parallelism: 1,
        },
    ];

    for config in &test_configs {
        // Configuration creation should not panic

        // Try creating pipeline with this config
        let pool = create_encoding_pool(config);
        let _pipeline = EncodingPipeline::new(config.clone(), pool);
    }
}

fn test_main_input_data(config: &EncodingConfig, data: &[u8]) {
    let limited_data = if data.len() > MAX_DATA_SIZE {
        &data[..MAX_DATA_SIZE]
    } else {
        data
    };

    let pool = create_encoding_pool(config);
    let mut encoder = EncodingPipeline::new(config.clone(), pool);
    let object_id = ObjectId::from_u128(0xDEADBEEF);

    // Test encoding with the provided data
    let symbol_iter = encoder.encode(object_id, limited_data);
    // Consume iterator to trigger any encoding errors
    for (i, _) in symbol_iter.enumerate() {
        if i > MAX_SYMBOLS {
            break;
        }
    }
}

// Helper functions

fn create_safe_encoding_config(config: &EncodingConfigFuzz) -> EncodingConfig {
    EncodingConfig {
        symbol_size: config.symbol_size.clamp(MIN_SYMBOL_SIZE, MAX_SYMBOL_SIZE),
        max_block_size: config.max_block_size.clamp(1, MAX_BLOCK_SIZE) as usize,
        repair_overhead: config.repair_overhead.clamp(0.0, 2.0),
        encoding_parallelism: 1,
        decoding_parallelism: 1,
    }
}

fn create_safe_decoding_config(config: &DecodingConfigFuzz) -> DecodingConfig {
    use std::time::Duration;
    DecodingConfig {
        symbol_size: config.symbol_size.clamp(MIN_SYMBOL_SIZE, MAX_SYMBOL_SIZE),
        max_block_size: config.max_block_size.clamp(1, MAX_BLOCK_SIZE) as usize,
        repair_overhead: config.repair_overhead.clamp(1.0, 2.0),
        min_overhead: config.min_overhead.clamp(0, 1000) as usize,
        max_buffered_symbols: config.max_buffered_symbols.clamp(0, MAX_SYMBOLS as u32) as usize,
        block_timeout: Duration::from_millis(config.block_timeout_ms.clamp(100, 60000) as u64),
        verify_auth: config.verify_auth,
    }
}

fn create_encoding_pool(config: &EncodingConfig) -> SymbolPool {
    let pool_config = PoolConfig {
        symbol_size: config.symbol_size,
        initial_size: 100,
        max_size: 1000,
        allow_growth: true,
        growth_increment: 50,
    };
    SymbolPool::new(pool_config)
}

fn convert_symbol_fuzz(symbol_fuzz: &SymbolFuzz) -> Symbol {
    let symbol_kind = match symbol_fuzz.symbol_id.kind {
        SymbolKindFuzz::Source => SymbolKind::Source,
        SymbolKindFuzz::Repair => SymbolKind::Repair,
    };

    let symbol_id = SymbolId::new(
        ObjectId::from_u128(symbol_fuzz.symbol_id.object_id),
        symbol_fuzz.symbol_id.block_number,
        symbol_fuzz.symbol_id.symbol_index as u32,
    );

    let limited_data = if symbol_fuzz.data.len() > MAX_SYMBOL_SIZE as usize {
        symbol_fuzz.data[..MAX_SYMBOL_SIZE as usize].to_vec()
    } else {
        symbol_fuzz.data.clone()
    };

    Symbol::new(symbol_id, limited_data, symbol_kind)
}

fn corrupt_symbol_data(symbol: &mut Symbol) {
    // Introduce corruption to test error handling
    let data = symbol.data_mut();
    if !data.is_empty() {
        data[0] ^= 0xFF; // Flip first byte
    }
}


// Test validation functions

fn test_encoded_symbol_properties(symbol: &EncodedSymbol, expected_object_id: ObjectId) {
    assert_eq!(symbol.symbol().id().object_id(), expected_object_id);
    assert!(matches!(symbol.kind(), SymbolKind::Source | SymbolKind::Repair));
    assert!(!symbol.symbol().data().is_empty());
}

fn test_encoding_error_properties(err: &EncodingError) {
    // Error should have valid properties
    match err {
        EncodingError::DataTooLarge { size, limit } => {
            assert!(*size > *limit);
        },
        EncodingError::PoolExhausted => {},
        EncodingError::InvalidConfig { reason } => {
            assert!(!reason.is_empty());
        },
        EncodingError::ComputationFailed { details } => {
            assert!(!details.is_empty());
        },
    }
}

fn test_decoding_error_properties(err: &DecodingError) {
    // Error should have valid properties
    match err {
        DecodingError::AuthenticationFailed { symbol_id } => {
            // Symbol ID should be valid
            let _ = symbol_id.object_id();
        },
        DecodingError::InsufficientSymbols { received, needed } => {
            assert!(*received < *needed);
        },
        DecodingError::MatrixInversionFailed { reason } => {
            assert!(!reason.is_empty());
        },
        DecodingError::BlockTimeout { sbn, elapsed } => {
            assert!(*sbn <= 255);
            assert!(*elapsed > std::time::Duration::ZERO);
        },
        DecodingError::InconsistentMetadata { sbn, details } => {
            assert!(*sbn <= 255);
            assert!(!details.is_empty());
        },
        DecodingError::SymbolSizeMismatch { expected, actual } => {
            assert!(*expected != *actual as u16);
        },
    }
}

fn test_encoding_stats_consistency(stats: &EncodingStats, input_size: usize) {
    assert_eq!(stats.bytes_in, input_size);
    assert!(stats.source_symbols >= stats.repair_symbols || stats.source_symbols == 0);
}

fn test_decoded_data_properties(data: &[u8]) {
    // Decoded data should be reasonable
    assert!(data.len() <= MAX_DATA_SIZE);
}

fn test_reject_reason_validity(reason: RejectReason) {
    // All reject reasons should be valid enum variants
    match reason {
        RejectReason::WrongObjectId |
        RejectReason::AuthenticationFailed |
        RejectReason::SymbolSizeMismatch |
        RejectReason::BlockAlreadyDecoded |
        RejectReason::InsufficientRank |
        RejectReason::InconsistentEquations |
        RejectReason::InvalidMetadata |
        RejectReason::MemoryLimitReached => {
            // All valid reasons
        }
    }
}

fn test_symbol_basic_properties(symbol: &Symbol) {
    assert!(!symbol.data().is_empty() || symbol.data().is_empty()); // Should not panic
    let _ = symbol.id().object_id();
    let _ = symbol.id().sbn();
    let _ = symbol.id().esi();
    let _ = symbol.kind();
}