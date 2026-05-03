#![no_main]
//! RFC 6330 RaptorQ encoder K_max + N_max boundary limits fuzzer.
//!
//! Tests the encoder's behavior at RFC 6330 parameter boundaries, focusing on:
//! 1. K values around the systematic index table limit (~56,403)
//! 2. Various symbol sizes that affect the K calculation
//! 3. Repair overhead combinations that affect N (total encoding symbols)
//! 4. Edge cases around block size limits and object size calculations
//!
//! Oracles:
//! - No panics under any parameter combination
//! - Proper error handling for unsupported K values
//! - Valid encoding symbols when parameters are accepted
//! - Consistent error messages and types

use arbitrary::{Arbitrary, Unstructured};
use asupersync::codec::raptorq::{EncodingConfig, EncodingPipeline};
use asupersync::types::ObjectId;
use asupersync::types::resource::{PoolConfig, SymbolPool};
use libfuzzer_sys::fuzz_target;

/// RFC 6330 boundary testing parameters
#[derive(Arbitrary, Debug, Clone)]
struct Rfc6330TestParams {
    /// K boundary testing: focus around the known limit of ~56,403
    #[arbitrary(with = k_boundary_generator)]
    k_target: usize,

    /// Symbol size affecting K calculation (block_len / symbol_size = K)
    #[arbitrary(with = symbol_size_generator)]
    symbol_size: u16,

    /// Repair overhead affecting N (total symbols = K + repair_symbols)
    #[arbitrary(with = repair_overhead_generator)]
    repair_overhead: f64,

    /// Block size for testing max_object_size calculations
    #[arbitrary(with = block_size_generator)]
    max_block_size: usize,

    /// Test data pattern
    data_pattern: DataPattern,
}

#[derive(Arbitrary, Debug, Clone)]
enum DataPattern {
    /// Empty data (edge case)
    Empty,
    /// Exact block size (triggers K = block_size / symbol_size)
    ExactBlock,
    /// Just over block size (triggers multi-block)
    OverBlock,
    /// Target specific K value
    TargetK,
    /// Max object size minus small delta
    NearMaxObject,
}

/// Generate K values focused on RFC 6330 boundaries
fn k_boundary_generator(u: &mut Unstructured) -> arbitrary::Result<usize> {
    let choice: u8 = u.arbitrary()?;
    match choice % 8 {
        0 => Ok(0),                       // Invalid: K=0
        1 => Ok(1),                       // Minimum valid K
        2 => Ok(56_402),                  // Just under limit
        3 => Ok(56_403),                  // At limit (should work)
        4 => Ok(56_404),                  // Just over limit (should fail)
        5 => Ok(56_500),                  // Well over limit
        6 => Ok(u32::MAX as usize),       // Extreme overflow
        _ => u.int_in_range(1..=57_000)?, // Random around boundary
    }
}

/// Generate symbol sizes that create interesting K calculations
fn symbol_size_generator(u: &mut Unstructured) -> arbitrary::Result<u16> {
    let choice: u8 = u.arbitrary()?;
    match choice % 6 {
        0 => Ok(0),                     // Invalid
        1 => Ok(1),                     // Minimum (creates large K)
        2 => Ok(8),                     // Small (common test size)
        3 => Ok(64),                    // Medium
        4 => Ok(1024),                  // Large (creates small K)
        _ => u.int_in_range(1..=1500)?, // Random valid range
    }
}

/// Generate repair overhead values including edge cases
fn repair_overhead_generator(u: &mut Unstructured) -> arbitrary::Result<f64> {
    let choice: u8 = u.arbitrary()?;
    match choice % 8 {
        0 => Ok(f64::NAN),
        1 => Ok(f64::INFINITY),
        2 => Ok(f64::NEG_INFINITY),
        3 => Ok(0.0), // Invalid: < 1.0
        4 => Ok(0.5), // Invalid: < 1.0
        5 => Ok(1.0), // Minimum valid
        6 => Ok(1.5), // Common value
        _ => u.arbitrary::<f32>().map(|f| f.into())?,
    }
}

/// Generate block sizes affecting object size limits
fn block_size_generator(u: &mut Unstructured) -> arbitrary::Result<usize> {
    let choice: u8 = u.arbitrary()?;
    match choice % 6 {
        0 => Ok(0),         // Invalid
        1 => Ok(1),         // Minimum
        2 => Ok(64),        // Small
        3 => Ok(8192),      // Medium
        4 => Ok(1_000_000), // Large
        _ => u.int_in_range(1..=2_000_000)?,
    }
}

impl Rfc6330TestParams {
    /// Generate test data based on the pattern and parameters
    fn generate_data(&self) -> Vec<u8> {
        if self.symbol_size == 0 || self.max_block_size == 0 {
            return vec![0xAA; 100]; // Fallback for invalid configs
        }

        match self.data_pattern {
            DataPattern::Empty => vec![],
            DataPattern::ExactBlock => vec![0xBB; self.max_block_size],
            DataPattern::OverBlock => vec![0xCC; self.max_block_size + 1],
            DataPattern::TargetK => {
                // Create data that should result in approximately k_target symbols
                let target_bytes = self.k_target.saturating_mul(self.symbol_size as usize);
                let clamped = target_bytes.min(10_000_000); // Prevent extreme allocation
                vec![0xDD; clamped]
            }
            DataPattern::NearMaxObject => {
                let max_obj_size = self.max_block_size.saturating_mul(256); // MAX_SOURCE_BLOCKS
                let near_max = max_obj_size.saturating_sub(1000).min(5_000_000);
                vec![0xEE; near_max]
            }
        }
    }
}

fuzz_target!(|params: Rfc6330TestParams| {
    // Create encoding configuration from fuzzed parameters
    let config = EncodingConfig {
        repair_overhead: params.repair_overhead,
        max_block_size: params.max_block_size,
        symbol_size: params.symbol_size,
        encoding_parallelism: 1, // Keep simple for fuzzing
        decoding_parallelism: 1,
    };

    // Create pipeline - this should never panic
    let pool = SymbolPool::new(PoolConfig::default());
    let mut pipeline = EncodingPipeline::new(config, pool);

    // Generate test data
    let data = params.generate_data();
    let object_id = ObjectId::new_for_test(42);

    // Test encoding - should handle all errors gracefully
    let encoding_result: Result<Vec<_>, _> = pipeline.encode(object_id, &data).collect();

    match encoding_result {
        Ok(symbols) => {
            // If encoding succeeded, verify basic properties
            assert_symbols_valid(&symbols, &params);
        }
        Err(err) => {
            // If encoding failed, verify error is appropriate
            assert_error_appropriate(&err, &params);
        }
    }

    // Test with explicit repair count override
    let mut pipeline2 = EncodingPipeline::new(config, SymbolPool::new(PoolConfig::default()));
    let repair_result: Result<Vec<_>, _> =
        pipeline2.encode_with_repair(object_id, &data, 10).collect();

    // Same validations for repair override
    match repair_result {
        Ok(symbols) => assert_symbols_valid(&symbols, &params),
        Err(err) => assert_error_appropriate(&err, &params),
    }
});

/// Verify that successfully encoded symbols have valid properties
fn assert_symbols_valid(
    symbols: &[Result<
        asupersync::codec::raptorq::EncodedSymbol,
        asupersync::codec::raptorq::EncodingError,
    >],
    params: &Rfc6330TestParams,
) {
    for (idx, symbol_result) in symbols.iter().enumerate() {
        if let Ok(symbol) = symbol_result {
            // Symbol data length should match symbol_size
            assert_eq!(
                symbol.symbol().data().len(),
                params.symbol_size as usize,
                "Symbol {idx} has wrong data length"
            );

            // Symbol ID should be valid
            let id = symbol.id();
            assert!(id.esi() < u32::MAX, "Symbol {idx} has invalid ESI");
        } else {
            panic!("Symbol {idx} encoding failed when pipeline reported success");
        }
    }
}

/// Verify that encoding errors are appropriate for the given parameters
fn assert_error_appropriate(
    err: &asupersync::codec::raptorq::EncodingError,
    params: &Rfc6330TestParams,
) {
    let err_str = err.to_string();

    // Check that error types match expected parameter violations
    if params.symbol_size == 0 {
        assert!(
            err_str.contains("symbol_size must be non-zero"),
            "Expected symbol_size error, got: {err_str}"
        );
    } else if params.max_block_size == 0 {
        assert!(
            err_str.contains("max_block_size must be non-zero"),
            "Expected max_block_size error, got: {err_str}"
        );
    } else if !params.repair_overhead.is_finite() || params.repair_overhead < 1.0 {
        assert!(
            err_str.contains("repair_overhead"),
            "Expected repair_overhead error, got: {err_str}"
        );
    } else if params.k_target > 56_403 {
        // Check for unsupported K error
        assert!(
            err_str.contains("unsupported source block K=")
                || err_str.contains("UnsupportedSourceBlockSize"),
            "Expected unsupported K error for K={}, got: {err_str}",
            params.k_target
        );
    } else if params.data_pattern == DataPattern::NearMaxObject {
        // Large data might hit size limits
        assert!(
            err_str.contains("data too large") || err_str.contains("unsupported source block"),
            "Expected size limit error, got: {err_str}"
        );
    }

    // All errors should be typed appropriately (no generic panics)
    assert!(
        matches!(
            err,
            asupersync::codec::raptorq::EncodingError::DataTooLarge { .. }
                | asupersync::codec::raptorq::EncodingError::InvalidConfig { .. }
                | asupersync::codec::raptorq::EncodingError::PoolExhausted
                | asupersync::codec::raptorq::EncodingError::ComputationFailed { .. }
        ),
        "Error has unexpected variant: {err:?}"
    );
}

impl PartialEq for DataPattern {
    fn eq(&self, other: &Self) -> bool {
        std::mem::discriminant(self) == std::mem::discriminant(other)
    }
}
