//! Fuzz target for RaptorQ codec frame splitter.
//!
//! This harness tests the RaptorQ encoding pipeline's frame splitting functionality
//! with adversarial inputs including:
//! - Variable data sizes (empty, small, large, boundary conditions)
//! - Different symbol sizes and repair counts
//! - Invalid encoding configurations
//! - Edge cases in block planning and frame generation
//!
//! Validates that encoding either produces valid encoded symbols or fails
//! cleanly with appropriate EncodingError, never panicking.

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

use asupersync::codec::raptorq::{EncodingConfig, EncodingPipeline};
use asupersync::types::ObjectId;

const MAX_INPUT_SIZE: usize = 32768; // 32KB limit
const MAX_SYMBOL_SIZE: usize = 8192;  // 8KB symbol limit
const MAX_REPAIR_COUNT: usize = 256;

/// Adversarial configuration for RaptorQ codec frame splitter fuzzing
#[derive(Debug, Arbitrary)]
struct FrameSplitterFuzzInput {
    // Data to encode
    data: Vec<u8>,

    // Object ID for encoding
    object_id_seed: u64,

    // Encoding configuration parameters
    symbol_size: u16,
    repair_overhead_percent: u8,
    explicit_repair_count: Option<u16>,

    // Adversarial scenarios
    scenario: FrameSplitterScenario,
}

#[derive(Debug, Arbitrary)]
enum FrameSplitterScenario {
    /// Normal encoding with valid parameters
    Normal,
    /// Empty data edge case
    EmptyData,
    /// Single byte data
    SingleByte,
    /// Data size exactly matching symbol size boundary
    ExactSymbolBoundary,
    /// Data size just over symbol boundary
    OverSymbolBoundary,
    /// Very small symbol size
    MinimalSymbolSize,
    /// Very large symbol size
    MaximalSymbolSize,
    /// High repair overhead
    HighRepairOverhead,
    /// Zero repair overhead
    ZeroRepairOverhead,
    /// Maximum repair count
    MaxRepairCount,
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_SIZE {
        return;
    }

    let mut u = Unstructured::new(data);
    let input: Result<FrameSplitterFuzzInput, _> = u.arbitrary();
    if input.is_err() {
        return;
    }
    let input = input.unwrap();

    test_frame_splitter_with_scenario(&input);
});

/// Test RaptorQ codec frame splitter with adversarial scenarios
fn test_frame_splitter_with_scenario(input: &FrameSplitterFuzzInput) {
    // Prepare data based on scenario
    let test_data = match input.scenario {
        FrameSplitterScenario::EmptyData => Vec::new(),
        FrameSplitterScenario::SingleByte => vec![42u8],
        FrameSplitterScenario::ExactSymbolBoundary => {
            let symbol_size = input.symbol_size.clamp(1, MAX_SYMBOL_SIZE as u16) as usize;
            vec![0u8; symbol_size * 2] // Exactly 2 symbols
        }
        FrameSplitterScenario::OverSymbolBoundary => {
            let symbol_size = input.symbol_size.clamp(1, MAX_SYMBOL_SIZE as u16) as usize;
            vec![0u8; symbol_size * 2 + 1] // Just over 2 symbols
        }
        _ => input.data.iter().take(MAX_INPUT_SIZE).cloned().collect(),
    };

    // Configure encoding parameters based on scenario
    let (symbol_size, repair_overhead_percent) = match input.scenario {
        FrameSplitterScenario::MinimalSymbolSize => (4, input.repair_overhead_percent),
        FrameSplitterScenario::MaximalSymbolSize => (MAX_SYMBOL_SIZE as u16, input.repair_overhead_percent),
        FrameSplitterScenario::HighRepairOverhead => (input.symbol_size, 200), // 200% overhead
        FrameSplitterScenario::ZeroRepairOverhead => (input.symbol_size, 0),
        _ => (input.symbol_size, input.repair_overhead_percent),
    };

    // Clamp parameters to reasonable ranges
    let symbol_size = symbol_size.clamp(4, MAX_SYMBOL_SIZE as u16) as usize;
    let repair_overhead_percent = repair_overhead_percent.clamp(0, 255) as usize;

    // Create encoding configuration
    let config = EncodingConfig {
        symbol_size,
        repair_overhead_percent,
        ..Default::default()
    };

    // Test encoding pipeline - should never panic
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut pipeline = EncodingPipeline::new(config);
        let object_id = ObjectId::new_for_test(input.object_id_seed as u32, 0);

        // Test both encoding variants
        test_encoding_variants(&mut pipeline, object_id, &test_data, input.explicit_repair_count);
    }));

    match result {
        Ok(_) => {
            // Encoding succeeded or failed cleanly
        }
        Err(_) => {
            panic!("RaptorQ codec frame splitter panicked with input: {:?}", input);
        }
    }
}

/// Test different encoding variants with the same data
fn test_encoding_variants(
    pipeline: &mut EncodingPipeline,
    object_id: ObjectId,
    data: &[u8],
    explicit_repair_count: Option<u16>,
) {
    // Test 1: Basic encoding
    let basic_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let iter = pipeline.encode(object_id, data);

        // Consume iterator to test frame splitting
        let symbols: Result<Vec<_>, _> = iter.collect();
        symbols
    }));

    if basic_result.is_err() {
        panic!("Basic encoding panicked");
    }

    // Test 2: Encoding with explicit repair count (if specified)
    if let Some(repair_count) = explicit_repair_count {
        let repair_count = repair_count.clamp(0, MAX_REPAIR_COUNT as u16) as usize;

        let repair_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let iter = pipeline.encode_with_repair(object_id, data, repair_count);

            // Consume iterator to test frame splitting with explicit repair
            let symbols: Result<Vec<_>, _> = iter.collect();
            symbols
        }));

        if repair_result.is_err() {
            panic!("Repair encoding panicked with repair_count={}", repair_count);
        }
    }

    // Test 3: Multiple encoding calls with same pipeline (state consistency)
    if !data.is_empty() && data.len() <= 1024 { // Limit for performance
        let multi_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            for i in 0..3 {
                let iter_object_id = ObjectId::new_for_test(object_id.inner() + i, 0);
                let iter = pipeline.encode(iter_object_id, data);

                // Just get first few symbols to test consistency
                let symbols: Vec<_> = iter.take(5).collect();

                // Validate that all symbols are either Ok or consistent errors
                for symbol_result in symbols {
                    match symbol_result {
                        Ok(symbol) => {
                            // Validate basic symbol properties
                            assert!(symbol.data.len() > 0, "Symbol data should not be empty");
                        }
                        Err(_) => {
                            // Error is acceptable - just shouldn't panic
                        }
                    }
                }
            }
        }));

        if multi_result.is_err() {
            panic!("Multiple encoding calls panicked");
        }
    }
}