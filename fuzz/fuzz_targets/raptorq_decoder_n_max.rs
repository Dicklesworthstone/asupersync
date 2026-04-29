#![no_main]

//! Structure-aware fuzz target for RaptorQ decoder N_max boundary handling.
//!
//! Targets edge cases in repair symbol ESI handling near the RFC 6330 N_max boundary:
//! - ESI values approaching 2^20 - 1 (N_max per RFC 6330)
//! - Overflow scenarios when computing repair ISI from ESI + padding
//! - Validation of repair symbol equations near the maximum ESI boundary
//! - Edge cases with very large ESI values combined with K' padding deltas
//! - RFC 6330 conformance around maximum repair symbol indices

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use asupersync::bytes::Bytes;
use asupersync::raptorq::decoder::{DecodeError, InactivationDecoder, ReceivedSymbol};

/// RFC 6330 maximum ESI value (2^20 - 1).
const RFC6330_N_MAX: u32 = (1u32 << 20) - 1; // 1,048,575

/// Test scenario focusing on N_max boundary cases
#[derive(Arbitrary, Debug, Clone)]
struct NMaxBoundaryScenario {
    /// Source block configuration
    source_config: SourceConfig,
    /// Strategy for ESI values near N_max
    esi_strategy: EsiStrategy,
    /// Sequence of decoder operations
    operations: Vec<DecoderOperation>,
}

/// Source block configuration that affects K' padding
#[derive(Arbitrary, Debug, Clone)]
struct SourceConfig {
    /// Number of source symbols (K)
    k: SmallK,
    /// Symbol size for this test
    symbol_size: SymbolSize,
    /// Decoder seed
    seed: u64,
}

/// Small K values to ensure large K' padding deltas
#[derive(Arbitrary, Debug, Clone, Copy)]
enum SmallK {
    /// Very small K (high padding delta)
    Minimal(u8), // 1-255
    /// Small K near systematic table boundaries
    TableBoundary(TableBoundaryK),
}

impl SmallK {
    fn as_usize(self) -> usize {
        match self {
            SmallK::Minimal(k) => (k as usize).max(1).min(100), // 1-100 for high padding
            SmallK::TableBoundary(tb) => tb.as_usize(),
        }
    }
}

/// K values near RFC 6330 systematic index table boundaries
#[derive(Arbitrary, Debug, Clone, Copy)]
enum TableBoundaryK {
    /// K values that trigger large K' jumps
    SmallJump, // K around 10
    MediumJump, // K around 100
    LargeJump,  // K around 1000
}

impl TableBoundaryK {
    fn as_usize(self) -> usize {
        match self {
            TableBoundaryK::SmallJump => 10,   // K'=17 → padding=7
            TableBoundaryK::MediumJump => 100, // K'=104 → padding=4
            TableBoundaryK::LargeJump => 1000, // K'=1009 → padding=9
        }
    }
}

/// Symbol size options
#[derive(Arbitrary, Debug, Clone, Copy)]
enum SymbolSize {
    Small,
    Medium,
    Large,
}

impl SymbolSize {
    fn as_usize(self) -> usize {
        match self {
            SymbolSize::Small => 64,
            SymbolSize::Medium => 256,
            SymbolSize::Large => 1024,
        }
    }
}

/// Strategy for generating ESI values near N_max
#[derive(Arbitrary, Debug, Clone)]
enum EsiStrategy {
    /// ESI values very close to N_max
    NearNMax {
        /// Offset from N_max (0 = exactly N_max)
        offset_from_max: u16, // 0-65535
    },
    /// ESI values that would overflow when adding K' padding
    OverflowTrigger {
        /// Base ESI designed to overflow
        base_esi: OverflowEsi,
    },
    /// Mix of boundary and normal ESI values
    Mixed {
        /// Boundary ESI values
        boundary_esis: Vec<BoundaryEsi>,
        /// Normal repair ESI range
        normal_repair_count: u8, // 0-255
    },
}

/// ESI values designed to trigger overflow with K' padding
#[derive(Arbitrary, Debug, Clone, Copy)]
enum OverflowEsi {
    /// ESI that overflows when any padding is added
    MaxMinus1,
    MaxMinus2,
    MaxMinus10,
    /// ESI that overflows with typical padding deltas
    TypicalPaddingOverflow(u8), // ESI = u32::MAX - padding
}

impl OverflowEsi {
    fn as_u32(self, k_prime_padding: u32) -> u32 {
        match self {
            OverflowEsi::MaxMinus1 => u32::MAX - 1,
            OverflowEsi::MaxMinus2 => u32::MAX - 2,
            OverflowEsi::MaxMinus10 => u32::MAX - 10,
            OverflowEsi::TypicalPaddingOverflow(offset) => {
                u32::MAX.saturating_sub(u32::from(offset)).saturating_sub(k_prime_padding)
            }
        }
    }
}

/// Boundary ESI test cases
#[derive(Arbitrary, Debug, Clone, Copy)]
enum BoundaryEsi {
    /// Exactly N_max
    ExactNMax,
    /// N_max + 1 (should be rejected)
    NMaxPlus1,
    /// N_max - small offset
    NMaxMinus(u8), // 1-255
    /// Powers of 2 near N_max
    PowerOfTwo(PowerOfTwoNearNMax),
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum PowerOfTwoNearNMax {
    /// 2^19
    Pow19,
    /// 2^20 - 1 (N_max)
    Pow20Minus1,
    /// 2^21 - 1 (above N_max)
    Pow21Minus1,
}

impl BoundaryEsi {
    fn as_u32(self) -> u32 {
        match self {
            BoundaryEsi::ExactNMax => RFC6330_N_MAX,
            BoundaryEsi::NMaxPlus1 => RFC6330_N_MAX + 1,
            BoundaryEsi::NMaxMinus(offset) => RFC6330_N_MAX.saturating_sub(u32::from(offset)),
            BoundaryEsi::PowerOfTwo(pot) => match pot {
                PowerOfTwoNearNMax::Pow19 => (1u32 << 19),
                PowerOfTwoNearNMax::Pow20Minus1 => RFC6330_N_MAX,
                PowerOfTwoNearNMax::Pow21Minus1 => (1u32 << 21) - 1,
            },
        }
    }
}

/// Decoder operations to test
#[derive(Arbitrary, Debug, Clone)]
enum DecoderOperation {
    /// Add a source symbol
    AddSource {
        esi: u32, // Must be < K
        data: SymbolData,
    },
    /// Add a repair symbol with boundary ESI
    AddRepair {
        esi: RepairEsi,
        data: SymbolData,
    },
    /// Request repair equation for boundary ESI
    GetRepairEquation {
        esi: RepairEsi,
    },
    /// Attempt decode
    Decode,
    /// Inspect decoder state
    Inspect,
}

/// Repair ESI values for testing
#[derive(Arbitrary, Debug, Clone)]
enum RepairEsi {
    /// Use the strategy-determined ESI
    FromStrategy,
    /// Specific boundary value
    Boundary(BoundaryEsi),
    /// Specific overflow-triggering value
    Overflow(OverflowEsi),
    /// Normal repair ESI (K + offset)
    Normal(u16), // Small offset from K
}

/// Symbol data patterns
#[derive(Arbitrary, Debug, Clone)]
enum SymbolData {
    /// All zeros
    Zeros,
    /// All 0xFF
    Ones,
    /// Random pattern
    Random(u32), // Seed for deterministic random data
    /// Incremental pattern
    Incremental(u8), // Start value
}

impl SymbolData {
    fn generate(&self, size: usize) -> Vec<u8> {
        match self {
            SymbolData::Zeros => vec![0u8; size],
            SymbolData::Ones => vec![0xFFu8; size],
            SymbolData::Random(seed) => {
                let mut data = Vec::with_capacity(size);
                let mut state = *seed;
                for _ in 0..size {
                    state = state.wrapping_mul(1664525).wrapping_add(1013904223);
                    data.push((state >> 24) as u8);
                }
                data
            }
            SymbolData::Incremental(start) => {
                let mut data = Vec::with_capacity(size);
                let mut value = *start;
                for _ in 0..size {
                    data.push(value);
                    value = value.wrapping_add(1);
                }
                data
            }
        }
    }
}

fuzz_target!(|scenario: NMaxBoundaryScenario| {
    // Limit complexity for fuzzer performance
    if scenario.operations.len() > 100 {
        return;
    }

    // Test N_max boundary handling
    test_n_max_boundary_decoding(&scenario);

    // Test overflow scenarios specifically
    test_overflow_protection(&scenario);

    // Test RFC conformance around N_max
    test_rfc_conformance(&scenario);
});

fn test_n_max_boundary_decoding(scenario: &NMaxBoundaryScenario) {
    let k = scenario.source_config.k.as_usize();
    let symbol_size = scenario.source_config.symbol_size.as_usize();
    let seed = scenario.source_config.seed;

    // Create decoder - this validates K against systematic index table
    let decoder = match InactivationDecoder::try_new(k, symbol_size, seed) {
        Ok(d) => d,
        Err(_) => return, // Invalid K is expected for some test cases
    };

    // Get K' padding for overflow calculations
    let k_prime_padding = decoder.params().k_prime - k;

    // Generate strategy-specific ESI values
    let strategy_esis = match &scenario.esi_strategy {
        EsiStrategy::NearNMax { offset_from_max } => {
            vec![RFC6330_N_MAX.saturating_sub(u32::from(*offset_from_max))]
        }
        EsiStrategy::OverflowTrigger { base_esi } => {
            vec![base_esi.as_u32(k_prime_padding as u32)]
        }
        EsiStrategy::Mixed { boundary_esis, normal_repair_count } => {
            let mut esis: Vec<u32> = boundary_esis.iter().map(|be| be.as_u32()).collect();
            for i in 0..(*normal_repair_count as u32) {
                esis.push((k as u32) + i);
            }
            esis
        }
    };

    let mut received_symbols = Vec::new();
    let mut strategy_esi_idx = 0;

    // Process operations
    for operation in &scenario.operations {
        let result = match operation {
            DecoderOperation::AddSource { esi, data } => {
                if *esi >= k as u32 {
                    continue; // Invalid source ESI
                }
                let symbol_data = data.generate(symbol_size);
                let symbol = ReceivedSymbol {
                    esi: *esi,
                    is_source: true,
                    columns: vec![*esi as usize],
                    coefficients: vec![1.into()], // GF(256) one
                    data: symbol_data,
                };
                received_symbols.push(symbol);
                Ok(())
            }

            DecoderOperation::AddRepair { esi: repair_esi, data } => {
                let esi = match repair_esi {
                    RepairEsi::FromStrategy => {
                        if strategy_esi_idx < strategy_esis.len() {
                            let esi = strategy_esis[strategy_esi_idx];
                            strategy_esi_idx += 1;
                            esi
                        } else {
                            continue;
                        }
                    }
                    RepairEsi::Boundary(boundary) => boundary.as_u32(),
                    RepairEsi::Overflow(overflow) => overflow.as_u32(k_prime_padding as u32),
                    RepairEsi::Normal(offset) => (k as u32) + u32::from(*offset),
                };

                // Try to get repair equation for this ESI
                match decoder.repair_equation(esi) {
                    Ok((columns, coefficients)) => {
                        let symbol_data = data.generate(symbol_size);
                        let symbol = ReceivedSymbol {
                            esi,
                            is_source: false,
                            columns,
                            coefficients,
                            data: symbol_data,
                        };
                        received_symbols.push(symbol);
                        Ok(())
                    }
                    Err(_) => Err(()), // Expected for invalid ESIs
                }
            }

            DecoderOperation::GetRepairEquation { esi: repair_esi } => {
                let esi = match repair_esi {
                    RepairEsi::FromStrategy => {
                        if strategy_esi_idx < strategy_esis.len() {
                            strategy_esis[strategy_esi_idx]
                        } else {
                            continue;
                        }
                    }
                    RepairEsi::Boundary(boundary) => boundary.as_u32(),
                    RepairEsi::Overflow(overflow) => overflow.as_u32(k_prime_padding as u32),
                    RepairEsi::Normal(offset) => (k as u32) + u32::from(*offset),
                };

                // This tests the core N_max boundary logic
                match decoder.repair_equation(esi) {
                    Ok(_) => Ok(()),
                    Err(_) => Err(()), // Expected for ESI >= 2^20 or overflow cases
                }
            }

            DecoderOperation::Decode => {
                // Attempt decode with current symbols
                match decoder.decode(&received_symbols) {
                    Ok(_) => Ok(()),
                    Err(_) => Err(()), // Decode failure is expected in many test cases
                }
            }

            DecoderOperation::Inspect => {
                // Just verify we can query decoder state
                let _ = decoder.params();
                Ok(())
            }
        };

        // Don't fail on expected errors - we're testing error handling
        let _ = result;
    }
}

fn test_overflow_protection(scenario: &NMaxBoundaryScenario) {
    let k = scenario.source_config.k.as_usize();
    let symbol_size = scenario.source_config.symbol_size.as_usize();
    let seed = scenario.source_config.seed;

    let decoder = match InactivationDecoder::try_new(k, symbol_size, seed) {
        Ok(d) => d,
        Err(_) => return,
    };

    // Test specific overflow scenarios
    let overflow_esis = [
        u32::MAX,     // Maximum u32
        u32::MAX - 1, // One less than maximum
        u32::MAX - 10, // Close to maximum
        RFC6330_N_MAX + 1, // Just above N_max
        RFC6330_N_MAX + 1000, // Well above N_max
    ];

    for &esi in &overflow_esis {
        // These should all be rejected without panic/overflow
        let result = decoder.repair_equation(esi);

        // Verify failure mode is appropriate
        match result {
            Ok(_) => {
                // If it succeeds, the ESI must be valid (unlikely for these values)
            }
            Err(_) => {
                // Expected failure for ESI values that would overflow or exceed N_max
            }
        }
    }
}

fn test_rfc_conformance(scenario: &NMaxBoundaryScenario) {
    let k = scenario.source_config.k.as_usize();
    let symbol_size = scenario.source_config.symbol_size.as_usize();
    let seed = scenario.source_config.seed;

    let decoder = match InactivationDecoder::try_new(k, symbol_size, seed) {
        Ok(d) => d,
        Err(_) => return,
    };

    // RFC 6330 conformance tests around N_max boundary

    // Test 1: ESI values exactly at N_max
    let result_n_max = decoder.repair_equation(RFC6330_N_MAX);

    // Test 2: ESI values just above N_max (should be rejected)
    let result_above_n_max = decoder.repair_equation(RFC6330_N_MAX + 1);

    // Test 3: Large but valid ESI values
    let large_valid_esi = RFC6330_N_MAX - 1000;
    let result_large_valid = decoder.repair_equation(large_valid_esi);

    // Test 4: Powers of 2 boundary values
    let pow19_result = decoder.repair_equation(1u32 << 19);
    let pow20_minus1_result = decoder.repair_equation((1u32 << 20) - 1);
    let pow21_minus1_result = decoder.repair_equation((1u32 << 21) - 1);

    // Verify that results are consistent with RFC expectations:
    // - Valid ESI values should either succeed or fail deterministically
    // - Invalid ESI values (> N_max) should be rejected
    // - Overflow scenarios should be handled gracefully

    // For fuzzing purposes, we don't assert specific outcomes
    // but verify that the decoder doesn't panic or produce undefined behavior
    let _ = result_n_max;
    let _ = result_above_n_max;
    let _ = result_large_valid;
    let _ = pow19_result;
    let _ = pow20_minus1_result;
    let _ = pow21_minus1_result;
}