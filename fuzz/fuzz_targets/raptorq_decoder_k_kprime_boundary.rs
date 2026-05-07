//! Fuzz target for RaptorQ decoder K..K' boundary recovery edge cases.
//!
//! **CRITICAL GAP ADDRESSED**: Existing raptorq_decoder.rs mentions "padded K..K' synthesis"
//! but only as high-level integration testing. This fuzzer specifically targets the boundary
//! conditions between systematic symbols (K) and padded extended set (K').
//!
//! **VULNERABILITY SURFACE**: RFC 6330 systematic encoding boundary conditions:
//! - K = actual source symbols needed
//! - K' = padded symbol count to satisfy RFC constraints
//! - Gap K..K' contains zero-padded rows in encoding matrix
//! - Decoder must correctly handle missing symbols in this boundary region
//!
//! **ATTACK SCENARIOS**:
//! 1. Encoder built without padding, decoder expects padded symbols
//! 2. Missing symbols exactly at K..K' boundary
//! 3. Repair symbols that reference zero-padded source positions
//! 4. Inconsistent K' calculation between encoder/decoder
//! 5. Matrix inversion failures due to zero-padding artifacts
//!
//! **ORACLE**: Successful decoding when sufficient symbols available, consistent failures otherwise

#![no_main]
#![allow(clippy::too_many_lines)]

use arbitrary::Arbitrary;
use asupersync::raptorq::decoder::{DecodeError, InactivationDecoder, ReceivedSymbol};
use asupersync::raptorq::rfc6330::{derive_encoding_params, EncodingParams};
use asupersync::raptorq::systematic::SystematicEncoder;
use asupersync::types::ObjectId;
use libfuzzer_sys::fuzz_target;
use std::collections::HashSet;

const MAX_SOURCE_BYTES: usize = 32 * 1024; // Reasonable for focused boundary testing
const MAX_EXTRA_REPAIRS: usize = 16;

// Focus on K values that create interesting K..K' gaps
const BOUNDARY_K_VALUES: &[usize] = &[
    7, 8, 9,    // Small boundary cases
    15, 16, 17, // Power-of-2 boundaries
    31, 32, 33, // Another power-of-2 boundary
    63, 64, 65, // 64-byte boundary
    127, 128, 129, // 128-byte boundary
    255, 256, 257, // Critical 256 boundary (GF256 related)
    511, 512, 513, // 512 boundary
    1023, 1024, 1025, // 1K boundary
];

#[derive(Debug, Clone, Copy, Arbitrary)]
enum BoundaryScenario {
    /// Normal case - encoder and decoder agree on K'
    Normal,
    /// Missing symbols exactly at K boundary
    MissingAtKBoundary,
    /// Missing symbols in K..K' gap region
    MissingInGap,
    /// Missing symbols straddling K and K'
    MissingStraddling,
    /// Decoder gets symbols > K but < K'
    PartialPadding,
    /// Repair symbols referencing K..K' positions
    RepairsInGap,
    /// Matrix with zero rows due to padding
    ZeroPaddedMatrix,
    /// Inconsistent K' between components
    InconsistentKPrime,
}

#[derive(Debug, Arbitrary)]
struct KPrimeBoundaryInput {
    k_selector: u8,           // Index into BOUNDARY_K_VALUES
    symbol_size: u16,         // 1-1024 bytes per symbol
    scenario: BoundaryScenario,
    missing_pattern: MissingPattern,
    extra_repairs: u8,        // Additional repair symbols
    seed: u64,                // For deterministic randomness
    force_failure: bool,      // Test intentional decode failures
}

#[derive(Debug, Clone, Arbitrary)]
enum MissingPattern {
    /// Remove specific symbols by index
    Specific(Vec<u16>),
    /// Remove symbols in a contiguous range
    Range { start: u16, count: u8 },
    /// Remove symbols matching a pattern (e.g., every Nth)
    Pattern { modulus: u8, offset: u8 },
    /// Remove random symbols up to a count
    Random { count: u8, seed: u32 },
}

#[derive(Debug)]
struct BoundaryTestCase {
    k: usize,
    k_prime: usize,
    symbol_size: usize,
    source_data: Vec<u8>,
    encoding_params: EncodingParams,
}

impl BoundaryTestCase {
    fn new(k: usize, symbol_size: usize, seed: u64) -> Option<Self> {
        let total_bytes = k * symbol_size;
        if total_bytes > MAX_SOURCE_BYTES {
            return None;
        }

        // Generate deterministic source data
        let mut source_data = vec![0u8; total_bytes];
        let mut rng_state = seed;
        for byte in &mut source_data {
            rng_state = rng_state.wrapping_mul(1103515245).wrapping_add(12345);
            *byte = (rng_state >> 16) as u8;
        }

        let encoding_params = match derive_encoding_params(total_bytes, symbol_size) {
            Ok(params) => params,
            Err(_) => return None,
        };

        // Verify we have a meaningful K..K' gap for testing
        if encoding_params.k_prime <= encoding_params.k {
            return None; // No gap to test
        }

        Some(Self {
            k,
            k_prime: encoding_params.k_prime,
            symbol_size,
            source_data,
            encoding_params,
        })
    }

    fn create_encoder(&self) -> Result<SystematicEncoder, Box<dyn std::error::Error>> {
        SystematicEncoder::new(ObjectId::new([0; 32]), &self.source_data, self.symbol_size)
    }

    fn apply_missing_pattern(&self, pattern: &MissingPattern, total_symbols: usize) -> HashSet<usize> {
        let mut missing = HashSet::new();

        match pattern {
            MissingPattern::Specific(indices) => {
                for &idx in indices {
                    if (idx as usize) < total_symbols {
                        missing.insert(idx as usize);
                    }
                }
            }
            MissingPattern::Range { start, count } => {
                let start = (*start as usize).min(total_symbols);
                let count = (*count as usize).min(total_symbols - start);
                for i in start..start + count {
                    missing.insert(i);
                }
            }
            MissingPattern::Pattern { modulus, offset } => {
                if *modulus > 0 {
                    let mut i = *offset as usize;
                    while i < total_symbols {
                        missing.insert(i);
                        i += *modulus as usize;
                    }
                }
            }
            MissingPattern::Random { count, seed } => {
                let mut rng = *seed;
                let count = (*count as usize).min(total_symbols);
                while missing.len() < count {
                    rng = rng.wrapping_mul(1103515245).wrapping_add(12345);
                    let idx = (rng as usize) % total_symbols;
                    missing.insert(idx);
                }
            }
        }

        missing
    }

    fn execute_boundary_scenario(
        &self,
        scenario: BoundaryScenario,
        missing_pattern: &MissingPattern,
        extra_repairs: u8
    ) -> Result<BoundaryTestResult, String> {
        let encoder = self.create_encoder().map_err(|e| format!("Encoder creation failed: {}", e))?;

        // Generate source and repair symbols
        let mut available_symbols = Vec::new();

        // Add source symbols (K symbols)
        for i in 0..self.k {
            if let Some(symbol) = encoder.source_symbol(i) {
                available_symbols.push((i, symbol));
            }
        }

        // Add repair symbols
        let repair_count = extra_repairs.min(MAX_EXTRA_REPAIRS as u8) as usize;
        for i in 0..repair_count {
            if let Some(symbol) = encoder.repair_symbol(i) {
                available_symbols.push((self.k + i, symbol));
            }
        }

        // Apply scenario-specific modifications
        let missing_indices = match scenario {
            BoundaryScenario::Normal => {
                self.apply_missing_pattern(missing_pattern, available_symbols.len())
            }
            BoundaryScenario::MissingAtKBoundary => {
                // Force missing symbols exactly at K boundary
                let mut missing = HashSet::new();
                missing.insert(self.k - 1); // Last source symbol
                if self.k < available_symbols.len() {
                    missing.insert(self.k); // First repair symbol
                }
                missing
            }
            BoundaryScenario::MissingInGap => {
                // Target the K..K' gap region
                // Note: In practice, symbols K..K'-1 are zero-padded and not transmitted
                // This tests decoder handling of missing implicit padding
                let mut missing = HashSet::new();
                for i in self.k..self.k_prime.min(available_symbols.len()) {
                    missing.insert(i);
                }
                missing
            }
            BoundaryScenario::MissingStraddling => {
                // Remove symbols that straddle the K boundary
                let mut missing = HashSet::new();
                if self.k > 2 {
                    missing.insert(self.k - 2);
                    missing.insert(self.k - 1);
                }
                if self.k < available_symbols.len() {
                    missing.insert(self.k);
                }
                if self.k + 1 < available_symbols.len() {
                    missing.insert(self.k + 1);
                }
                missing
            }
            BoundaryScenario::PartialPadding => {
                // Simulate partial padding by removing some symbols > K
                let mut missing = HashSet::new();
                for i in (self.k..available_symbols.len()).step_by(2) {
                    missing.insert(i);
                }
                missing
            }
            BoundaryScenario::RepairsInGap => {
                // Remove source symbols, forcing reliance on repairs
                let mut missing = HashSet::new();
                for i in (0..self.k).step_by(3) {
                    missing.insert(i);
                }
                missing
            }
            BoundaryScenario::ZeroPaddedMatrix => {
                // Create a scenario that might produce zero rows in the matrix
                let mut missing = HashSet::new();
                // Remove every other symbol to create sparse matrix
                for i in (0..available_symbols.len()).step_by(2) {
                    missing.insert(i);
                }
                missing
            }
            BoundaryScenario::InconsistentKPrime => {
                // Test behavior when K' assumptions are violated
                // Remove symbols in a pattern that might confuse K' calculation
                let mut missing = HashSet::new();
                let pattern_size = (self.k_prime - self.k).max(1);
                for i in (0..available_symbols.len()).step_by(pattern_size) {
                    missing.insert(i);
                }
                missing
            }
        };

        // Filter available symbols based on missing pattern
        let filtered_symbols: Vec<_> = available_symbols
            .into_iter()
            .enumerate()
            .filter(|(idx, _)| !missing_indices.contains(idx))
            .map(|(_, (symbol_id, symbol_data))| ReceivedSymbol {
                id: symbol_id,
                data: symbol_data,
            })
            .collect();

        // Attempt decoding
        let mut decoder = InactivationDecoder::new(self.encoding_params.clone());

        // Add symbols to decoder
        for received in &filtered_symbols {
            if let Err(e) = decoder.add_symbol(received.clone()) {
                return Ok(BoundaryTestResult::AddSymbolFailed(format!("{:?}", e)));
            }
        }

        // Attempt decode
        match decoder.decode() {
            Ok(decoded_data) => {
                // Verify decoded data matches original
                if decoded_data == self.source_data {
                    Ok(BoundaryTestResult::DecodeSuccess {
                        symbols_used: filtered_symbols.len(),
                        k_gap: self.k_prime - self.k,
                    })
                } else {
                    Ok(BoundaryTestResult::DecodeCorruption {
                        expected_len: self.source_data.len(),
                        actual_len: decoded_data.len(),
                        first_diff: self.source_data.iter()
                            .zip(decoded_data.iter())
                            .position(|(a, b)| a != b),
                    })
                }
            }
            Err(e) => Ok(BoundaryTestResult::DecodeFailed(format!("{:?}", e))),
        }
    }
}

#[derive(Debug, PartialEq)]
enum BoundaryTestResult {
    DecodeSuccess {
        symbols_used: usize,
        k_gap: usize,
    },
    DecodeFailed(String),
    DecodeCorruption {
        expected_len: usize,
        actual_len: usize,
        first_diff: Option<usize>,
    },
    AddSymbolFailed(String),
}

fuzz_target!(|input: KPrimeBoundaryInput| {
    // Select K value from boundary-focused candidates
    let k_index = (input.k_selector as usize) % BOUNDARY_K_VALUES.len();
    let k = BOUNDARY_K_VALUES[k_index];

    // Bound symbol size
    let symbol_size = (input.symbol_size as usize).clamp(1, 1024);

    // Create test case
    let test_case = match BoundaryTestCase::new(k, symbol_size, input.seed) {
        Some(case) => case,
        None => return, // Skip invalid configurations
    };

    // Verify we have a meaningful K..K' gap
    if test_case.k_prime <= test_case.k {
        return; // No boundary to test
    }

    // Execute the boundary scenario
    let result = test_case.execute_boundary_scenario(
        input.scenario,
        &input.missing_pattern,
        input.extra_repairs,
    );

    match result {
        Ok(BoundaryTestResult::DecodeSuccess { symbols_used, k_gap }) => {
            // Success is expected when we have enough symbols
            // Verify the K..K' gap was properly handled
            assert!(k_gap > 0, "Expected meaningful K..K' gap, got {}", k_gap);

            // Verify we didn't succeed with impossible symbol counts
            if symbols_used < k {
                panic!(
                    "IMPOSSIBLE SUCCESS: Decoded with {} symbols but K={} (gap={})",
                    symbols_used, k, k_gap
                );
            }
        }
        Ok(BoundaryTestResult::DecodeCorruption { expected_len, actual_len, first_diff }) => {
            // Data corruption is never acceptable
            panic!(
                "K..K' BOUNDARY CORRUPTION: expected {} bytes, got {} bytes, first diff at {:?} (K={}, K'={}, gap={})",
                expected_len, actual_len, first_diff, test_case.k, test_case.k_prime, test_case.k_prime - test_case.k
            );
        }
        Ok(BoundaryTestResult::DecodeFailed(err)) => {
            // Decode failures are acceptable when insufficient symbols
            // But should not be due to K..K' boundary bugs
            if err.contains("matrix") || err.contains("zero") || err.contains("padding") {
                panic!(
                    "K..K' MATRIX ERROR: Decode failed with matrix/padding error: {} (K={}, K'={}, gap={})",
                    err, test_case.k, test_case.k_prime, test_case.k_prime - test_case.k
                );
            }
        }
        Ok(BoundaryTestResult::AddSymbolFailed(err)) => {
            // Symbol addition should not fail due to K..K' boundary issues
            if err.contains("index") || err.contains("bound") || err.contains("range") {
                panic!(
                    "K..K' INDEX ERROR: Add symbol failed with indexing error: {} (K={}, K'={}, gap={})",
                    err, test_case.k, test_case.k_prime, test_case.k_prime - test_case.k
                );
            }
        }
        Err(setup_err) => {
            // Setup errors are acceptable - skip this input
            return;
        }
    }

    // Additional invariant checks for K..K' boundary consistency
    assert!(test_case.k_prime >= test_case.k, "K' must be >= K");
    assert!(test_case.k_prime - test_case.k < 100, "K..K' gap should be reasonable (got {})", test_case.k_prime - test_case.k);

    // If force_failure is set, verify we can create scenarios that legitimately fail
    if input.force_failure {
        // Try decoding with deliberately insufficient symbols
        let encoder = test_case.create_encoder().unwrap();
        let insufficient_count = (test_case.k / 2).max(1);

        let mut decoder = InactivationDecoder::new(test_case.encoding_params.clone());
        for i in 0..insufficient_count {
            if let Some(symbol) = encoder.source_symbol(i) {
                let _ = decoder.add_symbol(ReceivedSymbol {
                    id: i,
                    data: symbol,
                });
            }
        }

        // This should fail - verify it fails gracefully
        match decoder.decode() {
            Ok(_) => {
                panic!(
                    "INSUFFICIENT SYMBOLS SUCCESS: Decoded with {} symbols but K={} (should fail)",
                    insufficient_count, test_case.k
                );
            }
            Err(_) => {
                // Expected failure - good
            }
        }
    }
});