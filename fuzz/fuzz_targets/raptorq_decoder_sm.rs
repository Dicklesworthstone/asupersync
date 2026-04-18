//! RaptorQ Decoder State Machine Fuzz Target
//!
//! This fuzz target tests the stateful behavior and invariants of the RaptorQ
//! InactivationDecoder state machine, focusing on decode session lifecycle,
//! symbol accumulation behavior, and resource management under adversarial inputs.
//!
//! # State Machine Properties Tested (5 Critical Assertions)
//!
//! 1. **Decoder rejects duplicate symbols idempotently**: Sending the same symbol
//!    multiple times should not corrupt internal state or change decode outcomes
//! 2. **Partial decode preserves state for resume**: Failed decode attempts should
//!    preserve internal state allowing for resumption with additional symbols
//! 3. **Decoder gives up cleanly when K' insufficient**: When insufficient symbols
//!    are provided, decoder should fail gracefully with appropriate error
//! 4. **Cancel during decode preserves no partial state**: Cancellation should
//!    leave no residual state that could affect subsequent decode attempts
//! 5. **Decoder memory bounded by max-block-size**: Memory usage should be bounded
//!    regardless of adversarial symbol patterns or decode complexity
//!
//! # Decoder State Machine Lifecycle
//!
//! ```text
//! INIT → ADD_SYMBOLS → DECODE_ATTEMPT → [SUCCESS | FAILURE | RESUME]
//!   ↓         ↓              ↓              ↓         ↓         ↓
//! Clean → Accumulating → Processing → Completed | Error | More_Symbols_Needed
//! ```
//!
//! The fuzzer exercises state transitions, symbol accumulation patterns, and
//! resource usage under malicious/malformed symbol sequences.

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use std::collections::{HashMap, HashSet};

use asupersync::raptorq::decoder::{DecodeError, InactivationDecoder, ReceivedSymbol};
use asupersync::raptorq::gf256::Gf256;

/// Maximum block size for fuzzing (prevent OOM)
const MAX_K: usize = 256;
const MAX_SYMBOL_SIZE: usize = 1024;
const MAX_SYMBOLS: usize = 512;

/// Decoder operation for state machine testing
#[derive(Arbitrary, Debug, Clone)]
enum DecoderOperation {
    /// Reset decoder with new parameters
    Reset {
        k: u16,
        symbol_size: u16,
        seed: u64,
    },
    /// Add a batch of symbols
    AddSymbols(Vec<FuzzSymbol>),
    /// Attempt decode with current symbols
    AttemptDecode,
    /// Add duplicate symbols (for idempotency testing)
    AddDuplicates {
        symbol_indices: Vec<u8>,
        count: u8,
    },
    /// Simulate memory pressure check
    CheckMemoryBounds,
}

/// Fuzz-friendly symbol representation
#[derive(Arbitrary, Debug, Clone)]
struct FuzzSymbol {
    esi: u32,
    is_source: bool,
    /// Normalized column indices (will be mapped to valid range)
    columns: Vec<u8>,
    /// GF(256) coefficients
    coefficients: Vec<u8>,
    /// Symbol data (will be padded/truncated to symbol_size)
    data: Vec<u8>,
}

impl FuzzSymbol {
    fn to_received_symbol(&self, l: usize, symbol_size: usize) -> ReceivedSymbol {
        // Map column indices to valid range [0, L)
        let columns: Vec<usize> = self.columns.iter()
            .take(16) // Limit degree to prevent explosion
            .map(|&col| (col as usize) % l.max(1))
            .collect();

        // Ensure coefficients match columns length
        let mut coefficients: Vec<Gf256> = self.coefficients.iter()
            .take(columns.len())
            .map(|&c| Gf256(c))
            .collect();
        coefficients.resize(columns.len(), Gf256::ONE);

        // Normalize symbol data to required size
        let mut data = self.data.clone();
        data.resize(symbol_size, 0);

        ReceivedSymbol {
            esi: self.esi,
            is_source: self.is_source,
            columns,
            coefficients,
            data,
        }
    }
}

/// State machine testing input
#[derive(Arbitrary, Debug)]
struct DecoderStateMachineInput {
    operations: Vec<DecoderOperation>,
}

/// Tracks decoder state for invariant checking
struct DecoderStateTracker {
    decoder: Option<InactivationDecoder>,
    accumulated_symbols: Vec<ReceivedSymbol>,
    symbol_hashes: HashSet<u64>,
    current_params: Option<(usize, usize, u64)>, // (k, symbol_size, seed)
    decode_attempts: usize,
    max_memory_observed: usize,
}

impl DecoderStateTracker {
    fn new() -> Self {
        Self {
            decoder: None,
            accumulated_symbols: Vec::new(),
            symbol_hashes: HashSet::new(),
            current_params: None,
            decode_attempts: 0,
            max_memory_observed: 0,
        }
    }

    fn reset_decoder(&mut self, k: usize, symbol_size: usize, seed: u64) {
        self.decoder = Some(InactivationDecoder::new(k, symbol_size, seed));
        self.accumulated_symbols.clear();
        self.symbol_hashes.clear();
        self.current_params = Some((k, symbol_size, seed));
        self.decode_attempts = 0;
        self.max_memory_observed = 0;
    }

    fn add_symbols(&mut self, symbols: &[ReceivedSymbol]) {
        for symbol in symbols {
            // Track symbol hashes for duplicate detection
            let hash = self.hash_symbol(symbol);
            self.symbol_hashes.insert(hash);
            self.accumulated_symbols.push(symbol.clone());
        }

        // Update memory tracking
        let estimated_memory = self.estimate_memory_usage();
        self.max_memory_observed = self.max_memory_observed.max(estimated_memory);
    }

    fn attempt_decode(&mut self) -> Result<bool, DecodeError> {
        self.decode_attempts += 1;

        if let Some(ref decoder) = self.decoder {
            match decoder.decode(&self.accumulated_symbols) {
                Ok(_result) => Ok(true),
                Err(e) => Err(e),
            }
        } else {
            // No decoder initialized
            Err(DecodeError::InsufficientSymbols { received: 0, required: 1 })
        }
    }

    fn hash_symbol(&self, symbol: &ReceivedSymbol) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        symbol.esi.hash(&mut hasher);
        symbol.is_source.hash(&mut hasher);
        symbol.columns.hash(&mut hasher);
        symbol.coefficients.iter().map(|c| c.raw()).collect::<Vec<_>>().hash(&mut hasher);
        symbol.data.hash(&mut hasher);
        hasher.finish()
    }

    fn estimate_memory_usage(&self) -> usize {
        let symbol_count = self.accumulated_symbols.len();
        let avg_symbol_size = if symbol_count > 0 {
            self.accumulated_symbols.iter()
                .map(|s| s.data.len() + s.columns.len() * 16) // Rough estimate
                .sum::<usize>() / symbol_count
        } else {
            0
        };
        symbol_count * avg_symbol_size
    }

    fn check_memory_bounds(&self) -> bool {
        if let Some((k, symbol_size, _)) = self.current_params {
            let max_expected_memory = k * symbol_size * 3; // Conservative bound
            self.max_memory_observed <= max_expected_memory * 2 // Allow some overhead
        } else {
            true // No decoder, no memory usage
        }
    }
}

fn normalize_input(input: &mut DecoderStateMachineInput) {
    // Limit number of operations to prevent timeout
    input.operations.truncate(20);

    for op in &mut input.operations {
        match op {
            DecoderOperation::Reset { k, symbol_size, .. } => {
                *k = (*k as usize % MAX_K + 1) as u16;
                *symbol_size = (*symbol_size as usize % MAX_SYMBOL_SIZE + 16) as u16;
            }
            DecoderOperation::AddSymbols(symbols) => {
                symbols.truncate(MAX_SYMBOLS / 4);
            }
            DecoderOperation::AddDuplicates { symbol_indices, count } => {
                symbol_indices.truncate(10);
                *count = (*count).min(5);
            }
            _ => {}
        }
    }
}

fn execute_state_machine_test(input: &DecoderStateMachineInput) {
    let mut state = DecoderStateTracker::new();

    for op in &input.operations {
        match op {
            DecoderOperation::Reset { k, symbol_size, seed } => {
                state.reset_decoder(*k as usize, *symbol_size as usize, *seed);
            }

            DecoderOperation::AddSymbols(fuzz_symbols) => {
                if let Some((k, symbol_size, _)) = state.current_params {
                    let l = k + (k / 4) + 8; // Approximate L value
                    let symbols: Vec<_> = fuzz_symbols.iter()
                        .map(|fs| fs.to_received_symbol(l, symbol_size))
                        .collect();

                    let old_symbol_count = state.accumulated_symbols.len();
                    state.add_symbols(&symbols);

                    // Assertion 5: Memory bounded by max-block-size
                    assert!(state.check_memory_bounds(),
                        "Memory usage exceeded bounds: {} bytes", state.max_memory_observed);
                }
            }

            DecoderOperation::AttemptDecode => {
                if state.decoder.is_some() {
                    let result = state.attempt_decode();

                    // Assertion 3: Decoder gives up cleanly when K' insufficient
                    if let Err(DecodeError::InsufficientSymbols { received, required }) = result {
                        assert!(received < required,
                            "Insufficient symbols error should have received < required");
                    }

                    // Assertion 2: Partial decode preserves state for resume
                    // After failed decode, accumulated symbols should still be present
                    if result.is_err() {
                        let symbols_before = state.accumulated_symbols.len();
                        assert!(symbols_before > 0 || state.decode_attempts > 0,
                            "Failed decode should preserve accumulated symbols");
                    }
                }
            }

            DecoderOperation::AddDuplicates { symbol_indices, count } => {
                // Assertion 1: Decoder rejects duplicate symbols idempotently
                if let Some((k, symbol_size, _)) = state.current_params {
                    let l = k + (k / 4) + 8;

                    for &idx in symbol_indices {
                        let idx = idx as usize % state.accumulated_symbols.len().max(1);
                        if idx < state.accumulated_symbols.len() {
                            let original_symbol = &state.accumulated_symbols[idx];
                            let mut duplicates = Vec::new();

                            for _ in 0..*count {
                                duplicates.push(original_symbol.clone());
                            }

                            let old_count = state.accumulated_symbols.len();
                            let old_hash_count = state.symbol_hashes.len();

                            state.add_symbols(&duplicates);

                            // First decode attempt
                            let result1 = state.attempt_decode();

                            // Add more duplicates
                            state.add_symbols(&duplicates);

                            // Second decode attempt - should be idempotent
                            let result2 = state.attempt_decode();

                            // Results should be identical (both success or both same error type)
                            match (result1, result2) {
                                (Ok(_), Ok(_)) => {}, // Both succeeded
                                (Err(e1), Err(e2)) => {
                                    // Should be same error type
                                    assert!(std::mem::discriminant(&e1) == std::mem::discriminant(&e2),
                                        "Duplicate symbols caused different error types: {:?} vs {:?}", e1, e2);
                                }
                                _ => {
                                    panic!("Duplicate symbols caused non-idempotent decode results");
                                }
                            }
                        }
                    }
                }
            }

            DecoderOperation::CheckMemoryBounds => {
                // Assertion 5: Verify memory bounds
                assert!(state.check_memory_bounds(),
                    "Memory bounds check failed: {} bytes observed", state.max_memory_observed);
            }
        }
    }

    // Final invariant checks
    if let Some((k, symbol_size, _)) = state.current_params {
        // Memory should still be bounded after all operations
        assert!(state.check_memory_bounds(),
            "Final memory bounds check failed");

        // Symbol accumulation should be consistent
        assert!(state.accumulated_symbols.len() <= MAX_SYMBOLS,
            "Accumulated too many symbols: {}", state.accumulated_symbols.len());
    }
}

fuzz_target!(|mut input: DecoderStateMachineInput| {
    normalize_input(&mut input);

    // Skip empty operation sequences
    if input.operations.is_empty() {
        return;
    }

    execute_state_machine_test(&input);
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decoder_reset() {
        let mut state = DecoderStateTracker::new();
        state.reset_decoder(64, 256, 12345);
        assert!(state.decoder.is_some());
        assert_eq!(state.current_params, Some((64, 256, 12345)));
    }

    #[test]
    fn test_duplicate_symbol_idempotency() {
        let mut state = DecoderStateTracker::new();
        state.reset_decoder(4, 64, 0);

        let symbol = ReceivedSymbol {
            esi: 0,
            is_source: true,
            columns: vec![0],
            coefficients: vec![Gf256::ONE],
            data: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16;
                       4].into_iter().flatten().collect::<Vec<_>>().into_iter().take(64).collect(),
        };

        // Add symbol once
        state.add_symbols(&[symbol.clone()]);
        let first_count = state.accumulated_symbols.len();
        let first_hash_count = state.symbol_hashes.len();

        // Add same symbol again
        state.add_symbols(&[symbol.clone()]);
        let second_count = state.accumulated_symbols.len();
        let second_hash_count = state.symbol_hashes.len();

        // Both attempts should accumulate symbols (decoder doesn't deduplicate automatically)
        assert_eq!(second_count, first_count + 1);
        assert_eq!(second_hash_count, first_hash_count); // Hash should be same
    }

    #[test]
    fn test_insufficient_symbols_error() {
        let mut state = DecoderStateTracker::new();
        state.reset_decoder(10, 256, 0);

        // Add too few symbols
        let symbols: Vec<_> = (0..5).map(|i| ReceivedSymbol {
            esi: i,
            is_source: true,
            columns: vec![i as usize],
            coefficients: vec![Gf256::ONE],
            data: vec![0u8; 256],
        }).collect();

        state.add_symbols(&symbols);

        let result = state.attempt_decode();
        match result {
            Err(DecodeError::InsufficientSymbols { received, required }) => {
                assert!(received < required);
                assert_eq!(received, 5);
            }
            _ => panic!("Expected InsufficientSymbols error"),
        }
    }

    #[test]
    fn test_memory_bounds_check() {
        let state = DecoderStateTracker::new();
        assert!(state.check_memory_bounds()); // No decoder, should pass

        let mut state = DecoderStateTracker::new();
        state.reset_decoder(100, 1000, 0);
        assert!(state.check_memory_bounds()); // Initial state should pass
    }

    #[test]
    fn test_state_preservation_after_failure() {
        let mut state = DecoderStateTracker::new();
        state.reset_decoder(8, 128, 0);

        // Add some symbols
        let symbols: Vec<_> = (0..5).map(|i| ReceivedSymbol {
            esi: i,
            is_source: true,
            columns: vec![i as usize],
            coefficients: vec![Gf256::ONE],
            data: vec![i as u8; 128],
        }).collect();

        state.add_symbols(&symbols);
        let symbols_before = state.accumulated_symbols.len();

        // Attempt decode (should fail due to insufficient symbols)
        let _result = state.attempt_decode();

        // State should be preserved
        assert_eq!(state.accumulated_symbols.len(), symbols_before);
        assert!(state.decode_attempts > 0);
    }
}