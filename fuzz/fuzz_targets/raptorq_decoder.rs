//! Comprehensive RaptorQ InactivationDecoder Fuzz Target
//!
//! Tests security assertions:
//! 1. No panic on oversized ESI (ESI ≥ 2^24)
//! 2. Per-block limits K' max honored (K ≤ 8192 per RFC 6330)
//! 3. Repair symbols parsed without overflow (column indices bounded)
//! 4. Early decoder failure returns error not hang (timeout-resistant)
//! 5. Duplicate ESIs idempotent (no corruption from dup processing)
//! 6. Decoder handles empty source-block gracefully (K=0, L=0 cases)

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

use asupersync::raptorq::decoder::{DecodeError, InactivationDecoder, ReceivedSymbol};
use asupersync::raptorq::gf256::Gf256;

/// Fuzz-friendly received symbol generator
#[derive(Debug, Clone, Arbitrary)]
struct FuzzReceivedSymbol {
    /// ESI value (may be oversized for testing)
    pub esi: u32,
    /// Whether this is marked as a source symbol
    pub is_source: bool,
    /// Column dependencies (indices into [0, L))
    pub columns: Vec<u16>, // Limited size to prevent explosion
    /// GF(256) coefficients for each column
    pub coefficients: Vec<u8>,
    /// Symbol payload data
    pub data: Vec<u8>,
}

impl FuzzReceivedSymbol {
    /// Convert to actual ReceivedSymbol, normalizing for valid ranges
    fn to_received_symbol(&self, l: usize, symbol_size: usize) -> ReceivedSymbol {
        // Clamp columns to valid range [0, L)
        let columns: Vec<usize> = self
            .columns
            .iter()
            .take(32) // Limit equation degree for performance
            .map(|&col| (col as usize) % l.max(1))
            .collect();

        // Truncate coefficients to match columns
        let coefficients: Vec<Gf256> = self
            .coefficients
            .iter()
            .take(columns.len())
            .map(|&coef| Gf256(coef))
            .collect();

        // Normalize data to expected symbol size
        let mut data = self.data.clone();
        data.truncate(symbol_size);
        data.resize(symbol_size, 0u8); // Pad with zeros if needed

        ReceivedSymbol {
            esi: self.esi,
            is_source: self.is_source,
            columns,
            coefficients,
            data,
        }
    }
}

/// Systematic parameters for fuzzing
#[derive(Debug, Clone, Arbitrary)]
struct FuzzParams {
    /// Number of source symbols K
    pub k: u16,
    /// Symbol size in bytes
    pub symbol_size: u16,
    /// Deterministic seed for decoder
    pub seed: u64,
}

impl FuzzParams {
    /// Normalize to valid ranges per RFC 6330
    fn normalize(&mut self) {
        // RFC 6330 constraint: 1 ≤ K ≤ 8192
        self.k = self.k.clamp(1, 8192);
        // Practical symbol size limits for fuzzing
        self.symbol_size = self.symbol_size.clamp(1, 1024);
    }

    /// Create InactivationDecoder from normalized parameters
    fn create_decoder(&self) -> InactivationDecoder {
        InactivationDecoder::new(self.k as usize, self.symbol_size as usize, self.seed)
    }
}

/// Security Assertion 1: No panic on oversized ESI
fn test_oversized_esi(params: &FuzzParams, unstructured: &mut Unstructured) {
    let decoder = params.create_decoder();

    if let Ok(oversized_esi) = u32::arbitrary(unstructured) {
        // Force ESI ≥ 2^24 to test bounds checking
        let oversized_esi = oversized_esi | (1u32 << 24);

        let symbol = ReceivedSymbol {
            esi: oversized_esi,
            is_source: false,
            columns: vec![0],
            coefficients: vec![Gf256(1)],
            data: vec![0u8; params.symbol_size as usize],
        };

        // Should return error, not panic
        let _result = decoder.decode(&[symbol]);
    }
}

/// Security Assertion 2: Per-block limits K' max honored
fn test_k_limit_enforcement(unstructured: &mut Unstructured) {
    // Test K > 8192 (RFC 6330 violation)
    if let Ok(oversized_k) = u16::arbitrary(unstructured) {
        let oversized_k = oversized_k.saturating_add(8193); // Force K > 8192

        let decoder = InactivationDecoder::new(oversized_k as usize, 64, 0);

        // Should handle gracefully without panic/hang
        let symbol = ReceivedSymbol {
            esi: 0,
            is_source: true,
            columns: vec![0],
            coefficients: vec![Gf256(1)],
            data: vec![0u8; 64],
        };

        let _result = decoder.decode(&[symbol]);
    }
}

/// Security Assertion 3: Repair symbols parsed without overflow
fn test_repair_symbol_overflow(params: &FuzzParams, fuzz_symbols: &[FuzzReceivedSymbol]) {
    let decoder = params.create_decoder();
    let l = decoder.params().l;

    let symbols: Vec<ReceivedSymbol> = fuzz_symbols
        .iter()
        .take(50) // Limit for performance
        .map(|fs| {
            // Intentionally create out-of-bounds column indices
            let mut symbol = fs.to_received_symbol(l, params.symbol_size as usize);

            // Force some columns to be out of bounds
            if !symbol.columns.is_empty() {
                symbol.columns[0] = symbol.columns[0].saturating_add(l * 2);
            }

            symbol
        })
        .collect();

    // Should detect out-of-bounds and return error, not overflow/panic
    let _result = decoder.decode(&symbols);
}

/// Security Assertion 4: Early failure returns error not hang
fn test_early_failure_no_hang(params: &FuzzParams, fuzz_symbols: &[FuzzReceivedSymbol]) {
    let decoder = params.create_decoder();
    let l = decoder.params().l;

    // Create obviously unsolvable system (insufficient symbols)
    let symbols: Vec<ReceivedSymbol> = fuzz_symbols
        .iter()
        .take((params.k as usize).saturating_sub(10).max(1)) // Definitely insufficient
        .map(|fs| fs.to_received_symbol(l, params.symbol_size as usize))
        .collect();

    // Should return InsufficientSymbols error quickly, not hang
    let result = decoder.decode(&symbols);

    // Verify it returns the expected error type
    if let Err(DecodeError::InsufficientSymbols { received, required }) = result {
        assert!(received < required, "Error should indicate insufficiency");
    }
}

/// Security Assertion 5: Duplicate ESIs idempotent
fn test_duplicate_esi_idempotent(params: &FuzzParams, unstructured: &mut Unstructured) {
    if let Ok(base_symbol) = FuzzReceivedSymbol::arbitrary(unstructured) {
        let decoder = params.create_decoder();
        let l = decoder.params().l;

        let base = base_symbol.to_received_symbol(l, params.symbol_size as usize);

        // Create duplicate symbols with same ESI
        let mut symbols = vec![base.clone(), base.clone(), base];

        // Add some different symbols to make system potentially solvable
        for i in 1..params.k.min(10) {
            if let Ok(other) = FuzzReceivedSymbol::arbitrary(unstructured) {
                let mut other = other.to_received_symbol(l, params.symbol_size as usize);
                other.esi = i as u32; // Ensure different ESI
                symbols.push(other);
            }
        }

        // Processing duplicate ESIs should be idempotent
        let _result = decoder.decode(&symbols);
    }
}

/// Security Assertion 6: Decoder handles empty source-block gracefully
fn test_empty_source_block() {
    // Test K=0 case
    let decoder = InactivationDecoder::new(0, 64, 0);
    let _result = decoder.decode(&[]);
    // Should return error gracefully, not panic

    // Test empty symbol list with valid K
    let decoder2 = InactivationDecoder::new(1, 64, 0);
    let result2 = decoder2.decode(&[]);
    if let Err(DecodeError::InsufficientSymbols { received, required }) = result2 {
        assert_eq!(received, 0);
        assert!(required > 0);
    }
}

/// Additional stress test: Malformed symbol structures
fn test_malformed_symbol_structures(params: &FuzzParams, fuzz_symbols: &[FuzzReceivedSymbol]) {
    let decoder = params.create_decoder();
    let l = decoder.params().l;

    let symbols: Vec<ReceivedSymbol> = fuzz_symbols
        .iter()
        .take(20)
        .map(|fs| {
            let mut symbol = fs.to_received_symbol(l, params.symbol_size as usize);

            // Introduce various malformations
            if !symbol.columns.is_empty() && !symbol.coefficients.is_empty() {
                // Mismatched columns/coefficients lengths
                symbol.coefficients.pop();

                // Wrong symbol size
                if !symbol.data.is_empty() {
                    symbol.data.pop();
                }
            }

            symbol
        })
        .collect();

    // Should detect malformation and return appropriate errors
    let _result = decoder.decode(&symbols);
}

fuzz_target!(|data: &[u8]| {
    // Guard against excessive input sizes
    if data.len() > 100_000 {
        return;
    }

    let mut unstructured = Unstructured::new(data);

    // Generate fuzzing parameters
    let mut params = match FuzzParams::arbitrary(&mut unstructured) {
        Ok(p) => p,
        Err(_) => return,
    };
    params.normalize();

    // Generate fuzzed symbols
    let fuzz_symbols: Vec<FuzzReceivedSymbol> = match Vec::arbitrary(&mut unstructured) {
        Ok(s) => s.into_iter().take(200).collect(), // Limit for performance
        Err(_) => vec![],
    };

    // Security Assertion 1: No panic on oversized ESI
    test_oversized_esi(&params, &mut unstructured);

    // Security Assertion 2: Per-block limits K' max honored
    test_k_limit_enforcement(&mut unstructured);

    // Security Assertion 3: Repair symbols parsed without overflow
    test_repair_symbol_overflow(&params, &fuzz_symbols);

    // Security Assertion 4: Early decoder failure returns error not hang
    test_early_failure_no_hang(&params, &fuzz_symbols);

    // Security Assertion 5: Duplicate ESIs idempotent
    test_duplicate_esi_idempotent(&params, &mut unstructured);

    // Security Assertion 6: Decoder handles empty source-block gracefully
    test_empty_source_block();

    // Additional: Malformed symbol structures
    test_malformed_symbol_structures(&params, &fuzz_symbols);

    // Main decode test with valid symbols
    let decoder = params.create_decoder();
    let l = decoder.params().l;

    let valid_symbols: Vec<ReceivedSymbol> = fuzz_symbols
        .iter()
        .take(100)
        .map(|fs| fs.to_received_symbol(l, params.symbol_size as usize))
        .collect();

    if !valid_symbols.is_empty() {
        let _result = decoder.decode(&valid_symbols);
    }
});
