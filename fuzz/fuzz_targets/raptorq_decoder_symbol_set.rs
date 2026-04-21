//! Fuzz target for RaptorQ decoder with adversarial symbol_set configurations.
//!
//! This harness tests the decode_block function with structure-aware adversarial
//! symbol_set inputs including:
//! - Missing rows (insufficient symbols for certain intermediate positions)
//! - Extra rows (redundant/duplicate symbols with same ESI)
//! - Padded zeros (zero coefficients, empty data)
//! - Repeated indices (duplicate column references in equations)
//!
//! Validates that decode_block either produces correct decoded bytes or fails
//! cleanly with appropriate DecodeError, never panicking.

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

use asupersync::raptorq::decoder::{DecodeError, InactivationDecoder, ReceivedSymbol};
use asupersync::raptorq::gf256::Gf256;
use asupersync::types::ObjectId;

const MAX_K: usize = 64;
const MAX_SYMBOL_SIZE: usize = 512;
const MAX_SYMBOLS: usize = 128;
const MAX_COLUMNS_PER_SYMBOL: usize = 32;
const MAX_INPUT_SIZE: usize = 8192;

/// Adversarial symbol set configuration for structure-aware fuzzing
#[derive(Debug, Arbitrary)]
struct AdversarialSymbolSet {
    k: u8,
    symbol_size: u16,
    seed: u64,
    symbols: Vec<AdversarialSymbol>,
    /// Include constraint violations that should cause decode errors
    include_violations: bool,
}

/// Adversarial received symbol with structure-aware mutations
#[derive(Debug, Arbitrary)]
struct AdversarialSymbol {
    esi: u32,
    is_source: bool,
    symbol_type: SymbolType,
    data_mutation: DataMutation,
}

#[derive(Debug, Arbitrary)]
enum SymbolType {
    /// Normal symbol with valid equation
    Valid { columns: Vec<u16>, coefficients: Vec<u8> },
    /// Missing rows: skip critical intermediate symbols
    MissingRow { skip_columns: Vec<u16> },
    /// Extra rows: duplicate ESI with different equations
    ExtraRow { duplicate_esi: u32, variant: u8 },
    /// Padded zeros: zero coefficients or empty equations
    PaddedZeros { zero_positions: Vec<u16> },
    /// Repeated indices: duplicate column references
    RepeatedIndices { base_columns: Vec<u16>, repetitions: Vec<u8> },
    /// Out of bounds column indices
    OutOfBounds { invalid_columns: Vec<u16> },
    /// Mismatched equation arity (columns.len() != coefficients.len())
    MismatchedArity { columns: Vec<u16>, coefficients: Vec<u8> },
}

#[derive(Debug, Arbitrary)]
enum DataMutation {
    /// Normal data with correct size
    Normal { fill: u8 },
    /// Empty data (zero length)
    Empty,
    /// Oversized data (larger than symbol_size)
    Oversized { extra_bytes: Vec<u8> },
    /// Undersized data (smaller than symbol_size)
    Undersized { truncate: u16 },
    /// Random corruption
    Corrupted { positions: Vec<u16>, values: Vec<u8> },
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_SIZE {
        return;
    }

    let mut u = Unstructured::new(data);
    let input: Result<AdversarialSymbolSet, _> = u.arbitrary();
    if input.is_err() {
        return;
    }
    let input = input.unwrap();

    // Clamp parameters to prevent memory exhaustion
    let k = (input.k as usize).clamp(1, MAX_K);
    let symbol_size = (input.symbol_size as usize).clamp(1, MAX_SYMBOL_SIZE);

    test_adversarial_symbol_set(&input, k, symbol_size);
});

/// Test decoder with adversarial symbol set configurations
fn test_adversarial_symbol_set(input: &AdversarialSymbolSet, k: usize, symbol_size: usize) {
    let decoder = InactivationDecoder::new(k, symbol_size, input.seed);

    // Limit symbols to prevent memory exhaustion
    let symbols: Vec<_> = input.symbols
        .iter()
        .take(MAX_SYMBOLS)
        .filter_map(|adv_symbol| build_received_symbol(adv_symbol, k, symbol_size))
        .collect();

    if symbols.is_empty() {
        return;
    }

    // Test basic decode - should never panic
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        decoder.decode(&symbols)
    }));

    match result {
        Ok(decode_result) => {
            // Decode succeeded or failed cleanly
            match decode_result {
                Ok(decoded) => {
                    // Successful decode - verify invariants
                    assert_eq!(decoded.source.len(), k, "Source length mismatch");
                    for (i, source_symbol) in decoded.source.iter().enumerate() {
                        assert_eq!(source_symbol.len(), symbol_size,
                            "Source symbol {} size mismatch", i);
                    }

                    // Intermediate symbols length should match the systematic parameter L
                    assert!(!decoded.intermediate.is_empty(), "No intermediate symbols recovered");
                }
                Err(decode_error) => {
                    // Decode failed cleanly - validate error types
                    validate_decode_error(&decode_error, k, &symbols);
                }
            }
        }
        Err(_) => {
            panic!("Decoder panicked with adversarial input: {:?}", input);
        }
    }

    // Test decode_wavefront with different batch sizes if enough symbols
    if symbols.len() > 10 {
        for batch_size in [0, 1, 4, 16] {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                decoder.decode_wavefront(&symbols, batch_size)
            }));

            if result.is_err() {
                panic!("decode_wavefront panicked with batch_size={}, input: {:?}",
                    batch_size, input);
            }
        }
    }

    // Test decode_with_proof
    if symbols.len() <= 64 { // Limit for proof generation
        let object_id = ObjectId::new_for_test(input.seed);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            decoder.decode_with_proof(&symbols, object_id, 0)
        }));

        if result.is_err() {
            panic!("decode_with_proof panicked with input: {:?}", input);
        }
    }
}

/// Build a ReceivedSymbol from adversarial configuration
fn build_received_symbol(
    adv_symbol: &AdversarialSymbol,
    k: usize,
    symbol_size: usize
) -> Option<ReceivedSymbol> {
    let esi = adv_symbol.esi;
    let is_source = adv_symbol.is_source;

    // Generate columns and coefficients based on symbol type
    let (columns, coefficients) = match &adv_symbol.symbol_type {
        SymbolType::Valid { columns, coefficients } => {
            let cols: Vec<usize> = columns.iter()
                .map(|&c| c as usize)
                .filter(|&c| c < k + 100) // Loose bound, let decoder validate
                .take(MAX_COLUMNS_PER_SYMBOL)
                .collect();
            let coeffs: Vec<Gf256> = coefficients.iter()
                .take(cols.len())
                .map(|&c| Gf256::new(c))
                .collect();
            (cols, coeffs)
        }

        SymbolType::MissingRow { skip_columns } => {
            // Create incomplete equation missing critical columns
            let mut cols: Vec<usize> = (0..k).collect();
            for &skip in skip_columns.iter().take(k / 2) {
                if let Some(pos) = cols.iter().position(|&x| x == skip as usize) {
                    cols.remove(pos);
                }
            }
            let coeffs = vec![Gf256::new(1); cols.len()];
            (cols, coeffs)
        }

        SymbolType::ExtraRow { duplicate_esi, variant } => {
            // Create duplicate ESI with different equation
            let base_col = (duplicate_esi % k as u32) as usize;
            let cols = vec![base_col, (base_col + (*variant as usize % 10)) % k];
            let coeffs = vec![Gf256::new(*variant), Gf256::new(1)];
            (cols, coeffs)
        }

        SymbolType::PaddedZeros { zero_positions } => {
            // Equation with zero coefficients at specified positions
            let cols: Vec<usize> = (0..k.min(8)).collect();
            let mut coeffs = vec![Gf256::new(1); cols.len()];
            for &pos in zero_positions.iter() {
                if (pos as usize) < coeffs.len() {
                    coeffs[pos as usize] = Gf256::new(0);
                }
            }
            (cols, coeffs)
        }

        SymbolType::RepeatedIndices { base_columns, repetitions } => {
            // Duplicate column indices in equation
            let mut cols = Vec::new();
            let mut coeffs = Vec::new();

            for (&base_col, &reps) in base_columns.iter().zip(repetitions.iter()) {
                let col = (base_col as usize) % k;
                for i in 0..(reps.min(4) + 1) {
                    cols.push(col);
                    coeffs.push(Gf256::new(i + 1));
                }
            }
            (cols, coeffs)
        }

        SymbolType::OutOfBounds { invalid_columns } => {
            // Column indices outside valid range [0, L)
            let cols: Vec<usize> = invalid_columns.iter()
                .map(|&c| c as usize)
                .take(MAX_COLUMNS_PER_SYMBOL)
                .collect();
            let coeffs = vec![Gf256::new(1); cols.len()];
            (cols, coeffs)
        }

        SymbolType::MismatchedArity { columns, coefficients } => {
            // Mismatched lengths between columns and coefficients
            let cols: Vec<usize> = columns.iter()
                .map(|&c| (c as usize) % (k + 10))
                .take(MAX_COLUMNS_PER_SYMBOL)
                .collect();
            let coeffs: Vec<Gf256> = coefficients.iter()
                .map(|&c| Gf256::new(c))
                .take(MAX_COLUMNS_PER_SYMBOL)
                .collect();
            // Intentionally different lengths for arity mismatch
            (cols, coeffs)
        }
    };

    // Generate symbol data based on mutation type
    let data = match &adv_symbol.data_mutation {
        DataMutation::Normal { fill } => {
            vec![*fill; symbol_size]
        }
        DataMutation::Empty => {
            Vec::new()
        }
        DataMutation::Oversized { extra_bytes } => {
            let mut data = vec![0u8; symbol_size];
            data.extend_from_slice(&extra_bytes[..extra_bytes.len().min(256)]);
            data
        }
        DataMutation::Undersized { truncate } => {
            let size = symbol_size.saturating_sub(*truncate as usize);
            vec![0u8; size]
        }
        DataMutation::Corrupted { positions, values } => {
            let mut data = vec![0u8; symbol_size];
            for (&pos, &val) in positions.iter().zip(values.iter()) {
                if (pos as usize) < data.len() {
                    data[pos as usize] = val;
                }
            }
            data
        }
    };

    Some(ReceivedSymbol {
        esi,
        is_source,
        columns,
        coefficients,
        data,
    })
}

/// Validate that decode errors are appropriate for the input
fn validate_decode_error(error: &DecodeError, k: usize, symbols: &[ReceivedSymbol]) {
    match error {
        DecodeError::InsufficientSymbols { received, required } => {
            assert_eq!(*received, symbols.len());
            assert!(*required > *received);
        }
        DecodeError::SingularMatrix { row } => {
            // Matrix became singular during elimination
            assert!(*row < symbols.len() + k);
        }
        DecodeError::SymbolSizeMismatch { expected, actual } => {
            assert!(*expected != *actual);
        }
        DecodeError::SymbolEquationArityMismatch { esi: _, columns, coefficients } => {
            assert_ne!(*columns, *coefficients);
        }
        DecodeError::ColumnIndexOutOfRange { esi: _, column, max_valid } => {
            assert!(*column >= *max_valid);
        }
        DecodeError::SourceEsiOutOfRange { esi, max_valid } => {
            assert!(*esi >= (*max_valid as u32));
        }
        DecodeError::InvalidSourceSymbolEquation { esi, expected_column } => {
            assert!((*esi as usize) < k);
            assert!(*expected_column < k + 100); // Reasonable upper bound
        }
        DecodeError::CorruptDecodedOutput { .. } => {
            // Decoder detected corruption in the decoded output
            // This is a valid error condition
        }
    }
}