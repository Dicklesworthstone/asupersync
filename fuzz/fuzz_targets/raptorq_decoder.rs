#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

/// RaptorQ Galois Field GF(256) operations for fuzzing
mod gf256 {
    pub type Gf256 = u8;

    pub fn add(a: Gf256, b: Gf256) -> Gf256 {
        a ^ b
    }

    pub fn mul(a: Gf256, b: Gf256) -> Gf256 {
        if a == 0 || b == 0 {
            return 0;
        }

        // Simple GF(256) multiplication (not the full table for fuzzing)
        let mut result = 0u8;
        let mut a = a;
        let mut b = b;

        while b != 0 {
            if b & 1 != 0 {
                result ^= a;
            }
            a = if a & 0x80 != 0 {
                (a << 1) ^ 0x1B // Primitive polynomial x^8 + x^4 + x^3 + x + 1
            } else {
                a << 1
            };
            b >>= 1;
        }

        result
    }
}

/// Simulated RaptorQ received symbol for fuzzing
#[derive(Debug, Clone, Arbitrary)]
struct FuzzReceivedSymbol {
    /// Encoding Symbol Index
    pub esi: u32,
    /// Whether this is a source symbol (ESI < K)
    pub is_source: bool,
    /// Column indices this symbol depends on
    pub columns: Vec<u16>, // Use u16 to limit size
    /// GF(256) coefficients
    pub coefficients: Vec<u8>,
    /// Symbol data
    pub data: Vec<u8>,
}

/// Simulated systematic parameters
#[derive(Debug, Clone, Arbitrary)]
struct FuzzSystematicParams {
    /// Number of source symbols
    pub k: u16,
    /// Symbol size in bytes
    pub symbol_size: u16,
    /// Number of LDPC overhead symbols
    pub s: u16,
    /// Number of HDPC overhead symbols
    pub h: u16,
}

/// Simple decode error for fuzzing
#[derive(Debug)]
enum FuzzDecodeError {
    InsufficientSymbols,
    InvalidSymbolSize,
    InvalidParameters,
    CorruptData,
    MatrixSingular,
}

/// Validate and normalize systematic parameters
fn validate_systematic_params(params: &mut FuzzSystematicParams) -> Result<(), FuzzDecodeError> {
    // Clamp parameters to reasonable ranges for fuzzing
    params.k = params.k.clamp(1, 256);
    params.symbol_size = params.symbol_size.clamp(1, 1024);
    params.s = params.s.clamp(0, 64);
    params.h = params.h.clamp(0, 64);

    // Basic RFC 6330 constraints
    if params.k == 0 {
        return Err(FuzzDecodeError::InvalidParameters);
    }

    Ok(())
}

/// Validate received symbols structure
fn validate_received_symbols(
    symbols: &[FuzzReceivedSymbol],
    params: &FuzzSystematicParams,
) -> Result<(), FuzzDecodeError> {
    let l = params.k + params.s + params.h;

    for symbol in symbols {
        // ESI bounds checking
        if symbol.esi >= 2u32.pow(24) {
            // 24-bit ESI limit
            return Err(FuzzDecodeError::InvalidParameters);
        }

        // Symbol data size validation
        if symbol.data.len() != params.symbol_size as usize {
            return Err(FuzzDecodeError::InvalidSymbolSize);
        }

        // Coefficient/column alignment
        if symbol.columns.len() != symbol.coefficients.len() {
            return Err(FuzzDecodeError::CorruptData);
        }

        // Column bounds checking
        for &col in &symbol.columns {
            if col as usize >= l as usize {
                return Err(FuzzDecodeError::InvalidParameters);
            }
        }

        // Source symbol consistency
        if symbol.is_source && symbol.esi >= params.k as u32 {
            return Err(FuzzDecodeError::InvalidParameters);
        }

        // Limit equation complexity for fuzzing performance
        if symbol.columns.len() > 32 {
            return Err(FuzzDecodeError::CorruptData);
        }
    }

    Ok(())
}

/// Simulate gaussian elimination operation for fuzzing
fn simulate_gaussian_elimination(
    matrix_rows: usize,
    matrix_cols: usize,
    symbols: &[FuzzReceivedSymbol],
) -> Result<Vec<Vec<u8>>, FuzzDecodeError> {
    if matrix_rows == 0 || matrix_cols == 0 {
        return Err(FuzzDecodeError::MatrixSingular);
    }

    // Simulate creating coefficient matrix
    let mut equations = Vec::new();
    for symbol in symbols.iter().take(matrix_rows) {
        let mut row = vec![0u8; matrix_cols];
        for (&col, &coef) in symbol.columns.iter().zip(symbol.coefficients.iter()) {
            if (col as usize) < matrix_cols {
                row[col as usize] = coef;
            }
        }
        equations.push(row);
    }

    // Simulate pivoting - just check for zero diagonal elements
    for i in 0..matrix_rows.min(matrix_cols) {
        if i < equations.len() && equations[i][i] == 0 {
            // Try to find a pivot
            let mut found_pivot = false;
            for j in i + 1..equations.len() {
                if equations[j][i] != 0 {
                    equations.swap(i, j);
                    found_pivot = true;
                    break;
                }
            }
            if !found_pivot {
                return Err(FuzzDecodeError::MatrixSingular);
            }
        }
    }

    // Simulate back-substitution - return dummy solution
    let symbol_size = if symbols.is_empty() {
        64
    } else {
        symbols[0].data.len().clamp(1, 1024)
    };

    let solution: Vec<Vec<u8>> = (0..matrix_cols)
        .map(|i| vec![(i % 256) as u8; symbol_size])
        .collect();

    Ok(solution)
}

/// Simulate RaptorQ peeling process for fuzzing
fn simulate_peeling_phase(symbols: &[FuzzReceivedSymbol]) -> Result<usize, FuzzDecodeError> {
    let mut solved_count = 0;
    let mut remaining_symbols = symbols.to_vec();

    // Simple peeling: find degree-1 equations and solve them
    let mut made_progress = true;
    while made_progress && !remaining_symbols.is_empty() {
        made_progress = false;

        let mut to_remove = Vec::new();
        for (idx, symbol) in remaining_symbols.iter().enumerate() {
            if symbol.columns.len() == 1 {
                // Found a degree-1 equation - "solve" it
                solved_count += 1;
                to_remove.push(idx);
                made_progress = true;
            }
        }

        // Remove solved symbols (reverse order to maintain indices)
        for &idx in to_remove.iter().rev() {
            remaining_symbols.remove(idx);
        }

        // Simulate constraint propagation - reduce degree of remaining equations
        for symbol in &mut remaining_symbols {
            if symbol.columns.len() > 1 {
                // Randomly reduce degree to simulate solved variable elimination
                if symbol.columns.len() > 2 && solved_count % 3 == 0 {
                    symbol.columns.pop();
                    symbol.coefficients.pop();
                }
            }
        }
    }

    Ok(solved_count)
}

/// Main fuzzing function that exercises RaptorQ decoding logic
fn fuzz_raptorq_decode(
    mut params: FuzzSystematicParams,
    symbols: Vec<FuzzReceivedSymbol>,
) -> Result<(), FuzzDecodeError> {
    // Validate and normalize parameters
    validate_systematic_params(&mut params)?;

    // Validate symbol structures
    validate_received_symbols(&symbols, &params)?;

    if symbols.is_empty() {
        return Err(FuzzDecodeError::InsufficientSymbols);
    }

    let l = params.k + params.s + params.h;

    // Check if we have enough symbols for decoding
    if symbols.len() < params.k as usize {
        return Err(FuzzDecodeError::InsufficientSymbols);
    }

    // Phase 1: Simulate peeling
    let peeled_count = simulate_peeling_phase(&symbols)?;

    // Phase 2: Simulate Gaussian elimination on remaining system
    let remaining_unknowns = l as usize - peeled_count;
    if remaining_unknowns > 0 && remaining_unknowns <= symbols.len() {
        let _solution = simulate_gaussian_elimination(
            remaining_unknowns.min(symbols.len()),
            remaining_unknowns,
            &symbols,
        )?;
    }

    // Phase 3: Simulate verification - check a few GF operations
    if !symbols.is_empty() && !symbols[0].coefficients.is_empty() {
        let a = symbols[0].coefficients[0];
        let b = if symbols.len() > 1 && !symbols[1].coefficients.is_empty() {
            symbols[1].coefficients[0]
        } else {
            1
        };

        let _sum = gf256::add(a, b);
        let _product = gf256::mul(a, b);
    }

    Ok(())
}

fuzz_target!(|data: &[u8]| {
    // Guard against very large inputs
    if data.len() > 50_000 {
        return;
    }

    // Parse input using arbitrary
    let mut unstructured = Unstructured::new(data);

    // Try to generate systematic parameters
    let params = if let Ok(p) = FuzzSystematicParams::arbitrary(&mut unstructured) {
        p
    } else {
        return;
    };

    // Try to generate received symbols
    let symbols: Vec<FuzzReceivedSymbol> =
        if let Ok(s) = Vec::<FuzzReceivedSymbol>::arbitrary(&mut unstructured) {
            s
        } else {
            return;
        };

    // Limit the number of symbols for performance
    let limited_symbols: Vec<_> = symbols.into_iter().take(100).collect();

    // Run the RaptorQ decode simulation
    let _ = fuzz_raptorq_decode(params, limited_symbols);

    // Test some additional edge cases if we have remaining data
    if unstructured.len() > 0 {
        // Test empty symbol list
        let _ = fuzz_raptorq_decode(
            FuzzSystematicParams {
                k: 1,
                symbol_size: 64,
                s: 0,
                h: 0,
            },
            vec![],
        );

        // Test single symbol
        if let Ok(single_symbol) = FuzzReceivedSymbol::arbitrary(&mut unstructured) {
            let _ = fuzz_raptorq_decode(
                FuzzSystematicParams {
                    k: 1,
                    symbol_size: single_symbol.data.len() as u16,
                    s: 0,
                    h: 0,
                },
                vec![single_symbol],
            );
        }
    }
});
