#![no_main]

use arbitrary::Arbitrary;
use asupersync::raptorq::decoder::{InactivationDecoder, ReceivedSymbol};
use asupersync::raptorq::gf256::Gf256;
use asupersync::raptorq::linalg::{DenseRow, GaussianResult, GaussianSolver};
use asupersync::raptorq::systematic::SystematicEncoder;
use libfuzzer_sys::fuzz_target;

/// Maximum matrix dimensions for fuzzing to avoid memory exhaustion
const MAX_ROWS: usize = 64;
const MAX_COLS: usize = 64;
const MAX_RHS_LEN: usize = 32;
const MAX_CACHE_PROBES: usize = 4;
const CACHE_PROBE_K: usize = 4;
const MAX_CACHE_SYMBOL_SIZE: usize = 16;

/// Fuzzing input structure for RaptorQ matrix elimination kernel
#[derive(Arbitrary, Debug)]
struct MatrixEliminationFuzzInput {
    /// Matrix solver tests with varying configurations
    solver_tests: Vec<SolverTest>,
    /// Boundary value tests for GF(256) operations in matrix context
    gf256_boundary_tests: Vec<Gf256BoundaryTest>,
    /// Live dense-factor cache probes through the decoder path
    cache_probes: Vec<DenseFactorCacheProbe>,
}

/// Test cases for GaussianSolver with different matrix configurations
#[derive(Arbitrary, Debug)]
enum SolverTest {
    /// Test with rank-deficient matrix (fewer linearly independent rows than rank)
    RankDeficient {
        rows: usize,
        cols: usize,
        rank_deficit: u8, // How many rows to make linearly dependent
        matrix_data: Vec<u8>,
        rhs_data: Vec<Vec<u8>>,
    },
    /// Test boundary conditions for Block-Schur solver scenarios
    BlockSchur {
        block_size: usize,
        matrix_data: Vec<u8>,
        rhs_data: Vec<Vec<u8>>,
    },
    /// Test with all-zero matrix (extreme singularity)
    AllZero {
        rows: usize,
        cols: usize,
        rhs_data: Vec<Vec<u8>>,
    },
    /// Test with identity matrix (trivial solve)
    Identity { size: usize, rhs_data: Vec<Vec<u8>> },
    /// Test with single pivot elements (sparse matrix)
    SparsePivots {
        rows: usize,
        cols: usize,
        pivot_positions: Vec<(usize, usize)>, // (row, col) positions for non-zero elements
        pivot_values: Vec<u8>,
        rhs_data: Vec<Vec<u8>>,
    },
    /// Test with adversarial pivot sequences (alternating large/small values)
    AdversarialPivots { size: usize, rhs_data: Vec<Vec<u8>> },
    /// Test inconsistent systems (overdetermined with contradictions)
    Inconsistent {
        rows: usize,
        cols: usize,
        matrix_data: Vec<u8>,
        rhs_data: Vec<Vec<u8>>,
    },
}

/// GF(256) boundary value testing in matrix context
#[derive(Arbitrary, Debug)]
struct Gf256BoundaryTest {
    operation: Gf256Operation,
    test_values: Vec<u8>,
}

#[derive(Arbitrary, Debug)]
enum Gf256Operation {
    /// Test multiplication with boundary values during elimination
    EliminationMultiply,
    /// Test addition during row operations
    RowAddition,
    /// Test inversion for pivot normalization
    PivotInversion,
    /// Test with irreducible polynomial edge cases
    IrreduciblePolyEdge,
}

/// Bounded decoder inputs that exercise real dense-factor cache reuse.
#[derive(Arbitrary, Debug)]
struct DenseFactorCacheProbe {
    symbol_size_hint: u8,
    seed: u64,
    payload: Vec<u8>,
    repeat_count: u8,
}

/// Boundary values for GF(256) that are likely to expose edge cases
const GF256_BOUNDARY_VALUES: &[u8] = &[
    0x00, // Zero element
    0x01, // Multiplicative identity
    0x02, // Generator of the multiplicative group
    0xFF, // Maximum field element
    0x1D, // Irreducible polynomial coefficient (x^8 + x^4 + x^3 + x^2 + 1)
    0x1C, // One less than irreducible poly
    0x1E, // One more than irreducible poly
    0x80, // High bit set (x^7)
    0x40, // x^6
    0x20, // x^5
    0x10, // x^4 (part of irreducible poly)
    0x08, // x^3 (part of irreducible poly)
    0x04, // x^2 (part of irreducible poly)
    0x7F, // All low bits set
    0xFE, // All bits except LSB
];

fuzz_target!(|input: MatrixEliminationFuzzInput| {
    // Test matrix solver operations
    for solver_test in input.solver_tests {
        test_solver_operation(solver_test);
    }

    // Test GF(256) boundary cases in matrix context
    for boundary_test in input.gf256_boundary_tests {
        test_gf256_boundaries(boundary_test);
    }

    // Exercise live dense-factor cache telemetry through the decoder.
    for cache_probe in input.cache_probes.into_iter().take(MAX_CACHE_PROBES) {
        test_dense_factor_cache_probe(cache_probe);
    }
});

fn test_solver_operation(test: SolverTest) {
    match test {
        SolverTest::RankDeficient {
            rows,
            cols,
            rank_deficit,
            matrix_data,
            rhs_data,
        } => {
            let rows = rows.clamp(1, MAX_ROWS);
            let cols = cols.clamp(1, MAX_COLS);

            // Create rank-deficient matrix by making some rows linear combinations of others
            let mut solver = GaussianSolver::new(rows, cols);

            // Fill matrix with bounded random data
            for (i, row_data) in matrix_data.chunks(cols).enumerate().take(rows) {
                let mut coefficients = vec![0u8; cols];
                for (j, &val) in row_data.iter().enumerate().take(cols) {
                    coefficients[j] = val;
                }

                // Create RHS for this row
                let rhs = if i < rhs_data.len() {
                    let rhs_len = rhs_data[i].len().min(MAX_RHS_LEN);
                    DenseRow::new(rhs_data[i][..rhs_len].to_vec())
                } else {
                    DenseRow::zeros(0)
                };

                solver.set_row(i, &coefficients, rhs);
            }

            // Make some rows linearly dependent to create rank deficiency
            let deficit = (rank_deficit as usize).min(rows.saturating_sub(1));
            for i in 0..deficit {
                if i + 1 < rows {
                    // Make row i+1 a linear combination of row 0 and row i
                    let factor1 = Gf256::new(if matrix_data.is_empty() {
                        1
                    } else {
                        matrix_data[0]
                    });
                    let factor2 = Gf256::new(if matrix_data.len() > 1 {
                        matrix_data[1]
                    } else {
                        1
                    });

                    for col in 0..cols {
                        solver.set_coefficient(0, col, Gf256::new(1)); // Ensure row 0 has some content
                        let val1 = Gf256::new(1) * factor1; // Content from row 0
                        let val2 = Gf256::new(if col < matrix_data.len() {
                            matrix_data[col]
                        } else {
                            0
                        }) * factor2;
                        solver.set_coefficient(i + 1, col, val1 + val2);
                    }
                }
            }

            // Test that solver handles rank deficiency gracefully
            let result = solver.solve();
            match result {
                GaussianResult::Singular { .. } => {
                    // Expected for rank-deficient matrices
                }
                GaussianResult::Solved(_) => {
                    // Might happen if rank deficiency didn't actually occur
                }
                GaussianResult::Inconsistent { .. } => {
                    // Can happen with rank deficiency + inconsistent RHS
                }
            }

            // Verify solver stats are reasonable
            let stats = solver.stats();
            assert!(stats.swaps <= rows, "Too many row swaps: {}", stats.swaps);
            assert!(
                stats.pivot_selections <= rows.max(cols),
                "Too many pivot selections: {}",
                stats.pivot_selections
            );
        }

        SolverTest::BlockSchur {
            block_size,
            matrix_data,
            rhs_data,
        } => {
            let block_size = block_size.clamp(1, MAX_ROWS / 2);
            let total_size = block_size * 2; // 2x2 block structure

            let mut solver = GaussianSolver::new(total_size, total_size);

            // Create block structure: [A B; C D] where A is block_size x block_size
            for i in 0..total_size {
                let mut coefficients = vec![0u8; total_size];
                for (j, coefficient) in coefficients.iter_mut().enumerate() {
                    *coefficient = if matrix_data.is_empty() {
                        0
                    } else {
                        let data_idx = (i * total_size + j) % matrix_data.len();
                        matrix_data[data_idx]
                    };

                    // Ensure block structure has some pattern
                    if i < block_size && j < block_size {
                        // Block A - make it non-singular if possible
                        if i == j {
                            *coefficient = (*coefficient).max(1); // Ensure diagonal elements
                        }
                    }
                }

                let rhs = if i < rhs_data.len() {
                    let rhs_len = rhs_data[i].len().min(MAX_RHS_LEN);
                    DenseRow::new(rhs_data[i][..rhs_len].to_vec())
                } else {
                    DenseRow::zeros(0)
                };

                solver.set_row(i, &coefficients, rhs);
            }

            // Test Block-Schur elimination patterns
            let result = solver.solve();
            // Just verify no panic - Block-Schur handling depends on pivot selection
            drop(result);
        }

        SolverTest::AllZero {
            rows,
            cols,
            rhs_data,
        } => {
            let rows = rows.clamp(1, MAX_ROWS);
            let cols = cols.clamp(1, MAX_COLS);

            let mut solver = GaussianSolver::new(rows, cols);

            // Set all coefficients to zero
            for i in 0..rows {
                let coefficients = vec![0u8; cols];
                let rhs = if i < rhs_data.len() {
                    let rhs_len = rhs_data[i].len().min(MAX_RHS_LEN);
                    DenseRow::new(rhs_data[i][..rhs_len].to_vec())
                } else {
                    DenseRow::zeros(0)
                };
                solver.set_row(i, &coefficients, rhs);
            }

            let result = solver.solve();
            match result {
                GaussianResult::Singular { .. } => {
                    // Expected - all-zero matrix is singular
                }
                GaussianResult::Inconsistent { .. } => {
                    // Expected if RHS is non-zero
                }
                GaussianResult::Solved(_) => {
                    // Should only happen if RHS is all zero too
                }
            }
        }

        SolverTest::Identity { size, rhs_data } => {
            let size = size.clamp(1, MAX_ROWS.min(MAX_COLS));

            let mut solver = GaussianSolver::new(size, size);

            // Create identity matrix
            for i in 0..size {
                let mut coefficients = vec![0u8; size];
                coefficients[i] = 1; // Identity diagonal

                let rhs = if i < rhs_data.len() {
                    let rhs_len = rhs_data[i].len().min(MAX_RHS_LEN);
                    DenseRow::new(rhs_data[i][..rhs_len].to_vec())
                } else {
                    DenseRow::zeros(1) // Single element for identity solve
                };

                solver.set_row(i, &coefficients, rhs);
            }

            let result = solver.solve();
            match result {
                GaussianResult::Solved(solution) => {
                    // Identity matrix should always solve cleanly
                    assert_eq!(solution.len(), size, "Solution size mismatch for identity");
                }
                _ => {
                    panic!("Identity matrix should always be solvable");
                }
            }
        }

        SolverTest::SparsePivots {
            rows,
            cols,
            pivot_positions,
            pivot_values,
            rhs_data,
        } => {
            let rows = rows.clamp(1, MAX_ROWS);
            let cols = cols.clamp(1, MAX_COLS);

            let mut solver = GaussianSolver::new(rows, cols);

            // Start with zero matrix
            for i in 0..rows {
                let coefficients = vec![0u8; cols];
                let rhs = if i < rhs_data.len() {
                    let rhs_len = rhs_data[i].len().min(MAX_RHS_LEN);
                    DenseRow::new(rhs_data[i][..rhs_len].to_vec())
                } else {
                    DenseRow::zeros(0)
                };
                solver.set_row(i, &coefficients, rhs);
            }

            // Place sparse pivots
            for (idx, &(row, col)) in pivot_positions.iter().enumerate() {
                if row < rows && col < cols && idx < pivot_values.len() {
                    let value = pivot_values[idx].max(1); // Avoid zero pivots
                    solver.set_coefficient(row, col, Gf256::new(value));
                }
            }

            let result = solver.solve();
            // Test that sparse matrices don't cause issues with pivot finding
            drop(result);
        }

        SolverTest::AdversarialPivots { size, rhs_data } => {
            let size = size.clamp(1, MAX_ROWS.min(MAX_COLS));

            let mut solver = GaussianSolver::new(size, size);

            // Create matrix with alternating very small and very large elements
            // In GF(256), this means elements near 1 and near 255
            for i in 0..size {
                let mut coefficients = vec![0u8; size];
                for (j, coefficient) in coefficients.iter_mut().enumerate() {
                    if i == j {
                        // Diagonal: alternate between small and large values
                        *coefficient = if i % 2 == 0 { 1 } else { 255 };
                    } else {
                        // Off-diagonal: create some coupling
                        *coefficient = if (i + j) % 3 == 0 { 2 } else { 0 };
                    }
                }

                let rhs = if i < rhs_data.len() {
                    let rhs_len = rhs_data[i].len().min(MAX_RHS_LEN);
                    DenseRow::new(rhs_data[i][..rhs_len].to_vec())
                } else {
                    DenseRow::zeros(1)
                };

                solver.set_row(i, &coefficients, rhs);
            }

            let result = solver.solve();
            // Test numerical stability with adversarial pivot values
            drop(result);
        }

        SolverTest::Inconsistent {
            rows,
            cols,
            matrix_data,
            rhs_data,
        } => {
            let rows = rows.clamp(2, MAX_ROWS); // Need at least 2 rows for inconsistency
            let cols = cols.clamp(1, MAX_COLS);

            let mut solver = GaussianSolver::new(rows, cols);

            // Set up matrix
            for (i, row_data) in matrix_data.chunks(cols).enumerate().take(rows) {
                let mut coefficients = vec![0u8; cols];
                for (j, &val) in row_data.iter().enumerate().take(cols) {
                    coefficients[j] = val;
                }

                let rhs = if i < rhs_data.len() {
                    let rhs_len = rhs_data[i].len().min(MAX_RHS_LEN);
                    DenseRow::new(rhs_data[i][..rhs_len].to_vec())
                } else {
                    DenseRow::zeros(0)
                };

                solver.set_row(i, &coefficients, rhs);
            }

            // Force inconsistency: make row 1 = row 0 but with different RHS
            if rows >= 2 {
                // Copy coefficients from row 0 to row 1
                for j in 0..cols {
                    solver.set_coefficient(0, j, Gf256::new(1)); // Ensure row 0 has content
                    solver.set_coefficient(1, j, Gf256::new(1)); // Make row 1 identical
                }

                // Set different RHS values to create inconsistency
                solver.set_rhs(0, DenseRow::new(vec![1]));
                solver.set_rhs(1, DenseRow::new(vec![2])); // Different from row 0
            }

            let result = solver.solve();
            match result {
                GaussianResult::Inconsistent { .. } => {
                    // Expected for inconsistent systems
                }
                GaussianResult::Singular { .. } => {
                    // Also possible if the inconsistency isn't detected due to randomness
                }
                GaussianResult::Solved(_) => {
                    // Unexpected but possible if inconsistency wasn't actually created
                }
            }
        }
    }
}

fn test_gf256_boundaries(test: Gf256BoundaryTest) {
    match test.operation {
        Gf256Operation::EliminationMultiply => {
            // Test GF(256) multiplication during elimination with boundary values
            for &val1 in GF256_BOUNDARY_VALUES {
                for val2 in test.test_values.iter().take(8) {
                    // Limit iterations
                    let a = Gf256::new(val1);
                    let b = Gf256::new(*val2);
                    let result = a.mul_field(b);

                    // Test key properties during elimination
                    if val1 == 0 || *val2 == 0 {
                        assert_eq!(
                            result.raw(),
                            0,
                            "Zero multiplication failed: {} * {}",
                            val1,
                            val2
                        );
                    }
                    if val1 == 1 {
                        assert_eq!(
                            result.raw(),
                            *val2,
                            "Identity multiplication failed: 1 * {}",
                            val2
                        );
                    }
                    if *val2 == 1 {
                        assert_eq!(
                            result.raw(),
                            val1,
                            "Identity multiplication failed: {} * 1",
                            val1
                        );
                    }

                    // Test commutativity
                    let reverse = b.mul_field(a);
                    assert_eq!(
                        result.raw(),
                        reverse.raw(),
                        "Multiplication not commutative"
                    );
                }
            }
        }

        Gf256Operation::RowAddition => {
            // Test GF(256) addition (XOR) during row operations
            for &val1 in GF256_BOUNDARY_VALUES {
                for val2 in test.test_values.iter().take(8) {
                    let result = val1 ^ val2; // Addition is XOR in GF(256)

                    // Test key properties
                    if val1 == 0 {
                        assert_eq!(result, *val2, "Additive identity failed: 0 + {}", val2);
                    }
                    if *val2 == 0 {
                        assert_eq!(result, val1, "Additive identity failed: {} + 0", val1);
                    }
                    if val1 == *val2 {
                        assert_eq!(result, 0, "Self-inverse failed: {} + {}", val1, val1);
                    }

                    // Test commutativity
                    let reverse = val2 ^ val1;
                    assert_eq!(result, reverse, "Addition not commutative");
                }
            }
        }

        Gf256Operation::PivotInversion => {
            // Test GF(256) inversion for pivot normalization
            for &val in GF256_BOUNDARY_VALUES {
                if val != 0 {
                    let element = Gf256::new(val);
                    let inv = element.inv();
                    let product = element.mul_field(inv);

                    assert_eq!(
                        product.raw(),
                        1,
                        "Inversion failed: {} * inv({}) != 1",
                        val,
                        val
                    );

                    // Test boundary cases
                    if val == 1 {
                        assert_eq!(inv.raw(), 1, "Inverse of 1 should be 1");
                    }

                    // Test double inversion
                    let double_inv = inv.inv();
                    assert_eq!(
                        double_inv.raw(),
                        val,
                        "Double inversion failed: inv(inv({})) != {}",
                        val,
                        val
                    );
                }
            }
        }

        Gf256Operation::IrreduciblePolyEdge => {
            // Test operations near the irreducible polynomial value (0x1D)
            let poly_coeff: u8 = 0x1D; // x^8 + x^4 + x^3 + x^2 + 1
            for offset in 0..8u8 {
                let test_val = poly_coeff.wrapping_add(offset);
                let element = Gf256::new(test_val);
                verify_field_invariants(element, Gf256::new(0x02), Gf256::new(offset));

                // Test that field operations remain valid near polynomial boundary
                let squared = element.mul_field(element);
                let inv = if test_val != 0 {
                    element.inv()
                } else {
                    Gf256::new(0)
                };

                if test_val != 0 {
                    let verify = element.mul_field(inv);
                    assert_eq!(
                        verify.raw(),
                        1,
                        "Irreducible poly edge inversion failed for {}",
                        test_val
                    );
                }

                // Test that polynomial reduction works correctly
                let high_power = element.pow(255); // Maximum exponent
                let _ = high_power; // Just verify no panic

                let _ = squared; // Verify squaring doesn't cause issues
            }
        }
    }
}

fn test_dense_factor_cache_probe(probe: DenseFactorCacheProbe) {
    let symbol_size = usize::from(probe.symbol_size_hint % MAX_CACHE_SYMBOL_SIZE as u8) + 1;
    let source = make_cache_probe_source(CACHE_PROBE_K, symbol_size, probe.seed, &probe.payload);
    let encoder = SystematicEncoder::new(&source, symbol_size, probe.seed)
        .expect("bounded cache probe source should build a systematic encoder");
    let decoder = InactivationDecoder::new(CACHE_PROBE_K, symbol_size, probe.seed);

    let mut received = decoder.constraint_symbols();
    let repair_count = decoder.params().l;
    for esi in (CACHE_PROBE_K as u32)..(CACHE_PROBE_K as u32 + repair_count as u32) {
        let (columns, coefficients) = decoder
            .repair_equation(esi)
            .expect("bounded repair ESI should produce an equation");
        let data = encoder.repair_symbol(esi);
        received.push(ReceivedSymbol::repair(esi, columns, coefficients, data));
    }

    let iterations = 2 + usize::from(probe.repeat_count % 2);
    let mut previous_key = None;
    let mut saw_miss = false;
    let mut saw_hit = false;

    for iteration in 0..iterations {
        let decoded = decoder
            .decode(&received)
            .expect("repair-only cache probe should decode");
        assert_eq!(
            decoded.source, source,
            "cache probe decode must recover source on iteration {iteration}"
        );

        let stats = decoded.stats;
        saw_miss |= stats.factor_cache_misses > 0;
        saw_hit |= stats.factor_cache_hits > 0;

        if let Some(key) = stats.factor_cache_last_key {
            if let Some(prev) = previous_key {
                assert_eq!(
                    key, prev,
                    "repeated cache probe should reuse structural key"
                );
            }
            previous_key = Some(key);
        }

        if stats.factor_cache_capacity > 0 {
            assert!(
                stats.factor_cache_entries <= stats.factor_cache_capacity,
                "cache entries {} exceed capacity {}",
                stats.factor_cache_entries,
                stats.factor_cache_capacity
            );
        }
    }

    assert!(
        saw_miss,
        "first repair-only decode should populate the dense-factor cache"
    );
    assert!(
        saw_hit,
        "repeated repair-only decode should hit the dense-factor cache"
    );
}

fn make_cache_probe_source(
    k: usize,
    symbol_size: usize,
    seed: u64,
    payload: &[u8],
) -> Vec<Vec<u8>> {
    let seed_bytes = seed.to_le_bytes();
    (0..k)
        .map(|symbol_idx| {
            (0..symbol_size)
                .map(|byte_idx| {
                    let offset = symbol_idx * symbol_size + byte_idx;
                    let payload_byte = payload
                        .get(offset % payload.len().max(1))
                        .copied()
                        .unwrap_or(seed_bytes[offset % seed_bytes.len()]);
                    payload_byte ^ seed_bytes[(offset + symbol_idx) % seed_bytes.len()]
                })
                .collect()
        })
        .collect()
}

/// Test helper: verify that matrix operations maintain GF(256) field properties
fn verify_field_invariants(a: Gf256, b: Gf256, c: Gf256) {
    // Commutativity: a + b = b + a, a * b = b * a
    assert_eq!(
        (a.raw() ^ b.raw()),
        (b.raw() ^ a.raw()),
        "Addition not commutative"
    );
    assert_eq!(
        a.mul_field(b).raw(),
        b.mul_field(a).raw(),
        "Multiplication not commutative"
    );

    // Associativity: (a + b) + c = a + (b + c), (a * b) * c = a * (b * c)
    let add_left = (a.raw() ^ b.raw()) ^ c.raw();
    let add_right = a.raw() ^ (b.raw() ^ c.raw());
    assert_eq!(add_left, add_right, "Addition not associative");

    let mul_left = a.mul_field(b).mul_field(c);
    let mul_right = a.mul_field(b.mul_field(c));
    assert_eq!(
        mul_left.raw(),
        mul_right.raw(),
        "Multiplication not associative"
    );

    // Distributivity: a * (b + c) = (a * b) + (a * c)
    let left = a.mul_field(Gf256::new(b.raw() ^ c.raw()));
    let right_b = a.mul_field(b);
    let right_c = a.mul_field(c);
    let right = Gf256::new(right_b.raw() ^ right_c.raw());
    assert_eq!(left.raw(), right.raw(), "Distributivity failed");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_boundary_values_coverage() {
        // Ensure our boundary values actually cover the important cases
        assert!(GF256_BOUNDARY_VALUES.contains(&0x00), "Missing zero");
        assert!(GF256_BOUNDARY_VALUES.contains(&0x01), "Missing one");
        assert!(GF256_BOUNDARY_VALUES.contains(&0xFF), "Missing max");
        assert!(
            GF256_BOUNDARY_VALUES.contains(&0x1D),
            "Missing irreducible poly"
        );
    }

    #[test]
    fn test_field_invariants_with_boundaries() {
        for &a in GF256_BOUNDARY_VALUES.iter().take(3) {
            for &b in GF256_BOUNDARY_VALUES.iter().take(3) {
                for &c in GF256_BOUNDARY_VALUES.iter().take(3) {
                    verify_field_invariants(Gf256::new(a), Gf256::new(b), Gf256::new(c));
                }
            }
        }
    }

    #[test]
    fn test_small_identity_matrix() {
        let mut solver = GaussianSolver::new(2, 2);
        solver.set_row(0, &[1, 0], DenseRow::new(vec![5]));
        solver.set_row(1, &[0, 1], DenseRow::new(vec![7]));

        let result = solver.solve();
        match result {
            GaussianResult::Solved(solution) => {
                assert_eq!(solution.len(), 2);
                assert_eq!(solution[0].as_slice(), &[5]);
                assert_eq!(solution[1].as_slice(), &[7]);
            }
            _ => panic!("Identity matrix should solve successfully"),
        }
    }
}
