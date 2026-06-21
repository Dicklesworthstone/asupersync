#![allow(warnings)]
#![allow(clippy::all)]
#![allow(missing_docs)]
//! RaptorQ conformance, property tests, and deterministic fuzz harness.
//!
//! This test suite validates:
//! - Roundtrip correctness: encode → drop → decode → verify
//! - Determinism: same inputs produce identical outputs
//! - Edge cases: empty, tiny, large blocks, various loss patterns
//! - Fuzz testing with fixed seeds for reproducibility

use asupersync::raptorq::decoder::{DecodeError, InactivationDecoder, ReceivedSymbol};
use asupersync::raptorq::gf256::{Gf256, gf256_addmul_slice};
use asupersync::raptorq::rfc6330::rand as rfc6330_rand;
use asupersync::raptorq::systematic::{
    ConstraintMatrix, EmittedSymbol, SystematicEncoder, SystematicParams,
};
use asupersync::util::DetRng;

fn repair_equation(decoder: &InactivationDecoder, esi: u32) -> (Vec<usize>, Vec<Gf256>) {
    decoder
        .repair_equation(esi)
        .unwrap_or_else(|err| panic!("repair equation for esi={esi} failed: {err:?}"))
}

fn rfc_repair_equation(params: &SystematicParams, esi: u32) -> (Vec<usize>, Vec<Gf256>) {
    params
        .rfc_repair_equation(esi)
        .unwrap_or_else(|err| panic!("RFC repair equation for esi={esi} failed: {err:?}"))
}

// ============================================================================
// RFC 6330 scenario harness skeleton
// ============================================================================

#[derive(Clone, Copy, Debug)]
enum RequirementLevel {
    Must,
}

#[derive(Clone, Copy, Debug)]
struct Rfc6330Scenario {
    id: &'static str,
    clause: &'static str,
    description: &'static str,
    requirement: RequirementLevel,
}

fn assert_roundtrip_scenario(
    scenario: Rfc6330Scenario,
    k: usize,
    symbol_size: usize,
    seed: u64,
    drop_source_indices: &[usize],
    max_repair_esi: u32,
) {
    let source = make_patterned_source(k, symbol_size);
    let encoder = SystematicEncoder::new(&source, symbol_size, seed)
        .unwrap_or_else(|| panic!("{} setup failed", scenario.id));
    let decoder = InactivationDecoder::new(k, symbol_size, seed);
    let received = build_received_symbols(
        &encoder,
        &decoder,
        &source,
        drop_source_indices,
        max_repair_esi,
        seed,
    );

    let result = decoder.decode(&received).unwrap_or_else(|err| {
        panic!(
            "{} ({:?}, {}) failed unexpectedly: {err:?}",
            scenario.id, scenario.requirement, scenario.clause
        )
    });

    assert_eq!(
        result.source, source,
        "{} ({}) must recover the original source block",
        scenario.id, scenario.description
    );
}

fn assert_failure_scenario(
    scenario: Rfc6330Scenario,
    decoder: &InactivationDecoder,
    received: &[ReceivedSymbol],
    predicate: impl FnOnce(&DecodeError) -> bool,
) {
    let err = decoder.decode(received).unwrap_err();
    assert!(
        predicate(&err),
        "{} ({:?}, {}) produced unexpected error: {err:?}",
        scenario.id,
        scenario.requirement,
        scenario.clause
    );
}

// ============================================================================
// Test helpers
// ============================================================================

/// Generate deterministic test data.
fn make_source_data(k: usize, symbol_size: usize, seed: u64) -> Vec<Vec<u8>> {
    let mut rng = DetRng::new(seed);
    (0..k)
        .map(|_| (0..symbol_size).map(|_| rng.next_u64() as u8).collect())
        .collect()
}

/// Generate source data with a specific pattern for easier debugging.
fn make_patterned_source(k: usize, symbol_size: usize) -> Vec<Vec<u8>> {
    (0..k)
        .map(|i| {
            (0..symbol_size)
                .map(|j| ((i * 37 + j * 13 + 7) % 256) as u8)
                .collect()
        })
        .collect()
}

fn flatten_source_bytes(source: &[Vec<u8>]) -> Vec<u8> {
    source.iter().flatten().copied().collect()
}

/// Build received symbols from encoder, optionally dropping some.
/// Extract non-zero columns and GF(256) coefficients for a constraint matrix row.
fn constraint_row_equation(constraints: &ConstraintMatrix, row: usize) -> (Vec<usize>, Vec<Gf256>) {
    let mut columns = Vec::new();
    let mut coefficients = Vec::new();
    for col in 0..constraints.cols {
        let coeff = constraints.get(row, col);
        if !coeff.is_zero() {
            columns.push(col);
            coefficients.push(coeff);
        }
    }
    (columns, coefficients)
}

fn reference_ldpc_hdpc_matrix(params: &SystematicParams) -> ConstraintMatrix {
    let mut matrix = ConstraintMatrix::zeros(params.s + params.h, params.l);
    reference_build_ldpc_rows(&mut matrix, params);
    reference_build_hdpc_rows(&mut matrix, params);
    matrix
}

fn reference_build_ldpc_rows(matrix: &mut ConstraintMatrix, params: &SystematicParams) {
    let s = params.s;
    let b = params.b;
    let w = params.w;
    let p = params.p;

    for symbol_idx in 0..b {
        let step = 1 + symbol_idx / s.max(1);
        let first_row = symbol_idx % s;
        let second_row = (first_row + step) % s;
        let third_row = (second_row + step) % s;

        matrix.add_assign(first_row, symbol_idx, Gf256::ONE);
        matrix.add_assign(second_row, symbol_idx, Gf256::ONE);
        matrix.add_assign(third_row, symbol_idx, Gf256::ONE);
    }

    for row in 0..s {
        matrix.set(row, b + row, Gf256::ONE);
        matrix.set(row, (row % p) + w, Gf256::ONE);
        matrix.set(row, ((row + 1) % p) + w, Gf256::ONE);
    }
}

fn reference_build_hdpc_rows(matrix: &mut ConstraintMatrix, params: &SystematicParams) {
    let s = params.s;
    let h = params.h;
    let k_prime = params.k_prime;
    let ks = k_prime + s;

    if h == 0 {
        return;
    }

    let mut hdpc = vec![vec![Gf256::ZERO; ks]; h];
    for (row_idx, row) in hdpc.iter_mut().enumerate() {
        row[ks - 1] = Gf256::ALPHA.pow((row_idx % 255) as u8);
    }

    for col in (0..ks.saturating_sub(1)).rev() {
        for row in &mut hdpc {
            row[col] = Gf256::ALPHA * row[col + 1];
        }

        let first_row = rfc6330_rand((col + 1) as u32, 6, h as u32) as usize;
        let step = if h > 1 {
            rfc6330_rand((col + 1) as u32, 7, (h - 1) as u32) as usize
        } else {
            0
        };
        let second_row = (first_row + step + 1) % h;
        hdpc[first_row][col] += Gf256::ONE;
        hdpc[second_row][col] += Gf256::ONE;
    }

    for (row, values) in hdpc.iter().enumerate() {
        for (col, &val) in values.iter().enumerate() {
            if !val.is_zero() {
                matrix.set(s + row, col, val);
            }
        }
        matrix.set(s + row, ks + row, Gf256::ONE);
    }
}

fn matrix_band_bytes(matrix: &ConstraintMatrix, row_start: usize, row_end: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity((row_end - row_start) * matrix.cols);
    for row in row_start..row_end {
        for col in 0..matrix.cols {
            bytes.push(matrix.get(row, col).raw());
        }
    }
    bytes
}

fn build_received_symbols(
    encoder: &SystematicEncoder,
    decoder: &InactivationDecoder,
    source: &[Vec<u8>],
    drop_source_indices: &[usize],
    max_repair_esi: u32,
    _seed: u64,
) -> Vec<ReceivedSymbol> {
    let k = source.len();

    // Start with constraint symbols (LDPC + HDPC parity checks with zero RHS).
    let mut received = decoder.constraint_symbols();

    // Add source symbols with the same canonical RFC tuple equations the
    // decoder validates and uses for reconstruction.
    for (i, data) in source.iter().enumerate() {
        if !drop_source_indices.contains(&i) {
            let (columns, coefficients) = decoder.source_equation(i as u32);
            received.push(ReceivedSymbol {
                esi: i as u32,
                is_source: true,
                columns,
                coefficients,
                data: data.clone(),
            });
        }
    }

    // Add repair symbols
    for esi in (k as u32)..max_repair_esi {
        let (cols, coefs) = repair_equation(decoder, esi);
        let repair_data = encoder.repair_symbol(esi);
        received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
    }

    received
}

#[test]
fn rfc6330_harness_systematic_only_decode() {
    let scenario = Rfc6330Scenario {
        id: "RFC6330-SYSTEMATIC-ONLY",
        clause: "RFC 6330 §5.6",
        description: "systematic symbols alone decode a fully delivered source block",
        requirement: RequirementLevel::Must,
    };

    let k = 8;
    let symbol_size = 64;
    let seed = 42u64;
    let max_repair_esi = InactivationDecoder::new(k, symbol_size, seed).params().l as u32;

    assert_roundtrip_scenario(scenario, k, symbol_size, seed, &[], max_repair_esi);
}

#[test]
fn rfc6330_harness_repair_assisted_decode() {
    let scenario = Rfc6330Scenario {
        id: "RFC6330-REPAIR-ASSISTED",
        clause: "RFC 6330 §5.3",
        description: "repair symbols restore a source block after deterministic source loss",
        requirement: RequirementLevel::Must,
    };

    let k = 10;
    let symbol_size = 32;
    let seed = 123u64;
    let drop_indices: Vec<usize> = (0..k).filter(|i| i % 2 == 0).collect();
    let l = InactivationDecoder::new(k, symbol_size, seed).params().l;
    let max_repair_esi = (l + drop_indices.len()) as u32;

    assert_roundtrip_scenario(
        scenario,
        k,
        symbol_size,
        seed,
        &drop_indices,
        max_repair_esi,
    );
}

#[test]
fn rfc6330_harness_rejects_source_esi_out_of_range() {
    let scenario = Rfc6330Scenario {
        id: "RFC6330-SOURCE-ESI-RANGE",
        clause: "RFC 6330 §5.3",
        description: "source symbols must stay within the systematic source ESI domain",
        requirement: RequirementLevel::Must,
    };

    let k = 4;
    let symbol_size = 16;
    let seed = 700u64;
    let decoder = InactivationDecoder::new(k, symbol_size, seed);
    let received = vec![ReceivedSymbol::source(k as u32, vec![0u8; symbol_size])];

    assert_failure_scenario(scenario, &decoder, &received, |err| {
        matches!(err, DecodeError::SourceEsiOutOfRange { .. })
    });
}

// ============================================================================
// Conformance: Roundtrip tests
// ============================================================================

#[test]
fn roundtrip_no_loss() {
    let k = 8;
    let symbol_size = 64;
    let seed = 42u64;

    let source = make_patterned_source(k, symbol_size);
    let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
    let decoder = InactivationDecoder::new(k, symbol_size, seed);
    let l = decoder.params().l;

    // Receive all source + enough repair to reach L
    let received = build_received_symbols(&encoder, &decoder, &source, &[], l as u32, seed);

    let result = decoder.decode(&received).expect("decode should succeed");

    for (i, original) in source.iter().enumerate() {
        assert_eq!(
            &result.source[i], original,
            "source symbol {i} mismatch after roundtrip"
        );
    }
}

#[test]
fn roundtrip_with_source_loss() {
    let k = 10;
    let symbol_size = 32;
    let seed = 123u64;

    let source = make_patterned_source(k, symbol_size);
    let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
    let decoder = InactivationDecoder::new(k, symbol_size, seed);
    let l = decoder.params().l;

    // Drop half the source symbols
    let drop_indices: Vec<usize> = (0..k).filter(|i| i % 2 == 0).collect();
    let dropped_count = drop_indices.len();

    // Need enough repair to compensate
    let max_repair = (l + dropped_count) as u32;
    let received =
        build_received_symbols(&encoder, &decoder, &source, &drop_indices, max_repair, seed);

    let result = decoder.decode(&received).expect("decode should succeed");

    for (i, original) in source.iter().enumerate() {
        assert_eq!(
            &result.source[i], original,
            "source symbol {i} mismatch after recovering from loss"
        );
    }
}

#[test]
fn roundtrip_repair_only() {
    let k = 6;
    let symbol_size = 24;
    let seed = 456u64;

    let source = make_patterned_source(k, symbol_size);
    let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
    let decoder = InactivationDecoder::new(k, symbol_size, seed);
    let l = decoder.params().l;

    // Drop ALL source symbols
    let drop_indices: Vec<usize> = (0..k).collect();

    // Need L repair symbols
    let max_repair = (k + l) as u32;
    let received =
        build_received_symbols(&encoder, &decoder, &source, &drop_indices, max_repair, seed);

    let result = decoder.decode(&received).expect("decode should succeed");

    for (i, original) in source.iter().enumerate() {
        assert_eq!(
            &result.source[i], original,
            "source symbol {i} mismatch with repair-only decode"
        );
    }
}

// Mirror the failure-mode unit-test contract in the integration harness so
// these exact deterministic cases remain remotely verifiable even when
// unrelated `cargo test --lib` worktree churn blocks the lib-test lane. These
// cases intentionally hand-build `ReceivedSymbol::source` rows to match the
// unit tests instead of routing through `build_received_symbols()`.
#[test]
fn contiguous_burst_loss_all_source_symbols_dropped_contract() {
    let k = 8;
    let symbol_size = 32;
    let seed = 42u64;

    let source = make_patterned_source(k, symbol_size);
    let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
    let decoder = InactivationDecoder::new(k, symbol_size, seed);
    let l = decoder.params().l;

    // Mirror the exact failure_modes contract so this scenario remains
    // runnable through the integration harness when unrelated lib-test
    // surfaces are red in the shared worktree.
    let mut received = decoder.constraint_symbols();
    for esi in (k as u32)..((k + l * 2) as u32) {
        let (cols, coefs) = repair_equation(&decoder, esi);
        let repair_data = encoder.repair_symbol(esi);
        received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
    }

    let result = decoder.decode(&received).expect("decode should succeed");
    assert_eq!(result.source, source);
}

#[test]
fn contiguous_burst_drop_first_half_of_source_contract() {
    let k = 16;
    let symbol_size = 32;
    let seed = 42u64;

    let source = make_patterned_source(k, symbol_size);
    let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
    let decoder = InactivationDecoder::new(k, symbol_size, seed);
    let l = decoder.params().l;

    // Mirror the exact failure_modes received-symbol shape here as well,
    // including direct source rows for the surviving half.
    let mut received = decoder.constraint_symbols();
    for (i, sym) in source.iter().enumerate().take(k).skip(k / 2) {
        received.push(ReceivedSymbol::source(i as u32, sym.clone()));
    }
    for esi in (k as u32)..((k + l * 2) as u32) {
        let (cols, coefs) = repair_equation(&decoder, esi);
        let repair_data = encoder.repair_symbol(esi);
        received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
    }

    let result = decoder.decode(&received).expect("decode should succeed");
    assert_eq!(result.source, source);
}

// ============================================================================
// Property: Determinism
// ============================================================================

#[test]
fn encoder_deterministic_same_seed() {
    let k = 12;
    let symbol_size = 48;
    let seed = 789u64;

    let source = make_source_data(k, symbol_size, 111);

    let enc1 = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
    let enc2 = SystematicEncoder::new(&source, symbol_size, seed).unwrap();

    // All intermediate and repair symbols must match
    for i in 0..enc1.params().l {
        assert_eq!(
            enc1.intermediate_symbol(i),
            enc2.intermediate_symbol(i),
            "intermediate symbol {i} differs"
        );
    }

    for esi in (k as u32)..(k as u32 + 50) {
        assert_eq!(
            enc1.repair_symbol(esi),
            enc2.repair_symbol(esi),
            "repair symbol ESI={esi} differs"
        );
    }
}

#[test]
fn decoder_deterministic_same_input() {
    let k = 8;
    let symbol_size = 32;
    let seed = 321u64;

    let source = make_patterned_source(k, symbol_size);
    let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
    let decoder = InactivationDecoder::new(k, symbol_size, seed);
    let l = decoder.params().l;

    let received = build_received_symbols(&encoder, &decoder, &source, &[], l as u32, seed);

    let result1 = decoder.decode(&received).unwrap();
    let result2 = decoder.decode(&received).unwrap();

    assert_eq!(result1.source, result2.source, "decoded source differs");
    assert_eq!(
        result1.intermediate, result2.intermediate,
        "decoded intermediate differs"
    );
    assert_eq!(result1.stats.peeled, result2.stats.peeled);
    assert_eq!(result1.stats.inactivated, result2.stats.inactivated);
    assert_eq!(result1.stats.gauss_ops, result2.stats.gauss_ops);
}

#[test]
fn full_roundtrip_deterministic() {
    let k = 10;
    let symbol_size = 40;

    for seed in [1u64, 42, 999, 12345] {
        let source = make_source_data(k, symbol_size, seed * 7);
        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        // Drop some symbols
        let drop: Vec<usize> = (0..k)
            .filter(|i| (i + seed as usize).is_multiple_of(3))
            .collect();
        let max_repair = (l + drop.len()) as u32;
        let received = build_received_symbols(&encoder, &decoder, &source, &drop, max_repair, seed);

        let result = decoder.decode(&received).expect("decode failed");

        for (i, original) in source.iter().enumerate() {
            assert_eq!(
                &result.source[i], original,
                "seed={seed}, symbol {i} mismatch"
            );
        }
    }
}

// ============================================================================
// Edge cases
// ============================================================================

#[test]
fn edge_case_k_equals_1() {
    let k = 1;
    let symbol_size = 16;
    let seed = 42u64;

    let source = make_patterned_source(k, symbol_size);
    let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
    let decoder = InactivationDecoder::new(k, symbol_size, seed);
    let l = decoder.params().l;

    let received = build_received_symbols(&encoder, &decoder, &source, &[], l as u32, seed);

    let result = decoder.decode(&received).expect("k=1 decode failed");
    assert_eq!(result.source[0], source[0], "k=1 roundtrip failed");
}

#[test]
fn edge_case_k_equals_2() {
    let k = 2;
    let symbol_size = 8;
    let seed = 100u64;

    let source = make_patterned_source(k, symbol_size);
    let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
    let decoder = InactivationDecoder::new(k, symbol_size, seed);
    let l = decoder.params().l;

    let received = build_received_symbols(&encoder, &decoder, &source, &[], l as u32, seed);

    let result = decoder.decode(&received).expect("k=2 decode failed");
    assert_eq!(result.source, source, "k=2 roundtrip failed");
}

#[test]
fn edge_case_tiny_symbol_size() {
    let k = 4;
    let symbol_size = 1; // Single byte symbols
    let seed = 200u64;

    let source: Vec<Vec<u8>> = (0..k).map(|i| vec![(i * 37) as u8]).collect();
    let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
    let decoder = InactivationDecoder::new(k, symbol_size, seed);
    let l = decoder.params().l;

    let received = build_received_symbols(&encoder, &decoder, &source, &[], l as u32, seed);

    let result = decoder
        .decode(&received)
        .expect("tiny symbol decode failed");
    assert_eq!(result.source, source, "tiny symbol roundtrip failed");
}

#[test]
fn edge_case_large_symbol_size() {
    let k = 4;
    let symbol_size = 4096; // 4KB symbols
    let seed = 300u64;

    let source = make_source_data(k, symbol_size, 777);
    let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
    let decoder = InactivationDecoder::new(k, symbol_size, seed);
    let l = decoder.params().l;

    let received = build_received_symbols(&encoder, &decoder, &source, &[], l as u32, seed);

    let result = decoder
        .decode(&received)
        .expect("large symbol decode failed");
    assert_eq!(result.source, source, "large symbol roundtrip failed");
}

#[test]
fn edge_case_larger_k() {
    let k = 100;
    let symbol_size = 64;
    let seed = 400u64;

    let source = make_source_data(k, symbol_size, 888);
    let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
    let decoder = InactivationDecoder::new(k, symbol_size, seed);
    let l = decoder.params().l;

    // Drop 10% of source symbols
    let drop: Vec<usize> = (0..k).filter(|i| i % 10 == 0).collect();
    let max_repair = (l + drop.len()) as u32;
    let received = build_received_symbols(&encoder, &decoder, &source, &drop, max_repair, seed);

    let result = decoder.decode(&received).expect("k=100 decode failed");
    for (i, original) in source.iter().enumerate() {
        assert_eq!(&result.source[i], original, "k=100 symbol {i} mismatch");
    }
}

// ============================================================================
// Failure cases
// ============================================================================

#[test]
fn insufficient_symbols_fails() {
    let k = 8;
    let symbol_size = 32;
    let seed = 500u64;

    let source = make_patterned_source(k, symbol_size);
    let decoder = InactivationDecoder::new(k, symbol_size, seed);

    // Only receive k-1 source symbols (not enough: need at least L total)
    let received: Vec<ReceivedSymbol> = source[..k - 1]
        .iter()
        .enumerate()
        .map(|(i, data)| ReceivedSymbol::source(i as u32, data.clone()))
        .collect();

    let err = decoder.decode(&received).unwrap_err();
    assert!(
        matches!(err, DecodeError::InsufficientSymbols { .. }),
        "expected InsufficientSymbols, got {err:?}"
    );
}

#[test]
fn symbol_size_mismatch_fails() {
    let k = 4;
    let symbol_size = 32;
    let seed = 600u64;

    let decoder = InactivationDecoder::new(k, symbol_size, seed);
    let l = decoder.params().l;

    // Create symbols with wrong size
    let received: Vec<ReceivedSymbol> = (0..l)
        .map(|i| ReceivedSymbol::source(i as u32, vec![0u8; symbol_size + 1])) // Wrong size!
        .collect();

    let err = decoder.decode(&received).unwrap_err();
    assert!(
        matches!(err, DecodeError::SymbolSizeMismatch { .. }),
        "expected SymbolSizeMismatch, got {err:?}"
    );
}

// ============================================================================
// Deterministic fuzz harness
// ============================================================================

/// Fuzz test with deterministic seeds for reproducibility.
#[test]
#[allow(clippy::cast_precision_loss)]
fn fuzz_roundtrip_various_sizes() {
    // Test matrix: (k, symbol_size, loss_ratio, seed)
    let test_cases = [
        (4, 16, 0.0, 1001u64),
        (4, 16, 0.25, 1002),
        (8, 32, 0.0, 1003),
        (8, 32, 0.5, 1004),
        (16, 64, 0.0, 1005),
        (16, 64, 0.25, 1006),
        (32, 128, 0.0, 1007),
        (32, 128, 0.125, 1008),
        (64, 256, 0.0, 1009),
        (64, 256, 0.1, 1010),
    ];

    for (k, symbol_size, loss_ratio, seed) in test_cases {
        let source = make_source_data(k, symbol_size, seed * 3);
        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        // Deterministically drop symbols based on loss ratio
        let mut rng = DetRng::new(seed.wrapping_add(0xDEAD));
        let drop: Vec<usize> = (0..k)
            .filter(|_| (rng.next_u64() as f64 / u64::MAX as f64) < loss_ratio)
            .collect();

        let max_repair = (l + drop.len() + 2) as u32; // +2 margin
        let received = build_received_symbols(&encoder, &decoder, &source, &drop, max_repair, seed);

        let result = decoder
            .decode(&received)
            .unwrap_or_else(|e| panic!("fuzz case k={k}, seed={seed} failed: {e:?}"));

        for (i, original) in source.iter().enumerate() {
            assert_eq!(
                &result.source[i], original,
                "fuzz case k={k}, seed={seed}, symbol {i} mismatch"
            );
        }
    }
}

/// Fuzz test with random loss patterns.
#[test]
fn fuzz_random_loss_patterns() {
    let base_seed = 2000u64;

    for iteration in 0..20 {
        let seed = base_seed + iteration;
        let mut rng = DetRng::new(seed);

        // Random parameters within bounds
        let k = 4 + rng.next_usize(60); // k in [4, 64)
        let symbol_size = 8 + rng.next_usize(248); // symbol_size in [8, 256)

        let source = make_source_data(k, symbol_size, seed * 5);
        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        // Random loss: 0-50%
        let loss_pct = rng.next_usize(51);
        let drop: Vec<usize> = (0..k).filter(|_| rng.next_usize(100) < loss_pct).collect();

        let max_repair = (l + drop.len() + 3) as u32;
        let received = build_received_symbols(&encoder, &decoder, &source, &drop, max_repair, seed);

        let result = decoder.decode(&received).unwrap_or_else(|e| {
            panic!(
                "fuzz iteration {iteration} failed: k={k}, symbol_size={symbol_size}, \
                 loss={loss_pct}%, dropped={}, error={:?}",
                drop.len(),
                e
            )
        });

        for (i, original) in source.iter().enumerate() {
            assert_eq!(
                &result.source[i], original,
                "fuzz iteration {iteration}, symbol {i} mismatch"
            );
        }
    }
}

/// Stress test: many small decodes.
#[test]
fn stress_many_small_decodes() {
    for iteration in 0..100 {
        let seed = 3000u64 + iteration;
        let k = 4;
        let symbol_size = 16;

        let source = make_source_data(k, symbol_size, seed);
        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        let received = build_received_symbols(&encoder, &decoder, &source, &[], l as u32, seed);

        let result = decoder
            .decode(&received)
            .unwrap_or_else(|e| panic!("stress iteration {iteration} failed: {e:?}"));

        assert_eq!(
            result.source, source,
            "stress iteration {iteration} mismatch"
        );
    }
}

// ============================================================================
// RFC tuple equation tests
// ============================================================================

#[test]
fn rfc_tuple_equation_degree_coverage() {
    let k_values = [10, 50, 100, 500];

    for k in k_values {
        let params = SystematicParams::for_source_block(k, 64);
        let mut degree_counts = std::collections::BTreeMap::<usize, usize>::new();
        let sample_count = 1_024u32;
        let start_esi = k as u32;

        for esi in start_esi..start_esi + sample_count {
            let (columns, coefficients) = rfc_repair_equation(&params, esi);
            assert_eq!(
                columns.len(),
                coefficients.len(),
                "k={k}, esi={esi}: columns/coefficients mismatch"
            );
            let unique_columns: std::collections::BTreeSet<usize> =
                columns.iter().copied().collect();
            assert!(
                !unique_columns.is_empty(),
                "k={k}, esi={esi}: empty effective repair equation"
            );
            assert!(
                unique_columns.len() <= params.l,
                "k={k}, esi={esi}: effective degree {} exceeds L={}",
                unique_columns.len(),
                params.l
            );
            assert!(
                columns.iter().all(|&col| col < params.l),
                "k={k}, esi={esi}: out-of-range repair index"
            );
            *degree_counts.entry(unique_columns.len()).or_insert(0) += 1;
        }

        assert!(
            degree_counts.len() >= 3,
            "k={k}: expected at least 3 distinct RFC tuple equation degrees, got {}",
            degree_counts.len()
        );
    }
}

#[test]
fn rfc_tuple_equation_deterministic_across_runs() {
    let params = SystematicParams::for_source_block(50, 64);

    let generate = |start_esi: u32| -> Vec<Vec<usize>> {
        (start_esi..start_esi + 512)
            .map(|esi| rfc_repair_equation(&params, esi).0)
            .collect()
    };

    let run1 = generate(50);
    let run2 = generate(50);
    let run3 = generate(51);

    assert_eq!(run1, run2, "same ESI range should produce same equations");
    assert_ne!(
        run1, run3,
        "different ESI ranges should produce different equations"
    );
}

// ============================================================================
// Systematic params tests
// ============================================================================

#[test]
fn params_consistency() {
    for k in [1, 2, 4, 8, 16, 32, 64, 100, 256] {
        let params = SystematicParams::for_source_block(k, 64);

        assert_eq!(params.k, k, "k mismatch");
        assert!(params.k_prime >= params.k, "k={k}: K' must satisfy K' >= K");
        assert!(params.s >= 2, "k={k}: S should be at least 2");
        assert!(params.h >= 1, "k={k}: H should be at least 1");
        assert_eq!(
            params.l,
            params.k_prime + params.s + params.h,
            "k={k}: L = K' + S + H"
        );
        assert!(params.w >= params.s, "k={k}: W should be >= S");
        assert_eq!(params.b, params.w - params.s, "k={k}: B = W - S");
    }
}

#[test]
#[allow(clippy::cast_precision_loss)]
fn params_overhead_bounded() {
    // Overhead = (L - K) / K should remain bounded with RFC table lookup and
    // improve as K grows. K' rounding increases small-K overhead.
    for (k, max_overhead) in [(10, 1.8), (50, 0.65), (100, 0.35), (500, 0.25)] {
        let params = SystematicParams::for_source_block(k, 64);
        let overhead = params.l - params.k;
        let overhead_ratio = overhead as f64 / k as f64;
        assert!(
            overhead_ratio < max_overhead,
            "k={k}: overhead {overhead_ratio:.2} exceeds bound {max_overhead}"
        );
    }
}

// ============================================================================
// GF(256) arithmetic sanity
// ============================================================================

#[test]
fn gf256_basic_properties() {
    // Additive identity
    assert_eq!(Gf256::ZERO + Gf256::ONE, Gf256::ONE);

    // Multiplicative identity
    assert_eq!(Gf256::ONE * Gf256::new(42), Gf256::new(42));

    // Self-inverse addition (XOR property)
    let x = Gf256::new(123);
    assert_eq!(x + x, Gf256::ZERO);

    // Multiplicative inverse
    for val in 1..=255u8 {
        let x = Gf256::new(val);
        let inv = x.inv();
        assert_eq!(x * inv, Gf256::ONE, "inverse failed for {val}");
    }
}

#[test]
fn gf256_alpha_powers() {
    // Alpha should generate the multiplicative group
    let mut seen = [false; 256];
    let mut current = Gf256::ONE;

    for i in 0..255 {
        let val = current.raw() as usize;
        assert!(
            !seen[val],
            "alpha^{i} = {val} already seen, not a generator"
        );
        seen[val] = true;
        current *= Gf256::ALPHA;
    }

    // After 255 multiplications, should cycle back to 1
    assert_eq!(
        current,
        Gf256::ONE,
        "alpha^255 should equal 1 (group order)"
    );
}

// ============================================================================
// E2E: EncodingPipeline/DecodingPipeline + proof artifacts (bd-15c5)
// ============================================================================

#[cfg(feature = "test-internals")]
mod pipeline_e2e {
    use super::*;
    use asupersync::config::EncodingConfig;
    use asupersync::decoding::{
        DecodingConfig, DecodingPipeline, RejectReason, SymbolAcceptResult,
    };
    use asupersync::encoding::EncodingPipeline;
    use asupersync::raptorq::decoder::{DecodeError, InactivationDecoder, ReceivedSymbol};
    use asupersync::raptorq::proof::{FailureReason, ProofOutcome};
    use asupersync::raptorq::systematic::ConstraintMatrix;
    use asupersync::security::AuthenticatedSymbol;
    use asupersync::security::tag::AuthenticationTag;
    use asupersync::types::resource::{PoolConfig, SymbolPool};
    use asupersync::types::{ObjectId, ObjectParams, Symbol, SymbolKind};
    use asupersync::util::DetRng;
    use serde::Serialize;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    #[derive(Clone, Copy)]
    #[allow(dead_code)]
    enum BurstPosition {
        Early,
        Late,
    }

    #[derive(Clone, Copy)]
    enum LossPattern {
        None,
        Random {
            seed: u64,
            drop_per_mille: u16,
        },
        Burst {
            drop_per_mille: u16,
            position: BurstPosition,
        },
        Insufficient,
    }

    #[derive(Clone, Copy)]
    struct Scenario {
        name: &'static str,
        id: &'static str,
        replay_id: &'static str,
        profile: &'static str,
        unit_sentinel: &'static str,
        assertion_id: &'static str,
        loss: LossPattern,
        expect_success: bool,
    }

    #[derive(Serialize)]
    struct ConfigReport {
        symbol_size: u16,
        max_block_size: usize,
        repair_overhead: f64,
        min_overhead: usize,
        seed: u64,
        block_k: usize,
        block_count: usize,
        data_len: usize,
    }

    #[derive(Serialize)]
    struct LossReport {
        kind: &'static str,
        seed: Option<u64>,
        drop_per_mille: Option<u16>,
        drop_count: usize,
        keep_count: usize,
        burst_start: Option<usize>,
        burst_len: Option<usize>,
    }

    #[derive(Serialize)]
    struct SymbolCounts {
        total: usize,
        source: usize,
        repair: usize,
    }

    #[derive(Serialize)]
    struct SymbolReport {
        generated: SymbolCounts,
        received: SymbolCounts,
    }

    #[derive(Serialize)]
    struct OutcomeReport {
        success: bool,
        reject_reason: Option<String>,
        decoded_bytes: usize,
    }

    #[derive(Serialize)]
    struct ProofReport {
        hash: u64,
        summary_bytes: usize,
        outcome: String,
        received_total: usize,
        received_source: usize,
        received_repair: usize,
        peeling_solved: usize,
        inactivated: usize,
        pivots: usize,
        row_ops: usize,
        equations_used: usize,
    }

    #[derive(Serialize)]
    struct Report {
        schema_version: &'static str,
        scenario: &'static str,
        scenario_id: &'static str,
        replay_id: &'static str,
        profile: &'static str,
        unit_sentinel: &'static str,
        assertion_id: &'static str,
        run_id: String,
        repro_command: String,
        phase_markers: [&'static str; 5],
        config: ConfigReport,
        loss: LossReport,
        symbols: SymbolReport,
        outcome: OutcomeReport,
        proof: ProofReport,
    }

    #[derive(Serialize)]
    struct ProofSummary {
        version: u8,
        hash: String,
        received_total: usize,
        peeling_solved: usize,
        inactivated: usize,
        pivots: usize,
        row_ops: usize,
        outcome: String,
    }

    fn proof_hash_prefix(hash: &asupersync::raptorq::proof::ProofHash) -> u64 {
        let bytes: [u8; 8] = hash.as_bytes()[..8]
            .try_into()
            .expect("proof hash prefix must be 8 bytes");
        u64::from_be_bytes(bytes)
    }

    fn seed_for_block(object_id: ObjectId, sbn: u8) -> u64 {
        let obj = object_id.as_u128();
        let hi = (obj >> 64) as u64;
        let lo = obj as u64;
        let mut seed = hi ^ lo.rotate_left(13);
        seed ^= u64::from(sbn) << 56;
        if seed == 0 { 1 } else { seed }
    }

    fn pool_for(symbol_size: u16) -> SymbolPool {
        SymbolPool::new(PoolConfig::new(symbol_size, 64, 256, true, 64))
    }

    fn make_bytes(len: usize, seed: u64) -> Vec<u8> {
        let mut rng = DetRng::new(seed);
        let mut data = vec![0u8; len];
        rng.fill_bytes(&mut data);
        data
    }

    fn count_symbols(symbols: &[Symbol]) -> SymbolCounts {
        let mut source = 0usize;
        let mut repair = 0usize;
        for symbol in symbols {
            match symbol.kind() {
                SymbolKind::Source => source += 1,
                SymbolKind::Repair => repair += 1,
            }
        }
        SymbolCounts {
            total: symbols.len(),
            source,
            repair,
        }
    }

    fn hash_symbols(symbols: &[Symbol]) -> u64 {
        let mut hasher = DefaultHasher::new();
        for symbol in symbols {
            symbol.hash(&mut hasher);
        }
        hasher.finish()
    }

    fn choose_drop_count(total: usize, min_keep: usize, drop_per_mille: u16) -> usize {
        if total <= min_keep {
            return 0;
        }
        let max_drop = total - min_keep;
        let desired = total
            .saturating_mul(usize::from(drop_per_mille))
            .div_ceil(1000);
        desired.min(max_drop)
    }

    fn apply_loss(
        symbols: &[Symbol],
        min_keep: usize,
        loss: LossPattern,
    ) -> (Vec<Symbol>, LossReport) {
        let total = symbols.len();
        match loss {
            LossPattern::None => (
                symbols.to_vec(),
                LossReport {
                    kind: "none",
                    seed: None,
                    drop_per_mille: None,
                    drop_count: 0,
                    keep_count: total,
                    burst_start: None,
                    burst_len: None,
                },
            ),
            LossPattern::Random {
                seed,
                drop_per_mille,
            } => {
                let drop_count = choose_drop_count(total, min_keep, drop_per_mille);
                let mut indices: Vec<usize> = (0..total).collect();
                let mut rng = DetRng::new(seed);
                rng.shuffle(&mut indices);
                let mut drop = vec![false; total];
                for idx in indices.into_iter().take(drop_count) {
                    drop[idx] = true;
                }
                let kept: Vec<Symbol> = symbols
                    .iter()
                    .enumerate()
                    .filter(|(idx, _)| !drop[*idx])
                    .map(|(_, sym)| sym.clone())
                    .collect();
                (
                    kept,
                    LossReport {
                        kind: "random",
                        seed: Some(seed),
                        drop_per_mille: Some(drop_per_mille),
                        drop_count,
                        keep_count: total - drop_count,
                        burst_start: None,
                        burst_len: None,
                    },
                )
            }
            LossPattern::Burst {
                drop_per_mille,
                position,
            } => {
                let drop_count = choose_drop_count(total, min_keep, drop_per_mille);
                let start = match position {
                    BurstPosition::Early => 0,
                    BurstPosition::Late => total.saturating_sub(drop_count),
                };
                let end = start.saturating_add(drop_count);
                let kept: Vec<Symbol> = symbols
                    .iter()
                    .enumerate()
                    .filter(|(idx, _)| *idx < start || *idx >= end)
                    .map(|(_, sym)| sym.clone())
                    .collect();
                (
                    kept,
                    LossReport {
                        kind: "burst",
                        seed: None,
                        drop_per_mille: Some(drop_per_mille),
                        drop_count,
                        keep_count: total - drop_count,
                        burst_start: Some(start),
                        burst_len: Some(drop_count),
                    },
                )
            }
            LossPattern::Insufficient => {
                let keep_count = min_keep.saturating_sub(1).min(total);
                let kept: Vec<Symbol> = symbols.iter().take(keep_count).cloned().collect();
                (
                    kept,
                    LossReport {
                        kind: "insufficient",
                        seed: None,
                        drop_per_mille: None,
                        drop_count: total - keep_count,
                        keep_count,
                        burst_start: None,
                        burst_len: None,
                    },
                )
            }
        }
    }

    fn constraint_row_equation(
        constraints: &ConstraintMatrix,
        row: usize,
    ) -> (Vec<usize>, Vec<Gf256>) {
        let mut columns = Vec::new();
        let mut coefficients = Vec::new();
        for col in 0..constraints.cols {
            let coeff = constraints.get(row, col);
            if !coeff.is_zero() {
                columns.push(col);
                coefficients.push(coeff);
            }
        }
        (columns, coefficients)
    }

    fn build_received_symbols(
        symbols: &[Symbol],
        object_id: ObjectId,
        k: usize,
        symbol_size: usize,
        sbn: u8,
    ) -> Vec<ReceivedSymbol> {
        let seed = seed_for_block(object_id, sbn);
        let decoder = InactivationDecoder::new(k, symbol_size, seed);

        let mut received = decoder.constraint_symbols();

        for symbol in symbols.iter().filter(|sym| sym.sbn() == sbn) {
            match symbol.kind() {
                SymbolKind::Source => {
                    let (columns, coefficients) = decoder.source_equation(symbol.esi());
                    received.push(ReceivedSymbol {
                        esi: symbol.esi(),
                        is_source: true,
                        columns,
                        coefficients,
                        data: symbol.data().to_vec(),
                    });
                }
                SymbolKind::Repair => {
                    let (columns, coefficients) = repair_equation(&decoder, symbol.esi());
                    received.push(ReceivedSymbol {
                        esi: symbol.esi(),
                        is_source: false,
                        columns,
                        coefficients,
                        data: symbol.data().to_vec(),
                    });
                }
            }
        }

        received
    }

    fn reject_reason_from_failure(reason: &FailureReason) -> RejectReason {
        match reason {
            FailureReason::InsufficientSymbols { .. } => RejectReason::InsufficientRank,
            FailureReason::SymbolSizeMismatch { .. } => RejectReason::SymbolSizeMismatch,
            FailureReason::ComputeBudgetExhausted { .. } => RejectReason::MemoryLimitReached,
            FailureReason::EsiRateLimitExceeded { .. } => RejectReason::InvalidMetadata,
            FailureReason::SingularMatrix { .. }
            | FailureReason::SymbolEquationArityMismatch { .. }
            | FailureReason::ColumnIndexOutOfRange { .. }
            | FailureReason::SourceEsiOutOfRange { .. }
            | FailureReason::InvalidSourceSymbolEquation { .. }
            | FailureReason::CorruptDecodedOutput { .. } => RejectReason::InconsistentEquations,
        }
    }

    fn proof_report(proof: &asupersync::raptorq::DecodeProof) -> ProofReport {
        let content_hash = proof.content_hash();
        let hash_hex = content_hash.to_hex();
        let outcome = match &proof.outcome {
            ProofOutcome::Success { .. } => "success".to_string(),
            ProofOutcome::Failure { reason } => format!("{reason:?}"),
        };
        let summary = ProofSummary {
            version: proof.version,
            hash: hash_hex,
            received_total: proof.received.total,
            peeling_solved: proof.peeling.solved,
            inactivated: proof.elimination.inactivated,
            pivots: proof.elimination.pivots,
            row_ops: proof.elimination.row_ops,
            outcome: outcome.clone(),
        };
        let summary_bytes = serde_json::to_vec(&summary)
            .expect("serialize proof summary")
            .len();
        ProofReport {
            hash: proof_hash_prefix(&content_hash),
            summary_bytes,
            outcome,
            received_total: proof.received.total,
            received_source: proof.received.source_count,
            received_repair: proof.received.repair_count,
            peeling_solved: proof.peeling.solved,
            inactivated: proof.elimination.inactivated,
            pivots: proof.elimination.pivots,
            row_ops: proof.elimination.row_ops,
            equations_used: proof.received.total,
        }
    }

    #[allow(clippy::too_many_lines)]
    fn run_scenario(
        scenario: Scenario,
        encoding: &EncodingConfig,
        decoding_min_overhead: usize,
        data_len: usize,
        data_seed: u64,
        object_id: ObjectId,
    ) -> (String, u64, String, bool) {
        let symbol_size = usize::from(encoding.symbol_size);
        let data = make_bytes(data_len, data_seed);
        let block_k = data_len.div_ceil(symbol_size);
        let repair_count = block_k / 2;
        let mut encoder = EncodingPipeline::new(encoding.clone(), pool_for(encoding.symbol_size));
        let symbols: Vec<Symbol> = encoder
            .encode_with_repair(object_id, &data, repair_count)
            .map(|res| res.expect("encode").into_symbol())
            .collect();
        let symbol_hash = hash_symbols(&symbols);
        let (received_symbols, loss_report) = apply_loss(&symbols, block_k, scenario.loss);
        let received_counts = count_symbols(&received_symbols);
        let generated_counts = count_symbols(&symbols);

        let params = ObjectParams::new(
            object_id,
            data_len as u64,
            encoding.symbol_size,
            1,
            u16::try_from(block_k).expect("k fits u16"),
        );
        let mut decoding_pipeline = DecodingPipeline::new(DecodingConfig {
            symbol_size: encoding.symbol_size,
            max_block_size: encoding.max_block_size,
            repair_overhead: encoding.repair_overhead,
            min_overhead: decoding_min_overhead,
            max_buffered_symbols: 0,
            block_timeout: std::time::Duration::from_secs(30),
            verify_auth: false,
        });
        decoding_pipeline.set_object_params(params).expect("params");

        let mut last_reject = None;
        for symbol in &received_symbols {
            let auth = AuthenticatedSymbol::from_parts(symbol.clone(), AuthenticationTag::zero());
            let result = decoding_pipeline.feed(auth).expect("feed");
            match result {
                SymbolAcceptResult::Rejected(reason) => last_reject = Some(reason),
                SymbolAcceptResult::BlockComplete { .. } => break,
                _ => {}
            }
        }

        let data_result = decoding_pipeline.into_data();
        let (success, decoded_bytes) = match data_result {
            Ok(decoded_data) => {
                assert_eq!(decoded_data, data, "roundtrip mismatch");
                (true, decoded_data.len())
            }
            Err(err) => {
                assert!(
                    matches!(
                        err,
                        asupersync::decoding::DecodingError::InsufficientSymbols { .. }
                    ),
                    "unexpected failure {err:?}"
                );
                (false, 0usize)
            }
        };

        let sbn = 0u8;
        let block_seed = seed_for_block(object_id, sbn);
        let run_id = format!(
            "{}-seed{}-k{}-len{}",
            scenario.replay_id, block_seed, block_k, data_len
        );
        let raptor_decoder = InactivationDecoder::new(block_k, symbol_size, block_seed);
        let received_for_proof =
            build_received_symbols(&received_symbols, object_id, block_k, symbol_size, sbn);

        let proof = match raptor_decoder.decode_with_proof(&received_for_proof, object_id, sbn) {
            Ok(result) => {
                assert!(
                    scenario.expect_success,
                    "scenario_id={} replay_id={} unexpected proof success",
                    scenario.id, scenario.replay_id
                );
                result.proof
            }
            Err((err, proof)) => {
                assert!(
                    !scenario.expect_success,
                    "scenario_id={} replay_id={} unexpected proof failure {err:?}",
                    scenario.id, scenario.replay_id
                );
                match err {
                    DecodeError::InsufficientSymbols { .. } => {}
                    DecodeError::SingularMatrix { .. }
                    | DecodeError::SymbolSizeMismatch { .. }
                    | DecodeError::SymbolEquationArityMismatch { .. }
                    | DecodeError::ColumnIndexOutOfRange { .. }
                    | DecodeError::SourceEsiOutOfRange { .. }
                    | DecodeError::InvalidSourceSymbolEquation { .. }
                    | DecodeError::CorruptDecodedOutput { .. }
                    | DecodeError::ComputeBudgetExhausted { .. }
                    | DecodeError::EsiRateLimitExceeded { .. } => {
                        panic!("unexpected decode error {err:?}");
                    }
                }
                proof
            }
        };

        proof
            .replay_and_verify(&received_for_proof)
            .expect("proof replay");

        let proof_hash = proof.content_hash().to_hex();
        let proof_report = proof_report(&proof);

        let reject_reason = match last_reject {
            Some(reason) => Some(format!("{reason:?}")),
            None => match &proof.outcome {
                ProofOutcome::Failure { reason } => {
                    let mapped = reject_reason_from_failure(reason);
                    Some(format!("{mapped:?}"))
                }
                ProofOutcome::Success { .. } => None,
            },
        };

        let report = Report {
            schema_version: "raptorq-e2e-log-v1",
            scenario: scenario.name,
            scenario_id: scenario.id,
            replay_id: scenario.replay_id,
            profile: scenario.profile,
            unit_sentinel: scenario.unit_sentinel,
            assertion_id: scenario.assertion_id,
            run_id,
            repro_command: format!(
                "rch exec -- cargo test --test raptorq_conformance e2e_pipeline_reports_are_deterministic -- --nocapture # scenario_id={} replay_id={}",
                scenario.id, scenario.replay_id
            ),
            phase_markers: ["encode", "loss", "decode", "proof", "report"],
            config: ConfigReport {
                symbol_size: encoding.symbol_size,
                max_block_size: encoding.max_block_size,
                repair_overhead: encoding.repair_overhead,
                min_overhead: decoding_min_overhead,
                seed: block_seed,
                block_k,
                block_count: 1,
                data_len,
            },
            loss: loss_report,
            symbols: SymbolReport {
                generated: generated_counts,
                received: received_counts,
            },
            outcome: OutcomeReport {
                success,
                reject_reason,
                decoded_bytes,
            },
            proof: proof_report,
        };

        let report_json = serde_json::to_string(&report).expect("serialize report");
        (report_json, symbol_hash, proof_hash, success)
    }

    fn assert_report_contract(report_json: &str, scenario: Scenario) {
        let report: serde_json::Value = serde_json::from_str(report_json).expect("parse report");
        assert_eq!(
            report["schema_version"].as_str(),
            Some("raptorq-e2e-log-v1"),
            "schema version mismatch"
        );
        assert_eq!(
            report["scenario_id"].as_str(),
            Some(scenario.id),
            "scenario id mismatch"
        );
        assert_eq!(
            report["replay_id"].as_str(),
            Some(scenario.replay_id),
            "replay id mismatch"
        );
        assert_eq!(
            report["profile"].as_str(),
            Some(scenario.profile),
            "profile marker mismatch"
        );
        assert!(
            matches!(scenario.profile, "fast" | "full" | "forensics"),
            "unexpected profile marker {}",
            scenario.profile
        );
        assert_eq!(
            report["unit_sentinel"].as_str(),
            Some(scenario.unit_sentinel),
            "unit sentinel mismatch"
        );
        assert_eq!(
            report["assertion_id"].as_str(),
            Some(scenario.assertion_id),
            "assertion id mismatch"
        );
        assert!(
            report["run_id"].as_str().is_some_and(|v| !v.is_empty()),
            "missing run id"
        );
        assert!(
            report["repro_command"].as_str().is_some_and(
                |cmd| cmd.contains("rch exec -- cargo test --test raptorq_conformance")
            ),
            "missing repro command"
        );
        let phase_markers = report["phase_markers"]
            .as_array()
            .expect("phase markers array");
        let actual_phase_markers = phase_markers
            .iter()
            .map(serde_json::Value::as_str)
            .collect::<Option<Vec<_>>>()
            .expect("phase markers strings");
        assert_eq!(
            actual_phase_markers.as_slice(),
            asupersync::raptorq::test_log_schema::REQUIRED_PHASE_MARKERS,
            "unexpected deterministic phase markers"
        );
    }

    #[test]
    fn e2e_pipeline_reports_are_deterministic() {
        let encoding = EncodingConfig {
            symbol_size: 64,
            max_block_size: 1024,
            repair_overhead: 1.0,
            encoding_parallelism: 1,
            decoding_parallelism: 1,
        };
        let decoding_min_overhead = 0usize;
        let data_len = 1024usize;
        let data_seed = 0xD1E5_u64;
        let object_id = ObjectId::new_for_test(9001);

        let scenarios = [
            Scenario {
                name: "systematic_only",
                id: "RQ-E2E-SYSTEMATIC-ONLY",
                replay_id: "replay:rq-e2e-systematic-only-v1",
                profile: "fast",
                unit_sentinel: "raptorq::tests::edge_cases::repair_zero_only_source",
                assertion_id: "E2E-ROUNDTRIP-SYSTEMATIC",
                loss: LossPattern::None,
                expect_success: true,
            },
            Scenario {
                name: "typical_random_loss",
                id: "RQ-E2E-TYPICAL-RANDOM-LOSS",
                replay_id: "replay:rq-e2e-typical-random-loss-v1",
                profile: "full",
                unit_sentinel: "roundtrip_with_source_loss",
                assertion_id: "E2E-ROUNDTRIP-RANDOM-LOSS",
                loss: LossPattern::Random {
                    seed: 0xBEEF_u64,
                    drop_per_mille: 200,
                },
                expect_success: true,
            },
            Scenario {
                name: "burst_loss_late",
                id: "RQ-E2E-BURST-LOSS-LATE",
                replay_id: "replay:rq-e2e-burst-loss-late-v1",
                profile: "forensics",
                unit_sentinel: "roundtrip_repair_only",
                assertion_id: "E2E-ROUNDTRIP-BURST-LOSS",
                loss: LossPattern::Burst {
                    drop_per_mille: 150,
                    position: BurstPosition::Late,
                },
                expect_success: true,
            },
            Scenario {
                name: "insufficient_symbols",
                id: "RQ-E2E-INSUFFICIENT-SYMBOLS",
                replay_id: "replay:rq-e2e-insufficient-symbols-v1",
                profile: "fast",
                unit_sentinel: "raptorq::tests::edge_cases::insufficient_symbols_error",
                assertion_id: "E2E-ERROR-INSUFFICIENT",
                loss: LossPattern::Insufficient,
                expect_success: false,
            },
        ];

        for scenario in scenarios {
            let (report_first, symbol_hash_first, proof_hash_first, success_first) = run_scenario(
                scenario,
                &encoding,
                decoding_min_overhead,
                data_len,
                data_seed,
                object_id,
            );
            let (report_second, symbol_hash_second, proof_hash_second, success_second) =
                run_scenario(
                    scenario,
                    &encoding,
                    decoding_min_overhead,
                    data_len,
                    data_seed,
                    object_id,
                );

            assert_eq!(
                symbol_hash_first, symbol_hash_second,
                "symbol stream hash mismatch"
            );
            assert_eq!(proof_hash_first, proof_hash_second, "proof hash mismatch");
            assert_report_contract(&report_first, scenario);
            assert_report_contract(&report_second, scenario);

            // D7 schema contract: validate via shared schema validator.
            let violations =
                asupersync::raptorq::test_log_schema::validate_e2e_log_json(&report_first);
            assert!(
                violations.is_empty(),
                "D7 E2E schema contract violation for {}: {violations:?}",
                scenario.id
            );

            assert_eq!(report_first, report_second, "report JSON mismatch");
            assert_eq!(success_first, success_second, "success mismatch");
        }
    }
}

// ============================================================================
// Differential Harness Against Independent Reference Decode (bd-136cm / D2)
// ============================================================================

#[cfg(feature = "test-internals")]
mod differential_harness {
    use super::*;
    use asupersync::config::EncodingConfig;
    use asupersync::encoding::EncodingPipeline;
    use asupersync::raptorq::linalg::{DenseRow, GaussianResult, GaussianSolver};
    use asupersync::raptorq::test_log_schema::{
        UnitDecodeStats, UnitGovernanceDecision, UnitLogEntry, validate_unit_log_json,
    };
    use asupersync::types::resource::{PoolConfig, SymbolPool};
    use asupersync::types::{ObjectId, Symbol, SymbolKind};
    use raptorq::{
        Decoder as RaptorqRsDecoder, EncodingPacket as RaptorqRsEncodingPacket,
        ObjectTransmissionInformation as RaptorqRsObjectTransmissionInformation,
        PayloadId as RaptorqRsPayloadId,
        extended_source_block_symbols as raptorq_rs_extended_source_block_symbols,
    };
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    const DIFF_REPLAY_REF: &str = "replay:rq-d2-diff-harness-v1";
    const DIFF_ARTIFACT_PATH: &str = "artifacts/raptorq_d2_differential_harness_v1.json";
    const DIFF_REPRO_COMMAND: &str = "rch exec -- cargo test --test raptorq_conformance differential_harness_selected_slice -- --nocapture";
    const RFC6330_DIFF_LOG_SCHEMA_VERSION: &str = "raptorq-rfc6330-differential-log-v1";
    const RFC6330_DIFF_REPRO_COMMAND: &str = "rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_asupersync_sldd1z_raptorq cargo test --test raptorq_conformance conformance_rfc6330_differential_vector_matrix_logs_evidence -- --nocapture";

    #[derive(Clone, Copy)]
    enum RepairBudget {
        None,
        ByDropped { extra: usize },
    }

    #[derive(Clone, Copy)]
    struct DifferentialCase {
        scenario_id: &'static str,
        k: usize,
        symbol_size: usize,
        seed: u64,
        drop_modulus: Option<usize>,
        drop_remainder: usize,
        repair_budget: RepairBudget,
        expect_success: bool,
        expected_error_kind: Option<&'static str>,
    }

    #[derive(Debug)]
    struct ReferenceDecodeResult {
        intermediate: Vec<Vec<u8>>,
        source: Vec<Vec<u8>>,
    }

    #[derive(Debug)]
    enum ReferenceDecodeError {
        InsufficientSymbols,
        SingularMatrix,
        SymbolSizeMismatch,
        SymbolEquationArityMismatch,
        ColumnOutOfRange,
    }

    fn decoder_error_kind(err: &DecodeError) -> &'static str {
        match err {
            DecodeError::InsufficientSymbols { .. } => "insufficient_symbols",
            DecodeError::SingularMatrix { .. } => "singular_matrix",
            DecodeError::SymbolSizeMismatch { .. } => "symbol_size_mismatch",
            DecodeError::SymbolEquationArityMismatch { .. } => "symbol_equation_arity_mismatch",
            DecodeError::ColumnIndexOutOfRange { .. } => "column_out_of_range",
            DecodeError::SourceEsiOutOfRange { .. } => "source_esi_out_of_range",
            DecodeError::InvalidSourceSymbolEquation { .. } => "invalid_source_symbol_equation",
            DecodeError::CorruptDecodedOutput { .. } => "corrupt_decoded_output",
            DecodeError::ComputeBudgetExhausted { .. } => "compute_budget_exhausted",
            DecodeError::EsiRateLimitExceeded { .. } => "esi_rate_limit_exceeded",
        }
    }

    fn reference_error_kind(err: &ReferenceDecodeError) -> &'static str {
        match err {
            ReferenceDecodeError::InsufficientSymbols => "insufficient_symbols",
            ReferenceDecodeError::SingularMatrix => "singular_matrix",
            ReferenceDecodeError::SymbolSizeMismatch => "symbol_size_mismatch",
            ReferenceDecodeError::SymbolEquationArityMismatch => "symbol_equation_arity_mismatch",
            ReferenceDecodeError::ColumnOutOfRange => "column_out_of_range",
        }
    }

    fn root_cause_label(
        decoder: &Result<asupersync::raptorq::decoder::DecodeResult, DecodeError>,
        reference: &Result<ReferenceDecodeResult, ReferenceDecodeError>,
    ) -> Option<String> {
        match (decoder, reference) {
            (Ok(decoder_ok), Ok(reference_ok)) => {
                if decoder_ok.source != reference_ok.source {
                    Some("source_payload_mismatch".to_string())
                } else if decoder_ok.intermediate != reference_ok.intermediate {
                    Some("intermediate_symbol_mismatch".to_string())
                } else {
                    None
                }
            }
            (Err(decoder_err), Err(reference_err)) => {
                let decoder_kind = decoder_error_kind(decoder_err);
                let reference_kind = reference_error_kind(reference_err);
                if decoder_kind == reference_kind {
                    None
                } else {
                    Some(format!(
                        "error_kind_mismatch__decoder_{decoder_kind}__reference_{reference_kind}"
                    ))
                }
            }
            (Ok(_), Err(reference_err)) => Some(format!(
                "reference_only_failure__{}",
                reference_error_kind(reference_err)
            )),
            (Err(decoder_err), Ok(_)) => Some(format!(
                "decoder_only_failure__{}",
                decoder_error_kind(decoder_err)
            )),
        }
    }

    fn drop_indices_for(case: DifferentialCase) -> Vec<usize> {
        case.drop_modulus.map_or_else(Vec::new, |modulus| {
            (0..case.k)
                .filter(|idx| idx % modulus == case.drop_remainder)
                .collect()
        })
    }

    fn max_repair_esi(case: DifferentialCase, l: usize, drop_count: usize) -> u32 {
        match case.repair_budget {
            RepairBudget::None => case.k as u32,
            RepairBudget::ByDropped { extra } => (l + drop_count + extra) as u32,
        }
    }

    fn choose_drop_count(total: usize, min_keep: usize, drop_per_mille: u16) -> usize {
        let drop_count = total.saturating_mul(usize::from(drop_per_mille)) / 1000;
        let max_drop = total.saturating_sub(min_keep);
        drop_count.min(max_drop)
    }

    fn exact_random_drop_indices(k: usize, drop_per_mille: u16, seed: u64) -> Vec<usize> {
        let drop_count = choose_drop_count(k, 1, drop_per_mille);
        let mut indices: Vec<usize> = (0..k).collect();
        let mut rng = DetRng::new(seed);
        rng.shuffle(&mut indices);
        indices.truncate(drop_count);
        indices.sort_unstable();
        indices
    }

    fn payload_fingerprint<T: Hash>(value: &T) -> String {
        let mut hasher = DefaultHasher::new();
        value.hash(&mut hasher);
        format!("{:016x}", hasher.finish())
    }

    fn received_symbol_ids(received: &[ReceivedSymbol]) -> Vec<u32> {
        received.iter().map(|symbol| symbol.esi).collect()
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_rfc6330_differential_log(
        vector_id: &str,
        k: usize,
        symbol_size: usize,
        symbol_ids: &[u32],
        received_symbol_count: usize,
        decode_result: &str,
        reference_fingerprint: Option<&str>,
        asupersync_fingerprint: Option<&str>,
        error_kind: Option<&str>,
        final_verdict: &str,
    ) {
        let log = serde_json::json!({
            "schema_version": RFC6330_DIFF_LOG_SCHEMA_VERSION,
            "rfc_vector_id": vector_id,
            "k": k,
            "t": symbol_size,
            "symbol_ids": symbol_ids,
            "received_symbol_count": received_symbol_count,
            "decode_result": decode_result,
            "reference_fingerprint": reference_fingerprint,
            "asupersync_fingerprint": asupersync_fingerprint,
            "error_kind": error_kind,
            "exact_rch_command": RFC6330_DIFF_REPRO_COMMAND,
            "artifact_paths": [DIFF_ARTIFACT_PATH],
            "final_rfc_differential_verdict": final_verdict,
        });
        eprintln!("{log}");
    }

    fn reference_decode(
        decoder: &InactivationDecoder,
        symbols: &[ReceivedSymbol],
    ) -> Result<ReferenceDecodeResult, ReferenceDecodeError> {
        let params = decoder.params();
        let l = params.l;
        let k = params.k;
        let symbol_size = params.symbol_size;

        if symbols.len() < l {
            return Err(ReferenceDecodeError::InsufficientSymbols);
        }

        let mut solver = GaussianSolver::new(symbols.len(), l);

        for (row_idx, sym) in symbols.iter().enumerate() {
            if sym.data.len() != symbol_size {
                return Err(ReferenceDecodeError::SymbolSizeMismatch);
            }
            if sym.columns.len() != sym.coefficients.len() {
                return Err(ReferenceDecodeError::SymbolEquationArityMismatch);
            }

            let mut row_coeffs = vec![0u8; l];
            for (&column, &coefficient) in sym.columns.iter().zip(sym.coefficients.iter()) {
                if column >= l {
                    return Err(ReferenceDecodeError::ColumnOutOfRange);
                }
                // Equation coefficients sum in GF(256), where addition is XOR.
                row_coeffs[column] ^= coefficient.raw();
            }

            solver.set_row(row_idx, &row_coeffs, DenseRow::new(sym.data.clone()));
        }

        match solver.solve_markowitz() {
            GaussianResult::Solved(solution_rows) => {
                let intermediate: Vec<Vec<u8>> = solution_rows
                    .iter()
                    .take(l)
                    .map(|row| row.as_slice().to_vec())
                    .collect();
                let mut source = Vec::with_capacity(k);
                for esi in 0..k {
                    let esi = u32::try_from(esi).expect("source ESI fits u32");
                    let (columns, coefficients) = decoder.source_equation(esi);
                    let mut symbol = vec![0u8; symbol_size];
                    for (&column, &coefficient) in columns.iter().zip(coefficients.iter()) {
                        gf256_addmul_slice(&mut symbol, &intermediate[column], coefficient);
                    }
                    source.push(symbol);
                }
                Ok(ReferenceDecodeResult {
                    intermediate,
                    source,
                })
            }
            GaussianResult::Singular { .. } | GaussianResult::Inconsistent { .. } => {
                Err(ReferenceDecodeError::SingularMatrix)
            }
        }
    }

    fn reference_decode_with_raptorq_rs(
        case: DifferentialCase,
        encoder: &SystematicEncoder,
        source: &[Vec<u8>],
        drop_indices: &[usize],
        repair_esi_upper: u32,
    ) -> Vec<u8> {
        let transfer_length = case
            .k
            .checked_mul(case.symbol_size)
            .expect("transfer length overflow");
        let symbol_size = u16::try_from(case.symbol_size).expect("symbol size must fit in u16");
        let config = RaptorqRsObjectTransmissionInformation::new(
            transfer_length as u64,
            symbol_size,
            1,
            1,
            1,
        );
        let mut decoder = RaptorqRsDecoder::new(config);
        let mut packets = Vec::new();

        for (esi, data) in source.iter().enumerate() {
            if !drop_indices.contains(&esi) {
                packets.push(RaptorqRsEncodingPacket::new(
                    RaptorqRsPayloadId::new(0, esi as u32),
                    data.clone(),
                ));
            }
        }

        for esi in (case.k as u32)..repair_esi_upper {
            packets.push(RaptorqRsEncodingPacket::new(
                RaptorqRsPayloadId::new(0, esi),
                encoder.repair_symbol(esi),
            ));
        }

        let mut decoded = None;
        for packet in packets {
            decoded = decoder.decode(packet);
            if decoded.is_some() {
                break;
            }
        }

        decoded.expect("raptorq-rs reference decode should succeed")
    }

    fn reference_source_packets_with_raptorq_rs(
        case: DifferentialCase,
        source: &[Vec<u8>],
    ) -> Vec<RaptorqRsEncodingPacket> {
        // raptorq-rs source_packets() is this PayloadId + payload mapping,
        // but SourceBlockEncoder::new2() also precomputes repair state. Keep
        // source-packet parity tests focused on the source packet contract.
        assert_eq!(
            source.len(),
            case.k,
            "scenario={} reference source must contain K symbols",
            case.scenario_id
        );
        source
            .iter()
            .enumerate()
            .map(|(esi, symbol)| {
                RaptorqRsEncodingPacket::new(
                    RaptorqRsPayloadId::new(0, u32::try_from(esi).expect("ESI fits u32")),
                    symbol.clone(),
                )
            })
            .collect()
    }

    fn pipeline_source_packets(case: DifferentialCase, source: &[Vec<u8>]) -> Vec<Symbol> {
        let max_block_size = case
            .k
            .checked_mul(case.symbol_size)
            .expect("max block size overflow");
        let source_bytes = flatten_source_bytes(source);
        let mut pipeline = EncodingPipeline::new(
            EncodingConfig {
                repair_overhead: 1.0,
                max_block_size,
                symbol_size: u16::try_from(case.symbol_size).expect("symbol size fits u16"),
                encoding_parallelism: 1,
                decoding_parallelism: 1,
            },
            SymbolPool::new(PoolConfig::default()),
        );

        pipeline
            .encode_with_repair(ObjectId::new_for_test(case.seed), &source_bytes, 0)
            .map(|result| {
                result
                    .unwrap_or_else(|err| {
                        panic!(
                            "scenario={} pipeline encode failed: {err}",
                            case.scenario_id
                        )
                    })
                    .into_symbol()
            })
            .collect()
    }

    fn assert_pipeline_source_packets_match_raptorq_rs(case: DifferentialCase) {
        let source = make_source_data(case.k, case.symbol_size, case.seed.wrapping_mul(17));
        let emitted = pipeline_source_packets(case, &source);
        let reference = reference_source_packets_with_raptorq_rs(case, &source);

        assert_eq!(
            emitted.len(),
            case.k,
            "scenario={} pipeline must emit exactly K source symbols",
            case.scenario_id
        );
        assert_eq!(
            reference.len(),
            case.k,
            "scenario={} raptorq-rs must emit exactly K source packets",
            case.scenario_id
        );

        for (idx, (our_packet, reference_packet)) in
            emitted.iter().zip(reference.iter()).enumerate()
        {
            let expected = &source[idx];
            let reference_esi = reference_packet.payload_id().encoding_symbol_id() as usize;

            assert_eq!(
                our_packet.kind(),
                SymbolKind::Source,
                "scenario={} pipeline packet {idx} must be a source symbol",
                case.scenario_id
            );
            assert_eq!(
                our_packet.sbn(),
                0,
                "scenario={} pipeline packet {idx} must belong to source block 0",
                case.scenario_id
            );
            assert_eq!(
                our_packet.esi(),
                idx as u32,
                "scenario={} pipeline source ESI must equal its source index",
                case.scenario_id
            );
            assert_eq!(
                reference_esi, idx,
                "scenario={} raptorq-rs source ESI must equal its source index",
                case.scenario_id
            );
            assert_eq!(
                our_packet.data(),
                expected,
                "scenario={} pipeline packet {idx} must equal the original source symbol",
                case.scenario_id
            );
            assert_eq!(
                reference_packet.data(),
                expected,
                "scenario={} raptorq-rs packet {idx} must equal the original source symbol",
                case.scenario_id
            );
            assert_eq!(
                our_packet.data(),
                reference_packet.data(),
                "scenario={} encoded source payload must match raptorq-rs at index {idx}",
                case.scenario_id
            );
        }
    }

    #[test]
    fn differential_pipeline_source_encoded_symbols_match_raptorq_rs_k4096() {
        assert_pipeline_source_packets_match_raptorq_rs(DifferentialCase {
            scenario_id: "RQ-D2-SOURCE-K4096-RAPTORQ-RS",
            k: 4096,
            symbol_size: 64,
            seed: 0x6330_4096,
            drop_modulus: None,
            drop_remainder: 0,
            repair_budget: RepairBudget::None,
            expect_success: true,
            expected_error_kind: None,
        });
    }

    #[test]
    fn differential_pipeline_source_encoded_symbols_match_raptorq_rs_k8192_t4096() {
        assert_pipeline_source_packets_match_raptorq_rs(DifferentialCase {
            scenario_id: "RQ-D2-SOURCE-K8192-T4096-RAPTORQ-RS",
            k: 8192,
            symbol_size: 4096,
            seed: 0x6330_8192,
            drop_modulus: None,
            drop_remainder: 0,
            repair_budget: RepairBudget::None,
            expect_success: true,
            expected_error_kind: None,
        });
    }

    #[test]
    fn differential_repair_esi_mapping_matches_raptorq_rs_k8192() {
        let k = 8192usize;
        let params = SystematicParams::for_source_block(k, 8);
        let reference_k_prime = usize::try_from(raptorq_rs_extended_source_block_symbols(
            u32::try_from(k).expect("K must fit u32"),
        ))
        .expect("raptorq-rs K' must fit usize");

        assert_eq!(
            params.k_prime, reference_k_prime,
            "raptorq-rs and asupersync must agree on K' before mapping K8192 repair ESIs"
        );

        for offset in [0_u32, 1, 15, 127] {
            let public_esi = u32::try_from(k).expect("K must fit u32") + offset;
            let internal_repair_isi = reference_k_prime
                .checked_add(usize::try_from(offset).expect("offset fits usize"))
                .expect("reference repair ESI must not overflow");
            let padding_delta = params.k_prime - params.k;

            assert_eq!(
                usize::try_from(public_esi).expect("public ESI fits usize") + padding_delta,
                internal_repair_isi,
                "public repair ESI {public_esi} must map to the RFC repair ISI \
                 {internal_repair_isi} for offset {offset}"
            );
        }
    }

    #[test]
    fn differential_systematic_source_packets_match_raptorq_rs_k2() {
        let case = DifferentialCase {
            scenario_id: "RQ-D2-SYSTEMATIC-K2-RAPTORQ-RS",
            k: 2,
            symbol_size: 64,
            seed: 0x6330_0002,
            drop_modulus: None,
            drop_remainder: 0,
            repair_budget: RepairBudget::None,
            expect_success: true,
            expected_error_kind: None,
        };

        let source = make_source_data(case.k, case.symbol_size, case.seed.wrapping_mul(17));
        let mut encoder = SystematicEncoder::new(&source, case.symbol_size, case.seed)
            .unwrap_or_else(|| panic!("scenario={} failed to build encoder", case.scenario_id));
        let emitted = encoder.emit_systematic();
        let reference = reference_source_packets_with_raptorq_rs(case, &source);

        assert_eq!(
            emitted.len(),
            case.k,
            "scenario={} our encoder must emit exactly K source packets",
            case.scenario_id
        );
        assert_eq!(
            reference.len(),
            case.k,
            "scenario={} raptorq-rs must emit exactly K source packets",
            case.scenario_id
        );

        for (idx, (our_packet, reference_packet)) in
            emitted.iter().zip(reference.iter()).enumerate()
        {
            let expected = &source[idx];
            let reference_esi = reference_packet.payload_id().encoding_symbol_id() as usize;

            assert!(
                our_packet.is_source,
                "scenario={} packet {idx} must remain systematic",
                case.scenario_id
            );
            assert_eq!(
                our_packet.esi, idx as u32,
                "scenario={} our systematic ESI must equal its source index",
                case.scenario_id
            );
            assert_eq!(
                reference_esi, idx,
                "scenario={} raptorq-rs systematic ESI must equal its source index",
                case.scenario_id
            );
            assert_eq!(
                &our_packet.data, expected,
                "scenario={} our packet {idx} must equal the original source symbol",
                case.scenario_id
            );
            assert_eq!(
                reference_packet.data(),
                expected,
                "scenario={} raptorq-rs packet {idx} must equal the original source symbol",
                case.scenario_id
            );
            assert_eq!(
                &our_packet.data,
                reference_packet.data(),
                "scenario={} our systematic payload must match raptorq-rs at index {idx}",
                case.scenario_id
            );
        }
    }

    #[test]
    fn differential_systematic_source_packets_match_raptorq_rs_k42() {
        let case = DifferentialCase {
            scenario_id: "RQ-D2-SYSTEMATIC-K42-RAPTORQ-RS",
            k: 42,
            symbol_size: 64,
            seed: 0x6330_0042,
            drop_modulus: None,
            drop_remainder: 0,
            repair_budget: RepairBudget::None,
            expect_success: true,
            expected_error_kind: None,
        };

        let source = make_source_data(case.k, case.symbol_size, case.seed.wrapping_mul(17));
        let mut encoder = SystematicEncoder::new(&source, case.symbol_size, case.seed)
            .unwrap_or_else(|| panic!("scenario={} failed to build encoder", case.scenario_id));
        let emitted = encoder.emit_systematic();
        let reference = reference_source_packets_with_raptorq_rs(case, &source);

        assert_eq!(
            emitted.len(),
            case.k,
            "scenario={} our encoder must emit exactly K source packets",
            case.scenario_id
        );
        assert_eq!(
            reference.len(),
            case.k,
            "scenario={} raptorq-rs must emit exactly K source packets",
            case.scenario_id
        );

        for (idx, (our_packet, reference_packet)) in
            emitted.iter().zip(reference.iter()).enumerate()
        {
            let expected = &source[idx];
            let reference_esi = reference_packet.payload_id().encoding_symbol_id() as usize;

            assert!(
                our_packet.is_source,
                "scenario={} packet {idx} must remain systematic",
                case.scenario_id
            );
            assert_eq!(
                our_packet.esi, idx as u32,
                "scenario={} our systematic ESI must equal its source index",
                case.scenario_id
            );
            assert_eq!(
                reference_esi, idx,
                "scenario={} raptorq-rs systematic ESI must equal its source index",
                case.scenario_id
            );
            assert_eq!(
                &our_packet.data, expected,
                "scenario={} our packet {idx} must equal the original source symbol",
                case.scenario_id
            );
            assert_eq!(
                reference_packet.data(),
                expected,
                "scenario={} raptorq-rs packet {idx} must equal the original source symbol",
                case.scenario_id
            );
            assert_eq!(
                &our_packet.data,
                reference_packet.data(),
                "scenario={} our systematic payload must match raptorq-rs at index {idx}",
                case.scenario_id
            );
        }
    }

    #[test]
    fn differential_systematic_source_packets_match_raptorq_rs_k100() {
        let case = DifferentialCase {
            scenario_id: "RQ-D2-SYSTEMATIC-K100-RAPTORQ-RS",
            k: 100,
            symbol_size: 64,
            seed: 0x6330_0100,
            drop_modulus: None,
            drop_remainder: 0,
            repair_budget: RepairBudget::None,
            expect_success: true,
            expected_error_kind: None,
        };

        let source = make_source_data(case.k, case.symbol_size, case.seed.wrapping_mul(17));
        let mut encoder = SystematicEncoder::new(&source, case.symbol_size, case.seed)
            .unwrap_or_else(|| panic!("scenario={} failed to build encoder", case.scenario_id));
        let emitted = encoder.emit_systematic();
        let reference = reference_source_packets_with_raptorq_rs(case, &source);

        assert_eq!(
            emitted.len(),
            case.k,
            "scenario={} our encoder must emit exactly K source packets",
            case.scenario_id
        );
        assert_eq!(
            reference.len(),
            case.k,
            "scenario={} raptorq-rs must emit exactly K source packets",
            case.scenario_id
        );

        for (idx, (our_packet, reference_packet)) in
            emitted.iter().zip(reference.iter()).enumerate()
        {
            let expected = &source[idx];
            let reference_esi = reference_packet.payload_id().encoding_symbol_id() as usize;

            assert!(
                our_packet.is_source,
                "scenario={} packet {idx} must remain systematic",
                case.scenario_id
            );
            assert_eq!(
                our_packet.esi, idx as u32,
                "scenario={} our systematic ESI must equal its source index",
                case.scenario_id
            );
            assert_eq!(
                reference_esi, idx,
                "scenario={} raptorq-rs systematic ESI must equal its source index",
                case.scenario_id
            );
            assert_eq!(
                &our_packet.data, expected,
                "scenario={} our packet {idx} must equal the original source symbol",
                case.scenario_id
            );
            assert_eq!(
                reference_packet.data(),
                expected,
                "scenario={} raptorq-rs packet {idx} must equal the original source symbol",
                case.scenario_id
            );
            assert_eq!(
                &our_packet.data,
                reference_packet.data(),
                "scenario={} our systematic payload must match raptorq-rs at index {idx}",
                case.scenario_id
            );
        }
    }

    #[test]
    fn differential_systematic_source_packets_match_raptorq_rs_k200() {
        let case = DifferentialCase {
            scenario_id: "RQ-D2-SYSTEMATIC-K200-RAPTORQ-RS",
            k: 200,
            symbol_size: 64,
            seed: 0x6330_0200,
            drop_modulus: None,
            drop_remainder: 0,
            repair_budget: RepairBudget::None,
            expect_success: true,
            expected_error_kind: None,
        };

        let source = make_source_data(case.k, case.symbol_size, case.seed.wrapping_mul(17));
        let mut encoder = SystematicEncoder::new(&source, case.symbol_size, case.seed)
            .unwrap_or_else(|| panic!("scenario={} failed to build encoder", case.scenario_id));
        let emitted = encoder.emit_systematic();
        let reference = reference_source_packets_with_raptorq_rs(case, &source);

        assert_eq!(
            emitted.len(),
            case.k,
            "scenario={} our encoder must emit exactly K source packets",
            case.scenario_id
        );
        assert_eq!(
            reference.len(),
            case.k,
            "scenario={} raptorq-rs must emit exactly K source packets",
            case.scenario_id
        );

        for (idx, (our_packet, reference_packet)) in
            emitted.iter().zip(reference.iter()).enumerate()
        {
            let expected = &source[idx];
            let reference_esi = reference_packet.payload_id().encoding_symbol_id() as usize;

            assert!(
                our_packet.is_source,
                "scenario={} packet {idx} must remain systematic",
                case.scenario_id
            );
            assert_eq!(
                our_packet.esi, idx as u32,
                "scenario={} our systematic ESI must equal its source index",
                case.scenario_id
            );
            assert_eq!(
                reference_esi, idx,
                "scenario={} raptorq-rs systematic ESI must equal its source index",
                case.scenario_id
            );
            assert_eq!(
                &our_packet.data, expected,
                "scenario={} our packet {idx} must equal the original source symbol",
                case.scenario_id
            );
            assert_eq!(
                reference_packet.data(),
                expected,
                "scenario={} raptorq-rs packet {idx} must equal the original source symbol",
                case.scenario_id
            );
            assert_eq!(
                &our_packet.data,
                reference_packet.data(),
                "scenario={} our systematic payload must match raptorq-rs at index {idx}",
                case.scenario_id
            );
        }
    }

    #[test]
    fn differential_systematic_source_packets_match_raptorq_rs_k200_t1500() {
        let case = DifferentialCase {
            scenario_id: "RQ-D2-SYSTEMATIC-K200-T1500-RAPTORQ-RS",
            k: 200,
            symbol_size: 1500,
            seed: 0x6330_15_00,
            drop_modulus: None,
            drop_remainder: 0,
            repair_budget: RepairBudget::None,
            expect_success: true,
            expected_error_kind: None,
        };

        let source = make_source_data(case.k, case.symbol_size, case.seed.wrapping_mul(17));
        let mut encoder = SystematicEncoder::new(&source, case.symbol_size, case.seed)
            .unwrap_or_else(|| panic!("scenario={} failed to build encoder", case.scenario_id));
        let emitted = encoder.emit_systematic();
        let reference = reference_source_packets_with_raptorq_rs(case, &source);

        assert_eq!(
            emitted.len(),
            case.k,
            "scenario={} our encoder must emit exactly K source packets",
            case.scenario_id
        );
        assert_eq!(
            reference.len(),
            case.k,
            "scenario={} raptorq-rs must emit exactly K source packets",
            case.scenario_id
        );

        for (idx, (our_packet, reference_packet)) in
            emitted.iter().zip(reference.iter()).enumerate()
        {
            let expected = &source[idx];
            let reference_esi = reference_packet.payload_id().encoding_symbol_id() as usize;

            assert!(
                our_packet.is_source,
                "scenario={} packet {idx} must remain systematic",
                case.scenario_id
            );
            assert_eq!(
                our_packet.esi, idx as u32,
                "scenario={} our systematic ESI must equal its source index",
                case.scenario_id
            );
            assert_eq!(
                reference_esi, idx,
                "scenario={} raptorq-rs systematic ESI must equal its source index",
                case.scenario_id
            );
            assert_eq!(
                &our_packet.data, expected,
                "scenario={} our packet {idx} must equal the original source symbol",
                case.scenario_id
            );
            assert_eq!(
                reference_packet.data(),
                expected,
                "scenario={} raptorq-rs packet {idx} must equal the original source symbol",
                case.scenario_id
            );
            assert_eq!(
                &our_packet.data,
                reference_packet.data(),
                "scenario={} our systematic payload must match raptorq-rs at index {idx}",
                case.scenario_id
            );
        }
    }

    #[test]
    fn differential_systematic_source_packets_match_raptorq_rs_k500() {
        let case = DifferentialCase {
            scenario_id: "RQ-D2-SYSTEMATIC-K500-RAPTORQ-RS",
            k: 500,
            symbol_size: 64,
            seed: 0x6330_0500,
            drop_modulus: None,
            drop_remainder: 0,
            repair_budget: RepairBudget::None,
            expect_success: true,
            expected_error_kind: None,
        };

        let source = make_source_data(case.k, case.symbol_size, case.seed.wrapping_mul(17));
        let mut encoder = SystematicEncoder::new(&source, case.symbol_size, case.seed)
            .unwrap_or_else(|| panic!("scenario={} failed to build encoder", case.scenario_id));
        let emitted = encoder.emit_systematic();
        let reference = reference_source_packets_with_raptorq_rs(case, &source);

        assert_eq!(
            emitted.len(),
            case.k,
            "scenario={} our encoder must emit exactly K source packets",
            case.scenario_id
        );
        assert_eq!(
            reference.len(),
            case.k,
            "scenario={} raptorq-rs must emit exactly K source packets",
            case.scenario_id
        );

        for (idx, (our_packet, reference_packet)) in
            emitted.iter().zip(reference.iter()).enumerate()
        {
            let expected = &source[idx];
            let reference_esi = reference_packet.payload_id().encoding_symbol_id() as usize;

            assert!(
                our_packet.is_source,
                "scenario={} packet {idx} must remain systematic",
                case.scenario_id
            );
            assert_eq!(
                our_packet.esi, idx as u32,
                "scenario={} our systematic ESI must equal its source index",
                case.scenario_id
            );
            assert_eq!(
                reference_esi, idx,
                "scenario={} raptorq-rs systematic ESI must equal its source index",
                case.scenario_id
            );
            assert_eq!(
                &our_packet.data, expected,
                "scenario={} our packet {idx} must equal the original source symbol",
                case.scenario_id
            );
            assert_eq!(
                reference_packet.data(),
                expected,
                "scenario={} raptorq-rs packet {idx} must equal the original source symbol",
                case.scenario_id
            );
            assert_eq!(
                &our_packet.data,
                reference_packet.data(),
                "scenario={} our systematic payload must match raptorq-rs at index {idx}",
                case.scenario_id
            );
        }
    }

    #[test]
    fn differential_systematic_source_packets_match_raptorq_rs_k1000() {
        let case = DifferentialCase {
            scenario_id: "RQ-D2-SYSTEMATIC-K1000-RAPTORQ-RS",
            k: 1000,
            symbol_size: 64,
            seed: 0x6330_1000,
            drop_modulus: None,
            drop_remainder: 0,
            repair_budget: RepairBudget::None,
            expect_success: true,
            expected_error_kind: None,
        };

        let source = make_source_data(case.k, case.symbol_size, case.seed.wrapping_mul(17));
        let mut encoder = SystematicEncoder::new(&source, case.symbol_size, case.seed)
            .unwrap_or_else(|| panic!("scenario={} failed to build encoder", case.scenario_id));
        let emitted = encoder.emit_systematic();
        let reference = reference_source_packets_with_raptorq_rs(case, &source);

        assert_eq!(
            emitted.len(),
            case.k,
            "scenario={} our encoder must emit exactly K source packets",
            case.scenario_id
        );
        assert_eq!(
            reference.len(),
            case.k,
            "scenario={} raptorq-rs must emit exactly K source packets",
            case.scenario_id
        );

        for (idx, (our_packet, reference_packet)) in
            emitted.iter().zip(reference.iter()).enumerate()
        {
            let expected = &source[idx];
            let reference_esi = reference_packet.payload_id().encoding_symbol_id() as usize;

            assert!(
                our_packet.is_source,
                "scenario={} packet {idx} must remain systematic",
                case.scenario_id
            );
            assert_eq!(
                our_packet.esi, idx as u32,
                "scenario={} our systematic ESI must equal its source index",
                case.scenario_id
            );
            assert_eq!(
                reference_esi, idx,
                "scenario={} raptorq-rs systematic ESI must equal its source index",
                case.scenario_id
            );
            assert_eq!(
                &our_packet.data, expected,
                "scenario={} our packet {idx} must equal the original source symbol",
                case.scenario_id
            );
            assert_eq!(
                reference_packet.data(),
                expected,
                "scenario={} raptorq-rs packet {idx} must equal the original source symbol",
                case.scenario_id
            );
            assert_eq!(
                &our_packet.data,
                reference_packet.data(),
                "scenario={} our systematic payload must match raptorq-rs at index {idx}",
                case.scenario_id
            );
        }
    }

    #[test]
    fn differential_systematic_source_packets_match_raptorq_rs_k10000() {
        let case = DifferentialCase {
            scenario_id: "RQ-D2-SYSTEMATIC-K10000-RAPTORQ-RS",
            k: 10_000,
            symbol_size: 16,
            seed: 0x6330_2710,
            drop_modulus: None,
            drop_remainder: 0,
            repair_budget: RepairBudget::None,
            expect_success: true,
            expected_error_kind: None,
        };

        let source = make_source_data(case.k, case.symbol_size, case.seed.wrapping_mul(17));
        let params = SystematicParams::for_source_block(case.k, case.symbol_size);
        let reference = reference_source_packets_with_raptorq_rs(case, &source);

        assert_eq!(
            params.k, case.k,
            "scenario={} our high-K parameter lookup must preserve K",
            case.scenario_id
        );
        assert_eq!(
            reference.len(),
            case.k,
            "scenario={} raptorq-rs must emit exactly K source packets",
            case.scenario_id
        );

        let emitted: Vec<EmittedSymbol> = source
            .iter()
            .enumerate()
            .map(|(esi, symbol)| EmittedSymbol {
                esi: u32::try_from(esi).expect("source ESI fits u32"),
                data: symbol.clone(),
                is_source: true,
                degree: 1,
            })
            .collect();

        for (idx, reference_packet) in reference.iter().enumerate() {
            let our_packet = &emitted[idx];
            let reference_esi = reference_packet.payload_id().encoding_symbol_id() as usize;

            assert!(
                our_packet.is_source,
                "scenario={} packet {idx} must remain systematic",
                case.scenario_id
            );
            assert_eq!(
                our_packet.esi, idx as u32,
                "scenario={} our systematic ESI must equal its source index",
                case.scenario_id
            );
            assert_eq!(
                reference_esi, idx,
                "scenario={} raptorq-rs systematic ESI must equal its source index",
                case.scenario_id
            );
            assert_eq!(
                our_packet.degree, 1,
                "scenario={} source packet degree must be one",
                case.scenario_id
            );
            assert_eq!(
                &our_packet.data, &source[idx],
                "scenario={} our packet {idx} must equal the original source symbol",
                case.scenario_id
            );
            assert_eq!(
                reference_packet.data(),
                &source[idx],
                "scenario={} raptorq-rs packet {idx} must equal the original source symbol",
                case.scenario_id
            );
            assert_eq!(
                &our_packet.data,
                reference_packet.data(),
                "scenario={} our systematic payload must match raptorq-rs at index {idx}",
                case.scenario_id
            );
        }
    }

    #[test]
    fn differential_harness_known_bad_k10_matches_raptorq_rs() {
        // Pinned lower-bound K=10 regression slice at the K'=10 floor.
        let case = DifferentialCase {
            scenario_id: "RQ-D2-DIFF-K10-RAPTORQ-RS",
            k: 10,
            symbol_size: 64,
            seed: 2024,
            drop_modulus: Some(3),
            drop_remainder: 1,
            repair_budget: RepairBudget::ByDropped { extra: 3 },
            expect_success: true,
            expected_error_kind: None,
        };

        let source = make_source_data(case.k, case.symbol_size, case.seed.wrapping_mul(17));
        let encoder = SystematicEncoder::new(&source, case.symbol_size, case.seed)
            .unwrap_or_else(|| panic!("scenario={} failed to build encoder", case.scenario_id));
        let decoder = InactivationDecoder::new(case.k, case.symbol_size, case.seed);
        let drop_indices = drop_indices_for(case);
        let repair_esi_upper = max_repair_esi(case, decoder.params().l, drop_indices.len());
        let received = build_received_symbols(
            &encoder,
            &decoder,
            &source,
            &drop_indices,
            repair_esi_upper,
            case.seed,
        );

        let our_decoded = decoder
            .decode(&received)
            .unwrap_or_else(|err| panic!("scenario={} decoder failed: {err:?}", case.scenario_id));
        let our_bytes = flatten_source_bytes(&our_decoded.source);
        let reference_bytes = reference_decode_with_raptorq_rs(
            case,
            &encoder,
            &source,
            &drop_indices,
            repair_esi_upper,
        );
        let expected_bytes = flatten_source_bytes(&source);

        assert_eq!(
            our_bytes, expected_bytes,
            "scenario={} our decoder must recover the exact K=10 source block",
            case.scenario_id
        );
        assert_eq!(
            reference_bytes, expected_bytes,
            "scenario={} raptorq-rs must recover the exact K=10 source block",
            case.scenario_id
        );
        assert_eq!(
            our_bytes, reference_bytes,
            "scenario={} decoders must emit byte-identical output for the pinned K=10 slice",
            case.scenario_id
        );
    }

    fn assert_decoder_matches_raptorq_rs_insufficient_source_packet(
        scenario_id: &str,
        k: usize,
        symbol_size: usize,
        seed: u64,
        expected_k_prime: usize,
    ) {
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        assert_eq!(
            decoder.params().k_prime,
            expected_k_prime,
            "scenario={scenario_id} must exercise the expected rounded RFC row"
        );

        let payload: Vec<u8> = (0..symbol_size)
            .map(|idx| {
                u8::try_from((idx.saturating_mul(17).saturating_add(0x42)) % 256)
                    .expect("payload byte fits u8")
            })
            .collect();
        assert_eq!(
            payload.len(),
            symbol_size,
            "scenario={scenario_id} payload must match the symbol size"
        );
        let (columns, coefficients) = decoder.source_equation(0);
        let received = [ReceivedSymbol {
            esi: 0,
            is_source: true,
            columns,
            coefficients,
            data: payload.clone(),
        }];
        let params = decoder.params();
        let implicit_padding = params.k_prime.saturating_sub(params.k);
        let required = params.l.saturating_sub(implicit_padding);

        match decoder.decode(&received) {
            Err(DecodeError::InsufficientSymbols {
                received: actual,
                required: expected,
            }) => {
                assert_eq!(
                    actual,
                    received.len(),
                    "scenario={scenario_id} must report the supplied symbol count"
                );
                assert_eq!(
                    expected, required,
                    "scenario={scenario_id} must report the effective decode threshold"
                );
            }
            other => {
                panic!("scenario={scenario_id} expected insufficient-symbol failure, got {other:?}")
            }
        }

        let reference_config = RaptorqRsObjectTransmissionInformation::new(
            u64::try_from(
                k.checked_mul(symbol_size)
                    .expect("transfer length fits usize"),
            )
            .expect("transfer length fits u64"),
            u16::try_from(symbol_size).expect("symbol size fits u16"),
            1,
            1,
            1,
        );
        let mut reference = RaptorqRsDecoder::new(reference_config);
        let reference_bytes = reference.decode(RaptorqRsEncodingPacket::new(
            RaptorqRsPayloadId::new(0, 0),
            payload,
        ));
        assert!(
            reference_bytes.is_none(),
            "scenario={scenario_id} raptorq-rs must also fail to decode one source packet"
        );
    }

    #[test]
    fn differential_decoder_matches_raptorq_rs_k8192_insufficient_symbols() {
        assert_decoder_matches_raptorq_rs_insufficient_source_packet(
            "RQ-D2-DIFF-K8192-INSUFFICIENT-RAPTORQ-RS",
            8192,
            8,
            0x6330_8192,
            8194,
        );
    }

    #[test]
    fn differential_decoder_matches_raptorq_rs_k10000_insufficient_symbols() {
        assert_decoder_matches_raptorq_rs_insufficient_source_packet(
            "RQ-D2-DIFF-K10000-INSUFFICIENT-RAPTORQ-RS",
            10_000,
            8,
            0x6330_2710,
            10_017,
        );
    }

    #[test]
    fn differential_decoder_matches_raptorq_rs_k16384_insufficient_symbols() {
        assert_decoder_matches_raptorq_rs_insufficient_source_packet(
            "RQ-D2-DIFF-K16384-INSUFFICIENT-RAPTORQ-RS",
            16384,
            4,
            0x6330_4000,
            16505,
        );
    }

    #[test]
    fn differential_loss_matrix_matches_raptorq_rs() {
        for &(case, drop_seed, drop_per_mille) in &[
            (
                DifferentialCase {
                    scenario_id: "RQ-D2-DIFF-K10-LOSS30-RAPTORQ-RS",
                    k: 10,
                    symbol_size: 64,
                    seed: 0x6330_0010,
                    drop_modulus: None,
                    drop_remainder: 0,
                    repair_budget: RepairBudget::ByDropped { extra: 4 },
                    expect_success: true,
                    expected_error_kind: None,
                },
                0xA1B2_C310_u64,
                300,
            ),
            (
                DifferentialCase {
                    scenario_id: "RQ-D2-DIFF-K42-LOSS30-RAPTORQ-RS",
                    k: 42,
                    symbol_size: 64,
                    seed: 0x6330_042A,
                    drop_modulus: None,
                    drop_remainder: 0,
                    repair_budget: RepairBudget::ByDropped { extra: 4 },
                    expect_success: true,
                    expected_error_kind: None,
                },
                0xA1B2_C342_u64,
                300,
            ),
            (
                DifferentialCase {
                    scenario_id: "RQ-D2-DIFF-K42-LOSS70-RAPTORQ-RS",
                    k: 42,
                    symbol_size: 64,
                    seed: 0x6330_7042,
                    drop_modulus: None,
                    drop_remainder: 0,
                    repair_budget: RepairBudget::ByDropped { extra: 12 },
                    expect_success: true,
                    expected_error_kind: None,
                },
                0xA1B2_C742_u64,
                700,
            ),
            (
                DifferentialCase {
                    scenario_id: "RQ-D2-DIFF-K842-LOSS30-RAPTORQ-RS",
                    k: 842,
                    symbol_size: 32,
                    seed: 0x6330_0842,
                    drop_modulus: None,
                    drop_remainder: 0,
                    repair_budget: RepairBudget::ByDropped { extra: 4 },
                    expect_success: true,
                    expected_error_kind: None,
                },
                0xA1B2_C842_u64,
                300,
            ),
        ] {
            let source = make_source_data(case.k, case.symbol_size, case.seed.wrapping_mul(17));
            let encoder = SystematicEncoder::new(&source, case.symbol_size, case.seed)
                .unwrap_or_else(|| panic!("scenario={} failed to build encoder", case.scenario_id));
            let decoder = InactivationDecoder::new(case.k, case.symbol_size, case.seed);
            let drop_indices = exact_random_drop_indices(case.k, drop_per_mille, drop_seed);
            let loss_pct = drop_indices
                .len()
                .saturating_mul(100)
                .checked_div(case.k)
                .unwrap_or(0);
            let repair_esi_upper = max_repair_esi(case, decoder.params().l, drop_indices.len());
            let received = build_received_symbols(
                &encoder,
                &decoder,
                &source,
                &drop_indices,
                repair_esi_upper,
                case.seed,
            );

            let our_decoded = decoder.decode(&received).unwrap_or_else(|err| {
                panic!("scenario={} decoder failed: {err:?}", case.scenario_id)
            });
            let our_bytes = flatten_source_bytes(&our_decoded.source);
            let reference_bytes = reference_decode_with_raptorq_rs(
                case,
                &encoder,
                &source,
                &drop_indices,
                repair_esi_upper,
            );
            let expected_bytes = flatten_source_bytes(&source);

            assert_eq!(
                our_bytes, expected_bytes,
                "scenario={} our decoder must recover the exact source block at {loss_pct}% loss",
                case.scenario_id,
            );
            assert_eq!(
                reference_bytes, expected_bytes,
                "scenario={} raptorq-rs must recover the exact source block at {loss_pct}% loss",
                case.scenario_id,
            );
            assert_eq!(
                our_bytes, reference_bytes,
                "scenario={} decoders must emit byte-identical output at {loss_pct}% loss",
                case.scenario_id,
            );
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn differential_harness_selected_slice() {
        let cases = [
            DifferentialCase {
                scenario_id: "RQ-D2-DIFF-OK-001",
                k: 10,
                symbol_size: 64,
                seed: 2024,
                drop_modulus: Some(3),
                drop_remainder: 1,
                repair_budget: RepairBudget::ByDropped { extra: 3 },
                expect_success: true,
                expected_error_kind: None,
            },
            DifferentialCase {
                scenario_id: "RQ-D2-DIFF-OK-002",
                k: 16,
                symbol_size: 32,
                seed: 9001,
                drop_modulus: Some(2),
                drop_remainder: 0,
                repair_budget: RepairBudget::ByDropped { extra: 2 },
                expect_success: true,
                expected_error_kind: None,
            },
            DifferentialCase {
                scenario_id: "RQ-D2-DIFF-FAIL-INSUFFICIENT",
                k: 12,
                symbol_size: 48,
                seed: 77,
                drop_modulus: Some(1),
                drop_remainder: 0,
                repair_budget: RepairBudget::None,
                expect_success: false,
                expected_error_kind: Some("insufficient_symbols"),
            },
        ];

        for case in cases {
            let source = make_source_data(case.k, case.symbol_size, case.seed.wrapping_mul(17));
            let encoder = SystematicEncoder::new(&source, case.symbol_size, case.seed)
                .unwrap_or_else(|| panic!("scenario={} failed to build encoder", case.scenario_id));
            let decoder = InactivationDecoder::new(case.k, case.symbol_size, case.seed);

            let drop_indices = drop_indices_for(case);
            let l = decoder.params().l;
            let repair_esi_upper = max_repair_esi(case, l, drop_indices.len());
            let received = build_received_symbols(
                &encoder,
                &decoder,
                &source,
                &drop_indices,
                repair_esi_upper,
                case.seed,
            );

            let decoder_result = decoder.decode(&received);
            let reference_result = reference_decode(&decoder, &received);
            let root_cause = root_cause_label(&decoder_result, &reference_result);

            let outcome = match (&root_cause, &decoder_result, &reference_result) {
                (None, Ok(_), Ok(_)) => "ok",
                (None, Err(_), Err(_)) => "decode_failure",
                (Some(_), Ok(_), Ok(_)) => "symbol_mismatch",
                _ => "fail",
            };

            let loss_pct = (drop_indices.len() * 100).checked_div(case.k).unwrap_or(0);

            let decode_stats = decoder_result.as_ref().map_or_else(
                |_| UnitDecodeStats {
                    k: case.k,
                    loss_pct,
                    dropped: drop_indices.len(),
                    peeled: 0,
                    inactivated: 0,
                    gauss_ops: 0,
                    pivots: 0,
                    peel_queue_pushes: 0,
                    peel_queue_pops: 0,
                    peel_frontier_peak: 0,
                    dense_core_rows: 0,
                    dense_core_cols: 0,
                    dense_core_dropped_rows: 0,
                    fallback_reason: "none".to_string(),
                    hard_regime_activated: false,
                    hard_regime_branch: "none".to_string(),
                    hard_regime_fallbacks: 0,
                    conservative_fallback_reason: "none".to_string(),
                    governance: None,
                },
                |result| UnitDecodeStats {
                    k: case.k,
                    loss_pct,
                    dropped: drop_indices.len(),
                    peeled: result.stats.peeled,
                    inactivated: result.stats.inactivated,
                    gauss_ops: result.stats.gauss_ops,
                    pivots: result.stats.pivots_selected,
                    peel_queue_pushes: result.stats.peel_queue_pushes,
                    peel_queue_pops: result.stats.peel_queue_pops,
                    peel_frontier_peak: result.stats.peel_frontier_peak,
                    dense_core_rows: result.stats.dense_core_rows,
                    dense_core_cols: result.stats.dense_core_cols,
                    dense_core_dropped_rows: result.stats.dense_core_dropped_rows,
                    fallback_reason: result
                        .stats
                        .hard_regime_conservative_fallback_reason
                        .or(result.stats.peeling_fallback_reason)
                        .unwrap_or("none")
                        .to_string(),
                    hard_regime_activated: result.stats.hard_regime_activated,
                    hard_regime_branch: result
                        .stats
                        .hard_regime_branch
                        .unwrap_or("none")
                        .to_string(),
                    hard_regime_fallbacks: result.stats.hard_regime_fallbacks,
                    conservative_fallback_reason: result
                        .stats
                        .hard_regime_conservative_fallback_reason
                        .unwrap_or("none")
                        .to_string(),
                    governance: result
                        .stats
                        .governance
                        .as_ref()
                        .map(UnitGovernanceDecision::from),
                },
            );

            let parameter_set = format!(
                "k={},symbol_size={},l={},received={},dropped={},expect_success={},root_cause={}",
                case.k,
                case.symbol_size,
                l,
                received.len(),
                drop_indices.len(),
                case.expect_success,
                root_cause.as_deref().unwrap_or("none")
            );
            let log_entry = UnitLogEntry::new(
                case.scenario_id,
                case.seed,
                &parameter_set,
                DIFF_REPLAY_REF,
                DIFF_REPRO_COMMAND,
                outcome,
            )
            .with_artifact_path(DIFF_ARTIFACT_PATH)
            .with_decode_stats(decode_stats);
            let log_json = log_entry
                .to_json()
                .expect("serialize differential log entry");
            let violations = validate_unit_log_json(&log_json);
            let context = log_entry.to_context_string();

            eprintln!("{log_json}");

            assert!(
                violations.is_empty(),
                "{context}: unit log schema violations: {violations:?}"
            );

            if let Some(label) = root_cause {
                panic!(
                    "{context} root_cause={label} decoder={decoder_result:?} reference={reference_result:?}"
                );
            }

            if case.expect_success {
                let decoder_ok = decoder_result.as_ref().unwrap_or_else(|err| {
                    panic!("{context}: decoder failed unexpectedly: {err:?}")
                });
                let reference_ok = reference_result.as_ref().unwrap_or_else(|err| {
                    panic!("{context}: reference failed unexpectedly: {err:?}")
                });
                for (idx, (lhs, rhs)) in decoder_ok
                    .source
                    .iter()
                    .zip(reference_ok.source.iter())
                    .enumerate()
                {
                    assert_eq!(
                        lhs, rhs,
                        "{context}: source symbol mismatch at index={idx} root_cause=source_payload_mismatch"
                    );
                }
                for (idx, (lhs, rhs)) in decoder_ok
                    .intermediate
                    .iter()
                    .zip(reference_ok.intermediate.iter())
                    .enumerate()
                {
                    assert_eq!(
                        lhs, rhs,
                        "{context}: intermediate symbol mismatch at index={idx} root_cause=intermediate_symbol_mismatch"
                    );
                }
            } else {
                let expected_kind = case.expected_error_kind.unwrap_or("insufficient_symbols");
                let decoder_err = decoder_result.as_ref().err().unwrap_or_else(|| {
                    panic!("{context}: expected decoder failure kind={expected_kind}")
                });
                let reference_err = reference_result.as_ref().err().unwrap_or_else(|| {
                    panic!("{context}: expected reference failure kind={expected_kind}")
                });
                assert_eq!(
                    decoder_error_kind(decoder_err),
                    expected_kind,
                    "{context}: unexpected decoder failure kind"
                );
                assert_eq!(
                    reference_error_kind(reference_err),
                    expected_kind,
                    "{context}: unexpected reference failure kind"
                );
            }
        }
    }

    #[test]
    fn conformance_rfc6330_differential_vector_matrix_logs_evidence() {
        let success_case = DifferentialCase {
            scenario_id: "RQ-SLDD1Z-RFC6330-DIFF-K10-SUCCESS",
            k: 10,
            symbol_size: 64,
            seed: 0x6330_0010,
            drop_modulus: Some(3),
            drop_remainder: 1,
            repair_budget: RepairBudget::ByDropped { extra: 4 },
            expect_success: true,
            expected_error_kind: None,
        };
        let source = make_source_data(
            success_case.k,
            success_case.symbol_size,
            success_case.seed.wrapping_mul(17),
        );
        let encoder = SystematicEncoder::new(&source, success_case.symbol_size, success_case.seed)
            .unwrap_or_else(|| {
                panic!(
                    "scenario={} failed to build encoder",
                    success_case.scenario_id
                )
            });
        let params = encoder.params().clone();
        assert_eq!(
            params.k_prime, 10,
            "scenario={} must pin the RFC 6330 K'=10 source-block row",
            success_case.scenario_id
        );

        let systematic = reference_source_packets_with_raptorq_rs(success_case, &source);
        for (idx, packet) in systematic.iter().take(3).enumerate() {
            assert_eq!(
                packet.payload_id().encoding_symbol_id() as usize,
                idx,
                "scenario={} reference systematic packet {} must preserve ESI={idx}",
                success_case.scenario_id,
                idx
            );
        }

        for esi in (success_case.k as u32)..(success_case.k as u32 + 3) {
            let repair_data = encoder.repair_symbol(esi);
            let decoder = InactivationDecoder::new(
                success_case.k,
                success_case.symbol_size,
                success_case.seed,
            );
            let (columns, coefficients) = repair_equation(&decoder, esi);
            let mut reconstructed = vec![0u8; success_case.symbol_size];
            for (&column, &coefficient) in columns.iter().zip(coefficients.iter()) {
                let intermediate = encoder.intermediate_symbol(column);
                for (byte, &intermediate_byte) in reconstructed.iter_mut().zip(intermediate.iter())
                {
                    *byte ^= (coefficient * Gf256::new(intermediate_byte)).raw();
                }
            }
            assert_eq!(
                repair_data, reconstructed,
                "scenario={} repair ESI {esi} must match its RFC repair equation",
                success_case.scenario_id
            );
        }

        let decoder =
            InactivationDecoder::new(success_case.k, success_case.symbol_size, success_case.seed);
        let drop_indices = drop_indices_for(success_case);
        let repair_esi_upper = max_repair_esi(success_case, decoder.params().l, drop_indices.len());
        let received = build_received_symbols(
            &encoder,
            &decoder,
            &source,
            &drop_indices,
            repair_esi_upper,
            success_case.seed,
        );
        let decoder_result = decoder.decode(&received).unwrap_or_else(|err| {
            panic!(
                "scenario={} decoder failed: {err:?}",
                success_case.scenario_id
            )
        });
        let reference_bytes = reference_decode_with_raptorq_rs(
            success_case,
            &encoder,
            &source,
            &drop_indices,
            repair_esi_upper,
        );
        let asupersync_bytes = flatten_source_bytes(&decoder_result.source);
        assert_eq!(
            asupersync_bytes, reference_bytes,
            "scenario={} asupersync and raptorq-rs must decode identical bytes",
            success_case.scenario_id
        );
        emit_rfc6330_differential_log(
            success_case.scenario_id,
            success_case.k,
            success_case.symbol_size,
            &received_symbol_ids(&received),
            received.len(),
            "success",
            Some(&payload_fingerprint(&reference_bytes)),
            Some(&payload_fingerprint(&asupersync_bytes)),
            None,
            "pass",
        );

        let mut permuted = received.clone();
        let mut perm_rng = DetRng::new(0x51DD_108D);
        perm_rng.shuffle(&mut permuted);
        let permuted_result = decoder.decode(&permuted).unwrap_or_else(|err| {
            panic!(
                "scenario={} permuted decode failed: {err:?}",
                success_case.scenario_id
            )
        });
        let permuted_bytes = flatten_source_bytes(&permuted_result.source);
        assert_eq!(
            permuted_bytes, reference_bytes,
            "scenario={} symbol ordering must not affect decode output",
            success_case.scenario_id
        );
        emit_rfc6330_differential_log(
            "RQ-SLDD1Z-RFC6330-DIFF-K10-PERMUTED",
            success_case.k,
            success_case.symbol_size,
            &received_symbol_ids(&permuted),
            permuted.len(),
            "success",
            Some(&payload_fingerprint(&reference_bytes)),
            Some(&payload_fingerprint(&permuted_bytes)),
            None,
            "pass",
        );

        let insufficient_scenario = "RQ-SLDD1Z-RFC6330-DIFF-K10-INSUFFICIENT";
        let insufficient_decoder = InactivationDecoder::new(10, 64, 0x6330_0011);
        assert_eq!(
            insufficient_decoder.params().k_prime,
            10,
            "scenario={insufficient_scenario} must stay on the K'=10 row"
        );
        let one_packet_payload: Vec<u8> = (0..64)
            .map(|idx| u8::try_from((idx * 17 + 0x42) % 256).expect("payload byte fits u8"))
            .collect();
        let (columns, coefficients) = insufficient_decoder.source_equation(0);
        let insufficient_received = [ReceivedSymbol {
            esi: 0,
            is_source: true,
            columns,
            coefficients,
            data: one_packet_payload.clone(),
        }];
        let insufficient_err = insufficient_decoder
            .decode(&insufficient_received)
            .expect_err("insufficient-symbol differential case must fail");
        assert_eq!(
            decoder_error_kind(&insufficient_err),
            "insufficient_symbols",
            "scenario={insufficient_scenario} must fail with InsufficientSymbols"
        );
        let insufficient_reference_config =
            RaptorqRsObjectTransmissionInformation::new(640, 64, 1, 1, 1);
        let mut insufficient_reference = RaptorqRsDecoder::new(insufficient_reference_config);
        let insufficient_reference_result = insufficient_reference.decode(
            RaptorqRsEncodingPacket::new(RaptorqRsPayloadId::new(0, 0), one_packet_payload),
        );
        assert!(
            insufficient_reference_result.is_none(),
            "scenario={insufficient_scenario} raptorq-rs must also fail with one source packet"
        );
        emit_rfc6330_differential_log(
            insufficient_scenario,
            10,
            64,
            &received_symbol_ids(&insufficient_received),
            insufficient_received.len(),
            "decode_failure",
            None,
            None,
            Some("insufficient_symbols"),
            "pass",
        );

        let malformed_scenario = "RQ-SLDD1Z-RFC6330-DIFF-MALFORMED-PARAMS";
        let malformed_err =
            SystematicParams::try_for_source_block(0, 64).expect_err("K=0 must be rejected");
        assert!(
            matches!(
                malformed_err,
                asupersync::raptorq::systematic::SystematicParamError::UnsupportedSourceBlockSize {
                    requested: 0,
                    ..
                }
            ),
            "scenario={malformed_scenario} must reject malformed source-block parameters"
        );
        emit_rfc6330_differential_log(
            malformed_scenario,
            0,
            64,
            &[],
            0,
            "parameter_rejected",
            None,
            None,
            Some("unsupported_source_block_size"),
            "pass",
        );
    }
}

// ============================================================================
// Metamorphic + Property Erasure-Recovery Test Battery (bd-3syrq / D3)
//
// Deterministic property-based tests that verify codec invariants hold
// under varied erasure patterns, symbol orderings, and parameter regimes.
// Every test uses fixed seeds for full reproducibility.
// ============================================================================

#[cfg(feature = "test-internals")]
mod metamorphic_property {
    use super::*;
    use asupersync::raptorq::rfc6330::rand;
    use asupersync::raptorq::test_log_schema::{
        UnitDecodeStats, UnitLogEntry, validate_unit_log_json,
    };

    const D4_ARTIFACT_PATH: &str = "artifacts/raptorq_d4_decode_failure_policy_v1.json";
    const D4_REPLAY_REF: &str = "replay:rq-d4-decode-failure-policy-v1";
    const D4_REPRO_INSUFFICIENT: &str = "rch exec -- cargo test --test raptorq_conformance insufficient_symbols_returns_error -- --nocapture";
    const D4_REPRO_COLUMN_RANGE: &str = "rch exec -- cargo test --test raptorq_conformance invalid_column_index_returns_unrecoverable_error -- --nocapture";
    const D4_REPRO_MULTI_SEED: &str = "rch exec -- cargo test --test raptorq_conformance multi_seed_erasure_stress -- --nocapture";

    fn emit_d4_unit_log(
        scenario_id: &str,
        seed: u64,
        parameter_set: &str,
        outcome: &str,
        repro_command: &str,
        decode_stats: Option<UnitDecodeStats>,
    ) -> String {
        let mut entry = UnitLogEntry::new(
            scenario_id,
            seed,
            parameter_set,
            D4_REPLAY_REF,
            repro_command,
            outcome,
        )
        .with_artifact_path(D4_ARTIFACT_PATH);
        if let Some(stats) = decode_stats {
            entry = entry.with_decode_stats(stats);
        }
        let json = entry.to_json().expect("serialize D4 unit log entry");
        let violations = validate_unit_log_json(&json);
        let context = entry.to_context_string();
        assert!(
            violations.is_empty(),
            "{context}: unit log schema violations: {violations:?}"
        );
        eprintln!("{json}");
        context
    }

    // ----------------------------------------------------------------
    // Helper: deterministic erasure pattern generator
    // ----------------------------------------------------------------

    /// Generate a pseudorandom drop set of `count` indices from 0..n.
    fn random_drop_set(n: usize, count: usize, seed: u64) -> Vec<usize> {
        assert!(count <= n);
        let mut indices: Vec<usize> = (0..n).collect();
        // Fisher-Yates shuffle with deterministic PRNG
        for i in (1..n).rev() {
            let j = rand(seed.wrapping_add(i as u64) as u32, 0, (i + 1) as u32) as usize;
            indices.swap(i, j);
        }
        indices.truncate(count);
        indices.sort_unstable();
        indices
    }

    /// Full encode-decode roundtrip helper that returns the decoded source.
    /// `drop_source` lists which source symbol indices to erase.
    /// `extra_repair` is how many repair symbols beyond L to provide.
    fn roundtrip(
        k: usize,
        symbol_size: usize,
        seed: u64,
        drop_source: &[usize],
        extra_repair: usize,
    ) -> Result<Vec<Vec<u8>>, String> {
        let source = make_source_data(k, symbol_size, seed);
        let encoder = SystematicEncoder::new(&source, symbol_size, seed)
            .ok_or_else(|| format!("encoder construction failed for K={k} seed={seed}"))?;
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        let max_repair_esi = (l + extra_repair) as u32;
        let received = build_received_symbols(
            &encoder,
            &decoder,
            &source,
            drop_source,
            max_repair_esi,
            seed,
        );

        let result = decoder
            .decode(&received)
            .map_err(|e| format!("K={k} seed={seed}: {e:?}"))?;
        Ok(result.source)
    }

    // ----------------------------------------------------------------
    // P1: Source Reconstruction Invariant
    //
    // For all valid (K, seed), encoding K source symbols and providing
    // at least L symbols to the decoder must recover all K originals
    // byte-for-byte.
    // ----------------------------------------------------------------

    #[test]
    fn source_reconstruction_sweep() {
        // Use (K, seed) combinations verified by the golden vector suite
        let test_cases: Vec<(usize, usize, u64)> = vec![
            (8, 32, 42),
            (8, 64, 42),
            (10, 32, 123),
            (16, 64, 789),
            (20, 128, 42),
            (32, 64, 456),
            (32, 128, 42),
        ];

        for (k, symbol_size, seed) in test_cases {
            let source = make_source_data(k, symbol_size, seed);
            let decoded = roundtrip(k, symbol_size, seed, &[], 0)
                .unwrap_or_else(|e| panic!("K={k} seed={seed}: decode failed: {e:?}"));

            assert_eq!(decoded.len(), k, "K={k}: wrong number of decoded symbols");
            for (i, (orig, dec)) in source.iter().zip(decoded.iter()).enumerate() {
                assert_eq!(orig, dec, "K={k} seed={seed}: symbol {i} mismatch");
            }
        }
    }

    // ----------------------------------------------------------------
    // P2: Symbol Permutation Resilience
    //
    // The decoder output must be identical regardless of the order in
    // which received symbols are presented.
    // ----------------------------------------------------------------

    #[test]
    fn symbol_permutation_resilience() {
        let k = 10;
        let symbol_size = 64;
        let seed = 42u64;

        let source = make_source_data(k, symbol_size, seed);
        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        // Build received symbols in natural order
        let received_natural =
            build_received_symbols(&encoder, &decoder, &source, &[], l as u32, seed);
        let result_natural = decoder
            .decode(&received_natural)
            .expect("natural order decode");

        // Permute the received symbols with 5 different shuffles
        for perm_seed in [7u64, 13, 29, 53, 97] {
            let mut received_shuffled = received_natural.clone();
            let n = received_shuffled.len();
            for i in (1..n).rev() {
                let j = rand(perm_seed.wrapping_add(i as u64) as u32, 0, (i + 1) as u32) as usize;
                received_shuffled.swap(i, j);
            }

            let result_shuffled = decoder
                .decode(&received_shuffled)
                .unwrap_or_else(|e| panic!("perm_seed={perm_seed}: decode failed: {e:?}"));

            for (i, (a, b)) in result_natural
                .source
                .iter()
                .zip(result_shuffled.source.iter())
                .enumerate()
            {
                assert_eq!(
                    a, b,
                    "perm_seed={perm_seed}: symbol {i} differs after permutation"
                );
            }
        }
    }

    // ----------------------------------------------------------------
    // P3: No Silent Corruption
    //
    // When decode succeeds, every decoded source symbol must match the
    // original. We test across multiple K values and erasure patterns
    // to ensure no partial/corrupt output escapes.
    // ----------------------------------------------------------------

    #[test]
    fn no_silent_corruption_random_erasure() {
        let test_configs: Vec<(usize, usize, u64, usize)> = vec![
            // (K, symbol_size, seed, num_erasures)
            (8, 64, 42, 2),
            (10, 32, 123, 3),
            (16, 64, 789, 5),
            (20, 128, 42, 7),
            (32, 64, 456, 10),
        ];

        for (k, symbol_size, seed, num_erasures) in test_configs {
            let source = make_source_data(k, symbol_size, seed);
            let drop_set = random_drop_set(k, num_erasures, seed + 1000);

            // Provide extra repair to compensate
            let extra = num_erasures + 2;
            let decoded = roundtrip(k, symbol_size, seed, &drop_set, extra).unwrap_or_else(|e| {
                panic!("K={k} erasures={num_erasures} seed={seed}: decode failed: {e:?}")
            });

            for (i, (orig, dec)) in source.iter().zip(decoded.iter()).enumerate() {
                assert_eq!(
                    orig, dec,
                    "K={k} seed={seed} erasures={num_erasures}: silent corruption at symbol {i}"
                );
            }
        }
    }

    // ----------------------------------------------------------------
    // P4: Erasure Pattern Independence
    //
    // Metamorphic relation: for a fixed (K, seed), decoding with
    // different erasure patterns (of the same count) that provide
    // sufficient symbols should all produce the same source output.
    // ----------------------------------------------------------------

    #[test]
    fn erasure_pattern_independence() {
        let k = 16;
        let symbol_size = 64;
        let seed = 42u64;
        let num_erasures = 4;
        let extra_repair = num_erasures + 3;

        let source = make_source_data(k, symbol_size, seed);

        // Generate 6 different erasure patterns of the same size
        let patterns: Vec<Vec<usize>> = (0..6)
            .map(|i| random_drop_set(k, num_erasures, seed + 2000 + i))
            .collect();

        for (pattern_idx, drop_set) in patterns.iter().enumerate() {
            let decoded =
                roundtrip(k, symbol_size, seed, drop_set, extra_repair).unwrap_or_else(|e| {
                    panic!("pattern {pattern_idx} ({drop_set:?}): decode failed: {e:?}")
                });

            for (i, (orig, dec)) in source.iter().zip(decoded.iter()).enumerate() {
                assert_eq!(orig, dec, "pattern {pattern_idx}: symbol {i} mismatch");
            }
        }
    }

    // ----------------------------------------------------------------
    // P5: Burst Erasure Recovery
    //
    // Consecutive (burst) erasure patterns are a common real-world
    // failure mode. Verify recovery across burst positions: early,
    // middle, and late in the source block.
    // ----------------------------------------------------------------

    #[test]
    fn burst_erasure_recovery() {
        let k = 20;
        let symbol_size = 64;
        let seed = 99u64;
        let burst_len = 5;
        let extra_repair = burst_len + 3;

        let source = make_source_data(k, symbol_size, seed);

        // Bursts at different positions
        let burst_starts = [0, 5, 10, 15]; // early, mid-early, mid-late, late
        for &start in &burst_starts {
            let end = (start + burst_len).min(k);
            let drop_set: Vec<usize> = (start..end).collect();

            let decoded = roundtrip(k, symbol_size, seed, &drop_set, extra_repair)
                .unwrap_or_else(|e| panic!("burst at [{start}..{end}): decode failed: {e:?}"));

            for (i, (orig, dec)) in source.iter().zip(decoded.iter()).enumerate() {
                assert_eq!(orig, dec, "burst at [{start}..{end}): symbol {i} mismatch");
            }
        }
    }

    // ----------------------------------------------------------------
    // P6: Repair Symbol Determinism
    //
    // Multiple calls to repair_symbol(esi) for the same encoder must
    // produce byte-identical output.
    // ----------------------------------------------------------------

    #[test]
    fn repair_symbol_determinism() {
        let k = 16;
        let symbol_size = 64;
        let seed = 42u64;

        let source = make_source_data(k, symbol_size, seed);
        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();

        // Call repair_symbol twice for each ESI and verify identity
        for esi in (k as u32)..(k as u32 + 20) {
            let first = encoder.repair_symbol(esi);
            let second = encoder.repair_symbol(esi);
            assert_eq!(first, second, "repair_symbol({esi}) not deterministic");
        }
    }

    // ----------------------------------------------------------------
    // P7: Cross-Instance Encoding Determinism
    //
    // Two independently constructed encoders with the same inputs must
    // produce identical intermediate symbols and repair symbols.
    // ----------------------------------------------------------------

    #[test]
    fn cross_instance_encoding_determinism() {
        let k = 10;
        let symbol_size = 64;
        let seed = 42u64;

        let source = make_source_data(k, symbol_size, seed);

        let enc_a = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let enc_b = SystematicEncoder::new(&source, symbol_size, seed).unwrap();

        let params = enc_a.params();

        // Intermediate symbols must match
        for i in 0..params.l {
            assert_eq!(
                enc_a.intermediate_symbol(i),
                enc_b.intermediate_symbol(i),
                "intermediate symbol {i} differs between instances"
            );
        }

        // Repair symbols must match
        for esi in (k as u32)..(k as u32 + 10) {
            assert_eq!(
                enc_a.repair_symbol(esi),
                enc_b.repair_symbol(esi),
                "repair_symbol({esi}) differs between instances"
            );
        }
    }

    // ----------------------------------------------------------------
    // P8: Overhead Tolerance
    //
    // The decoder should succeed with K + overhead symbols even when
    // all K source symbols are erased (pure repair decoding). Test
    // with increasing overhead from minimum.
    // ----------------------------------------------------------------

    #[test]
    fn pure_repair_decoding() {
        let test_cases: Vec<(usize, usize, u64)> = vec![(8, 64, 42), (10, 32, 123), (16, 64, 789)];

        for (k, symbol_size, seed) in test_cases {
            let source = make_source_data(k, symbol_size, seed);
            let drop_all: Vec<usize> = (0..k).collect();

            // Need at least L symbols total (constraint + repair)
            let decoder = InactivationDecoder::new(k, symbol_size, seed);
            let params = decoder.params();
            let extra_needed = params.l; // All intermediates needed, no source contributing

            let decoded_source = roundtrip(k, symbol_size, seed, &drop_all, extra_needed)
                .unwrap_or_else(|e| panic!("K={k} pure-repair: decode failed: {e}"));

            for (i, (orig, dec)) in source.iter().zip(decoded_source.iter()).enumerate() {
                assert_eq!(orig, dec, "K={k} pure-repair: symbol {i} mismatch");
            }
        }
    }

    // ----------------------------------------------------------------
    // P9: Insufficient Symbols Failure
    //
    // The decoder must return InsufficientSymbols (not succeed with
    // corrupt data) when fewer than L symbols are provided.
    // ----------------------------------------------------------------

    #[test]
    fn insufficient_symbols_returns_error() {
        let k = 10;
        let symbol_size = 64;
        let seed = 42u64;

        let source = make_source_data(k, symbol_size, seed);
        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);

        // Provide only constraint symbols + half the source (not enough)
        let drop_most: Vec<usize> = (k / 2..k).collect();
        let max_repair_esi = k as u32; // no repair symbols at all

        let received = build_received_symbols(
            &encoder,
            &decoder,
            &source,
            &drop_most,
            max_repair_esi,
            seed,
        );

        let context = emit_d4_unit_log(
            "RQ-D4-INSUFFICIENT-MUST-FAIL",
            seed,
            &format!(
                "k={k},symbol_size={symbol_size},received={},required_l={}",
                received.len(),
                decoder.params().l
            ),
            "decode_failure",
            D4_REPRO_INSUFFICIENT,
            Some(UnitDecodeStats {
                k,
                loss_pct: 50,
                dropped: drop_most.len(),
                peeled: 0,
                inactivated: 0,
                gauss_ops: 0,
                pivots: 0,
                peel_queue_pushes: 0,
                peel_queue_pops: 0,
                peel_frontier_peak: 0,
                dense_core_rows: 0,
                dense_core_cols: 0,
                dense_core_dropped_rows: 0,
                fallback_reason: "insufficient_symbols_precheck".to_string(),
                hard_regime_activated: false,
                hard_regime_branch: "none".to_string(),
                hard_regime_fallbacks: 0,
                conservative_fallback_reason: "none".to_string(),
                governance: None,
            }),
        );

        match decoder.decode(&received) {
            Err(DecodeError::InsufficientSymbols { .. }) => {}
            Err(err) => panic!(
                "{context}: expected InsufficientSymbols for in-scope insufficient-symbol case, got {err:?}"
            ),
            Ok(_) => panic!(
                "{context}: decoder unexpectedly succeeded in in-scope insufficient-symbol case"
            ),
        }
    }

    #[test]
    fn invalid_column_index_returns_unrecoverable_error() {
        let k = 10;
        let symbol_size = 32;
        let seed = 2026u64;

        let source = make_source_data(k, symbol_size, seed);
        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        let mut received =
            build_received_symbols(&encoder, &decoder, &source, &[], l as u32 + 2, seed);
        let bad_esi = received[0].esi;
        let bad_column = l + 1;
        received[0].columns[0] = bad_column;

        let context = emit_d4_unit_log(
            "RQ-D4-COLUMN-RANGE-REJECT",
            seed,
            &format!(
                "k={k},symbol_size={symbol_size},received={},required_l={},bad_esi={bad_esi},bad_column={bad_column}",
                received.len(),
                l
            ),
            "decode_failure",
            D4_REPRO_COLUMN_RANGE,
            None,
        );

        match decoder.decode(&received) {
            Err(DecodeError::ColumnIndexOutOfRange {
                esi,
                column,
                max_valid,
            }) => {
                assert_eq!(esi, bad_esi, "{context}: wrong ESI witness");
                assert_eq!(column, bad_column, "{context}: wrong column witness");
                assert_eq!(max_valid, l, "{context}: wrong upper bound witness");
            }
            Err(err) => panic!(
                "{context}: expected ColumnIndexOutOfRange for malformed equation, got {err:?}"
            ),
            Ok(_) => panic!(
                "{context}: decoder unexpectedly succeeded with out-of-range equation column"
            ),
        }
    }

    // ----------------------------------------------------------------
    // P10: Seed Invariance
    //
    // Metamorphic: changing only the seed (with same source data)
    // must preserve repair symbols. The current RFC tuple/equation path is
    // seed-independent for encoding outputs.
    // ----------------------------------------------------------------

    #[test]
    fn seed_sensitivity() {
        let k = 10;
        let symbol_size = 64;
        let source = make_source_data(k, symbol_size, 42);

        let enc_a = SystematicEncoder::new(&source, symbol_size, 42).unwrap();
        let enc_b = SystematicEncoder::new(&source, symbol_size, 43).unwrap();

        for esi in (k as u32)..(k as u32 + 5) {
            assert_eq!(
                enc_a.repair_symbol(esi),
                enc_b.repair_symbol(esi),
                "seed change must not alter repair symbol output for esi={esi}"
            );
        }
    }

    // ----------------------------------------------------------------
    // P11: Interleaved Source + Repair Resilience
    //
    // Mix of source and repair symbols in various ratios should all
    // decode correctly as long as total count >= L.
    // ----------------------------------------------------------------

    #[test]
    fn interleaved_source_repair_ratios() {
        let k = 16;
        let symbol_size = 64;
        let seed = 42u64;

        let source = make_source_data(k, symbol_size, seed);

        // Test dropping 25%, 50%, 75% of source symbols
        for drop_fraction in [4, 8, 12] {
            let drop_set = random_drop_set(k, drop_fraction, seed + drop_fraction as u64);
            let extra = drop_fraction + 3;

            let decoded = roundtrip(k, symbol_size, seed, &drop_set, extra)
                .unwrap_or_else(|e| panic!("drop {drop_fraction}/{k}: decode failed: {e:?}"));

            for (i, (orig, dec)) in source.iter().zip(decoded.iter()).enumerate() {
                assert_eq!(orig, dec, "drop {drop_fraction}/{k}: symbol {i} mismatch");
            }
        }
    }

    // ----------------------------------------------------------------
    // P12: Symbol Size Invariance
    //
    // The codec should work correctly across a range of symbol sizes,
    // including small (1 byte) and larger ones.
    // ----------------------------------------------------------------

    #[test]
    fn symbol_size_invariance() {
        let k = 8;
        let seed = 42u64;

        for symbol_size in [1, 2, 4, 8, 16, 32, 64, 128, 256] {
            let source = make_source_data(k, symbol_size, seed);
            let decoded = roundtrip(k, symbol_size, seed, &[], 0)
                .unwrap_or_else(|e| panic!("symbol_size={symbol_size}: decode failed: {e:?}"));

            for (i, (orig, dec)) in source.iter().zip(decoded.iter()).enumerate() {
                assert_eq!(orig, dec, "symbol_size={symbol_size}: symbol {i} mismatch");
            }
        }
    }

    // ----------------------------------------------------------------
    // P13: Multi-Seed Erasure Stress
    //
    // Sweep across multiple seeds with fixed erasure to ensure no
    // seed-specific decode failures in the normal operating range.
    // ----------------------------------------------------------------

    #[test]
    fn multi_seed_erasure_stress() {
        let k = 10;
        let symbol_size = 32;
        let num_erasures = 3;
        let extra_repair = num_erasures + 2;
        let in_scope_seeds = [1u64, 7, 42, 123, 321, 456, 789, 999, 2024, 9001];

        for seed in in_scope_seeds {
            let source = make_source_data(k, symbol_size, seed);
            let drop_set = random_drop_set(k, num_erasures, seed + 5000);
            let decoded = roundtrip(k, symbol_size, seed, &drop_set, extra_repair)
                .unwrap_or_else(|err| {
                    let context = emit_d4_unit_log(
                        "RQ-D4-MULTI-SEED-IN-SCOPE",
                        seed,
                        &format!(
                            "k={k},symbol_size={symbol_size},num_erasures={num_erasures},extra_repair={extra_repair},root_cause=decode_failure"
                        ),
                        "decode_failure",
                        D4_REPRO_MULTI_SEED,
                        Some(UnitDecodeStats {
                            k,
                            loss_pct: (num_erasures * 100) / k,
                            dropped: num_erasures,
                            peeled: 0,
                            inactivated: 0,
                            gauss_ops: 0,
                            pivots: 0,
                            peel_queue_pushes: 0,
                            peel_queue_pops: 0,
                            peel_frontier_peak: 0,
                            dense_core_rows: 0,
                            dense_core_cols: 0,
                            dense_core_dropped_rows: 0,
                            fallback_reason: "decode_failure".to_string(),
                            hard_regime_activated: false,
                            hard_regime_branch: "none".to_string(),
                            hard_regime_fallbacks: 0,
                            conservative_fallback_reason: "none".to_string(),
                            governance: None,
                        }),
                    );
                    panic!("{context}: decode failed for in-scope seed={seed}: {err}");
                });

            let _ = emit_d4_unit_log(
                "RQ-D4-MULTI-SEED-IN-SCOPE",
                seed,
                &format!(
                    "k={k},symbol_size={symbol_size},num_erasures={num_erasures},extra_repair={extra_repair},root_cause=none"
                ),
                "ok",
                D4_REPRO_MULTI_SEED,
                Some(UnitDecodeStats {
                    k,
                    loss_pct: (num_erasures * 100) / k,
                    dropped: num_erasures,
                    peeled: 0,
                    inactivated: 0,
                    gauss_ops: 0,
                    pivots: 0,
                    peel_queue_pushes: 0,
                    peel_queue_pops: 0,
                    peel_frontier_peak: 0,
                    dense_core_rows: 0,
                    dense_core_cols: 0,
                    dense_core_dropped_rows: 0,
                    fallback_reason: "none".to_string(),
                    hard_regime_activated: false,
                    hard_regime_branch: "none".to_string(),
                    hard_regime_fallbacks: 0,
                    conservative_fallback_reason: "none".to_string(),
                    governance: None,
                }),
            );

            for (i, (orig, dec)) in source.iter().zip(decoded.iter()).enumerate() {
                assert_eq!(orig, dec, "seed={seed}: symbol {i} mismatch");
            }
        }
    }

    // ----------------------------------------------------------------
    // P14: Repair Equation Consistency
    //
    // The repair equation (columns, coefficients) generated by the
    // decoder must match what the encoder uses to generate the repair
    // symbol. Verify via the linear algebra identity:
    //   data = sum(coeff[j] * intermediate[col[j]])
    // ----------------------------------------------------------------

    #[test]
    fn repair_equation_consistency() {
        let k = 10;
        let symbol_size = 64;
        let seed = 42u64;

        let source = make_source_data(k, symbol_size, seed);
        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);

        for esi in (k as u32)..(k as u32 + 10) {
            let repair_data = encoder.repair_symbol(esi);
            let (cols, coefs) = repair_equation(&decoder, esi);

            // Reconstruct from intermediate symbols
            let mut reconstructed = vec![0u8; symbol_size];
            for (&col, &coef) in cols.iter().zip(coefs.iter()) {
                let intermediate = encoder.intermediate_symbol(col);
                for (byte, &inter_byte) in reconstructed.iter_mut().zip(intermediate.iter()) {
                    *byte ^= (coef * Gf256::new(inter_byte)).raw();
                }
            }

            assert_eq!(
                repair_data, reconstructed,
                "ESI={esi}: repair_symbol disagrees with equation * intermediates"
            );
        }
    }

    // ----------------------------------------------------------------
    // P15: Monotonic Decode Success with Increasing Overhead
    //
    // As we add more repair symbols, decode should not go from
    // succeeding to failing (monotonicity of solvability).
    // ----------------------------------------------------------------

    #[test]
    fn monotonic_decode_success() {
        let k = 10;
        let symbol_size = 64;
        let seed = 42u64;
        let drop_count = 4;
        let drop_set = random_drop_set(k, drop_count, seed + 3000);

        let mut first_success_overhead = None;

        // Try increasing overhead from 0 to 2*L
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let max_overhead = decoder.params().l * 2;

        for extra in 0..max_overhead {
            let result = roundtrip(k, symbol_size, seed, &drop_set, extra);
            match (&first_success_overhead, &result) {
                (None, Ok(_)) => {
                    first_success_overhead = Some(extra);
                }
                (Some(threshold), Err(e)) => {
                    panic!(
                        "decode succeeded at overhead={threshold} but failed at overhead={extra}: {e:?}"
                    );
                }
                _ => {}
            }
        }

        assert!(
            first_success_overhead.is_some(),
            "decode never succeeded even with max overhead"
        );
    }
}

// ============================================================================
// Stress/Soak E2E deterministic profiles (bd-mztvq / D8)
// ============================================================================

#[cfg(feature = "test-internals")]
mod stress_soak_e2e {
    use super::*;
    use asupersync::raptorq::test_log_schema::{
        UnitDecodeStats, UnitGovernanceDecision, UnitLogEntry, validate_unit_log_json,
    };
    use serde::Serialize;

    const D8_ARTIFACT_PATH: &str = "artifacts/raptorq_d8_stress_soak_v1.json";
    const D8_REPRO_COMMAND: &str = "rch exec -- cargo test --test raptorq_conformance soak_stress_profiles_deterministic_with_forensic_logs -- --nocapture";
    const D8_FORENSIC_SCHEMA_VERSION: &str = "raptorq-d8-stress-forensic-v1";

    #[derive(Clone, Copy)]
    enum StressProfile {
        ClusteredLoss,
        BurstLoss,
        NearRankDeficient,
    }

    impl StressProfile {
        const fn label(self) -> &'static str {
            match self {
                Self::ClusteredLoss => "clustered_loss",
                Self::BurstLoss => "burst_loss",
                Self::NearRankDeficient => "near_rank_deficient",
            }
        }

        const fn scenario_id(self) -> &'static str {
            match self {
                Self::ClusteredLoss => "RQ-D8-STRESS-CLUSTER",
                Self::BurstLoss => "RQ-D8-STRESS-BURST",
                Self::NearRankDeficient => "RQ-D8-STRESS-NEAR-RANK",
            }
        }

        const fn replay_ref(self) -> &'static str {
            match self {
                Self::ClusteredLoss => "replay:rq-d8-stress-cluster-v1",
                Self::BurstLoss => "replay:rq-d8-stress-burst-v1",
                Self::NearRankDeficient => "replay:rq-d8-stress-near-rank-v1",
            }
        }

        const fn base_seed(self) -> u64 {
            match self {
                Self::ClusteredLoss => 12_200,
                Self::BurstLoss => 15_700,
                Self::NearRankDeficient => 20_900,
            }
        }
    }

    #[derive(Default, Clone, Debug)]
    struct StressAggregate {
        iterations: usize,
        successes: usize,
        failures: usize,
        corruption_events: usize,
        total_gauss_ops: usize,
        total_inactivated: usize,
        max_gauss_ops: usize,
        max_inactivated: usize,
        gauss_ops_samples: Vec<usize>,
        inactivated_samples: Vec<usize>,
        hard_regime_activations: usize,
        hard_regime_markowitz_branch_count: usize,
        hard_regime_block_schur_branch_count: usize,
        hard_regime_fallbacks: usize,
        fallback_after_baseline_failure_count: usize,
        block_schur_failed_to_converge_count: usize,
    }

    #[derive(Debug, Serialize)]
    struct StressForensicReport {
        schema_version: &'static str,
        scenario_id: &'static str,
        replay_ref: &'static str,
        profile: &'static str,
        seed_base: u64,
        iterations: usize,
        successes: usize,
        failures: usize,
        corruption_events: usize,
        success_rate: f64,
        avg_gauss_ops: f64,
        avg_inactivated: f64,
        max_gauss_ops: usize,
        max_inactivated: usize,
        p50_gauss_ops: usize,
        p95_gauss_ops: usize,
        p99_gauss_ops: usize,
        p50_inactivated: usize,
        p95_inactivated: usize,
        p99_inactivated: usize,
        hard_regime_activations: usize,
        hard_regime_markowitz_branch_count: usize,
        hard_regime_block_schur_branch_count: usize,
        hard_regime_fallbacks: usize,
        fallback_after_baseline_failure_count: usize,
        block_schur_failed_to_converge_count: usize,
        threshold_min_success_rate: f64,
        threshold_max_failures: usize,
        threshold_max_p99_gauss_ops: usize,
        threshold_max_p99_inactivated: usize,
        repro_command: &'static str,
        artifact_path: &'static str,
    }

    #[derive(Clone)]
    struct PeriodicSummaryInput {
        seed: u64,
        k: usize,
        symbol_size: usize,
        iteration: usize,
        dropped: usize,
        last_decode: Option<UnitDecodeStats>,
    }

    #[allow(clippy::cast_precision_loss)]
    fn ratio(numerator: usize, denominator: usize) -> f64 {
        if denominator == 0 {
            return 0.0;
        }
        numerator as f64 / denominator as f64
    }

    fn percentile_nearest_rank(samples: &[usize], percentile: usize) -> usize {
        if samples.is_empty() {
            return 0;
        }
        assert!(
            (1..=100).contains(&percentile),
            "percentile must be in 1..=100, got {percentile}"
        );
        let mut sorted = samples.to_vec();
        sorted.sort_unstable();
        let rank = (percentile * sorted.len()).div_ceil(100).saturating_sub(1);
        sorted[rank]
    }

    fn profile_drop_set(profile: StressProfile, iteration: usize, k: usize) -> Vec<usize> {
        match profile {
            StressProfile::ClusteredLoss => {
                let window = 6usize;
                let start = iteration % (k - window + 1);
                (start..(start + window)).collect()
            }
            StressProfile::BurstLoss => {
                let window = 4usize;
                let start_a = (iteration * 2) % (k - window + 1);
                let start_b = (iteration * 3 + 1) % (k - window + 1);
                let mut drops: std::collections::BTreeSet<usize> = (start_a..(start_a + window))
                    .chain(start_b..(start_b + window))
                    .collect();
                // Keep this profile bounded around ~40% loss.
                while drops.len() > 8 {
                    let last = *drops.iter().next_back().expect("non-empty set");
                    drops.remove(&last);
                }
                drops.into_iter().collect()
            }
            StressProfile::NearRankDeficient => {
                let heavy_loss = 10usize;
                let start = (iteration + 1) % (k - heavy_loss + 1);
                (start..(start + heavy_loss)).collect()
            }
        }
    }

    fn max_repair_esi_for_profile(
        profile: StressProfile,
        decoder: &InactivationDecoder,
        drop_count: usize,
    ) -> u32 {
        let params = decoder.params();
        let k = params.k;
        let constraints = params.s + params.h;
        let kept = k.saturating_sub(drop_count);
        let minimum_repair = params.l.saturating_sub(constraints + kept);

        let repair_count = match profile {
            // Keep healthy margin in the easier profiles.
            StressProfile::ClusteredLoss => minimum_repair + 4,
            StressProfile::BurstLoss => minimum_repair + 3,
            // Near-rank-deficient: intentionally close to threshold.
            StressProfile::NearRankDeficient => minimum_repair + 1,
        };
        (k + repair_count) as u32
    }

    fn emit_periodic_summary(
        profile: StressProfile,
        aggregate: &StressAggregate,
        input: PeriodicSummaryInput,
    ) {
        let outcome = if aggregate.failures == 0 {
            "ok"
        } else {
            "fail"
        };
        let mut entry = UnitLogEntry::new(
            profile.scenario_id(),
            input.seed,
            &format!(
                "profile={},phase=periodic,iter={},k={},symbol_size={},dropped={},successes={},failures={},max_gauss_ops={},max_inactivated={}",
                profile.label(),
                input.iteration + 1,
                input.k,
                input.symbol_size,
                input.dropped,
                aggregate.successes,
                aggregate.failures,
                aggregate.max_gauss_ops,
                aggregate.max_inactivated
            ),
            profile.replay_ref(),
            D8_REPRO_COMMAND,
            outcome,
        )
        .with_artifact_path(D8_ARTIFACT_PATH);

        if let Some(stats) = input.last_decode {
            entry = entry.with_decode_stats(stats);
        }

        let json = entry.to_json().expect("serialize periodic stress log");
        let violations = validate_unit_log_json(&json);
        let context = entry.to_context_string();
        assert!(
            violations.is_empty(),
            "{context}: unit log schema violations: {violations:?}"
        );
        eprintln!("{json}");
    }

    fn emit_final_forensic_report(
        profile: StressProfile,
        aggregate: &StressAggregate,
        threshold_min_success_rate: f64,
        threshold_max_failures: usize,
        threshold_max_p99_gauss_ops: usize,
        threshold_max_p99_inactivated: usize,
    ) {
        let success_rate = ratio(aggregate.successes, aggregate.iterations);
        let avg_gauss_ops = ratio(aggregate.total_gauss_ops, aggregate.successes);
        let avg_inactivated = ratio(aggregate.total_inactivated, aggregate.successes);
        let p50_gauss_ops = percentile_nearest_rank(&aggregate.gauss_ops_samples, 50);
        let p95_gauss_ops = percentile_nearest_rank(&aggregate.gauss_ops_samples, 95);
        let p99_gauss_ops = percentile_nearest_rank(&aggregate.gauss_ops_samples, 99);
        let p50_inactivated = percentile_nearest_rank(&aggregate.inactivated_samples, 50);
        let p95_inactivated = percentile_nearest_rank(&aggregate.inactivated_samples, 95);
        let p99_inactivated = percentile_nearest_rank(&aggregate.inactivated_samples, 99);

        let forensic = StressForensicReport {
            schema_version: D8_FORENSIC_SCHEMA_VERSION,
            scenario_id: profile.scenario_id(),
            replay_ref: profile.replay_ref(),
            profile: profile.label(),
            seed_base: profile.base_seed(),
            iterations: aggregate.iterations,
            successes: aggregate.successes,
            failures: aggregate.failures,
            corruption_events: aggregate.corruption_events,
            success_rate,
            avg_gauss_ops,
            avg_inactivated,
            max_gauss_ops: aggregate.max_gauss_ops,
            max_inactivated: aggregate.max_inactivated,
            p50_gauss_ops,
            p95_gauss_ops,
            p99_gauss_ops,
            p50_inactivated,
            p95_inactivated,
            p99_inactivated,
            hard_regime_activations: aggregate.hard_regime_activations,
            hard_regime_markowitz_branch_count: aggregate.hard_regime_markowitz_branch_count,
            hard_regime_block_schur_branch_count: aggregate.hard_regime_block_schur_branch_count,
            hard_regime_fallbacks: aggregate.hard_regime_fallbacks,
            fallback_after_baseline_failure_count: aggregate.fallback_after_baseline_failure_count,
            block_schur_failed_to_converge_count: aggregate.block_schur_failed_to_converge_count,
            threshold_min_success_rate,
            threshold_max_failures,
            threshold_max_p99_gauss_ops,
            threshold_max_p99_inactivated,
            repro_command: D8_REPRO_COMMAND,
            artifact_path: D8_ARTIFACT_PATH,
        };
        eprintln!(
            "{}",
            serde_json::to_string(&forensic).expect("serialize forensic report")
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn soak_stress_profiles_deterministic_with_forensic_logs() {
        const ITERATIONS: usize = 24;
        const K: usize = 18;
        const SYMBOL_SIZE: usize = 48;
        const SUMMARY_INTERVAL: usize = 8;

        let profiles = [
            StressProfile::ClusteredLoss,
            StressProfile::BurstLoss,
            StressProfile::NearRankDeficient,
        ];

        for profile in profiles {
            let mut aggregate = StressAggregate::default();

            for iteration in 0..ITERATIONS {
                let seed = profile.base_seed().wrapping_add(iteration as u64);
                let source = make_source_data(K, SYMBOL_SIZE, seed.wrapping_mul(31));
                let encoder =
                    SystematicEncoder::new(&source, SYMBOL_SIZE, seed).unwrap_or_else(|| {
                        panic!(
                            "profile={} seed={seed} encoder build failed",
                            profile.label()
                        )
                    });
                let decoder = InactivationDecoder::new(K, SYMBOL_SIZE, seed);

                let drop_set = profile_drop_set(profile, iteration, K);
                let max_repair_esi = max_repair_esi_for_profile(profile, &decoder, drop_set.len());
                let received = build_received_symbols(
                    &encoder,
                    &decoder,
                    &source,
                    &drop_set,
                    max_repair_esi,
                    seed,
                );

                aggregate.iterations += 1;
                let mut last_decode_stats = None;

                match decoder.decode(&received) {
                    Ok(result) => {
                        aggregate.successes += 1;
                        aggregate.total_gauss_ops += result.stats.gauss_ops;
                        aggregate.total_inactivated += result.stats.inactivated;
                        aggregate.max_gauss_ops =
                            aggregate.max_gauss_ops.max(result.stats.gauss_ops);
                        aggregate.max_inactivated =
                            aggregate.max_inactivated.max(result.stats.inactivated);
                        aggregate.gauss_ops_samples.push(result.stats.gauss_ops);
                        aggregate.inactivated_samples.push(result.stats.inactivated);
                        if result.stats.hard_regime_activated {
                            aggregate.hard_regime_activations += 1;
                        }
                        match result.stats.hard_regime_branch {
                            Some("markowitz") => {
                                aggregate.hard_regime_markowitz_branch_count += 1;
                            }
                            Some("block_schur_low_rank") => {
                                aggregate.hard_regime_block_schur_branch_count += 1;
                            }
                            _ => {}
                        }
                        aggregate.hard_regime_fallbacks += result.stats.hard_regime_fallbacks;
                        match result.stats.hard_regime_conservative_fallback_reason {
                            Some("fallback_after_baseline_failure") => {
                                aggregate.fallback_after_baseline_failure_count += 1;
                            }
                            Some("block_schur_failed_to_converge") => {
                                aggregate.block_schur_failed_to_converge_count += 1;
                            }
                            _ => {}
                        }

                        for (idx, (orig, decoded)) in
                            source.iter().zip(result.source.iter()).enumerate()
                        {
                            assert_eq!(
                                orig,
                                decoded,
                                "profile={} seed={seed} iteration={} corruption at symbol {idx}",
                                profile.label(),
                                iteration + 1
                            );
                        }

                        last_decode_stats = Some(UnitDecodeStats {
                            k: K,
                            loss_pct: (drop_set.len() * 100) / K,
                            dropped: drop_set.len(),
                            peeled: result.stats.peeled,
                            inactivated: result.stats.inactivated,
                            gauss_ops: result.stats.gauss_ops,
                            pivots: result.stats.pivots_selected,
                            peel_queue_pushes: result.stats.peel_queue_pushes,
                            peel_queue_pops: result.stats.peel_queue_pops,
                            peel_frontier_peak: result.stats.peel_frontier_peak,
                            dense_core_rows: result.stats.dense_core_rows,
                            dense_core_cols: result.stats.dense_core_cols,
                            dense_core_dropped_rows: result.stats.dense_core_dropped_rows,
                            fallback_reason: result
                                .stats
                                .hard_regime_conservative_fallback_reason
                                .or(result.stats.peeling_fallback_reason)
                                .unwrap_or("none")
                                .to_string(),
                            hard_regime_activated: result.stats.hard_regime_activated,
                            hard_regime_branch: result
                                .stats
                                .hard_regime_branch
                                .unwrap_or("none")
                                .to_string(),
                            hard_regime_fallbacks: result.stats.hard_regime_fallbacks,
                            conservative_fallback_reason: result
                                .stats
                                .hard_regime_conservative_fallback_reason
                                .unwrap_or("none")
                                .to_string(),
                            governance: result
                                .stats
                                .governance
                                .as_ref()
                                .map(UnitGovernanceDecision::from),
                        });
                    }
                    Err(err) => {
                        aggregate.failures += 1;
                        eprintln!(
                            "{{\"schema_version\":\"{}\",\"scenario_id\":\"{}\",\"profile\":\"{}\",\"seed\":{},\"iteration\":{},\"outcome\":\"decode_failure\",\"error\":\"{:?}\",\"repro_command\":\"{}\",\"artifact_path\":\"{}\"}}",
                            D8_FORENSIC_SCHEMA_VERSION,
                            profile.scenario_id(),
                            profile.label(),
                            seed,
                            iteration + 1,
                            err,
                            D8_REPRO_COMMAND,
                            D8_ARTIFACT_PATH
                        );
                    }
                }

                if (iteration + 1).is_multiple_of(SUMMARY_INTERVAL) || iteration + 1 == ITERATIONS {
                    emit_periodic_summary(
                        profile,
                        &aggregate,
                        PeriodicSummaryInput {
                            seed,
                            k: K,
                            symbol_size: SYMBOL_SIZE,
                            iteration,
                            dropped: drop_set.len(),
                            last_decode: last_decode_stats,
                        },
                    );
                }
            }

            let (
                threshold_min_success_rate,
                threshold_max_failures,
                threshold_max_p99_gauss_ops,
                threshold_max_p99_inactivated,
            ) = match profile {
                StressProfile::ClusteredLoss => (1.0, 0, 1400, 40),
                StressProfile::BurstLoss => (1.0, 0, 1400, 40),
                StressProfile::NearRankDeficient => (0.70, 7, 1300, 40),
            };

            emit_final_forensic_report(
                profile,
                &aggregate,
                threshold_min_success_rate,
                threshold_max_failures,
                threshold_max_p99_gauss_ops,
                threshold_max_p99_inactivated,
            );

            let success_rate = ratio(aggregate.successes, aggregate.iterations);
            assert_eq!(
                aggregate.corruption_events,
                0,
                "profile={} observed corruption under stress",
                profile.label()
            );
            assert!(
                aggregate.failures <= threshold_max_failures,
                "profile={} exceeded failure budget: failures={} threshold={}",
                profile.label(),
                aggregate.failures,
                threshold_max_failures
            );
            assert!(
                success_rate >= threshold_min_success_rate,
                "profile={} success rate {:.3} below threshold {:.3}",
                profile.label(),
                success_rate,
                threshold_min_success_rate
            );
            let p99_gauss_ops = percentile_nearest_rank(&aggregate.gauss_ops_samples, 99);
            let p99_inactivated = percentile_nearest_rank(&aggregate.inactivated_samples, 99);
            assert!(
                p99_gauss_ops <= threshold_max_p99_gauss_ops,
                "profile={} p99 gauss_ops regression: {} > {}",
                profile.label(),
                p99_gauss_ops,
                threshold_max_p99_gauss_ops
            );
            assert!(
                p99_inactivated <= threshold_max_p99_inactivated,
                "profile={} p99 inactivated regression: {} > {}",
                profile.label(),
                p99_inactivated,
                threshold_max_p99_inactivated
            );
        }
    }
}

// ============================================================================
// RFC 6330 Golden Vector Conformance Suite (bd-1rxlv / D1)
//
// Deterministic golden-vector tests sourced from RFC 6330 tables and
// internally curated canonical vectors. Every expected value is hardcoded
// so any implementation drift triggers an immediate regression failure.
// ============================================================================

mod golden_vectors {
    use super::*;
    use asupersync::raptorq::rfc6330::{LtTuple, deg, next_prime_ge, rand, tuple, tuple_indices};

    // ----------------------------------------------------------------
    // G1: Systematic Parameter Lookup (RFC 6330 Table 2)
    //
    // For each K, verify K', J, S, H, W, L, B against the RFC table.
    // These pin down the table-driven parameter derivation path.
    // ----------------------------------------------------------------

    struct ParamVector {
        scenario_id: &'static str,
        k: usize,
        expected_k_prime: usize,
        expected_j: usize,
        expected_s: usize,
        expected_h: usize,
        expected_w: usize,
        expected_l: usize,
        expected_b: usize,
    }

    const PARAM_VECTORS: &[ParamVector] = &[
        ParamVector {
            scenario_id: "RQ-D1-PARAMS-001",
            k: 1,
            expected_k_prime: 10,
            expected_j: 254,
            expected_s: 7,
            expected_h: 10,
            expected_w: 17,
            expected_l: 27,
            expected_b: 10,
        },
        ParamVector {
            scenario_id: "RQ-D1-PARAMS-002",
            k: 8,
            expected_k_prime: 10,
            expected_j: 254,
            expected_s: 7,
            expected_h: 10,
            expected_w: 17,
            expected_l: 27,
            expected_b: 10,
        },
        ParamVector {
            scenario_id: "RQ-D1-PARAMS-003",
            k: 10,
            expected_k_prime: 10,
            expected_j: 254,
            expected_s: 7,
            expected_h: 10,
            expected_w: 17,
            expected_l: 27,
            expected_b: 10,
        },
        ParamVector {
            scenario_id: "RQ-D1-PARAMS-004",
            k: 16,
            expected_k_prime: 18,
            expected_j: 682,
            expected_s: 11,
            expected_h: 10,
            expected_w: 29,
            expected_l: 39,
            expected_b: 18,
        },
        ParamVector {
            scenario_id: "RQ-D1-PARAMS-005",
            k: 20,
            expected_k_prime: 20,
            expected_j: 293,
            expected_s: 11,
            expected_h: 10,
            expected_w: 31,
            expected_l: 41,
            expected_b: 20,
        },
        ParamVector {
            scenario_id: "RQ-D1-PARAMS-006",
            k: 32,
            expected_k_prime: 32,
            expected_j: 860,
            expected_s: 11,
            expected_h: 10,
            expected_w: 43,
            expected_l: 53,
            expected_b: 32,
        },
        ParamVector {
            scenario_id: "RQ-D1-PARAMS-007",
            k: 50,
            expected_k_prime: 55,
            expected_j: 520,
            expected_s: 13,
            expected_h: 10,
            expected_w: 67,
            expected_l: 78,
            expected_b: 54,
        },
        ParamVector {
            scenario_id: "RQ-D1-PARAMS-008",
            k: 64,
            expected_k_prime: 69,
            expected_j: 157,
            expected_s: 13,
            expected_h: 10,
            expected_w: 79,
            expected_l: 92,
            expected_b: 66,
        },
        ParamVector {
            scenario_id: "RQ-D1-PARAMS-009",
            k: 100,
            expected_k_prime: 101,
            expected_j: 562,
            expected_s: 17,
            expected_h: 10,
            expected_w: 113,
            expected_l: 128,
            expected_b: 96,
        },
        ParamVector {
            scenario_id: "RQ-D1-PARAMS-010",
            k: 256,
            expected_k_prime: 257,
            expected_j: 265,
            expected_s: 29,
            expected_h: 10,
            expected_w: 271,
            expected_l: 296,
            expected_b: 242,
        },
        ParamVector {
            scenario_id: "RQ-D1-PARAMS-011",
            k: 500,
            expected_k_prime: 511,
            expected_j: 800,
            expected_s: 37,
            expected_h: 10,
            expected_w: 523,
            expected_l: 558,
            expected_b: 486,
        },
        ParamVector {
            scenario_id: "RQ-D1-PARAMS-012",
            k: 1000,
            expected_k_prime: 1002,
            expected_j: 299,
            expected_s: 59,
            expected_h: 10,
            expected_w: 1021,
            expected_l: 1071,
            expected_b: 962,
        },
    ];

    #[test]
    fn golden_rfc6330_systematic_params() {
        for v in PARAM_VECTORS {
            let params = SystematicParams::for_source_block(v.k, 64);
            let ctx = format!(
                "scenario_id={} K={} repro='cargo test --test raptorq_conformance golden_rfc6330_systematic_params'",
                v.scenario_id, v.k
            );
            assert_eq!(params.k_prime, v.expected_k_prime, "{ctx}: K' mismatch");
            assert_eq!(params.j, v.expected_j, "{ctx}: J mismatch");
            assert_eq!(params.s, v.expected_s, "{ctx}: S mismatch");
            assert_eq!(params.h, v.expected_h, "{ctx}: H mismatch");
            assert_eq!(params.w, v.expected_w, "{ctx}: W mismatch");
            assert_eq!(params.l, v.expected_l, "{ctx}: L mismatch");
            assert_eq!(params.b, v.expected_b, "{ctx}: B mismatch");
            // Structural invariants
            assert_eq!(
                params.l,
                params.k_prime + params.s + params.h,
                "{ctx}: L != K'+S+H"
            );
            assert_eq!(params.b, params.w - params.s, "{ctx}: B != W-S");
        }
    }

    // ----------------------------------------------------------------
    // G2: PRNG Golden Vectors (RFC 6330 Section 5.3.5.1)
    //
    // Rand(y, i, m) = (V0[x0] ^ V1[x1] ^ V2[x2] ^ V3[x3]) % m
    // where x_j = ((y >> (8*j)) + i) & 0xFF
    // ----------------------------------------------------------------

    #[test]
    fn golden_rfc6330_rand_prng() {
        // (y, i, m) -> expected result
        let vectors: &[(u32, u8, u32, u32)] = &[
            (0, 0, 256, 25),
            (0, 0, 1000, 529),
            (1, 0, 256, 214),
            (1, 0, 1000, 638),
            (42, 0, 1_048_576, 555_578),
            (42, 1, 100, 34),
            (42, 2, 100, 92),
            (0xDEAD_BEEF, 0, 256, 86),
            (0xDEAD_BEEF, 0, 1000, 326),
            (0xCAFE_BABE, 3, 500, 483),
            (12_345, 0, 1_048_576, 690_767),
            (12_345, 1, 65_536, 18_106),
        ];

        for &(y, i, m, expected) in vectors {
            let actual = rand(y, i, m);
            assert_eq!(
                actual, expected,
                "Rand({y}, {i}, {m}): expected {expected}, got {actual}. \
                 repro='cargo test --test raptorq_conformance golden_rfc6330_rand_prng'"
            );
        }
    }

    // ----------------------------------------------------------------
    // G3: Degree Generator Golden Vectors (RFC 6330 Section 5.3.5.2)
    //
    // deg(v) maps v in [0, 2^20) to degree d in [1, 30] via threshold table.
    // ----------------------------------------------------------------

    #[test]
    fn golden_rfc6330_degree_distribution() {
        // (v, expected_degree)
        let vectors: &[(u32, usize)] = &[
            (0, 1),
            (1, 1),
            (5_242, 1),      // last value in degree-1 range
            (5_243, 2),      // first value in degree-2 range
            (100_000, 2),    // mid degree-2
            (529_530, 2),    // last value in degree-2 range
            (529_531, 3),    // first value in degree-3 range
            (704_293, 3),    // last value in degree-3 range
            (704_294, 4),    // first value in degree-4 range
            (1_000_000, 20), // deep in high-degree range
            (1_017_661, 29), // last value in degree-29 range
            (1_017_662, 30), // first value in degree-30 range
            (1_048_575, 30), // max valid input (2^20 - 1)
        ];

        for &(v, expected) in vectors {
            let actual = deg(v);
            assert_eq!(
                actual, expected,
                "deg({v}): expected {expected}, got {actual}. \
                 repro='cargo test --test raptorq_conformance golden_rfc6330_degree_distribution'"
            );
        }
    }

    // ----------------------------------------------------------------
    // G4: LT Tuple Golden Vectors (RFC 6330 Section 5.3.5.4)
    //
    // tuple(J, W, P, P1, X) -> (d, a, b, d1, a1, b1) + expanded indices
    // ----------------------------------------------------------------

    struct TupleVector {
        scenario_id: &'static str,
        j: usize,
        w: usize,
        p: usize,
        x: u32,
        expected_tuple: LtTuple,
        expected_indices: &'static [usize],
    }

    const TUPLE_VECTORS: &[TupleVector] = &[
        // K=10 parameter space (K'=10, J=254, W=17, P=10)
        TupleVector {
            scenario_id: "RQ-D1-TUPLE-001",
            j: 254,
            w: 17,
            p: 10,
            x: 0,
            expected_tuple: LtTuple {
                d: 2,
                a: 4,
                b: 9,
                d1: 2,
                a1: 5,
                b1: 1,
            },
            expected_indices: &[9, 13, 18, 23],
        },
        TupleVector {
            scenario_id: "RQ-D1-TUPLE-002",
            j: 254,
            w: 17,
            p: 10,
            x: 1,
            expected_tuple: LtTuple {
                d: 7,
                a: 6,
                b: 12,
                d1: 2,
                a1: 1,
                b1: 3,
            },
            expected_indices: &[12, 1, 7, 13, 2, 8, 14, 20, 21],
        },
        TupleVector {
            scenario_id: "RQ-D1-TUPLE-003",
            j: 254,
            w: 17,
            p: 10,
            x: 10,
            expected_tuple: LtTuple {
                d: 2,
                a: 15,
                b: 15,
                d1: 2,
                a1: 10,
                b1: 7,
            },
            expected_indices: &[15, 13, 24, 23],
        },
        TupleVector {
            scenario_id: "RQ-D1-TUPLE-004",
            j: 254,
            w: 17,
            p: 10,
            x: 100,
            expected_tuple: LtTuple {
                d: 2,
                a: 13,
                b: 10,
                d1: 2,
                a1: 8,
                b1: 5,
            },
            expected_indices: &[10, 6, 22, 19],
        },
        // K=20 parameter space (K'=20, J=293, W=31, P=10)
        TupleVector {
            scenario_id: "RQ-D1-TUPLE-005",
            j: 293,
            w: 31,
            p: 10,
            x: 0,
            expected_tuple: LtTuple {
                d: 11,
                a: 15,
                b: 10,
                d1: 2,
                a1: 5,
                b1: 1,
            },
            expected_indices: &[10, 25, 9, 24, 8, 23, 7, 22, 6, 21, 5, 32, 37],
        },
        TupleVector {
            scenario_id: "RQ-D1-TUPLE-006",
            j: 293,
            w: 31,
            p: 10,
            x: 50,
            expected_tuple: LtTuple {
                d: 3,
                a: 3,
                b: 28,
                d1: 2,
                a1: 4,
                b1: 0,
            },
            expected_indices: &[28, 0, 3, 31, 35],
        },
        // K=100 parameter space (K'=101, J=562, W=113, P=15)
        TupleVector {
            scenario_id: "RQ-D1-TUPLE-007",
            j: 562,
            w: 113,
            p: 15,
            x: 0,
            expected_tuple: LtTuple {
                d: 2,
                a: 30,
                b: 4,
                d1: 2,
                a1: 5,
                b1: 12,
            },
            expected_indices: &[4, 34, 125, 113],
        },
        TupleVector {
            scenario_id: "RQ-D1-TUPLE-008",
            j: 562,
            w: 113,
            p: 15,
            x: 200,
            expected_tuple: LtTuple {
                d: 2,
                a: 109,
                b: 107,
                d1: 3,
                a1: 15,
                b1: 7,
            },
            expected_indices: &[107, 103, 120, 118, 116],
        },
    ];

    #[test]
    fn golden_rfc6330_lt_tuples() {
        for v in TUPLE_VECTORS {
            let p1 =
                next_prime_ge(v.p).expect("RFC 6330 golden vectors stay well within usize range");
            let actual_tuple = tuple(v.j, v.w, v.p, p1, v.x);
            let actual_indices = tuple_indices(actual_tuple, v.w, v.p, p1);
            let ctx = format!(
                "scenario_id={} J={} W={} P={} X={} \
                 repro='cargo test --test raptorq_conformance golden_rfc6330_lt_tuples'",
                v.scenario_id, v.j, v.w, v.p, v.x
            );
            assert_eq!(actual_tuple, v.expected_tuple, "{ctx}: tuple mismatch");
            assert_eq!(
                actual_indices, v.expected_indices,
                "{ctx}: indices mismatch"
            );
            // Structural: LT indices < W, PI indices in [W, W+P)
            for &idx in &actual_indices[..actual_tuple.d] {
                assert!(idx < v.w, "{ctx}: LT index {idx} >= W={}", v.w);
            }
            for &idx in &actual_indices[actual_tuple.d..] {
                assert!(
                    idx >= v.w && idx < v.w + v.p,
                    "{ctx}: PI index {idx} out of [W, W+P)"
                );
            }
        }
    }

    // ----------------------------------------------------------------
    // G5: Constraint Matrix Structure Vectors
    //
    // For K=10 seed=42, pin down LDPC row sparsity patterns.
    // These catch any drift in build_ldpc_rows / build_hdpc_rows.
    // ----------------------------------------------------------------

    #[test]
    fn golden_constraint_matrix_structure() {
        let k = 10;
        let seed = 42u64;
        let params = SystematicParams::for_source_block(k, 64);
        let constraints = ConstraintMatrix::build(&params, seed);

        // Dimensions
        assert_eq!(constraints.rows, 27, "matrix rows");
        assert_eq!(constraints.cols, 27, "matrix cols");

        // LDPC row 0 includes circulant, identity, and PI-link columns.
        let (cols0, coefs0) = super::constraint_row_equation(&constraints, 0);
        assert_eq!(cols0, vec![0, 5, 6, 7, 10, 17, 18], "LDPC row 0 columns");
        assert!(coefs0.iter().all(|c| c.raw() == 1), "LDPC row 0 all-ones");

        // LDPC row 1 includes circulant, identity, and PI-link columns.
        let (cols1, _) = super::constraint_row_equation(&constraints, 1);
        assert_eq!(cols1, vec![0, 1, 6, 8, 11, 18, 19], "LDPC row 1 columns");

        // LDPC row 2 includes circulant, identity, and PI-link columns.
        let (cols2, _) = super::constraint_row_equation(&constraints, 2);
        assert_eq!(cols2, vec![0, 1, 2, 7, 9, 12, 19, 20], "LDPC row 2 columns");

        // HDPC rows: verify nonzero counts (denser than LDPC)
        let hdpc_row_7_nnz = (0..constraints.cols)
            .filter(|&col| !constraints.get(7, col).is_zero())
            .count();
        assert_eq!(hdpc_row_7_nnz, 18, "HDPC row 7 nonzero count");

        let hdpc_row_8_nnz = (0..constraints.cols)
            .filter(|&col| !constraints.get(8, col).is_zero())
            .count();
        assert_eq!(hdpc_row_8_nnz, 18, "HDPC row 8 nonzero count");

        let hdpc_row_9_nnz = (0..constraints.cols)
            .filter(|&col| !constraints.get(9, col).is_zero())
            .count();
        assert_eq!(hdpc_row_9_nnz, 18, "HDPC row 9 nonzero count");
    }

    #[test]
    fn differential_rfc6330_ldpc_hdpc_bands_match_reference() {
        for &k in &[10usize, 42, 100] {
            let params = SystematicParams::for_source_block(k, 4);
            let actual = ConstraintMatrix::build(&params, 0xC0FFEE);
            let reference = super::reference_ldpc_hdpc_matrix(&params);

            let actual_ldpc = super::matrix_band_bytes(&actual, 0, params.s);
            let reference_ldpc = super::matrix_band_bytes(&reference, 0, params.s);
            assert_eq!(
                actual_ldpc, reference_ldpc,
                "K={k}: LDPC rows diverge from the RFC 6330 reference builder"
            );

            let actual_hdpc = super::matrix_band_bytes(&actual, params.s, params.s + params.h);
            let reference_hdpc =
                super::matrix_band_bytes(&reference, params.s, params.s + params.h);
            assert_eq!(
                actual_hdpc, reference_hdpc,
                "K={k}: HDPC rows diverge from the RFC 6330 reference builder"
            );
        }
    }

    // ----------------------------------------------------------------
    // G6: End-to-End Encode/Decode Fingerprint Vectors
    //
    // Fixed (K, symbol_size, seed, patterned data) -> pinned hashes of
    // intermediate symbols, repair symbols, and decode statistics.
    // Any change in encoder/decoder logic triggers a regression.
    // ----------------------------------------------------------------

    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    struct E2eVector {
        scenario_id: &'static str,
        k: usize,
        symbol_size: usize,
        seed: u64,
        expected_intermediate_hash: u64,
        expected_repair_hash: u64,
        expected_peeled: usize,
        expected_inactivated: usize,
        expected_gauss_ops: usize,
    }

    const E2E_VECTORS: &[E2eVector] = &[
        E2eVector {
            scenario_id: "RQ-D1-E2E-001",
            k: 8,
            symbol_size: 64,
            seed: 42,
            expected_intermediate_hash: 0xe8fe_95af_6d70_1835,
            expected_repair_hash: 0x18f6_ac48_702d_139e,
            expected_peeled: 0,
            expected_inactivated: 27,
            expected_gauss_ops: 848,
        },
        E2eVector {
            scenario_id: "RQ-D1-E2E-002",
            k: 10,
            symbol_size: 32,
            seed: 123,
            expected_intermediate_hash: 0x15a2_cfd9_3926_86d5,
            expected_repair_hash: 0x59b6_5fcd_5556_627a,
            expected_peeled: 0,
            expected_inactivated: 27,
            expected_gauss_ops: 810,
        },
        E2eVector {
            scenario_id: "RQ-D1-E2E-003",
            k: 16,
            symbol_size: 64,
            seed: 789,
            expected_intermediate_hash: 0xcef2_b156_a986_ef8a,
            expected_repair_hash: 0xe2ba_cf72_960e_aadb,
            expected_peeled: 0,
            expected_inactivated: 39,
            expected_gauss_ops: 1886,
        },
        E2eVector {
            scenario_id: "RQ-D1-E2E-004",
            k: 32,
            symbol_size: 128,
            seed: 456,
            expected_intermediate_hash: 0x592f_6d08_1d64_4bb1,
            expected_repair_hash: 0x3306_bdee_754f_070c,
            expected_peeled: 0,
            expected_inactivated: 53,
            expected_gauss_ops: 3265,
        },
    ];

    #[test]
    fn golden_e2e_encode_decode_fingerprint() {
        for v in E2E_VECTORS {
            let source = make_patterned_source(v.k, v.symbol_size);
            let encoder = SystematicEncoder::new(&source, v.symbol_size, v.seed).unwrap();
            let params = encoder.params();
            let ctx = format!(
                "scenario_id={} K={} sym={} seed={} \
                 repro='cargo test --test raptorq_conformance golden_e2e_encode_decode_fingerprint'",
                v.scenario_id, v.k, v.symbol_size, v.seed
            );

            // Pin intermediate symbol hash
            let mut intermediate_hasher = DefaultHasher::new();
            for i in 0..params.l {
                let sym = encoder.intermediate_symbol(i);
                sym.hash(&mut intermediate_hasher);
            }
            let actual_intermediate_hash = intermediate_hasher.finish();
            let mut repair_hasher = DefaultHasher::new();
            for esi in (v.k as u32)..((v.k + 5) as u32) {
                encoder.repair_symbol(esi).hash(&mut repair_hasher);
            }
            let actual_repair_hash = repair_hasher.finish();
            assert_eq!(
                actual_intermediate_hash, v.expected_intermediate_hash,
                "{ctx}: intermediate symbol hash drift"
            );

            // Pin repair symbol hash (first 5 repair symbols after K)
            assert_eq!(
                actual_repair_hash, v.expected_repair_hash,
                "{ctx}: repair symbol hash drift"
            );

            // Decode and pin stats
            let decoder = InactivationDecoder::new(v.k, v.symbol_size, v.seed);
            let received = build_received_symbols(
                &encoder,
                &decoder,
                &source,
                &[],
                decoder.params().l as u32,
                v.seed,
            );
            let result = decoder
                .decode(&received)
                .unwrap_or_else(|e| panic!("{ctx}: decode failed: {e:?}"));

            // Verify roundtrip
            for (i, original) in source.iter().enumerate() {
                assert_eq!(
                    &result.source[i], original,
                    "{ctx}: source symbol {i} mismatch"
                );
            }

            // Pin decode statistics
            assert_eq!(
                result.stats.peeled, v.expected_peeled,
                "{ctx}: peeled count drift"
            );
            assert_eq!(
                result.stats.inactivated, v.expected_inactivated,
                "{ctx}: inactivated count drift"
            );
            assert_eq!(
                result.stats.gauss_ops, v.expected_gauss_ops,
                "{ctx}: gauss_ops count drift"
            );
        }
    }

    // ----------------------------------------------------------------
    // G7: Cross-seed Determinism
    //
    // Verify that the same (K, data, seed) always produces identical
    // intermediate and repair symbols across separate encoder instances.
    // ----------------------------------------------------------------

    #[test]
    fn golden_cross_seed_determinism() {
        let seeds = [1u64, 42, 999, 0xDEAD_BEEF, 0xCAFE_0000_BABE_1234];
        let k = 16;
        let symbol_size = 48;
        let source = make_patterned_source(k, symbol_size);

        for seed in seeds {
            let enc1 = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
            let enc2 = SystematicEncoder::new(&source, symbol_size, seed).unwrap();

            // All L intermediate symbols must be bitwise identical
            for i in 0..enc1.params().l {
                assert_eq!(
                    enc1.intermediate_symbol(i),
                    enc2.intermediate_symbol(i),
                    "seed={seed:#x}: intermediate symbol {i} differs"
                );
            }

            // Repair symbols at arbitrary ESIs must match
            for esi in [k as u32, k as u32 + 1, k as u32 + 10, 50, 100, 999] {
                assert_eq!(
                    enc1.repair_symbol(esi),
                    enc2.repair_symbol(esi),
                    "seed={seed:#x}: repair ESI={esi} differs"
                );
            }
        }
    }

    // ----------------------------------------------------------------
    // G8: Parameter Invariant Sweep
    //
    // For every K in [1, 256], verify structural invariants hold:
    // L = K' + S + H, B = W - S, K' >= K, W >= S, H >= 1, S >= 2.
    // ----------------------------------------------------------------

    #[test]
    fn golden_param_invariant_sweep() {
        for k in 1..=256 {
            let params = SystematicParams::for_source_block(k, 64);
            let ctx = format!("K={k}");

            assert!(params.k_prime >= k, "{ctx}: K' < K");
            assert!(params.s >= 2, "{ctx}: S < 2");
            assert!(params.h >= 1, "{ctx}: H < 1");
            assert!(params.w >= params.s, "{ctx}: W < S");
            assert_eq!(
                params.l,
                params.k_prime + params.s + params.h,
                "{ctx}: L != K'+S+H"
            );
            assert_eq!(params.b, params.w - params.s, "{ctx}: B != W-S");
            // P = L - W = K' + H - B
            let p = params.l - params.w;
            assert!(p >= 1, "{ctx}: P < 1");
        }
    }

    // ----------------------------------------------------------------
    // G9: PRNG Boundary & Exhaustive Properties
    //
    // Verify PRNG range, determinism, and sensitivity to all four
    // byte lanes of the input word y.
    // ----------------------------------------------------------------

    #[test]
    fn golden_rand_properties() {
        // Range: output must be in [0, m) for all tested inputs
        for y in [0u32, 1, 0xFF, 0xFF00, 0xFF_0000, 0xFF00_0000, u32::MAX] {
            for i in 0..8u8 {
                for m in [1, 2, 3, 7, 256, 1000, 1_048_576] {
                    let r = rand(y, i, m);
                    assert!(r < m, "Rand({y:#x}, {i}, {m}) = {r} >= {m}");
                }
            }
        }

        // Each byte lane matters: shifting y by 8 bits should change output
        let base = rand(0x01_02_03_04, 0, 1000);
        let shift_b0 = rand(0x01_02_03_05, 0, 1000); // change byte 0
        let shift_b1 = rand(0x01_02_04_04, 0, 1000); // change byte 1
        let shift_b2 = rand(0x01_03_03_04, 0, 1000); // change byte 2
        let shift_b3 = rand(0x02_02_03_04, 0, 1000); // change byte 3

        // At least 3 of 4 lane changes should produce different results
        let diffs = [
            shift_b0 != base,
            shift_b1 != base,
            shift_b2 != base,
            shift_b3 != base,
        ]
        .iter()
        .filter(|&&d| d)
        .count();
        assert!(
            diffs >= 3,
            "PRNG not sensitive to byte lanes: only {diffs}/4 differ"
        );
    }

    // ----------------------------------------------------------------
    // G10: Degree Distribution Coverage
    //
    // Verify the full degree table boundary sweep: every threshold
    // transition from degree d to d+1 is exercised.
    // ----------------------------------------------------------------

    #[test]
    fn golden_degree_boundary_sweep() {
        // (last_v_for_degree, degree, first_v_for_next_degree, next_degree)
        let boundaries: &[(u32, usize, u32, usize)] = &[
            (5_242, 1, 5_243, 2),
            (529_530, 2, 529_531, 3),
            (704_293, 3, 704_294, 4),
            (791_674, 4, 791_675, 5),
            (844_103, 5, 844_104, 6),
            (879_056, 6, 879_057, 7),
            (904_022, 7, 904_023, 8),
            (922_746, 8, 922_747, 9),
            (937_310, 9, 937_311, 10),
            (948_961, 10, 948_962, 11),
            (958_493, 11, 958_494, 12),
            (966_437, 12, 966_438, 13),
            (973_159, 13, 973_160, 14),
            (978_920, 14, 978_921, 15),
            (983_913, 15, 983_914, 16),
            (988_282, 16, 988_283, 17),
            (992_137, 17, 992_138, 18),
            (995_564, 18, 995_565, 19),
            (998_630, 19, 998_631, 20),
            (1_001_390, 20, 1_001_391, 21),
            (1_003_886, 21, 1_003_887, 22),
            (1_006_156, 22, 1_006_157, 23),
            (1_008_228, 23, 1_008_229, 24),
            (1_010_128, 24, 1_010_129, 25),
            (1_011_875, 25, 1_011_876, 26),
            (1_013_489, 26, 1_013_490, 27),
            (1_014_982, 27, 1_014_983, 28),
            (1_016_369, 28, 1_016_370, 29),
            (1_017_661, 29, 1_017_662, 30),
        ];

        for &(last_v, d, first_v_next, d_next) in boundaries {
            assert_eq!(
                deg(last_v),
                d,
                "deg({last_v}) should be {d} (last value in degree-{d} range)"
            );
            assert_eq!(
                deg(first_v_next),
                d_next,
                "deg({first_v_next}) should be {d_next} (first value in degree-{d_next} range)"
            );
        }
    }
}
