//! RaptorQ conformance, property tests, and deterministic fuzz harness.
//!
//! This test suite validates:
//! - Roundtrip correctness: encode → drop → decode → verify
//! - Determinism: same inputs produce identical outputs
//! - Edge cases: empty, tiny, large blocks, various loss patterns
//! - Fuzz testing with fixed seeds for reproducibility

use asupersync::raptorq::decoder::{DecodeError, InactivationDecoder, ReceivedSymbol};
use asupersync::raptorq::gf256::Gf256;
use asupersync::raptorq::systematic::{ConstraintMatrix, SystematicEncoder, SystematicParams};
use asupersync::util::DetRng;

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

fn build_received_symbols(
    encoder: &SystematicEncoder,
    decoder: &InactivationDecoder,
    source: &[Vec<u8>],
    drop_source_indices: &[usize],
    max_repair_esi: u32,
    seed: u64,
) -> Vec<ReceivedSymbol> {
    let k = source.len();
    let params = decoder.params();
    let base_rows = params.s + params.h;
    let constraints = ConstraintMatrix::build(params, seed);

    // Start with constraint symbols (LDPC + HDPC parity checks with zero RHS).
    let mut received = decoder.constraint_symbols();

    // Add source symbols with their LT encoding equations from the constraint
    // matrix (rows S+H .. S+H+K-1), not identity equations.
    for (i, data) in source.iter().enumerate() {
        if !drop_source_indices.contains(&i) {
            let row = base_rows + i;
            let (columns, coefficients) = constraint_row_equation(&constraints, row);
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
        let (cols, coefs) = decoder.repair_equation(esi);
        let repair_data = encoder.repair_symbol(esi);
        received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
    }

    received
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

    for esi in 0..50u32 {
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
            let (columns, coefficients) = params.rfc_repair_equation(esi);
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
            .map(|esi| params.rfc_repair_equation(esi).0)
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
        hash: u64,
        received_total: usize,
        peeling_solved: usize,
        inactivated: usize,
        pivots: usize,
        row_ops: usize,
        outcome: String,
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
        let params = decoder.params();
        let base_rows = params.s + params.h;
        let constraints = ConstraintMatrix::build(params, seed);

        let mut received = decoder.constraint_symbols();

        for symbol in symbols.iter().filter(|sym| sym.sbn() == sbn) {
            match symbol.kind() {
                SymbolKind::Source => {
                    let esi = symbol.esi() as usize;
                    let row = base_rows + esi;
                    let (columns, coefficients) = constraint_row_equation(&constraints, row);
                    received.push(ReceivedSymbol {
                        esi: symbol.esi(),
                        is_source: true,
                        columns,
                        coefficients,
                        data: symbol.data().to_vec(),
                    });
                }
                SymbolKind::Repair => {
                    let (columns, coefficients) = decoder.repair_equation(symbol.esi());
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
            FailureReason::SingularMatrix { .. } => RejectReason::InconsistentEquations,
            FailureReason::SymbolSizeMismatch { .. } => RejectReason::SymbolSizeMismatch,
            FailureReason::SymbolEquationArityMismatch { .. } => {
                RejectReason::InconsistentEquations
            }
        }
    }

    fn proof_report(proof: &asupersync::raptorq::DecodeProof) -> ProofReport {
        let hash = proof.content_hash();
        let outcome = match &proof.outcome {
            ProofOutcome::Success { .. } => "success".to_string(),
            ProofOutcome::Failure { reason } => format!("{reason:?}"),
        };
        let summary = ProofSummary {
            version: proof.version,
            hash,
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
            hash,
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
    ) -> (String, u64, u64, bool) {
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
                    | DecodeError::SymbolEquationArityMismatch { .. } => {
                        panic!("unexpected decode error {err:?}");
                    }
                }
                proof
            }
        };

        proof
            .replay_and_verify(&received_for_proof)
            .expect("proof replay");

        let proof_hash = proof.content_hash();
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
        assert_eq!(
            phase_markers.len(),
            5,
            "expected five deterministic phase markers"
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
// Metamorphic + Property Erasure-Recovery Test Battery (bd-3syrq / D3)
//
// Deterministic property-based tests that verify codec invariants hold
// under varied erasure patterns, symbol orderings, and parameter regimes.
// Every test uses fixed seeds for full reproducibility.
// ============================================================================

mod metamorphic_property {
    use super::*;
    use asupersync::raptorq::rfc6330::rand;

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

        match decoder.decode(&received) {
            // Expected errors for insufficient / rank-deficient systems.
            Err(DecodeError::InsufficientSymbols { .. } | DecodeError::SingularMatrix { .. }) => {}
            Err(e) => panic!("unexpected error variant: {e:?}"),
            Ok(result) => {
                // If decode somehow succeeds, it MUST be correct
                for (i, (orig, dec)) in source.iter().zip(result.source.iter()).enumerate() {
                    assert_eq!(
                        orig, dec,
                        "decoder succeeded with insufficient symbols but symbol {i} is corrupt!"
                    );
                }
            }
        }
    }

    // ----------------------------------------------------------------
    // P10: Seed Sensitivity
    //
    // Metamorphic: changing only the seed (with same source data)
    // must produce different intermediate and repair symbols.
    // ----------------------------------------------------------------

    #[test]
    fn seed_sensitivity() {
        let k = 10;
        let symbol_size = 64;
        let source = make_source_data(k, symbol_size, 42);

        let enc_a = SystematicEncoder::new(&source, symbol_size, 42).unwrap();
        let enc_b = SystematicEncoder::new(&source, symbol_size, 43).unwrap();

        // At least one repair symbol should differ
        let mut any_differ = false;
        for esi in (k as u32)..(k as u32 + 5) {
            if enc_a.repair_symbol(esi) != enc_b.repair_symbol(esi) {
                any_differ = true;
                break;
            }
        }
        assert!(
            any_differ,
            "different seeds produced identical repair symbols"
        );
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

        let mut successes = 0;
        for seed in 0u64..50 {
            let source = make_source_data(k, symbol_size, seed);
            let drop_set = random_drop_set(k, num_erasures, seed + 5000);

            let Ok(decoded) = roundtrip(k, symbol_size, seed, &drop_set, extra_repair) else {
                continue; // skip seeds where encoder matrix is singular
            };

            successes += 1;
            for (i, (orig, dec)) in source.iter().zip(decoded.iter()).enumerate() {
                assert_eq!(orig, dec, "seed={seed}: symbol {i} mismatch");
            }
        }
        // At least 80% of seeds should work
        assert!(successes >= 40, "too few successful seeds: {successes}/50");
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
            let (cols, coefs) = decoder.repair_equation(esi);

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
            let p1 = next_prime_ge(v.p);
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

        // LDPC row 0: nonzero at columns [0, 5, 6, 7, 10] with GF(1) coefficients
        let (cols0, coefs0) = super::constraint_row_equation(&constraints, 0);
        assert_eq!(cols0, vec![0, 5, 6, 7, 10], "LDPC row 0 columns");
        assert!(coefs0.iter().all(|c| c.raw() == 1), "LDPC row 0 all-ones");

        // LDPC row 1: nonzero at columns [0, 1, 6, 8, 11]
        let (cols1, _) = super::constraint_row_equation(&constraints, 1);
        assert_eq!(cols1, vec![0, 1, 6, 8, 11], "LDPC row 1 columns");

        // LDPC row 2: nonzero at columns [0, 1, 2, 7, 9, 12]
        let (cols2, _) = super::constraint_row_equation(&constraints, 2);
        assert_eq!(cols2, vec![0, 1, 2, 7, 9, 12], "LDPC row 2 columns");

        // HDPC rows: verify nonzero counts (denser than LDPC)
        let hdpc_row_7_nnz = (0..constraints.cols)
            .filter(|&col| !constraints.get(7, col).is_zero())
            .count();
        assert_eq!(hdpc_row_7_nnz, 6, "HDPC row 7 nonzero count");

        let hdpc_row_8_nnz = (0..constraints.cols)
            .filter(|&col| !constraints.get(8, col).is_zero())
            .count();
        assert_eq!(hdpc_row_8_nnz, 7, "HDPC row 8 nonzero count");

        let hdpc_row_9_nnz = (0..constraints.cols)
            .filter(|&col| !constraints.get(9, col).is_zero())
            .count();
        assert_eq!(hdpc_row_9_nnz, 10, "HDPC row 9 nonzero count");
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
            expected_intermediate_hash: 0x579f_9e2c_82de_fa6e,
            expected_repair_hash: 0x423d_1c47_449f_1164,
            expected_peeled: 27,
            expected_inactivated: 0,
            expected_gauss_ops: 0,
        },
        E2eVector {
            scenario_id: "RQ-D1-E2E-002",
            k: 10,
            symbol_size: 32,
            seed: 123,
            expected_intermediate_hash: 0xe5d2_2d12_0286_3324,
            expected_repair_hash: 0x7d5e_22c9_b3a0_73d4,
            expected_peeled: 27,
            expected_inactivated: 0,
            expected_gauss_ops: 0,
        },
        E2eVector {
            scenario_id: "RQ-D1-E2E-003",
            k: 16,
            symbol_size: 64,
            seed: 789,
            expected_intermediate_hash: 0x561d_3e08_946d_dc38,
            expected_repair_hash: 0x4052_2112_cdad_996f,
            expected_peeled: 39,
            expected_inactivated: 0,
            expected_gauss_ops: 0,
        },
        E2eVector {
            scenario_id: "RQ-D1-E2E-004",
            k: 32,
            symbol_size: 128,
            seed: 456,
            expected_intermediate_hash: 0x644a_bddf_63a0_08bd,
            expected_repair_hash: 0x6c9c_2e69_8309_03d1,
            expected_peeled: 53,
            expected_inactivated: 0,
            expected_gauss_ops: 0,
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
            assert_eq!(
                intermediate_hasher.finish(),
                v.expected_intermediate_hash,
                "{ctx}: intermediate symbol hash drift"
            );

            // Pin repair symbol hash (first 5 repair symbols after K)
            let mut repair_hasher = DefaultHasher::new();
            for esi in (v.k as u32)..((v.k + 5) as u32) {
                encoder.repair_symbol(esi).hash(&mut repair_hasher);
            }
            assert_eq!(
                repair_hasher.finish(),
                v.expected_repair_hash,
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
            for esi in [0u32, 1, 10, 50, 100, 999] {
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
