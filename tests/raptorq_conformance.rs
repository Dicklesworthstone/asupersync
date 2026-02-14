//! RaptorQ conformance, property tests, and deterministic fuzz harness.
//!
//! This test suite validates:
//! - Roundtrip correctness: encode → drop → decode → verify
//! - Determinism: same inputs produce identical outputs
//! - Edge cases: empty, tiny, large blocks, various loss patterns
//! - Fuzz testing with fixed seeds for reproducibility

use asupersync::raptorq::decoder::{DecodeError, InactivationDecoder, ReceivedSymbol};
use asupersync::raptorq::gf256::Gf256;
use asupersync::raptorq::systematic::{
    ConstraintMatrix, RobustSoliton, SystematicEncoder, SystematicParams,
};
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
// Soliton distribution tests
// ============================================================================

#[test]
fn soliton_distribution_coverage() {
    let k_values = [10, 50, 100, 500];

    for k in k_values {
        let sol = RobustSoliton::new(k, 0.2, 0.05);
        let mut rng = DetRng::new(k as u64);

        let mut degrees = vec![0u32; k + 1];
        let samples = 10_000;

        for _ in 0..samples {
            let d = sol.sample(rng.next_u64() as u32);
            assert!(d >= 1 && d <= k, "k={k}: degree {d} out of range");
            degrees[d] += 1;
        }

        // Degree 2 should have significant mass (robust soliton concentrates
        // probability at degree 2 via the 1/(d*(d-1)) ideal soliton term).
        assert!(degrees[2] > 0, "k={k}: degree 2 should have nonzero mass");

        // The top degree (threshold region) should have significant mass
        // from the tau perturbation. Check that degrees aren't all
        // concentrated at a single value.
        let nonzero_degrees = degrees[1..].iter().filter(|&&c| c > 0).count();
        assert!(
            nonzero_degrees >= 3,
            "k={k}: should have at least 3 distinct degrees sampled"
        );
    }
}

#[test]
fn soliton_deterministic_across_runs() {
    let k = 50;
    let sol = RobustSoliton::new(k, 0.2, 0.05);

    let generate = |seed: u64| -> Vec<usize> {
        let mut rng = DetRng::new(seed);
        (0..1000)
            .map(|_| sol.sample(rng.next_u64() as u32))
            .collect()
    };

    let run1 = generate(42);
    let run2 = generate(42);
    let run3 = generate(99);

    assert_eq!(run1, run2, "same seed should produce same sequence");
    assert_ne!(run1, run3, "different seeds should differ");
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
    use asupersync::security::tag::AuthenticationTag;
    use asupersync::security::AuthenticatedSymbol;
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
        scenario: &'static str,
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
        if seed == 0 {
            1
        } else {
            seed
        }
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
        let raptor_decoder = InactivationDecoder::new(block_k, symbol_size, block_seed);
        let received_for_proof =
            build_received_symbols(&received_symbols, object_id, block_k, symbol_size, sbn);

        let proof = match raptor_decoder.decode_with_proof(&received_for_proof, object_id, sbn) {
            Ok(result) => {
                assert!(scenario.expect_success, "unexpected proof success");
                result.proof
            }
            Err((err, proof)) => {
                assert!(!scenario.expect_success, "unexpected proof failure {err:?}");
                match err {
                    DecodeError::InsufficientSymbols { .. } => {}
                    DecodeError::SingularMatrix { .. } | DecodeError::SymbolSizeMismatch { .. } => {
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
            scenario: scenario.name,
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
                loss: LossPattern::None,
                expect_success: true,
            },
            Scenario {
                name: "typical_random_loss",
                loss: LossPattern::Random {
                    seed: 0xBEEF_u64,
                    drop_per_mille: 200,
                },
                expect_success: true,
            },
            Scenario {
                name: "burst_loss_late",
                loss: LossPattern::Burst {
                    drop_per_mille: 250,
                    position: BurstPosition::Late,
                },
                expect_success: true,
            },
            Scenario {
                name: "insufficient_symbols",
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
            assert_eq!(report_first, report_second, "report JSON mismatch");
            assert_eq!(success_first, success_second, "success mismatch");
        }
    }
}
