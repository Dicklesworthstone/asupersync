//! RaptorQ conformance, property tests, and deterministic fuzz harness.
//!
//! This test suite validates:
//! - Roundtrip correctness: encode → drop → decode → verify
//! - Determinism: same inputs produce identical outputs
//! - Edge cases: empty, tiny, large blocks, various loss patterns
//! - Fuzz testing with fixed seeds for reproducibility

use asupersync::raptorq::decoder::{DecodeError, InactivationDecoder, ReceivedSymbol};
use asupersync::raptorq::gf256::Gf256;
use asupersync::raptorq::systematic::{RobustSoliton, SystematicEncoder, SystematicParams};
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
fn build_received_symbols(
    encoder: &SystematicEncoder,
    decoder: &InactivationDecoder,
    source: &[Vec<u8>],
    drop_source_indices: &[usize],
    max_repair_esi: u32,
) -> Vec<ReceivedSymbol> {
    let k = source.len();
    let mut received = Vec::new();

    // Add source symbols (except dropped)
    for (i, data) in source.iter().enumerate() {
        if !drop_source_indices.contains(&i) {
            received.push(ReceivedSymbol::source(i as u32, data.clone()));
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
    let received = build_received_symbols(&encoder, &decoder, &source, &[], l as u32);

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
    let received = build_received_symbols(&encoder, &decoder, &source, &drop_indices, max_repair);

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
    let received = build_received_symbols(&encoder, &decoder, &source, &drop_indices, max_repair);

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

    let received = build_received_symbols(&encoder, &decoder, &source, &[], l as u32);

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
        let drop: Vec<usize> = (0..k).filter(|i| (i + seed as usize) % 3 == 0).collect();
        let max_repair = (l + drop.len()) as u32;
        let received = build_received_symbols(&encoder, &decoder, &source, &drop, max_repair);

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

    let received = build_received_symbols(&encoder, &decoder, &source, &[], l as u32);

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

    let received = build_received_symbols(&encoder, &decoder, &source, &[], l as u32);

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

    let received = build_received_symbols(&encoder, &decoder, &source, &[], l as u32);

    let result = decoder.decode(&received).expect("tiny symbol decode failed");
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

    let received = build_received_symbols(&encoder, &decoder, &source, &[], l as u32);

    let result = decoder.decode(&received).expect("large symbol decode failed");
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
    let received = build_received_symbols(&encoder, &decoder, &source, &drop, max_repair);

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
    let l = decoder.params().l;

    // Only receive k-1 source symbols (not enough)
    let received: Vec<ReceivedSymbol> = source[..l - 1]
        .iter()
        .enumerate()
        .map(|(i, data)| ReceivedSymbol::source(i as u32, data.clone()))
        .collect();

    let err = decoder.decode(&received).unwrap_err();
    assert!(
        matches!(err, DecodeError::InsufficientSymbols { .. }),
        "expected InsufficientSymbols, got {:?}",
        err
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
        "expected SymbolSizeMismatch, got {:?}",
        err
    );
}

// ============================================================================
// Deterministic fuzz harness
// ============================================================================

/// Fuzz test with deterministic seeds for reproducibility.
#[test]
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
        let received = build_received_symbols(&encoder, &decoder, &source, &drop, max_repair);

        let result = decoder
            .decode(&received)
            .unwrap_or_else(|e| panic!("fuzz case k={k}, seed={seed} failed: {:?}", e));

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
        let received = build_received_symbols(&encoder, &decoder, &source, &drop, max_repair);

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

        let received = build_received_symbols(&encoder, &decoder, &source, &[], l as u32);

        let result = decoder
            .decode(&received)
            .unwrap_or_else(|e| panic!("stress iteration {iteration} failed: {:?}", e));

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

        // Degree 1 should be most common
        assert!(
            degrees[1] > degrees[2],
            "k={k}: degree 1 should be most common"
        );

        // Low degrees should dominate
        let low_total: u32 = degrees[1..=5.min(k)].iter().sum();
        assert!(
            low_total > samples as u32 / 2,
            "k={k}: low degrees should dominate, got {low_total}/{samples}"
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
        assert!(params.s >= 2, "k={k}: S should be at least 2");
        assert!(params.h >= 1, "k={k}: H should be at least 1");
        assert_eq!(
            params.l,
            params.k + params.s + params.h,
            "k={k}: L = K + S + H"
        );
    }
}

#[test]
fn params_overhead_bounded() {
    // Overhead should be reasonable (not excessive)
    for k in [10, 50, 100, 500] {
        let params = SystematicParams::for_source_block(k, 64);
        let overhead = params.l - params.k;
        let overhead_pct = overhead as f64 / k as f64;

        // Overhead should be less than 50% for reasonable k
        assert!(
            overhead_pct < 0.5,
            "k={k}: overhead {overhead_pct:.2}% too high"
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
            "alpha^{i} = {} already seen, not a generator",
            val
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
