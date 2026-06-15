//! RaptorQ GF(256) dual-slice bulk-kernel conformance.
//!
//! bd-3uox5 (RAPTORQ-RFC6330) AC3 (property/metamorphic checks) + AC7
//! (optimization inside proven-safe envelopes). The decoder's hot inner loops
//! fuse two source/destination pairs into one dispatch lookup so a single
//! kernel selection (scalar / AVX2 / NEON) amortizes setup across both lanes.
//! These fused bulk kernels in `src/raptorq/gf256.rs` had ZERO integration
//! coverage:
//!   - `gf256_add_slice`        (`dst[i] ^= src[i]`)
//!   - `gf256_add_slices2`      (two independent XOR pairs, fused)
//!   - `gf256_addmul_slices2`   (two independent `dst += c*src` pairs, fused)
//!
//! so nothing pinned the contract that the optimization must preserve: the
//! observable result is defined purely by GF(256) arithmetic and must be
//! byte-identical to the naive scalar computation on EVERY execution path
//! (32-byte wide / 8-byte tail / scalar tail, and per-lane-dispatch vs
//! arch-wide-fused for the dual kernels), independent of CPU features.
//!
//! The proofs are oracle-free: GF(256) addition is XOR and multiply-accumulate
//! is `dst ^ (c·src)` via the field's `mul_field`, both recomputed directly
//! here. We assert (1) differential equality vs the scalar oracle, (2) that the
//! fused dual kernels equal two independent single-pair calls, (3) field
//! identities (XOR involution, c==0 no-op, c==1 ≡ XOR), (4) cross-lane
//! independence, and (5) the documented length-mismatch panic contract.
//!
//! All targets are unconditionally-public free functions over byte slices, so
//! the harness needs no features and runs no decode.
//!
//! Repro: `cargo test --test raptorq_gf256_dual_slice_kernel_conformance`

use asupersync::raptorq::gf256::{
    Gf256, gf256_add_slice, gf256_add_slices2, gf256_addmul_slice, gf256_addmul_slices2,
};

// ---------------------------------------------------------------------------
// Deterministic fixtures + scalar oracles
// ---------------------------------------------------------------------------

/// Deterministic pseudo-random byte fill (xorshift64) — no `rand` dependency,
/// fully replayable from `seed`.
fn pseudo_bytes(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state & 0xFF) as u8
        })
        .collect()
}

/// Scalar oracle for `dst[i] ^= src[i]` (GF(256) addition == XOR).
fn oracle_add(dst: &mut [u8], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src) {
        *d ^= *s;
    }
}

/// Scalar oracle for `dst[i] += c * src[i]` (GF(256) multiply-accumulate).
fn oracle_addmul(dst: &mut [u8], src: &[u8], c: Gf256) {
    for (d, s) in dst.iter_mut().zip(src) {
        *d = Gf256::new(*d).add(c.mul_field(Gf256::new(*s))).raw();
    }
}

/// True iff `f` unwinds. Silences the panic hook so the expected panic does not
/// spam test output. Closures own their data, so they are unwind-safe.
fn panics(f: impl FnOnce() + std::panic::UnwindSafe) -> bool {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let result = std::panic::catch_unwind(f);
    std::panic::set_hook(prev);
    result.is_err()
}

/// Lengths chosen to straddle the 32-byte-wide / 8-byte / scalar tail
/// boundaries inside the bulk kernels.
const LENS: &[usize] = &[
    0, 1, 3, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 100, 127, 128, 255, 256,
];

/// Asymmetric pair lengths exercise the per-lane-dispatch vs arch-wide-fused
/// execution-path policy for the dual kernels.
const PAIR_LENS: &[(usize, usize)] = &[
    (0, 0),
    (0, 32),
    (32, 0),
    (1, 1),
    (32, 32),
    (32, 16),
    (16, 32),
    (33, 31),
    (31, 33),
    (64, 8),
    (8, 64),
    (100, 7),
    (7, 100),
    (255, 256),
    (256, 255),
];

fn coeffs() -> Vec<Gf256> {
    vec![
        Gf256::ZERO,
        Gf256::ONE,
        Gf256::ALPHA,
        Gf256::new(2),
        Gf256::new(0x53),
        Gf256::new(0xAB),
        Gf256::new(0xFF),
    ]
}

// ---------------------------------------------------------------------------
// gf256_add_slice — single-pair XOR
// ---------------------------------------------------------------------------

#[test]
fn add_slice_matches_scalar_xor_across_tail_paths() {
    for (i, &len) in LENS.iter().enumerate() {
        let mut dst = pseudo_bytes(len, 0x1000 + i as u64);
        let src = pseudo_bytes(len, 0x2000 + i as u64);

        let mut expected = dst.clone();
        oracle_add(&mut expected, &src);

        gf256_add_slice(&mut dst, &src);
        assert_eq!(
            dst, expected,
            "gf256_add_slice diverged from scalar XOR at len {len}"
        );
    }
}

#[test]
fn add_slice_is_involutive() {
    // XOR is its own inverse: adding the same source twice restores the input.
    for (i, &len) in LENS.iter().enumerate() {
        let original = pseudo_bytes(len, 0x3000 + i as u64);
        let src = pseudo_bytes(len, 0x4000 + i as u64);

        let mut dst = original.clone();
        gf256_add_slice(&mut dst, &src);
        gf256_add_slice(&mut dst, &src);
        assert_eq!(dst, original, "double-add must be identity at len {len}");
    }
}

#[test]
fn add_slice_zero_source_is_identity() {
    for (i, &len) in LENS.iter().enumerate() {
        let original = pseudo_bytes(len, 0x5000 + i as u64);
        let zeros = vec![0u8; len];

        let mut dst = original.clone();
        gf256_add_slice(&mut dst, &zeros);
        assert_eq!(dst, original, "XOR with zero must be identity at len {len}");
    }
}

#[test]
fn add_slice_empty_is_noop_and_mismatch_panics() {
    // Empty slices: no panic, no change.
    let mut empty: Vec<u8> = Vec::new();
    gf256_add_slice(&mut empty, &[]);
    assert!(empty.is_empty());

    // Documented length-mismatch panic (both directions).
    assert!(
        panics(|| {
            let mut dst = vec![0u8; 3];
            let src = vec![0u8; 4];
            gf256_add_slice(&mut dst, &src);
        }),
        "dst shorter than src must panic"
    );
    assert!(
        panics(|| {
            let mut dst = vec![0u8; 5];
            let src = vec![0u8; 2];
            gf256_add_slice(&mut dst, &src);
        }),
        "dst longer than src must panic"
    );
}

// ---------------------------------------------------------------------------
// gf256_add_slices2 — fused dual XOR
// ---------------------------------------------------------------------------

#[test]
fn add_slices2_equals_two_independent_single_adds() {
    for (i, &(la, lb)) in PAIR_LENS.iter().enumerate() {
        let dst_a0 = pseudo_bytes(la, 0x6000 + i as u64);
        let src_a = pseudo_bytes(la, 0x6100 + i as u64);
        let dst_b0 = pseudo_bytes(lb, 0x6200 + i as u64);
        let src_b = pseudo_bytes(lb, 0x6300 + i as u64);

        // Sequential single-pair reference.
        let mut ref_a = dst_a0.clone();
        let mut ref_b = dst_b0.clone();
        gf256_add_slice(&mut ref_a, &src_a);
        gf256_add_slice(&mut ref_b, &src_b);

        // Scalar oracle reference (independent of the kernel entirely).
        let mut oracle_a = dst_a0.clone();
        let mut oracle_b = dst_b0.clone();
        oracle_add(&mut oracle_a, &src_a);
        oracle_add(&mut oracle_b, &src_b);
        assert_eq!(ref_a, oracle_a, "single add vs oracle (a) at ({la},{lb})");
        assert_eq!(ref_b, oracle_b, "single add vs oracle (b) at ({la},{lb})");

        // Fused dual kernel must match both.
        let mut dst_a = dst_a0;
        let mut dst_b = dst_b0;
        gf256_add_slices2(&mut dst_a, &src_a, &mut dst_b, &src_b);
        assert_eq!(dst_a, ref_a, "fused add_slices2 lane a at ({la},{lb})");
        assert_eq!(dst_b, ref_b, "fused add_slices2 lane b at ({la},{lb})");
    }
}

#[test]
fn add_slices2_lanes_are_independent() {
    // Lane B's source is all-zero: lane B must be byte-identical to its input
    // regardless of what lane A does — proves no cross-lane contamination even
    // when the lanes have different lengths.
    let la = 33;
    let lb = 17;
    let original_b = vec![0x22u8; lb];

    let mut dst_a = vec![0x11u8; la];
    let src_a = vec![0xFFu8; la];
    let mut dst_b = original_b.clone();
    let src_b = vec![0x00u8; lb];

    gf256_add_slices2(&mut dst_a, &src_a, &mut dst_b, &src_b);

    assert_eq!(dst_a, vec![0xEEu8; la], "lane a = 0x11 ^ 0xFF = 0xEE");
    assert_eq!(dst_b, original_b, "lane b (zero source) must be untouched");
}

#[test]
fn add_slices2_length_mismatch_panics_either_lane() {
    assert!(
        panics(|| {
            let mut da = vec![0u8; 3];
            let sa = vec![0u8; 4];
            let mut db = vec![0u8; 8];
            let sb = vec![0u8; 8];
            gf256_add_slices2(&mut da, &sa, &mut db, &sb);
        }),
        "lane a mismatch must panic"
    );
    assert!(
        panics(|| {
            let mut da = vec![0u8; 8];
            let sa = vec![0u8; 8];
            let mut db = vec![0u8; 5];
            let sb = vec![0u8; 2];
            gf256_add_slices2(&mut da, &sa, &mut db, &sb);
        }),
        "lane b mismatch must panic"
    );
}

// ---------------------------------------------------------------------------
// gf256_addmul_slices2 — fused dual multiply-accumulate
// ---------------------------------------------------------------------------

#[test]
fn addmul_slices2_zero_coeff_is_noop() {
    for (i, &(la, lb)) in PAIR_LENS.iter().enumerate() {
        let dst_a0 = pseudo_bytes(la, 0x7000 + i as u64);
        let src_a = pseudo_bytes(la, 0x7100 + i as u64);
        let dst_b0 = pseudo_bytes(lb, 0x7200 + i as u64);
        let src_b = pseudo_bytes(lb, 0x7300 + i as u64);

        let mut dst_a = dst_a0.clone();
        let mut dst_b = dst_b0.clone();
        gf256_addmul_slices2(&mut dst_a, &src_a, &mut dst_b, &src_b, Gf256::ZERO);
        assert_eq!(
            dst_a, dst_a0,
            "c==0 must leave lane a untouched ({la},{lb})"
        );
        assert_eq!(
            dst_b, dst_b0,
            "c==0 must leave lane b untouched ({la},{lb})"
        );
    }
}

#[test]
fn addmul_slices2_unit_coeff_equals_dual_xor() {
    // c==1 is documented to route through the dual-add fast path, so it must be
    // byte-identical to gf256_add_slices2.
    for (i, &(la, lb)) in PAIR_LENS.iter().enumerate() {
        let dst_a0 = pseudo_bytes(la, 0x8000 + i as u64);
        let src_a = pseudo_bytes(la, 0x8100 + i as u64);
        let dst_b0 = pseudo_bytes(lb, 0x8200 + i as u64);
        let src_b = pseudo_bytes(lb, 0x8300 + i as u64);

        let mut xor_a = dst_a0.clone();
        let mut xor_b = dst_b0.clone();
        gf256_add_slices2(&mut xor_a, &src_a, &mut xor_b, &src_b);

        let mut mac_a = dst_a0;
        let mut mac_b = dst_b0;
        gf256_addmul_slices2(&mut mac_a, &src_a, &mut mac_b, &src_b, Gf256::ONE);
        assert_eq!(mac_a, xor_a, "c==1 lane a must equal XOR at ({la},{lb})");
        assert_eq!(mac_b, xor_b, "c==1 lane b must equal XOR at ({la},{lb})");
    }
}

#[test]
fn addmul_slices2_matches_scalar_and_sequential_for_all_coeffs() {
    for c in coeffs() {
        for (i, &(la, lb)) in PAIR_LENS.iter().enumerate() {
            let dst_a0 = pseudo_bytes(la, 0x9000 + i as u64 + (c.raw() as u64) * 31);
            let src_a = pseudo_bytes(la, 0x9100 + i as u64 + (c.raw() as u64) * 31);
            let dst_b0 = pseudo_bytes(lb, 0x9200 + i as u64 + (c.raw() as u64) * 31);
            let src_b = pseudo_bytes(lb, 0x9300 + i as u64 + (c.raw() as u64) * 31);

            // Sequential single-pair reference (gf256_addmul_slice already has
            // coverage, so it is a sound cross-check)...
            let mut seq_a = dst_a0.clone();
            let mut seq_b = dst_b0.clone();
            gf256_addmul_slice(&mut seq_a, &src_a, c);
            gf256_addmul_slice(&mut seq_b, &src_b, c);

            // ...and the fully independent scalar oracle grounds it.
            let mut oracle_a = dst_a0.clone();
            let mut oracle_b = dst_b0.clone();
            oracle_addmul(&mut oracle_a, &src_a, c);
            oracle_addmul(&mut oracle_b, &src_b, c);
            assert_eq!(
                seq_a,
                oracle_a,
                "single addmul vs oracle lane a (c={}, {la},{lb})",
                c.raw()
            );
            assert_eq!(
                seq_b,
                oracle_b,
                "single addmul vs oracle lane b (c={}, {la},{lb})",
                c.raw()
            );

            // Fused dual kernel must match both references on every path.
            let mut dst_a = dst_a0;
            let mut dst_b = dst_b0;
            gf256_addmul_slices2(&mut dst_a, &src_a, &mut dst_b, &src_b, c);
            assert_eq!(
                dst_a,
                seq_a,
                "fused addmul_slices2 lane a (c={}, {la},{lb})",
                c.raw()
            );
            assert_eq!(
                dst_b,
                seq_b,
                "fused addmul_slices2 lane b (c={}, {la},{lb})",
                c.raw()
            );
        }
    }
}

#[test]
fn addmul_slices2_lanes_are_independent() {
    // Lane B source all-zero ⇒ lane B untouched for any coeff; lane A changes.
    for c in coeffs()
        .into_iter()
        .filter(|c| !c.is_zero() && *c != Gf256::ONE)
    {
        let la = 65;
        let lb = 9;
        let original_a = vec![0x10u8; la];
        let original_b = vec![0x20u8; lb];

        let mut dst_a = original_a.clone();
        let src_a = vec![0x01u8; la];
        let mut dst_b = original_b.clone();
        let src_b = vec![0x00u8; lb];

        let mut expected_a = original_a.clone();
        oracle_addmul(&mut expected_a, &src_a, c);

        gf256_addmul_slices2(&mut dst_a, &src_a, &mut dst_b, &src_b, c);

        assert_eq!(
            dst_a,
            expected_a,
            "lane a must follow the oracle (c={})",
            c.raw()
        );
        assert_ne!(
            dst_a,
            original_a,
            "lane a must actually change (c={}, src=1)",
            c.raw()
        );
        assert_eq!(
            dst_b,
            original_b,
            "lane b (zero source) must be untouched (c={})",
            c.raw()
        );
    }
}

#[test]
fn addmul_slices2_length_mismatch_panics_either_lane() {
    assert!(
        panics(|| {
            let mut da = vec![0u8; 3];
            let sa = vec![0u8; 4];
            let mut db = vec![0u8; 8];
            let sb = vec![0u8; 8];
            gf256_addmul_slices2(&mut da, &sa, &mut db, &sb, Gf256::new(0x53));
        }),
        "lane a mismatch must panic"
    );
    assert!(
        panics(|| {
            let mut da = vec![0u8; 8];
            let sa = vec![0u8; 8];
            let mut db = vec![0u8; 5];
            let sb = vec![0u8; 2];
            gf256_addmul_slices2(&mut da, &sa, &mut db, &sb, Gf256::new(0x53));
        }),
        "lane b mismatch must panic"
    );
}
