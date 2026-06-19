//! RFC 6330 systematic-encoder linearity metamorphic relations (bead bd-3uox5).
//!
//! For a fixed `(K, symbol_size, seed)` the systematic encoder is a fixed
//! GF(256)-linear map from the source symbols to every repair symbol: the
//! constraint matrix and tuple schedule depend only on `K` and the seed, never
//! on source *content*, and the intermediate symbols are obtained by solving
//! that matrix with the source as the right-hand side. Repair symbols are then
//! fixed linear combinations of the intermediate symbols. Two consequences hold
//! for ANY source block, with no plaintext oracle:
//!
//! 1. **Additive homomorphism** — `repair_{S1 (+) S2}(esi)` equals
//!    `repair_{S1}(esi) (+) repair_{S2}(esi)` for every repair ESI, where `(+)`
//!    is symbol-wise GF(256) addition (XOR).
//! 2. **Zero-source annihilation** — encoding an all-zero source yields all-zero
//!    repair symbols (the linear image of the zero vector is zero).
//!
//! These catch non-linear corruption in the GF(256) multiply-add hot path that
//! a plaintext round-trip cannot: a decoder that inverts the *same* wrong-but-
//! self-consistent map still round-trips, but a map that is not additively
//! linear in the source breaks relation 1. Inputs use fixed `DetRng` seeds.
//!
//! # Repro
//!
//! ```text
//! rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_target_asupersync_test \
//!   cargo test --test raptorq_encoder_linearity_metamorphic -- --nocapture
//! ```

#![allow(missing_docs)]

use asupersync::raptorq::systematic::SystematicEncoder;
use asupersync::util::DetRng;

fn make_source(k: usize, symbol_size: usize, seed: u64) -> Vec<Vec<u8>> {
    let mut rng = DetRng::new(seed);
    (0..k)
        .map(|_| {
            (0..symbol_size)
                .map(|_| (rng.next_u64() & 0xFF) as u8)
                .collect()
        })
        .collect()
}

/// Symbol-wise GF(256) addition (XOR) of two equally shaped source blocks.
fn xor_sources(a: &[Vec<u8>], b: &[Vec<u8>]) -> Vec<Vec<u8>> {
    assert_eq!(a.len(), b.len(), "source blocks must share K");
    a.iter()
        .zip(b.iter())
        .map(|(sa, sb)| {
            assert_eq!(sa.len(), sb.len(), "symbols must share size");
            sa.iter().zip(sb.iter()).map(|(x, y)| x ^ y).collect()
        })
        .collect()
}

fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    assert_eq!(a.len(), b.len());
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

/// Configurations spanning several systematic-index-table rows.
const CASES: &[(usize, usize, u64)] = &[
    // (K, symbol_size, seed)
    (10, 32, 0x1111_1111_2222_2222),
    (16, 24, 0x3333_3333_4444_4444),
    (26, 48, 0x5555_5555_6666_6666),
    (40, 16, 0x7777_7777_8888_8888),
];

/// Relation 1 — the encoder's source-to-repair map is additively homomorphic
/// over GF(256): repair(S1 XOR S2) == repair(S1) XOR repair(S2) per ESI.
#[test]
fn repair_symbols_are_additively_linear_in_the_source() {
    for &(k, symbol_size, seed) in CASES {
        let s1 = make_source(k, symbol_size, seed);
        // A second, independent source sharing the same shape.
        let s2 = make_source(k, symbol_size, seed ^ 0xFFFF_FFFF_FFFF_FFFF);
        let s3 = xor_sources(&s1, &s2);

        // Identical (K, symbol_size, seed) => identical linear map; only the
        // source RHS differs across the three encoders.
        let e1 = SystematicEncoder::new(&s1, symbol_size, seed).expect("encoder s1");
        let e2 = SystematicEncoder::new(&s2, symbol_size, seed).expect("encoder s2");
        let e3 = SystematicEncoder::new(&s3, symbol_size, seed).expect("encoder s3");

        // Sweep a band of repair ESIs above K (low and elevated alike).
        let repair_esis = (k as u32..k as u32 + 24).chain([k as u32 + 100, k as u32 + 257]);
        for esi in repair_esis {
            let r1 = e1.repair_symbol(esi);
            let r2 = e2.repair_symbol(esi);
            let r3 = e3.repair_symbol(esi);

            assert_eq!(
                r1.len(),
                symbol_size,
                "repair symbol must be symbol_size bytes"
            );
            assert_eq!(
                r3,
                xor_bytes(&r1, &r2),
                "linearity violated at K={k} seed={seed:#x} esi={esi}: \
                 repair(S1 XOR S2) != repair(S1) XOR repair(S2)"
            );
        }
    }
}

/// Relation 2 — the linear image of the zero source is the zero symbol.
#[test]
fn repair_symbols_of_zero_source_are_zero() {
    for &(k, symbol_size, seed) in CASES {
        let zero = vec![vec![0u8; symbol_size]; k];
        let enc = SystematicEncoder::new(&zero, symbol_size, seed).expect("encoder zero");

        for esi in (k as u32..k as u32 + 24).chain([k as u32 + 100]) {
            let repair = enc.repair_symbol(esi);
            assert!(
                repair.iter().all(|&b| b == 0),
                "zero-source repair must be all zero at K={k} seed={seed:#x} esi={esi}, got {repair:?}"
            );
        }
    }
}
