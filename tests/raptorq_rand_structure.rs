//! RFC 6330 §5.3.5.1 `Rand[y, i, m]` — structural conformance sweep.
//!
//! bd-3uox5 (RAPTORQ-RFC6330 conformance, Track-D property verification).
//!
//! RFC 6330 §5.3.5.1 defines:
//!   Rand[y, i, m] = (V0[(y       + i) mod 256]
//!                  ^ V1[(y >> 8  + i) mod 256]
//!                  ^ V2[(y >> 16 + i) mod 256]
//!                  ^ V3[(y >> 24 + i) mod 256]) mod m
//!
//! The existing conformance suite pins a handful of golden (y,i,m)
//! triples. Those check specific outputs but exercise the byte-
//! decomposition indexing on only a few points — and an off-by-one in a
//! shift (e.g. `>> 8` vs `>> 16`) can pass a sparse golden set while
//! silently corrupting most inputs. This test re-derives the formula
//! independently across a broad (y,i,m) grid (the V-tables themselves
//! are byte-exact pinned by an inline regression test, so re-using them
//! here checks the *decomposition + XOR + mod* logic, not the table
//! values) and asserts the universal RFC invariants:
//!   - Rand[y,i,m] < m  (valid index into an m-sized space)
//!   - Rand[y,i,1] == 0
//!   - determinism
//!
//! Repro: `cargo test --test raptorq_rand_structure`

use asupersync::raptorq::rfc6330::{V0, V1, V2, V3, rand};

/// Independent re-derivation of the RFC 6330 §5.3.5.1 formula.
fn ref_rand(y: u32, i: u8, m: u32) -> u32 {
    let x0 = (y.wrapping_add(u32::from(i)) & 0xFF) as usize;
    let x1 = ((y >> 8).wrapping_add(u32::from(i)) & 0xFF) as usize;
    let x2 = ((y >> 16).wrapping_add(u32::from(i)) & 0xFF) as usize;
    let x3 = ((y >> 24).wrapping_add(u32::from(i)) & 0xFF) as usize;
    (V0[x0] ^ V1[x1] ^ V2[x2] ^ V3[x3]) % m
}

/// Diverse `y` sample: explicit byte/word boundaries plus a wide
/// odd-strided spread across the full u32 range.
fn y_samples() -> Vec<u32> {
    let mut ys = vec![
        0,
        1,
        255,
        256,
        257,
        65_535,
        65_536,
        65_537,
        0x00FF_FFFF,
        0x0100_0000,
        0x7FFF_FFFF,
        0x8000_0000,
        u32::MAX - 1,
        u32::MAX,
    ];
    // Large odd stride spreads samples across all four bytes.
    let mut v: u32 = 0;
    for _ in 0..2048 {
        v = v.wrapping_add(2_097_151); // odd, ~2^21
        ys.push(v);
    }
    ys
}

const M_SAMPLES: &[u32] = &[
    1,
    2,
    3,
    5,
    7,
    255,
    256,
    257,
    1023,
    1024,
    1 << 20, // degree-generator modulus
    0x7FFF_FFFF,
    u32::MAX,
];

#[test]
fn rand_matches_rfc_formula_and_invariants() {
    let ys = y_samples();
    let mut checked: u64 = 0;

    for &y in &ys {
        // `i` is a u8, so 0..=255 is its entire domain — exhaustive.
        for i in 0u16..=255 {
            let i = i as u8;
            for &m in M_SAMPLES {
                let got = rand(y, i, m);
                let expected = ref_rand(y, i, m);
                assert_eq!(
                    got, expected,
                    "rand({y},{i},{m}) = {got}, RFC formula re-derivation = {expected}; \
                     repro='cargo test --test raptorq_rand_structure'"
                );
                assert!(got < m, "rand({y},{i},{m}) = {got} not < m");
                // Determinism.
                assert_eq!(
                    rand(y, i, m),
                    got,
                    "rand not deterministic at ({y},{i},{m})"
                );
                checked += 1;
            }
            // mod-1 always collapses to zero.
            assert_eq!(rand(y, i, 1), 0, "rand({y},{i},1) must be 0");
        }
    }

    assert!(checked > 100_000, "sweep too small: only {checked} points");
}
