//! RFC 6330 §5.7 GF(256) arithmetic — primitive-polynomial + field-axiom
//! conformance proof.
//!
//! bd-3uox5 (RAPTORQ-RFC6330 conformance, Track-D property verification).
//!
//! RaptorQ operates over GF(2⁸) defined by the primitive polynomial
//! x⁸+x⁴+x³+x²+1 (reduction mask 0x1D) with generator α=2 (RFC 6330
//! §5.7). The implementation realises multiplication via log/exp tables;
//! this test proves those tables encode the *correct* field by checking
//! every product against an independent, table-free carryless-multiply
//! reference, and then verifies the field axioms that the decoder's
//! Gaussian elimination relies on (commutativity, associativity,
//! distributivity, identities, inverses, division, exponentiation, and
//! that α is genuinely primitive — multiplicative order 255).
//!
//! Existing tests cover SIMD slice bit-exactness and a couple of inverse
//! samples; none independently re-derives the field nor checks the
//! algebraic laws across the whole domain.
//!
//! Repro: `cargo test --test raptorq_gf256_field_axioms`

use asupersync::raptorq::gf256::Gf256;

/// Independent GF(2⁸) multiply (Russian-peasant) mod the RFC 6330
/// primitive polynomial x⁸+x⁴+x³+x²+1. Reduction mask = 0x1D after the
/// x⁸ term overflows the byte.
fn ref_mul(mut a: u8, mut b: u8) -> u8 {
    let mut product: u8 = 0;
    for _ in 0..8 {
        if b & 1 != 0 {
            product ^= a;
        }
        let high_bit_set = a & 0x80 != 0;
        a <<= 1;
        if high_bit_set {
            a ^= 0x1D;
        }
        b >>= 1;
    }
    product
}

#[test]
fn mul_field_matches_primitive_polynomial_reference() {
    for a in 0u16..=255 {
        for b in 0u16..=255 {
            let (a, b) = (a as u8, b as u8);
            let got = (Gf256(a) * Gf256(b)).0;
            let expected = ref_mul(a, b);
            assert_eq!(
                got, expected,
                "GF(256) mul({a},{b}) = {got}, RFC 0x1D reference = {expected}; \
                 repro='cargo test --test raptorq_gf256_field_axioms'"
            );
            // Operator and explicit method must agree.
            assert_eq!(
                Gf256(a).mul_field(Gf256(b)).0,
                got,
                "mul_field disagrees with * operator for ({a},{b})"
            );
        }
    }
}

#[test]
fn add_is_xor_and_self_inverse() {
    for a in 0u16..=255 {
        for b in 0u16..=255 {
            let (a, b) = (a as u8, b as u8);
            assert_eq!((Gf256(a) + Gf256(b)).0, a ^ b, "add != xor ({a},{b})");
        }
        let a = a as u8;
        assert_eq!((Gf256(a) + Gf256(a)).0, 0, "a+a != 0 for {a}");
        assert_eq!((Gf256(a) + Gf256::ZERO).0, a, "a+0 != a for {a}");
    }
}

#[test]
fn mul_identities_commutativity_and_inverses() {
    for a in 0u16..=255 {
        let a = a as u8;
        let ga = Gf256(a);
        assert_eq!((ga * Gf256::ONE).0, a, "a*1 != a for {a}");
        assert_eq!((ga * Gf256::ZERO).0, 0, "a*0 != 0 for {a}");

        for b in 0u16..=255 {
            let gb = Gf256(b as u8);
            assert_eq!(ga * gb, gb * ga, "mul not commutative ({a},{b})");
        }

        if a != 0 {
            let inv = ga.inv();
            assert_eq!((ga * inv).0, 1, "a*inv(a) != 1 for {a}");
            // Division consistency: (a/b)*b == a for all nonzero b.
            for b in 1u16..=255 {
                let gb = Gf256(b as u8);
                assert_eq!((ga.div_field(gb) * gb), ga, "(a/b)*b != a ({a},{b})");
            }
        }
    }
}

#[test]
fn mul_associativity_and_distributivity_full_domain() {
    for a in 0u16..=255 {
        let ga = Gf256(a as u8);
        for b in 0u16..=255 {
            let gb = Gf256(b as u8);
            let ab = ga * gb;
            for c in 0u16..=255 {
                let gc = Gf256(c as u8);
                // Associativity: (a*b)*c == a*(b*c).
                assert_eq!(ab * gc, ga * (gb * gc), "assoc fails ({a},{b},{c})");
                // Distributivity: a*(b+c) == a*b + a*c.
                assert_eq!(ga * (gb + gc), ab + ga * gc, "distrib fails ({a},{b},{c})");
            }
        }
    }
}

#[test]
fn pow_and_generator_is_primitive() {
    // pow consistency against repeated multiplication.
    for a in 0u16..=255 {
        let ga = Gf256(a as u8);
        assert_eq!(ga.pow(0), Gf256::ONE, "a^0 != 1 for {a}");
        assert_eq!(ga.pow(1), ga, "a^1 != a for {a}");
        assert_eq!(ga.pow(2), ga * ga, "a^2 != a*a for {a}");
        assert_eq!(ga.pow(3), ga * ga * ga, "a^3 != a*a*a for {a}");
    }

    // α=2 must be primitive: its powers cycle with order exactly 255 and
    // enumerate every nonzero element of GF(256).
    let alpha = Gf256::ALPHA;
    assert_eq!(alpha, Gf256(2), "generator must be 2 per RFC 6330 §5.7");
    let mut seen = [false; 256];
    let mut acc = Gf256::ONE;
    for k in 0..255 {
        assert!(
            !seen[acc.0 as usize],
            "alpha^{k} repeats value {} before order 255 — α is not primitive",
            acc.0
        );
        seen[acc.0 as usize] = true;
        assert_ne!(acc.0, 0, "alpha^{k} hit zero — impossible for a generator");
        acc *= alpha;
    }
    // After 255 steps we must return to 1 (full cycle).
    assert_eq!(acc, Gf256::ONE, "alpha^255 != 1 — order is not 255");
    // Every nonzero element was enumerated exactly once.
    for v in 1u16..=255 {
        assert!(
            seen[v as usize],
            "nonzero element {v} never produced by α powers"
        );
    }
    assert!(!seen[0], "zero must not appear in the multiplicative group");
}
