//! RFC 6330 PI-modulus derivation: `next_prime_ge` = smallest prime ≥ n.
//!
//! bd-3uox5 (RAPTORQ-RFC6330 conformance, Track-D property verification).
//!
//! RFC 6330 §5.3.3.3 derives `P1` as the smallest prime greater than or
//! equal to `P` (the PI symbol count). The PI symbol walk in §5.3.5.3
//! steps by `a1` over the modulus `P1`, and its distinctness / coverage
//! guarantees rely on `P1` being *prime* (so `a1 ∈ [1, P1)` generates the
//! full residue orbit). A `next_prime_ge` that returned a composite, or
//! skipped a prime (not the *smallest*), would silently corrupt every PI
//! walk and break decode parity — yet it had no dedicated test.
//!
//! This test is a sieve differential: an independent Sieve of
//! Eratosthenes computes the expected smallest-prime-≥-n for the whole
//! swept range, and we assert `next_prime_ge` agrees at every point.
//! Plus the structural property (result is prime, no prime in [n, P1)),
//! plus explicit RFC golden P→P1 pairs used by the conformance vectors.
//!
//! Repro: `cargo test --test raptorq_next_prime_ge_conformance`

use asupersync::raptorq::rfc6330::next_prime_ge;

const SWEEP_BOUND: usize = 20_000;

/// Independent Sieve of Eratosthenes: `is_prime[i]` for i in 0..=limit.
fn sieve(limit: usize) -> Vec<bool> {
    let mut is_prime = vec![true; limit + 1];
    is_prime[0] = false;
    if limit >= 1 {
        is_prime[1] = false;
    }
    let mut p = 2;
    while p * p <= limit {
        if is_prime[p] {
            let mut m = p * p;
            while m <= limit {
                is_prime[m] = false;
                m += p;
            }
        }
        p += 1;
    }
    is_prime
}

#[test]
fn next_prime_ge_matches_independent_sieve() {
    // Sieve a bit past the sweep so the smallest prime >= n always
    // exists within the sieved range for every n we test.
    let sieve_limit = SWEEP_BOUND + 1_000;
    let is_prime = sieve(sieve_limit);

    // Precompute "smallest prime >= n" by scanning the sieve downward.
    let mut next_prime = vec![0usize; sieve_limit + 1];
    let mut last = 0usize;
    for n in (0..=sieve_limit).rev() {
        if is_prime[n] {
            last = n;
        }
        next_prime[n] = last; // 0 means "none found at/above n within sieve"
    }

    for (n, &expected) in next_prime.iter().enumerate().take(SWEEP_BOUND + 1) {
        assert_ne!(expected, 0, "sieve too small for n={n}");
        let got = next_prime_ge(n)
            .unwrap_or_else(|| panic!("next_prime_ge({n}) returned None within sieved range"));
        assert_eq!(
            got, expected,
            "next_prime_ge({n}) = {got}, expected smallest prime >= n = {expected}; \
             repro='cargo test --test raptorq_next_prime_ge_conformance'"
        );
        // Structural belt-and-suspenders: result is prime and there is
        // no prime in [n, got).
        assert!(is_prime[got], "next_prime_ge({n}) = {got} is not prime");
        assert!(got >= n, "next_prime_ge({n}) = {got} < n");
        for (m, &prime) in is_prime.iter().enumerate().take(got).skip(n) {
            assert!(!prime, "next_prime_ge({n}) skipped prime {m} (< {got})");
        }
    }
}

#[test]
fn next_prime_ge_rfc_golden_pairs() {
    // n <= 2 collapses to the smallest prime, 2.
    for n in 0..=2 {
        assert_eq!(next_prime_ge(n), Some(2), "next_prime_ge({n}) must be 2");
    }
    // RFC PI-modulus golden pairs (P -> P1) drawn from the conformance
    // tuple vectors and nearby points.
    let golden: &[(usize, usize)] = &[
        (3, 3),
        (4, 5),
        (10, 11), // RQ-D1-TUPLE golden P=10 -> P1=11
        (15, 17), // RQ-D1-TUPLE-007/008 golden P=15 -> P1=17
        (100, 101),
        (113, 113), // 113 is itself prime
        (114, 127), // 114..126 composite, 127 prime
        (200, 211),
        (1000, 1009),
    ];
    for &(p, p1) in golden {
        assert_eq!(
            next_prime_ge(p),
            Some(p1),
            "RFC golden: smallest prime >= {p} must be {p1}"
        );
    }
}
