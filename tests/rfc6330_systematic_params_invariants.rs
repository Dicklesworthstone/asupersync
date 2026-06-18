//! Exhaustive RFC 6330 systematic-index-table invariant sweep.
//!
//! `SystematicParams::try_for_source_block` does a binary-search lookup into the
//! 477-row RFC 6330 Table 2 (`rfc6330_systematic_index_table.inc`) and derives
//! `L`, `P`, `B` from the row's `(K', J, S, H, W)`. The table is checked into the
//! tree as raw tuples; a single-value transcription error in a row that no other
//! test happens to exercise would silently corrupt every encode/decode that
//! lands in that K' band -- the "Heuristic parameter derivation" /
//! "silent decode corruption" anchor findings of bd-3uox5 (AC #2, AC #3).
//!
//! The lookup validates `W >= S` and `L >= W` only for the *single* row a call
//! hits, so an unexercised corrupt row escapes. This sweep drives the public API
//! across every reachable `K` (1..=K'_max), so every table row is exercised and
//! its RFC structural invariants are pinned:
//!
//! - `K' >= K`, requested `K` preserved
//! - `L == K' + S + H`
//! - `P == L - W` with `L >= W`   (PI-symbol count well-formed)
//! - `B == W - S` with `W >= S`   (non-LDPC LT-symbol count well-formed)
//! - `S, H, W, P, B >= 1`
//! - `W > 2` (LT tuple generator precondition; see
//!   `try_tuple` / `tuple_indices`)
//! - `P1 = next_prime_ge(P)` exists, is prime, and `>= P`
//! - `K'` fits in `u32` (ESI domain)
//! - `for_source_block` agrees with `try_for_source_block`
//! - `K'` is monotonic non-decreasing in `K`
//!
//! Coverage is asserted: exactly 477 distinct `K'` rows must be reached and the
//! max `K'` boundary must reject `K'_max + 1`, so a truncated or short-loaded
//! table fails loudly instead of silently shrinking the supported range.

#![allow(missing_docs)]

use asupersync::raptorq::rfc6330::next_prime_ge;
use asupersync::raptorq::systematic::{SystematicParamError, SystematicParams};

/// Number of rows in RFC 6330 Table 2 as transcribed in
/// `src/raptorq/rfc6330_systematic_index_table.inc`. Pinned here so a truncated
/// table load (e.g. a dropped trailing row) fails this test rather than silently
/// shrinking the supported source-block range.
const EXPECTED_DISTINCT_K_PRIME_ROWS: usize = 477;

/// Largest `K'` in RFC 6330 Table 2 (final row's first column).
const MAX_K_PRIME: usize = 56_403;

const SYMBOL_SIZE: usize = 64;

fn is_prime_reference(n: usize) -> bool {
    if n < 2 {
        return false;
    }
    if n % 2 == 0 {
        return n == 2;
    }
    let mut d = 3usize;
    while d * d <= n {
        if n % d == 0 {
            return false;
        }
        d += 2;
    }
    true
}

#[test]
fn systematic_index_table_rows_satisfy_rfc_invariants() {
    let mut distinct_rows = 0usize;
    let mut prev_k_prime = 0usize;
    let mut last_seen_k_prime = 0usize;

    for k in 1..=MAX_K_PRIME {
        let params = SystematicParams::try_for_source_block(k, SYMBOL_SIZE)
            .unwrap_or_else(|e| panic!("K={k} (<= K'_max) must resolve, got {e:?}"));

        // Requested K preserved; extended size never smaller than requested.
        assert_eq!(params.k, k, "params.k must echo requested K");
        assert!(
            params.k_prime >= k,
            "K'={} < K={k} violates extended-block-size invariant",
            params.k_prime
        );

        // Structural identities from RFC 6330 Section 5.3.3.3 / Table 2.
        assert_eq!(
            params.l,
            params.k_prime + params.s + params.h,
            "L != K'+S+H for K={k} (K'={})",
            params.k_prime
        );
        assert!(
            params.l >= params.w,
            "L={} < W={} for K={k} (K'={}) -> P would underflow",
            params.l,
            params.w,
            params.k_prime
        );
        assert_eq!(
            params.p,
            params.l - params.w,
            "P != L-W for K={k} (K'={})",
            params.k_prime
        );
        assert!(
            params.w >= params.s,
            "W={} < S={} for K={k} (K'={}) -> B would underflow",
            params.w,
            params.s,
            params.k_prime
        );
        assert_eq!(
            params.b,
            params.w - params.s,
            "B != W-S for K={k} (K'={})",
            params.k_prime
        );

        // Every RFC row carries at least one of each derived symbol class.
        assert!(params.s >= 1, "S=0 for K={k} (K'={})", params.k_prime);
        assert!(params.h >= 1, "H=0 for K={k} (K'={})", params.k_prime);
        assert!(params.w >= 1, "W=0 for K={k} (K'={})", params.k_prime);
        assert!(params.p >= 1, "P=0 for K={k} (K'={})", params.k_prime);
        assert!(params.b >= 1, "B=0 for K={k} (K'={})", params.k_prime);

        // LT tuple generator precondition: deg caps to min(_, W-2), so W must
        // exceed 2 or every LT degree degenerates to 0. Pins the table against
        // any row whose W would silently break tuple expansion.
        assert!(
            params.w > 2,
            "W={} <= 2 for K={k} (K'={}) breaks LT tuple generation",
            params.w,
            params.k_prime
        );

        // P1 = smallest prime >= P must exist and actually be prime.
        let p1 = next_prime_ge(params.p)
            .unwrap_or_else(|| panic!("next_prime_ge(P={}) overflowed for K={k}", params.p));
        assert!(
            p1 >= params.p && is_prime_reference(p1),
            "P1={p1} is not a prime >= P={} for K={k} (K'={})",
            params.p,
            params.k_prime
        );

        // K' must fit in u32 for the decoder's ESI arithmetic.
        assert!(
            u32::try_from(params.k_prime).is_ok(),
            "K'={} exceeds u32 for K={k}",
            params.k_prime
        );

        // Infallible wrapper must agree with the fallible lookup.
        let infallible = SystematicParams::for_source_block(k, SYMBOL_SIZE);
        assert_eq!(
            (infallible.k_prime, infallible.j, infallible.s, infallible.h, infallible.w),
            (params.k_prime, params.j, params.s, params.h, params.w),
            "for_source_block disagrees with try_for_source_block for K={k}"
        );

        // K' is monotonic non-decreasing in K (binary-search invariant).
        assert!(
            params.k_prime >= prev_k_prime,
            "K' decreased from {prev_k_prime} to {} at K={k}",
            params.k_prime
        );
        prev_k_prime = params.k_prime;

        if params.k_prime != last_seen_k_prime {
            distinct_rows += 1;
            last_seen_k_prime = params.k_prime;
        }
    }

    // Full table must be loaded: every row reached, no truncation.
    assert_eq!(
        distinct_rows, EXPECTED_DISTINCT_K_PRIME_ROWS,
        "reached {distinct_rows} distinct K' rows; RFC 6330 Table 2 has {EXPECTED_DISTINCT_K_PRIME_ROWS}"
    );
    assert_eq!(
        last_seen_k_prime, MAX_K_PRIME,
        "final reached K'={last_seen_k_prime} != table max {MAX_K_PRIME}"
    );
}

#[test]
fn unsupported_source_block_sizes_are_rejected() {
    // K = 0 is not a valid source block.
    match SystematicParams::try_for_source_block(0, SYMBOL_SIZE) {
        Err(SystematicParamError::UnsupportedSourceBlockSize { requested, .. }) => {
            assert_eq!(requested, 0);
        }
        other => panic!("K=0 must be UnsupportedSourceBlockSize, got {other:?}"),
    }

    // One past the largest K' must fall off the supported range.
    match SystematicParams::try_for_source_block(MAX_K_PRIME + 1, SYMBOL_SIZE) {
        Err(SystematicParamError::UnsupportedSourceBlockSize {
            requested,
            max_supported,
        }) => {
            assert_eq!(requested, MAX_K_PRIME + 1);
            assert_eq!(
                max_supported, MAX_K_PRIME,
                "max_supported must equal the table's largest K'"
            );
        }
        other => panic!("K=K'_max+1 must be UnsupportedSourceBlockSize, got {other:?}"),
    }

    // The largest K' itself must still resolve.
    let top = SystematicParams::try_for_source_block(MAX_K_PRIME, SYMBOL_SIZE)
        .expect("K'_max must resolve");
    assert_eq!(top.k_prime, MAX_K_PRIME);
}
