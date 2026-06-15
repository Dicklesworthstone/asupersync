//! RaptorQ receive-path authentication posture — predicate-method conformance.
//!
//! bd-3uox5 (RAPTORQ-RFC6330) AC3/AC5. The receive pipeline reports the
//! cryptographic posture of every symbol it accepts into a decode set through
//! two public re-exported types:
//!   - `ReceiveAuthenticationSummary` — three counters (`verified`,
//!     `unverified_tagged`, `unauthenticated_sentinel`) plus pure `const fn`
//!     predicates: `total`, `all_verified`, `has_unauthenticated_sentinel`,
//!     `has_unverified_tagged`, `has_unverified_symbols`.
//!   - `ReceiveOutcome` — wraps the summary alongside the `authenticated` gate
//!     and `symbols_received` count, exposing `all_symbols_verified` and
//!     `has_unverified_symbols`.
//!
//! Every one of those eight predicates had ZERO integration coverage, so
//! nothing pinned the boolean algebra that downstream operators key their
//! "was this transfer trustworthy?" decisions on. This harness pins them with
//! oracle-free identities recomputed from the public counters, so a refactor
//! of the predicate bodies cannot silently change the reported posture.
//!
//! Modeled invariants (mirroring how `receive_object` populates the fields):
//!   - `total() == verified + unverified_tagged + unauthenticated_sentinel`,
//!     saturating (never panics / wraps even at `usize::MAX`).
//!   - `all_verified()` <=> the two non-verified counters are both zero.
//!   - `has_unverified_symbols()` <=> `unverified_tagged>0 || sentinel>0` for
//!     ALL inputs; this is the exact logical negation of `all_verified()` for
//!     every non-saturating total (the realistic domain — see the saturation
//!     artifact pinned in `total_saturates_at_usize_max_without_panicking`).
//!   - `has_unverified_tagged()` / `has_unauthenticated_sentinel()` each track
//!     only their own counter, independent of the others.
//!   - `ReceiveOutcome::all_symbols_verified()` is the three-way conjunction
//!     `authenticated && total()==symbols_received && all_verified()`; each
//!     clause is independently load-bearing (proven by flipping one at a time).
//!   - `ReceiveOutcome::has_unverified_symbols()` delegates verbatim to the
//!     summary, independent of `authenticated`, `symbols_received`, `data`.
//!
//! Repro: `cargo test --test raptorq_receive_authentication_summary_predicates`

use asupersync::raptorq::{ReceiveAuthenticationSummary, ReceiveOutcome};

/// Construct a summary from the three public counters.
fn summary(
    verified: usize,
    unverified_tagged: usize,
    sentinel: usize,
) -> ReceiveAuthenticationSummary {
    ReceiveAuthenticationSummary {
        verified,
        unverified_tagged,
        unauthenticated_sentinel: sentinel,
    }
}

/// Construct a receive outcome around a summary. `data` is irrelevant to the
/// predicates under test; we keep it empty.
fn outcome(
    authenticated: bool,
    symbols_received: usize,
    s: ReceiveAuthenticationSummary,
) -> ReceiveOutcome {
    ReceiveOutcome {
        data: Vec::new(),
        symbols_received,
        authenticated,
        authentication: s,
    }
}

/// A small but representative sweep of counter triples used by the algebraic
/// identity tests. Covers all-zero, single-nonzero, multi-nonzero, and an
/// asymmetric large value, exercising every predicate branch.
fn counter_sweep() -> Vec<(usize, usize, usize)> {
    let mut out = Vec::new();
    for v in [0usize, 1, 3, 7] {
        for ut in [0usize, 1, 2] {
            for us in [0usize, 1, 4] {
                out.push((v, ut, us));
            }
        }
    }
    out
}

#[test]
fn default_summary_is_all_zero_and_vacuously_verified() {
    let d = ReceiveAuthenticationSummary::default();
    assert_eq!(d, summary(0, 0, 0));
    assert_eq!(d.total(), 0);
    // Vacuous truth: with nothing represented there is nothing unverified.
    assert!(d.all_verified());
    assert!(!d.has_unverified_symbols());
    assert!(!d.has_unverified_tagged());
    assert!(!d.has_unauthenticated_sentinel());
}

#[test]
fn total_is_the_saturating_sum_of_the_three_counters() {
    for (v, ut, us) in counter_sweep() {
        let s = summary(v, ut, us);
        // Recompute with the SAME saturating semantics as the impl so the
        // comparison is exact, not an approximation.
        let expected = v.saturating_add(ut).saturating_add(us);
        assert_eq!(s.total(), expected, "total mismatch for ({v},{ut},{us})");
        // In the small sweep none of these saturate, so it equals the plain sum.
        assert_eq!(s.total(), v + ut + us);
    }
}

#[test]
fn total_saturates_at_usize_max_without_panicking() {
    // Two counters at MAX must clamp rather than wrap/panic.
    let s = summary(usize::MAX, usize::MAX, 1);
    assert_eq!(s.total(), usize::MAX);
    let s2 = summary(usize::MAX, 1, 0);
    assert_eq!(s2.total(), usize::MAX);
    // A clean all-verified summary at the ceiling is still all-verified.
    assert!(summary(usize::MAX, 0, 0).all_verified());

    // SATURATION ARTIFACT (physically unreachable: would require ~2^64 accepted
    // symbols). `all_verified()` is defined as `total() == verified`, so when the
    // summed total saturates back down to equal `verified` it reports `true`
    // even though there ARE non-verified counters. The disjunction-form posture
    // check does NOT depend on `total()`, so it still correctly flags the
    // unverified symbols. We pin BOTH so any refactor must consciously revisit
    // this edge rather than change it silently.
    assert!(s.all_verified()); // artifact: saturated total == verified
    assert!(s.has_unverified_symbols()); // still correct via the disjunction
    assert!(s.has_unverified_tagged());
    assert!(s.has_unauthenticated_sentinel());
    // Consequently the `has_unverified_symbols() == !all_verified()` identity
    // holds only for non-saturating totals — exactly the realistic domain
    // exercised by has_unverified_symbols_is_the_disjunction_and_negates_all_verified.
}

#[test]
fn all_verified_iff_both_nonverified_counters_are_zero() {
    for (v, ut, us) in counter_sweep() {
        let s = summary(v, ut, us);
        let expected = ut == 0 && us == 0;
        assert_eq!(
            s.all_verified(),
            expected,
            "all_verified mismatch for ({v},{ut},{us})"
        );
        // Equivalent framing the impl uses internally: total() == verified.
        assert_eq!(s.all_verified(), s.total() == v);
    }
}

#[test]
fn per_counter_predicates_track_only_their_own_counter() {
    for (v, ut, us) in counter_sweep() {
        let s = summary(v, ut, us);
        assert_eq!(
            s.has_unverified_tagged(),
            ut > 0,
            "has_unverified_tagged mismatch for ({v},{ut},{us})"
        );
        assert_eq!(
            s.has_unauthenticated_sentinel(),
            us > 0,
            "has_unauthenticated_sentinel mismatch for ({v},{ut},{us})"
        );
    }
}

#[test]
fn has_unverified_symbols_is_the_disjunction_and_negates_all_verified() {
    for (v, ut, us) in counter_sweep() {
        let s = summary(v, ut, us);
        assert_eq!(
            s.has_unverified_symbols(),
            s.has_unverified_tagged() || s.has_unauthenticated_sentinel(),
            "disjunction mismatch for ({v},{ut},{us})"
        );
        // The load-bearing identity operators rely on: over non-saturating
        // totals (this sweep), "any symbol unverified" is the exact complement
        // of "every symbol verified" — including the all-zero vacuous case.
        assert_eq!(
            s.has_unverified_symbols(),
            !s.all_verified(),
            "negation identity mismatch for ({v},{ut},{us})"
        );
    }
}

#[test]
fn outcome_all_symbols_verified_when_authenticated_consistent_and_clean() {
    // Models a fully verified transfer: auth material present, every accepted
    // symbol verified, counts consistent.
    let s = summary(5, 0, 0);
    let o = outcome(true, 5, s);
    assert!(o.all_symbols_verified());
    assert!(!o.has_unverified_symbols());
}

#[test]
fn outcome_requires_the_authenticated_gate() {
    // Even with a fully-verified, count-consistent summary, a false
    // `authenticated` flag (e.g. no auth material on the receive path) must
    // force all_symbols_verified to false: the gate is load-bearing.
    let s = summary(3, 0, 0);
    let o = outcome(false, 3, s);
    assert!(!o.all_symbols_verified());
    // ...but the delegated summary view is unaffected by the gate.
    assert!(!o.has_unverified_symbols());
}

#[test]
fn outcome_requires_count_consistency() {
    // total() != symbols_received signals an accounting mismatch; the strict
    // predicate must reject it even though the summary itself is all-verified.
    let s = summary(4, 0, 0);
    assert!(s.all_verified());
    let short = outcome(true, 5, s); // received 5 but only 4 represented
    assert!(!short.all_symbols_verified());
    let over = outcome(true, 3, s); // received 3 but 4 represented
    assert!(!over.all_symbols_verified());
}

#[test]
fn outcome_rejects_when_any_symbol_unverified() {
    // A mixed posture (some tagged-but-unverified) — models reject_unauthenticated
    // disabled with a context that some symbols failed to verify against.
    let s = summary(4, 1, 0);
    // authenticated would be false in the real path (&= over an unverified
    // symbol), but assert the predicate rejects regardless of the gate value.
    for authed in [true, false] {
        let o = outcome(authed, 5, s);
        assert!(
            !o.all_symbols_verified(),
            "unverified-tagged must reject (authed={authed})"
        );
        assert!(o.has_unverified_symbols());
    }
    // Same for the all-zero-tag sentinel posture.
    let s2 = summary(4, 0, 1);
    let o2 = outcome(false, 5, s2);
    assert!(!o2.all_symbols_verified());
    assert!(o2.has_unverified_symbols());
    assert!(o2.authentication.has_unauthenticated_sentinel());
}

#[test]
fn outcome_has_unverified_symbols_delegates_verbatim_to_summary() {
    // The delegation must be independent of authenticated / symbols_received /
    // data: sweep the summary and confirm equality across irrelevant fields.
    for (v, ut, us) in counter_sweep() {
        let s = summary(v, ut, us);
        for authed in [true, false] {
            for received in [0usize, v, s.total(), s.total() + 1] {
                let o = outcome(authed, received, s);
                assert_eq!(
                    o.has_unverified_symbols(),
                    s.has_unverified_symbols(),
                    "delegation mismatch for ({v},{ut},{us}) authed={authed} recv={received}"
                );
            }
        }
    }
}

#[test]
fn outcome_empty_decode_set_with_auth_material_is_vacuously_verified() {
    // Edge: auth material present, zero symbols accepted. total()==0==received
    // and the summary is vacuously all-verified, so the strict predicate
    // reports true. Pinned as documented behavior of the pure predicate.
    let o = outcome(true, 0, ReceiveAuthenticationSummary::default());
    assert!(o.all_symbols_verified());
    assert!(!o.has_unverified_symbols());
}
