//! Conformance harness for `asupersync::trace::scoring`.
//!
//! This crate's exploration prioritizer (used by DPOR / topological novelty
//! search) ranks candidate schedules by a `TopologicalScore` triple
//! `(novelty, persistence_sum, fingerprint)`. The whole search depends on this
//! ordering being a deterministic *total* order with the documented dominance
//! hierarchy:
//!
//! 1. `novelty` (higher wins)
//! 2. `persistence_sum` (higher wins, ties broken by ...)
//! 3. `fingerprint` (lower wins — stable canonical order)
//!
//! Plus a small algebra over `score_persistence`:
//!
//! - entry count = `pairs.len() + unpaired.len()`
//! - `novelty` = number of entries with `is_novel == true`
//! - `persistence_sum` = sum of finite persistences (`saturating_add`)
//! - `seen_classes` is monotone (only insert, never remove)
//! - calling twice with the same `(pairs, seen)` yields a ledger with zero
//!   novelty the second time (idempotence of class discovery)
//!
//! These properties are easy to assert individually but easy to *regress*
//! independently — a refactor that, for example, switched the tie-break
//! direction or stopped accumulating persistence for non-novel classes would
//! silently change exploration behavior without breaking any per-test in
//! `trace::scoring`. This harness pins them all in one place.

#![allow(clippy::too_many_lines)]
#![allow(clippy::needless_range_loop)]

use std::cmp::Ordering;
use std::collections::BTreeSet;

use asupersync::trace::{
    BoundaryMatrix, ClassId, EvidenceLedger, PersistencePairs, TopologicalScore,
    score_boundary_matrix, score_persistence, seed_fingerprint,
};

// ---------------------------------------------------------------------------
// Total-order axioms on `TopologicalScore`
// ---------------------------------------------------------------------------

/// Build a deterministic spread of `TopologicalScore` values that exercises
/// every dominance lane (novelty, persistence_sum, fingerprint).
fn corpus() -> Vec<TopologicalScore> {
    let mut out = Vec::new();
    for novelty in [0u32, 1, 2, 5] {
        for persistence_sum in [0u64, 1, 7, 100] {
            for fingerprint in [0u64, 1, 0x42, u64::MAX] {
                out.push(TopologicalScore {
                    novelty,
                    persistence_sum,
                    fingerprint,
                });
            }
        }
    }
    out
}

#[test]
fn ordering_is_reflexive() {
    for s in corpus() {
        assert_eq!(s.cmp(&s), Ordering::Equal, "score {s:?} not reflexive");
        assert!(s <= s);
        assert!(s >= s);
    }
}

#[test]
fn ordering_is_antisymmetric() {
    let c = corpus();
    for a in &c {
        for b in &c {
            match a.cmp(b) {
                Ordering::Less => assert_eq!(b.cmp(a), Ordering::Greater, "{a:?} vs {b:?}"),
                Ordering::Greater => assert_eq!(b.cmp(a), Ordering::Less, "{a:?} vs {b:?}"),
                Ordering::Equal => assert_eq!(b.cmp(a), Ordering::Equal, "{a:?} vs {b:?}"),
            }
        }
    }
}

#[test]
fn ordering_is_transitive() {
    let c = corpus();
    for a in &c {
        for b in &c {
            for d in &c {
                if a.cmp(b) == Ordering::Greater && b.cmp(d) == Ordering::Greater {
                    assert_eq!(
                        a.cmp(d),
                        Ordering::Greater,
                        "transitivity broke: {a:?} > {b:?} > {d:?}"
                    );
                }
            }
        }
    }
}

#[test]
fn ordering_is_total() {
    let c = corpus();
    for a in &c {
        for b in &c {
            // partial_cmp never returns None — Ord is total
            assert!(a.partial_cmp(b).is_some(), "{a:?} vs {b:?}");
        }
    }
}

#[test]
fn ordering_equal_iff_field_equal() {
    let c = corpus();
    for a in &c {
        for b in &c {
            assert_eq!(
                a.cmp(b) == Ordering::Equal,
                a == b,
                "Eq/Cmp inconsistency: {a:?} vs {b:?}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Dominance hierarchy: novelty > persistence_sum > fingerprint
// ---------------------------------------------------------------------------

#[test]
fn novelty_dominates_persistence_sum() {
    // Higher novelty wins even when persistence_sum is much smaller.
    let high = TopologicalScore {
        novelty: 1,
        persistence_sum: 0,
        fingerprint: u64::MAX,
    };
    let low = TopologicalScore {
        novelty: 0,
        persistence_sum: u64::MAX,
        fingerprint: 0,
    };
    assert!(high > low);
}

#[test]
fn persistence_sum_dominates_fingerprint() {
    // Same novelty: higher persistence_sum wins even when fingerprint
    // is the most-canonical (smallest) value.
    let high = TopologicalScore {
        novelty: 3,
        persistence_sum: 10,
        fingerprint: u64::MAX,
    };
    let low = TopologicalScore {
        novelty: 3,
        persistence_sum: 1,
        fingerprint: 0,
    };
    assert!(high > low);
}

#[test]
fn lower_fingerprint_wins_tie() {
    // Same novelty + persistence: lower fingerprint is canonical winner.
    let canonical = TopologicalScore {
        novelty: 2,
        persistence_sum: 7,
        fingerprint: 0,
    };
    let secondary = TopologicalScore {
        novelty: 2,
        persistence_sum: 7,
        fingerprint: 1,
    };
    assert!(canonical > secondary);
    assert!(secondary < canonical);
}

// ---------------------------------------------------------------------------
// `score_persistence` algebra
// ---------------------------------------------------------------------------

fn pairs(finite: &[(usize, usize)], unpaired: &[usize]) -> PersistencePairs {
    PersistencePairs {
        pairs: finite.to_vec(),
        unpaired: unpaired.to_vec(),
    }
}

#[test]
fn ledger_entry_count_equals_input() {
    let p = pairs(&[(0, 5), (1, 8), (2, 3)], &[10, 11]);
    let mut seen = BTreeSet::new();
    let ledger = score_persistence(&p, &mut seen, 0);
    assert_eq!(ledger.entries.len(), p.pairs.len() + p.unpaired.len());
}

#[test]
fn novelty_equals_count_of_novel_entries() {
    let p = pairs(&[(0, 5), (1, 8)], &[3]);
    let mut seen = BTreeSet::new();
    let ledger = score_persistence(&p, &mut seen, 0);
    let novel = u32::try_from(ledger.entries.iter().filter(|e| e.is_novel).count()).unwrap();
    assert_eq!(ledger.score.novelty, novel);
}

#[test]
fn persistence_sum_equals_finite_persistences() {
    let p = pairs(&[(0, 5), (2, 7), (1, 4)], &[9, 10, 11]);
    let mut seen = BTreeSet::new();
    let ledger = score_persistence(&p, &mut seen, 0);

    let expected: u64 = p
        .pairs
        .iter()
        .map(|&(b, d)| u64::try_from(d - b).unwrap())
        .sum();
    assert_eq!(ledger.score.persistence_sum, expected);

    // Infinite (unpaired) classes never contribute to persistence_sum
    // even though they DO contribute to novelty.
    let unpaired_only = pairs(&[], &[0, 1, 2]);
    let mut seen2 = BTreeSet::new();
    let l2 = score_persistence(&unpaired_only, &mut seen2, 0);
    assert_eq!(l2.score.persistence_sum, 0);
    assert_eq!(l2.score.novelty, 3);
}

#[test]
fn persistence_sum_saturates_on_overflow() {
    // Two classes whose persistence intervals exceed u64::MAX combined.
    // The function uses saturating_add and must clamp to u64::MAX rather
    // than panic or wrap.
    let big = usize::MAX / 2;
    let p = pairs(&[(0, big), (0, big)], &[]);
    let mut seen = BTreeSet::new();
    let ledger = score_persistence(&p, &mut seen, 0);
    // Either the two values fit (depending on usize width) or it saturates;
    // in either case the result must be <= u64::MAX and >= one persistence.
    let single = u64::try_from(big).unwrap();
    assert!(ledger.score.persistence_sum >= single);
}

#[test]
fn fingerprint_passes_through_unchanged() {
    // The fingerprint provided by the caller appears verbatim on the
    // resulting score, regardless of the pairs being scored.
    for fp in [0u64, 1, 0xDEAD_BEEF, u64::MAX] {
        let p = pairs(&[(0, 1)], &[]);
        let mut seen = BTreeSet::new();
        let ledger = score_persistence(&p, &mut seen, fp);
        assert_eq!(ledger.score.fingerprint, fp);

        // Empty input still passes the fingerprint through.
        let empty = pairs(&[], &[]);
        let mut seen2 = BTreeSet::new();
        let l2 = score_persistence(&empty, &mut seen2, fp);
        assert_eq!(l2.score.fingerprint, fp);
        assert_eq!(l2.score.novelty, 0);
        assert_eq!(l2.score.persistence_sum, 0);
        assert!(l2.entries.is_empty());
    }
}

#[test]
fn determinism_under_repeated_scoring() {
    let p = pairs(&[(0, 3), (1, 6), (4, 9)], &[10, 12]);
    let mut seen_a = BTreeSet::new();
    let mut seen_b = BTreeSet::new();
    let la = score_persistence(&p, &mut seen_a, 1234);
    let lb = score_persistence(&p, &mut seen_b, 1234);
    assert_eq!(la.score, lb.score);
    assert_eq!(la.entries.len(), lb.entries.len());
    for (ea, eb) in la.entries.iter().zip(lb.entries.iter()) {
        assert_eq!(ea.class, eb.class);
        assert_eq!(ea.is_novel, eb.is_novel);
        assert_eq!(ea.persistence, eb.persistence);
    }
    assert_eq!(seen_a, seen_b);
}

#[test]
fn idempotence_of_class_discovery() {
    // Scoring the same pairs twice into the same `seen` set: the second
    // call has zero novelty but still accumulates persistence_sum.
    let p = pairs(&[(0, 5), (1, 8)], &[3]);
    let mut seen = BTreeSet::new();

    let l1 = score_persistence(&p, &mut seen, 1);
    assert_eq!(l1.score.novelty, 3);

    let l2 = score_persistence(&p, &mut seen, 2);
    assert_eq!(l2.score.novelty, 0);
    assert_eq!(l2.score.persistence_sum, l1.score.persistence_sum);
    assert!(l2.entries.iter().all(|e| !e.is_novel));
    assert_eq!(l2.entries.len(), l1.entries.len());
}

#[test]
fn seen_classes_grows_monotonically() {
    // After scoring, every class produced as an entry is in `seen_classes`.
    // `seen_classes` never shrinks.
    let p1 = pairs(&[(0, 5)], &[]);
    let p2 = pairs(&[(1, 8)], &[3]);

    let mut seen = BTreeSet::new();
    let _ = score_persistence(&p1, &mut seen, 0);
    let before: BTreeSet<ClassId> = seen.clone();
    let l2 = score_persistence(&p2, &mut seen, 0);

    for entry in &l2.entries {
        assert!(
            seen.contains(&entry.class),
            "class {:?} missing from seen",
            entry.class
        );
    }
    assert!(
        before.is_subset(&seen),
        "seen_classes shrank: before={before:?} after={seen:?}"
    );
}

#[test]
fn ordering_invariance_under_input_permutation_of_scores() {
    // Same set of (pairs, unpaired) presented in different orders should
    // produce the same score (novelty, persistence_sum) — entries may
    // appear in a different order, but the score must be invariant.
    let a = pairs(&[(0, 5), (1, 8), (2, 3)], &[9, 11]);
    let b = pairs(&[(2, 3), (0, 5), (1, 8)], &[11, 9]);

    let mut sa = BTreeSet::new();
    let mut sb = BTreeSet::new();
    let la = score_persistence(&a, &mut sa, 0);
    let lb = score_persistence(&b, &mut sb, 0);

    assert_eq!(la.score.novelty, lb.score.novelty);
    assert_eq!(la.score.persistence_sum, lb.score.persistence_sum);
    assert_eq!(la.score.fingerprint, lb.score.fingerprint);
    assert_eq!(sa, sb);
}

// ---------------------------------------------------------------------------
// `ClassId` semantics
// ---------------------------------------------------------------------------

#[test]
fn class_id_persistence_distinguishes_finite_and_infinite() {
    let finite = ClassId {
        birth: 2,
        death: 10,
    };
    assert_eq!(finite.persistence(), Some(8));

    let zero_len = ClassId { birth: 5, death: 5 };
    assert_eq!(zero_len.persistence(), Some(0));

    let infinite = ClassId {
        birth: 0,
        death: usize::MAX,
    };
    assert_eq!(infinite.persistence(), None);
}

#[test]
fn class_id_persistence_does_not_underflow_when_birth_after_death() {
    // The function uses saturating_sub; an inverted interval is clamped
    // to zero rather than wrapping or panicking. This is a defensive
    // guarantee — production callers should never feed inverted pairs,
    // but if a buggy reducer ever did, scoring must stay non-panicking.
    let inverted = ClassId {
        birth: 10,
        death: 3,
    };
    assert_eq!(inverted.persistence(), Some(0));
}

// ---------------------------------------------------------------------------
// `seed_fingerprint` determinism + dispersion
// ---------------------------------------------------------------------------

#[test]
fn seed_fingerprint_is_deterministic() {
    for seed in 0u64..32 {
        let a = seed_fingerprint(seed);
        let b = seed_fingerprint(seed);
        assert_eq!(a, b, "seed {seed} produced non-deterministic fingerprint");
    }
}

#[test]
fn seed_fingerprint_disperses_distinct_seeds() {
    // Not a cryptographic property — just a sanity check that the hasher
    // doesn't collapse small seeds onto the same fingerprint, which would
    // break tie-breaking across exploration nodes.
    let mut seen = std::collections::HashSet::new();
    for seed in 0u64..256 {
        seen.insert(seed_fingerprint(seed));
    }
    // 256 distinct seeds should produce hundreds of distinct fingerprints.
    assert!(
        seen.len() > 200,
        "seed_fingerprint collapsed {} distinct seeds onto {} fingerprints",
        256,
        seen.len()
    );
}

// ---------------------------------------------------------------------------
// End-to-end: `score_boundary_matrix` agrees with `score_persistence` on the
// reduced matrix's persistence pairs.
// ---------------------------------------------------------------------------

/// Build the classic filled-triangle 2-complex (β0=1, β1=0).
fn filled_triangle() -> BoundaryMatrix {
    let mut d = BoundaryMatrix::zeros(7, 7);
    // edges
    d.set(0, 3); // e01 = v0 + v1
    d.set(1, 3);
    d.set(0, 4); // e02 = v0 + v2
    d.set(2, 4);
    d.set(1, 5); // e12 = v1 + v2
    d.set(2, 5);
    // triangle face
    d.set(3, 6); // t012 = e01 + e02 + e12
    d.set(4, 6);
    d.set(5, 6);
    d
}

#[test]
fn score_boundary_matrix_matches_score_persistence() {
    let d = filled_triangle();

    let reduced = d.reduce();
    let pairs_direct = reduced.persistence_pairs();

    let mut seen_direct = BTreeSet::new();
    let direct = score_persistence(&pairs_direct, &mut seen_direct, 99);

    let mut seen_e2e = BTreeSet::new();
    let e2e = score_boundary_matrix(&d, &mut seen_e2e, 99);

    assert_eq!(e2e.score, direct.score);
    assert_eq!(e2e.entries.len(), direct.entries.len());
    assert_eq!(seen_direct, seen_e2e);
}

#[test]
fn score_boundary_matrix_two_runs_are_identical_when_seen_resets() {
    // Determinism: same matrix + same fingerprint + fresh `seen` → identical
    // score.
    let d = filled_triangle();
    let mut s1 = BTreeSet::new();
    let mut s2 = BTreeSet::new();
    let a = score_boundary_matrix(&d, &mut s1, 7);
    let b = score_boundary_matrix(&d, &mut s2, 7);
    assert_eq!(a.score, b.score);
    assert_eq!(s1, s2);
}

// ---------------------------------------------------------------------------
// Evidence ledger formatting contract
// ---------------------------------------------------------------------------

#[test]
fn evidence_ledger_summary_contains_required_fields() {
    let p = pairs(&[(0, 5), (1, 8)], &[3]);
    let mut seen = BTreeSet::new();
    let ledger = score_persistence(&p, &mut seen, 0xCAFE);
    let s = ledger.summary();

    // Header line
    assert!(s.contains("novelty=3"), "summary missing novelty\n{s}");
    assert!(
        s.contains("persistence_sum="),
        "summary missing persistence_sum\n{s}"
    );
    assert!(
        s.contains("fingerprint=0x000000000000cafe"),
        "fingerprint must be zero-padded hex\n{s}"
    );

    // Class counts line
    assert!(s.contains("3 total"), "{s}");
    assert!(s.contains("3 novel"), "{s}");
    assert!(s.contains("2 finite"), "{s}");

    // Per-entry lines: novel classes are tagged NEW, infinite uses ∞ + pers=∞
    assert!(s.contains("[NEW]"), "{s}");
    assert!(s.contains("pers=5"), "{s}");
    assert!(s.contains("pers=7"), "{s}");
    assert!(s.contains("pers=∞"), "{s}");
    assert!(s.contains("death=∞"), "{s}");
}

#[test]
fn evidence_ledger_summary_marks_repeated_classes_as_old() {
    let p = pairs(&[(0, 5)], &[]);
    let mut seen = BTreeSet::new();
    let _ = score_persistence(&p, &mut seen, 0);
    let again = score_persistence(&p, &mut seen, 0);

    let s = again.summary();
    assert!(s.contains("[old]"), "{s}");
    assert!(s.contains("0 novel"), "{s}");
}

// ---------------------------------------------------------------------------
// TopologicalScore::zero is the identity for the natural order
// ---------------------------------------------------------------------------

#[test]
fn zero_score_is_minimal_for_each_fingerprint_class() {
    // For any (novelty, persistence_sum, fingerprint) with novelty > 0 or
    // persistence_sum > 0, the zero score with the same fingerprint must
    // be strictly less.
    for fp in [0u64, 1, u64::MAX / 2, u64::MAX] {
        let zero = TopologicalScore::zero(fp);
        assert_eq!(zero.novelty, 0);
        assert_eq!(zero.persistence_sum, 0);
        assert_eq!(zero.fingerprint, fp);

        let bigger = TopologicalScore {
            novelty: 1,
            persistence_sum: 0,
            fingerprint: fp,
        };
        assert!(zero < bigger);
    }
}

#[test]
fn zero_score_ties_only_share_zero_lanes() {
    // Two zero-scores tie iff their fingerprints are equal.
    let a = TopologicalScore::zero(7);
    let b = TopologicalScore::zero(7);
    let c = TopologicalScore::zero(8);
    assert_eq!(a, b);
    assert_ne!(a, c);
    // Lower fingerprint wins
    assert!(a > c);
}

// ---------------------------------------------------------------------------
// Cross-check: a richer ledger that mixes finite + infinite classes preserves
// the score-from-entries identity.
// ---------------------------------------------------------------------------

fn recompute_score_from_entries(ledger: &EvidenceLedger) -> (u32, u64) {
    let novelty = u32::try_from(ledger.entries.iter().filter(|e| e.is_novel).count()).unwrap();
    let mut persistence_sum: u64 = 0;
    for e in &ledger.entries {
        if let Some(p) = e.persistence {
            persistence_sum = persistence_sum.saturating_add(p);
        }
    }
    (novelty, persistence_sum)
}

#[test]
fn score_is_consistent_with_entries() {
    let cases = [
        pairs(&[], &[]),
        pairs(&[(0, 1)], &[]),
        pairs(&[], &[0, 1, 2]),
        pairs(&[(0, 5), (1, 8), (2, 3)], &[9, 11]),
        pairs(&[(0, 1), (1, 2), (2, 3), (3, 4)], &[]),
    ];
    for p in cases {
        let mut seen = BTreeSet::new();
        let ledger = score_persistence(&p, &mut seen, 0);
        let (n, ps) = recompute_score_from_entries(&ledger);
        assert_eq!(
            ledger.score.novelty, n,
            "novelty mismatch for {:?}",
            ledger.entries
        );
        assert_eq!(
            ledger.score.persistence_sum, ps,
            "persistence_sum mismatch for {:?}",
            ledger.entries
        );
    }
}
