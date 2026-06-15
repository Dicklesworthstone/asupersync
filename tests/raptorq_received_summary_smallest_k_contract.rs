//! RaptorQ `ReceivedSummary::from_received` — smallest-K selection and
//! order-independent multiset-hash conformance.
//!
//! bd-3uox5 (RAPTORQ-RFC6330). The replay/forensics layer summarizes the set of
//! symbols a decode actually consumed through `ReceivedSummary::from_received`
//! (`raptorq::proof`). It partitions counts into source/repair, retains the
//! SMALLEST `MAX_RECEIVED_SYMBOLS` ESIs in ascending order (via a bounded heap),
//! flags truncation, and folds a deterministic multiset hash that binds replay
//! verification to entries pushed out of the bounded preview.
//!
//! The constructor had ZERO integration coverage — only the `ReceivedSummary`
//! TYPE is referenced elsewhere, never `from_received` itself — so nothing
//! pinned the two non-obvious guarantees the replay contract leans on: that the
//! preview list is the globally smallest K ESIs (not merely the first K seen),
//! and that the multiset hash is invariant to the order symbols arrive in while
//! still binding the `is_source` flag and multiplicity.
//!
//! This harness pins them oracle-free, recomputing every expectation from the
//! input pairs and the public `MAX_RECEIVED_SYMBOLS` constant:
//!   - counts partition exactly: `total == source_count + repair_count`;
//!   - `esis` equals the input ESIs sorted ascending and truncated to the cap —
//!     proven with a reversed/scrambled feed so a first-K shortcut would fail;
//!   - `truncated` is `total > MAX_RECEIVED_SYMBOLS`, pinned at cap and cap+1;
//!   - the WHOLE summary is invariant under input permutation (the heap output
//!     is sorted and every hash accumulator is a commutative `wrapping_add`);
//!   - the multiset hash binds the `is_source` flag and is multiplicity- (not
//!     just set-) sensitive;
//!   - the empty input yields the deterministic zero summary.
//!
//! Repro: `cargo test --test raptorq_received_summary_smallest_k_contract`

use asupersync::raptorq::proof::{MAX_RECEIVED_SYMBOLS, ReceivedSummary};

/// Oracle for the retained preview list: the input ESIs, sorted ascending and
/// truncated to the smallest `MAX_RECEIVED_SYMBOLS` entries (multiplicity kept).
fn expected_esis(pairs: &[(u32, bool)]) -> Vec<u32> {
    let mut esis: Vec<u32> = pairs.iter().map(|&(esi, _)| esi).collect();
    esis.sort_unstable();
    esis.truncate(MAX_RECEIVED_SYMBOLS);
    esis
}

fn summary(pairs: &[(u32, bool)]) -> ReceivedSummary {
    ReceivedSummary::from_received(pairs.iter().copied())
}

#[test]
fn counts_partition_total_into_source_and_repair() {
    // Interleave a known number of source and repair symbols.
    let mut pairs = Vec::new();
    for i in 0..10u32 {
        pairs.push((i, true)); // source
    }
    for i in 0..7u32 {
        pairs.push((100 + i, false)); // repair
    }
    let s = summary(&pairs);
    assert_eq!(s.total, 17);
    assert_eq!(s.source_count, 10);
    assert_eq!(s.repair_count, 7);
    assert_eq!(
        s.total,
        s.source_count + s.repair_count,
        "every symbol is exactly source xor repair"
    );
    assert!(!s.truncated, "well below the cap");
}

#[test]
fn esis_are_the_sorted_full_set_below_cap() {
    // Shuffled ESIs with duplicates, comfortably below the cap.
    let pairs: Vec<(u32, bool)> = [9u32, 3, 3, 7, 1, 8, 1, 5, 0, 9]
        .into_iter()
        .enumerate()
        .map(|(i, esi)| (esi, i % 2 == 0))
        .collect();
    let s = summary(&pairs);
    assert!(!s.truncated);
    assert_eq!(s.esis, expected_esis(&pairs), "ascending full multiset");
    // Sanity: explicitly ascending (multiset duplicates retained).
    assert_eq!(s.esis, vec![0, 1, 1, 3, 3, 5, 7, 8, 9, 9]);
    assert_eq!(s.total, 10);
}

#[test]
fn esis_are_the_globally_smallest_k_when_truncated() {
    // Feed distinct ESIs 0..N in DESCENDING order so the smallest are seen LAST.
    // A first-K-seen shortcut would retain the largest K and fail this test.
    let n = (MAX_RECEIVED_SYMBOLS + 300) as u32;
    let pairs: Vec<(u32, bool)> = (0..n).rev().map(|esi| (esi, esi % 3 == 0)).collect();
    let s = summary(&pairs);

    assert_eq!(s.total, n as usize);
    assert!(s.truncated, "total exceeds the cap");
    assert_eq!(s.esis.len(), MAX_RECEIVED_SYMBOLS, "preview frozen at cap");
    // The globally smallest cap ESIs are 0..cap, ascending.
    let want: Vec<u32> = (0..MAX_RECEIVED_SYMBOLS as u32).collect();
    assert_eq!(s.esis, want, "retains the smallest K, not the first K seen");
    assert_eq!(s.esis, expected_esis(&pairs));
}

#[test]
fn truncated_flag_tracks_the_cap_boundary() {
    for (count, want_truncated) in [
        (MAX_RECEIVED_SYMBOLS - 1, false),
        (MAX_RECEIVED_SYMBOLS, false),
        (MAX_RECEIVED_SYMBOLS + 1, true),
    ] {
        let pairs: Vec<(u32, bool)> = (0..count as u32).map(|esi| (esi, true)).collect();
        let s = summary(&pairs);
        assert_eq!(s.total, count);
        assert_eq!(
            s.truncated, want_truncated,
            "truncated must be (total > cap) at count={count}"
        );
        assert_eq!(
            s.esis.len(),
            count.min(MAX_RECEIVED_SYMBOLS),
            "preview length is min(total, cap)"
        );
    }
}

#[test]
fn summary_is_invariant_under_input_permutation() {
    // Both below and above the cap: the heap output is sorted and every hash
    // accumulator is a commutative wrapping_add, so order cannot matter.
    for n in [200u32, (MAX_RECEIVED_SYMBOLS + 150) as u32] {
        let forward: Vec<(u32, bool)> = (0..n).map(|esi| (esi, esi % 2 == 0)).collect();

        let mut reversed = forward.clone();
        reversed.reverse();

        // A deterministic non-trivial shuffle: swap symmetric positions.
        let mut shuffled = forward.clone();
        let len = shuffled.len();
        for i in 0..len / 3 {
            shuffled.swap(i, len - 1 - i);
        }

        let base = summary(&forward);
        assert_eq!(base, summary(&reversed), "reversed feed (n={n})");
        assert_eq!(base, summary(&shuffled), "shuffled feed (n={n})");
        // Hash is the load-bearing order-free field once the preview truncates.
        assert_eq!(base.esi_multiset_hash, summary(&reversed).esi_multiset_hash);
    }
}

#[test]
fn multiset_hash_binds_the_is_source_flag() {
    // Identical ESIs, but one symbol flips source<->repair: the counts shift and
    // the hash must change because `observe` folds (esi, is_source) together.
    let source = [(1u32, true), (2, true), (3, true)];
    let one_repair = [(1u32, true), (2, false), (3, true)];

    let a = ReceivedSummary::from_received(source.into_iter());
    let b = ReceivedSummary::from_received(one_repair.into_iter());

    assert_eq!(a.esis, b.esis, "same ESI preview");
    assert_eq!(a.total, b.total);
    assert_ne!(a.source_count, b.source_count, "the flip moved one count");
    assert_ne!(
        a.esi_multiset_hash, b.esi_multiset_hash,
        "hash binds the is_source flag, not just the ESI set"
    );
}

#[test]
fn multiset_hash_is_multiplicity_sensitive() {
    // Same SET {1,2}, different multisets => different hashes.
    let m1 = [(1u32, true), (1, true), (2, true)]; // {1:2, 2:1}
    let m2 = [(1u32, true), (2, true), (2, true)]; // {1:1, 2:2}
    let h1 = ReceivedSummary::from_received(m1.into_iter()).esi_multiset_hash;
    let h2 = ReceivedSummary::from_received(m2.into_iter()).esi_multiset_hash;
    assert_ne!(h1, h2, "hash distinguishes multiset multiplicities");

    // Adding a duplicate (changing the count) also changes the hash.
    let base = [(5u32, false), (6, false)];
    let plus_dup = [(5u32, false), (6, false), (5, false)];
    let hb = ReceivedSummary::from_received(base.into_iter()).esi_multiset_hash;
    let hd = ReceivedSummary::from_received(plus_dup.into_iter()).esi_multiset_hash;
    assert_ne!(hb, hd, "an extra occurrence changes the hash");
}

#[test]
fn empty_input_is_the_deterministic_zero_summary() {
    let s = ReceivedSummary::from_received(std::iter::empty());
    assert_eq!(s.total, 0);
    assert_eq!(s.source_count, 0);
    assert_eq!(s.repair_count, 0);
    assert!(s.esis.is_empty());
    assert!(!s.truncated);
    // The empty hash is deterministic across constructions.
    let s2 = ReceivedSummary::from_received(std::iter::empty());
    assert_eq!(s, s2, "empty summary is reproducible");
}
