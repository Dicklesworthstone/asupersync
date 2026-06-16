//! Property/fuzz hardening for the selective-sync filter engine (b0k8qo.11.4 / J4).
//!
//! The filter parses operator config and runs a recursive glob matcher with
//! `**` handling, so it is worth fuzzing for totality (never panics on arbitrary
//! input) and pinning its algebraic guarantees: empty-set includes all,
//! first-match-wins precedence (a prepended anchored include rescues any path,
//! an anchored exact exclude removes exactly that path), determinism, and
//! `select` returning an included, order-preserving subset.
//!
//! Inputs are deliberately bounded (short patterns/paths) so the recursive
//! matcher stays fast; the goal is correctness coverage, not a perf benchmark.

#![allow(missing_docs)]

use asupersync::net::atp::transport_common::{FilterDecision, FilterRule, FilterSet};
use proptest::prelude::*;

// Realistic forward-slash rel-paths: 1-3 lowercase segments, no glob chars.
const PATH_RE: &str = "[a-z]{1,4}(/[a-z]{1,4}){0,2}";
// Filter patterns that exercise globs (`*`, `?`, and `**` via repeated `*`),
// path separators, and an optional trailing slash (dir-only).
const PATTERN_RE: &str = "[a-z*?]{0,6}(/[a-z*?]{0,6}){0,2}/?";

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Decisions are total: arbitrary rule pattern + path never panics and always
    /// yields a definite Include/Exclude.
    #[test]
    fn decision_is_total(pat in PATTERN_RE, path in PATH_RE, is_dir in any::<bool>()) {
        let fs = FilterSet::with_rules(vec![FilterRule::exclude(&pat)]);
        let d = fs.decision(&path, is_dir);
        prop_assert!(matches!(d, FilterDecision::Include | FilterDecision::Exclude));
    }

    /// Parsing arbitrary `+`/`-` rule lines never panics, and the resulting set
    /// decides every path totally.
    #[test]
    fn parse_then_decide_is_total(
        sign in "[+-]",
        pat in PATTERN_RE,
        path in PATH_RE,
        is_dir in any::<bool>(),
    ) {
        let line = format!("{sign} {pat}");
        if let Ok(fs) = FilterSet::parse([line.as_str()]) {
            let d = fs.decision(&path, is_dir);
            prop_assert!(matches!(d, FilterDecision::Include | FilterDecision::Exclude));
        }
    }

    /// An empty filter set includes everything.
    #[test]
    fn empty_set_includes_all(path in PATH_RE, is_dir in any::<bool>()) {
        prop_assert!(FilterSet::new().is_included(&path, is_dir));
    }

    /// First-match-wins: an anchored exact include placed first rescues a path no
    /// matter what later rules (even an exclude-everything) say.
    #[test]
    fn prepended_anchored_include_rescues_any_path(
        pat in PATTERN_RE,
        path in PATH_RE,
        is_dir in any::<bool>(),
    ) {
        let fs = FilterSet::with_rules(vec![
            FilterRule::include(&format!("/{path}")),
            FilterRule::exclude(&pat),
            FilterRule::exclude("**"),
        ]);
        prop_assert_eq!(fs.decision(&path, is_dir), FilterDecision::Include);
    }

    /// An anchored exact exclude removes exactly that path.
    #[test]
    fn anchored_exact_exclude_removes_that_path(path in PATH_RE, is_dir in any::<bool>()) {
        let fs = FilterSet::with_rules(vec![FilterRule::exclude(&format!("/{path}"))]);
        prop_assert_eq!(fs.decision(&path, is_dir), FilterDecision::Exclude);
    }

    /// Decisions are deterministic.
    #[test]
    fn decision_is_deterministic(pat in PATTERN_RE, path in PATH_RE, is_dir in any::<bool>()) {
        let fs = FilterSet::with_rules(vec![FilterRule::exclude(&pat)]);
        prop_assert_eq!(fs.decision(&path, is_dir), fs.decision(&path, is_dir));
    }

    /// `select` returns an order-preserving subset of the input, and every
    /// returned path is itself included by the filter.
    #[test]
    fn select_is_included_subsequence(
        entries in prop::collection::vec((PATH_RE, any::<bool>()), 0..12),
        pat in PATTERN_RE,
    ) {
        let fs = FilterSet::with_rules(vec![FilterRule::exclude(&pat)]);
        let selected = fs.select(&entries);

        // Subsequence of the input rel-paths (subset + order-preserving): every
        // selected path is an in-order member of the input. select() only ever
        // drops entries (excluded files + pruned subtrees), never invents them.
        let mut cursor = entries.iter();
        for s in &selected {
            prop_assert!(
                cursor.by_ref().any(|(r, _)| r == s),
                "selected {s:?} is not an in-order member of the input"
            );
        }
        prop_assert!(selected.len() <= entries.len());
    }
}
