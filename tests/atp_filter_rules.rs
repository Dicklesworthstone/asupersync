//! ATP include/exclude filter contract (b0k8qo.11.4 / J4).
//!
//! Pins the selective-sync filter engine from outside the crate: deterministic
//! first-match-wins precedence, glob + anchored + dir-only patterns, basename
//! matching at any depth, directory-subtree pruning, and the headline acceptance
//! — exclude `target/` and `*.tmp` but rescue a needed subdir, with the
//! transferred set matching exactly. Pure (no runtime/features needed).

#![allow(missing_docs)]

use asupersync::net::atp::transport_common::{FilterDecision, FilterRule, FilterSet};

#[test]
fn acceptance_excludes_target_and_tmp_but_keeps_a_needed_subdir() {
    // Rules are ordered; the leading include rescues src/keep before the excludes.
    let fs = FilterSet::parse(["+ src/keep/", "- target/", "- *.tmp"]).unwrap();

    let entries = vec![
        ("src".to_string(), true),
        ("src/main.rs".to_string(), false),
        ("src/keep".to_string(), true),
        ("src/keep/important.rs".to_string(), false),
        ("src/keep/cache.tmp".to_string(), false), // rescued: under an included dir? no — see note
        ("src/scratch.tmp".to_string(), false),
        ("target".to_string(), true),
        ("target/app".to_string(), false),
        ("target/debug".to_string(), true),
        ("target/debug/app".to_string(), false),
        ("notes.tmp".to_string(), false),
    ];
    let selected = fs.select(&entries);

    // target/ subtree fully pruned.
    assert!(!selected.iter().any(|p| p.starts_with("target")));
    // *.tmp excluded everywhere it is matched by the basename rule...
    assert!(selected.contains(&"src/main.rs".to_string()));
    assert!(selected.contains(&"src/keep".to_string()));
    assert!(selected.contains(&"src/keep/important.rs".to_string()));
    // The include rule matched the *directory* src/keep (rescue), but *.tmp still
    // excludes individual tmp files (first-match: "+ src/keep/" only matches the
    // dir, not the tmp file, so "- *.tmp" wins for the file).
    assert!(!selected.contains(&"src/keep/cache.tmp".to_string()));
    assert!(!selected.contains(&"src/scratch.tmp".to_string()));
    assert!(!selected.contains(&"notes.tmp".to_string()));
}

#[test]
fn first_match_wins_is_deterministic() {
    // Include before exclude -> rescued.
    let rescue = FilterSet::with_rules(vec![
        FilterRule::include("keep.tmp"),
        FilterRule::exclude("*.tmp"),
    ]);
    assert_eq!(rescue.decision("keep.tmp", false), FilterDecision::Include);
    assert_eq!(rescue.decision("other.tmp", false), FilterDecision::Exclude);

    // Reverse order -> the exclude wins first, so it is NOT rescued.
    let no_rescue = FilterSet::with_rules(vec![
        FilterRule::exclude("*.tmp"),
        FilterRule::include("keep.tmp"),
    ]);
    assert_eq!(
        no_rescue.decision("keep.tmp", false),
        FilterDecision::Exclude
    );
}

#[test]
fn unmatched_paths_default_to_include() {
    let fs = FilterSet::parse(["- *.tmp"]).unwrap();
    assert!(fs.is_included("src/main.rs", false));
    assert!(fs.is_included("README.md", false));
    assert!(!fs.is_included("a/b/c.tmp", false));
}

#[test]
fn anchored_vs_basename_matching() {
    // Non-anchored: matches at any depth (basename).
    let any = FilterSet::with_rules(vec![FilterRule::exclude("node_modules/")]);
    assert!(!any.is_included("node_modules", true));
    assert!(!any.is_included("a/b/node_modules", true));
    // Anchored (leading slash): only at the root.
    let root = FilterSet::with_rules(vec![FilterRule::exclude("/build")]);
    assert!(!root.is_included("build", true));
    assert!(root.is_included("sub/build", true));
}

#[test]
fn double_star_anchored_pattern() {
    let fs = FilterSet::with_rules(vec![FilterRule::exclude("src/**/generated.rs")]);
    assert!(!fs.is_included("src/generated.rs", false));
    assert!(!fs.is_included("src/a/b/generated.rs", false));
    assert!(fs.is_included("other/generated.rs", false));
}

#[test]
fn select_preserves_order_and_prunes_subtrees() {
    let fs = FilterSet::with_rules(vec![FilterRule::exclude("ex/")]);
    let entries = vec![
        ("a".to_string(), false),
        ("ex".to_string(), true),
        ("ex/deep".to_string(), true),
        ("ex/deep/file".to_string(), false),
        ("z".to_string(), false),
    ];
    assert_eq!(fs.select(&entries), vec!["a".to_string(), "z".to_string()]);
}

#[test]
fn empty_filter_includes_all() {
    let fs = FilterSet::new();
    let entries = vec![("a".to_string(), false), ("b/c.tmp".to_string(), false)];
    assert_eq!(
        fs.select(&entries),
        vec!["a".to_string(), "b/c.tmp".to_string()]
    );
}
