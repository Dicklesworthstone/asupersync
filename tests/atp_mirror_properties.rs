//! Property/metamorphic safety hardening for ATP mirror (b0k8qo.11.3 / J3).
//!
//! Mirror deletes receiver files, so its safety invariants are fuzzed over
//! random destination trees + random keep sets on real temp directories:
//!
//! - **Exactness**: after an enabled mirror the destination contains exactly the
//!   kept files (every kept file survives; every extra is gone) — the core
//!   "never delete a kept file, always delete the extras" guarantee.
//! - **Dry-run is inert**: a dry-run never deletes anything yet still reports the
//!   would-be deletions.
//! - **Idempotence**: mirroring an already-mirrored tree deletes nothing.
//!
//! `Cx::for_testing` requires `--features test-internals`.

#![allow(missing_docs)]

use std::collections::BTreeSet;
use std::path::Path;

use asupersync::cx::Cx;
use asupersync::net::atp::transport_common::{MirrorPolicy, mirror_dest};
use proptest::prelude::*;

fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    futures_lite::future::block_on(fut)
}

/// `a` is a strict ancestor directory of `b` (`b` lies beneath `a/`).
fn is_ancestor(a: &str, b: &str) -> bool {
    a != b && b.strip_prefix(a).is_some_and(|rest| rest.starts_with('/'))
}

/// Reduce raw generated paths to a set of distinct *leaf* files: dedup, then keep
/// only paths that are not an ancestor of any other (so no path is both a file
/// and a directory — building them as files never conflicts).
fn leaf_files(raw: Vec<(String, bool)>) -> Vec<(String, bool)> {
    let mut seen = BTreeSet::new();
    let uniq: Vec<(String, bool)> = raw
        .into_iter()
        .filter(|(p, _)| !p.is_empty() && seen.insert(p.clone()))
        .collect();
    uniq.iter()
        .filter(|(p, _)| !uniq.iter().any(|(q, _)| is_ancestor(p, q)))
        .cloned()
        .collect()
}

/// Materialize each `(rel, _)` as a file under `dest`.
fn build_tree(dest: &Path, files: &[(String, bool)]) {
    for (rel, _) in files {
        let path = dest.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&path, b"x").unwrap();
    }
}

fn keep_set(files: &[(String, bool)]) -> BTreeSet<String> {
    files
        .iter()
        .filter(|(_, k)| *k)
        .map(|(p, _)| p.clone())
        .collect()
}

const FILES_STRAT: &str = "[a-z]{1,4}(/[a-z]{1,4}){0,2}";

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// After an enabled mirror, the destination holds exactly the kept files:
    /// every kept file survives and every extra is removed.
    #[test]
    fn mirror_makes_dest_exactly_the_kept_set(
        raw in prop::collection::vec((FILES_STRAT, any::<bool>()), 1..7),
    ) {
        let files = leaf_files(raw);
        prop_assume!(!files.is_empty());

        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path();
        build_tree(dest, &files);
        let keep = keep_set(&files);

        let cx = Cx::for_testing();
        let report = block_on(mirror_dest(
            &cx,
            dest,
            &keep,
            MirrorPolicy { enabled: true, max_delete_fraction: 1.0 },
        ))
        .unwrap();
        prop_assert!(!report.dry_run);

        for (rel, kept) in &files {
            let exists = dest.join(rel).exists();
            if *kept {
                prop_assert!(exists, "kept file {rel:?} was deleted by mirror");
            } else {
                prop_assert!(!exists, "extra file {rel:?} survived mirror");
            }
        }
    }

    /// A dry-run deletes nothing but still reports the would-be deletions.
    #[test]
    fn dry_run_is_inert_but_reports(
        raw in prop::collection::vec((FILES_STRAT, any::<bool>()), 1..7),
    ) {
        let files = leaf_files(raw);
        prop_assume!(!files.is_empty());

        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path();
        build_tree(dest, &files);
        let keep = keep_set(&files);
        let extras = files.iter().filter(|(_, k)| !*k).count();

        let cx = Cx::for_testing();
        let report = block_on(mirror_dest(
            &cx,
            dest,
            &keep,
            MirrorPolicy { enabled: false, max_delete_fraction: 1.0 },
        ))
        .unwrap();

        prop_assert!(report.dry_run);
        prop_assert_eq!(report.deleted, 0);
        // The plan covers at least every extra file (it may also list extra dirs).
        prop_assert!(report.planned.len() >= extras);
        // Everything still on disk.
        for (rel, _) in &files {
            prop_assert!(dest.join(rel).exists(), "dry-run deleted {rel:?}");
        }
        // Each extra file is reported as a planned deletion.
        let planned: BTreeSet<&str> =
            report.planned.iter().map(|e| e.rel_path.as_str()).collect();
        for (rel, kept) in &files {
            if !*kept {
                prop_assert!(planned.contains(rel.as_str()), "extra {rel:?} not in plan");
            }
        }
    }

    /// Mirroring an already-mirrored tree is a no-op (the extras are already gone).
    #[test]
    fn mirror_is_idempotent(
        raw in prop::collection::vec((FILES_STRAT, any::<bool>()), 1..7),
    ) {
        let files = leaf_files(raw);
        prop_assume!(!files.is_empty());

        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path();
        build_tree(dest, &files);
        let keep = keep_set(&files);
        let policy = MirrorPolicy { enabled: true, max_delete_fraction: 1.0 };

        let cx = Cx::for_testing();
        block_on(mirror_dest(&cx, dest, &keep, policy)).unwrap();
        let second = block_on(mirror_dest(&cx, dest, &keep, policy)).unwrap();
        prop_assert_eq!(second.deleted, 0, "second mirror should delete nothing");
        prop_assert!(second.planned.is_empty(), "second mirror should plan nothing");
    }
}
