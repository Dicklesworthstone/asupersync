//! ATP mirror (`rsync --delete`) safety contract (b0k8qo.11.3 / J3).
//!
//! Pins the receiver-side mirror reconciliation: it removes exactly the
//! destination entries absent from the sender manifest and only those, never
//! outside the destination root, with a dry-run preview that deletes nothing, a
//! max-delete fraction guard that aborts pathological cases, and symlinks
//! treated as leaves (the link is unlinked, never its target).
//!
//! Uses real temp directories (no network). `Cx::for_testing` requires
//! `--features test-internals`.

#![allow(missing_docs)]

use std::collections::BTreeSet;
use std::path::Path;

use asupersync::cx::Cx;
use asupersync::net::atp::transport_common::{
    MirrorEntryKind, MirrorError, MirrorPolicy, MirrorReport, mirror_dest,
};

fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    futures_lite::future::block_on(fut)
}

fn keep(paths: &[&str]) -> BTreeSet<String> {
    paths.iter().map(|p| (*p).to_string()).collect()
}

fn mkfile(base: &Path, rel: &str, contents: &[u8]) {
    let path = base.join(rel);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, contents).unwrap();
}

fn run_mirror(dest: &Path, keep_set: &BTreeSet<String>, policy: MirrorPolicy) -> MirrorReport {
    let cx = Cx::for_testing();
    block_on(mirror_dest(&cx, dest, keep_set, policy)).unwrap()
}

#[test]
fn removes_exactly_the_extras_and_only_those() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path();
    // Manifest files (kept).
    mkfile(dest, "keep/a.txt", b"a");
    mkfile(dest, "keep/sub/b.txt", b"b");
    // Extras: a top-level file, a whole extra dir, and a file inside a kept dir.
    mkfile(dest, "extra.txt", b"x");
    mkfile(dest, "extradir/c.txt", b"c");
    mkfile(dest, "extradir/nested/d.txt", b"d");
    mkfile(dest, "keep/junk.txt", b"j");

    let report = run_mirror(
        dest,
        &keep(&["keep/a.txt", "keep/sub/b.txt"]),
        MirrorPolicy {
            enabled: true,
            max_delete_fraction: 1.0,
        },
    );

    assert!(!report.dry_run);
    // Kept files + their ancestor dirs survive.
    assert!(dest.join("keep/a.txt").exists());
    assert!(dest.join("keep/sub/b.txt").exists());
    assert!(dest.join("keep").is_dir());
    assert!(dest.join("keep/sub").is_dir());
    // Every extra is gone — and only the extras.
    assert!(!dest.join("extra.txt").exists());
    assert!(!dest.join("extradir").exists());
    assert!(!dest.join("keep/junk.txt").exists());
    // extras: extra.txt, keep/junk.txt, extradir, extradir/c.txt,
    // extradir/nested, extradir/nested/d.txt = 6
    assert_eq!(report.deleted, 6);
    assert_eq!(report.planned.len(), 6);
}

#[test]
fn dry_run_lists_without_deleting() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path();
    mkfile(dest, "keep.txt", b"k");
    mkfile(dest, "gone.txt", b"g");
    mkfile(dest, "gonedir/x.txt", b"x");

    // Default policy is a dry-run.
    let report = run_mirror(dest, &keep(&["keep.txt"]), MirrorPolicy::default());

    assert!(report.dry_run);
    assert_eq!(report.deleted, 0);
    // Plan lists the extras (gone.txt, gonedir, gonedir/x.txt).
    let planned: BTreeSet<&str> = report.planned.iter().map(|e| e.rel_path.as_str()).collect();
    assert!(planned.contains("gone.txt"));
    assert!(planned.contains("gonedir"));
    assert!(planned.contains("gonedir/x.txt"));
    // Nothing was actually deleted.
    assert!(dest.join("keep.txt").exists());
    assert!(dest.join("gone.txt").exists());
    assert!(dest.join("gonedir/x.txt").exists());
}

#[test]
fn max_delete_guard_aborts_pathological_case() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path();
    // Receiver is full but the manifest is (near) empty -> would delete ~everything.
    mkfile(dest, "f1.txt", b"1");
    mkfile(dest, "f2.txt", b"2");
    mkfile(dest, "f3.txt", b"3");
    mkfile(dest, "f4.txt", b"4");

    let cx = Cx::for_testing();
    let result = block_on(mirror_dest(
        &cx,
        dest,
        &keep(&["f1.txt"]), // keep 1 of 4 -> 75% would be deleted
        MirrorPolicy {
            enabled: true,
            max_delete_fraction: 0.5,
        },
    ));

    match result {
        Err(MirrorError::MaxDeleteGuard {
            would_delete,
            dest_entries,
            ..
        }) => {
            assert_eq!(dest_entries, 4);
            assert_eq!(would_delete, 3);
        }
        other => panic!("expected MaxDeleteGuard, got {other:?}"),
    }
    // Guard tripped before any deletion: everything is still present.
    for f in ["f1.txt", "f2.txt", "f3.txt", "f4.txt"] {
        assert!(dest.join(f).exists(), "{f} must survive an aborted mirror");
    }
}

#[test]
fn empty_keep_under_full_guard_is_allowed_only_when_unbounded() {
    // With the guard disabled (1.0), an empty manifest legitimately clears all.
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path();
    mkfile(dest, "only.txt", b"o");
    let report = run_mirror(
        dest,
        &BTreeSet::new(),
        MirrorPolicy {
            enabled: true,
            max_delete_fraction: 1.0,
        },
    );
    assert_eq!(report.deleted, 1);
    assert!(!dest.join("only.txt").exists());
}

#[cfg(unix)]
#[test]
fn extra_symlink_is_unlinked_never_followed() {
    let outside = tempfile::tempdir().unwrap();
    let target = outside.path().join("precious.txt");
    std::fs::write(&target, b"do not delete me").unwrap();

    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path();
    mkfile(dest, "keep.txt", b"k");
    // An extra symlink inside dest pointing OUTSIDE dest.
    let link = dest.join("escape_link");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    let report = run_mirror(
        dest,
        &keep(&["keep.txt"]),
        MirrorPolicy {
            enabled: true,
            max_delete_fraction: 1.0,
        },
    );

    // The symlink entry was classified as a symlink and removed...
    assert!(
        report
            .planned
            .iter()
            .any(|e| e.kind == MirrorEntryKind::Symlink)
    );
    assert!(!link.exists(), "the symlink itself must be removed");
    // ...but its target outside the destination is untouched.
    assert!(
        target.exists(),
        "mirror must never follow a symlink out of dest"
    );
    assert!(dest.join("keep.txt").exists());
}

#[test]
fn missing_destination_is_a_noop() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("does-not-exist");
    let report = run_mirror(
        &missing,
        &keep(&["anything"]),
        MirrorPolicy {
            enabled: true,
            max_delete_fraction: 1.0,
        },
    );
    assert_eq!(report.dest_entries, 0);
    assert_eq!(report.deleted, 0);
    assert!(report.planned.is_empty());
}

#[test]
fn deep_kept_file_preserves_all_ancestor_dirs() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path();
    mkfile(dest, "deep/nested/path/file.txt", b"f");
    mkfile(dest, "deep/extra.txt", b"e");

    let report = run_mirror(
        dest,
        &keep(&["deep/nested/path/file.txt"]),
        MirrorPolicy {
            enabled: true,
            max_delete_fraction: 1.0,
        },
    );

    assert_eq!(report.deleted, 1);
    assert!(dest.join("deep/nested/path/file.txt").exists());
    assert!(dest.join("deep").is_dir());
    assert!(dest.join("deep/nested").is_dir());
    assert!(dest.join("deep/nested/path").is_dir());
    assert!(!dest.join("deep/extra.txt").exists());
}
