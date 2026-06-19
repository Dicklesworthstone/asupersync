//! ATP dry-run plan + progress reporting contract (b0k8qo.11.5 / J5).
//!
//! Pins the rsync-UX-parity primitives: `plan_transfer` computes the exact
//! transfer plan (file list, sizes, SHA-256s, total bytes, merkle root) from a
//! real source tree without any network I/O, and `TransferProgress` yields a
//! monotonic completion fraction + throughput + plausible ETA.
//!
//! `plan_transfer` uses real temp dirs; `Cx::for_testing` requires
//! `--features test-internals`.

#![allow(missing_docs)]

use std::time::Duration;

use asupersync::atp::object::MetadataPolicy;
use asupersync::cx::Cx;
use asupersync::net::atp::transport_common::{TransferPlan, TransferProgress, plan_transfer};

const HELLO_WORLD_SHA256: &str = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

/// Plan with the same defaults the `atp` CLI / real TCP send uses
/// (`MetadataPolicy::default()`, hardlinks off).
fn plan(source: &std::path::Path) -> TransferPlan {
    let cx = Cx::for_testing();
    futures_lite::future::block_on(plan_transfer(
        &cx,
        source,
        4096,
        &MetadataPolicy::default(),
        false,
    ))
    .unwrap()
}

#[test]
fn dry_run_plan_of_single_file_is_network_free_and_exact() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("hello.txt");
    std::fs::write(&file, b"hello world").unwrap();

    let p = plan(&file);
    assert!(!p.is_directory);
    assert_eq!(p.file_count, 1);
    assert_eq!(p.total_bytes, 11);
    assert_eq!(p.entries.len(), 1);
    assert_eq!(p.entries[0].size, 11);
    assert_eq!(p.entries[0].sha256_hex, HELLO_WORLD_SHA256);
    assert_eq!(p.merkle_root_hex.len(), 64);
}

#[test]
fn dry_run_plan_of_directory_lists_every_file() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path();
    std::fs::create_dir_all(base.join("sub")).unwrap();
    std::fs::write(base.join("a.txt"), b"aaaa").unwrap(); // 4
    std::fs::write(base.join("sub/b.txt"), b"bbbbbb").unwrap(); // 6

    let p = plan(base);
    assert!(p.is_directory);
    assert_eq!(p.file_count, 2);
    assert_eq!(p.total_bytes, 10);
    let rels: std::collections::BTreeSet<&str> =
        p.entries.iter().map(|e| e.rel_path.as_str()).collect();
    assert!(rels.contains("a.txt"));
    assert!(rels.contains("sub/b.txt"));
    assert_eq!(p.merkle_root_hex.len(), 64);
}

#[test]
fn dry_run_plan_handles_empty_dirs_without_eisdir() {
    // Regression: `plan_transfer` used to hash *every* entry, but
    // `collect_entries` emits an explicit entry for an empty subdir (J2). Opening
    // a directory as a file and reading it yields `EISDIR`, so the dry-run errored
    // on any tree with an empty dir. The faithful plan classifies it as a
    // zero-content directory entry — exactly what the sender commits.
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path();
    std::fs::write(base.join("a.txt"), b"aaaa").unwrap(); // 4 bytes of content
    std::fs::create_dir_all(base.join("empty")).unwrap(); // empty subdir -> J2 entry

    let p = plan(base); // must not error
    assert!(p.is_directory);
    // Only the regular file contributes bytes; the directory is zero-content.
    assert_eq!(p.total_bytes, 4);
    let by_rel: std::collections::BTreeMap<&str, u64> = p
        .entries
        .iter()
        .map(|e| (e.rel_path.as_str(), e.size))
        .collect();
    assert_eq!(by_rel.get("a.txt"), Some(&4));
    assert_eq!(
        by_rel.get("empty"),
        Some(&0),
        "empty dir is a zero-content plan entry, not a hashed file"
    );
    assert_eq!(p.merkle_root_hex.len(), 64);
}

#[cfg(unix)]
#[test]
fn dry_run_plan_treats_symlink_as_zero_content() {
    // With `preserve_symlinks` (the default), a symlink carries its target as
    // metadata and contributes zero content bytes — it must NOT be followed and
    // hashed as if it were the target's bytes.
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path();
    std::fs::write(base.join("real.txt"), b"hello world").unwrap(); // 11 bytes
    std::os::unix::fs::symlink("real.txt", base.join("link.txt")).unwrap();

    let p = plan(base);
    let by_rel: std::collections::BTreeMap<&str, u64> = p
        .entries
        .iter()
        .map(|e| (e.rel_path.as_str(), e.size))
        .collect();
    assert_eq!(by_rel.get("real.txt"), Some(&11));
    assert_eq!(
        by_rel.get("link.txt"),
        Some(&0),
        "symlink carries no content bytes in the plan"
    );
    // The target's bytes are counted once (for the real file), not twice.
    assert_eq!(p.total_bytes, 11);
}

#[cfg(unix)]
#[test]
fn dry_run_plan_tolerates_dangling_symlink() {
    // Regression: the old code did `File::open` on the symlink, which `ENOENT`s on
    // a dangling link and failed the whole dry-run. A preserved symlink records
    // its (possibly broken) target as metadata and is zero-content.
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path();
    std::fs::write(base.join("real.txt"), b"data!").unwrap(); // 5 bytes
    std::os::unix::fs::symlink("nonexistent-target", base.join("dangling")).unwrap();

    let p = plan(base); // must not error
    let by_rel: std::collections::BTreeMap<&str, u64> = p
        .entries
        .iter()
        .map(|e| (e.rel_path.as_str(), e.size))
        .collect();
    assert_eq!(by_rel.get("dangling"), Some(&0));
    assert_eq!(p.total_bytes, 5);
}

#[test]
fn dry_run_plan_is_deterministic() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path();
    std::fs::write(base.join("x.bin"), vec![7u8; 5000]).unwrap();
    std::fs::write(base.join("y.bin"), vec![9u8; 1234]).unwrap();

    let a = plan(base);
    let b = plan(base);
    assert_eq!(
        a, b,
        "plan_transfer must be deterministic (no clock/network)"
    );
    assert_eq!(a.total_bytes, 6234);
}

#[test]
fn progress_fraction_rate_and_eta_are_plausible() {
    let mut p = TransferProgress::new(1000, 4);
    p.record_bytes(250);
    p.record_file();
    let s = p.snapshot(Duration::from_secs(1));
    assert!((s.fraction - 0.25).abs() < 1e-9);
    assert!((s.rate_bytes_per_sec - 250.0).abs() < 1e-9);
    assert_eq!(s.files_done, 1);
    // 750 bytes remaining at 250 B/s -> ~3s.
    assert!((s.eta.unwrap().as_secs_f64() - 3.0).abs() < 1e-6);
}

#[test]
fn progress_is_monotonic_and_saturates() {
    let mut p = TransferProgress::new(100, 2);
    p.record_bytes(60);
    p.record_bytes(60); // would exceed total -> saturates at 100
    assert_eq!(p.bytes_done(), 100);
    assert!(p.is_complete());
    p.record_file();
    p.record_file();
    p.record_file(); // beyond total_files -> saturates
    assert_eq!(p.files_done(), 2);
    // Done -> no ETA, full fraction.
    let s = p.snapshot(Duration::from_secs(5));
    assert!(s.eta.is_none());
    assert!((s.fraction - 1.0).abs() < 1e-9);
}
