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

use asupersync::cx::Cx;
use asupersync::net::atp::transport_common::{TransferPlan, TransferProgress, plan_transfer};

const HELLO_WORLD_SHA256: &str =
    "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

fn plan(source: &std::path::Path) -> TransferPlan {
    let cx = Cx::for_testing();
    futures_lite::future::block_on(plan_transfer(&cx, source, 4096)).unwrap()
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
fn dry_run_plan_is_deterministic() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path();
    std::fs::write(base.join("x.bin"), vec![7u8; 5000]).unwrap();
    std::fs::write(base.join("y.bin"), vec![9u8; 1234]).unwrap();

    let a = plan(base);
    let b = plan(base);
    assert_eq!(a, b, "plan_transfer must be deterministic (no clock/network)");
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
