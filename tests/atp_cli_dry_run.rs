//! CLI contract for `atp send --dry-run` (b0k8qo.11.5 / J5).
//!
//! Runs the real `atp` binary: `--dry-run` must compute and print the transfer
//! plan (root, file list, sizes, total bytes, merkle root) as JSON on stdout and
//! exit 0 *without* opening any socket — the rsync `--dry-run` "show the plan"
//! surface.
//!
//! Gated on `atp-cli`: the `atp` binary (and thus `CARGO_BIN_EXE_atp`) only
//! exists when that feature is enabled, so run with `--features atp-cli`.
#![cfg(feature = "atp-cli")]
#![allow(missing_docs)]

use std::path::{Path, PathBuf};
use std::process::Command;

fn unique_tmp(label: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    std::env::temp_dir().join(format!(
        "atp_cli_dryrun_{label}_{}_{nanos}",
        std::process::id()
    ))
}

fn mkfile(base: &Path, rel: &str, contents: &[u8]) {
    let path = base.join(rel);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, contents).unwrap();
}

#[test]
fn atp_send_dry_run_prints_plan_and_opens_no_socket() {
    let root = unique_tmp("plan");
    let proj = root.join("proj");
    mkfile(&proj, "a.txt", b"hello"); // 5 bytes
    mkfile(&proj, "sub/b.txt", b"world!!"); // 7 bytes -> total 12

    // Target is required by the parser but ignored under --dry-run (no connect),
    // so an unroutable address must still produce the plan and exit 0.
    let output = Command::new(env!("CARGO_BIN_EXE_atp"))
        .args(["send", "--dry-run", proj.to_str().unwrap(), "127.0.0.1:0"])
        .output()
        .expect("run atp binary");

    assert!(
        output.status.success(),
        "atp send --dry-run exited non-zero; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("\"root_name\":\"proj\""),
        "stdout: {stdout}"
    );
    assert!(stdout.contains("\"is_directory\":true"), "stdout: {stdout}");
    assert!(stdout.contains("\"file_count\":2"), "stdout: {stdout}");
    assert!(stdout.contains("\"total_bytes\":12"), "stdout: {stdout}");
    assert!(stdout.contains("a.txt"), "stdout: {stdout}");
    assert!(stdout.contains("sub/b.txt"), "stdout: {stdout}");
}
