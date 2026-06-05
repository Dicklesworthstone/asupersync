//! Contract tests for the CI-local RCH fallback wrapper.

#![allow(missing_docs)]

use std::path::PathBuf;
use std::process::{Command, Output};

const SCRIPT_PATH: &str = "scripts/rch_ci_fallback.sh";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn run_fallback(envs: &[(&str, &str)], args: &[&str]) -> Output {
    let mut command = Command::new("bash");
    command
        .arg(repo_root().join(SCRIPT_PATH))
        .args(args)
        .current_dir(repo_root());
    for (name, value) in envs {
        command.env(name, value);
    }
    command.output().expect("run rch fallback wrapper")
}

#[test]
fn fallback_rejects_missing_command() {
    let output = run_fallback(&[], &["exec"]);
    assert_eq!(
        output.status.code(),
        Some(64),
        "missing fallback command must be usage error\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("missing command"),
        "stderr should explain missing command: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn fallback_applies_virtual_memory_limit_to_child() {
    let output = run_fallback(
        &[
            ("RCH_CI_FALLBACK_MEMORY_MB", "64"),
            ("RCH_CI_FALLBACK_TIMEOUT_SEC", "0"),
        ],
        &["exec", "bash", "-lc", "ulimit -v"],
    );
    assert!(
        output.status.success(),
        "memory-limit probe failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "65536",
        "child process must inherit 64 MiB virtual-memory cap"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("memory limit: 64 MiB"),
        "stderr must log the applied memory limit: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn fallback_times_out_runaway_child() {
    let output = run_fallback(
        &[
            ("RCH_CI_FALLBACK_MEMORY_MB", "0"),
            ("RCH_CI_FALLBACK_TIMEOUT_SEC", "1"),
        ],
        &["exec", "bash", "-lc", "sleep 5"],
    );
    assert_eq!(
        output.status.code(),
        Some(124),
        "timeout should terminate the runaway child\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("timeout: 1s"),
        "stderr must log the timeout guard: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn fallback_rejects_oversized_memory_guard_before_arithmetic() {
    let output = run_fallback(
        &[
            ("RCH_CI_FALLBACK_MEMORY_MB", "999999999999999999999999"),
            ("RCH_CI_FALLBACK_TIMEOUT_SEC", "0"),
        ],
        &["exec", "bash", "-lc", "echo should-not-run"],
    );
    assert_eq!(
        output.status.code(),
        Some(64),
        "oversized memory guard must fail as usage error\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("RCH_CI_FALLBACK_MEMORY_MB must be <= 1048576 MiB"),
        "stderr must explain the memory guard bound: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).is_empty(),
        "child command must not run after guard validation failure"
    );
}

#[test]
fn fallback_rejects_oversized_timeout_guard_before_exec() {
    let output = run_fallback(
        &[
            ("RCH_CI_FALLBACK_MEMORY_MB", "0"),
            ("RCH_CI_FALLBACK_TIMEOUT_SEC", "999999999999999999999999"),
        ],
        &["exec", "bash", "-lc", "echo should-not-run"],
    );
    assert_eq!(
        output.status.code(),
        Some(64),
        "oversized timeout guard must fail as usage error\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("RCH_CI_FALLBACK_TIMEOUT_SEC must be <= 604800 seconds"),
        "stderr must explain the timeout guard bound: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).is_empty(),
        "child command must not run after guard validation failure"
    );
}
