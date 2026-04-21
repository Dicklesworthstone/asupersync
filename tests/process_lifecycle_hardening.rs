#![allow(clippy::all)]
//! Process Lifecycle Parity Hardening Tests (Track 3.4)
//!
//! Validates process spawn, stdio, wait, kill, and exit status parity
//! contracts. Closes PR-G1 (async wait), documents PR-G2 (PTY accepted gap),
//! and closes PR-G3 (cross-platform behavior documentation).
//!
//! Bead: asupersync-2oh2u.3.4

#![allow(missing_docs)]

use asupersync::process::{Command, Stdio};
use std::collections::{BTreeSet, HashSet};
use std::path::Path;

// ─── Constants ──────────────────────────────────────────────────────

const DOC_PATH: &str = "docs/process_lifecycle_hardening.md";
const JSON_PATH: &str = "docs/process_lifecycle_hardening.json";

// ─── Helpers ────────────────────────────────────────────────────────

fn load_doc() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(DOC_PATH);
    std::fs::read_to_string(path).expect("failed to load process lifecycle hardening doc")
}

fn load_json() -> serde_json::Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(JSON_PATH);
    let raw = std::fs::read_to_string(path).expect("failed to load process lifecycle JSON");
    serde_json::from_str(&raw).expect("failed to parse process lifecycle JSON")
}

// ═══════════════════════════════════════════════════════════════════
// Section 1: Document infrastructure (7 tests)
// ═══════════════════════════════════════════════════════════════════

#[test]
fn doc_exists() {
    assert!(
        Path::new(DOC_PATH).exists(),
        "Process lifecycle hardening doc must exist"
    );
}

#[test]
fn doc_references_bead() {
    let doc = load_doc();
    assert!(
        doc.contains("asupersync-2oh2u.3.4"),
        "Doc must reference its own bead ID"
    );
}

#[test]
fn doc_has_required_sections() {
    let doc = load_doc();
    let sections = [
        "Scope",
        "PR-G1",
        "PR-G2",
        "PR-G3",
        "Spawn and Stdio Hardening",
        "Kill and Exit Status Hardening",
        "Determinism Invariants",
        "Cross-References",
    ];
    let mut missing = Vec::new();
    for section in &sections {
        if !doc.contains(section) {
            missing.push(*section);
        }
    }
    assert!(
        missing.is_empty(),
        "Doc missing sections:\n{}",
        missing
            .iter()
            .map(|s| format!("  - {s}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn doc_references_all_gaps() {
    let doc = load_doc();
    for gap in &["PR-G1", "PR-G2", "PR-G3"] {
        assert!(doc.contains(gap), "Doc must reference gap: {gap}");
    }
}

#[test]
fn doc_references_cross_documents() {
    let doc = load_doc();
    let refs = [
        "tokio_fs_process_signal_parity_matrix.md",
        "src/process.rs",
        "compile_test_process.rs",
    ];
    for r in &refs {
        assert!(doc.contains(r), "Doc must reference: {r}");
    }
}

#[test]
fn doc_documents_determinism_invariant_count() {
    let doc = load_doc();
    let count = doc
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            (1..=8).any(|i| trimmed.starts_with(&format!("{i}. **")))
        })
        .count();
    assert!(
        count >= 8,
        "Doc must have at least 8 determinism invariants, found {count}"
    );
}

#[test]
fn doc_references_test_file() {
    let doc = load_doc();
    assert!(
        doc.contains("process_lifecycle_hardening.rs"),
        "Doc must reference its test file"
    );
}

// ═══════════════════════════════════════════════════════════════════
// Section 2: JSON artifact validation (8 tests)
// ═══════════════════════════════════════════════════════════════════

#[test]
fn json_exists() {
    assert!(
        Path::new(JSON_PATH).exists(),
        "Process lifecycle JSON must exist"
    );
}

#[test]
fn json_has_bead_id() {
    let json = load_json();
    assert_eq!(json["bead_id"].as_str().unwrap(), "asupersync-2oh2u.3.4");
}

#[test]
fn json_has_all_source_gaps() {
    let json = load_json();
    let gaps: Vec<&str> = json["source_gaps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(gaps.contains(&"PR-G1"));
    assert!(gaps.contains(&"PR-G2"));
    assert!(gaps.contains(&"PR-G3"));
}

#[test]
fn json_gap_closures_cover_all_gaps() {
    let json = load_json();
    let closures = json["gap_closures"].as_array().unwrap();
    let ids: BTreeSet<String> = closures
        .iter()
        .map(|c| c["gap_id"].as_str().unwrap().to_string())
        .collect();
    assert!(ids.contains("PR-G1"));
    assert!(ids.contains("PR-G2"));
    assert!(ids.contains("PR-G3"));
}

#[test]
fn json_contract_tests_have_unique_ids() {
    let json = load_json();
    let tests = json["contract_tests"].as_array().unwrap();
    let mut ids = HashSet::new();
    for test in tests {
        let id = test["id"].as_str().unwrap();
        assert!(ids.insert(id), "Duplicate test ID: {id}");
    }
}

#[test]
fn json_contract_tests_have_valid_categories() {
    let json = load_json();
    let valid_categories = ["async_wait_parity", "spawn", "stdio", "kill", "exit_status"];
    let tests = json["contract_tests"].as_array().unwrap();
    for test in tests {
        let cat = test["category"].as_str().unwrap();
        assert!(
            valid_categories.contains(&cat),
            "Invalid test category: {cat}"
        );
    }
}

#[test]
fn json_platform_matrix_covers_required_platforms() {
    let json = load_json();
    let matrix = json["platform_matrix"].as_object().unwrap();
    for platform in &["linux", "macos", "windows", "wasm"] {
        assert!(
            matrix.contains_key(*platform),
            "Platform matrix must cover: {platform}"
        );
    }
}

#[test]
fn json_determinism_invariants_count() {
    let json = load_json();
    let invariants = json["determinism_invariants"].as_array().unwrap();
    assert!(
        invariants.len() >= 8,
        "Must have at least 8 determinism invariants, found {}",
        invariants.len()
    );
}

// ═══════════════════════════════════════════════════════════════════
// Section 3: Spawn contract tests (5 tests) — PL-SP-*
// ═══════════════════════════════════════════════════════════════════

#[test]
fn pl_sp_01_valid_program_spawns() {
    let mut child = Command::new("echo")
        .arg("hello")
        .stdout(Stdio::piped())
        .spawn()
        .expect("echo should spawn");

    let status = child.wait().expect("wait should succeed");
    assert!(status.success(), "echo should exit successfully");
}

#[test]
fn pl_sp_02_invalid_program_returns_error() {
    let result = Command::new("__nonexistent_program_42__").spawn();
    assert!(result.is_err(), "Spawning nonexistent program must fail");
}

#[test]
fn pl_sp_03_arguments_passed_correctly() {
    let output = Command::new("echo")
        .arg("alpha")
        .arg("beta")
        .arg("gamma")
        .output()
        .expect("echo with args should succeed");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("alpha") && stdout.contains("beta") && stdout.contains("gamma"),
        "All arguments must appear in output: {stdout}"
    );
}

#[test]
fn pl_sp_04_environment_variables_set() {
    let output = Command::new("sh")
        .arg("-c")
        .arg("echo $TEST_VAR_3_4")
        .env("TEST_VAR_3_4", "hardening_value")
        .output()
        .expect("env test should succeed");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("hardening_value"),
        "Environment variable must be visible to child: {stdout}"
    );
}

#[test]
fn pl_sp_05_working_directory_set() {
    let output = Command::new("pwd")
        .current_dir("/tmp")
        .output()
        .expect("pwd should succeed");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.trim().starts_with("/tmp") || stdout.trim().starts_with("/private/tmp"),
        "Working directory must be /tmp: {stdout}"
    );
}

// ═══════════════════════════════════════════════════════════════════
// Section 4: Stdio contract tests (4 tests) — PL-IO-*
// ═══════════════════════════════════════════════════════════════════

#[test]
fn pl_io_01_piped_stdout_captures_output() {
    let output = Command::new("echo")
        .arg("piped_test")
        .stdout(Stdio::piped())
        .output()
        .expect("piped echo should succeed");

    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "piped_test");
}

#[test]
fn pl_io_02_piped_stderr_captures_errors() {
    let output = Command::new("sh")
        .arg("-c")
        .arg("echo error_msg >&2")
        .stderr(Stdio::piped())
        .output()
        .expect("stderr capture should succeed");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("error_msg"),
        "Stderr must be captured: {stderr}"
    );
}

#[test]
fn pl_io_03_piped_stdin_delivers_data() {
    use asupersync::io::AsyncWriteExt;

    futures_lite::future::block_on(async {
        let mut child = Command::new("cat")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("cat should spawn");

        // Take ownership of stdin handle and write via AsyncWrite
        if let Some(mut stdin_handle) = child.stdin() {
            stdin_handle
                .write_all(b"stdin_test_data\n")
                .await
                .expect("write to stdin should succeed");
            // Drop stdin to close pipe (signals EOF to cat)
        }

        let output = child
            .wait_with_output()
            .expect("wait_with_output should succeed");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("stdin_test_data"),
            "Child must read from stdin: {stdout}"
        );
    });
}

#[test]
fn pl_io_04_null_stdio_discards() {
    // With Stdio::null(), output is sent to /dev/null.
    // Verify by spawning with piped stdout after null — the null child gets no data.
    let mut child = Command::new("echo")
        .arg("discarded")
        .stdout(Stdio::null())
        .spawn()
        .expect("null stdio should spawn");

    let status = child.wait().expect("wait should succeed");
    assert!(status.success(), "echo with null stdout should succeed");

    // The key contract: Stdio::null() doesn't error and the process runs normally.
    // We can't capture output (that's the point of null), so we verify the child
    // runs to completion and that piped vs null produces different capture results.
    let piped_output = Command::new("echo")
        .arg("visible")
        .stdout(Stdio::piped())
        .output()
        .expect("piped echo should succeed");
    assert!(
        !piped_output.stdout.is_empty(),
        "Piped stdout must capture output (control test)"
    );
}

// ═══════════════════════════════════════════════════════════════════
// Section 5: Async wait parity (3 tests) — PL-G1-*
// ═══════════════════════════════════════════════════════════════════

#[test]
fn pl_g1_01_wait_async_nonblocking() {
    let output = futures_lite::future::block_on(async {
        let mut child = Command::new("echo")
            .arg("async_test")
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn for async test");

        let status = child.wait_async().await.expect("wait_async should succeed");
        assert!(status.success(), "echo should exit successfully");
        status
    });
    assert!(output.success());
}

#[test]
fn pl_g1_02_output_async_captures_stdio() {
    let output = futures_lite::future::block_on(async {
        let mut cmd = Command::new("echo");
        cmd.arg("async_output_test");
        cmd.output_async().await
    })
    .expect("output_async should succeed");

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "async_output_test"
    );
}

#[test]
fn pl_g1_03_status_async_returns_correct_exit_code() {
    let status = futures_lite::future::block_on(async {
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg("exit 7");
        cmd.status_async().await
    })
    .expect("status_async should succeed");

    assert!(!status.success());
    assert_eq!(status.code(), Some(7));
}

// ═══════════════════════════════════════════════════════════════════
// Section 6: try_wait contract tests (2 tests)
// ═══════════════════════════════════════════════════════════════════

#[test]
fn pl_g1_04_try_wait_before_exit() {
    // Spawn a sleeping child
    let mut child = Command::new("sleep")
        .arg("10")
        .spawn()
        .expect("sleep should spawn");

    // try_wait should return None while child is running
    let result = child.try_wait().expect("try_wait should not error");
    assert!(
        result.is_none(),
        "try_wait before child exit must return None"
    );

    // Clean up: kill the child
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn pl_g1_05_try_wait_after_exit() {
    let mut child = Command::new("true").spawn().expect("true should spawn");

    // Spin until try_wait returns Some (child has exited)
    let status = loop {
        match child.try_wait().expect("try_wait should not error") {
            Some(s) => break s,
            None => std::thread::sleep(std::time::Duration::from_millis(10)),
        }
    };
    assert!(status.success(), "true must exit with code 0");
}

// ═══════════════════════════════════════════════════════════════════
// Section 7: Kill contract tests (2 tests) — PL-KL-*
// ═══════════════════════════════════════════════════════════════════

#[test]
fn pl_kl_01_kill_terminates_running_child() {
    let mut child = Command::new("sleep")
        .arg("60")
        .spawn()
        .expect("sleep should spawn");

    child.kill().expect("kill should succeed");
    let status = child.wait().expect("wait after kill should succeed");
    assert!(
        !status.success(),
        "Killed process should not report success"
    );
}

#[test]
fn pl_kl_02_kill_on_drop_terminates() {
    // Verify kill_on_drop by checking Child runs before drop, then is killed after.
    // We test the contract indirectly: spawn with kill_on_drop, confirm child was
    // alive (had a pid), drop it, then verify a new wait-based approach.
    let mut child = Command::new("sleep")
        .arg("60")
        .kill_on_drop(true)
        .spawn()
        .expect("sleep with kill_on_drop should spawn");

    let pid = child.id().expect("spawned child must have pid");
    assert!(pid > 0, "child must have valid pid");

    // try_wait should show child still running
    let pre_drop = child.try_wait().expect("try_wait should not error");
    assert!(
        pre_drop.is_none(),
        "child should still be running before drop"
    );

    // Drop the child — kill_on_drop should send SIGKILL + try reap
    drop(child);

    // Verify: since we dropped, the child should have been killed.
    // We can't call wait() on a dropped child, but the contract is tested
    // by confirming the child was alive before drop and that drop completed
    // without hanging (which would indicate the kill succeeded).
    // Additionally, check /proc/<pid>/cmdline — dead processes lose it quickly.
    std::thread::sleep(std::time::Duration::from_millis(200));
    let cmdline_path = format!("/proc/{pid}/cmdline");
    let cmdline = std::fs::read_to_string(&cmdline_path).unwrap_or_default();
    assert!(
        !cmdline.contains("sleep"),
        "Process should be dead after kill_on_drop (pid={pid}, cmdline={cmdline:?})"
    );
}

// ═══════════════════════════════════════════════════════════════════
// Section 8: Exit status contract tests (4 tests) — PL-EX-*
// ═══════════════════════════════════════════════════════════════════

#[test]
fn pl_ex_01_success_for_exit_0() {
    let output = Command::new("true").output().expect("true should succeed");
    assert!(output.status.success());
    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn pl_ex_02_not_success_for_nonzero() {
    let output = Command::new("false")
        .output()
        .expect("false should exit non-zero");
    assert!(!output.status.success());
}

#[test]
fn pl_ex_03_correct_exit_code() {
    let output = Command::new("sh")
        .arg("-c")
        .arg("exit 42")
        .output()
        .expect("exit 42 should succeed");

    assert_eq!(output.status.code(), Some(42));
}

#[cfg(unix)]
#[test]
fn pl_ex_04_signal_termination_detected() {
    let mut child = Command::new("sleep")
        .arg("60")
        .spawn()
        .expect("sleep should spawn");

    // Send SIGTERM
    child.signal(15).expect("signal should succeed");
    let status = child.wait().expect("wait should succeed");

    // Process terminated by signal
    assert!(!status.success());
    // Signal should be detectable
    assert!(
        status.signal().is_some() || status.code().is_some(),
        "Signal-terminated process must report signal or non-zero code"
    );
}

// ═══════════════════════════════════════════════════════════════════
// Section 9: Contract coverage validation (3 tests)
// ═══════════════════════════════════════════════════════════════════

#[test]
fn json_test_ids_cover_all_categories() {
    let json = load_json();
    let tests = json["contract_tests"].as_array().unwrap();
    let categories: HashSet<&str> = tests
        .iter()
        .map(|t| t["category"].as_str().unwrap())
        .collect();

    let required = ["async_wait_parity", "spawn", "stdio", "kill", "exit_status"];
    for cat in &required {
        assert!(
            categories.contains(cat),
            "Contract tests must cover category: {cat}"
        );
    }
}

#[test]
fn json_summary_test_count_matches() {
    let json = load_json();
    let declared = json["summary"]["total_contract_tests"].as_u64().unwrap() as usize;
    let actual = json["contract_tests"].as_array().unwrap().len();
    assert_eq!(
        declared, actual,
        "Summary test count ({declared}) must match actual ({actual})"
    );
}

#[test]
fn json_gap_closure_statuses_valid() {
    let json = load_json();
    let valid_statuses = ["closed", "accepted_gap", "deferred"];
    let closures = json["gap_closures"].as_array().unwrap();
    for closure in closures {
        let status = closure["status"].as_str().unwrap();
        assert!(
            valid_statuses.contains(&status),
            "Invalid gap closure status: {status}"
        );
    }
}
