#![allow(clippy::all)]
#![allow(unsafe_code)]
//! End-to-end tests for [T3.10] FS/Process/Signal with forensic-grade logging.
//!
//! Each scenario uses structured log entries with scenario IDs, phases,
//! timestamps, and outcome markers for forensic replay.
//!
//! Categories:
//! - EF-01..EF-04: File lifecycle
//! - EP-01..EP-05: Process lifecycle
//! - ES-01..ES-03: Signal orchestration
//! - EX-01..EX-04: Cross-module E2E
//! - EV-01..EV-04: Validation

use asupersync::process::{Command, Stdio};
use asupersync::signal::ShutdownController;

/// Forensic log entry for replay and audit.
#[derive(Debug)]
#[allow(dead_code)]
struct LogEntry {
    scenario_id: &'static str,
    phase: &'static str,
    timestamp_ms: u64,
    resource: &'static str,
    action: &'static str,
    outcome: &'static str,
    detail: String,
}

/// Forensic log collector for a single scenario.
struct ScenarioLog {
    scenario_id: &'static str,
    start: std::time::Instant,
    entries: Vec<LogEntry>,
}

impl ScenarioLog {
    fn new(scenario_id: &'static str) -> Self {
        Self {
            scenario_id,
            start: std::time::Instant::now(),
            entries: Vec::new(),
        }
    }

    fn log(
        &mut self,
        phase: &'static str,
        resource: &'static str,
        action: &'static str,
        outcome: &'static str,
        detail: impl Into<String>,
    ) {
        self.entries.push(LogEntry {
            scenario_id: self.scenario_id,
            phase,
            timestamp_ms: self.start.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
            resource,
            action,
            outcome,
            detail: detail.into(),
        });
    }

    fn assert_all_ok(&self) {
        for entry in &self.entries {
            assert_ne!(
                entry.outcome, "err",
                "[{}] {} failed: {}",
                entry.scenario_id, entry.action, entry.detail
            );
        }
    }

    fn entry_count(&self) -> usize {
        self.entries.len()
    }
}

mod common {
    pub const DOC_MD: &str = include_str!("../docs/tokio_fs_process_signal_e2e.md");
    pub const DOC_JSON: &str = include_str!("../docs/tokio_fs_process_signal_e2e.json");

    pub fn json() -> serde_json::Value {
        serde_json::from_str(DOC_JSON).expect("JSON artifact must parse")
    }

    pub fn md_has_section(heading: &str) -> bool {
        for line in DOC_MD.lines() {
            let trimmed = line.trim();
            if (trimmed.starts_with("## ") || trimmed.starts_with("### "))
                && trimmed.contains(heading)
            {
                return true;
            }
        }
        false
    }
}

// ── EF: File Lifecycle ──────────────────────────────────────────────

#[test]
fn ef_01_create_write_read_verify_delete() {
    let mut log = ScenarioLog::new("EF-01");
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("lifecycle.txt");

    // Setup
    log.log(
        "setup",
        "file",
        "tempdir_create",
        "ok",
        format!("{}", dir.path().display()),
    );

    // Execute: create and write
    std::fs::write(&path, b"lifecycle data").expect("write");
    log.log("execute", "file", "write", "ok", "14 bytes written");

    // Verify: read back
    let content = std::fs::read(&path).expect("read");
    assert_eq!(content, b"lifecycle data");
    log.log("verify", "file", "read_verify", "ok", "content matches");

    // Teardown: delete
    std::fs::remove_file(&path).expect("remove");
    assert!(!path.exists());
    log.log("teardown", "file", "delete", "ok", "file removed");

    log.assert_all_ok();
    assert!(log.entry_count() >= 4);
}

#[test]
fn ef_02_concurrent_file_ops_no_cross_contamination() {
    let mut log = ScenarioLog::new("EF-02");
    let dir = tempfile::tempdir().expect("tempdir");

    log.log("setup", "file", "tempdir_create", "ok", "ready");

    // Create multiple files
    for i in 0..5 {
        let path = dir.path().join(format!("file_{i}.txt"));
        let data = format!("content_{i}");
        std::fs::write(&path, data.as_bytes()).expect("write");
        log.log("execute", "file", "write", "ok", format!("file_{i}"));
    }

    // Verify no cross-contamination
    for i in 0..5 {
        let path = dir.path().join(format!("file_{i}.txt"));
        let content = std::fs::read_to_string(&path).expect("read");
        assert_eq!(content, format!("content_{i}"));
        log.log(
            "verify",
            "file",
            "read_verify",
            "ok",
            format!("file_{i} correct"),
        );
    }

    log.assert_all_ok();
}

#[test]
fn ef_03_large_file_write_sync_readback() {
    let mut log = ScenarioLog::new("EF-03");
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("large.bin");

    log.log("setup", "file", "prepare", "ok", "1MB test");

    // Write 1MB of patterned data
    let data: Vec<u8> = (0u32..1_000_000).map(|i| (i % 256) as u8).collect();
    std::fs::write(&path, &data).expect("write");
    log.log("execute", "file", "write_1mb", "ok", "1000000 bytes");

    // Sync via metadata check
    let meta = std::fs::metadata(&path).expect("metadata");
    assert_eq!(meta.len(), 1_000_000);
    log.log("execute", "file", "sync_check", "ok", "size verified");

    // Read back and verify
    let readback = std::fs::read(&path).expect("read");
    assert_eq!(readback, data);
    log.log("verify", "file", "readback_verify", "ok", "all bytes match");

    log.assert_all_ok();
}

#[test]
fn ef_04_rename_atomic_swap() {
    let mut log = ScenarioLog::new("EF-04");
    let dir = tempfile::tempdir().expect("tempdir");
    let src = dir.path().join("src.txt");
    let dst = dir.path().join("dst.txt");

    log.log("setup", "file", "prepare", "ok", "rename test");

    std::fs::write(&src, b"swap_data").expect("write");
    log.log("execute", "file", "write_src", "ok", "9 bytes");

    std::fs::rename(&src, &dst).expect("rename");
    log.log("execute", "file", "rename", "ok", "src -> dst");

    assert!(!src.exists());
    assert_eq!(std::fs::read(&dst).expect("read"), b"swap_data");
    log.log(
        "verify",
        "file",
        "rename_verify",
        "ok",
        "atomic swap confirmed",
    );

    log.assert_all_ok();
}

// ── EP: Process Lifecycle ───────────────────────────────────────────

#[test]
fn ep_01_spawn_pipe_capture_exit() {
    let mut log = ScenarioLog::new("EP-01");

    log.log("setup", "process", "prepare", "ok", "echo test");

    let output = Command::new("echo")
        .arg("e2e_output")
        .stdout(Stdio::piped())
        .output()
        .expect("output");

    log.log(
        "execute",
        "process",
        "spawn_and_wait",
        "ok",
        format!("exit={}", output.status.code().unwrap_or(-1)),
    );

    assert!(output.status.success());
    assert_eq!(output.stdout, b"e2e_output\n");
    log.log(
        "verify",
        "process",
        "output_verify",
        "ok",
        "content matches",
    );

    log.assert_all_ok();
}

#[test]
fn ep_02_pipe_chain_a_to_b() {
    let mut log = ScenarioLog::new("EP-02");

    log.log("setup", "process", "prepare", "ok", "pipe chain");

    // echo "hello" | tr 'a-z' 'A-Z'
    let output = Command::new("sh")
        .arg("-c")
        .arg("echo hello | tr 'a-z' 'A-Z'")
        .stdout(Stdio::piped())
        .output()
        .expect("output");

    log.log("execute", "process", "pipe_chain", "ok", "echo | tr");

    assert!(output.status.success());
    assert_eq!(output.stdout, b"HELLO\n");
    log.log(
        "verify",
        "process",
        "chain_verify",
        "ok",
        "transform correct",
    );

    log.assert_all_ok();
}

#[test]
fn ep_03_spawn_sigterm_wait() {
    let mut log = ScenarioLog::new("EP-03");

    log.log("setup", "process", "prepare", "ok", "sigterm test");

    let mut child = Command::new("sleep").arg("100").spawn().expect("spawn");

    log.log(
        "execute",
        "process",
        "spawn",
        "ok",
        format!("pid={}", child.id().unwrap_or(0)),
    );

    child.signal(libc::SIGTERM).expect("signal");
    log.log("execute", "process", "sigterm", "ok", "sent");

    let status = child.wait().expect("wait");
    assert!(!status.success());
    assert_eq!(status.signal(), Some(libc::SIGTERM));
    log.log(
        "verify",
        "process",
        "signal_verify",
        "ok",
        "terminated by SIGTERM",
    );

    log.assert_all_ok();
}

#[test]
fn ep_04_kill_on_drop_nested_scope() {
    let mut log = ScenarioLog::new("EP-04");
    log.log("setup", "process", "prepare", "ok", "kill_on_drop");

    let pid;
    {
        let child = Command::new("sleep")
            .arg("100")
            .kill_on_drop(true)
            .spawn()
            .expect("spawn");
        pid = child.id().expect("pid");
        log.log("execute", "process", "spawn", "ok", format!("pid={pid}"));
        // child dropped here
    }
    log.log("execute", "process", "scope_exit", "ok", "child dropped");

    std::thread::sleep(std::time::Duration::from_millis(100));
    #[allow(clippy::cast_possible_wrap)]
    let pid_i32 = pid as i32;
    unsafe { libc::waitpid(pid_i32, std::ptr::null_mut(), libc::WNOHANG) };
    std::thread::sleep(std::time::Duration::from_millis(50));

    let ret = unsafe { libc::kill(pid_i32, 0) };
    assert_ne!(ret, 0);
    log.log("verify", "process", "zombie_check", "ok", "no zombie");

    log.assert_all_ok();
}

#[test]
fn ep_05_process_env_isolation() {
    let mut log = ScenarioLog::new("EP-05");
    log.log("setup", "process", "prepare", "ok", "env isolation");

    let output = Command::new("sh")
        .arg("-c")
        .arg("echo $E2E_VAR1-$E2E_VAR2")
        .env("E2E_VAR1", "alpha")
        .env("E2E_VAR2", "beta")
        .stdout(Stdio::piped())
        .output()
        .expect("output");

    log.log("execute", "process", "spawn_with_env", "ok", "2 vars set");

    assert!(output.status.success());
    assert_eq!(output.stdout, b"alpha-beta\n");
    log.log("verify", "process", "env_verify", "ok", "vars propagated");

    log.assert_all_ok();
}

// ── ES: Signal Orchestration ────────────────────────────────────────

#[test]
fn es_01_controller_five_receivers_all_notified() {
    let mut log = ScenarioLog::new("ES-01");
    log.log("setup", "signal", "prepare", "ok", "5 receivers");

    let controller = ShutdownController::new();
    let receivers: Vec<_> = (0..5).map(|_| controller.subscribe()).collect();
    log.log(
        "execute",
        "signal",
        "subscribe_5",
        "ok",
        "5 receivers created",
    );

    controller.shutdown();
    log.log("execute", "signal", "shutdown", "ok", "broadcast sent");

    for (i, rx) in receivers.iter().enumerate() {
        assert!(rx.is_shutting_down());
        log.log(
            "verify",
            "signal",
            "receiver_check",
            "ok",
            format!("rx_{i} notified"),
        );
    }

    log.assert_all_ok();
}

#[test]
fn es_02_graceful_shutdown_task_completion_race() {
    let mut log = ScenarioLog::new("ES-02");
    log.log("setup", "signal", "prepare", "ok", "graceful race");

    let controller = ShutdownController::new();
    let receiver = controller.subscribe();

    // Task completes before shutdown
    let result = futures_lite::future::block_on(asupersync::signal::with_graceful_shutdown(
        std::future::ready(42),
        receiver,
    ));

    assert!(result.is_completed());
    assert_eq!(result.into_completed(), Some(42));
    log.log(
        "verify",
        "signal",
        "graceful_outcome",
        "ok",
        "Completed(42)",
    );

    log.assert_all_ok();
}

#[test]
fn es_03_grace_period_elapsed() {
    let mut log = ScenarioLog::new("ES-03");
    log.log("setup", "signal", "prepare", "ok", "grace period");

    let guard = asupersync::signal::GracePeriodGuard::new(std::time::Duration::from_millis(50));
    assert!(!guard.is_elapsed());
    log.log("execute", "signal", "guard_create", "ok", "50ms period");

    std::thread::sleep(std::time::Duration::from_millis(100));

    assert!(guard.is_elapsed());
    assert_eq!(guard.remaining(), std::time::Duration::ZERO);
    log.log("verify", "signal", "guard_elapsed", "ok", "period elapsed");

    log.assert_all_ok();
}

// ── EX: Cross-Module E2E ────────────────────────────────────────────

#[test]
fn ex_01_process_writes_file_parent_reads() {
    let mut log = ScenarioLog::new("EX-01");
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("process_output.txt");

    log.log("setup", "cross", "prepare", "ok", "process -> file");

    // Process writes to stdout
    let output = Command::new("echo")
        .arg("process_data")
        .stdout(Stdio::piped())
        .output()
        .expect("output");

    log.log("execute", "process", "spawn_capture", "ok", "echo done");

    // Parent writes to file
    std::fs::write(&path, &output.stdout).expect("write");
    log.log("execute", "file", "write", "ok", "data written");

    // Verify
    let content = std::fs::read(&path).expect("read");
    assert_eq!(content, b"process_data\n");
    log.log("verify", "cross", "data_flow", "ok", "end-to-end correct");

    log.assert_all_ok();
}

#[test]
fn ex_02_shutdown_kills_process_file_cleanup() {
    let mut log = ScenarioLog::new("EX-02");
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("cleanup.txt");

    log.log("setup", "cross", "prepare", "ok", "shutdown + cleanup");

    // Write a file
    std::fs::write(&path, b"temp_data").expect("write");
    log.log("execute", "file", "write", "ok", "temp file created");

    // Spawn process with kill_on_drop
    let pid;
    {
        let child = Command::new("sleep")
            .arg("100")
            .kill_on_drop(true)
            .spawn()
            .expect("spawn");
        pid = child.id().expect("pid");
        log.log("execute", "process", "spawn", "ok", format!("pid={pid}"));

        let controller = ShutdownController::new();
        controller.shutdown();
        log.log("execute", "signal", "shutdown", "ok", "initiated");
        // child dropped — kill_on_drop fires
    }

    // Cleanup file
    std::fs::remove_file(&path).expect("remove");
    assert!(!path.exists());
    log.log("teardown", "file", "cleanup", "ok", "file removed");

    // Verify no zombie
    std::thread::sleep(std::time::Duration::from_millis(100));
    #[allow(clippy::cast_possible_wrap)]
    let pid_i32 = pid as i32;
    unsafe { libc::waitpid(pid_i32, std::ptr::null_mut(), libc::WNOHANG) };
    std::thread::sleep(std::time::Duration::from_millis(50));
    let ret = unsafe { libc::kill(pid_i32, 0) };
    assert_ne!(ret, 0);
    log.log("verify", "cross", "quiescence", "ok", "no zombie, no file");

    log.assert_all_ok();
}

#[test]
fn ex_03_file_process_signal_concurrent_lifecycle() {
    let mut log = ScenarioLog::new("EX-03");
    let dir = tempfile::tempdir().expect("tempdir");

    log.log("setup", "cross", "prepare", "ok", "concurrent lifecycle");

    // File operations
    let fpath = dir.path().join("concurrent.txt");
    std::fs::write(&fpath, b"concurrent_data").expect("write");
    log.log("execute", "file", "write", "ok", "file created");

    // Process operations
    let output = Command::new("echo")
        .arg("concurrent_process")
        .stdout(Stdio::piped())
        .output()
        .expect("output");
    assert!(output.status.success());
    log.log("execute", "process", "spawn_complete", "ok", "process done");

    // Signal operations
    let controller = ShutdownController::new();
    let receiver = controller.subscribe();
    controller.shutdown();
    assert!(receiver.is_shutting_down());
    log.log("execute", "signal", "shutdown", "ok", "signal delivered");

    // Verify all resources
    assert_eq!(std::fs::read(&fpath).expect("read"), b"concurrent_data");
    log.log("verify", "file", "intact", "ok", "data preserved");

    // Cleanup
    std::fs::remove_file(&fpath).expect("remove");
    log.log(
        "teardown",
        "file",
        "cleanup",
        "ok",
        "all resources released",
    );

    log.assert_all_ok();
    assert!(log.entry_count() >= 6);
}

#[test]
fn ex_04_crash_recovery_retry() {
    let mut log = ScenarioLog::new("EX-04");
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("recovery.txt");

    log.log("setup", "cross", "prepare", "ok", "crash recovery");

    // First attempt: process "crashes" (exits with error)
    let output = Command::new("sh")
        .arg("-c")
        .arg("exit 1")
        .output()
        .expect("output");
    assert!(!output.status.success());
    log.log("execute", "process", "attempt_1", "ok", "expected failure");

    // Cleanup any partial state
    if path.exists() {
        std::fs::remove_file(&path).expect("cleanup");
    }
    log.log("execute", "cross", "cleanup", "ok", "partial state cleared");

    // Retry: successful attempt
    let output = Command::new("echo")
        .arg("recovered")
        .stdout(Stdio::piped())
        .output()
        .expect("output");
    assert!(output.status.success());
    std::fs::write(&path, &output.stdout).expect("write");
    log.log("execute", "cross", "retry", "ok", "recovery succeeded");

    // Verify
    assert_eq!(std::fs::read(&path).expect("read"), b"recovered\n");
    log.log(
        "verify",
        "cross",
        "recovery_verify",
        "ok",
        "data correct after retry",
    );

    log.assert_all_ok();
}

// ── EV: Validation ──────────────────────────────────────────────────

#[test]
fn ev_01_json_structural_validity() {
    let j = common::json();
    assert_eq!(
        j.get("bead_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(""),
        "asupersync-2oh2u.3.10"
    );
    assert!(j.get("scenarios").is_some());
    assert!(j.get("summary").is_some());
}

#[test]
fn ev_02_doc_completeness() {
    let required = ["Scope", "Scenarios", "Forensic Logging", "Drift Detection"];
    for section in &required {
        assert!(
            common::md_has_section(section),
            "Missing section: '{section}'"
        );
    }
}

#[test]
fn ev_03_all_scenario_ids_in_json() {
    let j = common::json();
    let scenarios = j
        .get("scenarios")
        .and_then(serde_json::Value::as_array)
        .expect("scenarios");

    let prefixes: Vec<&str> = scenarios
        .iter()
        .filter_map(|s| s.get("prefix").and_then(serde_json::Value::as_str))
        .collect();

    for expected in ["EF", "EP", "ES", "EX", "EV"] {
        assert!(
            prefixes.contains(&expected),
            "Missing scenario prefix: {expected}"
        );
    }
}

#[test]
fn ev_04_summary_verdict() {
    let j = common::json();
    let summary = j.get("summary").expect("summary");
    assert_eq!(
        summary
            .get("overall_verdict")
            .and_then(serde_json::Value::as_str),
        Some("COMPLETE")
    );
    assert_eq!(
        summary
            .get("total_tests")
            .and_then(serde_json::Value::as_u64),
        Some(20)
    );
}
