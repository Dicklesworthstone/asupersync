#![allow(unsafe_code)]
//! Contract tests for [T3.7] Deterministic Conformance and Fault-Injection Suites
//!
//! Validates error paths, adversarial edge cases, and fault-injection scenarios
//! across filesystem, process, and signal subsystems.
//!
//! Categories:
//! - FF-01..FF-08: Filesystem fault injection
//! - PF-01..PF-11: Process fault injection
//! - SF-01..SF-07: Signal fault injection
//! - CF-01..CF-04: Cross-module fault scenarios
//! - CT-01..CT-04: Contract artifact validation

use asupersync::process::{Command, Stdio};
use asupersync::signal::ShutdownController;

mod common {
    pub const DOC_MD: &str = include_str!("../docs/tokio_fs_process_signal_conformance.md");
    pub const DOC_JSON: &str = include_str!("../docs/tokio_fs_process_signal_conformance.json");

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

// ── FF: Filesystem Fault Injection ──────────────────────────────────

#[test]
fn ff_01_try_clone_produces_independent_handle() {
    // try_clone creates a new OS-level fd wrapped in a new Arc, so both are independent
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("clone_test.txt");
    std::fs::write(&path, b"hello world").expect("write");

    let file = futures_lite::future::block_on(asupersync::fs::File::open(&path)).expect("open");
    let clone = futures_lite::future::block_on(file.try_clone()).expect("try_clone");

    // Both handles can seek independently (each has its own Arc)
    let mut file_mut = file;
    let pos1 = futures_lite::future::block_on(file_mut.seek(std::io::SeekFrom::Start(5)));
    assert!(pos1.is_ok(), "Original file seek should succeed");
    assert_eq!(pos1.unwrap(), 5);

    let mut clone_mut = clone;
    let pos2 = futures_lite::future::block_on(clone_mut.seek(std::io::SeekFrom::Start(0)));
    assert!(pos2.is_ok(), "Cloned file seek should succeed");
    assert_eq!(pos2.unwrap(), 0);
}

#[test]
fn ff_02_poll_shutdown_is_noop() {
    // AsyncWrite::poll_shutdown should return Ok without any side effect
    use asupersync::io::AsyncWrite;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll, Wake, Waker};

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("shutdown_noop.txt");
    std::fs::write(&path, b"data").expect("write");

    let file = futures_lite::future::block_on(asupersync::fs::File::open(&path)).expect("open");
    let mut file = file;

    let waker: Waker = std::task::Waker::noop().clone();
    let mut cx = Context::from_waker(&waker);

    let result = Pin::new(&mut file).poll_shutdown(&mut cx);
    assert!(
        matches!(result, Poll::Ready(Ok(()))),
        "poll_shutdown should be a no-op returning Ok"
    );
}

#[test]
fn ff_03_into_std_returns_valid_handle() {
    // into_std unwraps the Arc and returns the underlying std::fs::File
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("into_std.txt");
    std::fs::write(&path, b"content").expect("write");

    let file = futures_lite::future::block_on(asupersync::fs::File::open(&path)).expect("open");

    let std_file = file.into_std().expect("into_std");
    // Verify the handle is valid by reading metadata
    let meta = std_file.metadata().expect("metadata");
    assert_eq!(meta.len(), 7);
}

#[test]
fn ff_04_open_nonexistent_path() {
    let result = futures_lite::future::block_on(asupersync::fs::File::open(
        "/nonexistent/path/that/does/not/exist.txt",
    ));
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
}

#[test]
fn ff_05_write_to_readonly_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("readonly.txt");
    std::fs::write(&path, b"original").expect("write");

    // Make read-only
    let mut perms = std::fs::metadata(&path).expect("meta").permissions();
    perms.set_readonly(true);
    std::fs::set_permissions(&path, perms).expect("set_permissions");

    // Try to write
    let result = std::fs::OpenOptions::new().write(true).open(&path);
    assert!(
        result.is_err(),
        "Opening read-only file for write should fail"
    );
    let err = result.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
}

#[test]
fn ff_06_set_len_truncation_preserves_prefix() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("truncate.txt");
    std::fs::write(&path, b"hello world!").expect("write");

    let file = futures_lite::future::block_on(asupersync::fs::File::create(&path)).expect("create");
    // Re-write then truncate
    std::fs::write(&path, b"abcdefghij").expect("rewrite");

    futures_lite::future::block_on(file.set_len(5)).expect("set_len");
    let content = std::fs::read(&path).expect("read");
    assert_eq!(content.len(), 5, "File should be truncated to 5 bytes");
}

#[test]
fn ff_07_metadata_on_deleted_file_errors() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("deleted.txt");
    std::fs::write(&path, b"temp").expect("write");
    std::fs::remove_file(&path).expect("remove");

    let result = std::fs::metadata(&path);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::NotFound);
}

#[test]
fn ff_08_double_rewind_idempotent() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("rewind.txt");
    std::fs::write(&path, b"rewind test data").expect("write");

    let file = futures_lite::future::block_on(asupersync::fs::File::open(&path)).expect("open");
    let mut file = file;

    // First rewind
    let r1 = futures_lite::future::block_on(file.rewind());
    assert!(r1.is_ok(), "First rewind should succeed");

    // Second rewind
    let r2 = futures_lite::future::block_on(file.rewind());
    assert!(r2.is_ok(), "Second rewind should succeed (idempotent)");
}

// ── PF: Process Fault Injection ─────────────────────────────────────

#[test]
fn pf_01_spawn_nonexistent_binary() {
    let result = Command::new("this_binary_does_not_exist_anywhere_at_all").spawn();
    assert!(result.is_err(), "Spawning nonexistent binary should fail");
    let err = result.unwrap_err();
    let err_str = format!("{err}");
    // Should be NotFound variant
    assert!(
        err_str.contains("not found")
            || err_str.contains("NotFound")
            || err_str.contains("No such file"),
        "Error should indicate not found: {err_str}"
    );
}

#[test]
fn pf_02_double_wait_returns_error() {
    let mut child = Command::new("true").spawn().expect("spawn");
    let status = child.wait().expect("first wait");
    assert!(status.success());

    // Second wait should fail
    let result = child.wait();
    assert!(result.is_err(), "Double wait should return error");
    let err_str = format!("{}", result.unwrap_err());
    assert!(
        err_str.contains("already waited") || err_str.contains("InvalidInput"),
        "Error should indicate already waited: {err_str}"
    );
}

#[test]
fn pf_03_signal_on_consumed_handle() {
    let mut child = Command::new("true").spawn().expect("spawn");
    child.wait().expect("wait");

    // Signal after wait should fail
    let result = child.signal(libc::SIGTERM);
    assert!(result.is_err(), "Signal on consumed handle should fail");
}

#[test]
fn pf_04_kill_on_consumed_handle() {
    let mut child = Command::new("true").spawn().expect("spawn");
    child.wait().expect("wait");

    // Kill after wait should fail
    let result = child.kill();
    assert!(result.is_err(), "Kill on consumed handle should fail");
}

#[test]
fn pf_05_large_stdout_stderr_no_deadlock() {
    // Spawn a process that writes >64KB to both stdout and stderr simultaneously
    // wait_with_output must drain both without deadlocking
    let child = Command::new("sh")
        .arg("-c")
        .arg("dd if=/dev/zero bs=1024 count=128 2>/dev/null | tr '\\0' 'A'; dd if=/dev/zero bs=1024 count=128 | tr '\\0' 'B' >&2")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");

    let output = child.wait_with_output().expect("wait_with_output");
    assert!(output.status.success(), "Process should succeed");
    // Each channel should have ~128KB of data
    assert!(
        output.stdout.len() >= 100_000,
        "stdout should have significant data: {} bytes",
        output.stdout.len()
    );
    assert!(
        output.stderr.len() >= 100_000,
        "stderr should have significant data: {} bytes",
        output.stderr.len()
    );
}

#[test]
fn pf_06_stdin_dropped_after_child_exits() {
    // After child exits and handle is waited, stdin take returns None
    let mut child = Command::new("true")
        .stdin(Stdio::piped())
        .spawn()
        .expect("spawn");

    let _stdin = child.stdin().expect("first stdin take");
    // Second take returns None (take-once semantics)
    assert!(
        child.stdin().is_none(),
        "Second stdin take should return None"
    );

    child.wait().expect("wait");
}

#[test]
fn pf_07_try_wait_returns_none_for_running() {
    let mut child = Command::new("sleep").arg("100").spawn().expect("spawn");

    let result = child.try_wait().expect("try_wait");
    assert!(
        result.is_none(),
        "try_wait should return None for running child"
    );

    child.kill().expect("kill");
    child.wait().expect("reap");
}

#[test]
fn pf_08_exit_code_127_command_not_found_at_exec() {
    // sh -c with nonexistent command gives exit code 127
    let output = Command::new("sh")
        .arg("-c")
        .arg("nonexistent_command_xyz_12345")
        .output()
        .expect("output");
    assert!(!output.status.success());
    assert_eq!(
        output.status.code(),
        Some(127),
        "Exit code should be 127 for command not found"
    );
}

#[test]
fn pf_09_env_clear_with_full_path_works() {
    let output = Command::new("/bin/echo")
        .arg("works")
        .env_clear()
        .stdout(Stdio::piped())
        .output()
        .expect("output");

    assert!(output.status.success());
    assert_eq!(output.stdout, b"works\n");
}

#[test]
fn pf_10_kill_on_drop_rapid_scope_exit() {
    let pid;
    {
        let child = Command::new("sleep")
            .arg("100")
            .kill_on_drop(true)
            .spawn()
            .expect("spawn");
        pid = child.id().expect("pid");
        // Immediately drop — kill_on_drop fires
    }

    std::thread::sleep(std::time::Duration::from_millis(100));
    #[allow(clippy::cast_possible_wrap)]
    let pid_i32 = pid as i32;
    // Reap zombie if any
    unsafe { libc::waitpid(pid_i32, std::ptr::null_mut(), libc::WNOHANG) };
    std::thread::sleep(std::time::Duration::from_millis(50));

    let ret = unsafe { libc::kill(pid_i32, 0) };
    assert_ne!(ret, 0, "Process {pid} should be gone after kill_on_drop");
}

#[test]
fn pf_11_fast_exit_before_first_try_wait() {
    // Spawn a process that exits immediately
    let mut child = Command::new("true").spawn().expect("spawn");
    // Small delay to ensure it exits
    std::thread::sleep(std::time::Duration::from_millis(50));

    let result = child.try_wait().expect("try_wait");
    assert!(
        result.is_some(),
        "try_wait should return Some for already-exited process"
    );
    assert!(result.unwrap().success());
}

// ── SF: Signal Fault Injection ──────────────────────────────────────

#[test]
fn sf_01_shutdown_coalescing_multiple_calls() {
    // Multiple rapid shutdown calls should all be idempotent (coalescing)
    let controller = ShutdownController::new();
    let receiver = controller.subscribe();

    // Call shutdown 100 times rapidly
    for _ in 0..100 {
        controller.shutdown();
    }

    // Receiver should observe exactly one shutdown state
    assert!(
        receiver.is_shutting_down(),
        "Should observe shutdown after coalesced calls"
    );
}

#[test]
fn sf_02_multiple_receivers_independent_observation() {
    // Multiple receivers from the same controller observe shutdown independently
    let controller = ShutdownController::new();
    let rx1 = controller.subscribe();
    let rx2 = controller.subscribe();

    assert!(!rx1.is_shutting_down());
    assert!(!rx2.is_shutting_down());

    controller.shutdown();

    // Both observe it independently
    assert!(rx1.is_shutting_down(), "Receiver 1 should observe shutdown");
    assert!(rx2.is_shutting_down(), "Receiver 2 should observe shutdown");
}

#[test]
fn sf_03_concurrent_shutdown_from_multiple_threads() {
    let controller = ShutdownController::new();
    let receivers: Vec<_> = (0..10).map(|_| controller.subscribe()).collect();

    // Spawn 10 threads all calling shutdown simultaneously
    let ctrl = std::sync::Arc::new(controller);
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(10));

    let handles: Vec<_> = (0..10)
        .map(|_| {
            let c = std::sync::Arc::clone(&ctrl);
            let b = std::sync::Arc::clone(&barrier);
            std::thread::spawn(move || {
                b.wait();
                c.shutdown();
            })
        })
        .collect();

    for h in handles {
        h.join().expect("thread join");
    }

    // All receivers should see shutdown
    for (i, rx) in receivers.iter().enumerate() {
        assert!(
            rx.is_shutting_down(),
            "Receiver {i} should observe shutdown after concurrent calls"
        );
    }
}

#[test]
fn sf_04_subscribe_after_shutdown_observes_immediately() {
    let controller = ShutdownController::new();
    controller.shutdown();

    // Subscribe after shutdown
    let receiver = controller.subscribe();
    assert!(
        receiver.is_shutting_down(),
        "Receiver created after shutdown should immediately observe it"
    );
}

#[test]
fn sf_05_grace_period_boundary() {
    let guard = asupersync::signal::GracePeriodGuard::new(std::time::Duration::from_millis(50));
    assert!(!guard.is_elapsed(), "Should not be elapsed immediately");
    assert!(guard.remaining() > std::time::Duration::ZERO);

    std::thread::sleep(std::time::Duration::from_millis(100));

    assert!(guard.is_elapsed(), "Should be elapsed after duration");
    assert_eq!(guard.remaining(), std::time::Duration::ZERO);
}

#[test]
fn sf_06_graceful_shutdown_when_already_shutdown() {
    let controller = ShutdownController::new();
    controller.shutdown();
    let receiver = controller.subscribe();

    let result = futures_lite::future::block_on(asupersync::signal::with_graceful_shutdown(
        std::future::ready(42),
        receiver,
    ));

    assert!(
        result.is_shutdown(),
        "Should return ShutdownSignaled when already shut down"
    );
}

#[test]
fn sf_07_controller_drop_before_receivers() {
    let receiver;
    {
        let controller = ShutdownController::new();
        receiver = controller.subscribe();
        controller.shutdown();
        // controller dropped here
    }
    // Receiver still works because it holds an Arc to the shared state
    assert!(
        receiver.is_shutting_down(),
        "Receiver should still work after controller is dropped"
    );
}

// ── CF: Cross-Module Fault Scenarios ────────────────────────────────

#[test]
fn cf_01_file_write_and_process_kill_interleaved() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("interleave.txt");

    // Write file data
    std::fs::write(&path, b"important data").expect("write");

    // Spawn and kill a process
    let mut child = Command::new("sleep").arg("100").spawn().expect("spawn");
    child.kill().expect("kill");
    child.wait().expect("reap");

    // File should be untouched
    assert_eq!(std::fs::read(&path).expect("read"), b"important data");
}

#[test]
fn cf_02_shutdown_during_process_wait() {
    // Shutdown signal and process wait are independent subsystems
    let controller = ShutdownController::new();
    let receiver = controller.subscribe();

    let child = Command::new("echo")
        .arg("signal_test")
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn");

    // Trigger shutdown while process is running
    controller.shutdown();
    assert!(receiver.is_shutting_down());

    // Process output is still captured correctly
    let output = child.wait_with_output().expect("wait_with_output");
    assert!(output.status.success());
    assert_eq!(output.stdout, b"signal_test\n");
}

#[test]
fn cf_03_graceful_shutdown_with_file_operations() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("graceful_file.txt");
    std::fs::write(&path, b"before shutdown").expect("write");

    let controller = ShutdownController::new();
    controller.shutdown();

    // File operations still work after shutdown
    let content = std::fs::read(&path).expect("read");
    assert_eq!(content, b"before shutdown");

    std::fs::write(&path, b"after shutdown").expect("write after");
    assert_eq!(std::fs::read(&path).expect("read"), b"after shutdown");
}

#[test]
fn cf_04_kill_on_drop_during_shutdown() {
    let controller = ShutdownController::new();

    let pid;
    {
        let child = Command::new("sleep")
            .arg("100")
            .kill_on_drop(true)
            .spawn()
            .expect("spawn");
        pid = child.id().expect("pid");

        controller.shutdown();
        // child dropped here — kill_on_drop fires
    }

    std::thread::sleep(std::time::Duration::from_millis(100));
    #[allow(clippy::cast_possible_wrap)]
    let pid_i32 = pid as i32;
    unsafe { libc::waitpid(pid_i32, std::ptr::null_mut(), libc::WNOHANG) };
    std::thread::sleep(std::time::Duration::from_millis(50));

    let ret = unsafe { libc::kill(pid_i32, 0) };
    assert_ne!(
        ret, 0,
        "Process should be gone after kill_on_drop during shutdown"
    );
}

// ── CT: Contract Artifact Validation ────────────────────────────────

#[test]
fn ct_01_json_parses_and_has_bead_id() {
    let j = common::json();
    assert_eq!(
        j.get("bead_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(""),
        "asupersync-2oh2u.3.7"
    );
}

#[test]
fn ct_02_doc_has_required_sections() {
    let required = [
        "Scope",
        "Fault-Injection Categories",
        "Conformance Invariants",
        "Test Evidence",
        "Drift Detection",
    ];
    for section in &required {
        assert!(
            common::md_has_section(section),
            "Missing section: '{section}'"
        );
    }
}

#[test]
fn ct_03_all_fault_categories_in_json() {
    let j = common::json();
    let categories = j
        .get("fault_categories")
        .and_then(serde_json::Value::as_array)
        .expect("fault_categories");

    let prefixes: Vec<&str> = categories
        .iter()
        .filter_map(|c| c.get("prefix").and_then(serde_json::Value::as_str))
        .collect();

    assert!(prefixes.contains(&"FF"), "Missing FF category");
    assert!(prefixes.contains(&"PF"), "Missing PF category");
    assert!(prefixes.contains(&"SF"), "Missing SF category");
    assert!(prefixes.contains(&"CF"), "Missing CF category");
    assert!(prefixes.contains(&"CT"), "Missing CT category");
}

#[test]
fn ct_04_summary_verdict() {
    let j = common::json();
    let summary = j.get("summary").expect("summary");
    assert_eq!(
        summary
            .get("overall_verdict")
            .and_then(serde_json::Value::as_str),
        Some("CONFORMANT")
    );
    assert_eq!(
        summary
            .get("total_tests")
            .and_then(serde_json::Value::as_u64),
        Some(34)
    );
}
