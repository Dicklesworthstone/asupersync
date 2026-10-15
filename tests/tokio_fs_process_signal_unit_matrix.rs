//! Contract tests for [T3.9] Exhaustive Unit-Test Matrix: FS, Process, Signal
//!
//! Maps each test explicitly to its owning T3 bead for traceability.
//! Fills coverage gaps identified after T3.3, T3.4, T3.5, T3.6, T3.7.
//!
//! Categories:
//! - FS-01..FS-06: File seek and position (T3.3)
//! - SC-01..SC-08: Signal convenience constructors (T3.5)
//! - GB-01..GB-05: Graceful builder (T3.5)
//! - GP-01..GP-03: Grace period guard (T3.5)
//! - CM-01..CM-04: Cross-module composed workflows (T3.6)
//! - MV-01..MV-04: Matrix validation (T3.9)

use asupersync::process::{Command, Stdio};
use asupersync::signal::{GracePeriodGuard, GracefulBuilder, GracefulConfig, ShutdownController};

mod common {
    pub const DOC_MD: &str = include_str!("../docs/tokio_fs_process_signal_unit_matrix.md");
    pub const DOC_JSON: &str = include_str!("../docs/tokio_fs_process_signal_unit_matrix.json");

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

// ── FS: File Seek and Position (T3.3) ───────────────────────────────

#[test]
fn fs_01_stream_position_zero_after_open() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("pos.txt");
    std::fs::write(&path, b"hello world").expect("write");

    let file = futures_lite::future::block_on(asupersync::fs::File::open(&path)).expect("open");
    let mut file = file;
    let pos = futures_lite::future::block_on(file.stream_position()).expect("stream_position");
    assert_eq!(pos, 0, "Position should be 0 after open");
}

#[test]
fn fs_02_seek_then_stream_position_consistent() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("seek_pos.txt");
    std::fs::write(&path, b"abcdefghij").expect("write");

    let file = futures_lite::future::block_on(asupersync::fs::File::open(&path)).expect("open");
    let mut file = file;

    let seek_result =
        futures_lite::future::block_on(file.seek(std::io::SeekFrom::Start(5))).expect("seek");
    assert_eq!(seek_result, 5);

    let pos = futures_lite::future::block_on(file.stream_position()).expect("stream_position");
    assert_eq!(pos, 5, "stream_position should match seek target");
}

#[test]
fn fs_03_rewind_resets_to_zero() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("rewind.txt");
    std::fs::write(&path, b"rewind data").expect("write");

    let file = futures_lite::future::block_on(asupersync::fs::File::open(&path)).expect("open");
    let mut file = file;

    // Seek to middle
    futures_lite::future::block_on(file.seek(std::io::SeekFrom::Start(6))).expect("seek");
    // Rewind
    futures_lite::future::block_on(file.rewind()).expect("rewind");

    let pos = futures_lite::future::block_on(file.stream_position()).expect("stream_position");
    assert_eq!(pos, 0, "Position should be 0 after rewind");
}

#[test]
fn fs_04_seek_end_returns_file_length() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("seek_end.txt");
    std::fs::write(&path, b"twelve bytes").expect("write");

    let file = futures_lite::future::block_on(asupersync::fs::File::open(&path)).expect("open");
    let mut file = file;

    let pos = futures_lite::future::block_on(file.seek(std::io::SeekFrom::End(0))).expect("seek");
    assert_eq!(pos, 12, "Seek(End(0)) should return file length");
}

#[test]
fn fs_05_open_options_read_write() {
    use std::io::{Read, Seek, Write};

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("rw.txt");
    std::fs::write(&path, b"initial").expect("write");

    // Open with read+write
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .expect("open rw");

    // Read the content
    let mut buf = Vec::new();
    let mut file_ref = &file;
    file_ref.read_to_end(&mut buf).expect("read");
    assert_eq!(buf, b"initial");

    // Write at the beginning
    let mut file_mut = file;
    file_mut.seek(std::io::SeekFrom::Start(0)).expect("seek");
    file_mut.write_all(b"updated").expect("write");
    file_mut.flush().expect("flush");

    assert_eq!(std::fs::read(&path).expect("read"), b"updated");
}

#[test]
fn fs_06_open_options_append() {
    use std::io::Write;

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("append.txt");
    std::fs::write(&path, b"first").expect("write");

    // Open with append
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .expect("open append");

    file.write_all(b"_second").expect("append");
    file.flush().expect("flush");

    assert_eq!(std::fs::read(&path).expect("read"), b"first_second");
}

// ── SC: Signal Convenience Constructors (T3.5) ─────────────────────

#[cfg(unix)]
#[test]
fn sc_01_sigterm_creates_valid_stream() {
    let stream = asupersync::signal::sigterm().expect("sigterm");
    assert_eq!(
        stream.kind(),
        asupersync::signal::SignalKind::Terminate,
        "sigterm() should produce Terminate kind"
    );
}

#[cfg(unix)]
#[test]
fn sc_02_sighup_creates_valid_stream() {
    let stream = asupersync::signal::sighup().expect("sighup");
    assert_eq!(stream.kind(), asupersync::signal::SignalKind::Hangup);
}

#[cfg(unix)]
#[test]
fn sc_03_sigquit_creates_valid_stream() {
    let stream = asupersync::signal::sigquit().expect("sigquit");
    assert_eq!(stream.kind(), asupersync::signal::SignalKind::Quit);
}

#[cfg(unix)]
#[test]
fn sc_04_sigchld_creates_valid_stream() {
    let stream = asupersync::signal::sigchld().expect("sigchld");
    assert_eq!(stream.kind(), asupersync::signal::SignalKind::Child);
}

#[cfg(unix)]
#[test]
fn sc_05_sigwinch_creates_valid_stream() {
    let stream = asupersync::signal::sigwinch().expect("sigwinch");
    assert_eq!(stream.kind(), asupersync::signal::SignalKind::WindowChange);
}

#[cfg(unix)]
#[test]
fn sc_06_sigpipe_creates_valid_stream() {
    let stream = asupersync::signal::sigpipe().expect("sigpipe");
    assert_eq!(stream.kind(), asupersync::signal::SignalKind::Pipe);
}

#[cfg(unix)]
#[test]
fn sc_07_sigalrm_creates_valid_stream() {
    let stream = asupersync::signal::sigalrm().expect("sigalrm");
    assert_eq!(stream.kind(), asupersync::signal::SignalKind::Alarm);
}

#[test]
fn sc_08_ctrl_c_is_available() {
    let available = asupersync::signal::is_available();
    #[cfg(unix)]
    assert!(available, "ctrl_c should be available on Unix");
    #[cfg(not(unix))]
    {
        let _ = available; // Platform-dependent
    }
}

// ── GB: Graceful Builder (T3.5) ─────────────────────────────────────

#[test]
fn gb_01_default_config() {
    let controller = ShutdownController::new();
    let receiver = controller.subscribe();
    let builder = GracefulBuilder::new(receiver);

    assert_eq!(
        builder.config().grace_period,
        std::time::Duration::from_secs(30)
    );
    assert!(builder.config().log_events);
}

#[test]
fn gb_02_custom_grace_period() {
    let controller = ShutdownController::new();
    let receiver = controller.subscribe();
    let builder = GracefulBuilder::new(receiver).grace_period(std::time::Duration::from_secs(10));

    assert_eq!(
        builder.config().grace_period,
        std::time::Duration::from_secs(10)
    );
}

#[test]
fn gb_03_run_completes_normally() {
    let controller = ShutdownController::new();
    let receiver = controller.subscribe();
    let builder = GracefulBuilder::new(receiver);

    let result = futures_lite::future::block_on(builder.run(std::future::ready(42)));
    assert!(result.is_completed());
    assert_eq!(result.into_completed(), Some(42));
}

#[test]
fn gb_04_run_with_pre_shutdown() {
    let controller = ShutdownController::new();
    controller.shutdown(); // Pre-shutdown
    let receiver = controller.subscribe();
    let builder = GracefulBuilder::new(receiver);

    let result = futures_lite::future::block_on(builder.run(std::future::ready(42)));
    assert!(result.is_shutdown());
}

#[test]
fn gb_05_graceful_config_fluent_builder() {
    let config = GracefulConfig::default()
        .with_grace_period(std::time::Duration::from_secs(5))
        .with_logging(false);

    assert_eq!(config.grace_period, std::time::Duration::from_secs(5));
    assert!(!config.log_events);
}

// ── GP: Grace Period Guard (T3.5) ───────────────────────────────────

#[test]
fn gp_01_remaining_decreases() {
    let guard = GracePeriodGuard::new(std::time::Duration::from_millis(200));
    let initial = guard.remaining();

    std::thread::sleep(std::time::Duration::from_millis(50));
    let after = guard.remaining();

    assert!(
        after < initial,
        "Remaining should decrease over time: initial={initial:?}, after={after:?}"
    );
}

#[test]
fn gp_02_duration_accessor() {
    let dur = std::time::Duration::from_millis(750);
    let guard = GracePeriodGuard::new(dur);
    assert_eq!(guard.duration(), dur);
}

#[test]
fn gp_03_started_at_is_recent() {
    let before = std::time::Instant::now();
    let guard = GracePeriodGuard::new(std::time::Duration::from_secs(1));
    let after = std::time::Instant::now();

    assert!(guard.started_at() >= before);
    assert!(guard.started_at() <= after);
}

// ── CM: Cross-Module Composed Workflows (T3.6) ─────────────────────

#[test]
fn cm_01_shutdown_receiver_clone_both_observe() {
    let controller = ShutdownController::new();
    let rx1 = controller.subscribe();
    let rx2 = rx1.clone();

    assert!(!rx1.is_shutting_down());
    assert!(!rx2.is_shutting_down());

    controller.shutdown();

    assert!(rx1.is_shutting_down(), "Original should observe shutdown");
    assert!(rx2.is_shutting_down(), "Clone should observe shutdown");
}

#[test]
fn cm_02_file_write_process_output_verify() {
    // End-to-end: process produces output → write to file → verify
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("e2e.txt");

    let output = Command::new("echo")
        .arg("end_to_end")
        .stdout(Stdio::piped())
        .output()
        .expect("output");

    std::fs::write(&path, &output.stdout).expect("write");
    let content = std::fs::read(&path).expect("read");
    assert_eq!(content, b"end_to_end\n");
}

#[test]
fn cm_03_shutdown_during_file_seek() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("seek_shutdown.txt");
    std::fs::write(&path, b"seek during shutdown").expect("write");

    let controller = ShutdownController::new();
    let file = futures_lite::future::block_on(asupersync::fs::File::open(&path)).expect("open");
    let mut file = file;

    // Seek first
    futures_lite::future::block_on(file.seek(std::io::SeekFrom::Start(5))).expect("seek");

    // Shutdown
    controller.shutdown();

    // File still accessible after shutdown
    let pos = futures_lite::future::block_on(file.stream_position()).expect("stream_position");
    assert_eq!(pos, 5);
}

#[test]
fn cm_04_process_with_env_and_shutdown() {
    let controller = ShutdownController::new();
    let receiver = controller.subscribe();

    let output = Command::new("sh")
        .arg("-c")
        .arg("echo $MY_VAR")
        .env("MY_VAR", "test_value")
        .stdout(Stdio::piped())
        .output()
        .expect("output");

    assert!(output.status.success());
    assert_eq!(output.stdout, b"test_value\n");

    // Shutdown observed independently
    controller.shutdown();
    assert!(receiver.is_shutting_down());
}

// ── MV: Matrix Validation (T3.9) ───────────────────────────────────

#[test]
fn mv_01_json_has_bead_id() {
    let j = common::json();
    assert_eq!(
        j.get("bead_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(""),
        "asupersync-2oh2u.3.9"
    );
}

#[test]
fn mv_02_doc_has_required_sections() {
    let required = ["Scope", "Test Categories", "Drift Detection"];
    for section in &required {
        assert!(
            common::md_has_section(section),
            "Missing section: '{section}'"
        );
    }
}

#[test]
fn mv_03_all_bead_references_present() {
    let j = common::json();
    let coverage = j
        .get("bead_coverage")
        .and_then(serde_json::Value::as_array)
        .expect("bead_coverage");

    let beads: Vec<&str> = coverage
        .iter()
        .filter_map(|c| c.get("bead").and_then(serde_json::Value::as_str))
        .collect();

    assert!(beads.contains(&"T3.3"), "Missing T3.3 coverage");
    assert!(beads.contains(&"T3.5"), "Missing T3.5 coverage");
    assert!(beads.contains(&"T3.6"), "Missing T3.6 coverage");
    assert!(beads.contains(&"T3.9"), "Missing T3.9 coverage");
}

#[test]
fn mv_04_summary_test_count() {
    let j = common::json();
    let summary = j.get("summary").expect("summary");
    assert_eq!(
        summary
            .get("total_tests")
            .and_then(serde_json::Value::as_u64),
        Some(30)
    );
    assert_eq!(
        summary
            .get("overall_verdict")
            .and_then(serde_json::Value::as_str),
        Some("COMPLETE")
    );
}
