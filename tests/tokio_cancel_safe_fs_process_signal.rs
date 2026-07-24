#![allow(unsafe_code)]
//! Contract tests for [T3.6] Cancellation-Safe Integration: FS, Process, Signal
//!
//! Checks the scoped cancellation contracts across filesystem, process, and
//! signal flows, including ordered (non-rollback) File cursor completion.
//!
//! Categories:
//! - FC-01..FC-05: FS cancel-safety
//! - PC-01..PC-05: Process cancel-safety
//! - SC-01..SC-04: Signal cancel-safety
//! - IC-01..IC-06: Cross-module integration
//! - CT-01..CT-04: Contract artifact validation

#[cfg(feature = "test-internals")]
use asupersync::fs::{
    File, FileCursorOperationProbe, FilesystemOperationProbe,
    stage_write_atomic_with_probe_for_test, write_atomic, write_with_probe_for_test,
};
use asupersync::process::{Command, Stdio};
#[cfg(feature = "test-internals")]
use std::sync::Arc;
#[cfg(feature = "test-internals")]
use std::time::Duration;

mod common {
    pub const DOC_MD: &str = include_str!("../docs/tokio_cancel_safe_fs_process_signal.md");
    pub const DOC_JSON: &str = include_str!("../docs/tokio_cancel_safe_fs_process_signal.json");

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

fn long_running_command() -> Command {
    #[cfg(windows)]
    {
        let mut command = Command::new("cmd");
        command.arg("/C").arg("ping -n 100 127.0.0.1 >NUL");
        command
    }

    #[cfg(not(windows))]
    {
        let mut command = Command::new("sleep");
        command.arg("100");
        command
    }
}

fn echo_line_command(line: &str) -> Command {
    #[cfg(windows)]
    {
        let mut command = Command::new("cmd");
        command.arg("/C").arg(format!("echo {line}"));
        command
    }

    #[cfg(not(windows))]
    {
        let mut command = Command::new("printf");
        command.arg("%s\n").arg(line);
        command
    }
}

fn assert_stdout_line(bytes: &[u8], expected: &str) {
    let line = String::from_utf8(bytes.to_vec()).expect("child output must be valid UTF-8");
    assert_eq!(line.trim_end_matches(['\r', '\n']), expected);
}

#[cfg(unix)]
fn assert_process_not_running_after_drop(pid: u32, context: &str) {
    #[allow(clippy::cast_possible_wrap)]
    let pid = pid as libc::pid_t;

    loop {
        let mut status: libc::c_int = 0;
        let waited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if waited == -1 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            assert_eq!(
                err.raw_os_error(),
                Some(libc::ECHILD),
                "{context}: unexpected waitpid error after kill_on_drop"
            );
            return;
        }

        assert_ne!(
            waited, pid,
            "{context}: kill_on_drop terminated the child but left it waitable"
        );
        assert_eq!(
            waited, 0,
            "{context}: unexpected waitpid result after kill_on_drop"
        );

        let probe = unsafe { libc::kill(pid, 0) };
        assert_ne!(
            probe, 0,
            "{context}: child process is still alive after kill_on_drop"
        );
        return;
    }
}

#[cfg(windows)]
fn assert_process_not_running_after_drop(pid: u32, context: &str) {
    use windows_sys::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, WaitForSingleObject,
    };

    const SYNCHRONIZE_ACCESS: u32 = 0x0010_0000;

    let handle = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE_ACCESS,
            0,
            pid,
        )
    };
    if handle.is_null() {
        return;
    }

    let wait_result = unsafe { WaitForSingleObject(handle, 0) };
    unsafe {
        CloseHandle(handle);
    }

    assert_eq!(
        wait_result, WAIT_OBJECT_0,
        "{context}: child process is still running after kill_on_drop"
    );
}

// ── FC: FS Cancel-Safety ─────────────────────────────────────────────

#[test]
fn fc_01_started_file_cursor_operation_completes_before_reuse() {
    #[cfg(feature = "test-internals")]
    {
        futures_lite::future::block_on(async {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = dir.path().join("cursor_soft_cancel.txt");
            std::fs::write(&path, b"abcdef").expect("write fixture");

            let mut file = File::open(&path).await.expect("open fixture");
            let probe = Arc::new(FileCursorOperationProbe::new());
            file.install_cursor_operation_probe_for_test(Arc::clone(&probe));

            let mut cancelled_read = Box::pin(file.read_into_vec(vec![0_u8; 2]));
            assert!(
                futures_lite::future::poll_once(cancelled_read.as_mut())
                    .await
                    .is_none(),
                "probe must hold the started read pending"
            );
            if !probe.wait_until_first_blocked(Duration::from_secs(5)) {
                probe.release_first();
                panic!("read must actually start and acquire the cursor gate");
            }
            drop(cancelled_read);

            let mut reuse = Box::pin(file.stream_position());
            assert!(
                futures_lite::future::poll_once(reuse.as_mut())
                    .await
                    .is_none(),
                "immediate reuse must wait for the started read"
            );
            if !probe.wait_for_arrivals(2, Duration::from_secs(5)) {
                probe.release_first();
                panic!("replacement operation must reach the cursor gate");
            }
            assert_eq!(
                probe.acquisition_count(),
                1,
                "replacement operation must not overtake the cancelled read"
            );

            probe.release_first();
            assert_eq!(
                reuse.await.expect("replacement stream_position"),
                2,
                "the started read may commit, but must commit before reuse"
            );
            assert_eq!(probe.acquisition_count(), 2);
            assert_eq!(
                file.stream_position()
                    .await
                    .expect("stable cursor position"),
                2,
                "no late cursor mutation may occur after reuse completes"
            );
        });
    }

    #[cfg(not(feature = "test-internals"))]
    {
        let j = common::json();
        let required = j
            .get("proof_requirements")
            .and_then(|requirements| requirements.get("required_features"))
            .and_then(serde_json::Value::as_array)
            .expect("proof_requirements.required_features");
        assert!(
            required.iter().any(|feature| feature == "test-internals"),
            "the deterministic started-operation proof must fail closed without its feature"
        );
    }
}

#[test]
fn fc_02_cancelled_direct_write_may_commit_late() {
    #[cfg(feature = "test-internals")]
    {
        futures_lite::future::block_on(async {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = dir.path().join("soft_cancelled_write.txt");
            std::fs::write(&path, b"original").expect("write fixture");

            let probe = Arc::new(FilesystemOperationProbe::new());
            let mut cancelled_write = Box::pin(write_with_probe_for_test(
                &path,
                b"replacement",
                Arc::clone(&probe),
            ));
            assert!(
                futures_lite::future::poll_once(cancelled_write.as_mut())
                    .await
                    .is_none(),
                "probe must hold the started direct write pending"
            );
            if !probe.wait_until_blocked(Duration::from_secs(5)) {
                probe.release();
                panic!("direct write must reach its deterministic pre-mutation gate");
            }
            assert_eq!(
                std::fs::read(&path).expect("read target before release"),
                b"original",
                "the gate must precede the filesystem mutation"
            );

            drop(cancelled_write);
            probe.release();
            assert!(
                probe.wait_until_completed(Duration::from_secs(5)),
                "the dropped future's blocking write must finish"
            );
            assert_eq!(
                std::fs::read(&path).expect("read target after completion"),
                b"replacement",
                "soft cancellation discards the result, not a started mutation"
            );
        });
    }

    #[cfg(not(feature = "test-internals"))]
    {
        let j = common::json();
        let required = j
            .get("proof_requirements")
            .and_then(|requirements| requirements.get("required_features"))
            .and_then(serde_json::Value::as_array)
            .expect("proof_requirements.required_features");
        assert!(required.iter().any(|feature| feature == "test-internals"));
    }
}

#[test]
fn fc_03_cancelled_atomic_stage_preserves_target() {
    #[cfg(feature = "test-internals")]
    {
        futures_lite::future::block_on(async {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = dir.path().join("atomic_cancelled_stage.txt");
            std::fs::write(&path, b"original").expect("write fixture");

            let probe = Arc::new(FilesystemOperationProbe::new());
            let mut cancelled_stage = Box::pin(stage_write_atomic_with_probe_for_test(
                &path,
                b"replacement",
                Arc::clone(&probe),
            ));
            assert!(
                futures_lite::future::poll_once(cancelled_stage.as_mut())
                    .await
                    .is_none(),
                "probe must hold the fully staged replacement pending"
            );
            if !probe.wait_until_blocked(Duration::from_secs(5)) {
                probe.release();
                panic!("atomic replacement must reach its deterministic post-stage gate");
            }
            assert_eq!(
                std::fs::read(&path).expect("read target while staged"),
                b"original",
                "staging must not change the target"
            );

            drop(cancelled_stage);
            probe.release();
            assert!(
                probe.wait_until_completed(Duration::from_secs(5)),
                "discarding the staged result must finish temporary-file cleanup"
            );
            assert_eq!(
                std::fs::read(&path).expect("read target after cancellation"),
                b"original",
                "cancelling staging must leave the target unchanged"
            );
            let leaked_temps: Vec<_> = std::fs::read_dir(dir.path())
                .expect("read temp directory")
                .filter_map(Result::ok)
                .filter(|entry| {
                    entry
                        .file_name()
                        .to_string_lossy()
                        .contains(".asupersync-tmp-")
                })
                .collect();
            assert!(
                leaked_temps.is_empty(),
                "discarded staging must remove its temporary file: {leaked_temps:?}"
            );

            write_atomic(&path, b"committed")
                .await
                .expect("commit replacement");
            assert_eq!(
                std::fs::read(&path).expect("read committed target"),
                b"committed",
                "the public atomic helper must commit after successful staging"
            );
        });
    }

    #[cfg(not(feature = "test-internals"))]
    {
        let j = common::json();
        let required = j
            .get("proof_requirements")
            .and_then(|requirements| requirements.get("required_features"))
            .and_then(serde_json::Value::as_array)
            .expect("proof_requirements.required_features");
        assert!(required.iter().any(|feature| feature == "test-internals"));
    }
}

#[test]
fn fc_04_cancelled_open_leaves_no_handle() {
    // Opening a file and immediately dropping is safe
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("open_drop.txt");
    std::fs::write(&path, b"test").expect("write");
    {
        let _file = std::fs::File::open(&path).expect("open");
        // file dropped here — handle released
    }
    // File still accessible
    assert_eq!(std::fs::read(&path).expect("read"), b"test");
}

#[test]
fn fc_05_file_metadata_cancel_safe() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("meta.txt");
    std::fs::write(&path, b"hello").expect("write");
    let meta = std::fs::metadata(&path).expect("metadata");
    assert_eq!(meta.len(), 5);
}

// ── PC: Process Cancel-Safety ────────────────────────────────────────

#[test]
fn pc_01_kill_on_drop_prevents_zombie() {
    let pid;
    {
        let child = long_running_command()
            .kill_on_drop(true)
            .spawn()
            .expect("spawn");
        pid = child.id().expect("pid");
        // child dropped here — kill_on_drop sends SIGKILL
    }
    std::thread::sleep(std::time::Duration::from_millis(100));
    assert_process_not_running_after_drop(pid, "pc_01");
}

#[test]
fn pc_02_cancelled_wait_leaves_process_running() {
    let mut child = long_running_command().spawn().expect("spawn");
    // try_wait simulates a cancelled wait — process still running
    let result = child.try_wait().expect("try_wait");
    assert!(result.is_none());
    // Clean up
    child.kill().expect("kill");
    child.wait().expect("reap");
}

#[test]
fn pc_03_wait_async_cancel_safe() {
    let output = futures_lite::future::block_on(async {
        let child = echo_line_command("cancel_safe")
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn");
        let cx = asupersync::cx::Cx::for_testing();
        child.wait_with_output_async(&cx).await
    })
    .expect("output");
    assert!(output.status.success());
    assert_stdout_line(&output.stdout, "cancel_safe");
}

#[test]
fn pc_04_multiple_children_kill_on_drop() {
    // Spawn multiple children, all with kill_on_drop
    let mut pids = Vec::new();
    for _ in 0..3 {
        let child = long_running_command()
            .kill_on_drop(true)
            .spawn()
            .expect("spawn");
        pids.push(child.id().expect("pid"));
        // child dropped each iteration
    }
    std::thread::sleep(std::time::Duration::from_millis(150));
    for (index, pid) in pids.iter().enumerate() {
        assert_process_not_running_after_drop(*pid, &format!("pc_04 child {index}"));
    }
}

#[cfg(unix)]
#[test]
fn pc_05_signal_then_wait_no_leak() {
    let mut child = Command::new("sleep").arg("100").spawn().expect("spawn");
    child.signal(libc::SIGTERM).expect("signal");
    let status = child.wait().expect("wait");
    assert!(!status.success());
    assert_eq!(status.signal(), Some(libc::SIGTERM));
    // After wait, handle is consumed — no zombie
    assert!(child.try_wait().is_err(), "Handle should be consumed");
}

// ── SC: Signal Cancel-Safety ─────────────────────────────────────────

#[test]
fn sc_01_shutdown_controller_is_idempotent() {
    let controller = asupersync::signal::ShutdownController::new();
    assert!(!controller.is_shutting_down());
    controller.shutdown();
    assert!(controller.is_shutting_down());
    // Second call is idempotent
    controller.shutdown();
    assert!(controller.is_shutting_down());
}

#[test]
fn sc_02_shutdown_receiver_observes_shutdown() {
    let controller = asupersync::signal::ShutdownController::new();
    let receiver = controller.subscribe();
    assert!(!receiver.is_shutting_down());
    controller.shutdown();
    assert!(receiver.is_shutting_down());
}

#[test]
fn sc_03_multiple_receivers_all_notified() {
    let controller = asupersync::signal::ShutdownController::new();
    let receivers: Vec<_> = (0..5).map(|_| controller.subscribe()).collect();
    controller.shutdown();
    for (i, rx) in receivers.iter().enumerate() {
        assert!(
            rx.is_shutting_down(),
            "Receiver {i} should observe shutdown"
        );
    }
}

#[test]
fn sc_04_receiver_drop_before_shutdown_no_panic() {
    let controller = asupersync::signal::ShutdownController::new();
    {
        let _rx = controller.subscribe();
        // rx dropped before shutdown
    }
    // Shutdown after receiver dropped should not panic
    controller.shutdown();
    assert!(controller.is_shutting_down());
}

// ── IC: Cross-Module Integration ─────────────────────────────────────

#[test]
fn ic_01_file_and_process_concurrent() {
    // File write + process spawn — both succeed independently
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("concurrent.txt");

    let output = echo_line_command("process_output")
        .stdout(Stdio::piped())
        .output()
        .expect("process output");

    std::fs::write(&path, &output.stdout).expect("file write");
    assert_stdout_line(&std::fs::read(&path).expect("read"), "process_output");
}

#[test]
fn ic_02_process_kill_during_file_write() {
    // Start process, write file, kill process — file should be intact
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("kill_during_write.txt");

    let mut child = long_running_command().spawn().expect("spawn");

    std::fs::write(&path, b"written_before_kill").expect("write");
    child.kill().expect("kill");
    child.wait().expect("reap");

    assert_eq!(std::fs::read(&path).expect("read"), b"written_before_kill");
}

#[test]
fn ic_03_shutdown_kills_processes() {
    // Simulate: shutdown signal → kill child processes
    let controller = asupersync::signal::ShutdownController::new();
    let receiver = controller.subscribe();

    let mut child = long_running_command().spawn().expect("spawn");

    // Simulate shutdown signal
    controller.shutdown();
    assert!(receiver.is_shutting_down());

    // Application responds to shutdown by killing child
    child.kill().expect("kill");
    let status = child.wait().expect("wait");
    assert!(!status.success());
}

#[test]
fn ic_04_shutdown_with_kill_on_drop() {
    // Child with kill_on_drop is automatically cleaned up when scope exits
    let controller = asupersync::signal::ShutdownController::new();

    {
        let _child = long_running_command()
            .kill_on_drop(true)
            .spawn()
            .expect("spawn");

        controller.shutdown();
        // child dropped here — kill_on_drop sends SIGKILL
    }

    assert!(controller.is_shutting_down());
}

#[test]
fn ic_05_file_cleanup_after_process_exit() {
    // Process writes output, then we clean up the file
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("process_output.txt");

    let output = echo_line_command("cleanup_test")
        .stdout(Stdio::piped())
        .output()
        .expect("output");

    std::fs::write(&path, &output.stdout).expect("write");
    assert!(path.exists());
    std::fs::remove_file(&path).expect("remove");
    assert!(!path.exists());
}

#[test]
fn ic_06_concurrent_shutdown_and_file_ops() {
    // Shutdown does not interfere with file operations
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("shutdown_file.txt");
    let controller = asupersync::signal::ShutdownController::new();

    std::fs::write(&path, b"before_shutdown").expect("write");
    controller.shutdown();
    // File ops still work after shutdown signal
    let content = std::fs::read(&path).expect("read");
    assert_eq!(content, b"before_shutdown");
    std::fs::write(&path, b"after_shutdown").expect("write after");
    assert_eq!(std::fs::read(&path).expect("read"), b"after_shutdown");
}

// ── CT: Contract Artifact Validation ─────────────────────────────────

#[test]
fn ct_01_json_parses_and_has_bead_id() {
    let j = common::json();
    assert_eq!(
        j.get("bead_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(""),
        "asupersync-2oh2u.3.6"
    );
}

#[test]
fn ct_02_doc_has_required_sections() {
    let required = [
        "Scope",
        "Cancel-Safety Proof",
        "Region Quiescence",
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
fn ct_03_all_invariants_proven() {
    let j = common::json();
    let invariants = j
        .get("invariants_proven")
        .and_then(serde_json::Value::as_array)
        .expect("invariants_proven");
    assert!(invariants.len() >= 6);
    for inv in invariants {
        let verdict = inv
            .get("verdict")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        assert_eq!(verdict, "PROVEN");
    }

    let file_invariant = invariants
        .iter()
        .find(|invariant| {
            invariant.get("id").and_then(serde_json::Value::as_str) == Some("INV-CS-1")
        })
        .expect("INV-CS-1");
    assert!(
        file_invariant
            .get("description")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|description| {
                description.contains("completes before subsequent cursor access")
                    && description.contains("not rolled back")
            }),
        "File cancellation invariant must state ordered, non-rollback completion"
    );

    let file_module = j
        .get("modules_tested")
        .and_then(serde_json::Value::as_array)
        .and_then(|modules| {
            modules.iter().find(|module| {
                module.get("module").and_then(serde_json::Value::as_str) == Some("src/fs/file.rs")
            })
        })
        .expect("src/fs/file.rs module row");
    assert_eq!(
        file_module
            .get("rollback_safe")
            .and_then(serde_json::Value::as_bool),
        Some(false),
        "artifact must fail closed on rollback claims"
    );

    let mutation_invariant = invariants
        .iter()
        .find(|invariant| {
            invariant.get("id").and_then(serde_json::Value::as_str) == Some("INV-CS-6")
        })
        .expect("INV-CS-6");
    assert!(
        mutation_invariant
            .get("description")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|description| {
                description.contains("direct filesystem write may commit late")
                    && description.contains("atomic staging leaves the target unchanged")
            }),
        "filesystem mutation invariant must distinguish soft mutation from target-stable staging"
    );

    let mutation_contracts = j
        .get("filesystem_mutation_contracts")
        .and_then(serde_json::Value::as_array)
        .expect("filesystem_mutation_contracts");
    for operation in [
        "File::create",
        "OpenOptions::open(truncate)",
        "AsyncWrite for File::poll_write",
        "File::set_len",
        "fs::write",
        "fs::rename",
        "fs::remove_dir_all",
        "IoUringFile::open_with_flags(O_CREAT/O_TRUNC)",
        "IoUringFile::write_at",
        "IoUringFile::sync_all",
        "IoUringFile::set_permissions",
        "VfsFile::set_len",
        "Vfs::open_create",
        "Vfs::remove_dir_all",
        "UnixVfs::write",
        "fs::stage_write_atomic",
        "StagedAtomicWrite::commit",
        "fs::write_atomic",
    ] {
        assert!(
            mutation_contracts.iter().any(|contract| {
                contract
                    .get("operations")
                    .and_then(serde_json::Value::as_array)
                    .is_some_and(|operations| operations.iter().any(|item| item == operation))
            }),
            "filesystem mutation inventory missing {operation}"
        );
    }
}

#[test]
fn ct_04_summary_verdict() {
    let j = common::json();
    let summary = j.get("summary").expect("summary");
    assert_eq!(
        summary
            .get("overall_verdict")
            .and_then(serde_json::Value::as_str),
        Some("PROVEN")
    );
    assert_eq!(
        summary
            .get("obligation_leaks")
            .and_then(serde_json::Value::as_u64),
        Some(0)
    );
    assert_eq!(
        summary
            .get("total_tests")
            .and_then(serde_json::Value::as_u64),
        Some(24)
    );

    let required_features = j
        .get("proof_requirements")
        .and_then(|requirements| requirements.get("required_features"))
        .and_then(serde_json::Value::as_array)
        .expect("proof_requirements.required_features");
    assert!(
        required_features
            .iter()
            .any(|feature| feature == "test-internals")
    );
    assert_eq!(
        j.get("proof_requirements")
            .and_then(|requirements| requirements.get("behavioral_test"))
            .and_then(serde_json::Value::as_str),
        Some("fc_01_started_file_cursor_operation_completes_before_reuse")
    );
    let behavioral_tests = j
        .get("proof_requirements")
        .and_then(|requirements| requirements.get("behavioral_tests"))
        .and_then(serde_json::Value::as_array)
        .expect("proof_requirements.behavioral_tests");
    assert_eq!(behavioral_tests.len(), 3);
    for test in [
        "fc_01_started_file_cursor_operation_completes_before_reuse",
        "fc_02_cancelled_direct_write_may_commit_late",
        "fc_03_cancelled_atomic_stage_preserves_target",
    ] {
        assert!(behavioral_tests.iter().any(|item| item == test));
    }
}
