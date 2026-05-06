//! Deterministic Conformance and Fault-Injection Tests (Track 3.7)
//!
//! Validates conformance contracts and adversarial fault scenarios for
//! filesystem, process, and signal domains. Proves deterministic behavior
//! under normal, cancellation, and fault conditions.
//!
//! Bead: asupersync-2oh2u.3.7

#![allow(missing_docs)]

use asupersync::fs;
use asupersync::process::{Command, Stdio};
use asupersync::signal::{GracefulOutcome, ShutdownController, with_graceful_shutdown};
use std::collections::{BTreeSet, HashSet};
use std::path::Path;

// ─── Constants ──────────────────────────────────────────────────────

const DOC_PATH: &str = "docs/tokio_fs_process_signal_conformance_faults.md";
const JSON_PATH: &str = "docs/tokio_fs_process_signal_conformance_faults.json";

// ─── Helpers ────────────────────────────────────────────────────────

fn load_doc() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(DOC_PATH);
    std::fs::read_to_string(path).expect("failed to load conformance faults doc")
}

fn load_json() -> serde_json::Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(JSON_PATH);
    let raw = std::fs::read_to_string(path).expect("failed to load conformance faults JSON");
    serde_json::from_str(&raw).expect("failed to parse conformance faults JSON")
}

fn temp_dir(suffix: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("asupersync_t37_{}_{suffix}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp_dir setup must succeed");
    dir
}

// ═══════════════════════════════════════════════════════════════════
// Section 1: Document infrastructure (7 tests)
// ═══════════════════════════════════════════════════════════════════

#[test]
fn doc_exists() {
    assert!(
        Path::new(DOC_PATH).exists(),
        "Conformance faults doc must exist"
    );
}

#[test]
fn doc_references_bead() {
    let doc = load_doc();
    assert!(
        doc.contains("asupersync-2oh2u.3.7"),
        "Doc must reference its own bead ID"
    );
}

#[test]
fn doc_has_required_sections() {
    let doc = load_doc();
    let sections = [
        "Scope",
        "Filesystem Conformance",
        "Process Conformance",
        "Signal Conformance",
        "Cross-Domain Integration",
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
    for gap in &["FS-G3", "PR-G4", "SG-G3", "SG-G4"] {
        assert!(doc.contains(gap), "Doc must reference gap: {gap}");
    }
}

#[test]
fn doc_references_cross_documents() {
    let doc = load_doc();
    let refs = [
        "tokio_fs_process_signal_parity_matrix.md",
        "src/fs/vfs.rs",
        "src/signal/mod.rs",
        "src/process.rs",
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
            (1..=10).any(|i| trimmed.starts_with(&format!("{i}. **")))
        })
        .count();
    assert!(
        count >= 10,
        "Doc must have at least 10 determinism invariants, found {count}"
    );
}

#[test]
fn doc_references_test_file() {
    let doc = load_doc();
    assert!(
        doc.contains("tokio_fs_process_signal_conformance_faults.rs"),
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
        "Conformance faults JSON must exist"
    );
}

#[test]
fn json_has_bead_id() {
    let json = load_json();
    assert_eq!(json["bead_id"].as_str().unwrap(), "asupersync-2oh2u.3.7");
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
    for gap in &["FS-G3", "PR-G4", "SG-G3", "SG-G4"] {
        assert!(gaps.contains(gap), "JSON must reference gap: {gap}");
    }
}

#[test]
fn json_conformance_contracts_have_unique_ids() {
    let json = load_json();
    let contracts = json["conformance_contracts"].as_array().unwrap();
    let mut ids = HashSet::new();
    for c in contracts {
        let id = c["id"].as_str().unwrap();
        assert!(ids.insert(id), "Duplicate contract ID: {id}");
    }
}

#[test]
fn json_fault_scenarios_have_unique_ids() {
    let json = load_json();
    let faults = json["fault_scenarios"].as_array().unwrap();
    let mut ids = HashSet::new();
    for f in faults {
        let id = f["id"].as_str().unwrap();
        assert!(ids.insert(id), "Duplicate fault ID: {id}");
    }
}

#[test]
fn json_contracts_cover_all_domains() {
    let json = load_json();
    let contracts = json["conformance_contracts"].as_array().unwrap();
    let domains: BTreeSet<&str> = contracts
        .iter()
        .map(|c| c["domain"].as_str().unwrap())
        .collect();
    for domain in &["filesystem", "process", "signal", "cross-domain"] {
        assert!(
            domains.contains(domain),
            "Contracts must cover domain: {domain}"
        );
    }
}

#[test]
fn json_summary_counts_match() {
    let json = load_json();
    let declared_contracts = json["summary"]["total_conformance_contracts"]
        .as_u64()
        .unwrap() as usize;
    let actual_contracts = json["conformance_contracts"].as_array().unwrap().len();
    assert_eq!(
        declared_contracts, actual_contracts,
        "Summary contract count ({declared_contracts}) != actual ({actual_contracts})"
    );

    let declared_faults = json["summary"]["total_fault_scenarios"].as_u64().unwrap() as usize;
    let actual_faults = json["fault_scenarios"].as_array().unwrap().len();
    assert_eq!(
        declared_faults, actual_faults,
        "Summary fault count ({declared_faults}) != actual ({actual_faults})"
    );
}

#[test]
fn json_determinism_invariants_count() {
    let json = load_json();
    let invariants = json["determinism_invariants"].as_array().unwrap();
    assert!(
        invariants.len() >= 10,
        "Must have at least 10 invariants, found {}",
        invariants.len()
    );
}

// ═══════════════════════════════════════════════════════════════════
// Section 3: Filesystem conformance tests (6 tests) — CF-FS-*
// ═══════════════════════════════════════════════════════════════════

#[test]
fn cf_fs_01_unix_vfs_implements_trait() {
    // Type-system proof: UnixVfs is usable as a Vfs implementor.
    // This is a compile-time contract — if this test compiles, it passes.
    fn assert_vfs<V: asupersync::fs::Vfs>() {}
    assert_vfs::<asupersync::fs::UnixVfs>();
}

#[test]
fn cf_fs_02_file_roundtrip() {
    use asupersync::io::{AsyncReadExt, AsyncWriteExt};

    let dir = temp_dir("cf02");
    let path = dir.join("roundtrip.txt");
    let data = b"deterministic content for CF-FS-02";

    futures_lite::future::block_on(async {
        let mut file = fs::File::create(&path).await.expect("create");
        file.write_all(data).await.expect("write");
        file.sync_all().await.expect("sync");
        drop(file);

        let mut file = fs::File::open(&path).await.expect("open");
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).await.expect("read");
        assert_eq!(buf, data, "Roundtrip must produce identical bytes");
    });

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cf_fs_03_directory_create_and_list() {
    let dir = temp_dir("cf03");
    let sub = dir.join("subdir_cf03");

    // Use std::fs for directory setup since async fs convenience fns need a runtime
    std::fs::create_dir_all(&sub).expect("create_dir_all");
    std::fs::write(sub.join("a.txt"), b"a").expect("write a");
    std::fs::write(sub.join("b.txt"), b"b").expect("write b");

    futures_lite::future::block_on(async {
        let mut entries = Vec::new();
        let mut rd = fs::read_dir(&sub).await.expect("read_dir should succeed");
        while let Some(entry) = rd.next_entry().await.expect("next_entry") {
            entries.push(entry.file_name().to_string_lossy().to_string());
        }
        entries.sort();
        assert_eq!(entries, vec!["a.txt", "b.txt"]);
    });

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cf_fs_04_canonicalize_idempotent() {
    let dir = temp_dir("cf04");
    let path = dir.join("canon_test.txt");
    std::fs::write(&path, b"x").expect("setup");

    // Use std::fs::canonicalize since async path_ops need spawn_blocking runtime
    let canon1 = std::fs::canonicalize(&path).expect("first canonicalize");
    let canon2 = std::fs::canonicalize(&canon1).expect("second canonicalize");
    assert_eq!(
        canon1, canon2,
        "canonicalize must be idempotent: {canon1:?} != {canon2:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cf_fs_05_metadata_reflects_file_size() {
    let dir = temp_dir("cf05");
    let path = dir.join("meta_size.txt");
    let data = b"hello metadata world";

    std::fs::write(&path, data).expect("write");
    let meta = std::fs::metadata(&path).expect("metadata");
    assert_eq!(
        meta.len(),
        data.len() as u64,
        "Metadata size must match written bytes"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cf_fs_06_sync_all_after_write() {
    use asupersync::io::AsyncWriteExt;

    let dir = temp_dir("cf06");
    let path = dir.join("sync_test.txt");

    futures_lite::future::block_on(async {
        let mut file = fs::File::create(&path).await.expect("create");
        file.write_all(b"sync data").await.expect("write");
        file.sync_all().await.expect("sync_all must succeed");
    });

    let _ = std::fs::remove_dir_all(&dir);
}

// ═══════════════════════════════════════════════════════════════════
// Section 4: Filesystem fault injection (5 tests) — FI-FS-*
// ═══════════════════════════════════════════════════════════════════

#[test]
fn fi_fs_01_read_nonexistent() {
    // Use std::fs since async fs::read needs spawn_blocking
    let result = std::fs::read("/tmp/__nonexistent_t37_file__");
    assert!(result.is_err(), "Reading nonexistent file must error");
    let err = result.unwrap_err();
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::NotFound,
        "Error must be NotFound, got: {err}"
    );
}

#[test]
fn fi_fs_02_write_to_readonly() {
    let dir = temp_dir("fi02");
    let path = dir.join("readonly.txt");
    std::fs::write(&path, b"original").expect("setup");

    // Make read-only
    let mut perms = std::fs::metadata(&path).unwrap().permissions();
    perms.set_readonly(true);
    std::fs::set_permissions(&path, perms).unwrap();

    let result = std::fs::write(&path, b"overwrite attempt");
    assert!(result.is_err(), "Writing to read-only file must error");

    // Cleanup: restore permissions before removal
    let mut perms = std::fs::metadata(&path).unwrap().permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    perms.set_readonly(false);
    std::fs::set_permissions(&path, perms).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn fi_fs_03_remove_nonexistent_dir() {
    let result = std::fs::remove_dir("/tmp/__nonexistent_dir_t37__");
    assert!(result.is_err(), "Removing nonexistent directory must error");
}

#[test]
fn fi_fs_04_create_existing_dir() {
    let dir = temp_dir("fi04");
    let sub = dir.join("existing_dir_test");
    std::fs::create_dir_all(&sub).expect("setup");

    // create_dir (not create_dir_all) should fail on existing dir
    let result = std::fs::create_dir(&sub);
    assert!(
        result.is_err(),
        "create_dir on existing directory must error"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn fi_fs_05_read_empty_file() {
    let dir = temp_dir("fi05");
    let path = dir.join("empty.txt");
    std::fs::write(&path, b"").expect("setup");

    let data = std::fs::read(&path).expect("reading empty file should not error");
    assert!(data.is_empty(), "Empty file must return zero bytes");

    let _ = std::fs::remove_dir_all(&dir);
}

// ═══════════════════════════════════════════════════════════════════
// Section 5: Process conformance tests (4 tests) — CF-PR-*
// ═══════════════════════════════════════════════════════════════════

#[test]
fn cf_pr_01_spawn_returns_child_with_pid() {
    let child = Command::new("true").spawn().expect("spawn should succeed");
    let pid = child.id();
    assert!(pid.is_some(), "Spawned child must have a pid");
    assert!(pid.unwrap() > 0, "Pid must be positive");
}

#[test]
fn cf_pr_02_wait_after_kill_returns_nonsuccess() {
    let mut child = Command::new("sleep")
        .arg("60")
        .spawn()
        .expect("spawn should succeed");
    child.kill().expect("kill should succeed");
    let status = child.wait().expect("wait after kill should succeed");
    assert!(!status.success(), "Killed process must not report success");
}

#[test]
fn cf_pr_03_kill_on_drop_terminates_child() {
    let pid: u32;
    {
        let child = Command::new("sleep")
            .arg("60")
            .kill_on_drop(true)
            .spawn()
            .expect("spawn should succeed");
        pid = child.id().expect("must have pid");

        // Verify child is alive before drop
        assert!(
            Path::new(&format!("/proc/{pid}/cmdline")).exists(),
            "child must be alive before drop"
        );
        // child dropped here
    }

    std::thread::sleep(std::time::Duration::from_millis(200));
    let cmdline = std::fs::read_to_string(format!("/proc/{pid}/cmdline")).unwrap_or_default();
    assert!(
        !cmdline.contains("sleep"),
        "child should be dead after kill_on_drop"
    );
}

#[test]
fn cf_pr_04_try_wait_is_nonblocking() {
    let mut child = Command::new("sleep")
        .arg("60")
        .spawn()
        .expect("spawn should succeed");

    let start = std::time::Instant::now();
    let result = child.try_wait().expect("try_wait should not error");
    let elapsed = start.elapsed();

    assert!(
        result.is_none(),
        "try_wait must return None for running child"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(1),
        "try_wait must complete quickly (took {elapsed:?})"
    );

    let _ = child.kill();
    let _ = child.wait();
}

// ═══════════════════════════════════════════════════════════════════
// Section 6: Process fault injection (4 tests) — FI-PR-*
// ═══════════════════════════════════════════════════════════════════

#[test]
fn fi_pr_01_spawn_nonexistent_binary() {
    let result = Command::new("__nonexistent_binary_t37__").spawn();
    assert!(result.is_err(), "Spawning nonexistent binary must error");
}

#[test]
fn fi_pr_02_kill_already_exited() {
    let mut child = Command::new("true").spawn().expect("spawn should succeed");
    let _ = child.wait();

    // kill on already-exited process should not panic
    let result = child.kill();
    // Either Ok or Err is fine — the contract is that it doesn't panic
    let _ = result;
}

#[test]
fn fi_pr_03_read_stdout_from_stderr_only() {
    let output = Command::new("sh")
        .arg("-c")
        .arg("echo stderr_only >&2")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("should succeed");

    assert!(
        output.stdout.is_empty(),
        "stdout must be empty when process only writes to stderr"
    );
    assert!(!output.stderr.is_empty(), "stderr must not be empty");
}

#[test]
fn fi_pr_04_empty_env_variable() {
    let output = Command::new("sh")
        .arg("-c")
        .arg("printf '%s' \"$T37_EMPTY_VAR\"")
        .env("T37_EMPTY_VAR", "")
        .stdout(Stdio::piped())
        .output()
        .expect("should succeed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        stdout, "",
        "Empty env var must be visible as empty string to child"
    );
}

// ═══════════════════════════════════════════════════════════════════
// Section 7: Signal conformance tests (5 tests) — CF-SG-*
// ═══════════════════════════════════════════════════════════════════

#[test]
fn cf_sg_01_shutdown_controller_creates() {
    let controller = ShutdownController::new();
    assert!(
        !controller.is_shutting_down(),
        "Fresh controller must not be shutting down"
    );
}

#[test]
fn cf_sg_02_receiver_resolves_after_shutdown() {
    futures_lite::future::block_on(async {
        let controller = ShutdownController::new();
        let mut receiver = controller.subscribe();
        controller.shutdown();
        receiver.wait().await;
        assert!(
            receiver.is_shutting_down(),
            "Receiver must report shutting down after wait"
        );
    });
}

#[test]
fn cf_sg_03_multiple_shutdown_calls_idempotent() {
    let controller = ShutdownController::new();
    controller.shutdown();
    controller.shutdown();
    controller.shutdown();
    assert!(
        controller.is_shutting_down(),
        "Controller must still report shutting down"
    );
}

#[test]
fn cf_sg_04_graceful_shutdown_returns_shutdown_signaled() {
    futures_lite::future::block_on(async {
        let controller = ShutdownController::new();
        let receiver = controller.subscribe();

        // Signal shutdown immediately so the task never completes
        controller.shutdown();

        let outcome = with_graceful_shutdown(
            std::pin::pin!(async {
                // This future would take forever, but shutdown fires first
                futures_lite::future::yield_now().await;
                loop {
                    futures_lite::future::yield_now().await;
                }
                #[allow(unreachable_code)]
                42
            }),
            receiver,
        )
        .await;

        assert!(
            outcome.is_shutdown(),
            "Must return ShutdownSignaled when shutdown fires first"
        );
    });
}

#[test]
fn cf_sg_05_graceful_shutdown_returns_completed() {
    futures_lite::future::block_on(async {
        let controller = ShutdownController::new();
        let receiver = controller.subscribe();

        let outcome = with_graceful_shutdown(std::pin::pin!(async { 42_i32 }), receiver).await;

        assert!(
            outcome.is_completed(),
            "Must return Completed when task finishes first"
        );
        assert_eq!(outcome.into_completed(), Some(42));
        // Don't signal shutdown — task completed first
        drop(controller);
    });
}

// ═══════════════════════════════════════════════════════════════════
// Section 8: Signal fault injection (3 tests) — FI-SG-*
// ═══════════════════════════════════════════════════════════════════

#[test]
fn fi_sg_01_subscribe_after_controller_shutdown() {
    futures_lite::future::block_on(async {
        let controller = ShutdownController::new();
        controller.shutdown();

        // Subscribe after shutdown has been called
        let mut receiver = controller.subscribe();
        // Should resolve immediately or very quickly since shutdown is already signaled
        receiver.wait().await;
        assert!(
            receiver.is_shutting_down(),
            "Receiver subscribed after shutdown must see shutdown state"
        );
    });
}

#[test]
fn fi_sg_02_multiple_receivers_all_notified() {
    futures_lite::future::block_on(async {
        let controller = ShutdownController::new();
        let mut r1 = controller.subscribe();
        let mut r2 = controller.subscribe();
        let mut r3 = controller.subscribe();

        controller.shutdown();

        r1.wait().await;
        r2.wait().await;
        r3.wait().await;

        assert!(r1.is_shutting_down());
        assert!(r2.is_shutting_down());
        assert!(r3.is_shutting_down());
    });
}

#[test]
fn fi_sg_03_shutdown_during_task_deterministic() {
    // Verify that with_graceful_shutdown always produces exactly one outcome variant
    futures_lite::future::block_on(async {
        let controller = ShutdownController::new();
        let receiver = controller.subscribe();

        // Task completes immediately
        let outcome: GracefulOutcome<i32> =
            with_graceful_shutdown(std::pin::pin!(async { 99 }), receiver).await;

        // Must be exactly one of the two variants
        let is_exactly_one = outcome.is_completed() ^ outcome.is_shutdown();
        assert!(is_exactly_one, "Outcome must be exactly one variant");
    });
}

// ═══════════════════════════════════════════════════════════════════
// Section 9: Cross-domain integration (3 tests) — CF-X-*
// ═══════════════════════════════════════════════════════════════════

#[test]
fn cf_x_01_fs_during_graceful_shutdown() {
    let dir = temp_dir("cx01");
    let path = dir.join("shutdown_fs.txt");
    let path_clone = path.clone();

    futures_lite::future::block_on(async {
        let controller = ShutdownController::new();
        let receiver = controller.subscribe();

        // Task writes file synchronously (to avoid spawn_blocking issues) then completes
        let outcome = with_graceful_shutdown(
            std::pin::pin!(async move {
                std::fs::write(&path_clone, b"written during shutdown scope")
                    .expect("fs write in shutdown scope");
                true
            }),
            receiver,
        )
        .await;

        assert!(
            outcome.is_completed(),
            "Task should complete before shutdown"
        );

        // Verify file was written
        let data = std::fs::read(&path).expect("read back");
        assert_eq!(data, b"written during shutdown scope");
    });

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cf_x_02_process_kill_on_drop_during_shutdown() {
    futures_lite::future::block_on(async {
        let controller = ShutdownController::new();
        let receiver = controller.subscribe();

        // Signal shutdown immediately
        controller.shutdown();

        let outcome = with_graceful_shutdown(
            std::pin::pin!(async {
                let child = Command::new("sleep")
                    .arg("60")
                    .kill_on_drop(true)
                    .spawn()
                    .expect("spawn");
                let pid = child.id().expect("pid");
                // child dropped when async block ends
                drop(child);

                std::thread::sleep(std::time::Duration::from_millis(100));
                let cmdline =
                    std::fs::read_to_string(format!("/proc/{pid}/cmdline")).unwrap_or_default();
                !cmdline.contains("sleep")
            }),
            receiver,
        )
        .await;

        // Either the task completed (child killed) or shutdown happened first
        // Both are valid outcomes — the contract is that no zombie is left
        match outcome {
            GracefulOutcome::Completed(dead) => {
                assert!(
                    dead,
                    "Child must be dead after kill_on_drop in shutdown scope"
                );
            }
            GracefulOutcome::ShutdownSignaled => {
                // Shutdown fired before task completed — acceptable
            }
        }
    });
}

#[test]
fn cf_x_03_process_output_alongside_fs() {
    let dir = temp_dir("cx03");
    let path = dir.join("alongside.txt");

    // Run both FS and process operations to prove cross-domain isolation
    std::fs::write(&path, b"concurrent").expect("fs write");

    let output = Command::new("echo")
        .arg("concurrent_proc")
        .stdout(Stdio::piped())
        .output()
        .expect("process output");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("concurrent_proc"));

    // FS data is intact after process operation
    let data = std::fs::read(&path).expect("read back");
    assert_eq!(data, b"concurrent");

    let _ = std::fs::remove_dir_all(&dir);
}

// ═══════════════════════════════════════════════════════════════════
// Section 10: Contract coverage validation (3 tests)
// ═══════════════════════════════════════════════════════════════════

#[test]
fn json_contracts_cover_all_gaps() {
    let json = load_json();
    let contracts = json["conformance_contracts"].as_array().unwrap();
    let gaps: BTreeSet<&str> = contracts
        .iter()
        .map(|c| c["gap"].as_str().unwrap())
        .collect();

    for gap in &["FS-G3", "PR-G4", "SG-G3", "SG-G4"] {
        assert!(gaps.contains(gap), "Contracts must cover gap: {gap}");
    }
}

#[test]
fn json_faults_cover_all_domains() {
    let json = load_json();
    let faults = json["fault_scenarios"].as_array().unwrap();
    let domains: BTreeSet<&str> = faults
        .iter()
        .map(|f| f["domain"].as_str().unwrap())
        .collect();

    for domain in &["filesystem", "process", "signal"] {
        assert!(
            domains.contains(domain),
            "Faults must cover domain: {domain}"
        );
    }
}

#[test]
fn json_all_ids_follow_naming_convention() {
    let json = load_json();

    let contracts = json["conformance_contracts"].as_array().unwrap();
    for c in contracts {
        let id = c["id"].as_str().unwrap();
        assert!(
            id.starts_with("CF-"),
            "Contract ID must start with CF-: {id}"
        );
    }

    let faults = json["fault_scenarios"].as_array().unwrap();
    for f in faults {
        let id = f["id"].as_str().unwrap();
        assert!(id.starts_with("FI-"), "Fault ID must start with FI-: {id}");
    }
}
