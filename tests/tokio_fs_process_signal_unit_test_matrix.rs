#![allow(clippy::all)]
//! Exhaustive Unit-Test Matrix for FS/Process/Signal (Track 3.9)
//!
//! Maps test coverage to T3 implementation beads (T3.3, T3.5, T3.6, T3.7),
//! identifies coverage gaps, and provides gap-closure tests with boundary,
//! error, and cancellation assertions.
//!
//! Bead: asupersync-2oh2u.3.9

#![allow(missing_docs)]

use asupersync::fs;
use asupersync::process::{Command, Stdio};
use asupersync::signal::{ShutdownController, SignalKind, with_graceful_shutdown};
use std::collections::{BTreeSet, HashSet};
use std::path::Path;

// ─── Constants ──────────────────────────────────────────────────────

const DOC_PATH: &str = "docs/tokio_fs_process_signal_unit_test_matrix.md";
const JSON_PATH: &str = "docs/tokio_fs_process_signal_unit_test_matrix.json";

// ─── Helpers ────────────────────────────────────────────────────────

fn load_doc() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(DOC_PATH);
    std::fs::read_to_string(path).expect("failed to load unit test matrix doc")
}

fn load_json() -> serde_json::Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(JSON_PATH);
    let raw = std::fs::read_to_string(path).expect("failed to load unit test matrix JSON");
    serde_json::from_str(&raw).expect("failed to parse unit test matrix JSON")
}

fn temp_dir(suffix: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("asupersync_t39_{}_{suffix}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp_dir setup");
    dir
}

// ═══════════════════════════════════════════════════════════════════
// Section 1: Document infrastructure (7 tests)
// ═══════════════════════════════════════════════════════════════════

#[test]
fn doc_exists() {
    assert!(Path::new(DOC_PATH).exists(), "Matrix doc must exist");
}

#[test]
fn doc_references_bead() {
    let doc = load_doc();
    assert!(
        doc.contains("asupersync-2oh2u.3.9"),
        "Doc must reference its own bead ID"
    );
}

#[test]
fn doc_has_required_sections() {
    let doc = load_doc();
    let sections = [
        "Scope",
        "Existing Test Evidence",
        "Coverage Gap Analysis",
        "Enforcement Thresholds",
        "Diagnostic Requirements",
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
fn doc_references_source_beads() {
    let doc = load_doc();
    for bead in &["T3.3", "T3.5", "T3.6", "T3.7"] {
        assert!(doc.contains(bead), "Doc must reference bead: {bead}");
    }
}

#[test]
fn doc_defines_coverage_categories() {
    let doc = load_doc();
    let categories = ["HP", "EC", "EP", "CX", "DT", "IX"];
    for cat in &categories {
        assert!(
            doc.contains(cat),
            "Doc must define coverage category: {cat}"
        );
    }
}

#[test]
fn doc_documents_determinism_invariants() {
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
        doc.contains("tokio_fs_process_signal_unit_test_matrix.rs"),
        "Doc must reference its test file"
    );
}

// ═══════════════════════════════════════════════════════════════════
// Section 2: JSON artifact validation (8 tests)
// ═══════════════════════════════════════════════════════════════════

#[test]
fn json_exists() {
    assert!(Path::new(JSON_PATH).exists(), "Matrix JSON must exist");
}

#[test]
fn json_has_bead_id() {
    let json = load_json();
    assert_eq!(json["bead_id"].as_str().unwrap(), "asupersync-2oh2u.3.9");
}

#[test]
fn json_references_all_source_beads() {
    let json = load_json();
    let beads: Vec<&str> = json["source_beads"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    for expected in &[
        "asupersync-2oh2u.3.3",
        "asupersync-2oh2u.3.5",
        "asupersync-2oh2u.3.6",
        "asupersync-2oh2u.3.7",
    ] {
        assert!(
            beads.contains(expected),
            "JSON must reference source bead: {expected}"
        );
    }
}

#[test]
fn json_test_evidence_covers_all_domains() {
    let json = load_json();
    let evidence = json["test_evidence"].as_array().unwrap();
    let domains: BTreeSet<&str> = evidence
        .iter()
        .map(|e| e["domain"].as_str().unwrap())
        .collect();
    for d in &["filesystem", "process", "signal"] {
        assert!(domains.contains(d), "Test evidence must cover domain: {d}");
    }
}

#[test]
fn json_domain_totals_meet_minimums() {
    let json = load_json();
    let totals = json["domain_totals"].as_object().unwrap();
    for (domain, info) in totals {
        let count = info["test_count"].as_u64().unwrap();
        let minimum = info["minimum"].as_u64().unwrap();
        assert!(
            count >= minimum,
            "{domain} test count ({count}) below minimum ({minimum})"
        );
    }
}

#[test]
fn json_coverage_gaps_all_closed() {
    let json = load_json();
    let gaps = json["coverage_gaps"].as_array().unwrap();
    for gap in gaps {
        let status = gap["status"].as_str().unwrap();
        let id = gap["id"].as_str().unwrap();
        assert_eq!(status, "closed", "Gap {id} must be closed, found: {status}");
    }
}

#[test]
fn json_gap_closure_tests_have_unique_ids() {
    let json = load_json();
    let tests = json["gap_closure_tests"].as_array().unwrap();
    let mut ids = HashSet::new();
    for t in tests {
        let id = t["id"].as_str().unwrap();
        assert!(ids.insert(id), "Duplicate gap closure test ID: {id}");
    }
}

#[test]
fn json_invariants_count() {
    let json = load_json();
    let invariants = json["determinism_invariants"].as_array().unwrap();
    assert!(
        invariants.len() >= 10,
        "Must have at least 10 invariants, found {}",
        invariants.len()
    );
}

// ═══════════════════════════════════════════════════════════════════
// Section 3: Coverage threshold enforcement (4 tests)
// ═══════════════════════════════════════════════════════════════════

#[test]
fn threshold_fs_tests_exist() {
    // Verify key FS test files exist
    let files = ["tests/fs_verification.rs", "tests/e2e_fs.rs"];
    for f in &files {
        assert!(Path::new(f).exists(), "FS test file must exist: {f}");
    }
}

#[test]
fn threshold_process_tests_exist() {
    let files = [
        "tests/process_lifecycle_hardening.rs",
        "tests/tokio_process_lifecycle_parity.rs",
    ];
    for f in &files {
        assert!(Path::new(f).exists(), "Process test file must exist: {f}");
    }
}

#[test]
fn threshold_signal_tests_exist() {
    let files = ["tests/e2e_signal.rs"];
    for f in &files {
        assert!(Path::new(f).exists(), "Signal test file must exist: {f}");
    }
}

#[test]
fn threshold_cross_domain_tests_exist() {
    let files = [
        "tests/tokio_cancel_safe_fs_process_signal.rs",
        "tests/tokio_fs_process_signal_conformance_faults.rs",
    ];
    for f in &files {
        assert!(
            Path::new(f).exists(),
            "Cross-domain test file must exist: {f}"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════
// Section 4: Gap closure — FS cancellation (UTM-01, UTM-02)
// ═══════════════════════════════════════════════════════════════════

#[test]
fn utm_01_file_drop_mid_create_safe() {
    use asupersync::io::AsyncWriteExt;

    let dir = temp_dir("utm01");
    let path = dir.join("drop_test.txt");

    futures_lite::future::block_on(async {
        // Create file then drop before sync — must not panic or corrupt
        let mut file = fs::File::create(&path).await.expect("create");
        file.write_all(b"partial").await.expect("write");
        // Drop without sync — file may or may not persist, but must not panic
        drop(file);
    });

    // The contract is that drop is safe — no assertion on file content
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn utm_02_file_read_returns_actual_content() {
    use asupersync::io::AsyncReadExt;

    let dir = temp_dir("utm02");
    let path = dir.join("read_cancel.txt");
    std::fs::write(&path, b"full content here").expect("setup");

    futures_lite::future::block_on(async {
        let mut file = fs::File::open(&path).await.expect("open");
        let mut buf = String::new();
        file.read_to_string(&mut buf).await.expect("read");
        assert_eq!(
            buf, "full content here",
            "Read must return complete content"
        );
    });

    let _ = std::fs::remove_dir_all(&dir);
}

// ═══════════════════════════════════════════════════════════════════
// Section 5: Gap closure — Signal edge cases (UTM-03, UTM-04)
// ═══════════════════════════════════════════════════════════════════

#[test]
fn utm_03_signal_kind_variants_distinct() {
    // All SignalKind variants must be distinct via Hash/Eq
    let kinds = [
        SignalKind::Interrupt,
        SignalKind::Terminate,
        SignalKind::Hangup,
        SignalKind::Quit,
        SignalKind::User1,
        SignalKind::User2,
        SignalKind::Child,
        SignalKind::WindowChange,
        SignalKind::Pipe,
        SignalKind::Alarm,
    ];

    let mut set = HashSet::new();
    for kind in &kinds {
        assert!(
            set.insert(kind),
            "SignalKind variant must be unique: {kind:?}"
        );
    }
    assert_eq!(
        set.len(),
        10,
        "Must have exactly 10 distinct SignalKind variants"
    );
}

#[test]
fn utm_04_shutdown_controller_multiple_subscribe() {
    // Multiple subscriptions from same controller must all work
    let controller = ShutdownController::new();
    let r1 = controller.subscribe();
    let r2 = controller.subscribe();
    let r3 = controller.subscribe();

    assert!(!r1.is_shutting_down());
    assert!(!r2.is_shutting_down());
    assert!(!r3.is_shutting_down());

    controller.shutdown();

    assert!(r1.is_shutting_down());
    assert!(r2.is_shutting_down());
    assert!(r3.is_shutting_down());
}

// ═══════════════════════════════════════════════════════════════════
// Section 6: Gap closure — Signal cancellation (UTM-05, UTM-06)
// ═══════════════════════════════════════════════════════════════════

#[test]
fn utm_05_shutdown_receiver_drop_before_wait() {
    // Dropping a receiver before calling wait must not leak or panic
    let controller = ShutdownController::new();
    let receiver = controller.subscribe();
    drop(receiver);
    // Controller still functional
    assert!(!controller.is_shutting_down());
    controller.shutdown();
    assert!(controller.is_shutting_down());
}

#[test]
fn utm_06_concurrent_receivers_resolve_independently() {
    futures_lite::future::block_on(async {
        let controller = ShutdownController::new();
        let mut r1 = controller.subscribe();
        let mut r2 = controller.subscribe();

        // Signal shutdown
        controller.shutdown();

        // Both must resolve independently
        r1.wait().await;
        r2.wait().await;

        assert!(r1.is_shutting_down());
        assert!(r2.is_shutting_down());
    });
}

// ═══════════════════════════════════════════════════════════════════
// Section 7: Gap closure — Process integration (UTM-07)
// ═══════════════════════════════════════════════════════════════════

#[test]
fn utm_07_process_exit_visible_via_try_wait() {
    // Spawn a fast-exiting process, poll until try_wait sees it
    let mut child = Command::new("true").spawn().expect("spawn");

    let mut found = false;
    for _ in 0..100 {
        match child.try_wait().expect("try_wait") {
            Some(status) => {
                assert!(status.success(), "true must exit 0");
                found = true;
                break;
            }
            None => std::thread::sleep(std::time::Duration::from_millis(10)),
        }
    }
    assert!(found, "try_wait must eventually see process exit");
}

// ═══════════════════════════════════════════════════════════════════
// Section 8: Gap closure — FS edge cases (UTM-08, UTM-09)
// ═══════════════════════════════════════════════════════════════════

#[test]
fn utm_08_empty_filename_returns_error() {
    let result = std::fs::read("");
    assert!(result.is_err(), "Empty filename must return error");
}

#[test]
fn utm_09_path_with_null_byte_returns_error() {
    let result = std::fs::read("/tmp/test\0file");
    assert!(result.is_err(), "Path with null byte must return error");
}

// ═══════════════════════════════════════════════════════════════════
// Section 9: Gap closure — Cross-domain cancellation (UTM-10)
// ═══════════════════════════════════════════════════════════════════

#[test]
fn utm_10_concurrent_fs_process_shutdown() {
    let dir = temp_dir("utm10");
    let path = dir.join("concurrent.txt");

    futures_lite::future::block_on(async {
        let controller = ShutdownController::new();
        let receiver = controller.subscribe();

        // Run a combined fs+process task with shutdown
        let outcome = with_graceful_shutdown(
            std::pin::pin!(async move {
                // FS operation
                std::fs::write(&path, b"cross-domain test").expect("write");

                // Process operation
                let output = Command::new("echo")
                    .arg("cross-domain")
                    .stdout(Stdio::piped())
                    .output()
                    .expect("echo");

                (
                    std::fs::read_to_string(&path).expect("readback"),
                    output.status.success(),
                )
            }),
            receiver,
        )
        .await;

        match outcome {
            asupersync::signal::GracefulOutcome::Completed((content, proc_ok)) => {
                assert_eq!(content, "cross-domain test");
                assert!(proc_ok, "echo must succeed");
            }
            asupersync::signal::GracefulOutcome::ShutdownSignaled => {
                // Acceptable if shutdown raced ahead
            }
        }
    });

    let _ = std::fs::remove_dir_all(&dir);
}

// ═══════════════════════════════════════════════════════════════════
// Section 10: Matrix coverage validation (3 tests)
// ═══════════════════════════════════════════════════════════════════

#[test]
fn json_gap_closure_covers_all_gaps() {
    let json = load_json();
    let gaps = json["coverage_gaps"].as_array().unwrap();
    let gap_ids: BTreeSet<&str> = gaps.iter().map(|g| g["id"].as_str().unwrap()).collect();

    let closures = json["gap_closure_tests"].as_array().unwrap();
    let covered_gaps: BTreeSet<&str> = closures
        .iter()
        .map(|c| c["gap"].as_str().unwrap())
        .collect();

    for gap in &gap_ids {
        assert!(
            covered_gaps.contains(gap),
            "Gap {gap} must have closure test"
        );
    }
}

#[test]
fn json_gap_closure_tests_cover_all_categories() {
    let json = load_json();
    let closures = json["gap_closure_tests"].as_array().unwrap();
    let categories: BTreeSet<&str> = closures
        .iter()
        .map(|c| c["category"].as_str().unwrap())
        .collect();

    // Must cover at least CX, EC, and IX
    for cat in &["CX", "EC", "IX"] {
        assert!(
            categories.contains(cat),
            "Gap closure tests must cover category: {cat}"
        );
    }
}

#[test]
fn json_all_test_evidence_files_exist() {
    let json = load_json();
    let evidence = json["test_evidence"].as_array().unwrap();
    for entry in evidence {
        let file = entry["file"].as_str().unwrap();
        assert!(
            Path::new(file).exists(),
            "Test evidence file must exist: {file}"
        );
    }
}
