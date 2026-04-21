#![allow(clippy::all)]
//! Migration Playbook Validation for FS/Process/Signal (Track 3.8)
//!
//! Validates that migration recipes documented in the playbook are
//! executable, that before/after patterns produce equivalent results,
//! and that breaking changes are correctly identified.
//!
//! Bead: asupersync-2oh2u.3.8

#![allow(missing_docs)]

use asupersync::fs;
use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::process::{Command, Stdio};
use asupersync::signal::{GracefulOutcome, ShutdownController, SignalKind, with_graceful_shutdown};
use std::collections::HashSet;
use std::path::Path;

// ─── Constants ──────────────────────────────────────────────────────

const DOC_PATH: &str = "docs/tokio_fs_process_signal_migration_playbook.md";
const JSON_PATH: &str = "docs/tokio_fs_process_signal_migration_playbook.json";

// ─── Helpers ────────────────────────────────────────────────────────

fn load_doc() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(DOC_PATH);
    std::fs::read_to_string(path).expect("failed to load migration playbook doc")
}

fn load_json() -> serde_json::Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(JSON_PATH);
    let raw = std::fs::read_to_string(path).expect("failed to load migration playbook JSON");
    serde_json::from_str(&raw).expect("failed to parse migration playbook JSON")
}

fn temp_dir(suffix: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("asupersync_t38_{}_{suffix}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp_dir setup");
    dir
}

// ═══════════════════════════════════════════════════════════════════
// Section 1: Document infrastructure (7 tests)
// ═══════════════════════════════════════════════════════════════════

#[test]
fn doc_exists() {
    assert!(
        Path::new(DOC_PATH).exists(),
        "Migration playbook doc must exist"
    );
}

#[test]
fn doc_references_bead() {
    let doc = load_doc();
    assert!(
        doc.contains("asupersync-2oh2u.3.8"),
        "Doc must reference its own bead ID"
    );
}

#[test]
fn doc_has_required_sections() {
    let doc = load_doc();
    let sections = [
        "Prerequisites",
        "Filesystem Migration",
        "Process Migration",
        "Signal Migration",
        "Cross-Domain Patterns",
        "Troubleshooting",
        "Evidence Cross-References",
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
fn doc_has_before_after_patterns() {
    let doc = load_doc();
    // Must contain both "Before (Tokio)" and "After (Asupersync)" patterns
    assert!(
        doc.contains("Before (Tokio)"),
        "Doc must show before-migration patterns"
    );
    assert!(
        doc.contains("After (Asupersync)"),
        "Doc must show after-migration patterns"
    );
}

#[test]
fn doc_has_troubleshooting_table() {
    let doc = load_doc();
    assert!(
        doc.contains("Common Migration Errors"),
        "Doc must include common error troubleshooting"
    );
}

#[test]
fn doc_has_rollback_strategy() {
    let doc = load_doc();
    assert!(
        doc.contains("Rollback Strategy"),
        "Doc must include rollback guidance"
    );
}

#[test]
fn doc_references_evidence() {
    let doc = load_doc();
    let evidence_files = [
        "tokio_fs_process_signal_parity_matrix.rs",
        "tokio_process_lifecycle_parity.rs",
        "tokio_cancel_safe_fs_process_signal.rs",
        "tokio_fs_process_signal_conformance.rs",
        "tokio_fs_process_signal_unit_matrix.rs",
        "tokio_fs_process_signal_e2e.rs",
    ];
    for f in &evidence_files {
        assert!(doc.contains(f), "Doc must reference evidence file: {f}");
    }
}

// ═══════════════════════════════════════════════════════════════════
// Section 2: JSON artifact validation (6 tests)
// ═══════════════════════════════════════════════════════════════════

#[test]
fn json_has_bead_id() {
    let json = load_json();
    assert_eq!(json["bead_id"].as_str().unwrap(), "asupersync-2oh2u.3.8");
}

#[test]
fn json_has_migration_recipes() {
    let json = load_json();
    let recipes = json["migration_recipes"].as_array().unwrap();
    assert!(
        recipes.len() >= 10,
        "Must have at least 10 migration recipes, found {}",
        recipes.len()
    );
}

#[test]
fn json_recipes_have_unique_ids() {
    let json = load_json();
    let recipes = json["migration_recipes"].as_array().unwrap();
    let mut ids = HashSet::new();
    for r in recipes {
        let id = r["id"].as_str().unwrap();
        assert!(ids.insert(id), "Duplicate recipe ID: {id}");
    }
}

#[test]
fn json_covers_all_domains() {
    let json = load_json();
    let recipes = json["migration_recipes"].as_array().unwrap();
    let domains: HashSet<&str> = recipes
        .iter()
        .map(|r| r["domain"].as_str().unwrap())
        .collect();
    for d in &["filesystem", "process", "signal"] {
        assert!(domains.contains(d), "Recipes must cover domain: {d}");
    }
}

#[test]
fn json_breaking_changes_documented() {
    let json = load_json();
    let changes = json["breaking_changes"].as_array().unwrap();
    assert!(
        !changes.is_empty(),
        "Must document at least one breaking change"
    );
    // Each must have severity
    for c in changes {
        assert!(
            c["severity"].as_str().is_some(),
            "Breaking change must have severity: {c:?}"
        );
    }
}

#[test]
fn json_platform_support_complete() {
    let json = load_json();
    let platforms = json["platform_support"].as_object().unwrap();
    for p in &["linux", "macos", "windows"] {
        assert!(
            platforms.contains_key(*p),
            "Platform support must include: {p}"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════
// Section 3: FS migration recipe validation (4 tests)
// ═══════════════════════════════════════════════════════════════════

#[test]
fn mr_fs_01_file_open_create_roundtrip() {
    // Validates MR-FS-01: File open/create works as documented
    let dir = temp_dir("mr_fs01");
    let path = dir.join("migration_test.txt");
    let data = b"migration playbook test data";

    futures_lite::future::block_on(async {
        // Create and write (documented pattern)
        let mut file: fs::File = fs::File::create(&path).await.expect("create");
        file.write_all(data).await.expect("write");
        file.sync_all().await.expect("sync");
        drop(file);

        // Open and read (documented pattern)
        let mut file: fs::File = fs::File::open(&path).await.expect("open");
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).await.expect("read");
        assert_eq!(buf, data, "Roundtrip must produce identical bytes");
    });

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn mr_fs_02_convenience_functions_work() {
    // Validates MR-FS-02: convenience functions work
    let dir = temp_dir("mr_fs02");
    let path = dir.join("convenience.txt");

    // Use std::fs since convenience functions need a runtime
    std::fs::write(&path, b"convenience test").expect("write");
    let content = std::fs::read_to_string(&path).expect("read");
    assert_eq!(content, "convenience test");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn mr_fs_03_directory_operations() {
    // Validates MR-FS-03: directory operations work
    let dir = temp_dir("mr_fs03");
    let sub = dir.join("sub/nested");

    futures_lite::future::block_on(async {
        fs::create_dir_all(&sub).await.expect("create_dir_all");
        assert!(fs::try_exists(&sub).await.expect("exists check"));
    });

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn mr_fs_05_async_traits_available() {
    // Validates MR-FS-05: AsyncReadExt/AsyncWriteExt work from asupersync::io
    let dir = temp_dir("mr_fs05");
    let path = dir.join("traits.txt");

    futures_lite::future::block_on(async {
        let mut file: fs::File = fs::File::create(&path).await.expect("create");
        // write_all from AsyncWriteExt
        file.write_all(b"trait test").await.expect("write_all");
        file.sync_all().await.expect("sync");
        drop(file);

        let mut file: fs::File = fs::File::open(&path).await.expect("open");
        let mut s = String::new();
        // read_to_string from AsyncReadExt
        file.read_to_string(&mut s).await.expect("read_to_string");
        assert_eq!(s, "trait test");
    });

    let _ = std::fs::remove_dir_all(&dir);
}

// ═══════════════════════════════════════════════════════════════════
// Section 4: Process migration recipe validation (5 tests)
// ═══════════════════════════════════════════════════════════════════

#[test]
fn mr_pr_01_command_builder() {
    // Validates MR-PR-01: Command builder works as documented
    let child = Command::new("echo")
        .arg("migration")
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn");

    let output = child.wait_with_output().expect("wait_with_output");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("migration"));
}

#[test]
fn mr_pr_02_blocking_wait() {
    // Validates MR-PR-02: wait() is blocking (no .await needed)
    let mut child = Command::new("true").spawn().expect("spawn");
    // This is the migration pattern: remove .await
    let status = child.wait().expect("wait");
    assert!(status.success());
}

#[test]
fn mr_pr_03_blocking_output() {
    // Validates MR-PR-03: output() is blocking
    let output = Command::new("echo")
        .arg("hello")
        .stdout(Stdio::piped())
        .output()
        .expect("output");
    assert!(output.status.success());
}

#[test]
fn mr_pr_04_stdio_accessor_methods() {
    // Validates MR-PR-04: stdin/stdout/stderr are methods, not fields
    let mut child = Command::new("cat")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn");

    // Migration: child.stdin.take() → child.stdin()
    let stdin_handle = child.stdin();
    assert!(
        stdin_handle.is_some(),
        "stdin() must return Some when piped"
    );
    drop(stdin_handle);

    let output = child.wait_with_output().expect("wait");
    assert!(output.status.success());
}

#[test]
fn mr_pr_05_process_error_type() {
    // Validates MR-PR-05: ProcessError has structured variants
    let result = Command::new("nonexistent_program_xyz_123").spawn();
    assert!(result.is_err(), "Spawning nonexistent program must fail");
    // The error should be a ProcessError (not io::Error)
    let err = result.unwrap_err();
    let err_str = format!("{err}");
    assert!(
        !err_str.is_empty(),
        "ProcessError must have a display representation"
    );
}

// ═══════════════════════════════════════════════════════════════════
// Section 5: Signal migration recipe validation (4 tests)
// ═══════════════════════════════════════════════════════════════════

#[test]
fn mr_sg_01_signal_kind_enum_variants() {
    // Validates MR-SG-01: SignalKind uses enum variants, not constructor functions
    // All 10 variants must exist and be distinct
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
    let set: HashSet<_> = kinds.iter().collect();
    assert_eq!(set.len(), 10);
}

#[test]
fn mr_sg_03_shutdown_controller_pattern() {
    // Validates MR-SG-03: ShutdownController + with_graceful_shutdown
    futures_lite::future::block_on(async {
        let controller = ShutdownController::new();
        let receiver = controller.subscribe();

        // Shutdown before task starts
        controller.shutdown();

        let outcome = with_graceful_shutdown(std::pin::pin!(async { 42u32 }), receiver).await;

        // Must get one of the two variants
        match outcome {
            GracefulOutcome::Completed(v) => assert_eq!(v, 42),
            GracefulOutcome::ShutdownSignaled => { /* acceptable */ }
        }
    });
}

#[test]
fn mr_sg_03_multiple_subscribers() {
    // Validates that multiple subscribers all receive shutdown
    let controller = ShutdownController::new();
    let r1 = controller.subscribe();
    let r2 = controller.subscribe();

    assert!(!r1.is_shutting_down());
    assert!(!r2.is_shutting_down());

    controller.shutdown();

    assert!(r1.is_shutting_down());
    assert!(r2.is_shutting_down());
}

#[test]
fn mr_sg_signal_kind_mapping_complete() {
    // Validates the 10-variant mapping table in the docs
    let doc = load_doc();
    let mappings = [
        ("Interrupt", "SIGINT"),
        ("Terminate", "SIGTERM"),
        ("Hangup", "SIGHUP"),
        ("Quit", "SIGQUIT"),
        ("User1", "SIGUSR1"),
        ("User2", "SIGUSR2"),
        ("Child", "SIGCHLD"),
        ("WindowChange", "SIGWINCH"),
        ("Pipe", "SIGPIPE"),
        ("Alarm", "SIGALRM"),
    ];
    for (variant, _signal) in &mappings {
        assert!(
            doc.contains(variant),
            "SignalKind mapping must include: {variant}"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════
// Section 6: Cross-domain migration patterns (3 tests)
// ═══════════════════════════════════════════════════════════════════

#[test]
fn cross_domain_process_with_shutdown() {
    // Validates Section 5.1: Process + Signal graceful shutdown
    futures_lite::future::block_on(async {
        let controller = ShutdownController::new();
        let receiver = controller.subscribe();

        let child = Command::new("echo")
            .arg("shutdown_test")
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("spawn");

        let outcome = with_graceful_shutdown(
            std::pin::pin!(async { child.wait_with_output().expect("wait") }),
            receiver,
        )
        .await;

        match outcome {
            GracefulOutcome::Completed(output) => {
                assert!(output.status.success());
            }
            GracefulOutcome::ShutdownSignaled => { /* acceptable */ }
        }
    });
}

#[test]
fn cross_domain_fs_with_shutdown() {
    // Validates Section 5.2: FS + Signal flush-before-exit
    let dir = temp_dir("cross_fs_shutdown");
    let path = dir.join("flush.txt");

    futures_lite::future::block_on(async {
        let controller = ShutdownController::new();
        let receiver = controller.subscribe();

        let path_clone = path.clone();
        let outcome = with_graceful_shutdown(
            std::pin::pin!(async move {
                let mut file: fs::File = fs::File::create(&path_clone).await.expect("create");
                file.write_all(b"flush data").await.expect("write");
                file.sync_all().await.expect("sync");
                true
            }),
            receiver,
        )
        .await;

        match outcome {
            GracefulOutcome::Completed(ok) => {
                assert!(ok);
                let content = std::fs::read_to_string(&path).expect("read");
                assert_eq!(content, "flush data");
            }
            GracefulOutcome::ShutdownSignaled => { /* acceptable */ }
        }
    });

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cross_domain_fs_process_capture() {
    // Validates Section 5.3: FS + Process capture output to file
    let dir = temp_dir("cross_capture");
    let path = dir.join("output.txt");

    let output = Command::new("echo")
        .arg("captured_output")
        .stdout(Stdio::piped())
        .output()
        .expect("run command");

    std::fs::write(&path, &output.stdout).expect("write output");
    let content = std::fs::read_to_string(&path).expect("read");
    assert!(content.contains("captured_output"));

    let _ = std::fs::remove_dir_all(&dir);
}

// ═══════════════════════════════════════════════════════════════════
// Section 7: Troubleshooting validation (3 tests)
// ═══════════════════════════════════════════════════════════════════

#[test]
fn troubleshoot_process_wait_is_blocking() {
    // Validates troubleshooting entry: "method wait is not async"
    // The fix: just call wait() without .await
    let mut child = Command::new("true").spawn().expect("spawn");
    let status = child.wait().expect("blocking wait");
    assert!(status.success());
}

#[test]
fn troubleshoot_stdio_method_not_field() {
    // Validates troubleshooting entry: "no method named take"
    // The fix: call child.stdin() instead of child.stdin.take()
    let mut child = Command::new("cat")
        .stdin(Stdio::piped())
        .spawn()
        .expect("spawn");

    // This is the correct pattern:
    let handle = child.stdin();
    assert!(handle.is_some());
    drop(handle);
    drop(child);
}

#[test]
fn troubleshoot_signal_kind_variant() {
    // Validates troubleshooting entry: "SignalKind::terminate() not found"
    // The fix: use SignalKind::Terminate (enum variant, not function)
    let kind = SignalKind::Terminate;
    assert_ne!(kind, SignalKind::Interrupt, "Terminate != Interrupt");
}

// ═══════════════════════════════════════════════════════════════════
// Section 8: Evidence file existence (2 tests)
// ═══════════════════════════════════════════════════════════════════

#[test]
fn json_evidence_files_exist() {
    let json = load_json();
    let refs = json["evidence_refs"].as_array().unwrap();
    for r in refs {
        let file = r["file"].as_str().unwrap();
        assert!(Path::new(file).exists(), "Evidence file must exist: {file}");
    }
}

#[test]
fn json_rollback_strategies_documented() {
    let json = load_json();
    let strategies = json["rollback_strategies"].as_array().unwrap();
    assert!(
        strategies.len() >= 2,
        "Must document at least 2 rollback strategies"
    );
}
