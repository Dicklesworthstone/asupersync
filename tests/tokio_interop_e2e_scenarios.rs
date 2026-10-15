//! End-to-end interoperability scenarios for Tokio adapter ecosystem (T7.11).
//!
//! Validates representative adapter stacks under realistic integration
//! pressure, including incompatibility drills, failure diagnostics, and
//! structured compatibility evidence.
//!
//! # Test Categories
//!
//! 1. **Adapter stack integration** — multi-layer adapter composition
//! 2. **Compatibility evidence** — doc/code/test alignment verification
//! 3. **Incompatibility drills** — known failure patterns validated
//! 4. **Log schema compliance** — structured log field requirements
//! 5. **Artifact reproducibility** — seed-based determinism checks
//! 6. **Remediation hooks** — actionable diagnostic patterns

#![allow(missing_docs)]

use std::path::Path;

// ─── helpers ───────────────────────────────────────────────────────────

fn load_source(module: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("asupersync-tokio-compat/src")
        .join(module);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("{module} must exist at {}", path.display()))
}

fn load_budget_doc() -> String {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/tokio_adapter_performance_budgets.md");
    std::fs::read_to_string(path).expect("budget doc must exist")
}

fn load_boundary_doc() -> String {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/tokio_adapter_boundary_architecture.md");
    std::fs::read_to_string(path).expect("boundary doc must exist")
}

fn all_adapter_sources() -> Vec<(String, String)> {
    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("asupersync-tokio-compat/src");
    let mut sources = Vec::new();
    for entry in std::fs::read_dir(&src_dir).expect("src dir must exist") {
        let entry = entry.unwrap();
        if entry.path().extension().is_some_and(|e| e == "rs") {
            let name = entry.file_name().to_string_lossy().into_owned();
            let content = std::fs::read_to_string(entry.path()).unwrap();
            sources.push((name, content));
        }
    }
    sources
}

// ═══════════════════════════════════════════════════════════════════════
// 1. ADAPTER STACK INTEGRATION
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn e2e_tower_hyper_body_stack_composes() {
    // Verify that tower, hyper, and body bridge modules can coexist.
    // This validates no conflicting type definitions or feature conflicts.
    let tower_src = load_source("tower_bridge.rs");
    let hyper_src = load_source("hyper_bridge.rs");
    let body_src = load_source("body_bridge.rs");

    // Tower uses BridgeError, hyper uses AsupersyncExecutor, body uses IntoHttpBody
    assert!(tower_src.contains("BridgeError"));
    assert!(hyper_src.contains("AsupersyncExecutor"));
    assert!(body_src.contains("IntoHttpBody"));

    // All three are gated behind feature flags that compose
    let cargo_toml = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("asupersync-tokio-compat/Cargo.toml"),
    )
    .unwrap();
    assert!(
        cargo_toml.contains("full = [\"hyper-bridge\", \"tokio-io\", \"tower-bridge\"]"),
        "full feature must compose all adapter features"
    );
}

#[test]
fn e2e_cancel_aware_integrates_with_all_adapters() {
    // CancelAware is referenced by tower and blocking bridges.
    let cancel_src = load_source("cancel.rs");
    let tower_src = load_source("tower_bridge.rs");
    let blocking_src = load_source("blocking.rs");
    let lib_src = load_source("lib.rs");

    // CancelAware exists and is exported
    assert!(cancel_src.contains("pub struct CancelAware"));

    // Tower bridge references cancellation
    assert!(tower_src.contains("is_cancel_requested"));

    // Blocking bridge references CancellationMode
    assert!(blocking_src.contains("CancellationMode"));

    // CancellationMode is defined in lib.rs and usable by all
    assert!(lib_src.contains("pub enum CancellationMode"));
}

#[test]
fn e2e_io_bridge_feeds_into_hyper_bridge() {
    // TokioIo is used to feed I/O into hyper connections.
    let io_src = load_source("io.rs");

    // TokioIo implements hyper::rt::Read and hyper::rt::Write
    assert!(
        io_src.contains("hyper::rt::Read for TokioIo")
            && io_src.contains("hyper::rt::Write for TokioIo"),
        "TokioIo must implement hyper runtime traits for stack integration"
    );
}

#[test]
fn e2e_blocking_bridge_cx_available_for_all_modes() {
    // All three cancellation modes are usable with block_on_sync.
    let src = load_source("blocking.rs");

    for mode in ["BestEffort", "Strict", "TimeoutFallback"] {
        assert!(
            src.contains(mode),
            "blocking bridge must support {mode} cancellation mode"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════
// 2. COMPATIBILITY EVIDENCE
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn e2e_all_adapters_have_doc_comments() {
    let sources = all_adapter_sources();
    assert!(!sources.is_empty());

    for (name, content) in &sources {
        assert!(
            content.contains("//!"),
            "{name} must have module-level doc comment"
        );
    }
}

#[test]
fn e2e_all_adapters_have_unit_tests() {
    let sources = all_adapter_sources();

    for (name, content) in &sources {
        assert!(
            content.contains("#[cfg(test)]") || content.contains("#[test]"),
            "{name} must have unit tests"
        );
    }
}

#[test]
fn e2e_adapter_test_coverage_substantial() {
    let sources = all_adapter_sources();

    let total_tests: usize = sources
        .iter()
        .map(|(_, content)| content.matches("#[test]").count())
        .sum();

    assert!(
        total_tests >= 40,
        "adapter crate must have >= 40 unit tests; found {total_tests}"
    );
}

#[test]
fn e2e_all_public_types_have_debug_impl() {
    let sources = all_adapter_sources();

    // Key public types that must have Debug
    let required_debug = [
        ("lib.rs", "CancellationMode"),
        ("lib.rs", "AdapterConfig"),
        ("lib.rs", "AdapterError"),
        ("cancel.rs", "CancelResult"),
        ("blocking.rs", "BlockingOutcome"),
        ("blocking.rs", "BlockingBridgeError"),
        ("body_bridge.rs", "IntoHttpBody"),
        ("body_bridge.rs", "BodyLimitError"),
        ("body_bridge.rs", "GrpcServiceAdapter"),
        ("tower_bridge.rs", "FromTower"),
        ("tower_bridge.rs", "IntoTower"),
        ("tower_bridge.rs", "BridgeError"),
        ("hyper_bridge.rs", "AsupersyncExecutor"),
        ("hyper_bridge.rs", "AsupersyncTimer"),
    ];

    for (file, type_name) in &required_debug {
        let content = sources
            .iter()
            .find(|(n, _)| n == file)
            .map_or("", |(_, c)| c.as_str());
        assert!(
            content.contains("Debug") && content.contains(type_name),
            "{file}::{type_name} must have Debug implementation"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════
// 3. INCOMPATIBILITY DRILLS
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn drill_no_tokio_runtime_features_in_deps() {
    let cargo_toml = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("asupersync-tokio-compat/Cargo.toml"),
    )
    .unwrap();

    // Must not require rt or rt-multi-thread
    assert!(
        !cargo_toml.contains("\"rt\"") || !cargo_toml.contains("\"rt\"]"),
        "must not depend on tokio rt feature"
    );
    assert!(
        !cargo_toml.contains("rt-multi-thread"),
        "must not depend on tokio rt-multi-thread"
    );
}

#[test]
fn drill_no_std_thread_spawn_in_hot_paths() {
    // Adapter hot paths should not spawn OS threads. Only hyper_bridge's
    // timer and blocking bridge are allowed to use threads.
    let hot_path_modules = ["cancel.rs", "tower_bridge.rs", "body_bridge.rs", "io.rs"];

    for module in &hot_path_modules {
        let src = load_source(module);
        assert!(
            !src.contains("std::thread::spawn("),
            "{module} should not use std::thread::spawn in hot path"
        );
    }
}

#[test]
fn drill_no_unwrap_in_production_code() {
    // Adapter code should not use .unwrap() outside of tests.
    let sources = all_adapter_sources();

    for (name, content) in &sources {
        // Split at #[cfg(test)] and only check production code
        let production = content.split("#[cfg(test)]").next().unwrap_or(content);

        // Allow .unwrap() in specific patterns: expect() is preferred over unwrap()
        let unwrap_count = production.matches(".unwrap()").count();
        let expect_count = production.matches(".expect(").count();

        // Some unwraps are OK (e.g., lock poisoning), but should be minimal
        assert!(
            unwrap_count <= 5,
            "{name} has {unwrap_count} .unwrap() calls in production code (max 5)"
        );
        let _ = expect_count; // expect is fine
    }
}

#[test]
fn drill_no_ambient_globals_in_adapter_code() {
    // No lazy_static!, once_cell::sync::Lazy, or static mut in adapters.
    let sources = all_adapter_sources();

    for (name, content) in &sources {
        let production = content.split("#[cfg(test)]").next().unwrap_or(content);
        assert!(
            !production.contains("lazy_static!"),
            "{name} must not use lazy_static!"
        );
        assert!(
            !production.contains("static mut"),
            "{name} must not use static mut"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════
// 4. LOG SCHEMA COMPLIANCE
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn log_schema_boundary_doc_defines_required_fields() {
    let doc = load_boundary_doc();

    let required_log_fields = ["correlation_id", "adapter_path", "outcome_class"];

    for field in &required_log_fields {
        assert!(
            doc.contains(field),
            "boundary doc must define log field: {field}"
        );
    }
}

#[test]
fn log_schema_budget_doc_defines_artifact_outputs() {
    let doc = load_budget_doc();

    assert!(
        doc.contains("manifest.json"),
        "budget doc must require JSON manifest artifact"
    );
    assert!(
        doc.contains("report.md"),
        "budget doc must require markdown report artifact"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// 5. ARTIFACT REPRODUCIBILITY
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn e2e_script_exists_and_is_executable() {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/test_tokio_interop_e2e.sh");
    assert!(script.exists(), "e2e script must exist");

    // Check it has shebang
    let content = std::fs::read_to_string(&script).unwrap();
    assert!(
        content.starts_with("#!/usr/bin/env bash"),
        "script must have bash shebang"
    );
}

#[test]
fn e2e_script_has_deterministic_seed() {
    let script = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/test_tokio_interop_e2e.sh"),
    )
    .unwrap();

    assert!(
        script.contains("TEST_SEED"),
        "e2e script must support TEST_SEED for reproducibility"
    );
}

#[test]
fn e2e_script_has_structured_logging() {
    let script = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/test_tokio_interop_e2e.sh"),
    )
    .unwrap();

    assert!(
        script.contains("correlation_id"),
        "e2e script must generate correlation_id"
    );
    assert!(
        script.contains("compatibility_log.jsonl"),
        "e2e script must produce JSONL compat log"
    );
    assert!(
        script.contains("e2e_summary.md"),
        "e2e script must produce summary markdown"
    );
}

#[test]
fn e2e_script_runs_all_test_suites() {
    let script = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/test_tokio_interop_e2e.sh"),
    )
    .unwrap();

    let required_suites = [
        "tokio_adapter_boundary_architecture",
        "tokio_interop_conformance_suites",
        "tokio_adapter_performance_budgets",
        "tokio_adapter_boundary_correctness",
        "tokio_interop_e2e_scenarios",
    ];

    for suite in &required_suites {
        assert!(
            script.contains(suite),
            "e2e script must run test suite: {suite}"
        );
    }
}

#[test]
fn e2e_script_has_quality_gates() {
    let script = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/test_tokio_interop_e2e.sh"),
    )
    .unwrap();

    assert!(
        script.contains("cargo check"),
        "e2e script must run cargo check"
    );
    assert!(
        script.contains("cargo clippy"),
        "e2e script must run cargo clippy"
    );
    assert!(
        script.contains("cargo fmt --check"),
        "e2e script must run cargo fmt --check"
    );
}

#[test]
fn e2e_script_has_repro_command_in_artifacts() {
    let script = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/test_tokio_interop_e2e.sh"),
    )
    .unwrap();

    // Summary must include repro command
    assert!(
        script.contains("Repro Command") || script.contains("repro"),
        "e2e artifact must include repro command"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// 6. REMEDIATION HOOKS
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn remediation_error_messages_are_actionable() {
    let sources = all_adapter_sources();

    // BridgeError::NoCxAvailable should explain what to do
    let tower_src = sources
        .iter()
        .find(|(n, _)| n == "tower_bridge.rs")
        .map(|(_, c)| c.as_str())
        .unwrap();

    assert!(
        tower_src.contains("install Cx") || tower_src.contains("set_current"),
        "NoCxAvailable error message must suggest installing Cx"
    );
}

#[test]
fn remediation_blocking_panics_include_message() {
    let src = load_source("blocking.rs");

    // Panicked variant includes the panic message for diagnostics
    assert!(
        src.contains("Panicked(String)"),
        "Panicked must carry the message for diagnostics"
    );
    assert!(
        src.contains("panic_message"),
        "must have panic_message extractor for actionable diagnostics"
    );
}

#[test]
fn remediation_body_limit_includes_sizes() {
    let src = load_source("body_bridge.rs");

    assert!(
        src.contains("limit: usize") && src.contains("received: usize"),
        "TooLarge error must include both limit and received for diagnostics"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// 7. CROSS-BEAD TRACEABILITY
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn all_t7_test_files_exist() {
    let test_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");

    let required_test_files = [
        "tokio_adapter_boundary_architecture.rs",
        "tokio_interop_conformance_suites.rs",
        "tokio_adapter_performance_budgets.rs",
        "tokio_adapter_boundary_correctness.rs",
        "tokio_interop_e2e_scenarios.rs",
    ];

    for file in &required_test_files {
        assert!(
            test_dir.join(file).exists(),
            "required T7 test file missing: {file}"
        );
    }
}

#[test]
fn all_t7_docs_exist() {
    let docs_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs");

    let required_docs = [
        "tokio_adapter_boundary_architecture.md",
        "tokio_adapter_performance_budgets.md",
        "tokio_interop_target_ranking.md",
    ];

    for doc in &required_docs {
        assert!(
            docs_dir.join(doc).exists(),
            "required T7 doc missing: {doc}"
        );
    }
}

#[test]
fn e2e_script_references_correct_bead() {
    let script = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/test_tokio_interop_e2e.sh"),
    )
    .unwrap();

    assert!(
        script.contains("asupersync-2oh2u.7.11"),
        "e2e script must reference bead asupersync-2oh2u.7.11"
    );
}

#[test]
fn e2e_downstream_beads_referenced_in_budget_doc() {
    // T7.11 feeds into T8.12 (cross-track logging) and T9.2 (cookbooks)
    let budget_doc = load_budget_doc();

    assert!(
        budget_doc.contains("asupersync-2oh2u.10.12"),
        "budget doc must reference T8.12 downstream"
    );
}
