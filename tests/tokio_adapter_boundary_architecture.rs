//! Contract tests for Tokio adapter boundary architecture (2oh2u.7.2).
//!
//! Validates enforceable adapter invariants, outcome contracts, structured
//! replay evidence requirements, and rch-offloaded validation commands.

#![allow(missing_docs)]

use std::path::Path;

fn load_doc() -> String {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/tokio_adapter_boundary_architecture.md");
    std::fs::read_to_string(path).expect("adapter boundary architecture document must exist")
}

#[test]
fn architecture_doc_exists_and_is_substantial() {
    let doc = load_doc();
    assert!(
        doc.len() > 9_000,
        "adapter boundary architecture doc should be substantial, got {} bytes",
        doc.len()
    );
}

#[test]
fn architecture_doc_references_correct_bead_and_metadata() {
    let doc = load_doc();
    for token in [
        "asupersync-2oh2u.7.2",
        "[T7.2]",
        "Maintained by",
        "WhiteDesert",
        "Version",
        "1.4.0",
    ] {
        assert!(doc.contains(token), "missing metadata token: {token}");
    }
}

#[test]
fn architecture_doc_declares_non_negotiable_runtime_invariants() {
    let doc = load_doc();
    for token in [
        "No ambient authority",
        "Structured concurrency",
        "Cancellation is a protocol",
        "No obligation leaks",
        "Outcome severity lattice",
    ] {
        assert!(doc.contains(token), "missing invariant token: {token}");
    }
}

#[test]
fn architecture_doc_enforces_hard_tokio_boundary_rules() {
    let doc = load_doc();
    for token in [
        "RULE 1: No Tokio in core runtime paths.",
        "RULE 2: Adapters are in a separate crate.",
        "RULE 3: Cx must cross the boundary.",
        "RULE 4: Region ownership is non-negotiable.",
        "asupersync-tokio-compat",
    ] {
        assert!(doc.contains(token), "missing boundary-rule token: {token}");
    }
}

#[test]
fn architecture_doc_has_success_failure_cancellation_outcome_matrix() {
    let doc = load_doc();
    assert!(
        doc.contains("Boundary Outcome Contract (Success/Failure/Cancellation)"),
        "must include boundary outcome contract section"
    );
    for token in [
        "Success Contract",
        "Failure Contract",
        "Cancellation Contract",
        "Deterministic Assertion",
        "Runtime bridge (`with_tokio_context`)",
        "Hyper bridge (`hyper_bridge`)",
        "SQLx runtime adapter (`sqlx_runtime`)",
        "Tonic transport bridge (`tonic_transport`)",
        "Outcome::Cancelled",
    ] {
        assert!(
            doc.contains(token),
            "missing outcome-contract token: {token}"
        );
    }
}

#[test]
fn architecture_doc_declares_forbidden_patterns_explicitly() {
    let doc = load_doc();
    for token in [
        "NEVER: Embed a Hidden Tokio Runtime",
        "NEVER: Bypass Cx for Convenience",
        "NEVER: Spawn Untracked Background Tasks",
        "NEVER: Swallow Cancellation",
    ] {
        assert!(
            doc.contains(token),
            "missing forbidden-pattern token: {token}"
        );
    }
}

#[test]
fn architecture_doc_requires_structured_logs_and_replay_artifacts() {
    let doc = load_doc();
    assert!(
        doc.contains("Structured Logs and Replay Artifacts"),
        "must include structured logs and replay artifacts section"
    );
    for token in [
        "`correlation_id`",
        "`adapter_path`",
        "`trace_id`",
        "`decision_id`",
        "`replay_seed`",
        "`artifact_uri`",
        "artifacts/tokio_adapter_boundary/<run-id>/adapter_events.jsonl",
        "artifacts/tokio_adapter_boundary/<run-id>/replay_summary.json",
        "artifacts/tokio_adapter_boundary/<run-id>/failure_triage.md",
        "Hard-fail quality gate policy",
    ] {
        assert!(
            doc.contains(token),
            "missing replay-evidence token: {token}"
        );
    }
}

#[test]
fn architecture_doc_includes_rch_validation_bundle() {
    let doc = load_doc();
    for token in [
        "rch exec -- cargo test --test tokio_adapter_boundary_architecture -- --nocapture",
        "rch exec -- cargo check --all-targets -q",
        "rch exec -- cargo fmt --check",
        "rch exec -- cargo clippy --all-targets -- -D warnings",
    ] {
        assert!(
            doc.contains(token),
            "missing validation command token: {token}"
        );
    }
}

#[test]
fn architecture_doc_links_contract_and_source_evidence() {
    let doc = load_doc();
    for token in [
        "docs/tokio_interop_target_ranking.md",
        "docs/tokio_functional_parity_contract.md",
        "docs/tokio_nonfunctional_closure_criteria.md",
        "docs/tokio_evidence_checklist.md",
        "asupersync-tokio-compat/src/runtime.rs",
        "asupersync-tokio-compat/src/executor.rs",
        "asupersync-tokio-compat/src/timer.rs",
        "asupersync-tokio-compat/src/io.rs",
        "asupersync-tokio-compat/src/cancel.rs",
        "tests/tokio_adapter_boundary_architecture.rs",
    ] {
        assert!(doc.contains(token), "missing evidence-link token: {token}");
    }
}

#[test]
fn architecture_doc_revision_history_tracks_latest_update() {
    let doc = load_doc();
    assert!(
        doc.contains("| 2026-03-03 | WhiteDesert |"),
        "revision history should include WhiteDesert row"
    );
    assert!(
        doc.contains("| 2026-03-03 | SapphireHill | Initial architecture (v1.0) |"),
        "revision history should retain initial baseline row"
    );
}

// ---------------------------------------------------------------------------
// T7.4 Contract Tests — Adapter Primitive Implementation Evidence
// ---------------------------------------------------------------------------

#[test]
fn t74_architecture_doc_records_implementation_evidence() {
    let doc = load_doc();
    assert!(
        doc.contains("T7.4"),
        "architecture doc must reference T7.4 implementation"
    );
    for token in [
        "I/O trait bridging",
        "TokioIo",
        "AsupersyncIo",
        "executor",
        "spawn_fn",
        "timer",
        "waker",
    ] {
        assert!(
            doc.to_ascii_lowercase()
                .contains(&token.to_ascii_lowercase()),
            "T7.4 evidence missing implementation token: {token}"
        );
    }
}

#[test]
fn t74_compat_crate_cargo_toml_has_required_deps() {
    let toml_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("asupersync-tokio-compat/Cargo.toml");
    let toml = std::fs::read_to_string(toml_path).expect("compat crate Cargo.toml must exist");

    for dep in ["asupersync", "tokio", "pin-project-lite"] {
        assert!(toml.contains(dep), "must depend on {dep}");
    }
    for feature in ["hyper-bridge", "tokio-io"] {
        assert!(toml.contains(feature), "must define {feature} feature");
    }
    assert!(
        toml.contains("default-features = false"),
        "tokio dependency must disable default features (no runtime)"
    );
}

#[test]
fn t74_compat_crate_lib_rs_exports_expected_modules() {
    let lib_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("asupersync-tokio-compat/src/lib.rs");
    let lib = std::fs::read_to_string(lib_path).expect("compat crate lib.rs must exist");

    for module in ["pub mod cancel", "pub mod io"] {
        assert!(lib.contains(module), "lib.rs must export module: {module}");
    }
    assert!(
        lib.contains("pub mod hyper_bridge"),
        "lib.rs must export hyper_bridge (gated on hyper-bridge feature)"
    );
    assert!(
        lib.contains("#![deny(unsafe_code)]"),
        "compat crate must deny unsafe code by default"
    );
}

#[test]
fn t74_io_module_has_bidirectional_trait_impls() {
    let io_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("asupersync-tokio-compat/src/io.rs");
    let io = std::fs::read_to_string(io_path).expect("compat crate io.rs must exist");

    // Direction 1: Asupersync → Tokio
    assert!(
        io.contains("tokio::io::AsyncRead for TokioIo"),
        "must impl tokio::io::AsyncRead for TokioIo"
    );
    assert!(
        io.contains("tokio::io::AsyncWrite for TokioIo"),
        "must impl tokio::io::AsyncWrite for TokioIo"
    );

    // Direction 2: Tokio → Asupersync
    assert!(
        io.contains("asupersync::io::AsyncRead for AsupersyncIo"),
        "must impl asupersync::io::AsyncRead for AsupersyncIo"
    );
    assert!(
        io.contains("asupersync::io::AsyncWrite for AsupersyncIo"),
        "must impl asupersync::io::AsyncWrite for AsupersyncIo"
    );

    // Direction 3: Asupersync → hyper v1
    assert!(
        io.contains("hyper::rt::Read for TokioIo"),
        "must impl hyper::rt::Read for TokioIo"
    );
    assert!(
        io.contains("hyper::rt::Write for TokioIo"),
        "must impl hyper::rt::Write for TokioIo"
    );

    // ReadBuf bridging evidence
    assert!(
        io.contains("ReadBuf::new"),
        "must bridge ReadBuf types between Asupersync and Tokio"
    );
}

#[test]
fn t74_executor_uses_callback_not_ambient_authority() {
    let bridge_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("asupersync-tokio-compat/src/hyper_bridge.rs");
    let bridge =
        std::fs::read_to_string(bridge_path).expect("compat crate hyper_bridge.rs must exist");

    // INV-1: No ambient authority — executor uses explicit spawn callback.
    assert!(
        bridge.contains("spawn_fn"),
        "executor must use explicit spawn_fn (no ambient authority)"
    );
    assert!(
        bridge.contains("with_spawn_fn"),
        "executor must expose with_spawn_fn constructor"
    );

    // INV-2: Structured concurrency — documents region ownership.
    assert!(
        bridge.contains("region-owned"),
        "executor must document region ownership of spawned tasks"
    );

    // No unimplemented! in production code paths.
    assert!(
        !bridge.contains("unimplemented!"),
        "executor must not contain unimplemented!() stubs"
    );
}

#[test]
fn t74_timer_uses_waker_based_notification() {
    let bridge_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("asupersync-tokio-compat/src/hyper_bridge.rs");
    let bridge =
        std::fs::read_to_string(bridge_path).expect("compat crate hyper_bridge.rs must exist");

    assert!(
        bridge.contains("waker"),
        "timer must use waker-based notification"
    );
    assert!(
        bridge.contains("hyper::rt::Timer for AsupersyncTimer"),
        "must impl hyper::rt::Timer"
    );
    assert!(
        bridge.contains("hyper::rt::Sleep for AsupersyncSleep"),
        "must impl hyper::rt::Sleep"
    );
}

#[test]
fn t74_cancellation_bridge_supports_three_modes() {
    let cancel_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("asupersync-tokio-compat/src/cancel.rs");
    let cancel = std::fs::read_to_string(cancel_path).expect("compat crate cancel.rs must exist");

    assert!(
        cancel.contains("CancelAware"),
        "must define CancelAware wrapper"
    );
    assert!(
        cancel.contains("CancelResult"),
        "must define CancelResult enum"
    );

    for mode in ["BestEffort", "Strict", "TimeoutFallback"] {
        assert!(
            cancel.contains(mode),
            "cancellation bridge must support {mode} mode"
        );
    }

    // INV-3: Cancellation is a protocol.
    assert!(
        cancel.contains("request_cancel"),
        "must expose request_cancel for protocol propagation"
    );
}

// ---------------------------------------------------------------------------
// T7.5 Contract Tests — Tower Bridge Implementation Evidence
// ---------------------------------------------------------------------------

#[test]
fn t75_tower_bridge_module_exists() {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("asupersync-tokio-compat/src/tower_bridge.rs");
    assert!(path.exists(), "tower_bridge.rs must exist");
    let src = std::fs::read_to_string(path).expect("must read tower_bridge.rs");
    assert!(
        src.len() > 2_000,
        "tower_bridge.rs should be substantial, got {} bytes",
        src.len()
    );
}

#[test]
fn t75_tower_bridge_has_from_tower_adapter() {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("asupersync-tokio-compat/src/tower_bridge.rs");
    let src = std::fs::read_to_string(path).unwrap();

    assert!(
        src.contains("pub struct FromTower"),
        "must define FromTower adapter"
    );
    assert!(
        src.contains("tower::Service<Request>"),
        "FromTower must constrain on tower::Service"
    );
    // INV-1: Must accept Cx explicitly.
    assert!(
        src.contains("cx: &asupersync::Cx"),
        "FromTower::call must accept &Cx"
    );
}

#[test]
fn t75_tower_bridge_has_into_tower_adapter() {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("asupersync-tokio-compat/src/tower_bridge.rs");
    let src = std::fs::read_to_string(path).unwrap();

    assert!(
        src.contains("pub struct IntoTower"),
        "must define IntoTower adapter"
    );
    assert!(
        src.contains("tower::Service<Request> for IntoTower"),
        "IntoTower must implement tower::Service"
    );
    assert!(
        src.contains("Cx::current()"),
        "IntoTower must retrieve Cx from thread-local"
    );
}

#[test]
fn t75_tower_bridge_has_bridge_error() {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("asupersync-tokio-compat/src/tower_bridge.rs");
    let src = std::fs::read_to_string(path).unwrap();

    assert!(
        src.contains("pub enum BridgeError"),
        "must define BridgeError enum"
    );
    // INV-5: Outcome severity lattice — must distinguish error classes.
    for variant in ["Readiness", "Service", "Cancelled", "NoCxAvailable"] {
        assert!(
            src.contains(variant),
            "BridgeError must include {variant} variant"
        );
    }
    assert!(
        src.contains("impl<E: std::fmt::Display> std::fmt::Display for BridgeError<E>"),
        "BridgeError must implement Display"
    );
    assert!(
        src.contains("std::error::Error for BridgeError<E>"),
        "BridgeError must implement Error"
    );
}

#[test]
fn t75_tower_bridge_preserves_cancellation_invariant() {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("asupersync-tokio-compat/src/tower_bridge.rs");
    let src = std::fs::read_to_string(path).unwrap();

    // INV-3: Cancellation is a protocol.
    assert!(
        src.contains("is_cancel_requested"),
        "FromTower must check cancellation before awaiting response"
    );
    assert!(
        src.contains("BridgeError::Cancelled"),
        "must return Cancelled variant when cancelled"
    );
}

#[test]
fn t75_tower_bridge_preserves_cx_invariant() {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("asupersync-tokio-compat/src/tower_bridge.rs");
    let src = std::fs::read_to_string(path).unwrap();

    // INV-1: No ambient authority — FromTower takes &Cx.
    assert!(
        src.contains("pub async fn call"),
        "FromTower must have async call method"
    );
    assert!(
        src.contains("Cx::set_current"),
        "must install Cx for tower future execution"
    );
    // IntoTower must fail explicitly when Cx is missing.
    assert!(
        src.contains("NoCxAvailable"),
        "IntoTower must fail with NoCxAvailable when Cx not installed"
    );
}

#[test]
fn t75_tower_bridge_has_tests() {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("asupersync-tokio-compat/src/tower_bridge.rs");
    let src = std::fs::read_to_string(path).unwrap();

    assert!(
        src.contains("#[cfg(test)]"),
        "tower_bridge must include unit tests"
    );
    // Verify key test coverage.
    for test_name in [
        "from_tower_echo_service",
        "from_tower_cancelled_before_call",
        "into_tower_counter_service",
        "into_tower_no_cx_returns_error",
        "bridge_error_display",
    ] {
        assert!(
            src.contains(test_name),
            "tower_bridge must include test: {test_name}"
        );
    }
}

#[test]
fn t75_cargo_toml_has_tower_dependency() {
    let toml_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("asupersync-tokio-compat/Cargo.toml");
    let toml = std::fs::read_to_string(toml_path).unwrap();

    assert!(
        toml.contains("tower"),
        "Cargo.toml must list tower dependency"
    );
    assert!(
        toml.contains("tower-bridge"),
        "Cargo.toml must define tower-bridge feature"
    );
}

#[test]
fn t75_lib_rs_exports_tower_bridge() {
    let lib_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("asupersync-tokio-compat/src/lib.rs");
    let lib = std::fs::read_to_string(lib_path).unwrap();

    assert!(
        lib.contains("pub mod tower_bridge"),
        "lib.rs must export tower_bridge module"
    );
    assert!(
        lib.contains("tower-bridge"),
        "lib.rs must gate tower_bridge on tower-bridge feature"
    );
}

#[test]
fn t75_architecture_doc_references_tower_bridge() {
    let doc = load_doc();
    assert!(
        doc.contains("tower_bridge.rs"),
        "architecture doc must reference tower_bridge.rs"
    );
    assert!(
        doc.contains("T7.5"),
        "architecture doc revision history must reference T7.5"
    );
}
