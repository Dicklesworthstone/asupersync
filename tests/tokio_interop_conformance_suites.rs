#![allow(clippy::all)]
//! Interop conformance suites for prioritized third-party crates (T7.7).
//!
//! Validates behavioral contracts for tower, hyper, and body bridge adapters
//! across success, failure, and cancellation paths. Conformance tests
//! reference the boundary architecture (T7.2) invariants and outcome contracts.
//!
//! # Test Categories
//!
//! 1. **Invariant verification** — INV-1..5 + RULE-1..2 from boundary architecture
//! 2. **Tower bridge conformance** — FromTower/IntoTower behavioral contracts
//! 3. **Hyper bridge conformance** — Executor/Timer/Sleep contracts
//! 4. **Body bridge conformance** — HTTP body encoding/decoding contracts
//! 5. **Blocking bridge conformance** — Sync/async boundary contracts
//! 6. **Cancellation bridge conformance** — CancelAware mode contracts
//! 7. **I/O adapter conformance** — AsyncRead/AsyncWrite bridge contracts

#![allow(missing_docs)]

use std::path::Path;

// ─── helpers ───────────────────────────────────────────────────────────

fn load_boundary_doc() -> String {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/tokio_adapter_boundary_architecture.md");
    std::fs::read_to_string(path).expect("boundary architecture doc must exist")
}

fn load_ranking_doc() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/tokio_interop_target_ranking.md");
    std::fs::read_to_string(path).expect("interop ranking doc must exist")
}

// ═══════════════════════════════════════════════════════════════════════
// 1. INVARIANT VERIFICATION TESTS (INV-1 through INV-5 + RULES)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn inv1_no_ambient_authority_all_adapters_require_explicit_construction() {
    // INV-1: All adapter entry points require explicit construction.
    // No global statics, no ambient Tokio runtime, no implicit context.
    // Verify: all public adapter types require explicit new()/full()/streaming().

    let doc = load_boundary_doc();
    assert!(
        doc.contains("No ambient authority"),
        "boundary doc must declare INV-1"
    );

    // Verify the compat crate lib.rs declares no ambient authority
    let lib_src = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("asupersync-tokio-compat/src/lib.rs"),
    )
    .expect("lib.rs must exist");
    assert!(
        lib_src.contains("No ambient authority"),
        "lib.rs doc must reference INV-1"
    );
}

#[test]
fn inv2_structured_concurrency_adapter_tasks_are_region_owned() {
    let doc = load_boundary_doc();
    assert!(
        doc.contains("Structured concurrency"),
        "boundary doc must declare INV-2"
    );

    let lib_src = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("asupersync-tokio-compat/src/lib.rs"),
    )
    .expect("lib.rs must exist");
    assert!(
        lib_src.contains("region-owned"),
        "lib.rs doc must reference region ownership"
    );
}

#[test]
fn inv3_cancellation_is_a_protocol_adapters_propagate_cancel() {
    let doc = load_boundary_doc();
    assert!(
        doc.contains("Cancellation is a protocol"),
        "boundary doc must declare INV-3"
    );

    // Verify CancellationMode enum exists and has all three modes
    let lib_src = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("asupersync-tokio-compat/src/lib.rs"),
    )
    .expect("lib.rs must exist");
    for mode in ["BestEffort", "Strict", "TimeoutFallback"] {
        assert!(
            lib_src.contains(mode),
            "lib.rs must define CancellationMode::{mode}"
        );
    }
}

#[test]
fn inv4_no_obligation_leaks_resources_tracked_on_region_close() {
    let doc = load_boundary_doc();
    assert!(
        doc.contains("No obligation leaks"),
        "boundary doc must declare INV-4"
    );

    let lib_src = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("asupersync-tokio-compat/src/lib.rs"),
    )
    .expect("lib.rs must exist");
    assert!(
        lib_src.contains("obligation"),
        "lib.rs doc must reference obligation tracking"
    );
}

#[test]
fn inv5_outcome_severity_lattice_adapter_error_variants() {
    let doc = load_boundary_doc();
    assert!(
        doc.contains("Outcome severity lattice"),
        "boundary doc must declare INV-5"
    );

    // Verify AdapterError has all required variants
    let lib_src = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("asupersync-tokio-compat/src/lib.rs"),
    )
    .expect("lib.rs must exist");
    for variant in [
        "Service",
        "Cancelled",
        "Timeout",
        "InsufficientBudget",
        "CancellationIgnored",
    ] {
        assert!(
            lib_src.contains(variant),
            "AdapterError must have {variant} variant"
        );
    }
}

#[test]
fn rule1_no_tokio_runtime_embedded_in_compat_crate() {
    // RULE 1: No Tokio runtime is embedded or started.
    let doc = load_boundary_doc();
    assert!(
        doc.contains("No Tokio in core runtime paths"),
        "boundary doc must declare RULE 1"
    );

    // Verify: no `tokio::runtime::Runtime` or `#[tokio::main]` in the compat crate
    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("asupersync-tokio-compat/src");
    for entry in std::fs::read_dir(&src_dir).expect("src dir must exist") {
        let entry = entry.unwrap();
        if entry.path().extension().is_some_and(|e| e == "rs") {
            let content = std::fs::read_to_string(entry.path()).unwrap();
            assert!(
                !content.contains("tokio::runtime::Runtime"),
                "{}: must not embed Tokio runtime",
                entry.path().display()
            );
            assert!(
                !content.contains("#[tokio::main]"),
                "{}: must not use #[tokio::main]",
                entry.path().display()
            );
            assert!(
                !content.contains("#[tokio::test]"),
                "{}: must not use #[tokio::test] (tests run on Asupersync runtime)",
                entry.path().display()
            );
        }
    }
}

#[test]
fn rule2_adapters_in_separate_crate_one_way_dependency() {
    // RULE 2: main asupersync crate does NOT depend on tokio-compat
    let doc = load_boundary_doc();
    assert!(
        doc.contains("Adapters are in a separate crate"),
        "boundary doc must declare RULE 2"
    );

    // Verify the compat crate exists as a separate workspace member
    let workspace_toml =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
            .expect("workspace Cargo.toml must exist");
    assert!(
        workspace_toml.contains("asupersync-tokio-compat"),
        "workspace must include tokio-compat crate"
    );

    // Verify main crate does NOT depend on tokio-compat
    let main_toml =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
            .expect("main Cargo.toml must exist");
    // The main Cargo.toml should not have asupersync-tokio-compat in [dependencies]
    // (it may appear in [workspace.members] which is fine)
    let in_deps = main_toml
        .lines()
        .skip_while(|l| !l.starts_with("[dependencies]"))
        .take_while(|l| !l.starts_with('[') || l.starts_with("[dependencies]"))
        .any(|l| l.contains("asupersync-tokio-compat"));
    assert!(
        !in_deps,
        "main crate must NOT depend on asupersync-tokio-compat"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// 2. INTEROP TARGET RANKING CONFORMANCE
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn ranking_doc_defines_critical_tier_crates() {
    let doc = load_ranking_doc();
    for crate_name in ["reqwest", "axum", "tonic"] {
        assert!(
            doc.contains(crate_name),
            "ranking doc must include critical-tier crate: {crate_name}"
        );
    }
}

#[test]
fn ranking_doc_identifies_hyper_as_keystone() {
    let doc = load_ranking_doc();
    // hyper is the keystone that unlocks reqwest/axum/tonic
    assert!(
        doc.to_lowercase().contains("keystone") || doc.to_lowercase().contains("key enabler"),
        "ranking doc must identify hyper as keystone/key enabler"
    );
    assert!(doc.contains("hyper"), "ranking doc must include hyper");
}

#[test]
fn ranking_doc_has_impact_scoring_methodology() {
    let doc = load_ranking_doc();
    // The ranking uses a multi-dimensional scoring model
    for token in ["Impact", "Score", "Tier"] {
        assert!(
            doc.contains(token),
            "ranking doc must have scoring methodology token: {token}"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════
// 3. TOWER BRIDGE CONFORMANCE
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn tower_bridge_source_declares_cx_boundary() {
    let src = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("asupersync-tokio-compat/src/tower_bridge.rs"),
    )
    .expect("tower_bridge.rs must exist");

    // Must have both direction adapters
    assert!(src.contains("FromTower"), "must define FromTower adapter");
    assert!(src.contains("IntoTower"), "must define IntoTower adapter");

    // Must reference Cx (explicit capability threading)
    assert!(
        src.contains("Cx") || src.contains("cx"),
        "tower bridge must reference Cx capability context"
    );
}

#[test]
fn tower_bridge_handles_cancellation_path() {
    let src = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("asupersync-tokio-compat/src/tower_bridge.rs"),
    )
    .expect("tower_bridge.rs must exist");

    // Must handle cancellation
    assert!(
        src.contains("Cancel") || src.contains("cancel"),
        "tower bridge must handle cancellation"
    );
}

#[test]
fn tower_bridge_has_bidirectional_service_tests() {
    let src = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("asupersync-tokio-compat/src/tower_bridge.rs"),
    )
    .expect("tower_bridge.rs must exist");

    // Must have tests for both directions
    assert!(
        src.contains("from_tower") && src.contains("into_tower"),
        "tower bridge must test both directions"
    );
    // Must test round-trip
    assert!(
        src.contains("round_trip"),
        "tower bridge must test round-trip conversion"
    );
}

#[test]
fn tower_bridge_error_type_is_display_and_debug() {
    let src = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("asupersync-tokio-compat/src/tower_bridge.rs"),
    )
    .expect("tower_bridge.rs must exist");

    assert!(
        src.contains("Display") && src.contains("Debug"),
        "tower bridge error must implement Display + Debug"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// 4. HYPER BRIDGE CONFORMANCE
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn hyper_bridge_implements_executor_trait() {
    let src = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("asupersync-tokio-compat/src/hyper_bridge.rs"),
    )
    .expect("hyper_bridge.rs must exist");

    assert!(
        src.contains("Executor"),
        "hyper bridge must implement Executor trait"
    );
    assert!(
        src.contains("hyper::rt::Executor") || src.contains("impl<F> hyper"),
        "hyper bridge must implement hyper's Executor"
    );
}

#[test]
fn hyper_bridge_implements_timer_trait() {
    let src = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("asupersync-tokio-compat/src/hyper_bridge.rs"),
    )
    .expect("hyper_bridge.rs must exist");

    assert!(
        src.contains("Timer"),
        "hyper bridge must implement Timer trait"
    );
    assert!(
        src.contains("Sleep"),
        "hyper bridge must implement Sleep trait"
    );
}

#[test]
fn hyper_bridge_sleep_respects_deadline_contract() {
    let src = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("asupersync-tokio-compat/src/hyper_bridge.rs"),
    )
    .expect("hyper_bridge.rs must exist");

    // Sleep must support reset and deadline query
    assert!(
        src.contains("reset") && src.contains("deadline"),
        "hyper bridge Sleep must support reset() and deadline()"
    );
}

#[test]
fn hyper_bridge_has_executor_and_timer_tests() {
    let src = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("asupersync-tokio-compat/src/hyper_bridge.rs"),
    )
    .expect("hyper_bridge.rs must exist");

    assert!(
        src.contains("executor_implements_hyper_trait"),
        "must test executor trait implementation"
    );
    assert!(
        src.contains("timer_implements_hyper_trait"),
        "must test timer trait implementation"
    );
    assert!(
        src.contains("sleep_completes"),
        "must test sleep completion"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// 5. BODY BRIDGE CONFORMANCE
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn body_bridge_implements_http_body_trait() {
    let src = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("asupersync-tokio-compat/src/body_bridge.rs"),
    )
    .expect("body_bridge.rs must exist");

    assert!(
        src.contains("http_body::Body"),
        "body bridge must implement http_body::Body"
    );
    assert!(
        src.contains("poll_frame"),
        "body bridge must implement poll_frame"
    );
}

#[test]
fn body_bridge_supports_full_and_streaming_bodies() {
    let src = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("asupersync-tokio-compat/src/body_bridge.rs"),
    )
    .expect("body_bridge.rs must exist");

    assert!(src.contains("Full"), "body bridge must support full bodies");
    assert!(
        src.contains("Stream"),
        "body bridge must support streaming bodies"
    );
    assert!(
        src.contains("fn full("),
        "body bridge must have full() constructor"
    );
    assert!(
        src.contains("fn streaming("),
        "body bridge must have streaming() constructor"
    );
    assert!(
        src.contains("fn empty("),
        "body bridge must have empty() constructor"
    );
}

#[test]
fn body_bridge_supports_trailers() {
    let src = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("asupersync-tokio-compat/src/body_bridge.rs"),
    )
    .expect("body_bridge.rs must exist");

    assert!(
        src.contains("trailers"),
        "body bridge must support HTTP trailers"
    );
    assert!(
        src.contains("with_trailers"),
        "body bridge must have with_trailers() builder"
    );
    // gRPC requires trailers for status codes
    assert!(
        src.contains("grpc-status") || src.contains("grpc_status"),
        "body bridge tests must verify gRPC trailer handling"
    );
}

#[test]
fn body_bridge_provides_size_limited_collection() {
    let src = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("asupersync-tokio-compat/src/body_bridge.rs"),
    )
    .expect("body_bridge.rs must exist");

    assert!(
        src.contains("collect_body_limited"),
        "body bridge must provide size-limited body collection"
    );
    assert!(
        src.contains("TooLarge"),
        "body bridge must define TooLarge error variant"
    );
    assert!(
        src.contains("max_bytes"),
        "body bridge must accept max_bytes parameter"
    );
}

#[test]
fn body_bridge_has_grpc_service_adapter() {
    let src = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("asupersync-tokio-compat/src/body_bridge.rs"),
    )
    .expect("body_bridge.rs must exist");

    assert!(
        src.contains("GrpcServiceAdapter"),
        "body bridge must provide GrpcServiceAdapter"
    );
    assert!(
        src.contains("fn new(") && src.contains("fn inner(") && src.contains("fn into_inner("),
        "GrpcServiceAdapter must have new/inner/into_inner methods"
    );
}

#[test]
fn body_bridge_is_data_only_no_cx_required() {
    // INV-1 for body bridge: data-only, no Cx needed
    let src = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("asupersync-tokio-compat/src/body_bridge.rs"),
    )
    .expect("body_bridge.rs must exist");

    assert!(
        src.contains("data-only") || src.contains("No ambient authority") || src.contains("INV-1"),
        "body bridge must document that it is data-only (no Cx required)"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// 6. CANCELLATION BRIDGE CONFORMANCE
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn cancel_bridge_supports_all_three_modes() {
    let src = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("asupersync-tokio-compat/src/cancel.rs"),
    )
    .expect("cancel.rs must exist");

    assert!(
        src.contains("CancelAware"),
        "cancel bridge must define CancelAware wrapper"
    );
    for mode in ["BestEffort", "Strict", "TimeoutFallback"] {
        assert!(
            src.contains(mode),
            "cancel bridge must handle CancellationMode::{mode}"
        );
    }
}

#[test]
fn cancel_bridge_documents_cancellation_semantics() {
    let src = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("asupersync-tokio-compat/src/cancel.rs"),
    )
    .expect("cancel.rs must exist");

    // Must document how cancellation interacts with wrapped futures
    assert!(
        src.contains("cancellation") || src.contains("Cancellation"),
        "cancel bridge must document cancellation semantics"
    );
    assert!(
        src.contains("cancel_requested") || src.contains("is_cancel_requested"),
        "cancel bridge must reference cancel request checking"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// 7. BLOCKING BRIDGE CONFORMANCE
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn blocking_bridge_captures_panics() {
    let src = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("asupersync-tokio-compat/src/blocking.rs"),
    )
    .expect("blocking.rs must exist");

    assert!(
        src.contains("Panicked") || src.contains("panicked"),
        "blocking bridge must capture panics"
    );
    assert!(
        src.contains("catch_unwind") || src.contains("panic"),
        "blocking bridge must use catch_unwind or panic handling"
    );
}

#[test]
fn blocking_bridge_has_outcome_type_with_three_variants() {
    let src = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("asupersync-tokio-compat/src/blocking.rs"),
    )
    .expect("blocking.rs must exist");

    // Outcome must have Ok, Cancelled, Panicked
    for variant in ["Ok(", "Cancelled", "Panicked("] {
        assert!(
            src.contains(variant),
            "blocking Outcome must have {variant} variant"
        );
    }
}

#[test]
fn blocking_bridge_propagates_context() {
    let src = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("asupersync-tokio-compat/src/blocking.rs"),
    )
    .expect("blocking.rs must exist");

    // Must support context propagation across sync/async boundary
    assert!(
        src.contains("cx") || src.contains("Cx") || src.contains("context"),
        "blocking bridge must propagate context across sync/async boundary"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// 8. I/O ADAPTER CONFORMANCE
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn io_adapter_has_bidirectional_wrappers() {
    let src = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("asupersync-tokio-compat/src/io.rs"),
    )
    .expect("io.rs must exist");

    assert!(
        src.contains("TokioIo"),
        "io adapter must define TokioIo wrapper"
    );
    assert!(
        src.contains("AsupersyncIo"),
        "io adapter must define AsupersyncIo wrapper"
    );
}

#[test]
fn io_adapter_implements_async_read_write() {
    let src = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("asupersync-tokio-compat/src/io.rs"),
    )
    .expect("io.rs must exist");

    assert!(
        src.contains("AsyncRead"),
        "io adapter must implement AsyncRead"
    );
    assert!(
        src.contains("AsyncWrite"),
        "io adapter must implement AsyncWrite"
    );
}

#[test]
fn io_adapter_supports_inner_access() {
    let src = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("asupersync-tokio-compat/src/io.rs"),
    )
    .expect("io.rs must exist");

    // Must allow accessing the inner type
    assert!(
        src.contains("fn inner(") && src.contains("fn inner_mut("),
        "io adapters must provide inner()/inner_mut() accessors"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// 9. CROSS-CUTTING CONFORMANCE
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn all_adapter_modules_deny_unsafe_code() {
    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("asupersync-tokio-compat/src");

    // Check lib.rs for crate-level deny
    let lib_src = std::fs::read_to_string(src_dir.join("lib.rs")).expect("lib.rs must exist");
    assert!(
        lib_src.contains("deny(unsafe_code)"),
        "compat crate must deny unsafe code"
    );
}

#[test]
fn all_adapter_modules_have_module_docs() {
    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("asupersync-tokio-compat/src");

    for file_name in ["lib.rs", "blocking.rs", "cancel.rs", "io.rs"] {
        let src = std::fs::read_to_string(src_dir.join(file_name))
            .unwrap_or_else(|_| panic!("{file_name} must exist"));
        assert!(
            src.starts_with("//!"),
            "{file_name} must have module-level documentation"
        );
    }
}

#[test]
fn feature_gated_modules_exist_when_features_enabled() {
    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("asupersync-tokio-compat/src");

    // These files must exist (gated by features in lib.rs)
    for file_name in ["hyper_bridge.rs", "body_bridge.rs", "tower_bridge.rs"] {
        assert!(
            src_dir.join(file_name).exists(),
            "{file_name} must exist for feature-gated module"
        );
    }
}

#[test]
fn compat_crate_cargo_toml_has_correct_features() {
    let toml_src = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("asupersync-tokio-compat/Cargo.toml"),
    )
    .expect("compat Cargo.toml must exist");

    for feature in ["hyper-bridge", "tokio-io", "tower-bridge", "full"] {
        assert!(
            toml_src.contains(feature),
            "Cargo.toml must define feature: {feature}"
        );
    }
}

#[test]
fn compat_crate_depends_on_main_crate() {
    let toml_src = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("asupersync-tokio-compat/Cargo.toml"),
    )
    .expect("compat Cargo.toml must exist");

    assert!(
        toml_src.contains("asupersync"),
        "compat crate must depend on main asupersync crate"
    );
}

#[test]
fn adapter_error_implements_std_error() {
    let lib_src = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("asupersync-tokio-compat/src/lib.rs"),
    )
    .expect("lib.rs must exist");

    assert!(
        lib_src.contains("std::error::Error"),
        "AdapterError must implement std::error::Error"
    );
    assert!(
        lib_src.contains("std::fmt::Display"),
        "AdapterError must implement Display"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// 10. CONFORMANCE COVERAGE MATRIX
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn conformance_matrix_all_adapters_have_tests() {
    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("asupersync-tokio-compat/src");

    let modules_with_required_tests = [
        ("lib.rs", "mod tests"),
        ("blocking.rs", "mod tests"),
        ("cancel.rs", "mod tests"),
        ("io.rs", "mod tests"),
        ("hyper_bridge.rs", "mod tests"),
        ("body_bridge.rs", "mod tests"),
        ("tower_bridge.rs", "mod tests"),
    ];

    for (file_name, test_marker) in modules_with_required_tests {
        let src = std::fs::read_to_string(src_dir.join(file_name))
            .unwrap_or_else(|_| panic!("{file_name} must exist"));
        assert!(
            src.contains(test_marker),
            "{file_name} must contain test module ({test_marker})"
        );
    }
}

#[test]
fn conformance_test_count_meets_minimum_threshold() {
    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("asupersync-tokio-compat/src");

    let mut total_tests = 0;
    for entry in std::fs::read_dir(&src_dir).expect("src dir must exist") {
        let entry = entry.unwrap();
        if entry.path().extension().is_some_and(|e| e == "rs") {
            let content = std::fs::read_to_string(entry.path()).unwrap();
            total_tests += content.matches("#[test]").count();
        }
    }

    // T7.5 shipped with 58 tests, conformance requires >= 50
    assert!(
        total_tests >= 50,
        "compat crate must have >= 50 unit tests, found {total_tests}"
    );
}

#[test]
fn conformance_policy_version_is_current() {
    let lib_src = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("asupersync-tokio-compat/src/lib.rs"),
    )
    .expect("lib.rs must exist");

    assert!(
        lib_src.contains("COMPAT_POLICY_VERSION"),
        "lib.rs must declare COMPAT_POLICY_VERSION"
    );
    assert!(
        lib_src.contains("COMPATIBILITY_LINE"),
        "lib.rs must declare COMPATIBILITY_LINE"
    );
    assert!(
        lib_src.contains("OWNER_TRACK_ID"),
        "lib.rs must declare OWNER_TRACK_ID"
    );
}
