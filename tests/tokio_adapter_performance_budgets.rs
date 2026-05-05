//! Adapter performance and correctness budget contract tests (T7.8).
//!
//! Validates that the budget document is complete, all NF28 thresholds are
//! defined, startup/shutdown contracts are covered, invariant gates are
//! enforced, and adapter-specific correctness contracts are mapped.
//!
//! # Test Categories
//!
//! 1. **Document schema** — budget doc exists with required sections
//! 2. **NF28 threshold completeness** — all deferred rows now have concrete values
//! 3. **Startup contracts** — SU-01..07 are defined
//! 4. **Shutdown contracts** — SD-01..06 are defined
//! 5. **Graceful drain contracts** — GD-01..03 are defined
//! 6. **Invariant gates** — IG-01..07 are defined
//! 7. **Correctness contracts** — CC/BC/BB/TC/IC/HC contracts exist
//! 8. **Regression policy** — PB-11 binding and alarm rules
//! 9. **Code-level enforcement** — adapter code matches declared budgets
//! 10. **Cross-reference validation** — downstream bindings are consistent

#![allow(missing_docs)]

use std::path::Path;

// ─── helpers ───────────────────────────────────────────────────────────

fn load_budget_doc() -> String {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/tokio_adapter_performance_budgets.md");
    std::fs::read_to_string(path).expect("adapter performance budgets doc must exist")
}

fn load_nf_criteria_doc() -> String {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/tokio_nonfunctional_closure_criteria.md");
    std::fs::read_to_string(path).expect("nonfunctional closure criteria doc must exist")
}

fn load_regression_doc() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("docs/tokio_track_performance_regression_budgets.md");
    std::fs::read_to_string(path).expect("performance regression budgets doc must exist")
}

fn load_compat_source(module: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("asupersync-tokio-compat/src")
        .join(module);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("{module} must exist at {}", path.display()))
}

fn load_boundary_doc() -> String {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/tokio_adapter_boundary_architecture.md");
    std::fs::read_to_string(path).expect("boundary architecture doc must exist")
}

// ═══════════════════════════════════════════════════════════════════════
// 1. DOCUMENT SCHEMA COMPLETENESS
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn budget_doc_exists_and_has_required_sections() {
    let doc = load_budget_doc();

    let required_sections = [
        "## 1. Scope",
        "## 2. NF28 Concrete Thresholds",
        "## 3. Startup and Shutdown Behavior Contracts",
        "## 4. Invariant Enforcement Gates",
        "## 5. Quality Gate Integration",
        "## 6. Adapter-Specific Correctness Contracts",
        "## 7. Measurement Methodology",
        "## 8. Downstream Binding",
        "## 9. Revision History",
    ];

    for section in &required_sections {
        assert!(
            doc.contains(section),
            "budget doc missing required section: {section}"
        );
    }
}

#[test]
fn budget_doc_has_correct_bead_and_metadata() {
    let doc = load_budget_doc();

    assert!(
        doc.contains("asupersync-2oh2u.7.8"),
        "must reference T7.8 bead"
    );
    assert!(doc.contains("[T7.8]"), "must reference T7.8 label");
    assert!(
        doc.contains("asupersync-2oh2u.7.5") && doc.contains("asupersync-2oh2u.7.7"),
        "must declare dependencies on T7.5 and T7.7"
    );
}

#[test]
fn budget_doc_covers_all_six_adapter_modules() {
    let doc = load_budget_doc();

    let modules = [
        "hyper_bridge",
        "body_bridge",
        "tower_bridge",
        "io",
        "cancel",
        "blocking",
    ];

    for module in &modules {
        assert!(
            doc.contains(module),
            "budget doc must cover adapter module: {module}"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════
// 2. NF28 THRESHOLD COMPLETENESS
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn nf28_adapter_call_overhead_thresholds_defined() {
    let doc = load_budget_doc();

    // All NF28.1 through NF28.6a must have concrete thresholds (not DEFERRED).
    let overhead_ids = [
        "NF28.1 ", "NF28.1a", "NF28.1b", "NF28.2 ", "NF28.2a", "NF28.3 ", "NF28.3a", "NF28.3b",
        "NF28.4 ", "NF28.4a", "NF28.4b", "NF28.5 ", "NF28.5a", "NF28.5b", "NF28.6 ", "NF28.6a",
    ];

    for id in &overhead_ids {
        assert!(
            doc.contains(id.trim()),
            "budget doc missing overhead threshold: {id}"
        );
    }

    // No DEFERRED markers should remain.
    assert!(
        !doc.contains("[DEFERRED]"),
        "no DEFERRED placeholders should remain in budget doc"
    );
}

#[test]
fn nf28_throughput_thresholds_defined() {
    let doc = load_budget_doc();

    let throughput_ids = ["NF28.7", "NF28.8", "NF28.9", "NF28.10"];

    for id in &throughput_ids {
        assert!(
            doc.contains(id),
            "budget doc missing throughput threshold: {id}"
        );
    }
}

#[test]
fn nf28_memory_thresholds_defined() {
    let doc = load_budget_doc();

    let memory_ids = [
        "NF28.11", "NF28.12", "NF28.13", "NF28.14", "NF28.15", "NF28.16", "NF28.17",
    ];

    for id in &memory_ids {
        assert!(
            doc.contains(id),
            "budget doc missing memory threshold: {id}"
        );
    }
}

#[test]
fn nf28_cancellation_correctness_thresholds_defined() {
    let doc = load_budget_doc();

    let cancel_ids = ["NF28.18", "NF28.19", "NF28.20", "NF28.21", "NF28.22"];

    for id in &cancel_ids {
        assert!(
            doc.contains(id),
            "budget doc missing cancellation threshold: {id}"
        );
    }
}

#[test]
fn nf28_no_regression_gate_defined() {
    let doc = load_budget_doc();
    assert!(
        doc.contains("NF28.NR"),
        "no-regression gate NF28.NR must be defined"
    );
    assert!(
        doc.contains("+8%") && doc.contains("+15%"),
        "NR gate must specify warning (+8%) and hard-fail (+15%) thresholds"
    );
}

#[test]
fn nf28_thresholds_use_concrete_units() {
    let doc = load_budget_doc();

    // Verify concrete measurement units are present (not vague).
    let expected_units = ["ns", "us", "ms", "calls/sec", "frames/sec", "GB/s", "bytes"];

    for unit in &expected_units {
        assert!(
            doc.contains(unit),
            "budget doc should use concrete unit: {unit}"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════
// 3. STARTUP CONTRACT COVERAGE
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn startup_contracts_su01_through_su07_defined() {
    let doc = load_budget_doc();

    for i in 1..=7 {
        let id = format!("SU-{i:02}");
        assert!(
            doc.contains(&id),
            "budget doc missing startup contract: {id}"
        );
    }
}

#[test]
fn startup_contracts_reference_correct_modules() {
    let doc = load_budget_doc();

    // SU-01 and SU-02 → hyper_bridge
    assert!(doc.contains("SU-01") && doc.contains("hyper_bridge"));
    // SU-03 → body_bridge
    assert!(doc.contains("SU-03") && doc.contains("body_bridge"));
    // SU-04 → tower_bridge
    assert!(doc.contains("SU-04") && doc.contains("tower_bridge"));
    // SU-05 → io
    assert!(doc.contains("SU-05"));
    // SU-06 → cancel
    assert!(doc.contains("SU-06") && doc.contains("cancel"));
    // SU-07 → blocking
    assert!(doc.contains("SU-07") && doc.contains("blocking"));
}

#[test]
fn startup_const_fn_contracts_verified_in_code() {
    // SU-03 claims body_bridge constructors are const fn.
    let body_src = load_compat_source("body_bridge.rs");
    assert!(
        body_src.contains("pub const fn full("),
        "IntoHttpBody::full must be const fn"
    );
    assert!(
        body_src.contains("pub const fn empty("),
        "IntoHttpBody::empty must be const fn"
    );
    assert!(
        body_src.contains("pub const fn streaming("),
        "IntoHttpBody::streaming must be const fn"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// 4. SHUTDOWN CONTRACT COVERAGE
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn shutdown_contracts_sd01_through_sd06_defined() {
    let doc = load_budget_doc();

    for i in 1..=6 {
        let id = format!("SD-{i:02}");
        assert!(
            doc.contains(&id),
            "budget doc missing shutdown contract: {id}"
        );
    }
}

#[test]
fn graceful_drain_contracts_gd01_through_gd03_defined() {
    let doc = load_budget_doc();

    for i in 1..=3 {
        let id = format!("GD-{i:02}");
        assert!(
            doc.contains(&id),
            "budget doc missing graceful drain contract: {id}"
        );
    }
}

#[test]
fn graceful_drain_references_fallback_timeout() {
    let doc = load_budget_doc();
    assert!(
        doc.contains("fallback_timeout"),
        "GD-01 must reference fallback_timeout configuration"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// 5. INVARIANT ENFORCEMENT GATES
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn invariant_gates_ig01_through_ig07_defined() {
    let doc = load_budget_doc();

    for i in 1..=7 {
        let id = format!("IG-{i:02}");
        assert!(doc.contains(&id), "budget doc missing invariant gate: {id}");
    }
}

#[test]
fn invariant_gates_cover_all_five_invariants_and_two_rules() {
    let doc = load_budget_doc();

    // INV-1 through INV-5
    for i in 1..=5 {
        assert!(
            doc.contains(&format!("INV-{i}")),
            "invariant gate must reference INV-{i}"
        );
    }

    // RULE-1, RULE-2
    assert!(doc.contains("RULE-1"), "must reference RULE-1");
    assert!(doc.contains("RULE-2"), "must reference RULE-2");
}

#[test]
fn invariant_gates_are_hard_fail() {
    let doc = load_budget_doc();
    assert!(
        doc.contains("hard-fail") || doc.contains("Hard fail") || doc.contains("hard fail"),
        "invariant gates must be marked as hard-fail"
    );
}

#[test]
fn ig06_no_tokio_runtime_enforced_in_code() {
    // IG-06: No tokio::runtime::Runtime in adapter code.
    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("asupersync-tokio-compat/src");

    for entry in std::fs::read_dir(&src_dir).expect("src dir must exist") {
        let entry = entry.unwrap();
        if entry.path().extension().is_some_and(|e| e == "rs") {
            let content = std::fs::read_to_string(entry.path()).unwrap();
            let fname = entry.file_name();
            assert!(
                !content.contains("tokio::runtime::Runtime"),
                "IG-06 violation: {fname:?} contains tokio::runtime::Runtime"
            );
            assert!(
                !content.contains("#[tokio::main]"),
                "IG-06 violation: {fname:?} contains #[tokio::main]"
            );
            assert!(
                !content.contains("#[tokio::test]"),
                "IG-06 violation: {fname:?} contains #[tokio::test]"
            );
        }
    }
}

#[test]
fn ig07_all_adapter_code_in_compat_crate() {
    // IG-07: All adapter code lives in asupersync-tokio-compat/.
    let compat_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("asupersync-tokio-compat/src");
    assert!(
        compat_dir.exists(),
        "asupersync-tokio-compat/src must exist"
    );

    let expected_modules = [
        "lib.rs",
        "hyper_bridge.rs",
        "body_bridge.rs",
        "tower_bridge.rs",
        "io.rs",
        "cancel.rs",
        "blocking.rs",
    ];

    for module in &expected_modules {
        assert!(
            compat_dir.join(module).exists(),
            "adapter module {module} must be in asupersync-tokio-compat/src/"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════
// 6. ADAPTER-SPECIFIC CORRECTNESS CONTRACTS
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn cancel_aware_contracts_cc01_through_cc05_defined() {
    let doc = load_budget_doc();

    for i in 1..=5 {
        let id = format!("CC-{i:02}");
        assert!(
            doc.contains(&id),
            "budget doc missing CancelAware contract: {id}"
        );
    }
}

#[test]
fn blocking_bridge_contracts_bc01_through_bc04_defined() {
    let doc = load_budget_doc();

    for i in 1..=4 {
        let id = format!("BC-{i:02}");
        assert!(
            doc.contains(&id),
            "budget doc missing blocking bridge contract: {id}"
        );
    }
}

#[test]
fn body_bridge_contracts_bb01_through_bb07_defined() {
    let doc = load_budget_doc();

    for i in 1..=7 {
        let id = format!("BB-{i:02}");
        assert!(
            doc.contains(&id),
            "budget doc missing body bridge contract: {id}"
        );
    }
}

#[test]
fn tower_bridge_contracts_tc01_through_tc03_defined() {
    let doc = load_budget_doc();

    for i in 1..=3 {
        let id = format!("TC-{i:02}");
        assert!(
            doc.contains(&id),
            "budget doc missing tower bridge contract: {id}"
        );
    }
}

#[test]
fn io_bridge_contracts_ic01_through_ic04_defined() {
    let doc = load_budget_doc();

    for i in 1..=4 {
        let id = format!("IC-{i:02}");
        assert!(
            doc.contains(&id),
            "budget doc missing I/O bridge contract: {id}"
        );
    }
}

#[test]
fn hyper_bridge_contracts_hc01_through_hc04_defined() {
    let doc = load_budget_doc();

    for i in 1..=4 {
        let id = format!("HC-{i:02}");
        assert!(
            doc.contains(&id),
            "budget doc missing hyper bridge contract: {id}"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════
// 7. CODE-LEVEL BUDGET ENFORCEMENT VERIFICATION
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn cancel_aware_source_has_three_modes() {
    let src = load_compat_source("cancel.rs");

    assert!(
        src.contains("BestEffort"),
        "cancel.rs must implement BestEffort mode"
    );
    assert!(
        src.contains("Strict"),
        "cancel.rs must implement Strict mode"
    );
    assert!(
        src.contains("TimeoutFallback"),
        "cancel.rs must implement TimeoutFallback mode"
    );
}

#[test]
fn blocking_bridge_has_outcome_enum() {
    let src = load_compat_source("blocking.rs");

    // BC-02: panic capture
    assert!(
        src.contains("Panicked"),
        "blocking.rs must have Panicked outcome variant"
    );
    assert!(
        src.contains("Cancelled"),
        "blocking.rs must have Cancelled outcome variant"
    );
}

#[test]
fn blocking_bridge_has_cx_propagation() {
    // BC-01: Cx propagation to blocking thread
    let src = load_compat_source("blocking.rs");

    assert!(
        src.contains("set_current") || src.contains("cx") || src.contains("Cx"),
        "blocking.rs must propagate Cx context"
    );
}

#[test]
fn body_bridge_has_size_limit_enforcement() {
    // BB-06: collect_body_limited rejects oversize
    let src = load_compat_source("body_bridge.rs");

    assert!(
        src.contains("collect_body_limited"),
        "body_bridge.rs must have collect_body_limited"
    );
    assert!(
        src.contains("TooLarge"),
        "body_bridge.rs must have TooLarge error variant"
    );
    assert!(
        src.contains("max_bytes"),
        "body_bridge.rs must enforce max_bytes limit"
    );
}

#[test]
fn body_bridge_has_size_hint() {
    // BB-05: size_hint accurate for full bodies
    let src = load_compat_source("body_bridge.rs");

    assert!(
        src.contains("size_hint"),
        "body_bridge.rs must implement size_hint"
    );
    assert!(
        src.contains("SizeHint"),
        "body_bridge.rs must use http_body::SizeHint"
    );
}

#[test]
fn body_bridge_has_trailers_support() {
    // BB-03: trailers support
    let src = load_compat_source("body_bridge.rs");

    assert!(
        src.contains("trailers"),
        "body_bridge.rs must support trailers"
    );
    assert!(
        src.contains("Frame::trailers"),
        "body_bridge.rs must produce trailer frames"
    );
}

#[test]
fn adapter_config_has_min_budget_enforcement() {
    // NF28.5 budget gate: min_budget_for_call in AdapterConfig
    let src = load_compat_source("lib.rs");

    assert!(
        src.contains("min_budget_for_call"),
        "lib.rs must have min_budget_for_call in AdapterConfig"
    );
    assert!(
        src.contains("InsufficientBudget"),
        "lib.rs must have InsufficientBudget error variant"
    );
}

#[test]
fn tower_bridge_has_from_and_into_adapters() {
    let src = load_compat_source("tower_bridge.rs");

    assert!(
        src.contains("FromTower") || src.contains("from_tower"),
        "tower_bridge.rs must have FromTower adapter"
    );
    assert!(
        src.contains("IntoTower") || src.contains("into_tower"),
        "tower_bridge.rs must have IntoTower adapter"
    );
}

#[test]
fn io_bridge_has_bidirectional_wrappers() {
    let src = load_compat_source("io.rs");

    assert!(src.contains("TokioIo"), "io.rs must have TokioIo wrapper");
    assert!(
        src.contains("AsupersyncIo"),
        "io.rs must have AsupersyncIo wrapper"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// 8. REGRESSION POLICY AND QUALITY GATE BINDING
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn budget_doc_references_pb11_from_regression_policy() {
    let doc = load_budget_doc();
    assert!(
        doc.contains("PB-11"),
        "budget doc must reference PB-11 from T8.7 regression policy"
    );
}

#[test]
fn regression_policy_has_pb11_for_t7() {
    let doc = load_regression_doc();
    assert!(
        doc.contains("PB-11"),
        "T8.7 regression policy must define PB-11"
    );
    assert!(doc.contains("T7"), "PB-11 must be associated with track T7");
}

#[test]
fn budget_doc_defines_alarm_bindings() {
    let doc = load_budget_doc();

    assert!(doc.contains("AL-01"), "must reference alarm AL-01");
    assert!(doc.contains("AL-02"), "must reference alarm AL-02");
    assert!(
        doc.contains("AL-09"),
        "must define new alarm AL-09 for invariant gates"
    );
}

#[test]
fn budget_doc_requires_artifact_outputs() {
    let doc = load_budget_doc();

    assert!(
        doc.contains("tokio_adapter_performance_budgets_manifest.json"),
        "must require JSON manifest artifact"
    );
    assert!(
        doc.contains("tokio_adapter_performance_budgets_report.md"),
        "must require markdown report artifact"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// 9. CROSS-REFERENCE VALIDATION
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn budget_doc_downstream_bindings_reference_valid_beads() {
    let doc = load_budget_doc();

    let downstream_beads = [
        "asupersync-2oh2u.7.9",
        "asupersync-2oh2u.7.10",
        "asupersync-2oh2u.10.7",
        "asupersync-2oh2u.10.12",
    ];

    for bead in &downstream_beads {
        assert!(
            doc.contains(bead),
            "budget doc must reference downstream bead: {bead}"
        );
    }
}

#[test]
fn nf_criteria_doc_has_nf28_section() {
    let doc = load_nf_criteria_doc();
    assert!(
        doc.contains("NF28"),
        "nonfunctional criteria doc must have NF28 section"
    );
}

#[test]
fn budget_doc_benchmark_suite_mapping_complete() {
    let doc = load_budget_doc();

    let suites = [
        "interop_tower",
        "interop_hyper",
        "interop_body",
        "interop_io",
        "interop_cancel",
        "interop_blocking",
    ];

    for suite in &suites {
        assert!(
            doc.contains(suite),
            "budget doc must map benchmark suite: {suite}"
        );
    }
}

#[test]
fn budget_doc_measurement_methodology_aligns_with_nf_criteria() {
    let doc = load_budget_doc();

    // Must reference the same measurement framework.
    assert!(
        doc.contains("Release profile") || doc.contains("release"),
        "must reference release profile"
    );
    assert!(doc.contains("LTO"), "must reference LTO-enabled builds");
    assert!(
        doc.contains("warmup") || doc.contains("Warmup"),
        "must reference warmup iterations"
    );
    assert!(
        doc.contains("Median") || doc.contains("median"),
        "must reference median-of-runs methodology"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// 10. BOUNDARY ARCHITECTURE CONSISTENCY
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn budget_thresholds_align_with_boundary_architecture_invariants() {
    let boundary = load_boundary_doc();
    let budget = load_budget_doc();

    // Both docs must reference the same five invariants.
    for i in 1..=5 {
        let inv = format!("INV-{i}");
        assert!(boundary.contains(&inv), "boundary doc missing {inv}");
        assert!(budget.contains(&inv), "budget doc missing {inv}");
    }
}

#[test]
fn budget_doc_feature_gates_match_cargo_toml() {
    let doc = load_budget_doc();

    // Verify feature gate references match actual Cargo.toml features.
    let cargo_toml = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("asupersync-tokio-compat/Cargo.toml"),
    )
    .expect("compat Cargo.toml must exist");

    if cargo_toml.contains("hyper-bridge") {
        assert!(
            doc.contains("hyper-bridge"),
            "budget doc must reference hyper-bridge feature"
        );
    }
    if cargo_toml.contains("tower-bridge") {
        assert!(
            doc.contains("tower-bridge"),
            "budget doc must reference tower-bridge feature"
        );
    }
}

#[test]
fn all_adapter_modules_have_corresponding_contracts() {
    let doc = load_budget_doc();

    // Each adapter module must have a corresponding correctness contract section.
    let module_contract_pairs = [
        ("cancel", "CancelAware Contracts"),
        ("blocking", "Blocking Bridge Contracts"),
        ("body_bridge", "Body Bridge Contracts"),
        ("tower_bridge", "Tower Bridge Contracts"),
        ("io", "I/O Bridge Contracts"),
        ("hyper_bridge", "Hyper Bridge Contracts"),
    ];

    for (module, section) in &module_contract_pairs {
        assert!(
            doc.contains(section),
            "budget doc missing correctness contract section for {module}: expected '{section}'"
        );
    }
}

#[test]
fn budget_doc_has_no_deferred_or_tbd_markers() {
    let doc = load_budget_doc();

    assert!(
        !doc.contains("[DEFERRED]"),
        "budget doc must not contain [DEFERRED] markers"
    );
    assert!(
        !doc.contains("[TBD]"),
        "budget doc must not contain [TBD] markers"
    );
    assert!(
        !doc.contains("[TODO]"),
        "budget doc must not contain [TODO] markers"
    );
}
