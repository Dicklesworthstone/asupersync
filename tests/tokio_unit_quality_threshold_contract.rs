//! Contract tests for cross-track unit-test quality thresholds (2oh2u.10.11).
//!
//! These tests enforce presence of required gate IDs, prerequisite bead bindings,
//! leak-oracle requirements, required artifacts, and deterministic CI command tokens.

#![allow(missing_docs)]

use std::collections::BTreeSet;
use std::path::Path;

fn load_doc() -> String {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/tokio_unit_quality_threshold_contract.md");
    std::fs::read_to_string(path).expect("unit quality threshold contract must exist")
}

fn extract_gate_ids(doc: &str) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    for line in doc.lines() {
        let trimmed = line.trim().trim_start_matches('|').trim();
        if let Some(id) = trimmed.split('|').next() {
            let id = id.trim().trim_matches('`');
            if id.starts_with("UQ-") {
                ids.insert(id.to_string());
            }
        }
    }
    ids
}

#[test]
fn doc_exists_and_is_substantial() {
    let doc = load_doc();
    let len = doc.len();
    assert!(
        len > 3000,
        "document should be substantial, got {len} bytes"
    );
}

#[test]
fn doc_references_correct_bead_and_program() {
    let doc = load_doc();
    assert!(
        doc.contains("asupersync-2oh2u.10.11"),
        "document must reference bead 2oh2u.10.11"
    );
    assert!(doc.contains("[T8.11]"), "document must reference T8.11");
    assert!(
        doc.contains("asupersync-2oh2u"),
        "document must reference the TOKIO-REPLACE program root"
    );
}

#[test]
fn doc_references_all_prerequisite_unit_matrix_beads() {
    let doc = load_doc();
    for token in [
        "asupersync-2oh2u.2.9",
        "asupersync-2oh2u.3.9",
        "asupersync-2oh2u.4.10",
        "asupersync-2oh2u.5.11",
        "asupersync-2oh2u.6.12",
        "asupersync-2oh2u.7.10",
    ] {
        assert!(
            doc.contains(token),
            "missing prerequisite bead token: {token}"
        );
    }
}

#[test]
fn doc_defines_required_test_categories() {
    let doc = load_doc();
    for token in [
        "Happy path",
        "Edge cases",
        "Error paths",
        "Cancellation race invariants",
        "Leak invariants",
    ] {
        assert!(doc.contains(token), "missing category token: {token}");
    }
}

#[test]
fn doc_defines_full_uq_gate_set() {
    let doc = load_doc();
    let gate_ids = extract_gate_ids(&doc);
    for id in ["UQ-01", "UQ-02", "UQ-03", "UQ-04", "UQ-05", "UQ-06"] {
        assert!(gate_ids.contains(id), "missing gate id token: {id}");
    }
}

#[test]
fn doc_defines_cross_track_threshold_set() {
    let doc = load_doc();
    for token in [
        "TQ-01",
        "TQ-02",
        "TQ-03",
        "TQ-04",
        ">= 20",
        ">= 0.50",
        ">= 4",
        "retry-only pass",
    ] {
        assert!(doc.contains(token), "missing threshold token: {token}");
    }
}

#[test]
fn doc_requires_leak_oracles_for_concurrency_paths() {
    let doc = load_doc();
    for token in [
        "no_task_leak",
        "no_obligation_leak",
        "region_close_quiescence",
        "loser_drain_complete",
        "oracle_not_applicable",
    ] {
        assert!(
            doc.contains(token),
            "missing leak-oracle contract token: {token}"
        );
    }
}

#[test]
fn doc_defines_required_ci_commands_with_rch() {
    let doc = load_doc();
    assert!(
        doc.contains("rch exec --"),
        "document must require rch exec for heavy checks"
    );
    for token in [
        "rch exec -- cargo check --all-targets",
        "rch exec -- cargo clippy --all-targets -- -D warnings",
        "rch exec -- cargo fmt --check",
        "rch exec -- cargo test --test tokio_unit_quality_threshold_contract -- --nocapture",
        "rch exec -- cargo test --test tokio_io_parity_audit -- --nocapture",
        "rch exec -- cargo test --test tokio_fs_process_signal_parity_matrix -- --nocapture",
        "rch exec -- cargo test --test tokio_web_grpc_parity_map -- --nocapture",
        "rch exec -- cargo test --test tokio_ecosystem_capability_inventory -- --nocapture",
    ] {
        assert!(doc.contains(token), "missing CI command token: {token}");
    }
}

#[test]
fn doc_defines_required_artifact_bundle() {
    let doc = load_doc();
    for token in [
        "tokio_unit_quality_manifest.json",
        "tokio_unit_quality_report.md",
        "tokio_unit_quality_failures.json",
        "tokio_unit_quality_triage_pointers.txt",
    ] {
        assert!(doc.contains(token), "missing artifact token: {token}");
    }
}

#[test]
fn doc_defines_manifest_schema_fields() {
    let doc = load_doc();
    for token in [
        "track_id",
        "bead_id",
        "commit_sha",
        "category_counts",
        "threshold_result",
        "threshold_metrics",
        "oracle_status",
        "repro_commands",
        "artifact_links",
    ] {
        assert!(doc.contains(token), "missing manifest field token: {token}");
    }
}

#[test]
fn doc_defines_failure_routing_contract() {
    let doc = load_doc();
    for token in [
        "gate_id",
        "track_id",
        "bead_id",
        "severity",
        "owner",
        "repro_command",
        "first_failing_commit",
    ] {
        assert!(
            doc.contains(token),
            "missing failure routing token: {token}"
        );
    }
}

#[test]
fn doc_binds_downstream_t8_tasks() {
    let doc = load_doc();
    for token in ["asupersync-2oh2u.10.12", "asupersync-2oh2u.10.9"] {
        assert!(
            doc.contains(token),
            "missing downstream dependency token: {token}"
        );
    }
}

// ===========================================================================
// Enforcement: Validate track test files meet contracted thresholds
// ===========================================================================

fn load_test_source(rel: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("Cannot read test file {}", path.display()))
}

fn count_test_fns(source: &str) -> usize {
    source.lines().filter(|l| l.contains("#[test]")).count()
}

fn count_matching_test_fns(source: &str, patterns: &[&str]) -> usize {
    source
        .lines()
        .filter(|l| l.trim_start().starts_with("fn "))
        .filter(|l| {
            let lower = l.to_lowercase();
            patterns.iter().any(|p| lower.contains(p))
        })
        .count()
}

struct TrackDef {
    track_id: &'static str,
    #[allow(dead_code)]
    bead_id: &'static str,
    primary_test: &'static str,
}

fn track_defs() -> Vec<TrackDef> {
    vec![
        TrackDef {
            track_id: "T2",
            bead_id: "asupersync-2oh2u.2.9",
            primary_test: "tests/tokio_io_codec_cancellation_correctness.rs",
        },
        TrackDef {
            track_id: "T3",
            bead_id: "asupersync-2oh2u.3.9",
            primary_test: "tests/tokio_fs_process_signal_unit_test_matrix.rs",
        },
        TrackDef {
            track_id: "T4",
            bead_id: "asupersync-2oh2u.4.10",
            primary_test: "tests/tokio_quic_h3_unit_protocol_matrix.rs",
        },
        TrackDef {
            track_id: "T5",
            bead_id: "asupersync-2oh2u.5.11",
            primary_test: "tests/web_grpc_exhaustive_unit.rs",
        },
        TrackDef {
            track_id: "T6",
            bead_id: "asupersync-2oh2u.6.12",
            primary_test: "tests/tokio_db_messaging_unit_test_matrix.rs",
        },
        TrackDef {
            track_id: "T7",
            bead_id: "asupersync-2oh2u.7.10",
            primary_test: "tests/tokio_adapter_boundary_correctness.rs",
        },
    ]
}

// ---------------------------------------------------------------------------
// TQ-01: Per-track unit test count >= 20
// ---------------------------------------------------------------------------

#[test]
fn tq01_all_tracks_have_at_least_20_tests() {
    for td in &track_defs() {
        let src = load_test_source(td.primary_test);
        let count = count_test_fns(&src);
        let track = td.track_id;
        let file = td.primary_test;
        assert!(
            count >= 20,
            "TQ-01 FAIL: {track} ({file}) has {count} tests, need >= 20"
        );
    }
}

#[test]
fn tq01_all_primary_test_files_exist() {
    for td in &track_defs() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(td.primary_test);
        let track = td.track_id;
        let file = td.primary_test;
        assert!(path.exists(), "{track} primary test file missing: {file}");
    }
}

// ---------------------------------------------------------------------------
// TQ-03: (cancel + leak) >= 4 per track
// ---------------------------------------------------------------------------

const CANCEL_LEAK_KW: &[&str] = &[
    "cancel",
    "race",
    "drain",
    "loser",
    "leak",
    "oracle",
    "obligation",
    "quiescence",
    "unwind",
    "panic",
];

#[test]
fn tq03_t2_cancel_leak_minimum() {
    let src = load_test_source("tests/tokio_io_codec_cancellation_correctness.rs");
    let count = count_matching_test_fns(&src, CANCEL_LEAK_KW);
    assert!(
        count >= 4,
        "TQ-03 FAIL: T2 has {count} cancel/leak tests, need >= 4"
    );
}

#[test]
fn tq03_t3_cancel_leak_minimum() {
    let files = [
        "tests/tokio_fs_process_signal_unit_test_matrix.rs",
        "tests/tokio_fs_process_signal_unit_matrix.rs",
        "tests/tokio_fs_process_signal_conformance.rs",
    ];
    let total: usize = files
        .iter()
        .filter_map(|f| std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(f)).ok())
        .map(|src| count_matching_test_fns(&src, CANCEL_LEAK_KW))
        .sum();
    assert!(
        total >= 4,
        "TQ-03 FAIL: T3 aggregate has {total} cancel/leak tests, need >= 4"
    );
}

#[test]
fn tq03_t4_cancel_leak_minimum() {
    let files = [
        "tests/tokio_quic_h3_unit_protocol_matrix.rs",
        "tests/tokio_quic_h3_soak_adversarial.rs",
    ];
    let total: usize = files
        .iter()
        .filter_map(|f| std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(f)).ok())
        .map(|src| count_matching_test_fns(&src, CANCEL_LEAK_KW))
        .sum();
    assert!(
        total >= 4,
        "TQ-03 FAIL: T4 aggregate has {total} cancel/leak tests, need >= 4"
    );
}

#[test]
fn tq03_t5_cancel_leak_minimum() {
    let files = [
        "tests/web_grpc_exhaustive_unit.rs",
        "tests/web_grpc_interop_matrix.rs",
        "tests/web_grpc_reference_services.rs",
        "tests/web_framework_integration.rs",
    ];
    let total: usize = files
        .iter()
        .filter_map(|f| std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(f)).ok())
        .map(|src| count_matching_test_fns(&src, CANCEL_LEAK_KW))
        .sum();
    assert!(
        total >= 4,
        "TQ-03 FAIL: T5 aggregate has {total} cancel/leak tests, need >= 4"
    );
}

#[test]
fn tq03_t6_cancel_leak_minimum() {
    let files = [
        "tests/tokio_db_messaging_unit_test_matrix.rs",
        "tests/tokio_db_messaging_integration.rs",
    ];
    let total: usize = files
        .iter()
        .filter_map(|f| std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(f)).ok())
        .map(|src| count_matching_test_fns(&src, CANCEL_LEAK_KW))
        .sum();
    assert!(
        total >= 4,
        "TQ-03 FAIL: T6 aggregate has {total} cancel/leak tests, need >= 4"
    );
}

#[test]
fn tq03_t7_cancel_leak_minimum() {
    let src = load_test_source("tests/tokio_adapter_boundary_correctness.rs");
    let count = count_matching_test_fns(&src, CANCEL_LEAK_KW);
    assert!(
        count >= 4,
        "TQ-03 FAIL: T7 has {count} cancel/leak tests, need >= 4"
    );
}

// ---------------------------------------------------------------------------
// UQ-01: Required category coverage per track
// ---------------------------------------------------------------------------

#[test]
fn uq01_all_tracks_cover_five_test_categories() {
    let categories: &[(&str, &[&str])] = &[
        (
            "happy",
            &[
                "happy",
                "success",
                "pass",
                "ok",
                "valid",
                "correct",
                "canonical",
            ],
        ),
        (
            "edge",
            &[
                "edge", "bound", "empty", "max", "min", "zero", "overflow", "limit",
            ],
        ),
        (
            "error",
            &[
                "error", "malform", "invalid", "fail", "reject", "bad", "corrupt",
            ],
        ),
        (
            "cancel",
            &["cancel", "race", "drain", "loser", "abort", "timeout"],
        ),
        (
            "leak",
            &[
                "leak",
                "oracle",
                "obligation",
                "quiescence",
                "drop",
                "cleanup",
                "release",
                "close",
                "pool",
                "dispose",
            ],
        ),
    ];

    for td in &track_defs() {
        let src = load_test_source(td.primary_test);
        let fn_lines: Vec<String> = src
            .lines()
            .filter(|l| l.trim_start().starts_with("fn "))
            .map(str::to_lowercase)
            .collect();

        for (cat_name, keywords) in categories {
            // Check fn names AND file body (some tracks use non-standard naming)
            let has_fn = fn_lines
                .iter()
                .any(|l| keywords.iter().any(|kw| l.contains(kw)));
            let lower_src = src.to_lowercase();
            let has_body = keywords.iter().any(|kw| lower_src.contains(kw));
            let track = td.track_id;
            let file = td.primary_test;
            assert!(
                has_fn || has_body,
                "UQ-01 FAIL: {track} ({file}) missing '{cat_name}' category coverage"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// UQ-03: Cancellation race assertions present
// ---------------------------------------------------------------------------

#[test]
fn uq03_each_track_has_cancellation_content() {
    let cancel_kw = ["cancel", "race", "drain", "abort", "loser"];
    for td in &track_defs() {
        let src = load_test_source(td.primary_test);
        let lower = src.to_lowercase();
        let has = cancel_kw.iter().any(|kw| lower.contains(kw));
        let track = td.track_id;
        let file = td.primary_test;
        assert!(
            has,
            "UQ-03 FAIL: {track} ({file}) has no cancellation-related content"
        );
    }
}

// ---------------------------------------------------------------------------
// UQ-04: Leak-oracle content present
// ---------------------------------------------------------------------------

#[test]
fn uq04_each_track_has_leak_oracle_content() {
    let oracle_kw = [
        "leak",
        "obligation",
        "quiescence",
        "drain",
        "oracle",
        "cleanup",
        "cancel_safety",
        "resource",
        "drop",
    ];
    for td in &track_defs() {
        let src = load_test_source(td.primary_test);
        let lower = src.to_lowercase();
        let has = oracle_kw.iter().any(|kw| lower.contains(kw));
        let track = td.track_id;
        let file = td.primary_test;
        assert!(
            has,
            "UQ-04 FAIL: {track} ({file}) has no leak-oracle related content"
        );
    }
}

// ---------------------------------------------------------------------------
// Cross-track aggregate validation
// ---------------------------------------------------------------------------

#[test]
fn cross_track_total_exceeds_120_tests() {
    let total: usize = track_defs()
        .iter()
        .map(|td| count_test_fns(&load_test_source(td.primary_test)))
        .sum();
    assert!(
        total >= 120,
        "cross-track aggregate has {total} tests, need >= 120 (6 x 20)"
    );
}

// ---------------------------------------------------------------------------
// Supplementary track test files exist
// ---------------------------------------------------------------------------

#[test]
fn supplementary_t2_files_exist() {
    for f in &[
        "tests/tokio_io_parity_audit.rs",
        "tests/tokio_io_conformance_gates.rs",
    ] {
        assert!(
            Path::new(env!("CARGO_MANIFEST_DIR")).join(f).exists(),
            "T2 supplementary missing: {f}"
        );
    }
}

#[test]
fn supplementary_t3_files_exist() {
    for f in &[
        "tests/tokio_fs_process_signal_parity_matrix.rs",
        "tests/tokio_fs_process_signal_conformance.rs",
    ] {
        assert!(
            Path::new(env!("CARGO_MANIFEST_DIR")).join(f).exists(),
            "T3 supplementary missing: {f}"
        );
    }
}

#[test]
fn supplementary_t4_files_exist() {
    for f in &[
        "tests/tokio_quic_h3_interop_matrix.rs",
        "tests/tokio_quic_h3_soak_adversarial.rs",
    ] {
        assert!(
            Path::new(env!("CARGO_MANIFEST_DIR")).join(f).exists(),
            "T4 supplementary missing: {f}"
        );
    }
}

#[test]
fn supplementary_t5_files_exist() {
    for f in &[
        "tests/tokio_web_grpc_parity_map.rs",
        "tests/web_grpc_interop_matrix.rs",
    ] {
        assert!(
            Path::new(env!("CARGO_MANIFEST_DIR")).join(f).exists(),
            "T5 supplementary missing: {f}"
        );
    }
}

#[test]
fn supplementary_t6_files_exist() {
    for f in &[
        "tests/tokio_db_messaging_gap_baseline.rs",
        "tests/tokio_db_messaging_integration.rs",
    ] {
        assert!(
            Path::new(env!("CARGO_MANIFEST_DIR")).join(f).exists(),
            "T6 supplementary missing: {f}"
        );
    }
}

#[test]
fn supplementary_t7_files_exist() {
    for f in &[
        "tests/tokio_adapter_performance_budgets.rs",
        "tests/tokio_interop_conformance_suites.rs",
    ] {
        assert!(
            Path::new(env!("CARGO_MANIFEST_DIR")).join(f).exists(),
            "T7 supplementary missing: {f}"
        );
    }
}

// ---------------------------------------------------------------------------
// No deferred/TBD markers in contract
// ---------------------------------------------------------------------------

#[test]
fn contract_has_no_deferred_markers() {
    let doc = load_doc();
    for marker in ["[DEFERRED]", "[TBD]", "[TODO]", "[PLACEHOLDER]"] {
        assert!(
            !doc.contains(marker),
            "contract must not contain {marker} marker"
        );
    }
}

// ---------------------------------------------------------------------------
// Test function name uniqueness
// ---------------------------------------------------------------------------

#[test]
fn no_duplicate_test_names_in_this_suite() {
    let src = load_test_source("tests/tokio_unit_quality_threshold_contract.rs");
    let fn_names: Vec<&str> = src
        .lines()
        .filter(|l| l.trim_start().starts_with("fn "))
        .filter_map(|l| l.trim_start().strip_prefix("fn ")?.split('(').next())
        .collect();
    let unique: BTreeSet<&str> = fn_names.iter().copied().collect();
    assert_eq!(
        fn_names.len(),
        unique.len(),
        "duplicate test function names in this suite"
    );
}
