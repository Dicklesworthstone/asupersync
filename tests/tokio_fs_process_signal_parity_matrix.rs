//! Contract tests for the fs/process/signal parity matrix (2oh2u.3.1).
//!
//! Validates matrix completeness, gap/ownership/evidence mapping, and
//! platform-specific divergence coverage.

#![allow(missing_docs)]

use std::collections::BTreeSet;
use std::path::Path;
use std::path::PathBuf;

use serde_json::Value;

fn load_matrix_doc() -> String {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/tokio_fs_process_signal_parity_matrix.md");
    std::fs::read_to_string(path).expect("matrix document must exist")
}

fn load_matrix_json() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("docs/tokio_fs_process_signal_parity_matrix.json");
    let raw = std::fs::read_to_string(path).expect("json matrix document must exist");
    serde_json::from_str(&raw).expect("json matrix must parse")
}

fn extract_gap_ids(doc: &str) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    for line in doc.lines() {
        let trimmed = line.trim().trim_start_matches('|').trim();
        if let Some(id) = trimmed.split('|').next() {
            let id = id
                .trim()
                .trim_matches('`')
                .trim_matches('*')
                .trim_end_matches(':');
            let prefixes = ["FS-G", "PR-G", "SG-G"];
            if prefixes.iter().any(|p| id.starts_with(p)) && id.len() >= 5 {
                ids.insert(id.to_string());
            }
        }
    }
    ids
}

fn extract_json_gap_ids(json: &Value) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    let gaps = json["gaps"]
        .as_array()
        .expect("json matrix must have array field: gaps");
    for gap in gaps {
        let id = gap["id"]
            .as_str()
            .expect("each gap row must contain string field: id");
        ids.insert(id.to_string());
    }
    ids
}

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn load_source(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|_| panic!("source file must exist: {relative}"))
}

#[test]
fn matrix_document_exists_and_is_substantial() {
    let doc = load_matrix_doc();
    assert!(
        doc.len() > 2000,
        "matrix document should be substantial, got {} bytes",
        doc.len()
    );
}

#[test]
fn matrix_references_correct_bead() {
    let doc = load_matrix_doc();
    assert!(
        doc.contains("asupersync-2oh2u.3.1"),
        "document must reference bead 2oh2u.3.1"
    );
    assert!(doc.contains("[T3.1]"), "document must reference T3.1");
}

#[test]
fn matrix_covers_tokio_fs_process_signal_surfaces() {
    let doc = load_matrix_doc();
    for token in ["tokio::fs", "tokio::process", "tokio::signal"] {
        assert!(doc.contains(token), "matrix must reference {token}");
    }
}

#[test]
fn matrix_covers_expected_asupersync_owner_modules() {
    let doc = load_matrix_doc();
    for token in [
        "src/fs/file.rs",
        "src/fs/path_ops.rs",
        "src/process.rs",
        "src/signal/signal.rs",
        "src/signal/ctrl_c.rs",
        "src/signal/shutdown.rs",
    ] {
        assert!(
            doc.contains(token),
            "matrix missing owner module token: {token}"
        );
    }
}

#[test]
fn matrix_includes_platform_specific_semantics_section() {
    let doc = load_matrix_doc();
    assert!(
        doc.contains("Platform-Specific Semantics Matrix"),
        "must include platform-specific semantics section"
    );
    for token in ["Unix", "Windows", "WASM", "Known Divergence Risk"] {
        assert!(
            doc.contains(token),
            "platform semantics matrix missing token: {token}"
        );
    }
}

#[test]
fn matrix_has_gap_entries_for_all_three_domains() {
    let doc = load_matrix_doc();
    let ids = extract_gap_ids(&doc);

    let domain_prefixes = [("FS-G", 5usize), ("PR-G", 4usize), ("SG-G", 4usize)];
    for (prefix, min_count) in &domain_prefixes {
        let count = ids.iter().filter(|id| id.starts_with(prefix)).count();
        assert!(
            count >= *min_count,
            "domain {prefix} must have >= {min_count} gaps, found {count}"
        );
    }

    assert!(
        ids.len() >= 13,
        "matrix should identify >=13 total gaps, found {}",
        ids.len()
    );
}

#[test]
fn matrix_maps_track_level_gaps_g8_g12_g13() {
    let doc = load_matrix_doc();
    for token in ["G8", "G12", "G13"] {
        assert!(
            doc.contains(token),
            "matrix must map track-level gap token: {token}"
        );
    }
}

#[test]
fn matrix_includes_owner_and_evidence_columns_in_gap_registers() {
    let doc = load_matrix_doc();
    for token in ["Owner Modules", "Evidence Requirements", "Downstream Bead"] {
        assert!(
            doc.contains(token),
            "gap register missing required column token: {token}"
        );
    }
}

#[test]
fn matrix_references_current_evidence_artifacts() {
    let doc = load_matrix_doc();
    for token in [
        "tests/fs_verification.rs",
        "tests/e2e_fs.rs",
        "tests/compile_test_process.rs",
        "tests/e2e_signal.rs",
    ] {
        assert!(
            doc.contains(token),
            "matrix missing evidence token: {token}"
        );
    }
}

#[test]
fn matrix_execution_mapping_points_to_t3_followups() {
    let doc = load_matrix_doc();
    for token in [
        "2oh2u.3.2",
        "2oh2u.3.4",
        "2oh2u.3.5",
        "2oh2u.3.6",
        "2oh2u.3.7",
    ] {
        assert!(
            doc.contains(token),
            "execution mapping missing followup task token: {token}"
        );
    }
}

#[test]
fn json_matrix_exists_and_has_core_fields() {
    let json = load_matrix_json();
    let bead_id = json["bead_id"]
        .as_str()
        .expect("json matrix must contain bead_id");
    assert_eq!(bead_id, "asupersync-2oh2u.3.1");

    let domains = json["domains"]
        .as_array()
        .expect("json matrix must contain domains array");
    let mut found = BTreeSet::new();
    for domain in domains {
        found.insert(domain.as_str().expect("domain values must be strings"));
    }
    for required in ["filesystem", "process", "signal"] {
        assert!(
            found.contains(required),
            "missing required domain: {required}"
        );
    }

    let rules = json["drift_detection_rules"]
        .as_array()
        .expect("json matrix must contain drift_detection_rules array");
    assert!(
        rules.len() >= 5,
        "expected at least 5 drift detection rules, found {}",
        rules.len()
    );
}

#[test]
fn json_and_markdown_gap_ids_stay_in_sync() {
    let doc = load_matrix_doc();
    let json = load_matrix_json();

    let doc_ids = extract_gap_ids(&doc);
    let json_ids = extract_json_gap_ids(&json);

    assert_eq!(
        doc_ids, json_ids,
        "markdown and json gap ids must stay in sync to prevent drift"
    );
}

#[test]
fn json_gap_rows_include_required_fields() {
    let json = load_matrix_json();
    let gaps = json["gaps"]
        .as_array()
        .expect("json matrix must have array field: gaps");
    assert!(
        gaps.len() >= 13,
        "expected at least 13 gap rows, found {}",
        gaps.len()
    );

    for gap in gaps {
        for field in [
            "id",
            "domain",
            "severity",
            "divergence_risk",
            "owner_modules",
            "evidence_requirements",
            "downstream_bead",
        ] {
            assert!(
                gap.get(field).is_some(),
                "gap row missing required field: {field}"
            );
        }
    }
}

#[test]
fn json_owner_and_evidence_paths_exist() {
    let json = load_matrix_json();
    let ownership = json["ownership_matrix"]
        .as_array()
        .expect("json matrix must contain ownership_matrix array");

    for row in ownership {
        let surfaces = row["asupersync_surface"]
            .as_array()
            .expect("ownership row must contain asupersync_surface array");
        for surface in surfaces {
            let p = surface
                .as_str()
                .expect("surface entries must be string paths");
            assert!(
                repo_path(p).exists(),
                "ownership surface path must exist in repository: {p}"
            );
        }

        let evidence = row["existing_evidence"]
            .as_array()
            .expect("ownership row must contain existing_evidence array");
        for artifact in evidence {
            let p = artifact
                .as_str()
                .expect("evidence entries must be string paths");
            assert!(
                repo_path(p).exists(),
                "evidence path must exist in repository: {p}"
            );
        }
    }
}

#[test]
fn matrix_includes_t35_signal_contract_pack_section() {
    let doc = load_matrix_doc();
    for token in [
        "T3.5 Executable Cross-Platform Signal Contract Pack",
        "SGC-01",
        "SGC-02",
        "SGC-03",
        "SGC-04",
        "Pass Criteria",
        "Violation Diagnostics",
        "Repro Command",
        "asupersync-2oh2u.3.5",
    ] {
        assert!(
            doc.contains(token),
            "signal contract pack missing token: {token}"
        );
    }
}

#[test]
fn json_signal_contract_pack_is_complete() {
    let json = load_matrix_json();
    let contracts = json["signal_contracts"]
        .as_array()
        .expect("json must contain signal_contracts array");
    assert!(
        contracts.len() >= 4,
        "expected at least 4 signal contracts, found {}",
        contracts.len()
    );

    let mut ids = BTreeSet::new();
    for contract in contracts {
        let id = contract["id"]
            .as_str()
            .expect("signal contract must include string id");
        ids.insert(id.to_string());
        for field in [
            "bead_id",
            "focus",
            "pass_criteria",
            "failure_semantics",
            "owner_modules",
            "artifacts",
            "contract_tests",
            "reproduction_command",
        ] {
            assert!(
                contract.get(field).is_some(),
                "signal contract {id} missing required field: {field}"
            );
        }

        let bead_id = contract["bead_id"]
            .as_str()
            .expect("signal contract bead_id must be string");
        assert_eq!(
            bead_id, "asupersync-2oh2u.3.5",
            "signal contract {id} must map to bead 2oh2u.3.5"
        );

        let criteria = contract["pass_criteria"]
            .as_array()
            .expect("signal contract pass_criteria must be array");
        assert!(
            !criteria.is_empty(),
            "signal contract {id} must include non-empty pass_criteria"
        );
    }

    for required in ["SGC-01", "SGC-02", "SGC-03", "SGC-04"] {
        assert!(
            ids.contains(required),
            "signal contract pack missing required id: {required}"
        );
    }
}

#[test]
fn json_signal_contract_paths_and_commands_are_valid() {
    let json = load_matrix_json();
    let contracts = json["signal_contracts"]
        .as_array()
        .expect("json must contain signal_contracts array");

    for contract in contracts {
        let id = contract["id"]
            .as_str()
            .expect("signal contract id must be string");

        let owner_modules = contract["owner_modules"]
            .as_array()
            .expect("owner_modules must be array");
        assert!(
            !owner_modules.is_empty(),
            "signal contract {id} must include owner_modules"
        );
        for owner in owner_modules {
            let path = owner.as_str().expect("owner module paths must be strings");
            assert!(
                repo_path(path).exists(),
                "signal contract {id} owner module path must exist: {path}"
            );
        }

        let artifacts = contract["artifacts"]
            .as_array()
            .expect("artifacts must be array");
        assert!(
            !artifacts.is_empty(),
            "signal contract {id} must include artifacts"
        );
        for artifact in artifacts {
            let path = artifact.as_str().expect("artifact paths must be strings");
            assert!(
                repo_path(path).exists(),
                "signal contract {id} artifact path must exist: {path}"
            );
        }

        let tests = contract["contract_tests"]
            .as_array()
            .expect("contract_tests must be array");
        assert!(
            !tests.is_empty(),
            "signal contract {id} must include contract_tests"
        );
        for test_name in tests {
            let test_name = test_name
                .as_str()
                .expect("contract test names must be strings")
                .trim();
            assert!(
                !test_name.is_empty(),
                "signal contract {id} must not contain blank test names"
            );
        }

        let repro = contract["reproduction_command"]
            .as_str()
            .expect("reproduction_command must be string");
        assert!(
            repro.starts_with("rch exec -- "),
            "signal contract {id} reproduction command must route through rch: {repro}"
        );
        assert!(
            repro.contains("cargo test"),
            "signal contract {id} reproduction command must run cargo test: {repro}"
        );
    }
}

#[test]
fn signal_fallback_contract_is_explicit_in_source() {
    let signal_src = load_source("src/signal/signal.rs");
    let ctrl_c_src = load_source("src/signal/ctrl_c.rs");

    for token in [
        "#[cfg(not(unix))]",
        "signal handling is only available on Unix in this build",
    ] {
        assert!(
            signal_src.contains(token),
            "signal source must include explicit fallback token: {token}"
        );
    }

    for token in [
        "#[cfg(not(unix))]",
        "Ctrl+C handling is unavailable on this platform/build",
    ] {
        assert!(
            ctrl_c_src.contains(token),
            "ctrl_c source must include explicit fallback token: {token}"
        );
    }
}

#[test]
fn json_includes_signal_contract_drift_rules() {
    let json = load_matrix_json();
    let rules = json["drift_detection_rules"]
        .as_array()
        .expect("drift_detection_rules must be array");
    let mut ids = BTreeSet::new();
    for rule in rules {
        let id = rule["id"]
            .as_str()
            .expect("drift rule id must be string")
            .to_string();
        ids.insert(id);
    }
    for required in ["T3-DRIFT-06", "T3-DRIFT-07"] {
        assert!(
            ids.contains(required),
            "missing required signal drift rule: {required}"
        );
    }
}
