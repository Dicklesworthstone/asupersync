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

// =============================================================================
// T3.7 Deterministic Conformance and Fault-Injection Contract Tests
// =============================================================================

#[test]
fn matrix_includes_t37_conformance_contract_pack_section() {
    let doc = load_matrix_doc();
    for token in [
        "T3.7 Deterministic Conformance and Fault-Injection Contract Pack",
        "T37C-01",
        "T37C-02",
        "T37C-03",
        "T37C-04",
        "T37C-05",
        "T37C-06",
        "T37C-07",
        "T37C-08",
        "Fault-Injection Scenario Matrix",
        "asupersync-2oh2u.3.7",
    ] {
        assert!(
            doc.contains(token),
            "T3.7 conformance contract pack missing token: {token}"
        );
    }
}

#[test]
fn matrix_t37_covers_all_three_domains() {
    let doc = load_matrix_doc();
    // Section 11 must have subsections for all three domains
    for token in [
        "Filesystem Conformance Contracts",
        "Process Conformance Contracts",
        "Signal Conformance Contracts",
    ] {
        assert!(
            doc.contains(token),
            "T3.7 section missing domain subsection: {token}"
        );
    }
}

#[test]
fn json_conformance_contracts_are_complete() {
    let json = load_matrix_json();
    let contracts = json["conformance_contracts"]
        .as_array()
        .expect("json must contain conformance_contracts array");
    assert!(
        contracts.len() >= 8,
        "expected at least 8 conformance contracts, found {}",
        contracts.len()
    );

    let mut ids = BTreeSet::new();
    for contract in contracts {
        let id = contract["id"]
            .as_str()
            .expect("conformance contract must include string id");
        ids.insert(id.to_string());
        for field in [
            "bead_id",
            "domain",
            "focus",
            "pass_criteria",
            "failure_semantics",
            "owner_modules",
            "artifacts",
            "contract_tests",
            "mapped_gap",
            "reproduction_command",
        ] {
            assert!(
                contract.get(field).is_some(),
                "conformance contract {id} missing required field: {field}"
            );
        }

        let bead_id = contract["bead_id"]
            .as_str()
            .expect("conformance contract bead_id must be string");
        assert_eq!(
            bead_id, "asupersync-2oh2u.3.7",
            "conformance contract {id} must map to bead 2oh2u.3.7"
        );

        let criteria = contract["pass_criteria"]
            .as_array()
            .expect("conformance contract pass_criteria must be array");
        assert!(
            !criteria.is_empty(),
            "conformance contract {id} must include non-empty pass_criteria"
        );
    }

    for required in [
        "T37C-01", "T37C-02", "T37C-03", "T37C-04", "T37C-05", "T37C-06", "T37C-07", "T37C-08",
    ] {
        assert!(
            ids.contains(required),
            "conformance contract pack missing required id: {required}"
        );
    }
}

#[test]
fn json_conformance_contract_paths_and_commands_are_valid() {
    let json = load_matrix_json();
    let contracts = json["conformance_contracts"]
        .as_array()
        .expect("json must contain conformance_contracts array");

    for contract in contracts {
        let id = contract["id"]
            .as_str()
            .expect("conformance contract id must be string");

        let owner_modules = contract["owner_modules"]
            .as_array()
            .expect("owner_modules must be array");
        assert!(
            !owner_modules.is_empty(),
            "conformance contract {id} must include owner_modules"
        );
        for owner in owner_modules {
            let path = owner.as_str().expect("owner module paths must be strings");
            assert!(
                repo_path(path).exists(),
                "conformance contract {id} owner module path must exist: {path}"
            );
        }

        let artifacts = contract["artifacts"]
            .as_array()
            .expect("artifacts must be array");
        assert!(
            !artifacts.is_empty(),
            "conformance contract {id} must include artifacts"
        );
        for artifact in artifacts {
            let path = artifact.as_str().expect("artifact paths must be strings");
            assert!(
                repo_path(path).exists(),
                "conformance contract {id} artifact path must exist: {path}"
            );
        }

        let repro = contract["reproduction_command"]
            .as_str()
            .expect("reproduction_command must be string");
        assert!(
            repro.starts_with("rch exec -- "),
            "conformance contract {id} reproduction command must route through rch: {repro}"
        );
        assert!(
            repro.contains("cargo test"),
            "conformance contract {id} reproduction command must run cargo test: {repro}"
        );
    }
}

#[test]
fn json_conformance_contracts_cover_all_domains() {
    let json = load_matrix_json();
    let contracts = json["conformance_contracts"]
        .as_array()
        .expect("json must contain conformance_contracts array");

    let mut domains = BTreeSet::new();
    for contract in contracts {
        let domain = contract["domain"]
            .as_str()
            .expect("conformance contract must include domain");
        domains.insert(domain.to_string());
    }

    for required in ["filesystem", "process", "signal"] {
        assert!(
            domains.contains(required),
            "conformance contracts missing domain coverage: {required}"
        );
    }
}

#[test]
fn json_conformance_contracts_map_to_known_gaps() {
    let json = load_matrix_json();
    let contracts = json["conformance_contracts"]
        .as_array()
        .expect("json must contain conformance_contracts array");

    let gap_ids = extract_json_gap_ids(&json);
    for contract in contracts {
        let id = contract["id"].as_str().expect("contract must have id");
        let gap = contract["mapped_gap"]
            .as_str()
            .expect("conformance contract must include mapped_gap");
        assert!(
            gap_ids.contains(gap),
            "conformance contract {id} mapped_gap {gap} not found in gap register"
        );
    }
}

#[test]
fn json_fault_injection_scenarios_are_complete() {
    let json = load_matrix_json();
    let scenarios = json["fault_injection_scenarios"]
        .as_array()
        .expect("json must contain fault_injection_scenarios array");
    assert!(
        scenarios.len() >= 8,
        "expected at least 8 fault injection scenarios, found {}",
        scenarios.len()
    );

    let mut ids = BTreeSet::new();
    for scenario in scenarios {
        let id = scenario["id"]
            .as_str()
            .expect("fault injection scenario must include string id");
        ids.insert(id.to_string());
        for field in [
            "domain",
            "injection_point",
            "expected_behavior",
            "owner_module",
            "mapped_gap",
        ] {
            assert!(
                scenario.get(field).is_some(),
                "fault injection scenario {id} missing required field: {field}"
            );
        }
    }

    for required in [
        "FI-01", "FI-02", "FI-03", "FI-04", "FI-05", "FI-06", "FI-07", "FI-08",
    ] {
        assert!(
            ids.contains(required),
            "fault injection scenarios missing required id: {required}"
        );
    }
}

#[test]
fn json_includes_t37_drift_rules() {
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
    for required in ["T3-DRIFT-08", "T3-DRIFT-09"] {
        assert!(
            ids.contains(required),
            "missing required T3.7 drift rule: {required}"
        );
    }
}

// Source verification: confirm source modules contain the conformance-relevant
// types, traits, and APIs referenced by the T3.7 contracts.

#[test]
fn t37c_01_vfs_deterministic_seam() {
    let vfs_src = load_source("src/fs/vfs.rs");
    for token in [
        "pub trait VfsFile",
        "AsyncRead",
        "AsyncWrite",
        "AsyncSeek",
        "Send",
        "Unpin",
        "pub trait Vfs",
        "Sync",
        "pub struct UnixVfs",
        "io::Result",
    ] {
        assert!(
            vfs_src.contains(token),
            "[T37C-01/FS-G3] VFS deterministic seam: src/fs/vfs.rs missing token: {token}"
        );
    }
    // VFS methods that enable fault injection (all return io::Result)
    for method in [
        "fn open",
        "fn metadata",
        "fn create_dir",
        "fn remove_file",
        "fn rename",
    ] {
        assert!(
            vfs_src.contains(method),
            "[T37C-01/FS-G3] VFS trait missing method: {method}"
        );
    }
}

#[test]
fn t37c_02_fs_cancel_safety_protocol() {
    let file_src = load_source("src/fs/file.rs");
    let mod_src = load_source("src/fs/mod.rs");

    // File type with core async operations
    for token in [
        "pub struct File",
        "fn open",
        "fn create",
        "sync_all",
        "sync_data",
    ] {
        assert!(
            file_src.contains(token),
            "[T37C-02/FS-G2] FS cancel-safety: src/fs/file.rs missing token: {token}"
        );
    }

    // WritePermit documented as cancel-safety pattern
    assert!(
        mod_src.contains("WritePermit"),
        "[T37C-02/FS-G2] FS cancel-safety: src/fs/mod.rs must document WritePermit pattern"
    );
}

#[test]
fn t37c_03_atomic_write_error_fidelity() {
    let path_ops_src = load_source("src/fs/path_ops.rs");
    let mod_src = load_source("src/fs/mod.rs");

    assert!(
        path_ops_src.contains("write_atomic"),
        "[T37C-03/FS-G1] atomic write: src/fs/path_ops.rs must contain write_atomic"
    );
    assert!(
        mod_src.contains("try_exists"),
        "[T37C-03/FS-G1] error fidelity: src/fs/mod.rs must export try_exists"
    );
    // write_atomic should use temp file + rename pattern
    assert!(
        path_ops_src.contains("rename") || path_ops_src.contains("persist"),
        "[T37C-03/FS-G1] write_atomic should use rename/persist for atomicity"
    );
}

#[test]
fn t37c_04_process_lifecycle_protocol() {
    let process_src = load_source("src/process.rs");

    // Command builder API surface
    for token in [
        "pub struct Command",
        "fn new<",
        "fn arg(",
        "fn args(",
        "fn env(",
        "fn current_dir(",
        "fn stdin(",
        "fn stdout(",
        "fn stderr(",
        "fn kill_on_drop(",
        "fn spawn(",
    ] {
        assert!(
            process_src.contains(token),
            "[T37C-04/PR-G1] process lifecycle: src/process.rs missing Command method: {token}"
        );
    }

    // Child handle API surface
    for token in [
        "pub struct Child",
        "fn id(",
        "fn kill(",
        "fn try_wait(",
        "wait_async",
    ] {
        assert!(
            process_src.contains(token),
            "[T37C-04/PR-G1] process lifecycle: src/process.rs missing Child method: {token}"
        );
    }

    // ExitStatus and Stdio
    for token in ["ExitStatus", "fn code(", "fn success(", "Stdio"] {
        assert!(
            process_src.contains(token),
            "[T37C-04/PR-G1] process lifecycle: src/process.rs missing type: {token}"
        );
    }
}

#[test]
fn t37c_05_process_kill_on_drop() {
    let process_src = load_source("src/process.rs");

    assert!(
        process_src.contains("kill_on_drop"),
        "[T37C-05/PR-G4] kill_on_drop: src/process.rs must contain kill_on_drop"
    );
    assert!(
        process_src.contains("fn kill("),
        "[T37C-05/PR-G4] kill_on_drop: src/process.rs must contain Child::kill"
    );
    // Drop impl should handle kill_on_drop
    assert!(
        process_src.contains("impl Drop for Child") || process_src.contains("fn drop("),
        "[T37C-05/PR-G4] kill_on_drop: src/process.rs must implement Drop for Child cleanup"
    );
}

#[test]
fn t37c_06_process_error_classification() {
    let process_src = load_source("src/process.rs");

    for token in [
        "pub enum ProcessError",
        "NotFound(",
        "PermissionDenied(",
        "Signaled(",
    ] {
        assert!(
            process_src.contains(token),
            "[T37C-06/PR-G3] error classification: src/process.rs missing variant: {token}"
        );
    }

    // Error mapping from spawn
    assert!(
        process_src.contains("ErrorKind::NotFound"),
        "[T37C-06/PR-G3] src/process.rs must map ENOENT to NotFound"
    );
    assert!(
        process_src.contains("ErrorKind::PermissionDenied"),
        "[T37C-06/PR-G3] src/process.rs must map EACCES to PermissionDenied"
    );
}

#[test]
fn t37c_07_signal_delivery_monotonicity() {
    let signal_src = load_source("src/signal/signal.rs");
    let kind_src = load_source("src/signal/kind.rs");

    // Delivery counter monotonicity
    assert!(
        signal_src.contains("AtomicU64"),
        "[T37C-07/SG-G3] delivery monotonicity: src/signal/signal.rs must use AtomicU64"
    );
    assert!(
        signal_src.contains("fetch_add"),
        "[T37C-07/SG-G3] delivery monotonicity: src/signal/signal.rs must use fetch_add"
    );
    assert!(
        signal_src.contains("seen_deliveries"),
        "[T37C-07/SG-G3] delivery tracking: src/signal/signal.rs must track seen_deliveries"
    );
    assert!(
        signal_src.contains("pub async fn recv"),
        "[T37C-07/SG-G3] Signal::recv must exist"
    );

    // SignalKind coverage
    for variant in [
        "Interrupt",
        "Terminate",
        "Hangup",
        "Quit",
        "User1",
        "User2",
        "Child",
        "Pipe",
        "Alarm",
    ] {
        assert!(
            kind_src.contains(variant),
            "[T37C-07/SG-G3] SignalKind missing variant: {variant}"
        );
    }
}

#[test]
fn t37c_08_shutdown_convergence() {
    let shutdown_src = load_source("src/signal/shutdown.rs");
    let graceful_src = load_source("src/signal/graceful.rs");

    // ShutdownController API
    for token in [
        "pub struct ShutdownController",
        "fn new(",
        "fn subscribe(",
        "fn shutdown(",
    ] {
        assert!(
            shutdown_src.contains(token),
            "[T37C-08/SG-G4] shutdown convergence: src/signal/shutdown.rs missing: {token}"
        );
    }

    // ShutdownReceiver API
    for token in [
        "pub struct ShutdownReceiver",
        "pub async fn wait(",
        "fn is_shutting_down(",
    ] {
        assert!(
            shutdown_src.contains(token),
            "[T37C-08/SG-G4] shutdown convergence: src/signal/shutdown.rs missing: {token}"
        );
    }

    // GracefulOutcome API
    for token in [
        "pub enum GracefulOutcome",
        "Completed(",
        "ShutdownSignaled",
        "pub async fn with_graceful_shutdown",
    ] {
        assert!(
            graceful_src.contains(token),
            "[T37C-08/SG-G4] graceful outcome: src/signal/graceful.rs missing: {token}"
        );
    }
}

#[test]
fn matrix_t37_has_evidence_commands() {
    let doc = load_matrix_doc();
    // All repro commands are rch-routed
    assert!(
        doc.contains("rch exec -- cargo test --test tokio_fs_process_signal_parity_matrix t37c"),
        "T3.7 section must include rch-routed conformance test command"
    );
    // Deterministic replay command for full suite
    assert!(
        doc.contains(
            "rch exec -- cargo test --test tokio_fs_process_signal_parity_matrix -- --nocapture"
        ),
        "T3.7 section must include full suite replay command"
    );
}
