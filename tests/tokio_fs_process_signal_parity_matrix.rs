#![allow(warnings)]
#![allow(clippy::all)]
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
        "#[cfg(not(any(unix, windows)))]",
        "signal handling is unavailable on this platform/build",
    ] {
        assert!(
            signal_src.contains(token),
            "signal source must include explicit fallback token: {token}"
        );
    }

    for token in [
        "#[cfg(not(any(unix, windows)))]",
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

    // Command builder API surface — methods may have generics so match on "fn name"
    for method in [
        "pub struct Command",
        "fn new",
        "fn arg",
        "fn args",
        "fn env",
        "fn current_dir",
        "fn stdin",
        "fn stdout",
        "fn stderr",
        "fn kill_on_drop",
        "fn spawn",
    ] {
        assert!(
            process_src.contains(method),
            "[T37C-04/PR-G1] process lifecycle: src/process.rs missing Command method: {method}"
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

// =============================================================================
// T3.9 Exhaustive Unit-Test Coverage Matrix Contract Tests
// =============================================================================

#[test]
fn matrix_includes_t39_unit_test_matrix_section() {
    let doc = load_matrix_doc();
    for token in [
        "T3.9 Exhaustive Unit-Test Coverage Matrix",
        "asupersync-2oh2u.3.9",
        "Test File Inventory",
        "Inline Unit-Test Inventory",
        "Coverage Matrix by Domain",
        "Bead-to-Test Traceability Matrix",
        "CI Enforcement Thresholds",
        "Deterministic Replay Commands",
    ] {
        assert!(
            doc.contains(token),
            "T3.9 unit-test matrix section missing token: {token}"
        );
    }
}

#[test]
fn t39_test_file_inventory_covers_all_files() {
    let doc = load_matrix_doc();
    let required_files = [
        "tests/fs_verification.rs",
        "tests/e2e_fs.rs",
        "tests/compile_test_process.rs",
        "tests/e2e_signal.rs",
        "tests/process_lifecycle_hardening.rs",
        "tests/tokio_process_lifecycle_parity.rs",
        "tests/tokio_cancel_safe_fs_process_signal.rs",
        "tests/tokio_fs_process_signal_conformance.rs",
        "tests/tokio_fs_process_signal_conformance_faults.rs",
        "tests/tokio_fs_process_signal_parity_matrix.rs",
    ];
    for file in &required_files {
        assert!(
            doc.contains(file),
            "T3.9 inventory missing test file: {file}"
        );
    }
    // All listed files must exist in the repo
    for file in &required_files {
        assert!(
            repo_path(file).exists(),
            "T3.9 test file must exist in repository: {file}"
        );
    }
}

#[test]
fn t39_inline_test_modules_exist() {
    let required_modules = [
        "src/fs/file.rs",
        "src/fs/vfs.rs",
        "src/fs/path_ops.rs",
        "src/fs/dir.rs",
        "src/fs/read_dir.rs",
        "src/fs/open_options.rs",
        "src/fs/metadata.rs",
        "src/process.rs",
        "src/signal/signal.rs",
        "src/signal/ctrl_c.rs",
        "src/signal/kind.rs",
        "src/signal/shutdown.rs",
        "src/signal/graceful.rs",
    ];
    for module in &required_modules {
        assert!(
            repo_path(module).exists(),
            "T3.9 inline test module must exist: {module}"
        );
    }
}

#[test]
fn t39_inline_modules_contain_tests() {
    let modules_with_min_tests = [
        ("src/fs/file.rs", 5),
        ("src/fs/vfs.rs", 8),
        ("src/fs/path_ops.rs", 8),
        ("src/process.rs", 15),
        ("src/signal/shutdown.rs", 7),
        ("src/signal/graceful.rs", 14),
    ];
    for (module, min) in &modules_with_min_tests {
        let src = load_source(module);
        let count = src.matches("#[test]").count();
        assert!(
            count >= *min,
            "T3.9: {module} must have >= {min} inline tests, found {count}"
        );
    }
}

#[test]
fn t39_bead_traceability_covers_t33_through_t37() {
    let doc = load_matrix_doc();
    for bead in ["T3.3", "T3.4", "T3.5", "T3.6", "T3.7"] {
        assert!(
            doc.contains(bead),
            "T3.9 bead traceability missing coverage for {bead}"
        );
    }
    for bead_id in [
        "2oh2u.3.3",
        "2oh2u.3.4",
        "2oh2u.3.5",
        "2oh2u.3.6",
        "2oh2u.3.7",
    ] {
        assert!(
            doc.contains(bead_id),
            "T3.9 bead traceability missing bead ID: {bead_id}"
        );
    }
}

#[test]
fn json_unit_test_matrix_is_complete() {
    let json = load_matrix_json();
    let matrix = &json["unit_test_matrix"];
    assert!(
        matrix.is_object(),
        "json must contain unit_test_matrix object"
    );

    let bead_id = matrix["bead_id"]
        .as_str()
        .expect("unit_test_matrix must have bead_id");
    assert_eq!(bead_id, "asupersync-2oh2u.3.9");

    let test_files = matrix["test_files"]
        .as_array()
        .expect("unit_test_matrix must have test_files array");
    assert!(
        test_files.len() >= 10,
        "expected at least 10 test files, found {}",
        test_files.len()
    );

    for entry in test_files {
        for field in [
            "file",
            "bead",
            "domain",
            "category",
            "test_count",
            "scenario_prefix",
        ] {
            assert!(
                entry.get(field).is_some(),
                "test file entry missing field: {field}"
            );
        }
        let file = entry["file"].as_str().expect("file must be string");
        assert!(
            repo_path(file).exists(),
            "unit_test_matrix test file must exist: {file}"
        );
    }
}

#[test]
fn json_unit_test_matrix_inline_tests_valid() {
    let json = load_matrix_json();
    let inline = json["unit_test_matrix"]["inline_tests"]
        .as_array()
        .expect("unit_test_matrix must have inline_tests array");
    assert!(
        inline.len() >= 13,
        "expected at least 13 inline test modules, found {}",
        inline.len()
    );

    for entry in inline {
        let module = entry["module"]
            .as_str()
            .expect("inline test module must be string");
        assert!(
            repo_path(module).exists(),
            "inline test module must exist: {module}"
        );
        let count = entry["test_count"]
            .as_u64()
            .expect("test_count must be integer");
        assert!(
            count >= 2,
            "inline test module {module} must have >= 2 tests, declared {count}"
        );
    }
}

#[test]
fn json_unit_test_matrix_bead_coverage_complete() {
    let json = load_matrix_json();
    let coverage = json["unit_test_matrix"]["bead_coverage"]
        .as_array()
        .expect("unit_test_matrix must have bead_coverage array");
    assert!(
        coverage.len() >= 5,
        "expected at least 5 bead coverage entries, found {}",
        coverage.len()
    );

    let mut covered_beads = BTreeSet::new();
    for entry in coverage {
        let bead = entry["bead"]
            .as_str()
            .expect("bead_coverage entry must have bead string");
        covered_beads.insert(bead.to_string());

        let test_files = entry["test_files"]
            .as_array()
            .expect("bead_coverage entry must have test_files array");
        assert!(
            !test_files.is_empty(),
            "bead {bead} must have at least one test file"
        );
        for tf in test_files {
            let path = tf.as_str().expect("test file path must be string");
            assert!(
                repo_path(path).exists(),
                "bead {bead} test file must exist: {path}"
            );
        }
    }

    for required in [
        "asupersync-2oh2u.3.3",
        "asupersync-2oh2u.3.4",
        "asupersync-2oh2u.3.5",
        "asupersync-2oh2u.3.6",
        "asupersync-2oh2u.3.7",
    ] {
        assert!(
            covered_beads.contains(required),
            "bead coverage missing required bead: {required}"
        );
    }
}

#[test]
fn json_unit_test_matrix_ci_thresholds_defined() {
    let json = load_matrix_json();
    let thresholds = &json["unit_test_matrix"]["ci_thresholds"];
    assert!(
        thresholds.is_object(),
        "unit_test_matrix must have ci_thresholds object"
    );

    let min_integration = thresholds["min_integration_tests"]
        .as_u64()
        .expect("min_integration_tests must be integer");
    assert!(
        min_integration >= 280,
        "min_integration_tests must be >= 280, got {min_integration}"
    );

    let min_inline = thresholds["min_inline_tests"]
        .as_u64()
        .expect("min_inline_tests must be integer");
    assert!(
        min_inline >= 100,
        "min_inline_tests must be >= 100, got {min_inline}"
    );

    let domains = thresholds["required_domains"]
        .as_array()
        .expect("required_domains must be array");
    let domain_set: BTreeSet<_> = domains
        .iter()
        .map(|d| d.as_str().expect("domain must be string"))
        .collect();
    for required in ["filesystem", "process", "signal"] {
        assert!(
            domain_set.contains(required),
            "CI thresholds missing required domain: {required}"
        );
    }
}

#[test]
fn json_includes_t39_drift_rule() {
    let json = load_matrix_json();
    let rules = json["drift_detection_rules"]
        .as_array()
        .expect("drift_detection_rules must be array");
    let ids: BTreeSet<_> = rules
        .iter()
        .map(|r| r["id"].as_str().expect("rule id must be string"))
        .collect();
    assert!(
        ids.contains("T3-DRIFT-10"),
        "missing required T3.9 drift rule: T3-DRIFT-10"
    );
}

#[test]
fn t39_replay_commands_are_rch_routed() {
    let doc = load_matrix_doc();
    // Full suite replay command
    assert!(
        doc.contains("rch exec -- cargo test --test fs_verification --test e2e_fs"),
        "T3.9 must include full-suite rch replay command"
    );
    // Per-bead replay commands
    assert!(
        doc.contains("rch exec -- cargo test --test process_lifecycle_hardening"),
        "T3.9 must include T3.4 per-bead replay command"
    );
    assert!(
        doc.contains("rch exec -- cargo test --test tokio_cancel_safe_fs_process_signal"),
        "T3.9 must include T3.6 per-bead replay command"
    );
    // Inline test replay
    assert!(
        doc.contains("rch exec -- cargo test --lib fs:: signal:: process"),
        "T3.9 must include inline unit test replay command"
    );
}

// =============================================================================
// T3.10 End-to-End Scripts with Forensic-Grade Logging Contract Tests
// =============================================================================

#[test]
fn matrix_includes_t310_e2e_section() {
    let doc = load_matrix_doc();
    for token in [
        "T3.10 End-to-End Scripts with Forensic-Grade Logging",
        "asupersync-2oh2u.3.10",
        "E2E Scenario Matrix",
        "Structured Log Schema Contract",
        "Failure and Recovery Drills",
        "Reproducible Artifact Bundle",
        "Migration Playbook Linkage",
    ] {
        assert!(
            doc.contains(token),
            "T3.10 E2E section missing token: {token}"
        );
    }
}

#[test]
fn t310_scenario_matrix_covers_all_domains() {
    let doc = load_matrix_doc();
    // All 10 scenario IDs present
    for id in [
        "T310-E2E-01",
        "T310-E2E-02",
        "T310-E2E-03",
        "T310-E2E-04",
        "T310-E2E-05",
        "T310-E2E-06",
        "T310-E2E-07",
        "T310-E2E-08",
        "T310-E2E-09",
        "T310-E2E-10",
    ] {
        assert!(
            doc.contains(id),
            "T3.10 scenario matrix missing scenario: {id}"
        );
    }
    // Domain coverage
    for domain in ["filesystem", "process", "signal", "cross-domain"] {
        assert!(
            doc.contains(domain),
            "T3.10 scenario matrix missing domain: {domain}"
        );
    }
}

#[test]
fn t310_log_schema_has_required_fields() {
    let doc = load_matrix_doc();
    for field in [
        "correlation_id",
        "scenario_id",
        "timestamp_ms",
        "phase",
        "op_type",
        "outcome",
        "timeline_ms",
        "replay_command",
        "owner_module",
        "error_detail",
    ] {
        assert!(
            doc.contains(field),
            "T3.10 log schema missing required field: {field}"
        );
    }
}

#[test]
fn t310_failure_drills_are_complete() {
    let doc = load_matrix_doc();
    for drill in [
        "T310-FD-01",
        "T310-FD-02",
        "T310-FD-03",
        "T310-FD-04",
        "T310-FD-05",
    ] {
        assert!(doc.contains(drill), "T3.10 failure drills missing: {drill}");
    }
    // Quiescence checks
    for check in [
        "No leaked file handles",
        "No zombie processes",
        "No obligation leaks",
    ] {
        assert!(
            doc.contains(check),
            "T3.10 failure drills missing quiescence check: {check}"
        );
    }
}

#[test]
fn t310_migration_linkage_references_downstream_beads() {
    let doc = load_matrix_doc();
    for bead in ["asupersync-2oh2u.3.8", "asupersync-2oh2u.11.2"] {
        assert!(
            doc.contains(bead),
            "T3.10 migration linkage missing downstream bead: {bead}"
        );
    }
}

#[test]
fn json_e2e_scenarios_are_complete() {
    let json = load_matrix_json();
    let e2e = &json["e2e_scenarios"];
    assert!(e2e.is_object(), "json must contain e2e_scenarios object");

    let bead_id = e2e["bead_id"]
        .as_str()
        .expect("e2e_scenarios must have bead_id");
    assert_eq!(bead_id, "asupersync-2oh2u.3.10");

    let scenarios = e2e["scenarios"]
        .as_array()
        .expect("e2e_scenarios must have scenarios array");
    assert!(
        scenarios.len() >= 10,
        "expected at least 10 E2E scenarios, found {}",
        scenarios.len()
    );

    let mut ids = BTreeSet::new();
    for scenario in scenarios {
        let id = scenario["id"]
            .as_str()
            .expect("scenario must have string id");
        ids.insert(id.to_string());
        for field in ["domain", "focus", "owner_modules"] {
            assert!(
                scenario.get(field).is_some(),
                "scenario {id} missing field: {field}"
            );
        }
        let modules = scenario["owner_modules"]
            .as_array()
            .expect("owner_modules must be array");
        for module in modules {
            let path = module.as_str().expect("module path must be string");
            assert!(
                repo_path(path).exists(),
                "scenario {id} owner module must exist: {path}"
            );
        }
    }

    for required in [
        "T310-E2E-01",
        "T310-E2E-02",
        "T310-E2E-03",
        "T310-E2E-04",
        "T310-E2E-05",
        "T310-E2E-06",
        "T310-E2E-07",
        "T310-E2E-08",
        "T310-E2E-09",
        "T310-E2E-10",
    ] {
        assert!(
            ids.contains(required),
            "E2E scenarios missing required id: {required}"
        );
    }
}

#[test]
fn json_failure_drills_are_complete() {
    let json = load_matrix_json();
    let drills = json["e2e_scenarios"]["failure_drills"]
        .as_array()
        .expect("e2e_scenarios must have failure_drills array");
    assert!(
        drills.len() >= 5,
        "expected at least 5 failure drills, found {}",
        drills.len()
    );

    let mut ids = BTreeSet::new();
    for drill in drills {
        let id = drill["id"].as_str().expect("drill must have string id");
        ids.insert(id.to_string());
        for field in ["failure_class", "quiescence_check"] {
            assert!(
                drill.get(field).is_some(),
                "drill {id} missing field: {field}"
            );
        }
    }

    for required in [
        "T310-FD-01",
        "T310-FD-02",
        "T310-FD-03",
        "T310-FD-04",
        "T310-FD-05",
    ] {
        assert!(
            ids.contains(required),
            "failure drills missing required id: {required}"
        );
    }
}

#[test]
fn json_e2e_log_schema_has_required_fields() {
    let json = load_matrix_json();
    let required_fields = json["e2e_scenarios"]["required_log_fields"]
        .as_array()
        .expect("e2e_scenarios must have required_log_fields array");
    let field_set: BTreeSet<_> = required_fields
        .iter()
        .map(|f| f.as_str().expect("field must be string"))
        .collect();
    for required in [
        "correlation_id",
        "scenario_id",
        "timestamp_ms",
        "phase",
        "op_type",
        "outcome",
        "timeline_ms",
    ] {
        assert!(
            field_set.contains(required),
            "required log fields missing: {required}"
        );
    }
}

#[test]
fn json_e2e_migration_linkage_valid() {
    let json = load_matrix_json();
    let linkage = &json["e2e_scenarios"]["migration_linkage"];
    assert!(
        linkage.is_object(),
        "e2e_scenarios must have migration_linkage object"
    );

    let beads = linkage["playbook_beads"]
        .as_array()
        .expect("migration_linkage must have playbook_beads array");
    let bead_set: BTreeSet<_> = beads
        .iter()
        .map(|b| b.as_str().expect("bead must be string"))
        .collect();
    for required in ["asupersync-2oh2u.3.8", "asupersync-2oh2u.11.2"] {
        assert!(
            bead_set.contains(required),
            "migration linkage missing playbook bead: {required}"
        );
    }

    // Verify all domain scenario arrays exist and are non-empty
    for key in [
        "tokio_fs_scenarios",
        "tokio_process_scenarios",
        "tokio_signal_scenarios",
        "cross_domain_scenarios",
    ] {
        let arr = linkage[key]
            .as_array()
            .unwrap_or_else(|| panic!("migration_linkage missing: {key}"));
        assert!(!arr.is_empty(), "migration_linkage {key} must be non-empty");
    }
}

#[test]
fn json_includes_t310_drift_rule() {
    let json = load_matrix_json();
    let rules = json["drift_detection_rules"]
        .as_array()
        .expect("drift_detection_rules must be array");
    let ids: BTreeSet<_> = rules
        .iter()
        .map(|r| r["id"].as_str().expect("rule id must be string"))
        .collect();
    assert!(
        ids.contains("T3-DRIFT-11"),
        "missing required T3.10 drift rule: T3-DRIFT-11"
    );
}

#[test]
fn t310_replay_command_is_rch_routed() {
    let doc = load_matrix_doc();
    assert!(
        doc.contains("rch exec -- cargo test --test tokio_fs_process_signal_parity_matrix t310"),
        "T3.10 must include rch-routed replay command"
    );
}

// =============================================================================
// T3.8 Migration Playbook Contract Tests
// =============================================================================

#[test]
fn matrix_includes_t38_migration_playbook_section() {
    let doc = load_matrix_doc();
    for token in [
        "T3.8 Migration Playbook for fs/process/signal Users",
        "asupersync-2oh2u.3.8",
        "Filesystem Migration Patterns",
        "Process Migration Patterns",
        "Signal Migration Patterns",
        "Rollback and Troubleshooting Decision Tree",
        "Version and Evidence Linkage",
    ] {
        assert!(
            doc.contains(token),
            "T3.8 migration playbook missing section token: {token}"
        );
    }
}

#[test]
fn t38_documents_breaking_changes() {
    let doc = load_matrix_doc();
    // Key breaking changes must be documented
    for token in [
        "wait_async()",
        "wait_with_output_async()",
        "ProcessError",
        "Breaking change",
        "Sync in asupersync",
    ] {
        assert!(
            doc.contains(token),
            "T3.8 migration playbook missing breaking change documentation: {token}"
        );
    }
}

#[test]
fn t38_covers_api_compatible_surfaces() {
    let doc = load_matrix_doc();
    // Must document API-compatible surfaces
    for api in [
        "asupersync::fs::File::open",
        "asupersync::fs::File::create",
        "asupersync::fs::read",
        "asupersync::fs::write",
        "asupersync::process::Command::new",
        "asupersync::signal::ctrl_c",
    ] {
        assert!(
            doc.contains(api),
            "T3.8 playbook missing API-compatible surface: {api}"
        );
    }
}

#[test]
fn t38_documents_asupersync_extensions() {
    let doc = load_matrix_doc();
    for ext in [
        "write_atomic",
        "try_exists",
        "VFS trait",
        "ShutdownController",
        "GracefulOutcome",
        "with_graceful_shutdown",
    ] {
        assert!(
            doc.contains(ext),
            "T3.8 playbook missing asupersync extension: {ext}"
        );
    }
}

#[test]
fn t38_includes_rollback_paths() {
    let doc = load_matrix_doc();
    for token in [
        "Rollback Path",
        "Revert to tokio::process",
        "Wrap in adapter",
        "platform-conditional",
    ] {
        assert!(
            doc.contains(token),
            "T3.8 playbook missing rollback guidance: {token}"
        );
    }
}

#[test]
fn json_migration_playbook_is_complete() {
    let json = load_matrix_json();
    let playbook = &json["migration_playbook"];
    assert!(
        playbook.is_object(),
        "json must contain migration_playbook object"
    );

    let bead_id = playbook["bead_id"]
        .as_str()
        .expect("migration_playbook must have bead_id");
    assert_eq!(bead_id, "asupersync-2oh2u.3.8");

    let breaking = playbook["breaking_changes"]
        .as_array()
        .expect("migration_playbook must have breaking_changes array");
    assert!(
        breaking.len() >= 5,
        "expected at least 5 breaking changes, found {}",
        breaking.len()
    );
    for change in breaking {
        for field in ["domain", "change", "severity", "migration"] {
            assert!(
                change.get(field).is_some(),
                "breaking change missing field: {field}"
            );
        }
    }

    let compatible = playbook["api_compatible_surfaces"]
        .as_array()
        .expect("migration_playbook must have api_compatible_surfaces array");
    assert!(
        compatible.len() >= 15,
        "expected at least 15 API-compatible surfaces, found {}",
        compatible.len()
    );

    let extensions = playbook["asupersync_extensions"]
        .as_array()
        .expect("migration_playbook must have asupersync_extensions array");
    assert!(
        extensions.len() >= 7,
        "expected at least 7 asupersync extensions, found {}",
        extensions.len()
    );

    let evidence = &playbook["evidence_linkage"];
    assert!(
        evidence.is_object(),
        "migration_playbook must have evidence_linkage object"
    );
    for key in [
        "conformance_tests",
        "fault_injection_tests",
        "cancellation_tests",
    ] {
        let path = evidence[key]
            .as_str()
            .unwrap_or_else(|| panic!("evidence_linkage missing: {key}"));
        assert!(
            repo_path(path).exists(),
            "evidence_linkage path must exist: {path}"
        );
    }
}

#[test]
fn json_includes_t38_drift_rule() {
    let json = load_matrix_json();
    let rules = json["drift_detection_rules"]
        .as_array()
        .expect("drift_detection_rules must be array");
    let ids: BTreeSet<_> = rules
        .iter()
        .map(|r| r["id"].as_str().expect("rule id must be string"))
        .collect();
    assert!(
        ids.contains("T3-DRIFT-12"),
        "missing required T3.8 drift rule: T3-DRIFT-12"
    );
}
