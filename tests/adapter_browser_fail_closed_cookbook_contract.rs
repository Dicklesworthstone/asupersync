#![allow(missing_docs)]

use serde_json::Value as JsonValue;
use std::path::{Path, PathBuf};

const CONTRACT_PATH: &str = "artifacts/adapter_browser_fail_closed_cookbook_contract_v1.json";
const WASM_BOUNDARY_CONTRACT_PATH: &str =
    "artifacts/wasm_browser_support_boundary_contract_v1.json";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|err| panic!("read {relative}: {err}"))
}

fn json_file(relative: &str) -> JsonValue {
    serde_json::from_str(&read_repo_file(relative))
        .unwrap_or_else(|err| panic!("parse {relative}: {err}"))
}

fn contract() -> JsonValue {
    json_file(CONTRACT_PATH)
}

fn array<'a>(value: &'a JsonValue, key: &str) -> &'a Vec<JsonValue> {
    value
        .get(key)
        .and_then(JsonValue::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn string_field<'a>(value: &'a JsonValue, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(JsonValue::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"))
}

fn bool_field(value: &JsonValue, key: &str) -> bool {
    value
        .get(key)
        .and_then(JsonValue::as_bool)
        .unwrap_or_else(|| panic!("{key} must be a bool"))
}

fn entry<'a>(contract: &'a JsonValue, id: &str) -> &'a JsonValue {
    array(contract, "entries")
        .iter()
        .find(|entry| entry.get("entry_id").and_then(JsonValue::as_str) == Some(id))
        .unwrap_or_else(|| panic!("missing cookbook entry {id}"))
}

fn joined_sources(paths: &[&str]) -> String {
    paths
        .iter()
        .map(|path| read_repo_file(path))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn contract_names_bounded_scope_entries_and_validation_lane() {
    let contract = contract();
    assert_eq!(
        contract.get("contract_version").and_then(JsonValue::as_str),
        Some("adapter-browser-fail-closed-cookbook-contract-v1")
    );
    assert_eq!(
        contract.get("bead_id").and_then(JsonValue::as_str),
        Some("asupersync-xeh8m0.6")
    );
    assert_eq!(array(&contract, "entries").len(), 2);

    let scope = contract.get("scope").expect("scope object");
    assert_eq!(
        scope.get("tracker_mutation").and_then(JsonValue::as_str),
        Some("manual_only")
    );
    assert_eq!(
        scope
            .get("no_broad_support_claims")
            .and_then(JsonValue::as_bool),
        Some(true)
    );

    let validation_commands = array(&contract, "validation_commands");
    assert!(
        validation_commands.iter().any(|command| {
            command.as_str().is_some_and(|command| {
                command.starts_with("rch exec -- ")
                    && command
                        .contains("cargo test -p asupersync --test adapter_browser_fail_closed_cookbook_contract")
            })
        }),
        "validation commands must include the rch-scoped cookbook contract proof"
    );
}

#[test]
fn cookbook_entries_reference_existing_sources_fixtures_and_rch_proofs() {
    let contract = contract();

    for cookbook_entry in array(&contract, "entries") {
        let entry_id = string_field(cookbook_entry, "entry_id");
        let claim_scope = string_field(cookbook_entry, "claim_scope");
        assert_ne!(
            claim_scope, "blanket_support",
            "{entry_id} must not use a blanket support claim"
        );

        for path in array(cookbook_entry, "source_paths")
            .iter()
            .chain(array(cookbook_entry, "fixture_paths"))
        {
            let path = path.as_str().expect("path entry must be a string");
            assert!(
                repo_path(path).exists(),
                "{entry_id} references missing path {path}"
            );
        }

        let proof_command = string_field(cookbook_entry, "proof_command");
        assert!(
            proof_command.starts_with("rch exec -- "),
            "{entry_id} proof must go through rch"
        );
        assert!(
            proof_command.contains(" cargo test "),
            "{entry_id} proof must be an executable cargo test lane"
        );
        for forbidden in [
            "git checkout",
            "git switch",
            "git worktree",
            "cargo test -p asupersync --all-targets",
        ] {
            assert!(
                !proof_command.contains(forbidden),
                "{entry_id} proof command contains forbidden marker {forbidden}"
            );
        }
    }
}

#[test]
fn adapter_entry_preserves_cancel_safety_refusal() {
    let contract = contract();
    let adapter = entry(&contract, "tokio-io-cancel-safety-boundary");
    let evidence = joined_sources(&[
        "asupersync-tokio-compat/src/io.rs",
        "asupersync-tokio-compat/Cargo.toml",
        "tests/tokio_interop_support_matrix.rs",
        "docs/tokio_interop_support_matrix.md",
    ]);

    assert_eq!(
        string_field(adapter, "boundary_kind"),
        "adapter",
        "adapter entry must stay classified as an adapter boundary"
    );
    assert_eq!(
        string_field(adapter, "support_posture"),
        "supported_with_documented_cancel_safety_limits"
    );

    for marker in array(adapter, "required_markers") {
        let marker = marker.as_str().expect("required marker string");
        assert!(
            evidence.contains(marker),
            "adapter evidence missing required marker {marker}"
        );
    }

    for unsupported in array(adapter, "unsupported_claims") {
        let claim = string_field(unsupported, "claim");
        assert!(
            !bool_field(unsupported, "expected"),
            "{claim} must remain a false unsupported claim"
        );
        let marker = string_field(unsupported, "evidence_marker");
        assert!(
            evidence.contains(marker),
            "adapter unsupported claim {claim} missing evidence marker {marker}"
        );
    }
}

#[test]
fn browser_entry_preserves_worker_direct_runtime_fail_closed_boundary() {
    let contract = contract();
    let browser = entry(&contract, "browser-worker-direct-runtime-boundary");
    let wasm_boundary = json_file(WASM_BOUNDARY_CONTRACT_PATH);
    let evidence = joined_sources(&[
        "packages/browser/src/index.ts",
        "src/runtime/builder.rs",
        "docs/WASM.md",
        "tests/wasm_browser_support_boundary_contract.rs",
    ]);

    assert_eq!(
        string_field(browser, "boundary_kind"),
        "browser_fixture",
        "browser entry must stay classified as a browser fixture"
    );
    assert_eq!(
        string_field(browser, "support_posture"),
        "direct_runtime_supported_only_for_main_thread_and_dedicated_worker"
    );

    for marker in array(browser, "required_markers") {
        let marker = marker.as_str().expect("required marker string");
        assert!(
            evidence.contains(marker),
            "browser evidence missing required marker {marker}"
        );
    }

    let scope_limits = wasm_boundary
        .get("scope_limits")
        .expect("wasm boundary scope_limits object");
    for unsupported in array(browser, "unsupported_claims") {
        let claim = string_field(unsupported, "claim");
        let scope_key = string_field(unsupported, "scope_limit_key");
        assert_eq!(
            scope_limits.get(scope_key).and_then(JsonValue::as_bool),
            Some(false),
            "{claim} must stay false in the wasm support-boundary contract"
        );
        assert!(
            !bool_field(unsupported, "expected"),
            "{claim} must remain a false unsupported claim"
        );
    }
}

#[test]
fn cookbook_refuses_raw_coordination_or_auto_tracker_mutation() {
    let contract_text = read_repo_file(CONTRACT_PATH);
    let contract = contract();

    for forbidden in [
        "raw_agent_mail_body",
        "sender_token",
        "auto_close_tracker",
        "broadcast=true",
        "master branch",
    ] {
        assert!(
            !contract_text.contains(forbidden),
            "cookbook contract must not publish raw coordination or unsafe action marker {forbidden}"
        );
    }

    for cookbook_entry in array(&contract, "entries") {
        let entry_id = string_field(cookbook_entry, "entry_id");
        assert!(
            !string_field(cookbook_entry, "support_posture").contains("full_"),
            "{entry_id} must not claim full support from a narrow cookbook fixture"
        );
        assert!(
            !array(cookbook_entry, "unsupported_claims").is_empty(),
            "{entry_id} must name at least one unsupported/fail-closed claim"
        );
    }
}
