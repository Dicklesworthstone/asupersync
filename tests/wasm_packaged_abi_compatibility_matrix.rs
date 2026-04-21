#![allow(clippy::all)]
//! Packaged WASM ABI compatibility matrix contract
//! (`asupersync-3qv04.6.5`, `asupersync-v2ofj7.2`).
//!
//! Validates the package-level ABI compatibility surfaces that consumers rely
//! on outside the Rust crate graph: published metadata sidecars, manifest
//! exports, package-layer cross references, documented packaged
//! upgrade/downgrade matrix, and the current single-owner canonical-vs-retained
//! Browser Edition boundary policy.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(path: &str) -> String {
    let full = repo_root().join(path);
    assert!(full.exists(), "missing {}", full.display());
    std::fs::read_to_string(&full).expect("required fixture file should be readable")
}

fn read_json(path: &str) -> serde_json::Value {
    serde_json::from_str(&read(path)).expect("invalid JSON")
}

fn assert_markers_in_order(content: &str, markers: &[&str], failure_context: &str) {
    let mut offset = 0usize;
    for marker in markers {
        let next = content[offset..]
            .find(marker)
            .unwrap_or_else(|| panic!("{failure_context}: missing ordered marker: {marker}"));
        offset += next + marker.len();
    }
}

#[test]
fn packaged_policy_document_exists() {
    assert!(
        repo_root()
            .join(Path::new("docs/wasm_abi_compatibility_policy.md"))
            .exists(),
        "packaged ABI policy document must exist"
    );
}

#[test]
fn packaged_policy_references_extension_bead() {
    let doc = read("docs/wasm_abi_compatibility_policy.md");
    assert!(
        doc.contains("asupersync-3qv04.6.5"),
        "policy must reference packaged ABI compatibility bead"
    );
}

#[test]
fn packaged_policy_covers_observability_surfaces() {
    let doc = read("docs/wasm_abi_compatibility_policy.md");
    for marker in [
        "Packaged Observability Surfaces",
        "`packages/browser-core/abi-metadata.json`",
        "`./abi-metadata.json`",
        "`abi_version()`",
        "`abi_fingerprint()`",
        "`scripts/validate_package_build.sh`",
    ] {
        assert!(
            doc.contains(marker),
            "policy missing packaged observability marker: {marker}"
        );
    }
}

#[test]
fn packaged_policy_covers_upgrade_and_downgrade_decisions() {
    let doc = read("docs/wasm_abi_compatibility_policy.md");
    for marker in [
        "Packaged Browser-Core Upgrade / Downgrade Matrix",
        "`Exact`",
        "`BackwardCompatible`",
        "`ConsumerTooOld`",
        "`MajorMismatch`",
        "`compatibility_rejected`",
        "omitted consumer version",
    ] {
        assert!(
            doc.contains(marker),
            "policy missing packaged matrix marker: {marker}"
        );
    }
}

#[test]
fn packaged_policy_reproduction_includes_contract_test() {
    let doc = read("docs/wasm_abi_compatibility_policy.md");
    assert!(
        doc.contains("cargo test --test wasm_packaged_abi_compatibility_matrix -- --nocapture"),
        "policy must include packaged ABI matrix reproduction command"
    );
}

#[test]
fn browser_core_manifest_publishes_abi_metadata_sidecar() {
    let manifest = read_json("packages/browser-core/package.json");
    let exports = manifest["exports"]
        .as_object()
        .expect("exports map required");
    assert!(
        exports.contains_key("./abi-metadata.json"),
        "browser-core package must export abi-metadata sidecar"
    );

    let has_abi_metadata = manifest["files"]
        .as_array()
        .expect("files array required")
        .iter()
        .filter_map(serde_json::Value::as_str)
        .any(|x| x == "abi-metadata.json");
    assert!(
        has_abi_metadata,
        "browser-core package files must publish abi-metadata.json"
    );
}

#[test]
fn build_artifact_script_emits_and_syncs_abi_metadata() {
    let script = read("scripts/build_browser_core_artifacts.sh");
    for marker in [
        "abi-metadata.json",
        "\"abi_version\": {",
        "\"abi_signature_fingerprint_v1\":",
        "major=\"$(rg -No 'WASM_ABI_MAJOR_VERSION",
        "minor=\"$(rg -No 'WASM_ABI_MINOR_VERSION",
        "fingerprint=\"$(rg -No 'WASM_ABI_SIGNATURE_FINGERPRINT_V1[^=]*= ([0-9_]+);' \"${ABI_FILE}\" -r '$1' -m1 | tr -d '_')\"",
        "cp \"${STAGING_DIR}/${artifact}\" \"${PACKAGE_DIR}/${artifact}\"",
    ] {
        assert!(
            script.contains(marker),
            "artifact build script missing ABI metadata marker: {marker}"
        );
    }
}

#[test]
fn package_validation_script_checks_abi_metadata_keys() {
    let script = read("scripts/validate_package_build.sh");
    for marker in [
        "check_json_key",
        "'abi_version'",
        "'abi_signature_fingerprint_v1'",
        "ABI version key",
        "ABI fingerprint key",
    ] {
        assert!(
            script.contains(marker),
            "package validation script missing ABI metadata check marker: {marker}"
        );
    }
}

#[test]
fn raw_browser_core_export_tests_cover_version_and_fingerprint() {
    let tests = read("asupersync-browser-core/tests/abi_exports.rs");
    for marker in [
        "abi_version().expect(\"abi_version succeeds\")",
        "assert_eq!(version.major, WASM_ABI_MAJOR_VERSION);",
        "assert_eq!(version.minor, WASM_ABI_MINOR_VERSION);",
        "assert_eq!(abi_fingerprint(), WASM_ABI_SIGNATURE_FINGERPRINT_V1);",
    ] {
        assert!(
            tests.contains(marker),
            "browser-core export tests missing ABI marker: {marker}"
        );
    }
}

#[test]
fn browser_package_keeps_browser_core_as_abi_source_of_truth() {
    let manifest = read_json("packages/browser/package.json");
    let dependency = manifest["dependencies"]["@asupersync/browser-core"]
        .as_str()
        .expect("browser package must depend on browser-core");
    assert!(
        dependency.contains("workspace:") || dependency.starts_with("0."),
        "browser package must consume browser-core through workspace or semver dependency"
    );

    let source = read("packages/browser/src/index.ts");
    assert!(
        source.contains("@asupersync/browser-core"),
        "browser entrypoint must source its ABI-facing surface from browser-core"
    );
}

#[test]
fn retained_wasm_manifest_declares_non_canonical_scaffold_policy() {
    let manifest = read("asupersync-wasm/Cargo.toml");
    for marker in [
        "name = \"asupersync-wasm\"",
        "description = \"Non-canonical scaffold for future or alternative Browser Edition WASM binding strategies.\"",
        "[package.metadata.asupersync_wasm_policy]",
        "policy_version = \"1.0.0\"",
        "owner_track = \"asupersync-v2ofj7.2\"",
    ] {
        assert!(
            manifest.contains(marker),
            "retained wasm manifest missing scaffold-policy marker: {marker}"
        );
    }
}

#[test]
fn browser_boundary_crates_agree_on_single_canonical_owner() {
    let browser_core = read("asupersync-browser-core/src/lib.rs");
    let retained_wasm = read("asupersync-wasm/src/lib.rs");
    let retained_exports = read("asupersync-wasm/src/exports.rs");
    let retained_error = read("asupersync-wasm/src/error.rs");
    let retained_types = read("asupersync-wasm/src/types.rs");

    for marker in [
        "sole workspace crate that owns the live",
        "asupersync-wasm",
        "non-canonical scaffold",
    ] {
        assert!(
            browser_core.contains(marker),
            "browser-core crate docs missing canonical-owner marker: {marker}"
        );
    }

    for marker in [
        "Non-canonical Browser Edition binding scaffold.",
        "asupersync-browser-core",
        "@asupersync/browser-core",
        "retained scaffold",
        "fail_closed_symbol",
    ] {
        assert!(
            retained_wasm.contains(marker),
            "retained wasm crate docs missing scaffold marker: {marker}"
        );
    }

    for marker in [
        "non-live scaffold",
        "deterministic fail-closed path",
        "canonical_boundary_status",
        "fail_closed_symbol",
    ] {
        assert!(
            retained_exports.contains(marker),
            "retained wasm exports missing fail-closed marker: {marker}"
        );
    }

    for marker in [
        "NON_CANONICAL_BOUNDARY_ERROR_CODE",
        "retained-scaffold",
        "asupersync-browser-core",
        "@asupersync/browser-core",
    ] {
        assert!(
            retained_error.contains(marker),
            "retained wasm error surface missing canonical-owner marker: {marker}"
        );
    }

    for marker in [
        "CANONICAL_RUST_CRATE",
        "CANONICAL_JS_PACKAGE",
        "RETAINED_ROLE",
        "retained scaffold",
    ] {
        assert!(
            retained_types.contains(marker),
            "retained wasm types missing scaffold marker: {marker}"
        );
    }
}

#[test]
fn browser_boundary_docs_keep_single_owner_language_aligned() {
    let disposition = read("docs/stub_disposition_matrix.md");
    assert_markers_in_order(
        &disposition,
        &[
            "Surface 1: WASM boundary split-brain",
            "`asupersync-browser-core` is the frozen canonical owner",
            "`asupersync-wasm` is no longer comment-only; it is a retained non-canonical scaffold",
            "Keep `asupersync-browser-core` as the sole live boundary owner",
        ],
        "stub disposition matrix",
    );

    let migration = read("docs/wasm_quickstart_migration.md");
    for marker in [
        "`asupersync-browser-core` is the canonical owner and `asupersync-wasm` is retained scaffold",
        "Treat `asupersync-browser-core` as the canonical shipped boundary owner and",
        "`asupersync-wasm` as retained non-canonical scaffold",
    ] {
        assert!(
            migration.contains(marker),
            "wasm quickstart missing single-owner marker: {marker}"
        );
    }
}
