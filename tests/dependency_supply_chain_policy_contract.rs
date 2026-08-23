#![allow(missing_docs)]

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const POLICY_PATH: &str = "artifacts/dependency_supply_chain_policy_v1.json";
const DENY_PATH: &str = "deny.toml";
const AUDIT_PATH: &str = ".cargo/audit.toml";
const GITIGNORE_PATH: &str = ".gitignore";
const FUZZ_MANIFEST_PATH: &str = "fuzz/Cargo.toml";
const FUZZ_CONFORMANCE_MANIFEST_PATH: &str = "fuzz/conformance/Cargo.toml";
const FUZZ_LOCK_PATH: &str = "fuzz/Cargo.lock";
const TOOLCHAIN_PATH: &str = "rust-toolchain.toml";
const RUNNER_PATH: &str = "scripts/ci/audit_dependencies.sh";
const DOC_PATH: &str = "docs/dependency_supply_chain_policy.md";
const WORKFLOW_PATH: &str = ".github/workflows/ci.yml";
const MANIFEST_PATH: &str = "artifacts/proof_lane_manifest_v1.json";
const SNAPSHOT_PATH: &str = "artifacts/proof_status_snapshot_v1.json";
const LANE_ID: &str = "dependency-supply-chain-policy-contract";
const PROOF_COMMAND: &str = "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_dependency_supply_chain_policy CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -j 2 -p asupersync --test dependency_supply_chain_policy_contract -- --nocapture";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

fn json(relative: &str) -> Value {
    serde_json::from_str(&read(relative))
        .unwrap_or_else(|error| panic!("parse {relative}: {error}"))
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"))
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn sha256(relative: &str) -> String {
    let bytes = std::fs::read(repo_path(relative))
        .unwrap_or_else(|error| panic!("read bytes {relative}: {error}"));
    hex::encode(Sha256::digest(bytes))
}

fn lockfile_duplicates(relative: &str) -> BTreeMap<String, BTreeSet<String>> {
    let mut all_versions = BTreeMap::<String, BTreeSet<String>>::new();
    let mut current_name = None::<String>;
    let mut current_version = None::<String>;

    let mut flush = |name: &mut Option<String>, version: &mut Option<String>| {
        if let (Some(name), Some(version)) = (name.take(), version.take()) {
            all_versions.entry(name).or_default().insert(version);
        }
    };

    for line in read(relative).lines() {
        if line == "[[package]]" {
            flush(&mut current_name, &mut current_version);
        } else if let Some(value) = line.strip_prefix("name = \"") {
            current_name = Some(
                value
                    .strip_suffix('"')
                    .unwrap_or_else(|| panic!("malformed name in {relative}"))
                    .to_string(),
            );
        } else if let Some(value) = line.strip_prefix("version = \"") {
            current_version = Some(
                value
                    .strip_suffix('"')
                    .unwrap_or_else(|| panic!("malformed version in {relative}"))
                    .to_string(),
            );
        }
    }
    flush(&mut current_name, &mut current_version);
    all_versions.retain(|_, versions| versions.len() > 1);
    all_versions
}

fn artifact_ratchet(policy: &Value, scope: &str) -> BTreeMap<String, BTreeSet<String>> {
    array(&policy["duplicate_version_ratchets"][scope], "allowed")
        .iter()
        .map(|row| {
            (
                text(row, "name").to_string(),
                array(row, "versions")
                    .iter()
                    .map(|version| {
                        version
                            .as_str()
                            .expect("ratchet version must be a string")
                            .to_string()
                    })
                    .collect(),
            )
        })
        .collect()
}

#[test]
fn tool_versions_and_cargo_only_installation_are_pinned() {
    let policy = json(POLICY_PATH);
    let runner = read(RUNNER_PATH);

    assert_eq!(text(&policy["tools"]["cargo_deny"], "version"), "0.19.4");
    assert_eq!(text(&policy["tools"]["cargo_audit"], "version"), "0.22.2");
    for marker in [
        "cargo install --locked --version",
        "cargo-deny --version",
        "cargo-audit --version",
        "BLOCKED_EXIT=75",
        "write_blocked_summary",
    ] {
        assert!(runner.contains(marker), "runner missing {marker}");
    }
    for forbidden in [
        "apt-get",
        "pip install",
        "npm install",
        "cargo clean",
        "|| true",
        "skipping",
    ] {
        assert!(
            !runner.contains(forbidden),
            "runner contains forbidden marker {forbidden}"
        );
    }
}

#[test]
fn advisory_database_and_exception_policy_fail_closed() {
    let policy = json(POLICY_PATH);
    let deny = read(DENY_PATH);
    let audit = read(AUDIT_PATH);
    let database = &policy["advisory_database_policy"];
    let exception = &array(&policy, "advisory_exceptions")[0];

    assert_eq!(
        database["maximum_age_seconds"].as_u64(),
        Some(7 * 24 * 60 * 60)
    );
    assert_eq!(
        text(database, "missing_or_stale_outcome"),
        "BLOCKED_EXTERNAL"
    );
    assert_eq!(text(exception, "id"), "RUSTSEC-2025-0134");
    assert_eq!(text(exception, "owner"), "asupersync-mnotoo.4.3");
    assert!(
        text(exception, "expires_date_utc") > text(&policy, "policy_as_of_date_utc"),
        "exception must be unexpired at the policy date"
    );
    assert!(deny.contains("maximum-db-staleness = \"P7D\""));
    assert!(deny.contains("RUSTSEC-2025-0134"));
    assert!(deny.contains("Temporary direct-edge exception through 2026-09-01"));
    assert!(audit.contains("RUSTSEC-2025-0134"));
    assert!(audit.contains("stale = false"));
}

#[test]
fn checked_manifest_and_lockfile_fingerprints_match() {
    let policy = json(POLICY_PATH);

    {
        let scope = "root_workspace";
        let row = &policy[scope];
        let manifest = text(row, "manifest_path");
        let lockfile = text(row, "lockfile_path");
        assert_eq!(sha256(manifest), text(row, "manifest_sha256"));
        assert_eq!(sha256(lockfile), text(row, "lockfile_sha256"));
        assert_eq!(
            read(manifest).lines().count() as u64,
            row["manifest_line_count"]
                .as_u64()
                .expect("manifest_line_count must be unsigned")
        );
        assert_eq!(
            read(lockfile).lines().count() as u64,
            row["lockfile_line_count"]
                .as_u64()
                .expect("lockfile_line_count must be unsigned")
        );
    }

    let fuzz = &policy["excluded_fuzz_workspace"];
    let fuzz_manifest = text(fuzz, "manifest_path");
    let fuzz_lockfile = text(fuzz, "lockfile_path");
    let fuzz_conformance_manifest = text(fuzz, "conformance_manifest_path");
    assert!(
        repo_path(fuzz_lockfile).is_file(),
        "tracked fuzz lock missing"
    );
    assert_eq!(fuzz["lockfile_tracked"].as_bool(), Some(true));
    assert!(read(GITIGNORE_PATH).contains("!fuzz/Cargo.lock"));
    assert_eq!(sha256(fuzz_manifest), text(fuzz, "manifest_sha256"));
    assert_eq!(sha256(fuzz_lockfile), text(fuzz, "lockfile_sha256"));
    assert_eq!(
        sha256(fuzz_conformance_manifest),
        text(fuzz, "conformance_manifest_sha256")
    );
    assert_eq!(
        read(fuzz_manifest).lines().count() as u64,
        fuzz["manifest_line_count"]
            .as_u64()
            .expect("fuzz manifest lines")
    );
    assert_eq!(
        read(fuzz_lockfile).lines().count() as u64,
        fuzz["lockfile_line_count"]
            .as_u64()
            .expect("fuzz lock lines")
    );
    assert_eq!(
        read(fuzz_conformance_manifest).lines().count() as u64,
        fuzz["conformance_manifest_line_count"]
            .as_u64()
            .expect("fuzz conformance manifest lines")
    );
    assert_eq!(sha256(TOOLCHAIN_PATH), text(&fuzz["toolchain"], "sha256"));
    assert_eq!(text(&fuzz["toolchain"], "channel"), "nightly-2026-07-05");
    assert_eq!(text(fuzz, "cargo_deny_status"), "pass");
    assert_eq!(text(fuzz, "cargo_audit_status"), "pass");
}

#[test]
fn duplicate_baselines_match_both_checked_lockfiles() {
    let policy = json(POLICY_PATH);
    assert_eq!(
        lockfile_duplicates("Cargo.lock"),
        artifact_ratchet(&policy, "root")
    );
    assert_eq!(
        lockfile_duplicates(FUZZ_LOCK_PATH),
        artifact_ratchet(&policy, "fuzz")
    );

    let mut reduced = lockfile_duplicates("Cargo.lock");
    let first = reduced
        .values_mut()
        .next()
        .expect("root duplicate baseline must be nonempty");
    first.pop_first();
    assert!(
        reduced
            .iter()
            .all(|(name, versions)| versions.is_subset(&artifact_ratchet(&policy, "root")[name])),
        "removing a duplicate version must remain within the ratchet"
    );

    let mut expanded = lockfile_duplicates("Cargo.lock");
    expanded
        .get_mut("base64")
        .expect("base64 duplicate baseline")
        .insert("99.0.0".to_string());
    assert!(
        !expanded["base64"].is_subset(&artifact_ratchet(&policy, "root")["base64"]),
        "adding an unreviewed version must exceed the ratchet"
    );
}

#[test]
fn license_source_and_graph_scope_are_explicit() {
    let policy = json(POLICY_PATH);
    let deny = read(DENY_PATH);
    for marker in [
        "all-features = true",
        "include-dev = true",
        "multiple-versions-include-dev = true",
        "wildcards = \"deny\"",
        "unknown-registry = \"deny\"",
        "unknown-git = \"deny\"",
        "required-git-spec = \"rev\"",
        "wasm32-unknown-unknown",
        "x86_64-pc-windows-msvc",
    ] {
        assert!(deny.contains(marker), "deny.toml missing {marker}");
    }
    assert_eq!(
        policy["license_policy"]["include_dev"].as_bool(),
        Some(true)
    );
    assert_eq!(text(&policy["source_policy"], "required_git_spec"), "rev");
    assert!(deny.contains("\"NCSA\""));
    assert!(
        array(&policy["license_policy"], "allowed_spdx_identifiers")
            .iter()
            .any(|item| item.as_str() == Some("NCSA"))
    );
    assert!(read(FUZZ_MANIFEST_PATH).contains("license = \"MIT OR Apache-2.0\""));
    assert!(
        array(&policy["root_workspace"], "coverage")
            .iter()
            .any(|item| item.as_str() == Some("proc-macro"))
    );
}

#[test]
fn fuzz_native_edges_and_tokio_quarantine_are_explicit() {
    let policy = json(POLICY_PATH);
    let fuzz = &policy["excluded_fuzz_workspace"];
    let lock = read(FUZZ_LOCK_PATH);
    let fuzz_manifest = read(FUZZ_MANIFEST_PATH);
    let conformance_manifest = read(FUZZ_CONFORMANCE_MANIFEST_PATH);

    assert!(lock.contains("name = \"libfuzzer-sys\"\nversion = \"0.4.13\""));
    assert!(lock.contains("name = \"cc\"\nversion = \"1.4.4\""));
    assert_eq!(
        text(
            &fuzz["native_build_edges"]["libfuzzer_sys"],
            "license_expression"
        ),
        "(MIT OR Apache-2.0) AND NCSA"
    );
    assert!(text(&fuzz["native_build_edges"]["cc"], "prerequisites").contains("C/C++ compiler"));
    assert!(fuzz_manifest.contains("\"gen-tonic-messages\""));
    assert!(conformance_manifest.contains("tokio = { version = \"1\""));
    assert_eq!(
        text(&fuzz["tokio_quarantine"], "state"),
        "expected_excluded_fuzz_only"
    );
    assert!(text(&fuzz["tokio_quarantine"], "production_boundary").contains("no tokio path"));
}

#[test]
fn negative_fixtures_are_safe_and_cover_each_policy_class() {
    let policy = json(POLICY_PATH);
    let runner = read(RUNNER_PATH);
    let fixture_ids = array(&policy, "negative_fixture_contract")
        .iter()
        .map(|row| text(row, "fixture_id"))
        .collect::<BTreeSet<_>>();

    assert_eq!(
        fixture_ids,
        BTreeSet::from([
            "advisory-ignore-removed",
            "duplicate-version-added",
            "fuzz-license-ncsa-removed",
            "license-isc-removed",
            "unknown-git-source",
        ])
    );
    for marker in [
        "mktemp -d",
        "deny-advisory.toml",
        "deny-license.toml",
        "deny-fuzz-license.toml",
        "license-ncsa-removed.jsonl",
        "duplicates-mutated.json",
        "metadata-original.json",
        "fixture_failures",
    ] {
        assert!(
            runner.contains(marker),
            "runner missing fixture marker {marker}"
        );
    }
    for destructive in ["rm ", "git clean", "git reset", "Cargo.lock\" >"] {
        assert!(
            !runner.contains(destructive),
            "runner contains destructive fixture marker {destructive}"
        );
    }
}

#[test]
fn ci_and_runbook_use_the_canonical_runner_and_preserve_receipts() {
    let workflow = read(WORKFLOW_PATH);
    let docs = read(DOC_PATH);
    for marker in [
        "Dependency supply-chain audit",
        "scripts/ci/audit_dependencies.sh install-tools",
        "scripts/ci/audit_dependencies.sh self-test",
        "scripts/ci/audit_dependencies.sh run",
        "artifacts/dependency-supply-chain",
        "if: always()",
    ] {
        assert!(workflow.contains(marker), "workflow missing {marker}");
    }
    for marker in [
        "both locked dependency-policy surfaces passed",
        "BLOCKED_EXTERNAL",
        "RUSTSEC-2026-0204",
        "RUSTSEC-2026-0190",
        "libfuzzer-sys 0.4.13",
        "NCSA",
        "release readiness",
        "rch_target_dependency_supply_chain_policy",
        "dependency_supply_chain_policy_contract",
    ] {
        assert!(docs.contains(marker), "runbook missing {marker}");
    }
}

#[test]
fn proof_manifest_and_status_snapshot_map_the_scoped_contract() {
    let manifest = json(MANIFEST_PATH);
    let snapshot = json(SNAPSHOT_PATH);
    let lane = array(&manifest, "lanes")
        .iter()
        .find(|lane| text(lane, "lane_id") == LANE_ID)
        .expect("dependency supply-chain lane");
    let guarantee = array(&manifest, "guarantees")
        .iter()
        .find(|row| text(row, "guarantee_id") == LANE_ID)
        .expect("dependency supply-chain guarantee");
    let status = array(&snapshot, "claim_categories")
        .iter()
        .find(|row| text(row, "claim_id") == LANE_ID)
        .expect("dependency supply-chain status row");

    assert_eq!(text(lane, "command"), PROOF_COMMAND);
    assert_eq!(
        text(lane, "resource_envelope_class"),
        "artifact-contract-medium"
    );
    assert_eq!(array(guarantee, "lane_ids"), &vec![Value::from(LANE_ID)]);
    assert_eq!(text(status, "status"), "yellow_scoped");
    assert_eq!(text(status, "proof_evidence_status"), "rerun-required");
    assert_eq!(
        array(status, "proof_commands"),
        &vec![Value::from(PROOF_COMMAND)]
    );
    assert!(
        text(status, "notes").contains("excluded-fuzz"),
        "status must preserve the fuzz no-claim boundary"
    );
}
