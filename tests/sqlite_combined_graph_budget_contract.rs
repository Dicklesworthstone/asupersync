//! Fail-closed contract for the FrankenSQLite combined-graph budget.
//!
//! Bead: asupersync-ym2wtv.1
//! Governing ADR: DEP-ADR-010
//! Fixture: artifacts/sqlite_combined_graph_budget_v1.json
//!
//! Two jobs. First, the dependency-direction proof, which is the one part of
//! this measurement that must live inside asupersync: this crate must contain
//! no FrankenSQLite edge of any kind, normal or dev, in either the manifest or
//! the lockfile. Second, the budget artifact must stay internally consistent and
//! must keep its unmeasured axes explicitly BLOCKED rather than silently absent.
//!
//! It proves nothing about FrankenSQLite's correctness, parity or performance,
//! and authorizes no cutover.

#![allow(missing_docs)]

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::PathBuf;

const BEAD_ID: &str = "asupersync-ym2wtv.1";
const ARTIFACT_PATH: &str = "artifacts/sqlite_combined_graph_budget_v1.json";
const DOC_PATH: &str = "docs/sqlite_combined_graph_budget.md";
const MANIFEST_PATH: &str = "Cargo.toml";
const LOCKFILE_PATH: &str = "Cargo.lock";
const GOVERNING_ADR: &str = "DEP-ADR-010";

/// Names that would indicate a reverse edge back into the downstream engine.
const FORBIDDEN_EDGE_TOKENS: [&str; 2] = ["frankensqlite", "fsqlite"];

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_repo_file(path: &str) -> String {
    std::fs::read_to_string(repo_root().join(path))
        .unwrap_or_else(|error| panic!("failed to read {path}: {error}"))
}

fn artifact() -> Value {
    serde_json::from_str(&read_repo_file(ARTIFACT_PATH))
        .unwrap_or_else(|error| panic!("{ARTIFACT_PATH} must be valid JSON: {error}"))
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"))
}

fn number(value: &Value, key: &str) -> i64 {
    value
        .get(key)
        .and_then(Value::as_i64)
        .unwrap_or_else(|| panic!("{key} must be an integer"))
}

fn consumer<'a>(artifact: &'a Value, consumer_id: &str) -> &'a Value {
    array(artifact, "consumers")
        .iter()
        .find(|row| text(row, "consumer_id") == consumer_id)
        .unwrap_or_else(|| panic!("consumer {consumer_id} must be recorded"))
}

/// The cycle proof. FrankenSQLite depends on asupersync, so any edge back the
/// other way — including a dev-dependency, which is what an in-workspace
/// parity oracle would need — closes a package cycle. This is checked against
/// the manifest and the lockfile rather than asserted in the artifact.
#[test]
fn asupersync_has_no_edge_back_into_frankensqlite() {
    for path in [MANIFEST_PATH, LOCKFILE_PATH] {
        let contents = read_repo_file(path).to_lowercase();
        for token in FORBIDDEN_EDGE_TOKENS {
            assert!(
                !contents.contains(token),
                "{path} references {token}: this would close the reverse dependency cycle \
                 that {GOVERNING_ADR} forbids"
            );
        }
    }

    // The satellite manifests must stay clean too; a cycle introduced through a
    // workspace member is still a cycle.
    for path in ["conformance/Cargo.toml", "fuzz/Cargo.toml"] {
        let full = repo_root().join(path);
        if !full.exists() {
            continue;
        }
        let contents = std::fs::read_to_string(&full)
            .unwrap_or_else(|error| panic!("failed to read {path}: {error}"))
            .to_lowercase();
        for token in FORBIDDEN_EDGE_TOKENS {
            assert!(
                !contents.contains(token),
                "{path} references {token}: workspace members may not close the cycle either"
            );
        }
    }
}

#[test]
fn metadata_and_policy_are_fail_closed() {
    let artifact = artifact();
    assert_eq!(
        text(&artifact, "artifact_id"),
        "sqlite-combined-graph-budget-v1"
    );
    assert_eq!(
        artifact.get("schema_version").and_then(Value::as_u64),
        Some(1)
    );
    assert_eq!(text(&artifact, "bead_id"), BEAD_ID);
    assert_eq!(text(&artifact, "governing_adr"), GOVERNING_ADR);
    assert_eq!(text(&artifact, "doc_path"), DOC_PATH);
    assert!(repo_root().join(DOC_PATH).exists(), "{DOC_PATH} must exist");

    let policy = artifact
        .get("policy")
        .unwrap_or_else(|| panic!("policy must be present"));
    for key in [
        "purpose",
        "cycle_rule",
        "native_attribution_rule",
        "no_free_capability_rule",
        "blocked_rule",
    ] {
        assert!(
            !text(policy, key).trim().is_empty(),
            "policy.{key} must be a non-empty statement"
        );
    }

    let environment = artifact
        .get("environment")
        .unwrap_or_else(|| panic!("environment must be present"));
    for key in [
        "host_triple",
        "target_triple",
        "profile",
        "toolchain",
        "edge_kinds_counted",
        "asupersync_rev",
        "frankensqlite_rev",
        "reproducibility_caveat",
    ] {
        assert!(
            !text(environment, key).trim().is_empty(),
            "environment.{key} must be recorded"
        );
    }
    // A measurement taken against dirty trees must say so.
    assert!(
        text(environment, "reproducibility_caveat").contains("uncommitted"),
        "the reproducibility caveat must disclose the working-tree state"
    );
}

#[test]
fn every_consumer_records_a_reproducible_manifest_and_lockfile() {
    let artifact = artifact();
    let consumers = array(&artifact, "consumers");
    assert!(
        consumers.len() >= 4,
        "the incumbent, the proposal and both combined cases must all be recorded"
    );

    let mut ids = BTreeSet::new();
    for row in consumers {
        let consumer_id = text(row, "consumer_id");
        assert!(
            ids.insert(consumer_id.to_owned()),
            "duplicate consumer id {consumer_id}"
        );
        assert!(!text(row, "role").trim().is_empty());
        assert!(!text(row, "description").trim().is_empty());

        let manifest = text(row, "manifest");
        assert!(
            manifest.contains("[dependencies]"),
            "consumer {consumer_id} must record its manifest verbatim"
        );
        assert!(
            manifest.contains("[workspace]"),
            "consumer {consumer_id} must be standalone, not a member of any workspace"
        );

        let lockfile = row
            .get("lockfile")
            .unwrap_or_else(|| panic!("consumer {consumer_id} must record a lockfile"));
        assert_eq!(
            text(lockfile, "sha256").len(),
            64,
            "consumer {consumer_id} lockfile digest must be SHA-256"
        );
        assert!(
            number(lockfile, "locked_packages") > 0,
            "consumer {consumer_id} must record its locked package count"
        );

        let graph = row
            .get("graph")
            .unwrap_or_else(|| panic!("consumer {consumer_id} must record a graph"));
        for key in [
            "reachable_packages",
            "unique_crates",
            "build_script_packages",
            "proc_macro_packages",
        ] {
            assert!(
                number(graph, key) > 0,
                "consumer {consumer_id} graph.{key} must be measured"
            );
        }
        assert!(
            graph.get("active_c_compilation").is_some(),
            "consumer {consumer_id} must record active C compilation, even if empty"
        );
    }

    for required in ["A", "B", "C", "D"] {
        assert!(
            ids.contains(required),
            "consumer {required} must be present: the incumbent, the proposal, and the \
             combined case both naive and patched"
        );
    }
}

#[test]
fn the_delta_is_arithmetically_consistent_with_the_consumer_rows() {
    let artifact = artifact();
    let delta = artifact
        .get("delta_incumbent_to_proposal")
        .unwrap_or_else(|| panic!("delta must be present"));

    let incumbent = consumer(&artifact, "A")
        .get("graph")
        .and_then(|graph| graph.get("unique_crates"))
        .and_then(Value::as_i64)
        .expect("incumbent unique crates");
    let proposal = consumer(&artifact, "B")
        .get("graph")
        .and_then(|graph| graph.get("unique_crates"))
        .and_then(Value::as_i64)
        .expect("proposal unique crates");

    assert_eq!(number(delta, "unique_crates_incumbent"), incumbent);
    assert_eq!(number(delta, "unique_crates_proposal"), proposal);
    assert_eq!(
        number(delta, "net_unique_crates"),
        proposal - incumbent,
        "the net crate delta must equal the difference between the measured consumers"
    );

    // Shared plus each side's exclusive set must reconstruct both totals.
    let shared = number(delta, "shared_crates");
    let incumbent_only = i64::try_from(array(delta, "incumbent_only").len())
        .expect("incumbent-only crate count fits in i64");
    let proposal_only = i64::try_from(array(delta, "proposal_only").len())
        .expect("proposal-only crate count fits in i64");
    assert_eq!(
        shared + incumbent_only,
        incumbent,
        "shared + incumbent-only must equal the incumbent total"
    );
    assert_eq!(
        shared + proposal_only,
        proposal,
        "shared + proposal-only must equal the proposal total"
    );

    // The native trade must be disjoint by construction.
    let evicted: BTreeSet<&str> = array(delta, "c_compilation_evicted")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let added: BTreeSet<&str> = array(delta, "c_compilation_added")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let common: BTreeSet<&str> = array(delta, "c_compilation_common")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(
        evicted.is_disjoint(&added) && evicted.is_disjoint(&common) && added.is_disjoint(&common),
        "evicted, added and common native compilation must be disjoint sets"
    );
}

/// The finding that decides this bead: a naive combined consumer links two
/// asupersync runtimes, so the coexistence period DEP-ADR-010 requires cannot
/// happen in one binary without unifying the graphs.
#[test]
fn the_naive_combined_consumer_is_recorded_as_duplicating_asupersync() {
    let artifact = artifact();

    let naive = consumer(&artifact, "C")
        .get("graph")
        .expect("combined-naive graph");
    let instances = array(naive, "asupersync_instances");
    assert!(
        instances.len() >= 2,
        "consumer C is the naive combined case and must record the duplicated runtime"
    );
    let sources: Vec<&str> = instances.iter().filter_map(Value::as_str).collect();
    assert!(
        sources.iter().any(|entry| entry.contains("path"))
            && sources.iter().any(|entry| entry.contains("crates.io")),
        "the duplication is path versus registry; both origins must be recorded: {sources:?}"
    );

    let patched = consumer(&artifact, "D")
        .get("graph")
        .expect("combined-patched graph");
    assert_eq!(
        array(patched, "asupersync_instances").len(),
        1,
        "consumer D applies a unifying patch and must resolve exactly one asupersync"
    );

    let naive_dupes = naive
        .get("duplicate_version_crates")
        .and_then(Value::as_object)
        .expect("naive duplicates")
        .len();
    let patched_dupes = patched
        .get("duplicate_version_crates")
        .and_then(Value::as_object)
        .expect("patched duplicates")
        .len();
    assert!(
        patched_dupes < naive_dupes,
        "the patch must measurably reduce duplication: {patched_dupes} is not fewer than {naive_dupes}"
    );

    let has_duplicated_runtime_finding = array(&artifact, "findings")
        .iter()
        .any(|row| text(row, "finding_id") == "GB-03");
    assert!(
        has_duplicated_runtime_finding,
        "the duplicated-runtime finding must be recorded"
    );
}

#[test]
fn unmeasured_axes_are_explicitly_blocked_with_an_unblock_path() {
    let artifact = artifact();
    let blocked = array(&artifact, "blocked_measurements");
    assert!(
        !blocked.is_empty(),
        "binary size and compile time were not measured and must be recorded, not omitted"
    );

    let mut axes = BTreeSet::new();
    for row in blocked {
        let axis = text(row, "axis");
        axes.insert(axis.to_owned());
        assert_eq!(
            text(row, "state"),
            "BLOCKED",
            "{axis} must be marked BLOCKED rather than skipped"
        );
        assert!(
            !text(row, "reason").trim().is_empty(),
            "{axis} must say why it is blocked"
        );
        assert!(
            !text(row, "unblock").trim().is_empty(),
            "{axis} must say how to unblock it"
        );
    }
    for axis in ["binary_size", "compile_time"] {
        assert!(axes.contains(axis), "{axis} must be accounted for");
    }
}

#[test]
fn findings_and_terminal_outcome_are_complete_and_claim_nothing_extra() {
    let artifact = artifact();

    for row in array(&artifact, "findings") {
        let finding_id = text(row, "finding_id");
        assert!(
            matches!(
                text(row, "severity"),
                "critical" | "high" | "medium" | "low"
            ),
            "{finding_id} has an unknown severity"
        );
        assert!(!text(row, "summary").trim().is_empty());
        assert!(
            text(row, "detail").len() > 80,
            "{finding_id} must carry evidence, not just a headline"
        );
    }

    let threshold = artifact
        .get("budget_threshold")
        .unwrap_or_else(|| panic!("budget_threshold must be present"));
    assert!(!text(threshold, "rule").trim().is_empty());
    assert!(!text(threshold, "assessment").trim().is_empty());

    let outcome = artifact
        .get("terminal_outcome")
        .unwrap_or_else(|| panic!("terminal_outcome must be present"));
    assert!(
        matches!(text(outcome, "decision"), "KEEP" | "DEFER" | "TRANSITION"),
        "terminal decision must be one of the allowed values"
    );
    assert!(
        !text(outcome, "keeps").trim().is_empty(),
        "the outcome must state what stands in the meantime"
    );
    assert!(!text(outcome, "rationale").trim().is_empty());
    assert!(
        !text(outcome, "not_a_rejection").trim().is_empty(),
        "a defer must say what it does not decide"
    );

    let validation = artifact
        .get("validation")
        .unwrap_or_else(|| panic!("validation must be present"));
    assert_eq!(
        text(validation, "contract_test"),
        "tests/sqlite_combined_graph_budget_contract.rs"
    );
    let boundary = text(validation, "no_claim_boundary");
    for phrase in ["binary size", "authorizes no cutover", "parity"] {
        assert!(
            boundary.contains(phrase),
            "no_claim_boundary must address {phrase:?}"
        );
    }
}
