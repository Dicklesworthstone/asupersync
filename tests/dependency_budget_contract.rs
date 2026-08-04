//! Checked synthesized-consumer dependency-budget contract.
//!
//! Bead: asupersync-mnotoo.1
//! Fixture: artifacts/dependency_budget_contract_v1.json

#![allow(missing_docs)]

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

const AGENTS_PATH: &str = "AGENTS.md";
const ARTIFACT_PATH: &str = "artifacts/dependency_budget_contract_v1.json";
const LEDGER_PATH: &str = "artifacts/dependency_marginal_ledger_v1.json";
const GENERATOR_PATH: &str = "src/bin/dependency_marginal_ledger.rs";
const DOC_PATH: &str = "docs/dependency_budget_contract.md";
const CONTRACT_PATH: &str = "tests/dependency_budget_contract.rs";
const BEAD_ID: &str = "asupersync-mnotoo.1";
const ARTIFACT_ID: &str = "dependency-budget-contract-v1";
const LANE_ID: &str = "dependency-budget-contract";
const PROOF_COMMAND: &str = "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_dependency_budget_contract CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --features dependency-ledger --test dependency_budget_contract -- --nocapture";

type GraphKey = (String, String, String);
type GraphCounts = BTreeMap<GraphKey, (u64, u64)>;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(path: &str) -> String {
    std::fs::read_to_string(repo_root().join(path))
        .unwrap_or_else(|error| panic!("read {path}: {error}"))
}

fn json(path: &str) -> Value {
    serde_json::from_str(&read(path)).unwrap_or_else(|error| panic!("parse {path}: {error}"))
}

fn array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    let value = value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"));
    assert!(!value.trim().is_empty(), "{key} must be nonempty");
    value
}

fn number(value: &Value, key: &str) -> u64 {
    value
        .get(key)
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("{key} must be an unsigned integer"))
}

fn graph_key(value: &Value) -> GraphKey {
    (
        text(value, "feature_profile").to_owned(),
        text(value, "target_triple").to_owned(),
        text(value, "host_triple").to_owned(),
    )
}

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    array(value, key)
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
                .to_owned()
        })
        .collect()
}

fn manifest_edge_ids() -> BTreeSet<String> {
    let manifest = toml::from_str::<toml::Value>(&read("Cargo.toml")).expect("root Cargo.toml");
    let mut edges = BTreeSet::new();
    collect_manifest_table(&manifest, "dependencies", "normal", None, &mut edges);
    collect_manifest_table(&manifest, "build-dependencies", "build", None, &mut edges);
    collect_manifest_table(&manifest, "dev-dependencies", "dev", None, &mut edges);
    if let Some(targets) = manifest.get("target").and_then(toml::Value::as_table) {
        for (target, value) in targets {
            collect_manifest_table(
                value,
                "dependencies",
                "target-normal",
                Some(target),
                &mut edges,
            );
            collect_manifest_table(
                value,
                "build-dependencies",
                "target-build",
                Some(target),
                &mut edges,
            );
            collect_manifest_table(
                value,
                "dev-dependencies",
                "target-dev",
                Some(target),
                &mut edges,
            );
        }
    }
    edges
}

fn collect_manifest_table(
    manifest: &toml::Value,
    table: &str,
    kind: &str,
    target: Option<&str>,
    edges: &mut BTreeSet<String>,
) {
    let Some(dependencies) = manifest.get(table).and_then(toml::Value::as_table) else {
        return;
    };
    for name in dependencies.keys() {
        let edge = target.map_or_else(
            || format!("{kind}:{name}"),
            |target| format!("{kind}:{target}:{name}"),
        );
        assert!(edges.insert(edge), "manifest edge IDs must be unique");
    }
}

fn artifact_allowed_edges(budget: &Value) -> BTreeSet<String> {
    array(budget, "allowed_direct_dependencies")
        .iter()
        .map(|row| text(row, "edge_id").to_owned())
        .collect()
}

fn artifact_ceilings(budget: &Value) -> GraphCounts {
    array(budget, "graph_ceilings")
        .iter()
        .map(|row| {
            (
                graph_key(row),
                (
                    number(row, "package_version_ceiling"),
                    number(row, "unique_package_name_ceiling"),
                ),
            )
        })
        .collect()
}

fn ledger_consumer_counts(ledger: &Value) -> GraphCounts {
    let profile_scopes = array(ledger, "canonical_profiles")
        .iter()
        .map(|profile| (text(profile, "profile_id"), text(profile, "graph_scope")))
        .collect::<BTreeMap<_, _>>();
    array(ledger, "graph_records")
        .iter()
        .filter(|row| {
            profile_scopes.get(text(row, "feature_profile")) == Some(&"synthesized-consumer")
        })
        .map(|row| {
            (
                graph_key(row),
                (
                    number(row, "baseline_package_version_count"),
                    number(row, "baseline_unique_package_name_count"),
                ),
            )
        })
        .collect()
}

fn validate_state(
    budget: &Value,
    current_direct_edges: &BTreeSet<String>,
    current_graph_counts: &GraphCounts,
) -> Vec<String> {
    let mut errors = Vec::new();
    let allowed = artifact_allowed_edges(budget);
    if current_direct_edges != &allowed {
        errors.push(format!(
            "direct dependency allowset drift: added={:?}, removed={:?}",
            current_direct_edges
                .difference(&allowed)
                .collect::<Vec<_>>(),
            allowed.difference(current_direct_edges).collect::<Vec<_>>()
        ));
    }

    let ceilings = artifact_ceilings(budget);
    if current_graph_counts.keys().collect::<BTreeSet<_>>()
        != ceilings.keys().collect::<BTreeSet<_>>()
    {
        errors.push("synthesized-consumer graph cell key drift".to_owned());
    }
    for (key, (versions, names)) in current_graph_counts {
        let Some((version_ceiling, name_ceiling)) = ceilings.get(key) else {
            continue;
        };
        if versions > version_ceiling {
            errors.push(format!(
                "{key:?} package-version count {versions} exceeds ceiling {version_ceiling}"
            ));
        }
        if names > name_ceiling {
            errors.push(format!(
                "{key:?} unique-name count {names} exceeds ceiling {name_ceiling}"
            ));
        }
    }
    errors
}

#[test]
fn header_provenance_and_documentation_are_pinned() {
    let budget = json(ARTIFACT_PATH);
    assert_eq!(number(&budget, "schema_version"), 1);
    assert_eq!(text(&budget, "artifact_id"), ARTIFACT_ID);
    assert_eq!(text(&budget, "bead_id"), BEAD_ID);
    assert_eq!(text(&budget, "program_id"), "asupersync-ir2uf0");
    assert_eq!(text(&budget, "capability_id"), "CAP-DEPENDENCY-LEDGER");
    assert_eq!(text(&budget, "generator_path"), GENERATOR_PATH);
    assert_eq!(text(&budget, "contract_path"), CONTRACT_PATH);
    assert_eq!(text(&budget, "documentation_path"), DOC_PATH);
    let source_commit = text(&budget, "source_commit");
    assert_eq!(source_commit.len(), 40);
    assert!(source_commit.bytes().all(|byte| byte.is_ascii_hexdigit()));

    let source = &budget["source_ledger"];
    assert_eq!(text(source, "path"), LEDGER_PATH);
    assert_eq!(text(source, "artifact_id"), "dependency-marginal-ledger-v1");
    let ledger_bytes = std::fs::read(repo_root().join(LEDGER_PATH)).expect("read ledger bytes");
    assert_eq!(
        text(source, "sha256"),
        hex::encode(Sha256::digest(&ledger_bytes))
    );
    assert!(text(source, "measurement_basis").contains("package IDs"));

    let docs = read(DOC_PATH);
    for marker in [
        ARTIFACT_PATH,
        LEDGER_PATH,
        GENERATOR_PATH,
        "--budget-from-ledger",
        "reviewed exception",
        "ratchet down",
        "synthesized out-of-workspace consumer",
        LANE_ID,
        "does not authorize dependency removal",
    ] {
        assert!(
            docs.contains(marker),
            "documentation marker missing: {marker}"
        );
    }
    let generator = read(GENERATOR_PATH);
    for marker in [
        "--budget-from-ledger",
        "direct-dependency-addition",
        "graph-ceiling-increase",
        "synthesized-consumer",
        "Package IDs",
    ] {
        assert!(
            generator.contains(marker),
            "generator marker missing: {marker}"
        );
    }
}

#[test]
fn exact_direct_allowset_matches_manifest_and_frozen_ledger() {
    let budget = json(ARTIFACT_PATH);
    let ledger = json(LEDGER_PATH);
    let artifact_edges = artifact_allowed_edges(&budget);
    let ledger_edges = array(&ledger, "direct_dependency_inventory")
        .iter()
        .map(|row| text(row, "edge_id").to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(artifact_edges, ledger_edges);
    assert_eq!(artifact_edges, manifest_edge_ids());
    assert_eq!(
        artifact_edges.len(),
        array(&budget, "allowed_direct_dependencies").len(),
        "allowed direct edges must be unique"
    );
    assert!(
        budget["ratchet_policy"]["fail_closed"]
            .as_bool()
            .is_some_and(|value| value)
    );
}

#[test]
fn direct_edge_cells_preserve_profile_target_host_and_kind_keys() {
    let budget = json(ARTIFACT_PATH);
    let ledger = json(LEDGER_PATH);
    let inventory_kinds = array(&ledger, "direct_dependency_inventory")
        .iter()
        .map(|row| {
            (
                text(row, "edge_id").to_owned(),
                text(row, "dependency_edge_kind").to_owned(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let profile_scopes = array(&ledger, "canonical_profiles")
        .iter()
        .map(|profile| {
            (
                text(profile, "profile_id").to_owned(),
                text(profile, "graph_scope").to_owned(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut expected = BTreeMap::<(String, String, String, String), BTreeSet<String>>::new();
    for graph in array(&ledger, "graph_records") {
        let profile = text(graph, "feature_profile");
        if profile_scopes.get(profile).map(String::as_str) != Some("synthesized-consumer") {
            continue;
        }
        for edge in string_set(graph, "active_direct_root_edges") {
            let kind = inventory_kinds
                .get(&edge)
                .unwrap_or_else(|| panic!("missing inventory kind for {edge}"));
            expected
                .entry((
                    profile.to_owned(),
                    text(graph, "target_triple").to_owned(),
                    text(graph, "host_triple").to_owned(),
                    kind.clone(),
                ))
                .or_default()
                .insert(edge);
        }
    }

    let actual = array(&budget, "direct_edge_cells")
        .iter()
        .map(|row| {
            (
                (
                    text(row, "feature_profile").to_owned(),
                    text(row, "target_triple").to_owned(),
                    text(row, "host_triple").to_owned(),
                    text(row, "dependency_edge_kind").to_owned(),
                ),
                string_set(row, "allowed_direct_root_edges"),
            )
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(actual, expected);
}

#[test]
fn synthesized_consumer_ceilings_exactly_match_the_frozen_ledger() {
    let budget = json(ARTIFACT_PATH);
    let ledger = json(LEDGER_PATH);
    let ceilings = artifact_ceilings(&budget);
    let current = ledger_consumer_counts(&ledger);
    assert_eq!(ceilings, current);
    assert_eq!(ceilings.len(), 48, "12 consumer profiles x 4 targets");
    for row in array(&budget, "graph_ceilings") {
        assert_eq!(text(row, "graph_scope"), "synthesized-consumer");
        assert!(number(row, "package_version_ceiling") > 0);
        assert!(number(row, "unique_package_name_ceiling") > 0);
        assert!(text(row, "exact_command").contains("cargo metadata --format-version 1"));
        assert!(text(row, "exact_command").contains("--filter-platform"));
        assert!(text(row, "exact_command").contains("$LEDGER_WORK_DIR"));
    }
    assert!(
        array(&budget, "excluded_graph_scopes")
            .iter()
            .any(|row| text(row, "feature_profile") == "workspace-dev-build-audit")
    );
}

#[test]
fn injected_direct_edge_and_graph_growth_fail_but_smaller_graph_passes() {
    let budget = json(ARTIFACT_PATH);
    let ledger = json(LEDGER_PATH);
    let direct_edges = manifest_edge_ids();
    let graph_counts = ledger_consumer_counts(&ledger);
    assert!(validate_state(&budget, &direct_edges, &graph_counts).is_empty());

    let mut injected_direct_edges = direct_edges.clone();
    injected_direct_edges.insert("normal:trivial-budget-negative-fixture".to_owned());
    let direct_errors = validate_state(&budget, &injected_direct_edges, &graph_counts);
    assert!(
        direct_errors
            .iter()
            .any(|error| error.contains("direct dependency allowset drift")),
        "injected dependency must fail closed: {direct_errors:?}"
    );

    let mut increased = graph_counts.clone();
    let (_, counts) = increased.iter_mut().next().expect("consumer graph cell");
    counts.0 += 1;
    let graph_errors = validate_state(&budget, &direct_edges, &increased);
    assert!(
        graph_errors
            .iter()
            .any(|error| error.contains("exceeds ceiling")),
        "injected graph growth must fail closed: {graph_errors:?}"
    );

    let mut reduced = graph_counts;
    for (versions, names) in reduced.values_mut() {
        *versions = versions.saturating_sub(1);
        *names = names.saturating_sub(1);
    }
    assert!(
        validate_state(&budget, &direct_edges, &reduced).is_empty(),
        "a smaller graph must remain admissible so regeneration can ratchet down"
    );
}

#[test]
fn reviewed_exception_shape_is_narrow_and_explicit() {
    let budget = json(ARTIFACT_PATH);
    let mut ids = BTreeSet::new();
    for exception in array(&budget, "reviewed_exceptions") {
        let id = text(exception, "exception_id");
        assert!(ids.insert(id), "reviewed exception IDs must be unique");
        for key in [
            "reviewed_by",
            "approved_on",
            "expires_on",
            "review_reference",
            "rationale",
        ] {
            text(exception, key);
        }
        match text(exception, "exception_kind") {
            "direct-dependency-addition" => {
                text(exception, "direct_root_edge");
            }
            "graph-ceiling-increase" => {
                graph_key(exception);
                number(exception, "approved_package_version_ceiling");
                number(exception, "approved_unique_package_name_ceiling");
            }
            kind => panic!("unknown reviewed exception kind {kind}"),
        }
    }
    assert!(
        array(&budget, "reviewed_exceptions").is_empty(),
        "initial frozen baseline requires no upward-budget exceptions"
    );
}

#[test]
fn proof_manifest_status_and_docs_map_the_scoped_lane() {
    let manifest = json("artifacts/proof_lane_manifest_v1.json");
    let lane = array(&manifest, "lanes")
        .iter()
        .find(|lane| text(lane, "lane_id") == LANE_ID)
        .expect("dependency budget manifest lane");
    assert_eq!(text(lane, "command"), PROOF_COMMAND);
    assert_eq!(
        text(lane, "resource_envelope_class"),
        "artifact-contract-medium"
    );
    assert_eq!(
        string_set(lane, "source_paths"),
        BTreeSet::from([
            AGENTS_PATH.to_owned(),
            ARTIFACT_PATH.to_owned(),
            CONTRACT_PATH.to_owned(),
            DOC_PATH.to_owned(),
            GENERATOR_PATH.to_owned(),
            LEDGER_PATH.to_owned(),
            "README.md".to_owned(),
            "artifacts/proof_lane_manifest_v1.json".to_owned(),
            "artifacts/proof_status_snapshot_v1.json".to_owned(),
            "tests/fixtures/proof_lane_manifest/manifest_projection.json".to_owned(),
        ])
    );

    let snapshot = json("artifacts/proof_status_snapshot_v1.json");
    let claim = array(&snapshot, "claim_categories")
        .iter()
        .find(|claim| text(claim, "claim_id") == LANE_ID)
        .expect("dependency budget status row");
    assert_eq!(text(claim, "status"), "yellow_scoped");
    assert_eq!(text(claim, "proof_evidence_status"), "rerun-required");
    assert_eq!(
        string_set(claim, "manifest_lane_ids"),
        BTreeSet::from([LANE_ID.to_owned()])
    );
    assert_eq!(
        string_set(claim, "proof_commands"),
        BTreeSet::from([PROOF_COMMAND.to_owned()])
    );

    for (path, markers) in [
        (
            "README.md",
            ["Dependency budget contract", "dependency-budget-contract"],
        ),
        (
            "AGENTS.md",
            ["dependency budget contract", "dependency-budget-contract"],
        ),
    ] {
        let contents = read(path);
        for marker in markers {
            assert!(contents.contains(marker), "{path} missing marker {marker}");
        }
    }
}
