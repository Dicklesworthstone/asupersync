//! Checked synthesized-consumer dependency-budget contract.
//!
//! Bead: asupersync-mnotoo.1
//! Fixture: artifacts/dependency_budget_contract_v1.json

#![allow(missing_docs)]

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const AGENTS_PATH: &str = "AGENTS.md";
const ARTIFACT_PATH: &str = "artifacts/dependency_budget_contract_v1.json";
const LEDGER_PATH: &str = "artifacts/dependency_marginal_ledger_v1.json";
const GENERATOR_PATH: &str = "src/bin/dependency_marginal_ledger.rs";
const DOC_PATH: &str = "docs/dependency_budget_contract.md";
const CONTRACT_PATH: &str = "tests/dependency_budget_contract.rs";
const BEAD_ID: &str = "asupersync-mnotoo.1";
const ARTIFACT_ID: &str = "dependency-budget-contract-v1";
const LANE_ID: &str = "dependency-budget-contract";
const PROOF_COMMAND: &str = "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_dependency_budget_contract CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -j 2 -p asupersync --features dependency-ledger --test dependency_budget_contract -- --nocapture";
const AGENTS_BEGIN: &str = "<!-- BEGIN GENERATED AGENTS KEY DEPENDENCIES -->";
const AGENTS_END: &str = "<!-- END GENERATED AGENTS KEY DEPENDENCIES -->";

type GraphKey = (String, String, String);
type GraphCounts = BTreeMap<GraphKey, (u64, u64)>;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(path: &str) -> String {
    std::fs::read_to_string(repo_root().join(path))
        .unwrap_or_else(|error| panic!("read {path}: {error}"))
}

fn generated_agents_region(document: &str) -> &str {
    let (_, after_begin) = document
        .split_once(&format!("{AGENTS_BEGIN}\n"))
        .expect("AGENTS begin marker");
    let (region, _) = after_begin
        .split_once(AGENTS_END)
        .expect("AGENTS end marker");
    region
}

fn run_agents_generator(repo: &Path, budget: &Path, mode: &str, extra: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_dependency_marginal_ledger"));
    command
        .arg("--repo-root")
        .arg(repo)
        .arg("--agents-key-dependencies-from-budget")
        .arg(budget)
        .arg(mode)
        .args(extra)
        .output()
        .expect("run dependency_marginal_ledger AGENTS mode")
}

fn assert_failed_with(output: &Output, marker: &str) {
    assert!(
        !output.status.success(),
        "negative command unexpectedly passed"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(marker),
        "negative stderr missing {marker:?}: {stderr}"
    );
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
        "--agents-key-dependencies-from-budget",
        "--render-agents-key-dependencies",
        "--check-agents-key-dependencies",
        AGENTS_BEGIN,
        AGENTS_END,
        "apply_patch",
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
        "--agents-key-dependencies-from-budget",
        "--render-agents-key-dependencies",
        "--check-agents-key-dependencies",
        AGENTS_BEGIN,
    ] {
        assert!(
            generator.contains(marker),
            "generator marker missing: {marker}"
        );
    }
}

#[test]
fn agents_key_dependency_projection_joins_exact_budget_metadata() {
    let budget = json(ARTIFACT_PATH);
    let projection = &budget["agents_key_dependencies"];
    let projection_keys = projection
        .as_object()
        .expect("agents_key_dependencies object")
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        projection_keys,
        BTreeSet::from([
            "schema_version",
            "bead_id",
            "heading",
            "begin_marker",
            "end_marker",
            "columns",
            "consumer_profile_vocabulary",
            "tier_vocabulary",
            "rows",
        ])
    );
    assert_eq!(number(projection, "schema_version"), 1);
    assert_eq!(text(projection, "bead_id"), "asupersync-mnotoo.3.6");
    assert_eq!(text(projection, "heading"), "### Key Dependencies");
    assert_eq!(text(projection, "begin_marker"), AGENTS_BEGIN);
    assert_eq!(text(projection, "end_marker"), AGENTS_END);
    assert_eq!(
        array(projection, "columns"),
        ["Crate", "Purpose", "Feature/Profile", "Tier"]
    );
    assert_eq!(
        array(projection, "tier_vocabulary"),
        [
            "core-runtime",
            "optional-production",
            "development-test",
            "development-benchmark",
        ]
    );
    let expected_profiles = array(&budget, "graph_ceilings")
        .iter()
        .map(|row| text(row, "feature_profile").to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        string_set(projection, "consumer_profile_vocabulary"),
        expected_profiles
    );

    let allowed_edges = array(&budget, "allowed_direct_dependencies")
        .iter()
        .map(|row| (text(row, "edge_id"), row))
        .collect::<BTreeMap<_, _>>();
    let rows = array(projection, "rows");
    assert_eq!(rows.len(), 14);
    assert_eq!(
        rows.iter()
            .map(|row| text(row, "row_id"))
            .collect::<Vec<_>>(),
        [
            "key-thiserror",
            "key-crossbeam-queue",
            "key-parking-lot",
            "key-polling",
            "key-slab",
            "key-smallvec",
            "key-pin-project",
            "key-serde-json",
            "key-socket2",
            "key-rustls",
            "key-rusqlite",
            "key-proptest",
            "key-criterion",
            "key-rayon",
        ]
    );
    assert_eq!(
        rows.iter()
            .map(|row| number(row, "display_order"))
            .collect::<Vec<_>>(),
        (1..=14).map(|index| index * 10).collect::<Vec<_>>()
    );

    let mut projected_dependencies = BTreeSet::new();
    for row in rows {
        let dependencies = string_set(row, "dependency_names");
        assert!(!dependencies.is_empty());
        for dependency in &dependencies {
            assert!(
                projected_dependencies.insert(dependency.clone()),
                "dependency {dependency} appears in multiple display rows"
            );
        }
        let expected_crate_cell = array(row, "dependency_names")
            .iter()
            .map(|name| format!("`{}`", name.as_str().expect("dependency name")))
            .collect::<Vec<_>>()
            .join(" + ");
        assert_eq!(text(row, "crate_cell"), expected_crate_cell);
        text(row, "purpose");
        text(row, "feature_profile_cell");

        let mut joined_dependencies = BTreeSet::new();
        let mut joined_targets = BTreeSet::new();
        for edge_id in string_set(row, "direct_edge_ids") {
            let edge = allowed_edges
                .get(edge_id.as_str())
                .unwrap_or_else(|| panic!("unknown projected edge {edge_id}"));
            joined_dependencies.insert(text(edge, "dependency_name").to_owned());
            assert_eq!(
                edge["optional"].as_bool(),
                row["optional"].as_bool(),
                "optional metadata drift for {edge_id}"
            );
            if let Some(condition) = edge["target_condition"].as_str() {
                joined_targets.insert(condition.to_owned());
            }
        }
        assert_eq!(joined_dependencies, dependencies);
        assert_eq!(joined_targets, string_set(row, "target_conditions"));
        assert_ne!(
            row.get("feature_profiles").is_some(),
            row.get("development_scope").is_some(),
            "each row needs exactly one activation selector"
        );
    }
    assert_eq!(projected_dependencies.len(), 15);
}

#[test]
fn cargo_renderer_reproduces_the_marked_agents_table_and_check_is_read_only() {
    let root = repo_root();
    let budget = root.join(ARTIFACT_PATH);
    let render = run_agents_generator(&root, &budget, "--render-agents-key-dependencies", &[]);
    assert!(
        render.status.success(),
        "render failed: {}",
        String::from_utf8_lossy(&render.stderr)
    );
    assert!(
        render.stderr.is_empty(),
        "render diagnostics leaked on success"
    );
    assert_eq!(
        String::from_utf8(render.stdout).expect("render stdout utf8"),
        generated_agents_region(&read(AGENTS_PATH))
    );

    let before = std::fs::read(root.join(AGENTS_PATH)).expect("read AGENTS before check");
    let check = run_agents_generator(&root, &budget, "--check-agents-key-dependencies", &[]);
    assert!(
        check.status.success(),
        "check failed: {}",
        String::from_utf8_lossy(&check.stderr)
    );
    assert!(check.stdout.is_empty());
    assert!(check.stderr.is_empty());
    assert_eq!(
        std::fs::read(root.join(AGENTS_PATH)).expect("read AGENTS after check"),
        before,
        "check mode must not mutate AGENTS.md"
    );
}

#[test]
fn projection_and_marker_negative_mutations_fail_closed() {
    let root = repo_root();
    let temp = tempfile::tempdir().expect("create negative fixture directory");
    let budget_path = temp.path().join("budget.json");
    let canonical = json(ARTIFACT_PATH);

    let mut missing = canonical.clone();
    missing["agents_key_dependencies"]["rows"]
        .as_array_mut()
        .expect("rows")
        .pop();
    std::fs::write(
        &budget_path,
        serde_json::to_vec(&missing).expect("serialize missing row"),
    )
    .expect("write missing-row budget");
    assert_failed_with(
        &run_agents_generator(&root, &budget_path, "--render-agents-key-dependencies", &[]),
        "reviewed canonical seed",
    );

    let mut extra = canonical.clone();
    let mut extra_row = extra["agents_key_dependencies"]["rows"][0].clone();
    extra_row["row_id"] = Value::String("key-extra".to_owned());
    extra_row["display_order"] = Value::from(150);
    extra["agents_key_dependencies"]["rows"]
        .as_array_mut()
        .expect("rows")
        .push(extra_row);
    std::fs::write(
        &budget_path,
        serde_json::to_vec(&extra).expect("serialize extra row"),
    )
    .expect("write extra-row budget");
    assert_failed_with(
        &run_agents_generator(&root, &budget_path, "--render-agents-key-dependencies", &[]),
        "occurs in multiple rows",
    );

    let mut stale = canonical.clone();
    stale["agents_key_dependencies"]["rows"][0]["purpose"] =
        Value::String("stale planted purpose".to_owned());
    std::fs::write(
        &budget_path,
        serde_json::to_vec(&stale).expect("serialize stale row"),
    )
    .expect("write stale-row budget");
    assert_failed_with(
        &run_agents_generator(&root, &budget_path, "--render-agents-key-dependencies", &[]),
        "reviewed canonical seed",
    );

    let mut reordered = canonical.clone();
    reordered["agents_key_dependencies"]["rows"]
        .as_array_mut()
        .expect("rows")
        .swap(0, 1);
    std::fs::write(
        &budget_path,
        serde_json::to_vec(&reordered).expect("serialize reordered rows"),
    )
    .expect("write reordered budget");
    assert_failed_with(
        &run_agents_generator(&root, &budget_path, "--render-agents-key-dependencies", &[]),
        "ascending display_order",
    );

    let mut unknown = canonical;
    unknown["agents_key_dependencies"]["rows"][0]["planted_unknown"] = Value::Bool(true);
    std::fs::write(
        &budget_path,
        serde_json::to_vec(&unknown).expect("serialize unknown field"),
    )
    .expect("write unknown-field budget");
    assert_failed_with(
        &run_agents_generator(&root, &budget_path, "--render-agents-key-dependencies", &[]),
        "unknown field",
    );

    let canonical_budget = root.join(ARTIFACT_PATH);
    let agents = read(AGENTS_PATH);
    for (case, mutated, marker) in [
        (
            "content-drift",
            agents.replacen("Ergonomic error type derivation", "planted drift", 1),
            "generated region drift",
        ),
        (
            "missing-marker",
            agents.replacen(AGENTS_BEGIN, "<!-- planted missing begin -->", 1),
            "markers must each occur once",
        ),
        (
            "duplicate-marker",
            agents.replacen(AGENTS_BEGIN, &format!("{AGENTS_BEGIN}\n{AGENTS_BEGIN}"), 1),
            "markers must each occur once",
        ),
        (
            "reversed-markers",
            agents
                .replace(AGENTS_BEGIN, "<!-- planted temporary marker -->")
                .replace(AGENTS_END, AGENTS_BEGIN)
                .replace("<!-- planted temporary marker -->", AGENTS_END),
            "reversed or nested",
        ),
    ] {
        let case_root = temp.path().join(case);
        std::fs::create_dir(&case_root).expect("create marker case directory");
        std::fs::write(case_root.join(AGENTS_PATH), mutated).expect("write marker case");
        assert_failed_with(
            &run_agents_generator(
                &case_root,
                &canonical_budget,
                "--check-agents-key-dependencies",
                &[],
            ),
            marker,
        );
    }
}

#[test]
fn agents_modes_reject_ambiguous_or_ledger_generation_options() {
    let root = repo_root();
    let budget = root.join(ARTIFACT_PATH);
    assert_failed_with(
        &run_agents_generator(
            &root,
            &budget,
            "--render-agents-key-dependencies",
            &["--output", "-"],
        ),
        "cannot be combined with ledger-generation options",
    );
    assert_failed_with(
        &run_agents_generator(
            &root,
            &budget,
            "--render-agents-key-dependencies",
            &["--check-agents-key-dependencies"],
        ),
        "select exactly one",
    );

    let output = Command::new(env!("CARGO_BIN_EXE_dependency_marginal_ledger"))
        .arg("--repo-root")
        .arg(&root)
        .arg("--render-agents-key-dependencies")
        .output()
        .expect("run missing-input negative");
    assert_failed_with(&output, "requires both an input budget");
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
    assert_eq!(
        ids,
        BTreeSet::from([
            "release-v040-dev-tracing-log",
            "release-v040-normal-tracing-log",
        ]),
        "only the reviewed v0.4.0 tracing-log additions may widen the direct-edge allowset"
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
    assert_eq!(text(claim, "status"), "green");
    assert_eq!(text(claim, "proof_evidence_status"), "fresh-rch-pass");
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
