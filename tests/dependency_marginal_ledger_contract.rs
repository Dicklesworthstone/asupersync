//! Cargo-built dependency marginal-ledger contract.
//!
//! Bead: asupersync-dep-p1-foundations-upksjk.2
//! Fixture: artifacts/dependency_marginal_ledger_v1.json

#![allow(missing_docs)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

const BEAD_ID: &str = "asupersync-dep-p1-foundations-upksjk.2";
const PROGRAM_ID: &str = "asupersync-ir2uf0";
const ARTIFACT_ID: &str = "dependency-marginal-ledger-v1";
const ARTIFACT_PATH: &str = "artifacts/dependency_marginal_ledger_v1.json";
const GENERATOR_PATH: &str = "src/bin/dependency_marginal_ledger.rs";
const TAXONOMY_PATH: &str = "artifacts/dependency_safety_taxonomy_v1.json";
const DOC_PATH: &str = "docs/dependency_marginal_ledger.md";
const CONTRACT_PATH: &str = "tests/dependency_marginal_ledger_contract.rs";
const PROOF_TARGET_DIR: &str = "rch_target_dependency_marginal_ledger_contract";

const PROFILES: &[(&str, &str)] = &[
    ("minimal", "synthesized-consumer"),
    ("default", "synthesized-consumer"),
    ("tls", "synthesized-consumer"),
    ("sqlite", "synthesized-consumer"),
    ("kafka", "synthesized-consumer"),
    ("metrics", "synthesized-consumer"),
    ("cli", "synthesized-consumer"),
    ("compression", "synthesized-consumer"),
    ("trace-compression", "synthesized-consumer"),
    ("io-uring", "synthesized-consumer"),
    ("loom-tests", "synthesized-consumer"),
    ("fuzz-quarantine", "synthesized-consumer"),
    (
        "workspace-dev-build-audit",
        "full-workspace-dev-build-audit",
    ),
];

const TARGETS: &[&str] = &[
    "x86_64-unknown-linux-gnu",
    "aarch64-apple-darwin",
    "x86_64-pc-windows-msvc",
    "wasm32-unknown-unknown",
];

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_repo_file(path: &str) -> String {
    std::fs::read_to_string(repo_root().join(path))
        .expect("failed to read dependency marginal-ledger contract input")
}

fn json_file(path: &str) -> Value {
    serde_json::from_str(&read_repo_file(path))
        .expect("dependency marginal-ledger contract input must be valid JSON")
}

fn ledger() -> Value {
    json_file(ARTIFACT_PATH)
}

fn array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .expect("required ledger field must be an array")
}

fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Value::as_str)
        .expect("required ledger field must be a string")
}

fn number(value: &Value, key: &str) -> u64 {
    value
        .get(key)
        .and_then(Value::as_u64)
        .expect("required ledger field must be an unsigned integer")
}

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    array(value, key)
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .expect("ledger array entries must be strings")
                .to_owned()
        })
        .collect()
}

fn assert_nonempty_string_array(value: &Value, key: &str) {
    let entries = array(value, key);
    assert!(!entries.is_empty(), "{key} must not be empty");
    for entry in entries {
        assert!(
            entry.as_str().is_some_and(|text| !text.trim().is_empty()),
            "{key} entries must be nonempty strings"
        );
    }
}

fn manifest_edge_ids() -> BTreeSet<String> {
    let manifest =
        toml::from_str::<toml::Value>(&read_repo_file("Cargo.toml")).expect("root Cargo.toml");
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
        assert!(
            edges.insert(edge),
            "manifest dependency edge must be unique"
        );
    }
}

fn measurement_key(row: &Value) -> (String, String, String, String, String) {
    (
        string(row, "feature_profile").to_owned(),
        string(row, "target_triple").to_owned(),
        string(row, "host_triple").to_owned(),
        string(row, "dependency_edge_kind").to_owned(),
        string(row, "direct_root_edge").to_owned(),
    )
}

fn native_rank(status: &str) -> u8 {
    match status {
        "none" => 0,
        "declared-inactive" => 1,
        "unknown" => 2,
        "active" => 3,
        _ => u8::MAX,
    }
}

fn safety_rank(class: &str) -> u8 {
    match class {
        "SAFE-OWN" => 1,
        "BOUNDARY-UNSAFE" => 2,
        "ALGORITHMIC-UNSAFE" => 3,
        _ => 4,
    }
}

#[test]
fn header_provenance_and_docs_are_pinned() {
    let ledger = ledger();
    assert_eq!(number(&ledger, "schema_version"), 1);
    assert_eq!(string(&ledger, "artifact_id"), ARTIFACT_ID);
    assert_eq!(string(&ledger, "bead_id"), BEAD_ID);
    assert_eq!(string(&ledger, "program_id"), PROGRAM_ID);
    assert_eq!(string(&ledger, "generator_path"), GENERATOR_PATH);
    assert_eq!(string(&ledger, "taxonomy_path"), TAXONOMY_PATH);
    assert_eq!(string(&ledger, "contract_path"), CONTRACT_PATH);
    assert_eq!(string(&ledger, "documentation_path"), DOC_PATH);

    let source_commit = string(&ledger, "source_commit");
    assert_eq!(source_commit.len(), 40, "source_commit must be a full SHA");
    assert!(
        source_commit.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "source_commit must be hexadecimal"
    );
    assert!(string(&ledger, "cargo_version").starts_with("cargo "));
    assert!(string(&ledger, "rustc_version").starts_with("rustc "));
    assert!(!string(&ledger, "host_triple").trim().is_empty());

    let docs = read_repo_file(DOC_PATH);
    for marker in [
        ARTIFACT_PATH,
        GENERATOR_PATH,
        CONTRACT_PATH,
        "Package IDs",
        "declared-inactive",
        "workspace-dev-build-audit",
        "Individual-edge marginals are not additive savings claims",
        PROOF_TARGET_DIR,
    ] {
        assert!(
            docs.contains(marker),
            "documentation marker missing: {marker}"
        );
    }
    let generator = read_repo_file(GENERATOR_PATH);
    for marker in [
        "#![forbid(unsafe_code)]",
        "--filter-platform",
        "--offline",
        "--source-commit",
        "workspace_members",
        "AtomicUsize",
        "seed_counterfactual_lock",
    ] {
        assert!(
            generator.contains(marker),
            "generator marker missing: {marker}"
        );
    }
    let manifest = read_repo_file("Cargo.toml");
    assert!(manifest.contains("dependency-ledger = [\"dep:toml\"]"));
    assert!(manifest.contains("name = \"dependency_marginal_ledger\""));
    assert!(manifest.contains("required-features = [\"dependency-ledger\"]"));
}

#[test]
fn canonical_profile_target_and_graph_matrix_is_complete() {
    let ledger = ledger();
    let profiles = array(&ledger, "canonical_profiles");
    assert_eq!(profiles.len(), PROFILES.len());
    for (row, (expected_id, expected_scope)) in profiles.iter().zip(PROFILES) {
        assert_eq!(string(row, "profile_id"), *expected_id);
        assert_eq!(string(row, "graph_scope"), *expected_scope);
        assert!(
            row.get("default_features")
                .and_then(Value::as_bool)
                .is_some()
        );
        assert!(
            row.get("feature_vector")
                .and_then(Value::as_array)
                .is_some()
        );
    }
    assert_eq!(
        string_set(&ledger, "canonical_target_triples"),
        TARGETS.iter().map(|target| (*target).to_owned()).collect()
    );

    let expected_cells = PROFILES
        .iter()
        .flat_map(|(profile, _)| {
            TARGETS
                .iter()
                .map(move |target| ((*profile).to_owned(), (*target).to_owned()))
        })
        .collect::<BTreeSet<_>>();
    let graph_records = array(&ledger, "graph_records");
    let actual_cells = graph_records
        .iter()
        .map(|row| {
            (
                string(row, "feature_profile").to_owned(),
                string(row, "target_triple").to_owned(),
            )
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(actual_cells, expected_cells);
    assert_eq!(graph_records.len(), expected_cells.len());

    for row in graph_records {
        let profile = string(row, "feature_profile");
        let target = string(row, "target_triple");
        assert_eq!(string(row, "host_triple"), string(&ledger, "host_triple"));
        assert!(number(row, "baseline_package_version_count") > 0);
        assert!(number(row, "baseline_unique_package_name_count") > 0);
        let active = string_set(row, "active_direct_root_edges");
        let absent = string_set(row, "absent_direct_root_edges");
        assert!(active.is_disjoint(&absent));
        assert_eq!(
            active.union(&absent).cloned().collect::<BTreeSet<_>>(),
            manifest_edge_ids(),
            "{profile} / {target} must classify every root edge"
        );
        let command = string(row, "exact_command");
        assert!(command.contains("cargo metadata --format-version 1"));
        assert!(command.contains(&format!("--filter-platform {target}")));
        assert!(command.contains("$LEDGER_WORK_DIR"));
        assert!(!command.contains("/data/tmp/rch/"));
        if profile == "workspace-dev-build-audit" {
            assert!(command.contains("--all-features"));
        } else {
            assert!(!command.contains("--all-features"));
        }
    }
}

#[test]
fn direct_dependency_inventory_matches_the_root_manifest() {
    let ledger = ledger();
    let inventory = array(&ledger, "direct_dependency_inventory");
    let actual = inventory
        .iter()
        .map(|row| string(row, "edge_id").to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(actual, manifest_edge_ids());
    assert_eq!(actual.len(), inventory.len(), "edge IDs must be unique");

    for row in inventory {
        let kind = string(row, "dependency_edge_kind");
        assert!(
            [
                "normal",
                "dev",
                "build",
                "target-normal",
                "target-dev",
                "target-build"
            ]
            .contains(&kind),
            "unexpected dependency edge kind: {kind}"
        );
        for key in [
            "edge_id",
            "dependency_name",
            "package_name",
            "manifest_table",
        ] {
            assert!(!string(row, key).trim().is_empty());
        }
        assert!(row.get("optional").and_then(Value::as_bool).is_some());
        if kind.starts_with("target-") {
            assert!(
                row.get("target_condition")
                    .and_then(Value::as_str)
                    .is_some_and(|target| !target.is_empty())
            );
        } else {
            assert!(row.get("target_condition").is_some_and(Value::is_null));
        }
    }
}

#[test]
fn every_active_edge_has_one_independent_counterfactual() {
    let ledger = ledger();
    let rows = array(&ledger, "marginal_measurements");
    assert!(!rows.is_empty());
    let keys = rows.iter().map(measurement_key).collect::<BTreeSet<_>>();
    assert_eq!(
        keys.len(),
        rows.len(),
        "marginal result keys must be unique"
    );

    let by_cell = rows.iter().fold(
        BTreeMap::<(String, String), BTreeSet<String>>::new(),
        |mut map, row| {
            map.entry((
                string(row, "feature_profile").to_owned(),
                string(row, "target_triple").to_owned(),
            ))
            .or_default()
            .insert(string(row, "direct_root_edge").to_owned());
            map
        },
    );

    for graph in array(&ledger, "graph_records") {
        let key = (
            string(graph, "feature_profile").to_owned(),
            string(graph, "target_triple").to_owned(),
        );
        assert_eq!(
            by_cell.get(&key),
            Some(&string_set(graph, "active_direct_root_edges")),
            "every active edge needs exactly one counterfactual for {key:?}"
        );
    }

    for row in rows {
        let baseline = number(row, "baseline_package_version_count");
        let counterfactual = number(row, "counterfactual_package_version_count");
        let marginal = number(row, "marginal_package_version_count");
        assert!(counterfactual <= baseline);
        assert_eq!(baseline - counterfactual, marginal);
        assert_eq!(
            marginal,
            array(row, "marginal_package_versions").len() as u64
        );
        assert_ne!(
            string(row, "baseline_manifest_hash"),
            string(row, "counterfactual_manifest_hash")
        );
        for key in [
            "baseline_manifest_hash",
            "counterfactual_manifest_hash",
            "baseline_lockfile_hash",
            "counterfactual_lockfile_hash",
        ] {
            let hash = string(row, key);
            assert_eq!(hash.len(), 64, "{key} must be SHA-256");
            assert!(hash.bytes().all(|byte| byte.is_ascii_hexdigit()));
        }

        let target = string(row, "target_triple");
        let baseline_command = string(row, "exact_baseline_command");
        let counterfactual_command = string(row, "exact_counterfactual_command");
        for command in [baseline_command, counterfactual_command] {
            assert!(command.contains("cargo metadata --format-version 1"));
            assert!(command.contains(&format!("--filter-platform {target}")));
            assert!(command.contains("$LEDGER_WORK_DIR"));
            assert!(!command.contains("/data/tmp/rch/"));
        }
        assert!(!baseline_command.contains("--offline"));
        assert!(counterfactual_command.ends_with("--offline"));
        assert_ne!(baseline_command, counterfactual_command);

        let context = string(row, "execution_context");
        match string(row, "dependency_edge_kind") {
            "build" | "target-build" => assert_eq!(context, "host"),
            "dev" | "target-dev" => assert_eq!(context, "target-dev"),
            "normal" | "target-normal" => {
                assert!(
                    matches!(context, "target" | "host"),
                    "normal dependency has invalid execution context: {context}"
                );
                if context == "host" {
                    assert!(
                        !array(row, "proc_macros").is_empty(),
                        "host-context normal dependency lacks proc-macro evidence"
                    );
                }
            }
            other => {
                assert!(false, "unexpected dependency edge kind: {other}");
            }
        }
    }
}

#[test]
fn identities_native_evidence_and_taxonomy_fail_closed() {
    let ledger = ledger();
    let taxonomy = json_file(TAXONOMY_PATH);
    let taxonomy_rows = array(&taxonomy, "classifications")
        .iter()
        .map(|row| (string(row, "candidate_id"), row))
        .collect::<BTreeMap<_, _>>();
    let mut saw_declared_inactive_signal_hook = false;
    let mut saw_active_rdkafka = false;

    for row in array(&ledger, "marginal_measurements") {
        for package in array(row, "marginal_package_versions") {
            let package = package.as_str().expect("package IDs must be strings");
            assert!(!package.trim().is_empty());
            assert!(!package.starts_with("path+file://$LEDGER_WORK_DIR"));
        }
        for identity in array(row, "unique_upstream_identities") {
            let identity = identity.as_str().expect("identities must be strings");
            assert_ne!(identity, "unknown");
            if identity.starts_with("unknown:") {
                assert!(
                    identity.len() > "unknown:".len(),
                    "unknown identity must retain a package ID"
                );
            }
        }

        for key in ["root_native_code", "marginal_native_code"] {
            let native = row
                .get(key)
                .filter(|value| value.is_object())
                .expect("native evidence field must be an object");
            let status = string(native, "status");
            assert_ne!(native_rank(status), u8::MAX);
            let packages = array(native, "packages");
            let expected = packages
                .iter()
                .map(|package| {
                    assert_nonempty_string_array(package, "evidence_sources");
                    let package_id = string(package, "package_id");
                    let package_status = string(package, "status");
                    assert_ne!(native_rank(package_status), u8::MAX);
                    if package_id.contains("#signal-hook@") && package_status == "declared-inactive"
                    {
                        saw_declared_inactive_signal_hook = true;
                    }
                    if package_id.contains("#rdkafka-sys@") && package_status == "active" {
                        saw_active_rdkafka = true;
                    }
                    native_rank(package_status)
                })
                .max()
                .unwrap_or(0);
            assert_eq!(native_rank(status), expected);
        }

        let refs = array(row, "taxonomy_refs");
        let expected_class = refs
            .iter()
            .map(|reference| {
                let candidate = string(reference, "candidate_id");
                let canonical = taxonomy_rows
                    .get(candidate)
                    .expect("taxonomy reference must name a canonical candidate");
                for key in ["class_id", "program_phase", "program_verdict"] {
                    assert_eq!(string(reference, key), string(canonical, key));
                }
                assert_eq!(
                    string_set(reference, "review_sensitivity_tags"),
                    string_set(canonical, "review_sensitivity_tags")
                );
                string(reference, "class_id")
            })
            .max_by_key(|class| safety_rank(class));
        assert_eq!(
            string(row, "unsafe_exposure_class"),
            expected_class.unwrap_or("unclassified-fail-closed")
        );
    }
    assert!(
        saw_declared_inactive_signal_hook,
        "canonical matrix must retain the signal-hook -> absent cc fixture"
    );
    assert!(
        saw_active_rdkafka,
        "canonical matrix must retain active rdkafka-sys configure/make evidence"
    );
}

#[test]
fn generated_phase_forecasts_recompute_from_measurements() {
    #[derive(Default)]
    struct Expected {
        packages: BTreeSet<String>,
        sum: u64,
        edges: BTreeSet<String>,
    }

    let ledger = ledger();
    let mut expected = BTreeMap::<(String, String, String), Expected>::new();
    for row in array(&ledger, "marginal_measurements") {
        for taxonomy_ref in array(row, "taxonomy_refs") {
            let key = (
                string(row, "feature_profile").to_owned(),
                string(row, "target_triple").to_owned(),
                string(taxonomy_ref, "program_phase").to_owned(),
            );
            let entry = expected.entry(key).or_default();
            entry
                .packages
                .extend(string_set(row, "marginal_package_versions"));
            entry.sum += number(row, "marginal_package_version_count");
            entry
                .edges
                .insert(string(row, "direct_root_edge").to_owned());
        }
    }

    let forecasts = array(&ledger, "generated_phase_forecasts");
    assert_eq!(forecasts.len(), expected.len());
    let mut seen = BTreeSet::new();
    for row in forecasts {
        let key = (
            string(row, "feature_profile").to_owned(),
            string(row, "target_triple").to_owned(),
            string(row, "program_phase").to_owned(),
        );
        assert!(seen.insert(key.clone()), "forecast keys must be unique");
        let expected = expected
            .get(&key)
            .expect("forecast must correspond to measured taxonomy rows");
        assert_eq!(
            number(row, "lower_bound_unique_individual_marginals"),
            expected.packages.len() as u64
        );
        assert_eq!(
            number(row, "upper_bound_sum_individual_marginals"),
            expected.sum
        );
        assert_eq!(
            string_set(row, "contributing_direct_root_edges"),
            expected.edges
        );
        assert!(
            string(row, "no_claim_boundary").contains("separately resolved multi-edge"),
            "forecast must state its non-additivity boundary"
        );
    }
}

#[test]
fn policies_and_no_claim_boundaries_remain_explicit() {
    let ledger = ledger();
    for key in [
        "upstream_identity_policy",
        "native_evidence_policy",
        "methodology",
        "no_claim_boundaries",
    ] {
        assert_nonempty_string_array(&ledger, key);
    }
    let policies = [
        "Cargo resolution alone never proves native compilation",
        "Package IDs, not package-name text",
        "not compilation, runtime correctness, performance, release readiness",
        "Individual-edge marginals do not equal",
        "taxonomy reference records review obligations",
    ];
    let rendered = serde_json::to_string(&ledger).expect("serialize ledger");
    for policy in policies {
        assert!(rendered.contains(policy), "missing policy marker: {policy}");
    }
}
