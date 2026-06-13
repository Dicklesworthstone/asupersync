#![allow(clippy::nursery, clippy::pedantic, missing_docs)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const ARTIFACT_PATH: &str = "artifacts/migration_recipe_compiler_v1.json";
const DOCS_PATH: &str = "docs/migration_recipe_compiler.md";
const INTEGRATION_DOCS_PATH: &str = "docs/integration.md";
const TEST_PATH: &str = "tests/migration_recipe_compiler_contract.rs";
const BEAD_ID: &str = "asupersync-idea-wizard-fifth-wave-3gaiun.13";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|err| panic!("read {relative}: {err}"))
}

fn artifact() -> Value {
    serde_json::from_str(&read_repo_file(ARTIFACT_PATH))
        .unwrap_or_else(|err| panic!("parse {ARTIFACT_PATH}: {err}"))
}

fn array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .map_or_else(|| panic!("{key} must be an array"), Vec::as_slice)
}

fn object<'a>(value: &'a Value, key: &str) -> &'a serde_json::Map<String, Value> {
    value
        .get(key)
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("{key} must be an object"))
}

fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    let text = value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"));
    assert!(!text.trim().is_empty(), "{key} must be nonempty");
    text
}

fn bool_field(value: &Value, key: &str) -> bool {
    value
        .get(key)
        .and_then(Value::as_bool)
        .unwrap_or_else(|| panic!("{key} must be a bool"))
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

fn assert_live_path(path: &str) {
    assert!(repo_path(path).exists(), "path must exist: {path}");
}

#[test]
fn artifact_declares_source_paths_docs_and_remote_validation() {
    let artifact = artifact();
    assert_eq!(
        artifact.get("schema_version").and_then(Value::as_str),
        Some("migration-recipe-compiler-v1")
    );
    assert_eq!(
        artifact.get("bead_id").and_then(Value::as_str),
        Some(BEAD_ID)
    );
    assert_eq!(
        artifact.get("artifact_path").and_then(Value::as_str),
        Some(ARTIFACT_PATH)
    );

    let source = object(&artifact, "source_of_truth");
    assert_eq!(
        source.get("artifact").and_then(Value::as_str),
        Some(ARTIFACT_PATH)
    );
    assert_eq!(source.get("docs").and_then(Value::as_str), Some(DOCS_PATH));
    assert_eq!(
        source.get("integration_docs").and_then(Value::as_str),
        Some(INTEGRATION_DOCS_PATH)
    );
    assert_eq!(
        source.get("contract_test").and_then(Value::as_str),
        Some(TEST_PATH)
    );

    for path in array(&artifact, "source_paths") {
        assert_live_path(path.as_str().expect("source path string"));
    }

    let docs = read_repo_file(DOCS_PATH);
    assert!(docs.contains(ARTIFACT_PATH), "docs must link artifact");
    assert!(docs.contains(BEAD_ID), "docs must link bead");
    for marker in array(&artifact, "docs_markers") {
        let marker = marker.as_str().expect("docs marker string");
        assert!(docs.contains(marker), "docs missing marker {marker}");
    }

    let integration_docs = read_repo_file(INTEGRATION_DOCS_PATH);
    assert!(
        integration_docs.contains(DOCS_PATH),
        "integration docs must link recipe compiler docs"
    );
    for marker in array(&artifact, "integration_docs_markers") {
        let marker = marker.as_str().expect("integration marker string");
        assert!(
            integration_docs.contains(marker),
            "integration docs missing marker {marker}"
        );
    }

    let validation = object(&artifact, "validation");
    let command = validation
        .get("rch_command")
        .and_then(Value::as_str)
        .expect("validation.rch_command string");
    assert!(command.starts_with("RCH_REQUIRE_REMOTE=1 rch exec -- env "));
    assert!(command.contains("cargo test -p asupersync --test migration_recipe_compiler_contract"));
    assert!(command.contains("--no-default-features"));
    assert_eq!(
        validation.get("no_local_cargo_fallback"),
        Some(&Value::Bool(true))
    );
}

#[test]
fn concept_catalog_covers_required_tokio_and_web_migration_surfaces() {
    let artifact = artifact();
    let required = string_set(&artifact, "required_source_concepts");
    let catalog = array(&artifact, "concept_catalog");
    let actual = catalog
        .iter()
        .map(|concept| string(concept, "concept_id").to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(actual, required);

    for required_prefix in ["tokio_", "hyper_", "tonic_", "axum_", "tower_", "reqwest_"] {
        assert!(
            required
                .iter()
                .any(|concept| concept.starts_with(required_prefix)),
            "missing source concept prefix {required_prefix}"
        );
    }

    for concept in catalog {
        let concept_id = string(concept, "concept_id");
        assert!(
            !array(concept, "planner_markers").is_empty(),
            "{concept_id} must declare planner markers"
        );
        assert!(
            !array(concept, "target_modules").is_empty(),
            "{concept_id} must declare target modules"
        );
        assert!(
            string(concept, "recipe_guidance").contains("Cx")
                || string(concept, "recipe_guidance").contains("compat")
                || string(concept, "recipe_guidance").contains("native")
                || string(concept, "recipe_guidance").contains("cancel")
                || string(concept, "recipe_guidance").contains("Preserve"),
            "{concept_id} guidance must be migration-specific"
        );
    }
}

#[test]
fn fixtures_and_recipes_are_complete_and_read_only() {
    let artifact = artifact();
    let required_fixtures = string_set(&artifact, "required_fixture_ids");
    let fixture_ids = array(&artifact, "fixture_projects")
        .iter()
        .map(|fixture| string(fixture, "fixture_id").to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(fixture_ids, required_fixtures);

    let required_recipe_fields = string_set(&artifact, "required_recipe_fields");
    let recipes = array(&artifact, "compiled_recipe_examples");
    assert!(
        !recipes.is_empty(),
        "compiled recipe examples must not be empty"
    );

    let mut covered_concepts = BTreeSet::new();
    for recipe in recipes {
        let recipe_id = string(recipe, "recipe_id");
        for required in &required_recipe_fields {
            assert!(
                recipe.get(required).is_some(),
                "{recipe_id} missing {required}"
            );
        }
        assert_eq!(
            recipe.get("no_destructive_edits").and_then(Value::as_bool),
            Some(true),
            "{recipe_id} must be read-only"
        );
        assert_eq!(
            recipe.get("no_auto_codemod").and_then(Value::as_bool),
            Some(true),
            "{recipe_id} must not be a codemod"
        );
        assert!(
            !array(recipe, "generated_checklist").is_empty(),
            "{recipe_id} must include a generated checklist"
        );
        assert!(
            !array(recipe, "pattern_changes").is_empty(),
            "{recipe_id} must include manual pattern changes"
        );
        assert!(
            !array(recipe, "no_claims").is_empty(),
            "{recipe_id} must include no-claim boundaries"
        );
        for concept in array(recipe, "source_concepts") {
            covered_concepts.insert(concept.as_str().expect("concept string").to_owned());
        }
    }

    let required_concepts = string_set(&artifact, "required_source_concepts");
    assert_eq!(
        covered_concepts, required_concepts,
        "recipe examples must cover every required concept"
    );
}

#[test]
fn proof_lanes_are_rch_routed_and_scoped() {
    let artifact = artifact();
    let proof_lanes = array(&artifact, "proof_lanes");
    assert!(!proof_lanes.is_empty(), "proof lanes must not be empty");

    let lane_ids = proof_lanes
        .iter()
        .map(|lane| string(lane, "lane_id").to_owned())
        .collect::<BTreeSet<_>>();
    assert!(lane_ids.contains("migration-recipe-compiler-contract"));
    assert!(lane_ids.contains("default-production-tokio-tree"));
    assert!(lane_ids.contains("migration-readiness-planner-contract"));

    for lane in proof_lanes {
        let lane_id = string(lane, "lane_id");
        let command = string(lane, "command");
        assert!(
            command.starts_with("RCH_REQUIRE_REMOTE=1 rch exec -- env "),
            "{lane_id} must be remote-only"
        );
        assert!(
            !command.starts_with("cargo "),
            "{lane_id} must not use local cargo"
        );
        assert!(
            !array(lane, "covers").is_empty(),
            "{lane_id} must declare scoped coverage"
        );
        assert!(
            !array(lane, "does_not_cover").is_empty(),
            "{lane_id} must declare no-claim boundaries"
        );
    }
}

#[test]
fn destructive_policy_and_rendered_artifact_reject_auto_porting() {
    let artifact = artifact();
    let policy = artifact
        .get("no_destructive_edit_policy")
        .expect("policy must exist");
    assert!(!bool_field(policy, "planner_mutates_scanned_project"));
    assert!(!bool_field(policy, "compiler_mutates_scanned_project"));
    assert!(!bool_field(policy, "auto_codemod_allowed"));
    assert!(!bool_field(policy, "destructive_commands_allowed"));
    assert!(string(policy, "required_boundary").contains("must not rewrite source files"));

    let forbidden_commands = array(policy, "forbidden_commands")
        .iter()
        .map(|command| command.as_str().expect("forbidden command"))
        .collect::<BTreeSet<_>>();
    for forbidden in [
        "git reset --hard",
        "git clean -fd",
        "rm -rf",
        "git worktree add",
        "git branch ",
    ] {
        assert!(
            forbidden_commands.contains(forbidden),
            "missing forbidden command {forbidden}"
        );
    }

    let rendered = serde_json::to_string(&artifact).expect("render artifact");
    let forbidden_claims = BTreeMap::from([
        (
            "\"auto_codemod_allowed\":true",
            "auto codemod must remain false",
        ),
        (
            "\"destructive_commands_allowed\":true",
            "destructive edits must remain false",
        ),
        (
            "\"planner_mutates_scanned_project\":true",
            "planner must be read-only",
        ),
        (
            "\"compiler_mutates_scanned_project\":true",
            "compiler must be read-only",
        ),
    ]);
    for (needle, message) in forbidden_claims {
        assert!(!rendered.contains(needle), "{message}");
    }
}
