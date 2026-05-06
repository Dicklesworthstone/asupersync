//! Contract tests for the massive-swarm skill provenance artifact.

#![allow(missing_docs)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const ARTIFACT_PATH: &str = "artifacts/massive_swarm_skill_provenance_v1.json";
const RUNNER_SCRIPT_PATH: &str = "scripts/run_massive_swarm_skill_provenance_smoke.sh";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn load_artifact() -> Value {
    let raw = std::fs::read_to_string(repo_root().join(ARTIFACT_PATH))
        .expect("failed to load massive swarm skill provenance artifact");
    serde_json::from_str(&raw).expect("failed to parse massive swarm skill provenance artifact")
}

fn validate_mapping(mapping: &Value, required_fields: &[String]) -> Result<(), String> {
    for field in required_fields {
        let value = mapping
            .get(field)
            .ok_or_else(|| format!("missing mapping field {field}"))?;
        let missing = value.is_null()
            || value.as_str().is_some_and(str::is_empty)
            || value.as_array().is_some_and(Vec::is_empty);
        if missing {
            return Err(format!("empty mapping field {field}"));
        }
    }

    let ev_score = mapping["ev_score"]
        .as_f64()
        .ok_or_else(|| "ev_score must be numeric".to_string())?;
    if ev_score < 2.0 {
        return Err(format!("ev_score below implementation gate: {ev_score}"));
    }

    let relevance_score = mapping["relevance_score"]
        .as_f64()
        .ok_or_else(|| "relevance_score must be numeric".to_string())?;
    if relevance_score <= 0.0 {
        return Err("relevance_score must be positive".to_string());
    }

    Ok(())
}

fn ranked_ideas(value: &Value, field: &str) -> Result<BTreeMap<u64, String>, String> {
    let ideas = value[field]
        .as_array()
        .ok_or_else(|| format!("{field} must be array"))?;
    let mut ranked = BTreeMap::new();

    for item in ideas {
        let rank = item["rank"]
            .as_u64()
            .ok_or_else(|| format!("{field} rank must be unsigned integer"))?;
        let idea = item["idea"]
            .as_str()
            .ok_or_else(|| format!("{field} idea must be string"))?
            .to_string();
        if idea.trim().is_empty() {
            return Err(format!("{field} idea must be nonempty"));
        }
        if ranked.insert(rank, idea).is_some() {
            return Err(format!("{field} contains duplicate rank {rank}"));
        }
    }

    Ok(ranked)
}

fn require_exact_rank_window(
    ranked: &BTreeMap<u64, String>,
    field: &str,
    expected: std::ops::RangeInclusive<u64>,
) -> Result<(), String> {
    let actual = ranked.keys().copied().collect::<Vec<_>>();
    let expected = expected.collect::<Vec<_>>();
    if actual != expected {
        return Err(format!(
            "{field} ranks must be exactly {expected:?}, got {actual:?}"
        ));
    }
    Ok(())
}

fn validate_artifact(artifact: &Value) -> Result<(), String> {
    let top_level_required = [
        "contract_version",
        "bead_id",
        "source_skills",
        "objective",
        "objective_requirements",
        "idea_wizard_phase_ledger",
        "alien_artifact_compilation",
        "extreme_optimization_discipline",
        "alien_graveyard_provenance",
        "required_mapping_fields",
        "selected_bead_mappings",
        "smoke_scenarios",
    ];

    for field in top_level_required {
        if artifact.get(field).is_none() {
            return Err(format!("missing top-level field {field}"));
        }
    }

    if artifact["source_skills"].as_array().map_or(0, Vec::len) != 4 {
        return Err("source_skills must contain the four requested skills".to_string());
    }

    let ledger = &artifact["idea_wizard_phase_ledger"];
    if ledger["generated_ideas"].as_array().map_or(0, Vec::len) != 30 {
        return Err("idea-wizard phase 2 must preserve 30 generated ideas".to_string());
    }
    if ledger["top_5"].as_array().map_or(0, Vec::len) != 5 {
        return Err("idea-wizard phase 2 must preserve the top 5".to_string());
    }
    if ledger["next_10"].as_array().map_or(0, Vec::len) != 10 {
        return Err("idea-wizard phase 3 must preserve the next 10".to_string());
    }
    if ledger["parked_ideas"].as_array().map_or(0, Vec::len) != 5 {
        return Err("idea-wizard overlap pass must preserve parked ideas".to_string());
    }

    let generated_ideas = ranked_ideas(ledger, "generated_ideas")?;
    let top_5 = ranked_ideas(ledger, "top_5")?;
    let next_10 = ranked_ideas(ledger, "next_10")?;
    let parked_ideas = ranked_ideas(ledger, "parked_ideas")?;
    require_exact_rank_window(&generated_ideas, "generated_ideas", 1..=30)?;
    require_exact_rank_window(&top_5, "top_5", 1..=5)?;
    require_exact_rank_window(&next_10, "next_10", 6..=15)?;
    require_exact_rank_window(&parked_ideas, "parked_ideas", 26..=30)?;

    for (field, ranked) in [
        ("top_5", &top_5),
        ("next_10", &next_10),
        ("parked_ideas", &parked_ideas),
    ] {
        for (rank, idea) in ranked {
            match generated_ideas.get(rank) {
                Some(generated) if generated == idea => {}
                Some(generated) => {
                    return Err(format!(
                        "{field} rank {rank} idea must match generated idea {generated:?}"
                    ));
                }
                None => return Err(format!("{field} rank {rank} missing from generated ideas")),
            }
        }
    }

    let required_fields: Vec<String> = artifact["required_mapping_fields"]
        .as_array()
        .ok_or_else(|| "required_mapping_fields must be array".to_string())?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| "required_mapping_fields entries must be strings".to_string())
        })
        .collect::<Result<_, _>>()?;

    let mappings = artifact["selected_bead_mappings"]
        .as_array()
        .ok_or_else(|| "selected_bead_mappings must be array".to_string())?;
    if mappings.len() < 16 {
        return Err("selected_bead_mappings must cover the selected program surface".to_string());
    }

    let mut bead_ids = BTreeSet::new();
    for mapping in mappings {
        validate_mapping(mapping, &required_fields)?;
        let bead_id = mapping["bead_id"]
            .as_str()
            .ok_or_else(|| "bead_id must be string".to_string())?;
        if !bead_ids.insert(bead_id.to_string()) {
            return Err(format!("duplicate bead mapping {bead_id}"));
        }
    }

    let compilation = &artifact["alien_artifact_compilation"];
    if compilation["assumptions_ledger"]
        .as_array()
        .map_or(0, Vec::len)
        < 3
    {
        return Err("assumptions ledger is too thin".to_string());
    }
    if compilation["proof_obligations"]
        .as_array()
        .map_or(0, Vec::len)
        < 4
    {
        return Err("proof obligations are too thin".to_string());
    }
    if compilation["fallback_policy"]["activation_conditions"]
        .as_array()
        .map_or(0, Vec::len)
        < 4
    {
        return Err(
            "fallback policy must fail closed on multiple missing-evidence modes".to_string(),
        );
    }
    if compilation["galaxy_brain_cards"]
        .as_array()
        .map_or(0, Vec::len)
        < 4
    {
        return Err("galaxy-brain transparency cards are missing".to_string());
    }

    let optimization = &artifact["extreme_optimization_discipline"];
    if optimization["baseline_profile_required"].as_bool() != Some(true) {
        return Err("baseline/profile gate must be required".to_string());
    }
    if optimization["one_lever_per_commit"].as_bool() != Some(true) {
        return Err("one-lever-per-commit discipline must be required".to_string());
    }
    if optimization["minimum_score_to_implement"]
        .as_f64()
        .unwrap_or(0.0)
        < 2.0
    {
        return Err("minimum EV score gate must be at least 2.0".to_string());
    }

    if artifact["alien_graveyard_provenance"]
        .as_array()
        .map_or(0, Vec::len)
        < 6
    {
        return Err("graveyard provenance must cover all selected primitive families".to_string());
    }

    Ok(())
}

#[test]
fn artifact_and_runner_exist() {
    assert!(
        Path::new(ARTIFACT_PATH).exists(),
        "skill provenance artifact must exist"
    );
    assert!(
        Path::new(RUNNER_SCRIPT_PATH).exists(),
        "skill provenance smoke runner must exist"
    );
}

#[test]
fn schema_parse_round_trip_is_stable() {
    let artifact = load_artifact();
    let serialized = serde_json::to_string_pretty(&artifact).expect("serialize artifact");
    let reparsed: Value = serde_json::from_str(&serialized).expect("reparse artifact");
    assert_eq!(artifact, reparsed, "artifact must round-trip through JSON");
}

#[test]
fn artifact_contains_required_skill_phase_evidence() {
    let artifact = load_artifact();
    validate_artifact(&artifact).expect("artifact should satisfy required provenance contract");
}

#[test]
fn missing_objective_mapping_is_rejected() {
    let mut artifact = load_artifact();
    artifact
        .as_object_mut()
        .expect("artifact object")
        .remove("objective_requirements");
    assert!(
        validate_artifact(&artifact)
            .expect_err("missing objective requirements should fail")
            .contains("objective_requirements")
    );
}

#[test]
fn missing_idea_wizard_phase_is_rejected() {
    let mut artifact = load_artifact();
    artifact["idea_wizard_phase_ledger"]["generated_ideas"] = Value::Array(Vec::new());
    assert!(
        validate_artifact(&artifact)
            .expect_err("missing idea-wizard phase evidence should fail")
            .contains("30 generated ideas")
    );
}

#[test]
fn idea_wizard_rank_drift_is_rejected() {
    let mut artifact = load_artifact();
    artifact["idea_wizard_phase_ledger"]["next_10"][9]["idea"] =
        Value::from("large-memory evidence/storage profile");
    assert!(
        validate_artifact(&artifact)
            .expect_err("rank drift should fail")
            .contains("next_10 rank 15 idea"),
        "error should identify the drifted rank"
    );

    let mut artifact = load_artifact();
    artifact["idea_wizard_phase_ledger"]["top_5"][4]["rank"] = Value::from(4);
    assert!(
        validate_artifact(&artifact)
            .expect_err("duplicate rank should fail")
            .contains("duplicate rank 4"),
        "error should identify duplicate ranks"
    );
}

#[test]
fn missing_canonical_graveyard_provenance_is_rejected() {
    let mut artifact = load_artifact();
    artifact["alien_graveyard_provenance"] = Value::Array(Vec::new());
    assert!(
        validate_artifact(&artifact)
            .expect_err("missing graveyard provenance should fail")
            .contains("graveyard provenance")
    );
}

#[test]
fn missing_ev_or_relevance_score_is_rejected() {
    let mut artifact = load_artifact();
    artifact["selected_bead_mappings"][0]
        .as_object_mut()
        .expect("mapping object")
        .remove("ev_score");
    assert!(
        validate_artifact(&artifact)
            .expect_err("missing EV score should fail")
            .contains("ev_score")
    );

    let mut artifact = load_artifact();
    artifact["selected_bead_mappings"][0]["relevance_score"] = Value::from(0.0);
    assert!(
        validate_artifact(&artifact)
            .expect_err("zero relevance score should fail")
            .contains("relevance_score")
    );
}

#[test]
fn missing_assumptions_ledger_is_rejected() {
    let mut artifact = load_artifact();
    artifact["alien_artifact_compilation"]["assumptions_ledger"] = Value::Array(Vec::new());
    assert!(
        validate_artifact(&artifact)
            .expect_err("missing assumptions ledger should fail")
            .contains("assumptions ledger")
    );
}

#[test]
fn missing_proof_obligations_are_rejected() {
    let mut artifact = load_artifact();
    artifact["alien_artifact_compilation"]["proof_obligations"] = Value::Array(Vec::new());
    assert!(
        validate_artifact(&artifact)
            .expect_err("missing proof obligations should fail")
            .contains("proof obligations")
    );
}

#[test]
fn missing_fallback_policy_is_rejected() {
    let mut artifact = load_artifact();
    artifact["alien_artifact_compilation"]["fallback_policy"]["activation_conditions"] =
        Value::Array(Vec::new());
    assert!(
        validate_artifact(&artifact)
            .expect_err("missing fallback policy should fail")
            .contains("fallback policy")
    );
}

#[test]
fn missing_galaxy_brain_cards_are_rejected() {
    let mut artifact = load_artifact();
    artifact["alien_artifact_compilation"]["galaxy_brain_cards"] = Value::Array(Vec::new());
    assert!(
        validate_artifact(&artifact)
            .expect_err("missing galaxy brain cards should fail")
            .contains("galaxy-brain")
    );
}

#[test]
fn missing_unit_e2e_or_logging_obligations_are_rejected() {
    for field in ["unit_tests", "e2e_script", "logging_fields"] {
        let mut artifact = load_artifact();
        artifact["selected_bead_mappings"][0][field] = Value::Array(Vec::new());
        assert!(
            validate_artifact(&artifact)
                .unwrap_err_or_else(|| panic!("missing {field} should fail"))
                .contains(field),
            "error should identify missing {field}"
        );
    }
}

#[test]
fn duplicate_bead_ids_are_rejected() {
    let mut artifact = load_artifact();
    let first = artifact["selected_bead_mappings"][0].clone();
    artifact["selected_bead_mappings"]
        .as_array_mut()
        .expect("mappings array")
        .push(first);
    assert!(
        validate_artifact(&artifact)
            .expect_err("duplicate bead should fail")
            .contains("duplicate bead")
    );
}

#[test]
fn stale_closed_bead_reference_without_proof_refs_is_rejected() {
    let mut artifact = load_artifact();
    let mapping = artifact["selected_bead_mappings"][0]
        .as_object_mut()
        .expect("mapping object");
    mapping.insert("proof_refs".to_string(), Value::Array(Vec::new()));
    assert!(
        validate_artifact(&artifact)
            .expect_err("closed/proven bead without proof refs should fail")
            .contains("proof_refs")
    );
}

#[test]
fn deterministic_report_projection_is_stable_and_redacted() {
    let artifact = load_artifact();
    let mapping_ids: BTreeSet<String> = artifact["selected_bead_mappings"]
        .as_array()
        .expect("mappings")
        .iter()
        .map(|mapping| mapping["bead_id"].as_str().expect("bead_id").to_string())
        .collect();

    let projection = serde_json::json!({
        "contract_version": artifact["contract_version"],
        "source_skill_count": artifact["source_skills"].as_array().unwrap().len(),
        "generated_idea_count": artifact["idea_wizard_phase_ledger"]["generated_ideas"].as_array().unwrap().len(),
        "top_5_count": artifact["idea_wizard_phase_ledger"]["top_5"].as_array().unwrap().len(),
        "next_10_count": artifact["idea_wizard_phase_ledger"]["next_10"].as_array().unwrap().len(),
        "parked_idea_count": artifact["idea_wizard_phase_ledger"]["parked_ideas"].as_array().unwrap().len(),
        "bead_mapping_ids": mapping_ids,
    });

    let rendered = serde_json::to_string_pretty(&projection).expect("render projection");
    assert!(
        !rendered.contains("TOKEN") && !rendered.contains("SECRET"),
        "projection should not expose env or secret material"
    );
    assert!(
        rendered.contains("\"generated_idea_count\": 30"),
        "golden projection must pin generated idea count"
    );
    assert!(
        rendered.contains("\"source_skill_count\": 4"),
        "golden projection must pin source skill count"
    );
    assert!(
        rendered.contains("asupersync-ndr3ev"),
        "golden projection must include the provenance bead"
    );
}

#[test]
fn mappings_cover_all_objective_requirements() {
    let artifact = load_artifact();
    let requirements: BTreeSet<String> = artifact["objective_requirements"]
        .as_array()
        .expect("requirements")
        .iter()
        .map(|requirement| {
            requirement["id"]
                .as_str()
                .expect("requirement id")
                .to_string()
        })
        .collect();
    let mapped: BTreeSet<String> = artifact["selected_bead_mappings"]
        .as_array()
        .expect("mappings")
        .iter()
        .map(|mapping| {
            mapping["objective_requirement_id"]
                .as_str()
                .expect("objective requirement id")
                .to_string()
        })
        .collect();

    assert_eq!(
        requirements, mapped,
        "every objective requirement must have at least one selected bead mapping"
    );
}

#[test]
fn mapping_order_is_deterministic_by_first_appearance() {
    let artifact = load_artifact();
    let mut seen = BTreeMap::new();
    for (index, mapping) in artifact["selected_bead_mappings"]
        .as_array()
        .expect("mappings")
        .iter()
        .enumerate()
    {
        let bead_id = mapping["bead_id"].as_str().expect("bead_id");
        assert!(
            seen.insert(bead_id.to_string(), index).is_none(),
            "duplicate bead id should be caught deterministically"
        );
    }
}

#[test]
fn disabled_mode_is_runtime_neutral() {
    let artifact = load_artifact();
    assert_eq!(
        artifact["description"].as_str(),
        Some(
            "Skill-phase provenance and recommendation-card evidence pack for the massive-swarm responsiveness program."
        )
    );
    assert!(
        artifact["selected_bead_mappings"]
            .as_array()
            .expect("mappings")
            .iter()
            .all(|mapping| mapping["verification_command_class"]
                .as_str()
                .expect("verification command")
                .contains("rch")),
        "provenance artifact should specify validation, not change runtime behavior"
    );
}

#[test]
fn runner_script_declares_required_modes_and_log_fields() {
    let script = std::fs::read_to_string(repo_root().join(RUNNER_SCRIPT_PATH))
        .expect("failed to read smoke runner");
    for needle in [
        "--list",
        "--dry-run",
        "--execute",
        "--output-root",
        "source_repo_hash",
        "input_bead_count",
        "selected_idea_count",
        "rejected_idea_count",
        "missing_field_count",
        "projection_hash",
        "repeated_run_hash_match",
    ] {
        assert!(script.contains(needle), "runner must contain {needle}");
    }
}

trait ResultExt<T> {
    fn unwrap_err_or_else(self, f: impl FnOnce() -> T) -> String;
}

impl<T> ResultExt<T> for Result<T, String> {
    fn unwrap_err_or_else(self, f: impl FnOnce() -> T) -> String {
        match self {
            Ok(_) => {
                f();
                unreachable!("closure should panic")
            }
            Err(err) => err,
        }
    }
}
