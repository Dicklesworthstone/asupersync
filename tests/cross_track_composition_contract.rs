//! Cross-track composition contract invariants (AA-10.4).

#![allow(missing_docs, clippy::cast_precision_loss)]

use serde_json::Value;
use std::collections::HashSet;

const DOC_PATH: &str = "docs/cross_track_composition_contract.md";
const ARTIFACT_PATH: &str = "artifacts/cross_track_composition_v1.json";
const RUNNER_PATH: &str = "scripts/run_cross_track_composition_smoke.sh";

fn load_artifact() -> Value {
    let content =
        std::fs::read_to_string(ARTIFACT_PATH).expect("artifact must exist at expected path");
    serde_json::from_str(&content).expect("artifact must be valid JSON")
}

fn load_doc() -> String {
    std::fs::read_to_string(DOC_PATH).expect("contract doc must exist")
}

fn load_runner() -> String {
    std::fs::read_to_string(RUNNER_PATH).expect("runner script must exist")
}

// ── Document stability ─────────────────────────────────────────────

#[test]
fn doc_exists_and_has_required_sections() {
    let doc = load_doc();
    for section in &[
        "## Purpose",
        "## Contract Artifacts",
        "## Compatibility Matrix",
        "## Incident Drills",
        "## Validation",
        "## Cross-References",
    ] {
        assert!(doc.contains(section), "doc must contain section: {section}");
    }
}

#[test]
fn doc_references_bead_id() {
    let doc = load_doc();
    let art = load_artifact();
    let bead_id = art["bead_id"].as_str().unwrap();
    assert!(doc.contains(bead_id), "doc must reference bead_id {bead_id}");
}

// ── Artifact stability ─────────────────────────────────────────────

#[test]
fn artifact_has_contract_version() {
    let art = load_artifact();
    assert_eq!(
        art["contract_version"].as_str().unwrap(),
        "cross-track-composition-v1"
    );
}

#[test]
fn artifact_has_runner_script() {
    let art = load_artifact();
    let runner = art["runner_script"].as_str().unwrap();
    assert!(
        std::path::Path::new(runner).exists(),
        "runner script must exist at {runner}"
    );
}

// ── Compatibility matrix: structure ─────────────────────────────────

#[test]
fn matrix_tracks_are_nonempty() {
    let art = load_artifact();
    let tracks = art["compatibility_matrix"]["tracks"].as_array().unwrap();
    assert!(tracks.len() >= 9, "must have at least 9 tracks");
}

#[test]
fn matrix_track_ids_are_unique() {
    let art = load_artifact();
    let tracks = art["compatibility_matrix"]["tracks"].as_array().unwrap();
    let ids: Vec<&str> = tracks
        .iter()
        .map(|t| t["track_id"].as_str().unwrap())
        .collect();
    let mut deduped = ids.clone();
    deduped.sort_unstable();
    deduped.dedup();
    assert_eq!(ids.len(), deduped.len(), "track_ids must be unique");
}

#[test]
fn matrix_track_ids_have_aa_prefix() {
    let art = load_artifact();
    let tracks = art["compatibility_matrix"]["tracks"].as_array().unwrap();
    for track in tracks {
        let tid = track["track_id"].as_str().unwrap();
        assert!(tid.starts_with("AA-"), "track '{tid}' must start with AA-");
    }
}

#[test]
fn matrix_combinations_are_nonempty() {
    let art = load_artifact();
    let combos = art["compatibility_matrix"]["combinations"]
        .as_array()
        .unwrap();
    assert!(combos.len() >= 10, "must have at least 10 combinations");
}

#[test]
fn matrix_combo_ids_are_unique() {
    let art = load_artifact();
    let combos = art["compatibility_matrix"]["combinations"]
        .as_array()
        .unwrap();
    let ids: Vec<&str> = combos
        .iter()
        .map(|c| c["combo_id"].as_str().unwrap())
        .collect();
    let mut deduped = ids.clone();
    deduped.sort_unstable();
    deduped.dedup();
    assert_eq!(ids.len(), deduped.len(), "combo_ids must be unique");
}

#[test]
fn matrix_combo_ids_have_cx_prefix() {
    let art = load_artifact();
    let combos = art["compatibility_matrix"]["combinations"]
        .as_array()
        .unwrap();
    for combo in combos {
        let cid = combo["combo_id"].as_str().unwrap();
        assert!(
            cid.starts_with("CX-"),
            "combo '{cid}' must start with CX-"
        );
    }
}

#[test]
fn matrix_combo_statuses_are_valid() {
    let art = load_artifact();
    let combos = art["compatibility_matrix"]["combinations"]
        .as_array()
        .unwrap();
    let valid = art["compatibility_matrix"]["status_definitions"]
        .as_object()
        .unwrap();
    let valid_keys: HashSet<&str> = valid.keys().map(String::as_str).collect();
    for combo in combos {
        let cid = combo["combo_id"].as_str().unwrap();
        let status = combo["status"].as_str().unwrap();
        assert!(
            valid_keys.contains(status),
            "{cid}: status '{status}' must be a defined status"
        );
    }
}

#[test]
fn matrix_combo_tracks_reference_known_tracks() {
    let art = load_artifact();
    let tracks = art["compatibility_matrix"]["tracks"].as_array().unwrap();
    let known: HashSet<&str> = tracks
        .iter()
        .map(|t| t["track_id"].as_str().unwrap())
        .collect();
    let combos = art["compatibility_matrix"]["combinations"]
        .as_array()
        .unwrap();
    for combo in combos {
        let cid = combo["combo_id"].as_str().unwrap();
        let combo_tracks = combo["tracks"].as_array().unwrap();
        for t in combo_tracks {
            let tid = t.as_str().unwrap();
            assert!(known.contains(tid), "{cid}: track '{tid}' must be known");
        }
    }
}

#[test]
fn matrix_has_full_stack_combination() {
    let art = load_artifact();
    let combos = art["compatibility_matrix"]["combinations"]
        .as_array()
        .unwrap();
    assert!(
        combos
            .iter()
            .any(|c| c["combo_id"].as_str().unwrap() == "CX-FULL-STACK"),
        "must have CX-FULL-STACK combination"
    );
}

#[test]
fn matrix_full_stack_is_supported() {
    let art = load_artifact();
    let combos = art["compatibility_matrix"]["combinations"]
        .as_array()
        .unwrap();
    let full_stack = combos
        .iter()
        .find(|c| c["combo_id"].as_str().unwrap() == "CX-FULL-STACK")
        .unwrap();
    assert_eq!(
        full_stack["status"].as_str().unwrap(),
        "supported",
        "CX-FULL-STACK must be supported"
    );
}

#[test]
fn matrix_at_least_half_supported() {
    let art = load_artifact();
    let combos = art["compatibility_matrix"]["combinations"]
        .as_array()
        .unwrap();
    let supported = combos
        .iter()
        .filter(|c| c["status"].as_str().unwrap() == "supported")
        .count();
    assert!(
        supported * 2 >= combos.len(),
        "at least half of combinations must be supported"
    );
}

#[test]
fn matrix_status_definitions_cover_all_used() {
    let art = load_artifact();
    let combos = art["compatibility_matrix"]["combinations"]
        .as_array()
        .unwrap();
    let used: HashSet<&str> = combos
        .iter()
        .map(|c| c["status"].as_str().unwrap())
        .collect();
    let defined = art["compatibility_matrix"]["status_definitions"]
        .as_object()
        .unwrap();
    for status in &used {
        assert!(
            defined.contains_key(*status),
            "used status '{status}' must be defined in status_definitions"
        );
    }
}

// ── Incident drills ─────────────────────────────────────────────────

#[test]
fn drill_definitions_are_nonempty() {
    let art = load_artifact();
    let drills = art["incident_drills"].as_array().unwrap();
    assert!(drills.len() >= 5, "must have at least 5 incident drills");
}

#[test]
fn drill_ids_are_unique() {
    let art = load_artifact();
    let drills = art["incident_drills"].as_array().unwrap();
    let ids: Vec<&str> = drills
        .iter()
        .map(|d| d["drill_id"].as_str().unwrap())
        .collect();
    let mut deduped = ids.clone();
    deduped.sort_unstable();
    deduped.dedup();
    assert_eq!(ids.len(), deduped.len(), "drill_ids must be unique");
}

#[test]
fn drill_ids_have_id_prefix() {
    let art = load_artifact();
    let drills = art["incident_drills"].as_array().unwrap();
    for drill in drills {
        let did = drill["drill_id"].as_str().unwrap();
        assert!(did.starts_with("ID-"), "drill '{did}' must start with ID-");
    }
}

#[test]
fn drills_have_steps() {
    let art = load_artifact();
    let drills = art["incident_drills"].as_array().unwrap();
    for drill in drills {
        let did = drill["drill_id"].as_str().unwrap();
        let steps = drill["steps"].as_array().unwrap();
        assert!(
            steps.len() >= 3,
            "{did}: must have at least 3 steps, got {}",
            steps.len()
        );
    }
}

#[test]
fn drills_reference_known_tracks() {
    let art = load_artifact();
    let tracks = art["compatibility_matrix"]["tracks"].as_array().unwrap();
    let known: HashSet<&str> = tracks
        .iter()
        .map(|t| t["track_id"].as_str().unwrap())
        .collect();
    let drills = art["incident_drills"].as_array().unwrap();
    for drill in drills {
        let did = drill["drill_id"].as_str().unwrap();
        let exercised = drill["tracks_exercised"].as_array().unwrap();
        for t in exercised {
            let tid = t.as_str().unwrap();
            assert!(
                known.contains(tid),
                "{did}: track '{tid}' must be a known track"
            );
        }
    }
}

#[test]
fn drills_cover_recovery_track() {
    let art = load_artifact();
    let drills = art["incident_drills"].as_array().unwrap();
    let covers_recovery = drills.iter().any(|d| {
        d["tracks_exercised"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t.as_str().unwrap() == "AA-09")
    });
    assert!(
        covers_recovery,
        "at least one drill must exercise recovery track AA-09"
    );
}

#[test]
fn drills_cover_authority_track() {
    let art = load_artifact();
    let drills = art["incident_drills"].as_array().unwrap();
    let covers_authority = drills.iter().any(|d| {
        d["tracks_exercised"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t.as_str().unwrap() == "AA-07")
    });
    assert!(
        covers_authority,
        "at least one drill must exercise authority track AA-07"
    );
}

// ── Structured logging ──────────────────────────────────────────────

#[test]
fn structured_log_fields_are_nonempty() {
    let art = load_artifact();
    let fields = art["structured_log_fields_required"]
        .as_array()
        .unwrap();
    assert!(fields.len() >= 8, "must have at least 8 log fields");
}

#[test]
fn structured_log_fields_are_unique() {
    let art = load_artifact();
    let fields = art["structured_log_fields_required"]
        .as_array()
        .unwrap();
    let strs: Vec<&str> = fields.iter().map(|f| f.as_str().unwrap()).collect();
    let mut deduped = strs.clone();
    deduped.sort_unstable();
    deduped.dedup();
    assert_eq!(strs.len(), deduped.len(), "log fields must be unique");
}

#[test]
fn structured_log_includes_drill_fields() {
    let art = load_artifact();
    let fields = art["structured_log_fields_required"]
        .as_array()
        .unwrap();
    let strs: Vec<&str> = fields.iter().map(|f| f.as_str().unwrap()).collect();
    assert!(strs.contains(&"drill_id"), "must include drill_id");
    assert!(strs.contains(&"drill_step"), "must include drill_step");
    assert!(strs.contains(&"combo_id"), "must include combo_id");
}

#[test]
fn structured_log_includes_rerun_command() {
    let art = load_artifact();
    let fields = art["structured_log_fields_required"]
        .as_array()
        .unwrap();
    assert!(
        fields
            .iter()
            .any(|f| f.as_str().unwrap() == "rerun_command"),
        "must include rerun_command"
    );
}

// ── Smoke / runner ──────────────────────────────────────────────────

#[test]
fn smoke_scenarios_are_nonempty() {
    let art = load_artifact();
    let scenarios = art["smoke_scenarios"].as_array().unwrap();
    assert!(scenarios.len() >= 3, "must have at least 3 smoke scenarios");
}

#[test]
fn smoke_scenario_ids_are_unique() {
    let art = load_artifact();
    let scenarios = art["smoke_scenarios"].as_array().unwrap();
    let ids: Vec<&str> = scenarios
        .iter()
        .map(|s| s["scenario_id"].as_str().unwrap())
        .collect();
    let mut deduped = ids.clone();
    deduped.sort_unstable();
    deduped.dedup();
    assert_eq!(ids.len(), deduped.len(), "scenario_ids must be unique");
}

#[test]
fn smoke_scenarios_are_rch_routed() {
    let art = load_artifact();
    let scenarios = art["smoke_scenarios"].as_array().unwrap();
    for scenario in scenarios {
        let sid = scenario["scenario_id"].as_str().unwrap();
        let cmd = scenario["command"].as_str().unwrap();
        assert!(cmd.starts_with("rch exec"), "{sid}: must be rch-routed");
    }
}

#[test]
fn runner_script_exists_and_declares_modes() {
    let runner = load_runner();
    for mode in &["--list", "--dry-run", "--execute", "--scenario"] {
        assert!(runner.contains(mode), "runner must support {mode}");
    }
}

// ── Functional: composition validation ──────────────────────────────

#[test]
fn composition_supported_combos_have_at_least_two_tracks() {
    let art = load_artifact();
    let combos = art["compatibility_matrix"]["combinations"]
        .as_array()
        .unwrap();
    for combo in combos {
        let cid = combo["combo_id"].as_str().unwrap();
        let tracks = combo["tracks"].as_array().unwrap();
        assert!(
            tracks.len() >= 2,
            "{cid}: must reference at least 2 tracks"
        );
    }
}

#[test]
fn composition_full_stack_covers_core_tracks() {
    let art = load_artifact();
    let combos = art["compatibility_matrix"]["combinations"]
        .as_array()
        .unwrap();
    let full_stack = combos
        .iter()
        .find(|c| c["combo_id"].as_str().unwrap() == "CX-FULL-STACK")
        .unwrap();
    let tracks: HashSet<&str> = full_stack["tracks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t.as_str().unwrap())
        .collect();
    for core in &["AA-01", "AA-02", "AA-04", "AA-05", "AA-07", "AA-09"] {
        assert!(
            tracks.contains(core),
            "CX-FULL-STACK must include core track {core}"
        );
    }
}

#[test]
fn composition_experimental_combos_involve_transport() {
    let art = load_artifact();
    let combos = art["compatibility_matrix"]["combinations"]
        .as_array()
        .unwrap();
    let experimental: Vec<&Value> = combos
        .iter()
        .filter(|c| c["status"].as_str().unwrap() == "experimental")
        .collect();
    for combo in &experimental {
        let cid = combo["combo_id"].as_str().unwrap();
        let tracks = combo["tracks"].as_array().unwrap();
        let has_transport = tracks
            .iter()
            .any(|t| t.as_str().unwrap() == "AA-08");
        assert!(
            has_transport,
            "{cid}: experimental combos should involve transport (AA-08)"
        );
    }
}

#[test]
fn composition_drill_multi_track_coverage() {
    let art = load_artifact();
    let drills = art["incident_drills"].as_array().unwrap();
    let multi_track_drills = drills
        .iter()
        .filter(|d| d["tracks_exercised"].as_array().unwrap().len() >= 3)
        .count();
    assert!(
        multi_track_drills >= 2,
        "must have at least 2 drills exercising 3+ tracks"
    );
}

#[test]
fn composition_decision_plane_most_connected() {
    let art = load_artifact();
    let combos = art["compatibility_matrix"]["combinations"]
        .as_array()
        .unwrap();
    let tracks = art["compatibility_matrix"]["tracks"].as_array().unwrap();
    let track_ids: Vec<&str> = tracks
        .iter()
        .map(|t| t["track_id"].as_str().unwrap())
        .collect();

    let mut max_connections = 0;
    let mut most_connected = "";
    for tid in &track_ids {
        let count = combos
            .iter()
            .filter(|c| {
                let ct = c["tracks"].as_array().unwrap();
                ct.iter().any(|t| t.as_str().unwrap() == *tid)
                    && c["combo_id"].as_str().unwrap() != "CX-FULL-STACK"
            })
            .count();
        if count > max_connections {
            max_connections = count;
            most_connected = tid;
        }
    }
    assert_eq!(
        most_connected, "AA-02",
        "Decision Plane (AA-02) should be most connected track"
    );
}

// ── Cross-artifact consistency ──────────────────────────────────────

#[test]
fn downstream_beads_are_listed() {
    let art = load_artifact();
    let downstream = art["downstream_beads"].as_array().unwrap();
    assert!(
        !downstream.is_empty(),
        "must list at least one downstream bead"
    );
}

#[test]
fn doc_lists_all_matrix_combinations() {
    let doc = load_doc();
    let art = load_artifact();
    let combos = art["compatibility_matrix"]["combinations"]
        .as_array()
        .unwrap();
    for combo in combos {
        let cid = combo["combo_id"].as_str().unwrap();
        assert!(
            doc.contains(cid),
            "doc must list combination {cid}"
        );
    }
}

#[test]
fn doc_lists_all_drill_ids() {
    let doc = load_doc();
    let art = load_artifact();
    let drills = art["incident_drills"].as_array().unwrap();
    for drill in drills {
        let did = drill["drill_id"].as_str().unwrap();
        assert!(doc.contains(did), "doc must list drill {did}");
    }
}
