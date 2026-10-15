//! Contract tests for the shared-main swarm heatmap helper.

#![allow(missing_docs)]

use serde_json::Value;
use std::path::PathBuf;
use std::process::{Command, Output};

const SCRIPT_PATH: &str = "scripts/swarm_heatmap.py";
const FIXTURE_ROOT: &str = "tests/fixtures/swarm_heatmap";
const GENERATED_AT: &str = "2026-05-10T08:50:00Z";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn run_heatmap(fixture: &str) -> Output {
    Command::new("python3")
        .arg(repo_root().join(SCRIPT_PATH))
        .arg("--fixture")
        .arg(repo_root().join(FIXTURE_ROOT).join(fixture))
        .arg("--repo-path")
        .arg(repo_root())
        .arg("--agent")
        .arg("CopperSpring")
        .arg("--generated-at")
        .arg(GENERATED_AT)
        .arg("--output")
        .arg("json")
        .current_dir(repo_root())
        .output()
        .expect("run swarm heatmap helper")
}

fn heatmap_json(fixture: &str) -> Value {
    let output = run_heatmap(fixture);
    assert!(
        output.status.success(),
        "heatmap helper failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("heatmap output must be JSON")
}

fn graph_has_node(graph: &Value, kind: &str, id: &str) -> bool {
    graph["nodes"]
        .as_array()
        .expect("graph nodes")
        .iter()
        .any(|node| node["kind"].as_str() == Some(kind) && node["id"].as_str() == Some(id))
}

fn graph_has_edge(graph: &Value, kind: &str, source: &str, target: &str, path: &str) -> bool {
    graph["edges"]
        .as_array()
        .expect("graph edges")
        .iter()
        .any(|edge| {
            edge["kind"].as_str() == Some(kind)
                && edge["source"].as_str() == Some(source)
                && edge["target"].as_str() == Some(target)
                && edge["path"].as_str() == Some(path)
        })
}

#[test]
fn script_exists_and_help_is_non_mutating() {
    assert!(
        repo_root().join(SCRIPT_PATH).exists(),
        "heatmap helper must exist at {SCRIPT_PATH}"
    );
    let output = Command::new("python3")
        .arg(repo_root().join(SCRIPT_PATH))
        .arg("--help")
        .current_dir(repo_root())
        .output()
        .expect("run helper --help");
    assert!(output.status.success(), "--help should succeed");
}

#[test]
fn live_probe_preserves_porcelain_status_columns_for_unstaged_paths() {
    let script = r#"
import importlib.util
import json
import pathlib
import sys

script_path = pathlib.Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("swarm_heatmap", script_path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class Completed:
    stdout = " M scripts/closeout_verifier.py \n"

module.subprocess.run = lambda *args, **kwargs: Completed()
status, raw = module.run_text(pathlib.Path("."), ["git", "status", "--porcelain=v1"], 1.0)
entries = module.parse_status_lines(raw if status == "ok" else "")
print(json.dumps({"status": status, "raw": raw, "entries": entries}))
"#;
    let output = Command::new("python3")
        .arg("-c")
        .arg(script)
        .arg(repo_root().join(SCRIPT_PATH))
        .current_dir(repo_root())
        .output()
        .expect("run swarm heatmap live probe parser smoke");
    assert!(
        output.status.success(),
        "parser smoke failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let parsed: Value = serde_json::from_slice(&output.stdout).expect("parser smoke JSON");
    assert_eq!(parsed["status"].as_str(), Some("ok"));
    assert_eq!(
        parsed["raw"].as_str(),
        Some(" M scripts/closeout_verifier.py ")
    );
    assert_eq!(parsed["entries"][0]["status"].as_str(), Some(" M"));
    assert_eq!(
        parsed["entries"][0]["path"].as_str(),
        Some("scripts/closeout_verifier.py ")
    );
}

#[test]
fn live_probe_expands_porcelain_rename_source_and_target_paths() {
    let script = r#"
import importlib.util
import json
import pathlib
import sys

script_path = pathlib.Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("swarm_heatmap", script_path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

entries = module.parse_status_lines(
    "R  docs/old-secret.rs -> src/security/secret.rs\n M docs/name -> literal.rs \n"
)
print(json.dumps({"entries": entries}))
"#;
    let output = Command::new("python3")
        .arg("-c")
        .arg(script)
        .arg(repo_root().join(SCRIPT_PATH))
        .current_dir(repo_root())
        .output()
        .expect("run swarm heatmap rename parser smoke");
    assert!(
        output.status.success(),
        "rename parser smoke failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let parsed: Value = serde_json::from_slice(&output.stdout).expect("parser smoke JSON");
    let entries = parsed["entries"].as_array().expect("entries array");
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0]["status"].as_str(), Some("R "));
    assert_eq!(entries[0]["path"].as_str(), Some("docs/old-secret.rs"));
    assert_eq!(entries[1]["path"].as_str(), Some("src/security/secret.rs"));
    assert_eq!(entries[2]["status"].as_str(), Some(" M"));
    assert_eq!(
        entries[2]["path"].as_str(),
        Some("docs/name -> literal.rs ")
    );
}

#[test]
fn overlapping_reservations_are_visible_and_stable() {
    let heatmap = heatmap_json("overlapping_reservations.json");
    let overlap = &heatmap["reservations"]["overlaps"][0];

    assert_eq!(heatmap["schema_version"].as_str(), Some("swarm-heatmap-v1"));
    assert_eq!(heatmap["current_date"].as_str(), Some("2026-05-10"));
    assert_eq!(heatmap["summary"]["active_reservations"].as_u64(), Some(2));
    assert_eq!(overlap["left_holder"].as_str(), Some("BlueMesa"));
    assert_eq!(overlap["right_holder"].as_str(), Some("GentleCitadel"));
    assert_eq!(overlap["severity"].as_str(), Some("warning"));
    assert_eq!(
        heatmap["suggested_stay_off_surfaces"][0]["path"].as_str(),
        Some("src/http/**")
    );
}

#[test]
fn rename_target_reservation_owns_target_and_blocks_surface() {
    let heatmap = heatmap_json("rename_target_reservation.json");
    let dirty_paths = heatmap["dirty_paths"].as_array().expect("dirty paths");
    let target = dirty_paths
        .iter()
        .find(|row| row["path"].as_str() == Some("src/security/secret.rs"))
        .expect("rename target dirty row");
    let source = dirty_paths
        .iter()
        .find(|row| row["path"].as_str() == Some("docs/old-secret.rs"))
        .expect("rename source dirty row");
    let open_surfaces = heatmap["suggested_open_surfaces"]
        .as_array()
        .expect("open surfaces");

    assert_eq!(source["classification"].as_str(), Some("unattributed"));
    assert_eq!(target["classification"].as_str(), Some("peer-owned"));
    assert_eq!(target["owner"].as_str(), Some("BoldPlateau"));
    assert_eq!(target["owner_source"].as_str(), Some("reservation"));
    assert_eq!(target["stay_off"].as_bool(), Some(true));
    assert!(
        !open_surfaces
            .iter()
            .any(|path| path.as_str() == Some("src/security/secret.rs")),
        "rename target candidate surface must not remain open under a peer reservation"
    );
}

#[test]
fn directory_reservation_owns_child_dirty_path_and_blocks_child_surface() {
    let heatmap = heatmap_json("directory_reservation.json");
    let dirty = &heatmap["dirty_paths"][0];
    let stay_off = heatmap["suggested_stay_off_surfaces"]
        .as_array()
        .expect("stay-off surfaces");
    let open_surfaces = heatmap["suggested_open_surfaces"]
        .as_array()
        .expect("open surfaces");

    assert_eq!(dirty["path"].as_str(), Some("src/security/secret.rs"));
    assert_eq!(dirty["classification"].as_str(), Some("peer-owned"));
    assert_eq!(dirty["owner"].as_str(), Some("BoldPlateau"));
    assert_eq!(dirty["owner_source"].as_str(), Some("reservation"));
    assert_eq!(dirty["stay_off"].as_bool(), Some(true));
    assert!(stay_off.iter().any(|row| {
        row["path"].as_str() == Some("src/security")
            && row["holder"].as_str() == Some("BoldPlateau")
    }));
    assert!(
        !open_surfaces
            .iter()
            .any(|path| path.as_str() == Some("src/security/secret.rs")),
        "child candidate surface must not remain open under a peer directory reservation"
    );
    assert!(
        open_surfaces
            .iter()
            .any(|path| path.as_str() == Some("src/http")),
        "unrelated candidate surfaces should stay available"
    );
}

#[test]
fn expired_reservations_do_not_create_stay_off_surfaces() {
    let heatmap = heatmap_json("expired_reservations.json");

    assert_eq!(heatmap["summary"]["active_reservations"].as_u64(), Some(0));
    assert_eq!(
        heatmap["summary"]["expired_or_released_reservations"].as_u64(),
        Some(2)
    );
    assert_eq!(
        heatmap["suggested_stay_off_surfaces"]
            .as_array()
            .expect("stay-off surfaces")
            .len(),
        0
    );
}

#[test]
fn peer_dirty_file_reports_owner_target_dir_and_stay_off_path() {
    let heatmap = heatmap_json("peer_dirty_file.json");
    let dirty = &heatmap["dirty_paths"][0];

    assert_eq!(dirty["path"].as_str(), Some("scripts/closeout_verifier.py"));
    assert_eq!(dirty["classification"].as_str(), Some("peer-owned"));
    assert_eq!(dirty["owner"].as_str(), Some("GentleCitadel"));
    assert_eq!(dirty["stay_off"].as_bool(), Some(true));
    assert_eq!(
        heatmap["target_dirs"][0].as_str(),
        Some("/tmp/rch_target_gentlecitadel_closeout_verifier")
    );
    assert_eq!(
        heatmap["suggested_stay_off_surfaces"][0]["path"].as_str(),
        Some("scripts/closeout_verifier.py")
    );
}

#[test]
fn no_active_agents_stays_empty_without_false_conflicts() {
    let heatmap = heatmap_json("no_active_agents.json");

    assert_eq!(heatmap["summary"]["active_agents"].as_u64(), Some(0));
    assert_eq!(
        heatmap["reservations"]["active"]
            .as_array()
            .expect("active reservations")
            .len(),
        0
    );
    assert_eq!(
        heatmap["dirty_paths"]
            .as_array()
            .expect("dirty paths")
            .len(),
        0
    );
    assert_eq!(
        heatmap["suggested_open_surfaces"][0].as_str(),
        Some("fuzz/fuzz_targets")
    );
}

#[test]
fn semantic_conflict_graph_links_reservations_dirty_paths_and_proof_lanes() {
    let heatmap = heatmap_json("semantic_conflict_graph.json");
    let graph = &heatmap["semantic_conflict_graph"];
    let contact_targets = graph["summary"]["owner_contact_targets"]
        .as_array()
        .expect("contact targets");

    assert_eq!(
        graph["schema_version"].as_str(),
        Some("semantic-conflict-graph-v1")
    );
    assert_eq!(
        graph["summary"]["dominant_conflict_class"].as_str(),
        Some("blocks_proof")
    );
    assert_eq!(
        graph["summary"]["suggested_narrow_proof"].as_str(),
        Some("sync-proof")
    );
    assert!(contact_targets.iter().any(|name| name == "BlueMesa"));
    assert!(contact_targets.iter().any(|name| name == "OldHarbor"));

    assert!(graph_has_node(graph, "reservation", "reservation:401"));
    assert!(graph_has_node(graph, "dirty_path", "dirty:src/http/h1.rs"));
    assert!(graph_has_node(
        graph,
        "validation_blocker",
        "validation_blocker:src/http/h1.rs"
    ));
    assert!(graph_has_node(graph, "bead", "bead:asupersync-http-proof"));
    assert!(graph_has_node(
        graph,
        "proof_lane",
        "proof_lane:http-h1-proof"
    ));
    assert!(graph_has_node(graph, "proof_lane", "proof_lane:sync-proof"));

    assert!(graph_has_edge(
        graph,
        "blocks_proof",
        "reservation:401",
        "proof_lane:http-h1-proof",
        "src/http/**"
    ));
    assert!(graph_has_edge(
        graph,
        "blocks_proof",
        "dirty:src/http/h1.rs",
        "proof_lane:http-h1-proof",
        "src/http/h1.rs"
    ));
    assert!(graph_has_edge(
        graph,
        "blocks_proof",
        "validation_blocker:src/http/h1.rs",
        "proof_lane:http-h1-proof",
        "src/http/h1.rs"
    ));
    assert!(graph_has_edge(
        graph,
        "clean_surface",
        "proof_lane:sync-proof",
        "surface:src/sync",
        "src/sync"
    ));
    assert!(graph_has_edge(
        graph,
        "stale_owner",
        "reservation:402",
        "agent:OldHarbor",
        "src/runtime/**"
    ));
    assert!(graph_has_edge(
        graph,
        "unknown_owner",
        "dirty:tests/unowned_probe.rs",
        "agent:unknown",
        "tests/unowned_probe.rs"
    ));
}

#[test]
fn semantic_conflict_graph_keeps_clean_surfaces_open_and_blocks_owned_production_paths() {
    let heatmap = heatmap_json("semantic_conflict_graph.json");
    let graph = &heatmap["semantic_conflict_graph"];
    let open_surfaces = heatmap["suggested_open_surfaces"]
        .as_array()
        .expect("open surfaces");
    let clean_surfaces = graph["summary"]["clean_surfaces"]
        .as_array()
        .expect("clean surfaces");

    assert!(open_surfaces.iter().any(|path| path == "src/sync"));
    assert!(clean_surfaces.iter().any(|path| path == "src/sync"));
    assert!(
        !open_surfaces
            .iter()
            .any(|path| path.as_str() == Some("src/http/h1.rs")),
        "peer-reserved production paths must not remain open"
    );
    assert_eq!(
        graph["summary"]["conflict_count"].as_u64(),
        Some(6),
        "fixture should expose reservation, dirty-path, stale-owner, unknown-owner, and proof blockers"
    );
}

#[test]
fn helper_declares_no_mutating_side_effects() {
    let heatmap = heatmap_json("peer_dirty_file.json");

    for key in [
        "mutating_commands_executed",
        "beads_mutated",
        "cargo_executed",
        "agent_mail_mutated",
        "branch_or_worktree_operations",
    ] {
        assert_eq!(
            heatmap["safety"][key].as_bool(),
            Some(false),
            "{key} must stay false"
        );
    }
    assert_eq!(
        heatmap["safety"]["forbidden_command_tokens"]
            .as_array()
            .expect("forbidden tokens")
            .len(),
        0
    );
}
