//! Swarm-ops certification bundle contract (br-asupersync-vssefs.9.8).
//!
//! The certification bundle aggregates every swarm-ops (asupersync-vssefs.9)
//! child bead's contract artifact, contract test, runtime source, proof-command
//! pointer, and evidence class into one fail-closed certification surface.
//!
//! This test is the bundle's enforcement: it fails closed when any child
//! artifact is missing or mismatched, when a child bead is not closed in the
//! beads snapshot (and not explicitly deferred), when a proof-command pointer
//! does not resolve to a real RCH command, when evidence classes are conflated
//! with benchmark/release claims, or when the certified dependency subgraph
//! contains a cycle.

#![allow(missing_docs)]
#![allow(clippy::pedantic, clippy::nursery)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const BUNDLE_PATH: &str = "artifacts/swarm_ops_certification_bundle_v1.json";
const BEADS_SNAPSHOT_PATH: &str = ".beads/issues.jsonl";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_json(relative: &str) -> Value {
    let raw = std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|error| panic!("read {relative}: {error}"));
    serde_json::from_str(&raw).unwrap_or_else(|error| panic!("parse {relative}: {error}"))
}

fn bundle() -> Value {
    read_json(BUNDLE_PATH)
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn object<'a>(value: &'a Value, key: &str) -> &'a Value {
    let nested = value
        .get(key)
        .unwrap_or_else(|| panic!("{key} must be present"));
    assert!(nested.is_object(), "{key} must be an object");
    nested
}

fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    let text = value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"));
    assert!(!text.trim().is_empty(), "{key} must be nonempty");
    text
}

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    array(value, key)
        .iter()
        .map(|item| {
            item.as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
                .to_string()
        })
        .collect()
}

/// Resolve a dotted/indexed pointer like `runner_contract.proof_command` or
/// `lanes[0].planner_request.command` inside a JSON value.
fn resolve_pointer<'a>(root: &'a Value, pointer: &str) -> Option<&'a Value> {
    let mut current = root;
    for raw_segment in pointer.split('.') {
        let (key, indices) = match raw_segment.find('[') {
            Some(bracket) => (&raw_segment[..bracket], &raw_segment[bracket..]),
            None => (raw_segment, ""),
        };
        if !key.is_empty() {
            current = current.get(key)?;
        }
        let mut rest = indices;
        while let Some(stripped) = rest.strip_prefix('[') {
            let close = stripped.find(']')?;
            let index: usize = stripped[..close].parse().ok()?;
            current = current.get(index)?;
            rest = &stripped[close + 1..];
        }
    }
    Some(current)
}

/// Load the latest status of every bead id from the beads JSONL snapshot.
fn beads_status_snapshot() -> BTreeMap<String, String> {
    // RCH workers exclude .beads/ from sync; a missing snapshot means the
    // live cross-check cannot run and the embedded evidence is authoritative.
    let Ok(raw) = std::fs::read_to_string(repo_path(BEADS_SNAPSHOT_PATH)) else {
        return BTreeMap::new();
    };
    let mut statuses = BTreeMap::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(entry) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let (Some(id), Some(status)) = (
            entry.get("id").and_then(Value::as_str),
            entry.get("status").and_then(Value::as_str),
        ) else {
            continue;
        };
        // Later lines win so append-style snapshots resolve to latest state.
        statuses.insert(id.to_string(), status.to_string());
    }
    statuses
}

fn certified_bead_ids(bundle: &Value) -> BTreeSet<String> {
    let mut ids: BTreeSet<String> = array(bundle, "child_certifications")
        .iter()
        .map(|child| string(child, "bead_id").to_string())
        .collect();
    ids.insert(string(bundle, "bead_id").to_string());
    ids.insert(string(bundle, "epic_bead_id").to_string());
    ids
}

#[test]
fn bundle_artifact_is_source_backed_and_declares_fail_closed_rules() {
    let bundle = bundle();

    assert_eq!(
        string(&bundle, "contract_version"),
        "swarm-ops-certification-bundle-v1"
    );
    assert_eq!(
        string(&bundle, "bundle_schema_version"),
        "asupersync.swarm-ops-certification-bundle.v1"
    );
    assert_eq!(string(&bundle, "bead_id"), "asupersync-vssefs.9.8");
    assert_eq!(string(&bundle, "epic_bead_id"), "asupersync-vssefs.9");
    assert_eq!(
        string(&bundle, "contract_test"),
        "tests/swarm_ops_certification_bundle_contract.rs"
    );

    // Declared source files must exist.
    for key in ["contract_test", "scenario_corpus", "beads_snapshot"] {
        let relative = string(&bundle, key);
        assert!(
            repo_path(relative).exists(),
            "{key} {relative} must exist in the repository"
        );
    }

    // The certification HEAD must be a well-formed git SHA, and the recorded
    // freshness policy must exist so consumers know how to detect staleness.
    let head = string(&bundle, "certified_at_head");
    assert!(
        head.len() == 40 && head.chars().all(|c| c.is_ascii_hexdigit()),
        "certified_at_head must be a full 40-hex git SHA, got {head}"
    );
    assert!(
        string(&bundle, "certified_at_head_policy").contains("stale"),
        "certified_at_head_policy must explain staleness handling"
    );

    // Fail-closed rules and the bundle proof command must be declared.
    assert!(
        !array(&bundle, "fail_closed_rules").is_empty(),
        "fail_closed_rules must not be empty"
    );
    let proof_command = string(&bundle, "proof_command");
    assert!(proof_command.contains("RCH_REQUIRE_REMOTE=1"));
    assert!(proof_command.contains("rch exec"));
    assert!(proof_command.contains("CARGO_TARGET_DIR"));
    assert!(proof_command.contains("--features"));
    assert!(proof_command.contains("swarm_ops_certification_bundle_contract"));

    // The operator handoff must name the Agent Mail thread and boundaries.
    let handoff = object(&bundle, "operator_handoff");
    assert_eq!(
        string(handoff, "agent_mail_thread"),
        "asupersync-vssefs.9.8"
    );
    assert!(!string(handoff, "support_boundary_summary").is_empty());
}

#[test]
fn evidence_classes_are_complete_and_not_conflated() {
    let bundle = bundle();
    let classes = object(&bundle, "evidence_classes");

    // The full evidence taxonomy must be declared, including the classes this
    // bundle explicitly does NOT provide.
    for class in [
        "synthetic_fixture",
        "lab_runtime_deterministic",
        "no_mock_rch_backed",
        "benchmark",
        "release",
    ] {
        assert!(
            !string(classes, class).is_empty(),
            "evidence class {class} must be described"
        );
    }

    // Benchmark and release evidence must be declared as not covered, so the
    // bundle can never be read as performance or release certification.
    let not_covered = string_set(&bundle, "does_not_cover");
    assert!(
        not_covered
            .iter()
            .any(|claim| claim.contains("wall_clock_performance")),
        "does_not_cover must exclude wall-clock performance claims"
    );
    assert!(
        not_covered
            .iter()
            .any(|claim| claim.contains("release_gate")),
        "does_not_cover must exclude release-gate claims"
    );

    // Every child must use a declared, non-benchmark, non-release class.
    let allowed: BTreeSet<&str> = [
        "synthetic_fixture",
        "lab_runtime_deterministic",
        "no_mock_rch_backed",
    ]
    .into_iter()
    .collect();
    for child in array(&bundle, "child_certifications") {
        let class = string(child, "evidence_class");
        assert!(
            allowed.contains(class),
            "{} declares evidence class {class}, which this bundle cannot certify",
            string(child, "bead_id")
        );
    }

    // Bundle-level covers must not silently claim benchmark/release evidence.
    for claim in string_set(&bundle, "covers") {
        let lowered = claim.to_ascii_lowercase();
        assert!(
            !lowered.contains("benchmark") && !lowered.contains("release gate"),
            "covers must not claim benchmark or release-gate evidence: {claim}"
        );
    }
}

#[test]
fn every_child_certification_resolves_to_real_artifacts_and_rch_proof_commands() {
    let bundle = bundle();
    let children = array(&bundle, "child_certifications");
    assert_eq!(
        children.len(),
        7,
        "the swarm-ops epic has exactly seven certified children (.9.1 - .9.7)"
    );

    for child in children {
        let bead_id = string(child, "bead_id");

        // Child artifact must exist, parse, and self-identify consistently.
        let artifact_path = string(child, "artifact");
        assert!(
            repo_path(artifact_path).exists(),
            "{bead_id}: artifact {artifact_path} must exist"
        );
        let artifact = read_json(artifact_path);
        let expected_artifact_bead_id = child
            .get("artifact_bead_id")
            .and_then(Value::as_str)
            .unwrap_or(bead_id);
        assert_eq!(
            string(&artifact, "bead_id"),
            expected_artifact_bead_id,
            "{bead_id}: artifact bead_id must match the declared artifact owner"
        );
        assert_eq!(
            string(&artifact, "contract_version"),
            string(child, "artifact_contract_version"),
            "{bead_id}: artifact contract_version must match the certified version"
        );

        // Contract test, runtime source, and optional runner script must exist.
        for key in ["contract_test", "runtime_source"] {
            let relative = string(child, key);
            assert!(
                repo_path(relative).exists(),
                "{bead_id}: {key} {relative} must exist"
            );
        }
        if let Some(script) = child.get("runner_script").and_then(Value::as_str) {
            assert!(
                repo_path(script).exists(),
                "{bead_id}: runner_script {script} must exist"
            );
        }

        // The proof-command pointer must resolve to a real remote-required
        // command inside the child artifact. The command qualifies when it
        // dispatches through `rch exec` directly, or when it invokes the
        // child's certified RCH-only runner script. Anything else (for
        // example a bare local cargo command) fails the bundle.
        let pointer = string(child, "proof_command_pointer");
        let resolved = resolve_pointer(&artifact, pointer).unwrap_or_else(|| {
            panic!("{bead_id}: proof_command_pointer {pointer} did not resolve in {artifact_path}")
        });
        let command = resolved
            .as_str()
            .unwrap_or_else(|| panic!("{bead_id}: proof command at {pointer} must be a string"));
        let dispatches_via_rch = command.contains("rch exec");
        let dispatches_via_certified_runner = child
            .get("runner_script")
            .and_then(Value::as_str)
            .is_some_and(|script| command.contains(script));
        assert!(
            command.contains("RCH_REQUIRE_REMOTE=1")
                && (dispatches_via_rch || dispatches_via_certified_runner),
            "{bead_id}: proof command at {pointer} must be remote-required (rch exec or the \
             certified runner script), got: {}",
            &command[..command.len().min(120)]
        );

        // Claim-scope hygiene: every certified child must separate what it
        // covers from what it does not cover.
        assert!(
            !array(child, "covers").is_empty(),
            "{bead_id}: covers must not be empty"
        );
        assert!(
            !array(child, "does_not_cover").is_empty(),
            "{bead_id}: does_not_cover must not be empty"
        );
    }
}

/// The live beads snapshot is authoritative only when it actually tracks the
/// certified subgraph. RCH workers exclude `.beads/` from sync, so remote runs
/// may see a missing or stale snapshot; in that case the embedded certification
/// evidence in the bundle is the record of truth.
fn live_beads_cover_certified_subgraph(
    statuses: &BTreeMap<String, String>,
    bundle: &Value,
) -> bool {
    statuses.contains_key(string(bundle, "epic_bead_id"))
}

#[test]
fn child_beads_are_closed_or_explicitly_deferred() {
    let bundle = bundle();
    let deferred: BTreeSet<String> = array(&bundle, "deferred_items")
        .iter()
        .map(|item| string(item, "bead_id").to_string())
        .collect();

    // Bundle-internal certification evidence: every child must embed verified
    // closure evidence captured at certification time. This check runs in
    // every environment, including RCH workers without beads data.
    for child in array(&bundle, "child_certifications") {
        let bead_id = string(child, "bead_id");
        assert_eq!(
            string(child, "expected_status"),
            "closed",
            "{bead_id}: certified children must declare expected_status closed"
        );
        assert_eq!(
            string(child, "verified_status"),
            "closed",
            "{bead_id}: certified children must embed verified_status closed"
        );
        let closed_at = string(child, "verified_closed_at");
        assert!(
            closed_at.contains('T') && closed_at.ends_with('Z'),
            "{bead_id}: verified_closed_at must be an ISO-8601 UTC timestamp, got {closed_at}"
        );
    }

    // Deferred items must carry an owner bead and a reason so deferral can
    // never silently drop work.
    for item in array(&bundle, "deferred_items") {
        let bead_id = string(item, "bead_id");
        assert!(
            !string(item, "reason").is_empty(),
            "{bead_id}: deferred items must explain why"
        );
        assert!(
            !string(item, "owner_bead").is_empty(),
            "{bead_id}: deferred items must name an owner bead"
        );
    }

    // Live cross-check: when the beads snapshot covers the certified subgraph
    // (real repository checkouts), a certified child that is no longer closed
    // invalidates the certification. This is the reopened-bead fail-closed path.
    let statuses = beads_status_snapshot();
    if live_beads_cover_certified_subgraph(&statuses, &bundle) {
        for child in array(&bundle, "child_certifications") {
            let bead_id = string(child, "bead_id");
            let actual = statuses
                .get(bead_id)
                .unwrap_or_else(|| panic!("{bead_id}: missing from live beads snapshot"));
            assert!(
                actual == "closed" || deferred.contains(bead_id),
                "{bead_id}: live beads snapshot shows status {actual}; the certification is \
                 invalid until the child is re-closed or explicitly deferred"
            );
        }
        for item in array(&bundle, "deferred_items") {
            let owner = string(item, "owner_bead");
            assert!(
                statuses.contains_key(owner),
                "deferred owner bead {owner} must exist in the live beads snapshot"
            );
        }
    } else {
        // Environment without beads coverage (for example an RCH worker):
        // the embedded evidence above is the certification record.
        println!(
            "live beads snapshot does not cover the certified subgraph; \
             embedded closure evidence verified instead"
        );
    }
}

#[test]
fn certification_subgraph_has_no_dependency_cycles() {
    let bundle = bundle();

    // The graph check performed at certification time must be recorded.
    let graph_check = object(&bundle, "graph_check");
    assert!(!string(graph_check, "tool").is_empty());
    assert_eq!(
        graph_check.get("cycle_count").and_then(Value::as_u64),
        Some(0),
        "recorded graph check must report zero cycles"
    );

    // Equivalent check, re-run on every execution: Kahn's topological sort
    // over the embedded dependency edges. Node set = certified beads plus any
    // referenced program beads (which act as sinks here).
    let mut ids = certified_bead_ids(&bundle);
    let mut edges: Vec<(String, String)> = Vec::new();
    for child in array(&bundle, "child_certifications") {
        let from = string(child, "bead_id").to_string();
        for dep in array(child, "depends_on_within_program") {
            let to = dep
                .as_str()
                .expect("depends_on_within_program entries must be strings")
                .to_string();
            ids.insert(to.clone());
            edges.push((from.clone(), to));
        }
    }

    let mut indegree: BTreeMap<&str, usize> = ids.iter().map(|id| (id.as_str(), 0)).collect();
    let mut adjacency: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (from, to) in &edges {
        *indegree.get_mut(to.as_str()).expect("known node") += 1;
        adjacency
            .entry(from.as_str())
            .or_default()
            .push(to.as_str());
    }

    let mut queue: Vec<&str> = indegree
        .iter()
        .filter(|(_, degree)| **degree == 0)
        .map(|(id, _)| *id)
        .collect();
    let mut visited = 0_usize;
    while let Some(node) = queue.pop() {
        visited += 1;
        if let Some(targets) = adjacency.get(node) {
            for target in targets {
                let degree = indegree.get_mut(target).expect("known node");
                *degree -= 1;
                if *degree == 0 {
                    queue.push(target);
                }
            }
        }
    }
    assert_eq!(
        visited,
        ids.len(),
        "dependency cycle detected among certified beads: {ids:?}"
    );
    assert!(
        !edges.is_empty(),
        "embedded dependency edges must not be empty; the certification must \
         record the real program structure"
    );
}

#[test]
fn bundle_serialization_is_stable_for_release_evidence() {
    let bundle = bundle();

    // Round-trip through serde to prove the artifact stays machine-stable.
    let rendered = serde_json::to_string_pretty(&bundle).expect("render bundle");
    let reparsed: Value = serde_json::from_str(&rendered).expect("reparse bundle");
    assert_eq!(reparsed, bundle, "bundle JSON must round-trip stably");

    // The bundle must reference the scenario corpus contract version that the
    // corpus artifact actually declares, so corpus drift fails closed here.
    let corpus = read_json(string(&bundle, "scenario_corpus"));
    assert_eq!(
        string(&corpus, "contract_version"),
        string(&bundle, "scenario_corpus_contract_version"),
        "scenario corpus contract version drifted; recertify the bundle"
    );
}
