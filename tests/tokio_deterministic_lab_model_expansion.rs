//! Contract tests for deterministic lab-model expansion baseline (2oh2u.10.1).
//!
//! Validates model-domain coverage, scenario taxonomy, schedule-control
//! requirements, and replay artifact contract tokens needed to unblock T8.2.

#![allow(missing_docs)]

use std::collections::BTreeSet;
use std::path::Path;

fn load_doc() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("docs/tokio_deterministic_lab_model_expansion.md");
    std::fs::read_to_string(path).expect("deterministic lab model expansion document must exist")
}

fn extract_gap_ids(doc: &str) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    for line in doc.lines() {
        let trimmed = line.trim().trim_start_matches('|').trim();
        if let Some(id) = trimmed.split('|').next() {
            let id = id.trim().trim_matches('`');
            if id.starts_with("LM-G") && id.len() >= 5 {
                ids.insert(id.to_string());
            }
        }
    }
    ids
}

#[test]
fn doc_exists_and_is_substantial() {
    let doc = load_doc();
    assert!(
        doc.len() > 2500,
        "document should be substantial, got {} bytes",
        doc.len()
    );
}

#[test]
fn doc_references_correct_bead_and_track() {
    let doc = load_doc();
    assert!(
        doc.contains("asupersync-2oh2u.10.1"),
        "document must reference bead 2oh2u.10.1"
    );
    assert!(doc.contains("[T8.1]"), "document must reference T8.1");
}

#[test]
fn doc_references_required_input_baselines() {
    let doc = load_doc();
    for token in [
        "asupersync-2oh2u.2.1",
        "asupersync-2oh2u.3.1",
        "asupersync-2oh2u.5.1",
        "asupersync-2oh2u.6.1",
        "asupersync-2oh2u.7.2",
    ] {
        assert!(
            doc.contains(token),
            "document must reference input baseline bead: {token}"
        );
    }
}

#[test]
fn doc_covers_all_nine_model_domains() {
    let doc = load_doc();
    for domain in [
        "DM01", "DM02", "DM03", "DM04", "DM05", "DM06", "DM07", "DM08", "DM09",
    ] {
        assert!(doc.contains(domain), "missing model domain token: {domain}");
    }
}

#[test]
fn doc_covers_required_tokio_surface_anchors() {
    let doc = load_doc();
    for token in [
        "tokio::io",
        "tokio::fs",
        "tokio::process",
        "tokio::signal",
        "axum",
        "tower-http",
        "tonic",
    ] {
        assert!(
            doc.contains(token),
            "document must include Tokio surface anchor: {token}"
        );
    }
}

#[test]
fn doc_references_key_lab_runtime_surfaces() {
    let doc = load_doc();
    for token in [
        "src/lab/runtime.rs",
        "src/lab/config.rs",
        "src/lab/replay.rs",
        "src/lab/explorer.rs",
        "src/lab/chaos.rs",
        "src/lab/scenario_runner.rs",
        "src/lab/network/harness.rs",
        "src/lab/oracle/cancellation_protocol.rs",
        "src/lab/oracle/loser_drain.rs",
        "src/lab/oracle/obligation_leak.rs",
        "src/lab/oracle/task_leak.rs",
        "src/lab/oracle/determinism.rs",
    ] {
        assert!(
            doc.contains(token),
            "document missing required lab/runtime surface token: {token}"
        );
    }
}

#[test]
fn doc_defines_all_six_scenario_families() {
    let doc = load_doc();
    for scenario in ["LM-S1", "LM-S2", "LM-S3", "LM-S4", "LM-S5", "LM-S6"] {
        assert!(
            doc.contains(scenario),
            "missing scenario family token: {scenario}"
        );
    }
}

#[test]
fn doc_includes_schedule_control_requirements() {
    let doc = load_doc();
    for token in ["SC-01", "SC-02", "SC-03", "SC-04", "SC-05"] {
        assert!(
            doc.contains(token),
            "missing schedule-control requirement token: {token}"
        );
    }
}

#[test]
fn doc_includes_replay_artifact_contract() {
    let doc = load_doc();
    for artifact in [
        "event_log.txt",
        "failed_assertions.json",
        "repro_manifest.json",
    ] {
        assert!(
            doc.contains(artifact),
            "document must include replay artifact token: {artifact}"
        );
    }
}

#[test]
fn doc_has_sufficient_gap_register_coverage() {
    let doc = load_doc();
    let ids = extract_gap_ids(&doc);
    assert!(
        ids.len() >= 12,
        "gap register must include >=12 LM-G entries, found {}",
        ids.len()
    );

    for token in ["LM-G1", "LM-G10", "LM-G12"] {
        assert!(ids.contains(token), "gap register missing token: {token}");
    }
}

#[test]
fn doc_unblocks_t8_2_with_explicit_mapping() {
    let doc = load_doc();
    assert!(
        doc.contains("2oh2u.10.2"),
        "document must explicitly map to downstream bead 2oh2u.10.2"
    );
    for token in [
        "Domain contract generation",
        "Scenario catalog formalization",
        "Replay schema binding",
        "Oracle selection map",
    ] {
        assert!(
            doc.contains(token),
            "execution mapping missing token: {token}"
        );
    }
}
