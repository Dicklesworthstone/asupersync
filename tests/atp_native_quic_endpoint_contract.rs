//! Contract tests for the ATP native QUIC endpoint gap matrix.
//!
//! These tests keep `artifacts/atp_native_quic_endpoint_contract_v1.json`
//! synchronized with the live codebase and the no-external-QUIC policy.

#![allow(clippy::pedantic, clippy::nursery)]

use asupersync::net::atp::quic::{AtpTransportMetricsCollector, PathIssue, PathRecommendation};
use asupersync::net::quic_native::QuicTransportMachine;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const CONTRACT_PATH: &str = "artifacts/atp_native_quic_endpoint_contract_v1.json";
const FORENSIC_SCHEMA_PATH: &str = "artifacts/quic_h3_forensic_log_schema_v1.json";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

fn read_repo_file(relative: &str) -> String {
    let path = repo_root().join(relative);
    fs::read_to_string(&path).unwrap_or_else(|err| panic!("failed to read {path:?}: {err}"))
}

fn load_contract() -> Value {
    load_json(CONTRACT_PATH, "ATP native QUIC endpoint contract")
}

fn load_json(relative: &str, _label: &str) -> Value {
    let text = read_repo_file(relative);
    serde_json::from_str(&text).expect("contract artifact must be valid JSON")
}

fn nonempty_str<'a>(value: &'a Value, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| panic!("{key} must be a non-empty string in {value:?}"))
}

fn nonempty_array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    let array = value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array in {value:?}"));
    assert!(!array.is_empty(), "{key} must not be empty in {value:?}");
    array
}

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    nonempty_array(value, key)
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings: {entry:?}"))
                .to_owned()
        })
        .collect()
}

#[test]
fn contract_is_complete_and_self_documenting() {
    let contract = load_contract();
    assert_eq!(
        nonempty_str(&contract, "schema_id"),
        "atp-native-quic-endpoint-contract.v1"
    );
    assert_eq!(contract["contract_version"], 1);
    assert_eq!(nonempty_str(&contract, "bead_id"), "asupersync-l6f1ja");
    nonempty_str(&contract, "north_star");
    nonempty_str(&contract, "scope_statement");
    nonempty_array(&contract, "non_negotiables");
    nonempty_array(&contract, "rfc_scope");
    nonempty_array(&contract, "source_inventory");
    nonempty_array(&contract, "v0_exclusions");
    nonempty_array(&contract, "future_self_notes");

    let required_feature_ids = string_set(&contract, "required_feature_ids");
    let expected_feature_ids = BTreeSet::from([
        "quic_varint_and_header_codecs".to_string(),
        "connection_id_and_packet_number_spaces".to_string(),
        "packet_number_encoding_and_reconstruction".to_string(),
        "transport_parameter_codec_and_validation".to_string(),
        "quic_frame_codec_and_packet_assembly".to_string(),
        "version_negotiation_retry_and_initial_handshake".to_string(),
        "packet_protection_tls_provider_boundary".to_string(),
        "crypto_levels_key_phase_and_key_update".to_string(),
        "ack_ranges_rtt_loss_pto_and_congestion".to_string(),
        "anti_amplification_and_address_validation".to_string(),
        "stream_id_flow_control_reset_stop_and_reassembly".to_string(),
        "socket_endpoint_packet_io_under_cx".to_string(),
        "connection_id_lifecycle_path_validation_and_migration".to_string(),
        "quic_datagram_extension".to_string(),
        "connection_close_draining_and_error_surfaces".to_string(),
        "qlog_forensics_deterministic_replay_and_lab_adapter".to_string(),
        "external_quic_dependency_policy".to_string(),
    ]);
    assert_eq!(
        required_feature_ids, expected_feature_ids,
        "the contract should enumerate every ATP minimum native QUIC feature"
    );

    let rows = nonempty_array(&contract, "minimum_endpoint_contract");
    let row_ids = rows
        .iter()
        .map(|row| nonempty_str(row, "id").to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        row_ids, required_feature_ids,
        "each required feature must have exactly one matrix row"
    );

    let status_legend = contract["status_legend"]
        .as_object()
        .expect("status_legend must be an object");
    let implemented_statuses = BTreeSet::from([
        "implemented_core",
        "implemented_state_machine",
        "policy_gate",
    ]);

    for row in rows {
        let id = nonempty_str(row, "id");
        nonempty_str(row, "requirement");
        nonempty_str(row, "why_atp_needs_it");
        nonempty_array(row, "rfc_refs");
        nonempty_array(row, "source_files");
        nonempty_array(row, "source_markers");
        nonempty_str(row, "gap");
        nonempty_str(row, "atp_dependency_impact");
        nonempty_array(row, "test_expectations");

        let status = nonempty_str(row, "current_status");
        assert!(
            status_legend.contains_key(status),
            "{id} uses undocumented status {status}"
        );

        if !implemented_statuses.contains(status) {
            let followups = row
                .get("followup_beads")
                .and_then(Value::as_array)
                .unwrap_or_else(|| panic!("{id}.followup_beads must be an array"));
            let has_v0_exclusion = row
                .get("v0_exclusion")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.trim().is_empty());
            assert!(
                !followups.is_empty() || has_v0_exclusion,
                "{id} is not implemented but has no follow-up bead or explicit v0 exclusion"
            );
        }

        for bead in row
            .get("followup_beads")
            .and_then(Value::as_array)
            .unwrap_or_else(|| panic!("{id}.followup_beads must be an array"))
        {
            let bead_id = bead
                .as_str()
                .unwrap_or_else(|| panic!("{id}.followup_beads entries must be strings"));
            assert!(
                bead_id.starts_with("asupersync-"),
                "{id} follow-up bead must be a real bead id, got {bead_id}"
            );
        }
    }
}

#[test]
fn source_inventory_and_markers_exist() {
    let contract = load_contract();
    let mut referenced_files = BTreeSet::new();

    for source in nonempty_array(&contract, "source_inventory") {
        let path = nonempty_str(source, "path");
        nonempty_str(source, "role");
        let full = repo_root().join(path);
        assert!(full.exists(), "source inventory path must exist: {path}");
        referenced_files.insert(path.to_owned());
    }

    for row in nonempty_array(&contract, "minimum_endpoint_contract") {
        let id = nonempty_str(row, "id");
        for source_file in nonempty_array(row, "source_files") {
            let source_file = source_file
                .as_str()
                .unwrap_or_else(|| panic!("{id}.source_files entries must be strings"));
            let full = repo_root().join(source_file);
            assert!(full.exists(), "{id} references missing file {source_file}");
            referenced_files.insert(source_file.to_owned());
        }

        for marker in nonempty_array(row, "source_markers") {
            let file = nonempty_str(marker, "file");
            let needle = nonempty_str(marker, "marker");
            let haystack = read_repo_file(file);
            assert!(
                haystack.contains(needle),
                "{id} marker {needle:?} not found in {file}"
            );
        }
    }

    assert!(
        referenced_files.contains("src/net/quic_native/connection.rs"),
        "contract must cover native connection state"
    );
    assert!(
        referenced_files.contains("src/net/quic_core/mod.rs"),
        "contract must cover core QUIC codecs"
    );
    assert!(
        referenced_files.contains("src/net/udp.rs"),
        "contract must cover UDP endpoint substrate"
    );
}

#[test]
fn forensic_schema_documents_qlog_artifact_and_release_proof_lanes() {
    let schema = load_json(FORENSIC_SCHEMA_PATH, "QUIC/H3 forensic log schema");
    assert_eq!(
        nonempty_str(&schema, "schema_id"),
        "quic-h3-forensic-log.v1"
    );
    assert_eq!(schema["schema_version"], 1);
    assert_eq!(
        nonempty_str(&schema, "proof_suite_bead"),
        "asupersync-prl0wp"
    );

    let qlog = &schema["qlog_export"];
    assert_eq!(nonempty_str(qlog, "format"), "qlog-style-json");
    assert_eq!(
        nonempty_str(qlog, "writer"),
        "QuicH3ForensicLogger::write_qlog_json"
    );

    let artifact_dir = schema["artifact_bundle_layout"]["structure"]
        ["{artifacts_dir}/{scenario_id}/0x{SEED:016X}/"]
        .as_object()
        .expect("forensic artifact bundle directory must be an object");
    assert!(
        artifact_dir.contains_key("scenario.qlog.json"),
        "artifact bundle must document the qlog JSON file"
    );

    let source = read_repo_file("src/net/quic_native/forensic_log.rs");
    for marker in nonempty_array(qlog, "source_markers") {
        let marker = marker
            .as_str()
            .expect("qlog source markers must be strings");
        assert!(
            source.contains(marker),
            "qlog source marker {marker:?} missing from forensic logger"
        );
    }

    for common_field in nonempty_array(qlog, "required_common_fields") {
        let common_field = common_field
            .as_str()
            .expect("qlog common fields must be strings");
        assert!(
            source.contains(common_field),
            "qlog common field {common_field:?} missing from qlog export"
        );
    }

    let required_events = string_set(qlog, "required_event_evidence");
    for expected in [
        "packet_sent",
        "ack_received",
        "loss_detected",
        "pto_fired",
        "stream_opened",
        "path_validation_started",
        "path_validation_completed",
        "migration_observed",
        "close_initiated",
        "cancel_requested",
        "scenario_completed",
    ] {
        assert!(
            required_events.contains(expected),
            "qlog required event evidence missing {expected}"
        );
    }

    let commands = nonempty_array(&schema, "proof_commands");
    let command_ids = commands
        .iter()
        .map(|entry| nonempty_str(entry, "id").to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        command_ids,
        BTreeSet::from([
            "focused_forensic_logger".to_string(),
            "forensic_fuzz_smoke".to_string(),
            "native_transport_conformance".to_string(),
            "packet_number_fuzz_smoke".to_string(),
            "rfc9000_conformance".to_string(),
            "stream_id_conformance".to_string(),
            "transport_params_fuzz_smoke".to_string(),
        ])
    );

    for command in commands {
        let id = nonempty_str(command, "id");
        let proof = nonempty_str(command, "command");
        assert!(
            proof.starts_with("rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_quic_"),
            "{id} proof command must route Cargo through rch with a QUIC target dir"
        );
        assert!(
            proof.contains(" cargo "),
            "{id} proof command must invoke cargo under the rch env wrapper"
        );
        nonempty_array(command, "covers");
    }
}

#[test]
fn external_quic_stack_policy_is_enforced_against_active_dependencies() {
    let contract = load_contract();
    let policy = &contract["external_dependency_policy"];
    let allowed = policy["allowed_external_quic_stack_crates"]
        .as_array()
        .expect("allowed external QUIC stack list must be an array");
    assert!(
        allowed.is_empty(),
        "ATP native QUIC must not allow external endpoint-stack crates"
    );

    let forbidden = string_set(policy, "forbidden_external_quic_stack_crates");
    let expected = BTreeSet::from([
        "quinn".to_string(),
        "quiche".to_string(),
        "s2n-quic".to_string(),
        "msquic".to_string(),
        "h3-quinn".to_string(),
    ]);
    assert_eq!(forbidden, expected);

    let active_dependency_names = read_repo_file("Cargo.toml")
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| line.split_once('=').map(|(name, _)| name.trim()))
        .map(|name| name.trim_matches('"').to_owned())
        .collect::<BTreeSet<_>>();

    for crate_name in &forbidden {
        assert!(
            !active_dependency_names.contains(crate_name),
            "forbidden external QUIC stack dependency is active in Cargo.toml: {crate_name}"
        );
    }
}

#[test]
fn followup_overlay_covers_implementation_beads_that_own_the_gaps() {
    let contract = load_contract();
    let overlay = nonempty_array(&contract, "followup_dependency_overlay");
    let overlay_ids = overlay
        .iter()
        .map(|entry| nonempty_str(entry, "bead_id").to_owned())
        .collect::<BTreeSet<_>>();

    let expected = BTreeSet::from([
        "asupersync-rvryit".to_string(),
        "asupersync-e8hst6".to_string(),
        "asupersync-ny1gr9".to_string(),
        "asupersync-kwvb2g".to_string(),
        "asupersync-51uf70".to_string(),
        "asupersync-rsr2wm".to_string(),
        "asupersync-vls4za".to_string(),
        "asupersync-prl0wp".to_string(),
        "asupersync-xq4dvp".to_string(),
        "asupersync-crscmn".to_string(),
        "asupersync-jaghjr".to_string(),
        "asupersync-33lyim".to_string(),
    ]);
    assert_eq!(
        overlay_ids, expected,
        "A1 must name every native-QUIC implementation/proof bead that owns follow-up gaps"
    );

    for entry in overlay {
        nonempty_str(entry, "title");
        nonempty_array(entry, "depends_on_contract_features");
        nonempty_str(entry, "implementation_comment");
    }
}

#[test]
fn validation_commands_preserve_rch_cargo_policy_and_detailed_proof_surface() {
    let contract = load_contract();
    let commands = nonempty_array(&contract, "validation_commands");
    let mut saw_json_validation = false;
    let mut saw_contract_test = false;
    let mut saw_check = false;
    let mut saw_fmt = false;

    for command in commands {
        let purpose = nonempty_str(command, "purpose");
        let command_text = nonempty_str(command, "command");
        assert!(
            purpose.len() >= 24,
            "validation command purpose should explain the proof: {purpose}"
        );
        if command_text.contains("cargo ") {
            assert!(
                command_text.contains("rch exec -- env"),
                "cargo validation commands must run through rch: {command_text}"
            );
            assert!(
                command_text.contains("CARGO_TARGET_DIR"),
                "cargo validation commands must set CARGO_TARGET_DIR: {command_text}"
            );
        }
        saw_json_validation |= command_text.contains("python3 -m json.tool");
        saw_contract_test |= command_text.contains("--test atp_native_quic_endpoint_contract");
        saw_check |= command_text.contains("cargo check");
        saw_fmt |= command_text.contains("cargo fmt --check");
    }

    assert!(
        saw_json_validation,
        "artifact JSON validation command is required"
    );
    assert!(saw_contract_test, "contract test command is required");
    assert!(saw_check, "feature compile command is required");
    assert!(saw_fmt, "format check command is required");
}

#[test]
fn native_transport_metrics_report_pto_backoff_from_transport() {
    let mut transport = QuicTransportMachine::new();
    let collector =
        AtpTransportMetricsCollector::new("native-quic-contract".into(), "path-a".into());

    assert_eq!(collector.current_metrics(&transport).pto_count, 0);

    transport.on_pto_expired();
    transport.on_pto_expired();

    let metrics = collector.current_metrics(&transport);
    assert_eq!(
        metrics.pto_count, 2,
        "ATP transfer metrics must expose the native transport PTO backoff count"
    );
}

#[test]
fn native_transport_metrics_diagnose_repeated_pto_backoff() {
    let mut transport = QuicTransportMachine::new();
    let collector =
        AtpTransportMetricsCollector::new("native-quic-pto-doctor".into(), "path-b".into());

    transport.on_pto_expired();
    transport.on_pto_expired();
    transport.on_pto_expired();

    let metrics = collector.current_metrics(&transport);
    let assessment = metrics
        .path_doctor_assessment
        .as_ref()
        .expect("ATP metrics must include a path doctor assessment");

    assert!(
        assessment.detected_issues.iter().any(
            |issue| matches!(issue, PathIssue::FrequentTimeouts { pto_rate } if *pto_rate >= 0.75)
        ),
        "repeated native QUIC PTO backoff must be surfaced as path timeout pressure"
    );
    assert!(
        assessment
            .recommendations
            .iter()
            .any(|recommendation| matches!(
                recommendation,
                PathRecommendation::ReduceSendingRate { factor } if *factor <= 0.7
            )),
        "repeated PTO backoff should conservatively reduce send pressure"
    );
    assert!(
        assessment.recommendations.iter().any(|recommendation| {
            matches!(recommendation, PathRecommendation::EnablePathValidation)
        }),
        "repeated PTO backoff should trigger path validation advice"
    );
    assert!(
        assessment
            .recommendations
            .iter()
            .any(|recommendation| matches!(recommendation, PathRecommendation::ConsiderRelay)),
        "severe PTO backoff should recommend relay consideration"
    );
}
