//! Contract tests for PROOF-TRAFFIC A3 clean-overlay runner handshake.
//!
//! The handshake composes the existing clean-overlay planner with installed RCH
//! capability evidence. It admits a command only when selected dirty/untracked
//! paths are covered by exclusive self reservations, the planner is unblocked,
//! and installed `rch exec` supports the clean-overlay flag surface.

#![allow(missing_docs)]

use asupersync::audit::clean_overlay_planner::{
    CleanOverlayRequest, ExclusionReason, PathChange, ReservationLease, WorkingTreeEntry,
};
use asupersync::audit::proof_traffic_overlay_handshake::{
    PROOF_TRAFFIC_OVERLAY_HANDSHAKE_SCHEMA_VERSION, ProofTrafficOverlayCapability,
    ProofTrafficOverlayHandshake, ProofTrafficOverlayHandshakeInput,
};
use asupersync::audit::proof_traffic_receipt::ProofTrafficDecision;
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const ARTIFACT_PATH: &str = "artifacts/proof_traffic_clean_overlay_runner_handshake_v1.json";
const DOCS_PATH: &str = "docs/proof_traffic_control.md";
const GATE_ID: &str = "asupersync-proof-traffic-control-kuyx64.3";
const HEAD: &str = "4be8af503cafebeef0000000000000000000000";
const INTENT: &str = "cargo test -p asupersync --test proof_traffic_clean_overlay_runner_handshake_contract -- --nocapture";
const TARGET_DIR: &str = "${TMPDIR:-/tmp}/rch_target_proof_traffic_clean_overlay_handshake";
const SELECTED_DIRTY: &str = "src/audit/proof_traffic_overlay_handshake.rs";
const SELECTED_UNTRACKED: &str = "tests/proof_traffic_clean_overlay_runner_handshake_contract.rs";
const POISON: &str = "src/peer_poison_would_not_compile.rs";
const SUPPORTED_RCH_HELP: &str = r"
Options:
    -b, --base=<HEAD>
    --clean-overlay
    -o, --overlay-path=<PATH>
    --no-overlay
";
const UNSUPPORTED_RCH_HELP: &str = r"
Options:
    -v, --verbose
    -q, --quiet
    Examples:
    --base HEAD
    --clean-overlay
    --overlay-path PATH
    --no-overlay
";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

fn json(relative: &str) -> Value {
    serde_json::from_str(&read_repo_file(relative))
        .unwrap_or_else(|error| panic!("parse {relative}: {error}"))
}

fn array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value[key]
        .as_array()
        .unwrap_or_else(|| panic!("{key} array"))
        .as_slice()
}

fn string_field<'a>(value: &'a Value, key: &str) -> &'a str {
    let text = value[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} string"));
    assert!(!text.trim().is_empty(), "{key} must be nonempty");
    text
}

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    array(value, key)
        .iter()
        .map(|entry| entry.as_str().expect("string entry").to_string())
        .collect()
}

fn wte(path: &str, change: PathChange) -> WorkingTreeEntry {
    WorkingTreeEntry::new(path, change)
}

fn lease(pattern: &str) -> ReservationLease {
    ReservationLease::new(pattern, true)
}

fn shared_lease(pattern: &str) -> ReservationLease {
    ReservationLease::new(pattern, false)
}

fn request(
    working_tree: Vec<WorkingTreeEntry>,
    selected: &[&str],
    reservations: Vec<ReservationLease>,
    report_only: bool,
) -> CleanOverlayRequest {
    CleanOverlayRequest {
        head_commit: HEAD.to_string(),
        working_tree,
        selected_paths: selected.iter().map(|path| (*path).to_string()).collect(),
        reservations,
        command_intent: INTENT.to_string(),
        report_only,
    }
}

fn supported_capability() -> ProofTrafficOverlayCapability {
    ProofTrafficOverlayCapability::from_rch_exec_help("rch-1.0.99-exec-help", SUPPORTED_RCH_HELP)
}

fn unsupported_capability() -> ProofTrafficOverlayCapability {
    ProofTrafficOverlayCapability::from_rch_exec_help("rch-1.0.49-exec-help", UNSUPPORTED_RCH_HELP)
}

fn handshake(
    request: CleanOverlayRequest,
    capability: ProofTrafficOverlayCapability,
) -> ProofTrafficOverlayHandshake {
    let input = ProofTrafficOverlayHandshakeInput::new(
        GATE_ID.to_string(),
        request,
        TARGET_DIR,
        capability,
    );
    ProofTrafficOverlayHandshake::from_input(&input)
}

fn assert_no_forbidden_command_surface(handshake: &ProofTrafficOverlayHandshake) {
    assert!(
        handshake.forbidden_command_tokens().is_empty(),
        "forbidden command tokens leaked in {}: {:?}\n{}",
        handshake.decision.label(),
        handshake.forbidden_command_tokens(),
        handshake.rendered_command
    );
    assert!(
        !handshake.uses_local_cargo_fallback(),
        "local Cargo fallback leaked in command:\n{}",
        handshake.rendered_command
    );
}

#[test]
fn supported_capability_admits_reserved_dirty_and_untracked_paths() {
    let receipt = handshake(
        request(
            vec![
                wte(SELECTED_DIRTY, PathChange::Modified),
                wte(SELECTED_UNTRACKED, PathChange::Untracked),
            ],
            &[SELECTED_DIRTY, SELECTED_UNTRACKED],
            vec![lease(SELECTED_DIRTY), lease("tests/*.rs")],
            false,
        ),
        supported_capability(),
    );

    assert_eq!(receipt.decision, ProofTrafficDecision::RunNow);
    assert!(receipt.admitted);
    assert_eq!(
        receipt.included_paths,
        vec![SELECTED_DIRTY.to_string(), SELECTED_UNTRACKED.to_string()]
    );
    assert_eq!(
        receipt.reservation_evidence,
        vec![
            "src/audit/proof_traffic_overlay_handshake.rs".to_string(),
            "tests/*.rs".to_string()
        ]
    );
    assert!(receipt.rendered_command.contains("RCH_REQUIRE_REMOTE=1"));
    assert!(receipt.rendered_command.contains("--clean-overlay"));
    assert!(
        receipt
            .rendered_command
            .contains(&format!("--overlay-path {SELECTED_DIRTY}"))
    );
    assert!(
        receipt
            .rendered_command
            .contains(&format!("--overlay-path {SELECTED_UNTRACKED}"))
    );
    assert_no_forbidden_command_surface(&receipt);
}

#[test]
fn shared_or_missing_reservation_fails_closed() {
    let receipt = handshake(
        request(
            vec![wte(SELECTED_DIRTY, PathChange::Modified)],
            &[SELECTED_DIRTY],
            vec![shared_lease(SELECTED_DIRTY)],
            false,
        ),
        supported_capability(),
    );

    assert_eq!(receipt.decision, ProofTrafficDecision::ParkRerunRequired);
    assert!(!receipt.admitted);
    assert!(receipt.rendered_command.starts_with("# BLOCKED"));
    assert_eq!(
        receipt
            .excluded_paths
            .iter()
            .find(|excluded| excluded.path == SELECTED_DIRTY)
            .map(|excluded| excluded.reason),
        Some(ExclusionReason::UnreservedSelection)
    );
    assert_no_forbidden_command_surface(&receipt);
}

#[test]
fn unsupported_overlay_capability_blocks_command_emission() {
    let receipt = handshake(
        request(
            vec![wte(SELECTED_DIRTY, PathChange::Modified)],
            &[SELECTED_DIRTY],
            vec![lease(SELECTED_DIRTY)],
            false,
        ),
        unsupported_capability(),
    );

    assert_eq!(
        receipt.decision,
        ProofTrafficDecision::BlockedByCapabilityDrift
    );
    assert!(!receipt.admitted);
    assert!(!receipt.clean_overlay_supported);
    assert!(
        receipt
            .missing_flags
            .contains(&"--clean-overlay".to_string())
    );
    assert_eq!(
        receipt.rendered_command,
        "# BLOCKED: installed RCH clean-overlay capability unsupported; no proof command emitted"
    );
    assert!(!receipt.rendered_command.to_lowercase().contains("cargo"));
    assert!(!receipt.rendered_command.contains("--overlay-path"));
    assert!(!receipt.rendered_command.contains(SELECTED_DIRTY));
    assert_no_forbidden_command_surface(&receipt);
}

#[test]
fn capability_help_probe_requires_option_declarations_not_example_mentions() {
    let supported = supported_capability();
    assert!(supported.clean_overlay_supported());
    assert!(supported.missing_flags().is_empty());

    let unsupported = unsupported_capability();
    assert!(!unsupported.clean_overlay_supported());
    assert_eq!(unsupported.missing_flags().len(), 4);
    for flag in [
        "--base",
        "--clean-overlay",
        "--overlay-path",
        "--no-overlay",
    ] {
        assert!(
            unsupported
                .missing_flags()
                .iter()
                .any(|missing| missing == flag),
            "example-only {flag} mention must not count as an option declaration"
        );
    }

    let missing_probe_version =
        ProofTrafficOverlayCapability::from_rch_exec_help("   ", SUPPORTED_RCH_HELP);
    assert!(!missing_probe_version.supports_required_flags());
    assert!(
        missing_probe_version
            .capability_findings()
            .iter()
            .any(|finding| finding.contains("probe version is missing"))
    );

    let receipt = handshake(
        request(
            vec![wte(SELECTED_DIRTY, PathChange::Modified)],
            &[SELECTED_DIRTY],
            vec![lease(SELECTED_DIRTY)],
            false,
        ),
        missing_probe_version,
    );
    assert_eq!(
        receipt.decision,
        ProofTrafficDecision::BlockedByCapabilityDrift
    );
    assert!(receipt.missing_flags.is_empty());
    assert!(receipt.retry_condition.contains("non-empty"));
    assert!(receipt.retry_condition.contains("probe version"));
    assert!(!receipt.retry_condition.contains("flags []"));
}

#[test]
fn peer_poison_path_fails_closed_and_never_enters_admitted_command() {
    let receipt = handshake(
        request(
            vec![
                wte(SELECTED_DIRTY, PathChange::Modified),
                wte(POISON, PathChange::Modified),
            ],
            &[SELECTED_DIRTY],
            vec![lease(SELECTED_DIRTY)],
            false,
        ),
        supported_capability(),
    );

    assert_eq!(receipt.decision, ProofTrafficDecision::BlockedByPeer);
    assert!(!receipt.admitted);
    assert!(
        receipt.included_paths.contains(&SELECTED_DIRTY.to_string()),
        "selected reserved path should remain classified as includable"
    );
    assert_eq!(
        receipt
            .excluded_paths
            .iter()
            .find(|excluded| excluded.path == POISON)
            .map(|excluded| excluded.reason),
        Some(ExclusionReason::PeerDirtyUnselected)
    );
    assert!(
        !receipt.rendered_command.contains(POISON),
        "poison peer path must not enter command: {}",
        receipt.rendered_command
    );
    let handoff = receipt.agent_mail_body();
    assert!(handoff.contains(
        "dirty_frontier: `peer-dirty observed; no command admitted and no exclusion claim`"
    ));
    assert!(!handoff.contains("peer-dirty excluded"));
    assert_no_forbidden_command_surface(&receipt);
}

#[test]
fn deleted_selected_path_is_refused_without_file_deletion() {
    let receipt = handshake(
        request(
            vec![wte(SELECTED_DIRTY, PathChange::Deleted)],
            &[SELECTED_DIRTY],
            vec![lease(SELECTED_DIRTY)],
            false,
        ),
        supported_capability(),
    );

    assert_eq!(receipt.decision, ProofTrafficDecision::ParkRerunRequired);
    assert!(!receipt.admitted);
    assert_eq!(
        receipt
            .excluded_paths
            .iter()
            .find(|excluded| excluded.path == SELECTED_DIRTY)
            .map(|excluded| excluded.reason),
        Some(ExclusionReason::DeletedSelectionRefused)
    );
    assert!(!receipt.rendered_command.contains("rm "));
    assert!(!receipt.rendered_command.contains("delete"));
    assert_no_forbidden_command_surface(&receipt);
}

#[test]
fn report_only_mode_renders_exclusions_but_no_proof_command() {
    let receipt = handshake(
        request(
            vec![
                wte(SELECTED_DIRTY, PathChange::Modified),
                wte(POISON, PathChange::Modified),
            ],
            &[SELECTED_DIRTY],
            vec![lease(SELECTED_DIRTY)],
            true,
        ),
        supported_capability(),
    );

    assert_eq!(receipt.decision, ProofTrafficDecision::ReportOnly);
    assert!(receipt.report_only);
    assert!(!receipt.admitted);
    assert_eq!(
        receipt.rendered_command,
        "# REPORT-ONLY: clean-overlay handshake dry run; no proof command emitted"
    );
    let report = receipt.render_markdown();
    assert!(
        report.contains(POISON),
        "report must name excluded peer path"
    );
    assert!(report.contains("peer-dirty-unselected"));
    assert!(!receipt.rendered_command.to_lowercase().contains("cargo"));
    assert_no_forbidden_command_surface(&receipt);
}

#[test]
fn unsupported_capability_precedes_report_only_mode() {
    let receipt = handshake(
        request(
            vec![wte(SELECTED_DIRTY, PathChange::Modified)],
            &[SELECTED_DIRTY],
            vec![lease(SELECTED_DIRTY)],
            true,
        ),
        unsupported_capability(),
    );

    assert_eq!(
        receipt.decision,
        ProofTrafficDecision::BlockedByCapabilityDrift
    );
    assert!(receipt.report_only, "source planner mode remains recorded");
    assert!(!receipt.admitted);
    assert_eq!(
        receipt.rendered_command,
        "# BLOCKED: installed RCH clean-overlay capability unsupported; no proof command emitted"
    );
    assert_no_forbidden_command_surface(&receipt);
}

#[test]
fn json_markdown_and_handoff_bodies_are_deterministic() {
    let receipt = handshake(
        request(
            vec![wte(SELECTED_DIRTY, PathChange::Modified)],
            &[SELECTED_DIRTY],
            vec![lease(SELECTED_DIRTY)],
            false,
        ),
        supported_capability(),
    );

    let json = serde_json::to_value(&receipt).expect("serialize receipt");
    assert_eq!(
        string_field(&json, "schema_version"),
        PROOF_TRAFFIC_OVERLAY_HANDSHAKE_SCHEMA_VERSION
    );
    assert_eq!(string_field(&json, "gate_id"), GATE_ID);
    assert_eq!(json["decision"].as_str(), Some("run-now"));
    assert_eq!(string_field(&json, "head_commit"), HEAD);
    assert_eq!(string_field(&json, "target_dir"), TARGET_DIR);
    assert!(string_field(&json, "command_intent").contains("proof_traffic_clean_overlay"));
    assert_eq!(
        json["selected_paths"][0].as_str(),
        Some("src/audit/proof_traffic_overlay_handshake.rs")
    );
    assert_eq!(json["clean_overlay_supported"].as_bool(), Some(true));
    assert!(string_field(&json, "retry_condition").contains("none"));
    assert!(receipt.no_claim_boundaries.iter().any(|boundary| {
        boundary
            == "No claim that peer dirt was excluded unless installed RCH clean-overlay capability evidence is supported and an admitted command completed with terminal execution evidence."
    }));

    let markdown = receipt.render_markdown();
    assert_eq!(markdown, receipt.render_markdown());
    for field in [
        "gate_id",
        "status",
        "head_commit",
        "command_intent",
        "target_dir",
        "selected_paths",
        "included_paths",
        "excluded_paths",
        "reservation_evidence",
        "capability_probe_version",
        "clean_overlay_supported",
        "missing_flags",
        "capability_findings",
        "rendered_command",
        "admitted",
        "report_only",
        "retry_condition",
        "terminal_execution_evidence",
        "rch_worker_or_refusal",
        "dirty_frontier",
        "rollback_action",
        "no_claim_boundaries",
    ] {
        assert!(markdown.contains(field), "markdown missing {field}");
    }

    let agent_mail = receipt.agent_mail_body();
    let br_comment = receipt.br_comment_body();
    for body in [agent_mail, br_comment] {
        for field in [
            "gate_id",
            "status",
            "head_commit",
            "command_intent",
            "target_dir",
            "selected_paths",
            "included_paths",
            "excluded_paths",
            "reservation_evidence",
            "rendered_command",
            "capability_probe_version",
            "clean_overlay_supported",
            "missing_flags",
            "capability_findings",
            "admitted",
            "report_only",
            "retry_condition",
            "terminal_execution_evidence",
            "rch_worker_or_refusal",
            "dirty_frontier",
            "rollback_action",
            "no_claim_boundaries",
        ] {
            assert!(body.contains(field), "handoff body missing {field}");
        }
        assert!(body.contains("local_cargo_fallback_allowed: `false`"));
        assert!(body.contains("branch_or_worktree_allowed: `false`"));
        assert!(
            body.contains(
                "terminal_execution_evidence: `none; pre-execution admission receipt only`"
            )
        );
        assert!(body.contains("execution not attested"));
    }
}

#[test]
fn artifact_and_docs_pin_a3_contract_scope() {
    let artifact = json(ARTIFACT_PATH);
    assert_eq!(
        string_field(&artifact, "schema_version"),
        "proof-traffic-clean-overlay-runner-handshake-v1"
    );
    assert_eq!(string_field(&artifact, "bead_id"), GATE_ID);
    assert_eq!(string_field(&artifact, "status"), "contract_guarded");
    assert!(string_field(&artifact, "handoff_stage").contains("pre-execution admission receipt"));

    let capability_rules = &artifact["capability_evidence_rules"];
    assert_eq!(
        capability_rules["nonempty_probe_version_required"].as_bool(),
        Some(true)
    );
    assert_eq!(
        capability_rules["required_flags_must_be_declared_in_options_section"].as_bool(),
        Some(true)
    );
    assert_eq!(
        capability_rules["prose_or_example_mentions_do_not_count"].as_bool(),
        Some(true)
    );
    assert_eq!(
        capability_rules["unsupported_capability_precedes_report_only"].as_bool(),
        Some(true)
    );
    assert_eq!(
        string_field(capability_rules, "unsupported_marker"),
        "# BLOCKED: installed RCH clean-overlay capability unsupported; no proof command emitted"
    );

    for path in [
        string_field(&artifact["source_of_truth"], "artifact"),
        string_field(&artifact["source_of_truth"], "operator_doc"),
        string_field(&artifact["source_of_truth"], "contract_test"),
        string_field(&artifact["source_of_truth"], "rust_module"),
        string_field(&artifact["source_of_truth"], "planner_module"),
        string_field(&artifact["source_of_truth"], "command_module"),
        string_field(&artifact["source_of_truth"], "capability_artifact"),
    ] {
        assert!(repo_path(path).exists(), "{path} must exist");
    }

    let required = string_set(&artifact, "required_fixture_coverage");
    for fixture in [
        "reservation-matched-dirty-path",
        "reservation-matched-untracked-path",
        "peer-reservation-conflict",
        "report-only-mode",
        "admitted-mode",
        "unsupported-backend-mode",
        "deleted-selection-refused",
        "poison-peer-path-excluded",
    ] {
        assert!(required.contains(fixture), "missing fixture {fixture}");
    }

    let report_fields = string_set(&artifact, "required_report_fields");
    for field in [
        "capability_probe_version",
        "clean_overlay_supported",
        "missing_flags",
        "capability_findings",
        "rendered_command",
        "admitted",
        "report_only",
        "terminal_execution_evidence",
        "rch_worker_or_refusal",
        "dirty_frontier",
        "rollback_action",
        "no_claim_boundaries",
    ] {
        assert!(
            report_fields.contains(field),
            "missing report field {field}"
        );
    }
    assert!(
        string_set(&artifact, "no_claim_boundaries").contains(
            "No claim that peer dirt was excluded unless installed RCH clean-overlay capability evidence is supported and an admitted command completed with terminal execution evidence."
        )
    );

    let docs = read_repo_file(DOCS_PATH);
    for needle in [
        "Proof-Traffic A3 Clean-Overlay Handshake",
        "artifacts/proof_traffic_clean_overlay_runner_handshake_v1.json",
        "tests/proof_traffic_clean_overlay_runner_handshake_contract.rs",
        "blocked-by-capability-drift",
        "poison peer path",
        "exclusive self reservations",
        "prose and example mentions do not count",
        "terminal execution evidence",
        "pre-execution admission receipts",
    ] {
        assert!(docs.contains(needle), "docs missing {needle}");
    }
}
