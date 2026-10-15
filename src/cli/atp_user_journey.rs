//! ATP CLI and daemon user-journey proof contracts.
//!
//! The real transfer commands are still landing behind separate ATP-I/H/F
//! beads. This module gives the CLI e2e lane a stable, machine-readable
//! contract for the journeys, log fields, and artifacts those commands must
//! preserve as the implementations come online.

use serde::Serialize;

/// Stable contract identifier emitted by the ATP CLI journey scripts.
pub const ATP_USER_JOURNEY_CONTRACT_VERSION: &str = "atp-user-journey-e2e.v1";

/// Required fields for every structured event in a CLI journey bundle.
pub const ATP_USER_JOURNEY_REQUIRED_LOG_FIELDS: &[&str] = &[
    "event",
    "scenario_id",
    "command_line",
    "config_profile",
    "daemon_ids",
    "transfer_id",
    "path_summary",
    "manifest_root",
    "receive_plan_digest",
    "progress_event",
    "quarantine_path_state",
    "final_path_state",
    "final_proof",
];

/// One CLI, daemon, or SDK journey covered by the proof lane.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct AtpUserJourneyScenario {
    /// Stable scenario id used in JSONL logs and run reports.
    pub scenario_id: &'static str,
    /// User-facing journey name.
    pub journey: &'static str,
    /// Surfaces exercised by the scenario.
    pub surfaces: &'static [&'static str],
    /// Representative command lines the e2e script must exercise or dry-run.
    pub command_lines: &'static [&'static str],
    /// SDK APIs covered by this journey.
    pub sdk_apis: &'static [&'static str],
    /// Daemon lifecycle or topology events covered by this journey.
    pub daemon_events: &'static [&'static str],
    /// Receive-side permission and destination policy covered by this journey.
    pub receive_policy: &'static [&'static str],
    /// Network path modes covered by this journey.
    pub path_modes: &'static [&'static str],
    /// Artifacts that must be discoverable after success or failure.
    pub artifact_paths: &'static [&'static str],
    /// Human-output constraints asserted by the journey.
    pub human_output_assertions: &'static [&'static str],
}

/// Serializable top-level ATP user journey contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AtpUserJourneyContract {
    /// Contract schema/version id.
    pub contract_version: &'static str,
    /// Required structured event fields.
    pub required_log_fields: &'static [&'static str],
    /// Scenario matrix.
    pub scenarios: &'static [AtpUserJourneyScenario],
}

const SCENARIOS: &[AtpUserJourneyScenario] = &[
    AtpUserJourneyScenario {
        scenario_id: "first_pairing_share_code",
        journey: "first pairing and share code",
        surfaces: &["cli", "atpd", "sdk"],
        command_lines: &[
            "asupersync atp serve --profile first-run --json",
            "asupersync atp share ./fixture --peer bob --json",
            "asupersync atp status --json",
        ],
        sdk_apis: &["AtpSdk::create_identity", "AtpSdk::create_share_code"],
        daemon_events: &["daemon_start", "identity_created", "grant_recorded"],
        receive_policy: &["deny_by_default"],
        path_modes: &["direct"],
        artifact_paths: &[
            "structured_events.jsonl",
            "identity_bundle.json",
            "grant_log.jsonl",
        ],
        human_output_assertions: &["concise_pairing_code", "no_secret_echo"],
    },
    AtpUserJourneyScenario {
        scenario_id: "send_receive_explicit_approval",
        journey: "send and receive with explicit approval",
        surfaces: &["cli", "atpd", "sdk"],
        command_lines: &[
            "asupersync atp send ./fixture bob --name demo --json",
            "asupersync atp inbox --json",
            "asupersync atp get transfer-demo ./out --approve --json",
        ],
        sdk_apis: &[
            "AtpSdk::send",
            "AtpSdk::receive_plan",
            "ReceivePlan::approve",
        ],
        daemon_events: &[
            "sender_daemon_start",
            "receiver_daemon_start",
            "inbox_insert",
        ],
        receive_policy: &["explicit_approval", "safe_destination"],
        path_modes: &["direct", "relay"],
        artifact_paths: &["manifest.json", "receive_plan.json", "proof_bundle.json"],
        human_output_assertions: &["short_progress", "stable_json"],
    },
    AtpUserJourneyScenario {
        scenario_id: "receive_safety_deny_quarantine",
        journey: "receive safety, deny, quarantine, and dry-run",
        surfaces: &["cli", "atpd", "sdk"],
        command_lines: &[
            "asupersync atp get transfer-demo ./out --dry-run --json",
            "asupersync atp get transfer-demo ./out --deny --json",
            "asupersync atp get transfer-demo ./out --quarantine-only --json",
        ],
        sdk_apis: &[
            "AtpSdk::receive_plan",
            "ReceivePlan::deny",
            "ReceivePlan::quarantine_only",
        ],
        daemon_events: &[
            "receive_plan_constructed",
            "receive_denied",
            "quarantine_created",
        ],
        receive_policy: &[
            "deny_by_default",
            "quarantine_only",
            "safe_destination",
            "dry_run",
        ],
        path_modes: &["mailbox"],
        artifact_paths: &[
            "receive_plan.json",
            "quarantine_manifest.json",
            "safety_report.json",
        ],
        human_output_assertions: &[
            "danger_explained_before_execution",
            "no_mutation_on_dry_run",
        ],
    },
    AtpUserJourneyScenario {
        scenario_id: "sync_mirror_watch_seed",
        journey: "sync, mirror, watch, and seed",
        surfaces: &["cli", "sdk"],
        command_lines: &[
            "asupersync atp sync ./left bob:/right --json",
            "asupersync atp mirror ./left bob:/mirror --json",
            "asupersync atp watch ./left bob:/watch --json",
            "asupersync atp seed transfer-demo --json",
        ],
        sdk_apis: &[
            "AtpSdk::sync",
            "AtpSdk::mirror",
            "AtpSdk::watch",
            "AtpSdk::seed",
        ],
        daemon_events: &["watch_started", "seed_registered"],
        receive_policy: &["policy_driven_auto_accept", "policy_driven_auto_deny"],
        path_modes: &["direct", "relay"],
        artifact_paths: &["sync_plan.json", "mirror_plan.json", "watch_events.jsonl"],
        human_output_assertions: &["concise_conflict_summary", "stable_json"],
    },
    AtpUserJourneyScenario {
        scenario_id: "resume_cancel_restart",
        journey: "resume, cancel, shutdown, and daemon restart",
        surfaces: &["cli", "atpd", "sdk"],
        command_lines: &[
            "asupersync atp cancel transfer-demo --json",
            "asupersync atp resume transfer-demo --json",
            "asupersync atp status transfer-demo --json",
        ],
        sdk_apis: &["AtpSdk::cancel", "AtpSdk::resume", "AtpSdk::status"],
        daemon_events: &["shutdown_requested", "daemon_restart", "journal_recovered"],
        receive_policy: &["resume_preserves_receive_plan"],
        path_modes: &["direct"],
        artifact_paths: &[
            "resume_journal.jsonl",
            "restart_report.json",
            "final_proof.json",
        ],
        human_output_assertions: &["interruption_recovery_explained", "stable_json"],
    },
    AtpUserJourneyScenario {
        scenario_id: "nat_tailscale_relay_mailbox",
        journey: "NAT fallback, optional Tailscale, relay, and mailbox",
        surfaces: &["cli", "atpd"],
        command_lines: &[
            "asupersync atp send ./fixture bob --path auto --json",
            "asupersync atp status transfer-demo --explain --json",
        ],
        sdk_apis: &["AtpSdk::path_candidates", "AtpSdk::mailbox_enqueue"],
        daemon_events: &[
            "nat_probe",
            "tailscale_candidate_optional",
            "relay_fallback",
        ],
        receive_policy: &["mailbox_requires_receive_plan"],
        path_modes: &["nat_fallback", "tailscale_optional", "relay", "mailbox"],
        artifact_paths: &[
            "path_graph.json",
            "relay_trace.jsonl",
            "mailbox_receipt.json",
        ],
        human_output_assertions: &["path_reason_visible", "stable_json"],
    },
    AtpUserJourneyScenario {
        scenario_id: "doctor_trace_replay_bench",
        journey: "doctor, trace, replay, and bench smoke",
        surfaces: &["cli"],
        command_lines: &[
            "asupersync atp doctor --json",
            "asupersync trace verify trace.bin --json",
            "asupersync lab replay scenario.yaml --json",
            "asupersync atp bench --smoke --json",
        ],
        sdk_apis: &["AtpSdk::doctor", "AtpSdk::bench_smoke"],
        daemon_events: &["diagnostics_collected"],
        receive_policy: &["not_applicable"],
        path_modes: &["loopback"],
        artifact_paths: &["doctor.json", "trace.json", "replay.json", "bench.json"],
        human_output_assertions: &["human_output_concise", "stable_json"],
    },
    AtpUserJourneyScenario {
        scenario_id: "proof_verify_failure_discovery",
        journey: "proof, verify, and failure artifact discovery",
        surfaces: &["cli", "sdk"],
        command_lines: &[
            "asupersync atp proof proof_bundle.json --summary --json",
            "asupersync atp verify proof_bundle.json --strict --json",
        ],
        sdk_apis: &["AtpSdk::proof", "AtpSdk::verify"],
        daemon_events: &["proof_recorded"],
        receive_policy: &["proof_bound_to_receive_plan"],
        path_modes: &["direct", "relay", "mailbox"],
        artifact_paths: &[
            "proof_bundle.json",
            "verification_report.json",
            "failure_index.json",
        ],
        human_output_assertions: &["proof_artifacts_discoverable_after_failure", "stable_json"],
    },
];

/// Return the ATP user journey e2e scenario matrix.
#[must_use]
pub const fn atp_user_journey_scenarios() -> &'static [AtpUserJourneyScenario] {
    SCENARIOS
}

/// Return the required structured log fields for ATP user journey bundles.
#[must_use]
pub const fn atp_user_journey_required_log_fields() -> &'static [&'static str] {
    ATP_USER_JOURNEY_REQUIRED_LOG_FIELDS
}

/// Return the serializable ATP user journey e2e contract.
#[must_use]
pub const fn atp_user_journey_contract() -> AtpUserJourneyContract {
    AtpUserJourneyContract {
        contract_version: ATP_USER_JOURNEY_CONTRACT_VERSION,
        required_log_fields: ATP_USER_JOURNEY_REQUIRED_LOG_FIELDS,
        scenarios: SCENARIOS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn values_for<F>(extract: F) -> BTreeSet<&'static str>
    where
        F: Fn(&AtpUserJourneyScenario) -> &'static [&'static str],
    {
        SCENARIOS
            .iter()
            .flat_map(extract)
            .copied()
            .collect::<BTreeSet<_>>()
    }

    #[test]
    fn user_journey_matrix_covers_cli_daemon_sdk_and_safety_paths() {
        let surfaces = values_for(|scenario| scenario.surfaces);
        for expected in ["cli", "atpd", "sdk"] {
            assert!(surfaces.contains(expected), "missing surface {expected}");
        }

        let policies = values_for(|scenario| scenario.receive_policy);
        for expected in [
            "deny_by_default",
            "explicit_approval",
            "quarantine_only",
            "safe_destination",
            "dry_run",
            "policy_driven_auto_accept",
            "policy_driven_auto_deny",
        ] {
            assert!(
                policies.contains(expected),
                "missing receive policy {expected}"
            );
        }

        let paths = values_for(|scenario| scenario.path_modes);
        for expected in [
            "direct",
            "nat_fallback",
            "tailscale_optional",
            "relay",
            "mailbox",
        ] {
            assert!(paths.contains(expected), "missing path mode {expected}");
        }
    }

    #[test]
    fn user_journey_matrix_covers_core_operator_commands() {
        let command_blob = SCENARIOS
            .iter()
            .flat_map(|scenario| scenario.command_lines.iter())
            .copied()
            .collect::<Vec<_>>()
            .join("\n");

        for expected in [
            "send", "get", "sync", "mirror", "share", "watch", "seed", "inbox", "status", "resume",
            "cancel", "verify", "proof", "doctor", "trace", "replay", "bench",
        ] {
            assert!(
                command_blob.contains(expected),
                "missing command coverage for {expected}"
            );
        }
    }

    #[test]
    fn user_journey_log_contract_has_required_bundle_fields() {
        let fields = ATP_USER_JOURNEY_REQUIRED_LOG_FIELDS
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        for expected in [
            "command_line",
            "config_profile",
            "daemon_ids",
            "transfer_id",
            "path_summary",
            "manifest_root",
            "receive_plan_digest",
            "progress_event",
            "quarantine_path_state",
            "final_path_state",
            "final_proof",
        ] {
            assert!(fields.contains(expected), "missing log field {expected}");
        }

        let assertions = values_for(|scenario| scenario.human_output_assertions);
        for expected in [
            "danger_explained_before_execution",
            "proof_artifacts_discoverable_after_failure",
            "stable_json",
        ] {
            assert!(
                assertions.contains(expected),
                "missing output assertion {expected}"
            );
        }
    }

    #[test]
    fn user_journey_contract_serializes_with_stable_schema() {
        let value = serde_json::to_value(atp_user_journey_contract())
            .expect("user journey contract should serialize");
        assert_eq!(value["contract_version"], ATP_USER_JOURNEY_CONTRACT_VERSION);
        assert_eq!(
            value["required_log_fields"]
                .as_array()
                .expect("required fields should serialize as an array")
                .len(),
            ATP_USER_JOURNEY_REQUIRED_LOG_FIELDS.len()
        );
        assert_eq!(
            value["scenarios"]
                .as_array()
                .expect("scenarios should serialize as an array")
                .len(),
            SCENARIOS.len()
        );
    }
}
