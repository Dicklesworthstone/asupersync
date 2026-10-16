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
