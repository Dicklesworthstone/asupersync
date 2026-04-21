#![allow(clippy::all)]
//! Integration contract tests for advanced doctor provenance fixtures.
#![cfg(feature = "cli")]

use std::collections::BTreeSet;

use asupersync::cli::doctor::{
    advanced_diagnostics_report_bundle, agent_mail_pane_contract, beads_command_center_contract,
    run_advanced_diagnostics_report_smoke, run_agent_mail_pane_smoke,
    run_beads_command_center_smoke, structured_logging_contract,
    validate_advanced_diagnostics_report_extension,
    validate_advanced_diagnostics_report_extension_contract,
    validate_core_diagnostics_report_contract,
};

#[test]
fn advanced_fixture_corpus_covers_required_scenarios() {
    let bundle = advanced_diagnostics_report_bundle();
    let fixture_ids = bundle
        .fixtures
        .iter()
        .map(|fixture| fixture.fixture_id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        fixture_ids,
        vec![
            "advanced_conflicting_signal_path",
            "advanced_cross_system_mismatch_path",
            "advanced_failure_path",
            "advanced_happy_path",
            "advanced_partial_success_path",
            "advanced_rollback_path",
        ]
    );
}

#[test]
fn advanced_cross_system_fixture_links_beads_agent_mail_and_frankensuite() {
    let bundle = advanced_diagnostics_report_bundle();
    let fixture = bundle
        .fixtures
        .iter()
        .find(|candidate| candidate.fixture_id == "advanced_cross_system_mismatch_path")
        .expect("cross-system mismatch fixture exists");

    let channels = fixture
        .extension
        .collaboration_trail
        .iter()
        .map(|entry| entry.channel.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        channels,
        BTreeSet::from(["agent_mail", "beads", "frankensuite"])
    );
    assert!(
        fixture
            .extension
            .trust_transitions
            .iter()
            .any(|transition| transition.rationale.contains("mismatch")),
        "cross-system mismatch fixture must include mismatch rationale"
    );
    assert!(
        fixture
            .extension
            .troubleshooting_playbooks
            .iter()
            .any(|playbook| {
                playbook
                    .ordered_steps
                    .iter()
                    .any(|step| step == "generate_mismatch_diagnostics_bundle")
            }),
        "cross-system mismatch fixture must include mismatch diagnostics step"
    );
}

#[test]
fn advanced_smoke_emits_events_for_every_fixture() {
    let bundle = advanced_diagnostics_report_bundle();
    validate_core_diagnostics_report_contract(&bundle.core_contract).expect("core contract valid");
    validate_advanced_diagnostics_report_extension_contract(&bundle.extension_contract)
        .expect("extension contract valid");
    for fixture in &bundle.fixtures {
        validate_advanced_diagnostics_report_extension(
            &fixture.extension,
            &fixture.core_report,
            &bundle.extension_contract,
            &bundle.core_contract,
        )
        .expect("fixture extension validates");
    }

    let logging_contract = structured_logging_contract();
    let first = run_advanced_diagnostics_report_smoke(&bundle, &logging_contract)
        .expect("first advanced smoke run succeeds");
    let second = run_advanced_diagnostics_report_smoke(&bundle, &logging_contract)
        .expect("second advanced smoke run succeeds");
    assert_eq!(first, second, "advanced smoke output must be deterministic");
    assert_eq!(first.len(), bundle.fixtures.len() * 3);

    let fixture_ids_from_events = first
        .iter()
        .filter_map(|event| event.fields.get("artifact_pointer"))
        .map(String::as_str)
        .filter_map(|pointer: &str| pointer.rsplit('/').next())
        .filter_map(|name: &str| name.strip_suffix(".json"))
        .collect::<BTreeSet<_>>();
    let expected_fixture_ids = bundle
        .fixtures
        .iter()
        .map(|fixture| fixture.fixture_id.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(fixture_ids_from_events, expected_fixture_ids);
}

#[test]
fn beads_and_agent_mail_smokes_are_deterministic_and_interoperable() {
    let beads_contract = beads_command_center_contract();
    let beads_first = run_beads_command_center_smoke(&beads_contract).expect("beads smoke");
    let beads_second = run_beads_command_center_smoke(&beads_contract).expect("beads smoke rerun");
    assert_eq!(
        beads_first, beads_second,
        "beads smoke must be deterministic"
    );
    assert!(
        beads_first
            .events
            .iter()
            .any(|event| event.event_kind == "command_invoked" && event.source == "triage"),
        "beads smoke must keep deterministic bv invocation events"
    );

    let bead_ids = beads_first
        .ready_work
        .iter()
        .map(|item| item.id.clone())
        .chain(beads_first.blocked_work.iter().map(|item| item.id.clone()))
        .chain(beads_first.triage.iter().map(|item| item.id.clone()))
        .collect::<BTreeSet<_>>();
    assert!(
        !bead_ids.is_empty(),
        "beads smoke should expose at least one bead id"
    );
    assert!(
        bead_ids
            .iter()
            .all(|bead_id| bead_id.starts_with("asupersync-")),
        "beads smoke should emit canonical asupersync bead ids"
    );

    let agent_mail_contract = agent_mail_pane_contract();
    let agent_first = run_agent_mail_pane_smoke(&agent_mail_contract).expect("agent mail smoke");
    let agent_second =
        run_agent_mail_pane_smoke(&agent_mail_contract).expect("agent mail smoke rerun");
    assert_eq!(
        agent_first, agent_second,
        "agent mail smoke must be deterministic"
    );
    assert_eq!(agent_first.steps.len(), 3, "expected fetch/ack/reply flow");

    let fetch_snapshot = &agent_first.steps[0].snapshot;
    let ack_snapshot = &agent_first.steps[1].snapshot;
    let reply_snapshot = &agent_first.steps[2].snapshot;
    assert!(
        fetch_snapshot.pending_ack_count > ack_snapshot.pending_ack_count,
        "ack step must reduce pending acknowledgements"
    );
    assert!(
        fetch_snapshot
            .replay_commands
            .iter()
            .any(|command| command.contains("acknowledge_message")),
        "fetch snapshot must preserve ack replay command"
    );
    assert!(
        reply_snapshot
            .replay_commands
            .iter()
            .any(|command| command.contains("reply_message")),
        "reply snapshot must preserve in-thread reply replay command"
    );

    let thread_ids = agent_first
        .steps
        .iter()
        .flat_map(|step| step.snapshot.thread_messages.iter())
        .filter_map(|message| message.thread_id.clone())
        .collect::<BTreeSet<_>>();
    assert!(
        thread_ids.iter().any(|thread| thread.starts_with("coord-")),
        "agent mail thread snapshots should preserve coordination thread ids"
    );
}

#[test]
fn integration_docs_and_e2e_runner_define_cross_system_matrix_guards() {
    let core_doc = include_str!("../docs/doctor_diagnostics_report_contract.md");
    for required in [
        "Cross-System Compatibility Matrix (`asupersync-2b4jj.5.5`)",
        "doctor-beads-command-center-v1",
        "doctor-agent-mail-pane-v1",
        "doctor-frankensuite-export-v1",
        "doctor-report-export-v1",
    ] {
        assert!(
            core_doc.contains(required),
            "core diagnostics contract doc missing required integration token: {required}"
        );
    }

    let franken_doc = include_str!("../docs/doctor_frankensuite_export_contract.md");
    for required in [
        "Cross-System Integration Assertions (`asupersync-2b4jj.5.5`)",
        "doctor-core-report-v1",
        "has_mismatch_diagnostics == true",
        "doctor report-contract",
    ] {
        assert!(
            franken_doc.contains(required),
            "frankensuite export doc missing required integration token: {required}"
        );
    }

    let e2e_runner = include_str!("../scripts/test_doctor_frankensuite_export_e2e.sh");
    for required in [
        "doctor report-export",
        "doctor-report-export-v1",
        "collaboration_channels == [\"agent_mail\", \"beads\", \"frankensuite\"]",
        "has_mismatch_diagnostics == true",
        "doctor report-contract",
    ] {
        assert!(
            e2e_runner.contains(required),
            "frankensuite export e2e runner missing required integration assertion token: {required}"
        );
    }
}
