//! ATP path doctor JSON and trace contract tests.

use asupersync::atp::path::{
    PathCandidate, PathCandidateId, PathFailureKind, PathKind, PathOutcome, PathRace,
    PathSuccessKind, PathTraceId,
};
use asupersync::atp::{
    ATP_PATH_DOCTOR_SCHEMA, ATP_PATH_TRACE_ATTEMPT_SCHEMA, build_path_doctor_document,
    render_path_doctor_human,
};
use asupersync::lab::atp_path::{
    AtpPathEventKind, AtpPathExecutionResult, AtpPathLabHarness, AtpPathTestConfig,
};
use asupersync::lab::{AtpLabRegime, AtpLabScenario};
use asupersync::net::atp::{
    DirectCandidateRejection, DirectCandidateSource, PathDiscoveryInputs, PathDiscoveryPolicy,
    TailscaleCandidateObservation, TailscaleDetectionSource, TailscalePathPolicy,
    discover_direct_paths,
};
use std::net::SocketAddr;

fn path_candidate(raw: u64, kind: PathKind) -> PathCandidate {
    PathCandidate::new(
        PathCandidateId::new(raw),
        kind,
        PathTraceId::new(90_000 + raw),
    )
}

fn socket(address: &str) -> SocketAddr {
    address.parse().expect("socket address")
}

fn relay_fallback_race() -> PathRace {
    let direct = PathCandidateId::new(1);
    let relay = PathCandidateId::new(2);
    let mut race = PathRace::new();
    race.add_candidate(path_candidate(direct.get(), PathKind::NatPunchedUdp))
        .unwrap();
    race.add_candidate(path_candidate(relay.get(), PathKind::AtpRelayTcpTls443))
        .unwrap();
    race.add_candidate(path_candidate(3, PathKind::TailscaleIp))
        .unwrap();

    race.start_all().unwrap();
    race.record_outcome(
        direct,
        PathOutcome::failure(PathFailureKind::HardNat, 4_000).with_bytes(384, 128),
    )
    .unwrap();
    race.record_outcome(
        relay,
        PathOutcome::success(PathSuccessKind::RelaySelected, 8_000, Some(42_000))
            .with_bytes(1_200, 1_024),
    )
    .unwrap();
    race
}

fn udp_blocked_tcp_tls_fallback_race() -> PathRace {
    let direct = PathCandidateId::new(10);
    let relay = PathCandidateId::new(11);
    let mut race = PathRace::new();
    race.add_candidate(path_candidate(direct.get(), PathKind::NatPunchedUdp))
        .unwrap();
    race.add_candidate(path_candidate(relay.get(), PathKind::AtpRelayTcpTls443))
        .unwrap();

    race.start_all().unwrap();
    race.record_outcome(
        direct,
        PathOutcome::failure(PathFailureKind::UdpBlocked, 3_000).with_bytes(256, 0),
    )
    .unwrap();
    race.record_outcome(
        relay,
        PathOutcome::success(PathSuccessKind::RelaySelected, 9_000, Some(55_000))
            .with_bytes(1_800, 1_600),
    )
    .unwrap();
    race
}

fn path_race_from_lab_result(result: &AtpPathExecutionResult) -> PathRace {
    let attempts = result
        .trace_events
        .iter()
        .filter_map(|event| match &event.event {
            AtpPathEventKind::ConnectionAttempt { path_kind, .. } => {
                Some((*path_kind, event.trace_id))
            }
            _ => None,
        })
        .collect::<Vec<_>>();

    let mut race = PathRace::new();
    for (index, (path_kind, trace_id)) in attempts.iter().copied().enumerate() {
        race.add_candidate(PathCandidate::new(
            PathCandidateId::new(index as u64 + 1),
            path_kind,
            trace_id,
        ))
        .expect("lab path candidate");
    }
    race.start_all().expect("start lab-derived path race");

    for event in &result.trace_events {
        match &event.event {
            AtpPathEventKind::PathSucceeded {
                path_kind,
                latency_micros,
            } => {
                let candidate_id = candidate_id_for_path(&attempts, *path_kind);
                race.record_outcome(
                    candidate_id,
                    PathOutcome::success(
                        success_kind_for_path(*path_kind),
                        event.timestamp.as_nanos().saturating_div(1_000),
                        Some(*latency_micros),
                    )
                    .with_bytes(1_200, 1_024),
                )
                .expect("record lab path success");
            }
            AtpPathEventKind::PathFailed { path_kind, .. } => {
                let candidate_id = candidate_id_for_path(&attempts, *path_kind);
                race.record_outcome(
                    candidate_id,
                    PathOutcome::failure(
                        failure_kind_for_path(*path_kind),
                        event.timestamp.as_nanos().saturating_div(1_000),
                    )
                    .with_bytes(384, 0),
                )
                .expect("record lab path failure");
            }
            _ => {}
        }
    }

    race
}

fn candidate_id_for_path(
    attempts: &[(PathKind, PathTraceId)],
    path_kind: PathKind,
) -> PathCandidateId {
    let index = attempts
        .iter()
        .position(|(candidate_kind, _)| *candidate_kind == path_kind)
        .expect("lab trace should include connection attempt before outcome");
    PathCandidateId::new(index as u64 + 1)
}

fn success_kind_for_path(path_kind: PathKind) -> PathSuccessKind {
    match path_kind {
        PathKind::TailscaleIp => PathSuccessKind::TailscaleSelected,
        PathKind::AtpRelayUdp | PathKind::AtpRelayTcpTls443 | PathKind::MasqueConnectUdp => {
            PathSuccessKind::RelaySelected
        }
        PathKind::OfflineMailbox => PathSuccessKind::MailboxAccepted,
        PathKind::LanMulticast
        | PathKind::ExplicitPublicUdp
        | PathKind::PublicIpv6
        | PathKind::NatPunchedUdp => PathSuccessKind::DirectValidated,
    }
}

fn failure_kind_for_path(path_kind: PathKind) -> PathFailureKind {
    match path_kind {
        PathKind::NatPunchedUdp => PathFailureKind::HardNat,
        PathKind::AtpRelayUdp | PathKind::AtpRelayTcpTls443 | PathKind::MasqueConnectUdp => {
            PathFailureKind::RelayUnavailable
        }
        PathKind::TailscaleIp
        | PathKind::LanMulticast
        | PathKind::ExplicitPublicUdp
        | PathKind::PublicIpv6
        | PathKind::OfflineMailbox => PathFailureKind::ProtocolError,
    }
}

#[test]
fn path_doctor_document_has_stable_json_and_trace_contract() {
    let race = relay_fallback_race();
    let document = build_path_doctor_document("peer-redacted", &race);
    let json = serde_json::to_value(&document).unwrap();

    assert_eq!(json["schema_version"], ATP_PATH_DOCTOR_SCHEMA);
    assert_eq!(json["peer"], "peer-redacted");
    assert_eq!(json["summary"]["overall_health"], "degraded");
    assert_eq!(json["summary"]["reason_code"], "relay_fallback_validated");
    assert_eq!(json["summary"]["failure_count"], 1);
    assert_eq!(json["summary"]["drained_loser_count"], 1);
    assert_eq!(json["selected_path"]["candidate_id"], 2);
    assert_eq!(json["selected_path"]["family"], "relay");
    assert_eq!(json["selected_path"]["trace_id"], 90_002);

    let trace = json["trace"].as_array().unwrap();
    assert_eq!(trace.len(), 3);
    assert!(
        trace
            .iter()
            .all(|row| row["schema_version"] == ATP_PATH_TRACE_ATTEMPT_SCHEMA)
    );
    assert!(trace.iter().any(|row| {
        row["candidate_id"] == 3
            && row["state"] == "drained_loser"
            && row["detail"]
                .as_str()
                .unwrap()
                .contains("lost to candidate 2")
    }));

    let human = render_path_doctor_human(&document);
    assert!(human.contains("Overall: degraded reason=relay_fallback_validated"));
    assert!(human.contains("Selected: candidate=2 kind=atp_relay_tcp_tls_443 family=relay"));
    assert!(human.contains("Structured trace rows: 3"));
}

#[tokio::test]
async fn path_doctor_example_is_validated_against_lab_scenario_log() {
    let mut harness = AtpPathLabHarness::new(AtpPathTestConfig::nat_stress());
    let scenario = AtpLabScenario::new("doctor-hard-nat-tcp-tls-failover", 0xA7F0_3001)
        .with_regime(AtpLabRegime::HardNat)
        .with_regime(AtpLabRegime::RelayTcpTls443)
        .with_regime(AtpLabRegime::RelayOnly);

    let result = harness
        .execute_scenario(&scenario)
        .await
        .expect("lab path scenario");

    assert_eq!(
        result.path_validation.selected_path_kind,
        Some(PathKind::AtpRelayTcpTls443)
    );
    assert_eq!(result.candidates_evaluated, 3);

    let race = path_race_from_lab_result(&result);
    let document = build_path_doctor_document("peer-redacted", &race);
    let json = serde_json::to_value(&document).expect("serialize path doctor");

    assert_eq!(json["schema_version"], ATP_PATH_DOCTOR_SCHEMA);
    assert_eq!(json["summary"]["candidate_count"], 3);
    assert_eq!(json["summary"]["failure_count"], 1);
    assert_eq!(json["summary"]["drained_loser_count"], 1);
    assert_eq!(json["summary"]["reason_code"], "relay_fallback_validated");
    assert_eq!(json["selected_path"]["kind"], "atp_relay_tcp_tls_443");
    assert_eq!(json["selected_path"]["family"], "relay");

    assert!(
        json["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .all(|candidate| {
                candidate["budget"]["connect_timeout_micros"]
                    .as_u64()
                    .unwrap()
                    > 0
                    && candidate["budget"]["loser_drain_timeout_micros"]
                        .as_u64()
                        .unwrap()
                        > 0
                    && candidate["security"]["authenticated_peer"] == true
                    && candidate["security"]["end_to_end_encrypted"] == true
            })
    );

    assert!(json["trace"].as_array().unwrap().iter().any(|entry| {
        entry["kind"] == "atp_relay_udp"
            && entry["state"] == "drained_loser"
            && entry["detail"]
                .as_str()
                .unwrap()
                .contains("lost to candidate 2")
    }));

    let human = render_path_doctor_human(&document);
    assert!(human.contains("Selected: candidate=2 kind=atp_relay_tcp_tls_443"));
    assert!(human.contains("Structured trace rows: 3"));
}

#[test]
fn path_doctor_identifies_udp_blocked_tcp_tls_443_fallback() {
    let race = udp_blocked_tcp_tls_fallback_race();
    let document = build_path_doctor_document("peer-redacted", &race);
    let json = serde_json::to_value(&document).unwrap();

    assert_eq!(json["summary"]["overall_health"], "degraded");
    assert_eq!(json["summary"]["reason_code"], "relay_fallback_validated");
    assert_eq!(json["summary"]["failure_count"], 1);
    assert_eq!(json["selected_path"]["kind"], "atp_relay_tcp_tls_443");
    assert_eq!(json["trace"][0]["outcome"], "failure_udp_blocked");

    let recommendation = &json["recommendations"][0];
    assert_eq!(recommendation["severity"], "warning");
    assert_eq!(recommendation["code"], "tcp_tls_443_fallback_selected");
    assert!(
        recommendation["message"]
            .as_str()
            .unwrap()
            .contains("head-of-line blocking")
    );

    let human = render_path_doctor_human(&document);
    assert!(human.contains("warning tcp_tls_443_fallback_selected"));
    assert!(human.contains("kind=atp_relay_tcp_tls_443"));
}

#[test]
fn tailscale_provider_is_optional_ranked_and_redacted_in_path_doctor() {
    let report = discover_direct_paths(
        PathDiscoveryPolicy::safe_default().with_tailscale_policy(TailscalePathPolicy::Prefer),
        PathDiscoveryInputs {
            explicit_direct_endpoint: Some("198.51.100.20:41641".to_string()),
            tailscale_candidates: vec![TailscaleCandidateObservation::new(
                socket("100.100.10.20:41641"),
                TailscaleDetectionSource::LabProvider,
                1_000,
            )],
            now_micros: 2_000,
            ..PathDiscoveryInputs::default()
        },
    );

    let doctor = report.doctor_report();
    let selected = doctor.selected.as_ref().expect("selected path");
    assert_eq!(selected.source, DirectCandidateSource::TailscaleProvider);
    assert_eq!(selected.kind, PathKind::TailscaleIp);
    assert_eq!(selected.endpoint_scope, "tailscale-ipv4:41641");
    assert_eq!(
        selected.evidence,
        "tailscale_lab_provider_candidate_validated"
    );
    assert!(
        doctor
            .guidance
            .contains(&"keep_native_direct_or_atp_relay_fallback_because_tailscale_is_optional")
    );
    assert!(
        doctor
            .candidates
            .iter()
            .all(|candidate| !candidate.endpoint_scope.contains("100.100.10.20"))
    );
}

#[test]
fn tailscale_policy_contract_distinguishes_absent_disabled_forbidden_and_stale() {
    let absent = discover_direct_paths(
        PathDiscoveryPolicy::safe_default(),
        PathDiscoveryInputs::default(),
    );
    assert!(absent.rejections.iter().any(|rejection| {
        rejection.source == DirectCandidateSource::TailscaleProvider
            && rejection.reason == DirectCandidateRejection::TailscaleNotPresent
    }));

    let candidate = TailscaleCandidateObservation::new(
        socket("100.100.10.20:41641"),
        TailscaleDetectionSource::StatusCommand,
        1_000,
    );
    let disabled = discover_direct_paths(
        PathDiscoveryPolicy::safe_default().with_tailscale_policy(TailscalePathPolicy::Disabled),
        PathDiscoveryInputs {
            tailscale_candidates: vec![candidate.clone()],
            now_micros: 2_000,
            ..PathDiscoveryInputs::default()
        },
    );
    assert!(disabled.rejections.iter().any(|rejection| {
        rejection.source == DirectCandidateSource::TailscaleProvider
            && rejection.reason == DirectCandidateRejection::PolicyDisabled
    }));

    let forbidden = discover_direct_paths(
        PathDiscoveryPolicy::safe_default().with_tailscale_policy(TailscalePathPolicy::Forbid),
        PathDiscoveryInputs {
            tailscale_candidates: vec![candidate.clone()],
            now_micros: 2_000,
            ..PathDiscoveryInputs::default()
        },
    );
    assert!(forbidden.rejections.iter().any(|rejection| {
        rejection.source == DirectCandidateSource::TailscaleProvider
            && rejection.reason == DirectCandidateRejection::PolicyForbidden
    }));

    let stale = discover_direct_paths(
        PathDiscoveryPolicy::safe_default()
            .with_tailscale_policy(TailscalePathPolicy::Allow)
            .with_tailscale_max_staleness_micros(10),
        PathDiscoveryInputs {
            tailscale_candidates: vec![candidate],
            now_micros: 1_011,
            ..PathDiscoveryInputs::default()
        },
    );
    assert!(stale.rejections.iter().any(|rejection| {
        rejection.source == DirectCandidateSource::TailscaleProvider
            && rejection.reason == DirectCandidateRejection::StaleCandidate
            && rejection.detail.contains("source=status_command")
            && !rejection.detail.contains("100.100.10.20")
    }));
}
