//! ATP path doctor JSON and trace contract tests.

use asupersync::atp::path::{
    PathCandidate, PathCandidateId, PathFailureKind, PathKind, PathOutcome, PathRace,
    PathSuccessKind, PathTraceId,
};
use asupersync::atp::{
    ATP_PATH_DOCTOR_SCHEMA, ATP_PATH_TRACE_ATTEMPT_SCHEMA, build_path_doctor_document,
    render_path_doctor_human,
};

fn path_candidate(raw: u64, kind: PathKind) -> PathCandidate {
    PathCandidate::new(
        PathCandidateId::new(raw),
        kind,
        PathTraceId::new(90_000 + raw),
    )
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
