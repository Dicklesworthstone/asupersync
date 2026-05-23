//! ATP relay integration scenarios for ATP-F5.
//!
//! These tests exercise the real relay reservation and forwarding model rather
//! than mocks. They are intentionally deterministic so `scripts/run_atp_relay_e2e.sh`
//! can capture stable stage logs, proof metadata, and failure points.

use asupersync::atp::path::{
    PathAttemptState, PathCandidate, PathCandidateId, PathFailureKind, PathKind, PathOutcome,
    PathOutcomeResult, PathRace, PathSelectionReason, PathSuccessKind, PathTraceId,
};
use asupersync::net::atp::relay::{
    OpaqueRelayPacket, ProofTag, RelayError, RelayEventKind, RelayQuota, RelayReservationGrant,
    RelayReservationId, RelayService, RelayServiceConfig, RelayTransport, RelayWireFrame,
};
use asupersync::net::atp::rendezvous::{CandidateSignature, PeerId, TransferNonce};

fn log_stage(test: &str, stage: &str, detail: impl AsRef<str>) {
    println!(
        "atp_relay_e2e test={} stage={} detail={}",
        test,
        stage,
        detail.as_ref()
    );
}

fn peer(seed: u8) -> PeerId {
    PeerId::new([seed; 32]).expect("peer id")
}

fn nonce(raw: u128) -> TransferNonce {
    TransferNonce::new(raw).expect("transfer nonce")
}

fn reservation_id(raw: u128) -> RelayReservationId {
    RelayReservationId::new(raw).expect("reservation id")
}

fn signature() -> CandidateSignature {
    CandidateSignature::new(vec![0xa7, 0x50, 0xf5]).expect("signature")
}

fn grant(expires_at_micros: u64, quota: RelayQuota) -> RelayReservationGrant {
    RelayReservationGrant::udp_first_tcp_tls_443(
        peer(1),
        peer(2),
        nonce(0xfeed_f500),
        expires_at_micros,
        quota,
        signature(),
    )
    .expect("relay grant")
}

fn packet(transport: RelayTransport, payload: &[u8], sequence: u64) -> OpaqueRelayPacket {
    packet_sent_at(transport, payload, sequence, 1_000 + sequence)
}

fn packet_sent_at(
    transport: RelayTransport,
    payload: &[u8],
    sequence: u64,
    sent_at_micros: u64,
) -> OpaqueRelayPacket {
    OpaqueRelayPacket::new(
        sequence,
        transport,
        payload.to_vec(),
        ProofTag::new([0x5a; 32]).expect("proof tag"),
        sent_at_micros,
    )
    .expect("opaque relay packet")
}

#[test]
fn relay_only_locked_down_tcp_tls_fallback_produces_complete_proof_logs() {
    let test = "relay_only_locked_down_tcp_tls_fallback_produces_complete_proof_logs";
    let config = RelayServiceConfig::new("relay-f5-e2e", 8)
        .expect("config")
        .with_udp_enabled(false)
        .with_log_peer_ids(true);
    let mut service = RelayService::new(config);

    log_stage(
        test,
        "reserve",
        "udp disabled; tcp_tls_443 fallback must be selected",
    );
    let candidate = service
        .reserve(
            100,
            reservation_id(100),
            "relay-only-path",
            grant(10_000, RelayQuota::default()),
            &|grant: &RelayReservationGrant| grant.signature().bytes() == [0xa7, 0x50, 0xf5],
        )
        .expect("reserve relay-only path");
    assert_eq!(candidate.primary_transport(), RelayTransport::TcpTls443);
    assert_eq!(candidate.fallback_transport(), None);
    assert_eq!(candidate.relay_id(), "relay-f5-e2e");

    log_stage(
        test,
        "forward",
        "source sends encrypted payload through tcp_tls_443 relay",
    );
    let forwarded = service
        .forward(
            120,
            reservation_id(100),
            peer(1),
            packet_sent_at(RelayTransport::TcpTls443, b"encrypted-atp-frame", 1, 100),
        )
        .expect("forward over tcp fallback");
    assert_eq!(forwarded.to_peer_id(), peer(2));
    assert_eq!(forwarded.packet().transport(), RelayTransport::TcpTls443);
    assert_eq!(
        service.dequeue_for_peer(peer(2)).expect("receiver queue"),
        forwarded
    );

    log_stage(
        test,
        "loss",
        "record relay path loss summary without verifier trust",
    );
    let loss = service
        .record_packet_loss(reservation_id(100), 1, 64)
        .expect("loss summary");
    let proof = service
        .proof_artifact(reservation_id(100))
        .expect("proof artifact");

    assert_eq!(loss.loss_ppm, 15_625);
    assert_eq!(proof.relay_id, "relay-f5-e2e");
    assert_eq!(proof.path_id, "relay-only-path");
    assert_eq!(proof.opaque_bytes_forwarded, 19);
    assert_eq!(proof.packets_forwarded, 1);
    assert_eq!(proof.loss_summary, Some(loss));
    let latency = proof.latency_summary.expect("latency summary");
    assert_eq!(latency.sample_count, 1);
    assert_eq!(latency.latest_latency_micros, 20);
    assert_eq!(latency.min_latency_micros, 20);
    assert_eq!(latency.max_latency_micros, 20);
    assert_eq!(latency.average_latency_micros, 20);
    assert_eq!(proof.fallback_reason, Some("udp_unavailable_tcp_tls_443"));
    assert!(proof.e2e_proof_preserved);
    assert_eq!(proof.redacted_source_peer, "peer:0101...");

    log_stage(
        test,
        "events",
        "operator events include redacted ids and replay pointers",
    );
    assert!(service.events().iter().any(|event| {
        event.kind == RelayEventKind::PacketForwarded
            && event.relay_id == "relay-f5-e2e"
            && event.path_id.as_deref() == Some("relay-only-path")
            && event.fallback_reason == Some("udp_unavailable_tcp_tls_443")
            && event
                .latency_summary
                .is_some_and(|summary| summary.latest_latency_micros == 20)
            && event.replay_pointer > 0
    }));
    assert!(service.events().iter().any(|event| {
        event.kind == RelayEventKind::PacketLossRecorded
            && event.loss_summary == Some(loss)
            && event
                .latency_summary
                .is_some_and(|summary| summary.average_latency_micros == 20)
    }));
}

#[test]
fn relay_candidate_feeds_path_race_and_preserves_proof_evidence() {
    let test = "relay_candidate_feeds_path_race_and_preserves_proof_evidence";
    let config = RelayServiceConfig::new("relay-path-race-e2e", 4)
        .expect("config")
        .with_udp_enabled(false)
        .with_log_peer_ids(true);
    let mut service = RelayService::new(config);

    log_stage(
        test,
        "reserve",
        "tcp_tls_443 relay candidate is converted into shared path graph",
    );
    let relay_candidate = service
        .reserve(
            100,
            reservation_id(400),
            "relay-path-graph",
            grant(10_000, RelayQuota::default()),
            &|grant: &RelayReservationGrant| grant.signature().bytes() == [0xa7, 0x50, 0xf5],
        )
        .expect("reserve relay candidate");
    assert_eq!(relay_candidate.path_kind(), PathKind::AtpRelayTcpTls443);
    let relay_path =
        relay_candidate.to_path_candidate(PathCandidateId::new(40), PathTraceId::new(40_000));
    assert_eq!(relay_path.kind, PathKind::AtpRelayTcpTls443);
    assert!(relay_path.security.relay_metadata_visible);
    assert!(!relay_path.security.exposes_local_ip_to_peer);

    log_stage(
        test,
        "path-race",
        "direct path fails and relay path wins with structured loser state",
    );
    let direct_id = PathCandidateId::new(10);
    let relay_id = relay_path.id;
    let mut race = PathRace::new();
    race.add_candidate(PathCandidate::new(
        direct_id,
        PathKind::NatPunchedUdp,
        PathTraceId::new(10_000),
    ))
    .expect("direct candidate");
    race.add_candidate(relay_path).expect("relay candidate");
    race.start_all().expect("start path race");
    race.record_outcome(
        direct_id,
        PathOutcome::failure(PathFailureKind::UdpBlocked, 150),
    )
    .expect("record direct failure");

    let forwarded = service
        .forward(
            160,
            reservation_id(400),
            peer(1),
            packet_sent_at(
                RelayTransport::TcpTls443,
                b"encrypted-path-race-frame",
                1,
                140,
            ),
        )
        .expect("relay forward");
    assert_eq!(forwarded.to_peer_id(), peer(2));
    let proof = service
        .proof_artifact(reservation_id(400))
        .expect("relay proof");
    assert_eq!(
        proof
            .latency_summary
            .expect("path-race latency")
            .latest_latency_micros,
        20
    );
    let relay_outcome = proof.to_path_success_outcome(175, Some(25));
    race.record_outcome(relay_id, relay_outcome)
        .expect("record relay win");
    race.record_outcome(
        direct_id,
        PathOutcome::failure(PathFailureKind::Timeout, 180),
    )
    .expect("late direct failure is idempotent");
    race.record_outcome(
        relay_id,
        PathOutcome::failure(PathFailureKind::RelayUnavailable, 181),
    )
    .expect("late relay failure cannot overwrite selected success");

    let snapshot = race.diagnostic_snapshot();
    assert_eq!(race.winner(), Some(relay_id));
    assert_eq!(snapshot.reason, PathSelectionReason::RelayFallbackValidated);
    assert_eq!(snapshot.selected_kind, Some(PathKind::AtpRelayTcpTls443));
    assert_eq!(snapshot.relay_count, 1);
    assert_eq!(snapshot.failure_count, 1);
    assert_eq!(snapshot.success_count, 1);
    assert_eq!(snapshot.drained_loser_count, 0);
    assert!(matches!(
        race.candidate(direct_id).expect("direct state").state,
        PathAttemptState::Failed(outcome)
            if outcome.result == PathOutcomeResult::Failure(PathFailureKind::UdpBlocked)
    ));
    assert!(matches!(
        race.candidate(relay_id).expect("relay state").state,
        PathAttemptState::Succeeded(outcome)
            if outcome.result == PathOutcomeResult::Success(PathSuccessKind::RelaySelected)
                && outcome.bytes_sent == proof.opaque_bytes_forwarded
                && outcome.bytes_received == proof.opaque_bytes_forwarded
    ));
    assert_eq!(
        RelayError::InvalidAuthorization.path_failure_kind(),
        PathFailureKind::AuthFailure
    );
    assert_eq!(proof.fallback_reason, Some("udp_unavailable_tcp_tls_443"));
    assert!(proof.e2e_proof_preserved);
}

#[test]
fn relay_wire_frames_feed_udp_and_tcp_tls_fallback_without_trusting_plaintext() {
    let test = "relay_wire_frames_feed_udp_and_tcp_tls_fallback_without_trusting_plaintext";
    let mut udp_service = RelayService::new(
        RelayServiceConfig::new("relay-wire-udp", 4)
            .expect("udp config")
            .with_log_peer_ids(true),
    );

    log_stage(
        test,
        "udp-wire-frame",
        "encode canonical relay tunnel frame and submit through UDP relay model",
    );
    udp_service
        .reserve(
            100,
            reservation_id(500),
            "wire-udp-path",
            grant(10_000, RelayQuota::default()),
            &|_: &RelayReservationGrant| true,
        )
        .expect("reserve udp relay");
    let wrong_nonce_frame = RelayWireFrame::new(
        reservation_id(500),
        nonce(0xdead_beef),
        peer(1),
        packet_sent_at(RelayTransport::Udp, b"wrong-transfer", 9, 91),
    );
    assert_eq!(
        wrong_nonce_frame
            .forward_into(&mut udp_service, 126)
            .expect_err("wrong transfer nonce"),
        RelayError::InvalidAuthorization
    );
    assert!(udp_service.events().iter().any(|event| {
        event.kind == RelayEventKind::AuthorizationRejected
            && event.quota_decision == "transfer_nonce_mismatch_rejected"
            && event.opaque_bytes == 14
    }));

    let udp_frame = RelayWireFrame::new(
        reservation_id(500),
        nonce(0xfeed_f500),
        peer(1),
        packet_sent_at(RelayTransport::Udp, b"encrypted-wire-udp", 1, 90),
    );
    let udp_encoded = udp_frame
        .encode(RelayQuota::default().max_packet_bytes)
        .expect("encode udp wire frame");
    let udp_decoded = RelayWireFrame::decode(&udp_encoded, RelayQuota::default().max_packet_bytes)
        .expect("decode udp wire frame");
    let udp_forwarded = udp_decoded
        .forward_into(&mut udp_service, 125)
        .expect("forward decoded udp frame");
    assert_eq!(udp_forwarded.to_peer_id(), peer(2));
    assert_eq!(udp_forwarded.packet().opaque_bytes(), b"encrypted-wire-udp");
    let udp_proof = udp_service
        .proof_artifact(reservation_id(500))
        .expect("udp proof");
    assert_eq!(udp_proof.opaque_bytes_forwarded, 18);
    assert_eq!(udp_proof.fallback_reason, None);
    assert!(udp_proof.e2e_proof_preserved);

    log_stage(
        test,
        "tcp-tls-wire-frame",
        "same frame codec carries locked-down tcp_tls_443 fallback traffic",
    );
    let mut tcp_service = RelayService::new(
        RelayServiceConfig::new("relay-wire-tcp", 4)
            .expect("tcp config")
            .with_udp_enabled(false)
            .with_log_peer_ids(true),
    );
    tcp_service
        .reserve(
            200,
            reservation_id(501),
            "wire-tcp-path",
            grant(10_000, RelayQuota::default()),
            &|_: &RelayReservationGrant| true,
        )
        .expect("reserve tcp fallback relay");
    let tcp_frame = RelayWireFrame::new(
        reservation_id(501),
        nonce(0xfeed_f500),
        peer(1),
        packet_sent_at(
            RelayTransport::TcpTls443,
            b"encrypted-wire-tcp-fallback",
            1,
            205,
        ),
    );
    let tcp_encoded = tcp_frame
        .encode(RelayQuota::default().max_packet_bytes)
        .expect("encode tcp wire frame");
    assert_ne!(
        udp_encoded, tcp_encoded,
        "transport and reservation metadata must be encoded deterministically"
    );
    let tcp_decoded = RelayWireFrame::decode(&tcp_encoded, RelayQuota::default().max_packet_bytes)
        .expect("decode tcp wire frame");
    let tcp_forwarded = tcp_decoded
        .forward_into(&mut tcp_service, 240)
        .expect("forward decoded tcp frame");
    assert_eq!(
        tcp_forwarded.packet().transport(),
        RelayTransport::TcpTls443
    );
    assert_eq!(
        tcp_forwarded.packet().opaque_bytes(),
        b"encrypted-wire-tcp-fallback"
    );
    let tcp_proof = tcp_service
        .proof_artifact(reservation_id(501))
        .expect("tcp proof");
    assert_eq!(
        tcp_proof.fallback_reason,
        Some("udp_unavailable_tcp_tls_443")
    );
    assert_eq!(
        tcp_proof
            .latency_summary
            .expect("tcp latency")
            .latest_latency_micros,
        35
    );
    assert!(tcp_service.events().iter().any(|event| {
        event.kind == RelayEventKind::PacketForwarded
            && event.transport == Some(RelayTransport::TcpTls443)
            && event.fallback_reason == Some("udp_unavailable_tcp_tls_443")
            && event.quota_decision == "packet_accepted"
    }));
}

#[test]
fn relay_restart_sender_disconnect_and_mailbox_boundary_are_deterministic() {
    let test = "relay_restart_sender_disconnect_and_mailbox_boundary_are_deterministic";
    let mut service = RelayService::new(RelayServiceConfig::default());

    log_stage(test, "reserve", "accept active relay reservation");
    service
        .reserve(
            100,
            reservation_id(200),
            "restart-path",
            grant(10_000, RelayQuota::default()),
            &|_: &RelayReservationGrant| true,
        )
        .expect("reserve");
    let first = service
        .forward(
            110,
            reservation_id(200),
            peer(1),
            packet(RelayTransport::Udp, b"before-restart", 1),
        )
        .expect("forward before restart");

    log_stage(
        test,
        "restart",
        "snapshot retains active relay queue but no plaintext",
    );
    let snapshot = service.snapshot();
    assert_eq!(snapshot.reservation_count(), 1);
    let mut restored = RelayService::restore(snapshot);
    assert_eq!(restored.dequeue_for_peer(peer(2)), Some(first));
    assert!(
        restored
            .events()
            .iter()
            .any(|event| event.kind == RelayEventKind::RestartRestored)
    );

    log_stage(
        test,
        "disconnect",
        "structured cancellation drains relay queues",
    );
    restored
        .forward(
            120,
            reservation_id(200),
            peer(1),
            packet(RelayTransport::Udp, b"queued-for-drain", 2),
        )
        .expect("queued before sender disconnect");
    restored
        .cancel_reservation(reservation_id(200))
        .expect("cancel reservation");
    assert_eq!(restored.dequeue_for_peer(peer(2)), None);
    assert_eq!(
        restored
            .record_packet_loss(reservation_id(200), 1, 2)
            .expect_err("terminal relay rejects post-cancel loss"),
        RelayError::ReservationCancelled
    );

    log_stage(
        test,
        "mailbox-boundary",
        "relay restart snapshot does not retain terminal state",
    );
    let terminal_snapshot = restored.snapshot();
    assert_eq!(terminal_snapshot.reservation_count(), 0);
    let post_cancel_restore = RelayService::restore(terminal_snapshot);
    assert_eq!(
        post_cancel_restore
            .proof_artifact(reservation_id(200))
            .expect_err("cancelled relay state is not mailbox storage"),
        RelayError::UnknownReservation
    );
}

#[test]
fn relay_auth_expiry_and_capacity_oracles_are_fail_closed() {
    let test = "relay_auth_expiry_and_capacity_oracles_are_fail_closed";
    let config = RelayServiceConfig::new("tiny-relay", 1).expect("config");
    let mut service = RelayService::new(config);

    log_stage(
        test,
        "auth",
        "invalid expired grant returns auth failure before expiry",
    );
    assert_eq!(
        service
            .reserve(
                500,
                reservation_id(300),
                "invalid-expired",
                grant(100, RelayQuota::default()),
                &|_: &RelayReservationGrant| false,
            )
            .expect_err("invalid expired grant"),
        RelayError::InvalidAuthorization
    );
    assert!(service.events().iter().any(|event| {
        event.kind == RelayEventKind::AuthorizationRejected
            && event.reservation_id == Some(reservation_id(300))
            && event.quota_decision == "grant_authorization_rejected"
    }));

    log_stage(
        test,
        "capacity",
        "new reserve sweeps stale expired state before quota check",
    );
    service
        .reserve(
            10,
            reservation_id(301),
            "stale-before-capacity",
            grant(20, RelayQuota::default()),
            &|_: &RelayReservationGrant| true,
        )
        .expect("first reservation");
    let candidate = service
        .reserve(
            30,
            reservation_id(302),
            "active-after-sweep",
            grant(1_000, RelayQuota::default()),
            &|_: &RelayReservationGrant| true,
        )
        .expect("stale reservation should be terminalized before capacity");
    assert_eq!(candidate.reservation_id(), reservation_id(302));
    assert_eq!(service.snapshot().reservation_count(), 1);

    log_stage(
        test,
        "restart",
        "stale expired reservation cannot revive through snapshot",
    );
    let restored = RelayService::restore(service.snapshot());
    assert_eq!(
        restored
            .proof_artifact(reservation_id(301))
            .expect_err("expired state is not retained"),
        RelayError::UnknownReservation
    );
    assert!(
        restored.proof_artifact(reservation_id(302)).is_ok(),
        "new active reservation survives restart"
    );
}
