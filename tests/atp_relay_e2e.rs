//! ATP relay integration scenarios for ATP-F5.
//!
//! These tests exercise the real relay reservation and forwarding model rather
//! than mocks. They are intentionally deterministic so `scripts/run_atp_relay_e2e.sh`
//! can capture stable stage logs, proof metadata, and failure points.

use asupersync::net::atp::relay::{
    OpaqueRelayPacket, ProofTag, RelayError, RelayEventKind, RelayQuota, RelayReservationGrant,
    RelayReservationId, RelayService, RelayServiceConfig, RelayTransport,
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
    OpaqueRelayPacket::new(
        sequence,
        transport,
        payload.to_vec(),
        ProofTag::new([0x5a; 32]).expect("proof tag"),
        1_000 + sequence,
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
            packet(RelayTransport::TcpTls443, b"encrypted-atp-frame", 1),
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
            && event.replay_pointer > 0
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
