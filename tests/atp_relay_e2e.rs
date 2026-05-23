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
    RelayReservationId, RelayService, RelayServiceConfig, RelayTcpTlsStreamBuffer, RelayTransport,
    RelayWireFrame,
};
use asupersync::net::atp::rendezvous::{CandidateSignature, PeerId, TransferNonce};
use std::net::SocketAddr;

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
    assert_eq!(
        udp_frame
            .encode_tcp_tls_record(RelayQuota::default().max_packet_bytes)
            .expect_err("tcp stream record must not carry udp transport"),
        RelayError::InvalidRelayWireFrame
    );
    let udp_record_len = u32::try_from(udp_encoded.len()).expect("udp frame len fits in u32");
    let mut udp_inside_tcp_record = Vec::with_capacity(4 + udp_encoded.len());
    udp_inside_tcp_record.extend_from_slice(&udp_record_len.to_be_bytes());
    udp_inside_tcp_record.extend_from_slice(&udp_encoded);
    assert_eq!(
        RelayWireFrame::decode_tcp_tls_record(
            &udp_inside_tcp_record,
            RelayQuota::default().max_packet_bytes,
        )
        .expect_err("tcp stream decoder must reject udp transport"),
        RelayError::InvalidRelayWireFrame
    );
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
    let tcp_record = tcp_frame
        .encode_tcp_tls_record(RelayQuota::default().max_packet_bytes)
        .expect("encode tcp wire record");
    assert_ne!(
        udp_encoded, tcp_record,
        "transport and reservation metadata must be encoded deterministically"
    );
    let followup_frame = RelayWireFrame::new(
        reservation_id(501),
        nonce(0xfeed_f500),
        peer(1),
        packet_sent_at(
            RelayTransport::TcpTls443,
            b"encrypted-wire-tcp-followup",
            2,
            250,
        ),
    );
    let followup_record = followup_frame
        .encode_tcp_tls_record(RelayQuota::default().max_packet_bytes)
        .expect("encode follow-up tcp wire record");
    let mut tcp_stream = tcp_record.clone();
    tcp_stream.extend_from_slice(&followup_record);
    let mut tcp_stream_buffer = RelayTcpTlsStreamBuffer::new(
        RelayQuota::default().max_packet_bytes,
        tcp_record.len().max(followup_record.len()),
    )
    .expect("bounded TCP/TLS stream buffer");
    let partial_forwarded = tcp_service
        .forward_tcp_tls_stream_bytes(300, peer(1), &mut tcp_stream_buffer, &tcp_stream[..2])
        .expect("partial tcp stream prefix is buffered");
    assert!(partial_forwarded.is_empty());
    assert_eq!(tcp_stream_buffer.pending_len(), 2);
    let forwarded_batch = tcp_service
        .forward_tcp_tls_stream_bytes(300, peer(1), &mut tcp_stream_buffer, &tcp_stream[2..])
        .expect("coalesced tcp stream records are forwarded");
    assert_eq!(forwarded_batch.len(), 2);
    assert_eq!(tcp_stream_buffer.pending_len(), 0);
    let tcp_forwarded = &forwarded_batch[0];
    assert_eq!(
        tcp_forwarded.packet().transport(),
        RelayTransport::TcpTls443
    );
    assert_eq!(
        tcp_forwarded.packet().opaque_bytes(),
        b"encrypted-wire-tcp-fallback"
    );
    let followup_forwarded = &forwarded_batch[1];
    assert_eq!(followup_forwarded.to_peer_id(), peer(2));
    assert_eq!(
        followup_forwarded.packet().opaque_bytes(),
        b"encrypted-wire-tcp-followup"
    );
    let packet_count_before_undersized = tcp_service
        .proof_artifact(reservation_id(501))
        .expect("tcp proof before undersized stream")
        .packets_forwarded;
    let mut undersized_stream_buffer =
        RelayTcpTlsStreamBuffer::new(RelayQuota::default().max_packet_bytes, tcp_record.len() - 1)
            .expect("undersized stream buffer still accepts relay header");
    assert_eq!(
        tcp_service
            .forward_tcp_tls_stream_bytes(325, peer(1), &mut undersized_stream_buffer, &tcp_record)
            .expect_err("record larger than pending buffer fails closed"),
        RelayError::PacketTooLarge
    );
    assert_eq!(
        tcp_service
            .proof_artifact(reservation_id(501))
            .expect("tcp proof after undersized stream")
            .packets_forwarded,
        packet_count_before_undersized
    );
    let tcp_proof = tcp_service
        .proof_artifact(reservation_id(501))
        .expect("tcp proof");
    assert_eq!(
        tcp_proof.fallback_reason,
        Some("udp_unavailable_tcp_tls_443")
    );
    assert_eq!(
        tcp_proof.opaque_bytes_forwarded,
        u64::try_from(b"encrypted-wire-tcp-fallback".len() + b"encrypted-wire-tcp-followup".len())
            .expect("expected tcp proof byte count fits in u64")
    );
    assert_eq!(tcp_proof.packets_forwarded, 2);
    assert_eq!(
        tcp_proof
            .latency_summary
            .expect("tcp latency")
            .latest_latency_micros,
        50
    );
    assert!(tcp_service.events().iter().any(|event| {
        event.kind == RelayEventKind::PacketForwarded
            && event.transport == Some(RelayTransport::TcpTls443)
            && event.fallback_reason == Some("udp_unavailable_tcp_tls_443")
            && event.quota_decision == "packet_accepted"
    }));
}

#[test]
fn relay_socket_adapters_bridge_udp_datagrams_and_tcp_records() {
    let test = "relay_socket_adapters_bridge_udp_datagrams_and_tcp_records";
    let mut udp_service = RelayService::new(
        RelayServiceConfig::new("relay-socket-udp", 4)
            .expect("udp config")
            .with_log_peer_ids(true),
    );

    log_stage(
        test,
        "udp-ingress",
        "socket datagram bytes enter the canonical relay forwarding path",
    );
    udp_service
        .reserve(
            100,
            reservation_id(700),
            "socket-udp-path",
            grant(10_000, RelayQuota::default()),
            &|_: &RelayReservationGrant| true,
        )
        .expect("reserve udp socket relay");
    let udp_frame = RelayWireFrame::new(
        reservation_id(700),
        nonce(0xfeed_f500),
        peer(1),
        packet_sent_at(RelayTransport::Udp, b"socket-udp-ciphertext", 1, 175),
    );
    let udp_datagram_bytes = udp_frame
        .encode(RelayQuota::default().max_packet_bytes)
        .expect("encode inbound udp datagram");
    log_stage(
        test,
        "udp-peer-mismatch",
        "socket endpoint identity must match the datagram's relay frame source peer",
    );
    assert_eq!(
        udp_service
            .forward_udp_datagram(
                199,
                peer(3),
                &udp_datagram_bytes,
                RelayQuota::default().max_packet_bytes,
            )
            .expect_err("udp endpoint peer mismatch must fail closed"),
        RelayError::UnauthorizedPeer
    );
    assert_eq!(
        udp_service
            .proof_artifact(reservation_id(700))
            .expect("udp proof after rejected peer mismatch")
            .packets_forwarded,
        0
    );
    assert!(udp_service.events().iter().any(|event| {
        event.kind == RelayEventKind::AuthorizationRejected
            && event.transport == Some(RelayTransport::Udp)
            && event.quota_decision == "endpoint_peer_mismatch_rejected"
    }));
    let udp_forwarded = udp_service
        .forward_udp_datagram(
            200,
            peer(1),
            &udp_datagram_bytes,
            RelayQuota::default().max_packet_bytes,
        )
        .expect("forward inbound udp datagram");
    assert_eq!(udp_forwarded.to_peer_id(), peer(2));

    log_stage(
        test,
        "udp-egress",
        "queued relay packet encodes as a UDP datagram for the peer directory endpoint",
    );
    let dst_addr = SocketAddr::from(([127, 0, 0, 1], 47_000));
    let udp_egress = udp_service
        .dequeue_udp_datagram_for_peer(peer(2), dst_addr, RelayQuota::default().max_packet_bytes)
        .expect("encode outbound udp datagram")
        .expect("queued udp egress packet");
    assert_eq!(udp_egress.dst_addr(), dst_addr);
    assert_eq!(udp_egress.to_peer_id(), peer(2));
    assert_eq!(
        udp_egress.opaque_bytes(),
        u64::try_from(b"socket-udp-ciphertext".len()).expect("ciphertext len fits in u64")
    );
    let decoded_udp =
        RelayWireFrame::decode(udp_egress.payload(), RelayQuota::default().max_packet_bytes)
            .expect("decode outbound udp datagram");
    assert_eq!(decoded_udp.from_peer_id(), peer(1));
    assert_eq!(decoded_udp.packet().transport(), RelayTransport::Udp);
    assert_eq!(
        decoded_udp.packet().opaque_bytes(),
        b"socket-udp-ciphertext"
    );
    assert!(
        udp_service
            .events()
            .iter()
            .any(|event| event.kind == RelayEventKind::PacketForwarded
                && event.transport == Some(RelayTransport::Udp)
                && event.quota_decision == "packet_accepted")
    );

    log_stage(
        test,
        "tcp-egress",
        "tcp/tls stream bytes retain ordering until the tcp writer drains the record",
    );
    let mut tcp_service = RelayService::new(
        RelayServiceConfig::new("relay-socket-tcp", 4)
            .expect("tcp config")
            .with_udp_enabled(false)
            .with_log_peer_ids(true),
    );
    tcp_service
        .reserve(
            300,
            reservation_id(701),
            "socket-tcp-path",
            grant(10_000, RelayQuota::default()),
            &|_: &RelayReservationGrant| true,
        )
        .expect("reserve tcp socket relay");
    let tcp_frame = RelayWireFrame::new(
        reservation_id(701),
        nonce(0xfeed_f500),
        peer(1),
        packet_sent_at(RelayTransport::TcpTls443, b"socket-tcp-ciphertext", 2, 310),
    );
    let tcp_record_bytes = tcp_frame
        .encode_tcp_tls_record(RelayQuota::default().max_packet_bytes)
        .expect("encode inbound tcp record");
    log_stage(
        test,
        "tcp-peer-mismatch",
        "tcp/tls endpoint identity must match each stream record's relay frame source peer",
    );
    let mut rejected_stream = RelayTcpTlsStreamBuffer::new(
        RelayQuota::default().max_packet_bytes,
        tcp_record_bytes.len(),
    )
    .expect("rejected tcp stream buffer");
    assert_eq!(
        tcp_service
            .forward_tcp_tls_stream_bytes(349, peer(3), &mut rejected_stream, &tcp_record_bytes)
            .expect_err("tcp endpoint peer mismatch must fail closed"),
        RelayError::UnauthorizedPeer
    );
    assert_eq!(
        tcp_service
            .proof_artifact(reservation_id(701))
            .expect("tcp proof after rejected peer mismatch")
            .packets_forwarded,
        0
    );
    assert!(tcp_service.events().iter().any(|event| {
        event.kind == RelayEventKind::AuthorizationRejected
            && event.transport == Some(RelayTransport::TcpTls443)
            && event.quota_decision == "endpoint_peer_mismatch_rejected"
    }));
    let mut stream = RelayTcpTlsStreamBuffer::new(
        RelayQuota::default().max_packet_bytes,
        tcp_record_bytes.len(),
    )
    .expect("tcp stream buffer");
    let tcp_forwarded = tcp_service
        .forward_tcp_tls_stream_bytes(350, peer(1), &mut stream, &tcp_record_bytes)
        .expect("forward inbound tcp record");
    assert_eq!(tcp_forwarded.len(), 1);
    assert!(
        tcp_service
            .dequeue_udp_datagram_for_peer(
                peer(2),
                dst_addr,
                RelayQuota::default().max_packet_bytes
            )
            .expect("udp egress must preserve tcp queue front")
            .is_none(),
        "wrong writer must not consume tcp/tls queued packets"
    );
    let tcp_record = tcp_service
        .dequeue_tcp_tls_record_for_peer(peer(2), RelayQuota::default().max_packet_bytes)
        .expect("encode outbound tcp record")
        .expect("queued tcp egress packet");
    assert_eq!(tcp_record.to_peer_id(), peer(2));
    assert_eq!(
        tcp_record.opaque_bytes(),
        u64::try_from(b"socket-tcp-ciphertext".len()).expect("ciphertext len fits in u64")
    );
    let decoded_tcp = RelayWireFrame::decode_complete_tcp_tls_record(
        tcp_record.bytes(),
        RelayQuota::default().max_packet_bytes,
    )
    .expect("decode outbound tcp record");
    assert_eq!(decoded_tcp.from_peer_id(), peer(1));
    assert_eq!(decoded_tcp.packet().transport(), RelayTransport::TcpTls443);
    assert_eq!(
        decoded_tcp.packet().opaque_bytes(),
        b"socket-tcp-ciphertext"
    );
    let tcp_proof = tcp_service
        .proof_artifact(reservation_id(701))
        .expect("tcp proof");
    assert_eq!(
        tcp_proof.fallback_reason,
        Some("udp_unavailable_tcp_tls_443")
    );
    assert!(tcp_proof.e2e_proof_preserved);
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
