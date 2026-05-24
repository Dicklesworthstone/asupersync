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
    OpaqueRelayPacket, ProofTag, RelayEndpointDirectory, RelayEndpointDirectoryQuota, RelayError,
    RelayEventKind, RelayQuota, RelayReservationGrant, RelayReservationId, RelayService,
    RelayServiceConfig, RelaySocketIoError, RelaySocketLoop, RelayTcpTlsStreamBuffer,
    RelayTcpTlsStreamId, RelayTransport, RelayWireFrame,
};
use asupersync::net::atp::rendezvous::{CandidateSignature, PeerId, TransferNonce};
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::time::Duration;

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
fn relay_endpoint_directory_admits_socket_sources_before_forwarding() {
    let test = "relay_endpoint_directory_admits_socket_sources_before_forwarding";
    let mut service = RelayService::new(
        RelayServiceConfig::new("relay-endpoint-directory-e2e", 4)
            .expect("config")
            .with_log_peer_ids(true),
    );
    service
        .reserve(
            400,
            reservation_id(702),
            "endpoint-directory-path",
            grant(10_000, RelayQuota::default()),
            &|_: &RelayReservationGrant| true,
        )
        .expect("reserve endpoint directory relay");
    let mut directory = RelayEndpointDirectory::default();
    let source_udp = SocketAddr::from(([203, 0, 113, 21], 47_021));
    let wrong_udp = SocketAddr::from(([203, 0, 113, 22], 47_022));
    let source_stream = RelayTcpTlsStreamId::new(702).expect("source stream id");
    let wrong_stream = RelayTcpTlsStreamId::new(703).expect("wrong stream id");

    log_stage(
        test,
        "admit",
        "bind UDP endpoints and TCP/TLS stream ids to authenticated peer ids",
    );
    directory
        .bind_udp_endpoint(peer(1), source_udp)
        .expect("bind source udp endpoint");
    directory
        .bind_udp_endpoint(peer(3), wrong_udp)
        .expect("bind wrong udp endpoint");
    directory
        .bind_tcp_tls_stream(peer(1), source_stream)
        .expect("bind source tcp stream");
    directory
        .bind_tcp_tls_stream(peer(3), wrong_stream)
        .expect("bind wrong tcp stream");
    assert_eq!(directory.udp_endpoint_count(), 2);
    assert_eq!(directory.tcp_tls_stream_count(), 2);
    assert_eq!(
        directory
            .first_udp_endpoint_for_peer(peer(1))
            .expect("first source udp endpoint"),
        source_udp
    );

    let udp_frame = RelayWireFrame::new(
        reservation_id(702),
        nonce(0xfeed_f500),
        peer(1),
        packet_sent_at(RelayTransport::Udp, b"endpoint-udp-ciphertext", 1, 425),
    );
    let udp_datagram = udp_frame
        .encode(RelayQuota::default().max_packet_bytes)
        .expect("encode udp datagram");
    log_stage(
        test,
        "udp-unknown",
        "unadmitted UDP addresses fail before frame metadata can affect relay state",
    );
    assert_eq!(
        service
            .forward_udp_datagram_from_endpoint(
                430,
                &directory,
                SocketAddr::from(([203, 0, 113, 99], 47_099)),
                &udp_datagram,
                RelayQuota::default().max_packet_bytes,
            )
            .expect_err("unknown udp endpoint"),
        RelayError::UnknownRelayEndpoint
    );
    assert_eq!(
        service
            .proof_artifact(reservation_id(702))
            .expect("proof after unknown udp")
            .packets_forwarded,
        0
    );

    log_stage(
        test,
        "udp-mismatch",
        "admitted endpoint peer must match decoded frame source peer",
    );
    assert_eq!(
        service
            .forward_udp_datagram_from_endpoint(
                431,
                &directory,
                wrong_udp,
                &udp_datagram,
                RelayQuota::default().max_packet_bytes,
            )
            .expect_err("mismatched udp endpoint"),
        RelayError::UnauthorizedPeer
    );
    assert!(service.events().iter().any(|event| {
        event.kind == RelayEventKind::AuthorizationRejected
            && event.transport == Some(RelayTransport::Udp)
            && event.quota_decision == "endpoint_peer_mismatch_rejected"
    }));

    log_stage(
        test,
        "udp-forward",
        "admitted UDP endpoint forwards through normal proof and queue path",
    );
    let udp_forwarded = service
        .forward_udp_datagram_from_endpoint(
            432,
            &directory,
            source_udp,
            &udp_datagram,
            RelayQuota::default().max_packet_bytes,
        )
        .expect("forward admitted udp endpoint");
    assert_eq!(udp_forwarded.to_peer_id(), peer(2));

    let tcp_frame = RelayWireFrame::new(
        reservation_id(702),
        nonce(0xfeed_f500),
        peer(1),
        packet_sent_at(
            RelayTransport::TcpTls443,
            b"endpoint-tcp-ciphertext",
            2,
            440,
        ),
    );
    let tcp_record = tcp_frame
        .encode_tcp_tls_record(RelayQuota::default().max_packet_bytes)
        .expect("encode tcp record");
    log_stage(
        test,
        "tcp-unknown",
        "unadmitted TCP/TLS stream ids fail before bytes enter the stream decoder",
    );
    let mut unknown_stream =
        RelayTcpTlsStreamBuffer::new(RelayQuota::default().max_packet_bytes, tcp_record.len())
            .expect("unknown stream buffer");
    assert_eq!(
        service
            .forward_tcp_tls_stream_bytes_from_endpoint(
                450,
                &directory,
                RelayTcpTlsStreamId::new(704).expect("unknown stream id"),
                &mut unknown_stream,
                &tcp_record,
            )
            .expect_err("unknown tcp stream"),
        RelayError::UnknownRelayEndpoint
    );
    assert_eq!(unknown_stream.pending_len(), 0);

    log_stage(
        test,
        "tcp-mismatch",
        "admitted TCP/TLS stream peer must match decoded frame source peer",
    );
    let mut wrong_stream_buffer =
        RelayTcpTlsStreamBuffer::new(RelayQuota::default().max_packet_bytes, tcp_record.len())
            .expect("wrong stream buffer");
    assert_eq!(
        service
            .forward_tcp_tls_stream_bytes_from_endpoint(
                451,
                &directory,
                wrong_stream,
                &mut wrong_stream_buffer,
                &tcp_record,
            )
            .expect_err("mismatched tcp stream"),
        RelayError::UnauthorizedPeer
    );
    assert!(service.events().iter().any(|event| {
        event.kind == RelayEventKind::AuthorizationRejected
            && event.transport == Some(RelayTransport::TcpTls443)
            && event.quota_decision == "endpoint_peer_mismatch_rejected"
    }));

    log_stage(
        test,
        "tcp-forward",
        "admitted TCP/TLS stream forwards through normal proof and queue path",
    );
    let mut source_stream_buffer =
        RelayTcpTlsStreamBuffer::new(RelayQuota::default().max_packet_bytes, tcp_record.len())
            .expect("source stream buffer");
    let tcp_forwarded = service
        .forward_tcp_tls_stream_bytes_from_endpoint(
            452,
            &directory,
            source_stream,
            &mut source_stream_buffer,
            &tcp_record,
        )
        .expect("forward admitted tcp stream");
    assert_eq!(tcp_forwarded.len(), 1);
    assert_eq!(tcp_forwarded[0].to_peer_id(), peer(2));

    let proof = service
        .proof_artifact(reservation_id(702))
        .expect("endpoint proof");
    assert_eq!(proof.packets_forwarded, 2);
    assert_eq!(
        proof.opaque_bytes_forwarded,
        u64::try_from(b"endpoint-udp-ciphertext".len() + b"endpoint-tcp-ciphertext".len())
            .expect("ciphertext lengths fit")
    );
    assert!(proof.e2e_proof_preserved);
    assert_eq!(
        service
            .dequeue_for_peer(peer(2))
            .expect("first queued packet"),
        udp_forwarded
    );
    assert_eq!(
        service
            .dequeue_for_peer(peer(2))
            .expect("second queued packet"),
        tcp_forwarded[0]
    );
}

#[test]
fn relay_socket_loop_runs_udp_and_tcp_boundaries_with_detailed_logs() {
    let test = "relay_socket_loop_runs_udp_and_tcp_boundaries_with_detailed_logs";
    let mut service = RelayService::new(
        RelayServiceConfig::new("relay-socket-loop-e2e", 4)
            .expect("config")
            .with_log_peer_ids(true),
    );
    log_stage(
        test,
        "reserve",
        "accept a relay reservation that can race udp and tcp/tls 443 fallback",
    );
    service
        .reserve(
            500,
            reservation_id(703),
            "socket-loop-path",
            grant(10_000, RelayQuota::default()),
            &|_: &RelayReservationGrant| true,
        )
        .expect("reserve socket-loop relay");

    let mut socket_loop = RelaySocketLoop::new(
        RelayEndpointDirectoryQuota {
            max_udp_endpoints: 4,
            max_tcp_tls_streams: 4,
        },
        RelayQuota::default().max_packet_bytes,
        1024,
    )
    .expect("socket loop");
    let source_udp = SocketAddr::from(([203, 0, 113, 31], 47_031));
    let destination_udp = SocketAddr::from(([203, 0, 113, 32], 47_032));
    let migrated_destination_udp = SocketAddr::from(([203, 0, 113, 33], 47_033));
    let source_stream = RelayTcpTlsStreamId::new(731).expect("source stream");
    let destination_stream = RelayTcpTlsStreamId::new(732).expect("destination stream");
    let migrated_destination_stream =
        RelayTcpTlsStreamId::new(734).expect("migrated destination stream");
    let unknown_stream = RelayTcpTlsStreamId::new(733).expect("unknown stream");

    log_stage(
        test,
        "admit",
        "bind concrete socket endpoints to authenticated peers before bytes are decoded",
    );
    socket_loop
        .admit_udp_endpoint(peer(1), source_udp)
        .expect("admit source udp");
    socket_loop
        .admit_udp_endpoint(peer(2), destination_udp)
        .expect("admit destination udp");
    socket_loop
        .admit_udp_endpoint(peer(2), migrated_destination_udp)
        .expect("admit migrated destination udp");
    socket_loop
        .admit_tcp_tls_stream(peer(1), source_stream)
        .expect("admit source tcp");
    socket_loop
        .admit_tcp_tls_stream(peer(2), destination_stream)
        .expect("admit destination tcp");
    socket_loop
        .admit_tcp_tls_stream(peer(2), migrated_destination_stream)
        .expect("admit migrated destination tcp");

    log_stage(
        test,
        "unknown-ingress",
        "unadmitted UDP addresses and TCP/TLS streams fail before malformed bytes are decoded",
    );
    assert_eq!(
        socket_loop
            .ingest_udp_datagram(
                &mut service,
                505,
                SocketAddr::from(([203, 0, 113, 99], 47_099)),
                b"not-a-relay-frame",
            )
            .expect_err("unknown udp source is rejected before decode"),
        RelayError::UnknownRelayEndpoint
    );
    assert_eq!(
        socket_loop
            .ingest_tcp_tls_stream_bytes(&mut service, 506, unknown_stream, b"not-a-record")
            .expect_err("unknown tcp stream is rejected before buffering"),
        RelayError::UnknownRelayEndpoint
    );
    assert_eq!(socket_loop.tcp_tls_stream_buffer_count(), 3);
    assert_eq!(
        service
            .proof_artifact(reservation_id(703))
            .expect("proof after unknown ingress")
            .packets_forwarded,
        0
    );

    let udp_frame = RelayWireFrame::new(
        reservation_id(703),
        nonce(0xfeed_f500),
        peer(1),
        packet_sent_at(RelayTransport::Udp, b"loop-e2e-udp-ciphertext", 1, 510),
    );
    let udp_datagram = udp_frame
        .encode(RelayQuota::default().max_packet_bytes)
        .expect("encode udp datagram");
    log_stage(
        test,
        "udp-ingress",
        "udp socket reads are resolved through endpoint admission before relay forwarding",
    );
    let udp_forwarded = socket_loop
        .ingest_udp_datagram(&mut service, 520, source_udp, &udp_datagram)
        .expect("ingest udp datagram");
    assert_eq!(udp_forwarded.to_peer_id(), peer(2));
    assert_eq!(
        service
            .proof_artifact(reservation_id(703))
            .expect("udp proof")
            .packets_forwarded,
        1
    );

    log_stage(
        test,
        "udp-egress",
        "udp writer resolves destination endpoint before consuming queued packets",
    );
    let udp_write = socket_loop
        .drain_udp_datagram_for_peer(&mut service, peer(2))
        .expect("drain udp")
        .expect("udp write");
    assert_eq!(udp_write.dst_addr(), migrated_destination_udp);
    let decoded_udp =
        RelayWireFrame::decode(udp_write.payload(), RelayQuota::default().max_packet_bytes)
            .expect("decode udp write");
    assert_eq!(decoded_udp.from_peer_id(), peer(1));
    assert_eq!(
        decoded_udp.packet().opaque_bytes(),
        b"loop-e2e-udp-ciphertext"
    );

    let tcp_frame = RelayWireFrame::new(
        reservation_id(703),
        nonce(0xfeed_f500),
        peer(1),
        packet_sent_at(
            RelayTransport::TcpTls443,
            b"loop-e2e-tcp-ciphertext",
            2,
            530,
        ),
    );
    let tcp_record = tcp_frame
        .encode_tcp_tls_record(RelayQuota::default().max_packet_bytes)
        .expect("encode tcp record");
    log_stage(
        test,
        "tcp-partial-read",
        "tcp/tls reads retain incomplete records and forward once the record completes",
    );
    assert_eq!(
        socket_loop
            .ingest_tcp_tls_stream_bytes(&mut service, 540, source_stream, &tcp_record[..3])
            .expect("partial tcp read"),
        Vec::new()
    );
    assert_eq!(
        socket_loop
            .tcp_tls_pending_len(source_stream)
            .expect("pending tcp bytes"),
        3
    );
    let tcp_forwarded = socket_loop
        .ingest_tcp_tls_stream_bytes(&mut service, 541, source_stream, &tcp_record[3..])
        .expect("complete tcp read");
    assert_eq!(tcp_forwarded.len(), 1);
    assert_eq!(tcp_forwarded[0].to_peer_id(), peer(2));

    log_stage(
        test,
        "tcp-egress",
        "tcp/tls writer receives stream id plus length-prefixed opaque record",
    );
    let tcp_write = socket_loop
        .drain_tcp_tls_record_for_peer(&mut service, peer(2))
        .expect("drain tcp")
        .expect("tcp write");
    assert_eq!(tcp_write.stream_id(), migrated_destination_stream);
    assert_eq!(
        tcp_write.opaque_bytes(),
        u64::try_from(b"loop-e2e-tcp-ciphertext".len()).expect("ciphertext len fits")
    );
    let decoded_tcp = RelayWireFrame::decode_complete_tcp_tls_record(
        tcp_write.bytes(),
        RelayQuota::default().max_packet_bytes,
    )
    .expect("decode tcp write");
    assert_eq!(decoded_tcp.packet().transport(), RelayTransport::TcpTls443);
    assert_eq!(
        decoded_tcp.packet().opaque_bytes(),
        b"loop-e2e-tcp-ciphertext"
    );

    log_stage(
        test,
        "tcp-fail-closed",
        "a hostile tcp record closes the admitted stream and preserves relay proof counters",
    );
    let bad_frame = RelayWireFrame::new(
        reservation_id(703),
        nonce(0xfeed_f500),
        peer(3),
        packet_sent_at(
            RelayTransport::TcpTls443,
            b"loop-e2e-bad-ciphertext",
            3,
            550,
        ),
    );
    let bad_record = bad_frame
        .encode_tcp_tls_record(RelayQuota::default().max_packet_bytes)
        .expect("encode bad record");
    assert_eq!(
        socket_loop
            .ingest_tcp_tls_stream_bytes(&mut service, 560, source_stream, &bad_record)
            .expect_err("hostile stream record"),
        RelayError::UnauthorizedPeer
    );
    assert_eq!(
        socket_loop
            .tcp_tls_pending_len(source_stream)
            .expect_err("source stream closed after hostile record"),
        RelayError::UnknownRelayEndpoint
    );
    let proof = service
        .proof_artifact(reservation_id(703))
        .expect("socket-loop proof");
    assert_eq!(proof.packets_forwarded, 2);
    assert_eq!(
        proof.opaque_bytes_forwarded,
        u64::try_from(b"loop-e2e-udp-ciphertext".len() + b"loop-e2e-tcp-ciphertext".len())
            .expect("ciphertext lengths fit")
    );
    assert!(proof.e2e_proof_preserved);
    assert!(service.events().iter().any(|event| {
        event.kind == RelayEventKind::AuthorizationRejected
            && event.quota_decision == "endpoint_peer_mismatch_rejected"
            && event.transport == Some(RelayTransport::TcpTls443)
    }));
}

#[test]
fn relay_socket_loop_round_trips_real_udp_socket_with_detailed_logs() {
    let test = "relay_socket_loop_round_trips_real_udp_socket_with_detailed_logs";
    let mut service = RelayService::new(
        RelayServiceConfig::new("relay-real-udp-socket-e2e", 4)
            .expect("config")
            .with_log_peer_ids(true),
    );
    log_stage(
        test,
        "reserve",
        "accept a relay reservation before admitting concrete loopback UDP sockets",
    );
    service
        .reserve(
            600,
            reservation_id(704),
            "real-udp-socket-path",
            grant(10_000, RelayQuota::default()),
            &|_: &RelayReservationGrant| true,
        )
        .expect("reserve real udp socket relay");

    let relay_socket =
        UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).expect("bind relay socket");
    let source_socket =
        UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).expect("bind source socket");
    let destination_socket =
        UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).expect("bind destination socket");
    relay_socket
        .set_nonblocking(true)
        .expect("relay socket nonblocking");
    destination_socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("destination read timeout");

    let source_addr = source_socket.local_addr().expect("source addr");
    let relay_addr = relay_socket.local_addr().expect("relay addr");
    let destination_addr = destination_socket.local_addr().expect("destination addr");
    let mut socket_loop = RelaySocketLoop::new(
        RelayEndpointDirectoryQuota {
            max_udp_endpoints: 2,
            max_tcp_tls_streams: 1,
        },
        RelayQuota::default().max_packet_bytes,
        1024,
    )
    .expect("socket loop");
    socket_loop
        .admit_udp_endpoint(peer(1), source_addr)
        .expect("admit source udp");
    socket_loop
        .admit_udp_endpoint(peer(2), destination_addr)
        .expect("admit destination udp");
    let recv_capacity = socket_loop
        .udp_socket_recv_buffer_capacity()
        .expect("udp recv capacity");

    log_stage(
        test,
        "empty-nonblocking-read",
        "nonblocking relay UDP sockets report no datagram without mutating relay state",
    );
    let mut scratch = vec![0; recv_capacity];
    assert_eq!(
        socket_loop
            .recv_udp_socket_once(&mut service, 601, &relay_socket, &mut scratch)
            .expect("empty nonblocking relay socket read"),
        None
    );
    assert_eq!(
        service
            .proof_artifact(reservation_id(704))
            .expect("proof after empty read")
            .packets_forwarded,
        0
    );

    log_stage(
        test,
        "buffer-capacity",
        "socket read helper rejects scratch buffers that cannot prove truncation safety",
    );
    let mut undersized_scratch = vec![0; recv_capacity - 1];
    let err = socket_loop
        .recv_udp_socket_once(&mut service, 602, &relay_socket, &mut undersized_scratch)
        .expect_err("undersized scratch is rejected before socket read");
    match err {
        RelaySocketIoError::DatagramBufferTooSmall { capacity, required } => {
            assert_eq!(capacity, recv_capacity - 1);
            assert_eq!(required, recv_capacity);
        }
        other => panic!("unexpected socket I/O error: {other:?}"),
    }

    let udp_frame = RelayWireFrame::new(
        reservation_id(704),
        nonce(0xfeed_f500),
        peer(1),
        packet_sent_at(RelayTransport::Udp, b"real-udp-socket-ciphertext", 1, 610),
    );
    let udp_datagram = udp_frame
        .encode(RelayQuota::default().max_packet_bytes)
        .expect("encode udp datagram");
    source_socket
        .send_to(&udp_datagram, relay_addr)
        .expect("source sends to relay socket");

    log_stage(
        test,
        "socket-ingress",
        "real UDP socket bytes are admitted by source address before relay decode",
    );
    let forwarded = socket_loop
        .recv_udp_socket_once(&mut service, 620, &relay_socket, &mut scratch)
        .expect("read relay UDP datagram")
        .expect("forwarded packet");
    assert_eq!(forwarded.from_peer_id(), peer(1));
    assert_eq!(forwarded.to_peer_id(), peer(2));
    assert_eq!(
        forwarded.packet().opaque_bytes(),
        b"real-udp-socket-ciphertext"
    );
    assert_eq!(
        service
            .proof_artifact(reservation_id(704))
            .expect("proof after real udp ingress")
            .packets_forwarded,
        1
    );

    log_stage(
        test,
        "empty-egress",
        "socket write helper distinguishes empty queues from successful sends",
    );
    assert_eq!(
        socket_loop
            .send_udp_socket_once(&mut service, &relay_socket, peer(1))
            .expect("no queued source write"),
        None
    );

    log_stage(
        test,
        "socket-egress",
        "queued relay datagram is committed only after the OS accepts the UDP send",
    );
    let bytes_sent = socket_loop
        .send_udp_socket_once(&mut service, &relay_socket, peer(2))
        .expect("relay socket write")
        .expect("queued destination datagram");
    assert!(bytes_sent > 0);

    let mut received = vec![0; recv_capacity];
    let (received_len, from_addr) = destination_socket
        .recv_from(&mut received)
        .expect("destination receives relay datagram");
    assert_eq!(from_addr, relay_addr);
    let decoded = RelayWireFrame::decode(
        &received[..received_len],
        RelayQuota::default().max_packet_bytes,
    )
    .expect("decode destination relay datagram");
    assert_eq!(decoded.reservation_id(), reservation_id(704));
    assert_eq!(decoded.from_peer_id(), peer(1));
    assert_eq!(decoded.packet().transport(), RelayTransport::Udp);
    assert_eq!(
        decoded.packet().opaque_bytes(),
        b"real-udp-socket-ciphertext"
    );
    assert!(
        socket_loop
            .drain_udp_datagram_for_peer(&mut service, peer(2))
            .expect("queue drained after successful socket send")
            .is_none()
    );
}

#[test]
fn relay_socket_loop_round_trips_real_tcp_stream_with_detailed_logs() {
    let test = "relay_socket_loop_round_trips_real_tcp_stream_with_detailed_logs";
    let mut service = RelayService::new(
        RelayServiceConfig::new("relay-real-tcp-socket-e2e", 4)
            .expect("config")
            .with_udp_enabled(false)
            .with_log_peer_ids(true),
    );
    log_stage(
        test,
        "reserve",
        "accept a relay reservation that must use tcp/tls 443 fallback",
    );
    service
        .reserve(
            700,
            reservation_id(705),
            "real-tcp-socket-path",
            grant(10_000, RelayQuota::default()),
            &|_: &RelayReservationGrant| true,
        )
        .expect("reserve real tcp stream relay");

    log_stage(
        test,
        "connect",
        "create real loopback tcp streams for source ingress and destination egress",
    );
    let source_listener =
        TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).expect("source listener");
    let source_addr = source_listener.local_addr().expect("source listener addr");
    let mut source_client = TcpStream::connect(source_addr).expect("source client connects");

    let destination_listener =
        TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).expect("destination listener");
    let destination_addr = destination_listener
        .local_addr()
        .expect("destination listener addr");
    let mut destination_client =
        TcpStream::connect(destination_addr).expect("destination client connects");
    destination_client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("destination read timeout");

    let mut socket_loop = RelaySocketLoop::new(
        RelayEndpointDirectoryQuota {
            max_udp_endpoints: 1,
            max_tcp_tls_streams: 2,
        },
        RelayQuota::default().max_packet_bytes,
        1024,
    )
    .expect("socket loop");
    let mut source_accept = socket_loop
        .accept_tcp_tls_stream_once(&source_listener, peer(1))
        .expect("accept source tcp stream")
        .expect("source tcp stream accepted");
    assert_eq!(
        source_accept.peer_addr(),
        source_client.local_addr().expect("source client addr")
    );
    let source_stream_id = source_accept.stream_id();
    source_accept
        .stream()
        .set_nonblocking(true)
        .expect("relay source stream nonblocking");

    let mut destination_accept = socket_loop
        .accept_tcp_tls_stream_once(&destination_listener, peer(2))
        .expect("accept destination tcp stream")
        .expect("destination tcp stream accepted");
    assert_eq!(
        destination_accept.peer_addr(),
        destination_client
            .local_addr()
            .expect("destination client addr")
    );
    let destination_stream_id = destination_accept.stream_id();

    log_stage(
        test,
        "empty-nonblocking-read",
        "tcp stream read helper reports would-block without mutating proof state",
    );
    let mut scratch = vec![0; 1024];
    assert_eq!(
        socket_loop
            .recv_accepted_tcp_tls_stream_once(&mut service, 701, &mut source_accept, &mut scratch,)
            .expect("empty nonblocking tcp stream read"),
        None
    );
    assert_eq!(
        service
            .proof_artifact(reservation_id(705))
            .expect("proof after empty tcp read")
            .packets_forwarded,
        0
    );
    source_accept
        .stream()
        .set_nonblocking(false)
        .expect("relay source stream blocking for deterministic read");
    source_accept
        .stream()
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("relay source read timeout");

    log_stage(
        test,
        "socket-ingress",
        "real tcp stream bytes are admitted by stream id before relay decode",
    );
    let tcp_frame = RelayWireFrame::new(
        reservation_id(705),
        nonce(0xfeed_f500),
        peer(1),
        packet_sent_at(
            RelayTransport::TcpTls443,
            b"real-tcp-socket-ciphertext",
            1,
            720,
        ),
    );
    let tcp_record = tcp_frame
        .encode_tcp_tls_record(RelayQuota::default().max_packet_bytes)
        .expect("encode tcp record");
    source_client
        .write_all(&tcp_record)
        .expect("source writes tcp relay record");
    let forwarded = socket_loop
        .recv_accepted_tcp_tls_stream_once(&mut service, 740, &mut source_accept, &mut scratch)
        .expect("read relay tcp stream")
        .expect("forwarded tcp packets");
    assert_eq!(forwarded.len(), 1);
    assert_eq!(forwarded[0].from_peer_id(), peer(1));
    assert_eq!(forwarded[0].to_peer_id(), peer(2));
    assert_eq!(
        forwarded[0].packet().opaque_bytes(),
        b"real-tcp-socket-ciphertext"
    );
    assert_eq!(
        service
            .proof_artifact(reservation_id(705))
            .expect("proof after real tcp ingress")
            .packets_forwarded,
        1
    );

    log_stage(
        test,
        "empty-egress",
        "tcp stream write helper keys egress by admitted stream id before queue drain",
    );
    assert_eq!(
        socket_loop
            .send_tcp_tls_stream_once(
                &mut service,
                source_stream_id,
                destination_accept.stream_mut()
            )
            .expect("source stream id cannot drain destination queue"),
        None
    );

    log_stage(
        test,
        "socket-egress",
        "queued tcp relay record is staged and written to the concrete destination stream",
    );
    let mut total_written = 0usize;
    for _ in 0..8 {
        let Some(written) = socket_loop
            .send_accepted_tcp_tls_stream_once(&mut service, &mut destination_accept)
            .expect("relay tcp stream write")
        else {
            break;
        };
        total_written = total_written.saturating_add(written);
        if socket_loop.tcp_tls_pending_write_len(destination_stream_id) == 0 {
            break;
        }
    }
    assert!(total_written > 0);
    assert_eq!(
        socket_loop.tcp_tls_pending_write_len(destination_stream_id),
        0
    );
    assert_eq!(socket_loop.tcp_tls_pending_write_count(), 0);

    let mut received = vec![0; 2048];
    let mut received_len = 0usize;
    while received_len < 4 {
        let read = destination_client
            .read(&mut received[received_len..])
            .expect("destination reads tcp record prefix");
        assert!(read > 0, "destination stream closed before record prefix");
        received_len += read;
    }
    let frame_len =
        u32::from_be_bytes(received[..4].try_into().expect("record prefix bytes")) as usize;
    let record_len = frame_len + 4;
    assert!(
        record_len <= received.len(),
        "destination tcp record length exceeds receive buffer"
    );
    while received_len < record_len {
        let read = destination_client
            .read(&mut received[received_len..record_len])
            .expect("destination reads complete tcp record");
        assert!(read > 0, "destination stream closed before complete record");
        received_len += read;
    }
    let decoded = RelayWireFrame::decode_complete_tcp_tls_record(
        &received[..record_len],
        RelayQuota::default().max_packet_bytes,
    )
    .expect("decode destination tcp relay record");
    assert_eq!(decoded.reservation_id(), reservation_id(705));
    assert_eq!(decoded.from_peer_id(), peer(1));
    assert_eq!(decoded.packet().transport(), RelayTransport::TcpTls443);
    assert_eq!(
        decoded.packet().opaque_bytes(),
        b"real-tcp-socket-ciphertext"
    );
    assert!(
        socket_loop
            .drain_tcp_tls_record_for_peer(&mut service, peer(2))
            .expect("queue drained after successful tcp stream write")
            .is_none()
    );

    log_stage(
        test,
        "eof",
        "tcp stream eof closes endpoint binding and retained stream buffers",
    );
    source_client
        .shutdown(Shutdown::Write)
        .expect("source half closes write side");
    let err = socket_loop
        .recv_accepted_tcp_tls_stream_once(&mut service, 780, &mut source_accept, &mut scratch)
        .expect_err("tcp stream eof closes the admitted stream");
    match err {
        RelaySocketIoError::TcpTlsStreamClosed { stream_id } => {
            assert_eq!(stream_id, source_stream_id);
        }
        other => panic!("unexpected tcp stream EOF error: {other:?}"),
    }
    assert_eq!(socket_loop.tcp_tls_stream_buffer_count(), 1);
}

#[test]
fn relay_socket_turn_services_udp_and_tcp_with_detailed_logs() {
    let test = "relay_socket_turn_services_udp_and_tcp_with_detailed_logs";
    let mut service = RelayService::new(
        RelayServiceConfig::new("relay-socket-turn-e2e", 4)
            .expect("config")
            .with_log_peer_ids(true),
    );

    log_stage(
        test,
        "reserve",
        "accept one relay reservation that can move opaque UDP and TCP/TLS traffic",
    );
    service
        .reserve(
            800,
            reservation_id(805),
            "socket-turn-path",
            grant(10_000, RelayQuota::default()),
            &|_: &RelayReservationGrant| true,
        )
        .expect("reserve relay socket turn");

    log_stage(
        test,
        "udp-setup",
        "bind real relay/source/destination UDP sockets and admit endpoints",
    );
    let relay_udp =
        UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).expect("relay udp binds");
    relay_udp
        .set_nonblocking(true)
        .expect("relay udp nonblocking");
    let relay_udp_addr = relay_udp.local_addr().expect("relay udp addr");
    let source_udp =
        UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).expect("source udp binds");
    let destination_udp =
        UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).expect("destination udp binds");
    destination_udp
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("destination udp read timeout");

    let mut socket_loop = RelaySocketLoop::new(
        RelayEndpointDirectoryQuota {
            max_udp_endpoints: 2,
            max_tcp_tls_streams: 2,
        },
        RelayQuota::default().max_packet_bytes,
        2048,
    )
    .expect("socket loop");
    socket_loop
        .admit_udp_endpoint(peer(1), source_udp.local_addr().expect("source udp addr"))
        .expect("admit source udp endpoint");
    socket_loop
        .admit_udp_endpoint(
            peer(2),
            destination_udp.local_addr().expect("destination udp addr"),
        )
        .expect("admit destination udp endpoint");

    log_stage(
        test,
        "tcp-setup",
        "accept real source and destination TCP/TLS fallback streams through the relay loop",
    );
    let source_listener =
        TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).expect("source listener");
    let mut source_client =
        TcpStream::connect(source_listener.local_addr().expect("source listener addr"))
            .expect("source client connects");
    let source_accept = socket_loop
        .accept_tcp_tls_stream_once(&source_listener, peer(1))
        .expect("accept source stream")
        .expect("source stream accepted");

    let destination_listener =
        TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).expect("destination listener");
    let mut destination_client = TcpStream::connect(
        destination_listener
            .local_addr()
            .expect("destination listener addr"),
    )
    .expect("destination client connects");
    destination_client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("destination tcp read timeout");
    let destination_accept = socket_loop
        .accept_tcp_tls_stream_once(&destination_listener, peer(2))
        .expect("accept destination stream")
        .expect("destination stream accepted");

    source_accept
        .stream()
        .set_nonblocking(true)
        .expect("source accepted stream nonblocking");
    destination_accept
        .stream()
        .set_nonblocking(true)
        .expect("destination accepted stream nonblocking");

    log_stage(
        test,
        "send-inputs",
        "submit one real UDP datagram and one real TCP/TLS relay record before one service turn",
    );
    let udp_frame = RelayWireFrame::new(
        reservation_id(805),
        nonce(0xfeed_f500),
        peer(1),
        packet_sent_at(RelayTransport::Udp, b"turn-udp-ciphertext", 1, 810),
    );
    let udp_datagram = udp_frame
        .encode(RelayQuota::default().max_packet_bytes)
        .expect("encode udp frame");
    source_udp
        .send_to(&udp_datagram, relay_udp_addr)
        .expect("source udp sends relay datagram");

    let tcp_frame = RelayWireFrame::new(
        reservation_id(805),
        nonce(0xfeed_f500),
        peer(1),
        packet_sent_at(RelayTransport::TcpTls443, b"turn-tcp-ciphertext", 2, 820),
    );
    let tcp_record = tcp_frame
        .encode_tcp_tls_record(RelayQuota::default().max_packet_bytes)
        .expect("encode tcp record");
    source_client
        .write_all(&tcp_record)
        .expect("source client writes tcp record");

    log_stage(
        test,
        "service-turn",
        "one deterministic socket turn services UDP ingress, TCP ingress, UDP egress, and TCP egress",
    );
    let mut udp_scratch = vec![
        0;
        socket_loop
            .udp_socket_recv_buffer_capacity()
            .expect("udp scratch capacity")
    ];
    let mut tcp_scratch = vec![0; 2048];
    let mut accepted_streams = vec![source_accept, destination_accept];
    let mut summary = socket_loop
        .service_socket_turn_once(
            &mut service,
            900,
            Some(&relay_udp),
            &mut udp_scratch,
            &mut accepted_streams,
            &mut tcp_scratch,
        )
        .expect("service socket turn");
    for _ in 0..8 {
        if summary.udp_datagrams_sent > 0
            && summary.tcp_tls_bytes_written > 0
            && socket_loop.tcp_tls_pending_write_count() == 0
        {
            break;
        }
        let next = socket_loop
            .service_socket_turn_once(
                &mut service,
                901,
                Some(&relay_udp),
                &mut udp_scratch,
                &mut accepted_streams,
                &mut tcp_scratch,
            )
            .expect("follow-up service socket turn");
        summary.udp_datagrams_received += next.udp_datagrams_received;
        summary.udp_datagrams_sent += next.udp_datagrams_sent;
        summary.tcp_tls_chunks_read += next.tcp_tls_chunks_read;
        summary.tcp_tls_packets_forwarded += next.tcp_tls_packets_forwarded;
        summary.tcp_tls_streams_closed += next.tcp_tls_streams_closed;
        summary.tcp_tls_bytes_written += next.tcp_tls_bytes_written;
        summary.socket_would_block += next.socket_would_block;
        summary.empty_egress_attempts += next.empty_egress_attempts;
    }
    assert!(summary.made_progress());
    assert_eq!(summary.udp_datagrams_received, 1);
    assert_eq!(summary.udp_datagrams_sent, 1);
    assert_eq!(summary.tcp_tls_chunks_read, 1);
    assert_eq!(summary.tcp_tls_packets_forwarded, 1);
    assert!(summary.tcp_tls_bytes_written > 0);
    assert_eq!(socket_loop.tcp_tls_pending_write_count(), 0);

    log_stage(
        test,
        "verify-udp-output",
        "destination UDP socket receives the relayed opaque frame from the relay address",
    );
    let mut received_udp = vec![0; 2048];
    let (received_udp_len, received_udp_from) = destination_udp
        .recv_from(&mut received_udp)
        .expect("destination udp receives relay datagram");
    assert_eq!(received_udp_from, relay_udp_addr);
    let decoded_udp = RelayWireFrame::decode(
        &received_udp[..received_udp_len],
        RelayQuota::default().max_packet_bytes,
    )
    .expect("decode relayed udp frame");
    assert_eq!(decoded_udp.from_peer_id(), peer(1));
    assert_eq!(decoded_udp.packet().transport(), RelayTransport::Udp);
    assert_eq!(decoded_udp.packet().opaque_bytes(), b"turn-udp-ciphertext");

    log_stage(
        test,
        "verify-tcp-output",
        "destination TCP client receives the relayed length-prefixed fallback record",
    );
    let mut received_tcp = vec![0; 2048];
    let mut received_tcp_len = 0usize;
    while received_tcp_len < 4 {
        let read = destination_client
            .read(&mut received_tcp[received_tcp_len..])
            .expect("destination reads tcp prefix");
        assert!(read > 0, "destination closed before tcp record prefix");
        received_tcp_len += read;
    }
    let frame_len =
        u32::from_be_bytes(received_tcp[..4].try_into().expect("tcp prefix bytes")) as usize;
    let tcp_record_len = frame_len + 4;
    assert!(
        tcp_record_len <= received_tcp.len(),
        "relayed tcp record exceeds receive buffer"
    );
    while received_tcp_len < tcp_record_len {
        let read = destination_client
            .read(&mut received_tcp[received_tcp_len..tcp_record_len])
            .expect("destination reads complete tcp record");
        assert!(read > 0, "destination closed before complete tcp record");
        received_tcp_len += read;
    }
    let decoded_tcp = RelayWireFrame::decode_complete_tcp_tls_record(
        &received_tcp[..tcp_record_len],
        RelayQuota::default().max_packet_bytes,
    )
    .expect("decode relayed tcp record");
    assert_eq!(decoded_tcp.from_peer_id(), peer(1));
    assert_eq!(decoded_tcp.packet().transport(), RelayTransport::TcpTls443);
    assert_eq!(decoded_tcp.packet().opaque_bytes(), b"turn-tcp-ciphertext");

    let proof = service
        .proof_artifact(reservation_id(805))
        .expect("proof after socket turn");
    assert_eq!(proof.packets_forwarded, 2);
    assert_eq!(
        proof.opaque_bytes_forwarded,
        (b"turn-udp-ciphertext".len() + b"turn-tcp-ciphertext".len()) as u64
    );
    assert!(proof.latency_summary.is_some());
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
