    use super::*;

    fn peer(seed: u8) -> PeerId {
        PeerId::new([seed; 32]).expect("peer")
    }

    fn transfer_nonce(raw: u128) -> TransferNonce {
        TransferNonce::new(raw).expect("transfer nonce")
    }

    fn reservation_id(raw: u128) -> RelayReservationId {
        RelayReservationId::new(raw).expect("reservation id")
    }

    fn proof_tag(seed: u8) -> ProofTag {
        ProofTag::new([seed; 32]).expect("proof tag")
    }

    fn signature() -> CandidateSignature {
        CandidateSignature::new(vec![1, 2, 3]).expect("signature")
    }

    fn grant(expires_at_micros: u64, quota: RelayQuota) -> RelayReservationGrant {
        RelayReservationGrant::udp_first_tcp_tls_443(
            peer(1),
            peer(2),
            transfer_nonce(9),
            expires_at_micros,
            quota,
            signature(),
        )
        .expect("grant")
    }

    fn packet(transport: RelayTransport, payload: &[u8], sequence: u64) -> OpaqueRelayPacket {
        packet_sent_at(transport, payload, sequence, 10)
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
            proof_tag(7),
            sent_at_micros,
        )
        .expect("packet")
    }

    #[test]
    fn endpoint_directory_binds_socket_endpoints_to_authenticated_peers() {
        let mut directory = RelayEndpointDirectory::new(RelayEndpointDirectoryQuota {
            max_udp_endpoints: 2,
            max_tcp_tls_streams: 2,
        })
        .expect("directory");
        let udp_endpoint = SocketAddr::from(([192, 0, 2, 10], 40_000));
        let second_udp_endpoint = SocketAddr::from(([192, 0, 2, 11], 40_001));
        let stream_id = RelayTcpTlsStreamId::new(700).expect("stream id");
        let second_stream_id = RelayTcpTlsStreamId::new(701).expect("second stream id");

        assert_eq!(
            RelayTcpTlsStreamId::new(0).expect_err("zero stream id"),
            RelayError::ZeroTcpTlsStreamId
        );
        assert_eq!(
            directory
                .bind_udp_endpoint(peer(1), SocketAddr::from(([0, 0, 0, 0], 40_000)))
                .expect_err("wildcard endpoint"),
            RelayError::InvalidRelayEndpoint
        );
        assert_eq!(
            directory
                .bind_udp_endpoint(peer(1), SocketAddr::from(([192, 0, 2, 12], 0)))
                .expect_err("port-zero endpoint"),
            RelayError::InvalidRelayEndpoint
        );

        directory
            .bind_udp_endpoint(peer(1), udp_endpoint)
            .expect("bind udp");
        directory
            .bind_udp_endpoint(peer(1), udp_endpoint)
            .expect("idempotent udp bind");
        assert_eq!(
            directory
                .bind_udp_endpoint(peer(2), udp_endpoint)
                .expect_err("conflicting udp bind"),
            RelayError::DuplicateRelayEndpoint
        );
        assert_eq!(
            directory
                .peer_for_udp_endpoint(udp_endpoint)
                .expect("udp peer"),
            peer(1)
        );
        assert_eq!(
            directory
                .first_udp_endpoint_for_peer(peer(1))
                .expect("udp endpoint for peer"),
            udp_endpoint
        );
        directory
            .bind_udp_endpoint(peer(1), second_udp_endpoint)
            .expect("migrated udp endpoint");
        assert_eq!(
            directory
                .first_udp_endpoint_for_peer(peer(1))
                .expect("fresh udp endpoint for peer"),
            second_udp_endpoint
        );
        assert_eq!(
            directory
                .peer_for_udp_endpoint(SocketAddr::from(([192, 0, 2, 99], 40_099)))
                .expect_err("unknown udp endpoint"),
            RelayError::UnknownRelayEndpoint
        );
        assert_eq!(
            directory
                .bind_udp_endpoint(peer(3), SocketAddr::from(([192, 0, 2, 13], 40_002)))
                .expect_err("udp endpoint quota"),
            RelayError::QuotaExceeded
        );
        assert_eq!(directory.unbind_udp_endpoint(udp_endpoint), Some(peer(1)));
        assert_eq!(
            directory
                .first_udp_endpoint_for_peer(peer(1))
                .expect("fresh udp endpoint survives stale unbind"),
            second_udp_endpoint
        );
        assert_eq!(
            directory
                .peer_for_udp_endpoint(udp_endpoint)
                .expect_err("unbound udp endpoint"),
            RelayError::UnknownRelayEndpoint
        );

        directory
            .bind_tcp_tls_stream(peer(1), stream_id)
            .expect("bind tcp stream");
        directory
            .bind_tcp_tls_stream(peer(1), stream_id)
            .expect("idempotent tcp bind");
        assert_eq!(
            directory
                .bind_tcp_tls_stream(peer(2), stream_id)
                .expect_err("conflicting tcp bind"),
            RelayError::DuplicateRelayEndpoint
        );
        assert_eq!(
            directory
                .peer_for_tcp_tls_stream(stream_id)
                .expect("tcp stream peer"),
            peer(1)
        );
        directory
            .bind_tcp_tls_stream(peer(1), second_stream_id)
            .expect("reconnected tcp stream");
        assert_eq!(
            directory
                .first_tcp_tls_stream_for_peer(peer(1))
                .expect("fresh tcp stream for peer"),
            second_stream_id
        );
        assert_eq!(
            directory
                .bind_tcp_tls_stream(
                    peer(3),
                    RelayTcpTlsStreamId::new(702).expect("third stream id"),
                )
                .expect_err("tcp stream quota"),
            RelayError::QuotaExceeded
        );
        assert_eq!(directory.unbind_tcp_tls_stream(stream_id), Some(peer(1)));
        assert_eq!(
            directory
                .first_tcp_tls_stream_for_peer(peer(1))
                .expect("fresh tcp stream survives stale unbind"),
            second_stream_id
        );
        assert_eq!(
            directory
                .peer_for_tcp_tls_stream(stream_id)
                .expect_err("unbound tcp stream"),
            RelayError::UnknownRelayEndpoint
        );
    }

    #[test]
    fn udp_first_reservation_emits_tcp_tls_443_fallback_candidate() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        let candidate = service
            .reserve(
                10,
                reservation_id(1),
                "path-relay-1",
                grant(1_000, RelayQuota::default()),
                &|grant: &RelayReservationGrant| grant.signature().bytes() == [1, 2, 3],
            )
            .expect("reservation");

        assert_eq!(candidate.primary_transport(), RelayTransport::Udp);
        assert_eq!(
            candidate.fallback_transport(),
            Some(RelayTransport::TcpTls443)
        );
        assert_eq!(candidate.path_id(), "path-relay-1");
        assert_eq!(service.events()[0].quota_decision, "reservation_accepted");
        assert_eq!(service.events()[0].fallback_reason, None);
    }

    #[test]
    fn tcp_tls_443_is_selected_when_udp_is_disabled() {
        let config = RelayServiceConfig::default().with_udp_enabled(false);
        let mut service = RelayService::new(config);

        let candidate = service
            .reserve(
                10,
                reservation_id(2),
                "path-relay-2",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");

        assert_eq!(candidate.primary_transport(), RelayTransport::TcpTls443);
        assert_eq!(
            candidate.primary_transport().fallback_reason(),
            Some("udp_unavailable_tcp_tls_443")
        );
    }

    #[test]
    fn relay_candidate_converts_to_path_graph_candidate() {
        let config = RelayServiceConfig::default().with_udp_enabled(false);
        let mut service = RelayService::new(config);
        let relay_candidate = service
            .reserve(
                10,
                reservation_id(33),
                "path-relay-33",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");

        assert_eq!(relay_candidate.path_kind(), PathKind::AtpRelayTcpTls443);
        assert_eq!(relay_candidate.fallback_path_kind(), None);

        let path_candidate =
            relay_candidate.to_path_candidate(PathCandidateId::new(333), PathTraceId::new(333_000));
        assert_eq!(path_candidate.id, PathCandidateId::new(333));
        assert_eq!(path_candidate.kind, PathKind::AtpRelayTcpTls443);
        assert_eq!(path_candidate.trace_id, PathTraceId::new(333_000));
        assert!(path_candidate.security.authenticated_peer);
        assert!(path_candidate.security.end_to_end_encrypted);
        assert!(!path_candidate.security.exposes_local_ip_to_peer);
        assert!(path_candidate.security.relay_metadata_visible);
    }

    #[test]
    fn relay_proof_and_errors_convert_to_path_graph_outcomes() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        service
            .reserve(
                10,
                reservation_id(34),
                "path-relay-34",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");
        service
            .forward(
                20,
                reservation_id(34),
                peer(1),
                packet(RelayTransport::Udp, b"ciphertext", 1),
            )
            .expect("forward");

        let proof = service
            .proof_artifact(reservation_id(34))
            .expect("proof artifact");
        let latency = proof.latency_summary.expect("latency summary");
        assert_eq!(latency.sample_count, 1);
        assert_eq!(latency.latest_latency_micros, 10);
        let outcome = proof.to_path_success_outcome(30, Some(10));
        assert!(outcome.is_success());
        assert_eq!(outcome.observed_rtt_micros, Some(10));
        assert_eq!(outcome.bytes_sent, proof.opaque_bytes_forwarded);
        assert_eq!(outcome.bytes_received, proof.opaque_bytes_forwarded);

        assert_eq!(
            RelayError::InvalidAuthorization.path_failure_kind(),
            PathFailureKind::AuthFailure
        );
        assert_eq!(
            RelayError::TransportUnavailable.path_failure_kind(),
            PathFailureKind::RelayUnavailable
        );
        assert_eq!(
            RelayError::PacketTooLarge.path_failure_kind(),
            PathFailureKind::PolicyDenied
        );
        assert_eq!(
            RelayError::InvalidProofTag.path_failure_kind(),
            PathFailureKind::ProtocolError
        );
    }

    #[test]
    fn forwards_opaque_bytes_and_preserves_proof_tag() {
        let mut service = RelayService::new(RelayServiceConfig::default().with_log_peer_ids(true));
        service
            .reserve(
                10,
                reservation_id(3),
                "path-relay-3",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");

        let original = packet(RelayTransport::Udp, b"ciphertext", 42);
        let forwarded = service
            .forward(20, reservation_id(3), peer(1), original.clone())
            .expect("forward");

        assert_eq!(forwarded.to_peer_id(), peer(2));
        assert_eq!(forwarded.packet().opaque_bytes(), b"ciphertext");
        assert_eq!(forwarded.packet().proof_tag(), original.proof_tag());
        assert_eq!(
            service.dequeue_for_peer(peer(2)).expect("queued packet"),
            forwarded
        );
    }

    #[test]
    fn latency_summary_tracks_min_max_latest_and_average() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        service
            .reserve(
                10,
                reservation_id(35),
                "path-relay-35",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");

        service
            .forward(
                20,
                reservation_id(35),
                peer(1),
                packet_sent_at(RelayTransport::Udp, b"first", 1, 12),
            )
            .expect("first forward");
        service
            .forward(
                35,
                reservation_id(35),
                peer(2),
                packet_sent_at(RelayTransport::Udp, b"second", 2, 20),
            )
            .expect("second forward");

        let proof = service
            .proof_artifact(reservation_id(35))
            .expect("proof artifact");
        let latency = proof.latency_summary.expect("latency summary");
        assert_eq!(latency.sample_count, 2);
        assert_eq!(latency.latest_latency_micros, 15);
        assert_eq!(latency.min_latency_micros, 8);
        assert_eq!(latency.max_latency_micros, 15);
        assert_eq!(latency.total_latency_micros, 23);
        assert_eq!(latency.average_latency_micros, 11);
    }

    #[test]
    fn relay_wire_frame_round_trips_and_forwards_through_service() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        service
            .reserve(
                10,
                reservation_id(36),
                "path-relay-36",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");

        let frame = RelayWireFrame::new(
            reservation_id(36),
            transfer_nonce(9),
            peer(1),
            packet_sent_at(RelayTransport::Udp, b"encrypted-relay-payload", 7, 70),
        );
        let encoded = frame
            .encode(RelayQuota::default().max_packet_bytes)
            .expect("encode relay frame");
        assert!(encoded.starts_with(&RELAY_WIRE_MAGIC));
        assert!(!encoded.windows(10).any(|window| window == b"object-path"));

        let wrong_nonce_frame = RelayWireFrame::new(
            reservation_id(36),
            transfer_nonce(99),
            peer(1),
            packet_sent_at(RelayTransport::Udp, b"wrong-transfer", 8, 72),
        );
        assert_eq!(
            wrong_nonce_frame
                .forward_into(&mut service, 91)
                .expect_err("wrong transfer nonce"),
            RelayError::InvalidAuthorization
        );
        assert_eq!(
            service.usage(reservation_id(36)).expect("usage"),
            RelayUsage::default()
        );
        assert!(service.events().iter().any(|event| {
            event.kind == RelayEventKind::AuthorizationRejected
                && event.quota_decision == "transfer_nonce_mismatch_rejected"
        }));

        let decoded = RelayWireFrame::decode(&encoded, RelayQuota::default().max_packet_bytes)
            .expect("decode relay frame");
        assert_eq!(decoded.reservation_id(), reservation_id(36));
        assert_eq!(decoded.transfer_nonce(), transfer_nonce(9));
        assert_eq!(decoded.from_peer_id(), peer(1));
        assert_eq!(decoded.packet().opaque_bytes(), b"encrypted-relay-payload");
        assert_eq!(decoded.packet().sequence(), 7);

        let forwarded = decoded
            .forward_into(&mut service, 90)
            .expect("decoded relay frame forwards");
        assert_eq!(forwarded.to_peer_id(), peer(2));
        assert_eq!(
            service
                .proof_artifact(reservation_id(36))
                .expect("proof")
                .latency_summary
                .expect("latency")
                .latest_latency_micros,
            20
        );
    }

    #[test]
    fn relay_wire_frame_rejects_truncated_trailing_oversize_and_unknown_headers() {
        let frame = RelayWireFrame::new(
            reservation_id(37),
            transfer_nonce(9),
            peer(1),
            packet(RelayTransport::TcpTls443, b"encrypted", 8),
        );
        let encoded = frame
            .encode(RelayQuota::default().max_packet_bytes)
            .expect("encode relay frame");

        assert_eq!(
            RelayWireFrame::decode(&encoded[..RELAY_WIRE_HEADER_LEN - 1], 1024)
                .expect_err("truncated"),
            RelayError::TruncatedRelayWireFrame
        );

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            RelayWireFrame::decode(&trailing, 1024).expect_err("trailing bytes"),
            RelayError::InvalidRelayWireFrame
        );

        assert_eq!(
            RelayWireFrame::decode(&encoded, 4).expect_err("payload too large"),
            RelayError::PacketTooLarge
        );

        let mut unsupported_version = encoded.clone();
        unsupported_version[4] = RELAY_WIRE_VERSION.saturating_add(1);
        assert_eq!(
            RelayWireFrame::decode(&unsupported_version, 1024).expect_err("version"),
            RelayError::UnsupportedRelayWireVersion
        );

        let mut unsupported_kind = encoded;
        unsupported_kind[5] = RELAY_WIRE_FORWARD_FRAME_KIND.saturating_add(1);
        assert_eq!(
            RelayWireFrame::decode(&unsupported_kind, 1024).expect_err("kind"),
            RelayError::UnsupportedRelayWireFrameKind
        );
    }

    #[test]
    fn relay_wire_tcp_tls_records_decode_partial_and_coalesced_stream_bytes() {
        let first = RelayWireFrame::new(
            reservation_id(38),
            transfer_nonce(9),
            peer(1),
            packet(RelayTransport::TcpTls443, b"first-stream-record", 1),
        );
        let second = RelayWireFrame::new(
            reservation_id(38),
            transfer_nonce(9),
            peer(2),
            packet(RelayTransport::TcpTls443, b"second-stream-record", 2),
        );
        let first_record = first
            .encode_tcp_tls_record(RelayQuota::default().max_packet_bytes)
            .expect("encode first record");
        let second_record = second
            .encode_tcp_tls_record(RelayQuota::default().max_packet_bytes)
            .expect("encode second record");
        let udp_frame = RelayWireFrame::new(
            reservation_id(38),
            transfer_nonce(9),
            peer(1),
            packet(RelayTransport::Udp, b"udp-on-tcp-record", 3),
        );

        assert_eq!(
            udp_frame
                .encode_tcp_tls_record(RelayQuota::default().max_packet_bytes)
                .expect_err("tcp record encoder rejects udp frame transport"),
            RelayError::InvalidRelayWireFrame
        );
        let udp_encoded = udp_frame
            .encode(RelayQuota::default().max_packet_bytes)
            .expect("encode raw udp relay frame");
        let udp_len = u32::try_from(udp_encoded.len()).expect("udp frame len fits in u32");
        let mut udp_inside_tcp_record =
            Vec::with_capacity(RELAY_WIRE_TCP_TLS_RECORD_PREFIX_LEN + udp_encoded.len());
        udp_inside_tcp_record.extend_from_slice(&udp_len.to_be_bytes());
        udp_inside_tcp_record.extend_from_slice(&udp_encoded);
        assert_eq!(
            RelayWireFrame::decode_tcp_tls_record(&udp_inside_tcp_record, 1024)
                .expect_err("tcp record decoder rejects udp frame transport"),
            RelayError::InvalidRelayWireFrame
        );

        assert_eq!(
            RelayWireFrame::decode_tcp_tls_record(&first_record[..2], 1024)
                .expect("partial prefix"),
            RelayWireRecordDecode::NeedMore { minimum_len: 4 }
        );
        assert_eq!(
            RelayWireFrame::decode_tcp_tls_record(&first_record[..8], 1024).expect("partial frame"),
            RelayWireRecordDecode::NeedMore {
                minimum_len: first_record.len()
            }
        );

        let mut coalesced = first_record.clone();
        coalesced.extend_from_slice(&second_record);
        let RelayWireRecordDecode::Complete {
            frame: decoded_first,
            consumed: first_consumed,
        } = RelayWireFrame::decode_tcp_tls_record(&coalesced, 1024).expect("decode first record")
        else {
            panic!("first coalesced record should be complete");
        };
        assert_eq!(first_consumed, first_record.len());
        assert_eq!(
            decoded_first.packet().opaque_bytes(),
            b"first-stream-record"
        );
        assert_eq!(
            RelayWireFrame::decode_complete_tcp_tls_record(&coalesced, 1024)
                .expect_err("coalesced bytes are not exactly one record"),
            RelayError::InvalidRelayWireFrame
        );

        let RelayWireRecordDecode::Complete {
            frame: decoded_second,
            consumed: second_consumed,
        } = RelayWireFrame::decode_tcp_tls_record(&coalesced[first_consumed..], 1024)
            .expect("decode second record")
        else {
            panic!("second coalesced record should be complete");
        };
        assert_eq!(second_consumed, second_record.len());
        assert_eq!(decoded_second.from_peer_id(), peer(2));
        assert_eq!(decoded_second.packet().sequence(), 2);

        let exact = RelayWireFrame::decode_complete_tcp_tls_record(&second_record, 1024)
            .expect("decode exactly one record");
        assert_eq!(exact.packet().opaque_bytes(), b"second-stream-record");

        let mut invalid_short_record = first_record;
        let invalid_short_len =
            u32::try_from(RELAY_WIRE_HEADER_LEN - 1).expect("relay header len fits in u32");
        invalid_short_record[..4].copy_from_slice(&invalid_short_len.to_be_bytes());
        assert_eq!(
            RelayWireFrame::decode_tcp_tls_record(&invalid_short_record, 1024)
                .expect_err("invalid frame length"),
            RelayError::InvalidRelayWireFrame
        );
        let mut oversize_record = second_record;
        let oversize_len =
            u32::try_from(RELAY_WIRE_HEADER_LEN + 5).expect("relay header len fits in u32");
        oversize_record[..4].copy_from_slice(&oversize_len.to_be_bytes());
        assert_eq!(
            RelayWireFrame::decode_tcp_tls_record(&oversize_record, 4)
                .expect_err("oversize record"),
            RelayError::PacketTooLarge
        );
    }

    #[test]
    fn relay_tcp_tls_stream_buffer_drains_partial_coalesced_records_with_bounds() {
        assert_eq!(
            RelayTcpTlsStreamBuffer::new(1024, RELAY_WIRE_TCP_TLS_RECORD_PREFIX_LEN)
                .expect_err("buffer smaller than the minimum record is invalid"),
            RelayError::InvalidQuota
        );

        let first = RelayWireFrame::new(
            reservation_id(39),
            transfer_nonce(9),
            peer(1),
            packet(RelayTransport::TcpTls443, b"buffered-first", 1),
        );
        let second = RelayWireFrame::new(
            reservation_id(39),
            transfer_nonce(9),
            peer(2),
            packet(RelayTransport::TcpTls443, b"buffered-second", 2),
        );
        let first_record = first
            .encode_tcp_tls_record(RelayQuota::default().max_packet_bytes)
            .expect("encode first buffered record");
        let second_record = second
            .encode_tcp_tls_record(RelayQuota::default().max_packet_bytes)
            .expect("encode second buffered record");
        let mut stream = RelayTcpTlsStreamBuffer::new(
            RelayQuota::default().max_packet_bytes,
            first_record.len() + second_record.len(),
        )
        .expect("stream buffer");

        stream
            .push_bytes(&first_record[..3])
            .expect("buffer partial prefix");
        assert_eq!(stream.pending_len(), 3);
        assert_eq!(stream.pop_next_frame().expect("partial decode"), None);
        stream
            .push_bytes(&first_record[3..])
            .expect("finish first record");
        let decoded_first = stream
            .pop_next_frame()
            .expect("decode first")
            .expect("first complete");
        assert_eq!(decoded_first.packet().opaque_bytes(), b"buffered-first");
        assert_eq!(stream.pending_len(), 0);

        let mut coalesced = second_record.clone();
        coalesced.extend_from_slice(&first_record);
        stream
            .push_bytes(&coalesced)
            .expect("buffer coalesced records");
        let drained = stream
            .drain_available_frames()
            .expect("drain coalesced records");
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0].from_peer_id(), peer(2));
        assert_eq!(drained[1].from_peer_id(), peer(1));
        assert_eq!(stream.pending_len(), 0);

        let mut tight_stream = RelayTcpTlsStreamBuffer::new(
            RelayQuota::default().max_packet_bytes,
            first_record.len(),
        )
        .expect("tight stream buffer");
        tight_stream
            .push_bytes(&first_record)
            .expect("fill buffer exactly with one record");
        assert_eq!(
            tight_stream
                .push_bytes(&[0])
                .expect_err("bounded buffer rejects unbounded stream growth"),
            RelayError::PacketTooLarge
        );
        assert_eq!(tight_stream.pending_len(), first_record.len());
        tight_stream.clear();
        assert_eq!(tight_stream.pending_len(), 0);

        let undersized_cap = first_record.len() - 1;
        let mut undersized_stream =
            RelayTcpTlsStreamBuffer::new(RelayQuota::default().max_packet_bytes, undersized_cap)
                .expect("undersized stream buffer still holds minimum record header");
        undersized_stream
            .push_bytes(&first_record[..undersized_cap])
            .expect("fill undersized buffer with incomplete record");
        assert_eq!(
            undersized_stream
                .pop_next_frame()
                .expect_err("record that can never fit the buffer fails closed"),
            RelayError::PacketTooLarge
        );
        assert_eq!(undersized_stream.pending_len(), undersized_cap);

        let udp_frame = RelayWireFrame::new(
            reservation_id(39),
            transfer_nonce(9),
            peer(1),
            packet(RelayTransport::Udp, b"udp-in-stream-buffer", 3),
        );
        let udp_encoded = udp_frame
            .encode(RelayQuota::default().max_packet_bytes)
            .expect("encode raw udp relay frame");
        let udp_len = u32::try_from(udp_encoded.len()).expect("udp frame len fits in u32");
        let mut udp_record =
            Vec::with_capacity(RELAY_WIRE_TCP_TLS_RECORD_PREFIX_LEN + udp_encoded.len());
        udp_record.extend_from_slice(&udp_len.to_be_bytes());
        udp_record.extend_from_slice(&udp_encoded);
        stream.push_bytes(&udp_record).expect("buffer bad record");
        assert_eq!(
            stream
                .pop_next_frame()
                .expect_err("stream buffer rejects udp record on tcp path"),
            RelayError::InvalidRelayWireFrame
        );
        assert_eq!(
            stream.pending_len(),
            udp_record.len(),
            "malformed bytes are retained for caller diagnostics before close"
        );
    }

    #[test]
    fn udp_socket_ingress_and_egress_round_trip_without_plaintext_authority() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        service
            .reserve(
                10,
                reservation_id(40),
                "path-relay-40",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");

        let frame = RelayWireFrame::new(
            reservation_id(40),
            transfer_nonce(9),
            peer(1),
            packet_sent_at(RelayTransport::Udp, b"udp-socket-ciphertext", 1, 90),
        );
        let encoded = frame
            .encode(RelayQuota::default().max_packet_bytes)
            .expect("encode udp datagram");
        assert_eq!(
            service
                .forward_udp_datagram(
                    124,
                    peer(3),
                    &encoded,
                    RelayQuota::default().max_packet_bytes
                )
                .expect_err("endpoint peer mismatch must not forward"),
            RelayError::UnauthorizedPeer
        );
        assert_eq!(
            service
                .proof_artifact(reservation_id(40))
                .expect("proof after rejected endpoint mismatch")
                .packets_forwarded,
            0
        );
        assert!(service.events().iter().any(|event| {
            event.kind == RelayEventKind::AuthorizationRejected
                && event.transport == Some(RelayTransport::Udp)
                && event.quota_decision == "endpoint_peer_mismatch_rejected"
        }));
        let forwarded = service
            .forward_udp_datagram(
                125,
                peer(1),
                &encoded,
                RelayQuota::default().max_packet_bytes,
            )
            .expect("udp datagram forwards");
        assert_eq!(forwarded.to_peer_id(), peer(2));
        assert_eq!(forwarded.packet().opaque_bytes(), b"udp-socket-ciphertext");

        let dst_addr = SocketAddr::from(([127, 0, 0, 1], 45_000));
        let datagram = service
            .dequeue_udp_datagram_for_peer(
                peer(2),
                dst_addr,
                RelayQuota::default().max_packet_bytes,
            )
            .expect("encode outbound udp datagram")
            .expect("queued udp packet");
        assert_eq!(datagram.dst_addr(), dst_addr);
        assert_eq!(datagram.to_peer_id(), peer(2));
        assert_eq!(datagram.reservation_id(), reservation_id(40));
        assert_eq!(
            datagram.opaque_bytes(),
            u64::try_from(b"udp-socket-ciphertext".len()).expect("ciphertext len fits in u64")
        );

        let decoded =
            RelayWireFrame::decode(datagram.payload(), RelayQuota::default().max_packet_bytes)
                .expect("decode outbound datagram frame");
        assert_eq!(decoded.reservation_id(), reservation_id(40));
        assert_eq!(decoded.transfer_nonce(), transfer_nonce(9));
        assert_eq!(decoded.from_peer_id(), peer(1));
        assert_eq!(decoded.packet().transport(), RelayTransport::Udp);
        assert_eq!(decoded.packet().opaque_bytes(), b"udp-socket-ciphertext");
        assert!(
            service
                .dequeue_udp_datagram_for_peer(
                    peer(2),
                    dst_addr,
                    RelayQuota::default().max_packet_bytes
                )
                .expect("empty udp queue")
                .is_none()
        );
    }

    #[test]
    fn udp_socket_egress_peek_does_not_consume_before_commit() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        service
            .reserve(
                10,
                reservation_id(41),
                "path-relay-41",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");

        let frame = RelayWireFrame::new(
            reservation_id(41),
            transfer_nonce(9),
            peer(1),
            packet_sent_at(RelayTransport::Udp, b"udp-peek-ciphertext", 1, 90),
        );
        let encoded = frame
            .encode(RelayQuota::default().max_packet_bytes)
            .expect("encode udp datagram");
        service
            .forward_udp_datagram(
                125,
                peer(1),
                &encoded,
                RelayQuota::default().max_packet_bytes,
            )
            .expect("udp datagram forwards");

        let dst_addr = SocketAddr::from(([127, 0, 0, 1], 45_001));
        let first = service
            .peek_udp_datagram_for_peer(peer(2), dst_addr, RelayQuota::default().max_packet_bytes)
            .expect("peek queued udp")
            .expect("queued udp packet");
        let second = service
            .peek_udp_datagram_for_peer(peer(2), dst_addr, RelayQuota::default().max_packet_bytes)
            .expect("peek queued udp again")
            .expect("queue remains intact after peek");
        assert_eq!(first, second);
        assert_eq!(
            service
                .commit_udp_datagram_for_peer(peer(2), reservation_id(999))
                .expect_err("wrong reservation does not consume queue"),
            RelayError::UnknownReservation
        );
        assert!(
            service
                .peek_udp_datagram_for_peer(
                    peer(2),
                    dst_addr,
                    RelayQuota::default().max_packet_bytes
                )
                .expect("peek after failed commit")
                .is_some()
        );

        service
            .commit_udp_datagram_for_peer(peer(2), reservation_id(41))
            .expect("commit sent datagram");
        assert!(
            service
                .peek_udp_datagram_for_peer(
                    peer(2),
                    dst_addr,
                    RelayQuota::default().max_packet_bytes
                )
                .expect("empty queue after commit")
                .is_none()
        );
    }

    #[test]
    fn tcp_tls_egress_peek_does_not_consume_before_commit() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        service
            .reserve(
                10,
                reservation_id(43),
                "path-relay-43",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");
        service
            .forward(
                125,
                reservation_id(43),
                peer(1),
                packet_sent_at(RelayTransport::TcpTls443, b"tcp-peek-ciphertext", 1, 90),
            )
            .expect("tcp fallback packet forwards");

        let first = service
            .peek_tcp_tls_record_for_peer(peer(2), RelayQuota::default().max_packet_bytes)
            .expect("peek queued tcp")
            .expect("queued tcp packet");
        let second = service
            .peek_tcp_tls_record_for_peer(peer(2), RelayQuota::default().max_packet_bytes)
            .expect("peek queued tcp again")
            .expect("queue remains intact after tcp peek");
        assert_eq!(first, second);
        assert_eq!(
            service
                .commit_tcp_tls_record_for_peer(peer(2), reservation_id(999))
                .expect_err("wrong reservation does not consume tcp queue"),
            RelayError::UnknownReservation
        );
        assert!(
            service
                .peek_tcp_tls_record_for_peer(peer(2), RelayQuota::default().max_packet_bytes)
                .expect("peek after failed tcp commit")
                .is_some()
        );

        service
            .commit_tcp_tls_record_for_peer(peer(2), reservation_id(43))
            .expect("commit sent tcp record");
        assert!(
            service
                .peek_tcp_tls_record_for_peer(peer(2), RelayQuota::default().max_packet_bytes)
                .expect("empty tcp queue after commit")
                .is_none()
        );
    }

    #[test]
    fn tcp_tls_socket_write_uses_explicit_stream_binding_before_dequeue() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        service
            .reserve(
                10,
                reservation_id(44),
                "path-relay-44",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");
        service
            .forward(
                125,
                reservation_id(44),
                peer(1),
                packet_sent_at(RelayTransport::TcpTls443, b"stream-bound-ciphertext", 1, 90),
            )
            .expect("tcp fallback packet forwards");

        let mut socket_loop = RelaySocketLoop::new(
            RelayEndpointDirectoryQuota {
                max_udp_endpoints: 1,
                max_tcp_tls_streams: 2,
            },
            RelayQuota::default().max_packet_bytes,
            1024,
        )
        .expect("socket loop");
        let source_stream = RelayTcpTlsStreamId::new(44).expect("source stream");
        let destination_stream = RelayTcpTlsStreamId::new(45).expect("destination stream");
        socket_loop
            .admit_tcp_tls_stream(peer(1), source_stream)
            .expect("admit source stream");
        socket_loop
            .admit_tcp_tls_stream(peer(2), destination_stream)
            .expect("admit destination stream");

        let mut wrong_writer = Vec::new();
        assert_eq!(
            socket_loop
                .send_tcp_tls_stream_once(&mut service, source_stream, &mut wrong_writer)
                .expect("source stream has no outbound record"),
            None
        );
        assert!(wrong_writer.is_empty());
        assert!(
            service
                .peek_tcp_tls_record_for_peer(peer(2), RelayQuota::default().max_packet_bytes)
                .expect("destination queue remains after wrong stream id")
                .is_some()
        );

        let mut destination_writer = Vec::new();
        let written = socket_loop
            .send_tcp_tls_stream_once(&mut service, destination_stream, &mut destination_writer)
            .expect("destination stream writes queued record")
            .expect("bytes written");
        assert_eq!(written, destination_writer.len());
        let decoded = RelayWireFrame::decode_complete_tcp_tls_record(
            &destination_writer,
            RelayQuota::default().max_packet_bytes,
        )
        .expect("decode written record");
        assert_eq!(decoded.from_peer_id(), peer(1));
        assert_eq!(decoded.packet().opaque_bytes(), b"stream-bound-ciphertext");
        assert!(
            service
                .peek_tcp_tls_record_for_peer(peer(2), RelayQuota::default().max_packet_bytes)
                .expect("queue drained only after destination stream write")
                .is_none()
        );
    }

    #[test]
    fn tcp_tls_socket_write_commits_queue_only_after_positive_write() {
        struct WouldBlockWriter;

        impl io::Write for WouldBlockWriter {
            fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
                Err(io::Error::from(io::ErrorKind::WouldBlock))
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        struct ZeroWriter;

        impl io::Write for ZeroWriter {
            fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
                Ok(0)
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        struct PrefixWriter {
            max_write: usize,
            bytes: Vec<u8>,
        }

        impl io::Write for PrefixWriter {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                let accepted = self.max_write.min(buf.len());
                self.bytes.extend_from_slice(&buf[..accepted]);
                Ok(accepted)
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let mut service = RelayService::new(RelayServiceConfig::default());
        service
            .reserve(
                10,
                reservation_id(45),
                "path-relay-45",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");
        service
            .forward(
                125,
                reservation_id(45),
                peer(1),
                packet_sent_at(
                    RelayTransport::TcpTls443,
                    b"commit-after-positive-write",
                    1,
                    90,
                ),
            )
            .expect("tcp fallback packet forwards");

        let mut socket_loop = RelaySocketLoop::new(
            RelayEndpointDirectoryQuota {
                max_udp_endpoints: 1,
                max_tcp_tls_streams: 1,
            },
            RelayQuota::default().max_packet_bytes,
            1024,
        )
        .expect("socket loop");
        let destination_stream = RelayTcpTlsStreamId::new(45).expect("destination stream");
        socket_loop
            .admit_tcp_tls_stream(peer(2), destination_stream)
            .expect("admit destination stream");

        let err = socket_loop
            .send_tcp_tls_stream_once(&mut service, destination_stream, &mut WouldBlockWriter)
            .expect_err("would-block must not commit queued tcp record");
        assert!(matches!(err, RelaySocketIoError::WouldBlock));
        assert_eq!(socket_loop.tcp_tls_pending_write_count(), 0);
        assert!(
            service
                .peek_tcp_tls_record_for_peer(peer(2), RelayQuota::default().max_packet_bytes)
                .expect("peek after would-block")
                .is_some()
        );

        let err = socket_loop
            .send_tcp_tls_stream_once(&mut service, destination_stream, &mut ZeroWriter)
            .expect_err("zero write must not commit queued tcp record");
        match err {
            RelaySocketIoError::TcpTlsWriteZero {
                stream_id,
                remaining,
            } => {
                assert_eq!(stream_id, destination_stream);
                assert!(remaining > 0);
            }
            other => panic!("unexpected zero-write error: {other:?}"),
        }
        assert_eq!(socket_loop.tcp_tls_pending_write_count(), 0);
        assert!(
            service
                .peek_tcp_tls_record_for_peer(peer(2), RelayQuota::default().max_packet_bytes)
                .expect("peek after zero write")
                .is_some()
        );

        let mut partial_writer = PrefixWriter {
            max_write: 7,
            bytes: Vec::new(),
        };
        let first_write = socket_loop
            .send_tcp_tls_stream_once(&mut service, destination_stream, &mut partial_writer)
            .expect("positive prefix write")
            .expect("bytes written");
        assert_eq!(first_write, 7);
        assert!(socket_loop.tcp_tls_pending_write_len(destination_stream) > 0);
        assert!(
            service
                .peek_tcp_tls_record_for_peer(peer(2), RelayQuota::default().max_packet_bytes)
                .expect("peek after positive write")
                .is_none()
        );

        partial_writer.max_write = usize::MAX;
        while socket_loop.tcp_tls_pending_write_len(destination_stream) > 0 {
            let written = socket_loop
                .send_tcp_tls_stream_once(&mut service, destination_stream, &mut partial_writer)
                .expect("flush retained tcp suffix")
                .expect("suffix bytes written");
            assert!(written > 0);
        }
        assert_eq!(socket_loop.tcp_tls_pending_write_count(), 0);

        let decoded = RelayWireFrame::decode_complete_tcp_tls_record(
            &partial_writer.bytes,
            RelayQuota::default().max_packet_bytes,
        )
        .expect("decode fully written record");
        assert_eq!(decoded.from_peer_id(), peer(1));
        assert_eq!(
            decoded.packet().opaque_bytes(),
            b"commit-after-positive-write"
        );
    }

    #[test]
    fn endpoint_admission_helpers_reject_unknown_or_mismatched_socket_sources() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        service
            .reserve(
                10,
                reservation_id(42),
                "path-relay-42",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");
        let mut directory = RelayEndpointDirectory::default();
        let source_udp = SocketAddr::from(([203, 0, 113, 10], 47_000));
        let wrong_udp = SocketAddr::from(([203, 0, 113, 11], 47_001));
        let source_stream = RelayTcpTlsStreamId::new(42).expect("source stream");
        let wrong_stream = RelayTcpTlsStreamId::new(43).expect("wrong stream");
        directory
            .bind_udp_endpoint(peer(1), source_udp)
            .expect("bind source udp");
        directory
            .bind_udp_endpoint(peer(3), wrong_udp)
            .expect("bind wrong udp");
        directory
            .bind_tcp_tls_stream(peer(1), source_stream)
            .expect("bind source stream");
        directory
            .bind_tcp_tls_stream(peer(3), wrong_stream)
            .expect("bind wrong stream");

        let udp_frame = RelayWireFrame::new(
            reservation_id(42),
            transfer_nonce(9),
            peer(1),
            packet_sent_at(RelayTransport::Udp, b"udp-endpoint-ciphertext", 1, 90),
        );
        let udp_datagram = udp_frame
            .encode(RelayQuota::default().max_packet_bytes)
            .expect("encode udp datagram");
        assert_eq!(
            service
                .forward_udp_datagram_from_endpoint(
                    100,
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
                .proof_artifact(reservation_id(42))
                .expect("proof after unknown udp endpoint")
                .packets_forwarded,
            0
        );
        assert_eq!(
            service
                .forward_udp_datagram_from_endpoint(
                    101,
                    &directory,
                    wrong_udp,
                    &udp_datagram,
                    RelayQuota::default().max_packet_bytes,
                )
                .expect_err("mismatched udp endpoint"),
            RelayError::UnauthorizedPeer
        );
        let udp_forwarded = service
            .forward_udp_datagram_from_endpoint(
                102,
                &directory,
                source_udp,
                &udp_datagram,
                RelayQuota::default().max_packet_bytes,
            )
            .expect("forward admitted udp endpoint");
        assert_eq!(udp_forwarded.to_peer_id(), peer(2));

        let tcp_frame = RelayWireFrame::new(
            reservation_id(42),
            transfer_nonce(9),
            peer(1),
            packet_sent_at(
                RelayTransport::TcpTls443,
                b"tcp-endpoint-ciphertext",
                2,
                110,
            ),
        );
        let tcp_record = tcp_frame
            .encode_tcp_tls_record(RelayQuota::default().max_packet_bytes)
            .expect("encode tcp record");
        let mut unknown_stream_buffer =
            RelayTcpTlsStreamBuffer::new(RelayQuota::default().max_packet_bytes, tcp_record.len())
                .expect("unknown stream buffer");
        assert_eq!(
            service
                .forward_tcp_tls_stream_bytes_from_endpoint(
                    120,
                    &directory,
                    RelayTcpTlsStreamId::new(44).expect("unknown stream"),
                    &mut unknown_stream_buffer,
                    &tcp_record,
                )
                .expect_err("unknown tcp stream"),
            RelayError::UnknownRelayEndpoint
        );
        assert_eq!(unknown_stream_buffer.pending_len(), 0);

        let mut wrong_stream_buffer =
            RelayTcpTlsStreamBuffer::new(RelayQuota::default().max_packet_bytes, tcp_record.len())
                .expect("wrong stream buffer");
        assert_eq!(
            service
                .forward_tcp_tls_stream_bytes_from_endpoint(
                    121,
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
                && event.quota_decision == "endpoint_peer_mismatch_rejected"
                && event.transport == Some(RelayTransport::TcpTls443)
        }));

        let mut source_stream_buffer =
            RelayTcpTlsStreamBuffer::new(RelayQuota::default().max_packet_bytes, tcp_record.len())
                .expect("source stream buffer");
        let tcp_forwarded = service
            .forward_tcp_tls_stream_bytes_from_endpoint(
                122,
                &directory,
                source_stream,
                &mut source_stream_buffer,
                &tcp_record,
            )
            .expect("forward admitted tcp stream");
        assert_eq!(tcp_forwarded.len(), 1);
        assert_eq!(tcp_forwarded[0].to_peer_id(), peer(2));
    }

    #[test]
    fn tcp_listener_accept_allocates_and_admits_stream_ids() {
        let mut socket_loop = RelaySocketLoop::new(
            RelayEndpointDirectoryQuota {
                max_udp_endpoints: 1,
                max_tcp_tls_streams: 1,
            },
            RelayQuota::default().max_packet_bytes,
            1024,
        )
        .expect("socket loop");
        let listener =
            TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).expect("bind listener");
        listener
            .set_nonblocking(true)
            .expect("listener nonblocking");
        assert!(
            socket_loop
                .accept_tcp_tls_stream_once(&listener, peer(1))
                .expect("empty nonblocking accept")
                .is_none()
        );
        listener
            .set_nonblocking(false)
            .expect("listener blocking for deterministic accept");

        let client = TcpStream::connect(listener.local_addr().expect("listener addr"))
            .expect("client connects");
        let accepted = socket_loop
            .accept_tcp_tls_stream_once(&listener, peer(1))
            .expect("accept stream")
            .expect("accepted stream");
        assert_eq!(accepted.stream_id().get(), 1);
        assert_eq!(accepted.peer_id(), peer(1));
        assert_eq!(
            accepted.peer_addr(),
            client.local_addr().expect("client local addr")
        );
        assert_eq!(
            socket_loop
                .endpoints()
                .peer_for_tcp_tls_stream(accepted.stream_id())
                .expect("accepted stream admitted"),
            peer(1)
        );
        assert_eq!(socket_loop.tcp_tls_stream_buffer_count(), 1);

        let _second_client = TcpStream::connect(listener.local_addr().expect("listener addr"))
            .expect("second client connects");
        let err = socket_loop
            .accept_tcp_tls_stream_once(&listener, peer(2))
            .expect_err("quota prevents second accepted stream");
        match err {
            RelaySocketIoError::Relay {
                source: RelayError::QuotaExceeded,
            } => {}
            other => panic!("unexpected accept error: {other:?}"),
        }
        assert_eq!(socket_loop.endpoints().tcp_tls_stream_count(), 1);
        assert_eq!(socket_loop.tcp_tls_stream_buffer_count(), 1);
    }

    #[test]
    fn relay_socket_loop_bridges_admitted_endpoints_and_closes_bad_streams() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        service
            .reserve(
                10,
                reservation_id(48),
                "path-relay-48",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");
        let mut socket_loop = RelaySocketLoop::new(
            RelayEndpointDirectoryQuota {
                max_udp_endpoints: 4,
                max_tcp_tls_streams: 4,
            },
            RelayQuota::default().max_packet_bytes,
            1024,
        )
        .expect("socket loop");
        let source_udp = SocketAddr::from(([203, 0, 113, 40], 47_040));
        let destination_udp = SocketAddr::from(([203, 0, 113, 41], 47_041));
        let source_stream = RelayTcpTlsStreamId::new(48).expect("source stream");
        let destination_stream = RelayTcpTlsStreamId::new(49).expect("destination stream");
        let orphaned_stream = RelayTcpTlsStreamId::new(50).expect("orphaned stream");

        socket_loop
            .admit_udp_endpoint(peer(1), source_udp)
            .expect("admit source udp");
        socket_loop
            .admit_udp_endpoint(peer(2), destination_udp)
            .expect("admit destination udp");
        socket_loop
            .admit_tcp_tls_stream(peer(1), source_stream)
            .expect("admit source tcp");
        socket_loop
            .admit_tcp_tls_stream(peer(2), destination_stream)
            .expect("admit destination tcp");
        socket_loop
            .admit_tcp_tls_stream(peer(1), orphaned_stream)
            .expect("admit stream for orphan-buffer regression");
        socket_loop.tcp_tls_streams.remove(&orphaned_stream);
        assert_eq!(
            socket_loop
                .ingest_tcp_tls_stream_bytes(&mut service, 80, orphaned_stream, b"")
                .expect_err("admitted stream without buffer fails closed"),
            RelayError::UnknownRelayEndpoint
        );
        assert_eq!(
            socket_loop
                .endpoints()
                .peer_for_tcp_tls_stream(orphaned_stream)
                .expect_err("orphaned stream binding is removed"),
            RelayError::UnknownRelayEndpoint
        );
        assert_eq!(socket_loop.endpoints().udp_endpoint_count(), 2);
        assert_eq!(socket_loop.tcp_tls_stream_buffer_count(), 2);

        let udp_frame = RelayWireFrame::new(
            reservation_id(48),
            transfer_nonce(9),
            peer(1),
            packet_sent_at(RelayTransport::Udp, b"loop-udp-ciphertext", 1, 90),
        );
        let udp_datagram = udp_frame
            .encode(RelayQuota::default().max_packet_bytes)
            .expect("encode udp datagram");
        let udp_forwarded = socket_loop
            .ingest_udp_datagram(&mut service, 100, source_udp, &udp_datagram)
            .expect("ingest admitted udp datagram");
        assert_eq!(udp_forwarded.to_peer_id(), peer(2));
        assert_eq!(
            socket_loop
                .drain_udp_datagram_for_peer(&mut service, peer(3))
                .expect_err("unknown udp destination"),
            RelayError::UnknownRelayEndpoint
        );
        let drained_udp = socket_loop
            .drain_udp_datagram_for_peer(&mut service, peer(2))
            .expect("drain udp")
            .expect("queued udp datagram");
        assert_eq!(drained_udp.dst_addr(), destination_udp);
        let decoded_udp = RelayWireFrame::decode(
            drained_udp.payload(),
            RelayQuota::default().max_packet_bytes,
        )
        .expect("decode drained udp");
        assert_eq!(decoded_udp.from_peer_id(), peer(1));
        assert_eq!(decoded_udp.packet().opaque_bytes(), b"loop-udp-ciphertext");

        let tcp_frame = RelayWireFrame::new(
            reservation_id(48),
            transfer_nonce(9),
            peer(1),
            packet_sent_at(RelayTransport::TcpTls443, b"loop-tcp-ciphertext", 2, 110),
        );
        let tcp_record = tcp_frame
            .encode_tcp_tls_record(RelayQuota::default().max_packet_bytes)
            .expect("encode tcp record");
        assert_eq!(
            socket_loop
                .ingest_tcp_tls_stream_bytes(&mut service, 120, source_stream, &tcp_record[..2])
                .expect("partial tcp prefix"),
            Vec::new()
        );
        assert_eq!(
            socket_loop
                .tcp_tls_pending_len(source_stream)
                .expect("source pending bytes"),
            2
        );
        let tcp_forwarded = socket_loop
            .ingest_tcp_tls_stream_bytes(&mut service, 121, source_stream, &tcp_record[2..])
            .expect("complete tcp record");
        assert_eq!(tcp_forwarded.len(), 1);
        let drained_tcp = socket_loop
            .drain_tcp_tls_record_for_peer(&mut service, peer(2))
            .expect("drain tcp")
            .expect("queued tcp record");
        assert_eq!(drained_tcp.stream_id(), destination_stream);
        assert_eq!(drained_tcp.to_peer_id(), peer(2));
        let decoded_tcp = RelayWireFrame::decode_complete_tcp_tls_record(
            drained_tcp.bytes(),
            RelayQuota::default().max_packet_bytes,
        )
        .expect("decode drained tcp");
        assert_eq!(decoded_tcp.packet().opaque_bytes(), b"loop-tcp-ciphertext");

        let mismatch_frame = RelayWireFrame::new(
            reservation_id(48),
            transfer_nonce(9),
            peer(3),
            packet_sent_at(RelayTransport::TcpTls443, b"bad-stream-ciphertext", 3, 130),
        );
        let mismatch_record = mismatch_frame
            .encode_tcp_tls_record(RelayQuota::default().max_packet_bytes)
            .expect("encode mismatch record");
        assert_eq!(
            socket_loop
                .ingest_tcp_tls_stream_bytes(&mut service, 140, source_stream, &mismatch_record)
                .expect_err("mismatched stream source"),
            RelayError::UnauthorizedPeer
        );
        assert_eq!(
            socket_loop
                .tcp_tls_pending_len(source_stream)
                .expect_err("bad stream closed"),
            RelayError::UnknownRelayEndpoint
        );
        assert_eq!(
            socket_loop
                .close_tcp_tls_stream(destination_stream)
                .expect("close destination stream"),
            peer(2)
        );
        assert_eq!(
            socket_loop
                .drain_tcp_tls_record_for_peer(&mut service, peer(2))
                .expect_err("closed tcp destination"),
            RelayError::UnknownRelayEndpoint
        );
    }

    #[test]
    fn socket_adapters_fail_closed_and_preserve_transport_order() {
        let config = RelayServiceConfig::default().with_udp_enabled(false);
        let mut service = RelayService::new(config);
        service
            .reserve(
                10,
                reservation_id(41),
                "path-relay-41",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");

        let tcp_frame = RelayWireFrame::new(
            reservation_id(41),
            transfer_nonce(9),
            peer(1),
            packet_sent_at(RelayTransport::TcpTls443, b"tcp-stream-ciphertext", 1, 90),
        );
        let canonical_tcp_frame = tcp_frame
            .encode(RelayQuota::default().max_packet_bytes)
            .expect("encode canonical tcp frame");
        assert_eq!(
            service
                .forward_udp_datagram(
                    100,
                    peer(1),
                    &canonical_tcp_frame,
                    RelayQuota::default().max_packet_bytes
                )
                .expect_err("tcp frame must not enter udp datagram ingress"),
            RelayError::InvalidRelayWireFrame
        );
        assert_eq!(
            service
                .proof_artifact(reservation_id(41))
                .expect("proof after rejected udp ingress")
                .packets_forwarded,
            0
        );

        let tcp_record = tcp_frame
            .encode_tcp_tls_record(RelayQuota::default().max_packet_bytes)
            .expect("encode tcp record");
        let mut mismatched_stream =
            RelayTcpTlsStreamBuffer::new(RelayQuota::default().max_packet_bytes, tcp_record.len())
                .expect("mismatched stream buffer");
        assert_eq!(
            service
                .forward_tcp_tls_stream_bytes(124, peer(3), &mut mismatched_stream, &tcp_record)
                .expect_err("endpoint peer mismatch must not forward tcp record"),
            RelayError::UnauthorizedPeer
        );
        assert_eq!(
            service
                .proof_artifact(reservation_id(41))
                .expect("proof after rejected tcp endpoint mismatch")
                .packets_forwarded,
            0
        );
        assert!(service.events().iter().any(|event| {
            event.kind == RelayEventKind::AuthorizationRejected
                && event.transport == Some(RelayTransport::TcpTls443)
                && event.quota_decision == "endpoint_peer_mismatch_rejected"
        }));
        let mut stream =
            RelayTcpTlsStreamBuffer::new(RelayQuota::default().max_packet_bytes, tcp_record.len())
                .expect("stream buffer");
        let forwarded = service
            .forward_tcp_tls_stream_bytes(125, peer(1), &mut stream, &tcp_record)
            .expect("tcp stream forwards");
        assert_eq!(forwarded.len(), 1);

        let dst_addr = SocketAddr::from(([127, 0, 0, 1], 45_001));
        assert!(
            service
                .dequeue_udp_datagram_for_peer(
                    peer(2),
                    dst_addr,
                    RelayQuota::default().max_packet_bytes
                )
                .expect("udp egress sees tcp front and preserves it")
                .is_none()
        );
        let record = service
            .dequeue_tcp_tls_record_for_peer(peer(2), RelayQuota::default().max_packet_bytes)
            .expect("encode outbound tcp record")
            .expect("queued tcp packet");
        assert_eq!(record.to_peer_id(), peer(2));
        assert_eq!(record.reservation_id(), reservation_id(41));
        assert_eq!(
            record.opaque_bytes(),
            u64::try_from(b"tcp-stream-ciphertext".len()).expect("ciphertext len fits in u64")
        );
        let decoded = RelayWireFrame::decode_complete_tcp_tls_record(
            record.bytes(),
            RelayQuota::default().max_packet_bytes,
        )
        .expect("decode outbound tcp record");
        assert_eq!(decoded.from_peer_id(), peer(1));
        assert_eq!(decoded.packet().transport(), RelayTransport::TcpTls443);
        assert_eq!(decoded.packet().opaque_bytes(), b"tcp-stream-ciphertext");
        assert!(
            service
                .dequeue_tcp_tls_record_for_peer(peer(2), RelayQuota::default().max_packet_bytes)
                .expect("empty tcp queue")
                .is_none()
        );
    }

    #[test]
    fn dequeue_removes_empty_peer_queue_from_restart_snapshot() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        service
            .reserve(
                10,
                reservation_id(25),
                "path-relay-25",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");
        service
            .forward(
                20,
                reservation_id(25),
                peer(1),
                packet(RelayTransport::Udp, b"ciphertext", 1),
            )
            .expect("forward");

        assert!(service.dequeue_for_peer(peer(2)).is_some());
        let snapshot = service.snapshot();
        assert!(
            snapshot
                .queues
                .iter()
                .all(|(queued_peer, _)| *queued_peer != peer(2))
        );
        assert!(
            snapshot
                .queues
                .iter()
                .all(|(_, queued_packets)| !queued_packets.is_empty())
        );
    }

    #[test]
    fn rejects_quota_overflow_and_logs_rejection() {
        let quota = RelayQuota {
            max_packets_per_reservation: 1,
            max_bytes_per_reservation: 4,
            max_packet_bytes: 4,
        };
        let mut service = RelayService::new(RelayServiceConfig::default());
        service
            .reserve(
                10,
                reservation_id(4),
                "path-relay-4",
                grant(1_000, quota),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");

        service
            .forward(
                20,
                reservation_id(4),
                peer(1),
                packet(RelayTransport::Udp, b"abcd", 1),
            )
            .expect("first packet");
        assert_eq!(
            service
                .forward(
                    21,
                    reservation_id(4),
                    peer(1),
                    packet(RelayTransport::Udp, b"e", 2)
                )
                .expect_err("quota"),
            RelayError::QuotaExceeded
        );
        assert!(
            service
                .events()
                .iter()
                .any(|event| event.kind == RelayEventKind::QuotaRejected)
        );
    }

    #[test]
    fn rejects_expired_reservations_and_unauthorized_peers() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        assert_eq!(
            service
                .reserve(
                    20,
                    reservation_id(5),
                    "expired",
                    grant(20, RelayQuota::default()),
                    &|_: &RelayReservationGrant| true,
                )
                .expect_err("expired"),
            RelayError::ExpiredReservation
        );

        service
            .reserve(
                10,
                reservation_id(6),
                "path-relay-6",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");
        assert_eq!(
            service
                .forward(
                    20,
                    reservation_id(6),
                    peer(3),
                    packet(RelayTransport::Udp, b"ciphertext", 1)
                )
                .expect_err("unauthorized"),
            RelayError::UnauthorizedPeer
        );
    }

    #[test]
    fn invalid_grant_authorization_is_logged_without_accepting_reservation() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        assert_eq!(
            service
                .reserve(
                    10,
                    reservation_id(17),
                    "path-relay-17",
                    grant(1_000, RelayQuota::default()),
                    &|_: &RelayReservationGrant| false,
                )
                .expect_err("auth"),
            RelayError::InvalidAuthorization
        );

        let event = service.events().last().expect("auth event");
        assert_eq!(event.kind, RelayEventKind::AuthorizationRejected);
        assert_eq!(event.reservation_id, Some(reservation_id(17)));
        assert_eq!(event.path_id.as_deref(), Some("path-relay-17"));
        assert_eq!(event.from_peer.as_deref(), Some("peer:redacted"));
        assert_eq!(event.to_peer.as_deref(), Some("peer:redacted"));
        assert_eq!(event.transport, None);
        assert_eq!(event.opaque_bytes, 0);
        assert_eq!(event.quota_decision, "grant_authorization_rejected");
        assert_eq!(
            service
                .proof_artifact(reservation_id(17))
                .expect_err("rejected reservation must not be installed"),
            RelayError::UnknownReservation
        );
    }

    #[test]
    fn invalid_grant_authorization_precedes_duplicate_and_capacity_checks() {
        let config = RelayServiceConfig::new("tiny-relay", 1).expect("config");
        let mut service = RelayService::new(config);
        service
            .reserve(
                10,
                reservation_id(19),
                "path-relay-19",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");

        assert_eq!(
            service
                .reserve(
                    11,
                    reservation_id(19),
                    "path-relay-duplicate-invalid",
                    grant(1_000, RelayQuota::default()),
                    &|_: &RelayReservationGrant| false,
                )
                .expect_err("invalid duplicate grant"),
            RelayError::InvalidAuthorization
        );
        assert_eq!(
            service
                .reserve(
                    12,
                    reservation_id(20),
                    "path-relay-over-capacity-invalid",
                    grant(1_000, RelayQuota::default()),
                    &|_: &RelayReservationGrant| false,
                )
                .expect_err("invalid over-capacity grant"),
            RelayError::InvalidAuthorization
        );

        let auth_rejections = service
            .events()
            .iter()
            .filter(|event| event.kind == RelayEventKind::AuthorizationRejected)
            .count();
        assert_eq!(auth_rejections, 2);
        assert!(
            service
                .events()
                .iter()
                .all(|event| event.quota_decision != "active_reservation_quota_rejected")
        );
    }

    #[test]
    fn invalid_grant_authorization_precedes_expiry_check() {
        let mut service = RelayService::new(RelayServiceConfig::default());

        assert_eq!(
            service
                .reserve(
                    20,
                    reservation_id(32),
                    "path-relay-32",
                    grant(20, RelayQuota::default()),
                    &|_: &RelayReservationGrant| false,
                )
                .expect_err("invalid expired grant"),
            RelayError::InvalidAuthorization
        );

        let event = service.events().last().expect("auth rejection event");
        assert_eq!(event.kind, RelayEventKind::AuthorizationRejected);
        assert_eq!(event.reservation_id, Some(reservation_id(32)));
        assert_eq!(event.quota_decision, "grant_authorization_rejected");
        assert_eq!(event.path_id.as_deref(), Some("path-relay-32"));
        assert_eq!(
            service
                .proof_artifact(reservation_id(32))
                .expect_err("invalid grant must not install expired reservation"),
            RelayError::UnknownReservation
        );
    }

    #[test]
    fn unauthorized_peer_rejection_is_logged_before_transport_policy() {
        let config = RelayServiceConfig::default().with_tcp_tls_443_enabled(false);
        let mut service = RelayService::new(config);
        service
            .reserve(
                10,
                reservation_id(18),
                "path-relay-18",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");

        assert_eq!(
            service
                .forward(
                    20,
                    reservation_id(18),
                    peer(9),
                    packet(RelayTransport::TcpTls443, b"ciphertext", 1),
                )
                .expect_err("unauthorized"),
            RelayError::UnauthorizedPeer
        );

        let event = service.events().last().expect("auth event");
        assert_eq!(event.kind, RelayEventKind::AuthorizationRejected);
        assert_eq!(event.reservation_id, Some(reservation_id(18)));
        assert_eq!(event.from_peer.as_deref(), Some("peer:redacted"));
        assert_eq!(event.to_peer, None);
        assert_eq!(event.transport, Some(RelayTransport::TcpTls443));
        assert_eq!(event.opaque_bytes, 10);
        assert_eq!(event.quota_decision, "peer_authorization_rejected");
        assert_eq!(event.fallback_reason, None);
        assert_eq!(
            service.usage(reservation_id(18)).expect("usage"),
            RelayUsage::default()
        );
    }

    #[test]
    fn unauthorized_peer_rejection_precedes_lifecycle_state() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        service
            .reserve(
                10,
                reservation_id(21),
                "path-relay-21",
                grant(30, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");
        service
            .cancel_reservation(reservation_id(21))
            .expect("cancel");

        assert_eq!(
            service
                .forward(
                    40,
                    reservation_id(21),
                    peer(9),
                    packet(RelayTransport::Udp, b"ciphertext", 1),
                )
                .expect_err("unauthorized cancellation probe"),
            RelayError::UnauthorizedPeer
        );
        let cancelled_probe_event = service.events().last().expect("auth event");
        assert_eq!(
            cancelled_probe_event.kind,
            RelayEventKind::AuthorizationRejected
        );
        assert_eq!(
            cancelled_probe_event.quota_decision,
            "peer_authorization_rejected"
        );

        service
            .reserve(
                10,
                reservation_id(22),
                "path-relay-22",
                grant(20, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");
        assert_eq!(
            service
                .forward(
                    30,
                    reservation_id(22),
                    peer(9),
                    packet(RelayTransport::Udp, b"ciphertext", 2),
                )
                .expect_err("unauthorized expiry probe"),
            RelayError::UnauthorizedPeer
        );
        let expired_probe_event = service.events().last().expect("auth event");
        assert_eq!(
            expired_probe_event.kind,
            RelayEventKind::AuthorizationRejected
        );
        assert!(
            service
                .events()
                .iter()
                .filter(|event| event.reservation_id == Some(reservation_id(22)))
                .all(|event| event.kind != RelayEventKind::ReservationExpired)
        );
    }

    #[test]
    fn quota_rejection_logs_actual_packet_direction() {
        let quota = RelayQuota {
            max_packets_per_reservation: 4,
            max_bytes_per_reservation: 4,
            max_packet_bytes: 4,
        };
        let mut service = RelayService::new(RelayServiceConfig::default().with_log_peer_ids(true));
        service
            .reserve(
                10,
                reservation_id(23),
                "path-relay-23",
                grant(1_000, quota),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");

        assert_eq!(
            service
                .forward(
                    20,
                    reservation_id(23),
                    peer(2),
                    packet(RelayTransport::Udp, b"abcde", 1),
                )
                .expect_err("oversized reverse packet"),
            RelayError::PacketTooLarge
        );

        let event = service.events().last().expect("quota event");
        assert_eq!(event.kind, RelayEventKind::QuotaRejected);
        assert_eq!(event.reservation_id, Some(reservation_id(23)));
        assert_eq!(event.from_peer.as_deref(), Some("peer:0202..."));
        assert_eq!(event.to_peer.as_deref(), Some("peer:0101..."));
        assert_eq!(event.opaque_bytes, 5);
        assert_eq!(event.quota_decision, "packet_quota_rejected");
        assert_eq!(
            service.usage(reservation_id(23)).expect("usage"),
            RelayUsage::default()
        );
    }

    #[test]
    fn rejects_invalid_auth_and_cancelled_reservations() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        assert_eq!(
            service
                .reserve(
                    10,
                    reservation_id(7),
                    "path-relay-7",
                    grant(1_000, RelayQuota::default()),
                    &|_: &RelayReservationGrant| false,
                )
                .expect_err("auth"),
            RelayError::InvalidAuthorization
        );

        service
            .reserve(
                10,
                reservation_id(8),
                "path-relay-8",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");
        service
            .cancel_reservation(reservation_id(8))
            .expect("cancel");
        assert_eq!(
            service
                .forward(
                    20,
                    reservation_id(8),
                    peer(1),
                    packet(RelayTransport::Udp, b"ciphertext", 1)
                )
                .expect_err("cancelled"),
            RelayError::ReservationCancelled
        );
    }

    #[test]
    fn cancellation_drains_queued_packets_for_reservation() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        service
            .reserve(
                10,
                reservation_id(12),
                "path-relay-12",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");
        service
            .forward(
                20,
                reservation_id(12),
                peer(1),
                packet(RelayTransport::Udp, b"ciphertext", 1),
            )
            .expect("forward");

        service
            .cancel_reservation(reservation_id(12))
            .expect("cancel");

        assert_eq!(service.dequeue_for_peer(peer(2)), None);
        let usage = service.usage(reservation_id(12)).expect("usage");
        assert_eq!(usage.dropped_packets, 1);
        assert_eq!(
            service
                .events()
                .last()
                .expect("cancel event")
                .quota_decision,
            "reservation_cancelled_queued_packets_drained"
        );
    }

    #[test]
    fn cancel_reservation_is_idempotent_after_first_drain() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        service
            .reserve(
                10,
                reservation_id(24),
                "path-relay-24",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");
        service
            .forward(
                20,
                reservation_id(24),
                peer(1),
                packet(RelayTransport::Udp, b"ciphertext", 1),
            )
            .expect("forward");

        service
            .cancel_reservation(reservation_id(24))
            .expect("first cancel");
        let events_after_first_cancel = service.events().len();
        let usage_after_first_cancel = service.usage(reservation_id(24)).expect("usage");
        service
            .cancel_reservation(reservation_id(24))
            .expect("second cancel");

        assert_eq!(service.events().len(), events_after_first_cancel);
        assert_eq!(
            service.usage(reservation_id(24)).expect("usage"),
            usage_after_first_cancel
        );
        assert_eq!(usage_after_first_cancel.dropped_packets, 1);
        assert_eq!(service.dequeue_for_peer(peer(2)), None);
    }

    #[test]
    fn expired_reservations_do_not_consume_active_capacity() {
        let config = RelayServiceConfig::new("tiny-relay", 1).expect("config");
        let mut service = RelayService::new(config);
        service
            .reserve(
                10,
                reservation_id(13),
                "path-relay-13",
                grant(20, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("first reservation");

        let candidate = service
            .reserve(
                30,
                reservation_id(14),
                "path-relay-14",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("expired reservation should not occupy the only active slot");

        assert_eq!(candidate.reservation_id(), reservation_id(14));
        assert_eq!(service.snapshot().reservation_count(), 1);
        assert!(
            service
                .snapshot()
                .reservations
                .iter()
                .all(|(id, _)| *id != reservation_id(13))
        );
        assert!(
            service
                .events()
                .iter()
                .any(|event| event.reservation_id == Some(reservation_id(13))
                    && event.kind == RelayEventKind::ReservationExpired)
        );
    }

    #[test]
    fn forwarding_after_expiry_drains_queued_packets_and_blocks_restart_retention() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        service
            .reserve(
                10,
                reservation_id(26),
                "path-relay-26",
                grant(30, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");
        service
            .forward(
                20,
                reservation_id(26),
                peer(1),
                packet(RelayTransport::Udp, b"ciphertext", 1),
            )
            .expect("queued before expiry");

        assert_eq!(
            service
                .forward(
                    31,
                    reservation_id(26),
                    peer(1),
                    packet(RelayTransport::Udp, b"late", 2),
                )
                .expect_err("expired forward"),
            RelayError::ExpiredReservation
        );

        assert_eq!(service.dequeue_for_peer(peer(2)), None);
        let usage = service.usage(reservation_id(26)).expect("usage");
        assert_eq!(usage.forwarded_packets, 1);
        assert_eq!(usage.dropped_packets, 1);

        let event = service.events().last().expect("expiry event");
        assert_eq!(event.kind, RelayEventKind::ReservationExpired);
        assert_eq!(
            event.quota_decision,
            "reservation_expired_queued_packets_drained"
        );
        assert_eq!(event.opaque_bytes, 10);
        assert_eq!(service.snapshot().reservation_count(), 0);
    }

    #[test]
    fn expire_reservations_drains_only_expired_queues() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        service
            .reserve(
                10,
                reservation_id(27),
                "path-relay-27",
                grant(30, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("expired candidate");
        service
            .reserve(
                10,
                reservation_id(28),
                "path-relay-28",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("active candidate");
        service
            .forward(
                20,
                reservation_id(27),
                peer(1),
                packet(RelayTransport::Udp, b"expired", 1),
            )
            .expect("expired queued before cutoff");
        let active_packet = service
            .forward(
                20,
                reservation_id(28),
                peer(1),
                packet(RelayTransport::Udp, b"active", 2),
            )
            .expect("active queued");

        assert_eq!(service.expire_reservations(31), 1);
        assert_eq!(service.active_reservation_count(20), 1);
        assert_eq!(
            service.dequeue_for_peer(peer(2)).expect("active packet"),
            active_packet
        );
        assert_eq!(service.dequeue_for_peer(peer(2)), None);
        assert_eq!(
            service
                .proof_artifact(reservation_id(27))
                .expect("expired proof remains auditable")
                .packets_forwarded,
            1
        );
        assert_eq!(service.snapshot().reservation_count(), 1);
        assert_eq!(
            service
                .snapshot()
                .reservations
                .iter()
                .map(|(id, _)| *id)
                .collect::<Vec<_>>(),
            vec![reservation_id(28)]
        );
    }

    #[test]
    fn cancellation_after_expiry_is_terminal_idempotent() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        service
            .reserve(
                10,
                reservation_id(29),
                "path-relay-29",
                grant(30, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");
        service
            .forward(
                20,
                reservation_id(29),
                peer(1),
                packet(RelayTransport::Udp, b"ciphertext", 1),
            )
            .expect("queued before expiry");
        assert_eq!(
            service
                .forward(
                    31,
                    reservation_id(29),
                    peer(1),
                    packet(RelayTransport::Udp, b"late", 2),
                )
                .expect_err("expired"),
            RelayError::ExpiredReservation
        );
        let events_after_expiry = service.events().len();
        let usage_after_expiry = service.usage(reservation_id(29)).expect("usage");

        service
            .cancel_reservation(reservation_id(29))
            .expect("cancel after expiry is a no-op");

        assert_eq!(service.events().len(), events_after_expiry);
        assert_eq!(
            service.usage(reservation_id(29)).expect("usage"),
            usage_after_expiry
        );
        assert_eq!(
            service.events().last().expect("expiry event").kind,
            RelayEventKind::ReservationExpired
        );
    }

    #[test]
    fn packet_loss_after_cancellation_does_not_mutate_usage_or_proof() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        service
            .reserve(
                10,
                reservation_id(30),
                "path-relay-30",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");
        service
            .forward(
                20,
                reservation_id(30),
                peer(1),
                packet(RelayTransport::Udp, b"ciphertext", 1),
            )
            .expect("forward");
        service
            .cancel_reservation(reservation_id(30))
            .expect("cancel");

        let events_after_cancel = service.events().len();
        let usage_after_cancel = service.usage(reservation_id(30)).expect("usage");
        let proof_after_cancel = service
            .proof_artifact(reservation_id(30))
            .expect("proof artifact");

        assert_eq!(
            service
                .record_packet_loss(reservation_id(30), 1, 10)
                .expect_err("terminal reservations reject loss summaries"),
            RelayError::ReservationCancelled
        );
        assert_eq!(
            service
                .record_packet_loss(reservation_id(30), 1, 0)
                .expect_err("terminal lifecycle wins over malformed loss summary"),
            RelayError::ReservationCancelled
        );

        assert_eq!(service.events().len(), events_after_cancel);
        assert_eq!(
            service.usage(reservation_id(30)).expect("usage"),
            usage_after_cancel
        );
        assert_eq!(
            service
                .proof_artifact(reservation_id(30))
                .expect("proof artifact"),
            proof_after_cancel
        );
        assert_eq!(usage_after_cancel.loss_summary, None);
        assert_eq!(
            service.events().last().expect("cancel event").kind,
            RelayEventKind::ReservationCancelled
        );
    }

    #[test]
    fn packet_loss_after_expiry_does_not_mutate_usage_or_proof() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        service
            .reserve(
                10,
                reservation_id(31),
                "path-relay-31",
                grant(30, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");
        service
            .forward(
                20,
                reservation_id(31),
                peer(1),
                packet(RelayTransport::Udp, b"ciphertext", 1),
            )
            .expect("queued before expiry");

        assert_eq!(service.expire_reservations(31), 1);
        let events_after_expiry = service.events().len();
        let usage_after_expiry = service.usage(reservation_id(31)).expect("usage");
        let proof_after_expiry = service
            .proof_artifact(reservation_id(31))
            .expect("proof artifact");

        assert_eq!(
            service
                .record_packet_loss(reservation_id(31), 1, 10)
                .expect_err("expired reservations reject loss summaries"),
            RelayError::ExpiredReservation
        );
        assert_eq!(
            service
                .record_packet_loss(reservation_id(31), 1, 0)
                .expect_err("terminal lifecycle wins over malformed loss summary"),
            RelayError::ExpiredReservation
        );

        assert_eq!(service.events().len(), events_after_expiry);
        assert_eq!(
            service.usage(reservation_id(31)).expect("usage"),
            usage_after_expiry
        );
        assert_eq!(
            service
                .proof_artifact(reservation_id(31))
                .expect("proof artifact"),
            proof_after_expiry
        );
        assert_eq!(usage_after_expiry.loss_summary, None);
        assert_eq!(
            service.events().last().expect("expiry event").kind,
            RelayEventKind::ReservationExpired
        );
    }

    #[test]
    fn tcp_tls_fallback_reason_is_reported_only_after_tcp_path_is_used() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        service
            .reserve(
                10,
                reservation_id(15),
                "path-relay-15",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");

        assert_eq!(
            service
                .proof_artifact(reservation_id(15))
                .expect("pre-forward artifact")
                .fallback_reason,
            None
        );
        service
            .forward(
                20,
                reservation_id(15),
                peer(1),
                packet(RelayTransport::Udp, b"ciphertext", 1),
            )
            .expect("udp forward");
        assert_eq!(
            service
                .proof_artifact(reservation_id(15))
                .expect("udp artifact")
                .fallback_reason,
            None
        );
        service
            .forward(
                21,
                reservation_id(15),
                peer(1),
                packet(RelayTransport::TcpTls443, b"ciphertext", 2),
            )
            .expect("tcp fallback forward");
        assert_eq!(
            service
                .proof_artifact(reservation_id(15))
                .expect("tcp artifact")
                .fallback_reason,
            Some("udp_unavailable_tcp_tls_443")
        );
    }

    #[test]
    fn cancellation_event_preserves_tcp_tls_fallback_reason_after_tcp_use() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        service
            .reserve(
                10,
                reservation_id(16),
                "path-relay-16",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");
        service
            .forward(
                20,
                reservation_id(16),
                peer(1),
                packet(RelayTransport::TcpTls443, b"ciphertext", 1),
            )
            .expect("tcp fallback forward");

        service
            .cancel_reservation(reservation_id(16))
            .expect("cancel");

        let cancel_event = service.events().last().expect("cancel event");
        assert_eq!(cancel_event.kind, RelayEventKind::ReservationCancelled);
        assert_eq!(
            cancel_event.fallback_reason,
            Some("udp_unavailable_tcp_tls_443")
        );
    }

    #[test]
    fn restart_snapshot_recovers_active_reservations_and_queues() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        service
            .reserve(
                10,
                reservation_id(9),
                "path-relay-9",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");
        let forwarded = service
            .forward(
                20,
                reservation_id(9),
                peer(1),
                packet(RelayTransport::Udp, b"ciphertext", 1),
            )
            .expect("forward");

        let snapshot = service.snapshot();
        assert_eq!(snapshot.reservation_count(), 1);

        let mut restored = RelayService::restore(snapshot);
        let restored_proof = restored
            .proof_artifact(reservation_id(9))
            .expect("restored proof");
        let restored_latency = restored_proof
            .latency_summary
            .expect("restored latency summary");
        assert_eq!(restored_latency.sample_count, 1);
        assert_eq!(restored_latency.latest_latency_micros, 10);
        assert_eq!(
            restored.dequeue_for_peer(peer(2)).expect("restored packet"),
            forwarded
        );
        assert!(
            restored
                .events()
                .iter()
                .any(|event| event.kind == RelayEventKind::RestartRestored)
        );
    }

    #[test]
    fn packet_loss_and_proof_artifact_are_redaction_safe() {
        let mut service = RelayService::new(RelayServiceConfig::default().with_log_peer_ids(true));
        service
            .reserve(
                10,
                reservation_id(10),
                "path-relay-10",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");
        service
            .forward(
                20,
                reservation_id(10),
                peer(1),
                packet(RelayTransport::TcpTls443, b"ciphertext", 1),
            )
            .expect("forward");
        let loss = service
            .record_packet_loss(reservation_id(10), 1, 10)
            .expect("loss");
        let artifact = service
            .proof_artifact(reservation_id(10))
            .expect("artifact");

        assert_eq!(loss.loss_ppm, 100_000);
        assert_eq!(artifact.loss_summary, Some(loss));
        assert_eq!(artifact.accepted_at_micros, 10);
        assert_eq!(
            artifact.fallback_reason,
            Some("udp_unavailable_tcp_tls_443")
        );
        assert_eq!(artifact.opaque_bytes_forwarded, 10);
        assert_eq!(artifact.redacted_source_peer, "peer:0101...");
        assert!(!artifact.redacted_source_peer.contains("0101010101010101"));
        assert!(artifact.e2e_proof_preserved);
    }

    #[test]
    fn disabled_restart_retention_drops_active_state() {
        let config = RelayServiceConfig::default().with_retain_state_on_restart(false);
        let mut service = RelayService::new(config);
        service
            .reserve(
                10,
                reservation_id(11),
                "path-relay-11",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");

        let snapshot = service.snapshot();
        assert_eq!(snapshot.reservation_count(), 0);

        let restored = RelayService::restore(snapshot);
        assert_eq!(
            restored
                .proof_artifact(reservation_id(11))
                .expect_err("dropped state"),
            RelayError::UnknownReservation
        );
    }
