    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    #[cfg(feature = "tls")]
    use crate::tls::{Certificate, CertificateChain, RootCertStore};
    #[cfg(feature = "tls")]
    use std::time::Duration;

    fn test_cx() -> Cx<crate::cx::cap::All> {
        Cx::for_testing()
    }

    #[test]
    fn received_packet_tracker_incrementally_merges_neighbor_ranges() {
        let mut tracker = ReceivedPacketTracker::default();

        for packet_number in [10, 8, 6] {
            tracker.observe(packet_number);
        }
        assert_eq!(
            tracker.ranges,
            vec![
                AckRange {
                    largest: 10,
                    smallest: 10,
                },
                AckRange {
                    largest: 8,
                    smallest: 8,
                },
                AckRange {
                    largest: 6,
                    smallest: 6,
                },
            ]
        );

        tracker.observe(8);
        assert_eq!(tracker.ranges.len(), 3, "duplicate must be a no-op");

        for packet_number in [7, 9, 12, 11, 3, 4, 5] {
            tracker.observe(packet_number);
        }
        assert_eq!(
            tracker.ranges,
            vec![AckRange {
                largest: 12,
                smallest: 3,
            }]
        );
    }

    #[test]
    fn received_packet_tracker_bounds_oldest_gap_history() {
        let mut tracker = ReceivedPacketTracker::default();
        let observed_ranges = MAX_TRACKED_ACK_RANGES + 32;

        for index in 0..observed_ranges {
            tracker.observe((index as u64) * 2);
        }

        assert_eq!(tracker.ranges.len(), MAX_TRACKED_ACK_RANGES);
        assert_eq!(
            tracker.ranges.first(),
            Some(&AckRange {
                largest: ((observed_ranges - 1) as u64) * 2,
                smallest: ((observed_ranges - 1) as u64) * 2,
            })
        );
        assert_eq!(
            tracker.ranges.last(),
            Some(&AckRange {
                largest: 64,
                smallest: 64,
            }),
            "oldest ranges beyond the retained window must be dropped"
        );

        let retained = tracker.ranges.clone();
        tracker.observe(0);
        assert_eq!(
            tracker.ranges, retained,
            "isolated packets older than the retained window must be ignored"
        );

        tracker.observe(63);
        assert_eq!(tracker.ranges.last().map(|range| range.smallest), Some(63));
        assert_eq!(tracker.ranges.len(), MAX_TRACKED_ACK_RANGES);

        let QuicFrame::Ack {
            ack_range_count,
            ack_ranges,
            ..
        } = tracker.ack_frame().expect("nonempty tracker emits an ACK")
        else {
            panic!("received packet tracker emitted a non-ACK frame");
        };
        assert_eq!(ack_range_count.value() as usize, MAX_ACK_FRAME_RANGES - 1);
        assert_eq!(ack_ranges.len(), MAX_ACK_FRAME_RANGES - 1);
    }

    #[test]
    fn received_packet_tracker_merges_at_packet_number_boundary() {
        let mut tracker = ReceivedPacketTracker::default();

        tracker.observe(u64::MAX);
        tracker.observe(u64::MAX - 2);
        tracker.observe(u64::MAX - 1);
        tracker.observe(u64::MAX);

        assert_eq!(
            tracker.ranges,
            vec![AckRange {
                largest: u64::MAX,
                smallest: u64::MAX - 2,
            }]
        );
    }

    #[cfg(feature = "tls")]
    const TEST_CERT_PEM: &[u8] = include_bytes!("../../../tests/fixtures/tls/server.crt");

    #[cfg(feature = "tls")]
    fn fixed_cert_validity_time() -> rustls_pki_types::UnixTime {
        rustls_pki_types::UnixTime::since_unix_epoch(Duration::from_secs(1_780_000_000))
    }

    #[cfg(feature = "tls")]
    fn trusted_identity_material() -> (QuicServerIdentityVerifier, CertificateChain) {
        let certs = Certificate::from_pem(TEST_CERT_PEM).expect("fixture cert parses");
        let mut roots = RootCertStore::empty();
        roots
            .add(&certs[0])
            .expect("fixture cert can be a test trust anchor");
        let verifier = QuicServerIdentityVerifier::from_root_store(roots).expect("build verifier");
        (verifier, CertificateChain::from(certs))
    }

    fn established_conn() -> NativeQuicConnection {
        let cx = test_cx();
        let mut conn = NativeQuicConnection::new(NativeQuicConnectionConfig::default());
        conn.begin_handshake(&cx).expect("begin");
        conn.on_handshake_keys_available(&cx).expect("hs keys");
        conn.on_1rtt_keys_available(&cx).expect("1rtt keys");
        // A real verifying handshake would validate the server cert here; the
        // helper records it so the fail-closed gate (br-7pwwwe) lets the
        // state-machine tests reach the confirmed state.
        conn.record_verified_server_identity();
        conn.on_handshake_confirmed(&cx).expect("confirmed");
        conn
    }

    fn established_server_conn() -> NativeQuicConnection {
        let cx = test_cx();
        let mut conn = NativeQuicConnection::new(NativeQuicConnectionConfig {
            role: StreamRole::Server,
            ..NativeQuicConnectionConfig::default()
        });
        conn.begin_handshake(&cx).expect("begin");
        conn.on_handshake_keys_available(&cx).expect("hs keys");
        conn.on_1rtt_keys_available(&cx).expect("1rtt keys");
        conn.on_handshake_confirmed(&cx).expect("confirmed");
        conn
    }

    #[test]
    fn decode_ack_delay_scales_by_exponent_and_clamps_by_max_ack_delay() {
        // asupersync-mc7m2r / RFC 9000 §19.3, RFC 9002 §5.3.
        let cx = test_cx();
        let mut conn = established_conn(); // handshake confirmed
        // Peer advertises ack_delay_exponent = 5 (ACK Delay in units of 32 us)
        // and max_ack_delay = 10 ms.
        let params = TransportParameters {
            ack_delay_exponent: Some(5),
            max_ack_delay: Some(10),
            ..TransportParameters::default()
        };
        conn.apply_peer_transport_parameters(&cx, &params)
            .expect("apply params");

        // 1-RTT ACK: 100 << 5 = 3_200 us, below the 10 ms clamp.
        assert_eq!(
            conn.decode_ack_delay(PacketNumberSpace::ApplicationData, 100),
            3_200
        );
        // 1-RTT ACK, large delay: 1_000 << 5 = 32_000 us, clamped to the peer's
        // max_ack_delay of 10 ms (10_000 us) so a peer cannot deflate our RTT.
        assert_eq!(
            conn.decode_ack_delay(PacketNumberSpace::ApplicationData, 1_000),
            10_000
        );
        // Initial/Handshake ACKs use the default exponent 3 and are not clamped:
        // 100 << 3 = 800 us.
        assert_eq!(
            conn.decode_ack_delay(PacketNumberSpace::Handshake, 100),
            800
        );
        // Zero delay always decodes to zero.
        assert_eq!(
            conn.decode_ack_delay(PacketNumberSpace::ApplicationData, 0),
            0
        );
    }

    #[test]
    fn peer_transport_parameter_refusal_preserves_all_negotiated_settings() {
        let cx = test_cx();
        let mut conn = established_conn();
        let valid = TransportParameters {
            ack_delay_exponent: Some(10),
            max_ack_delay: Some(5),
            max_datagram_frame_size: Some(1200),
            disable_active_migration: true,
            ..TransportParameters::default()
        };
        conn.apply_peer_transport_parameters_with_datagram_cap(&cx, &valid, 32)
            .unwrap();
        for invalid in [
            TransportParameters {
                ack_delay_exponent: Some(21),
                ..TransportParameters::default()
            },
            TransportParameters {
                max_ack_delay: Some(1 << 14),
                ..TransportParameters::default()
            },
        ] {
            assert!(conn.apply_peer_transport_parameters(&cx, &invalid).is_err());
            assert!(conn.migration_disabled);
            assert_eq!(conn.max_datagram_frame_size, 32);
            assert_eq!(conn.peer_ack_delay_exponent, 10);
            assert_eq!(conn.peer_max_ack_delay_micros, 5_000);
        }
        #[cfg(target_pointer_width = "32")]
        {
            let invalid = TransportParameters {
                max_datagram_frame_size: Some(u64::from(u32::MAX) + 1),
                ..TransportParameters::default()
            };
            assert!(conn.apply_peer_transport_parameters(&cx, &invalid).is_err());
            assert!(conn.migration_disabled);
            assert_eq!(conn.max_datagram_frame_size, 32);
            assert_eq!(conn.peer_ack_delay_exponent, 10);
            assert_eq!(conn.peer_max_ack_delay_micros, 5_000);
        }
        // The existing public API still replaces the peer cap without a UDP
        // owner's optional local admission policy.
        conn.apply_peer_transport_parameters(&cx, &valid).unwrap();
        assert_eq!(conn.max_datagram_frame_size, 1200);
    }

    #[test]
    fn decode_ack_delay_is_unclamped_before_handshake_confirmed() {
        // asupersync-mc7m2r: RFC 9002 §5.3 clamps by max_ack_delay only after the
        // handshake is confirmed. Before confirmation, scale but do not clamp.
        let cx = test_cx();
        let mut conn = NativeQuicConnection::new(NativeQuicConnectionConfig::default());
        conn.begin_handshake(&cx).expect("begin");
        let params = TransportParameters {
            ack_delay_exponent: Some(3),
            max_ack_delay: Some(10),
            ..TransportParameters::default()
        };
        conn.apply_peer_transport_parameters(&cx, &params)
            .expect("apply params");
        // Not confirmed: 5_000 << 3 = 40_000 us is returned unclamped (would be
        // capped to 10_000 once confirmed).
        assert!(!conn.tls().handshake_confirmed());
        assert_eq!(
            conn.decode_ack_delay(PacketNumberSpace::ApplicationData, 5_000),
            40_000
        );
    }

    #[test]
    fn client_fails_closed_on_confirm_without_verified_server_identity() {
        // br-asupersync-7pwwwe: the native QUIC TLS path performs no certificate
        // exchange/verification, so a client that never recorded a verified
        // server identity must fail closed at handshake confirmation instead of
        // accepting an unauthenticated server (MITM exposure).
        let cx = test_cx();
        let mut conn = NativeQuicConnection::new(NativeQuicConnectionConfig::default());
        conn.begin_handshake(&cx).expect("begin");
        conn.on_handshake_keys_available(&cx).expect("hs keys");
        conn.on_1rtt_keys_available(&cx).expect("1rtt keys");
        let err = conn
            .on_handshake_confirmed(&cx)
            .expect_err("client confirm must fail closed without a verified server identity");
        assert!(
            matches!(
                err,
                NativeQuicConnectionError::Tls(QuicTlsError::ServerCertificateUnverified)
            ),
            "expected ServerCertificateUnverified, got {err:?}"
        );
    }

    #[test]
    fn client_confirms_after_recording_verified_server_identity() {
        let cx = test_cx();
        let mut conn = NativeQuicConnection::new(NativeQuicConnectionConfig::default());
        conn.begin_handshake(&cx).expect("begin");
        conn.on_handshake_keys_available(&cx).expect("hs keys");
        conn.on_1rtt_keys_available(&cx).expect("1rtt keys");
        conn.record_verified_server_identity();
        conn.on_handshake_confirmed(&cx)
            .expect("client confirms once a verifying handshake has recorded server identity");
    }

    #[cfg(feature = "tls")]
    #[test]
    fn client_verifies_server_identity_before_confirming_handshake() {
        let cx = test_cx();
        let (verifier, chain) = trusted_identity_material();
        let mut conn = NativeQuicConnection::new(NativeQuicConnectionConfig::default());
        conn.begin_handshake(&cx).expect("begin");
        conn.on_handshake_keys_available(&cx).expect("hs keys");
        conn.on_1rtt_keys_available(&cx).expect("1rtt keys");

        let receipt = conn
            .verify_server_identity_and_confirm_handshake(
                &cx,
                &verifier,
                "localhost",
                chain,
                fixed_cert_validity_time(),
            )
            .expect("valid server identity confirms handshake");

        assert_eq!(receipt.chain_len, 1);
        assert_eq!(receipt.root_count, 1);
        assert_eq!(conn.state(), QuicConnectionState::Established);
        assert!(conn.can_send_1rtt());
    }

    #[cfg(feature = "tls")]
    #[test]
    fn client_rejects_bad_server_identity_without_confirming_handshake() {
        let cx = test_cx();
        let (verifier, chain) = trusted_identity_material();
        let mut conn = NativeQuicConnection::new(NativeQuicConnectionConfig::default());
        conn.begin_handshake(&cx).expect("begin");
        conn.on_handshake_keys_available(&cx).expect("hs keys");
        conn.on_1rtt_keys_available(&cx).expect("1rtt keys");

        let err = conn
            .verify_server_identity_and_confirm_handshake(
                &cx,
                &verifier,
                "not-localhost.example",
                chain,
                fixed_cert_validity_time(),
            )
            .expect_err("bad hostname must fail closed");

        assert!(matches!(
            err,
            NativeQuicConnectionError::Tls(QuicTlsError::ServerCertificateRejected {
                code: "server_certificate_invalid"
            })
        ));
        assert_eq!(conn.state(), QuicConnectionState::Handshaking);
        assert!(!conn.can_send_1rtt());
        let confirm_err = conn
            .on_handshake_confirmed(&cx)
            .expect_err("failed verification must not set identity gate");
        assert!(matches!(
            confirm_err,
            NativeQuicConnectionError::Tls(QuicTlsError::ServerCertificateUnverified)
        ));
    }

    #[test]
    fn cannot_open_data_stream_before_1rtt_enabled() {
        let cx = test_cx();
        let mut conn = NativeQuicConnection::new(NativeQuicConnectionConfig::default());
        conn.begin_handshake(&cx).expect("begin");
        let err = conn.open_local_bidi(&cx).expect_err("must fail");
        assert_eq!(
            err,
            NativeQuicConnectionError::InvalidState("1-RTT traffic not yet enabled")
        );
    }

    #[test]
    fn cannot_accept_remote_stream_before_established() {
        let cx = test_cx();
        let mut conn = NativeQuicConnection::new(NativeQuicConnectionConfig::default());
        conn.begin_handshake(&cx).expect("begin");
        let remote = StreamId::local(
            StreamRole::Server,
            crate::net::quic_native::streams::StreamDirection::Bidirectional,
            0,
        );
        let err = conn
            .accept_remote_stream(&cx, remote)
            .expect_err("must fail before established");
        assert_eq!(
            err,
            NativeQuicConnectionError::InvalidState(
                "new application streams require established state"
            )
        );
    }

    #[test]
    fn established_connection_can_open_and_write_stream() {
        let cx = test_cx();
        let mut conn = established_conn();
        let stream = conn.open_local_bidi(&cx).expect("open");
        conn.write_stream(&cx, stream, 12).expect("write");
        conn.receive_stream(&cx, stream, 4).expect("receive");
        conn.set_stream_final_size(&cx, stream, 3)
            .expect_err("final size must not regress");
    }

    #[test]
    fn packet_numbers_increase_per_space() {
        let cx = test_cx();
        let mut conn = established_conn();
        let pn0 = conn
            .on_packet_sent(&cx, PacketNumberSpace::Initial, 1200, true, true, 10_000)
            .expect("pn0");
        let pn1 = conn
            .on_packet_sent(&cx, PacketNumberSpace::Initial, 1200, true, true, 10_100)
            .expect("pn1");
        let pn2 = conn
            .on_packet_sent(
                &cx,
                PacketNumberSpace::ApplicationData,
                1200,
                true,
                true,
                10_200,
            )
            .expect("pn2");
        assert_eq!(pn0, 0);
        assert_eq!(pn1, 1);
        assert_eq!(pn2, 0);
    }

    #[test]
    fn application_data_packets_require_established_1rtt() {
        let cx = test_cx();
        let mut conn = NativeQuicConnection::new(NativeQuicConnectionConfig::default());
        conn.begin_handshake(&cx).expect("begin");
        let err = conn
            .on_packet_sent(
                &cx,
                PacketNumberSpace::ApplicationData,
                1200,
                true,
                true,
                10_000,
            )
            .expect_err("appdata before 1-rtt must fail");
        assert_eq!(
            err,
            NativeQuicConnectionError::InvalidState(
                "application-data packets require established 1-RTT state"
            )
        );
    }

    #[test]
    fn queue_ping_emits_ack_eliciting_ping_without_stream_payload() {
        let cx = test_cx();
        let mut conn = established_conn();

        conn.queue_ping(&cx).expect("queue ping");
        let frames = conn
            .generate_frames(&cx, PacketNumberSpace::ApplicationData, 128)
            .expect("queued ping should generate");

        assert_eq!(frames, vec![QuicFrame::Ping]);
    }

    fn ack_frame_shape(frames: &[QuicFrame]) -> Option<(u64, u64, u64)> {
        frames.iter().find_map(|frame| match frame {
            QuicFrame::Ack {
                largest_acknowledged,
                first_ack_range,
                ack_range_count,
                ..
            } => Some((
                largest_acknowledged.value(),
                first_ack_range.value(),
                ack_range_count.value(),
            )),
            _ => None,
        })
    }

    /// GH#71: a received ACK-only packet elicits no ACK of its own, but its
    /// number stays in the ACK ranges so the next elicited ACK is contiguous
    /// instead of carrying a gap at every ACK-only packet the peer sent.
    #[test]
    fn non_ack_eliciting_packets_stay_in_ack_ranges_without_eliciting_an_ack() {
        let cx = test_cx();
        let mut conn = established_server_conn();
        let space = PacketNumberSpace::ApplicationData;
        // Drain whatever the handshake confirmation queued.
        let _ = conn.generate_frames(&cx, space, 1_024).expect("drain");

        conn.process_packet_frames(&cx, space, 5, &[QuicFrame::Ping], 10_000)
            .expect("ping 5");
        let frames = conn.generate_frames(&cx, space, 1_024).expect("ack for 5");
        assert_eq!(ack_frame_shape(&frames), Some((5, 0, 0)));

        let zero = VarInt::from_u64_unchecked(0);
        let ack_only = QuicFrame::Ack {
            largest_acknowledged: zero,
            ack_delay: zero,
            ack_range_count: zero,
            first_ack_range: zero,
            ack_ranges: Vec::new(),
            ecn_counts: None,
        };
        conn.process_packet_frames(&cx, space, 6, &[ack_only], 10_100)
            .expect("ack-only 6");
        let frames = conn.generate_frames(&cx, space, 1_024).expect("nothing");
        assert_eq!(
            ack_frame_shape(&frames),
            None,
            "an ACK-only packet must not elicit an ACK (RFC 9000 §13.2.1)"
        );

        conn.process_packet_frames(&cx, space, 7, &[QuicFrame::Ping], 10_200)
            .expect("ping 7");
        let frames = conn.generate_frames(&cx, space, 1_024).expect("ack for 7");
        assert_eq!(
            ack_frame_shape(&frames),
            Some((7, 2, 0)),
            "5..=7 must be one contiguous range: the ACK-only packet 6 is acknowledged"
        );
    }

    #[test]
    fn packet_send_is_rejected_after_close() {
        let cx = test_cx();
        let mut conn = established_conn();
        conn.close_immediately(&cx, 0x77).expect("close");
        let err = conn
            .on_packet_sent(&cx, PacketNumberSpace::Initial, 1200, true, true, 10_000)
            .expect_err("send after close must fail");
        assert_eq!(
            err,
            NativeQuicConnectionError::InvalidState(
                "packet send requires non-draining, non-closed connection state"
            )
        );
    }

    #[test]
    fn packet_send_is_rejected_after_begin_close_enters_draining() {
        let cx = test_cx();
        let mut conn = established_conn();
        conn.begin_close(&cx, 50_000, 0x77).expect("begin close");

        let err = conn
            .on_packet_sent(
                &cx,
                PacketNumberSpace::ApplicationData,
                1200,
                true,
                true,
                50_100,
            )
            .expect_err("send after begin_close must fail");
        assert_eq!(
            err,
            NativeQuicConnectionError::InvalidState(
                "packet send requires non-draining, non-closed connection state"
            )
        );
    }

    #[test]
    fn bounded_recv_window_advertises_via_reads_and_reattaches_on_acks() {
        let cx = test_cx();
        let mut conn = established_conn();
        let stream = conn.open_local_bidi(&cx).expect("open");
        let advertised = conn
            .configure_stream_recv_window(&cx, stream, 100)
            .expect("configure window");
        assert_eq!(advertised, 100);
        let frames = conn
            .generate_frames(&cx, PacketNumberSpace::ApplicationData, 128)
            .expect("initial advertisement");
        assert!(frames.contains(&QuicFrame::MaxStreamData {
            stream_id: VarInt(stream.0),
            maximum_stream_data: VarInt(100),
        }));

        // Draining past a quarter window queues a fresh advertisement.
        conn.receive_stream_bytes(&cx, stream, 0, Bytes::from_static(&[7u8; 40]), false)
            .expect("inbound bytes");
        assert_eq!(
            conn.read_stream_bytes(&cx, stream, 40)
                .expect("drain")
                .len(),
            40
        );
        let frames = conn
            .generate_frames(&cx, PacketNumberSpace::ApplicationData, 128)
            .expect("advertisement after drain");
        assert!(frames.contains(&QuicFrame::MaxStreamData {
            stream_id: VarInt(stream.0),
            maximum_stream_data: VarInt(140),
        }));

        // Every ApplicationData ACK re-attaches the current advertisement, so
        // a lost MAX_STREAM_DATA can never wedge a credit-blocked sender.
        conn.acknowledge_received_packet(PacketNumberSpace::ApplicationData, 9);
        let frames = conn
            .generate_frames(&cx, PacketNumberSpace::ApplicationData, 256)
            .expect("ack with advertisement");
        assert!(frames.iter().any(|f| matches!(f, QuicFrame::Ack { .. })));
        assert!(frames.contains(&QuicFrame::MaxStreamData {
            stream_id: VarInt(stream.0),
            maximum_stream_data: VarInt(140),
        }));
    }

    /// A stream whose sender has finished, or that was reset, needs no more
    /// credit (RFC 9000 3.2), yet every ACK re-advertised its window, and the
    /// re-attach rescanned the control queue once per stream.
    #[test]
    fn acks_reattach_windows_only_for_streams_still_receiving() {
        let cx = test_cx();
        let mut conn = established_conn();
        let live = conn.open_local_bidi(&cx).expect("open");
        let finished = conn.open_local_bidi(&cx).expect("open");
        let reset = conn.open_local_bidi(&cx).expect("open");
        for stream in [live, finished, reset] {
            conn.configure_stream_recv_window(&cx, stream, 100)
                .expect("configure window");
        }
        let _ = conn
            .generate_frames(&cx, PacketNumberSpace::ApplicationData, 1024)
            .expect("initial advertisements");
        conn.receive_stream_bytes(&cx, finished, 0, Bytes::from_static(b"done"), true)
            .expect("the sender finishes");
        conn.reset_stream_receive(&cx, reset, 0, 0)
            .expect("the sender resets");

        conn.acknowledge_received_packet(PacketNumberSpace::ApplicationData, 9);
        let frames = conn
            .generate_frames(&cx, PacketNumberSpace::ApplicationData, 1024)
            .expect("ack with advertisements");
        assert!(frames.iter().any(|f| matches!(f, QuicFrame::Ack { .. })));
        let advertised: Vec<u64> = frames
            .iter()
            .filter_map(|frame| match frame {
                QuicFrame::MaxStreamData { stream_id, .. } => Some(stream_id.value()),
                _ => None,
            })
            .collect();
        assert_eq!(advertised, vec![live.0]);
    }

    #[test]
    fn peer_stream_data_blocked_grows_an_allowed_bounded_window_and_advertises_it() {
        let cx = test_cx();
        let mut conn = established_conn();
        let stream = conn.open_local_bidi(&cx).expect("open");
        conn.configure_stream_recv_window(&cx, stream, 100)
            .expect("configure window");
        conn.allow_stream_recv_window_growth(&cx, stream, 400, 0)
            .expect("allow growth");
        let _ = conn
            .generate_frames(&cx, PacketNumberSpace::ApplicationData, 128)
            .expect("initial advertisement");

        // The peer reports being blocked before we consumed a full window:
        // nothing grows and nothing new is advertised.
        conn.process_frame(
            &cx,
            &QuicFrame::StreamDataBlocked {
                stream_id: VarInt(stream.0),
                maximum_stream_data: VarInt(100),
            },
            PacketNumberSpace::ApplicationData,
        )
        .expect("blocked before consumption");
        assert_eq!(
            conn.stream_recv_window_bytes(stream).expect("window"),
            Some(100)
        );

        // Consume a full window, then the peer is blocked at our new edge:
        // the window doubles and read_offset + 200 goes on the wire.
        conn.receive_stream_bytes(&cx, stream, 0, Bytes::from_static(&[7u8; 100]), false)
            .expect("inbound bytes");
        assert_eq!(
            conn.read_stream_bytes(&cx, stream, 100)
                .expect("drain")
                .len(),
            100
        );
        let _ = conn
            .generate_frames(&cx, PacketNumberSpace::ApplicationData, 128)
            .expect("consumption advertisement");
        conn.process_frame(
            &cx,
            &QuicFrame::StreamDataBlocked {
                stream_id: VarInt(stream.0),
                maximum_stream_data: VarInt(200),
            },
            PacketNumberSpace::ApplicationData,
        )
        .expect("blocked at the edge");
        assert_eq!(
            conn.stream_recv_window_bytes(stream).expect("window"),
            Some(200)
        );
        let frames = conn
            .generate_frames(&cx, PacketNumberSpace::ApplicationData, 128)
            .expect("growth advertisement");
        assert!(frames.contains(&QuicFrame::MaxStreamData {
            stream_id: VarInt(stream.0),
            maximum_stream_data: VarInt(300),
        }));
    }

    #[test]
    fn report_stream_data_blocked_queues_one_frame_with_the_current_send_limit() {
        let cx = test_cx();
        let mut conn = established_conn();
        let stream = conn.open_local_bidi(&cx).expect("open");
        assert_eq!(
            conn.set_fresh_stream_send_limit(&cx, stream, 64)
                .expect("cap"),
            64
        );
        conn.report_stream_data_blocked(&cx, stream)
            .expect("report");
        conn.report_stream_data_blocked(&cx, stream)
            .expect("report again");
        let frames = conn
            .generate_frames(&cx, PacketNumberSpace::ApplicationData, 128)
            .expect("frames");
        let blocked: Vec<&QuicFrame> = frames
            .iter()
            .filter(|frame| matches!(frame, QuicFrame::StreamDataBlocked { .. }))
            .collect();
        assert_eq!(
            blocked,
            vec![&QuicFrame::StreamDataBlocked {
                stream_id: VarInt(stream.0),
                maximum_stream_data: VarInt(64),
            }],
            "a repeated report replaces the pending frame instead of stacking"
        );
    }

    /// br-asupersync-tzjbn9 F9: every refused write queued another
    /// STREAM_DATA_BLOCKED, and one refused by the connection limit named the
    /// stream instead of sending DATA_BLOCKED (RFC 9000 19.12, 19.13).
    #[test]
    fn a_refused_write_names_the_binding_limit_once() {
        let cx = test_cx();
        let blocked_frames = |conn: &NativeQuicConnection| -> Vec<QuicFrame> {
            conn.pending_control_frames
                .iter()
                .filter(|frame| {
                    matches!(
                        frame,
                        QuicFrame::StreamDataBlocked { .. } | QuicFrame::DataBlocked { .. }
                    )
                })
                .cloned()
                .collect()
        };

        let mut conn = established_conn();
        let stream = conn.open_local_bidi(&cx).expect("open");
        conn.set_fresh_stream_send_limit(&cx, stream, 8)
            .expect("stream cap");
        for _ in 0..3 {
            conn.write_stream_bytes(&cx, stream, Bytes::from_static(&[1u8; 16]), false)
                .expect_err("16 bytes exceed the stream's 8");
        }
        assert_eq!(
            blocked_frames(&conn),
            vec![QuicFrame::StreamDataBlocked {
                stream_id: VarInt(stream.0),
                maximum_stream_data: VarInt(8),
            }],
            "three refused writes queue one STREAM_DATA_BLOCKED"
        );

        let mut conn = established_conn();
        let stream = conn.open_local_bidi(&cx).expect("open");
        conn.constrain_connection_send_limit_for_testing(&cx, 8)
            .expect("connection cap");
        for _ in 0..3 {
            conn.write_stream_bytes(&cx, stream, Bytes::from_static(&[1u8; 16]), false)
                .expect_err("16 bytes exceed the connection's 8");
        }
        assert_eq!(
            blocked_frames(&conn),
            vec![QuicFrame::DataBlocked {
                maximum_data: VarInt(8),
            }],
            "a write refused by the connection limit queues one DATA_BLOCKED"
        );
    }

    #[test]
    fn ack_path_repeats_consumption_clocked_window_past_head_of_line_hole() {
        let cx = test_cx();
        let mut conn = established_conn();
        let stream = conn.open_local_bidi(&cx).expect("open");
        conn.configure_stream_recv_window(&cx, stream, 100)
            .expect("configure window");
        // A segment lands beyond a head-of-line hole (0..10 missing): the
        // ACK-attached advertisement must REPEAT the consumption-clocked
        // limit (100), not chase the received offset — settled after four
        // attempts (MATRIX-227 on advance_bounded_recv_windows).
        conn.receive_stream_bytes(&cx, stream, 10, Bytes::from_static(&[7u8; 40]), false)
            .expect("inbound bytes past hole");
        assert!(
            conn.read_stream_bytes(&cx, stream, 100)
                .expect("read")
                .is_empty()
        );
        conn.acknowledge_received_packet(PacketNumberSpace::ApplicationData, 3);
        let frames = conn
            .generate_frames(&cx, PacketNumberSpace::ApplicationData, 256)
            .expect("ack with advertisement");
        assert!(frames.contains(&QuicFrame::MaxStreamData {
            stream_id: VarInt(stream.0),
            maximum_stream_data: VarInt(100),
        }));
        assert!(!frames.iter().any(|frame| matches!(
            frame,
            QuicFrame::MaxStreamData { stream_id, maximum_stream_data }
                if stream_id.value() == stream.0 && maximum_stream_data.value() > 100
        )));
    }

    /// A packet with STREAM_DATA_BLOCKED or MAX_STREAM_DATA can arrive before
    /// the lost packet that carried the stream's first STREAM frame. Both open
    /// the peer's stream (RFC 9000 3.2); they used to fail the packet with an
    /// unknown-stream error, which the endpoint dropped unacknowledged on
    /// every retransmission.
    #[test]
    fn blocked_and_credit_frames_open_a_peer_stream() {
        let cx = test_cx();
        let mut conn = established_server_conn();
        let blocked = StreamId(0);
        let credited = StreamId(4);
        let frames = [
            QuicFrame::StreamDataBlocked {
                stream_id: VarInt(blocked.0),
                maximum_stream_data: VarInt(100),
            },
            QuicFrame::MaxStreamData {
                stream_id: VarInt(credited.0),
                maximum_stream_data: VarInt(1 << 20),
            },
        ];
        conn.process_packet_frames(&cx, PacketNumberSpace::ApplicationData, 3, &frames, 100)
            .expect("both frames open their streams");
        assert!(conn.streams.stream(blocked).is_ok());
        assert!(conn.streams.stream(credited).is_ok());

        let late = [QuicFrame::Stream {
            stream_id: VarInt(blocked.0),
            offset: Some(VarInt(0)),
            data: Bytes::from_static(b"late"),
            fin: false,
        }];
        conn.process_packet_frames(&cx, PacketNumberSpace::ApplicationData, 4, &late, 200)
            .expect("the retransmitted first STREAM frame lands on the open stream");
        assert_eq!(
            conn.read_stream_bytes(&cx, blocked, 16).expect("read"),
            Bytes::from_static(b"late")
        );

        // A peer's unidirectional stream only receives; credit for sending on
        // it does not open it.
        let receive_only = [QuicFrame::MaxStreamData {
            stream_id: VarInt(2),
            maximum_stream_data: VarInt(1 << 20),
        }];
        assert!(
            conn.process_packet_frames(
                &cx,
                PacketNumberSpace::ApplicationData,
                5,
                &receive_only,
                300
            )
            .is_err()
        );
        assert!(conn.streams.stream(StreamId(2)).is_err());
    }

    /// The per-stream bound alone let a peer keep that many one-byte holes on
    /// every stream it could open, about 1M for the default stream limits.
    #[test]
    fn stream_receive_reassembly_fragments_are_bounded_across_streams() {
        let cx = test_cx();
        let mut conn = established_conn();
        let per_stream = MAX_BUFFERED_STREAM_REASSEMBLY_FRAGMENTS - 1;
        let full_streams = MAX_BUFFERED_CONNECTION_REASSEMBLY_FRAGMENTS / per_stream;
        let mut holes = 0usize;
        for _ in 0..full_streams {
            let stream = conn.open_local_bidi(&cx).expect("open");
            for fragment in 0..per_stream {
                let offset = 1 + (fragment as u64 * 2);
                conn.receive_stream_bytes(&cx, stream, offset, Bytes::from_static(b"x"), false)
                    .expect("fragment within both limits");
                holes += 1;
            }
        }
        let last = conn.open_local_bidi(&cx).expect("open");
        let mut fragment = 0u64;
        while holes < MAX_BUFFERED_CONNECTION_REASSEMBLY_FRAGMENTS {
            conn.receive_stream_bytes(&cx, last, 1 + fragment * 2, Bytes::from_static(b"x"), false)
                .expect("fragment within the connection limit");
            fragment += 1;
            holes += 1;
        }

        let err = conn
            .receive_stream_bytes(&cx, last, 1 + fragment * 2, Bytes::from_static(b"x"), false)
            .expect_err("a hole beyond the connection limit must fail closed");
        assert!(err.is_stream_reassembly_backpressure(), "{err:?}");
        let frames = [QuicFrame::Stream {
            stream_id: VarInt(last.0),
            offset: Some(VarInt(1 + fragment * 2)),
            data: Bytes::from_static(b"x"),
            fin: false,
        }];
        let err = conn
            .process_packet_frames(&cx, PacketNumberSpace::ApplicationData, 9, &frames, 300)
            .expect_err("a packet adding a hole beyond the connection limit is refused");
        assert!(err.is_stream_reassembly_backpressure(), "{err:?}");

        // A frame that makes a stream's head readable is not out of order, so
        // it stays admissible at the limit. Here it also joins the first hole
        // into the readable head, which frees one slot.
        conn.receive_stream_bytes(&cx, last, 0, Bytes::from_static(b"h"), false)
            .expect("head-of-line fragment remains admissible");
        assert_eq!(
            conn.read_stream_bytes(&cx, last, 2)
                .expect("read the head and its joined successor"),
            Bytes::from_static(b"hx")
        );
        conn.receive_stream_bytes(&cx, last, 1 + fragment * 2, Bytes::from_static(b"x"), false)
            .expect("the freed slot admits one more hole");
    }

    #[test]
    fn stream_receive_reassembly_fragment_count_is_bounded_before_mutation() {
        let cx = test_cx();
        let mut conn = established_conn();
        let stream = conn.open_local_bidi(&cx).expect("open");

        // Leave one metadata slot reserved for the readable head fragment.
        for fragment in 0..MAX_BUFFERED_STREAM_REASSEMBLY_FRAGMENTS - 1 {
            let offset = 1 + (fragment as u64 * 2);
            conn.receive_stream_bytes(&cx, stream, offset, Bytes::from_static(b"x"), false)
                .expect("fragment within metadata limit");
        }

        let rejected_offset = 1 + ((MAX_BUFFERED_STREAM_REASSEMBLY_FRAGMENTS - 1) as u64 * 2);
        let err = conn
            .receive_stream_bytes(
                &cx,
                stream,
                rejected_offset,
                Bytes::from_static(b"x"),
                false,
            )
            .expect_err("fragment beyond metadata limit must fail closed");
        assert_eq!(
            err,
            NativeQuicConnectionError::InvalidState(
                "stream receive reassembly fragment limit exceeded"
            )
        );

        conn.receive_stream_bytes(&cx, stream, 1, Bytes::from_static(b"x"), false)
            .expect("duplicate fragment at the limit does not add metadata");
        assert!(
            conn.read_stream_bytes(&cx, stream, 1)
                .expect("read after rejected fragment")
                .is_empty(),
            "rejected fragment must not fill the head-of-line gap"
        );

        conn.receive_stream_bytes(&cx, stream, 0, Bytes::from_static(b"x"), false)
            .expect("head-of-line fragment must remain admissible at the metadata cap");
        assert_eq!(
            conn.read_stream_bytes(&cx, stream, 1)
                .expect("read head fragment"),
            Bytes::from_static(b"x")
        );
        assert_eq!(
            conn.read_stream_bytes(&cx, stream, 1)
                .expect("read formerly blocked successor"),
            Bytes::from_static(b"x"),
            "filling the head gap must restore forward progress"
        );
    }

    #[test]
    fn stop_sending_is_enforced_via_connection_api() {
        let cx = test_cx();
        let mut conn = established_conn();
        let stream = conn.open_local_uni(&cx).expect("open");
        conn.write_stream(&cx, stream, 4).expect("write");
        conn.on_stop_sending(&cx, stream, 77).expect("stop_sending");
        let err = conn.write_stream(&cx, stream, 1).expect_err("must fail");
        assert_eq!(
            err,
            NativeQuicConnectionError::Stream(QuicStreamError::SendStopped { code: 77 })
        );
    }

    #[test]
    fn reset_stream_frame_aborts_receive_side_and_preserves_error_code() {
        let cx = test_cx();
        let mut conn = established_conn();
        let stream = conn.open_local_bidi(&cx).expect("open");
        conn.receive_stream_bytes(&cx, stream, 0, Bytes::from_static(b"abc"), false)
            .expect("buffer inbound bytes");

        conn.process_frame(
            &cx,
            &QuicFrame::ResetStream {
                stream_id: VarInt::from_u64_unchecked(stream.0),
                error_code: VarInt::from_u64_unchecked(0x44),
                final_size: VarInt::from_u64_unchecked(8),
            },
            PacketNumberSpace::ApplicationData,
        )
        .expect("reset stream");

        let s = conn.streams().stream(stream).expect("stream");
        assert_eq!(s.recv_reset, Some((0x44, 8)));
        assert_eq!(s.final_size, Some(8));

        // RFC 9000 s3.2: a STREAM frame after RESET_STREAM inside the final
        // size is discarded, not a connection error (it used to fail the
        // whole packet on ordinary reordering).
        conn.receive_stream_bytes(&cx, stream, 3, Bytes::from_static(b"d"), false)
            .expect("STREAM frames after RESET_STREAM are discarded");

        let err = conn
            .read_stream_bytes(&cx, stream, 8)
            .expect_err("buffered data is discarded after RESET_STREAM");
        assert_eq!(
            err,
            NativeQuicConnectionError::Stream(QuicStreamError::ReceiveReset {
                code: 0x44,
                final_size: 8
            })
        );
    }

    #[test]
    fn out_of_order_receive_segment_reassembles_via_connection_api() {
        let cx = test_cx();
        let mut conn = established_conn();
        let stream = conn.open_local_bidi(&cx).expect("open");
        conn.receive_stream_segment(&cx, stream, 5, 5, false)
            .expect("out-of-order");
        assert_eq!(
            conn.streams().stream(stream).expect("stream").recv_offset,
            0
        );
        conn.receive_stream_segment(&cx, stream, 0, 5, false)
            .expect("fill gap");
        assert_eq!(
            conn.streams().stream(stream).expect("stream").recv_offset,
            10
        );
    }

    #[test]
    fn stream_payload_frames_round_trip_via_connection_api() {
        let cx = test_cx();
        let mut tx = established_conn();
        let stream = tx.open_local_bidi(&cx).expect("open");
        let payload = Bytes::from_static(b"manifest-control-stream");
        tx.write_stream_bytes(&cx, stream, payload.clone(), true)
            .expect("queue bytes");

        let first = tx
            .generate_frames(&cx, PacketNumberSpace::ApplicationData, 42)
            .expect("first frames")
            .into_iter()
            .find_map(|frame| match frame {
                QuicFrame::Stream { .. } => Some(frame),
                _ => None,
            })
            .expect("first stream frame");
        let lost = tx
            .generate_frames(&cx, PacketNumberSpace::ApplicationData, 42)
            .expect("lost frames")
            .into_iter()
            .find_map(|frame| match frame {
                QuicFrame::Stream { .. } => Some(frame),
                _ => None,
            })
            .expect("lost stream frame");
        let lost_offset = match &lost {
            QuicFrame::Stream { offset, .. } => offset.map_or(0, VarInt::value),
            _ => unreachable!("lost is a STREAM frame"),
        };
        let last = tx
            .generate_frames(&cx, PacketNumberSpace::ApplicationData, 128)
            .expect("last frames")
            .into_iter()
            .find_map(|frame| match frame {
                QuicFrame::Stream { .. } => Some(frame),
                _ => None,
            })
            .expect("last stream frame");
        tx.requeue_sent_stream_frame(&cx, stream, lost_offset)
            .expect("requeue lost frame");
        let retransmit = tx
            .generate_frames(&cx, PacketNumberSpace::ApplicationData, 42)
            .expect("retransmit frames")
            .into_iter()
            .find_map(|frame| match frame {
                QuicFrame::Stream { .. } => Some(frame),
                _ => None,
            })
            .expect("retransmitted stream frame");

        let mut rx = established_server_conn();
        for frame in [last, retransmit, first] {
            rx.process_frame(&cx, &frame, PacketNumberSpace::ApplicationData)
                .expect("process stream frame");
        }
        let mut out = Vec::new();
        while !rx.is_stream_read_eof(stream).expect("eof check") {
            let chunk = rx.read_stream_bytes(&cx, stream, 8).expect("read bytes");
            assert!(!chunk.is_empty(), "stream must not stall after retransmit");
            out.extend_from_slice(&chunk);
        }
        assert_eq!(out, payload.as_ref());
    }

    #[test]
    fn native_h3_adapter_reset_purges_in_flight_stream_recovery_refs() {
        let cx = test_cx();
        let mut conn = established_conn();
        let stream = conn.open_local_bidi(&cx).expect("open");
        conn.write_stream_bytes(&cx, stream, Bytes::from_static(b"cancel-me"), false)
            .expect("queue stream bytes");
        let frames = conn
            .generate_frames(&cx, PacketNumberSpace::ApplicationData, 128)
            .expect("generate stream packet");
        conn.on_packet_sent_with_frames(
            &cx,
            PacketNumberSpace::ApplicationData,
            128,
            true,
            true,
            10_000,
            &frames,
        )
        .expect("commit stream packet");
        assert!(
            conn.in_flight_retransmittable_frames[2]
                .values()
                .flatten()
                .any(|frame_ref| matches!(
                    frame_ref,
                    RetransmittableFrameRef::Stream {
                        stream_id,
                        ..
                    } if *stream_id == stream
                ))
        );

        conn.reset_stream_send(&cx, stream, 0x10c, 9)
            .expect("reset stream send side");
        assert!(
            conn.in_flight_retransmittable_frames
                .iter()
                .flat_map(|ledger| ledger.values())
                .flatten()
                .all(|frame_ref| !matches!(
                    frame_ref,
                    RetransmittableFrameRef::Stream {
                        stream_id,
                        ..
                    } if *stream_id == stream
                )),
            "terminal reset must not leave permanently unacknowledgeable STREAM refs"
        );
    }

    #[test]
    fn native_h3_adapter_lost_extents_coalesce_and_ack_without_recovery_leak() {
        let cx = test_cx();
        let mut conn = established_conn();
        let stream = conn.open_local_bidi(&cx).expect("open");
        conn.write_stream_bytes(&cx, stream, Bytes::from_static(b"abcdef"), false)
            .expect("queue stream bytes");

        for sent_at in [10_000, 10_100] {
            let frames = conn
                .generate_frames(&cx, PacketNumberSpace::ApplicationData, 35)
                .expect("generate three-byte STREAM extent");
            assert_eq!(
                frames.iter().find_map(|frame| match frame {
                    QuicFrame::Stream { data, .. } => Some(data.len()),
                    _ => None,
                }),
                Some(3)
            );
            conn.on_packet_sent_with_frames(
                &cx,
                PacketNumberSpace::ApplicationData,
                35,
                true,
                true,
                sent_at,
                &frames,
            )
            .expect("commit small STREAM packet");
        }
        for sent_at in [10_200, 10_300, 10_400] {
            conn.on_packet_sent(
                &cx,
                PacketNumberSpace::ApplicationData,
                1,
                true,
                true,
                sent_at,
            )
            .expect("commit packet-threshold marker");
        }

        let loss = conn
            .on_ack_received(&cx, PacketNumberSpace::ApplicationData, &[4], 0, 10_500)
            .expect("ACK declares packets zero and one lost");
        assert_eq!(loss.lost_packets, 2);
        assert!(conn.in_flight_retransmittable_frames[2].is_empty());

        let retransmit = conn
            .generate_frames(&cx, PacketNumberSpace::ApplicationData, 64)
            .expect("generate coalesced retransmit");
        assert!(retransmit.iter().any(|frame| matches!(
            frame,
            QuicFrame::Stream { offset, data, .. }
                if offset.map_or(0, VarInt::value) == 0 && data.len() == 6
        )));
        let retransmit_packet = conn
            .on_packet_sent_with_frames(
                &cx,
                PacketNumberSpace::ApplicationData,
                64,
                true,
                true,
                10_600,
                &retransmit,
            )
            .expect("commit coalesced retransmit");
        conn.on_ack_received(
            &cx,
            PacketNumberSpace::ApplicationData,
            &[retransmit_packet],
            0,
            10_700,
        )
        .expect("ACK coalesced retransmit");
        assert!(
            conn.in_flight_retransmittable_frames
                .iter()
                .all(BTreeMap::is_empty),
            "lost packet refs must be removed before coalesced recovery is tracked"
        );
    }

    #[test]
    fn pending_stream_frames_track_partial_packetization() {
        let cx = test_cx();
        let mut conn = established_conn();
        let stream = conn.open_local_bidi(&cx).expect("open");
        conn.write_stream_bytes(
            &cx,
            stream,
            Bytes::from_static(b"source-stream-payload"),
            true,
        )
        .expect("queue source stream bytes");

        assert!(
            conn.has_pending_stream_frames(),
            "queued source bytes must be visible to drain loops"
        );
        assert!(
            conn.has_pending_stream_frames_for(stream),
            "queued source bytes must be visible by stream id"
        );
        let first = conn
            .generate_frames(&cx, PacketNumberSpace::ApplicationData, 42)
            .expect("first packet")
            .into_iter()
            .any(|frame| matches!(frame, QuicFrame::Stream { .. }));
        assert!(first, "first packet should carry a STREAM frame");
        assert!(
            conn.has_pending_stream_frames(),
            "partial packetization must leave the stream pending"
        );
        let second = conn
            .generate_frames(&cx, PacketNumberSpace::ApplicationData, 128)
            .expect("final packet")
            .into_iter()
            .any(|frame| matches!(frame, QuicFrame::Stream { .. }));
        assert!(second, "final packet should carry the STREAM tail");
        assert!(
            !conn.has_pending_stream_frames(),
            "source-stream drain may finish only after queued STREAM frames clear"
        );
        assert!(
            !conn.has_pending_stream_frames_for(stream),
            "stream-id predicate must clear with the stream queue"
        );
    }

    #[test]
    fn generate_stream_frames_for_drains_only_requested_stream() {
        let cx = test_cx();
        let mut conn = established_conn();
        let source = conn.open_local_bidi(&cx).expect("source stream");
        let control = conn.open_local_bidi(&cx).expect("control stream");
        conn.pending_control_frames.push_back(QuicFrame::Ack {
            largest_acknowledged: VarInt::from_u64_unchecked(7),
            ack_delay: VarInt::from_u64_unchecked(0),
            ack_range_count: VarInt::from_u64_unchecked(0),
            first_ack_range: VarInt::from_u64_unchecked(0),
            ack_ranges: Vec::new(),
            ecn_counts: None,
        });
        conn.pending_control_frames.push_back(QuicFrame::MaxData {
            maximum_data: VarInt::from_u64_unchecked(4096),
        });
        conn.write_stream_bytes(&cx, control, Bytes::from_static(b"control"), true)
            .expect("queue control stream");
        conn.write_stream_bytes(&cx, source, Bytes::from_static(b"source"), true)
            .expect("queue source stream");

        let frames = conn
            .generate_stream_frames_for(&cx, PacketNumberSpace::ApplicationData, source, 128)
            .expect("source-only packet");
        assert!(
            frames.iter().all(|frame| matches!(
                frame,
                QuicFrame::Stream { stream_id, .. } if stream_id.value() == source.0
            ) || matches!(
                frame,
                QuicFrame::Ack { .. } | QuicFrame::Padding { .. }
            )),
            "source-only generator must not coalesce other stream or ack-eliciting control frames"
        );
        assert!(
            frames
                .iter()
                .any(|frame| matches!(frame, QuicFrame::Ack { .. })),
            "source-only generator should still coalesce non-ack-eliciting ACK frames"
        );
        assert!(
            !frames
                .iter()
                .any(|frame| matches!(frame, QuicFrame::MaxData { .. })),
            "source-only generator must defer ack-eliciting control frames"
        );
        assert!(!conn.has_pending_stream_frames_for(source));
        assert!(
            conn.has_pending_stream_frames_for(control),
            "control stream must stay queued for the normal generator"
        );

        let control_frames = conn
            .generate_frames(&cx, PacketNumberSpace::ApplicationData, 128)
            .expect("control packet");
        assert!(
            control_frames
                .iter()
                .any(|frame| matches!(frame, QuicFrame::MaxData { .. })),
            "normal generator should drain deferred ack-eliciting control frames"
        );
        assert!(
            control_frames.iter().any(|frame| matches!(
                frame,
                QuicFrame::Stream { stream_id, .. } if stream_id.value() == control.0
            )),
            "normal generator should still drain the deferred control stream"
        );
    }

    #[test]
    fn quic_flow_admission_ack_only_preserves_mixed_congestion_controlled_state() {
        let cx = test_cx();
        let mut conn = established_conn();
        let mut in_flight_packets = Vec::new();
        while conn.transport().can_send(1_200) {
            in_flight_packets.push(
                conn.on_packet_sent(
                    &cx,
                    PacketNumberSpace::ApplicationData,
                    1_200,
                    true,
                    true,
                    10_000,
                )
                .expect("fill congestion window"),
            );
        }
        assert!(!conn.transport().can_send(1_200));

        let stream = conn.open_local_bidi(&cx).expect("open stream");
        conn.write_stream_bytes(&cx, stream, Bytes::from_static(b"stream-body"), true)
            .expect("queue STREAM frame");
        conn.send_datagram(&cx, Bytes::from_static(b"datagram-body"))
            .expect("queue DATAGRAM frame");

        let zero = VarInt::from_u64_unchecked(0);
        let max_data = QuicFrame::MaxData {
            maximum_data: VarInt::from_u64_unchecked(4096),
        };
        let ack = QuicFrame::Ack {
            largest_acknowledged: VarInt::from_u64_unchecked(7),
            ack_delay: zero,
            ack_range_count: zero,
            first_ack_range: zero,
            ack_ranges: Vec::new(),
            ecn_counts: None,
        };
        let path_response = QuicFrame::PathResponse { data: [9; 8] };
        let connection_close = QuicFrame::ConnectionClose {
            error_code: zero,
            frame_type: None,
            reason_phrase: Bytes::from_static(b"later"),
        };
        conn.pending_control_frames.extend([
            max_data.clone(),
            ack.clone(),
            path_response.clone(),
            connection_close.clone(),
        ]);

        let pending_stream_bytes = conn.pending_stream_data_bytes();
        let ack_frames =
            crate::net::quic_native::connection_manager::generate_congestion_admitted_1rtt_frames(
                &cx, &mut conn, 1_176,
            )
            .expect("full congestion window generates ACKs only");
        assert_eq!(ack_frames, vec![ack]);
        assert_eq!(
            conn.pending_control_frames,
            VecDeque::from([
                max_data.clone(),
                path_response.clone(),
                connection_close.clone(),
            ])
        );
        assert_eq!(conn.pending_stream_data_bytes(), pending_stream_bytes);
        assert_eq!(conn.pending_outbound_datagram_count(), 1);
        assert_eq!(conn.datagrams_sent(), 0);

        conn.on_ack_received(
            &cx,
            PacketNumberSpace::ApplicationData,
            &[in_flight_packets[0]],
            0,
            20_000,
        )
        .expect("ACK reopens congestion window");
        assert!(conn.transport().can_send(1_200));
        let resumed =
            crate::net::quic_native::connection_manager::generate_congestion_admitted_1rtt_frames(
                &cx, &mut conn, 1_176,
            )
            .expect("ordinary generation after congestion admission");
        assert_eq!(
            &resumed[..3],
            &[max_data, path_response, connection_close],
            "congestion-controlled control frames retain their original order"
        );
        assert!(resumed.iter().any(|frame| matches!(
            frame,
            QuicFrame::Stream {
                stream_id,
                data,
                fin: true,
                ..
            } if stream_id.value() == stream.0 && data.as_ref() == b"stream-body"
        )));
        assert!(resumed.iter().any(|frame| matches!(
            frame,
            QuicFrame::Datagram { data } if data.as_ref() == b"datagram-body"
        )));
        assert_eq!(conn.pending_outbound_datagram_count(), 0);
        assert_eq!(conn.datagrams_sent(), 1);
    }

    // br-asupersync-bi2462.75: explicit connection/clock fixtures. Native UDP
    // wakeup, encryption, and delivery remain the managed endpoint lane's proof.
    #[test]
    fn managed_pto_probe_crosses_full_cwnd_once_without_draining_queues() {
        let cx = test_cx();
        let mut conn = established_conn();
        for _ in 0..10 {
            conn.on_packet_sent(
                &cx,
                PacketNumberSpace::ApplicationData,
                1_200,
                true,
                true,
                10_000,
            )
            .expect("fill congestion window");
        }
        assert_eq!(conn.transport().bytes_in_flight(), 12_000);
        assert!(!conn.transport().can_send(1));
        let stream = conn.open_local_bidi(&cx).expect("open stream");
        conn.write_stream_bytes(&cx, stream, Bytes::from_static(b"keep-stream"), true)
            .expect("queue stream");
        conn.send_datagram(&cx, Bytes::from_static(b"keep-datagram"))
            .expect("queue datagram");
        conn.pending_control_frames.push_back(QuicFrame::MaxData {
            maximum_data: VarInt::from_u64_unchecked(4096),
        });
        let control_before = conn.pending_control_frames.clone();
        let stream_bytes_before = conn.pending_stream_data_bytes();
        let fired_at = conn
            .pto_deadline_micros(&cx, 10_000)
            .expect("clock")
            .expect("PTO");
        let rearmed = conn
            .on_managed_probe_timeout(&cx, fired_at)
            .expect("fire")
            .expect("rearm");
        assert_eq!(rearmed - fired_at, 2_048_000);
        // An obsolete readiness notification cannot grant another expiration.
        assert_eq!(
            conn.on_managed_probe_timeout(&cx, fired_at)
                .expect("obsolete timer"),
            Some(rearmed)
        );
        assert_eq!(conn.transport().pto_count(), 1);
        assert!(
            conn.generate_pto_probe_frames(&cx, 0)
                .expect("zero budget")
                .is_empty()
        );
        let probe = conn.generate_pto_probe_frames(&cx, 1).expect("PING");
        assert_eq!(probe, vec![QuicFrame::Ping]);
        assert!(matches!(
            conn.on_packet_sent(
                &cx,
                PacketNumberSpace::ApplicationData,
                40,
                true,
                true,
                fired_at,
            ),
            Err(NativeQuicConnectionError::CongestionLimited { .. })
        ));
        let packet_number = conn
            .on_pto_probe_packet_sent(&cx, 40, fired_at, &probe)
            .expect("one congestion-exempt probe");
        assert_eq!(packet_number, 10);
        assert_eq!(conn.transport().bytes_in_flight(), 12_040);
        assert_eq!(conn.transport().packets_lost_total(), 0);
        assert_eq!(conn.transport().congestion_window_bytes(), 12_000);
        assert!(
            conn.generate_pto_probe_frames(&cx, 1)
                .expect("spent permit")
                .is_empty()
        );
        assert!(matches!(
            conn.on_pto_probe_packet_sent(&cx, 40, fired_at, &probe),
            Err(NativeQuicConnectionError::InvalidState(_))
        ));
        assert!(!conn.transport().can_send(1));
        assert_eq!(conn.pending_control_frames, control_before);
        assert_eq!(conn.pending_stream_data_bytes(), stream_bytes_before);
        assert_eq!(conn.pending_outbound_datagram_count(), 1);
        assert_eq!(conn.datagrams_sent(), 0);
        assert_eq!(
            conn.next_packet_number_for_protection(PacketNumberSpace::ApplicationData)
                .expect("next packet"),
            11
        );
        let event = conn
            .on_ack_received(
                &cx,
                PacketNumberSpace::ApplicationData,
                &[packet_number],
                0,
                fired_at + 1_000,
            )
            .expect("probe ACK drives ordinary recovery");
        assert_eq!(event.acked_packets, 1);
        assert_eq!(event.acked_bytes, 40);
        assert_eq!(event.lost_packets, 10);
        assert_eq!(conn.transport().bytes_in_flight(), 0);
    }

    #[test]
    fn managed_pto_probe_preserves_anti_amplification_and_failed_commit_state() {
        let cx = test_cx();
        let mut conn = established_server_conn();
        // Keep valid 1-RTT state while planting an unvalidated path with
        // exactly the initial 3x credit exhausted by three real send commits.
        conn.peer_address_validated = false;
        for _ in 0..3 {
            conn.on_packet_sent(
                &cx,
                PacketNumberSpace::ApplicationData,
                1_200,
                true,
                true,
                10_000,
            )
            .expect("use amplification credit");
        }
        let fired_at = conn
            .pto_deadline_micros(&cx, 10_000)
            .expect("clock")
            .expect("PTO");
        conn.on_managed_probe_timeout(&cx, fired_at).expect("fire");
        let frames = conn.generate_pto_probe_frames(&cx, 1).expect("PING");
        assert!(matches!(
            conn.on_pto_probe_packet_sent(&cx, 40, fired_at, &frames),
            Err(NativeQuicConnectionError::AmplificationLimited {
                requested: 40,
                bytes_sent: 3_600,
                bytes_received: 1_200,
                limit: 3_600,
            })
        ));
        assert_eq!(conn.transport().bytes_in_flight(), 3_600);
        assert_eq!(conn.anti_amplification_bytes_sent, 3_600);
        assert_eq!(
            conn.next_packet_number_for_protection(PacketNumberSpace::ApplicationData)
                .expect("unchanged packet number"),
            3
        );
        assert_eq!(
            conn.generate_pto_probe_frames(&cx, 1)
                .expect("retry permit"),
            frames
        );
        conn.on_datagram_received(&cx, 40)
            .expect("new peer traffic adds credit");
        assert_eq!(
            conn.on_pto_probe_packet_sent(&cx, 40, fired_at, &frames)
                .expect("probe now fits amplification credit"),
            3
        );
        assert_eq!(conn.anti_amplification_bytes_sent, 3_640);
        assert_eq!(conn.transport().bytes_in_flight(), 3_640);
    }

    #[test]
    fn managed_pto_probe_refuses_ordinary_frames_oversize_and_cancelled_commits() {
        let cx = test_cx();
        let cancelled = test_cx();
        cancelled.set_cancel_requested(true);
        let mut conn = established_conn();
        conn.on_packet_sent(
            &cx,
            PacketNumberSpace::ApplicationData,
            1_200,
            true,
            true,
            10_000,
        )
        .expect("original flight");
        let fired_at = conn
            .pto_deadline_micros(&cx, 10_000)
            .expect("clock")
            .expect("PTO");
        assert_eq!(
            conn.on_managed_probe_timeout(&cancelled, fired_at),
            Err(NativeQuicConnectionError::Cancelled)
        );
        assert_eq!(conn.transport().pto_count(), 0);
        assert!(
            conn.generate_pto_probe_frames(&cx, 1)
                .expect("no permit")
                .is_empty()
        );
        conn.on_managed_probe_timeout(&cx, fired_at).expect("fire");
        for (bytes, frames) in [
            (0, vec![QuicFrame::Ping]),
            (1_201, vec![QuicFrame::Ping]),
            (40, Vec::new()),
            (40, vec![QuicFrame::Ping, QuicFrame::Ping]),
            (
                40,
                vec![QuicFrame::Datagram {
                    data: Bytes::from_static(b"forbidden"),
                }],
            ),
        ] {
            assert!(matches!(
                conn.on_pto_probe_packet_sent(&cx, bytes, fired_at, &frames),
                Err(NativeQuicConnectionError::InvalidState(_))
            ));
        }
        assert_eq!(
            conn.generate_pto_probe_frames(&cancelled, 1),
            Err(NativeQuicConnectionError::Cancelled)
        );
        assert_eq!(
            conn.on_pto_probe_packet_sent(&cancelled, 40, fired_at, &[QuicFrame::Ping]),
            Err(NativeQuicConnectionError::Cancelled)
        );
        assert_eq!(conn.transport().bytes_in_flight(), 1_200);
        assert_eq!(
            conn.next_packet_number_for_protection(PacketNumberSpace::ApplicationData)
                .expect("failed attempts consume no packet number"),
            1
        );
        assert_eq!(
            conn.on_pto_probe_packet_sent(&cx, 1_200, fired_at, &[QuicFrame::Ping])
                .expect("one valid bounded retry"),
            1
        );
        assert_eq!(conn.transport().bytes_in_flight(), 2_400);
    }

    #[test]
    fn managed_pto_repeated_unsent_probes_do_not_grow_control_queue() {
        let cx = test_cx();
        let mut conn = established_conn();
        conn.on_packet_sent(
            &cx,
            PacketNumberSpace::ApplicationData,
            1_200,
            true,
            true,
            10_000,
        )
        .expect("original flight");
        let control_before = conn.pending_control_frames.clone();
        let mut deadline = conn
            .pto_deadline_micros(&cx, 10_000)
            .expect("clock")
            .expect("PTO");
        for expiration in 1u32..=14 {
            let fired_at = deadline + 5_000_000;
            deadline = conn
                .on_managed_probe_timeout(&cx, fired_at)
                .expect("fire")
                .expect("rearm");
            assert_eq!(
                deadline - fired_at,
                1_024_000 * (1u64 << expiration.min(10))
            );
            assert_eq!(
                conn.generate_pto_probe_frames(&cx, 1)
                    .expect("bounded probe"),
                vec![QuicFrame::Ping]
            );
            assert_eq!(conn.pending_control_frames, control_before);
            assert_eq!(conn.transport().bytes_in_flight(), 1_200);
            assert_eq!(conn.transport().packets_lost_total(), 0);
        }
    }

    #[test]
    fn managed_pto_probe_ack_requeues_lost_reliable_stream_data() {
        let cx = test_cx();
        let mut conn = established_conn();
        let stream = conn.open_local_bidi(&cx).expect("open stream");
        conn.write_stream_bytes(&cx, stream, Bytes::from_static(b"recover-me"), true)
            .expect("queue reliable data");
        let original_frames = conn
            .generate_frames(&cx, PacketNumberSpace::ApplicationData, 128)
            .expect("original frames");
        assert!(original_frames.iter().any(|frame| matches!(
            frame,
            QuicFrame::Stream { data, fin: true, .. } if data.as_ref() == b"recover-me"
        )));
        conn.on_packet_sent_with_frames(
            &cx,
            PacketNumberSpace::ApplicationData,
            1_200,
            true,
            true,
            10_000,
            &original_frames,
        )
        .expect("retain original packet recovery references");
        let fired_at = conn
            .pto_deadline_micros(&cx, 10_000)
            .expect("clock")
            .expect("PTO");
        conn.on_managed_probe_timeout(&cx, fired_at).expect("fire");
        assert!(!conn.has_pending_stream_frames_for(stream));
        let probe_number = conn
            .on_pto_probe_packet_sent(&cx, 40, fired_at, &[QuicFrame::Ping])
            .expect("probe packet");
        assert_eq!(conn.transport().packets_lost_total(), 0);
        let event = conn
            .on_ack_received(
                &cx,
                PacketNumberSpace::ApplicationData,
                &[probe_number],
                0,
                fired_at + 1_000,
            )
            .expect("probe ACK");
        assert_eq!(event.acked_packets, 1);
        assert_eq!(event.lost_packets, 1);
        assert!(conn.has_pending_stream_frames_for(stream));
        let retransmission = conn
            .generate_frames(&cx, PacketNumberSpace::ApplicationData, 128)
            .expect("ordinary reliable retransmission");
        assert!(retransmission.iter().any(|frame| matches!(
            frame,
            QuicFrame::Stream { stream_id, offset, data, fin: true, .. }
                if stream_id.value() == stream.0
                    && offset.map_or(0, VarInt::value) == 0
                    && data.as_ref() == b"recover-me"
        )));
    }

    #[test]
    fn acknowledging_one_copy_of_a_frame_forgets_its_other_in_flight_copies() {
        // br-asupersync-5f1fcj: acknowledged frames now leave the ledgers in
        // one pass per ACK; a copy in another packet must still go with them.
        let cx = test_cx();
        let mut conn = established_conn();
        let stream = conn.open_local_bidi(&cx).expect("open stream");
        conn.write_stream_bytes(&cx, stream, Bytes::from_static(b"copied"), true)
            .expect("queue reliable data");
        let frames = conn
            .generate_frames(&cx, PacketNumberSpace::ApplicationData, 128)
            .expect("frames");
        let mut send = |time_sent_micros| {
            conn.on_packet_sent_with_frames(
                &cx,
                PacketNumberSpace::ApplicationData,
                1_200,
                true,
                true,
                time_sent_micros,
                &frames,
            )
            .expect("packet carrying the frame")
        };
        let first = send(10_000);
        let second = send(10_100);
        let ledger = packet_number_space_idx(PacketNumberSpace::ApplicationData);
        assert!(conn.in_flight_retransmittable_frames[ledger].contains_key(&second));
        let ack = [AckRange::new(first, first).expect("range")];
        conn.on_ack_ranges(&cx, PacketNumberSpace::ApplicationData, &ack, 0, 20_000)
            .expect("ACK of the first copy");
        assert!(
            conn.in_flight_retransmittable_frames[ledger].is_empty(),
            "the copy in packet {second} was acknowledged with packet {first}"
        );
    }

    #[test]
    fn managed_pto_probe_preserves_packet_number_exhaustion_and_1rtt_gates() {
        let cx = test_cx();
        let mut conn = established_conn();
        conn.on_packet_sent(
            &cx,
            PacketNumberSpace::ApplicationData,
            1_200,
            true,
            true,
            10_000,
        )
        .expect("original flight");
        let fired_at = conn
            .pto_deadline_micros(&cx, 10_000)
            .expect("clock")
            .expect("PTO");
        conn.on_managed_probe_timeout(&cx, fired_at).expect("fire");
        conn.next_packet_numbers[packet_number_space_idx(PacketNumberSpace::ApplicationData)] =
            1u64 << 62;
        assert_eq!(
            conn.on_pto_probe_packet_sent(&cx, 40, fired_at, &[QuicFrame::Ping]),
            Err(NativeQuicConnectionError::InvalidState(
                "packet number limit reached; connection must be closed"
            ))
        );
        assert_eq!(conn.transport().bytes_in_flight(), 1_200);
        assert!(conn.pending_pto_probe);

        let mut handshaking = NativeQuicConnection::new(NativeQuicConnectionConfig::default());
        handshaking.begin_handshake(&cx).expect("handshaking");
        handshaking
            .on_packet_sent(&cx, PacketNumberSpace::Initial, 1_200, true, true, 10_000)
            .expect("initial flight");
        let deadline = handshaking
            .pto_deadline_micros(&cx, 10_000)
            .expect("clock")
            .expect("initial PTO");
        handshaking
            .on_managed_probe_timeout(&cx, deadline)
            .expect("initial timer rearmed");
        let expected = NativeQuicConnectionError::InvalidState(
            "managed PTO probe requires established 1-RTT state",
        );
        assert_eq!(
            handshaking.generate_pto_probe_frames(&cx, 1),
            Err(expected.clone())
        );
        assert_eq!(
            handshaking.on_pto_probe_packet_sent(&cx, 40, deadline, &[QuicFrame::Ping]),
            Err(expected)
        );
        assert_eq!(handshaking.transport().bytes_in_flight(), 1_200);
    }

    #[test]
    fn connection_stream_io_adapter_round_trips_one_payload() {
        let cx = test_cx();
        let mut tx = established_conn();
        let stream = tx.open_local_bidi(&cx).expect("open");
        let waker = std::task::Waker::noop().clone();
        let mut task_cx = std::task::Context::from_waker(&waker);

        {
            let mut io = tx.stream_io(&cx, stream).expect("stream io");
            let poll = crate::io::AsyncWrite::poll_write(
                std::pin::Pin::new(&mut io),
                &mut task_cx,
                b"abc",
            );
            assert!(matches!(poll, Poll::Ready(Ok(3))));
        }
        let frame = tx
            .generate_frames(&cx, PacketNumberSpace::ApplicationData, 128)
            .expect("frames")
            .into_iter()
            .find_map(|frame| match frame {
                QuicFrame::Stream { .. } => Some(frame),
                _ => None,
            })
            .expect("stream frame");

        let mut rx = established_server_conn();
        rx.process_frame(&cx, &frame, PacketNumberSpace::ApplicationData)
            .expect("process stream frame");
        let mut storage = [0u8; 8];
        let mut read_buf = crate::io::ReadBuf::new(&mut storage);
        {
            let mut io = rx.stream_io(&cx, stream).expect("stream io");
            let poll = crate::io::AsyncRead::poll_read(
                std::pin::Pin::new(&mut io),
                &mut task_cx,
                &mut read_buf,
            );
            assert!(matches!(poll, Poll::Ready(Ok(()))));
        }
        assert_eq!(read_buf.filled(), b"abc");
    }

    #[test]
    fn stream_flow_exhaustion_queues_stream_data_blocked() {
        let cx = test_cx();
        let mut conn = NativeQuicConnection::new(NativeQuicConnectionConfig {
            send_window: 4,
            connection_send_limit: 4,
            ..NativeQuicConnectionConfig::default()
        });
        conn.begin_handshake(&cx).expect("begin");
        conn.on_handshake_keys_available(&cx).expect("hs keys");
        conn.on_1rtt_keys_available(&cx).expect("1rtt keys");
        conn.record_verified_server_identity();
        conn.on_handshake_confirmed(&cx).expect("confirmed");
        let stream = conn.open_local_bidi(&cx).expect("open");
        let err = conn
            .write_stream_bytes(&cx, stream, Bytes::from_static(b"abcde"), false)
            .expect_err("flow controlled");
        assert!(matches!(
            err,
            NativeQuicConnectionError::Stream(QuicStreamError::Flow(
                FlowControlError::Exhausted { .. }
            ))
        ));
        let blocked = conn
            .generate_frames(&cx, PacketNumberSpace::ApplicationData, 128)
            .expect("frames")
            .into_iter()
            .find_map(|frame| match frame {
                QuicFrame::StreamDataBlocked { .. } => Some(frame),
                _ => None,
            });
        assert!(blocked.is_some(), "STREAM_DATA_BLOCKED must be emitted");
    }

    #[test]
    fn on_ack_ranges_via_connection_api() {
        let cx = test_cx();
        let mut conn = established_conn();
        conn.on_packet_sent(
            &cx,
            PacketNumberSpace::ApplicationData,
            1200,
            true,
            true,
            10_000,
        )
        .expect("sent");
        conn.on_packet_sent(
            &cx,
            PacketNumberSpace::ApplicationData,
            1200,
            true,
            true,
            10_050,
        )
        .expect("sent");
        let ranges = [AckRange::new(1, 0).expect("range")];
        let ack = conn
            .on_ack_ranges(&cx, PacketNumberSpace::ApplicationData, &ranges, 0, 20_000)
            .expect("ack");
        assert_eq!(ack.acked_packets, 2);
    }

    #[test]
    fn queued_ack_does_not_regress_largest_on_reordered_packets() {
        let mut conn = established_conn();
        conn.queue_ack_frame(PacketNumberSpace::ApplicationData, 5);
        conn.queue_ack_frame(PacketNumberSpace::ApplicationData, 3);

        let acks = conn
            .pending_control_frames
            .iter()
            .filter_map(|frame| match frame {
                QuicFrame::Ack {
                    largest_acknowledged,
                    first_ack_range,
                    ack_ranges,
                    ..
                } => Some((*largest_acknowledged, *first_ack_range, ack_ranges)),
                _ => None,
            })
            .collect::<Vec<_>>();

        assert_eq!(acks.len(), 1, "ACK queue should coalesce stale ACK frames");
        let (largest, first_range, ranges) = acks[0];
        assert_eq!(largest.value(), 5);
        assert_eq!(first_range.value(), 0);
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].gap.value(), 0);
        assert_eq!(ranges[0].ack_range_length.value(), 0);
    }

    #[test]
    fn queued_ack_coalesces_contiguous_received_packets() {
        let mut conn = established_conn();
        conn.queue_ack_frame(PacketNumberSpace::ApplicationData, 5);
        conn.queue_ack_frame(PacketNumberSpace::ApplicationData, 4);
        conn.queue_ack_frame(PacketNumberSpace::ApplicationData, 3);

        let ack = conn
            .pending_control_frames
            .iter()
            .find_map(|frame| match frame {
                QuicFrame::Ack {
                    largest_acknowledged,
                    first_ack_range,
                    ack_ranges,
                    ..
                } => Some((*largest_acknowledged, *first_ack_range, ack_ranges)),
                _ => None,
            })
            .expect("ACK frame queued");

        assert_eq!(ack.0.value(), 5);
        assert_eq!(ack.1.value(), 2);
        assert!(ack.2.is_empty());
    }

    #[test]
    fn begin_close_records_application_error_code() {
        let cx = test_cx();
        let mut conn = established_conn();
        conn.begin_close(&cx, 50_000, 0xdead).expect("close");
        assert_eq!(conn.transport().close_code(), Some(0xdead));
        assert!(!conn.close_was_peer_initiated());
    }

    #[test]
    fn local_close_commit_only_accepts_exact_close_without_recovery_work() {
        let cx = test_cx();
        let mut conn = established_conn();
        let frames = [QuicFrame::ConnectionClose {
            error_code: VarInt::from_u64_unchecked(42),
            frame_type: None,
            reason_phrase: Bytes::new(),
        }];
        assert!(conn.validate_local_close_packet(&cx, 64, &frames).is_err());
        conn.begin_close(&cx, 0, 42).unwrap();
        let space = PacketNumberSpace::ApplicationData;
        let number = conn.next_packet_number_for_protection(space).unwrap();
        let flight = conn.transport().bytes_in_flight();
        assert!(
            conn.validate_local_close_packet(&cx, 64, &[QuicFrame::Ping])
                .is_err()
        );
        assert!(
            conn.validate_local_close_packet(&cx, 64, &[frames[0].clone(), QuicFrame::Ping])
                .is_err()
        );
        let wrong_code = [QuicFrame::ConnectionClose {
            error_code: VarInt::from_u64_unchecked(43),
            frame_type: None,
            reason_phrase: Bytes::new(),
        }];
        assert!(
            conn.validate_local_close_packet(&cx, 64, &wrong_code)
                .is_err()
        );
        let cancelled = test_cx();
        cancelled.set_cancel_requested(true);
        assert!(matches!(
            conn.on_local_close_packet_sent(&cancelled, 64, &frames),
            Err(NativeQuicConnectionError::Cancelled)
        ));
        assert_eq!(
            conn.next_packet_number_for_protection(space).unwrap(),
            number
        );
        assert_eq!(
            conn.on_local_close_packet_sent(&cx, 64, &frames).unwrap(),
            number
        );
        assert_eq!(
            conn.next_packet_number_for_protection(space).unwrap(),
            number + 1
        );
        assert_eq!(conn.transport().bytes_in_flight(), flight);
        assert!(conn.transport().pto_deadline_micros(0).is_none());
        conn.peer_close_observed = true;
        assert!(conn.validate_local_close_packet(&cx, 64, &frames).is_err());
        conn.close_immediately(&cx, 42).unwrap();
        assert!(conn.validate_local_close_packet(&cx, 64, &frames).is_err());
    }

    /// asupersync-bi2462.107 (N10): a PATH_CHALLENGE flood keeps one pending
    /// PATH_RESPONSE (for the newest challenge), and a PATH_RESPONSE this
    /// endpoint never solicited does not validate the peer's address.
    #[test]
    fn path_challenge_flood_is_bounded_and_unsolicited_response_does_not_validate() {
        let cx = test_cx();
        let space = PacketNumberSpace::ApplicationData;
        let mut conn = established_server_conn();
        for pn in 0..1_000_u64 {
            let frames = [QuicFrame::PathChallenge {
                data: pn.to_be_bytes(),
            }];
            let mut payload = BytesMut::new();
            NativeQuicConnection::encode_frames(&frames, &mut payload).expect("encode");
            conn.process_packet_payload(&cx, space, 10 + pn, &payload, 100 + pn)
                .expect("challenge");
        }
        let responses: Vec<_> = conn
            .pending_control_frames
            .iter()
            .filter(|frame| matches!(frame, QuicFrame::PathResponse { .. }))
            .collect();
        assert_eq!(
            responses.len(),
            1,
            "one pending PATH_RESPONSE after 1000 challenges"
        );
        assert!(
            matches!(responses[0], QuicFrame::PathResponse { data } if *data == 999_u64.to_be_bytes()),
            "the pending response answers the newest challenge"
        );
        assert!(
            conn.pending_control_frames.len() < 16,
            "control queue stays bounded"
        );

        conn.peer_address_validated = false;
        let frames = [QuicFrame::PathResponse { data: [9; 8] }];
        let mut payload = BytesMut::new();
        NativeQuicConnection::encode_frames(&frames, &mut payload).expect("encode");
        conn.process_packet_payload(&cx, space, 2_000, &payload, 5_000)
            .expect("unsolicited response is ignored");
        assert!(
            !conn.peer_address_validated,
            "an unsolicited PATH_RESPONSE must not validate the peer"
        );
    }

    #[test]
    fn packet_peer_close_preserves_prefix_and_ignores_tail_without_ack() {
        let cx = test_cx();
        let space = PacketNumberSpace::ApplicationData;
        for tail in [
            QuicFrame::PathChallenge { data: [7; 8] },
            QuicFrame::Datagram {
                data: Bytes::from_static(b"after close"),
            },
            QuicFrame::Stream {
                stream_id: VarInt::from_u64_unchecked(0),
                offset: None,
                data: Bytes::from_static(b"after close"),
                fin: false,
            },
        ] {
            let mut conn = established_conn();
            let stream = conn.open_local_bidi(&cx).expect("stream");
            assert_eq!(stream.0, 0);
            let frames = [
                QuicFrame::Datagram {
                    data: Bytes::from_static(b"before close"),
                },
                QuicFrame::ConnectionClose {
                    error_code: VarInt::from_u64_unchecked(42),
                    frame_type: None,
                    reason_phrase: Bytes::new(),
                },
                tail,
            ];
            let mut payload = BytesMut::new();
            NativeQuicConnection::encode_frames(&frames, &mut payload).expect("encode");
            conn.process_packet_payload(&cx, space, 7, &payload, 100)
                .expect("trailing frames cannot fail a peer close");

            assert_eq!(conn.state(), QuicConnectionState::Draining);
            assert!(conn.close_was_peer_initiated());
            assert_eq!(conn.transport().close_code(), Some(42));
            assert_eq!(
                conn.recv_datagram(),
                Some(Bytes::from_static(b"before close"))
            );
            assert_eq!(conn.recv_datagram(), None);
            assert_eq!(conn.streams.stream(stream).unwrap().recv_offset, 0);
            assert!(conn.pending_control_frames.is_empty());
            assert!(conn.received_ack_trackers[2].ranges.is_empty());
        }
    }

    #[test]
    fn packet_delivery_after_close_has_no_effects_and_still_checks_cancellation() {
        for immediate in [false, true] {
            let cx = test_cx();
            let mut conn = established_conn();
            if immediate {
                conn.close_immediately(&cx, 42).expect("close");
            } else {
                conn.begin_close(&cx, 100, 42).expect("drain");
            }
            let state = conn.state();
            let deadline = conn.transport().drain_deadline_micros();
            let frames = [
                QuicFrame::PathChallenge { data: [9; 8] },
                QuicFrame::ConnectionClose {
                    error_code: VarInt::from_u64_unchecked(99),
                    frame_type: None,
                    reason_phrase: Bytes::new(),
                },
            ];
            conn.process_packet_frames(&cx, PacketNumberSpace::ApplicationData, 8, &frames, 200)
                .expect("terminal packet discarded");
            assert_eq!(conn.state(), state);
            assert_eq!(conn.transport().close_code(), Some(42));
            assert_eq!(conn.transport().drain_deadline_micros(), deadline);
            assert!(!conn.close_was_peer_initiated());
            assert!(conn.pending_control_frames.is_empty());
            assert!(conn.received_ack_trackers[2].ranges.is_empty());

            cx.set_cancel_requested(true);
            assert_eq!(
                conn.process_packet_frames(
                    &cx,
                    PacketNumberSpace::ApplicationData,
                    9,
                    &frames,
                    300,
                ),
                Err(NativeQuicConnectionError::Cancelled),
            );
        }
    }

    #[test]
    fn body_diagnostic_connection_close_origin_distinguishes_peer_and_local_shutdown() {
        let cx = test_cx();
        let mut peer_closed = established_conn();
        peer_closed
            .process_frame(
                &cx,
                &QuicFrame::ConnectionClose {
                    error_code: VarInt::from_u64_unchecked(0x10c),
                    frame_type: None,
                    reason_phrase: Bytes::from_static(b"peer shutdown"),
                },
                PacketNumberSpace::ApplicationData,
            )
            .expect("peer CONNECTION_CLOSE enters draining");
        assert_eq!(peer_closed.state(), QuicConnectionState::Draining);
        assert!(peer_closed.close_was_peer_initiated());
        peer_closed
            .begin_close(&cx, 1, 0)
            .expect("local drain request is idempotent after peer close");
        peer_closed
            .close_immediately(&cx, 0)
            .expect("local terminal cleanup preserves initiating origin");
        assert!(peer_closed.close_was_peer_initiated());

        let mut locally_closed = established_conn();
        locally_closed
            .begin_close(&cx, 0, 0x10c)
            .expect("local shutdown enters draining");
        locally_closed
            .process_frame(
                &cx,
                &QuicFrame::ConnectionClose {
                    error_code: VarInt::from_u64_unchecked(0x10c),
                    frame_type: None,
                    reason_phrase: Bytes::from_static(b"peer acknowledges close"),
                },
                PacketNumberSpace::ApplicationData,
            )
            .expect("peer close is idempotent after local shutdown");
        assert_eq!(locally_closed.state(), QuicConnectionState::Draining);
        assert!(!locally_closed.close_was_peer_initiated());
    }

    #[test]
    fn receive_stream_allowed_while_draining() {
        let cx = test_cx();
        let mut conn = established_conn();
        let stream = conn.open_local_bidi(&cx).expect("open");
        conn.begin_close(&cx, 50_000, 0xdead).expect("close");
        conn.receive_stream(&cx, stream, 1)
            .expect("receive while draining");
    }

    #[test]
    fn write_is_blocked_when_congestion_window_is_full() {
        let cx = test_cx();
        let mut conn = established_conn();
        for _ in 0..20 {
            let send = conn.on_packet_sent(
                &cx,
                PacketNumberSpace::ApplicationData,
                1_200,
                true,
                true,
                10_000,
            );
            if matches!(
                send,
                Err(NativeQuicConnectionError::CongestionLimited { .. })
            ) {
                return;
            }
        }
        panic!("expected congestion to limit packet sends"); // ubs:ignore - test assertion
    }

    #[test]
    fn authenticated_completion_preserves_identity_and_cancellation_gates() {
        let cx = test_cx();
        let mut conn = NativeQuicConnection::new(NativeQuicConnectionConfig::default());
        conn.begin_handshake(&cx).unwrap();
        conn.on_handshake_keys_available(&cx).unwrap();
        assert!(matches!(
            conn.on_authenticated_handshake_complete(&cx),
            Err(NativeQuicConnectionError::Tls(
                QuicTlsError::HandshakeNotConfirmed
            ))
        ));
        conn.on_1rtt_keys_available(&cx).unwrap();
        assert!(matches!(
            conn.on_authenticated_handshake_complete(&cx),
            Err(NativeQuicConnectionError::Tls(
                QuicTlsError::ServerCertificateUnverified
            ))
        ));
        assert_eq!(conn.state(), QuicConnectionState::Handshaking);
        assert!(!conn.can_send_1rtt());
        assert!(!conn.tls().can_send_1rtt());
        conn.record_verified_server_identity();
        let cancelled = test_cx();
        cancelled.set_cancel_requested(true);
        assert!(matches!(
            conn.on_authenticated_handshake_complete(&cancelled),
            Err(NativeQuicConnectionError::Cancelled)
        ));
        assert_eq!(conn.state(), QuicConnectionState::Handshaking);
        assert!(!conn.tls().can_send_1rtt());
        conn.on_authenticated_handshake_complete(&cx).unwrap();
        assert_eq!(conn.state(), QuicConnectionState::Established);
        assert!(conn.can_send_1rtt());
        assert!(!conn.tls().handshake_confirmed());
        conn.process_frame_at(
            &cx,
            &QuicFrame::HandshakeDone,
            PacketNumberSpace::ApplicationData,
            0,
        )
        .unwrap();
        assert!(conn.tls().handshake_confirmed());
    }

    #[test]
    fn handshake_confirm_does_not_mutate_tls_if_transport_is_not_handshaking() {
        let cx = test_cx();
        let mut conn = NativeQuicConnection::new(NativeQuicConnectionConfig::default());
        conn.on_1rtt_keys_available(&cx).expect("1rtt keys");
        // Record verification so this test exercises the transport-state guard
        // rather than the br-7pwwwe server-identity gate.
        conn.record_verified_server_identity();
        let err = conn.on_handshake_confirmed(&cx).expect_err("must fail");
        assert!(matches!(
            err,
            NativeQuicConnectionError::Transport(TransportError::InvalidStateTransition {
                from: QuicConnectionState::Idle,
                to: QuicConnectionState::Established
            })
        ));
        assert!(!conn.tls().can_send_1rtt());
    }

    // --- Gap 1: Cancellation path via Cx (Cancelled error variant) ---

    #[test]
    fn cancelled_cx_returns_cancelled_error() {
        let cx = test_cx();
        cx.set_cancel_requested(true);
        let mut conn = NativeQuicConnection::new(NativeQuicConnectionConfig::default());
        let err = conn.begin_handshake(&cx).expect_err("must fail");
        assert_eq!(err, NativeQuicConnectionError::Cancelled);
    }

    #[test]
    fn cancelled_cx_blocks_open_local_bidi() {
        let cx = test_cx();
        let mut conn = established_conn();
        cx.set_cancel_requested(true);
        let err = conn.open_local_bidi(&cx).expect_err("must fail");
        assert_eq!(err, NativeQuicConnectionError::Cancelled);
    }

    #[test]
    fn cancelled_cx_blocks_poll() {
        let cx = test_cx();
        let mut conn = established_conn();
        cx.set_cancel_requested(true);
        let err = conn.poll(&cx, 1_000_000).expect_err("must fail");
        assert_eq!(err, NativeQuicConnectionError::Cancelled);
    }

    // --- Gap 2: close_immediately via NativeQuicConnection wrapper ---

    #[test]
    fn close_immediately_transitions_to_closed_with_code() {
        let cx = test_cx();
        let mut conn = established_conn();
        conn.close_immediately(&cx, 0xbeef).expect("close");
        assert_eq!(conn.state(), QuicConnectionState::Closed);
        assert_eq!(conn.transport().close_code(), Some(0xbeef));
    }

    #[test]
    fn close_immediately_from_handshaking() {
        let cx = test_cx();
        let mut conn = NativeQuicConnection::new(NativeQuicConnectionConfig::default());
        conn.begin_handshake(&cx).expect("begin");
        conn.close_immediately(&cx, 42).expect("close");
        assert_eq!(conn.state(), QuicConnectionState::Closed);
        assert_eq!(conn.transport().close_code(), Some(42));
    }

    // --- Gap 3: poll drives drain-to-closed transition ---

    #[test]
    fn poll_drives_drain_to_closed_when_deadline_reached() {
        let cx = test_cx();
        let mut conn = established_conn();
        let drain_timeout = conn.drain_timeout_micros;
        let now = 100_000u64;
        conn.begin_close(&cx, now, 0x1234).expect("drain");
        assert_eq!(conn.state(), QuicConnectionState::Draining);

        conn.poll(&cx, now + drain_timeout - 1)
            .expect("poll before deadline");
        assert_eq!(conn.state(), QuicConnectionState::Draining);

        conn.poll(&cx, now + drain_timeout)
            .expect("poll at deadline");
        assert_eq!(conn.state(), QuicConnectionState::Closed);
    }

    #[test]
    fn poll_noop_when_not_draining() {
        let cx = test_cx();
        let mut conn = established_conn();
        conn.poll(&cx, 999_999).expect("poll");
        assert_eq!(conn.state(), QuicConnectionState::Established);
    }

    // --- Gap 4: reset_stream_send via connection API ---

    #[test]
    fn reset_stream_send_records_reset_on_stream() {
        let cx = test_cx();
        let mut conn = established_conn();
        let stream = conn.open_local_bidi(&cx).expect("open");
        conn.write_stream(&cx, stream, 10).expect("write");
        conn.reset_stream_send(&cx, stream, 0x77, 10)
            .expect("reset");
        let s = conn.streams().stream(stream).expect("stream");
        assert_eq!(s.send_reset, Some((0x77, 10)));
    }

    #[test]
    fn reset_stream_send_rejects_final_size_below_sent() {
        let cx = test_cx();
        let mut conn = established_conn();
        let stream = conn.open_local_bidi(&cx).expect("open");
        conn.write_stream(&cx, stream, 20).expect("write");
        let err = conn
            .reset_stream_send(&cx, stream, 0x01, 5)
            .expect_err("must fail");
        assert!(matches!(
            err,
            NativeQuicConnectionError::Stream(QuicStreamError::InvalidFinalSize { .. })
        ));
    }

    // --- Gap 5: stop_receiving via connection API ---

    #[test]
    fn stop_receiving_discards_subsequent_receives_and_blocks_reads() {
        let cx = test_cx();
        let mut conn = established_conn();
        let stream = conn.open_local_bidi(&cx).expect("open");
        conn.stop_receiving(&cx, stream, 0x42)
            .expect("stop_receiving");
        // RFC 9000 s3.5: the peer may keep sending until it processes our
        // STOP_SENDING; that data is discarded, not a connection error.
        conn.receive_stream(&cx, stream, 1)
            .expect("data after our STOP_SENDING is discarded");
        let err = conn
            .read_stream_bytes(&cx, stream, 1)
            .expect_err("the application read side stays stopped");
        assert_eq!(
            err,
            NativeQuicConnectionError::Stream(QuicStreamError::ReceiveStopped { code: 0x42 })
        );
    }

    #[test]
    fn stop_receiving_records_error_code() {
        let cx = test_cx();
        let mut conn = established_conn();
        let stream = conn.open_local_bidi(&cx).expect("open");
        conn.stop_receiving(&cx, stream, 99).expect("stop");
        let s = conn.streams().stream(stream).expect("stream");
        assert_eq!(s.receive_stopped_error_code, Some(99));
    }

    // --- Gap 6: Key update methods via connection API ---

    #[test]
    fn request_and_commit_local_key_update() {
        let cx = test_cx();
        let mut conn = established_conn();
        let scheduled = conn.request_local_key_update(&cx).expect("request");
        assert_eq!(
            scheduled,
            KeyUpdateEvent::LocalUpdateScheduled {
                next_phase: true,
                generation: 1,
            }
        );
        let committed = conn.commit_local_key_update(&cx).expect("commit");
        assert_eq!(
            committed,
            KeyUpdateEvent::LocalUpdateScheduled {
                next_phase: true,
                generation: 1,
            }
        );
        assert!(conn.tls().local_key_phase());
    }

    #[test]
    fn on_peer_key_phase_via_connection_api() {
        let cx = test_cx();
        let mut conn = established_conn();
        assert!(!conn.tls().remote_key_phase());
        let evt = conn.on_peer_key_phase(&cx, true).expect("peer update");
        assert_eq!(
            evt,
            KeyUpdateEvent::RemoteUpdateAccepted {
                new_phase: true,
                generation: 1,
            }
        );
        assert!(conn.tls().remote_key_phase());
    }

    #[test]
    fn duplicate_peer_key_phase_returns_no_change() {
        let cx = test_cx();
        let mut conn = established_conn();
        conn.on_peer_key_phase(&cx, true).expect("first");
        let evt = conn.on_peer_key_phase(&cx, true).expect("second same");
        assert_eq!(evt, KeyUpdateEvent::NoChange);
    }

    #[test]
    fn appdata_packets_allowed_with_0rtt_resumption() {
        let cx = test_cx();
        let mut conn = NativeQuicConnection::new(NativeQuicConnectionConfig::default());
        conn.begin_handshake(&cx).expect("begin");
        conn.on_handshake_keys_available(&cx)
            .expect("handshake keys");
        conn.enable_resumption_0rtt(&cx).expect("enable 0-rtt");

        assert!(conn.can_send_0rtt());
        let pn = conn
            .on_packet_sent(
                &cx,
                PacketNumberSpace::ApplicationData,
                1200,
                true,
                true,
                10_000,
            )
            .expect("0-rtt appdata send");
        assert_eq!(pn, 0);
    }

    #[test]
    fn client_can_open_and_write_stream_during_0rtt() {
        let cx = test_cx();
        let mut conn = NativeQuicConnection::new(NativeQuicConnectionConfig::default());
        conn.begin_handshake(&cx).expect("begin");
        conn.on_handshake_keys_available(&cx)
            .expect("handshake keys");
        conn.enable_resumption_0rtt(&cx).expect("enable 0-rtt");

        let stream = conn.open_local_bidi(&cx).expect("open 0-rtt stream");
        conn.write_stream(&cx, stream, 32)
            .expect("write 0-rtt stream");
    }

    #[test]
    fn disable_resumption_0rtt_revokes_client_early_data() {
        let cx = test_cx();
        let mut conn = NativeQuicConnection::new(NativeQuicConnectionConfig::default());
        conn.begin_handshake(&cx).expect("begin");
        conn.on_handshake_keys_available(&cx)
            .expect("handshake keys");
        conn.enable_resumption_0rtt(&cx).expect("enable 0-rtt");
        assert!(conn.can_send_0rtt());

        conn.disable_resumption_0rtt(&cx).expect("disable 0-rtt");

        assert!(!conn.can_send_0rtt());
        let err = conn
            .on_packet_sent(
                &cx,
                PacketNumberSpace::ApplicationData,
                1200,
                true,
                true,
                10_000,
            )
            .expect_err("application data must fail after disabling 0-rtt");
        assert_eq!(
            err,
            NativeQuicConnectionError::InvalidState(
                "application-data packets require established 1-RTT state"
            )
        );
    }

    #[test]
    fn server_cannot_enable_0rtt_resumption() {
        let cx = test_cx();
        let mut conn = NativeQuicConnection::new(NativeQuicConnectionConfig {
            role: StreamRole::Server,
            ..NativeQuicConnectionConfig::default()
        });
        conn.begin_handshake(&cx).expect("begin");
        conn.on_handshake_keys_available(&cx)
            .expect("handshake keys");

        let err = conn
            .enable_resumption_0rtt(&cx)
            .expect_err("server must not opt into 0-rtt sending");
        assert_eq!(
            err,
            NativeQuicConnectionError::InvalidState("0-RTT resumption is client-only")
        );
        assert!(!conn.can_send_0rtt());
    }

    #[test]
    fn server_send_is_limited_by_anti_amplification_budget() {
        let cx = test_cx();
        let mut conn = NativeQuicConnection::new(NativeQuicConnectionConfig {
            role: StreamRole::Server,
            ..NativeQuicConnectionConfig::default()
        });
        conn.begin_handshake(&cx).expect("begin");

        conn.on_packet_sent(&cx, PacketNumberSpace::Handshake, 1_200, true, true, 10_000)
            .expect("first flight");
        conn.on_packet_sent(&cx, PacketNumberSpace::Handshake, 1_200, true, true, 10_100)
            .expect("second flight");
        conn.on_packet_sent(&cx, PacketNumberSpace::Handshake, 1_200, true, true, 10_200)
            .expect("third flight");

        let err = conn
            .on_packet_sent(&cx, PacketNumberSpace::Handshake, 1, true, true, 10_300)
            .expect_err("fourth flight must exceed 3x limit");
        assert_eq!(
            err,
            NativeQuicConnectionError::AmplificationLimited {
                requested: 1,
                bytes_sent: 3_600,
                bytes_received: 1_200,
                limit: 3_600,
            }
        );
    }

    #[test]
    fn peer_address_validation_lifts_anti_amplification_limit() {
        let cx = test_cx();
        let mut conn = NativeQuicConnection::new(NativeQuicConnectionConfig {
            role: StreamRole::Server,
            ..NativeQuicConnectionConfig::default()
        });
        conn.begin_handshake(&cx).expect("begin");
        conn.on_packet_sent(&cx, PacketNumberSpace::Handshake, 1_200, true, true, 10_000)
            .expect("first flight");
        conn.on_packet_sent(&cx, PacketNumberSpace::Handshake, 1_200, true, true, 10_100)
            .expect("second flight");
        conn.on_packet_sent(&cx, PacketNumberSpace::Handshake, 1_200, true, true, 10_200)
            .expect("third flight");

        conn.validate_peer_address(&cx).expect("validate");
        conn.on_packet_sent(&cx, PacketNumberSpace::Handshake, 1_200, true, true, 10_300)
            .expect("validated peer may exceed prior 3x limit");
    }

    #[test]
    fn path_migration_requires_established_state() {
        let cx = test_cx();
        let mut conn = NativeQuicConnection::new(NativeQuicConnectionConfig::default());
        conn.begin_handshake(&cx).expect("begin");
        let err = conn
            .request_path_migration(&cx, 7)
            .expect_err("must fail while handshaking");
        assert_eq!(
            err,
            NativeQuicConnectionError::InvalidState("path migration requires established state")
        );
    }

    #[test]
    fn path_migration_is_blocked_when_disabled() {
        let cx = test_cx();
        let mut conn = established_conn();
        conn.set_active_migration_disabled(&cx, true)
            .expect("set policy");
        let err = conn
            .request_path_migration(&cx, 9)
            .expect_err("must fail when migration disabled");
        assert_eq!(
            err,
            NativeQuicConnectionError::InvalidState(
                "active migration disabled by transport parameters"
            )
        );
    }

    #[test]
    fn path_migration_updates_active_path_and_counter() {
        let cx = test_cx();
        let mut conn = established_conn();
        assert_eq!(conn.active_path_id(), 0);
        assert_eq!(conn.migration_events(), 0);

        let n = conn
            .request_path_migration(&cx, 3)
            .expect("first migration");
        assert_eq!(n, 1);
        assert_eq!(conn.active_path_id(), 3);
        assert_eq!(conn.migration_events(), 1);

        let n = conn
            .request_path_migration(&cx, 3)
            .expect("same path is idempotent");
        assert_eq!(n, 1);
        assert_eq!(conn.migration_events(), 1);

        let n = conn
            .request_path_migration(&cx, 11)
            .expect("second migration");
        assert_eq!(n, 2);
        assert_eq!(conn.active_path_id(), 11);
        assert_eq!(conn.migration_events(), 2);
    }

    // --- Gap 7: next_writable_stream via connection API ---

    #[test]
    fn next_writable_stream_returns_open_stream() {
        let cx = test_cx();
        let mut conn = established_conn();
        let stream = conn.open_local_bidi(&cx).expect("open");
        let writable = conn.next_writable_stream(&cx).expect("next_writable");
        assert_eq!(writable, Some(stream));
    }

    #[test]
    fn next_writable_stream_returns_none_when_no_streams() {
        let cx = test_cx();
        let mut conn = established_conn();
        let writable = conn.next_writable_stream(&cx).expect("next_writable");
        assert_eq!(writable, None);
    }

    #[test]
    fn next_writable_stream_skips_stopped_stream() {
        let cx = test_cx();
        let mut conn = established_conn();
        let s1 = conn.open_local_bidi(&cx).expect("open1");
        let s2 = conn.open_local_bidi(&cx).expect("open2");
        conn.on_stop_sending(&cx, s1, 99).expect("stop s1");
        let writable = conn.next_writable_stream(&cx).expect("next_writable");
        assert_eq!(writable, Some(s2));
    }

    // --- Gap 8: Write operations after Close -> InvalidState ---

    #[test]
    fn write_stream_after_close_returns_invalid_state() {
        let cx = test_cx();
        let mut conn = established_conn();
        let stream = conn.open_local_bidi(&cx).expect("open");
        conn.close_immediately(&cx, 0xff).expect("close");
        let err = conn
            .write_stream(&cx, stream, 1)
            .expect_err("must fail after close");
        assert_eq!(
            err,
            NativeQuicConnectionError::InvalidState("connection is closed")
        );
    }

    #[test]
    fn open_local_bidi_after_close_returns_invalid_state() {
        let cx = test_cx();
        let mut conn = established_conn();
        conn.close_immediately(&cx, 0xff).expect("close");
        let err = conn.open_local_bidi(&cx).expect_err("must fail");
        assert_eq!(
            err,
            NativeQuicConnectionError::InvalidState("connection is closed")
        );
    }

    #[test]
    fn next_writable_stream_after_close_returns_invalid_state() {
        let cx = test_cx();
        let mut conn = established_conn();
        conn.open_local_bidi(&cx).expect("open");
        conn.close_immediately(&cx, 0xff).expect("close");
        let err = conn
            .next_writable_stream(&cx)
            .expect_err("must fail after close");
        assert_eq!(
            err,
            NativeQuicConnectionError::InvalidState("connection is closed")
        );
    }

    // --- Gap 9: accept_remote_stream while draining -> InvalidState ---

    #[test]
    fn accept_remote_stream_while_draining_returns_invalid_state() {
        let cx = test_cx();
        let mut conn = established_conn();
        conn.begin_close(&cx, 50_000, 0xdead).expect("drain");
        assert_eq!(conn.state(), QuicConnectionState::Draining);
        let remote = StreamId::local(
            StreamRole::Server,
            crate::net::quic_native::streams::StreamDirection::Bidirectional,
            0,
        );
        let err = conn
            .accept_remote_stream(&cx, remote)
            .expect_err("must fail while draining");
        assert_eq!(
            err,
            NativeQuicConnectionError::InvalidState(
                "new application streams require established state"
            )
        );
    }

    #[test]
    fn accept_remote_stream_enforces_default_remote_limit() {
        // `NativeQuicConnection::new` must install a finite cap on
        // remotely-initiated streams (RFC 9000 §4.6 MAX_STREAMS) so a peer
        // cannot force unbounded stream allocations from the wire. The default
        // client connection accepts server-initiated (remote) streams; sequence
        // `DEFAULT_MAX_REMOTE_STREAMS - 1` is the highest within-limit index and
        // `DEFAULT_MAX_REMOTE_STREAMS` is the first index that must be rejected.
        let cx = test_cx();
        let mut conn = established_conn();
        let within = StreamId::local(
            StreamRole::Server,
            crate::net::quic_native::streams::StreamDirection::Bidirectional,
            DEFAULT_MAX_REMOTE_STREAMS - 1,
        );
        conn.accept_remote_stream(&cx, within)
            .expect("highest within-limit remote stream accepted");
        let over = StreamId::local(
            StreamRole::Server,
            crate::net::quic_native::streams::StreamDirection::Bidirectional,
            DEFAULT_MAX_REMOTE_STREAMS,
        );
        let err = conn
            .accept_remote_stream(&cx, over)
            .expect_err("remote stream at the limit must be rejected");
        assert!(
            matches!(
                err,
                NativeQuicConnectionError::StreamTable(
                    StreamTableError::StreamLimitExceeded { .. }
                )
            ),
            "expected StreamLimitExceeded, got: {err:?}"
        );
    }

    #[test]
    fn set_remote_stream_limits_overrides_default() {
        // The per-connection override tightens (or relaxes) the wire cap.
        let cx = test_cx();
        let mut conn = established_conn();
        conn.set_remote_stream_limits(1, 1);
        let first = StreamId::local(
            StreamRole::Server,
            crate::net::quic_native::streams::StreamDirection::Bidirectional,
            0,
        );
        conn.accept_remote_stream(&cx, first)
            .expect("first remote stream within tightened limit");
        let second = StreamId::local(
            StreamRole::Server,
            crate::net::quic_native::streams::StreamDirection::Bidirectional,
            1,
        );
        let err = conn
            .accept_remote_stream(&cx, second)
            .expect_err("second remote stream exceeds tightened limit");
        assert!(matches!(
            err,
            NativeQuicConnectionError::StreamTable(StreamTableError::StreamLimitExceeded { .. })
        ));
    }

    #[test]
    fn increasing_remote_stream_limits_emits_max_streams_frames() {
        let cx = test_cx();
        let mut conn = established_conn();

        conn.set_remote_stream_limits(256, 512);
        let frames = conn
            .generate_frames(&cx, PacketNumberSpace::ApplicationData, 128)
            .expect("control frames should generate");

        assert_eq!(
            frames,
            vec![
                QuicFrame::MaxStreams {
                    maximum_streams: VarInt::from_u64_unchecked(256),
                    bidirectional: true,
                },
                QuicFrame::MaxStreams {
                    maximum_streams: VarInt::from_u64_unchecked(512),
                    bidirectional: false,
                },
            ]
        );

        conn.set_remote_stream_limits(128, 128);
        let frames = conn
            .generate_frames(&cx, PacketNumberSpace::ApplicationData, 128)
            .expect("lowering limits should not emit MAX_STREAMS");
        assert!(frames.is_empty());
    }

    #[test]
    fn remote_stream_limits_never_advertise_more_than_two_to_the_sixty() {
        // br-asupersync-5f1fcj: the clamp was VARINT_MAX (2^62 - 1), so a large
        // limit sent a MAX_STREAMS that a conforming peer must reject with
        // FRAME_ENCODING_ERROR (RFC 9000 section 4.6).
        let cx = test_cx();
        let mut conn = established_conn();
        conn.set_remote_stream_limits(u64::MAX, (1u64 << 60) + 1);
        let frames = conn
            .generate_frames(&cx, PacketNumberSpace::ApplicationData, 128)
            .expect("control frames should generate");
        assert_eq!(
            frames,
            vec![
                QuicFrame::MaxStreams {
                    maximum_streams: VarInt::from_u64_unchecked(1u64 << 60),
                    bidirectional: true,
                },
                QuicFrame::MaxStreams {
                    maximum_streams: VarInt::from_u64_unchecked(1u64 << 60),
                    bidirectional: false,
                },
            ]
        );
    }

    #[test]
    fn received_max_streams_extends_exhausted_connections_in_each_direction() {
        let cx = test_cx();
        for mut conn in [established_conn(), established_server_conn()] {
            let role = conn.role;
            for seq in 0..128 {
                assert_eq!(
                    conn.open_local_bidi(&cx).expect("initial bidi grant"),
                    StreamId::local(role, StreamDirection::Bidirectional, seq)
                );
                conn.open_local_uni(&cx).expect("initial uni grant");
            }
            assert!(conn.open_local_bidi(&cx).is_err());
            assert!(conn.open_local_uni(&cx).is_err());
            let remote_limits = conn.streams().remote_stream_limits();
            // Independent wire bytes: MAX_STREAMS_BIDI(256), followed by
            // duplicate/reordered grants. These must not reduce the new limit.
            conn.process_packet_payload(
                &cx,
                PacketNumberSpace::ApplicationData,
                1,
                &[0x12, 0x41, 0x00, 0x12, 0x41, 0x00, 0x12, 0x00],
                100,
            )
            .expect("process peer bidi credit");
            assert_eq!(conn.streams().len(), 256, "grant must allocate nothing");
            assert!(
                conn.open_local_uni(&cx).is_err(),
                "uni is still exhausted"
            );
            for seq in 128..256 {
                assert_eq!(
                    conn.open_local_bidi(&cx).expect("renewed bidi credit"),
                    StreamId::local(role, StreamDirection::Bidirectional, seq)
                );
            }
            assert!(conn.open_local_bidi(&cx).is_err());

            // A separate unidirectional grant authorizes exactly one new ID.
            conn.process_packet_payload(
                &cx,
                PacketNumberSpace::ApplicationData,
                2,
                &[0x13, 0x40, 0x81],
                200,
            )
            .expect("process peer uni credit");
            assert_eq!(
                conn.open_local_uni(&cx).expect("renewed uni credit"),
                StreamId::local(role, StreamDirection::Unidirectional, 128)
            );
            assert!(conn.open_local_uni(&cx).is_err());
            assert!(conn.open_local_bidi(&cx).is_err());
            assert_eq!(conn.streams().remote_stream_limits(), remote_limits);
        }
    }

    #[test]
    fn received_max_streams_rejects_unencodable_grants_before_mutation() {
        let cx = test_cx();
        for frame_type in [0x12, 0x13] {
            let mut conn = established_conn();
            let error = conn
                .process_packet_payload(
                    &cx,
                    PacketNumberSpace::ApplicationData,
                    1,
                    &[frame_type, 0xd0, 0, 0, 0, 0, 0, 0, 1], // 2^60 + 1
                    100,
                )
                .expect_err("MAX_STREAMS above 2^60 is a frame error");
            assert_eq!(
                error,
                NativeQuicConnectionError::Frame(QuicFrameError::InvalidFormat(
                    "MAX_STREAMS exceeds the 2^60 stream limit".to_owned()
                ))
            );
            assert!(
                !conn.has_pending_control_frames(),
                "rejected packet is not ACKed"
            );
            // The error closes the connection (br-asupersync-tzjbn9 F3), so
            // the unchanged credit is read from the stream table.
            assert_eq!(conn.transport().close_code(), Some(FRAME_ENCODING_ERROR));
            for _ in 0..128 {
                conn.streams
                    .open_local_bidi()
                    .expect("original bidi credit unchanged");
                conn.streams
                    .open_local_uni()
                    .expect("original uni credit unchanged");
            }
            assert!(conn.streams.open_local_bidi().is_err());
            assert!(conn.streams.open_local_uni().is_err());

            let mut conn = established_conn();
            for _ in 0..128 {
                conn.open_local_bidi(&cx).expect("initial bidi credit");
                conn.open_local_uni(&cx).expect("initial uni credit");
            }
            conn.process_packet_payload(
                &cx,
                PacketNumberSpace::ApplicationData,
                2,
                &[frame_type, 0xd0, 0, 0, 0, 0, 0, 0, 0], // 2^60 exactly
                200,
            )
            .expect("largest encodable grant is valid");
            let (renewed, unchanged) = if frame_type == 0x12 {
                (conn.open_local_bidi(&cx), conn.open_local_uni(&cx))
            } else {
                (conn.open_local_uni(&cx), conn.open_local_bidi(&cx))
            };
            assert!(renewed.is_ok());
            assert!(unchanged.is_err());
        }
    }

    /// br-asupersync-tzjbn9 (suspected item, confirmed): a held slice keeps its
    /// whole datagram allocated, so a STREAM payload that uses under a quarter
    /// of its datagram is copied out, while one that fills most of it stays a
    /// zero-copy slice of the datagram.
    #[test]
    fn decode_frames_bytes_copies_small_payloads_and_slices_large_ones() {
        let slices = |data: &Bytes, datagram: &Bytes| {
            let start = datagram.as_ptr() as usize;
            let at = data.as_ptr() as usize;
            at >= start && at < start + datagram.len()
        };
        for (data_len, zero_copy) in [(1_usize, false), (3_000, true)] {
            let mut encoded = BytesMut::new();
            QuicFrame::Stream {
                stream_id: VarInt::from_u64_unchecked(0),
                offset: Some(VarInt::from_u64_unchecked(7)),
                data: Bytes::from(vec![0xab; data_len]),
                fin: false,
            }
            .encode(&mut encoded)
            .expect("encode STREAM");
            // PADDING out to a 4 KiB datagram.
            encoded.resize(4096, 0);
            let datagram = encoded.freeze();

            let frames = NativeQuicConnection::decode_frames_bytes(&datagram).expect("decode");
            let QuicFrame::Stream { data, .. } = &frames[0] else {
                panic!("expected STREAM first, got {:?}", frames[0]);
            };
            assert_eq!(data.len(), data_len);
            assert_eq!(slices(data, &datagram), zero_copy, "data_len={data_len}");
        }
    }

    #[test]
    fn received_max_streams_requires_application_packet_space() {
        let cx = test_cx();
        for space in [PacketNumberSpace::Initial, PacketNumberSpace::Handshake] {
            let mut conn = established_conn();
            let error = conn
                .process_packet_payload(&cx, space, 1, &[0x12, 0x41, 0x00], 100)
                .expect_err("MAX_STREAMS is not permitted in handshake packets");
            assert_eq!(
                error,
                NativeQuicConnectionError::InvalidState(FRAME_NOT_PERMITTED_IN_PACKET_SPACE)
            );
            // RFC 9000 section 12.4: a PROTOCOL_VIOLATION naming MAX_STREAMS.
            assert_eq!(conn.transport().close_code(), Some(PROTOCOL_VIOLATION));
            assert_eq!(conn.local_close_frame_type(), Some(VarInt(0x12)));
            assert!(!conn.has_pending_control_frames(), "no ACK for the packet");
            for _ in 0..128 {
                conn.streams
                    .open_local_bidi()
                    .expect("initial credit unchanged");
            }
            assert!(conn.streams.open_local_bidi().is_err());
        }
    }

    /// br-asupersync-tzjbn9 F9: Initial keys derive from the client's
    /// connection ID, so anyone on the path can forge an Initial packet. Its
    /// STREAM data must never reach a stream, nor may the frames ahead of it
    /// take effect.
    #[test]
    fn handshake_packets_refuse_frames_rfc_9000_does_not_permit_there() {
        let cx = test_cx();
        // A server: stream 0 is the peer's bidirectional stream.
        let stream = QuicFrame::Stream {
            stream_id: VarInt(0),
            offset: None,
            data: Bytes::from_static(b"forged"),
            fin: false,
        };
        let max_data = QuicFrame::MaxData {
            maximum_data: VarInt(1 << 30),
        };
        for space in [PacketNumberSpace::Initial, PacketNumberSpace::Handshake] {
            let mut conn = established_server_conn();
            let error = conn
                .process_packet_frames(&cx, space, 1, &[QuicFrame::Ping, stream.clone()], 100)
                .expect_err("STREAM is not permitted in handshake packets");
            assert_eq!(
                error,
                NativeQuicConnectionError::InvalidState(FRAME_NOT_PERMITTED_IN_PACKET_SPACE)
            );
            assert_eq!(conn.transport().close_code(), Some(PROTOCOL_VIOLATION));
            assert_eq!(conn.local_close_frame_type(), Some(VarInt(0x08)));
            assert!(
                conn.streams.stream(StreamId(0)).is_err(),
                "forged data opened no stream"
            );
            // A server already owes HANDSHAKE_DONE, so look for the ACK itself.
            assert!(
                !conn
                    .pending_control_frames
                    .iter()
                    .any(|frame| matches!(frame, QuicFrame::Ack { .. })),
                "no ACK for the packet"
            );

            let mut conn = established_server_conn();
            conn.process_packet_frames(&cx, space, 1, &[max_data.clone()], 100)
                .expect_err("MAX_DATA is not permitted in handshake packets");
            assert_eq!(conn.transport().close_code(), Some(PROTOCOL_VIOLATION));
            assert_eq!(conn.local_close_frame_type(), Some(VarInt(0x10)));
        }

        // The same frames are ordinary 1-RTT input, and the frames Table 3
        // permits stay accepted in the handshake spaces.
        let mut conn = established_server_conn();
        conn.process_packet_frames(&cx, PacketNumberSpace::ApplicationData, 1, &[stream], 100)
            .expect("STREAM in a 1-RTT packet");
        assert!(conn.streams.stream(StreamId(0)).is_ok());
        for space in [PacketNumberSpace::Initial, PacketNumberSpace::Handshake] {
            let mut conn = established_server_conn();
            conn.process_packet_frames(
                &cx,
                space,
                1,
                &[QuicFrame::Padding { length: 1 }, QuicFrame::Ping],
                100,
            )
            .expect("PADDING and PING are permitted in every space");
            assert_eq!(conn.transport().close_code(), None);
        }
    }

    /// br-asupersync-tzjbn9 F3, F5 and F9: a peer frame that breaks a stream,
    /// flow-control or frame-encoding rule closes the connection with the RFC
    /// 9000 transport code, and its local CONNECTION_CLOSE is the transport
    /// variant naming the frame type. The error used to return with the
    /// connection still open and no close to send. RESET_STREAM and
    /// STREAM_DATA_BLOCKED on a send-only stream, MAX_STREAM_DATA on a
    /// receive-only stream and STREAMS_BLOCKED above 2^60 were accepted.
    #[test]
    fn peer_stream_violations_close_with_the_transport_error_code() {
        let cx = test_cx();
        let window = NativeQuicConnectionConfig::default().recv_window;
        let stream = |id: u64, offset: Option<u64>, data: &'static [u8]| QuicFrame::Stream {
            stream_id: VarInt(id),
            offset: offset.map(VarInt),
            data: Bytes::from_static(data),
            fin: false,
        };
        // A server: stream 0 is the peer's bidirectional stream, 2 the peer's
        // receive-only stream, 1 a local stream never opened, and 3 the local
        // send-only stream each case opens.
        let send_only = 3;
        let remote_bidi_limit = established_server_conn().streams().remote_stream_limits().0;
        let cases = [
            (
                "STREAM past the stream window",
                vec![stream(0, Some(window), b"x")],
                FLOW_CONTROL_ERROR,
                0x0c,
            ),
            (
                "STREAM past the peer's stream limit",
                vec![stream(remote_bidi_limit << 2, None, b"x")],
                STREAM_LIMIT_ERROR,
                0x08,
            ),
            (
                "STREAM for a local stream never opened",
                vec![stream(1, None, b"x")],
                STREAM_STATE_ERROR,
                0x08,
            ),
            (
                "RESET_STREAM on a send-only stream",
                vec![QuicFrame::ResetStream {
                    stream_id: VarInt(send_only),
                    error_code: VarInt(9),
                    final_size: VarInt(0),
                }],
                STREAM_STATE_ERROR,
                0x04,
            ),
            (
                "MAX_STREAM_DATA on a receive-only stream",
                vec![
                    stream(2, Some(0), b"up"),
                    QuicFrame::MaxStreamData {
                        stream_id: VarInt(2),
                        maximum_stream_data: VarInt(1 << 20),
                    },
                ],
                STREAM_STATE_ERROR,
                0x11,
            ),
            (
                "STREAM_DATA_BLOCKED on a send-only stream",
                vec![QuicFrame::StreamDataBlocked {
                    stream_id: VarInt(send_only),
                    maximum_stream_data: VarInt(0),
                }],
                STREAM_STATE_ERROR,
                0x15,
            ),
            (
                "RESET_STREAM below the bytes received",
                vec![
                    stream(0, Some(0), b"abcd"),
                    QuicFrame::ResetStream {
                        stream_id: VarInt(0),
                        error_code: VarInt(9),
                        final_size: VarInt(2),
                    },
                ],
                FINAL_SIZE_ERROR,
                0x04,
            ),
            (
                "STREAMS_BLOCKED above 2^60",
                vec![QuicFrame::StreamsBlocked {
                    maximum_streams: VarInt((1 << 60) + 1),
                    bidirectional: true,
                }],
                FRAME_ENCODING_ERROR,
                0x16,
            ),
        ];
        let mut failures = Vec::new();
        for (case, frames, code, frame_type) in cases {
            let mut conn = established_server_conn();
            assert_eq!(conn.open_local_uni(&cx).expect("open"), StreamId(send_only));
            let result = conn.process_packet_frames(
                &cx,
                PacketNumberSpace::ApplicationData,
                1,
                &frames,
                100,
            );
            let close = |frame_type| {
                [QuicFrame::ConnectionClose {
                    error_code: VarInt(code),
                    frame_type,
                    reason_phrase: Bytes::new(),
                }]
            };
            let observed = (
                result.is_err(),
                conn.state(),
                conn.transport().close_code(),
                conn.close_was_peer_initiated(),
                conn.is_local_close_frame(&close(Some(VarInt(frame_type)))),
                conn.is_local_close_frame(&close(None)),
            );
            let expected = (
                true,
                QuicConnectionState::Draining,
                Some(code),
                false,
                true,
                false,
            );
            if observed != expected {
                failures.push(format!("{case}: {observed:?}, result {result:?}"));
            }
        }
        // (error, state, close code, peer-initiated, transport close with the
        // frame type, application close)
        assert!(failures.is_empty(), "{failures:#?}");

        // RFC 9000 12.4: a frame type this endpoint does not know is a
        // FRAME_ENCODING_ERROR that names it.
        let mut conn = established_server_conn();
        conn.process_packet_payload(&cx, PacketNumberSpace::ApplicationData, 1, &[0x21], 100)
            .expect_err("unknown frame type");
        assert_eq!(conn.transport().close_code(), Some(FRAME_ENCODING_ERROR));
        assert_eq!(conn.local_close_frame_type(), Some(VarInt(0x21)));
    }

    /// A local close stays the application variant (0x1d), and a later peer
    /// violation cannot turn the draining close into a transport close.
    #[test]
    fn a_local_close_stays_the_application_variant() {
        let cx = test_cx();
        let mut conn = established_server_conn();
        conn.begin_close(&cx, 200, 0x42).expect("close");
        assert_eq!(conn.local_close_frame_type(), None);
        let frames = [QuicFrame::StreamsBlocked {
            maximum_streams: VarInt((1 << 60) + 1),
            bidirectional: true,
        }];
        conn.process_packet_frames(&cx, PacketNumberSpace::ApplicationData, 1, &frames, 300)
            .expect("a draining connection ignores further frames");
        assert_eq!(conn.transport().close_code(), Some(0x42));
        assert!(conn.is_local_close_frame(&[QuicFrame::ConnectionClose {
            error_code: VarInt(0x42),
            frame_type: None,
            reason_phrase: Bytes::new(),
        }]));
    }

    #[test]
    fn application_datagram_generation_coalesces_many_payloads_when_budget_allows() {
        let cx = test_cx();
        let mut conn = established_conn();
        let datagram_count = 64usize;

        for idx in 0..datagram_count {
            let payload = Bytes::from(vec![(idx % 251) as u8; 64]);
            conn.send_datagram(&cx, payload)
                .expect("queue outbound datagram");
        }

        let frames = conn
            .generate_frames(&cx, PacketNumberSpace::ApplicationData, 65_000)
            .expect("coalesced datagram frames should generate");
        let emitted = frames
            .iter()
            .filter(|frame| matches!(frame, QuicFrame::Datagram { .. }))
            .count();

        assert_eq!(emitted, datagram_count);
        assert_eq!(conn.pending_outbound_datagram_count(), 0);
        assert_eq!(conn.datagrams_sent(), datagram_count as u64);
    }

    #[test]
    fn non_datagram_generation_leaves_application_datagrams_queued() {
        let cx = test_cx();
        let mut conn = established_conn();
        conn.queue_ping(&cx).expect("queue control ping");
        conn.send_datagram(&cx, Bytes::from_static(b"symbol"))
            .expect("queue outbound datagram");

        let frames = conn
            .generate_non_datagram_frames(&cx, PacketNumberSpace::ApplicationData, 65_000)
            .expect("non-datagram frames should generate");

        assert_eq!(frames, vec![QuicFrame::Ping]);
        assert_eq!(conn.pending_outbound_datagram_count(), 1);
        assert_eq!(conn.datagrams_sent(), 0);

        let frames = conn
            .generate_frames(&cx, PacketNumberSpace::ApplicationData, 65_000)
            .expect("queued datagram should remain sendable");
        assert!(
            frames
                .iter()
                .any(|frame| matches!(frame, QuicFrame::Datagram { .. }))
        );
        assert_eq!(conn.pending_outbound_datagram_count(), 0);
        assert_eq!(conn.datagrams_sent(), 1);
    }

    /// GH#66: the peer may advertise a 65535-byte DATAGRAM frame limit, but a
    /// frame that cannot fit one protected 1-RTT packet must be refused at
    /// admission with a typed error, not admitted and then killed at assembly.
    #[test]
    fn datagram_admission_is_bounded_by_the_one_rtt_packet_budget() {
        let cx = test_cx();
        let mut conn = established_conn();
        conn.max_datagram_frame_size = 65_535;
        // 1200 - (1 + 8-byte destination CID + 4-byte packet number + 16-byte tag).
        conn.set_one_rtt_frame_budget(1_171);
        assert_eq!(conn.one_rtt_frame_budget(), 1_171);

        // 1168-byte payload -> 1 (type) + 2 (length) + 1168 = 1171-byte frame: fits exactly.
        conn.send_datagram(&cx, Bytes::from(vec![7u8; 1_168]))
            .expect("a payload whose frame fits the packet budget is admitted");
        let err = conn
            .send_datagram(&cx, Bytes::from(vec![7u8; 1_169]))
            .expect_err("a payload whose frame exceeds the packet budget is refused");
        assert!(
            matches!(
                err,
                NativeQuicConnectionError::DatagramTooLarge {
                    payload_len: 1_169,
                    encoded_len: 1_172,
                    max_frame_size: 1_171,
                }
            ),
            "{err:?}"
        );

        let frames = conn
            .generate_frames(&cx, PacketNumberSpace::ApplicationData, 1_171)
            .expect("the admitted datagram generates");
        for frame in &frames {
            let mut encoded = BytesMut::new();
            frame.encode(&mut encoded).expect("encode generated frame");
            assert!(encoded.len() <= 1_171, "generated frame exceeds the budget");
        }
        assert_eq!(conn.datagrams_sent(), 1);
        assert_eq!(conn.datagrams_dropped_on_send(), 0);
    }

    /// GH#66, defence in depth: a queued DATAGRAM that can never fit the
    /// packet budget is dropped and counted, never emitted alone into an
    /// oversize packet.
    #[test]
    fn generation_drops_a_datagram_that_can_never_fit_the_packet_budget() {
        let cx = test_cx();
        let mut conn = established_conn();
        conn.max_datagram_frame_size = 65_535;
        conn.set_one_rtt_frame_budget(5_000);
        conn.send_datagram(&cx, Bytes::from(vec![1u8; 1_180]))
            .expect("admitted under a loose budget");
        conn.send_datagram(&cx, Bytes::from(vec![2u8; 64]))
            .expect("a small payload is admitted");

        let frames = conn
            .generate_frames(&cx, PacketNumberSpace::ApplicationData, 1_171)
            .expect("generation succeeds");
        let emitted: Vec<usize> = frames
            .iter()
            .filter_map(|frame| match frame {
                QuicFrame::Datagram { data } => Some(data.len()),
                _ => None,
            })
            .collect();
        assert_eq!(emitted, vec![64], "only the fitting datagram is emitted");
        assert_eq!(conn.pending_outbound_datagram_count(), 0);
        assert_eq!(conn.datagrams_dropped_on_send(), 1);
        assert_eq!(conn.datagrams_sent(), 1);
    }

    #[test]
    fn application_datagram_batch_enqueue_preserves_order() {
        let cx = test_cx();
        let mut conn = established_conn();
        let payloads = (0..8)
            .map(|idx| Bytes::from(vec![idx as u8; 4]))
            .collect::<Vec<_>>();

        let queued = conn
            .send_datagram_batch(&cx, payloads.clone())
            .expect("batch queues outbound datagrams");

        assert_eq!(queued, payloads.len());
        assert_eq!(conn.pending_outbound_datagram_count(), payloads.len());
        let frames = conn
            .generate_frames(&cx, PacketNumberSpace::ApplicationData, 65_000)
            .expect("coalesced datagram frames should generate");
        let emitted = frames
            .into_iter()
            .filter_map(|frame| match frame {
                QuicFrame::Datagram { data } => Some(data),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(emitted, payloads);
        assert_eq!(conn.pending_outbound_datagram_count(), 0);
        assert_eq!(conn.datagrams_sent(), queued as u64);
    }

    #[test]
    fn process_packet_payload_batches_coalesced_datagrams_in_order() {
        let cx = test_cx();
        let mut conn = established_conn();
        let payloads = (0..8)
            .map(|idx| Bytes::from(vec![idx as u8; 4]))
            .collect::<Vec<_>>();
        let mut packet_payload = BytesMut::new();
        for payload in &payloads {
            QuicFrame::Datagram {
                data: payload.clone(),
            }
            .encode(&mut packet_payload)
            .expect("datagram frame encodes");
        }

        conn.process_packet_payload(
            &cx,
            PacketNumberSpace::ApplicationData,
            7,
            &packet_payload,
            1,
        )
        .expect("coalesced datagram packet accepted");

        assert_eq!(conn.pending_datagram_count(), payloads.len());
        assert_eq!(conn.datagrams_received(), payloads.len() as u64);
        for expected in payloads {
            assert_eq!(conn.recv_datagram().expect("queued datagram"), expected);
        }
        assert!(conn.recv_datagram().is_none());
    }

    #[test]
    fn inbound_datagram_queue_drops_new_overflow_without_evicting_survivors() {
        let cx = test_cx();
        let mut conn = established_conn();
        assert_eq!(conn.inbound_datagram_capacity(), MAX_INBOUND_DATAGRAMS);
        assert_eq!(
            conn.inbound_datagram_remaining_capacity(),
            MAX_INBOUND_DATAGRAMS
        );

        for idx in 0..MAX_INBOUND_DATAGRAMS {
            let payload = Bytes::from(vec![(idx % 251) as u8]);
            conn.process_frame(
                &cx,
                &QuicFrame::Datagram { data: payload },
                PacketNumberSpace::ApplicationData,
            )
            .expect("within-capacity datagram accepted");
        }

        assert_eq!(conn.pending_datagram_count(), MAX_INBOUND_DATAGRAMS);
        assert_eq!(conn.inbound_datagram_remaining_capacity(), 0);
        assert_eq!(conn.datagrams_received(), MAX_INBOUND_DATAGRAMS as u64);
        assert_eq!(conn.datagrams_dropped_on_receive(), 0);

        conn.process_frame(
            &cx,
            &QuicFrame::Datagram {
                data: Bytes::from_static(b"overflow"),
            },
            PacketNumberSpace::ApplicationData,
        )
        .expect("full inbound datagram queue treats new payload as counted loss");
        assert_eq!(conn.pending_datagram_count(), MAX_INBOUND_DATAGRAMS);
        assert_eq!(conn.datagrams_received(), MAX_INBOUND_DATAGRAMS as u64);
        assert_eq!(conn.datagrams_dropped_on_receive(), 1);

        for idx in 0..MAX_INBOUND_DATAGRAMS {
            let payload = conn.recv_datagram().expect("survivor preserved");
            assert_eq!(payload.as_ref(), &[(idx % 251) as u8]);
        }
        assert!(conn.recv_datagram().is_none());
        assert_eq!(
            conn.inbound_datagram_remaining_capacity(),
            MAX_INBOUND_DATAGRAMS
        );
    }

    #[test]
    fn datagrams_beyond_the_local_offer_are_protocol_violations_and_never_queued() {
        let cx = test_cx();
        let space = PacketNumberSpace::ApplicationData;
        let datagram = |len: usize| QuicFrame::Datagram {
            data: Bytes::from(vec![7; len]),
        };

        // A construction path that records no offer keeps the old behaviour.
        let mut unrecorded = established_conn();
        unrecorded
            .process_frame(&cx, &datagram(1), space)
            .expect("an unrecorded offer keeps accepting DATAGRAM frames");
        assert_eq!(unrecorded.pending_datagram_count(), 1);

        // RFC 9221 §3: DATAGRAM support was never advertised.
        let mut unadvertised = established_conn();
        unadvertised.set_local_max_datagram_frame_size(None);
        for _ in 0..1_000 {
            let error = unadvertised
                .process_frame(&cx, &datagram(1_000), space)
                .expect_err("an unadvertised DATAGRAM is a protocol violation");
            assert!(
                matches!(&error, NativeQuicConnectionError::InvalidState(message)
                    if message.contains("without an advertised")),
                "{error:?}"
            );
        }
        assert_eq!(unadvertised.pending_datagram_count(), 0);
        assert_eq!(unadvertised.datagrams_received(), 0);

        // An offer of 100 bytes covers the whole frame, type byte included.
        let mut bounded = established_conn();
        bounded.set_local_max_datagram_frame_size(Some(100));
        bounded
            .process_frame(&cx, &datagram(99), space)
            .expect("a 100-byte frame fits a 100-byte offer");
        let error = bounded
            .process_frame(&cx, &datagram(100), space)
            .expect_err("a frame larger than the offer is a protocol violation");
        assert!(
            matches!(&error, NativeQuicConnectionError::InvalidState(message)
                if message.contains("exceeds the advertised")),
            "{error:?}"
        );
        assert_eq!(bounded.pending_datagram_count(), 1);
        assert_eq!(bounded.datagrams_received(), 1);
    }

    #[test]
    fn recv_datagram_batch_preserves_order_and_limit() {
        let cx = test_cx();
        let mut conn = established_conn();

        for idx in 0u8..5 {
            conn.process_frame(
                &cx,
                &QuicFrame::Datagram {
                    data: Bytes::from(vec![idx]),
                },
                PacketNumberSpace::ApplicationData,
            )
            .expect("datagram accepted");
        }

        let mut batch = VecDeque::new();
        assert_eq!(conn.recv_datagram_batch(0, &mut batch), 0);
        assert!(batch.is_empty());
        assert_eq!(conn.pending_datagram_count(), 5);

        assert_eq!(conn.recv_datagram_batch(3, &mut batch), 3);
        let first: Vec<_> = batch.iter().map(|bytes| bytes[0]).collect();
        assert_eq!(first, vec![0, 1, 2]);
        assert_eq!(conn.pending_datagram_count(), 2);

        assert_eq!(conn.recv_datagram_batch(10, &mut batch), 2);
        let second: Vec<_> = batch.iter().map(|bytes| bytes[0]).collect();
        assert_eq!(second, vec![3, 4]);
        assert_eq!(conn.pending_datagram_count(), 0);
        assert_eq!(conn.recv_datagram_batch(10, &mut batch), 0);
        assert!(batch.is_empty());
    }

    // --- Gap 10: NativeQuicConnectionError Display/From impls ---

    #[test]
    fn display_cancelled() {
        let err = NativeQuicConnectionError::Cancelled;
        assert_eq!(format!("{err}"), "operation cancelled");
    }

    #[test]
    fn display_congestion_limited() {
        let err = NativeQuicConnectionError::CongestionLimited {
            requested: 1500,
            bytes_in_flight: 12000,
            congestion_window: 12000,
        };
        assert_eq!(
            format!("{err}"),
            "congestion window exceeded: requested=1500, in_flight=12000, cwnd=12000"
        );
    }

    #[test]
    fn display_invalid_state() {
        let err = NativeQuicConnectionError::InvalidState("test message");
        assert_eq!(
            format!("{err}"),
            "invalid native quic connection state: test message"
        );
    }

    #[test]
    fn display_datagram_too_large() {
        let err = NativeQuicConnectionError::DatagramTooLarge {
            payload_len: 4096,
            encoded_len: 4099,
            max_frame_size: 1200,
        };
        assert_eq!(
            format!("{err}"),
            "datagram frame too large: payload_len=4096, encoded_len=4099, max_frame_size=1200"
        );
    }

    #[test]
    fn display_datagram_receive_queue_full() {
        let err = NativeQuicConnectionError::DatagramReceiveQueueFull {
            capacity: MAX_INBOUND_DATAGRAMS,
        };
        assert_eq!(
            format!("{err}"),
            format!(
                "inbound datagram receive queue full: capacity={MAX_INBOUND_DATAGRAMS}; drain buffered payloads before processing more"
            )
        );
    }

    #[test]
    fn from_quic_tls_error() {
        let tls_err = QuicTlsError::HandshakeNotConfirmed;
        let conn_err: NativeQuicConnectionError = tls_err.clone().into();
        assert_eq!(conn_err, NativeQuicConnectionError::Tls(tls_err));
    }

    #[test]
    fn from_transport_error() {
        let transport_err = TransportError::InvalidStateTransition {
            from: QuicConnectionState::Idle,
            to: QuicConnectionState::Established,
        };
        let conn_err: NativeQuicConnectionError = transport_err.clone().into();
        assert_eq!(
            conn_err,
            NativeQuicConnectionError::Transport(transport_err)
        );
    }

    #[test]
    fn from_quic_frame_error() {
        let frame_err = QuicFrameError::UnexpectedEof;
        let conn_err: NativeQuicConnectionError = frame_err.clone().into();
        assert_eq!(conn_err, NativeQuicConnectionError::Frame(frame_err));
    }

    #[test]
    fn from_stream_table_error() {
        let st_err = StreamTableError::UnknownStream(StreamId(99));
        let conn_err: NativeQuicConnectionError = st_err.clone().into();
        assert_eq!(conn_err, NativeQuicConnectionError::StreamTable(st_err));
    }

    #[test]
    fn from_quic_stream_error() {
        let stream_err = QuicStreamError::SendStopped { code: 42 };
        let conn_err: NativeQuicConnectionError = stream_err.clone().into();
        assert_eq!(conn_err, NativeQuicConnectionError::Stream(stream_err));
    }

    #[test]
    fn display_tls_error_passthrough() {
        let inner = QuicTlsError::HandshakeNotConfirmed;
        let err = NativeQuicConnectionError::Tls(inner.clone());
        assert_eq!(format!("{err}"), format!("{inner}"));
    }

    #[test]
    fn display_transport_error_passthrough() {
        let inner = TransportError::InvalidStateTransition {
            from: QuicConnectionState::Idle,
            to: QuicConnectionState::Closed,
        };
        let err = NativeQuicConnectionError::Transport(inner.clone());
        assert_eq!(format!("{err}"), format!("{inner}"));
    }

    #[test]
    fn display_frame_error_passthrough() {
        let inner = QuicFrameError::UnknownFrameType(0x40);
        let err = NativeQuicConnectionError::Frame(inner.clone());
        assert_eq!(format!("{err}"), format!("{inner}"));
    }

    #[test]
    fn display_stream_table_error_passthrough() {
        let inner = StreamTableError::UnknownStream(StreamId(7));
        let err = NativeQuicConnectionError::StreamTable(inner.clone());
        assert_eq!(format!("{err}"), format!("{inner}"));
    }

    #[test]
    fn display_stream_error_passthrough() {
        let inner = QuicStreamError::SendStopped { code: 100 };
        let err = NativeQuicConnectionError::Stream(inner.clone());
        assert_eq!(format!("{err}"), format!("{inner}"));
    }

    #[test]
    fn next_packet_number_accepts_max_valid_then_rejects_overflow() {
        // RFC 9000 §17.1: packet numbers in [0, 2^62-1] inclusive.
        let mut conn = NativeQuicConnection::new(NativeQuicConnectionConfig::default());
        // Seed the Initial space cursor at 2^62 - 1: that exact value is the
        // last valid packet number and must be issued exactly once before the
        // exhaustion guard fires.
        conn.next_packet_numbers[0] = (1u64 << 62) - 1;
        let pn = conn
            .next_packet_number(PacketNumberSpace::Initial)
            .expect("max valid packet number must be issuable");
        assert_eq!(pn, (1u64 << 62) - 1);
        let err = conn
            .next_packet_number(PacketNumberSpace::Initial)
            .expect_err("packet number 2^62 must be rejected");
        assert!(matches!(
            err,
            NativeQuicConnectionError::InvalidState(
                "packet number limit reached; connection must be closed"
            )
        ));
    }
