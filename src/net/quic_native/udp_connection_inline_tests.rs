    use super::*;
    use crate::bytes::Bytes;
    use crate::net::atp::protocol::quic_frames::QuicFrame;
    use crate::net::atp::protocol::varint::VarInt;
    use crate::net::quic_native::connection::NativeQuicConnection;
    use crate::net::quic_native::connection_manager::{
        ConnectionRouter, RoutingResult, assemble_protected_1rtt_packet, unprotect_1rtt_packet,
    };
    use crate::net::quic_native::handshake_driver::tests::{
        CA_CERT_PEM, LEAF_CERT_PEM, leaf_key, parse_one_cert,
    };
    use crate::net::quic_native::handshake_driver::{client_config, server_config};
    use crate::net::quic_native::{QuicConnectionState, StreamId};
    use futures_lite::future::{block_on, zip};
    use rustls::pki_types::ServerName;

    /// A peer that omits `initial_max_stream_data_uni` (as the managed-quiet
    /// loopback pair does) must keep full bidirectional windows. The previous
    /// binding took the minimum over all three per-type parameters with an
    /// omitted one counted as zero, which left every stream with zero send
    /// credit and failed the first `write_stream` with `Flow(Exhausted)`.
    #[test]
    fn bind_transport_parameters_keeps_bidi_windows_when_uni_is_omitted() {
        let config = NativeQuicConnectionConfig {
            max_local_bidi: 4,
            max_local_uni: 4,
            send_window: 1 << 18,
            recv_window: 1 << 18,
            connection_send_limit: 1 << 20,
            connection_recv_limit: 1 << 20,
            ..NativeQuicConnectionConfig::default()
        };
        let peer = TransportParameters {
            initial_max_data: Some(1 << 19),
            initial_max_stream_data_bidi_local: Some(1_000),
            initial_max_stream_data_bidi_remote: Some(2_000),
            initial_max_stream_data_uni: None,
            initial_max_streams_bidi: Some(2),
            ..TransportParameters::default()
        };
        let local = TransportParameters {
            initial_max_data: Some(1 << 21),
            initial_max_stream_data_bidi_local: Some(3_000),
            initial_max_stream_data_bidi_remote: Some(1 << 20),
            initial_max_stream_data_uni: None,
            initial_max_streams_bidi: Some(4),
            ..TransportParameters::default()
        };

        let bound = bind_transport_parameters(config, &local, &peer);

        // Send side: a locally opened bidi stream sends against the peer's
        // `bidi_remote`, a peer-opened one against the peer's `bidi_local`.
        assert_eq!(
            bound.send_windows,
            StreamWindows {
                local_bidi: 2_000,
                remote_bidi: 1_000,
                uni: 0,
            }
        );
        // Receive side mirrors the mapping and is capped by the configured
        // window: the local `bidi_remote` of 1 MiB clamps to 256 KiB.
        assert_eq!(
            bound.recv_windows,
            StreamWindows {
                local_bidi: 3_000,
                remote_bidi: 1 << 18,
                uni: 0,
            }
        );
        assert_eq!(bound.config.send_window, 1 << 18);
        assert_eq!(bound.config.recv_window, 1 << 18);
        assert_eq!(bound.config.max_local_bidi, 2);
        assert_eq!(bound.config.connection_send_limit, 1 << 19);
        assert_eq!(bound.config.connection_recv_limit, 1 << 20);
        // The authenticated handoff applies DATAGRAM, ACK timing and migration
        // together after this flow-control-only binding.
        assert_eq!(
            bound.config.max_datagram_frame_size,
            config.max_datagram_frame_size
        );

        // The windows reach the stream table: a client opening stream 0 gets
        // the peer's `bidi_remote` credit, not zero.
        let mut connection = QuicConnection::client(bound.config);
        let cx = Cx::for_testing();
        connection
            .inner_mut()
            .apply_peer_transport_parameters_with_datagram_cap(
                &cx,
                &peer,
                config.max_datagram_frame_size,
            )
            .unwrap();
        assert!(matches!(
            connection
                .inner_mut()
                .send_datagram(&cx, Bytes::from_static(b"no peer support")),
            Err(NativeQuicConnectionError::DatagramTooLarge {
                max_frame_size: 0,
                ..
            })
        ));
        connection
            .inner_mut()
            .set_initial_stream_windows(bound.send_windows, bound.recv_windows);
        connection.begin_handshake(&cx).unwrap();
        connection.mark_handshake_keys_available(&cx).unwrap();
        connection.mark_app_keys_available(&cx).unwrap();
        // The production handoff records the rustls-verified server identity
        // before confirming; a client cannot confirm without it.
        connection.record_verified_server_identity();
        connection.confirm_handshake(&cx).unwrap();
        let stream = connection.open_bidi_stream(&cx).unwrap();
        assert_eq!(stream, StreamId(0));
        assert_eq!(
            connection
                .inner()
                .streams()
                .stream_send_credit_remaining(stream),
            2_000
        );
        assert_eq!(
            connection
                .inner()
                .streams()
                .stream(stream)
                .unwrap()
                .recv_credit
                .limit(),
            3_000
        );
    }

    fn assert_reassembly_recovered(cx: &Cx, connection: &mut NativeQuicConnection) {
        assert_eq!(connection.state(), QuicConnectionState::Established);
        assert_eq!(connection.datagrams_received(), 1);
        assert_eq!(connection.recv_datagram().as_deref(), Some(&b"once"[..]));
        assert!(connection.recv_datagram().is_none());
        let mut received = Vec::new();
        while received.len() < 2 {
            let bytes = connection.read_stream_bytes(cx, StreamId(0), 2).unwrap();
            assert!(!bytes.is_empty());
            received.extend_from_slice(&bytes);
        }
        assert_eq!(received, b"hx");
        assert!(!connection.is_stream_read_eof(StreamId(0)).unwrap());
        assert_eq!(
            connection
                .streams()
                .stream(StreamId(0))
                .unwrap()
                .recv_offset,
            2
        );
    }

    async fn authenticated_udp_pair() -> (NativeQuicUdpConnection, NativeQuicUdpConnection) {
        let config = NativeQuicConnectionConfig::default();
        let parameters = TransportParameters {
            initial_max_data: Some(config.connection_recv_limit),
            initial_max_stream_data_bidi_local: Some(config.recv_window),
            initial_max_stream_data_bidi_remote: Some(config.recv_window),
            initial_max_streams_bidi: Some(config.max_local_bidi),
            ..TransportParameters::default()
        };
        authenticated_udp_pair_with_parameters(config, config, &parameters, &parameters).await
    }

    async fn authenticated_udp_pair_with_parameters(
        client_connection_config: NativeQuicConnectionConfig,
        server_connection_config: NativeQuicConnectionConfig,
        client_parameters: &TransportParameters,
        server_parameters: &TransportParameters,
    ) -> (NativeQuicUdpConnection, NativeQuicUdpConnection) {
        let cx = Cx::current().unwrap_or_else(Cx::for_testing);
        let mut client_encoded = Vec::new();
        client_parameters.encode(&mut client_encoded).unwrap();
        let mut server_encoded = Vec::new();
        server_parameters.encode(&mut server_encoded).unwrap();
        let client_socket = QuicUdpEndpoint::bind(
            &cx,
            "127.0.0.1:0".parse().unwrap(),
            QuicUdpEndpointConfig::default(),
        )
        .await
        .unwrap();
        let server_socket = QuicUdpEndpoint::bind(
            &cx,
            "127.0.0.1:0".parse().unwrap(),
            QuicUdpEndpointConfig::default(),
        )
        .await
        .unwrap();
        let address = server_socket.local_addr();
        let alpn = b"pto-test";
        let client_tls =
            client_config(vec![parse_one_cert(CA_CERT_PEM)], vec![alpn.to_vec()]).unwrap();
        let server_tls = server_config(
            vec![parse_one_cert(LEAF_CERT_PEM)],
            leaf_key(),
            vec![alpn.to_vec()],
        )
        .unwrap();
        let initial_cid = ConnectionId::new(b"initial").unwrap();
        let (client, server) = zip(
            NativeQuicUdpConnection::connect(
                &cx,
                client_socket,
                address,
                QuicHandshakeDriver::client(
                    client_tls,
                    ServerName::try_from("localhost").unwrap(),
                    client_encoded,
                )
                .unwrap(),
                initial_cid,
                ConnectionId::new(b"client").unwrap(),
                client_connection_config,
                alpn,
            ),
            NativeQuicUdpConnection::accept(
                &cx,
                server_socket,
                QuicHandshakeDriver::server(server_tls, server_encoded).unwrap(),
                initial_cid,
                ConnectionId::new(b"server").unwrap(),
                server_connection_config,
                alpn,
            ),
        )
        .await;
        (client.unwrap(), server.unwrap())
    }

    async fn deliver_peer_ack(
        sender: &mut NativeQuicUdpConnection,
        receiver: &mut NativeQuicUdpConnection,
        acked: u64,
        raw_delay: u64,
        now_micros: u64,
    ) {
        let cx = Cx::current().expect("native ACK test runtime");
        let frames = [QuicFrame::Ack {
            largest_acknowledged: VarInt(acked),
            ack_delay: VarInt(raw_delay),
            ack_range_count: VarInt(0),
            first_ack_range: VarInt(0),
            ack_ranges: Vec::new(),
            ecn_counts: None,
        }];
        let mut payload = BytesMut::new();
        NativeQuicConnection::encode_frames(&frames, &mut payload).unwrap();
        let packet = assemble_protected_1rtt_packet(
            &cx,
            receiver.local_cid,
            sender.connection.inner_mut(),
            &mut sender.protection,
            &frames,
            &payload,
            now_micros,
            false,
        )
        .await
        .unwrap();
        let sent = sender
            .endpoint
            .send_batch(
                &cx,
                &[OutgoingPacket {
                    dst_addr: receiver.local_addr(),
                    data: packet,
                    send_time: None,
                }],
            )
            .await
            .unwrap();
        assert_eq!(sent.packets_processed, 1);
        assert!(sent.error.is_none());
        // Receive on the real socket and authenticate with the negotiated TLS
        // keys. Only the recovery clock is deterministic, so RTT expectations
        // do not depend on machine load or loopback scheduling.
        timeout(cx.now(), Duration::from_secs(5), async {
            loop {
                for packet in receiver.endpoint.receive_batch(&cx, 8).await.unwrap() {
                    if !matches!(
                        ProtectedHeaderPrefix::decode(&packet.data, receiver.local_cid.len()),
                        Ok(ProtectedHeaderPrefix::Short { .. })
                    ) {
                        continue;
                    }
                    let decoded = unprotect_1rtt_packet(
                        &cx,
                        receiver.local_cid,
                        &mut receiver.protection,
                        &packet.data,
                    )
                    .await
                    .unwrap();
                    assert_eq!(
                        NativeQuicConnection::decode_frames(&decoded.plaintext).unwrap(),
                        frames
                    );
                    receiver
                        .connection
                        .inner_mut()
                        .process_packet_payload(
                            &cx,
                            PacketNumberSpace::ApplicationData,
                            decoded.header.packet_number,
                            &decoded.plaintext,
                            now_micros,
                        )
                        .unwrap();
                    return;
                }
            }
        })
        .await
        .expect("authenticated ACK must arrive");
    }

    #[test]
    fn authenticated_udp_handshake_applies_peer_ack_timing_and_migration_policy() {
        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .with_reactor(crate::runtime::reactor::create_reactor().unwrap())
            .build()
            .unwrap();
        runtime.block_on(runtime.handle().spawn(async move {
            let cx = Cx::current().expect("native transport-parameter test runtime");
            let config = NativeQuicConnectionConfig::default();
            for (peer_parameters, delay, expected_adjusted, expected_max_delay) in [
                (
                    TransportParameters {
                        ack_delay_exponent: Some(10),
                        max_ack_delay: Some(5),
                        disable_active_migration: true,
                        ..TransportParameters::default()
                    },
                    2,
                    17_952,
                    5_000,
                ),
                (TransportParameters::default(), 2, 19_984, 25_000),
            ] {
                let (mut client, mut server) = authenticated_udp_pair_with_parameters(
                    config,
                    config,
                    &peer_parameters,
                    &TransportParameters::default(),
                )
                .await;
                assert!(server.connection.inner().tls().handshake_confirmed());
                let migration = server.connection.inner_mut().request_path_migration(&cx, 7);
                if peer_parameters.disable_active_migration {
                    assert!(matches!(migration, Err(NativeQuicConnectionError::InvalidState(
                        "active migration disabled by transport parameters"
                    ))));
                    assert_eq!(server.connection.inner().active_path_id(), 0);
                } else {
                    assert_eq!(migration.unwrap(), 1);
                }
                // The client's peer omitted the migration restriction; do not
                // accidentally apply our local advertised restriction to self.
                assert_eq!(client.connection.inner_mut().request_path_migration(&cx, 8).unwrap(), 1);
                for (sent_at, received_at, raw_delay, expected) in [
                    (10_000, 11_000, 0, 1_000),
                    (20_000, 40_000, delay, expected_adjusted),
                    (50_000, 90_000, 100_000, 40_000 - expected_max_delay),
                ] {
                    let pn = server.connection.inner_mut().on_packet_sent(
                        &cx, PacketNumberSpace::ApplicationData, 64, true, true, sent_at,
                    ).unwrap();
                    deliver_peer_ack(&mut client, &mut server, pn, raw_delay, received_at).await;
                    assert_eq!(server.connection.inner().transport().rtt().latest_rtt_micros(), Some(expected));
                }
                let rtt = server.connection.inner().transport().rtt();
                let base_pto = rtt.smoothed_rtt_micros().unwrap()
                    + (4 * rtt.rttvar_micros().unwrap()).max(1_000);
                server.connection.inner_mut().on_packet_sent(
                    &cx, PacketNumberSpace::ApplicationData, 64, true, true, 100_000,
                ).unwrap();
                assert_eq!(server.connection.inner().pto_deadline_micros(&cx, 100_000).unwrap(),
                    Some(100_000 + base_pto + expected_max_delay));
            }
        }));
    }

    #[test]
    fn authenticated_udp_handshake_keeps_datagram_support_directional_and_locally_capped() {
        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .with_reactor(crate::runtime::reactor::create_reactor().unwrap())
            .build()
            .unwrap();
        runtime.block_on(runtime.handle().spawn(async move {
            let cx = Cx::current().expect("native transport-parameter test runtime");
            let config = NativeQuicConnectionConfig {
                max_datagram_frame_size: 32,
                ..NativeQuicConnectionConfig::default()
            };
            let parameters = TransportParameters {
                max_datagram_frame_size: Some(1_200),
                ..TransportParameters::default()
            };
            for client_support in [false, true] {
                let client_parameters = if client_support {
                    parameters.clone()
                } else {
                    TransportParameters::default()
                };
                let (mut client, mut server) = authenticated_udp_pair_with_parameters(
                    config, config, &client_parameters, &parameters,
                ).await;
                for (owner, cap) in [(&mut client, 32), (&mut server, if client_support { 32 } else { 0 })] {
                    if cap != 0 {
                        owner.connection.inner_mut().send_datagram(&cx, Bytes::from_static(b"fits")).unwrap();
                    }
                    assert!(matches!(
                        owner.connection.inner_mut().send_datagram(&cx, Bytes::from(vec![0; 32])),
                        Err(NativeQuicConnectionError::DatagramTooLarge { max_frame_size, .. }) if max_frame_size == cap
                    ));
                }
            }
        }));
    }

    #[test]
    fn udp_idle_expiry_discards_retained_output_and_respects_disabled_timeout() {
        block_on(async {
            let cx = Cx::for_testing();
            let (mut client, server) = authenticated_udp_pair().await;
            let old_activity = Instant::now().checked_sub(Duration::from_secs(60)).unwrap();
            client.last_activity = old_activity;
            assert!(client.idle_deadline().is_none());
            assert!(!client.expire_idle_at(&cx, Instant::now()).unwrap());
            assert_eq!(client.connection.state(), QuicConnectionState::Established);

            let parameters = TransportParameters {
                max_idle_timeout: Some(1),
                ..TransportParameters::default()
            };
            client
                .connection
                .inner_mut()
                .set_negotiated_idle_timeout(&parameters, &TransportParameters::default());
            let floor = client
                .connection
                .inner()
                .transport()
                .idle_timeout_floor_micros();
            assert_eq!(
                client.idle_deadline().unwrap(),
                old_activity + Duration::from_micros(floor.max(1_000))
            );
            client.pending_outgoing.push(RoutedOutgoingPacket {
                connection_id: client.local_cid,
                packet: OutgoingPacket {
                    dst_addr: client.peer_addr,
                    data: b"retained unsent output must not escape idle expiry".to_vec(),
                    send_time: None,
                },
                final_handshake_flight: false,
                ack_eliciting: true,
            });
            assert_eq!(client.pending_outgoing.len(), 1, "retained-output witness");
            let cancelled = Cx::for_testing();
            cancelled.set_cancel_requested(true);
            assert!(matches!(
                client.flush(&cancelled).await,
                Err(NativeQuicUdpConnectionError::Cancelled)
            ));
            assert_eq!(client.pending_outgoing.len(), 1);
            assert_eq!(client.connection.state(), QuicConnectionState::Established);

            assert_eq!(client.flush(&cx).await.unwrap(), 0);
            assert_eq!(client.connection.state(), QuicConnectionState::Closed);
            assert_eq!(client.connection.inner().transport().close_code(), Some(0));
            assert!(!client.connection.close_was_peer_initiated());
            assert!(client.pending_outgoing.is_empty());
            assert!(client.final_handshake_flight.is_empty());
            assert!(client.early_one_rtt_packets.is_empty());
            assert!(client.local_close.is_none());
            client.service_due_loss_timer(&cx).unwrap();
            assert_eq!(client.flush(&cx).await.unwrap(), 0);
            assert_eq!(client.close(&cx, 7).await.unwrap(), 0);
            assert_eq!(client.connection.inner().transport().close_code(), Some(0));
            assert_eq!(
                client
                    .receive_wait_duration(&cx, Duration::from_millis(25))
                    .unwrap(),
                Duration::from_millis(25),
                "closed owners retain caller-driven pacing"
            );
            drop(server);
        });
    }

    #[test]
    fn udp_idle_activity_uses_authenticated_input_and_one_ack_eliciting_send() {
        block_on(async {
            let cx = Cx::for_testing();
            let (mut client, mut server) = authenticated_udp_pair().await;
            let mut quiet_rounds = 0;
            for turn in 0..60 {
                let a = client
                    .drive_io_once(&cx, Duration::from_millis(25))
                    .await
                    .unwrap();
                let b = server
                    .drive_io_once(&cx, Duration::from_millis(25))
                    .await
                    .unwrap();
                let quiet = |p: NativeQuicUdpIoProgress| {
                    p.receive_timed_out
                        && p.packets_received == 0
                        && p.packets_sent == 0
                        && p.early_packets_replayed == 0
                        && p.handshake_flights_retransmitted == 0
                };
                quiet_rounds = if quiet(a) && quiet(b) {
                    quiet_rounds + 1
                } else {
                    0
                };
                if quiet_rounds == 2 {
                    break;
                }
                assert!(turn < 59, "handshake settle: client={a:?} server={b:?}");
            }
            let parameters = TransportParameters {
                max_idle_timeout: Some(30_000),
                ..TransportParameters::default()
            };
            client
                .connection
                .inner_mut()
                .set_negotiated_idle_timeout(&parameters, &TransportParameters::default());
            client.last_activity = Instant::now().checked_sub(Duration::from_secs(1)).unwrap();
            client.sent_since_receive = false;
            let before_send = client.last_activity;
            client.connection.inner_mut().queue_ping(&cx).unwrap();
            assert!(client.flush(&cx).await.unwrap() > 0);
            assert!(client.last_activity > before_send);
            assert!(client.sent_since_receive);
            let after_first_send = client.last_activity;
            client.connection.inner_mut().queue_ping(&cx).unwrap();
            assert!(client.flush(&cx).await.unwrap() > 0);
            assert_eq!(
                client.last_activity, after_first_send,
                "repeated sends/probes cannot keep a silent peer alive"
            );

            let mut forged = vec![0x40];
            forged.extend_from_slice(client.local_cid.as_bytes());
            forged.extend_from_slice(&[0; 64]);
            server
                .endpoint
                .send_batch(
                    &cx,
                    &[OutgoingPacket {
                        dst_addr: client.endpoint.local_addr(),
                        data: forged,
                        send_time: None,
                    }],
                )
                .await
                .unwrap();
            let rejected = client
                .drive_io_once(&cx, Duration::from_millis(100))
                .await
                .unwrap();
            assert!(rejected.packets_dropped > 0);
            assert_eq!(rejected.packets_received, 0);
            assert_eq!(client.last_activity, after_first_send);

            let accepted = server
                .drive_io_once(&cx, Duration::from_millis(100))
                .await
                .unwrap();
            assert!(
                accepted.packets_received > 0,
                "peer processed the live PINGs"
            );
            server.connection.inner_mut().queue_ping(&cx).unwrap();
            assert!(server.flush(&cx).await.unwrap() > 0);
            let accepted = client
                .drive_io_once(&cx, Duration::from_millis(100))
                .await
                .unwrap();
            assert!(accepted.packets_received > 0);
            assert!(client.last_activity > after_first_send);
            // ACK-only output is not a new liveness-initiating send.
            assert!(!client.sent_since_receive);

            // Exercise the off-Cx timeout path's ready-I/O preference: park
            // the real UDP read first, let the deadline pass without polling
            // it, then deliver a valid encrypted packet before repolling.
            // Authentication must not resurrect this expired owner.
            let parameters = TransportParameters {
                max_idle_timeout: Some(1_000),
                ..TransportParameters::default()
            };
            client
                .connection
                .inner_mut()
                .set_negotiated_idle_timeout(&parameters, &TransportParameters::default());
            let idle = Duration::from_micros(
                client
                    .connection
                    .inner()
                    .transport()
                    .idle_timeout_floor_micros()
                    .max(1_000_000),
            );
            let grace = (idle / 4).min(Duration::from_millis(250));
            client.last_activity = Instant::now().checked_sub(idle).unwrap() + grace;
            let expired_activity = client.last_activity;
            let result = {
                let _ambient = Cx::set_current(None);
                let mut drive = Box::pin(client.drive_io_once(&cx, Duration::from_secs(60)));
                assert!(
                    futures_lite::future::poll_once(drive.as_mut()).await.is_none(),
                    "late-input regression must first park the UDP receive"
                );
                std::thread::sleep(grace + Duration::from_millis(50));
                server.connection.inner_mut().queue_ping(&cx).unwrap();
                assert!(
                    server.flush(&cx).await.unwrap() > 0,
                    "authenticated peer packet reaches the socket after idle expiry"
                );
                drive.await.unwrap()
            };
            assert!(result.receive_timed_out);
            assert_eq!(result.packets_received, 0);
            assert_eq!(result.packets_sent, 0);
            assert_eq!(client.connection.state(), QuicConnectionState::Closed);
            assert_eq!(client.last_activity, expired_activity);
        });
    }

    #[test]
    fn udp_idle_handoff_preserves_deadline_and_send_refresh_budget() {
        block_on(async {
            let (mut client, _server) = authenticated_udp_pair().await;
            let parameters = TransportParameters {
                max_idle_timeout: Some(30_000),
                ..TransportParameters::default()
            };
            client
                .connection
                .inner_mut()
                .set_negotiated_idle_timeout(&parameters, &TransportParameters::default());
            client.last_activity = Instant::now().checked_sub(Duration::from_secs(1)).unwrap();
            client.sent_since_receive = true;
            let original_activity = client.last_activity;
            let deadline = client.idle_deadline().unwrap();
            let cid = client.local_cid;
            let peer = client.peer_addr;
            let parts = client.into_managed_parts();
            let client = NativeQuicUdpConnection::from_managed_parts(parts);
            assert_eq!(client.last_activity, original_activity);
            assert!(client.sent_since_receive);
            let (mut router, _endpoint, _incoming) = ConnectionRouter::from_authenticated_parts(
                client.into_managed_parts(),
                NativeQuicConnectionConfig::default(),
                1,
                None,
                Instant::now(),
            );
            assert!(
                router
                    .expired_connections(deadline.checked_sub(Duration::from_micros(1)).unwrap())
                    .is_empty()
            );
            router.packet_sent(
                &RoutedOutgoingPacket {
                    connection_id: cid,
                    packet: OutgoingPacket {
                        dst_addr: peer,
                        data: Vec::new(),
                        send_time: None,
                    },
                    final_handshake_flight: false,
                    ack_eliciting: true,
                },
                Some(deadline.checked_sub(Duration::from_millis(1)).unwrap()),
            );
            assert_eq!(
                router.expired_connections(deadline),
                vec![cid],
                "handoff must not reset idle or restore the consumed send refresh"
            );
        });
    }

    #[test]
    fn udp_local_close_retains_ciphertext_and_stops_at_drain_deadline() {
        block_on(async {
            let cx = Cx::for_testing();
            let (mut client, mut server) = authenticated_udp_pair().await;
            assert!(client.close(&cx, u64::MAX).await.is_err());
            assert_eq!(
                client.connection.inner().state(),
                QuicConnectionState::Established
            );

            // Force a real socket send failure after protection and packet-number
            // commitment. Retrying must reuse that ciphertext, not encrypt again.
            let peer = client.peer_addr;
            client.pending_outgoing.push(RoutedOutgoingPacket {
                connection_id: client.local_cid,
                packet: OutgoingPacket {
                    dst_addr: peer,
                    data: b"must never escape after closing".to_vec(),
                    send_time: None,
                },
                final_handshake_flight: false,
                ack_eliciting: true,
            });
            client.peer_addr.set_port(0);
            assert!(client.close(&cx, 42).await.is_err());
            assert!(client.pending_outgoing.is_empty());
            let retained = client.local_close.as_ref().unwrap().packet.data.clone();
            assert!(client.local_close.as_ref().unwrap().pending);
            assert!(client.local_close.as_ref().unwrap().last_sent.is_none());
            let cancelled = Cx::for_testing();
            cancelled.set_cancel_requested(true);
            assert!(matches!(
                client.flush(&cancelled).await,
                Err(NativeQuicUdpConnectionError::Cancelled)
            ));
            assert_eq!(client.local_close.as_ref().unwrap().packet.data, retained);
            client = client
                .into_managed(&cx, ManagedEndpointConfig::default())
                .expect_err("closing owner must retain standalone output")
                .into_connection();
            assert_eq!(client.local_close.as_ref().unwrap().packet.data, retained);
            client.peer_addr = peer;
            client.local_close.as_mut().unwrap().packet.dst_addr = peer;
            assert_eq!(client.flush(&cx).await.unwrap(), 1);
            assert_eq!(client.flush(&cx).await.unwrap(), 0);
            assert_eq!(client.local_close.as_ref().unwrap().packet.data, retained);
            let progress = server
                .drive_io_once(&cx, Duration::from_secs(1))
                .await
                .unwrap();
            assert_eq!(progress.packets_received, 1);
            assert_eq!(progress.packets_sent, 0);
            assert!(server.connection.close_was_peer_initiated());
            assert_eq!(server.connection.inner().transport().close_code(), Some(42));

            // The closing owner responds only to the matching short-header
            // destination, coalescing traffic into at most one send per PTO.
            let mut matching = vec![0x40];
            matching.extend_from_slice(client.local_cid.as_bytes());
            matching.extend_from_slice(&[0; 24]);
            let packet = ReceivedPacket {
                src_addr: peer,
                data: matching,
                receive_time: Instant::now(),
                transmit_time: None,
            };
            client.early_one_rtt_packets.push(packet.clone());
            let progress = client.drive_io_once(&cx, Duration::ZERO).await.unwrap();
            assert_eq!(progress.packets_dropped, 1);
            assert_eq!(progress.packets_sent, 0);
            let interval = Duration::from_micros(
                client
                    .connection
                    .inner()
                    .transport()
                    .idle_timeout_floor_micros()
                    / 3,
            )
            .max(Duration::from_millis(1));
            client.local_close.as_mut().unwrap().last_sent = Some(
                Instant::now()
                    .checked_sub(interval)
                    .unwrap()
                    .checked_sub(Duration::from_millis(1))
                    .unwrap(),
            );
            let mut wrong_cid = packet.clone();
            wrong_cid.data[1] ^= 1;
            let mut wrong_peer = packet.clone();
            wrong_peer.src_addr.set_port(0);
            let mut stale_handshake = packet.clone();
            stale_handshake.data[0] = 0x80;
            client
                .early_one_rtt_packets
                .extend([wrong_cid, wrong_peer, stale_handshake]);
            let progress = client.drive_io_once(&cx, Duration::ZERO).await.unwrap();
            assert_eq!(progress.packets_sent, 0);
            assert_eq!(progress.handshake_flights_retransmitted, 0);
            let mut packet = packet;
            packet.receive_time = Instant::now();
            client
                .early_one_rtt_packets
                .extend([packet.clone(), packet]);
            let progress = client.drive_io_once(&cx, Duration::ZERO).await.unwrap();
            assert_eq!(progress.packets_sent, 1);
            assert_eq!(client.local_close.as_ref().unwrap().packet.data, retained);
            let retransmission = server.endpoint.receive_batch(&cx, 1).await.unwrap();
            assert_eq!(retransmission.len(), 1);
            assert_eq!(retransmission[0].data, retained);

            // An expired recovery timer must not produce an application probe.
            client.service_due_loss_timer(&cx).unwrap();
            assert_eq!(client.flush(&cx).await.unwrap(), 0);
            let deadline = client
                .connection
                .inner()
                .transport()
                .drain_deadline_micros()
                .unwrap();
            client.clock_origin = Instant::now()
                .checked_sub(Duration::from_micros(deadline))
                .unwrap()
                .checked_sub(Duration::from_millis(1))
                .unwrap();
            client.local_close.as_mut().unwrap().pending = true;
            assert_eq!(
                client.flush_local_close(&cx, Instant::now()).await.unwrap(),
                0
            );
            assert_eq!(
                client.connection.inner().state(),
                QuicConnectionState::Closed
            );
            assert_eq!(client.flush(&cx).await.unwrap(), 0);
            assert!(client.local_close.is_none());
            assert_eq!(
                client
                    .receive_wait_duration(&cx, Duration::from_secs(1))
                    .unwrap(),
                Duration::from_secs(1)
            );
        });
    }

    /// br-asupersync-tzjbn9 F3: a peer frame past the stream's receive window
    /// returned the error with the connection still open and nothing sent, so
    /// the peer never learned why. RFC 9000 10.2 and 4.1: the connection closes
    /// with FLOW_CONTROL_ERROR in a transport CONNECTION_CLOSE.
    #[test]
    fn udp_peer_flow_control_violation_sends_a_transport_close() {
        block_on(async {
            let cx = Cx::for_testing();
            let (mut client, mut server) = authenticated_udp_pair().await;
            let stream = client.connection.inner_mut().open_local_bidi(&cx).unwrap();
            // Past both the stream and the connection receive limits.
            let config = NativeQuicConnectionConfig::default();
            let frames = [QuicFrame::Stream {
                stream_id: VarInt(stream.0),
                offset: Some(VarInt(config.recv_window.max(config.connection_recv_limit))),
                data: Bytes::from_static(b"x"),
                fin: false,
            }];
            let mut payload = BytesMut::new();
            NativeQuicConnection::encode_frames(&frames, &mut payload).unwrap();
            let packet = assemble_protected_1rtt_packet(
                &cx,
                server.local_cid,
                client.connection.inner_mut(),
                &mut client.protection,
                &frames,
                &payload,
                0,
                false,
            )
            .await
            .unwrap();
            let sent = client
                .endpoint
                .send_batch(
                    &cx,
                    &[OutgoingPacket {
                        dst_addr: server.local_addr(),
                        data: packet,
                        send_time: None,
                    }],
                )
                .await
                .unwrap();
            assert_eq!(sent.packets_processed, 1);

            let error = server
                .drive_io_once(&cx, Duration::from_secs(5))
                .await
                .expect_err("the violation is still reported");
            assert!(
                matches!(error, NativeQuicUdpConnectionError::Transport(_)),
                "{error:?}"
            );
            assert_eq!(
                server.connection.inner().state(),
                QuicConnectionState::Draining
            );
            assert_eq!(
                server.connection.inner().transport().close_code(),
                Some(0x03),
                "FLOW_CONTROL_ERROR"
            );
            assert!(!server.connection.close_was_peer_initiated());
            let close = server.local_close.as_ref().expect("a close was assembled");
            assert!(!close.pending, "and sent before the error returned");

            let progress = client
                .drive_io_once(&cx, Duration::from_secs(5))
                .await
                .unwrap();
            assert_eq!(progress.packets_received, 1);
            assert!(client.connection.close_was_peer_initiated());
            assert_eq!(
                client.connection.inner().transport().close_code(),
                Some(0x03)
            );
        });
    }

    #[test]
    fn udp_pto_preserves_full_flight_and_sends_one_probe() {
        block_on(async {
            let cx = Cx::for_testing();
            let config = NativeQuicConnectionConfig::default();
            let (mut client, mut server) = authenticated_udp_pair().await;
            // Seed a full flight without sleeping for a real network timeout.
            // Handshake, packet protection, and probe transmission use real UDP.
            let connection = client.connection.inner_mut();
            let window = connection.transport().congestion_window_bytes();
            let mut original = Vec::new();
            let mut remaining = window;
            while remaining > 0 {
                let bytes = remaining.min(1200);
                original.push(
                    connection
                        .on_packet_sent(
                            &cx,
                            PacketNumberSpace::ApplicationData,
                            bytes,
                            true,
                            true,
                            0,
                        )
                        .unwrap(),
                );
                remaining -= bytes;
            }
            let stream = connection.open_local_bidi(&cx).unwrap();
            connection
                .write_stream_bytes(&cx, stream, Bytes::from_static(b"still queued"), false)
                .unwrap();
            let queued = connection.pending_stream_data_bytes();
            let deadline = connection.pto_deadline_micros(&cx, 0).unwrap().unwrap();
            client.clock_origin = Instant::now()
                .checked_sub(Duration::from_micros(deadline + 1))
                .unwrap();
            client.service_due_loss_timer(&cx).unwrap();
            let transport = client.connection.inner_mut().transport();
            assert_eq!(transport.bytes_in_flight(), window);
            assert_eq!(transport.congestion_window_bytes(), window);
            assert_eq!(transport.packets_lost_total(), 0);
            assert_eq!(transport.pto_count(), 1);
            let cancelled = Cx::for_testing();
            cancelled.set_cancel_requested(true);
            assert!(matches!(
                client.flush(&cancelled).await,
                Err(NativeQuicUdpConnectionError::Cancelled)
            ));
            assert_eq!(
                client.connection.inner_mut().transport().bytes_in_flight(),
                window,
                "cancelled admission must not consume the probe permit"
            );
            // Refuse an already-protected packet at the real endpoint boundary.
            // Keep the original socket alive so retry uses the same peer tuple.
            let small_endpoint = QuicUdpEndpoint::bind(
                &cx,
                "127.0.0.1:0".parse().unwrap(),
                QuicUdpEndpointConfig {
                    max_packet_size: 1,
                    ..QuicUdpEndpointConfig::default()
                },
            )
            .await
            .unwrap();
            let original_endpoint = std::mem::replace(&mut client.endpoint, small_endpoint);
            assert!(matches!(
                client.flush(&cx).await,
                Err(NativeQuicUdpConnectionError::Endpoint(_))
            ));
            assert_eq!(client.pending_outgoing.len(), 1);
            let protected_probe = client.pending_outgoing[0].packet.data.clone();
            let accounted = client.connection.inner_mut().transport().bytes_in_flight();
            assert!(matches!(
                client.flush(&cancelled).await,
                Err(NativeQuicUdpConnectionError::Cancelled)
            ));
            client = NativeQuicUdpConnection::from_managed_parts(client.into_managed_parts());
            assert_eq!(client.pending_outgoing.len(), 1);
            assert_eq!(client.pending_outgoing[0].packet.data, protected_probe);
            let small_endpoint = std::mem::replace(&mut client.endpoint, original_endpoint);
            assert_eq!(client.flush(&cx).await.unwrap(), 1);
            assert!(client.pending_outgoing.is_empty());
            assert_eq!(
                client.connection.inner_mut().transport().bytes_in_flight(),
                accounted,
                "retry must not allocate another packet number or account twice"
            );
            assert_eq!(client.flush(&cx).await.unwrap(), 0, "permit consumed once");
            let mut received_probe = false;
            for _ in 0..4 {
                let packets = timeout(
                    cx.now(),
                    Duration::from_secs(1),
                    server.endpoint.receive_batch(&cx, RECEIVE_BATCH_SIZE),
                )
                .await
                .expect("probe must reach the peer")
                .unwrap();
                for packet in packets {
                    if !matches!(
                        ProtectedHeaderPrefix::decode(&packet.data, server.local_cid.len()),
                        Ok(ProtectedHeaderPrefix::Short { .. })
                    ) {
                        // Handshake retransmissions may precede the probe.
                        continue;
                    }
                    let decoded = unprotect_1rtt_packet(
                        &cx,
                        server.local_cid,
                        &mut server.protection,
                        &packet.data,
                    )
                    .await
                    .unwrap();
                    assert_eq!(
                        NativeQuicConnection::decode_frames(&decoded.plaintext).unwrap(),
                        vec![QuicFrame::Ping]
                    );
                    assert!(!received_probe, "only one probe was authorized");
                    received_probe = true;
                }
                if received_probe {
                    break;
                }
            }
            assert!(received_probe, "peer authenticated the PING probe");
            let connection = client.connection.inner_mut();
            assert_eq!(connection.transport().congestion_window_bytes(), window);
            assert_eq!(connection.pending_stream_data_bytes(), queued);
            let after_probe = connection.transport().bytes_in_flight();
            assert!(after_probe > window && after_probe <= window + 1200);
            connection
                .on_ack_received(
                    &cx,
                    PacketNumberSpace::ApplicationData,
                    &original,
                    0,
                    deadline + 2,
                )
                .unwrap();
            assert_eq!(
                connection.transport().bytes_in_flight(),
                after_probe - window
            );
            assert_eq!(connection.transport().packets_lost_total(), 0);
            // Send one protected packet before a real destination error, then
            // import only the unsent suffix into the router.
            connection
                .write_stream_bytes(&cx, stream, Bytes::from(vec![7; 3600]), true)
                .unwrap();
            let original_endpoint = std::mem::replace(&mut client.endpoint, small_endpoint);
            assert!(matches!(
                client.flush(&cx).await,
                Err(NativeQuicUdpConnectionError::Endpoint(
                    QuicUdpEndpointError::PacketTooLarge { limit: 1, .. }
                ))
            ));
            assert!(client.pending_outgoing.len() >= 3);
            let protected_flight: Vec<_> = client
                .pending_outgoing
                .iter()
                .map(|packet| packet.packet.data.clone())
                .collect();
            let accounted = client.connection.inner_mut().transport().bytes_in_flight();
            client.pending_outgoing[1].packet.dst_addr.set_port(0);
            client.endpoint = original_endpoint;
            assert!(matches!(
                client.flush(&cx).await,
                Err(NativeQuicUdpConnectionError::Endpoint(_))
            ));
            assert_eq!(client.pending_outgoing.len(), protected_flight.len() - 1);
            assert!(
                client
                    .pending_outgoing
                    .iter()
                    .map(|packet| &packet.packet.data)
                    .eq(protected_flight[1..].iter()),
                "the acknowledged prefix must be removed without changing the suffix"
            );
            assert_eq!(
                client.connection.inner_mut().transport().bytes_in_flight(),
                accounted,
                "a partial send must not account for protected packets twice"
            );
            let received = timeout(
                cx.now(),
                Duration::from_secs(1),
                server.endpoint.receive_batch(&cx, RECEIVE_BATCH_SIZE),
            )
            .await
            .expect("the successful prefix must reach the peer")
            .unwrap();
            assert_eq!(received.len(), 1);
            assert_eq!(received[0].data, protected_flight[0]);
            unprotect_1rtt_packet(
                &cx,
                server.local_cid,
                &mut server.protection,
                &received[0].data,
            )
            .await
            .expect("the peer must authenticate the successful prefix");
            client.pending_outgoing[0].packet.dst_addr = client.peer_addr;
            let expected_first = protected_flight[1].clone();
            let local_cid = client.local_cid;
            let now = Instant::now();
            let (mut router, _endpoint, incoming) = ConnectionRouter::from_authenticated_parts(
                client.into_managed_parts(),
                config,
                1,
                None,
                now,
            );
            assert!(incoming.is_empty());
            assert!(
                router
                    .drain_deferred_output(&cx, now, 0)
                    .await
                    .unwrap()
                    .is_empty()
            );
            assert!(matches!(
                router.drain_deferred_output(&cancelled, now, 1).await,
                Err(ConnectionRouterError::Cancelled)
            ));
            let prefix = router.drain_deferred_output(&cx, now, 1).await.unwrap();
            assert_eq!(prefix.len(), 1);
            assert_eq!(prefix[0].connection_id, local_cid);
            assert_eq!(prefix[0].packet.data, expected_first);
            assert!(prefix[0].ack_eliciting);
            assert!(!prefix[0].final_handshake_flight);
            assert_eq!(router.close_all(&cx, now, 0).unwrap(), 1);
            assert!(
                router
                    .drain_deferred_output(&cx, now, MAX_PACKETS_PER_FLUSH)
                    .await
                    .unwrap()
                    .is_empty()
            );
        });
    }

    #[test]
    fn reassembly_backpressure_recovers_in_udp_owner_and_authenticated_router() {
        block_on(async {
            for routed in [false, true] {
                let cx = Cx::for_testing();
                let config = NativeQuicConnectionConfig::default();
                let parameters = TransportParameters {
                    initial_max_data: Some(config.connection_recv_limit),
                    initial_max_stream_data_bidi_local: Some(config.recv_window),
                    initial_max_stream_data_bidi_remote: Some(config.recv_window),
                    initial_max_stream_data_uni: Some(config.recv_window),
                    initial_max_streams_bidi: Some(config.max_local_bidi),
                    max_datagram_frame_size: Some(1200),
                    ..TransportParameters::default()
                };
                let mut parameters_bytes = Vec::new();
                parameters.encode(&mut parameters_bytes).unwrap();
                let client_socket = QuicUdpEndpoint::bind(
                    &cx,
                    "127.0.0.1:0".parse().unwrap(),
                    QuicUdpEndpointConfig::default(),
                )
                .await
                .unwrap();
                let server_socket = QuicUdpEndpoint::bind(
                    &cx,
                    "127.0.0.1:0".parse().unwrap(),
                    QuicUdpEndpointConfig::default(),
                )
                .await
                .unwrap();
                let address = server_socket.local_addr();
                let alpn = b"reassembly-test";
                let client_tls =
                    client_config(vec![parse_one_cert(CA_CERT_PEM)], vec![alpn.to_vec()]).unwrap();
                let server_tls = server_config(
                    vec![parse_one_cert(LEAF_CERT_PEM)],
                    leaf_key(),
                    vec![alpn.to_vec()],
                )
                .unwrap();
                let initial_cid = ConnectionId::new(b"initial").unwrap();
                let server_cid = ConnectionId::new(b"server").unwrap();
                let (client, server) = zip(
                    NativeQuicUdpConnection::connect(
                        &cx,
                        client_socket,
                        address,
                        QuicHandshakeDriver::client(
                            client_tls,
                            ServerName::try_from("localhost").unwrap(),
                            parameters_bytes.clone(),
                        )
                        .unwrap(),
                        initial_cid,
                        ConnectionId::new(b"client").unwrap(),
                        config,
                        alpn,
                    ),
                    NativeQuicUdpConnection::accept(
                        &cx,
                        server_socket,
                        QuicHandshakeDriver::server(server_tls, parameters_bytes).unwrap(),
                        initial_cid,
                        server_cid,
                        config,
                        alpn,
                    ),
                )
                .await;
                let mut client = client.unwrap();
                let mut server = server.unwrap();
                assert!(server.early_one_rtt_packets.is_empty());
                let id = StreamId(0);
                let connection = server.connection.inner_mut();
                connection.accept_remote_stream(&cx, id).unwrap();
                // Seed only the bounded capacity precondition. All three
                // admission/recovery packets use real TLS keys and UDP below.
                for fragment in 0..4095u64 {
                    connection
                        .receive_stream_bytes(
                            &cx,
                            id,
                            1 + fragment * 2,
                            Bytes::from_static(b"x"),
                            false,
                        )
                        .unwrap();
                }
                connection
                    .generate_frames(&cx, PacketNumberSpace::ApplicationData, 65535)
                    .unwrap();
                let overflow = vec![
                    QuicFrame::Datagram {
                        data: Bytes::from_static(b"once"),
                    },
                    QuicFrame::Stream {
                        stream_id: VarInt(id.0),
                        offset: Some(VarInt(8191)),
                        data: Bytes::from_static(b"z"),
                        fin: true,
                    },
                ];
                let repair = vec![QuicFrame::Stream {
                    stream_id: VarInt(id.0),
                    offset: Some(VarInt(0)),
                    data: Bytes::from_static(b"h"),
                    fin: false,
                }];
                let mut packets = Vec::new();
                for frames in [&overflow, &repair, &overflow] {
                    let mut payload = BytesMut::new();
                    NativeQuicConnection::encode_frames(frames, &mut payload).unwrap();
                    let data = assemble_protected_1rtt_packet(
                        &cx,
                        server_cid,
                        client.connection.inner_mut(),
                        &mut client.protection,
                        frames,
                        &payload,
                        1,
                        true,
                    )
                    .await
                    .unwrap();
                    packets.push(OutgoingPacket {
                        dst_addr: address,
                        data,
                        send_time: None,
                    });
                }
                let sent = client.endpoint.send_batch(&cx, &packets).await.unwrap();
                assert_eq!(sent.packets_processed, 3);
                assert!(sent.error.is_none());
                if routed {
                    let (mut router, mut endpoint, early) =
                        ConnectionRouter::from_authenticated_parts(
                            server.into_managed_parts(),
                            config,
                            1,
                            None,
                            Instant::now(),
                        );
                    assert!(early.is_empty());
                    let mut outcomes = Vec::new();
                    while outcomes.len() < 3 {
                        let packets = timeout(
                            crate::time::wall_now(),
                            Duration::from_secs(10),
                            endpoint.receive_batch(&cx, 3 - outcomes.len()),
                        )
                        .await
                        .unwrap()
                        .unwrap();
                        for packet in packets {
                            outcomes.push(router.route_packet(&cx, packet).await.unwrap());
                        }
                    }
                    assert!(matches!(&outcomes[0], RoutingResult::Drop { reason }
                        if reason == "stream reassembly backpressure"));
                    assert!(matches!(&outcomes[1], RoutingResult::Routed { .. }));
                    assert!(matches!(&outcomes[2], RoutingResult::Routed { .. }));
                    let connection = router.connection_mut_for_testing(&cx, server_cid).unwrap();
                    assert_reassembly_recovered(&cx, connection);
                    let frames = connection
                        .generate_frames(&cx, PacketNumberSpace::ApplicationData, 65535)
                        .unwrap();
                    assert!(frames.iter().any(|frame| matches!(frame,
                        QuicFrame::Ack { largest_acknowledged, first_ack_range, ack_ranges, .. }
                            if largest_acknowledged.value() == 2 && first_ack_range.value() == 1 && ack_ranges.is_empty()
                    )), "only packets 1 and 2 were admitted");
                } else {
                    let mut received = 0;
                    let mut dropped = 0;
                    for _ in 0..3 {
                        let progress = server
                            .drive_io_once(&cx, Duration::from_secs(10))
                            .await
                            .unwrap();
                        received += progress.packets_received;
                        dropped += progress.packets_dropped;
                        if received + dropped == 3 {
                            break;
                        }
                    }
                    assert_eq!((received, dropped), (2, 1));
                    assert_reassembly_recovered(&cx, server.connection.inner_mut());
                }
            }
        });
    }
