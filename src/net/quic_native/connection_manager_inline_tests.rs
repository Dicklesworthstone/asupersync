    use super::*;
    use crate::bytes::{Bytes, BytesMut};
    use crate::net::VarInt;
    use crate::net::atp::protocol::quic_frames::QuicFrame;
    use crate::net::atp::quic::AtpPacketProtection;
    use crate::net::quic_core::{LongHeader, LongPacketType, PacketHeader};
    use crate::net::quic_native::QuicHandshakeTranscript;
    use crate::test_utils::run_test_with_cx;

    #[test]
    fn protected_packet_ack_elicitation_matches_rfc_9000() {
        let zero = crate::net::VarInt(0);
        assert!(!is_ack_eliciting(&QuicFrame::Padding { length: 1 }));
        assert!(!is_ack_eliciting(&QuicFrame::Ack {
            largest_acknowledged: zero,
            ack_delay: zero,
            ack_range_count: zero,
            first_ack_range: zero,
            ack_ranges: Vec::new(),
            ecn_counts: None,
        }));
        assert!(!is_ack_eliciting(&QuicFrame::ConnectionClose {
            error_code: zero,
            frame_type: None,
            reason_phrase: Bytes::new(),
        }));
        assert!(is_ack_eliciting(&QuicFrame::Ping));
        assert!(is_ack_eliciting(&QuicFrame::MaxData { maximum_data: zero }));
    }

    #[test]
    fn test_connection_router_creation() {
        let config = NativeQuicConnectionConfig::default();
        let router = ConnectionRouter::new(config);

        assert_eq!(router.connections.len(), 0);
        assert_eq!(router.next_connection_id, 1);
    }

    #[test]
    fn test_connection_id_allocation() {
        run_test_with_cx(|_cx| async move {
            let config = NativeQuicConnectionConfig::default();
            let mut router = ConnectionRouter::new(config);

            let id1 = router.allocate_connection_id();
            let id2 = router.allocate_connection_id();

            assert_ne!(id1, id2);
            assert!(router.next_connection_id > 2);
        });
    }

    #[test]
    fn test_connection_creation() {
        run_test_with_cx(|cx| async move {
            let config = NativeQuicConnectionConfig::default();
            let mut router = ConnectionRouter::new(config);

            let connection_id = router.allocate_connection_id();
            let peer_addr = "127.0.0.1:12345".parse().unwrap();

            router
                .create_connection(&cx, connection_id, peer_addr, false)
                .await
                .expect("connection creation should succeed");

            assert_eq!(router.connections.len(), 1);
            assert!(router.connections.contains_key(&connection_id));
        });
    }

    #[test]
    fn create_connection_rejects_duplicate_connection_id_without_overwrite() {
        run_test_with_cx(|cx| async move {
            let config = NativeQuicConnectionConfig::default();
            let mut router = ConnectionRouter::new(config);
            let connection_id = ConnectionId::new(&[0x31, 0x71, 0x00, 0x01]).expect("cid");
            let original_peer: SocketAddr = "127.0.0.1:4401".parse().unwrap();
            let colliding_peer: SocketAddr = "127.0.0.1:4402".parse().unwrap();

            router
                .create_connection(&cx, connection_id, original_peer, true)
                .await
                .expect("first connection creation should succeed");

            let err = router
                .create_connection(&cx, connection_id, colliding_peer, false)
                .await
                .expect_err("duplicate destination CID must fail closed");
            assert!(matches!(
                err,
                ConnectionRouterError::ConnectionCreationFailed(ref msg)
                    if msg.contains("connection ID collision")
            ));
            assert_eq!(router.connections.len(), 1);
            assert_eq!(
                router
                    .connections
                    .get(&connection_id)
                    .expect("original connection remains")
                    .peer_addr,
                original_peer
            );
        });
    }

    #[test]
    fn connection_limit_rejects_create_and_drops_unknown_initials() {
        run_test_with_cx(|cx| async move {
            let config = NativeQuicConnectionConfig::default();
            let mut router = ConnectionRouter::with_max_connections(config, 0);
            assert_eq!(router.max_connections, 1);

            let peer_addr: SocketAddr = "127.0.0.1:4403".parse().unwrap();
            let first = ConnectionId::new(&[0x31, 0x71, 0x00, 0x02]).expect("first cid");
            router
                .create_connection(&cx, first, peer_addr, true)
                .await
                .expect("first connection within normalized limit should succeed");

            let second = ConnectionId::new(&[0x31, 0x71, 0x00, 0x03]).expect("second cid");
            let err = router
                .create_connection(&cx, second, peer_addr, true)
                .await
                .expect_err("second connection must hit the cap");
            assert!(matches!(
                err,
                ConnectionRouterError::ConnectionCreationFailed(ref msg)
                    if msg.contains("connection limit reached")
            ));

            let packet = ReceivedPacket {
                src_addr: peer_addr,
                data: encode_long_packet(second, LongPacketType::Initial, 0, QuicFrame::Ping),
                receive_time: Instant::now(),
                transmit_time: None,
            };
            match router.route_packet(&cx, packet).await.expect("route") {
                RoutingResult::Drop { reason } => {
                    assert!(reason.contains("connection limit reached"));
                }
                other => panic!("full router must not advertise a new connection: {other:?}"),
            }
        });
    }

    #[test]
    fn test_take_connection_removes_handle_and_preserves_peer() {
        run_test_with_cx(|cx| async move {
            let config = NativeQuicConnectionConfig::default();
            let mut router = ConnectionRouter::new(config);
            let connection_id = ConnectionId::new(&[0x10, 0x00, 0x00, 0x01]).expect("cid");
            let peer_addr: SocketAddr = "127.0.0.1:5544".parse().unwrap();
            router
                .create_connection(&cx, connection_id, peer_addr, true)
                .await
                .expect("connection creation should succeed");

            let accepted = router
                .take_connection(&cx, connection_id)
                .expect("connection should be handed off");
            assert_eq!(accepted.connection_id, connection_id);
            assert_eq!(accepted.peer_addr, peer_addr);
            assert_eq!(accepted.connection.pending_outbound_datagram_count(), 0);
            assert!(!router.connections.contains_key(&connection_id));
            assert_eq!(router.connection_stats().active_connections, 0);

            let err = router
                .take_connection(&cx, connection_id)
                .expect_err("missing connection must fail closed");
            assert!(matches!(
                err,
                ConnectionRouterError::ConnectionNotFound(id) if id == connection_id
            ));
        });
    }

    #[test]
    fn test_take_next_connection_uses_deterministic_connection_id_order() {
        run_test_with_cx(|cx| async move {
            let config = NativeQuicConnectionConfig::default();
            let mut router = ConnectionRouter::new(config);
            let low = ConnectionId::new(&[0x01, 0x00, 0x00, 0x00]).expect("low cid");
            let mid = ConnectionId::new(&[0x10, 0x00, 0x00, 0x00]).expect("mid cid");
            let high = ConnectionId::new(&[0xff, 0x00, 0x00, 0x00]).expect("high cid");
            let peer_addr: SocketAddr = "127.0.0.1:5545".parse().unwrap();

            for connection_id in [high, low, mid] {
                router
                    .create_connection(&cx, connection_id, peer_addr, true)
                    .await
                    .expect("connection creation should succeed");
            }

            let first = router
                .take_next_connection(&cx)
                .expect("take should succeed")
                .expect("connection should exist");
            assert_eq!(first.connection_id, low);

            let second = router
                .take_next_connection(&cx)
                .expect("take should succeed")
                .expect("connection should exist");
            assert_eq!(second.connection_id, mid);

            let third = router
                .take_next_connection(&cx)
                .expect("take should succeed")
                .expect("connection should exist");
            assert_eq!(third.connection_id, high);

            assert!(
                router
                    .take_next_connection(&cx)
                    .expect("empty take should succeed")
                    .is_none()
            );
        });
    }

    #[test]
    fn test_long_header_initial_routes_as_new_connection() {
        run_test_with_cx(|cx| async move {
            let config = NativeQuicConnectionConfig::default();
            let mut router = ConnectionRouter::new(config);
            let dst_cid = ConnectionId::new(&[0xaa, 0xbb, 0xcc]).expect("cid");
            let src_addr: SocketAddr = "127.0.0.1:4433".parse().unwrap();
            let packet = ReceivedPacket {
                src_addr,
                data: encode_long_packet(dst_cid, LongPacketType::Initial, 0, QuicFrame::Ping),
                receive_time: Instant::now(),
                transmit_time: None,
            };

            match router.route_packet(&cx, packet).await.expect("route") {
                RoutingResult::NewConnection { peer_addr, .. } => assert_eq!(peer_addr, src_addr),
                other => panic!("expected new connection, got {other:?}"),
            }
        });
    }

    #[test]
    fn test_new_initial_reroutes_after_connection_creation() {
        run_test_with_cx(|cx| async move {
            let config = NativeQuicConnectionConfig::default();
            let mut router = ConnectionRouter::new(config);
            let dst_cid = ConnectionId::new(&[0xda, 0x7a, 0x00, 0x01]).expect("cid");
            let src_addr: SocketAddr = "127.0.0.1:4436".parse().unwrap();
            let packet = ReceivedPacket {
                src_addr,
                data: encode_long_packet(dst_cid, LongPacketType::Initial, 7, QuicFrame::Ping),
                receive_time: Instant::now(),
                transmit_time: None,
            };

            let triggering_packet = match router.route_packet(&cx, packet).await.expect("route") {
                RoutingResult::NewConnection {
                    connection_id,
                    peer_addr,
                    triggering_packet,
                    outgoing_packets,
                } => {
                    assert_eq!(connection_id, dst_cid);
                    assert_eq!(peer_addr, src_addr);
                    assert!(outgoing_packets.is_empty());
                    triggering_packet
                }
                other => panic!("expected new connection, got {other:?}"),
            };

            router
                .create_connection(&cx, dst_cid, src_addr, true)
                .await
                .expect("connection creation should succeed");

            match router
                .route_packet(&cx, triggering_packet)
                .await
                .expect("reroute")
            {
                RoutingResult::Routed {
                    connection_id,
                    outgoing_packets,
                } => {
                    assert_eq!(connection_id, dst_cid);
                    assert_eq!(outgoing_packets.len(), 1);
                    assert_eq!(outgoing_packets[0].dst_addr, src_addr);
                    assert!(!outgoing_packets[0].data.is_empty());
                }
                other => panic!("expected triggering Initial to reroute, got {other:?}"),
            }
        });
    }

    #[test]
    fn test_existing_connection_processes_ping_and_emits_ack_frame() {
        run_test_with_cx(|cx| async move {
            let config = NativeQuicConnectionConfig::default();
            let mut router = ConnectionRouter::new(config);
            let connection_id = router.allocate_connection_id();
            let peer_addr: SocketAddr = "127.0.0.1:4434".parse().unwrap();
            router
                .create_connection(&cx, connection_id, peer_addr, false)
                .await
                .expect("connection creation should succeed");

            let packet = ReceivedPacket {
                src_addr: peer_addr,
                data: encode_long_packet(
                    connection_id,
                    LongPacketType::Initial,
                    42,
                    QuicFrame::Ping,
                ),
                receive_time: Instant::now(),
                transmit_time: None,
            };

            match router.route_packet(&cx, packet).await.expect("route") {
                RoutingResult::Routed {
                    outgoing_packets, ..
                } => {
                    assert_eq!(outgoing_packets.len(), 1);
                    assert_eq!(outgoing_packets[0].dst_addr, peer_addr);
                    assert!(!outgoing_packets[0].data.is_empty());
                }
                other => panic!("expected routed packet, got {other:?}"),
            }
        });
    }

    #[test]
    fn test_application_datagram_handoff_uses_protected_short_header_packet() {
        run_test_with_cx(|cx| async move {
            let config = NativeQuicConnectionConfig::default();
            let mut router = ConnectionRouter::new(config);
            let connection_id = ConnectionId::new(&[0xa1, 0x01, 0x00, 0x01]).expect("cid");
            let peer_addr: SocketAddr = "127.0.0.1:4435".parse().unwrap();
            router
                .create_connection(&cx, connection_id, peer_addr, false)
                .await
                .expect("connection creation should succeed");
            router
                .install_packet_protection(
                    &cx,
                    connection_id,
                    deterministic_one_rtt_protection(&cx).await,
                )
                .expect("install packet protection");
            let mut receiver = ConnectionRouter::new(config);
            receiver
                .create_connection(&cx, connection_id, peer_addr, false)
                .await
                .expect("receiver connection creation should succeed");
            receiver
                .install_packet_protection(
                    &cx,
                    connection_id,
                    deterministic_one_rtt_protection(&cx).await,
                )
                .expect("install receiver packet protection");

            let datagram = Bytes::from_static(b"a1 protected udp symbol");
            {
                let handle = router
                    .connections
                    .get_mut(&connection_id)
                    .expect("connection handle");
                establish_for_application_data(&cx, &mut handle.connection);
                handle
                    .connection
                    .send_datagram(&cx, datagram.clone())
                    .expect("queue datagram");
            }

            let now = Instant::now();
            let packets = {
                let handle = router
                    .connections
                    .get_mut(&connection_id)
                    .expect("connection handle");
                drain_connection_frames(
                    &cx,
                    connection_id,
                    handle,
                    PacketNumberSpace::ApplicationData,
                    peer_addr,
                    now,
                    42_000,
                )
                .await
                .expect("drain protected packet")
            };
            assert_eq!(packets.len(), 1);
            assert_eq!(packets[0].packet.dst_addr, peer_addr);
            assert_eq!(packets[0].packet.send_time, Some(now));
            assert!(packets[0].packet.data.len() <= PROTECTED_1RTT_MAX_PACKET_BYTES);

            let mut raw_frame_payload = BytesMut::new();
            QuicFrame::Datagram { data: datagram }
                .encode(&mut raw_frame_payload)
                .expect("encode raw DATAGRAM frame");
            let packet = &packets[0].packet.data;
            assert_ne!(packet.as_slice(), raw_frame_payload.as_ref());

            // On the wire only the invariant prefix is readable (RFC 9001
            // §5.4): the packet number and key phase are masked until the
            // receiver removes header protection with the sender's key.
            let ProtectedHeaderPrefix::Short {
                dst_cid,
                packet_number_offset,
            } = ProtectedHeaderPrefix::decode(packet, connection_id.len())
                .expect("decode protected short prefix")
            else {
                panic!("expected a protected 1-RTT short header packet");
            };
            assert_eq!(dst_cid, connection_id);
            assert_eq!(packet_number_offset, 1 + connection_id.len());
            let header_len = packet_number_offset + usize::from(PROTECTED_1RTT_PACKET_NUMBER_LEN);
            assert_eq!(
                packet.len(),
                header_len + raw_frame_payload.len() + PROTECTED_1RTT_TAG_LEN
            );
            assert_ne!(
                &packet[header_len..header_len + raw_frame_payload.len()],
                raw_frame_payload.as_ref()
            );
            let mut verifier = deterministic_one_rtt_protection(&cx).await;
            let unprotected = unprotect_1rtt_packet(&cx, connection_id, &mut verifier, packet)
                .await
                .expect("unmask and authenticate");
            assert!(!unprotected.header.spin);
            assert!(!unprotected.header.key_phase);
            assert_eq!(unprotected.header.dst_cid, connection_id);
            assert_eq!(unprotected.header.packet_number, 0);
            assert_eq!(
                unprotected.header.packet_number_len,
                PROTECTED_1RTT_PACKET_NUMBER_LEN
            );
            assert_eq!(unprotected.plaintext, raw_frame_payload.as_ref());
            // Planted negative: a flipped masked bit (packet-number length)
            // changes the AEAD associated data, so authentication fails.
            let mut flipped = packet.clone();
            flipped[0] ^= 0x01;
            let mut verifier = deterministic_one_rtt_protection(&cx).await;
            assert!(
                unprotect_1rtt_packet(&cx, connection_id, &mut verifier, &flipped)
                    .await
                    .is_err(),
                "flipping a header-protected bit must fail authentication"
            );
            let mut flipped_pn = packet.clone();
            flipped_pn[packet_number_offset] ^= 0x80;
            let mut verifier = deterministic_one_rtt_protection(&cx).await;
            assert!(
                unprotect_1rtt_packet(&cx, connection_id, &mut verifier, &flipped_pn)
                    .await
                    .is_err(),
                "flipping a protected packet-number byte must fail authentication"
            );

            {
                let handle = receiver
                    .connections
                    .get_mut(&connection_id)
                    .expect("receiver connection handle");
                establish_for_application_data(&cx, &mut handle.connection);
            }
            let received = ReceivedPacket {
                src_addr: peer_addr,
                data: packet.clone(),
                receive_time: Instant::now(),
                transmit_time: None,
            };
            match receiver
                .route_packet(&cx, received)
                .await
                .expect("route protected packet")
            {
                RoutingResult::Routed {
                    connection_id: routed_id,
                    ..
                } => assert_eq!(routed_id, connection_id),
                other => panic!("expected routed protected packet, got {other:?}"),
            }
            let received_datagram = receiver
                .connections
                .get_mut(&connection_id)
                .expect("receiver connection handle")
                .connection
                .recv_datagram()
                .expect("datagram delivered after unprotect");
            assert_eq!(received_datagram.as_ref(), b"a1 protected udp symbol");
        });
    }

    #[test]
    fn test_application_datagram_handoff_without_protection_fails_closed() {
        run_test_with_cx(|cx| async move {
            let config = NativeQuicConnectionConfig::default();
            let mut router = ConnectionRouter::new(config);
            let connection_id = ConnectionId::new(&[0xa1, 0x01, 0x00, 0x02]).expect("cid");
            let peer_addr: SocketAddr = "127.0.0.1:4436".parse().unwrap();
            router
                .create_connection(&cx, connection_id, peer_addr, false)
                .await
                .expect("connection creation should succeed");

            let handle = router
                .connections
                .get_mut(&connection_id)
                .expect("connection handle");
            establish_for_application_data(&cx, &mut handle.connection);
            handle
                .connection
                .send_datagram(&cx, Bytes::from_static(b"must not leak raw"))
                .expect("queue datagram");

            let err = drain_connection_frames(
                &cx,
                connection_id,
                handle,
                PacketNumberSpace::ApplicationData,
                peer_addr,
                Instant::now(),
                42_000,
            )
            .await
            .expect_err("missing 1-RTT packet protection must fail closed");
            assert!(matches!(
                err,
                ConnectionRouterError::PacketProtectionUnavailable { connection_id: id }
                    if id == connection_id
            ));
            assert_eq!(handle.connection.pending_outbound_datagram_count(), 1);
        });
    }

    #[test]
    fn overdue_managed_pto_emits_bounded_protected_probes_and_isolates_a_bad_connection() {
        run_test_with_cx(|cx| async move {
            let mut router = ConnectionRouter::new(NativeQuicConnectionConfig::default());
            let peer: SocketAddr = "127.0.0.1:4401".parse().unwrap();
            let ids = [1u8, 2, 3].map(|id| ConnectionId::new(&[id, 0, 0, 1]).unwrap());
            for (index, id) in ids.into_iter().enumerate() {
                router
                    .create_connection(&cx, id, peer, false)
                    .await
                    .unwrap();
                if index != 1 {
                    router
                        .install_packet_protection(
                            &cx,
                            id,
                            deterministic_one_rtt_protection(&cx).await,
                        )
                        .unwrap();
                }
                let handle = router.connections.get_mut(&id).unwrap();
                establish_for_application_data(&cx, &mut handle.connection);
                let cwnd = handle.connection.transport().congestion_window_bytes();
                for sent in 0..cwnd / 1_200 {
                    handle
                        .connection
                        .on_packet_sent(
                            &cx,
                            PacketNumberSpace::ApplicationData,
                            1_200,
                            true,
                            true,
                            1_000 + sent,
                        )
                        .unwrap();
                }
                handle
                    .connection
                    .send_datagram(&cx, Bytes::from_static(b"ordinary data must stay queued"))
                    .unwrap();
                let origin = router.clock_origin;
                ConnectionRouter::refresh_connection_timer(
                    &cx,
                    id,
                    handle,
                    origin,
                    1_000,
                    origin + Duration::from_micros(1_000),
                )
                .unwrap();
            }
            // One hour exceeds the old capped PTO horizon. Both healthy peers
            // must emit one authenticated probe despite a full congestion window.
            let now = router.clock_origin + Duration::from_secs(3_600);
            let packets = router.process_timer_events(&cx, now).await.unwrap();
            assert_eq!(
                packets.len(),
                2,
                "one broken protection provider must not erase healthy output"
            );
            for packet in packets {
                let ProtectedHeaderPrefix::Short { dst_cid, .. } =
                    ProtectedHeaderPrefix::decode(&packet.data, 4).unwrap()
                else {
                    panic!("protected short packet required")
                };
                assert!(dst_cid == ids[0] || dst_cid == ids[2]);
                let mut protection = deterministic_one_rtt_protection(&cx).await;
                let unprotected =
                    unprotect_1rtt_packet(&cx, dst_cid, &mut protection, &packet.data)
                        .await
                        .unwrap();
                let mut expected = BytesMut::new();
                QuicFrame::Ping.encode(&mut expected).unwrap();
                assert_eq!(unprotected.plaintext, expected.as_ref());
            }
            assert!(router.next_timer_deadline().unwrap() > now);
            assert!(
                router
                    .process_timer_events(&cx, now)
                    .await
                    .unwrap()
                    .is_empty(),
                "the same elapsed deadline must not fire twice"
            );
            for id in ids {
                let handle = &router.connections[&id];
                assert_eq!(handle.connection.pending_outbound_datagram_count(), 1);
                assert!(handle.next_timer_deadline.unwrap() > now);
            }
        });
    }

    #[test]
    fn test_timer_scheduler_basic() {
        let (cx, _, _) = timer_test_context(crate::Time::from_secs(123));
        futures_lite::future::block_on(async move {
            let mut scheduler = QuicTimerScheduler::new();

            assert!(!scheduler.has_pending_timer());
            assert_eq!(scheduler.current_deadline(), None);

            let deadline = Instant::now() + std::time::Duration::from_millis(10);
            scheduler
                .schedule_timer(&cx, deadline)
                .await
                .expect("timer scheduling should succeed");

            assert!(scheduler.has_pending_timer());
            assert_eq!(scheduler.current_deadline(), Some(deadline));
        });
    }

    // br-asupersync-bi2462.75: real router/frame/protection transitions with
    // explicit clock inputs; these unit cases do not claim native UDP delivery.
    #[test]
    fn managed_router_unsent_probe_keeps_queue_and_in_flight_bytes_bounded() {
        run_test_with_cx(|cx| async move {
            let mut router = ConnectionRouter::new(NativeQuicConnectionConfig::default());
            let cid = ConnectionId::new(&[7, 0, 0, 1]).unwrap();
            let peer = "127.0.0.1:4450".parse().unwrap();
            add_protected_test_connection(&cx, &mut router, cid, peer).await;
            let handle = router.connections.get_mut(&cid).unwrap();
            handle
                .connection
                .on_packet_sent(
                    &cx,
                    PacketNumberSpace::ApplicationData,
                    1_200,
                    true,
                    true,
                    1_000,
                )
                .unwrap();
            let origin = router.clock_origin;
            ConnectionRouter::refresh_connection_timer(
                &cx,
                cid,
                handle,
                origin,
                1_000,
                origin + Duration::from_micros(1_000),
            )
            .unwrap();
            let first = router.next_timer_deadline().unwrap();
            let mut queued = router
                .process_managed_timer_events(&cx, first, &HashSet::new())
                .await
                .unwrap();
            assert_eq!(queued.len(), 1);
            assert_eq!(queued[0].connection_id, cid);
            let committed_bytes = router.connections[&cid]
                .connection
                .transport()
                .bytes_in_flight();
            assert_eq!(committed_bytes, 1_200 + queued[0].packet.data.len() as u64);
            let first_packet = queued[0].packet.data.clone();
            let endpoint_pending = HashSet::from([cid]);
            for _ in 0..14 {
                let now = router.next_timer_deadline().unwrap() + Duration::from_secs(1);
                queued.extend(
                    router
                        .process_managed_timer_events(&cx, now, &endpoint_pending)
                        .await
                        .unwrap(),
                );
                assert_eq!(queued.len(), 1);
                assert_eq!(queued[0].packet.data, first_packet);
                assert_eq!(
                    router.connections[&cid]
                        .connection
                        .transport()
                        .bytes_in_flight(),
                    committed_bytes
                );
                assert!(router.next_timer_deadline().unwrap() > now);
            }
            // Exercise the same bound while the committed packet remains in
            // the router (for example after a cancelled multi-connection pass).
            router.pending_timer_packets.extend(queued);
            let now = router.next_timer_deadline().unwrap();
            let retained = router
                .process_managed_timer_events(&cx, now, &HashSet::new())
                .await
                .unwrap();
            assert_eq!(retained.len(), 1);
            assert_eq!(retained[0].packet.data, first_packet);
            assert_eq!(
                router.connections[&cid]
                    .connection
                    .transport()
                    .bytes_in_flight(),
                committed_bytes
            );
            assert!(router.next_timer_deadline().unwrap() > now);
            // Once the owner reports the packet drained, a later PTO really
            // commits another bounded protected probe rather than refusing all output.
            let now = router.next_timer_deadline().unwrap();
            let resumed = router
                .process_managed_timer_events(&cx, now, &HashSet::new())
                .await
                .unwrap();
            assert_eq!(resumed.len(), 1);
            assert_ne!(resumed[0].packet.data, first_packet);
            assert_eq!(
                router.connections[&cid]
                    .connection
                    .transport()
                    .bytes_in_flight(),
                committed_bytes + resumed[0].packet.data.len() as u64
            );
        });
    }

    #[test]
    fn managed_router_handoff_purges_only_its_cid_at_a_shared_peer() {
        run_test_with_cx(|cx| async move {
            let mut router = ConnectionRouter::new(NativeQuicConnectionConfig::default());
            let ids = [1u8, 2].map(|id| ConnectionId::new(&[8, 0, 0, id]).unwrap());
            let peer = "127.0.0.1:4451".parse().unwrap();
            for cid in ids {
                add_protected_test_connection(&cx, &mut router, cid, peer).await;
                let handle = router.connections.get_mut(&cid).unwrap();
                handle
                    .connection
                    .on_packet_sent(
                        &cx,
                        PacketNumberSpace::ApplicationData,
                        1_200,
                        true,
                        true,
                        1_000,
                    )
                    .unwrap();
                let origin = router.clock_origin;
                ConnectionRouter::refresh_connection_timer(
                    &cx,
                    cid,
                    handle,
                    origin,
                    1_000,
                    origin + Duration::from_micros(1_000),
                )
                .unwrap();
            }
            let now = router.next_timer_deadline().unwrap();
            let packets = router
                .process_managed_timer_events(&cx, now, &HashSet::new())
                .await
                .unwrap();
            assert_eq!(
                packets
                    .iter()
                    .map(|routed| routed.connection_id)
                    .collect::<Vec<_>>(),
                ids
            );
            let survivor = packets[1].packet.data.clone();
            router.pending_timer_packets.extend(packets);
            for cid in ids {
                router
                    .connections
                    .get_mut(&cid)
                    .unwrap()
                    .connection
                    .queue_ping(&cx)
                    .unwrap();
            }
            let deferred = router.drain_deferred_output(&cx, now, 2).await.unwrap();
            assert_eq!(deferred.len(), 2);
            let deferred_survivor = deferred
                .iter()
                .find(|routed| routed.connection_id == ids[1])
                .unwrap()
                .packet
                .data
                .clone();
            router.pending_deferred_packets.extend(deferred);
            let accepted = router.take_connection(&cx, ids[0]).unwrap();
            assert_eq!(accepted.peer_addr, peer);
            assert_eq!(router.pending_timer_packets.len(), 1);
            assert_eq!(router.pending_timer_packets[0].connection_id, ids[1]);
            assert_eq!(router.pending_timer_packets[0].packet.data, survivor);
            assert_eq!(router.pending_deferred_packets.len(), 1);
            assert_eq!(
                router.pending_deferred_packets[0].packet.data,
                deferred_survivor
            );
            router.remove_connection(&cx, ids[1]).unwrap();
            assert!(router.pending_timer_packets.is_empty());
            assert!(router.pending_deferred_packets.is_empty());
        });
    }

    #[test]
    fn managed_router_backpressure_processes_ack_then_drains_encrypted_data() {
        run_test_with_cx(|cx| async move {
            let mut router = ConnectionRouter::new(NativeQuicConnectionConfig::default());
            let cid = ConnectionId::new(&[9, 0, 0, 1]).unwrap();
            let peer = "127.0.0.1:4452".parse().unwrap();
            add_protected_test_connection(&cx, &mut router, cid, peer).await;
            let handle = router.connections.get_mut(&cid).unwrap();
            for _ in 0..10 {
                handle
                    .connection
                    .on_packet_sent(
                        &cx,
                        PacketNumberSpace::ApplicationData,
                        1_200,
                        true,
                        true,
                        1_000,
                    )
                    .unwrap();
            }
            handle
                .connection
                .send_datagram(&cx, Bytes::from_static(b"deferred actual data"))
                .unwrap();
            let now = router.clock_origin + Duration::from_micros(2_000);
            assert!(
                router
                    .drain_deferred_output(&cx, now, 1)
                    .await
                    .unwrap()
                    .is_empty()
            );
            assert!(
                !router.connections[&cid].deferred_spaces[2],
                "cwnd-blocked data is not immediate readiness"
            );
            assert_eq!(
                router.connections[&cid]
                    .connection
                    .pending_outbound_datagram_count(),
                1
            );

            let mut peer_connection =
                NativeQuicConnection::new(NativeQuicConnectionConfig::default());
            establish_for_application_data(&cx, &mut peer_connection);
            let mut protection = deterministic_one_rtt_protection(&cx).await;
            let zero = crate::net::VarInt(0);
            let ack = QuicFrame::Ack {
                largest_acknowledged: zero,
                ack_delay: zero,
                ack_range_count: zero,
                first_ack_range: zero,
                ack_ranges: Vec::new(),
                ecn_counts: None,
            };
            let mut payload = BytesMut::new();
            ack.encode(&mut payload).unwrap();
            let packet = assemble_protected_1rtt_packet(
                &cx,
                cid,
                &mut peer_connection,
                &mut protection,
                &[ack],
                &payload,
                2_000,
                false,
            )
            .await
            .unwrap();
            let result = router
                .route_packet_with_output(
                    &cx,
                    ReceivedPacket {
                        src_addr: peer,
                        data: packet,
                        receive_time: now,
                        transmit_time: None,
                    },
                    false,
                )
                .await
                .unwrap();
            let RoutingResult::Routed {
                outgoing_packets, ..
            } = result
            else {
                panic!("ACK must reach connection")
            };
            assert!(outgoing_packets.is_empty());
            let connection = &router.connections[&cid].connection;
            assert_eq!(connection.transport().packets_acked_total(), 1);
            assert_eq!(connection.transport().bytes_in_flight(), 10_800);
            assert!(connection.transport().can_send(1_200));
            assert_eq!(connection.pending_outbound_datagram_count(), 1);
            assert_eq!(connection.datagrams_sent(), 0);
            assert!(router.connections[&cid].deferred_spaces[2]);
            assert!(
                router
                    .drain_deferred_output(&cx, now, 0)
                    .await
                    .unwrap()
                    .is_empty()
            );
            let output = router.drain_deferred_output(&cx, now, 1).await.unwrap();
            assert_eq!(output.len(), 1);
            assert_eq!(output[0].connection_id, cid);
            assert_eq!(
                router.connections[&cid]
                    .connection
                    .pending_outbound_datagram_count(),
                0
            );
            let packet = &output[0].packet.data;
            let ProtectedHeaderPrefix::Short { dst_cid, .. } =
                ProtectedHeaderPrefix::decode(packet, cid.len()).unwrap()
            else {
                panic!("protected short packet")
            };
            assert_eq!(dst_cid, cid);
            let plaintext = unprotect_1rtt_packet(&cx, cid, &mut protection, packet)
                .await
                .unwrap()
                .plaintext;
            let mut decoded = plaintext.as_slice();
            let frame = QuicFrame::decode(&mut decoded).unwrap().unwrap();
            assert!(
                matches!(frame, QuicFrame::Datagram { data } if data.as_ref() == b"deferred actual data")
            );
            assert!(decoded.is_empty());
            assert!(
                router
                    .drain_deferred_output(&cx, now, 1)
                    .await
                    .unwrap()
                    .is_empty()
            );
            assert!(!router.connections[&cid].deferred_spaces[2]);
        });
    }

    #[test]
    fn managed_router_timer_batch_yields_and_keeps_committed_prefix_after_drop() {
        run_test_with_cx(|cx| async move {
            let mut router = ConnectionRouter::new(NativeQuicConnectionConfig::default());
            let peer = "127.0.0.1:4454".parse().unwrap();
            let mut ids = Vec::new();
            for index in 0..=TIMER_CONNECTIONS_PER_TURN {
                let cid = ConnectionId::new(&(index as u64).to_be_bytes()).unwrap();
                ids.push(cid);
                add_protected_test_connection(&cx, &mut router, cid, peer).await;
                let handle = router.connections.get_mut(&cid).unwrap();
                handle
                    .connection
                    .on_packet_sent(
                        &cx,
                        PacketNumberSpace::ApplicationData,
                        1_200,
                        true,
                        true,
                        1_000,
                    )
                    .unwrap();
                let origin = router.clock_origin;
                ConnectionRouter::refresh_connection_timer(
                    &cx,
                    cid,
                    handle,
                    origin,
                    1_000,
                    origin + Duration::from_micros(1_000),
                )
                .unwrap();
            }
            let now = router.next_timer_deadline().unwrap();
            let pending = HashSet::new();
            {
                let mut timers =
                    std::pin::pin!(router.process_managed_timer_events(&cx, now, &pending));
                assert!(
                    timers
                        .as_mut()
                        .poll(&mut Context::from_waker(Waker::noop()))
                        .is_pending()
                );
            }
            assert_eq!(
                router.pending_timer_packets.len(),
                TIMER_CONNECTIONS_PER_TURN
            );
            for cid in &ids[..TIMER_CONNECTIONS_PER_TURN] {
                assert!(router.connections[cid].next_timer_deadline.unwrap() > now);
            }
            let last = ids[TIMER_CONNECTIONS_PER_TURN];
            assert_eq!(router.connections[&last].next_timer_deadline, Some(now));
            let prefix: Vec<_> = router
                .pending_timer_packets
                .iter()
                .map(|routed| (routed.connection_id, routed.packet.data.clone()))
                .collect();
            let cancelled = Cx::for_testing();
            cancelled.set_cancel_requested(true);
            assert!(matches!(
                router
                    .process_managed_timer_events(&cancelled, now, &pending)
                    .await,
                Err(ConnectionRouterError::Cancelled)
            ));
            assert_eq!(
                router.pending_timer_packets.len(),
                TIMER_CONNECTIONS_PER_TURN
            );
            let resumed = router
                .process_managed_timer_events(&cx, now, &pending)
                .await
                .unwrap();
            assert_eq!(resumed.len(), TIMER_CONNECTIONS_PER_TURN + 1);
            assert_eq!(
                resumed
                    .iter()
                    .map(|routed| routed.connection_id)
                    .collect::<HashSet<_>>()
                    .len(),
                resumed.len()
            );
            for (routed, (cid, packet)) in resumed.iter().zip(prefix) {
                assert_eq!(routed.connection_id, cid);
                assert_eq!(routed.packet.data, packet);
            }
            for cid in ids {
                let handle = &router.connections[&cid];
                assert_eq!(handle.connection.transport().pto_count(), 1);
                assert!(handle.next_timer_deadline.unwrap() > now);
            }
            assert!(router.pending_timer_packets.is_empty());
        });
    }

    #[test]
    fn managed_router_restarted_timer_handoff_does_not_wait_for_future_deadline() {
        run_test_with_cx(|cx| async move {
            let mut router = ConnectionRouter::new(NativeQuicConnectionConfig::default());
            let peer = "127.0.0.1:4455".parse().unwrap();
            for index in 0..TIMER_CONNECTIONS_PER_TURN {
                let cid = ConnectionId::new(&(index as u64).to_be_bytes()).unwrap();
                add_protected_test_connection(&cx, &mut router, cid, peer).await;
                let handle = router.connections.get_mut(&cid).unwrap();
                handle
                    .connection
                    .on_packet_sent(
                        &cx,
                        PacketNumberSpace::ApplicationData,
                        1_200,
                        true,
                        true,
                        1_000,
                    )
                    .unwrap();
                let origin = router.clock_origin;
                ConnectionRouter::refresh_connection_timer(
                    &cx,
                    cid,
                    handle,
                    origin,
                    1_000,
                    origin + Duration::from_micros(1_000),
                )
                .unwrap();
            }
            // An idle final CID makes the traversal yield after all due
            // connections have already been rearmed into the future.
            let idle =
                ConnectionId::new(&(TIMER_CONNECTIONS_PER_TURN as u64).to_be_bytes()).unwrap();
            router
                .create_connection(&cx, idle, peer, false)
                .await
                .unwrap();
            let now = router.next_timer_deadline().unwrap();
            let pending = HashSet::new();
            {
                let mut timers =
                    std::pin::pin!(router.process_managed_timer_events(&cx, now, &pending));
                assert!(
                    timers
                        .as_mut()
                        .poll(&mut Context::from_waker(Waker::noop()))
                        .is_pending()
                );
            }
            assert!(router.next_timer_deadline().unwrap() > now);
            assert!(router.connections[&idle].next_timer_deadline.is_none());
            let expected: Vec<_> = router
                .pending_timer_packets
                .iter()
                .map(|routed| (routed.connection_id, routed.packet.data.clone()))
                .collect();
            assert_eq!(expected.len(), TIMER_CONNECTIONS_PER_TURN);
            assert!(router.take_pending_timer_output(0).is_empty());
            assert_eq!(router.pending_timer_packets.len(), expected.len());
            let mut output = router.take_pending_timer_output(3);
            assert_eq!(output.len(), 3);
            assert_eq!(router.pending_timer_packets.len(), expected.len() - 3);
            output.extend(router.take_pending_timer_output(TIMER_CONNECTIONS_PER_TURN));
            assert_eq!(output.len(), expected.len());
            for (routed, (cid, bytes)) in output.iter().zip(expected) {
                assert_eq!(routed.connection_id, cid);
                assert_eq!(routed.packet.data, bytes);
                assert_eq!(routed.packet.dst_addr, peer);
                assert_eq!(
                    router.connections[&cid].connection.transport().pto_count(),
                    1
                );
            }
            assert!(router.take_pending_timer_output(1).is_empty());
            assert!(router.next_timer_deadline().unwrap() > now);
        });
    }

    #[test]
    fn managed_router_deferred_budget_rotates_peers_and_keeps_prefix_on_error() {
        run_test_with_cx(|cx| async move {
            let mut router = ConnectionRouter::new(NativeQuicConnectionConfig::default());
            let ids = [1u8, 2, 3].map(|id| ConnectionId::new(&[10, 0, 0, id]).unwrap());
            let peer = "127.0.0.1:4453".parse().unwrap();
            for cid in ids {
                add_protected_test_connection(&cx, &mut router, cid, peer).await;
                router
                    .connections
                    .get_mut(&cid)
                    .unwrap()
                    .connection
                    .queue_ping(&cx)
                    .unwrap();
            }
            let now = router.clock_origin + Duration::from_micros(1_000);
            let first = router.drain_deferred_output(&cx, now, 1).await.unwrap();
            assert_eq!(first.len(), 1);
            assert_eq!(first[0].connection_id, ids[0]);
            router
                .connections
                .get_mut(&ids[0])
                .unwrap()
                .connection
                .queue_ping(&cx)
                .unwrap();
            let second = router.drain_deferred_output(&cx, now, 1).await.unwrap();
            assert_eq!(second[0].connection_id, ids[1]);
            let third = router.drain_deferred_output(&cx, now, 1).await.unwrap();
            assert_eq!(third[0].connection_id, ids[2]);
            // The next pass commits CID 1 before CID 2 fails its real missing
            // protection gate. The good prefix must still be returned.
            router
                .connections
                .get_mut(&ids[1])
                .unwrap()
                .packet_protection = None;
            let prefix = router.drain_deferred_output(&cx, now, 3).await.unwrap();
            assert_eq!(prefix.len(), 1);
            assert_eq!(prefix[0].connection_id, ids[0]);
            let bytes = prefix[0].packet.data.clone();
            router.pending_deferred_packets.extend(prefix);
            let cancelled = Cx::for_testing();
            cancelled.set_cancel_requested(true);
            assert!(matches!(
                router.drain_deferred_output(&cancelled, now, 1).await,
                Err(ConnectionRouterError::Cancelled)
            ));
            assert_eq!(router.pending_deferred_packets.len(), 1);
            let recovered = router.drain_deferred_output(&cx, now, 1).await.unwrap();
            assert_eq!(recovered.len(), 1);
            assert_eq!(recovered[0].packet.data, bytes);
        });
    }

    fn timer_test_context(
        epoch: crate::Time,
    ) -> (
        Cx,
        std::sync::Arc<crate::time::VirtualClock>,
        TimerDriverHandle,
    ) {
        let clock = std::sync::Arc::new(crate::time::VirtualClock::starting_at(epoch));
        let driver = TimerDriverHandle::with_virtual_clock(clock.clone());
        let cx = Cx::new_with_drivers(
            crate::types::RegionId::new_for_test(0, 1),
            crate::types::TaskId::new_for_test(0, 0),
            crate::types::Budget::INFINITE,
            None,
            None,
            None,
            Some(driver.clone()),
            None,
        );
        (cx, clock, driver)
    }

    #[test]
    fn timer_uses_explicit_nonzero_epoch_and_survives_a_losing_wait() {
        let (cx, clock, driver) = timer_test_context(crate::Time::from_secs(123));
        let (ambient, _, ambient_driver) = timer_test_context(crate::Time::from_secs(900));
        let _ambient = Cx::set_current(Some(ambient));
        let mut scheduler = QuicTimerScheduler::new();
        let start = scheduler.now(&cx).unwrap();
        let deadline = start + Duration::from_secs(2);
        futures_lite::future::block_on(scheduler.schedule_timer(&cx, deadline)).unwrap();
        let mut task_cx = Context::from_waker(Waker::noop());
        {
            let mut wait = std::pin::pin!(scheduler.wait_for_timer(&cx));
            assert!(wait.as_mut().poll(&mut task_cx).is_pending());
        }
        assert_eq!(scheduler.current_deadline(), Some(deadline));
        assert_eq!(driver.pending_count(), 1);
        assert_eq!(ambient_driver.pending_count(), 0);
        clock.advance(1_999_999_999);
        assert_eq!(driver.process_timers(), 0);
        assert!(scheduler.poll_timer(&mut task_cx).is_pending());
        clock.advance(1);
        assert_eq!(driver.process_timers(), 1);
        assert_eq!(
            scheduler.poll_timer(&mut task_cx),
            Poll::Ready(Some(deadline))
        );
        assert_eq!(scheduler.poll_timer(&mut task_cx), Poll::Ready(None));
        assert_eq!(driver.pending_count(), 0);
    }

    #[test]
    fn timer_overdue_reschedule_and_removal_keep_one_registration() {
        let (cx, clock, driver) = timer_test_context(crate::Time::from_secs(100));
        let mut scheduler = QuicTimerScheduler::new();
        let start = scheduler.now(&cx).unwrap();
        let mut task_cx = Context::from_waker(Waker::noop());
        let overdue = start
            .checked_sub(Duration::from_secs(1))
            .expect("test clock supports an overdue deadline");
        futures_lite::future::block_on(scheduler.schedule_timer(&cx, overdue)).unwrap();
        assert!(scheduler.has_pending_timer());
        assert_eq!(
            scheduler.poll_timer(&mut task_cx),
            Poll::Ready(Some(overdue))
        );
        assert_eq!(scheduler.poll_timer(&mut task_cx), Poll::Ready(None));

        let early = start + Duration::from_secs(2);
        let late = start + Duration::from_secs(4);
        futures_lite::future::block_on(scheduler.schedule_timer(&cx, late)).unwrap();
        assert!(scheduler.poll_timer(&mut task_cx).is_pending());
        assert_eq!(driver.pending_count(), 1);
        futures_lite::future::block_on(scheduler.schedule_timer(&cx, early)).unwrap();
        assert_eq!(
            driver.pending_count(),
            0,
            "old registration removed on rearm"
        );
        assert!(scheduler.poll_timer(&mut task_cx).is_pending());
        futures_lite::future::block_on(scheduler.schedule_timer(&cx, late)).unwrap();
        futures_lite::future::block_on(scheduler.schedule_timer(&cx, early)).unwrap();
        assert_eq!(scheduler.current_deadline(), Some(early));
        assert_eq!(driver.pending_count(), 1);
        clock.advance(2_000_000_000);
        assert_eq!(driver.process_timers(), 1);
        assert_eq!(scheduler.poll_timer(&mut task_cx), Poll::Ready(Some(early)));
        futures_lite::future::block_on(scheduler.schedule_timer(&cx, late)).unwrap();
        assert!(scheduler.poll_timer(&mut task_cx).is_pending());
        scheduler.cancel();
        assert_eq!(driver.pending_count(), 0);
        assert_eq!(scheduler.current_deadline(), None);
    }

    #[test]
    fn timer_refuses_missing_changed_or_overflowing_clock_without_losing_current_timer() {
        // This newly authored strict-owner test targets managed admission.
        // The established public API allows no-ops and independent caller cancellation.
        let mut scheduler = QuicTimerScheduler::new();
        let missing = Cx::for_testing();
        assert!(matches!(
            futures_lite::future::block_on(
                scheduler.schedule_timer_bound(&missing, Instant::now())
            ),
            Err(ConnectionRouterError::TimerSchedulingFailed(_))
        ));
        let (cx, _, _) = timer_test_context(crate::Time::from_nanos(u64::MAX - 100));
        let start = scheduler.now(&cx).unwrap();
        assert!(matches!(
            futures_lite::future::block_on(
                scheduler.schedule_timer_bound(&cx, start + Duration::from_secs(1))
            ),
            Err(ConnectionRouterError::TimerSchedulingFailed(_))
        ));
        assert!(!scheduler.has_pending_timer());
        futures_lite::future::block_on(scheduler.schedule_timer_bound(&cx, start)).unwrap();
        let (other, _, _) = timer_test_context(crate::Time::ZERO);
        assert!(matches!(
            scheduler.now(&other),
            Err(ConnectionRouterError::TimerSchedulingFailed(_))
        ));
        for refused in [&other, &missing] {
            assert!(matches!(
                futures_lite::future::block_on(
                    scheduler.schedule_timer_bound(refused, start + Duration::from_secs(1))
                ),
                Err(ConnectionRouterError::TimerSchedulingFailed(_))
            ));
            assert!(matches!(
                scheduler.now(refused),
                Err(ConnectionRouterError::TimerSchedulingFailed(_))
            ));
        }
        assert_eq!(scheduler.current_deadline(), Some(start));
    }

    struct TimerSignal(std::sync::mpsc::Sender<()>);

    impl std::task::Wake for TimerSignal {
        fn wake(self: std::sync::Arc<Self>) {
            let _ = self.0.send(());
        }
    }

    fn timer_signal() -> (Waker, std::sync::mpsc::Receiver<()>) {
        let (sender, receiver) = std::sync::mpsc::channel();
        (
            Waker::from(std::sync::Arc::new(TimerSignal(sender))),
            receiver,
        )
    }

    #[test]
    fn public_timer_noop_and_cancel_allow_a_new_driver_without_old_wakes() {
        let (first, first_clock, first_driver) = timer_test_context(crate::Time::from_secs(123));
        let (second, second_clock, second_driver) = timer_test_context(crate::Time::from_secs(987));
        let mut scheduler = QuicTimerScheduler::new();
        let first_deadline = Instant::now() + Duration::from_secs(2);
        futures_lite::future::block_on(scheduler.schedule_timer(&first, first_deadline)).unwrap();
        let (waker, signal) = timer_signal();
        {
            let mut wait = std::pin::pin!(scheduler.wait_for_timer(&first));
            assert!(
                wait.as_mut()
                    .poll(&mut Context::from_waker(&waker))
                    .is_pending()
            );
        }
        assert_eq!(first_driver.pending_count(), 1);
        let first_registered = first_driver.next_deadline();
        futures_lite::future::block_on(
            scheduler.schedule_timer(&second, first_deadline + Duration::from_secs(1)),
        )
        .unwrap();
        assert_eq!(scheduler.current_deadline(), Some(first_deadline));
        assert_eq!(first_driver.next_deadline(), first_registered);
        assert_eq!(first_driver.pending_count(), 1);
        assert_eq!(second_driver.pending_count(), 0);
        scheduler.cancel();
        assert_eq!(first_driver.pending_count(), 0);
        assert!(scheduler.clock.is_none());
        let second_deadline = Instant::now() + Duration::from_secs(2);
        futures_lite::future::block_on(scheduler.schedule_timer(&second, second_deadline)).unwrap();
        let due = scheduler.current_sleep.as_ref().unwrap().deadline();
        let advance = due.as_nanos() - second_driver.now().as_nanos();
        assert!(advance > 0);
        {
            let mut wait = std::pin::pin!(scheduler.wait_for_timer(&second));
            assert!(
                wait.as_mut()
                    .poll(&mut Context::from_waker(&waker))
                    .is_pending()
            );
            assert_eq!(second_driver.pending_count(), 1);
            first_clock.advance(3_000_000_000);
            assert_eq!(first_driver.process_timers(), 0);
            second_clock.advance(advance - 1);
            assert_eq!(second_driver.process_timers(), 0);
            assert!(matches!(
                signal.try_recv(),
                Err(std::sync::mpsc::TryRecvError::Empty)
            ));
            second_clock.advance(1);
            assert_eq!(second_driver.process_timers(), 1);
            signal
                .try_recv()
                .expect("new driver must wake the current waiter");
            assert_eq!(
                wait.as_mut().poll(&mut Context::from_waker(&waker)),
                Poll::Ready(Ok(Some(second_deadline)))
            );
        }
        assert_eq!(first_driver.pending_count(), 0);
        assert_eq!(second_driver.pending_count(), 0);
        assert!(!scheduler.has_pending_timer());
        assert_eq!(scheduler.current_deadline(), None);
        println!(
            "quic_timer_public_reuse first_epoch_s=123 second_epoch_s=987 no_op_kept_registration=true old_driver_firings=0 new_driver_firings=1 pending_after=0"
        );
    }

    #[test]
    fn public_wait_keeps_created_driver_and_observes_callers_cancellation() {
        let (owner, _, owner_driver) = timer_test_context(crate::Time::from_secs(41));
        let (caller, caller_clock, caller_driver) = timer_test_context(crate::Time::from_secs(800));
        let mut scheduler = QuicTimerScheduler::new();
        let deadline = Instant::now() + Duration::from_secs(2);
        futures_lite::future::block_on(scheduler.schedule_timer(&owner, deadline)).unwrap();
        let (waker, signal) = timer_signal();
        {
            let mut wait = std::pin::pin!(scheduler.wait_for_timer(&caller));
            assert!(
                wait.as_mut()
                    .poll(&mut Context::from_waker(&waker))
                    .is_pending()
            );
            assert_eq!(owner_driver.pending_count(), 1);
            assert_eq!(caller_driver.pending_count(), 0);
            caller_clock.advance(10_000_000_000);
            assert_eq!(caller_driver.process_timers(), 0);
            assert!(matches!(
                signal.try_recv(),
                Err(std::sync::mpsc::TryRecvError::Empty)
            ));
            caller.cancel_with(crate::types::CancelKind::User, None);
            signal
                .try_recv()
                .expect("explicit caller cancellation must wake its wait");
            assert_eq!(
                wait.as_mut().poll(&mut Context::from_waker(&waker)),
                Poll::Ready(Err(ConnectionRouterError::Cancelled))
            );
        }
        assert_eq!(scheduler.current_deadline(), Some(deadline));
        scheduler.cancel();
        assert_eq!(owner_driver.pending_count(), 0);
        assert_eq!(caller_driver.pending_count(), 0);
        assert!(!scheduler.has_pending_timer());
    }

    #[test]
    fn public_driverless_timer_uses_shared_epoch_and_real_fallback_wake() {
        let missing = Cx::for_testing();
        assert!(missing.timer_driver().is_none());
        let (ambient, _, ambient_driver) = timer_test_context(crate::Time::from_secs(9_000));
        let _ambient = Cx::set_current(Some(ambient));
        let epoch = crate::time::process_epoch();
        let mut scheduler = QuicTimerScheduler::new();
        let deadline = Instant::now() + Duration::from_millis(150);
        futures_lite::future::block_on(scheduler.schedule_timer(&missing, deadline)).unwrap();
        let sleep = scheduler.current_sleep.as_ref().unwrap();
        assert_eq!(
            sleep.deadline(),
            crate::Time::from_nanos(
                u64::try_from(deadline.duration_since(epoch).as_nanos()).unwrap()
            )
        );
        assert!(!sleep.has_custom_time_getter());
        assert!(scheduler.clock.is_none());
        let (waker, signal) = timer_signal();
        {
            let mut wait = std::pin::pin!(scheduler.wait_for_timer(&missing));
            assert!(
                wait.as_mut()
                    .poll(&mut Context::from_waker(&waker))
                    .is_pending()
            );
            assert_eq!(ambient_driver.pending_count(), 0);
            // The maintained shared fallback must wake us; no speculative
            // repolls, including if a wheel wake only requests a rearm.
            let limit = Instant::now() + Duration::from_secs(2);
            loop {
                assert!(
                    Instant::now() < limit,
                    "shared fallback did not complete within its test bound"
                );
                signal
                    .recv_timeout(limit.saturating_duration_since(Instant::now()))
                    .expect("shared wall-clock fallback wake");
                if let Poll::Ready(result) = wait.as_mut().poll(&mut Context::from_waker(&waker)) {
                    assert_eq!(result, Ok(Some(deadline)));
                    assert!(
                        Instant::now() >= deadline,
                        "fallback completed before the absolute deadline"
                    );
                    break;
                }
            }
        }
        assert!(!scheduler.has_pending_timer());
        assert_eq!(scheduler.current_deadline(), None);
        assert_eq!(ambient_driver.pending_count(), 0);
        // An already due fallback deadline is observed once instead of discarded.
        let overdue = Instant::now()
            .checked_sub(Duration::from_millis(1))
            .expect("test clock supports an overdue deadline");
        futures_lite::future::block_on(scheduler.schedule_timer(&missing, overdue)).unwrap();
        assert_eq!(
            futures_lite::future::block_on(scheduler.wait_for_timer(&missing)),
            Ok(Some(overdue))
        );
        assert_eq!(
            futures_lite::future::block_on(scheduler.wait_for_timer(&missing)),
            Ok(None)
        );
        scheduler.cancel();
        assert!(scheduler.clock.is_none());
        println!(
            "quic_timer_public_fallback source=shared_process_epoch actual_wake=true custom_getter=false unrelated_driver_pending=0 owned_timer_after=none"
        );
    }

    #[test]
    fn public_fallback_wait_adopts_nonzero_driver_before_polling() {
        let missing = Cx::for_testing();
        let (adopter, clock, driver) = timer_test_context(crate::Time::from_secs(700));
        let mut scheduler = QuicTimerScheduler::new();
        let deadline = Instant::now() + Duration::from_millis(250);
        futures_lite::future::block_on(scheduler.schedule_timer(&missing, deadline)).unwrap();
        let (old_waker, old_signal) = timer_signal();
        {
            let mut wait = std::pin::pin!(scheduler.wait_for_timer(&missing));
            assert!(
                wait.as_mut()
                    .poll(&mut Context::from_waker(&old_waker))
                    .is_pending()
            );
        }
        assert!(scheduler.clock.is_none());
        let (new_waker, new_signal) = timer_signal();
        {
            let mut wait = std::pin::pin!(scheduler.wait_for_timer(&adopter));
            assert!(
                wait.as_mut()
                    .poll(&mut Context::from_waker(&new_waker))
                    .is_pending()
            );
        }
        let bound = scheduler.clock.as_ref().unwrap();
        assert!(bound.driver.ptr_eq(&driver));
        assert_eq!(bound.runtime_origin, crate::Time::from_secs(700));
        assert_eq!(driver.now(), crate::Time::from_secs(700));
        let due = scheduler.current_sleep.as_ref().unwrap().deadline();
        assert_eq!(
            due.as_nanos(),
            bound.runtime_origin.as_nanos()
                + u64::try_from(deadline.duration_since(bound.instant_origin).as_nanos()).unwrap()
        );
        let advance = due.as_nanos() - driver.now().as_nanos();
        assert!(advance > 0);
        assert_eq!(driver.pending_count(), 1);
        // Cross the retired wall-clock deadline while the adopted virtual clock
        // stays fixed. A leaked old registration would wake old_signal here.
        assert!(matches!(
            old_signal.recv_timeout(
                deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(50)
            ),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));
        assert!(matches!(
            new_signal.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
        clock.advance(advance - 1);
        assert_eq!(driver.process_timers(), 0);
        assert!(matches!(
            new_signal.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
        clock.advance(1);
        assert_eq!(driver.process_timers(), 1);
        new_signal
            .try_recv()
            .expect("adopted nonzero-epoch driver must wake the retained timer");
        assert_eq!(
            futures_lite::future::block_on(scheduler.wait_for_timer(&adopter)),
            Ok(Some(deadline))
        );
        assert_eq!(driver.pending_count(), 0);
        assert!(!scheduler.has_pending_timer());
        assert_eq!(scheduler.current_deadline(), None);
        println!(
            "quic_timer_public_adoption virtual_epoch_s=700 retired_fallback_wakes=0 early_virtual_firings=0 due_virtual_firings=1 pending_after=0"
        );
    }

    #[test]
    fn managed_timer_wrong_owner_keeps_pending_registration() {
        let (owner, clock, driver) = timer_test_context(crate::Time::from_secs(63));
        let (other, _, other_driver) = timer_test_context(crate::Time::from_secs(900));
        let missing = Cx::for_testing();
        let mut scheduler = QuicTimerScheduler::new();
        let start = scheduler.now(&owner).unwrap();
        let deadline = start + Duration::from_secs(2);
        futures_lite::future::block_on(scheduler.schedule_timer_bound(&owner, deadline)).unwrap();
        let (waker, signal) = timer_signal();
        assert!(
            scheduler
                .poll_timer(&mut Context::from_waker(&waker))
                .is_pending()
        );
        let registered = driver.next_deadline();
        assert_eq!(driver.pending_count(), 1);
        for refused in [&other, &missing] {
            for candidate in [
                deadline
                    .checked_sub(Duration::from_secs(1))
                    .expect("test deadline has one second of headroom"),
                deadline + Duration::from_secs(1),
            ] {
                assert!(matches!(
                    futures_lite::future::block_on(
                        scheduler.schedule_timer_bound(refused, candidate)
                    ),
                    Err(ConnectionRouterError::TimerSchedulingFailed(_))
                ));
                assert_eq!(driver.next_deadline(), registered);
                assert_eq!(driver.pending_count(), 1);
                assert_eq!(other_driver.pending_count(), 0);
            }
            assert!(matches!(
                scheduler.now(refused),
                Err(ConnectionRouterError::TimerSchedulingFailed(_))
            ));
        }
        assert!(matches!(
            signal.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
        clock.advance(1_999_999_999);
        assert_eq!(driver.process_timers(), 0);
        clock.advance(1);
        assert_eq!(driver.process_timers(), 1);
        signal
            .try_recv()
            .expect("refusals must retain the original timer's wake");
        assert_eq!(
            scheduler.poll_timer(&mut Context::from_waker(&waker)),
            Poll::Ready(Some(deadline))
        );
        scheduler.cancel_pending();
        assert_eq!(driver.pending_count(), 0);
        assert_eq!(scheduler.current_deadline(), None);
        assert!(scheduler.clock.as_ref().unwrap().driver.ptr_eq(&driver));
        assert!(matches!(
            futures_lite::future::block_on(scheduler.schedule_timer_bound(&other, deadline)),
            Err(ConnectionRouterError::TimerSchedulingFailed(_))
        ));
    }

    #[test]
    fn explicit_timer_cancellation_wakes_the_current_waiter_and_cleans_up_on_drop() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct Counter(AtomicUsize);
        impl std::task::Wake for Counter {
            fn wake(self: std::sync::Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let (cx, _, driver) = timer_test_context(crate::Time::from_secs(5));
        let mut scheduler = QuicTimerScheduler::new();
        let deadline = scheduler.now(&cx).unwrap() + Duration::from_secs(10);
        futures_lite::future::block_on(scheduler.schedule_timer(&cx, deadline)).unwrap();
        let first = std::sync::Arc::new(Counter(AtomicUsize::new(0)));
        let second = std::sync::Arc::new(Counter(AtomicUsize::new(0)));
        let first_waker = Waker::from(first.clone());
        let second_waker = Waker::from(second.clone());
        {
            let mut wait = std::pin::pin!(scheduler.wait_for_timer(&cx));
            assert!(
                wait.as_mut()
                    .poll(&mut Context::from_waker(&first_waker))
                    .is_pending()
            );
            assert!(
                wait.as_mut()
                    .poll(&mut Context::from_waker(&second_waker))
                    .is_pending()
            );
            cx.cancel_with(crate::types::CancelKind::User, None);
            assert_eq!(first.0.load(Ordering::SeqCst), 0);
            assert!(second.0.load(Ordering::SeqCst) > 0);
            assert_eq!(
                wait.as_mut().poll(&mut Context::from_waker(&second_waker)),
                Poll::Ready(Err(ConnectionRouterError::Cancelled))
            );
        }
        scheduler.cancel();
        assert_eq!(driver.pending_count(), 0);
    }

    fn encode_long_packet(
        dst_cid: ConnectionId,
        packet_type: LongPacketType,
        packet_number: u64,
        frame: QuicFrame,
    ) -> Vec<u8> {
        let mut payload = BytesMut::new();
        frame.encode(&mut payload).expect("frame encode");
        let header = PacketHeader::Long(LongHeader {
            packet_type,
            version: 1,
            dst_cid,
            src_cid: ConnectionId::new(&[0x01, 0x02, 0x03, 0x04]).expect("src cid"),
            token: Vec::new(),
            payload_length: payload.len() as u64 + 1,
            packet_number,
            packet_number_len: 1,
        });
        let mut out = Vec::new();
        header.encode(&mut out).expect("header encode");
        out.extend_from_slice(&payload);
        out
    }

    async fn deterministic_one_rtt_protection(cx: &Cx) -> AtpPacketProtection {
        let mut transcript = QuicHandshakeTranscript::new();
        transcript.record("client_initial", b"a1 client hello");
        transcript.record("server_handshake", b"a1 server hello");
        let mut protection =
            AtpPacketProtection::new_client(true).expect("deterministic ATP packet protection");
        protection
            .derive_keys(
                cx,
                PacketProtectionSpace::OneRtt,
                &transcript,
                b"asupersync a1 protected udp handoff",
            )
            .await
            .expect("derive 1-RTT keys");
        protection
    }

    #[test]
    fn managed_key_updates_require_acknowledgement_of_the_current_generation() {
        run_test_with_cx(|cx| async move {
            let cid = ConnectionId::new(b"key-acks").unwrap();
            let peer = "127.0.0.1:4460".parse().unwrap();
            let mut router = ConnectionRouter::new(NativeQuicConnectionConfig::default());
            add_protected_test_connection(&cx, &mut router, cid, peer).await;
            let handle = router.connections.get_mut(&cid).unwrap();
            handle
                .packet_protection
                .as_mut()
                .unwrap()
                .protection
                .set_key_update_confidentiality_threshold(2);

            // PN 0/1 use the initial key; PN 2 initiates generation one.
            // Matching peer phases, old ACKs, unsent ACKs, and other packet
            // spaces must not authorize the second update.
            for (pn, phase) in [
                (0, false),
                (1, false),
                (2, true),
                (3, true),
                (4, true),
                (5, true),
                (6, false),
                (7, false),
                (8, false),
                (9, true),
            ] {
                if pn == 4 {
                    handle.connection.on_peer_key_phase_pn(&cx, true, 0).unwrap();
                    handle.connection.on_ack_received(
                        &cx, PacketNumberSpace::ApplicationData, &[0, 999], 0, pn,
                    ).unwrap();
                    handle.connection.on_ack_received(
                        &cx, PacketNumberSpace::Handshake, &[2], 0, pn,
                    ).unwrap();
                }
                if pn == 6 || pn == 9 {
                    let acknowledged = if pn == 6 { 2 } else { 6 };
                    let ack = QuicFrame::Ack {
                        largest_acknowledged: VarInt::from_u64_unchecked(acknowledged),
                        ack_delay: VarInt::from_u64_unchecked(0),
                        ack_range_count: VarInt::from_u64_unchecked(0),
                        first_ack_range: VarInt::from_u64_unchecked(0),
                        ack_ranges: Vec::new(),
                        ecn_counts: None,
                    };
                    handle.connection.process_frame(
                        &cx, &ack, PacketNumberSpace::ApplicationData,
                    ).unwrap();
                }
                handle.connection.queue_ping(&cx).unwrap();
                let packets = drain_connection_frames(
                    &cx, cid, handle, PacketNumberSpace::ApplicationData, peer, Instant::now(), pn,
                ).await.unwrap();
                assert_eq!(packets.len(), 1, "packet {pn}");
                assert_eq!(handle.connection.tls().local_key_phase(), phase, "packet {pn}");
                assert_eq!(
                    handle.connection.next_packet_number_for_protection(
                        PacketNumberSpace::ApplicationData,
                    ).unwrap(),
                    pn + 1,
                );
                if matches!(pn, 2 | 6 | 9) {
                    assert_eq!(
                        handle.packet_protection.as_ref().unwrap().protection
                            .protected_packet_count(PacketProtectionSpace::OneRtt),
                        1,
                        "exactly one encryption under the new key",
                    );
                }
            }
        });
    }

    #[test]
    fn managed_key_update_waits_for_handshake_confirmation_before_ratcheting() {
        run_test_with_cx(|cx| async move {
            let cid = ConnectionId::new(b"key-hs").unwrap();
            let mut connection = NativeQuicConnection::new(NativeQuicConnectionConfig::default());
            connection.begin_handshake(&cx).unwrap();
            connection.on_handshake_keys_available(&cx).unwrap();
            connection.on_1rtt_keys_available(&cx).unwrap();
            connection.record_verified_server_identity();
            connection.on_authenticated_handshake_complete(&cx).unwrap();
            let mut protection = deterministic_one_rtt_protection(&cx).await;
            protection.set_key_update_confidentiality_threshold(1);
            protection.set_protected_packet_count_for_test(PacketProtectionSpace::OneRtt, 1);
            assert!(connection.can_send_1rtt());
            assert!(!connection.tls().handshake_confirmed());
            prepare_one_rtt_send_key(&cx, cid, &mut connection, &mut protection).unwrap();
            assert!(!connection.tls().local_key_phase());
            assert!(!protection.next_gen_keys_installed(PacketProtectionSpace::OneRtt, true));
            assert_eq!(protection.protected_packet_count(PacketProtectionSpace::OneRtt), 1);

            connection.on_handshake_confirmed(&cx).unwrap();
            prepare_one_rtt_send_key(&cx, cid, &mut connection, &mut protection).unwrap();
            assert!(connection.tls().local_key_phase());
            assert!(protection.next_gen_keys_installed(PacketProtectionSpace::OneRtt, true));
            assert_eq!(protection.protected_packet_count(PacketProtectionSpace::OneRtt), 0);
        });
    }

    #[test]
    fn managed_key_limit_closes_before_encrypting_application_probe_or_close() {
        run_test_with_cx(|cx| async move {
            for mode in ["application", "probe", "close"] {
                let cid = ConnectionId::new(b"key-limit").unwrap();
                let mut connection = NativeQuicConnection::new(NativeQuicConnectionConfig::default());
                establish_for_application_data(&cx, &mut connection);
                let mut protection = deterministic_one_rtt_protection(&cx).await;
                protection.set_key_update_confidentiality_threshold(1);
                protection.set_protected_packet_count_for_test(PacketProtectionSpace::OneRtt, 1);
                prepare_one_rtt_send_key(&cx, cid, &mut connection, &mut protection).unwrap();
                assert!(!connection.can_initiate_local_key_update());
                protection.set_protected_packet_count_for_test(PacketProtectionSpace::OneRtt, 1 << 23);
                let frames = if mode == "close" {
                    connection.begin_close(&cx, 0, 7).unwrap();
                    vec![QuicFrame::ConnectionClose {
                        error_code: VarInt::from_u64_unchecked(7),
                        frame_type: None,
                        reason_phrase: Bytes::new(),
                    }]
                } else {
                    vec![QuicFrame::Ping]
                };
                let mut payload = BytesMut::new();
                NativeQuicConnection::encode_frames(&frames, &mut payload).unwrap();
                let error = assemble_protected_1rtt_packet_inner(
                    &cx, cid, &mut connection, &mut protection, &frames, &payload, 0,
                    mode != "close", mode == "probe",
                ).await.unwrap_err();
                assert!(matches!(error, ConnectionRouterError::PacketProcessingFailed {
                    reason, ..
                } if reason.starts_with("AEAD_LIMIT_REACHED:")), "{mode}");
                assert_eq!(connection.state(), QuicConnectionState::Closed, "{mode}");
                assert_eq!(connection.transport().close_code(), Some(0x0f));
                assert_eq!(protection.protected_packet_count(PacketProtectionSpace::OneRtt), 1 << 23);
                assert_eq!(connection.next_packet_number_for_protection(
                    PacketNumberSpace::ApplicationData,
                ).unwrap(), 0, "refusal must not consume a packet number");
            }
        });
    }

    #[test]
    fn managed_key_limit_allows_the_last_packet_without_confirming_an_update() {
        run_test_with_cx(|cx| async move {
            let cid = ConnectionId::new(b"key-last").unwrap();
            let mut connection = NativeQuicConnection::new(NativeQuicConnectionConfig::default());
            establish_for_application_data(&cx, &mut connection);
            let mut protection = deterministic_one_rtt_protection(&cx).await;
            protection.set_key_update_confidentiality_threshold(1);
            protection.set_protected_packet_count_for_test(PacketProtectionSpace::OneRtt, 1);
            prepare_one_rtt_send_key(&cx, cid, &mut connection, &mut protection).unwrap();
            protection.set_protected_packet_count_for_test(PacketProtectionSpace::OneRtt, (1 << 23) - 1);
            let frames = [QuicFrame::Ping];
            let mut payload = BytesMut::new();
            NativeQuicConnection::encode_frames(&frames, &mut payload).unwrap();
            let packet = assemble_protected_1rtt_packet(
                &cx, cid, &mut connection, &mut protection, &frames, &payload, 0, true,
            ).await.unwrap();
            assert!(!packet.is_empty());
            assert!(connection.tls().local_key_phase());
            assert_eq!(protection.protected_packet_count(PacketProtectionSpace::OneRtt), 1 << 23);
            assert_eq!(connection.state(), QuicConnectionState::Established);
            assert!(!connection.can_initiate_local_key_update());
            let error = assemble_protected_1rtt_packet(
                &cx, cid, &mut connection, &mut protection, &frames, &payload, 1, true,
            ).await.unwrap_err();
            assert!(matches!(error, ConnectionRouterError::PacketProcessingFailed {
                reason, ..
            } if reason.starts_with("AEAD_LIMIT_REACHED:")));
            assert_eq!(connection.state(), QuicConnectionState::Closed);
            assert_eq!(protection.protected_packet_count(PacketProtectionSpace::OneRtt), 1 << 23);
        });
    }

    #[test]
    fn authenticated_handshake_ack_does_not_request_finished_retransmission() {
        run_test_with_cx(|cx| async move {
            let cid = ConnectionId::new(b"ack-peer").unwrap();
            let mut protection = deterministic_one_rtt_protection(&cx).await;
            let mut transcript = QuicHandshakeTranscript::new();
            transcript.record("handshake", b"ack classification");
            protection
                .derive_keys(
                    &cx,
                    PacketProtectionSpace::Handshake,
                    &transcript,
                    b"ack test",
                )
                .await
                .expect("derive handshake keys");
            for (number, frame, expected) in [
                (
                    1,
                    QuicFrame::Ack {
                        largest_acknowledged: VarInt::from_u64_unchecked(0),
                        ack_delay: VarInt::from_u64_unchecked(0),
                        ack_range_count: VarInt::from_u64_unchecked(0),
                        first_ack_range: VarInt::from_u64_unchecked(0),
                        ack_ranges: Vec::new(),
                        ecn_counts: None,
                    },
                    true,
                ),
                (
                    2,
                    QuicFrame::Crypto {
                        offset: VarInt::from_u64_unchecked(0),
                        data: Bytes::from_static(b"finished"),
                    },
                    false,
                ),
            ] {
                let mut payload = BytesMut::new();
                frame.encode(&mut payload).unwrap();
                let header = PacketHeader::Long(LongHeader {
                    packet_type: LongPacketType::Handshake,
                    version: 1,
                    dst_cid: cid,
                    src_cid: cid,
                    token: Vec::new(),
                    payload_length: 4 + payload.len() as u64 + 16,
                    packet_number: number,
                    packet_number_len: 4,
                });
                let mut packet = Vec::new();
                header.encode(&mut packet).unwrap();
                let associated_data = packet.clone();
                let offset = packet.len() - 4;
                let protected = protection
                    .protect_packet_now(
                        &cx,
                        PacketProtectionRequest {
                            space: PacketProtectionSpace::Handshake,
                            key_phase: false,
                            packet_number: number,
                            associated_data: &packet,
                            payload: &payload,
                        },
                    )
                    .expect("protect");
                packet.extend_from_slice(&protected.ciphertext);
                packet.extend_from_slice(&protected.tag);
                let sample = header_protection_sample(&packet, offset).unwrap();
                let mask = protection
                    .header_protection_mask_now(&cx, PacketProtectionSpace::Handshake, &sample)
                    .expect("mask");
                apply_header_protection(&mut packet, offset, mask.bytes).unwrap();
                let mut forged = packet.clone();
                *forged.last_mut().unwrap() ^= 1;
                assert!(!authenticated_handshake_ack_only(
                    &cx,
                    cid,
                    &mut protection,
                    &forged
                ));
                assert!(!authenticated_handshake_ack_only(
                    &cx,
                    ConnectionId::new(b"wrongcid").unwrap(),
                    &mut protection,
                    &packet
                ));
                assert_eq!(
                    authenticated_handshake_ack_only(&cx, cid, &mut protection, &packet),
                    expected
                );
                // An exact replay must retain its authenticated frame class:
                // ACKs stay silent, while CRYPTO still requests recovery.
                assert_eq!(
                    authenticated_handshake_ack_only(&cx, cid, &mut protection, &packet),
                    expected
                );
                assert!(!authenticated_handshake_ack_only(
                    &cx,
                    cid,
                    &mut protection,
                    &forged
                ));
                // Inspection never grants delivery admission for a replay.
                assert!(matches!(
                    protection.unprotect_packet_now(&cx, &protected, &associated_data),
                    Outcome::Err(crate::net::atp::protocol::outcome::AtpError::Auth(
                        crate::net::atp::protocol::outcome::AuthError::ReplayedNonce
                    ))
                ));
                let mut wrong_space = protected.clone();
                wrong_space.space = PacketProtectionSpace::OneRtt;
                assert!(matches!(
                    protection.inspect_handshake_packet_now(&cx, &wrong_space, &associated_data),
                    Outcome::Err(crate::net::atp::protocol::outcome::AtpError::Protocol(
                        crate::net::atp::protocol::outcome::ProtocolError::SessionStateMismatch
                    ))
                ));
            }
        });
    }

    async fn add_protected_test_connection(
        cx: &Cx,
        router: &mut ConnectionRouter,
        cid: ConnectionId,
        peer: SocketAddr,
    ) {
        router
            .create_connection(cx, cid, peer, false)
            .await
            .unwrap();
        router
            .install_packet_protection(cx, cid, deterministic_one_rtt_protection(cx).await)
            .unwrap();
        establish_for_application_data(
            cx,
            &mut router.connections.get_mut(&cid).unwrap().connection,
        );
    }

    #[test]
    fn lifecycle_reaping_rejected_packets_and_repeated_sends_do_not_extend_idle() {
        run_test_with_cx(|cx| async move {
            let mut router = ConnectionRouter::new(NativeQuicConnectionConfig::default());
            router.set_idle_timeout_micros(10_000_000);
            let cid = ConnectionId::new(b"activity").unwrap();
            let peer = "127.0.0.1:4450".parse().unwrap();
            add_protected_test_connection(&cx, &mut router, cid, peer).await;
            let origin = router.clock_origin;
            router.connections.get_mut(&cid).unwrap().last_activity = origin;
            let mut sender = NativeQuicConnection::new(NativeQuicConnectionConfig::default());
            establish_for_application_data(&cx, &mut sender);
            let mut protection = deterministic_one_rtt_protection(&cx).await;
            let frames = [QuicFrame::Ping];
            let mut payload = BytesMut::new();
            NativeQuicConnection::encode_frames(&frames, &mut payload).unwrap();
            let ciphertext = assemble_protected_1rtt_packet(
                &cx,
                cid,
                &mut sender,
                &mut protection,
                &frames,
                &payload,
                2_000_000,
                true,
            )
            .await
            .unwrap();
            let packet = ReceivedPacket {
                src_addr: peer,
                data: ciphertext,
                receive_time: origin + Duration::from_secs(2),
                transmit_time: None,
            };
            let mut damaged = packet.clone();
            *damaged.data.last_mut().unwrap() ^= 1;
            assert!(
                router
                    .route_packet_with_output(&cx, damaged, false)
                    .await
                    .is_err()
            );
            assert_eq!(
                router.next_timer_deadline(),
                Some(origin + Duration::from_secs(10))
            );
            assert!(matches!(
                router
                    .route_packet_with_output(&cx, packet.clone(), false)
                    .await
                    .unwrap(),
                RoutingResult::Routed { .. }
            ));
            assert_eq!(
                router.next_timer_deadline(),
                Some(origin + Duration::from_secs(12))
            );
            let mut outgoing = RoutedOutgoingPacket {
                connection_id: cid,
                packet: OutgoingPacket {
                    dst_addr: peer,
                    data: vec![0],
                    send_time: None,
                },
                final_handshake_flight: false,
                ack_eliciting: false,
            };
            router.packet_sent(&outgoing, Some(origin + Duration::from_secs(3)));
            assert_eq!(
                router.next_timer_deadline(),
                Some(origin + Duration::from_secs(12))
            );
            outgoing.ack_eliciting = true;
            router.packet_sent(&outgoing, Some(origin + Duration::from_secs(4)));
            router.packet_sent(&outgoing, Some(origin + Duration::from_secs(8)));
            assert_eq!(
                router.next_timer_deadline(),
                Some(origin + Duration::from_secs(14))
            );
            let mut replay = packet;
            replay.receive_time = origin + Duration::from_secs(9);
            assert!(
                router
                    .route_packet_with_output(&cx, replay, false)
                    .await
                    .is_err()
            );
            assert_eq!(
                router.next_timer_deadline(),
                Some(origin + Duration::from_secs(14))
            );
            assert!(
                router
                    .process_timer_events(&cx, origin + Duration::from_secs(14))
                    .await
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(router.connection_stats().active_connections, 0);
        });
    }

    #[cfg(feature = "tls")]
    #[test]
    fn lifecycle_reaping_negotiation_cannot_extend_the_local_idle_limit() {
        run_test_with_cx(|cx| async move {
            let mut router = ConnectionRouter::new(NativeQuicConnectionConfig::default());
            router.set_idle_timeout_micros(10_000_000);
            let cid = ConnectionId::new(b"idle-cap").unwrap();
            add_protected_test_connection(&cx, &mut router, cid, "127.0.0.1:4450".parse().unwrap())
                .await;
            let origin = router.clock_origin;
            let local = crate::net::quic_core::TransportParameters::default();
            let mut peer = crate::net::quic_core::TransportParameters {
                max_idle_timeout: Some(120_000),
                ..crate::net::quic_core::TransportParameters::default()
            };
            let handle = router.connections.get_mut(&cid).unwrap();
            handle.last_activity = origin;
            handle.connection.set_negotiated_idle_timeout(&local, &peer);
            assert_eq!(
                router.next_timer_deadline(),
                Some(origin + Duration::from_secs(10)),
                "a long peer timeout must not bypass the configured local limit"
            );
            router.set_idle_timeout_micros(0);
            assert_eq!(
                router.next_timer_deadline(),
                Some(origin + Duration::from_secs(120)),
                "disabling the local limit still honors a finite peer timeout"
            );
            router.set_idle_timeout_micros(10_000_000);
            peer.max_idle_timeout = Some(5_000);
            router
                .connections
                .get_mut(&cid)
                .unwrap()
                .connection
                .set_negotiated_idle_timeout(&local, &peer);
            assert_eq!(
                router.next_timer_deadline(),
                Some(origin + Duration::from_secs(5)),
                "a shorter negotiated timeout must still win"
            );
            peer.max_idle_timeout = Some(0);
            router
                .connections
                .get_mut(&cid)
                .unwrap()
                .connection
                .set_negotiated_idle_timeout(&local, &peer);
            assert_eq!(
                router.next_timer_deadline(),
                Some(origin + Duration::from_secs(10))
            );
            router.set_idle_timeout_micros(0);
            assert!(router.next_timer_deadline().is_none());
        });
    }

    #[test]
    fn lifecycle_reaping_pto_backoff_and_queued_probes_cannot_keep_a_peer_alive() {
        run_test_with_cx(|cx| async move {
            let mut router = ConnectionRouter::new(NativeQuicConnectionConfig::default());
            router.set_idle_timeout_micros(1);
            let cid = ConnectionId::new(b"lostpeer").unwrap();
            let peer = "127.0.0.1:4450".parse().unwrap();
            add_protected_test_connection(&cx, &mut router, cid, peer).await;
            let origin = router.clock_origin;
            let handle = router.connections.get_mut(&cid).unwrap();
            handle.last_activity = origin;
            let floor = handle.connection.transport().idle_timeout_floor_micros();
            assert!(floor > 2_000_000);
            handle
                .connection
                .on_packet_sent(
                    &cx,
                    PacketNumberSpace::ApplicationData,
                    1_200,
                    true,
                    true,
                    0,
                )
                .unwrap();
            ConnectionRouter::refresh_connection_timer(&cx, cid, handle, origin, 0, origin)
                .unwrap();
            let mut probes = 0;
            while let Some(deadline) = router.next_timer_deadline() {
                let packets = router
                    .process_managed_timer_events(&cx, deadline, &HashSet::new())
                    .await
                    .unwrap();
                for packet in packets {
                    assert!(packet.ack_eliciting);
                    router.packet_sent(&packet, Some(deadline));
                    probes += 1;
                }
                if let Some(handle) = router.connections.get(&cid) {
                    assert_eq!(
                        handle.connection.transport().idle_timeout_floor_micros(),
                        floor
                    );
                    assert!(deadline < origin + Duration::from_secs(5));
                }
                assert!(probes < 4, "repeated PTO must give way to idle expiry");
            }
            assert!(probes > 0);
            assert_eq!(router.connection_stats().active_connections, 0);
        });
    }

    #[test]
    fn lifecycle_reaping_draining_connection_releases_capacity_at_its_deadline() {
        run_test_with_cx(|cx| async move {
            let mut router =
                ConnectionRouter::with_max_connections(NativeQuicConnectionConfig::default(), 1);
            let cid = ConnectionId::new(b"expired").unwrap();
            let replacement = ConnectionId::new(b"new-peer").unwrap();
            let peer = "127.0.0.1:4450".parse().unwrap();
            add_protected_test_connection(&cx, &mut router, cid, peer).await;
            let origin = router.clock_origin;
            router
                .connections
                .get_mut(&cid)
                .unwrap()
                .connection
                .begin_close(&cx, 1_000, 0x17)
                .unwrap();
            let deadline = origin + Duration::from_micros(3_001_000);
            assert_eq!(router.next_timer_deadline(), Some(deadline));
            assert!(
                router
                    .create_connection(&cx, replacement, peer, false)
                    .await
                    .is_err()
            );
            let just_before_deadline = deadline.checked_sub(Duration::from_micros(1)).unwrap();
            assert!(
                router
                    .process_timer_events(&cx, just_before_deadline)
                    .await
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(router.connection_stats().active_connections, 1);
            assert!(
                router
                    .process_timer_events(&cx, deadline)
                    .await
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(router.connection_stats().active_connections, 0);
            assert!(router.next_timer_deadline().is_none());
            router
                .create_connection(&cx, replacement, peer, false)
                .await
                .unwrap();
            assert_eq!(router.connection_stats().active_connections, 1);
        });
    }

    #[test]
    fn lifecycle_reaping_closed_connection_needs_no_recovery_flight() {
        run_test_with_cx(|cx| async move {
            let mut router = ConnectionRouter::new(NativeQuicConnectionConfig::default());
            let cid = ConnectionId::new(b"closed").unwrap();
            add_protected_test_connection(&cx, &mut router, cid, "127.0.0.1:4450".parse().unwrap())
                .await;
            router
                .connections
                .get_mut(&cid)
                .unwrap()
                .connection
                .close_immediately(&cx, 0x18)
                .unwrap();
            assert!(router.next_timer_deadline().is_some());
            assert!(
                router
                    .process_timer_events(&cx, Instant::now())
                    .await
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(router.connection_stats().active_connections, 0);
        });
    }

    #[cfg(feature = "tls")]
    #[test]
    fn authenticated_input_commits_all_frames_when_stream_wake_requests_cancel() {
        struct CancelOnReadable {
            cx: Cx,
            calls: std::sync::atomic::AtomicUsize,
        }
        impl std::task::Wake for CancelOnReadable {
            fn wake(self: std::sync::Arc<Self>) {
                self.wake_by_ref();
            }
            fn wake_by_ref(self: &std::sync::Arc<Self>) {
                self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                self.cx.cancel_with(crate::types::CancelKind::User, None);
            }
        }
        run_test_with_cx(|cx| async move {
            let observer = Cx::for_testing();
            let config = NativeQuicConnectionConfig::default();
            let mut receiver = ConnectionRouter::new(config);
            let cid = ConnectionId::new(b"receive").unwrap();
            let peer_cid = ConnectionId::new(b"other-cid").unwrap();
            let peer: SocketAddr = "127.0.0.1:4459".parse().unwrap();
            add_protected_test_connection(&cx, &mut receiver, cid, peer).await;
            // This deliberately establishes unit state and fixture keys. It
            // tests the real imported-input transaction, not TLS authentication.
            let origin = receiver.clock_origin;
            let handle = receiver.connections.get_mut(&cid).unwrap();
            let mut application = super::super::QuicConnection::client(config);
            establish_for_application_data(&cx, application.inner_mut());
            handle.connection = RoutedConnection::Authenticated(application);
            handle.peer_connection_id = Some(peer_cid);
            handle.clock_origin = Some(origin);
            handle.authenticated = Some(AuthenticatedRouting {
                negotiated_alpn: b"h3".to_vec(),
                final_handshake_flight: Vec::new(),
                last_final_flight_retransmit: None,
                pending_final_flight_packets: 0,
            });
            let wake = std::sync::Arc::new(CancelOnReadable {
                cx: cx.clone(),
                calls: std::sync::atomic::AtomicUsize::new(0),
            });
            let waker = Waker::from(std::sync::Arc::clone(&wake));
            assert!(
                handle
                    .connection
                    .poll_next_readable_stream(&cx, &mut Context::from_waker(&waker),)
                    .is_pending()
            );
            let frames = [
                QuicFrame::Stream {
                    stream_id: crate::net::VarInt(1),
                    offset: None,
                    data: Bytes::from_static(b"first"),
                    fin: false,
                },
                QuicFrame::Stream {
                    stream_id: crate::net::VarInt(1),
                    offset: Some(crate::net::VarInt(5)),
                    data: Bytes::from_static(b"-last"),
                    fin: true,
                },
            ];
            let mut payload = BytesMut::new();
            NativeQuicConnection::encode_frames(&frames, &mut payload).unwrap();
            let mut sender = NativeQuicConnection::new(config);
            establish_for_application_data(&cx, &mut sender);
            let mut sender_protection = deterministic_one_rtt_protection(&cx).await;
            let data = assemble_protected_1rtt_packet(
                &cx,
                cid,
                &mut sender,
                &mut sender_protection,
                &frames,
                &payload,
                13_000,
                true,
            )
            .await
            .unwrap();
            let packet = ReceivedPacket {
                src_addr: peer,
                data,
                receive_time: origin + Duration::from_micros(13_000),
                transmit_time: None,
            };
            assert!(
                matches!(receiver.route_packet_with_output(&cx, packet.clone(), true).await,
                Ok(RoutingResult::Routed { connection_id, outgoing_packets })
                    if connection_id == cid && outgoing_packets.is_empty())
            );
            assert!(
                wake.calls.load(std::sync::atomic::Ordering::SeqCst) > 0,
                "first STREAM frame must invoke the registered cancelling waker"
            );
            assert!(
                cx.checkpoint().is_err(),
                "cancel is visible after bounded commitment"
            );
            let handle = receiver.connections.get_mut(&cid).unwrap();
            assert!(
                handle.deferred_spaces[2],
                "ACK/control output remains owned"
            );
            let stream = crate::net::quic_native::StreamId(1);
            let readiness = handle
                .connection
                .next_readable_stream(&observer)
                .unwrap()
                .expect("both authenticated STREAM frames are committed before cancellation");
            assert_eq!(readiness.stream_id, stream);
            assert_eq!(readiness.readable_bytes, 10);
            assert!(readiness.fin_received);
            assert_eq!(readiness.reset, None);
            assert_eq!(readiness.receive_stopped, None);
            // Reads return the committed bytes in one or more chunks; small
            // frames may already be joined (asupersync-4gdidf). Drain all ten
            // without routing another packet or polling I/O.
            let mut received = Vec::new();
            while received.len() < 10 {
                let bytes = handle
                    .connection
                    .read_stream_bytes(&observer, stream, 32)
                    .unwrap();
                assert!(!bytes.is_empty(), "committed bytes stay readable");
                received.extend_from_slice(&bytes);
            }
            assert_eq!(received.as_slice(), b"first-last");
            assert!(
                handle
                    .connection
                    .read_stream_bytes(&observer, stream, 32)
                    .unwrap()
                    .is_empty()
            );
            assert!(
                matches!(receiver.route_packet_with_output(&observer, packet, false).await,
                Err(ConnectionRouterError::PacketProcessingFailed { reason, .. })
                    if reason.contains("ReplayedNonce")),
                "the fully committed packet is accepted by the replay window exactly once"
            );
        });
    }

    #[cfg(feature = "tls")]
    async fn add_authenticated_close_test_connection(
        cx: &Cx,
        router: &mut ConnectionRouter,
        cid: ConnectionId,
        peer_cid: ConnectionId,
        peer: SocketAddr,
        origin: Instant,
    ) {
        add_protected_test_connection(cx, router, cid, peer).await;
        // Synthetic authenticated-owner state and deterministic fixture keys
        // exercise close ownership, protection and timing. Real TLS admission
        // is covered by the live UDP tests, not by this unit fixture.
        let mut application = super::super::QuicConnection::client(router.config_template);
        establish_for_application_data(cx, application.inner_mut());
        let handle = router.connections.get_mut(&cid).unwrap();
        handle.connection = RoutedConnection::Authenticated(application);
        handle.peer_connection_id = Some(peer_cid);
        handle.clock_origin = Some(origin);
        handle.last_activity = origin;
        handle.established_at = Some(origin);
        handle.deferred_spaces = [false; 3];
        handle.authenticated = Some(AuthenticatedRouting {
            negotiated_alpn: b"h3".to_vec(),
            final_handshake_flight: Vec::new(),
            last_final_flight_retransmit: None,
            pending_final_flight_packets: 0,
        });
    }

    #[cfg(feature = "tls")]
    #[test]
    fn authenticated_close_waits_for_buffered_output_and_acknowledged_flight() {
        run_test_with_cx(|cx| async move {
            let mut router = ConnectionRouter::new(NativeQuicConnectionConfig::default());
            let cid = ConnectionId::new(b"closing").unwrap();
            let peer_cid = ConnectionId::new(b"close-peer").unwrap();
            let peer = "127.0.0.1:4490".parse().unwrap();
            let origin = router.clock_origin;
            let now = origin + Duration::from_secs(1);
            add_authenticated_close_test_connection(&cx, &mut router, cid, peer_cid, peer, origin)
                .await;
            let stream = router
                .connections
                .get_mut(&cid)
                .unwrap()
                .connection
                .open_local_bidi(&cx)
                .unwrap();
            router
                .connections
                .get_mut(&cid)
                .unwrap()
                .connection
                .write_stream_bytes(
                    &cx,
                    stream,
                    Bytes::from_static(b"keep this response"),
                    false,
                )
                .unwrap();

            assert!(matches!(
                router.request_authenticated_close(&cx, cid, now, u64::MAX, true),
                Err(ConnectionRouterError::InvalidConnectionState { connection_id, .. })
                    if connection_id == cid
            ));
            let cancelled = Cx::for_testing();
            cancelled.set_cancel_requested(true);
            assert!(matches!(
                router.request_authenticated_close(&cancelled, cid, now, 42, true),
                Err(ConnectionRouterError::Cancelled)
            ));
            assert!(
                !router
                    .request_authenticated_close(&cx, cid, now, 42, false)
                    .unwrap()
            );
            let handle = router.connections.get_mut(&cid).unwrap();
            assert_eq!(handle.connection.state(), QuicConnectionState::Established);
            assert_eq!(handle.connection.transport().close_code(), None);
            assert_eq!(handle.local_close_output, None);
            assert_eq!(handle.connection.pending_stream_data_bytes(), 18);
            let frames = handle
                .connection
                .generate_frames(&cx, PacketNumberSpace::ApplicationData, 1200)
                .unwrap();
            assert!(frames.iter().any(|frame| matches!(frame,
                QuicFrame::Stream { data, .. } if data.as_ref() == b"keep this response"
            )));
            assert!(!handle.connection.has_pending_stream_frames());

            // Control output alone must also finish before graceful retirement.
            handle.connection.queue_ping(&cx).unwrap();
            assert!(
                !router
                    .request_authenticated_close(&cx, cid, now, 42, false)
                    .unwrap()
            );
            let handle = router.connections.get_mut(&cid).unwrap();
            assert!(handle.connection.has_pending_control_frames());
            assert_eq!(
                handle
                    .connection
                    .generate_frames(&cx, PacketNumberSpace::ApplicationData, 1200,)
                    .unwrap(),
                vec![QuicFrame::Ping]
            );

            handle
                .connection
                .send_datagram(&cx, Bytes::from_static(b"queued datagram"))
                .unwrap();
            assert!(
                !router
                    .request_authenticated_close(&cx, cid, now, 42, false)
                    .unwrap()
            );
            let handle = router.connections.get_mut(&cid).unwrap();
            assert_eq!(handle.connection.pending_outbound_datagram_count(), 1);
            assert_eq!(
                handle
                    .connection
                    .generate_frames(&cx, PacketNumberSpace::ApplicationData, 1200,)
                    .unwrap(),
                vec![QuicFrame::Datagram {
                    data: Bytes::from_static(b"queued datagram")
                }]
            );

            for timer_queue in [true, false] {
                let packet = RoutedOutgoingPacket {
                    connection_id: cid,
                    packet: OutgoingPacket {
                        dst_addr: peer,
                        data: b"already protected output".to_vec(),
                        send_time: Some(now),
                    },
                    final_handshake_flight: false,
                    ack_eliciting: true,
                };
                if timer_queue {
                    router.pending_timer_packets.push(packet);
                } else {
                    router.pending_deferred_packets.push(packet);
                }
                assert_eq!(router.pending_datagram_count_for(cid), 1);
                assert!(
                    !router
                        .request_authenticated_close(&cx, cid, now, 42, false)
                        .unwrap()
                );
                assert_eq!(router.pending_datagram_count_for(cid), 1);
                let retained = if timer_queue {
                    router.pending_timer_packets.pop().unwrap()
                } else {
                    router.pending_deferred_packets.pop().unwrap()
                };
                assert_eq!(retained.packet.data, b"already protected output");
                assert_eq!(retained.packet.send_time, Some(now));
            }

            // A frame leaving every local queue is still outstanding until the
            // peer acknowledges its transport packet.
            let packet_number = router
                .connections
                .get_mut(&cid)
                .unwrap()
                .connection
                .on_packet_sent(
                    &cx,
                    PacketNumberSpace::ApplicationData,
                    1200,
                    true,
                    true,
                    900_000,
                )
                .unwrap();
            assert!(
                !router
                    .request_authenticated_close(&cx, cid, now, 42, false)
                    .unwrap()
            );
            let handle = router.connections.get_mut(&cid).unwrap();
            assert_eq!(handle.connection.transport().bytes_in_flight(), 1200);
            assert_eq!(handle.connection.state(), QuicConnectionState::Established);
            handle
                .connection
                .on_ack_received(
                    &cx,
                    PacketNumberSpace::ApplicationData,
                    &[packet_number],
                    0,
                    1_000_000,
                )
                .unwrap();
            assert_eq!(handle.connection.transport().bytes_in_flight(), 0);
            assert!(
                router
                    .request_authenticated_close(&cx, cid, now, 42, false)
                    .unwrap()
            );
            assert_eq!(
                router.connections[&cid].local_close_output,
                Some(LocalCloseOutput::Requested)
            );
        });
    }

    /// br-asupersync-tzjbn9 F3: the managed endpoint logged a peer's stream
    /// violation and kept the connection open, with the packet partly applied
    /// and unacknowledged, so every retransmission failed again. The route now
    /// closes with the transport code, and the next deferred-output turn sends
    /// the transport CONNECTION_CLOSE that names the frame type.
    #[cfg(feature = "tls")]
    #[test]
    fn authenticated_peer_flow_control_violation_sends_a_transport_close() {
        run_test_with_cx(|cx| async move {
            let config = NativeQuicConnectionConfig::default();
            let mut router = ConnectionRouter::new(config);
            let cid = ConnectionId::new(b"violated").unwrap();
            let peer_cid = ConnectionId::new(b"violator").unwrap();
            let peer = "127.0.0.1:4493".parse().unwrap();
            let origin = router.clock_origin;
            add_authenticated_close_test_connection(&cx, &mut router, cid, peer_cid, peer, origin)
                .await;
            // Past both the stream and the connection receive limits.
            let frames = [QuicFrame::Stream {
                stream_id: VarInt(1),
                offset: Some(VarInt(config.recv_window.max(config.connection_recv_limit))),
                data: Bytes::from_static(b"x"),
                fin: false,
            }];
            let mut payload = BytesMut::new();
            NativeQuicConnection::encode_frames(&frames, &mut payload).unwrap();
            let mut sender = NativeQuicConnection::new(config);
            establish_for_application_data(&cx, &mut sender);
            let mut sender_protection = deterministic_one_rtt_protection(&cx).await;
            let data = assemble_protected_1rtt_packet(
                &cx,
                cid,
                &mut sender,
                &mut sender_protection,
                &frames,
                &payload,
                1_000,
                true,
            )
            .await
            .unwrap();
            let now = origin + Duration::from_millis(1);
            let packet = ReceivedPacket {
                src_addr: peer,
                data,
                receive_time: now,
                transmit_time: None,
            };
            assert!(matches!(
                router.route_packet_with_output(&cx, packet, true).await,
                Err(ConnectionRouterError::PacketProcessingFailed { .. })
            ));
            let handle = &router.connections[&cid];
            assert_eq!(handle.connection.state(), QuicConnectionState::Draining);
            assert_eq!(handle.connection.transport().close_code(), Some(0x03));

            let packets = router.drain_deferred_output(&cx, now, 8).await.unwrap();
            assert_eq!(packets.len(), 1, "only the close leaves");
            assert_eq!(packets[0].packet.dst_addr, peer);
            let mut verifier = deterministic_one_rtt_protection(&cx).await;
            let decoded =
                unprotect_1rtt_packet(&cx, peer_cid, &mut verifier, &packets[0].packet.data)
                    .await
                    .unwrap();
            assert_eq!(
                NativeQuicConnection::decode_frames(&decoded.plaintext).unwrap(),
                vec![QuicFrame::ConnectionClose {
                    error_code: VarInt(0x03),
                    frame_type: Some(VarInt(0x0c)),
                    reason_phrase: Bytes::new(),
                }],
                "FLOW_CONTROL_ERROR for a STREAM frame with an offset"
            );
        });
    }

    /// Review r29-e8 of 168379675 (H1): a peer that still holds Handshake keys
    /// coalesces `[Handshake(ACK)][1-RTT(STREAM)]` in one datagram (RFC 9000
    /// section 12.2), as mainstream stacks do until HANDSHAKE_DONE. The router
    /// adopted the 1-RTT tail but kept the leading long header's Handshake
    /// packet-number space, so the STREAM frame broke RFC 9000 section 12.4:
    /// on the broken code the route returns `Err(PacketProcessingFailed)` and
    /// the connection closes with PROTOCOL_VIOLATION. The tail belongs to
    /// ApplicationData: its data is delivered and only that space owes output.
    #[cfg(feature = "tls")]
    #[test]
    fn authenticated_coalesced_one_rtt_tail_is_processed_in_application_data_space() {
        run_test_with_cx(|cx| async move {
            let config = NativeQuicConnectionConfig::default();
            let mut router = ConnectionRouter::new(config);
            let cid = ConnectionId::new(b"coalesce").unwrap();
            let peer_cid = ConnectionId::new(b"coal-peer").unwrap();
            let peer = "127.0.0.1:4494".parse().unwrap();
            let origin = router.clock_origin;
            add_authenticated_close_test_connection(&cx, &mut router, cid, peer_cid, peer, origin)
                .await;

            // The leading packet is a sealed Handshake ACK. The router never
            // authenticates it: only its Length field bounds the 1-RTT tail.
            let mut handshake_protection = deterministic_one_rtt_protection(&cx).await;
            let mut transcript = QuicHandshakeTranscript::new();
            transcript.record("handshake", b"coalesced 1-RTT tail");
            handshake_protection
                .derive_keys(
                    &cx,
                    PacketProtectionSpace::Handshake,
                    &transcript,
                    b"coalesced test",
                )
                .await
                .expect("derive handshake keys");
            let mut ack = BytesMut::new();
            QuicFrame::Ack {
                largest_acknowledged: VarInt::from_u64_unchecked(0),
                ack_delay: VarInt::from_u64_unchecked(0),
                ack_range_count: VarInt::from_u64_unchecked(0),
                first_ack_range: VarInt::from_u64_unchecked(0),
                ack_ranges: Vec::new(),
                ecn_counts: None,
            }
            .encode(&mut ack)
            .unwrap();
            let header = PacketHeader::Long(LongHeader {
                packet_type: LongPacketType::Handshake,
                version: 1,
                dst_cid: cid,
                src_cid: peer_cid,
                token: Vec::new(),
                payload_length: 4 + ack.len() as u64 + 16,
                packet_number: 0,
                packet_number_len: 4,
            });
            let mut datagram = Vec::new();
            header.encode(&mut datagram).unwrap();
            let offset = datagram.len() - 4;
            let sealed = handshake_protection
                .protect_packet_now(
                    &cx,
                    PacketProtectionRequest {
                        space: PacketProtectionSpace::Handshake,
                        key_phase: false,
                        packet_number: 0,
                        associated_data: &datagram,
                        payload: &ack,
                    },
                )
                .expect("protect");
            datagram.extend_from_slice(&sealed.ciphertext);
            datagram.extend_from_slice(&sealed.tag);
            let sample = header_protection_sample(&datagram, offset).unwrap();
            let mask = handshake_protection
                .header_protection_mask_now(&cx, PacketProtectionSpace::Handshake, &sample)
                .expect("mask");
            apply_header_protection(&mut datagram, offset, mask.bytes).unwrap();

            // The coalesced tail: a genuine 1-RTT packet with application data.
            let frames = [QuicFrame::Stream {
                stream_id: VarInt(1),
                offset: None,
                data: Bytes::from_static(b"x"),
                fin: false,
            }];
            let mut payload = BytesMut::new();
            NativeQuicConnection::encode_frames(&frames, &mut payload).unwrap();
            let mut sender = NativeQuicConnection::new(config);
            establish_for_application_data(&cx, &mut sender);
            let mut sender_protection = deterministic_one_rtt_protection(&cx).await;
            let tail = assemble_protected_1rtt_packet(
                &cx,
                cid,
                &mut sender,
                &mut sender_protection,
                &frames,
                &payload,
                1_000,
                true,
            )
            .await
            .unwrap();
            datagram.extend_from_slice(&tail);

            let packet = ReceivedPacket {
                src_addr: peer,
                data: datagram,
                receive_time: origin + Duration::from_millis(1),
                transmit_time: None,
            };
            match router.route_packet_with_output(&cx, packet, true).await {
                Ok(RoutingResult::Routed {
                    connection_id,
                    outgoing_packets,
                }) => {
                    assert_eq!(connection_id, cid);
                    assert!(outgoing_packets.is_empty());
                }
                other => panic!("the coalesced 1-RTT packet must be processed: {other:?}"),
            }
            let handle = router.connections.get_mut(&cid).unwrap();
            assert_eq!(handle.connection.state(), QuicConnectionState::Established);
            assert_eq!(handle.connection.transport().close_code(), None);
            assert_eq!(
                handle.deferred_spaces,
                [false, false, true],
                "the tail's ACK is owed in ApplicationData, never in Handshake"
            );
            let stream = crate::net::quic_native::StreamId(1);
            let readiness = handle
                .connection
                .next_readable_stream(&cx)
                .unwrap()
                .expect("the coalesced STREAM frame is delivered");
            assert_eq!(readiness.stream_id, stream);
            assert_eq!(
                handle
                    .connection
                    .read_stream_bytes(&cx, stream, 32)
                    .unwrap(),
                Bytes::from_static(b"x")
            );
        });
    }

    /// Seal one Handshake packet under fixture keys.
    #[cfg(feature = "tls")]
    fn seal_handshake_packet(
        cx: &Cx,
        protection: &mut AtpPacketProtection,
        dst_cid: ConnectionId,
        src_cid: ConnectionId,
        packet_number: u64,
        frame: &QuicFrame,
    ) -> Vec<u8> {
        let mut payload = BytesMut::new();
        frame.encode(&mut payload).unwrap();
        let header = PacketHeader::Long(LongHeader {
            packet_type: LongPacketType::Handshake,
            version: 1,
            dst_cid,
            src_cid,
            token: Vec::new(),
            payload_length: 4 + payload.len() as u64 + 16,
            packet_number,
            packet_number_len: 4,
        });
        let mut packet = Vec::new();
        header.encode(&mut packet).unwrap();
        let offset = packet.len() - 4;
        let sealed = protection
            .protect_packet_now(
                cx,
                PacketProtectionRequest {
                    space: PacketProtectionSpace::Handshake,
                    key_phase: false,
                    packet_number,
                    associated_data: &packet,
                    payload: &payload,
                },
            )
            .expect("protect");
        packet.extend_from_slice(&sealed.ciphertext);
        packet.extend_from_slice(&sealed.tag);
        let sample = header_protection_sample(&packet, offset).unwrap();
        let mask = protection
            .header_protection_mask_now(cx, PacketProtectionSpace::Handshake, &sample)
            .expect("mask");
        apply_header_protection(&mut packet, offset, mask.bytes).unwrap();
        packet
    }

    /// br-asupersync-1r3f5u L2/L4: each long-header packet of a datagram is
    /// classified on its own, bounded by its Length field, and a 1-RTT tail
    /// after any number of them is processed. A peer that still holds
    /// Handshake keys sends [Handshake(ACK)][1-RTT]; that requests no
    /// final-flight retransmission, nor does trailing padding. A Handshake
    /// packet carrying more than ACKs still requests it, and a tail for
    /// another connection is ignored.
    #[cfg(feature = "tls")]
    #[test]
    fn authenticated_coalesced_long_header_packets_are_classified_one_by_one() {
        run_test_with_cx(|cx| async move {
            let ack = QuicFrame::Ack {
                largest_acknowledged: VarInt::from_u64_unchecked(0),
                ack_delay: VarInt::from_u64_unchecked(0),
                ack_range_count: VarInt::from_u64_unchecked(0),
                first_ack_range: VarInt::from_u64_unchecked(0),
                ack_ranges: Vec::new(),
                ecn_counts: None,
            };
            let crypto = QuicFrame::Crypto {
                offset: VarInt::from_u64_unchecked(0),
                data: Bytes::from_static(b"finished"),
            };
            let cid = ConnectionId::new(b"coalesce").unwrap();
            let stranger = ConnectionId::new(b"stranger").unwrap();
            let peer_cid = ConnectionId::new(b"coal-peer").unwrap();
            let peer = "127.0.0.1:4495".parse().unwrap();
            // (case, leading Handshake frames, padding, 1-RTT tail CID,
            // final flight requested, tail delivered)
            for (case, leading, padding, tail_cid, requested, delivered) in [
                ("ack + tail", vec![&ack], 0, Some(cid), false, true),
                (
                    "ack + ack + tail",
                    vec![&ack, &ack],
                    0,
                    Some(cid),
                    false,
                    true,
                ),
                ("crypto + tail", vec![&crypto], 0, Some(cid), true, true),
                (
                    "ack + stranger's tail",
                    vec![&ack],
                    0,
                    Some(stranger),
                    false,
                    false,
                ),
                ("ack + padding", vec![&ack], 24, None, false, false),
            ] {
                let config = NativeQuicConnectionConfig::default();
                let mut router = ConnectionRouter::new(config);
                let origin = router.clock_origin;
                add_authenticated_close_test_connection(
                    &cx,
                    &mut router,
                    cid,
                    peer_cid,
                    peer,
                    origin,
                )
                .await;
                let mut transcript = QuicHandshakeTranscript::new();
                transcript.record("handshake", b"coalesced classification");
                let mut handshake_protection = deterministic_one_rtt_protection(&cx).await;
                handshake_protection
                    .derive_keys(
                        &cx,
                        PacketProtectionSpace::Handshake,
                        &transcript,
                        b"classification test",
                    )
                    .await
                    .expect("derive handshake keys");
                {
                    let handle = router.connections.get_mut(&cid).unwrap();
                    handle
                        .packet_protection
                        .as_mut()
                        .unwrap()
                        .protection
                        .derive_keys(
                            &cx,
                            PacketProtectionSpace::Handshake,
                            &transcript,
                            b"classification test",
                        )
                        .await
                        .expect("derive the router's handshake keys");
                    handle
                        .authenticated
                        .as_mut()
                        .unwrap()
                        .final_handshake_flight = vec![OutgoingPacket {
                        dst_addr: peer,
                        data: vec![0xe5; 48],
                        send_time: None,
                    }];
                }

                let mut datagram = Vec::new();
                for (number, frame) in (0u64..).zip(&leading) {
                    datagram.extend(seal_handshake_packet(
                        &cx,
                        &mut handshake_protection,
                        cid,
                        peer_cid,
                        number,
                        frame,
                    ));
                }
                datagram.resize(datagram.len() + padding, 0);
                if let Some(tail_cid) = tail_cid {
                    let frames = [QuicFrame::Stream {
                        stream_id: VarInt(1),
                        offset: None,
                        data: Bytes::from_static(b"x"),
                        fin: false,
                    }];
                    let mut payload = BytesMut::new();
                    NativeQuicConnection::encode_frames(&frames, &mut payload).unwrap();
                    let mut sender = NativeQuicConnection::new(config);
                    establish_for_application_data(&cx, &mut sender);
                    let mut sender_protection = deterministic_one_rtt_protection(&cx).await;
                    datagram.extend(
                        assemble_protected_1rtt_packet(
                            &cx,
                            tail_cid,
                            &mut sender,
                            &mut sender_protection,
                            &frames,
                            &payload,
                            1_000,
                            true,
                        )
                        .await
                        .unwrap(),
                    );
                }

                let packet = ReceivedPacket {
                    src_addr: peer,
                    data: datagram,
                    receive_time: origin + Duration::from_millis(1),
                    transmit_time: None,
                };
                match router.route_packet_with_output(&cx, packet, true).await {
                    Ok(RoutingResult::Routed {
                        connection_id,
                        outgoing_packets,
                    }) => {
                        assert_eq!(connection_id, cid, "{case}");
                        assert!(outgoing_packets.is_empty(), "{case}");
                    }
                    other => panic!("{case}: the datagram must be routed: {other:?}"),
                }
                let retransmitted = router
                    .pending_deferred_packets
                    .iter()
                    .filter(|packet| packet.final_handshake_flight)
                    .count();
                assert_eq!(
                    retransmitted,
                    usize::from(requested),
                    "{case}: final flight requested"
                );
                let handle = router.connections.get_mut(&cid).unwrap();
                assert_eq!(
                    handle.connection.state(),
                    QuicConnectionState::Established,
                    "{case}"
                );
                assert_eq!(handle.connection.transport().close_code(), None, "{case}");
                assert_eq!(
                    handle.deferred_spaces,
                    [false, false, delivered],
                    "{case}: only a processed tail owes output, in ApplicationData"
                );
                let readable = handle.connection.next_readable_stream(&cx).unwrap();
                assert_eq!(readable.is_some(), delivered, "{case}: tail delivered");
                if delivered {
                    assert_eq!(
                        handle
                            .connection
                            .read_stream_bytes(&cx, crate::net::quic_native::StreamId(1), 32)
                            .unwrap(),
                        Bytes::from_static(b"x"),
                        "{case}"
                    );
                }
            }
        });
    }

    #[cfg(feature = "tls")]
    #[test]
    fn authenticated_forced_close_preserves_other_peer_and_original_drain_clock() {
        run_test_with_cx(|cx| async move {
            for acknowledge_close in [false, true] {
                let config = NativeQuicConnectionConfig {
                    drain_timeout_micros: 3_000_000,
                    ..NativeQuicConnectionConfig::default()
                };
                let mut router = ConnectionRouter::new(config);
                router.set_idle_timeout_micros(0);
                let a = ConnectionId::new(b"close-a").unwrap();
                let b = ConnectionId::new(b"close-b").unwrap();
                let peer_a = ConnectionId::new(b"peer-a").unwrap();
                let peer_b = ConnectionId::new(b"peer-b").unwrap();
                let address_a = "127.0.0.1:4491".parse().unwrap();
                let address_b = "127.0.0.1:4492".parse().unwrap();
                let origin_a = router.clock_origin + Duration::from_secs(17);
                let origin_b = router.clock_origin;
                let now = origin_a + Duration::from_secs(7);
                let deadline = origin_a + Duration::from_secs(10);
                for (cid, peer_cid, address, origin) in [
                    (a, peer_a, address_a, origin_a),
                    (b, peer_b, address_b, origin_b),
                ] {
                    add_authenticated_close_test_connection(
                        &cx,
                        &mut router,
                        cid,
                        peer_cid,
                        address,
                        origin,
                    )
                    .await;
                    let handle = router.connections.get_mut(&cid).unwrap();
                    let stream = handle.connection.open_local_bidi(&cx).unwrap();
                    handle
                        .connection
                        .write_stream_bytes(
                            &cx,
                            stream,
                            Bytes::from_static(b"owned response"),
                            false,
                        )
                        .unwrap();
                    handle.connection.queue_ping(&cx).unwrap();
                    for timer_queue in [true, false] {
                        let packet = RoutedOutgoingPacket {
                            connection_id: cid,
                            packet: OutgoingPacket {
                                dst_addr: address,
                                data: cid.as_bytes().to_vec(),
                                send_time: Some(now),
                            },
                            final_handshake_flight: false,
                            ack_eliciting: false,
                        };
                        if timer_queue {
                            router.pending_timer_packets.push(packet);
                        } else {
                            router.pending_deferred_packets.push(packet);
                        }
                    }
                }
                assert!(
                    router
                        .request_authenticated_close(&cx, a, now, 42, true)
                        .unwrap()
                );
                assert_eq!(router.pending_datagram_count_for(a), 0);
                assert_eq!(router.pending_datagram_count_for(b), 2);
                assert_eq!(
                    router.connections[&a].connection.state(),
                    QuicConnectionState::Draining
                );
                assert_eq!(
                    router.connections[&a]
                        .connection
                        .transport()
                        .drain_deadline_micros(),
                    Some(10_000_000)
                );
                assert_eq!(router.next_timer_deadline(), Some(deadline));
                assert_eq!(
                    router.connections[&b].connection.state(),
                    QuicConnectionState::Established
                );
                assert_eq!(
                    router.connections[&b]
                        .connection
                        .pending_stream_data_bytes(),
                    14
                );
                assert!(
                    router.connections[&b]
                        .connection
                        .has_pending_control_frames()
                );

                let packets = router.drain_deferred_output(&cx, now, 8).await.unwrap();
                assert_eq!(packets.len(), 2);
                let close = packets
                    .iter()
                    .find(|packet| packet.connection_id == a)
                    .unwrap();
                assert_eq!(close.packet.dst_addr, address_a);
                assert!(!close.ack_eliciting);
                assert!(!close.final_handshake_flight);
                let ciphertext = close.packet.data.clone();
                let mut verifier = deterministic_one_rtt_protection(&cx).await;
                let decoded = unprotect_1rtt_packet(&cx, peer_a, &mut verifier, &ciphertext)
                    .await
                    .unwrap();
                assert_eq!(
                    NativeQuicConnection::decode_frames(&decoded.plaintext).unwrap(),
                    vec![QuicFrame::ConnectionClose {
                        error_code: VarInt(42),
                        frame_type: None,
                        reason_phrase: Bytes::new(),
                    },]
                );
                router.pending_deferred_packets.extend(packets);
                router.discard_terminal_output();
                assert!(router.connection_can_send_queued(a));
                assert_eq!(
                    router.connections[&a].local_close_output,
                    Some(LocalCloseOutput::Queued)
                );
                assert_eq!(router.pending_datagram_count_for(a), 1);

                let cancelled = Cx::for_testing();
                cancelled.set_cancel_requested(true);
                assert!(matches!(
                    router.drain_deferred_output(&cancelled, now, 8).await,
                    Err(ConnectionRouterError::Cancelled)
                ));
                assert_eq!(
                    router
                        .pending_deferred_packets
                        .iter()
                        .find(|packet| packet.connection_id == a)
                        .unwrap()
                        .packet
                        .data,
                    ciphertext
                );
                let other = router.pending_deferred_packets.remove(
                    router
                        .pending_deferred_packets
                        .iter()
                        .position(|packet| packet.connection_id == b)
                        .unwrap(),
                );
                assert_eq!(other.packet.data, b.as_bytes());
                router.packet_sent(&other, Some(now));
                assert_eq!(
                    router.connections[&a].local_close_output,
                    Some(LocalCloseOutput::Queued)
                );
                assert_eq!(router.connections[&b].local_close_output, None);
                router.pending_deferred_packets.push(other);

                if acknowledge_close {
                    let sent = router.pending_deferred_packets.remove(
                        router
                            .pending_deferred_packets
                            .iter()
                            .position(|packet| packet.connection_id == a)
                            .unwrap(),
                    );
                    router.packet_sent(&sent, Some(now));
                    router.packet_sent(&sent, Some(now));
                    assert_eq!(
                        router.connections[&a].local_close_output,
                        Some(LocalCloseOutput::Sent)
                    );
                    assert!(!router.connection_can_send_queued(a));
                }
                // Repeating close neither changes its code/deadline nor makes
                // another protected packet after the first has been committed.
                assert!(router.request_authenticated_close(
                    &cx, a, now + Duration::from_secs(1), 99, true,
                ).unwrap());
                assert_eq!(
                    router.connections[&a].connection.transport().close_code(),
                    Some(42)
                );
                assert_eq!(router.next_timer_deadline(), Some(deadline));
                assert!(
                    router
                        .expired_connections(
                            deadline.checked_sub(Duration::from_micros(1)).unwrap()
                        )
                        .is_empty()
                );
                assert_eq!(router.expired_connections(deadline), vec![a]);
                let remaining = router
                    .process_managed_timer_events(&cx, deadline, &HashSet::new())
                    .await
                    .unwrap();
                assert_eq!(remaining.len(), 1);
                assert_eq!(remaining[0].connection_id, b);
                assert_eq!(remaining[0].packet.data, b.as_bytes());
                assert!(!router.connections.contains_key(&a));
                assert_eq!(router.pending_datagram_count_for(a), 0);
                assert_eq!(router.pending_datagram_count_for(b), 1);
                assert_eq!(
                    router.connections[&b].connection.state(),
                    QuicConnectionState::Established
                );
                assert_eq!(
                    router.connections[&b]
                        .connection
                        .pending_stream_data_bytes(),
                    14
                );
                assert!(router.next_timer_deadline().is_none());
            }
        });
    }

    #[cfg(feature = "tls")]
    #[test]
    fn authenticated_close_shutdown_transfers_committed_ciphertext_once() {
        run_test_with_cx(|cx| async move {
            let mut router = ConnectionRouter::new(NativeQuicConnectionConfig::default());
            let cid = ConnectionId::new(b"close-shutdown").unwrap();
            let peer_cid = ConnectionId::new(b"shutdown-peer").unwrap();
            let peer = "127.0.0.1:4493".parse().unwrap();
            let origin = router.clock_origin + Duration::from_secs(17);
            let now = origin + Duration::from_secs(7);
            let deadline = origin + Duration::from_secs(10);
            add_authenticated_close_test_connection(&cx, &mut router, cid, peer_cid, peer, origin)
                .await;
            assert!(
                router
                    .request_authenticated_close(&cx, cid, now, 42, true)
                    .unwrap()
            );
            let packets = router.drain_deferred_output(&cx, now, 1).await.unwrap();
            assert_eq!(packets.len(), 1);
            let ciphertext = packets[0].packet.data.clone();
            router.pending_deferred_packets.extend(packets);
            assert_eq!(router.queued_local_close_deadline(cid), Some(deadline));

            let mut shutdown = router
                .prepare_shutdown_close_packets(&cx, now)
                .await
                .unwrap();
            assert_eq!(shutdown.len(), 1);
            assert_eq!(shutdown[0].0.data, ciphertext);
            assert_eq!(shutdown[0].0.dst_addr, peer);
            assert_eq!(shutdown[0].1, deadline);
            assert_eq!(router.pending_datagram_count_for(cid), 0);
            assert_eq!(
                router.connections[&cid].local_close_output,
                Some(LocalCloseOutput::Queued)
            );
            assert!(
                router
                    .prepare_shutdown_close_packets(&cx, now)
                    .await
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(
                router.connections[&cid].connection.transport().close_code(),
                Some(42)
            );

            let (packet, _) = shutdown.pop().unwrap();
            let sent = RoutedOutgoingPacket {
                connection_id: cid,
                packet,
                final_handshake_flight: false,
                ack_eliciting: false,
            };
            router.packet_sent(&sent, Some(now));
            assert_eq!(
                router.connections[&cid].local_close_output,
                Some(LocalCloseOutput::Sent)
            );
            assert_eq!(router.queued_local_close_deadline(cid), None);
            assert!(
                router
                    .prepare_shutdown_close_packets(&cx, now + Duration::from_secs(1),)
                    .await
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(sent.packet.data, ciphertext);
            assert_eq!(
                router.connections[&cid]
                    .connection
                    .transport()
                    .drain_deadline_micros(),
                Some(10_000_000)
            );
        });
    }

    fn establish_for_application_data(cx: &Cx, connection: &mut NativeQuicConnection) {
        connection.begin_handshake(cx).expect("begin");
        connection
            .on_handshake_keys_available(cx)
            .expect("handshake keys");
        connection.on_1rtt_keys_available(cx).expect("1rtt keys");
        connection.record_verified_server_identity();
        connection
            .on_handshake_confirmed(cx)
            .expect("handshake confirmed");
    }
