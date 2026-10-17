    use super::*;
    use crate::net::quic_native::handshake_driver::tests::{
        CA_CERT_PEM, LEAF_CERT_PEM, leaf_key, parse_one_cert,
    };
    use crate::net::quic_native::handshake_driver::{client_config, server_config};
    use futures_lite::future::{block_on, zip};

    async fn established_loopback_links(cx: &Cx, config: &QuicConfig) -> (QuicLink, QuicLink) {
        let endpoint = bind_endpoint(cx, "127.0.0.1:0".parse().unwrap())
            .await
            .expect("bind endpoint");
        let address = endpoint.local_addr();
        let client_tls = QuicClientTls {
            server_name: ServerName::try_from("localhost").unwrap(),
            config: client_config(
                vec![parse_one_cert(CA_CERT_PEM)],
                vec![ATP_QUIC_ALPN.to_vec()],
            )
            .unwrap(),
        };
        let server_tls = QuicServerTls {
            config: server_config(
                vec![parse_one_cert(LEAF_CERT_PEM)],
                leaf_key(),
                vec![ATP_QUIC_ALPN.to_vec()],
            )
            .unwrap(),
        };
        let (client, server) = zip(
            connect(cx, address, &client_tls, config),
            accept(cx, endpoint, &server_tls, config),
        )
        .await;
        let client = client.expect("client link");
        let (mut server, early) = server.expect("server link");
        server.ingest_packets(cx, early).expect("early packets");
        (client, server)
    }

    // br-asupersync-5f1fcj: a long-header datagram that fails to authenticate
    // made the server's accept return an error, so anyone who could reach the
    // port could end an accept with one garbage packet (ATP's Initial DCID is
    // a protocol constant). It must be discarded and the handshake complete.
    #[test]
    fn a_garbage_long_header_datagram_does_not_end_an_accept() {
        let cx = Cx::for_testing();
        let config = QuicConfig::default();
        block_on(async {
            let endpoint = bind_endpoint(&cx, "127.0.0.1:0".parse().unwrap())
                .await
                .expect("bind endpoint");
            let address = endpoint.local_addr();
            // An Initial-typed long header with ATP's Initial DCID and a body
            // that cannot authenticate, queued before the real client.
            let mut garbage = vec![0xc0, 0x00, 0x00, 0x00, 0x01];
            garbage.push(u8::try_from(ATP_QUIC_INITIAL_DCID.len()).expect("dcid length"));
            garbage.extend_from_slice(ATP_QUIC_INITIAL_DCID);
            garbage.extend_from_slice(&[8, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0x44, 0x00]);
            garbage.resize(1_200, 0xa5);
            let forger = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind forger");
            forger.send_to(&garbage, address).expect("send garbage");

            let client_tls = QuicClientTls {
                server_name: ServerName::try_from("localhost").unwrap(),
                config: client_config(
                    vec![parse_one_cert(CA_CERT_PEM)],
                    vec![ATP_QUIC_ALPN.to_vec()],
                )
                .unwrap(),
            };
            let server_tls = QuicServerTls {
                config: server_config(
                    vec![parse_one_cert(LEAF_CERT_PEM)],
                    leaf_key(),
                    vec![ATP_QUIC_ALPN.to_vec()],
                )
                .unwrap(),
            };
            let (client, server) = zip(
                connect(&cx, address, &client_tls, &config),
                accept(&cx, endpoint, &server_tls, &config),
            )
            .await;
            client.expect("client link");
            server.expect("the accept survives the garbage datagram");
        });
    }

    // br-asupersync-8vrx8q (audit r8 H1): accept stashed every short-header
    // datagram from any address while no peer was known, without bound. Those
    // sent before the client's Initial must not reach the replayed early data.
    #[test]
    fn short_header_datagrams_before_the_client_is_known_are_not_stashed() {
        let cx = Cx::for_testing();
        let config = QuicConfig::default();
        block_on(async {
            let endpoint = bind_endpoint(&cx, "127.0.0.1:0".parse().unwrap())
                .await
                .expect("bind endpoint");
            let address = endpoint.local_addr();
            let sprayer = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind sprayer");
            let sprayer_addr = sprayer.local_addr().expect("sprayer address");
            for _ in 0..64 {
                sprayer
                    .send_to(&[0x40; 1_200], address)
                    .expect("send short header");
            }

            let client_tls = QuicClientTls {
                server_name: ServerName::try_from("localhost").unwrap(),
                config: client_config(
                    vec![parse_one_cert(CA_CERT_PEM)],
                    vec![ATP_QUIC_ALPN.to_vec()],
                )
                .unwrap(),
            };
            let server_tls = QuicServerTls {
                config: server_config(
                    vec![parse_one_cert(LEAF_CERT_PEM)],
                    leaf_key(),
                    vec![ATP_QUIC_ALPN.to_vec()],
                )
                .unwrap(),
            };
            let (client, server) = zip(
                connect(&cx, address, &client_tls, &config),
                accept(&cx, endpoint, &server_tls, &config),
            )
            .await;
            client.expect("client link");
            let (_server, early) = server.expect("server link");
            let sprayed = early
                .iter()
                .filter(|packet| packet.src_addr == sprayer_addr)
                .count();
            assert_eq!(
                sprayed, 0,
                "short-header datagrams sent before the client's Initial were stashed"
            );
        });
    }

    // br-asupersync-8vrx8q (audit r8 H1): once the peer is known the stash is
    // bounded by packet count and by bytes.
    #[test]
    fn the_early_one_rtt_stash_is_bounded() {
        let packet = |len: usize| ReceivedPacket {
            src_addr: "127.0.0.1:9".parse().unwrap(),
            data: vec![0x40; len],
            receive_time: Instant::now(),
            transmit_time: None,
        };
        let mut stash = EarlyOneRttStash::default();
        assert!(!stash.offer(packet(64), false), "no peer yet: dropped");
        for _ in 0..ACCEPT_EARLY_ONE_RTT_MAX_PACKETS {
            assert!(stash.offer(packet(1), true));
        }
        assert!(!stash.offer(packet(1), true), "count cap reached");

        let mut stash = EarlyOneRttStash::default();
        let big = 64 * 1024;
        for _ in 0..ACCEPT_EARLY_ONE_RTT_MAX_BYTES / big {
            assert!(stash.offer(packet(big), true));
        }
        assert!(!stash.offer(packet(1), true), "byte cap reached");
        assert_eq!(stash.bytes, ACCEPT_EARLY_ONE_RTT_MAX_BYTES);
    }

    // asupersync-18hhdp: the client's handshake source CID is per connection,
    // not the former protocol constant, so an off-path sender cannot aim a
    // forged Retry or stale-key long header at it.
    #[test]
    fn client_handshake_source_connection_id_is_per_connection() {
        const FORMER_CONSTANT: [u8; 8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let server = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind raw server");
        server
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("raw server read timeout");
        let address = server.local_addr().expect("raw server address");
        let client_tls = QuicClientTls {
            server_name: ServerName::try_from("localhost").unwrap(),
            config: client_config(
                vec![parse_one_cert(CA_CERT_PEM)],
                vec![ATP_QUIC_ALPN.to_vec()],
            )
            .unwrap(),
        };
        let config = QuicConfig {
            handshake_timeout: Duration::from_millis(300),
            ..QuicConfig::default()
        };
        let cx = Cx::for_testing();
        let mut seen = Vec::new();
        for _ in 0..2 {
            let result = block_on(connect(&cx, address, &client_tls, &config));
            assert!(
                matches!(result, Err(QuicTransportError::Timeout { .. })),
                "no server answers: {:?}",
                result.as_ref().err()
            );
            let mut datagram = vec![0_u8; 65_536];
            let (len, _) = server.recv_from(&mut datagram).expect("client Initial");
            // Long header: flags, version (4), DCID length + DCID, SCID length + SCID.
            let dcid_len = usize::from(datagram[5]);
            let scid_len = usize::from(datagram[6 + dcid_len]);
            assert!(len > 7 + dcid_len + scid_len, "truncated client Initial");
            assert_eq!(&datagram[6..6 + dcid_len], ATP_QUIC_INITIAL_DCID);
            seen.push(datagram[7 + dcid_len..7 + dcid_len + scid_len].to_vec());
            // Discard anything else this attempt sent before the next one.
            server.set_nonblocking(true).expect("drain mode");
            while server.recv_from(&mut datagram).is_ok() {}
            server.set_nonblocking(false).expect("blocking mode");
        }
        for scid in &seen {
            assert_eq!(scid.len(), ATP_QUIC_CLIENT_SCID_LEN);
            assert_ne!(
                scid.as_slice(),
                FORMER_CONSTANT,
                "client SCID must not be a protocol constant"
            );
        }
        assert_ne!(
            seen[0], seen[1],
            "each connection draws a fresh client SCID"
        );
    }

    // asupersync-gsnci5: RFC 9001 §6.6 — the send path must not protect beyond
    // the AEAD confidentiality limit under one key. Since 1bheeo the flush
    // rotates the key before the limit, but only when no local update is still
    // awaiting the peer's confirmation. While one is, it cannot rotate again, so
    // it must fail closed at the limit rather than over-use the key.
    #[test]
    fn one_rtt_send_fails_closed_at_confidentiality_limit() {
        use crate::net::atp::quic::packet_protection::AEAD_CONFIDENTIALITY_LIMIT;
        use crate::net::quic_native::tls::PacketProtectionSpace;
        block_on(async {
            let cx = Cx::for_testing();
            let config = QuicConfig::default();
            let (mut client, _server) = established_loopback_links(&cx, &config).await;
            // A local key update the peer never confirms: the flush's own
            // rotation steps, so the local phase moves ahead of the remote one.
            let next_phase = !client.conn.tls().local_key_phase();
            assert!(
                client
                    .protection
                    .ensure_next_gen_keys(&cx, PacketProtectionSpace::OneRtt, next_phase)
                    .is_ok()
            );
            client.conn.request_local_key_update(&cx).unwrap();
            client.conn.commit_local_key_update(&cx).unwrap();
            client
                .protection
                .note_local_key_update(PacketProtectionSpace::OneRtt);
            assert_ne!(
                client.conn.tls().local_key_phase(),
                client.conn.tls().remote_key_phase(),
                "a key update must be awaiting the peer's confirmation"
            );
            client.protection.set_protected_packet_count_for_test(
                PacketProtectionSpace::OneRtt,
                AEAD_CONFIDENTIALITY_LIMIT,
            );
            // Queue a control-stream frame so the flush assembles a 1-RTT batch
            // and reaches the confidentiality guard.
            let mut client_control = NativeQuicFrameTransport::open(&cx, &mut client.conn).unwrap();
            let frame = Frame::empty(FrameType::KeepAlive).unwrap();
            client_control.send(&cx, &mut client.conn, &frame).unwrap();
            let result = client.flush(&cx).await;
            assert!(
                matches!(&result, Err(QuicTransportError::Quic(msg)) if msg.contains("confidentiality limit")),
                "flush must fail closed at the confidentiality limit, got {result:?}"
            );
        });
    }

    // asupersync-1bheeo: with no key update awaiting confirmation, the same
    // preloaded limit makes the flush rotate the key instead of failing, and
    // the batch goes out under the fresh key.
    #[test]
    fn one_rtt_send_rotates_before_the_confidentiality_limit() {
        use crate::net::atp::quic::packet_protection::AEAD_CONFIDENTIALITY_LIMIT;
        use crate::net::quic_native::tls::PacketProtectionSpace;
        block_on(async {
            let cx = Cx::for_testing();
            let config = QuicConfig::default();
            let (mut client, _server) = established_loopback_links(&cx, &config).await;
            let phase_before = client.conn.tls().local_key_phase();
            assert_eq!(phase_before, client.conn.tls().remote_key_phase());
            client.protection.set_protected_packet_count_for_test(
                PacketProtectionSpace::OneRtt,
                AEAD_CONFIDENTIALITY_LIMIT,
            );
            let mut client_control = NativeQuicFrameTransport::open(&cx, &mut client.conn).unwrap();
            let frame = Frame::empty(FrameType::KeepAlive).unwrap();
            client_control.send(&cx, &mut client.conn, &frame).unwrap();
            let result = client.flush(&cx).await;
            assert!(result.is_ok(), "flush must rotate, not fail: {result:?}");
            assert_ne!(
                client.conn.tls().local_key_phase(),
                phase_before,
                "the send key rotated"
            );
            assert!(
                !client
                    .protection
                    .confidentiality_limit_reached(PacketProtectionSpace::OneRtt),
                "the fresh key starts below the limit"
            );
        });
    }

    // asupersync-gsnci5: RFC 9001 §6.6 — the receive path must close the
    // connection once too many packets have failed authentication under one key
    // (integrity limit). This bounds forgery attempts; it never fires normally.
    #[test]
    fn one_rtt_receive_fails_closed_at_integrity_limit() {
        use crate::net::atp::quic::packet_protection::AEAD_INTEGRITY_LIMIT;
        use crate::net::quic_native::endpoint::ReceivedPacket;
        use crate::net::quic_native::tls::PacketProtectionSpace;
        block_on(async {
            let cx = Cx::for_testing();
            let config = QuicConfig::default();
            let (_client, mut server) = established_loopback_links(&cx, &config).await;
            server.protection.set_auth_failure_count_for_test(
                PacketProtectionSpace::OneRtt,
                AEAD_INTEGRITY_LIMIT,
            );
            // A well-formed short-header 1-RTT packet with a high packet number
            // (past the accepted window) and undecryptable body.
            let mut data = encode_one_rtt_header(1_000_000, false).to_vec();
            data.extend_from_slice(&[0u8; ONE_RTT_TAG_LEN + 8]);
            let packet = ReceivedPacket {
                src_addr: "127.0.0.1:0".parse().unwrap(),
                data,
                receive_time: Instant::now(),
                transmit_time: None,
            };
            let result = server.ingest_packets(&cx, vec![packet]);
            assert!(
                matches!(&result, Err(QuicTransportError::Integrity(_))),
                "ingest must fail closed at the integrity limit, got {result:?}"
            );
        });
    }

    // asupersync-1bheeo (RFC 9001 §6.3/§6.5): with a lowered soft key-update
    // threshold, a long-lived bidirectional 1-RTT exchange crosses the
    // confidentiality threshold repeatedly, so BOTH endpoints rotate their keys
    // several times (alternating phases). Each endpoint's flush initiates a
    // local update (Part 1) and each receive path installs the peer's
    // next-generation keys and decrypts the rotated traffic (Part 2). Every
    // control frame must survive intact — its AEAD tag verifies only under the
    // correct rotated keys — and neither side may fall back to the hard
    // confidentiality-limit fail-closed. The `>= 3` rotation asserts make this
    // non-vacuous: without the rotation wiring the remote key phase never moves
    // and the test fails.
    #[test]
    fn bidirectional_key_rotation_over_real_udp() {
        use crate::net::quic_native::tls::PacketProtectionSpace;

        // Deliver `frame` over the control stream, rotating keys as the soft
        // threshold trips, pumping until it authenticates and decodes. Returns
        // the received frame type so the caller can assert byte-intactness.
        async fn ping(
            cx: &Cx,
            from: &mut QuicLink,
            from_control: &mut NativeQuicFrameTransport,
            to: &mut QuicLink,
            to_control: &mut NativeQuicFrameTransport,
            frame: &Frame,
        ) -> FrameType {
            from_control.send(cx, &mut from.conn, frame).unwrap();
            from.flush(cx).await.unwrap();
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                to.pump_inbound_for(cx, Duration::from_secs(2))
                    .await
                    .unwrap();
                if let Some(received) = to_control.try_recv(cx, &mut to.conn).unwrap() {
                    return received.frame_type();
                }
                assert!(
                    Instant::now() < deadline,
                    "rotated control frame never arrived"
                );
            }
        }

        block_on(async {
            let cx = Cx::for_testing();
            let config = QuicConfig::default();
            let (mut client, mut server) = established_loopback_links(&cx, &config).await;

            // A tiny soft threshold forces a key update every few sent packets;
            // production uses the RFC 9001 §6.6 default (millions of packets).
            client
                .protection
                .set_key_update_confidentiality_threshold(2);
            server
                .protection
                .set_key_update_confidentiality_threshold(2);

            let (mut client_control, mut server_control) =
                opened_control_streams(&cx, &mut client, &mut server).await;

            let mut client_remote_phases = vec![client.conn.tls().remote_key_phase()];
            let mut server_remote_phases = vec![server.conn.tls().remote_key_phase()];

            for round in 0..14u32 {
                // Alternate frame types so a decrypt under the wrong key would
                // surface as a wrong or absent frame, not a silent pass.
                let c2s = if round % 2 == 0 {
                    Frame::empty(FrameType::KeepAlive).unwrap()
                } else {
                    Frame::empty(FrameType::Proof).unwrap()
                };
                let got = ping(
                    &cx,
                    &mut client,
                    &mut client_control,
                    &mut server,
                    &mut server_control,
                    &c2s,
                )
                .await;
                assert_eq!(
                    got,
                    c2s.frame_type(),
                    "client->server frame corrupted in round {round}"
                );
                server_remote_phases.push(server.conn.tls().remote_key_phase());

                let s2c = if round % 2 == 0 {
                    Frame::empty(FrameType::Proof).unwrap()
                } else {
                    Frame::empty(FrameType::KeepAlive).unwrap()
                };
                let got = ping(
                    &cx,
                    &mut server,
                    &mut server_control,
                    &mut client,
                    &mut client_control,
                    &s2c,
                )
                .await;
                assert_eq!(
                    got,
                    s2c.frame_type(),
                    "server->client frame corrupted in round {round}"
                );
                client_remote_phases.push(client.conn.tls().remote_key_phase());

                // Rotation must keep each key's packet count below the hard
                // limit; a fail-closed here means Part 1 never rotated.
                assert!(
                    !client
                        .protection
                        .confidentiality_limit_reached(PacketProtectionSpace::OneRtt),
                    "client hit the hard confidentiality limit instead of rotating",
                );
                assert!(
                    !server
                        .protection
                        .confidentiality_limit_reached(PacketProtectionSpace::OneRtt),
                    "server hit the hard confidentiality limit instead of rotating",
                );
            }

            // Count accepted peer rotations on each side (adjacent phase flips of
            // the remote key phase). Both receive paths must have installed and
            // committed several peer key updates.
            let count_flips = |phases: &[bool]| phases.windows(2).filter(|w| w[0] != w[1]).count();
            let client_rotations = count_flips(&client_remote_phases);
            let server_rotations = count_flips(&server_remote_phases);
            assert!(
                client_rotations >= 3,
                "client should accept several peer key updates, saw {client_rotations}: {client_remote_phases:?}",
            );
            assert!(
                server_rotations >= 3,
                "server should accept several peer key updates, saw {server_rotations}: {server_remote_phases:?}",
            );
        });
    }

    #[test]
    fn stream_pto_budget_counts_consecutive_silent_windows() {
        assert_eq!(stream_pto_attempts_after_pump(0, 0), 1);
        assert_eq!(stream_pto_attempts_after_pump(5, 0), 6);
        assert_eq!(
            stream_pto_attempts_after_pump(5, 1),
            0,
            "any 1-RTT packet from the peer restarts the silent-window count"
        );
        assert_eq!(stream_pto_attempts_after_pump(u32::MAX, 0), u32::MAX);
    }

    #[test]
    fn local_work_keep_alive_fires_once_per_cadence() {
        let start = Instant::now();
        let cadence = Duration::from_millis(200);
        let mut keep_alive = LocalWorkKeepAlive::new(start);
        assert!(!keep_alive.due(start, cadence));
        assert!(!keep_alive.due(start + Duration::from_millis(199), cadence));
        assert!(keep_alive.due(start + Duration::from_millis(200), cadence));
        assert!(
            !keep_alive.due(start + Duration::from_millis(399), cadence),
            "re-based on the emission, not on the poll"
        );
        assert!(keep_alive.due(start + Duration::from_millis(400), cadence));
    }

    /// Sender side: with a 3 s idle budget (two 1.5 s windows) the proof wait
    /// used to give up after ANY three silent windows in total, even with a
    /// keep-alive between each pair. The peer here pings every 2.2 s (one
    /// silent window per gap, three gaps) and then answers at ~8 s; the
    /// cumulative count died in the third gap (~5.9 s).
    #[test]
    fn proof_wait_survives_a_slow_but_pinging_peer_over_real_udp() {
        block_on(async {
            let cx = Cx::for_testing();
            let config = QuicConfig {
                idle_timeout: Duration::from_secs(3),
                ..QuicConfig::default()
            };
            let (mut client, mut server) = established_loopback_links(&cx, &config).await;
            let control_stream = super::super::first_client_bidi_stream();
            // The client opens its control stream (as the sender's Hello does)
            // and writes on it so the server can answer on the same stream.
            let mut client_control = NativeQuicFrameTransport::open(&cx, &mut client.conn).unwrap();
            assert_eq!(client_control.stream, control_stream);
            let mut server_control = NativeQuicFrameTransport::for_stream(control_stream);
            let opener = Frame::empty(FrameType::KeepAlive).unwrap();
            client_control.send(&cx, &mut client.conn, &opener).unwrap();
            client.flush(&cx).await.unwrap();
            let opened_at = Instant::now();
            loop {
                server
                    .pump_inbound_for(&cx, Duration::from_secs(2))
                    .await
                    .unwrap();
                if server_control
                    .try_recv(&cx, &mut server.conn)
                    .unwrap()
                    .is_some()
                {
                    break;
                }
                assert!(
                    opened_at.elapsed() < Duration::from_secs(10),
                    "control stream never opened"
                );
            }

            let placeholder = [SentControlStreamFrame {
                stream: control_stream,
                offset: 0,
                len: 1,
            }];
            let client_wait = async {
                let started = Instant::now();
                let frame = client
                    .next_control_frame_with_stream_pto(
                        &cx,
                        &mut client_control,
                        "gh67 proof wait",
                        &placeholder,
                        "gh67_test_pto",
                    )
                    .await;
                (started.elapsed(), frame.map(|frame| frame.frame_type()))
            };
            let server_pinger = async {
                for _ in 0..3 {
                    crate::time::sleep(cx.now(), Duration::from_millis(2200)).await;
                    send_and_flush_native_keep_alive(&cx, &mut server, &mut server_control)
                        .await
                        .unwrap();
                }
                crate::time::sleep(cx.now(), Duration::from_millis(1400)).await;
                let proof = Frame::empty(FrameType::Proof).unwrap();
                server_control.send(&cx, &mut server.conn, &proof).unwrap();
                server.flush(&cx).await.unwrap();
            };
            let ((elapsed, frame), ()) = zip(client_wait, server_pinger).await;
            assert_eq!(
                frame.expect("proof after three keep-alives"),
                FrameType::Proof
            );
            assert!(
                elapsed >= Duration::from_millis(7500),
                "the wait must have outlived the cumulative budget (~5.9 s): {elapsed:?}"
            );
            assert!(elapsed < Duration::from_secs(12), "{elapsed:?}");
        });
    }

    /// Opens the client's control stream (as the sender's Hello does) and
    /// pumps the server until it holds the opener, returning both ends.
    async fn opened_control_streams(
        cx: &Cx,
        client: &mut QuicLink,
        server: &mut QuicLink,
    ) -> (NativeQuicFrameTransport, NativeQuicFrameTransport) {
        let control_stream = super::super::first_client_bidi_stream();
        let mut client_control = NativeQuicFrameTransport::open(cx, &mut client.conn).unwrap();
        assert_eq!(client_control.stream, control_stream);
        let mut server_control = NativeQuicFrameTransport::for_stream(control_stream);
        let opener = Frame::empty(FrameType::KeepAlive).unwrap();
        client_control.send(cx, &mut client.conn, &opener).unwrap();
        client.flush(cx).await.unwrap();
        let opened_at = Instant::now();
        loop {
            server
                .pump_inbound_for(cx, Duration::from_secs(2))
                .await
                .unwrap();
            if server_control
                .try_recv(cx, &mut server.conn)
                .unwrap()
                .is_some()
            {
                break;
            }
            assert!(
                opened_at.elapsed() < Duration::from_secs(10),
                "control stream never opened"
            );
        }
        (client_control, server_control)
    }

    /// Sender side, pure-stream path (asupersync-ybczmx): the source-stream
    /// proof wait measured its idle budget from the start of the wait, so a
    /// receiver that pinged every 200 ms through a long packed-tree commit
    /// was declared dead the moment the budget elapsed (149 pumped windows on
    /// record when the 45 s budget fired). The peer here pings every 400 ms
    /// for 4.4 s against a 2 s budget and then answers; the old clock died
    /// at 2 s.
    #[test]
    fn source_stream_proof_wait_survives_a_slow_but_pinging_peer_over_real_udp() {
        block_on(async {
            let cx = Cx::for_testing();
            let config = QuicConfig {
                idle_timeout: Duration::from_secs(2),
                ..QuicConfig::default()
            };
            let (mut client, mut server) = established_loopback_links(&cx, &config).await;
            let (mut client_control, mut server_control) =
                opened_control_streams(&cx, &mut client, &mut server).await;
            let client_wait = async {
                let started = Instant::now();
                let frame = client
                    .next_control_frame_with_source_stream_recovery(
                        &cx,
                        &mut client_control,
                        "ybczmx proof wait",
                    )
                    .await;
                (started.elapsed(), frame.map(|frame| frame.frame_type()))
            };
            let server_pinger = async {
                for _ in 0..11 {
                    crate::time::sleep(cx.now(), Duration::from_millis(400)).await;
                    send_and_flush_native_keep_alive(&cx, &mut server, &mut server_control)
                        .await
                        .unwrap();
                }
                let proof = Frame::empty(FrameType::Proof).unwrap();
                server_control.send(&cx, &mut server.conn, &proof).unwrap();
                server.flush(&cx).await.unwrap();
            };
            let ((elapsed, frame), ()) = zip(client_wait, server_pinger).await;
            assert_eq!(
                frame.expect("proof after eleven keep-alives"),
                FrameType::Proof
            );
            assert!(
                elapsed >= Duration::from_millis(4000),
                "the wait must have outlived the 2 s budget measured from its start: {elapsed:?}"
            );
            assert!(elapsed < Duration::from_secs(12), "{elapsed:?}");
        });
    }

    /// A peer that stays silent still fails closed after one idle budget of
    /// silence, well before the liveness cap.
    #[test]
    fn source_stream_proof_wait_fails_closed_after_an_idle_budget_of_silence() {
        block_on(async {
            let cx = Cx::for_testing();
            let config = QuicConfig {
                idle_timeout: Duration::from_secs(1),
                ..QuicConfig::default()
            };
            let (mut client, mut server) = established_loopback_links(&cx, &config).await;
            let (mut client_control, _server_control) =
                opened_control_streams(&cx, &mut client, &mut server).await;
            let started = Instant::now();
            let result = client
                .next_control_frame_with_source_stream_recovery(
                    &cx,
                    &mut client_control,
                    "ybczmx silent peer",
                )
                .await;
            let elapsed = started.elapsed();
            match result {
                Err(QuicTransportError::Quic(message)) => assert!(
                    message.contains("source_stream_proof_timeout"),
                    "silence must expire on the idle clock: {message}"
                ),
                Err(other) => panic!("unexpected error class: {other:?}"),
                Ok(frame) => panic!("a silent peer delivered {:?}", frame.frame_type()),
            }
            assert!(
                elapsed >= Duration::from_secs(1) && elapsed < Duration::from_secs(6),
                "one idle budget of silence, not the 8 s liveness cap: {elapsed:?}"
            );
        });
    }

    /// A peer that keeps pinging but never delivers the Proof is bounded by
    /// the absolute liveness cap (eight idle budgets), not held forever.
    #[test]
    fn source_stream_proof_wait_caps_a_live_peer_that_never_answers_over_real_udp() {
        block_on(async {
            let cx = Cx::for_testing();
            let config = QuicConfig {
                idle_timeout: Duration::from_millis(500),
                ..QuicConfig::default()
            };
            let (mut client, mut server) = established_loopback_links(&cx, &config).await;
            let (mut client_control, mut server_control) =
                opened_control_streams(&cx, &mut client, &mut server).await;
            let client_wait = async {
                let started = Instant::now();
                let result = client
                    .next_control_frame_with_source_stream_recovery(
                        &cx,
                        &mut client_control,
                        "ybczmx capped wait",
                    )
                    .await;
                (started.elapsed(), result)
            };
            let server_pinger = async {
                for _ in 0..70 {
                    crate::time::sleep(cx.now(), Duration::from_millis(100)).await;
                    send_and_flush_native_keep_alive(&cx, &mut server, &mut server_control)
                        .await
                        .unwrap();
                }
            };
            let ((elapsed, result), ()) = zip(client_wait, server_pinger).await;
            match result {
                Err(QuicTransportError::Quic(message)) => assert!(
                    message.contains("source_stream_proof_liveness_cap"),
                    "a live peer that never answers must hit the cap: {message}"
                ),
                Err(other) => panic!("unexpected error class: {other:?}"),
                Ok(frame) => panic!("the peer never sent a frame, got {:?}", frame.frame_type()),
            }
            assert!(
                elapsed >= Duration::from_secs(4) && elapsed < Duration::from_secs(7),
                "cap = 8 x 500 ms: {elapsed:?}"
            );
        });
    }

    /// Receiver side: a long blocking step raced with the keep-alive pinger
    /// keeps the peer fed at the cadence (and drains the socket) until the
    /// step completes; the step's result is returned unchanged.
    #[test]
    fn long_blocking_step_keeps_pinging_the_peer_over_real_udp() {
        block_on(async {
            let cx = Cx::for_testing();
            let config = QuicConfig::default();
            let (mut client, mut server) = established_loopback_links(&cx, &config).await;
            let mut server_control =
                NativeQuicFrameTransport::for_stream(super::super::first_client_bidi_stream());
            let work = async {
                let started = crate::runtime::spawn_blocking_io(|| {
                    std::thread::sleep(Duration::from_millis(1100));
                    Ok::<Instant, std::io::Error>(Instant::now())
                })
                .await
                .expect("blocking step");
                Ok::<Instant, QuicTransportError>(started)
            };
            let server_side = async {
                let began = Instant::now();
                let finished = keep_peer_alive_while(&cx, &mut server, &mut server_control, work)
                    .await
                    .expect("raced step result");
                (began, finished)
            };
            let client_listener = async {
                let started = Instant::now();
                let mut packets = 0usize;
                while started.elapsed() < Duration::from_millis(1700) {
                    packets += client
                        .pump_inbound_for(&cx, Duration::from_millis(200))
                        .await
                        .unwrap();
                }
                packets
            };
            let ((began, finished), packets) = zip(server_side, client_listener).await;
            assert!(finished.saturating_duration_since(began) >= Duration::from_millis(1000));
            assert!(
                (4..=8).contains(&packets),
                "expected roughly one keep-alive per 200 ms over 1.1 s, got {packets}"
            );
        });
    }

    /// asupersync-nnm3gw (review MEDIUMs 1 and 3): a refusing receiver waits
    /// its whole bound for the sender's Close however busy the sender is, and
    /// sends the Proof alone. This sender keeps the receiver's socket busy and
    /// reads control only at the end, as a v0.4.x source-stream sender does.
    /// Each packet used to end a wait round, so the receiver left within
    /// milliseconds, and the Close it sent behind the Proof made a spray sender
    /// that read both in one pass fail on the Close instead of the reason.
    #[test]
    fn a_refusing_receiver_waits_its_bound_for_a_busy_sender_and_sends_only_the_proof() {
        block_on(async {
            let cx = Cx::for_testing();
            let config = QuicConfig::default();
            let (mut client, mut server) = established_loopback_links(&cx, &config).await;
            let (mut client_control, mut server_control) =
                opened_control_streams(&cx, &mut client, &mut server).await;
            let bound = NEEDMORE_PTO * REFUSAL_CLOSE_WAIT_ROUNDS;
            let receiver = async {
                let started = Instant::now();
                let reason = "nnm3gw test refusal".to_string();
                refuse_transfer_in_band(&cx, &mut server, &mut server_control, reason).await;
                started.elapsed()
            };
            let busy_sender = async {
                let started = Instant::now();
                while started.elapsed() < bound + Duration::from_secs(1) {
                    send_and_flush_native_keep_alive(&cx, &mut client, &mut client_control)
                        .await
                        .unwrap();
                    client
                        .pump_inbound_for(&cx, Duration::from_millis(50))
                        .await
                        .unwrap();
                }
                let mut frames = Vec::new();
                while let Some(frame) = client_control.try_recv(&cx, &mut client.conn).unwrap() {
                    frames.push(frame);
                }
                frames
            };
            let (waited, frames) = zip(receiver, busy_sender).await;
            assert!(
                waited >= bound.saturating_sub(Duration::from_millis(250)),
                "a busy sender cut the refusal wait short: {waited:?} of {bound:?}"
            );
            assert!(waited < bound + Duration::from_secs(2), "{waited:?}");
            let kinds: Vec<FrameType> = frames.iter().map(Frame::frame_type).collect();
            assert_eq!(
                kinds,
                vec![FrameType::Proof],
                "the refusal Proof alone, no Close"
            );
            let receipt = super::super::parse_json::<ReceiveReceipt>(&frames[0]).unwrap();
            assert!(!receipt.committed);
            assert_eq!(receipt.reason.as_deref(), Some("nnm3gw test refusal"));
        });
    }

    /// asupersync-nnm3gw (review MEDIUM 2): a source-stream sender held by its
    /// unacked-bytes cap, with credit to spare, reads control too. A refusing
    /// receiver that has stopped acknowledging leaves a sender exactly there,
    /// and it used to read control only while credit-blocked, so it waited out
    /// its idle timeout without the receiver's reason.
    #[test]
    fn a_sender_held_by_its_unacked_cap_hears_a_refusal() {
        block_on(async {
            let cx = Cx::for_testing();
            let config = QuicConfig {
                idle_timeout: Duration::from_secs(3),
                ..QuicConfig::default()
            };
            let (mut client, mut server) = established_loopback_links(&cx, &config).await;
            let (mut client_control, mut server_control) =
                opened_control_streams(&cx, &mut client, &mut server).await;
            let refusal = ReceiveReceipt {
                committed: false,
                bytes_received: 0,
                files: 0,
                sha_ok: false,
                merkle_ok: false,
                symbols_accepted: 0,
                feedback_rounds: 0,
                decode_count: 0,
                decode_micros: 0,
                reason: Some("nnm3gw unacked refusal".to_string()),
                committed_paths: Vec::new(),
            };
            let proof = super::super::json_frame(FrameType::Proof, &refusal).unwrap();
            server_control.send(&cx, &mut server.conn, &proof).unwrap();
            server.flush(&cx).await.unwrap();
            // No credit minimum, but more bytes in flight than the cap admits.
            client.stream_unacked_bytes = client
                .source_stream_unacked_admission_max()
                .saturating_add(1);
            let stream = client_control.stream;
            let mut early = None;
            let started = Instant::now();
            let result = wait_source_stream_send_admission(
                &cx,
                &mut client,
                &mut client_control,
                &mut early,
                stream,
                0,
                &config,
            )
            .await;
            let elapsed = started.elapsed();
            match result {
                Err(QuicTransportError::Integrity(reason)) => {
                    assert_eq!(reason, "nnm3gw unacked refusal");
                }
                other => {
                    panic!("the held sender must report the refusal: {other:?} after {elapsed:?}")
                }
            }
            assert!(elapsed < Duration::from_secs(2), "{elapsed:?}");
            assert!(early.is_none());
        });
    }
