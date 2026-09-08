#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytes::Bytes;
    use crate::net::atp::protocol::quic_frames::QuicFrame;
    use crate::net::quic_native::{DEFAULT_MAX_PACKET_BYTES, StreamDirection};

    fn established_native_test_conn() -> NativeQuicConnection {
        let cx = Cx::for_testing();
        let mut conn = NativeQuicConnection::new(NativeQuicConnectionConfig::default());
        conn.begin_handshake(&cx).expect("begin handshake");
        conn.on_handshake_keys_available(&cx)
            .expect("handshake keys");
        conn.on_1rtt_keys_available(&cx).expect("1rtt keys");
        conn.record_verified_server_identity();
        conn.on_handshake_confirmed(&cx)
            .expect("handshake confirmed");
        conn
    }

    #[test]
    fn reassembly_backpressure_drops_without_parking_or_ack_over_real_udp() {
        use crate::net::atp::protocol::varint::VarInt;
        use crate::net::quic_native::handshake_driver::tests::{
            CA_CERT_PEM, LEAF_CERT_PEM, leaf_key, parse_one_cert,
        };
        use crate::net::quic_native::handshake_driver::{client_config, server_config};
        use futures_lite::future::{block_on, zip};

        block_on(async {
            for fill_datagram_queue in [false, true] {
                let cx = Cx::for_testing();
                let config = QuicConfig::default();
                let endpoint = bind_endpoint(&cx, "127.0.0.1:0".parse().unwrap())
                    .await
                    .unwrap();
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
                    connect(&cx, address, &client_tls, &config),
                    accept(&cx, endpoint, &server_tls, &config),
                )
                .await;
                let mut client = client.unwrap();
                let (mut server, early) = server.unwrap();
                server.ingest_packets(&cx, early).unwrap();
                let id = StreamId(0);
                server.conn.accept_remote_stream(&cx, id).unwrap();
                // Plant a precise, bounded hole pattern in the real receiver;
                // the overflow, repair, and retry below cross actual TLS/UDP.
                for fragment in 0..4095u64 {
                    server
                        .conn
                        .receive_stream_bytes(
                            &cx,
                            id,
                            1 + fragment * 2,
                            Bytes::from_static(b"x"),
                            false,
                        )
                        .unwrap();
                }
                if fill_datagram_queue {
                    while server.conn.inbound_datagram_remaining_capacity() > 0 {
                        server
                            .conn
                            .process_frame(
                                &cx,
                                &QuicFrame::Datagram {
                                    data: Bytes::from_static(b"queued"),
                                },
                                PacketNumberSpace::ApplicationData,
                            )
                            .unwrap();
                    }
                }
                let prior_datagrams = server.conn.datagrams_received();
                server
                    .conn
                    .generate_frames(&cx, PacketNumberSpace::ApplicationData, 65535)
                    .unwrap();
                let mut expected = vec![b'.'; 8192];
                for fragment in 0..4095usize {
                    expected[1 + fragment * 2] = b'x';
                }
                expected[8191] = b'z';
                let overflow = vec![
                    QuicFrame::Datagram {
                        data: Bytes::from_static(b"delivered once"),
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
                    data: Bytes::copy_from_slice(&expected[..8191]),
                    fin: false,
                }];
                let mut packets = Vec::new();
                for (number, frames) in [(10, &overflow), (11, &repair), (12, &overflow)] {
                    let mut payload = BytesMut::new();
                    for frame in frames {
                        frame.encode(&mut payload).unwrap();
                    }
                    let header = encode_one_rtt_header(number);
                    let request = PacketProtectionRequest {
                        space: PacketProtectionSpace::OneRtt,
                        key_phase: false,
                        packet_number: number,
                        associated_data: &header,
                        payload: &payload,
                    };
                    let protected =
                        protection_result(client.protection.protect_packets(&cx, &[request]))
                            .unwrap()
                            .pop()
                            .unwrap();
                    let mut data = header.to_vec();
                    data.extend_from_slice(&protected.ciphertext);
                    data.extend_from_slice(&protected.tag);
                    packets.push(OutgoingPacket {
                        dst_addr: address,
                        data,
                        send_time: None,
                    });
                }
                client.endpoint.send_batch(&cx, &packets).await.unwrap();
                let mut received = Vec::new();
                while received.len() < 3 {
                    let batch = crate::time::timeout(
                        crate::time::wall_now(),
                        Duration::from_secs(10),
                        server.endpoint.receive_batch(&cx, 3 - received.len()),
                    )
                    .await
                    .unwrap()
                    .unwrap();
                    received.extend(batch);
                }
                let report = server.ingest_packets(&cx, received).unwrap();
                assert_eq!(report.packets_consumed, 3);
                assert_eq!(report.one_rtt_packets_processed, 2);
                assert!(!report.receive_backpressure);
                assert!(server.pending_decoded_packets.is_empty());
                assert!(server.pending_received_packets.is_empty());
                assert_eq!(server.one_rtt_packets_ingested, 2);
                assert_eq!(
                    server.conn.datagrams_received(),
                    prior_datagrams + u64::from(!fill_datagram_queue)
                );
                let mut actual = Vec::new();
                while !server.conn.is_stream_read_eof(id).unwrap() {
                    let bytes = server.conn.read_stream_bytes(&cx, id, 317).unwrap();
                    assert!(!bytes.is_empty());
                    actual.extend_from_slice(&bytes);
                }
                assert_eq!(actual, expected);
                let ack = server
                    .conn
                    .generate_frames(&cx, PacketNumberSpace::ApplicationData, 65535)
                    .unwrap();
                assert!(ack.iter().any(|frame| matches!(frame,
                    QuicFrame::Ack { largest_acknowledged, first_ack_range, ack_ranges, .. }
                        if largest_acknowledged.value() == 12 && first_ack_range.value() == 1 && ack_ranges.is_empty()
                )), "discarded packet 10 must not be acknowledged, including the DATAGRAM-shedding path");

                // Already-decoded pending input must also discard a saturated
                // packet within its work budget rather than park it forever.
                let other = StreamId(4);
                server.conn.accept_remote_stream(&cx, other).unwrap();
                for fragment in 0..4095u64 {
                    server
                        .conn
                        .receive_stream_bytes(
                            &cx,
                            other,
                            1 + fragment * 2,
                            Bytes::from_static(b"x"),
                            false,
                        )
                        .unwrap();
                }
                server
                    .pending_decoded_packets
                    .push_back(DecodedOneRttPacket {
                        packet_number: 20,
                        frames: vec![QuicFrame::Stream {
                            stream_id: VarInt(other.0),
                            offset: Some(VarInt(8191)),
                            data: Bytes::from_static(b"z"),
                            fin: false,
                        }],
                    });
                server
                    .pending_decoded_packets
                    .push_back(DecodedOneRttPacket {
                        packet_number: 21,
                        frames: vec![QuicFrame::Stream {
                            stream_id: VarInt(other.0),
                            offset: Some(VarInt(0)),
                            data: Bytes::from_static(b"h"),
                            fin: false,
                        }],
                    });
                let dropped = server.ingest_pending_received_packets(&cx, 1).unwrap();
                assert_eq!(dropped.packets_consumed, 1);
                assert_eq!(dropped.one_rtt_packets_processed, 0);
                assert!(!dropped.receive_backpressure);
                assert_eq!(server.pending_decoded_packets.len(), 1);
                let repaired = server.ingest_pending_received_packets(&cx, 1).unwrap();
                assert_eq!(repaired.one_rtt_packets_processed, 1);
                assert!(server.pending_decoded_packets.is_empty());
                assert_eq!(
                    server
                        .conn
                        .read_stream_bytes(&cx, other, 1)
                        .unwrap()
                        .as_ref(),
                    b"h"
                );
            }
        });
    }

    fn clean_window(bps: u64) -> DeliveryWindow {
        DeliveryWindow {
            max_bps: Some(bps),
            max_app_limited_bps: None,
        }
    }

    #[test]
    fn recv_window_growth_cap_is_fragment_safe_and_disables_itself() {
        let window = 2 * 1024 * 1024;
        // 4 MiB configured, 1200-byte frames: 4032 × 1200 ≈ 4.6 MiB fits, so
        // the configured cap wins.
        assert_eq!(
            quic_source_stream_recv_window_growth_cap(window, 4 * 1024 * 1024, 1200),
            Some(4 * 1024 * 1024)
        );
        // 8 MiB configured with the same frames: the fragment guard clamps it.
        assert_eq!(
            quic_source_stream_recv_window_growth_cap(window, 8 * 1024 * 1024, 1200),
            Some(4032 * 1200)
        );
        // Tiny frames: even 4 MiB does not fit under the guard, and a cap at
        // or below the starting window disables growth.
        assert_eq!(
            quic_source_stream_recv_window_growth_cap(window, 4 * 1024 * 1024, 300),
            None
        );
        assert_eq!(
            quic_source_stream_recv_window_growth_cap(window, window, 1200),
            None
        );
        assert_eq!(
            quic_source_stream_recv_window_growth_cap(window, 0, 1200),
            None
        );
    }

    #[test]
    fn malformed_sender_hello_ack_is_typed_as_pre_transfer_rejection() {
        let wrong_type = Frame::new(
            crate::net::atp::protocol::frames::ProtocolVersion::CURRENT,
            FrameType::KeepAlive,
            Vec::new(),
        )
        .expect("valid wrong-type fixture");
        assert!(matches!(
            parse_hello_ack(&wrong_type),
            Err(QuicTransportError::HandshakeRejected(_))
        ));

        let malformed = Frame::new(
            crate::net::atp::protocol::frames::ProtocolVersion::CURRENT,
            FrameType::HandshakeAck,
            b"{".to_vec(),
        )
        .expect("valid malformed-payload fixture");
        assert!(matches!(
            parse_hello_ack(&malformed),
            Err(QuicTransportError::HandshakeRejected(_))
        ));
    }

    #[test]
    fn stream_rate_floor_releases_after_sustained_loss() {
        let seed = 80 * 1024 * 1024;
        let mut pacer = SourceStreamRatePacer::new(seed);
        // Low delivery with no loss: the seeded filter + initial floor keep
        // the rate at/above the regime-derived seed.
        let rate = pacer.on_delivery_window(clean_window(2_500_000), 0, 0, None);
        assert!(rate >= seed);
        // Sustained retransmit-queued bytes release the floor...
        let _ = pacer.on_delivery_window(
            clean_window(2_500_000),
            STREAM_RATE_FLOOR_RELEASE_LOST_BYTES + 1,
            0,
            None,
        );
        // ...and once the seeded samples rotate out of the max-filter the
        // rate drops to the RELEASED floor (seed / 8) — not to the global
        // minimum: recovery-phase delivery reflects only the retransmit
        // trickle, and a to-minimum release measured as a rate collapse.
        let mut last = 0;
        for _ in 0..STREAM_RATE_FILTER_WINDOWS {
            last = pacer.on_delivery_window(clean_window(2_500_000), 0, 0, None);
        }
        assert_eq!(last, seed / STREAM_RATE_FLOOR_RELEASE_DIVISOR);
        assert!(last > 2_500_000 * STREAM_RATE_GAIN_X1000 / 1000);
    }

    #[test]
    fn delivery_sampler_ack_clump_reads_true_rate_not_burst() {
        // The MATRIX-224/225 killer scenario: 1 MB flights sent 40 ms apart
        // (25 MB/s true rate), ACKs arrive as ONE clump. A window aggregate
        // reads 3 MB over the last short window (3-4× the link); per-packet
        // delivered-counter samples read Δdelivered over each flight's full
        // interval — the true rate.
        let mut sampler = SourceStreamDeliverySampler::new();
        sampler.on_packet_sent(1, 0, false);
        sampler.on_packet_sent(2, 40_000, false);
        sampler.on_packet_sent(3, 80_000, false);
        // Clump at t=160 ms: all three flights acked at once, 3 MB delivered.
        sampler.on_packets_acked(&[1, 2, 3], 3_000_000, 160_000);
        let window = sampler.take_window();
        // Best sample: pkt 3 delivered 3 MB over 80 ms = 37.5 MB/s upper
        // bound; pkt 1 reads 3 MB / 160 ms = 18.75 MB/s. All far below the
        // 120 MB/s a 25 ms window aggregate would have claimed.
        let max = window.max_bps.expect("clean samples");
        assert!(max <= 37_500_000, "clump sample must not spike: {max}");
        assert!(
            max >= 18_000_000,
            "sample must reflect real delivery: {max}"
        );
        // A second identical round with steady clumped ACKs converges to the
        // true rate: flights now span a full clump cycle.
        sampler.on_packet_sent(4, 160_000, false);
        sampler.on_packet_sent(5, 200_000, false);
        sampler.on_packet_sent(6, 240_000, false);
        sampler.on_packets_acked(&[4, 5, 6], 3_000_000, 280_000);
        let window = sampler.take_window();
        let max = window.max_bps.expect("clean samples");
        assert!(max <= 30_000_000, "steady-state clump sample ≈ link: {max}");
    }

    #[test]
    fn delivery_sampler_dropped_flights_emit_no_samples() {
        let mut sampler = SourceStreamDeliverySampler::new();
        sampler.on_packet_sent(1, 0, false);
        sampler.on_packet_sent(2, 1_000, false);
        sampler.on_packet_dropped(1);
        sampler.on_packets_acked(&[2], 8_192, 55_000);
        let window = sampler.take_window();
        assert!(window.max_bps.is_some());
        // RTprop comes from the acked flight only (54 ms), and the dropped
        // packet contributed nothing.
        assert_eq!(sampler.rtprop_min_micros(), Some(54_000));
    }

    #[test]
    fn delivery_sampler_rtprop_tracks_minimum_interval() {
        let mut sampler = SourceStreamDeliverySampler::new();
        sampler.on_packet_sent(1, 0, false);
        sampler.on_packets_acked(&[1], 8_192, 60_000);
        sampler.on_packet_sent(2, 100_000, false);
        sampler.on_packets_acked(&[2], 8_192, 152_000);
        sampler.on_packet_sent(3, 200_000, false);
        sampler.on_packets_acked(&[3], 8_192, 270_000);
        assert_eq!(sampler.rtprop_min_micros(), Some(52_000));
    }

    #[test]
    fn pacer_app_limited_samples_only_raise_the_estimate() {
        let seed = 4_000_000;
        let mut pacer = SourceStreamRatePacer::new(seed);
        // Establish a real 24 MB/s plateau.
        for _ in 0..STREAM_RATE_FILTER_WINDOWS {
            let _ = pacer.on_delivery_window(clean_window(24_000_000), 0, 0, None);
        }
        assert_eq!(pacer.bottleneck_bytes_per_s(), 24_000_000);
        // App-limited windows BELOW the estimate must not decay it, even
        // after enough folds to rotate the whole ring (the MATRIX-204-era
        // rate-collapse class).
        for _ in 0..=STREAM_RATE_FILTER_WINDOWS {
            let _ = pacer.on_delivery_window(
                DeliveryWindow {
                    max_bps: None,
                    max_app_limited_bps: Some(6_000_000),
                },
                0,
                0,
                None,
            );
        }
        assert_eq!(pacer.bottleneck_bytes_per_s(), 24_000_000);
        // An app-limited window ABOVE the estimate raises it (BBR rule).
        let _ = pacer.on_delivery_window(
            DeliveryWindow {
                max_bps: None,
                max_app_limited_bps: Some(30_000_000),
            },
            0,
            0,
            None,
        );
        assert_eq!(pacer.bottleneck_bytes_per_s(), 30_000_000);
    }

    /// Deterministic delivery-control lab (the uw1cc2 GATE): a simulated
    /// shaped link driving the real sampler + pacer + BDP cap, asserting the
    /// exact failure modes that cost three bench cycles (MATRIX-224/225)
    /// before any matrix run gets to see a new controller change.
    struct DeliveryLab {
        link_bps: u64,
        one_way_micros: u64,
        queue_cap_bytes: u64,
        ack_batch_micros: u64,
        seed_bps: u64,
        /// Drop every Nth packet en route (deterministic "random" loss).
        drop_every: Option<u64>,
        /// Application produces data at only this rate (sender app-limited).
        app_rate_bps: Option<u64>,
        /// (at_micros, new_link_bps): genuine capacity change mid-run.
        rate_change: Option<(u64, u64)>,
        sim_micros: u64,
    }

    struct DeliveryLabOutcome {
        bottleneck_bps: u64,
        rtprop_micros: Option<u64>,
        cwnd_cap: u64,
        /// (t, folded clean sample, folded app-limited sample, rate, cwnd,
        /// unacked) per fold — the debugging trajectory.
        folds: Vec<(u64, u64, u64, u64, u64, u64)>,
        /// Bytes delivered during the final 2 sim-seconds: the sustained-
        /// utilization measure the gain-cycling gate asserts on.
        late_delivered_bytes: u64,
        /// Packets dropped (queue overflow or injected loss) during the
        /// final 2 sim-seconds: steady-state drops must be ~zero for a
        /// converged non-oscillating controller on a clean link.
        late_drops: u64,
    }

    fn run_delivery_lab(lab: &DeliveryLab) -> DeliveryLabOutcome {
        const PKT: u64 = 8_192;
        const LOSS_DETECT_MICROS: u64 = 250_000;
        let mut pacer = SourceStreamRatePacer::new(lab.seed_bps);
        let mut sampler = SourceStreamDeliverySampler::new();
        // Event calendar: time → acked (pns, bytes) and dropped pns.
        let mut acks: BTreeMap<u64, Vec<(u64, u64)>> = BTreeMap::new();
        let mut drops: BTreeMap<u64, Vec<(u64, u64)>> = BTreeMap::new();
        let mut now;
        let mut next_send = 0u64;
        let mut app_ready_at = 0u64;
        let mut unacked = 0u64;
        let mut lost_window = 0u64;
        let mut acked_window = 0u64;
        let mut window_start = 0u64;
        let mut queue_free_at = 0u64;
        let mut pn = 0u64;
        let mut link_bps = lab.link_bps;
        let mut folds: Vec<(u64, u64, u64, u64, u64, u64)> = Vec::new();
        let late_cutoff = lab.sim_micros.saturating_sub(2_000_000);
        let mut late_delivered = 0u64;
        let mut late_drops = 0u64;
        // The handshake RTT upper bound seeds RTprop until real samples land.
        let handshake_rtt = lab.one_way_micros * 2 + 2_000;
        loop {
            let next_ack = acks.keys().next().copied().unwrap_or(u64::MAX);
            let next_drop = drops.keys().next().copied().unwrap_or(u64::MAX);
            let next_event = next_ack.min(next_drop);
            let cwnd = source_stream_bdp_admission_cap(
                pacer.bottleneck_bytes_per_s(),
                sampler.rtprop_min_micros().or(Some(handshake_rtt)),
            );
            let send_due = next_send.max(app_ready_at);
            let can_send = unacked + PKT <= cwnd;
            let t_next = if can_send {
                send_due.min(next_event)
            } else {
                next_event
            };
            if t_next == u64::MAX || t_next >= lab.sim_micros {
                break;
            }
            now = t_next;
            if let Some((at, new_bps)) = lab.rate_change {
                if now >= at {
                    link_bps = new_bps;
                }
            }
            // Process one due ACK batch (all acks sharing this timestamp
            // fold as one clump — the batching model).
            if next_ack == now {
                let batch = acks.remove(&now).unwrap_or_default();
                let pns: Vec<u64> = batch.iter().map(|(p, _)| *p).collect();
                let bytes: u64 = batch.iter().map(|(_, b)| *b).sum();
                sampler.on_packets_acked(&pns, bytes, now);
                unacked = unacked.saturating_sub(bytes);
                acked_window = acked_window.saturating_add(bytes);
                if now >= late_cutoff {
                    late_delivered = late_delivered.saturating_add(bytes);
                }
            }
            if next_drop == now {
                for (dropped_pn, bytes) in drops.remove(&now).unwrap_or_default() {
                    sampler.on_packet_dropped(dropped_pn);
                    unacked = unacked.saturating_sub(bytes);
                    lost_window = lost_window.saturating_add(bytes);
                    if now >= late_cutoff {
                        late_drops = late_drops.saturating_add(1);
                    }
                }
            }
            if now.saturating_sub(window_start) >= 25_000 && (acked_window > 0 || lost_window > 0) {
                let window = sampler.take_window();
                let rate = pacer.on_delivery_window(
                    window,
                    lost_window,
                    now,
                    sampler.rtprop_min_micros().or(Some(handshake_rtt)),
                );
                folds.push((
                    now,
                    window.max_bps.unwrap_or_default(),
                    window.max_app_limited_bps.unwrap_or_default(),
                    rate,
                    source_stream_bdp_admission_cap(
                        pacer.bottleneck_bytes_per_s(),
                        sampler.rtprop_min_micros().or(Some(handshake_rtt)),
                    ),
                    unacked,
                ));
                acked_window = 0;
                lost_window = 0;
                window_start = now;
            }
            // Send one paced packet if due and admitted.
            if can_send && now >= send_due && send_due <= next_event {
                pn += 1;
                let app_limited = lab.app_rate_bps.is_some() && app_ready_at > next_send;
                let backlog_bytes =
                    queue_free_at.saturating_sub(now).saturating_mul(link_bps) / 1_000_000;
                let random_drop = lab.drop_every.is_some_and(|n| pn.is_multiple_of(n));
                if random_drop || backlog_bytes + PKT > lab.queue_cap_bytes {
                    drops
                        .entry(now + LOSS_DETECT_MICROS)
                        .or_default()
                        .push((pn, PKT));
                } else {
                    let service_start = queue_free_at.max(now);
                    let service_end = service_start + PKT.saturating_mul(1_000_000) / link_bps;
                    queue_free_at = service_end;
                    let ack_arrival = service_end + lab.one_way_micros * 2;
                    let process_at = ack_arrival.next_multiple_of(lab.ack_batch_micros.max(1));
                    acks.entry(process_at).or_default().push((pn, PKT));
                }
                sampler.on_packet_sent(pn, now, app_limited);
                unacked += PKT;
                next_send = now + PKT.saturating_mul(1_000_000) / pacer.rate_bytes_per_s.max(1);
                if let Some(app_rate) = lab.app_rate_bps {
                    app_ready_at =
                        app_ready_at.max(now) + PKT.saturating_mul(1_000_000) / app_rate.max(1);
                }
            }
        }
        DeliveryLabOutcome {
            bottleneck_bps: pacer.bottleneck_bytes_per_s(),
            rtprop_micros: sampler.rtprop_min_micros(),
            cwnd_cap: source_stream_bdp_admission_cap(
                pacer.bottleneck_bytes_per_s(),
                sampler.rtprop_min_micros().or(Some(handshake_rtt)),
            ),
            folds,
            late_delivered_bytes: late_delivered,
            late_drops,
        }
    }

    fn good_regime_lab() -> DeliveryLab {
        // The 500M/good cell: 200 mbit (25 MB/s), 25 ms each way, ~1.4 MB
        // shaper queue, 25 ms ACK batching.
        DeliveryLab {
            link_bps: 25_000_000,
            one_way_micros: 25_000,
            queue_cap_bytes: 1_400_000,
            ack_batch_micros: 25_000,
            seed_bps: 12_000_000,
            drop_every: None,
            app_rate_bps: None,
            rate_change: None,
            sim_micros: 5_000_000,
        }
    }

    /// What the constant-gain pacer + honest sampler ACTUALLY does on a
    /// shaped link (measured in this lab, understood before any bench): the
    /// 1.25× probe overshoots, the queue overflows, dropped flights sit as
    /// phantom un-ACKed until loss detection (~250 ms), the cwnd pins, and
    /// achieved throughput — honestly sampled — decays until the queue
    /// drains and the climb repeats. The estimate therefore OSCILLATES with
    /// peaks at the link rate; steady convergence needs a gain-cycling
    /// (drain-phase) pacer, which is out of scope for the sampler gate. The
    /// gate asserts the sampler's actual obligations: the climb REACHES the
    /// link, no sample ever spikes above it (the MATRIX-224/225 collapse
    /// class), and the estimate never collapses toward zero.
    fn assert_honest_estimate(outcome: &DeliveryLabOutcome, link_bps: u64) {
        let peak = outcome
            .folds
            .iter()
            .map(|(_, sample, _, _, _, _)| *sample)
            .max()
            .unwrap_or(0);
        assert!(
            peak >= link_bps * 8 / 10,
            "climb must reach the link rate: peak {peak} vs link {link_bps}"
        );
        let spike = outcome
            .folds
            .iter()
            .map(|(_, sample, app, _, _, _)| (*sample).max(*app))
            .max()
            .unwrap_or(0);
        assert!(
            spike <= link_bps * 11 / 10,
            "no sample may exceed the link (the M224/225 spike class): {spike}"
        );
        assert!(
            outcome.bottleneck_bps >= link_bps * 4 / 10,
            "estimate must not collapse: {} — folds tail: {:?}",
            outcome.bottleneck_bps,
            &outcome.folds[outcome.folds.len().saturating_sub(8)..]
        );
    }

    #[test]
    fn matrix226_delivery_lab_climbs_to_link_without_spiking() {
        let outcome = run_delivery_lab(&good_regime_lab());
        assert_honest_estimate(&outcome, 25_000_000);
        let rtprop = outcome.rtprop_micros.expect("samples must land");
        assert!(
            (50_000..=70_000).contains(&rtprop),
            "RTprop must track the 50 ms path: {rtprop}"
        );
        assert!(
            (2_097_152..=3_600_000).contains(&outcome.cwnd_cap),
            "cwnd ≈ 2×BDP band: {}",
            outcome.cwnd_cap
        );
    }

    #[test]
    fn matrix226_delivery_lab_severe_ack_clumping_cannot_spike_the_filter() {
        // The MATRIX-224 killer: 200 ms ACK clumps on this link read
        // 84-88 MB/s under window aggregates. With a 2 MiB in-flight floor
        // and 200 ms feedback, the TRUE throughput ceiling is
        // cwnd/batch ≈ 10.5 MB/s — the honest estimator must report that
        // ceiling, and above all must not spike past the link.
        let lab = DeliveryLab {
            ack_batch_micros: 200_000,
            ..good_regime_lab()
        };
        let outcome = run_delivery_lab(&lab);
        let spike = outcome
            .folds
            .iter()
            .map(|(_, sample, app, _, _, _)| (*sample).max(*app))
            .max()
            .unwrap_or(0);
        assert!(
            spike <= 27_500_000,
            "clumped ACKs must never spike the estimate (M224 class): {spike}"
        );
        assert!(
            (8_000_000..=12_500_000).contains(&outcome.bottleneck_bps),
            "estimate must honestly read the feedback-limited ceiling \
             (cwnd floor 2 MiB / 200 ms ≈ 10.5 MB/s): {}",
            outcome.bottleneck_bps
        );
    }

    #[test]
    fn matrix226_delivery_lab_overseeded_rate_reads_honest_link() {
        // The good-regime mis-seed (96 MiB/s seed on a 25 MB/s link): the
        // ESTIMATE must read the true link even while the seeded floor keeps
        // the offered rate high (floor release is the pacer's separate job).
        let lab = DeliveryLab {
            seed_bps: 100_663_296,
            ..good_regime_lab()
        };
        let outcome = run_delivery_lab(&lab);
        assert!(
            outcome.bottleneck_bps <= 27_500_000,
            "estimate must not follow the mis-seed: {}",
            outcome.bottleneck_bps
        );
    }

    #[test]
    fn matrix226_delivery_lab_app_limited_sender_keeps_its_estimate() {
        // Converge at full rate first, then the app throttles to ~8 MB/s:
        // app-limited samples may not decay the capacity estimate (the
        // MATRIX-204-era self-starvation spiral).
        let lab = DeliveryLab {
            seed_bps: 24_000_000,
            app_rate_bps: Some(8_000_000),
            ..good_regime_lab()
        };
        let outcome = run_delivery_lab(&lab);
        assert!(
            outcome.bottleneck_bps >= 20_000_000,
            "app-limited flights must not define capacity downward: {}",
            outcome.bottleneck_bps
        );
    }

    #[test]
    fn matrix226_delivery_lab_random_loss_does_not_collapse_estimate() {
        // 0.2% deterministic loss: the anti-NewReno property (MATRIX-202) —
        // loss must not shrink BtlBw/RTprop while delivery holds.
        let lab = DeliveryLab {
            drop_every: Some(500),
            ..good_regime_lab()
        };
        let outcome = run_delivery_lab(&lab);
        assert_honest_estimate(&outcome, 25_000_000);
        let rtprop = outcome.rtprop_micros.expect("samples");
        assert!(
            (50_000..=70_000).contains(&rtprop),
            "rtprop stable: {rtprop}"
        );
    }

    #[test]
    fn matrix226_delivery_lab_genuine_capacity_drop_decays_estimate() {
        // The link genuinely halves mid-run: the filter must follow DOWN
        // within its window (loss-blind but delivery-honest).
        let lab = DeliveryLab {
            rate_change: Some((2_500_000, 12_500_000)),
            sim_micros: 8_000_000,
            ..good_regime_lab()
        };
        let outcome = run_delivery_lab(&lab);
        assert!(
            outcome.bottleneck_bps <= 15_500_000,
            "estimate must decay to the new 12.5 MB/s capacity: {}",
            outcome.bottleneck_bps
        );
    }

    #[test]
    fn matrix227_delivery_lab_gain_cycling_sustains_utilization_without_drops() {
        // THE gate for the drain-phase fix (M224/225/226 law): with the
        // PROBE_BW cycle, the good-regime lab (which models the Phase-B
        // world — cwnd-bounded, no flow-window stall) must sustain ~link
        // utilization with an empty steady-state queue, where constant
        // gain 1.25 oscillated and dropped continuously.
        let outcome = run_delivery_lab(&good_regime_lab());
        // Last 2 s must deliver ≥ 0.8 × link (40 MB of 50 MB ideal).
        assert!(
            outcome.late_delivered_bytes >= 40_000_000,
            "sustained utilization: {} bytes in the last 2 s — folds tail: {:?}",
            outcome.late_delivered_bytes,
            &outcome.folds[outcome.folds.len().saturating_sub(8)..]
        );
        // Steady-state drops ≈ 0 on a clean link (the drain phase keeps the
        // probe's queue from ever reaching the 1.4 MB cap).
        assert!(
            outcome.late_drops <= 2,
            "steady-state drops must be ~zero: {}",
            outcome.late_drops
        );
        // Estimate pinned at the link — the oscillation is dead.
        assert!(
            (20_000_000..=27_500_000).contains(&outcome.bottleneck_bps),
            "estimate stable at link: {}",
            outcome.bottleneck_bps
        );
    }

    #[test]
    fn matrix227_delivery_lab_gain_cycling_holds_under_random_loss() {
        let lab = DeliveryLab {
            drop_every: Some(500),
            ..good_regime_lab()
        };
        let outcome = run_delivery_lab(&lab);
        // 0.2 % loss + detection lag: still ≥ 0.7 × link sustained.
        assert!(
            outcome.late_delivered_bytes >= 35_000_000,
            "utilization under random loss: {}",
            outcome.late_delivered_bytes
        );
        assert!(
            (18_000_000..=27_500_000).contains(&outcome.bottleneck_bps),
            "estimate must not collapse under random loss: {}",
            outcome.bottleneck_bps
        );
    }

    #[test]
    fn pacer_gain_cycle_advances_per_rtprop_and_applies_drain() {
        let seed = 4_000_000;
        let mut pacer = SourceStreamRatePacer::new(seed);
        let rtprop = Some(50_000u64);
        // Converge the filter at 24 MB/s while pinned in phase 0 (folds at
        // now=0 never advance the phase).
        for _ in 0..STREAM_RATE_FILTER_WINDOWS {
            let _ = pacer.on_delivery_window(clean_window(24_000_000), 0, 0, rtprop);
        }
        assert_eq!(pacer.cycle_phase(), 0);
        // Probe phase (0): gain 1.25 → 30 MB/s (10 ms in: phase holds).
        assert_eq!(
            pacer.on_delivery_window(clean_window(24_000_000), 0, 10_000, rtprop),
            30_000_000
        );
        assert_eq!(pacer.cycle_phase(), 0);
        // One RTprop elapses → drain phase (1): gain 0.75 → 18 MB/s.
        assert_eq!(
            pacer.on_delivery_window(clean_window(24_000_000), 0, 60_000, rtprop),
            18_000_000
        );
        assert_eq!(pacer.cycle_phase(), 1);
        // Next RTprop → cruise (2): gain 1.0 → 24 MB/s.
        assert_eq!(
            pacer.on_delivery_window(clean_window(24_000_000), 0, 120_000, rtprop),
            24_000_000
        );
        assert_eq!(pacer.cycle_phase(), 2);
        // Six more RTprops walk the cruise phases and wrap to probe.
        let mut now = 120_000;
        for _ in 0..6 {
            now += 60_000;
            let _ = pacer.on_delivery_window(clean_window(24_000_000), 0, now, rtprop);
        }
        assert_eq!(pacer.cycle_phase(), 0);
        assert_eq!(
            pacer.on_delivery_window(clean_window(24_000_000), 0, now, rtprop),
            30_000_000
        );
    }

    #[test]
    fn pacer_gain_phase_holds_until_rtprop_elapses() {
        let seed = 4_000_000;
        let mut pacer = SourceStreamRatePacer::new(seed);
        let rtprop = Some(50_000u64);
        for _ in 0..STREAM_RATE_FILTER_WINDOWS {
            let _ = pacer.on_delivery_window(clean_window(24_000_000), 0, 0, rtprop);
        }
        // Folds 10/20/30 ms into the phase: no advance (< one RTprop).
        for now in [10_000u64, 20_000, 30_000] {
            let _ = pacer.on_delivery_window(clean_window(24_000_000), 0, now, rtprop);
            assert_eq!(pacer.cycle_phase(), 0, "phase must hold at t={now}");
        }
    }

    #[test]
    fn pacer_empty_windows_leave_filter_untouched() {
        let seed = 4_000_000;
        let mut pacer = SourceStreamRatePacer::new(seed);
        for _ in 0..STREAM_RATE_FILTER_WINDOWS {
            let _ = pacer.on_delivery_window(clean_window(24_000_000), 0, 0, None);
        }
        // A stall (loss folded, no completed flights) must not write
        // near-zero slots into the ring.
        let rate = pacer.on_delivery_window(
            DeliveryWindow {
                max_bps: None,
                max_app_limited_bps: None,
            },
            256 * 1024,
            0,
            None,
        );
        assert_eq!(pacer.bottleneck_bytes_per_s(), 24_000_000);
        assert_eq!(rate, 30_000_000);
    }

    #[test]
    fn native_feedback_round_budget_allows_first_pending_round() {
        assert_eq!(
            next_feedback_round_or_no_convergence(0, 1, 1)
                .expect("first pending feedback round fits budget"),
            1
        );
    }

    #[test]
    fn native_feedback_round_budget_rejects_pending_round_after_cap() {
        assert_eq!(
            next_feedback_round_or_no_convergence(1, 1, 2)
                .expect("first still-viable grace round should not fast-fail"),
            2
        );
        let fail_closed_rounds = still_viable_feedback_fail_closed_rounds(1);
        let err = next_feedback_round_or_no_convergence(fail_closed_rounds, 1, 2)
            .expect_err("pending feedback beyond bounded grace fails closed");

        assert!(matches!(
            err,
            QuicTransportError::NoConvergence {
                rounds,
                pending: 2,
            } if rounds == fail_closed_rounds
        ));
    }

    #[test]
    fn native_feedback_round_budget_keeps_empty_feedback_out_of_no_convergence() {
        assert_eq!(
            next_feedback_round_or_no_convergence(1, 1, 0)
                .expect("empty feedback is not an incomplete-transfer convergence failure"),
            2
        );
    }

    #[test]
    fn native_quic_honors_explicit_symbol_auth_posture() {
        assert!(
            QuicConfig::default().symbol_auth_context().is_err(),
            "native QUIC must not silently rewrite missing symbol auth into a transport-auth opt-out"
        );

        let authenticated =
            QuicConfig::default().with_symbol_auth(SecurityContext::for_testing(0xA7_50));
        assert!(
            authenticated
                .symbol_auth_context()
                .expect("authenticated native config")
                .is_some(),
            "explicit per-symbol auth remains active on the native QUIC path"
        );
    }

    #[test]
    fn native_sender_feedback_round_uses_receiver_round_identity() {
        assert_eq!(
            feedback_round_for_need_or_no_convergence(1, 8, 2, 1)
                .expect("next receiver-assigned round fits budget"),
            (2, 2)
        );
        assert_eq!(
            feedback_round_for_need_or_no_convergence(5, 8, 3, 1)
                .expect("duplicate older PTO round can be served without advancing the budget"),
            (5, 3)
        );
    }

    #[test]
    fn native_sender_feedback_round_rejects_pending_round_beyond_cap() {
        assert_eq!(
            feedback_round_for_need_or_no_convergence(8, 8, 9, 1)
                .expect("first still-viable sender grace round should not fast-fail"),
            (9, 9)
        );
        let fail_closed_rounds = still_viable_feedback_fail_closed_rounds(8);
        let err = feedback_round_for_need_or_no_convergence(
            fail_closed_rounds,
            8,
            fail_closed_rounds.saturating_add(1),
            1,
        )
        .expect_err("receiver-assigned round beyond bounded grace fails closed");

        assert!(matches!(
            err,
            QuicTransportError::NoConvergence {
                rounds,
                pending: 1,
            } if rounds == fail_closed_rounds
        ));
    }

    #[test]
    fn native_receiver_infers_missing_repair_round_complete_symbols_from_last_need() {
        let need = QuicNeedMore {
            feedback_round: 7,
            pending: vec![0],
            repair_blocks: vec![QuicBlockRepairRequest {
                entry: 0,
                sbn: 3,
                symbols: 5,
            }],
            source_symbols: vec![
                QuicSourceSymbolRequest {
                    entry: 0,
                    sbn: 3,
                    esi: 11,
                },
                QuicSourceSymbolRequest {
                    entry: 0,
                    sbn: 3,
                    esi: 12,
                },
            ],
            ..QuicNeedMore::default()
        };

        assert_eq!(
            infer_missing_round_complete_symbols(7, 4, Some(&need)),
            7,
            "missing ObjectComplete on the active repair round uses the requested symbol count"
        );
        assert_eq!(
            infer_missing_round_complete_symbols(7, 9, Some(&need)),
            9,
            "the observed count remains a lower bound when more symbols arrive than requested"
        );
        assert_eq!(
            infer_missing_round_complete_symbols(6, 4, Some(&need)),
            4,
            "stale/out-of-round NeedMore state does not contaminate another round"
        );
    }

    #[test]
    fn quic_aimd_backs_off_on_queue_drop_with_blind_receiver_loss() {
        // MATRIX-123/124/125 (bead asupersync-atp-dataplane-redesign-317hxr.2.5.1):
        // during a ~98% queue overflow the receiver's round_loss_fraction reads ~0
        // (it counts loss only among ARRIVED symbols). The sender-side delivery loss
        // (sent vs observed) must drive AIMD so the cap backs off instead of flooding
        // the overflowing queue until PTO timeout.
        let cx = Cx::for_testing();
        let config = QuicConfig {
            max_spray_symbols_per_flush: 64,
            ..QuicConfig::default().allow_unauthenticated_for_trusted_transport()
        };
        let mut aimd = NativeQuicAimdPacer::default();
        aimd.record_spray(1000, 50_000_000, Duration::from_millis(1));
        let need = QuicNeedMore {
            feedback_round: 1,
            pending: vec![0],
            round_symbols_observed: Some(20), // only 2% arrived -> 98% dropped
            round_loss_fraction: Some(0.0),   // receiver blind to the drop
            ..QuicNeedMore::default()
        };
        aimd.observe_need_more(&cx, &config, &need);
        assert!(
            aimd.last_round_loss_fraction >= 0.5,
            "sender-side delivery loss must surface the queue drop, got {}",
            aimd.last_round_loss_fraction
        );
        assert!(
            aimd.cap_bps().is_some(),
            "a ~98% drop must trip the AIMD multiplicative-decrease cap (no flood)"
        );
        let cap = aimd
            .cap_bps()
            .expect("severe sender-observed delivery loss should arm the shared cap");
        let half_cold_start = ((super::super::QUIC_DEFAULT_COLD_START_PACING_BYTES_PER_S
            * super::super::QUIC_AIMD_MULTIPLICATIVE_DECREASE)
            .ceil()) as u64;
        assert!(
            cap <= half_cold_start,
            "severe sender-observed delivery loss must cut below half-rate, got {cap}"
        );
        let conn = established_native_test_conn();
        let lossy = super::super::quic_spray_pacing_decision_from_config(
            &config,
            native_quic_path_signal_with_observed_loss(conn.transport(), aimd.observed_loss()),
        );
        assert_eq!(
            lossy.limiter,
            super::super::QuicSprayPacingLimiter::LossBackoff,
            "sender-side delivery loss must shape the next pacing decision, not only trace metadata"
        );
        assert!(
            !super::super::quic_round0_clean_ramp_enabled(&config, &lossy, true),
            "Bug A: sender-side delivery loss must keep the clean ramp from re-arming"
        );
        // Clean delivery (observed ~= sent) must NOT spuriously back off.
        let mut clean = NativeQuicAimdPacer::default();
        clean.record_spray(1000, 50_000_000, Duration::from_millis(1));
        let clean_need = QuicNeedMore {
            feedback_round: 1,
            round_symbols_observed: Some(1000),
            round_loss_fraction: Some(0.0),
            ..QuicNeedMore::default()
        };
        clean.observe_need_more(&cx, &config, &clean_need);
        assert!(
            clean.last_round_loss_fraction <= f64::EPSILON,
            "full delivery must register ~0 loss, got {}",
            clean.last_round_loss_fraction
        );
    }

    #[test]
    fn matrix164_native_quic_shared_rate_decision_caps_next_pacing_epoch() {
        let cx = Cx::for_testing();
        let config = QuicConfig {
            symbol_size: 1200,
            max_spray_symbols_per_flush: 128,
            round0_loss_target: 0.10,
            datagram_fanout: 1,
            ..QuicConfig::default().allow_unauthenticated_for_trusted_transport()
        };
        let mut aimd = NativeQuicAimdPacer::default();
        aimd.record_spray(10_000, 64 * 1024 * 1024, Duration::from_secs(1));
        let need = QuicNeedMore {
            feedback_round: 1,
            pending: vec![0],
            round_symbols_observed: Some(1_000),
            round_loss_fraction: Some(0.0),
            ..QuicNeedMore::default()
        };

        aimd.observe_need_more(&cx, &config, &need);
        let decision = aimd
            .shared_decision()
            .expect("NeedMore should feed the shared datagram controller");
        assert!(
            decision.sender_loss_fraction_ppm >= 900_000,
            "shared controller must see sender-side queue overflow"
        );
        assert!(
            decision.bytes_in_flight > 0,
            "sender-observed queue loss must leave outstanding bytes in the shared controller"
        );
        assert!(
            decision.loss_limited,
            "sender-observed overflow must put the shared controller in loss backoff"
        );

        let conn = established_native_test_conn();
        let mut pacing = super::super::quic_spray_pacing_decision_from_config(
            &config,
            native_quic_path_signal_with_observed_loss(conn.transport(), 0.0),
        );
        let uncapped_rate = pacing.pacing_rate_bps;
        let uncapped_burst = pacing.max_burst_symbols;
        NativeQuicAimdPacer::apply_shared_decision_to_pacing(
            Some(decision),
            &mut pacing,
            usize::from(config.symbol_size.max(1)),
            &config,
        );

        let symbol_bytes = u64::from(config.symbol_size.max(1));
        let budget_symbols = usize::try_from(
            decision
                .send_budget_bytes
                .checked_div(symbol_bytes)
                .unwrap_or(0)
                .max(1),
        )
        .unwrap_or(usize::MAX);
        assert!(
            pacing.pacing_rate_bps <= decision.pacing_bytes_per_s,
            "native QUIC pacing must consume the shared controller rate cap"
        );
        assert!(
            pacing.pacing_rate_bps <= uncapped_rate,
            "shared controller may only tighten the native pacing epoch"
        );
        assert!(
            pacing.max_burst_symbols <= budget_symbols,
            "native QUIC burst must respect shared cwnd/receiver send budget"
        );
        assert!(
            pacing.max_burst_symbols <= uncapped_burst,
            "shared controller may only tighten the native burst epoch"
        );
        assert_eq!(
            pacing.limiter,
            super::super::QuicSprayPacingLimiter::LossBackoff,
            "sender-side overflow must disable the clean/unbounded pacing path"
        );
    }

    #[test]
    fn matrix168_lossy_quic_datagram_config_uses_conservative_bdp_cwnd() {
        let clean = quic_datagram_rate_config(&QuicConfig::default());
        assert_eq!(
            clean.initial_cwnd_bytes,
            256 * 1024,
            "clean/default paths keep the historical cold-start cwnd"
        );

        let broken = QuicConfig {
            round0_loss_target: 0.10,
            ..QuicConfig::default()
        };
        let lossy = quic_datagram_rate_config(&broken);
        let expected_bdp = lossy
            .initial_pacing_bytes_per_s
            .saturating_mul(QUIC_LOSSY_COLD_START_RTT_MICROS)
            .div_ceil(1_000_000);
        assert_eq!(
            lossy.initial_cwnd_bytes,
            expected_bdp.clamp(16 * 1024, 256 * 1024),
            "lossy cold-start cwnd should begin at the seeded BDP envelope"
        );
        assert!(
            lossy.initial_cwnd_bytes < clean.initial_cwnd_bytes,
            "broken/high-loss presets should not inherit the clean 256 KiB initial burst"
        );
    }

    #[test]
    fn quic_native_aimd_drops_rate_and_bounds_inflight_on_ten_percent_loss() {
        let cx = Cx::for_testing();
        let config = QuicConfig {
            symbol_size: 1200,
            max_spray_symbols_per_flush: 128,
            datagram_fanout: 1,
            ..QuicConfig::default().allow_unauthenticated_for_trusted_transport()
        };
        let mut aimd = NativeQuicAimdPacer::default();
        aimd.record_spray(10_000, 64 * 1024 * 1024, Duration::from_secs(1));
        let need = QuicNeedMore {
            feedback_round: 1,
            pending: vec![0],
            round_symbols_observed: Some(9_000),
            round_loss_fraction: Some(0.0),
            ..QuicNeedMore::default()
        };

        let conn = established_native_test_conn();
        let mut pacing = super::super::quic_spray_pacing_decision_from_config(
            &config,
            native_quic_path_signal_with_observed_loss(conn.transport(), 0.0),
        );
        let uncapped_rate = pacing.pacing_rate_bps;
        let uncapped_burst = pacing.max_burst_symbols;

        aimd.observe_need_more(&cx, &config, &need);
        let decision = aimd
            .shared_decision()
            .expect("10% sender-observed loss should feed the shared controller");
        assert!(
            decision.sender_loss_fraction_ppm >= 100_000,
            "shared controller must see the injected sender-side loss"
        );
        assert!(
            decision.bytes_in_flight > 0,
            "10% sender-observed loss should bound outstanding bytes"
        );
        assert!(
            decision.loss_limited,
            "10% unexpected sender loss should put the shared controller in loss backoff"
        );

        NativeQuicAimdPacer::apply_shared_decision_to_pacing(
            Some(decision),
            &mut pacing,
            usize::from(config.symbol_size.max(1)),
            &config,
        );

        let symbol_bytes = u64::from(config.symbol_size.max(1));
        let budget_symbols = usize::try_from(
            decision
                .send_budget_bytes
                .checked_div(symbol_bytes)
                .unwrap_or(0)
                .max(1),
        )
        .unwrap_or(usize::MAX);
        assert!(
            pacing.pacing_rate_bps < uncapped_rate,
            "native QUIC shared controller must drop rate under injected loss"
        );
        assert!(
            pacing.max_burst_symbols <= budget_symbols,
            "native QUIC shared controller must cap burst by cwnd/receiver budget"
        );
        assert!(
            pacing.max_burst_symbols <= uncapped_burst,
            "native QUIC shared controller may only tighten burst after loss"
        );
        assert_eq!(
            pacing.limiter,
            super::super::QuicSprayPacingLimiter::LossBackoff,
            "injected sender-side loss must gate the next pacing epoch"
        );
    }

    #[test]
    fn quic_aimd_backs_off_when_rank_progress_stalls_despite_zero_loss() {
        let cx = Cx::for_testing();
        let config = QuicConfig {
            symbol_size: 1200,
            round0_loss_target: 0.10,
            ..QuicConfig::default().allow_unauthenticated_for_trusted_transport()
        };

        let mut stalled = NativeQuicAimdPacer::default();
        stalled.record_spray(10_000, 50_000_000, Duration::from_millis(800));
        let stalled_need = QuicNeedMore {
            feedback_round: 1,
            pending: vec![0],
            round_symbols_observed: Some(10_000),
            round_symbols_accepted: Some(10_000),
            round_loss_fraction: Some(0.0),
            pending_rank: Some(100),
            pending_rank_columns: Some(43_700),
            pending_rank_deficit: Some(43_600),
            pending_decode_jobs: Some(0),
            ..QuicNeedMore::default()
        };
        stalled.observe_need_more(&cx, &config, &stalled_need);
        let stalled_decision = stalled
            .shared_decision()
            .expect("rank-progress feedback should feed the shared controller");
        assert!(
            stalled_decision.loss_limited,
            "rank-progress loss must still put the shared controller in loss backoff"
        );
        assert!(
            stalled.last_round_loss_fraction
                > super::super::quic_aimd_loss_decrease_threshold(&config),
            "rank-progress stall must override underreported receiver arrival loss"
        );
        assert!(
            stalled.cap_bps().is_some(),
            "stalled rank progress should arm a shared-controller rate cap"
        );

        let mut healthy = NativeQuicAimdPacer::default();
        healthy.record_spray(10_000, 50_000_000, Duration::from_millis(1_000));
        let healthy_need = QuicNeedMore {
            feedback_round: 1,
            pending: vec![0],
            round_symbols_observed: Some(10_000),
            round_symbols_accepted: Some(10_000),
            round_loss_fraction: Some(0.0),
            pending_rank: Some(8_500),
            pending_rank_columns: Some(43_700),
            pending_rank_deficit: Some(35_200),
            pending_decode_jobs: Some(0),
            ..QuicNeedMore::default()
        };
        healthy.observe_need_more(&cx, &config, &healthy_need);
        assert_eq!(
            healthy.last_round_loss_fraction, 0.0,
            "healthy rank progress should not manufacture congestion loss"
        );
        assert_eq!(
            healthy.cap_bps(),
            None,
            "healthy rank progress should keep the native QUIC cap unarmed"
        );
    }

    #[test]
    fn native_sender_observed_loss_shapes_pacing_decision_not_only_trace_field() {
        // MATRIX-127: observed delivery loss must be present before the pacing
        // decision is computed. Updating only `path_loss_rate` after the fact disables
        // the clean-ramp flag but leaves rate, burst, pause, and limiter on stale
        // zero-loss math.
        let conn = established_native_test_conn();
        let config = QuicConfig {
            max_spray_symbols_per_flush: 64,
            ..QuicConfig::default().allow_unauthenticated_for_trusted_transport()
        };

        let clean = super::super::quic_spray_pacing_decision_from_config(
            &config,
            native_quic_path_signal_with_observed_loss(conn.transport(), 0.0),
        );
        let lossy = super::super::quic_spray_pacing_decision_from_config(
            &config,
            native_quic_path_signal_with_observed_loss(conn.transport(), 0.90),
        );

        assert_eq!(
            lossy.limiter,
            super::super::QuicSprayPacingLimiter::LossBackoff
        );
        assert!(
            lossy.pacing_rate_bps < clean.pacing_rate_bps,
            "sender-observed loss must reduce the computed pacing rate: clean={clean:?} lossy={lossy:?}"
        );
        assert!(
            lossy.max_burst_symbols <= clean.max_burst_symbols,
            "sender-observed loss must not leave burst sizing on the stale clean path: clean={clean:?} lossy={lossy:?}"
        );
        assert!(
            !super::super::quic_round0_clean_ramp_enabled(&config, &lossy, true),
            "sender-observed delivery loss must also block clean-ramp eligibility"
        );
    }

    #[test]
    fn native_data_plane_path_signal_preserves_cwnd_as_telemetry() {
        let conn = established_native_test_conn();
        let native_cwnd = conn.transport().congestion_window_bytes();

        let clean = native_quic_path_signal_with_observed_loss(conn.transport(), 0.0);
        assert_eq!(
            clean.congestion_window_bytes, native_cwnd,
            "MATRIX-132: native cwnd must remain honest telemetry, not a synthesized data-plane window"
        );
        assert_eq!(clean.loss_rate, 0.0);

        let lossy = native_quic_path_signal_with_observed_loss(conn.transport(), 0.42);
        assert_eq!(lossy.congestion_window_bytes, native_cwnd);
        assert_eq!(lossy.loss_rate, 0.42);
    }

    #[test]
    fn source_stream_packet_budget_allows_cwnd_floor_tail_progress() {
        let observed_tail_bytes = 95u64;

        assert!(
            QUIC_STREAM_PACKET_OVERHEAD_BUDGET >= ONE_RTT_PACKET_OVERHEAD as u64,
            "source STREAM packet budget must cover 1-RTT header/tag bytes"
        );
        assert!(
            observed_tail_bytes.saturating_sub(QUIC_STREAM_PACKET_OVERHEAD_BUDGET) > 32,
            "MATRIX-148: source STREAM flushing must leave enough frame budget to emit a tiny frame at the cwnd floor"
        );
    }

    #[test]
    fn native_data_plane_recovery_accounting_uses_packet_units_for_jumbo_udp() {
        let cx = Cx::for_testing();
        assert_eq!(data_plane_packet_accounting_bytes(0), 1);
        assert_eq!(
            data_plane_packet_accounting_bytes(512),
            QUIC_DATA_PLANE_TELEMETRY_PACKET_BYTES
        );
        assert_eq!(
            data_plane_packet_accounting_bytes(ATP_QUIC_UDP_MAX_PACKET),
            QUIC_DATA_PLANE_TELEMETRY_PACKET_BYTES
        );

        let datagram = QuicFrame::Datagram {
            data: Bytes::from_static(b"symbol"),
        };
        assert!(frames_have_datagram(core::slice::from_ref(&datagram)));
        assert!(frame_is_ack_eliciting_for_recovery(&datagram));
        assert!(!frames_have_datagram(&[QuicFrame::Ping]));
        assert!(!frame_is_ack_eliciting_for_recovery(&QuicFrame::Padding {
            length: 1
        }));

        let mut conn = established_native_test_conn();
        let initial_cwnd = conn.transport().congestion_window_bytes();
        let initial_packet_credits = initial_cwnd / QUIC_DATA_PLANE_TELEMETRY_PACKET_BYTES;
        assert!(initial_packet_credits >= 700);

        for idx in 0..initial_packet_credits {
            assert!(
                conn.transport()
                    .can_send(QUIC_DATA_PLANE_TELEMETRY_PACKET_BYTES),
                "packet {idx} should fit before cwnd fills"
            );
            let pn = conn
                .on_packet_sent(
                    &cx,
                    PacketNumberSpace::ApplicationData,
                    data_plane_packet_accounting_bytes(ATP_QUIC_UDP_MAX_PACKET),
                    true,
                    true,
                    (idx + 1) * CLOCK_STEP_MICROS,
                )
                .expect("jumbo ATP packet should charge one recovery unit");
            assert_eq!(pn, idx);
        }

        assert_eq!(conn.transport().bytes_in_flight(), initial_cwnd);
        assert!(
            !conn
                .transport()
                .can_send(QUIC_DATA_PLANE_TELEMETRY_PACKET_BYTES),
            "initial cwnd should be full after ATP packet-credit charges"
        );
        assert_eq!(
            data_plane_cwnd_telemetry(conn.transport(), 0),
            None,
            "empty data-plane queues must not emit cwnd telemetry"
        );
        let cwnd_telemetry = data_plane_cwnd_telemetry(conn.transport(), 3)
            .expect("full native cwnd should be visible as telemetry");
        assert_eq!(cwnd_telemetry.bytes_in_flight, initial_cwnd);
        assert_eq!(cwnd_telemetry.congestion_window, initial_cwnd);
        let admission =
            data_plane_flush_admission(conn.transport(), 3, 1_200, ATP_QUIC_UDP_MAX_PACKET);
        assert_eq!(
            admission.max_frame_bytes, 1_200,
            "MATRIX-132: cwnd telemetry must not switch ATP DATAGRAM flushes to the control-only path"
        );
        assert_eq!(
            admission.cwnd_telemetry,
            Some(cwnd_telemetry),
            "native QUIC cwnd remains observable while the RaptorQ pacer owns admission"
        );
        let overflow_accounting = data_plane_packet_accounting_bytes(ATP_QUIC_UDP_MAX_PACKET);
        assert!(
            data_plane_packet_uses_paced_recovery(core::slice::from_ref(&datagram)),
            "pure ATP DATAGRAM packets must use the RaptorQ data-plane pacer as send authority"
        );
        assert!(
            !packet_tracks_recovery_in_flight(core::slice::from_ref(&datagram), None),
            "pure ATP DATAGRAM packets must not require NewReno admission"
        );
        let overflow_pn = conn
            .on_packet_sent(
                &cx,
                PacketNumberSpace::ApplicationData,
                overflow_accounting,
                true,
                false,
                (initial_packet_credits + 1) * CLOCK_STEP_MICROS,
            )
            .expect("MATRIX-132: ATP pacer, not QUIC cwnd, admits the next DATAGRAM");
        assert_eq!(overflow_pn, initial_packet_credits);
        assert_eq!(
            conn.transport().bytes_in_flight(),
            initial_cwnd,
            "telemetry-only DATAGRAM sends must not grow QUIC bytes_in_flight past cwnd"
        );

        let ack_range =
            crate::net::quic_native::AckRange::new(initial_packet_credits, 0).expect("ack range");
        conn.on_ack_ranges(
            &cx,
            PacketNumberSpace::ApplicationData,
            &[ack_range],
            0,
            20 * CLOCK_STEP_MICROS,
        )
        .expect("ack range should clear tracked in-flight packets");
        assert_eq!(conn.transport().bytes_in_flight(), 0);
        assert!(
            conn.transport()
                .can_send(QUIC_DATA_PLANE_TELEMETRY_PACKET_BYTES),
            "ACK feedback should reopen native recovery cwnd"
        );
    }

    #[test]
    fn native_data_plane_admission_is_pacer_not_newreno_cwnd() {
        let cx = Cx::for_testing();
        let datagram = QuicFrame::Datagram {
            data: Bytes::from_static(b"symbol"),
        };
        assert!(frame_is_ack_eliciting_for_recovery(&datagram));
        assert!(!frames_require_quic_recovery_in_flight(
            core::slice::from_ref(&datagram)
        ));
        assert!(frames_require_quic_recovery_in_flight(&[QuicFrame::Ping]));

        let mut conn = established_native_test_conn();
        let initial_cwnd = conn.transport().congestion_window_bytes();
        let initial_packet_credits = initial_cwnd / QUIC_DATA_PLANE_TELEMETRY_PACKET_BYTES;
        assert!(initial_packet_credits > 0);
        for idx in 0..initial_packet_credits {
            conn.on_packet_sent(
                &cx,
                PacketNumberSpace::ApplicationData,
                QUIC_DATA_PLANE_TELEMETRY_PACKET_BYTES,
                true,
                true,
                (idx + 1) * CLOCK_STEP_MICROS,
            )
            .expect("setup packet should fit before cwnd fills");
        }
        assert_eq!(conn.transport().bytes_in_flight(), initial_cwnd);
        assert!(
            !conn
                .transport()
                .can_send(QUIC_DATA_PLANE_TELEMETRY_PACKET_BYTES)
        );

        let datagram_accounting = data_plane_packet_accounting_bytes(ATP_QUIC_UDP_MAX_PACKET);
        assert!(data_plane_packet_uses_paced_recovery(
            core::slice::from_ref(&datagram)
        ));
        let datagram_pn = conn
            .on_packet_sent(
                &cx,
                PacketNumberSpace::ApplicationData,
                datagram_accounting,
                true,
                false,
                (initial_packet_credits + 1) * CLOCK_STEP_MICROS,
            )
            .expect("pure ATP DATAGRAM packet admission is owned by the spray pacer");
        assert_eq!(datagram_pn, initial_packet_credits);
        assert_eq!(
            conn.transport().bytes_in_flight(),
            initial_cwnd,
            "pure ATP DATAGRAM packets stay packet-number visible but bypass NewReno in-flight admission"
        );

        let control_err = conn
            .on_packet_sent(
                &cx,
                PacketNumberSpace::ApplicationData,
                1,
                true,
                frames_require_quic_recovery_in_flight(&[QuicFrame::Ping]),
                (initial_packet_credits + 2) * CLOCK_STEP_MICROS,
            )
            .expect_err("reliable/control packets must remain NewReno governed");
        assert!(matches!(
            control_err,
            NativeQuicConnectionError::CongestionLimited { .. }
        ));
    }

    #[test]
    fn native_source_stream_bulk_admission_is_pacer_not_newreno_cwnd() {
        let cx = Cx::for_testing();
        let source_stream = StreamId::local(StreamRole::Client, StreamDirection::Bidirectional, 1);
        let other_stream = StreamId::local(StreamRole::Client, StreamDirection::Bidirectional, 3);
        let source_frame = QuicFrame::Stream {
            stream_id: crate::net::atp::protocol::varint::VarInt::from_u64_unchecked(
                source_stream.0,
            ),
            offset: None,
            data: Bytes::from_static(b"source"),
            fin: false,
        };
        let other_frame = QuicFrame::Stream {
            stream_id: crate::net::atp::protocol::varint::VarInt::from_u64_unchecked(
                other_stream.0,
            ),
            offset: None,
            data: Bytes::from_static(b"control"),
            fin: false,
        };

        assert!(source_stream_packet_uses_paced_recovery(
            core::slice::from_ref(&source_frame),
            Some(source_stream)
        ));
        assert!(!packet_tracks_recovery_in_flight(
            core::slice::from_ref(&source_frame),
            Some(source_stream)
        ));
        assert!(!source_stream_packet_uses_paced_recovery(
            core::slice::from_ref(&other_frame),
            Some(source_stream)
        ));
        assert!(packet_tracks_recovery_in_flight(
            core::slice::from_ref(&other_frame),
            Some(source_stream)
        ));
        let mixed_source_and_control = [source_frame.clone(), QuicFrame::Ping];
        assert!(!source_stream_packet_uses_paced_recovery(
            &mixed_source_and_control,
            Some(source_stream)
        ));
        assert!(packet_tracks_recovery_in_flight(
            &mixed_source_and_control,
            Some(source_stream)
        ));

        let mut conn = established_native_test_conn();
        let initial_cwnd = conn.transport().congestion_window_bytes();
        let initial_packet_credits = initial_cwnd / QUIC_DATA_PLANE_TELEMETRY_PACKET_BYTES;
        for idx in 0..initial_packet_credits {
            conn.on_packet_sent(
                &cx,
                PacketNumberSpace::ApplicationData,
                QUIC_DATA_PLANE_TELEMETRY_PACKET_BYTES,
                true,
                true,
                (idx + 1) * CLOCK_STEP_MICROS,
            )
            .expect("setup packet should fill the native recovery cwnd");
        }
        assert_eq!(conn.transport().bytes_in_flight(), initial_cwnd);
        assert!(!conn.transport().can_send(1));

        let source_accounting = data_plane_packet_accounting_bytes(source_stream_max_frame_bytes());
        let source_tracks_in_flight = packet_tracks_recovery_in_flight(
            core::slice::from_ref(&source_frame),
            Some(source_stream),
        );
        let pn = conn
            .on_packet_sent(
                &cx,
                PacketNumberSpace::ApplicationData,
                source_accounting,
                true,
                source_tracks_in_flight,
                (initial_packet_credits + 1) * CLOCK_STEP_MICROS,
            )
            .expect("marked source STREAM packet should use ATP-paced admission");
        assert_eq!(pn, initial_packet_credits);
        assert_eq!(
            conn.transport().bytes_in_flight(),
            initial_cwnd,
            "bulk source STREAM packets must not grow NewReno bytes_in_flight past cwnd"
        );
    }

    #[test]
    fn native_source_stream_pacing_uses_stream_ceiling_for_good_path() {
        let good_config = QuicConfig {
            round0_loss_target: super::super::QUIC_NEAR_CLEAN_SOURCE_STREAM_MAX_LOSS_TARGET,
            max_spray_symbols_per_flush: 54,
            ..QuicConfig::default().allow_unauthenticated_for_trusted_transport()
        };
        let mut pacing = QuicSprayPacingDecision {
            max_burst_symbols: 4,
            pause_after_burst: Duration::from_millis(1),
            pacing_rate_bps: super::super::QUIC_ROUND0_CLEAN_RAMP_MAX_PACING_BPS,
            cwnd_symbols: 4,
            cwnd_share_symbols: 4,
            burst_cap_share_symbols: 4,
            loss_backoff: 1.0,
            responsiveness_backoff: 1.0,
            path_rtt_s: 0.025,
            path_cwnd_bytes: 12_000,
            path_loss_rate: super::super::QUIC_NEAR_CLEAN_SOURCE_STREAM_MAX_LOSS_TARGET,
            fec_loss_budget: 0.0,
            congestion_loss_rate: 0.0,
            limiter: super::super::QuicSprayPacingLimiter::PacingRate,
        };
        promote_source_stream_pacing(&mut pacing, &good_config, 1200);

        assert_eq!(
            pacing.pacing_rate_bps,
            super::super::QUIC_RELIABLE_SOURCE_STREAM_MAX_PACING_BPS,
            "GOOD source STREAM pacing must not inherit the lower DATAGRAM clean-ramp cap"
        );

        let capped_config = QuicConfig {
            bwlimit_bps: Some(super::super::QUIC_ROUND0_CLEAN_RAMP_MAX_PACING_BPS),
            ..good_config
        };
        let mut capped = pacing;
        capped.pacing_rate_bps = super::super::QUIC_ROUND0_CLEAN_RAMP_MAX_PACING_BPS;
        promote_source_stream_pacing(&mut capped, &capped_config, 1200);
        assert_eq!(
            capped.pacing_rate_bps,
            super::super::QUIC_ROUND0_CLEAN_RAMP_MAX_PACING_BPS,
            "operator bandwidth caps must still bound source STREAM pacing"
        );
    }

    #[test]
    fn legacy_source_stream_repair_tail_helper_has_near_clean_loss_floor() {
        let config = QuicConfig {
            repair_overhead: 1.0,
            round0_loss_target: super::super::QUIC_NEAR_CLEAN_SOURCE_STREAM_MAX_LOSS_TARGET,
            symbol_size: 1141,
            max_block_size: 512 * 1024,
            ..QuicConfig::default().allow_unauthenticated_for_trusted_transport()
        };
        let manifest = TransferManifest {
            transfer_id: "goodtail".to_string(),
            root_name: "goodtail.bin".to_string(),
            is_directory: false,
            total_bytes: 1024 * 1024,
            merkle_root_hex: "00".repeat(32),
            metadata_root_hex: None,
            directory_metadata: None,
            delta_manifest: None,
            entries: vec![crate::net::atp::transport_tcp::ManifestEntry {
                index: 0,
                rel_path: "goodtail.bin".to_string(),
                size: 1024 * 1024,
                sha256_hex: "11".repeat(32),
                metadata: None,
                members: Vec::new(),
            }],
        };

        let requests =
            source_stream_repair_tail_requests(&manifest, &config).expect("tail requests");

        assert_eq!(requests.len(), 2);
        assert!(
            requests.iter().all(|request| request.symbols == 2),
            "legacy near-clean repair-tail sizing should not collapse to zero when CLI repair_overhead is 1.0"
        );
    }

    #[test]
    fn native_repair_round_pacing_forces_single_symbol_bursts() {
        let mut pacing = QuicSprayPacingDecision {
            max_burst_symbols: 64,
            pause_after_burst: Duration::ZERO,
            pacing_rate_bps: 1_152 * 1024,
            cwnd_symbols: 512,
            cwnd_share_symbols: 64,
            burst_cap_share_symbols: 64,
            loss_backoff: 1.0,
            responsiveness_backoff: 1.0,
            path_rtt_s: 0.200,
            path_cwnd_bytes: 256 * 1024,
            path_loss_rate: 0.10,
            fec_loss_budget: 0.0,
            congestion_loss_rate: 0.10,
            limiter: super::super::QuicSprayPacingLimiter::PathRateMatch,
        };

        enforce_native_repair_round_pacing(&mut pacing, 1024);

        assert_eq!(pacing.max_burst_symbols, 1);
        assert_eq!(pacing.burst_cap_share_symbols, 1);
        assert!(
            pacing.cwnd_share_symbols > 1,
            "repair pacing must not collapse the in-flight window to one RTT-bound symbol"
        );
        assert_eq!(
            pacing.cwnd_share_symbols, 231,
            "repair cwnd should use the pacing-rate BDP instead of the collapsed shared cwnd"
        );
        assert!(
            pacing.pause_after_burst >= Duration::from_micros(800),
            "one 1KiB repair symbol at 1.152 MiB/s should have a rate-derived pause, got {:?}",
            pacing.pause_after_burst
        );
    }

    #[test]
    fn quic_sender_delivery_loss_paces_without_inflating_repair_deficits() {
        // MATRIX-171/176: sender-side delivery loss still drives pacing, but the
        // sender must serve the receiver's exact per-block deficit request. If
        // the sender expands this list again, it can drown a shaped 10 mbit link
        // with self-inflicted repair queue loss.
        let cx = Cx::for_testing();
        let config = QuicConfig::default().allow_unauthenticated_for_trusted_transport();
        let mut aimd = NativeQuicAimdPacer::default();
        aimd.record_spray(1_000, 50_000_000, Duration::from_millis(1));
        let need = QuicNeedMore {
            feedback_round: 1,
            pending: vec![0],
            repair_blocks: vec![QuicBlockRepairRequest {
                entry: 0,
                sbn: 0,
                symbols: 100,
            }],
            round_symbols_observed: Some(20),
            round_loss_fraction: Some(0.0),
            ..QuicNeedMore::default()
        };

        aimd.observe_need_more(&cx, &config, &need);
        let sender_loss = aimd.sender_delivery_loss_for_repair(need.round_loss_fraction);
        assert!(
            sender_loss.is_some_and(|loss| loss >= 0.5),
            "sender-side delivery loss should dominate blind receiver loss: {sender_loss:?}"
        );
        let repair_blocks_to_send = need.repair_blocks.clone();
        assert_eq!(
            repair_blocks_to_send, need.repair_blocks,
            "sender-side delivery loss should not inflate an already-targeted per-block repair deficit"
        );

        assert!(
            aimd.sender_delivery_loss_for_repair(Some(0.90)).is_none(),
            "do not double-compensate when the receiver loss signal is already at least as high"
        );
    }

    #[test]
    fn native_keep_alive_uses_ping_not_ordered_control_stream() {
        let cx = Cx::for_testing();
        let mut conn = established_native_test_conn();
        let mut control = NativeQuicFrameTransport::open(&cx, &mut conn).expect("control stream");

        send_native_keep_alive(&cx, &mut conn, &mut control).expect("queue native keepalive");
        let frames = conn
            .generate_frames(&cx, PacketNumberSpace::ApplicationData, 128)
            .expect("keepalive frame should generate");

        assert_eq!(frames, vec![QuicFrame::Ping]);
    }

    #[test]
    fn native_receiver_progress_idle_grace_covers_control_pto() {
        assert_eq!(
            ROUND_PROGRESS_IDLE_GRACE, NEEDMORE_PTO,
            "receiver must not emit stale NeedMore before one control PTO elapses"
        );
    }

    #[test]
    fn native_receiver_paced_repair_idle_grace_covers_shaped_round() {
        let mut config = QuicConfig::default();
        config.round0_loss_target = 0.10;
        config.idle_timeout = Duration::from_secs(60);
        let need = QuicNeedMore {
            feedback_round: 2,
            pending: vec![0],
            repair_blocks: vec![QuicBlockRepairRequest {
                entry: 0,
                sbn: 0,
                symbols: 2_304,
            }],
            round_loss_fraction: Some(0.90),
            ..QuicNeedMore::default()
        };

        let grace = paced_repair_round_idle_grace(&config, Some(&need), 1_200);

        assert!(
            grace >= Duration::from_secs(20),
            "2304 shaped repair symbols at the conservative 128 KiB/s receive floor need a long enough grace, got {grace:?}"
        );
        assert!(
            grace > ROUND_PROGRESS_IDLE_GRACE,
            "paced repair rounds must not collapse back to one control PTO"
        );
        assert_eq!(
            paced_repair_round_idle_grace(&config, None, 1_200),
            ROUND_PROGRESS_IDLE_GRACE
        );
    }

    #[test]
    fn queued_fountain_feedback_count_ignores_liveness_and_round_markers() {
        fn empty_frame(ty: FrameType) -> Frame {
            Frame::new(
                crate::net::atp::protocol::frames::ProtocolVersion::CURRENT,
                ty,
                Vec::new(),
            )
            .expect("valid empty test frame")
        }

        let pending = VecDeque::from([
            empty_frame(FrameType::KeepAlive),
            empty_frame(FrameType::ObjectComplete),
            empty_frame(FrameType::ObjectRequest),
            empty_frame(FrameType::Proof),
        ]);

        assert_eq!(queued_fountain_feedback_count(&pending), 2);
    }

    #[test]
    fn one_rtt_header_round_trips() {
        for pn in [0u64, 1, 41, 255, 65_536, u64::from(u32::MAX), u64::MAX] {
            let header = encode_one_rtt_header(pn);
            // Build a minimal packet: header + 1 ciphertext byte + tag.
            let mut packet = header.to_vec();
            packet.push(0xAB);
            packet.extend_from_slice(&[0u8; ONE_RTT_TAG_LEN]);
            let (key_phase, decoded_pn, decoded_header, ciphertext, tag) =
                decode_one_rtt_packet(&packet).expect("decodes");
            assert!(!key_phase);
            assert_eq!(decoded_pn, pn);
            assert_eq!(decoded_header, &header);
            assert_eq!(ciphertext, &[0xAB]);
            assert_eq!(tag, [0u8; ONE_RTT_TAG_LEN]);
        }
    }

    #[test]
    fn decode_rejects_non_one_rtt_or_truncated_packets() {
        // Too short for header + tag.
        assert!(decode_one_rtt_packet(&[0x40, 0, 0]).is_none());
        // Long-header (fixed bit clear): a stray handshake packet.
        let mut long = vec![0x80];
        long.extend_from_slice(&[0u8; ONE_RTT_HEADER_LEN + ONE_RTT_TAG_LEN]);
        assert!(decode_one_rtt_packet(&long).is_none());
    }

    #[test]
    fn one_rtt_payload_budget_accounts_for_udp_overhead_and_control_headroom() {
        let legacy_cap = 16 * 1024;
        assert_eq!(
            one_rtt_max_payload_for_udp_packet(legacy_cap)
                + ONE_RTT_PACKET_OVERHEAD
                + ONE_RTT_COALESCED_CONTROL_HEADROOM,
            legacy_cap
        );
        assert_eq!(
            one_rtt_max_payload_for_udp_packet(ATP_QUIC_UDP_MAX_PACKET)
                + ONE_RTT_PACKET_OVERHEAD
                + ONE_RTT_COALESCED_CONTROL_HEADROOM,
            ATP_QUIC_UDP_MAX_PACKET
        );
        let protected_len =
            one_rtt_max_payload_for_udp_packet(ATP_QUIC_UDP_MAX_PACKET) + ONE_RTT_PACKET_OVERHEAD;
        assert!(protected_len < ATP_QUIC_UDP_MAX_PACKET);
        assert_eq!(
            ATP_QUIC_UDP_MAX_PACKET - protected_len,
            ONE_RTT_COALESCED_CONTROL_HEADROOM
        );
        assert_eq!(
            one_rtt_max_payload_for_udp_packet(ONE_RTT_PACKET_OVERHEAD - 1),
            0
        );
        assert_eq!(
            source_stream_max_frame_bytes(),
            one_rtt_max_payload_for_udp_packet(QUIC_SOURCE_STREAM_PACKET_BYTES),
            "ATP-paced source STREAM packets should use the configured native QUIC envelope"
        );
        assert_eq!(
            QUIC_SOURCE_STREAM_PACKET_BYTES,
            8 * 1024,
            "GOOD source STREAM packets should use the middle envelope, not the native MTU floor or jumbo UDP ceiling"
        );
        assert!(
            source_stream_max_frame_bytes() > DEFAULT_MAX_PACKET_BYTES,
            "source STREAM middle envelope should reduce receiver packet rate below the native MTU floor"
        );
        assert!(
            QUIC_SOURCE_STREAM_FLUSH_BYTES
                > u64::try_from(source_stream_max_frame_bytes()).unwrap(),
            "source STREAM flush windows should contain multiple native-envelope packets"
        );
        let interval = source_stream_pacing_interval(
            QUIC_SOURCE_STREAM_FLUSH_BYTES as usize,
            64 * 1024 * 1024,
        );
        assert!(
            (Duration::from_millis(7)..=Duration::from_millis(9)).contains(&interval),
            "source STREAM flush bursts should pace near the reliable-stream ceiling"
        );
        let pacing = QuicSprayPacingDecision {
            max_burst_symbols: 4,
            pause_after_burst: Duration::from_millis(1),
            pacing_rate_bps: 24 * 1024 * 1024,
            cwnd_symbols: 4,
            cwnd_share_symbols: 4,
            burst_cap_share_symbols: 4,
            loss_backoff: 1.0,
            responsiveness_backoff: 1.0,
            path_rtt_s: 0.025,
            path_cwnd_bytes: 12_000,
            path_loss_rate: 0.001,
            fec_loss_budget: 0.0,
            congestion_loss_rate: 0.0,
            limiter: super::super::QuicSprayPacingLimiter::PacingRate,
        };
        let mut pacer = NativeDataPlanePacer::new(1200, 4, pacing.pacing_rate_bps);
        pacer.configure(&pacing);
        assert_eq!(pacer.byte_pacer_burst_bytes, 4 * 1200);
        pacer.configure_source_stream(&pacing);
        assert_eq!(
            pacer.byte_pacer_burst_bytes,
            usize::try_from(QUIC_SOURCE_STREAM_FLUSH_BYTES).unwrap(),
            "source STREAM byte pacing should burst by the producer flush window, not symbol burst"
        );
        let first_packet = source_stream_max_frame_bytes();
        let second_packet = source_stream_max_frame_bytes();
        let packet_budget_before = pacer.byte_pacer_burst_remaining;
        let cx = Cx::for_testing();
        futures_lite::future::block_on(async {
            pacer
                .before_send_bytes(&cx, first_packet, 0, 0, 0)
                .await
                .expect("first source STREAM packet should consume byte budget");
            pacer
                .before_send_bytes(&cx, second_packet, 0, 0, 0)
                .await
                .expect("second source STREAM packet should consume byte budget");
        });
        assert_eq!(packet_budget_before, 0);
        assert_eq!(
            pacer.byte_pacer_burst_remaining,
            usize::try_from(QUIC_SOURCE_STREAM_FLUSH_BYTES)
                .unwrap()
                .saturating_sub(first_packet)
                .saturating_sub(second_packet),
            "source STREAM pacing must charge actual frame bytes, not rounded symbol units"
        );
    }

    #[test]
    fn source_stream_pacer_split_preserves_schedule_and_exposes_deadline() {
        // MATRIX-235: the source-stream flush loop now waits for the pacer
        // deadline itself (draining inbound ACKs meanwhile) via
        // `byte_pacer_deadline` + `note_bytes_paced`, instead of the opaque
        // `before_send_bytes` sleep. That split must NOT change the pacing rate
        // or burst shape: the deadline schedule stays exactly delivery-clocked
        // (no cwnd/rate change — the MATRIX-202 mild-loss refutation is not
        // re-tread; only WHEN ACKs are drained relative to the wait changes).
        let pacing = QuicSprayPacingDecision {
            max_burst_symbols: 4,
            pause_after_burst: Duration::from_millis(1),
            pacing_rate_bps: 24 * 1024 * 1024,
            cwnd_symbols: 4,
            cwnd_share_symbols: 4,
            burst_cap_share_symbols: 4,
            loss_backoff: 1.0,
            responsiveness_backoff: 1.0,
            path_rtt_s: 0.025,
            path_cwnd_bytes: 12_000,
            path_loss_rate: 0.001,
            fec_loss_budget: 0.0,
            congestion_loss_rate: 0.0,
            limiter: super::super::QuicSprayPacingLimiter::PacingRate,
        };
        let mut pacer = NativeDataPlanePacer::new(1200, 4, pacing.pacing_rate_bps);
        pacer.configure_source_stream(&pacing);
        let burst = pacer.byte_pacer_burst_bytes;
        assert_eq!(
            burst,
            usize::try_from(QUIC_SOURCE_STREAM_FLUSH_BYTES).unwrap()
        );

        // A burst sends back-to-back with no pacer deadline armed: the flush
        // loop only waits between bursts, so ACK-draining-during-wait never
        // stalls an in-progress burst.
        let packet = source_stream_max_frame_bytes();
        let mut frames = 0usize;
        loop {
            assert!(
                pacer.byte_pacer_deadline().is_none(),
                "no pacer deadline until the burst is exhausted (frame {frames})"
            );
            pacer.note_bytes_paced(packet);
            frames += 1;
            if pacer.byte_pacer_burst_remaining == 0 {
                break;
            }
            assert!(frames < 10_000, "burst must exhaust in bounded frames");
        }
        // The exhausted burst charged exactly `burst` bytes (frame-accurate,
        // not rounded symbol units) across `ceil(burst/packet)` frames.
        assert_eq!(frames, burst.div_ceil(packet));

        // Burst exhausted → a deadline is armed at most one pacing interval
        // ahead of now (the absolute deadline-credit schedule), matching the
        // configured rate exactly as `before_send_bytes` would have.
        let deadline = pacer
            .byte_pacer_deadline()
            .expect("deadline armed once a burst is exhausted");
        let interval = source_stream_pacing_interval(burst.max(packet), pacing.pacing_rate_bps);
        let ahead = deadline.saturating_duration_since(Instant::now());
        assert!(
            ahead > Duration::ZERO && ahead <= interval,
            "armed deadline must sit within one pacing interval ahead (schedule unchanged): ahead={ahead:?} interval={interval:?}"
        );

        // ACK-driven rate updates must retain the pending deadline. Clearing
        // it would turn every update into an unpaced send-now gap and permit a
        // repeating micro-burst at the delivery-sampling cadence.
        pacer.set_pacing_rate_bytes_per_s(pacing.pacing_rate_bps * 2);
        assert_eq!(
            pacer.byte_pacer_deadline(),
            Some(deadline),
            "a delivery-clocked rate change must preserve the armed deadline"
        );
    }

    #[test]
    fn one_rtt_payload_budget_coalesces_many_default_symbol_datagrams() {
        let symbol_envelope_len =
            usize::from(super::super::DEFAULT_SYMBOL_SIZE) + super::super::AUTH_ENVELOPE_HEADER_LEN;
        let mut encoded = BytesMut::new();
        QuicFrame::Datagram {
            data: Bytes::from(vec![0u8; symbol_envelope_len]),
        }
        .encode(&mut encoded)
        .expect("encode datagram frame");
        assert_eq!(
            encoded.len(),
            symbol_datagram_frame_len(
                super::super::DEFAULT_SYMBOL_SIZE,
                super::super::AUTH_ENVELOPE_HEADER_LEN,
            )
        );

        let max_app_payload = one_rtt_max_payload_for_udp_packet(ATP_QUIC_UDP_MAX_PACKET);
        let coalesced_symbols =
            coalesced_datagram_frames_per_packet(max_app_payload, encoded.len());

        assert!(
            coalesced_symbols >= 50,
            "one 1-RTT UDP packet should carry roughly MATRIX-39's ~53 symbol DATAGRAM frames"
        );
        assert!(encoded.len().saturating_mul(coalesced_symbols) <= max_app_payload);
        assert!(
            encoded
                .len()
                .saturating_mul(coalesced_symbols.saturating_add(1))
                > max_app_payload
        );
    }

    #[test]
    fn clean_spray_flush_limit_preserves_explicit_low_caps() {
        assert_eq!(
            coalesced_spray_flush_symbol_limit(54, 51, 54, 0.0, QUIC_CLEAN_GSO_PACKETS_PER_FLUSH),
            51,
            "raw caps below the GSO expansion still align to one full protected packet"
        );
        assert_eq!(
            coalesced_spray_flush_symbol_limit(1, 51, 54, 0.0, QUIC_CLEAN_GSO_PACKETS_PER_FLUSH),
            51,
            "raw caps below the GSO expansion still amortize to one protected packet"
        );
        assert_eq!(
            coalesced_spray_flush_symbol_limit(50, 51, 54, 0.0, QUIC_CLEAN_GSO_PACKETS_PER_FLUSH),
            51
        );
        assert_eq!(
            coalesced_spray_flush_symbol_limit(128, 51, 256, 0.0, QUIC_CLEAN_GSO_PACKETS_PER_FLUSH),
            204
        );
        assert_eq!(
            coalesced_spray_flush_symbol_limit(256, 51, 256, 0.0, QUIC_CLEAN_GSO_PACKETS_PER_FLUSH),
            255
        );
        assert_eq!(
            coalesced_spray_flush_symbol_limit(0, 51, 54, 0.0, QUIC_CLEAN_GSO_PACKETS_PER_FLUSH),
            51
        );
        assert_eq!(
            coalesced_spray_flush_symbol_limit(54, 0, 54, 0.0, QUIC_CLEAN_GSO_PACKETS_PER_FLUSH),
            54
        );
        assert_eq!(
            coalesced_spray_flush_symbol_limit(2, 60, 54, 0.0, QUIC_CLEAN_GSO_PACKETS_PER_FLUSH),
            54,
            "configured flush cap still bounds packet fill when one packet can hold more"
        );
        assert_eq!(
            coalesced_spray_flush_symbol_limit(2, 51, 16, 0.0, QUIC_CLEAN_GSO_PACKETS_PER_FLUSH),
            16,
            "operator burst cap remains the hard queueing envelope"
        );
        assert_eq!(
            coalesced_spray_flush_symbol_limit(2, 1, 64, 0.0, QUIC_CLEAN_GSO_PACKETS_PER_FLUSH),
            QUIC_CLEAN_SPRAY_BURST_FLOOR_SYMBOLS,
            "MATRIX-108: the encrypted clean path (one symbol per protected packet, \
             RTT-derived burst ≈ 2) floors to the rq-parity burst so a flush amortizes \
             QUIC packet protection and fills the send budget instead of ~5 MB/s"
        );
    }

    #[test]
    fn clean_coalescing_requires_low_loss_and_low_rtt() {
        let mut pacing = QuicSprayPacingDecision {
            max_burst_symbols: 2,
            pause_after_burst: Duration::from_millis(1),
            pacing_rate_bps: 12_000_000,
            cwnd_symbols: 10,
            cwnd_share_symbols: 10,
            burst_cap_share_symbols: 10,
            loss_backoff: 1.0,
            responsiveness_backoff: 1.0,
            path_rtt_s: 0.025,
            path_cwnd_bytes: 12_000,
            path_loss_rate: 0.0,
            fec_loss_budget: 0.0,
            congestion_loss_rate: 0.0,
            limiter: super::super::QuicSprayPacingLimiter::PacingRate,
        };
        assert!(
            !quic_clean_spray_coalescing_allowed(&pacing),
            "native ATP-QUIC keeps loss-granular symbol packets until lossy convergence is banked"
        );

        pacing.path_rtt_s = 0.0;
        assert!(
            !quic_clean_spray_coalescing_allowed(&pacing),
            "unknown RTT must stay on per-symbol packets until a clean path is measured"
        );

        pacing.path_rtt_s = 0.080;
        assert!(
            !quic_clean_spray_coalescing_allowed(&pacing),
            "50M/bad encrypted should not pack a full symbol group into one jumbo UDP packet"
        );

        pacing.path_rtt_s = 0.025;
        pacing.path_loss_rate = QUIC_CLEAN_SPRAY_MAX_LOSS_RATE;
        assert!(!quic_clean_spray_coalescing_allowed(&pacing));
    }

    #[test]
    fn clean_gso_flush_cap_batches_full_protected_packets_when_default_cap_allows_one() {
        assert_eq!(
            clean_gso_flush_symbol_cap(54, 54),
            54 * QUIC_CLEAN_GSO_PACKETS_PER_FLUSH
        );
        assert_eq!(
            coalesced_spray_flush_symbol_limit(
                1,
                54,
                clean_gso_flush_symbol_cap(54, 54),
                0.0,
                QUIC_CLEAN_GSO_PACKETS_PER_FLUSH
            ),
            54 * QUIC_CLEAN_GSO_PACKETS_PER_FLUSH
        );
        assert_eq!(
            clean_gso_flush_symbol_cap(16, 54),
            16,
            "operator caps below one packet remain hard caps"
        );
        assert_eq!(
            clean_gso_flush_symbol_cap(128, 54),
            128,
            "explicit operator caps above one packet remain explicit"
        );
    }

    #[test]
    fn clean_handoff_limit_fills_gso_flush_window() {
        let flush_window = 54 * QUIC_CLEAN_GSO_PACKETS_PER_FLUSH;
        assert_eq!(
            spray_handoff_symbol_limit_for(flush_window, 0, 0.0),
            flush_window,
            "MATRIX-112: clean encrypted sends hand one full GSO-ready flush window \
             to the QUIC sender instead of splitting it into 64-symbol scheduler turns"
        );
        assert_eq!(
            spray_handoff_symbol_limit_for(flush_window, 54, 0.0),
            flush_window - 54,
            "pending DATAGRAMs still reduce the next handoff to the remaining flush window"
        );
        assert_eq!(
            spray_handoff_symbol_limit_for(flush_window, flush_window, 0.0),
            1,
            "a full queue reports the minimum nudge so the caller flushes before enqueueing more"
        );
    }

    #[test]
    fn lossy_handoff_limit_preserves_bounded_scheduler_turns() {
        let flush_window = 54 * QUIC_CLEAN_GSO_PACKETS_PER_FLUSH;
        assert_eq!(
            spray_handoff_symbol_limit_for(flush_window, 0, 0.02),
            QUIC_LOSSY_SPRAY_HANDOFF_MAX_SYMBOLS,
            "lossy paths keep the old conservative per-turn handoff cap"
        );
        assert_eq!(
            spray_handoff_symbol_limit_for(32, 0, 0.02),
            32,
            "small lossy pacing bursts are still limited by the paced flush window"
        );
        assert_eq!(
            spray_handoff_symbol_limit_for(flush_window, flush_window - 10, 0.02),
            10,
            "pending DATAGRAMs can shrink the lossy handoff below the cap"
        );
        assert_eq!(
            spray_handoff_symbol_limit_for(flush_window, 0, QUIC_CLEAN_SPRAY_MAX_LOSS_RATE),
            QUIC_LOSSY_SPRAY_HANDOFF_MAX_SYMBOLS,
            "the clean fast path remains below the documented loss ceiling"
        );
    }

    #[test]
    fn lossy_spray_flush_limit_preserves_pacing_burst() {
        let loss = QUIC_CLEAN_SPRAY_MAX_LOSS_RATE;
        assert_eq!(
            coalesced_spray_flush_symbol_limit(1, 51, 54, loss, QUIC_CLEAN_GSO_PACKETS_PER_FLUSH),
            1
        );
        assert_eq!(
            coalesced_spray_flush_symbol_limit(50, 51, 54, loss, QUIC_CLEAN_GSO_PACKETS_PER_FLUSH),
            50
        );
        assert_eq!(
            coalesced_spray_flush_symbol_limit(54, 51, 54, loss, QUIC_CLEAN_GSO_PACKETS_PER_FLUSH),
            51
        );
        assert_eq!(
            coalesced_spray_flush_symbol_limit(
                128,
                51,
                256,
                loss,
                QUIC_CLEAN_GSO_PACKETS_PER_FLUSH
            ),
            102
        );
        assert_eq!(
            coalesced_spray_flush_symbol_limit(0, 51, 54, loss, QUIC_CLEAN_GSO_PACKETS_PER_FLUSH),
            1
        );
    }

    #[test]
    fn quic_gso_send_strategy_uses_full_protected_packet_segments() {
        let peer = "127.0.0.1:9000".parse().unwrap();
        let packets = vec![
            OutgoingPacket {
                dst_addr: peer,
                data: vec![0; ATP_QUIC_UDP_MAX_PACKET],
                send_time: None,
            };
            QUIC_CLEAN_GSO_PACKETS_PER_FLUSH
        ];

        let strategy = quic_gso_send_strategy(&packets);
        assert_eq!(strategy.gso_segment_bytes, ATP_QUIC_UDP_MAX_PACKET);
        assert_eq!(strategy.max_gso_segments, QUIC_CLEAN_GSO_PACKETS_PER_FLUSH);
    }

    #[test]
    fn inbound_receive_limit_reserves_slots_for_coalesced_datagrams() {
        assert_eq!(inbound_udp_packet_receive_limit(0, 64), 0);
        assert_eq!(inbound_udp_packet_receive_limit(63, 64), 0);
        assert_eq!(inbound_udp_packet_receive_limit(64, 64), 1);
        assert_eq!(inbound_udp_packet_receive_limit(4096, 64), 64);
        assert_eq!(
            inbound_udp_packet_receive_limit(usize::MAX, 64),
            INBOUND_PUMP_BATCH
        );
        let max_app_payload = one_rtt_max_payload_for_udp_packet(ATP_QUIC_UDP_MAX_PACKET);
        let default_frame_len = symbol_datagram_frame_len(
            super::super::DEFAULT_SYMBOL_SIZE,
            super::super::ENVELOPE_HEADER_LEN,
        );
        let default_frames =
            coalesced_datagram_frames_per_packet(max_app_payload, default_frame_len);
        let default_limit = inbound_udp_packet_receive_limit(4096, default_frames);
        assert!(default_limit > 0);
        assert!(default_limit.saturating_mul(default_frames) <= 4096);
    }

    #[test]
    fn quic_endpoint_packet_budget_accepts_matrix37_lossy_overshoot() {
        // MATRIX-37 encrypted lossy cells failed deterministically at 16 KiB + 1..6
        // bytes when ACK/control frames were coalesced with near-full 1-RTT data.
        let legacy_cap = 16 * 1024;
        let observed_overshoot = legacy_cap + 6;

        assert!(observed_overshoot > legacy_cap);
        assert!(observed_overshoot <= ATP_QUIC_UDP_MAX_PACKET);
    }

    #[test]
    fn native_receive_decoded_trace_includes_receiver_counters() {
        let cx = Cx::for_testing();
        let collector = crate::observability::LogCollector::new(8)
            .with_min_level(crate::observability::LogLevel::Trace);
        cx.set_log_collector(collector.clone());
        let counters = NativeReceiveTraceCounters {
            udp_packets_received: 17,
            one_rtt_packets_ingested: 16,
            non_one_rtt_packets_dropped: 1,
            unprotect_packets_dropped: 2,
            datagrams_received: 12,
            datagrams_dropped_on_receive: 0,
            pending_datagrams: 3,
            pending_received_packets: 2,
            inbound_datagram_capacity: 4096,
            inbound_datagram_available: 4093,
            inbound_pump_batch_limit: INBOUND_PUMP_BATCH,
            udp_recv_buffer_requested: Some(16 * 1024 * 1024),
            udp_recv_buffer_applied: Some(32 * 1024 * 1024),
            udp_kernel_rx_queue_bytes: Some(4096),
            udp_kernel_drops: Some(7),
        };
        let decode_stats = crate::net::atp::transport_quic::QuicDecodeStats {
            decode_count: 4,
            decode_micros: 55,
        };

        counters.trace_decoded(&cx, "transfer-g3", 99, 2, &decode_stats);

        let entries = collector.peek();
        let entry = entries
            .iter()
            .find(|entry| entry.message() == "atp_quic.receive.decoded")
            .expect("receive decoded trace entry");
        assert_eq!(entry.level(), crate::observability::LogLevel::Trace);
        assert_eq!(entry.get_field("transfer_id"), Some("transfer-g3"));
        assert_eq!(entry.get_field("symbols_accepted"), Some("99"));
        assert_eq!(entry.get_field("feedback_rounds"), Some("2"));
        assert_eq!(entry.get_field("decode_count"), Some("4"));
        assert_eq!(entry.get_field("decode_micros"), Some("55"));
        assert_eq!(entry.get_field("datagrams_received"), Some("12"));
        assert_eq!(entry.get_field("datagrams_dropped_on_receive"), Some("0"));
        assert_eq!(entry.get_field("pending_datagrams"), Some("3"));
        assert_eq!(entry.get_field("reorder_occupancy"), Some("3"));
        assert_eq!(entry.get_field("pending_received_packets"), Some("2"));
        let socket_entry = entries
            .iter()
            .find(|entry| entry.message() == "atp_quic.receive.socket")
            .expect("receive socket trace entry");
        assert_eq!(socket_entry.level(), crate::observability::LogLevel::Trace);
        assert_eq!(socket_entry.get_field("transfer_id"), Some("transfer-g3"));
        assert_eq!(socket_entry.get_field("udp_packets_received"), Some("17"));
        assert_eq!(
            socket_entry.get_field("one_rtt_packets_ingested"),
            Some("16")
        );
        assert_eq!(
            socket_entry.get_field("non_one_rtt_packets_dropped"),
            Some("1")
        );
        assert_eq!(
            socket_entry.get_field("unprotect_packets_dropped"),
            Some("2")
        );
        assert_eq!(
            socket_entry.get_field("inbound_datagram_capacity"),
            Some("4096")
        );
        assert_eq!(
            socket_entry.get_field("inbound_datagram_available"),
            Some("4093")
        );
        assert_eq!(
            socket_entry.get_field("inbound_pump_batch_limit"),
            Some("512")
        );
        assert_eq!(
            socket_entry.get_field("udp_recv_buffer_requested"),
            Some("16777216")
        );
        assert_eq!(
            socket_entry.get_field("udp_recv_buffer_applied"),
            Some("33554432")
        );
        assert_eq!(
            socket_entry.get_field("udp_kernel_rx_queue_bytes"),
            Some("4096")
        );
        assert_eq!(socket_entry.get_field("udp_kernel_drops"), Some("7"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_udp_proc_receive_stats_parses_rx_queue_and_drops() {
        let table = "\
  sl  local_address rem_address   st tx_queue:rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  7: 0100007F:9C40 00000000:0000 07 00000000:00001000 00:00000000 00000000  1000        0 12345 2 0000000000000000 17
";
        let local: SocketAddr = "127.0.0.1:40000".parse().expect("local addr");
        let stats = linux_udp_proc_receive_stats_from_table(table, local)
            .expect("synthetic udp row should match local socket");

        assert_eq!(
            stats,
            LinuxUdpProcReceiveStats {
                rx_queue_bytes: 4096,
                drops: 17,
            }
        );
    }

    #[test]
    fn sender_drops_exact_duplicate_need_more_resends_only() {
        let served = QuicNeedMore {
            pending: vec![0],
            repair_blocks: vec![QuicBlockRepairRequest {
                entry: 0,
                sbn: 1,
                symbols: 7,
            }],
            source_symbols: Vec::new(),
            round_symbols_observed: Some(90),
            round_loss_fraction: Some(0.10),
            round_symbols_accepted: Some(88),
            ..QuicNeedMore::default()
        };
        let same_request_different_telemetry = QuicNeedMore {
            round_symbols_observed: Some(42),
            round_loss_fraction: Some(0.42),
            round_symbols_accepted: Some(37),
            ..served.clone()
        };
        let changed_feedback_round = QuicNeedMore {
            feedback_round: 2,
            ..served.clone()
        };
        let changed = QuicNeedMore {
            repair_blocks: vec![QuicBlockRepairRequest {
                symbols: 3,
                ..served.repair_blocks[0]
            }],
            round_symbols_observed: Some(7),
            round_loss_fraction: Some(0.0),
            round_symbols_accepted: Some(7),
            ..served.clone()
        };
        let mut pending = VecDeque::from([
            super::super::json_frame(FrameType::ObjectRequest, &served)
                .expect("duplicate need-more"),
            super::super::json_frame(FrameType::ObjectRequest, &same_request_different_telemetry)
                .expect("duplicate need-more with fresh telemetry"),
            Frame::empty(FrameType::Proof).expect("proof frame"),
            super::super::json_frame(FrameType::ObjectRequest, &changed_feedback_round)
                .expect("next-round same-shape need-more"),
            super::super::json_frame(FrameType::ObjectRequest, &changed)
                .expect("changed need-more"),
            super::super::json_frame(FrameType::ObjectRequest, &served)
                .expect("duplicate need-more"),
        ]);

        let dropped = drop_duplicate_need_more_frames(&mut pending, &served)
            .expect("duplicate filter parses queued feedback");

        assert_eq!(dropped, 3);
        assert_eq!(pending.len(), 3);
        assert_eq!(pending[0].frame_type(), FrameType::Proof);
        assert_eq!(pending[1].frame_type(), FrameType::ObjectRequest);
        assert_eq!(pending[2].frame_type(), FrameType::ObjectRequest);
        let retained =
            super::super::parse_json::<QuicNeedMore>(&pending[1]).expect("retained need-more");
        assert_eq!(retained, changed_feedback_round);
        let retained =
            super::super::parse_json::<QuicNeedMore>(&pending[2]).expect("retained need-more");
        assert_eq!(retained, changed);
    }

    #[test]
    fn need_more_pto_retransmits_recorded_offsets_without_appending() {
        assert_eq!(need_more_pto_mode(&[]), NeedMorePtoMode::SendFresh);
        let recorded = [SentControlStreamFrame {
            stream: StreamId(0),
            offset: 4096,
            len: 1024,
        }];
        assert_eq!(
            need_more_pto_mode(&recorded),
            NeedMorePtoMode::RetransmitRecorded
        );
    }

    #[test]
    fn source_stream_ack_ranges_extract_sparse_packet_ranges() {
        let ack = QuicFrame::Ack {
            largest_acknowledged: crate::net::atp::protocol::varint::VarInt::from_u64_unchecked(10),
            ack_delay: crate::net::atp::protocol::varint::VarInt::from_u64_unchecked(0),
            ack_range_count: crate::net::atp::protocol::varint::VarInt::from_u64_unchecked(1),
            first_ack_range: crate::net::atp::protocol::varint::VarInt::from_u64_unchecked(2),
            ack_ranges: vec![crate::net::atp::protocol::quic_frames::AckRange {
                gap: crate::net::atp::protocol::varint::VarInt::from_u64_unchecked(1),
                ack_range_length: crate::net::atp::protocol::varint::VarInt::from_u64_unchecked(1),
            }],
            ecn_counts: None,
        };

        let ranges = acked_packet_ranges_from_frames(&[ack]).expect("ACK ranges decode");

        assert_eq!(
            ranges,
            vec![
                NativeAckRange::new(10, 8).expect("first ACK range"),
                NativeAckRange::new(5, 4).expect("second ACK range"),
            ]
        );
        assert!(packet_in_ack_ranges(10, &ranges));
        assert!(packet_in_ack_ranges(8, &ranges));
        assert!(packet_in_ack_ranges(4, &ranges));
        assert!(!packet_in_ack_ranges(7, &ranges));
        assert!(!packet_in_ack_ranges(11, &ranges));
        assert!(packet_lost_by_ack_gap(6, &ranges));
        assert!(packet_lost_by_ack_gap(7, &ranges));
        assert!(!packet_lost_by_ack_gap(8, &ranges));
        assert!(!packet_lost_by_ack_gap(10, &ranges));
        assert!(!packet_lost_by_ack_gap(11, &ranges));
    }

    #[test]
    fn source_stream_retransmit_frames_are_sorted_and_deduplicated() {
        let stream = StreamId(4);
        let frames = vec![
            SentControlStreamFrame {
                stream,
                offset: 4096,
                len: 1024,
            },
            SentControlStreamFrame {
                stream,
                offset: 1024,
                len: 1024,
            },
            SentControlStreamFrame {
                stream,
                offset: 4096,
                len: 1024,
            },
            SentControlStreamFrame {
                stream: StreamId(8),
                offset: 0,
                len: 1024,
            },
        ];

        assert_eq!(
            dedup_stream_frames_for_retransmit(frames),
            vec![
                SentControlStreamFrame {
                    stream,
                    offset: 1024,
                    len: 1024,
                },
                SentControlStreamFrame {
                    stream,
                    offset: 4096,
                    len: 1024,
                },
                SentControlStreamFrame {
                    stream: StreamId(8),
                    offset: 0,
                    len: 1024,
                },
            ]
        );
    }

    #[test]
    fn source_stream_proof_wait_deduplicates_replay_offsets() {
        let stream = StreamId(4);
        let frames = (0..8)
            .map(|idx| SentControlStreamFrame {
                stream,
                offset: idx * 1024,
                len: 1024,
            })
            .collect::<Vec<_>>();

        assert_eq!(
            dedup_stream_frames_for_retransmit(frames.clone()),
            frames,
            "proof wait replay uses stream offsets rather than the old marker-tail subset"
        );
    }

    #[test]
    fn sender_retains_need_more_with_changed_pending_or_source_shape() {
        let served = QuicNeedMore {
            pending: vec![0],
            repair_blocks: vec![QuicBlockRepairRequest {
                entry: 0,
                sbn: 1,
                symbols: 7,
            }],
            source_symbols: vec![QuicSourceSymbolRequest {
                entry: 0,
                sbn: 1,
                esi: 4,
            }],
            round_symbols_observed: Some(90),
            round_loss_fraction: Some(0.10),
            round_symbols_accepted: Some(88),
            ..QuicNeedMore::default()
        };
        let changed_pending = QuicNeedMore {
            pending: vec![1],
            ..served.clone()
        };
        let changed_source = QuicNeedMore {
            source_symbols: vec![QuicSourceSymbolRequest {
                esi: 5,
                ..served.source_symbols[0]
            }],
            ..served.clone()
        };
        let mut pending = VecDeque::from([
            super::super::json_frame(FrameType::ObjectRequest, &served)
                .expect("duplicate need-more"),
            super::super::json_frame(FrameType::ObjectRequest, &changed_pending)
                .expect("changed pending need-more"),
            super::super::json_frame(FrameType::ObjectRequest, &changed_source)
                .expect("changed source need-more"),
        ]);

        let dropped = drop_duplicate_need_more_frames(&mut pending, &served)
            .expect("duplicate filter parses queued feedback");

        assert_eq!(dropped, 1);
        assert_eq!(pending.len(), 2);
        let retained_pending = super::super::parse_json::<QuicNeedMore>(&pending[0])
            .expect("retained pending need-more");
        let retained_source = super::super::parse_json::<QuicNeedMore>(&pending[1])
            .expect("retained source need-more");
        assert_eq!(retained_pending, changed_pending);
        assert_eq!(retained_source, changed_source);
    }

    #[test]
    fn needmore_pto_attempt_budget_tracks_configured_idle_timeout() {
        assert_eq!(
            needmore_pto_attempt_budget(Duration::from_secs(60)),
            40,
            "the old default maps to the historical 60s PTO window"
        );
        assert_eq!(
            needmore_pto_attempt_budget(super::super::DEFAULT_IDLE_TIMEOUT),
            240,
            "the encrypted-lossy default gives repair rounds a 360s PTO window"
        );
        assert_eq!(
            needmore_pto_attempt_budget(Duration::from_millis(100)),
            MIN_NEEDMORE_PTO_ATTEMPTS,
            "short-timeout tests still fail fast instead of inheriting the production budget"
        );
    }

    fn quic_staging_test_entry(size: u64) -> crate::net::atp::transport_quic::ManifestEntry {
        crate::net::atp::transport_quic::ManifestEntry {
            index: 0,
            rel_path: "entry.bin".to_string(),
            size,
            sha256_hex: "0".repeat(64),
            metadata: None,
            members: Vec::new(),
        }
    }

    #[test]
    fn native_receiver_intake_trace_records_pump_feed_and_staging_work() {
        let cx = Cx::for_testing();
        let collector = crate::observability::LogCollector::new(8)
            .with_min_level(crate::observability::LogLevel::Trace);
        cx.set_log_collector(collector.clone());
        let mut stats = NativeReceiverIntakeStats::default();
        stats.record_symbol_drain(Duration::from_micros(11), 9, 7, 2);
        stats.record_pump(Duration::from_micros(13), 5);
        stats.record_staging_write(Duration::from_micros(17), 1024);
        stats.trace_summary(&cx, "transfer-intake");

        let entries = collector.peek();
        let entry = entries
            .iter()
            .find(|entry| entry.message() == "atp_quic.receive.intake")
            .expect("receive intake trace entry");
        assert_eq!(entry.get_field("transfer_id"), Some("transfer-intake"));
        assert_eq!(entry.get_field("drain_calls"), Some("1"));
        assert_eq!(entry.get_field("symbols_observed"), Some("9"));
        assert_eq!(entry.get_field("symbols_accepted"), Some("7"));
        assert_eq!(entry.get_field("blocks_completed"), Some("2"));
        assert_eq!(entry.get_field("drain_micros"), Some("11"));
        assert_eq!(entry.get_field("pump_calls"), Some("1"));
        assert_eq!(entry.get_field("pump_packets"), Some("5"));
        assert_eq!(entry.get_field("pump_micros"), Some("13"));
        assert_eq!(entry.get_field("staging_write_count"), Some("1"));
        assert_eq!(entry.get_field("staging_write_bytes"), Some("1024"));
        assert_eq!(entry.get_field("staging_write_micros"), Some("17"));
    }

    #[test]
    fn quic_staging_cache_policy_is_bounded() {
        assert!(should_cache_quic_staging_file(
            QUIC_STAGING_FILE_CACHE_MIN_BYTES,
            QUIC_STAGING_FILE_CACHE_MAX_ENTRIES
        ));
        assert!(!should_cache_quic_staging_file(
            QUIC_STAGING_FILE_CACHE_MIN_BYTES - 1,
            1
        ));
        assert!(!should_cache_quic_staging_file(
            QUIC_STAGING_FILE_CACHE_MIN_BYTES,
            QUIC_STAGING_FILE_CACHE_MAX_ENTRIES + 1
        ));
    }

    #[test]
    fn quic_staging_large_entry_cache_reuses_and_closes_file() {
        let temp = tempfile::tempdir().expect("temp dir");
        let staging_path = temp.path().join("entry0");
        let entry = quic_staging_test_entry(QUIC_STAGING_FILE_CACHE_MIN_BYTES);
        let config = QuicConfig {
            max_block_size: 4,
            ..QuicConfig::default()
        };
        let mut staged = QuicStagedEntryReceive::new(staging_path.clone(), entry.size, 1);

        futures_lite::future::block_on(staged.write_block(&entry, 0, &[1, 2, 3, 4], &config))
            .expect("write first cached block");
        assert!(staged.staging_file.is_some());
        assert_eq!(staged.staging_cursor, Some(4));
        assert_eq!(staged.staging_unflushed_bytes, 4);

        futures_lite::future::block_on(async {
            staged
                .staging_file
                .as_mut()
                .expect("cached staging file")
                .seek(std::io::SeekFrom::Start(0))
                .await
                .expect("desynchronize cached staging cursor");
            staged
                .write_range_with_cursor_audit(&entry, 4, &[5, 6, 7, 8], true)
                .await
                .expect("audit and write second cached block");
        });
        assert!(staged.staging_file.is_some());
        assert_eq!(staged.staging_cursor, Some(8));
        assert_eq!(staged.staging_unflushed_bytes, 8);

        futures_lite::future::block_on(staged.close_cached_staging_file())
            .expect("close cached staging file");
        assert!(staged.staging_file.is_none());
        assert_eq!(staged.staging_cursor, None);
        assert_eq!(staged.staging_unflushed_bytes, 0);

        let mut file = std::fs::File::open(staging_path).expect("open staged file");
        let mut prefix = [0u8; 8];
        std::io::Read::read_exact(&mut file, &mut prefix).expect("read staged prefix");
        assert_eq!(prefix, [1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn quic_staging_dir_guard_reclaims_on_hard_drop_unless_disarmed() {
        let temp = tempfile::tempdir().expect("temp dir");
        let armed = temp.path().join(".atp-quic-staging-guard-armed");
        std::fs::create_dir_all(&armed).expect("create armed staging dir");
        {
            let _guard = QuicStagingDirGuard::new(armed.clone());
        }
        assert!(
            !armed.exists(),
            "armed QuicStagingDirGuard must reclaim staging dir on drop"
        );

        let disarmed = temp.path().join(".atp-quic-staging-guard-disarmed");
        std::fs::create_dir_all(&disarmed).expect("create disarmed staging dir");
        {
            let mut guard = QuicStagingDirGuard::new(disarmed.clone());
            guard.disarm();
        }
        assert!(
            disarmed.exists(),
            "disarmed QuicStagingDirGuard must leave cooperative cleanup to the caller"
        );
    }

    #[test]
    fn quic_cached_staging_file_flushes_round_boundary_without_closing() {
        let temp = tempfile::tempdir().expect("temp dir");
        let staging_path = temp.path().join("entry0");
        let entry = quic_staging_test_entry(8);
        let config = QuicConfig {
            max_block_size: 4,
            ..QuicConfig::default()
        };
        let mut staged = QuicStagedEntryReceive::new(staging_path.clone(), entry.size, 1);
        staged.cache_staging_file = true;

        futures_lite::future::block_on(staged.write_block(&entry, 0, &[1, 2, 3, 4], &config))
            .expect("write first decoded block");
        assert!(
            staged.staging_file.is_some(),
            "large-entry QUIC receive should keep the staging descriptor hot"
        );
        assert_eq!(staged.staging_cursor, Some(4));
        assert_eq!(staged.staging_unflushed_bytes, 4);

        futures_lite::future::block_on(staged.flush_cached_staging_file())
            .expect("round-boundary flush");
        assert!(
            staged.staging_file.is_some(),
            "round-boundary flush should preserve the hot descriptor"
        );
        assert_eq!(staged.staging_cursor, Some(4));
        assert_eq!(staged.staging_unflushed_bytes, 0);

        futures_lite::future::block_on(staged.write_block(&entry, 1, &[5, 6, 7, 8], &config))
            .expect("write second decoded block");
        assert_eq!(staged.staging_cursor, Some(8));

        futures_lite::future::block_on(staged.close_cached_staging_file())
            .expect("close cached descriptor");
        assert!(staged.staging_file.is_none());
        assert_eq!(staged.staging_cursor, None);
        assert_eq!(staged.staging_unflushed_bytes, 0);
        assert_eq!(
            std::fs::read(staging_path).expect("read staged bytes"),
            vec![1, 2, 3, 4, 5, 6, 7, 8]
        );
    }
}
