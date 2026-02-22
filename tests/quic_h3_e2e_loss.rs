//! QH3-E3: Adversarial network scenario E2E tests.
//!
//! ACK ranges, loss detection, PTO, congestion edge scenarios.
//! Drives the full native QUIC stack with deterministic seeds and scheduling.
//! No async runtime is required.

use asupersync::cx::Cx;
use asupersync::net::quic_native::{
    AckRange, NativeQuicConnection, NativeQuicConnectionConfig, PacketNumberSpace,
    QuicConnectionState, QuicTransportMachine, SentPacketMeta, StreamRole,
};
use asupersync::types::Time;
use asupersync::util::DetRng;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a test Cx with infinite budget and no cancellation.
fn test_cx() -> Cx {
    Cx::for_testing()
}

/// Deterministic microsecond clock starting at seed-derived offset.
struct DetClock {
    now_micros: u64,
}

impl DetClock {
    fn new(rng: &mut DetRng) -> Self {
        let base_micros = Time::from_millis(1_000).as_nanos() / 1_000;
        let jitter = rng.next_u64() % 1_000;
        Self {
            now_micros: base_micros + jitter,
        }
    }

    fn advance(&mut self, delta_micros: u64) {
        self.now_micros += delta_micros;
    }

    fn now(&self) -> u64 {
        self.now_micros
    }
}

/// A paired client+server connection setup driven through the full handshake.
struct ConnectionPair {
    client: NativeQuicConnection,
    server: NativeQuicConnection,
    cx: Cx,
    clock: DetClock,
}

impl ConnectionPair {
    fn new(rng: &mut DetRng) -> Self {
        let cx = test_cx();
        let clock = DetClock::new(rng);

        let client_cfg = NativeQuicConnectionConfig {
            role: StreamRole::Client,
            max_local_bidi: 64,
            max_local_uni: 64,
            send_window: 1 << 18,
            recv_window: 1 << 18,
            connection_send_limit: 4 << 20,
            connection_recv_limit: 4 << 20,
            drain_timeout_micros: 2_000_000,
        };

        let server_cfg = NativeQuicConnectionConfig {
            role: StreamRole::Server,
            max_local_bidi: 64,
            max_local_uni: 64,
            send_window: 1 << 18,
            recv_window: 1 << 18,
            connection_send_limit: 4 << 20,
            connection_recv_limit: 4 << 20,
            drain_timeout_micros: 2_000_000,
        };

        let client = NativeQuicConnection::new(client_cfg);
        let server = NativeQuicConnection::new(server_cfg);

        Self {
            client,
            server,
            cx,
            clock,
        }
    }

    /// Drive both endpoints through the full handshake to Established state.
    fn establish(&mut self) {
        let cx = &self.cx;

        self.client
            .begin_handshake(cx)
            .expect("client begin_handshake");
        self.server
            .begin_handshake(cx)
            .expect("server begin_handshake");

        assert_eq!(self.client.state(), QuicConnectionState::Handshaking);
        assert_eq!(self.server.state(), QuicConnectionState::Handshaking);

        self.client
            .on_handshake_keys_available(cx)
            .expect("client hs keys");
        self.server
            .on_handshake_keys_available(cx)
            .expect("server hs keys");

        self.client
            .on_1rtt_keys_available(cx)
            .expect("client 1rtt keys");
        self.server
            .on_1rtt_keys_available(cx)
            .expect("server 1rtt keys");

        self.client
            .on_handshake_confirmed(cx)
            .expect("client confirmed");
        self.server
            .on_handshake_confirmed(cx)
            .expect("server confirmed");

        assert_eq!(self.client.state(), QuicConnectionState::Established);
        assert_eq!(self.server.state(), QuicConnectionState::Established);
        assert!(self.client.can_send_1rtt());
        assert!(self.server.can_send_1rtt());
    }
}

/// Convenience: build a SentPacketMeta for direct QuicTransportMachine use.
fn sent(space: PacketNumberSpace, pn: u64, bytes: u64, t: u64) -> SentPacketMeta {
    SentPacketMeta {
        space,
        packet_number: pn,
        bytes,
        ack_eliciting: true,
        in_flight: true,
        time_sent_micros: t,
    }
}

// ===========================================================================
// Test 1: ACK with gaps (selective ACK) -- odd-numbered ACKed, even remain
// ===========================================================================

#[test]
fn selective_ack_with_gaps_odd_only() {
    let mut rng = DetRng::new(0xE3_0001);
    let mut pair = ConnectionPair::new(&mut rng);
    pair.establish();

    let cx = &pair.cx;

    // Send 10 packets (pn 0..9) from the client.
    let t_base = pair.clock.now();
    for i in 0u64..10 {
        pair.client
            .on_packet_sent(
                cx,
                PacketNumberSpace::ApplicationData,
                1200,
                true,
                true,
                t_base + i * 100,
            )
            .unwrap_or_else(|_| panic!("send pn {i}"));
    }

    let bif_before = pair.client.transport().bytes_in_flight();
    assert_eq!(bif_before, 12_000, "10 packets x 1200 bytes");

    // ACK only odd-numbered packets: 1, 3, 5, 7, 9.
    pair.clock.advance(20_000); // 20ms RTT
    let ack = pair
        .client
        .on_ack_received(
            cx,
            PacketNumberSpace::ApplicationData,
            &[1, 3, 5, 7, 9],
            0,
            pair.clock.now(),
        )
        .expect("ack odd");

    assert_eq!(
        ack.acked_packets, 5,
        "5 odd-numbered packets should be acked"
    );
    assert_eq!(ack.acked_bytes, 5 * 1200, "5 packets x 1200 bytes acked");

    // Packets 0, 2, 4, 6 are unacked. Largest acked = 9.
    // Packet-threshold loss: pn + 3 <= largest_acked (9).
    //   pn 0: 0+3=3 <= 9 => lost
    //   pn 2: 2+3=5 <= 9 => lost
    //   pn 4: 4+3=7 <= 9 => lost
    //   pn 6: 6+3=9 <= 9 => lost
    //   pn 8: 8+3=11 > 9 => NOT lost
    // But pn 8 was not in the ack set either (it's even). Wait -- pn 8 was
    // never acked, and 8+3=11 > 9, so pn 8 stays in-flight.
    // Actually re-checking: we sent pn 0..9, acked 1,3,5,7,9.
    // Unacked: 0,2,4,6,8. Packet threshold detects 0,2,4,6 as lost (all have pn+3 <= 9).
    // pn 8 survives (8+3=11 > 9).
    assert_eq!(ack.lost_packets, 4, "pn 0,2,4,6 should be detected as lost");
    assert_eq!(ack.lost_bytes, 4 * 1200);

    // Remaining in-flight: only pn 8.
    let bif_after = pair.client.transport().bytes_in_flight();
    assert_eq!(bif_after, 1200, "only pn 8 should remain in-flight");
}

// ===========================================================================
// Test 2: ACK with explicit AckRange gaps
// ===========================================================================

#[test]
fn selective_ack_via_explicit_ranges() {
    let mut rng = DetRng::new(0xE3_0002);
    let mut pair = ConnectionPair::new(&mut rng);
    pair.establish();

    let cx = &pair.cx;
    let t_base = pair.clock.now();

    // Send 10 packets.
    for i in 0u64..10 {
        pair.client
            .on_packet_sent(
                cx,
                PacketNumberSpace::ApplicationData,
                1200,
                true,
                true,
                t_base + i * 100,
            )
            .unwrap_or_else(|_| panic!("send pn {i}"));
    }

    pair.clock.advance(20_000);

    // ACK via explicit ranges: [1..1], [3..3], [5..5], [7..9]
    // This acks pn 1, 3, 5, 7, 8, 9 = 6 packets.
    let ranges = [
        AckRange::new(9, 7).expect("range 7..9"),
        AckRange::new(5, 5).expect("range 5"),
        AckRange::new(3, 3).expect("range 3"),
        AckRange::new(1, 1).expect("range 1"),
    ];

    let ack = pair
        .client
        .on_ack_ranges(
            cx,
            PacketNumberSpace::ApplicationData,
            &ranges,
            0,
            pair.clock.now(),
        )
        .expect("ack ranges");

    assert_eq!(ack.acked_packets, 6, "6 packets should be acked");
    assert_eq!(ack.acked_bytes, 6 * 1200);

    // Unacked: 0, 2, 4, 6. Largest acked = 9.
    // All 4 unacked: pn+3 <= 9, so all lost via packet threshold.
    assert_eq!(ack.lost_packets, 4, "pn 0,2,4,6 should be detected as lost");
}

// ===========================================================================
// Test 3: Loss detection via time threshold
// ===========================================================================

#[test]
#[allow(clippy::too_many_lines)]
fn loss_detection_via_time_threshold() {
    let mut rng = DetRng::new(0xE3_0003);
    let mut pair = ConnectionPair::new(&mut rng);
    pair.establish();

    let cx = &pair.cx;

    // First establish an RTT sample: send pn 0 at t=base, ack at t=base+20ms.
    let t_base = pair.clock.now();
    pair.client
        .on_packet_sent(
            cx,
            PacketNumberSpace::ApplicationData,
            1200,
            true,
            true,
            t_base,
        )
        .expect("send pn 0");

    pair.clock.advance(20_000);
    let ack0 = pair
        .client
        .on_ack_received(
            cx,
            PacketNumberSpace::ApplicationData,
            &[0],
            0,
            pair.clock.now(),
        )
        .expect("ack pn 0");
    assert_eq!(ack0.acked_packets, 1);

    // Verify RTT = 20ms.
    let srtt = pair
        .client
        .transport()
        .rtt()
        .smoothed_rtt_micros()
        .expect("should have RTT");
    assert_eq!(srtt, 20_000);

    // loss_delay = max(9 * latest_rtt / 8, 1_000) = max(9*20_000/8, 1_000) = 22_500 us
    let loss_delay = 22_500u64;

    // Send pn 1 and pn 2 close together.
    let t_send1 = pair.clock.now();
    pair.client
        .on_packet_sent(
            cx,
            PacketNumberSpace::ApplicationData,
            1200,
            true,
            true,
            t_send1,
        )
        .expect("send pn 1");
    pair.clock.advance(100);
    pair.client
        .on_packet_sent(
            cx,
            PacketNumberSpace::ApplicationData,
            1200,
            true,
            true,
            pair.clock.now(),
        )
        .expect("send pn 2");

    // ACK pn 2 only, but NOT enough time has passed for pn 1 time-threshold loss.
    // pn 1 is only 1 packet behind (1+3=4 > 2), so no packet-threshold loss.
    pair.clock.advance(10_000); // Only 10ms after pn 1 was sent
    let ack1 = pair
        .client
        .on_ack_received(
            cx,
            PacketNumberSpace::ApplicationData,
            &[2],
            0,
            pair.clock.now(),
        )
        .expect("ack pn 2 early");
    assert_eq!(ack1.acked_packets, 1);
    assert_eq!(
        ack1.lost_packets, 0,
        "too early for time-threshold loss on pn 1"
    );

    // Now send pn 3 and ack it at a time well past loss_delay from pn 1's send time.
    pair.clock.advance(loss_delay + 5_000); // well past threshold
    let t_send3 = pair.clock.now();
    pair.client
        .on_packet_sent(
            cx,
            PacketNumberSpace::ApplicationData,
            1200,
            true,
            true,
            t_send3,
        )
        .expect("send pn 3");

    pair.clock.advance(5_000);
    let ack2 = pair
        .client
        .on_ack_received(
            cx,
            PacketNumberSpace::ApplicationData,
            &[3],
            0,
            pair.clock.now(),
        )
        .expect("ack pn 3");
    assert_eq!(ack2.acked_packets, 1);
    assert_eq!(
        ack2.lost_packets, 1,
        "pn 1 should be detected as lost via time threshold"
    );
    assert_eq!(ack2.lost_bytes, 1200);
}

// ===========================================================================
// Test 4: PTO (Probe Timeout) fire
// ===========================================================================

#[test]
fn pto_fire_after_timeout() {
    let mut rng = DetRng::new(0xE3_0004);
    let mut pair = ConnectionPair::new(&mut rng);
    pair.establish();

    let cx = &pair.cx;

    // Establish an RTT sample first.
    let t0 = pair.clock.now();
    pair.client
        .on_packet_sent(cx, PacketNumberSpace::ApplicationData, 1200, true, true, t0)
        .expect("send pn 0");
    pair.clock.advance(30_000); // 30ms RTT
    pair.client
        .on_ack_received(
            cx,
            PacketNumberSpace::ApplicationData,
            &[0],
            0,
            pair.clock.now(),
        )
        .expect("ack pn 0");

    // Send a new packet and don't ACK it.
    let t1 = pair.clock.now();
    pair.client
        .on_packet_sent(cx, PacketNumberSpace::ApplicationData, 1200, true, true, t1)
        .expect("send pn 1");

    // Get PTO deadline.
    let pto_deadline = pair
        .client
        .pto_deadline_micros(cx, t1)
        .expect("pto_deadline")
        .expect("should have deadline with bytes in flight");
    assert!(pto_deadline > t1, "PTO deadline should be in the future");

    // Advance clock past PTO deadline.
    let advance_needed = pto_deadline - pair.clock.now() + 1;
    pair.clock.advance(advance_needed);
    assert!(pair.clock.now() > pto_deadline);

    // Fire PTO.
    pair.client.on_pto_expired(cx).expect("pto expired");

    // Verify we can still send a probe packet (PTO allows sending even if
    // nothing was acked, it's a recovery mechanism).
    let t_probe = pair.clock.now();
    let probe_pn = pair
        .client
        .on_packet_sent(
            cx,
            PacketNumberSpace::ApplicationData,
            1200,
            true,
            true,
            t_probe,
        )
        .expect("send probe after PTO");
    assert_eq!(probe_pn, 2, "probe packet should get next packet number");

    // PTO deadline should now be further out due to backoff.
    let pto_deadline2 = pair
        .client
        .pto_deadline_micros(cx, pair.clock.now())
        .expect("pto_deadline after backoff")
        .expect("should have deadline");
    // The second PTO deadline (computed from same now) should be further out
    // because pto_count=1 means 2x backoff.
    let base_pto_timeout = pto_deadline - t1;
    let after_pto_timeout = pto_deadline2 - pair.clock.now();
    assert!(
        after_pto_timeout > base_pto_timeout,
        "PTO should be backed off: {after_pto_timeout} > {base_pto_timeout}"
    );
}

// ===========================================================================
// Test 5: PTO backoff capping at 2^10
// ===========================================================================

#[test]
fn pto_backoff_capping() {
    // Use QuicTransportMachine directly for precise control.
    let mut t = QuicTransportMachine::new();
    t.begin_handshake().expect("hs");
    t.on_established().expect("est");

    // Send a packet to enable PTO deadline computation.
    t.on_packet_sent(sent(PacketNumberSpace::ApplicationData, 0, 1200, 10_000));

    // Establish RTT.
    t.on_packet_sent(sent(PacketNumberSpace::ApplicationData, 1, 1200, 10_100));
    let _ = t.on_ack_received(PacketNumberSpace::ApplicationData, &[1], 0, 30_000);

    let now = 50_000u64;

    // Get base PTO timeout (pto_count=0).
    let base_deadline = t.pto_deadline_micros(now).expect("base deadline");
    let base_timeout = base_deadline - now;

    // Fire PTO 10 times.
    for _ in 0..10 {
        t.on_pto_expired();
    }
    let deadline_at_10 = t.pto_deadline_micros(now).expect("deadline at 10");
    let timeout_at_10 = deadline_at_10 - now;

    // Should be 2^10 = 1024x.
    assert_eq!(
        timeout_at_10,
        base_timeout * 1024,
        "PTO at count=10 should be 1024x base: {timeout_at_10} == {base_timeout} * 1024"
    );

    // Fire 5 more PTOs (total 15).
    for _ in 0..5 {
        t.on_pto_expired();
    }
    let deadline_at_15 = t.pto_deadline_micros(now).expect("deadline at 15");
    let timeout_at_15 = deadline_at_15 - now;

    // Should still be capped at 2^10 = 1024x (min(15, 10) = 10).
    assert_eq!(
        timeout_at_15, timeout_at_10,
        "PTO at count=15 should be capped at same as count=10: {timeout_at_15} == {timeout_at_10}"
    );
}

// ===========================================================================
// Test 6: Congestion window reduction on loss
// ===========================================================================

#[test]
fn congestion_window_reduction_on_loss() {
    let mut t = QuicTransportMachine::new();
    t.begin_handshake().expect("hs");
    t.on_established().expect("est");

    let initial_cwnd = t.congestion_window_bytes();
    assert_eq!(initial_cwnd, 12_000, "default cwnd");
    assert_eq!(
        t.ssthresh_bytes(),
        u64::MAX,
        "initial ssthresh is infinity (slow start)"
    );

    // Grow cwnd in slow start: send and ack multiple packets.
    // Slow start: cwnd grows by acked_bytes.
    for pn in 0u64..5 {
        t.on_packet_sent(sent(
            PacketNumberSpace::ApplicationData,
            pn,
            1200,
            10_000 + pn * 100,
        ));
    }
    // ACK all 5 individually to grow cwnd.
    let _ = t.on_ack_received(
        PacketNumberSpace::ApplicationData,
        &[0, 1, 2, 3, 4],
        0,
        30_000,
    );
    let cwnd_after_growth = t.congestion_window_bytes();
    assert!(
        cwnd_after_growth > initial_cwnd,
        "cwnd should have grown in slow start: {cwnd_after_growth} > {initial_cwnd}"
    );

    // Now send packets that will trigger packet-threshold loss.
    // Send pn 5..11 (7 packets).
    for pn in 5u64..12 {
        t.on_packet_sent(sent(
            PacketNumberSpace::ApplicationData,
            pn,
            1200,
            40_000 + pn * 100,
        ));
    }

    // ACK only pn 11 -- this triggers packet-threshold loss for pn 5..8
    // (pn + 3 <= 11).
    let ack = t.on_ack_received(PacketNumberSpace::ApplicationData, &[11], 0, 60_000);
    assert!(ack.lost_packets > 0, "should detect loss");

    let cwnd_after_loss = t.congestion_window_bytes();
    let ssthresh_after_loss = t.ssthresh_bytes();

    // The ACK processing order: on_ack_congestion(acked_bytes) runs first,
    // then on_loss_congestion() halves the window.
    // Slow start growth: cwnd_after_growth + acked_bytes (1200) = inflated cwnd.
    // Then halved: max(inflated/2, 2*max_datagram_size).
    let min_cwnd = 2 * 1200u64;
    let inflated = cwnd_after_growth + ack.acked_bytes;
    let expected_reduced = (inflated / 2).max(min_cwnd);
    assert_eq!(
        cwnd_after_loss, expected_reduced,
        "cwnd should be halved after ack-then-loss: {cwnd_after_loss} == {expected_reduced}"
    );
    assert_eq!(
        ssthresh_after_loss, cwnd_after_loss,
        "ssthresh should equal reduced cwnd"
    );
}

// ===========================================================================
// Test 7: RTT estimation with variable delays
// ===========================================================================

#[test]
fn rtt_estimation_with_variable_delays() {
    let mut rng = DetRng::new(0xE3_0007);
    let mut pair = ConnectionPair::new(&mut rng);
    pair.establish();

    let cx = &pair.cx;

    // Send packets with varying ACK delays to test RTT convergence.
    // Round-trip times: 20ms, 40ms, 30ms, 25ms, 22ms.
    let rtts_us = [20_000u64, 40_000, 30_000, 25_000, 22_000];

    let mut t_current = pair.clock.now();
    let mut prev_srtt = None;
    let mut srtt_values = Vec::new();

    for (i, &rtt) in rtts_us.iter().enumerate() {
        let pn = i as u64;
        let t_send = t_current;
        pair.client
            .on_packet_sent(
                cx,
                PacketNumberSpace::ApplicationData,
                1200,
                true,
                true,
                t_send,
            )
            .unwrap_or_else(|_| panic!("send pn {pn}"));

        t_current += rtt;
        pair.clock.advance(rtt);

        let ack = pair
            .client
            .on_ack_received(cx, PacketNumberSpace::ApplicationData, &[pn], 0, t_current)
            .unwrap_or_else(|_| panic!("ack pn {pn}"));
        assert_eq!(ack.acked_packets, 1);

        let srtt = pair
            .client
            .transport()
            .rtt()
            .smoothed_rtt_micros()
            .expect("should have SRTT");
        srtt_values.push(srtt);
        prev_srtt = Some(srtt);
    }

    // First sample: srtt = 20_000.
    assert_eq!(srtt_values[0], 20_000);

    // EWMA should converge. After all 5 samples, srtt should be
    // between min and max RTT samples.
    let final_srtt = prev_srtt.expect("final srtt");
    assert!(
        (20_000..=40_000).contains(&final_srtt),
        "smoothed RTT should be between min and max samples: {final_srtt}"
    );

    // Verify RTT variance is also populated.
    let rttvar = pair
        .client
        .transport()
        .rtt()
        .rttvar_micros()
        .expect("should have rttvar");
    assert!(
        rttvar > 0,
        "rttvar should be positive after variable delays"
    );
}

// ===========================================================================
// Test 8: RTT estimation with ack_delay subtraction
// ===========================================================================

#[test]
fn rtt_estimation_with_ack_delay() {
    let mut rng = DetRng::new(0xE3_0008);
    let mut pair = ConnectionPair::new(&mut rng);
    pair.establish();

    let cx = &pair.cx;

    // First sample: real RTT 20ms, ack_delay 0.
    let t0 = pair.clock.now();
    pair.client
        .on_packet_sent(cx, PacketNumberSpace::ApplicationData, 1200, true, true, t0)
        .expect("send pn 0");
    pair.clock.advance(20_000);
    pair.client
        .on_ack_received(
            cx,
            PacketNumberSpace::ApplicationData,
            &[0],
            0,
            pair.clock.now(),
        )
        .expect("ack pn 0");
    let srtt0 = pair.client.transport().rtt().smoothed_rtt_micros().unwrap();
    assert_eq!(srtt0, 20_000);

    // Second sample: observed 30ms, but 5ms is ack_delay.
    // Adjusted should be 30_000 - min(5_000, 30_000 - 20_000) = 30_000 - 5_000 = 25_000.
    let t1 = pair.clock.now();
    pair.client
        .on_packet_sent(cx, PacketNumberSpace::ApplicationData, 1200, true, true, t1)
        .expect("send pn 1");
    pair.clock.advance(30_000);
    pair.client
        .on_ack_received(
            cx,
            PacketNumberSpace::ApplicationData,
            &[1],
            5_000,
            pair.clock.now(),
        )
        .expect("ack pn 1");

    let srtt1 = pair.client.transport().rtt().smoothed_rtt_micros().unwrap();
    // EWMA: (7 * 20_000 + 25_000) / 8 = 165_000 / 8 = 20_625
    assert_eq!(srtt1, 20_625);
}

// ===========================================================================
// Test 9: Bytes-in-flight tracking across multiple spaces
// ===========================================================================

#[test]
fn bytes_in_flight_across_spaces() {
    let mut rng = DetRng::new(0xE3_0009);
    let mut pair = ConnectionPair::new(&mut rng);

    let cx = &pair.cx;

    // Start handshake to allow sending Initial/Handshake packets.
    pair.client.begin_handshake(cx).expect("client begin");
    pair.server.begin_handshake(cx).expect("server begin");

    let t0 = pair.clock.now();

    // Send Initial packets.
    pair.client
        .on_packet_sent(cx, PacketNumberSpace::Initial, 1200, true, true, t0)
        .expect("send Initial pn 0");
    pair.client
        .on_packet_sent(cx, PacketNumberSpace::Initial, 1200, true, true, t0 + 100)
        .expect("send Initial pn 1");
    assert_eq!(pair.client.transport().bytes_in_flight(), 2400);

    // Send Handshake packets.
    pair.client
        .on_packet_sent(cx, PacketNumberSpace::Handshake, 800, true, true, t0 + 200)
        .expect("send Handshake pn 0");
    assert_eq!(pair.client.transport().bytes_in_flight(), 3200);

    // Complete handshake, then send AppData packets.
    pair.client
        .on_handshake_keys_available(cx)
        .expect("hs keys");
    pair.server
        .on_handshake_keys_available(cx)
        .expect("hs keys");
    pair.client.on_1rtt_keys_available(cx).expect("1rtt keys");
    pair.server.on_1rtt_keys_available(cx).expect("1rtt keys");
    pair.client.on_handshake_confirmed(cx).expect("confirmed");
    pair.server.on_handshake_confirmed(cx).expect("confirmed");

    pair.client
        .on_packet_sent(
            cx,
            PacketNumberSpace::ApplicationData,
            1000,
            true,
            true,
            t0 + 300,
        )
        .expect("send AppData pn 0");
    assert_eq!(
        pair.client.transport().bytes_in_flight(),
        4200,
        "2400 (Initial) + 800 (Handshake) + 1000 (AppData)"
    );

    // ACK Initial pn 0: should reduce by 1200.
    pair.clock.advance(20_000);
    let ack_init = pair
        .client
        .on_ack_received(cx, PacketNumberSpace::Initial, &[0], 0, pair.clock.now())
        .expect("ack Initial pn 0");
    assert_eq!(ack_init.acked_packets, 1);
    assert_eq!(pair.client.transport().bytes_in_flight(), 3000);

    // ACK Handshake pn 0: should reduce by 800.
    let ack_hs = pair
        .client
        .on_ack_received(cx, PacketNumberSpace::Handshake, &[0], 0, pair.clock.now())
        .expect("ack Handshake pn 0");
    assert_eq!(ack_hs.acked_packets, 1);
    assert_eq!(pair.client.transport().bytes_in_flight(), 2200);

    // ACK AppData pn 0: should reduce by 1000.
    let ack_app = pair
        .client
        .on_ack_received(
            cx,
            PacketNumberSpace::ApplicationData,
            &[0],
            0,
            pair.clock.now(),
        )
        .expect("ack AppData pn 0");
    assert_eq!(ack_app.acked_packets, 1);
    assert_eq!(pair.client.transport().bytes_in_flight(), 1200);

    // ACK remaining Initial pn 1.
    let ack_init1 = pair
        .client
        .on_ack_received(cx, PacketNumberSpace::Initial, &[1], 0, pair.clock.now())
        .expect("ack Initial pn 1");
    assert_eq!(ack_init1.acked_packets, 1);
    assert_eq!(pair.client.transport().bytes_in_flight(), 0);
}

// ===========================================================================
// Test 10: Recovery from sustained loss cycle
// ===========================================================================

#[test]
fn recovery_from_sustained_loss() {
    let mut t = QuicTransportMachine::new();
    t.begin_handshake().expect("hs");
    t.on_established().expect("est");

    let initial_cwnd = t.congestion_window_bytes();

    // --- Phase 1: Normal operation (slow start growth) ---
    for pn in 0u64..5 {
        t.on_packet_sent(sent(
            PacketNumberSpace::ApplicationData,
            pn,
            1200,
            10_000 + pn * 100,
        ));
    }
    let _ = t.on_ack_received(
        PacketNumberSpace::ApplicationData,
        &[0, 1, 2, 3, 4],
        0,
        30_000,
    );
    let cwnd_after_growth = t.congestion_window_bytes();
    assert!(
        cwnd_after_growth > initial_cwnd,
        "Phase 1: cwnd should grow"
    );

    // --- Phase 2: Loss event (cwnd reduced) ---
    for pn in 10u64..17 {
        t.on_packet_sent(sent(
            PacketNumberSpace::ApplicationData,
            pn,
            1200,
            40_000 + pn * 100,
        ));
    }
    let loss_event = t.on_ack_received(PacketNumberSpace::ApplicationData, &[16], 0, 60_000);
    assert!(loss_event.lost_packets > 0, "Phase 2: should detect loss");
    let cwnd_after_loss = t.congestion_window_bytes();
    assert!(
        cwnd_after_loss < cwnd_after_growth,
        "Phase 2: cwnd should decrease"
    );
    let ssthresh = t.ssthresh_bytes();
    assert_eq!(cwnd_after_loss, ssthresh);

    // Clean up remaining unacked packets from phase 2.
    let _ = t.on_ack_received(PacketNumberSpace::ApplicationData, &[13, 14, 15], 0, 61_000);

    // --- Phase 3: Recovery (congestion avoidance, additive increase) ---
    let cwnd_before_recovery = t.congestion_window_bytes();
    for pn in 20u64..30 {
        t.on_packet_sent(sent(
            PacketNumberSpace::ApplicationData,
            pn,
            1200,
            70_000 + pn * 100,
        ));
    }
    // ACK all 10 recovery packets.
    let recovery_ack = t.on_ack_received(
        PacketNumberSpace::ApplicationData,
        &[20, 21, 22, 23, 24, 25, 26, 27, 28, 29],
        0,
        90_000,
    );
    assert_eq!(recovery_ack.lost_packets, 0, "Phase 3: no loss in recovery");
    let cwnd_after_recovery = t.congestion_window_bytes();
    assert!(
        cwnd_after_recovery > cwnd_before_recovery,
        "Phase 3: cwnd should grow during recovery: {cwnd_after_recovery} > {cwnd_before_recovery}"
    );

    // --- Phase 4: Normal resumed ---
    // Verify we are in congestion avoidance (cwnd >= ssthresh), growing slowly.
    assert!(t.congestion_window_bytes() >= t.ssthresh_bytes());
    let cwnd_pre = t.congestion_window_bytes();
    t.on_packet_sent(sent(PacketNumberSpace::ApplicationData, 50, 1200, 100_000));
    let _ = t.on_ack_received(PacketNumberSpace::ApplicationData, &[50], 0, 120_000);
    let cwnd_post = t.congestion_window_bytes();
    assert!(
        cwnd_post > cwnd_pre,
        "Phase 4: cwnd should continue growing: {cwnd_post} > {cwnd_pre}"
    );
    let growth = cwnd_post - cwnd_pre;
    // Additive increase: growth = (1200 * 1200) / cwnd, which is small.
    assert!(
        growth < 1200,
        "Phase 4: congestion avoidance growth should be sub-linear: {growth} < 1200"
    );
}

// ===========================================================================
// Test 11: PTO counter reset on successful ACK
// ===========================================================================

#[test]
fn pto_counter_resets_on_ack() {
    let mut t = QuicTransportMachine::new();
    t.begin_handshake().expect("hs");
    t.on_established().expect("est");

    // Establish RTT.
    t.on_packet_sent(sent(PacketNumberSpace::ApplicationData, 0, 1200, 10_000));
    let _ = t.on_ack_received(PacketNumberSpace::ApplicationData, &[0], 0, 30_000);

    // Send a packet, don't ack, fire PTO multiple times.
    t.on_packet_sent(sent(PacketNumberSpace::ApplicationData, 1, 1200, 40_000));

    let now = 50_000u64;
    let base_deadline = t.pto_deadline_micros(now).expect("base");
    let base_timeout = base_deadline - now;

    // Fire 5 PTOs.
    for _ in 0..5 {
        t.on_pto_expired();
    }
    let backed_off_deadline = t.pto_deadline_micros(now).expect("backed off");
    let backed_off_timeout = backed_off_deadline - now;
    assert_eq!(backed_off_timeout, base_timeout * 32, "2^5 = 32x backoff");

    // Now ACK pn 1 -- this should reset pto_count to 0.
    // Note: this ACK also updates the RTT estimator, which may change the
    // base PTO timeout slightly.
    let _ = t.on_ack_received(PacketNumberSpace::ApplicationData, &[1], 0, 60_000);

    // Send new packet so there are bytes in flight for PTO deadline.
    t.on_packet_sent(sent(PacketNumberSpace::ApplicationData, 2, 1200, 70_000));

    // Compute PTO after reset. The pto_count should be 0, so backoff = 1x.
    let reset_deadline = t.pto_deadline_micros(now).expect("reset");
    let reset_timeout = reset_deadline - now;

    // The reset timeout (backoff=1x) should be drastically smaller than
    // the backed-off timeout (backoff=32x). Specifically it should be
    // the backed-off value / 32, give or take RTT estimate changes.
    let backed_off_div16 = backed_off_timeout / 16;
    assert!(
        reset_timeout < backed_off_div16,
        "PTO should be reset (much smaller than backed-off): {reset_timeout} < {backed_off_timeout} / 16 = {backed_off_div16}"
    );

    // Verify the reset timeout is close to a 1x base (within 2x of the
    // original base, accounting for RTT EWMA drift).
    assert!(
        reset_timeout <= base_timeout * 2,
        "Reset PTO should be within 2x of original base: {reset_timeout} <= {base_timeout} * 2"
    );
}

// ===========================================================================
// Test 12: Non-in-flight packets don't affect bytes-in-flight or loss
// ===========================================================================

#[test]
fn non_in_flight_packets_excluded_from_tracking() {
    let mut rng = DetRng::new(0xE3_000C);
    let mut pair = ConnectionPair::new(&mut rng);
    pair.establish();

    let cx = &pair.cx;

    // Send a mix of in-flight and non-in-flight packets via transport directly.
    let transport = &mut pair.client;

    // pn 0: in-flight (via on_packet_sent which enforces congestion).
    let t0 = pair.clock.now();
    transport
        .on_packet_sent(cx, PacketNumberSpace::ApplicationData, 1200, true, true, t0)
        .expect("send pn 0 in-flight");
    assert_eq!(transport.transport().bytes_in_flight(), 1200);

    // pn 1: NOT in-flight (e.g., ACK-only frame).
    transport
        .on_packet_sent(
            cx,
            PacketNumberSpace::ApplicationData,
            50,
            true,
            false,
            t0 + 100,
        )
        .expect("send pn 1 not-in-flight");
    assert_eq!(
        transport.transport().bytes_in_flight(),
        1200,
        "non-in-flight packet should not increase bytes_in_flight"
    );

    // pn 2, 3, 4: in-flight.
    for i in 2u64..5 {
        transport
            .on_packet_sent(
                cx,
                PacketNumberSpace::ApplicationData,
                1200,
                true,
                true,
                t0 + i * 100,
            )
            .unwrap_or_else(|_| panic!("send pn {i}"));
    }
    assert_eq!(
        transport.transport().bytes_in_flight(),
        4800,
        "4 in-flight packets x 1200"
    );

    // ACK pn 1 (non-in-flight): should NOT change bytes_in_flight.
    pair.clock.advance(20_000);
    let ack_nofly = transport
        .on_ack_received(
            cx,
            PacketNumberSpace::ApplicationData,
            &[1],
            0,
            pair.clock.now(),
        )
        .expect("ack pn 1");
    assert_eq!(ack_nofly.acked_packets, 1);
    assert_eq!(
        ack_nofly.acked_bytes, 0,
        "non-in-flight ack has 0 acked_bytes"
    );
    assert_eq!(transport.transport().bytes_in_flight(), 4800);

    // ACK pn 4 (in-flight, triggers loss of pn 0 via packet threshold: 0+3=3 <= 4).
    let ack_loss = transport
        .on_ack_received(
            cx,
            PacketNumberSpace::ApplicationData,
            &[4],
            0,
            pair.clock.now(),
        )
        .expect("ack pn 4");
    assert_eq!(ack_loss.acked_packets, 1);
    assert_eq!(ack_loss.acked_bytes, 1200);
    assert_eq!(ack_loss.lost_packets, 1, "pn 0 lost via packet threshold");
    assert_eq!(ack_loss.lost_bytes, 1200);
    // Remaining: pn 2 (1200) + pn 3 (1200) = 2400.
    assert_eq!(transport.transport().bytes_in_flight(), 2400);
}
