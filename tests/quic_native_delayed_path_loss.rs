#![cfg(feature = "test-internals")]
#![allow(missing_docs)]
//! GH#71 / asupersync-mwzmp2: spurious loss and cwnd collapse on a clean
//! delayed path.
//!
//! Two `NativeQuicConnection`s exchange real 1-RTT frame payloads through a
//! deterministic constant-delay link under a virtual clock. Each peer is
//! driven with the cadence the reporter used
//! (`NativeQuicUdpConnection::drive_io_once(cx, 5 ms)` between application
//! steps): a receive wait bounded by the PTO deadline, at most 32 packets per
//! receive batch, a due-loss-timer check, then a flush of at most 64
//! congestion-admitted packets in which a cwnd-full sender still emits
//! ACK-only packets. No sockets, no crypto, no wall clock: every number below
//! is a replayable function of the seed-free schedule.
//!
//! The reported field defect (two hosts, ~29 ms RTT, 1 MiB echo): 736 of
//! 1032 packets declared lost with `pto_count` 0, cwnd collapsed to 2400,
//! 14.3 s elapsed. Loopback hides it because the loopback sender is never
//! cwnd-limited and therefore never emits ACK-only packets.

use asupersync::bytes::{Bytes, BytesMut};
use asupersync::cx::Cx;
use asupersync::net::atp::protocol::quic_frames::QuicFrame;
use asupersync::net::quic_native::{
    NativeQuicConnection, NativeQuicConnectionConfig, PacketNumberSpace, QuicConnectionState,
    StreamId, StreamRole,
};
use std::collections::VecDeque;
use std::num::NonZeroU64;

// ---------------------------------------------------------------------------
// Driver constants mirrored from `src/net/quic_native/udp_connection.rs` and
// `connection_manager.rs`. They are copied (not imported) on purpose: the
// harness must keep the reporter's cadence even if the driver retunes later.
// ---------------------------------------------------------------------------

/// `drive_io_once` receive wait the reporter's `serve` / `connect-remote`
/// scenarios pass (5 ms).
const RECEIVE_WAIT_MICROS: u64 = 5_000;
/// `RECEIVE_BATCH_SIZE` in `udp_connection.rs`.
const RECEIVE_BATCH_SIZE: usize = 32;
/// `MAX_PACKETS_PER_FLUSH` in `udp_connection.rs`.
const MAX_PACKETS_PER_FLUSH: usize = 64;
/// `PROTECTED_1RTT_MAX_PACKET_BYTES` in `connection_manager.rs`; also the
/// admission size `generate_congestion_admitted_1rtt_frames` checks.
const PROTECTED_1RTT_MAX_PACKET_BYTES: usize = 1_200;
/// Short header (flags + 8-byte CID + 4-byte packet number) plus AEAD tag, as
/// `protected_1rtt_packet_len(cid, 0)` computes for an 8-byte CID.
const PACKET_OVERHEAD_BYTES: usize = 1 + 8 + 4 + 16;
/// Frame budget per packet, as `NativeQuicUdpConnection::flush` derives it.
const MAX_FRAME_BYTES: usize = PROTECTED_1RTT_MAX_PACKET_BYTES - PACKET_OVERHEAD_BYTES;

/// Reporter's application chunking: 4 KiB writes, at most 64 KiB queued.
const CHUNK: usize = 4_096;
const MAX_QUEUED: u64 = 64 * 1_024;
/// Reporter's stream / connection receive window advertisements.
const STREAM_RECV_WINDOW: u64 = 1 << 20;
const CONNECTION_RECV_SLACK: u64 = 16 << 20;
/// Reporter's transfer deadline (virtual here).
const VIRTUAL_DEADLINE_MICROS: u64 = 120_000_000;

/// The reported path: ~29 ms RTT.
const REPORTED_ONE_WAY_DELAY_MICROS: u64 = 14_500;
/// A longer WAN-class path: 60 ms RTT.
const LONG_ONE_WAY_DELAY_MICROS: u64 = 30_000;
const ONE_MIB: u64 = 1 << 20;

fn test_cx() -> Cx {
    Cx::for_testing()
}

fn frame_is_ack_eliciting(frame: &QuicFrame) -> bool {
    !matches!(
        frame,
        QuicFrame::Padding { .. } | QuicFrame::Ack { .. } | QuicFrame::ConnectionClose { .. }
    )
}

/// Deterministic payload pattern so both sides can verify independently.
fn pattern_byte(offset: u64) -> u8 {
    (offset.wrapping_mul(0x9e37_79b9_7f4a_7c15) >> 56) as u8
}

fn pattern_chunk(offset: u64, len: usize) -> Bytes {
    let mut out = Vec::with_capacity(len);
    for i in 0..len as u64 {
        out.push(pattern_byte(offset + i));
    }
    Bytes::from(out)
}

// ---------------------------------------------------------------------------
// Virtual link
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct WirePacket {
    packet_number: u64,
    payload: Vec<u8>,
    deliver_at_micros: u64,
}

/// One direction of a constant-delay FIFO link with optional deterministic
/// drops (`drop_every = Some(n)` loses send ordinals `n`, `2n`, ...).
#[derive(Debug)]
struct Link {
    queue: VecDeque<WirePacket>,
    one_way_delay_micros: u64,
    drop_every: Option<NonZeroU64>,
    /// Lose every non-ack-eliciting (ACK-only) packet. From the sender's
    /// recovery state this is indistinguishable from a receiver that leaves
    /// non-ack-eliciting packets out of its ACK ranges, which RFC 9000
    /// §13.2.3 permits and which this stack did before GH#71.
    drop_non_ack_eliciting: bool,
    sent: u64,
    dropped: u64,
    dropped_ack_eliciting: u64,
    dropped_non_ack_eliciting: u64,
}

impl Link {
    fn new(
        one_way_delay_micros: u64,
        drop_every: Option<NonZeroU64>,
        drop_non_ack_eliciting: bool,
    ) -> Self {
        Self {
            queue: VecDeque::new(),
            one_way_delay_micros,
            drop_every,
            drop_non_ack_eliciting,
            sent: 0,
            dropped: 0,
            dropped_ack_eliciting: 0,
            dropped_non_ack_eliciting: 0,
        }
    }

    fn send(&mut self, packet_number: u64, payload: Vec<u8>, ack_eliciting: bool, now: u64) {
        self.sent += 1;
        if !ack_eliciting && self.drop_non_ack_eliciting {
            self.dropped += 1;
            self.dropped_non_ack_eliciting += 1;
            return;
        }
        if self.drop_every.is_some_and(|n| self.sent % n == 0) {
            self.dropped += 1;
            if ack_eliciting {
                self.dropped_ack_eliciting += 1;
            }
            return;
        }
        self.queue.push_back(WirePacket {
            packet_number,
            payload,
            deliver_at_micros: now + self.one_way_delay_micros,
        });
    }

    fn next_arrival(&self) -> Option<u64> {
        self.queue.front().map(|packet| packet.deliver_at_micros)
    }

    /// Everything that has arrived by `now`, bounded like one socket batch.
    fn take_due(&mut self, now: u64, max_packets: usize) -> Vec<WirePacket> {
        let mut batch = Vec::new();
        while batch.len() < max_packets {
            match self.queue.front() {
                Some(packet) if packet.deliver_at_micros <= now => {
                    batch.push(self.queue.pop_front().expect("front exists"));
                }
                _ => break,
            }
        }
        batch
    }
}

// ---------------------------------------------------------------------------
// Peer: one connection driven with the reporter's `drive_io_once` cadence
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Clone, Copy)]
struct PeerCounters {
    packets_sent: u64,
    ack_only_packets_sent: u64,
    packets_received: u64,
    packets_dropped_backpressure: u64,
    receive_batches: u64,
    receive_timeouts: u64,
    loss_timer_fires: u64,
    flushes: u64,
}

impl PeerCounters {
    fn summary(&self) -> String {
        format!(
            "sent={} ack_only_sent={} received={} dropped_backpressure={} batches={} \
             timeouts={} loss_timer_fires={} flushes={}",
            self.packets_sent,
            self.ack_only_packets_sent,
            self.packets_received,
            self.packets_dropped_backpressure,
            self.receive_batches,
            self.receive_timeouts,
            self.loss_timer_fires,
            self.flushes,
        )
    }
}

struct Peer {
    name: &'static str,
    conn: NativeQuicConnection,
    counters: PeerCounters,
}

impl Peer {
    fn new(name: &'static str, role: StreamRole) -> Self {
        let config = NativeQuicConnectionConfig {
            role,
            ..NativeQuicConnectionConfig::default()
        };
        Self {
            name,
            conn: NativeQuicConnection::new(config),
            counters: PeerCounters::default(),
        }
    }

    /// `receive_wait_duration`: the requested wait, shortened to the PTO
    /// deadline when ack-eliciting data is in flight.
    fn bounded_wait_micros(&self, cx: &Cx, now: u64) -> u64 {
        match self
            .conn
            .pto_deadline_micros(cx, now)
            .expect("pto deadline query")
        {
            Some(deadline) => RECEIVE_WAIT_MICROS.min(deadline.saturating_sub(now)),
            None => RECEIVE_WAIT_MICROS,
        }
    }

    /// The virtual instant this peer's `drive_io_once` returns from its
    /// receive wait: the first inbound arrival inside the bounded wait, else
    /// the wait's timeout.
    fn wake_time(&self, cx: &Cx, inbound: &Link, now: u64) -> u64 {
        let timeout_at = now + self.bounded_wait_micros(cx, now);
        match inbound.next_arrival() {
            Some(arrival) if arrival <= timeout_at => arrival.max(now),
            _ => timeout_at,
        }
    }

    /// `service_due_loss_timer`.
    fn service_due_loss_timer(&mut self, cx: &Cx, now: u64) {
        let Some(deadline) = self
            .conn
            .pto_deadline_micros(cx, now)
            .expect("pto deadline query")
        else {
            return;
        };
        if deadline <= now {
            self.counters.loss_timer_fires += 1;
            self.conn
                .on_loss_timeout_expired(cx, PacketNumberSpace::ApplicationData, now)
                .expect("loss timeout");
        }
    }

    /// `NativeQuicUdpConnection::flush`: up to `MAX_PACKETS_PER_FLUSH`
    /// packets, each admitted by `generate_congestion_admitted_1rtt_frames`
    /// (full frames when cwnd admits a max-size packet, ACK-only otherwise),
    /// all stamped with the flush's single `now`.
    fn flush(&mut self, cx: &Cx, outbound: &mut Link, now: u64) -> usize {
        self.counters.flushes += 1;
        let mut sent = 0usize;
        for _ in 0..MAX_PACKETS_PER_FLUSH {
            let frames = if self
                .conn
                .transport()
                .can_send(PROTECTED_1RTT_MAX_PACKET_BYTES as u64)
            {
                self.conn
                    .generate_frames(cx, PacketNumberSpace::ApplicationData, MAX_FRAME_BYTES)
                    .expect("generate frames")
            } else {
                self.conn
                    .generate_ack_only_frames_for_testing(cx, MAX_FRAME_BYTES)
                    .expect("generate ack-only frames")
            };
            if frames.is_empty() {
                break;
            }
            let mut payload = BytesMut::new();
            NativeQuicConnection::encode_frames(&frames, &mut payload).expect("encode frames");
            let ack_eliciting = frames.iter().any(frame_is_ack_eliciting);
            let packet_bytes = (payload.len() + PACKET_OVERHEAD_BYTES) as u64;
            let packet_number = self
                .conn
                .on_packet_sent_with_frames(
                    cx,
                    PacketNumberSpace::ApplicationData,
                    packet_bytes,
                    ack_eliciting,
                    ack_eliciting,
                    now,
                    &frames,
                )
                .expect("record sent packet");
            self.counters.packets_sent += 1;
            if !ack_eliciting {
                self.counters.ack_only_packets_sent += 1;
            }
            outbound.send(packet_number, payload.to_vec(), ack_eliciting, now);
            sent += 1;
        }
        sent
    }

    /// The body of `drive_io_once` after its receive wait returns at `now`:
    /// deliver one bounded batch, service the loss timer, flush.
    fn on_wake(&mut self, cx: &Cx, inbound: &mut Link, outbound: &mut Link, now: u64) {
        let batch = inbound.take_due(now, RECEIVE_BATCH_SIZE);
        if batch.is_empty() {
            self.counters.receive_timeouts += 1;
        } else {
            self.counters.receive_batches += 1;
        }
        for packet in batch {
            match self.conn.process_packet_payload(
                cx,
                PacketNumberSpace::ApplicationData,
                packet.packet_number,
                &packet.payload,
                now,
            ) {
                Ok(()) => self.counters.packets_received += 1,
                Err(error) if error.is_stream_reassembly_backpressure() => {
                    self.counters.packets_dropped_backpressure += 1;
                }
                Err(error) => panic!(
                    "{} failed to process packet {}: {error}",
                    self.name, packet.packet_number
                ),
            }
        }
        self.service_due_loss_timer(cx, now);
        self.flush(cx, outbound, now);
    }
}

/// Drive both peers through the key-availability transitions to
/// `Established` (the lab substitute for the wire handshake, as in
/// `tests/quic_h3_e2e_loss.rs`).
fn establish(cx: &Cx, client: &mut Peer, server: &mut Peer) {
    client
        .conn
        .begin_handshake(cx)
        .expect("client begin_handshake");
    server
        .conn
        .begin_handshake(cx)
        .expect("server begin_handshake");
    client
        .conn
        .on_handshake_keys_available(cx)
        .expect("client hs keys");
    server
        .conn
        .on_handshake_keys_available(cx)
        .expect("server hs keys");
    client
        .conn
        .on_1rtt_keys_available(cx)
        .expect("client 1rtt keys");
    server
        .conn
        .on_1rtt_keys_available(cx)
        .expect("server 1rtt keys");
    client.conn.record_verified_server_identity();
    client
        .conn
        .on_handshake_confirmed(cx)
        .expect("client confirmed");
    server
        .conn
        .on_handshake_confirmed(cx)
        .expect("server confirmed");
    assert_eq!(client.conn.state(), QuicConnectionState::Established);
    assert_eq!(server.conn.state(), QuicConnectionState::Established);
    assert!(client.conn.can_send_1rtt());
    assert!(server.conn.can_send_1rtt());
}

// ---------------------------------------------------------------------------
// The reporter's echo application on both ends
// ---------------------------------------------------------------------------

struct ClientApp {
    stream: StreamId,
    total: u64,
    sent: u64,
    echoed: u64,
    echo_intact: bool,
}

impl ClientApp {
    /// `client_echo_against_remote`: keep the send queue primed without
    /// overrunning flow control, then consume the echo and slide the windows.
    fn step(&mut self, cx: &Cx, client: &mut Peer) {
        loop {
            let bytes = client
                .conn
                .read_stream_bytes(cx, self.stream, CHUNK)
                .expect("client echo read");
            if bytes.is_empty() {
                break;
            }
            for (i, byte) in bytes.iter().enumerate() {
                if *byte != pattern_byte(self.echoed + i as u64) {
                    self.echo_intact = false;
                }
            }
            self.echoed += bytes.len() as u64;
            client
                .conn
                .configure_stream_recv_window(cx, self.stream, STREAM_RECV_WINDOW)
                .expect("client window");
            client
                .conn
                .advertise_connection_recv_limit(cx, self.echoed + CONNECTION_RECV_SLACK)
                .expect("client MAX_DATA");
        }
        while self.sent < self.total
            && client.conn.pending_stream_data_bytes_for(self.stream) < MAX_QUEUED
        {
            let len = CHUNK.min((self.total - self.sent) as usize);
            let chunk = pattern_chunk(self.sent, len);
            let fin = self.sent + len as u64 == self.total;
            match client.conn.write_stream_bytes(cx, self.stream, chunk, fin) {
                Ok(()) => self.sent += len as u64,
                // Flow-control window exhausted: drive I/O and retry later.
                Err(_) => break,
            }
        }
    }
}

#[derive(Default)]
struct ServerApp {
    stream: Option<StreamId>,
    seen: u64,
    eof_seen: bool,
    fin_echoed: bool,
    pending: VecDeque<Bytes>,
}

impl ServerApp {
    /// `serve_remote`: discover the stream, read everything readable, slide
    /// the windows, echo whatever the send window admits.
    fn step(&mut self, cx: &Cx, server: &mut Peer) {
        if self.stream.is_none() {
            self.stream = server
                .conn
                .next_readable_stream(cx)
                .expect("server next_readable_stream")
                .map(|readiness| readiness.stream_id);
        }
        let Some(id) = self.stream else {
            return;
        };
        let mut read_any = false;
        loop {
            let bytes = server
                .conn
                .read_stream_bytes(cx, id, CHUNK)
                .expect("server read");
            if bytes.is_empty() {
                break;
            }
            read_any = true;
            self.seen += bytes.len() as u64;
            self.pending.push_back(bytes);
        }
        if read_any {
            server
                .conn
                .configure_stream_recv_window(cx, id, STREAM_RECV_WINDOW)
                .expect("server window");
            server
                .conn
                .advertise_connection_recv_limit(cx, self.seen + CONNECTION_RECV_SLACK)
                .expect("server MAX_DATA");
        }
        if !self.eof_seen {
            self.eof_seen = server.conn.is_stream_read_eof(id).unwrap_or(false);
        }
        while let Some(front) = self.pending.front() {
            let fin = self.eof_seen && self.pending.len() == 1;
            match server.conn.write_stream_bytes(cx, id, front.clone(), fin) {
                Ok(()) => {
                    self.fin_echoed = fin;
                    self.pending.pop_front();
                }
                Err(_) => break,
            }
        }
        if self.eof_seen && self.pending.is_empty() && !self.fin_echoed {
            self.fin_echoed = server
                .conn
                .write_stream_bytes(cx, id, Bytes::new(), true)
                .is_ok();
        }
    }
}

// ---------------------------------------------------------------------------
// Scenario
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct Scenario {
    one_way_delay_micros: u64,
    transfer_bytes: u64,
    /// Deterministic drop policy on the client->server direction.
    client_to_server_drop_every: Option<NonZeroU64>,
    /// Lose every ACK-only packet the client sends.
    client_to_server_drop_ack_only: bool,
}

#[derive(Debug)]
struct Outcome {
    elapsed_micros: u64,
    echo_intact: bool,
    client_acked: u64,
    client_lost: u64,
    client_pto: u32,
    client_cwnd: u64,
    client_srtt_micros: Option<u64>,
    client_min_rtt_micros: Option<u64>,
    server_acked: u64,
    server_lost: u64,
    server_cwnd: u64,
    client: PeerCounters,
    server: PeerCounters,
    c2s_dropped: u64,
    c2s_dropped_ack_eliciting: u64,
    c2s_dropped_non_ack_eliciting: u64,
}

impl Outcome {
    fn client_loss_ratio(&self) -> f64 {
        if self.client_acked == 0 {
            return 0.0;
        }
        self.client_lost as f64 / self.client_acked as f64
    }
}

/// Discrete-event schedule: whichever peer's receive wait returns first is
/// run next (client first on ties); running a peer never consumes virtual
/// time, only its wait does.
fn run(scenario: Scenario) -> Outcome {
    let cx = test_cx();
    let mut client = Peer::new("client", StreamRole::Client);
    let mut server = Peer::new("server", StreamRole::Server);
    establish(&cx, &mut client, &mut server);

    let mut client_to_server = Link::new(
        scenario.one_way_delay_micros,
        scenario.client_to_server_drop_every,
        scenario.client_to_server_drop_ack_only,
    );
    let mut server_to_client = Link::new(scenario.one_way_delay_micros, None, false);

    let stream = client
        .conn
        .open_local_bidi(&cx)
        .expect("open client stream");
    let mut client_app = ClientApp {
        stream,
        total: scenario.transfer_bytes,
        sent: 0,
        echoed: 0,
        echo_intact: true,
    };
    let mut server_app = ServerApp::default();

    let started = 1_000_000u64;
    let mut now = started;
    // The reporter primes the send queue before the first drive.
    client_app.step(&cx, &mut client);
    let mut client_wake = client.wake_time(&cx, &server_to_client, now);
    let mut server_wake = server.wake_time(&cx, &client_to_server, now);
    let mut events = 0u64;

    while client_app.echoed < scenario.transfer_bytes {
        events += 1;
        assert!(
            events <= 4_000_000,
            "schedule did not converge within 4M events at {} ms virtual (echoed={})",
            (now - started) / 1_000,
            client_app.echoed
        );
        assert!(
            now - started <= VIRTUAL_DEADLINE_MICROS,
            "echo transfer timed out after {} ms virtual: sent={} server_seen={} echoed={} \
             client_acked={} client_lost={} client_cwnd={}",
            (now - started) / 1_000,
            client_app.sent,
            server_app.seen,
            client_app.echoed,
            client.conn.transport().packets_acked_total(),
            client.conn.transport().packets_lost_total(),
            client.conn.transport().congestion_window_bytes(),
        );
        if client_wake <= server_wake {
            now = client_wake;
            client.on_wake(&cx, &mut server_to_client, &mut client_to_server, now);
            client_app.step(&cx, &mut client);
            client_wake = client.wake_time(&cx, &server_to_client, now);
        } else {
            now = server_wake;
            server.on_wake(&cx, &mut client_to_server, &mut server_to_client, now);
            server_app.step(&cx, &mut server);
            server_wake = server.wake_time(&cx, &client_to_server, now);
        }
    }

    let client_transport = client.conn.transport();
    let server_transport = server.conn.transport();
    Outcome {
        elapsed_micros: now - started,
        echo_intact: client_app.echo_intact && client_app.echoed == scenario.transfer_bytes,
        client_acked: client_transport.packets_acked_total(),
        client_lost: client_transport.packets_lost_total(),
        client_pto: client_transport.pto_count(),
        client_cwnd: client_transport.congestion_window_bytes(),
        client_srtt_micros: client_transport.rtt().smoothed_rtt_micros(),
        client_min_rtt_micros: client_transport.rtt().min_rtt_micros(),
        server_acked: server_transport.packets_acked_total(),
        server_lost: server_transport.packets_lost_total(),
        server_cwnd: server_transport.congestion_window_bytes(),
        client: client.counters,
        server: server.counters,
        c2s_dropped: client_to_server.dropped,
        c2s_dropped_ack_eliciting: client_to_server.dropped_ack_eliciting,
        c2s_dropped_non_ack_eliciting: client_to_server.dropped_non_ack_eliciting,
    }
}

fn assert_lossless_path_declares_no_loss(label: &str, scenario: Scenario) -> Outcome {
    let outcome = run(scenario);
    println!(
        "{label}: rtt={}ms elapsed={}ms client_acked={} client_lost={} (ratio {:.3}) \
         client_pto={} client_cwnd={} srtt={:?}us min_rtt={:?}us server_acked={} \
         server_lost={} server_cwnd={} client[{}] server[{}]",
        scenario.one_way_delay_micros * 2 / 1_000,
        outcome.elapsed_micros / 1_000,
        outcome.client_acked,
        outcome.client_lost,
        outcome.client_loss_ratio(),
        outcome.client_pto,
        outcome.client_cwnd,
        outcome.client_srtt_micros,
        outcome.client_min_rtt_micros,
        outcome.server_acked,
        outcome.server_lost,
        outcome.server_cwnd,
        outcome.client.summary(),
        outcome.server.summary(),
    );
    assert!(outcome.echo_intact, "{label}: echo must match the pattern");
    assert!(
        outcome.client.ack_only_packets_sent > 0,
        "{label}: the cwnd-limited client must have emitted ACK-only packets, \
         otherwise this schedule does not exercise the reported cadence"
    );
    assert_eq!(
        outcome.client_lost,
        0,
        "{label}: a lossless delayed path must not declare any client packet lost \
         (acked={} lost={} ratio={:.3} cwnd={})",
        outcome.client_acked,
        outcome.client_lost,
        outcome.client_loss_ratio(),
        outcome.client_cwnd
    );
    assert_eq!(
        outcome.server_lost, 0,
        "{label}: a lossless delayed path must not declare any server packet lost \
         (acked={} lost={} cwnd={})",
        outcome.server_acked, outcome.server_lost, outcome.server_cwnd
    );
    assert_eq!(outcome.client_pto, 0, "{label}: no probe timeout may fire");
    assert!(
        outcome.client_cwnd >= 12_000,
        "{label}: cwnd must never shrink below the initial window without loss: {}",
        outcome.client_cwnd
    );
    let min_rtt = outcome
        .client_min_rtt_micros
        .expect("client observed an RTT sample");
    assert_eq!(
        min_rtt,
        scenario.one_way_delay_micros * 2,
        "{label}: min RTT must equal the path RTT"
    );
    outcome
}

/// The reported defect at the reported RTT: a clean ~29 ms path, 1 MiB echo,
/// the reporter's 5 ms drive cadence. Every packet the client declares lost
/// here is spurious because the link drops nothing.
#[test]
fn one_mib_echo_over_clean_29ms_rtt_path_declares_no_loss() {
    let outcome = assert_lossless_path_declares_no_loss(
        "clean-29ms-rtt",
        Scenario {
            one_way_delay_micros: REPORTED_ONE_WAY_DELAY_MICROS,
            transfer_bytes: ONE_MIB,
            client_to_server_drop_every: None,
            client_to_server_drop_ack_only: false,
        },
    );
    // Throughput is bounded by the path, not by the detector: the reporter
    // measured 14.3 s for this transfer.
    assert!(
        outcome.elapsed_micros < 3_000_000,
        "1 MiB over a clean 29 ms RTT path took {} ms virtual",
        outcome.elapsed_micros / 1_000
    );
}

/// Same defect on a longer path (60 ms RTT): the mechanism does not depend on
/// the exact RTT, only on the sender being cwnd-limited.
#[test]
fn one_mib_echo_over_clean_60ms_rtt_path_declares_no_loss() {
    assert_lossless_path_declares_no_loss(
        "clean-60ms-rtt",
        Scenario {
            one_way_delay_micros: LONG_ONE_WAY_DELAY_MICROS,
            transfer_bytes: ONE_MIB,
            client_to_server_drop_every: None,
            client_to_server_drop_ack_only: false,
        },
    );
}

/// ACK-only packets are neither congestion controlled nor retransmitted
/// (RFC 9002 §2, §6.1): losing every one of them on the wire — equivalently,
/// a peer that omits non-ack-eliciting packets from its ACK ranges, as this
/// stack did before GH#71 — must not register as loss or shrink the window.
/// This pins the sender-side rule independently of the receiver-side range
/// tracking fix.
#[test]
fn ack_only_packets_lost_on_the_wire_are_never_declared_lost() {
    let scenario = Scenario {
        one_way_delay_micros: REPORTED_ONE_WAY_DELAY_MICROS,
        transfer_bytes: ONE_MIB,
        client_to_server_drop_every: None,
        client_to_server_drop_ack_only: true,
    };
    let outcome = run(scenario);
    println!(
        "ack-only-dropped: elapsed={}ms client_acked={} client_lost={} \
         c2s_dropped_non_ack_eliciting={} client_pto={} client_cwnd={} server_acked={} \
         server_lost={} client[{}] server[{}]",
        outcome.elapsed_micros / 1_000,
        outcome.client_acked,
        outcome.client_lost,
        outcome.c2s_dropped_non_ack_eliciting,
        outcome.client_pto,
        outcome.client_cwnd,
        outcome.server_acked,
        outcome.server_lost,
        outcome.client.summary(),
        outcome.server.summary(),
    );
    assert!(outcome.echo_intact, "echo must match the pattern");
    assert!(
        outcome.c2s_dropped_non_ack_eliciting > 0,
        "the schedule must have lost at least one ACK-only packet"
    );
    assert_eq!(
        outcome.client_lost, 0,
        "lost ACK-only packets must never be declared lost (dropped {})",
        outcome.c2s_dropped_non_ack_eliciting
    );
    assert_eq!(outcome.client_pto, 0, "no client probe timeout may fire");
    assert!(
        outcome.client_cwnd >= 12_000,
        "cwnd must not shrink below the initial window: {}",
        outcome.client_cwnd
    );
    // The server side is deliberately unasserted here: once the client runs
    // out of data to piggyback ACKs on, every acknowledgement it owes rides in
    // an ACK-only packet this schedule drops, so the server is ACK-starved at
    // the tail and may legitimately fire its probe timeout. That is the
    // scenario's own consequence, not the GH#71 detector defect.
}

/// Planted control for the harness and the fix: with genuine deterministic
/// loss on the client->server direction the detector must still declare at
/// least every dropped ack-eliciting packet lost, and the transfer must still
/// complete intact through retransmission. A fix that silenced loss detection
/// wholesale would fail here.
#[test]
fn injected_loss_on_delayed_path_is_still_detected_and_recovered() {
    let scenario = Scenario {
        one_way_delay_micros: REPORTED_ONE_WAY_DELAY_MICROS,
        transfer_bytes: 256 * 1_024,
        client_to_server_drop_every: NonZeroU64::new(50),
        client_to_server_drop_ack_only: false,
    };
    let outcome = run(scenario);
    println!(
        "injected-loss: elapsed={}ms client_acked={} client_lost={} c2s_dropped={} \
         (ack-eliciting {}) client_pto={} client_cwnd={} client[{}]",
        outcome.elapsed_micros / 1_000,
        outcome.client_acked,
        outcome.client_lost,
        outcome.c2s_dropped,
        outcome.c2s_dropped_ack_eliciting,
        outcome.client_pto,
        outcome.client_cwnd,
        outcome.client.summary(),
    );
    assert!(outcome.echo_intact, "echo must survive injected loss");
    assert!(
        outcome.c2s_dropped_ack_eliciting > 0,
        "the control must actually drop ack-eliciting packets"
    );
    assert!(
        outcome.client_lost >= outcome.c2s_dropped_ack_eliciting,
        "every dropped ack-eliciting packet must be declared lost: lost={} dropped={}",
        outcome.client_lost,
        outcome.c2s_dropped_ack_eliciting
    );
    assert_eq!(
        outcome.server_lost, 0,
        "the lossless server->client direction must not declare loss"
    );
}
