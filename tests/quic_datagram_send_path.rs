//! QUIC DATAGRAM frame SEND path conformance (b0k8qo.1.1 / arq-quic-epic).
//!
//! Acceptance for A1's frame-generation half: an application enqueues unreliable
//! datagrams via `send_datagram`, and `generate_frames` emits them as RFC 9221
//! `QuicFrame::Datagram` frames in 1-RTT packets. These tests drive the real
//! `NativeQuicConnection` (no mocks) on the shared codec landed in d0e45d02a and
//! assert:
//!
//! - queued datagrams are emitted as DATAGRAM frames in FIFO order with exact
//!   payloads, and `datagrams_sent` counts what actually reaches the wire;
//! - DATAGRAM frames are emitted only in the ApplicationData (1-RTT) space, never
//!   Initial/Handshake;
//! - a small per-packet byte budget emits a prefix and leaves the remainder
//!   queued (no datagrams dropped on the floor), draining FIFO on the next call;
//! - an over-sized datagram is rejected with a typed error, and the bounded
//!   outbound queue drops oldest with accounting rather than growing unbounded.
//!
//! Scope: the queue→frame generation half of A1 on committed `HEAD` plus this
//! slice. The packet protection (A4) and UDP endpoint hand-off remain open.

#![allow(missing_docs)]

use asupersync::bytes::Bytes;
use asupersync::bytes::BytesMut;
use asupersync::cx::Cx;
use asupersync::net::atp::protocol::quic_frames::QuicFrame;
use asupersync::net::quic_core::TransportParameters;
use asupersync::net::quic_native::{
    NativeQuicConnection, NativeQuicConnectionConfig, NativeQuicConnectionError, PacketNumberSpace,
};

fn fresh_connection() -> NativeQuicConnection {
    NativeQuicConnection::new(NativeQuicConnectionConfig::default())
}

/// Extract the payloads of a run of frames, asserting each is a DATAGRAM.
fn datagram_payloads(frames: &[QuicFrame]) -> Vec<Bytes> {
    frames
        .iter()
        .map(|f| match f {
            QuicFrame::Datagram { data } => data.clone(),
            other => panic!("expected a DATAGRAM frame, got {other:?}"),
        })
        .collect()
}

#[test]
fn queued_datagrams_emit_as_frames_in_fifo_order() {
    let cx = Cx::for_testing();
    let mut conn = fresh_connection();

    let payloads = [
        Bytes::from_static(b"symbol-0"),
        Bytes::from_static(b"symbol-1"),
        Bytes::from_static(b"symbol-2"),
    ];
    for p in &payloads {
        conn.send_datagram(&cx, p.clone())
            .expect("enqueue datagram");
    }
    assert_eq!(conn.pending_outbound_datagram_count(), 3);
    assert_eq!(conn.datagrams_sent(), 0);

    let frames = conn
        .generate_frames(&cx, PacketNumberSpace::ApplicationData, 100_000)
        .expect("generate frames in 1-RTT");

    assert_eq!(datagram_payloads(&frames), payloads);
    assert_eq!(conn.datagrams_sent(), 3);
    assert_eq!(conn.pending_outbound_datagram_count(), 0);

    // Drained: a follow-up generation yields no further datagram frames.
    let again = conn
        .generate_frames(&cx, PacketNumberSpace::ApplicationData, 100_000)
        .expect("generate again");
    assert!(again.is_empty());
    assert_eq!(conn.datagrams_sent(), 3);
}

#[test]
fn datagrams_only_emitted_in_application_data_space() {
    let cx = Cx::for_testing();
    let mut conn = fresh_connection();

    conn.send_datagram(&cx, Bytes::from_static(b"a"))
        .expect("enqueue");
    conn.send_datagram(&cx, Bytes::from_static(b"b"))
        .expect("enqueue");

    // Initial and Handshake spaces must never carry DATAGRAM frames.
    let initial = conn
        .generate_frames(&cx, PacketNumberSpace::Initial, 100_000)
        .expect("initial");
    assert!(initial.is_empty());
    let handshake = conn
        .generate_frames(&cx, PacketNumberSpace::Handshake, 100_000)
        .expect("handshake");
    assert!(handshake.is_empty());

    assert_eq!(conn.pending_outbound_datagram_count(), 2);
    assert_eq!(conn.datagrams_sent(), 0);

    // 1-RTT space drains them.
    let app = conn
        .generate_frames(&cx, PacketNumberSpace::ApplicationData, 100_000)
        .expect("application data");
    assert_eq!(datagram_payloads(&app).len(), 2);
    assert_eq!(conn.datagrams_sent(), 2);
}

#[test]
fn small_budget_emits_prefix_and_leaves_remainder_queued() {
    let cx = Cx::for_testing();
    let mut conn = fresh_connection();

    // Four ~100-byte datagrams; each encoded frame is ~103 bytes.
    let payloads: Vec<Bytes> = (0u8..4).map(|i| Bytes::from(vec![i; 100])).collect();
    for p in &payloads {
        conn.send_datagram(&cx, p.clone()).expect("enqueue");
    }

    // A 250-byte budget fits two frames (~206), not three (~309).
    let first = conn
        .generate_frames(&cx, PacketNumberSpace::ApplicationData, 250)
        .expect("first packet");
    let first_payloads = datagram_payloads(&first);
    assert_eq!(first_payloads.len(), 2);
    assert_eq!(first_payloads, payloads[0..2]);
    // No datagram was dropped: emitted + still-queued == original.
    assert_eq!(conn.pending_outbound_datagram_count(), 2);
    assert_eq!(conn.datagrams_sent(), 2);

    // The next packet drains the remainder, preserving FIFO order overall.
    let second = conn
        .generate_frames(&cx, PacketNumberSpace::ApplicationData, 100_000)
        .expect("second packet");
    assert_eq!(datagram_payloads(&second), payloads[2..4]);
    assert_eq!(conn.pending_outbound_datagram_count(), 0);
    assert_eq!(conn.datagrams_sent(), 4);
}

#[test]
fn oversized_datagram_rejected_and_full_queue_drops_oldest() {
    let cx = Cx::for_testing();
    let mut conn = fresh_connection();

    // A payload whose encoded frame exceeds the max DATAGRAM frame size is
    // rejected, and nothing is enqueued.
    let err = conn
        .send_datagram(&cx, Bytes::from(vec![0u8; 4096]))
        .expect_err("oversized datagram must be rejected");
    assert!(matches!(
        err,
        NativeQuicConnectionError::DatagramTooLarge {
            payload_len: 4096,
            max_frame_size: 1200,
            ..
        }
    ));
    assert_eq!(conn.pending_outbound_datagram_count(), 0);

    // The bounded outbound queue is loss-tolerant: once full, each new symbol
    // evicts the oldest queued symbol and records the drop.
    for i in 0u32..300 {
        conn.send_datagram(&cx, Bytes::from(i.to_be_bytes().to_vec()))
            .expect("small datagram enqueue must stay infallible");
    }
    assert_eq!(conn.pending_outbound_datagram_count(), 256);
    assert_eq!(conn.datagrams_dropped_on_send(), 44);
    assert_eq!(conn.datagrams_sent(), 0);

    let frames = conn
        .generate_frames(&cx, PacketNumberSpace::ApplicationData, 100_000)
        .expect("drain queued datagrams");
    let payloads = datagram_payloads(&frames);
    assert_eq!(payloads.len(), 256);
    assert_eq!(payloads[0], Bytes::from(44u32.to_be_bytes().to_vec()));
    assert_eq!(payloads[255], Bytes::from(299u32.to_be_bytes().to_vec()));
}

#[test]
fn negotiated_max_datagram_frame_size_rejects_payload_above_peer_cap() {
    let cx = Cx::for_testing();
    let mut conn = NativeQuicConnection::new(NativeQuicConnectionConfig::default());
    let peer_params = TransportParameters {
        max_datagram_frame_size: Some(10),
        ..TransportParameters::default()
    };
    conn.apply_peer_transport_parameters(&cx, &peer_params)
        .expect("apply peer DATAGRAM transport parameter");

    conn.send_datagram(&cx, Bytes::from_static(b"12345678"))
        .expect("encoded frame fits negotiated cap");
    let err = conn
        .send_datagram(&cx, Bytes::from_static(b"123456789"))
        .expect_err("encoded frame exceeds negotiated cap");

    assert!(matches!(
        err,
        NativeQuicConnectionError::DatagramTooLarge {
            payload_len: 9,
            max_frame_size: 10,
            ..
        }
    ));
    assert_eq!(conn.pending_outbound_datagram_count(), 1);
}

#[test]
fn absent_peer_max_datagram_frame_size_disables_datagram_send() {
    let cx = Cx::for_testing();
    let mut conn = NativeQuicConnection::new(NativeQuicConnectionConfig::default());
    conn.apply_peer_transport_parameters(&cx, &TransportParameters::default())
        .expect("apply peer params without DATAGRAM support");

    let err = conn
        .send_datagram(&cx, Bytes::from_static(b"x"))
        .expect_err("peer did not negotiate DATAGRAM support");
    assert!(matches!(
        err,
        NativeQuicConnectionError::DatagramTooLarge {
            payload_len: 1,
            max_frame_size: 0,
            ..
        }
    ));
    assert_eq!(conn.pending_outbound_datagram_count(), 0);
}

#[test]
fn cancelled_cx_rejects_datagram_without_enqueueing() {
    let cx = Cx::for_testing();
    cx.set_cancel_requested(true);
    let mut conn = fresh_connection();

    let err = conn
        .send_datagram(&cx, Bytes::from_static(b"cancelled"))
        .expect_err("cancelled cx must reject enqueue");

    assert_eq!(err, NativeQuicConnectionError::Cancelled);
    assert_eq!(conn.pending_outbound_datagram_count(), 0);
    assert_eq!(conn.datagrams_dropped_on_send(), 0);
}

#[test]
fn datagram_coalesces_with_pending_ack_frame() {
    let cx = Cx::for_testing();
    let mut conn = fresh_connection();
    let mut inbound = BytesMut::new();
    QuicFrame::Ping.encode(&mut inbound).expect("encode ping");

    conn.process_packet_payload(&cx, PacketNumberSpace::ApplicationData, 41, &inbound, 0)
        .expect("process ack-eliciting ping");
    conn.send_datagram(&cx, Bytes::from_static(b"symbol"))
        .expect("enqueue datagram");

    let frames = conn
        .generate_frames(&cx, PacketNumberSpace::ApplicationData, 100_000)
        .expect("generate coalesced frames");

    assert!(matches!(frames.first(), Some(QuicFrame::Ack { .. })));
    assert!(
        matches!(frames.get(1), Some(QuicFrame::Datagram { data }) if data.as_ref() == b"symbol")
    );
}
