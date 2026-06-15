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
//! - an over-sized datagram is rejected, and the bounded outbound queue applies
//!   backpressure (the send side never silently grows unbounded).
//!
//! Scope: the queue→frame generation half of A1 on committed `HEAD` plus this
//! slice. The packet protection (A4) and UDP endpoint hand-off remain open.

#![allow(missing_docs)]

use asupersync::bytes::Bytes;
use asupersync::cx::Cx;
use asupersync::net::atp::protocol::quic_frames::QuicFrame;
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
        conn.send_datagram(p.clone()).expect("enqueue datagram");
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

    conn.send_datagram(Bytes::from_static(b"a")).expect("enqueue");
    conn.send_datagram(Bytes::from_static(b"b")).expect("enqueue");

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
        conn.send_datagram(p.clone()).expect("enqueue");
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
fn oversized_datagram_rejected_and_full_queue_backpressures() {
    let mut conn = fresh_connection();

    // A payload whose encoded frame exceeds the max DATAGRAM frame size is
    // rejected, and nothing is enqueued.
    let err = conn
        .send_datagram(Bytes::from(vec![0u8; 4096]))
        .expect_err("oversized datagram must be rejected");
    assert!(matches!(err, NativeQuicConnectionError::InvalidState(_)));
    assert_eq!(conn.pending_outbound_datagram_count(), 0);

    // The bounded outbound queue applies backpressure rather than growing
    // unbounded: small enqueues succeed up to the cap, then fail closed. We do
    // not hardcode the cap — only that backpressure engages and never drops.
    let mut accepted = 0usize;
    let mut backpressured = false;
    for i in 0u32..10_000 {
        match conn.send_datagram(Bytes::from(i.to_be_bytes().to_vec())) {
            Ok(()) => accepted += 1,
            Err(NativeQuicConnectionError::InvalidState(_)) => {
                backpressured = true;
                break;
            }
            Err(other) => panic!("unexpected send error: {other:?}"),
        }
    }
    assert!(backpressured, "outbound queue must apply backpressure when full");
    assert!(accepted > 0);
    // Every accepted datagram is still queued — backpressure never drops.
    assert_eq!(conn.pending_outbound_datagram_count(), accepted);
    assert_eq!(conn.datagrams_sent(), 0);
}
