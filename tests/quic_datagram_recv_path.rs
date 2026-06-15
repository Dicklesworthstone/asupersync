//! QUIC DATAGRAM frame RECEIVE path conformance (b0k8qo.1.2 / arq-quic-epic).
//!
//! Acceptance for A2: feeding a packet that contains a DATAGRAM frame (RFC 9221)
//! must surface the exact payload to the application via the receive API. These
//! tests drive the real `NativeQuicConnection::process_packet_payload` decode
//! path (no mocks) and assert the new `recv_datagram`/`pending_datagram_count`/
//! `datagrams_received` surface:
//!
//! - a multi-frame packet (PING + DATAGRAM) surfaces the exact datagram payload
//!   once and the receive counter reflects the wire;
//! - multiple datagrams in one packet are delivered in arrival (FIFO) order;
//! - an empty datagram payload still round-trips through the recv API;
//! - the bounded inbound queue is fountain-tolerant — it drops the *oldest*
//!   payloads on overflow while still counting every frame seen on the wire, and
//!   the retained set is exactly the most-recent contiguous suffix.
//!
//! Scope: node-local receive path on committed `HEAD` plus this slice's new
//! codec + handler. The Cx-aware async `poll_recv_datagram` waker layer and the
//! A1 send path remain open on the epic.

#![allow(missing_docs)]

use asupersync::bytes::{Bytes, BytesMut};
use asupersync::cx::Cx;
use asupersync::net::atp::protocol::quic_frames::QuicFrame;
use asupersync::net::quic_native::{
    NativeQuicConnection, NativeQuicConnectionConfig, PacketNumberSpace,
};

/// Encode a sequence of frames into a single packet payload, as the wire would
/// carry them.
fn encode_packet(frames: &[QuicFrame]) -> Vec<u8> {
    let mut buf = BytesMut::new();
    for frame in frames {
        frame.encode(&mut buf).expect("frame encodes");
    }
    buf.as_ref().to_vec()
}

fn fresh_connection() -> NativeQuicConnection {
    NativeQuicConnection::new(NativeQuicConnectionConfig::default())
}

#[test]
fn packet_with_datagram_frame_surfaces_exact_payload_via_recv() {
    let cx = Cx::for_testing();
    let mut conn = fresh_connection();

    let symbol = b"raptorq-symbol-0xfeed".to_vec();
    // PING then DATAGRAM proves the frame is decoded out of a multi-frame
    // packet, not merely a bare single-frame buffer.
    let packet = encode_packet(&[
        QuicFrame::Ping,
        QuicFrame::Datagram {
            data: Bytes::copy_from_slice(&symbol),
        },
    ]);

    assert_eq!(conn.pending_datagram_count(), 0);
    assert_eq!(conn.datagrams_received(), 0);

    conn.process_packet_payload(&cx, PacketNumberSpace::ApplicationData, 0, &packet, 0)
        .expect("processing a packet carrying a DATAGRAM frame succeeds");

    assert_eq!(conn.datagrams_received(), 1);
    assert_eq!(conn.pending_datagram_count(), 1);

    let received = conn.recv_datagram().expect("a datagram is available");
    assert_eq!(received.as_ref(), symbol.as_slice());

    // Drained exactly once; the wire counter is not a queue-depth gauge.
    assert!(conn.recv_datagram().is_none());
    assert_eq!(conn.pending_datagram_count(), 0);
    assert_eq!(conn.datagrams_received(), 1);
}

#[test]
fn multiple_datagrams_surface_in_arrival_order() {
    let cx = Cx::for_testing();
    let mut conn = fresh_connection();

    let payloads: Vec<Vec<u8>> = (0u8..5).map(|i| vec![i; 8]).collect();
    let frames: Vec<QuicFrame> = payloads
        .iter()
        .map(|p| QuicFrame::Datagram {
            data: Bytes::copy_from_slice(p),
        })
        .collect();
    let packet = encode_packet(&frames);

    conn.process_packet_payload(&cx, PacketNumberSpace::ApplicationData, 1, &packet, 0)
        .expect("processing a multi-datagram packet succeeds");

    assert_eq!(conn.datagrams_received(), 5);
    assert_eq!(conn.pending_datagram_count(), 5);
    for expected in &payloads {
        assert_eq!(
            conn.recv_datagram().expect("datagram available").as_ref(),
            expected.as_slice()
        );
    }
    assert!(conn.recv_datagram().is_none());
}

#[test]
fn empty_datagram_payload_is_delivered() {
    let cx = Cx::for_testing();
    let mut conn = fresh_connection();

    let packet = encode_packet(&[QuicFrame::Datagram { data: Bytes::new() }]);
    conn.process_packet_payload(&cx, PacketNumberSpace::ApplicationData, 2, &packet, 0)
        .expect("processing an empty DATAGRAM succeeds");

    assert_eq!(conn.datagrams_received(), 1);
    let got = conn.recv_datagram().expect("empty datagram still delivered");
    assert!(got.is_empty());
    assert!(conn.recv_datagram().is_none());
}

#[test]
fn inbound_queue_drops_oldest_on_overflow_but_counts_every_frame() {
    let cx = Cx::for_testing();
    let mut conn = fresh_connection();

    // Feed far more datagrams than the bounded queue can hold. Each payload is a
    // big-endian index so we can reconstruct exactly which ones were retained
    // without depending on the (private) queue capacity constant.
    let total: u32 = 300;
    let frames: Vec<QuicFrame> = (0..total)
        .map(|i| QuicFrame::Datagram {
            data: Bytes::copy_from_slice(&i.to_be_bytes()),
        })
        .collect();
    let packet = encode_packet(&frames);

    conn.process_packet_payload(&cx, PacketNumberSpace::ApplicationData, 3, &packet, 0)
        .expect("processing an overflowing datagram burst succeeds");

    // The counter reflects every frame seen on the wire, not the queue depth.
    assert_eq!(conn.datagrams_received(), u64::from(total));

    let pending = conn.pending_datagram_count();
    assert!(pending > 0, "some datagrams must remain buffered");
    assert!(
        u32::try_from(pending).expect("pending fits u32") < total,
        "overflow must have dropped some datagrams"
    );

    // Drain and decode the retained indices in delivery order.
    let mut drained = Vec::new();
    while let Some(d) = conn.recv_datagram() {
        let arr: [u8; 4] = d.as_ref().try_into().expect("4-byte index payload");
        drained.push(u32::from_be_bytes(arr));
    }
    assert_eq!(drained.len(), pending);

    // Drop-oldest: the retained set is exactly the most-recent contiguous suffix
    // [total - pending, total). The newest is always retained; the oldest go.
    let pending_u32 = u32::try_from(pending).expect("pending fits u32");
    assert_eq!(*drained.last().expect("non-empty"), total - 1);
    assert_eq!(drained[0], total - pending_u32);
    assert!(
        drained.windows(2).all(|w| w[1] == w[0] + 1),
        "retained indices must be a gap-free suffix"
    );
}
