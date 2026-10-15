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
//! - the bounded inbound queue never evicts already-buffered payloads: once full,
//!   newly-arrived payloads are counted as receive drops and the retained set is
//!   exactly the original accepted prefix.
//!
//! Scope: node-local receive path on committed `HEAD` plus this slice's new
//! codec + handler + Cx-aware `poll_recv_datagram` waker layer. The A1 send
//! path remains separately tracked on the epic.

#![allow(missing_docs)]

use asupersync::bytes::{Bytes, BytesMut};
use asupersync::cx::Cx;
use asupersync::net::atp::protocol::quic_frames::QuicFrame;
use asupersync::net::quic_native::{
    NativeQuicConnection, NativeQuicConnectionConfig, NativeQuicConnectionError, PacketNumberSpace,
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::task::{Context as TaskContext, Poll, Wake, Waker};

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

#[derive(Debug, Default)]
struct CountingWaker {
    wakes: AtomicUsize,
}

impl CountingWaker {
    fn wake_count(&self) -> usize {
        self.wakes.load(Ordering::SeqCst)
    }
}

impl Wake for CountingWaker {
    fn wake(self: Arc<Self>) {
        self.wakes.fetch_add(1, Ordering::SeqCst);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.wakes.fetch_add(1, Ordering::SeqCst);
    }
}

fn counting_waker() -> (Arc<CountingWaker>, Waker) {
    let state = Arc::new(CountingWaker::default());
    let waker = Waker::from(Arc::clone(&state));
    (state, waker)
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
fn poll_recv_datagram_registers_waker_and_wakes_on_arrival() {
    let cx = Cx::for_testing();
    let mut conn = fresh_connection();
    let (wake_state, waker) = counting_waker();
    let mut task_cx = TaskContext::from_waker(&waker);

    assert!(matches!(
        conn.poll_recv_datagram(&cx, &mut task_cx),
        Poll::Pending
    ));
    assert_eq!(wake_state.wake_count(), 0);

    let payload = Bytes::from_static(b"wake-me-when-symbol-arrives");
    let packet = encode_packet(&[QuicFrame::Datagram {
        data: payload.clone(),
    }]);
    conn.process_packet_payload(&cx, PacketNumberSpace::ApplicationData, 10, &packet, 0)
        .expect("processing DATAGRAM wakes the registered receiver");

    assert_eq!(wake_state.wake_count(), 1);
    match conn.poll_recv_datagram(&cx, &mut task_cx) {
        Poll::Ready(Ok(received)) => assert_eq!(received, payload),
        other => panic!("expected ready datagram after wake, got {other:?}"),
    }
    assert_eq!(conn.pending_datagram_count(), 0);
}

#[test]
fn poll_recv_datagram_observes_cx_cancellation() {
    let cx = Cx::for_testing();
    cx.set_cancel_requested(true);
    let mut conn = fresh_connection();
    let (_, waker) = counting_waker();
    let mut task_cx = TaskContext::from_waker(&waker);

    match conn.poll_recv_datagram(&cx, &mut task_cx) {
        Poll::Ready(Err(NativeQuicConnectionError::Cancelled)) => {}
        other => panic!("cancelled Cx must fail closed, got {other:?}"),
    }
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
    let got = conn
        .recv_datagram()
        .expect("empty datagram still delivered");
    assert!(got.is_empty());
    assert!(conn.recv_datagram().is_none());
}

#[test]
fn inbound_queue_drops_new_overflow_without_evicting_buffered_datagrams() {
    let cx = Cx::for_testing();
    let mut conn = fresh_connection();

    // Fill the receive queue to its advertised capacity. Each payload is a
    // big-endian index so we can reconstruct exactly which symbols survived.
    let fill_count = conn.inbound_datagram_capacity();
    assert!(
        fill_count >= 46_000,
        "receive queue must cover a 50 MiB encrypted symbol round before repair"
    );
    let frames: Vec<QuicFrame> = (0..fill_count)
        .map(|i| QuicFrame::Datagram {
            data: Bytes::copy_from_slice(
                &u32::try_from(i).expect("test index fits u32").to_be_bytes(),
            ),
        })
        .collect();
    let packet = encode_packet(&frames);

    conn.process_packet_payload(&cx, PacketNumberSpace::ApplicationData, 3, &packet, 0)
        .expect("processing a full-capacity datagram burst succeeds");

    assert_eq!(
        conn.datagrams_received(),
        u64::try_from(fill_count).expect("fill count fits u64")
    );
    assert_eq!(conn.pending_datagram_count(), fill_count);
    assert_eq!(
        conn.datagrams_dropped_on_receive(),
        0,
        "receive-side buffering must never evict accepted survivors"
    );

    let overflow = encode_packet(&[QuicFrame::Datagram {
        data: Bytes::copy_from_slice(
            &u32::try_from(fill_count)
                .expect("overflow index fits u32")
                .to_be_bytes(),
        ),
    }]);
    conn.process_packet_payload(&cx, PacketNumberSpace::ApplicationData, 4, &overflow, 0)
        .expect("full receive queue treats new unreliable datagram as counted loss");
    assert_eq!(
        conn.datagrams_received(),
        u64::try_from(fill_count).expect("fill count fits u64")
    );
    assert_eq!(conn.pending_datagram_count(), fill_count);
    assert_eq!(conn.datagrams_dropped_on_receive(), 1);

    // Drain and decode the retained indices in delivery order.
    let mut drained = Vec::new();
    while let Some(d) = conn.recv_datagram() {
        let arr: [u8; 4] = d.as_ref().try_into().expect("4-byte index payload");
        drained.push(u32::from_be_bytes(arr));
    }
    assert_eq!(drained.len(), fill_count);

    // No-evict overflow handling: the retained set is exactly the accepted
    // prefix [0, fill_count). The overflow payload is not inserted and no
    // survivor is displaced.
    assert_eq!(drained[0], 0);
    assert_eq!(
        *drained.last().expect("non-empty"),
        u32::try_from(fill_count - 1).expect("last index fits u32")
    );
    assert!(
        drained.windows(2).all(|w| w[1] == w[0] + 1),
        "retained indices must be a gap-free prefix"
    );
}

#[test]
fn inbound_queue_partial_overflow_accepts_capacity_and_counts_tail_drop() {
    let cx = Cx::for_testing();
    let mut conn = fresh_connection();
    let fill_count = conn.inbound_datagram_capacity();
    let prefill_count = fill_count - 1;
    let frames: Vec<QuicFrame> = (0..prefill_count)
        .map(|i| QuicFrame::Datagram {
            data: Bytes::copy_from_slice(
                &u32::try_from(i).expect("test index fits u32").to_be_bytes(),
            ),
        })
        .collect();

    conn.process_packet_payload(
        &cx,
        PacketNumberSpace::ApplicationData,
        5,
        &encode_packet(&frames),
        0,
    )
    .expect("prefill receive queue with one remaining slot");
    assert_eq!(conn.pending_datagram_count(), prefill_count);
    assert_eq!(conn.inbound_datagram_remaining_capacity(), 1);

    let accepted_tail = u32::try_from(prefill_count).expect("accepted tail index fits u32");
    let dropped_tail = u32::try_from(fill_count).expect("dropped tail index fits u32");
    let overflow = encode_packet(&[
        QuicFrame::Datagram {
            data: Bytes::copy_from_slice(&accepted_tail.to_be_bytes()),
        },
        QuicFrame::Datagram {
            data: Bytes::copy_from_slice(&dropped_tail.to_be_bytes()),
        },
    ]);
    conn.process_packet_payload(&cx, PacketNumberSpace::ApplicationData, 6, &overflow, 0)
        .expect("partial receive capacity accepts prefix and counts overflow tail");

    assert_eq!(conn.pending_datagram_count(), fill_count);
    assert_eq!(
        conn.datagrams_received(),
        u64::try_from(fill_count).expect("count fits u64")
    );
    assert_eq!(conn.datagrams_dropped_on_receive(), 1);

    let mut drained = Vec::new();
    while let Some(d) = conn.recv_datagram() {
        let arr: [u8; 4] = d.as_ref().try_into().expect("4-byte index payload");
        drained.push(u32::from_be_bytes(arr));
    }
    assert_eq!(drained.len(), fill_count);
    assert_eq!(
        *drained.last().expect("non-empty"),
        accepted_tail,
        "the first overflow-batch payload should fill the last slot"
    );
    assert!(
        !drained.contains(&dropped_tail),
        "the tail payload beyond capacity must be counted as loss, not queued"
    );
}

#[test]
fn inbound_queue_accepts_after_receiver_drains_capacity_without_dropping() {
    let cx = Cx::for_testing();
    let mut conn = fresh_connection();
    let fill_count = conn.inbound_datagram_capacity();
    let frames: Vec<QuicFrame> = (0..fill_count)
        .map(|i| QuicFrame::Datagram {
            data: Bytes::copy_from_slice(
                &u32::try_from(i).expect("test index fits u32").to_be_bytes(),
            ),
        })
        .collect();

    conn.process_packet_payload(
        &cx,
        PacketNumberSpace::ApplicationData,
        10,
        &encode_packet(&frames),
        0,
    )
    .expect("fill receive queue");
    assert_eq!(conn.pending_datagram_count(), fill_count);
    assert_eq!(conn.datagrams_dropped_on_receive(), 0);

    let drained = conn.recv_datagram().expect("receiver drains one slot");
    let drained_index = u32::from_be_bytes(drained.as_ref().try_into().expect("4-byte index"));
    assert_eq!(drained_index, 0);
    assert_eq!(conn.pending_datagram_count(), fill_count - 1);

    let refill_index = u32::try_from(fill_count).expect("refill index fits u32");
    let refill = encode_packet(&[QuicFrame::Datagram {
        data: Bytes::copy_from_slice(&refill_index.to_be_bytes()),
    }]);
    conn.process_packet_payload(&cx, PacketNumberSpace::ApplicationData, 11, &refill, 0)
        .expect("available capacity accepts a new datagram after drain");

    assert_eq!(
        conn.datagrams_received(),
        u64::try_from(fill_count + 1).expect("count fits u64")
    );
    assert_eq!(conn.pending_datagram_count(), fill_count);
    assert_eq!(
        conn.datagrams_dropped_on_receive(),
        0,
        "draining capacity must never be recorded as silent receive loss"
    );

    let mut drained_after_refill = Vec::new();
    while let Some(d) = conn.recv_datagram() {
        drained_after_refill.push(u32::from_be_bytes(
            d.as_ref().try_into().expect("4-byte index"),
        ));
    }
    assert_eq!(drained_after_refill.len(), fill_count);
    assert_eq!(drained_after_refill[0], 1);
    assert_eq!(
        *drained_after_refill.last().expect("non-empty"),
        refill_index
    );
}
