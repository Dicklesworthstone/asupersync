//! QUIC DATAGRAM send/receive end-to-end round-trip (arq-quic-epic b0k8qo.1.1 +
//! b0k8qo.1.2).
//!
//! The send path (A1) and receive path (A2) were landed independently. This
//! cross-bead integration proof closes the seam between them: a datagram queued
//! with `send_datagram`, generated into `QuicFrame::Datagram` frames, encoded to
//! wire bytes, and fed back through `process_packet_payload` must be recovered
//! byte-identical via `recv_datagram`, in order, with `datagrams_received` on the
//! receiver matching `datagrams_sent` on the sender. A metamorphic relation
//! pins that delivery is independent of how the datagrams are split across
//! packets. No mocks — two real `NativeQuicConnection`s exchange real wire bytes.

#![allow(missing_docs)]

use asupersync::bytes::{Bytes, BytesMut};
use asupersync::cx::Cx;
use asupersync::net::quic_native::{
    NativeQuicConnection, NativeQuicConnectionConfig, PacketNumberSpace,
};

fn fresh_connection() -> NativeQuicConnection {
    NativeQuicConnection::new(NativeQuicConnectionConfig::default())
}

/// Encode a connection's pending 1-RTT frames into one packet payload.
fn assemble_app_packet(conn: &mut NativeQuicConnection, cx: &Cx, budget: usize) -> Vec<u8> {
    let frames = conn
        .generate_frames(cx, PacketNumberSpace::ApplicationData, budget)
        .expect("generate 1-RTT frames");
    let mut packet = BytesMut::new();
    NativeQuicConnection::encode_frames(&frames, &mut packet).expect("encode frames");
    packet.as_ref().to_vec()
}

/// Drain every recovered datagram from a receiver in delivery order.
fn drain(conn: &mut NativeQuicConnection) -> Vec<Bytes> {
    let mut out = Vec::new();
    while let Some(d) = conn.recv_datagram() {
        out.push(d);
    }
    out
}

#[test]
fn datagrams_sent_are_recovered_byte_identical_on_receive() {
    let cx = Cx::for_testing();
    let mut tx = fresh_connection();
    let mut rx = fresh_connection();

    // Distinct lengths and contents so a swap or truncation would be caught.
    let payloads: Vec<Bytes> = (0u8..6)
        .map(|i| Bytes::from(vec![i; 16 + usize::from(i)]))
        .collect();
    for p in &payloads {
        tx.send_datagram(&cx, p.clone()).expect("enqueue datagram");
    }

    let packet = assemble_app_packet(&mut tx, &cx, 100_000);
    assert_eq!(tx.datagrams_sent(), payloads.len() as u64);

    rx.process_packet_payload(&cx, PacketNumberSpace::ApplicationData, 0, &packet, 0)
        .expect("receive the datagram packet");

    // Every sent datagram is accounted on receive, byte-identical and in order.
    assert_eq!(rx.datagrams_received(), tx.datagrams_sent());
    assert_eq!(drain(&mut rx), payloads);
}

#[test]
fn datagram_delivery_is_independent_of_packetization_metamorphic() {
    let cx = Cx::for_testing();
    let payloads: Vec<Bytes> = (0u8..5).map(|i| Bytes::from(vec![i; 64])).collect();

    // Baseline: all datagrams in a single large packet.
    let mut tx_one = fresh_connection();
    let mut rx_one = fresh_connection();
    for p in &payloads {
        tx_one.send_datagram(&cx, p.clone()).expect("enqueue");
    }
    let single_packet = assemble_app_packet(&mut tx_one, &cx, 100_000);
    rx_one
        .process_packet_payload(
            &cx,
            PacketNumberSpace::ApplicationData,
            0,
            &single_packet,
            0,
        )
        .expect("receive single packet");
    let single = drain(&mut rx_one);

    // Variant: a tiny per-packet budget forces one datagram per packet.
    let mut tx_many = fresh_connection();
    let mut rx_many = fresh_connection();
    for p in &payloads {
        tx_many.send_datagram(&cx, p.clone()).expect("enqueue");
    }
    let mut packet_number = 0u64;
    loop {
        let packet = assemble_app_packet(&mut tx_many, &cx, 80);
        if packet.is_empty() {
            break;
        }
        rx_many
            .process_packet_payload(
                &cx,
                PacketNumberSpace::ApplicationData,
                packet_number,
                &packet,
                0,
            )
            .expect("receive split packet");
        packet_number += 1;
    }
    assert!(
        packet_number >= 2,
        "a tiny budget must have produced multiple packets"
    );
    let split = drain(&mut rx_many);

    // Metamorphic equality: packetization does not change what is delivered.
    assert_eq!(single, payloads);
    assert_eq!(split, single);
}
