//! A6 high-level QUIC connection API — public-boundary integration proof.
//!
//! `arq-quic-epic-b0k8qo.1.6`. Exercises [`QuicConnection`] and the
//! deterministic in-memory loopback transport entirely through the public crate
//! surface (`asupersync::net::quic_native`), proving the "thin adapter target"
//! that Phase B (`transport_quic`) will use: establish a connection, open a
//! control stream, send/receive datagrams, read path stats, and close — with no
//! manual frame/packet/crypto calls in the application flow.
//!
//! Transport no-claim boundary (see `endpoint_api` module docs): the bytes
//! really flow through `generate_frames` → `process_packet_payload`; the
//! production event loop + real wire-CRYPTO handshake + AEAD/UDP wire path are
//! the remaining `b0k8qo.1.1`/`.1.5`/`.1.7` integration.

use asupersync::bytes::Bytes;
use asupersync::cx::Cx;
use asupersync::net::quic_native::{
    DEFAULT_MAX_PACKET_BYTES, NativeQuicConnectionConfig, NativeQuicConnectionError,
    QuicConnection, establish_loopback, pump_until_idle,
};
use asupersync::net::quic_native::{QuicConnectionState, StreamRole};

fn test_cx() -> Cx {
    Cx::for_testing()
}

fn fresh_pair() -> (QuicConnection, QuicConnection) {
    let cfg = NativeQuicConnectionConfig::default();
    (QuicConnection::client(cfg), QuicConnection::server(cfg))
}

/// Establish an authenticated loopback pair (client identity recorded, as a real
/// application would after verifying the server's certificate).
fn established_pair(cx: &Cx) -> (QuicConnection, QuicConnection) {
    let (mut client, mut server) = fresh_pair();
    client.record_verified_server_identity();
    establish_loopback(cx, &mut client, &mut server).expect("loopback establishes");
    (client, server)
}

#[test]
fn headline_usage_sequence_connect_stream_datagrams_close() {
    let cx = test_cx();
    // connect (deterministic loopback): both sides reach Established.
    let (mut client, mut server) = established_pair(&cx);
    assert_eq!(client.state(), QuicConnectionState::Established);
    assert_eq!(server.state(), QuicConnectionState::Established);
    assert_eq!(client.role(), StreamRole::Client);
    assert_eq!(server.role(), StreamRole::Server);

    // open a control stream and send a request body + FIN.
    let stream = client
        .open_control_stream(&cx)
        .expect("open control stream");
    client
        .write_control(&cx, stream, Bytes::from_static(b"MANIFEST v1\n"), true)
        .expect("write control");

    // send a couple of datagrams (the symbol spray).
    client
        .send_datagram(&cx, Bytes::from_static(b"symbol-0"))
        .expect("send datagram 0");
    client
        .send_datagram(&cx, Bytes::from_static(b"symbol-1"))
        .expect("send datagram 1");

    // deliver everything to the server.
    pump_until_idle(
        &cx,
        &mut client,
        &mut server,
        DEFAULT_MAX_PACKET_BYTES,
        1_000,
    )
    .expect("pump client->server");

    // server reads the control stream.
    let mut control = Vec::new();
    loop {
        let chunk = server
            .read_control(&cx, stream, 4096)
            .expect("read control");
        if chunk.is_empty() {
            break;
        }
        control.extend_from_slice(&chunk);
    }
    assert_eq!(control, b"MANIFEST v1\n");
    assert!(server.is_control_eof(stream).expect("eof"));

    // server receives both datagrams, exactly and in order.
    assert_eq!(server.recv_datagram().as_deref(), Some(&b"symbol-0"[..]));
    assert_eq!(server.recv_datagram().as_deref(), Some(&b"symbol-1"[..]));
    assert!(server.recv_datagram().is_none());

    // graceful close.
    client.begin_close(&cx, 2_000, 0).expect("begin close");
    assert_ne!(client.state(), QuicConnectionState::Established);
}

#[test]
fn datagram_roundtrip_is_bidirectional() {
    let cx = test_cx();
    let (mut client, mut server) = established_pair(&cx);

    client
        .send_datagram(&cx, Bytes::from_static(b"c2s"))
        .expect("client send");
    server
        .send_datagram(&cx, Bytes::from_static(b"s2c"))
        .expect("server send");

    pump_until_idle(&cx, &mut client, &mut server, DEFAULT_MAX_PACKET_BYTES, 10).expect("c->s");
    pump_until_idle(&cx, &mut server, &mut client, DEFAULT_MAX_PACKET_BYTES, 20).expect("s->c");

    assert_eq!(server.recv_datagram().as_deref(), Some(&b"c2s"[..]));
    assert_eq!(client.recv_datagram().as_deref(), Some(&b"s2c"[..]));
}

#[test]
fn client_fails_closed_without_verified_identity() {
    let cx = test_cx();
    let (mut client, mut server) = fresh_pair();
    let err = establish_loopback(&cx, &mut client, &mut server)
        .expect_err("client must fail closed without a verified server identity");
    assert!(
        matches!(err, NativeQuicConnectionError::Tls(_)),
        "expected fail-closed TLS error, got {err:?}"
    );
    assert_ne!(client.state(), QuicConnectionState::Established);
}

#[test]
fn datagram_send_rejected_before_established() {
    let cx = test_cx();
    let (mut client, _server) = fresh_pair();
    let err = client
        .send_datagram(&cx, Bytes::from_static(b"too early"))
        .expect_err("must reject before established");
    assert!(matches!(err, NativeQuicConnectionError::InvalidState(_)));
}

#[test]
fn oversize_datagram_rejected_fail_closed() {
    let cx = test_cx();
    let (mut client, _server) = established_pair(&cx);
    let err = client
        .send_datagram(&cx, Bytes::from(vec![0x5Au8; 8192]))
        .expect_err("oversize must be rejected");
    assert!(matches!(
        err,
        NativeQuicConnectionError::DatagramTooLarge { .. }
    ));
}

#[test]
fn large_control_stream_reassembles_across_many_packets() {
    let cx = test_cx();
    let (mut client, mut server) = established_pair(&cx);

    let stream = client.open_control_stream(&cx).expect("open");
    let body: Vec<u8> = (0..4096u32)
        .map(|i| u8::try_from(i % 251).unwrap())
        .collect();
    client
        .write_control(&cx, stream, Bytes::copy_from_slice(&body), true)
        .expect("write");

    // Small budget forces many packets; reassembly must restore exact order.
    let moved = pump_until_idle(&cx, &mut client, &mut server, 200, 7_000).expect("pump");
    assert!(moved > 1, "should fragment across packets, moved {moved}");

    let mut got = Vec::new();
    loop {
        let chunk = server.read_control(&cx, stream, 8192).expect("read");
        if chunk.is_empty() {
            break;
        }
        got.extend_from_slice(&chunk);
    }
    assert_eq!(got, body);
    assert!(server.is_control_eof(stream).expect("eof"));
}

#[test]
fn path_stats_exposed_for_phase_c() {
    let cx = test_cx();
    let (client, _server) = established_pair(&cx);
    let stats = client.path_stats();
    assert!(stats.congestion_window_bytes > 0);
    assert_eq!(stats.bytes_in_flight, 0);
    assert_eq!(stats.pto_count, 0);
}
