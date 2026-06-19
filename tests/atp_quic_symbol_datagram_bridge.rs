//! `Symbol` ↔ QUIC datagram bridge — end-to-end over the A6 datagram plane.
//!
//! `arq-quic-epic-b0k8qo.2.2` / `.2.3` (B2/B3 foundational slice). Proves a
//! RaptorQ [`Symbol`] really flows source→sink through `send_symbol` →
//! `QuicConnection` DATAGRAM → `recv_symbol_envelope` → `envelope_to_symbol`,
//! using the deterministic A6 loopback transport (`establish_loopback` +
//! `pump_until_idle`). Covers source/repair, FIFO order, ±auth posture, and the
//! fail-closed cases (non-envelope datagram, oversize symbol). Public API only;
//! `Symbol`/`SymbolId` lack `Debug`, so equality uses `==` rather than
//! `assert_eq!`.

use asupersync::bytes::Bytes;
use asupersync::cx::Cx;
use asupersync::net::atp::transport_quic::{
    SymbolDatagramError, envelope_to_symbol, recv_symbol_envelope, send_symbol,
};
use asupersync::net::quic_native::{
    DEFAULT_MAX_PACKET_BYTES, NativeQuicConnectionConfig, NativeQuicConnectionError,
    QuicConnection, establish_loopback, pump_until_idle,
};
use asupersync::types::symbol::{ObjectId, Symbol, SymbolId, SymbolKind};

fn test_cx() -> Cx {
    Cx::for_testing()
}

fn established_pair(cx: &Cx) -> (QuicConnection, QuicConnection) {
    let cfg = NativeQuicConnectionConfig::default();
    let mut client = QuicConnection::client(cfg);
    let mut server = QuicConnection::server(cfg);
    client.record_verified_server_identity();
    establish_loopback(cx, &mut client, &mut server).expect("loopback establishes");
    (client, server)
}

fn sym(object: u128, sbn: u8, esi: u32, repair: bool, data: &[u8]) -> Symbol {
    let kind = if repair {
        SymbolKind::Repair
    } else {
        SymbolKind::Source
    };
    Symbol::from_slice(
        SymbolId::new(ObjectId::from_u128(object), sbn, esi),
        data,
        kind,
    )
}

#[test]
fn symbols_flow_over_the_quic_datagram_plane() {
    let cx = test_cx();
    let (mut client, mut server) = established_pair(&cx);

    const OBJ: u128 = 0xDEAD_BEEF;
    let symbols = [
        sym(OBJ, 0, 0, false, b"source-symbol-0"),
        sym(OBJ, 0, 1, false, b"source-symbol-1"),
        sym(OBJ, 0, 2, true, b"repair-symbol-2"),
    ];
    for s in &symbols {
        send_symbol(&cx, &mut client, s, 0x42, 0, None).expect("send symbol");
    }
    let moved = pump_until_idle(
        &cx,
        &mut client,
        &mut server,
        DEFAULT_MAX_PACKET_BYTES,
        1_000,
    )
    .expect("pump");
    assert!(moved >= symbols.len(), "all symbol datagrams delivered");

    // Symbols arrive in order, decode, and reconstruct exactly (object_id is
    // supplied from "manifest" context — here the known OBJ).
    for expected in &symbols {
        let env = recv_symbol_envelope(&mut server, false)
            .expect("decode")
            .expect("a symbol datagram arrived");
        assert_eq!(env.transfer_tag, 0x42);
        let got = envelope_to_symbol(&env, ObjectId::from_u128(OBJ));
        assert!(got.eq(expected), "symbol reconstructed exactly, in order");
    }
    assert!(
        recv_symbol_envelope(&mut server, false)
            .expect("no error")
            .is_none(),
        "no extra datagrams"
    );
}

#[test]
fn authed_symbol_round_trips_with_matching_posture() {
    let cx = test_cx();
    let (mut client, mut server) = established_pair(&cx);

    const OBJ: u128 = 7;
    let s = sym(OBJ, 1, 9, false, b"authed-symbol");
    let tag = [0x5Au8; 32];
    send_symbol(&cx, &mut client, &s, 1, 4, Some(tag)).expect("send authed symbol");
    pump_until_idle(
        &cx,
        &mut client,
        &mut server,
        DEFAULT_MAX_PACKET_BYTES,
        2_000,
    )
    .expect("pump");

    let env = recv_symbol_envelope(&mut server, true)
        .expect("decode authed")
        .expect("a datagram arrived");
    assert_eq!(env.auth_tag, Some(tag));
    let got = envelope_to_symbol(&env, ObjectId::from_u128(OBJ));
    assert_eq!(got, s);
}

#[test]
fn non_envelope_datagram_fails_closed() {
    let cx = test_cx();
    let (mut client, mut server) = established_pair(&cx);

    // A datagram that is not a symbol envelope (wrong magic) must fail closed on
    // decode rather than be misparsed.
    client
        .send_datagram(
            &cx,
            Bytes::from_static(b"this-is-not-an-atqs-symbol-envelope"),
        )
        .expect("queue raw datagram");
    pump_until_idle(
        &cx,
        &mut client,
        &mut server,
        DEFAULT_MAX_PACKET_BYTES,
        3_000,
    )
    .expect("pump");

    let err = recv_symbol_envelope(&mut server, false)
        .expect_err("a non-envelope datagram must fail closed");
    assert!(matches!(err, SymbolDatagramError::Envelope(_)));
}

#[test]
fn oversize_symbol_rejected_by_connection() {
    let cx = test_cx();
    let (mut client, _server) = established_pair(&cx);

    // A symbol whose envelope exceeds the max DATAGRAM frame size must be
    // rejected fail-closed by the connection (not silently dropped/truncated).
    let big_payload = vec![0xABu8; 4096];
    let big = sym(1, 0, 0, false, &big_payload);
    let err = send_symbol(&cx, &mut client, &big, 0, 0, None)
        .expect_err("oversize symbol must be rejected");
    assert!(matches!(
        err,
        SymbolDatagramError::Connection(NativeQuicConnectionError::DatagramTooLarge { .. })
    ));
}

#[test]
fn auth_posture_mismatch_fails_closed() {
    let cx = test_cx();
    let (mut client, mut server) = established_pair(&cx);

    // Sender does NOT authenticate; a receiver that REQUIRES per-symbol auth must
    // reject the datagram (fail closed) rather than misparse it. A >= 32-byte
    // payload makes the posture mismatch surface as a length mismatch (the auth
    // header is 32 bytes longer than the unauthenticated one).
    let s = sym(5, 2, 3, false, &[0u8; 40]);
    send_symbol(&cx, &mut client, &s, 0, 0, None).expect("send unauthenticated symbol");
    pump_until_idle(
        &cx,
        &mut client,
        &mut server,
        DEFAULT_MAX_PACKET_BYTES,
        4_000,
    )
    .expect("pump");

    let err = recv_symbol_envelope(&mut server, true)
        .expect_err("an auth-required receiver must reject an unauthenticated symbol");
    assert!(matches!(err, SymbolDatagramError::Envelope(_)));
}
