#![allow(missing_docs)]
//! UDP integration tests for the parts of `asupersync::net::UdpSocket` that
//! `tests/net_udp.rs` does not exercise: peek-without-consume, `peer_addr`
//! before/after `connect`, oversized-datagram truncation, the empty-buffer
//! error path, and socket-option setters.
//!
//! All tests use real loopback sockets (no mocks) and are deterministic: every
//! receive/peek is preceded by a send so the datagram is already queued in the
//! kernel buffer and the first poll is `Ready` (no reactor parking).
//!
//! Coverage:
//!   - `peek_from_does_not_consume_datagram`: two peeks then a recv all see the
//!     same datagram; peek leaves it in the queue, recv consumes it.
//!   - `peer_addr_errors_when_unconnected_then_reflects_connect`: `peer_addr`
//!     is an error on an unconnected socket and returns the peer after connect.
//!   - `recv_from_truncates_oversized_datagram`: a datagram larger than the
//!     receive buffer is truncated to the buffer length (UDP semantics).
//!   - `recv_and_peek_reject_empty_buffer`: a zero-length buffer is rejected
//!     before touching the socket.
//!   - `socket_options_apply_on_bound_socket`: broadcast/TTL/multicast-loop/
//!     multicast-TTL setters succeed on a bound IPv4 socket.

use asupersync::net::UdpSocket;
use futures_lite::future::block_on;
use std::io;

/// `peek_from` must not remove the datagram from the receive queue: two
/// successive peeks and the final `recv_from` all observe the same bytes and
/// source address.
#[test]
fn peek_from_does_not_consume_datagram() {
    let result = block_on(async {
        let mut server = UdpSocket::bind("127.0.0.1:0").await?;
        let server_addr = server.local_addr()?;

        let mut client = UdpSocket::bind("127.0.0.1:0").await?;
        let client_addr = client.local_addr()?;

        let msg = b"peekable-datagram";
        let sent = client.send_to(msg, server_addr).await?;
        assert_eq!(sent, msg.len(), "client should send the whole datagram");

        // First peek observes the datagram without consuming it.
        let mut buf1 = [0u8; 64];
        let (n1, from1) = server.peek_from(&mut buf1).await?;
        assert_eq!(n1, msg.len(), "first peek sees the full datagram");
        assert_eq!(&buf1[..n1], msg, "first peek returns the sent bytes");
        assert_eq!(from1, client_addr, "first peek reports the client source");

        // Second peek observes the *same* datagram: peek did not consume it.
        let mut buf2 = [0u8; 64];
        let (n2, from2) = server.peek_from(&mut buf2).await?;
        assert_eq!(n2, msg.len(), "second peek still sees the datagram");
        assert_eq!(&buf2[..n2], msg, "second peek returns the same bytes");
        assert_eq!(from2, client_addr, "second peek reports the same source");

        // recv_from now consumes the datagram and returns the same content.
        let mut buf3 = [0u8; 64];
        let (n3, from3) = server.recv_from(&mut buf3).await?;
        assert_eq!(n3, msg.len(), "recv sees the still-queued datagram");
        assert_eq!(&buf3[..n3], msg, "recv returns the same bytes peek showed");
        assert_eq!(from3, client_addr, "recv reports the same source");

        Ok::<_, io::Error>(())
    });

    assert!(
        result.is_ok(),
        "peek/recv sequence should succeed: {result:?}"
    );
}

/// `peer_addr` returns an error before `connect` (the socket has no default
/// peer) and the connected peer's address afterwards.
#[test]
fn peer_addr_errors_when_unconnected_then_reflects_connect() {
    let result = block_on(async {
        let a = UdpSocket::bind("127.0.0.1:0").await?;
        let b = UdpSocket::bind("127.0.0.1:0").await?;
        let b_addr = b.local_addr()?;

        // An unconnected datagram socket has no peer: peer_addr is an error.
        assert!(
            a.peer_addr().is_err(),
            "peer_addr must error before connect, got {:?}",
            a.peer_addr()
        );

        a.connect(b_addr).await?;

        // After connect, peer_addr reports the address we connected to.
        let peer = a.peer_addr()?;
        assert_eq!(peer, b_addr, "peer_addr reflects the connected peer");

        Ok::<_, io::Error>(())
    });

    assert!(
        result.is_ok(),
        "peer_addr connect flow should succeed: {result:?}"
    );
}

/// A datagram larger than the supplied receive buffer is truncated to the
/// buffer length (the excess is discarded — standard UDP behaviour), and the
/// bytes that do fit are the datagram's prefix.
#[test]
fn recv_from_truncates_oversized_datagram() {
    let result = block_on(async {
        let mut server = UdpSocket::bind("127.0.0.1:0").await?;
        let server_addr = server.local_addr()?;

        let mut client = UdpSocket::bind("127.0.0.1:0").await?;
        let client_addr = client.local_addr()?;

        // A 2000-byte datagram (well within the loopback MTU, delivered whole).
        let payload = vec![0xABu8; 2000];
        let sent = client.send_to(&payload, server_addr).await?;
        assert_eq!(
            sent,
            payload.len(),
            "client sends the whole 2000-byte datagram"
        );

        // Receive into a buffer far smaller than the datagram.
        let mut small = [0u8; 16];
        let (n, from) = server.recv_from(&mut small).await?;
        assert_eq!(
            n,
            small.len(),
            "recv_from truncates to the buffer length when the datagram is larger"
        );
        assert!(
            small.iter().all(|&b| b == 0xAB),
            "the bytes that fit are the datagram's prefix: {small:?}"
        );
        assert_eq!(from, client_addr, "truncated recv still reports the source");

        Ok::<_, io::Error>(())
    });

    assert!(result.is_ok(), "truncating recv should succeed: {result:?}");
}

/// Both `recv_from` and `peek_from` reject a zero-length buffer up front
/// (there is nowhere to place a received byte), without touching the socket.
#[test]
fn recv_and_peek_reject_empty_buffer() {
    let result = block_on(async {
        let mut sock = UdpSocket::bind("127.0.0.1:0").await?;

        let mut empty: [u8; 0] = [];
        let recv_err = sock.recv_from(&mut empty).await;
        assert!(
            recv_err.is_err(),
            "recv_from must reject an empty buffer, got {recv_err:?}"
        );

        let peek_err = sock.peek_from(&mut empty).await;
        assert!(
            peek_err.is_err(),
            "peek_from must reject an empty buffer, got {peek_err:?}"
        );

        Ok::<_, io::Error>(())
    });

    assert!(
        result.is_ok(),
        "empty-buffer rejection setup should succeed: {result:?}"
    );
}

/// Socket-option setters that are pure `setsockopt` calls (no network
/// dependency) succeed on a freshly bound IPv4 socket.
#[test]
fn socket_options_apply_on_bound_socket() {
    let result = block_on(async {
        let sock = UdpSocket::bind("127.0.0.1:0").await?;

        sock.set_broadcast(true)?;
        sock.set_broadcast(false)?;
        sock.set_ttl(64)?;
        sock.set_multicast_loop_v4(true)?;
        sock.set_multicast_ttl_v4(1)?;

        Ok::<_, io::Error>(())
    });

    assert!(
        result.is_ok(),
        "socket option setters should succeed: {result:?}"
    );
}
