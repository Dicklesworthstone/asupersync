#![allow(missing_docs)]
#![cfg(unix)]
//! `UnixDatagram` integration tests for behaviour `tests/net_unix.rs` does not
//! exercise: peek-without-consume on both the addressed (`peek_from`) and the
//! connected (`peek`) paths, and oversized-datagram truncation.
//!
//! All tests use real Unix domain datagram sockets (temp-dir paths or a
//! `socketpair`), no mocks, and are deterministic: every receive/peek follows a
//! send, so the datagram is already queued and the first poll is `Ready`.
//!
//! Coverage:
//!   - `unix_datagram_peek_from_does_not_consume`: two `peek_from`s then a
//!     `recv_from` all see the same datagram and source path.
//!   - `unix_datagram_peek_on_pair_does_not_consume`: on a connected pair, two
//!     `peek`s then a `recv` all see the same datagram.
//!   - `unix_datagram_recv_from_truncates_oversized_datagram`: a datagram
//!     larger than the receive buffer is truncated to the buffer length.

use asupersync::net::unix::UnixDatagram;
use futures_lite::future::block_on;
use std::io;
use tempfile::TempDir;

/// `peek_from` leaves the datagram in the receive queue: two peeks and the
/// final `recv_from` all observe the same bytes and the same source path.
#[test]
fn unix_datagram_peek_from_does_not_consume() {
    let result = block_on(async {
        let dir = TempDir::new()?;
        let server_path = dir.path().join("server.sock");
        let client_path = dir.path().join("client.sock");

        let mut server = UnixDatagram::bind(&server_path)?;
        let mut client = UnixDatagram::bind(&client_path)?;

        let msg = b"unix-peekable-datagram";
        let sent = client.send_to(msg, &server_path).await?;
        assert_eq!(sent, msg.len(), "client sends the whole datagram");

        let mut buf1 = [0u8; 64];
        let (n1, a1) = server.peek_from(&mut buf1).await?;
        assert_eq!(n1, msg.len(), "first peek sees the full datagram");
        assert_eq!(&buf1[..n1], msg, "first peek returns the sent bytes");
        assert_eq!(
            a1.as_pathname(),
            Some(client_path.as_path()),
            "first peek reports the client's bound path"
        );

        let mut buf2 = [0u8; 64];
        let (n2, a2) = server.peek_from(&mut buf2).await?;
        assert_eq!(n2, msg.len(), "second peek still sees the datagram");
        assert_eq!(&buf2[..n2], msg, "second peek returns the same bytes");
        assert_eq!(
            a2.as_pathname(),
            Some(client_path.as_path()),
            "second peek reports the same source path"
        );

        let mut buf3 = [0u8; 64];
        let (n3, a3) = server.recv_from(&mut buf3).await?;
        assert_eq!(n3, msg.len(), "recv consumes the still-queued datagram");
        assert_eq!(&buf3[..n3], msg, "recv returns the bytes peek showed");
        assert_eq!(
            a3.as_pathname(),
            Some(client_path.as_path()),
            "recv reports the same source path"
        );

        Ok::<_, io::Error>(())
    });

    assert!(
        result.is_ok(),
        "addressed peek/recv sequence should succeed: {result:?}"
    );
}

/// On a connected `socketpair`, `peek` does not consume: two peeks then a
/// `recv` all observe the same datagram.
#[test]
fn unix_datagram_peek_on_pair_does_not_consume() {
    let result = block_on(async {
        let (mut a, mut b) = UnixDatagram::pair()?;

        let msg = b"pair-peekable";
        let sent = a.send(msg).await?;
        assert_eq!(sent, msg.len(), "send delivers the whole datagram");

        let mut buf1 = [0u8; 64];
        let n1 = b.peek(&mut buf1).await?;
        assert_eq!(n1, msg.len(), "first peek sees the datagram");
        assert_eq!(&buf1[..n1], msg, "first peek returns the sent bytes");

        let mut buf2 = [0u8; 64];
        let n2 = b.peek(&mut buf2).await?;
        assert_eq!(n2, msg.len(), "second peek still sees the datagram");
        assert_eq!(&buf2[..n2], msg, "second peek returns the same bytes");

        let mut buf3 = [0u8; 64];
        let n3 = b.recv(&mut buf3).await?;
        assert_eq!(n3, msg.len(), "recv consumes the datagram");
        assert_eq!(&buf3[..n3], msg, "recv returns the bytes peek showed");

        Ok::<_, io::Error>(())
    });

    assert!(
        result.is_ok(),
        "connected-pair peek/recv sequence should succeed: {result:?}"
    );
}

/// A datagram larger than the receive buffer is truncated to the buffer
/// length (the excess is discarded), with the prefix bytes intact.
#[test]
fn unix_datagram_recv_from_truncates_oversized_datagram() {
    let result = block_on(async {
        let dir = TempDir::new()?;
        let server_path = dir.path().join("server.sock");
        let client_path = dir.path().join("client.sock");

        let mut server = UnixDatagram::bind(&server_path)?;
        let mut client = UnixDatagram::bind(&client_path)?;

        let payload = vec![0x5Au8; 2000];
        let sent = client.send_to(&payload, &server_path).await?;
        assert_eq!(
            sent,
            payload.len(),
            "client sends the whole 2000-byte datagram"
        );

        let mut small = [0u8; 16];
        let (n, from) = server.recv_from(&mut small).await?;
        assert_eq!(
            n,
            small.len(),
            "recv_from truncates to the buffer length when the datagram is larger"
        );
        assert!(
            small.iter().all(|&b| b == 0x5A),
            "the bytes that fit are the datagram's prefix: {small:?}"
        );
        assert_eq!(
            from.as_pathname(),
            Some(client_path.as_path()),
            "truncated recv still reports the source path"
        );

        Ok::<_, io::Error>(())
    });

    assert!(result.is_ok(), "truncating recv should succeed: {result:?}");
}
