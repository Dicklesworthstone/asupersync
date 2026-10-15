#![allow(missing_docs)]
//! Integration test for connected-`UdpSocket` source filtering: a socket that
//! has `connect`ed to a peer must only receive datagrams from that peer; the
//! kernel drops datagrams from any other source. `tests/net_udp.rs` exercises
//! connected send/recv but not this filtering guarantee (a real, security-
//! relevant property), and `poll_recv` has no other `tests/*.rs` coverage.
//!
//! Real loopback sockets, no mocks. The connect happens before any send, so
//! filtering is active for both datagrams; the peer's datagram is queued and
//! the non-peer's is dropped, so the receive resolves `Ready` immediately and
//! the follow-up non-blocking poll is `Pending` (no reactor parking).

use asupersync::net::UdpSocket;
use futures_lite::future::block_on;
use std::future::poll_fn;
use std::io;
use std::task::Poll;

#[test]
fn connected_udp_socket_ignores_datagrams_from_non_peer() {
    let result = block_on(async {
        let mut server = UdpSocket::bind("127.0.0.1:0").await?;
        let server_addr = server.local_addr()?;

        let mut peer = UdpSocket::bind("127.0.0.1:0").await?;
        let peer_addr = peer.local_addr()?;

        let mut stranger = UdpSocket::bind("127.0.0.1:0").await?;

        // The server only talks to `peer` from now on.
        server.connect(peer_addr).await?;

        // The stranger's datagram is sent first but must be filtered out; the
        // peer's datagram is the only one the server should ever see.
        let dropped = stranger.send_to(b"from-stranger", server_addr).await?;
        assert_eq!(
            dropped,
            b"from-stranger".len(),
            "stranger's send itself succeeds"
        );
        let delivered = peer.send_to(b"from-peer", server_addr).await?;
        assert_eq!(delivered, b"from-peer".len(), "peer's send succeeds");

        // Connected recv returns the peer's datagram, never the stranger's.
        let mut buf = [0u8; 64];
        let n = server.recv(&mut buf).await?;
        assert_eq!(
            &buf[..n],
            b"from-peer",
            "a connected socket only receives from its peer"
        );

        // Nothing else is queued: the stranger's datagram was dropped by the
        // kernel, so a single non-blocking poll is Pending.
        let mut buf2 = [0u8; 64];
        let polled = poll_fn(|cx| Poll::Ready(server.poll_recv(cx, &mut buf2))).await;
        assert!(
            matches!(polled, Poll::Pending),
            "no non-peer datagram is queued on the connected socket: {polled:?}"
        );

        Ok::<_, io::Error>(())
    });

    assert!(
        result.is_ok(),
        "connected-socket filtering should hold: {result:?}"
    );
}
