#![allow(missing_docs)]
//! Integration test for `UdpSocket::recv_stream`, the `Stream` adapter over
//! `recv_from`, which has no other `tests/*.rs` coverage.
//!
//! Three datagrams are sent before the stream is pulled, so each `next()` finds
//! a datagram already queued and resolves `Ready` (no reactor parking). Exactly
//! three items are pulled — never a fourth, which would block on an empty queue.
//! Loopback delivery of a few small datagrams from a single source is reliable
//! and ordered (the existing `tests/net_udp.rs` relies on the same property).

use asupersync::net::UdpSocket;
use asupersync::stream::StreamExt as _;
use futures_lite::future::block_on;
use std::io;

#[test]
fn udp_recv_stream_yields_queued_datagrams_in_order() {
    let result = block_on(async {
        let mut server = UdpSocket::bind("127.0.0.1:0").await?;
        let server_addr = server.local_addr()?;

        let mut client = UdpSocket::bind("127.0.0.1:0").await?;
        let client_addr = client.local_addr()?;

        let messages: [&[u8]; 3] = [b"alpha", b"bravo", b"charlie"];
        for msg in messages {
            let sent = client.send_to(msg, server_addr).await?;
            assert_eq!(sent, msg.len(), "client sends the whole datagram");
        }

        // Pull exactly the three queued datagrams via the Stream adapter.
        let mut stream = server.recv_stream(2048);
        for expected in messages {
            let (data, from) = stream
                .next()
                .await
                .expect("stream yields a queued datagram")?;
            assert_eq!(data, expected, "recv_stream yields datagrams in FIFO order");
            assert_eq!(from, client_addr, "datagram source is the client");
        }
        // Intentionally stop here: a fourth `next()` would block on the now-empty
        // queue (there is no reactor under this executor).

        Ok::<_, io::Error>(())
    });

    assert!(
        result.is_ok(),
        "recv_stream should yield the queued datagrams: {result:?}"
    );
}
