#![allow(missing_docs)]
//! Integration test for `UdpSocket::send_sink`, the send-side wrapper exposing
//! `send_to` and `send_datagram`, which has no other `tests/*.rs` coverage.
//! Real loopback sockets, no mocks.

use asupersync::net::UdpSocket;
use futures_lite::future::block_on;
use std::io;

#[test]
fn udp_send_sink_delivers_via_send_to_and_send_datagram() {
    let result = block_on(async {
        let mut server = UdpSocket::bind("127.0.0.1:0").await?;
        let server_addr = server.local_addr()?;

        let mut client = UdpSocket::bind("127.0.0.1:0").await?;
        let client_addr = client.local_addr()?;

        // Send one datagram through each SendSink method.
        let mut sink = client.send_sink();
        let n1 = sink.send_to(b"via-send-to", server_addr).await?;
        assert_eq!(n1, b"via-send-to".len(), "send_to reports the bytes sent");

        let payload = b"via-send-datagram".to_vec();
        let payload_len = payload.len();
        let n2 = sink.send_datagram((payload, server_addr)).await?;
        assert_eq!(n2, payload_len, "send_datagram reports the bytes sent");

        // Both datagrams arrive at the server, in order, from the client.
        let mut buf = [0u8; 64];
        let (m1, from1) = server.recv_from(&mut buf).await?;
        assert_eq!(
            &buf[..m1],
            b"via-send-to",
            "first datagram is the send_to payload"
        );
        assert_eq!(from1, client_addr, "source is the client");

        let (m2, from2) = server.recv_from(&mut buf).await?;
        assert_eq!(
            &buf[..m2],
            b"via-send-datagram",
            "second datagram is the send_datagram payload"
        );
        assert_eq!(from2, client_addr, "source is the client");

        Ok::<_, io::Error>(())
    });

    assert!(
        result.is_ok(),
        "send_sink should deliver both datagrams: {result:?}"
    );
}
