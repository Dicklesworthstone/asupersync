//! E2E: Transport TCP+UDP — connect, send, receive, close, large transfer.
//!
//! QUIC requires feature flag and external dependencies, tested separately.
//! See net_tcp.rs and net_udp.rs for comprehensive individual protocol tests.
//! This E2E validates the combined transport layer.

#[macro_use]
mod common;

use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::net::{TcpListener, TcpStream, UdpSocket};
use common::*;
use futures_lite::future::block_on;
use std::io;
use std::thread;
use std::time::Duration;

fn init_test(name: &str) {
    init_test_logging();
    test_phase!(name);
}

// =========================================================================
// TCP: connect -> send known-size -> read exact -> close
// =========================================================================

#[test]
fn e2e_tcp_connect_echo_close() {
    init_test("e2e_tcp_connect_echo_close");

    let msg = b"hello transport layer";
    let msg_len = msg.len();

    let result = block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        test_section!("Start echo server");
        let server = thread::spawn(move || {
            block_on(async {
                let (mut stream, peer) = listener.accept().await?;
                tracing::info!(?peer, "accepted");

                let mut buf = vec![0u8; msg_len];
                stream.read_exact(&mut buf).await?;
                stream.write_all(&buf).await?;
                Ok::<_, io::Error>(())
            })
        });

        thread::sleep(Duration::from_millis(10));

        test_section!("Client connect and echo");
        let mut client = TcpStream::connect(addr).await?;
        client.write_all(msg).await?;

        let mut buf = vec![0u8; msg_len];
        client.read_exact(&mut buf).await?;
        assert_eq!(&buf, msg);

        test_section!("Close");
        drop(client);
        server.join().expect("server panicked")?;

        Ok::<_, io::Error>(())
    });

    assert!(result.is_ok(), "TCP echo: {result:?}");
    test_complete!("e2e_tcp_echo");
}

// =========================================================================
// UDP: bidirectional datagram exchange
// =========================================================================

#[test]
fn e2e_udp_bidirectional() {
    init_test("e2e_udp_bidirectional");

    let result = block_on(async {
        let mut sock_a = UdpSocket::bind("127.0.0.1:0").await?;
        let mut sock_b = UdpSocket::bind("127.0.0.1:0").await?;
        let addr_a = sock_a.local_addr()?;
        let addr_b = sock_b.local_addr()?;

        test_section!("A -> B");
        sock_a.send_to(b"ping", addr_b).await?;
        let mut buf = [0u8; 64];
        let (n, from) = sock_b.recv_from(&mut buf).await?;
        assert_eq!(&buf[..n], b"ping");
        assert_eq!(from, addr_a);

        test_section!("B -> A");
        sock_b.send_to(b"pong", addr_a).await?;
        let (n, from) = sock_a.recv_from(&mut buf).await?;
        assert_eq!(&buf[..n], b"pong");
        assert_eq!(from, addr_b);

        Ok::<_, io::Error>(())
    });

    assert!(result.is_ok(), "UDP bidirectional: {result:?}");
    test_complete!("e2e_udp_bidirectional");
}

// =========================================================================
// TCP: multiple sequential clients with known-size messages
// =========================================================================

#[test]
fn e2e_tcp_multiple_clients() {
    init_test("e2e_tcp_multiple_clients");
    let client_count = 3usize;
    // Each message is "client-N" which is 8 bytes for single-digit N
    let msg_len = 8;

    let result = block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        let server = thread::spawn(move || {
            block_on(async {
                for _ in 0..client_count {
                    let (mut stream, _) = listener.accept().await?;
                    let mut buf = vec![0u8; msg_len];
                    stream.read_exact(&mut buf).await?;
                    stream.write_all(&buf).await?;
                }
                Ok::<_, io::Error>(())
            })
        });

        thread::sleep(Duration::from_millis(10));

        test_section!("Connect clients sequentially");
        for i in 0..client_count {
            let mut client = TcpStream::connect(addr).await?;
            let msg = format!("client-{i}");
            client.write_all(msg.as_bytes()).await?;
            let mut buf = vec![0u8; msg.len()];
            client.read_exact(&mut buf).await?;
            assert_eq!(&buf, msg.as_bytes());
        }

        server.join().expect("server panicked")?;
        Ok::<_, io::Error>(())
    });

    assert!(result.is_ok(), "TCP multi-client: {result:?}");
    test_complete!("e2e_tcp_multi_client", clients = client_count);
}

// =========================================================================
// TCP: large data transfer (client -> server via read_to_end)
// =========================================================================

#[test]
fn e2e_tcp_large_transfer() {
    init_test("e2e_tcp_large_transfer");

    let result = block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let data_size = 64 * 1024; // 64KB

        let server = thread::spawn(move || {
            block_on(async {
                let (mut stream, _) = listener.accept().await?;
                let mut received = Vec::new();
                stream.read_to_end(&mut received).await?;
                Ok::<_, io::Error>(received)
            })
        });

        thread::sleep(Duration::from_millis(10));

        test_section!("Send large data");
        let mut client = TcpStream::connect(addr).await?;
        let data: Vec<u8> = (0..data_size).map(|i| (i % 256) as u8).collect();
        client.write_all(&data).await?;
        drop(client); // close to signal EOF

        let received = server.join().expect("server panicked")?;
        assert_eq!(received.len(), data_size);
        assert_eq!(received, data);
        tracing::info!(bytes = data_size, "large transfer verified");

        Ok::<_, io::Error>(())
    });

    assert!(result.is_ok(), "TCP large transfer: {result:?}");
    test_complete!("e2e_tcp_large_transfer");
}
