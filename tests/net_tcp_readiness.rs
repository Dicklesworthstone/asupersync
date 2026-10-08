//! `TcpStream::{peek, readable, writable, try_read, try_write}` and the
//! linger / pending-error options. A peeked prefix is read again; readiness
//! plus `try_*` moves data without the `AsyncRead`/`AsyncWrite` traits,
//! including waiting for a full send buffer to drain.

use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::net::{TcpListener, TcpStream};
use asupersync::runtime::RuntimeBuilder;
use std::io::ErrorKind;
use std::time::Duration;

async fn pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("address");
    let client = TcpStream::connect(address).await.expect("connect");
    let (server, _) = listener.accept().await.expect("accept");
    (client, server)
}

#[test]
fn peek_leaves_bytes_for_the_next_read() {
    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("runtime");
    let handle = runtime.handle();
    runtime.block_on(async move {
        let (mut client, mut server) = pair().await;
        // The peek waits for bytes that arrive later.
        let writer = handle.spawn(async move {
            for _ in 0..10 {
                asupersync::runtime::yield_now().await;
            }
            client
                .write_all(b"\x16\x03\x01 tls-ish")
                .await
                .expect("write");
            client
        });
        let mut first = [0_u8; 3];
        let peeked = server.peek(&mut first).await.expect("peek");
        assert_eq!(&first[..peeked], &b"\x16\x03\x01"[..peeked]);
        let mut all = [0_u8; 11];
        server.read_exact(&mut all).await.expect("read");
        assert_eq!(
            &all, b"\x16\x03\x01 tls-ish",
            "the peeked bytes are read again"
        );
        drop(writer.await);
        // End of stream peeks as zero bytes.
        assert_eq!(server.peek(&mut first).await.expect("peek at EOF"), 0);
    });
}

#[test]
fn readiness_and_try_io_move_data_and_wait_for_a_full_buffer_to_drain() {
    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("runtime");
    let handle = runtime.handle();
    runtime.block_on(async move {
        let (mut client, mut server) = pair().await;

        // Nothing to read yet.
        let mut buf = [0_u8; 64];
        assert_eq!(
            server.try_read(&mut buf).expect_err("empty").kind(),
            ErrorKind::WouldBlock
        );
        client.writable().await.expect("writable");
        assert_eq!(client.try_write(b"hello").expect("try_write"), 5);
        let mut received = Vec::new();
        while received.len() < 5 {
            server.readable().await.expect("readable");
            match server.try_read(&mut buf) {
                Ok(n) => received.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                Err(e) => panic!("try_read: {e}"),
            }
        }
        assert_eq!(received, b"hello");

        // Fill the send path until the kernel refuses more.
        let chunk = vec![7_u8; 64 * 1024];
        let mut sent = 0_usize;
        loop {
            match client.try_write(&chunk) {
                Ok(n) => sent += n,
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) => panic!("try_write: {e}"),
            }
        }
        assert!(sent > 0);

        // A reader drains it; `writable` resolves once there is room.
        let drain = handle.spawn(async move {
            let mut total = 0_usize;
            let mut buf = vec![0_u8; 64 * 1024];
            while total < sent + 3 {
                let n = server.read(&mut buf).await.expect("drain");
                assert!(n > 0, "the stream ended early");
                total += n;
            }
            total
        });
        let mut wrote_more = false;
        while !wrote_more {
            client.writable().await.expect("writable after drain");
            match client.try_write(b"end") {
                Ok(n) => {
                    assert_eq!(n, 3);
                    wrote_more = true;
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                Err(e) => panic!("try_write: {e}"),
            }
        }
        assert_eq!(drain.await, sent + 3);
    });
}

#[test]
fn linger_and_pending_error_options() {
    let runtime = RuntimeBuilder::current_thread().build().expect("runtime");
    runtime.block_on(async {
        let (client, _server) = pair().await;
        assert_eq!(client.linger().expect("linger"), None);
        client
            .set_linger(Some(Duration::from_secs(3)))
            .expect("set linger");
        assert_eq!(
            client.linger().expect("linger"),
            Some(Duration::from_secs(3))
        );
        assert!(client.take_error().expect("take_error").is_none());
    });
}
