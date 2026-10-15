//! `io::duplex`: an in-memory byte pipe with socket-like backpressure and
//! half-close. A megabyte crosses a 64-byte buffer between tasks on different
//! workers; shutdown and drop end the peer's reads with EOF and its writes
//! with `BrokenPipe`, waking a peer that was already waiting; and an HTTP/1
//! client and server exchange a request over a pair.

use asupersync::http::h1::client::Http1Client;
use asupersync::http::h1::server::{HostPolicy, Http1Config, Http1Server};
use asupersync::http::h1::types::{Request, Response};
use asupersync::io::{AsyncReadExt, AsyncWriteExt, duplex, split_owned};
use asupersync::runtime::{RuntimeBuilder, yield_now};
use std::io::ErrorKind;

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 31 % 251) as u8).collect()
}

#[test]
fn a_megabyte_crosses_a_small_buffer_in_both_directions() {
    let runtime = RuntimeBuilder::new()
        .worker_threads(4)
        .build()
        .expect("runtime");
    let handle = runtime.handle();
    runtime.block_on(async move {
        let ends: [_; 2] = duplex(64).into();
        let sent = pattern(1 << 20);

        // Each end writes the pattern and reads the other's, concurrently,
        // so both directions are full at once.
        let mut writers = Vec::new();
        let mut readers = Vec::new();
        for end in ends {
            let (mut reader, mut writer) = split_owned(end);
            let data = sent.clone();
            writers.push(handle.spawn(async move {
                writer.write_all(&data).await.expect("write");
                writer.shutdown().await.expect("shutdown");
            }));
            readers.push(handle.spawn(async move {
                let mut received = Vec::new();
                reader.read_to_end(&mut received).await.expect("read");
                received
            }));
        }
        for writer in writers {
            writer.await;
        }
        for reader in readers {
            assert!(reader.await == sent, "the bytes arrive intact and in order");
        }
    });
}

#[test]
fn shutdown_and_drop_end_the_peer_like_a_socket() {
    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("runtime");
    let handle = runtime.handle();
    runtime.block_on(async move {
        // Half-close: the peer drains the buffer, sees EOF, and can still
        // answer.
        let (mut client, mut server) = duplex(16);
        client.write_all(b"request").await.expect("write");
        client.shutdown().await.expect("shutdown");
        assert_eq!(
            client
                .write_all(b"more")
                .await
                .expect_err("write after shutdown")
                .kind(),
            ErrorKind::BrokenPipe
        );
        let mut request = Vec::new();
        server.read_to_end(&mut request).await.expect("read");
        assert_eq!(request, b"request");
        server.write_all(b"answer").await.expect("answer");
        drop(server);
        let mut answer = Vec::new();
        client.read_to_end(&mut answer).await.expect("read answer");
        assert_eq!(answer, b"answer");

        // A reader already waiting is woken by the peer's drop, with EOF.
        let (mut waiting, peer) = duplex(16);
        let reader = handle.spawn(async move {
            let mut buf = [0_u8; 8];
            waiting.read(&mut buf).await.expect("read")
        });
        for _ in 0..10 {
            yield_now().await;
        }
        drop(peer);
        assert_eq!(reader.await, 0);

        // A writer already waiting on a full buffer is woken by the peer's
        // drop, with BrokenPipe.
        let (mut writer, peer) = duplex(4);
        let blocked = handle.spawn(async move { writer.write_all(b"0123456789").await });
        for _ in 0..10 {
            yield_now().await;
        }
        drop(peer);
        assert_eq!(
            blocked.await.expect_err("peer dropped").kind(),
            ErrorKind::BrokenPipe
        );
    });
}

#[test]
fn an_http1_client_and_server_talk_over_a_duplex_pair() {
    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("runtime");
    let handle = runtime.handle();
    runtime.block_on(async move {
        let (client_end, server_end) = duplex(1024);
        let server = Http1Server::with_config(
            |request: Request| async move {
                Response::new(200, "OK", format!("echo {}", request.uri).into_bytes())
            },
            Http1Config {
                allowed_hosts: HostPolicy::allow_list(vec!["localhost".to_owned()]),
                ..Http1Config::default()
            },
        );
        let serving = handle.spawn(async move { server.serve(server_end).await });

        let request = Request::get("/in-memory")
            .header("Host", "localhost")
            .header("Connection", "close")
            .build();
        let response = Http1Client::request(client_end, request)
            .await
            .expect("response");
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"echo /in-memory");
        serving.await.expect("server finished the connection");
    });
}
