//! HTTP/1 client regression tests.

#![allow(clippy::items_after_statements)]

#[macro_use]
mod common;

use asupersync::http::h1::{Http1Client, Method, Request, Version};
use asupersync::net::TcpStream;
use asupersync::time::timeout;
use asupersync::types::Time;
use common::*;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::{Duration, Instant};

/// Regression: `Http1Client::request` must flush encoded request bytes before waiting on a
/// response, otherwise the server never receives the request and both sides hang until timeout.
#[test]
fn http1_client_request_flushes_request_bytes() {
    init_test_logging();
    test_phase!("http1_client_request_flushes_request_bytes");

    let timeout_duration = Duration::from_secs(5);
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    listener
        .set_nonblocking(true)
        .expect("set_nonblocking listener");
    let addr = listener.local_addr().expect("listener local_addr");

    let server = thread::spawn(move || -> std::io::Result<Vec<u8>> {
        let deadline = Instant::now() + timeout_duration;
        let (mut conn, _peer) = loop {
            match listener.accept() {
                Ok(value) => break value,
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() > deadline {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "server accept timed out",
                        ));
                    }
                    thread::sleep(Duration::from_millis(5));
                }
                Err(err) => return Err(err),
            }
        };

        conn.set_read_timeout(Some(timeout_duration))?;
        conn.set_write_timeout(Some(timeout_duration))?;

        let mut buf = Vec::with_capacity(2048);
        let mut scratch = [0u8; 1024];
        loop {
            let n = conn.read(&mut scratch)?;
            if n == 0 {
                break;
            }

            buf.extend_from_slice(&scratch[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }

        conn.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")?;
        conn.flush()?;

        Ok(buf)
    });

    run_test(|| async move {
        let stream = TcpStream::connect(addr).await.expect("client connect");

        let req = Request {
            method: Method::Get,
            uri: "/".to_owned(),
            version: Version::Http11,
            headers: vec![("Host".to_owned(), addr.to_string())],
            body: Vec::new(),
            trailers: Vec::new(),
            peer_addr: None,
        };

        let fut = Box::pin(Http1Client::request(stream, req));
        let resp = timeout(Time::ZERO, timeout_duration, fut)
            .await
            .expect("client request timed out")
            .expect("client request errored");

        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"OK");
    });

    let raw = server
        .join()
        .expect("server thread panicked")
        .expect("server io error");
    let raw_str = String::from_utf8_lossy(&raw);

    assert!(
        raw_str.starts_with("GET / HTTP/1.1\r\n"),
        "expected request line, got: {raw_str:?}"
    );

    test_complete!("http1_client_request_flushes_request_bytes");
}
