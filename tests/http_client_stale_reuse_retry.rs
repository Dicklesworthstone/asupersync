//! Integration test for `HttpClient` transparent retry on an immediate-EOF from
//! a stale pooled (reused) connection
//! (br-asupersync-server-stack-hardening-eeexl1.4, AC5).
//!
//! The default `RetryPolicy::SafeMethodsOnStaleReuse` optimistically reuses a
//! keep-alive pooled connection and, when that reused connection turns out to
//! have been closed by the peer (the common keep-alive idle-close race),
//! transparently retries a safe method once on a fresh connection.
//!
//! Fixture: a raw-TCP server serves the first request with a keep-alive 200 (so
//! the client pools the connection), then **closes** that connection. The
//! second request reuses the now-dead pooled connection, observes the EOF, and
//! must succeed by retrying on a fresh connection. Without the transparent
//! retry the second request would surface the stale-connection error instead.
//!
//! Runs as a standalone integration crate (reliable proof lane; the lib
//! unit-test target stalls on the conformance dev-dep).
#![allow(clippy::items_after_statements)]

#[macro_use]
mod common;

use asupersync::Cx;
use asupersync::http::h1::HttpClient;
use common::*;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

const IO_TIMEOUT: Duration = Duration::from_secs(5);

fn accept_with_timeout(listener: &TcpListener, timeout: Duration) -> std::io::Result<TcpStream> {
    let deadline = Instant::now() + timeout;
    loop {
        match listener.accept() {
            Ok((conn, _peer)) => return Ok(conn),
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() > deadline {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "accept timed out",
                    ));
                }
                thread::sleep(Duration::from_millis(5));
            }
            Err(err) => return Err(err),
        }
    }
}

fn read_until_headers_end(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(1024);
    let mut scratch = [0u8; 256];
    loop {
        let n = stream.read(&mut scratch)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&scratch[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    Ok(buf)
}

#[test]
fn stale_pooled_connection_is_transparently_retried_on_fresh_connection() {
    init_test_logging();
    test_phase!("stale_pooled_connection_is_transparently_retried_on_fresh_connection");

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    listener
        .set_nonblocking(true)
        .expect("set_nonblocking listener");
    let addr = listener.local_addr().expect("listener local_addr");

    let server = thread::spawn(move || -> std::io::Result<usize> {
        // Connection 1: respond keep-alive (no `Connection: close`) so the
        // client returns it to the pool, then close it to make it stale.
        let mut c1 = accept_with_timeout(&listener, IO_TIMEOUT)?;
        c1.set_read_timeout(Some(IO_TIMEOUT))?;
        c1.set_write_timeout(Some(IO_TIMEOUT))?;
        let _ = read_until_headers_end(&mut c1)?;
        c1.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nFIRST")?;
        c1.flush()?;
        drop(c1); // close -> the pooled connection is now stale

        // Connection 2: the transparent retry on a fresh connection.
        let mut c2 = accept_with_timeout(&listener, IO_TIMEOUT)?;
        c2.set_read_timeout(Some(IO_TIMEOUT))?;
        c2.set_write_timeout(Some(IO_TIMEOUT))?;
        let _ = read_until_headers_end(&mut c2)?;
        c2.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nSECOND")?;
        c2.flush()?;

        Ok(2)
    });

    run_test(|| async move {
        let cx = Cx::for_testing();
        // Default client: RetryPolicy::SafeMethodsOnStaleReuse + connection pool.
        let client = HttpClient::new();
        let url = format!("http://{addr}/");

        let first = client
            .get(url.as_str())
            .send(&cx)
            .await
            .expect("first request should succeed and pool the connection");
        assert_eq!(first.status, 200);
        assert_eq!(first.body, b"FIRST");

        // The second request reuses the now-stale pooled connection, hits an
        // immediate EOF, and must transparently retry on a fresh connection.
        let second = client.get(url.as_str()).send(&cx).await.expect(
            "stale pooled connection must be transparently retried, not surfaced as an error",
        );
        assert_eq!(second.status, 200);
        assert_eq!(second.body, b"SECOND");
    });

    let connections_served = server
        .join()
        .expect("server thread panicked")
        .expect("server io error");
    assert_eq!(
        connections_served, 2,
        "server should serve the original connection plus the retried fresh connection"
    );

    test_complete!("stale_pooled_connection_is_transparently_retried_on_fresh_connection");
}
