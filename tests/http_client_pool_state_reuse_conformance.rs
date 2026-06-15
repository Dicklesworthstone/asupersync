//! Connection-pool state conformance for the `HttpClient` fluent surface —
//! br-asupersync-server-stack-hardening-eeexl1.4, AC3: "connection
//! returned-or-closed correctly (pool-state asserted)".
//!
//! The existing `tests/http_client_stale_reuse_retry.rs` pins the *negative*
//! pool-state case — dropping a streaming response mid-body leaves
//! `pool_stats().idle_connections == 0` (the undrained connection is NOT
//! returned) — and proves keep-alive reuse at the *wire* level (the fixture
//! counts one accepted TCP connection). These tests pin the complementary
//! halves through the public `HttpClient::pool_stats()` introspection:
//!
//! - keep-alive: a fully-consumed non-streaming response is **returned** to the
//!   idle pool (`idle_connections == 1`, `in_use == 0`), and the next request
//!   **reuses** it — `connections_created` stays `1` (no second dial), which the
//!   wire connection count corroborates;
//! - `Connection: close`: the response connection is **closed**, not pooled
//!   (`idle_connections == 0`, `total_connections == 0`), so a follow-up request
//!   dials a fresh connection (`connections_created == 2`).
//!
//! Together they assert AC3's "returned-or-closed correctly" through the
//! client's own accounting, not just observed wire behavior. Standalone crate
//! (mirrors the sibling http_client conformance tests). Requires
//! `--features test-internals` for `Cx::for_testing()`.

use asupersync::Cx;
use asupersync::http::h1::HttpClient;
use asupersync::runtime::RuntimeBuilder;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Drive an async body on a lightweight current-thread runtime.
fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    RuntimeBuilder::current_thread()
        .build()
        .expect("build current-thread runtime")
        .block_on(fut)
}

/// Accept one connection from a non-blocking listener, polling until `timeout`.
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

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Read a request head up to and including the terminating `\r\n\r\n`. (All
/// fixture requests here are bodyless GETs.)
fn read_request_head(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(256);
    let mut scratch = [0u8; 512];
    loop {
        if find_subslice(&buf, b"\r\n\r\n").is_some() {
            return Ok(buf);
        }
        let n = stream.read(&mut scratch)?;
        if n == 0 {
            return Ok(buf);
        }
        buf.extend_from_slice(&scratch[..n]);
    }
}

/// Try to read a second request on the same (reused) connection. Returns `None`
/// if the peer closed the connection or no request arrives before the timeout —
/// i.e. the connection was NOT reused.
fn read_optional_next_request(stream: &mut TcpStream) -> std::io::Result<Option<Vec<u8>>> {
    let mut buf = Vec::with_capacity(256);
    let mut scratch = [0u8; 512];
    loop {
        if find_subslice(&buf, b"\r\n\r\n").is_some() {
            return Ok(Some(buf));
        }
        match stream.read(&mut scratch) {
            Ok(0) => return Ok(None),
            Ok(n) => buf.extend_from_slice(&scratch[..n]),
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                return Ok(None);
            }
            Err(err) => return Err(err),
        }
    }
}

fn request_method(raw: &[u8]) -> String {
    let text = String::from_utf8_lossy(raw);
    text.split_whitespace()
        .next()
        .unwrap_or_default()
        .to_owned()
}

/// Write a fixed-length `200 OK`. `keep_alive` selects the `Connection` header,
/// which is what tells the client whether the connection may be pooled.
fn write_fixed_response(
    stream: &mut TcpStream,
    body: &[u8],
    keep_alive: bool,
) -> std::io::Result<()> {
    let connection = if keep_alive { "keep-alive" } else { "close" };
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: {connection}\r\n\r\n",
        body.len()
    )?;
    stream.write_all(body)?;
    stream.flush()
}

/// Serve two keep-alive GETs. If the client reuses the connection, both arrive
/// on the first socket and the server accepts exactly one connection (`Ok(1)`);
/// otherwise it accepts a second (`Ok(2)`), which would mean reuse failed.
fn spawn_keepalive_reuse_server() -> (SocketAddr, thread::JoinHandle<std::io::Result<usize>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    listener
        .set_nonblocking(true)
        .expect("set_nonblocking listener");
    let addr = listener.local_addr().expect("listener local_addr");

    let handle = thread::spawn(move || -> std::io::Result<usize> {
        let mut first = accept_with_timeout(&listener, IO_TIMEOUT)?;
        first.set_nonblocking(false)?;
        first.set_read_timeout(Some(IO_TIMEOUT))?;
        first.set_write_timeout(Some(IO_TIMEOUT))?;
        let head = read_request_head(&mut first)?;
        assert_eq!(request_method(&head), "GET");
        write_fixed_response(&mut first, b"FIRST", true)?;

        if let Some(second) = read_optional_next_request(&mut first)? {
            assert_eq!(request_method(&second), "GET");
            write_fixed_response(&mut first, b"SECOND", true)?;
            return Ok(1);
        }

        // Reuse failed: the client opened a fresh connection.
        let mut second = accept_with_timeout(&listener, IO_TIMEOUT)?;
        second.set_nonblocking(false)?;
        second.set_read_timeout(Some(IO_TIMEOUT))?;
        second.set_write_timeout(Some(IO_TIMEOUT))?;
        let second_head = read_request_head(&mut second)?;
        assert_eq!(request_method(&second_head), "GET");
        write_fixed_response(&mut second, b"SECOND", true)?;
        Ok(2)
    });

    (addr, handle)
}

/// Serve two GETs, each on its own connection closed via `Connection: close`.
/// A client that honors `close` cannot pool the first connection, so the second
/// request must dial again — the server accepts exactly two connections.
fn spawn_close_each_request_server() -> (SocketAddr, thread::JoinHandle<std::io::Result<usize>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    listener
        .set_nonblocking(true)
        .expect("set_nonblocking listener");
    let addr = listener.local_addr().expect("listener local_addr");

    let handle = thread::spawn(move || -> std::io::Result<usize> {
        for body in [b"FIRST".as_slice(), b"SECOND".as_slice()] {
            let mut conn = accept_with_timeout(&listener, IO_TIMEOUT)?;
            conn.set_nonblocking(false)?;
            conn.set_read_timeout(Some(IO_TIMEOUT))?;
            conn.set_write_timeout(Some(IO_TIMEOUT))?;
            let head = read_request_head(&mut conn)?;
            assert_eq!(request_method(&head), "GET");
            write_fixed_response(&mut conn, body, false)?;
            // Drop `conn` -> close the socket, mirroring `Connection: close`.
        }
        Ok(2)
    });

    (addr, handle)
}

/// AC3 (returned): a fully-consumed keep-alive response returns its connection
/// to the idle pool, and the next request reuses it without dialing again.
#[test]
fn keepalive_response_returns_connection_to_pool_and_is_reused() {
    let (addr, server) = spawn_keepalive_reuse_server();

    block_on(async move {
        let cx = Cx::for_testing();
        // Cap to one connection so reuse is the only way the second request can
        // proceed without dialing.
        let client = HttpClient::builder()
            .max_connections_per_host(1)
            .max_total_connections(1)
            .build();
        let url = format!("http://{addr}/reuse");

        let fresh = client.pool_stats();
        assert_eq!(
            fresh.total_connections, 0,
            "fresh client has no connections"
        );
        assert_eq!(fresh.connections_created, 0);

        let first = client
            .get(url.as_str())
            .send(&cx)
            .await
            .expect("first request should succeed");
        assert_eq!(first.status, 200);
        assert_eq!(first.body, b"FIRST");

        // RETURNED: the drained keep-alive connection is back in the idle pool.
        let after_first = client.pool_stats();
        assert_eq!(
            after_first.idle_connections, 1,
            "a fully-consumed keep-alive response must return its connection to the idle pool"
        );
        assert_eq!(after_first.in_use_connections, 0);
        assert_eq!(after_first.total_connections, 1);
        assert_eq!(
            after_first.connections_created, 1,
            "exactly one connection dialed so far"
        );

        let second = client
            .get(url.as_str())
            .send(&cx)
            .await
            .expect("second request should reuse the idle connection");
        assert_eq!(second.status, 200);
        assert_eq!(second.body, b"SECOND");

        // REUSED: still one pooled connection, and NO new dial occurred.
        let after_second = client.pool_stats();
        assert_eq!(after_second.idle_connections, 1);
        assert_eq!(after_second.total_connections, 1);
        assert_eq!(
            after_second.connections_created, 1,
            "reusing the idle connection must NOT dial a second connection"
        );
    });

    let connections_seen = server
        .join()
        .expect("server thread panicked")
        .expect("server io error");
    assert_eq!(
        connections_seen, 1,
        "keep-alive reuse must serve both requests over one wire connection"
    );
}

/// AC3 (closed): a `Connection: close` response is not pooled, so the idle pool
/// stays empty and a follow-up request dials a fresh connection.
#[test]
fn connection_close_response_is_not_pooled_and_forces_fresh_dial() {
    let (addr, server) = spawn_close_each_request_server();

    block_on(async move {
        let cx = Cx::for_testing();
        let client = HttpClient::builder()
            .max_connections_per_host(1)
            .max_total_connections(1)
            .build();
        let url = format!("http://{addr}/close");

        let first = client
            .get(url.as_str())
            .send(&cx)
            .await
            .expect("first request should succeed");
        assert_eq!(first.status, 200);
        assert_eq!(first.body, b"FIRST");

        // CLOSED: the server asked to close, so nothing is pooled.
        let after_first = client.pool_stats();
        assert_eq!(
            after_first.idle_connections, 0,
            "a Connection: close response must NOT be returned to the idle pool"
        );
        assert_eq!(
            after_first.total_connections, 0,
            "the closed connection must not linger in the pool"
        );
        assert_eq!(after_first.connections_created, 1);

        let second = client
            .get(url.as_str())
            .send(&cx)
            .await
            .expect("second request should dial a fresh connection");
        assert_eq!(second.status, 200);
        assert_eq!(second.body, b"SECOND");

        // A second dial was required precisely because nothing was pooled.
        let after_second = client.pool_stats();
        assert_eq!(
            after_second.connections_created, 2,
            "a fresh connection must be dialed when none could be pooled"
        );
    });

    let connections_seen = server
        .join()
        .expect("server thread panicked")
        .expect("server io error");
    assert_eq!(
        connections_seen, 2,
        "two Connection: close requests must use two distinct wire connections"
    );
}
