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
use asupersync::bytes::Buf;
use asupersync::http::h1::HttpClient;
use asupersync::http::{Body, Frame};
use asupersync::types::Budget;
use common::*;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::pin::Pin;
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

fn request_method(raw: &[u8]) -> String {
    let text = String::from_utf8_lossy(raw);
    let first_line = text.lines().next().unwrap_or_default();
    first_line
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_owned()
}

fn spawn_status_retry_server(
    first_status: u16,
    first_reason: &'static str,
    first_retry_after: Option<&'static str>,
    final_body: &'static [u8],
    max_conns: usize,
) -> (SocketAddr, thread::JoinHandle<std::io::Result<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    listener
        .set_nonblocking(true)
        .expect("set_nonblocking listener");
    let addr = listener.local_addr().expect("listener local_addr");

    let handle = thread::spawn(move || -> std::io::Result<Vec<String>> {
        let mut methods = Vec::with_capacity(max_conns);
        for index in 0..max_conns {
            let mut conn = accept_with_timeout(&listener, IO_TIMEOUT)?;
            conn.set_read_timeout(Some(IO_TIMEOUT))?;
            conn.set_write_timeout(Some(IO_TIMEOUT))?;
            let raw = read_until_headers_end(&mut conn)?;
            methods.push(request_method(&raw));

            if index == 0 {
                write!(
                    conn,
                    "HTTP/1.1 {first_status} {first_reason}\r\nContent-Length: 0\r\nConnection: close\r\n"
                )?;
                if let Some(retry_after) = first_retry_after {
                    write!(conn, "Retry-After: {retry_after}\r\n")?;
                }
                conn.write_all(b"\r\n")?;
            } else {
                write!(
                    conn,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    final_body.len()
                )?;
                conn.write_all(final_body)?;
            }
            conn.flush()?;
        }
        Ok(methods)
    });

    (addr, handle)
}

fn spawn_json_once_server(
    body: &'static [u8],
) -> (SocketAddr, thread::JoinHandle<std::io::Result<String>>) {
    spawn_body_once_server("application/json", body)
}

fn spawn_body_once_server(
    content_type: &'static str,
    body: &'static [u8],
) -> (SocketAddr, thread::JoinHandle<std::io::Result<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    listener
        .set_nonblocking(true)
        .expect("set_nonblocking listener");
    let addr = listener.local_addr().expect("listener local_addr");

    let handle = thread::spawn(move || -> std::io::Result<String> {
        let mut conn = accept_with_timeout(&listener, IO_TIMEOUT)?;
        conn.set_read_timeout(Some(IO_TIMEOUT))?;
        conn.set_write_timeout(Some(IO_TIMEOUT))?;
        let raw = read_until_headers_end(&mut conn)?;
        write!(
            conn,
            "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )?;
        conn.write_all(body)?;
        conn.flush()?;
        Ok(request_method(&raw))
    });

    (addr, handle)
}

fn spawn_delayed_response_server(
    delay: Duration,
) -> (SocketAddr, thread::JoinHandle<std::io::Result<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    listener
        .set_nonblocking(true)
        .expect("set_nonblocking listener");
    let addr = listener.local_addr().expect("listener local_addr");

    let handle = thread::spawn(move || -> std::io::Result<String> {
        let mut conn = accept_with_timeout(&listener, IO_TIMEOUT)?;
        conn.set_read_timeout(Some(IO_TIMEOUT))?;
        conn.set_write_timeout(Some(IO_TIMEOUT))?;
        let raw = read_until_headers_end(&mut conn)?;
        thread::sleep(delay);
        let _ = conn
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nDONE");
        let _ = conn.flush();
        Ok(request_method(&raw))
    });

    (addr, handle)
}

fn read_optional_next_request(stream: &mut TcpStream) -> std::io::Result<Option<Vec<u8>>> {
    stream.set_read_timeout(Some(Duration::from_millis(750)))?;
    match read_until_headers_end(stream) {
        Ok(raw) if raw.is_empty() => Ok(None),
        Ok(raw) => Ok(Some(raw)),
        Err(err)
            if matches!(
                err.kind(),
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
            ) =>
        {
            Ok(None)
        }
        Err(err) => Err(err),
    }
}

fn read_reuse_or_close_after_stream_drop(
    stream: &mut TcpStream,
) -> std::io::Result<(bool, Option<Vec<u8>>)> {
    stream.set_read_timeout(Some(Duration::from_millis(750)))?;
    match read_until_headers_end(stream) {
        Ok(raw) if raw.is_empty() => Ok((true, None)),
        Ok(raw) => Ok((false, Some(raw))),
        Err(err)
            if matches!(
                err.kind(),
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
            ) =>
        {
            Ok((false, None))
        }
        Err(err) if err.kind() == std::io::ErrorKind::ConnectionReset => Ok((true, None)),
        Err(err) => Err(err),
    }
}

fn write_fixed_response(
    conn: &mut TcpStream,
    body: &'static [u8],
    close: bool,
) -> std::io::Result<()> {
    write!(
        conn,
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n",
        body.len()
    )?;
    if close {
        conn.write_all(b"Connection: close\r\n")?;
    }
    conn.write_all(b"\r\n")?;
    conn.write_all(body)?;
    conn.flush()
}

fn spawn_connection_reuse_probe_server() -> (SocketAddr, thread::JoinHandle<std::io::Result<usize>>)
{
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    listener
        .set_nonblocking(true)
        .expect("set_nonblocking listener");
    let addr = listener.local_addr().expect("listener local_addr");

    let handle = thread::spawn(move || -> std::io::Result<usize> {
        let mut first = accept_with_timeout(&listener, IO_TIMEOUT)?;
        first.set_read_timeout(Some(IO_TIMEOUT))?;
        first.set_write_timeout(Some(IO_TIMEOUT))?;
        let first_raw = read_until_headers_end(&mut first)?;
        assert_eq!(request_method(&first_raw), "GET");
        write_fixed_response(&mut first, b"FIRST", false)?;

        if let Some(second_raw) = read_optional_next_request(&mut first)? {
            assert_eq!(request_method(&second_raw), "GET");
            write_fixed_response(&mut first, b"SECOND", true)?;
            return Ok(1);
        }

        let mut second = accept_with_timeout(&listener, IO_TIMEOUT)?;
        second.set_read_timeout(Some(IO_TIMEOUT))?;
        second.set_write_timeout(Some(IO_TIMEOUT))?;
        let second_raw = read_until_headers_end(&mut second)?;
        assert_eq!(request_method(&second_raw), "GET");
        write_fixed_response(&mut second, b"SECOND", true)?;
        Ok(2)
    });

    (addr, handle)
}

fn spawn_streaming_drop_probe_server() -> (
    SocketAddr,
    thread::JoinHandle<std::io::Result<(bool, Vec<String>)>>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    listener
        .set_nonblocking(true)
        .expect("set_nonblocking listener");
    let addr = listener.local_addr().expect("listener local_addr");

    let handle = thread::spawn(move || -> std::io::Result<(bool, Vec<String>)> {
        let mut methods = Vec::with_capacity(2);

        let mut first = accept_with_timeout(&listener, IO_TIMEOUT)?;
        first.set_read_timeout(Some(IO_TIMEOUT))?;
        first.set_write_timeout(Some(IO_TIMEOUT))?;
        let first_raw = read_until_headers_end(&mut first)?;
        methods.push(request_method(&first_raw));
        first.write_all(
            b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\nConnection: keep-alive\r\n\r\nHELLO",
        )?;
        first.flush()?;

        let (first_closed, maybe_reused_request) =
            read_reuse_or_close_after_stream_drop(&mut first)?;
        if let Some(raw) = maybe_reused_request {
            methods.push(request_method(&raw));
            write_fixed_response(&mut first, b"FRESH", true)?;
            return Ok((first_closed, methods));
        }

        let mut second = accept_with_timeout(&listener, IO_TIMEOUT)?;
        second.set_read_timeout(Some(IO_TIMEOUT))?;
        second.set_write_timeout(Some(IO_TIMEOUT))?;
        let second_raw = read_until_headers_end(&mut second)?;
        methods.push(request_method(&second_raw));
        write_fixed_response(&mut second, b"FRESH", true)?;

        Ok((first_closed, methods))
    });

    (addr, handle)
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

#[test]
fn fluent_get_to_json_round_trip_uses_explicit_cx() {
    init_test_logging();
    test_phase!("fluent_get_to_json_round_trip_uses_explicit_cx");

    let (addr, server) = spawn_json_once_server(br#"{"ok":true,"name":"asupersync"}"#);

    run_test(|| async move {
        let cx = Cx::for_testing();
        let client = HttpClient::new();
        let url = format!("http://{addr}/user");

        let user: serde_json::Value = client
            .get(url.as_str())
            .send(&cx)
            .await
            .expect("GET should complete")
            .json()
            .expect("response body should decode as JSON");

        assert_eq!(user["ok"], true);
        assert_eq!(user["name"], "asupersync");
    });

    let method = server
        .join()
        .expect("server thread panicked")
        .expect("server io error");
    assert_eq!(method, "GET");

    test_complete!("fluent_get_to_json_round_trip_uses_explicit_cx");
}

#[test]
fn fluent_response_text_and_bytes_helpers_read_same_body() {
    init_test_logging();
    test_phase!("fluent_response_text_and_bytes_helpers_read_same_body");

    let body = b"hello from asupersync";
    let (addr, server) = spawn_body_once_server("text/plain; charset=utf-8", body);

    run_test(|| async move {
        let cx = Cx::for_testing();
        let client = HttpClient::new();
        let url = format!("http://{addr}/message");

        let response = client
            .get(url.as_str())
            .send(&cx)
            .await
            .expect("GET should complete");

        assert_eq!(
            response.text().expect("response body is UTF-8"),
            "hello from asupersync"
        );
        assert_eq!(response.bytes(), body);
    });

    let method = server
        .join()
        .expect("server thread panicked")
        .expect("server io error");
    assert_eq!(method, "GET");

    test_complete!("fluent_response_text_and_bytes_helpers_read_same_body");
}

#[test]
fn retry_policy_retries_idempotent_status_after_retry_after_zero() {
    init_test_logging();
    test_phase!("retry_policy_retries_idempotent_status_after_retry_after_zero");

    let (addr, server) =
        spawn_status_retry_server(503, "Service Unavailable", Some("0"), b"READY", 2);

    run_test(|| async move {
        let cx = Cx::for_testing();
        let client = HttpClient::builder().retry_idempotent_statuses(1).build();
        let url = format!("http://{addr}/resource");

        let response = client
            .get(url.as_str())
            .send(&cx)
            .await
            .expect("idempotent GET should retry 503 once and succeed");

        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"READY");
    });

    let methods = server
        .join()
        .expect("server thread panicked")
        .expect("server io error");
    assert_eq!(methods, vec!["GET".to_owned(), "GET".to_owned()]);

    test_complete!("retry_policy_retries_idempotent_status_after_retry_after_zero");
}

#[test]
fn retry_policy_does_not_retry_non_idempotent_post_status() {
    init_test_logging();
    test_phase!("retry_policy_does_not_retry_non_idempotent_post_status");

    let (addr, server) =
        spawn_status_retry_server(503, "Service Unavailable", Some("0"), b"UNUSED", 1);

    run_test(|| async move {
        let cx = Cx::for_testing();
        let client = HttpClient::builder().retry_idempotent_statuses(1).build();
        let url = format!("http://{addr}/mutate");

        let response = client
            .post(url.as_str())
            .body(b"create".to_vec())
            .send(&cx)
            .await
            .expect("POST should return the 503 response without retrying");

        assert_eq!(response.status, 503);
    });

    let methods = server
        .join()
        .expect("server thread panicked")
        .expect("server io error");
    assert_eq!(methods, vec!["POST".to_owned()]);

    test_complete!("retry_policy_does_not_retry_non_idempotent_post_status");
}

#[test]
fn fluent_timeout_cannot_extend_ambient_budget() {
    init_test_logging();
    test_phase!("fluent_timeout_cannot_extend_ambient_budget");

    let (addr, server) = spawn_delayed_response_server(Duration::from_millis(500));
    let started = Instant::now();

    run_test(|| async move {
        let budget = Budget::INFINITE
            .tightened_by_timeout(asupersync::time::wall_now(), Duration::from_millis(50));
        let cx = Cx::for_request_with_budget(budget);
        let client = HttpClient::new();
        let url = format!("http://{addr}/slow");

        let err = client
            .get(url.as_str())
            .timeout(Duration::from_secs(5))
            .send(&cx)
            .await
            .expect_err("ambient Cx budget must beat the larger per-call timeout");

        assert!(matches!(
            err,
            asupersync::http::h1::ClientError::DeadlineExceeded
        ));
    });

    assert!(
        started.elapsed() < Duration::from_secs(2),
        "fluent per-call timeout extended past the ambient budget"
    );

    let method = server
        .join()
        .expect("server thread panicked")
        .expect("server io error");
    assert_eq!(method, "GET");

    test_complete!("fluent_timeout_cannot_extend_ambient_budget");
}

#[test]
fn cloned_client_handles_share_connection_pool() {
    init_test_logging();
    test_phase!("cloned_client_handles_share_connection_pool");

    let (addr, server) = spawn_connection_reuse_probe_server();

    run_test(|| async move {
        let cx = Cx::for_testing();
        let client = HttpClient::builder()
            .max_connections_per_host(1)
            .max_total_connections(1)
            .build();
        let cloned = client.clone();
        let url = format!("http://{addr}/shared");

        let first = cloned
            .get(url.as_str())
            .send(&cx)
            .await
            .expect("first cloned-handle request should succeed");
        assert_eq!(first.body, b"FIRST");

        let second = client
            .get(url.as_str())
            .send(&cx)
            .await
            .expect("second original-handle request should reuse shared pool");
        assert_eq!(second.body, b"SECOND");
    });

    let connections_seen = server
        .join()
        .expect("server thread panicked")
        .expect("server io error");
    assert_eq!(
        connections_seen, 1,
        "cloned HttpClient handles must share idle pooled connections"
    );

    test_complete!("cloned_client_handles_share_connection_pool");
}

#[test]
fn dropping_streaming_response_mid_body_closes_connection_before_next_request() {
    init_test_logging();
    test_phase!("dropping_streaming_response_mid_body_closes_connection_before_next_request");

    let (addr, server) = spawn_streaming_drop_probe_server();

    run_test(|| async move {
        let cx = Cx::for_testing();
        let client = HttpClient::builder()
            .max_connections_per_host(1)
            .max_total_connections(1)
            .build();
        let url = format!("http://{addr}/stream");

        let mut streaming = client
            .request_streaming(
                &cx,
                asupersync::http::h1::Method::Get,
                url.as_str(),
                Vec::new(),
                Vec::new(),
            )
            .await
            .expect("streaming request should produce response head");
        assert_eq!(streaming.head.status, 200);

        let first_frame =
            std::future::poll_fn(|task_cx| Pin::new(&mut streaming.body).poll_frame(task_cx))
                .await
                .expect("streaming body should yield first frame")
                .expect("first body frame should parse");
        let mut chunk = match first_frame {
            Frame::Data(chunk) => chunk,
            Frame::Trailers(_) => panic!("first streaming frame should be data"),
        };
        let mut first_chunk = Vec::new();
        while chunk.has_remaining() {
            let bytes = chunk.chunk();
            first_chunk.extend_from_slice(bytes);
            chunk.advance(bytes.len());
        }
        assert_eq!(first_chunk, b"HELLO");

        drop(streaming);
        assert_eq!(
            client.pool_stats().idle_connections,
            0,
            "undrained streaming responses must not be returned to the idle pool"
        );

        let follow_up = client
            .get(url.as_str())
            .send(&cx)
            .await
            .expect("follow-up request should use a fresh connection");
        assert_eq!(follow_up.status, 200);
        assert_eq!(follow_up.body, b"FRESH");
    });

    let (first_closed, methods) = server
        .join()
        .expect("server thread panicked")
        .expect("server io error");
    assert!(
        first_closed,
        "dropping the undrained streaming body must close the first connection before reuse"
    );
    assert_eq!(methods, vec!["GET".to_owned(), "GET".to_owned()]);

    test_complete!("dropping_streaming_response_mid_body_closes_connection_before_next_request");
}
