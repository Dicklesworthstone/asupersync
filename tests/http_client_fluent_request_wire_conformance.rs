//! End-to-end wire-correctness conformance for the `HttpClient` fluent request
//! builder (br-asupersync-server-stack-hardening-eeexl1.4, AC1 — "GET-to-JSON in
//! <=5 lines"; the convenience surface that makes ad-hoc requests ergonomic).
//!
//! The in-module unit tests in `src/http/h1/http_client.rs`
//! (`client_request_builder_*`) verify that the fluent builder *collects* its
//! options into private fields (url/headers/body). These integration tests pin
//! the complementary, previously-unproven half: that `.send()` actually
//! serialises those options onto the wire so a real loopback server *receives*
//! them byte-for-byte — the percent-encoded query string in the request target,
//! the JSON/form body plus its `Content-Type` and encoder-supplied
//! `Content-Length`, and the `Authorization` headers.
//!
//! Drives the high-level async `HttpClient` (fluent `get()/post().send()`)
//! against a raw in-process TCP fixture that captures the full request (head +
//! body), mirroring the fixture-server pattern in
//! `tests/http_client_redirect_policy.rs`. Runs as a standalone integration
//! crate so the proof lane is reliable.
#![allow(clippy::items_after_statements)]

#[macro_use]
mod common;

use asupersync::Cx;
use asupersync::http::h1::HttpClient;
use common::*;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
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

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Parse the (case-insensitive) `Content-Length` value from a raw header block,
/// defaulting to 0 when absent — matching how the client encoder delimits a
/// fixed-length request body.
fn parse_content_length(head: &[u8]) -> usize {
    let text = String::from_utf8_lossy(head);
    text.split("\r\n")
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.trim().eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.trim().parse().ok())
        .unwrap_or(0)
}

/// Read a complete HTTP/1.1 request: the head up to `\r\n\r\n`, then exactly
/// `Content-Length` body bytes. Returns the raw request as observed on the wire.
fn read_full_request(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(1024);
    let mut scratch = [0u8; 256];

    let header_end = loop {
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            break pos + 4;
        }
        let n = stream.read(&mut scratch)?;
        if n == 0 {
            return Ok(buf);
        }
        buf.extend_from_slice(&scratch[..n]);
    };

    let target = header_end + parse_content_length(&buf[..header_end]);
    while buf.len() < target {
        let n = stream.read(&mut scratch)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&scratch[..n]);
    }
    Ok(buf)
}

/// Spawn a fixture that serves exactly one request with `200 OK` and returns the
/// raw request bytes (head + body) it captured.
fn spawn_capture_server() -> (SocketAddr, thread::JoinHandle<std::io::Result<Vec<u8>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    listener
        .set_nonblocking(true)
        .expect("set_nonblocking listener");
    let addr = listener.local_addr().expect("listener local_addr");

    let handle = thread::spawn(move || -> std::io::Result<Vec<u8>> {
        let mut conn = accept_with_timeout(&listener, IO_TIMEOUT)?;
        conn.set_read_timeout(Some(IO_TIMEOUT))?;
        conn.set_write_timeout(Some(IO_TIMEOUT))?;
        let raw = read_full_request(&mut conn)?;
        conn.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")?;
        conn.flush()?;
        Ok(raw)
    });

    (addr, handle)
}

/// Extract the request-target (second token of the request line). Works for both
/// origin-form (`/p?q`) and absolute-form (`http://h/p?q`).
fn request_target(raw: &[u8]) -> String {
    let text = String::from_utf8_lossy(raw);
    let first_line = text.lines().next().unwrap_or_default();
    first_line
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .to_owned()
}

/// The header block (everything before the body), as text.
fn head_text(raw: &[u8]) -> String {
    let text = String::from_utf8_lossy(raw);
    text.split("\r\n\r\n").next().unwrap_or_default().to_owned()
}

/// The request body bytes (everything after the first `\r\n\r\n`).
fn body_bytes(raw: &[u8]) -> Vec<u8> {
    find_subslice(raw, b"\r\n\r\n").map_or_else(Vec::new, |pos| raw[pos + 4..].to_vec())
}

/// True iff some header line has the given (case-insensitive) name and exactly
/// the given trimmed value.
fn header_present(head: &str, name: &str, value: &str) -> bool {
    head.split("\r\n").any(|line| {
        line.split_once(':')
            .is_some_and(|(n, v)| n.trim().eq_ignore_ascii_case(name) && v.trim() == value)
    })
}

#[test]
fn query_params_reach_server_percent_encoded() {
    init_test_logging();
    test_phase!("query_params_reach_server_percent_encoded");

    let (addr, server) = spawn_capture_server();

    run_test(|| async move {
        let cx = Cx::for_testing();
        let client = HttpClient::new();
        let url = format!("http://{addr}/search");

        let resp = client
            .get(url.as_str())
            .query([("q", "rust async"), ("tag", "a+b")])
            .send(&cx)
            .await
            .expect("request should succeed");

        assert_eq!(resp.status, 200);
    });

    let raw = server
        .join()
        .expect("server thread panicked")
        .expect("server io error");
    let target = request_target(&raw);
    assert!(
        target.ends_with("/search?q=rust%20async&tag=a%2Bb"),
        "fluent query() must reach the server percent-encoded; got target `{target}`"
    );

    test_complete!("query_params_reach_server_percent_encoded");
}

#[test]
fn bearer_auth_header_reaches_server() {
    init_test_logging();
    test_phase!("bearer_auth_header_reaches_server");

    let (addr, server) = spawn_capture_server();

    run_test(|| async move {
        let cx = Cx::for_testing();
        let client = HttpClient::new();
        let url = format!("http://{addr}/secure");

        let resp = client
            .get(url.as_str())
            .bearer_auth("token-xyz")
            .send(&cx)
            .await
            .expect("request should succeed");

        assert_eq!(resp.status, 200);
    });

    let raw = server
        .join()
        .expect("server thread panicked")
        .expect("server io error");
    let head = head_text(&raw);
    assert!(
        header_present(&head, "Authorization", "Bearer token-xyz"),
        "bearer_auth() must emit `Authorization: Bearer token-xyz`; head was:\n{head}"
    );

    test_complete!("bearer_auth_header_reaches_server");
}

#[test]
fn basic_auth_with_password_reaches_server() {
    init_test_logging();
    test_phase!("basic_auth_with_password_reaches_server");

    let (addr, server) = spawn_capture_server();

    run_test(|| async move {
        let cx = Cx::for_testing();
        let client = HttpClient::new();
        let url = format!("http://{addr}/secure");

        let resp = client
            .get(url.as_str())
            .basic_auth("user", Some("pass"))
            .send(&cx)
            .await
            .expect("request should succeed");

        assert_eq!(resp.status, 200);
    });

    let raw = server
        .join()
        .expect("server thread panicked")
        .expect("server io error");
    let head = head_text(&raw);
    // base64("user:pass") == "dXNlcjpwYXNz"
    assert!(
        header_present(&head, "Authorization", "Basic dXNlcjpwYXNz"),
        "basic_auth(user, Some(pass)) must emit base64(user:pass); head was:\n{head}"
    );

    test_complete!("basic_auth_with_password_reaches_server");
}

#[test]
fn basic_auth_without_password_reaches_server() {
    init_test_logging();
    test_phase!("basic_auth_without_password_reaches_server");

    let (addr, server) = spawn_capture_server();

    run_test(|| async move {
        let cx = Cx::for_testing();
        let client = HttpClient::new();
        let url = format!("http://{addr}/secure");

        let resp = client
            .get(url.as_str())
            .basic_auth("user", None)
            .send(&cx)
            .await
            .expect("request should succeed");

        assert_eq!(resp.status, 200);
    });

    let raw = server
        .join()
        .expect("server thread panicked")
        .expect("server io error");
    let head = head_text(&raw);
    // base64("user:") == "dXNlcjo=" — a None password still appends the `:`.
    assert!(
        header_present(&head, "Authorization", "Basic dXNlcjo="),
        "basic_auth(user, None) must emit base64(user:); head was:\n{head}"
    );

    test_complete!("basic_auth_without_password_reaches_server");
}

#[test]
fn json_body_and_content_type_reach_server() {
    init_test_logging();
    test_phase!("json_body_and_content_type_reach_server");

    // `[1, 2, 3]` is `serde::Serialize` (transitively) and serialises to the
    // compact `[1,2,3]` with no whitespace.
    let expected_body = b"[1,2,3]".to_vec();
    let (addr, server) = spawn_capture_server();

    run_test(|| async move {
        let cx = Cx::for_testing();
        let client = HttpClient::new();
        let url = format!("http://{addr}/ingest");

        let resp = client
            .post(url.as_str())
            .json(&[1, 2, 3])
            .expect("json body should serialize")
            .send(&cx)
            .await
            .expect("request should succeed");

        assert_eq!(resp.status, 200);
    });

    let raw = server
        .join()
        .expect("server thread panicked")
        .expect("server io error");
    let head = head_text(&raw);
    assert!(
        header_present(&head, "Content-Type", "application/json"),
        "json() must emit `Content-Type: application/json`; head was:\n{head}"
    );
    assert!(
        header_present(&head, "Content-Length", &expected_body.len().to_string()),
        "encoder must delimit the JSON body with Content-Length; head was:\n{head}"
    );
    assert_eq!(
        body_bytes(&raw),
        expected_body,
        "the serialised JSON body must reach the server byte-for-byte"
    );

    test_complete!("json_body_and_content_type_reach_server");
}

#[test]
fn form_body_and_content_type_reach_server() {
    init_test_logging();
    test_phase!("form_body_and_content_type_reach_server");

    let expected_body = b"name=Ada%20Lovelace&role=math%2Bruntime".to_vec();
    let (addr, server) = spawn_capture_server();

    run_test(|| async move {
        let cx = Cx::for_testing();
        let client = HttpClient::new();
        let url = format!("http://{addr}/form");

        let resp = client
            .post(url.as_str())
            .form([("name", "Ada Lovelace"), ("role", "math+runtime")])
            .send(&cx)
            .await
            .expect("request should succeed");

        assert_eq!(resp.status, 200);
    });

    let raw = server
        .join()
        .expect("server thread panicked")
        .expect("server io error");
    let head = head_text(&raw);
    assert!(
        header_present(&head, "Content-Type", "application/x-www-form-urlencoded"),
        "form() must emit `Content-Type: application/x-www-form-urlencoded`; head was:\n{head}"
    );
    assert_eq!(
        body_bytes(&raw),
        expected_body,
        "the percent-encoded form body must reach the server byte-for-byte"
    );

    test_complete!("form_body_and_content_type_reach_server");
}

#[test]
fn accept_and_custom_header_reach_server() {
    init_test_logging();
    test_phase!("accept_and_custom_header_reach_server");

    let (addr, server) = spawn_capture_server();

    run_test(|| async move {
        let cx = Cx::for_testing();
        let client = HttpClient::new();
        let url = format!("http://{addr}/items");

        let resp = client
            .get(url.as_str())
            .accept("application/json")
            .header("X-Trace-Id", "trace-9")
            .send(&cx)
            .await
            .expect("request should succeed");

        assert_eq!(resp.status, 200);
    });

    let raw = server
        .join()
        .expect("server thread panicked")
        .expect("server io error");
    let head = head_text(&raw);
    assert!(
        header_present(&head, "Accept", "application/json"),
        "accept() must emit `Accept: application/json`; head was:\n{head}"
    );
    assert!(
        header_present(&head, "X-Trace-Id", "trace-9"),
        "header() must forward a custom header verbatim; head was:\n{head}"
    );

    test_complete!("accept_and_custom_header_reach_server");
}
