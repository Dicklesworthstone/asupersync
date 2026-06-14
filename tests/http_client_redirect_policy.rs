//! Integration tests for `HttpClient` redirect handling (br-asupersync-server-stack-hardening-eeexl1.4,
//! AC4 — RedirectPolicy matrix).
//!
//! Drives the high-level async `HttpClient` (fluent `get().send()`) against a
//! raw in-process TCP fixture that issues `302 Found` -> `200 OK`, mirroring the
//! fixture-server pattern in `tests/http_h1_client_regression.rs`. Runs as a
//! standalone integration crate (reliable proof lane; the lib unit-test target
//! stalls on the conformance dev-dep).
#![allow(clippy::items_after_statements)]

#[macro_use]
mod common;

use asupersync::Cx;
use asupersync::http::h1::{ClientError, HttpClient, RedirectPolicy};
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

/// Extracts the request-target (path) from the first line of a raw HTTP request,
/// e.g. `GET /final HTTP/1.1` -> `/final`.
fn request_path(raw: &[u8]) -> String {
    let text = String::from_utf8_lossy(raw);
    let first_line = text.lines().next().unwrap_or_default();
    first_line
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .to_owned()
}

/// Spawns a fixture server that serves exactly `max_conns` connections (one
/// request each, `Connection: close`). A request for `/final` gets `200 OK`
/// with body `ARRIVED`; any other path gets `302 Found` with `Location: /final`.
/// Returns the bound address and a handle yielding the ordered request paths.
fn spawn_redirect_server(
    max_conns: usize,
) -> (SocketAddr, thread::JoinHandle<std::io::Result<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    listener
        .set_nonblocking(true)
        .expect("set_nonblocking listener");
    let addr = listener.local_addr().expect("listener local_addr");

    let handle = thread::spawn(move || -> std::io::Result<Vec<String>> {
        let mut paths = Vec::with_capacity(max_conns);
        for _ in 0..max_conns {
            let mut conn = accept_with_timeout(&listener, IO_TIMEOUT)?;
            conn.set_read_timeout(Some(IO_TIMEOUT))?;
            conn.set_write_timeout(Some(IO_TIMEOUT))?;

            let raw = read_until_headers_end(&mut conn)?;
            let path = request_path(&raw);

            if path == "/final" {
                conn.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nARRIVED",
                )?;
            } else {
                conn.write_all(
                    b"HTTP/1.1 302 Found\r\nLocation: /final\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )?;
            }
            conn.flush()?;
            paths.push(path);
        }
        Ok(paths)
    });

    (addr, handle)
}

#[test]
fn redirect_policy_limited_follows_redirect_to_final_200() {
    init_test_logging();
    test_phase!("redirect_policy_limited_follows_redirect_to_final_200");

    let (addr, server) = spawn_redirect_server(2);

    run_test(|| async move {
        let cx = Cx::for_testing();
        let client = HttpClient::builder()
            .redirect_policy(RedirectPolicy::Limited(5))
            .build();
        let url = format!("http://{addr}/");

        let resp = client
            .get(url.as_str())
            .send(&cx)
            .await
            .expect("request should succeed");

        assert_eq!(
            resp.status, 200,
            "Limited policy should follow the 302 to the final 200"
        );
        assert_eq!(resp.body, b"ARRIVED");
    });

    let paths = server
        .join()
        .expect("server thread panicked")
        .expect("server io error");
    assert_eq!(
        paths,
        vec!["/".to_string(), "/final".to_string()],
        "client should request / then follow Location to /final"
    );

    test_complete!("redirect_policy_limited_follows_redirect_to_final_200");
}

#[test]
fn redirect_policy_none_returns_302_without_following() {
    init_test_logging();
    test_phase!("redirect_policy_none_returns_302_without_following");

    let (addr, server) = spawn_redirect_server(1);

    run_test(|| async move {
        let cx = Cx::for_testing();
        let client = HttpClient::builder()
            .redirect_policy(RedirectPolicy::None)
            .build();
        let url = format!("http://{addr}/");

        let resp = client
            .get(url.as_str())
            .send(&cx)
            .await
            .expect("request should succeed");

        assert_eq!(
            resp.status, 302,
            "None policy must return the redirect response unfollowed"
        );
    });

    let paths = server
        .join()
        .expect("server thread panicked")
        .expect("server io error");
    assert_eq!(
        paths,
        vec!["/".to_string()],
        "client must NOT follow the redirect under RedirectPolicy::None"
    );

    test_complete!("redirect_policy_none_returns_302_without_following");
}

#[test]
fn redirect_policy_same_origin_follows_same_origin_redirect() {
    init_test_logging();
    test_phase!("redirect_policy_same_origin_follows_same_origin_redirect");

    let (addr, server) = spawn_redirect_server(2);

    run_test(|| async move {
        let cx = Cx::for_testing();
        let client = HttpClient::builder()
            .redirect_policy(RedirectPolicy::SameOrigin(5))
            .build();
        let url = format!("http://{addr}/");

        let resp = client
            .get(url.as_str())
            .send(&cx)
            .await
            .expect("request should succeed");

        assert_eq!(
            resp.status, 200,
            "SameOrigin policy should follow a same-origin 302 to the final 200"
        );
        assert_eq!(resp.body, b"ARRIVED");
    });

    let paths = server
        .join()
        .expect("server thread panicked")
        .expect("server io error");
    assert_eq!(
        paths,
        vec!["/".to_string(), "/final".to_string()],
        "SameOrigin should follow the same-origin Location to /final"
    );

    test_complete!("redirect_policy_same_origin_follows_same_origin_redirect");
}

#[test]
fn redirect_policy_limited_zero_errors_too_many_redirects() {
    init_test_logging();
    test_phase!("redirect_policy_limited_zero_errors_too_many_redirects");

    // With a budget of 0 redirects the first 302 immediately exceeds the cap,
    // so the server only ever serves the initial `/` request.
    let (addr, server) = spawn_redirect_server(1);

    run_test(|| async move {
        let cx = Cx::for_testing();
        let client = HttpClient::builder()
            .redirect_policy(RedirectPolicy::Limited(0))
            .build();
        let url = format!("http://{addr}/");

        let err = client
            .get(url.as_str())
            .send(&cx)
            .await
            .expect_err("a 302 under Limited(0) must exceed the redirect cap");
        assert!(
            matches!(err, ClientError::TooManyRedirects { max: 0, .. }),
            "expected TooManyRedirects {{ max: 0 }}, got {err:?}"
        );
    });

    let paths = server
        .join()
        .expect("server thread panicked")
        .expect("server io error");
    assert_eq!(
        paths,
        vec!["/".to_string()],
        "Limited(0) must not follow the redirect"
    );

    test_complete!("redirect_policy_limited_zero_errors_too_many_redirects");
}
