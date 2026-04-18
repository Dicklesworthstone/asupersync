//! Conformance tests for HTTP/1.1 keep-alive connection reuse.
//!
//! These tests verify that HTTP/1.1 keep-alive connections are properly reused
//! according to RFC 7230, including Connection:close termination, 100-Continue
//! interaction, idle timeout eviction, and max-requests-per-connection enforcement.

#![cfg(test)]

use asupersync::http::h1::server::{Http1Config, Http1Server};
use asupersync::http::h1::types::{Method, Request, Response};
use asupersync::io::{AsyncRead, AsyncWrite, ReadBuf};
use asupersync::runtime::RuntimeBuilder;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

/// Test transport that captures all written data and provides controlled read data.
struct TestTransport {
    read_data: Vec<u8>,
    read_position: usize,
    written: Arc<Mutex<Vec<u8>>>,
    closed: bool,
}

impl TestTransport {
    fn new(read_data: Vec<u8>) -> (Self, Arc<Mutex<Vec<u8>>>) {
        let written = Arc::new(Mutex::new(Vec::new()));
        let transport = Self {
            read_data,
            read_position: 0,
            written: written.clone(),
            closed: false,
        };
        (transport, written)
    }

    fn with_multiple_requests(requests: Vec<&str>) -> (Self, Arc<Mutex<Vec<u8>>>) {
        let combined = requests.join("");
        Self::new(combined.into_bytes())
    }
}

impl AsyncRead for TestTransport {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.closed || self.read_position >= self.read_data.len() {
            return Poll::Ready(Ok(()));
        }

        let remaining = &self.read_data[self.read_position..];
        let to_copy = std::cmp::min(buf.remaining(), remaining.len());

        if to_copy > 0 {
            buf.put_slice(&remaining[..to_copy]);
            self.read_position += to_copy;
        }

        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for TestTransport {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "transport closed",
            )));
        }

        self.written.lock().unwrap().extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.closed = true;
        Poll::Ready(Ok(()))
    }
}

/// Helper to create basic HTTP request string.
fn make_http_request(method: &str, path: &str, version: &str, headers: &[(&str, &str)]) -> String {
    let mut req = format!("{method} {path} {version}\r\n");
    for (name, value) in headers {
        req.push_str(&format!("{name}: {value}\r\n"));
    }
    req.push_str("\r\n");
    req
}

/// Helper to parse HTTP response from written bytes.
fn parse_response_count(written: &[u8]) -> usize {
    let response_str = String::from_utf8_lossy(written);
    response_str.matches("HTTP/1.1 200 OK").count()
}

/// Helper to check if response contains specific header.
fn response_has_header(written: &[u8], header: &str, value: &str) -> bool {
    let response_str = String::from_utf8_lossy(written);
    let header_line = format!("{header}: {value}");
    response_str.contains(&header_line)
}

/// Test that HTTP/1.1 keep-alive reuses connection per RFC 7230.
#[test]
fn test_http11_keepalive_connection_reuse() {
    let written = Arc::new(Mutex::new(Vec::new()));
    let transport = TestTransport {
        read_data: b"GET /first HTTP/1.1\r\nHost: example.com\r\n\r\nGET /second HTTP/1.1\r\nHost: example.com\r\n\r\nGET /third HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n".to_vec(),
        read_position: 0,
        written: written.clone(),
        closed: false,
    };

    let server = Http1Server::new(|req: Request| async move {
        Response::new(200, "OK", format!("Response for {}", req.uri).into_bytes())
    });

    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("build current-thread runtime");

    let state = runtime
        .block_on(async { server.serve(transport).await })
        .expect("serve keep-alive requests");

    // Should have served 3 requests on the same connection
    assert_eq!(state.requests_served, 3);

    let written_data = written.lock().unwrap();
    let response_str = String::from_utf8_lossy(&written_data);

    // Should have 3 responses
    assert_eq!(parse_response_count(&written_data), 3);

    // Should contain at least one Connection header
    assert!(response_str.contains("Connection:"));
}

/// Test that Connection:close terminates the pipeline.
#[test]
fn test_connection_close_terminates_pipeline() {
    let rt = RuntimeBuilder::new().build().unwrap();

    rt.block_on(async {
        // Client sends Connection: close on first request
        let req1 = make_http_request(
            "GET",
            "/close-me",
            "HTTP/1.1",
            &[("Host", "example.com"), ("Connection", "close")],
        );
        // This second request should never be processed
        let req2 = make_http_request(
            "GET",
            "/never-reached",
            "HTTP/1.1",
            &[("Host", "example.com")],
        );

        let (transport, written) = TestTransport::with_multiple_requests(vec![&req1, &req2]);

        let server = Http1Server::new(|req: Request| async move {
            Response::new(200, "OK", format!("Response for {}", req.uri).into_bytes())
        });

        let result = server.serve(transport).await;
        assert!(result.is_ok());

        let state = result.unwrap();
        // Should have served only 1 request because connection closed
        assert_eq!(state.requests_served, 1);

        let written_data = written.lock().unwrap();
        // Should have only 1 response
        assert_eq!(parse_response_count(&written_data), 1);

        // Response should have Connection: close
        assert!(response_has_header(&written_data, "Connection", "close"));
    });
}

/// Test 100-Continue interaction with keep-alive.
#[test]
fn test_100_continue_with_keepalive() {
    let rt = RuntimeBuilder::new().build().unwrap();

    rt.block_on(async {
        // Request with Expect: 100-continue
        let req1 = format!(
            "POST /upload HTTP/1.1\r\n\
             Host: example.com\r\n\
             Connection: keep-alive\r\n\
             Expect: 100-continue\r\n\
             Content-Length: 11\r\n\
             \r\n\
             Hello World"
        );

        // Follow-up request after successful POST
        let req2 = make_http_request(
            "GET",
            "/after-upload",
            "HTTP/1.1",
            &[("Host", "example.com"), ("Connection", "close")],
        );

        let (transport, written) = TestTransport::with_multiple_requests(vec![&req1, &req2]);

        let server = Http1Server::new(|req: Request| async move {
            if req.method == Method::Post {
                Response::new(201, "Created", b"Upload successful".to_vec())
            } else {
                Response::new(200, "OK", b"OK".to_vec())
            }
        });

        let result = server.serve(transport).await;
        assert!(result.is_ok());

        let state = result.unwrap();
        // Should have served 2 requests
        assert_eq!(state.requests_served, 2);

        let written_data = written.lock().unwrap();
        let response_str = String::from_utf8_lossy(&written_data);

        // Should contain 100 Continue response
        assert!(response_str.contains("HTTP/1.1 100"));
        // Should contain the final responses
        assert!(response_str.contains("HTTP/1.1 201"));
        assert!(response_str.contains("HTTP/1.1 200"));
    });
}

/// Test idle timeout eviction.
#[test]
fn test_idle_timeout_eviction() {
    let rt = RuntimeBuilder::new().build().unwrap();

    rt.block_on(async {
        // Only send one request, then let connection sit idle
        let req1 = make_http_request(
            "GET",
            "/first",
            "HTTP/1.1",
            &[("Host", "example.com"), ("Connection", "keep-alive")],
        );

        let (transport, written) = TestTransport::new(req1.into_bytes());

        // Configure server with very short idle timeout
        let config = Http1Config::default().idle_timeout(Some(Duration::from_millis(10)));

        let server = Http1Server::with_config(
            |_req: Request| async move { Response::new(200, "OK", b"OK".to_vec()) },
            config,
        );

        let result = server.serve(transport).await;
        assert!(result.is_ok());

        let state = result.unwrap();
        // Should have served 1 request before timing out
        assert_eq!(state.requests_served, 1);

        let written_data = written.lock().unwrap();
        assert_eq!(parse_response_count(&written_data), 1);
    });
}

/// Test max-requests-per-connection enforcement.
#[test]
fn test_max_requests_per_connection_enforcement() {
    let rt = RuntimeBuilder::new().build().unwrap();

    rt.block_on(async {
        // Send 4 requests, but limit is 3
        let req1 = make_http_request("GET", "/1", "HTTP/1.1", &[("Host", "example.com")]);
        let req2 = make_http_request("GET", "/2", "HTTP/1.1", &[("Host", "example.com")]);
        let req3 = make_http_request("GET", "/3", "HTTP/1.1", &[("Host", "example.com")]);
        let req4 = make_http_request("GET", "/4", "HTTP/1.1", &[("Host", "example.com")]);

        let (transport, written) =
            TestTransport::with_multiple_requests(vec![&req1, &req2, &req3, &req4]);

        // Configure server with max 3 requests per connection
        let config = Http1Config::default().max_requests(Some(3));

        let server = Http1Server::with_config(
            |req: Request| async move {
                Response::new(200, "OK", format!("Response {}", req.uri).into_bytes())
            },
            config,
        );

        let result = server.serve(transport).await;
        assert!(result.is_ok());

        let state = result.unwrap();
        // Should have served exactly 3 requests before closing
        assert_eq!(state.requests_served, 3);

        let written_data = written.lock().unwrap();
        // Should have exactly 3 responses
        assert_eq!(parse_response_count(&written_data), 3);

        let response_str = String::from_utf8_lossy(&written_data);
        // Third response should have Connection: close
        assert!(response_str.contains("Connection: close"));
    });
}

/// Test HTTP/1.0 requires explicit keep-alive header.
#[test]
fn test_http10_explicit_keepalive_required() {
    let written = Arc::new(Mutex::new(Vec::new()));
    let transport = TestTransport {
        read_data: b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n".to_vec(),
        read_position: 0,
        written: written.clone(),
        closed: false,
    };

    let server = Http1Server::new(|_req: Request| async move { Response::new(200, "OK", b"OK") });

    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("build current-thread runtime");

    let state = runtime
        .block_on(async { server.serve(transport).await })
        .expect("serve HTTP/1.0 request");

    // Should have served the 1 request, then closed (HTTP/1.0 defaults to close)
    assert_eq!(state.requests_served, 1);

    let written_data = written.lock().unwrap();
    let response_str = String::from_utf8_lossy(&written_data);

    // Response should be HTTP/1.0 (downgraded from 1.1)
    assert!(response_str.starts_with("HTTP/1.0 200"));
}

/// Test HTTP/1.0 with explicit Connection: keep-alive.
#[test]
fn test_http10_explicit_keepalive_works() {
    let req1 = make_http_request(
        "GET",
        "/first",
        "HTTP/1.0",
        &[("Host", "example.com"), ("Connection", "keep-alive")],
    );
    let req2 = make_http_request(
        "GET",
        "/second",
        "HTTP/1.0",
        &[("Host", "example.com"), ("Connection", "close")],
    );

    let (transport, written) = TestTransport::with_multiple_requests(vec![&req1, &req2]);

    let server = Http1Server::new(|_req: Request| async move { Response::new(200, "OK", b"OK") });

    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("build current-thread runtime");

    let state = runtime
        .block_on(async { server.serve(transport).await })
        .expect("serve HTTP/1.0 keep-alive requests");

    // Should have served 2 requests with explicit keep-alive
    assert_eq!(state.requests_served, 2);

    let written_data = written.lock().unwrap();
    assert_eq!(parse_response_count(&written_data), 2);

    let response_str = String::from_utf8_lossy(&written_data);
    // Should contain Connection headers
    assert!(response_str.contains("Connection:"));
}

/// Test keep-alive disabled server-wide.
#[test]
fn test_keepalive_disabled_server_wide() {
    let rt = RuntimeBuilder::new().build().unwrap();

    rt.block_on(async {
        let req1 = make_http_request(
            "GET",
            "/first",
            "HTTP/1.1",
            &[("Host", "example.com"), ("Connection", "keep-alive")],
        );
        let req2 = make_http_request("GET", "/second", "HTTP/1.1", &[("Host", "example.com")]);

        let (transport, written) = TestTransport::with_multiple_requests(vec![&req1, &req2]);

        // Disable keep-alive server-wide
        let config = Http1Config::default().keep_alive(false);

        let server = Http1Server::with_config(
            |_req: Request| async move { Response::new(200, "OK", b"OK".to_vec()) },
            config,
        );

        let result = server.serve(transport).await;
        assert!(result.is_ok());

        let state = result.unwrap();
        // Should have served only 1 request (keep-alive disabled)
        assert_eq!(state.requests_served, 1);

        let written_data = written.lock().unwrap();
        assert_eq!(parse_response_count(&written_data), 1);

        // Response should have Connection: close
        assert!(response_has_header(&written_data, "Connection", "close"));
    });
}
