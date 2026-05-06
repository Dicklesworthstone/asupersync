//! HTTP/1.1 keep-alive conformance tests against the live H1 server.
//!
//! These tests pin RFC 9112 connection persistence behavior using production
//! `Http1Server` request/response flow over an in-memory transport. The older
//! mock-pool draft is preserved below as disabled archaeology.

use asupersync::http::h1::server::HostPolicy;
use asupersync::http::h1::types::{Request, Response};
use asupersync::http::h1::{Http1Config, Http1Server};
use asupersync::io::{AsyncRead, AsyncWrite, ReadBuf};
use asupersync::runtime::RuntimeBuilder;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

const BEAD_ID: &str = "asupersync-nax796";
const SUITE_ID: &str = "h1_keepalive";

#[derive(Debug)]
struct KeepAliveCaseResult {
    scenario_id: &'static str,
    method: &'static str,
    headers: &'static str,
    body_shape: &'static str,
    connection_reused: &'static str,
    expected_status: &'static str,
    actual_status: String,
    expected_connection_state: &'static str,
    actual_connection_state: String,
    verdict: &'static str,
    first_failure: String,
}

impl KeepAliveCaseResult {
    fn pass(
        scenario_id: &'static str,
        method: &'static str,
        headers: &'static str,
        body_shape: &'static str,
        connection_reused: &'static str,
        expected_status: &'static str,
        expected_connection_state: &'static str,
    ) -> Self {
        Self {
            scenario_id,
            method,
            headers,
            body_shape,
            connection_reused,
            expected_status,
            actual_status: expected_status.to_string(),
            expected_connection_state,
            actual_connection_state: expected_connection_state.to_string(),
            verdict: "pass",
            first_failure: String::new(),
        }
    }

    fn fail(
        scenario_id: &'static str,
        method: &'static str,
        headers: &'static str,
        body_shape: &'static str,
        connection_reused: &'static str,
        expected_status: &'static str,
        actual_status: impl Into<String>,
        expected_connection_state: &'static str,
        actual_connection_state: impl Into<String>,
        first_failure: impl Into<String>,
    ) -> Self {
        Self {
            scenario_id,
            method,
            headers,
            body_shape,
            connection_reused,
            expected_status,
            actual_status: actual_status.into(),
            expected_connection_state,
            actual_connection_state: actual_connection_state.into(),
            verdict: "fail",
            first_failure: first_failure.into(),
        }
    }

    fn emit(&self) {
        println!(
            "bead_id={} suite_id={} scenario_id={} protocol_version=HTTP/1.1 method={} headers={} body_shape={} connection_reused={} cookie_case=n/a expected_status={} actual_status={} expected_connection_state={} actual_connection_state={} verdict={} first_failure={}",
            BEAD_ID,
            SUITE_ID,
            self.scenario_id,
            self.method,
            self.headers,
            self.body_shape,
            self.connection_reused,
            self.expected_status,
            self.actual_status,
            self.expected_connection_state,
            self.actual_connection_state,
            self.verdict,
            self.first_failure
        );
    }

    fn assert_pass(self) {
        self.emit();
        assert_eq!(
            self.verdict, "pass",
            "HTTP/1 keep-alive conformance failed: {self:?}"
        );
    }
}

struct TestIo {
    read_data: Vec<u8>,
    written: Arc<Mutex<Vec<u8>>>,
}

impl TestIo {
    fn new(read_data: Vec<u8>, written: Arc<Mutex<Vec<u8>>>) -> Self {
        Self { read_data, written }
    }
}

impl AsyncRead for TestIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.read_data.is_empty() {
            return Poll::Ready(Ok(()));
        }

        let n = buf.remaining().min(self.read_data.len());
        buf.put_slice(&self.read_data[..n]);
        self.read_data.drain(..n);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for TestIo {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.written.lock().unwrap().extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn h1_config(max_requests: Option<u64>) -> Http1Config {
    Http1Config::default()
        .host_policy(HostPolicy::allow_list(vec!["example.com".to_string()]))
        .keep_alive(true)
        .max_requests(max_requests)
        .idle_timeout(None)
}

fn run_server<I, F, Fut>(server: Http1Server<F>, io: I) -> asupersync::http::h1::ConnectionState
where
    I: AsyncRead + AsyncWrite + Unpin + Send,
    F: Fn(Request) -> Fut + Send + Sync,
    Fut: Future<Output = Response> + Send,
{
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("current-thread runtime should build");
    runtime
        .block_on(async { server.serve(io).await })
        .expect("HTTP/1 server should complete the test connection")
}

fn written_text(written: &Arc<Mutex<Vec<u8>>>) -> String {
    String::from_utf8(written.lock().unwrap().clone()).expect("HTTP output should be UTF-8")
}

fn response_count(output: &str, version: &str) -> usize {
    output.matches(&format!("{version} 200 OK\r\n")).count()
}

fn handler_recording_uris(
    seen_uris: Arc<Mutex<Vec<String>>>,
) -> impl Fn(Request) -> std::future::Ready<Response> + Send + Sync {
    move |req| {
        seen_uris.lock().unwrap().push(req.uri);
        std::future::ready(Response::new(200, "OK", b"done"))
    }
}

#[test]
fn http11_default_persistence_reuses_connection_until_close_token() {
    let scenario = "H1_KEEPALIVE_HTTP11_DEFAULT_REUSE";
    let written = Arc::new(Mutex::new(Vec::new()));
    let seen_uris = Arc::new(Mutex::new(Vec::new()));
    let raw = b"GET /one HTTP/1.1\r\nHost: example.com\r\n\r\nGET /two HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
    let server = Http1Server::with_config(
        handler_recording_uris(Arc::clone(&seen_uris)),
        h1_config(None),
    );

    let state = run_server(server, TestIo::new(raw.to_vec(), Arc::clone(&written)));
    let output = written_text(&written);

    if state.requests_served == 2
        && *seen_uris.lock().unwrap() == vec!["/one".to_string(), "/two".to_string()]
        && response_count(&output, "HTTP/1.1") == 2
        && output.contains("Connection: close\r\n")
    {
        KeepAliveCaseResult::pass(
            scenario,
            "GET",
            "http11-default+close-token",
            "pipelined_two_requests",
            "true",
            "200,200",
            "closed_after_second",
        )
        .assert_pass();
    } else {
        KeepAliveCaseResult::fail(
            scenario,
            "GET",
            "http11-default+close-token",
            "pipelined_two_requests",
            "expected_true",
            "200,200",
            format!(
                "served={} uris={:?} output={:?}",
                state.requests_served,
                *seen_uris.lock().unwrap(),
                output
            ),
            "closed_after_second",
            "unexpected_flow",
            "HTTP/1.1 default persistence did not reuse the connection until Connection: close",
        )
        .assert_pass();
    }
}

#[test]
fn connection_close_request_stops_before_pipelined_followup() {
    let scenario = "H1_KEEPALIVE_CLOSE_STOPS_PIPELINE";
    let written = Arc::new(Mutex::new(Vec::new()));
    let seen_uris = Arc::new(Mutex::new(Vec::new()));
    let raw = b"GET /one HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\nGET /two HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let server = Http1Server::with_config(
        handler_recording_uris(Arc::clone(&seen_uris)),
        h1_config(None),
    );

    let state = run_server(server, TestIo::new(raw.to_vec(), Arc::clone(&written)));
    let output = written_text(&written);

    if state.requests_served == 1
        && *seen_uris.lock().unwrap() == vec!["/one".to_string()]
        && response_count(&output, "HTTP/1.1") == 1
        && output.contains("Connection: close\r\n")
    {
        KeepAliveCaseResult::pass(
            scenario,
            "GET",
            "connection-close",
            "pipelined_followup_left_unserved",
            "false",
            "200",
            "closed_after_first",
        )
        .assert_pass();
    } else {
        KeepAliveCaseResult::fail(
            scenario,
            "GET",
            "connection-close",
            "pipelined_followup_left_unserved",
            "expected_false",
            "200",
            format!(
                "served={} uris={:?} output={:?}",
                state.requests_served,
                *seen_uris.lock().unwrap(),
                output
            ),
            "closed_after_first",
            "unexpected_flow",
            "Connection: close did not stop the pipelined follow-up",
        )
        .assert_pass();
    }
}

#[test]
fn http10_defaults_to_close_without_keepalive_token() {
    let scenario = "H1_KEEPALIVE_HTTP10_DEFAULT_CLOSE";
    let written = Arc::new(Mutex::new(Vec::new()));
    let seen_uris = Arc::new(Mutex::new(Vec::new()));
    let raw = b"GET /legacy HTTP/1.0\r\nHost: example.com\r\n\r\nGET /ignored HTTP/1.0\r\nHost: example.com\r\n\r\n";
    let server = Http1Server::with_config(
        handler_recording_uris(Arc::clone(&seen_uris)),
        h1_config(None),
    );

    let state = run_server(server, TestIo::new(raw.to_vec(), Arc::clone(&written)));
    let output = written_text(&written);

    if state.requests_served == 1
        && *seen_uris.lock().unwrap() == vec!["/legacy".to_string()]
        && response_count(&output, "HTTP/1.0") == 1
        && output.contains("Connection: close\r\n")
    {
        KeepAliveCaseResult::pass(
            scenario,
            "GET",
            "http10-default",
            "pipelined_followup_left_unserved",
            "false",
            "200",
            "closed_after_first",
        )
        .assert_pass();
    } else {
        KeepAliveCaseResult::fail(
            scenario,
            "GET",
            "http10-default",
            "pipelined_followup_left_unserved",
            "expected_false",
            "200",
            format!(
                "served={} uris={:?} output={:?}",
                state.requests_served,
                *seen_uris.lock().unwrap(),
                output
            ),
            "closed_after_first",
            "unexpected_flow",
            "HTTP/1.0 default did not close before the follow-up request",
        )
        .assert_pass();
    }
}

#[test]
fn http10_keepalive_token_allows_one_reuse_then_close_token() {
    let scenario = "H1_KEEPALIVE_HTTP10_TOKEN_REUSE";
    let written = Arc::new(Mutex::new(Vec::new()));
    let seen_uris = Arc::new(Mutex::new(Vec::new()));
    let raw = b"GET /legacy-one HTTP/1.0\r\nHost: example.com\r\nConnection: keep-alive\r\n\r\nGET /legacy-two HTTP/1.0\r\nHost: example.com\r\nConnection: close\r\n\r\n";
    let server = Http1Server::with_config(
        handler_recording_uris(Arc::clone(&seen_uris)),
        h1_config(None),
    );

    let state = run_server(server, TestIo::new(raw.to_vec(), Arc::clone(&written)));
    let output = written_text(&written);

    if state.requests_served == 2
        && *seen_uris.lock().unwrap() == vec!["/legacy-one".to_string(), "/legacy-two".to_string()]
        && response_count(&output, "HTTP/1.0") == 2
        && output.contains("Connection: keep-alive\r\n")
        && output.contains("Connection: close\r\n")
    {
        KeepAliveCaseResult::pass(
            scenario,
            "GET",
            "http10-keep-alive+close",
            "pipelined_two_requests",
            "true",
            "200,200",
            "closed_after_second",
        )
        .assert_pass();
    } else {
        KeepAliveCaseResult::fail(
            scenario,
            "GET",
            "http10-keep-alive+close",
            "pipelined_two_requests",
            "expected_true",
            "200,200",
            format!(
                "served={} uris={:?} output={:?}",
                state.requests_served,
                *seen_uris.lock().unwrap(),
                output
            ),
            "closed_after_second",
            "unexpected_flow",
            "HTTP/1.0 keep-alive token did not allow exactly one reuse",
        )
        .assert_pass();
    }
}

#[test]
fn max_requests_limit_closes_at_configured_boundary() {
    let scenario = "H1_KEEPALIVE_MAX_REQUESTS_LIMIT";
    let written = Arc::new(Mutex::new(Vec::new()));
    let seen_uris = Arc::new(Mutex::new(Vec::new()));
    let raw = b"GET /one HTTP/1.1\r\nHost: example.com\r\n\r\nGET /two HTTP/1.1\r\nHost: example.com\r\n\r\nGET /three HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let server = Http1Server::with_config(
        handler_recording_uris(Arc::clone(&seen_uris)),
        h1_config(Some(2)),
    );

    let state = run_server(server, TestIo::new(raw.to_vec(), Arc::clone(&written)));
    let output = written_text(&written);

    if state.requests_served == 2
        && *seen_uris.lock().unwrap() == vec!["/one".to_string(), "/two".to_string()]
        && response_count(&output, "HTTP/1.1") == 2
        && output.contains("Connection: close\r\n")
    {
        KeepAliveCaseResult::pass(
            scenario,
            "GET",
            "max-requests=2",
            "three_pipelined_requests",
            "true_until_limit",
            "200,200",
            "closed_at_limit",
        )
        .assert_pass();
    } else {
        KeepAliveCaseResult::fail(
            scenario,
            "GET",
            "max-requests=2",
            "three_pipelined_requests",
            "expected_true_until_limit",
            "200,200",
            format!(
                "served={} uris={:?} output={:?}",
                state.requests_served,
                *seen_uris.lock().unwrap(),
                output
            ),
            "closed_at_limit",
            "unexpected_flow",
            "max_requests_per_connection did not close at the configured boundary",
        )
        .assert_pass();
    }
}

#[test]
fn handler_connection_close_response_overrides_http11_default_reuse() {
    let scenario = "H1_KEEPALIVE_RESPONSE_CLOSE_OVERRIDES";
    let written = Arc::new(Mutex::new(Vec::new()));
    let seen_uris = Arc::new(Mutex::new(Vec::new()));
    let raw = b"GET /one HTTP/1.1\r\nHost: example.com\r\n\r\nGET /two HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let seen_uris_for_handler = Arc::clone(&seen_uris);
    let server = Http1Server::with_config(
        move |req| {
            seen_uris_for_handler.lock().unwrap().push(req.uri);
            std::future::ready(Response::new(200, "OK", b"done").with_header("Connection", "close"))
        },
        h1_config(None),
    );

    let state = run_server(server, TestIo::new(raw.to_vec(), Arc::clone(&written)));
    let output = written_text(&written);

    if state.requests_served == 1
        && *seen_uris.lock().unwrap() == vec!["/one".to_string()]
        && response_count(&output, "HTTP/1.1") == 1
        && output.contains("Connection: close\r\n")
    {
        KeepAliveCaseResult::pass(
            scenario,
            "GET",
            "response-connection-close",
            "pipelined_followup_left_unserved",
            "false",
            "200",
            "closed_after_first",
        )
        .assert_pass();
    } else {
        KeepAliveCaseResult::fail(
            scenario,
            "GET",
            "response-connection-close",
            "pipelined_followup_left_unserved",
            "expected_false",
            "200",
            format!(
                "served={} uris={:?} output={:?}",
                state.requests_served,
                *seen_uris.lock().unwrap(),
                output
            ),
            "closed_after_first",
            "unexpected_flow",
            "handler Connection: close response did not override HTTP/1.1 default reuse",
        )
        .assert_pass();
    }
}

#[rustfmt::skip]
#[cfg(any())]
mod stale_h1_keepalive_suite {
#![allow(warnings)]
#![allow(clippy::all)]
//! HTTP/1.1 Keep-Alive Connection Pooling Conformance Tests (RFC 9112)
//!
//! Validates RFC 9112 HTTP/1.1 connection pooling and keep-alive behavior:
//! 1. Connection: keep-alive honored for reuse
//! 2. Connection: close terminates after response
//! 3. Idle timeout recycles stale connections
//! 4. Pool capacity bound enforced
//! 5. Poisoned connection (bad body) removed from pool
//! 6. HTTP/1.0 connections default to close unless Keep-Alive header
//!
//! # RFC 9112 Section 9: Connection Management
//!
//! HTTP/1.1 defines a "keep-alive" mechanism that allows persistent connections
//! to be reused for multiple request/response pairs. This avoids the overhead
//! of establishing a new TCP connection for each HTTP exchange.
//!
//! ## Key Requirements (RFC 9112)
//!
//! - **Connection: keep-alive** signals the sender wants persistent connection
//! - **Connection: close** signals connection will be closed after response
//! - **HTTP/1.0** connections close by default unless Keep-Alive header present
//! - **Connection pools** MUST respect capacity limits and evict idle connections
//! - **Poisoned connections** (protocol errors) MUST be removed from pool

use asupersync::cx::Cx;
use asupersync::http::h1::client::Http1Client;
use asupersync::http::h1::codec::HttpError;
use asupersync::http::h1::types::{Method, Request, Response, Version};
use asupersync::http::pool::{Pool, PoolConfig, PoolKey, PooledConnectionState};
use asupersync::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use asupersync::net::tcp::stream::TcpStream;
use asupersync::time::{sleep, Duration, Instant};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

/// RFC 2119 requirement level for conformance testing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)]
pub enum RequirementLevel {
    Must,   // RFC 2119: MUST
    Should, // RFC 2119: SHOULD
    May,    // RFC 2119: MAY
}

/// Test result for a single keep-alive conformance requirement
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct KeepAliveResult {
    pub test_id: String,
    pub description: String,
    pub category: TestCategory,
    pub requirement_level: RequirementLevel,
    pub verdict: TestVerdict,
    pub error_message: Option<String>,
    pub execution_time_ms: u64,
}

/// Test categories for HTTP/1.1 keep-alive conformance
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[allow(dead_code)]
pub enum TestCategory {
    /// Connection: keep-alive header honored
    KeepAliveReuse,
    /// Connection: close header enforced
    ConnectionClose,
    /// Idle connection timeout and eviction
    IdleTimeout,
    /// Pool capacity bounds enforcement
    PoolCapacity,
    /// Poisoned connection removal
    PoisonedConnection,
    /// HTTP/1.0 vs HTTP/1.1 behavior
    HttpVersionCompat,
}

/// Test verdict
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)]
pub enum TestVerdict {
    Pass,
    Fail,
    Skipped,
    ExpectedFailure,
}

/// Mock HTTP server for testing connection behavior
#[allow(dead_code)]
struct MockHttpServer {
    responses: Arc<Mutex<VecDeque<MockResponse>>>,
    connections_created: Arc<Mutex<u32>>,
    connections_closed: Arc<Mutex<u32>>,
}

/// Mock HTTP response configuration
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct MockResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    /// Whether to close connection after response
    close_after: bool,
    /// Whether to send malformed body (for poisoning tests)
    malformed_body: bool,
}

#[allow(dead_code)]

impl MockHttpServer {
    #[allow(dead_code)]
    fn new() -> Self {
        Self {
            responses: Arc::new(Mutex::new(VecDeque::new())),
            connections_created: Arc::new(Mutex::new(0)),
            connections_closed: Arc::new(Mutex::new(0)),
        }
    }

    #[allow(dead_code)]

    fn add_response(&self, response: MockResponse) {
        self.responses.lock().unwrap().push_back(response);
    }

    #[allow(dead_code)]

    fn connections_created(&self) -> u32 {
        *self.connections_created.lock().unwrap()
    }

    #[allow(dead_code)]

    fn connections_closed(&self) -> u32 {
        *self.connections_closed.lock().unwrap()
    }

    #[allow(dead_code)]

    fn reset_counters(&self) {
        *self.connections_created.lock().unwrap() = 0;
        *self.connections_closed.lock().unwrap() = 0;
    }
}

/// Mock transport that simulates HTTP server behavior
#[allow(dead_code)]
struct MockTransport {
    server: Arc<MockHttpServer>,
    buffer: Vec<u8>,
    read_pos: usize,
    written_data: Vec<u8>,
    closed: bool,
}

#[allow(dead_code)]

impl MockTransport {
    #[allow(dead_code)]
    fn new(server: Arc<MockHttpServer>) -> Self {
        {
            let mut count = server.connections_created.lock().unwrap();
            *count += 1;
        }

        Self {
            server,
            buffer: Vec::new(),
            read_pos: 0,
            written_data: Vec::new(),
            closed: false,
        }
    }

    #[allow(dead_code)]

    fn prepare_response(&mut self) {
        let mut responses = self.server.responses.lock().unwrap();
        if let Some(mock_resp) = responses.pop_front() {
            let mut response = String::new();
            response.push_str(&format!("HTTP/1.1 {} OK\r\n", mock_resp.status));

            for (name, value) in &mock_resp.headers {
                response.push_str(&format!("{}: {}\r\n", name, value));
            }

            if !mock_resp.headers.iter().any(|(name, _)| name.eq_ignore_ascii_case("content-length")) {
                response.push_str(&format!("Content-Length: {}\r\n", mock_resp.body.len()));
            }

            response.push_str("\r\n");

            self.buffer = response.into_bytes();

            if mock_resp.malformed_body {
                // Add malformed body (shorter than Content-Length)
                self.buffer.extend_from_slice(b"short");
            } else {
                self.buffer.extend_from_slice(&mock_resp.body);
            }

            if mock_resp.close_after {
                self.closed = true;
            }
        }
    }
}

impl AsyncRead for MockTransport {
    #[allow(dead_code)]
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut asupersync::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.buffer.is_empty() {
            self.prepare_response();
        }

        if self.read_pos >= self.buffer.len() {
            return Poll::Ready(Ok(()));
        }

        let available = &self.buffer[self.read_pos..];
        let to_copy = available.len().min(buf.remaining());
        buf.put_slice(&available[..to_copy]);
        self.read_pos += to_copy;

        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for MockTransport {
    #[allow(dead_code)]
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        self.written_data.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    #[allow(dead_code)]

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }

    #[allow(dead_code)]

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        {
            let mut count = self.server.connections_closed.lock().unwrap();
            *count += 1;
        }
        Poll::Ready(Ok(()))
    }
}

impl Unpin for MockTransport {}

/// HTTP/1.1 keep-alive conformance test harness
#[allow(dead_code)]
pub struct H1KeepAliveHarness {
    server: Arc<MockHttpServer>,
    pool_config: PoolConfig,
}

#[allow(dead_code)]

impl H1KeepAliveHarness {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self {
            server: Arc::new(MockHttpServer::new()),
            pool_config: PoolConfig::default(),
        }
    }

    #[allow(dead_code)]

    pub fn with_pool_config(mut self, config: PoolConfig) -> Self {
        self.pool_config = config;
        self
    }

    /// Run all HTTP/1.1 keep-alive conformance tests
    #[allow(dead_code)]
    pub fn run_all_tests(&self) -> Vec<KeepAliveResult> {
        let mut results = Vec::new();

        // Test 1: Connection: keep-alive honored for reuse
        results.push(self.test_keep_alive_reuse());

        // Test 2: Connection: close terminates after response
        results.push(self.test_connection_close());

        // Test 3: Idle timeout recycles stale connections
        results.push(self.test_idle_timeout());

        // Test 4: Pool capacity bound enforced
        results.push(self.test_pool_capacity_bounds());

        // Test 5: Poisoned connection removed from pool
        results.push(self.test_poisoned_connection_removal());

        // Test 6: HTTP/1.0 vs HTTP/1.1 default behavior
        results.push(self.test_http_version_defaults());

        results
    }

    /// Test RFC 9112: Connection: keep-alive honored for reuse (Requirement 1)
    #[allow(dead_code)]
    fn test_keep_alive_reuse(&self) -> KeepAliveResult {
        let start = Instant::now();

        let result = std::panic::catch_unwind(|| {
            // Set up mock server with keep-alive response
            self.server.reset_counters();
            self.server.add_response(MockResponse {
                status: 200,
                headers: vec![
                    ("Connection".to_string(), "keep-alive".to_string()),
                    ("Keep-Alive".to_string(), "timeout=5, max=100".to_string()),
                ],
                body: b"First response".to_vec(),
                close_after: false,
                malformed_body: false,
            });

            self.server.add_response(MockResponse {
                status: 200,
                headers: vec![
                    ("Connection".to_string(), "keep-alive".to_string()),
                ],
                body: b"Second response".to_vec(),
                close_after: false,
                malformed_body: false,
            });

            // Create two requests that should reuse the same connection
            let transport1 = MockTransport::new(self.server.clone());
            let transport2 = MockTransport::new(self.server.clone());

            // Simulate connection reuse behavior
            let connections_before = self.server.connections_created();

            // The actual test would involve a real connection pool
            // For this mock test, we verify the server provides keep-alive headers
            assert_eq!(connections_before, 2); // Two transport objects created

            true
        });

        let execution_time = start.elapsed().as_millis() as u64;

        match result {
            Ok(true) => KeepAliveResult {
                test_id: "RFC9112-KEEP-ALIVE-REUSE".to_string(),
                description: "Connection: keep-alive header honored for connection reuse".to_string(),
                category: TestCategory::KeepAliveReuse,
                requirement_level: RequirementLevel::Must,
                verdict: TestVerdict::Pass,
                error_message: None,
                execution_time_ms: execution_time,
            },
            Ok(false) | Err(_) => KeepAliveResult {
                test_id: "RFC9112-KEEP-ALIVE-REUSE".to_string(),
                description: "Connection: keep-alive header honored for connection reuse".to_string(),
                category: TestCategory::KeepAliveReuse,
                requirement_level: RequirementLevel::Must,
                verdict: TestVerdict::Fail,
                error_message: Some("Keep-alive reuse test failed".to_string()),
                execution_time_ms: execution_time,
            },
        }
    }

    /// Test RFC 9112: Connection: close terminates after response (Requirement 2)
    #[allow(dead_code)]
    fn test_connection_close(&self) -> KeepAliveResult {
        let start = Instant::now();

        let result = std::panic::catch_unwind(|| {
            self.server.reset_counters();
            self.server.add_response(MockResponse {
                status: 200,
                headers: vec![
                    ("Connection".to_string(), "close".to_string()),
                ],
                body: b"Connection will close".to_vec(),
                close_after: true,
                malformed_body: false,
            });

            // Verify connection is marked for closure
            let transport = MockTransport::new(self.server.clone());

            // The transport should be closed after response
            assert_eq!(self.server.connections_created(), 1);

            true
        });

        let execution_time = start.elapsed().as_millis() as u64;

        match result {
            Ok(true) => KeepAliveResult {
                test_id: "RFC9112-CONNECTION-CLOSE".to_string(),
                description: "Connection: close header terminates connection after response".to_string(),
                category: TestCategory::ConnectionClose,
                requirement_level: RequirementLevel::Must,
                verdict: TestVerdict::Pass,
                error_message: None,
                execution_time_ms: execution_time,
            },
            Ok(false) | Err(_) => KeepAliveResult {
                test_id: "RFC9112-CONNECTION-CLOSE".to_string(),
                description: "Connection: close header terminates connection after response".to_string(),
                category: TestCategory::ConnectionClose,
                requirement_level: RequirementLevel::Must,
                verdict: TestVerdict::Fail,
                error_message: Some("Connection close test failed".to_string()),
                execution_time_ms: execution_time,
            },
        }
    }

    /// Test idle timeout recycles stale connections (Requirement 3)
    #[allow(dead_code)]
    fn test_idle_timeout(&self) -> KeepAliveResult {
        let start = Instant::now();

        let result = std::panic::catch_unwind(|| {
            // Test with very short idle timeout for fast test execution
            let config = PoolConfig {
                idle_timeout: Duration::from_millis(100),
                cleanup_interval: Duration::from_millis(50),
                max_connections_per_host: 10,
                max_total_connections: 100,
            };

            // Simulate idle connection timeout by checking timing
            let idle_start = Instant::now();

            // Wait longer than idle timeout
            std::thread::sleep(Duration::from_millis(150));

            let elapsed = idle_start.elapsed();
            assert!(elapsed > config.idle_timeout, "Should exceed idle timeout");

            true
        });

        let execution_time = start.elapsed().as_millis() as u64;

        match result {
            Ok(true) => KeepAliveResult {
                test_id: "RFC9112-IDLE-TIMEOUT".to_string(),
                description: "Idle timeout recycles stale connections".to_string(),
                category: TestCategory::IdleTimeout,
                requirement_level: RequirementLevel::Should,
                verdict: TestVerdict::Pass,
                error_message: None,
                execution_time_ms: execution_time,
            },
            Ok(false) | Err(_) => KeepAliveResult {
                test_id: "RFC9112-IDLE-TIMEOUT".to_string(),
                description: "Idle timeout recycles stale connections".to_string(),
                category: TestCategory::IdleTimeout,
                requirement_level: RequirementLevel::Should,
                verdict: TestVerdict::Fail,
                error_message: Some("Idle timeout test failed".to_string()),
                execution_time_ms: execution_time,
            },
        }
    }

    /// Test pool capacity bounds enforcement (Requirement 4)
    #[allow(dead_code)]
    fn test_pool_capacity_bounds(&self) -> KeepAliveResult {
        let start = Instant::now();

        let result = std::panic::catch_unwind(|| {
            // Test with very low capacity limits
            let config = PoolConfig {
                max_connections_per_host: 2,
                max_total_connections: 5,
                idle_timeout: Duration::from_secs(60),
                cleanup_interval: Duration::from_secs(30),
            };

            // Verify capacity constraints are enforced
            assert!(config.max_connections_per_host <= config.max_total_connections);
            assert!(config.max_connections_per_host > 0);
            assert!(config.max_total_connections > 0);

            // Test would verify that pool rejects excess connections
            let max_per_host = config.max_connections_per_host;
            assert_eq!(max_per_host, 2, "Max per host should be 2");

            true
        });

        let execution_time = start.elapsed().as_millis() as u64;

        match result {
            Ok(true) => KeepAliveResult {
                test_id: "RFC9112-POOL-CAPACITY".to_string(),
                description: "Pool capacity bounds enforced".to_string(),
                category: TestCategory::PoolCapacity,
                requirement_level: RequirementLevel::Must,
                verdict: TestVerdict::Pass,
                error_message: None,
                execution_time_ms: execution_time,
            },
            Ok(false) | Err(_) => KeepAliveResult {
                test_id: "RFC9112-POOL-CAPACITY".to_string(),
                description: "Pool capacity bounds enforced".to_string(),
                category: TestCategory::PoolCapacity,
                requirement_level: RequirementLevel::Must,
                verdict: TestVerdict::Fail,
                error_message: Some("Pool capacity test failed".to_string()),
                execution_time_ms: execution_time,
            },
        }
    }

    /// Test poisoned connection removal (Requirement 5)
    #[allow(dead_code)]
    fn test_poisoned_connection_removal(&self) -> KeepAliveResult {
        let start = Instant::now();

        let result = std::panic::catch_unwind(|| {
            self.server.reset_counters();
            self.server.add_response(MockResponse {
                status: 200,
                headers: vec![
                    ("Content-Length".to_string(), "100".to_string()),
                    ("Connection".to_string(), "keep-alive".to_string()),
                ],
                body: b"complete body".to_vec(),
                close_after: false,
                malformed_body: true, // This will send shorter body than Content-Length
            });

            // Create transport that will receive malformed response
            let transport = MockTransport::new(self.server.clone());

            // Verify that malformed response would poison the connection
            assert_eq!(self.server.connections_created(), 1);

            true
        });

        let execution_time = start.elapsed().as_millis() as u64;

        match result {
            Ok(true) => KeepAliveResult {
                test_id: "RFC9112-POISONED-CONNECTION".to_string(),
                description: "Poisoned connection (bad body) removed from pool".to_string(),
                category: TestCategory::PoisonedConnection,
                requirement_level: RequirementLevel::Must,
                verdict: TestVerdict::Pass,
                error_message: None,
                execution_time_ms: execution_time,
            },
            Ok(false) | Err(_) => KeepAliveResult {
                test_id: "RFC9112-POISONED-CONNECTION".to_string(),
                description: "Poisoned connection (bad body) removed from pool".to_string(),
                category: TestCategory::PoisonedConnection,
                requirement_level: RequirementLevel::Must,
                verdict: TestVerdict::Fail,
                error_message: Some("Poisoned connection test failed".to_string()),
                execution_time_ms: execution_time,
            },
        }
    }

    /// Test HTTP/1.0 vs HTTP/1.1 default behavior (Requirement 6)
    #[allow(dead_code)]
    fn test_http_version_defaults(&self) -> KeepAliveResult {
        let start = Instant::now();

        let result = std::panic::catch_unwind(|| {
            // Test HTTP/1.0 default (close unless Keep-Alive header)
            let http10_default_close = true; // HTTP/1.0 defaults to close
            assert!(http10_default_close, "HTTP/1.0 should default to close");

            // Test HTTP/1.1 default (keep-alive unless Connection: close)
            let http11_default_keepalive = true; // HTTP/1.1 defaults to keep-alive
            assert!(http11_default_keepalive, "HTTP/1.1 should default to keep-alive");

            // Test HTTP/1.0 with explicit Keep-Alive header
            self.server.add_response(MockResponse {
                status: 200,
                headers: vec![
                    ("Connection".to_string(), "Keep-Alive".to_string()),
                    ("Keep-Alive".to_string(), "timeout=5".to_string()),
                ],
                body: b"HTTP/1.0 with keep-alive".to_vec(),
                close_after: false,
                malformed_body: false,
            });

            true
        });

        let execution_time = start.elapsed().as_millis() as u64;

        match result {
            Ok(true) => KeepAliveResult {
                test_id: "RFC9112-HTTP-VERSION-DEFAULTS".to_string(),
                description: "HTTP/1.0 defaults to close, HTTP/1.1 defaults to keep-alive".to_string(),
                category: TestCategory::HttpVersionCompat,
                requirement_level: RequirementLevel::Must,
                verdict: TestVerdict::Pass,
                error_message: None,
                execution_time_ms: execution_time,
            },
            Ok(false) | Err(_) => KeepAliveResult {
                test_id: "RFC9112-HTTP-VERSION-DEFAULTS".to_string(),
                description: "HTTP/1.0 defaults to close, HTTP/1.1 defaults to keep-alive".to_string(),
                category: TestCategory::HttpVersionCompat,
                requirement_level: RequirementLevel::Must,
                verdict: TestVerdict::Fail,
                error_message: Some("HTTP version defaults test failed".to_string()),
                execution_time_ms: execution_time,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Run the complete RFC 9112 HTTP/1.1 keep-alive conformance test suite
    #[test]
    #[allow(dead_code)]
    fn rfc9112_keepalive_complete_conformance_suite() {
        let harness = H1KeepAliveHarness::new();
        let results = harness.run_all_tests();

        let passed = results
            .iter()
            .filter(|r| r.verdict == TestVerdict::Pass)
            .count();
        let failed = results
            .iter()
            .filter(|r| r.verdict == TestVerdict::Fail)
            .count();
        let xfail = results
            .iter()
            .filter(|r| r.verdict == TestVerdict::ExpectedFailure)
            .count();
        let total = results.len();

        println!(
            "\nRFC 9112 HTTP/1.1 Keep-Alive Conformance: {passed}/{total} pass, {failed} fail, {xfail} expected-fail"
        );

        // Print detailed results
        for result in &results {
            println!(
                "  {} [{}]: {} - {}ms",
                result.test_id,
                match result.verdict {
                    TestVerdict::Pass => "PASS",
                    TestVerdict::Fail => "FAIL",
                    TestVerdict::Skipped => "SKIP",
                    TestVerdict::ExpectedFailure => "XFAIL",
                },
                result.description,
                result.execution_time_ms
            );
            if let Some(ref error) = result.error_message {
                println!("    Error: {}", error);
            }
        }

        // Assert no unexpected failures
        assert_eq!(failed, 0, "{failed} conformance tests failed unexpectedly");

        // Coverage requirement: ≥95% MUST clause coverage
        let must_tests: Vec<_> = results
            .iter()
            .filter(|r| r.requirement_level == RequirementLevel::Must)
            .collect();
        let must_passed = must_tests
            .iter()
            .filter(|r| r.verdict == TestVerdict::Pass)
            .count();
        let must_total = must_tests.len();
        let must_coverage = if must_total > 0 {
            (must_passed as f64 / must_total as f64) * 100.0
        } else {
            100.0
        };

        assert!(
            must_coverage >= 95.0,
            "MUST clause coverage too low: {must_coverage:.1}% (target: ≥95%)"
        );
    }

    /// Test basic keep-alive connection reuse behavior
    #[test]
    #[allow(dead_code)]
    fn test_basic_keepalive_reuse() {
        let harness = H1KeepAliveHarness::new();
        let result = harness.test_keep_alive_reuse();
        assert_eq!(result.verdict, TestVerdict::Pass);
    }

    /// Test connection close header enforcement
    #[test]
    #[allow(dead_code)]
    fn test_connection_close_enforcement() {
        let harness = H1KeepAliveHarness::new();
        let result = harness.test_connection_close();
        assert_eq!(result.verdict, TestVerdict::Pass);
    }

    /// Test idle connection timeout mechanics
    #[test]
    #[allow(dead_code)]
    fn test_idle_connection_timeout() {
        let harness = H1KeepAliveHarness::new();
        let result = harness.test_idle_timeout();
        assert_eq!(result.verdict, TestVerdict::Pass);
    }

    /// Test pool capacity bounds enforcement
    #[test]
    #[allow(dead_code)]
    fn test_pool_capacity_enforcement() {
        let harness = H1KeepAliveHarness::new();
        let result = harness.test_pool_capacity_bounds();
        assert_eq!(result.verdict, TestVerdict::Pass);
    }

    /// Test poisoned connection removal from pool
    #[test]
    #[allow(dead_code)]
    fn test_poisoned_connection_cleanup() {
        let harness = H1KeepAliveHarness::new();
        let result = harness.test_poisoned_connection_removal();
        assert_eq!(result.verdict, TestVerdict::Pass);
    }

    /// Test HTTP version default connection behavior
    #[test]
    #[allow(dead_code)]
    fn test_http_version_connection_defaults() {
        let harness = H1KeepAliveHarness::new();
        let result = harness.test_http_version_defaults();
        assert_eq!(result.verdict, TestVerdict::Pass);
    }

    /// Test custom pool configuration
    #[test]
    #[allow(dead_code)]
    fn test_custom_pool_configuration() {
        let custom_config = PoolConfig {
            max_connections_per_host: 1,
            max_total_connections: 2,
            idle_timeout: Duration::from_millis(50),
            cleanup_interval: Duration::from_millis(25),
        };

        let harness = H1KeepAliveHarness::new().with_pool_config(custom_config);
        let results = harness.run_all_tests();

        // Verify all tests still pass with custom configuration
        let all_passed = results.iter().all(|r| {
            matches!(r.verdict, TestVerdict::Pass | TestVerdict::ExpectedFailure)
        });
        assert!(all_passed, "Custom pool config should not break tests");
    }

    /// Test comprehensive RFC 9112 coverage
    #[test]
    #[allow(dead_code)]
    fn test_rfc9112_coverage_completeness() {
        let harness = H1KeepAliveHarness::new();
        let results = harness.run_all_tests();

        // Verify we test all 6 required behaviors
        assert_eq!(results.len(), 6, "Should test all 6 keep-alive requirements");

        // Verify we cover all test categories
        let categories: std::collections::HashSet<TestCategory> = results
            .iter()
            .map(|r| r.category.clone())
            .collect();

        let expected_categories = [
            TestCategory::KeepAliveReuse,
            TestCategory::ConnectionClose,
            TestCategory::IdleTimeout,
            TestCategory::PoolCapacity,
            TestCategory::PoisonedConnection,
            TestCategory::HttpVersionCompat,
        ];

        for expected in &expected_categories {
            assert!(
                categories.contains(expected),
                "Missing test category: {:?}",
                expected
            );
        }
    }
}
}
