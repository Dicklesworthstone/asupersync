//! HTTP/1.1 Expect: 100-continue conformance tests against the live H1 server.
//!
//! These tests pin RFC 9110 Section 10.1.1 behavior using the production
//! `Http1Server` expectation gate instead of a mock-only classifier. The older
//! draft is preserved below as disabled archaeology until it can be mined for
//! smaller follow-up cases.

use asupersync::http::h1::server::HostPolicy;
use asupersync::http::h1::types::{Request, Response};
use asupersync::http::h1::{Http1Config, Http1Server};
use asupersync::io::{AsyncRead, AsyncWrite, ReadBuf};
use asupersync::runtime::RuntimeBuilder;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

const BEAD_ID: &str = "asupersync-nax796";
const SUITE_ID: &str = "h1_expect_continue";

#[derive(Debug)]
struct ExpectCaseResult {
    scenario_id: &'static str,
    method: &'static str,
    headers: &'static str,
    body_shape: &'static str,
    expected_status: &'static str,
    actual_status: String,
    expected_connection_state: &'static str,
    actual_connection_state: String,
    verdict: &'static str,
    first_failure: String,
}

impl ExpectCaseResult {
    fn pass(
        scenario_id: &'static str,
        method: &'static str,
        headers: &'static str,
        body_shape: &'static str,
        expected_status: &'static str,
        expected_connection_state: &'static str,
    ) -> Self {
        Self {
            scenario_id,
            method,
            headers,
            body_shape,
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
            "bead_id={} suite_id={} scenario_id={} protocol_version=HTTP/1.1 method={} headers={} body_shape={} connection_reused=n/a cookie_case=n/a expected_status={} actual_status={} expected_connection_state={} actual_connection_state={} verdict={} first_failure={}",
            BEAD_ID,
            SUITE_ID,
            self.scenario_id,
            self.method,
            self.headers,
            self.body_shape,
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
            "HTTP/1 Expect: 100-continue conformance failed: {self:?}"
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

struct GatedBodyIo {
    head: Vec<u8>,
    body: Vec<u8>,
    release_marker: Vec<u8>,
    gated_polls: usize,
    written: Arc<Mutex<Vec<u8>>>,
}

impl GatedBodyIo {
    fn new(
        head: Vec<u8>,
        body: Vec<u8>,
        release_marker: Vec<u8>,
        written: Arc<Mutex<Vec<u8>>>,
    ) -> Self {
        Self {
            head,
            body,
            release_marker,
            gated_polls: 0,
            written,
        }
    }

    fn body_release_seen(&self) -> bool {
        let written = self.written.lock().unwrap();
        written
            .windows(self.release_marker.len())
            .any(|window| window == self.release_marker.as_slice())
    }
}

impl AsyncRead for GatedBodyIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.head.is_empty() {
            let n = buf.remaining().min(self.head.len());
            buf.put_slice(&self.head[..n]);
            self.head.drain(..n);
            return Poll::Ready(Ok(()));
        }

        if self.body.is_empty() {
            return Poll::Ready(Ok(()));
        }

        if self.body_release_seen() {
            let n = buf.remaining().min(self.body.len());
            buf.put_slice(&self.body[..n]);
            self.body.drain(..n);
            return Poll::Ready(Ok(()));
        }

        self.gated_polls += 1;
        let written_so_far = self.written.lock().unwrap().clone();
        assert!(
            self.gated_polls < 8,
            "request body stayed gated because the server did not emit the expected expectation response; wrote so far: {:?}",
            String::from_utf8_lossy(&written_so_far)
        );
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

impl AsyncWrite for GatedBodyIo {
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

fn h1_config() -> Http1Config {
    Http1Config::default()
        .host_policy(HostPolicy::allow_list(vec!["example.com".to_string()]))
        .keep_alive(false)
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

#[test]
fn expect_continue_unblocks_body_before_handler_runs() {
    let scenario = "H1_EXPECT_CONTINUE_BEFORE_BODY";
    let written = Arc::new(Mutex::new(Vec::new()));
    let seen_body = Arc::new(Mutex::new(Vec::new()));
    let io = GatedBodyIo::new(
        b"POST /upload HTTP/1.1\r\nHost: example.com\r\nExpect: 100-continue\r\nContent-Length: 5\r\nConnection: close\r\n\r\n".to_vec(),
        b"hello".to_vec(),
        b"HTTP/1.1 100 Continue\r\n\r\n".to_vec(),
        Arc::clone(&written),
    );
    let seen_body_for_handler = Arc::clone(&seen_body);
    let server = Http1Server::with_config(
        move |req| {
            let seen_body_for_handler = Arc::clone(&seen_body_for_handler);
            async move {
                *seen_body_for_handler.lock().unwrap() = req.body;
                Response::new(200, "OK", b"done")
            }
        },
        h1_config(),
    );

    let state = run_server(server, io);
    let output = written_text(&written);

    if state.requests_served == 1
        && *seen_body.lock().unwrap() == b"hello".to_vec()
        && output.starts_with("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n")
    {
        ExpectCaseResult::pass(
            scenario,
            "POST",
            "expect+content-length",
            "body_gated_until_100",
            "100,200",
            "closed_after_final",
        )
        .assert_pass();
    } else {
        ExpectCaseResult::fail(
            scenario,
            "POST",
            "expect+content-length",
            "body_gated_until_100",
            "100,200",
            format!(
                "served={} body={:?} output={:?}",
                state.requests_served,
                *seen_body.lock().unwrap(),
                output
            ),
            "closed_after_final",
            "unexpected_flow",
            "server did not emit 100 Continue before consuming the gated body",
        )
        .assert_pass();
    }
}

#[test]
fn eager_expect_continue_body_still_gets_single_interim_response() {
    let scenario = "H1_EXPECT_EAGER_BODY_SINGLE_100";
    let written = Arc::new(Mutex::new(Vec::new()));
    let seen_body = Arc::new(Mutex::new(Vec::new()));
    let io = TestIo::new(
        b"POST /upload HTTP/1.1\r\nHost: example.com\r\nExpect: 100-continue\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello".to_vec(),
        Arc::clone(&written),
    );
    let seen_body_for_handler = Arc::clone(&seen_body);
    let server = Http1Server::with_config(
        move |req| {
            let seen_body_for_handler = Arc::clone(&seen_body_for_handler);
            async move {
                *seen_body_for_handler.lock().unwrap() = req.body;
                Response::new(200, "OK", b"done")
            }
        },
        h1_config(),
    );

    let state = run_server(server, io);
    let output = written_text(&written);
    let continue_count = output.matches("HTTP/1.1 100 Continue\r\n\r\n").count();

    if state.requests_served == 1
        && *seen_body.lock().unwrap() == b"hello".to_vec()
        && continue_count == 1
        && output.starts_with("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n")
    {
        ExpectCaseResult::pass(
            scenario,
            "POST",
            "expect+content-length",
            "eager_body",
            "100,200",
            "single_interim_then_final",
        )
        .assert_pass();
    } else {
        ExpectCaseResult::fail(
            scenario,
            "POST",
            "expect+content-length",
            "eager_body",
            "100,200",
            format!(
                "served={} continue_count={} body={:?} output={:?}",
                state.requests_served,
                continue_count,
                *seen_body.lock().unwrap(),
                output
            ),
            "single_interim_then_final",
            "unexpected_flow",
            "eager body request did not receive exactly one 100 Continue before final response",
        )
        .assert_pass();
    }
}

#[test]
fn unsupported_expectation_is_rejected_before_body_and_handler() {
    let scenario = "H1_EXPECT_UNSUPPORTED_REJECTS";
    let written = Arc::new(Mutex::new(Vec::new()));
    let handler_called = Arc::new(AtomicBool::new(false));
    let io = GatedBodyIo::new(
        b"POST /upload HTTP/1.1\r\nHost: example.com\r\nExpect: fancy-feature\r\nContent-Length: 5\r\nConnection: close\r\n\r\n".to_vec(),
        b"hello".to_vec(),
        b"HTTP/1.1 417 Expectation Failed\r\n".to_vec(),
        Arc::clone(&written),
    );
    let handler_called_for_handler = Arc::clone(&handler_called);
    let server = Http1Server::with_config(
        move |_req| {
            handler_called_for_handler.store(true, Ordering::SeqCst);
            async move { Response::new(200, "OK", b"unexpected") }
        },
        h1_config(),
    );

    let state = run_server(server, io);
    let output = written_text(&written);

    if state.requests_served == 1
        && !handler_called.load(Ordering::SeqCst)
        && output.starts_with("HTTP/1.1 417 Expectation Failed\r\n")
        && !output.contains("100 Continue")
        && !output.contains("200 OK")
    {
        ExpectCaseResult::pass(
            scenario,
            "POST",
            "expect=unsupported",
            "body_gated_until_417",
            "417",
            "closed_after_reject",
        )
        .assert_pass();
    } else {
        ExpectCaseResult::fail(
            scenario,
            "POST",
            "expect=unsupported",
            "body_gated_until_417",
            "417",
            format!(
                "served={} handler_called={} output={:?}",
                state.requests_served,
                handler_called.load(Ordering::SeqCst),
                output
            ),
            "closed_after_reject",
            "unexpected_flow",
            "unsupported expectation reached the handler or did not produce 417",
        )
        .assert_pass();
    }
}

#[test]
fn http10_expect_continue_is_rejected_without_handler() {
    let scenario = "H1_EXPECT_HTTP10_REJECTS";
    let written = Arc::new(Mutex::new(Vec::new()));
    let handler_called = Arc::new(AtomicBool::new(false));
    let io = GatedBodyIo::new(
        b"POST /upload HTTP/1.0\r\nHost: example.com\r\nExpect: 100-continue\r\nContent-Length: 5\r\nConnection: close\r\n\r\n".to_vec(),
        b"hello".to_vec(),
        b"HTTP/1.0 417 Expectation Failed\r\n".to_vec(),
        Arc::clone(&written),
    );
    let handler_called_for_handler = Arc::clone(&handler_called);
    let server = Http1Server::with_config(
        move |_req| {
            handler_called_for_handler.store(true, Ordering::SeqCst);
            async move { Response::new(200, "OK", b"unexpected") }
        },
        h1_config(),
    );

    let state = run_server(server, io);
    let output = written_text(&written);

    if state.requests_served == 1
        && !handler_called.load(Ordering::SeqCst)
        && output.starts_with("HTTP/1.0 417 Expectation Failed\r\n")
        && !output.contains("100 Continue")
    {
        ExpectCaseResult::pass(
            scenario,
            "POST",
            "http10+expect",
            "body_gated_until_417",
            "417",
            "closed_after_reject",
        )
        .assert_pass();
    } else {
        ExpectCaseResult::fail(
            scenario,
            "POST",
            "http10+expect",
            "body_gated_until_417",
            "417",
            format!(
                "served={} handler_called={} output={:?}",
                state.requests_served,
                handler_called.load(Ordering::SeqCst),
                output
            ),
            "closed_after_reject",
            "unexpected_flow",
            "HTTP/1.0 Expect request was not rejected before the handler",
        )
        .assert_pass();
    }
}

#[test]
fn expect_continue_without_body_does_not_emit_interim_response() {
    let scenario = "H1_EXPECT_NO_BODY_NO_100";
    let written = Arc::new(Mutex::new(Vec::new()));
    let handler_called = Arc::new(AtomicBool::new(false));
    let io = TestIo::new(
        b"GET /metadata HTTP/1.1\r\nHost: example.com\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n".to_vec(),
        Arc::clone(&written),
    );
    let handler_called_for_handler = Arc::clone(&handler_called);
    let server = Http1Server::with_config(
        move |_req| {
            handler_called_for_handler.store(true, Ordering::SeqCst);
            async move { Response::new(200, "OK", b"done") }
        },
        h1_config(),
    );

    let state = run_server(server, io);
    let output = written_text(&written);

    if state.requests_served == 1
        && handler_called.load(Ordering::SeqCst)
        && output.starts_with("HTTP/1.1 200 OK\r\n")
        && !output.contains("100 Continue")
    {
        ExpectCaseResult::pass(
            scenario,
            "GET",
            "expect_without_body",
            "no_body",
            "200",
            "final_only",
        )
        .assert_pass();
    } else {
        ExpectCaseResult::fail(
            scenario,
            "GET",
            "expect_without_body",
            "no_body",
            "200",
            format!(
                "served={} handler_called={} output={:?}",
                state.requests_served,
                handler_called.load(Ordering::SeqCst),
                output
            ),
            "final_only",
            "unexpected_flow",
            "bodyless Expect request emitted an interim response or skipped the handler",
        )
        .assert_pass();
    }
}

#[rustfmt::skip]
#[cfg(any())]
mod stale_h1_expect_continue_suite {
#![allow(warnings)]
#![allow(clippy::all)]
//! HTTP/1.1 Expect: 100-continue Conformance Tests (RFC 9110 Section 10.1.1)
//!
//! Validates RFC 9110 Section 10.1.1 Expect header handling compliance:
//! - Expect: 100-continue triggers server interim response before reading body
//! - Server may reply final 4xx to discard request body
//! - Expectation-Failed (417) for unknown expectation tokens
//! - HTTP/1.0 clients without Expect handled transparently
//! - Conditional requests with Expect: 100-continue evaluated before 100 Continue
//!
//! # RFC 9110 Section 10.1.1 Expect Header
//!
//! The "Expect" header field in a request indicates a certain set of
//! behaviors (expectations) that need to be supported by the server in
//! order to properly handle this request.
//!
//! ```
//! Expect = #expectation
//! expectation = token [ "=" ( token / quoted-string ) parameters ]
//! ```
//!
//! # 100-continue Processing Rules
//!
//! 1. **MUST send 100 Continue** before reading body when Expect: 100-continue present
//! 2. **MAY send 417 Expectation Failed** for unknown expectation tokens
//! 3. **SHOULD send final response** (not 100) when rejecting the request
//! 4. **MUST handle** conditional headers before sending 100 Continue
//! 5. **HTTP/1.0 compatibility**: ignore Expect header in HTTP/1.0 requests

use asupersync::http::h1::types::{Method, Request, Response, Version};
use serde::{Deserialize, Serialize};
use std::time::Instant;

/// RFC 2119 requirement level for conformance testing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)]
pub enum RequirementLevel {
    Must,   // RFC 2119: MUST
    Should, // RFC 2119: SHOULD
    May,    // RFC 2119: MAY
}

/// Test result for a single Expect: 100-continue conformance requirement
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct ExpectContinueResult {
    pub test_id: String,
    pub description: String,
    pub category: TestCategory,
    pub requirement_level: RequirementLevel,
    pub verdict: TestVerdict,
    pub error_message: Option<String>,
    pub execution_time_ms: u64,
}

/// Conformance test categories for Expect: 100-continue handling
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)]
pub enum TestCategory {
    /// Basic 100-continue interim response processing
    InterimResponse,
    /// Final response rejection (4xx) handling
    BodyRejection,
    /// Unknown expectation token handling (417)
    UnknownExpectation,
    /// HTTP/1.0 compatibility mode
    Http10Compatibility,
    /// Conditional request evaluation before 100
    ConditionalProcessing,
    /// Protocol format compliance
    ProtocolFormat,
}

/// Test execution result
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)]
pub enum TestVerdict {
    Pass,
    Fail,
    Skipped,
    ExpectedFailure,
}

/// Helper function to classify expectation actions from headers
#[allow(dead_code)]
fn classify_expectation_from_headers(version: Version, headers: &[(String, String)]) -> ExpectationAction {
    let mut saw_expect = false;
    let mut saw_continue = false;
    let mut saw_unsupported = false;

    for (name, value) in headers {
        if !name.eq_ignore_ascii_case("expect") {
            continue;
        }
        saw_expect = true;

        for token in value
            .split(',')
            .map(str::trim)
            .filter(|token| !token.is_empty())
        {
            if token.eq_ignore_ascii_case("100-continue") {
                saw_continue = true;
            } else {
                saw_unsupported = true;
            }
        }
    }

    if !saw_expect {
        return ExpectationAction::None;
    }

    if saw_unsupported || version != Version::Http11 {
        return ExpectationAction::Reject;
    }

    if saw_continue {
        return ExpectationAction::Continue;
    }

    // Expect header present but no token content: treat as unsupported.
    ExpectationAction::Reject
}

/// Expectation action classification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum ExpectationAction {
    None,
    Continue,
    Reject,
}

/// Test harness for HTTP/1.1 Expect: 100-continue conformance
#[allow(dead_code)]
pub struct ExpectContinueConformanceHarness {
    results: Vec<ExpectContinueResult>,
}

#[allow(dead_code)]

impl ExpectContinueConformanceHarness {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self {
            results: Vec::new(),
        }
    }

    /// Run all Expect: 100-continue conformance tests
    #[allow(dead_code)]
    pub fn run_all_tests(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Category 1: Basic expectation classification
        self.test_expect_continue_classification();
        self.test_unknown_expectation_classification();
        self.test_http10_expectation_handling();

        // Category 2: Request structure validation
        self.test_conditional_header_interaction();
        self.test_multiple_expectation_tokens();

        // Category 3: Response generation
        self.test_response_status_codes();

        Ok(())
    }

    /// Get accumulated test results
    #[allow(dead_code)]
    pub fn results(&self) -> &[ExpectContinueResult] {
        &self.results
    }

    /// Test: Expect: 100-continue classification
    #[allow(dead_code)]
    fn test_expect_continue_classification(&mut self) {
        let start = Instant::now();

        // Test valid 100-continue expectation
        let headers = vec![
            ("Host".to_string(), "example.com".to_string()),
            ("Expect".to_string(), "100-continue".to_string()),
        ];

        let action = classify_expectation_from_headers(Version::Http11, &headers);
        let success = matches!(action, ExpectationAction::Continue);

        let test_result = ExpectContinueResult {
            test_id: "RFC9110-10.1.1-01".to_string(),
            description: "Expect: 100-continue triggers Continue action for HTTP/1.1".to_string(),
            category: TestCategory::InterimResponse,
            requirement_level: RequirementLevel::Must,
            verdict: if success { TestVerdict::Pass } else { TestVerdict::Fail },
            error_message: if !success { Some(format!("Expected Continue, got {:?}", action)) } else { None },
            execution_time_ms: start.elapsed().as_millis() as u64,
        };
        self.results.push(test_result);
    }

    /// Test: Unknown expectation token handling
    #[allow(dead_code)]
    fn test_unknown_expectation_classification(&mut self) {
        let start = Instant::now();

        let headers = vec![
            ("Host".to_string(), "example.com".to_string()),
            ("Expect".to_string(), "custom-extension".to_string()),
        ];

        let action = classify_expectation_from_headers(Version::Http11, &headers);
        let success = matches!(action, ExpectationAction::Reject);

        let test_result = ExpectContinueResult {
            test_id: "RFC9110-10.1.1-03".to_string(),
            description: "Unknown expectation tokens trigger Reject action".to_string(),
            category: TestCategory::UnknownExpectation,
            requirement_level: RequirementLevel::May,
            verdict: if success { TestVerdict::Pass } else { TestVerdict::Fail },
            error_message: if !success { Some(format!("Expected Reject, got {:?}", action)) } else { None },
            execution_time_ms: start.elapsed().as_millis() as u64,
        };
        self.results.push(test_result);
    }

    /// Test: HTTP/1.0 expectation handling
    #[allow(dead_code)]
    fn test_http10_expectation_handling(&mut self) {
        let start = Instant::now();

        let headers = vec![
            ("Host".to_string(), "example.com".to_string()),
            ("Expect".to_string(), "100-continue".to_string()),
        ];

        let action = classify_expectation_from_headers(Version::Http10, &headers);
        let success = matches!(action, ExpectationAction::Reject);

        let test_result = ExpectContinueResult {
            test_id: "RFC9110-10.1.1-04".to_string(),
            description: "HTTP/1.0 requests with Expect header should be rejected".to_string(),
            category: TestCategory::Http10Compatibility,
            requirement_level: RequirementLevel::Must,
            verdict: if success { TestVerdict::Pass } else { TestVerdict::Fail },
            error_message: if !success { Some(format!("Expected Reject for HTTP/1.0, got {:?}", action)) } else { None },
            execution_time_ms: start.elapsed().as_millis() as u64,
        };
        self.results.push(test_result);
    }

    /// Test: Conditional header interaction
    #[allow(dead_code)]
    fn test_conditional_header_interaction(&mut self) {
        let start = Instant::now();

        // Test request with both Expect and conditional headers
        let headers = vec![
            ("Host".to_string(), "example.com".to_string()),
            ("Expect".to_string(), "100-continue".to_string()),
            ("If-None-Match".to_string(), "\"existing-etag\"".to_string()),
        ];

        let action = classify_expectation_from_headers(Version::Http11, &headers);
        let has_expect = matches!(action, ExpectationAction::Continue);
        let has_conditional = headers.iter().any(|(name, _)| name.eq_ignore_ascii_case("if-none-match"));
        let success = has_expect && has_conditional;

        let test_result = ExpectContinueResult {
            test_id: "RFC9110-10.1.1-05".to_string(),
            description: "Conditional headers with Expect: 100-continue are properly handled".to_string(),
            category: TestCategory::ConditionalProcessing,
            requirement_level: RequirementLevel::Must,
            verdict: if success { TestVerdict::Pass } else { TestVerdict::Fail },
            error_message: if !success { Some("Conditional header interaction failed".to_string()) } else { None },
            execution_time_ms: start.elapsed().as_millis() as u64,
        };
        self.results.push(test_result);
    }

    /// Test: Multiple expectation tokens
    #[allow(dead_code)]
    fn test_multiple_expectation_tokens(&mut self) {
        let start = Instant::now();

        let headers = vec![
            ("Host".to_string(), "example.com".to_string()),
            ("Expect".to_string(), "100-continue, custom-token".to_string()),
        ];

        let action = classify_expectation_from_headers(Version::Http11, &headers);
        // Should reject due to unknown token "custom-token"
        let success = matches!(action, ExpectationAction::Reject);

        let test_result = ExpectContinueResult {
            test_id: "RFC9110-10.1.1-03b".to_string(),
            description: "Multiple expectation tokens with unknown should be rejected".to_string(),
            category: TestCategory::UnknownExpectation,
            requirement_level: RequirementLevel::May,
            verdict: if success { TestVerdict::Pass } else { TestVerdict::Fail },
            error_message: if !success { Some(format!("Expected Reject for mixed tokens, got {:?}", action)) } else { None },
            execution_time_ms: start.elapsed().as_millis() as u64,
        };
        self.results.push(test_result);
    }

    /// Test: Response status codes
    #[allow(dead_code)]
    fn test_response_status_codes(&mut self) {
        let start = Instant::now();

        // Test that appropriate response status codes can be generated
        let continue_response = Response::new(100, "Continue", Vec::new());
        let expectation_failed = Response::new(417, "Expectation Failed", Vec::new());
        let precondition_failed = Response::new(412, "Precondition Failed", Vec::new());

        let success = continue_response.status_code == 100
            && expectation_failed.status_code == 417
            && precondition_failed.status_code == 412;

        let test_result = ExpectContinueResult {
            test_id: "RFC9110-10.1.1-FORMAT".to_string(),
            description: "Correct response status codes for Expect handling".to_string(),
            category: TestCategory::ProtocolFormat,
            requirement_level: RequirementLevel::Must,
            verdict: if success { TestVerdict::Pass } else { TestVerdict::Fail },
            error_message: if !success { Some("Incorrect response status codes".to_string()) } else { None },
            execution_time_ms: start.elapsed().as_millis() as u64,
        };
        self.results.push(test_result);
    }
}

/// Generate conformance report for Expect: 100-continue handling
#[allow(dead_code)]
pub fn generate_conformance_report(results: &[ExpectContinueResult]) -> String {
    let total_tests = results.len();
    let passed = results.iter().filter(|r| r.verdict == TestVerdict::Pass).count();
    let failed = results.iter().filter(|r| r.verdict == TestVerdict::Fail).count();

    let mut report = String::new();
    report.push_str(&format!("# HTTP/1.1 Expect: 100-continue Conformance Report\n\n"));
    report.push_str(&format!("**Total Tests:** {}\n", total_tests));
    report.push_str(&format!("**Passed:** {} ({:.1}%)\n", passed, (passed as f64 / total_tests as f64) * 100.0));
    report.push_str(&format!("**Failed:** {} ({:.1}%)\n\n", failed, (failed as f64 / total_tests as f64) * 100.0));

    report.push_str("## Test Results by Category\n\n");

    let categories = [
        TestCategory::InterimResponse,
        TestCategory::BodyRejection,
        TestCategory::UnknownExpectation,
        TestCategory::Http10Compatibility,
        TestCategory::ConditionalProcessing,
        TestCategory::ProtocolFormat,
    ];

    for category in &categories {
        let category_results: Vec<_> = results.iter().filter(|r| r.category == *category).collect();
        if !category_results.is_empty() {
            report.push_str(&format!("### {:?}\n\n", category));

            for result in category_results {
                let status_icon = match result.verdict {
                    TestVerdict::Pass => "✅",
                    TestVerdict::Fail => "❌",
                    TestVerdict::Skipped => "⏭️",
                    TestVerdict::ExpectedFailure => "⚠️",
                };

                report.push_str(&format!(
                    "- {} **{}**: {} ({:?})\n",
                    status_icon, result.test_id, result.description, result.requirement_level
                ));

                if let Some(error) = &result.error_message {
                    report.push_str(&format!("  - Error: {}\n", error));
                }
            }
            report.push_str("\n");
        }
    }

    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(dead_code)]
    fn test_expect_continue_conformance() {
        let mut harness = ExpectContinueConformanceHarness::new();

        // Run basic conformance tests
        harness.run_all_tests().unwrap();

        let results = harness.results();
        assert!(!results.is_empty(), "Should have test results");

        // Verify we have tests for all major categories
        let categories: std::collections::HashSet<_> = results.iter().map(|r| r.category.clone()).collect();
        assert!(categories.contains(&TestCategory::InterimResponse));
        assert!(categories.contains(&TestCategory::UnknownExpectation));
        assert!(categories.contains(&TestCategory::Http10Compatibility));

        // Generate and verify report
        let report = generate_conformance_report(results);
        assert!(report.contains("HTTP/1.1 Expect: 100-continue Conformance Report"));
        assert!(report.contains("Total Tests:"));

        println!("Conformance Report:\n{}", report);
    }

    #[test]
    #[allow(dead_code)]
    fn test_expectation_classification() {
        // Test basic expectation classification logic
        let headers_continue = vec![
            ("Host".to_string(), "example.com".to_string()),
            ("Expect".to_string(), "100-continue".to_string()),
        ];
        let action = classify_expectation_from_headers(Version::Http11, &headers_continue);
        assert!(matches!(action, ExpectationAction::Continue));

        // Test unknown expectation
        let headers_unknown = vec![
            ("Host".to_string(), "example.com".to_string()),
            ("Expect".to_string(), "custom-token".to_string()),
        ];
        let action = classify_expectation_from_headers(Version::Http11, &headers_unknown);
        assert!(matches!(action, ExpectationAction::Reject));

        // Test HTTP/1.0
        let action = classify_expectation_from_headers(Version::Http10, &headers_continue);
        assert!(matches!(action, ExpectationAction::Reject));
    }
}
}
