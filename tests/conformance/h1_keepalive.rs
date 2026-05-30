//! HTTP/1.1 keep-alive conformance tests against the live H1 server.
//!
//! These tests pin RFC 9112 connection persistence behavior using production
//! `Http1Server` request/response flow over an in-memory transport. The older
//! draft in-memory pool is preserved below as disabled archaeology.

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
