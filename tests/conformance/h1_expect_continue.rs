//! HTTP/1.1 Expect: 100-continue conformance tests against the live H1 server.
//!
//! These tests pin RFC 9110 Section 10.1.1 behavior using the production
//! `Http1Server` expectation gate instead of a synthetic classifier. The older
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
