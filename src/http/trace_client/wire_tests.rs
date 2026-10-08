//! Real sockets exercise the production propagation and pooled request paths.

use super::*;
use crate::runtime::RuntimeBuilder;
use crate::types::CancelKind;
use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

const IO_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Clone, Debug)]
struct CapturedRequest {
    head: String,
    body: Vec<u8>,
}

impl CapturedRequest {
    fn values(&self, name: &str) -> Vec<&str> {
        self.head
            .lines()
            .skip(1)
            .filter_map(|line| line.split_once(':'))
            .filter(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.trim())
            .collect()
    }
}

struct Reply {
    wire: String,
    close: bool,
    delay: Duration,
}

impl Reply {
    fn ok(close: bool) -> Self {
        let connection = if close { "close" } else { "keep-alive" };
        Self {
            wire: format!(
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: {connection}\r\n\r\nok"
            ),
            close,
            delay: Duration::ZERO,
        }
    }

    fn redirect(location: &str) -> Self {
        Self {
            wire: format!(
                "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            ),
            close: true,
            delay: Duration::ZERO,
        }
    }
}

/// The listener and every accepted socket are bounded and the worker is joined,
/// including when an assertion unwinds the test. No process-global server leaks.
struct Server {
    address: SocketAddr,
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
    connections: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl Server {
    fn start(replies: Vec<Reply>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let connections = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let saved = Arc::clone(&requests);
        let accepted = Arc::clone(&connections);
        let stopping = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            let mut replies: VecDeque<_> = replies.into();
            while !stopping.load(Ordering::Acquire) && !replies.is_empty() {
                let mut stream = match listener.accept() {
                    Ok((stream, _)) => stream,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(error) => panic!("accept: {error}"),
                };
                accepted.fetch_add(1, Ordering::Relaxed);
                stream.set_nonblocking(false).unwrap();
                stream.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
                stream.set_write_timeout(Some(IO_TIMEOUT)).unwrap();
                let mut pending = Vec::new();
                while !stopping.load(Ordering::Acquire) && !replies.is_empty() {
                    let Ok(Some(request)) = read_request(&mut stream, &mut pending) else {
                        break;
                    };
                    saved.lock().unwrap().push(request);
                    let reply = replies.pop_front().unwrap();
                    thread::sleep(reply.delay);
                    if stream.write_all(reply.wire.as_bytes()).is_err() || reply.close {
                        break;
                    }
                }
            }
        });
        Self {
            address,
            requests,
            connections,
            stop,
            worker: Some(worker),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.address)
    }

    fn finish(mut self) -> (Vec<CapturedRequest>, usize) {
        self.stop.store(true, Ordering::Release);
        self.worker.take().unwrap().join().expect("server worker");
        let requests = self.requests.lock().unwrap().clone();
        (requests, self.connections.load(Ordering::Relaxed))
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn read_request(
    stream: &mut TcpStream,
    pending: &mut Vec<u8>,
) -> io::Result<Option<CapturedRequest>> {
    let mut scratch = [0_u8; 1024];
    let end = loop {
        if let Some(index) = pending.windows(4).position(|part| part == b"\r\n\r\n") {
            break index + 4;
        }
        if pending.len() > 64 * 1024 {
            return Err(io::Error::other("test request headers exceeded their bound"));
        }
        let count = stream.read(&mut scratch)?;
        if count == 0 {
            return Ok(None);
        }
        pending.extend_from_slice(&scratch[..count]);
    };
    let head = String::from_utf8(pending[..end].to_vec())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let body_len = head
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(key, _)| key.eq_ignore_ascii_case("content-length"))
        .map_or(Ok(0), |(_, value)| value.trim().parse::<usize>())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if body_len > 1024 * 1024 {
        return Err(io::Error::other("test request body exceeded its bound"));
    }
    let total = end + body_len;
    while pending.len() < total {
        let count = stream.read(&mut scratch)?;
        if count == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        pending.extend_from_slice(&scratch[..count]);
    }
    let body = pending[end..total].to_vec();
    let _ = pending.drain(..total);
    Ok(Some(CapturedRequest { head, body }))
}

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    RuntimeBuilder::current_thread()
        .build()
        .expect("current-thread runtime")
        .block_on(future)
}

fn parent() -> W3CTraceContext {
    let mut parent: W3CTraceContext =
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
            .parse()
            .unwrap();
    parent.tracestate = Some("vendor=preserved".into());
    parent.baggage.insert("tenant", "sensitive").unwrap();
    parent
}

#[test]
fn cloned_requests_get_distinct_children_and_reuse_the_shared_pool() {
    let server = Server::start(vec![Reply::ok(false), Reply::ok(true)]);
    let parent = parent();
    let mut config = HttpClientConfig::default();
    config.default_headers = vec![
        ("TRACEPARENT".into(), "stale".into()),
        ("Baggage".into(), "stale=secret".into()),
        ("X-Default".into(), "kept".into()),
    ];
    let client = TracedHttpClient::with_config(config);
    let clone = client.clone();
    let cx = Cx::for_testing();
    let builder = client
        .post(server.url("/items"), &parent)
        .headers([
            ("TraceParent", "wrong"),
            ("TraceState", "wrong=state"),
            ("baggage", "wrong=secret"),
        ])
        .header("X-Request", "kept")
        .json(&serde_json::json!({"answer": 42}))
        .unwrap()
        .timeout(IO_TIMEOUT);
    let (first, second) = block_on(async {
        let first = builder.clone().send(&cx).await.unwrap();
        assert_eq!(clone.pool_stats().idle_connections, 1);
        let second = builder.propagate_baggage(true).send(&cx).await.unwrap();
        (first, second)
    });
    assert_eq!(first.response.status, 200);
    assert_eq!(second.response.body, b"ok");
    assert_ne!(first.context.span_id, second.context.span_id);
    let (requests, connections) = server.finish();
    assert_eq!(connections, 1, "the cloned client observes the same live pool");
    assert_eq!(requests.len(), 2);
    for (request, result) in requests.iter().zip([&first, &second]) {
        let traceparent = result.context.to_traceparent();
        assert_eq!(request.values("traceparent"), vec![traceparent.as_str()]);
        assert_eq!(request.values("tracestate"), vec!["vendor=preserved"]);
        assert_eq!(request.values("X-Default"), vec!["kept"]);
        assert_eq!(request.values("X-Request"), vec!["kept"]);
        assert_eq!(request.body, br#"{"answer":42}"#);
        assert_eq!(result.context.trace_id, parent.trace_id);
        assert_eq!(result.context.parent_span_id, parent.span_id);
    }
    assert!(requests[0].values("baggage").is_empty());
    assert_eq!(requests[1].values("baggage"), vec!["tenant=sensitive"]);
}

#[test]
fn same_origin_redirect_preserves_one_logical_request_context() {
    let server = Server::start(vec![Reply::redirect("/final"), Reply::ok(true)]);
    let parent = parent();
    let client = TracedHttpClient::new();
    let cx = Cx::for_testing();
    let result = block_on(
        client
            .get(server.url("/start"), &parent)
            .propagate_baggage(true)
            .timeout(IO_TIMEOUT)
            .send(&cx),
    )
    .unwrap();
    assert_eq!(result.response.status, 200);
    let (requests, _) = server.finish();
    assert_eq!(requests.len(), 2);
    assert!(requests[1].head.starts_with("GET /final HTTP/1.1\r\n"));
    for request in requests {
        let traceparent = result.context.to_traceparent();
        assert_eq!(request.values("traceparent"), vec![traceparent.as_str()]);
        assert_eq!(request.values("baggage"), vec!["tenant=sensitive"]);
    }
}

#[test]
fn cross_origin_redirect_returns_without_contacting_the_other_origin() {
    let other = Server::start(vec![Reply::ok(true)]);
    let server = Server::start(vec![Reply::redirect(&other.url("/capture"))]);
    let parent = parent();
    let client = TracedHttpClient::new();
    let cx = Cx::for_testing();
    let result = block_on(
        client
            .get(server.url("/start"), &parent)
            .propagate_baggage(true)
            .timeout(IO_TIMEOUT)
            .send(&cx),
    )
    .unwrap();
    let (requests, _) = server.finish();
    let (other_requests, other_connections) = other.finish();
    assert_eq!(result.response.status, 302);
    assert_eq!(requests.len(), 1);
    assert!(other_requests.is_empty(), "trace context escaped its origin");
    assert_eq!(other_connections, 0);
}

#[test]
fn cancelled_context_never_contacts_the_server() {
    let server = Server::start(vec![Reply::ok(true)]);
    let parent = parent();
    let client = TracedHttpClient::new();
    let cx = Cx::for_testing();
    cx.cancel_fast(CancelKind::User);
    let result = block_on(client.get(server.url("/cancelled"), &parent).send(&cx));
    assert!(matches!(result, Err(TracedClientError::Http(error)) if error.is_cancelled()));
    let (requests, connections) = server.finish();
    assert!(requests.is_empty());
    assert_eq!(connections, 0);
}

#[test]
fn per_call_timeout_does_not_extend_the_client_deadline() {
    let mut reply = Reply::ok(true);
    reply.delay = Duration::from_millis(200);
    let server = Server::start(vec![reply]);
    let parent = parent();
    let mut config = HttpClientConfig::default();
    config.request_timeout = Some(Duration::from_millis(20));
    let client = TracedHttpClient::with_config(config);
    let cx = Cx::for_testing();
    let result = block_on(
        client
            .get(server.url("/slow"), &parent)
            .timeout(Duration::from_secs(5))
            .send(&cx),
    );
    assert!(matches!(
        result,
        Err(TracedClientError::Http(ClientError::DeadlineExceeded))
    ));
    let _ = server.finish();
}

async fn collect_streamed(
    mut streamed: TracedStreamingResponse,
) -> Result<Response, crate::http::h1::HttpError> {
    use crate::bytes::Buf;
    use crate::http::body::{Body, Frame};
    use std::future::poll_fn;
    use std::pin::Pin;

    let head = streamed.response.head;
    let mut response = Response {
        version: head.version,
        status: head.status,
        reason: head.reason,
        headers: head.headers,
        body: Vec::new(),
        trailers: Vec::new(),
    };
    while let Some(frame) =
        poll_fn(|cx| Pin::new(&mut streamed.response.body).poll_frame(cx)).await
    {
        match frame? {
            Frame::Data(mut data) => {
                while data.has_remaining() {
                    let bytes = data.chunk();
                    response.body.extend_from_slice(bytes);
                    data.advance(bytes.len());
                }
            }
            Frame::Trailers(trailers) => {
                for (name, value) in trailers.iter() {
                    response
                        .trailers
                        .push((name.as_str().to_owned(), value.to_str().unwrap().to_owned()));
                }
            }
        }
    }
    Ok(response)
}

#[test]
fn streaming_preserves_chunked_body_trailers_and_request_owned_context() {
    let server = Server::start(vec![Reply {
        wire: "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Checksum\r\nConnection: close\r\n\r\n2\r\nhe\r\n3\r\nllo\r\n0\r\nX-Checksum: matched\r\n\r\n".into(),
        close: true,
        delay: Duration::ZERO,
    }]);
    let parent = parent();
    let client = TracedHttpClient::new();
    let cx = Cx::for_testing();
    let (response, context) = block_on(async {
        let streamed = client
            .streaming_request_builder(Method::Post, server.url("/stream"), &parent)
            .headers([
                ("TraceParent", "stale"),
                ("TRACESTATE", "stale=value"),
                ("Baggage", "stale=private"),
                ("X-Request", "kept"),
            ])
            .json(&serde_json::json!({"stream": true}))
            .unwrap()
            .propagate_baggage(true)
            .send(&cx)
            .await
            .unwrap();
        let context = streamed.context.clone();
        (collect_streamed(streamed).await.unwrap(), context)
    });
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"hello");
    assert_eq!(response.trailers.len(), 1);
    assert!(response.trailers[0].0.eq_ignore_ascii_case("X-Checksum"));
    assert_eq!(response.trailers[0].1, "matched");
    assert_eq!(context.trace_id, parent.trace_id);
    assert_eq!(context.parent_span_id, parent.span_id);
    let (requests, connections) = server.finish();
    assert_eq!(connections, 1);
    assert_eq!(requests.len(), 1);
    let traceparent = context.to_traceparent();
    assert_eq!(requests[0].values("traceparent"), vec![traceparent.as_str()]);
    assert_eq!(requests[0].values("tracestate"), vec!["vendor=preserved"]);
    assert_eq!(requests[0].values("baggage"), vec!["tenant=sensitive"]);
    assert_eq!(requests[0].values("X-Request"), vec!["kept"]);
    assert_eq!(requests[0].body, br#"{"stream":true}"#);
}

#[test]
fn streaming_returns_the_head_before_a_truncated_body_fails() {
    let server = Server::start(vec![Reply {
        wire: "HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nhi".into(),
        close: true,
        delay: Duration::ZERO,
    }]);
    let parent = parent();
    let client = TracedHttpClient::new();
    let cx = Cx::for_testing();
    block_on(async {
        // A buffered implementation would fail here rather than exposing the
        // valid head and letting the caller independently consume the body.
        let streamed = client
            .get_streaming(server.url("/truncated"), &parent)
            .send(&cx)
            .await
            .expect("a valid response head is returned before draining the body");
        assert_eq!(streamed.response.head.status, 200);
        assert_eq!(streamed.context.trace_id, parent.trace_id);
        assert!(collect_streamed(streamed).await.is_err());
    });
    let (requests, _) = server.finish();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].values("baggage").is_empty());
}

#[test]
fn streaming_same_origin_redirect_keeps_one_logical_child_context() {
    let server = Server::start(vec![Reply::redirect("/final"), Reply::ok(true)]);
    let parent = parent();
    let client = TracedHttpClient::new();
    let cx = Cx::for_testing();
    let context = block_on(async {
        let streamed = client
            .get_streaming(server.url("/start"), &parent)
            .send(&cx)
            .await
            .unwrap();
        let context = streamed.context.clone();
        assert_eq!(collect_streamed(streamed).await.unwrap().body, b"ok");
        context
    });
    let (requests, _) = server.finish();
    assert_eq!(requests.len(), 2);
    assert!(requests[1].head.starts_with("GET /final HTTP/1.1\r\n"));
    let traceparent = context.to_traceparent();
    for request in requests {
        assert_eq!(request.values("traceparent"), vec![traceparent.as_str()]);
        assert!(request.values("baggage").is_empty());
    }
}

#[test]
fn streaming_cross_origin_redirect_never_contacts_the_other_origin() {
    let other = Server::start(vec![Reply::ok(true)]);
    let server = Server::start(vec![Reply::redirect(&other.url("/capture"))]);
    let parent = parent();
    let client = TracedHttpClient::new();
    let cx = Cx::for_testing();
    block_on(async {
        let streamed = client
            .get_streaming(server.url("/start"), &parent)
            .propagate_baggage(true)
            .send(&cx)
            .await
            .unwrap();
        assert_eq!(streamed.response.head.status, 302);
        assert!(collect_streamed(streamed).await.unwrap().body.is_empty());
    });
    let (requests, _) = server.finish();
    let (other_requests, other_connections) = other.finish();
    assert_eq!(requests.len(), 1);
    assert!(other_requests.is_empty());
    assert_eq!(other_connections, 0);
}

#[test]
fn cancelled_streaming_request_never_contacts_the_server() {
    let server = Server::start(vec![Reply::ok(true)]);
    let parent = parent();
    let client = TracedHttpClient::new();
    let cx = Cx::for_testing();
    cx.cancel_fast(CancelKind::User);
    let result = block_on(client.get_streaming(server.url("/cancelled"), &parent).send(&cx));
    assert!(matches!(result, Err(TracedClientError::Http(error)) if error.is_cancelled()));
    let (requests, connections) = server.finish();
    assert!(requests.is_empty());
    assert_eq!(connections, 0);
}

#[test]
fn streaming_head_exchange_obeys_the_configured_client_deadline() {
    let mut reply = Reply::ok(true);
    reply.delay = Duration::from_millis(200);
    let server = Server::start(vec![reply]);
    let parent = parent();
    let mut config = HttpClientConfig::default();
    config.request_timeout = Some(Duration::from_millis(20));
    let client = TracedHttpClient::with_config(config);
    let cx = Cx::for_testing();
    let result = block_on(client.get_streaming(server.url("/slow"), &parent).send(&cx));
    assert!(matches!(
        result,
        Err(TracedClientError::Http(ClientError::DeadlineExceeded))
    ));
    let _ = server.finish();
}
