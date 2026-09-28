//! Native HTTP/2 request streaming through the production listener and Router.
//!
//! The client uses the public HTTP/2 connection state machine over real TCP.
//! Parked-body signals and received sibling responses establish the state
//! before END_STREAM, cancellation, and capacity-release operations.

#![cfg(all(not(target_arch = "wasm32"), feature = "http2-streaming"))]

use std::future::{Future, poll_fn};
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::{Duration, Instant};

use asupersync::bytes::{Buf, Bytes};
use asupersync::channel::oneshot;
use asupersync::codec::Framed;
use asupersync::cx::Cx;
use asupersync::http::body::{Body, Frame as BodyFrame};
use asupersync::http::h1::server::HostPolicy;
use asupersync::http::h1::stream::IncomingBodyError;
use asupersync::http::h2::connection::{CLIENT_PREFACE, ReceivedFrame};
use asupersync::http::h2::listener::{Http2Listener, Http2StreamingListenerConfig};
use asupersync::http::h2::{
    Connection, ConnectionState, ErrorCode, Frame, FrameCodec, Header, Settings,
};
use asupersync::io::AsyncWriteExt;
use asupersync::net::TcpStream;
use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::stream::StreamExt;
use asupersync::web::{
    AsyncCxFnHandler1, FnHandler, RequestBodyPolicy, Response, Router, StatusCode,
    StreamingRawBody, get, post,
};
use futures_lite::future::zip;

const INITIAL_WINDOW: usize = 65_535;

fn run(workers: usize, future: impl Future<Output = ()> + 'static) {
    let builder = if workers == 1 {
        RuntimeBuilder::current_thread()
    } else {
        RuntimeBuilder::multi_thread()
            .worker_threads(workers)
            .with_sharded_state(true)
    };
    let runtime = builder
        .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
        .build()
        .unwrap();
    runtime.block_on(async move {
        let cx = Cx::current().expect("native root context");
        asupersync::time::timeout(cx.now(), Duration::from_secs(30), future)
            .await
            .expect("HTTP/2 streaming workflow watchdog");
    });

    // The block_on root must finish before quiescence can be observed. These
    // waits are cleanup bounds, never witnesses for a concurrency assertion.
    let started = Instant::now();
    while !runtime.is_quiescent() {
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "native tasks must retire: {:?}",
            runtime
                .task_inspector(Default::default())
                .list_active_tasks(),
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(
        runtime
            .task_inspector(Default::default())
            .list_tasks()
            .is_empty()
    );
    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
    assert_eq!(runtime.draining_region_count(), 0);
}

fn config() -> Http2StreamingListenerConfig {
    let mut config = Http2StreamingListenerConfig::default();
    config.listener = config
        .listener
        .host_policy(HostPolicy::allow_list(vec!["localhost".to_owned()]))
        .drain_timeout(Duration::from_secs(2))
        .hard_drain_timeout(Duration::from_secs(5))
        .max_body_size(4 * INITIAL_WINDOW);
    config.request_body_buffer_bytes = NonZeroUsize::new(INITIAL_WINDOW).unwrap();
    config
}

struct Client {
    wire: Framed<TcpStream, FrameCodec>,
    connection: Connection,
}

impl Client {
    async fn connect(address: std::net::SocketAddr, settings: Settings) -> Self {
        let mut tcp = TcpStream::connect(address).await.expect("connect real TCP");
        tcp.write_all(CLIENT_PREFACE).await.expect("write preface");
        let mut client = Self {
            wire: Framed::new(tcp, FrameCodec::new()),
            connection: Connection::client(settings),
        };
        client.connection.queue_initial_settings();
        client.flush().await;
        while client.connection.state() == ConnectionState::Handshaking {
            assert!(client.receive().await.0.is_none());
        }
        client
    }

    async fn flush(&mut self) {
        while let Some(frame) = self.connection.next_frame() {
            poll_fn(|cx| self.wire.poll_ready(cx)).await.unwrap();
            self.wire.start_send(frame).unwrap();
        }
        poll_fn(|cx| self.wire.poll_flush(cx)).await.unwrap();
    }

    async fn receive(&mut self) -> (Option<ReceivedFrame>, Option<(u32, u32)>) {
        let frame = self
            .wire
            .next()
            .await
            .expect("server TCP stayed open")
            .unwrap();
        let capacity = match &frame {
            Frame::WindowUpdate(update) => Some((update.stream_id, update.increment)),
            _ => None,
        };
        let received = self
            .connection
            .process_frame(frame)
            .expect("valid server frame");
        self.flush().await;
        (received, capacity)
    }

    async fn open(&mut self, method: &str, path: &str, length: Option<usize>, end: bool) -> u32 {
        let mut headers = vec![
            Header::new(":method", method),
            Header::new(":scheme", "http"),
            Header::new(":path", path),
            Header::new(":authority", "localhost"),
        ];
        if let Some(length) = length {
            headers.push(Header::new("content-length", length.to_string()));
        }
        let stream = self.connection.open_stream(headers, end).unwrap();
        self.flush().await;
        stream
    }

    async fn data(&mut self, stream: u32, data: impl Into<Bytes>, end: bool) {
        self.connection.send_data(stream, data.into(), end).unwrap();
        self.flush().await;
    }

    async fn response(&mut self, stream: u32, status: &str, expected_body: &[u8]) {
        let mut body = Vec::new();
        let mut headers_seen = false;
        loop {
            match self.receive().await.0 {
                Some(ReceivedFrame::Headers {
                    stream_id,
                    headers,
                    end_stream,
                }) => {
                    assert_eq!(stream_id, stream);
                    assert!(!headers_seen, "unexpected trailing response HEADERS");
                    assert_eq!(
                        headers
                            .iter()
                            .find(|header| header.name == ":status")
                            .map(|header| header.value.as_str()),
                        Some(status),
                    );
                    headers_seen = true;
                    if end_stream {
                        break;
                    }
                }
                Some(ReceivedFrame::Data {
                    stream_id,
                    data,
                    end_stream,
                }) => {
                    assert_eq!(stream_id, stream);
                    assert!(headers_seen);
                    body.extend_from_slice(&data);
                    if end_stream {
                        break;
                    }
                }
                None => {}
                event => panic!("unexpected response event: {event:?}"),
            }
        }
        assert!(headers_seen);
        assert_eq!(body, expected_body);
    }

    async fn reset(&mut self, stream: u32, expected: ErrorCode) {
        loop {
            match self.receive().await.0 {
                Some(ReceivedFrame::Reset {
                    stream_id,
                    error_code,
                }) => {
                    assert_eq!(stream_id, stream);
                    assert_eq!(error_code, expected);
                    return;
                }
                None => {}
                event => panic!("failed request must reset, not return success: {event:?}"),
            }
        }
    }

    async fn survivor(&mut self) {
        let sibling = self.open("GET", "/survivor", None, true).await;
        self.response(sibling, "200", b"survived").await;
    }
}

async fn exercise<F, Fut>(router: Router, workflow: F)
where
    F: FnOnce(Client, Arc<AtomicUsize>) -> Fut,
    Fut: Future<Output = Client>,
{
    exercise_with_config(router, config(), workflow).await;
}

async fn exercise_with_config<F, Fut>(
    router: Router,
    config: Http2StreamingListenerConfig,
    workflow: F,
) where
    F: FnOnce(Client, Arc<AtomicUsize>) -> Fut,
    Fut: Future<Output = Client>,
{
    exercise_with_client_settings(router, config, Settings::client(), workflow).await;
}

async fn exercise_with_client_settings<F, Fut>(
    router: Router,
    config: Http2StreamingListenerConfig,
    client_settings: Settings,
    workflow: F,
) where
    F: FnOnce(Client, Arc<AtomicUsize>) -> Fut,
    Fut: Future<Output = Client>,
{
    let runtime = Runtime::current_handle().expect("native runtime handle");
    let (handler, config) = router
        .without_default_trace()
        .into_http2_streaming_parts(config);
    let listener = Http2Listener::bind_streaming_with_config("127.0.0.1:0", handler, config)
        .await
        .expect("bind production streaming listener");
    let address = listener.local_addr().unwrap();
    let manager = listener.connection_manager().clone();
    let in_flight = listener.in_flight_requests();
    let client_in_flight = Arc::clone(&in_flight);
    let serving = listener.run_streaming(&runtime);
    let client = async {
        let client = Client::connect(address, client_settings).await;
        let client = workflow(client, client_in_flight).await;
        drop(client);
        assert!(manager.begin_drain(Duration::from_secs(2)));
    };
    let (stats, ()) = zip(serving, client).await;
    let report = stats
        .unwrap()
        .drain_report
        .expect("request-aware drain report");
    assert!(report.reached_quiescence, "{report}");
    assert_eq!(in_flight.load(Ordering::SeqCst), 0);
    assert_eq!(manager.active_count(), 0);
}

fn with_survivor(router: Router) -> Router {
    router.route(
        "/survivor",
        get(FnHandler::new(|| Response::new(StatusCode::OK, "survived"))),
    )
}

async fn next_after_pending(
    body: &mut StreamingRawBody,
    request_cx: &Cx,
    parked: oneshot::Sender<Cx>,
) -> Option<Result<BodyFrame<<StreamingRawBody as Body>::Data>, IncomingBodyError>> {
    let mut parked = Some(parked);
    let frame = poll_fn(|cx| {
        let poll = Pin::new(&mut *body).poll_frame(cx);
        if poll.is_pending() {
            assert!(!body.is_end_stream());
            if let Some(signal) = parked.take() {
                signal.send(request_cx, request_cx.clone()).unwrap();
            }
        }
        poll
    })
    .await;
    assert!(
        parked.is_none(),
        "operation must observe a parked live body"
    );
    frame
}

async fn collect(body: &mut StreamingRawBody) -> Result<Vec<u8>, IncomingBodyError> {
    let mut data = Vec::new();
    while let Some(frame) = poll_fn(|cx| Pin::new(&mut *body).poll_frame(cx)).await {
        match frame? {
            BodyFrame::Data(bytes) => data.extend_from_slice(bytes.chunk()),
            BodyFrame::Trailers(_) => panic!("unexpected trailers"),
        }
    }
    Ok(data)
}

async fn wait_region_closed(request_cx: &Cx) {
    let diagnostics = Runtime::current_handle().unwrap().diagnostics().unwrap();
    poll_fn(|cx| {
        if diagnostics
            .explain_region_open(request_cx.region_id())
            .region_state
            .is_none()
        {
            Poll::Ready(())
        } else {
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    })
    .await;
}

async fn wait_requests_drained(in_flight: &AtomicUsize) {
    poll_fn(|cx| {
        if in_flight.load(Ordering::SeqCst) == 0 {
            Poll::Ready(())
        } else {
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    })
    .await;
}

#[test]
fn h2_router_consumes_upload_prefix_before_end_stream() {
    for workers in [1, 2] {
        for declared in [None, Some(11)] {
            run(workers, async move {
                let cx = Cx::current().unwrap();
                let (parked_tx, mut parked_rx) = oneshot::channel();
                let parked = Arc::new(Mutex::new(Some(parked_tx)));
                let router = Router::new().route(
                    "/upload",
                    post(AsyncCxFnHandler1::<_, StreamingRawBody>::new(
                        move |request_cx: Cx, mut body: StreamingRawBody| {
                            let parked = parked.lock().unwrap().take().unwrap();
                            async move {
                                let first = poll_fn(|cx| Pin::new(&mut body).poll_frame(cx))
                                    .await
                                    .unwrap()
                                    .unwrap();
                                assert_eq!(first.into_data().unwrap().chunk(), b"prefix-");
                                let next = next_after_pending(&mut body, &request_cx, parked)
                                    .await
                                    .unwrap()
                                    .unwrap();
                                assert_eq!(next.into_data().unwrap().chunk(), b"tail");
                                assert!(collect(&mut body).await.unwrap().is_empty());
                                Response::new(StatusCode::OK, "streamed")
                            }
                        },
                    )),
                );
                exercise(router, move |mut client, _| async move {
                    let stream = client.open("POST", "/upload", declared, false).await;
                    client
                        .data(stream, Bytes::from_static(b"prefix-"), false)
                        .await;
                    let request_cx = parked_rx.recv(&cx).await.unwrap();
                    assert_ne!(request_cx.task_id(), cx.task_id());
                    assert_ne!(request_cx.region_id(), cx.region_id());
                    client.data(stream, Bytes::from_static(b"tail"), true).await;
                    client.response(stream, "200", b"streamed").await;
                    wait_region_closed(&request_cx).await;
                    client
                })
                .await;
            });
        }
    }
}

#[test]
fn h2_router_zero_content_length_waits_for_end_stream() {
    for workers in [1, 2] {
        run(workers, async {
            let cx = Cx::current().unwrap();
            let (parked_tx, mut parked_rx) = oneshot::channel();
            let parked = Arc::new(Mutex::new(Some(parked_tx)));
            let router = Router::new().route(
                "/empty",
                post(AsyncCxFnHandler1::<_, StreamingRawBody>::new(
                    move |request_cx: Cx, mut body: StreamingRawBody| {
                        let parked = parked.lock().unwrap().take().unwrap();
                        async move {
                            assert!(
                                next_after_pending(&mut body, &request_cx, parked)
                                    .await
                                    .is_none()
                            );
                            Response::new(StatusCode::OK, "explicit end")
                        }
                    },
                )),
            );
            exercise(router, move |mut client, _| async move {
                let stream = client.open("POST", "/empty", Some(0), false).await;
                let request_cx = parked_rx.recv(&cx).await.unwrap();
                client.data(stream, Bytes::new(), true).await;
                client.response(stream, "200", b"explicit end").await;
                wait_region_closed(&request_cx).await;
                client
            })
            .await;
        });
    }
}

#[test]
fn h2_router_request_trailers_follow_live_data_and_close_the_body() {
    for workers in [1, 2] {
        run(workers, async {
            let cx = Cx::current().unwrap();
            let (parked_tx, mut parked_rx) = oneshot::channel();
            let parked = Arc::new(Mutex::new(Some(parked_tx)));
            let router = Router::new().route(
                "/trailers",
                post(AsyncCxFnHandler1::<_, StreamingRawBody>::new(
                    move |request_cx: Cx, mut body: StreamingRawBody| {
                        let parked = parked.lock().unwrap().take().unwrap();
                        async move {
                            let first = poll_fn(|cx| Pin::new(&mut body).poll_frame(cx))
                                .await
                                .unwrap()
                                .unwrap();
                            assert_eq!(first.into_data().unwrap().chunk(), b"body");
                            let trailers = next_after_pending(&mut body, &request_cx, parked)
                                .await
                                .unwrap()
                                .unwrap()
                                .into_trailers()
                                .unwrap();
                            let fields: Vec<_> = trailers
                                .iter()
                                .map(|(name, value)| (name.as_str(), value.as_bytes()))
                                .collect();
                            assert_eq!(
                                fields,
                                vec![("x-part", &b"one"[..]), ("x-part", &b"two"[..])]
                            );
                            assert!(collect(&mut body).await.unwrap().is_empty());
                            Response::new(StatusCode::OK, "trailers delivered")
                        }
                    },
                )),
            );
            exercise(router, move |mut client, _| async move {
                let stream = client.open("POST", "/trailers", Some(4), false).await;
                client
                    .data(stream, Bytes::from_static(b"body"), false)
                    .await;
                let request_cx = parked_rx.recv(&cx).await.unwrap();
                // HTTP/2 trailers themselves carry END_STREAM. Waiting for
                // them must not complete merely because Content-Length is met.
                client
                    .connection
                    .send_headers(
                        stream,
                        vec![Header::new("x-part", "one"), Header::new("x-part", "two")],
                        true,
                    )
                    .unwrap();
                client.flush().await;
                client.response(stream, "200", b"trailers delivered").await;
                wait_region_closed(&request_cx).await;
                client
            })
            .await;
        });
    }
}

#[test]
fn h2_router_withholds_stream_credit_until_consumption_while_sibling_progresses() {
    for workers in [1, 2] {
        run(workers, async {
            let cx = Cx::current().unwrap();
            let (entered_tx, mut entered_rx) = oneshot::channel();
            let entered = Arc::new(Mutex::new(Some(entered_tx)));
            let (resume_tx, resume_rx) = oneshot::channel();
            let resume = Arc::new(Mutex::new(Some(resume_rx)));
            let router = with_survivor(Router::new().route(
                "/bounded",
                post(AsyncCxFnHandler1::<_, StreamingRawBody>::new(
                    move |request_cx: Cx, mut body: StreamingRawBody| {
                        let entered = entered.lock().unwrap().take().unwrap();
                        let mut resume = resume.lock().unwrap().take().unwrap();
                        async move {
                            entered.send(&request_cx, request_cx.clone()).unwrap();
                            resume.recv(&request_cx).await.unwrap();
                            let data = collect(&mut body).await.unwrap();
                            assert_eq!(data.len(), INITIAL_WINDOW + 127);
                            assert!(data[..INITIAL_WINDOW].iter().all(|byte| *byte == 7));
                            assert!(data[INITIAL_WINDOW..].iter().all(|byte| *byte == 9));
                            assert!(body.queued_bytes_peak() <= INITIAL_WINDOW);
                            Response::new(StatusCode::OK, "resumed")
                        }
                    },
                )),
            ));
            exercise(router, move |mut client, in_flight| async move {
                let stream = client.open("POST", "/bounded", None, false).await;
                let request_cx = entered_rx.recv(&cx).await.unwrap();
                assert_eq!(
                    client.connection.stream(stream).unwrap().send_window(),
                    i32::try_from(INITIAL_WINDOW).unwrap()
                );
                client
                    .data(stream, Bytes::from(vec![7; INITIAL_WINDOW]), false)
                    .await;
                // A response to later HEADERS witnesses that the server has
                // parsed all preceding DATA while the upload consumer is gated.
                client.survivor().await;
                assert_eq!(client.connection.available_send_capacity(stream), 0);
                assert!(in_flight.load(Ordering::SeqCst) >= 1);
                client.data(stream, Bytes::from(vec![9; 127]), true).await;
                assert!(client.connection.has_pending_frames_for_stream(stream));
                assert_eq!(client.connection.available_send_capacity(stream), 0);
                resume_tx.send(&cx, ()).unwrap();
                loop {
                    let (event, capacity) = client.receive().await;
                    assert!(
                        event.is_none(),
                        "response cannot precede the blocked tail: {event:?}"
                    );
                    if let Some((id, increment)) = capacity {
                        if id == stream {
                            assert!(increment > 0);
                            break;
                        }
                    }
                }
                assert!(!client.connection.has_pending_frames_for_stream(stream));
                client.response(stream, "200", b"resumed").await;
                wait_region_closed(&request_cx).await;
                client
            })
            .await;
        });
    }
}

struct Retired(Arc<AtomicUsize>);

impl Drop for Retired {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn h2_router_reset_length_and_live_limit_errors_reclaim_parked_request_regions() {
    for workers in [1, 2] {
        for case in ["reset", "short", "long", "limit"] {
            run(workers, async move {
                let cx = Cx::current().unwrap();
                let terminal = Arc::new(Mutex::new(None));
                let handler_terminal = Arc::clone(&terminal);
                let retired = Arc::new(AtomicUsize::new(0));
                let handler_retired = Arc::clone(&retired);
                let (parked_tx, mut parked_rx) = oneshot::channel();
                let parked = Arc::new(Mutex::new(Some(parked_tx)));
                let router = with_survivor(
                    Router::new().route(
                        "/failure",
                        post(AsyncCxFnHandler1::<_, StreamingRawBody>::new(
                            move |request_cx: Cx, mut body: StreamingRawBody| {
                                let parked = parked.lock().unwrap().take().unwrap();
                                let terminal = Arc::clone(&handler_terminal);
                                let retired = Arc::clone(&handler_retired);
                                async move {
                                    let _retired = Retired(retired);
                                    let first =
                                        next_after_pending(&mut body, &request_cx, parked).await;
                                    let error = match first {
                                        Some(Err(error)) => error,
                                        Some(Ok(BodyFrame::Data(_))) => {
                                            collect(&mut body).await.unwrap_err()
                                        }
                                        other => panic!(
                                            "malformed upload must produce a typed error: {other:?}"
                                        ),
                                    };
                                    *terminal.lock().unwrap() = Some(error);
                                    Response::new(StatusCode::OK, "must not become success")
                                }
                            },
                        ))
                        .with_body_policy(
                            RequestBodyPolicy::new().max_total_body_size(if case == "limit" {
                                8
                            } else {
                                4 * INITIAL_WINDOW
                            }),
                        ),
                    ),
                );
                exercise(router, move |mut client, in_flight| async move {
                    let declared = match case {
                        "short" => Some(9),
                        "long" => Some(0),
                        _ => None,
                    };
                    let stream = client.open("POST", "/failure", declared, false).await;
                    let request_cx = parked_rx.recv(&cx).await.unwrap();
                    assert_eq!(retired.load(Ordering::SeqCst), 0);
                    if case == "reset" {
                        client.connection.reset_stream(stream, ErrorCode::Cancel);
                        client.flush().await;
                    } else if case == "limit" {
                        client
                            .data(stream, Bytes::from_static(b"too large"), true)
                            .await;
                        client.reset(stream, ErrorCode::EnhanceYourCalm).await;
                    } else {
                        client
                            .data(stream, Bytes::from_static(b"invalid"), true)
                            .await;
                        client.reset(stream, ErrorCode::ProtocolError).await;
                    }
                    wait_region_closed(&request_cx).await;
                    wait_requests_drained(&in_flight).await;
                    assert_eq!(retired.load(Ordering::SeqCst), 1);
                    assert_eq!(
                        *terminal.lock().unwrap(),
                        Some(if case == "reset" {
                            IncomingBodyError::ClientAborted
                        } else if case == "limit" {
                            IncomingBodyError::BodyTooLarge {
                                actual: Some(9),
                                limit: 8,
                            }
                        } else {
                            IncomingBodyError::BadContentLength
                        })
                    );
                    assert_eq!(in_flight.load(Ordering::SeqCst), 0);
                    client.survivor().await;
                    client
                })
                .await;
            });
        }
    }
}

#[test]
fn h2_router_early_body_drop_flushes_response_before_no_error_reset() {
    for workers in [1, 2] {
        run(workers, async {
            let cx = Cx::current().unwrap();
            let (dropped_tx, mut dropped_rx) = oneshot::channel();
            let dropped = Arc::new(Mutex::new(Some(dropped_tx)));
            let (respond_tx, respond_rx) = oneshot::channel();
            let respond = Arc::new(Mutex::new(Some(respond_rx)));
            let router = with_survivor(Router::new().route(
                "/early",
                post(AsyncCxFnHandler1::<_, StreamingRawBody>::new(
                    move |request_cx: Cx, body: StreamingRawBody| {
                        let dropped = dropped.lock().unwrap().take().unwrap();
                        let mut respond = respond.lock().unwrap().take().unwrap();
                        async move {
                            drop(body);
                            dropped.send(&request_cx, request_cx.clone()).unwrap();
                            respond.recv(&request_cx).await.unwrap();
                            assert!(!request_cx.is_cancel_requested());
                            Response::new(StatusCode::OK, "early response")
                        }
                    },
                )),
            ));
            exercise(router, move |mut client, _| async move {
                let stream = client.open("POST", "/early", None, false).await;
                let request_cx = dropped_rx.recv(&cx).await.unwrap();
                client
                    .data(stream, Bytes::from_static(b"unread"), false)
                    .await;
                client.survivor().await;
                respond_tx.send(&cx, ()).unwrap();
                client.response(stream, "200", b"early response").await;
                client.reset(stream, ErrorCode::NoError).await;
                wait_region_closed(&request_cx).await;
                client.survivor().await;
                client
            })
            .await;
        });
    }
}

#[test]
fn h2_router_static_body_policy_rejects_declared_size_at_headers() {
    run(2, async {
        let calls = Arc::new(AtomicUsize::new(0));
        let handler_calls = Arc::clone(&calls);
        let router = with_survivor(
            Router::new().route(
                "/limited",
                post(AsyncCxFnHandler1::<_, StreamingRawBody>::new(
                    move |_cx: Cx, _body: StreamingRawBody| {
                        handler_calls.fetch_add(1, Ordering::SeqCst);
                        async { Response::new(StatusCode::OK, "must not be admitted") }
                    },
                ))
                .with_body_policy(RequestBodyPolicy::new().max_total_body_size(8)),
            ),
        );
        exercise(router, move |mut client, in_flight| async move {
            let stream = client.open("POST", "/limited", Some(9), false).await;
            // Only HEADERS have been transmitted: rejection must not wait for
            // DATA/END_STREAM or call a handler with a newly allocated body.
            let mut status = None;
            loop {
                match client.receive().await.0 {
                    Some(ReceivedFrame::Headers {
                        stream_id,
                        headers,
                        end_stream,
                    }) => {
                        assert_eq!(stream_id, stream);
                        status = headers
                            .into_iter()
                            .find(|header| header.name == ":status")
                            .map(|header| header.value);
                        if end_stream {
                            break;
                        }
                    }
                    Some(ReceivedFrame::Data {
                        stream_id,
                        end_stream,
                        ..
                    }) => {
                        assert_eq!(stream_id, stream);
                        if end_stream {
                            break;
                        }
                    }
                    None => {}
                    event => panic!("declared size rejection must return 413: {event:?}"),
                }
            }
            assert_eq!(status.as_deref(), Some("413"));
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            assert_eq!(in_flight.load(Ordering::SeqCst), 0);
            client.reset(stream, ErrorCode::NoError).await;
            client.survivor().await;
            client
        })
        .await;
    });
}

struct TightenQueuedBody {
    admitted: Mutex<Option<oneshot::Sender<Cx>>>,
    resume: Mutex<Option<oneshot::Receiver<()>>>,
    terminal: Arc<Mutex<Option<IncomingBodyError>>>,
    retired: Arc<AtomicUsize>,
}

impl asupersync::web::handler::Handler for TightenQueuedBody {
    fn call(
        &self,
        cx: &Cx,
        mut request: asupersync::web::extract::Request,
    ) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        use asupersync::web::extract::FromRequest;

        let request_cx = cx.clone();
        let admitted = self.admitted.lock().unwrap().take().unwrap();
        let mut resume = self.resume.lock().unwrap().take().unwrap();
        let terminal = Arc::clone(&self.terminal);
        let retired = Arc::clone(&self.retired);
        Box::pin(async move {
            let _retired = Retired(retired);
            admitted.send(&request_cx, request_cx.clone()).unwrap();
            resume.recv(&request_cx).await.unwrap();
            // Application policy may tighten after HEADERS admission, for
            // example after authentication. Exercise that public extension
            // boundary after the peer has already filled the body queue.
            request
                .extensions
                .insert_typed(RequestBodyPolicy::new().max_total_body_size(4));
            let mut body = StreamingRawBody::from_request(request).unwrap();
            assert_eq!(body.queued_bytes(), 8);
            match poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await {
                Some(Err(error)) => *terminal.lock().unwrap() = Some(error),
                other => panic!("tightened policy must reject queued DATA: {other:?}"),
            }
            Response::new(StatusCode::OK, "must not become success")
        })
    }
}

#[test]
fn h2_router_caught_application_body_error_cannot_become_success() {
    for workers in [1, 2] {
        run(workers, async {
            let cx = Cx::current().unwrap();
            let terminal = Arc::new(Mutex::new(None));
            let retired = Arc::new(AtomicUsize::new(0));
            let (admitted_tx, mut admitted_rx) = oneshot::channel();
            let (resume_tx, resume_rx) = oneshot::channel();
            let router = with_survivor(Router::new().route(
                "/tighten",
                post(TightenQueuedBody {
                    admitted: Mutex::new(Some(admitted_tx)),
                    resume: Mutex::new(Some(resume_rx)),
                    terminal: Arc::clone(&terminal),
                    retired: Arc::clone(&retired),
                }),
            ));
            exercise(router, move |mut client, in_flight| async move {
                let stream = client.open("POST", "/tighten", None, false).await;
                let request_cx = admitted_rx.recv(&cx).await.unwrap();
                client
                    .data(stream, Bytes::from_static(b"12345678"), true)
                    .await;
                // The connection driver polls incoming-body publication and
                // delivery before the subsequent sibling HEADERS/response.
                // The handler additionally asserts the exact queued-byte state.
                client.survivor().await;
                assert!(terminal.lock().unwrap().is_none());
                assert_eq!(retired.load(Ordering::SeqCst), 0);
                resume_tx.send(&cx, ()).unwrap();
                client.reset(stream, ErrorCode::EnhanceYourCalm).await;
                wait_region_closed(&request_cx).await;
                wait_requests_drained(&in_flight).await;
                assert_eq!(retired.load(Ordering::SeqCst), 1);
                assert_eq!(
                    *terminal.lock().unwrap(),
                    Some(IncomingBodyError::BodyTooLarge {
                        actual: Some(8),
                        limit: 4
                    }),
                );
                client.survivor().await;
                client
            })
            .await;
        });
    }
}

#[test]
fn h2_router_aggregate_body_reservation_refuses_then_reclaims_admission() {
    for workers in [1, 2] {
        run(workers, async {
            let cx = Cx::current().unwrap();
            let mut listener_config = config();
            // The public budget covers one body queue, its already granted
            // stream receive credit, and one bounded trailer block.
            listener_config.connection_request_body_buffer_bytes =
                NonZeroUsize::new(2 * INITIAL_WINDOW + 16 * 1024).unwrap();
            let terminal = Arc::new(Mutex::new(None));
            let held_terminal = Arc::clone(&terminal);
            let retired = Arc::new(AtomicUsize::new(0));
            let held_retired = Arc::clone(&retired);
            let probe_calls = Arc::new(AtomicUsize::new(0));
            let handler_probe_calls = Arc::clone(&probe_calls);
            let (parked_tx, mut parked_rx) = oneshot::channel();
            let parked = Arc::new(Mutex::new(Some(parked_tx)));
            let router = Router::new()
                .route(
                    "/held",
                    post(AsyncCxFnHandler1::<_, StreamingRawBody>::new(
                        move |request_cx: Cx, mut body: StreamingRawBody| {
                            let parked = parked.lock().unwrap().take().unwrap();
                            let terminal = Arc::clone(&held_terminal);
                            let retired = Arc::clone(&held_retired);
                            async move {
                                let _retired = Retired(retired);
                                match next_after_pending(&mut body, &request_cx, parked).await {
                                    Some(Err(error)) => *terminal.lock().unwrap() = Some(error),
                                    other => {
                                        panic!("held upload must observe peer reset: {other:?}")
                                    }
                                }
                                Response::new(StatusCode::OK, "must not become success")
                            }
                        },
                    )),
                )
                .route(
                    "/probe",
                    get(FnHandler::new(move || {
                        handler_probe_calls.fetch_add(1, Ordering::SeqCst);
                        Response::new(StatusCode::OK, "slot reclaimed")
                    })),
                );
            exercise_with_config(
                router,
                listener_config,
                move |mut client, in_flight| async move {
                    let inspector = Runtime::current_handle()
                        .unwrap()
                        .task_inspector(Default::default())
                        .unwrap();
                    let baseline: Vec<_> = inspector
                        .list_tasks()
                        .into_iter()
                        .map(|task| task.id)
                        .collect();
                    let held = client.open("POST", "/held", None, false).await;
                    let request_cx = parked_rx.recv(&cx).await.unwrap();
                    let owned_tasks: Vec<_> = inspector
                        .list_tasks()
                        .into_iter()
                        .map(|task| task.id)
                        .filter(|id| !baseline.contains(id))
                        .collect();
                    assert!(owned_tasks.contains(&request_cx.task_id()));
                    assert!(
                        owned_tasks.len() >= 2,
                        "request task and coordinator are live"
                    );
                    assert_eq!(in_flight.load(Ordering::SeqCst), 1);
                    let refused = client.open("GET", "/probe", None, true).await;
                    client.reset(refused, ErrorCode::RefusedStream).await;
                    assert_eq!(probe_calls.load(Ordering::SeqCst), 0);
                    assert_eq!(in_flight.load(Ordering::SeqCst), 1);
                    assert_eq!(retired.load(Ordering::SeqCst), 0);
                    assert!(terminal.lock().unwrap().is_none());
                    assert!(!request_cx.is_cancel_requested());

                    client.connection.reset_stream(held, ErrorCode::Cancel);
                    client.flush().await;
                    wait_region_closed(&request_cx).await;
                    wait_requests_drained(&in_flight).await;
                    // The coordinator can retire just after publishing its
                    // completion and releasing the in-flight guard. Observe
                    // its actual task removal before requiring the reservation
                    // to be available for the very next request.
                    poll_fn(|cx| {
                        if inspector
                            .list_tasks()
                            .iter()
                            .all(|task| !owned_tasks.contains(&task.id))
                        {
                            Poll::Ready(())
                        } else {
                            cx.waker().wake_by_ref();
                            Poll::Pending
                        }
                    })
                    .await;
                    assert_eq!(retired.load(Ordering::SeqCst), 1);
                    assert_eq!(
                        *terminal.lock().unwrap(),
                        Some(IncomingBodyError::ClientAborted),
                    );
                    let admitted = client.open("GET", "/probe", None, true).await;
                    client.response(admitted, "200", b"slot reclaimed").await;
                    assert_eq!(probe_calls.load(Ordering::SeqCst), 1);
                    wait_requests_drained(&in_flight).await;
                    assert_eq!(in_flight.load(Ordering::SeqCst), 0);
                    client
                },
            )
            .await;
        });
    }
}

#[test]
fn h2_router_late_request_trailers_preserve_response_after_handler_retirement() {
    for workers in [1, 2] {
        run(workers, async {
            const RESPONSE: &[u8] = b"response retained after handler exit";
            let cx = Cx::current().unwrap();
            let mut client_settings = Settings::client();
            client_settings.initial_window_size = 0;
            let retired = Arc::new(AtomicUsize::new(0));
            let handler_retired = Arc::clone(&retired);
            let (entered_tx, mut entered_rx) = oneshot::channel();
            let entered = Arc::new(Mutex::new(Some(entered_tx)));
            let (respond_tx, respond_rx) = oneshot::channel();
            let respond = Arc::new(Mutex::new(Some(respond_rx)));
            let router = Router::new().route(
                "/late-trailers",
                post(AsyncCxFnHandler1::<_, StreamingRawBody>::new(
                    move |request_cx: Cx, body: StreamingRawBody| {
                        let entered = entered.lock().unwrap().take().unwrap();
                        let mut respond = respond.lock().unwrap().take().unwrap();
                        let retired = Arc::clone(&handler_retired);
                        async move {
                            let _retired = Retired(retired);
                            drop(body);
                            entered.send(&request_cx, request_cx.clone()).unwrap();
                            respond.recv(&request_cx).await.unwrap();
                            Response::new(StatusCode::OK, Bytes::from_static(RESPONSE))
                        }
                    },
                )),
            );
            exercise_with_client_settings(
                router,
                config(),
                client_settings,
                move |mut client, in_flight| async move {
                    let inspector = Runtime::current_handle()
                        .unwrap()
                        .task_inspector(Default::default())
                        .unwrap();
                    let baseline: Vec<_> = inspector
                        .list_tasks()
                        .into_iter()
                        .map(|task| task.id)
                        .collect();
                    let stream = client.open("POST", "/late-trailers", None, false).await;
                    let request_cx = entered_rx.recv(&cx).await.unwrap();
                    let owned_tasks: Vec<_> = inspector
                        .list_tasks()
                        .into_iter()
                        .map(|task| task.id)
                        .filter(|id| !baseline.contains(id))
                        .collect();
                    assert!(owned_tasks.contains(&request_cx.task_id()));
                    assert!(owned_tasks.len() >= 2);
                    assert_eq!(retired.load(Ordering::SeqCst), 0);
                    respond_tx.send(&cx, ()).unwrap();
                    loop {
                        match client.receive().await.0 {
                            Some(ReceivedFrame::Headers {
                                stream_id,
                                headers,
                                end_stream,
                            }) => {
                                assert_eq!(stream_id, stream);
                                assert!(!end_stream);
                                assert_eq!(
                                    headers
                                        .iter()
                                        .find(|header| header.name == ":status")
                                        .map(|header| header.value.as_str()),
                                    Some("200"),
                                );
                                break;
                            }
                            None => {}
                            event => {
                                panic!("response HEADERS must precede blocked DATA: {event:?}")
                            }
                        }
                    }
                    assert_eq!(client.connection.stream(stream).unwrap().recv_window(), 0);
                    wait_region_closed(&request_cx).await;
                    poll_fn(|cx| {
                        if inspector
                            .list_tasks()
                            .iter()
                            .all(|task| !owned_tasks.contains(&task.id))
                        {
                            Poll::Ready(())
                        } else {
                            cx.waker().wake_by_ref();
                            Poll::Pending
                        }
                    })
                    .await;
                    assert_eq!(retired.load(Ordering::SeqCst), 1);
                    // The handler and coordinator have retired, but the wire
                    // response still owns the request's in-flight guard.
                    assert_eq!(in_flight.load(Ordering::SeqCst), 1);

                    client
                        .connection
                        .send_headers(stream, vec![Header::new("x-late-trailer", "valid")], true)
                        .unwrap();
                    client.flush().await;
                    client
                        .connection
                        .send_stream_window_update(stream, u32::try_from(RESPONSE.len()).unwrap())
                        .unwrap();
                    client.flush().await;
                    let mut received = Vec::new();
                    loop {
                        match client.receive().await.0 {
                            Some(ReceivedFrame::Data {
                                stream_id,
                                data,
                                end_stream,
                            }) => {
                                assert_eq!(stream_id, stream);
                                received.extend_from_slice(&data);
                                if end_stream {
                                    break;
                                }
                            }
                            None => {}
                            event => panic!(
                                "late request trailers must preserve original response: {event:?}"
                            ),
                        }
                    }
                    assert_eq!(received, RESPONSE);
                    wait_requests_drained(&in_flight).await;
                    assert_eq!(in_flight.load(Ordering::SeqCst), 0);
                    client
                },
            )
            .await;
        });
    }
}
