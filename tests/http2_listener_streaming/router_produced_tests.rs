//! Router live ingress/egress keeps the listener's one request owner.

use super::*;
use asupersync::record::ObligationAbortReason;
use asupersync::web::{AsyncCxFnHandler2, Http2StreamResponder};
use std::sync::atomic::AtomicBool;
use std::task::Context;

struct ObservedUpload {
    body: StreamingRawBody,
    request: Cx,
    parked: Option<oneshot::Sender<Cx>>,
    dropped: Arc<AtomicUsize>,
    cancelled_on_drop: Arc<AtomicBool>,
}

impl Body for ObservedUpload {
    type Data = <StreamingRawBody as Body>::Data;
    type Error = IncomingBodyError;

    fn poll_frame(mut self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<Option<Result<BodyFrame<Self::Data>, Self::Error>>> {
        let ambient = Cx::current().expect("live response producer retains its request context");
        assert_eq!(ambient.region_id(), self.request.region_id());
        assert_eq!(ambient.task_id(), self.request.task_id());
        let result = Pin::new(&mut self.body).poll_frame(task);
        if result.is_pending()
            && let Some(parked) = self.parked.take()
        {
            parked.send_blocking(self.request.clone()).unwrap();
        }
        result
    }
}

impl Drop for ObservedUpload {
    fn drop(&mut self) {
        self.cancelled_on_drop.store(self.request.is_cancel_requested(), Ordering::SeqCst);
        self.dropped.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn router_duplex_echoes_before_upload_eof_and_retires_exactly_once_on_reset() {
    for workers in [1, 2] {
        for reset in [false, true] {
            run(workers, async move {
                let cx = Cx::current().unwrap();
                let runtime = Runtime::current_handle().unwrap();
                let (parked_tx, mut parked_rx) = oneshot::channel();
                let parked = Arc::new(Mutex::new(Some(parked_tx)));
                let dropped = Arc::new(AtomicUsize::new(0));
                let handler_dropped = Arc::clone(&dropped);
                let cancelled = Arc::new(AtomicBool::new(false));
                let handler_cancelled = Arc::clone(&cancelled);
                let router = with_survivor(Router::new().without_default_trace().route(
                    "/duplex",
                    post(AsyncCxFnHandler2::new(move |request: Cx, responder: Http2StreamResponder, body: StreamingRawBody| {
                        let parked = parked.lock().unwrap().take().unwrap();
                        let dropped = Arc::clone(&handler_dropped);
                        let cancelled_on_drop = Arc::clone(&handler_cancelled);
                        async move {
                            responder.body(
                                Response::empty(StatusCode::OK).header("content-type", "application/octet-stream"),
                                NonZeroUsize::MIN, NonZeroUsize::new(3).unwrap(),
                                ObservedUpload { body, request, parked: Some(parked), dropped, cancelled_on_drop },
                            )
                        }
                    })),
                ));
                // Exercise the public handler-only adapter here; the policy
                // case below independently exercises the paired parts API.
                exercise_produced(router.into_http2_streaming_produced_handler(), Settings::client(), move |mut client, in_flight| async move {
                    let stream = client.open("POST", "/duplex", Some(11), false).await;
                    let request = parked_rx.recv(&cx).await.unwrap();
                    assert_ne!(request.region_id(), cx.region_id());
                    assert_ne!(request.task_id(), cx.task_id());
                    let credit = obligation_tests::pending_credit(&runtime, &request).await;
                    client.data(stream, Bytes::from_static(b"prefix-"), false).await;
                    let mut prefix = Vec::new();
                    let mut head_seen = false;
                    while prefix.len() < 7 {
                        match client.receive().await.0 {
                            Some(ReceivedFrame::Headers { stream_id, headers, end_stream }) => {
                                assert_eq!(stream_id, stream);
                                assert!(!head_seen && !end_stream);
                                assert!(headers.iter().any(|field| field.name == ":status" && field.value == "200"));
                                assert!(!headers.iter().any(|field| matches!(field.name.as_str(), "content-length" | "transfer-encoding")));
                                head_seen = true;
                            }
                            Some(ReceivedFrame::Data { stream_id, data, end_stream }) => {
                                assert_eq!(stream_id, stream);
                                assert!(head_seen && !end_stream);
                                assert!(data.len() <= 3);
                                prefix.extend_from_slice(&data);
                            }
                            None => {},
                            other => panic!("router must echo live DATA before upload EOF: {other:?}"),
                        }
                    }
                    assert_eq!(prefix, b"prefix-");
                    assert_eq!(in_flight.load(Ordering::SeqCst), 1);
                    assert_eq!(dropped.load(Ordering::SeqCst), 0);
                    if reset {
                        client.connection.reset_stream(stream, ErrorCode::Cancel);
                        client.flush().await;
                    } else {
                        client.data(stream, Bytes::from_static(b"tail"), false).await;
                        client.connection.send_headers(stream, vec![Header::new("x-upload", "complete")], true).unwrap();
                        client.flush().await;
                        let mut tail = Vec::new();
                        loop {
                            match client.receive().await.0 {
                                Some(ReceivedFrame::Data { stream_id, data, end_stream }) => {
                                    assert_eq!(stream_id, stream);
                                    assert!(!end_stream, "trailers own the final response boundary");
                                    tail.extend_from_slice(&data);
                                }
                                Some(ReceivedFrame::Headers { stream_id, headers, end_stream }) => {
                                    assert_eq!(stream_id, stream);
                                    assert!(end_stream);
                                    assert_eq!(headers, vec![Header::new("x-upload", "complete")]);
                                    break;
                                }
                                None => {},
                                other => panic!("router must preserve trailing headers after DATA: {other:?}"),
                            }
                        }
                        assert_eq!(tail, b"tail");
                    }
                    wait_region_closed(&request).await;
                    wait_requests_drained(&in_flight).await;
                    assert_eq!(dropped.load(Ordering::SeqCst), 1);
                    assert_eq!(cancelled.load(Ordering::SeqCst), reset);
                    assert_eq!(obligation_tests::assert_retired(
                        &runtime, &request, reset.then_some(ObligationAbortReason::Error),
                    ).await, credit);
                    client.survivor().await;
                    client
                }).await;
            });
        }
    }
}

fn counted_echo(calls: Arc<AtomicUsize>) -> impl asupersync::web::handler::Handler {
    AsyncCxFnHandler2::new(move |_cx: Cx, responder: Http2StreamResponder, body: StreamingRawBody| {
        calls.fetch_add(1, Ordering::SeqCst);
        async move {
            responder.body(Response::empty(StatusCode::OK), NonZeroUsize::MIN, NonZeroUsize::new(3).unwrap(), body)
        }
    })
}

#[test]
fn router_duplex_parts_enforce_route_nested_and_outer_limits_before_admission() {
    for workers in [1, 2] {
        run(workers, async {
            let calls = Arc::new(AtomicUsize::new(0));
            let nested = Router::new().with_body_policy(RequestBodyPolicy::new().max_total_body_size(16))
                .route("/route", post(counted_echo(Arc::clone(&calls)))
                    .with_body_policy(RequestBodyPolicy::new().max_total_body_size(8)))
                .route("/nested", post(counted_echo(Arc::clone(&calls)))
                    .with_body_policy(RequestBodyPolicy::new().max_total_body_size(64)));
            let wide = Router::new().with_body_policy(RequestBodyPolicy::new().max_total_body_size(64))
                .route("/outer", post(counted_echo(Arc::clone(&calls)))
                    .with_body_policy(RequestBodyPolicy::new().max_total_body_size(128)));
            let router = with_survivor(Router::new().without_default_trace()
                .with_body_policy(RequestBodyPolicy::new().max_total_body_size(32))
                .nest("/api", nested).nest("/wide", wide));
            let (handler, listener_config) = router.into_http2_streaming_produced_parts(config());
            exercise_produced_with_config(handler, listener_config, Settings::client(), move |mut client, in_flight| async move {
                for (path, declared) in [("/api/route", 9), ("/api/nested", 17), ("/wide/outer", 33)] {
                    let stream = client.open("POST", path, Some(declared), false).await;
                    let mut status = None;
                    loop {
                        match client.receive().await.0 {
                            Some(ReceivedFrame::Headers { stream_id, headers, end_stream }) => {
                                assert_eq!(stream_id, stream);
                                status = headers.into_iter().find(|field| field.name == ":status").map(|field| field.value);
                                if end_stream { break; }
                            }
                            Some(ReceivedFrame::Data { stream_id, end_stream, .. }) => {
                                assert_eq!(stream_id, stream);
                                if end_stream { break; }
                            }
                            None => {},
                            other => panic!("HEADERS-only policy refusal must return 413: {other:?}"),
                        }
                    }
                    assert_eq!(status.as_deref(), Some("413"));
                    assert_eq!(calls.load(Ordering::SeqCst), 0, "no request-body extractor or producer is admitted");
                    assert_eq!(in_flight.load(Ordering::SeqCst), 0);
                    client.reset(stream, ErrorCode::NoError).await;
                    client.survivor().await;
                }
                // Admission remains available after all refusals, and the
                // tightest route ceiling accepts an exactly bounded upload.
                let stream = client.open("POST", "/api/route", Some(8), false).await;
                client.data(stream, Bytes::from_static(b"12345678"), true).await;
                client.response(stream, "200", b"12345678").await;
                wait_requests_drained(&in_flight).await;
                assert_eq!(calls.load(Ordering::SeqCst), 1);
                client.survivor().await;
                client
            }).await;
        });
    }
}
