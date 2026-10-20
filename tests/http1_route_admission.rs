//! Native head-only admission and live body ownership journeys for HTTP/1.
//!
//! A withheld upload and an actual body Pending poll witness the admission
//! boundary. Timeouts only bound failures. Every journey runs on one and two
//! workers with both unified and sharded runtime state.
#![cfg(not(target_arch = "wasm32"))]

use asupersync::channel::oneshot;
use asupersync::cx::Cx;
use asupersync::http::body::{Body, Frame};
use asupersync::http::h1::listener::{Http1Listener, Http1ListenerConfig};
use asupersync::http::h1::server::{
    HostPolicy, Http1Config, Http1StreamingConfig, Http1StreamingServer,
};
use asupersync::http::h1::stream::{
    Http1ProducedResponse, IncomingBodyError, IncomingRequestBody, StreamingServerRequest,
};
use asupersync::http::h1::types::Response;
use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::net::TcpStream;
use asupersync::record::{ObligationAbortReason, ObligationKind};
use asupersync::runtime::{RootDrainOutcome, RuntimeBuilder, RuntimeHandle};
use asupersync::trace::{TraceData, TraceEvent, TraceEventKind};
use asupersync::types::ObligationId;
use asupersync::web::handler::AsyncCxFnHandler1;
use asupersync::web::router::post;
use asupersync::web::sse::StreamingSse;
use asupersync::web::{RequestBodyPolicy, Router, StreamingRawBody};
use std::future::{Future, poll_fn};
use std::io::Write;
use std::num::NonZeroUsize;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

fn native<F, Fut>(scenario: F)
where
    F: Fn(Cx, RuntimeHandle) -> Fut + Copy + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let (send, receive) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let result = catch_unwind(AssertUnwindSafe(|| {
            for workers in [1, 2] {
                for sharded in [false, true] {
                    let builder = if workers == 1 {
                        RuntimeBuilder::current_thread()
                    } else {
                        RuntimeBuilder::new().worker_threads(workers)
                    };
                    let runtime = builder
                        .with_sharded_state(sharded)
                        .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
                        .build()
                        .unwrap();
                    runtime.block_on(async {
                        let root = Cx::current().unwrap();
                        let handle = runtime.handle();
                        let mut task = root.spawn(move |cx| scenario(cx, handle)).unwrap();
                        task.join(&root).await.unwrap();
                    });
                    let report = runtime.shutdown_drained(Duration::from_secs(5));
                    assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
                    assert_eq!(report.live_tasks, 0);
                    assert_eq!(report.pending_spawns, 0);
                    assert_eq!(report.pending_obligations, 0);
                }
            }
        }));
        let _ = send.send(result);
    });
    let result = receive
        .recv_timeout(Duration::from_secs(45))
        .expect("HTTP/1 admission and owned body work must retire");
    worker.join().unwrap();
    if let Err(payload) = result {
        resume_unwind(payload);
    }
}

fn config() -> Http1StreamingConfig {
    Http1StreamingConfig::from(
        Http1Config::default()
            .host_policy(HostPolicy::allow_list(vec!["localhost".to_owned()]))
            .max_body_size(64)
            .idle_timeout(None),
    )
    .incoming_body_queue(1, 64)
}

fn pair(head: &[u8]) -> (TcpStream, TcpStream) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let mut peer = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    peer.write_all(head).unwrap();
    let (server, _) = listener.accept().unwrap();
    server.set_nonblocking(true).unwrap();
    peer.set_nonblocking(true).unwrap();
    (
        TcpStream::from_std(server).unwrap(),
        TcpStream::from_std(peer).unwrap(),
    )
}

async fn response(peer: &mut TcpStream) -> String {
    let mut bytes = Vec::new();
    peer.read_to_end(&mut bytes).await.unwrap();
    String::from_utf8(bytes).unwrap()
}

async fn response_head(peer: &mut TcpStream) -> String {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        peer.read_exact(&mut byte).await.unwrap();
        bytes.push(byte[0]);
        assert!(bytes.len() <= 4096);
    }
    String::from_utf8(bytes).unwrap()
}

fn ownership_counts(runtime: &RuntimeHandle) -> (usize, usize) {
    let trace = runtime.trace_snapshot().expect("live runtime trace");
    let regions = trace
        .iter()
        .filter(|event| event.kind == TraceEventKind::RegionCreated)
        .count();
    let io_credits = trace
        .iter()
        .filter(|event| {
            event.kind == TraceEventKind::ObligationReserve
                && matches!(
                    event.data,
                    TraceData::Obligation {
                        kind: ObligationKind::IoOp,
                        ..
                    }
                )
        })
        .count();
    (regions, io_credits)
}

fn body_events<'a>(trace: &'a [TraceEvent], request: &Cx) -> Vec<(usize, &'a TraceEvent)> {
    trace
        .iter()
        .enumerate()
        .filter(|(_, event)| {
            matches!(event.data,
                TraceData::Obligation { task, region, kind: ObligationKind::IoOp, .. }
                if task == request.task_id() && region == request.region_id()
            )
        })
        .collect()
}

async fn pending_credit(runtime: &RuntimeHandle, request: &Cx) -> ObligationId {
    loop {
        let trace = runtime.trace_snapshot().expect("live runtime trace");
        let events = body_events(&trace, request);
        if let Some((_, reserve)) = events.first() {
            assert_eq!(
                events.len(),
                1,
                "the parked live body has one unresolved credit"
            );
            assert_eq!(reserve.kind, TraceEventKind::ObligationReserve);
            let TraceData::Obligation { obligation, .. } = reserve.data else {
                unreachable!("filtered body obligation");
            };
            return obligation;
        }
        // The checked ticket precedes its mailbox projection. Wait for that
        // record rather than treating an elapsed delay as readiness.
        asupersync::runtime::yield_now().await;
    }
}

fn assert_credit_retired(
    runtime: &RuntimeHandle,
    request: &Cx,
    credit: ObligationId,
    aborted: bool,
) {
    let trace = runtime.trace_snapshot().expect("live runtime trace");
    let events = body_events(&trace, request);
    assert_eq!(events.len(), 2, "one reserve and one terminal body event");
    assert_eq!(events[0].1.kind, TraceEventKind::ObligationReserve);
    assert_eq!(
        events[1].1.kind,
        if aborted {
            TraceEventKind::ObligationAbort
        } else {
            TraceEventKind::ObligationCommit
        }
    );
    assert!(matches!(events[1].1.data,
        TraceData::Obligation { obligation, abort_reason, .. }
        if obligation == credit && abort_reason == aborted.then_some(ObligationAbortReason::Error)
    ));
    let retired = trace
        .iter()
        .position(|event| {
            event.kind == TraceEventKind::Complete
                && matches!(event.data, TraceData::Task { task, .. } if task == request.task_id())
        })
        .expect("actual request holder retired");
    assert!(
        events[1].0 < retired,
        "the holder cannot retire with a live body credit"
    );
}

async fn collect_at_pending(
    cx: &Cx,
    body: &mut IncomingRequestBody,
    mut ready: Option<oneshot::Sender<Cx>>,
) -> Result<Vec<u8>, IncomingBodyError> {
    let mut bytes = Vec::new();
    loop {
        let frame = poll_fn(|task| {
            let frame = Pin::new(&mut *body).poll_frame(task);
            if frame.is_pending()
                && let Some(ready) = ready.take()
            {
                ready.send_blocking(cx.clone()).unwrap();
            }
            frame
        })
        .await;
        match frame {
            Some(Ok(Frame::Data(data))) => bytes.extend_from_slice(data.into_inner().as_ref()),
            Some(Ok(Frame::Trailers(_))) => {}
            Some(Err(error)) => return Err(error),
            None => return Ok(bytes),
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Mode {
    Buffered,
    Produced,
    Sse,
}

#[derive(Clone, Copy, Debug)]
enum Refusal {
    RouteLimit,
    CustomHead,
    Panic,
    Interim,
    Http10Head,
    TransportLimit,
}

async fn refused_before_ownership(cx: Cx, runtime: RuntimeHandle) {
    for mode in [Mode::Buffered, Mode::Produced, Mode::Sse] {
        for refusal in [
            Refusal::RouteLimit,
            Refusal::CustomHead,
            Refusal::Panic,
            Refusal::Interim,
            Refusal::Http10Head,
            Refusal::TransportLimit,
        ] {
            let head: &[u8] = match refusal {
                Refusal::CustomHead => b"HEAD /private HTTP/1.1\r\nHost: localhost\r\nContent-Length: 3\r\nExpect: 100-continue\r\n\r\n",
                Refusal::Http10Head => b"HEAD /private HTTP/1.0\r\nHost: localhost\r\nContent-Length: 3\r\nConnection: keep-alive\r\n\r\n",
                _ => b"POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 3\r\nExpect: 100-continue\r\n\r\n",
            };
            let (socket, mut peer) = pair(head);
            let before = ownership_counts(&runtime);
            let admissions = Arc::new(AtomicUsize::new(0));
            let calls = Arc::new(AtomicUsize::new(0));
            let admission_calls = Arc::clone(&admissions);
            let mut policy = config();
            if matches!(refusal, Refusal::TransportLimit) {
                policy.connection.max_body_size = 2;
            }
            let policy = policy.with_request_body_policy(move |head| {
                admission_calls.fetch_add(1, Ordering::SeqCst);
                assert!(matches!(head.uri.as_str(), "/upload" | "/private"));
                match refusal {
                    Refusal::RouteLimit => Ok(Some(2)),
                    Refusal::CustomHead | Refusal::Http10Head => {
                        Err(Response::new(403, "Forbidden", b"private body".to_vec())
                            .with_header("connection", "keep-alive"))
                    }
                    Refusal::Panic => panic!("admission callback failed"),
                    Refusal::Interim => Err(Response::new(100, "Continue", Vec::new())),
                    Refusal::TransportLimit => Ok(Some(u64::MAX)),
                }
            });
            let factory_calls = Arc::clone(&calls);
            let mut serving = cx
                .spawn(move |connection| async move {
                    match mode {
                        Mode::Buffered => {
                            let server = Http1StreamingServer::with_config(
                                move |_cx: Cx, _request: StreamingServerRequest| {
                                    factory_calls.fetch_add(1, Ordering::SeqCst);
                                    async { Response::new(200, "OK", Vec::new()) }
                                },
                                policy,
                            );
                            server.serve_owned(&connection, socket).await
                        }
                        Mode::Produced => {
                            let server = Http1StreamingServer::with_config_produced(
                                move |_cx: Cx, _request: StreamingServerRequest| {
                                    factory_calls.fetch_add(1, Ordering::SeqCst);
                                    async {
                                        Http1ProducedResponse::chunked(
                                            NonZeroUsize::MIN,
                                            200,
                                            "OK",
                                            |cx, mut sender| async move {
                                                sender.finish(&cx)?;
                                                Ok(sender)
                                            },
                                        )
                                    }
                                },
                                policy,
                            );
                            server.serve_produced_owned(&connection, socket).await
                        }
                        Mode::Sse => {
                            let server = Http1StreamingServer::with_config_sse(
                                move |_cx: Cx, _request: StreamingServerRequest| {
                                    factory_calls.fetch_add(1, Ordering::SeqCst);
                                    async {
                                        StreamingSse::empty().into_http1_response(NonZeroUsize::MIN)
                                    }
                                },
                                policy,
                            );
                            server.serve_sse_owned(&connection, socket).await
                        }
                    }
                })
                .unwrap();
            // The upload body is never sent and the client stays open. A
            // final response must follow head admission alone.
            let reply = response(&mut peer).await;
            serving.join(&cx).await.unwrap().unwrap();
            let status = match refusal {
                Refusal::RouteLimit | Refusal::TransportLimit => 413,
                Refusal::CustomHead | Refusal::Http10Head => 403,
                Refusal::Panic | Refusal::Interim => 500,
            };
            let version = if matches!(refusal, Refusal::Http10Head) {
                "HTTP/1.0"
            } else {
                "HTTP/1.1"
            };
            assert!(
                reply.starts_with(&format!("{version} {status} ")),
                "{mode:?}/{refusal:?}: {reply:?}"
            );
            assert!(
                !reply.contains("100 Continue"),
                "{mode:?}/{refusal:?}: {reply:?}"
            );
            assert!(reply.to_ascii_lowercase().contains("connection: close\r\n"));
            if matches!(refusal, Refusal::CustomHead | Refusal::Http10Head) {
                assert!(
                    reply.ends_with("\r\n\r\n"),
                    "HEAD never emits the refusal body"
                );
                assert!(!reply.contains("private body"));
            }
            if !matches!(refusal, Refusal::TransportLimit) {
                assert_eq!(admissions.load(Ordering::SeqCst), 1);
            }
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            assert_eq!(
                ownership_counts(&runtime),
                before,
                "refused heads create neither request regions nor body credits"
            );
        }
    }
}

#[test]
fn owned_response_modes_refuse_before_continue_body_credit_or_handler_admission() {
    native(refused_before_ownership);
}

async fn paired_router_listener(cx: Cx, runtime: RuntimeHandle) {
    let (ready, mut pending) = oneshot::channel();
    let ready = Arc::new(Mutex::new(Some(ready)));
    let calls = Arc::new(AtomicUsize::new(0));
    let handler_calls = Arc::clone(&calls);
    let handler = AsyncCxFnHandler1::<_, StreamingRawBody>::new(
        move |request_cx: Cx, body: StreamingRawBody| {
            handler_calls.fetch_add(1, Ordering::SeqCst);
            let ready = ready.lock().unwrap().take();
            async move {
                let current = Cx::current().unwrap();
                assert_eq!(current.task_id(), request_cx.task_id());
                assert_eq!(current.region_id(), request_cx.region_id());
                let mut body = body.into_inner();
                let bytes = collect_at_pending(&request_cx, &mut body, ready)
                    .await
                    .unwrap();
                String::from_utf8(bytes).unwrap()
            }
        },
    );
    let router = Router::new()
        .nest(
            "/api",
            Router::new().route(
                "/upload",
                post(handler).with_body_policy(RequestBodyPolicy::new().max_total_body_size(3)),
            ),
        )
        .with_body_policy(RequestBodyPolicy::new().max_total_body_size(8));
    let (handler, policy) = router.into_http1_streaming_parts(config());
    let listener = Http1Listener::bind_streaming_with_config(
        "127.0.0.1:0",
        handler,
        Http1ListenerConfig::default(),
    )
    .await
    .unwrap()
    .with_streaming_config(policy);
    let address = listener.local_addr().unwrap();
    let manager = listener.connection_manager().clone();
    let mut serving = cx
        .spawn(
            move |listener_cx| async move { listener.run_streaming_owned_in(&listener_cx).await },
        )
        .unwrap();

    let mut refused = TcpStream::connect(address).await.unwrap();
    let before = ownership_counts(&runtime);
    refused.write_all(b"POST /api/upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\nExpect: 100-continue\r\n\r\n").await.unwrap();
    let reply = response(&mut refused).await;
    assert!(reply.starts_with("HTTP/1.1 413 "), "{reply:?}");
    assert!(!reply.contains("100 Continue"));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    manager.wait_all_closed().await;
    assert_eq!(ownership_counts(&runtime), before);

    let mut peer = TcpStream::connect(address).await.unwrap();
    peer.write_all(b"POST /api/upload?mode=live HTTP/1.1\r\nHost: localhost\r\nContent-Length: 3\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n").await.unwrap();
    let request = pending.recv(&cx).await.unwrap();
    assert_ne!(request.task_id(), serving.task_id());
    assert_ne!(request.region_id(), cx.region_id());
    let credit = pending_credit(&runtime, &request).await;
    assert!(
        response_head(&mut peer)
            .await
            .starts_with("HTTP/1.1 100 Continue\r\n")
    );
    let monitor = cx.monitor(request.task_id()).await.unwrap();
    peer.write_all(b"abc").await.unwrap();
    let reply = response(&mut peer).await;
    assert!(reply.starts_with("HTTP/1.1 200 "), "{reply:?}");
    assert!(reply.ends_with("abc"), "{reply:?}");
    monitor.down(&cx).await.unwrap();
    manager.wait_all_closed().await;
    assert_credit_retired(&runtime, &request, credit, false);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(manager.begin_drain(Duration::from_secs(5)));
    serving.join(&cx).await.unwrap().unwrap();
}

#[test]
fn router_listener_pairs_static_policy_with_a_live_owned_upload() {
    native(paired_router_listener);
}

async fn chunked_limit(cx: Cx, runtime: RuntimeHandle) {
    let (socket, mut peer) =
        pair(b"POST /upload HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n");
    let (ready, mut pending) = oneshot::channel();
    let ready = Arc::new(Mutex::new(Some(ready)));
    let server = Http1StreamingServer::with_config(
        move |request_cx: Cx, mut request: StreamingServerRequest| {
            let ready = ready.lock().unwrap().take();
            async move {
                let _result = collect_at_pending(&request_cx, &mut request.body, ready).await;
                // The protocol's failed incoming body must dominate this
                // handler response and cannot permit a pipelined next hop.
                Response::new(200, "OK", b"handler response".to_vec())
            }
        },
        config().with_request_body_policy(|_| Ok(Some(5))),
    );
    let mut serving = cx
        .spawn(move |connection| async move { server.serve_owned(&connection, socket).await })
        .unwrap();
    let request = pending.recv(&cx).await.unwrap();
    let credit = pending_credit(&runtime, &request).await;
    peer.write_all(b"3\r\nabc\r\n3\r\ndef\r\n0\r\n\r\n")
        .await
        .unwrap();
    let reply = response(&mut peer).await;
    serving.join(&cx).await.unwrap().unwrap();
    assert!(reply.starts_with("HTTP/1.1 413 "), "{reply:?}");
    assert!(!reply.contains("HTTP/1.1 200"));
    assert!(reply.to_ascii_lowercase().contains("connection: close\r\n"));
    assert_credit_retired(&runtime, &request, credit, true);
}

#[test]
fn chunked_route_overrun_aborts_the_live_body_credit_and_closes_the_connection() {
    native(chunked_limit);
}

async fn request_local_ceiling(cx: Cx, _runtime: RuntimeHandle) {
    for explicit_large in [false, true] {
        let (socket, mut peer) = pair(b"POST /empty HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\nPOST /open HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello");
        let paths = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&paths);
        let server = Http1StreamingServer::with_config(
            |cx: Cx, mut request: StreamingServerRequest| async move {
                let bytes = collect_at_pending(&cx, &mut request.body, None)
                    .await
                    .unwrap();
                Response::new(200, "OK", bytes)
            },
            config().with_request_body_policy(move |head| {
                seen.lock().unwrap().push(head.uri.clone());
                match head.uri.as_str() {
                    "/empty" => Ok(Some(0)),
                    // This also catches truncating a large u64 ceiling on
                    // 32-bit hosts; meeting with the transport cap is safe.
                    "/open" => Ok(explicit_large.then_some(1_u64 << 32)),
                    other => panic!("unexpected request path: {other}"),
                }
            }),
        );
        let mut serving = cx
            .spawn(move |connection| async move { server.serve_owned(&connection, socket).await })
            .unwrap();
        let reply = response(&mut peer).await;
        assert_eq!(serving.join(&cx).await.unwrap().unwrap().requests_served, 2);
        assert_eq!(reply.matches("HTTP/1.1 200 ").count(), 2, "{reply:?}");
        assert!(reply.ends_with("hello"), "{reply:?}");
        assert_eq!(
            *paths.lock().unwrap(),
            vec!["/empty".to_owned(), "/open".to_owned()]
        );
    }
}

#[test]
fn zero_length_route_ceiling_does_not_leak_into_the_next_keep_alive_request() {
    native(request_local_ceiling);
}
