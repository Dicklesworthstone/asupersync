//! Native ownership, cursor and reconnect contracts for the SSE client.
#![cfg(not(target_arch = "wasm32"))]
#![recursion_limit = "256"]

use std::future::{Future, poll_fn};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::pin::Pin;
use std::sync::mpsc;
use std::task::Poll;
use std::time::{Duration, Instant};

use asupersync::cx::Cx;
use asupersync::http::HttpClient;
use asupersync::http::sse::{
    EventSource, EventSourceError, EventSourceOptions, ReconnectPolicy,
};
use asupersync::runtime::{RootDrainOutcome, Runtime, RuntimeBuilder};
use asupersync::stream::Stream;
use asupersync::types::{Budget, CancelKind, CancelReason};

fn native(mut scenario: impl FnMut(&Runtime) + Send + 'static) {
    let (send, receive) = mpsc::channel();
    let supervisor = std::thread::spawn(move || {
        let result = catch_unwind(AssertUnwindSafe(|| {
            for workers in [1, 2] {
                let builder = if workers == 1 {
                    RuntimeBuilder::current_thread()
                } else {
                    RuntimeBuilder::multi_thread().worker_threads(workers)
                };
                let runtime = builder
                    .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
                    .build()
                    .unwrap();
                scenario(&runtime);
                let report = runtime.shutdown_drained(Duration::from_secs(5));
                assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
                assert_eq!(report.pending_obligations, 0);
                assert_eq!(report.live_tasks, 0);
                assert_eq!(report.pending_spawns, 0);
            }
        }));
        let _ = send.send(result);
    });
    let result = receive
        .recv_timeout(Duration::from_secs(40))
        .expect("native event source must finish and retire its resources");
    supervisor.join().unwrap();
    if let Err(payload) = result {
        resume_unwind(payload);
    }
}

fn client() -> HttpClient {
    HttpClient::builder()
        .no_proxy()
        .request_timeout(Duration::from_secs(5))
        .build()
}

fn accept(listener: &TcpListener) -> TcpStream {
    listener.set_nonblocking(true).unwrap();
    let start = Instant::now();
    let socket = loop {
        match listener.accept() {
            Ok((socket, _)) => break socket,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(start.elapsed() < Duration::from_secs(5), "missing GET");
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic!("accept failed: {error}"),
        }
    };
    socket.set_nonblocking(false).unwrap();
    socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    socket.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
    socket
}

fn request(socket: &mut TcpStream) -> String {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        assert!(bytes.len() < 16 * 1024);
        let mut byte = [0];
        socket.read_exact(&mut byte).unwrap();
        bytes.push(byte[0]);
    }
    String::from_utf8(bytes).unwrap()
}

fn header<'a>(request: &'a str, name: &str) -> Option<&'a str> {
    request.lines().skip(1).find_map(|line| {
        let (candidate, value) = line.split_once(':')?;
        candidate.eq_ignore_ascii_case(name).then(|| value.trim())
    })
}

fn response(status: &str, headers: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n{body}",
        body.len(),
    )
}

fn events(body: &str) -> String {
    response(
        "200 OK",
        "Content-Type: text/event-stream; charset=utf-8\r\n",
        body,
    )
}

fn scripted(responses: Vec<String>) -> (String, std::thread::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/events?feed=one", listener.local_addr().unwrap());
    let peer = std::thread::spawn(move || {
        let mut requests = Vec::new();
        for response in responses {
            let mut socket = accept(&listener);
            requests.push(request(&mut socket));
            socket.write_all(response.as_bytes()).unwrap();
        }
        requests
    });
    (url, peer)
}

fn write_chunk(socket: &mut TcpStream, data: &str) {
    write!(socket, "{:x}\r\n{data}\r\n", data.len()).unwrap();
    socket.flush().unwrap();
}

fn assert_closed(socket: &mut TcpStream) {
    let mut byte = [0];
    match socket.read(&mut byte) {
        Ok(0) => {}
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
            ) => {}
        result => panic!("unfinished SSE transport was not closed: {result:?}"),
    }
}

#[test]
fn native_sse_reconnects_only_from_committed_ids_and_204_stops() {
    native(|runtime| {
        let (url, peer) = scripted(vec![
            events("\u{feff}id: first\ndata: hello\n\nretry: 0\nid: not-committed\ndata: incomplete\n"),
            events("data: resumed\n\nid:\ndata: reset\n\n"),
            response("204 No Content", "", ""),
        ]);
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let client = HttpClient::builder()
                .no_proxy()
                .request_timeout(Duration::from_secs(5))
                .default_header("Last-Event-ID", "stale-client-default")
                .default_header("Accept", "application/json")
                .default_header("Accept-Encoding", "gzip")
                .default_header("Authorization", "Bearer origin-only")
                .build();
            let options = EventSourceOptions::default()
                .header("Last-Event-ID", "stale-option")
                .reconnect(ReconnectPolicy::new(5, Duration::ZERO));
            let mut source = EventSource::with_options(&cx, client, url, options).unwrap();
            let first = source.next_event().await.unwrap().unwrap();
            assert_eq!(first.data, "hello");
            assert_eq!(first.last_event_id, "first");
            let second = source.next_event().await.unwrap().unwrap();
            assert_eq!(second.data, "resumed");
            assert_eq!(second.last_event_id, "first");
            let third = source.next_event().await.unwrap().unwrap();
            assert_eq!(third.data, "reset");
            assert_eq!(third.last_event_id, "");
            assert!(source.next_event().await.is_none());
            assert!(source.is_terminated());
            assert_eq!(source.reconnects(), 2);
            assert!(source.next_event().await.is_none());
        });
        let requests = peer.join().unwrap();
        assert_eq!(requests.len(), 3);
        for (request, id) in requests.iter().zip(["", "first", ""]) {
            assert!(request.starts_with("GET /events?feed=one HTTP/1.1\r\n"));
            assert_eq!(header(request, "Accept"), Some("text/event-stream"));
            assert_eq!(header(request, "Accept-Encoding"), Some("identity"));
            assert_eq!(header(request, "Cache-Control"), Some("no-cache"));
            assert_eq!(header(request, "Last-Event-ID"), Some(id));
            assert_eq!(header(request, "Authorization"), Some("Bearer origin-only"));
        }
    });
}

#[test]
fn native_sse_finite_allowance_is_not_replenished_by_events() {
    native(|runtime| {
        for max_reconnects in [0, 1] {
            let (url, peer) = scripted(
                (0..=max_reconnects)
                    .map(|_| events("data: one\n\n"))
                    .collect(),
            );
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let options = EventSourceOptions::default()
                    .reconnect(ReconnectPolicy::new(max_reconnects, Duration::ZERO));
                let mut source = EventSource::with_options(&cx, client(), url, options).unwrap();
                for _ in 0..=max_reconnects {
                    assert_eq!(source.next_event().await.unwrap().unwrap().data, "one");
                }
                assert!(source.next_event().await.is_none());
                assert_eq!(source.reconnects(), max_reconnects);
            });
            assert_eq!(peer.join().unwrap().len(), max_reconnects as usize + 1);
        }
    });
}

#[test]
fn native_sse_rejects_redirects_and_invalid_metadata_without_retry() {
    native(|runtime| {
        let target = TcpListener::bind("127.0.0.1:0").unwrap();
        target.set_nonblocking(true).unwrap();
        let redirect_headers = format!(
            "Location: http://{}/stolen\r\n",
            target.local_addr().unwrap(),
        );
        let replies = [
            response("302 Found", &redirect_headers, ""),
            response("200 OK", "Content-Type: application/json\r\n", "{}"),
            response(
                "200 OK",
                "Content-Type: text/event-stream\r\nContent-Encoding: gzip\r\n",
                "not-gzip",
            ),
        ];
        for (index, reply) in replies.into_iter().enumerate() {
            let (url, peer) = scripted(vec![reply]);
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let options = EventSourceOptions::default()
                    .header("Authorization", "Bearer must-stay-at-origin")
                    .reconnect(ReconnectPolicy::new(3, Duration::ZERO));
                let mut source = EventSource::with_options(&cx, client(), url, options).unwrap();
                let error = source.next_event().await.unwrap().unwrap_err();
                match index {
                    0 => assert!(matches!(error, EventSourceError::UnexpectedStatus(302))),
                    1 => assert!(matches!(error, EventSourceError::InvalidContentType)),
                    2 => assert!(matches!(
                        error,
                        EventSourceError::UnsupportedContentEncoding(_)
                    )),
                    _ => unreachable!(),
                }
                assert_eq!(source.reconnects(), 0);
                assert!(source.next_event().await.is_none());
            });
            assert_eq!(peer.join().unwrap().len(), 1);
        }
        assert!(matches!(
            target.accept(),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ));
    });
}

#[test]
fn native_sse_dropped_next_wait_keeps_partial_event_and_drop_closes_socket() {
    native(|runtime| {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/partial", listener.local_addr().unwrap());
        let (resume_tx, resume_rx) = mpsc::channel();
        let peer = std::thread::spawn(move || {
            let mut socket = accept(&listener);
            request(&mut socket);
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\n\
                    Content-Type: text/event-stream\r\n\
                    Transfer-Encoding: chunked\r\n\r\n",
                )
                .unwrap();
            write_chunk(&mut socket, "id: first\ndata: ready\n\nid: second\ndata: par");
            resume_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            write_chunk(&mut socket, "tial\n\n");
            assert_closed(&mut socket);
        });
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let mut source = EventSource::new(&cx, client(), url).unwrap();
            assert_eq!(source.next_event().await.unwrap().unwrap().data, "ready");
            let mut wait = Box::pin(source.next_event());
            poll_fn(|task| {
                assert!(wait.as_mut().poll(task).is_pending());
                Poll::Ready(())
            })
            .await;
            drop(wait);
            assert!(!source.is_terminated());
            assert_eq!(source.last_event_id(), "first");
            resume_tx.send(()).unwrap();
            let event = source.next_event().await.unwrap().unwrap();
            assert_eq!(event.data, "partial");
            assert_eq!(event.last_event_id, "second");
            drop(source);
        });
        peer.join().unwrap();
    });
}

#[test]
fn native_sse_owner_cancellation_wakes_parked_body_and_reconnect_delay() {
    native(|runtime| {
        for backoff in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let url = format!("http://{}/parked", listener.local_addr().unwrap());
            let peer = std::thread::spawn(move || {
                let mut socket = accept(&listener);
                request(&mut socket);
                if backoff {
                    socket
                        .write_all(events("data: ready\n\n").as_bytes())
                        .unwrap();
                } else {
                    socket
                        .write_all(
                            b"HTTP/1.1 200 OK\r\n\
                            Content-Type: text/event-stream\r\n\
                            Transfer-Encoding: chunked\r\n\r\n",
                        )
                        .unwrap();
                    write_chunk(&mut socket, "data: ready\n\n");
                    assert_closed(&mut socket);
                }
            });
            let owner = runtime.request_cx_with_budget(Budget::INFINITE);
            let reason = CancelReason::user("SSE subscriber stopped")
                .with_cause(CancelReason::shutdown().with_message("service draining"));
            let (parked_tx, parked_rx) = mpsc::channel();
            let controller_owner = owner.clone();
            let controller_reason = reason.clone();
            let controller = std::thread::spawn(move || {
                parked_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                controller_owner.cancel_with_reason(controller_reason);
            });
            runtime.block_on(async {
                let options = EventSourceOptions::default()
                    .reconnect(ReconnectPolicy::new(3, Duration::from_secs(60)));
                let mut source = EventSource::with_options(&owner, client(), url, options).unwrap();
                assert_eq!(source.next_event().await.unwrap().unwrap().data, "ready");
                let mut parked = Some(parked_tx);
                let error = poll_fn(|task| {
                    let result = Pin::new(&mut source).poll_next(task);
                    if result.is_pending() && let Some(parked) = parked.take() {
                        parked.send(()).unwrap();
                    }
                    result
                })
                .await
                .unwrap()
                .unwrap_err();
                assert!(matches!(
                    error,
                    EventSourceError::Cancelled(ref observed) if *observed == reason
                ));
                assert_eq!(source.reconnects(), 0);
                assert!(source.is_terminated());
                assert!(source.next_event().await.is_none());
            });
            controller.join().unwrap();
            peer.join().unwrap();
        }
    });
}

#[test]
fn native_sse_budget_deadline_wakes_reconnect_delay() {
    native(|runtime| {
        let clock = runtime.request_cx_with_budget(Budget::INFINITE);
        let owner = runtime.request_cx_with_budget(
            Budget::INFINITE.with_deadline(clock.now() + Duration::from_secs(1)),
        );
        let (url, peer) = scripted(vec![events("data: ready\n\n")]);
        runtime.block_on(async {
            let options = EventSourceOptions::default()
                .reconnect(ReconnectPolicy::new(1, Duration::from_secs(60)));
            let mut source = EventSource::with_options(&owner, client(), url, options).unwrap();
            assert_eq!(source.next_event().await.unwrap().unwrap().data, "ready");
            let error = source.next_event().await.unwrap().unwrap_err();
            assert!(matches!(
                error,
                EventSourceError::Cancelled(reason) if reason.kind == CancelKind::Deadline
            ));
            assert_eq!(source.reconnects(), 0);
            assert!(source.is_terminated());
        });
        assert_eq!(peer.join().unwrap().len(), 1);
    });
}
