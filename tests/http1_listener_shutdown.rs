//! Native regressions for parked HTTP/1 connection tasks owned by a listener.
//!
//! The observer delegates every operation to a real reactor-backed TCP stream.
//! It reports actual Pending reads without manufacturing Pending or waking the
//! serving task. Peers remain open and silent until the shutdown verdict.

#![cfg(all(not(target_arch = "wasm32"), feature = "test-internals"))]
#![recursion_limit = "256"]

use std::io::Write;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use asupersync::Cx;
use asupersync::http::h1::server::{
    ConnectionPhase, HostPolicy, Http1Config, Http1StreamingConfig, Http1StreamingServer,
};
use asupersync::http::h1::stream::Http1ProducedResponse;
use asupersync::http::h1::types::Response;
use asupersync::io::{AsyncRead, AsyncWrite, ReadBuf};
use asupersync::net::TcpStream;
use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::server::connection::ConnectionManager;
use asupersync::server::shutdown::{ShutdownPhase, ShutdownSignal};
use asupersync::sync::Notify;
use asupersync::types::CancelKind;

const WATCHDOG: Duration = Duration::from_secs(2);

#[derive(Default)]
struct ReadWitness {
    pending: AtomicUsize,
    bytes: AtomicUsize,
    parked_bytes: AtomicUsize,
    dropped: AtomicUsize,
    parked: Notify,
}

struct ObservedRequestSocket {
    inner: TcpStream,
    witness: Arc<ReadWitness>,
}

impl AsyncRead for ObservedRequestSocket {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        self.witness
            .bytes
            .fetch_add(buf.filled().len() - before, Ordering::AcqRel);
        if result.is_pending() {
            self.witness.parked_bytes.store(
                self.witness.bytes.load(Ordering::Acquire),
                Ordering::Release,
            );
            self.witness.pending.fetch_add(1, Ordering::AcqRel);
            self.witness.parked.notify_one();
        }
        result
    }
}

impl AsyncWrite for ObservedRequestSocket {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl Drop for ObservedRequestSocket {
    fn drop(&mut self) {
        self.witness.dropped.fetch_add(1, Ordering::AcqRel);
    }
}

fn socket_pair(request: &[u8]) -> (std::net::TcpStream, std::net::TcpStream) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind native peer");
    let mut peer =
        std::net::TcpStream::connect(listener.local_addr().unwrap()).expect("connect native peer");
    peer.write_all(request).expect("send request prefix");
    let (server, _) = listener.accept().expect("accept native peer");
    server.set_nonblocking(true).expect("nonblocking server");
    (server, peer)
}

fn runtime(workers: usize) -> Runtime {
    let builder = if workers == 0 {
        RuntimeBuilder::current_thread()
    } else {
        RuntimeBuilder::multi_thread().worker_threads(workers)
    };
    builder
        .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
        .build()
        .expect("native HTTP/1 runtime")
}

fn assert_retired(runtime: &Runtime) {
    let started = Instant::now();
    while !runtime.is_quiescent() {
        assert!(started.elapsed() < WATCHDOG, "connection tasks must retire");
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

async fn await_parked(witness: &ReadWitness, expected_bytes: usize) {
    asupersync::time::timeout(
        asupersync::time::wall_now(),
        WATCHDOG,
        witness.parked.wait_until(|| {
            witness.pending.load(Ordering::Acquire) > 0
                && witness.parked_bytes.load(Ordering::Acquire) >= expected_bytes
        }),
    )
    .await
    .expect("server must reach an actual pending TCP read before shutdown");
}

#[test]
fn silent_streaming_heads_release_on_drain_force_close_and_owner_cancel() {
    for workers in [0, 1, 2] {
        for produced in [false, true] {
            for partial in [false, true] {
                for trigger in ["drain", "force-close", "owner-cancel"] {
                    let request = if partial {
                        &b"GET / HTTP/1.1\r\nHost:"[..]
                    } else {
                        &[]
                    };
                    let (server, peer) = socket_pair(request);
                    let runtime = runtime(workers);
                    let handle = runtime.handle();
                    runtime.block_on(async move {
                        let witness = Arc::new(ReadWitness::default());
                        let shutdown = ShutdownSignal::new();
                        let manager = ConnectionManager::new(Some(1), shutdown.clone());
                        let in_flight = Arc::new(AtomicUsize::new(0));
                        let handler_calls = Arc::new(AtomicUsize::new(0));
                        let owner = Arc::new(Mutex::new(None::<Cx>));
                        let guard = manager.register(peer.local_addr().unwrap()).expect("connection slot");
                        let socket = ObservedRequestSocket {
                            inner: TcpStream::from_std(server).expect("reactor stream"),
                            witness: Arc::clone(&witness),
                        };
                        let serving_signal = shutdown.clone();
                        let serving_in_flight = Arc::clone(&in_flight);
                        let serving_calls = Arc::clone(&handler_calls);
                        let serving_owner = Arc::clone(&owner);
                        let mut serving = handle.try_spawn(async move {
                            let _guard = guard;
                            let cx = Cx::current().expect("connection context");
                            *serving_owner.lock().unwrap() = Some(cx.clone());
                            let config = Http1Config {
                                idle_timeout: None,
                                request_timeout: None,
                                ..Http1Config::default()
                            };
                            if produced {
                                Http1StreamingServer::with_config_produced(
                                    move |_cx, _request| {
                                        serving_calls.fetch_add(1, Ordering::AcqRel);
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
                                    config,
                                )
                                .with_shutdown_signal(serving_signal)
                                .with_in_flight_requests(serving_in_flight)
                                .serve_produced(&cx, socket)
                                .await
                            } else {
                                Http1StreamingServer::with_config(
                                    move |_cx, _request| {
                                        serving_calls.fetch_add(1, Ordering::AcqRel);
                                        async { Response::new(200, "OK", Vec::new()) }
                                    },
                                    config,
                                )
                                .with_shutdown_signal(serving_signal)
                                .with_in_flight_requests(serving_in_flight)
                                .serve(&cx, socket)
                                .await
                            }
                        }).expect("spawn tracked connection");
                        await_parked(&witness, request.len()).await;
                        assert_eq!(witness.bytes.load(Ordering::Acquire), request.len());
                        assert_eq!(manager.active_count(), 1);
                        assert_eq!(in_flight.load(Ordering::Acquire), 0);
                        let triggered = Instant::now();
                        if trigger == "owner-cancel" {
                            owner.lock().unwrap().as_ref().unwrap().cancel_fast(CancelKind::User);
                        } else {
                            assert!(manager.begin_drain(Duration::from_secs(60)));
                            if trigger == "force-close" {
                                assert!(shutdown.begin_force_close());
                            }
                        }
                        let verdict = asupersync::time::timeout(
                            asupersync::time::wall_now(), WATCHDOG, &mut serving,
                        ).await;
                        let elapsed = triggered.elapsed();
                        // Only failure cleanup may release the peer. Socket
                        // readability cannot rescue a missing shutdown waker.
                        drop(peer);
                        let state = verdict.expect("parked head must release within shutdown bound")
                            .expect("head shutdown closes normally");
                        assert_eq!(state.phase, ConnectionPhase::Closing);
                        assert_eq!(handler_calls.load(Ordering::Acquire), 0);
                        assert_eq!(witness.dropped.load(Ordering::Acquire), 1);
                        assert!(manager.is_empty(), "connection guard leaked");
                        assert_eq!(in_flight.load(Ordering::Acquire), 0);
                        if trigger == "drain" {
                            assert_eq!(shutdown.phase(), ShutdownPhase::Draining, "graceful drain must need no force-close");
                        }
                        eprintln!("{{\"bead\":\"asupersync-bi2462.103\",\"scenario\":\"parked-head\",\"workers\":{workers},\"produced\":{produced},\"partial\":{partial},\"trigger\":\"{trigger}\",\"pending_reads\":{},\"elapsed_ms\":{},\"connections\":0,\"handler_calls\":0}}", witness.pending.load(Ordering::Acquire), elapsed.as_millis());
                    });
                    assert_retired(&runtime);
                }
            }
        }
    }
}

#[test]
fn force_close_interrupts_unread_body_drain_after_handler_completion() {
    for workers in [0, 1, 2] {
        let request = b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\n\r\n";
        let (server, peer) = socket_pair(request);
        let runtime = runtime(workers);
        let handle = runtime.handle();
        runtime.block_on(async move {
            let witness = Arc::new(ReadWitness::default());
            let completed_handlers = Arc::new(AtomicUsize::new(0));
            let handler_completed = Arc::clone(&completed_handlers);
            let shutdown = ShutdownSignal::new();
            let manager = ConnectionManager::new(Some(1), shutdown.clone());
            let in_flight = Arc::new(AtomicUsize::new(0));
            let guard = manager.register(peer.local_addr().unwrap()).expect("connection slot");
            let socket = ObservedRequestSocket {
                inner: TcpStream::from_std(server).expect("reactor stream"),
                witness: Arc::clone(&witness),
            };
            let serving_signal = shutdown.clone();
            let serving_in_flight = Arc::clone(&in_flight);
            let mut serving = handle.try_spawn(async move {
                let _guard = guard;
                let cx = Cx::current().expect("connection context");
                Http1StreamingServer::with_config(
                    move |_cx, request| {
                        let completed = Arc::clone(&handler_completed);
                        async move {
                            drop(request.body);
                            completed.fetch_add(1, Ordering::AcqRel);
                            Response::new(200, "OK", b"done".to_vec())
                        }
                    },
                    Http1StreamingConfig::from(Http1Config {
                        allowed_hosts: HostPolicy::allow_list(vec!["localhost".to_owned()]),
                        idle_timeout: None,
                        request_timeout: None,
                        ..Http1Config::default()
                    }).unread_body_drain(8, 1024, Duration::from_secs(60)),
                )
                .with_shutdown_signal(serving_signal)
                .with_in_flight_requests(serving_in_flight)
                .serve(&cx, socket)
                .await
            }).expect("spawn tracked connection");
            await_parked(&witness, request.len()).await;
            assert_eq!(completed_handlers.load(Ordering::Acquire), 1, "handler must finish before body drain parks");
            assert_eq!(witness.bytes.load(Ordering::Acquire), request.len());
            assert_eq!(in_flight.load(Ordering::Acquire), 1);
            assert!(manager.begin_drain(Duration::from_secs(60)));
            let triggered = Instant::now();
            assert!(shutdown.begin_force_close());
            let verdict = asupersync::time::timeout(
                asupersync::time::wall_now(), WATCHDOG, &mut serving,
            ).await;
            let elapsed = triggered.elapsed();
            drop(peer);
            let state = verdict.expect("force-close must interrupt the 60-second protocol drain")
                .expect("force-close closes normally");
            assert_eq!(state.phase, ConnectionPhase::Closing);
            assert_eq!(state.requests_served, 0, "no response before body synchronization");
            assert_eq!(witness.dropped.load(Ordering::Acquire), 1);
            assert_eq!(completed_handlers.load(Ordering::Acquire), 1);
            assert!(manager.is_empty());
            assert_eq!(in_flight.load(Ordering::Acquire), 0);
            eprintln!("{{\"bead\":\"asupersync-bi2462.103\",\"scenario\":\"completed-handler-parked-body\",\"workers\":{workers},\"pending_reads\":{},\"elapsed_ms\":{},\"connections\":0,\"in_flight\":0}}", witness.pending.load(Ordering::Acquire), elapsed.as_millis());
        });
        assert_retired(&runtime);
    }
}
