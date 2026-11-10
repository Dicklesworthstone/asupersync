//! The native RFC 8441 client interoperates with the request-owned server.

use super::Http2ClientWebSocket;
use crate::channel::oneshot;
use crate::cx::Cx;
use crate::http::h1::Response;
use crate::http::h1::server::HostPolicy;
use crate::http::h1::stream::StreamingServerRequest;
use crate::http::h2::listener::{
    Http2Listener, Http2ProducedResponse, Http2StreamingListenerConfig,
};
use crate::http::h2::{Http2Client, Http2TunnelConfig};
use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
use crate::net::TcpStream;
use crate::net::websocket::{
    CloseCode, CloseReason, Message, WebSocketAcceptor, WebSocketConfig, WebSocketConnectOptions,
    WsError,
};
use crate::runtime::{RootDrainOutcome, Runtime, RuntimeBuilder};
use crate::types::{Budget, CancelKind};
use std::future::{Future, poll_fn};
use std::io;
use std::net::SocketAddr;
use std::num::NonZeroU64;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

const WATCHDOG: Duration = Duration::from_secs(10);
const AUTHORIZATION: &str = "Bearer private-http2-websocket-token";
const COOKIE: &str = "session=private-http2-websocket-cookie";
const ORIGIN: &str = "https://application.example";
const BULK_BYTES: usize = 1024 * 1024;

pub(super) fn native<F, Fut>(scenario: F)
where
    F: Fn(Cx, Cx) -> Fut + Copy + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let (send, receive) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let result = catch_unwind(AssertUnwindSafe(|| {
            for workers in [1, 2] {
                let builder = if workers == 1 {
                    RuntimeBuilder::current_thread()
                } else {
                    RuntimeBuilder::new().worker_threads(workers)
                };
                let runtime = builder.build().unwrap();
                let explicit_owner = runtime.request_cx_with_budget(Budget::INFINITE);
                runtime.block_on(async {
                    let root = Cx::current().unwrap();
                    let mut task = root
                        .spawn(move |driver| scenario(driver, explicit_owner))
                        .unwrap();
                    task.join(&root).await.unwrap();
                });
                let report = runtime.shutdown_drained(WATCHDOG);
                assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
                assert_eq!(report.live_tasks, 0);
                assert_eq!(report.pending_spawns, 0);
                assert_eq!(report.pending_obligations, 0);
            }
        }));
        let _ = send.send(result);
    });
    let result = receive
        .recv_timeout(Duration::from_secs(30))
        .expect("native HTTP/2 WebSocket client workflow must finish and quiesce");
    worker.join().unwrap();
    if let Err(payload) = result {
        resume_unwind(payload);
    }
}

fn require_send<F: Future + Send>(future: F) -> F {
    future
}

fn options() -> WebSocketConnectOptions {
    let mut config = WebSocketConfig::default()
        .protocol("chat")
        .ping_interval(None)
        .connect_timeout(Some(WATCHDOG));
    config.close_config.close_timeout = WATCHDOG;
    WebSocketConnectOptions::new(config)
        .try_header("Authorization", AUTHORIZATION)
        .unwrap()
        .try_header("Cookie", COOKIE)
        .unwrap()
        .try_header("Origin", ORIGIN)
        .unwrap()
}

fn tunnel() -> Http2TunnelConfig {
    Http2TunnelConfig::new(
        NonZeroU64::new(8 * BULK_BYTES as u64).unwrap(),
        NonZeroU64::new(8 * BULK_BYTES as u64).unwrap(),
    )
}

fn configuration() -> Http2StreamingListenerConfig {
    let mut config = Http2StreamingListenerConfig::default()
        .with_extended_connect(NonZeroU64::new(8 * BULK_BYTES as u64).unwrap());
    config.listener = config
        .listener
        .host_policy(HostPolicy::allow_list(vec![
            "127.0.0.1".to_owned(),
            "localhost".to_owned(),
        ]))
        // A tunnel must use its explicit policy rather than this ordinary-body cap.
        .max_body_size(8)
        .drain_timeout(Duration::from_secs(2))
        .hard_drain_timeout(Duration::from_secs(5));
    config
}

enum ListenerMode {
    Plain,
    #[cfg(feature = "tls")]
    Tls(crate::tls::TlsAcceptor),
}

struct Controls {
    driver: Cx,
    server: Cx,
    in_flight: Arc<AtomicUsize>,
}

async fn exercise<H, HFut, F, Fut>(driver: Cx, handler: H, mode: ListenerMode, workflow: F)
where
    H: Fn(StreamingServerRequest) -> HFut + Send + Sync + 'static,
    HFut: Future<Output = Http2ProducedResponse> + Send + 'static,
    F: FnOnce(SocketAddr, Controls) -> Fut + Send,
    Fut: Future<Output = ()> + Send,
{
    let listener =
        Http2Listener::bind_streaming_produced_with_config("127.0.0.1:0", handler, configuration())
            .await
            .unwrap()
            .flow_control_progress_timeout(WATCHDOG);
    let listener = match mode {
        ListenerMode::Plain => listener,
        #[cfg(feature = "tls")]
        ListenerMode::Tls(acceptor) => listener.with_tls(acceptor),
    };
    let address = listener.local_addr().unwrap();
    let manager = listener.connection_manager().clone();
    let in_flight = listener.in_flight_requests();
    let (started, mut starting) = oneshot::channel();
    let mut service = driver
        .spawn(move |server| async move {
            started.send_blocking(server.clone()).unwrap();
            listener.run_streaming_produced_in(&server).await
        })
        .unwrap();
    let server = starting.recv(&driver).await.unwrap();
    workflow(
        address,
        Controls {
            driver: driver.clone(),
            server,
            in_flight: Arc::clone(&in_flight),
        },
    )
    .await;
    if !manager.shutdown_signal().is_shutting_down() {
        assert!(manager.begin_drain(Duration::from_secs(2)));
    }
    let stats = service.join(&driver).await.unwrap().unwrap();
    let report = stats.drain_report.expect("request-aware native drain");
    assert!(report.reached_quiescence, "{report}");
    assert_eq!(in_flight.load(Ordering::SeqCst), 0);
    assert_eq!(manager.active_count(), 0);
}

fn assert_request(request: &StreamingServerRequest, scheme: &str, path: &str) -> String {
    assert_eq!(request.extended_connect_protocol(), Some("websocket"));
    assert_eq!(request.extended_connect_scheme(), Some(scheme));
    assert_eq!(request.head.uri, path);
    for (name, expected) in [
        ("authorization", AUTHORIZATION),
        ("cookie", COOKIE),
        ("origin", ORIGIN),
        ("sec-websocket-version", "13"),
    ] {
        assert_eq!(
            request
                .head
                .headers
                .iter()
                .filter(|(key, _)| key.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.as_str())
                .collect::<Vec<_>>(),
            vec![expected]
        );
    }
    for name in [
        "connection",
        "upgrade",
        "sec-websocket-key",
        "sec-websocket-accept",
        "proxy-authorization",
        "content-length",
    ] {
        assert!(
            !request
                .head
                .headers
                .iter()
                .any(|(key, _)| key.eq_ignore_ascii_case(name)),
            "unexpected HTTP/1 or proxy field {name}"
        );
    }
    request.extended_connect_authority().unwrap().to_owned()
}

async fn wait_retired(request: &Cx, in_flight: &AtomicUsize) {
    // `Diagnostics` is not `Send` (it can own an `Arc<RuntimeState>`, and a
    // region's finalizers are `Send` without `Sync`), so it must not live
    // across this await. Open it for each poll from the worker's runtime
    // handle instead; the spawned workflow that awaits this must stay `Send`.
    poll_fn(|task| {
        if in_flight.load(Ordering::SeqCst) == 0
            && Runtime::current_handle()
                .unwrap()
                .diagnostics()
                .unwrap()
                .explain_region_open(request.region_id())
                .region_state
                .is_none()
        {
            Poll::Ready(())
        } else {
            task.waker().wake_by_ref();
            Poll::Pending
        }
    })
    .await;
}

struct SessionDrop(Arc<AtomicUsize>);

impl Drop for SessionDrop {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn native_client_preserves_auth_query_and_protocol_then_completes_client_close() {
    native(|driver, owner| async move {
        assert_ne!(driver.task_id(), owner.task_id());
        let authority = Arc::new(Mutex::new(None));
        let observed_authority = Arc::clone(&authority);
        let closes = Arc::new(AtomicUsize::new(0));
        let observed_closes = Arc::clone(&closes);
        let (entered, mut entering) = oneshot::channel();
        let entered = Arc::new(Mutex::new(Some(entered)));
        let handler = move |request: StreamingServerRequest| {
            let entered = entered.lock().unwrap().take().unwrap();
            let closes = Arc::clone(&observed_closes);
            *observed_authority.lock().unwrap() =
                Some(assert_request(&request, "http", "/socket?room=7"));
            async move {
                WebSocketAcceptor::new()
                    .protocol("chat")
                    .ping_interval(None)
                    .close_timeout(WATCHDOG)
                    .accept_http2(request, move |cx, mut socket| async move {
                        entered.send_blocking(cx.clone()).unwrap();
                        assert_eq!(Cx::current().unwrap().task_id(), cx.task_id());
                        assert_eq!(socket.protocol(), Some("chat"));
                        assert!(socket.extensions().is_empty());
                        let message = socket.recv(&cx).await?.unwrap();
                        assert!(matches!(&message, Message::Text(text) if text == "native hello"));
                        socket.send(&cx, message).await?;
                        let Some(Message::Close(Some(reason))) = socket.recv(&cx).await? else {
                            panic!("client close reaches application exactly once");
                        };
                        assert_eq!(reason.raw_code, Some(1000));
                        assert_eq!(reason.text.as_deref(), Some("client finished"));
                        closes.fetch_add(1, Ordering::SeqCst);
                        assert!(socket.recv(&cx).await?.is_none());
                        socket.finish(&cx).await
                    })
                    .unwrap()
            }
        };
        exercise(driver, handler, ListenerMode::Plain, move |address, controls| async move {
            let client = Http2Client::new().timeout(WATCHDOG);
            let url = format!("ws://{address}/socket?room=7");
            let mut socket = require_send(Http2ClientWebSocket::connect(
                &owner, &client, &url, options(), tunnel(),
            ))
            .await
            .unwrap();
            assert_eq!(authority.lock().unwrap().as_deref(), Some(address.to_string().as_str()));
            assert_eq!(socket.protocol(), Some("chat"));
            assert!(socket.is_open());
            assert!(!socket.compression_enabled());
            let request = entering.recv(&controls.driver).await.unwrap();
            socket.send(&owner, Message::text("native hello")).await.unwrap();
            assert!(matches!(socket.recv(&owner).await.unwrap(), Some(Message::Text(text)) if text == "native hello"));
            socket
                .close(&owner, CloseReason::new(CloseCode::Normal, Some("client finished")))
                .await
                .unwrap();
            assert!(socket.is_closed());
            socket.finish(&owner).await.unwrap();
            wait_retired(&request, &controls.in_flight).await;
            assert_eq!(closes.load(Ordering::SeqCst), 1);
            assert!(owner.inner.read().cancel_waker_registrations.is_empty());
            assert!(!controls.server.is_cancel_requested());
        })
        .await;
    });
}

#[test]
fn dropped_receive_can_resume_and_report_server_close_once_after_both_half_closes() {
    native(|driver, owner| async move {
        let (release, released) = oneshot::channel();
        let released = Arc::new(Mutex::new(Some(released)));
        let (entered, mut entering) = oneshot::channel();
        let entered = Arc::new(Mutex::new(Some(entered)));
        let completed = Arc::new(AtomicUsize::new(0));
        let observed_completed = Arc::clone(&completed);
        let handler = move |request: StreamingServerRequest| {
            assert_request(&request, "http", "/server-close");
            let mut released = released.lock().unwrap().take().unwrap();
            let entered = entered.lock().unwrap().take().unwrap();
            let completed = Arc::clone(&observed_completed);
            async move {
                WebSocketAcceptor::new()
                    .protocol("chat")
                    .ping_interval(None)
                    .close_timeout(WATCHDOG)
                    .accept_http2(request, move |cx, mut socket| async move {
                        entered.send_blocking(cx.clone()).unwrap();
                        released.recv(&cx).await.unwrap();
                        socket
                            .close(
                                &cx,
                                CloseReason::new(CloseCode::GoingAway, Some("maintenance")),
                            )
                            .await?;
                        let receipt = socket.finish(&cx).await?;
                        completed.fetch_add(1, Ordering::SeqCst);
                        Ok(receipt)
                    })
                    .unwrap()
            }
        };
        exercise(
            driver,
            handler,
            ListenerMode::Plain,
            move |address, controls| async move {
                let client = Http2Client::new().timeout(WATCHDOG);
                let mut socket = Http2ClientWebSocket::connect(
                    &owner,
                    &client,
                    &format!("ws://{address}/server-close"),
                    options(),
                    tunnel(),
                )
                .await
                .unwrap();
                let request = entering.recv(&controls.driver).await.unwrap();
                {
                    let mut receiving = Box::pin(socket.recv(&owner));
                    poll_fn(|task| {
                        assert!(receiving.as_mut().poll(task).is_pending());
                        Poll::Ready(())
                    })
                    .await;
                }
                release.send_blocking(()).unwrap();
                let Some(Message::Close(Some(reason))) = socket.recv(&owner).await.unwrap() else {
                    panic!("one retained peer close receipt");
                };
                assert_eq!(reason.raw_code, Some(1001));
                assert_eq!(reason.text.as_deref(), Some("maintenance"));
                assert!(socket.is_closed());
                assert!(socket.recv(&owner).await.unwrap().is_none());
                socket.finish(&owner).await.unwrap();
                wait_retired(&request, &controls.in_flight).await;
                assert_eq!(completed.load(Ordering::SeqCst), 1);
            },
        )
        .await;
    });
}

struct CountWrites {
    stream: TcpStream,
    written: Arc<AtomicUsize>,
}

impl AsyncRead for CountWrites {
    fn poll_read(
        mut self: Pin<&mut Self>,
        task: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(task, output)
    }
}

impl AsyncWrite for CountWrites {
    fn poll_write(
        mut self: Pin<&mut Self>,
        task: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.stream).poll_write(task, data);
        if let Poll::Ready(Ok(written)) = result {
            self.written.fetch_add(written, Ordering::SeqCst);
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(task)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(task)
    }
}

#[test]
fn receive_finishes_a_dropped_partial_send_and_exchanges_bodies_beyond_both_windows() {
    native(|driver, owner| async move {
        let (release, released) = oneshot::channel();
        let released = Arc::new(Mutex::new(Some(released)));
        let (entered, mut entering) = oneshot::channel();
        let entered = Arc::new(Mutex::new(Some(entered)));
        let received = Arc::new(AtomicUsize::new(0));
        let observed_received = Arc::clone(&received);
        let handler = move |request: StreamingServerRequest| {
            assert_request(&request, "http", "/large");
            let mut released = released.lock().unwrap().take().unwrap();
            let entered = entered.lock().unwrap().take().unwrap();
            let received = Arc::clone(&observed_received);
            async move {
                WebSocketAcceptor::new()
                    .protocol("chat")
                    .ping_interval(None)
                    .close_timeout(WATCHDOG)
                    .accept_http2(request, move |cx, mut socket| async move {
                        entered.send_blocking(cx.clone()).unwrap();
                        // Retain a bounded, unread body so initial credit really runs out.
                        released.recv(&cx).await.unwrap();
                        let Some(Message::Binary(bytes)) = socket.recv(&cx).await? else {
                            panic!("the interrupted send must remain one binary message");
                        };
                        assert_eq!(bytes.len(), BULK_BYTES);
                        assert!(
                            bytes
                                .iter()
                                .enumerate()
                                .all(|(index, byte)| *byte == (index % 251) as u8)
                        );
                        received.fetch_add(1, Ordering::SeqCst);
                        socket.send(&cx, Message::Binary(bytes)).await?;
                        assert!(matches!(socket.recv(&cx).await?, Some(Message::Close(_))));
                        socket.finish(&cx).await
                    })
                    .unwrap()
            }
        };
        exercise(
            driver,
            handler,
            ListenerMode::Plain,
            move |address, controls| async move {
                let written = Arc::new(AtomicUsize::new(0));
                let io = CountWrites {
                    stream: TcpStream::connect(address).await.unwrap(),
                    written: Arc::clone(&written),
                };
                let client = Http2Client::new().timeout(WATCHDOG);
                let mut socket = require_send(Http2ClientWebSocket::<CountWrites>::connect_on(
                    &owner,
                    &client,
                    &format!("ws://{address}/large"),
                    io,
                    options(),
                    tunnel(),
                ))
                .await
                .unwrap();
                let request = entering.recv(&controls.driver).await.unwrap();
                written.store(0, Ordering::SeqCst);
                {
                    let body: Vec<u8> = (0..BULK_BYTES).map(|index| (index % 251) as u8).collect();
                    let mut sending =
                        Box::pin(require_send(socket.send(&owner, Message::binary(body))));
                    poll_fn(|task| {
                        assert!(
                            sending.as_mut().poll(task).is_pending(),
                            "a gated reader cannot admit a complete MiB"
                        );
                        if written.load(Ordering::SeqCst) >= 60 * 1024 {
                            Poll::Ready(())
                        } else {
                            task.waker().wake_by_ref();
                            Poll::Pending
                        }
                    })
                    .await;
                }
                assert!(written.load(Ordering::SeqCst) < BULK_BYTES);
                assert_eq!(received.load(Ordering::SeqCst), 0);
                release.send_blocking(()).unwrap();
                // Do not call send again: recv must resume the accepted frame itself.
                let Some(Message::Binary(bytes)) = socket.recv(&owner).await.unwrap() else {
                    panic!("the complete message must return after receive-window replenishment");
                };
                assert_eq!(bytes.len(), BULK_BYTES);
                assert!(
                    bytes
                        .iter()
                        .enumerate()
                        .all(|(index, byte)| *byte == (index % 251) as u8)
                );
                socket.finish(&owner).await.unwrap();
                wait_retired(&request, &controls.in_flight).await;
                assert_eq!(received.load(Ordering::SeqCst), 1);
            },
        )
        .await;
    });
}

struct ForwardWake {
    count: Arc<AtomicUsize>,
    parent: Waker,
}

impl Wake for ForwardWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.count.fetch_add(1, Ordering::SeqCst);
        self.parent.wake_by_ref();
    }
}

#[test]
fn parked_sessions_retire_on_explicit_owner_cancel_or_socket_drop() {
    for cancel in [false, true] {
        native(move |driver, owner| async move {
            assert_ne!(driver.task_id(), owner.task_id());
            let (parked, mut parking) = oneshot::channel();
            let parked = Arc::new(Mutex::new(Some(parked)));
            let drops = Arc::new(AtomicUsize::new(0));
            let observed_drops = Arc::clone(&drops);
            let handler = move |request: StreamingServerRequest| {
                assert_request(&request, "http", "/parked");
                let parked = parked.lock().unwrap().take().unwrap();
                let drops = Arc::clone(&observed_drops);
                async move {
                    WebSocketAcceptor::new()
                        .protocol("chat")
                        .ping_interval(None)
                        .close_timeout(WATCHDOG)
                        .accept_http2(request, move |cx, mut socket| async move {
                            let _retired = SessionDrop(drops);
                            let result = {
                                let mut receiving = Box::pin(socket.recv(&cx));
                                let mut parked = Some(parked);
                                poll_fn(|task| {
                                    let result = receiving.as_mut().poll(task);
                                    if result.is_pending()
                                        && let Some(parked) = parked.take()
                                    {
                                        parked.send_blocking(cx.clone()).unwrap();
                                    }
                                    result
                                })
                                .await
                            };
                            assert!(!matches!(result, Ok(Some(Message::Close(_)))));
                            assert!(socket.finish(&cx).await.is_err());
                            Err(WsError::Io(io::Error::new(
                                io::ErrorKind::ConnectionAborted,
                                "peer retired",
                            )))
                        })
                        .unwrap()
                }
            };
            exercise(driver, handler, ListenerMode::Plain, move |address, controls| async move {
                let client = Http2Client::new().timeout(WATCHDOG);
                let mut socket = Http2ClientWebSocket::connect(
                    &owner, &client, &format!("ws://{address}/parked"), options(), tunnel(),
                ).await.unwrap();
                let request = parking.recv(&controls.driver).await.unwrap();
                let wakes = Arc::new(AtomicUsize::new(0));
                {
                    let mut receiving = Box::pin(require_send(socket.recv(&controls.driver)));
                    poll_fn(|task| {
                        let wake = Waker::from(Arc::new(ForwardWake {
                            count: Arc::clone(&wakes),
                            parent: task.waker().clone(),
                        }));
                        assert!(receiving.as_mut().poll(&mut Context::from_waker(&wake)).is_pending());
                        Poll::Ready(())
                    }).await;
                    if cancel {
                        let before = wakes.load(Ordering::SeqCst);
                        owner.cancel_with(CancelKind::User, Some("stop the HTTP/2 WebSocket owner"));
                        assert!(wakes.load(Ordering::SeqCst) > before, "the captured owner wakes a receive driven by another Cx");
                        let error = receiving.as_mut().await.unwrap_err();
                        assert!(matches!(error, WsError::Io(error) if error.kind() == io::ErrorKind::Interrupted));
                    }
                }
                drop(socket);
                wait_retired(&request, &controls.in_flight).await;
                assert_eq!(drops.load(Ordering::SeqCst), 1);
                assert!(owner.inner.read().cancel_waker_registrations.is_empty());
                assert!(!controls.driver.is_cancel_requested());
                assert!(!controls.server.is_cancel_requested());
            }).await;
        });
    }
}

#[derive(Clone, Copy)]
enum Failure {
    Redirect,
    EndedSuccess,
    AcceptedAbort,
}

#[test]
fn redirects_ended_success_and_aborted_tunnels_never_become_clean_websockets() {
    for failure in [
        Failure::Redirect,
        Failure::EndedSuccess,
        Failure::AcceptedAbort,
    ] {
        native(move |driver, owner| async move {
            let calls = Arc::new(AtomicUsize::new(0));
            let observed_calls = Arc::clone(&calls);
            let (release, released) = oneshot::channel();
            let released = Arc::new(Mutex::new(Some(released)));
            let handler = move |request: StreamingServerRequest| {
                assert_request(&request, "http", "/failure");
                observed_calls.fetch_add(1, Ordering::SeqCst);
                let mut released = released.lock().unwrap().take().unwrap();
                async move {
                    match failure {
                        Failure::Redirect => {
                            let mut response = Response::new(307, "Temporary Redirect", Vec::new());
                            response.headers.push((
                                "location".to_owned(),
                                "http://127.0.0.1:1/credential-target".to_owned(),
                            ));
                            response
                                .headers
                                .push(("x-echo-credential".to_owned(), AUTHORIZATION.to_owned()));
                            Http2ProducedResponse::buffered(response)
                        }
                        Failure::EndedSuccess => {
                            Http2ProducedResponse::buffered(Response::new(200, "OK", Vec::new()))
                        }
                        Failure::AcceptedAbort => WebSocketAcceptor::new()
                            .protocol("chat")
                            .ping_interval(None)
                            .close_timeout(WATCHDOG)
                            .accept_http2(request, move |cx, mut socket| async move {
                                socket.send(&cx, Message::text("accepted")).await?;
                                released.recv(&cx).await.unwrap();
                                Err(WsError::Io(io::Error::new(
                                    io::ErrorKind::ConnectionAborted,
                                    "application stopped",
                                )))
                            })
                            .unwrap(),
                    }
                }
            };
            exercise(driver, handler, ListenerMode::Plain, move |address, controls| async move {
                let client = Http2Client::new().timeout(WATCHDOG);
                let result = Http2ClientWebSocket::connect(
                    &owner, &client, &format!("ws://{address}/failure"), options(), tunnel(),
                ).await;
                if matches!(failure, Failure::AcceptedAbort) {
                    let mut socket = result.unwrap();
                    assert!(matches!(socket.recv(&owner).await.unwrap(), Some(Message::Text(text)) if text == "accepted"));
                    release.send_blocking(()).unwrap();
                    assert!(socket.recv(&owner).await.is_err(), "RST cannot become a successful peer Close");
                    assert!(socket.finish(&owner).await.is_err());
                } else {
                    let error = result.err().expect("no socket before a live successful tunnel");
                    if matches!(failure, Failure::Redirect) {
                        assert!(matches!(
                            &error,
                            crate::net::websocket::WsConnectError::Handshake(
                                crate::net::websocket::HandshakeError::Rejected { status: 307, .. }
                            )
                        ));
                    } else {
                        assert!(
                            matches!(&error, crate::net::websocket::WsConnectError::Handshake(_)),
                            "an ended success is refused by protocol validation, not a setup timeout"
                        );
                    }
                    let diagnostics = format!("{error:?} {error}");
                    assert!(!diagnostics.contains(AUTHORIZATION));
                    assert!(!diagnostics.contains(COOKIE));
                    assert!(!diagnostics.contains("credential-target"));
                }
                assert_eq!(calls.load(Ordering::SeqCst), 1);
                assert!(!controls.driver.is_cancel_requested());
                assert!(owner.inner.read().cancel_waker_registrations.is_empty());
            }).await;
        });
    }
}

#[cfg(feature = "tls")]
#[test]
fn wss_client_uses_explicit_h2_trust_with_authenticated_native_endpoint() {
    use crate::tls::{
        Certificate, CertificateChain, PrivateKey, TlsAcceptorBuilder, TlsConnectorBuilder,
    };
    const CERT: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/tls/server.crt"
    ));
    const KEY: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/tls/server.key"
    ));
    native(|driver, owner| async move {
        let acceptor = TlsAcceptorBuilder::new(
            CertificateChain::from_pem(CERT).unwrap(),
            PrivateKey::from_pem(KEY).unwrap(),
        )
        .alpn_grpc()
        .build()
        .unwrap();
        let root = Certificate::from_pem(CERT).unwrap().remove(0);
        let connector = TlsConnectorBuilder::new()
            .add_root_certificate(&root)
            .alpn_grpc()
            .build()
            .unwrap();
        let authority = Arc::new(Mutex::new(None));
        let observed_authority = Arc::clone(&authority);
        let handler = move |request: StreamingServerRequest| {
            *observed_authority.lock().unwrap() =
                Some(assert_request(&request, "https", "/secure?room=9"));
            async move {
                WebSocketAcceptor::new()
                    .protocol("chat")
                    .ping_interval(None)
                    .close_timeout(WATCHDOG)
                    .accept_http2(request, |cx, mut socket| async move {
                        socket.send(&cx, Message::text("secure welcome")).await?;
                        assert!(matches!(socket.recv(&cx).await?, Some(Message::Text(text)) if text == "secure reply"));
                        assert!(matches!(socket.recv(&cx).await?, Some(Message::Close(_))));
                        socket.finish(&cx).await
                    })
                    .unwrap()
            }
        };
        exercise(driver, handler, ListenerMode::Tls(acceptor), move |address, _controls| async move {
            let client = Http2Client::new().timeout(WATCHDOG).tls_connector(connector);
            let mut socket = Http2ClientWebSocket::connect(
                &owner, &client, &format!("wss://localhost:{}/secure?room=9", address.port()), options(), tunnel(),
            ).await.unwrap();
            assert_eq!(authority.lock().unwrap().as_deref(), Some(format!("localhost:{}", address.port()).as_str()));
            assert_eq!(socket.protocol(), Some("chat"));
            assert!(matches!(socket.recv(&owner).await.unwrap(), Some(Message::Text(text)) if text == "secure welcome"));
            socket.send(&owner, Message::text("secure reply")).await.unwrap();
            socket.finish(&owner).await.unwrap();
        }).await;
    });
}

#[cfg(feature = "compression")]
#[test]
fn negotiated_deflate_uses_the_same_bounded_websocket_codec_over_h2() {
    native(|driver, owner| async move {
        let handler = |request: StreamingServerRequest| async move {
            assert_request(&request, "http", "/compressed");
            WebSocketAcceptor::new()
                .protocol("chat")
                .permessage_deflate()
                .ping_interval(None)
                .close_timeout(WATCHDOG)
                .accept_http2(request, |cx, mut socket| async move {
                    assert!(socket.compression_enabled());
                    let message = socket.recv(&cx).await?.unwrap();
                    assert!(matches!(&message, Message::Text(text) if text == &"compressed native message ".repeat(4096)));
                    socket.send(&cx, message).await?;
                    assert!(matches!(socket.recv(&cx).await?, Some(Message::Close(_))));
                    socket.finish(&cx).await
                })
                .unwrap()
        };
        exercise(driver, handler, ListenerMode::Plain, move |address, _controls| async move {
            let client = Http2Client::new().timeout(WATCHDOG);
            let mut socket = Http2ClientWebSocket::connect(
                &owner, &client, &format!("ws://{address}/compressed"), options().with_compression(), tunnel(),
            ).await.unwrap();
            assert!(socket.compression_enabled());
            let text = "compressed native message ".repeat(4096);
            socket.send(&owner, Message::text(text.clone())).await.unwrap();
            assert!(matches!(socket.recv(&owner).await.unwrap(), Some(Message::Text(reply)) if reply == text));
            socket.finish(&owner).await.unwrap();
        }).await;
    });
}
