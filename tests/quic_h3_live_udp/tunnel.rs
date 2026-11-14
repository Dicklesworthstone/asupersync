//! Public CONNECT ownership across authenticated loopback UDP and native tasks.

use super::*;
use asupersync::http::h3::{
    NativeH3ResponseBodyWriter, NativeH3Tunnel, NativeH3TunnelError, NativeH3TunnelEvent,
};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;

#[derive(Clone, Copy)]
enum ResponseFin {
    AfterPayload,
    AfterRequest,
    Hold,
}

struct PeerPlan {
    settings: H3Settings,
    response: H3ResponseHead,
    bytes: Bytes,
    fin: ResponseFin,
    gate_upload: bool,
}

impl PeerPlan {
    fn new(bytes: Vec<u8>, fin: ResponseFin) -> Self {
        Self {
            settings: H3Settings::default(),
            // Successful CONNECT ignores this field: it cannot turn DATA into
            // an empty HTTP body or close either tunnel direction.
            response: H3ResponseHead::new(200, vec![("content-length".to_owned(), "0".to_owned())])
                .unwrap(),
            bytes: Bytes::from(bytes),
            fin,
            gate_upload: false,
        }
    }
}

#[derive(Default)]
struct PeerControl {
    upload_released: AtomicBool,
    request_finished: AtomicBool,
    server_wake: Mutex<Option<Waker>>,
}

impl PeerControl {
    fn release_upload(&self) {
        self.upload_released.store(true, Ordering::SeqCst);
        let wake = self.server_wake.lock().unwrap().clone();
        if let Some(wake) = wake {
            wake.wake();
        }
    }
}

#[derive(Default, Debug)]
struct PeerProgress {
    request: Option<H3RequestHead>,
    upload: Vec<u8>,
    request_finished: bool,
    response_finished: bool,
}

fn connect_head(extended: bool) -> H3RequestHead {
    H3RequestHead::new_with_settings(
        H3PseudoHeaders {
            method: Some("CONNECT".to_owned()),
            authority: Some("localhost:443".to_owned()),
            scheme: extended.then(|| "https".to_owned()),
            path: extended.then(|| "/tunnel".to_owned()),
            protocol: extended.then(|| "websocket".to_owned()),
            ..Default::default()
        },
        vec![("x-tunnel-test".to_owned(), "native-owner".to_owned())],
        extended,
    )
    .unwrap()
}

fn patterned(len: usize, salt: usize) -> Vec<u8> {
    (0..len)
        .map(|index| ((index * 13 + salt) % 251) as u8)
        .collect()
}

/// Drive the actual peer for the complete lifetime of the public client owner.
/// Application completion explicitly wakes the peer; no timer pumps transport.
async fn exchange<R, F, Fut>(
    cx: &Cx,
    request: H3RequestHead,
    plan: PeerPlan,
    config: NativeH3ClientConfig,
    execute: F,
) -> (R, PeerProgress)
where
    F: FnOnce(NativeH3Client, H3RequestHead, SocketAddr, Arc<PeerControl>) -> Fut,
    Fut: Future<Output = R>,
{
    let (client, server) = live_pair_with_client_session(cx, H3_ALPN, H3_ALPN, false).await;
    let (client, session) = client.expect("authenticated fresh CONNECT client");
    assert!(
        session.is_none(),
        "the public client must initialize HTTP/3"
    );
    let address = client.local_addr();
    let client = NativeH3Client::new(client, config).unwrap();
    let mut server = server.expect("authenticated native CONNECT peer");
    let server_id = server.local_connection_id();
    let mut session = NativeH3Session::server();
    session
        .enable_streaming_receive(std::num::NonZeroUsize::new(16_384).unwrap())
        .unwrap();
    session
        .initialize(cx, server.connection_mut(), plan.settings)
        .unwrap();
    let mut endpoint = server
        .into_managed(
            cx,
            ManagedEndpointConfig {
                is_server: true,
                max_connections: 1,
                ..Default::default()
            },
        )
        .unwrap();
    let completed = Arc::new(AtomicBool::new(false));
    let peer = Arc::new(PeerControl::default());
    if !plan.gate_upload {
        peer.release_upload();
    }
    let mut progress = PeerProgress::default();
    let mut stream = None;
    let mut writer = None::<NativeH3ResponseBodyWriter>;
    let mut written = 0;
    let serving = endpoint.run_event_loop_with_application(cx, |cx, endpoint, task| {
        *peer.server_wake.lock().unwrap() = Some(task.waker().clone());
        match endpoint.with_connection_mut(cx, server_id, |connection| {
            for step in 0..32 {
                if stream.is_some() && !peer.upload_released.load(Ordering::SeqCst) {
                    break;
                }
                let event = match session.poll_event(cx, connection, task) {
                    Poll::Pending => break,
                    Poll::Ready(Err(error)) => {
                        return Poll::Ready(Err(ManagedEndpointError::UdpEndpoint(
                            error.to_string(),
                        )));
                    }
                    Poll::Ready(Ok(event)) => event,
                };
                match event {
                    NativeH3Event::RequestHeaders { stream_id, head } => {
                        assert!(stream.replace(stream_id).is_none());
                        assert!(progress.request.replace(head).is_none());
                    }
                    NativeH3Event::Data { stream_id, bytes } => {
                        assert_eq!(Some(stream_id), stream);
                        progress.upload.extend_from_slice(&bytes);
                    }
                    NativeH3Event::Finished { stream_id } => {
                        assert_eq!(Some(stream_id), stream);
                        assert!(!progress.request_finished, "one request FIN");
                        progress.request_finished = true;
                        peer.request_finished.store(true, Ordering::SeqCst);
                    }
                    NativeH3Event::Settings(_) | NativeH3Event::StreamReset { .. } => {}
                    other => panic!("unexpected CONNECT peer event: {other:?}"),
                }
                if step == 31 {
                    task.waker().wake_by_ref();
                }
            }
            if let Some(stream) = stream {
                if writer.is_none() {
                    writer = Some(
                        session
                            .start_response_body_writer(
                                cx,
                                connection,
                                stream,
                                &plan.response,
                                false,
                            )
                            .unwrap(),
                    );
                }
                let writer = writer.as_mut().unwrap();
                for step in 0..32 {
                    if writer.is_finished() {
                        break;
                    }
                    match writer.poll_flush(cx, connection, task) {
                        Poll::Pending => break,
                        Poll::Ready(Err(error)) => {
                            return Poll::Ready(Err(ManagedEndpointError::UdpEndpoint(
                                error.to_string(),
                            )));
                        }
                        Poll::Ready(Ok(_)) => {}
                    }
                    if writer.is_finished() {
                        break;
                    }
                    if written < plan.bytes.len() {
                        let end = (written + writer.max_frame_payload_size()).min(plan.bytes.len());
                        writer.queue_data(plan.bytes.slice(written..end)).unwrap();
                        written = end;
                    } else if matches!(plan.fin, ResponseFin::Hold)
                        || (matches!(plan.fin, ResponseFin::AfterRequest)
                            && !progress.request_finished)
                    {
                        break;
                    } else {
                        writer.finish().unwrap();
                    }
                    if step == 31 {
                        task.waker().wake_by_ref();
                    }
                }
                progress.response_finished = writer.is_finished();
            }
            if completed.load(Ordering::SeqCst) {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        }) {
            Ok(result) => result,
            Err(error) => Poll::Ready(Err(error)),
        }
    });
    let requesting = async {
        let mut operation = Box::pin(execute(client, request, address, Arc::clone(&peer)));
        let result = operation.as_mut().await;
        drop(operation);
        completed.store(true, Ordering::SeqCst);
        let wake = peer.server_wake.lock().unwrap().clone();
        if let Some(wake) = wake {
            wake.wake();
        }
        result
    };
    let (result, _server_terminal) =
        asupersync::time::timeout(cx.now(), Duration::from_secs(10), zip(requesting, serving))
            .await
            .expect("CONNECT owner and peer must terminate within the watchdog");
    // A close packet can end the server before its completion wake is polled.
    // The tests assert the client outcome and actual peer-observed stream bytes.
    drop(endpoint);
    drop(std::net::UdpSocket::bind(address).expect("terminal tunnel releases its real UDP socket"));
    (result, progress)
}

async fn transfer(
    mut tunnel: NativeH3Tunnel,
    upload: &[u8],
    peer: &PeerControl,
    wait_for_read_fin: bool,
) -> Result<Vec<u8>, NativeH3TunnelError> {
    assert_eq!(tunnel.response_head().status, 200);
    let stream_id = tunnel.stream_id();
    let mut sent = 0;
    let mut received = Vec::new();
    let mut read_closed = false;
    let mut write_closed = false;
    let mut fin_requested = false;
    let mut busy_observations = 0;
    loop {
        if !fin_requested && (!wait_for_read_fin || read_closed) && tunnel.send_ready() {
            if sent < upload.len() {
                let accepted = tunnel.queue_data(&upload[sent..])?;
                assert!((1..=16_384).contains(&accepted));
                sent += accepted;
                assert_eq!(tunnel.sent_bytes(), sent);
                assert!(!tunnel.send_ready());
                assert_eq!(tunnel.queue_data(b"never admitted")?, 0);
                busy_observations += 1;
            }
            if sent == upload.len() {
                // FIN must follow the last accepted DATA even though its slot
                // remains occupied and has not yet been driven to the socket.
                tunnel.finish_send()?;
                tunnel.finish_send()?;
                fin_requested = true;
                assert!(matches!(
                    tunnel.queue_data(b"after FIN"),
                    Err(NativeH3TunnelError::Closed)
                ));
            }
        }
        match tunnel.next_event().await? {
            Some(NativeH3TunnelEvent::SendReady) => {
                assert!(!write_closed);
                assert!(tunnel.send_ready());
            }
            Some(NativeH3TunnelEvent::Data(bytes)) => {
                assert!(!read_closed);
                assert!(bytes.len() <= 16_384);
                if !peer.upload_released.load(Ordering::SeqCst) {
                    assert!(
                        !peer.request_finished.load(Ordering::SeqCst),
                        "response DATA is observable before the peer can consume upload FIN"
                    );
                    peer.release_upload();
                }
                received.extend_from_slice(&bytes);
            }
            Some(NativeH3TunnelEvent::ReadClosed) => {
                assert!(!read_closed, "one receive-half close notification");
                read_closed = true;
                if wait_for_read_fin {
                    assert_eq!(sent, 0, "this peer closes before upload starts");
                    assert!(!write_closed);
                    assert!(!tunnel.is_closed());
                }
            }
            Some(NativeH3TunnelEvent::WriteClosed) => {
                assert!(!write_closed, "one send-half close notification");
                assert!(fin_requested);
                assert_eq!(sent, upload.len());
                write_closed = true;
            }
            None => break,
            Some(other) => panic!("unexpected tunnel event: {other:?}"),
        }
    }
    assert!(read_closed && write_closed);
    assert!(
        tunnel.is_closed(),
        "terminal success drains both halves and recovery"
    );
    assert!(tunnel.next_event().await?.is_none());
    assert_eq!(tunnel.stream_id(), stream_id);
    assert_eq!(tunnel.sent_bytes(), upload.len());
    assert_eq!(tunnel.received_bytes(), received.len());
    if !upload.is_empty() {
        assert!(busy_observations > 0);
    }
    Ok(received)
}

#[test]
fn tunnel_streams_both_directions_past_initial_credit_with_one_send_slot() {
    let runtime = managed_runtime();
    let work: Pin<Box<dyn Future<Output = ()> + Send>> = Box::pin(async {
        let cx = Cx::current().unwrap();
        let upload = patterned(800_000, 17);
        let download = patterned(900_000, 73);
        assert!(upload.len() as u64 > connection_config().recv_window);
        assert!(download.len() as u64 > connection_config().recv_window);
        let mut plan = PeerPlan::new(download.clone(), ResponseFin::AfterRequest);
        plan.gate_upload = true;
        let action_cx = cx.clone();
        let expected_upload = upload.clone();
        let (result, progress) = exchange(
            &cx,
            connect_head(false),
            plan,
            NativeH3ClientConfig {
                max_request_body_bytes: upload.len(),
                max_response_body_bytes: download.len(),
                ..Default::default()
            },
            move |client, head, _, peer| async move {
                let tunnel = client.connect_tunnel(&action_cx, head).await?;
                transfer(tunnel, &upload, &peer, false).await
            },
        )
        .await;
        assert_eq!(
            result.expect("duplex CONNECT across repeated credit updates"),
            download
        );
        assert_eq!(progress.upload, expected_upload);
        assert!(progress.request_finished && progress.response_finished);
        let request = progress.request.unwrap();
        assert_eq!(request.pseudo, connect_head(false).pseudo);
        assert!(
            request
                .headers
                .iter()
                .all(|(name, _)| name != "content-length")
        );
    });
    runtime.block_on(runtime.handle().spawn(work));
    managed_assert_runtime_cleanup(&runtime);
}

#[test]
fn tunnel_peer_fin_keeps_upload_open_and_success_content_length_is_ignored() {
    let runtime = managed_runtime();
    let work: Pin<Box<dyn Future<Output = ()> + Send>> = Box::pin(async {
        let cx = Cx::current().unwrap();
        let upload = patterned(600_000, 41);
        let download = patterned(41_000, 97);
        let action_cx = cx.clone();
        let expected_upload = upload.clone();
        let (result, progress) = exchange(
            &cx,
            connect_head(false),
            PeerPlan::new(download.clone(), ResponseFin::AfterPayload),
            NativeH3ClientConfig::default(),
            move |client, head, _, peer| async move {
                let tunnel = client.connect_tunnel(&action_cx, head).await?;
                assert_eq!(
                    tunnel.response_head().headers,
                    [("content-length".to_owned(), "0".to_owned())]
                );
                transfer(tunnel, &upload, &peer, true).await
            },
        )
        .await;
        assert_eq!(
            result.expect("upload survives independently closed receive half"),
            download
        );
        assert_eq!(progress.upload, expected_upload);
        assert!(progress.request_finished && progress.response_finished);
    });
    runtime.block_on(runtime.handle().spawn(work));
    managed_assert_runtime_cleanup(&runtime);
}

#[test]
fn tunnel_extended_connect_negotiates_settings_and_reports_rejection() {
    let runtime = managed_runtime();
    let work: Pin<Box<dyn Future<Output = ()> + Send>> = Box::pin(async {
        let cx = Cx::current().unwrap();
        for enabled in [None, Some(false), Some(true)] {
            let mut plan = PeerPlan::new(Vec::new(), ResponseFin::AfterRequest);
            plan.settings.enable_connect_protocol = enabled;
            let action_cx = cx.clone();
            let (result, progress) = exchange(
                &cx,
                connect_head(true),
                plan,
                NativeH3ClientConfig::default(),
                move |client, head, _, peer| async move {
                    let tunnel = client.connect_tunnel(&action_cx, head).await?;
                    transfer(tunnel, b"extended protocol bytes", &peer, false).await
                },
            )
            .await;
            if enabled == Some(true) {
                assert!(result.expect("negotiated extended CONNECT").is_empty());
                assert_eq!(progress.upload, b"extended protocol bytes");
                assert!(progress.request_finished);
                assert_eq!(progress.request.unwrap().pseudo, connect_head(true).pseudo);
            } else {
                assert!(matches!(result, Err(NativeH3TunnelError::NotNegotiated)));
                assert!(
                    progress.request.is_none(),
                    "no CONNECT head observed without permission"
                );
                assert!(progress.upload.is_empty());
            }
        }
        let mut plan = PeerPlan::new(Vec::new(), ResponseFin::AfterPayload);
        plan.response = H3ResponseHead::new(403, Vec::new()).unwrap();
        let action_cx = cx.clone();
        let (result, progress) = exchange(
            &cx,
            connect_head(false),
            plan,
            NativeH3ClientConfig::default(),
            move |client, head, _, _| async move { client.connect_tunnel(&action_cx, head).await },
        )
        .await;
        assert!(matches!(result, Err(NativeH3TunnelError::Rejected(403))));
        assert!(progress.request.is_some());
        assert!(
            progress.upload.is_empty(),
            "rejection never admits tunneled bytes"
        );
    });
    runtime.block_on(runtime.handle().spawn(work));
    managed_assert_runtime_cleanup(&runtime);
}

async fn wait_send_ready(tunnel: &mut NativeH3Tunnel) {
    while !tunnel.send_ready() {
        assert!(matches!(
            tunnel.next_event().await.unwrap(),
            Some(NativeH3TunnelEvent::SendReady)
        ));
    }
}

async fn wait_until_parked<F: Future>(future: Pin<&mut F>) {
    let mut future = future;
    let mut parent = None::<Arc<ManagedParentWake>>;
    let mut attempts = 0;
    std::future::poll_fn(|task| {
        attempts += 1;
        assert!(attempts <= 512, "established tunnel must actually park");
        let parent = parent.get_or_insert_with(|| {
            Arc::new(ManagedParentWake {
                parent: task.waker().clone(),
                wakes: AtomicUsize::new(0),
            })
        });
        let waker = Waker::from(Arc::clone(parent));
        let before = parent.wakes.load(Ordering::SeqCst);
        assert!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(&waker))
                .is_pending()
        );
        if parent.wakes.load(Ordering::SeqCst) == before {
            Poll::Ready(())
        } else {
            task.waker().wake_by_ref();
            Poll::Pending
        }
    })
    .await;
}

#[test]
fn dropping_a_parked_tunnel_wait_preserves_owner_and_resumable_transfer() {
    let runtime = managed_runtime();
    let work: Pin<Box<dyn Future<Output = ()> + Send>> = Box::pin(async {
        let cx = Cx::current().unwrap();
        let action_cx = cx.clone();
        let (result, progress) = exchange(
            &cx,
            connect_head(false),
            PeerPlan::new(Vec::new(), ResponseFin::AfterRequest),
            NativeH3ClientConfig::default(),
            move |client, head, address, peer| async move {
                let mut tunnel = client.connect_tunnel(&action_cx, head).await?;
                wait_send_ready(&mut tunnel).await;
                let mut wait = Box::pin(tunnel.next_event());
                wait_until_parked(wait.as_mut()).await;
                std::net::UdpSocket::bind(address)
                    .expect_err("parked receive still owns the authenticated transport");
                drop(wait);
                std::net::UdpSocket::bind(address)
                    .expect_err("dropping only the borrowing wait preserves its owner");
                transfer(
                    tunnel,
                    b"resumed after an abandoned receive wait",
                    &peer,
                    false,
                )
                .await
            },
        )
        .await;
        assert!(
            result
                .expect("resumed tunnel finishes both directions")
                .is_empty()
        );
        assert_eq!(progress.upload, b"resumed after an abandoned receive wait");
        assert!(progress.request_finished && progress.response_finished);
        assert_eq!(cx.timer_driver().unwrap().pending_count(), 0);
    });
    runtime.block_on(runtime.handle().spawn(work));
    managed_assert_runtime_cleanup(&runtime);
}

#[test]
fn cancelling_an_established_parked_tunnel_wakes_and_retires_native_ownership() {
    let runtime = managed_runtime();
    let work: Pin<Box<dyn Future<Output = ()> + Send>> = Box::pin(async {
        let cx = Cx::current().unwrap();
        let action_cx = cx.clone();
        let (result, progress) = exchange(
            &cx,
            connect_head(false),
            PeerPlan::new(Vec::new(), ResponseFin::Hold),
            NativeH3ClientConfig::default(),
            move |client, head, address, _| async move {
                let parked = Arc::new(AtomicBool::new(false));
                let child_parked = Arc::clone(&parked);
                let mut child = action_cx
                    .spawn(move |child_cx| {
                        let future: Pin<
                            Box<dyn Future<Output = Result<(), NativeH3TunnelError>> + Send>,
                        > =
                            Box::pin(async move {
                                let mut tunnel = client.connect_tunnel(&child_cx, head).await?;
                                let stream_id = tunnel.stream_id();
                                wait_send_ready(&mut tunnel).await;
                                let mut wait = Box::pin(tunnel.next_event());
                                wait_until_parked(wait.as_mut()).await;
                                child_parked.store(true, Ordering::SeqCst);
                                let result = wait.await;
                                assert!(
                                    matches!(
                                        &result,
                                        Err(NativeH3TunnelError::Client(
                                            NativeH3ClientError::Cancelled
                                        ))
                                    ),
                                    "parked owner must report typed cancellation: {result:?}"
                                );
                                assert!(
                                    !tunnel.is_closed(),
                                    "cancellation is not graceful completion"
                                );
                                assert!(tunnel.next_event().await.unwrap().is_none());
                                assert_eq!(tunnel.stream_id(), stream_id);
                                drop(std::net::UdpSocket::bind(address).expect(
                                    "cancellation retires socket before returning its error",
                                ));
                                result.map(|_| ())
                            });
                        future
                    })
                    .unwrap();
                let started = Instant::now();
                while !parked.load(Ordering::SeqCst) {
                    assert!(
                        started.elapsed() < IO_TIMEOUT,
                        "accepted tunnel must reach stable Pending"
                    );
                    assert!(!child.is_finished());
                    asupersync::runtime::yield_now().await;
                }
                std::net::UdpSocket::bind(address)
                    .expect_err("live parked child exclusively owns the native socket");
                child.abort();
                let result =
                    asupersync::time::timeout(action_cx.now(), IO_TIMEOUT, child.join(&action_cx))
                        .await
                        .expect("in-flight tunnel cancellation must wake its actual parked future")
                        .expect("structured cancellation retains the typed child result");
                assert!(child.is_finished());
                result
            },
        )
        .await;
        assert!(matches!(
            result,
            Err(NativeH3TunnelError::Client(NativeH3ClientError::Cancelled))
        ));
        assert!(
            progress.request.is_some(),
            "cancel an accepted tunnel, not unpolled setup"
        );
        assert!(progress.upload.is_empty());
        assert!(!progress.request_finished);
        assert_eq!(cx.timer_driver().unwrap().pending_count(), 0);
    });
    runtime.block_on(runtime.handle().spawn(work));
    managed_assert_runtime_cleanup(&runtime);
}

#[test]
fn established_tunnel_outlives_setup_timeout_but_enforces_actual_poller_authority() {
    let runtime = managed_runtime();
    let work: Pin<Box<dyn Future<Output = ()> + Send>> = Box::pin(async {
        let cx = Cx::current().unwrap();
        let action_cx = cx.clone();
        let setup_timeout = Duration::from_secs(1);
        let (result, progress) = exchange(
            &cx,
            connect_head(false),
            PeerPlan::new(Vec::new(), ResponseFin::Hold),
            NativeH3ClientConfig {
                timeout: setup_timeout,
                ..Default::default()
            },
            move |client, head, address, _| async move {
                let mut tunnel = client.connect_tunnel(&action_cx, head).await?;
                let stream_id = tunnel.stream_id();
                wait_send_ready(&mut tunnel).await;
                // The peer keeps both directions open. A configured setup
                // timeout must not become a lifetime limit on accepted tunnels.
                asupersync::time::sleep(action_cx.now(), setup_timeout + Duration::from_millis(50))
                    .await;
                let bytes = b"DATA after the setup deadline";
                assert_eq!(tunnel.queue_data(bytes)?, bytes.len());
                wait_send_ready(&mut tunnel).await;
                assert_eq!(tunnel.sent_bytes(), bytes.len());
                assert!(!tunnel.is_closed());
                std::net::UdpSocket::bind(address)
                    .expect_err("accepted tunnel still owns its socket after setup timeout");

                let mut wait = Box::pin(tunnel.next_event());
                let result = std::future::poll_fn(|task| {
                    // This is the same native task as the constructor, but
                    // with less authority. Identity-based deduplication must
                    // not accidentally restore its owner's wider capability.
                    let _restricted = Cx::push_restriction(asupersync::cx::cap::CapMask::none());
                    wait.as_mut().poll(task)
                })
                .await;
                drop(wait);
                assert!(
                    matches!(
                        &result,
                        Err(NativeH3TunnelError::Client(NativeH3ClientError::Admission(
                            _
                        )))
                    ),
                    "narrowed actual poller must be refused: {result:?}"
                );
                assert!(!tunnel.is_closed());
                assert!(tunnel.next_event().await.unwrap().is_none());
                assert_eq!(tunnel.stream_id(), stream_id);
                drop(
                    std::net::UdpSocket::bind(address)
                        .expect("authority refusal retires the owned transport before return"),
                );
                result.map(|_| ())
            },
        )
        .await;
        assert!(matches!(
            result,
            Err(NativeH3TunnelError::Client(NativeH3ClientError::Admission(
                _
            )))
        ));
        assert!(progress.request.is_some());
        assert!(!progress.request_finished);
        assert_eq!(cx.timer_driver().unwrap().pending_count(), 0);
    });
    runtime.block_on(runtime.handle().spawn(work));
    managed_assert_runtime_cleanup(&runtime);
}
