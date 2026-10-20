//! Native HTTPS request ownership and handshake retirement.
//!
//! Uses the repository's local certificate fixture, real loopback sockets,
//! current-thread/two-worker runtimes, and unified/sharded state.
//! Run through RCH with `--features tls --test http1_owned_tls`.

#![cfg(all(feature = "tls", not(target_arch = "wasm32")))]

use asupersync::channel::oneshot;
use asupersync::cx::{ChildRegionSpec, Cx};
use asupersync::http::h1::Http1Client;
use asupersync::http::h1::listener::{Http1Listener, Http1ListenerConfig};
use asupersync::http::h1::server::{HostPolicy, Http1Config};
use asupersync::http::h1::types::{Request, Response};
use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::net::TcpStream;
use asupersync::runtime::{JoinError, RootDrainOutcome, RuntimeBuilder, yield_now};
use asupersync::tls::{
    Certificate, CertificateChain, PrivateKey, TlsAcceptor, TlsAcceptorBuilder, TlsConnector,
    TlsConnectorBuilder,
};
use asupersync::types::CancelReason;
use std::future::{Future, poll_fn};
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::pin::pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::task::Poll;
use std::time::Duration;

const CERT: &[u8] = include_bytes!("fixtures/tls/server.crt");
const KEY: &[u8] = include_bytes!("fixtures/tls/server.key");

fn native<F, Fut>(scenario: F)
where
    F: Fn(Cx) -> Fut + Copy + Send + 'static,
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
                        let mut task = root.spawn(scenario).unwrap();
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
    // Bounds a broken scenario, without supplying any readiness witness.
    let result = receive
        .recv_timeout(Duration::from_secs(45))
        .expect("owned HTTPS journey must finish and drain");
    worker.join().unwrap();
    if let Err(payload) = result {
        resume_unwind(payload);
    }
}

fn acceptor(protocol: &[u8]) -> TlsAcceptor {
    TlsAcceptorBuilder::new(
        CertificateChain::from_pem(CERT).unwrap(),
        PrivateKey::from_pem(KEY).unwrap(),
    )
    .alpn_protocols(vec![protocol.to_vec()])
    .build()
    .unwrap()
}

fn connector(protocol: &[u8]) -> TlsConnector {
    let root = Certificate::from_pem(CERT).unwrap().remove(0);
    TlsConnectorBuilder::new()
        .add_root_certificate(&root)
        .alpn_protocols_required(vec![protocol.to_vec()])
        .build()
        .unwrap()
}

fn config() -> Http1ListenerConfig {
    Http1ListenerConfig::default()
        .http_config(
            Http1Config::default()
                .host_policy(HostPolicy::allow_list(vec!["localhost".to_owned()]))
                .idle_timeout(None)
                .request_drain_grace(Duration::from_millis(100)),
        )
        .drain_timeout(Duration::from_secs(5))
        .hard_drain_timeout(Duration::from_secs(10))
}

struct Dropped(Arc<AtomicUsize>);

impl Drop for Dropped {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

async fn https_waits_for_request_subtree(cx: Cx) {
    let drops = Arc::new(AtomicUsize::new(0));
    let identities = Arc::new(Mutex::new(Vec::new()));
    let (body_ready, mut body_started) = oneshot::channel();
    let (child_ready, mut child_parked) = oneshot::channel();
    let (finish, finished) = oneshot::channel();
    let (cleanup_ready, mut cleanup_parked) = oneshot::channel();
    let (release, released) = oneshot::channel();
    let signals = Arc::new(Mutex::new(Some((
        body_ready, child_ready, finished, cleanup_ready, released,
    ))));
    let cleanup_owner = cx.clone();
    let handler_drops = Arc::clone(&drops);
    let handler_ids = Arc::clone(&identities);
    let listener = Http1Listener::bind_with_config(
        "127.0.0.1:0",
        move |request: Request| {
            let factory_cx = Cx::current().unwrap();
            assert!(request.peer_addr.is_some());
            let first = signals.lock().unwrap().take();
            let drops = Arc::clone(&handler_drops);
            let identities = Arc::clone(&handler_ids);
            let cleanup_owner = cleanup_owner.clone();
            async move {
                let body_cx = Cx::current().unwrap();
                assert_eq!(factory_cx.task_id(), body_cx.task_id());
                assert_eq!(factory_cx.region_id(), body_cx.region_id());
                identities.lock().unwrap().push(body_cx.clone());
                if let Some((body_ready, child_ready, mut finish, cleanup_ready, mut release)) = first {
                    body_cx.spawn(move |child_cx| async move {
                        let _dropped = Dropped(drops);
                        let mut ready = Some(child_ready);
                        let mut cancelled = pin!(child_cx.cancelled());
                        poll_fn(|task| match cancelled.as_mut().poll(task) {
                            Poll::Ready(()) => Poll::Ready(()),
                            Poll::Pending => {
                                if let Some(ready) = ready.take() {
                                    ready.send_blocking(child_cx.clone()).unwrap();
                                }
                                Poll::Pending
                            }
                        }).await;
                        assert!(child_cx.checkpoint().is_err());
                        let mut ready = Some(cleanup_ready);
                        let mut cleanup = pin!(release.recv(&cleanup_owner));
                        poll_fn(|task| match cleanup.as_mut().poll(task) {
                            Poll::Ready(result) => Poll::Ready(result.unwrap()),
                            Poll::Pending => {
                                if let Some(ready) = ready.take() {
                                    ready.send_blocking(()).unwrap();
                                }
                                Poll::Pending
                            }
                        }).await;
                    }).unwrap();
                    body_ready.send_blocking(body_cx.clone()).unwrap();
                    finish.recv(&body_cx).await.unwrap();
                    Response::new(200, "OK", b"first over TLS".to_vec())
                } else {
                    assert_eq!(drops.load(Ordering::SeqCst), 1);
                    Response::new(200, "OK", b"second over TLS".to_vec())
                }
            }
        },
        config(),
    ).await.unwrap();
    let address = listener.local_addr().unwrap();
    let manager = listener.connection_manager().clone();
    let in_flight = listener.in_flight_requests();
    let mut serving = cx.spawn(move |listener_cx| async move {
        listener.run_tls_owned_in(&listener_cx, acceptor(b"http/1.1")).await
    }).unwrap();
    let tls = connector(b"http/1.1")
        .connect("localhost", TcpStream::connect(address).await.unwrap())
        .await.unwrap();
    let mut client = cx.spawn(move |_| async move {
        Http1Client::request_with_io(
            tls,
            Request::get("/first").header("Host", "localhost").build(),
        ).await
    }).unwrap();
    let body = body_started.recv(&cx).await.unwrap();
    let child = child_parked.recv(&cx).await.unwrap();
    assert_ne!(body.task_id(), serving.task_id());
    assert_ne!(body.region_id(), cx.region_id());
    assert_eq!(child.region_id(), body.region_id());
    assert_ne!(child.task_id(), body.task_id());
    let monitor = cx.monitor(body.task_id()).await.unwrap();
    finish.send_blocking(()).unwrap();
    cleanup_parked.recv(&cx).await.unwrap();
    monitor.down(&cx).await.unwrap();
    assert_eq!(in_flight.load(Ordering::SeqCst), 1);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    poll_fn(|task| {
        assert!(client.poll_join(task).is_pending(), "no response before request cleanup");
        Poll::Ready(())
    }).await;
    release.send_blocking(()).unwrap();
    let (first, tls, body_withheld) = client.join(&cx).await.unwrap().unwrap();
    assert_eq!(first.status, 200);
    assert_eq!(first.body, b"first over TLS");
    assert!(!body_withheld);
    let second = Http1Client::request(
        tls,
        Request::get("/second")
            .header("Host", "localhost")
            .header("Connection", "close")
            .build(),
    ).await.unwrap();
    assert_eq!(second.status, 200);
    assert_eq!(second.body, b"second over TLS");
    assert!(manager.begin_drain(Duration::from_secs(5)));
    let stats = serving.join(&cx).await.unwrap().unwrap();
    assert!(stats.drain_report.unwrap().reached_quiescence);
    assert!(manager.is_empty());
    assert_eq!(in_flight.load(Ordering::SeqCst), 0);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    let identities = identities.lock().unwrap();
    assert_eq!(identities.len(), 2);
    assert_ne!(identities[0].task_id(), identities[1].task_id());
    assert_ne!(identities[0].region_id(), identities[1].region_id());
}

#[test]
fn owned_https_joins_request_subtree_before_response_and_tls_reuse() {
    native(https_waits_for_request_subtree);
}

async fn non_http1_alpn_is_refused(cx: Cx) {
    let calls = Arc::new(AtomicUsize::new(0));
    let handler_calls = Arc::clone(&calls);
    let listener = Http1Listener::bind_with_config(
        "127.0.0.1:0",
        move |_: Request| {
            handler_calls.fetch_add(1, Ordering::SeqCst);
            async { Response::new(200, "OK", Vec::new()) }
        },
        config(),
    ).await.unwrap();
    let address = listener.local_addr().unwrap();
    let manager = listener.connection_manager().clone();
    let in_flight = listener.in_flight_requests();
    let mut serving = cx.spawn(move |listener_cx| async move {
        listener.run_tls_owned_in(&listener_cx, acceptor(b"h2")).await
    }).unwrap();
    let mut tls = connector(b"h2")
        .connect("localhost", TcpStream::connect(address).await.unwrap())
        .await.unwrap();
    assert_eq!(tls.alpn_protocol(), Some(b"h2".as_slice()));
    // A negotiated h2 peer cannot smuggle HTTP/1 bytes into the handler.
    let _ = tls.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").await;
    let mut byte = [0; 1];
    match tls.read(&mut byte).await {
        Ok(0) | Err(_) => {}
        result => panic!("non-HTTP/1 ALPN must close without an HTTP response: {result:?}"),
    }
    assert!(manager.begin_drain(Duration::from_secs(5)));
    serving.join(&cx).await.unwrap().unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(in_flight.load(Ordering::SeqCst), 0);
    assert!(manager.is_empty());
}

#[test]
fn owned_https_refuses_non_http1_alpn_before_request_admission() {
    native(non_http1_alpn_is_refused);
}

async fn silent_handshake_retires(cx: Cx) {
    for force_close in [false, true] {
        let owner = cx.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let handler_calls = Arc::clone(&calls);
        let listener = Http1Listener::bind_with_config(
            "127.0.0.1:0",
            move |_: Request| {
                handler_calls.fetch_add(1, Ordering::SeqCst);
                async { Response::new(200, "OK", Vec::new()) }
            },
            config().drain_timeout(Duration::from_millis(20)),
        ).await.unwrap();
        let address = listener.local_addr().unwrap();
        let manager = listener.connection_manager().clone();
        let in_flight = listener.in_flight_requests();
        let mut serving = owner.cx().spawn(move |listener_cx| async move {
            listener.run_tls_owned_in(&listener_cx, acceptor(b"http/1.1")).await
        }).unwrap();
        let mut silent = TcpStream::connect(address).await.unwrap();
        while manager.active_count() != 1 {
            yield_now().await;
        }
        // No ClientHello is sent and neither handshake nor idle timeout is
        // enabled. Only cancellation or force-close can release this slot.
        if force_close {
            assert!(manager.begin_drain(Duration::from_secs(5)));
            assert!(manager.begin_force_close());
        } else {
            owner.cancel(CancelReason::user("cancel owned HTTPS service region")).unwrap();
        }
        let result = serving.join(&cx).await;
        assert!(!matches!(result, Err(JoinError::Panicked(_))), "{result:?}");
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(in_flight.load(Ordering::SeqCst), 0);
        assert!(manager.is_empty());
        let mut byte = [0; 1];
        assert_eq!(silent.read(&mut byte).await.unwrap(), 0);
        owner.close().await.unwrap();
    }
}

#[test]
fn owner_cancel_and_force_close_release_registered_tls_handshakes() {
    native(silent_handshake_retires);
}
