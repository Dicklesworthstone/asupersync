//! Reusable native TCP/TLS service journeys and witnessed shutdown boundaries.
//! Existing public test-only identities are reused, never copied into source.

#![cfg(all(feature = "tls", feature = "test-internals", not(target_arch = "wasm32")))]

use asupersync::Cx;
use asupersync::io::AsyncWrite;
use asupersync::net::atp::sdk::native_auth::live::{
    LiveStreamConfig, LiveStreamError, LiveStreamReceiver, LiveStreamSender,
};
use asupersync::net::atp::sdk::native_auth::live::service::{
    LiveStreamCompletion, LiveStreamPeer,
};
use asupersync::net::atp::sdk::{
    AtpSdk, NativeClientAuthorization, NativeClientCertificateId, NativeTlsIdentity, SessionConfig,
};
use asupersync::runtime::{JoinError, RuntimeBuilder, yield_now};
use asupersync::types::CancelReason;
use futures_lite::future::{or, zip};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject};
use sha2::{Digest, Sha256};
use std::future::{Future, Ready, poll_fn, ready};
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, mpsc};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

fn fixtures() -> serde_json::Value {
    serde_json::from_str(include_str!("fixtures/atp_native_auth_identities.json")).unwrap()
}
fn certificate(name: &str) -> CertificateDer<'static> {
    let fixtures = fixtures();
    let text = if name == "ca" { fixtures["ca"].as_str() }
        else { fixtures["identities"][name]["certificate"].as_str() }.unwrap();
    CertificateDer::pem_reader_iter(&mut io::BufReader::new(text.as_bytes())).next().unwrap().unwrap()
}
fn identity(name: &str) -> NativeTlsIdentity {
    let fixtures = fixtures();
    let text = fixtures["identities"][name]["key"].as_str().unwrap();
    let key = PrivateKeyDer::pem_reader_iter(&mut io::BufReader::new(text.as_bytes())).next().unwrap().unwrap();
    NativeTlsIdentity::new(vec![certificate(name)], key).unwrap()
}
fn roots() -> RootCertStore {
    let mut roots = RootCertStore::empty(); roots.add(certificate("ca")).unwrap(); roots
}
fn sdk(capacity: u32) -> AtpSdk {
    AtpSdk::new_in_process(SessionConfig { max_concurrent_transfers: capacity, ..SessionConfig::default() })
}
fn config() -> LiveStreamConfig {
    let mut config = LiveStreamConfig::default();
    config.epoch_bytes = 8; config.max_bytes = 4096;
    config.operation_timeout = Duration::from_secs(10); config
}
fn sender(name: &str) -> LiveStreamSender {
    sdk(4).live_stream_sender(config(), ServerName::try_from("localhost").unwrap(), roots(), identity(name)).unwrap()
}
fn receiver(capacity: u32) -> (LiveStreamReceiver, NativeClientAuthorization) {
    let allowed = NativeClientCertificateId::from_certificate(&certificate("allowed"));
    let authorization = NativeClientAuthorization::new(roots(), [allowed]).unwrap();
    let receiver = sdk(capacity).live_stream_receiver(config(), identity("server"), authorization.clone()).unwrap();
    (receiver, authorization)
}
fn run<T: Send + 'static>(workers: usize, future: impl Future<Output = T> + Send + 'static) -> T {
    let runtime = if workers == 1 { RuntimeBuilder::current_thread() }
        else { RuntimeBuilder::multi_thread().worker_threads(workers).with_sharded_state(true) }
        .build().unwrap();
    let future: Pin<Box<dyn Future<Output = T> + Send>> = Box::pin(future);
    let result = runtime.block_on(runtime.handle().spawn(future));
    let started = Instant::now();
    while !runtime.is_quiescent() {
        assert!(started.elapsed() < Duration::from_secs(5), "service children did not drain");
        runtime.block_on(yield_now());
    }
    assert!(runtime.task_inspector(Default::default()).list_tasks().is_empty());
    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
    assert!(runtime.shutdown_timeout(Duration::from_secs(5)));
    result
}
async fn witness(cx: &Cx, predicate: impl Fn() -> bool) {
    asupersync::time::timeout(cx.now(), Duration::from_secs(5), async {
        while !predicate() { yield_now().await; }
    }).await.expect("required accepted/parked state was never reached");
}

#[derive(Default)]
struct SinkState {
    bytes: Mutex<Vec<u8>>,
    parked: AtomicBool,
    dropped: AtomicBool,
    waiter: Mutex<Option<Waker>>,
}
#[derive(Clone)]
struct Store {
    entries: Arc<Mutex<Vec<(LiveStreamPeer, Arc<SinkState>)>>>,
    released: Arc<AtomicBool>,
}
impl Store {
    fn new(released: bool) -> Self {
        Self { entries: Arc::new(Mutex::new(Vec::new())), released: Arc::new(AtomicBool::new(released)) }
    }
    fn create(&self, cx: Cx, peer: LiveStreamPeer) -> Sink {
        assert_eq!(Cx::current().unwrap().task_id(), cx.task_id(), "factory must run in its actual child context");
        let state = Arc::new(SinkState::default());
        self.entries.lock().unwrap().push((peer, Arc::clone(&state)));
        Sink { state, released: Arc::clone(&self.released) }
    }
    fn factory(&self) -> impl Fn(Cx, LiveStreamPeer) -> Ready<io::Result<Sink>> + Clone + Send + Sync + 'static {
        let store = self.clone();
        move |cx, peer| ready(Ok(store.create(cx, peer)))
    }
    fn entries(&self) -> Vec<(LiveStreamPeer, Arc<SinkState>)> { self.entries.lock().unwrap().clone() }
    fn parked(&self) -> usize {
        self.entries().iter().filter(|(_, state)| state.parked.load(Ordering::SeqCst)).count()
    }
    fn release(&self) {
        self.released.store(true, Ordering::SeqCst);
        for (_, state) in self.entries() {
            let wake = state.waiter.lock().unwrap().take();
            if let Some(wake) = wake { wake.wake(); }
        }
    }
}
struct Sink { state: Arc<SinkState>, released: Arc<AtomicBool> }
impl AsyncWrite for Sink {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        let count = bytes.len().min(3);
        self.state.bytes.lock().unwrap().extend_from_slice(&bytes[..count]);
        Poll::Ready(Ok(count))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.released.load(Ordering::SeqCst) {
            let candidate = cx.waker().clone();
            let retired = self.state.waiter.lock().unwrap().replace(candidate);
            drop(retired);
            self.state.parked.store(true, Ordering::SeqCst);
            if !self.released.load(Ordering::SeqCst) { return Poll::Pending; }
        }
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        panic!("service must not invent sink shutdown semantics");
    }
}
impl Drop for Sink {
    fn drop(&mut self) { self.state.dropped.store(true, Ordering::SeqCst); }
}

fn assert_cancelled(completion: LiveStreamCompletion, reason: &CancelReason) {
    let report = completion.result.expect("witnessed parked worker must preserve its acknowledged domain result");
    assert!(report.peer.is_some());
    assert!(matches!(report.transfer.outcome, Err(LiveStreamError::Cancelled(Some(actual))) if &actual == reason));
    let prefix = report.transfer.prefix.unwrap();
    assert_eq!((prefix.epochs, prefix.bytes), (0, 0));
    assert_eq!(report.transfer.sink_written_bytes, 5, "partial publication must survive cancellation");
}

#[test]
fn one_bound_service_handles_repeated_clients_without_rebinding() {
    for workers in [1, 2] {
        run(workers, async {
            let cx = Cx::current().unwrap(); let scope = cx.scope();
            let (receive, _) = receiver(1);
            let mut service = receive.bind_service(&cx, "127.0.0.1:0".parse().unwrap(), 1).await.unwrap();
            let address = service.local_addr();
            let store = Store::new(true); let send = sender("allowed");
            for (id, payload) in [b"first".as_slice(), b"", b"third payload crosses epochs"].into_iter().enumerate() {
                let (completion, sent) = zip(service.next(&cx, &scope, store.factory()), send.send_reader(&cx, address, payload)).await;
                let completion = completion.unwrap().unwrap();
                assert_eq!(completion.connection, id as u64);
                let report = completion.result.unwrap();
                assert_eq!(report.peer.unwrap().certificate, NativeClientCertificateId::from_certificate(&certificate("allowed")));
                let receipt = report.transfer.outcome.unwrap();
                assert_eq!(receipt, sent.outcome.unwrap());
                let hash: [u8; 32] = Sha256::digest(payload).into();
                assert_eq!(receipt.source_sha256, hash);
                let entries = store.entries();
                assert_eq!(*entries[id].1.bytes.lock().unwrap(), payload);
                assert!(entries[id].1.dropped.load(Ordering::SeqCst));
                assert_eq!(service.local_addr(), address);
                assert_eq!(receive.active_streams(), 1, "service retains its capacity partition while open");
            }
            service.stop_accepting();
            assert!(service.drain_next().await.is_none());
            assert!(service.is_drained());
            assert_eq!(receive.active_streams(), 0);
        });
    }
}

#[test]
fn concurrent_connections_and_uncollected_workers_obey_the_reserved_bound() {
    for workers in [1, 2] {
        run(workers, async {
            let cx = Cx::current().unwrap(); let scope = cx.scope();
            let (receive, _) = receiver(2);
            let mut service = receive.bind_service(&cx, "127.0.0.1:0".parse().unwrap(), 2).await.unwrap();
            let store = Store::new(false); let send = sender("allowed");
            let mut senders = Vec::new();
            for payload in [b"one".as_slice(), b"two", b"three"] {
                senders.push(send.spawn_send_reader(&cx, &scope, service.local_addr(), payload).unwrap());
            }
            or(async {
                let premature = service.next(&cx, &scope, store.factory()).await;
                panic!("blocked sinks cannot complete: {premature:?}");
            }, witness(&cx, || store.parked() == 2)).await;
            assert_eq!(service.in_flight(), 2);
            assert_eq!(store.entries().len(), 2);
            for _ in 0..32 { yield_now().await; }
            assert_eq!(store.entries().len(), 2, "third connection cannot allocate a sink behind full service capacity");
            store.release();
            let mut ids = Vec::new();
            for _ in 0..3 {
                let completed = service.next(&cx, &scope, store.factory()).await.unwrap().unwrap();
                assert!(completed.result.unwrap().transfer.outcome.is_ok());
                ids.push(completed.connection);
                assert!(service.in_flight() <= 2);
            }
            ids.sort_unstable(); assert_eq!(ids, [0, 1, 2]);
            for sender in &mut senders { assert!(sender.join(&cx).await.unwrap().outcome.is_ok()); }
            let mut actual: Vec<_> = store.entries().iter().map(|(_, state)| state.bytes.lock().unwrap().clone()).collect();
            actual.sort();
            let mut expected = vec![b"one".to_vec(), b"two".to_vec(), b"three".to_vec()]; expected.sort();
            assert_eq!(actual, expected);
            service.stop_accepting(); assert!(service.drain_next().await.is_none());
            assert_eq!(receive.active_streams(), 0);
        });
    }
}

#[test]
fn unauthorized_clients_never_construct_sinks_and_rotation_keeps_the_port_open() {
    run(2, async {
        let cx = Cx::current().unwrap(); let scope = cx.scope();
        let (receive, policy) = receiver(1);
        let mut service = receive.bind_service(&cx, "127.0.0.1:0".parse().unwrap(), 1).await.unwrap();
        let store = Store::new(true); let address = service.local_addr();
        let unlisted = sender("unlisted");
        let (failed, sent) = zip(service.next(&cx, &scope, store.factory()), unlisted.send_reader(&cx, address, b"denied".as_slice())).await;
        let failed = failed.unwrap().unwrap().result.unwrap();
        assert!(failed.peer.is_none());
        assert!(matches!(failed.transfer.outcome, Err(LiveStreamError::Tls(_))));
        assert!(sent.outcome.is_err()); assert!(store.entries().is_empty());
        policy.replace_allowed([NativeClientCertificateId::from_certificate(&certificate("unlisted"))]).unwrap();
        let (completed, sent) = zip(service.next(&cx, &scope, store.factory()), unlisted.send_reader(&cx, address, b"allowed after rotation".as_slice())).await;
        let completed = completed.unwrap().unwrap(); assert_eq!(completed.connection, 1);
        assert_eq!(completed.result.unwrap().transfer.outcome.unwrap(), sent.outcome.unwrap());
        assert_eq!(store.entries().len(), 1);
        assert_eq!(service.local_addr(), address);
        service.stop_accepting(); assert!(service.drain_next().await.is_none());
        assert_eq!(receive.active_streams(), 0);
    });
}

#[test]
fn factory_errors_and_panics_are_per_connection_not_service_failures() {
    run(2, async {
        let cx = Cx::current().unwrap(); let scope = cx.scope();
        let (receive, _) = receiver(1);
        let mut service = receive.bind_service(&cx, "127.0.0.1:0".parse().unwrap(), 1).await.unwrap();
        let store = Store::new(true); let calls = Arc::new(AtomicUsize::new(0));
        let factory = {
            let store = store.clone(); let calls = Arc::clone(&calls);
            move |cx, peer| {
                match calls.fetch_add(1, Ordering::SeqCst) {
                    0 => ready(Err(io::Error::from(io::ErrorKind::PermissionDenied))),
                    1 => panic!("deliberate sink factory panic"),
                    _ => ready(Ok(store.create(cx, peer))),
                }
            }
        };
        let send = sender("allowed");
        let address = service.local_addr();
        for attempt in 0..3 {
            let (completion, sent) = zip(service.next(&cx, &scope, factory.clone()), send.send_reader(&cx, address, b"payload".as_slice())).await;
            let completion = completion.unwrap().unwrap();
            assert_eq!(completion.connection, attempt);
            match attempt {
                0 => {
                    let report = completion.result.unwrap(); assert!(report.peer.is_some());
                    assert!(report.transfer.prefix.is_none());
                    assert!(matches!(report.transfer.outcome, Err(LiveStreamError::Io(error)) if error.kind() == io::ErrorKind::PermissionDenied));
                    assert!(sent.outcome.is_err());
                }
                1 => { assert!(matches!(completion.result, Err(JoinError::Panicked(_)))); assert!(sent.outcome.is_err()); }
                _ => { assert_eq!(completion.result.unwrap().transfer.outcome.unwrap(), sent.outcome.unwrap()); }
            }
        }
        assert_eq!(store.entries().len(), 1);
        assert_eq!(*store.entries()[0].1.bytes.lock().unwrap(), b"payload");
        service.stop_accepting(); assert!(service.drain_next().await.is_none());
        assert_eq!(receive.active_streams(), 0);
    });
}

#[test]
fn graceful_stop_and_resumed_drain_keep_the_full_peer_receipt() {
    run(2, async {
        let cx = Cx::current().unwrap(); let scope = cx.scope();
        let (receive, _) = receiver(1);
        let mut service = receive.bind_service(&cx, "127.0.0.1:0".parse().unwrap(), 1).await.unwrap();
        let store = Store::new(false); let send = sender("allowed");
        let mut sending = send.spawn_send_reader(&cx, &scope, service.local_addr(), b"first".as_slice()).unwrap();
        or(async {
            let premature = service.next(&cx, &scope, store.factory()).await;
            panic!("flush must remain pending: {premature:?}");
        }, witness(&cx, || store.parked() == 1)).await;
        service.stop_accepting();
        {
            let mut wait = Box::pin(service.drain_next());
            assert!(wait.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
        }
        assert_eq!(service.in_flight(), 1);
        assert!(!service.is_drained()); assert_eq!(receive.active_streams(), 1);
        store.release();
        let completion = service.drain_next().await.unwrap();
        let receipt = completion.result.unwrap().transfer.outcome.unwrap();
        assert_eq!(receipt, sending.join(&cx).await.unwrap().outcome.unwrap());
        assert!(service.drain_next().await.is_none());
        assert!(service.is_drained()); assert_eq!(receive.active_streams(), 0);
        assert!(store.entries()[0].1.dropped.load(Ordering::SeqCst));
    });
}

#[test]
fn cancelling_a_witnessed_parked_sink_preserves_partial_progress_and_reason() {
    for workers in [1, 2] {
        run(workers, async {
            let cx = Cx::current().unwrap(); let scope = cx.scope();
            let (receive, _) = receiver(1);
            let mut service = receive.bind_service(&cx, "127.0.0.1:0".parse().unwrap(), 1).await.unwrap();
            let store = Store::new(false); let send = sender("allowed");
            let mut sending = send.spawn_send_reader(&cx, &scope, service.local_addr(), b"first".as_slice()).unwrap();
            or(async {
                let premature = service.next(&cx, &scope, store.factory()).await;
                panic!("flush must remain pending: {premature:?}");
            }, witness(&cx, || store.parked() == 1)).await;
            let reason = CancelReason::user("operator stopped live service");
            service.control().cancel(reason.clone());
            assert_cancelled(service.drain_next().await.unwrap(), &reason);
            assert!(service.drain_next().await.is_none());
            assert_eq!(receive.active_streams(), 0);
            assert!(store.entries()[0].1.dropped.load(Ordering::SeqCst));
            assert!(sending.join(&cx).await.unwrap().outcome.is_err());
        });
    }
}

#[test]
fn idle_service_wakes_on_a_cross_thread_stop_and_releases_the_actual_listener() {
    run(1, async {
        let cx = Cx::current().unwrap(); let scope = cx.scope();
        let (receive, _) = receiver(1);
        let mut service = receive.bind_service(&cx, "127.0.0.1:0".parse().unwrap(), 1).await.unwrap();
        let address = service.local_addr(); let control = service.control();
        let store = Store::new(true);
        let (parked_tx, parked_rx) = mpsc::sync_channel(1);
        let stopper = std::thread::spawn(move || {
            parked_rx.recv_timeout(Duration::from_secs(5)).unwrap(); control.stop();
        });
        let mut signalled = false;
        {
            let mut next = Box::pin(service.next(&cx, &scope, store.factory()));
            let result = asupersync::time::timeout(cx.now(), Duration::from_secs(5), poll_fn(|ctx| {
                let result = next.as_mut().poll(ctx);
                if result.is_pending() && !signalled {
                    signalled = true; parked_tx.send(()).unwrap();
                }
                result
            })).await.unwrap().unwrap();
            assert!(result.is_none());
        }
        stopper.join().unwrap(); assert!(signalled);
        assert!(service.is_drained()); assert_eq!(receive.active_streams(), 0);
        assert!(store.entries().is_empty());
        // No connection ever existed, so TIME_WAIT cannot confuse ownership.
        let rebound = std::net::TcpListener::bind(address).expect("the real listening socket must be closed");
        drop(rebound);
    });
}

#[test]
fn service_capacity_and_bind_failures_roll_back_before_any_accept() {
    run(1, async {
        let cx = Cx::current().unwrap(); let (receive, _) = receiver(3);
        let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = occupied.local_addr().unwrap();
        let one_shot = receive.bind(&cx, "127.0.0.1:0".parse().unwrap()).await.unwrap();
        assert!(matches!(receive.bind_service(&cx, address, 3).await, Err(LiveStreamError::Capacity)));
        assert_eq!(receive.active_streams(), 1, "partial reservation must roll back");
        drop(one_shot); assert_eq!(receive.active_streams(), 0);
        assert!(matches!(receive.bind_service(&cx, address, 3).await, Err(LiveStreamError::Io(error)) if error.kind() == io::ErrorKind::AddrInUse));
        assert_eq!(receive.active_streams(), 0);
        for count in [0, 4, usize::MAX] {
            assert!(matches!(receive.bind_service(&cx, address, count).await, Err(LiveStreamError::Configuration(_))));
            assert_eq!(receive.active_streams(), 0);
        }
        drop(occupied);
    });
}

#[test]
fn cancelled_manager_joins_its_children_before_publishing_its_domain_result() {
    run(2, async {
        let cx = Cx::current().unwrap(); let scope = cx.scope();
        let (receive, _) = receiver(1);
        let mut service = receive.bind_service(&cx, "127.0.0.1:0".parse().unwrap(), 1).await.unwrap();
        let address = service.local_addr(); let store = Store::new(false);
        let manager_store = store.clone();
        let mut manager = cx.spawn_in(&scope, move |child| {
            let future: Pin<Box<dyn Future<Output = (LiveStreamError, Vec<LiveStreamCompletion>)> + Send>> = Box::pin(async move {
                let scope = child.scope();
                let error = service.next(&child, &scope, manager_store.factory()).await.unwrap_err();
                let mut completions = Vec::new();
                while let Some(completion) = service.drain_next().await { completions.push(completion); }
                assert!(service.is_drained());
                (error, completions)
            });
            future
        }).unwrap();
        let send = sender("allowed");
        let mut sending = send.spawn_send_reader(&cx, &scope, address, b"first".as_slice()).unwrap();
        witness(&cx, || store.parked() == 1).await;
        let reason = CancelReason::user("cancel owning manager");
        manager.abort_with_reason(reason.clone());
        let (error, mut completions) = manager.join(&cx).await.expect("acknowledged manager cancellation must retain its drained report");
        assert!(matches!(error, LiveStreamError::Cancelled(Some(actual)) if actual == reason));
        assert_eq!(completions.len(), 1);
        assert_cancelled(completions.pop().unwrap(), &reason);
        assert!(store.entries()[0].1.dropped.load(Ordering::SeqCst));
        assert_eq!(receive.active_streams(), 0);
        assert!(sending.join(&cx).await.unwrap().outcome.is_err());
    });
}
