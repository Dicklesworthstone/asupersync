//! Shared-port reconnect journeys over native mTLS and canonical child tasks.
//! TLS identities are public test fixtures; no user credentials are used.
#![cfg(all(
    feature = "tls",
    feature = "test-internals",
    not(target_arch = "wasm32")
))]

use asupersync::Cx;
use asupersync::bytes::BytesMut;
use asupersync::codec::Decoder;
use asupersync::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use asupersync::net::TcpStream;
use asupersync::net::atp::protocol::codec::AtpFrameCodec;
use asupersync::net::atp::protocol::frames::{Frame, FrameType, ProtocolVersion};
use asupersync::net::atp::sdk::native_auth::live::commit::resume::service::{
    ResumeRetireError, ResumeServiceConfig, ResumeServiceOutcome, ResumeServiceRejection,
    ResumeSessionKey, ResumeSessionStatus,
};
use asupersync::net::atp::sdk::native_auth::live::commit::resume::{
    RESUMABLE_LIVE_ALPN, ResumeError, ResumeReport,
};
use asupersync::net::atp::sdk::native_auth::live::commit::{
    LiveStreamCommitError, LiveStreamCommitSink,
};
use asupersync::net::atp::sdk::native_auth::live::{
    LiveStreamConfig, LiveStreamError, LiveStreamReceipt, LiveStreamReceiver, LiveStreamSender,
};
use asupersync::net::atp::sdk::{
    AtpSdk, NativeClientAuthorization, NativeClientCertificateId, NativeTlsIdentity, SessionConfig,
};
use asupersync::runtime::{JoinError, RuntimeBuilder, yield_now};
use asupersync::tls::{TlsConnector, TlsStream};
use asupersync::types::CancelReason;
use futures_lite::future::{or, zip};
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject},
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::future::{Future, Ready, ready};
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!("fixtures/atp_native_auth_identities.json")).unwrap()
}
fn certificate(name: &str) -> CertificateDer<'static> {
    let value = fixture();
    let pem = if name == "ca" {
        value["ca"].as_str()
    } else {
        value["identities"][name]["certificate"].as_str()
    }
    .unwrap();
    CertificateDer::pem_reader_iter(&mut io::BufReader::new(pem.as_bytes()))
        .next()
        .unwrap()
        .unwrap()
}
fn key(name: &str) -> PrivateKeyDer<'static> {
    let value = fixture();
    let pem = value["identities"][name]["key"].as_str().unwrap();
    PrivateKeyDer::pem_reader_iter(&mut io::BufReader::new(pem.as_bytes()))
        .next()
        .unwrap()
        .unwrap()
}
fn identity(name: &str) -> NativeTlsIdentity {
    NativeTlsIdentity::new(vec![certificate(name)], key(name)).unwrap()
}
fn roots() -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.add(certificate("ca")).unwrap();
    roots
}
fn id(name: &str) -> NativeClientCertificateId {
    NativeClientCertificateId::from_certificate(&certificate(name))
}
fn session(name: &str, nonce: u8) -> ResumeSessionKey {
    ResumeSessionKey {
        client: id(name),
        nonce: [nonce; 32],
    }
}
fn profile() -> LiveStreamConfig {
    let mut config = LiveStreamConfig::default();
    config.epoch_bytes = 8;
    config.max_bytes = 1024;
    config.operation_timeout = Duration::from_secs(3);
    config
}
fn sdk() -> AtpSdk {
    AtpSdk::new_in_process(SessionConfig {
        max_concurrent_transfers: 4,
        ..SessionConfig::default()
    })
}
fn sender(name: &str) -> LiveStreamSender {
    sdk()
        .live_stream_sender(
            profile(),
            ServerName::try_from("localhost").unwrap(),
            roots(),
            identity(name),
        )
        .unwrap()
}
fn receiver(second: bool) -> LiveStreamReceiver {
    let mut allowed = vec![id("allowed")];
    if second {
        allowed.push(id("unlisted"));
    }
    let policy = NativeClientAuthorization::new(roots(), allowed).unwrap();
    sdk()
        .live_stream_receiver(profile(), identity("server"), policy)
        .unwrap()
}
fn limits() -> ResumeServiceConfig {
    ResumeServiceConfig {
        max_connections: 2,
        max_sessions: 4,
        max_sessions_per_client: 2,
        max_session_keys: 8,
        max_attempts_per_session: 4,
    }
}
fn run<T: Send + 'static>(workers: usize, future: impl Future<Output = T> + Send + 'static) -> T {
    let runtime = if workers == 1 {
        RuntimeBuilder::current_thread()
    } else {
        RuntimeBuilder::multi_thread()
            .worker_threads(workers)
            .with_sharded_state(true)
    }
    .blocking_threads(1, 2)
    .build()
    .unwrap();
    let future: Pin<Box<dyn Future<Output = T> + Send>> = Box::pin(async move {
        let cx = Cx::current().unwrap();
        asupersync::time::timeout(cx.now(), Duration::from_secs(30), future)
            .await
            .expect("shared resume journey must terminate")
    });
    let output = runtime.block_on(runtime.handle().spawn(future));
    let started = Instant::now();
    while !runtime.is_quiescent() {
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "service owner did not drain"
        );
        runtime.block_on(yield_now());
    }
    assert!(
        runtime
            .task_inspector(Default::default())
            .list_tasks()
            .is_empty()
    );
    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
    assert!(runtime.shutdown_timeout(Duration::from_secs(5)));
    output
}
async fn witness(cx: &Cx, condition: impl Fn() -> bool) {
    asupersync::time::timeout(cx.now(), Duration::from_secs(5), async {
        while !condition() {
            yield_now().await;
        }
    })
    .await
    .expect("the required causal state was not reached");
}
fn transfer(outcome: ResumeServiceOutcome) -> ResumeReport {
    match outcome {
        ResumeServiceOutcome::Transfer(report) => report,
        other => panic!("expected transfer report: {other:?}"),
    }
}

#[derive(Default)]
struct Probe {
    bytes: Mutex<Vec<u8>>,
    commits: AtomicUsize,
    dropped: AtomicBool,
    write_parked: AtomicBool,
    commit_parked: AtomicBool,
    cancelled_commit: AtomicBool,
    release_write: AtomicBool,
    release_commit: AtomicBool,
    write_waker: Mutex<Option<Waker>>,
    commit_waker: Mutex<Option<Waker>>,
}
impl Probe {
    fn release(&self) {
        self.release_write.store(true, Ordering::SeqCst);
        self.release_commit.store(true, Ordering::SeqCst);
        let write = self.write_waker.lock().unwrap().take();
        let commit = self.commit_waker.lock().unwrap().take();
        if let Some(waker) = write {
            waker.wake();
        }
        if let Some(waker) = commit {
            waker.wake();
        }
    }
}
fn register(slot: &Mutex<Option<Waker>>, ctx: &Context<'_>) {
    let candidate = ctx.waker().clone();
    let old = slot.lock().unwrap().replace(candidate);
    drop(old);
}
struct Sink {
    probe: Arc<Probe>,
    pause_write: bool,
    pause_commit: bool,
}
impl AsyncWrite for Sink {
    fn poll_write(
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut output = self.probe.bytes.lock().unwrap();
        if self.pause_write && output.len() >= 3 && !self.probe.release_write.load(Ordering::SeqCst)
        {
            drop(output);
            register(&self.probe.write_waker, ctx);
            self.probe.write_parked.store(true, Ordering::SeqCst);
            if !self.probe.release_write.load(Ordering::SeqCst) {
                return Poll::Pending;
            }
            output = self.probe.bytes.lock().unwrap();
        }
        let count = bytes.len().min(3);
        output.extend_from_slice(&bytes[..count]);
        Poll::Ready(Ok(count))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        panic!("shared resume must not implicitly shut down a sink")
    }
}
impl LiveStreamCommitSink for Sink {
    fn poll_commit(
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        receipt: &LiveStreamReceipt,
    ) -> Poll<io::Result<()>> {
        if Cx::current().and_then(|cx| cx.cancel_reason()).is_some() {
            self.probe.cancelled_commit.store(true, Ordering::SeqCst);
        }
        if self.pause_commit && !self.probe.release_commit.load(Ordering::SeqCst) {
            register(&self.probe.commit_waker, ctx);
            self.probe.commit_parked.store(true, Ordering::SeqCst);
            if !self.probe.release_commit.load(Ordering::SeqCst) {
                return Poll::Pending;
            }
        }
        let bytes = self.probe.bytes.lock().unwrap();
        assert_eq!(receipt.prefix.bytes, bytes.len() as u64);
        assert_eq!(
            receipt.source_sha256.as_slice(),
            Sha256::digest(&*bytes).as_slice()
        );
        assert_eq!(
            self.probe.commits.fetch_add(1, Ordering::SeqCst),
            0,
            "sink committed twice"
        );
        Poll::Ready(Ok(()))
    }
}
impl Drop for Sink {
    fn drop(&mut self) {
        self.probe.dropped.store(true, Ordering::SeqCst);
    }
}
#[derive(Clone, Default)]
struct Store {
    probes: Arc<Mutex<BTreeMap<ResumeSessionKey, Arc<Probe>>>>,
    calls: Arc<AtomicUsize>,
    pause_write: bool,
    pause_commit: bool,
    fail_factory: u8,
}
impl Store {
    fn factory(
        &self,
    ) -> impl Fn(Cx, ResumeSessionKey) -> Ready<io::Result<Sink>> + Clone + Send + Sync + 'static
    {
        let store = self.clone();
        move |_child, key| {
            store.calls.fetch_add(1, Ordering::SeqCst);
            assert!(store.fail_factory != 2, "deliberate factory panic");
            if store.fail_factory == 1 {
                return ready(Err(io::Error::from(io::ErrorKind::PermissionDenied)));
            }
            let probe = Arc::new(Probe::default());
            assert!(
                store
                    .probes
                    .lock()
                    .unwrap()
                    .insert(key, Arc::clone(&probe))
                    .is_none(),
                "factory recreated an existing session"
            );
            ready(Ok(Sink {
                probe,
                pause_write: store.pause_write,
                pause_commit: store.pause_commit,
            }))
        }
    }
    fn first(&self) -> Option<Arc<Probe>> {
        self.probes.lock().unwrap().values().next().cloned()
    }
    fn get(&self, key: &ResumeSessionKey) -> Arc<Probe> {
        Arc::clone(&self.probes.lock().unwrap()[key])
    }
}
// Release intentionally parked test sinks on assertion failure as well as success.
// Wake outside the store lock so a failed regression cannot strand runtime teardown.
struct ReleaseAll(Arc<Mutex<BTreeMap<ResumeSessionKey, Arc<Probe>>>>);
impl Drop for ReleaseAll {
    fn drop(&mut self) {
        let probes: Vec<_> = self.0.lock().unwrap().values().cloned().collect();
        for probe in probes {
            probe.release();
        }
    }
}
struct Source {
    bytes: &'static [u8],
    offset: usize,
    reads: Arc<AtomicUsize>,
}
impl AsyncRead for Source {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        let count = out.remaining().min(self.bytes.len() - self.offset);
        out.put_slice(&self.bytes[self.offset..self.offset + count]);
        self.offset += count;
        Poll::Ready(Ok(()))
    }
}

struct Wire {
    tls: TlsStream<TcpStream>,
    codec: AtpFrameCodec,
    buffer: BytesMut,
}
impl Wire {
    async fn connect(address: SocketAddr, client: &str) -> Self {
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots())
        .with_client_auth_cert(vec![certificate(client)], key(client))
        .unwrap();
        config.alpn_protocols = vec![RESUMABLE_LIVE_ALPN.to_vec()];
        config.resumption = rustls::client::Resumption::disabled();
        let tcp = TcpStream::connect(address).await.unwrap();
        let tls = TlsConnector::new(config)
            .connect("localhost", tcp)
            .await
            .unwrap();
        assert_eq!(tls.alpn_protocol(), Some(RESUMABLE_LIVE_ALPN));
        Self {
            tls,
            codec: AtpFrameCodec::with_max_frame_size(66000),
            buffer: BytesMut::new(),
        }
    }
    async fn send(&mut self, kind: FrameType, payload: Vec<u8>) {
        let encoded = Frame::new(ProtocolVersion::V0, kind, payload)
            .unwrap()
            .to_wire_bytes()
            .unwrap();
        self.tls.write_all(&encoded).await.unwrap();
        self.tls.flush().await.unwrap();
    }
    async fn read(&mut self, kind: FrameType) -> io::Result<Vec<u8>> {
        loop {
            if let Some(frame) = self.codec.decode(&mut self.buffer).unwrap() {
                assert_eq!(frame.frame_type(), kind);
                return Ok(frame.payload().to_vec());
            }
            let mut bytes = [0; 4096];
            let count = self.tls.read(&mut bytes).await?;
            if count == 0 {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
            }
            self.buffer.extend_from_slice(&bytes[..count]);
        }
    }
}
// Independent wire model: never calls private production reconciliation helpers.
struct Model {
    hello: Vec<u8>,
    prefix: Vec<u8>,
    data: Vec<u8>,
}
impl Model {
    fn new(nonce: u8) -> Self {
        let mut hello = b"ATPRSM01ATPLIVE1".to_vec();
        hello.extend_from_slice(&[nonce; 32]);
        hello.extend_from_slice(&8_u32.to_be_bytes());
        hello.extend_from_slice(&1024_u64.to_be_bytes());
        let mut hash = Sha256::new();
        hash.update(b"asupersync.atp.live.resume.hello.v1");
        hash.update(&hello);
        let mut prefix = vec![0; 16];
        prefix.extend_from_slice(&hash.finalize());
        Self {
            hello,
            prefix,
            data: Vec::new(),
        }
    }
    fn state(&self, completed: bool) -> Vec<u8> {
        let mut state = self.hello.clone();
        state.extend_from_slice(&self.prefix);
        state.extend_from_slice(&Sha256::digest(&self.data));
        state.push(u8::from(completed));
        state
    }
    fn epoch(&mut self, data: &[u8]) -> Vec<u8> {
        let mut payload = self.prefix.clone();
        payload.extend_from_slice(&Sha256::digest(data));
        payload.extend_from_slice(data);
        let mut hash = Sha256::new();
        hash.update(b"asupersync.atp.live.epoch.v1");
        hash.update(&self.prefix[16..]);
        hash.update(&payload);
        let epochs = u64::from_be_bytes(self.prefix[..8].try_into().unwrap()) + 1;
        self.data.extend_from_slice(data);
        self.prefix = epochs.to_be_bytes().to_vec();
        self.prefix
            .extend_from_slice(&(self.data.len() as u64).to_be_bytes());
        self.prefix.extend_from_slice(&hash.finalize());
        payload
    }
    fn final_payload(&self) -> Vec<u8> {
        let mut payload = self.prefix.clone();
        payload.extend_from_slice(&Sha256::digest(&self.data));
        payload
    }
    async fn hello(&self, wire: &mut Wire, complete: bool) {
        wire.send(FrameType::Handshake, self.hello.clone()).await;
        assert_eq!(
            wire.read(FrameType::HandshakeAck).await.unwrap(),
            self.state(complete)
        );
    }
    async fn finish(&self, wire: &mut Wire) {
        wire.send(FrameType::ObjectComplete, self.final_payload())
            .await;
        assert_eq!(
            wire.read(FrameType::Proof).await.unwrap(),
            self.final_payload()
        );
    }
}

#[test]
fn shared_port_runs_independent_clients_and_retires_only_the_selected_sink() {
    for workers in [1, 2] {
        run(workers, async {
            let cx = Cx::current().unwrap();
            let scope = cx.scope();
            let receive = receiver(true);
            let mut service = receive
                .bind_resumable_service::<Sink>(&cx, "127.0.0.1:0".parse().unwrap(), limits())
                .await
                .unwrap();
            let store = Store::default();
            let first = sender("allowed");
            let second = sender("unlisted");
            let mut a = first
                .resumable_reader(
                    &cx,
                    service.local_addr(),
                    b"first shared client".as_slice(),
                    4,
                )
                .unwrap();
            let mut b = second
                .resumable_reader(
                    &cx,
                    service.local_addr(),
                    b"second shared client".as_slice(),
                    4,
                )
                .unwrap();
            let ((a, b), completions) = zip(zip(a.send(&cx), b.send(&cx)), async {
                let a = service
                    .next(&cx, &scope, store.factory())
                    .await
                    .unwrap()
                    .unwrap();
                let b = service
                    .next(&cx, &scope, store.factory())
                    .await
                    .unwrap()
                    .unwrap();
                vec![a, b]
            })
            .await;
            let mut receipts = BTreeMap::new();
            for completion in completions {
                let key = completion.session.unwrap();
                let report = transfer(completion.outcome);
                let receipt = report.outcome.unwrap();
                assert_eq!(report.attempts, 1);
                assert_eq!(store.get(&key).commits.load(Ordering::SeqCst), 1);
                assert_eq!(
                    service.session_status(&key),
                    Some(ResumeSessionStatus::Idle)
                );
                assert_eq!(
                    service.retire(&key).unwrap().unwrap().completed.as_ref(),
                    Some(&receipt)
                );
                assert!(store.get(&key).dropped.load(Ordering::SeqCst));
                receipts.insert(key.client, receipt);
            }
            assert_eq!(a.outcome.unwrap(), receipts[&id("allowed")]);
            assert_eq!(b.outcome.unwrap(), receipts[&id("unlisted")]);
            assert_eq!(store.calls.load(Ordering::SeqCst), 2);
            assert_eq!(
                (service.resident_sessions(), service.retained_keys()),
                (0, 2)
            );
            assert_eq!(receive.active_streams(), 4);
            assert!(service.drain_next().await.is_none());
            assert!(service.is_drained());
            assert_eq!(receive.active_streams(), 0);
        });
    }
}

#[test]
fn dropped_attempt_resumes_partial_sink_bytes_on_the_same_port_without_a_new_factory() {
    for workers in [1, 2] {
        run(workers, async {
            let cx = Cx::current().unwrap();
            let scope = cx.scope();
            let receive = receiver(false);
            let mut service = receive
                .bind_resumable_service::<Sink>(&cx, "127.0.0.1:0".parse().unwrap(), limits())
                .await
                .unwrap();
            let store = Store {
                pause_write: true,
                ..Store::default()
            };
            let send = sender("allowed");
            let _release = ReleaseAll(Arc::clone(&store.probes));
            let reads = Arc::new(AtomicUsize::new(0));
            let source = Source {
                bytes: b"prefix-and-tail",
                offset: 0,
                reads: Arc::clone(&reads),
            };
            let mut outgoing = send
                .resumable_reader(&cx, service.local_addr(), source, 4)
                .unwrap();
            or(
                async {
                    let premature = zip(
                        outgoing.send(&cx),
                        service.next(&cx, &scope, store.factory()),
                    )
                    .await;
                    panic!("sink must still be parked: {premature:?}");
                },
                witness(&cx, || {
                    store
                        .first()
                        .is_some_and(|probe| probe.write_parked.load(Ordering::SeqCst))
                }),
            )
            .await;
            assert_eq!(reads.load(Ordering::SeqCst), 1);
            // The receiver still owns its parked sink; its actual operation timeout
            // returns the retained state, not cancellation of the manager's wait.
            let completion = service
                .next(&cx, &scope, store.factory())
                .await
                .unwrap()
                .unwrap();
            let key = completion.session.unwrap();
            let report = transfer(completion.outcome);
            assert!(matches!(
                report.outcome,
                Err(ResumeError::Transfer(LiveStreamError::Timeout(
                    "resume sink epoch"
                )))
            ));
            assert_eq!(report.sink_written_bytes, 3);
            assert_eq!(report.prefix.unwrap().bytes, 0);
            assert_eq!(report.retained_epoch_bytes, 8);
            assert_eq!(report.attempts, 1);
            let probe = store.get(&key);
            assert_eq!(*probe.bytes.lock().unwrap(), b"pre");
            probe.release();
            let (sent, completion) = zip(
                outgoing.send(&cx),
                service.next(&cx, &scope, store.factory()),
            )
            .await;
            let completion = completion.unwrap().unwrap();
            assert_eq!(completion.session, Some(key));
            let received = transfer(completion.outcome);
            assert_eq!(sent.outcome.unwrap(), received.outcome.unwrap());
            assert_eq!(received.attempts, 2);
            assert_eq!(*probe.bytes.lock().unwrap(), b"prefix-and-tail");
            assert_eq!(
                reads.load(Ordering::SeqCst),
                3,
                "two nonempty reads plus EOF, no restart read"
            );
            assert_eq!(probe.commits.load(Ordering::SeqCst), 1);
            assert_eq!(store.calls.load(Ordering::SeqCst), 1);
            assert!(service.drain_next().await.is_none());
            assert!(probe.dropped.load(Ordering::SeqCst));
            drop(outgoing);
            assert_eq!((send.active_streams(), receive.active_streams()), (0, 0));
        });
    }
}

#[test]
fn overlapping_reconnect_is_busy_but_the_same_nonce_under_another_certificate_is_independent() {
    run(2, async {
        let cx = Cx::current().unwrap();
        let scope = cx.scope();
        let receive = receiver(true);
        let mut service = receive
            .bind_resumable_service::<Sink>(&cx, "127.0.0.1:0".parse().unwrap(), limits())
            .await
            .unwrap();
        let address = service.local_addr();
        let store = Store::default();
        let model = Model::new(7);
        let mut first = None;
        or(
            async {
                let completion = service.next(&cx, &scope, store.factory()).await;
                panic!("first peer has not finished: {completion:?}");
            },
            async {
                let mut wire = Wire::connect(address, "allowed").await;
                model.hello(&mut wire, false).await;
                first = Some(wire);
            },
        )
        .await;
        let key = session("allowed", 7);
        assert_eq!(
            service.session_status(&key),
            Some(ResumeSessionStatus::Active)
        );
        assert_eq!(service.retire(&key).unwrap_err(), ResumeRetireError::Active);
        let ((), refused) = zip(
            async {
                let mut wire = Wire::connect(address, "allowed").await;
                wire.send(FrameType::Handshake, model.hello.clone()).await;
                assert!(wire.read(FrameType::HandshakeAck).await.is_err());
            },
            service.next(&cx, &scope, store.factory()),
        )
        .await;
        assert!(matches!(
            refused.unwrap().unwrap().outcome,
            ResumeServiceOutcome::Rejected(ResumeServiceRejection::Busy)
        ));
        let ((), other) = zip(
            async {
                let mut wire = Wire::connect(address, "unlisted").await;
                model.hello(&mut wire, false).await;
                model.finish(&mut wire).await;
            },
            service.next(&cx, &scope, store.factory()),
        )
        .await;
        let other = other.unwrap().unwrap();
        assert_eq!(other.session, Some(session("unlisted", 7)));
        assert!(transfer(other.outcome).outcome.is_ok());
        let ((), original) = zip(
            model.finish(first.as_mut().unwrap()),
            service.next(&cx, &scope, store.factory()),
        )
        .await;
        let original = original.unwrap().unwrap();
        assert_eq!(original.session, Some(key));
        assert_eq!(
            transfer(original.outcome).attempts,
            1,
            "busy refusal must not consume the owner's attempt"
        );
        assert_eq!(store.calls.load(Ordering::SeqCst), 2);
        assert!(service.drain_next().await.is_none());
    });
}

#[test]
fn retirement_releases_sinks_but_tombstones_and_lifetime_key_limits_remain() {
    run(1, async {
        let cx = Cx::current().unwrap();
        let scope = cx.scope();
        let receive = receiver(false);
        let config = ResumeServiceConfig {
            max_connections: 1,
            max_sessions: 1,
            max_sessions_per_client: 1,
            max_session_keys: 2,
            ..limits()
        };
        let mut service = receive
            .bind_resumable_service::<Sink>(&cx, "127.0.0.1:0".parse().unwrap(), config)
            .await
            .unwrap();
        let address = service.local_addr();
        let store = Store::default();
        for nonce in [1, 2] {
            let model = Model::new(nonce);
            let ((), complete) = zip(
                async {
                    let mut wire = Wire::connect(address, "allowed").await;
                    model.hello(&mut wire, false).await;
                    model.finish(&mut wire).await;
                },
                service.next(&cx, &scope, store.factory()),
            )
            .await;
            let complete = complete.unwrap().unwrap();
            let key = complete.session.unwrap();
            assert!(transfer(complete.outcome).outcome.is_ok());
            if nonce == 1 {
                let ((), refused) = zip(
                    async {
                        let mut wire = Wire::connect(address, "allowed").await;
                        wire.send(FrameType::Handshake, Model::new(2).hello).await;
                        assert!(wire.read(FrameType::HandshakeAck).await.is_err());
                    },
                    service.next(&cx, &scope, store.factory()),
                )
                .await;
                assert!(matches!(
                    refused.unwrap().unwrap().outcome,
                    ResumeServiceOutcome::Rejected(ResumeServiceRejection::Capacity(
                        "resident session"
                    ))
                ));
                assert_eq!(store.calls.load(Ordering::SeqCst), 1);
            }
            let snapshot = service.retire(&key).unwrap().unwrap();
            assert!(snapshot.completed.is_some());
            assert!(store.get(&key).dropped.load(Ordering::SeqCst));
            assert!(service.retire(&key).unwrap().unwrap().completed.is_some());
            let ((), refused) = zip(
                async {
                    let mut wire = Wire::connect(address, "allowed").await;
                    wire.send(FrameType::Handshake, model.hello.clone()).await;
                    assert!(wire.read(FrameType::HandshakeAck).await.is_err());
                },
                service.next(&cx, &scope, store.factory()),
            )
            .await;
            assert!(matches!(
                refused.unwrap().unwrap().outcome,
                ResumeServiceOutcome::Rejected(ResumeServiceRejection::Retired)
            ));
        }
        let ((), refused) = zip(
            async {
                let mut wire = Wire::connect(address, "allowed").await;
                wire.send(FrameType::Handshake, Model::new(3).hello).await;
                assert!(wire.read(FrameType::HandshakeAck).await.is_err());
            },
            service.next(&cx, &scope, store.factory()),
        )
        .await;
        assert!(matches!(
            refused.unwrap().unwrap().outcome,
            ResumeServiceOutcome::Rejected(ResumeServiceRejection::Capacity("lifetime key"))
        ));
        assert_eq!(
            (service.resident_sessions(), service.retained_keys()),
            (0, 2)
        );
        assert_eq!(store.calls.load(Ordering::SeqCst), 2);
        assert!(service.drain_next().await.is_none());
    });
}

#[test]
fn factory_error_or_panic_is_terminal_for_that_key_without_killing_the_listener() {
    for fail_factory in [1, 2] {
        run(2, async move {
            let cx = Cx::current().unwrap();
            let scope = cx.scope();
            let receive = receiver(false);
            let mut service = receive
                .bind_resumable_service::<Sink>(&cx, "127.0.0.1:0".parse().unwrap(), limits())
                .await
                .unwrap();
            let address = service.local_addr();
            let store = Store {
                fail_factory,
                ..Store::default()
            };
            let key = session("allowed", 9);
            for attempt in 0..2 {
                let ((), completion) = zip(
                    async {
                        let mut wire = Wire::connect(address, "allowed").await;
                        wire.send(FrameType::Handshake, Model::new(9).hello).await;
                        assert!(wire.read(FrameType::HandshakeAck).await.is_err());
                    },
                    service.next(&cx, &scope, store.factory()),
                )
                .await;
                let completion = completion.unwrap().unwrap();
                assert_eq!(completion.session, Some(key));
                match (attempt, fail_factory, completion.outcome) {
                    (
                        0,
                        1,
                        ResumeServiceOutcome::Rejected(ResumeServiceRejection::Factory(
                            LiveStreamError::Io(error),
                        )),
                    ) => assert_eq!(error.kind(), io::ErrorKind::PermissionDenied),
                    (0, 2, ResumeServiceOutcome::JoinFailed(JoinError::Panicked(_)))
                    | (1, _, ResumeServiceOutcome::Rejected(ResumeServiceRejection::Retired)) => {}
                    other => panic!("wrong factory result: {other:?}"),
                }
                assert_eq!(store.calls.load(Ordering::SeqCst), 1);
                assert_eq!(
                    service.session_status(&key),
                    Some(ResumeSessionStatus::Retired)
                );
                assert_eq!(service.resident_sessions(), 0);
            }
            let healthy = Store::default();
            let model = Model::new(10);
            let ((), completion) = zip(
                async {
                    let mut wire = Wire::connect(address, "allowed").await;
                    model.hello(&mut wire, false).await;
                    model.finish(&mut wire).await;
                },
                service.next(&cx, &scope, healthy.factory()),
            )
            .await;
            assert!(
                transfer(completion.unwrap().unwrap().outcome)
                    .outcome
                    .is_ok()
            );
            assert!(service.drain_next().await.is_none());
        });
    }
}

#[test]
fn failed_tls_never_allocates_a_session_or_invokes_the_sink_factory() {
    run(1, async {
        let cx = Cx::current().unwrap();
        let scope = cx.scope();
        let receive = receiver(false);
        let mut service = receive
            .bind_resumable_service::<Sink>(&cx, "127.0.0.1:0".parse().unwrap(), limits())
            .await
            .unwrap();
        let store = Store::default();
        for name in ["unlisted", "expired"] {
            let send = sender(name);
            let mut outgoing = send
                .resumable_reader(&cx, service.local_addr(), b"not authorized".as_slice(), 2)
                .unwrap();
            let (sent, completion) = zip(
                outgoing.send(&cx),
                service.next(&cx, &scope, store.factory()),
            )
            .await;
            assert!(sent.outcome.is_err());
            let completion = completion.unwrap().unwrap();
            assert!(completion.session.is_none());
            assert!(matches!(
                completion.outcome,
                ResumeServiceOutcome::Rejected(ResumeServiceRejection::Connection(
                    ResumeError::Transfer(LiveStreamError::Tls(_))
                ))
            ));
            assert_eq!(
                (service.resident_sessions(), service.retained_keys()),
                (0, 0)
            );
            assert_eq!(store.calls.load(Ordering::SeqCst), 0);
        }
        assert!(service.drain_next().await.is_none());
        assert_eq!(receive.active_streams(), 0);
    });
}

#[test]
fn per_client_resident_limits_do_not_block_another_authorized_identity() {
    run(2, async {
        let cx = Cx::current().unwrap();
        let scope = cx.scope();
        let receive = receiver(true);
        let config = ResumeServiceConfig {
            max_sessions_per_client: 1,
            ..limits()
        };
        let mut service = receive
            .bind_resumable_service::<Sink>(&cx, "127.0.0.1:0".parse().unwrap(), config)
            .await
            .unwrap();
        let address = service.local_addr();
        let store = Store::default();
        for (client, nonce, accepted) in [
            ("allowed", 21, true),
            ("allowed", 22, false),
            ("unlisted", 22, true),
        ] {
            let model = Model::new(nonce);
            let ((), completion) = zip(
                async {
                    let mut wire = Wire::connect(address, client).await;
                    if accepted {
                        model.hello(&mut wire, false).await;
                        model.finish(&mut wire).await;
                    } else {
                        wire.send(FrameType::Handshake, model.hello.clone()).await;
                        assert!(wire.read(FrameType::HandshakeAck).await.is_err());
                    }
                },
                service.next(&cx, &scope, store.factory()),
            )
            .await;
            let completion = completion.unwrap().unwrap();
            if accepted {
                assert!(transfer(completion.outcome).outcome.is_ok());
            } else {
                assert!(matches!(
                    completion.outcome,
                    ResumeServiceOutcome::Rejected(ResumeServiceRejection::Capacity(
                        "per-client session"
                    ))
                ));
            }
        }
        assert_eq!(store.calls.load(Ordering::SeqCst), 2);
        assert_eq!(service.resident_sessions(), 2);
        service.retire(&session("allowed", 21)).unwrap();
        let model = Model::new(22);
        let ((), completion) = zip(
            async {
                let mut wire = Wire::connect(address, "allowed").await;
                model.hello(&mut wire, false).await;
                model.finish(&mut wire).await;
            },
            service.next(&cx, &scope, store.factory()),
        )
        .await;
        assert!(
            transfer(completion.unwrap().unwrap().outcome)
                .outcome
                .is_ok()
        );
        assert_eq!(store.calls.load(Ordering::SeqCst), 3);
        assert!(service.drain_next().await.is_none());
    });
}

#[test]
fn changed_offer_cannot_rebind_a_session_or_reset_its_attempt_budget() {
    run(1, async {
        let cx = Cx::current().unwrap();
        let scope = cx.scope();
        let receive = receiver(false);
        let config = ResumeServiceConfig {
            max_attempts_per_session: 2,
            ..limits()
        };
        let mut service = receive
            .bind_resumable_service::<Sink>(&cx, "127.0.0.1:0".parse().unwrap(), config)
            .await
            .unwrap();
        let address = service.local_addr();
        let store = Store::default();
        let model = Model::new(31);
        let ((), completion) = zip(
            async {
                let mut wire = Wire::connect(address, "allowed").await;
                model.hello(&mut wire, false).await;
            },
            service.next(&cx, &scope, store.factory()),
        )
        .await;
        let report = transfer(completion.unwrap().unwrap().outcome);
        assert!(report.outcome.is_err());
        assert_eq!(report.attempts, 1);
        let ((), completion) = zip(
            async {
                let mut wire = Wire::connect(address, "allowed").await;
                let mut changed = model.hello.clone();
                changed[48..52].copy_from_slice(&4_u32.to_be_bytes());
                wire.send(FrameType::Handshake, changed).await;
                assert!(wire.read(FrameType::HandshakeAck).await.is_err());
            },
            service.next(&cx, &scope, store.factory()),
        )
        .await;
        let report = transfer(completion.unwrap().unwrap().outcome);
        assert!(matches!(
            report.outcome,
            Err(ResumeError::Continuity("session nonce or offer changed"))
        ));
        assert_eq!(report.attempts, 2);
        assert_eq!(report.sink_written_bytes, 0);
        let ((), refused) = zip(
            async {
                let mut wire = Wire::connect(address, "allowed").await;
                wire.send(FrameType::Handshake, model.hello.clone()).await;
                assert!(wire.read(FrameType::HandshakeAck).await.is_err());
            },
            service.next(&cx, &scope, store.factory()),
        )
        .await;
        assert!(matches!(
            refused.unwrap().unwrap().outcome,
            ResumeServiceOutcome::Rejected(ResumeServiceRejection::AttemptsExhausted)
        ));
        assert_eq!(store.calls.load(Ordering::SeqCst), 1);
        let snapshot = service.session_snapshot(&session("allowed", 31)).unwrap();
        assert_eq!(snapshot.attempts, 2);
        assert!(!snapshot.failed);
        assert_eq!(snapshot.prefix.as_ref().unwrap().bytes, 0);
        assert!(service.drain_next().await.is_none());
    });
}

#[test]
fn shared_service_resends_lost_final_proof_without_writing_or_committing_again() {
    run(2, async {
        let cx = Cx::current().unwrap();
        let scope = cx.scope();
        let receive = receiver(false);
        let mut service = receive
            .bind_resumable_service::<Sink>(&cx, "127.0.0.1:0".parse().unwrap(), limits())
            .await
            .unwrap();
        let address = service.local_addr();
        let store = Store::default();
        let mut model = Model::new(41);
        let ((), completion) = zip(
            async {
                let mut wire = Wire::connect(address, "allowed").await;
                model.hello(&mut wire, false).await;
                wire.send(FrameType::ObjectData, model.epoch(b"original"))
                    .await;
                assert_eq!(wire.read(FrameType::Control).await.unwrap(), model.prefix);
                wire.send(FrameType::ObjectComplete, model.final_payload())
                    .await;
                // Deliberately do not read Proof. The connection is dropped only
                // after the application commit is witnessed, so this is not a
                // source truncation masquerading as a lost acknowledgment.
                witness(&cx, || {
                    store
                        .first()
                        .is_some_and(|probe| probe.commits.load(Ordering::SeqCst) == 1)
                })
                .await;
            },
            service.next(&cx, &scope, store.factory()),
        )
        .await;
        let completion = completion.unwrap().unwrap();
        let key = completion.session.unwrap();
        let initial = transfer(completion.outcome);
        let committed = initial.completed.unwrap();
        let probe = store.get(&key);
        assert_eq!(probe.commits.load(Ordering::SeqCst), 1);
        let ((), completion) = zip(
            async {
                let mut wire = Wire::connect(address, "allowed").await;
                model.hello(&mut wire, true).await;
                model.finish(&mut wire).await;
            },
            service.next(&cx, &scope, store.factory()),
        )
        .await;
        let report = transfer(completion.unwrap().unwrap().outcome);
        assert!(report.receipt_reused);
        assert_eq!(report.outcome.unwrap(), committed);
        assert_eq!(report.attempts, 2);
        assert_eq!(probe.commits.load(Ordering::SeqCst), 1);
        assert_eq!(*probe.bytes.lock().unwrap(), b"original");
        assert_eq!(store.calls.load(Ordering::SeqCst), 1);
        assert!(service.drain_next().await.is_none());
    });
}

#[test]
fn stopping_or_cancelling_drains_a_witnessed_commit_before_releasing_admission() {
    for cancel in [false, true] {
        run(2, async move {
            let cx = Cx::current().unwrap();
            let scope = cx.scope();
            let receive = receiver(false);
            let mut service = receive
                .bind_resumable_service::<Sink>(&cx, "127.0.0.1:0".parse().unwrap(), limits())
                .await
                .unwrap();
            let store = Store {
                pause_commit: true,
                ..Store::default()
            };
            let send = sender("allowed");
            let _release = ReleaseAll(Arc::clone(&store.probes));
            let mut outgoing = send
                .resumable_reader(&cx, service.local_addr(), b"data".as_slice(), 4)
                .unwrap();
            let mut sending = cx
                .spawn_in(&scope, move |child| {
                    let future: Pin<Box<dyn Future<Output = ResumeReport> + Send>> =
                        Box::pin(async move { outgoing.send(&child).await });
                    future
                })
                .unwrap();
            or(
                async {
                    let result = service.next(&cx, &scope, store.factory()).await;
                    panic!("commit must still be parked: {result:?}");
                },
                witness(&cx, || {
                    store
                        .first()
                        .is_some_and(|probe| probe.commit_parked.load(Ordering::SeqCst))
                }),
            )
            .await;
            let probe = store.first().unwrap();
            service.stop_accepting();
            {
                let mut wait = Box::pin(service.drain_next());
                assert!(
                    wait.as_mut()
                        .poll(&mut Context::from_waker(Waker::noop()))
                        .is_pending()
                );
            }
            let reason = CancelReason::user("operator cancelled shared resume service");
            if cancel {
                service.cancel(reason.clone());
                witness(&cx, || probe.cancelled_commit.load(Ordering::SeqCst)).await;
            }
            assert_eq!(service.in_flight(), 1);
            assert_eq!(receive.active_streams(), 4);
            assert!(!probe.dropped.load(Ordering::SeqCst));
            probe.release();
            let report = transfer(service.drain_next().await.unwrap().outcome);
            let sent = sending.join(&cx).await.unwrap();
            if cancel {
                assert!(sent.outcome.is_err());
                assert!(report.completed.is_some());
                match report.outcome.unwrap_err() {
                    ResumeError::Transfer(LiveStreamError::Commit(error)) => match *error {
                        LiveStreamCommitError::CommittedWithoutProof { source, .. } => {
                            assert!(
                                matches!(*source, LiveStreamError::Cancelled(Some(actual)) if actual == reason)
                            );
                        }
                        other => panic!("lost committed evidence: {other:?}"),
                    },
                    other => panic!("wrong cancellation result: {other:?}"),
                }
            } else {
                assert_eq!(sent.outcome.unwrap(), report.outcome.unwrap());
            }
            assert_eq!(probe.commits.load(Ordering::SeqCst), 1);
            assert!(probe.dropped.load(Ordering::SeqCst));
            assert!(service.drain_next().await.is_none());
            assert!(service.is_drained());
            assert_eq!((send.active_streams(), receive.active_streams()), (0, 0));
        });
    }
}

#[test]
fn invalid_limits_and_bind_failure_leave_no_reserved_admission() {
    run(1, async {
        let cx = Cx::current().unwrap();
        let receive = receiver(false);
        let base = limits();
        let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = occupied.local_addr().unwrap();
        for config in [
            ResumeServiceConfig {
                max_connections: 0,
                ..base
            },
            ResumeServiceConfig {
                max_connections: 5,
                ..base
            },
            ResumeServiceConfig {
                max_sessions: 5,
                ..base
            },
            ResumeServiceConfig {
                max_sessions_per_client: 0,
                ..base
            },
            ResumeServiceConfig {
                max_sessions_per_client: 5,
                ..base
            },
            ResumeServiceConfig {
                max_session_keys: 3,
                ..base
            },
            ResumeServiceConfig {
                max_session_keys: usize::MAX,
                ..base
            },
            ResumeServiceConfig {
                max_attempts_per_session: 0,
                ..base
            },
        ] {
            assert!(matches!(
                receive
                    .bind_resumable_service::<Sink>(&cx, address, config)
                    .await,
                Err(LiveStreamError::Configuration(_))
            ));
            assert_eq!(receive.active_streams(), 0);
        }
        assert!(
            matches!(receive.bind_resumable_service::<Sink>(&cx, address, base).await,
            Err(LiveStreamError::Io(error)) if error.kind() == io::ErrorKind::AddrInUse)
        );
        assert_eq!(receive.active_streams(), 0);
        let one = receive
            .bind(&cx, "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        assert!(matches!(
            receive
                .bind_resumable_service::<Sink>(&cx, address, base)
                .await,
            Err(LiveStreamError::Capacity)
        ));
        assert_eq!(
            receive.active_streams(),
            1,
            "failed partial reservation must return its credits"
        );
        drop(one);
        assert_eq!(receive.active_streams(), 0);
    });
}

#[cfg(unix)]
#[test]
fn shared_file_receiver_preserves_real_staged_bytes_across_a_reconnect() {
    use asupersync::net::atp::sdk::native_auth::live::commit::file::{
        LiveFilePublication, LiveFileSink, LiveFileState,
    };
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    for workers in [1, 2] {
        let directory = tempfile::tempdir().unwrap().keep();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        run(workers, async move {
            let cx = Cx::current().unwrap();
            let scope = cx.scope();
            let receive = receiver(false);
            let mut service = receive
                .bind_resumable_service::<LiveFileSink>(
                    &cx,
                    "127.0.0.1:0".parse().unwrap(),
                    limits(),
                )
                .await
                .unwrap();
            let address = service.local_addr();
            let retained: Arc<Mutex<Option<LiveFilePublication>>> = Arc::new(Mutex::new(None));
            let calls = Arc::new(AtomicUsize::new(0));
            let factory = {
                let retained = Arc::clone(&retained);
                let calls = Arc::clone(&calls);
                move |child: Cx, key: ResumeSessionKey| {
                    assert_eq!(key, session("allowed", 51));
                    let retained = Arc::clone(&retained);
                    let calls = Arc::clone(&calls);
                    let directory = directory.clone();
                    async move {
                        assert_eq!(calls.fetch_add(1, Ordering::SeqCst), 0);
                        let sink =
                            LiveFileSink::create(&child, directory, "shared.bin".to_owned(), 1024)
                                .await?;
                        *retained.lock().unwrap() = Some(sink.publication());
                        Ok(sink)
                    }
                }
            };
            let mut model = Model::new(51);
            let ((), completion) = zip(
                async {
                    let mut wire = Wire::connect(address, "allowed").await;
                    model.hello(&mut wire, false).await;
                    wire.send(FrameType::ObjectData, model.epoch(b"prefix00"))
                        .await;
                    assert_eq!(wire.read(FrameType::Control).await.unwrap(), model.prefix);
                },
                service.next(&cx, &scope, factory.clone()),
            )
            .await;
            let report = transfer(completion.unwrap().unwrap().outcome);
            assert!(report.outcome.is_err());
            assert_eq!(report.prefix.unwrap().bytes, 8);
            assert_eq!(report.sink_written_bytes, 8);
            let publication = retained.lock().unwrap().as_ref().unwrap().clone();
            assert_eq!(
                std::fs::read(publication.staging_path()).unwrap(),
                b"prefix00"
            );
            assert!(!publication.destination_path().exists());
            assert_eq!(publication.status().state, LiveFileState::Staged);
            let ((), completion) = zip(
                async {
                    let mut wire = Wire::connect(address, "allowed").await;
                    model.hello(&mut wire, false).await;
                    wire.send(FrameType::ObjectData, model.epoch(b"-tail"))
                        .await;
                    assert_eq!(wire.read(FrameType::Control).await.unwrap(), model.prefix);
                    model.finish(&mut wire).await;
                },
                service.next(&cx, &scope, factory),
            )
            .await;
            let report = transfer(completion.unwrap().unwrap().outcome);
            let receipt = report.outcome.unwrap();
            assert_eq!(report.attempts, 2);
            assert_eq!(receipt.prefix.bytes, 13);
            assert_eq!(
                receipt.source_sha256.as_slice(),
                Sha256::digest(b"prefix00-tail").as_slice()
            );
            assert_eq!(
                std::fs::read(publication.destination_path()).unwrap(),
                b"prefix00-tail"
            );
            assert_eq!(publication.status().state, LiveFileState::Durable);
            let staged = std::fs::metadata(publication.staging_path()).unwrap();
            let final_file = std::fs::metadata(publication.destination_path()).unwrap();
            assert_eq!(
                (staged.dev(), staged.ino()),
                (final_file.dev(), final_file.ino())
            );
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert!(service.drain_next().await.is_none());
            assert_eq!(receive.active_streams(), 0);
        });
    }
}

#[test]
fn authenticated_hello_handoff_preserves_already_buffered_epoch_frames() {
    run(1, async {
        let cx = Cx::current().unwrap();
        let scope = cx.scope();
        let receive = receiver(false);
        let mut service = receive
            .bind_resumable_service::<Sink>(&cx, "127.0.0.1:0".parse().unwrap(), limits())
            .await
            .unwrap();
        let address = service.local_addr();
        let store = Store::default();
        let mut model = Model::new(61);
        let ((), completion) = zip(
            async {
                let mut wire = Wire::connect(address, "allowed").await;
                let initial = model.state(false);
                let mut bytes = Frame::new(
                    ProtocolVersion::V0,
                    FrameType::Handshake,
                    model.hello.clone(),
                )
                .unwrap()
                .to_wire_bytes()
                .unwrap();
                bytes.extend_from_slice(
                    &Frame::new(
                        ProtocolVersion::V0,
                        FrameType::ObjectData,
                        model.epoch(b"pipeline"),
                    )
                    .unwrap()
                    .to_wire_bytes()
                    .unwrap(),
                );
                bytes.extend_from_slice(
                    &Frame::new(
                        ProtocolVersion::V0,
                        FrameType::ObjectComplete,
                        model.final_payload(),
                    )
                    .unwrap()
                    .to_wire_bytes()
                    .unwrap(),
                );
                // One write deliberately coalesces the routing hello with transfer data.
                wire.tls.write_all(&bytes).await.unwrap();
                wire.tls.flush().await.unwrap();
                assert_eq!(wire.read(FrameType::HandshakeAck).await.unwrap(), initial);
                assert_eq!(wire.read(FrameType::Control).await.unwrap(), model.prefix);
                assert_eq!(
                    wire.read(FrameType::Proof).await.unwrap(),
                    model.final_payload()
                );
            },
            service.next(&cx, &scope, store.factory()),
        )
        .await;
        let report = transfer(completion.unwrap().unwrap().outcome);
        assert_eq!(report.outcome.unwrap().prefix.bytes, 8);
        assert_eq!(
            *store.get(&session("allowed", 61)).bytes.lock().unwrap(),
            b"pipeline"
        );
        assert_eq!(store.calls.load(Ordering::SeqCst), 1);
        assert!(service.drain_next().await.is_none());
    });
}
