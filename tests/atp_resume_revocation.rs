//! Targeted client revocation through real native mTLS and owned task joins.
//! Public fixture identities only. A parked sink/commit is witnessed before
//! revocation; a generic connection error is never the cancellation oracle.
#![cfg(all(
    feature = "tls",
    feature = "test-internals",
    not(target_arch = "wasm32")
))]

use asupersync::Cx;
use asupersync::bytes::BytesMut;
use asupersync::codec::Decoder;
use asupersync::cx::Scope;
use asupersync::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use asupersync::net::TcpStream;
use asupersync::net::atp::protocol::codec::AtpFrameCodec;
use asupersync::net::atp::protocol::frames::{Frame, FrameType, ProtocolVersion};
use asupersync::net::atp::sdk::native_auth::live::commit::resume::service::{
    MAX_REVOKED_RESUME_CLIENTS, ResumeRetireError, ResumeRevokeError, ResumeServiceConfig,
    ResumeServiceOutcome, ResumeServiceRejection, ResumeSessionInit, ResumeSessionKey,
    ResumeSessionStatus,
};
use asupersync::net::atp::sdk::native_auth::live::commit::resume::{
    RESUMABLE_LIVE_ALPN, ResumeError, ResumeReport,
};
use asupersync::net::atp::sdk::native_auth::live::commit::{
    LiveStreamCommitError, LiveStreamCommitSink,
};
use asupersync::net::atp::sdk::native_auth::live::{
    LiveStreamConfig, LiveStreamError, LiveStreamPrefix, LiveStreamReceipt, LiveStreamReceiver,
    LiveStreamSender,
};
use asupersync::net::atp::sdk::{
    AtpSdk, NativeClientAuthorization, NativeClientCertificateId, NativeTlsIdentity, SessionConfig,
};
use asupersync::runtime::{RuntimeBuilder, TaskHandle, yield_now};
use asupersync::tls::{TlsConnector, TlsStream};
use asupersync::types::{CancelReason, Policy};
use futures_lite::future::{or, zip};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::future::{Future, Ready, poll_fn, ready};
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!("fixtures/atp_native_auth_identities.json")).unwrap()
}
fn certificate(name: &str) -> CertificateDer<'static> {
    let data = fixture();
    let pem = if name == "ca" {
        data["ca"].as_str()
    } else {
        data["identities"][name]["certificate"].as_str()
    }
    .unwrap();
    CertificateDer::pem_reader_iter(&mut io::BufReader::new(pem.as_bytes()))
        .next()
        .unwrap()
        .unwrap()
}
fn key(name: &str) -> PrivateKeyDer<'static> {
    let data = fixture();
    let pem = data["identities"][name]["key"].as_str().unwrap();
    PrivateKeyDer::pem_reader_iter(&mut io::BufReader::new(pem.as_bytes()))
        .next()
        .unwrap()
        .unwrap()
}
fn identity(name: &str) -> NativeTlsIdentity {
    NativeTlsIdentity::new(vec![certificate(name)], key(name)).unwrap()
}
fn roots() -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate("ca")).unwrap();
    roots
}
fn id(name: &str) -> NativeClientCertificateId {
    NativeClientCertificateId::from_certificate(&certificate(name))
}
fn sdk() -> AtpSdk {
    AtpSdk::new_in_process(SessionConfig {
        max_concurrent_transfers: 4,
        ..SessionConfig::default()
    })
}
fn profile() -> LiveStreamConfig {
    let mut config = LiveStreamConfig::default();
    config.epoch_bytes = 8;
    config.max_bytes = 1024;
    config.operation_timeout = Duration::from_secs(10);
    config
}
fn receiver() -> LiveStreamReceiver {
    let authorization =
        NativeClientAuthorization::new(roots(), [id("allowed"), id("unlisted")]).unwrap();
    sdk()
        .live_stream_receiver(profile(), identity("server"), authorization)
        .unwrap()
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
fn limits() -> ResumeServiceConfig {
    ResumeServiceConfig {
        max_connections: 4,
        max_sessions: 4,
        max_sessions_per_client: 2,
        max_session_keys: 8,
        max_attempts_per_session: 4,
    }
}
fn run(workers: usize, future: impl Future<Output = ()> + Send + 'static) {
    let builder = if workers == 1 {
        RuntimeBuilder::current_thread()
    } else {
        RuntimeBuilder::multi_thread()
            .worker_threads(workers)
            .with_sharded_state(true)
    };
    let runtime = builder.blocking_threads(1, 2).build().unwrap();
    let future: Pin<Box<dyn Future<Output = ()> + Send>> = Box::pin(async move {
        let cx = Cx::current().unwrap();
        asupersync::time::timeout(cx.now(), Duration::from_secs(30), future)
            .await
            .unwrap();
    });
    runtime.block_on(runtime.handle().spawn(future));
    let started = Instant::now();
    while !runtime.is_quiescent() {
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "revocation left owned tasks live"
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
}
async fn witness(cx: &Cx, condition: impl Fn() -> bool) {
    asupersync::time::timeout(cx.now(), Duration::from_secs(5), async {
        while !condition() {
            yield_now().await;
        }
    })
    .await
    .expect("required parked state was never reached");
}
fn start<P: Policy>(
    cx: &Cx,
    scope: &Scope<'_, P>,
    address: SocketAddr,
    name: &str,
    bytes: &'static [u8],
) -> TaskHandle<ResumeReport> {
    let authority = sender(name);
    cx.spawn_in(scope, move |child| {
        let future: Pin<Box<dyn Future<Output = ResumeReport> + Send>> = Box::pin(async move {
            let mut outgoing = authority
                .resumable_reader(&child, address, bytes, 1)
                .unwrap();
            outgoing.send(&child).await
        });
        future
    })
    .unwrap()
}
fn transfer(outcome: ResumeServiceOutcome) -> ResumeReport {
    match outcome {
        ResumeServiceOutcome::Transfer(report) => report,
        other => panic!("expected transfer: {other:?}"),
    }
}

#[derive(Default)]
struct Probe {
    bytes: Mutex<Vec<u8>>,
    write_parked: AtomicBool,
    commit_parked: AtomicBool,
    cancel_seen: AtomicBool,
    released: AtomicBool,
    dropped: AtomicBool,
    commits: AtomicUsize,
    wake: Mutex<Option<Waker>>,
}
impl Probe {
    fn park(&self, cx: &Context<'_>) -> bool {
        let candidate = cx.waker().clone();
        let old = self.wake.lock().unwrap().replace(candidate);
        drop(old);
        !self.released.load(Ordering::SeqCst)
    }
    fn release(&self) {
        self.released.store(true, Ordering::SeqCst);
        let wake = self.wake.lock().unwrap().take();
        if let Some(wake) = wake {
            wake.wake();
        }
    }
}
struct Sink {
    probe: Arc<Probe>,
    pause_write: bool,
    pause_commit: bool,
}
impl AsyncWrite for Sink {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.pause_write && self.probe.bytes.lock().unwrap().len() >= 3 && self.probe.park(cx) {
            self.probe.write_parked.store(true, Ordering::SeqCst);
            return Poll::Pending;
        }
        let count = bytes.len().min(3);
        self.probe
            .bytes
            .lock()
            .unwrap()
            .extend_from_slice(&bytes[..count]);
        Poll::Ready(Ok(count))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        panic!("revocation must not implicitly shut down the sink")
    }
}
impl LiveStreamCommitSink for Sink {
    fn poll_commit(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        receipt: &LiveStreamReceipt,
    ) -> Poll<io::Result<()>> {
        if Cx::current().and_then(|cx| cx.cancel_reason()).is_some() {
            self.probe.cancel_seen.store(true, Ordering::SeqCst);
        }
        if self.pause_commit && self.probe.park(cx) {
            self.probe.commit_parked.store(true, Ordering::SeqCst);
            return Poll::Pending;
        }
        let bytes = self.probe.bytes.lock().unwrap();
        assert_eq!(receipt.prefix.bytes, bytes.len() as u64);
        assert_eq!(
            receipt.source_sha256.as_slice(),
            Sha256::digest(&*bytes).as_slice()
        );
        assert_eq!(self.probe.commits.fetch_add(1, Ordering::SeqCst), 0);
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
}
impl Store {
    fn factory(
        &self,
    ) -> impl Fn(Cx, ResumeSessionKey) -> Ready<io::Result<Sink>> + Clone + Send + Sync + 'static
    {
        let store = self.clone();
        move |_, key| {
            store.calls.fetch_add(1, Ordering::SeqCst);
            let probe = Arc::new(Probe::default());
            assert!(
                store
                    .probes
                    .lock()
                    .unwrap()
                    .insert(key, Arc::clone(&probe))
                    .is_none()
            );
            ready(Ok(Sink {
                probe,
                pause_write: store.pause_write,
                pause_commit: store.pause_commit,
            }))
        }
    }
    fn client(&self, client: NativeClientCertificateId) -> Option<(ResumeSessionKey, Arc<Probe>)> {
        self.probes
            .lock()
            .unwrap()
            .iter()
            .find(|(key, _)| key.client == client)
            .map(|(key, probe)| (*key, Arc::clone(probe)))
    }
}
struct ReleaseAll(Store);
impl Drop for ReleaseAll {
    fn drop(&mut self) {
        let probes: Vec<_> = self.0.probes.lock().unwrap().values().cloned().collect();
        for probe in probes {
            probe.release();
        }
    }
}

struct Wire {
    tls: TlsStream<TcpStream>,
    codec: AtpFrameCodec,
    buffer: BytesMut,
}
impl Wire {
    async fn connect(address: SocketAddr, name: &str) -> Self {
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots())
        .with_client_auth_cert(vec![certificate(name)], key(name))
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
    async fn hello(&mut self, nonce: [u8; 32]) -> io::Result<Frame> {
        let encoded = Frame::new(ProtocolVersion::V0, FrameType::Handshake, hello(nonce))
            .unwrap()
            .to_wire_bytes()
            .unwrap();
        self.tls.write_all(&encoded).await?;
        self.tls.flush().await?;
        loop {
            if let Some(frame) = self
                .codec
                .decode(&mut self.buffer)
                .map_err(io::Error::other)?
            {
                return Ok(frame);
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
fn hello(nonce: [u8; 32]) -> Vec<u8> {
    let mut bytes = b"ATPRSM01ATPLIVE1".to_vec();
    bytes.extend_from_slice(&nonce);
    bytes.extend_from_slice(&8_u32.to_be_bytes());
    bytes.extend_from_slice(&1024_u64.to_be_bytes());
    bytes
}

#[test]
fn revocation_stops_only_the_target_parked_writer_and_preserves_its_join() {
    for workers in [1, 2] {
        run(workers, async {
            let cx = Cx::current().unwrap();
            let scope = cx.scope();
            let receiver = receiver();
            let mut service = receiver
                .bind_resumable_service::<Sink>(&cx, "127.0.0.1:0".parse().unwrap(), limits())
                .await
                .unwrap();
            let store = Store {
                pause_write: true,
                ..Store::default()
            };
            let _release = ReleaseAll(store.clone());
            let target = id("allowed");
            let other = id("unlisted");
            let mut a = start(&cx, &scope, service.local_addr(), "allowed", b"abcdefgh");
            let mut b = start(&cx, &scope, service.local_addr(), "unlisted", b"12345678");
            or(
                async {
                    let early = service.next(&cx, &scope, store.factory()).await;
                    panic!("connection completed before the parked witness: {early:?}");
                },
                witness(&cx, || {
                    [target, other].iter().all(|id| {
                        store
                            .client(*id)
                            .is_some_and(|(_, probe)| probe.write_parked.load(Ordering::SeqCst))
                    })
                }),
            )
            .await;
            let (key, probe) = store.client(target).unwrap();
            let (other_key, other_probe) = store.client(other).unwrap();
            let reason = CancelReason::user("revoke compromised transfer client");
            let changed = service.revoke_client(target, reason.clone()).unwrap();
            assert!(changed.newly_revoked);
            assert_eq!(
                (changed.signalled_connections, changed.retained_sessions),
                (1, 1)
            );
            assert_eq!(service.retire(&key).unwrap_err(), ResumeRetireError::Active);
            assert!(!probe.dropped.load(Ordering::SeqCst));
            assert_eq!(receiver.active_streams(), 4);
            let completion = service
                .next(&cx, &scope, store.factory())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(completion.session, Some(key));
            let report = transfer(completion.outcome);
            match report.outcome {
                Err(ResumeError::Transfer(LiveStreamError::Cancelled(Some(actual)))) => {
                    assert_eq!(actual, reason)
                }
                other => panic!("revocation lost its cancellation attribution: {other:?}"),
            }
            assert_eq!(report.sink_written_bytes, 3);
            assert_eq!(report.prefix.unwrap().bytes, 0);
            assert!(report.completed.is_none());
            assert!(!probe.dropped.load(Ordering::SeqCst));
            assert_eq!(
                service.session_status(&other_key),
                Some(ResumeSessionStatus::Active)
            );
            assert!(!other_probe.cancel_seen.load(Ordering::SeqCst));
            let snapshot = service.retire(&key).unwrap().unwrap();
            assert_eq!(snapshot.sink_written_bytes, 3);
            assert!(probe.dropped.load(Ordering::SeqCst));
            assert!(
                poll_fn(|ctx| a.poll_join(ctx))
                    .await
                    .unwrap()
                    .outcome
                    .is_err()
            );
            other_probe.release();
            let completion = service
                .next(&cx, &scope, store.factory())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(completion.session, Some(other_key));
            assert!(transfer(completion.outcome).outcome.is_ok());
            assert!(
                poll_fn(|ctx| b.poll_join(ctx))
                    .await
                    .unwrap()
                    .outcome
                    .is_ok()
            );
            assert_eq!(&*other_probe.bytes.lock().unwrap(), b"12345678");
            assert_eq!(other_probe.commits.load(Ordering::SeqCst), 1);
            assert!(service.drain_next().await.is_none());
            assert_eq!(receiver.active_streams(), 0);
        });
    }
}

#[test]
fn handshake_started_before_revocation_cannot_create_a_sink_or_consume_a_key() {
    run(2, async {
        let cx = Cx::current().unwrap();
        let scope = cx.scope();
        let receiver = receiver();
        let mut service = receiver
            .bind_resumable_service::<Sink>(&cx, "127.0.0.1:0".parse().unwrap(), limits())
            .await
            .unwrap();
        let store = Store::default();
        let address = service.local_addr();
        // Complete client-side TLS before revoking. This SDK operation does not
        // change the TLS allowlist: the registry must refuse the later hello.
        let mut wire = or(
            async {
                let early = service.next(&cx, &scope, store.factory()).await;
                panic!("no hello exists to complete: {early:?}");
            },
            Wire::connect(address, "allowed"),
        )
        .await;
        let changed = service
            .revoke_client(id("allowed"), CancelReason::user("certificate revoked"))
            .unwrap();
        assert_eq!(changed.signalled_connections, 0);
        let (refused, completion) = zip(
            wire.hello([7; 32]),
            service.next(&cx, &scope, store.factory()),
        )
        .await;
        assert!(refused.is_err());
        assert!(matches!(
            completion.unwrap().unwrap().outcome,
            ResumeServiceOutcome::Rejected(ResumeServiceRejection::Revoked)
        ));
        assert_eq!(
            (
                store.calls.load(Ordering::SeqCst),
                service.resident_sessions(),
                service.retained_keys()
            ),
            (0, 0, 0)
        );
        drop(wire);
        // New nonces and new connections cannot bypass the same certificate denial.
        let address = service.local_addr();
        let (refused, completion) = zip(
            async { Wire::connect(address, "allowed").await.hello([8; 32]).await },
            service.next(&cx, &scope, store.factory()),
        )
        .await;
        assert!(refused.is_err());
        assert!(matches!(
            completion.unwrap().unwrap().outcome,
            ResumeServiceOutcome::Rejected(ResumeServiceRejection::Revoked)
        ));
        assert_eq!(store.calls.load(Ordering::SeqCst), 0);
        assert!(service.drain_next().await.is_none());
    });
}

#[test]
fn revoking_a_started_commit_drains_and_retains_committed_without_proof() {
    for workers in [1, 2] {
        run(workers, async {
            let cx = Cx::current().unwrap();
            let scope = cx.scope();
            let receiver = receiver();
            let mut service = receiver
                .bind_resumable_service::<Sink>(&cx, "127.0.0.1:0".parse().unwrap(), limits())
                .await
                .unwrap();
            let store = Store {
                pause_commit: true,
                ..Store::default()
            };
            let _release = ReleaseAll(store.clone());
            let mut sending = start(&cx, &scope, service.local_addr(), "allowed", b"abcdefgh");
            or(
                async {
                    let early = service.next(&cx, &scope, store.factory()).await;
                    panic!("commit completed before release: {early:?}");
                },
                witness(&cx, || {
                    store
                        .client(id("allowed"))
                        .is_some_and(|(_, probe)| probe.commit_parked.load(Ordering::SeqCst))
                }),
            )
            .await;
            let (key, probe) = store.client(id("allowed")).unwrap();
            let reason = CancelReason::user("revoke during publication");
            assert_eq!(
                service
                    .revoke_client(key.client, reason.clone())
                    .unwrap()
                    .signalled_connections,
                1
            );
            witness(&cx, || probe.cancel_seen.load(Ordering::SeqCst)).await;
            assert_eq!(
                service.session_status(&key),
                Some(ResumeSessionStatus::Active)
            );
            assert_eq!(probe.commits.load(Ordering::SeqCst), 0);
            assert_eq!(receiver.active_streams(), 4);
            probe.release();
            let report = transfer(
                service
                    .next(&cx, &scope, store.factory())
                    .await
                    .unwrap()
                    .unwrap()
                    .outcome,
            );
            let committed = report
                .completed
                .as_ref()
                .expect("completed commit must survive revocation");
            match &report.outcome {
                Err(ResumeError::Transfer(LiveStreamError::Commit(error))) => {
                    match error.as_ref() {
                        LiveStreamCommitError::CommittedWithoutProof { receipt, source } => {
                            assert_eq!(receipt.as_ref(), committed);
                            assert!(
                                matches!(source.as_ref(), LiveStreamError::Cancelled(Some(actual)) if actual == &reason)
                            );
                        }
                        other => panic!("publication was mislabeled: {other:?}"),
                    }
                }
                other => panic!("expected committed-without-Proof, got {other:?}"),
            }
            assert_eq!(probe.commits.load(Ordering::SeqCst), 1);
            assert!(!probe.dropped.load(Ordering::SeqCst));
            let snapshot = service.retire(&key).unwrap().unwrap();
            assert_eq!(snapshot.completed.as_ref(), Some(committed));
            assert!(probe.dropped.load(Ordering::SeqCst));
            assert!(
                poll_fn(|ctx| sending.poll_join(ctx))
                    .await
                    .unwrap()
                    .outcome
                    .is_err()
            );
            assert!(service.drain_next().await.is_none());
        });
    }
}

#[test]
fn revocation_preserves_completed_receipts_but_refuses_their_reconnects() {
    run(1, async {
        let cx = Cx::current().unwrap();
        let scope = cx.scope();
        let receiver = receiver();
        let mut service = receiver
            .bind_resumable_service::<Sink>(&cx, "127.0.0.1:0".parse().unwrap(), limits())
            .await
            .unwrap();
        let store = Store::default();
        let mut sending = start(&cx, &scope, service.local_addr(), "allowed", b"completed");
        let complete = service
            .next(&cx, &scope, store.factory())
            .await
            .unwrap()
            .unwrap();
        let key = complete.session.unwrap();
        let report = transfer(complete.outcome);
        assert!(report.outcome.is_ok());
        assert!(
            poll_fn(|ctx| sending.poll_join(ctx))
                .await
                .unwrap()
                .outcome
                .is_ok()
        );
        let changed = service
            .revoke_client(key.client, CancelReason::user("deny receipt access"))
            .unwrap();
        assert_eq!(
            (changed.signalled_connections, changed.retained_sessions),
            (0, 1)
        );
        assert_eq!(
            service.session_snapshot(&key).unwrap().completed,
            report.completed
        );
        let again = service
            .revoke_client(
                key.client,
                CancelReason::user("must not change prior attribution"),
            )
            .unwrap();
        assert!(!again.newly_revoked);
        assert_eq!(service.revoked_clients(), 1);
        let address = service.local_addr();
        let (refused, completion) = zip(
            async {
                Wire::connect(address, "allowed")
                    .await
                    .hello(key.nonce)
                    .await
            },
            service.next(&cx, &scope, store.factory()),
        )
        .await;
        assert!(refused.is_err());
        assert!(matches!(
            completion.unwrap().unwrap().outcome,
            ResumeServiceOutcome::Rejected(ResumeServiceRejection::Revoked)
        ));
        assert_eq!(store.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            service.retire(&key).unwrap().unwrap().completed,
            report.completed
        );
        assert!(service.is_client_revoked(&key.client));
        assert!(service.drain_next().await.is_none());
        assert!(service.is_client_revoked(&key.client));
        assert!(
            !service
                .revoke_client(key.client, CancelReason::user("duplicate after drain"))
                .unwrap()
                .newly_revoked
        );
        assert_eq!(
            service
                .revoke_client(id("unlisted"), CancelReason::user("already drained"))
                .unwrap_err(),
            ResumeRevokeError::Drained
        );
    });
}

#[test]
fn revoked_client_never_invokes_a_historical_receipt_restoration_factory() {
    run(2, async {
        let cx = Cx::current().unwrap();
        let scope = cx.scope();
        let receiver = receiver();
        let mut service = receiver
            .bind_resumable_service::<Sink>(&cx, "127.0.0.1:0".parse().unwrap(), limits())
            .await
            .unwrap();
        let client = id("allowed");
        assert!(
            service
                .revoke_client(
                    client,
                    CancelReason::user("old receipts do not renew authority")
                )
                .unwrap()
                .newly_revoked
        );
        let calls = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&calls);
        let address = service.local_addr();
        let (refused, completion) = zip(
            async { Wire::connect(address, "allowed").await.hello([9; 32]).await },
            service.next_restoring(&cx, &scope, move |_, key| {
                count.fetch_add(1, Ordering::SeqCst);
                let mut hash = Sha256::new();
                hash.update(b"asupersync.atp.live.resume.hello.v1");
                hash.update(hello(key.nonce));
                ready(Ok(ResumeSessionInit::<Sink>::Committed(
                    LiveStreamReceipt {
                        prefix: LiveStreamPrefix {
                            stream_nonce: key.nonce,
                            epochs: 0,
                            bytes: 0,
                            chain: hash.finalize().into(),
                        },
                        source_sha256: Sha256::digest(b"").into(),
                    },
                )))
            }),
        )
        .await;
        assert!(refused.is_err());
        assert!(matches!(
            completion.unwrap().unwrap().outcome,
            ResumeServiceOutcome::Rejected(ResumeServiceRejection::Revoked)
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(service.retained_keys(), 0);
        assert!(service.drain_next().await.is_none());
    });
}

#[test]
fn revocation_cancels_a_parked_factory_without_recreating_its_session() {
    run(2, async {
        let cx = Cx::current().unwrap();
        let scope = cx.scope();
        let receiver = receiver();
        let mut service = receiver
            .bind_resumable_service::<Sink>(&cx, "127.0.0.1:0".parse().unwrap(), limits())
            .await
            .unwrap();
        let entered = Arc::new(AtomicBool::new(false));
        let marker = Arc::clone(&entered);
        let factory = move |_: Cx, _: ResumeSessionKey| {
            let marker = Arc::clone(&marker);
            async move {
                marker.store(true, Ordering::SeqCst);
                std::future::pending::<io::Result<Sink>>().await
            }
        };
        let mut sending = start(&cx, &scope, service.local_addr(), "allowed", b"not written");
        or(
            async {
                let early = service.next(&cx, &scope, factory.clone()).await;
                panic!("factory completed without revocation: {early:?}");
            },
            witness(&cx, || entered.load(Ordering::SeqCst)),
        )
        .await;
        let reason = CancelReason::user("revoke during factory");
        assert_eq!(
            service
                .revoke_client(id("allowed"), reason.clone())
                .unwrap()
                .signalled_connections,
            1
        );
        let complete = service.next(&cx, &scope, factory).await.unwrap().unwrap();
        let key = complete.session.unwrap();
        assert!(matches!(complete.outcome,
            ResumeServiceOutcome::Rejected(ResumeServiceRejection::Factory(LiveStreamError::Cancelled(Some(actual)))) if actual == reason));
        assert_eq!(
            service.session_status(&key),
            Some(ResumeSessionStatus::Retired)
        );
        assert_eq!(
            (service.resident_sessions(), service.retained_keys()),
            (0, 1)
        );
        assert!(
            poll_fn(|ctx| sending.poll_join(ctx))
                .await
                .unwrap()
                .outcome
                .is_err()
        );
        assert!(service.drain_next().await.is_none());
    });
}

#[test]
fn revocation_capacity_is_independent_of_session_capacity_and_never_evicts_denials() {
    run(1, async {
        let cx = Cx::current().unwrap();
        let receiver = receiver();
        let mut service = receiver
            .bind_resumable_service::<Sink>(&cx, "127.0.0.1:0".parse().unwrap(), limits())
            .await
            .unwrap();
        for number in 0..MAX_REVOKED_RESUME_CLIENTS as u32 {
            let mut digest = [0; 32];
            digest[..4].copy_from_slice(&number.to_be_bytes());
            assert!(
                service
                    .revoke_client(
                        NativeClientCertificateId::from_sha256(digest),
                        CancelReason::user("bounded denial")
                    )
                    .unwrap()
                    .newly_revoked
            );
        }
        assert_eq!(service.revoked_clients(), MAX_REVOKED_RESUME_CLIENTS);
        assert_eq!(
            (
                service.retained_keys(),
                service.resident_sessions(),
                service.in_flight()
            ),
            (0, 0, 0)
        );
        assert_eq!(
            service
                .revoke_client(
                    id("allowed"),
                    CancelReason::user("must not pretend success")
                )
                .unwrap_err(),
            ResumeRevokeError::Capacity
        );
        assert!(!service.is_client_revoked(&id("allowed")));
        assert!(service.is_client_revoked(&NativeClientCertificateId::from_sha256([0; 32])));
        assert!(
            !service
                .revoke_client(
                    NativeClientCertificateId::from_sha256([0; 32]),
                    CancelReason::user("idempotent at capacity")
                )
                .unwrap()
                .newly_revoked
        );
        service.stop_accepting();
        assert!(service.drain_next().await.is_none());
        assert_eq!(receiver.active_streams(), 0);
    });
}

#[test]
fn revocation_does_not_relabel_an_uncollected_success_as_cancellation() {
    run(2, async {
        let cx = Cx::current().unwrap();
        let scope = cx.scope();
        let receiver = receiver();
        let mut service = receiver
            .bind_resumable_service::<Sink>(&cx, "127.0.0.1:0".parse().unwrap(), limits())
            .await
            .unwrap();
        let store = Store {
            pause_commit: true,
            ..Store::default()
        };
        let _release = ReleaseAll(store.clone());
        let mut sending = start(
            &cx,
            &scope,
            service.local_addr(),
            "allowed",
            b"already committed",
        );
        or(
            async {
                let early = service.next(&cx, &scope, store.factory()).await;
                panic!("commit completed before test released it: {early:?}");
            },
            witness(&cx, || {
                store
                    .client(id("allowed"))
                    .is_some_and(|(_, probe)| probe.commit_parked.load(Ordering::SeqCst))
            }),
        )
        .await;
        let (key, probe) = store.client(id("allowed")).unwrap();
        probe.release();
        // Do not poll service.next while the worker finishes. The sender's
        // verified Proof establishes completion, while the service still owns
        // the uncollected server result and its admission reservation.
        let sent = poll_fn(|ctx| sending.poll_join(ctx)).await.unwrap();
        let receipt = sent.outcome.unwrap();
        assert_eq!(
            service.session_status(&key),
            Some(ResumeSessionStatus::Active)
        );
        assert_eq!(service.in_flight(), 1);
        assert_eq!(probe.commits.load(Ordering::SeqCst), 1);
        let changed = service
            .revoke_client(key.client, CancelReason::user("late revocation"))
            .unwrap();
        assert_eq!(changed.signalled_connections, 1);
        let report = transfer(
            service
                .next(&cx, &scope, store.factory())
                .await
                .unwrap()
                .unwrap()
                .outcome,
        );
        assert_eq!(report.outcome.unwrap(), receipt);
        assert_eq!(report.completed, Some(receipt.clone()));
        assert_eq!(
            service.retire(&key).unwrap().unwrap().completed,
            Some(receipt)
        );
        assert!(probe.dropped.load(Ordering::SeqCst));
        assert!(service.drain_next().await.is_none());
    });
}
