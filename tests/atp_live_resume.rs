//! Native mTLS reconnects with independent wire peers and witnessed interruption.
//! No process-restart claim: the source, sink and sessions stay alive between attempts.
#![cfg(all(
    feature = "tls",
    feature = "test-internals",
    not(target_arch = "wasm32")
))]

use asupersync::Cx;
use asupersync::bytes::BytesMut;
use asupersync::codec::Decoder;
use asupersync::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use asupersync::net::atp::protocol::codec::AtpFrameCodec;
use asupersync::net::atp::protocol::frames::{Frame, FrameType, ProtocolVersion};
use asupersync::net::atp::sdk::native_auth::live::commit::resume::{
    RESUMABLE_LIVE_ALPN, ResumeError,
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
use asupersync::net::{TcpListener, TcpStream};
use asupersync::runtime::{RuntimeBuilder, yield_now};
use asupersync::tls::{TlsAcceptor, TlsConnector, TlsStream};
use asupersync::types::CancelReason;
use futures_lite::future::{or, zip};
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject},
};
use sha2::{Digest, Sha256};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::task::{Context, Poll};
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
fn client_id() -> NativeClientCertificateId {
    NativeClientCertificateId::from_certificate(&certificate("allowed"))
}
fn profile() -> LiveStreamConfig {
    let mut config = LiveStreamConfig::default();
    config.epoch_bytes = 8;
    config.max_bytes = 1024;
    config.operation_timeout = Duration::from_secs(5);
    config
}
fn sdk() -> AtpSdk {
    AtpSdk::new_in_process(SessionConfig {
        max_concurrent_transfers: 1,
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
fn receiver() -> LiveStreamReceiver {
    // Both have valid certificates. The resume endpoint must ALSO enforce its
    // selected owner instead of accepting every member of this broader policy.
    let policy = NativeClientAuthorization::new(
        roots(),
        [
            client_id(),
            NativeClientCertificateId::from_certificate(&certificate("unlisted")),
        ],
    )
    .unwrap();
    sdk()
        .live_stream_receiver(profile(), identity("server"), policy)
        .unwrap()
}
fn raw_client() -> TlsConnector {
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots())
    .with_client_auth_cert(vec![certificate("allowed")], key("allowed"))
    .unwrap();
    config.alpn_protocols = vec![RESUMABLE_LIVE_ALPN.to_vec()];
    config.resumption = rustls::client::Resumption::disabled();
    TlsConnector::new(config)
}
fn raw_server() -> TlsAcceptor {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots()),
        Arc::clone(&provider),
    )
    .build()
    .unwrap();
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![certificate("server")], key("server"))
        .unwrap();
    config.alpn_protocols = vec![RESUMABLE_LIVE_ALPN.to_vec()];
    config.send_tls13_tickets = 0;
    TlsAcceptor::new(config)
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
        asupersync::time::timeout(cx.now(), Duration::from_secs(20), future)
            .await
            .expect("native resume journey must terminate")
    });
    let output = runtime.block_on(runtime.handle().spawn(future));
    let started = Instant::now();
    while !runtime.is_quiescent() {
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "session owner did not drain"
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
async fn witness(cx: &Cx, ready: impl Fn() -> bool) {
    asupersync::time::timeout(cx.now(), Duration::from_secs(5), async {
        while !ready() {
            yield_now().await;
        }
    })
    .await
    .expect("required causal interruption point was not reached");
}

#[derive(Default)]
struct Probe {
    bytes: Mutex<Vec<u8>>,
    reads: AtomicUsize,
    commits: AtomicUsize,
    commit_polls: AtomicUsize,
    write_parked: AtomicBool,
    commit_parked: AtomicBool,
    cancel_polled: AtomicBool,
    release_write: AtomicBool,
    release_commit: AtomicBool,
}
struct Source {
    bytes: &'static [u8],
    offset: usize,
    probe: Arc<Probe>,
    fail: bool,
}
impl AsyncRead for Source {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.probe.reads.fetch_add(1, Ordering::SeqCst);
        if self.fail && self.offset != 0 {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::InvalidData)));
        }
        let count = out.remaining().min(self.bytes.len() - self.offset);
        out.put_slice(&self.bytes[self.offset..self.offset + count]);
        self.offset += count;
        Poll::Ready(Ok(()))
    }
}
struct Sink {
    probe: Arc<Probe>,
    park_write: bool,
    park_commit: bool,
    fail_write: bool,
}
impl AsyncWrite for Sink {
    fn poll_write(
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut retained = self.probe.bytes.lock().unwrap();
        if retained.len() >= 3 && self.fail_write {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::PermissionDenied)));
        }
        if retained.len() >= 3
            && self.park_write
            && !self.probe.release_write.load(Ordering::SeqCst)
        {
            self.probe.write_parked.store(true, Ordering::SeqCst);
            // A task must remain driveable while the observer releases the gate.
            drop(retained);
            ctx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let count = bytes.len().min(3);
        retained.extend_from_slice(&bytes[..count]);
        Poll::Ready(Ok(count))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        panic!("resume must not implicitly close the application sink")
    }
}
impl LiveStreamCommitSink for Sink {
    fn poll_commit(
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        receipt: &LiveStreamReceipt,
    ) -> Poll<io::Result<()>> {
        self.probe.commit_polls.fetch_add(1, Ordering::SeqCst);
        if Cx::current().and_then(|cx| cx.cancel_reason()).is_some() {
            self.probe.cancel_polled.store(true, Ordering::SeqCst);
        }
        assert_eq!(
            receipt.prefix.bytes,
            self.probe.bytes.lock().unwrap().len() as u64
        );
        assert_eq!(
            receipt.source_sha256.as_slice(),
            Sha256::digest(&*self.probe.bytes.lock().unwrap()).as_slice()
        );
        if self.park_commit && !self.probe.release_commit.load(Ordering::SeqCst) {
            self.probe.commit_parked.store(true, Ordering::SeqCst);
            ctx.waker().wake_by_ref();
            return Poll::Pending;
        }
        assert_eq!(
            self.probe.commits.fetch_add(1, Ordering::SeqCst),
            0,
            "application commit executed twice"
        );
        Poll::Ready(Ok(()))
    }
}
fn source(probe: &Arc<Probe>, bytes: &'static [u8]) -> Source {
    Source {
        bytes,
        offset: 0,
        probe: Arc::clone(probe),
        fail: false,
    }
}
fn sink(probe: &Arc<Probe>) -> Sink {
    Sink {
        probe: Arc::clone(probe),
        park_write: false,
        park_commit: false,
        fail_write: false,
    }
}

struct RawWire {
    tls: TlsStream<TcpStream>,
    codec: AtpFrameCodec,
    buffer: BytesMut,
}
impl RawWire {
    fn new(tls: TlsStream<TcpStream>) -> Self {
        assert_eq!(tls.alpn_protocol(), Some(RESUMABLE_LIVE_ALPN));
        Self {
            tls,
            codec: AtpFrameCodec::with_max_frame_size(66000),
            buffer: BytesMut::new(),
        }
    }
    async fn accept(listener: &TcpListener) -> Self {
        let (tcp, _) = listener.accept().await.unwrap();
        Self::new(raw_server().accept(tcp).await.unwrap())
    }
    async fn connect(address: std::net::SocketAddr) -> Self {
        let tcp = TcpStream::connect(address).await.unwrap();
        Self::new(raw_client().connect("localhost", tcp).await.unwrap())
    }
    async fn send(&mut self, kind: FrameType, bytes: Vec<u8>) {
        let frame = Frame::new(ProtocolVersion::V0, kind, bytes)
            .unwrap()
            .to_wire_bytes()
            .unwrap();
        self.tls.write_all(&frame).await.unwrap();
        self.tls.flush().await.unwrap();
    }
    async fn receive(&mut self, kind: FrameType) -> Vec<u8> {
        loop {
            if let Some(frame) = self.codec.decode(&mut self.buffer).unwrap() {
                assert_eq!(frame.frame_type(), kind);
                return frame.payload().to_vec();
            }
            let mut bytes = [0; 4096];
            let count = self.tls.read(&mut bytes).await.unwrap();
            assert_ne!(
                count, 0,
                "independent peer did not receive the required frame"
            );
            self.buffer.extend_from_slice(&bytes[..count]);
        }
    }
}

// Independent wire model; no calls to the production private reconciliation helpers.
#[derive(Clone)]
struct Model {
    hello: Vec<u8>,
    prefix: Vec<u8>,
    data: Vec<u8>,
}
impl Model {
    fn new(hello: Vec<u8>) -> Self {
        assert_eq!(hello.len(), 60);
        assert_eq!(&hello[..8], b"ATPRSM01");
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
    fn client() -> Self {
        let mut hello = b"ATPRSM01ATPLIVE1".to_vec();
        hello.extend_from_slice(&[7; 32]);
        hello.extend_from_slice(&8_u32.to_be_bytes());
        hello.extend_from_slice(&1024_u64.to_be_bytes());
        Self::new(hello)
    }
    fn state(&self, complete: bool) -> Vec<u8> {
        let mut bytes = self.hello.clone();
        bytes.extend_from_slice(&self.prefix);
        bytes.extend_from_slice(&Sha256::digest(&self.data));
        bytes.push(u8::from(complete));
        bytes
    }
    fn epoch(&self, data: &[u8]) -> Vec<u8> {
        let mut bytes = self.prefix.clone();
        bytes.extend_from_slice(&Sha256::digest(data));
        bytes.extend_from_slice(data);
        bytes
    }
    fn accept_epoch(&mut self, bytes: &[u8]) {
        assert_eq!(&bytes[..48], self.prefix);
        assert!(!bytes[80..].is_empty());
        assert_eq!(&bytes[48..80], Sha256::digest(&bytes[80..]).as_slice());
        let mut hash = Sha256::new();
        hash.update(b"asupersync.atp.live.epoch.v1");
        hash.update(&self.prefix[16..]);
        hash.update(bytes);
        let epochs = u64::from_be_bytes(self.prefix[..8].try_into().unwrap()) + 1;
        self.data.extend_from_slice(&bytes[80..]);
        self.prefix = epochs.to_be_bytes().to_vec();
        self.prefix
            .extend_from_slice(&(self.data.len() as u64).to_be_bytes());
        self.prefix.extend_from_slice(&hash.finalize());
    }
    fn final_payload(&self) -> Vec<u8> {
        let mut bytes = self.prefix.clone();
        bytes.extend_from_slice(&Sha256::digest(&self.data));
        bytes
    }
}

#[test]
fn native_sessions_finish_and_cached_sender_performs_no_additional_attempt() {
    for workers in [1, 2] {
        run(workers, async {
            let cx = Cx::current().unwrap();
            let tx = sender("allowed");
            let rx = receiver();
            for data in [b"abcdefghIJKLMNOP".as_slice(), b""] {
                let probe = Arc::new(Probe::default());
                let mut incoming = rx
                    .bind_resumable_committing(
                        &cx,
                        "127.0.0.1:0".parse().unwrap(),
                        client_id(),
                        sink(&probe),
                        2,
                    )
                    .await
                    .unwrap();
                let mut outgoing = tx
                    .resumable_reader(&cx, incoming.local_addr().unwrap(), source(&probe, data), 2)
                    .unwrap();
                let (sent, received) = zip(outgoing.send(&cx), incoming.receive(&cx)).await;
                let receipt = sent.outcome.unwrap();
                assert_eq!(receipt, received.outcome.unwrap());
                assert_eq!(*probe.bytes.lock().unwrap(), data);
                assert_eq!(probe.commits.load(Ordering::SeqCst), 1);
                assert_eq!(
                    receipt.source_sha256.as_slice(),
                    Sha256::digest(data).as_slice()
                );
                assert_eq!((tx.active_streams(), rx.active_streams()), (1, 1));
                let cached = outgoing.send(&cx).await;
                assert!(cached.receipt_reused);
                assert_eq!(cached.attempts, 1);
                assert_eq!(cached.outcome.unwrap(), receipt);
                drop(outgoing);
                drop(incoming);
                assert_eq!((tx.active_streams(), rx.active_streams()), (0, 0));
            }
        });
    }
}

#[test]
fn dropped_attempts_resume_after_a_witnessed_partial_write_without_duplicate_bytes() {
    for workers in [1, 2] {
        run(workers, async {
            let cx = Cx::current().unwrap();
            let tx = sender("allowed");
            let rx = receiver();
            let probe = Arc::new(Probe::default());
            let mut output = sink(&probe);
            output.park_write = true;
            let mut incoming = rx
                .bind_resumable_committing(
                    &cx,
                    "127.0.0.1:0".parse().unwrap(),
                    client_id(),
                    output,
                    3,
                )
                .await
                .unwrap();
            let mut outgoing = tx
                .resumable_reader(
                    &cx,
                    incoming.local_addr().unwrap(),
                    source(&probe, b"abcdefghIJKLMNOP"),
                    3,
                )
                .unwrap();
            or(
                async {
                    let premature = zip(outgoing.send(&cx), incoming.receive(&cx)).await;
                    panic!("the partial write must still be parked: {premature:?}");
                },
                witness(&cx, || probe.write_parked.load(Ordering::SeqCst)),
            )
            .await;
            assert_eq!(*probe.bytes.lock().unwrap(), b"abc");
            assert_eq!(incoming.sink_written_bytes(), 3);
            assert_eq!(incoming.flushed_prefix().unwrap().bytes, 0);
            assert_eq!(probe.reads.load(Ordering::SeqCst), 1);
            probe.release_write.store(true, Ordering::SeqCst);
            let (sent, received) = zip(outgoing.send(&cx), incoming.receive(&cx)).await;
            assert_eq!(sent.outcome.unwrap(), received.outcome.unwrap());
            assert_eq!((sent.attempts, received.attempts), (2, 2));
            assert_eq!(*probe.bytes.lock().unwrap(), b"abcdefghIJKLMNOP");
            assert_eq!(
                probe.reads.load(Ordering::SeqCst),
                3,
                "two source epochs plus EOF, no reread"
            );
            assert_eq!(probe.commits.load(Ordering::SeqCst), 1);
        });
    }
}

#[test]
fn sender_reconciles_a_lost_epoch_ack_without_retransmitting_the_accepted_prefix() {
    run(2, async {
        let cx = Cx::current().unwrap();
        let tx = sender("allowed");
        let probe = Arc::new(Probe::default());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut outgoing = tx
            .resumable_reader(
                &cx,
                listener.local_addr().unwrap(),
                source(&probe, b"abcdefghIJKLMNOP"),
                3,
            )
            .unwrap();
        let peer = async {
            let mut wire = RawWire::accept(&listener).await;
            let mut model = Model::new(wire.receive(FrameType::Handshake).await);
            wire.send(FrameType::HandshakeAck, model.state(false)).await;
            model.accept_epoch(&wire.receive(FrameType::ObjectData).await);
            // The complete first epoch arrived; deliberately never send its ACK.
            model
        };
        let (first, mut model) = zip(outgoing.send(&cx), peer).await;
        assert!(first.outcome.is_err());
        assert_eq!(first.retained_epoch_bytes, 8);
        assert_eq!(first.prefix.unwrap().bytes, 0);
        assert_eq!(model.data, b"abcdefgh");
        assert_eq!(probe.reads.load(Ordering::SeqCst), 1);
        let peer = async {
            let mut wire = RawWire::accept(&listener).await;
            assert_eq!(wire.receive(FrameType::Handshake).await, model.hello);
            wire.send(FrameType::HandshakeAck, model.state(false)).await;
            // A retransmission of epoch zero fails the independent sequence check.
            model.accept_epoch(&wire.receive(FrameType::ObjectData).await);
            assert_eq!(model.data, b"abcdefghIJKLMNOP");
            wire.send(FrameType::Control, model.prefix.clone()).await;
            assert_eq!(
                wire.receive(FrameType::ObjectComplete).await,
                model.final_payload()
            );
            wire.send(FrameType::Proof, model.final_payload()).await;
        };
        let (second, ()) = zip(outgoing.send(&cx), peer).await;
        assert_eq!(second.outcome.unwrap().prefix.bytes, 16);
        assert_eq!(probe.reads.load(Ordering::SeqCst), 3);
    });
}

#[test]
fn sender_recovers_a_lost_final_proof_without_reading_the_source_again() {
    run(1, async {
        let cx = Cx::current().unwrap();
        let tx = sender("allowed");
        let probe = Arc::new(Probe::default());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut outgoing = tx
            .resumable_reader(
                &cx,
                listener.local_addr().unwrap(),
                source(&probe, b"abcdefgh"),
                3,
            )
            .unwrap();
        let peer = async {
            let mut wire = RawWire::accept(&listener).await;
            let mut model = Model::new(wire.receive(FrameType::Handshake).await);
            wire.send(FrameType::HandshakeAck, model.state(false)).await;
            model.accept_epoch(&wire.receive(FrameType::ObjectData).await);
            wire.send(FrameType::Control, model.prefix.clone()).await;
            assert_eq!(
                wire.receive(FrameType::ObjectComplete).await,
                model.final_payload()
            );
            model // No Proof: close only after witnessing the actual final frame.
        };
        let (first, model) = zip(outgoing.send(&cx), peer).await;
        assert!(first.outcome.is_err());
        assert!(outgoing.completed_receipt().is_none());
        assert_eq!(probe.reads.load(Ordering::SeqCst), 2);
        let peer = async {
            let mut wire = RawWire::accept(&listener).await;
            assert_eq!(wire.receive(FrameType::Handshake).await, model.hello);
            wire.send(FrameType::HandshakeAck, model.state(true)).await;
            assert_eq!(
                wire.receive(FrameType::ObjectComplete).await,
                model.final_payload()
            );
            wire.send(FrameType::Proof, model.final_payload()).await;
        };
        let (second, ()) = zip(outgoing.send(&cx), peer).await;
        assert_eq!(second.outcome.unwrap().prefix.bytes, 8);
        assert_eq!(probe.reads.load(Ordering::SeqCst), 2);
    });
}

#[test]
fn receiver_retransmits_final_proof_but_never_reexecutes_the_committed_sink() {
    run(2, async {
        let cx = Cx::current().unwrap();
        let rx = receiver();
        let probe = Arc::new(Probe::default());
        let mut incoming = rx
            .bind_resumable_committing(
                &cx,
                "127.0.0.1:0".parse().unwrap(),
                client_id(),
                sink(&probe),
                3,
            )
            .await
            .unwrap();
        let address = incoming.local_addr().unwrap();
        let peer = async {
            let mut model = Model::client();
            let mut wire = RawWire::connect(address).await;
            wire.send(FrameType::Handshake, model.hello.clone()).await;
            assert_eq!(
                wire.receive(FrameType::HandshakeAck).await,
                model.state(false)
            );
            let epoch = model.epoch(b"abcdefgh");
            model.accept_epoch(&epoch);
            wire.send(FrameType::ObjectData, epoch).await;
            assert_eq!(wire.receive(FrameType::Control).await, model.prefix);
            wire.send(FrameType::ObjectComplete, model.final_payload())
                .await;
            witness(&cx, || probe.commits.load(Ordering::SeqCst) == 1).await;
            model // Do not even poll a Proof read on this connection.
        };
        let (first, model) = zip(incoming.receive(&cx), peer).await;
        assert!(first.completed.is_some());
        assert!(incoming.completed_receipt().is_some());
        let peer = async {
            let mut wire = RawWire::connect(address).await;
            wire.send(FrameType::Handshake, model.hello.clone()).await;
            assert_eq!(
                wire.receive(FrameType::HandshakeAck).await,
                model.state(true)
            );
            wire.send(FrameType::ObjectComplete, model.final_payload())
                .await;
            assert_eq!(wire.receive(FrameType::Proof).await, model.final_payload());
        };
        let (second, ()) = zip(incoming.receive(&cx), peer).await;
        assert!(second.receipt_reused);
        assert_eq!(second.outcome.unwrap(), first.completed.unwrap());
        assert_eq!(probe.commits.load(Ordering::SeqCst), 1);
        assert_eq!(probe.commit_polls.load(Ordering::SeqCst), 1);
        assert_eq!(*probe.bytes.lock().unwrap(), b"abcdefgh");
        assert_eq!(second.sink_written_bytes, 8);
    });
}

#[test]
fn another_allowed_certificate_cannot_take_over_the_selected_resume_sink() {
    run(1, async {
        let cx = Cx::current().unwrap();
        let rx = receiver();
        let probe = Arc::new(Probe::default());
        let mut incoming = rx
            .bind_resumable_committing(
                &cx,
                "127.0.0.1:0".parse().unwrap(),
                client_id(),
                sink(&probe),
                3,
            )
            .await
            .unwrap();
        let address = incoming.local_addr().unwrap();
        let bad = sender("unlisted");
        let mut outgoing = bad
            .resumable_reader(&cx, address, source(&probe, b"wrong"), 1)
            .unwrap();
        let (sent, received) = zip(outgoing.send(&cx), incoming.receive(&cx)).await;
        assert!(matches!(received.outcome, Err(ResumeError::PeerIdentity)));
        assert!(sent.outcome.is_err());
        assert_eq!(probe.reads.load(Ordering::SeqCst), 0);
        assert_eq!(probe.commits.load(Ordering::SeqCst), 0);
        assert!(probe.bytes.lock().unwrap().is_empty());
        let good = sender("allowed");
        let mut outgoing = good
            .resumable_reader(&cx, address, source(&probe, b"right"), 1)
            .unwrap();
        let (sent, received) = zip(outgoing.send(&cx), incoming.receive(&cx)).await;
        assert_eq!(sent.outcome.unwrap(), received.outcome.unwrap());
        assert_eq!(*probe.bytes.lock().unwrap(), b"right");
    });
}

#[test]
fn fabricated_resume_state_is_rejected_before_the_source_is_polled() {
    for case in ["offset", "hash", "complete", "flag", "nonce", "trailing"] {
        run(1, async move {
            let cx = Cx::current().unwrap();
            let tx = sender("allowed");
            let probe = Arc::new(Probe::default());
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut outgoing = tx
                .resumable_reader(
                    &cx,
                    listener.local_addr().unwrap(),
                    source(&probe, b"never read"),
                    1,
                )
                .unwrap();
            let peer = async {
                let mut wire = RawWire::accept(&listener).await;
                let model = Model::new(wire.receive(FrameType::Handshake).await);
                let mut state = model.state(false);
                match case {
                    "offset" => state[75] = 1,
                    "hash" => state[108] ^= 1,
                    "complete" => state[140] = 1,
                    "flag" => state[140] = 2,
                    "nonce" => state[16] ^= 1,
                    "trailing" => state.push(0),
                    _ => unreachable!(),
                }
                wire.send(FrameType::HandshakeAck, state).await;
            };
            let (report, ()) = zip(outgoing.send(&cx), peer).await;
            assert!(matches!(report.outcome, Err(ResumeError::Continuity(_))));
            assert!(outgoing.acknowledged_prefix().is_none());
            assert_eq!(probe.reads.load(Ordering::SeqCst), 0);
            let refused = outgoing.send(&cx).await;
            assert!(matches!(
                refused.outcome,
                Err(ResumeError::AttemptsExhausted)
            ));
            assert_eq!(refused.attempts, 1);
        });
    }
}

#[test]
fn terminal_local_errors_do_not_become_automatic_retries_or_successful_eof() {
    for fail_source in [true, false] {
        run(1, async move {
            let cx = Cx::current().unwrap();
            let tx = sender("allowed");
            let rx = receiver();
            let probe = Arc::new(Probe::default());
            let mut output = sink(&probe);
            output.fail_write = !fail_source;
            let mut input = source(&probe, b"abcdefghIJKLMNOP");
            input.fail = fail_source;
            let mut incoming = rx
                .bind_resumable_committing(
                    &cx,
                    "127.0.0.1:0".parse().unwrap(),
                    client_id(),
                    output,
                    3,
                )
                .await
                .unwrap();
            let mut outgoing = tx
                .resumable_reader(&cx, incoming.local_addr().unwrap(), input, 3)
                .unwrap();
            let (sent, received) = zip(outgoing.send(&cx), incoming.receive(&cx)).await;
            assert!(sent.outcome.is_err());
            assert!(received.outcome.is_err());
            assert_eq!(probe.commits.load(Ordering::SeqCst), 0);
            if fail_source {
                assert!(
                    matches!(sent.outcome, Err(ResumeError::Transfer(LiveStreamError::Io(error))) if error.kind() == io::ErrorKind::InvalidData)
                );
                let again = outgoing.send(&cx).await;
                assert!(matches!(again.outcome, Err(ResumeError::LocalFailure)));
                assert_eq!(again.attempts, 1);
                assert_eq!(*probe.bytes.lock().unwrap(), b"abcdefgh");
            } else {
                assert!(
                    matches!(received.outcome, Err(ResumeError::Transfer(LiveStreamError::Io(error))) if error.kind() == io::ErrorKind::PermissionDenied)
                );
                let again = incoming.receive(&cx).await;
                assert!(matches!(again.outcome, Err(ResumeError::LocalFailure)));
                assert_eq!(again.attempts, 1);
                assert_eq!(*probe.bytes.lock().unwrap(), b"abc");
            }
        });
    }
}

#[test]
fn dropping_an_attempt_during_pending_commit_preserves_the_same_commit_operation() {
    run(2, async {
        let cx = Cx::current().unwrap();
        let tx = sender("allowed");
        let rx = receiver();
        let probe = Arc::new(Probe::default());
        let mut output = sink(&probe);
        output.park_commit = true;
        let mut incoming = rx
            .bind_resumable_committing(&cx, "127.0.0.1:0".parse().unwrap(), client_id(), output, 3)
            .await
            .unwrap();
        let mut outgoing = tx
            .resumable_reader(
                &cx,
                incoming.local_addr().unwrap(),
                source(&probe, b"abcdefgh"),
                3,
            )
            .unwrap();
        or(
            async {
                let premature = zip(outgoing.send(&cx), incoming.receive(&cx)).await;
                panic!("commit must still be parked: {premature:?}");
            },
            witness(&cx, || probe.commit_parked.load(Ordering::SeqCst)),
        )
        .await;
        assert_eq!(probe.reads.load(Ordering::SeqCst), 2);
        assert_eq!(probe.commits.load(Ordering::SeqCst), 0);
        probe.release_commit.store(true, Ordering::SeqCst);
        let (sent, received) = zip(outgoing.send(&cx), incoming.receive(&cx)).await;
        assert_eq!(sent.outcome.unwrap(), received.outcome.unwrap());
        assert_eq!(probe.reads.load(Ordering::SeqCst), 2);
        assert_eq!(probe.commits.load(Ordering::SeqCst), 1);
        assert_eq!(*probe.bytes.lock().unwrap(), b"abcdefgh");
    });
}

#[test]
fn attributed_cancellation_drains_commit_then_a_fresh_attempt_recovers_its_proof() {
    run(2, async {
        let cx = Cx::current().unwrap();
        let scope = cx.scope();
        let tx = sender("allowed");
        let rx = receiver();
        let probe = Arc::new(Probe::default());
        let mut output = sink(&probe);
        output.park_commit = true;
        let mut incoming = rx
            .bind_resumable_committing(&cx, "127.0.0.1:0".parse().unwrap(), client_id(), output, 3)
            .await
            .unwrap();
        let mut outgoing = tx
            .resumable_reader(
                &cx,
                incoming.local_addr().unwrap(),
                source(&probe, b"abcdefgh"),
                3,
            )
            .unwrap();
        let mut receiving = cx
            .spawn_in(&scope, move |child| {
                let future: Pin<Box<dyn Future<Output = _> + Send>> = Box::pin(async move {
                    let report = incoming.receive(&child).await;
                    (incoming, report)
                });
                future
            })
            .unwrap();
        let mut sending = cx
            .spawn_in(&scope, move |child| {
                let future: Pin<Box<dyn Future<Output = _> + Send>> = Box::pin(async move {
                    let report = outgoing.send(&child).await;
                    (outgoing, report)
                });
                future
            })
            .unwrap();
        witness(&cx, || probe.commit_parked.load(Ordering::SeqCst)).await;
        let reason = CancelReason::user("cancel retained commit attempt");
        receiving.abort_with_reason(reason.clone());
        // Witness an actual commit poll carrying attributed cancellation before
        // releasing it; a sleep or an arbitrary poll count is not that witness.
        witness(&cx, || probe.cancel_polled.load(Ordering::SeqCst)).await;
        assert!(!receiving.is_finished());
        assert_eq!(rx.active_streams(), 1);
        probe.release_commit.store(true, Ordering::SeqCst);
        let (mut incoming, received) = receiving
            .join(&cx)
            .await
            .expect("acknowledged cancellation retains the session");
        match received.outcome.unwrap_err() {
            ResumeError::Transfer(LiveStreamError::Commit(error)) => match *error {
                LiveStreamCommitError::CommittedWithoutProof { source, .. } => assert!(
                    matches!(*source, LiveStreamError::Cancelled(Some(actual)) if actual == reason)
                ),
                other => panic!("lost commit evidence: {other:?}"),
            },
            other => panic!("lost cancellation attribution: {other:?}"),
        }
        assert!(received.completed.is_some());
        let (mut outgoing, sent) = sending.join(&cx).await.unwrap();
        assert!(sent.outcome.is_err());
        let (sent, received) = zip(outgoing.send(&cx), incoming.receive(&cx)).await;
        assert_eq!(sent.outcome.unwrap(), received.outcome.unwrap());
        assert!(received.receipt_reused);
        assert_eq!(probe.commits.load(Ordering::SeqCst), 1);
        assert_eq!(probe.reads.load(Ordering::SeqCst), 2);
    });
}

#[test]
fn reconnect_cannot_rebind_the_nonce_or_replace_a_partially_written_epoch() {
    run(1, async {
        let cx = Cx::current().unwrap();
        let rx = receiver();
        let probe = Arc::new(Probe::default());
        let mut output = sink(&probe);
        output.park_write = true;
        let mut incoming = rx
            .bind_resumable_committing(&cx, "127.0.0.1:0".parse().unwrap(), client_id(), output, 5)
            .await
            .unwrap();
        let address = incoming.local_addr().unwrap();
        let mut model = Model::client();
        let epoch = model.epoch(b"abcdefgh");
        or(
            async {
                let peer = async {
                    let mut wire = RawWire::connect(address).await;
                    wire.send(FrameType::Handshake, model.hello.clone()).await;
                    assert_eq!(
                        wire.receive(FrameType::HandshakeAck).await,
                        model.state(false)
                    );
                    wire.send(FrameType::ObjectData, epoch.clone()).await;
                    std::future::pending::<()>().await;
                };
                let premature = zip(incoming.receive(&cx), peer).await;
                panic!("partial sink must still be parked: {premature:?}");
            },
            witness(&cx, || probe.write_parked.load(Ordering::SeqCst)),
        )
        .await;
        assert_eq!(incoming.sink_written_bytes(), 3);
        let peer = async {
            let mut wire = RawWire::connect(address).await;
            let mut wrong = model.hello.clone();
            wrong[16] ^= 1;
            wire.send(FrameType::Handshake, wrong).await;
        };
        let (rebound, ()) = zip(incoming.receive(&cx), peer).await;
        assert!(matches!(
            rebound.outcome,
            Err(ResumeError::Continuity("session nonce or offer changed"))
        ));
        let peer = async {
            let mut wire = RawWire::connect(address).await;
            wire.send(FrameType::Handshake, model.hello.clone()).await;
            assert_eq!(
                wire.receive(FrameType::HandshakeAck).await,
                model.state(false)
            );
            wire.send(FrameType::ObjectData, model.epoch(b"abcXXXXX"))
                .await;
        };
        let (replaced, ()) = zip(incoming.receive(&cx), peer).await;
        assert!(matches!(
            replaced.outcome,
            Err(ResumeError::Continuity("partially written epoch changed"))
        ));
        assert_eq!(*probe.bytes.lock().unwrap(), b"abc");
        assert_eq!(incoming.sink_written_bytes(), 3);
        probe.release_write.store(true, Ordering::SeqCst);
        let peer = async {
            let mut wire = RawWire::connect(address).await;
            wire.send(FrameType::Handshake, model.hello.clone()).await;
            assert_eq!(
                wire.receive(FrameType::HandshakeAck).await,
                model.state(false)
            );
            wire.send(FrameType::ObjectData, epoch.clone()).await;
            model.accept_epoch(&epoch);
            assert_eq!(wire.receive(FrameType::Control).await, model.prefix);
            wire.send(FrameType::ObjectComplete, model.final_payload())
                .await;
            assert_eq!(wire.receive(FrameType::Proof).await, model.final_payload());
        };
        let (recovered, ()) = zip(incoming.receive(&cx), peer).await;
        assert!(recovered.outcome.is_ok());
        assert_eq!(recovered.attempts, 4);
        assert_eq!(*probe.bytes.lock().unwrap(), b"abcdefgh");
        assert_eq!(probe.commits.load(Ordering::SeqCst), 1);
    });
}
