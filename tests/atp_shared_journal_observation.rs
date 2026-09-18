//! Shared listener recovery using real private WALs, native runtimes and mTLS.
//! Wire peers do not call the production reconciliation or checkpoint encoders.
//! All test-created files are retained. Threads are joined, never detached.
#![cfg(all(unix, feature = "tls", feature = "test-internals", not(target_arch = "wasm32")))]

use asupersync::Cx;
use asupersync::bytes::BytesMut;
use asupersync::codec::Decoder;
use asupersync::fs::File as AsyncFile;
use asupersync::io::{AsyncRead, AsyncWrite, ReadBuf};
use asupersync::net::atp::protocol::codec::AtpFrameCodec;
use asupersync::net::atp::protocol::frames::{Frame, FrameType, ProtocolVersion};
use asupersync::net::atp::sdk::{AtpSdk, NativeClientAuthorization, NativeClientCertificateId, NativeTlsIdentity, SessionConfig};
use asupersync::net::atp::sdk::native_auth::live::{LiveStreamConfig, LiveStreamError, LiveStreamReceipt, LiveStreamReceiver};
use asupersync::net::atp::sdk::native_auth::live::commit::LiveStreamCommitSink;
use asupersync::net::atp::sdk::native_auth::live::commit::resume::{ResumeError, ResumeReport};
use asupersync::net::atp::sdk::native_auth::live::commit::resume::receiver_journal::{ReceiverCheckpoint, ReceiverCheckpointPhase, ReceiverCheckpointStore};
use asupersync::net::atp::sdk::native_auth::live::commit::resume::receiver_journal::file::{ReceiverFileLimits, ReceiverJournalFile};
use asupersync::net::atp::sdk::native_auth::live::commit::resume::receiver_journal::shared::JournaledSession;
use asupersync::net::atp::sdk::native_auth::live::commit::resume::service::{ResumeServiceConfig, ResumeServiceOutcome, ResumeServiceRejection, ResumeSessionKey};
use asupersync::runtime::{RuntimeBuilder, spawn_blocking_io, yield_now};
use asupersync::types::CancelReason;
use futures_lite::future::or;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::future::{Future, Ready, ready};
use std::io::{self, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const WAIT: Duration = Duration::from_secs(20);
fn certificate(name: &str) -> CertificateDer<'static> {
    let fixture: serde_json::Value = serde_json::from_str(include_str!("fixtures/atp_native_auth_identities.json")).unwrap();
    let pem = if name == "ca" { fixture["ca"].as_str() }
        else { fixture["identities"][name]["certificate"].as_str() }.unwrap();
    CertificateDer::pem_reader_iter(&mut BufReader::new(pem.as_bytes())).next().unwrap().unwrap()
}
fn private_key(name: &str) -> PrivateKeyDer<'static> {
    let fixture: serde_json::Value = serde_json::from_str(include_str!("fixtures/atp_native_auth_identities.json")).unwrap();
    let pem = fixture["identities"][name]["key"].as_str().unwrap();
    PrivateKeyDer::pem_reader_iter(&mut BufReader::new(pem.as_bytes())).next().unwrap().unwrap()
}
fn client(name: &str) -> NativeClientCertificateId {
    NativeClientCertificateId::from_certificate(&certificate(name))
}
fn roots() -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate("ca")).unwrap();
    roots
}
fn receiver() -> LiveStreamReceiver {
    let sdk = AtpSdk::new_in_process(SessionConfig { max_concurrent_transfers: 2, ..SessionConfig::default() });
    let mut config = LiveStreamConfig::default();
    config.epoch_bytes = 8;
    config.max_bytes = 64;
    config.operation_timeout = Duration::from_secs(5);
    sdk.live_stream_receiver(config,
        NativeTlsIdentity::new(vec![certificate("server")], private_key("server")).unwrap(),
        NativeClientAuthorization::new(roots(), [client("allowed"), client("unlisted")]).unwrap(),
    ).unwrap()
}
fn limits() -> ResumeServiceConfig {
    ResumeServiceConfig { max_connections: 2, max_sessions: 2, max_sessions_per_client: 1,
        max_session_keys: 8, max_attempts_per_session: 8 }
}
fn key(name: &str) -> ResumeSessionKey {
    ResumeSessionKey { client: client(name), nonce: [31; 32] }
}
fn directory() -> PathBuf {
    let root = tempfile::tempdir().unwrap().keep();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    root
}
fn paths(root: &Path, name: &str) -> (PathBuf, PathBuf) {
    (root.join(format!("{name}.wal")), root.join(format!("{name}.data")))
}
fn run<T: Send + 'static>(workers: usize, future: impl Future<Output = T> + Send + 'static) -> T {
    let builder = if workers == 1 { RuntimeBuilder::current_thread() }
        else { RuntimeBuilder::multi_thread().worker_threads(workers).with_sharded_state(true) };
    let runtime = builder.blocking_threads(1, 2).build().unwrap();
    let future: Pin<Box<dyn Future<Output = T> + Send>> = Box::pin(async move {
        let cx = Cx::current().unwrap();
        asupersync::time::timeout(cx.now(), WAIT, future).await.expect("shared journal deadline")
    });
    let result = runtime.block_on(runtime.handle().spawn(future));
    let started = Instant::now();
    while !runtime.is_quiescent() {
        assert!(started.elapsed() < WAIT);
        runtime.block_on(yield_now());
    }
    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
    assert!(runtime.shutdown_timeout(Duration::from_secs(5)));
    result
}
async fn witness(flag: &AtomicBool) {
    while !flag.load(Ordering::Acquire) { yield_now().await; }
}
struct PeerJob(Option<JoinHandle<()>>);
impl PeerJob {
    fn start(f: impl FnOnce() + Send + 'static) -> Self { Self(Some(thread::spawn(f))) }
    fn join(mut self) { self.0.take().unwrap().join().unwrap(); }
}
impl Drop for PeerJob {
    fn drop(&mut self) {
        if let Some(thread) = self.0.take() { let _ = thread.join(); }
    }
}

struct Peer {
    tls: rustls::StreamOwned<rustls::ClientConnection, TcpStream>,
    codec: AtpFrameCodec,
    buffer: BytesMut,
}
impl Peer {
    fn connect(address: SocketAddr, name: &str) -> Self {
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13]).unwrap()
            .with_root_certificates(roots())
            .with_client_auth_cert(vec![certificate(name)], private_key(name)).unwrap();
        config.alpn_protocols = vec![b"atp-live-resume/1".to_vec()];
        config.resumption = rustls::client::Resumption::disabled();
        let tcp = TcpStream::connect_timeout(&address, WAIT).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
        tcp.set_write_timeout(Some(Duration::from_secs(8))).unwrap();
        let connection = rustls::ClientConnection::new(Arc::new(config), ServerName::try_from("localhost").unwrap()).unwrap();
        Self { tls: rustls::StreamOwned::new(connection, tcp), codec: AtpFrameCodec::with_max_frame_size(65536), buffer: BytesMut::new() }
    }
    fn send(&mut self, kind: FrameType, payload: Vec<u8>) {
        let bytes = Frame::new(ProtocolVersion::V0, kind, payload).unwrap().to_wire_bytes().unwrap();
        self.tls.write_all(&bytes).unwrap();
        self.tls.flush().unwrap();
    }
    fn read(&mut self, kind: FrameType) -> io::Result<Vec<u8>> {
        loop {
            if let Some(frame) = self.codec.decode(&mut self.buffer).map_err(io::Error::other)? {
                assert_eq!(frame.frame_type(), kind);
                return Ok(frame.payload().to_vec());
            }
            let mut bytes = [0; 4096];
            let count = self.tls.read(&mut bytes)?;
            if count == 0 { return Err(io::Error::from(io::ErrorKind::UnexpectedEof)); }
            self.buffer.extend_from_slice(&bytes[..count]);
            assert!(self.buffer.len() < 65536);
        }
    }
    fn hello(&mut self) -> io::Result<Vec<u8>> {
        let mut offered = b"ATPRSM01ATPLIVE1".to_vec();
        offered.extend_from_slice(&[31; 32]);
        offered.extend_from_slice(&8_u32.to_be_bytes());
        offered.extend_from_slice(&64_u64.to_be_bytes());
        self.send(FrameType::Handshake, offered.clone());
        let state = self.read(FrameType::HandshakeAck)?;
        assert_eq!(state.len(), 141);
        assert_eq!(&state[..60], offered);
        Ok(state)
    }
    fn epoch(&mut self, prefix: &[u8], bytes: &[u8]) {
        let mut payload = prefix.to_vec();
        payload.extend_from_slice(&Sha256::digest(bytes));
        payload.extend_from_slice(bytes);
        self.send(FrameType::ObjectData, payload);
    }
    fn finish(&mut self, prefix: &[u8], bytes: &[u8]) {
        let mut final_value = prefix.to_vec();
        final_value.extend_from_slice(&Sha256::digest(bytes));
        self.send(FrameType::ObjectComplete, final_value.clone());
        assert_eq!(self.read(FrameType::Proof).unwrap(), final_value);
    }
}

#[derive(Default)]
struct Probe {
    bytes: AtomicUsize,
    commits: AtomicUsize,
    parked: AtomicBool,
    reads: AtomicUsize,
}
struct Sink {
    file: AsyncFile,
    path: PathBuf,
    written: u64,
    stop_at: Option<u64>,
    probe: Arc<Probe>,
    commit: Option<Pin<Box<dyn Future<Output = io::Result<()>> + Send>>>,
}
impl Sink {
    fn open(path: &Path, stop_at: Option<u64>, probe: Arc<Probe>) -> Self {
        let file = OpenOptions::new().read(true).append(true).open(path).unwrap();
        let written = file.metadata().unwrap().len();
        Self { file: AsyncFile::from_std(file), path: path.to_owned(), written, stop_at, probe, commit: None }
    }
}
impl AsyncWrite for Sink {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let maximum = this.stop_at.map_or(bytes.len(), |end| end.saturating_sub(this.written) as usize).min(bytes.len());
        if maximum == 0 {
            this.probe.parked.store(true, Ordering::Release);
            return Poll::Pending;
        }
        match Pin::new(&mut this.file).poll_write(cx, &bytes[..maximum]) {
            Poll::Ready(Ok(count)) => {
                this.written += count as u64;
                this.probe.bytes.fetch_add(count, Ordering::Relaxed);
                Poll::Ready(Ok(count))
            }
            result => result,
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().file).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::from(io::ErrorKind::Unsupported)))
    }
}
impl LiveStreamCommitSink for Sink {
    fn poll_commit(self: Pin<&mut Self>, cx: &mut Context<'_>, receipt: &LiveStreamReceipt) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.commit.is_none() {
            this.probe.commits.fetch_add(1, Ordering::Relaxed);
            let path = this.path.clone();
            let receipt = receipt.clone();
            this.commit = Some(Box::pin(async move {
                spawn_blocking_io(move || {
                    let bytes = std::fs::read(&path)?;
                    assert_eq!(bytes.len() as u64, receipt.prefix.bytes);
                    assert_eq!(Sha256::digest(&bytes).as_slice(), receipt.source_sha256);
                    std::fs::File::open(path)?.sync_all()
                }).await
            }));
        }
        this.commit.as_mut().unwrap().as_mut().poll(cx)
    }
}
struct Reader { file: AsyncFile, probe: Arc<Probe> }
impl AsyncRead for Reader {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, out: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.probe.reads.fetch_add(1, Ordering::Relaxed);
        Pin::new(&mut this.file).poll_read(cx, out)
    }
}
#[derive(Clone, Default)]
struct Catalog {
    entries: Arc<Mutex<BTreeMap<ResumeSessionKey, JournaledSession<Sink>>>>,
    calls: Arc<AtomicUsize>,
}
impl Catalog {
    fn put(&self, key: ResumeSessionKey, init: JournaledSession<Sink>) {
        assert!(self.entries.lock().unwrap().insert(key, init).is_none());
    }
    fn factory(&self) -> impl Fn(Cx, ResumeSessionKey) -> Ready<io::Result<JournaledSession<Sink>>> + Clone + Send + Sync + 'static {
        let entries = Arc::clone(&self.entries);
        let calls = Arc::clone(&self.calls);
        move |_cx, key| {
            calls.fetch_add(1, Ordering::Relaxed);
            ready(entries.lock().unwrap().remove(&key).ok_or_else(|| io::Error::from(io::ErrorKind::PermissionDenied)))
        }
    }
}
fn fresh(root: &Path, name: &str, stop_at: Option<u64>, snapshots: u32, probe: Arc<Probe>) -> JournaledSession<Sink> {
    let (wal, data) = paths(root, name);
    let journal = ReceiverJournalFile::create_new(&wal, &data, ReceiverFileLimits {
        max_data_bytes: 64, max_snapshots: snapshots, max_journal_bytes: 65536,
    }).unwrap();
    let sink = Sink::open(&data, stop_at, probe);
    JournaledSession::new(sink, journal)
}
fn restored(root: &Path, name: &str, probe: Arc<Probe>) -> JournaledSession<Sink> {
    let (wal, data) = paths(root, name);
    let journal = ReceiverJournalFile::open_existing(&wal, &data).unwrap();
    let saved = journal.checkpoint().unwrap();
    let sink = Sink::open(&data, None, Arc::clone(&probe));
    let retained = Reader { file: AsyncFile::from_std(std::fs::File::open(data).unwrap()), probe };
    JournaledSession::restore(sink, journal, retained, saved)
}
fn transfer(outcome: ResumeServiceOutcome) -> ResumeReport {
    match outcome { ResumeServiceOutcome::Transfer(report) => report, other => panic!("unexpected outcome: {other:?}") }
}

#[test]
fn two_clients_restore_partial_sessions_on_one_listener_without_rewriting_surviving_bytes() {
    for workers in [1, 2] {
        let root = directory();
        let catalog = Catalog::default();
        let blocked = Arc::new(Probe::default());
        catalog.put(key("allowed"), fresh(&root, "allowed", None, 32, Arc::new(Probe::default())));
        catalog.put(key("unlisted"), fresh(&root, "unlisted", Some(11), 32, Arc::clone(&blocked)));
        let address = run(workers, async move {
            let cx = Cx::current().unwrap();
            let scope = cx.scope();
            let authority = receiver();
            let mut config = limits(); config.max_attempts_per_session = 4;
            let mut service = authority.bind_resumable_service::<Sink>(&cx, "127.0.0.1:0".parse().unwrap(), config).await.unwrap();
            let address = service.local_addr();
            let a = PeerJob::start(move || {
                let mut peer = Peer::connect(address, "allowed");
                let state = peer.hello().unwrap();
                peer.epoch(&state[60..108], b"abcdefgh");
                assert_eq!(peer.read(FrameType::Control).unwrap().len(), 48);
            });
            let b = PeerJob::start(move || {
                let mut peer = Peer::connect(address, "unlisted");
                let state = peer.hello().unwrap();
                peer.epoch(&state[60..108], b"qrstuvwx");
                let prefix = peer.read(FrameType::Control).unwrap();
                peer.epoch(&prefix, b"yzABCDEF");
                assert!(peer.read(FrameType::Control).is_err());
            });
            let mut reports = BTreeMap::new();
            loop {
                let completion = or(
                    async { Some(service.next_journaled(&cx, &scope, catalog.factory()).await.unwrap().unwrap()) },
                    async { witness(&blocked.parked).await; None },
                ).await;
                match completion {
                    Some(completion) => { reports.insert(completion.session.unwrap(), transfer(completion.outcome)); }
                    None => break,
                }
            }
            assert_eq!(blocked.bytes.load(Ordering::Relaxed), 11);
            let reason = CancelReason::user("shared journal partial-write boundary");
            assert_eq!(service.revoke_client(client("unlisted"), reason.clone()).unwrap().signalled_connections, 1);
            while reports.len() < 2 {
                let completion = service.next_journaled(&cx, &scope, catalog.factory()).await.unwrap().unwrap();
                reports.insert(completion.session.unwrap(), transfer(completion.outcome));
            }
            let report = &reports[&key("unlisted")];
            assert!(matches!(&report.outcome,
                Err(ResumeError::Transfer(LiveStreamError::Cancelled(Some(actual)))) if actual == &reason));
            assert_eq!(report.prefix.as_ref().unwrap().bytes, 8);
            assert_eq!(report.sink_written_bytes, 11);
            assert_eq!(report.attempts, 1);
            assert_eq!(catalog.calls.load(Ordering::Relaxed), 2);
            assert_eq!(service.resident_sessions(), 2);
            assert_eq!(authority.active_streams(), 2);
            assert!(service.drain_next().await.is_none());
            assert!(service.is_drained());
            assert_eq!(authority.active_streams(), 0);
            a.join(); b.join();
            address
        });
        let mut original = BTreeMap::new();
        for (name, bytes) in [("allowed", b"abcdefgh".as_slice()), ("unlisted", b"qrstuvwxyzA".as_slice())] {
            let (wal, data) = paths(&root, name);
            assert_eq!(std::fs::read(&data).unwrap(), bytes);
            let inode = std::fs::metadata(&data).unwrap();
            original.insert(name, ((inode.dev(), inode.ino()), std::fs::read(wal).unwrap()));
        }
        for committed_only in [false, true] {
            let catalog = Catalog::default();
            let a_probe = Arc::new(Probe::default());
            let b_probe = Arc::new(Probe::default());
            catalog.put(key("allowed"), restored(&root, "allowed", Arc::clone(&a_probe)));
            catalog.put(key("unlisted"), restored(&root, "unlisted", Arc::clone(&b_probe)));
            run(workers, async move {
                let cx = Cx::current().unwrap();
                let scope = cx.scope();
                let authority = receiver();
                // The service has reserved every SDK credit. Restoration must
                // use that reservation rather than asking for another one.
                let mut service = authority.bind_resumable_service::<Sink>(&cx, address, limits()).await.unwrap();
                assert_eq!(authority.active_streams(), 2);
                let jobs: Vec<_> = [("allowed", b"abcdefghijklmnop".as_slice()), ("unlisted", b"qrstuvwxyzABCDEF".as_slice())]
                    .into_iter().map(|(name, bytes)| PeerJob::start(move || {
                        let mut peer = Peer::connect(address, name);
                        let state = peer.hello().unwrap();
                        assert_eq!(state[140], u8::from(committed_only));
                        let prefix = if committed_only {
                            state[60..108].to_vec()
                        } else {
                            assert_eq!(u64::from_be_bytes(state[68..76].try_into().unwrap()), 8);
                            assert_eq!(&state[108..140], Sha256::digest(&bytes[..8]).as_slice());
                            peer.epoch(&state[60..108], &bytes[8..]);
                            peer.read(FrameType::Control).unwrap()
                        };
                        peer.finish(&prefix, bytes);
                    })).collect();
                for _ in 0..2 {
                    let completion = service.next_journaled(&cx, &scope, catalog.factory()).await.unwrap().unwrap();
                    let report = transfer(completion.outcome);
                    assert!(report.outcome.is_ok());
                    assert_eq!(report.sink_written_bytes, 16);
                    assert_eq!(report.attempts, if committed_only { 3 } else { 2 });
                    assert_eq!(report.receipt_reused, committed_only);
                }
                assert_eq!(catalog.calls.load(Ordering::Relaxed), 2);
                assert_eq!(a_probe.bytes.load(Ordering::Relaxed), if committed_only { 0 } else { 8 });
                assert_eq!(b_probe.bytes.load(Ordering::Relaxed), if committed_only { 0 } else { 5 });
                assert_eq!(a_probe.commits.load(Ordering::Relaxed), usize::from(!committed_only));
                assert_eq!(b_probe.commits.load(Ordering::Relaxed), usize::from(!committed_only));
                assert!(service.drain_next().await.is_none());
                assert!(service.is_drained());
                assert_eq!(authority.active_streams(), 0);
                for job in jobs { job.join(); }
            });
        }
        for (name, bytes) in [("allowed", b"abcdefghijklmnop".as_slice()), ("unlisted", b"qrstuvwxyzABCDEF".as_slice())] {
            let (wal, data) = paths(&root, name);
            assert_eq!(std::fs::read(&data).unwrap(), bytes);
            let inode = std::fs::metadata(&data).unwrap();
            assert_eq!((inode.dev(), inode.ino()), original[name].0);
            assert!(std::fs::read(&wal).unwrap().starts_with(&original[name].1));
            let saved = ReceiverJournalFile::open_existing(&wal, &data).unwrap().checkpoint().unwrap();
            assert_eq!(saved.maximum_attempts(), 4);
            assert_eq!(saved.attempts(), 3);
            assert_eq!(saved.committed_receipt().unwrap().source_sha256, Sha256::digest(bytes).as_slice());
        }
        assert_eq!(std::fs::read_dir(root).unwrap().count(), 4);
    }
}

#[test]
fn changing_the_next_api_cannot_remove_a_retained_sessions_journal_barriers() {
    let root = directory();
    let catalog = Catalog::default();
    let probe = Arc::new(Probe::default());
    catalog.put(key("allowed"), fresh(&root, "allowed", None, 1, Arc::clone(&probe)));
    run(1, async move {
        let cx = Cx::current().unwrap(); let scope = cx.scope(); let authority = receiver();
        let mut service = authority.bind_resumable_service::<Sink>(&cx, "127.0.0.1:0".parse().unwrap(), limits()).await.unwrap();
        let address = service.local_addr();
        let first = PeerJob::start(move || { Peer::connect(address, "allowed").hello().unwrap(); });
        let result = service.next_journaled(&cx, &scope, catalog.factory()).await.unwrap().unwrap();
        assert!(transfer(result.outcome).outcome.is_err()); first.join();
        let second = PeerJob::start(move || { assert!(Peer::connect(address, "allowed").hello().is_err()); });
        let replacements = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&replacements);
        let result = service.next(&cx, &scope, move |_, _| {
            counted.fetch_add(1, Ordering::Relaxed);
            ready(Err::<Sink, _>(io::Error::other("replacement factory ran")))
        }).await.unwrap().unwrap();
        let report = transfer(result.outcome);
        match report.outcome {
            Err(ResumeError::ReceiverJournal(error)) => {
                assert!(!error.stored);
                assert_eq!(error.source.unwrap().kind(), io::ErrorKind::StorageFull);
            }
            other => panic!("journal limit was bypassed: {other:?}"),
        }
        assert_eq!(probe.bytes.load(Ordering::Relaxed), 0);
        assert_eq!(catalog.calls.load(Ordering::Relaxed), 1);
        assert_eq!(replacements.load(Ordering::Relaxed), 0);
        assert!(service.drain_next().await.is_none()); second.join();
    });
    let (wal, data) = paths(&root, "allowed");
    assert_eq!(std::fs::metadata(&data).unwrap().len(), 0);
    assert_eq!(ReceiverJournalFile::open_existing(&wal, &data).unwrap().checkpoint().unwrap().attempts(), 1);
}

#[derive(Default)]
struct Gate { open: AtomicBool, parked: AtomicBool, waker: Mutex<Option<Waker>> }
impl Gate {
    fn release(&self) {
        self.open.store(true, Ordering::Release);
        let waker = self.waker.lock().unwrap().take();
        if let Some(waker) = waker { waker.wake(); }
    }
}
struct GatedJournal { inner: ReceiverJournalFile, gate: Arc<Gate> }
impl ReceiverCheckpointStore for GatedJournal {
    fn poll_store(self: Pin<&mut Self>, cx: &mut Context<'_>, checkpoint: &ReceiverCheckpoint) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if checkpoint.pending_bytes() != 0 {
            let mut slot = this.gate.waker.lock().unwrap();
            if !this.gate.open.load(Ordering::Acquire) {
                *slot = Some(cx.waker().clone());
                this.gate.parked.store(true, Ordering::Release);
                return Poll::Pending;
            }
        }
        Pin::new(&mut this.inner).poll_store(cx, checkpoint)
    }
}

#[test]
fn revoked_shared_worker_drains_its_started_journal_before_releasing_the_connection() {
    for workers in [1, 2] {
        let root = directory(); let (wal, data) = paths(&root, "allowed");
        let journal = ReceiverJournalFile::create_new(&wal, &data, ReceiverFileLimits {
            max_data_bytes: 64, max_snapshots: 16, max_journal_bytes: 65536,
        }).unwrap();
        let observer = journal.observer();
        let probe = Arc::new(Probe::default()); let gate = Arc::new(Gate::default());
        let catalog = Catalog::default();
        catalog.put(key("allowed"), JournaledSession::new(
            Sink::open(&data, None, Arc::clone(&probe)),
            GatedJournal { inner: journal, gate: Arc::clone(&gate) },
        ));
        run(workers, async move {
            let cx = Cx::current().unwrap(); let scope = cx.scope(); let authority = receiver();
            let mut service = authority.bind_resumable_service::<Sink>(&cx, "127.0.0.1:0".parse().unwrap(), limits()).await.unwrap();
            let address = service.local_addr();
            let peer = PeerJob::start(move || {
                let mut peer = Peer::connect(address, "allowed"); let state = peer.hello().unwrap();
                peer.epoch(&state[60..108], b"abcdefgh");
                assert!(peer.read(FrameType::Control).is_err());
            });
            let ended = or(
                async { Some(service.next_journaled(&cx, &scope, catalog.factory()).await) },
                async { witness(&gate.parked).await; None },
            ).await;
            assert!(ended.is_none());
            let before = observer.checkpoint().unwrap();
            assert_eq!(before.prefix().bytes, 0);
            assert_eq!(before.pending_bytes(), 0);
            let reason = CancelReason::user("shared journal persistence revocation");
            service.revoke_client(client("allowed"), reason.clone()).unwrap();
            let premature = or(
                async { Some(service.next_journaled(&cx, &scope, catalog.factory()).await) },
                async { for _ in 0..16 { yield_now().await; } None },
            ).await;
            assert!(premature.is_none());
            assert_eq!(service.in_flight(), 1);
            assert_eq!(authority.active_streams(), 2);
            assert_eq!(probe.bytes.load(Ordering::Relaxed), 0);
            gate.release();
            let completion = service.next_journaled(&cx, &scope, catalog.factory()).await.unwrap().unwrap();
            let report = transfer(completion.outcome);
            match report.outcome {
                Err(ResumeError::ReceiverJournal(error)) => {
                    assert!(error.stored);
                    assert!(error.source.is_none());
                    assert!(matches!(error.interruption.as_deref(),
                        Some(LiveStreamError::Cancelled(Some(actual))) if actual == &reason));
                }
                other => panic!("lost persistence outcome: {other:?}"),
            }
            assert_eq!(report.sink_written_bytes, 0);
            assert!(report.completed.is_none());
            let durable = observer.checkpoint().unwrap();
            assert_eq!(durable.pending_bytes(), 8);
            assert!(durable.committed_receipt().is_none());
            assert!(service.drain_next().await.is_none());
            assert_eq!(authority.active_streams(), 0);
            assert_eq!(observer.checkpoint().unwrap_err().kind(), io::ErrorKind::NotConnected);
            peer.join();
        });
        assert_eq!(std::fs::metadata(&data).unwrap().len(), 0);
        assert_eq!(ReceiverJournalFile::open_existing(&wal, &data).unwrap().checkpoint().unwrap().pending_bytes(), 8);
    }
}

#[test]
fn invalid_restoration_is_tombstoned_without_reads_for_wrong_identity_or_policy() {
    for variant in ["client", "data", "attempts"] {
        let root = directory();
        let catalog = Catalog::default();
        catalog.put(key("allowed"), fresh(&root, "allowed", None, 32, Arc::new(Probe::default())));
        run(1, async move {
            let cx = Cx::current().unwrap(); let scope = cx.scope(); let authority = receiver();
            let mut service = authority.bind_resumable_service::<Sink>(&cx, "127.0.0.1:0".parse().unwrap(), limits()).await.unwrap();
            let address = service.local_addr();
            let peer = PeerJob::start(move || {
                let mut peer = Peer::connect(address, "allowed"); let state = peer.hello().unwrap();
                peer.epoch(&state[60..108], b"abcdefgh"); peer.read(FrameType::Control).unwrap();
            });
            let report = transfer(service.next_journaled(&cx, &scope, catalog.factory()).await.unwrap().unwrap().outcome);
            assert_eq!(report.prefix.unwrap().bytes, 8);
            assert!(report.completed.is_none());
            assert!(service.drain_next().await.is_none()); peer.join();
        });
        let (wal, data) = paths(&root, "allowed");
        let before = std::fs::read(&wal).unwrap();
        if variant == "data" {
            let mut file = OpenOptions::new().write(true).open(&data).unwrap();
            file.write_all(b"X").unwrap(); file.sync_all().unwrap();
        }
        let expected_data = std::fs::read(&data).unwrap();
        let probe = Arc::new(Probe::default());
        let catalog = Catalog::default();
        let peer_name = if variant == "client" { "unlisted" } else { "allowed" };
        catalog.put(key(peer_name), restored(&root, "allowed", Arc::clone(&probe)));
        run(2, async move {
            let cx = Cx::current().unwrap(); let scope = cx.scope(); let authority = receiver();
            let mut config = limits();
            if variant == "attempts" { config.max_attempts_per_session = 3; }
            let mut service = authority.bind_resumable_service::<Sink>(&cx, "127.0.0.1:0".parse().unwrap(), config).await.unwrap();
            let address = service.local_addr();
            for repeated in [false, true] {
                let peer = PeerJob::start(move || {
                    assert!(Peer::connect(address, peer_name).hello().is_err());
                });
                let completion = service.next_journaled(&cx, &scope, catalog.factory()).await.unwrap().unwrap();
                match (repeated, variant, completion.outcome) {
                    (true, _, ResumeServiceOutcome::Rejected(ResumeServiceRejection::Retired)) => {}
                    (false, "client", ResumeServiceOutcome::Rejected(ResumeServiceRejection::Factory(
                        LiveStreamError::Configuration("receiver journal does not match authenticated session key"),
                    ))) => {}
                    (false, "attempts", ResumeServiceOutcome::Rejected(ResumeServiceRejection::Factory(
                        LiveStreamError::Configuration("receiver journal exceeds shared service policy"),
                    ))) => {}
                    (false, "data", ResumeServiceOutcome::Rejected(ResumeServiceRejection::Factory(
                        LiveStreamError::Io(error),
                    ))) => assert_eq!(error.kind(), io::ErrorKind::InvalidData),
                    other => panic!("wrong restoration result: {other:?}"),
                }
                assert_eq!(catalog.calls.load(Ordering::Relaxed), 1);
                assert_eq!(service.resident_sessions(), 0);
                peer.join();
            }
            assert_eq!(probe.bytes.load(Ordering::Relaxed), 0);
            assert_eq!(probe.commits.load(Ordering::Relaxed), 0);
            if variant == "data" { assert!(probe.reads.load(Ordering::Relaxed) > 0); }
            else { assert_eq!(probe.reads.load(Ordering::Relaxed), 0); }
            assert!(service.drain_next().await.is_none());
            assert_eq!(authority.active_streams(), 0);
        });
        assert_eq!(std::fs::read(&wal).unwrap(), before);
        assert_eq!(std::fs::read(&data).unwrap(), expected_data);
    }
}

#[test]
fn built_in_file_pairs_recover_on_a_shared_port_without_an_application_sink_adapter() {
    for workers in [1, 2] {
        let root = directory();
        let mut identities = BTreeMap::new();
        let mut original_history = BTreeMap::new();
        for round in 0..3 {
            let mut sessions = BTreeMap::new();
            let mut observers = BTreeMap::new();
            for name in ["allowed", "unlisted"] {
                let (wal, data) = paths(&root, name);
                let journal = if round == 0 {
                    let journal = ReceiverJournalFile::create_new(&wal, &data, ReceiverFileLimits {
                        max_data_bytes: 64, max_snapshots: 32, max_journal_bytes: 65536,
                    }).unwrap();
                    let inode = std::fs::metadata(&data).unwrap();
                    identities.insert(name, (inode.dev(), inode.ino()));
                    journal
                } else {
                    ReceiverJournalFile::open_existing(&wal, &data).unwrap()
                };
                // This must still be the exclusively held original pair before
                // any factory or runtime starts driving it.
                let contender = OpenOptions::new().read(true).write(true).open(&data).unwrap();
                assert!(contender.try_lock().is_err());
                observers.insert(key(name), journal.observer());
                sessions.insert(key(name), journal);
            }
            let sessions = Arc::new(Mutex::new(sessions));
            // The address is handed back by the first real bind, never guessed.
            let requested = if round == 0 {
                "127.0.0.1:0".parse().unwrap()
            } else {
                // The file is public test metadata, retained rather than deleted.
                std::fs::read_to_string(root.join("endpoint")).unwrap().parse().unwrap()
            };
            let address = run(workers, async move {
                let cx = Cx::current().unwrap();
                let scope = cx.scope();
                let authority = receiver();
                let calls = Arc::new(AtomicUsize::new(0));
                let counted = Arc::clone(&calls);
                let factory = move |_: Cx, key| {
                    let sessions = Arc::clone(&sessions);
                    let counted = Arc::clone(&counted);
                    async move {
                        counted.fetch_add(1, Ordering::Relaxed);
                        let journal = sessions.lock().unwrap().remove(&key)
                            .ok_or_else(|| io::Error::from(io::ErrorKind::PermissionDenied))?;
                        journal.into_service_session().await
                    }
                };
                let mut config = limits();
                if round == 0 { config.max_attempts_per_session = 4; }
                let mut service = authority.bind_resumable_service::<_>(
                    &cx, requested, config,
                ).await.unwrap();
                let address = service.local_addr();
                assert_eq!(authority.active_streams(), 2);
                let jobs: Vec<_> = [
                    ("allowed", b"abcdefghijklmnop".as_slice()),
                    ("unlisted", b"".as_slice()),
                ].into_iter().map(|(name, bytes)| PeerJob::start(move || {
                    let mut peer = Peer::connect(address, name);
                    let state = peer.hello().unwrap();
                    assert_eq!(state[140], u8::from(round == 2));
                    let mut prefix = state[60..108].to_vec();
                    let position = u64::from_be_bytes(prefix[8..16].try_into().unwrap());
                    let expected = if round == 0 || bytes.is_empty() { 0 }
                        else if round == 1 { 8 } else { 16 };
                    assert_eq!(position, expected);
                    assert_eq!(&state[108..140], Sha256::digest(&bytes[..expected as usize]).as_slice());
                    if !bytes.is_empty() && round < 2 {
                        let epoch = if round == 0 { &bytes[..8] } else { &bytes[8..] };
                        peer.epoch(&prefix, epoch);
                        prefix = peer.read(FrameType::Control).unwrap();
                    }
                    if round != 0 { peer.finish(&prefix, bytes); }
                })).collect();
                for _ in 0..2 {
                    let completion = service.next_journaled(&cx, &scope, factory.clone()).await.unwrap().unwrap();
                    let name = if completion.session.unwrap() == key("allowed") { "allowed" } else { "unlisted" };
                    let report = transfer(completion.outcome);
                    let checkpoint = observers[&key(name)].checkpoint().unwrap();
                    assert_eq!(checkpoint.attempts(), round + 1);
                    assert_eq!(checkpoint.maximum_attempts(), 4);
                    assert_eq!(checkpoint.committed_receipt().is_some(), round != 0);
                    assert_eq!(report.attempts, round + 1);
                    assert_eq!(report.receipt_reused, round == 2);
                    assert_eq!(report.sink_written_bytes,
                        if name == "unlisted" { 0 } else if round == 0 { 8 } else { 16 });
                    if round == 0 {
                        assert!(report.outcome.is_err());
                        assert!(report.completed.is_none());
                    } else {
                        let receipt = report.outcome.unwrap();
                        let expected = if name == "allowed" { b"abcdefghijklmnop".as_slice() } else { b"".as_slice() };
                        assert_eq!(receipt.source_sha256, Sha256::digest(expected).as_slice());
                        assert_eq!(report.completed.as_ref(), Some(&receipt));
                    }
                }
                assert_eq!(calls.load(Ordering::Relaxed), 2);
                assert_eq!(service.resident_sessions(), 2);
                assert!(service.drain_next().await.is_none());
                assert!(service.is_drained());
                assert_eq!(authority.active_streams(), 0);
                for observer in observers.values() {
                    assert_eq!(observer.checkpoint().unwrap_err().kind(), io::ErrorKind::NotConnected);
                }
                for job in jobs { job.join(); }
                address
            });
            if round == 0 {
                let mut endpoint = OpenOptions::new().write(true).create_new(true).open(root.join("endpoint")).unwrap();
                write!(endpoint, "{address}").unwrap();
            }
            for name in ["allowed", "unlisted"] {
                let (wal, data) = paths(&root, name);
                let expected = if name == "unlisted" { b"".as_slice() }
                    else if round == 0 { b"abcdefgh".as_slice() } else { b"abcdefghijklmnop".as_slice() };
                assert_eq!(std::fs::read(&data).unwrap(), expected);
                let inode = std::fs::metadata(&data).unwrap();
                assert_eq!((inode.dev(), inode.ino()), identities[name]);
                let saved = ReceiverJournalFile::open_existing(&wal, &data).unwrap().checkpoint().unwrap();
                assert_eq!(saved.attempts(), round + 1);
                assert_eq!(saved.maximum_attempts(), 4);
                assert_eq!(saved.committed_receipt().is_some(), round != 0);
                let history = std::fs::read(&wal).unwrap();
                if round == 0 { original_history.insert(name, history); }
                else { assert!(history.starts_with(&original_history[name])); }
            }
        }
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 5);
    }
}

#[test]
fn built_in_shared_restore_does_not_trust_file_handoff_as_content_validation() {
    let root = directory();
    let (wal, data) = paths(&root, "allowed");
    let journal = ReceiverJournalFile::create_new(&wal, &data, ReceiverFileLimits {
        max_data_bytes: 64, max_snapshots: 32, max_journal_bytes: 65536,
    }).unwrap();
    let catalog = Arc::new(Mutex::new(BTreeMap::from([(key("allowed"), journal)])));
    run(1, async move {
        let cx = Cx::current().unwrap(); let scope = cx.scope(); let authority = receiver();
        let factory = move |_: Cx, key| {
            let catalog = Arc::clone(&catalog);
            async move {
                let journal = catalog.lock().unwrap().remove(&key)
                    .ok_or_else(|| io::Error::from(io::ErrorKind::PermissionDenied))?;
                journal.into_service_session().await
            }
        };
        let mut service = authority.bind_resumable_service::<_>(
            &cx, "127.0.0.1:0".parse().unwrap(), limits(),
        ).await.unwrap();
        let address = service.local_addr();
        let peer = PeerJob::start(move || {
            let mut peer = Peer::connect(address, "allowed");
            let state = peer.hello().unwrap(); peer.epoch(&state[60..108], b"abcdefgh");
            peer.read(FrameType::Control).unwrap();
        });
        let report = transfer(service.next_journaled(&cx, &scope, factory).await.unwrap().unwrap().outcome);
        assert_eq!(report.prefix.unwrap().bytes, 8);
        assert!(service.drain_next().await.is_none()); peer.join();
    });
    let mut changed = OpenOptions::new().write(true).open(&data).unwrap();
    changed.write_all(b"X").unwrap(); changed.sync_all().unwrap(); drop(changed);
    let history = std::fs::read(&wal).unwrap();
    let bytes = std::fs::read(&data).unwrap();
    let reopened = ReceiverJournalFile::open_existing(&wal, &data).unwrap();
    // Reopening the WAL alone must not be reported as accepted restoration.
    // Actual content is checked in the authenticated service worker.
    let catalog = Arc::new(Mutex::new(BTreeMap::from([(key("allowed"), reopened)])));
    run(2, async move {
        let cx = Cx::current().unwrap(); let scope = cx.scope(); let authority = receiver();
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&calls);
        let factory = move |_: Cx, key| {
            let catalog = Arc::clone(&catalog);
            let counted = Arc::clone(&counted);
            async move {
                counted.fetch_add(1, Ordering::Relaxed);
                let journal = catalog.lock().unwrap().remove(&key)
                    .ok_or_else(|| io::Error::from(io::ErrorKind::PermissionDenied))?;
                journal.into_service_session().await
            }
        };
        let mut service = authority.bind_resumable_service::<_>(
            &cx, "127.0.0.1:0".parse().unwrap(), limits(),
        ).await.unwrap();
        let address = service.local_addr();
        let peer = PeerJob::start(move || { assert!(Peer::connect(address, "allowed").hello().is_err()); });
        let completion = service.next_journaled(&cx, &scope, factory).await.unwrap().unwrap();
        assert!(matches!(completion.outcome,
            ResumeServiceOutcome::Rejected(ResumeServiceRejection::Factory(LiveStreamError::Io(ref error)))
                if error.kind() == io::ErrorKind::InvalidData));
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert_eq!(service.resident_sessions(), 0);
        assert!(service.drain_next().await.is_none());
        assert_eq!(authority.active_streams(), 0); peer.join();
    });
    assert_eq!(std::fs::read(&wal).unwrap(), history);
    assert_eq!(std::fs::read(&data).unwrap(), bytes);
}

struct CompletedGateJournal {
    inner: ReceiverJournalFile,
    gate: Arc<Gate>,
    fail: bool,
}
impl ReceiverCheckpointStore for CompletedGateJournal {
    fn poll_store(self: Pin<&mut Self>, cx: &mut Context<'_>, saved: &ReceiverCheckpoint) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if saved.phase() == ReceiverCheckpointPhase::Committed {
            let mut slot = this.gate.waker.lock().unwrap();
            if !this.gate.open.load(Ordering::Acquire) {
                *slot = Some(cx.waker().clone());
                this.gate.parked.store(true, Ordering::Release);
                return Poll::Pending;
            }
            if this.fail {
                return Poll::Ready(Err(io::Error::from(io::ErrorKind::StorageFull)));
            }
        }
        Pin::new(&mut this.inner).poll_store(cx, saved)
    }
}

#[test]
fn local_commit_persisted_commit_and_peer_proof_remain_independent_during_revocation() {
    for fail in [false, true] {
        let root = directory(); let (wal, data) = paths(&root, "allowed");
        let journal = ReceiverJournalFile::create_new(&wal, &data, ReceiverFileLimits {
            max_data_bytes: 64, max_snapshots: 16, max_journal_bytes: 65536,
        }).unwrap();
        let observer = journal.observer();
        let gate = Arc::new(Gate::default());
        let probe = Arc::new(Probe::default());
        let catalog = Catalog::default();
        catalog.put(key("allowed"), JournaledSession::new(
            Sink::open(&data, None, Arc::clone(&probe)),
            CompletedGateJournal { inner: journal, gate: Arc::clone(&gate), fail },
        ));
        run(2, async move {
            let cx = Cx::current().unwrap(); let scope = cx.scope(); let authority = receiver();
            let mut service = authority.bind_resumable_service::<Sink>(
                &cx, "127.0.0.1:0".parse().unwrap(), limits(),
            ).await.unwrap();
            let address = service.local_addr();
            let peer = PeerJob::start(move || {
                let mut peer = Peer::connect(address, "allowed");
                let state = peer.hello().unwrap();
                peer.epoch(&state[60..108], b"abcdefgh");
                let mut final_value = peer.read(FrameType::Control).unwrap();
                final_value.extend_from_slice(&Sha256::digest(b"abcdefgh"));
                peer.send(FrameType::ObjectComplete, final_value);
                assert!(peer.read(FrameType::Proof).is_err());
            });
            let ended = or(
                async { Some(service.next_journaled(&cx, &scope, catalog.factory()).await) },
                async { witness(&gate.parked).await; None },
            ).await;
            assert!(ended.is_none());
            assert_eq!(probe.commits.load(Ordering::Relaxed), 1);
            let before = observer.checkpoint().unwrap();
            assert_eq!(before.phase(), ReceiverCheckpointPhase::Finalizing);
            assert!(before.committed_receipt().is_none());
            let reason = CancelReason::user("shared journal committed-receipt revocation");
            service.revoke_client(client("allowed"), reason.clone()).unwrap();
            let premature = or(
                async { Some(service.next_journaled(&cx, &scope, catalog.factory()).await) },
                async { for _ in 0..16 { yield_now().await; } None },
            ).await;
            assert!(premature.is_none());
            assert_eq!(service.in_flight(), 1);
            gate.release();
            let report = transfer(service.next_journaled(&cx, &scope, catalog.factory()).await.unwrap().unwrap().outcome);
            match report.outcome {
                Err(ResumeError::ReceiverJournal(error)) => {
                    assert_eq!(error.stored, !fail);
                    assert_eq!(error.source.as_ref().map(io::Error::kind), fail.then_some(io::ErrorKind::StorageFull));
                    assert!(matches!(error.interruption.as_deref(),
                        Some(LiveStreamError::Cancelled(Some(actual))) if actual == &reason));
                }
                other => panic!("lost independent commit/persistence result: {other:?}"),
            }
            assert_eq!(report.completed.as_ref().unwrap().source_sha256, Sha256::digest(b"abcdefgh").as_slice());
            let saved = observer.checkpoint().unwrap();
            assert_eq!(saved.phase(), if fail { ReceiverCheckpointPhase::Finalizing } else { ReceiverCheckpointPhase::Committed });
            assert_eq!(saved.committed_receipt().is_some(), !fail);
            assert_eq!(before.phase(), ReceiverCheckpointPhase::Finalizing);
            assert_eq!(probe.commits.load(Ordering::Relaxed), 1);
            assert!(service.drain_next().await.is_none());
            assert_eq!(observer.checkpoint().unwrap_err().kind(), io::ErrorKind::NotConnected);
            assert_eq!(authority.active_streams(), 0); peer.join();
        });
        assert_eq!(std::fs::read(&data).unwrap(), b"abcdefgh");
        let saved = ReceiverJournalFile::open_existing(&wal, &data).unwrap().checkpoint().unwrap();
        assert_eq!(saved.committed_receipt().is_some(), !fail);
    }
}
