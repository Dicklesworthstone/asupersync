//! Sender EOF checkpointing against an independently driven, mutually authenticated peer.
//! The peer withholds the first Proof and rejects any ObjectData on recovery.
//! Subprocess witnesses exercise a new sender process with no retained source.
#![cfg(all(unix, feature = "tls", feature = "test-internals", not(target_arch = "wasm32")))]

use asupersync::Cx;
use asupersync::bytes::BytesMut;
use asupersync::codec::Decoder;
use asupersync::io::{AsyncRead, ReadBuf};
use asupersync::net::atp::protocol::codec::AtpFrameCodec;
use asupersync::net::atp::protocol::frames::{Frame, FrameType, ProtocolVersion};
use asupersync::net::atp::sdk::native_auth::live::{LiveStreamConfig, LiveStreamSender};
use asupersync::net::atp::sdk::native_auth::live::commit::resume::ResumeError;
use asupersync::net::atp::sdk::native_auth::live::commit::resume::finalization::{FinalProofCheckpoint, FinalProofStore};
use asupersync::net::atp::sdk::native_auth::live::commit::resume::finalization::file::FinalProofFile;
use asupersync::net::atp::sdk::{AtpSdk, NativeTlsIdentity, SessionConfig};
use asupersync::runtime::{RuntimeBuilder, yield_now};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject};
use sha2::{Digest, Sha256};
use std::future::Future;
use std::io::{self, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, atomic::{AtomicBool, AtomicUsize, Ordering}};
use std::task::{Context, Poll};
use std::thread;
use std::time::{Duration, Instant};

const DATA: &[u8] = b"checkpointed source is consumed once, never by recovery";
const WAIT: Duration = Duration::from_secs(20);
fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!("fixtures/atp_native_auth_identities.json")).unwrap()
}
fn cert(name: &str) -> CertificateDer<'static> {
    let value = fixture();
    let pem = if name == "ca" { value["ca"].as_str() } else { value["identities"][name]["certificate"].as_str() }.unwrap();
    CertificateDer::pem_reader_iter(&mut BufReader::new(pem.as_bytes())).next().unwrap().unwrap()
}
fn key(name: &str) -> PrivateKeyDer<'static> {
    let value = fixture(); let pem = value["identities"][name]["key"].as_str().unwrap();
    PrivateKeyDer::pem_reader_iter(&mut BufReader::new(pem.as_bytes())).next().unwrap().unwrap()
}
fn roots() -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty(); roots.add(cert("ca")).unwrap(); roots
}
fn sender() -> LiveStreamSender {
    let sdk = AtpSdk::new_in_process(SessionConfig { max_concurrent_transfers: 2, ..SessionConfig::default() });
    let mut profile = LiveStreamConfig::default(); profile.epoch_bytes = 8; profile.max_bytes = 128;
    profile.operation_timeout = Duration::from_secs(3);
    sdk.live_stream_sender(profile, ServerName::try_from("localhost").unwrap(), roots(),
        NativeTlsIdentity::new(vec![cert("allowed")], key("allowed")).unwrap()).unwrap()
}
fn run<T: Send + 'static>(workers: usize, future: impl Future<Output = T> + Send + 'static) -> T {
    let runtime = if workers == 1 { RuntimeBuilder::current_thread() }
        else { RuntimeBuilder::multi_thread().worker_threads(workers).with_sharded_state(true) }
        .blocking_threads(1, 2).build().unwrap();
    let future: Pin<Box<dyn Future<Output = T> + Send>> = Box::pin(async move {
        let cx = Cx::current().unwrap();
        asupersync::time::timeout(cx.now(), WAIT, future).await.expect("final-Proof test deadline")
    });
    let value = runtime.block_on(runtime.handle().spawn(future));
    let start = Instant::now();
    while !runtime.is_quiescent() {
        assert!(start.elapsed() < WAIT); runtime.block_on(yield_now());
    }
    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
    assert!(runtime.shutdown_timeout(Duration::from_secs(5)));
    value
}
fn directory() -> PathBuf {
    let path = tempfile::tempdir().unwrap().keep();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap(); path
}

struct Source { remaining: &'static [u8], reads: Arc<AtomicUsize> }
impl AsyncRead for Source {
    fn poll_read(mut self: Pin<&mut Self>, _: &mut Context<'_>, out: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        let count = out.remaining().min(self.remaining.len());
        out.put_slice(&self.remaining[..count]); self.remaining = &self.remaining[count..];
        Poll::Ready(Ok(()))
    }
}

struct Wire {
    tls: rustls::StreamOwned<rustls::ServerConnection, TcpStream>,
    codec: AtpFrameCodec,
    bytes: BytesMut,
}
impl Wire {
    fn new(tcp: TcpStream, config: Arc<rustls::ServerConfig>) -> Self {
        tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        tcp.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
        Self { tls: rustls::StreamOwned::new(rustls::ServerConnection::new(config).unwrap(), tcp),
            codec: AtpFrameCodec::with_max_frame_size(66000), bytes: BytesMut::new() }
    }
    fn receive(&mut self) -> io::Result<Frame> {
        loop {
            if let Some(frame) = self.codec.decode(&mut self.bytes).map_err(io::Error::other)? { return Ok(frame); }
            let mut bytes = [0; 4096]; let count = self.tls.read(&mut bytes)?;
            if count == 0 { return Err(io::Error::from(io::ErrorKind::UnexpectedEof)); }
            self.bytes.extend_from_slice(&bytes[..count]);
        }
    }
    fn send(&mut self, kind: FrameType, payload: Vec<u8>) {
        let bytes = Frame::new(ProtocolVersion::V0, kind, payload).unwrap().to_wire_bytes().unwrap();
        self.tls.write_all(&bytes).unwrap(); self.tls.flush().unwrap();
    }
}

#[derive(Clone, Copy)]
enum Reply { Exact, Incomplete, ChangedPrefix, WrongProof, StoreFailure }
struct Peer {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<usize>>,
}
impl Peer {
    fn start(path: PathBuf, reply: Reply) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap(); listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false)); let stopped = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(Arc::new(roots()), Arc::clone(&provider)).build().unwrap();
            let mut config = rustls::ServerConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&rustls::version::TLS13]).unwrap()
                .with_client_cert_verifier(verifier).with_single_cert(vec![cert("server")], key("server")).unwrap();
            config.alpn_protocols = vec![b"atp-live-resume/1".to_vec()]; config.send_tls13_tickets = 0;
            let config = Arc::new(config);
            let accept = || {
                let start = Instant::now();
                loop {
                    if stopped.load(Ordering::SeqCst) { return None; }
                    assert!(start.elapsed() < WAIT);
                    match listener.accept() {
                        Ok((tcp, _)) => return Some(Wire::new(tcp, Arc::clone(&config))),
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(2)),
                        Err(error) => panic!("accept failed: {error}"),
                    }
                }
            };
            let Some(mut first) = accept() else { return 0; };
            let hello = first.receive().unwrap(); assert_eq!(hello.frame_type(), FrameType::Handshake);
            let hello = hello.payload().to_vec(); assert_eq!(hello.len(), 60);
            assert_eq!(first.tls.conn.peer_certificates().unwrap()[0], cert("allowed"));
            let mut h = Sha256::new(); h.update(b"asupersync.atp.live.resume.hello.v1"); h.update(&hello);
            let mut prefix = vec![0; 16]; prefix.extend_from_slice(&h.finalize());
            let mut state = hello.clone(); state.extend_from_slice(&prefix); state.extend_from_slice(&Sha256::digest(b"")); state.push(0);
            first.send(FrameType::HandshakeAck, state);
            let mut data = Vec::new(); let mut epochs = 0_u64;
            let final_value = loop {
                let frame = match first.receive() {
                    Ok(frame) => frame,
                    Err(_) if matches!(reply, Reply::StoreFailure) => return data.len(),
                    Err(error) => panic!("source transfer failed: {error}"),
                };
                if frame.frame_type() == FrameType::ObjectComplete {
                    assert!(!matches!(reply, Reply::StoreFailure), "store failure leaked finalization");
                    let mut expected = prefix.clone(); expected.extend_from_slice(&Sha256::digest(&data));
                    assert_eq!(frame.payload(), expected);
                    // Read independently while the store's exclusive lock is held.
                    // A network final request must never precede complete checkpoint bytes.
                    let saved = FinalProofCheckpoint::from_canonical_bytes(&std::fs::read(&path).unwrap()).unwrap();
                    assert_eq!(saved.intent().prefix.bytes, data.len() as u64);
                    assert_eq!(saved.intent().source_sha256.as_slice(), Sha256::digest(&data).as_slice());
                    break expected;
                }
                assert_eq!(frame.frame_type(), FrameType::ObjectData);
                let epoch = frame.payload(); assert!(epoch.len() > 80);
                assert_eq!(&epoch[..48], &prefix);
                assert_eq!(&epoch[48..80], Sha256::digest(&epoch[80..]).as_slice());
                let mut chain = Sha256::new(); chain.update(b"asupersync.atp.live.epoch.v1");
                chain.update(&prefix[16..]); chain.update(epoch);
                data.extend_from_slice(&epoch[80..]); epochs += 1;
                prefix = epochs.to_be_bytes().to_vec(); prefix.extend_from_slice(&(data.len() as u64).to_be_bytes());
                prefix.extend_from_slice(&chain.finalize());
                first.send(FrameType::Control, prefix.clone());
            };
            drop(first); // Intentionally withhold Proof after the final request.
            let Some(mut recovered) = accept() else { return data.len(); };
            let request = recovered.receive().unwrap(); assert_eq!(request.frame_type(), FrameType::Handshake);
            assert_eq!(request.payload(), hello);
            let mut state = hello; state.extend_from_slice(&final_value); state.push(1);
            match reply {
                Reply::Incomplete => state[140] = 0,
                Reply::ChangedPrefix => state[60] ^= 1,
                _ => {}
            }
            recovered.send(FrameType::HandshakeAck, state);
            if matches!(reply, Reply::Incomplete | Reply::ChangedPrefix) {
                assert!(recovered.receive().is_err(), "refused state must not receive a finalization request");
            } else {
                let request = recovered.receive().unwrap();
                assert_eq!(request.frame_type(), FrameType::ObjectComplete, "recovery retransmitted source bytes");
                assert_eq!(request.payload(), final_value);
                let mut proof = final_value;
                if matches!(reply, Reply::WrongProof) { proof[79] ^= 1; }
                recovered.send(FrameType::Proof, proof);
            }
            data.len()
        });
        Self { address, stop, worker: Some(worker) }
    }
    fn finish(&mut self) -> usize { self.worker.take().unwrap().join().unwrap() }
}
impl Drop for Peer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() { let _ = worker.join(); }
    }
}

fn capture(path: &Path, address: SocketAddr, workers: usize, data: &'static [u8]) {
    let mut store = FinalProofFile::create_new(path).unwrap();
    run(workers, async move {
        let cx = Cx::current().unwrap(); let authority = sender();
        let reads = Arc::new(AtomicUsize::new(0));
        let source = Source { remaining: data, reads: Arc::clone(&reads) };
        let mut transfer = authority.resumable_reader(&cx, address, source, 2).unwrap();
        let report = transfer.send_checkpointed(&cx, &mut store).await;
        assert!(report.outcome.is_err()); assert!(report.completed.is_none());
        assert!(store.is_persisted()); assert_eq!(store.checkpoint().unwrap().intent().prefix.bytes, data.len() as u64);
        assert_eq!(reads.load(Ordering::SeqCst), data.len().div_ceil(8) + 1);
        drop(transfer); assert_eq!(authority.active_streams(), 0);
    });
}
fn recover(path: &Path, address: SocketAddr, workers: usize, success: bool) {
    let store = FinalProofFile::open_existing(path).unwrap();
    run(workers, async move {
        let cx = Cx::current().unwrap(); let authority = sender(); let checkpoint = store.checkpoint().unwrap();
        let mut wrong = address; wrong.set_port(address.port().wrapping_add(1));
        assert!(authority.restore_final_proof(&cx, wrong, checkpoint.clone(), 2).is_err());
        assert_eq!(authority.active_streams(), 0);
        let mut restored = authority.restore_final_proof(&cx, address, checkpoint.clone(), 1).unwrap();
        let report = restored.send(&cx).await;
        assert_eq!(report.outcome.is_ok(), success, "{report:?}");
        assert!(!report.receipt_reused);
        if success {
            assert_eq!(report.outcome.unwrap(), *checkpoint.intent());
            let cached = restored.send(&cx).await; assert!(cached.receipt_reused); assert_eq!(cached.attempts, 1);
        } else {
            assert!(matches!(report.outcome, Err(ResumeError::Continuity(_))));
            assert!(report.completed.is_none());
            assert!(matches!(restored.send(&cx).await.outcome, Err(ResumeError::AttemptsExhausted)));
        }
        drop(restored); assert_eq!(authority.active_streams(), 0); drop(store);
    });
}

#[test]
fn source_free_recovery_requires_committed_exact_state_and_exact_proof() {
    for workers in [1, 2] {
        for reply in [Reply::Exact, Reply::Incomplete, Reply::ChangedPrefix, Reply::WrongProof] {
            let path = directory().join("final.checkpoint"); let mut peer = Peer::start(path.clone(), reply);
            capture(&path, peer.address, workers, DATA);
            let before = std::fs::read(&path).unwrap();
            recover(&path, peer.address, workers, matches!(reply, Reply::Exact));
            assert_eq!(peer.finish(), DATA.len()); assert_eq!(std::fs::read(&path).unwrap(), before);
        }
    }
}

struct RefuseStore;
impl FinalProofStore for RefuseStore {
    fn poll_store(self: Pin<&mut Self>, _: &mut Context<'_>, _: &FinalProofCheckpoint) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::from(io::ErrorKind::StorageFull)))
    }
}
#[test]
fn persistence_failure_withholds_object_complete() {
    let path = directory().join("never-created"); let mut peer = Peer::start(path.clone(), Reply::StoreFailure);
    let address = peer.address;
    run(1, async move {
        let cx = Cx::current().unwrap(); let authority = sender();
        let mut transfer = authority.resumable_reader(&cx, address, DATA, 1).unwrap();
        let report = transfer.send_checkpointed(&cx, &mut RefuseStore).await;
        match report.outcome {
            Err(ResumeError::Checkpoint(error)) => {
                assert!(!error.stored); assert!(error.interruption.is_none());
                assert_eq!(error.source.unwrap().kind(), io::ErrorKind::StorageFull);
            }
            other => panic!("unexpected checkpoint result {other:?}"),
        }
        assert!(report.completed.is_none());
    });
    assert_eq!(peer.finish(), DATA.len()); assert!(!path.exists());
}

struct ChildGuard(Child);
impl ChildGuard {
    fn wait(&mut self) {
        let start = Instant::now();
        loop {
            if let Some(status) = self.0.try_wait().unwrap() { assert!(status.success()); return; }
            assert!(start.elapsed() < WAIT, "sender subprocess deadline");
            thread::sleep(Duration::from_millis(5));
        }
    }
}
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if matches!(self.0.try_wait(), Ok(None)) { let _ = self.0.kill(); }
        let _ = self.0.wait();
    }
}
#[test]
fn final_proof_subprocess_worker() {
    let Ok(phase) = std::env::var("ASUPERSYNC_FINAL_PROOF_TEST_PHASE") else { return; };
    let path = PathBuf::from(std::env::var_os("ASUPERSYNC_FINAL_PROOF_TEST_PATH").unwrap());
    let address = std::env::var("ASUPERSYNC_FINAL_PROOF_TEST_ADDRESS").unwrap().parse().unwrap();
    if phase == "capture" { capture(&path, address, 1, DATA); }
    else { assert_eq!(phase, "recover"); recover(&path, address, 2, true); }
    let witness = path.with_extension(format!("{phase}-witness"));
    let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(witness).unwrap();
    file.write_all(b"verified\n").unwrap();
}
#[test]
fn a_new_sender_process_recovers_proof_without_the_original_source_owner() {
    let path = directory().join("sender.checkpoint"); let mut peer = Peer::start(path.clone(), Reply::Exact);
    for phase in ["capture", "recover"] {
        let log = std::fs::OpenOptions::new().write(true).create_new(true)
            .open(path.with_extension(format!("{phase}-log"))).unwrap();
        let mut child = ChildGuard(Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "final_proof_subprocess_worker", "--nocapture"])
            .env("ASUPERSYNC_FINAL_PROOF_TEST_PHASE", phase)
            .env("ASUPERSYNC_FINAL_PROOF_TEST_PATH", &path)
            .env("ASUPERSYNC_FINAL_PROOF_TEST_ADDRESS", peer.address.to_string())
            .stdin(Stdio::null()).stdout(log.try_clone().unwrap()).stderr(log).spawn().unwrap());
        child.wait();
        assert_eq!(std::fs::read(path.with_extension(format!("{phase}-witness"))).unwrap(), b"verified\n");
    }
    assert_eq!(peer.finish(), DATA.len());
}

#[test]
fn empty_source_recovery_also_requires_prior_remote_commit() {
    for reply in [Reply::Exact, Reply::Incomplete] {
        let path = directory().join("empty.checkpoint"); let mut peer = Peer::start(path.clone(), reply);
        capture(&path, peer.address, 1, b"");
        recover(&path, peer.address, 2, matches!(reply, Reply::Exact));
        assert_eq!(peer.finish(), 0);
    }
}

struct SlowStore { finish: Option<Pin<Box<dyn Future<Output = ()> + Send>>>, polls: usize }
impl FinalProofStore for SlowStore {
    fn poll_store(self: Pin<&mut Self>, cx: &mut Context<'_>, _: &FinalProofCheckpoint) -> Poll<io::Result<()>> {
        let this = self.get_mut(); this.polls += 1;
        if this.finish.is_none() {
            this.finish = Some(Box::pin(asupersync::time::sleep(Cx::current().unwrap().now(), Duration::from_secs(4))));
        }
        this.finish.as_mut().unwrap().as_mut().poll(cx).map(|()| Ok(()))
    }
}
#[test]
fn started_store_is_drained_after_timeout_without_sending_finalization() {
    let path = directory().join("memory-only-test-store"); let mut peer = Peer::start(path, Reply::StoreFailure);
    let address = peer.address;
    run(2, async move {
        let cx = Cx::current().unwrap(); let authority = sender();
        let mut transfer = authority.resumable_reader(&cx, address, DATA, 1).unwrap();
        let mut store = SlowStore { finish: None, polls: 0 };
        let report = transfer.send_checkpointed(&cx, &mut store).await;
        match report.outcome {
            Err(ResumeError::Checkpoint(error)) => {
                assert!(error.stored); assert!(error.source.is_none());
                assert!(matches!(error.interruption.as_deref(), Some(asupersync::net::atp::sdk::native_auth::live::LiveStreamError::Timeout("sender final checkpoint"))));
            }
            other => panic!("expected drained checkpoint timeout, got {other:?}"),
        }
        assert!(store.polls >= 2); assert!(report.completed.is_none());
    });
    assert_eq!(peer.finish(), DATA.len());
}
