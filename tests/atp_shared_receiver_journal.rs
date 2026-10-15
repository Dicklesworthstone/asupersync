//! Shared-port WAL recovery against independent mTLS wire peers and processes.
//! All files/logs remain retained. Only test-owned child processes are terminated.
#![cfg(all(
    unix,
    feature = "tls",
    feature = "test-internals",
    not(target_arch = "wasm32")
))]

use asupersync::Cx;
use asupersync::bytes::BytesMut;
use asupersync::codec::Decoder;
use asupersync::io::AsyncWrite;
use asupersync::net::atp::protocol::codec::AtpFrameCodec;
use asupersync::net::atp::protocol::frames::{Frame, FrameType, ProtocolVersion};
use asupersync::net::atp::sdk::native_auth::live::commit::LiveStreamCommitSink;
use asupersync::net::atp::sdk::native_auth::live::commit::resume::receiver_journal::file::{
    ReceiverFileLimits, ReceiverJournalFile,
};
use asupersync::net::atp::sdk::native_auth::live::commit::resume::receiver_journal::shared::JournaledSession;
use asupersync::net::atp::sdk::native_auth::live::commit::resume::receiver_journal::{
    ReceiverCheckpoint, ReceiverCheckpointPhase, ReceiverCheckpointStore,
};
use asupersync::net::atp::sdk::native_auth::live::commit::resume::service::{
    ResumableService, ResumeServiceConfig, ResumeServiceOutcome, ResumeServiceRejection,
    ResumeSessionKey, ResumeSessionStatus,
};
use asupersync::net::atp::sdk::native_auth::live::commit::resume::{ResumeError, ResumeReport};
use asupersync::net::atp::sdk::native_auth::live::{
    LiveStreamConfig, LiveStreamError, LiveStreamReceipt, LiveStreamReceiver,
};
use asupersync::net::atp::sdk::{
    AtpSdk, NativeClientAuthorization, NativeClientCertificateId, NativeTlsIdentity, SessionConfig,
};
use asupersync::runtime::{RuntimeBuilder, spawn_blocking_io, yield_now};
use asupersync::types::CancelReason;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::future::{Future, poll_fn};
use std::io::{self, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::thread;
use std::time::{Duration, Instant};

const WAIT: Duration = Duration::from_secs(20);
const CONTENT: [&[u8]; 2] = [b"abcdefghijklmnop", b"0123456789ABCDEF"];
const CLIENTS: [&str; 2] = ["allowed", "unlisted"];

fn fixtures() -> Value {
    serde_json::from_str(include_str!("fixtures/atp_native_auth_identities.json")).unwrap()
}
fn cert(name: &str) -> CertificateDer<'static> {
    let value = fixtures();
    let pem = if name == "ca" {
        value["ca"].as_str()
    } else {
        value["identities"][name]["certificate"].as_str()
    }
    .unwrap();
    CertificateDer::pem_reader_iter(&mut BufReader::new(pem.as_bytes()))
        .next()
        .unwrap()
        .unwrap()
}
fn key(name: &str) -> PrivateKeyDer<'static> {
    let value = fixtures();
    PrivateKeyDer::pem_reader_iter(&mut BufReader::new(
        value["identities"][name]["key"]
            .as_str()
            .unwrap()
            .as_bytes(),
    ))
    .next()
    .unwrap()
    .unwrap()
}
fn roots() -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert("ca")).unwrap();
    roots
}
fn session(name: &str, nonce: u8) -> ResumeSessionKey {
    ResumeSessionKey {
        client: NativeClientCertificateId::from_certificate(&cert(name)),
        nonce: [nonce; 32],
    }
}
fn authority() -> LiveStreamReceiver {
    let sdk = AtpSdk::new_in_process(SessionConfig {
        max_concurrent_transfers: 2,
        ..SessionConfig::default()
    });
    let mut profile = LiveStreamConfig::default();
    profile.epoch_bytes = 8;
    profile.max_bytes = 64;
    profile.operation_timeout = Duration::from_secs(5);
    sdk.live_stream_receiver(
        profile,
        NativeTlsIdentity::new(vec![cert("server")], key("server")).unwrap(),
        NativeClientAuthorization::new(roots(), CLIENTS.map(|name| session(name, 7).client))
            .unwrap(),
    )
    .unwrap()
}
fn limits() -> ResumeServiceConfig {
    ResumeServiceConfig {
        max_connections: 2,
        max_sessions: 2,
        max_sessions_per_client: 1,
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
        asupersync::time::timeout(cx.now(), WAIT, future)
            .await
            .expect("shared WAL test deadline")
    });
    let result = runtime.block_on(runtime.handle().spawn(future));
    let start = Instant::now();
    while !runtime.is_quiescent() {
        assert!(start.elapsed() < WAIT);
        runtime.block_on(yield_now());
    }
    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
    assert!(runtime.shutdown_timeout(Duration::from_secs(5)));
    result
}
fn directory() -> PathBuf {
    let root = tempfile::tempdir().unwrap().keep();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    root
}

#[derive(Clone)]
struct Entry {
    wal: PathBuf,
    data: PathBuf,
    reopen: bool,
    snapshots: u32,
}
#[derive(Clone)]
struct Catalog {
    entries: Arc<BTreeMap<ResumeSessionKey, Entry>>,
    calls: Arc<AtomicUsize>,
}
impl Catalog {
    fn new(root: &Path, reopen: bool) -> Self {
        let entries = CLIENTS
            .into_iter()
            .map(|name| {
                (
                    session(name, 7),
                    Entry {
                        wal: root.join(format!("{name}.wal")),
                        data: root.join(format!("{name}.data")),
                        reopen,
                        snapshots: 32,
                    },
                )
            })
            .collect();
        Self {
            entries: Arc::new(entries),
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }
    async fn open(
        self,
        key: ResumeSessionKey,
    ) -> io::Result<JournaledSession<impl LiveStreamCommitSink + Unpin + Send>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let entry = self
            .entries
            .get(&key)
            .cloned()
            .ok_or_else(|| io::Error::from(io::ErrorKind::PermissionDenied))?;
        let journal = spawn_blocking_io(move || {
            // Explicit catalog decision, NEVER a missing-file/create fallback.
            if entry.reopen {
                ReceiverJournalFile::open_existing(&entry.wal, &entry.data)
            } else {
                ReceiverJournalFile::create_new(
                    &entry.wal,
                    &entry.data,
                    ReceiverFileLimits {
                        max_data_bytes: 64,
                        max_snapshots: entry.snapshots,
                        max_journal_bytes: 65536,
                    },
                )
            }
        })
        .await?;
        journal.into_service_session().await
    }
}

struct Wire {
    tls: rustls::StreamOwned<rustls::ClientConnection, TcpStream>,
    codec: AtpFrameCodec,
    buffer: BytesMut,
}
impl Wire {
    fn connect(address: SocketAddr, name: &str) -> Self {
        let tcp = TcpStream::connect_timeout(&address, WAIT).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
        tcp.set_write_timeout(Some(Duration::from_secs(8))).unwrap();
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots())
        .with_client_auth_cert(vec![cert(name)], key(name))
        .unwrap();
        config.alpn_protocols = vec![b"atp-live-resume/1".to_vec()];
        config.resumption = rustls::client::Resumption::disabled();
        Self {
            tls: rustls::StreamOwned::new(
                rustls::ClientConnection::new(
                    Arc::new(config),
                    ServerName::try_from("localhost").unwrap(),
                )
                .unwrap(),
                tcp,
            ),
            codec: AtpFrameCodec::with_max_frame_size(66000),
            buffer: BytesMut::new(),
        }
    }
    fn send(&mut self, kind: FrameType, payload: Vec<u8>) -> io::Result<()> {
        self.tls.write_all(
            &Frame::new(ProtocolVersion::V0, kind, payload)
                .unwrap()
                .to_wire_bytes()
                .unwrap(),
        )?;
        self.tls.flush()
    }
    fn read(&mut self, kind: FrameType) -> io::Result<Vec<u8>> {
        loop {
            if let Some(frame) = self
                .codec
                .decode(&mut self.buffer)
                .map_err(io::Error::other)?
            {
                assert_eq!(frame.frame_type(), kind);
                assert!(frame.header.extensions.is_empty());
                return Ok(frame.payload().to_vec());
            }
            let mut bytes = [0; 4096];
            let count = self.tls.read(&mut bytes)?;
            if count == 0 {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
            }
            self.buffer.extend_from_slice(&bytes[..count]);
            assert!(self.buffer.len() <= 66000);
        }
    }
}
#[derive(Clone)]
struct Model {
    hello: Vec<u8>,
    prefix: Vec<u8>,
    bytes: Vec<u8>,
}
impl Model {
    fn new(nonce: u8) -> Self {
        let mut hello = b"ATPRSM01ATPLIVE1".to_vec();
        hello.extend_from_slice(&[nonce; 32]);
        hello.extend_from_slice(&8_u32.to_be_bytes());
        hello.extend_from_slice(&64_u64.to_be_bytes());
        let mut hash = Sha256::new();
        hash.update(b"asupersync.atp.live.resume.hello.v1");
        hash.update(&hello);
        let mut prefix = vec![0; 16];
        prefix.extend_from_slice(&hash.finalize());
        Self {
            hello,
            prefix,
            bytes: Vec::new(),
        }
    }
    fn hello(&self, wire: &mut Wire, committed: bool) {
        wire.send(FrameType::Handshake, self.hello.clone()).unwrap();
        let mut expected = self.hello.clone();
        expected.extend_from_slice(&self.prefix);
        expected.extend_from_slice(&Sha256::digest(&self.bytes));
        expected.push(u8::from(committed));
        assert_eq!(wire.read(FrameType::HandshakeAck).unwrap(), expected);
    }
    fn epoch(&mut self, bytes: &[u8]) -> Vec<u8> {
        let mut payload = self.prefix.clone();
        payload.extend_from_slice(&Sha256::digest(bytes));
        payload.extend_from_slice(bytes);
        let mut hash = Sha256::new();
        hash.update(b"asupersync.atp.live.epoch.v1");
        hash.update(&self.prefix[16..]);
        hash.update(&payload);
        let epochs = u64::from_be_bytes(self.prefix[..8].try_into().unwrap()) + 1;
        self.bytes.extend_from_slice(bytes);
        self.prefix = epochs.to_be_bytes().to_vec();
        self.prefix
            .extend_from_slice(&(self.bytes.len() as u64).to_be_bytes());
        self.prefix.extend_from_slice(&hash.finalize());
        payload
    }
    fn send_epoch(&mut self, wire: &mut Wire, bytes: &[u8]) {
        wire.send(FrameType::ObjectData, self.epoch(bytes)).unwrap();
        assert_eq!(wire.read(FrameType::Control).unwrap(), self.prefix);
    }
    fn finish(&self, wire: &mut Wire) {
        let mut value = self.prefix.clone();
        value.extend_from_slice(&Sha256::digest(&self.bytes));
        wire.send(FrameType::ObjectComplete, value.clone()).unwrap();
        assert_eq!(wire.read(FrameType::Proof).unwrap(), value);
    }
}

// Always join test peers, including while unwinding. Peer I/O has finite deadlines.
struct Peer<T>(Option<thread::JoinHandle<T>>);
impl<T: Send + 'static> Peer<T> {
    fn start(f: impl FnOnce() -> T + Send + 'static) -> Self {
        Self(Some(thread::spawn(f)))
    }
    fn finish(mut self) -> T {
        self.0
            .take()
            .unwrap()
            .join()
            .expect("independent wire peer")
    }
}
impl<T> Drop for Peer<T> {
    fn drop(&mut self) {
        if let Some(thread) = self.0.take() {
            let _ = thread.join();
        }
    }
}
fn transfer(outcome: ResumeServiceOutcome) -> ResumeReport {
    match outcome {
        ResumeServiceOutcome::Transfer(report) => report,
        other => panic!("not a transfer: {other:?}"),
    }
}
async fn drain<W: LiveStreamCommitSink + Unpin + Send + 'static>(
    service: &mut ResumableService<W>,
) {
    while service.drain_next().await.is_some() {}
    assert!(service.is_drained());
}

// Independent WAL framing/checksum parser, used only at witnessed idle boundaries.
fn records(path: &Path) -> Vec<Vec<u8>> {
    let bytes = std::fs::read(path).unwrap();
    assert!(bytes.len() >= 96);
    assert_eq!(&bytes[..8], b"ATPRFL01");
    let checksum = |previous: &[u8], body: &[u8]| {
        let mut hash = Sha256::new();
        hash.update(b"asupersync.atp.receiver-file-journal.v1");
        hash.update(previous);
        hash.update(body);
        hash.finalize().to_vec()
    };
    let mut previous = checksum(&[], &bytes[..64]);
    assert_eq!(bytes[64..96], previous);
    let mut rows = Vec::new();
    let mut offset = 96;
    while offset < bytes.len() {
        assert!(offset + 16 <= bytes.len());
        let length =
            u32::from_be_bytes(bytes[offset + 8..offset + 12].try_into().unwrap()) as usize;
        assert!((317..=65933).contains(&length));
        assert_eq!(
            &bytes[offset..offset + 8],
            &(rows.len() as u64).to_be_bytes()
        );
        assert_eq!(&bytes[offset + 12..offset + 16], &[0; 4]);
        let end = offset + 16 + length;
        assert!(end + 32 <= bytes.len());
        let hash = checksum(&previous, &bytes[offset..end]);
        assert_eq!(bytes[end..end + 32], hash);
        let row = bytes[offset + 16..end].to_vec();
        assert_eq!(&row[..8], b"ATPRCV01");
        let mut inner = Sha256::new();
        inner.update(b"asupersync.atp.receiver-checkpoint.v1");
        inner.update(&row[..row.len() - 32]);
        assert_eq!(&row[row.len() - 32..], inner.finalize().as_slice());
        rows.push(row);
        previous = hash;
        offset = end + 32;
    }
    assert_eq!(offset, bytes.len());
    rows
}

fn seed(root: PathBuf, workers: usize) -> SocketAddr {
    run(workers, async move {
        let cx = Cx::current().unwrap();
        let scope = cx.scope();
        let authority = authority();
        let mut service = authority
            .bind_resumable_service(&cx, "127.0.0.1:0".parse().unwrap(), limits())
            .await
            .unwrap();
        let address = service.local_addr();
        let catalog = Catalog::new(&root, false);
        let factory = {
            let catalog = catalog.clone();
            move |_: Cx, key| catalog.clone().open(key)
        };
        let peers: Vec<_> = CLIENTS
            .into_iter()
            .enumerate()
            .map(|(index, name)| {
                Peer::start(move || {
                    let mut wire = Wire::connect(address, name);
                    let mut model = Model::new(7);
                    model.hello(&mut wire, false);
                    model.send_epoch(&mut wire, &CONTENT[index][..8]);
                })
            })
            .collect();
        for _ in 0..2 {
            let completion = service
                .next_journaled(&cx, &scope, factory.clone())
                .await
                .unwrap()
                .unwrap();
            let report = transfer(completion.outcome);
            assert!(
                matches!(report.outcome, Err(ResumeError::Transfer(LiveStreamError::Io(ref error)))
                if error.kind() == io::ErrorKind::UnexpectedEof)
            );
            assert_eq!(report.prefix.unwrap().bytes, 8);
            assert_eq!(report.attempts, 1);
            assert_eq!(report.sink_written_bytes, 8);
            assert!(report.completed.is_none());
        }
        for peer in peers {
            peer.finish();
        }
        assert_eq!(catalog.calls.load(Ordering::SeqCst), 2);
        assert_eq!(service.resident_sessions(), 2);
        assert_eq!(authority.active_streams(), 2); // The service uses the entire SDK budget.
        drain(&mut service).await;
        assert_eq!(authority.active_streams(), 0);
        address
    })
}

#[test]
fn two_clients_restore_their_own_files_and_legacy_next_cannot_disable_journaling() {
    for workers in [1, 2] {
        let root = directory();
        let address = seed(root.clone(), workers);
        let inodes: Vec<_> = CLIENTS
            .map(|name| {
                std::fs::metadata(root.join(format!("{name}.data")))
                    .unwrap()
                    .ino()
            })
            .into();
        let result_root = root.clone();
        run(workers, async move {
            let cx = Cx::current().unwrap();
            let scope = cx.scope();
            let authority = authority();
            // A wider current ceiling must NOT rewrite the saved ceiling of four.
            let mut service = authority
                .bind_resumable_service(
                    &cx,
                    address,
                    ResumeServiceConfig {
                        max_attempts_per_session: 8,
                        ..limits()
                    },
                )
                .await
                .unwrap();
            let catalog = Catalog::new(&root, true);
            let factory = {
                let catalog = catalog.clone();
                move |_: Cx, key| catalog.clone().open(key)
            };
            let peers: Vec<_> = CLIENTS
                .into_iter()
                .enumerate()
                .map(|(index, name)| {
                    Peer::start(move || {
                        let mut model = Model::new(7);
                        model.epoch(&CONTENT[index][..8]);
                        let mut wire = Wire::connect(address, name);
                        model.hello(&mut wire, false);
                        model.send_epoch(&mut wire, &CONTENT[index][8..]);
                        model.finish(&mut wire);
                    })
                })
                .collect();
            for _ in 0..2 {
                let completion = service
                    .next_journaled(&cx, &scope, factory.clone())
                    .await
                    .unwrap()
                    .unwrap();
                let report = transfer(completion.outcome);
                let receipt = report.outcome.unwrap();
                assert_eq!(receipt.prefix.bytes, 16);
                assert_eq!(report.attempts, 2);
                assert_eq!(report.sink_written_bytes, 16);
                assert!(!report.receipt_reused);
                assert_eq!(report.completed.as_ref(), Some(&receipt));
            }
            for peer in peers {
                peer.finish();
            }
            assert_eq!(catalog.calls.load(Ordering::SeqCst), 2);
            let forbidden = Arc::new(AtomicUsize::new(0));
            for (index, name) in CLIENTS.into_iter().enumerate() {
                let peer = Peer::start(move || {
                    let mut model = Model::new(7);
                    model.epoch(&CONTENT[index][..8]);
                    model.epoch(&CONTENT[index][8..]);
                    let mut wire = Wire::connect(address, name);
                    model.hello(&mut wire, true);
                    model.finish(&mut wire);
                });
                let calls = Arc::clone(&forbidden);
                let report = transfer(
                    service
                        .next(&cx, &scope, move |_, _| {
                            calls.fetch_add(1, Ordering::SeqCst);
                            std::future::ready(Err(io::Error::other(
                                "a retained session must not run a new factory",
                            )))
                        })
                        .await
                        .unwrap()
                        .unwrap()
                        .outcome,
                );
                assert!(report.outcome.is_ok());
                assert_eq!(report.attempts, 3);
                assert!(report.receipt_reused);
                peer.finish();
            }
            assert_eq!(forbidden.load(Ordering::SeqCst), 0);
            drain(&mut service).await;
            assert_eq!(authority.active_streams(), 0);
        });
        for (index, name) in CLIENTS.into_iter().enumerate() {
            let data = result_root.join(format!("{name}.data"));
            assert_eq!(std::fs::read(&data).unwrap(), CONTENT[index]);
            assert_eq!(std::fs::metadata(&data).unwrap().ino(), inodes[index]);
            let saved =
                ReceiverJournalFile::open_existing(&result_root.join(format!("{name}.wal")), &data)
                    .unwrap()
                    .checkpoint()
                    .unwrap();
            assert_eq!(saved.client(), session(name, 7).client);
            assert_eq!(saved.attempts(), 3);
            assert_eq!(saved.maximum_attempts(), 4);
            assert_eq!(saved.phase(), ReceiverCheckpointPhase::Committed);
            assert_eq!(
                saved.committed_receipt().unwrap().source_sha256,
                Sha256::digest(CONTENT[index]).as_slice()
            );
        }
        assert_eq!(std::fs::read_dir(&result_root).unwrap().count(), 4);
    }
}

#[test]
fn altered_retained_data_is_tombstoned_without_blocking_another_restored_client() {
    let root = directory();
    let address = seed(root.clone(), 2);
    let path = root.join("allowed.data");
    let mut file = OpenOptions::new().write(true).open(&path).unwrap();
    file.write_all(b"X").unwrap();
    file.sync_all().unwrap();
    drop(file);
    let before = std::fs::read(root.join("allowed.wal")).unwrap();
    let check = root.clone();
    run(2, async move {
        let cx = Cx::current().unwrap();
        let scope = cx.scope();
        let authority = authority();
        let mut service = authority
            .bind_resumable_service(&cx, address, limits())
            .await
            .unwrap();
        let catalog = Catalog::new(&root, true);
        let factory = {
            let catalog = catalog.clone();
            move |_: Cx, key| catalog.clone().open(key)
        };
        let bad = Peer::start(move || {
            let mut wire = Wire::connect(address, "allowed");
            wire.send(FrameType::Handshake, Model::new(7).hello)
                .unwrap();
            assert!(wire.read(FrameType::HandshakeAck).is_err());
        });
        let rejected = service
            .next_journaled(&cx, &scope, factory.clone())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(rejected.session, Some(session("allowed", 7)));
        assert!(
            matches!(rejected.outcome, ResumeServiceOutcome::Rejected(ResumeServiceRejection::Factory(
            LiveStreamError::Io(ref error))) if error.kind() == io::ErrorKind::InvalidData)
        );
        bad.finish();
        assert_eq!(
            service.session_status(&session("allowed", 7)),
            Some(ResumeSessionStatus::Retired)
        );
        assert_eq!(service.resident_sessions(), 0);
        let healthy = Peer::start(move || {
            let mut model = Model::new(7);
            model.epoch(&CONTENT[1][..8]);
            let mut wire = Wire::connect(address, "unlisted");
            model.hello(&mut wire, false);
            model.send_epoch(&mut wire, &CONTENT[1][8..]);
            model.finish(&mut wire);
        });
        assert!(
            transfer(
                service
                    .next_journaled(&cx, &scope, factory)
                    .await
                    .unwrap()
                    .unwrap()
                    .outcome
            )
            .outcome
            .is_ok()
        );
        healthy.finish();
        assert_eq!(catalog.calls.load(Ordering::SeqCst), 2);
        drain(&mut service).await;
        assert_eq!(authority.active_streams(), 0);
    });
    assert_eq!(std::fs::read(check.join("allowed.wal")).unwrap(), before);
    assert_eq!(
        std::fs::read(check.join("allowed.data")).unwrap(),
        b"Xbcdefgh"
    );
    assert_eq!(
        std::fs::read(check.join("unlisted.data")).unwrap(),
        CONTENT[1]
    );
}

#[test]
fn wrong_catalog_key_and_revoked_clients_cannot_reach_journal_writes() {
    let root = directory();
    let address = seed(root.clone(), 1);
    let before: Vec<_> = CLIENTS
        .map(|name| std::fs::read(root.join(format!("{name}.wal"))).unwrap())
        .into();
    let check = root.clone();
    run(1, async move {
        let cx = Cx::current().unwrap();
        let scope = cx.scope();
        let authority = authority();
        let mut service = authority
            .bind_resumable_service(&cx, address, limits())
            .await
            .unwrap();
        let mut catalog = Catalog::new(&root, true);
        // A valid authenticated client is deliberately mapped to another client's WAL.
        let wrong = catalog.entries[&session("unlisted", 7)].clone();
        Arc::make_mut(&mut catalog.entries).insert(session("allowed", 7), wrong);
        let factory = {
            let catalog = catalog.clone();
            move |_: Cx, key| catalog.clone().open(key)
        };
        let peer = Peer::start(move || {
            let mut wire = Wire::connect(address, "allowed");
            wire.send(FrameType::Handshake, Model::new(7).hello)
                .unwrap();
            assert!(wire.read(FrameType::HandshakeAck).is_err());
        });
        let rejected = service
            .next_journaled(&cx, &scope, factory.clone())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            rejected.outcome,
            ResumeServiceOutcome::Rejected(ResumeServiceRejection::Factory(
                LiveStreamError::Configuration(
                    "receiver journal does not match authenticated session key"
                )
            ))
        ));
        peer.finish();
        assert_eq!(catalog.calls.load(Ordering::SeqCst), 1);
        let revocation = service
            .revoke_client(
                session("unlisted", 7).client,
                CancelReason::user("journal test revocation"),
            )
            .unwrap();
        assert!(revocation.newly_revoked);
        assert_eq!(revocation.signalled_connections, 0);
        assert_eq!(revocation.retained_sessions, 0);
        let peer = Peer::start(move || {
            let mut wire = Wire::connect(address, "unlisted");
            wire.send(FrameType::Handshake, Model::new(7).hello)
                .unwrap();
            assert!(wire.read(FrameType::HandshakeAck).is_err());
        });
        let rejected = service
            .next_journaled(&cx, &scope, factory)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            rejected.outcome,
            ResumeServiceOutcome::Rejected(ResumeServiceRejection::Revoked)
        ));
        peer.finish();
        assert_eq!(catalog.calls.load(Ordering::SeqCst), 1);
        drain(&mut service).await;
    });
    for (index, name) in CLIENTS.into_iter().enumerate() {
        assert_eq!(
            std::fs::read(check.join(format!("{name}.wal"))).unwrap(),
            before[index]
        );
        assert_eq!(
            std::fs::read(check.join(format!("{name}.data"))).unwrap(),
            &CONTENT[index][..8]
        );
    }
}

#[derive(Default)]
struct GateState {
    latest: Option<ReceiverCheckpoint>,
    waiting: Option<ReceiverCheckpoint>,
    entered: bool,
    released: bool,
    polls: usize,
    worker: Option<Waker>,
    observer: Option<Waker>,
}
#[derive(Default)]
struct Gate {
    state: Mutex<GateState>,
    data: Mutex<Vec<u8>>,
    commits: AtomicUsize,
}
impl Gate {
    fn watch(&self, context: &Context<'_>, after: Option<usize>) -> bool {
        let mut state = self.state.lock().unwrap();
        state.observer = Some(context.waker().clone());
        after.map_or(state.entered, |polls| state.polls > polls)
    }
    fn release(&self) {
        let worker = {
            let mut state = self.state.lock().unwrap();
            state.released = true;
            state.worker.take()
        };
        if let Some(worker) = worker {
            worker.wake();
        }
    }
}
struct GateStore(Arc<Gate>);
impl ReceiverCheckpointStore for GateStore {
    fn poll_store(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        saved: &ReceiverCheckpoint,
    ) -> Poll<io::Result<()>> {
        let gate = &self.0;
        let mut state = gate.state.lock().unwrap();
        if let Some(previous) = &state.latest {
            saved.validate_successor(previous)?;
        }
        if saved.prefix().bytes == 8 && saved.pending_bytes() == 0 && !state.released {
            if let Some(waiting) = &state.waiting {
                assert_eq!(
                    waiting.to_canonical_bytes().unwrap().as_slice(),
                    saved.to_canonical_bytes().unwrap().as_slice()
                );
            } else {
                state.waiting = Some(saved.clone());
            }
            state.entered = true;
            state.polls += 1;
            state.worker = Some(context.waker().clone());
            let observer = state.observer.take();
            drop(state);
            if let Some(observer) = observer {
                observer.wake();
            }
            return Poll::Pending;
        }
        state.latest = Some(saved.clone());
        Poll::Ready(Ok(()))
    }
}
struct GateSink(Arc<Gate>);
impl AsyncWrite for GateSink {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.0.data.lock().unwrap().extend_from_slice(bytes);
        Poll::Ready(Ok(bytes.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
impl LiveStreamCommitSink for GateSink {
    fn poll_commit(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &LiveStreamReceipt,
    ) -> Poll<io::Result<()>> {
        self.0.commits.fetch_add(1, Ordering::SeqCst);
        Poll::Ready(Ok(()))
    }
}

#[test]
fn revoked_pending_checkpoint_drains_the_same_store_without_acknowledging_or_committing() {
    for workers in [1, 2] {
        run(workers, async move {
            let cx = Cx::current().unwrap();
            let scope = cx.scope();
            let authority = authority();
            let mut service = authority
                .bind_resumable_service::<GateSink>(&cx, "127.0.0.1:0".parse().unwrap(), limits())
                .await
                .unwrap();
            let address = service.local_addr();
            let gate = Arc::new(Gate::default());
            let factory = {
                let gate = Arc::clone(&gate);
                move |_: Cx, _| {
                    let gate = Arc::clone(&gate);
                    async move {
                        Ok(JournaledSession::new(
                            GateSink(Arc::clone(&gate)),
                            GateStore(gate),
                        ))
                    }
                }
            };
            let ack = Arc::new(AtomicBool::new(false));
            let observed = Arc::clone(&ack);
            let peer = Peer::start(move || {
                let mut wire = Wire::connect(address, "allowed");
                let mut model = Model::new(7);
                model.hello(&mut wire, false);
                wire.send(FrameType::ObjectData, model.epoch(b"abcdefgh"))
                    .unwrap();
                observed.store(wire.read(FrameType::Control).is_ok(), Ordering::SeqCst);
            });
            {
                let mut next = Box::pin(service.next_journaled(&cx, &scope, factory.clone()));
                poll_fn(|context| {
                    let witnessed = gate.watch(context, None);
                    assert!(next.as_mut().poll(context).is_pending());
                    if witnessed {
                        Poll::Ready(())
                    } else {
                        Poll::Pending
                    }
                })
                .await;
            }
            assert_eq!(*gate.data.lock().unwrap(), b"abcdefgh");
            assert!(!ack.load(Ordering::SeqCst));
            assert_eq!(gate.commits.load(Ordering::SeqCst), 0);
            let polls = gate.state.lock().unwrap().polls;
            let reason = CancelReason::user("shared WAL exact cancellation");
            assert_eq!(
                service
                    .revoke_client(session("allowed", 7).client, reason.clone())
                    .unwrap()
                    .signalled_connections,
                1
            );
            {
                let mut next = Box::pin(service.next_journaled(&cx, &scope, factory.clone()));
                poll_fn(|context| {
                    let drained_poll = gate.watch(context, Some(polls));
                    assert!(next.as_mut().poll(context).is_pending());
                    if drained_poll {
                        Poll::Ready(())
                    } else {
                        Poll::Pending
                    }
                })
                .await;
            }
            assert_eq!(service.in_flight(), 1);
            assert_eq!(authority.active_streams(), 2);
            gate.release();
            let report = transfer(
                service
                    .next_journaled(&cx, &scope, factory)
                    .await
                    .unwrap()
                    .unwrap()
                    .outcome,
            );
            match report.outcome {
                Err(ResumeError::ReceiverJournal(error)) => {
                    assert!(error.stored);
                    assert!(error.source.is_none());
                    assert!(
                        matches!(error.interruption.as_deref(), Some(LiveStreamError::Cancelled(Some(actual))) if *actual == reason)
                    );
                }
                other => panic!("wrong interrupted WAL outcome: {other:?}"),
            }
            assert_eq!(report.prefix.unwrap().bytes, 8);
            assert_eq!(report.sink_written_bytes, 8);
            assert!(report.completed.is_none());
            assert_eq!(
                gate.state
                    .lock()
                    .unwrap()
                    .latest
                    .as_ref()
                    .unwrap()
                    .prefix()
                    .bytes,
                8
            );
            peer.finish();
            assert!(!ack.load(Ordering::SeqCst));
            assert_eq!(gate.commits.load(Ordering::SeqCst), 0);
            let retired = service.retire(&session("allowed", 7)).unwrap().unwrap();
            assert_eq!(retired.sink_written_bytes, 8);
            assert!(retired.completed.is_none());
            drain(&mut service).await;
            assert_eq!(authority.active_streams(), 0);
        });
    }
}

#[test]
fn shared_journal_exhaustion_blocks_data_and_keeps_the_failed_owner_until_retirement() {
    let root = directory();
    let inspect = root.clone();
    run(1, async move {
        let cx = Cx::current().unwrap();
        let scope = cx.scope();
        let authority = authority();
        let mut service = authority
            .bind_resumable_service(&cx, "127.0.0.1:0".parse().unwrap(), limits())
            .await
            .unwrap();
        let address = service.local_addr();
        let mut catalog = Catalog::new(&root, false);
        Arc::make_mut(&mut catalog.entries)
            .get_mut(&session("allowed", 7))
            .unwrap()
            .snapshots = 1;
        let factory = {
            let catalog = catalog.clone();
            move |_: Cx, key| catalog.clone().open(key)
        };
        let peer = Peer::start(move || {
            let mut wire = Wire::connect(address, "allowed");
            let mut model = Model::new(7);
            model.hello(&mut wire, false);
            wire.send(FrameType::ObjectData, model.epoch(b"abcdefgh"))
                .unwrap();
            assert!(wire.read(FrameType::Control).is_err());
        });
        let report = transfer(
            service
                .next_journaled(&cx, &scope, factory)
                .await
                .unwrap()
                .unwrap()
                .outcome,
        );
        match report.outcome {
            Err(ResumeError::ReceiverJournal(error)) => {
                assert!(!error.stored);
                assert!(error.interruption.is_none());
                assert_eq!(error.source.unwrap().kind(), io::ErrorKind::StorageFull);
            }
            other => panic!("wrong capacity result: {other:?}"),
        }
        assert_eq!(report.sink_written_bytes, 0);
        assert!(report.completed.is_none());
        assert_eq!(
            service.session_status(&session("allowed", 7)),
            Some(ResumeSessionStatus::Idle)
        );
        assert!(
            ReceiverJournalFile::open_existing(
                &root.join("allowed.wal"),
                &root.join("allowed.data")
            )
            .is_err()
        );
        let snapshot = service.retire(&session("allowed", 7)).unwrap().unwrap();
        assert!(snapshot.failed);
        assert_eq!(snapshot.sink_written_bytes, 0);
        peer.finish();
        drain(&mut service).await;
        assert_eq!(authority.active_streams(), 0);
    });
    assert_eq!(
        std::fs::metadata(inspect.join("allowed.data"))
            .unwrap()
            .len(),
        0
    );
    assert_eq!(records(&inspect.join("allowed.wal")).len(), 1);
}

fn write_witness(path: &Path, value: Value) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(&serde_json::to_vec(&value).unwrap())
        .unwrap();
    file.sync_all().unwrap();
}

#[test]
fn shared_journal_process_worker() {
    let Ok(root) = std::env::var("ASUP_TEST_SHARED_WAL_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    let mode = std::env::var("ASUP_TEST_SHARED_WAL_MODE").unwrap();
    let workers = std::env::var("ASUP_TEST_SHARED_WAL_WORKERS")
        .unwrap()
        .parse()
        .unwrap();
    let address = std::env::var("ASUP_TEST_SHARED_WAL_ADDRESS")
        .unwrap()
        .parse()
        .unwrap();
    let witness = root.join(format!("done-{mode}.json"));
    let mode_for_task = mode.clone();
    run(workers, async move {
        let cx = Cx::current().unwrap();
        let scope = cx.scope();
        let authority = authority();
        let mut service = authority
            .bind_resumable_service(&cx, address, limits())
            .await
            .unwrap();
        let catalog = Catalog::new(&root, mode_for_task != "create");
        let factory = {
            let catalog = catalog.clone();
            move |_: Cx, key| catalog.clone().open(key)
        };
        write_witness(
            &root.join(format!("ready-{mode_for_task}.json")),
            json!({"address": service.local_addr()}),
        );
        for _ in 0..2 {
            let completion = service
                .next_journaled(&cx, &scope, factory.clone())
                .await
                .unwrap()
                .unwrap();
            let key = completion.session.unwrap();
            let report = transfer(completion.outcome);
            // The create process is killed while peers still own their ACKed
            // connections. Any earlier terminal result is an explicit test failure.
            assert_ne!(
                mode_for_task, "create",
                "connection ended before crash witness"
            );
            let receipt = report.outcome.unwrap();
            assert_eq!(receipt.prefix.stream_nonce, [7; 32]);
            assert_eq!(receipt.prefix.bytes, 16);
            assert_eq!(report.sink_written_bytes, 16);
            assert_eq!(
                report.attempts,
                if mode_for_task == "restore" { 2 } else { 3 }
            );
            assert_eq!(report.receipt_reused, mode_for_task == "receipt");
            let index = CLIENTS
                .iter()
                .position(|name| session(name, 7).client == key.client)
                .unwrap();
            assert_eq!(
                receipt.source_sha256,
                Sha256::digest(CONTENT[index]).as_slice()
            );
        }
        assert_eq!(catalog.calls.load(Ordering::SeqCst), 2);
        drain(&mut service).await;
        assert_eq!(authority.active_streams(), 0);
    });
    // Existence proves the worker completed assertions AND native runtime drain.
    write_witness(
        &witness,
        json!({"mode": mode, "assertions_completed": true, "drained": true}),
    );
}

struct Process {
    child: Child,
    root: PathBuf,
    mode: String,
}
impl Process {
    fn spawn(root: &Path, mode: &str, workers: usize, address: SocketAddr) -> Self {
        let log = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(root.join(format!("log-{mode}")))
            .unwrap();
        let child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "shared_journal_process_worker",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("ASUP_TEST_SHARED_WAL_ROOT", root)
            .env("ASUP_TEST_SHARED_WAL_MODE", mode)
            .env("ASUP_TEST_SHARED_WAL_WORKERS", workers.to_string())
            .env("ASUP_TEST_SHARED_WAL_ADDRESS", address.to_string())
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap();
        Self {
            child,
            root: root.to_owned(),
            mode: mode.to_owned(),
        }
    }
    fn ready(&mut self) -> SocketAddr {
        let start = Instant::now();
        let path = self.root.join(format!("ready-{}.json", self.mode));
        loop {
            if let Ok(bytes) = std::fs::read(&path) {
                if let Ok(value) = serde_json::from_slice::<Value>(&bytes) {
                    return value["address"].as_str().unwrap().parse().unwrap();
                }
            }
            assert!(
                self.child.try_wait().unwrap().is_none(),
                "worker ended before readiness; root {}",
                self.root.display()
            );
            assert!(start.elapsed() < WAIT);
            thread::sleep(Duration::from_millis(2));
        }
    }
    fn wait(&mut self) -> ExitStatus {
        let start = Instant::now();
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            assert!(start.elapsed() < WAIT);
            thread::sleep(Duration::from_millis(2));
        }
    }
    fn crash(&mut self) {
        self.child.kill().unwrap();
        assert!(!self.wait().success());
    }
    fn done(&mut self) {
        assert!(
            self.wait().success(),
            "worker assertions failed; root {}",
            self.root.display()
        );
        let value: Value = serde_json::from_slice(
            &std::fs::read(self.root.join(format!("done-{}.json", self.mode))).unwrap(),
        )
        .unwrap();
        assert_eq!(value["mode"], self.mode);
        assert_eq!(value["assertions_completed"], true);
        assert_eq!(value["drained"], true);
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

#[test]
fn killed_shared_receiver_restores_two_original_inodes_and_then_reuses_committed_proofs() {
    for workers in [1, 2] {
        let root = directory();
        let mut original = Process::spawn(&root, "create", workers, "127.0.0.1:0".parse().unwrap());
        let address = original.ready();
        let mut peers = Vec::new();
        let mut models = Vec::new();
        let mut inodes = Vec::new();
        let mut histories = Vec::new();
        for (index, name) in CLIENTS.into_iter().enumerate() {
            let mut wire = Wire::connect(address, name);
            let mut model = Model::new(7);
            model.hello(&mut wire, false);
            model.send_epoch(&mut wire, &CONTENT[index][..8]);
            let data = root.join(format!("{name}.data"));
            let wal = root.join(format!("{name}.wal"));
            assert_eq!(std::fs::read(&data).unwrap(), &CONTENT[index][..8]);
            let rows = records(&wal);
            let row = rows.last().unwrap();
            assert_eq!(&row[160..208], model.prefix);
            assert_eq!(row[280], 0);
            assert_eq!(&row[8..40], session(name, 7).client.as_bytes());
            assert!(ReceiverJournalFile::open_existing(&wal, &data).is_err());
            inodes.push(std::fs::metadata(&data).unwrap().ino());
            histories.push(std::fs::read(&wal).unwrap());
            peers.push(wire);
            models.push(model);
        }
        // Kill only after real ACKs, matching durable WALs, data and held locks.
        original.crash();
        drop(peers);
        let mut restored = Process::spawn(&root, "restore", workers, address);
        assert_eq!(restored.ready(), address);
        for (index, name) in CLIENTS.into_iter().enumerate() {
            let mut wire = Wire::connect(address, name);
            models[index].hello(&mut wire, false);
            models[index].send_epoch(&mut wire, &CONTENT[index][8..]);
            models[index].finish(&mut wire);
        }
        restored.done();
        for (index, name) in CLIENTS.into_iter().enumerate() {
            let data = root.join(format!("{name}.data"));
            let wal = root.join(format!("{name}.wal"));
            assert_eq!(std::fs::read(&data).unwrap(), CONTENT[index]);
            assert_eq!(std::fs::metadata(&data).unwrap().ino(), inodes[index]);
            assert!(std::fs::read(&wal).unwrap().starts_with(&histories[index]));
            let rows = records(&wal);
            assert_eq!(rows.last().unwrap()[280], 2);
            histories[index] = std::fs::read(&wal).unwrap();
        }
        let mut receipt = Process::spawn(&root, "receipt", workers, address);
        assert_eq!(receipt.ready(), address);
        for (index, name) in CLIENTS.into_iter().enumerate() {
            let mut wire = Wire::connect(address, name);
            models[index].hello(&mut wire, true);
            models[index].finish(&mut wire);
        }
        receipt.done();
        for (index, name) in CLIENTS.into_iter().enumerate() {
            let data = root.join(format!("{name}.data"));
            let wal = root.join(format!("{name}.wal"));
            assert_eq!(std::fs::read(&data).unwrap(), CONTENT[index]);
            assert_eq!(std::fs::metadata(&data).unwrap().ino(), inodes[index]);
            assert!(std::fs::read(&wal).unwrap().starts_with(&histories[index]));
            let saved = ReceiverJournalFile::open_existing(&wal, &data)
                .unwrap()
                .checkpoint()
                .unwrap();
            assert_eq!(saved.attempts(), 3);
            assert_eq!(saved.maximum_attempts(), 4);
            assert!(saved.committed_receipt().is_some());
        }
    }
}
