//! Receiver restart through real TCP/mTLS and original private data inodes.
//! The independent peer does not use receiver reconciliation helpers. Process
//! death occurs only after an ACK or a witnessed parked partial write/commit.
//! Test-created files and logs are retained, never automatically deleted.
#![cfg(all(
    unix,
    feature = "tls",
    feature = "test-internals",
    not(target_arch = "wasm32")
))]

use asupersync::Cx;
use asupersync::bytes::BytesMut;
use asupersync::codec::Decoder;
use asupersync::fs::File as AsyncFile;
use asupersync::io::AsyncWrite;
use asupersync::net::atp::protocol::codec::AtpFrameCodec;
use asupersync::net::atp::protocol::frames::{Frame, FrameType, ProtocolVersion};
use asupersync::net::atp::sdk::native_auth::live::commit::LiveStreamCommitSink;
use asupersync::net::atp::sdk::native_auth::live::commit::resume::receiver_journal::ReceiverCheckpointPhase;
use asupersync::net::atp::sdk::native_auth::live::commit::resume::receiver_journal::file::{
    JournaledFileReceiver, ReceiverFileLimits, ReceiverJournalFile,
};
use asupersync::net::atp::sdk::native_auth::live::commit::resume::{ResumeError, ResumeReport};
use asupersync::net::atp::sdk::native_auth::live::{
    LiveStreamConfig, LiveStreamError, LiveStreamReceipt, LiveStreamReceiver, LiveStreamSender,
};
use asupersync::net::atp::sdk::{
    AtpSdk, NativeClientAuthorization, NativeClientCertificateId, NativeTlsIdentity, SessionConfig,
};
use asupersync::runtime::{RuntimeBuilder, yield_now};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::future::{Future, poll_fn};
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::task::{Context, Poll, Waker, ready};
use std::thread;
use std::time::{Duration, Instant};

const WAIT: Duration = Duration::from_secs(20);
const DATA: &[u8] = b"abcdefghijklmnop";
fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/atp_native_auth_identities.json")).unwrap()
}
fn cert(name: &str) -> CertificateDer<'static> {
    let value = fixture();
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
    let value = fixture();
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
fn client() -> NativeClientCertificateId {
    NativeClientCertificateId::from_certificate(&cert("allowed"))
}
fn profile() -> LiveStreamConfig {
    let mut profile = LiveStreamConfig::default();
    profile.epoch_bytes = 8;
    profile.max_bytes = 64;
    profile.operation_timeout = Duration::from_secs(8);
    profile
}
fn sdk() -> AtpSdk {
    AtpSdk::new_in_process(SessionConfig {
        max_concurrent_transfers: 2,
        ..SessionConfig::default()
    })
}
fn receiver() -> LiveStreamReceiver {
    sdk()
        .live_stream_receiver(
            profile(),
            NativeTlsIdentity::new(vec![cert("server")], key("server")).unwrap(),
            NativeClientAuthorization::new(roots(), [client()]).unwrap(),
        )
        .unwrap()
}
fn sender() -> LiveStreamSender {
    sdk()
        .live_stream_sender(
            profile(),
            ServerName::try_from("localhost").unwrap(),
            roots(),
            NativeTlsIdentity::new(vec![cert("allowed")], key("allowed")).unwrap(),
        )
        .unwrap()
}
fn limits(snapshots: u32) -> ReceiverFileLimits {
    ReceiverFileLimits {
        max_data_bytes: 64,
        max_snapshots: snapshots,
        max_journal_bytes: 65536,
    }
}
fn directory() -> PathBuf {
    let root = tempfile::tempdir().unwrap().keep();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    root
}
fn write_json(path: &Path, value: Value) {
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
            .expect("receiver journal runtime deadline")
    });
    let value = runtime.block_on(runtime.handle().spawn(future));
    let start = Instant::now();
    while !runtime.is_quiescent() {
        assert!(start.elapsed() < WAIT);
        runtime.block_on(yield_now());
    }
    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
    assert!(runtime.shutdown_timeout(Duration::from_secs(5)));
    value
}

// Independent file-format reader: durability witnesses do not come from the
// production decoder. Check complete framing/hash chains before inspecting state.
fn records(path: &Path) -> Vec<Vec<u8>> {
    let bytes = std::fs::read(path).unwrap();
    assert!((96..=65536).contains(&bytes.len()));
    assert_eq!(&bytes[..8], b"ATPRFL01");
    let chain_hash = |previous: &[u8], body: &[u8]| -> Vec<u8> {
        let mut hash = Sha256::new();
        hash.update(b"asupersync.atp.receiver-file-journal.v1");
        hash.update(previous);
        hash.update(body);
        hash.finalize().to_vec()
    };
    let mut previous = chain_hash(&[], &bytes[..64]);
    assert_eq!(previous, bytes[64..96]);
    let mut offset = 96;
    let mut result = Vec::new();
    while offset < bytes.len() {
        let size = u32::from_be_bytes(bytes[offset + 8..offset + 12].try_into().unwrap()) as usize;
        assert!((317..=65933).contains(&size));
        assert_eq!(
            u64::from_be_bytes(bytes[offset..offset + 8].try_into().unwrap()),
            result.len() as u64
        );
        assert_eq!(&bytes[offset + 12..offset + 16], &[0; 4]);
        let end = offset + 16 + size;
        assert!(end + 32 <= bytes.len());
        let checksum = chain_hash(&previous, &bytes[offset..end]);
        assert_eq!(checksum, bytes[end..end + 32]);
        let saved = bytes[offset + 16..end].to_vec();
        assert_eq!(&saved[..8], b"ATPRCV01");
        let mut hash = Sha256::new();
        hash.update(b"asupersync.atp.receiver-checkpoint.v1");
        hash.update(&saved[..saved.len() - 32]);
        assert_eq!(hash.finalize().as_slice(), &saved[saved.len() - 32..]);
        assert_eq!(&saved[8..40], client().as_bytes());
        previous = checksum;
        result.push(saved);
        offset = end + 32;
    }
    assert_eq!(offset, bytes.len());
    result
}

struct Peer {
    stream: rustls::StreamOwned<rustls::ClientConnection, TcpStream>,
    codec: AtpFrameCodec,
    buffer: BytesMut,
}
impl Peer {
    fn connect(address: SocketAddr) -> Self {
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots())
        .with_client_auth_cert(vec![cert("allowed")], key("allowed"))
        .unwrap();
        config.alpn_protocols = vec![b"atp-live-resume/1".to_vec()];
        config.resumption = rustls::client::Resumption::disabled();
        let tcp = TcpStream::connect_timeout(&address, WAIT).unwrap();
        tcp.set_read_timeout(Some(WAIT)).unwrap();
        tcp.set_write_timeout(Some(WAIT)).unwrap();
        let connection = rustls::ClientConnection::new(
            Arc::new(config),
            ServerName::try_from("localhost").unwrap(),
        )
        .unwrap();
        Self {
            stream: rustls::StreamOwned::new(connection, tcp),
            codec: AtpFrameCodec::with_max_frame_size(66000),
            buffer: BytesMut::new(),
        }
    }
    fn send(&mut self, kind: FrameType, payload: Vec<u8>) {
        let bytes = Frame::new(ProtocolVersion::V0, kind, payload)
            .unwrap()
            .to_wire_bytes()
            .unwrap();
        self.stream.write_all(&bytes).unwrap();
        self.stream.flush().unwrap();
    }
    fn read(&mut self, kind: FrameType) -> io::Result<Vec<u8>> {
        loop {
            if let Some(frame) = self
                .codec
                .decode(&mut self.buffer)
                .map_err(io::Error::other)?
            {
                assert_eq!(frame.frame_type(), kind);
                return Ok(frame.payload().to_vec());
            }
            let mut bytes = [0; 4096];
            let count = self.stream.read(&mut bytes)?;
            if count == 0 {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
            }
            self.buffer.extend_from_slice(&bytes[..count]);
            assert!(self.buffer.len() <= 66000);
        }
    }
    fn hello(&mut self) -> Vec<u8> {
        let mut hello = b"ATPRSM01ATPLIVE1".to_vec();
        hello.extend_from_slice(&[7; 32]);
        hello.extend_from_slice(&8_u32.to_be_bytes());
        hello.extend_from_slice(&64_u64.to_be_bytes());
        self.send(FrameType::Handshake, hello.clone());
        let state = self.read(FrameType::HandshakeAck).unwrap();
        assert_eq!(state.len(), 141);
        assert_eq!(state[..60], hello);
        assert_eq!(
            self.stream.conn.peer_certificates().unwrap()[0],
            cert("server")
        );
        state
    }
    fn epoch(&mut self, prefix: &[u8], data: &[u8]) -> Vec<u8> {
        let mut payload = prefix.to_vec();
        payload.extend_from_slice(&Sha256::digest(data));
        payload.extend_from_slice(data);
        let mut hash = Sha256::new();
        hash.update(b"asupersync.atp.live.epoch.v1");
        hash.update(&prefix[16..]);
        hash.update(&payload);
        let mut next = (u64::from_be_bytes(prefix[..8].try_into().unwrap()) + 1)
            .to_be_bytes()
            .to_vec();
        next.extend_from_slice(
            &(u64::from_be_bytes(prefix[8..16].try_into().unwrap()) + data.len() as u64)
                .to_be_bytes(),
        );
        next.extend_from_slice(&hash.finalize());
        self.send(FrameType::ObjectData, payload);
        next
    }
    fn finish(&mut self, prefix: &[u8], data: &[u8]) {
        let mut final_value = prefix.to_vec();
        final_value.extend_from_slice(&Sha256::digest(data));
        self.send(FrameType::ObjectComplete, final_value.clone());
        assert_eq!(self.read(FrameType::Proof).unwrap(), final_value);
    }
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
            .open(root.join(format!("{mode}.log")))
            .unwrap();
        let child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "receiver_journal_process_worker", "--nocapture"])
            .env("ASUPERSYNC_RECEIVER_JOURNAL_CASE", mode)
            .env("ASUPERSYNC_RECEIVER_JOURNAL_ROOT", root)
            .env("ASUPERSYNC_RECEIVER_JOURNAL_WORKERS", workers.to_string())
            .env("ASUPERSYNC_RECEIVER_JOURNAL_ADDRESS", address.to_string())
            .stdin(Stdio::null())
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap();
        Self {
            child,
            root: root.to_owned(),
            mode: mode.to_owned(),
        }
    }
    fn witness(&mut self, name: &str) -> Value {
        let path = self.root.join(name);
        let start = Instant::now();
        loop {
            if let Ok(bytes) = std::fs::read(&path) {
                assert!(bytes.len() <= 8192);
                if let Ok(value) = serde_json::from_slice(&bytes) {
                    return value;
                }
            }
            assert!(
                start.elapsed() < WAIT,
                "missing witness {name}; retained {}.log",
                self.mode
            );
            if let Some(status) = self.child.try_wait().unwrap() {
                // The last read may have raced the completed witness write.
                if let Ok(bytes) = std::fs::read(&path) {
                    assert!(bytes.len() <= 8192);
                    if let Ok(value) = serde_json::from_slice(&bytes) {
                        return value;
                    }
                }
                panic!("worker {} ended {status} before {name}", self.mode);
            }
            thread::sleep(Duration::from_millis(2));
        }
    }
    fn ready(&mut self) -> SocketAddr {
        self.witness(&format!("{}.ready", self.mode))["address"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap()
    }
    fn done(&mut self) -> Value {
        self.witness(&format!("{}.done", self.mode))
    }
    fn wait(&mut self) -> ExitStatus {
        let start = Instant::now();
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            assert!(start.elapsed() < WAIT, "worker {} did not exit", self.mode);
            thread::sleep(Duration::from_millis(2));
        }
    }
    fn crash(&mut self) {
        self.child.kill().unwrap();
        assert!(!self.wait().success());
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

// Test-only sink: deterministic partial-write/commit crash points, not sleeps.
// The production file journal still synchronizes this exact test-owned inode.
struct ParkedSink {
    file: AsyncFile,
    written: usize,
    park_at: Option<usize>,
    commit_park: bool,
    root: PathBuf,
    witnessed: bool,
    waker: Option<Waker>,
}
impl ParkedSink {
    fn park(&mut self, cx: &Context<'_>) {
        self.waker = Some(cx.waker().clone());
        if !self.witnessed {
            write_json(
                &self.root.join("parked"),
                json!({"written": self.written, "commit": self.commit_park}),
            );
            self.witnessed = true;
        }
    }
}
impl AsyncWrite for ParkedSink {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.park_at == Some(this.written) {
            this.park(cx);
            return Poll::Pending;
        }
        let maximum = this
            .park_at
            .map_or(3, |limit| (limit - this.written).min(3))
            .min(bytes.len());
        let result = ready!(Pin::new(&mut this.file).poll_write(cx, &bytes[..maximum]));
        if let Ok(count) = result {
            this.written += count;
        }
        Poll::Ready(result)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().file).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        panic!("test sink requires explicit commit")
    }
}
impl LiveStreamCommitSink for ParkedSink {
    fn poll_commit(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        _: &LiveStreamReceipt,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        assert!(this.commit_park);
        this.park(cx);
        Poll::Pending
    }
}

fn report_json(report: &ResumeReport) -> Value {
    let status = match &report.outcome {
        Ok(_) => "complete",
        Err(ResumeError::ReceiverJournal(error))
            if error
                .source
                .as_ref()
                .is_some_and(|e| e.kind() == io::ErrorKind::StorageFull) =>
        {
            "storage_full"
        }
        other => panic!("unexpected worker result {other:?}"),
    };
    json!({"status": status, "attempts": report.attempts, "sink_written_bytes": report.sink_written_bytes,
        "receipt_reused": report.receipt_reused, "completed": report.completed.is_some(),
        "sha256": report.outcome.as_ref().ok().map(|r| hex::encode(r.source_sha256))})
}

#[test]
fn receiver_journal_process_worker() {
    let Ok(mode) = std::env::var("ASUPERSYNC_RECEIVER_JOURNAL_CASE") else {
        return;
    };
    let root = PathBuf::from(std::env::var_os("ASUPERSYNC_RECEIVER_JOURNAL_ROOT").unwrap());
    let workers = std::env::var("ASUPERSYNC_RECEIVER_JOURNAL_WORKERS")
        .unwrap()
        .parse()
        .unwrap();
    let address = std::env::var("ASUPERSYNC_RECEIVER_JOURNAL_ADDRESS")
        .unwrap()
        .parse()
        .unwrap();
    let journal = root.join("receiver.wal");
    let data = root.join("receiver.data");
    let creating = matches!(mode.as_str(), "begin" | "partial" | "commit" | "capacity");
    let store = if creating {
        ReceiverJournalFile::create_new(
            &journal,
            &data,
            limits(if mode == "capacity" { 1 } else { 32 }),
        )
        .unwrap()
    } else {
        ReceiverJournalFile::open_existing(&journal, &data).unwrap()
    };
    let work_root = root.clone();
    let work_mode = mode.clone();
    let value = run(workers, async move {
        let cx = Cx::current().unwrap();
        let authority = receiver();
        if work_mode.starts_with("reject-") {
            let expected = if work_mode == "reject-client" {
                NativeClientCertificateId::from_sha256([9; 32])
            } else {
                client()
            };
            let result = store
                .bind_restored(&authority, &cx, address, expected)
                .await;
            match (work_mode.as_str(), result) {
                ("reject-client", Err(ResumeError::PeerIdentity)) => {}
                ("reject-unresolved", Err(ResumeError::Transfer(LiveStreamError::Io(error)))) => {
                    assert_eq!(error.kind(), io::ErrorKind::Other);
                    assert_eq!(
                        error.to_string(),
                        "receiver application commit remains unresolved"
                    );
                }
                ("reject-corrupt", Err(ResumeError::Transfer(LiveStreamError::Io(error)))) => {
                    assert_eq!(error.kind(), io::ErrorKind::InvalidData)
                }
                other => panic!("wrong restore refusal {other:?}"),
            }
            assert_eq!(authority.active_streams(), 0);
            return json!({"rejected_before_bind": true});
        }
        if matches!(work_mode.as_str(), "partial" | "commit") {
            let file = OpenOptions::new()
                .read(true)
                .append(true)
                .open(&data)
                .unwrap();
            let sink = ParkedSink {
                file: AsyncFile::from_std(file),
                written: 0,
                park_at: (work_mode == "partial").then_some(11),
                commit_park: work_mode == "commit",
                root: work_root.clone(),
                witnessed: false,
                waker: None,
            };
            let mut incoming = authority
                .bind_resumable_committing(&cx, address, client(), sink, 4)
                .await
                .unwrap();
            write_json(
                &work_root.join(format!("{work_mode}.ready")),
                json!({"address": incoming.local_addr().unwrap()}),
            );
            let mut store = store;
            let report = incoming.receive_journaled(&cx, &mut store).await;
            panic!("parent must kill the witnessed parked process, got {report:?}");
        }
        let mut incoming = if creating {
            store
                .bind_new(&authority, &cx, address, client(), 4)
                .await
                .unwrap()
        } else {
            store
                .bind_restored(&authority, &cx, address, client())
                .await
                .unwrap()
        };
        write_json(
            &work_root.join(format!("{work_mode}.ready")),
            json!({"address": incoming.local_addr().unwrap()}),
        );
        let report = incoming.receive(&cx).await;
        let value = report_json(&report);
        if report.outcome.is_ok() {
            assert_eq!(
                incoming.checkpoint().unwrap().phase(),
                ReceiverCheckpointPhase::Committed
            );
        }
        drop(incoming);
        assert_eq!(authority.active_streams(), 0);
        value
    });
    // This witness follows the actual assertions AND confirmed runtime drain.
    write_json(&root.join(format!("{mode}.done")), value);
}

#[test]
fn killed_receivers_restore_acknowledged_and_partially_written_epochs_without_duplicate_bytes() {
    for workers in [1, 2] {
        for partial in [false, true] {
            let root = directory();
            let journal = root.join("receiver.wal");
            let data = root.join("receiver.data");
            let mut original = Process::spawn(
                &root,
                if partial { "partial" } else { "begin" },
                workers,
                "127.0.0.1:0".parse().unwrap(),
            );
            let address = original.ready();
            let mut peer = Peer::connect(address);
            let hello = peer.hello();
            let first = peer.epoch(&hello[60..108], &DATA[..8]);
            assert_eq!(peer.read(FrameType::Control).unwrap(), first);
            let persisted = records(&journal);
            assert_eq!(&persisted.last().unwrap()[160..208], first);
            if partial {
                peer.epoch(&first, &DATA[8..]);
                let parked = original.witness("parked");
                assert_eq!(parked["written"], 11);
                assert_eq!(parked["commit"], false);
            }
            let expected = if partial { 11 } else { 8 };
            assert_eq!(std::fs::read(&data).unwrap(), DATA[..expected]);
            let inode = std::fs::metadata(&data).unwrap();
            assert!(ReceiverJournalFile::open_existing(&journal, &data).is_err());
            let saved = records(&journal).pop().unwrap();
            assert_eq!(saved[280], 0);
            assert_eq!(u64::from_be_bytes(saved[168..176].try_into().unwrap()), 8);
            assert_eq!(
                u32::from_be_bytes(saved[281..285].try_into().unwrap()),
                if partial { 88 } else { 0 }
            );
            original.crash();
            drop(peer);
            let history = std::fs::read(&journal).unwrap();
            let mut restored = Process::spawn(&root, "restore", workers, address);
            assert_eq!(restored.ready(), address);
            let mut peer = Peer::connect(address);
            let state = peer.hello();
            assert_eq!(&state[60..108], first);
            assert_eq!(&state[108..140], Sha256::digest(&DATA[..8]).as_slice());
            assert_eq!(state[140], 0);
            let final_prefix = peer.epoch(&first, &DATA[8..]);
            assert_eq!(peer.read(FrameType::Control).unwrap(), final_prefix);
            peer.finish(&final_prefix, DATA);
            let done = restored.done();
            assert!(restored.wait().success());
            drop(peer);
            assert_eq!(done["status"], "complete");
            assert_eq!(done["attempts"], 2);
            assert_eq!(done["sink_written_bytes"], DATA.len());
            assert_eq!(done["sha256"], hex::encode(Sha256::digest(DATA)));
            assert_eq!(std::fs::read(&data).unwrap(), DATA);
            let finished = std::fs::metadata(&data).unwrap();
            assert_eq!((finished.dev(), finished.ino()), (inode.dev(), inode.ino()));
            assert!(std::fs::read(&journal).unwrap().starts_with(&history));
            assert_eq!(records(&journal).last().unwrap()[280], 2);

            // A third receiver process reuses only the completed receipt. It is
            // not another file transaction or another data upload.
            let mut receipt = Process::spawn(&root, "receipt", workers, address);
            assert_eq!(receipt.ready(), address);
            let mut peer = Peer::connect(address);
            let state = peer.hello();
            assert_eq!(state[140], 1);
            assert_eq!(&state[60..108], final_prefix);
            peer.finish(&final_prefix, DATA);
            let done = receipt.done();
            assert!(receipt.wait().success());
            assert_eq!(done["receipt_reused"], true);
            assert_eq!(done["attempts"], 3);
            assert_eq!(std::fs::read(&data).unwrap(), DATA);
            assert_eq!(std::fs::metadata(&data).unwrap().ino(), inode.ino());
        }
    }
}

#[test]
fn corrupt_data_wrong_client_and_uncertain_commit_are_refused_before_restored_listening() {
    for case in ["prefix", "extra", "client", "unresolved"] {
        let root = directory();
        let journal = root.join("receiver.wal");
        let data = root.join("receiver.data");
        let mut original = Process::spawn(
            &root,
            if case == "unresolved" {
                "commit"
            } else {
                "begin"
            },
            2,
            "127.0.0.1:0".parse().unwrap(),
        );
        let address = original.ready();
        let mut peer = Peer::connect(address);
        let state = peer.hello();
        let prefix = peer.epoch(&state[60..108], &DATA[..8]);
        assert_eq!(peer.read(FrameType::Control).unwrap(), prefix);
        if case == "unresolved" {
            let mut final_value = prefix;
            final_value.extend_from_slice(&Sha256::digest(&DATA[..8]));
            peer.send(FrameType::ObjectComplete, final_value);
            assert_eq!(original.witness("parked")["commit"], true);
            assert_eq!(records(&journal).last().unwrap()[280], 1);
        }
        original.crash();
        drop(peer);
        if case == "prefix" {
            let mut file = OpenOptions::new().write(true).open(&data).unwrap();
            file.seek(SeekFrom::Start(0)).unwrap();
            file.write_all(b"X").unwrap();
            file.sync_all().unwrap();
        } else if case == "extra" {
            let mut file = OpenOptions::new().append(true).open(&data).unwrap();
            file.write_all(b"X").unwrap();
            file.sync_all().unwrap();
        }
        let old_data = std::fs::read(&data).unwrap();
        let old_journal = std::fs::read(&journal).unwrap();
        let mode = match case {
            "client" => "reject-client",
            "unresolved" => "reject-unresolved",
            _ => "reject-corrupt",
        };
        let mut rejected = Process::spawn(&root, mode, 1, address);
        assert_eq!(rejected.done()["rejected_before_bind"], true);
        assert!(rejected.wait().success());
        assert!(!root.join(format!("{mode}.ready")).exists());
        assert!(TcpStream::connect_timeout(&address, Duration::from_millis(250)).is_err());
        assert_eq!(std::fs::read(&data).unwrap(), old_data);
        assert_eq!(std::fs::read(&journal).unwrap(), old_journal);
    }
}

#[test]
fn persistent_snapshot_exhaustion_withholds_epoch_write_and_cannot_reset_on_reopen() {
    let root = directory();
    let journal = root.join("receiver.wal");
    let data = root.join("receiver.data");
    let mut original = Process::spawn(&root, "capacity", 1, "127.0.0.1:0".parse().unwrap());
    let address = original.ready();
    let mut peer = Peer::connect(address);
    let state = peer.hello();
    peer.epoch(&state[60..108], &DATA[..8]);
    assert!(peer.read(FrameType::Control).is_err());
    let failed = original.done();
    assert!(original.wait().success());
    drop(peer);
    assert_eq!(failed["status"], "storage_full");
    assert_eq!(failed["completed"], false);
    assert_eq!(failed["sink_written_bytes"], 0);
    assert_eq!(std::fs::metadata(&data).unwrap().len(), 0);
    assert_eq!(records(&journal).len(), 1);
    let history = std::fs::read(&journal).unwrap();
    let mut restarted = Process::spawn(&root, "capacity-restore", 2, address);
    assert_eq!(restarted.ready(), address);
    let failed = restarted.done();
    assert!(restarted.wait().success());
    assert_eq!(failed["status"], "storage_full");
    assert_eq!(failed["attempts"], 2);
    assert_eq!(std::fs::read(&journal).unwrap(), history);
    assert_eq!(std::fs::metadata(&data).unwrap().len(), 0);
}

#[test]
fn public_native_sender_and_journaled_receiver_finish_nonempty_and_empty_files() {
    for workers in [1, 2] {
        for content in [DATA, b"".as_slice()] {
            let root = directory();
            let journal = root.join("receiver.wal");
            let data = root.join("receiver.data");
            let store = ReceiverJournalFile::create_new(&journal, &data, limits(32)).unwrap();
            let owned_journal = journal.clone();
            let owned_data = data.clone();
            run(workers, async move {
                let cx = Cx::current().unwrap();
                let scope = cx.scope();
                let authority = receiver();
                let mut incoming = store
                    .bind_new(&authority, &cx, "127.0.0.1:0".parse().unwrap(), client(), 4)
                    .await
                    .unwrap();
                let address = incoming.local_addr().unwrap();
                let mut worker = cx
                    .spawn_in(&scope, move |child| {
                        let future: Pin<
                            Box<dyn Future<Output = (JournaledFileReceiver, ResumeReport)> + Send>,
                        > = Box::pin(async move {
                            let report = incoming.receive(&child).await;
                            (incoming, report)
                        });
                        future
                    })
                    .unwrap();
                let send = sender();
                let mut outgoing = send.resumable_reader(&cx, address, content, 4).unwrap();
                let sent = outgoing.send(&cx).await;
                let (incoming, received) = poll_fn(|ctx| worker.poll_join(ctx)).await.unwrap();
                assert_eq!(sent.outcome.unwrap(), received.outcome.unwrap());
                assert_eq!(received.sink_written_bytes, content.len() as u64);
                assert_eq!(
                    incoming.checkpoint().unwrap().phase(),
                    ReceiverCheckpointPhase::Committed
                );
                assert!(ReceiverJournalFile::open_existing(&owned_journal, &owned_data).is_err());
                drop(incoming);
                drop(outgoing);
                assert_eq!(authority.active_streams(), 0);
                assert_eq!(send.active_streams(), 0);
            });
            let store = ReceiverJournalFile::open_existing(&journal, &data).unwrap();
            assert_eq!(
                store
                    .checkpoint()
                    .unwrap()
                    .committed_receipt()
                    .unwrap()
                    .source_sha256,
                Sha256::digest(content).as_slice()
            );
            assert_eq!(std::fs::read(&data).unwrap(), content);
            let snapshots = records(&journal);
            assert!(snapshots.iter().any(|s| s[280] == 1));
            assert_eq!(snapshots.last().unwrap()[280], 2);
        }
    }
}
