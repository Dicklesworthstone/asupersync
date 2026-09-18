//! Real executable receiver restoration, composed with journaled sender restart.
//! TLS relay faults are opaque; disk and WAL witnesses precede process kills.
//! Only test-owned processes are signalled. All fixtures/history are retained.
#![cfg(all(
    unix,
    feature = "atp-cli",
    feature = "tls",
    not(target_arch = "wasm32")
))]

use asupersync::net::atp::sdk::native_auth::live::commit::resume::journal::file::SenderJournalFile;
use asupersync::net::atp::sdk::native_auth::live::commit::resume::receiver_journal::file::ReceiverJournalFile;
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use rustls::pki_types::{CertificateDer, pem::PemObject};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const BINARY: &str = env!("CARGO_BIN_EXE_atpd-live");
const WAIT: Duration = Duration::from_secs(20);

struct Fixture {
    root: PathBuf,
    inbox: PathBuf,
    allowed: String,
    next: AtomicUsize,
}
impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap().keep();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let inbox = root.join("inbox");
        std::fs::create_dir(&inbox).unwrap();
        std::fs::set_permissions(&inbox, std::fs::Permissions::from_mode(0o700)).unwrap();
        let fixture: Value =
            serde_json::from_str(include_str!("fixtures/atp_native_auth_identities.json")).unwrap();
        std::fs::write(root.join("ca.pem"), fixture["ca"].as_str().unwrap()).unwrap();
        for name in ["server", "allowed", "unlisted"] {
            std::fs::write(
                root.join(format!("{name}.pem")),
                fixture["identities"][name]["certificate"].as_str().unwrap(),
            )
            .unwrap();
            let path = root.join(format!("{name}.key"));
            std::fs::write(&path, fixture["identities"][name]["key"].as_str().unwrap()).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let cert = CertificateDer::pem_reader_iter(&mut BufReader::new(
            fixture["identities"]["allowed"]["certificate"]
                .as_str()
                .unwrap()
                .as_bytes(),
        ))
        .next()
        .unwrap()
        .unwrap();
        Self {
            root,
            inbox,
            allowed: hex::encode(Sha256::digest(cert.as_ref())),
            next: AtomicUsize::new(0),
        }
    }
    fn unique(&self, kind: &str) -> PathBuf {
        self.root.join(format!(
            "{}.{kind}",
            self.next.fetch_add(1, Ordering::SeqCst)
        ))
    }
    fn identity(&self, name: &str) -> Value {
        json!({"certificate": self.root.join(format!("{name}.pem")),
            "private_key": self.root.join(format!("{name}.key"))})
    }
    fn json_file(&self, value: &Value) -> PathBuf {
        let path = self.unique("json");
        std::fs::write(&path, serde_json::to_vec(value).unwrap()).unwrap();
        path
    }
    fn source(&self, bytes: &[u8]) -> PathBuf {
        let path = self.unique("source");
        std::fs::write(&path, bytes).unwrap();
        path
    }
    fn receiver_config(&self, workers: usize, maximum: usize) -> Value {
        json!({"schema_version": 1, "bind": "127.0.0.1:0", "identity": self.identity("server"),
            "client_ca": self.root.join("ca.pem"), "clients": [{"certificate_sha256": self.allowed,
                "directory": self.inbox, "max_retained_bytes": maximum, "max_retained_entries": 2}],
            "max_connections": 1, "workers": workers, "epoch_bytes": 4096,
            "max_transfer_bytes": maximum, "operation_timeout_secs": 3, "shutdown_grace_secs": 1})
    }
    fn sender_config(&self, address: SocketAddr, workers: usize, maximum: usize) -> Value {
        json!({"schema_version": 1, "remote": address, "server_name": "localhost",
            "server_ca": self.root.join("ca.pem"), "identity": self.identity("allowed"),
            "workers": workers, "epoch_bytes": 4096, "max_transfer_bytes": maximum,
            "operation_timeout_secs": 3})
    }
    fn receiver(
        &self,
        config: &Value,
        wal: &Path,
        data: &Path,
        create: Option<u32>,
        delay: u64,
    ) -> Process {
        let mut command = Command::new(BINARY);
        command
            .arg(if create.is_some() {
                "receive-journaled"
            } else {
                "resume-receiver"
            })
            .arg("--config")
            .arg(self.json_file(config))
            .arg("--journal")
            .arg(wal)
            .arg("--data")
            .arg(data)
            .arg("--retry-delay-ms")
            .arg(delay.to_string())
            .args(["--proof-recovery-secs", "60"]);
        if let Some(snapshots) = create {
            command
                .args(["--attempts", "8", "--max-snapshots"])
                .arg(snapshots.to_string())
                .args(["--max-journal-bytes", "1048576"]);
        }
        self.launch(command)
    }
    fn sender(
        &self,
        config: &Value,
        wal: &Path,
        input: &Path,
        create: bool,
        delay: u64,
    ) -> Process {
        let mut command = Command::new(BINARY);
        command
            .arg(if create {
                "send-journaled"
            } else {
                "resume-journaled"
            })
            .arg("--config")
            .arg(self.json_file(config))
            .arg("--journal")
            .arg(wal)
            .arg("--input")
            .arg(input)
            .arg("--retry-delay-ms")
            .arg(delay.to_string());
        if create {
            command.args(["--attempts", "8", "--max-snapshots", "64"]);
        }
        self.launch(command)
    }
    fn launch(&self, mut command: Command) -> Process {
        let log = self.unique("stderr");
        command.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&log)
                .unwrap(),
        );
        let mut child = command.spawn().unwrap();
        let output = child.stdout.take().unwrap();
        let (send, events) = mpsc::channel();
        let reader = thread::spawn(move || {
            for line in BufReader::new(output).lines() {
                let value = line
                    .map_err(|e| e.to_string())
                    .and_then(|line| serde_json::from_str(&line).map_err(|e| e.to_string()));
                if send.send(value).is_err() {
                    break;
                }
            }
        });
        Process {
            child,
            reader: Some(reader),
            events,
            log,
            saw_ready: false,
        }
    }
}

struct Process {
    child: Child,
    reader: Option<JoinHandle<()>>,
    events: mpsc::Receiver<Result<Value, String>>,
    log: PathBuf,
    saw_ready: bool,
}
impl Process {
    fn until(&mut self, name: &str) -> Value {
        for _ in 0..128 {
            let event = self
                .events
                .recv_timeout(WAIT)
                .unwrap_or_else(|error| {
                    panic!(
                        "missing {name}: {error}; retained log {}",
                        self.log.display()
                    )
                })
                .unwrap();
            self.saw_ready |= event["event"] == "ready";
            if event["event"] == name {
                return event;
            }
        }
        panic!("event bound exceeded waiting for {name}");
    }
    fn exit(&mut self) -> ExitStatus {
        let start = Instant::now();
        let status = loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                break status;
            }
            assert!(
                start.elapsed() < WAIT,
                "process deadline; log {}",
                self.log.display()
            );
            thread::sleep(Duration::from_millis(5));
        };
        if let Some(reader) = self.reader.take() {
            reader.join().unwrap();
        }
        status
    }
    fn crash(&mut self) {
        self.child.kill().unwrap();
        assert!(!self.exit().success());
    }
    fn stop(&mut self, committed: bool) -> Value {
        kill(
            Pid::from_raw(i32::try_from(self.child.id()).unwrap()),
            Signal::SIGTERM,
        )
        .unwrap();
        let result = self.until("receive_result");
        assert_eq!(result["drained"], true);
        assert_eq!(self.exit().success(), committed);
        result
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

fn relay_copy(
    mut from: TcpStream,
    mut to: TcpStream,
    stop: Arc<AtomicBool>,
    cut: Option<(PathBuf, Arc<AtomicBool>)>,
) {
    let mut bytes = [0; 4096];
    while !stop.load(Ordering::SeqCst) {
        let count = match from.read(&mut bytes) {
            Ok(0) => break,
            Ok(count) => count,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            Err(_) => break,
        };
        if let Some((path, flag)) = &cut {
            if std::fs::metadata(path).is_ok_and(|m| m.len() >= 4096)
                && !flag.swap(true, Ordering::SeqCst)
            {
                break; // Discard encrypted ACK bytes after the actual data witness.
            }
        }
        if to.write_all(&bytes[..count]).is_err() {
            break;
        }
    }
    let _ = from.shutdown(Shutdown::Both);
    let _ = to.shutdown(Shutdown::Both);
}
struct Relay {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    cut: Arc<AtomicBool>,
    connections: Arc<AtomicUsize>,
    worker: Option<JoinHandle<()>>,
}
impl Relay {
    fn new(target: SocketAddr, data: PathBuf) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let cut = Arc::new(AtomicBool::new(false));
        let connections = Arc::new(AtomicUsize::new(0));
        let (stopped, cut_flag, count) = (
            Arc::clone(&stop),
            Arc::clone(&cut),
            Arc::clone(&connections),
        );
        let worker = thread::spawn(move || {
            let mut jobs = Vec::new();
            while !stopped.load(Ordering::SeqCst) {
                let incoming = match listener.accept() {
                    Ok((tcp, _)) => tcp,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(error) => panic!("relay accept: {error}"),
                };
                assert!(count.fetch_add(1, Ordering::SeqCst) < 16);
                let outgoing = TcpStream::connect_timeout(&target, WAIT).unwrap();
                for tcp in [&incoming, &outgoing] {
                    tcp.set_read_timeout(Some(Duration::from_millis(100)))
                        .unwrap();
                    tcp.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
                }
                let (a, b, stop) = (
                    incoming.try_clone().unwrap(),
                    outgoing.try_clone().unwrap(),
                    Arc::clone(&stopped),
                );
                jobs.push(thread::spawn(move || relay_copy(a, b, stop, None)));
                let (stop, flag, path) =
                    (Arc::clone(&stopped), Arc::clone(&cut_flag), data.clone());
                jobs.push(thread::spawn(move || {
                    relay_copy(outgoing, incoming, stop, Some((path, flag)))
                }));
            }
            for job in jobs {
                job.join().unwrap();
            }
        });
        Self {
            address,
            stop,
            cut,
            connections,
            worker: Some(worker),
        }
    }
}
impl Drop for Relay {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            worker.join().unwrap();
        }
    }
}

// Independent complete-WAL verification, not the production file decoder.
fn receiver_records(path: &Path) -> Vec<Vec<u8>> {
    let bytes = std::fs::read(path).unwrap();
    assert!(bytes.len() <= 1_048_576);
    assert_eq!(&bytes[..8], b"ATPRFL01");
    let checksum = |previous: &[u8], body: &[u8]| {
        let mut h = Sha256::new();
        h.update(b"asupersync.atp.receiver-file-journal.v1");
        h.update(previous);
        h.update(body);
        h.finalize().to_vec()
    };
    let mut previous = checksum(&[], &bytes[..64]);
    assert_eq!(&bytes[64..96], previous);
    let mut offset = 96;
    let mut states = Vec::new();
    while offset < bytes.len() {
        let frame = &bytes[offset..offset + 16];
        assert_eq!(
            u64::from_be_bytes(frame[..8].try_into().unwrap()),
            states.len() as u64
        );
        assert_eq!(&frame[12..], &[0; 4]);
        let size = u32::from_be_bytes(frame[8..12].try_into().unwrap()) as usize;
        assert!((317..=65_933).contains(&size));
        let end = offset + 16 + size;
        let digest = checksum(&previous, &bytes[offset..end]);
        assert_eq!(&bytes[end..end + 32], digest);
        let state = &bytes[offset + 16..end];
        assert_eq!(&state[..8], b"ATPRCV01");
        let mut h = Sha256::new();
        h.update(b"asupersync.atp.receiver-checkpoint.v1");
        h.update(&state[..size - 32]);
        assert_eq!(&state[size - 32..], h.finalize().as_slice());
        states.push(state.to_vec());
        previous = digest;
        offset = end + 32;
    }
    assert_eq!(offset, bytes.len());
    states
}

struct Interrupted {
    receiver_config: Value,
    sender_config: Value,
    receiver_wal: PathBuf,
    sender_wal: PathBuf,
    data: PathBuf,
    source: PathBuf,
    bytes: Vec<u8>,
    address: SocketAddr,
    relay: Relay,
}
fn interrupt(fixture: &Fixture, workers: usize) -> Interrupted {
    let bytes: Vec<_> = (0_usize..12293)
        .map(|n| ((n * 29) ^ (n / 251)).to_le_bytes()[0])
        .collect();
    let source = fixture.source(&bytes);
    let data = fixture.inbox.join("transfer.data");
    let receiver_wal = fixture.unique("receiver-wal");
    let sender_wal = fixture.unique("sender-wal");
    let mut receiver_config = fixture.receiver_config(workers, bytes.len());
    let mut receiver = fixture.receiver(&receiver_config, &receiver_wal, &data, Some(64), 60_000);
    let ready = receiver.until("ready");
    assert_eq!(ready["mode"], "journaled_single");
    let address = ready["address"].as_str().unwrap().parse().unwrap();
    receiver_config["bind"] = json!(address);
    let relay = Relay::new(address, data.clone());
    let sender_config = fixture.sender_config(relay.address, workers, bytes.len());
    let mut sender = fixture.sender(&sender_config, &sender_wal, &source, true, 60_000);
    let sent = sender.until("journal_attempt");
    let received = receiver.until("receiver_journal_attempt");
    assert!(relay.cut.load(Ordering::SeqCst));
    assert_eq!(sent["retry_eligible"], true);
    assert_eq!(sent["journal"]["source_eof"], false);
    assert_eq!(sent["journal"]["saved_pending_bytes"], 4096);
    assert_eq!(received["transfer"]["flushed_prefix_bytes"], 4096);
    assert_eq!(received["checkpoint"]["phase"], "receiving");
    assert_eq!(std::fs::read(&data).unwrap(), bytes[..4096]);
    assert_eq!(receiver_records(&receiver_wal).last().unwrap()[280], 0);
    assert!(ReceiverJournalFile::open_existing(&receiver_wal, &data).is_err());
    assert!(SenderJournalFile::open_existing(&sender_wal).is_err());
    sender.crash();
    receiver.crash();
    let saved = SenderJournalFile::open_existing(&sender_wal)
        .unwrap()
        .checkpoint()
        .unwrap();
    assert!(!saved.source_eof());
    assert_eq!(saved.attempts(), 1);
    Interrupted {
        receiver_config,
        sender_config,
        receiver_wal,
        sender_wal,
        data,
        source,
        bytes,
        address,
        relay,
    }
}

#[test]
fn both_executables_restart_before_eof_and_complete_the_original_receiver_inode() {
    for workers in [1, 2] {
        let fixture = Fixture::new();
        let state = interrupt(&fixture, workers);
        let old_wal = std::fs::read(&state.receiver_wal).unwrap();
        let inode = std::fs::metadata(&state.data).unwrap();
        let mut receiver = fixture.receiver(
            &state.receiver_config,
            &state.receiver_wal,
            &state.data,
            None,
            25,
        );
        let ready = receiver.until("ready");
        assert_eq!(ready["restored"], true);
        assert_eq!(ready["address"], json!(state.address));
        assert_eq!(ready["checkpoint"]["prefix_bytes"], 4096);
        assert_eq!(ready["attempt_limit"], 8);
        let mut sender = fixture.sender(
            &state.sender_config,
            &state.sender_wal,
            &state.source,
            false,
            25,
        );
        let sent = sender.until("send_result");
        assert!(sender.exit().success());
        let received = receiver.until("receiver_journal_attempt");
        assert_eq!(sent["transfer"]["status"], "complete");
        assert_eq!(received["transfer"]["status"], "complete");
        assert_eq!(sent["transfer"]["receipt"], received["transfer"]["receipt"]);
        assert_eq!(sent["transfer"]["attempts"], 2);
        assert_eq!(received["transfer"]["attempts"], 2);
        assert_eq!(received["checkpoint"]["phase"], "committed");
        // Quiesce the owner before parsing the entire WAL: a new accept attempt
        // can append its counter while a reader otherwise snapshots the file.
        let ended = receiver.stop(true);
        assert_eq!(std::fs::read(&state.data).unwrap(), state.bytes);
        let after = std::fs::metadata(&state.data).unwrap();
        assert_eq!((after.dev(), after.ino()), (inode.dev(), inode.ino()));
        assert_eq!(std::fs::read_dir(&fixture.inbox).unwrap().count(), 2); // original file and lock, no second reservation
        assert_eq!(
            sent["transfer"]["receipt"]["sha256"],
            hex::encode(Sha256::digest(&state.bytes))
        );
        assert!(
            std::fs::read(&state.receiver_wal)
                .unwrap()
                .starts_with(&old_wal)
        );
        assert_eq!(
            receiver_records(&state.receiver_wal).last().unwrap()[280],
            2
        );
        assert_eq!(ended["durable_receipt"], sent["transfer"]["receipt"]);
        assert_eq!(ended["sender_receipt_observed"], false);
        assert_eq!(ended["atomic_publication"], false);
        assert_eq!(state.relay.connections.load(Ordering::SeqCst), 2);
    }
}

#[test]
fn changed_data_and_unreserved_growth_are_refused_before_restored_readiness() {
    for tamper in [true, false] {
        let fixture = Fixture::new();
        let mut state = interrupt(&fixture, 1);
        let before = std::fs::read(&state.receiver_wal).unwrap();
        if tamper {
            let mut file = OpenOptions::new().write(true).open(&state.data).unwrap();
            file.write_all(&[state.bytes[0] ^ 1]).unwrap();
            file.sync_all().unwrap();
        } else {
            // Restart must reserve the missing suffix in addition to unrelated files.
            std::fs::write(fixture.inbox.join("retained-other"), b"x").unwrap();
            state.receiver_config["clients"][0]["max_retained_entries"] = json!(3);
        }
        let data = std::fs::read(&state.data).unwrap();
        let mut refused = fixture.receiver(
            &state.receiver_config,
            &state.receiver_wal,
            &state.data,
            None,
            25,
        );
        if tamper {
            assert_eq!(
                refused.until("receive_result")["transfer"]["status"],
                "preparation_refused"
            );
            assert!(!refused.saw_ready);
        }
        assert!(!refused.exit().success());
        assert!(
            refused
                .events
                .try_iter()
                .all(|event| event.unwrap()["event"] != "ready")
        );
        assert_eq!(std::fs::read(&state.receiver_wal).unwrap(), before);
        assert_eq!(std::fs::read(&state.data).unwrap(), data);
        assert!(TcpStream::connect_timeout(&state.address, Duration::from_millis(250)).is_err());
        assert_eq!(state.relay.connections.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn ordinary_and_empty_receivers_use_actual_peer_proof_not_data_file_existence() {
    for bytes in [b"command-level receipt".as_slice(), b"".as_slice()] {
        let fixture = Fixture::new();
        let maximum = bytes.len().max(1);
        let wal = fixture.unique("receiver-wal");
        let data = fixture.inbox.join("transfer.data");
        let mut receiver = fixture.receiver(
            &fixture.receiver_config(2, maximum),
            &wal,
            &data,
            Some(32),
            25,
        );
        let ready = receiver.until("ready");
        assert!(ready["checkpoint"].is_null());
        assert_eq!(std::fs::metadata(&data).unwrap().len(), 0);
        assert_eq!(std::fs::metadata(&wal).unwrap().len(), 96);
        let address = ready["address"].as_str().unwrap().parse().unwrap();
        let mut sender = fixture.sender(
            &fixture.sender_config(address, 1, maximum),
            &fixture.unique("sender-wal"),
            &fixture.source(bytes),
            true,
            25,
        );
        let sent = sender.until("send_result");
        assert!(sender.exit().success());
        let received = receiver.until("receiver_journal_attempt");
        assert_eq!(received["checkpoint"]["phase"], "committed");
        assert_eq!(received["transfer"]["receipt"], sent["transfer"]["receipt"]);
        let ended = receiver.stop(true);
        assert_eq!(std::fs::read(&data).unwrap(), bytes);
        assert_eq!(receiver_records(&wal).last().unwrap()[280], 2);
        assert_eq!(ended["durable_receipt"], sent["transfer"]["receipt"]);
    }
}

#[test]
fn receiver_snapshot_exhaustion_prevents_data_writes_and_remains_exhausted_on_restore() {
    let fixture = Fixture::new();
    let wal = fixture.unique("receiver-wal");
    let data = fixture.inbox.join("transfer.data");
    let mut config = fixture.receiver_config(1, 8);
    let mut receiver = fixture.receiver(&config, &wal, &data, Some(1), 25);
    let address = receiver.until("ready")["address"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    config["bind"] = json!(address);
    let mut send_config = fixture.sender_config(address, 1, 8);
    send_config["operation_timeout_secs"] = json!(1);
    let mut sender = fixture.sender(
        &send_config,
        &fixture.unique("sender-wal"),
        &fixture.source(b"12345678"),
        true,
        25,
    );
    let received = receiver.until("receive_result");
    assert!(!receiver.exit().success());
    assert_eq!(received["transfer"]["status"], "journal_blocked");
    assert_eq!(received["transfer"]["persistence"]["storage_full"], true);
    assert!(received["durable_receipt"].is_null());
    assert_eq!(std::fs::metadata(&data).unwrap().len(), 0);
    let before = std::fs::read(&wal).unwrap();
    assert_eq!(receiver_records(&wal).len(), 1);
    assert_ne!(
        sender.until("send_result")["transfer"]["status"],
        "complete"
    );
    assert!(!sender.exit().success());
    let mut restored = fixture.receiver(&config, &wal, &data, None, 25);
    let result = restored.until("receive_result");
    assert!(!restored.exit().success());
    assert_eq!(result["transfer"]["status"], "journal_blocked");
    assert_eq!(std::fs::read(&wal).unwrap(), before);
    assert_eq!(std::fs::metadata(&data).unwrap().len(), 0);
}

#[test]
fn preflight_never_recreates_history_and_tls_refusal_never_creates_a_checkpoint() {
    let fixture = Fixture::new();
    let wal = fixture.unique("receiver-wal");
    let data = fixture.inbox.join("transfer.data");
    let mut config = fixture.receiver_config(1, 8);
    config["bind"] = json!("127.0.0.1:9443");
    let mut missing = fixture.receiver(&config, &wal, &data, None, 25);
    assert!(!missing.exit().success());
    assert!(!wal.exists());
    assert!(!data.exists());
    assert!(
        missing
            .events
            .try_iter()
            .all(|event| event.unwrap()["event"] != "ready")
    );
    config["bind"] = json!("127.0.0.1:0");
    let mut receiver = fixture.receiver(&config, &wal, &data, Some(16), 25);
    let address = receiver.until("ready")["address"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let mut wrong = fixture.sender_config(address, 1, 8);
    wrong["identity"] = fixture.identity("unlisted");
    let mut command = Command::new(BINARY);
    command
        .args(["send-journaled", "--config"])
        .arg(fixture.json_file(&wrong))
        .arg("--journal")
        .arg(fixture.unique("sender-wal"))
        .arg("--input")
        .arg(fixture.source(b"refused"))
        .args([
            "--attempts",
            "1",
            "--max-snapshots",
            "8",
            "--retry-delay-ms",
            "25",
        ]);
    let mut sender = fixture.launch(command);
    let result = receiver.until("receiver_journal_attempt");
    assert_eq!(result["transfer"]["status"], "tls_failed");
    assert!(result["checkpoint"].is_null());
    assert_ne!(
        sender.until("send_result")["transfer"]["status"],
        "complete"
    );
    assert!(!sender.exit().success());
    assert_eq!(std::fs::metadata(&wal).unwrap().len(), 96);
    assert_eq!(std::fs::metadata(&data).unwrap().len(), 0);
    receiver.stop(false);
}
