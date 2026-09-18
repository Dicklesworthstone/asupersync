//! Real pre-EOF sender process loss, with opaque TLS faults and file witnesses.
//! All credentials are public test fixtures. Files/logs are retained, never deleted.
#![cfg(all(feature = "atp-cli", feature = "tls", unix, not(target_arch = "wasm32")))]

use asupersync::net::atp::sdk::native_auth::live::commit::resume::journal::file::SenderJournalFile;
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
use std::sync::{Arc, mpsc, atomic::{AtomicBool, AtomicUsize, Ordering}};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const BINARY: &str = env!("CARGO_BIN_EXE_atpd-live");
const WAIT: Duration = Duration::from_secs(20);

struct Fixture { root: PathBuf, inbox: PathBuf, next: AtomicUsize, client: String }
impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap().keep();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let inbox = root.join("inbox"); std::fs::create_dir(&inbox).unwrap();
        std::fs::set_permissions(&inbox, std::fs::Permissions::from_mode(0o700)).unwrap();
        let identities: Value = serde_json::from_str(include_str!("fixtures/atp_native_auth_identities.json")).unwrap();
        std::fs::write(root.join("ca.pem"), identities["ca"].as_str().unwrap()).unwrap();
        for name in ["allowed", "server"] {
            std::fs::write(root.join(format!("{name}.pem")), identities["identities"][name]["certificate"].as_str().unwrap()).unwrap();
            let key = root.join(format!("{name}.key"));
            std::fs::write(&key, identities["identities"][name]["key"].as_str().unwrap()).unwrap();
            std::fs::set_permissions(key, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let pem = identities["identities"]["allowed"]["certificate"].as_str().unwrap();
        let certificate = CertificateDer::pem_reader_iter(&mut BufReader::new(pem.as_bytes())).next().unwrap().unwrap();
        Self { root, inbox, next: AtomicUsize::new(0), client: hex::encode(Sha256::digest(certificate.as_ref())) }
    }
    fn unique(&self, suffix: &str) -> PathBuf {
        self.root.join(format!("{}.{suffix}", self.next.fetch_add(1, Ordering::Relaxed)))
    }
    fn json(&self, config: &Value) -> PathBuf {
        let path = self.unique("json"); std::fs::write(&path, serde_json::to_vec(config).unwrap()).unwrap(); path
    }
    fn identity(&self, name: &str) -> Value {
        json!({"certificate": self.root.join(format!("{name}.pem")), "private_key": self.root.join(format!("{name}.key"))})
    }
    fn source(&self, bytes: &[u8]) -> PathBuf {
        let path = self.unique("input"); std::fs::write(&path, bytes).unwrap(); path
    }
    fn receiver(&self, workers: usize, length: usize) -> (Process, SocketAddr) {
        let config = self.json(&json!({"schema_version": 1, "bind": "127.0.0.1:0",
            "identity": self.identity("server"), "client_ca": self.root.join("ca.pem"),
            "clients": [{"certificate_sha256": self.client, "directory": self.inbox,
                "max_retained_bytes": length * 2, "max_retained_entries": 3}],
            "max_connections": 2, "workers": workers, "epoch_bytes": 4096,
            "max_transfer_bytes": length, "operation_timeout_secs": 10, "shutdown_grace_secs": 1}));
        let mut command = Command::new(BINARY);
        command.args(["serve-resumable", "--config"]).arg(config).args([
            "--max-sessions", "2", "--max-sessions-per-client", "2", "--max-session-keys", "8",
            "--attempts-per-session", "8", "--idle-retention-secs", "120", "--proof-recovery-secs", "120",
        ]);
        let mut process = self.launch(command);
        let ready = process.event("ready");
        assert_eq!(ready["profile"], "atp-live-resume/1");
        let address = ready["address"].as_str().unwrap().parse().unwrap();
        (process, address)
    }
    fn config(&self, remote: SocketAddr, workers: usize, length: usize) -> Value {
        json!({"schema_version": 1, "remote": remote, "server_name": "localhost",
            "server_ca": self.root.join("ca.pem"), "identity": self.identity("allowed"),
            "workers": workers, "epoch_bytes": 4096, "max_transfer_bytes": length, "operation_timeout_secs": 10})
    }
    fn sender(&self, config: &Value, source: &Path, journal: &Path, create: Option<(u32, u32)>, delay: u64) -> Process {
        let mut command = Command::new(BINARY);
        command.arg(if create.is_some() { "send-journaled" } else { "resume-journaled" })
            .arg("--config").arg(self.json(config)).arg("--input").arg(source)
            .arg("--journal").arg(journal).arg("--retry-delay-ms").arg(delay.to_string());
        if let Some((attempts, snapshots)) = create {
            command.arg("--attempts").arg(attempts.to_string()).arg("--max-snapshots").arg(snapshots.to_string());
        }
        self.launch(command)
    }
    fn launch(&self, mut command: Command) -> Process {
        let stderr = self.unique("stderr");
        command.stdout(Stdio::piped()).stderr(OpenOptions::new().write(true).create_new(true).open(&stderr).unwrap());
        let mut child = command.spawn().unwrap(); let stdout = child.stdout.take().unwrap();
        let (tx, events) = mpsc::channel();
        let reader = thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let row: Value = serde_json::from_str(&line.unwrap()).unwrap();
                if tx.send(row).is_err() { break; }
            }
        });
        Process { child, events, reader: Some(reader), stderr }
    }
}

struct Process { child: Child, events: mpsc::Receiver<Value>, reader: Option<JoinHandle<()>>, stderr: PathBuf }
impl Process {
    fn event(&mut self, expected: &str) -> Value {
        let row = self.events.recv_timeout(WAIT).unwrap_or_else(|e| panic!("missing {expected}: {e}; {}", self.stderr.display()));
        assert_eq!(row["event"], expected, "unexpected process result: {row}"); row
    }
    fn result(&mut self) -> Value {
        for _ in 0..8 {
            let row = self.events.recv_timeout(WAIT).unwrap();
            if row["event"] == "send_result" { return row; }
            assert_eq!(row["event"], "journal_attempt");
        }
        panic!("sender exceeded bounded result count");
    }
    fn exit(&mut self) -> ExitStatus {
        let start = Instant::now();
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                if let Some(reader) = self.reader.take() { reader.join().unwrap(); }
                return status;
            }
            assert!(start.elapsed() < WAIT, "process did not exit; {}", self.stderr.display());
            thread::sleep(Duration::from_millis(5));
        }
    }
    fn stop(&mut self) {
        kill(Pid::from_raw(self.child.id().try_into().unwrap()), Signal::SIGTERM).unwrap();
        assert_eq!(self.event("stopped")["drained"], true);
        assert!(self.exit().success());
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) { let _ = self.child.kill(); }
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() { let _ = reader.join(); }
    }
}

fn paths(directory: &Path) -> Vec<PathBuf> {
    let mut paths: Vec<_> = std::fs::read_dir(directory).unwrap().map(|entry| entry.unwrap().path()).collect();
    paths.sort(); paths
}
fn staging(directory: &Path) -> Option<PathBuf> {
    paths(directory).into_iter().find(|path| path.file_name().unwrap().to_string_lossy().starts_with(".atp-live-"))
}
fn retry_read(error: &io::Error) -> bool {
    matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted)
}

// Opaque forwarding: cut only after real receiver file progress, immediately
// before forwarding the corresponding response. No TLS decryption or SDK hooks.
struct Relay { address: SocketAddr, cut: Arc<AtomicBool>, count: Arc<AtomicUsize>, stop: Arc<AtomicBool>, worker: Option<JoinHandle<()>> }
impl Relay {
    fn new(remote: SocketAddr, inbox: PathBuf, threshold: u64) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap(); listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let cut = Arc::new(AtomicBool::new(false)); let count = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (fault, connections, stopped) = (cut.clone(), count.clone(), stop.clone());
        let worker = thread::spawn(move || {
            while !stopped.load(Ordering::SeqCst) {
                let (client, _) = match listener.accept() {
                    Ok(pair) => pair,
                    Err(error) if retry_read(&error) => { thread::sleep(Duration::from_millis(2)); continue; }
                    Err(error) => panic!("relay accept: {error}"),
                };
                connections.fetch_add(1, Ordering::SeqCst);
                let server = TcpStream::connect_timeout(&remote, WAIT).unwrap();
                for socket in [&client, &server] {
                    socket.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
                    socket.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
                }
                let ended = Arc::new(AtomicBool::new(false));
                let (mut from_client, mut to_server) = (client.try_clone().unwrap(), server.try_clone().unwrap());
                let (up_end, up_stop) = (ended.clone(), stopped.clone());
                let upstream = thread::spawn(move || {
                    let mut bytes = [0; 4096];
                    while !up_end.load(Ordering::SeqCst) && !up_stop.load(Ordering::SeqCst) {
                        match from_client.read(&mut bytes) {
                            Ok(0) => break,
                            Ok(count) => { if to_server.write_all(&bytes[..count]).is_err() { break; } }
                            Err(error) if retry_read(&error) => continue,
                            Err(_) => break,
                        }
                    }
                    up_end.store(true, Ordering::SeqCst);
                    let _ = from_client.shutdown(Shutdown::Both); let _ = to_server.shutdown(Shutdown::Both);
                });
                let (mut from_server, mut to_client) = (server, client);
                let mut bytes = [0; 4096];
                while !ended.load(Ordering::SeqCst) && !stopped.load(Ordering::SeqCst) {
                    match from_server.read(&mut bytes) {
                        Ok(0) => break,
                        Ok(count) => {
                            if !fault.load(Ordering::SeqCst) && staging(&inbox).is_some_and(|path| std::fs::metadata(path).unwrap().len() >= threshold) {
                                fault.store(true, Ordering::SeqCst); break;
                            }
                            if to_client.write_all(&bytes[..count]).is_err() { break; }
                        }
                        Err(error) if retry_read(&error) => continue,
                        Err(_) => break,
                    }
                }
                ended.store(true, Ordering::SeqCst);
                let _ = from_server.shutdown(Shutdown::Both); let _ = to_client.shutdown(Shutdown::Both);
                upstream.join().unwrap();
            }
        });
        Self { address, cut, count, stop, worker: Some(worker) }
    }
}
impl Drop for Relay {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() { worker.join().unwrap(); }
    }
}

// Independent framing/checksum reader, not SenderJournalFile::checkpoint().
fn snapshots(path: &Path) -> (Vec<u8>, Vec<Vec<u8>>) {
    let bytes = std::fs::read(path).unwrap(); assert_eq!(&bytes[..8], b"ATPSJL01");
    let hash = |previous: &[u8], body: &[u8]| {
        let mut h = Sha256::new(); h.update(b"asupersync.atp.sender-journal.v1");
        h.update(previous); h.update(body); h.finalize().to_vec()
    };
    let mut previous = hash(&[], &bytes[..16]); assert_eq!(&bytes[16..48], previous);
    assert_eq!((bytes.len() - 48) % 720, 0);
    let mut snapshots = Vec::new();
    for (sequence, record) in bytes[48..].chunks_exact(720).enumerate() {
        assert_eq!(&record[..8], &(sequence as u64).to_be_bytes());
        let n = u16::from_be_bytes([record[8], record[9]]) as usize;
        assert!(n <= 667); assert_eq!(&record[10..16], &[0; 6]);
        assert!(record[16 + n..688].iter().all(|b| *b == 0));
        let next = hash(&previous, &record[..688]); assert_eq!(&record[688..], next);
        previous = next;
        let saved = &record[16..16 + n]; assert_eq!(&saved[..8], b"ATPSND01");
        let body = saved.len() - 32; let mut h = Sha256::new();
        h.update(b"asupersync.atp.sender-checkpoint.v1"); h.update(&saved[..body]);
        assert_eq!(&saved[body..], h.finalize().as_slice()); snapshots.push(saved.to_vec());
    }
    (bytes, snapshots)
}

#[test]
fn sender_process_dies_before_eof_and_resumes_into_the_same_receiver_inode() {
    for workers in [1, 2] {
        for threshold in [4096_u64, 8192] {
            let fixture = Fixture::new();
            let data: Vec<_> = (0_usize..12293).map(|n| ((n * 29) ^ (n / 251)).to_le_bytes()[0]).collect();
            let input = fixture.source(&data); let journal = fixture.unique("journal");
            let (mut receiver, address) = fixture.receiver(workers, data.len());
            let relay = Relay::new(address, fixture.inbox.clone(), threshold);
            let config = fixture.config(relay.address, workers, data.len());
            let mut original = fixture.sender(&config, &input, &journal, Some((4, 32)), 60_000);
            let failed = original.event("journal_attempt");
            assert!(relay.cut.load(Ordering::SeqCst));
            assert_eq!(failed["retry_eligible"], true);
            assert_eq!(failed["journal"]["source_eof"], false);
            assert_eq!(failed["journal"]["saved_pending_bytes"], 4096);
            assert!(failed["transfer"]["receipt"].is_null());
            assert!(SenderJournalFile::open_existing(&journal).is_err(), "the original process still owns its journal");
            let receive_failure = receiver.event("resume_completion");
            assert_eq!(receive_failure["transfer"]["flushed_prefix_bytes"], threshold);
            let staged = staging(&fixture.inbox).unwrap();
            assert_eq!(std::fs::read(&staged).unwrap(), data[..threshold as usize]);
            let inode = std::fs::metadata(&staged).unwrap();
            assert_eq!(paths(&fixture.inbox).len(), 2);
            // Only this test-owned sender is killed, after actual disk/network witnesses.
            original.child.kill().unwrap(); assert!(!original.exit().success());
            let (before, states) = snapshots(&journal); let saved = states.last().unwrap();
            assert_eq!(saved[307], 0); // real source EOF has not been observed
            assert_eq!(u32::from_be_bytes(saved[299..303].try_into().unwrap()), 1);
            assert_eq!(u32::from_be_bytes(saved[303..307].try_into().unwrap()), 4);
            assert_eq!(u64::from_be_bytes(saved[136..144].try_into().unwrap()), threshold - 4096);

            let mut changed = data.clone(); changed[0] ^= 1;
            let changed_input = fixture.source(&changed);
            let mut refused = fixture.sender(&config, &changed_input, &journal, None, 25);
            let refusal = refused.result(); assert!(!refused.exit().success());
            assert_eq!(refusal["transfer"]["status"], "preparation_refused");
            assert_eq!(refusal["transfer"]["network_attempt_started"], false);
            assert_eq!(relay.count.load(Ordering::SeqCst), 1);
            assert_eq!(std::fs::read(&journal).unwrap(), before);

            let mut restarted = fixture.sender(&config, &input, &journal, None, 25);
            let complete = restarted.result(); assert!(restarted.exit().success());
            assert_eq!(complete["transfer"]["status"], "complete");
            assert_eq!(complete["transfer"]["attempts"], 2);
            assert_eq!(complete["resumed"], true); assert_eq!(complete["drained"], true);
            assert_eq!(complete["final_proof_direction"], "received");
            let received = receiver.event("resume_completion");
            assert_eq!(received["session"], receive_failure["session"]);
            assert_eq!(received["transfer"]["receipt"], complete["transfer"]["receipt"]);
            assert_eq!(received["transfer"]["sink_written_bytes"], data.len());
            let destination = fixture.inbox.join(received["publication"]["filename"].as_str().unwrap());
            let published = std::fs::metadata(&destination).unwrap();
            assert_eq!((published.dev(), published.ino()), (inode.dev(), inode.ino()));
            assert_eq!(std::fs::read(destination).unwrap(), data);
            assert_eq!(complete["transfer"]["receipt"]["sha256"], hex::encode(Sha256::digest(&data)));
            assert_eq!(paths(&fixture.inbox).len(), 3, "reconnect must not charge/create a second sink");
            let (after, states) = snapshots(&journal); assert!(after.starts_with(&before));
            assert_eq!(states.last().unwrap()[307], 1);
            assert_eq!(relay.count.load(Ordering::SeqCst), 2);
            drop(relay); receiver.stop();
        }
    }
}

#[test]
fn journal_capacity_failure_precedes_data_and_cannot_reset_on_restart() {
    let fixture = Fixture::new(); let input = fixture.source(b"not sent");
    let journal = fixture.unique("journal");
    let (mut receiver, address) = fixture.receiver(1, 8);
    let config = fixture.config(address, 1, 8);
    let mut sender = fixture.sender(&config, &input, &journal, Some((4, 1)), 25);
    let result = sender.result(); assert!(!sender.exit().success());
    assert_eq!(result["transfer"]["status"], "journal_blocked");
    assert_eq!(result["transfer"]["persistence"]["storage_full"], true);
    assert!(result["transfer"]["receipt"].is_null());
    let ended = receiver.event("resume_completion");
    assert_eq!(ended["transfer"]["sink_written_bytes"], 0);
    assert_eq!(std::fs::metadata(staging(&fixture.inbox).unwrap()).unwrap().len(), 0);
    let (before, states) = snapshots(&journal); assert_eq!(states.len(), 1);
    let mut restarted = fixture.sender(&config, &input, &journal, None, 25);
    let result = restarted.result(); assert!(!restarted.exit().success());
    assert_eq!(result["transfer"]["status"], "journal_blocked");
    assert_eq!(std::fs::read(&journal).unwrap(), before);
    assert_eq!(paths(&fixture.inbox).len(), 2); receiver.stop();
}

#[test]
fn ordinary_and_empty_journaled_sends_publish_exactly_one_file() {
    for bytes in [b"ordinary journaled delivery".as_slice(), b"".as_slice()] {
        let fixture = Fixture::new(); let input = fixture.source(bytes);
        let journal = fixture.unique("journal");
        let (mut receiver, address) = fixture.receiver(2, bytes.len());
        let config = fixture.config(address, 2, bytes.len());
        let mut sender = fixture.sender(&config, &input, &journal, Some((4, 16)), 25);
        let result = sender.result(); assert!(sender.exit().success());
        assert_eq!(result["journal"]["source_eof"], true);
        assert_eq!(result["transfer"]["receipt"]["sha256"], hex::encode(Sha256::digest(bytes)));
        let completion = receiver.event("resume_completion");
        assert_eq!(completion["transfer"]["receipt"], result["transfer"]["receipt"]);
        let path = fixture.inbox.join(completion["publication"]["filename"].as_str().unwrap());
        assert_eq!(std::fs::read(path).unwrap(), bytes);
        let before = std::fs::read(&journal).unwrap();
        let mut duplicate = fixture.sender(&config, &input, &journal, Some((4, 16)), 25);
        assert!(!duplicate.exit().success()); assert_eq!(std::fs::read(&journal).unwrap(), before);
        assert_eq!(paths(&fixture.inbox).len(), 3); receiver.stop();
    }
}
