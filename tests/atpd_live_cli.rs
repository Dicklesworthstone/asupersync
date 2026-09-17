//! Execute the foreground live profile in independent native processes.
//!
//! TLS identities are public test fixtures, never production credentials. Every
//! created directory and log is retained. Watchdogs kill only children created
//! by this test, and a successful exit is never the sole delivery witness.

#![cfg(all(feature = "atp-cli", feature = "tls", unix, not(target_arch = "wasm32")))]

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use rustls::pki_types::{CertificateDer, pem::PemObject};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, Read};
use std::net::{SocketAddr, TcpListener};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const WAIT: Duration = Duration::from_secs(15);
const BINARY: &str = env!("CARGO_BIN_EXE_atpd-live");

struct Fixture {
    root: PathBuf,
    inbox: PathBuf,
    sequence: AtomicUsize,
    allowed: String,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap().keep();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let inbox = root.join("inbox");
        std::fs::create_dir(&inbox).unwrap();
        std::fs::set_permissions(&inbox, std::fs::Permissions::from_mode(0o700)).unwrap();
        let fixture: Value = serde_json::from_str(include_str!("fixtures/atp_native_auth_identities.json")).unwrap();
        std::fs::write(root.join("ca.pem"), fixture["ca"].as_str().unwrap()).unwrap();
        for name in ["server", "allowed", "unlisted", "expired"] {
            std::fs::write(root.join(format!("{name}.pem")), fixture["identities"][name]["certificate"].as_str().unwrap()).unwrap();
            let key = root.join(format!("{name}.key"));
            std::fs::write(&key, fixture["identities"][name]["key"].as_str().unwrap()).unwrap();
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let pem = fixture["identities"]["allowed"]["certificate"].as_str().unwrap();
        let cert = CertificateDer::pem_reader_iter(&mut BufReader::new(pem.as_bytes())).next().unwrap().unwrap();
        let allowed = hex::encode(Sha256::digest(cert.as_ref()));
        Self { root, inbox, sequence: AtomicUsize::new(0), allowed }
    }

    fn unique(&self, extension: &str) -> PathBuf {
        self.root.join(format!("{}.{extension}", self.sequence.fetch_add(1, Ordering::SeqCst)))
    }

    fn json_file(&self, value: Value) -> PathBuf {
        let path = self.unique("json");
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        path
    }

    fn identity(&self, name: &str) -> Value {
        json!({"certificate": self.root.join(format!("{name}.pem")), "private_key": self.root.join(format!("{name}.key"))})
    }

    fn receiver_config(&self, workers: usize, max_transfer: u64, retained: u64) -> Value {
        json!({"schema_version": 1, "bind": "127.0.0.1:0", "identity": self.identity("server"),
            "client_ca": self.root.join("ca.pem"), "clients": [{
                "certificate_sha256": self.allowed, "directory": self.inbox,
                "max_retained_bytes": retained, "max_retained_entries": 32}],
            "max_connections": 2, "workers": workers, "epoch_bytes": 32,
            "max_transfer_bytes": max_transfer, "operation_timeout_secs": 3, "shutdown_grace_secs": 1})
    }

    fn start_receiver(&self, config: Value) -> (Process, SocketAddr) {
        let path = self.json_file(config);
        let mut process = self.spawn("serve", &path, None);
        let ready = process.event("ready");
        assert_eq!(ready["schema_version"], 1);
        assert_eq!(ready["application_commit"], true);
        assert_eq!(ready["profile"], "atp-live/1");
        let address: SocketAddr = ready["address"].as_str().unwrap().parse().unwrap();
        assert_ne!(address.port(), 0);
        (process, address)
    }

    fn sender_config(&self, address: SocketAddr, identity: &str, workers: usize) -> Value {
        json!({"schema_version": 1, "remote": address, "server_name": "localhost",
            "server_ca": self.root.join("ca.pem"), "identity": self.identity(identity),
            "workers": workers, "epoch_bytes": 32, "max_transfer_bytes": 4096,
            "operation_timeout_secs": 3})
    }

    fn send(&self, config: Value, bytes: &[u8]) -> (ExitStatus, Value) {
        let input = self.unique("input");
        std::fs::write(&input, bytes).unwrap();
        let config = self.json_file(config);
        let mut process = self.spawn("send", &config, Some(&input));
        let event = process.event("send_result");
        let status = process.exit();
        (status, event)
    }

    fn spawn(&self, operation: &str, config: &Path, input: Option<&Path>) -> Process {
        let stderr = self.unique("stderr");
        let error_log = OpenOptions::new().write(true).create_new(true).open(&stderr).unwrap();
        let mut command = Command::new(BINARY);
        command.args([operation, "--config"]).arg(config).stdout(Stdio::piped()).stderr(error_log);
        if let Some(input) = input { command.arg("--input").arg(input); }
        let mut child = command.spawn().unwrap();
        let output = child.stdout.take().unwrap();
        let (sender, events) = mpsc::channel();
        let reader = thread::spawn(move || {
            for line in BufReader::new(output).lines() {
                let record = line.map_err(|error| error.to_string()).and_then(|line| {
                    serde_json::from_str::<Value>(&line).map_err(|error| error.to_string())
                });
                if sender.send(record).is_err() { break; }
            }
        });
        Process { child, reader: Some(reader), events, stderr }
    }

    fn entries(&self) -> Vec<PathBuf> {
        let mut files: Vec<_> = std::fs::read_dir(&self.inbox).unwrap().map(|entry| entry.unwrap().path()).collect();
        files.sort();
        files
    }
}

struct Process {
    child: Child,
    reader: Option<JoinHandle<()>>,
    events: Receiver<Result<Value, String>>,
    stderr: PathBuf,
}

impl Process {
    fn event(&mut self, expected: &str) -> Value {
        let event = self.events.recv_timeout(WAIT).unwrap_or_else(|error| {
            panic!("missing {expected} event: {error}; retained stderr {}", self.stderr.display())
        }).unwrap();
        assert_eq!(event["event"], expected, "unexpected executable result: {event}");
        event
    }

    fn exit(&mut self) -> ExitStatus {
        let start = Instant::now();
        let status = loop {
            if let Some(status) = self.child.try_wait().unwrap() { break status; }
            assert!(start.elapsed() < WAIT, "child failed to exit; stderr {}", self.stderr.display());
            thread::sleep(Duration::from_millis(5));
        };
        if let Some(reader) = self.reader.take() { reader.join().unwrap(); }
        status
    }

    fn stop(&mut self) {
        let pid = Pid::from_raw(i32::try_from(self.child.id()).unwrap());
        kill(pid, Signal::SIGTERM).unwrap();
        let stopped = self.event("stopped");
        assert_eq!(stopped["drained"], true);
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

fn verify_publication(fixture: &Fixture, sent: &Value, received: &Value, expected: &[u8]) -> PathBuf {
    assert_eq!(sent["transfer"]["status"], "complete");
    assert_eq!(received["transfer"]["status"], "complete");
    assert_eq!(sent["transfer"]["receipt"], received["transfer"]["receipt"]);
    assert_eq!(received["publication"]["state"], "durable");
    assert_eq!(received["publication"]["error"], false);
    assert_eq!(received["client_certificate_sha256"], fixture.allowed);
    let filename = received["publication"]["filename"].as_str().unwrap();
    assert!(filename.ends_with(".bin"));
    let path = fixture.inbox.join(filename);
    assert_eq!(std::fs::read(&path).unwrap(), expected);
    assert_eq!(received["transfer"]["receipt"]["sha256"], hex::encode(Sha256::digest(expected)));
    let published = std::fs::metadata(&path).unwrap();
    assert_eq!(published.permissions().mode() & 0o777, 0o600);
    let aliases = fixture.entries().into_iter().filter(|entry| {
        let metadata = std::fs::metadata(entry).unwrap();
        (metadata.dev(), metadata.ino()) == (published.dev(), published.ino())
    }).count();
    assert_eq!(aliases, 2, "retained staging and final aliases must name the actual committed inode");
    path
}

#[test]
fn executable_sender_and_receiver_commit_multiple_files_on_one_bound_port() {
    for workers in [1, 2] {
        let fixture = Fixture::new();
        let (mut receiver, address) = fixture.start_receiver(fixture.receiver_config(workers, 4096, 65536));
        let mut paths = Vec::new();
        for bytes in [b"first executable transfer".as_slice(), &[0x5a; 1024][..], b""] {
            let (status, sent) = fixture.send(fixture.sender_config(address, "allowed", workers), bytes);
            assert!(status.success());
            let received = receiver.event("completion");
            let path = verify_publication(&fixture, &sent, &received, bytes);
            assert!(!paths.contains(&path), "new sends must not clobber previous files");
            paths.push(path);
        }
        receiver.stop();
        assert_eq!(std::fs::read(&paths[0]).unwrap(), b"first executable transfer");
        let (mut restarted, _) = fixture.start_receiver(fixture.receiver_config(workers, 4096, 65536));
        restarted.stop();
    }
}

#[test]
fn executable_authentication_refuses_unlisted_expired_and_wrong_server_names() {
    let fixture = Fixture::new();
    let (mut receiver, address) = fixture.start_receiver(fixture.receiver_config(2, 4096, 65536));
    for (identity, hostname) in [("unlisted", "localhost"), ("expired", "localhost"), ("allowed", "wrong.invalid")] {
        let mut config = fixture.sender_config(address, identity, 1);
        config["server_name"] = json!(hostname);
        let (status, sent) = fixture.send(config, b"must not be published");
        assert!(!status.success());
        assert_ne!(sent["transfer"]["status"], "complete");
        let received = receiver.event("completion");
        assert_eq!(received["transfer"]["status"], "tls_failed");
        assert!(received["publication"].is_null());
        assert!(received["client_certificate_sha256"].is_null());
        assert_eq!(fixture.entries(), vec![fixture.inbox.join(".atpd-live.lock")]);
    }
    // A refused client must not have killed the reusable listener.
    let (status, sent) = fixture.send(fixture.sender_config(address, "allowed", 1), b"accepted");
    assert!(status.success());
    verify_publication(&fixture, &sent, &receiver.event("completion"), b"accepted");
    receiver.stop();
}

#[test]
fn executable_retention_refusal_survives_process_restart_without_deleting_data() {
    let fixture = Fixture::new();
    let config = fixture.receiver_config(2, 64, 128);
    let (mut receiver, address) = fixture.start_receiver(config.clone());
    let bytes = [0xa5; 64];
    let (status, sent) = fixture.send(fixture.sender_config(address, "allowed", 2), &bytes);
    assert!(status.success());
    let path = verify_publication(&fixture, &sent, &receiver.event("completion"), &bytes);
    let before = fixture.entries();
    let (status, _) = fixture.send(fixture.sender_config(address, "allowed", 1), b"next");
    assert!(!status.success());
    assert_eq!(receiver.event("completion")["transfer"]["status"], "retention_refused");
    assert_eq!(fixture.entries(), before);
    receiver.stop();
    let (mut restarted, address) = fixture.start_receiver(config);
    let (status, _) = fixture.send(fixture.sender_config(address, "allowed", 1), b"next");
    assert!(!status.success());
    assert_eq!(restarted.event("completion")["transfer"]["status"], "retention_refused");
    assert_eq!(fixture.entries(), before);
    assert_eq!(std::fs::read(path).unwrap(), bytes);
    restarted.stop();
}

#[test]
fn executable_startup_rejects_concurrent_inbox_owner_and_invalid_configuration() {
    let fixture = Fixture::new();
    let config = fixture.receiver_config(1, 4096, 65536);
    let (mut receiver, address) = fixture.start_receiver(config.clone());
    let path = fixture.json_file(config.clone());
    let mut conflicting = fixture.spawn("serve", &path, None);
    assert!(!conflicting.exit().success());
    assert!(conflicting.events.try_iter().all(|event| event.unwrap()["event"] != "ready"));
    for invalid in [
        { let mut c = config.clone(); c["ambient_trust_fallback"] = json!(true); c },
        { let mut c = config.clone(); c["identity"]["private_key"] = json!(fixture.root.join("missing.key")); c },
        { let mut c = config; c["max_connections"] = json!(0); c },
    ] {
        let path = fixture.json_file(invalid);
        let mut process = fixture.spawn("serve", &path, None);
        assert!(!process.exit().success());
        assert!(process.events.try_iter().all(|event| event.unwrap()["event"] != "ready"));
    }
    let (status, sent) = fixture.send(fixture.sender_config(address, "allowed", 1), b"original owner still serves");
    assert!(status.success());
    verify_publication(&fixture, &sent, &receiver.event("completion"), b"original owner still serves");
    receiver.stop();
}

#[test]
fn executable_sender_requires_a_real_handshake_not_merely_a_listening_socket() {
    let fixture = Fixture::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let mut config = fixture.sender_config(listener.local_addr().unwrap(), "allowed", 1);
    config["operation_timeout_secs"] = json!(1);
    let config = fixture.json_file(config);
    let input = fixture.unique("input");
    std::fs::write(&input, b"never delivered").unwrap();
    let mut sender = fixture.spawn("send", &config, Some(&input));
    let start = Instant::now();
    let (mut socket, _) = loop {
        match listener.accept() {
            Ok(pair) => break pair,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                assert!(start.elapsed() < WAIT, "sender never reached the peer");
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("accept failed: {error}"),
        }
    };
    socket.set_read_timeout(Some(WAIT)).unwrap();
    let mut record = [0; 4096];
    assert!(socket.read(&mut record).unwrap() > 0, "actual TLS bytes must reach the independent peer");
    let result = sender.event("send_result");
    assert_eq!(result["transfer"]["status"], "timeout");
    assert!(result["transfer"]["receipt"].is_null());
    assert!(!sender.exit().success());
}
