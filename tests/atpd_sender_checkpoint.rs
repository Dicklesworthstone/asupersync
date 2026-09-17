//! Execute checkpoint/recovery commands in separate Unix processes.
//! Every fixture is retained. The fault relay forwards opaque TLS bytes and
//! drops a response only after independently observing the durable commit.
#![cfg(all(feature = "atp-cli", feature = "tls", unix, not(target_arch = "wasm32")))]

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

const WAIT: Duration = Duration::from_secs(20);
const BINARY: &str = env!("CARGO_BIN_EXE_atpd-live");

struct Fixture { root: PathBuf, inbox: PathBuf, serial: AtomicUsize, client: String }
impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap().keep();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let inbox = root.join("inbox");
        std::fs::create_dir(&inbox).unwrap();
        std::fs::set_permissions(&inbox, std::fs::Permissions::from_mode(0o700)).unwrap();
        let data: Value = serde_json::from_str(include_str!("fixtures/atp_native_auth_identities.json")).unwrap();
        std::fs::write(root.join("ca.pem"), data["ca"].as_str().unwrap()).unwrap();
        for name in ["server", "allowed", "unlisted"] {
            std::fs::write(root.join(format!("{name}.pem")), data["identities"][name]["certificate"].as_str().unwrap()).unwrap();
            let key = root.join(format!("{name}.key"));
            std::fs::write(&key, data["identities"][name]["key"].as_str().unwrap()).unwrap();
            std::fs::set_permissions(key, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let certificate = CertificateDer::pem_reader_iter(&mut BufReader::new(
            data["identities"]["allowed"]["certificate"].as_str().unwrap().as_bytes(),
        )).next().unwrap().unwrap();
        let client = hex::encode(Sha256::digest(certificate.as_ref()));
        Self { root, inbox, serial: AtomicUsize::new(0), client }
    }
    fn unique(&self, suffix: &str) -> PathBuf {
        self.root.join(format!("{}.{suffix}", self.serial.fetch_add(1, Ordering::SeqCst)))
    }
    fn config(&self, config: &Value) -> PathBuf {
        let path = self.unique("json");
        std::fs::write(&path, serde_json::to_vec(config).unwrap()).unwrap(); path
    }
    fn identity(&self, name: &str) -> Value {
        json!({"certificate": self.root.join(format!("{name}.pem")), "private_key": self.root.join(format!("{name}.key"))})
    }
    fn sender(&self, address: SocketAddr, workers: usize, limit: usize) -> Value {
        json!({"schema_version": 1, "remote": address, "server_name": "localhost",
            "server_ca": self.root.join("ca.pem"), "identity": self.identity("allowed"),
            "workers": workers, "epoch_bytes": 65536, "max_transfer_bytes": limit,
            "operation_timeout_secs": 3})
    }
    fn receiver(&self, workers: usize, limit: usize) -> Value {
        json!({"schema_version": 1, "bind": "127.0.0.1:0", "identity": self.identity("server"),
            "client_ca": self.root.join("ca.pem"), "clients": [{"certificate_sha256": self.client,
                "directory": self.inbox, "max_retained_bytes": limit * 2,
                "max_retained_entries": 3}],
            "max_connections": 1, "workers": workers, "epoch_bytes": 65536,
            "max_transfer_bytes": limit, "operation_timeout_secs": 3, "shutdown_grace_secs": 1})
    }
    fn launch(&self, mut command: Command) -> Process {
        let log = self.unique("stderr");
        command.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(
            OpenOptions::new().write(true).create_new(true).open(&log).unwrap(),
        );
        let mut child = command.spawn().unwrap(); let stdout = child.stdout.take().unwrap();
        let (tx, events) = mpsc::channel();
        let reader = thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let value = serde_json::from_str(&line.unwrap()).unwrap();
                if tx.send(value).is_err() { break; }
            }
        });
        Process { child, events, reader: Some(reader), log }
    }
    fn ledger(&self) -> PathBuf {
        let path = self.unique("ledger");
        let mut command = Command::new(BINARY);
        command.args(["init-session-ledger", "--path"]).arg(&path).args(["--max-keys", "1"]);
        let mut process = self.launch(command);
        assert_eq!(process.until("session_ledger_initialized").0["maximum_keys"], 1);
        assert!(process.exit().success()); path
    }
    fn serve(&self, config: &Value, ledger: &Path) -> (Process, SocketAddr) {
        let mut command = Command::new(BINARY);
        command.args(["serve-durable", "--config"]).arg(self.config(config))
            .arg("--session-ledger").arg(ledger).arg("--recover-committed")
            .args(["--max-sessions", "1", "--max-sessions-per-client", "1", "--max-session-keys", "4",
                "--attempts-per-session", "8", "--idle-retention-secs", "30", "--proof-recovery-secs", "60"]);
        let mut process = self.launch(command); let ready = process.until("ready").0;
        assert_eq!(ready["durable_session_ledger"], true);
        let address = ready["address"].as_str().unwrap().parse().unwrap(); (process, address)
    }
    fn run_sender(&self, config: &Value, checkpoint: &Path, input: Option<&Path>, attempts: u32, delay: u64) -> Process {
        let mut command = Command::new(BINARY);
        command.arg(if input.is_some() { "send-checkpointed" } else { "recover-proof" })
            .arg("--config").arg(self.config(config)).arg("--checkpoint").arg(checkpoint)
            .arg("--attempts").arg(attempts.to_string()).arg("--retry-delay-ms").arg(delay.to_string());
        if let Some(input) = input { command.arg("--input").arg(input); }
        self.launch(command)
    }
    fn input(&self, bytes: &[u8]) -> PathBuf {
        let path = self.unique("input"); std::fs::write(&path, bytes).unwrap(); path
    }
}

struct Process { child: Child, events: mpsc::Receiver<Value>, reader: Option<JoinHandle<()>>, log: PathBuf }
impl Process {
    fn until(&mut self, wanted: &str) -> (Value, Vec<Value>) {
        let until = Instant::now() + WAIT; let mut earlier = Vec::new();
        for _ in 0..32 {
            let value = self.events.recv_timeout(until.saturating_duration_since(Instant::now()))
                .unwrap_or_else(|error| panic!("missing {wanted}: {error}; {}", self.log.display()));
            if value["event"] == wanted { return (value, earlier); }
            earlier.push(value);
        }
        panic!("test event bound exceeded");
    }
    fn exit(&mut self) -> ExitStatus {
        let until = Instant::now() + WAIT;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                if let Some(reader) = self.reader.take() { reader.join().unwrap(); }
                return status;
            }
            assert!(Instant::now() < until, "child did not exit; {}", self.log.display());
            thread::sleep(Duration::from_millis(5));
        }
    }
    fn signal(&self) { kill(Pid::from_raw(i32::try_from(self.child.id()).unwrap()), Signal::SIGTERM).unwrap(); }
    fn stop(&mut self) {
        self.signal(); assert_eq!(self.until("stopped").0["drained"], true); assert!(self.exit().success());
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) { let _ = self.child.kill(); }
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() { let _ = reader.join(); }
    }
}

fn files(directory: &Path) -> Vec<(String, u64, u64)> {
    let mut values: Vec<_> = std::fs::read_dir(directory).unwrap().map(|entry| {
        let entry = entry.unwrap(); let m = entry.metadata().unwrap();
        (entry.file_name().to_str().unwrap().to_owned(), m.ino(), m.len())
    }).collect(); values.sort(); values
}
fn checkpoint_bytes(path: &Path, data: &[u8]) -> Vec<u8> {
    let bytes = std::fs::read(path).unwrap();
    assert!((302..=554).contains(&bytes.len())); assert_eq!(&bytes[..8], b"ATPFNL01");
    let body = bytes.len() - 32; let mut hash = Sha256::new();
    hash.update(b"asupersync.atp.sender-final-checkpoint.v1"); hash.update(&bytes[..body]);
    assert_eq!(&bytes[body..], hash.finalize().as_slice());
    assert_eq!(u64::from_be_bytes(bytes[136..144].try_into().unwrap()), data.len() as u64);
    assert_eq!(&bytes[176..208], Sha256::digest(data).as_slice());
    assert_eq!(std::fs::metadata(path).unwrap().permissions().mode() & 0o777, 0o600);
    bytes
}
fn committed_record(ledger: &Path) -> Option<Vec<u8>> {
    let bytes = std::fs::read(ledger).ok()?;
    if bytes.len() != 48 + 2 * 256 || bytes[48 + 256 + 8] != 2 { return None; }
    let hash = |previous: &[u8], body: &[u8]| {
        let mut h = Sha256::new(); h.update(b"asupersync.atpd.session-ledger.v1");
        h.update(previous); h.update(body); h.finalize().to_vec()
    };
    let mut previous = hash(&[], &bytes[..16]);
    if bytes[16..48] != previous { return None; }
    for row in bytes[48..].chunks_exact(256) {
        let sum = hash(&previous, &row[..224]); if row[224..] != sum { return None; } previous = sum;
    }
    Some(bytes[48 + 256..].to_vec())
}
fn verify_delivery(fixture: &Fixture, ledger: &Path, result: &Value, data: &[u8], source_free: bool) {
    assert_eq!(result["transfer"]["status"], "complete"); assert_eq!(result["drained"], true);
    assert_eq!(result["source_free"], source_free); assert_eq!(result["checkpoint_persisted"], true);
    assert_eq!(result["final_proof_direction"], "received");
    assert_eq!(result["transfer"]["receipt"]["sha256"], hex::encode(Sha256::digest(data)));
    let row = committed_record(ledger).expect("independently verified claim and commit");
    let name = std::str::from_utf8(&row[80..116]).unwrap();
    assert_eq!(std::fs::read(fixture.inbox.join(name)).unwrap(), data);
    let m = std::fs::metadata(fixture.inbox.join(name)).unwrap();
    assert_eq!(files(&fixture.inbox).len(), 3);
    assert_eq!(files(&fixture.inbox).iter().filter(|(_, ino, _)| *ino == m.ino()).count(), 2);
}

fn would_wait(error: &io::Error) -> bool {
    matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted)
}
fn accept(listener: &TcpListener) -> TcpStream {
    let until = Instant::now() + WAIT;
    loop {
        match listener.accept() {
            Ok((stream, _)) => return stream,
            Err(error) if would_wait(&error) => {
                assert!(Instant::now() < until, "no actual client connection");
                thread::sleep(Duration::from_millis(2));
            }
            Err(error) => panic!("listener failed: {error}"),
        }
    }
}

struct Relay {
    address: SocketAddr, stopped: Arc<AtomicBool>, cut: Arc<AtomicBool>,
    connections: Arc<AtomicUsize>, worker: Option<JoinHandle<()>>,
}
impl Relay {
    fn new(remote: SocketAddr, ledger: PathBuf) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap(); listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let stopped = Arc::new(AtomicBool::new(false)); let cut = Arc::new(AtomicBool::new(false));
        let connections = Arc::new(AtomicUsize::new(0));
        let (stop, fault, count) = (stopped.clone(), cut.clone(), connections.clone());
        let worker = thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                let (client, _) = match listener.accept() {
                    Ok(pair) => pair,
                    Err(error) if would_wait(&error) => { thread::sleep(Duration::from_millis(2)); continue; }
                    Err(error) => panic!("relay accept: {error}"),
                };
                count.fetch_add(1, Ordering::SeqCst);
                let server = match TcpStream::connect_timeout(&remote, Duration::from_secs(2)) {
                    Ok(server) => server, Err(_) => { drop(client); continue; }
                };
                for stream in [&server, &client] {
                    stream.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
                    stream.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
                }
                let ended = Arc::new(AtomicBool::new(false));
                let (mut cr, mut sw) = (client.try_clone().unwrap(), server.try_clone().unwrap());
                let (up_stop, up_end) = (stop.clone(), ended.clone());
                let up = thread::spawn(move || {
                    let mut buf = [0; 4096];
                    while !up_stop.load(Ordering::SeqCst) && !up_end.load(Ordering::SeqCst) {
                        match cr.read(&mut buf) {
                            Ok(0) => break,
                            Ok(n) => if sw.write_all(&buf[..n]).is_err() { break; },
                            Err(error) if would_wait(&error) => continue,
                            Err(_) => break,
                        }
                    }
                    up_end.store(true, Ordering::SeqCst);
                    let _ = cr.shutdown(Shutdown::Both); let _ = sw.shutdown(Shutdown::Both);
                });
                let (mut sr, mut cw) = (server, client); let mut buf = [0; 4096];
                while !stop.load(Ordering::SeqCst) && !ended.load(Ordering::SeqCst) {
                    match sr.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            // A claim, listening socket, or staged prefix is insufficient.
                            // Only a complete independently checksummed commit cuts Proof.
                            if !fault.load(Ordering::SeqCst) && committed_record(&ledger).is_some() {
                                fault.store(true, Ordering::SeqCst); break;
                            }
                            if cw.write_all(&buf[..n]).is_err() { break; }
                        }
                        Err(error) if would_wait(&error) => continue,
                        Err(_) => break,
                    }
                }
                ended.store(true, Ordering::SeqCst);
                let _ = sr.shutdown(Shutdown::Both); let _ = cw.shutdown(Shutdown::Both); up.join().unwrap();
            }
        });
        Self { address, stopped, cut, connections, worker: Some(worker) }
    }
    fn finish(&mut self) {
        self.stopped.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() { worker.join().unwrap(); }
    }
}
impl Drop for Relay {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() { let _ = worker.join(); }
    }
}

#[test]
fn checkpointed_command_delivers_and_recovers_nonempty_and_empty_files() {
    for workers in [1, 2] {
        for data in [b"actual checkpointed executable transfer".as_slice(), b"".as_slice()] {
            let fixture = Fixture::new(); let ledger = fixture.ledger();
            let (mut server, address) = fixture.serve(&fixture.receiver(workers, data.len()), &ledger);
            let config = fixture.sender(address, workers, data.len()); let checkpoint = fixture.unique("checkpoint");
            let input = fixture.input(data); let mut sender = fixture.run_sender(&config, &checkpoint, Some(&input), 1, 25);
            let result = sender.until("send_result").0; assert!(sender.exit().success());
            verify_delivery(&fixture, &ledger, &result, data, false);
            let saved = checkpoint_bytes(&checkpoint, data); let before = files(&fixture.inbox);
            let history = std::fs::read(&ledger).unwrap(); server.until("resume_completion");
            let mut recovery = fixture.run_sender(&config, &checkpoint, None, 1, 25);
            let recovered = recovery.until("send_result").0; assert!(recovery.exit().success());
            verify_delivery(&fixture, &ledger, &recovered, data, true);
            assert_eq!(result["transfer"]["receipt"], recovered["transfer"]["receipt"]);
            assert_eq!(checkpoint_bytes(&checkpoint, data), saved);
            assert_eq!(files(&fixture.inbox), before); assert_eq!(std::fs::read(&ledger).unwrap(), history);
            server.stop();
        }
    }
}

#[test]
fn both_executables_restart_after_lost_proof_without_reopening_source_or_republishing() {
    for workers in [1, 2] {
        let fixture = Fixture::new(); let ledger = fixture.ledger();
        let data: Vec<_> = (0_usize..131083).map(|n| ((n * 37) ^ (n / 251)).to_le_bytes()[0]).collect();
        let mut receiver_config = fixture.receiver(workers, data.len());
        let (mut receiver, address) = fixture.serve(&receiver_config, &ledger);
        let mut relay = Relay::new(address, ledger.clone());
        let config = fixture.sender(relay.address, workers, data.len());
        let checkpoint = fixture.unique("checkpoint"); let input = fixture.input(&data);
        let mut sender = fixture.run_sender(&config, &checkpoint, Some(&input), 1, 25);
        let failed = sender.until("send_result").0; assert!(!sender.exit().success());
        assert!(relay.cut.load(Ordering::SeqCst)); assert_eq!(failed["checkpoint_persisted"], true);
        assert!(failed["transfer"]["receipt"].is_null()); assert_eq!(failed["final_proof_direction"], "not_received");
        let saved = checkpoint_bytes(&checkpoint, &data); let before = files(&fixture.inbox);
        let history = std::fs::read(&ledger).unwrap(); assert!(committed_record(&ledger).is_some());
        receiver.child.kill().unwrap(); assert!(!receiver.exit().success());
        // Retain, rather than delete, the input; its old path is now a directory.
        // A restarted sender that accidentally reopens that source must fail.
        std::fs::rename(&input, fixture.unique("retained-input")).unwrap(); std::fs::create_dir(&input).unwrap();
        receiver_config["bind"] = json!(address);
        let (mut restarted, same) = fixture.serve(&receiver_config, &ledger); assert_eq!(same, address);
        let mut recovery = fixture.run_sender(&config, &checkpoint, None, 3, 25);
        let recovered = recovery.until("send_result").0; assert!(recovery.exit().success());
        verify_delivery(&fixture, &ledger, &recovered, &data, true);
        let completion = restarted.until("resume_completion").0;
        assert_eq!(completion["transfer"]["receipt_reused"], true);
        assert_eq!(completion["transfer"]["sink_written_bytes"], 0);
        assert!(completion["publication"].is_null());
        assert_eq!(std::fs::read(&ledger).unwrap(), history); assert_eq!(files(&fixture.inbox), before);
        assert_eq!(checkpoint_bytes(&checkpoint, &data), saved); assert!(relay.connections.load(Ordering::SeqCst) >= 2);
        relay.finish(); restarted.stop();
    }
}

#[test]
fn source_free_recovery_refuses_a_fresh_uncommitted_receiver_even_for_empty_input() {
    for data in [b"content".as_slice(), b"".as_slice()] {
        let fixture = Fixture::new(); let ledger = fixture.ledger();
        let (mut receiver, address) = fixture.serve(&fixture.receiver(1, data.len()), &ledger);
        let config = fixture.sender(address, 1, data.len()); let checkpoint = fixture.unique("checkpoint");
        let input = fixture.input(data); let mut sender = fixture.run_sender(&config, &checkpoint, Some(&input), 1, 25);
        assert_eq!(sender.until("send_result").0["transfer"]["status"], "complete"); assert!(sender.exit().success());
        receiver.stop(); let new_ledger = fixture.ledger();
        let empty_inbox = fixture.unique("fresh-inbox"); std::fs::create_dir(&empty_inbox).unwrap();
        std::fs::set_permissions(&empty_inbox, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut changed = fixture.receiver(1, data.len()); changed["bind"] = json!(address);
        changed["clients"][0]["directory"] = json!(empty_inbox);
        let (mut fresh, _) = fixture.serve(&changed, &new_ledger);
        let mut recovery = fixture.run_sender(&config, &checkpoint, None, 4, 25);
        let (failed, attempts) = recovery.until("send_result"); assert!(!recovery.exit().success());
        assert_eq!(failed["transfer"]["status"], "continuity_refused"); assert!(failed["transfer"]["receipt"].is_null());
        assert_eq!(attempts.len(), 1); assert_eq!(attempts[0]["retry_eligible"], false);
        assert!(files(&empty_inbox).iter().all(|(name, _, len)| !name.ends_with(".bin") && *len == 0));
        assert!(committed_record(&new_ledger).is_none()); fresh.stop();
    }
}

#[test]
fn checkpoints_are_create_only_and_recovery_policy_is_checked_before_networking() {
    let fixture = Fixture::new(); let ledger = fixture.ledger(); let data = b"policy data";
    let (mut receiver, address) = fixture.serve(&fixture.receiver(1, data.len()), &ledger);
    let config = fixture.sender(address, 1, data.len()); let checkpoint = fixture.unique("checkpoint"); let input = fixture.input(data);
    let mut original = fixture.run_sender(&config, &checkpoint, Some(&input), 1, 25);
    original.until("send_result"); assert!(original.exit().success()); receiver.stop();
    let before = checkpoint_bytes(&checkpoint, data);
    let mut overwrite = fixture.run_sender(&config, &checkpoint, Some(&input), 1, 25);
    assert!(!overwrite.exit().success()); assert_eq!(checkpoint_bytes(&checkpoint, data), before);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap(); listener.set_nonblocking(true).unwrap();
    let mut changed = config.clone(); changed["remote"] = json!(listener.local_addr().unwrap());
    let mut recovery = fixture.run_sender(&changed, &checkpoint, None, 4, 25);
    assert!(!recovery.exit().success()); assert_eq!(listener.accept().unwrap_err().kind(), io::ErrorKind::WouldBlock);
    for changed in [
        { let mut c = config.clone(); c["server_name"] = json!("wrong.invalid"); c },
        { let mut c = config.clone(); c["max_transfer_bytes"] = json!(data.len() - 1); c },
        { let mut c = config.clone(); c["epoch_bytes"] = json!(1); c },
    ] {
        let mut process = fixture.run_sender(&changed, &checkpoint, None, 4, 25);
        assert!(!process.exit().success());
        assert!(process.events.try_iter().all(|row| row["event"] != "checkpoint_attempt"));
    }
    assert_eq!(checkpoint_bytes(&checkpoint, data), before);
    let missing = fixture.unique("missing-checkpoint");
    let mut process = fixture.run_sender(&config, &missing, None, 1, 25); assert!(!process.exit().success()); assert!(!missing.exists());
    let invalid = fixture.unique("invalid-checkpoint");
    let mut process = fixture.run_sender(&config, &invalid, Some(&input), 0, 25);
    assert!(!process.exit().success()); assert!(!invalid.exists());
}

#[test]
fn recovery_uses_current_client_authorization_without_recreating_a_checkpoint() {
    let fixture = Fixture::new(); let ledger = fixture.ledger(); let data = b"private";
    let (mut receiver, address) = fixture.serve(&fixture.receiver(2, data.len()), &ledger);
    let mut config = fixture.sender(address, 2, data.len()); let checkpoint = fixture.unique("checkpoint"); let input = fixture.input(data);
    let mut original = fixture.run_sender(&config, &checkpoint, Some(&input), 1, 25);
    original.until("send_result"); assert!(original.exit().success()); receiver.until("resume_completion");
    let before = files(&fixture.inbox); let history = std::fs::read(&ledger).unwrap(); let saved = checkpoint_bytes(&checkpoint, data);
    config["identity"] = fixture.identity("unlisted");
    let mut denied = fixture.run_sender(&config, &checkpoint, None, 4, 25);
    let (failed, attempts) = denied.until("send_result"); assert!(!denied.exit().success());
    assert!(failed["transfer"]["receipt"].is_null()); assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0]["retry_eligible"], false);
    let refusal = receiver.until("resume_completion").0; assert_eq!(refusal["transfer"]["status"], "tls_failed");
    assert!(refusal["session"].is_null()); assert_eq!(files(&fixture.inbox), before);
    assert_eq!(std::fs::read(&ledger).unwrap(), history); assert_eq!(checkpoint_bytes(&checkpoint, data), saved);
    receiver.stop();
}

#[test]
fn signal_joins_a_real_pending_handshake_and_releases_checkpoint_ownership() {
    let fixture = Fixture::new(); let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let mut config = fixture.sender(listener.local_addr().unwrap(), 2, 10); config["operation_timeout_secs"] = json!(15);
    let checkpoint = fixture.unique("checkpoint"); let input = fixture.input(b"pending");
    let mut sender = fixture.run_sender(&config, &checkpoint, Some(&input), 4, 60_000);
    let mut socket = accept(&listener); socket.set_read_timeout(Some(WAIT)).unwrap();
    assert!(socket.read(&mut [0; 4096]).unwrap() > 0, "real TLS bytes precede the signal");
    let contender = OpenOptions::new().read(true).write(true).open(&checkpoint).unwrap();
    assert_eq!(io::Error::from(contender.try_lock().unwrap_err()).kind(), io::ErrorKind::WouldBlock);
    sender.signal(); let result = sender.until("send_result").0; assert!(!sender.exit().success());
    assert_eq!(result["transfer"]["status"], "cancelled"); assert_eq!(result["transfer"]["attempts"], 1);
    assert_eq!(result["checkpoint_persisted"], false); assert_eq!(result["drained"], true);
    assert!(result["transfer"]["receipt"].is_null()); contender.try_lock().unwrap(); drop(contender);
    assert_eq!(std::fs::metadata(&checkpoint).unwrap().len(), 0);
    let mut recovery = fixture.run_sender(&config, &checkpoint, None, 1, 25); assert!(!recovery.exit().success());
    assert_eq!(listener.accept().unwrap_err().kind(), io::ErrorKind::WouldBlock);
}
