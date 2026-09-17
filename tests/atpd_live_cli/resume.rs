//! Real executables, opaque TLS relay failures, and retained file witnesses.
//! The relay never decrypts TLS or calls the SDK's reconciliation helpers.

use super::*;
use std::io::Write;
use std::net::{Shutdown, TcpStream};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

impl Fixture {
    fn spawn_resumable(&self, operation: &str, config: Value, input: Option<&[u8]>,
        attempts: u32, delay_ms: u64, proof_secs: u64) -> Process
    {
        let path = self.json_file(config);
        let stderr = self.unique("resume-stderr");
        let error_log = OpenOptions::new().write(true).create_new(true).open(&stderr).unwrap();
        let mut command = Command::new(BINARY);
        command.args([operation, "--config"]).arg(path)
            .arg("--attempts").arg(attempts.to_string())
            .arg("--retry-delay-ms").arg(delay_ms.to_string())
            .stdout(Stdio::piped()).stderr(error_log);
        if operation == "receive-resumable" {
            command.arg("--proof-recovery-secs").arg(proof_secs.to_string());
        }
        if let Some(bytes) = input {
            let path = self.unique("resume-input");
            std::fs::write(&path, bytes).unwrap();
            command.arg("--input").arg(path);
        }
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

    fn resume_receiver(&self, workers: usize, limit: u64) -> (Process, SocketAddr) {
        let mut config = self.receiver_config(workers, limit, limit * 2);
        config["max_connections"] = json!(1);
        config["epoch_bytes"] = json!(65536);
        config["operation_timeout_secs"] = json!(2);
        let mut process = self.spawn_resumable("receive-resumable", config, None, 8, 25, 1);
        let ready = process.event("ready");
        assert_eq!(ready["profile"], "atp-live-resume/1");
        assert_eq!(ready["session_preallocated"], true);
        assert_eq!(ready["expected_client_certificate_sha256"], self.allowed);
        assert_eq!(ready["publication"]["state"], "staged");
        let address = ready["address"].as_str().unwrap().parse().unwrap();
        (process, address)
    }

    fn resume_sender(&self, address: SocketAddr, workers: usize, bytes: &[u8], delay_ms: u64) -> Process {
        let mut config = self.sender_config(address, "allowed", workers);
        config["epoch_bytes"] = json!(65536);
        config["max_transfer_bytes"] = json!(bytes.len());
        config["operation_timeout_secs"] = json!(2);
        self.spawn_resumable("send-resumable", config, Some(bytes), 4, delay_ms, 1)
    }
}

fn until(process: &mut Process, terminal: &str) -> (Value, Vec<Value>) {
    let mut attempts = Vec::new();
    loop {
        let event = process.events.recv_timeout(WAIT).unwrap_or_else(|error| {
            panic!("missing {terminal}: {error}; stderr {}", process.stderr.display())
        }).unwrap();
        if event["event"] == terminal { return (event, attempts); }
        assert_eq!(event["event"], "resume_attempt", "unexpected result: {event}");
        attempts.push(event);
        assert!(attempts.len() <= 16, "finite test budget must bound output");
    }
}

fn finish_receiver(process: &mut Process) -> (Value, Vec<Value>) {
    let (result, attempts) = until(process, "receive_result");
    let stopped = process.event("stopped");
    assert_eq!(stopped["drained"], true);
    assert!(process.exit().success());
    (result, attempts)
}

fn verify_resumed_file(fixture: &Fixture, sent: &Value, received: &Value, bytes: &[u8]) {
    assert_eq!(sent["transfer"]["status"], "complete");
    assert_eq!(sent["final_proof_direction"], "received");
    assert_eq!(sent["transfer"]["receipt"], received["completed_receipt"]);
    assert_eq!(received["sender_receipt_observed"], false);
    assert_eq!(received["publication"]["state"], "durable");
    assert_eq!(received["completed_receipt"]["sha256"], hex::encode(Sha256::digest(bytes)));
    let filename = received["publication"]["filename"].as_str().unwrap();
    let path = fixture.inbox.join(filename);
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    let final_metadata = std::fs::metadata(&path).unwrap();
    let entries = fixture.entries();
    assert_eq!(entries.len(), 3, "exactly one lock, one staging alias, and one destination");
    assert_eq!(entries.iter().filter(|path| {
        let m = std::fs::metadata(path).unwrap();
        (m.dev(), m.ino()) == (final_metadata.dev(), final_metadata.ino())
    }).count(), 2);
}

#[derive(Clone, Copy)]
enum Fault { Prefix(u64), Publication }

fn fault_ready(directory: &Path, fault: Fault) -> bool {
    std::fs::read_dir(directory).unwrap().any(|entry| {
        let entry = entry.unwrap();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        match fault {
            Fault::Prefix(length) => name.starts_with(".atp-live-")
                && entry.metadata().unwrap().len() >= length,
            Fault::Publication => name.ends_with(".bin"),
        }
    })
}

struct Relay {
    address: SocketAddr,
    stopped: Arc<AtomicBool>,
    faulted: Arc<AtomicBool>,
    connections: Arc<AtomicUsize>,
    worker: Option<JoinHandle<()>>,
}

fn retry_read(error: &io::Error) -> bool {
    matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted)
}

impl Relay {
    fn new(remote: SocketAddr, inbox: PathBuf, fault: Fault) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let stopped = Arc::new(AtomicBool::new(false));
        let faulted = Arc::new(AtomicBool::new(false));
        let connections = Arc::new(AtomicUsize::new(0));
        let (stop, failed, count) = (stopped.clone(), faulted.clone(), connections.clone());
        let worker = thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                let (client, _) = match listener.accept() {
                    Ok(pair) => pair,
                    Err(error) if retry_read(&error) => { thread::sleep(Duration::from_millis(2)); continue; }
                    Err(error) => panic!("relay accept: {error}"),
                };
                count.fetch_add(1, Ordering::SeqCst);
                let server = TcpStream::connect_timeout(&remote, Duration::from_secs(2)).unwrap();
                for stream in [&client, &server] {
                    stream.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
                    stream.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
                }
                let ended = Arc::new(AtomicBool::new(false));
                let mut client_read = client.try_clone().unwrap();
                let mut server_write = server.try_clone().unwrap();
                let (up_stop, up_end) = (stop.clone(), ended.clone());
                let upstream = thread::spawn(move || {
                    let mut bytes = [0; 4096];
                    while !up_stop.load(Ordering::SeqCst) && !up_end.load(Ordering::SeqCst) {
                        match client_read.read(&mut bytes) {
                            Ok(0) => break,
                            Ok(n) => { if server_write.write_all(&bytes[..n]).is_err() { break; } }
                            Err(error) if retry_read(&error) => continue,
                            Err(_) => break,
                        }
                    }
                    up_end.store(true, Ordering::SeqCst);
                    let _ = client_read.shutdown(Shutdown::Both);
                    let _ = server_write.shutdown(Shutdown::Both);
                });
                let (mut server_read, mut client_write) = (server, client);
                let mut bytes = [0; 4096];
                while !stop.load(Ordering::SeqCst) && !ended.load(Ordering::SeqCst) {
                    match server_read.read(&mut bytes) {
                        Ok(0) => break,
                        Ok(n) => {
                            // Discard the response only after the actual receiver
                            // file witnesses the selected prefix or publication.
                            if !failed.load(Ordering::SeqCst) && fault_ready(&inbox, fault) {
                                failed.store(true, Ordering::SeqCst);
                                break;
                            }
                            if client_write.write_all(&bytes[..n]).is_err() { break; }
                        }
                        Err(error) if retry_read(&error) => continue,
                        Err(_) => break,
                    }
                }
                ended.store(true, Ordering::SeqCst);
                let _ = server_read.shutdown(Shutdown::Both);
                let _ = client_write.shutdown(Shutdown::Both);
                upstream.join().unwrap();
            }
        });
        Self { address, stopped, faulted, connections, worker: Some(worker) }
    }
}

impl Relay {
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
fn resumable_commands_deliver_regular_and_empty_files_on_both_runtime_shapes() {
    for workers in [1, 2] {
        for bytes in [b"ordinary resumable CLI delivery".as_slice(), b""] {
            let fixture = Fixture::new();
            let (mut receiver, address) = fixture.resume_receiver(workers, bytes.len() as u64);
            let mut sender = fixture.resume_sender(address, workers, bytes, 25);
            let (sent, attempts) = until(&mut sender, "send_result");
            assert_eq!(attempts.len(), 1);
            assert!(sender.exit().success());
            let (received, _) = finish_receiver(&mut receiver);
            assert_eq!(received["recovery_end"], "proof_recovery_expired");
            verify_resumed_file(&fixture, &sent, &received, bytes);
        }
    }
}

#[test]
fn executable_reconnect_reconciles_a_witnessed_lost_epoch_ack_without_new_inbox_charge() {
    for workers in [1, 2] {
        let bytes: Vec<u8> = (0..196_609_usize).map(|n| n.wrapping_mul(37).to_le_bytes()[0]).collect();
        let fixture = Fixture::new();
        let (mut receiver, address) = fixture.resume_receiver(workers, bytes.len() as u64);
        let mut relay = Relay::new(address, fixture.inbox.clone(), Fault::Prefix(65536));
        let mut sender = fixture.resume_sender(relay.address, workers, &bytes, 50);
        let (sent, send_attempts) = until(&mut sender, "send_result");
        assert!(sender.exit().success());
        let (received, receive_attempts) = finish_receiver(&mut receiver);
        assert!(relay.faulted.load(Ordering::SeqCst), "actual post-prefix response must be lost");
        assert_eq!(relay.connections.load(Ordering::SeqCst), 2);
        assert_eq!(send_attempts.len(), 2);
        assert_ne!(send_attempts[0]["transfer"]["status"], "complete");
        assert_eq!(receive_attempts[0]["transfer"]["flushed_prefix_bytes"], 65536);
        assert_eq!(received["last_transfer"]["sink_written_bytes"], bytes.len());
        verify_resumed_file(&fixture, &sent, &received, &bytes);
        relay.finish();
    }
}

#[test]
fn executable_reconnect_recovers_lost_final_proof_without_republishing() {
    let bytes = b"commit once even when its final Proof is lost";
    let fixture = Fixture::new();
    let (mut receiver, address) = fixture.resume_receiver(2, bytes.len() as u64);
    let mut relay = Relay::new(address, fixture.inbox.clone(), Fault::Publication);
    let mut sender = fixture.resume_sender(relay.address, 2, bytes, 50);
    let (sent, send_attempts) = until(&mut sender, "send_result");
    assert!(sender.exit().success());
    let (received, receive_attempts) = finish_receiver(&mut receiver);
    assert!(relay.faulted.load(Ordering::SeqCst));
    assert_eq!(relay.connections.load(Ordering::SeqCst), 2);
    assert_eq!(send_attempts.len(), 2);
    assert!(receive_attempts.iter().any(|record| record["transfer"]["receipt_reused"] == true
        && record["transfer"]["status"] == "complete"));
    verify_resumed_file(&fixture, &sent, &received, bytes);
    relay.finish();
}

#[test]
fn executable_sender_does_not_retry_certificate_refusal_and_receiver_never_publishes() {
    let fixture = Fixture::new();
    let (mut receiver, address) = fixture.resume_receiver(2, 4096);
    let config = fixture.sender_config(address, "unlisted", 1);
    let mut sender = fixture.spawn_resumable("send-resumable", config, Some(b"not authorized"), 4, 25, 1);
    let (sent, attempts) = until(&mut sender, "send_result");
    assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0]["retry_eligible"], false);
    assert_ne!(sent["transfer"]["status"], "complete");
    assert!(!sender.exit().success());
    kill(Pid::from_raw(i32::try_from(receiver.child.id()).unwrap()), Signal::SIGTERM).unwrap();
    let (received, _) = until(&mut receiver, "receive_result");
    assert!(received["completed_receipt"].is_null());
    assert!(!receiver.exit().success());
    assert_eq!(fixture.entries().len(), 2, "startup created only one staging file and its lock");
    assert!(!fixture.entries().iter().any(|path| path.extension().is_some_and(|ext| ext == "bin")));
}

#[test]
fn executable_shutdown_between_retries_preserves_partial_bytes_without_fabricated_eof() {
    let bytes = vec![0x4d; 196_609];
    let fixture = Fixture::new();
    let (mut receiver, address) = fixture.resume_receiver(2, bytes.len() as u64);
    let mut relay = Relay::new(address, fixture.inbox.clone(), Fault::Prefix(65536));
    let mut sender = fixture.resume_sender(relay.address, 2, &bytes, 5000);
    let first = sender.event("resume_attempt");
    assert!(relay.faulted.load(Ordering::SeqCst));
    assert_eq!(first["retry_eligible"], true);
    kill(Pid::from_raw(i32::try_from(sender.child.id()).unwrap()), Signal::SIGTERM).unwrap();
    let (sent, later) = until(&mut sender, "send_result");
    assert!(later.is_empty());
    assert_eq!(sent["final_proof_direction"], "not_received");
    assert!(!sender.exit().success());
    kill(Pid::from_raw(i32::try_from(receiver.child.id()).unwrap()), Signal::SIGTERM).unwrap();
    let (received, _) = until(&mut receiver, "receive_result");
    assert!(received["completed_receipt"].is_null());
    assert!(!receiver.exit().success());
    assert_eq!(relay.connections.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.entries().len(), 2);
    let staging = fixture.entries().into_iter().find(|path| path.extension().is_some_and(|ext| ext == "part")).unwrap();
    assert_eq!(std::fs::read(staging).unwrap(), bytes[..65536]);
    relay.finish();
}

#[test]
fn executable_resume_attempt_budget_bounds_a_real_silent_peer() {
    let fixture = Fixture::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let mut config = fixture.sender_config(address, "allowed", 1);
    config["operation_timeout_secs"] = json!(1);
    let observed = Arc::new(AtomicUsize::new(0));
    let observed_peer = observed.clone();
    let peer = thread::spawn(move || {
        let start = Instant::now();
        for _ in 0..2 {
            let (mut socket, _) = loop {
                match listener.accept() {
                    Ok(pair) => break pair,
                    Err(error) if retry_read(&error) => {
                        assert!(start.elapsed() < WAIT); thread::sleep(Duration::from_millis(2));
                    }
                    Err(error) => panic!("silent peer accept: {error}"),
                }
            };
            socket.set_read_timeout(Some(WAIT)).unwrap();
            let mut record = [0; 4096];
            assert!(socket.read(&mut record).unwrap() > 0, "actual TLS ClientHello required");
            observed_peer.fetch_add(1, Ordering::SeqCst);
            loop {
                match socket.read(&mut record) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        }
    });
    let mut sender = fixture.spawn_resumable("send-resumable", config, Some(b"not delivered"), 2, 25, 1);
    let (result, attempts) = until(&mut sender, "send_result");
    assert!(!sender.exit().success());
    peer.join().unwrap();
    assert_eq!(observed.load(Ordering::SeqCst), 2);
    assert_eq!(attempts.len(), 2);
    assert_eq!(result["transfer"]["attempts"], 2);
    assert_eq!(result["transfer"]["status"], "timeout");
    assert!(result["transfer"]["receipt"].is_null());
}

#[test]
fn executable_resume_receiver_rejects_ambiguous_multi_client_settings_before_file_creation() {
    let fixture = Fixture::new();
    let config = fixture.receiver_config(1, 4096, 65536); // max_connections=2
    let mut receiver = fixture.spawn_resumable("receive-resumable", config, None, 4, 25, 1);
    assert!(!receiver.exit().success());
    assert!(receiver.events.try_iter().all(|event| event.unwrap()["event"] != "ready"));
    assert!(fixture.entries().is_empty());
}
