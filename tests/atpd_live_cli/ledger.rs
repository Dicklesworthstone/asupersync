//! Process-death duplicate suppression with independent authenticated wire peers.
//! No session registry helper is called. Created processes/files remain scoped;
//! retained fixtures and logs are never deleted by this suite.
use super::*;
use asupersync::bytes::BytesMut;
use asupersync::codec::Decoder;
use asupersync::net::atp::protocol::codec::AtpFrameCodec;
use asupersync::net::atp::protocol::frames::{Frame, FrameType, ProtocolVersion};
use rustls::pki_types::{PrivateKeyDer, ServerName};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::sync::Arc;

fn launch(fixture: &Fixture, mut command: Command) -> Process {
    let stderr = fixture.unique("ledger-stderr");
    command.stdout(Stdio::piped()).stderr(
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&stderr)
            .unwrap(),
    );
    let mut child = command.spawn().unwrap();
    let output = child.stdout.take().unwrap();
    let (sender, events) = mpsc::channel();
    let reader = thread::spawn(move || {
        for line in BufReader::new(output).lines() {
            let record = line.map_err(|error| error.to_string()).and_then(|line| {
                serde_json::from_str::<Value>(&line).map_err(|error| error.to_string())
            });
            if sender.send(record).is_err() {
                break;
            }
        }
    });
    Process {
        child,
        reader: Some(reader),
        events,
        stderr,
    }
}
fn initialize(fixture: &Fixture, maximum: u32) -> PathBuf {
    let path = fixture.unique("ledger");
    let mut command = Command::new(BINARY);
    command
        .args(["init-session-ledger", "--path"])
        .arg(&path)
        .arg("--max-keys")
        .arg(maximum.to_string());
    let mut process = launch(fixture, command);
    assert_eq!(
        process.event("session_ledger_initialized")["maximum_keys"],
        maximum
    );
    assert!(process.exit().success());
    path
}
fn spawn(fixture: &Fixture, path: &Path, config: Value) -> Process {
    let config = fixture.json_file(config);
    let mut command = Command::new(BINARY);
    command
        .args(["serve-durable", "--config"])
        .arg(config)
        .arg("--session-ledger")
        .arg(path)
        .args([
            "--max-sessions",
            "4",
            "--max-sessions-per-client",
            "4",
            "--max-session-keys",
            "16",
            "--attempts-per-session",
            "8",
            "--idle-retention-secs",
            "30",
            "--proof-recovery-secs",
            "60",
        ]);
    launch(fixture, command)
}
fn start(fixture: &Fixture, path: &Path, workers: usize) -> (Process, SocketAddr) {
    let mut process = spawn(fixture, path, fixture.receiver_config(workers, 64, 65536));
    let ready = process.event("ready");
    assert_eq!(ready["durable_session_ledger"], true);
    assert_eq!(ready["continuation_restored"], false);
    let address = ready["address"].as_str().unwrap().parse().unwrap();
    (process, address)
}
fn completion(process: &mut Process) -> Value {
    for _ in 0..32 {
        let event = process.events.recv_timeout(WAIT).unwrap().unwrap();
        if event["event"] == "resume_completion" {
            return event;
        }
        assert_eq!(event["event"], "session_retired");
    }
    panic!("missing bounded connection completion");
}
fn stop(process: &mut Process) {
    kill(
        Pid::from_raw(i32::try_from(process.child.id()).unwrap()),
        Signal::SIGTERM,
    )
    .unwrap();
    for _ in 0..32 {
        let event = process.events.recv_timeout(WAIT).unwrap().unwrap();
        if event["event"] == "stopped" {
            assert_eq!(event["drained"], true);
            assert!(process.exit().success());
            return;
        }
        assert!(event["event"] == "resume_completion" || event["event"] == "session_retired");
    }
    panic!("missing drained shutdown");
}
fn inspect(fixture: &Fixture, path: &Path) -> Vec<Value> {
    let mut command = Command::new(BINARY);
    command.args(["inspect-session-ledger", "--path"]).arg(path);
    let mut process = launch(fixture, command);
    let header = process.event("session_ledger");
    assert_eq!(header["continuation_restored"], false);
    let rows = (0..header["keys"].as_u64().unwrap())
        .map(|_| process.event("session_record"))
        .collect();
    assert!(process.exit().success());
    rows
}

struct Peer {
    tls: rustls::StreamOwned<rustls::ClientConnection, std::net::TcpStream>,
    codec: AtpFrameCodec,
    buffer: BytesMut,
}
impl Peer {
    fn connect(fixture: &Fixture, address: SocketAddr, identity: &str) -> Self {
        let mut roots = rustls::RootCertStore::empty();
        let certificates = |name: &str| {
            CertificateDer::pem_reader_iter(&mut BufReader::new(
                std::fs::File::open(fixture.root.join(format!("{name}.pem"))).unwrap(),
            ))
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
        };
        for certificate in certificates("ca") {
            roots.add(certificate).unwrap();
        }
        let key = PrivateKeyDer::pem_reader_iter(&mut BufReader::new(
            std::fs::File::open(fixture.root.join(format!("{identity}.key"))).unwrap(),
        ))
        .next()
        .unwrap()
        .unwrap();
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_client_auth_cert(certificates(identity), key)
        .unwrap();
        config.alpn_protocols = vec![b"atp-live-resume/1".to_vec()];
        config.resumption = rustls::client::Resumption::disabled();
        let tcp = std::net::TcpStream::connect_timeout(&address, WAIT).unwrap();
        tcp.set_read_timeout(Some(WAIT)).unwrap();
        tcp.set_write_timeout(Some(WAIT)).unwrap();
        let conn = rustls::ClientConnection::new(
            Arc::new(config),
            ServerName::try_from("localhost").unwrap(),
        )
        .unwrap();
        Self {
            tls: rustls::StreamOwned::new(conn, tcp),
            codec: AtpFrameCodec::with_max_frame_size(65536),
            buffer: BytesMut::new(),
        }
    }
    fn send(&mut self, kind: FrameType, payload: Vec<u8>) -> io::Result<()> {
        let frame = Frame::new(ProtocolVersion::V0, kind, payload)
            .unwrap()
            .to_wire_bytes()
            .unwrap();
        self.tls.write_all(&frame)?;
        self.tls.flush()
    }
    fn receive(&mut self) -> io::Result<Frame> {
        loop {
            if let Some(frame) = self
                .codec
                .decode(&mut self.buffer)
                .map_err(io::Error::other)?
            {
                return Ok(frame);
            }
            let mut bytes = [0; 4096];
            let count = self.tls.read(&mut bytes)?;
            if count == 0 {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
            }
            self.buffer.extend_from_slice(&bytes[..count]);
            assert!(
                self.buffer.len() <= 65536,
                "test peer response exceeded bound"
            );
        }
    }
    fn hello(&mut self, nonce: u8) -> io::Result<Vec<u8>> {
        let mut offer = b"ATPRSM01ATPLIVE1".to_vec();
        offer.extend_from_slice(&[nonce; 32]);
        offer.extend_from_slice(&8_u32.to_be_bytes());
        offer.extend_from_slice(&64_u64.to_be_bytes());
        self.send(FrameType::Handshake, offer)?;
        let ack = self.receive()?;
        assert_eq!(ack.frame_type(), FrameType::HandshakeAck);
        assert_eq!(ack.payload().len(), 141);
        Ok(ack.payload().to_vec())
    }
    fn epoch(&mut self, state: &[u8], bytes: &[u8]) -> Vec<u8> {
        let mut epoch = state[60..108].to_vec();
        epoch.extend_from_slice(&Sha256::digest(bytes));
        epoch.extend_from_slice(bytes);
        self.send(FrameType::ObjectData, epoch).unwrap();
        let ack = self.receive().unwrap();
        assert_eq!(ack.frame_type(), FrameType::Control);
        assert_eq!(ack.payload().len(), 48);
        ack.payload().to_vec()
    }
    fn finish(&mut self, prefix: &[u8], bytes: &[u8]) -> Vec<u8> {
        let mut final_value = prefix.to_vec();
        final_value.extend_from_slice(&Sha256::digest(bytes));
        self.send(FrameType::ObjectComplete, final_value.clone())
            .unwrap();
        let proof = self.receive().unwrap();
        assert_eq!(proof.frame_type(), FrameType::Proof);
        assert_eq!(proof.payload(), final_value);
        final_value
    }
}

// Independent fixed-record parser: assert persistence BEFORE observing the
// receiver's completion log. No production ledger decoder supplies the answer.
fn records(path: &Path) -> Vec<Vec<u8>> {
    let bytes = std::fs::read(path).unwrap();
    assert_eq!(&bytes[..8], b"ATPRJ001");
    let hash = |previous: &[u8], body: &[u8]| {
        let mut h = Sha256::new();
        h.update(b"asupersync.atpd.session-ledger.v1");
        h.update(previous);
        h.update(body);
        h.finalize().to_vec()
    };
    let mut previous = hash(&[], &bytes[..16]);
    assert_eq!(&bytes[16..48], previous);
    assert_eq!((bytes.len() - 48) % 256, 0);
    let mut rows = Vec::new();
    for (sequence, row) in bytes[48..].chunks_exact(256).enumerate() {
        assert_eq!(&row[..8], &(sequence as u64).to_be_bytes());
        let checksum = hash(&previous, &row[..224]);
        assert_eq!(&row[224..], checksum);
        previous = checksum;
        rows.push(row.to_vec());
    }
    rows
}

#[test]
fn durable_receiver_receipt_is_persisted_before_final_proof_including_empty_files() {
    for workers in [1, 2] {
        let fixture = Fixture::new();
        let path = initialize(&fixture, 4);
        let (mut receiver, address) = start(&fixture, &path, workers);
        for (nonce, bytes) in [(1, b"abc".as_slice()), (2, b"".as_slice())] {
            let mut peer = Peer::connect(&fixture, address, "allowed");
            let state = peer.hello(nonce).unwrap();
            let rows = records(&path);
            assert_eq!(rows.last().unwrap()[8], 1);
            assert_eq!(&rows.last().unwrap()[48..80], &[nonce; 32]);
            let prefix = if bytes.is_empty() {
                state[60..108].to_vec()
            } else {
                peer.epoch(&state, bytes)
            };
            peer.finish(&prefix, bytes);
            let rows = records(&path);
            let last = rows.last().unwrap();
            assert_eq!(last[8], 2);
            assert_eq!(&last[164..196], Sha256::digest(bytes).as_slice());
            let name = std::str::from_utf8(&last[80..116]).unwrap();
            assert_eq!(std::fs::read(fixture.inbox.join(name)).unwrap(), bytes);
            assert_eq!(completion(&mut receiver)["transfer"]["status"], "complete");
        }
        stop(&mut receiver);
        let entries = inspect(&fixture, &path);
        assert_eq!(entries.len(), 2);
        for entry in entries {
            assert_eq!(entry["state"], "committed");
            assert_eq!(entry["historical"], true);
        }
    }
}

fn crash_and_refuse(committed: bool) {
    let fixture = Fixture::new();
    let path = initialize(&fixture, 4);
    let (mut receiver, address) = start(&fixture, &path, 2);
    let mut peer = Peer::connect(&fixture, address, "allowed");
    let state = peer.hello(9).unwrap();
    let prefix = peer.epoch(&state, b"abc");
    if committed {
        peer.finish(&prefix, b"abc");
    }
    let before = records(&path);
    assert_eq!(before.len(), if committed { 2 } else { 1 });
    let files = fixture.entries();
    // SIGKILL only this test-owned process, after actual ACK/Proof witnesses.
    receiver.child.kill().unwrap();
    assert!(!receiver.exit().success());
    drop(peer);
    let (mut restarted, address) = start(&fixture, &path, 1);
    let mut peer = Peer::connect(&fixture, address, "allowed");
    assert!(peer.hello(9).is_err());
    let refused = completion(&mut restarted);
    assert_eq!(refused["transfer"]["status"], "durable_session_refused");
    assert!(refused["publication"].is_null());
    assert_eq!(records(&path), before);
    assert_eq!(fixture.entries(), files);
    // The same authorized client can still admit a genuinely different key.
    let mut fresh = Peer::connect(&fixture, address, "allowed");
    let state = fresh.hello(10).unwrap();
    fresh.finish(&state[60..108], b"");
    assert_eq!(completion(&mut restarted)["transfer"]["status"], "complete");
    stop(&mut restarted);
    let entries = inspect(&fixture, &path);
    let old = entries
        .iter()
        .find(|row| row["stream_nonce"] == hex::encode([9; 32]))
        .unwrap();
    assert_eq!(
        old["state"],
        if committed {
            "committed"
        } else {
            "claimed_unresolved"
        }
    );
    assert_eq!(old["sender_receipt_observed"], false);
}

#[test]
fn durable_receiver_refuses_claim_only_replay_after_process_death() {
    crash_and_refuse(false);
}
#[test]
fn durable_receiver_refuses_committed_replay_after_process_death() {
    crash_and_refuse(true);
}

#[test]
fn durable_key_budget_survives_restart_and_inspection_excludes_live_owners() {
    let fixture = Fixture::new();
    let path = initialize(&fixture, 1);
    let (mut receiver, address) = start(&fixture, &path, 1);
    let mut command = Command::new(BINARY);
    command
        .args(["inspect-session-ledger", "--path"])
        .arg(&path);
    let mut inspector = launch(&fixture, command);
    assert!(!inspector.exit().success());
    let mut conflicting = spawn(&fixture, &path, fixture.receiver_config(1, 64, 65536));
    assert!(!conflicting.exit().success());
    let mut peer = Peer::connect(&fixture, address, "allowed");
    let state = peer.hello(1).unwrap();
    peer.finish(&state[60..108], b"");
    completion(&mut receiver);
    stop(&mut receiver);
    let before = std::fs::read(&path).unwrap();
    let files = fixture.entries();
    let (mut restarted, address) = start(&fixture, &path, 1);
    let mut peer = Peer::connect(&fixture, address, "allowed");
    assert!(peer.hello(2).is_err());
    assert_eq!(
        completion(&mut restarted)["transfer"]["status"],
        "retention_refused"
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert_eq!(fixture.entries(), files);
    stop(&mut restarted);
}

#[test]
fn durable_claim_precedes_storage_refusal_and_never_becomes_a_commit_receipt() {
    let fixture = Fixture::new();
    let path = initialize(&fixture, 4);
    let mut receiver = spawn(&fixture, &path, fixture.receiver_config(1, 64, 0));
    let address = receiver.event("ready")["address"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let mut peer = Peer::connect(&fixture, address, "allowed");
    assert!(peer.hello(3).is_err());
    assert_eq!(
        completion(&mut receiver)["transfer"]["status"],
        "retention_refused"
    );
    let rows = records(&path);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0][8], 1);
    assert_eq!(
        fixture.entries(),
        vec![fixture.inbox.join(".atpd-live.lock")]
    );
    stop(&mut receiver);
    let entries = inspect(&fixture, &path);
    assert_eq!(entries[0]["state"], "claimed_unresolved");
    assert!(entries[0]["receipt"].is_null());
}

#[test]
fn durable_profile_refuses_unlisted_clients_without_ledger_or_sink_effects() {
    let fixture = Fixture::new();
    let path = initialize(&fixture, 2);
    let (mut receiver, address) = start(&fixture, &path, 1);
    let before = std::fs::read(&path).unwrap();
    let mut peer = Peer::connect(&fixture, address, "unlisted");
    assert!(peer.hello(7).is_err());
    let refused = completion(&mut receiver);
    assert_eq!(refused["transfer"]["status"], "tls_failed");
    assert!(refused["session"].is_null());
    assert!(refused["publication"].is_null());
    assert_eq!(std::fs::read(path).unwrap(), before);
    stop(&mut receiver);
}

#[test]
fn durable_startup_never_recreates_missing_or_repairs_torn_history() {
    let fixture = Fixture::new();
    let path = initialize(&fixture, 2);
    let mut broken = std::fs::read(&path).unwrap();
    broken.push(0);
    let torn = fixture.unique("torn");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&torn)
        .unwrap();
    file.write_all(&broken).unwrap();
    file.sync_all().unwrap();
    let missing = fixture.unique("missing");
    for rejected in [&torn, &missing] {
        let mut process = spawn(&fixture, rejected, fixture.receiver_config(1, 64, 65536));
        assert!(!process.exit().success());
        assert!(
            process
                .events
                .try_iter()
                .all(|event| event.unwrap()["event"] != "ready")
        );
    }
    assert!(!missing.exists());
    assert_eq!(std::fs::read(torn).unwrap(), broken);
}

#[test]
fn durable_ledger_separates_equal_nonces_from_concurrent_authenticated_clients() {
    let fixture = Fixture::new();
    let path = initialize(&fixture, 4);
    let directory = fixture.root.join("other-inbox");
    std::fs::create_dir(&directory).unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let certificate = CertificateDer::pem_reader_iter(&mut BufReader::new(
        std::fs::File::open(fixture.root.join("unlisted.pem")).unwrap(),
    ))
    .next()
    .unwrap()
    .unwrap();
    let other = hex::encode(Sha256::digest(certificate.as_ref()));
    let mut config = fixture.receiver_config(2, 64, 65536);
    config["clients"]
        .as_array_mut()
        .unwrap()
        .push(json!({"certificate_sha256": other,
        "directory": directory, "max_retained_bytes": 65536, "max_retained_entries": 32}));
    let mut receiver = spawn(&fixture, &path, config);
    let address = receiver.event("ready")["address"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    thread::scope(|scope| {
        for identity in ["allowed", "unlisted"] {
            let fixture = &fixture;
            scope.spawn(move || {
                let mut peer = Peer::connect(fixture, address, identity);
                let state = peer.hello(8).unwrap();
                let prefix = peer.epoch(&state, b"abc");
                peer.finish(&prefix, b"abc");
            });
        }
    });
    for _ in 0..2 {
        assert_eq!(completion(&mut receiver)["transfer"]["status"], "complete");
    }
    assert_eq!(records(&path).len(), 4);
    stop(&mut receiver);
    let rows = inspect(&fixture, &path);
    assert_eq!(rows.len(), 2);
    assert_ne!(
        rows[0]["client_certificate_sha256"],
        rows[1]["client_certificate_sha256"]
    );
    for row in rows {
        assert_eq!(row["stream_nonce"], hex::encode([8; 32]));
        let inbox = if row["client_certificate_sha256"] == fixture.allowed {
            &fixture.inbox
        } else {
            &directory
        };
        assert_eq!(
            std::fs::read(inbox.join(row["filename"].as_str().unwrap())).unwrap(),
            b"abc"
        );
    }
}

#[test]
fn durable_receipt_failure_does_not_erase_publication_or_emit_successful_proof() {
    let fixture = Fixture::new();
    let path = initialize(&fixture, 4);
    let (mut receiver, address) = start(&fixture, &path, 2);
    let mut peer = Peer::connect(&fixture, address, "allowed");
    let state = peer.hello(1).unwrap();
    let mut final_value = peer.epoch(&state, b"abc");
    final_value.extend_from_slice(&Sha256::digest(b"abc"));
    // Deliberate test-owned corruption, not a supported concurrent-writer mode.
    // Admission has succeeded, but receipt append must now refuse the changed length.
    let mut corruptor = OpenOptions::new().append(true).open(&path).unwrap();
    corruptor.write_all(&[0]).unwrap();
    corruptor.sync_all().unwrap();
    peer.send(FrameType::ObjectComplete, final_value).unwrap();
    assert!(peer.receive().is_err());
    let result = completion(&mut receiver);
    assert_eq!(result["transfer"]["status"], "commit_unconfirmed");
    assert_eq!(result["publication"]["state"], "durable");
    assert_eq!(result["proof_write_confirmed"], false);
    assert!(result["transfer"]["completed_receipt"].is_null());
    let file = fixture
        .inbox
        .join(result["publication"]["filename"].as_str().unwrap());
    assert_eq!(std::fs::read(file).unwrap(), b"abc");
    let before = fixture.entries();
    let mut next = Peer::connect(&fixture, address, "allowed");
    assert!(next.hello(2).is_err());
    assert_eq!(
        completion(&mut receiver)["transfer"]["status"],
        "factory_failed"
    );
    assert_eq!(fixture.entries(), before);
    stop(&mut receiver);
}
