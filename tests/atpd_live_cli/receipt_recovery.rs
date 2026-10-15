//! Committed Proof recovery across actual receiver process death.
//! Original sender state survives. No test decrypts the opaque fault relay.
use super::*;
use asupersync::bytes::BytesMut;
use asupersync::codec::Decoder;
use asupersync::net::atp::protocol::codec::AtpFrameCodec;
use asupersync::net::atp::protocol::frames::{Frame, FrameType, ProtocolVersion};
use rustls::pki_types::{PrivateKeyDer, ServerName};

fn launch(fixture: &Fixture, mut command: Command) -> Process {
    let stderr = fixture.unique("receipt-recovery-stderr");
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
fn initialize(fixture: &Fixture, keys: u32) -> PathBuf {
    let path = fixture.unique("ledger");
    let mut command = Command::new(BINARY);
    command
        .args(["init-session-ledger", "--path"])
        .arg(&path)
        .arg("--max-keys")
        .arg(keys.to_string());
    let mut process = launch(fixture, command);
    process.event("session_ledger_initialized");
    assert!(process.exit().success());
    path
}
fn start(fixture: &Fixture, path: &Path, config: Value, recover: bool) -> (Process, SocketAddr) {
    let settings = fixture.json_file(config);
    let mut command = Command::new(BINARY);
    command
        .args(["serve-durable", "--config"])
        .arg(settings)
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
    if recover {
        command.arg("--recover-committed");
    }
    let mut process = launch(fixture, command);
    let ready = process.event("ready");
    assert_eq!(ready["committed_proof_recovery"], recover);
    assert_eq!(ready["continuation_restored"], false);
    assert_eq!(ready["durable_session_ledger"], true);
    let address = ready["address"].as_str().unwrap().parse().unwrap();
    (process, address)
}
fn completion(process: &mut Process) -> Value {
    for _ in 0..32 {
        let record = process.events.recv_timeout(WAIT).unwrap().unwrap();
        if record["event"] == "resume_completion" {
            return record;
        }
        assert_eq!(record["event"], "session_retired");
    }
    panic!("no connection completion");
}
fn stop(process: &mut Process) {
    kill(
        Pid::from_raw(i32::try_from(process.child.id()).unwrap()),
        Signal::SIGTERM,
    )
    .unwrap();
    for _ in 0..32 {
        let record = process.events.recv_timeout(WAIT).unwrap().unwrap();
        if record["event"] == "stopped" {
            assert_eq!(record["drained"], true);
            assert!(process.exit().success());
            return;
        }
        assert!(record["event"] == "resume_completion" || record["event"] == "session_retired");
    }
    panic!("service did not drain");
}
fn crash(process: &mut Process) {
    process.child.kill().unwrap();
    assert!(!process.exit().success());
}
// Independent ledger checksum reader: no production decoder supplies the witness.
fn history(path: &Path) -> Vec<u8> {
    let bytes = std::fs::read(path).unwrap();
    assert_eq!(&bytes[..8], b"ATPRJ001");
    let hash = |previous: &[u8], body: &[u8]| {
        let mut hash = Sha256::new();
        hash.update(b"asupersync.atpd.session-ledger.v1");
        hash.update(previous);
        hash.update(body);
        hash.finalize().to_vec()
    };
    let mut previous = hash(&[], &bytes[..16]);
    assert_eq!(&bytes[16..48], previous);
    assert_eq!((bytes.len() - 48) % 256, 0);
    for (sequence, record) in bytes[48..].chunks_exact(256).enumerate() {
        assert_eq!(&record[..8], &(sequence as u64).to_be_bytes());
        let actual = hash(&previous, &record[..224]);
        assert_eq!(&record[224..], actual);
        previous = actual;
    }
    bytes
}
fn published_file(fixture: &Fixture, history: &[u8]) -> PathBuf {
    let last = &history[history.len() - 256..];
    assert_eq!(last[8], 2);
    fixture
        .inbox
        .join(std::str::from_utf8(&last[80..116]).unwrap())
}

#[test]
fn original_sender_recovers_proof_after_receiver_death_without_rereading_or_republishing() {
    for workers in [1, 2] {
        let fixture = Fixture::new();
        let path = initialize(&fixture, 1);
        let bytes: Vec<_> = (0_usize..131083)
            .map(|n| ((n * 37) ^ (n / 251)).to_le_bytes()[0])
            .collect();
        // Full ledger and full logical inbox usage must still permit read-only recovery.
        let mut config =
            fixture.receiver_config(workers, bytes.len() as u64, bytes.len() as u64 * 2);
        config["epoch_bytes"] = json!(65536);
        let (mut receiver, address) = start(&fixture, &path, config.clone(), true);
        let mut relay = Relay::new(address, fixture.inbox.clone(), Fault::Publication);
        let mut sender = fixture.resume_sender(relay.address, workers, &bytes, 5000);
        let first = sender.event("resume_attempt");
        assert_ne!(first["transfer"]["status"], "complete");
        assert!(relay.faulted.load(Ordering::SeqCst));
        let pid = Pid::from_raw(i32::try_from(sender.child.id()).unwrap());
        kill(pid, Signal::SIGSTOP).unwrap(); // Test-owned producer cannot race restart.
        let original_report = completion(&mut receiver);
        assert!(original_report["transfer"]["completed_receipt"].is_object());
        let before = history(&path);
        let output = published_file(&fixture, &before);
        assert_eq!(std::fs::read(&output).unwrap(), bytes);
        let files = fixture.entries();
        let metadata = std::fs::metadata(&output).unwrap();
        crash(&mut receiver);
        // The producer had sent ObjectComplete. Its retained final receipt must
        // suffice now; changing this test-owned source after EOF catches rereads.
        let sources: Vec<_> = std::fs::read_dir(&fixture.root)
            .unwrap()
            .map(|p| p.unwrap().path())
            .filter(|p| p.extension().is_some_and(|e| e == "resume-input"))
            .collect();
        assert_eq!(sources.len(), 1);
        std::fs::write(&sources[0], b"must not be reread").unwrap();
        config["bind"] = json!(address);
        let (mut restarted, rebound) = start(&fixture, &path, config, true);
        assert_eq!(rebound, address);
        kill(pid, Signal::SIGCONT).unwrap();
        let (sent, attempts) = until(&mut sender, "send_result");
        assert!(!attempts.is_empty());
        assert!(sender.exit().success());
        assert!(relay.connections.load(Ordering::SeqCst) >= 2);
        let recovered = completion(&mut restarted);
        assert_eq!(sent["transfer"]["status"], "complete");
        assert_eq!(
            sent["transfer"]["receipt"],
            original_report["transfer"]["completed_receipt"]
        );
        assert_eq!(
            recovered["transfer"]["receipt"],
            sent["transfer"]["receipt"]
        );
        assert_eq!(recovered["transfer"]["receipt_reused"], true);
        assert_eq!(recovered["transfer"]["sink_written_bytes"], 0);
        assert!(
            recovered["publication"].is_null(),
            "recovery must not construct a live file sink"
        );
        assert_eq!(recovered["sender_receipt_observed"], false);
        assert_eq!(history(&path), before);
        assert_eq!(fixture.entries(), files);
        let after = std::fs::metadata(&output).unwrap();
        assert_eq!((after.dev(), after.ino()), (metadata.dev(), metadata.ino()));
        assert_eq!(std::fs::read(output).unwrap(), bytes);
        relay.finish();
        stop(&mut restarted);
    }
}

// Synchronous independent protocol peer for negative checks, never a SDK session.
struct Peer {
    tls: rustls::StreamOwned<rustls::ClientConnection, TcpStream>,
    codec: AtpFrameCodec,
    buffer: BytesMut,
}
impl Peer {
    fn connect(fixture: &Fixture, address: SocketAddr, identity: &str) -> Self {
        let certificates = |name: &str| {
            CertificateDer::pem_reader_iter(&mut BufReader::new(
                std::fs::File::open(fixture.root.join(format!("{name}.pem"))).unwrap(),
            ))
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
        };
        let mut roots = rustls::RootCertStore::empty();
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
        let tcp = TcpStream::connect_timeout(&address, WAIT).unwrap();
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
        let bytes = Frame::new(ProtocolVersion::V0, kind, payload)
            .unwrap()
            .to_wire_bytes()
            .unwrap();
        self.tls.write_all(&bytes)?;
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
            assert!(self.buffer.len() <= 65536);
        }
    }
    fn hello(&mut self, nonce: u8) -> io::Result<Vec<u8>> {
        let mut offer = b"ATPRSM01ATPLIVE1".to_vec();
        offer.extend_from_slice(&[nonce; 32]);
        offer.extend_from_slice(&8_u32.to_be_bytes());
        offer.extend_from_slice(&64_u64.to_be_bytes());
        self.send(FrameType::Handshake, offer)?;
        let state = self.receive()?;
        assert_eq!(state.frame_type(), FrameType::HandshakeAck);
        assert_eq!(state.payload().len(), 141);
        Ok(state.payload().to_vec())
    }
}
fn prepare(
    fixture: &Fixture,
    path: &Path,
    nonce: u8,
    bytes: &[u8],
    committed: bool,
) -> (Process, Vec<u8>) {
    let (mut server, address) = start(fixture, path, fixture.receiver_config(1, 64, 65536), true);
    let mut peer = Peer::connect(fixture, address, "allowed");
    let state = peer.hello(nonce).unwrap();
    let mut prefix = state[60..108].to_vec();
    if !bytes.is_empty() {
        let mut epoch = prefix;
        epoch.extend_from_slice(&Sha256::digest(bytes));
        epoch.extend_from_slice(bytes);
        peer.send(FrameType::ObjectData, epoch).unwrap();
        let ack = peer.receive().unwrap();
        assert_eq!(ack.frame_type(), FrameType::Control);
        prefix = ack.payload().to_vec();
    }
    let mut final_value = prefix;
    final_value.extend_from_slice(&Sha256::digest(bytes));
    if committed {
        peer.send(FrameType::ObjectComplete, final_value.clone())
            .unwrap();
        let proof = peer.receive().unwrap();
        assert_eq!(proof.frame_type(), FrameType::Proof);
        assert_eq!(proof.payload(), final_value);
        assert_eq!(completion(&mut server)["transfer"]["status"], "complete");
    }
    drop(peer);
    crash(&mut server);
    (server, final_value)
}

#[test]
fn empty_saved_receipt_replays_only_the_exact_final_commitment() {
    let fixture = Fixture::new();
    let path = initialize(&fixture, 1);
    let (_, final_value) = prepare(&fixture, &path, 7, b"", true);
    let before = history(&path);
    let files = fixture.entries();
    let (mut server, address) = start(&fixture, &path, fixture.receiver_config(2, 64, 65536), true);
    for bad in [true, false] {
        let mut peer = Peer::connect(&fixture, address, "allowed");
        let state = peer.hello(7).unwrap();
        assert_eq!(state[140], 1);
        assert_eq!(&state[60..140], final_value);
        let mut final_request = final_value.clone();
        if bad {
            final_request[79] ^= 1;
        }
        peer.send(FrameType::ObjectComplete, final_request).unwrap();
        if bad {
            assert!(peer.receive().is_err());
        } else {
            let proof = peer.receive().unwrap();
            assert_eq!(proof.frame_type(), FrameType::Proof);
            assert_eq!(proof.payload(), final_value);
        }
        let report = completion(&mut server);
        assert_eq!(
            report["transfer"]["status"],
            if bad {
                "continuity_refused"
            } else {
                "complete"
            }
        );
        assert_eq!(report["transfer"]["receipt_reused"], true);
        assert_eq!(report["transfer"]["sink_written_bytes"], 0);
    }
    assert_eq!(history(&path), before);
    assert_eq!(fixture.entries(), files);
    stop(&mut server);
}

#[test]
fn restored_nonempty_session_refuses_data_instead_of_reopening_its_sink() {
    let fixture = Fixture::new();
    let path = initialize(&fixture, 1);
    let (_, final_value) = prepare(&fixture, &path, 8, b"saved", true);
    let before = history(&path);
    let files = fixture.entries();
    let (mut server, address) = start(&fixture, &path, fixture.receiver_config(1, 64, 65536), true);
    let mut peer = Peer::connect(&fixture, address, "allowed");
    let state = peer.hello(8).unwrap();
    assert_eq!(state[140], 1);
    assert_eq!(&state[60..140], final_value);
    peer.send(FrameType::ObjectData, vec![0; 81]).unwrap();
    assert!(peer.receive().is_err());
    let report = completion(&mut server);
    assert_eq!(report["transfer"]["status"], "continuity_refused");
    assert_eq!(report["transfer"]["sink_written_bytes"], 0);
    assert_eq!(history(&path), before);
    assert_eq!(fixture.entries(), files);
    stop(&mut server);
}

#[test]
fn unresolved_history_is_still_refused_and_old_refusal_mode_is_unchanged() {
    for committed in [true, false] {
        let fixture = Fixture::new();
        let path = initialize(&fixture, 1);
        prepare(&fixture, &path, 9, b"part", committed);
        let before = history(&path);
        let files = fixture.entries();
        // Unresolved claims fail even with recovery enabled; old mode also
        // continues refusing successful prior claims when no opt-in is present.
        let (mut server, address) = start(
            &fixture,
            &path,
            fixture.receiver_config(1, 64, 65536),
            !committed,
        );
        let mut peer = Peer::connect(&fixture, address, "allowed");
        assert!(peer.hello(9).is_err());
        assert_eq!(
            completion(&mut server)["transfer"]["status"],
            "durable_session_refused"
        );
        assert_eq!(history(&path), before);
        assert_eq!(fixture.entries(), files);
        stop(&mut server);
    }
}

#[test]
fn changed_missing_or_truncated_files_cannot_supply_a_saved_proof() {
    for mode in ["changed", "missing", "short"] {
        let fixture = Fixture::new();
        let path = initialize(&fixture, 1);
        prepare(&fixture, &path, 10, b"saved", true);
        let before = history(&path);
        let output = published_file(&fixture, &before);
        match mode {
            "changed" => std::fs::write(&output, b"wrong").unwrap(),
            "short" => std::fs::write(&output, b"x").unwrap(),
            _ => std::fs::rename(&output, fixture.inbox.join("retained-original")).unwrap(),
        }
        let files = fixture.entries();
        let (mut server, address) =
            start(&fixture, &path, fixture.receiver_config(1, 64, 65536), true);
        let mut peer = Peer::connect(&fixture, address, "allowed");
        assert!(peer.hello(10).is_err());
        let report = completion(&mut server);
        assert_eq!(report["transfer"]["status"], "factory_failed");
        assert!(report["publication"].is_null());
        assert_eq!(history(&path), before);
        assert_eq!(fixture.entries(), files);
        stop(&mut server);
    }
}

#[test]
fn saved_receipts_do_not_bypass_current_client_certificate_authorization() {
    let fixture = Fixture::new();
    let path = initialize(&fixture, 1);
    let (_, final_value) = prepare(&fixture, &path, 11, b"saved", true);
    let before = history(&path);
    let files = fixture.entries();
    let (mut server, address) = start(&fixture, &path, fixture.receiver_config(2, 64, 65536), true);
    let mut unlisted = Peer::connect(&fixture, address, "unlisted");
    assert!(unlisted.hello(11).is_err());
    let refused = completion(&mut server);
    assert_eq!(refused["transfer"]["status"], "tls_failed");
    assert!(refused["session"].is_null());
    let mut allowed = Peer::connect(&fixture, address, "allowed");
    assert_eq!(allowed.hello(11).unwrap()[140], 1);
    allowed
        .send(FrameType::ObjectComplete, final_value.clone())
        .unwrap();
    let proof = allowed.receive().unwrap();
    assert_eq!(proof.frame_type(), FrameType::Proof);
    assert_eq!(proof.payload(), final_value);
    assert_eq!(completion(&mut server)["transfer"]["status"], "complete");
    assert_eq!(history(&path), before);
    assert_eq!(fixture.entries(), files);
    stop(&mut server);
}
