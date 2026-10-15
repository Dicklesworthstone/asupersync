//! Shared resume executable: independent clients, ciphertext faults, and real files.
//! All fixtures remain on disk. No SDK registry helper stands in for routing.

use super::*;
use asupersync::bytes::BytesMut;
use asupersync::codec::Decoder;
use asupersync::net::atp::protocol::codec::AtpFrameCodec;
use asupersync::net::atp::protocol::frames::{Frame, FrameType, ProtocolVersion};
use rustls::pki_types::{PrivateKeyDer, ServerName};

#[derive(Clone, Copy)]
struct Limits {
    sessions: usize,
    per_client: usize,
    keys: usize,
    attempts: u32,
    idle: u64,
    proof: u64,
}

fn limits() -> Limits {
    Limits {
        sessions: 4,
        per_client: 2,
        keys: 16,
        attempts: 8,
        idle: 30,
        proof: 60,
    }
}

fn spawn_shared(fixture: &Fixture, config: Value, limits: Limits) -> Process {
    let path = fixture.json_file(config);
    let stderr = fixture.unique("shared-stderr");
    let error_log = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&stderr)
        .unwrap();
    let mut command = Command::new(BINARY);
    command
        .arg("serve-resumable")
        .arg("--config")
        .arg(path)
        .arg("--max-sessions")
        .arg(limits.sessions.to_string())
        .arg("--max-sessions-per-client")
        .arg(limits.per_client.to_string())
        .arg("--max-session-keys")
        .arg(limits.keys.to_string())
        .arg("--attempts-per-session")
        .arg(limits.attempts.to_string())
        .arg("--idle-retention-secs")
        .arg(limits.idle.to_string())
        .arg("--proof-recovery-secs")
        .arg(limits.proof.to_string())
        .stdout(Stdio::piped())
        .stderr(error_log);
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

fn start_shared(fixture: &Fixture, config: Value, limits: Limits) -> (Process, SocketAddr) {
    let mut process = spawn_shared(fixture, config, limits);
    let ready = process.event("ready");
    assert_eq!(ready["profile"], "atp-live-resume/1");
    assert_eq!(ready["mode"], "shared");
    assert_eq!(ready["application_commit"], true);
    assert_eq!(ready["session_preallocated"], false);
    assert_eq!(ready["max_sessions"], limits.sessions);
    let address: SocketAddr = ready["address"].as_str().unwrap().parse().unwrap();
    assert_ne!(address.port(), 0);
    (process, address)
}

fn event(process: &mut Process) -> Value {
    process
        .events
        .recv_timeout(WAIT)
        .unwrap_or_else(|error| {
            panic!(
                "missing shared-service event: {error}; stderr {}",
                process.stderr.display()
            )
        })
        .unwrap()
}

fn completion(process: &mut Process) -> Value {
    for _ in 0..128 {
        let event = event(process);
        if event["event"] == "resume_completion" {
            return event;
        }
        assert_eq!(event["event"], "session_retired");
    }
    panic!("bounded test unexpectedly emitted more than 128 retirements")
}

fn stop_shared(process: &mut Process) -> Vec<Value> {
    kill(
        Pid::from_raw(i32::try_from(process.child.id()).unwrap()),
        Signal::SIGTERM,
    )
    .unwrap();
    let mut retained = Vec::new();
    for _ in 0..128 {
        let event = event(process);
        if event["event"] == "stopped" {
            assert_eq!(event["drained"], true);
            assert!(process.exit().success());
            return retained;
        }
        assert!(event["event"] == "resume_completion" || event["event"] == "session_retired");
        retained.push(event);
    }
    panic!("service never reported complete shutdown")
}

fn send_shared(
    fixture: &Fixture,
    address: SocketAddr,
    identity: &str,
    workers: usize,
    bytes: &[u8],
) -> Process {
    let mut config = fixture.sender_config(address, identity, workers);
    config["max_transfer_bytes"] = json!(bytes.len());
    config["epoch_bytes"] = json!(65536);
    fixture.spawn_resumable("send-resumable", config, Some(bytes), 1, 25, 1)
}

fn second_client(fixture: &Fixture, config: &mut Value) -> (PathBuf, String) {
    let directory = fixture.root.join("second-inbox");
    std::fs::create_dir(&directory).unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let bytes = std::fs::read(fixture.root.join("unlisted.pem")).unwrap();
    let certificate = CertificateDer::pem_reader_iter(&mut BufReader::new(bytes.as_slice()))
        .next()
        .unwrap()
        .unwrap();
    let id = hex::encode(Sha256::digest(certificate.as_ref()));
    config["clients"].as_array_mut().unwrap().push(json!({
        "certificate_sha256": id, "directory": directory,
        "max_retained_bytes": 65536, "max_retained_entries": 32,
    }));
    (directory, id)
}

fn entries(directory: &Path) -> Vec<PathBuf> {
    let mut paths: Vec<_> = std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    paths.sort();
    paths
}

fn verify_shared(
    directory: &Path,
    client: &str,
    sent: &Value,
    received: &Value,
    bytes: &[u8],
) -> PathBuf {
    assert_eq!(received["outcome_kind"], "transfer");
    assert_eq!(received["transfer"]["status"], "complete");
    assert_eq!(received["session"]["client_certificate_sha256"], client);
    assert_eq!(
        received["session"]["stream_nonce"],
        sent["transfer"]["receipt"]["stream_nonce"]
    );
    assert_eq!(received["transfer"]["receipt"], sent["transfer"]["receipt"]);
    assert_eq!(received["publication"]["state"], "durable");
    assert_eq!(received["publication"]["error"], false);
    assert_eq!(received["proof_write_confirmed"], true);
    assert_eq!(received["sender_receipt_observed"], false);
    let name = received["publication"]["filename"].as_str().unwrap();
    assert_eq!(
        name.rsplit_once('.').map(|(_, extension)| extension),
        Some("bin")
    );
    assert!(!name.contains('/'));
    let path = directory.join(name);
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    assert_eq!(
        received["transfer"]["receipt"]["sha256"],
        hex::encode(Sha256::digest(bytes))
    );
    let published = std::fs::metadata(&path).unwrap();
    assert_eq!(
        entries(directory)
            .iter()
            .filter(|entry| {
                let metadata = std::fs::metadata(entry).unwrap();
                (metadata.dev(), metadata.ino()) == (published.dev(), published.ino())
            })
            .count(),
        2,
        "reconnects must not create another publication inode"
    );
    path
}

#[test]
fn shared_executable_routes_concurrent_clients_to_separate_private_inboxes() {
    for workers in [1, 2] {
        let fixture = Fixture::new();
        let mut config = fixture.receiver_config(workers, 4096, 65536);
        let (other_inbox, other_id) = second_client(&fixture, &mut config);
        let (mut receiver, address) = start_shared(&fixture, config, limits());
        for directory in [&fixture.inbox, &other_inbox] {
            assert_eq!(
                entries(directory),
                vec![directory.join(".atpd-live.lock")],
                "readiness creates no transfer sink"
            );
        }
        let inputs: [&[u8]; 4] = [
            b"first client first object",
            b"other client's private object",
            b"",
            b"fourth object",
        ];
        let mut senders: Vec<_> = inputs
            .iter()
            .enumerate()
            .map(|(index, bytes)| {
                send_shared(
                    &fixture,
                    address,
                    if index % 2 == 0 {
                        "allowed"
                    } else {
                        "unlisted"
                    },
                    workers,
                    bytes,
                )
            })
            .collect();
        let sent: Vec<_> = senders
            .iter_mut()
            .map(|sender| {
                let (result, attempts) = until(sender, "send_result");
                assert_eq!(attempts.len(), 1);
                assert!(sender.exit().success());
                result
            })
            .collect();
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..4 {
            let received = completion(&mut receiver);
            assert!(
                seen.insert(
                    received["session"]["stream_nonce"]
                        .as_str()
                        .unwrap()
                        .to_owned()
                )
            );
            let index = sent
                .iter()
                .position(|sent| {
                    sent["transfer"]["receipt"]["stream_nonce"]
                        == received["session"]["stream_nonce"]
                })
                .unwrap();
            let (directory, id) = if index % 2 == 0 {
                (&fixture.inbox, &fixture.allowed)
            } else {
                (&other_inbox, &other_id)
            };
            verify_shared(directory, id, &sent[index], &received, inputs[index]);
        }
        assert_eq!(entries(&fixture.inbox).len(), 5);
        assert_eq!(entries(&other_inbox).len(), 5);
        stop_shared(&mut receiver);
    }
}

#[test]
fn shared_executable_recovers_opaque_ack_and_proof_loss_with_one_disk_reservation() {
    for workers in [1, 2] {
        for fault in [Fault::Prefix(4096), Fault::Publication] {
            let fixture = Fixture::new();
            let bytes: Vec<_> = (0_usize..131083)
                .map(|n| ((n * 37) ^ (n / 251)).to_le_bytes()[0])
                .collect();
            // Just one transfer's conservative storage charge can be admitted.
            let mut config =
                fixture.receiver_config(workers, bytes.len() as u64, bytes.len() as u64 * 2);
            config["epoch_bytes"] = json!(65536);
            let policy = Limits {
                sessions: 2,
                per_client: 1,
                keys: 4,
                ..limits()
            };
            let (mut receiver, address) = start_shared(&fixture, config, policy);
            let mut relay = Relay::new(address, fixture.inbox.clone(), fault);
            let mut sender = fixture.resume_sender(relay.address, workers, &bytes, 50);
            let (sent, attempts) = until(&mut sender, "send_result");
            assert!(sender.exit().success());
            assert!(attempts.len() >= 2);
            assert!(relay.faulted.load(Ordering::SeqCst));
            assert!(relay.connections.load(Ordering::SeqCst) >= 2);
            let first = completion(&mut receiver);
            let mut received = completion(&mut receiver);
            for _ in 0..8 {
                if received["transfer"]["status"] == "complete" {
                    break;
                }
                received = completion(&mut receiver);
            }
            assert_eq!(first["session"], received["session"]);
            assert_eq!(
                first["publication"]["filename"],
                received["publication"]["filename"]
            );
            assert!(received["transfer"]["attempts"].as_u64().unwrap() >= 2);
            if matches!(fault, Fault::Publication) {
                assert_eq!(received["transfer"]["receipt_reused"], true);
            }
            verify_shared(&fixture.inbox, &fixture.allowed, &sent, &received, &bytes);
            assert_eq!(entries(&fixture.inbox).len(), 3);
            relay.finish();
            stop_shared(&mut receiver);
        }
    }
}

#[test]
fn shared_per_client_residency_refusal_leaves_capacity_for_another_client() {
    let fixture = Fixture::new();
    let mut config = fixture.receiver_config(2, 4096, 65536);
    let (other_inbox, other_id) = second_client(&fixture, &mut config);
    let policy = Limits {
        sessions: 2,
        per_client: 1,
        keys: 4,
        ..limits()
    };
    let (mut receiver, address) = start_shared(&fixture, config, policy);
    let mut first = send_shared(&fixture, address, "allowed", 1, b"retained first client");
    let (sent, _) = until(&mut first, "send_result");
    assert!(first.exit().success());
    verify_shared(
        &fixture.inbox,
        &fixture.allowed,
        &sent,
        &completion(&mut receiver),
        b"retained first client",
    );
    let before = entries(&fixture.inbox);
    let mut excess = send_shared(&fixture, address, "allowed", 1, b"must not allocate a sink");
    let _ = until(&mut excess, "send_result");
    assert!(!excess.exit().success());
    let rejected = completion(&mut receiver);
    assert_eq!(rejected["transfer"]["status"], "session_capacity_refused");
    assert!(rejected["publication"].is_null());
    assert_eq!(entries(&fixture.inbox), before);
    let mut other = send_shared(
        &fixture,
        address,
        "unlisted",
        2,
        b"another client's capacity",
    );
    let (sent, _) = until(&mut other, "send_result");
    assert!(other.exit().success());
    verify_shared(
        &other_inbox,
        &other_id,
        &sent,
        &completion(&mut receiver),
        b"another client's capacity",
    );
    stop_shared(&mut receiver);
}

// A synchronous, independently driven mTLS peer makes nonce reuse and the exact
// interruption boundary observable without exposing the SDK's registry internals.
struct RawPeer {
    stream: rustls::StreamOwned<rustls::ClientConnection, TcpStream>,
    buffer: BytesMut,
    codec: AtpFrameCodec,
}

impl RawPeer {
    fn connect(fixture: &Fixture, address: SocketAddr) -> Self {
        let ca = std::fs::read(fixture.root.join("ca.pem")).unwrap();
        let leaf = std::fs::read(fixture.root.join("allowed.pem")).unwrap();
        let key = std::fs::read(fixture.root.join("allowed.key")).unwrap();
        let cert = |pem: &[u8]| {
            CertificateDer::pem_reader_iter(&mut BufReader::new(pem))
                .next()
                .unwrap()
                .unwrap()
        };
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert(&ca)).unwrap();
        let key = PrivateKeyDer::pem_reader_iter(&mut BufReader::new(key.as_slice()))
            .next()
            .unwrap()
            .unwrap();
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_client_auth_cert(vec![cert(&leaf)], key)
        .unwrap();
        config.alpn_protocols = vec![b"atp-live-resume/1".to_vec()];
        config.resumption = rustls::client::Resumption::disabled();
        let socket = TcpStream::connect_timeout(&address, Duration::from_secs(3)).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let connection = rustls::ClientConnection::new(
            Arc::new(config),
            ServerName::try_from("localhost").unwrap(),
        )
        .unwrap();
        Self {
            stream: rustls::StreamOwned::new(connection, socket),
            buffer: BytesMut::new(),
            codec: AtpFrameCodec::with_max_frame_size(65536 + 256),
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
            let count = self.stream.read(&mut bytes)?;
            if count == 0 {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
            }
            self.buffer.extend_from_slice(&bytes[..count]);
            assert!(self.buffer.len() < 65536 + 256);
        }
    }

    fn offer(&mut self, nonce: u8) {
        let mut offered = b"ATPRSM01ATPLIVE1".to_vec();
        offered.extend_from_slice(&[nonce; 32]);
        offered.extend_from_slice(&32u32.to_be_bytes());
        offered.extend_from_slice(&4096u64.to_be_bytes());
        self.send(FrameType::Handshake, offered);
    }

    fn state(&mut self) -> (Vec<u8>, bool) {
        let state = self.receive().unwrap();
        assert_eq!(state.frame_type(), FrameType::HandshakeAck);
        assert_eq!(state.payload().len(), 141);
        (state.payload()[60..108].to_vec(), state.payload()[140] == 1)
    }

    fn epoch(&mut self, prefix: &[u8], bytes: &[u8]) -> Vec<u8> {
        let mut payload = prefix.to_vec();
        payload.extend_from_slice(&Sha256::digest(bytes));
        payload.extend_from_slice(bytes);
        self.send(FrameType::ObjectData, payload);
        let ack = self.receive().unwrap();
        assert_eq!(ack.frame_type(), FrameType::Control);
        assert_eq!(ack.payload().len(), 48);
        ack.payload().to_vec()
    }

    fn finish(&mut self, prefix: &[u8], bytes: &[u8]) {
        let mut payload = prefix.to_vec();
        payload.extend_from_slice(&Sha256::digest(bytes));
        self.send(FrameType::ObjectComplete, payload.clone());
        let proof = self.receive().unwrap();
        assert_eq!(proof.frame_type(), FrameType::Proof);
        assert_eq!(proof.payload(), payload);
    }
}

#[test]
fn shared_idle_retirement_keeps_tombstones_and_does_not_recycle_lifetime_keys() {
    let fixture = Fixture::new();
    let mut config = fixture.receiver_config(1, 4096, 65536);
    config["max_connections"] = json!(1);
    let policy = Limits {
        sessions: 1,
        per_client: 1,
        keys: 2,
        idle: 1,
        proof: 1,
        ..limits()
    };
    let (mut receiver, address) = start_shared(&fixture, config, policy);
    let mut peer = RawPeer::connect(&fixture, address);
    peer.offer(11);
    let (prefix, completed) = peer.state();
    assert!(!completed);
    let _ = peer.epoch(&prefix, b"part");
    drop(peer);
    let attempt = completion(&mut receiver);
    assert_eq!(attempt["transfer"]["flushed_prefix_bytes"], 4);
    assert!(attempt["transfer"]["completed_receipt"].is_null());
    let retired = receiver.event("session_retired");
    assert_eq!(retired["reason"], "idle_retention_expired");
    assert_eq!(retired["resident_sessions"], 0);
    assert_eq!(retired["retained_keys"], 1);
    assert_eq!(retired["tombstone_retained"], true);
    let before = entries(&fixture.inbox);
    assert_eq!(before.len(), 2);
    assert!(
        before
            .iter()
            .any(|path| std::fs::read(path).unwrap() == b"part")
    );
    let mut late = RawPeer::connect(&fixture, address);
    late.offer(11);
    assert!(late.receive().is_err());
    drop(late);
    assert_eq!(
        completion(&mut receiver)["transfer"]["status"],
        "session_retired"
    );
    assert_eq!(entries(&fixture.inbox), before);
    // A new key can use the released resident slot, but never an old key.
    let mut next = RawPeer::connect(&fixture, address);
    next.offer(12);
    let (prefix, completed) = next.state();
    assert!(!completed);
    next.finish(&prefix, b"");
    drop(next);
    assert_eq!(completion(&mut receiver)["transfer"]["status"], "complete");
    let retired = receiver.event("session_retired");
    assert_eq!(retired["reason"], "proof_recovery_expired");
    assert_eq!(retired["resident_sessions"], 0);
    assert_eq!(retired["retained_keys"], 2);
    let before = entries(&fixture.inbox);
    let mut excess = RawPeer::connect(&fixture, address);
    excess.offer(13);
    assert!(excess.receive().is_err());
    drop(excess);
    assert_eq!(
        completion(&mut receiver)["transfer"]["status"],
        "session_capacity_refused"
    );
    assert_eq!(entries(&fixture.inbox), before);
    stop_shared(&mut receiver);
}

#[test]
fn shared_completed_session_replays_proof_then_retires_without_republishing() {
    let fixture = Fixture::new();
    let policy = Limits {
        sessions: 2,
        per_client: 1,
        proof: 2,
        ..limits()
    };
    let (mut receiver, address) =
        start_shared(&fixture, fixture.receiver_config(2, 4096, 65536), policy);
    let mut peer = RawPeer::connect(&fixture, address);
    peer.offer(21);
    let (prefix, completed) = peer.state();
    assert!(!completed);
    peer.finish(&prefix, b"");
    drop(peer);
    let first = completion(&mut receiver);
    assert_eq!(first["transfer"]["status"], "complete");
    let before = entries(&fixture.inbox);
    let mut replay = RawPeer::connect(&fixture, address);
    replay.offer(21);
    let (prefix, completed) = replay.state();
    assert!(completed);
    replay.finish(&prefix, b"");
    drop(replay);
    let second = completion(&mut receiver);
    assert_eq!(second["transfer"]["receipt_reused"], true);
    assert_eq!(second["transfer"]["receipt"], first["transfer"]["receipt"]);
    assert_eq!(second["publication"], first["publication"]);
    let retired = receiver.event("session_retired");
    assert_eq!(retired["reason"], "proof_recovery_expired");
    assert_eq!(
        retired["snapshot"]["completed_receipt"],
        first["transfer"]["receipt"]
    );
    let mut late = RawPeer::connect(&fixture, address);
    late.offer(21);
    assert!(late.receive().is_err());
    drop(late);
    assert_eq!(
        completion(&mut receiver)["transfer"]["status"],
        "session_retired"
    );
    assert_eq!(entries(&fixture.inbox), before);
    stop_shared(&mut receiver);
}

#[test]
fn shared_signal_shutdown_drains_a_witnessed_live_prefix_before_stopped() {
    for workers in [1, 2] {
        let fixture = Fixture::new();
        let mut config = fixture.receiver_config(workers, 4096, 65536);
        config["operation_timeout_secs"] = json!(10);
        let (mut receiver, address) = start_shared(&fixture, config.clone(), limits());
        let mut peer = RawPeer::connect(&fixture, address);
        peer.offer(31);
        let (prefix, _) = peer.state();
        let acknowledged = peer.epoch(&prefix, b"part");
        assert_eq!(
            u64::from_be_bytes(acknowledged[8..16].try_into().unwrap()),
            4
        );
        let events = stop_shared(&mut receiver); // Keep peer connected: server must cancel its parked read.
        let completions: Vec<_> = events
            .iter()
            .filter(|event| event["event"] == "resume_completion")
            .collect();
        assert_eq!(completions.len(), 1);
        assert_eq!(completions[0]["transfer"]["status"], "cancelled");
        assert_eq!(completions[0]["transfer"]["flushed_prefix_bytes"], 4);
        assert_eq!(completions[0]["transfer"]["sink_written_bytes"], 4);
        assert_eq!(completions[0]["publication"]["state"], "staged");
        assert_eq!(completions[0]["proof_write_confirmed"], false);
        assert_eq!(entries(&fixture.inbox).len(), 2);
        drop(peer);
        let (mut restarted, _) = start_shared(&fixture, config, limits());
        stop_shared(&mut restarted); // Exclusive ownership was released at process exit.
    }
}

#[test]
fn shared_tls_refusal_does_not_admit_a_key_or_construct_a_sink() {
    let fixture = Fixture::new();
    let (mut receiver, address) =
        start_shared(&fixture, fixture.receiver_config(1, 4096, 65536), limits());
    let mut denied = send_shared(&fixture, address, "unlisted", 1, b"not authorized");
    let (_, attempts) = until(&mut denied, "send_result");
    assert_eq!(attempts.len(), 1);
    assert!(!denied.exit().success());
    let rejected = completion(&mut receiver);
    assert_eq!(rejected["transfer"]["status"], "tls_failed");
    assert!(rejected["session"].is_null());
    assert!(rejected["publication"].is_null());
    assert_eq!(
        entries(&fixture.inbox),
        vec![fixture.inbox.join(".atpd-live.lock")]
    );
    let mut allowed = send_shared(&fixture, address, "allowed", 1, b"still serving");
    let (sent, _) = until(&mut allowed, "send_result");
    assert!(allowed.exit().success());
    verify_shared(
        &fixture.inbox,
        &fixture.allowed,
        &sent,
        &completion(&mut receiver),
        b"still serving",
    );
    stop_shared(&mut receiver);
}

#[test]
fn shared_invalid_budgets_fail_before_creating_inbox_locks_or_sinks() {
    let fixture = Fixture::new();
    for bad in [
        Limits {
            sessions: 0,
            ..limits()
        },
        Limits {
            sessions: 1,
            ..limits()
        }, // Configured two connections cannot fit.
        Limits {
            per_client: 0,
            ..limits()
        },
        Limits {
            keys: 3,
            ..limits()
        },
        Limits {
            idle: 0,
            ..limits()
        },
    ] {
        let mut process = spawn_shared(&fixture, fixture.receiver_config(1, 4096, 65536), bad);
        assert!(!process.exit().success());
        assert!(
            process
                .events
                .try_iter()
                .all(|event| event.unwrap()["event"] != "ready")
        );
        assert!(entries(&fixture.inbox).is_empty());
    }
}
