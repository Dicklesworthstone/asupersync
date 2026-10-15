//! Operator revocation through real processes, signals, authenticated epochs,
//! and private inbox files. Reuse the independent wire peer, not SDK internals.
use super::*;

fn policy_bytes(generation: u64, revoked: &[&str]) -> Vec<u8> {
    serde_json::to_vec(&json!({"schema_version": 1, "generation": generation,
        "revoked_certificates": revoked}))
    .unwrap()
}

fn provision_policy(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
    std::fs::File::open(path.parent().unwrap())
        .unwrap()
        .sync_all()
        .unwrap();
}

fn replace_policy(fixture: &Fixture, path: &Path, bytes: &[u8]) {
    // Preserve the previous snapshot; do not delete or overwrite it. Nothing
    // rereads the path until the explicit signal after provisioning completes.
    std::fs::rename(path, fixture.unique("retained-policy")).unwrap();
    provision_policy(path, bytes);
}

fn reload(process: &Process) {
    kill(
        Pid::from_raw(i32::try_from(process.child.id()).unwrap()),
        Signal::SIGHUP,
    )
    .unwrap();
}

fn spawn_revoking(fixture: &Fixture, config: Value, path: &Path, ledger: Option<&Path>) -> Process {
    let config = fixture.json_file(config);
    let mut command = Command::new(BINARY);
    command
        .arg(if ledger.is_some() {
            "serve-durable"
        } else {
            "serve-resumable"
        })
        .arg("--config")
        .arg(config)
        .arg("--revocations")
        .arg(path)
        .args([
            "--max-sessions",
            "4",
            "--max-sessions-per-client",
            "2",
            "--max-session-keys",
            "16",
            "--attempts-per-session",
            "8",
            "--idle-retention-secs",
            "60",
            "--proof-recovery-secs",
            "60",
        ]);
    if let Some(ledger) = ledger {
        command
            .arg("--session-ledger")
            .arg(ledger)
            .arg("--recover-committed");
    }
    launch(fixture, command)
}

fn start_revoking(
    fixture: &Fixture,
    config: Value,
    path: &Path,
    ledger: Option<&Path>,
    generation: u64,
    denied: usize,
) -> (Process, SocketAddr) {
    let mut process = spawn_revoking(fixture, config, path, ledger);
    let ready = process.event("ready");
    assert_eq!(ready["revocation_generation"], generation);
    assert_eq!(ready["revoked_clients"], denied);
    assert_eq!(ready["durable_session_ledger"], ledger.is_some());
    let address = ready["address"].as_str().unwrap().parse().unwrap();
    (process, address)
}

fn second_inbox(fixture: &Fixture, config: &mut Value) -> PathBuf {
    let directory = fixture.root.join("second-inbox");
    std::fs::create_dir(&directory).unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let certificate = CertificateDer::pem_reader_iter(&mut BufReader::new(
        std::fs::File::open(fixture.root.join("unlisted.pem")).unwrap(),
    ))
    .next()
    .unwrap()
    .unwrap();
    config["clients"].as_array_mut().unwrap().push(json!({
        "certificate_sha256": hex::encode(Sha256::digest(certificate.as_ref())),
        "directory": directory, "max_retained_bytes": 65536, "max_retained_entries": 32,
    }));
    directory
}

fn paths(directory: &Path) -> Vec<PathBuf> {
    let mut paths: Vec<_> = std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    paths.sort();
    paths
}

fn staged_bytes(directory: &Path) -> Vec<Vec<u8>> {
    paths(directory)
        .into_iter()
        .filter(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(".atp-live-")
        })
        .map(|path| std::fs::read(path).unwrap())
        .collect()
}

fn assert_tls_refused(fixture: &Fixture, process: &mut Process, address: SocketAddr, nonce: u8) {
    let mut denied = Peer::connect(fixture, address, "allowed");
    assert!(denied.hello(nonce).is_err());
    let refused = completion(process);
    assert_eq!(refused["transfer"]["status"], "tls_failed");
    assert!(refused["session"].is_null());
    assert!(refused["publication"].is_null());
}

#[test]
fn sighup_revokes_one_acknowledged_client_while_another_finishes_on_the_same_listener() {
    for workers in [1, 2] {
        let fixture = Fixture::new();
        let policy = fixture.unique("revocations");
        provision_policy(&policy, &policy_bytes(1, &[]));
        let mut config = fixture.receiver_config(workers, 64, 65536);
        config["operation_timeout_secs"] = json!(10);
        let other_inbox = second_inbox(&fixture, &mut config);
        let (mut process, address) = start_revoking(&fixture, config, &policy, None, 1, 0);
        let mut target = Peer::connect(&fixture, address, "allowed");
        let target_state = target.hello(71).unwrap();
        target.epoch(&target_state, b"abc");
        let mut other = Peer::connect(&fixture, address, "unlisted");
        let other_state = other.hello(72).unwrap();
        let other_prefix = other.epoch(&other_state, b"xyz");
        // Actual authenticated epoch ACKs and file bytes, not scheduling sleeps.
        assert_eq!(staged_bytes(&fixture.inbox), vec![b"abc".to_vec()]);
        assert_eq!(staged_bytes(&other_inbox), vec![b"xyz".to_vec()]);
        let retained = fixture.entries();
        replace_policy(&fixture, &policy, &policy_bytes(2, &[&fixture.allowed]));
        reload(&process);
        let applied = process.event("revocation_policy_applied");
        assert_eq!(applied["generation"], 2);
        assert_eq!(applied["newly_revoked"], 1);
        assert_eq!(applied["signalled_connections"], 1);
        assert_eq!(applied["retained_sessions"], 1);
        assert_eq!(applied["drained"], false);
        let cancelled = completion(&mut process);
        assert_eq!(cancelled["session"]["stream_nonce"], hex::encode([71; 32]));
        assert_eq!(cancelled["transfer"]["status"], "cancelled");
        assert_eq!(cancelled["transfer"]["flushed_prefix_bytes"], 3);
        assert_eq!(cancelled["transfer"]["sink_written_bytes"], 3);
        assert!(cancelled["transfer"]["completed_receipt"].is_null());
        assert_eq!(cancelled["publication"]["state"], "staged");
        assert!(target.receive().is_err());
        let retired = process.event("session_retired");
        assert_eq!(retired["reason"], "client_revoked");
        assert_eq!(retired["tombstone_retained"], true);
        assert_eq!(fixture.entries(), retained);
        assert!(
            !paths(&fixture.inbox)
                .iter()
                .any(|path| path.extension().is_some_and(|ext| ext == "bin"))
        );

        other.finish(&other_prefix, b"xyz");
        let healthy = completion(&mut process);
        assert_eq!(healthy["session"]["stream_nonce"], hex::encode([72; 32]));
        assert_eq!(healthy["transfer"]["status"], "complete");
        assert_eq!(healthy["publication"]["state"], "durable");
        let published = other_inbox.join(healthy["publication"]["filename"].as_str().unwrap());
        assert_eq!(std::fs::read(&published).unwrap(), b"xyz");
        assert_eq!(
            healthy["transfer"]["receipt"]["sha256"],
            hex::encode(Sha256::digest(b"xyz"))
        );
        let inode = std::fs::metadata(&published).unwrap();
        assert_eq!(
            paths(&other_inbox)
                .iter()
                .filter(|path| {
                    let file = std::fs::metadata(path).unwrap();
                    (file.dev(), file.ino()) == (inode.dev(), inode.ino())
                })
                .count(),
            2
        );
        assert_tls_refused(&fixture, &mut process, address, 73);
        assert_eq!(fixture.entries(), retained);
        reload(&process); // Identical snapshots are idempotent, not new cancellations.
        let same = process.event("revocation_policy_applied");
        assert_eq!(same["generation"], 2);
        assert_eq!(same["newly_revoked"], 0);
        assert_eq!(same["signalled_connections"], 0);
        drop(target);
        drop(other);
        stop(&mut process);
    }
}

#[test]
fn failed_requested_policy_cancels_and_reports_owned_work_before_unsuccessful_exit() {
    for variant in 0..5 {
        let fixture = Fixture::new();
        let policy = fixture.unique("revocations");
        let unrelated = "44".repeat(32);
        provision_policy(&policy, &policy_bytes(2, &[&unrelated]));
        let mut config = fixture.receiver_config(2, 64, 65536);
        config["operation_timeout_secs"] = json!(10);
        let (mut process, address) = start_revoking(&fixture, config, &policy, None, 2, 1);
        let mut peer = Peer::connect(&fixture, address, "allowed");
        let state = peer.hello(81).unwrap();
        peer.epoch(&state, b"abc");
        let retained = fixture.entries();
        assert_eq!(staged_bytes(&fixture.inbox), vec![b"abc".to_vec()]);
        match variant {
            0 => replace_policy(&fixture, &policy, &policy_bytes(1, &[&unrelated])),
            1 => replace_policy(
                &fixture,
                &policy,
                &policy_bytes(2, &[&unrelated, &fixture.allowed]),
            ),
            2 => replace_policy(&fixture, &policy, &policy_bytes(3, &[])),
            3 => replace_policy(&fixture, &policy, b"{\"schema_version\":1,"),
            4 => std::fs::rename(&policy, fixture.unique("retained-missing-policy")).unwrap(),
            _ => unreachable!(),
        }
        reload(&process);
        let rejected = process.event("revocation_policy_rejected");
        assert_eq!(rejected["generation"], 2);
        assert_eq!(rejected["admission_closed"], true);
        assert_eq!(rejected["drained"], false);
        // A policy failure must not suppress the canonical connection outcome.
        let cancelled = completion(&mut process);
        assert_eq!(cancelled["transfer"]["status"], "cancelled");
        assert_eq!(cancelled["transfer"]["sink_written_bytes"], 3);
        assert!(cancelled["transfer"]["completed_receipt"].is_null());
        assert_eq!(cancelled["publication"]["state"], "staged");
        assert!(peer.receive().is_err());
        drop(peer);
        assert!(!process.exit().success());
        assert!(
            std::net::TcpStream::connect_timeout(&address, Duration::from_millis(250)).is_err()
        );
        assert_eq!(fixture.entries(), retained);
        assert_eq!(staged_bytes(&fixture.inbox), vec![b"abc".to_vec()]);
    }
}

#[test]
fn persisted_revocation_blocks_historical_proof_after_receiver_restart_without_changing_history() {
    let fixture = Fixture::new();
    let ledger = initialize(&fixture, 2);
    let policy = fixture.unique("revocations");
    provision_policy(&policy, &policy_bytes(1, &[]));
    let config = fixture.receiver_config(2, 64, 65536);
    let (mut process, address) =
        start_revoking(&fixture, config.clone(), &policy, Some(&ledger), 1, 0);
    let mut peer = Peer::connect(&fixture, address, "allowed");
    let state = peer.hello(91).unwrap();
    let prefix = peer.epoch(&state, b"abc");
    peer.finish(&prefix, b"abc");
    let complete = completion(&mut process);
    assert_eq!(complete["transfer"]["status"], "complete");
    let receipt = complete["transfer"]["receipt"].clone();
    let published = fixture
        .inbox
        .join(complete["publication"]["filename"].as_str().unwrap());
    assert_eq!(std::fs::read(&published).unwrap(), b"abc");
    let inode = std::fs::metadata(&published).unwrap();
    assert_eq!(records(&ledger).len(), 2);
    let history = std::fs::read(&ledger).unwrap();
    let retained = fixture.entries();
    replace_policy(&fixture, &policy, &policy_bytes(2, &[&fixture.allowed]));
    reload(&process);
    let applied = process.event("revocation_policy_applied");
    assert_eq!(applied["signalled_connections"], 0);
    let retired = process.event("session_retired");
    assert_eq!(retired["reason"], "client_revoked");
    assert_eq!(retired["snapshot"]["completed_receipt"], receipt);
    assert_eq!(retired["publication"]["state"], "durable");
    assert_tls_refused(&fixture, &mut process, address, 91);
    drop(peer);
    stop(&mut process);

    let (mut restarted, address) = start_revoking(&fixture, config, &policy, Some(&ledger), 2, 1);
    for nonce in [91, 92] {
        assert_tls_refused(&fixture, &mut restarted, address, nonce);
    }
    assert_eq!(std::fs::read(&ledger).unwrap(), history);
    assert_eq!(fixture.entries(), retained);
    let now = std::fs::metadata(&published).unwrap();
    assert_eq!((now.dev(), now.ino()), (inode.dev(), inode.ino()));
    assert_eq!(std::fs::read(&published).unwrap(), b"abc");
    stop(&mut restarted);
}

#[test]
fn invalid_policy_never_reaches_readiness_or_creates_an_inbox_sink() {
    for variant in 0..6 {
        let fixture = Fixture::new();
        let mut policy = fixture.unique("revocations");
        match variant {
            0 => {} // Missing policies must not silently become empty policies.
            1 => {
                provision_policy(&policy, &policy_bytes(1, &[]));
                std::fs::set_permissions(&policy, std::fs::Permissions::from_mode(0o644)).unwrap();
            }
            2 => {
                let retained = fixture.unique("private-policy");
                provision_policy(&retained, &policy_bytes(1, &[]));
                std::os::unix::fs::symlink(retained, &policy).unwrap();
            }
            3 => provision_policy(&policy, b"{\"schema_version\":1,"),
            4 => provision_policy(&policy, &vec![b' '; 128 * 1024 + 1]),
            5 => {
                policy = fixture.inbox.join("policy.json");
                provision_policy(&policy, &policy_bytes(1, &[]));
            }
            _ => unreachable!(),
        }
        let retained = fixture.entries();
        let mut process = spawn_revoking(
            &fixture,
            fixture.receiver_config(1, 64, 65536),
            &policy,
            None,
        );
        assert!(!process.exit().success());
        assert!(
            process
                .events
                .try_iter()
                .all(|event| event.unwrap()["event"] != "ready")
        );
        assert_eq!(fixture.entries(), retained);
        if variant == 0 {
            assert!(!policy.exists());
        }
    }
}
