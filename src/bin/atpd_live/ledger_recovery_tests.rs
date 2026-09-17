//! Real files, retained fixtures, and exact read-only recovery boundaries.
use super::*;
use super::super::{is_replay_refusal, LiveStreamPrefix};
use asupersync::net::atp::sdk::NativeClientCertificateId;
use std::os::unix::fs::OpenOptionsExt;
use std::io::Write;

fn key(nonce: u8) -> ResumeSessionKey {
    ResumeSessionKey { client: NativeClientCertificateId::from_sha256([1; 32]), nonce: [nonce; 32] }
}
struct Fixture { ledger: Arc<Ledger>, inbox: PathBuf, path: PathBuf, output: PathBuf, receipt: LiveStreamReceipt }
impl Fixture {
    fn new(committed: bool) -> Self {
        let root = tempfile::tempdir().unwrap().keep();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let inbox = root.join("inbox"); std::fs::create_dir(&inbox).unwrap();
        std::fs::set_permissions(&inbox, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.join("history"); Ledger::initialize(&path, 1).unwrap();
        let ledger = Ledger::open(&path).unwrap(); let name = format!("{}.bin", "a".repeat(32));
        ledger.claim_sync(key(2), name.clone(), 64).unwrap();
        let output = inbox.join(name);
        let mut file = std::fs::OpenOptions::new().create_new(true).write(true).mode(0o600).open(&output).unwrap();
        file.write_all(b"receipt").unwrap(); file.sync_all().unwrap();
        File::open(&inbox).unwrap().sync_all().unwrap();
        let receipt = LiveStreamReceipt {
            prefix: LiveStreamPrefix { stream_nonce: [2; 32], bytes: 7, epochs: 1, chain: [3; 32] },
            source_sha256: Sha256::digest(b"receipt").into(),
        };
        if committed { ledger.commit_sync(key(2), receipt.clone()).unwrap(); }
        Self { ledger, inbox, path, output, receipt }
    }
    fn recover(&self) -> io::Result<Option<LiveStreamReceipt>> {
        self.ledger.recover_sync(key(2), &self.inbox, 64, &AtomicBool::new(false))
    }
}

#[test]
fn restart_recovery_rehashes_without_appending_claims_or_receipts() {
    let Fixture { ledger, inbox, path, output, receipt } = Fixture::new(true);
    let original = std::fs::read(&path).unwrap(); let identity = file_identity(&std::fs::metadata(&output).unwrap());
    drop(ledger); let reopened = Ledger::open(&path).unwrap();
    for _ in 0..3 {
        assert_eq!(reopened.recover_sync(key(2), &inbox, 64, &AtomicBool::new(false)).unwrap(), Some(receipt.clone()));
    }
    assert_eq!(std::fs::read(&path).unwrap(), original);
    assert_eq!(file_identity(&std::fs::metadata(output).unwrap()), identity);
    assert!(reopened.recover_sync(key(3), &inbox, 64, &AtomicBool::new(false)).unwrap().is_none());
    assert_eq!(reopened.claim_sync(key(3), format!("{}.bin", "b".repeat(32)), 64).unwrap_err().kind(), io::ErrorKind::StorageFull);
}

#[test]
fn unresolved_claim_with_present_file_never_becomes_a_commit_receipt() {
    let fixture = Fixture::new(false); let before = std::fs::read(&fixture.path).unwrap();
    assert!(is_replay_refusal(&fixture.recover().unwrap_err()));
    assert_eq!(std::fs::read(&fixture.path).unwrap(), before);
    assert_eq!(std::fs::read(&fixture.output).unwrap(), b"receipt");
}

#[test]
fn changed_truncated_missing_and_symlinked_publications_are_refused() {
    for kind in ["changed", "short", "missing", "symlink", "public"] {
        let fixture = Fixture::new(true);
        let before = std::fs::read(&fixture.path).unwrap();
        match kind {
            "changed" => std::fs::write(&fixture.output, b"corrupt").unwrap(),
            "short" => std::fs::write(&fixture.output, b"short").unwrap(),
            "public" => std::fs::set_permissions(&fixture.output, std::fs::Permissions::from_mode(0o644)).unwrap(),
            _ => {
                let saved = fixture.inbox.join("retained-original");
                std::fs::rename(&fixture.output, &saved).unwrap();
                if kind == "symlink" { std::os::unix::fs::symlink(&saved, &fixture.output).unwrap(); }
            }
        }
        assert!(fixture.recover().is_err(), "accepted {kind} file");
        assert_eq!(std::fs::read(&fixture.path).unwrap(), before);
    }
}

#[test]
fn current_size_limit_and_poisoned_history_do_not_release_old_receipts() {
    let fixture = Fixture::new(true);
    assert!(fixture.ledger.recover_sync(key(2), &fixture.inbox, 6, &AtomicBool::new(false)).is_err());
    fixture.ledger.state.lock().poisoned = true;
    assert!(fixture.recover().is_err());
    assert!(fixture.ledger.recover_sync(key(3), &fixture.inbox, 64, &AtomicBool::new(false)).is_err());
}

#[test]
fn queued_or_abandoned_reads_keep_their_independent_admission_slot() {
    let fixture = Fixture::new(true);
    let mut permits: Vec<_> = (0..MAX_RECOVERY_READS).map(|_| ReadPermit::reserve(&fixture.ledger).unwrap()).collect();
    assert_eq!(ReadPermit::reserve(&fixture.ledger).err().unwrap().kind(), io::ErrorKind::WouldBlock);
    let stopped = Arc::new(AtomicBool::new(false)); let stop = StopRead(Arc::clone(&stopped));
    drop(stop); // Equivalent to dropping the factory await, not its blocking job.
    assert_eq!(fixture.ledger.recover_sync(key(2), &fixture.inbox, 64, &stopped).unwrap_err().kind(), io::ErrorKind::Interrupted);
    assert_eq!(fixture.ledger.recovery_reads.load(Ordering::Acquire), MAX_RECOVERY_READS);
    drop(permits.pop());
    let last = ReadPermit::reserve(&fixture.ledger).unwrap();
    drop(permits); drop(last);
    assert_eq!(fixture.ledger.recovery_reads.load(Ordering::Acquire), 0);
}

#[test]
fn committed_proof_recovery_requires_explicit_command_opt_in() {
    use super::super::super::{Cli, Command};
    use clap::Parser;
    let args = ["atpd-live", "serve-durable", "--config", "receiver.json", "--session-ledger", "history",
        "--max-sessions", "4", "--max-sessions-per-client", "2", "--max-session-keys", "8", "--attempts-per-session", "4"];
    assert!(matches!(Cli::try_parse_from(args).unwrap().command,
        Command::ServeDurable { recover_committed: false, .. }));
    let mut opted = args.to_vec(); opted.push("--recover-committed");
    assert!(matches!(Cli::try_parse_from(opted).unwrap().command,
        Command::ServeDurable { recover_committed: true, .. }));
    assert!(Cli::try_parse_from(["atpd-live", "serve", "--config", "receiver.json", "--recover-committed"]).is_err());
}
