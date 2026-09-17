//! Real private-file ledger tests; every fixture is deliberately retained.
use super::*;

fn fixture() -> PathBuf {
    let directory = tempfile::tempdir().unwrap().keep();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    directory.join("sessions.log")
}
fn key(client: u8, nonce: u8) -> ResumeSessionKey {
    ResumeSessionKey { client: NativeClientCertificateId::from_sha256([client; 32]), nonce: [nonce; 32] }
}
fn name(byte: u8) -> String { format!("{}.bin", hex(&[byte; 16])) }
fn receipt(key: ResumeSessionKey) -> LiveStreamReceipt {
    LiveStreamReceipt { prefix: LiveStreamPrefix { stream_nonce: key.nonce, epochs: 1, bytes: 3, chain: [8; 32] },
        source_sha256: Sha256::digest(b"abc").into() }
}
fn write_new(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(path).unwrap();
    file.write_all(bytes).unwrap(); file.sync_all().unwrap();
}

#[test]
fn ledger_recovers_claims_and_actual_receipts_without_recreating_old_keys() {
    let path = fixture(); Ledger::initialize(&path, 2).unwrap();
    let ledger = Ledger::open(&path).unwrap();
    let first = key(1, 7); let other_client = key(2, 7);
    ledger.claim_sync(first, name(1), 10).unwrap();
    ledger.claim_sync(other_client, name(2), 10).unwrap();
    ledger.commit_sync(first, receipt(first)).unwrap();
    let length = std::fs::metadata(&path).unwrap().len();
    ledger.commit_sync(first, receipt(first)).unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().len(), length);
    drop(ledger);
    let reopened = Ledger::open(&path).unwrap();
    let entries = reopened.snapshot().unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].maximum_bytes, 10);
    assert_eq!(entries[0].receipt, Some(receipt(first)));
    assert!(entries[1].receipt.is_none());
    for old in [first, other_client] {
        assert!(is_replay_refusal(&reopened.claim_sync(old, name(3), 10).unwrap_err()));
    }
    assert_eq!(reopened.claim_sync(key(1, 8), name(4), 10).unwrap_err().kind(), io::ErrorKind::StorageFull);
    assert_eq!(std::fs::metadata(path).unwrap().len(), length);
}

#[test]
fn ledger_initialization_never_overwrites_and_open_never_creates() {
    let path = fixture();
    assert_eq!(Ledger::open(&path).unwrap_err().kind(), io::ErrorKind::NotFound);
    assert!(!path.exists());
    for limit in [0, MAX_KEYS + 1] { assert!(Ledger::initialize(&path, limit).is_err()); }
    assert!(!path.exists());
    Ledger::initialize(&path, 3).unwrap();
    let before = std::fs::read(&path).unwrap();
    assert!(Ledger::initialize(&path, 4).is_err());
    assert_eq!(std::fs::read(path).unwrap(), before);
}

#[test]
fn ledger_exclusive_ownership_and_inode_validation_fail_closed() {
    let path = fixture(); Ledger::initialize(&path, 2).unwrap();
    let ledger = Ledger::open(&path).unwrap();
    assert_eq!(Ledger::open(&path).unwrap_err().kind(), io::ErrorKind::WouldBlock);
    let symlink = path.with_extension("symlink");
    std::os::unix::fs::symlink(&path, &symlink).unwrap();
    assert!(Ledger::open(&symlink).is_err());
    let alias = path.with_extension("alias");
    std::fs::hard_link(&path, &alias).unwrap();
    assert!(ledger.claim_sync(key(1, 1), name(1), 1).is_err());
    assert!(ledger.snapshot().is_err());
    drop(ledger);
    assert!(Ledger::open(&path).is_err());
}

#[test]
fn ledger_torn_tails_and_corruption_are_rejected_without_repair() {
    let path = fixture(); Ledger::initialize(&path, 1).unwrap();
    let ledger = Ledger::open(&path).unwrap();
    ledger.claim_sync(key(1, 1), name(1), 10).unwrap(); drop(ledger);
    let bytes = std::fs::read(&path).unwrap();
    for length in [0, 1, HEADER_BYTES - 1, HEADER_BYTES + 1, bytes.len() - 1] {
        let bad = fixture(); write_new(&bad, &bytes[..length]);
        assert!(Ledger::open(&bad).is_err());
        assert_eq!(std::fs::read(bad).unwrap(), bytes[..length]);
    }
    for index in [0, 8, 12, 16, HEADER_BYTES, HEADER_BYTES + 16, bytes.len() - 1] {
        let bad = fixture(); let mut broken = bytes.clone(); broken[index] ^= 1;
        write_new(&bad, &broken); assert!(Ledger::open(&bad).is_err());
        assert_eq!(std::fs::read(bad).unwrap(), broken);
    }
}

#[test]
fn ledger_rejects_semantically_invalid_records_even_with_valid_checksums() {
    let path = fixture(); Ledger::initialize(&path, 2).unwrap();
    let header = std::fs::read(&path).unwrap();
    let entry = Entry { key: key(1, 1), filename: name(1), maximum_bytes: 3, receipt: None };
    for case in 0..4 {
        let mut bytes = header.clone();
        let mut previous: [u8; 32] = header[16..].try_into().unwrap();
        for seq in 0..2 {
            let mut item = entry.clone();
            let kind = if seq == 0 && case != 0 { 1 } else { 2 };
            if kind == 2 { item.receipt = Some(receipt(item.key)); }
            if seq == 1 {
                match case {
                    1 => item.filename = name(9),
                    2 => item.receipt.as_mut().unwrap().prefix.bytes = 4,
                    3 => { item.receipt = None; }
                    _ => {}
                }
            }
            let kind = if case == 3 && seq == 1 { 1 } else { kind };
            let mut record = encode(seq, kind, &item);
            let checksum = hash(&previous, &record[..BODY_BYTES]);
            record[BODY_BYTES..].copy_from_slice(&checksum); previous = checksum;
            bytes.extend_from_slice(&record);
        }
        let bad = fixture(); write_new(&bad, &bytes);
        assert!(Ledger::open(&bad).is_err(), "case {case}");
    }
}

#[test]
fn ledger_failed_append_poison_is_sticky_even_after_the_handle_is_repaired() {
    let path = fixture(); Ledger::initialize(&path, 2).unwrap();
    let ledger = Ledger::open(&path).unwrap();
    // Real write refusal; keep the original locked descriptor alive throughout.
    let locked = {
        let mut state = ledger.state.lock();
        std::mem::replace(&mut state.file, File::open(&path).unwrap())
    };
    assert!(ledger.claim_sync(key(1, 1), name(1), 3).is_err());
    ledger.state.lock().file = locked;
    assert!(ledger.claim_sync(key(1, 2), name(2), 3).is_err());
    assert!(ledger.snapshot().is_err());
    assert_eq!(std::fs::metadata(&path).unwrap().len(), HEADER_BYTES as u64);
    drop(ledger);
    // No sink could have been admitted by the failed claim. Valid empty state
    // may be reopened; a partial append instead fails the torn-tail test.
    assert!(Ledger::open(&path).unwrap().snapshot().unwrap().is_empty());
}

#[test]
fn ledger_commit_validates_nonce_size_and_idempotent_receipt() {
    let path = fixture(); Ledger::initialize(&path, 1).unwrap();
    let ledger = Ledger::open(&path).unwrap(); let key = key(1, 1);
    ledger.claim_sync(key, name(1), 3).unwrap();
    let mut wrong = receipt(key); wrong.prefix.stream_nonce = [9; 32];
    assert!(ledger.commit_sync(key, wrong).is_err());
    let mut wrong = receipt(key); wrong.prefix.bytes = 4;
    assert!(ledger.commit_sync(key, wrong).is_err());
    ledger.commit_sync(key, receipt(key)).unwrap();
    let mut wrong = receipt(key); wrong.source_sha256[0] ^= 1;
    assert!(ledger.commit_sync(key, wrong).is_err());
    assert_eq!(ledger.snapshot().unwrap()[0].receipt, Some(receipt(key)));
}
