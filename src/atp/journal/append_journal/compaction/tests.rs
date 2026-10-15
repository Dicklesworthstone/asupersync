//! Retention/reopen tests exercise real encoded generations, not a mock log.

use super::*;
use crate::atp::journal::{ChunkState, recover_journal_and_bitmap};
use std::cell::Cell;

fn key() -> AuthKey { AuthKey::from_seed(42) }

fn config(path: &Path, retain: u32) -> JournalConfig {
    JournalConfig {
        base_dir: path.to_owned(),
        max_journal_size: u64::MAX,
        recent_entries_limit: 1,
        max_generations: retain,
        ..JournalConfig::default()
    }
}

fn accept(id: &str, peer: &str) -> JournalRecord {
    JournalRecord::Accept {
        transfer_id: id.to_owned(), peer_id: peer.to_owned(), timestamp: 1,
        auth_tag: AuthenticationTag::zero(),
    }
}

fn offer(id: &str) -> JournalRecord {
    JournalRecord::Offer {
        transfer_id: id.to_owned(), object_id: ObjectId::content(ContentId::from_bytes(id.as_bytes())),
        manifest_root: MerkleRoot::new([1; 32]), total_size: 8, timestamp: 1,
        auth_tag: AuthenticationTag::zero(),
    }
}

fn progress(journal: &mut AppendJournal, id: &str) {
    journal.append(offer(id)).unwrap();
    for record in [
        JournalRecord::ChunkReceived { transfer_id: id.to_owned(), chunk_offset: 0,
            chunk_size: 4, chunk_hash: [7; 32], timestamp: 2, auth_tag: AuthenticationTag::zero() },
        JournalRecord::ChunkVerified { transfer_id: id.to_owned(), chunk_offset: 0,
            chunk_size: 4, verified_hash: [7; 32], timestamp: 3, auth_tag: AuthenticationTag::zero() },
        JournalRecord::ChunkWritten { transfer_id: id.to_owned(), chunk_offset: 0,
            chunk_size: 4, file_path: "stage".to_owned(), timestamp: 4, auth_tag: AuthenticationTag::zero() },
    ] { journal.append(record).unwrap(); }
}

fn frames(entries: impl IntoIterator<Item = JournalEntry>) -> Vec<u8> {
    let mut bytes = Vec::new();
    for entry in entries { storage::write_frame(&mut bytes, &entry.encode()).unwrap(); }
    bytes
}

fn same_records(a: &[JournalEntry], b: &[JournalEntry]) {
    assert_eq!(a.len(), b.len());
    assert!(a.iter().zip(b).all(|(a, b)| same_entry(a, b)));
}

#[test]
fn repeated_compaction_preserves_transfer_history_beyond_retention_and_tiny_cache() {
    for force_sync in [false, true] {
        for retain in [0, 1, 2] {
            let root = tempfile::tempdir().unwrap();
            let cfg = JournalConfig { force_sync, ..config(root.path(), retain) };
            let mut journal = AppendJournal::new(cfg.clone(), key()).unwrap();
            for id in ["active", "cancelled", "pending", "committed", "rolled"] {
                progress(&mut journal, id);
            }
            for record in [
                JournalRecord::Cancellation { transfer_id: "cancelled".to_owned(), reason: "stop".to_owned(),
                    timestamp: 5, auth_tag: AuthenticationTag::zero() },
                JournalRecord::CommitIntent { transfer_id: "pending".to_owned(), final_manifest_root: MerkleRoot::new([1; 32]),
                    timestamp: 5, auth_tag: AuthenticationTag::zero() },
                JournalRecord::CommitComplete { transfer_id: "committed".to_owned(), final_path: "file".to_owned(),
                    committed_size: 8, timestamp: 5, auth_tag: AuthenticationTag::zero() },
                JournalRecord::Rollback { transfer_id: "rolled".to_owned(), rollback_reason: "retry".to_owned(),
                    checkpoint_sequence: 1, timestamp: 5, auth_tag: AuthenticationTag::zero() },
            ] { journal.append(record).unwrap(); }
            let before = journal.get_transfer_entries("active").unwrap();
            let expected: Vec<_> = ["active", "cancelled", "pending", "committed", "rolled"]
                .map(|id| journal.get_resume_summary(id).unwrap()).into_iter().collect();
            for iteration in 0..5 {
                journal.compact().unwrap();
                assert_eq!(journal.recent_entries.len(), 1);
                let generation = journal.generation;
                let prefix = journal.generation_base_bytes;
                assert!(prefix > 0);
                drop(journal);
                journal = AppendJournal::new(cfg.clone(), key()).unwrap();
                assert_eq!(journal.generation, generation);
                assert_eq!(journal.generation_base_bytes, prefix);
                for summary in &expected {
                    assert_eq!(journal.get_resume_summary(&summary.transfer_id).unwrap(), *summary);
                }
                same_records(&journal.get_transfer_entries("active").unwrap(), &before);
                let records = journal.read_all_entries_from_disk().unwrap();
                assert_eq!(records.len() as u64, journal.sequence);
                assert!(records.iter().all(|entry| entry.record.verify_signature(&key())));
                assert!(journal.discover_generations().unwrap().len() <= retain as usize + 1);
                journal.append(accept("other", &iteration.to_string())).unwrap();
            }
        }
    }
}

#[test]
fn every_snapshot_byte_cut_recovers_original_history_without_duplicate_replay() {
    let root = tempfile::tempdir().unwrap();
    let cfg = config(root.path(), 0);
    let mut source = AppendJournal::new(cfg, key()).unwrap();
    source.append(accept("transfer", "first")).unwrap();
    source.append(accept("transfer", "second")).unwrap();
    let original = std::fs::read(journal_file_path(root.path(), 0)).unwrap();
    let before = source.get_transfer_entries("transfer").unwrap();
    let mut snapshot = before.clone();
    snapshot.push(JournalEntry::new(2, JournalRecord::signed_compaction_boundary(1, 2, 3, &key())));
    let snapshot = frames(snapshot);
    for cut in 0..=snapshot.len() {
        let case = root.path().join(format!("cut-{cut}"));
        std::fs::create_dir(&case).unwrap();
        std::fs::write(journal_file_path(&case, 0), &original).unwrap();
        std::fs::write(journal_file_path(&case, 1), &snapshot[..cut]).unwrap();
        let cfg = config(&case, 0);
        let mut recovered = AppendJournal::new(cfg.clone(), key()).unwrap();
        same_records(&recovered.get_transfer_entries("transfer").unwrap(), &before);
        let next = if cut == snapshot.len() { 3 } else { 2 };
        assert_eq!(recovered.sequence, next, "cut {cut}");
        assert_eq!(recovered.append(accept("transfer", "after restart")).unwrap(), next);
        drop(recovered);
        let recovered = AppendJournal::new(cfg, key()).unwrap();
        assert_eq!(recovered.get_transfer_entries("transfer").unwrap().len(), 3);
        assert_eq!(recovered.read_all_entries_from_disk().unwrap().len(), next as usize + 1);
        assert_eq!(std::fs::read(journal_file_path(&case, 0)).unwrap(), original);
    }
}

#[test]
fn partial_copy_errors_and_panics_keep_originals_and_fence_the_instance() {
    for panic in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let cfg = config(root.path(), 0);
        let mut journal = AppendJournal::new(cfg.clone(), key()).unwrap();
        progress(&mut journal, "active");
        let expected = journal.get_resume_summary("active").unwrap();
        let original = std::fs::read(journal_file_path(root.path(), 0)).unwrap();
        let count = Cell::new(0);
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            journal.compact_with_storage(|file, entry| {
                count.set(count.get() + 1);
                if count.get() == 2 {
                    file.write_all(&[1, 2]).unwrap();
                    assert!(!panic, "partial snapshot panic");
                    return Err(JournalError::WriteFailure("partial snapshot witness".to_owned()));
                }
                write_entry(file, entry)
            }, |_| panic!("failed copy reached sync"), |_| panic!("failed copy reached directory sync"))
        }));
        if panic { assert!(outcome.is_err()); } else {
            assert!(matches!(outcome.unwrap(), Outcome::Err(JournalError::WriteFailure(message))
                if message == "partial snapshot witness"));
        }
        assert!(journal.storage_failed);
        assert!(matches!(journal.append(accept("later", "no")), Outcome::Err(JournalError::WriteFailure(_))));
        assert!(matches!(journal.get_resume_summary("active"), Outcome::Err(JournalError::WriteFailure(_))));
        let partial = std::fs::read(journal_file_path(root.path(), 1)).unwrap();
        drop(journal);
        assert_eq!(std::fs::read(journal_file_path(root.path(), 1)).unwrap(), partial);
        assert_eq!(std::fs::read(journal_file_path(root.path(), 0)).unwrap(), original);
        let mut recovered = AppendJournal::new(cfg, key()).unwrap();
        assert_eq!(recovered.get_resume_summary("active").unwrap(), expected);
        assert_eq!(recovered.generation, 2);
        recovered.compact().unwrap();
        // Torn candidate remains forensic evidence even with zero old-generation retention.
        assert_eq!(std::fs::read(journal_file_path(root.path(), 1)).unwrap(), partial);
        assert_eq!(recovered.get_resume_summary("active").unwrap(), expected);
    }
}

#[test]
fn both_durability_barriers_precede_any_retention_cleanup() {
    for fail_directory in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let cfg = JournalConfig { force_sync: false, ..config(root.path(), 0) };
        let mut journal = AppendJournal::new(cfg.clone(), key()).unwrap();
        progress(&mut journal, "active");
        let original_path = journal_file_path(root.path(), 0);
        let original = std::fs::read(&original_path).unwrap();
        let expected = journal.get_resume_summary("active").unwrap();
        let sync_calls = Cell::new(0);
        let directory_calls = Cell::new(0);
        let result = journal.compact_with_storage(write_entry, |file| {
            sync_calls.set(sync_calls.get() + 1);
            assert_eq!(std::fs::read(&original_path).unwrap(), original);
            if fail_directory { file.sync_all() }
            else { Err(io::Error::other("snapshot barrier")) }
        }, |_| {
            directory_calls.set(directory_calls.get() + 1);
            assert_eq!(std::fs::read(&original_path).unwrap(), original);
            Err(JournalError::SyncFailure("directory barrier".to_owned()))
        });
        assert!(matches!(result, Outcome::Err(JournalError::SyncFailure(message))
            if message == if fail_directory { "directory barrier" } else { "snapshot barrier" }));
        assert_eq!(sync_calls.get(), 1);
        assert_eq!(directory_calls.get(), usize::from(fail_directory));
        assert!(original_path.exists());
        assert!(journal.storage_failed);
        drop(journal);
        let recovered = AppendJournal::new(cfg, key()).unwrap();
        assert_eq!(recovered.get_resume_summary("active").unwrap(), expected);
    }
}

#[test]
fn snapshot_growth_is_excluded_from_rotation_threshold_after_reopen() {
    let root = tempfile::tempdir().unwrap();
    let cfg = config(root.path(), 0);
    let mut journal = AppendJournal::new(cfg.clone(), key()).unwrap();
    journal.append(accept("large", &"x".repeat(4096))).unwrap();
    journal.compact().unwrap();
    let base = journal.generation_base_bytes;
    assert!(base > 4096);
    drop(journal);
    let mut cfg = cfg;
    cfg.max_journal_size = 512;
    let mut journal = AppendJournal::new(cfg, key()).unwrap();
    assert_eq!(journal.generation_base_bytes, base);
    let generation = journal.generation;
    journal.append(accept("small", "one")).unwrap();
    assert_eq!(journal.generation, generation, "carried bytes caused premature rotation");
    journal.append(accept("large", &"y".repeat(512))).unwrap();
    assert_eq!(journal.generation, generation + 1);
    journal.append(accept("small", "two")).unwrap();
    assert_eq!(journal.generation, generation + 1);
    assert_eq!(journal.get_transfer_entries("large").unwrap().len(), 2);
}

#[test]
fn automatic_compaction_reopens_with_every_accepted_record_and_terminal() {
    let root = tempfile::tempdir().unwrap();
    let cfg = JournalConfig { max_journal_size: 1, ..config(root.path(), 0) };
    let mut journal = AppendJournal::new(cfg.clone(), key()).unwrap();
    progress(&mut journal, "active");
    journal.append(JournalRecord::Cancellation { transfer_id: "active".to_owned(), reason: "stop".to_owned(),
        timestamp: 6, auth_tag: AuthenticationTag::zero() }).unwrap();
    let before = journal.get_transfer_entries("active").unwrap();
    assert_eq!(before.len(), 5);
    assert_eq!(journal.generation, 5);
    drop(journal);
    let recovered = AppendJournal::new(cfg, key()).unwrap();
    same_records(&recovered.get_transfer_entries("active").unwrap(), &before);
    assert!(matches!(recovered.get_resume_summary("active").unwrap().status, TransferResumeStatus::Cancelled { .. }));
    assert_eq!(recovered.read_all_entries_from_disk().unwrap().len(), 10);
}

#[test]
fn conflicting_sequences_refuse_globally_even_for_different_transfers() {
    for same_transfer in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let cfg = config(root.path(), 0);
        let mut journal = AppendJournal::new(cfg.clone(), key()).unwrap();
        journal.append(accept("first", "original")).unwrap();
        let original_path = journal_file_path(root.path(), 0);
        let original = std::fs::read(&original_path).unwrap();
        let conflicting = JournalEntry::new(0, accept(if same_transfer { "first" } else { "second" }, "conflict").with_signature(&key()));
        let other = frames([conflicting]);
        std::fs::write(journal_file_path(root.path(), 1), &other).unwrap();
        assert!(matches!(AppendJournal::new(cfg, key()), Outcome::Err(JournalError::Deserialization(message))
            if message.contains("conflicting journal copies")));
        assert!(journal.compact().is_err());
        assert_eq!(std::fs::read(original_path).unwrap(), original);
        assert_eq!(std::fs::read(journal_file_path(root.path(), 1)).unwrap(), other);
        assert!(!journal_file_path(root.path(), 2).exists());
    }
}

#[test]
fn wrong_key_and_missing_indexed_history_cannot_authorize_retention() {
    for missing in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let cfg = config(root.path(), 0);
        let mut journal = AppendJournal::new(cfg.clone(), key()).unwrap();
        journal.append(accept("first", "original")).unwrap();
        let original_path = journal_file_path(root.path(), 0);
        let original = std::fs::read(&original_path).unwrap();
        if missing {
            // Preserve the evidence at a non-generation path; do not delete it.
            std::fs::rename(&original_path, root.path().join("retained-evidence.dat")).unwrap();
        } else {
            drop(journal);
            journal = AppendJournal::new(cfg, AuthKey::from_seed(43)).unwrap();
        }
        assert!(journal.compact().is_err());
        assert!(!journal_file_path(root.path(), 1).exists());
        let path = if missing { root.path().join("retained-evidence.dat") } else { original_path };
        assert_eq!(std::fs::read(path).unwrap(), original);
    }
}

#[test]
fn noncanonical_record_lengths_refuse_before_creating_a_replacement() {
    let root = tempfile::tempdir().unwrap();
    let cfg = config(root.path(), 0);
    let entry = JournalEntry::new(0, accept("first", "original").with_signature(&key()));
    let mut encoded = entry.encode();
    encoded[12..16].copy_from_slice(&(entry.entry_size + 1).to_le_bytes());
    encoded.push(0); // Old payload decoding accepts a trailing byte.
    let mut bytes = Vec::new();
    storage::write_frame(&mut bytes, &encoded).unwrap();
    let path = journal_file_path(root.path(), 0);
    std::fs::write(&path, &bytes).unwrap();
    let mut journal = AppendJournal::new(cfg, key()).unwrap();
    assert!(matches!(journal.compact(), Outcome::Err(JournalError::CompactionFailed(message))
        if message.contains("canonical payload")));
    assert_eq!(std::fs::read(path).unwrap(), bytes);
    assert!(!journal_file_path(root.path(), 1).exists());
}

#[test]
fn existing_generation_is_never_opened_or_truncated_by_compaction() {
    let root = tempfile::tempdir().unwrap();
    let cfg = config(root.path(), 0);
    let mut journal = AppendJournal::new(cfg, key()).unwrap();
    journal.append(accept("first", "original")).unwrap();
    let original = std::fs::read(journal_file_path(root.path(), 0)).unwrap();
    let next = journal_file_path(root.path(), 1);
    std::fs::write(&next, []).unwrap();
    assert!(journal.compact().is_err());
    assert_eq!(std::fs::read(next).unwrap(), b"");
    assert_eq!(std::fs::read(journal_file_path(root.path(), 0)).unwrap(), original);
}

#[test]
fn empty_journal_compaction_and_zero_cache_keep_monotone_sequence() {
    let root = tempfile::tempdir().unwrap();
    let cfg = JournalConfig { recent_entries_limit: 0, ..config(root.path(), 0) };
    let mut journal = AppendJournal::new(cfg.clone(), key()).unwrap();
    for sequence in 1..=3 {
        journal.compact().unwrap();
        assert_eq!(journal.sequence, sequence);
        assert!(journal.recent_entries.is_empty());
        drop(journal);
        journal = AppendJournal::new(cfg.clone(), key()).unwrap();
        assert_eq!(journal.sequence, sequence);
    }
    assert_eq!(journal.append(accept("first", "after empty snapshots")).unwrap(), 3);
}

#[test]
fn native_bitmap_recovery_uses_carry_forward_records_after_originals_expire() {
    use crate::runtime::{RootDrainOutcome, RuntimeBuilder};
    use std::time::Duration;
    for workers in [1, 2] {
        let root = tempfile::tempdir().unwrap();
        let journal_dir = root.path().join("journal");
        let cfg = config(&journal_dir, 0);
        let mut journal = AppendJournal::new(cfg, key()).unwrap();
        progress(&mut journal, "active");
        progress(&mut journal, "cancelled");
        journal.append(JournalRecord::Cancellation { transfer_id: "cancelled".to_owned(), reason: "stop".to_owned(),
            timestamp: 5, auth_tag: AuthenticationTag::zero() }).unwrap();
        for _ in 0..3 { journal.compact().unwrap(); }
        assert!(!journal_file_path(&journal_dir, 0).exists());
        drop(journal);
        let builder = if workers == 1 { RuntimeBuilder::current_thread() }
            else { RuntimeBuilder::new().worker_threads(workers) };
        let runtime = builder.blocking_threads(1, 2).build().unwrap();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let (recovered, bitmaps) = recover_journal_and_bitmap(
                &cx, &journal_file_path(&journal_dir, 0), &root.path().join("bitmaps"), &key(),
            ).await.unwrap();
            assert_eq!(recovered.get_resume_summary("active").unwrap().contiguous_prefix_bytes, 4);
            assert_eq!(bitmaps.len(), 1);
            assert_eq!(bitmaps["active"].get_chunk_state(0), Some(ChunkState::Written));
            assert!(bitmaps["active"].get_chunk_state(4).is_none());
            assert!(matches!(recovered.get_resume_summary("cancelled").unwrap().status,
                TransferResumeStatus::Cancelled { .. }));
        });
        let report = runtime.shutdown_drained(Duration::from_secs(5));
        assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
    }
}
