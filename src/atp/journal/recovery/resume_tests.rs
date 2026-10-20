//! Public disk recovery must not promote transient or terminal journal state.

use super::*;
use crate::atp::journal::TransferResumeStatus;
use crate::atp::manifest::MerkleRoot;
use crate::atp::object::{ContentId, ObjectId};
use crate::runtime::{RootDrainOutcome, Runtime, RuntimeBuilder};
use crate::security::AuthenticationTag;
use std::time::Duration;

fn key() -> AuthKey { AuthKey::from_seed(91) }

fn offer(id: &str, size: u64) -> JournalRecord {
    JournalRecord::Offer {
        transfer_id: id.to_owned(),
        object_id: ObjectId::content(ContentId::from_bytes(id.as_bytes())),
        manifest_root: MerkleRoot::new([3; 32]),
        total_size: size,
        timestamp: 1,
        auth_tag: AuthenticationTag::zero(),
    }
}

fn chunk(id: &str, offset: u64, size: u64, phase: u8) -> JournalRecord {
    let transfer_id = id.to_owned();
    let auth_tag = AuthenticationTag::zero();
    let timestamp = u64::from(phase) + 2;
    match phase {
        0 => JournalRecord::ChunkReceived {
            transfer_id, chunk_offset: offset, chunk_size: size,
            chunk_hash: [1; 32], timestamp, auth_tag,
        },
        1 => JournalRecord::ChunkVerified {
            transfer_id, chunk_offset: offset, chunk_size: size,
            verified_hash: [1; 32], timestamp, auth_tag,
        },
        2 => JournalRecord::ChunkWritten {
            transfer_id, chunk_offset: offset, chunk_size: size,
            file_path: "staged-payload".to_owned(), timestamp, auth_tag,
        },
        _ => unreachable!(),
    }
}

fn terminal(id: &str, phase: u8) -> JournalRecord {
    let transfer_id = id.to_owned();
    let auth_tag = AuthenticationTag::zero();
    let timestamp = 10;
    match phase {
        0 => JournalRecord::Cancellation { transfer_id, reason: "cancelled".to_owned(), timestamp, auth_tag },
        1 => JournalRecord::CommitIntent { transfer_id, final_manifest_root: MerkleRoot::new([3; 32]), timestamp, auth_tag },
        2 => JournalRecord::CommitComplete { transfer_id, final_path: "published".to_owned(), committed_size: 8, timestamp, auth_tag },
        3 => JournalRecord::Rollback { transfer_id, rollback_reason: "rollback".to_owned(), checkpoint_sequence: 0, timestamp, auth_tag },
        _ => unreachable!(),
    }
}

fn journal(root: &Path, records: impl IntoIterator<Item = JournalRecord>) -> PathBuf {
    let directory = root.join("journal");
    let mut journal = AppendJournal::new(JournalConfig {
        base_dir: directory.clone(), ..JournalConfig::default()
    }, key()).unwrap();
    for record in records { journal.append(record).unwrap(); }
    journal.flush().unwrap();
    drop(journal);
    directory.join("journal_gen_000000.dat")
}

fn runtime(workers: usize) -> Runtime {
    let builder = if workers == 1 { RuntimeBuilder::current_thread() }
        else { RuntimeBuilder::new().worker_threads(workers) };
    builder.blocking_threads(1, 2).build().unwrap()
}

fn drained(runtime: &Runtime) {
    let report = runtime.shutdown_drained(Duration::from_secs(5));
    assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
    assert_eq!(report.live_tasks, 0);
    assert_eq!(report.pending_spawns, 0);
    assert_eq!(report.pending_obligations, 0);
}

#[test]
fn reopened_journal_activates_only_matching_written_progress() {
    for workers in [1, 2] {
        let root = tempfile::tempdir().unwrap();
        let mut records = vec![offer("mixed", 12), offer("received", 8), offer("verified", 8)];
        for (offset, phase) in [(0, 2), (4, 1), (8, 0)] {
            for current in 0..=phase { records.push(chunk("mixed", offset, 4, current)); }
        }
        records.push(chunk("received", 0, 8, 0));
        records.push(chunk("verified", 0, 8, 0));
        records.push(chunk("verified", 0, 8, 1));
        let path = journal(root.path(), records);
        let bitmap_dir = root.path().join("new-bitmaps");
        let runtime = runtime(workers);
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let (journal, bitmaps) = recover_journal_and_bitmap(&cx, &path, &bitmap_dir, &key()).await.unwrap();
            assert_eq!(bitmaps.len(), 3);
            assert_eq!(bitmaps["mixed"].get_chunk_state(0), Some(ChunkState::Written));
            assert_eq!(bitmaps["mixed"].get_chunk_state(4), None);
            assert_eq!(bitmaps["mixed"].get_chunk_state(8), None);
            assert_eq!(bitmaps["received"].entry_count(), 0);
            assert_eq!(bitmaps["verified"].entry_count(), 0);
            assert_eq!(bitmaps["verified"].total_size(), 8);
            assert_eq!(journal.get_resume_summary("mixed").unwrap().durable_bytes, 4);
            let accepted = bitmaps.keys().cloned().collect::<HashSet<_>>();
            let loaded = load_recovered_or_create_bitmap(&bitmap_dir.join("transfer_mixed.bitmap"), &accepted)
                .await.unwrap().unwrap();
            assert_eq!(loaded.entry_count(), 1);
            assert_eq!(loaded.get_chunk_state(4), None);
            let before = std::fs::read(bitmap_dir.join("transfer_mixed.bitmap")).unwrap();
            drop(journal);
            let (_, repeated) = recover_journal_and_bitmap(&cx, &path, &bitmap_dir, &key()).await.unwrap();
            assert_eq!(repeated["mixed"].entry_count(), 1);
            assert_eq!(std::fs::read(bitmap_dir.join("transfer_mixed.bitmap")).unwrap(), before);
        });
        drained(&runtime);
    }
}

#[test]
fn terminal_and_offerless_transfers_cannot_reactivate_stale_bitmaps() {
    for workers in [1, 2] {
        let root = tempfile::tempdir().unwrap();
        let bitmap_dir = root.path().join("bitmaps");
        std::fs::create_dir(&bitmap_dir).unwrap();
        let mut records = vec![offer("live", 8)];
        for phase in 0..=2 { records.push(chunk("live", 0, 8, phase)); }
        for (kind, id) in ["cancel", "pending", "committed", "rollback"].into_iter().enumerate() {
            records.push(offer(id, 8));
            for phase in 0..=2 { records.push(chunk(id, 0, 8, phase)); }
            records.push(terminal(id, kind as u8));
        }
        for phase in 0..=2 { records.push(chunk("offerless", 0, 8, phase)); }
        for id in ["cancel", "pending", "committed", "rollback", "offerless"] {
            let mut stale = ChunkBitmap::new(id.to_owned(), 8, 8, 1);
            stale.update_chunk_state(0, ChunkState::Written, 1, None);
            std::fs::write(bitmap_dir.join(format!("transfer_{id}.bitmap")), stale.serialize_to_bytes()).unwrap();
        }
        let path = journal(root.path(), records);
        let runtime = runtime(workers);
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let (journal, bitmaps) = recover_journal_and_bitmap(&cx, &path, &bitmap_dir, &key()).await.unwrap();
            assert_eq!(bitmaps.len(), 1);
            assert!(bitmaps.contains_key("live"));
            assert!(matches!(journal.get_resume_summary("cancel").unwrap().status, TransferResumeStatus::Cancelled { .. }));
            assert!(matches!(journal.get_resume_summary("pending").unwrap().status, TransferResumeStatus::CommitIntentPending));
            assert!(matches!(journal.get_resume_summary("committed").unwrap().status, TransferResumeStatus::Committed { .. }));
            assert!(matches!(journal.get_resume_summary("rollback").unwrap().status, TransferResumeStatus::RolledBack { .. }));
            for id in ["cancel", "pending", "committed", "rollback", "offerless"] {
                let active = bitmap_dir.join(format!("transfer_{id}.bitmap"));
                assert!(!active.exists());
                let quarantined = std::fs::read(active.with_extension("bitmap.stale")).unwrap();
                assert_eq!(ChunkBitmap::deserialize_from_bytes(&quarantined).unwrap().transfer_id(), id);
            }
        });
        drained(&runtime);
    }
}

#[test]
fn unordered_verified_and_written_records_do_not_override_replay_admission() {
    for corrected in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let mut records = vec![offer("ordered", 8), chunk("ordered", 0, 8, 1),
            chunk("ordered", 0, 8, 2), chunk("ordered", 0, 8, 0)];
        if corrected {
            records.push(chunk("ordered", 0, 8, 1));
            records.push(chunk("ordered", 0, 8, 2));
        }
        let path = journal(root.path(), records);
        let runtime = runtime(2);
        runtime.block_on(async {
            let (journal, bitmaps) = recover_journal_and_bitmap(
                &Cx::current().unwrap(), &path, &root.path().join("bitmaps"), &key(),
            ).await.unwrap();
            // The shared summary now rejects stale credit as well as replay does.
            assert_eq!(journal.get_resume_summary("ordered").unwrap().durable_bytes, u64::from(corrected) * 8);
            assert_eq!(bitmaps["ordered"].entry_count(), usize::from(corrected));
            assert_eq!(bitmaps["ordered"].get_chunk_state(0), corrected.then_some(ChunkState::Written));
        });
        drained(&runtime);
    }
}

#[test]
fn unauthenticated_cancellation_refuses_before_any_bitmap_is_changed() {
    let root = tempfile::tempdir().unwrap();
    let mut records = vec![offer("live", 8)];
    for phase in 0..=2 { records.push(chunk("live", 0, 8, phase)); }
    let path = journal(root.path(), records);
    // Append a CRC-valid cancellation signed with another key. Ignoring it and
    // exporting the earlier prefix would silently erase a terminal boundary.
    let mut wrong_key_writer = AppendJournal::new(JournalConfig {
        base_dir: path.parent().unwrap().to_owned(), ..JournalConfig::default()
    }, AuthKey::from_seed(92)).unwrap();
    wrong_key_writer.append(terminal("live", 0)).unwrap();
    wrong_key_writer.flush().unwrap();
    drop(wrong_key_writer);
    let bitmap_dir = root.path().join("bitmaps");
    std::fs::create_dir(&bitmap_dir).unwrap();
    let original = bitmap_dir.join("transfer_live.bitmap");
    let stale = bitmap_dir.join("transfer_other.bitmap");
    std::fs::write(&original, b"original bitmap evidence").unwrap();
    std::fs::write(&stale, b"other bitmap evidence").unwrap();
    let runtime = runtime(1);
    runtime.block_on(async {
        assert!(matches!(recover_journal_and_bitmap(&Cx::current().unwrap(), &path, &bitmap_dir, &key()).await,
            Err(RecoveryError::InvalidSignature)));
    });
    drained(&runtime);
    assert_eq!(std::fs::read(&original).unwrap(), b"original bitmap evidence");
    assert_eq!(std::fs::read(&stale).unwrap(), b"other bitmap evidence");
    assert_eq!(std::fs::read_dir(&bitmap_dir).unwrap().count(), 2);
}

#[test]
fn authenticated_summary_conflicts_refuse_before_export_or_stale_quarantine() {
    let root = tempfile::tempdir().unwrap();
    let mut records = vec![offer("conflict", 8)];
    for phase in 0..=2 { records.push(chunk("conflict", 0, 8, phase)); }
    let mut conflicting = chunk("conflict", 0, 8, 1);
    if let JournalRecord::ChunkVerified { verified_hash, .. } = &mut conflicting { *verified_hash = [2; 32]; }
    records.push(conflicting);
    let path = journal(root.path(), records);
    let bitmap_dir = root.path().join("bitmaps");
    std::fs::create_dir(&bitmap_dir).unwrap();
    let stale = bitmap_dir.join("transfer_other.bitmap");
    std::fs::write(&stale, b"retained").unwrap();
    let runtime = runtime(1);
    runtime.block_on(async {
        assert!(matches!(recover_journal_and_bitmap(&Cx::current().unwrap(), &path, &bitmap_dir, &key()).await,
            Err(RecoveryError::JournalCorrupted(message)) if message.contains("verified hash conflict")));
    });
    drained(&runtime);
    assert_eq!(std::fs::read(stale).unwrap(), b"retained");
    assert_eq!(std::fs::read_dir(bitmap_dir).unwrap().count(), 1);
}

#[test]
fn journal_ids_cannot_escape_or_alias_the_bitmap_namespace() {
    for ids in [vec!["part/leaf"], vec!["part\\leaf"], vec!["stream:payload"],
        vec![""], vec!["control\nname"], vec!["alpha", "ALPHA"]]
    {
        let root = tempfile::tempdir().unwrap();
        let records = ids.iter().flat_map(|id| [offer(id, 8), chunk(id, 0, 8, 0)]);
        let path = journal(root.path(), records);
        let bitmap_dir = root.path().join("bitmaps");
        std::fs::create_dir(&bitmap_dir).unwrap();
        let stale = bitmap_dir.join("transfer_existing.bitmap");
        std::fs::write(&stale, b"retained evidence").unwrap();
        let runtime = runtime(1);
        runtime.block_on(async {
            assert!(matches!(recover_journal_and_bitmap(&Cx::current().unwrap(), &path, &bitmap_dir, &key()).await,
                Err(RecoveryError::BitmapRecovery(_))), "ids={ids:?}");
        });
        drained(&runtime);
        assert_eq!(std::fs::read(&stale).unwrap(), b"retained evidence");
        assert_eq!(std::fs::read_dir(&bitmap_dir).unwrap().count(), 1);
    }
    assert_eq!(recovery_bitmap_name("résumé-123").unwrap(), "transfer_résumé-123.bitmap");
}

#[cfg(unix)]
#[test]
fn atomic_bitmap_replacement_preserves_old_readers_and_link_targets() {
    use std::io::Read;
    for symlink in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let mut records = vec![offer("live", 8)];
        for phase in 0..=2 { records.push(chunk("live", 0, 8, phase)); }
        let path = journal(root.path(), records);
        let bitmap_dir = root.path().join("bitmaps");
        std::fs::create_dir(&bitmap_dir).unwrap();
        let target = bitmap_dir.join("transfer_live.bitmap");
        let old = root.path().join("previous-inode");
        std::fs::write(&old, b"previous contents stay intact").unwrap();
        if symlink { std::os::unix::fs::symlink(&old, &target).unwrap(); }
        else { std::fs::hard_link(&old, &target).unwrap(); }
        let mut reader = std::fs::File::open(&target).unwrap();
        let runtime = runtime(2);
        runtime.block_on(async {
            let (_, bitmaps) = recover_journal_and_bitmap(&Cx::current().unwrap(), &path, &bitmap_dir, &key())
                .await.unwrap();
            let bytes = std::fs::read(&target).unwrap();
            let decoded = ChunkBitmap::deserialize_from_bytes(&bytes).unwrap();
            assert_eq!(decoded.get_chunk_state(0), Some(ChunkState::Written));
            assert_eq!(decoded.total_size(), bitmaps["live"].total_size());
        });
        drained(&runtime);
        let mut previous = Vec::new();
        reader.read_to_end(&mut previous).unwrap();
        assert_eq!(previous, b"previous contents stay intact");
        assert_eq!(std::fs::read(&old).unwrap(), previous);
        assert!(!std::fs::symlink_metadata(&target).unwrap().file_type().is_symlink());
    }
}
