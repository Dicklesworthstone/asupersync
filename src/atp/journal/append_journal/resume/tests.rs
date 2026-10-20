//! Regressions for ordered receipts and non-masking terminal history.

use super::build;
use super::super::{
    AppendJournal, JournalConfig, JournalEntry, JournalError, JournalRecord,
    MerkleRoot, ObjectId, ContentId, TransferResumeStatus, TransferResumeSummary,
};
use crate::security::{AuthKey, AuthenticationTag};
use crate::types::Outcome;

fn offer() -> JournalRecord {
    JournalRecord::Offer {
        transfer_id: "ordered".to_owned(), object_id: ObjectId::content(ContentId::from_bytes(b"abcdefgh")),
        manifest_root: MerkleRoot::new([1; 32]), total_size: 8,
        timestamp: 99, auth_tag: AuthenticationTag::zero(),
    }
}

fn chunk(kind: u8, offset: u64, size: u64, hash: u8) -> JournalRecord {
    let transfer_id = "ordered".to_owned();
    let timestamp = 1; // Deliberately not monotone; sequences order effects.
    let auth_tag = AuthenticationTag::zero();
    match kind {
        0 => JournalRecord::ChunkReceived { transfer_id, chunk_offset: offset, chunk_size: size,
            chunk_hash: [hash; 32], timestamp, auth_tag },
        1 => JournalRecord::ChunkVerified { transfer_id, chunk_offset: offset, chunk_size: size,
            verified_hash: [hash; 32], timestamp, auth_tag },
        2 => JournalRecord::ChunkWritten { transfer_id, chunk_offset: offset, chunk_size: size,
            file_path: "never-open-this-path".to_owned(), timestamp, auth_tag },
        3 => JournalRecord::RepairDecode { transfer_id, chunk_offset: offset, chunk_size: size,
            source_chunks: vec![99], timestamp, auth_tag },
        _ => unreachable!(),
    }
}

fn terminal(kind: u8) -> JournalRecord {
    let transfer_id = "ordered".to_owned();
    let timestamp = 2;
    let auth_tag = AuthenticationTag::zero();
    match kind {
        0 => JournalRecord::CommitIntent { transfer_id, final_manifest_root: MerkleRoot::new([1; 32]), timestamp, auth_tag },
        1 => JournalRecord::CommitComplete { transfer_id, final_path: "published".to_owned(), committed_size: 8, timestamp, auth_tag },
        2 => JournalRecord::Cancellation { transfer_id, reason: "stopped".to_owned(), timestamp, auth_tag },
        3 => JournalRecord::Rollback { transfer_id, rollback_reason: "retry".to_owned(), checkpoint_sequence: 1, timestamp, auth_tag },
        _ => unreachable!(),
    }
}

fn summary(records: impl IntoIterator<Item = JournalRecord>) -> Result<TransferResumeSummary, JournalError> {
    let entries: Vec<_> = records.into_iter().enumerate()
        .map(|(index, record)| JournalEntry::new(7 + index as u64 * 2, record))
        .collect();
    // Authentication is exercised through the public API below; this pure
    // projection deliberately accepts fixtures with nonzero/gapped origins.
    build("ordered", &entries)
}

#[test]
fn every_short_receipt_history_agrees_with_a_sequence_witness() {
    for length in 0..=7 {
        for mut encoded in 0..4usize.pow(length) {
            let mut history = Vec::new();
            for _ in 0..length {
                history.push((encoded % 4) as u8);
                encoded /= 4;
            }
            // Independent oracle: a reusable receipt needs an ordered V,W
            // witness strictly after the last receive/repair invalidation.
            let boundary = history.iter().rposition(|kind| matches!(kind, 0 | 3))
                .map_or(0, |index| index + 1);
            let suffix = &history[boundary..];
            let reusable = suffix.iter().enumerate().any(|(index, kind)| {
                *kind == 1 && suffix[index + 1..].contains(&2)
            });
            let records = std::iter::once(offer()).chain(history.iter().map(|kind| chunk(*kind, 0, 4, 1)));
            let actual = summary(records).unwrap();
            assert_eq!(actual.durable_bytes, if reusable { 4 } else { 0 }, "{history:?}");
            assert_eq!(actual.contiguous_prefix_bytes, actual.durable_bytes);
            assert_eq!(actual.durable_chunks.len(), usize::from(reusable));
        }
    }
}

#[test]
fn sparse_attempts_are_independent_and_legacy_verified_written_is_supported() {
    let records = vec![
        offer(), chunk(1, 4, 4, 2), chunk(2, 4, 4, 2),
        chunk(1, 0, 4, 1), chunk(2, 0, 4, 1), chunk(0, 0, 4, 1),
    ];
    let pending = summary(records.clone()).unwrap();
    assert_eq!(pending.durable_bytes, 4);
    assert_eq!(pending.contiguous_prefix_bytes, 0);
    assert_eq!(pending.durable_chunks[0].chunk_offset, 4);
    let repaired = summary(records.into_iter().chain([chunk(1, 0, 4, 1), chunk(2, 0, 4, 1)])).unwrap();
    assert_eq!(repaired.contiguous_prefix_bytes, 8);
    let legacy = summary([chunk(1, 0, 4, 1), chunk(2, 0, 4, 1)]).unwrap();
    assert_eq!(legacy.total_size, None);
    assert_eq!(legacy.durable_bytes, 4);
    assert_eq!(summary([]).unwrap().status, TransferResumeStatus::Unknown);
}

#[test]
fn conflicting_hashes_do_not_rebind_existing_verified_evidence() {
    for records in [
        vec![chunk(0, 0, 4, 1), chunk(1, 0, 4, 2)],
        vec![chunk(1, 0, 4, 1), chunk(2, 0, 4, 1), chunk(1, 0, 4, 2)],
        vec![chunk(1, 0, 4, 1), chunk(2, 0, 4, 1), chunk(0, 0, 4, 2)],
        vec![chunk(1, 0, 4, 1), chunk(3, 0, 4, 1), chunk(1, 0, 4, 2)],
    ] {
        assert!(summary(std::iter::once(offer()).chain(records)).is_err());
    }
    // Before verification, a replacement receive supersedes the earlier input.
    assert_eq!(summary([offer(), chunk(0, 0, 4, 2), chunk(0, 0, 4, 1),
        chunk(1, 0, 4, 1), chunk(2, 0, 4, 1)]).unwrap().durable_bytes, 4);
}

#[test]
fn geometry_is_checked_even_for_incomplete_attempts_and_late_offers() {
    for records in [
        vec![offer(), chunk(0, 0, 0, 1)],
        vec![offer(), chunk(0, 8, 1, 1)],
        vec![chunk(0, u64::MAX, 1, 1)],
        vec![offer(), chunk(0, 0, 4, 1), chunk(1, 0, 3, 1)],
        vec![offer(), chunk(0, 0, 5, 1), chunk(0, 4, 4, 1)],
        vec![offer(), chunk(0, 4, 4, 1), chunk(0, 0, 5, 1)],
        vec![chunk(0, 8, 4, 1), offer()],
    ] {
        assert!(summary(records).is_err());
    }
    let high = summary([chunk(1, u64::MAX - 3, 3, 1), chunk(2, u64::MAX - 3, 3, 1)]).unwrap();
    assert_eq!(high.durable_bytes, 3);
    assert_eq!(high.contiguous_prefix_bytes, 0);
    assert_eq!(high.durable_chunks.len(), 1);
}

#[test]
fn terminal_decisions_cannot_be_masked_or_resume_payload() {
    for first in 0..4 {
        for second in 0..4 {
            let allowed = first == second || (first == 0 && second == 1);
            assert_eq!(summary([offer(), terminal(first), terminal(second)]).is_ok(), allowed,
                "terminal {first} -> {second}");
        }
        for kind in 0..4 {
            assert!(summary([offer(), terminal(first), chunk(kind, 0, 4, 1)]).is_err());
        }
        assert!(summary([offer(), terminal(first), offer()]).is_err());
        let proof = JournalRecord::ProofDigest {
            transfer_id: "ordered".to_owned(), proof_type: "diagnostic".to_owned(),
            digest: [7; 32], timestamp: 0, auth_tag: AuthenticationTag::zero(),
        };
        let saved = summary([offer(), terminal(first), proof]).unwrap();
        assert!(saved.durable_chunks.is_empty());
        assert!(!saved.is_resumable());
        assert_eq!(saved.last_sequence, Some(11));
    }
    // Preserve non-resumable legacy reports without inventing prior intent.
    assert!(matches!(summary([terminal(1)]).unwrap().status, TransferResumeStatus::Committed { .. }));
}

#[test]
fn changed_offers_and_terminal_parameters_refuse_instead_of_last_record_wins() {
    for case in 0..7 {
        let mut changed = if case < 2 { offer() } else { terminal((case - 2).min(3)) };
        match (&mut changed, case) {
            (JournalRecord::Offer { object_id, .. }, 0) => *object_id = ObjectId::content(ContentId::from_bytes(b"different")),
            (JournalRecord::Offer { manifest_root, .. }, 1) => *manifest_root = MerkleRoot::new([9; 32]),
            (JournalRecord::CommitIntent { final_manifest_root, .. }, 2) => *final_manifest_root = MerkleRoot::new([9; 32]),
            (JournalRecord::CommitComplete { final_path, .. }, 3) => *final_path = "other".to_owned(),
            (JournalRecord::Cancellation { reason, .. }, 4) => *reason = "changed".to_owned(),
            (JournalRecord::Rollback { checkpoint_sequence, .. }, 5) => *checkpoint_sequence = 2,
            (JournalRecord::Rollback { rollback_reason, .. }, 6) => *rollback_reason = "changed".to_owned(),
            _ => unreachable!(),
        }
        let records = if case < 2 { vec![offer(), changed] }
            else { vec![offer(), terminal((case - 2).min(3)), changed] };
        assert!(summary(records).is_err(), "case {case}");
    }
    let mut wrong_size = terminal(1);
    if let JournalRecord::CommitComplete { committed_size, .. } = &mut wrong_size { *committed_size = 7; }
    assert!(summary([offer(), wrong_size]).is_err());
}

#[test]
fn public_signed_summary_preserves_order_through_compaction_and_reopen() {
    for force_sync in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let config = JournalConfig {
            base_dir: directory.path().to_owned(), force_sync, max_generations: 0,
            recent_entries_limit: 1, max_journal_size: u64::MAX, ..JournalConfig::default()
        };
        let key = AuthKey::from_seed(42);
        let mut journal = AppendJournal::new(config.clone(), key.clone()).unwrap();
        for record in [offer(), chunk(2, 0, 4, 1), chunk(1, 0, 4, 1)] {
            journal.append(record).unwrap();
        }
        journal.flush().unwrap();
        assert_eq!(journal.get_resume_summary("ordered").unwrap().durable_bytes, 0);
        journal.compact().unwrap();
        drop(journal);
        let mut journal = AppendJournal::new(config.clone(), key.clone()).unwrap();
        assert_eq!(journal.get_resume_summary("ordered").unwrap().durable_bytes, 0);
        journal.append(chunk(2, 0, 4, 1)).unwrap();
        assert_eq!(journal.get_resume_summary("ordered").unwrap().durable_bytes, 4);
        journal.append(chunk(3, 0, 4, 1)).unwrap();
        assert_eq!(journal.get_resume_summary("ordered").unwrap().durable_bytes, 0);
        journal.append(terminal(2)).unwrap();
        journal.append(terminal(0)).unwrap();
        let before = journal.get_transfer_entries("ordered").unwrap();
        assert!(journal.get_resume_summary("ordered").is_err());
        journal.compact().unwrap();
        drop(journal);
        let reopened = AppendJournal::new(config.clone(), key).unwrap();
        assert!(reopened.get_resume_summary("ordered").is_err());
        let raw = reopened.get_transfer_entries("ordered").unwrap();
        assert_eq!(raw.len(), before.len());
        assert!(raw.iter().zip(before).all(|(a, b)| a.sequence == b.sequence && a.record == b.record));
        let wrong = AppendJournal::new(config, AuthKey::from_seed(43)).unwrap();
        assert!(matches!(wrong.get_resume_summary("ordered"), Outcome::Err(JournalError::Deserialization(message))
            if message.contains("authentication failed")));
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn physical_restore_does_not_import_a_superseded_durable_prefix() {
    use crate::atp::journal::sparse_writer::ScopedSparseWriter;
    use crate::atp::journal::{JournalRestoreLimits, JournalRestoreRequest, ScopedReceiveOptions, SparseWriterConfig};
    use crate::atp::manifest::Manifest;
    use crate::atp::object::{MetadataPolicy, Object, ObjectGraph};
    use crate::cx::Cx;
    use crate::runtime::{RootDrainOutcome, RuntimeBuilder};
    use sha2::{Digest, Sha256};
    use std::sync::Arc;
    use std::time::Duration;

    for workers in [1, 2] {
        let directory = tempfile::tempdir().unwrap();
        let builder = if workers == 1 { RuntimeBuilder::current_thread() }
            else { RuntimeBuilder::new().worker_threads(2).with_sharded_state(true) };
        let runtime = builder.blocking_threads(1, 2).build().unwrap();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let object = Object::file(b"abcdefgh".to_vec());
            let id = object.id.clone();
            let mut graph = ObjectGraph::new();
            graph.add_root(object).unwrap();
            let manifest = Arc::new(Manifest::from_graph(&graph, MetadataPolicy::portable()).unwrap());
            let root = manifest.merkle_root.clone();
            let path = directory.path().join("source");
            let source = path.clone();
            let config = JournalConfig { base_dir: directory.path().join("journal"),
                max_generations: 0, max_journal_size: u64::MAX, ..JournalConfig::default() };
            let creating = config.clone();
            cx.scoped_fs().run_io(move |_| {
                std::fs::write(&source, b"abcd")?;
                let mut journal = AppendJournal::new(creating, AuthKey::from_seed(42)).unwrap();
                journal.append(JournalRecord::Offer { transfer_id: "ordered".to_owned(), object_id: id,
                    manifest_root: root, total_size: 8, timestamp: 1, auth_tag: AuthenticationTag::zero() }).unwrap();
                let hash: [u8; 32] = Sha256::digest(b"abcd").into();
                journal.append(JournalRecord::ChunkVerified { transfer_id: "ordered".to_owned(), chunk_offset: 0,
                    chunk_size: 4, verified_hash: hash, timestamp: 2, auth_tag: AuthenticationTag::zero() }).unwrap();
                journal.append(chunk(2, 0, 4, 1)).unwrap();
                assert_eq!(journal.get_resume_summary("ordered").unwrap().durable_bytes, 4);
                journal.append(JournalRecord::ChunkReceived { transfer_id: "ordered".to_owned(), chunk_offset: 0,
                    chunk_size: 4, chunk_hash: hash, timestamp: 3, auth_tag: AuthenticationTag::zero() }).unwrap();
                journal.flush().unwrap();
                journal.compact().unwrap();
                Ok(())
            }).await.unwrap();
            let destination = directory.path().join("destination");
            let restored = ScopedSparseWriter::restore_from_storage(&cx, JournalRestoreRequest {
                journal_config: config, auth_key: AuthKey::from_seed(42), transfer_id: "ordered".to_owned(),
                source_path: path.clone(), final_path: destination.clone(),
                writer_config: SparseWriterConfig { enable_preallocation: false, ..SparseWriterConfig::default() },
                limits: JournalRestoreLimits { max_bytes: 8, max_chunks: 4, max_chunk_bytes: 4 },
            }).await.unwrap().unwrap();
            assert_eq!(restored.get_stats(&cx).await.unwrap().unwrap().total_bytes_written, 0);
            assert_eq!(restored.checked_receive_offset(&cx).await.unwrap().unwrap(), 0);
            let mut receive = restored.receive_exact(&cx, b"abcdefghNEXT".as_slice(), manifest,
                ScopedReceiveOptions { max_bytes: 8, max_chunks: 4, chunk_size: 4 }).unwrap();
            assert_eq!(receive.wait().await.unwrap().unwrap(), destination);
            assert_eq!(receive.take_source().unwrap(), b"NEXT");
            assert_eq!(cx.scoped_fs().read(destination).await.unwrap(), b"abcdefgh");
            assert_eq!(cx.scoped_fs().read(path).await.unwrap(), b"abcd");
        });
        let report = runtime.shutdown_drained(Duration::from_secs(5));
        assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
        assert_eq!(report.live_tasks, 0);
        assert_eq!(report.pending_spawns, 0);
        assert_eq!(report.pending_obligations, 0);
    }
}
