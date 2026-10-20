//! Full frames cannot hide ignored bytes inside or after an authenticated record.

use super::*;

fn key() -> AuthKey { AuthKey::from_seed(83) }

fn records() -> Vec<JournalRecord> {
    let transfer_id = "strict".to_owned();
    let timestamp = 7;
    let auth_tag = AuthenticationTag::zero();
    vec![
        JournalRecord::Offer { transfer_id: transfer_id.clone(),
            object_id: ObjectId::content(ContentId::from_bytes(b"data")),
            manifest_root: MerkleRoot::new([1; 32]), total_size: 4, timestamp, auth_tag },
        JournalRecord::Accept { transfer_id: transfer_id.clone(), peer_id: "peer".to_owned(), timestamp, auth_tag },
        JournalRecord::ChunkReceived { transfer_id: transfer_id.clone(), chunk_offset: 0,
            chunk_size: 4, chunk_hash: [7; 32], timestamp, auth_tag },
        JournalRecord::ChunkVerified { transfer_id: transfer_id.clone(), chunk_offset: 0,
            chunk_size: 4, verified_hash: [7; 32], timestamp, auth_tag },
        JournalRecord::ChunkWritten { transfer_id: transfer_id.clone(), chunk_offset: 0,
            chunk_size: 4, file_path: "evidence-only".to_owned(), timestamp, auth_tag },
        JournalRecord::RepairDecode { transfer_id: transfer_id.clone(), chunk_offset: 0,
            chunk_size: 4, source_chunks: vec![1, 2], timestamp, auth_tag },
        JournalRecord::CommitIntent { transfer_id: transfer_id.clone(),
            final_manifest_root: MerkleRoot::new([1; 32]), timestamp, auth_tag },
        JournalRecord::CommitComplete { transfer_id: transfer_id.clone(), final_path: "published".to_owned(),
            committed_size: 4, timestamp, auth_tag },
        JournalRecord::Cancellation { transfer_id: transfer_id.clone(), reason: "stop".to_owned(), timestamp, auth_tag },
        JournalRecord::Rollback { transfer_id: transfer_id.clone(), rollback_reason: "retry".to_owned(),
            checkpoint_sequence: 0, timestamp, auth_tag },
        JournalRecord::CompactionBoundary { generation: 1, compacted_up_to_sequence: 0, timestamp, auth_tag },
        JournalRecord::ProofDigest { transfer_id, proof_type: "diagnostic".to_owned(), digest: [3; 32], timestamp, auth_tag },
    ]
}

fn trailing(error: &JournalError) -> bool {
    matches!(error, JournalError::Deserialization(message) if message == TRAILING_JOURNAL_BYTES)
}

fn append_frame(output: &mut Vec<u8>, bytes: &[u8]) {
    storage::write_frame(output, bytes).unwrap();
}

// Preserve the original record's valid checksum and authentication tag, but
// enlarge the inner record length to cover extra bytes. Before the fix the
// decoder discarded them and validation re-encoded only the known prefix.
fn padded_entry(sequence: u64, record: JournalRecord, suffix: &[u8], inner: bool) -> Vec<u8> {
    let mut encoded = JournalEntry::new(sequence, record.with_signature(&key())).encode();
    encoded.extend_from_slice(suffix);
    if inner {
        let size = u32::try_from(encoded.len() - 16).unwrap();
        encoded[12..16].copy_from_slice(&size.to_le_bytes());
    }
    encoded
}

#[test]
fn every_record_consumes_exactly_its_authenticated_payload() {
    let hidden = records()[8].clone().with_signature(&key()).encode_payload();
    for record in records() {
        let signed = record.with_signature(&key());
        let bytes = signed.encode_payload();
        let decoded = JournalRecord::decode_payload(&bytes).unwrap();
        assert_eq!(decoded, signed);
        assert!(decoded.verify_signature(&key()));
        for cut in 0..bytes.len() {
            assert!(JournalRecord::decode_payload(&bytes[..cut]).is_err(),
                "{} prefix {cut}", signed.record_type());
        }
        for suffix in [b"\0".as_slice(), b"extra".as_slice(), hidden.as_slice()] {
            let mut padded = bytes.clone();
            padded.extend_from_slice(suffix);
            let error = JournalRecord::decode_payload(&padded).unwrap_err();
            assert!(trailing(&error), "{}: {error}", signed.record_type());
        }
    }
}

#[test]
fn valid_crc_and_signature_cannot_normalize_inner_or_outer_padding() {
    let hidden = JournalEntry::new(99, records()[8].clone().with_signature(&key())).encode();
    for record in records() {
        let valid = JournalEntry::new(11, record.clone().with_signature(&key()));
        let decoded = JournalEntry::decode(&valid.encode()).unwrap();
        assert!(decoded.validate_checksum());
        assert!(decoded.record.verify_signature(&key()));
        for inner in [false, true] {
            for suffix in [b"\0".as_slice(), hidden.as_slice()] {
                let padded = padded_entry(11, record.clone(), suffix, inner);
                // The prefix CRC and record tag are intentionally not damaged.
                assert_eq!(&padded[8..12], &valid.encode()[8..12]);
                assert!(trailing(&JournalEntry::decode(&padded).unwrap_err()));
            }
        }
    }
}

#[test]
fn padded_complete_tail_refuses_reopen_without_rotating_or_losing_evidence() {
    for record in records() {
        for inner in [false, true] {
            for followed in [false, true] {
                let directory = tempfile::tempdir().unwrap();
                let config = JournalConfig { base_dir: directory.path().to_owned(), ..JournalConfig::default() };
                let path = journal_file_path(directory.path(), 0);
                let mut bytes = Vec::new();
                append_frame(&mut bytes, &JournalEntry::new(0, records()[0].clone().with_signature(&key())).encode());
                append_frame(&mut bytes, &padded_entry(1, record.clone(), b"unexplained", inner));
                if followed {
                    append_frame(&mut bytes, &JournalEntry::new(2, records()[1].clone().with_signature(&key())).encode());
                }
                std::fs::write(&path, &bytes).unwrap();
                match AppendJournal::new(config, key()) {
                    Outcome::Err(error) => assert!(trailing(&error), "{error}"),
                    _ => panic!("complete padded frame must refuse, not recover a prefix"),
                }
                assert_eq!(std::fs::read(&path).unwrap(), bytes);
                assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
            }
        }
    }
    // Actual incomplete length prefixes retain the existing torn-tail policy.
    for prefix in 1..4 {
        let directory = tempfile::tempdir().unwrap();
        let config = JournalConfig { base_dir: directory.path().to_owned(), ..JournalConfig::default() };
        let path = journal_file_path(directory.path(), 0);
        let mut bytes = Vec::new();
        append_frame(&mut bytes, &JournalEntry::new(0, records()[0].clone().with_signature(&key())).encode());
        bytes.extend_from_slice(&100u32.to_le_bytes()[..prefix]);
        std::fs::write(&path, &bytes).unwrap();
        let reopened = AppendJournal::new(config, key()).unwrap();
        assert_eq!(reopened.get_stats().generation, 1);
        assert_eq!(reopened.get_transfer_entries("strict").unwrap().len(), 1);
        assert_eq!(std::fs::read(path).unwrap(), bytes);
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn bitmap_recovery_refuses_a_padded_terminal_before_any_bitmap_mutation() {
    use crate::atp::journal::recover_journal_and_bitmap;
    use crate::runtime::{RootDrainOutcome, RuntimeBuilder};
    use std::time::Duration;

    for workers in [1, 2] {
        let directory = tempfile::tempdir().unwrap();
        let journal_dir = directory.path().join("journal");
        std::fs::create_dir(&journal_dir).unwrap();
        let path = journal_file_path(&journal_dir, 0);
        let mut bytes = Vec::new();
        for (sequence, index) in [0, 2, 3, 4].into_iter().enumerate() {
            append_frame(&mut bytes, &JournalEntry::new(sequence as u64,
                records()[index].clone().with_signature(&key())).encode());
        }
        append_frame(&mut bytes, &padded_entry(4, records()[8].clone(), b"suffix", true));
        std::fs::write(&path, &bytes).unwrap();
        let bitmap_dir = directory.path().join("bitmaps");
        std::fs::create_dir(&bitmap_dir).unwrap();
        let sentinel = bitmap_dir.join("transfer_other.bitmap");
        std::fs::write(&sentinel, b"retain existing bitmap evidence").unwrap();
        let builder = if workers == 1 { RuntimeBuilder::current_thread() }
            else { RuntimeBuilder::new().worker_threads(2).with_sharded_state(true) };
        let runtime = builder.blocking_threads(1, 2).build().unwrap();
        runtime.block_on(async {
            assert!(recover_journal_and_bitmap(&Cx::current().unwrap(), &path, &bitmap_dir, &key()).await.is_err());
        });
        let drained = runtime.shutdown_drained(Duration::from_secs(5));
        assert_eq!(drained.outcome, RootDrainOutcome::Quiescent, "{drained:?}");
        assert_eq!(drained.live_tasks, 0);
        assert_eq!(drained.pending_spawns, 0);
        assert_eq!(drained.pending_obligations, 0);
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        assert_eq!(std::fs::read(sentinel).unwrap(), b"retain existing bitmap evidence");
        assert_eq!(std::fs::read_dir(bitmap_dir).unwrap().count(), 1);
        assert_eq!(std::fs::read_dir(journal_dir).unwrap().count(), 1);
    }
}
