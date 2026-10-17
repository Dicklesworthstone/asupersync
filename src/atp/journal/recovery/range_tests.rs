//! Regression coverage for projecting journal intervals onto a fixed bitmap.

use super::*;
use crate::atp::manifest::MerkleRoot;
use crate::atp::object::{ContentId, ObjectId};
use crate::security::AuthenticationTag;

fn record(start: u64, size: u64, phase: u8) -> JournalRecord {
    let transfer_id = "ranges".to_owned();
    let auth_tag = AuthenticationTag::zero();
    let timestamp = u64::from(phase) + 2;
    match phase {
        0 => JournalRecord::ChunkReceived {
            transfer_id, chunk_offset: start, chunk_size: size,
            chunk_hash: [1; 32], timestamp, auth_tag,
        },
        1 => JournalRecord::ChunkVerified {
            transfer_id, chunk_offset: start, chunk_size: size,
            verified_hash: [1; 32], timestamp, auth_tag,
        },
        2 => JournalRecord::ChunkWritten {
            transfer_id, chunk_offset: start, chunk_size: size,
            file_path: "staging".to_owned(), timestamp, auth_tag,
        },
        _ => unreachable!(),
    }
}

fn process(context: &mut RecoveryContext, record: JournalRecord) -> Result<bool, RecoveryError> {
    let key = AuthKey::from_seed(91);
    context.process_record(&record.with_signature(&key), &key)
}

fn offer(total_size: u64) -> JournalRecord {
    JournalRecord::Offer {
        transfer_id: "ranges".to_owned(),
        object_id: ObjectId::content(ContentId::from_bytes(b"range-recovery-fixture")),
        manifest_root: MerkleRoot::new([3; 32]),
        total_size,
        timestamp: 1,
        auth_tag: AuthenticationTag::zero(),
    }
}

fn add(context: &mut RecoveryContext, start: u64, size: u64, phase: u8) {
    for current in 0..=phase {
        assert!(process(context, record(start, size, current)).unwrap());
    }
}

#[test]
fn a_short_nonterminal_receipt_never_credits_the_unwritten_rest_of_its_cell() {
    let mut context = RecoveryContext::new();
    process(&mut context, offer(8)).unwrap();
    add(&mut context, 0, 2, 2);
    add(&mut context, 4, 4, 2);
    let (bitmaps, stats) = context.finalize();
    let bitmap = &bitmaps["ranges"];
    assert_eq!(bitmap.chunk_size(), 4);
    assert_eq!(bitmap.get_chunk_state(0), None, "bytes 2..4 were never written");
    assert_eq!(bitmap.get_chunk_state(4), Some(ChunkState::Written));
    assert_eq!(stats.chunks_recovered, 1, "count actual projected cells, not input records");
    let decoded = ChunkBitmap::deserialize_from_bytes(&bitmap.serialize_to_bytes()).unwrap();
    assert_eq!(decoded.entry_count(), 1);
    assert_eq!(decoded.get_chunk_state(0), None);
}

#[test]
fn adjoining_variable_receipts_cover_cells_without_upgrading_their_weakest_bytes() {
    let mut context = RecoveryContext::new();
    process(&mut context, offer(10)).unwrap();
    add(&mut context, 8, 2, 1);
    add(&mut context, 0, 3, 0);
    add(&mut context, 3, 5, 2);
    let (bitmaps, stats) = context.finalize();
    let bitmap = &bitmaps["ranges"];
    assert_eq!(bitmap.chunk_size(), 5);
    assert_eq!(bitmap.entry_count(), 2);
    assert_eq!(bitmap.get_chunk_state(0), Some(ChunkState::Received));
    assert_eq!(bitmap.get_chunk_state(5), Some(ChunkState::Verified));
    assert_eq!(stats.chunks_recovered, 2);
    assert!(bitmap.get_chunk_entry(0).unwrap().chunk_hash.is_none());
    assert!(bitmap.get_chunk_entry(5).unwrap().chunk_hash.is_none());
    let decoded = ChunkBitmap::deserialize_from_bytes(&bitmap.serialize_to_bytes()).unwrap();
    assert_eq!(decoded.chunk_size(), 5);
    assert_eq!(decoded.get_chunk_state(5), Some(ChunkState::Verified));
}

#[test]
fn invalid_geometry_is_rejected_before_state_or_duplicate_tracking_changes() {
    let mut context = RecoveryContext::new();
    process(&mut context, offer(16)).unwrap();
    add(&mut context, 4, 4, 0);
    let before = context.seen_records.len();
    for (start, size, phase) in [(4, 2, 1), (2, 4, 0), (6, 4, 0), (0, 0, 0), (u64::MAX, 1, 0)] {
        for _ in 0..2 {
            assert!(matches!(process(&mut context, record(start, size, phase)),
                Err(RecoveryError::JournalCorrupted(_))));
        }
        assert_eq!(context.seen_records.len(), before);
        let transfer = &context.transfers["ranges"];
        assert_eq!(transfer.chunk_sizes.len(), 1);
        assert_eq!(transfer.chunk_sizes[&ChunkId::from_u64(4)], 4);
        assert_eq!(transfer.chunk_states[&ChunkId::from_u64(4)], ChunkState::Received);
    }
    // Adjacent ranges and the original range's legitimate next state still work.
    add(&mut context, 0, 4, 2);
    process(&mut context, record(4, 4, 1)).unwrap();
    process(&mut context, record(4, 4, 2)).unwrap();
    add(&mut context, 8, 4, 2);
    let (bitmaps, _) = context.finalize();
    assert_eq!(bitmaps["ranges"].entry_count(), 3);
    assert_eq!(bitmaps["ranges"].get_chunk_state(4), Some(ChunkState::Written));
}

#[test]
fn error_states_never_turn_into_available_projected_cells() {
    for a in ChunkState::all() {
        for b in ChunkState::all() {
            let mut context = RecoveryContext::new();
            let transfer = context.ensure_transfer("ranges");
            transfer.record_offer(8, 1);
            // Private state injection exercises every state, including error
            // states that do not have dedicated JournalRecord variants.
            for (start, size, state) in [(0, 2, *a), (2, 2, *b), (4, 4, ChunkState::Written)] {
                let id = ChunkId::from_u64(start);
                transfer.record_chunk_geometry(id, size, 1);
                transfer.chunk_states.insert(id, state);
            }
            let (bitmaps, _) = context.finalize();
            let projected = bitmaps["ranges"].get_chunk_state(0).unwrap();
            assert!(!projected.has_data() || (a.has_data() && b.has_data()));
            assert!(!projected.is_verified() || (a.is_verified() && b.is_verified()));
            assert!(projected != ChunkState::Committed || (*a == ChunkState::Committed && *b == ChunkState::Committed));
            assert_eq!(bitmaps["ranges"].get_chunk_state(4), Some(ChunkState::Written));
        }
    }
}

#[test]
fn coprime_lengths_and_huge_sparse_offsets_do_not_expand_per_byte() {
    let width = 1_u64 << 40;
    let mut context = RecoveryContext::new();
    process(&mut context, offer(2 * width - 1)).unwrap();
    add(&mut context, 0, width - 1, 2);
    add(&mut context, width - 1, width, 2);
    let (bitmaps, stats) = context.finalize();
    let bitmap = &bitmaps["ranges"];
    assert_eq!(bitmap.chunk_size(), width);
    assert_eq!(bitmap.entry_count(), 2);
    assert_eq!(stats.chunks_recovered, 2);
    assert_eq!(bitmap.get_chunk_state(width), Some(ChunkState::Written));

    let mut context = RecoveryContext::new();
    process(&mut context, offer(u64::MAX)).unwrap();
    add(&mut context, 0, 4, 2);
    add(&mut context, u64::MAX - 3, 3, 2);
    let (bitmaps, _) = context.finalize();
    let bitmap = &bitmaps["ranges"];
    assert_eq!(bitmap.entry_count(), 2);
    assert_eq!(bitmap.get_chunk_state(u64::MAX - 3), Some(ChunkState::Written));
    assert_eq!(bitmap.get_chunk_state(4), None);
    assert_eq!(ChunkBitmap::deserialize_from_bytes(&bitmap.serialize_to_bytes()).unwrap().entry_count(), 2);
}

#[test]
fn small_layouts_match_an_independent_per_byte_state_oracle() {
    for length in 0..=7_u32 {
        for encoded in 0..4_u32.pow(length) {
            let mut value = encoded;
            let bytes: Vec<_> = (0..length).map(|_| {
                let state = match value % 4 {
                    0 => None,
                    1 => Some(ChunkState::Received),
                    2 => Some(ChunkState::Verified),
                    _ => Some(ChunkState::Written),
                };
                value /= 4;
                state
            }).collect();
            for split_runs in [false, true] {
                let mut context = RecoveryContext::new();
                let transfer = context.ensure_transfer("ranges");
                transfer.record_offer(u64::from(length), 1);
                let mut start = 0;
                while start < bytes.len() {
                    let Some(state) = bytes[start] else { start += 1; continue; };
                    let mut end = start + 1;
                    while end < bytes.len() && bytes[end] == Some(state) { end += 1; }
                    if split_runs && end - start > 1 { end = start + (end - start) / 2; }
                    let id = ChunkId::from_u64(start as u64);
                    transfer.record_chunk_geometry(id, (end - start) as u64, 1);
                    transfer.chunk_states.insert(id, state);
                    start = end;
                }
                let bitmap = context.transfers.remove("ranges").unwrap().into_bitmap("ranges".to_owned());
                let width = bitmap.chunk_size() as usize;
                let mut expected_count = 0;
                for start in (0..bytes.len()).step_by(width) {
                    let part = &bytes[start..(start + width).min(bytes.len())];
                    let expected = if part.contains(&None) { None }
                        else if part.contains(&Some(ChunkState::Received)) { Some(ChunkState::Received) }
                        else if part.contains(&Some(ChunkState::Verified)) { Some(ChunkState::Verified) }
                        else { Some(ChunkState::Written) };
                    assert_eq!(bitmap.get_chunk_state(start as u64), expected,
                        "length={length} encoded={encoded} split={split_runs} start={start}");
                    expected_count += usize::from(expected.is_some());
                }
                assert_eq!(bitmap.entry_count(), expected_count);
            }
        }
    }
}

#[test]
fn signed_disk_recovery_and_bitmap_reload_preserve_the_real_gap() {
    use crate::runtime::{RootDrainOutcome, RuntimeBuilder};
    use std::time::Duration;

    for workers in [1, 2] {
        let root = tempfile::tempdir().unwrap();
        let journal_dir = root.path().join("journal");
        let bitmap_dir = root.path().join("bitmaps");
        std::fs::create_dir(&bitmap_dir).unwrap();
        let key = AuthKey::from_seed(91);
        let mut journal = AppendJournal::new(JournalConfig {
            base_dir: journal_dir.clone(), ..JournalConfig::default()
        }, key.clone()).unwrap();
        journal.append(offer(8)).unwrap();
        for (start, size) in [(0, 2), (4, 4)] {
            for phase in 0..=2 { journal.append(record(start, size, phase)).unwrap(); }
        }
        journal.flush().unwrap();
        drop(journal);
        let builder = if workers == 1 { RuntimeBuilder::current_thread() }
            else { RuntimeBuilder::new().worker_threads(workers) };
        let runtime = builder.blocking_threads(1, 2).build().unwrap();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let (_, bitmaps) = recover_journal_and_bitmap(
                &cx, &journal_dir.join("journal_gen_000000.dat"), &bitmap_dir, &key,
            ).await.unwrap();
            assert_eq!(bitmaps["ranges"].get_chunk_state(0), None);
            assert_eq!(bitmaps["ranges"].get_chunk_state(4), Some(ChunkState::Written));
            let accepted: HashSet<_> = bitmaps.keys().cloned().collect();
            let loaded = load_recovered_or_create_bitmap(&bitmap_dir.join("transfer_ranges.bitmap"), &accepted)
                .await.unwrap().unwrap();
            assert_eq!(loaded.get_chunk_state(0), None);
            assert_eq!(loaded.entry_count(), 1);
        });
        let report = runtime.shutdown_drained(Duration::from_secs(5));
        assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
        assert_eq!(report.live_tasks, 0);
        assert_eq!(report.pending_obligations, 0);
    }
}
