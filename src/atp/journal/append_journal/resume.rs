//! Ordered progress interpretation for the existing authenticated journal API.
//!
//! Authentication happens in `get_resume_summary` before this pure projection.
//! A set intersection cannot distinguish Verified -> Written from Written ->
//! Verified, or notice a later receive/repair invalidating the previous bytes.
//! Keep the legacy Verified -> Written profile (Received is optional), but only
//! credit a write observed after verification in the current payload attempt.
//! Terminal observations are monotone; a later record cannot erase a decision.
//!
//! This does not authenticate sequence headers, detect missing leading/trailing
//! history, verify physical payload, or grant filesystem authority. Offerless
//! legacy receipts and standalone terminal reports remain diagnostic inputs;
//! actual writer restoration still requires an independently matched Offer.

use super::{
    AppendJournal, JournalEntry, JournalError, JournalRecord, MerkleRoot, ObjectId,
    ResumeChunkKey, TransferResumeStatus, TransferResumeSummary,
};
use std::collections::{BTreeMap, HashMap, HashSet};
use crate::types::Outcome;

impl AppendJournal {
    /// Reconstruct authenticated progress with explicit per-transfer work limits.
    ///
    /// Inspect the immutable transfer index by reference: unlike raw record
    /// inspection, this does not clone the complete history or its path strings.
    /// Before signature verification, require at most `max_records` indexed
    /// records and `max_history_bytes` encoded bytes (20 framing bytes plus each
    /// entry's payload size). Authentication still covers EVERY admitted record.
    /// During the same ordered projection used by `get_resume_summary`, admit at
    /// most `max_ranges` distinct payload ranges, including transient/invalidated
    /// ranges. Repeated attempts at one exact range do not consume another slot.
    ///
    /// A limit returns `JournalError::ReadFailure`, never partial progress or an
    /// unauthenticated terminal state. Storage uncertainty is checked first.
    /// Zero budgets allow empty history; zero ranges also allow offer/terminal
    /// histories without payload records. No journal or payload is modified.
    ///
    /// These are projection limits, NOT limits on disk reopening, already-owned
    /// journal memory, allocator overhead, or later appends. Physical snapshot
    /// copies have already been deduplicated in this index. The caller's transfer
    /// ID and returned summary also consume memory. This synchronous query may
    /// still do substantial CPU work; async callers should offload it through
    /// their existing region-owned filesystem job. Legacy APIs are unchanged.
    pub fn get_resume_summary_with_limits(
        &self,
        transfer_id: &str,
        max_records: usize,
        max_ranges: usize,
        max_history_bytes: u64,
    ) -> Outcome<TransferResumeSummary, JournalError> {
        if let Err(error) = self.require_storage_ready() {
            return Outcome::Err(error);
        }
        let entries = self.transfer_entries.get(transfer_id).map_or(&[][..], Vec::as_slice);
        if entries.len() > max_records {
            return Outcome::Err(projection_limit("records"));
        }
        let mut remaining = max_history_bytes;
        for entry in entries {
            let encoded_bytes = 20 + u64::from(entry.entry_size);
            let Some(next) = remaining.checked_sub(encoded_bytes) else {
                return Outcome::Err(projection_limit("history bytes"));
            };
            remaining = next;
        }
        if entries.iter().any(|entry| !entry.record.verify_signature(&self.auth_key)) {
            return Outcome::Err(invalid("resume journal record authentication failed"));
        }
        match build_with_range_limit(transfer_id, entries, max_ranges) {
            Ok(summary) => Outcome::Ok(summary),
            Err(error) => Outcome::Err(error),
        }
    }
}

fn projection_limit(dimension: &str) -> JournalError {
    JournalError::ReadFailure(format!("resume projection limit exceeded: {dimension}"))
}

#[derive(Default)]
struct Receipt {
    size: u64,
    received: Option<[u8; 32]>,
    // Retain the immutable expectation even if another payload attempt begins.
    verified_hash: Option<[u8; 32]>,
    verified: bool,
    written: bool,
}

#[derive(Clone, Copy)]
enum Terminal<'a> {
    Intent(&'a MerkleRoot),
    Complete(&'a str, u64),
    Cancelled(&'a str),
    RolledBack(&'a str, u64),
}

fn invalid(message: &str) -> JournalError {
    JournalError::Deserialization(message.to_owned())
}

// The map tracks recorded ranges, never the size of the logical sparse object.
// Reject ambiguous/rechunked geometry rather than credit an overlapping old
// write to a differently sized new receive. No payload or path strings are copied.
fn receipt(
    receipts: &mut BTreeMap<u64, Receipt>,
    offset: u64,
    size: u64,
    total: Option<u64>,
    max_ranges: usize,
) -> Result<&mut Receipt, JournalError> {
    let end = offset.checked_add(size)
        .filter(|end| size != 0 && total.is_none_or(|total| *end <= total))
        .ok_or_else(|| invalid("resume chunk has zero size, overflow, or exceeds offered transfer size"))?;
    if let Some((previous, entry)) = receipts.range(..offset).next_back() {
        if previous.checked_add(entry.size).is_none_or(|end| end > offset) {
            return Err(invalid("resume chunks overlap"));
        }
    }
    if let Some((next, entry)) = receipts.range(offset..).next() {
        if *next == offset {
            if entry.size != size {
                return Err(invalid("resume chunk size conflict at an existing offset"));
            }
        } else if *next < end {
            return Err(invalid("resume chunks overlap"));
        }
    }
    if receipts.len() >= max_ranges && !receipts.contains_key(&offset) {
        return Err(projection_limit("ranges"));
    }
    Ok(receipts.entry(offset).or_insert_with(|| Receipt { size, ..Receipt::default() }))
}

pub(super) fn build(
    transfer_id: &str,
    entries: &[JournalEntry],
) -> Result<TransferResumeSummary, JournalError> {
    build_with_range_limit(transfer_id, entries, usize::MAX)
}

fn build_with_range_limit(
    transfer_id: &str,
    entries: &[JournalEntry],
    max_ranges: usize,
) -> Result<TransferResumeSummary, JournalError> {
    let mut offered: Option<(&ObjectId, &MerkleRoot, u64)> = None;
    let mut terminal: Option<Terminal<'_>> = None;
    let mut last_sequence = None;
    let mut receipts = BTreeMap::<u64, Receipt>::new();
    let mut largest_end = 0;

    for entry in entries {
        // Transfer sequences may have gaps because other transfers interleave.
        // The disk reader, not this per-transfer projection, checks global gaps.
        if last_sequence.is_some_and(|previous| previous >= entry.sequence) {
            return Err(invalid("resume transfer records are not strictly ordered"));
        }
        last_sequence = Some(entry.sequence);
        if entry.record.transfer_id().is_some_and(|id| id != transfer_id) {
            return Err(invalid("resume transfer record identity mismatch"));
        }
        if matches!(&entry.record, JournalRecord::ProofDigest { .. } | JournalRecord::CompactionBoundary { .. }) {
            continue;
        }

        match &entry.record {
            JournalRecord::Offer { object_id, manifest_root, total_size, .. } => {
                if terminal.is_some() {
                    return Err(invalid("resume offer follows a terminal decision"));
                }
                if let Some((id, root, size)) = offered {
                    if size != *total_size {
                        return Err(invalid("resume offer total_size conflict"));
                    }
                    if id != object_id || root != manifest_root {
                        return Err(invalid("resume offer object identity or manifest root conflict"));
                    }
                }
                if largest_end > *total_size {
                    return Err(invalid("resume chunk exceeds offered transfer size"));
                }
                offered = Some((object_id, manifest_root, *total_size));
            }
            JournalRecord::CommitIntent { final_manifest_root, .. } => {
                if offered.is_some_and(|(_, root, _)| root != final_manifest_root) {
                    return Err(invalid("resume commit intent differs from offered manifest root"));
                }
                match terminal {
                    None => {}
                    Some(Terminal::Intent(root)) if root == final_manifest_root => {}
                    _ => return Err(invalid("resume commit intent conflicts with an earlier terminal decision")),
                }
                terminal = Some(Terminal::Intent(final_manifest_root));
            }
            JournalRecord::CommitComplete { final_path, committed_size, .. } => {
                if offered.is_some_and(|(_, _, size)| size != *committed_size)
                    || largest_end > *committed_size
                {
                    return Err(invalid("resume completion size conflicts with recorded payload"));
                }
                match terminal {
                    // A standalone legacy completion is still non-resumable.
                    // It is NOT proof that an intent or publisher was observed.
                    None | Some(Terminal::Intent(_)) => {}
                    Some(Terminal::Complete(path, size))
                        if path == final_path.as_str() && size == *committed_size => {}
                    _ => return Err(invalid("resume completion conflicts with an earlier terminal decision")),
                }
                terminal = Some(Terminal::Complete(final_path, *committed_size));
            }
            JournalRecord::Cancellation { reason, .. } => {
                match terminal {
                    None => {}
                    Some(Terminal::Cancelled(previous)) if previous == reason.as_str() => {}
                    _ => return Err(invalid("resume cancellation conflicts with an earlier terminal decision")),
                }
                terminal = Some(Terminal::Cancelled(reason));
            }
            JournalRecord::Rollback { rollback_reason, checkpoint_sequence, .. } => {
                match terminal {
                    None => {}
                    Some(Terminal::RolledBack(reason, sequence))
                        if reason == rollback_reason.as_str() && sequence == *checkpoint_sequence => {}
                    _ => return Err(invalid("resume rollback conflicts with an earlier terminal decision")),
                }
                terminal = Some(Terminal::RolledBack(rollback_reason, *checkpoint_sequence));
            }
            record => {
                if terminal.is_some() {
                    return Err(invalid("resume payload or acceptance follows a terminal decision"));
                }
                let (offset, size) = match record {
                    JournalRecord::ChunkReceived { chunk_offset, chunk_size, .. }
                    | JournalRecord::ChunkVerified { chunk_offset, chunk_size, .. }
                    | JournalRecord::ChunkWritten { chunk_offset, chunk_size, .. }
                    | JournalRecord::RepairDecode { chunk_offset, chunk_size, .. } => (*chunk_offset, *chunk_size),
                    JournalRecord::Accept { .. } => continue,
                    _ => return Err(invalid("unsupported resume transition")),
                };
                let current = receipt(&mut receipts, offset, size, offered.map(|(_, _, size)| size), max_ranges)?;
                largest_end = largest_end.max(offset + size); // Checked by receipt.
                match record {
                    JournalRecord::ChunkReceived { chunk_hash, .. } => {
                        if current.verified_hash.is_some_and(|hash| hash != *chunk_hash) {
                            return Err(invalid("resume received hash conflicts with previous verification"));
                        }
                        current.received = Some(*chunk_hash);
                        current.verified = false;
                        current.written = false;
                    }
                    JournalRecord::RepairDecode { .. } => {
                        current.received = None;
                        current.verified = false;
                        current.written = false;
                    }
                    JournalRecord::ChunkVerified { verified_hash, .. } => {
                        if current.verified_hash.is_some_and(|hash| hash != *verified_hash) {
                            return Err(invalid("resume chunk verified hash conflict"));
                        }
                        if current.received.is_some_and(|hash| hash != *verified_hash) {
                            return Err(invalid("resume verified hash differs from received payload"));
                        }
                        current.verified_hash = Some(*verified_hash);
                        current.verified = true;
                        // Identical re-verification alone does not undo a write;
                        // Received/RepairDecode already clear its prior credit.
                    }
                    JournalRecord::ChunkWritten { .. } => {
                        // An earlier write cannot be retrospectively validated by
                        // a later Verified. Another Written must follow it.
                        current.written = current.verified;
                    }
                    _ => unreachable!("receipt variant was selected above"),
                }
            }
        }
    }

    let total_size = offered.map(|(_, _, size)| size);
    let status = match terminal {
        Some(Terminal::Intent(_)) => TransferResumeStatus::CommitIntentPending,
        Some(Terminal::Complete(path, size)) => TransferResumeStatus::Committed {
            final_path: path.to_owned(), committed_size: size,
        },
        Some(Terminal::Cancelled(reason)) => TransferResumeStatus::Cancelled { reason: reason.to_owned() },
        Some(Terminal::RolledBack(reason, sequence)) => TransferResumeStatus::RolledBack {
            reason: reason.to_owned(), checkpoint_sequence: sequence,
        },
        None if entries.is_empty() => TransferResumeStatus::Unknown,
        None => TransferResumeStatus::Resumable,
    };
    let (durable_chunks, durable_bytes, contiguous_prefix_bytes) = if matches!(status, TransferResumeStatus::Resumable) {
        let mut verified = HashMap::new();
        let mut written = HashSet::new();
        for (offset, receipt) in receipts {
            if receipt.verified && receipt.written {
                let key = ResumeChunkKey { chunk_offset: offset, chunk_size: receipt.size };
                if let Some(hash) = receipt.verified_hash {
                    verified.insert(key, hash);
                    written.insert(key);
                }
            }
        }
        AppendJournal::durable_resume_chunks(&verified, &written, total_size)?
    } else {
        (Vec::new(), 0, 0)
    };
    Ok(TransferResumeSummary {
        transfer_id: transfer_id.to_owned(), status, total_size, durable_chunks,
        durable_bytes, contiguous_prefix_bytes, last_sequence,
    })
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod bounded_tests {
    use super::*;
    use crate::atp::journal::JournalConfig;
    use crate::atp::object::ContentId;
    use crate::security::{AuthKey, AuthenticationTag};

    fn key() -> AuthKey { AuthKey::from_seed(59) }

    fn journal(path: &std::path::Path) -> AppendJournal {
        AppendJournal::new(JournalConfig {
            base_dir: path.to_owned(), force_sync: false,
            max_journal_size: u64::MAX, ..JournalConfig::default()
        }, key()).unwrap()
    }

    fn offer() -> JournalRecord {
        JournalRecord::Offer {
            transfer_id: "bounded".to_owned(),
            object_id: ObjectId::content(ContentId::from_bytes(b"abcdefgh")),
            manifest_root: MerkleRoot::new([2; 32]), total_size: 8,
            timestamp: 1, auth_tag: AuthenticationTag::zero(),
        }
    }

    fn record(kind: u8, offset: u64) -> JournalRecord {
        let transfer_id = "bounded".to_owned();
        let timestamp = 2;
        let auth_tag = AuthenticationTag::zero();
        match kind {
            0 => JournalRecord::ChunkReceived { transfer_id, chunk_offset: offset, chunk_size: 4,
                chunk_hash: [7; 32], timestamp, auth_tag },
            1 => JournalRecord::ChunkVerified { transfer_id, chunk_offset: offset, chunk_size: 4,
                verified_hash: [7; 32], timestamp, auth_tag },
            2 => JournalRecord::ChunkWritten { transfer_id, chunk_offset: offset, chunk_size: 4,
                file_path: "not-opened".to_owned(), timestamp, auth_tag },
            _ => unreachable!(),
        }
    }

    fn history_bytes(journal: &AppendJournal) -> u64 {
        journal.get_transfer_entries("bounded").unwrap().iter()
            .map(|entry| 4 + entry.encode().len() as u64).sum()
    }

    fn limited(journal: &AppendJournal, records: usize, ranges: usize, bytes: u64, dimension: &str) {
        assert!(matches!(journal.get_resume_summary_with_limits("bounded", records, ranges, bytes),
            Outcome::Err(JournalError::ReadFailure(message))
                if message == format!("resume projection limit exceeded: {dimension}")));
    }

    #[test]
    fn exact_projection_limits_match_legacy_and_one_less_returns_no_summary() {
        let root = tempfile::tempdir().unwrap();
        let mut journal = journal(root.path());
        for record in [offer(), record(0, 0), record(1, 0), record(2, 0)] {
            journal.append(record).unwrap();
        }
        let bytes = history_bytes(&journal);
        let expected = journal.get_resume_summary("bounded").unwrap();
        assert_eq!(journal.get_resume_summary_with_limits("bounded", 4, 1, bytes).unwrap(), expected);
        let before = journal.get_stats().sequence;
        limited(&journal, 3, 1, bytes, "records");
        limited(&journal, 4, 0, bytes, "ranges");
        limited(&journal, 4, 1, bytes - 1, "history bytes");
        assert_eq!(journal.get_stats().sequence, before);
        assert_eq!(journal.get_resume_summary("bounded").unwrap(), expected);
        assert_eq!(journal.get_resume_summary_with_limits("absent", 0, 0, 0).unwrap().status,
            TransferResumeStatus::Unknown);
    }

    #[test]
    fn transient_ranges_count_but_repeated_attempts_do_not_consume_new_slots() {
        let root = tempfile::tempdir().unwrap();
        let mut journal = journal(root.path());
        journal.append(offer()).unwrap();
        for _ in 0..4 {
            for record in [record(0, 0), record(1, 0), record(2, 0)] {
                journal.append(record).unwrap();
            }
            let summary = journal.get_resume_summary_with_limits("bounded", 64, 1, 16384).unwrap();
            assert_eq!(summary.durable_bytes, 4);
            assert_eq!(summary.durable_chunks.len(), 1);
        }
        journal.append(record(0, 4)).unwrap();
        limited(&journal, 64, 1, 16384, "ranges");
        let summary = journal.get_resume_summary_with_limits("bounded", 64, 2, 16384).unwrap();
        assert_eq!(summary.durable_bytes, 4);
        assert_eq!(summary.contiguous_prefix_bytes, 4);
        journal.append(record(0, 0)).unwrap();
        let summary = journal.get_resume_summary_with_limits("bounded", 64, 2, 16384).unwrap();
        assert_eq!(summary.durable_bytes, 0);
        limited(&journal, 64, 1, 16384, "ranges");
    }

    #[test]
    fn admitted_history_still_requires_authentication_and_storage_readiness() {
        let root = tempfile::tempdir().unwrap();
        let mut journal = journal(root.path());
        journal.append(offer()).unwrap();
        journal.append(JournalRecord::Cancellation {
            transfer_id: "bounded".to_owned(), reason: "stopped".to_owned(),
            timestamp: 3, auth_tag: AuthenticationTag::zero(),
        }).unwrap();
        let bytes = history_bytes(&journal);
        assert!(matches!(journal.get_resume_summary_with_limits("bounded", 2, 0, bytes).unwrap().status,
            TransferResumeStatus::Cancelled { reason } if reason == "stopped"));
        limited(&journal, 1, 0, bytes, "records");
        // Fault only the key supplied to the query, retaining the actual signed
        // records. Budget admission is not authentication and returns no state.
        journal.auth_key = AuthKey::from_seed(60);
        limited(&journal, 0, 0, 0, "records");
        assert!(matches!(journal.get_resume_summary_with_limits("bounded", 2, 0, bytes),
            Outcome::Err(JournalError::Deserialization(message))
                if message == "resume journal record authentication failed"));
        journal.auth_key = key();
        // Exercise the same existing uncertain-storage gate as the legacy API.
        journal.storage_failed = true;
        assert!(matches!(journal.get_resume_summary_with_limits("bounded", 0, 0, 0),
            Outcome::Err(JournalError::WriteFailure(_))));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn bounded_projection_composes_with_native_physical_restore_and_suffix_receive() {
        use crate::atp::journal::{CommitPolicy, FsyncPolicy, JournalRestoreLimits, ScopedReceiveOptions, SparseWriterConfig};
        use crate::atp::journal::sparse_writer::ScopedSparseWriter;
        use crate::atp::manifest::Manifest;
        use crate::atp::object::{MetadataPolicy, Object, ObjectGraph};
        use crate::cx::Cx;
        use crate::runtime::{RootDrainOutcome, RuntimeBuilder};
        use sha2::{Digest, Sha256};
        use std::sync::Arc;
        use std::time::Duration;

        for workers in [1, 2] {
            let root = tempfile::tempdir().unwrap();
            let builder = if workers == 1 { RuntimeBuilder::current_thread() }
                else { RuntimeBuilder::new().worker_threads(workers).with_sharded_state(true) };
            let runtime = builder.blocking_threads(1, 2).build().unwrap();
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let object = Object::file(b"abcdefgh".to_vec());
                let id = object.id.clone();
                let mut graph = ObjectGraph::new();
                graph.add_root(object).unwrap();
                let manifest = Arc::new(Manifest::from_graph(&graph, MetadataPolicy::portable()).unwrap());
                let manifest_root = manifest.merkle_root.clone();
                let base = root.path().join("journal");
                let owner = cx.scoped_fs().run_io(move |_| {
                    let mut journal = journal(&base);
                    let tag = AuthenticationTag::zero();
                    journal.append(JournalRecord::Offer {
                        transfer_id: "bounded".to_owned(), object_id: id,
                        manifest_root, total_size: 8, timestamp: 1, auth_tag: tag,
                    }).unwrap();
                    journal.append(JournalRecord::ChunkVerified {
                        transfer_id: "bounded".to_owned(), chunk_offset: 0, chunk_size: 4,
                        verified_hash: Sha256::digest(b"abcd").into(), timestamp: 2, auth_tag: tag,
                    }).unwrap();
                    journal.append(JournalRecord::ChunkWritten {
                        transfer_id: "bounded".to_owned(), chunk_offset: 0, chunk_size: 4,
                        file_path: "not-source-authority".to_owned(), timestamp: 3, auth_tag: tag,
                    }).unwrap();
                    journal.flush().unwrap();
                    limited(&journal, 2, 1, 4096, "records");
                    let summary = journal.get_resume_summary_with_limits("bounded", 3, 1, 4096).unwrap();
                    assert_eq!(summary.contiguous_prefix_bytes, 4);
                    Ok(Arc::new(journal))
                }).await.unwrap();
                let source_path = root.path().join("retained");
                cx.scoped_fs().write(source_path.clone(), b"abcd".to_vec()).await.unwrap();
                let source = cx.scoped_fs().run_io(move |_| std::fs::File::open(source_path)).await.unwrap();
                let destination = root.path().join("destination");
                let writer = ScopedSparseWriter::restore_from_journal(
                    &cx, owner, "bounded".to_owned(), source, destination.clone(),
                    SparseWriterConfig {
                        enable_preallocation: false, fsync_policy: FsyncPolicy::BeforeCommit,
                        commit_policy: CommitPolicy::AtomicRename, ..SparseWriterConfig::default()
                    }, JournalRestoreLimits { max_bytes: 8, max_chunks: 2, max_chunk_bytes: 4 },
                ).await.unwrap().unwrap();
                assert_eq!(writer.checked_receive_offset(&cx).await.unwrap().unwrap(), 4);
                let mut receiving = writer.resume_exact_at(
                    &cx, b"efghNEXT".as_slice(), manifest,
                    ScopedReceiveOptions { max_bytes: 8, max_chunks: 2, chunk_size: 4 }, 4,
                ).unwrap();
                assert_eq!(receiving.wait().await.unwrap().unwrap(), destination);
                assert_eq!(receiving.take_source().unwrap(), b"NEXT");
                assert_eq!(std::fs::read(destination).unwrap(), b"abcdefgh");
                assert_eq!(std::fs::read(root.path().join("retained")).unwrap(), b"abcd");
            });
            let report = runtime.shutdown_drained(Duration::from_secs(5));
            assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
            assert_eq!(report.live_tasks, 0);
            assert_eq!(report.pending_spawns, 0);
            assert_eq!(report.pending_obligations, 0);
        }
    }
}
