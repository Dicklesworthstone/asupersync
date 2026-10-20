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
    Ok(receipts.entry(offset).or_insert_with(|| Receipt { size, ..Receipt::default() }))
}

pub(super) fn build(
    transfer_id: &str,
    entries: &[JournalEntry],
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
                let current = receipt(&mut receipts, offset, size, offered.map(|(_, _, size)| size))?;
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
