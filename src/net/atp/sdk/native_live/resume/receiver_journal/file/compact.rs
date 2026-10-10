//! Metadata-only WAL records backed by two bounded pending-epoch slots.
//!
//! A new slot is synchronized before its intent record. Alternating by epoch
//! retains the preceding slot while the next record is prepared. Completed
//! historical epochs come from their original data offsets during replay.

use super::{
    EPOCH_HEADER_BYTES, MAX_RECEIVER_CHECKPOINT_BYTES, ReceiverCheckpoint, identity, invalid,
    private_parent,
};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub(super) const HEADER: usize = 128;
pub(super) const MAGIC: &[u8; 8] = b"ATPRFL02";
pub(super) const MAX_SNAPSHOTS: u32 = 1_048_576;
pub(super) const MAX_CHECKPOINT: usize = super::super::FIXED + EPOCH_HEADER_BYTES + 64;
const SLOT_HEADER: usize = 48;
const MAX_PENDING: usize =
    MAX_RECEIVER_CHECKPOINT_BYTES - super::super::FIXED - 32;
const SLOT_BYTES: usize = SLOT_HEADER + MAX_PENDING;
pub(super) const INTENT_BYTES: usize = 2 * SLOT_BYTES;
const SLOT_MAGIC: &[u8; 8] = b"ATPRIN02";

pub(super) fn hash(previous: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"asupersync.atp.receiver-file-journal.v2");
    hash.update(previous);
    hash.update(bytes);
    hash.finalize().into()
}

fn pending_hash(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"asupersync.atp.receiver-intent.v2");
    hash.update(bytes);
    hash.finalize().into()
}

pub(super) struct Intent {
    file: File,
    path: PathBuf,
    directory: File,
}

impl Intent {
    pub(super) fn open(path: &Path, create: bool) -> io::Result<Self> {
        let (path, directory) = private_parent(path)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(create)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)?;
        file.try_lock().map_err(io::Error::from)?;
        identity(&file, &path, &directory, true)?;
        if create {
            // Initialize once at the fixed size. Later writes never change it.
            let bytes = Zeroizing::new(vec![0; INTENT_BYTES]);
            file.write_all_at(&bytes, 0)?;
            file.sync_all()?;
            directory.sync_all()?;
        }
        let intent = Self {
            file,
            path,
            directory,
        };
        intent.verify()?;
        Ok(intent)
    }

    pub(super) fn verify(&self) -> io::Result<()> {
        identity(&self.file, &self.path, &self.directory, true)?;
        if self.file.metadata()?.len() != INTENT_BYTES as u64 {
            return Err(invalid());
        }
        Ok(())
    }

    pub(super) fn write_identity(&self, header: &mut [u8]) -> io::Result<()> {
        let file = self.file.metadata()?;
        let parent = self.directory.metadata()?;
        for (offset, value) in [
            (64, file.dev()),
            (72, file.ino()),
            (80, parent.dev()),
            (88, parent.ino()),
        ] {
            header[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
        }
        Ok(())
    }

    pub(super) fn matches_identity(&self, header: &[u8]) -> io::Result<bool> {
        // Device numbers can change on reboot, just as in the original profile.
        let inode = u64::from_be_bytes(header[72..80].try_into().expect("bounded inode"));
        let parent = u64::from_be_bytes(header[88..96].try_into().expect("bounded parent"));
        Ok(self.file.metadata()?.ino() == inode && self.directory.metadata()?.ino() == parent)
    }

    pub(super) fn stage(&self, checkpoint: &ReceiverCheckpoint) -> io::Result<()> {
        let pending = &checkpoint.pending;
        if !(EPOCH_HEADER_BYTES + 1..=MAX_PENDING).contains(&pending.len()) {
            return Err(invalid());
        }
        self.verify()?;
        let mut slot = Zeroizing::new(vec![0; SLOT_BYTES]);
        slot[..8].copy_from_slice(SLOT_MAGIC);
        slot[8..12].copy_from_slice(&(pending.len() as u32).to_be_bytes());
        slot[16..SLOT_HEADER].copy_from_slice(&pending_hash(pending));
        slot[SLOT_HEADER..SLOT_HEADER + pending.len()].copy_from_slice(pending);
        let offset = (checkpoint.prefix.epochs % 2) * SLOT_BYTES as u64;
        self.file.write_all_at(&slot, offset)?;
        self.file.sync_all()?;
        self.directory.sync_all()?;
        self.verify()
    }

    pub(super) fn slots(&self) -> io::Result<[Zeroizing<Vec<u8>>; 2]> {
        self.verify()?;
        let mut slots = [
            Zeroizing::new(vec![0; SLOT_BYTES]),
            Zeroizing::new(vec![0; SLOT_BYTES]),
        ];
        for (index, slot) in slots.iter_mut().enumerate() {
            self.file.read_exact_at(slot, (index * SLOT_BYTES) as u64)?;
        }
        Ok(slots)
    }
}

/// Preserve the original full canonical checksum, replacing only payload bytes
/// with a separate commitment. No existing checkpoint or wire codec changes.
pub(super) fn encode(full: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
    let fixed = super::super::FIXED;
    if !(fixed + 32..=MAX_RECEIVER_CHECKPOINT_BYTES).contains(&full.len()) {
        return Err(invalid());
    }
    let length = u32::from_be_bytes(full[281..285].try_into().expect("bounded length")) as usize;
    if full.len() != fixed + length + 32 {
        return Err(invalid());
    }
    if length == 0 {
        return Ok(Zeroizing::new(full.to_vec()));
    }
    if !(EPOCH_HEADER_BYTES + 1..=MAX_PENDING).contains(&length) {
        return Err(invalid());
    }
    let mut record = Zeroizing::new(Vec::with_capacity(MAX_CHECKPOINT));
    record.extend_from_slice(&full[..fixed + EPOCH_HEADER_BYTES]);
    record.extend_from_slice(&pending_hash(&full[fixed..fixed + length]));
    record.extend_from_slice(&full[full.len() - 32..]);
    Ok(record)
}

/// Rehydrate at most one epoch. The caller streams records and keeps only the
/// current checkpoint plus these two fixed slots, irrespective of transfer size.
pub(super) fn decode(
    record: &[u8],
    data: &File,
    slots: &[Zeroizing<Vec<u8>>; 2],
) -> io::Result<ReceiverCheckpoint> {
    let fixed = super::super::FIXED;
    if !(fixed + 32..=MAX_CHECKPOINT).contains(&record.len()) {
        return Err(invalid());
    }
    let length =
        u32::from_be_bytes(record[281..285].try_into().expect("bounded length")) as usize;
    if length == 0 {
        return ReceiverCheckpoint::from_canonical_bytes(record);
    }
    if !(EPOCH_HEADER_BYTES + 1..=MAX_PENDING).contains(&length)
        || record.len() != MAX_CHECKPOINT
    {
        return Err(invalid());
    }
    let payload_length = length - EPOCH_HEADER_BYTES;
    let offset = u64::from_be_bytes(record[168..176].try_into().expect("bounded offset"));
    let epoch = u64::from_be_bytes(record[160..168].try_into().expect("bounded epoch"));
    let end = offset.checked_add(payload_length as u64).ok_or_else(invalid)?;
    let expected: [u8; 32] = record[fixed + EPOCH_HEADER_BYTES..fixed + EPOCH_HEADER_BYTES + 32]
        .try_into()
        .expect("bounded commitment");
    let mut full = Zeroizing::new(vec![0; fixed + length + 32]);
    full[..fixed + EPOCH_HEADER_BYTES].copy_from_slice(&record[..fixed + EPOCH_HEADER_BYTES]);

    let slot = &slots[(epoch % 2) as usize];
    let slot_length =
        u32::from_be_bytes(slot[8..12].try_into().expect("bounded slot length")) as usize;
    let matching_slot = &slot[..8] == SLOT_MAGIC
        && slot[12..16] == [0; 4]
        && slot_length == length
        && slot[16..SLOT_HEADER] == expected
        && slot[SLOT_HEADER..SLOT_HEADER + EPOCH_HEADER_BYTES]
            == record[fixed..fixed + EPOCH_HEADER_BYTES]
        // A power loss while reusing an obsolete slot can preserve its old
        // header sectors but tear its payload. Such a slot is not authoritative;
        // the completed historical epoch still has its exact durable data.
        && pending_hash(&slot[SLOT_HEADER..SLOT_HEADER + length]) == expected;
    if matching_slot {
        full[fixed..fixed + length]
            .copy_from_slice(&slot[SLOT_HEADER..SLOT_HEADER + length]);
    } else {
        // Only complete historical payloads can replace an obsolete intent
        // slot. Partial data never fabricates the absent pending suffix.
        if data.metadata()?.len() < end {
            return Err(invalid());
        }
        data.read_exact_at(
            &mut full[fixed + EPOCH_HEADER_BYTES..fixed + length],
            offset,
        )?;
    }
    if pending_hash(&full[fixed..fixed + length]) != expected {
        return Err(invalid());
    }
    full[fixed + length..].copy_from_slice(&record[record.len() - 32..]);
    ReceiverCheckpoint::from_canonical_bytes(&full)
}
