//! Bounded canonical payloads for the separate global-name computation.
//!
//! Owner identity is supplied by the authenticated transport, never by a field
//! inside a snapshot. Full catalogs retain sequence high-water marks; a missing
//! name withdraws that owner's previous claim.

use super::{GlobalNameError, GlobalNameSnapshotReceipt, GlobalNameTarget};
use crate::remote::NodeId;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Hard upper bound before decoding or allocating any payload fields.
pub const MAX_GLOBAL_NAME_MESSAGE_BYTES: usize = 1024 * 1024;
pub(super) const MAX_LABEL_BYTES: usize = 255;
pub(super) const MAX_NAMES: usize = 1024;
pub(super) const MAX_PEERS: usize = 64;

#[derive(Debug, Clone)]
pub(super) struct Snapshot {
    pub incarnation: u64,
    pub sequence: u64,
    pub names: BTreeMap<String, GlobalNameTarget>,
    pub digest: [u8; 32],
}

pub(super) fn label(value: &str) -> Result<(), GlobalNameError> {
    if value.is_empty() || value.len() > MAX_LABEL_BYTES || value.as_bytes().contains(&0) {
        return Err(GlobalNameError::Format);
    }
    Ok(())
}

fn put_label(bytes: &mut Vec<u8>, value: &str) -> Result<(), GlobalNameError> {
    label(value)?;
    bytes.extend_from_slice(&u16::try_from(value.len()).map_err(|_| GlobalNameError::Format)?.to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}

struct Reader<'a> { bytes: &'a [u8], cursor: usize }
impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8], magic: &[u8; 4]) -> Result<Self, GlobalNameError> {
        if bytes.len() > MAX_GLOBAL_NAME_MESSAGE_BYTES || !bytes.starts_with(magic) {
            return Err(GlobalNameError::Format);
        }
        Ok(Self { bytes, cursor: 4 })
    }
    fn take(&mut self, count: usize) -> Result<&'a [u8], GlobalNameError> {
        let end = self.cursor.checked_add(count).ok_or(GlobalNameError::Format)?;
        let part = self.bytes.get(self.cursor..end).ok_or(GlobalNameError::Format)?;
        self.cursor = end;
        Ok(part)
    }
    fn u64(&mut self) -> Result<u64, GlobalNameError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().map_err(|_| GlobalNameError::Format)?))
    }
    fn u16(&mut self) -> Result<u16, GlobalNameError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().map_err(|_| GlobalNameError::Format)?))
    }
    fn label(&mut self) -> Result<String, GlobalNameError> {
        let len = usize::from(self.u16()?);
        if len == 0 || len > MAX_LABEL_BYTES { return Err(GlobalNameError::Format); }
        let value = std::str::from_utf8(self.take(len)?).map_err(|_| GlobalNameError::Format)?;
        label(value)?;
        Ok(value.to_owned())
    }
    fn finish(self) -> Result<(), GlobalNameError> {
        if self.cursor == self.bytes.len() { Ok(()) } else { Err(GlobalNameError::Format) }
    }
}

pub(super) fn encode_snapshot(
    incarnation: u64, sequence: u64, names: &BTreeMap<String, GlobalNameTarget>,
) -> Result<Vec<u8>, GlobalNameError> {
    if incarnation == 0 || sequence == 0 || names.len() > MAX_NAMES { return Err(GlobalNameError::Format); }
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"GNS1");
    bytes.extend_from_slice(&incarnation.to_be_bytes());
    bytes.extend_from_slice(&sequence.to_be_bytes());
    bytes.extend_from_slice(&u16::try_from(names.len()).map_err(|_| GlobalNameError::Format)?.to_be_bytes());
    for (name, target) in names {
        if target.incarnation != incarnation || target.registration == 0 { return Err(GlobalNameError::Format); }
        put_label(&mut bytes, name)?;
        bytes.extend_from_slice(&target.registration.to_be_bytes());
        put_label(&mut bytes, &target.computation)?;
    }
    if bytes.len() > MAX_GLOBAL_NAME_MESSAGE_BYTES { return Err(GlobalNameError::Format); }
    Ok(bytes)
}

pub(super) fn decode_snapshot(
    owner: &NodeId, bytes: &[u8], limit: usize,
) -> Result<Snapshot, GlobalNameError> {
    let mut reader = Reader::new(bytes, b"GNS1")?;
    let incarnation = reader.u64()?;
    let sequence = reader.u64()?;
    let count = usize::from(reader.u16()?);
    if incarnation == 0 || sequence == 0 || count > limit || count > MAX_NAMES {
        return Err(GlobalNameError::Format);
    }
    let mut names = BTreeMap::new();
    let mut previous: Option<String> = None;
    for _ in 0..count {
        let name = reader.label()?;
        if previous.as_ref().is_some_and(|prior| prior >= &name) { return Err(GlobalNameError::Format); }
        let registration = reader.u64()?;
        if registration == 0 { return Err(GlobalNameError::Format); }
        let computation = reader.label()?;
        previous = Some(name.clone());
        names.insert(name, GlobalNameTarget { node: owner.clone(), incarnation, registration, computation });
    }
    reader.finish()?;
    Ok(Snapshot { incarnation, sequence, names, digest: Sha256::digest(bytes).into() })
}

pub(super) fn snapshot_receipt(receipt: &GlobalNameSnapshotReceipt) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(52);
    bytes.extend_from_slice(b"GNA1");
    bytes.extend_from_slice(&receipt.incarnation.to_be_bytes());
    bytes.extend_from_slice(&receipt.sequence.to_be_bytes());
    bytes.extend_from_slice(&receipt.digest);
    bytes
}

/// Bind an acknowledgement to the entire exact snapshot sent in this attempt.
/// This acknowledges in-memory admission, not lease drain or quorum acceptance.
pub fn verify_snapshot_receipt(bytes: &[u8], snapshot: &[u8]) -> Result<(), GlobalNameError> {
    if bytes.len() != 52 || !bytes.starts_with(b"GNA1") || snapshot.len() < 22
        || snapshot.len() > MAX_GLOBAL_NAME_MESSAGE_BYTES || !snapshot.starts_with(b"GNS1")
        || bytes[4..20] != snapshot[4..20]
    { return Err(GlobalNameError::Receipt); }
    let digest: [u8; 32] = Sha256::digest(snapshot).into();
    if bytes[20..] != digest { return Err(GlobalNameError::Receipt); }
    Ok(())
}

/// Encode an exact-incarnation query to the owner of a possibly stale view.
pub fn lookup_request(name: &str, incarnation: u64) -> Result<Vec<u8>, GlobalNameError> {
    if incarnation == 0 { return Err(GlobalNameError::Format); }
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"GNL1");
    bytes.extend_from_slice(&incarnation.to_be_bytes());
    put_label(&mut bytes, name)?;
    Ok(bytes)
}

pub(super) fn decode_lookup_request(bytes: &[u8]) -> Result<(u64, String), GlobalNameError> {
    let mut reader = Reader::new(bytes, b"GNL1")?;
    let incarnation = reader.u64()?;
    let name = reader.label()?;
    reader.finish()?;
    if incarnation == 0 { return Err(GlobalNameError::Format); }
    Ok((incarnation, name))
}

pub(super) fn lookup_reply(
    incarnation: u64, sequence: u64, name: &str, target: Option<&GlobalNameTarget>,
) -> Result<Vec<u8>, GlobalNameError> {
    if incarnation == 0 || sequence == 0 { return Err(GlobalNameError::Format); }
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"GNR1");
    bytes.extend_from_slice(&incarnation.to_be_bytes());
    bytes.extend_from_slice(&sequence.to_be_bytes());
    put_label(&mut bytes, name)?;
    if let Some(target) = target {
        if target.incarnation != incarnation || target.registration == 0 { return Err(GlobalNameError::Format); }
        bytes.push(1);
        bytes.extend_from_slice(&target.registration.to_be_bytes());
        put_label(&mut bytes, &target.computation)?;
    } else { bytes.push(0); }
    Ok(bytes)
}

/// Verify the requested name and destination incarnation in an owner reply.
/// The result describes that owner's observation at reply time. It neither
/// proves cluster-wide exclusivity nor reserves a subsequent invocation.
pub fn decode_lookup_reply(
    owner: &NodeId, incarnation: u64, name: &str, bytes: &[u8],
) -> Result<(u64, Option<GlobalNameTarget>), GlobalNameError> {
    label(name)?;
    let mut reader = Reader::new(bytes, b"GNR1")?;
    let actual_incarnation = reader.u64()?;
    let sequence = reader.u64()?;
    let actual_name = reader.label()?;
    if incarnation == 0 || actual_incarnation != incarnation || sequence == 0 || actual_name != name {
        return Err(GlobalNameError::Receipt);
    }
    let present = reader.take(1)?[0];
    let target = match present {
        0 => None,
        1 => {
            let registration = reader.u64()?;
            if registration == 0 { return Err(GlobalNameError::Format); }
            Some(GlobalNameTarget { node: owner.clone(), incarnation, registration, computation: reader.label()? })
        }
        _ => return Err(GlobalNameError::Format),
    };
    reader.finish()?;
    Ok((sequence, target))
}
