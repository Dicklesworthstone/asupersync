//! Authenticated recovery metadata that can outlive the original publisher.
//!
//! A manifest binds an authenticated origin namespace, exact snapshot identity,
//! decoder parameters, replica labels and immutable batch digests. It contains
//! neither routes nor keys. Import requires a separately trusted expected identity
//! and origin: a valid signature is not permission to choose a different branch.
//! This is an author assertion, not a transferable proof of replica durability.

use super::recovery::{ReplicaFetch, SnapshotIdentity};
use super::SymbolBatchKey;
use crate::remote::NodeId;
use crate::security::{AuthKey, AuthenticationTag};
use crate::types::symbol::{ObjectId, ObjectParams};
use std::fmt;
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"ASUPMNF\0";
const HEADER: usize = 83;
const TAG: usize = 32;
const DOMAIN: &[u8] = b"asupersync.snapshot-recovery-manifest.v1";

/// Admission bounds for metadata, independent of network and RaptorQ limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManifestLimits {
    /// Complete encoding, including labels and authentication tag.
    pub max_encoded_bytes: usize,
    /// Maximum replica entries, including duplicates in constructor input.
    pub max_replicas: usize,
    /// Logical replica-vector storage plus all origin/replica label bytes.
    /// Excludes the struct, allocator overhead and caller-owned encoded input.
    pub max_decoded_bytes: usize,
}

/// Payload-free refusal; no partially authenticated manifest is returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ManifestError {
    /// Unsupported framing, invalid UTF-8, order, dimensions or replica threshold.
    #[error("invalid recovery manifest format or parameters")]
    Format,
    /// A complete field is missing.
    #[error("truncated recovery manifest")]
    Truncated,
    /// Trailing bytes are not part of one canonical manifest.
    #[error("trailing recovery manifest data")]
    TrailingData,
    /// The independently supplied author key did not authenticate the metadata.
    #[error("recovery manifest authentication failed")]
    Authentication,
    /// The manifest differs from the caller's exact expected identity or origin.
    #[error("recovery manifest authority does not match the expected checkpoint")]
    Identity,
    /// Explicit metadata admission exceeded.
    #[error("recovery manifest exceeds its {0} limit")]
    Limit(&'static str),
    /// Checked length/count arithmetic overflowed the target address space.
    #[error("recovery manifest size overflow")]
    Overflow,
    /// Bounded metadata allocation failed.
    #[error("recovery manifest allocation failed")]
    Allocation,
}

/// Authenticated, plaintext metadata bytes; owned storage zeroizes on drop.
/// No automatic persistence occurs. Copies and files remain caller-owned.
pub struct ManifestBytes(Zeroizing<Vec<u8>>);
impl AsRef<[u8]> for ManifestBytes {
    fn as_ref(&self) -> &[u8] { &self.0 }
}
impl fmt::Debug for ManifestBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ManifestBytes").field("encoded_bytes", &self.0.len()).finish_non_exhaustive()
    }
}

/// Complete, immutable recovery instructions for one locally authorized snapshot.
///
/// The origin is the service namespace, distinct from the snapshot's numeric
/// origin incarnation. Replica labels name preprovisioned routes, never addresses.
/// `minimum_replicas` is a sealed recovery floor, not the original write quorum.
/// A restored caller may require more responses, but must not weaken this floor.
/// Authentication neither encrypts metadata nor selects the latest checkpoint.
/// Retain the expected identity and author key independently of this encoding.
pub struct RecoveryManifest {
    peer: NodeId,
    params: ObjectParams,
    identity: SnapshotIdentity,
    minimum_replicas: usize,
    replicas: Vec<ReplicaFetch>,
}
impl fmt::Debug for RecoveryManifest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveryManifest").field("replicas", &self.replicas.len())
            .field("minimum_replicas", &self.minimum_replicas).finish_non_exhaustive()
    }
}

fn add(a: usize, b: usize) -> Result<usize, ManifestError> {
    a.checked_add(b).ok_or(ManifestError::Overflow)
}
fn valid_label(label: &str) -> bool { !label.is_empty() && label.len() <= 255 }
fn dimensions(params: ObjectParams) -> Result<(), ManifestError> {
    if params.object_size == 0 || params.symbol_size == 0 || params.symbols_per_block == 0
        || params.source_blocks == 0 || params.source_blocks > 256
    { return Err(ManifestError::Format); }
    let block_bytes = u64::from(params.symbol_size) * u64::from(params.symbols_per_block);
    if params.object_size.div_ceil(block_bytes) != u64::from(params.source_blocks) {
        return Err(ManifestError::Format);
    }
    Ok(())
}
fn counts(count: usize, minimum: usize, limits: ManifestLimits) -> Result<(), ManifestError> {
    if count > limits.max_replicas { return Err(ManifestError::Limit("replicas")); }
    if minimum == 0 || minimum > count { return Err(ManifestError::Format); }
    u32::try_from(count).map_err(|_| ManifestError::Overflow)?;
    Ok(())
}
fn storage(count: usize, labels: usize, limits: ManifestLimits) -> Result<(), ManifestError> {
    let vector = count.checked_mul(std::mem::size_of::<ReplicaFetch>()).ok_or(ManifestError::Overflow)?;
    if add(vector, labels)? > limits.max_decoded_bytes { return Err(ManifestError::Limit("decoded bytes")); }
    Ok(())
}

impl RecoveryManifest {
    /// Author a manifest from explicitly trusted metadata and confirmed replica keys.
    /// This constructor performs no I/O and does NOT verify that replicas stored
    /// anything. Its caller owns that assertion. Replica entries are sorted in
    /// place; duplicates and mixed objects refuse rather than silently coalescing.
    pub fn new(
        peer: NodeId, params: ObjectParams, identity: SnapshotIdentity,
        mut replicas: Vec<ReplicaFetch>, minimum_replicas: usize, limits: ManifestLimits,
    ) -> Result<Self, ManifestError> {
        counts(replicas.len(), minimum_replicas, limits)?;
        dimensions(params)?;
        if !valid_label(peer.as_str()) { return Err(ManifestError::Format); }
        let mut labels = peer.as_str().len();
        let mut encoded = add(HEADER + TAG, labels)?;
        for replica in &replicas {
            if !valid_label(&replica.replica_id) || replica.key.object_id != params.object_id {
                return Err(ManifestError::Format);
            }
            labels = add(labels, replica.replica_id.len())?;
            encoded = add(encoded, add(33, replica.replica_id.len())?)?;
        }
        storage(replicas.len(), labels, limits)?;
        if encoded > limits.max_encoded_bytes { return Err(ManifestError::Limit("encoded bytes")); }
        replicas.sort_unstable_by(|a, b| a.replica_id.cmp(&b.replica_id));
        if replicas.windows(2).any(|pair| pair[0].replica_id == pair[1].replica_id) {
            return Err(ManifestError::Format);
        }
        Ok(Self { peer, params, identity, minimum_replicas, replicas })
    }

    /// Certificate-bound service origin required during recovery.
    pub fn peer_node(&self) -> &NodeId { &self.peer }
    /// Exact decoder parameters; they do not grant a decoder memory budget.
    pub const fn params(&self) -> ObjectParams { self.params }
    /// Exact snapshot branch and generation, not a peer-selected lower bound.
    pub const fn identity(&self) -> SnapshotIdentity { self.identity }
    /// Minimum distinct successful responses authorized by the manifest author.
    pub const fn minimum_replicas(&self) -> usize { self.minimum_replicas }
    /// Unique replica labels and batch keys in canonical label order.
    pub fn replicas(&self) -> &[ReplicaFetch] { &self.replicas }

    /// Authenticate the complete V1 encoding with an explicitly supplied author key.
    /// No keys or transport addresses are serialized. All integers are little-endian.
    /// Header: magic[8], version:u32, region:u64 (generation high, slot low),
    /// origin/epoch/sequence:u64 each, object:u128, object-size:u64, symbol-size/
    /// source-blocks/symbols-per-block:u16 each, minimum/count:u32, origin-len:u8,
    /// origin UTF-8; then replica-len:u8, replica UTF-8, digest[32] for each entry;
    /// finally an AuthenticationTag over the domain-framed complete preceding bytes.
    pub fn to_canonical_bytes(&self, key: &AuthKey, max_bytes: usize) -> Result<ManifestBytes, ManifestError> {
        let mut length = add(HEADER + TAG, self.peer.as_str().len())?;
        for replica in &self.replicas { length = add(length, add(33, replica.replica_id.len())?)?; }
        if length > max_bytes { return Err(ManifestError::Limit("encoded bytes")); }
        let mut out = Zeroizing::new(Vec::new());
        out.try_reserve_exact(length).map_err(|_| ManifestError::Allocation)?;
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&1_u32.to_le_bytes());
        out.extend_from_slice(&self.identity.region_id.as_u64().to_le_bytes());
        for value in [self.identity.origin_id, self.identity.epoch, self.identity.sequence] {
            out.extend_from_slice(&value.to_le_bytes());
        }
        out.extend_from_slice(&self.params.object_id.as_u128().to_le_bytes());
        out.extend_from_slice(&self.params.object_size.to_le_bytes());
        for value in [self.params.symbol_size, self.params.source_blocks, self.params.symbols_per_block] {
            out.extend_from_slice(&value.to_le_bytes());
        }
        out.extend_from_slice(&(self.minimum_replicas as u32).to_le_bytes());
        out.extend_from_slice(&(self.replicas.len() as u32).to_le_bytes());
        out.push(self.peer.as_str().len() as u8);
        out.extend_from_slice(self.peer.as_str().as_bytes());
        for replica in &self.replicas {
            out.push(replica.replica_id.len() as u8);
            out.extend_from_slice(replica.replica_id.as_bytes());
            out.extend_from_slice(&replica.key.digest);
        }
        let tag = AuthenticationTag::compute_for_domain_payload(key, DOMAIN, &out);
        out.extend_from_slice(tag.as_bytes());
        debug_assert_eq!(out.len(), length);
        Ok(ManifestBytes(out))
    }

    /// Authenticate, validate and admit the ENTIRE manifest before allocating labels.
    /// The expected identity and service origin are independent caller authority.
    /// No untrusted RegionId is installed in the runtime, no routes are created,
    /// and no network request or decoder allocation is performed by this function.
    pub fn from_canonical_bytes(
        bytes: &[u8], key: &AuthKey, expected: SnapshotIdentity,
        expected_peer: &NodeId, limits: ManifestLimits,
    ) -> Result<Self, ManifestError> {
        if bytes.len() > limits.max_encoded_bytes { return Err(ManifestError::Limit("encoded bytes")); }
        if bytes.len() < HEADER + TAG { return Err(ManifestError::Truncated); }
        let end = bytes.len() - TAG;
        let body = &bytes[..end];
        if &body[..8] != MAGIC || body[8..12] != 1_u32.to_le_bytes() { return Err(ManifestError::Format); }
        let tag = AuthenticationTag::from_bytes(bytes[end..].try_into().expect("tag bytes"));
        if !tag.verify_domain_payload(key, DOMAIN, body) { return Err(ManifestError::Authentication); }
        let mut c = Cursor { bytes: body, position: 12 };
        if c.u64()? != expected.region_id.as_u64() || c.u64()? != expected.origin_id
            || c.u64()? != expected.epoch || c.u64()? != expected.sequence
        { return Err(ManifestError::Identity); }
        let object_id = ObjectId::from_u128(u128::from_le_bytes(c.take(16)?.try_into().expect("object bytes")));
        let params = ObjectParams::new(object_id, c.u64()?, c.u16()?, c.u16()?, c.u16()?);
        dimensions(params)?;
        let minimum = usize::try_from(c.u32()?).map_err(|_| ManifestError::Overflow)?;
        let count = usize::try_from(c.u32()?).map_err(|_| ManifestError::Overflow)?;
        counts(count, minimum, limits)?;
        let origin = c.label()?;
        if origin != expected_peer.as_str() { return Err(ManifestError::Identity); }
        let replica_start = c.position;
        let mut labels = origin.len();
        storage(count, labels, limits)?;
        let mut previous = None;
        for _ in 0..count {
            let label = c.label()?;
            if previous.is_some_and(|old| old >= label) { return Err(ManifestError::Format); }
            labels = add(labels, label.len())?;
            storage(count, labels, limits)?;
            c.take(32)?;
            previous = Some(label);
        }
        if c.position != body.len() { return Err(ManifestError::TrailingData); }
        let mut replicas = Vec::new();
        replicas.try_reserve_exact(count).map_err(|_| ManifestError::Allocation)?;
        c.position = replica_start;
        for _ in 0..count {
            let label = c.label()?;
            let mut replica_id = String::new();
            replica_id.try_reserve_exact(label.len()).map_err(|_| ManifestError::Allocation)?;
            replica_id.push_str(label);
            let digest = c.take(32)?.try_into().expect("digest bytes");
            replicas.push(ReplicaFetch { replica_id, key: SymbolBatchKey { object_id, digest } });
        }
        Ok(Self { peer: expected_peer.clone(), params, identity: expected, minimum_replicas: minimum, replicas })
    }
}

struct Cursor<'a> { bytes: &'a [u8], position: usize }
impl<'a> Cursor<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], ManifestError> {
        let end = add(self.position, length)?;
        let bytes = self.bytes.get(self.position..end).ok_or(ManifestError::Truncated)?;
        self.position = end;
        Ok(bytes)
    }
    fn u16(&mut self) -> Result<u16, ManifestError> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().expect("two bytes")))
    }
    fn u32(&mut self) -> Result<u32, ManifestError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().expect("four bytes")))
    }
    fn u64(&mut self) -> Result<u64, ManifestError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().expect("eight bytes")))
    }
    fn label(&mut self) -> Result<&'a str, ManifestError> {
        let n = usize::from(self.take(1)?[0]);
        if n == 0 { return Err(ManifestError::Format); }
        std::str::from_utf8(self.take(n)?).map_err(|_| ManifestError::Format)
    }
}

#[cfg(test)]
mod tests;
