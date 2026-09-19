//! Separate, non-downgradable persistence for ordered observation sessions.
use super::gate::{Entry, OrderTape};
use super::{OrderedEffect, OrderedRecordedSession};
use super::super::{RecordedSession, SessionDecodeLimits, SessionTapeError};
use crate::io::replay::IoOperation;
use sha2::{Digest, Sha256};
use std::fmt;
use zeroize::Zeroize;

mod poll;

const MAGIC: &[u8; 8] = b"ASUPORD\0";
const VERSION: u32 = 1;
const HEADER: usize = 28;
const ENTRY_BYTES: usize = 17;
const CHECKSUM: usize = 32;
const DOMAIN: &[u8] = b"asupersync.ordered-session.v1";

/// Independent encoded, order-storage, and component admission limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OrderedSessionDecodeLimits {
    /// Entire envelope, nested session, order, and checksum.
    pub max_encoded_bytes: usize,
    /// Maximum number of order entries, including pending attempts in V2.
    pub max_effects: usize,
    /// Maximum logical `Entry` vector storage, excluding allocator overhead.
    pub max_order_bytes: usize,
    /// All independent component session/tape limits. In V2, the I/O write-byte
    /// and vector-slice ceilings ALSO bound pending fingerprints independently
    /// of completed writes (the combined offered-byte bound is at most twice
    /// `components.io.capture.max_write_bytes`). Pending read capacities do
    /// not allocate buffers. The effect/order limits bound pending count/storage.
    pub components: SessionDecodeLimits,
}

/// Ordered-session persistence refusal. No captured values are formatted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum OrderedSessionTapeError {
    /// The complete declared frame is absent.
    #[error("ordered session is truncated")]
    Truncated,
    /// Magic, version, effect tag, or reserved field is unsupported.
    #[error("unsupported ordered session format")]
    Format,
    /// More bytes follow the declared frame.
    #[error("ordered session contains trailing data")]
    TrailingData,
    /// Domain-separated envelope checksum mismatch.
    #[error("ordered session checksum mismatch")]
    Checksum,
    /// A caller-owned encoded/count/storage ceiling was exceeded.
    #[error("ordered session exceeds its {0} limit")]
    Limit(&'static str),
    /// A count, ordinal, or size exceeds this target's address space.
    #[error("ordered session size overflow")]
    Overflow,
    /// Bounded storage could not be reserved.
    #[error("ordered session allocation failed")]
    Allocation,
    /// The order does not cover the tapes or contains invalid source creation.
    #[error("ordered session order does not cover its component windows")]
    Coverage,
    /// A component envelope/tape refused import or export.
    #[error(transparent)]
    Components(#[from] SessionTapeError),
}

/// Sensitive plaintext encoding, zeroized on drop. Debug reveals only size.
///
/// Checksums are not authentication or encryption. Protect copies and storage
/// with caller-owned controls. No persistence, logging, or transport is implicit.
pub struct OrderedSessionBytes(Vec<u8>);
impl fmt::Debug for OrderedSessionBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OrderedSessionBytes").field("encoded_bytes", &self.0.len()).finish_non_exhaustive()
    }
}
impl AsRef<[u8]> for OrderedSessionBytes { fn as_ref(&self) -> &[u8] { &self.0 } }
impl Drop for OrderedSessionBytes { fn drop(&mut self) { self.0.zeroize(); } }

fn add(a: usize, b: usize) -> Result<usize, OrderedSessionTapeError> {
    a.checked_add(b).ok_or(OrderedSessionTapeError::Overflow)
}
fn mul(a: usize, b: usize) -> Result<usize, OrderedSessionTapeError> {
    a.checked_mul(b).ok_or(OrderedSessionTapeError::Overflow)
}
fn size(bytes: &[u8]) -> Result<usize, OrderedSessionTapeError> {
    let value: [u8; 8] = bytes.try_into().map_err(|_| OrderedSessionTapeError::Truncated)?;
    usize::try_from(u64::from_le_bytes(value)).map_err(|_| OrderedSessionTapeError::Overflow)
}
fn put(out: &mut Vec<u8>, value: usize) -> Result<(), OrderedSessionTapeError> {
    out.extend_from_slice(&u64::try_from(value).map_err(|_| OrderedSessionTapeError::Overflow)?.to_le_bytes());
    Ok(())
}
fn checksum(bytes: &[u8]) -> [u8; CHECKSUM] {
    let mut hash = Sha256::new(); hash.update(DOMAIN); hash.update(bytes); hash.finalize().into()
}
fn decode_entry(bytes: &[u8]) -> Result<Entry, OrderedSessionTapeError> {
    let source = size(&bytes[1..9])?;
    let child = size(&bytes[9..17])?;
    let effect = match bytes[0] {
        0 => OrderedEffect::Io(IoOperation::Read),
        1 => OrderedEffect::Io(IoOperation::Write),
        2 => OrderedEffect::Io(IoOperation::WriteVectored),
        3 => OrderedEffect::Io(IoOperation::Flush),
        4 => OrderedEffect::Io(IoOperation::Shutdown),
        5 => OrderedEffect::Clock,
        6 => OrderedEffect::Entropy(source),
        7 => OrderedEffect::Fork(source),
        _ => return Err(OrderedSessionTapeError::Format),
    };
    if (bytes[0] < 6 && source != 0) || (bytes[0] != 7 && child != 0) {
        return Err(OrderedSessionTapeError::Format);
    }
    Ok(Entry { effect, child, pending: None })
}
fn encode_entry(out: &mut Vec<u8>, entry: &Entry) -> Result<(), OrderedSessionTapeError> {
    let (tag, source) = match entry.effect {
        OrderedEffect::Io(IoOperation::Read) => (0, 0),
        OrderedEffect::Io(IoOperation::Write) => (1, 0),
        OrderedEffect::Io(IoOperation::WriteVectored) => (2, 0),
        OrderedEffect::Io(IoOperation::Flush) => (3, 0),
        OrderedEffect::Io(IoOperation::Shutdown) => (4, 0),
        OrderedEffect::Clock => (5, 0),
        OrderedEffect::Entropy(source) => (6, source),
        OrderedEffect::Fork(source) => (7, source),
    };
    out.push(tag); put(out, source)?; put(out, entry.child)
}

impl OrderedRecordedSession {
    /// Export a bounded ordered envelope without discarding sequencing authority.
    ///
    /// Completed-only sessions retain byte-identical V1 encodings. Poll-aware
    /// sessions always use V2, even with no pending attempts: strict polling must
    /// not silently downgrade to completed-effect replay.
    ///
    /// V1 layout: magic[8], version:u32, component-session length:u64, effect
    /// count:u64, complete component-session V1 bytes, fixed 17-byte entries
    /// (tag:u8, source:u64, child:u64), and SHA-256 of domain then all prior bytes.
    /// All integers are little-endian. Tags 0..4 are read/write/vectored/flush/
    /// shutdown, 5 is clock, 6 is entropy read, and 7 is fork. Unused ordinals
    /// are zero. I/O's existing OS-bound encoding remains OS-bound.
    ///
    /// V2 keeps this header and component format but uses version 2 and the
    /// checksum domain `asupersync.ordered-session.v2`. Each 66-byte entry is the
    /// V1 entry plus a pending flag (0/1), extent:u64, slice-count:u64, digest[32].
    /// Nonpending entries have 49 zero extension bytes. Pending entries are I/O
    /// only; reads use capacity/zero-slices/zero-digest, flush and shutdown use
    /// all-zero request metadata, and writes retain offered length and their
    /// pending-request fingerprint. The V1 decoder rejects version 2.
    ///
    /// Temporary component bytes plus final output require at most twice the
    /// encoded limit, apart from live tapes and allocator overhead. The nested
    /// export is given only the budget remaining AFTER order/header/checksum.
    /// An independent-session decoder refuses this magic; it cannot silently
    /// turn an ordered capture into a weaker independent replay.
    pub fn to_canonical_bytes(&self, max_encoded_bytes: usize) -> Result<OrderedSessionBytes, OrderedSessionTapeError> {
        if self.order.poll_aware { return poll::encode(self, max_encoded_bytes); }
        if !self.order.covers(&self.components) { return Err(OrderedSessionTapeError::Coverage); }
        let overhead = add(HEADER + CHECKSUM, mul(self.order.entries.len(), ENTRY_BYTES)?)?;
        let remaining = max_encoded_bytes.checked_sub(overhead).ok_or(OrderedSessionTapeError::Limit("encoded bytes"))?;
        let components = self.components.to_canonical_bytes(remaining)?;
        let length = add(overhead, components.as_ref().len())?;
        let mut out = OrderedSessionBytes(Vec::new());
        out.0.try_reserve_exact(length).map_err(|_| OrderedSessionTapeError::Allocation)?;
        out.0.extend_from_slice(MAGIC);
        out.0.extend_from_slice(&VERSION.to_le_bytes());
        put(&mut out.0, components.as_ref().len())?;
        put(&mut out.0, self.order.entries.len())?;
        out.0.extend_from_slice(components.as_ref());
        for entry in &self.order.entries { encode_entry(&mut out.0, entry)?; }
        let mut digest = checksum(&out.0);
        out.0.extend_from_slice(&digest); digest.zeroize();
        debug_assert_eq!(out.0.len(), length);
        Ok(out)
    }

    /// Admit one complete V1 or V2 ordered session without invoking providers.
    ///
    /// Use [`from_poll_aware_bytes`](Self::from_poll_aware_bytes) when pending
    /// fidelity is required; it refuses a completed-only V1 input instead of
    /// weakening that requirement. V2 validates pending metadata and hash-work
    /// limits before any nested component allocation.
    ///
    /// Encoded, effect-count, order-allocation and component-encoded limits,
    /// checked framing, checksum and entry tags/reserved fields are checked
    /// before decoding component storage. Components retain their own bounds.
    /// Order coverage and source creation are checked before returning a session;
    /// a later refusal drops earlier decoded components. This validates bytes,
    /// not producer authenticity or arbitrary concurrent-execution equivalence.
    pub fn from_canonical_bytes(bytes: &[u8], limits: OrderedSessionDecodeLimits) -> Result<Self, OrderedSessionTapeError> {
        if bytes.len() > limits.max_encoded_bytes { return Err(OrderedSessionTapeError::Limit("encoded bytes")); }
        if bytes.len() < HEADER + CHECKSUM { return Err(OrderedSessionTapeError::Truncated); }
        if &bytes[..8] == MAGIC && bytes[8..12] == poll::VERSION.to_le_bytes() {
            return poll::decode(bytes, limits);
        }
        if &bytes[..8] != MAGIC || bytes[8..12] != VERSION.to_le_bytes() { return Err(OrderedSessionTapeError::Format); }
        let component_len = size(&bytes[12..20])?;
        let count = size(&bytes[20..28])?;
        if count > limits.max_effects { return Err(OrderedSessionTapeError::Limit("effects")); }
        if mul(count, std::mem::size_of::<Entry>())? > limits.max_order_bytes {
            return Err(OrderedSessionTapeError::Limit("order bytes"));
        }
        if component_len > limits.components.max_encoded_bytes {
            return Err(OrderedSessionTapeError::Limit("component bytes"));
        }
        let order_start = add(HEADER, component_len)?;
        let body_end = add(order_start, mul(count, ENTRY_BYTES)?)?;
        let length = add(body_end, CHECKSUM)?;
        if bytes.len() < length { return Err(OrderedSessionTapeError::Truncated); }
        if bytes.len() > length { return Err(OrderedSessionTapeError::TrailingData); }
        let mut expected = checksum(&bytes[..body_end]);
        let matches = expected.as_slice() == &bytes[body_end..]; expected.zeroize();
        if !matches { return Err(OrderedSessionTapeError::Checksum); }
        let raw_order = &bytes[order_start..body_end];
        for chunk in raw_order.chunks_exact(ENTRY_BYTES) { decode_entry(chunk)?; }
        let components = RecordedSession::from_canonical_bytes(&bytes[HEADER..order_start], limits.components)?;
        let mut order = OrderTape { entries: Vec::new(), poll_aware: false };
        order.entries.try_reserve_exact(count).map_err(|_| OrderedSessionTapeError::Allocation)?;
        for chunk in raw_order.chunks_exact(ENTRY_BYTES) { order.entries.push(decode_entry(chunk)?); }
        if !order.covers(&components) { return Err(OrderedSessionTapeError::Coverage); }
        Ok(Self { components, order })
    }

    /// Require a strict poll-aware V2 capture, including for an empty window.
    ///
    /// V1 and independent-session input are rejected, never converted. All
    /// admission bounds and sensitive-data ownership match `from_canonical_bytes`.
    /// Pending write hashing is bounded independently by the component I/O
    /// write-byte/slice ceilings. Bytes do not authenticate the producer or bind
    /// a consumer version. Replayed pending calls request immediate continuation;
    /// no actual host wake timing, scheduler or cancellation is encoded here.
    pub fn from_poll_aware_bytes(
        bytes: &[u8], limits: OrderedSessionDecodeLimits,
    ) -> Result<Self, OrderedSessionTapeError> {
        poll::decode(bytes, limits)
    }
}

#[cfg(test)]
mod tests;
