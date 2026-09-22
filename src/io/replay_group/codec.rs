//! Explicit, bounded persistence for a complete multi-stream observation window.

use super::{Entry, RecordedIoGroup, RecordedStream};
use crate::io::replay::{IoOperation, IoTape, IoTapeDecodeLimits, IoTapeError};
use sha2::{Digest, Sha256};
use std::{fmt, mem::size_of};
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 8] = b"ASUPMIO\0";
const VERSION: u32 = 1;
const HEADER: usize = 28;
const CHECKSUM: usize = 32;
const ENTRY_BYTES: usize = 9;
const DOMAIN: &[u8] = b"asupersync.multi-io.v1";

/// Independent encoded, group-metadata and per-stream decoder bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoGroupDecodeLimits {
    /// Entire envelope, including all nested tapes and checksum.
    pub max_encoded_bytes: usize,
    /// Maximum distinct streams, including streams with no observations.
    pub max_streams: usize,
    /// Maximum total completed-operation order entries.
    pub max_events: usize,
    /// Logical decoded group metadata plus temporary descriptors/IDs/counts.
    /// Excludes nested tape storage, input bytes, allocator overhead and later
    /// replay-slot storage, which is separately bounded by the stream count.
    pub max_group_bytes: usize,
    /// Independent bounds for EACH stream. The combined component allowance
    /// is at most `max_streams` times these limits, not one shared allowance.
    pub per_stream: IoTapeDecodeLimits,
}

/// Redacted import/export failure; no partial group is returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum IoGroupTapeError {
    /// A complete declared envelope was not supplied.
    #[error("multi-stream I/O capture is truncated")]
    Truncated,
    /// Extra bytes followed the single declared envelope.
    #[error("multi-stream I/O capture has trailing bytes")]
    TrailingData,
    /// Magic, version or operation tag is not supported.
    #[error("unsupported multi-stream I/O capture format")]
    Format,
    /// Domain-separated corruption-detection checksum did not match.
    #[error("multi-stream I/O capture checksum mismatch")]
    Checksum,
    /// Length, multiplication or ordinal cannot fit the target address space.
    #[error("multi-stream I/O capture size overflow")]
    Overflow,
    /// A caller-selected resource bound was exceeded.
    #[error("multi-stream I/O capture exceeds its {0} limit")]
    Limit(&'static str),
    /// Bounded storage could not be reserved.
    #[error("multi-stream I/O capture allocation failed")]
    Allocation,
    /// Duplicate identity, invalid stream ordinal or operation-count mismatch.
    #[error("multi-stream I/O order does not cover its streams")]
    Coverage,
    /// Original nested per-stream decoder/encoder refusal.
    #[error("multi-stream I/O component: {0}")]
    Stream(#[from] IoTapeError),
}

/// Sensitive plaintext bytes, zeroized on drop. No persistence is implicit.
///
/// The checksum is NOT authentication or encryption. Prefer the authenticated
/// archive adapter or caller-controlled protected storage for real captures.
pub struct IoGroupBytes(Zeroizing<Vec<u8>>);
impl fmt::Debug for IoGroupBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IoGroupBytes").field("encoded_bytes", &self.0.len()).finish_non_exhaustive()
    }
}
impl AsRef<[u8]> for IoGroupBytes {
    fn as_ref(&self) -> &[u8] { &self.0 }
}

fn add(a: usize, b: usize) -> Result<usize, IoGroupTapeError> { a.checked_add(b).ok_or(IoGroupTapeError::Overflow) }
fn mul(a: usize, b: usize) -> Result<usize, IoGroupTapeError> { a.checked_mul(b).ok_or(IoGroupTapeError::Overflow) }
fn number(bytes: &[u8], at: usize) -> Result<u64, IoGroupTapeError> {
    let value = bytes.get(at..add(at, 8)?).ok_or(IoGroupTapeError::Truncated)?;
    Ok(u64::from_le_bytes(value.try_into().expect("eight-byte field")))
}
fn count(bytes: &[u8], at: usize) -> Result<usize, IoGroupTapeError> {
    usize::try_from(number(bytes, at)?).map_err(|_| IoGroupTapeError::Overflow)
}
fn put(out: &mut Vec<u8>, value: usize) -> Result<(), IoGroupTapeError> {
    out.extend_from_slice(&u64::try_from(value).map_err(|_| IoGroupTapeError::Overflow)?.to_le_bytes()); Ok(())
}
fn checksum(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new(); hash.update(DOMAIN); hash.update(bytes); hash.finalize().into()
}
fn tag(operation: IoOperation) -> u8 {
    match operation { IoOperation::Read => 0, IoOperation::Write => 1, IoOperation::WriteVectored => 2, IoOperation::Flush => 3, IoOperation::Shutdown => 4 }
}
fn operation(tag: u8) -> Result<IoOperation, IoGroupTapeError> {
    match tag { 0 => Ok(IoOperation::Read), 1 => Ok(IoOperation::Write), 2 => Ok(IoOperation::WriteVectored), 3 => Ok(IoOperation::Flush), 4 => Ok(IoOperation::Shutdown), _ => Err(IoGroupTapeError::Format) }
}

#[derive(Clone, Copy)]
struct Descriptor { id: u64, start: usize, end: usize }
fn metadata_bytes(streams: usize, events: usize) -> Result<usize, IoGroupTapeError> {
    let per_stream = add(size_of::<RecordedStream>(), add(size_of::<Descriptor>(), add(size_of::<u64>(), size_of::<usize>())?)?)?;
    add(mul(streams, per_stream)?, mul(events, size_of::<Entry>())?)
}
fn vector<T>(capacity: usize) -> Result<Vec<T>, IoGroupTapeError> {
    let mut out = Vec::new(); out.try_reserve_exact(capacity).map_err(|_| IoGroupTapeError::Allocation)?; Ok(out)
}

impl RecordedIoGroup {
    /// Export one complete group with an aggregate shrinking encoded-byte budget.
    ///
    /// V1: magic[8], version:u32, stream-count:u64, event-count:u64; then each
    /// stream's id:u64, tape-length:u64 and unchanged canonical IoTape bytes;
    /// then events (stream-ordinal:u64, operation-tag:u8); finally SHA-256 of
    /// the domain followed by all prior envelope bytes. Integers are LE.
    /// Tags 0..4 are read/write/vectored-write/flush/shutdown. Per-stream tape
    /// versions and OS binding remain unchanged. Cross-stream pending timing
    /// and connection establishment are not encoded.
    ///
    /// Encoded component temporaries and final output each fit the chosen
    /// bound; live tapes, small metadata vectors and allocator overhead are
    /// separate. Temporary plaintext owners zeroize on success and refusal.
    pub fn to_canonical_bytes(&self, max_encoded_bytes: usize) -> Result<IoGroupBytes, IoGroupTapeError> {
        let overhead = add(HEADER + CHECKSUM, add(mul(self.streams.len(), 16)?, mul(self.order.len(), ENTRY_BYTES)?)?)?;
        let mut remaining = max_encoded_bytes.checked_sub(overhead).ok_or(IoGroupTapeError::Limit("encoded bytes"))?;
        let mut components = vector(self.streams.len())?;
        for stream in &self.streams {
            let encoded = stream.tape.to_canonical_bytes(remaining)?;
            remaining = remaining.checked_sub(encoded.as_ref().len()).ok_or(IoGroupTapeError::Limit("encoded bytes"))?;
            components.push(encoded);
        }
        let length = max_encoded_bytes - remaining;
        let mut out = IoGroupBytes(Zeroizing::new(vector(length)?));
        out.0.extend_from_slice(MAGIC);
        out.0.extend_from_slice(&VERSION.to_le_bytes());
        put(&mut out.0, self.streams.len())?; put(&mut out.0, self.order.len())?;
        for (stream, encoded) in self.streams.iter().zip(&components) {
            out.0.extend_from_slice(&stream.id.to_le_bytes());
            put(&mut out.0, encoded.as_ref().len())?;
            out.0.extend_from_slice(encoded.as_ref());
        }
        for entry in &self.order { put(&mut out.0, entry.stream)?; out.0.push(tag(entry.operation)); }
        let mut digest = checksum(&out.0); out.0.extend_from_slice(&digest); digest.zeroize();
        debug_assert_eq!(out.0.len(), length);
        Ok(out)
    }

    /// Validate exact framing, all outer bounds, IDs, ordinals, counts and every
    /// nested tape before returning any stream provider. A later refusal drops
    /// and zeroizes earlier decoded tapes. No original provider is invoked.
    ///
    /// Operation kinds and request shapes are checked against their component
    /// tapes during replay, not asserted by an unkeyed checksum. Incorrect kinds
    /// fail closed in the replay driver rather than fabricating readiness. Always
    /// require `IoReplayGroup::verify_complete` after the consumer drains.
    pub fn from_canonical_bytes(bytes: &[u8], limits: IoGroupDecodeLimits) -> Result<Self, IoGroupTapeError> {
        if bytes.len() > limits.max_encoded_bytes { return Err(IoGroupTapeError::Limit("encoded bytes")); }
        if bytes.len() < HEADER + CHECKSUM { return Err(IoGroupTapeError::Truncated); }
        if &bytes[..8] != MAGIC || bytes[8..12] != VERSION.to_le_bytes() { return Err(IoGroupTapeError::Format); }
        let streams = count(bytes, 12)?; let events = count(bytes, 20)?;
        if streams > limits.max_streams { return Err(IoGroupTapeError::Limit("streams")); }
        if events > limits.max_events { return Err(IoGroupTapeError::Limit("events")); }
        if metadata_bytes(streams, events)? > limits.max_group_bytes { return Err(IoGroupTapeError::Limit("group storage")); }
        // Framing and every component encoded bound precede any tape decoding.
        // This pass allocates nothing, including for forged large stream counts.
        let mut position = HEADER;
        for _ in 0..streams {
            let length = count(bytes, add(position, 8)?)?;
            if length > limits.per_stream.max_encoded_bytes { return Err(IoGroupTapeError::Stream(IoTapeError::Limit("encoded bytes"))); }
            position = add(add(position, 16)?, length)?;
            if position > bytes.len() { return Err(IoGroupTapeError::Truncated); }
        }
        let order_start = position;
        let body_end = add(order_start, mul(events, ENTRY_BYTES)?)?;
        let expected_length = add(body_end, CHECKSUM)?;
        if bytes.len() < expected_length { return Err(IoGroupTapeError::Truncated); }
        if bytes.len() > expected_length { return Err(IoGroupTapeError::TrailingData); }
        let mut expected = checksum(&bytes[..body_end]); let matches = expected.as_slice() == &bytes[body_end..]; expected.zeroize();
        if !matches { return Err(IoGroupTapeError::Checksum); }
        let mut descriptors = vector(streams)?; let mut ids = vector(streams)?;
        position = HEADER;
        for _ in 0..streams {
            let id = number(bytes, position)?;
            let length = count(bytes, position + 8)?;
            let start = position + 16; let end = start + length; // preflight checked
            descriptors.push(Descriptor { id, start, end }); ids.push(id); position = end;
        }
        ids.sort_unstable();
        if ids.windows(2).any(|pair| pair[0] == pair[1]) { return Err(IoGroupTapeError::Coverage); }
        let mut counts = vector(streams)?; counts.resize(streams, 0usize);
        let mut order = vector(events)?;
        for entry in bytes[order_start..body_end].chunks_exact(ENTRY_BYTES) {
            let stream = count(entry, 0)?;
            let count = counts.get_mut(stream).ok_or(IoGroupTapeError::Coverage)?;
            *count = count.checked_add(1).ok_or(IoGroupTapeError::Overflow)?;
            order.push(Entry { stream, operation: operation(entry[8])? });
        }
        let mut decoded = vector(streams)?;
        for (descriptor, count) in descriptors.iter().zip(counts) {
            let tape = IoTape::from_canonical_bytes(&bytes[descriptor.start..descriptor.end], limits.per_stream)?;
            if tape.operations() != count { return Err(IoGroupTapeError::Coverage); }
            decoded.push(RecordedStream { id: descriptor.id, tape });
        }
        Ok(Self { streams: decoded, order })
    }
}

#[cfg(test)]
mod tests;
