//! Bounded, all-or-nothing persistence of a joint cross-provider window.

use super::{Entry, GroupEffect, RecordedGroupSession, RecordedStream};
use crate::io::replay::{IoOperation, IoTape, IoTapeDecodeLimits, IoTapeError};
use crate::time::replay::{TimeTape, TimeTapeDecodeLimits, TimeTapeError};
use crate::util::entropy_replay::{EntropyTape, EntropyTapeDecodeLimits, EntropyTapeError};
use sha2::{Digest, Sha256};
use std::{fmt, mem::size_of};
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 8] = b"ASUPGSC\0";
const VERSION: u32 = 1;
const HEADER: usize = 44;
const CHECKSUM: usize = 32;
const EFFECT_BYTES: usize = 17;
const DOMAIN: &[u8] = b"asupersync.group-session.v1\0";

/// Independent envelope, metadata and component admission limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupSessionDecodeLimits {
    /// Entire encoding, including all components, timeline and checksum.
    pub max_encoded_bytes: usize,
    /// Unique byte-stream identities, including empty streams.
    pub max_streams: usize,
    /// Total completed effects across all components.
    pub max_effects: usize,
    /// Logical group metadata plus temporary descriptors, sorted IDs and counts.
    /// Excludes input, component storage, allocator overhead and later replay state.
    pub max_group_bytes: usize,
    /// Applied independently to EACH byte stream; allowances multiply by count.
    pub per_stream: IoTapeDecodeLimits,
    /// Applied once to the entire entropy fork tree.
    pub entropy: EntropyTapeDecodeLimits,
    /// Applied once to the serial clock tape.
    pub clock: TimeTapeDecodeLimits,
}

/// Import/export refusal without source bytes, random values or timestamps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum GroupSessionTapeError {
    /// Input was shorter than its declared envelope.
    #[error("group session encoding is truncated")]
    Truncated,
    /// Trailing data is not silently accepted.
    #[error("group session encoding has trailing bytes")]
    TrailingData,
    /// Magic/version/tag or a reserved field was invalid.
    #[error("unsupported group session encoding")]
    Format,
    /// Unkeyed corruption-detection checksum did not match.
    #[error("group session checksum mismatch")]
    Checksum,
    /// Arithmetic overflow or an unrepresentable target-size count.
    #[error("group session size overflow")]
    Overflow,
    /// A caller-selected resource bound was exceeded.
    #[error("group session exceeds its {0} limit")]
    Limit(&'static str),
    /// Bounded allocation failed.
    #[error("group session allocation failed")]
    Allocation,
    /// Identities, effect counts or entropy source topology were inconsistent.
    #[error("group session timeline does not cover its components")]
    Coverage,
    /// Original I/O component refusal.
    #[error("group session I/O tape: {0}")]
    Io(#[from] IoTapeError),
    /// Original entropy component refusal.
    #[error("group session entropy tape: {0}")]
    Entropy(#[from] EntropyTapeError),
    /// Original clock component refusal.
    #[error("group session clock tape: {0}")]
    Clock(#[from] TimeTapeError),
}

/// Sensitive plaintext with a zeroizing owner and size-only Debug output.
/// A checksum is NOT authentication; use an encrypted archive for real captures.
pub struct GroupSessionBytes(Zeroizing<Vec<u8>>);
impl fmt::Debug for GroupSessionBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GroupSessionBytes").field("encoded_bytes", &self.0.len()).finish_non_exhaustive()
    }
}
impl AsRef<[u8]> for GroupSessionBytes {
    fn as_ref(&self) -> &[u8] { &self.0 }
}

fn add(a: usize, b: usize) -> Result<usize, GroupSessionTapeError> {
    a.checked_add(b).ok_or(GroupSessionTapeError::Overflow)
}
fn mul(a: usize, b: usize) -> Result<usize, GroupSessionTapeError> {
    a.checked_mul(b).ok_or(GroupSessionTapeError::Overflow)
}
fn number(bytes: &[u8], at: usize) -> Result<u64, GroupSessionTapeError> {
    let slice = bytes.get(at..add(at, 8)?).ok_or(GroupSessionTapeError::Truncated)?;
    Ok(u64::from_le_bytes(slice.try_into().expect("eight-byte field")))
}
fn count(bytes: &[u8], at: usize) -> Result<usize, GroupSessionTapeError> {
    usize::try_from(number(bytes, at)?).map_err(|_| GroupSessionTapeError::Overflow)
}
fn put(out: &mut Vec<u8>, value: usize) -> Result<(), GroupSessionTapeError> {
    out.extend_from_slice(&u64::try_from(value).map_err(|_| GroupSessionTapeError::Overflow)?.to_le_bytes());
    Ok(())
}
fn vector<T>(capacity: usize) -> Result<Vec<T>, GroupSessionTapeError> {
    let mut out = Vec::new();
    out.try_reserve_exact(capacity).map_err(|_| GroupSessionTapeError::Allocation)?;
    Ok(out)
}
fn checksum(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new(); hash.update(DOMAIN); hash.update(bytes); hash.finalize().into()
}
fn io_tag(operation: IoOperation) -> u8 {
    match operation {
        IoOperation::Read => 0, IoOperation::Write => 1, IoOperation::WriteVectored => 2,
        IoOperation::Flush => 3, IoOperation::Shutdown => 4,
    }
}
fn io_operation(tag: u8) -> Result<IoOperation, GroupSessionTapeError> {
    match tag {
        0 => Ok(IoOperation::Read), 1 => Ok(IoOperation::Write), 2 => Ok(IoOperation::WriteVectored),
        3 => Ok(IoOperation::Flush), 4 => Ok(IoOperation::Shutdown), _ => Err(GroupSessionTapeError::Format),
    }
}
struct Descriptor { id: u64, start: usize, end: usize }
fn metadata_bytes(streams: usize, effects: usize) -> Result<usize, GroupSessionTapeError> {
    let stream = add(size_of::<RecordedStream>(), add(size_of::<Descriptor>(), add(size_of::<(u64, usize)>(), size_of::<usize>())?)?)?;
    add(mul(streams, stream)?, mul(effects, size_of::<Entry>())?)
}

impl RecordedGroupSession {
    /// Encode every component and its complete cross-provider timeline atomically
    /// as one logical envelope (not an implicit filesystem transaction).
    ///
    /// V1 uses LE integers: magic[8], version:u32, stream-count:u64,
    /// effect-count:u64, entropy-length:u64, clock-length:u64. Each stream is
    /// id:u64, length:u64, canonical IoTape bytes; then entropy bytes, clock bytes,
    /// and effects (tag:u8, subject:u64, child:u64), followed by SHA-256 of the
    /// domain and all preceding bytes. Tags 0..4 are I/O with a stream ordinal;
    /// 5 is clock (subject=0); 6 is entropy; 7 is fork (subject=parent source).
    /// Child is zero except on forks, which allocate consecutive source ordinals.
    ///
    /// Components retain their exact existing versions/platform restrictions.
    /// A shrinking total byte budget applies during nested encoding. Encoded
    /// temporaries and the final zeroizing output each fit that bound; original
    /// tapes, bounded metadata vectors and allocator overhead are separate.
    pub fn to_canonical_bytes(&self, max_encoded_bytes: usize) -> Result<GroupSessionBytes, GroupSessionTapeError> {
        let overhead = add(HEADER + CHECKSUM, add(mul(self.streams.len(), 16)?, mul(self.entries.len(), EFFECT_BYTES)?)?)?;
        let mut remaining = max_encoded_bytes.checked_sub(overhead).ok_or(GroupSessionTapeError::Limit("encoded bytes"))?;
        let mut components = vector(self.streams.len())?;
        let mut ids = vector(self.streams.len())?;
        for (index, stream) in self.streams.iter().enumerate() {
            let bytes = stream.tape.to_canonical_bytes(remaining)?;
            remaining = remaining.checked_sub(bytes.as_ref().len()).ok_or(GroupSessionTapeError::Limit("encoded bytes"))?;
            components.push(bytes);
            ids.push((stream.id, index));
        }
        ids.sort_unstable();
        let entropy = self.entropy.to_canonical_bytes(remaining)?;
        remaining = remaining.checked_sub(entropy.as_ref().len()).ok_or(GroupSessionTapeError::Limit("encoded bytes"))?;
        let clock = self.clock.to_canonical_bytes(remaining)?;
        remaining = remaining.checked_sub(clock.as_ref().len()).ok_or(GroupSessionTapeError::Limit("encoded bytes"))?;
        let length = max_encoded_bytes - remaining;
        let mut out = GroupSessionBytes(Zeroizing::new(vector(length)?));
        out.0.extend_from_slice(MAGIC); out.0.extend_from_slice(&VERSION.to_le_bytes());
        put(&mut out.0, self.streams.len())?; put(&mut out.0, self.entries.len())?;
        put(&mut out.0, entropy.as_ref().len())?; put(&mut out.0, clock.as_ref().len())?;
        for (stream, bytes) in self.streams.iter().zip(&components) {
            out.0.extend_from_slice(&stream.id.to_le_bytes());
            put(&mut out.0, bytes.as_ref().len())?; out.0.extend_from_slice(bytes.as_ref());
        }
        out.0.extend_from_slice(entropy.as_ref()); out.0.extend_from_slice(clock.as_ref());
        for entry in &self.entries {
            let (tag, subject) = match entry.effect {
                GroupEffect::Io { stream, operation } => {
                    let index = ids.binary_search_by_key(&stream, |pair| pair.0).map_err(|_| GroupSessionTapeError::Coverage)?;
                    (io_tag(operation), ids[index].1)
                }
                GroupEffect::Clock => (5, 0),
                GroupEffect::Entropy(source) => (6, source),
                GroupEffect::Fork(source) => (7, source),
            };
            out.0.push(tag); put(&mut out.0, subject)?; put(&mut out.0, entry.child)?;
        }
        let mut digest = checksum(&out.0); out.0.extend_from_slice(&digest); digest.zeroize();
        debug_assert_eq!(out.0.len(), length);
        Ok(out)
    }

    /// Validate framing, every outer bound, unique identities, source topology,
    /// coverage counts and all nested tapes before returning any replay authority.
    ///
    /// Preflight scans allocate nothing. Metadata allocation follows exact length
    /// and checksum checks; source-count and metadata limits are independent.
    /// Nested decoders additionally enforce their own payload/storage limits.
    /// Partial decoded owners are dropped/zeroized on later refusal. Group metadata
    /// validation is O(encoded bytes + streams log streams + effects), not
    /// effects*streams; nested component costs remain their own.
    ///
    /// An unkeyed checksum is not trust. Request shapes, operation kinds and exact
    /// entropy fork TaskIds are checked during replay; import does not assert that
    /// a consumer reproduces the window. Require complete execution verification.
    pub fn from_canonical_bytes(bytes: &[u8], limits: GroupSessionDecodeLimits) -> Result<Self, GroupSessionTapeError> {
        if bytes.len() > limits.max_encoded_bytes { return Err(GroupSessionTapeError::Limit("encoded bytes")); }
        if bytes.len() < HEADER + CHECKSUM { return Err(GroupSessionTapeError::Truncated); }
        if &bytes[..8] != MAGIC || bytes[8..12] != VERSION.to_le_bytes() { return Err(GroupSessionTapeError::Format); }
        let streams = count(bytes, 12)?; let effects = count(bytes, 20)?;
        let entropy_len = count(bytes, 28)?; let clock_len = count(bytes, 36)?;
        if streams > limits.max_streams { return Err(GroupSessionTapeError::Limit("streams")); }
        if effects > limits.max_effects { return Err(GroupSessionTapeError::Limit("effects")); }
        if metadata_bytes(streams, effects)? > limits.max_group_bytes { return Err(GroupSessionTapeError::Limit("group storage")); }
        if entropy_len > limits.entropy.max_encoded_bytes { return Err(GroupSessionTapeError::Limit("entropy encoded bytes")); }
        if clock_len > limits.clock.max_encoded_bytes { return Err(GroupSessionTapeError::Limit("clock encoded bytes")); }
        let min_size = add(HEADER + CHECKSUM, add(mul(streams, 16)?, add(mul(effects, EFFECT_BYTES)?, add(entropy_len, clock_len)?)?)?)?;
        if min_size > bytes.len() { return Err(GroupSessionTapeError::Truncated); }
        let mut position = HEADER;
        for _ in 0..streams {
            let length = count(bytes, add(position, 8)?)?;
            if length > limits.per_stream.max_encoded_bytes { return Err(GroupSessionTapeError::Limit("stream encoded bytes")); }
            position = add(add(position, 16)?, length)?;
            if position > bytes.len() - CHECKSUM { return Err(GroupSessionTapeError::Truncated); }
        }
        let entropy_start = position;
        let clock_start = add(entropy_start, entropy_len)?;
        let order_start = add(clock_start, clock_len)?;
        let body_end = add(order_start, mul(effects, EFFECT_BYTES)?)?;
        let total = add(body_end, CHECKSUM)?;
        if total > bytes.len() { return Err(GroupSessionTapeError::Truncated); }
        if total < bytes.len() { return Err(GroupSessionTapeError::TrailingData); }
        let mut expected = checksum(&bytes[..body_end]);
        let valid = expected.as_slice() == &bytes[body_end..]; expected.zeroize();
        if !valid { return Err(GroupSessionTapeError::Checksum); }
        let mut descriptors = vector(streams)?; let mut ids = vector(streams)?;
        position = HEADER;
        for index in 0..streams {
            let id = number(bytes, position)?; let length = count(bytes, position + 8)?;
            let start = position + 16; let end = start + length; // preflight checked
            descriptors.push(Descriptor { id, start, end }); ids.push((id, index)); position = end;
        }
        ids.sort_unstable();
        if ids.windows(2).any(|pair| pair[0].0 == pair[1].0) { return Err(GroupSessionTapeError::Coverage); }
        let mut counts = vector(streams)?; counts.resize(streams, 0usize);
        let mut entries = vector(effects)?;
        let (mut entropy_count, mut clock_count, mut sources) = (0usize, 0usize, 1usize);
        for bytes in bytes[order_start..body_end].chunks_exact(EFFECT_BYTES) {
            let tag = bytes[0]; let subject = count(bytes, 1)?; let child = count(bytes, 9)?;
            if tag != 7 && child != 0 { return Err(GroupSessionTapeError::Format); }
            let effect = match tag {
                0..=4 => {
                    let descriptor = descriptors.get(subject).ok_or(GroupSessionTapeError::Coverage)?;
                    counts[subject] += 1;
                    GroupEffect::Io { stream: descriptor.id, operation: io_operation(tag)? }
                }
                5 if subject == 0 => { clock_count += 1; GroupEffect::Clock }
                6 if subject < sources => { entropy_count += 1; GroupEffect::Entropy(subject) }
                7 if subject < sources && child == sources => {
                    entropy_count += 1; sources = add(sources, 1)?;
                    GroupEffect::Fork(subject)
                }
                5..=7 => return Err(GroupSessionTapeError::Coverage),
                _ => return Err(GroupSessionTapeError::Format),
            };
            entries.push(Entry { effect, child });
        }
        let mut decoded = vector(streams)?;
        for (descriptor, count) in descriptors.iter().zip(counts) {
            let tape = IoTape::from_canonical_bytes(&bytes[descriptor.start..descriptor.end], limits.per_stream)?;
            if tape.operations() != count { return Err(GroupSessionTapeError::Coverage); }
            decoded.push(RecordedStream { id: descriptor.id, tape });
        }
        let entropy = EntropyTape::from_canonical_bytes(&bytes[entropy_start..clock_start], limits.entropy)?;
        let clock = TimeTape::from_canonical_bytes(&bytes[clock_start..order_start], limits.clock)?;
        if entropy.calls() != entropy_count || entropy.streams() != sources || clock.observations() != clock_count {
            return Err(GroupSessionTapeError::Coverage);
        }
        Ok(Self { streams: decoded, entropy, clock, entries })
    }
}

#[cfg(test)]
mod tests;
