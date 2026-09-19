//! Explicit bounded persistence of consumer polls and their ordered observations.
use super::{PollCaptureLimits, PolledRecordedSession};
use super::super::{OrderedRecordedSession, OrderedSessionDecodeLimits, OrderedSessionTapeError};
use super::trace::{Checkpoint, IoStep, PollStep, PollTape};
use crate::io::replay::IoOperation;
use sha2::{Digest, Sha256};
use std::fmt;
use zeroize::Zeroize;

const MAGIC: &[u8; 8] = b"ASUPPOL\0";
const VERSION: u32 = 1;
const HEADER: usize = 68;
const IO_BYTES: usize = 58;
const POLL_BYTES: usize = 17;
const CHECKSUM: usize = 32;
const DOMAIN: &[u8] = b"asupersync.polled-session.v1";

/// Independent admission limits for the poll envelope and its nested tapes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolledDecodeLimits {
    /// Entire encoded envelope, including all nested tapes and checksum.
    pub max_encoded_bytes: usize,
    /// Poll/call/request-work bounds, including Pending operations.
    pub polls: PollCaptureLimits,
    /// Logical in-memory IoStep + PollStep vector storage. Excludes allocator
    /// overhead, the caller's encoded input, and separately bounded nested tapes.
    pub max_poll_bytes: usize,
    /// All existing ordered/component admission limits remain independently active.
    pub ordered: OrderedSessionDecodeLimits,
}

/// Redacted polled-session encoding refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PolledTapeError {
    /// Missing declared bytes.
    #[error("polled session is truncated")]
    Truncated,
    /// Extra bytes follow the declared envelope.
    #[error("polled session contains trailing data")]
    TrailingData,
    /// Unknown magic/version/operation or invalid flag/unused field.
    #[error("unsupported polled session format")]
    Format,
    /// Envelope integrity check failed.
    #[error("polled session checksum mismatch")]
    Checksum,
    /// A caller-selected admission ceiling was exceeded.
    #[error("polled session exceeds its {0} limit")]
    Limit(&'static str),
    /// Size arithmetic exceeds this target's address space.
    #[error("polled session size overflow")]
    Overflow,
    /// Bounded allocation failed.
    #[error("polled session allocation failed")]
    Allocation,
    /// Checkpoints/outcomes do not cover the ordered component window.
    #[error("polled session has inconsistent coverage")]
    Coverage,
    /// Nested ordered/component validation failed.
    #[error(transparent)]
    Ordered(#[from] OrderedSessionTapeError),
}

/// Sensitive plaintext bytes, zeroized on drop. Debug shows only length.
///
/// The checksum is not authentication or encryption. Persist only through
/// caller-authorized protected storage. Copies/files are the caller's concern;
/// no filesystem, network, or diagnostic output is performed by this owner.
pub struct PolledSessionBytes(Vec<u8>);
impl fmt::Debug for PolledSessionBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PolledSessionBytes").field("encoded_bytes", &self.0.len()).finish_non_exhaustive()
    }
}
impl AsRef<[u8]> for PolledSessionBytes { fn as_ref(&self) -> &[u8] { &self.0 } }
impl Drop for PolledSessionBytes { fn drop(&mut self) { self.0.zeroize(); } }

fn add(a: usize, b: usize) -> Result<usize, PolledTapeError> { a.checked_add(b).ok_or(PolledTapeError::Overflow) }
fn mul(a: usize, b: usize) -> Result<usize, PolledTapeError> { a.checked_mul(b).ok_or(PolledTapeError::Overflow) }
fn size(bytes: &[u8]) -> Result<usize, PolledTapeError> {
    let value: [u8; 8] = bytes.try_into().map_err(|_| PolledTapeError::Truncated)?;
    usize::try_from(u64::from_le_bytes(value)).map_err(|_| PolledTapeError::Overflow)
}
fn put(out: &mut Vec<u8>, value: usize) -> Result<(), PolledTapeError> {
    out.extend_from_slice(&u64::try_from(value).map_err(|_| PolledTapeError::Overflow)?.to_le_bytes()); Ok(())
}
fn digest(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new(); hash.update(DOMAIN); hash.update(bytes); hash.finalize().into()
}
fn flag(byte: u8) -> Result<bool, PolledTapeError> {
    match byte { 0 => Ok(false), 1 => Ok(true), _ => Err(PolledTapeError::Format) }
}
fn checkpoint(bytes: &[u8]) -> Result<Checkpoint, PolledTapeError> {
    Ok(Checkpoint { effects: size(&bytes[..8])?, io: size(&bytes[8..16])? })
}
fn decode_io(bytes: &[u8]) -> Result<IoStep, PolledTapeError> {
    let operation = match bytes[0] {
        0 => IoOperation::Read, 1 => IoOperation::Write, 2 => IoOperation::WriteVectored,
        3 => IoOperation::Flush, 4 => IoOperation::Shutdown, _ => return Err(PolledTapeError::Format),
    };
    let pending = flag(bytes[1])?;
    let effect = size(&bytes[2..10])?;
    let length = size(&bytes[10..18])?;
    let slices = size(&bytes[18..26])?;
    if (operation != IoOperation::WriteVectored && slices != 0)
        || (matches!(operation, IoOperation::Flush | IoOperation::Shutdown) && length != 0)
        || (operation == IoOperation::WriteVectored && slices == 0 && length != 0) {
        return Err(PolledTapeError::Format);
    }
    let mut fingerprint = [0; 32]; fingerprint.copy_from_slice(&bytes[26..]);
    Ok(IoStep { operation, pending, effect, length, slices, digest: fingerprint })
}

impl PolledRecordedSession {
    /// Export a versioned envelope without losing Pending outcomes or boundaries.
    ///
    /// V1 uses little-endian fixed integers: magic[8], version:u32, ordered-byte
    /// length:u64, I/O-poll count:u64, consumer-poll count:u64, construction and
    /// terminal checkpoints (each effects:u64 + I/O polls:u64). Then come the
    /// complete ordered bytes, 58-byte I/O records (operation:u8, pending:u8,
    /// effect:u64, length:u64, slices:u64, digest[32]), 17-byte consumer records
    /// (checkpoint + ready:u8), and SHA-256(domain || all preceding bytes).
    /// Operation IDs 0..4 are read/write/vectored/flush/shutdown. No padding.
    ///
    /// Outer overhead is charged before nested encoding. Temporary encodings and
    /// the final buffer are separately bounded by the ceiling. Live tapes and
    /// allocator overhead are separate. Existing I/O platform restrictions remain.
    pub fn to_canonical_bytes(&self, max_encoded_bytes: usize) -> Result<PolledSessionBytes, PolledTapeError> {
        if !self.polls.covers(&self.ordered) { return Err(PolledTapeError::Coverage); }
        let overhead = add(HEADER + CHECKSUM, add(mul(self.polls.io.len(), IO_BYTES)?, mul(self.polls.frames.len(), POLL_BYTES)?)?)?;
        let remaining = max_encoded_bytes.checked_sub(overhead).ok_or(PolledTapeError::Limit("encoded bytes"))?;
        let ordered = self.ordered.to_canonical_bytes(remaining)?;
        let length = add(overhead, ordered.as_ref().len())?;
        let mut out = PolledSessionBytes(Vec::new());
        out.0.try_reserve_exact(length).map_err(|_| PolledTapeError::Allocation)?;
        out.0.extend_from_slice(MAGIC); out.0.extend_from_slice(&VERSION.to_le_bytes());
        put(&mut out.0, ordered.as_ref().len())?;
        put(&mut out.0, self.polls.io.len())?; put(&mut out.0, self.polls.frames.len())?;
        for point in [self.polls.construction, self.polls.terminal] {
            put(&mut out.0, point.effects)?; put(&mut out.0, point.io)?;
        }
        out.0.extend_from_slice(ordered.as_ref());
        for step in &self.polls.io {
            out.0.push(match step.operation {
                IoOperation::Read => 0, IoOperation::Write => 1, IoOperation::WriteVectored => 2,
                IoOperation::Flush => 3, IoOperation::Shutdown => 4,
            });
            out.0.push(u8::from(step.pending));
            put(&mut out.0, step.effect)?; put(&mut out.0, step.length)?; put(&mut out.0, step.slices)?;
            out.0.extend_from_slice(&step.digest);
        }
        for step in &self.polls.frames {
            put(&mut out.0, step.checkpoint.effects)?; put(&mut out.0, step.checkpoint.io)?;
            out.0.push(u8::from(step.ready));
        }
        let mut checksum = digest(&out.0); out.0.extend_from_slice(&checksum); checksum.zeroize();
        debug_assert_eq!(out.0.len(), length);
        Ok(out)
    }

    /// Validate one full encoding without invoking a provider or consumer.
    ///
    /// All encoded/count/storage/work bounds, framing, checksum, operation tags,
    /// flags and basic checkpoint ranges precede nested decoding and vector
    /// allocation. Exact ordered coverage is checked before exposing the result.
    /// Decoded request digests and nested owners are zeroized on late failure.
    /// This does not authenticate the producer or prove application equivalence.
    pub fn from_canonical_bytes(bytes: &[u8], limits: PolledDecodeLimits) -> Result<Self, PolledTapeError> {
        if bytes.len() > limits.max_encoded_bytes { return Err(PolledTapeError::Limit("encoded bytes")); }
        if bytes.len() < HEADER + CHECKSUM { return Err(PolledTapeError::Truncated); }
        if &bytes[..8] != MAGIC || bytes[8..12] != VERSION.to_le_bytes() { return Err(PolledTapeError::Format); }
        let ordered_len = size(&bytes[12..20])?;
        let io_count = size(&bytes[20..28])?;
        let poll_count = size(&bytes[28..36])?;
        let construction = checkpoint(&bytes[36..52])?;
        let terminal = checkpoint(&bytes[52..68])?;
        if io_count > limits.polls.max_io_polls { return Err(PolledTapeError::Limit("I/O polls")); }
        if poll_count > limits.polls.max_polls { return Err(PolledTapeError::Limit("consumer polls")); }
        if poll_count == 0 || terminal.io != io_count { return Err(PolledTapeError::Coverage); }
        if add(mul(io_count, std::mem::size_of::<IoStep>())?, mul(poll_count, std::mem::size_of::<PollStep>())?)? > limits.max_poll_bytes {
            return Err(PolledTapeError::Limit("poll bytes"));
        }
        if ordered_len > limits.ordered.max_encoded_bytes { return Err(PolledTapeError::Limit("ordered bytes")); }
        let io_start = add(HEADER, ordered_len)?;
        let frames_start = add(io_start, mul(io_count, IO_BYTES)?)?;
        let body_end = add(frames_start, mul(poll_count, POLL_BYTES)?)?;
        let length = add(body_end, CHECKSUM)?;
        if bytes.len() < length { return Err(PolledTapeError::Truncated); }
        if bytes.len() > length { return Err(PolledTapeError::TrailingData); }
        let mut checksum = digest(&bytes[..body_end]);
        let valid = checksum.as_slice() == &bytes[body_end..]; checksum.zeroize();
        if !valid { return Err(PolledTapeError::Checksum); }
        let raw_io = &bytes[io_start..frames_start];
        let raw_frames = &bytes[frames_start..body_end];
        let mut written = 0;
        for bytes in raw_io.chunks_exact(IO_BYTES) {
            let step = decode_io(bytes)?;
            if step.slices > limits.polls.max_vectored_slices { return Err(PolledTapeError::Limit("vectored slices")); }
            if matches!(step.operation, IoOperation::Write | IoOperation::WriteVectored) {
                written = add(written, step.length)?;
                if written > limits.polls.max_write_bytes { return Err(PolledTapeError::Limit("write bytes")); }
            }
            if step.effect > terminal.effects { return Err(PolledTapeError::Coverage); }
        }
        let mut previous = construction;
        if construction.effects > terminal.effects || construction.io > io_count { return Err(PolledTapeError::Coverage); }
        for (index, bytes) in raw_frames.chunks_exact(POLL_BYTES).enumerate() {
            let point = checkpoint(bytes)?;
            if flag(bytes[16])? != (index + 1 == poll_count)
                || point.effects < previous.effects || point.io < previous.io
                || point.effects > terminal.effects || point.io > io_count { return Err(PolledTapeError::Coverage); }
            previous = point;
        }
        let ordered = OrderedRecordedSession::from_canonical_bytes(&bytes[HEADER..io_start], limits.ordered)?;
        let mut polls = PollTape { io: Vec::new(), frames: Vec::new(), construction, terminal };
        polls.io.try_reserve_exact(io_count).map_err(|_| PolledTapeError::Allocation)?;
        polls.frames.try_reserve_exact(poll_count).map_err(|_| PolledTapeError::Allocation)?;
        for bytes in raw_io.chunks_exact(IO_BYTES) { polls.io.push(decode_io(bytes)?); }
        for bytes in raw_frames.chunks_exact(POLL_BYTES) {
            polls.frames.push(PollStep { checkpoint: checkpoint(bytes)?, ready: flag(bytes[16])? });
        }
        if !polls.covers(&ordered) { return Err(PolledTapeError::Coverage); }
        Ok(Self { ordered, polls })
    }
}

#[cfg(test)]
mod tests;
