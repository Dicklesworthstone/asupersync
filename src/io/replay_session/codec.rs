//! Bounded all-or-nothing persistence for a consumer's three observation tapes.

use super::RecordedSession;
use crate::io::replay::{IoTape, IoTapeDecodeLimits, IoTapeError};
use crate::time::replay::{TimeTape, TimeTapeDecodeLimits, TimeTapeError};
use crate::util::entropy_replay::{EntropyTape, EntropyTapeDecodeLimits, EntropyTapeError};
use sha2::{Digest, Sha256};
use std::fmt;
use zeroize::Zeroize;

const MAGIC: &[u8; 8] = b"ASUPSES\0";
const VERSION: u32 = 1;
const HEADER: usize = 36;
const CHECKSUM: usize = 32;
const OVERHEAD: usize = HEADER + CHECKSUM;
const DOMAIN: &[u8] = b"asupersync.replay-session.v1";

/// Admission limits for the envelope and each independently validated component.
///
/// Component storage bounds add together; none replaces another. They exclude
/// the caller's encoded input, allocator overhead, and later entropy replay
/// cursors (bounded by the admitted entropy source count).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionDecodeLimits {
    /// Maximum entire envelope, including header, all tapes, and checksum.
    pub max_encoded_bytes: usize,
    /// I/O count, payload, vector, encoded-size, and decoded-storage limits.
    pub io: IoTapeDecodeLimits,
    /// Entropy count, fork, payload, encoded-size, and decoded-storage limits.
    pub entropy: EntropyTapeDecodeLimits,
    /// Clock count, encoded-size, and decoded-storage limits.
    pub clock: TimeTapeDecodeLimits,
}

/// Redacted session import/export refusal; a component error returns no session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SessionTapeError {
    /// Input is shorter than its header or the sum of its declared lengths.
    #[error("replay session is truncated")]
    Truncated,
    /// Unknown magic or version.
    #[error("unsupported replay session format")]
    Format,
    /// Bytes remain after the single declared envelope.
    #[error("replay session contains trailing data")]
    TrailingData,
    /// The checksum over the envelope and all component bytes did not match.
    #[error("replay session checksum mismatch")]
    Checksum,
    /// The total encoding exceeded the caller-selected byte ceiling.
    #[error("replay session exceeds its encoded-byte limit")]
    EncodedLimit,
    /// A length or aggregate size overflowed the target's address space.
    #[error("replay session size overflow")]
    Overflow,
    /// Bounded output storage could not be reserved.
    #[error("replay session allocation failed")]
    Allocation,
    /// The I/O component refused import or export.
    #[error("replay session I/O component: {0}")]
    Io(#[from] IoTapeError),
    /// The entropy component refused import or export.
    #[error("replay session entropy component: {0}")]
    Entropy(#[from] EntropyTapeError),
    /// The clock component refused import or export.
    #[error("replay session clock component: {0}")]
    Clock(#[from] TimeTapeError),
}

/// Sensitive plaintext session bytes, zeroized on drop.
///
/// Debug shows only size. The checksum detects accidental corruption/mixing,
/// not deliberate substitution: it is NOT authentication or encryption. Use
/// caller-owned encrypted/authenticated storage. Copies/files are not zeroized
/// by this owner. No file, network, or diagnostic output is created implicitly.
pub struct SessionBytes(Vec<u8>);

impl fmt::Debug for SessionBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionBytes")
            .field("encoded_bytes", &self.0.len())
            .finish_non_exhaustive()
    }
}

impl AsRef<[u8]> for SessionBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for SessionBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

fn checksum(bytes: &[u8]) -> [u8; CHECKSUM] {
    let mut hash = Sha256::new();
    hash.update(DOMAIN);
    hash.update(bytes);
    hash.finalize().into()
}

fn add(a: usize, b: usize) -> Result<usize, SessionTapeError> {
    a.checked_add(b).ok_or(SessionTapeError::Overflow)
}

fn read_size(bytes: &[u8]) -> Result<usize, SessionTapeError> {
    let raw: [u8; 8] = bytes.try_into().map_err(|_| SessionTapeError::Truncated)?;
    usize::try_from(u64::from_le_bytes(raw)).map_err(|_| SessionTapeError::Overflow)
}

fn put_size(out: &mut Vec<u8>, size: usize) -> Result<(), SessionTapeError> {
    let size = u64::try_from(size).map_err(|_| SessionTapeError::Overflow)?;
    out.extend_from_slice(&size.to_le_bytes());
    Ok(())
}

impl RecordedSession {
    /// Export all three tapes in one explicitly bounded V1 envelope.
    ///
    /// Wire layout: magic[8], version:u32, I/O length:u64, entropy length:u64,
    /// clock length:u64, followed by the three complete component encodings in
    /// that order and a SHA-256 checksum of the domain followed by the entire
    /// preceding envelope. All integers are little-endian. Components retain
    /// their own version/checksum/platform validation; I/O V1 is OS-bound.
    ///
    /// The shrinking aggregate budget is enforced while encoding components,
    /// not just after concatenation. Temporary component encodings sum to at
    /// most the selected limit; the final buffer requires a second copy within
    /// that same limit. Live tapes and allocator overhead are separate. All
    /// temporary encoded owners zeroize on success and every error path.
    pub fn to_canonical_bytes(
        &self,
        max_encoded_bytes: usize,
    ) -> Result<SessionBytes, SessionTapeError> {
        let mut remaining = max_encoded_bytes
            .checked_sub(OVERHEAD)
            .ok_or(SessionTapeError::EncodedLimit)?;
        let io = self.io.to_canonical_bytes(remaining)?;
        remaining = remaining
            .checked_sub(io.as_ref().len())
            .ok_or(SessionTapeError::EncodedLimit)?;
        let entropy = self.entropy.to_canonical_bytes(remaining)?;
        remaining = remaining
            .checked_sub(entropy.as_ref().len())
            .ok_or(SessionTapeError::EncodedLimit)?;
        let clock = self.clock.to_canonical_bytes(remaining)?;
        let size = add(
            OVERHEAD,
            add(
                io.as_ref().len(),
                add(entropy.as_ref().len(), clock.as_ref().len())?,
            )?,
        )?;
        if size > max_encoded_bytes {
            return Err(SessionTapeError::EncodedLimit);
        }
        let mut out = SessionBytes(Vec::new());
        out.0
            .try_reserve_exact(size)
            .map_err(|_| SessionTapeError::Allocation)?;
        out.0.extend_from_slice(MAGIC);
        out.0.extend_from_slice(&VERSION.to_le_bytes());
        put_size(&mut out.0, io.as_ref().len())?;
        put_size(&mut out.0, entropy.as_ref().len())?;
        put_size(&mut out.0, clock.as_ref().len())?;
        out.0.extend_from_slice(io.as_ref());
        out.0.extend_from_slice(entropy.as_ref());
        out.0.extend_from_slice(clock.as_ref());
        let mut digest = checksum(&out.0);
        out.0.extend_from_slice(&digest);
        digest.zeroize();
        debug_assert_eq!(out.0.len(), size);
        Ok(out)
    }

    /// Admit one complete session before exposing any replay provider.
    ///
    /// The envelope bound, checked lengths, exact framing, all component encoded
    /// bounds, and outer checksum are checked BEFORE any component is decoded.
    /// Each component then enforces its own logical/allocation/semantic limits.
    /// If a later component fails, earlier decoded owners are dropped/zeroized;
    /// no partial session escapes. Neither clocks nor entropy nor I/O run here.
    /// This verifies bytes, not producer identity, causality, or application code.
    pub fn from_canonical_bytes(
        bytes: &[u8],
        limits: SessionDecodeLimits,
    ) -> Result<Self, SessionTapeError> {
        if bytes.len() > limits.max_encoded_bytes {
            return Err(SessionTapeError::EncodedLimit);
        }
        if bytes.len() < OVERHEAD {
            return Err(SessionTapeError::Truncated);
        }
        if &bytes[..8] != MAGIC || bytes[8..12] != VERSION.to_le_bytes() {
            return Err(SessionTapeError::Format);
        }
        let io_len = read_size(&bytes[12..20])?;
        let entropy_len = read_size(&bytes[20..28])?;
        let clock_len = read_size(&bytes[28..HEADER])?;
        let io_end = add(HEADER, io_len)?;
        let entropy_end = add(io_end, entropy_len)?;
        let body_end = add(entropy_end, clock_len)?;
        let size = add(body_end, CHECKSUM)?;
        if bytes.len() < size {
            return Err(SessionTapeError::Truncated);
        }
        if bytes.len() > size {
            return Err(SessionTapeError::TrailingData);
        }
        if io_len > limits.io.max_encoded_bytes {
            return Err(SessionTapeError::Io(IoTapeError::Limit("encoded bytes")));
        }
        if entropy_len > limits.entropy.max_encoded_bytes {
            return Err(SessionTapeError::Entropy(EntropyTapeError::Limit(
                "encoded bytes",
            )));
        }
        if clock_len > limits.clock.max_encoded_bytes {
            return Err(SessionTapeError::Clock(TimeTapeError::Limit("encoded bytes")));
        }
        let mut expected = checksum(&bytes[..body_end]);
        let matches = expected.as_slice() == &bytes[body_end..];
        expected.zeroize();
        if !matches {
            return Err(SessionTapeError::Checksum);
        }
        let io = IoTape::from_canonical_bytes(&bytes[HEADER..io_end], limits.io)?;
        let entropy = EntropyTape::from_canonical_bytes(&bytes[io_end..entropy_end], limits.entropy)?;
        let clock = TimeTape::from_canonical_bytes(&bytes[entropy_end..body_end], limits.clock)?;
        Ok(Self { io, entropy, clock })
    }
}

#[cfg(test)]
mod tests;
