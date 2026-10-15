//! Explicit, bounded persistence for serial monotonic-clock observations.

use super::TimeTape;
use sha2::{Digest, Sha256};
use std::fmt;
use zeroize::Zeroize;

const MAGIC: &[u8; 8] = b"ASUPTM\0\0";
const VERSION: u32 = 1;
const HEADER_BYTES: usize = 20;
const SAMPLE_BYTES: usize = 8;
const CHECKSUM_BYTES: usize = 32;
const DOMAIN: &[u8] = b"asupersync.time-tape.v1";

/// Independent admission limits for an imported clock tape.
///
/// Zero limits are valid. An empty tape needs room for its header and checksum,
/// but no observations or decoded sample storage. Limits do not include the
/// caller's input allocation, allocator overhead, or fixed hashing workspace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeTapeDecodeLimits {
    /// Maximum complete encoding size, including header and checksum.
    pub max_encoded_bytes: usize,
    /// Maximum number of observations, including repeated timestamps.
    pub max_observations: usize,
    /// Maximum logical decoded sample storage, at eight bytes per observation.
    pub max_decoded_bytes: usize,
}

impl TimeTapeDecodeLimits {
    /// Set all import limits explicitly; no unbounded default is provided.
    #[must_use]
    pub const fn new(
        max_encoded_bytes: usize,
        max_observations: usize,
        max_decoded_bytes: usize,
    ) -> Self {
        Self {
            max_encoded_bytes,
            max_observations,
            max_decoded_bytes,
        }
    }
}

/// A clock-tape import or export failure without captured timestamps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TimeTapeError {
    /// The encoding does not contain all bytes required by its declared count.
    #[error("clock tape is truncated")]
    Truncated,
    /// Magic or version is unsupported; no best-effort conversion is attempted.
    #[error("unsupported clock tape format")]
    Format,
    /// Extra bytes follow the single declared tape.
    #[error("clock tape contains trailing data")]
    TrailingData,
    /// The complete body does not match its domain-separated checksum.
    #[error("clock tape checksum mismatch")]
    Checksum,
    /// A caller-selected resource ceiling was exceeded.
    #[error("clock tape exceeds its {0} limit")]
    Limit(&'static str),
    /// A count or size cannot be represented on this target.
    #[error("clock tape size overflow")]
    Overflow,
    /// An observation is earlier than its predecessor.
    #[error("clock tape is non-monotonic at observation {index}")]
    NonMonotonic {
        /// Zero-based position of the first backwards observation.
        index: usize,
    },
    /// Storage within the admitted bounds could not be reserved.
    #[error("clock tape allocation failed")]
    Allocation,
}

/// Owned sensitive clock-tape encoding, zeroized on drop.
///
/// Debug output shows only size. Copies and files made by the caller are not
/// zeroized by this owner. A checksum detects corruption, not malicious changes:
/// it is neither authentication nor encryption. Protect persisted captures with
/// caller-owned access controls and encryption/authentication as appropriate.
pub struct TimeTapeBytes(Vec<u8>);

impl fmt::Debug for TimeTapeBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TimeTapeBytes")
            .field("encoded_bytes", &self.0.len())
            .finish_non_exhaustive()
    }
}

impl AsRef<[u8]> for TimeTapeBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for TimeTapeBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

fn encoded_size(sample_bytes: usize) -> Result<usize, TimeTapeError> {
    HEADER_BYTES
        .checked_add(sample_bytes)
        .and_then(|size| size.checked_add(CHECKSUM_BYTES))
        .ok_or(TimeTapeError::Overflow)
}

fn read_u64(bytes: &[u8]) -> Result<u64, TimeTapeError> {
    bytes
        .try_into()
        .map(u64::from_le_bytes)
        .map_err(|_| TimeTapeError::Truncated)
}

fn checksum(bytes: &[u8]) -> [u8; CHECKSUM_BYTES] {
    let mut hash = Sha256::new();
    hash.update(DOMAIN);
    hash.update(bytes);
    hash.finalize().into()
}

impl TimeTape {
    /// Export a portable V1 encoding under an explicit byte ceiling.
    ///
    /// V1 is the eight-byte magic `ASUPTM\0\0`, a little-endian u32 version,
    /// a little-endian u64 observation count, that many little-endian u64
    /// nanosecond timestamps, then SHA-256 of `asupersync.time-tape.v1` followed
    /// by all preceding bytes. There are no platform tags or padding bytes.
    /// Absolute observations and duplicates are preserved without rebasing.
    ///
    /// Nothing is written to disk, and the original tape remains usable after
    /// either success or failure. The caller must preserve the relevant consumer
    /// version and call order separately; these bytes are not a scheduler trace
    /// or an authenticated statement about a particular application run.
    ///
    /// # Example
    ///
    /// ```
    /// use asupersync::time::{TimeSource, VirtualClock};
    /// use asupersync::time::replay::{RecordingTimeSource, TimeTape, TimeTapeDecodeLimits};
    /// use std::sync::Arc;
    ///
    /// let recorder = RecordingTimeSource::new(Arc::new(VirtualClock::new()), 4);
    /// let observed = [recorder.now(), recorder.now()];
    /// let tape = recorder.finish()?;
    /// let encoded = tape.to_canonical_bytes(1024)?;
    /// // Store/transmit these bytes only through caller-authorized storage.
    /// let restored = TimeTape::from_canonical_bytes(
    ///     encoded.as_ref(),
    ///     TimeTapeDecodeLimits::new(1024, 4, 32),
    /// )?;
    /// let replay = restored.replay();
    /// for expected in observed {
    ///     assert_eq!(replay.try_now()?, expected);
    /// }
    /// replay.verify_complete()?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn to_canonical_bytes(&self, max_encoded_bytes: usize) -> Result<TimeTapeBytes, TimeTapeError> {
        let count = u64::try_from(self.samples.len()).map_err(|_| TimeTapeError::Overflow)?;
        let sample_bytes = self
            .samples
            .len()
            .checked_mul(SAMPLE_BYTES)
            .ok_or(TimeTapeError::Overflow)?;
        let size = encoded_size(sample_bytes)?;
        if size > max_encoded_bytes {
            return Err(TimeTapeError::Limit("encoded bytes"));
        }
        let mut out = TimeTapeBytes(Vec::new());
        out.0
            .try_reserve_exact(size)
            .map_err(|_| TimeTapeError::Allocation)?;
        out.0.extend_from_slice(MAGIC);
        out.0.extend_from_slice(&VERSION.to_le_bytes());
        out.0.extend_from_slice(&count.to_le_bytes());
        for sample in &self.samples {
            out.0.extend_from_slice(&sample.to_le_bytes());
        }
        let mut digest = checksum(&out.0);
        out.0.extend_from_slice(&digest);
        digest.zeroize();
        debug_assert_eq!(out.0.len(), size);
        Ok(out)
    }

    /// Validate one complete encoding before allocating a replayable tape.
    ///
    /// Encoded size, observation count, decoded storage, integer overflow,
    /// framing, checksum, and monotonicity are all checked before allocating
    /// sample storage. Unknown formats, trailing bytes, and incomplete tapes
    /// are refused rather than silently converted or replayed as a prefix.
    /// Import does not read any clock and never adjusts captured timestamps.
    pub fn from_canonical_bytes(
        bytes: &[u8],
        limits: TimeTapeDecodeLimits,
    ) -> Result<Self, TimeTapeError> {
        if bytes.len() > limits.max_encoded_bytes {
            return Err(TimeTapeError::Limit("encoded bytes"));
        }
        if bytes.len() < HEADER_BYTES + CHECKSUM_BYTES {
            return Err(TimeTapeError::Truncated);
        }
        if &bytes[..8] != MAGIC || bytes[8..12] != VERSION.to_le_bytes() {
            return Err(TimeTapeError::Format);
        }
        let count = usize::try_from(read_u64(&bytes[12..HEADER_BYTES])?)
            .map_err(|_| TimeTapeError::Overflow)?;
        if count > limits.max_observations {
            return Err(TimeTapeError::Limit("observations"));
        }
        let sample_bytes = count
            .checked_mul(SAMPLE_BYTES)
            .ok_or(TimeTapeError::Overflow)?;
        if sample_bytes > limits.max_decoded_bytes {
            return Err(TimeTapeError::Limit("decoded bytes"));
        }
        let size = encoded_size(sample_bytes)?;
        if bytes.len() < size {
            return Err(TimeTapeError::Truncated);
        }
        if bytes.len() > size {
            return Err(TimeTapeError::TrailingData);
        }
        let body_len = size - CHECKSUM_BYTES;
        let mut expected = checksum(&bytes[..body_len]);
        let matches = expected.as_slice() == &bytes[body_len..];
        expected.zeroize();
        if !matches {
            return Err(TimeTapeError::Checksum);
        }
        let payload = &bytes[HEADER_BYTES..body_len];
        let mut previous = 0;
        for (index, chunk) in payload.chunks_exact(SAMPLE_BYTES).enumerate() {
            let sample = read_u64(chunk)?;
            if sample < previous {
                return Err(TimeTapeError::NonMonotonic { index });
            }
            previous = sample;
        }
        // All structure has been admitted. Reserve once and never expose a
        // partially decoded prefix, including on allocation failure.
        let mut tape = Self {
            samples: Vec::new(),
        };
        tape.samples
            .try_reserve_exact(count)
            .map_err(|_| TimeTapeError::Allocation)?;
        for chunk in payload.chunks_exact(SAMPLE_BYTES) {
            tape.samples.push(read_u64(chunk)?);
        }
        Ok(tape)
    }
}

#[cfg(test)]
mod tests;
