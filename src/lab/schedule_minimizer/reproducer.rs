//! Portable executable recipes for minimized lab failures.
//!
//! A recipe carries the complete canonical source schedule, an ordered subset
//! of its dispatch indices, a caller-defined workload key, and the expected
//! failure key. It never serializes closures, fixtures, file paths or authority
//! to execute code. The consumer must supply the matching workload factory.
//!
//! Decoding establishes integrity and shape, NOT that a failure reproduces.
//! Checksums are not signatures; a caller must treat all decoded recipes as
//! unverified and run them again. No minimization or verification result is
//! inferred from a stored test count. Strict source replay remains distinct
//! from replaying the retained subsequence.
//!
//! Codec bounds cover encoded bytes and the requested source/index vector
//! storage, not allocator overhead. The nested source codec may temporarily
//! re-encode its source within the admitted encoded-byte bound. This module
//! does not perform ambient filesystem or network I/O.

use super::{FailureKey, MinimizedSchedule};
use crate::lab::runtime::{
    ForcedDispatch, ForcedSchedule, ForcedScheduleArtifactError, ForcedScheduleCandidate,
    ForcedScheduleCandidateLimits, ForcedScheduleDecodeLimits, ForcedScheduleError,
};
use sha2::{Digest, Sha256};

/// Magic prefix of a portable minimized-schedule recipe.
pub const REPRODUCER_MAGIC: [u8; 8] = *b"ASUPRPR\0";
/// Canonical fixed-width, little-endian recipe format version.
pub const REPRODUCER_VERSION: u32 = 1;
const HEADER_BYTES: usize = 124;
const CHECKSUM_BYTES: usize = 32;
const CHECKSUM_DOMAIN: &[u8] = b"asupersync.lab.schedule-reproducer.v1\0";
const SOURCE_DOMAIN: &[u8] = b"asupersync.lab.schedule-minimizer.source.v1\0";

/// Caller-defined identity of workload code, fixture inputs and their schema.
///
/// Use a domain-separated digest over those inputs. This is an explicit
/// identity check, not a claim that arbitrary callbacks can be authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WorkloadKey(pub [u8; 32]);

/// Explicit admission bounds; zero count limits admit only empty vectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReproducerLimits {
    /// Maximum entire encoded recipe, including source and checksums.
    pub max_encoded_bytes: usize,
    /// Maximum number of source dispatches.
    pub max_source_dispatches: usize,
    /// Maximum number of retained source indices.
    pub max_retained_dispatches: usize,
    /// Maximum requested source-dispatch plus retained-index vector bytes.
    pub max_decoded_dispatch_bytes: usize,
}

/// A bounded replay recipe. Loading one never certifies a reproduction.
///
/// The source cannot be mutated through this type. Consequently the cached
/// encoded length remains exact and encoders can reject an insufficient byte
/// limit before allocating either the source encoding or the outer buffer.
#[derive(Debug)]
pub struct ScheduleReproducer {
    source: ForcedSchedule,
    source_encoded_len: usize,
    retained: Vec<usize>,
    workload: WorkloadKey,
    failure: FailureKey,
    source_digest: [u8; 32],
}

/// Malformed, mismatched or over-budget replay recipe.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum ReproducerError {
    /// Unsupported magic or version.
    #[error("unrecognized schedule reproducer format")]
    Format,
    /// The supplied bytes do not have their exact declared length.
    #[error("schedule reproducer has truncated or trailing bytes")]
    Length,
    /// Checked count/size arithmetic overflowed, including pointer-width conversion.
    #[error("schedule reproducer length overflow")]
    Overflow,
    /// The encoded-byte admission was exceeded.
    #[error("schedule reproducer encoded byte limit exceeded")]
    ByteLimit,
    /// The source dispatch admission was exceeded.
    #[error("schedule reproducer source dispatch limit exceeded")]
    SourceLimit,
    /// The retained dispatch admission was exceeded.
    #[error("schedule reproducer retained dispatch limit exceeded")]
    RetainedLimit,
    /// Combined decoded vector storage exceeds admission.
    #[error("schedule reproducer decoded vector limit exceeded")]
    DecodedLimit,
    /// Outer integrity checksum mismatch.
    #[error("schedule reproducer checksum mismatch")]
    Checksum,
    /// Source digest does not match the exact canonical source bytes.
    #[error("schedule reproducer source digest mismatch")]
    SourceDigest,
    /// A minimizer result was paired with a different complete source.
    #[error("minimized result belongs to a different source schedule")]
    ResultSourceMismatch,
    /// Retained indices are not strictly increasing or reference missing source choices.
    #[error("invalid retained source index at position {position}")]
    Index {
        /// Position in the retained subsequence, not a source dispatch index.
        position: usize,
    },
    /// Invalid nested complete schedule; strict source codec semantics are retained.
    #[error("invalid reproducer source: {0}")]
    Source(#[from] ForcedScheduleArtifactError),
    /// A bounded vector allocation failed.
    #[error("could not allocate schedule reproducer storage")]
    Allocation,
}

fn digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(bytes);
    hash.finalize().into()
}

fn encoded_len(source_len: usize, retained: usize) -> Result<usize, ReproducerError> {
    retained
        .checked_mul(8)
        .and_then(|len| len.checked_add(source_len))
        .and_then(|len| len.checked_add(HEADER_BYTES + CHECKSUM_BYTES))
        .ok_or(ReproducerError::Overflow)
}

fn index_bytes(count: usize, limits: ReproducerLimits) -> Result<usize, ReproducerError> {
    if count > limits.max_retained_dispatches {
        return Err(ReproducerError::RetainedLimit);
    }
    let bytes = count
        .checked_mul(std::mem::size_of::<usize>())
        .ok_or(ReproducerError::Overflow)?;
    if bytes > limits.max_decoded_dispatch_bytes {
        return Err(ReproducerError::DecodedLimit);
    }
    Ok(bytes)
}

fn check_counts(
    source: usize,
    retained: usize,
    limits: ReproducerLimits,
) -> Result<(), ReproducerError> {
    if source > limits.max_source_dispatches {
        return Err(ReproducerError::SourceLimit);
    }
    let retained_bytes = index_bytes(retained, limits)?;
    let bytes = source
        .checked_mul(std::mem::size_of::<ForcedDispatch>())
        .and_then(|n| n.checked_add(retained_bytes))
        .ok_or(ReproducerError::Overflow)?;
    if bytes > limits.max_decoded_dispatch_bytes {
        return Err(ReproducerError::DecodedLimit);
    }
    Ok(())
}

fn read_array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], ReproducerError> {
    let end = offset.checked_add(N).ok_or(ReproducerError::Overflow)?;
    let slice = bytes.get(offset..end).ok_or(ReproducerError::Length)?;
    let mut out = [0; N];
    out.copy_from_slice(slice);
    Ok(out)
}

fn read_count(bytes: &[u8], offset: usize) -> Result<usize, ReproducerError> {
    usize::try_from(u64::from_le_bytes(read_array(bytes, offset)?))
        .map_err(|_| ReproducerError::Overflow)
}

fn validate_index(
    index: usize,
    previous: Option<usize>,
    source_len: usize,
    position: usize,
) -> Result<(), ReproducerError> {
    if index >= source_len || previous.is_some_and(|last| index <= last) {
        return Err(ReproducerError::Index { position });
    }
    Ok(())
}

impl ScheduleReproducer {
    /// Bind a minimizer result to its exact complete source and workload.
    ///
    /// Takes ownership of the source but leaves the minimizer result available
    /// to the caller. Source/count admission precedes encoding or index copies.
    /// This preserves the result's historical identity, not fresh verification.
    ///
    /// # Errors
    /// Refuses a partial source, mismatched digest, invalid indices or exceeded bounds.
    pub fn from_minimized(
        source: ForcedSchedule,
        minimized: &MinimizedSchedule,
        workload: WorkloadKey,
        limits: ReproducerLimits,
    ) -> Result<Self, ReproducerError> {
        let indices = minimized.retained_source_indices();
        check_counts(source.dispatches().len(), indices.len(), limits)?;
        let source_bytes = source.to_canonical_bytes()?;
        if encoded_len(source_bytes.len(), indices.len())? > limits.max_encoded_bytes {
            return Err(ReproducerError::ByteLimit);
        }
        let source_digest = digest(SOURCE_DOMAIN, &source_bytes);
        if &source_digest != minimized.source_digest() {
            return Err(ReproducerError::ResultSourceMismatch);
        }
        let mut previous = None;
        for (position, &index) in indices.iter().enumerate() {
            validate_index(index, previous, source.dispatches().len(), position)?;
            previous = Some(index);
        }
        let mut retained = Vec::new();
        retained
            .try_reserve_exact(indices.len())
            .map_err(|_| ReproducerError::Allocation)?;
        retained.extend_from_slice(indices);
        Ok(Self {
            source,
            source_encoded_len: source_bytes.len(),
            retained,
            workload,
            failure: minimized.failure(),
            source_digest,
        })
    }

    /// Encode a canonical recipe, refusing a too-small bound before allocation.
    ///
    /// # Errors
    /// Refuses insufficient byte admission, arithmetic overflow or allocation failure.
    pub fn to_canonical_bytes(&self, max_encoded_bytes: usize) -> Result<Vec<u8>, ReproducerError> {
        let len = encoded_len(self.source_encoded_len, self.retained.len())?;
        if len > max_encoded_bytes {
            return Err(ReproducerError::ByteLimit);
        }
        let source = self.source.to_canonical_bytes()?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(len)
            .map_err(|_| ReproducerError::Allocation)?;
        bytes.extend_from_slice(&REPRODUCER_MAGIC);
        bytes.extend_from_slice(&REPRODUCER_VERSION.to_le_bytes());
        let source_len = u64::try_from(source.len()).map_err(|_| ReproducerError::Overflow)?;
        let count = u64::try_from(self.retained.len()).map_err(|_| ReproducerError::Overflow)?;
        bytes.extend_from_slice(&source_len.to_le_bytes());
        bytes.extend_from_slice(&count.to_le_bytes());
        bytes.extend_from_slice(&self.workload.0);
        bytes.extend_from_slice(&self.failure.0);
        bytes.extend_from_slice(&self.source_digest);
        bytes.extend_from_slice(&source);
        for &index in &self.retained {
            let index = u64::try_from(index).map_err(|_| ReproducerError::Overflow)?;
            bytes.extend_from_slice(&index.to_le_bytes());
        }
        let checksum = digest(CHECKSUM_DOMAIN, &bytes);
        bytes.extend_from_slice(&checksum);
        debug_assert_eq!(bytes.len(), len);
        Ok(bytes)
    }

    /// Decode an unverified recipe with bounded nested source and index storage.
    ///
    /// Exact length, index storage admission and the outer checksum are checked
    /// before source decoding. The original strict source codec rejects partial
    /// receipts. Index order/range is scanned before allocating the index vector.
    ///
    /// # Errors
    /// Refuses unsupported, corrupted, incomplete, noncanonical or over-budget input.
    pub fn try_from_canonical_bytes(
        bytes: &[u8],
        limits: ReproducerLimits,
    ) -> Result<Self, ReproducerError> {
        if bytes.len() > limits.max_encoded_bytes {
            return Err(ReproducerError::ByteLimit);
        }
        if bytes.len() < HEADER_BYTES + CHECKSUM_BYTES {
            return Err(ReproducerError::Length);
        }
        if read_array::<8>(bytes, 0)? != REPRODUCER_MAGIC
            || u32::from_le_bytes(read_array(bytes, 8)?) != REPRODUCER_VERSION
        {
            return Err(ReproducerError::Format);
        }
        let source_len = read_count(bytes, 12)?;
        let count = read_count(bytes, 20)?;
        let retained_bytes = index_bytes(count, limits)?;
        if encoded_len(source_len, count)? != bytes.len() {
            return Err(ReproducerError::Length);
        }
        let checksum_offset = bytes.len() - CHECKSUM_BYTES;
        if bytes[checksum_offset..] != digest(CHECKSUM_DOMAIN, &bytes[..checksum_offset]) {
            return Err(ReproducerError::Checksum);
        }
        // Exact total length established that these additions fit in usize.
        let source_end = HEADER_BYTES + source_len;
        let source_bytes = &bytes[HEADER_BYTES..source_end];
        let source_digest = read_array::<32>(bytes, 92)?;
        if source_digest != digest(SOURCE_DOMAIN, source_bytes) {
            return Err(ReproducerError::SourceDigest);
        }
        let source = ForcedSchedule::try_from_canonical_bytes(
            source_bytes,
            ForcedScheduleDecodeLimits::new(
                source_len,
                limits.max_source_dispatches,
                limits.max_decoded_dispatch_bytes - retained_bytes,
            ),
        )?;
        let mut previous = None;
        for position in 0..count {
            let index = read_count(bytes, source_end + position * 8)?;
            validate_index(index, previous, source.dispatches().len(), position)?;
            previous = Some(index);
        }
        let mut retained = Vec::new();
        retained
            .try_reserve_exact(count)
            .map_err(|_| ReproducerError::Allocation)?;
        for position in 0..count {
            retained.push(read_count(bytes, source_end + position * 8)?);
        }
        Ok(Self {
            source,
            source_encoded_len: source_len,
            retained,
            workload: WorkloadKey(read_array(bytes, 28)?),
            failure: FailureKey(read_array(bytes, 60)?),
            source_digest,
        })
    }

    /// Complete source receipt; no mutable access is exposed.
    #[must_use]
    pub const fn source(&self) -> &ForcedSchedule {
        &self.source
    }

    /// Source indices of the proposed reproduction, in original order.
    #[must_use]
    pub fn retained_source_indices(&self) -> &[usize] {
        &self.retained
    }

    /// Caller-defined workload and fixture identity.
    #[must_use]
    pub const fn workload(&self) -> WorkloadKey {
        self.workload
    }

    /// Failure to verify on both the strict source and the reduced candidate.
    #[must_use]
    pub const fn failure(&self) -> FailureKey {
        self.failure
    }

    /// Derive executable candidate authority without claiming it reproduced.
    ///
    /// # Errors
    /// Refuses a zero or insufficient work bound and bounded allocation failures.
    pub fn candidate(
        &self,
        max_work_units: u64,
    ) -> Result<ForcedScheduleCandidate, ForcedScheduleError> {
        self.source.derive_candidate(
            &self.retained,
            ForcedScheduleCandidateLimits::new(
                self.source.dispatches().len().max(1),
                self.retained.len().max(1),
                max_work_units,
            ),
        )
    }
}

#[cfg(test)]
mod tests;
