//! Explicit, bounded persistence for sensitive entropy tapes.

use super::{EntropyCaptureLimits, EntropyTape, Event};
use sha2::{Digest, Sha256};
use std::fmt;
use zeroize::Zeroize;

const MAGIC: &[u8; 8] = b"ASUPENT\0";
const VERSION: u32 = 1;
const HEADER: usize = 36;
const CHECKSUM: usize = 32;
const DOMAIN: &[u8] = b"asupersync.entropy-tape.v1";

/// Admission bounds checked before allocating a decoded tape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntropyTapeDecodeLimits {
    /// Maximum entire encoded input, including its checksum.
    pub max_encoded_bytes: usize,
    /// Maximum events, random bytes, and sources admitted from the header.
    pub capture: EntropyCaptureLimits,
    /// Maximum logical decoded storage: vectors, events, payload and temporary
    /// fork-validation bitmap. Excludes allocator overhead and replay cursors.
    pub max_decoded_bytes: usize,
}

impl EntropyTapeDecodeLimits {
    /// Set encoded, logical-count, and decoded-storage bounds explicitly.
    #[must_use]
    pub const fn new(
        max_encoded_bytes: usize,
        capture: EntropyCaptureLimits,
        max_decoded_bytes: usize,
    ) -> Self {
        Self {
            max_encoded_bytes,
            capture,
            max_decoded_bytes,
        }
    }
}

/// Invalid, corrupted, oversized, or unallocatable tape. No payload is printed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EntropyTapeError {
    /// The input does not contain the full declared encoding.
    #[error("entropy tape is truncated")]
    Truncated,
    /// Unsupported magic or version.
    #[error("unsupported entropy tape format")]
    Format,
    /// Domain-separated checksum did not match.
    #[error("entropy tape checksum mismatch")]
    Checksum,
    /// An explicit caller resource ceiling was exceeded.
    #[error("entropy tape exceeds {0} limit")]
    Limit(&'static str),
    /// Counts, event tags, or fork topology were inconsistent.
    #[error("invalid entropy tape structure: {0}")]
    Invalid(&'static str),
    /// The declared size is not representable on this target.
    #[error("entropy tape size overflow")]
    Overflow,
    /// Bounded storage could not be allocated.
    #[error("entropy tape allocation failed")]
    Allocation,
}

/// Sensitive canonical bytes.
///
/// Debug shows only their length; Drop zeroizes the owned buffer. `as_ref()`
/// exposes plaintext deliberately for caller-owned encrypted storage or
/// transport. Copies and persisted files are the caller's responsibility. This
/// encoding provides integrity, NOT confidentiality or authenticity, and must
/// not be placed in ordinary diagnostic artifacts.
pub struct EntropyTapeBytes(Vec<u8>);

impl fmt::Debug for EntropyTapeBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EntropyTapeBytes")
            .field("encoded_bytes", &self.0.len())
            .finish_non_exhaustive()
    }
}

impl AsRef<[u8]> for EntropyTapeBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for EntropyTapeBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

fn add(a: usize, b: usize) -> Result<usize, EntropyTapeError> {
    a.checked_add(b).ok_or(EntropyTapeError::Overflow)
}

fn mul(a: usize, b: usize) -> Result<usize, EntropyTapeError> {
    a.checked_mul(b).ok_or(EntropyTapeError::Overflow)
}

fn put_size(out: &mut Vec<u8>, size: usize) -> Result<(), EntropyTapeError> {
    let size = u64::try_from(size).map_err(|_| EntropyTapeError::Overflow)?;
    out.extend_from_slice(&size.to_le_bytes());
    Ok(())
}

fn checksum(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(DOMAIN);
    hash.update(bytes);
    hash.finalize().into()
}

impl EntropyTape {
    /// Encode without consuming the tape, under an explicit output bound.
    ///
    /// V1 is little-endian: magic\[8\], version:u32, source/call/random-byte
    /// counts:u64, then one call count:u64 per source followed by its events.
    /// Tags are 0 (length:u64 + bytes), 1 (u64), and 2 (task:u64 + child:u64).
    /// A domain-separated SHA-256 covers every preceding byte. Forks refer to
    /// flat source ordinals; no recursion or RNG state reconstruction is used.
    pub fn to_canonical_bytes(
        &self,
        max_encoded_bytes: usize,
    ) -> Result<EntropyTapeBytes, EntropyTapeError> {
        let mut size = add(HEADER, CHECKSUM)?;
        size = add(size, mul(self.streams.len(), 8)?)?;
        for stream in &self.streams {
            for event in stream {
                size = add(
                    size,
                    match event {
                        Event::Bytes(bytes) => add(9, bytes.len())?,
                        Event::U64(_) => 9,
                        Event::Fork { .. } => 17,
                    },
                )?;
            }
        }
        if size > max_encoded_bytes {
            return Err(EntropyTapeError::Limit("encoded bytes"));
        }
        let mut out = EntropyTapeBytes(Vec::new());
        out.0
            .try_reserve_exact(size)
            .map_err(|_| EntropyTapeError::Allocation)?;
        out.0.extend_from_slice(MAGIC);
        out.0.extend_from_slice(&VERSION.to_le_bytes());
        put_size(&mut out.0, self.streams.len())?;
        put_size(&mut out.0, self.calls)?;
        put_size(&mut out.0, self.bytes)?;
        for stream in &self.streams {
            put_size(&mut out.0, stream.len())?;
            for event in stream {
                match event {
                    Event::Bytes(bytes) => {
                        out.0.push(0);
                        put_size(&mut out.0, bytes.len())?;
                        out.0.extend_from_slice(bytes);
                    }
                    Event::U64(value) => {
                        out.0.push(1);
                        out.0.extend_from_slice(&value.to_le_bytes());
                    }
                    Event::Fork { task, child } => {
                        out.0.push(2);
                        out.0.extend_from_slice(&task.to_le_bytes());
                        put_size(&mut out.0, *child)?;
                    }
                }
            }
        }
        let digest = checksum(&out.0);
        out.0.extend_from_slice(&digest);
        debug_assert_eq!(out.0.len(), size);
        Ok(out)
    }

    /// Validate and decode an explicitly supplied sensitive tape.
    ///
    /// Validates limits and checksum before allocating tape data, then exact
    /// counts, tags, one-parent forward-only fork topology and full input
    /// consumption. Rejects trailing bytes, partial captures and forged sizes.
    /// The checksum detects corruption, not a malicious author: trust and
    /// encryption of the input remain the caller's responsibility.
    pub fn from_canonical_bytes(
        bytes: &[u8],
        limits: EntropyTapeDecodeLimits,
    ) -> Result<Self, EntropyTapeError> {
        if bytes.len() > limits.max_encoded_bytes {
            return Err(EntropyTapeError::Limit("encoded bytes"));
        }
        if bytes.len() < HEADER + CHECKSUM {
            return Err(EntropyTapeError::Truncated);
        }
        let body_len = bytes.len() - CHECKSUM;
        let mut input = Input {
            bytes: &bytes[..body_len],
            offset: 0,
        };
        if input.take(8)? != MAGIC || input.u32()? != VERSION {
            return Err(EntropyTapeError::Format);
        }
        let streams = input.size()?;
        let calls = input.size()?;
        let random_bytes = input.size()?;
        if streams == 0 {
            return Err(EntropyTapeError::Invalid("missing root"));
        }
        if streams > limits.capture.max_streams {
            return Err(EntropyTapeError::Limit("sources"));
        }
        if calls > limits.capture.max_calls {
            return Err(EntropyTapeError::Limit("calls"));
        }
        if random_bytes > limits.capture.max_bytes {
            return Err(EntropyTapeError::Limit("random bytes"));
        }
        if streams - 1 > calls {
            return Err(EntropyTapeError::Invalid("missing fork calls"));
        }
        let minimum = add(add(HEADER, mul(streams, 8)?)?, add(calls, random_bytes)?)?;
        if minimum > body_len {
            return Err(EntropyTapeError::Truncated);
        }
        let decoded = add(
            add(
                mul(streams, std::mem::size_of::<Vec<Event>>())?,
                mul(calls, std::mem::size_of::<Event>())?,
            )?,
            add(random_bytes, streams)?,
        )?;
        if decoded > limits.max_decoded_bytes {
            return Err(EntropyTapeError::Limit("decoded bytes"));
        }
        if checksum(&bytes[..body_len])[..] != bytes[body_len..] {
            return Err(EntropyTapeError::Checksum);
        }
        let mut result = Vec::new();
        result
            .try_reserve_exact(streams)
            .map_err(|_| EntropyTapeError::Allocation)?;
        let mut parents = Vec::new();
        parents
            .try_reserve_exact(streams)
            .map_err(|_| EntropyTapeError::Allocation)?;
        parents.resize(streams, false);
        parents[0] = true;
        let mut seen_calls = 0usize;
        let mut seen_bytes = 0usize;
        for source in 0..streams {
            let count = input.size()?;
            if count > calls - seen_calls {
                return Err(EntropyTapeError::Invalid("call count"));
            }
            let mut events = Vec::new();
            events
                .try_reserve_exact(count)
                .map_err(|_| EntropyTapeError::Allocation)?;
            for _ in 0..count {
                let event = match input.take(1)?[0] {
                    0 => {
                        let length = input.size()?;
                        if length > random_bytes - seen_bytes {
                            return Err(EntropyTapeError::Invalid("byte count"));
                        }
                        let payload = input.take(length)?;
                        let mut data = Vec::new();
                        data.try_reserve_exact(length)
                            .map_err(|_| EntropyTapeError::Allocation)?;
                        data.extend_from_slice(payload);
                        seen_bytes += length;
                        Event::Bytes(data)
                    }
                    1 => {
                        if random_bytes - seen_bytes < 8 {
                            return Err(EntropyTapeError::Invalid("u64 byte count"));
                        }
                        let value = input.u64()?;
                        seen_bytes += 8;
                        Event::U64(value)
                    }
                    2 => {
                        let task = input.u64()?;
                        let child = input.size()?;
                        if child <= source || child >= streams || parents[child] {
                            return Err(EntropyTapeError::Invalid("fork topology"));
                        }
                        parents[child] = true;
                        Event::Fork { task, child }
                    }
                    _ => return Err(EntropyTapeError::Invalid("event tag")),
                };
                events.push(event);
            }
            seen_calls += count;
            result.push(events);
        }
        if seen_calls != calls || seen_bytes != random_bytes {
            return Err(EntropyTapeError::Invalid("aggregate counts"));
        }
        if parents.iter().any(|seen| !seen) {
            return Err(EntropyTapeError::Invalid("unreachable source"));
        }
        if input.offset != body_len {
            return Err(EntropyTapeError::Invalid("trailing bytes"));
        }
        Ok(Self {
            streams: result,
            calls,
            bytes: random_bytes,
        })
    }
}

struct Input<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Input<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], EntropyTapeError> {
        let end = add(self.offset, length)?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(EntropyTapeError::Truncated)?;
        self.offset = end;
        Ok(bytes)
    }

    fn u32(&mut self) -> Result<u32, EntropyTapeError> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().expect("four bytes"),
        ))
    }

    fn u64(&mut self) -> Result<u64, EntropyTapeError> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().expect("eight bytes"),
        ))
    }

    fn size(&mut self) -> Result<usize, EntropyTapeError> {
        usize::try_from(self.u64()?).map_err(|_| EntropyTapeError::Overflow)
    }
}

#[cfg(test)]
#[path = "codec_inline_tests.rs"]
mod tests;
