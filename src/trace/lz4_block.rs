//! Safe, resource-bounded LZ4 block codec for the trace replacement experiment.
//!
//! This module implements only the format frozen by
//! `artifacts/lz4_surface_artifact_inventory_v1.json`:
//!
//! - a four-byte little-endian uncompressed-size prefix;
//! - one independent LZ4 block;
//! - no frame headers, dictionaries, or LZ4-native checksums.
//!
//! The module is deliberately private and has no production caller. A2 owns the
//! finite codec; A3 owns independent vectors and fuzzing, while A4 owns any
//! trace reader/writer integration.

#![forbid(unsafe_code)]

use std::error::Error as StdError;
use std::fmt;

const SIZE_PREFIX_LEN: usize = 4;
const MIN_MATCH_LEN: usize = 4;
const LAST_LITERALS: usize = 5;
const LAST_MATCH_START_DISTANCE: usize = 12;
const MIN_COMPRESSIBLE_BLOCK_LEN: usize = LAST_MATCH_START_DISTANCE + 1;
const MAX_MATCH_OFFSET: usize = u16::MAX as usize;
const HASH_LOG: u32 = 16;
const HASH_TABLE_LEN: usize = 1 << HASH_LOG;
const HASH_MULTIPLIER: u32 = 2_654_435_761;
const EMPTY_HASH_SLOT: usize = usize::MAX;
const TRACE_LIMIT_BYTES: usize = 64 * 1024 * 1024;

/// Default maximum decoded-to-compressed ratio.
///
/// The LZ4 block format's length extension gives an asymptotic ratio below
/// 256:1. Keeping the explicit ceiling at 256 admits conforming blocks while
/// failing closed on impossible size prefixes before allocation.
const DEFAULT_MAX_EXPANSION_RATIO: usize = 256;

const LZ4_FRAME_MAGIC: [u8; 4] = [0x04, 0x22, 0x4d, 0x18];
const LZ4_LEGACY_FRAME_MAGIC: [u8; 4] = [0x02, 0x21, 0x4c, 0x18];
const LZ4_SKIPPABLE_MAGIC_MASK: u32 = 0xffff_fff0;
const LZ4_SKIPPABLE_MAGIC: u32 = 0x184d_2a50;

/// Resource limits applied before allocation and during every output append.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Limits {
    /// Maximum uncompressed input accepted by the encoder.
    pub(super) max_input_bytes: usize,
    /// Maximum complete size-prepended block accepted or emitted.
    pub(super) max_compressed_bytes: usize,
    /// Maximum advertised and actual decompressed output.
    pub(super) max_decompressed_bytes: usize,
    /// Maximum decoded-to-compressed-body ratio.
    pub(super) max_expansion_ratio: usize,
}

impl Limits {
    /// Limits matching the trace reader's current 64 MiB chunk envelope.
    pub(super) const TRACE: Self = Self {
        max_input_bytes: TRACE_LIMIT_BYTES,
        max_compressed_bytes: TRACE_LIMIT_BYTES,
        max_decompressed_bytes: TRACE_LIMIT_BYTES,
        max_expansion_ratio: DEFAULT_MAX_EXPANSION_RATIO,
    };

    fn validate(self) -> Result<(), Error> {
        if self.max_expansion_ratio == 0 {
            return Err(Error::InvalidLimits {
                reason: "max_expansion_ratio must be non-zero",
            });
        }
        Ok(())
    }
}

/// Unsupported LZ4 container identified before interpreting a size prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum UnsupportedContainer {
    /// Standard LZ4 frame format.
    Frame,
    /// Legacy LZ4 frame format.
    LegacyFrame,
    /// Skippable LZ4 frame.
    SkippableFrame,
}

impl fmt::Display for UnsupportedContainer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Frame => "LZ4 frame",
            Self::LegacyFrame => "legacy LZ4 frame",
            Self::SkippableFrame => "skippable LZ4 frame",
        })
    }
}

/// Safe codec failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Error {
    /// Limits cannot express a valid bounded operation.
    InvalidLimits {
        /// Static reason for rejecting the limits.
        reason: &'static str,
    },
    /// Encoder input exceeds its configured ceiling.
    InputTooLarge {
        /// Actual input bytes.
        actual: usize,
        /// Configured ceiling.
        max: usize,
    },
    /// Encoder input cannot fit the persisted u32 size prefix.
    InputLengthNotRepresentable {
        /// Actual input bytes.
        actual: usize,
    },
    /// Complete compressed input exceeds its configured ceiling.
    CompressedInputTooLarge {
        /// Actual compressed bytes, including the size prefix.
        actual: usize,
        /// Configured ceiling.
        max: usize,
    },
    /// Encoder output would exceed its configured ceiling.
    CompressedOutputTooLarge {
        /// Minimum bytes required by the attempted append.
        needed: usize,
        /// Configured ceiling.
        max: usize,
    },
    /// Input is shorter than the four-byte size prefix.
    MissingSizePrefix {
        /// Actual input bytes.
        actual: usize,
    },
    /// A frame container was supplied where the trace contract requires a block.
    UnsupportedContainer {
        /// Identified container.
        container: UnsupportedContainer,
    },
    /// Advertised output exceeds its configured ceiling.
    AdvertisedOutputTooLarge {
        /// Advertised output bytes.
        actual: usize,
        /// Configured ceiling.
        max: usize,
    },
    /// Advertised output exceeds the maximum possible block expansion.
    ExpansionRatioExceeded {
        /// Advertised output bytes.
        advertised: usize,
        /// Compressed block bytes, excluding the size prefix.
        compressed: usize,
        /// Configured ratio ceiling.
        max_ratio: usize,
    },
    /// A required token, length byte, literal, or offset is truncated.
    UnexpectedEnd {
        /// Field being decoded.
        field: &'static str,
        /// Byte offset within the block body.
        at: usize,
    },
    /// A length extension overflowed the host integer.
    LengthOverflow {
        /// Length field being decoded.
        field: &'static str,
    },
    /// A literal run crosses the compressed input boundary.
    LiteralOutOfBounds {
        /// Requested literal bytes.
        length: usize,
        /// Remaining compressed bytes.
        remaining: usize,
    },
    /// Decoded bytes would exceed the advertised output length.
    OutputLengthExceeded {
        /// Minimum decoded bytes required by the sequence.
        needed: usize,
        /// Advertised output bytes.
        advertised: usize,
    },
    /// Match offset zero is invalid in the LZ4 block format.
    OffsetZero {
        /// Offset byte position within the block body.
        at: usize,
    },
    /// Match refers to bytes before this independent block.
    ExternalDictionaryRequired {
        /// Requested match offset.
        offset: usize,
        /// Bytes already produced by this independent block.
        produced: usize,
    },
    /// A structurally decodable block violates a canonical end condition.
    NonCanonicalBlock {
        /// Static canonicality rule.
        rule: &'static str,
    },
    /// Actual decoded length differs from the persisted size prefix.
    OutputLengthMismatch {
        /// Persisted output length.
        advertised: usize,
        /// Actual decoded bytes.
        actual: usize,
    },
    /// A bounded allocation could not be reserved.
    AllocationFailed {
        /// Bytes or entries requested.
        requested: usize,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits { reason } => write!(formatter, "invalid LZ4 limits: {reason}"),
            Self::InputTooLarge { actual, max } => {
                write!(formatter, "LZ4 input has {actual} bytes; maximum is {max}")
            }
            Self::InputLengthNotRepresentable { actual } => write!(
                formatter,
                "LZ4 input has {actual} bytes and cannot fit the u32 size prefix"
            ),
            Self::CompressedInputTooLarge { actual, max } => write!(
                formatter,
                "size-prepended LZ4 input has {actual} bytes; maximum is {max}"
            ),
            Self::CompressedOutputTooLarge { needed, max } => write!(
                formatter,
                "size-prepended LZ4 output needs at least {needed} bytes; maximum is {max}"
            ),
            Self::MissingSizePrefix { actual } => write!(
                formatter,
                "size-prepended LZ4 input needs four prefix bytes; found {actual}"
            ),
            Self::UnsupportedContainer { container } => write!(
                formatter,
                "{container} is unsupported; ASUPERTRACE uses one size-prepended LZ4 block"
            ),
            Self::AdvertisedOutputTooLarge { actual, max } => write!(
                formatter,
                "LZ4 block advertises {actual} output bytes; maximum is {max}"
            ),
            Self::ExpansionRatioExceeded {
                advertised,
                compressed,
                max_ratio,
            } => write!(
                formatter,
                "LZ4 block advertises {advertised} bytes from {compressed} compressed bytes; maximum ratio is {max_ratio}:1"
            ),
            Self::UnexpectedEnd { field, at } => {
                write!(formatter, "truncated LZ4 {field} at block byte {at}")
            }
            Self::LengthOverflow { field } => {
                write!(formatter, "LZ4 {field} overflows the host integer")
            }
            Self::LiteralOutOfBounds { length, remaining } => write!(
                formatter,
                "LZ4 literal run needs {length} bytes but only {remaining} remain"
            ),
            Self::OutputLengthExceeded { needed, advertised } => write!(
                formatter,
                "LZ4 sequence needs {needed} decoded bytes but prefix advertises {advertised}"
            ),
            Self::OffsetZero { at } => {
                write!(formatter, "LZ4 match offset is zero at block byte {at}")
            }
            Self::ExternalDictionaryRequired { offset, produced } => write!(
                formatter,
                "LZ4 match offset {offset} exceeds {produced} produced bytes; external dictionaries are unsupported"
            ),
            Self::NonCanonicalBlock { rule } => {
                write!(formatter, "non-canonical LZ4 block: {rule}")
            }
            Self::OutputLengthMismatch { advertised, actual } => write!(
                formatter,
                "LZ4 size prefix advertises {advertised} bytes but block produced {actual}"
            ),
            Self::AllocationFailed { requested } => {
                write!(
                    formatter,
                    "failed to reserve bounded LZ4 storage for {requested} entries"
                )
            }
        }
    }
}

impl StdError for Error {}

/// Deterministically encode one independent size-prepended LZ4 block.
///
/// The encoder uses a fixed-size last-seen hash table and never consults
/// ambient state. Its bytes are accepted by the incumbent decoder; byte-for-
/// byte equality with the incumbent encoder is not claimed by A2.
///
/// # Errors
///
/// Returns an error before exceeding `limits`, when the input cannot fit the
/// persisted u32 prefix, or when bounded storage cannot be reserved.
pub(super) fn encode_size_prepended(input: &[u8], limits: Limits) -> Result<Vec<u8>, Error> {
    limits.validate()?;
    if input.len() > limits.max_input_bytes {
        return Err(Error::InputTooLarge {
            actual: input.len(),
            max: limits.max_input_bytes,
        });
    }
    let input_len = u32::try_from(input.len()).map_err(|_| Error::InputLengthNotRepresentable {
        actual: input.len(),
    })?;

    let mut encoded = BoundedOutput::new(limits.max_compressed_bytes, input.len())?;
    encoded.extend_from_slice(&input_len.to_le_bytes())?;

    if input.len() < MIN_COMPRESSIBLE_BLOCK_LEN {
        emit_last_literals(&mut encoded, input)?;
        return Ok(encoded.finish());
    }

    let mut table = Vec::new();
    table
        .try_reserve_exact(HASH_TABLE_LEN)
        .map_err(|_| Error::AllocationFailed {
            requested: HASH_TABLE_LEN,
        })?;
    table.resize(HASH_TABLE_LEN, EMPTY_HASH_SLOT);

    table[hash_at(input, 0)] = 0;
    let mut literal_start = 0;
    let mut cursor = 1;
    let last_match_start = input.len() - LAST_MATCH_START_DISTANCE;
    let match_end_limit = input.len() - LAST_LITERALS;

    while cursor <= last_match_start {
        let hash = hash_at(input, cursor);
        let candidate = table[hash];
        table[hash] = cursor;

        let is_match = candidate != EMPTY_HASH_SLOT
            && cursor - candidate <= MAX_MATCH_OFFSET
            && input[candidate..candidate + MIN_MATCH_LEN] == input[cursor..cursor + MIN_MATCH_LEN];
        if !is_match {
            cursor += 1;
            continue;
        }

        let mut match_start = cursor;
        let mut match_candidate = candidate;
        let earliest_match_start = usize::from(literal_start == 0).max(literal_start);
        while match_start > earliest_match_start
            && match_candidate > 0
            && input[match_start - 1] == input[match_candidate - 1]
        {
            match_start -= 1;
            match_candidate -= 1;
        }

        let mut match_end = match_start + MIN_MATCH_LEN;
        let mut candidate_end = match_candidate + MIN_MATCH_LEN;
        while match_end < match_end_limit && input[match_end] == input[candidate_end] {
            match_end += 1;
            candidate_end += 1;
        }

        let offset = match_start - match_candidate;
        emit_sequence(
            &mut encoded,
            &input[literal_start..match_start],
            Some((offset, match_end - match_start)),
        )?;

        let mut update = match_start + 1;
        while update < match_end && update + MIN_MATCH_LEN <= input.len() {
            table[hash_at(input, update)] = update;
            update += 1;
        }

        literal_start = match_end;
        cursor = match_end;
    }

    emit_last_literals(&mut encoded, &input[literal_start..])?;
    Ok(encoded.finish())
}

/// Decode one independent size-prepended LZ4 block.
///
/// The size prefix, compressed input limit, output limit, and expansion ratio
/// are checked before reserving decoded storage. Every length, offset, append,
/// and overlapping match copy is bounds checked.
///
/// # Errors
///
/// Returns a typed error for unsupported containers/dictionaries, malformed or
/// non-canonical sequences, resource-limit violations, and allocation failure.
pub(super) fn decode_size_prepended(input: &[u8], limits: Limits) -> Result<Vec<u8>, Error> {
    limits.validate()?;
    if input.len() > limits.max_compressed_bytes {
        return Err(Error::CompressedInputTooLarge {
            actual: input.len(),
            max: limits.max_compressed_bytes,
        });
    }
    if input.len() < SIZE_PREFIX_LEN {
        return Err(Error::MissingSizePrefix {
            actual: input.len(),
        });
    }
    reject_frame_magic(input)?;

    let advertised = usize::try_from(u32::from_le_bytes(
        input[..SIZE_PREFIX_LEN]
            .try_into()
            .expect("size prefix length is checked"),
    ))
    .expect("u32 always fits usize on supported targets");
    if advertised > limits.max_decompressed_bytes {
        return Err(Error::AdvertisedOutputTooLarge {
            actual: advertised,
            max: limits.max_decompressed_bytes,
        });
    }

    let block = &input[SIZE_PREFIX_LEN..];
    let maximum_by_ratio = block.len().saturating_mul(limits.max_expansion_ratio);
    if advertised > maximum_by_ratio {
        return Err(Error::ExpansionRatioExceeded {
            advertised,
            compressed: block.len(),
            max_ratio: limits.max_expansion_ratio,
        });
    }

    let mut output = Vec::new();
    output
        .try_reserve_exact(advertised)
        .map_err(|_| Error::AllocationFailed {
            requested: advertised,
        })?;

    let mut input_pos = 0;
    let mut sequence_index = 0;
    let mut last_match_start = None;

    let final_literal_len = loop {
        let token = read_byte(block, &mut input_pos, "token")?;
        let mut literal_len = usize::from(token >> 4);
        if literal_len == 15 {
            literal_len = read_extended_len(block, &mut input_pos, literal_len, "literal length")?;
        }

        let remaining = block.len() - input_pos;
        if literal_len > remaining {
            return Err(Error::LiteralOutOfBounds {
                length: literal_len,
                remaining,
            });
        }
        ensure_output_room(output.len(), literal_len, advertised)?;
        output.extend_from_slice(&block[input_pos..input_pos + literal_len]);
        input_pos += literal_len;

        if input_pos == block.len() {
            if token & 0x0f != 0 {
                return Err(Error::NonCanonicalBlock {
                    rule: "the final literal-only sequence has non-zero match bits",
                });
            }
            break literal_len;
        }

        if sequence_index == 0 && literal_len == 0 {
            return Err(Error::NonCanonicalBlock {
                rule: "an independent block cannot begin with a match",
            });
        }

        let offset_pos = input_pos;
        let offset = read_offset(block, &mut input_pos)?;
        if offset == 0 {
            return Err(Error::OffsetZero { at: offset_pos });
        }
        if offset > output.len() {
            return Err(Error::ExternalDictionaryRequired {
                offset,
                produced: output.len(),
            });
        }

        let mut match_len = MIN_MATCH_LEN + usize::from(token & 0x0f);
        if match_len == MIN_MATCH_LEN + 15 {
            match_len = read_extended_len(block, &mut input_pos, match_len, "match length")?;
        }
        ensure_output_room(output.len(), match_len, advertised)?;

        let match_start = output.len();
        for _ in 0..match_len {
            let source = output.len() - offset;
            let byte = output[source];
            output.push(byte);
        }
        last_match_start = Some(match_start);
        sequence_index += 1;
    };

    if let Some(match_start) = last_match_start {
        if final_literal_len < LAST_LITERALS {
            return Err(Error::NonCanonicalBlock {
                rule: "the last sequence must contain at least five literals",
            });
        }
        if advertised.saturating_sub(match_start) < LAST_MATCH_START_DISTANCE {
            return Err(Error::NonCanonicalBlock {
                rule: "the last match must start at least twelve bytes before block end",
            });
        }
    }

    if output.len() != advertised {
        return Err(Error::OutputLengthMismatch {
            advertised,
            actual: output.len(),
        });
    }
    Ok(output)
}

fn reject_frame_magic(input: &[u8]) -> Result<(), Error> {
    let magic: [u8; 4] = input[..SIZE_PREFIX_LEN]
        .try_into()
        .expect("size prefix length is checked");
    let container = if magic == LZ4_FRAME_MAGIC {
        Some(UnsupportedContainer::Frame)
    } else if magic == LZ4_LEGACY_FRAME_MAGIC {
        Some(UnsupportedContainer::LegacyFrame)
    } else {
        let value = u32::from_le_bytes(magic);
        (value & LZ4_SKIPPABLE_MAGIC_MASK == LZ4_SKIPPABLE_MAGIC)
            .then_some(UnsupportedContainer::SkippableFrame)
    };

    match container {
        Some(container) => Err(Error::UnsupportedContainer { container }),
        None => Ok(()),
    }
}

fn read_byte(input: &[u8], input_pos: &mut usize, field: &'static str) -> Result<u8, Error> {
    let Some(byte) = input.get(*input_pos).copied() else {
        return Err(Error::UnexpectedEnd {
            field,
            at: *input_pos,
        });
    };
    *input_pos += 1;
    Ok(byte)
}

fn read_extended_len(
    input: &[u8],
    input_pos: &mut usize,
    mut length: usize,
    field: &'static str,
) -> Result<usize, Error> {
    loop {
        let extension = read_byte(input, input_pos, field)?;
        length = length
            .checked_add(usize::from(extension))
            .ok_or(Error::LengthOverflow { field })?;
        if extension != u8::MAX {
            return Ok(length);
        }
    }
}

fn read_offset(input: &[u8], input_pos: &mut usize) -> Result<usize, Error> {
    let start = *input_pos;
    let end = start.checked_add(2).ok_or(Error::LengthOverflow {
        field: "match offset position",
    })?;
    let Some(bytes) = input.get(start..end) else {
        return Err(Error::UnexpectedEnd {
            field: "match offset",
            at: start,
        });
    };
    *input_pos = end;
    Ok(usize::from(u16::from_le_bytes(
        bytes.try_into().expect("match offset slice has two bytes"),
    )))
}

fn ensure_output_room(current: usize, additional: usize, advertised: usize) -> Result<(), Error> {
    let needed = current
        .checked_add(additional)
        .ok_or(Error::LengthOverflow {
            field: "decoded output length",
        })?;
    if needed > advertised {
        return Err(Error::OutputLengthExceeded { needed, advertised });
    }
    Ok(())
}

fn hash_at(input: &[u8], position: usize) -> usize {
    let batch = u32::from_le_bytes(
        input[position..position + MIN_MATCH_LEN]
            .try_into()
            .expect("hash caller guarantees four input bytes"),
    );
    usize::try_from(batch.wrapping_mul(HASH_MULTIPLIER) >> (u32::BITS - HASH_LOG))
        .expect("u16-sized hash always fits usize")
}

fn emit_last_literals(output: &mut BoundedOutput, literals: &[u8]) -> Result<(), Error> {
    emit_sequence(output, literals, None)
}

fn emit_sequence(
    output: &mut BoundedOutput,
    literals: &[u8],
    matched: Option<(usize, usize)>,
) -> Result<(), Error> {
    let token_pos = output.len();
    output.push(0)?;

    let literal_nibble = literals.len().min(15);
    if literals.len() >= 15 {
        emit_length_extension(output, literals.len() - 15)?;
    }
    output.extend_from_slice(literals)?;

    let mut match_nibble = 0;
    if let Some((offset, match_len)) = matched {
        debug_assert!((1..=MAX_MATCH_OFFSET).contains(&offset));
        debug_assert!(match_len >= MIN_MATCH_LEN);
        let offset = u16::try_from(offset).expect("match offset was range checked");
        output.extend_from_slice(&offset.to_le_bytes())?;

        let adjusted_match_len = match_len - MIN_MATCH_LEN;
        match_nibble = adjusted_match_len.min(15);
        if adjusted_match_len >= 15 {
            emit_length_extension(output, adjusted_match_len - 15)?;
        }
    }

    let token = (u8::try_from(literal_nibble).expect("literal nibble is at most 15") << 4)
        | u8::try_from(match_nibble).expect("match nibble is at most 15");
    output.set(token_pos, token);
    Ok(())
}

fn emit_length_extension(output: &mut BoundedOutput, mut remaining: usize) -> Result<(), Error> {
    while remaining >= usize::from(u8::MAX) {
        output.push(u8::MAX)?;
        remaining -= usize::from(u8::MAX);
    }
    output.push(u8::try_from(remaining).expect("extension remainder is below 255"))
}

struct BoundedOutput {
    bytes: Vec<u8>,
    max: usize,
}

impl BoundedOutput {
    fn new(max: usize, input_len: usize) -> Result<Self, Error> {
        let initial_capacity = input_len
            .min(64 * 1024)
            .checked_add(SIZE_PREFIX_LEN)
            .unwrap_or(max)
            .min(max);
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(initial_capacity)
            .map_err(|_| Error::AllocationFailed {
                requested: initial_capacity,
            })?;
        Ok(Self { bytes, max })
    }

    fn len(&self) -> usize {
        self.bytes.len()
    }

    fn push(&mut self, byte: u8) -> Result<(), Error> {
        let needed = self
            .bytes
            .len()
            .checked_add(1)
            .ok_or(Error::LengthOverflow {
                field: "compressed output length",
            })?;
        if needed > self.max {
            return Err(Error::CompressedOutputTooLarge {
                needed,
                max: self.max,
            });
        }
        self.bytes.push(byte);
        Ok(())
    }

    fn extend_from_slice(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let needed = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .ok_or(Error::LengthOverflow {
                field: "compressed output length",
            })?;
        if needed > self.max {
            return Err(Error::CompressedOutputTooLarge {
                needed,
                max: self.max,
            });
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    fn set(&mut self, position: usize, byte: u8) {
        self.bytes[position] = byte;
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

/// Feature-gated test and fuzz boundary for the private codec.
///
/// This deliberately exposes only classified errors and explicit resource
/// limits. Production trace readers and writers continue to use the incumbent
/// codec until A4 integration and A5 cutover decisions are complete.
#[cfg(any(feature = "fuzz", feature = "test-internals"))]
#[doc(hidden)]
pub mod harness {
    use super::{DEFAULT_MAX_EXPANSION_RATIO, Error, Limits};

    /// Stable error categories used by the independent corpus and fuzz target.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum ErrorClass {
        /// The caller supplied an internally invalid limit set.
        InvalidLimits,
        /// Encoder input exceeded its configured or persisted-size ceiling.
        InputLimit,
        /// A complete compressed input or output crossed its byte ceiling.
        CompressedLimit,
        /// The block ended before a required field or literal run completed.
        Truncated,
        /// An LZ4 frame container was supplied instead of an independent block.
        UnsupportedContainer,
        /// Advertised or decoded output crossed a size or ratio ceiling.
        OutputLimit,
        /// A checked integer operation overflowed.
        IntegerOverflow,
        /// A zero or out-of-history match offset was rejected.
        Offset,
        /// The input violated a canonical independent-block rule.
        NonCanonical,
        /// Actual decoded length did not equal the persisted size prefix.
        SizeMismatch,
        /// A bounded allocation reservation failed.
        Allocation,
    }

    impl ErrorClass {
        /// Canonical machine-readable category used by the corpus artifact.
        #[must_use]
        pub const fn as_str(self) -> &'static str {
            match self {
                Self::InvalidLimits => "invalid_limits",
                Self::InputLimit => "input_limit",
                Self::CompressedLimit => "compressed_limit",
                Self::Truncated => "truncated",
                Self::UnsupportedContainer => "unsupported_container",
                Self::OutputLimit => "output_limit",
                Self::IntegerOverflow => "integer_overflow",
                Self::Offset => "offset",
                Self::NonCanonical => "noncanonical",
                Self::SizeMismatch => "size_mismatch",
                Self::Allocation => "allocation",
            }
        }
    }

    impl From<Error> for ErrorClass {
        fn from(error: Error) -> Self {
            match error {
                Error::InvalidLimits { .. } => Self::InvalidLimits,
                Error::InputTooLarge { .. } | Error::InputLengthNotRepresentable { .. } => {
                    Self::InputLimit
                }
                Error::CompressedInputTooLarge { .. } | Error::CompressedOutputTooLarge { .. } => {
                    Self::CompressedLimit
                }
                Error::MissingSizePrefix { .. }
                | Error::UnexpectedEnd { .. }
                | Error::LiteralOutOfBounds { .. } => Self::Truncated,
                Error::UnsupportedContainer { .. } => Self::UnsupportedContainer,
                Error::AdvertisedOutputTooLarge { .. }
                | Error::ExpansionRatioExceeded { .. }
                | Error::OutputLengthExceeded { .. } => Self::OutputLimit,
                Error::LengthOverflow { .. } => Self::IntegerOverflow,
                Error::OffsetZero { .. } | Error::ExternalDictionaryRequired { .. } => Self::Offset,
                Error::NonCanonicalBlock { .. } => Self::NonCanonical,
                Error::OutputLengthMismatch { .. } => Self::SizeMismatch,
                Error::AllocationFailed { .. } => Self::Allocation,
            }
        }
    }

    /// Encode with explicit input and complete-compressed-output ceilings.
    ///
    /// # Errors
    ///
    /// Returns a classified error before either ceiling is exceeded.
    pub fn encode(
        input: &[u8],
        max_input_bytes: usize,
        max_compressed_bytes: usize,
    ) -> Result<Vec<u8>, ErrorClass> {
        super::encode_size_prepended(
            input,
            Limits {
                max_input_bytes,
                max_compressed_bytes,
                max_decompressed_bytes: max_input_bytes,
                max_expansion_ratio: DEFAULT_MAX_EXPANSION_RATIO,
            },
        )
        .map_err(ErrorClass::from)
    }

    /// Decode with explicit complete-input, output, and expansion-ratio caps.
    ///
    /// # Errors
    ///
    /// Returns a classified error for malformed, unsupported, non-canonical, or
    /// resource-exceeding input.
    pub fn decode(
        input: &[u8],
        max_compressed_bytes: usize,
        max_decompressed_bytes: usize,
        max_expansion_ratio: usize,
    ) -> Result<Vec<u8>, ErrorClass> {
        super::decode_size_prepended(
            input,
            Limits {
                max_input_bytes: max_decompressed_bytes,
                max_compressed_bytes,
                max_decompressed_bytes,
                max_expansion_ratio,
            },
        )
        .map_err(ErrorClass::from)
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_fun_call,
        clippy::match_wildcard_for_single_variants,
        clippy::needless_collect,
        clippy::pedantic,
        clippy::nursery
    )]

    use super::*;

    fn custom_limits(
        max_input_bytes: usize,
        max_compressed_bytes: usize,
        max_decompressed_bytes: usize,
        max_expansion_ratio: usize,
    ) -> Limits {
        Limits {
            max_input_bytes,
            max_compressed_bytes,
            max_decompressed_bytes,
            max_expansion_ratio,
        }
    }

    fn block(advertised: u32, body: &[u8]) -> Vec<u8> {
        let mut encoded = advertised.to_le_bytes().to_vec();
        encoded.extend_from_slice(body);
        encoded
    }

    #[test]
    fn empty_input_has_canonical_single_token_roundtrip() {
        let encoded = encode_size_prepended(b"", Limits::TRACE).unwrap();
        assert_eq!(encoded, [0, 0, 0, 0, 0]);
        assert_eq!(decode_size_prepended(&encoded, Limits::TRACE).unwrap(), b"");
    }

    #[test]
    fn literal_only_length_boundaries_roundtrip() {
        for len in [1, 4, 5, 12, 13, 14, 15, 16, 269, 270, 271] {
            let payload: Vec<u8> = (0..len).map(|value| value as u8).collect();
            let encoded = encode_size_prepended(&payload, Limits::TRACE).unwrap();
            assert_eq!(
                decode_size_prepended(&encoded, Limits::TRACE).unwrap(),
                payload,
                "length {len}"
            );
        }
    }

    #[test]
    fn decoder_accepts_exact_literal_extension_boundaries() {
        let fifteen = block(15, &[&[0xf0, 0][..], &[b'x'; 15]].concat());
        assert_eq!(
            decode_size_prepended(&fifteen, Limits::TRACE).unwrap(),
            vec![b'x'; 15]
        );

        let two_hundred_seventy = block(270, &[&[0xf0, 255, 0][..], &[b'y'; 270]].concat());
        assert_eq!(
            decode_size_prepended(&two_hundred_seventy, Limits::TRACE).unwrap(),
            vec![b'y'; 270]
        );
    }

    #[test]
    fn overlapping_match_and_match_extension_roundtrip() {
        let encoded = block(
            25,
            &[
                &[0x1f, b'a', 1, 0, 0][..],
                &[0x50, b'b', b'c', b'd', b'e', b'f'][..],
            ]
            .concat(),
        );
        let mut expected = vec![b'a'; 20];
        expected.extend_from_slice(b"bcdef");
        assert_eq!(
            decode_size_prepended(&encoded, Limits::TRACE).unwrap(),
            expected
        );
    }

    #[test]
    fn repeated_payload_is_compressed_and_deterministic() {
        let payload = vec![0xa5; 64 * 1024];
        let first = encode_size_prepended(&payload, Limits::TRACE).unwrap();
        let second = encode_size_prepended(&payload, Limits::TRACE).unwrap();
        assert_eq!(first, second);
        assert!(first.len() < payload.len() / 100);
        assert_eq!(
            decode_size_prepended(&first, Limits::TRACE).unwrap(),
            payload
        );
    }

    #[test]
    fn incumbent_and_owned_codec_accept_each_others_basic_blocks() {
        let payloads: [Vec<u8>; 4] = [
            Vec::new(),
            b"small literal".to_vec(),
            vec![7; 4096],
            (0_usize..65_537)
                .map(|index| (index.wrapping_mul(31) & 0xff) as u8)
                .collect(),
        ];

        for payload in payloads {
            let owned = encode_size_prepended(&payload, Limits::TRACE).unwrap();
            assert_eq!(
                lz4_flex::decompress_size_prepended(&owned).unwrap(),
                payload
            );

            let incumbent = lz4_flex::compress_prepend_size(&payload);
            assert_eq!(
                decode_size_prepended(&incumbent, Limits::TRACE).unwrap(),
                payload
            );
        }
    }

    #[test]
    fn deterministic_roundtrip_sweep_covers_empty_and_mixed_inputs() {
        for len in 0_usize..512 {
            let payload: Vec<u8> = (0..len)
                .map(|index| {
                    let mixed = index ^ (index >> 3) ^ len;
                    (mixed.wrapping_mul(17) & 0xff) as u8
                })
                .collect();
            let encoded = encode_size_prepended(&payload, Limits::TRACE).unwrap();
            assert_eq!(
                decode_size_prepended(&encoded, Limits::TRACE).unwrap(),
                payload,
                "length {len}"
            );
            assert_eq!(
                lz4_flex::decompress_size_prepended(&encoded).unwrap(),
                payload,
                "incumbent decode at length {len}"
            );
        }
    }

    #[test]
    fn encoder_enforces_input_and_output_limits() {
        let input_limited = custom_limits(3, 1024, 1024, 256);
        assert!(matches!(
            encode_size_prepended(b"four", input_limited),
            Err(Error::InputTooLarge { actual: 4, max: 3 })
        ));

        let output_limited = custom_limits(1024, 4, 1024, 256);
        assert!(matches!(
            encode_size_prepended(b"", output_limited),
            Err(Error::CompressedOutputTooLarge { max: 4, .. })
        ));
    }

    #[test]
    fn decoder_enforces_compressed_output_and_ratio_limits_before_decode() {
        let compressed_limited = custom_limits(1024, 4, 1024, 256);
        assert!(matches!(
            decode_size_prepended(&[0, 0, 0, 0, 0], compressed_limited),
            Err(Error::CompressedInputTooLarge { actual: 5, max: 4 })
        ));

        let output_limited = custom_limits(1024, 1024, 4, 256);
        assert!(matches!(
            decode_size_prepended(&block(5, &[0x50, 1, 2, 3, 4, 5]), output_limited),
            Err(Error::AdvertisedOutputTooLarge { actual: 5, max: 4 })
        ));

        let ratio_limited = custom_limits(1024, 1024, 1024, 2);
        let high_ratio = block(
            25,
            &[
                &[0x1f, b'a', 1, 0, 0][..],
                &[0x50, b'b', b'c', b'd', b'e', b'f'][..],
            ]
            .concat(),
        );
        assert!(matches!(
            decode_size_prepended(&high_ratio, ratio_limited),
            Err(Error::ExpansionRatioExceeded {
                advertised: 25,
                max_ratio: 2,
                ..
            })
        ));
    }

    #[test]
    fn zero_ratio_limit_is_rejected() {
        let invalid = custom_limits(1024, 1024, 1024, 0);
        assert!(matches!(
            encode_size_prepended(b"x", invalid),
            Err(Error::InvalidLimits { .. })
        ));
        assert!(matches!(
            decode_size_prepended(&block(0, &[0]), invalid),
            Err(Error::InvalidLimits { .. })
        ));
    }

    #[test]
    fn missing_prefix_and_token_are_typed() {
        assert!(matches!(
            decode_size_prepended(&[0, 0, 0], Limits::TRACE),
            Err(Error::MissingSizePrefix { actual: 3 })
        ));
        assert!(matches!(
            decode_size_prepended(&[0, 0, 0, 0], Limits::TRACE),
            Err(Error::UnexpectedEnd {
                field: "token",
                at: 0
            })
        ));
    }

    #[test]
    fn frame_containers_are_rejected_explicitly() {
        for (magic, expected) in [
            (LZ4_FRAME_MAGIC, UnsupportedContainer::Frame),
            (LZ4_LEGACY_FRAME_MAGIC, UnsupportedContainer::LegacyFrame),
            (
                LZ4_SKIPPABLE_MAGIC.to_le_bytes(),
                UnsupportedContainer::SkippableFrame,
            ),
        ] {
            let mut framed = magic.to_vec();
            framed.push(0);
            assert!(matches!(
                decode_size_prepended(&framed, Limits::TRACE),
                Err(Error::UnsupportedContainer { container }) if container == expected
            ));
        }
    }

    #[test]
    fn truncated_literal_and_match_extensions_are_typed() {
        assert!(matches!(
            decode_size_prepended(&block(15, &[0xf0]), Limits::TRACE),
            Err(Error::UnexpectedEnd {
                field: "literal length",
                ..
            })
        ));
        assert!(matches!(
            decode_size_prepended(&block(20, &[0x1f, b'a', 1, 0]), Limits::TRACE),
            Err(Error::UnexpectedEnd {
                field: "match length",
                ..
            })
        ));
    }

    #[test]
    fn literal_and_offset_truncation_are_typed() {
        assert!(matches!(
            decode_size_prepended(&block(3, &[0x30, b'a']), Limits::TRACE),
            Err(Error::LiteralOutOfBounds {
                length: 3,
                remaining: 1
            })
        ));
        assert!(matches!(
            decode_size_prepended(&block(5, &[0x10, b'a', 1]), Limits::TRACE),
            Err(Error::UnexpectedEnd {
                field: "match offset",
                ..
            })
        ));
    }

    #[test]
    fn zero_and_out_of_history_offsets_fail_closed() {
        assert!(matches!(
            decode_size_prepended(&block(10, &[0x10, b'a', 0, 0]), Limits::TRACE),
            Err(Error::OffsetZero { .. })
        ));
        assert!(matches!(
            decode_size_prepended(&block(10, &[0x10, b'a', 2, 0]), Limits::TRACE),
            Err(Error::ExternalDictionaryRequired {
                offset: 2,
                produced: 1
            })
        ));
    }

    #[test]
    fn decoded_output_must_equal_size_prefix_exactly() {
        assert!(matches!(
            decode_size_prepended(&block(1, &[0x20, b'a', b'b']), Limits::TRACE),
            Err(Error::OutputLengthExceeded {
                needed: 2,
                advertised: 1
            })
        ));
        assert!(matches!(
            decode_size_prepended(&block(2, &[0x10, b'a']), Limits::TRACE),
            Err(Error::OutputLengthMismatch {
                advertised: 2,
                actual: 1
            })
        ));
    }

    #[test]
    fn final_sequence_match_bits_are_rejected() {
        assert!(matches!(
            decode_size_prepended(&block(1, &[0x11, b'a']), Limits::TRACE),
            Err(Error::NonCanonicalBlock {
                rule: "the final literal-only sequence has non-zero match bits"
            })
        ));
    }

    #[test]
    fn independent_block_cannot_start_with_match() {
        assert!(matches!(
            decode_size_prepended(&block(9, &[0x00, 1, 0, 0x50, 1, 2, 3, 4, 5]), Limits::TRACE),
            Err(Error::NonCanonicalBlock {
                rule: "an independent block cannot begin with a match"
            })
        ));
    }

    #[test]
    fn canonical_end_conditions_are_enforced() {
        let four_final_literals = block(
            17,
            &[&[0x18, b'a', 1, 0][..], &[0x40, b'b', b'c', b'd', b'e'][..]].concat(),
        );
        assert!(matches!(
            decode_size_prepended(&four_final_literals, Limits::TRACE),
            Err(Error::NonCanonicalBlock {
                rule: "the last sequence must contain at least five literals"
            })
        ));

        let late_match = block(
            10,
            &[
                &[0x10, b'a', 1, 0][..],
                &[0x50, b'b', b'c', b'd', b'e', b'f'][..],
            ]
            .concat(),
        );
        assert!(matches!(
            decode_size_prepended(&late_match, Limits::TRACE),
            Err(Error::NonCanonicalBlock {
                rule: "the last match must start at least twelve bytes before block end"
            })
        ));
    }

    #[test]
    fn error_display_names_actionable_boundary() {
        let error = Error::ExternalDictionaryRequired {
            offset: 17,
            produced: 3,
        };
        let rendered = error.to_string();
        assert!(rendered.contains("offset 17"));
        assert!(rendered.contains("external dictionaries are unsupported"));
    }
}
