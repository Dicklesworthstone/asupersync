//! Safe, scalar RFC 4648 Base64 encoding and decoding.
//!
//! This module owns the bounded kernel for `CAP-BASE64-CODEC`. Four immutable
//! engines cover the standard and URL-safe alphabets, each with canonical
//! padded and unpadded forms. Decoding is strict: alphabets may not mix,
//! whitespace is rejected, padding must match the selected engine, and unused
//! trailing bits must be zero.
//!
//! The codec admits at most [`MAX_BASE64_BINARY_LEN`] decoded bytes. Allocating
//! entry points make fallible exact reservations, while slice entry points
//! validate the complete request before changing the destination. A malformed
//! credential therefore cannot expose a partially decoded prefix.
//!
//! Decode errors have deterministic precedence: encoded-text envelope; an
//! invalid final non-padding byte in a one-symbol-tail shape; decoded-binary
//! envelope; the first invalid byte or padding placement in complete groups
//! and the terminal group; structural one-symbol tail; engine padding mode;
//! canonical trailing bits; then destination length. Encoding reports
//! representational overflow before the binary policy cap, and destination
//! mismatch only after the complete size plan succeeds.
//!
//! This is a general-purpose safe scalar kernel, not a side-channel-hardened
//! primitive. It makes no constant-time claim; security-bearing callers must
//! retain their protocol-specific validation, redaction, and failure mapping.

#![forbid(unsafe_code)]

use std::error::Error as StdError;
use std::fmt;

/// Maximum binary input or decoded output admitted by the generic codec (64 MiB).
///
/// Protocols with smaller resource envelopes must enforce them before calling
/// this generic kernel. This limit is an owned-codec policy, not an incumbent
/// `base64` crate limit.
pub const MAX_BASE64_BINARY_LEN: usize = 64 * 1024 * 1024;

/// Maximum encoded text admitted or emitted by the generic codec.
pub const MAX_BASE64_TEXT_LEN: usize = ((MAX_BASE64_BINARY_LEN + 2) / 3) * 4;

const INVALID_VALUE: u8 = u8::MAX;
const STANDARD_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL_SAFE_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const STANDARD_VALUES: [u8; 256] = build_decode_values(STANDARD_ALPHABET);
const URL_SAFE_VALUES: [u8; 256] = build_decode_values(URL_SAFE_ALPHABET);

/// Standard RFC 4648 alphabet with canonical `=` padding.
pub const STANDARD: Base64Engine = Base64Engine::new(Alphabet::Standard, true);
/// Standard RFC 4648 alphabet without padding.
pub const STANDARD_NO_PAD: Base64Engine = Base64Engine::new(Alphabet::Standard, false);
/// URL-safe RFC 4648 alphabet with canonical `=` padding.
pub const URL_SAFE: Base64Engine = Base64Engine::new(Alphabet::UrlSafe, true);
/// URL-safe RFC 4648 alphabet without padding.
pub const URL_SAFE_NO_PAD: Base64Engine = Base64Engine::new(Alphabet::UrlSafe, false);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Alphabet {
    Standard,
    UrlSafe,
}

/// One of the four immutable RFC 4648 Base64 engines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Base64Engine {
    alphabet: Alphabet,
    padded: bool,
}

impl Base64Engine {
    const fn new(alphabet: Alphabet, padded: bool) -> Self {
        Self { alphabet, padded }
    }

    /// Returns a stable engine name suitable for diagnostics and evidence.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match (self.alphabet, self.padded) {
            (Alphabet::Standard, true) => "STANDARD",
            (Alphabet::Standard, false) => "STANDARD_NO_PAD",
            (Alphabet::UrlSafe, true) => "URL_SAFE",
            (Alphabet::UrlSafe, false) => "URL_SAFE_NO_PAD",
        }
    }

    /// Returns whether this engine emits and requires canonical tail padding.
    #[must_use]
    pub const fn emits_padding(self) -> bool {
        self.padded
    }

    /// Plans the exact encoded length for a binary input.
    ///
    /// # Errors
    ///
    /// Returns [`Base64Error::BinaryLengthExceeded`] above the codec envelope
    /// or [`Base64Error::OutputLengthOverflow`] when the encoded length cannot
    /// be represented.
    pub fn encoded_len(self, input_len: usize) -> Result<usize, Base64Error> {
        encoded_len_with_max(input_len, MAX_BASE64_BINARY_LEN, self.padded)
    }

    /// Validates Base64 text and returns its exact decoded length.
    ///
    /// # Errors
    ///
    /// Returns a typed [`Base64Error`] for resource, length, alphabet, padding,
    /// or canonical trailing-bit violations.
    pub fn decoded_len<T: AsRef<[u8]>>(self, input: T) -> Result<usize, Base64Error> {
        self.decode_plan(input.as_ref(), MAX_BASE64_BINARY_LEN)
            .map(|plan| plan.output_len)
    }

    /// Encodes binary data into canonical text for this engine.
    ///
    /// Empty input is accepted. The complete output length is checked and
    /// reserved before any text is emitted.
    ///
    /// # Errors
    ///
    /// Returns a typed resource, representational, or allocation error.
    pub fn encode<T: AsRef<[u8]>>(self, input: T) -> Result<String, Base64Error> {
        let input = input.as_ref();
        let output_len = self.encoded_len(input.len())?;
        let mut output = reserve_string(output_len)?;
        encode_validated(input, self.alphabet_bytes(), self.padded, &mut output);
        Ok(output)
    }

    /// Encodes binary data into an exact destination slice.
    ///
    /// The destination is unchanged when its length is not exact or the input
    /// exceeds the resource envelope.
    ///
    /// # Errors
    ///
    /// Returns a typed length, resource, or representational error.
    pub fn encode_to_slice<T: AsRef<[u8]>>(
        self,
        input: T,
        output: &mut [u8],
    ) -> Result<(), Base64Error> {
        let input = input.as_ref();
        let expected = self.encoded_len(input.len())?;
        ensure_output_len(expected, output.len())?;
        encode_validated_to_slice(input, self.alphabet_bytes(), self.padded, output);
        Ok(())
    }

    /// Decodes strict canonical text into an owned byte vector.
    ///
    /// The entire input is validated before the exact bounded allocation is
    /// attempted, so malformed input never exposes a decoded prefix.
    ///
    /// # Errors
    ///
    /// Returns a typed resource, length, alphabet, padding, trailing-bit, or
    /// allocation error.
    pub fn decode<T: AsRef<[u8]>>(self, input: T) -> Result<Vec<u8>, Base64Error> {
        let input = input.as_ref();
        let plan = self.decode_plan(input, MAX_BASE64_BINARY_LEN)?;
        let mut output = reserve_bytes(plan.output_len)?;
        decode_validated(input, plan, self.decode_values(), &mut output);
        Ok(output)
    }

    /// Decodes strict canonical text into an exact destination slice.
    ///
    /// Validation, including trailing-bit validation, completes before the
    /// destination length is checked and before any byte is written. Every
    /// error therefore leaves the entire destination unchanged.
    ///
    /// # Errors
    ///
    /// Returns a typed resource, input-validity, or destination-length error.
    pub fn decode_to_slice<T: AsRef<[u8]>>(
        self,
        input: T,
        output: &mut [u8],
    ) -> Result<(), Base64Error> {
        let input = input.as_ref();
        let plan = self.decode_plan(input, MAX_BASE64_BINARY_LEN)?;
        ensure_output_len(plan.output_len, output.len())?;
        decode_validated_to_slice(input, plan, self.decode_values(), output);
        Ok(())
    }

    const fn alphabet_bytes(self) -> &'static [u8; 64] {
        match self.alphabet {
            Alphabet::Standard => STANDARD_ALPHABET,
            Alphabet::UrlSafe => URL_SAFE_ALPHABET,
        }
    }

    const fn decode_values(self) -> &'static [u8; 256] {
        match self.alphabet {
            Alphabet::Standard => &STANDARD_VALUES,
            Alphabet::UrlSafe => &URL_SAFE_VALUES,
        }
    }

    fn decode_plan(self, input: &[u8], max_binary_len: usize) -> Result<DecodePlan, Base64Error> {
        let text_limit = max_text_len(max_binary_len)?;
        if input.len() > text_limit {
            return Err(Base64Error::TextLengthExceeded {
                len: input.len(),
                limit: text_limit,
            });
        }

        let remainder = input.len() % 4;
        let values = self.decode_values();
        if remainder == 1 {
            let index = input.len() - 1;
            let byte = input[index];
            if byte != b'=' && values[usize::from(byte)] == INVALID_VALUE {
                return Err(Base64Error::InvalidByte { index, byte });
            }
        }

        let padding_len = match input {
            [.., b'=', b'='] => 2,
            [.., b'='] => 1,
            _ => 0,
        };
        let data_len = input.len() - padding_len;
        let tail_len = data_len % 4;
        let tail_output_len = match tail_len {
            0 | 1 => 0,
            2 => 1,
            3 => 2,
            _ => return Err(Base64Error::OutputLengthOverflow {
                input_len: input.len(),
            }),
        };
        let output_len = (data_len / 4)
            .checked_mul(3)
            .and_then(|full| full.checked_add(tail_output_len))
            .ok_or(Base64Error::OutputLengthOverflow {
                input_len: input.len(),
            })?;
        ensure_binary_len(output_len, max_binary_len)?;

        let suffix_len = if input.is_empty() {
            0
        } else if remainder == 0 {
            4
        } else {
            remainder
        };
        let suffix_start = input.len() - suffix_len;

        for (index, &byte) in input[..suffix_start].iter().enumerate() {
            if values[usize::from(byte)] == INVALID_VALUE {
                return Err(Base64Error::InvalidByte { index, byte });
            }
        }

        let mut suffix_symbols = 0usize;
        let mut suffix_padding = 0usize;
        let mut first_padding_offset = 0usize;
        let mut last_symbol = 0;
        let mut last_symbol_value = 0;
        for (offset, &byte) in input[suffix_start..].iter().enumerate() {
            if byte == b'=' {
                if offset < 2 {
                    return Err(Base64Error::InvalidByte {
                        index: suffix_start + offset,
                        byte,
                    });
                }
                if suffix_padding == 0 {
                    first_padding_offset = offset;
                }
                suffix_padding += 1;
                continue;
            }
            if suffix_padding != 0 {
                return Err(Base64Error::InvalidByte {
                    index: suffix_start + first_padding_offset,
                    byte: b'=',
                });
            }

            let value = values[usize::from(byte)];
            if value == INVALID_VALUE {
                return Err(Base64Error::InvalidByte {
                    index: suffix_start + offset,
                    byte,
                });
            }
            last_symbol = byte;
            last_symbol_value = value;
            suffix_symbols += 1;
        }

        if !input.is_empty() && suffix_symbols < 2 {
            return Err(Base64Error::InvalidLength { len: input.len() });
        }

        if self.padded {
            if !(suffix_padding + suffix_symbols).is_multiple_of(4) {
                return Err(Base64Error::InvalidPadding {
                    index: input.len(),
                });
            }
        } else if suffix_padding != 0 {
            return Err(Base64Error::InvalidPadding {
                index: suffix_start + first_padding_offset,
            });
        }

        if suffix_symbols != 0 {
            let index = suffix_start + suffix_symbols - 1;
            let unused_mask = match suffix_symbols {
                2 => 0b0000_1111,
                3 => 0b0000_0011,
                _ => 0,
            };
            if last_symbol_value & unused_mask != 0 {
                return Err(Base64Error::InvalidLastSymbol {
                    index,
                    byte: last_symbol,
                    value: last_symbol_value,
                });
            }
        }

        let data_len = suffix_start + suffix_symbols;
        Ok(DecodePlan {
            data_len,
            output_len,
        })
    }
}

/// Failure returned by the owned Base64 codec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Base64Error {
    /// A byte outside the selected RFC 4648 alphabet was found.
    InvalidByte {
        /// Raw byte position in the encoded input.
        index: usize,
        /// Invalid raw byte.
        byte: u8,
    },
    /// Encoded input has an impossible length for the selected padding mode.
    InvalidLength {
        /// Encoded input length.
        len: usize,
    },
    /// Padding is absent, present, or incomplete contrary to the engine mode.
    InvalidPadding {
        /// Raw position of the first forbidden padding symbol, or the encoded
        /// input length when canonical padding is missing or incomplete.
        index: usize,
    },
    /// The final symbol has non-zero bits outside the decoded payload.
    InvalidLastSymbol {
        /// Raw byte position of the final symbol.
        index: usize,
        /// Final raw byte.
        byte: u8,
        /// Six-bit alphabet value of the final symbol.
        value: u8,
    },
    /// Binary input or decoded output exceeds the fixed resource envelope.
    BinaryLengthExceeded {
        /// Binary bytes required by the operation.
        len: usize,
        /// Maximum admitted binary bytes.
        limit: usize,
    },
    /// Encoded text exceeds the maximum implied by the binary envelope.
    TextLengthExceeded {
        /// Encoded bytes supplied.
        len: usize,
        /// Maximum admitted encoded bytes.
        limit: usize,
    },
    /// Checked encoded or decoded length planning overflowed `usize`.
    OutputLengthOverflow {
        /// Input length whose output plan overflowed.
        input_len: usize,
    },
    /// A slice destination does not have the exact planned length.
    InvalidOutputLength {
        /// Exact required destination length.
        expected: usize,
        /// Supplied destination length.
        actual: usize,
    },
    /// The exact bounded output reservation failed.
    AllocationFailed {
        /// Number of output bytes requested.
        requested: usize,
    },
}

impl fmt::Display for Base64Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::InvalidByte { index, byte } => {
                write!(
                    formatter,
                    "Invalid Base64 byte 0x{byte:02x} at position {index}"
                )
            }
            Self::InvalidLength { len } => {
                write!(formatter, "Invalid Base64 input length {len}")
            }
            Self::InvalidPadding { index } => {
                write!(formatter, "Invalid Base64 padding at position {index}")
            }
            Self::InvalidLastSymbol { index, byte, value } => write!(
                formatter,
                "Invalid Base64 last symbol 0x{byte:02x} (value {value}) at position {index}"
            ),
            Self::BinaryLengthExceeded { len, limit } => {
                write!(
                    formatter,
                    "Base64 binary length {len} exceeds limit {limit}"
                )
            }
            Self::TextLengthExceeded { len, limit } => {
                write!(formatter, "Base64 text length {len} exceeds limit {limit}")
            }
            Self::OutputLengthOverflow { input_len } => write!(
                formatter,
                "Base64 output length overflow for input length {input_len}"
            ),
            Self::InvalidOutputLength { expected, actual } => write!(
                formatter,
                "Base64 output length {actual} does not match required length {expected}"
            ),
            Self::AllocationFailed { requested } => write!(
                formatter,
                "Base64 output allocation failed for {requested} bytes"
            ),
        }
    }
}

impl StdError for Base64Error {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DecodePlan {
    data_len: usize,
    output_len: usize,
}

const fn build_decode_values(alphabet: &[u8; 64]) -> [u8; 256] {
    let mut values = [INVALID_VALUE; 256];
    let mut index = 0;
    while index < alphabet.len() {
        values[alphabet[index] as usize] = index as u8;
        index += 1;
    }
    values
}

fn encoded_len_with_max(
    input_len: usize,
    max_binary_len: usize,
    padded: bool,
) -> Result<usize, Base64Error> {
    let full_len = (input_len / 3)
        .checked_mul(4)
        .ok_or(Base64Error::OutputLengthOverflow { input_len })?;
    let tail_len = match input_len % 3 {
        0 => 0,
        1 => {
            if padded {
                4
            } else {
                2
            }
        }
        2 => {
            if padded {
                4
            } else {
                3
            }
        }
        _ => return Err(Base64Error::OutputLengthOverflow { input_len }),
    };
    let output_len = full_len
        .checked_add(tail_len)
        .ok_or(Base64Error::OutputLengthOverflow { input_len })?;
    ensure_binary_len(input_len, max_binary_len)?;
    Ok(output_len)
}

fn max_text_len(max_binary_len: usize) -> Result<usize, Base64Error> {
    encoded_len_with_max(max_binary_len, max_binary_len, true)
}

const fn ensure_binary_len(len: usize, limit: usize) -> Result<(), Base64Error> {
    if len > limit {
        return Err(Base64Error::BinaryLengthExceeded { len, limit });
    }
    Ok(())
}

const fn ensure_output_len(expected: usize, actual: usize) -> Result<(), Base64Error> {
    if expected != actual {
        return Err(Base64Error::InvalidOutputLength { expected, actual });
    }
    Ok(())
}

fn encode_validated(input: &[u8], alphabet: &[u8; 64], padded: bool, output: &mut String) {
    let mut chunks = input.chunks_exact(3);
    for chunk in &mut chunks {
        output.push(char::from(alphabet[usize::from(chunk[0] >> 2)]));
        output.push(char::from(
            alphabet[usize::from(((chunk[0] & 0x03) << 4) | (chunk[1] >> 4))],
        ));
        output.push(char::from(
            alphabet[usize::from(((chunk[1] & 0x0f) << 2) | (chunk[2] >> 6))],
        ));
        output.push(char::from(alphabet[usize::from(chunk[2] & 0x3f)]));
    }

    let tail = chunks.remainder();
    if let Some((&first, rest)) = tail.split_first() {
        output.push(char::from(alphabet[usize::from(first >> 2)]));
        let second_value = ((first & 0x03) << 4) | (rest.first().copied().unwrap_or(0) >> 4);
        output.push(char::from(alphabet[usize::from(second_value)]));
        if let Some(&second) = rest.first() {
            output.push(char::from(alphabet[usize::from((second & 0x0f) << 2)]));
        } else if padded {
            output.push('=');
        }
        if padded {
            output.push('=');
        }
    }
}

fn encode_validated_to_slice(input: &[u8], alphabet: &[u8; 64], padded: bool, output: &mut [u8]) {
    let mut write_index = 0;
    let mut chunks = input.chunks_exact(3);
    for chunk in &mut chunks {
        output[write_index] = alphabet[usize::from(chunk[0] >> 2)];
        output[write_index + 1] = alphabet[usize::from(((chunk[0] & 0x03) << 4) | (chunk[1] >> 4))];
        output[write_index + 2] = alphabet[usize::from(((chunk[1] & 0x0f) << 2) | (chunk[2] >> 6))];
        output[write_index + 3] = alphabet[usize::from(chunk[2] & 0x3f)];
        write_index += 4;
    }

    let tail = chunks.remainder();
    match tail {
        [] | [_, _, _, ..] => {}
        [first] => {
            output[write_index] = alphabet[usize::from(first >> 2)];
            output[write_index + 1] = alphabet[usize::from((first & 0x03) << 4)];
            if padded {
                output[write_index + 2] = b'=';
                output[write_index + 3] = b'=';
            }
        }
        [first, second] => {
            output[write_index] = alphabet[usize::from(first >> 2)];
            output[write_index + 1] = alphabet[usize::from(((first & 0x03) << 4) | (second >> 4))];
            output[write_index + 2] = alphabet[usize::from((second & 0x0f) << 2)];
            if padded {
                output[write_index + 3] = b'=';
            }
        }
    }
}

fn decode_validated(input: &[u8], plan: DecodePlan, values: &[u8; 256], output: &mut Vec<u8>) {
    let data = &input[..plan.data_len];
    let mut chunks = data.chunks_exact(4);
    for chunk in &mut chunks {
        let [first, second, third] = decode_quad(chunk, values);
        output.extend_from_slice(&[first, second, third]);
    }
    let tail = chunks.remainder();
    if tail.len() >= 2 {
        let first = values[usize::from(tail[0])];
        let second = values[usize::from(tail[1])];
        output.push((first << 2) | (second >> 4));
        if tail.len() == 3 {
            let third = values[usize::from(tail[2])];
            output.push((second << 4) | (third >> 2));
        }
    }
}

fn decode_validated_to_slice(
    input: &[u8],
    plan: DecodePlan,
    values: &[u8; 256],
    output: &mut [u8],
) {
    let data = &input[..plan.data_len];
    let mut write_index = 0;
    let mut chunks = data.chunks_exact(4);
    for chunk in &mut chunks {
        let decoded = decode_quad(chunk, values);
        output[write_index..write_index + 3].copy_from_slice(&decoded);
        write_index += 3;
    }
    let tail = chunks.remainder();
    if tail.len() >= 2 {
        let first = values[usize::from(tail[0])];
        let second = values[usize::from(tail[1])];
        output[write_index] = (first << 2) | (second >> 4);
        if tail.len() == 3 {
            let third = values[usize::from(tail[2])];
            output[write_index + 1] = (second << 4) | (third >> 2);
        }
    }
}

fn decode_quad(chunk: &[u8], values: &[u8; 256]) -> [u8; 3] {
    let first = values[usize::from(chunk[0])];
    let second = values[usize::from(chunk[1])];
    let third = values[usize::from(chunk[2])];
    let fourth = values[usize::from(chunk[3])];
    [
        (first << 2) | (second >> 4),
        (second << 4) | (third >> 2),
        (third << 6) | fourth,
    ]
}

fn reserve_string(requested: usize) -> Result<String, Base64Error> {
    let mut output = String::new();
    output
        .try_reserve_exact(requested)
        .map_err(|_| Base64Error::AllocationFailed { requested })?;
    Ok(output)
}

fn reserve_bytes(requested: usize) -> Result<Vec<u8>, Base64Error> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(requested)
        .map_err(|_| Base64Error::AllocationFailed { requested })?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::pedantic, clippy::nursery)]
    // Registered verification filters use double underscores to separate the
    // immutable authority prefix from the relation name.
    #![allow(non_snake_case)]

    use super::*;
    use proptest::prelude::*;
    use proptest::test_runner::{FileFailurePersistence, RngSeed, TestRunner};

    const CANONICAL_PROPERTY_FAILURES: &str = "target/test-artifacts/dependency-sovereignty/asupersync_d24mms_10_2_ff120f39f884/asupersync_d24mms_10_2_property/proptest-regressions.txt";
    const LOCAL_PROPERTY_FAILURES: &str =
        "target/test-artifacts/agent-lane/base64_a2_local_proptest-regressions.txt";

    const ENGINES: [Base64Engine; 4] = [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD];

    // bead_id: asupersync-d24mms.10.2
    // capability_ids: CAP-BASE64-CODEC, CAP-AUTH-CREDENTIALS
    // scenario_id: base64_a2_safe_scalar_four_engine_core
    // seed_or_fixture: RFC 4648 sections 3-5 and 10; local seed
    // 0x4236_3441_325f_5246; canonical seeds 0..64
    // registered_unit_filter:
    // ver_a1_asupersync_d24mms_10_2_ff120f39f884__local_invariants
    // registered_property_filter:
    // ver_a1_asupersync_d24mms_10_2_ff120f39f884__property_matrix
    // artifact_path: target/test-artifacts/dependency-sovereignty/
    // asupersync_d24mms_10_2_ff120f39f884/asupersync_d24mms_10_2_property
    // expected_outcome: pass
    // proof boundary: these are in-process codec contracts, not downstream
    // protocol, authentication-journey, performance, or dependency-cutover proof.

    fn assert_owned_error_traits<T: Copy + Eq + StdError>() {}

    #[test]
    fn ver_a1_asupersync_d24mms_10_2_ff120f39f884__local_invariants__owned_error() {
        assert_owned_error_traits::<Base64Error>();
        assert_eq!(STANDARD.name(), "STANDARD");
        assert_eq!(STANDARD_NO_PAD.name(), "STANDARD_NO_PAD");
        assert_eq!(URL_SAFE.name(), "URL_SAFE");
        assert_eq!(URL_SAFE_NO_PAD.name(), "URL_SAFE_NO_PAD");
        assert!(STANDARD.emits_padding());
        assert!(!STANDARD_NO_PAD.emits_padding());

        let cases = [
            (
                Base64Error::InvalidByte {
                    index: 2,
                    byte: 0xff,
                },
                "Invalid Base64 byte 0xff at position 2".to_owned(),
            ),
            (
                Base64Error::InvalidLength { len: 5 },
                "Invalid Base64 input length 5".to_owned(),
            ),
            (
                Base64Error::InvalidPadding { index: 3 },
                "Invalid Base64 padding at position 3".to_owned(),
            ),
            (
                Base64Error::InvalidLastSymbol {
                    index: 3,
                    byte: b'B',
                    value: 1,
                },
                "Invalid Base64 last symbol 0x42 (value 1) at position 3".to_owned(),
            ),
            (
                Base64Error::BinaryLengthExceeded { len: 9, limit: 8 },
                "Base64 binary length 9 exceeds limit 8".to_owned(),
            ),
            (
                Base64Error::TextLengthExceeded { len: 13, limit: 12 },
                "Base64 text length 13 exceeds limit 12".to_owned(),
            ),
            (
                Base64Error::OutputLengthOverflow {
                    input_len: usize::MAX,
                },
                format!(
                    "Base64 output length overflow for input length {}",
                    usize::MAX
                ),
            ),
            (
                Base64Error::InvalidOutputLength {
                    expected: 4,
                    actual: 3,
                },
                "Base64 output length 3 does not match required length 4".to_owned(),
            ),
            (
                Base64Error::AllocationFailed { requested: 17 },
                "Base64 output allocation failed for 17 bytes".to_owned(),
            ),
        ];
        for (error, expected) in cases {
            assert_eq!(error.to_string(), expected);
        }
    }

    #[test]
    fn ver_a1_asupersync_d24mms_10_2_ff120f39f884__local_invariants() {
        let vectors = [
            (b"".as_slice(), "", ""),
            (b"f".as_slice(), "Zg==", "Zg"),
            (b"fo".as_slice(), "Zm8=", "Zm8"),
            (b"foo".as_slice(), "Zm9v", "Zm9v"),
            (b"foob".as_slice(), "Zm9vYg==", "Zm9vYg"),
            (b"fooba".as_slice(), "Zm9vYmE=", "Zm9vYmE"),
            (b"foobar".as_slice(), "Zm9vYmFy", "Zm9vYmFy"),
        ];

        for (binary, padded, unpadded) in vectors {
            for engine in [STANDARD, URL_SAFE] {
                assert_eq!(engine.encode(binary), Ok(padded.to_owned()));
                assert_eq!(engine.decode(padded), Ok(binary.to_vec()));
            }
            for engine in [STANDARD_NO_PAD, URL_SAFE_NO_PAD] {
                assert_eq!(engine.encode(binary), Ok(unpadded.to_owned()));
                assert_eq!(engine.decode(unpadded), Ok(binary.to_vec()));
            }
        }
    }

    #[test]
    fn ver_a1_asupersync_d24mms_10_2_ff120f39f884__local_invariants__alphabets() {
        let binary = [0xfb, 0xff, 0xef];
        assert_eq!(STANDARD.encode(binary), Ok("+//v".to_owned()));
        assert_eq!(STANDARD_NO_PAD.encode(binary), Ok("+//v".to_owned()));
        assert_eq!(URL_SAFE.encode(binary), Ok("-__v".to_owned()));
        assert_eq!(URL_SAFE_NO_PAD.encode(binary), Ok("-__v".to_owned()));

        assert_eq!(STANDARD.encode([0xff]), Ok("/w==".to_owned()));
        assert_eq!(STANDARD_NO_PAD.encode([0xff]), Ok("/w".to_owned()));
        assert_eq!(URL_SAFE.encode([0xff]), Ok("_w==".to_owned()));
        assert_eq!(URL_SAFE_NO_PAD.encode([0xff]), Ok("_w".to_owned()));
        assert_eq!(STANDARD.encode([0xff, 0xff]), Ok("//8=".to_owned()));
        assert_eq!(STANDARD_NO_PAD.encode([0xff, 0xff]), Ok("//8".to_owned()));
        assert_eq!(URL_SAFE.encode([0xff, 0xff]), Ok("__8=".to_owned()));
        assert_eq!(URL_SAFE_NO_PAD.encode([0xff, 0xff]), Ok("__8".to_owned()));

        for engine in ENGINES {
            assert_eq!(engine.encode([]), Ok(String::new()));
            assert_eq!(engine.decode([]), Ok(Vec::new()));
        }
    }

    #[test]
    fn ver_a1_asupersync_d24mms_10_2_ff120f39f884__local_invariants__roundtrip() {
        for len in 0..=257 {
            let binary = (0..len)
                .map(|index| (index as u8).wrapping_mul(73).wrapping_add(19))
                .collect::<Vec<_>>();
            for engine in ENGINES {
                let encoded = engine.encode(&binary).expect("short input is bounded");
                assert_eq!(encoded.len(), engine.encoded_len(len).unwrap());
                assert_eq!(engine.decoded_len(&encoded), Ok(len));
                assert_eq!(engine.decode(&encoded), Ok(binary.clone()));

                let mut encoded_slice = vec![0xa5; encoded.len()];
                assert_eq!(engine.encode_to_slice(&binary, &mut encoded_slice), Ok(()));
                assert_eq!(encoded_slice, encoded.as_bytes());

                let mut decoded_slice = vec![0xa5; len];
                assert_eq!(engine.decode_to_slice(&encoded, &mut decoded_slice), Ok(()));
                assert_eq!(decoded_slice, binary);
            }
        }
    }

    #[test]
    fn ver_a1_asupersync_d24mms_10_2_ff120f39f884__local_invariants__strict_alphabet() {
        for (engine, forbidden) in [
            (STANDARD, [b'-', b'_']),
            (STANDARD_NO_PAD, [b'-', b'_']),
            (URL_SAFE, [b'+', b'/']),
            (URL_SAFE_NO_PAD, [b'+', b'/']),
        ] {
            for byte in forbidden {
                let input = [b'A', byte, b'A', b'A'];
                assert_eq!(
                    engine.decode(input),
                    Err(Base64Error::InvalidByte { index: 1, byte })
                );
            }
            for byte in [b' ', b'\n', b'\r', b'\t', 0, 0x80, 0xff] {
                let input = [b'A', b'A', byte, b'A'];
                assert_eq!(
                    engine.decode(input),
                    Err(Base64Error::InvalidByte { index: 2, byte })
                );
            }
            assert_eq!(
                engine.decode(b"Z g=="),
                Err(Base64Error::InvalidByte {
                    index: 1,
                    byte: b' ',
                })
            );
        }
    }

    #[test]
    fn ver_a1_asupersync_d24mms_10_2_ff120f39f884__local_invariants__invalid_offsets() {
        for engine in ENGINES {
            let values = engine.decode_values();
            for byte in u8::MIN..=u8::MAX {
                if values[usize::from(byte)] != INVALID_VALUE {
                    continue;
                }
                for index in 0..4 {
                    if engine.padded && byte == b'=' && index == 3 {
                        continue;
                    }
                    let mut input = [b'A'; 4];
                    input[index] = byte;
                    let expected = if byte == b'=' {
                        if !engine.padded && index == 3 {
                            Base64Error::InvalidPadding { index }
                        } else {
                            Base64Error::InvalidByte { index, byte }
                        }
                    } else {
                        Base64Error::InvalidByte { index, byte }
                    };
                    assert_eq!(engine.decode(input), Err(expected));
                }
            }
        }
    }

    #[test]
    fn ver_a1_asupersync_d24mms_10_2_ff120f39f884__local_invariants__padding() {
        for engine in ENGINES {
            for (input, index) in [("A=A==", 1), ("Zg===", 2), ("AAAA=", 4), ("AAAA==", 4)] {
                assert_eq!(
                    engine.decode(input),
                    Err(Base64Error::InvalidByte {
                        index,
                        byte: b'=',
                    })
                );
            }
        }

        for engine in [STANDARD, URL_SAFE] {
            for input in ["Zg", "Zg="] {
                assert_eq!(
                    engine.decode(input),
                    Err(Base64Error::InvalidPadding { index: input.len() })
                );
            }
            assert_eq!(
                engine.decode("A"),
                Err(Base64Error::InvalidLength { len: 1 })
            );
            for (input, index) in [("=AAA", 0), ("A=AA", 1), ("AA=A", 2), ("A===", 1)] {
                assert_eq!(
                    engine.decode(input),
                    Err(Base64Error::InvalidByte {
                        index,
                        byte: b'=',
                    })
                );
            }
            for input in ["SGVsbG9", "SGVsbA=", "SGVsbA"] {
                assert_eq!(
                    engine.decode(input),
                    Err(Base64Error::InvalidPadding { index: input.len() })
                );
            }
            assert_eq!(
                engine.decode("SGVsbA===="),
                Err(Base64Error::InvalidByte {
                    index: 6,
                    byte: b'=',
                })
            );
        }

        for engine in [STANDARD_NO_PAD, URL_SAFE_NO_PAD] {
            assert_eq!(
                engine.decode("Zg=="),
                Err(Base64Error::InvalidPadding { index: 2 })
            );
            assert_eq!(
                engine.decode("Zm8="),
                Err(Base64Error::InvalidPadding { index: 3 })
            );
            assert_eq!(
                engine.decode("A"),
                Err(Base64Error::InvalidLength { len: 1 })
            );
        }

        for engine in [STANDARD, URL_SAFE] {
            for mask in 0_u8..16 {
                let mut input = [b'A'; 4];
                for (index, byte) in input.iter_mut().enumerate() {
                    if mask & (1 << index) != 0 {
                        *byte = b'=';
                    }
                }
                assert_eq!(
                    engine.decode(input).is_ok(),
                    matches!(mask, 0 | 8 | 12),
                    "{} padding mask {mask:04b}",
                    engine.name()
                );
            }
        }
        for engine in [STANDARD_NO_PAD, URL_SAFE_NO_PAD] {
            for mask in 0_u8..16 {
                let mut input = [b'A'; 4];
                for (index, byte) in input.iter_mut().enumerate() {
                    if mask & (1 << index) != 0 {
                        *byte = b'=';
                    }
                }
                assert_eq!(
                    engine.decode(input).is_ok(),
                    mask == 0,
                    "{} padding mask {mask:04b}",
                    engine.name()
                );
            }
        }

        for symbol_count in 1..=257 {
            let remainder = symbol_count % 4;
            let mut input = vec![b'A'; symbol_count];
            input.resize(symbol_count + (4 - remainder), b'=');

            for engine in ENGINES {
                let result = engine.decode(&input);
                if remainder < 2 {
                    assert_eq!(
                        result,
                        Err(Base64Error::InvalidByte {
                            index: symbol_count,
                            byte: b'=',
                        }),
                        "{} padding at quartet offset {remainder}",
                        engine.name()
                    );
                } else if engine.padded {
                    assert!(
                        result.is_ok(),
                        "{} rejected canonical padding at quartet offset {remainder}",
                        engine.name()
                    );
                } else {
                    assert_eq!(
                        result,
                        Err(Base64Error::InvalidPadding {
                            index: symbol_count,
                        }),
                        "{} accepted forbidden padding at quartet offset {remainder}",
                        engine.name()
                    );
                }
            }
        }

        for len in 0..=12 {
            let input = vec![b'A'; len];
            for engine in [STANDARD, URL_SAFE] {
                assert_eq!(engine.decode(&input).is_ok(), len.is_multiple_of(4));
            }
            for engine in [STANDARD_NO_PAD, URL_SAFE_NO_PAD] {
                assert_eq!(engine.decode(&input).is_ok(), len % 4 != 1);
            }
        }
    }

    #[test]
    fn ver_a1_asupersync_d24mms_10_2_ff120f39f884__local_invariants__trailing_bits() {
        for engine in [STANDARD, URL_SAFE] {
            assert_eq!(
                engine.decode("SGVsbG9="),
                Err(Base64Error::InvalidLastSymbol {
                    index: 6,
                    byte: b'9',
                    value: 61,
                })
            );
        }

        for engine in ENGINES {
            let alphabet = engine.alphabet_bytes();
            for value in 0_u8..64 {
                let mut two_symbols = vec![alphabet[0], alphabet[usize::from(value)]];
                if engine.padded {
                    two_symbols.extend_from_slice(b"==");
                }
                let result = engine.decode(&two_symbols);
                if value & 0x0f == 0 {
                    assert!(result.is_ok(), "{} rejected value {value}", engine.name());
                } else {
                    assert_eq!(
                        result,
                        Err(Base64Error::InvalidLastSymbol {
                            index: 1,
                            byte: alphabet[usize::from(value)],
                            value,
                        })
                    );
                }

                let mut three_symbols =
                    vec![alphabet[0], alphabet[0], alphabet[usize::from(value)]];
                if engine.padded {
                    three_symbols.push(b'=');
                }
                let result = engine.decode(&three_symbols);
                if value & 0x03 == 0 {
                    assert!(result.is_ok(), "{} rejected value {value}", engine.name());
                } else {
                    assert_eq!(
                        result,
                        Err(Base64Error::InvalidLastSymbol {
                            index: 2,
                            byte: alphabet[usize::from(value)],
                            value,
                        })
                    );
                }
            }
        }
    }

    #[test]
    fn ver_a1_asupersync_d24mms_10_2_ff120f39f884__local_invariants__atomic_decode() {
        for engine in ENGINES {
            let valid = engine.encode([0, 1, 2, 3, 4, 5]).unwrap();
            let mut malformed = valid.into_bytes();
            malformed[7] = b'!';

            let before = [0xa5; 6];
            let mut output = before;
            assert_eq!(
                engine.decode_to_slice(&malformed, &mut output),
                Err(Base64Error::InvalidByte {
                    index: 7,
                    byte: b'!',
                })
            );
            assert_eq!(output, before);

            for actual in [0, 3, 5] {
                let before = vec![0x5a; actual];
                let mut output = before.clone();
                assert_eq!(
                    engine.decode_to_slice(engine.encode([1, 2, 3, 4]).unwrap(), &mut output),
                    Err(Base64Error::InvalidOutputLength {
                        expected: 4,
                        actual,
                    })
                );
                assert_eq!(output, before);
            }
        }
    }

    #[test]
    fn ver_a1_asupersync_d24mms_10_2_ff120f39f884__local_invariants__error_precedence() {
        assert_eq!(
            STANDARD.decode_plan(b"!AAA!", MAX_BASE64_BINARY_LEN),
            Err(Base64Error::InvalidByte {
                index: 4,
                byte: b'!',
            })
        );
        assert_eq!(
            STANDARD.decode_plan(b"!AAAA", MAX_BASE64_BINARY_LEN),
            Err(Base64Error::InvalidByte {
                index: 0,
                byte: b'!',
            })
        );
        assert_eq!(
            STANDARD.decode_plan(b"!AAAA", 2),
            Err(Base64Error::BinaryLengthExceeded { len: 3, limit: 2 })
        );
        assert_eq!(
            STANDARD.decode_plan(b"!", MAX_BASE64_BINARY_LEN),
            Err(Base64Error::InvalidByte {
                index: 0,
                byte: b'!',
            })
        );
        assert_eq!(
            STANDARD.decode_plan(b"AAA!", 2),
            Err(Base64Error::BinaryLengthExceeded { len: 3, limit: 2 })
        );

        let before = [0xa5; 2];
        let mut destination = before;
        assert_eq!(
            STANDARD.decode_to_slice(b"AAA!", &mut destination),
            Err(Base64Error::InvalidByte {
                index: 3,
                byte: b'!',
            })
        );
        assert_eq!(destination, before);

        let mut destination = before;
        assert_eq!(
            STANDARD.decode_to_slice(b"AAB=", &mut destination),
            Err(Base64Error::InvalidLastSymbol {
                index: 2,
                byte: b'B',
                value: 1,
            })
        );
        assert_eq!(destination, before);
    }

    #[test]
    fn ver_a1_asupersync_d24mms_10_2_ff120f39f884__local_invariants__atomic_encode() {
        for engine in ENGINES {
            let expected = engine.encoded_len(5).unwrap();
            for actual in [0, expected - 1, expected + 1] {
                let before = vec![0x5a; actual];
                let mut output = before.clone();
                assert_eq!(
                    engine.encode_to_slice([1, 2, 3, 4, 5], &mut output),
                    Err(Base64Error::InvalidOutputLength { expected, actual })
                );
                assert_eq!(output, before);
            }
        }
    }

    #[test]
    fn ver_a1_asupersync_d24mms_10_2_ff120f39f884__local_invariants__length_plans() {
        assert_eq!(STANDARD.encoded_len(0), Ok(0));
        assert_eq!(STANDARD.encoded_len(1), Ok(4));
        assert_eq!(STANDARD_NO_PAD.encoded_len(1), Ok(2));
        assert_eq!(STANDARD.encoded_len(2), Ok(4));
        assert_eq!(STANDARD_NO_PAD.encoded_len(2), Ok(3));
        assert_eq!(STANDARD.encoded_len(3), Ok(4));
        assert_eq!(STANDARD_NO_PAD.encoded_len(3), Ok(4));
        assert_eq!(
            STANDARD.encoded_len(MAX_BASE64_BINARY_LEN),
            Ok(MAX_BASE64_TEXT_LEN)
        );
        for engine in ENGINES {
            assert_eq!(
                engine.encoded_len(MAX_BASE64_BINARY_LEN + 1),
                Err(Base64Error::BinaryLengthExceeded {
                    len: MAX_BASE64_BINARY_LEN + 1,
                    limit: MAX_BASE64_BINARY_LEN,
                })
            );
        }

        assert_eq!(
            encoded_len_with_max(3, 2, true),
            Err(Base64Error::BinaryLengthExceeded { len: 3, limit: 2 })
        );
        assert_eq!(
            STANDARD.decode_plan(b"AAAA", 2),
            Err(Base64Error::BinaryLengthExceeded { len: 3, limit: 2 })
        );
        assert_eq!(
            STANDARD.decode_plan(b"AAAAA", 2),
            Err(Base64Error::TextLengthExceeded { len: 5, limit: 4 })
        );

        let overflowing = (usize::MAX / 4) * 3 + 3;
        assert!(matches!(
            encoded_len_with_max(overflowing, usize::MAX, true),
            Err(Base64Error::OutputLengthOverflow { .. })
        ));
    }

    #[test]
    fn ver_a1_asupersync_d24mms_10_2_ff120f39f884__local_invariants__allocation_errors() {
        assert_eq!(
            reserve_string(usize::MAX),
            Err(Base64Error::AllocationFailed {
                requested: usize::MAX,
            })
        );
        assert_eq!(
            reserve_bytes(usize::MAX),
            Err(Base64Error::AllocationFailed {
                requested: usize::MAX,
            })
        );
    }

    #[test]
    fn ver_a1_asupersync_d24mms_10_2_ff120f39f884__local_invariants__large_roundtrip() {
        const LARGE_LEN: usize = 1024 * 1024;
        let binary = (0..LARGE_LEN)
            .map(|index| (index as u8).wrapping_mul(31).wrapping_add(7))
            .collect::<Vec<_>>();

        for engine in ENGINES {
            let encoded = engine.encode(&binary).expect("one MiB is bounded");
            assert_eq!(encoded.len(), engine.encoded_len(LARGE_LEN).unwrap());
            assert_eq!(engine.decode(&encoded), Ok(binary.clone()));

            let mut destination = vec![0xa5; binary.len()];
            assert_eq!(engine.decode_to_slice(&encoded, &mut destination), Ok(()));
            assert_eq!(destination, binary);
        }
    }

    #[test]
    fn ver_a1_asupersync_d24mms_10_2_ff120f39f884__property_matrix() {
        let strategy = (
            proptest::collection::vec(any::<u8>(), 0..1024),
            proptest::collection::vec(any::<u8>(), 0..1024),
            any::<usize>(),
            any::<usize>(),
            any::<u8>(),
            any::<u8>().prop_filter(
                "byte is outside both RFC 4648 Base64 alphabets and padding",
                |byte| {
                    !matches!(
                        byte,
                        b'A'..=b'Z'
                            | b'a'..=b'z'
                            | b'0'..=b'9'
                            | b'+'
                            | b'/'
                            | b'-'
                            | b'_'
                            | b'='
                    )
                },
            ),
        );

        for seed in 0_u64..64 {
            let mut config = ProptestConfig::with_cases(4);
            config.rng_seed = RngSeed::Fixed(seed);
            config.source_file = Some(file!());
            config.failure_persistence = Some(Box::new(FileFailurePersistence::Direct(
                CANONICAL_PROPERTY_FAILURES,
            )));
            let mut runner = TestRunner::new(config);

            let result = runner.run(
                &strategy,
                |(binary, text, destination_len, raw_position, prefill, invalid)| {
                    for engine in ENGINES {
                        let encoded = engine
                            .encode(&binary)
                            .map_err(|error| TestCaseError::fail(error.to_string()))?;
                        prop_assert_eq!(engine.encoded_len(binary.len()), Ok(encoded.len()));
                        prop_assert_eq!(engine.decode(&encoded), Ok(binary.clone()));

                        let mut destination = vec![prefill; binary.len()];
                        prop_assert_eq!(
                            engine.decode_to_slice(&encoded, &mut destination),
                            Ok(())
                        );
                        prop_assert_eq!(&destination, &binary);

                        if !encoded.is_empty() {
                            let mut malformed = encoded.into_bytes();
                            let position = raw_position % malformed.len();
                            malformed[position] = invalid;
                            let expected = Base64Error::InvalidByte {
                                index: position,
                                byte: invalid,
                            };
                            prop_assert_eq!(engine.decode(&malformed), Err(expected));

                            let before = vec![prefill; binary.len()];
                            let mut destination = before.clone();
                            prop_assert_eq!(
                                engine.decode_to_slice(&malformed, &mut destination),
                                Err(expected)
                            );
                            prop_assert_eq!(destination, before);
                        }

                        let before = vec![prefill; destination_len % 1024];
                        let mut destination = before.clone();
                        if engine.decode_to_slice(&text, &mut destination).is_err() {
                            prop_assert_eq!(destination, before);
                        }
                    }

                    Ok(())
                },
            );
            assert!(result.is_ok(), "fixed seed {seed} failed: {result:?}");
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 128,
            failure_persistence: Some(Box::new(FileFailurePersistence::Direct(
                LOCAL_PROPERTY_FAILURES,
            ))),
            rng_seed: RngSeed::Fixed(0x4236_3441_325f_5246),
            ..ProptestConfig::default()
        })]

        #[test]
        fn ver_a1_asupersync_d24mms_10_2_ff120f39f884__property_matrix__roundtrip_and_atomicity(
            binary in proptest::collection::vec(any::<u8>(), 0..4096),
            prefill in any::<u8>(),
        ) {
            for engine in ENGINES {
                let encoded = engine.encode(&binary).expect("generated input is bounded");
                prop_assert_eq!(engine.decode(&encoded), Ok(binary.clone()));

                let mut output = vec![prefill; binary.len()];
                prop_assert_eq!(engine.decode_to_slice(&encoded, &mut output), Ok(()));
                prop_assert_eq!(&output, &binary);

                if !encoded.is_empty() {
                    let mut malformed = encoded.into_bytes();
                    let position = malformed.len() / 2;
                    malformed[position] = b'!';
                    let before = vec![prefill; binary.len()];
                    let mut destination = before.clone();
                    prop_assert!(engine.decode_to_slice(&malformed, &mut destination).is_err());
                    prop_assert_eq!(destination, before);
                }
            }
        }

        #[test]
        fn ver_a1_asupersync_d24mms_10_2_ff120f39f884__property_matrix__arbitrary_text_atomicity(
            text in proptest::collection::vec(any::<u8>(), 0..4096),
            destination_len in 0_usize..4096,
            prefill in any::<u8>(),
        ) {
            for engine in ENGINES {
                let before = vec![prefill; destination_len];
                let mut destination = before.clone();
                let result = engine.decode_to_slice(&text, &mut destination);
                if result.is_err() {
                    prop_assert_eq!(destination, before);
                }
            }
        }
    }
}
