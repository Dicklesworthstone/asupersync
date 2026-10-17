//! Safe, scalar hexadecimal encoding and decoding.
//!
//! This module owns the bounded kernel for `CAP-HEX-CODEC`. It preserves the
//! incumbent lowercase encoding, mixed-case decoding, raw-byte error indices,
//! and odd-length/destination-length precedence while strengthening failure
//! atomicity: [`decode_to_slice`] never changes its destination when it returns
//! an error.
//!
//! The codec admits at most [`MAX_HEX_BINARY_LEN`] binary bytes. Encoding can
//! therefore request at most [`MAX_HEX_TEXT_LEN`] output bytes, and decoding
//! accepts at most that many even-length text bytes. Both allocating paths use
//! fallible exact-reservation requests; there is no unbounded convenience entry
//! point.

#![forbid(unsafe_code)]

use std::error::Error as StdError;
use std::fmt;

/// Maximum binary input or output admitted by the generic hex codec (64 MiB).
///
/// This is a new A2 safety policy, chosen from the largest explicit transport
/// message ceiling inspected during design; it is not an incumbent API limit.
/// A3 must prove that every migrated consumer is already bounded by this
/// ceiling (and retain the incumbent path otherwise). Protocols with smaller
/// limits must enforce them before calling this generic kernel.
pub const MAX_HEX_BINARY_LEN: usize = 64 * 1024 * 1024;

/// Maximum encoded text emitted or admitted by the generic hex codec (128 MiB).
pub const MAX_HEX_TEXT_LEN: usize = MAX_HEX_BINARY_LEN * 2;

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";
const INVALID_NIBBLE: u8 = u8::MAX;
const NIBBLE_VALUES: [u8; 256] = build_nibble_values();

/// Failure returned by the owned hexadecimal codec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HexError {
    /// A byte outside `0-9`, `a-f`, and `A-F` was found.
    InvalidHexCharacter {
        /// The invalid raw byte represented as the same scalar value.
        c: char,
        /// Raw byte position in the encoded input.
        index: usize,
    },
    /// Encoded input contains an odd number of bytes.
    OddLength,
    /// Encoded input does not exactly fill the supplied destination.
    InvalidStringLength,
    /// Binary input or decoded output exceeds the fixed resource envelope.
    BinaryLengthExceeded {
        /// Binary bytes required by the operation.
        len: usize,
        /// Maximum admitted binary bytes.
        limit: usize,
    },
    /// Doubling a defensive or synthetic binary length cannot be represented
    /// by `usize`.
    ///
    /// Safe slices on supported targets encounter the fixed binary cap before
    /// this representational boundary; the variant keeps the length planner
    /// explicitly checked rather than relying on that platform invariant.
    OutputLengthOverflow {
        /// Binary input length whose encoded size overflowed.
        input_len: usize,
    },
    /// The exact bounded output reservation failed.
    AllocationFailed {
        /// Number of output bytes requested.
        requested: usize,
    },
}

impl fmt::Display for HexError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::InvalidHexCharacter { c, index } => {
                write!(formatter, "Invalid character {c:?} at position {index}")
            }
            Self::OddLength => formatter.write_str("Odd number of digits"),
            Self::InvalidStringLength => formatter.write_str("Invalid string length"),
            Self::BinaryLengthExceeded { len, limit } => {
                write!(formatter, "Hex binary length {len} exceeds limit {limit}")
            }
            Self::OutputLengthOverflow { input_len } => write!(
                formatter,
                "Hex output length overflow for input length {input_len}"
            ),
            Self::AllocationFailed { requested } => {
                write!(
                    formatter,
                    "Hex output allocation failed for {requested} bytes"
                )
            }
        }
    }
}

impl StdError for HexError {}

/// Encodes binary data with canonical lowercase hexadecimal digits.
///
/// Empty input is accepted. The operation rejects binary input above
/// [`MAX_HEX_BINARY_LEN`], checks the `2 * N` output length, and reserves the
/// complete output fallibly before emitting any digits.
///
/// # Errors
///
/// Returns [`HexError::BinaryLengthExceeded`] when the binary input exceeds the
/// codec envelope, [`HexError::OutputLengthOverflow`] when its encoded length
/// is not representable, or [`HexError::AllocationFailed`] when the bounded
/// exact reservation fails. The defensive representation check precedes the
/// policy-cap check for synthetic lengths, although a legal safe slice within
/// the fixed public envelope cannot reach that distinction.
pub fn encode<T: AsRef<[u8]>>(data: T) -> Result<String, HexError> {
    encode_with_max_binary_len(data.as_ref(), MAX_HEX_BINARY_LEN)
}

fn encode_with_max_binary_len(data: &[u8], max_binary_len: usize) -> Result<String, HexError> {
    let output_len = encoded_len(data.len(), max_binary_len)?;
    let mut output = reserve_string(output_len)?;

    for &byte in data {
        output.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
    }

    Ok(output)
}

/// Decodes strict ASCII hexadecimal text into an owned byte vector.
///
/// Uppercase and lowercase digits may be mixed. Odd length is rejected before
/// character validity, and the earliest invalid raw byte index is reported.
/// The full input is validated before the exact bounded allocation occurs, so
/// malformed input never produces or exposes a partial output buffer.
///
/// # Errors
///
/// Returns a typed [`HexError`] for odd length, an invalid byte, a binary
/// output above [`MAX_HEX_BINARY_LEN`], or a failed exact reservation.
pub fn decode<T: AsRef<[u8]>>(data: T) -> Result<Vec<u8>, HexError> {
    decode_with_max_binary_len(data.as_ref(), MAX_HEX_BINARY_LEN)
}

fn decode_with_max_binary_len(data: &[u8], max_binary_len: usize) -> Result<Vec<u8>, HexError> {
    let output_len = decoded_len(data.len(), max_binary_len)?;
    validate_hex(data)?;

    let mut output = reserve_bytes(output_len)?;
    for pair in data.as_chunks::<2>().0 {
        output.push(decode_validated_pair(*pair));
    }
    Ok(output)
}

/// Decodes strict ASCII hexadecimal text into an exact destination slice.
///
/// Error precedence is odd input length, destination-length mismatch, binary
/// resource limit, then earliest invalid raw byte. Every error leaves the
/// entire destination unchanged. The successful path is allocation-free.
///
/// # Errors
///
/// Returns [`HexError::OddLength`] for odd input,
/// [`HexError::InvalidStringLength`] when the destination is not exact,
/// [`HexError::BinaryLengthExceeded`] above the fixed binary envelope, or
/// [`HexError::InvalidHexCharacter`] for the earliest malformed byte.
pub fn decode_to_slice<T: AsRef<[u8]>>(data: T, out: &mut [u8]) -> Result<(), HexError> {
    decode_to_slice_with_max_binary_len(data.as_ref(), out, MAX_HEX_BINARY_LEN)
}

fn decode_to_slice_with_max_binary_len(
    data: &[u8],
    out: &mut [u8],
    max_binary_len: usize,
) -> Result<(), HexError> {
    let output_len = even_binary_len(data.len())?;
    if output_len != out.len() {
        return Err(HexError::InvalidStringLength);
    }
    ensure_binary_len(output_len, max_binary_len)?;
    validate_hex(data)?;

    for (pair, output_byte) in data.as_chunks::<2>().0.iter().zip(out.iter_mut()) {
        *output_byte = decode_validated_pair(*pair);
    }
    Ok(())
}

const fn build_nibble_values() -> [u8; 256] {
    let mut values = [INVALID_NIBBLE; 256];

    let mut digit = 0_u8;
    while digit < 10 {
        values[(b'0' + digit) as usize] = digit;
        digit += 1;
    }

    let mut letter = 0_u8;
    while letter < 6 {
        values[(b'a' + letter) as usize] = 10 + letter;
        values[(b'A' + letter) as usize] = 10 + letter;
        letter += 1;
    }

    values
}

fn encoded_len(input_len: usize, max_binary_len: usize) -> Result<usize, HexError> {
    // Keep representation failure explicit for synthetic length-plan tests.
    // Every safe slice admitted by the fixed public envelope is far below this
    // boundary, while ordinary over-cap inputs still receive the limit error.
    let output_len = input_len
        .checked_mul(2)
        .ok_or(HexError::OutputLengthOverflow { input_len })?;
    ensure_binary_len(input_len, max_binary_len)?;
    Ok(output_len)
}

const fn even_binary_len(input_len: usize) -> Result<usize, HexError> {
    if !input_len.is_multiple_of(2) {
        return Err(HexError::OddLength);
    }
    Ok(input_len / 2)
}

fn decoded_len(input_len: usize, max_binary_len: usize) -> Result<usize, HexError> {
    let output_len = even_binary_len(input_len)?;
    ensure_binary_len(output_len, max_binary_len)?;
    Ok(output_len)
}

const fn ensure_binary_len(len: usize, max_binary_len: usize) -> Result<(), HexError> {
    if len > max_binary_len {
        return Err(HexError::BinaryLengthExceeded {
            len,
            limit: max_binary_len,
        });
    }
    Ok(())
}

fn validate_hex(data: &[u8]) -> Result<(), HexError> {
    for (index, &byte) in data.iter().enumerate() {
        if NIBBLE_VALUES[usize::from(byte)] == INVALID_NIBBLE {
            return Err(HexError::InvalidHexCharacter {
                c: char::from(byte),
                index,
            });
        }
    }
    Ok(())
}

fn decode_validated_pair(pair: [u8; 2]) -> u8 {
    let high = NIBBLE_VALUES[usize::from(pair[0])];
    let low = NIBBLE_VALUES[usize::from(pair[1])];
    (high << 4) | low
}

fn reserve_string(requested: usize) -> Result<String, HexError> {
    let mut output = String::new();
    output
        .try_reserve_exact(requested)
        .map_err(|_| HexError::AllocationFailed { requested })?;
    Ok(output)
}

fn reserve_bytes(requested: usize) -> Result<Vec<u8>, HexError> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(requested)
        .map_err(|_| HexError::AllocationFailed { requested })?;
    Ok(output)
}

#[cfg(test)]
#[path = "hex_inline_tests.rs"]
mod tests;
