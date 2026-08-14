//! Strictly safe, bounded NKey text-codec primitives.
//!
//! This pre-cutover module owns canonical RFC 4648 Base32 text conversion,
//! CRC16-XMODEM computation, and checksum framing. Base32 is uppercase-only
//! and unpadded; CRC detects accidental corruption. Neither primitive is
//! authentication, authorization, collision resistance, signing, a MAC, or a
//! key-format decision. The production identity paths continue to use the
//! incumbent `nkeys` crate until the later parity and cutover gates close.

use std::fmt;

pub(super) const CHECKSUM_BYTES: usize = 2;
pub(super) const MAX_BODY_BYTES: usize = 65;
pub(super) const MAX_FRAME_BYTES: usize = MAX_BODY_BYTES + CHECKSUM_BYTES;
pub(super) const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
pub(super) const MAX_BASE32_ENCODED_CHARS: usize = 108;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Base32Limits {
    pub(super) max_decoded_bytes: usize,
    pub(super) max_encoded_chars: usize,
}

impl Default for Base32Limits {
    fn default() -> Self {
        Self {
            max_decoded_bytes: MAX_FRAME_BYTES,
            max_encoded_chars: MAX_BASE32_ENCODED_CHARS,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CodecPhase {
    ChecksumBody,
    ChecksumFrame,
    Base32Input,
    Base32Output,
}

impl CodecPhase {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ChecksumBody => "checksum-body",
            Self::ChecksumFrame => "checksum-frame",
            Self::Base32Input => "base32-input",
            Self::Base32Output => "base32-output",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum NonCanonicalReason {
    Lowercase,
    Padding,
    Whitespace,
    Separator,
    TrailingBits,
    RoundTrip,
}

impl NonCanonicalReason {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Lowercase => "lowercase",
            Self::Padding => "padding",
            Self::Whitespace => "whitespace",
            Self::Separator => "separator",
            Self::TrailingBits => "trailing-bits",
            Self::RoundTrip => "round-trip",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum NkeyCodecError {
    Length {
        phase: CodecPhase,
        actual: usize,
        expected: usize,
    },
    Alphabet {
        index: usize,
    },
    NonCanonical {
        reason: NonCanonicalReason,
        index: Option<usize>,
    },
    Checksum {
        body_len: usize,
    },
    Resource {
        phase: CodecPhase,
        requested: usize,
        limit: usize,
    },
}

impl NkeyCodecError {
    pub(super) const fn class(&self) -> &'static str {
        match self {
            Self::Length { .. } => "length",
            Self::Alphabet { .. } => "alphabet",
            Self::NonCanonical { .. } => "noncanonical",
            Self::Checksum { .. } => "checksum",
            Self::Resource { .. } => "resource",
        }
    }
}

impl fmt::Display for NkeyCodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length {
                phase,
                actual,
                expected,
            } => write!(
                formatter,
                "{} length is {actual}; expected {expected}",
                phase.as_str()
            ),
            Self::Alphabet { index } => {
                write!(formatter, "base32 alphabet error at index {index}")
            }
            Self::NonCanonical { reason, index } => {
                write!(formatter, "noncanonical base32 ({})", reason.as_str())?;
                if let Some(index) = index {
                    write!(formatter, " at index {index}")?;
                }
                Ok(())
            }
            Self::Checksum { body_len } => {
                write!(formatter, "checksum mismatch for {body_len}-byte body")
            }
            Self::Resource {
                phase,
                requested,
                limit,
            } => write!(
                formatter,
                "{} resource request {requested} exceeds limit {limit}",
                phase.as_str()
            ),
        }
    }
}

impl std::error::Error for NkeyCodecError {}

pub(super) fn base32_encoded_len(decoded_bytes: usize) -> Result<usize, NkeyCodecError> {
    decoded_bytes
        .checked_mul(8)
        .and_then(|bits| bits.checked_add(4))
        .map(|rounded_bits| rounded_bits / 5)
        .ok_or(NkeyCodecError::Resource {
            phase: CodecPhase::Base32Output,
            requested: usize::MAX,
            limit: MAX_BASE32_ENCODED_CHARS,
        })
}

pub(super) fn base32_decoded_len(encoded_chars: usize) -> Result<usize, NkeyCodecError> {
    encoded_chars
        .checked_mul(5)
        .map(|bits| bits / 8)
        .ok_or(NkeyCodecError::Resource {
            phase: CodecPhase::Base32Output,
            requested: usize::MAX,
            limit: MAX_FRAME_BYTES,
        })
}

pub(super) fn encode_base32(
    decoded: &[u8],
    limits: Base32Limits,
) -> Result<String, NkeyCodecError> {
    let decoded_limit = limits.max_decoded_bytes.min(MAX_FRAME_BYTES);
    if decoded.len() > decoded_limit {
        return Err(NkeyCodecError::Resource {
            phase: CodecPhase::Base32Input,
            requested: decoded.len(),
            limit: decoded_limit,
        });
    }

    let encoded_len = base32_encoded_len(decoded.len())?;
    let encoded_limit = limits.max_encoded_chars.min(MAX_BASE32_ENCODED_CHARS);
    if encoded_len > encoded_limit {
        return Err(NkeyCodecError::Resource {
            phase: CodecPhase::Base32Output,
            requested: encoded_len,
            limit: encoded_limit,
        });
    }

    let mut output = String::with_capacity(encoded_len);
    let mut accumulator = 0u16;
    let mut bits = 0u8;
    for byte in decoded {
        accumulator = (accumulator << 8) | u16::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let alphabet_index = usize::from((accumulator >> bits) & 0x1f);
            let symbol =
                BASE32_ALPHABET
                    .get(alphabet_index)
                    .copied()
                    .ok_or(NkeyCodecError::Alphabet {
                        index: alphabet_index,
                    })?;
            output.push(char::from(symbol));
        }
        accumulator &= low_bits_mask(bits);
    }
    if bits != 0 {
        let alphabet_index = usize::from((accumulator << (5 - bits)) & 0x1f);
        let symbol =
            BASE32_ALPHABET
                .get(alphabet_index)
                .copied()
                .ok_or(NkeyCodecError::Alphabet {
                    index: alphabet_index,
                })?;
        output.push(char::from(symbol));
    }
    debug_assert_eq!(output.len(), encoded_len);
    Ok(output)
}

pub(super) fn decode_base32(
    encoded: &str,
    limits: Base32Limits,
) -> Result<Vec<u8>, NkeyCodecError> {
    let encoded_limit = limits.max_encoded_chars.min(MAX_BASE32_ENCODED_CHARS);
    if encoded.len() > encoded_limit {
        return Err(NkeyCodecError::Resource {
            phase: CodecPhase::Base32Input,
            requested: encoded.len(),
            limit: encoded_limit,
        });
    }
    if !is_possible_base32_len(encoded.len()) {
        return Err(NkeyCodecError::Length {
            phase: CodecPhase::Base32Input,
            actual: encoded.len(),
            expected: encoded.len() + 1,
        });
    }

    let decoded_len = base32_decoded_len(encoded.len())?;
    let decoded_limit = limits.max_decoded_bytes.min(MAX_FRAME_BYTES);
    if decoded_len > decoded_limit {
        return Err(NkeyCodecError::Resource {
            phase: CodecPhase::Base32Output,
            requested: decoded_len,
            limit: decoded_limit,
        });
    }

    let mut last_symbol = 0u8;
    for (index, byte) in encoded.bytes().enumerate() {
        last_symbol = decode_base32_symbol(byte, index)?;
    }
    let unused_trailing_bits = (encoded.len() * 5) % 8;
    if unused_trailing_bits != 0 && last_symbol & ((1u8 << unused_trailing_bits) - 1) != 0 {
        return Err(NkeyCodecError::NonCanonical {
            reason: NonCanonicalReason::TrailingBits,
            index: Some(encoded.len() - 1),
        });
    }

    let mut output = Vec::with_capacity(decoded_len);
    let mut accumulator = 0u16;
    let mut bits = 0u8;
    for (index, byte) in encoded.bytes().enumerate() {
        let symbol = decode_base32_symbol(byte, index)?;
        accumulator = (accumulator << 5) | u16::from(symbol);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            let decoded = u8::try_from((accumulator >> bits) & 0xff).map_err(|_| {
                NkeyCodecError::Resource {
                    phase: CodecPhase::Base32Output,
                    requested: usize::from(accumulator),
                    limit: usize::from(u8::MAX),
                }
            })?;
            output.push(decoded);
        }
        accumulator &= low_bits_mask(bits);
    }
    if output.len() != decoded_len {
        return Err(NkeyCodecError::Length {
            phase: CodecPhase::Base32Output,
            actual: output.len(),
            expected: decoded_len,
        });
    }
    if encode_base32(&output, limits)?.as_bytes() != encoded.as_bytes() {
        return Err(NkeyCodecError::NonCanonical {
            reason: NonCanonicalReason::RoundTrip,
            index: None,
        });
    }
    Ok(output)
}

const fn is_possible_base32_len(encoded_chars: usize) -> bool {
    matches!(encoded_chars % 8, 0 | 2 | 4 | 5 | 7)
}

const fn low_bits_mask(bits: u8) -> u16 {
    if bits == 0 { 0 } else { (1u16 << bits) - 1 }
}

fn decode_base32_symbol(byte: u8, index: usize) -> Result<u8, NkeyCodecError> {
    match byte {
        b'A'..=b'Z' => Ok(byte - b'A'),
        b'2'..=b'7' => Ok(byte - b'2' + 26),
        b'a'..=b'z' => Err(NkeyCodecError::NonCanonical {
            reason: NonCanonicalReason::Lowercase,
            index: Some(index),
        }),
        b'=' => Err(NkeyCodecError::NonCanonical {
            reason: NonCanonicalReason::Padding,
            index: Some(index),
        }),
        b' ' | b'\t' | b'\r' | b'\n' => Err(NkeyCodecError::NonCanonical {
            reason: NonCanonicalReason::Whitespace,
            index: Some(index),
        }),
        b'-' | b'_' => Err(NkeyCodecError::NonCanonical {
            reason: NonCanonicalReason::Separator,
            index: Some(index),
        }),
        _ => Err(NkeyCodecError::Alphabet { index }),
    }
}

pub(super) fn crc16_xmodem(body: &[u8]) -> Result<u16, NkeyCodecError> {
    ensure_body_limit(body.len())?;

    let mut crc = 0u16;
    for byte in body {
        crc ^= u16::from(*byte) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    Ok(crc)
}

pub(super) fn append_checksum(body: &[u8]) -> Result<Vec<u8>, NkeyCodecError> {
    ensure_body_limit(body.len())?;
    let frame_len = body
        .len()
        .checked_add(CHECKSUM_BYTES)
        .ok_or(NkeyCodecError::Resource {
            phase: CodecPhase::ChecksumFrame,
            requested: usize::MAX,
            limit: MAX_FRAME_BYTES,
        })?;
    if frame_len > MAX_FRAME_BYTES {
        return Err(NkeyCodecError::Resource {
            phase: CodecPhase::ChecksumFrame,
            requested: frame_len,
            limit: MAX_FRAME_BYTES,
        });
    }

    let checksum = crc16_xmodem(body)?.to_le_bytes();
    let mut frame = Vec::with_capacity(frame_len);
    frame.extend_from_slice(body);
    frame.extend_from_slice(&checksum);
    Ok(frame)
}

pub(super) fn split_and_verify_checksum(frame: &[u8]) -> Result<&[u8], NkeyCodecError> {
    if frame.len() < CHECKSUM_BYTES {
        return Err(NkeyCodecError::Length {
            phase: CodecPhase::ChecksumFrame,
            actual: frame.len(),
            expected: CHECKSUM_BYTES,
        });
    }
    if frame.len() > MAX_FRAME_BYTES {
        return Err(NkeyCodecError::Resource {
            phase: CodecPhase::ChecksumFrame,
            requested: frame.len(),
            limit: MAX_FRAME_BYTES,
        });
    }

    let body_len = frame
        .len()
        .checked_sub(CHECKSUM_BYTES)
        .ok_or(NkeyCodecError::Length {
            phase: CodecPhase::ChecksumFrame,
            actual: frame.len(),
            expected: CHECKSUM_BYTES,
        })?;
    let (body, encoded_checksum) = frame.split_at(body_len);
    let encoded_checksum =
        <[u8; CHECKSUM_BYTES]>::try_from(encoded_checksum).map_err(|_| NkeyCodecError::Length {
            phase: CodecPhase::ChecksumFrame,
            actual: frame.len(),
            expected: CHECKSUM_BYTES,
        })?;
    if crc16_xmodem(body)? != u16::from_le_bytes(encoded_checksum) {
        return Err(NkeyCodecError::Checksum { body_len });
    }
    Ok(body)
}

fn ensure_body_limit(body_len: usize) -> Result<(), NkeyCodecError> {
    if body_len > MAX_BODY_BYTES {
        return Err(NkeyCodecError::Resource {
            phase: CodecPhase::ChecksumBody,
            requested: body_len,
            limit: MAX_BODY_BYTES,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_rfc4648_vectors_and_every_one_byte_value_are_exact() {
        for (decoded, encoded) in [
            (b"".as_slice(), ""),
            (b"f".as_slice(), "MY"),
            (b"fo".as_slice(), "MZXQ"),
            (b"foo".as_slice(), "MZXW6"),
            (b"foob".as_slice(), "MZXW6YQ"),
            (b"fooba".as_slice(), "MZXW6YTB"),
            (b"foobar".as_slice(), "MZXW6YTBOI"),
        ] {
            assert_eq!(
                encode_base32(decoded, Base32Limits::default()).as_deref(),
                Ok(encoded)
            );
            assert_eq!(
                decode_base32(encoded, Base32Limits::default()).as_deref(),
                Ok(decoded)
            );
        }

        for byte in u8::MIN..=u8::MAX {
            let decoded = [byte];
            let encoded = encode_base32(&decoded, Base32Limits::default())
                .expect("one-byte RFC 4648 value must encode");
            assert_eq!(encoded.len(), 2);
            assert_eq!(
                decode_base32(&encoded, Base32Limits::default()),
                Ok(decoded.to_vec()),
                "one-byte vector {byte:#04x}"
            );
        }
    }

    #[test]
    fn base32_every_symbol_and_residual_bit_count_round_trip_canonically() {
        for symbol in BASE32_ALPHABET {
            let encoded = String::from_utf8(vec![*symbol; 8]).expect("alphabet is ASCII");
            let decoded = decode_base32(&encoded, Base32Limits::default())
                .expect("every alphabet symbol is accepted in a complete block");
            assert_eq!(decoded.len(), 5);
            assert_eq!(
                encode_base32(&decoded, Base32Limits::default()).as_deref(),
                Ok(encoded.as_str())
            );
        }

        for decoded_len in 0..=9 {
            let decoded = (0..decoded_len)
                .map(|index| u8::try_from(index * 29).expect("small residual vector"))
                .collect::<Vec<_>>();
            let encoded = encode_base32(&decoded, Base32Limits::default())
                .expect("all five decoded-byte residual classes encode");
            assert_eq!(
                encoded.len(),
                base32_encoded_len(decoded.len()).expect("bounded encoded length")
            );
            assert_eq!(
                decode_base32(&encoded, Base32Limits::default()),
                Ok(decoded)
            );
        }
    }

    #[test]
    fn base32_capacity_plans_and_configured_limits_fail_before_allocation() {
        assert_eq!(base32_encoded_len(0), Ok(0));
        assert_eq!(base32_encoded_len(1), Ok(2));
        assert_eq!(base32_encoded_len(35), Ok(56));
        assert_eq!(base32_encoded_len(36), Ok(58));
        assert_eq!(base32_encoded_len(MAX_FRAME_BYTES), Ok(108));
        assert_eq!(base32_decoded_len(0), Ok(0));
        assert_eq!(base32_decoded_len(2), Ok(1));
        assert_eq!(base32_decoded_len(56), Ok(35));
        assert_eq!(base32_decoded_len(58), Ok(36));
        assert_eq!(base32_decoded_len(MAX_BASE32_ENCODED_CHARS), Ok(67));
        assert_eq!(
            base32_encoded_len(usize::MAX),
            Err(NkeyCodecError::Resource {
                phase: CodecPhase::Base32Output,
                requested: usize::MAX,
                limit: MAX_BASE32_ENCODED_CHARS,
            })
        );
        assert_eq!(
            base32_decoded_len(usize::MAX),
            Err(NkeyCodecError::Resource {
                phase: CodecPhase::Base32Output,
                requested: usize::MAX,
                limit: MAX_FRAME_BYTES,
            })
        );

        let exact = [0xa5; MAX_FRAME_BYTES];
        let encoded =
            encode_base32(&exact, Base32Limits::default()).expect("maximum NKey frame must encode");
        assert_eq!(encoded.len(), MAX_BASE32_ENCODED_CHARS);
        assert_eq!(
            decode_base32(&encoded, Base32Limits::default()),
            Ok(exact.to_vec())
        );

        let decoded_over = [0x5a; MAX_FRAME_BYTES + 1];
        assert_eq!(
            encode_base32(
                &decoded_over,
                Base32Limits {
                    max_decoded_bytes: usize::MAX,
                    max_encoded_chars: usize::MAX,
                },
            ),
            Err(NkeyCodecError::Resource {
                phase: CodecPhase::Base32Input,
                requested: MAX_FRAME_BYTES + 1,
                limit: MAX_FRAME_BYTES,
            })
        );
        assert_eq!(
            encode_base32(
                &exact,
                Base32Limits {
                    max_decoded_bytes: MAX_FRAME_BYTES,
                    max_encoded_chars: MAX_BASE32_ENCODED_CHARS - 1,
                },
            ),
            Err(NkeyCodecError::Resource {
                phase: CodecPhase::Base32Output,
                requested: MAX_BASE32_ENCODED_CHARS,
                limit: MAX_BASE32_ENCODED_CHARS - 1,
            })
        );
        assert_eq!(
            decode_base32(
                &encoded,
                Base32Limits {
                    max_decoded_bytes: MAX_FRAME_BYTES,
                    max_encoded_chars: MAX_BASE32_ENCODED_CHARS - 1,
                },
            ),
            Err(NkeyCodecError::Resource {
                phase: CodecPhase::Base32Input,
                requested: MAX_BASE32_ENCODED_CHARS,
                limit: MAX_BASE32_ENCODED_CHARS - 1,
            })
        );
        assert_eq!(
            decode_base32(
                &encoded,
                Base32Limits {
                    max_decoded_bytes: MAX_FRAME_BYTES - 1,
                    max_encoded_chars: MAX_BASE32_ENCODED_CHARS,
                },
            ),
            Err(NkeyCodecError::Resource {
                phase: CodecPhase::Base32Output,
                requested: MAX_FRAME_BYTES,
                limit: MAX_FRAME_BYTES - 1,
            })
        );
    }

    #[test]
    fn base32_rejects_every_noncanonical_class_at_an_exact_position() {
        for impossible_len in [1, 3, 6, 9, 11, 14] {
            let encoded = "A".repeat(impossible_len);
            assert_eq!(
                decode_base32(&encoded, Base32Limits::default()),
                Err(NkeyCodecError::Length {
                    phase: CodecPhase::Base32Input,
                    actual: impossible_len,
                    expected: impossible_len + 1,
                })
            );
        }

        for (encoded, expected) in [
            (
                "mY",
                NkeyCodecError::NonCanonical {
                    reason: NonCanonicalReason::Lowercase,
                    index: Some(0),
                },
            ),
            (
                "M=",
                NkeyCodecError::NonCanonical {
                    reason: NonCanonicalReason::Padding,
                    index: Some(1),
                },
            ),
            (
                "M ",
                NkeyCodecError::NonCanonical {
                    reason: NonCanonicalReason::Whitespace,
                    index: Some(1),
                },
            ),
            (
                "M-",
                NkeyCodecError::NonCanonical {
                    reason: NonCanonicalReason::Separator,
                    index: Some(1),
                },
            ),
            ("M!", NkeyCodecError::Alphabet { index: 1 }),
            ("AAAAAAA!", NkeyCodecError::Alphabet { index: 7 }),
        ] {
            let before = encoded.to_owned();
            assert_eq!(
                decode_base32(encoded, Base32Limits::default()),
                Err(expected)
            );
            assert_eq!(encoded, before);
        }

        let mut rejected_trailing_forms = 0usize;
        for decoded_len in 1..=4 {
            let canonical = encode_base32(&vec![0; decoded_len], Base32Limits::default())
                .expect("residual vector must encode");
            let unused_bits = (canonical.len() * 5) % 8;
            let unused_mask = (1u8 << unused_bits) - 1;
            for symbol_value in 0u8..32 {
                if symbol_value & unused_mask == 0 {
                    continue;
                }
                let mut mutated = canonical.as_bytes().to_vec();
                let final_index = mutated.len() - 1;
                mutated[final_index] = BASE32_ALPHABET[usize::from(symbol_value)];
                let mutated = String::from_utf8(mutated).expect("alphabet is ASCII");
                assert_eq!(
                    decode_base32(&mutated, Base32Limits::default()),
                    Err(NkeyCodecError::NonCanonical {
                        reason: NonCanonicalReason::TrailingBits,
                        index: Some(final_index),
                    }),
                    "decoded_len={decoded_len} symbol_value={symbol_value}"
                );
                rejected_trailing_forms += 1;
            }
        }
        assert_eq!(rejected_trailing_forms, 98);
    }

    fn reference_crc16_xmodem(body: &[u8]) -> u16 {
        let mut remainder = 0u16;
        for byte in body {
            for input_mask in [0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01] {
                let feedback = (remainder & 0x8000 != 0) != (byte & input_mask != 0);
                remainder <<= 1;
                if feedback {
                    remainder ^= 0x1021;
                }
            }
        }
        remainder
    }

    #[test]
    fn standard_empty_single_and_every_byte_vectors_are_exact() {
        assert_eq!(crc16_xmodem(b""), Ok(0x0000));
        assert_eq!(crc16_xmodem(&[0x01]), Ok(0x1021));
        assert_eq!(crc16_xmodem(b"123456789"), Ok(0x31c3));

        for byte in u8::MIN..=u8::MAX {
            assert_eq!(
                crc16_xmodem(&[byte]),
                Ok(reference_crc16_xmodem(&[byte])),
                "single-byte vector {byte:#04x}"
            );
        }
    }

    #[test]
    fn exact_limit_and_over_limit_are_bounded_before_allocation_or_work() {
        let exact = (0u8..65).collect::<Vec<_>>();
        assert_eq!(exact.len(), MAX_BODY_BYTES);
        assert_eq!(crc16_xmodem(&exact), Ok(0x28cd));

        let frame = append_checksum(&exact).expect("exact-limit body must frame");
        assert_eq!(frame.len(), MAX_FRAME_BYTES);
        assert_eq!(frame.get(MAX_BODY_BYTES..), Some([0xcd, 0x28].as_slice()));
        assert_eq!(split_and_verify_checksum(&frame), Ok(exact.as_slice()));

        let over = [0x5a; MAX_BODY_BYTES + 1];
        let expected = NkeyCodecError::Resource {
            phase: CodecPhase::ChecksumBody,
            requested: MAX_BODY_BYTES + 1,
            limit: MAX_BODY_BYTES,
        };
        assert_eq!(crc16_xmodem(&over), Err(expected.clone()));
        assert_eq!(append_checksum(&over), Err(expected));

        let over_frame = [0x5a; MAX_FRAME_BYTES + 1];
        assert_eq!(
            split_and_verify_checksum(&over_frame),
            Err(NkeyCodecError::Resource {
                phase: CodecPhase::ChecksumFrame,
                requested: MAX_FRAME_BYTES + 1,
                limit: MAX_FRAME_BYTES,
            })
        );
    }

    #[test]
    fn framing_is_little_endian_complete_and_failure_atomic() {
        let body = b"123456789";
        let before = *body;
        let frame = append_checksum(body).expect("standard vector must frame");
        assert_eq!(body, &before);
        assert_eq!(frame.get(body.len()..), Some([0xc3, 0x31].as_slice()));
        assert_eq!(split_and_verify_checksum(&frame), Ok(body.as_slice()));

        let mut corrupted = frame.clone();
        let last = corrupted
            .last_mut()
            .expect("framed checksum always has a last byte");
        *last ^= 0x01;
        let corrupted_before = corrupted.clone();
        assert_eq!(
            split_and_verify_checksum(&corrupted),
            Err(NkeyCodecError::Checksum {
                body_len: body.len(),
            })
        );
        assert_eq!(corrupted, corrupted_before);

        for short in [&[][..], &[0x00][..]] {
            let before = short.to_vec();
            assert_eq!(
                split_and_verify_checksum(short),
                Err(NkeyCodecError::Length {
                    phase: CodecPhase::ChecksumFrame,
                    actual: short.len(),
                    expected: CHECKSUM_BYTES,
                })
            );
            assert_eq!(short, before);
        }
    }

    #[test]
    fn errors_are_stable_safe_metadata_and_crc_has_no_security_claim() {
        let errors = [
            NkeyCodecError::Length {
                phase: CodecPhase::ChecksumFrame,
                actual: 1,
                expected: 2,
            },
            NkeyCodecError::Alphabet { index: 7 },
            NkeyCodecError::NonCanonical {
                reason: NonCanonicalReason::TrailingBits,
                index: Some(8),
            },
            NkeyCodecError::Checksum { body_len: 34 },
            NkeyCodecError::Resource {
                phase: CodecPhase::ChecksumBody,
                requested: 66,
                limit: 65,
            },
        ];
        assert_eq!(
            errors.iter().map(NkeyCodecError::class).collect::<Vec<_>>(),
            ["length", "alphabet", "noncanonical", "checksum", "resource"]
        );
        for error in errors {
            let display = error.to_string();
            let debug = format!("{error:?}");
            assert!(!display.contains("SUAAAA"));
            assert!(!debug.contains("SUAAAA"));
            assert!(!display.contains("secret"));
            assert!(!debug.contains("secret"));
        }

        assert_eq!(CodecPhase::Base32Input.as_str(), "base32-input");
        assert_eq!(CodecPhase::Base32Output.as_str(), "base32-output");
        for reason in [
            NonCanonicalReason::Lowercase,
            NonCanonicalReason::Padding,
            NonCanonicalReason::Whitespace,
            NonCanonicalReason::Separator,
            NonCanonicalReason::TrailingBits,
            NonCanonicalReason::RoundTrip,
        ] {
            assert!(!reason.as_str().is_empty());
        }

        let docs = include_str!("nkey_codec.rs");
        for boundary in [
            "accidental corruption",
            "not authentication",
            "authorization",
            "collision resistance",
            "signing",
            "a MAC",
            "key-format decision",
        ] {
            assert!(
                docs.contains(boundary),
                "missing no-claim boundary: {boundary}"
            );
        }
    }
}
