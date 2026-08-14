//! Strictly safe, bounded NKey text-codec primitives.
//!
//! This pre-cutover module currently owns only CRC16-XMODEM computation and
//! checksum framing. CRC detects accidental corruption; it is not
//! authentication, authorization, collision resistance, signing, a MAC, or a
//! key-format decision. The production identity paths continue to use the
//! incumbent `nkeys` crate until the later parity and cutover gates close.

use std::fmt;

pub(super) const CHECKSUM_BYTES: usize = 2;
pub(super) const MAX_BODY_BYTES: usize = 65;
pub(super) const MAX_FRAME_BYTES: usize = MAX_BODY_BYTES + CHECKSUM_BYTES;

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
