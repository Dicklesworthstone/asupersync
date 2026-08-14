//! Bounded, test-only NKey codec oracle scaffold.
//!
//! This module deliberately owns no key type, signer, verifier, RNG, or secret
//! storage. It only makes the byte-level Base32 and CRC framing contract
//! executable before any production codec exists.

use std::fmt;

pub(super) const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
pub(super) const CHECKSUM_BYTES: usize = 2;
pub(super) const MAX_DECODED_BYTES: usize = 67;
pub(super) const MAX_ENCODED_CHARS: usize = 108;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct OracleProvenance {
    pub rust_package: &'static str,
    pub rust_version: &'static str,
    pub rust_checksum: &'static str,
    pub rust_repository: &'static str,
    pub rust_license_spdx: &'static str,
    pub official_go_package: &'static str,
    pub official_go_version: &'static str,
    pub official_go_commit: &'static str,
    pub official_go_license_spdx: &'static str,
    pub license_blob_git_sha: &'static str,
    pub normative_artifact_sha256: &'static str,
    pub independent_rows_sha256: &'static str,
    pub private_rows_sha256: &'static str,
    pub official_rows_sha256: &'static str,
    pub malformed_rows_sha256: &'static str,
    pub cross_prefix_rows_sha256: &'static str,
    pub graph_disposition: &'static str,
    pub unsafe_disposition: &'static str,
    pub lifecycle_disposition: &'static str,
}

pub(super) const PROVENANCE: OracleProvenance = OracleProvenance {
    rust_package: "nkeys",
    rust_version: "0.4.5",
    rust_checksum: "879011babc47a1c7fdf5a935ae3cfe94f34645ca0cac1c7f6424b36fc743d1bf",
    rust_repository: "https://github.com/wasmcloud/nkeys",
    rust_license_spdx: "Apache-2.0",
    official_go_package: "github.com/nats-io/nkeys",
    official_go_version: "0.4.16",
    official_go_commit: "c1eebf38bd8b1b1021b45b5f8f403052ac042dc5",
    official_go_license_spdx: "Apache-2.0",
    license_blob_git_sha: "261eeb9e9f8b2b4b0d119366dda99c6fd7d35c64",
    normative_artifact_sha256: "dd1d4fcf010e9cf6ba974a8f009a5038970c4f0663fb797c49a3eb04588a458d",
    independent_rows_sha256: "5e6026c0aa5e2f833c3cbc5cb2cd2e12c50cb9f2797324a8e3f18411f3b8f726",
    private_rows_sha256: "8ecb645e10141193cef4fd2a6f9877b3949df4e8c4d70057853e61f0ff24d868",
    official_rows_sha256: "bc0d8a282b54779e0de7e4c9b387ce468a3915305fbcc2a17a24485443da6296",
    malformed_rows_sha256: "75b855bfa2b3d4c5e30b50e7e0ae67d53092ce0ec02318eff24a119c120e806d",
    cross_prefix_rows_sha256: "dca4cfb3cd05d1cd08555f49978f4f930d9d6e75c185a243a5b84704e8b13437",
    graph_disposition: "single existing workspace-normal incumbent edge; no oracle edge or reference client added",
    unsafe_disposition: "direct nkeys source is unsafe-free; transitive data-encoding and rand use unsafe; fresh cutover audit remains required",
    lifecycle_disposition: "pre-cutover development scaffold; policy remains planned while nkeys is the production incumbent",
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum EncodedKind {
    Public,
    Seed,
    PrivateX25519,
    PrivateEd25519,
}

impl EncodedKind {
    pub(super) const fn field(self) -> Field {
        match self {
            Self::Public => Field::Public,
            Self::Seed => Field::Seed,
            Self::PrivateX25519 => Field::PrivateX25519,
            Self::PrivateEd25519 => Field::PrivateEd25519,
        }
    }

    pub(super) const fn encoded_len(self) -> usize {
        match self {
            Self::Public | Self::PrivateX25519 => 56,
            Self::Seed => 58,
            Self::PrivateEd25519 => 108,
        }
    }

    pub(super) const fn decoded_len(self) -> usize {
        match self {
            Self::Public | Self::PrivateX25519 => 35,
            Self::Seed => 36,
            Self::PrivateEd25519 => 67,
        }
    }

    pub(super) const fn body_len(self) -> usize {
        self.decoded_len() - CHECKSUM_BYTES
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Field {
    Public,
    Seed,
    PrivateX25519,
    PrivateEd25519,
    CodecInput,
}

impl Field {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Seed => "seed",
            Self::PrivateX25519 => "private-x25519",
            Self::PrivateEd25519 => "private-ed25519",
            Self::CodecInput => "codec-input",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum NonCanonicalKind {
    Lowercase,
    Padding,
    Whitespace,
    Separator,
    TrailingBits,
    RoundTrip,
}

impl NonCanonicalKind {
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
pub(super) enum CodecError {
    Length {
        field: Field,
        actual: usize,
        expected: usize,
    },
    Alphabet {
        field: Field,
        index: usize,
    },
    NonCanonical {
        field: Field,
        kind: NonCanonicalKind,
        index: Option<usize>,
    },
    Checksum {
        field: Field,
    },
    Resource {
        field: Field,
        requested: usize,
        limit: usize,
    },
}

impl CodecError {
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

impl fmt::Display for CodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length {
                field,
                actual,
                expected,
            } => write!(
                formatter,
                "{} length is {actual}; expected {expected}",
                field.as_str()
            ),
            Self::Alphabet { field, index } => write!(
                formatter,
                "{} contains a non-alphabet byte at index {index}",
                field.as_str()
            ),
            Self::NonCanonical { field, kind, index } => {
                write!(
                    formatter,
                    "{} is noncanonical ({})",
                    field.as_str(),
                    kind.as_str()
                )?;
                if let Some(index) = index {
                    write!(formatter, " at index {index}")?;
                }
                Ok(())
            }
            Self::Checksum { field } => {
                write!(formatter, "{} checksum mismatch", field.as_str())
            }
            Self::Resource {
                field,
                requested,
                limit,
            } => write!(
                formatter,
                "{} resource request {requested} exceeds limit {limit}",
                field.as_str()
            ),
        }
    }
}

impl std::error::Error for CodecError {}

pub(super) fn encoded_len_for(decoded_bytes: usize) -> Result<usize, CodecError> {
    if decoded_bytes > MAX_DECODED_BYTES {
        return Err(CodecError::Resource {
            field: Field::CodecInput,
            requested: decoded_bytes,
            limit: MAX_DECODED_BYTES,
        });
    }
    let bits = decoded_bytes.checked_mul(8).ok_or(CodecError::Resource {
        field: Field::CodecInput,
        requested: decoded_bytes,
        limit: MAX_DECODED_BYTES,
    })?;
    bits.checked_add(4)
        .map(|rounded| rounded / 5)
        .ok_or(CodecError::Resource {
            field: Field::CodecInput,
            requested: usize::MAX,
            limit: MAX_ENCODED_CHARS,
        })
}

pub(super) fn decoded_capacity_for(encoded_chars: usize) -> Result<usize, CodecError> {
    if encoded_chars > MAX_ENCODED_CHARS {
        return Err(CodecError::Resource {
            field: Field::CodecInput,
            requested: encoded_chars,
            limit: MAX_ENCODED_CHARS,
        });
    }
    encoded_chars
        .checked_mul(5)
        .map(|bits| bits / 8)
        .ok_or(CodecError::Resource {
            field: Field::CodecInput,
            requested: encoded_chars,
            limit: MAX_ENCODED_CHARS,
        })
}

pub(super) fn crc16_xmodem(bytes: &[u8]) -> u16 {
    let mut crc = 0u16;
    for byte in bytes {
        crc ^= u16::from(*byte) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc
}

pub(super) fn encode_with_checksum(kind: EncodedKind, body: &[u8]) -> Result<String, CodecError> {
    if body.len() != kind.body_len() {
        return Err(CodecError::Length {
            field: kind.field(),
            actual: body.len(),
            expected: kind.body_len(),
        });
    }
    let frame_len = body
        .len()
        .checked_add(CHECKSUM_BYTES)
        .ok_or(CodecError::Resource {
            field: kind.field(),
            requested: usize::MAX,
            limit: MAX_DECODED_BYTES,
        })?;
    if frame_len > MAX_DECODED_BYTES {
        return Err(CodecError::Resource {
            field: kind.field(),
            requested: frame_len,
            limit: MAX_DECODED_BYTES,
        });
    }

    let mut frame = Vec::with_capacity(frame_len);
    frame.extend_from_slice(body);
    frame.extend_from_slice(&crc16_xmodem(body).to_le_bytes());
    encode_canonical(kind, &frame)
}

pub(super) fn decode_and_verify(kind: EncodedKind, encoded: &str) -> Result<Vec<u8>, CodecError> {
    let frame = decode_canonical(kind, encoded)?;
    let body_len = frame
        .len()
        .checked_sub(CHECKSUM_BYTES)
        .ok_or(CodecError::Length {
            field: kind.field(),
            actual: frame.len(),
            expected: CHECKSUM_BYTES,
        })?;
    let (body, checksum) = frame.split_at(body_len);
    let checksum = <[u8; CHECKSUM_BYTES]>::try_from(checksum).map_err(|_| CodecError::Length {
        field: kind.field(),
        actual: frame.len(),
        expected: kind.decoded_len(),
    })?;
    if crc16_xmodem(body) != u16::from_le_bytes(checksum) {
        return Err(CodecError::Checksum {
            field: kind.field(),
        });
    }
    Ok(body.to_vec())
}

fn encode_canonical(kind: EncodedKind, frame: &[u8]) -> Result<String, CodecError> {
    if frame.len() != kind.decoded_len() {
        return Err(CodecError::Length {
            field: kind.field(),
            actual: frame.len(),
            expected: kind.decoded_len(),
        });
    }
    if frame.len() > MAX_DECODED_BYTES {
        return Err(CodecError::Resource {
            field: kind.field(),
            requested: frame.len(),
            limit: MAX_DECODED_BYTES,
        });
    }
    let capacity = encoded_len_for(frame.len())?;
    if capacity > MAX_ENCODED_CHARS {
        return Err(CodecError::Resource {
            field: kind.field(),
            requested: capacity,
            limit: MAX_ENCODED_CHARS,
        });
    }

    let mut output = String::with_capacity(capacity);
    let mut accumulator = 0u16;
    let mut bits = 0u8;
    for byte in frame {
        accumulator = (accumulator << 8) | u16::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let index = usize::from((accumulator >> bits) & 0x1f);
            let symbol = BASE32_ALPHABET
                .get(index)
                .copied()
                .ok_or(CodecError::Alphabet {
                    field: kind.field(),
                    index,
                })?;
            output.push(char::from(symbol));
        }
        accumulator &= if bits == 0 { 0 } else { (1u16 << bits) - 1 };
    }
    if bits != 0 {
        let index = usize::from((accumulator << (5 - bits)) & 0x1f);
        let symbol = BASE32_ALPHABET
            .get(index)
            .copied()
            .ok_or(CodecError::Alphabet {
                field: kind.field(),
                index,
            })?;
        output.push(char::from(symbol));
    }
    debug_assert_eq!(output.len(), capacity);
    Ok(output)
}

fn decode_canonical(kind: EncodedKind, encoded: &str) -> Result<Vec<u8>, CodecError> {
    if encoded.len() > MAX_ENCODED_CHARS {
        return Err(CodecError::Resource {
            field: kind.field(),
            requested: encoded.len(),
            limit: MAX_ENCODED_CHARS,
        });
    }
    if encoded.len() != kind.encoded_len() {
        return Err(CodecError::Length {
            field: kind.field(),
            actual: encoded.len(),
            expected: kind.encoded_len(),
        });
    }

    let capacity = decoded_capacity_for(encoded.len())?;
    if capacity > MAX_DECODED_BYTES {
        return Err(CodecError::Resource {
            field: kind.field(),
            requested: capacity,
            limit: MAX_DECODED_BYTES,
        });
    }
    let mut output = Vec::with_capacity(capacity);
    let mut accumulator = 0u16;
    let mut bits = 0u8;

    for (index, byte) in encoded.bytes().enumerate() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'2'..=b'7' => byte - b'2' + 26,
            b'a'..=b'z' => {
                return Err(CodecError::NonCanonical {
                    field: kind.field(),
                    kind: NonCanonicalKind::Lowercase,
                    index: Some(index),
                });
            }
            b'=' => {
                return Err(CodecError::NonCanonical {
                    field: kind.field(),
                    kind: NonCanonicalKind::Padding,
                    index: Some(index),
                });
            }
            b' ' | b'\t' | b'\r' | b'\n' => {
                return Err(CodecError::NonCanonical {
                    field: kind.field(),
                    kind: NonCanonicalKind::Whitespace,
                    index: Some(index),
                });
            }
            b'-' | b'_' => {
                return Err(CodecError::NonCanonical {
                    field: kind.field(),
                    kind: NonCanonicalKind::Separator,
                    index: Some(index),
                });
            }
            _ => {
                return Err(CodecError::Alphabet {
                    field: kind.field(),
                    index,
                });
            }
        };

        accumulator = (accumulator << 5) | u16::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            let decoded =
                u8::try_from((accumulator >> bits) & 0xff).map_err(|_| CodecError::Resource {
                    field: kind.field(),
                    requested: usize::from(accumulator),
                    limit: usize::from(u8::MAX),
                })?;
            output.push(decoded);
        }
        accumulator &= if bits == 0 { 0 } else { (1u16 << bits) - 1 };
    }

    if accumulator != 0 {
        return Err(CodecError::NonCanonical {
            field: kind.field(),
            kind: NonCanonicalKind::TrailingBits,
            index: Some(encoded.len() - 1),
        });
    }
    if output.len() != kind.decoded_len() {
        return Err(CodecError::Length {
            field: kind.field(),
            actual: output.len(),
            expected: kind.decoded_len(),
        });
    }
    if encode_canonical(kind, &output)?.as_bytes() != encoded.as_bytes() {
        return Err(CodecError::NonCanonical {
            field: kind.field(),
            kind: NonCanonicalKind::RoundTrip,
            index: None,
        });
    }
    Ok(output)
}
