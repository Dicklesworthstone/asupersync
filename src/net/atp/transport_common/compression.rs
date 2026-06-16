//! Pre-encode compression helpers for ATP transports.
//!
//! This module owns the transport-agnostic decision and restore logic J6 needs
//! before QUIC/RaptorQ can put compressed bytes on the wire. It deliberately
//! keeps raw-content integrity outside the transform: callers still commit to
//! and verify the original bytes in their manifest, while the descriptor below
//! records the reversible wire encoding.

use serde::{Deserialize, Serialize};

/// Compression algorithm applied before transport encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompressionAlgorithm {
    /// Gzip framing backed by the existing pure-Rust `flate2` feature.
    Gzip,
}

/// Policy for deciding whether a pre-encode compression result is worth using.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompressionPolicy {
    /// Algorithm to attempt.
    pub algorithm: CompressionAlgorithm,
    /// Inputs smaller than this are left raw.
    pub min_input_bytes: usize,
    /// Minimum absolute bytes saved before accepting compression.
    pub min_savings_bytes: usize,
    /// Minimum savings ratio in basis points: 500 means 5%.
    pub min_savings_bps: u16,
}

impl Default for CompressionPolicy {
    fn default() -> Self {
        Self {
            algorithm: CompressionAlgorithm::Gzip,
            min_input_bytes: 1024,
            min_savings_bytes: 64,
            min_savings_bps: 500,
        }
    }
}

impl CompressionPolicy {
    fn accept_compressed(self, original_len: usize, encoded_len: usize) -> CompressionSkipReason {
        if encoded_len >= original_len {
            return CompressionSkipReason::NotSmaller;
        }
        let saved = original_len - encoded_len;
        if saved < self.min_savings_bytes {
            return CompressionSkipReason::SavingsBelowThreshold;
        }
        let saved_u128 = u128::try_from(saved).unwrap_or(u128::MAX);
        let original_u128 = u128::try_from(original_len).unwrap_or(u128::MAX);
        let savings_bps = saved_u128.saturating_mul(10_000) / original_u128.max(1);
        let required_bps = u128::from(self.min_savings_bps.min(10_000));
        if savings_bps < required_bps {
            return CompressionSkipReason::SavingsBelowThreshold;
        }
        CompressionSkipReason::Accepted
    }
}

/// Reversible wire-encoding metadata for one compressed object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompressionDescriptor {
    /// Algorithm used to produce the encoded payload.
    pub algorithm: CompressionAlgorithm,
    /// Raw object size before compression.
    pub original_size: u64,
    /// Encoded object size carried by the transport.
    pub encoded_size: u64,
}

/// Result of attempting a pre-encode transform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreEncodeCompression {
    /// Compression was accepted by policy and these bytes should be encoded.
    Compressed {
        descriptor: CompressionDescriptor,
        bytes: Vec<u8>,
    },
    /// Raw bytes should be sent instead.
    Skipped { reason: CompressionSkipReason },
}

/// Why a payload stayed raw.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompressionSkipReason {
    /// Internal sentinel used by [`CompressionPolicy::accept_compressed`].
    Accepted,
    /// The crate was built without the `compression` feature.
    FeatureDisabled,
    /// Empty inputs are already minimal.
    Empty,
    /// Input was smaller than [`CompressionPolicy::min_input_bytes`].
    BelowMinInput,
    /// Encoded output was not smaller than the original.
    NotSmaller,
    /// Savings were below the configured absolute or relative threshold.
    SavingsBelowThreshold,
}

/// Compression/decompression failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompressionError {
    /// The crate was built without support for the requested algorithm.
    FeatureDisabled(CompressionAlgorithm),
    /// Compression backend I/O failed.
    Backend(String),
    /// Descriptor and payload are inconsistent.
    InvalidDescriptor(String),
    /// Decompressed output exceeded the caller's fail-closed limit.
    OutputTooLarge { limit: usize, actual: usize },
}

impl std::fmt::Display for CompressionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FeatureDisabled(algorithm) => {
                write!(f, "compression algorithm {algorithm:?} is not enabled")
            }
            Self::Backend(message) => f.write_str(message),
            Self::InvalidDescriptor(message) => f.write_str(message),
            Self::OutputTooLarge { limit, actual } => write!(
                f,
                "decompressed output exceeded limit: {actual} bytes > {limit} bytes"
            ),
        }
    }
}

impl std::error::Error for CompressionError {}

/// Compress `raw` when the configured policy proves it saves meaningful bytes.
pub fn maybe_compress_pre_encode(
    raw: &[u8],
    policy: CompressionPolicy,
) -> Result<PreEncodeCompression, CompressionError> {
    if raw.is_empty() {
        return Ok(PreEncodeCompression::Skipped {
            reason: CompressionSkipReason::Empty,
        });
    }
    if raw.len() < policy.min_input_bytes {
        return Ok(PreEncodeCompression::Skipped {
            reason: CompressionSkipReason::BelowMinInput,
        });
    }

    let encoded = compress_with(policy.algorithm, raw)?;
    match policy.accept_compressed(raw.len(), encoded.len()) {
        CompressionSkipReason::Accepted => Ok(PreEncodeCompression::Compressed {
            descriptor: CompressionDescriptor {
                algorithm: policy.algorithm,
                original_size: u64::try_from(raw.len()).unwrap_or(u64::MAX),
                encoded_size: u64::try_from(encoded.len()).unwrap_or(u64::MAX),
            },
            bytes: encoded,
        }),
        reason => Ok(PreEncodeCompression::Skipped { reason }),
    }
}

/// Restore a pre-encoded payload and verify the descriptor exactly.
pub fn decompress_pre_encoded(
    descriptor: CompressionDescriptor,
    encoded: &[u8],
    max_output_bytes: usize,
) -> Result<Vec<u8>, CompressionError> {
    let expected_encoded = usize::try_from(descriptor.encoded_size).map_err(|_| {
        CompressionError::InvalidDescriptor(format!(
            "encoded size {} does not fit usize",
            descriptor.encoded_size
        ))
    })?;
    if encoded.len() != expected_encoded {
        return Err(CompressionError::InvalidDescriptor(format!(
            "encoded size mismatch: descriptor={expected_encoded}, actual={}",
            encoded.len()
        )));
    }

    let expected_original = usize::try_from(descriptor.original_size).map_err(|_| {
        CompressionError::InvalidDescriptor(format!(
            "original size {} does not fit usize",
            descriptor.original_size
        ))
    })?;
    if expected_original > max_output_bytes {
        return Err(CompressionError::OutputTooLarge {
            limit: max_output_bytes,
            actual: expected_original,
        });
    }

    let decoded = decompress_with(descriptor.algorithm, encoded, max_output_bytes)?;
    if decoded.len() != expected_original {
        return Err(CompressionError::InvalidDescriptor(format!(
            "decoded size mismatch: descriptor={expected_original}, actual={}",
            decoded.len()
        )));
    }
    Ok(decoded)
}

#[cfg(feature = "compression")]
fn compress_with(algorithm: CompressionAlgorithm, raw: &[u8]) -> Result<Vec<u8>, CompressionError> {
    match algorithm {
        CompressionAlgorithm::Gzip => {
            use flate2::Compression;
            use flate2::write::GzEncoder;
            use std::io::Write;

            let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
            encoder
                .write_all(raw)
                .map_err(|err| CompressionError::Backend(err.to_string()))?;
            encoder
                .finish()
                .map_err(|err| CompressionError::Backend(err.to_string()))
        }
    }
}

#[cfg(not(feature = "compression"))]
fn compress_with(
    algorithm: CompressionAlgorithm,
    _raw: &[u8],
) -> Result<Vec<u8>, CompressionError> {
    Err(CompressionError::FeatureDisabled(algorithm))
}

#[cfg(feature = "compression")]
fn decompress_with(
    algorithm: CompressionAlgorithm,
    encoded: &[u8],
    max_output_bytes: usize,
) -> Result<Vec<u8>, CompressionError> {
    match algorithm {
        CompressionAlgorithm::Gzip => {
            use flate2::read::GzDecoder;
            use std::io::Read;

            let mut decoder = GzDecoder::new(encoded);
            let mut out = Vec::with_capacity(max_output_bytes.min(64 * 1024));
            let mut buf = [0_u8; 8192];
            loop {
                let n = decoder
                    .read(&mut buf)
                    .map_err(|err| CompressionError::Backend(err.to_string()))?;
                if n == 0 {
                    break;
                }
                let next_len =
                    out.len()
                        .checked_add(n)
                        .ok_or(CompressionError::OutputTooLarge {
                            limit: max_output_bytes,
                            actual: usize::MAX,
                        })?;
                if next_len > max_output_bytes {
                    return Err(CompressionError::OutputTooLarge {
                        limit: max_output_bytes,
                        actual: next_len,
                    });
                }
                out.extend_from_slice(&buf[..n]);
            }
            Ok(out)
        }
    }
}

#[cfg(not(feature = "compression"))]
fn decompress_with(
    algorithm: CompressionAlgorithm,
    _encoded: &[u8],
    _max_output_bytes: usize,
) -> Result<Vec<u8>, CompressionError> {
    Err(CompressionError::FeatureDisabled(algorithm))
}

#[cfg(all(test, feature = "compression"))]
mod tests {
    use super::*;

    fn policy() -> CompressionPolicy {
        CompressionPolicy {
            min_input_bytes: 1,
            min_savings_bytes: 1,
            min_savings_bps: 1,
            ..CompressionPolicy::default()
        }
    }

    #[test]
    fn compressible_payload_is_encoded_and_restored() {
        let raw = b"atp-quic-compression\n".repeat(512);

        let PreEncodeCompression::Compressed { descriptor, bytes } =
            maybe_compress_pre_encode(&raw, policy()).expect("compress")
        else {
            panic!("compressible data should be encoded");
        };

        assert_eq!(descriptor.algorithm, CompressionAlgorithm::Gzip);
        assert_eq!(descriptor.original_size, u64::try_from(raw.len()).unwrap());
        assert!(bytes.len() < raw.len());

        let decoded =
            decompress_pre_encoded(descriptor, &bytes, raw.len()).expect("decompress exactly");
        assert_eq!(decoded, raw);
    }

    #[test]
    fn random_like_payload_stays_raw_when_not_worth_compressing() {
        let mut state = 0x1234_5678_9abc_def0_u64;
        let mut raw = Vec::with_capacity(8192);
        for _ in 0..8192 {
            state ^= state << 7;
            state ^= state >> 9;
            state ^= state << 8;
            raw.push(state.to_le_bytes()[0]);
        }

        let outcome = maybe_compress_pre_encode(&raw, CompressionPolicy::default())
            .expect("compression attempt");
        assert!(matches!(
            outcome,
            PreEncodeCompression::Skipped {
                reason: CompressionSkipReason::NotSmaller
                    | CompressionSkipReason::SavingsBelowThreshold
            }
        ));
    }

    #[test]
    fn below_minimum_input_stays_raw() {
        let outcome = maybe_compress_pre_encode(
            b"small",
            CompressionPolicy {
                min_input_bytes: 64,
                ..CompressionPolicy::default()
            },
        )
        .expect("skip small input");
        assert_eq!(
            outcome,
            PreEncodeCompression::Skipped {
                reason: CompressionSkipReason::BelowMinInput
            }
        );
    }

    #[test]
    fn restore_rejects_descriptor_size_mismatch() {
        let raw = b"same line\n".repeat(128);
        let PreEncodeCompression::Compressed {
            mut descriptor,
            bytes,
        } = maybe_compress_pre_encode(&raw, policy()).expect("compress")
        else {
            panic!("compressible data should be encoded");
        };
        descriptor.original_size = descriptor.original_size.saturating_add(1);

        let err =
            decompress_pre_encoded(descriptor, &bytes, raw.len() + 1).expect_err("size mismatch");
        assert!(matches!(err, CompressionError::InvalidDescriptor(_)));
    }

    #[test]
    fn restore_rejects_output_limit_before_inflating() {
        let raw = b"bounded output\n".repeat(256);
        let PreEncodeCompression::Compressed { descriptor, bytes } =
            maybe_compress_pre_encode(&raw, policy()).expect("compress")
        else {
            panic!("compressible data should be encoded");
        };

        let err =
            decompress_pre_encoded(descriptor, &bytes, raw.len() - 1).expect_err("limit exceeded");
        assert_eq!(
            err,
            CompressionError::OutputTooLarge {
                limit: raw.len() - 1,
                actual: raw.len()
            }
        );
    }
}
