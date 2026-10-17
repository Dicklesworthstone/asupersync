//! RaptorQ decode proof artifact for explainable failures.
//!
//! This module provides a compact, deterministic artifact that explains
//! how a decode operation proceeded and why it succeeded or failed.
//!
//! # Design Goals
//!
//! 1. **Deterministic**: Same inputs produce identical artifacts
//! 2. **Bounded size**: Explicit caps on unbounded collections
//! 3. **Explainable**: Human-readable failure reasons
//! 4. **Replayable**: Sufficient info to reproduce decoder state transitions

use crate::raptorq::decoder::{DecodeError, InactivationDecoder, ReceivedSymbol};
use crate::raptorq::systematic::{SystematicEncoder, SystematicParamError, SystematicParams};
use crate::types::ObjectId;
use crate::util::DetHasher;
use sha2::{Digest, Sha256};
use std::collections::BinaryHeap;
use std::fmt;

/// Maximum number of pivot events to record before truncation.
pub const MAX_PIVOT_EVENTS: usize = 256;

/// Maximum number of received symbol IDs to record.
pub const MAX_RECEIVED_SYMBOLS: usize = 1024;

/// Version of the proof artifact schema.
pub const PROOF_SCHEMA_VERSION: u8 = 2;

/// Version of the proof-artifact distribution manifest schema.
pub const PROOF_ARTIFACT_DISTRIBUTION_SCHEMA_VERSION: u8 = 1;

// ============================================================================
// Cryptographic attestation hash
// ============================================================================

/// Cryptographic SHA-256 hash for proof attestation and forgery detection.
///
/// Replaces the previous 64-bit non-cryptographic hash to prevent proof
/// forgery attacks where an attacker could construct false proofs that
/// hash to the same value as legitimate proofs.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "test-internals",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct ProofHash([u8; 32]);

impl ProofHash {
    /// Returns the raw 32-byte hash value.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns the hash as a 64-character lowercase hex string.
    #[must_use]
    pub fn to_hex(&self) -> String {
        let mut out = String::with_capacity(64);
        use std::fmt::Write;
        for byte in &self.0 {
            let _ = write!(out, "{byte:02x}");
        }
        out
    }

    /// Create ProofHash from hex string (for testing/deserialization).
    #[cfg(test)]
    pub fn from_hex(hex: &str) -> Option<Self> {
        if hex.len() != 64 {
            return None;
        }
        let bytes = hex.as_bytes();
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            let pair = [*bytes.get(i * 2)?, *bytes.get(i * 2 + 1)?];
            let s = std::str::from_utf8(&pair).ok()?;
            *byte = u8::from_str_radix(s, 16).ok()?;
        }
        Some(Self(out))
    }
}

impl std::fmt::Debug for ProofHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ProofHash({})", &self.to_hex()[..16]) // Truncated for readability
    }
}

impl std::fmt::Display for ProofHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

// ============================================================================
// Proof artifact types
// ============================================================================

/// A proof-carrying decode artifact that explains the decode process.
///
/// This artifact is produced during decoding and captures:
/// - Configuration and inputs
/// - Key decision points (pivots, inactivation)
/// - Final outcome with explanation
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "test-internals", derive(serde::Serialize))]
pub struct DecodeProof {
    /// Schema version for forward compatibility.
    pub version: u8,
    /// Configuration used for decoding.
    pub config: DecodeConfig,
    /// Summary of received symbols.
    pub received: ReceivedSummary,
    /// Phase 1: Peeling events.
    pub peeling: PeelingTrace,
    /// Phase 2: Inactivation and elimination events.
    pub elimination: EliminationTrace,
    /// Final outcome.
    pub outcome: ProofOutcome,
}

impl DecodeProof {
    /// Create a new proof builder.
    #[must_use]
    #[inline]
    pub fn builder(config: DecodeConfig) -> DecodeProofBuilder {
        DecodeProofBuilder::new(config)
    }

    /// Compute a cryptographic SHA-256 hash for secure attestation.
    ///
    /// This hash provides integrity protection against proof forgery attacks.
    /// Unlike the previous 64-bit non-cryptographic hash, this 256-bit SHA-256
    /// hash makes it computationally infeasible for an attacker to construct
    /// a false proof that produces the same hash as a legitimate proof.
    #[must_use]
    pub fn content_hash(&self) -> ProofHash {
        let mut hasher = Sha256::new();

        // Hash schema version for forward compatibility
        hasher.update([self.version]);

        // Hash configuration (deterministic field order)
        hasher.update((self.config.k as u32).to_le_bytes());
        hasher.update((self.config.s as u32).to_le_bytes());
        hasher.update((self.config.h as u32).to_le_bytes());
        hasher.update((self.config.l as u32).to_le_bytes());
        hasher.update((self.config.symbol_size as u32).to_le_bytes());
        hasher.update(self.config.seed.to_le_bytes());
        hasher.update(self.config.object_id.as_u128().to_le_bytes());
        hasher.update(self.config.sbn.to_le_bytes());

        // Hash received symbols summary
        hasher.update((self.received.total as u32).to_le_bytes());
        hasher.update((self.received.source_count as u32).to_le_bytes());
        hasher.update((self.received.repair_count as u32).to_le_bytes());
        hasher.update(self.received.esi_multiset_hash.to_le_bytes());
        hasher.update((self.received.esis.len() as u32).to_le_bytes());
        for esi in &self.received.esis {
            hasher.update(esi.to_le_bytes());
        }
        hasher.update([u8::from(self.received.truncated)]);

        // Hash peeling trace
        hasher.update((self.peeling.solved as u32).to_le_bytes());
        hasher.update((self.peeling.solved_indices.len() as u32).to_le_bytes());
        for index in &self.peeling.solved_indices {
            hasher.update((*index as u32).to_le_bytes());
        }
        hasher.update([u8::from(self.peeling.truncated)]);

        // Hash elimination trace
        hasher.update((self.elimination.pivots as u32).to_le_bytes());
        hasher.update((self.elimination.row_ops as u32).to_le_bytes());
        hasher.update((self.elimination.inactivated as u32).to_le_bytes());
        hash_inactivation_strategy(&mut hasher, self.elimination.strategy);
        hasher.update((self.elimination.inactive_cols.len() as u32).to_le_bytes());
        for col in &self.elimination.inactive_cols {
            hasher.update((*col as u32).to_le_bytes());
        }
        hasher.update([u8::from(self.elimination.inactive_cols_truncated)]);
        hasher.update((self.elimination.pivot_events.len() as u32).to_le_bytes());
        for pivot in &self.elimination.pivot_events {
            hasher.update((pivot.col as u32).to_le_bytes());
            hasher.update((pivot.row as u32).to_le_bytes());
        }
        hasher.update([u8::from(self.elimination.pivot_events_truncated)]);
        hasher.update((self.elimination.strategy_transitions.len() as u32).to_le_bytes());
        for transition in &self.elimination.strategy_transitions {
            hash_inactivation_strategy(&mut hasher, transition.from);
            hash_inactivation_strategy(&mut hasher, transition.to);
            hasher.update((transition.reason.len() as u32).to_le_bytes());
            hasher.update(transition.reason.as_bytes());
        }
        hasher.update([u8::from(self.elimination.strategy_transitions_truncated)]);

        // Hash outcome
        match &self.outcome {
            ProofOutcome::Success {
                symbols_recovered,
                source_payload_hash,
            } => {
                hasher.update([0u8]); // Success discriminant
                hasher.update((*symbols_recovered as u32).to_le_bytes());
                hasher.update(source_payload_hash.to_le_bytes());
            }
            ProofOutcome::Failure { reason } => {
                hasher.update([1u8]); // Failure discriminant

                // Hash FailureReason deterministically by variant
                match reason {
                    FailureReason::InsufficientSymbols { received, required } => {
                        hasher.update([0u8]); // InsufficientSymbols discriminant
                        hasher.update((*received as u32).to_le_bytes());
                        hasher.update((*required as u32).to_le_bytes());
                    }
                    FailureReason::SingularMatrix {
                        row,
                        attempted_cols,
                    } => {
                        hasher.update([1u8]); // SingularMatrix discriminant
                        hasher.update((*row as u32).to_le_bytes());
                        hasher.update((attempted_cols.len() as u32).to_le_bytes());
                        for col in attempted_cols {
                            hasher.update((*col as u32).to_le_bytes());
                        }
                    }
                    FailureReason::SymbolSizeMismatch { expected, actual } => {
                        hasher.update([2u8]); // SymbolSizeMismatch discriminant
                        hasher.update((*expected as u32).to_le_bytes());
                        hasher.update((*actual as u32).to_le_bytes());
                    }
                    FailureReason::SymbolEquationArityMismatch {
                        esi,
                        columns,
                        coefficients,
                    } => {
                        hasher.update([3u8]); // SymbolEquationArityMismatch discriminant
                        hasher.update(esi.to_le_bytes());
                        hasher.update((*columns as u32).to_le_bytes());
                        hasher.update((*coefficients as u32).to_le_bytes());
                    }
                    FailureReason::ColumnIndexOutOfRange {
                        esi,
                        column,
                        max_valid,
                    } => {
                        hasher.update([4u8]); // ColumnIndexOutOfRange discriminant
                        hasher.update(esi.to_le_bytes());
                        hasher.update((*column as u32).to_le_bytes());
                        hasher.update((*max_valid as u32).to_le_bytes());
                    }
                    FailureReason::SourceEsiOutOfRange { esi, max_valid } => {
                        hasher.update([5u8]); // SourceEsiOutOfRange discriminant
                        hasher.update(esi.to_le_bytes());
                        hasher.update((*max_valid as u32).to_le_bytes());
                    }
                    FailureReason::InvalidSourceSymbolEquation {
                        esi,
                        expected_column,
                    } => {
                        hasher.update([6u8]); // InvalidSourceSymbolEquation discriminant
                        hasher.update(esi.to_le_bytes());
                        hasher.update((*expected_column as u32).to_le_bytes());
                    }
                    FailureReason::CorruptDecodedOutput {
                        esi,
                        byte_index,
                        expected,
                        actual,
                    } => {
                        hasher.update([7u8]); // CorruptDecodedOutput discriminant
                        hasher.update(esi.to_le_bytes());
                        hasher.update((*byte_index as u32).to_le_bytes());
                        hasher.update([*expected]);
                        hasher.update([*actual]);
                    }
                    FailureReason::ComputeBudgetExhausted {
                        used,
                        requested,
                        max,
                    } => {
                        hasher.update([8u8]); // ComputeBudgetExhausted discriminant
                        hasher.update(used.to_le_bytes());
                        hasher.update(requested.to_le_bytes());
                        hasher.update(max.to_le_bytes());
                    }
                    FailureReason::EsiRateLimitExceeded {
                        esi,
                        column_count,
                        max_columns,
                    } => {
                        hasher.update([9u8]); // EsiRateLimitExceeded discriminant
                        hasher.update(esi.to_le_bytes());
                        hasher.update((*column_count as u32).to_le_bytes());
                        hasher.update((*max_columns as u32).to_le_bytes());
                    }
                }
            }
        }

        let digest: [u8; 32] = hasher.finalize().into();
        ProofHash(digest)
    }

    /// Replay the decode with the provided symbols and verify the proof trace matches.
    ///
    /// Returns a detailed [`ReplayError`] if any divergence is detected.
    pub fn replay_and_verify(&self, symbols: &[ReceivedSymbol]) -> Result<(), ReplayError> {
        let decoder =
            InactivationDecoder::new(self.config.k, self.config.symbol_size, self.config.seed);
        let actual =
            match decoder.decode_with_proof(symbols, self.config.object_id, self.config.sbn) {
                Ok(result) => result.proof,
                Err((_err, proof)) => proof,
            };
        compare_proofs(self, &actual)
    }
}

// ============================================================================
// Proof artifact distribution
// ============================================================================

/// Manifest describing a proof bundle distributed through RaptorQ shards.
///
/// The manifest is intentionally small and self-authenticating. Operators can
/// exchange it out-of-band, then verify every shard and recovered artifact
/// against the manifest before accepting the proof bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "test-internals", derive(serde::Serialize))]
pub struct ProofArtifactManifest {
    /// Distribution schema version.
    pub version: u8,
    /// Object ID bound to the proof bundle.
    pub object_id: ObjectId,
    /// Source block number bound to the proof bundle.
    pub sbn: u8,
    /// Original proof-artifact byte length before symbol padding.
    pub artifact_len: usize,
    /// RaptorQ symbol size used for sharding.
    pub symbol_size: usize,
    /// Number of source symbols in the padded artifact.
    pub source_symbols: usize,
    /// Number of repair symbols emitted for redundancy.
    pub repair_symbols: usize,
    /// RFC 6330 `K'` value selected for `source_symbols`.
    pub k_prime: usize,
    /// Total intermediate-symbol count for the selected source block.
    pub l: usize,
    /// Seed used to derive deterministic repair symbols.
    pub seed: u64,
    /// SHA-256 hash of the original unpadded artifact bytes.
    pub source_payload_hash: ProofHash,
    /// SHA-256 hash of all manifest fields above.
    pub manifest_hash: ProofHash,
}

impl ProofArtifactManifest {
    /// Recomputes the manifest hash from all manifest fields except
    /// `manifest_hash`.
    #[must_use]
    pub fn recompute_hash(&self) -> ProofHash {
        hash_proof_artifact_manifest(self)
    }

    /// Returns true when `manifest_hash` still matches the manifest fields.
    #[must_use]
    pub fn hash_is_valid(&self) -> bool {
        self.manifest_hash == self.recompute_hash()
    }
}

/// One RaptorQ shard of a proof bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "test-internals", derive(serde::Serialize))]
pub struct ProofArtifactShard {
    /// Manifest hash this shard belongs to.
    pub manifest_hash: ProofHash,
    /// Encoding Symbol ID.
    pub esi: u32,
    /// Whether this shard is a systematic source symbol.
    pub is_source: bool,
    /// RaptorQ symbol payload.
    pub data: Vec<u8>,
    /// SHA-256 hash of the shard payload.
    pub data_hash: ProofHash,
    /// Deterministic authentication tag over manifest hash, ESI, kind, and data hash.
    pub auth_tag: ProofHash,
}

/// Complete encoded distribution bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "test-internals", derive(serde::Serialize))]
pub struct ProofArtifactDistribution {
    /// Self-authenticating manifest for the bundle.
    pub manifest: ProofArtifactManifest,
    /// Source and repair shards emitted in deterministic ESI order.
    pub shards: Vec<ProofArtifactShard>,
}

/// Successful proof-artifact recovery result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofArtifactRecovery {
    /// Recovered unpadded proof-artifact bytes.
    pub payload: Vec<u8>,
    /// Number of supplied shards that passed per-shard authentication.
    pub symbols_received: usize,
    /// Number of supplied shards beyond the manifest's source-symbol count.
    pub overhead_symbols: usize,
    /// True when all supplied shards matched their deterministic auth tags.
    pub authenticated: bool,
    /// Manifest hash that authenticated the recovered payload.
    pub manifest_hash: ProofHash,
}

/// Error while packaging or recovering a distributed proof artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "test-internals", derive(serde::Serialize))]
pub enum ProofArtifactDistributionError {
    /// Proof artifact bytes were empty.
    EmptyArtifact,
    /// Symbol size must be non-zero.
    InvalidSymbolSize,
    /// The artifact needs more source symbols than RFC 6330 supports.
    UnsupportedSourceBlock {
        /// Requested source-symbol count.
        requested: usize,
        /// Maximum supported source-symbol count.
        max_supported: usize,
    },
    /// RFC 6330 table data violates an invariant required for proof distribution.
    RfcTableInvariantViolation {
        /// Description of the violated invariant.
        invariant: &'static str,
        /// Problematic RFC table values or derived parameters.
        details: String,
    },
    /// The systematic encoder could not solve the source block.
    EncoderUnavailable,
    /// The manifest hash does not match the manifest fields.
    ManifestHashMismatch {
        /// Hash stored in the manifest.
        expected: ProofHash,
        /// Hash recomputed from manifest fields.
        actual: ProofHash,
    },
    /// RFC 6330 parameters in the manifest do not match the source block.
    ManifestParameterMismatch {
        /// Manifest field that did not match recomputed parameters.
        field: &'static str,
        /// Value stored in the manifest.
        expected: usize,
        /// Value recomputed from `source_symbols` and `symbol_size`.
        actual: usize,
    },
    /// A shard belongs to a different manifest.
    ManifestMismatch {
        /// Manifest hash expected by the recovery operation.
        expected: ProofHash,
        /// Manifest hash carried by the shard.
        actual: ProofHash,
    },
    /// A shard payload had the wrong symbol size.
    ShardSizeMismatch {
        /// ESI of the malformed shard.
        esi: u32,
        /// Expected symbol size from the manifest.
        expected: usize,
        /// Actual payload length.
        actual: usize,
    },
    /// A shard payload hash did not match its bytes.
    ShardPayloadHashMismatch {
        /// ESI of the corrupted shard.
        esi: u32,
    },
    /// A shard authentication tag did not match the manifest and payload hash.
    ShardAuthenticationFailed {
        /// ESI of the unauthenticated shard.
        esi: u32,
    },
    /// RaptorQ decode failed after all supplied shards were authenticated.
    DecodeFailed {
        /// Proof-compatible failure reason.
        reason: FailureReason,
    },
    /// Recovered bytes did not match the source-payload hash in the manifest.
    SourcePayloadHashMismatch {
        /// Hash stored in the manifest.
        expected: ProofHash,
        /// Hash computed from recovered bytes.
        actual: ProofHash,
    },
}

impl fmt::Display for ProofArtifactDistributionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyArtifact => f.write_str("proof artifact payload is empty"),
            Self::InvalidSymbolSize => f.write_str("proof artifact symbol size must be non-zero"),
            Self::UnsupportedSourceBlock {
                requested,
                max_supported,
            } => write!(
                f,
                "proof artifact needs {requested} source symbols; maximum supported is {max_supported}"
            ),
            Self::RfcTableInvariantViolation { invariant, details } => write!(
                f,
                "proof artifact RFC 6330 table invariant violation: {invariant}; {details}"
            ),
            Self::EncoderUnavailable => {
                f.write_str("systematic RaptorQ encoder could not solve proof artifact block")
            }
            Self::ManifestHashMismatch { expected, actual } => write!(
                f,
                "manifest hash mismatch: stored {expected}, recomputed {actual}"
            ),
            Self::ManifestParameterMismatch {
                field,
                expected,
                actual,
            } => write!(
                f,
                "manifest {field} mismatch: stored {expected}, recomputed {actual}"
            ),
            Self::ManifestMismatch { expected, actual } => {
                write!(
                    f,
                    "shard manifest mismatch: expected {expected}, got {actual}"
                )
            }
            Self::ShardSizeMismatch {
                esi,
                expected,
                actual,
            } => write!(
                f,
                "shard {esi} has {actual} bytes; expected {expected} bytes"
            ),
            Self::ShardPayloadHashMismatch { esi } => {
                write!(f, "shard {esi} payload hash mismatch")
            }
            Self::ShardAuthenticationFailed { esi } => {
                write!(f, "shard {esi} authentication tag mismatch")
            }
            Self::DecodeFailed { reason } => {
                write!(f, "proof artifact decode failed: {reason:?}")
            }
            Self::SourcePayloadHashMismatch { expected, actual } => write!(
                f,
                "recovered proof artifact hash mismatch: expected {expected}, got {actual}"
            ),
        }
    }
}

impl std::error::Error for ProofArtifactDistributionError {}

/// Package a proof artifact into authenticated RaptorQ shards for distribution.
///
/// # Errors
///
/// Returns an error if the payload is empty, `symbol_size` is zero, the source
/// block exceeds the RFC 6330 table, or the systematic encoder cannot solve
/// the source block.
pub fn package_proof_artifact_for_distribution(
    artifact: &[u8],
    symbol_size: usize,
    repair_symbols: usize,
    seed: u64,
    object_id: ObjectId,
    sbn: u8,
) -> Result<ProofArtifactDistribution, ProofArtifactDistributionError> {
    let source = proof_artifact_source_symbols(artifact, symbol_size)?;
    let source_symbols = source.len();
    let params = SystematicParams::try_for_source_block(source_symbols, symbol_size)
        .map_err(map_systematic_param_error)?;
    let source_payload_hash = hash_proof_artifact_payload(artifact);

    let mut manifest = ProofArtifactManifest {
        version: PROOF_ARTIFACT_DISTRIBUTION_SCHEMA_VERSION,
        object_id,
        sbn,
        artifact_len: artifact.len(),
        symbol_size,
        source_symbols,
        repair_symbols,
        k_prime: params.k_prime,
        l: params.l,
        seed,
        source_payload_hash,
        manifest_hash: ProofHash([0u8; 32]),
    };
    manifest.manifest_hash = manifest.recompute_hash();

    let mut encoder = SystematicEncoder::new(&source, symbol_size, seed)
        .ok_or(ProofArtifactDistributionError::EncoderUnavailable)?;
    let shards = encoder
        .emit_all(repair_symbols)
        .into_iter()
        .map(|symbol| {
            ProofArtifactShard::new(
                manifest.manifest_hash,
                symbol.esi,
                symbol.is_source,
                symbol.data,
            )
        })
        .collect();

    Ok(ProofArtifactDistribution { manifest, shards })
}

/// Recover a proof artifact from any sufficiently complete authenticated shard set.
///
/// # Errors
///
/// Returns an error if the manifest or any supplied shard fails authentication,
/// if there are not enough shards to decode, or if the recovered artifact hash
/// does not match the manifest.
pub fn recover_proof_artifact_from_shards(
    manifest: &ProofArtifactManifest,
    shards: &[ProofArtifactShard],
) -> Result<ProofArtifactRecovery, ProofArtifactDistributionError> {
    validate_manifest(manifest)?;

    let decoder =
        InactivationDecoder::new(manifest.source_symbols, manifest.symbol_size, manifest.seed);
    let mut received = decoder.constraint_symbols();

    for shard in shards {
        verify_shard(manifest, shard)?;
        if shard.is_source {
            received.push(ReceivedSymbol::source(shard.esi, shard.data.clone()));
        } else {
            let (columns, coefficients) = decoder.repair_equation(shard.esi).map_err(|_| {
                ProofArtifactDistributionError::DecodeFailed {
                    reason: FailureReason::SingularMatrix {
                        row: usize::try_from(shard.esi).unwrap_or(usize::MAX),
                        attempted_cols: Vec::new(),
                    },
                }
            })?;
            received.push(ReceivedSymbol::repair(
                shard.esi,
                columns,
                coefficients,
                shard.data.clone(),
            ));
        }
    }

    let decoded =
        decoder
            .decode(&received)
            .map_err(|err| ProofArtifactDistributionError::DecodeFailed {
                reason: FailureReason::from(&err),
            })?;
    let payload = flatten_source_payload(&decoded.source, manifest.artifact_len);
    let actual_hash = hash_proof_artifact_payload(&payload);
    if actual_hash != manifest.source_payload_hash {
        return Err(ProofArtifactDistributionError::SourcePayloadHashMismatch {
            expected: manifest.source_payload_hash,
            actual: actual_hash,
        });
    }

    Ok(ProofArtifactRecovery {
        payload,
        symbols_received: shards.len(),
        overhead_symbols: shards.len().saturating_sub(manifest.source_symbols),
        authenticated: true,
        manifest_hash: manifest.manifest_hash,
    })
}

impl ProofArtifactShard {
    fn new(manifest_hash: ProofHash, esi: u32, is_source: bool, data: Vec<u8>) -> Self {
        let data_hash = hash_proof_artifact_shard_payload(&data);
        let auth_tag = hash_proof_artifact_shard_auth(manifest_hash, esi, is_source, data_hash);
        Self {
            manifest_hash,
            esi,
            is_source,
            data,
            data_hash,
            auth_tag,
        }
    }
}

fn proof_artifact_source_symbols(
    artifact: &[u8],
    symbol_size: usize,
) -> Result<Vec<Vec<u8>>, ProofArtifactDistributionError> {
    if artifact.is_empty() {
        return Err(ProofArtifactDistributionError::EmptyArtifact);
    }
    if symbol_size == 0 {
        return Err(ProofArtifactDistributionError::InvalidSymbolSize);
    }

    let source_symbols = artifact.len().div_ceil(symbol_size);
    SystematicParams::try_for_source_block(source_symbols, symbol_size)
        .map_err(map_systematic_param_error)?;

    let mut source = Vec::with_capacity(source_symbols);
    for chunk in artifact.chunks(symbol_size) {
        let mut symbol = vec![0u8; symbol_size];
        symbol[..chunk.len()].copy_from_slice(chunk);
        source.push(symbol);
    }
    Ok(source)
}

fn validate_manifest(
    manifest: &ProofArtifactManifest,
) -> Result<(), ProofArtifactDistributionError> {
    if manifest.symbol_size == 0 {
        return Err(ProofArtifactDistributionError::InvalidSymbolSize);
    }
    let params =
        SystematicParams::try_for_source_block(manifest.source_symbols, manifest.symbol_size)
            .map_err(map_systematic_param_error)?;
    validate_manifest_parameter("k_prime", manifest.k_prime, params.k_prime)?;
    validate_manifest_parameter("l", manifest.l, params.l)?;
    let actual = manifest.recompute_hash();
    if actual != manifest.manifest_hash {
        return Err(ProofArtifactDistributionError::ManifestHashMismatch {
            expected: manifest.manifest_hash,
            actual,
        });
    }
    Ok(())
}

fn validate_manifest_parameter(
    field: &'static str,
    expected: usize,
    actual: usize,
) -> Result<(), ProofArtifactDistributionError> {
    if expected == actual {
        return Ok(());
    }
    Err(ProofArtifactDistributionError::ManifestParameterMismatch {
        field,
        expected,
        actual,
    })
}

fn verify_shard(
    manifest: &ProofArtifactManifest,
    shard: &ProofArtifactShard,
) -> Result<(), ProofArtifactDistributionError> {
    if shard.manifest_hash != manifest.manifest_hash {
        return Err(ProofArtifactDistributionError::ManifestMismatch {
            expected: manifest.manifest_hash,
            actual: shard.manifest_hash,
        });
    }
    if shard.data.len() != manifest.symbol_size {
        return Err(ProofArtifactDistributionError::ShardSizeMismatch {
            esi: shard.esi,
            expected: manifest.symbol_size,
            actual: shard.data.len(),
        });
    }
    if shard.data_hash != hash_proof_artifact_shard_payload(&shard.data) {
        return Err(ProofArtifactDistributionError::ShardPayloadHashMismatch { esi: shard.esi });
    }
    if shard.auth_tag
        != hash_proof_artifact_shard_auth(
            shard.manifest_hash,
            shard.esi,
            shard.is_source,
            shard.data_hash,
        )
    {
        return Err(ProofArtifactDistributionError::ShardAuthenticationFailed { esi: shard.esi });
    }
    Ok(())
}

fn map_systematic_param_error(err: SystematicParamError) -> ProofArtifactDistributionError {
    match err {
        SystematicParamError::UnsupportedSourceBlockSize {
            requested,
            max_supported,
        } => ProofArtifactDistributionError::UnsupportedSourceBlock {
            requested,
            max_supported,
        },
        SystematicParamError::KPrimeExceedsU32 { k_prime, max_u32 } => {
            ProofArtifactDistributionError::UnsupportedSourceBlock {
                requested: k_prime,
                max_supported: max_u32,
            }
        }
        SystematicParamError::RfcTableInvariantViolation { invariant, details } => {
            ProofArtifactDistributionError::RfcTableInvariantViolation { invariant, details }
        }
    }
}

fn flatten_source_payload(source: &[Vec<u8>], artifact_len: usize) -> Vec<u8> {
    source
        .iter()
        .flatten()
        .copied()
        .take(artifact_len)
        .collect()
}

fn hash_proof_artifact_manifest(manifest: &ProofArtifactManifest) -> ProofHash {
    let mut hasher = Sha256::new();
    hasher.update(b"RaptorQ::ProofArtifactManifest::v1");
    hasher.update([manifest.version]);
    hasher.update(manifest.object_id.as_u128().to_le_bytes());
    hasher.update([manifest.sbn]);
    hash_usize(&mut hasher, manifest.artifact_len);
    hash_usize(&mut hasher, manifest.symbol_size);
    hash_usize(&mut hasher, manifest.source_symbols);
    hash_usize(&mut hasher, manifest.repair_symbols);
    hash_usize(&mut hasher, manifest.k_prime);
    hash_usize(&mut hasher, manifest.l);
    hasher.update(manifest.seed.to_le_bytes());
    hasher.update(manifest.source_payload_hash.as_bytes());
    ProofHash(hasher.finalize().into())
}

fn hash_proof_artifact_payload(payload: &[u8]) -> ProofHash {
    let mut hasher = Sha256::new();
    hasher.update(b"RaptorQ::ProofArtifactPayload::v1");
    hash_usize(&mut hasher, payload.len());
    hasher.update(payload);
    ProofHash(hasher.finalize().into())
}

fn hash_proof_artifact_shard_payload(payload: &[u8]) -> ProofHash {
    let mut hasher = Sha256::new();
    hasher.update(b"RaptorQ::ProofArtifactShardPayload::v1");
    hash_usize(&mut hasher, payload.len());
    hasher.update(payload);
    ProofHash(hasher.finalize().into())
}

fn hash_proof_artifact_shard_auth(
    manifest_hash: ProofHash,
    esi: u32,
    is_source: bool,
    data_hash: ProofHash,
) -> ProofHash {
    let mut hasher = Sha256::new();
    hasher.update(b"RaptorQ::ProofArtifactShardAuth::v1");
    hasher.update(manifest_hash.as_bytes());
    hasher.update(esi.to_le_bytes());
    hasher.update([u8::from(is_source)]);
    hasher.update(data_hash.as_bytes());
    ProofHash(hasher.finalize().into())
}

fn hash_usize(hasher: &mut Sha256, value: usize) {
    hasher.update(u64::try_from(value).unwrap_or(u64::MAX).to_le_bytes());
}

#[inline]
fn hash_inactivation_strategy(hasher: &mut Sha256, strategy: InactivationStrategy) {
    match strategy {
        InactivationStrategy::AllAtOnce => hasher.update([0u8]),
        InactivationStrategy::HighSupportFirst => hasher.update([1u8]),
        InactivationStrategy::BlockSchurLowRank => hasher.update([2u8]),
    }
}

#[inline]
fn recovered_source_hash(source: &[Vec<u8>]) -> u64 {
    // Use SHA-256 for cryptographic integrity, then truncate to u64 for compatibility
    // with existing ProofOutcome::Success struct (which expects u64).
    // This provides cryptographic strength while maintaining wire format compatibility.
    let mut hasher = Sha256::new();

    // Add domain separator to prevent cross-protocol attacks
    hasher.update(b"RaptorQ::RecoveredSource");
    hasher.update((source.len() as u64).to_le_bytes());
    for row in source {
        hasher.update((row.len() as u64).to_le_bytes());
        hasher.update(row);
    }

    let digest: [u8; 32] = hasher.finalize().into();
    // Take first 8 bytes as little-endian u64 (collision resistance still strong)
    u64::from_le_bytes([
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
    ])
}

#[derive(Default)]
struct ReceivedEsiMultisetHashState {
    count: u64,
    sum: u64,
    sum_products: u64,
    mix: u64,
}

impl ReceivedEsiMultisetHashState {
    #[inline]
    fn observe(&mut self, esi: u32, is_source: bool) {
        use std::hash::{Hash, Hasher};

        let mut hasher = DetHasher::for_lab();
        (esi, is_source).hash(&mut hasher);
        let digest = hasher.finish();

        self.count = self.count.wrapping_add(1);
        self.sum = self.sum.wrapping_add(digest);
        self.sum_products = self
            .sum_products
            .wrapping_add(digest.wrapping_mul(digest | 1));
        self.mix = self
            .mix
            .wrapping_add(digest.rotate_left(17) ^ digest.wrapping_mul(0x9E37_79B9_7F4A_7C15));
    }

    #[inline]
    fn finish(self) -> u64 {
        use std::hash::{Hash, Hasher};

        let mut hasher = DetHasher::for_lab();
        self.count.hash(&mut hasher);
        self.sum.hash(&mut hasher);
        self.sum_products.hash(&mut hasher);
        self.mix.hash(&mut hasher);
        hasher.finish()
    }
}

// ============================================================================
// Replay verification
// ============================================================================

/// Detailed error for proof replay verification.
#[derive(Debug)]
pub enum ReplayError {
    /// Generic mismatch for scalar fields.
    Mismatch {
        /// Name of the mismatched field.
        field: &'static str,
        /// Expected value (formatted).
        expected: String,
        /// Actual value (formatted).
        actual: String,
    },
    /// Sequence mismatch at a specific index.
    SequenceMismatch {
        /// Name of the sequence being compared.
        label: &'static str,
        /// Index of the first mismatch.
        index: usize,
        /// Expected value at the mismatch (formatted).
        expected: String,
        /// Actual value at the mismatch (formatted).
        actual: String,
    },
}

impl fmt::Display for ReplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mismatch {
                field,
                expected,
                actual,
            } => write!(f, "mismatch for {field}: expected {expected}, got {actual}"),
            Self::SequenceMismatch {
                label,
                index,
                expected,
                actual,
            } => write!(
                f,
                "sequence mismatch for {label} at index {index}: expected {expected}, got {actual}"
            ),
        }
    }
}

impl std::error::Error for ReplayError {}

#[inline]
fn mismatch<T: fmt::Debug>(field: &'static str, expected: T, actual: T) -> ReplayError {
    ReplayError::Mismatch {
        field,
        expected: format!("{expected:?}"),
        actual: format!("{actual:?}"),
    }
}

#[inline]
fn sequence_mismatch(
    label: &'static str,
    index: usize,
    expected: String,
    actual: String,
) -> ReplayError {
    ReplayError::SequenceMismatch {
        label,
        index,
        expected,
        actual,
    }
}

fn compare_prefix<T: PartialEq + fmt::Debug>(
    label: &'static str,
    expected: &[T],
    actual: &[T],
    truncated: bool,
) -> Result<(), ReplayError> {
    if actual.len() != expected.len() {
        let idx = expected.len().min(actual.len());
        let (expected_item, actual_item) = if actual.len() < expected.len() {
            (
                format!("{:?}", expected.get(actual.len())),
                "missing".to_string(),
            )
        } else if truncated {
            (
                format!("len {}", expected.len()),
                format!("len {}", actual.len()),
            )
        } else {
            (
                "missing".to_string(),
                format!("{:?}", actual.get(expected.len())),
            )
        };
        return Err(sequence_mismatch(label, idx, expected_item, actual_item));
    }
    for (idx, (exp, act)) in expected.iter().zip(actual.iter()).enumerate() {
        if exp != act {
            return Err(sequence_mismatch(
                label,
                idx,
                format!("{exp:?}"),
                format!("{act:?}"),
            ));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn compare_proofs(expected: &DecodeProof, actual: &DecodeProof) -> Result<(), ReplayError> {
    if expected.version != actual.version {
        return Err(mismatch("version", expected.version, actual.version));
    }
    if expected.config != actual.config {
        return Err(mismatch("config", &expected.config, &actual.config));
    }

    let exp_recv = &expected.received;
    let act_recv = &actual.received;
    if exp_recv.total != act_recv.total {
        return Err(mismatch("received.total", exp_recv.total, act_recv.total));
    }
    if exp_recv.source_count != act_recv.source_count {
        return Err(mismatch(
            "received.source_count",
            exp_recv.source_count,
            act_recv.source_count,
        ));
    }
    if exp_recv.repair_count != act_recv.repair_count {
        return Err(mismatch(
            "received.repair_count",
            exp_recv.repair_count,
            act_recv.repair_count,
        ));
    }
    if exp_recv.esi_multiset_hash != act_recv.esi_multiset_hash {
        return Err(mismatch(
            "received.esi_multiset_hash",
            exp_recv.esi_multiset_hash,
            act_recv.esi_multiset_hash,
        ));
    }
    if exp_recv.truncated != act_recv.truncated {
        return Err(mismatch(
            "received.truncated",
            exp_recv.truncated,
            act_recv.truncated,
        ));
    }
    compare_prefix(
        "received.esis",
        &exp_recv.esis,
        &act_recv.esis,
        exp_recv.truncated,
    )?;

    let exp_peel = &expected.peeling;
    let act_peel = &actual.peeling;
    if exp_peel.solved != act_peel.solved {
        return Err(mismatch("peeling.solved", exp_peel.solved, act_peel.solved));
    }
    if exp_peel.truncated != act_peel.truncated {
        return Err(mismatch(
            "peeling.truncated",
            exp_peel.truncated,
            act_peel.truncated,
        ));
    }
    compare_prefix(
        "peeling.solved_indices",
        &exp_peel.solved_indices,
        &act_peel.solved_indices,
        exp_peel.truncated,
    )?;

    let exp_elim = &expected.elimination;
    let act_elim = &actual.elimination;
    if exp_elim.inactivated != act_elim.inactivated {
        return Err(mismatch(
            "elimination.inactivated",
            exp_elim.inactivated,
            act_elim.inactivated,
        ));
    }
    if exp_elim.pivots != act_elim.pivots {
        return Err(mismatch(
            "elimination.pivots",
            exp_elim.pivots,
            act_elim.pivots,
        ));
    }
    if exp_elim.row_ops != act_elim.row_ops {
        return Err(mismatch(
            "elimination.row_ops",
            exp_elim.row_ops,
            act_elim.row_ops,
        ));
    }
    if exp_elim.inactive_cols_truncated != act_elim.inactive_cols_truncated {
        return Err(mismatch(
            "elimination.inactive_cols_truncated",
            exp_elim.inactive_cols_truncated,
            act_elim.inactive_cols_truncated,
        ));
    }
    if exp_elim.pivot_events_truncated != act_elim.pivot_events_truncated {
        return Err(mismatch(
            "elimination.pivot_events_truncated",
            exp_elim.pivot_events_truncated,
            act_elim.pivot_events_truncated,
        ));
    }
    if exp_elim.strategy_transitions_truncated != act_elim.strategy_transitions_truncated {
        return Err(mismatch(
            "elimination.strategy_transitions_truncated",
            exp_elim.strategy_transitions_truncated,
            act_elim.strategy_transitions_truncated,
        ));
    }
    if exp_elim.strategy != act_elim.strategy {
        return Err(mismatch(
            "elimination.strategy",
            exp_elim.strategy,
            act_elim.strategy,
        ));
    }
    compare_prefix(
        "elimination.inactive_cols",
        &exp_elim.inactive_cols,
        &act_elim.inactive_cols,
        exp_elim.inactive_cols_truncated,
    )?;
    compare_prefix(
        "elimination.pivot_events",
        &exp_elim.pivot_events,
        &act_elim.pivot_events,
        exp_elim.pivot_events_truncated,
    )?;
    compare_prefix(
        "elimination.strategy_transitions",
        &exp_elim.strategy_transitions,
        &act_elim.strategy_transitions,
        exp_elim.strategy_transitions_truncated,
    )?;

    if expected.outcome != actual.outcome {
        return Err(mismatch("outcome", &expected.outcome, &actual.outcome));
    }

    Ok(())
}

/// Decode configuration captured in the proof.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
#[cfg_attr(feature = "test-internals", derive(serde::Serialize))]
pub struct DecodeConfig {
    /// Object ID being decoded.
    pub object_id: ObjectId,
    /// Source block number.
    pub sbn: u8,
    /// Number of source symbols (K).
    pub k: usize,
    /// Number of LDPC symbols (S).
    pub s: usize,
    /// Number of HDPC symbols (H).
    pub h: usize,
    /// Total intermediate symbols (L = K + S + H).
    pub l: usize,
    /// Symbol size in bytes.
    pub symbol_size: usize,
    /// Seed used for encoding.
    pub seed: u64,
}

/// Summary of received symbols.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
#[cfg_attr(feature = "test-internals", derive(serde::Serialize))]
pub struct ReceivedSummary {
    /// Total symbols received.
    pub total: usize,
    /// Number of source symbols received.
    pub source_count: usize,
    /// Number of repair symbols received.
    pub repair_count: usize,
    /// Deterministic hash of the full received ESI/source multiset.
    ///
    /// This binds replay verification to entries that fall outside the bounded
    /// preview list once `esis` is truncated.
    pub esi_multiset_hash: u64,
    /// ESIs of received symbols (sorted, truncated to MAX_RECEIVED_SYMBOLS).
    pub esis: Vec<u32>,
    /// True if ESI list was truncated.
    pub truncated: bool,
}

impl ReceivedSummary {
    /// Create from a list of (ESI, is_source) pairs.
    ///
    /// ESIs are recorded in deterministic ascending order and truncated
    /// to the smallest MAX_RECEIVED_SYMBOLS entries.
    #[must_use]
    pub fn from_received(symbols: impl Iterator<Item = (u32, bool)>) -> Self {
        let mut source_count = 0;
        let mut repair_count = 0;
        let mut total = 0usize;
        let mut esis_heap: BinaryHeap<u32> = BinaryHeap::new();
        let mut hash_state = ReceivedEsiMultisetHashState::default();

        for (esi, is_source) in symbols {
            total += 1;
            if is_source {
                source_count += 1;
            } else {
                repair_count += 1;
            }
            hash_state.observe(esi, is_source);
            if esis_heap.len() < MAX_RECEIVED_SYMBOLS {
                esis_heap.push(esi);
                continue;
            }
            if let Some(&max) = esis_heap.peek() {
                if esi < max {
                    esis_heap.pop();
                    esis_heap.push(esi);
                }
            }
        }

        let truncated = total > MAX_RECEIVED_SYMBOLS;
        let esi_multiset_hash = hash_state.finish();
        let mut esis = esis_heap.into_vec();
        esis.sort_unstable();
        Self {
            total,
            source_count,
            repair_count,
            esi_multiset_hash,
            esis,
            truncated,
        }
    }
}

/// Trace of peeling (belief propagation) phase.
#[derive(Debug, Clone, Default, Hash, PartialEq, Eq)]
#[cfg_attr(feature = "test-internals", derive(serde::Serialize))]
pub struct PeelingTrace {
    /// Number of symbols solved via peeling.
    pub solved: usize,
    /// Intermediate symbol indices solved during peeling.
    pub solved_indices: Vec<usize>,
    /// True if solved_indices was truncated.
    pub truncated: bool,
}

impl PeelingTrace {
    /// Record a solved symbol index.
    pub fn record_solved(&mut self, col: usize) {
        self.solved += 1;
        if self.solved_indices.len() < MAX_PIVOT_EVENTS {
            self.solved_indices.push(col);
        } else {
            self.truncated = true;
        }
    }
}

/// Trace of inactivation and Gaussian elimination phase.
#[derive(Debug, Clone, Default, Hash, PartialEq, Eq)]
#[cfg_attr(feature = "test-internals", derive(serde::Serialize))]
pub struct EliminationTrace {
    /// Inactivation strategy selected for this decode.
    pub strategy: InactivationStrategy,
    /// Number of columns marked as inactive.
    pub inactivated: usize,
    /// Column indices that were inactivated.
    pub inactive_cols: Vec<usize>,
    /// Number of pivot selections.
    pub pivots: usize,
    /// Pivot events: (column, pivot_row) pairs.
    pub pivot_events: Vec<PivotEvent>,
    /// True if inactive_cols was truncated.
    pub inactive_cols_truncated: bool,
    /// True if pivot_events was truncated.
    pub pivot_events_truncated: bool,
    /// Number of row operations performed.
    pub row_ops: usize,
    /// Strategy transitions recorded during decode.
    pub strategy_transitions: Vec<StrategyTransition>,
    /// True if strategy_transitions was truncated.
    pub strategy_transitions_truncated: bool,
}

impl EliminationTrace {
    /// Set the strategy used by the decoder.
    pub fn set_strategy(&mut self, strategy: InactivationStrategy) {
        self.strategy = strategy;
    }

    /// Record a strategy transition.
    pub fn record_strategy_transition(
        &mut self,
        from: InactivationStrategy,
        to: InactivationStrategy,
        reason: &'static str,
    ) {
        if from == to {
            self.strategy = to;
            return;
        }
        if self.strategy_transitions.len() < MAX_PIVOT_EVENTS {
            self.strategy_transitions
                .push(StrategyTransition { from, to, reason });
        } else {
            self.strategy_transitions_truncated = true;
        }
        self.strategy = to;
    }

    /// Record an inactivated column.
    pub fn record_inactivation(&mut self, col: usize) {
        self.inactivated += 1;
        if self.inactive_cols.len() < MAX_PIVOT_EVENTS {
            self.inactive_cols.push(col);
        } else {
            self.inactive_cols_truncated = true;
        }
    }

    /// Record a pivot selection.
    pub fn record_pivot(&mut self, col: usize, row: usize) {
        self.pivots += 1;
        if self.pivot_events.len() < MAX_PIVOT_EVENTS {
            self.pivot_events.push(PivotEvent { col, row });
        } else {
            self.pivot_events_truncated = true;
        }
    }

    /// Record a row operation.
    pub fn record_row_op(&mut self) {
        self.row_ops += 1;
    }
}

/// Inactivation strategy used by the decoder.
#[derive(Debug, Clone, Copy, Default, Hash, PartialEq, Eq)]
#[cfg_attr(feature = "test-internals", derive(serde::Serialize))]
pub enum InactivationStrategy {
    /// Legacy behavior: inactivate all remaining unsolved columns in their natural order.
    #[default]
    AllAtOnce,
    /// Hard-regime behavior: inactivate columns ordered by descending equation support.
    HighSupportFirst,
    /// Accelerated hard-regime behavior: deterministic block-Schur partitioning with
    /// conservative fallback to high-support ordering when assumptions break.
    BlockSchurLowRank,
}

/// A single strategy transition event.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
#[cfg_attr(feature = "test-internals", derive(serde::Serialize))]
pub struct StrategyTransition {
    /// Previous strategy.
    pub from: InactivationStrategy,
    /// New strategy.
    pub to: InactivationStrategy,
    /// Deterministic reason for the transition.
    pub reason: &'static str,
}

/// A single pivot selection event.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
#[cfg_attr(feature = "test-internals", derive(serde::Serialize))]
pub struct PivotEvent {
    /// Column being eliminated.
    pub col: usize,
    /// Row selected as pivot.
    pub row: usize,
}

/// Final decode outcome.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
#[cfg_attr(feature = "test-internals", derive(serde::Serialize))]
pub enum ProofOutcome {
    /// Decode succeeded.
    Success {
        /// Total source symbols recovered.
        symbols_recovered: usize,
        /// Deterministic hash of the recovered source payload.
        source_payload_hash: u64,
    },
    /// Decode failed with a specific reason.
    Failure {
        /// The error that occurred.
        reason: FailureReason,
    },
}

/// Detailed failure reason for proof artifact.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
#[cfg_attr(feature = "test-internals", derive(serde::Serialize))]
pub enum FailureReason {
    /// Not enough symbols received.
    InsufficientSymbols {
        /// Symbols received.
        received: usize,
        /// Symbols required.
        required: usize,
    },
    /// Matrix became singular during elimination.
    SingularMatrix {
        /// Row that couldn't find a pivot.
        row: usize,
        /// Columns that were attempted.
        attempted_cols: Vec<usize>,
    },
    /// Symbol size mismatch.
    SymbolSizeMismatch {
        /// Expected size.
        expected: usize,
        /// Actual size.
        actual: usize,
    },
    /// Received symbol has mismatched equation vectors.
    SymbolEquationArityMismatch {
        /// ESI of malformed symbol.
        esi: u32,
        /// Number of column indices.
        columns: usize,
        /// Number of coefficients.
        coefficients: usize,
    },
    /// Received symbol references an invalid column outside [0, L).
    ColumnIndexOutOfRange {
        /// ESI of malformed symbol.
        esi: u32,
        /// Offending column index.
        column: usize,
        /// Exclusive upper bound for valid columns.
        max_valid: usize,
    },
    /// A source symbol used an ESI outside the systematic source domain [0, K).
    SourceEsiOutOfRange {
        /// ESI of malformed source symbol.
        esi: u32,
        /// Exclusive upper bound for valid source ESIs.
        max_valid: usize,
    },
    /// A source symbol did not use the required identity equation `C[esi] = data`.
    InvalidSourceSymbolEquation {
        /// ESI of malformed source symbol.
        esi: u32,
        /// Required intermediate column for that source symbol.
        expected_column: usize,
    },
    /// Decoder produced output that failed equation verification.
    CorruptDecodedOutput {
        /// ESI of mismatched equation row.
        esi: u32,
        /// First mismatching byte index.
        byte_index: usize,
        /// Reconstructed byte from decoded intermediate symbols.
        expected: u8,
        /// Received RHS byte from input symbol.
        actual: u8,
    },
    /// Decoder compute budget was exhausted.
    ComputeBudgetExhausted {
        /// Budget consumed before this operation.
        used: u64,
        /// Additional budget requested by the operation.
        requested: u64,
        /// Maximum allowed budget.
        max: u64,
    },
    /// ESI expansion exceeded the configured per-symbol rate limit.
    EsiRateLimitExceeded {
        /// ESI that exceeded the limit.
        esi: u32,
        /// Columns that would have been generated.
        column_count: usize,
        /// Maximum allowed columns.
        max_columns: usize,
    },
}

impl From<&DecodeError> for FailureReason {
    fn from(err: &DecodeError) -> Self {
        match err {
            DecodeError::InsufficientSymbols { received, required } => Self::InsufficientSymbols {
                received: *received,
                required: *required,
            },
            DecodeError::SingularMatrix { row } => Self::SingularMatrix {
                row: *row,
                attempted_cols: Vec::new(), // Filled in by caller if available
            },
            DecodeError::SymbolSizeMismatch { expected, actual } => Self::SymbolSizeMismatch {
                expected: *expected,
                actual: *actual,
            },
            DecodeError::SymbolEquationArityMismatch {
                esi,
                columns,
                coefficients,
            } => Self::SymbolEquationArityMismatch {
                esi: *esi,
                columns: *columns,
                coefficients: *coefficients,
            },
            DecodeError::ColumnIndexOutOfRange {
                esi,
                column,
                max_valid,
            } => Self::ColumnIndexOutOfRange {
                esi: *esi,
                column: *column,
                max_valid: *max_valid,
            },
            DecodeError::SourceEsiOutOfRange { esi, max_valid } => Self::SourceEsiOutOfRange {
                esi: *esi,
                max_valid: *max_valid,
            },
            DecodeError::InvalidSourceSymbolEquation {
                esi,
                expected_column,
            } => Self::InvalidSourceSymbolEquation {
                esi: *esi,
                expected_column: *expected_column,
            },
            DecodeError::CorruptDecodedOutput {
                esi,
                byte_index,
                expected,
                actual,
            } => Self::CorruptDecodedOutput {
                esi: *esi,
                byte_index: *byte_index,
                expected: *expected,
                actual: *actual,
            },
            DecodeError::ComputeBudgetExhausted {
                used,
                requested,
                max,
            } => Self::ComputeBudgetExhausted {
                used: *used,
                requested: *requested,
                max: *max,
            },
            DecodeError::EsiRateLimitExceeded {
                esi,
                column_count,
                max_columns,
            } => Self::EsiRateLimitExceeded {
                esi: *esi,
                column_count: *column_count,
                max_columns: *max_columns,
            },
        }
    }
}

// ============================================================================
// Builder for incremental construction
// ============================================================================

/// Builder for constructing a decode proof incrementally.
#[derive(Debug)]
pub struct DecodeProofBuilder {
    config: DecodeConfig,
    received: Option<ReceivedSummary>,
    peeling: PeelingTrace,
    elimination: EliminationTrace,
    outcome: Option<ProofOutcome>,
}

impl DecodeProofBuilder {
    /// Create a new builder with the given configuration.
    #[must_use]
    pub fn new(config: DecodeConfig) -> Self {
        Self {
            config,
            received: None,
            peeling: PeelingTrace::default(),
            elimination: EliminationTrace::default(),
            outcome: None,
        }
    }

    /// Set the received symbols summary.
    pub fn set_received(&mut self, received: ReceivedSummary) {
        self.received = Some(received);
    }

    /// Get mutable access to the peeling trace.
    pub fn peeling_mut(&mut self) -> &mut PeelingTrace {
        &mut self.peeling
    }

    /// Get mutable access to the elimination trace.
    pub fn elimination_mut(&mut self) -> &mut EliminationTrace {
        &mut self.elimination
    }

    /// Mark decode as successful.
    ///
    /// br-asupersync-gvxrxv: panics if the outcome was already set. Callers
    /// must drive a builder through exactly one terminal transition (success
    /// XOR failure) — silently overwriting an earlier outcome would let an
    /// internal-ordering bug bind source_payload_hash to garbage from a
    /// failed decode and attest success for a failed run, bypassing the
    /// s2jxu0 hash-binding protection entirely.
    ///
    /// # Panics
    ///
    /// Panics if the proof outcome was already set by a prior call to
    /// `set_success` or `set_failure`.
    pub fn set_success(&mut self, recovered_source: &[Vec<u8>]) {
        assert!(
            self.outcome.is_none(),
            "ProofBuilder::set_success called after outcome already set \
             (br-asupersync-gvxrxv): existing outcome = {:?}",
            self.outcome
        );
        self.outcome = Some(ProofOutcome::Success {
            symbols_recovered: recovered_source.len(),
            source_payload_hash: recovered_source_hash(recovered_source),
        });
    }

    /// Mark decode as failed.
    ///
    /// br-asupersync-gvxrxv: panics if the outcome was already set. See
    /// [`set_success`](Self::set_success) for the rationale.
    ///
    /// # Panics
    ///
    /// Panics if the proof outcome was already set by a prior call to
    /// `set_success` or `set_failure`.
    pub fn set_failure(&mut self, reason: FailureReason) {
        assert!(
            self.outcome.is_none(),
            "ProofBuilder::set_failure called after outcome already set \
             (br-asupersync-gvxrxv): existing outcome = {:?}",
            self.outcome
        );
        self.outcome = Some(ProofOutcome::Failure { reason });
    }

    /// Build the final proof artifact.
    ///
    /// # Panics
    ///
    /// Panics if received or outcome hasn't been set.
    #[must_use]
    pub fn build(self) -> DecodeProof {
        DecodeProof {
            version: PROOF_SCHEMA_VERSION,
            config: self.config,
            received: self.received.expect("received must be set before build"),
            peeling: self.peeling,
            elimination: self.elimination,
            outcome: self.outcome.expect("outcome must be set before build"),
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[path = "proof_inline_tests.rs"]
mod tests;
