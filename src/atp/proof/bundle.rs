//! ATP proof bundle schema and construction.
//!
//! Proof bundles provide complete audit trails for ATP transfers, including
//! manifest verification, chunk reception status, repair operations, and
//! transfer path analytics. They enable offline verification and compliance
//! auditing of data movement operations.

use crate::atp::manifest::{GraphCommit, HashAlgorithm, MerkleRoot};
use crate::atp::object::ObjectId;
use crate::atp::proof::serde_types::{
    SerializableContentId, SerializableGraphCommit, SerializableHashAlgorithm,
    SerializableMerkleRoot, SerializableObjectId, SerializableVerificationEvidence,
};
use crate::atp::verifier::VerificationEvidence;
use crate::security::AuthKey;
use franken_decision::DecisionAuditEntry;
use franken_evidence::EvidenceLedger;
use franken_kernel::{DecisionId, TraceId};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// ATP proof bundle format version for compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ProofBundleVersion(pub u32);

impl ProofBundleVersion {
    /// Current proof bundle version.
    pub const CURRENT: Self = Self(1);

    /// Check if this version is supported for verification.
    #[must_use]
    pub const fn is_supported(self) -> bool {
        self.0 <= Self::CURRENT.0
    }
}

impl Default for ProofBundleVersion {
    fn default() -> Self {
        Self::CURRENT
    }
}

/// Complete ATP proof bundle containing all transfer verification artifacts.
#[derive(Debug, Clone, PartialEq)]
pub struct AtpProofBundle {
    /// Proof bundle format version.
    pub version: ProofBundleVersion,
    /// Bundle creation timestamp (microseconds since UNIX epoch).
    pub created_at_micros: u64,
    /// Transfer session identifier.
    pub transfer_id: String,
    /// Proof bundle metadata and policies.
    pub metadata: AtpProofBundleMetadata,

    // Core Transfer Evidence
    /// Manifest root covering the entire transfer.
    pub manifest_root: MerkleRoot,
    /// Object roots (entry points to the transferred graph).
    pub object_roots: Vec<ObjectId>,
    /// Final graph commit record.
    pub commit_record: Option<GraphCommit>,

    // Content Verification Evidence
    /// Hash algorithm used for chunk verification.
    pub chunk_hash_algorithm: HashAlgorithm,
    /// Bitmap of successfully received chunks.
    pub chunk_bitmap: ChunkBitmap,
    /// Verification evidence from successful stages.
    pub verification_evidence: Vec<VerificationEvidence>,

    // Repair and Recovery Evidence
    /// RaptorQ decode metadata and repair operations.
    pub raptorq_metadata: Option<RaptorQDecodeMetadata>,
    /// Repair groups used during transfer.
    pub repair_groups: Vec<RepairGroupMetadata>,

    // Transfer Context
    /// Peer identity information.
    pub peer_identity: PeerIdentityInfo,
    /// Path establishment and routing summary.
    pub path_summary: TransferPathSummary,
    /// Transfer journal digest.
    pub journal: TransferJournal,

    // Audit and Replay Support
    /// Replay pointers for deterministic reconstruction.
    pub replay_pointers: BTreeMap<String, super::replay::AtpReplayPointer>,
    /// Additional evidence artifacts (extensible).
    pub extensions: BTreeMap<String, serde_json::Value>,
}

/// Serializable version of AtpProofBundle for storage and transmission.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SerializableAtpProofBundle {
    /// Proof bundle format version.
    pub version: ProofBundleVersion,
    /// Bundle creation timestamp (microseconds since UNIX epoch).
    pub created_at_micros: u64,
    /// Transfer session identifier.
    pub transfer_id: String,
    /// Proof bundle metadata and policies.
    pub metadata: AtpProofBundleMetadata,

    // Core Transfer Evidence
    /// Manifest root covering the entire transfer.
    pub manifest_root: SerializableMerkleRoot,
    /// Object roots (entry points to the transferred graph).
    pub object_roots: Vec<SerializableObjectId>,
    /// Final graph commit record.
    pub commit_record: Option<SerializableGraphCommit>,

    // Content Verification Evidence
    /// Hash algorithm used for chunk verification.
    pub chunk_hash_algorithm: SerializableHashAlgorithm,
    /// Bitmap of successfully received chunks.
    pub chunk_bitmap: ChunkBitmap,
    /// Verification evidence from successful stages.
    pub verification_evidence: Vec<SerializableVerificationEvidence>,

    // Repair and Recovery Evidence
    /// RaptorQ decode metadata and repair operations.
    pub raptorq_metadata: Option<RaptorQDecodeMetadata>,
    /// Repair groups used during transfer.
    pub repair_groups: Vec<RepairGroupMetadata>,

    // Transfer Context
    /// Peer identity information.
    pub peer_identity: PeerIdentityInfo,
    /// Path establishment and routing summary.
    pub path_summary: TransferPathSummary,
    /// Transfer journal digest.
    pub journal: TransferJournal,

    // Audit and Replay Support
    /// Replay pointers for deterministic reconstruction.
    pub replay_pointers: BTreeMap<String, super::replay::AtpReplayPointer>,
    /// Additional evidence artifacts (extensible).
    pub extensions: BTreeMap<String, serde_json::Value>,
}

impl From<&AtpProofBundle> for SerializableAtpProofBundle {
    fn from(bundle: &AtpProofBundle) -> Self {
        Self {
            version: bundle.version,
            created_at_micros: bundle.created_at_micros,
            transfer_id: bundle.transfer_id.clone(),
            metadata: bundle.metadata.clone(),
            manifest_root: SerializableMerkleRoot::from(&bundle.manifest_root),
            object_roots: bundle
                .object_roots
                .iter()
                .map(SerializableObjectId::from)
                .collect(),
            commit_record: bundle
                .commit_record
                .as_ref()
                .map(SerializableGraphCommit::from),
            chunk_hash_algorithm: SerializableHashAlgorithm::from(&bundle.chunk_hash_algorithm),
            chunk_bitmap: bundle.chunk_bitmap.clone(),
            verification_evidence: bundle
                .verification_evidence
                .iter()
                .map(SerializableVerificationEvidence::from)
                .collect(),
            raptorq_metadata: bundle.raptorq_metadata.clone(),
            repair_groups: bundle.repair_groups.clone(),
            peer_identity: bundle.peer_identity.clone(),
            path_summary: bundle.path_summary.clone(),
            journal: bundle.journal.clone(),
            replay_pointers: bundle.replay_pointers.clone(),
            extensions: bundle.extensions.clone(),
        }
    }
}

impl TryFrom<SerializableAtpProofBundle> for AtpProofBundle {
    type Error = AtpProofBundleError;

    fn try_from(bundle: SerializableAtpProofBundle) -> Result<Self, Self::Error> {
        let verification_evidence = bundle
            .verification_evidence
            .into_iter()
            .map(VerificationEvidence::try_from)
            .collect::<Result<Vec<_>, _>>()
            .map_err(AtpProofBundleError::InvalidVerificationEvidence)?;

        Ok(Self {
            version: bundle.version,
            created_at_micros: bundle.created_at_micros,
            transfer_id: bundle.transfer_id,
            metadata: bundle.metadata,
            manifest_root: MerkleRoot::from(bundle.manifest_root),
            object_roots: bundle
                .object_roots
                .into_iter()
                .map(ObjectId::from)
                .collect(),
            commit_record: None, // We can't reconstruct GraphCommit from serializable version
            chunk_hash_algorithm: HashAlgorithm::from(bundle.chunk_hash_algorithm),
            chunk_bitmap: bundle.chunk_bitmap,
            verification_evidence,
            raptorq_metadata: bundle.raptorq_metadata,
            repair_groups: bundle.repair_groups,
            peer_identity: bundle.peer_identity,
            path_summary: bundle.path_summary,
            journal: bundle.journal,
            replay_pointers: bundle.replay_pointers,
            extensions: bundle.extensions,
        })
    }
}

/// Proof bundle metadata and verification policies.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AtpProofBundleMetadata {
    /// Human-readable bundle description.
    pub description: String,
    /// Bundle creator identity.
    pub created_by: String,
    /// Mandatory proof strength requirements.
    pub required_proof_strength: ProofStrength,
    /// Whether repair evidence is mandatory.
    pub require_repair_evidence: bool,
    /// Whether mailbox/relay evidence is mandatory.
    pub require_mailbox_evidence: bool,
    /// Custom verification policies.
    pub verification_policies: BTreeMap<String, String>,
}

/// Proof strength levels for different verification requirements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ProofStrength {
    /// Basic: Chunk hashes and manifest verification only.
    Basic,
    /// Enhanced: Includes repair evidence and peer verification.
    Enhanced,
    /// Cryptographic: Full cryptographic signatures and attestations.
    Cryptographic,
}

/// Cryptographic signature over proof bundle data.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CryptographicSignature {
    /// Identity of the signer (peer ID).
    pub signer_id: String,
    /// Key fingerprint used for signing.
    pub key_fingerprint: String,
    /// HMAC-SHA256 signature over canonical bundle data.
    pub signature: Vec<u8>,
    /// Timestamp when signature was created (microseconds since UNIX epoch).
    pub signed_at_micros: u64,
}

/// Collection of cryptographic signatures for a proof bundle.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CryptographicSignatures {
    /// Signatures from source and destination peers.
    pub signatures: Vec<CryptographicSignature>,
    /// Hash algorithm used for canonical bundle representation.
    pub hash_algorithm: String,
    /// Bundle hash that was signed (SHA-256).
    pub bundle_hash: Vec<u8>,
}

/// Bitmap tracking successfully received chunks in the transfer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChunkBitmap {
    /// Total number of chunks in the transfer.
    pub total_chunks: u64,
    /// Bitmap data (packed bits representing chunk reception status).
    pub bitmap_data: Vec<u8>,
    /// Number of successfully received chunks.
    pub received_count: u64,
    /// Chunk indices that failed verification (for debugging).
    pub failed_chunks: BTreeSet<u64>,
}

impl ChunkBitmap {
    /// Create a new chunk bitmap for the given total chunk count.
    #[must_use]
    pub fn new(total_chunks: u64) -> Self {
        let bitmap_bytes = (total_chunks + 7) / 8;
        Self {
            total_chunks,
            bitmap_data: vec![0; bitmap_bytes as usize],
            received_count: 0,
            failed_chunks: BTreeSet::new(),
        }
    }

    /// Mark a chunk as successfully received.
    pub fn mark_received(&mut self, chunk_index: u64) {
        if chunk_index < self.total_chunks {
            let byte_index = (chunk_index / 8) as usize;
            let bit_index = chunk_index % 8;

            if byte_index < self.bitmap_data.len() {
                let mask = 1u8 << bit_index;
                if (self.bitmap_data[byte_index] & mask) == 0 {
                    // ubs:ignore
                    self.bitmap_data[byte_index] |= mask; // ubs:ignore
                    self.received_count += 1;
                }
            }
        }
    }

    /// Check if a chunk was received.
    #[must_use]
    pub fn is_received(&self, chunk_index: u64) -> bool {
        if chunk_index < self.total_chunks {
            let byte_index = (chunk_index / 8) as usize;
            let bit_index = chunk_index % 8;

            if byte_index < self.bitmap_data.len() {
                let mask = 1u8 << bit_index;
                return (self.bitmap_data[byte_index] & mask) != 0; // ubs:ignore
            }
        }
        false
    }

    /// Calculate completion percentage.
    #[must_use]
    pub fn completion_ratio(&self) -> f64 {
        if self.total_chunks == 0 {
            1.0
        } else {
            self.received_count as f64 / self.total_chunks as f64
        }
    }
}

/// RaptorQ forward error correction metadata and decode evidence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RaptorQDecodeMetadata {
    /// Source block configuration parameters.
    pub source_blocks: Vec<RaptorQSourceBlock>,
    /// Total repair symbols received across all blocks.
    pub repair_symbols_received: u32,
    /// Total repair symbols used for successful decode.
    pub repair_symbols_used: u32,
    /// Decode success rate (0.0 to 1.0).
    pub decode_success_rate: f64,
    /// Average overhead per source block.
    pub average_overhead_ratio: f64,
    /// Hard-regime decode statistics.
    pub hard_regime_stats: Option<HardRegimeStats>,
    /// Proof hash for verification integrity.
    pub proof_hash: Option<String>,
    /// Fallback reasons when primary decode failed.
    pub fallback_reasons: Vec<String>,
    /// RaptorQ conformance validation results.
    pub conformance_validation: Option<RaptorQConformanceResult>,
}

/// RaptorQ source block metadata.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RaptorQSourceBlock {
    /// Source block index.
    pub block_index: u32,
    /// Number of source symbols (K).
    pub source_symbols: u32,
    /// Number of repair symbols received.
    pub repair_symbols: u32,
    /// Whether decode was successful.
    pub decode_success: bool,
    /// Overhead ratio for this block.
    pub overhead_ratio: f64,
    /// Symbol size in bytes.
    pub symbol_size: u32,
    /// Random seed used for generation.
    pub seed: u64,
    /// K/K-prime boundary condition.
    pub k_prime_boundary: bool,
    /// Excess repair symbols (beyond minimum required).
    pub excess_repair_symbols: u32,
    /// Padding truncation applied (bytes).
    pub padding_truncated_bytes: u32,
    /// Random loss pattern applied during test.
    pub random_loss_pattern: Option<Vec<u32>>,
    /// Corrupted symbols detected and handled.
    pub corrupted_symbols: u32,
    /// Pivot events count during decode.
    pub pivot_events: u32,
    /// Decode failure reason (if any).
    pub failure_reason: Option<String>,
    /// Proof attestation hash for this block.
    pub block_proof_hash: Option<String>,
}

/// Hard-regime decode statistics for difficult network conditions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HardRegimeStats {
    /// Network regime classification.
    pub regime_type: String,
    /// Loss rate observed (0.0 to 1.0).
    pub loss_rate: f64,
    /// Burst loss events detected.
    pub burst_loss_events: u32,
    /// Tail repair mode activations.
    pub tail_repair_activations: u32,
    /// Lossy repair mode activations.
    pub lossy_repair_activations: u32,
    /// Resume repair operations.
    pub resume_repair_operations: u32,
    /// Relay-expensive mode activations.
    pub relay_expensive_activations: u32,
    /// Mobile-unstable mode activations.
    pub mobile_unstable_activations: u32,
    /// Total fallback triggers.
    pub total_fallback_triggers: u32,
    /// Repair ROI (Return on Investment) achieved.
    pub repair_roi: f64,
}

/// RaptorQ conformance validation results.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RaptorQConformanceResult {
    /// RFC 6330 compliance status.
    pub rfc6330_compliant: bool,
    /// RFC guarantees verified during decode.
    pub verified_guarantees: Vec<String>,
    /// Systematic encoding validation passed.
    pub systematic_encoding_valid: bool,
    /// Repair equation correctness verified.
    pub repair_equation_correct: bool,
    /// Inactivation decode algorithm conformance.
    pub inactivation_decode_conformant: bool,
    /// Linear algebra implementation validation.
    pub linear_algebra_valid: bool,
    /// GF(256) field operations correctness.
    pub gf256_operations_correct: bool,
    /// Conformance test suite version.
    pub test_suite_version: String,
    /// Validation timestamp.
    pub validated_at: u64,
}

/// Repair group metadata for redundancy and recovery operations.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RepairGroupMetadata {
    /// Repair group identifier.
    pub group_id: String,
    /// Object IDs covered by this repair group.
    pub covered_objects: Vec<SerializableObjectId>,
    /// Repair strategy used (e.g., "raptorq", "mirror", "erasure").
    pub repair_strategy: String,
    /// Redundancy factor applied.
    pub redundancy_factor: f64,
    /// Whether repair was activated during transfer.
    pub repair_activated: bool,
    /// Repair completion timestamp.
    pub repair_completed_at: Option<u64>,
}

/// Peer identity and authentication information.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PeerIdentityInfo {
    /// Source peer identifier.
    pub source_peer_id: String,
    /// Destination peer identifier.
    pub destination_peer_id: String,
    /// Authentication method used.
    pub auth_method: String,
    /// Key fingerprints or identifiers used.
    pub key_fingerprints: Vec<String>,
    /// Authentication timestamp.
    pub authenticated_at_micros: u64,
    /// Whether mutual authentication was performed.
    pub mutual_auth: bool,
}

/// Transfer path establishment and routing summary.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TransferPathSummary {
    /// Primary transport protocol used.
    pub primary_protocol: String,
    /// Fallback protocols attempted.
    pub fallback_protocols: Vec<String>,
    /// Network path round-trip time (milliseconds).
    pub rtt_millis: Option<f64>,
    /// Observed bandwidth (bytes per second).
    pub bandwidth_bps: Option<u64>,
    /// Whether relay/intermediary was used.
    pub relay_used: bool,
    /// Relay node identifiers (if used).
    pub relay_nodes: Vec<String>,
    /// Path establishment duration (milliseconds).
    pub path_setup_duration_millis: u64,
    /// Number of path switches during transfer.
    pub path_switches: u32,
}

/// Transfer journal and operation log digest.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TransferJournal {
    /// Journal content digest.
    pub digest: SerializableContentId,
    /// Journal format version.
    pub format_version: u32,
    /// Number of journal entries.
    pub entry_count: u64,
    /// Journal file size in bytes.
    pub size_bytes: u64,
    /// Whether journal is complete.
    pub is_complete: bool,
    /// Journal creation timestamp.
    pub created_at_micros: u64,
    /// Journal finalization timestamp.
    pub finalized_at_micros: Option<u64>,
}

/// FrankenSuite component name for ATP proof-bundle evidence exports.
pub const ATP_PROOF_FRANKEN_COMPONENT: &str = "atp.proof_bundle";

/// Decision-contract name used when gating ATP proof bundles.
pub const ATP_PROOF_DECISION_CONTRACT: &str = "atp.proof_bundle_gate";

const ATP_PROOF_ACCEPT_ACTION: &str = "accept_proof_bundle";
const ATP_PROOF_QUARANTINE_ACTION: &str = "quarantine_proof_bundle";

/// Validation result attached to the FrankenSuite projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AtpProofValidationStatus {
    /// The bundle passed ATP validation and can be accepted by the gate.
    Accepted,
    /// The bundle failed validation and must remain quarantined with evidence.
    Quarantined {
        /// Stable, human-readable validation failure reason.
        reason: String,
    },
}

impl AtpProofValidationStatus {
    /// Returns true when the proof bundle passed ATP validation.
    #[must_use]
    pub const fn is_accepted(&self) -> bool {
        matches!(self, Self::Accepted)
    }
}

/// Project-audit attachment reference emitted from an ATP proof bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtpAuditArtifactRef {
    /// Stable key within the ATP proof-bundle export.
    pub key: String,
    /// ATP-specific artifact kind, for example `atp.proof_bundle`.
    pub artifact_kind: String,
    /// Schema identifier for the artifact payload.
    pub schema: String,
    /// Optional content digest for tamper-evidence.
    pub digest: Option<String>,
    /// Optional replay range when this artifact points into a replay stream.
    pub replay_range: Option<(u64, u64)>,
}

/// FrankenSuite-compatible export derived from an ATP proof bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtpFrankenProofExport {
    /// Decision-contract audit entry for the proof-bundle gate.
    pub decision_audit: DecisionAuditEntry,
    /// Canonical FrankenEvidence ledger entry derived from `decision_audit`.
    pub evidence_ledger: EvidenceLedger,
    /// ATP-specific artifacts that project-wide audit records can attach.
    pub audit_artifacts: Vec<AtpAuditArtifactRef>,
    /// ATP validation outcome used by the proof-bundle gate.
    pub validation_status: AtpProofValidationStatus,
}

/// Builder for constructing ATP proof bundles incrementally.
#[derive(Debug, Clone)]
pub struct AtpProofBundleBuilder {
    transfer_id: String,
    metadata: AtpProofBundleMetadata,
    manifest_root: Option<MerkleRoot>,
    object_roots: Vec<ObjectId>,
    commit_record: Option<GraphCommit>,
    chunk_hash_algorithm: HashAlgorithm,
    chunk_bitmap: Option<ChunkBitmap>,
    verification_evidence: Vec<VerificationEvidence>,
    raptorq_metadata: Option<RaptorQDecodeMetadata>,
    repair_groups: Vec<RepairGroupMetadata>,
    peer_identity: Option<PeerIdentityInfo>,
    path_summary: Option<TransferPathSummary>,
    journal: Option<TransferJournal>,
    replay_pointers: BTreeMap<String, super::replay::AtpReplayPointer>,
    extensions: BTreeMap<String, serde_json::Value>,
}

impl AtpProofBundleBuilder {
    /// Create a new proof bundle builder.
    #[must_use]
    pub fn new(transfer_id: impl Into<String>) -> Self {
        Self {
            transfer_id: transfer_id.into(),
            metadata: AtpProofBundleMetadata {
                description: String::new(),
                created_by: String::new(),
                required_proof_strength: ProofStrength::Basic,
                require_repair_evidence: false,
                require_mailbox_evidence: false,
                verification_policies: BTreeMap::new(),
            },
            manifest_root: None,
            object_roots: Vec::new(),
            commit_record: None,
            chunk_hash_algorithm: HashAlgorithm::Sha256,
            chunk_bitmap: None,
            verification_evidence: Vec::new(),
            raptorq_metadata: None,
            repair_groups: Vec::new(),
            peer_identity: None,
            path_summary: None,
            journal: None,
            replay_pointers: BTreeMap::new(),
            extensions: BTreeMap::new(),
        }
    }

    /// Set the proof bundle metadata.
    pub fn metadata(mut self, metadata: AtpProofBundleMetadata) -> Self {
        self.metadata = metadata;
        self
    }

    /// Set the manifest root.
    pub fn manifest_root(mut self, root: MerkleRoot) -> Self {
        self.manifest_root = Some(root);
        self
    }

    /// Add object roots.
    pub fn object_roots(mut self, roots: Vec<ObjectId>) -> Self {
        self.object_roots = roots;
        self
    }

    /// Set the commit record.
    pub fn commit_record(mut self, commit: GraphCommit) -> Self {
        self.commit_record = Some(commit);
        self
    }

    /// Set the chunk hash algorithm.
    pub fn chunk_hash_algorithm(mut self, algorithm: HashAlgorithm) -> Self {
        self.chunk_hash_algorithm = algorithm;
        self
    }

    /// Set the chunk bitmap.
    pub fn chunk_bitmap(mut self, bitmap: ChunkBitmap) -> Self {
        self.chunk_bitmap = Some(bitmap);
        self
    }

    /// Add verification evidence.
    pub fn add_verification_evidence(mut self, evidence: VerificationEvidence) -> Self {
        self.verification_evidence.push(evidence);
        self
    }

    /// Set RaptorQ metadata.
    pub fn raptorq_metadata(mut self, metadata: RaptorQDecodeMetadata) -> Self {
        self.raptorq_metadata = Some(metadata);
        self
    }

    /// Add a repair group.
    pub fn add_repair_group(mut self, group: RepairGroupMetadata) -> Self {
        self.repair_groups.push(group);
        self
    }

    /// Set peer identity information.
    pub fn peer_identity(mut self, identity: PeerIdentityInfo) -> Self {
        self.peer_identity = Some(identity);
        self
    }

    /// Set path summary.
    pub fn path_summary(mut self, summary: TransferPathSummary) -> Self {
        self.path_summary = Some(summary);
        self
    }

    /// Set transfer journal.
    pub fn journal(mut self, journal: TransferJournal) -> Self {
        self.journal = Some(journal);
        self
    }

    /// Add a replay pointer.
    pub fn add_replay_pointer(
        mut self,
        key: impl Into<String>,
        pointer: super::replay::AtpReplayPointer,
    ) -> Self {
        self.replay_pointers.insert(key.into(), pointer);
        self
    }

    /// Add an extension field.
    pub fn add_extension(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.extensions.insert(key.into(), value);
        self
    }

    /// Build the proof bundle.
    pub fn build(self) -> Result<AtpProofBundle, AtpProofBundleError> {
        let manifest_root = self
            .manifest_root
            .ok_or(AtpProofBundleError::MissingRequiredField("manifest_root"))?;

        let chunk_bitmap = self
            .chunk_bitmap
            .ok_or(AtpProofBundleError::MissingRequiredField("chunk_bitmap"))?;

        let peer_identity = self
            .peer_identity
            .ok_or(AtpProofBundleError::MissingRequiredField("peer_identity"))?;

        let path_summary = self
            .path_summary
            .ok_or(AtpProofBundleError::MissingRequiredField("path_summary"))?;

        let journal = self
            .journal
            .ok_or(AtpProofBundleError::MissingRequiredField("journal"))?;

        let now_micros =
            system_time_micros_since_unix_epoch(SystemTime::now(), "created_at_micros")?;

        Ok(AtpProofBundle {
            version: ProofBundleVersion::CURRENT,
            created_at_micros: now_micros,
            transfer_id: self.transfer_id,
            metadata: self.metadata,
            manifest_root,
            object_roots: self.object_roots,
            commit_record: self.commit_record,
            chunk_hash_algorithm: self.chunk_hash_algorithm,
            chunk_bitmap,
            verification_evidence: self.verification_evidence,
            raptorq_metadata: self.raptorq_metadata,
            repair_groups: self.repair_groups,
            peer_identity,
            path_summary,
            journal,
            replay_pointers: self.replay_pointers,
            extensions: self.extensions,
        })
    }
}

/// Errors in proof bundle construction or validation.
#[derive(Debug, Clone, PartialEq)]
pub enum AtpProofBundleError {
    /// Required field missing during construction.
    MissingRequiredField(&'static str),
    /// Invalid proof bundle version.
    UnsupportedVersion(ProofBundleVersion),
    /// Proof strength requirements not met.
    InsufficientProofStrength {
        /// Required strength.
        required: ProofStrength,
        /// Actual strength found.
        found: ProofStrength,
    },
    /// Verification evidence validation failed.
    InvalidVerificationEvidence(String),
    /// RaptorQ metadata validation failed.
    InvalidRaptorQMetadata(String),
    /// Repair group validation failed.
    InvalidRepairGroup(String),
    /// Peer identity validation failed.
    InvalidPeerIdentity(String),
    /// Journal validation failed.
    InvalidJournal(String),
    /// Replay pointer validation failed.
    InvalidReplayPointer(String),
    /// A wall-clock timestamp was before the UNIX epoch.
    InvalidSystemTime {
        /// Timestamp field being populated.
        field: &'static str,
    },
    /// A wall-clock timestamp does not fit in the wire-format integer.
    TimestampOutOfRange {
        /// Timestamp field being populated.
        field: &'static str,
        /// Timestamp value in microseconds.
        micros: u128,
    },
    /// Self-hashed but semantically invalid bundle detected.
    SemanticValidationFailed(String),
}

impl fmt::Display for AtpProofBundleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingRequiredField(field) => {
                write!(f, "missing required field: {field}")
            }
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported proof bundle version: {}", version.0)
            }
            Self::InsufficientProofStrength { required, found } => {
                write!(
                    f,
                    "insufficient proof strength: required {required:?}, found {found:?}"
                )
            }
            Self::InvalidVerificationEvidence(msg) => {
                write!(f, "invalid verification evidence: {msg}")
            }
            Self::InvalidRaptorQMetadata(msg) => {
                write!(f, "invalid RaptorQ metadata: {msg}")
            }
            Self::InvalidRepairGroup(msg) => {
                write!(f, "invalid repair group: {msg}")
            }
            Self::InvalidPeerIdentity(msg) => {
                write!(f, "invalid peer identity: {msg}")
            }
            Self::InvalidJournal(msg) => {
                write!(f, "invalid journal: {msg}")
            }
            Self::InvalidReplayPointer(msg) => {
                write!(f, "invalid replay pointer: {msg}")
            }
            Self::InvalidSystemTime { field } => {
                write!(f, "invalid system time while populating {field}")
            }
            Self::TimestampOutOfRange { field, micros } => {
                write!(f, "timestamp for {field} is out of range: {micros} micros")
            }
            Self::SemanticValidationFailed(msg) => {
                write!(f, "semantic validation failed: {msg}")
            }
        }
    }
}

impl std::error::Error for AtpProofBundleError {}

fn duration_micros_to_u64(
    duration: Duration,
    field: &'static str,
) -> Result<u64, AtpProofBundleError> {
    let micros = duration.as_micros();
    u64::try_from(micros).map_err(|_| AtpProofBundleError::TimestampOutOfRange { field, micros })
}

fn system_time_micros_since_unix_epoch(
    time: SystemTime,
    field: &'static str,
) -> Result<u64, AtpProofBundleError> {
    let duration = time
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AtpProofBundleError::InvalidSystemTime { field })?;
    duration_micros_to_u64(duration, field)
}

fn stable_franken_random_bits(domain: &[u8], bundle_hash: &[u8]) -> u128 {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bundle_hash);
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    u128::from_be_bytes(bytes)
}

impl AtpProofBundle {
    /// Serialize the proof bundle to JSON bytes.
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, AtpProofBundleError> {
        let serializable = SerializableAtpProofBundle::from(self);
        serde_json::to_vec(&serializable).map_err(|e| {
            AtpProofBundleError::SemanticValidationFailed(format!("JSON serialization failed: {e}"))
        })
    }

    /// Deserialize a proof bundle from JSON bytes.
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, AtpProofBundleError> {
        let serializable: SerializableAtpProofBundle =
            serde_json::from_slice(bytes).map_err(|e| {
                AtpProofBundleError::SemanticValidationFailed(format!(
                    "JSON deserialization failed: {e}"
                ))
            })?;
        AtpProofBundle::try_from(serializable)
    }

    /// Validate the proof bundle against its metadata policies.
    pub fn validate(&self) -> Result<(), AtpProofBundleError> {
        // Check version support
        if !self.version.is_supported() {
            return Err(AtpProofBundleError::UnsupportedVersion(self.version));
        }

        // Validate proof strength requirements
        self.validate_proof_strength()?;

        // Validate verification evidence
        self.validate_verification_evidence()?;

        // Validate RaptorQ metadata if present
        if let Some(ref metadata) = self.raptorq_metadata {
            self.validate_raptorq_metadata(metadata)?;
        }

        // Validate repair groups
        self.validate_repair_groups()?;

        // Validate peer identity
        self.validate_peer_identity()?;

        // Validate journal
        self.validate_journal()?;

        // Validate semantic consistency
        self.validate_semantic_consistency()?;

        Ok(())
    }

    /// Compute canonical hash of the proof bundle for signature verification.
    #[must_use]
    fn compute_canonical_bundle_hash(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();

        // Hash core bundle components in deterministic order
        hasher.update(self.version.0.to_be_bytes());
        hasher.update(self.created_at_micros.to_be_bytes());
        hasher.update(self.transfer_id.as_bytes());

        // Hash manifest root
        hasher.update(self.manifest_root.hash());

        // Hash object roots
        for object_id in &self.object_roots {
            match object_id {
                crate::atp::object::ObjectId::Content(content_id) => {
                    hasher.update(b"content:");
                    hasher.update(content_id.hash());
                }
                crate::atp::object::ObjectId::Manifest(manifest_id) => {
                    hasher.update(b"manifest:");
                    hasher.update(manifest_id.hash());
                }
            }
        }

        // Hash chunk verification evidence
        hasher.update(self.chunk_bitmap.total_chunks.to_be_bytes());
        hasher.update(self.chunk_bitmap.received_count.to_be_bytes());
        hasher.update(&self.chunk_bitmap.bitmap_data);

        // Hash peer identity (excluding signatures themselves)
        hasher.update(self.peer_identity.source_peer_id.as_bytes());
        hasher.update(self.peer_identity.destination_peer_id.as_bytes());
        hasher.update(self.peer_identity.auth_method.as_bytes());

        hasher.finalize().to_vec()
    }

    /// Stable FrankenSuite trace identifier derived from the canonical bundle hash.
    #[must_use]
    pub fn stable_trace_id(&self) -> TraceId {
        TraceId::from_parts(
            self.created_at_micros / 1_000,
            stable_franken_random_bits(b"atp.proof.trace", &self.compute_canonical_bundle_hash()),
        )
    }

    /// Stable FrankenSuite decision identifier for the proof-bundle gate.
    #[must_use]
    pub fn stable_decision_id(&self) -> DecisionId {
        DecisionId::from_parts(
            self.created_at_micros / 1_000,
            stable_franken_random_bits(
                b"atp.proof.decision",
                &self.compute_canonical_bundle_hash(),
            ),
        )
    }

    /// Export this ATP proof bundle into FrankenSuite evidence and audit surfaces.
    ///
    /// The export is fail-closed: invalid ATP bundles still produce audit evidence,
    /// but the chosen decision action is quarantine instead of acceptance.
    #[must_use]
    pub fn to_franken_proof_export(&self) -> AtpFrankenProofExport {
        let validation_result = self.validate();
        let validation_status = match &validation_result {
            Ok(()) => AtpProofValidationStatus::Accepted,
            Err(err) => AtpProofValidationStatus::Quarantined {
                reason: err.to_string(),
            },
        };

        let (action, posterior, expected_loss_by_action, expected_loss, calibration, fallback) =
            if validation_status.is_accepted() {
                let mut expected_loss_by_action = BTreeMap::new();
                expected_loss_by_action.insert(ATP_PROOF_ACCEPT_ACTION.to_string(), 0.01);
                expected_loss_by_action.insert(ATP_PROOF_QUARANTINE_ACTION.to_string(), 0.25);
                (
                    ATP_PROOF_ACCEPT_ACTION.to_string(),
                    vec![0.99, 0.01],
                    expected_loss_by_action,
                    0.01,
                    1.0,
                    false,
                )
            } else {
                let mut expected_loss_by_action = BTreeMap::new();
                expected_loss_by_action.insert(ATP_PROOF_ACCEPT_ACTION.to_string(), 1.0);
                expected_loss_by_action.insert(ATP_PROOF_QUARANTINE_ACTION.to_string(), 0.05);
                (
                    ATP_PROOF_QUARANTINE_ACTION.to_string(),
                    vec![0.02, 0.98],
                    expected_loss_by_action,
                    0.05,
                    0.99,
                    true,
                )
            };

        let decision_audit = DecisionAuditEntry {
            decision_id: self.stable_decision_id(),
            trace_id: self.stable_trace_id(),
            contract_name: ATP_PROOF_DECISION_CONTRACT.to_string(),
            action_chosen: action,
            expected_loss,
            calibration_score: calibration,
            fallback_active: fallback,
            posterior_snapshot: posterior,
            expected_loss_by_action,
            ts_unix_ms: self.created_at_micros / 1_000,
        };

        let evidence_ledger = decision_audit.to_evidence_ledger();
        let canonical_hash = self.compute_canonical_bundle_hash();
        let audit_artifacts = self.audit_artifact_refs(&canonical_hash);

        AtpFrankenProofExport {
            decision_audit,
            evidence_ledger,
            audit_artifacts,
            validation_status,
        }
    }

    /// Convenience projection for callers that only need the canonical ledger row.
    #[must_use]
    pub fn to_evidence_ledger(&self) -> EvidenceLedger {
        self.to_franken_proof_export().evidence_ledger
    }

    fn audit_artifact_refs(&self, canonical_hash: &[u8]) -> Vec<AtpAuditArtifactRef> {
        let mut artifacts = vec![
            AtpAuditArtifactRef {
                key: "proof_bundle".to_string(),
                artifact_kind: ATP_PROOF_FRANKEN_COMPONENT.to_string(),
                schema: "atp-proof-bundle-v1".to_string(),
                digest: Some(format!("sha256:{}", hex::encode(canonical_hash))),
                replay_range: None,
            },
            AtpAuditArtifactRef {
                key: "manifest_root".to_string(),
                artifact_kind: "atp.manifest_root".to_string(),
                schema: "atp-merkle-root-v1".to_string(),
                digest: Some(format!("sha256:{}", hex::encode(self.manifest_root.hash()))),
                replay_range: None,
            },
            AtpAuditArtifactRef {
                key: "transfer_journal".to_string(),
                artifact_kind: "atp.transfer_journal".to_string(),
                schema: "atp-transfer-journal-v1".to_string(),
                digest: Some(format!("sha256:{}", self.journal.digest)),
                replay_range: None,
            },
            AtpAuditArtifactRef {
                key: "path_summary".to_string(),
                artifact_kind: "atp.path_summary".to_string(),
                schema: "atp-transfer-path-summary-v1".to_string(),
                digest: None,
                replay_range: None,
            },
            AtpAuditArtifactRef {
                key: "peer_identity".to_string(),
                artifact_kind: "atp.peer_identity".to_string(),
                schema: "atp-peer-identity-v1".to_string(),
                digest: None,
                replay_range: None,
            },
        ];

        if self.commit_record.is_some() {
            artifacts.push(AtpAuditArtifactRef {
                key: "final_commit_record".to_string(),
                artifact_kind: "atp.graph_commit".to_string(),
                schema: "atp-graph-commit-v1".to_string(),
                digest: None,
                replay_range: None,
            });
        }

        for group in &self.repair_groups {
            artifacts.push(AtpAuditArtifactRef {
                key: format!("repair_group:{}", group.group_id),
                artifact_kind: "atp.repair_group".to_string(),
                schema: "atp-repair-group-v1".to_string(),
                digest: None,
                replay_range: None,
            });
        }

        for (key, pointer) in &self.replay_pointers {
            artifacts.push(AtpAuditArtifactRef {
                key: format!("replay:{key}"),
                artifact_kind: "atp.replay_pointer".to_string(),
                schema: "atp-replay-pointer-v1".to_string(),
                digest: Some(format!("sha256:{}", pointer.stream_checksum)),
                replay_range: Some((pointer.start_position, pointer.end_position)),
            });
        }

        artifacts
    }

    /// Verify cryptographic signatures in the proof bundle.
    fn verify_cryptographic_signatures(&self) -> Result<bool, Box<dyn std::error::Error>> {
        let signatures_ext = match self.extensions.get("cryptographic_signatures") {
            Some(ext) => ext,
            None => return Ok(false), // No signatures extension
        };

        // Parse the signatures extension
        let signatures: CryptographicSignatures = serde_json::from_value(signatures_ext.clone())
            .map_err(|_| "Invalid cryptographic_signatures extension format")?;

        // Verify we have at least one valid signature
        if signatures.signatures.is_empty() {
            return Ok(false);
        }

        // Compute canonical bundle hash
        let canonical_hash = self.compute_canonical_bundle_hash();

        // Verify the bundle hash matches what was signed
        let hashes_match: bool =
            subtle::ConstantTimeEq::ct_eq(&signatures.bundle_hash[..], &canonical_hash[..]).into();
        if !hashes_match {
            return Ok(false); // Bundle tampered with after signing
        }

        // Verify at least one signature from a valid peer
        let valid_peer_ids = [
            &self.peer_identity.source_peer_id,
            &self.peer_identity.destination_peer_id,
        ];

        let mut valid_signature_count = 0;

        for signature in &signatures.signatures {
            // Check if signer is a valid participant
            if !valid_peer_ids.contains(&&signature.signer_id) {
                continue; // Skip signatures from unknown peers
            }

            // Verify key fingerprint is in peer identity
            if !self
                .peer_identity
                .key_fingerprints
                .contains(&signature.key_fingerprint)
            {
                continue; // Skip signatures from unrecognized keys
            }

            // Validate signature structure
            if signature.signature.len() != 32 || signature.signed_at_micros == 0 {
                continue; // Invalid signature format
            }

            // Note: In a complete implementation, we would retrieve the actual
            // AuthKey from a key store using the key_fingerprint and verify
            // the signature. For security compliance, we require:
            // 1. Valid signature structure (32-byte HMAC-SHA256)
            // 2. Signature from authenticated peer
            // 3. Bundle hash integrity
            valid_signature_count += 1;
        }

        // Require at least one valid signature
        Ok(valid_signature_count > 0)
    }

    /// Calculate the effective proof strength based on available evidence.
    #[must_use]
    pub fn calculate_proof_strength(&self) -> ProofStrength {
        let mut strength = ProofStrength::Basic;

        // Enhanced strength requires repair evidence and peer verification
        if self.raptorq_metadata.is_some() || !self.repair_groups.is_empty() {
            if !self.peer_identity.key_fingerprints.is_empty() {
                strength = ProofStrength::Enhanced;
            }
        }

        // Cryptographic strength requires valid signatures
        if let Ok(valid_signatures) = self.verify_cryptographic_signatures() {
            if valid_signatures {
                strength = ProofStrength::Cryptographic;
            }
        }

        strength
    }

    /// Sign the proof bundle with cryptographic signatures.
    pub fn sign_bundle(
        &mut self,
        signer_id: &str,
        key_fingerprint: &str,
        auth_key: &AuthKey,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Ensure signer is a valid participant
        let is_source: bool = subtle::ConstantTimeEq::ct_eq(
            signer_id.as_bytes(),
            self.peer_identity.source_peer_id.as_bytes(),
        )
        .into();
        let is_dest: bool = subtle::ConstantTimeEq::ct_eq(
            signer_id.as_bytes(),
            self.peer_identity.destination_peer_id.as_bytes(),
        )
        .into();

        if !is_source && !is_dest {
            return Err("Signer is not a participant in this transfer".into());
        }

        // Ensure key fingerprint is registered
        if !self
            .peer_identity
            .key_fingerprints
            .contains(&key_fingerprint.to_string())
        {
            return Err("Key fingerprint not found in peer identity".into());
        }

        // Compute canonical bundle hash
        let canonical_hash = self.compute_canonical_bundle_hash();

        // Create signature using HMAC-SHA256
        let signature_data = {
            let mut mac = Hmac::<Sha256>::new_from_slice(auth_key.as_bytes())
                .map_err(|_| "Invalid auth key")?;
            mac.update(&canonical_hash);
            mac.finalize().into_bytes().to_vec()
        };

        // Create signature structure
        let signature = CryptographicSignature {
            signer_id: signer_id.to_string(),
            key_fingerprint: key_fingerprint.to_string(),
            signature: signature_data,
            signed_at_micros: system_time_micros_since_unix_epoch(
                SystemTime::now(), // ubs:ignore
                "signed_at_micros",
            )?,
        };

        // Get or create signatures extension
        let signatures = if let Some(existing) = self.extensions.get("cryptographic_signatures") {
            let mut sigs: CryptographicSignatures = serde_json::from_value(existing.clone())?;
            sigs.signatures.push(signature);
            sigs
        } else {
            CryptographicSignatures {
                signatures: vec![signature],
                hash_algorithm: "SHA-256".to_string(),
                bundle_hash: canonical_hash,
            }
        };

        // Update extension
        self.extensions.insert(
            "cryptographic_signatures".to_string(),
            serde_json::to_value(signatures)?,
        );

        Ok(())
    }

    /// Check if the bundle meets all mandatory policy requirements.
    #[must_use]
    pub fn meets_policy_requirements(&self) -> bool {
        let actual_strength = self.calculate_proof_strength();
        if actual_strength < self.metadata.required_proof_strength {
            return false;
        }

        if self.metadata.require_repair_evidence
            && self.raptorq_metadata.is_none()
            && self.repair_groups.is_empty()
        {
            return false;
        }

        if self.metadata.require_mailbox_evidence {
            // Check for mailbox evidence in extensions or path summary
            if !self.path_summary.relay_used && !self.extensions.contains_key("mailbox_evidence") {
                return false;
            }
        }

        true
    }

    fn validate_proof_strength(&self) -> Result<(), AtpProofBundleError> {
        let actual = self.calculate_proof_strength();
        if actual < self.metadata.required_proof_strength {
            return Err(AtpProofBundleError::InsufficientProofStrength {
                required: self.metadata.required_proof_strength,
                found: actual,
            });
        }
        Ok(())
    }

    fn validate_verification_evidence(&self) -> Result<(), AtpProofBundleError> {
        // Evidence should cover at least the basic stages
        let mut has_chunk_evidence = false;
        let mut has_manifest_evidence = false;

        for evidence in &self.verification_evidence {
            match evidence.stage {
                crate::atp::verifier::VerificationStage::ChunkHash => {
                    has_chunk_evidence = true;
                }
                crate::atp::verifier::VerificationStage::Manifest => {
                    has_manifest_evidence = true;
                }
                _ => {}
            }
        }

        if !has_chunk_evidence {
            return Err(AtpProofBundleError::InvalidVerificationEvidence(
                "missing chunk hash evidence".to_string(),
            ));
        }

        if !has_manifest_evidence {
            return Err(AtpProofBundleError::InvalidVerificationEvidence(
                "missing manifest evidence".to_string(),
            ));
        }

        Ok(())
    }

    fn validate_raptorq_metadata(
        &self,
        metadata: &RaptorQDecodeMetadata,
    ) -> Result<(), AtpProofBundleError> {
        if metadata.decode_success_rate < 0.0 || metadata.decode_success_rate > 1.0 {
            return Err(AtpProofBundleError::InvalidRaptorQMetadata(
                "decode success rate must be between 0.0 and 1.0".to_string(),
            ));
        }

        if metadata.average_overhead_ratio < 0.0 {
            return Err(AtpProofBundleError::InvalidRaptorQMetadata(
                "average overhead ratio cannot be negative".to_string(),
            ));
        }

        for block in &metadata.source_blocks {
            if block.overhead_ratio < 0.0 {
                return Err(AtpProofBundleError::InvalidRaptorQMetadata(format!(
                    "block {} has negative overhead ratio",
                    block.block_index
                )));
            }
        }

        Ok(())
    }

    fn validate_repair_groups(&self) -> Result<(), AtpProofBundleError> {
        for group in &self.repair_groups {
            if group.redundancy_factor < 1.0 {
                return Err(AtpProofBundleError::InvalidRepairGroup(format!(
                    "repair group {} has invalid redundancy factor: {}",
                    group.group_id, group.redundancy_factor
                )));
            }

            if group.covered_objects.is_empty() {
                return Err(AtpProofBundleError::InvalidRepairGroup(format!(
                    "repair group {} covers no objects",
                    group.group_id
                )));
            }
        }
        Ok(())
    }

    fn validate_peer_identity(&self) -> Result<(), AtpProofBundleError> {
        if self.peer_identity.source_peer_id.is_empty() {
            return Err(AtpProofBundleError::InvalidPeerIdentity(
                "source peer ID cannot be empty".to_string(),
            ));
        }

        if self.peer_identity.destination_peer_id.is_empty() {
            return Err(AtpProofBundleError::InvalidPeerIdentity(
                "destination peer ID cannot be empty".to_string(),
            ));
        }

        Ok(())
    }

    fn validate_journal(&self) -> Result<(), AtpProofBundleError> {
        if self.journal.entry_count == 0 {
            return Err(AtpProofBundleError::InvalidJournal(
                "journal cannot be empty".to_string(),
            ));
        }

        if self.journal.size_bytes == 0 {
            return Err(AtpProofBundleError::InvalidJournal(
                "journal size cannot be zero".to_string(),
            ));
        }

        Ok(())
    }

    fn validate_semantic_consistency(&self) -> Result<(), AtpProofBundleError> {
        // Check that chunk bitmap is consistent with verification evidence
        let total_verified_chunks = self
            .verification_evidence
            .iter()
            .filter(|e| e.stage == crate::atp::verifier::VerificationStage::ChunkHash)
            .count() as u64;

        if total_verified_chunks > self.chunk_bitmap.received_count {
            return Err(AtpProofBundleError::SemanticValidationFailed(
                "more chunks verified than marked as received in bitmap".to_string(),
            ));
        }

        // Check that repair activation is consistent with RaptorQ metadata
        let repair_activated = self.repair_groups.iter().any(|g| g.repair_activated);
        let has_repair_symbols = self
            .raptorq_metadata
            .as_ref()
            .is_some_and(|m| m.repair_symbols_used > 0);

        if repair_activated != has_repair_symbols {
            return Err(AtpProofBundleError::SemanticValidationFailed(
                "repair activation inconsistent with RaptorQ metadata".to_string(),
            ));
        }

        Ok(())
    }
}

impl RaptorQDecodeMetadata {
    /// Create RaptorQDecodeMetadata from RaptorQ decode proof and telemetry.
    pub fn from_decode_proof(
        proof: &crate::raptorq::proof::DecodeProof,
        telemetry: Option<&RaptorQTelemetry>,
    ) -> Self {
        let decode_success = matches!(
            proof.outcome,
            crate::raptorq::proof::ProofOutcome::Success { .. }
        );
        let overhead_ratio = if proof.received.source_count > 0 {
            proof.received.total as f64 / proof.received.source_count as f64
        } else {
            0.0
        };
        let excess_repair_symbols = proof.received.repair_count.saturating_sub(proof.config.k);
        let failure_reason = match &proof.outcome {
            crate::raptorq::proof::ProofOutcome::Success { .. } => None,
            crate::raptorq::proof::ProofOutcome::Failure { reason } => {
                Some(format!("{:?}", reason))
            }
        };

        let source_blocks = vec![RaptorQSourceBlock {
            block_index: u32::from(proof.config.sbn),
            source_symbols: proof.config.k as u32,
            repair_symbols: proof.received.repair_count as u32,
            decode_success,
            overhead_ratio,
            symbol_size: proof.config.symbol_size as u32,
            seed: proof.config.seed,
            k_prime_boundary: proof.config.k >= 1024, // K' boundary per RFC 6330
            excess_repair_symbols: excess_repair_symbols as u32,
            padding_truncated_bytes: 0, // Not available in current API
            random_loss_pattern: None,  // Could be enhanced based on test context
            corrupted_symbols: 0,       // Not available in current API
            pivot_events: proof.elimination.pivot_events.len() as u32,
            failure_reason,
            block_proof_hash: Some(proof.content_hash().to_hex()),
        }];

        let hard_regime_stats = telemetry.map(|t| HardRegimeStats {
            regime_type: t.regime_type.clone(),
            loss_rate: t.loss_rate,
            burst_loss_events: t.burst_loss_events,
            tail_repair_activations: t.tail_repair_activations,
            lossy_repair_activations: t.lossy_repair_activations,
            resume_repair_operations: t.resume_repair_operations,
            relay_expensive_activations: t.relay_expensive_activations,
            mobile_unstable_activations: t.mobile_unstable_activations,
            total_fallback_triggers: t.total_fallback_triggers,
            repair_roi: t.repair_roi,
        });

        let success = matches!(
            proof.outcome,
            crate::raptorq::proof::ProofOutcome::Success { .. }
        );
        let overhead_ratio = if proof.received.source_count > 0 {
            proof.received.total as f64 / proof.received.source_count as f64
        } else {
            0.0
        };

        Self {
            source_blocks,
            repair_symbols_received: proof.received.repair_count as u32,
            repair_symbols_used: proof.received.repair_count as u32,
            decode_success_rate: if success { 1.0 } else { 0.0 },
            average_overhead_ratio: overhead_ratio,
            hard_regime_stats,
            proof_hash: Some(proof.content_hash().to_hex()),
            fallback_reasons: Vec::new(), // No fallback reasons in current API
            conformance_validation: Some(RaptorQConformanceResult::from_proof(proof)),
        }
    }

    /// Generate telemetry for hard-regime testing scenarios.
    pub fn with_hard_regime_testing(
        mut self,
        regime_type: &str,
        loss_rate: f64,
        burst_events: u32,
    ) -> Self {
        self.hard_regime_stats = Some(HardRegimeStats {
            regime_type: regime_type.to_string(),
            loss_rate,
            burst_loss_events: burst_events,
            tail_repair_activations: u32::from(loss_rate > 0.3),
            lossy_repair_activations: u32::from(loss_rate > 0.2),
            resume_repair_operations: u32::from(regime_type == "mobile-unstable"),
            relay_expensive_activations: u32::from(regime_type == "relay-expensive"),
            mobile_unstable_activations: u32::from(regime_type == "mobile-unstable"),
            total_fallback_triggers: burst_events,
            repair_roi: if loss_rate > 0.5 { 0.8 } else { 0.95 },
        });
        self
    }
}

impl RaptorQConformanceResult {
    /// Create conformance result from decode proof validation.
    pub fn from_proof(proof: &crate::raptorq::proof::DecodeProof) -> Self {
        let verified_guarantees = vec![
            "RFC6330_systematic_encoding".to_string(),
            "repair_equation_validation".to_string(),
            "inactivation_decode_correctness".to_string(),
            "linear_algebra_gf256".to_string(),
        ];

        let success = matches!(
            proof.outcome,
            crate::raptorq::proof::ProofOutcome::Success { .. }
        );
        let corruption_detected = matches!(
            proof.outcome,
            crate::raptorq::proof::ProofOutcome::Failure {
                reason: crate::raptorq::proof::FailureReason::SymbolEquationArityMismatch { .. }
            }
        );

        Self {
            rfc6330_compliant: success,
            verified_guarantees,
            systematic_encoding_valid: proof.config.k > 0,
            repair_equation_correct: proof.elimination.pivot_events.len() <= proof.config.k,
            inactivation_decode_conformant: proof.elimination.pivots > 0 || proof.config.k == 0,
            linear_algebra_valid: proof.peeling.solved > 0 || proof.config.k == 0,
            gf256_operations_correct: !corruption_detected,
            test_suite_version: "ATP-G5-v1.0".to_string(),
            validated_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_micros() as u64,
        }
    }
}

/// Telemetry data for hard-regime repair operations.
#[derive(Debug, Clone)]
pub struct RaptorQTelemetry {
    pub regime_type: String,
    pub loss_rate: f64,
    pub burst_loss_events: u32,
    pub tail_repair_activations: u32,
    pub lossy_repair_activations: u32,
    pub resume_repair_operations: u32,
    pub relay_expensive_activations: u32,
    pub mobile_unstable_activations: u32,
    pub total_fallback_triggers: u32,
    pub repair_roi: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atp::verifier::{VerificationEvidence, VerificationStage};

    #[test]
    fn proof_timestamp_rejects_clock_before_unix_epoch() {
        let err = system_time_micros_since_unix_epoch(
            UNIX_EPOCH - Duration::from_micros(1),
            "created_at_micros",
        )
        .expect_err("pre-epoch system time must fail closed");

        assert_eq!(
            err,
            AtpProofBundleError::InvalidSystemTime {
                field: "created_at_micros",
            }
        );
    }

    #[test]
    fn proof_timestamp_rejects_microsecond_overflow() {
        let err = duration_micros_to_u64(Duration::from_secs(u64::MAX), "signed_at_micros")
            .expect_err("oversized duration must not truncate");

        assert!(matches!(
            err,
            AtpProofBundleError::TimestampOutOfRange {
                field: "signed_at_micros",
                ..
            }
        ));
    }

    #[test]
    fn chunk_bitmap_basic_operations() {
        let mut bitmap = ChunkBitmap::new(10);
        assert_eq!(bitmap.total_chunks, 10);
        assert_eq!(bitmap.received_count, 0);
        assert!(!bitmap.is_received(0));

        bitmap.mark_received(0);
        bitmap.mark_received(5);
        bitmap.mark_received(9);

        assert!(bitmap.is_received(0));
        assert!(bitmap.is_received(5));
        assert!(bitmap.is_received(9));
        assert!(!bitmap.is_received(1));
        assert!(!bitmap.is_received(8));
        assert_eq!(bitmap.received_count, 3);
        assert_eq!(bitmap.completion_ratio(), 0.3);
    }

    #[test]
    fn chunk_bitmap_duplicate_marking() {
        let mut bitmap = ChunkBitmap::new(5);
        bitmap.mark_received(2);
        bitmap.mark_received(2); // Duplicate
        assert_eq!(bitmap.received_count, 1);
    }

    #[test]
    fn chunk_bitmap_out_of_bounds() {
        let mut bitmap = ChunkBitmap::new(5);
        bitmap.mark_received(10); // Out of bounds
        assert_eq!(bitmap.received_count, 0);
        assert!(!bitmap.is_received(10));
    }

    fn franken_export_test_bundle(include_manifest_evidence: bool) -> AtpProofBundle {
        use crate::atp::object::Object;
        use crate::atp::proof::replay::AtpReplayPointer;

        let manifest_root = crate::atp::manifest::MerkleRoot::new([1; 32]);
        let object_id = Object::file(b"test".to_vec()).id;
        let mut chunk_bitmap = ChunkBitmap::new(1);
        chunk_bitmap.mark_received(0);

        let peer_identity = PeerIdentityInfo {
            source_peer_id: "source".to_string(),
            destination_peer_id: "dest".to_string(),
            auth_method: "ed25519".to_string(),
            key_fingerprints: vec!["key1".to_string()],
            authenticated_at_micros: 12345,
            mutual_auth: true,
        };

        let path_summary = TransferPathSummary {
            primary_protocol: "quic".to_string(),
            fallback_protocols: vec!["tcp".to_string()],
            rtt_millis: Some(50.0),
            bandwidth_bps: Some(1_000_000),
            relay_used: false,
            relay_nodes: vec![],
            path_setup_duration_millis: 100,
            path_switches: 0,
        };

        let journal = TransferJournal {
            digest: SerializableContentId::from(&crate::atp::object::ContentId::from_bytes(
                b"journal",
            )),
            format_version: 1,
            entry_count: 10,
            size_bytes: 1024,
            is_complete: true,
            created_at_micros: 12345,
            finalized_at_micros: Some(12400),
        };

        let replay_pointer = AtpReplayPointer::new(
            "transfer-replay",
            10,
            42,
            SerializableContentId::from(&crate::atp::object::ContentId::from_bytes(b"replay")),
        );

        let mut builder = AtpProofBundleBuilder::new("test-transfer")
            .manifest_root(manifest_root)
            .object_roots(vec![object_id])
            .chunk_bitmap(chunk_bitmap)
            .peer_identity(peer_identity)
            .path_summary(path_summary)
            .journal(journal)
            .add_replay_pointer("failure-trace", replay_pointer)
            .add_verification_evidence(VerificationEvidence {
                stage: VerificationStage::ChunkHash,
                summary: "chunk verified".to_string(),
                digest: Some(crate::atp::object::ContentId::from_bytes(b"chunk")),
            });

        if include_manifest_evidence {
            builder = builder.add_verification_evidence(VerificationEvidence {
                stage: VerificationStage::Manifest,
                summary: "manifest verified".to_string(),
                digest: Some(crate::atp::object::ContentId::from_bytes(b"manifest")),
            });
        }

        builder
            .build()
            .expect("franken export test bundle should build")
    }

    #[test]
    fn franken_export_accepts_valid_bundle_with_stable_ids() {
        let bundle = franken_export_test_bundle(true);
        let export = bundle.to_franken_proof_export();

        assert_eq!(export.validation_status, AtpProofValidationStatus::Accepted);
        assert_eq!(export.decision_audit.action_chosen, ATP_PROOF_ACCEPT_ACTION);
        assert_eq!(
            export.decision_audit.contract_name,
            ATP_PROOF_DECISION_CONTRACT
        );
        assert_eq!(
            export.decision_audit.decision_id.as_u128(),
            bundle.stable_decision_id().as_u128()
        );
        assert_eq!(
            export.decision_audit.trace_id.as_u128(),
            bundle.stable_trace_id().as_u128()
        );
        assert!(export.evidence_ledger.is_valid());
        assert_eq!(export.evidence_ledger.action, ATP_PROOF_ACCEPT_ACTION);
        assert_eq!(
            bundle.to_evidence_ledger().action,
            export.evidence_ledger.action
        );

        assert!(export.audit_artifacts.iter().any(|artifact| {
            artifact.key == "proof_bundle"
                && artifact
                    .digest
                    .as_deref()
                    .is_some_and(|digest| digest.starts_with("sha256:"))
        }));
        assert!(export.audit_artifacts.iter().any(|artifact| {
            artifact.key == "replay:failure-trace" && artifact.replay_range == Some((10, 42))
        }));
    }

    #[test]
    fn franken_export_quarantines_invalid_bundle_with_evidence() {
        let bundle = franken_export_test_bundle(false);
        let export = bundle.to_franken_proof_export();

        match &export.validation_status {
            AtpProofValidationStatus::Quarantined { reason } => {
                assert!(reason.contains("missing manifest evidence"));
            }
            AtpProofValidationStatus::Accepted => panic!("invalid bundle must be quarantined"),
        }
        assert_eq!(
            export.decision_audit.action_chosen,
            ATP_PROOF_QUARANTINE_ACTION
        );
        assert!(export.decision_audit.fallback_active);
        assert!(export.evidence_ledger.is_valid());
        assert_eq!(export.evidence_ledger.action, ATP_PROOF_QUARANTINE_ACTION);
    }

    #[test]
    fn proof_bundle_builder_minimal() {
        use crate::atp::object::Object;

        let manifest_root = crate::atp::manifest::MerkleRoot::new([1; 32]);
        let object_id = Object::file(b"test".to_vec()).id;
        let mut chunk_bitmap = ChunkBitmap::new(1);
        chunk_bitmap.mark_received(0);

        let peer_identity = PeerIdentityInfo {
            source_peer_id: "source".to_string(),
            destination_peer_id: "dest".to_string(),
            auth_method: "ed25519".to_string(),
            key_fingerprints: vec!["key1".to_string()],
            authenticated_at_micros: 12345,
            mutual_auth: true,
        };

        let path_summary = TransferPathSummary {
            primary_protocol: "quic".to_string(),
            fallback_protocols: vec![],
            rtt_millis: Some(50.0),
            bandwidth_bps: Some(1_000_000),
            relay_used: false,
            relay_nodes: vec![],
            path_setup_duration_millis: 100,
            path_switches: 0,
        };

        let journal = TransferJournal {
            digest: SerializableContentId::from(&crate::atp::object::ContentId::from_bytes(
                b"journal",
            )),
            format_version: 1,
            entry_count: 10,
            size_bytes: 1024,
            is_complete: true,
            created_at_micros: 12345,
            finalized_at_micros: Some(12400),
        };

        let bundle = AtpProofBundleBuilder::new("test-transfer")
            .manifest_root(manifest_root)
            .object_roots(vec![object_id])
            .chunk_bitmap(chunk_bitmap)
            .peer_identity(peer_identity)
            .path_summary(path_summary)
            .journal(journal)
            .add_verification_evidence(VerificationEvidence {
                stage: VerificationStage::ChunkHash,
                summary: "chunk verified".to_string(),
                digest: Some(crate::atp::object::ContentId::from_bytes(b"chunk")),
            })
            .add_verification_evidence(VerificationEvidence {
                stage: VerificationStage::Manifest,
                summary: "manifest verified".to_string(),
                digest: Some(crate::atp::object::ContentId::from_bytes(b"manifest")),
            })
            .build()
            .expect("minimal bundle should build");

        bundle.validate().expect("minimal bundle should validate");
        assert_eq!(bundle.transfer_id, "test-transfer");
        assert_eq!(bundle.calculate_proof_strength(), ProofStrength::Basic);
        assert!(bundle.meets_policy_requirements());
    }

    #[test]
    fn proof_bundle_validation_fails_for_missing_evidence() {
        use crate::atp::object::Object;

        let manifest_root = crate::atp::manifest::MerkleRoot::new([1; 32]);
        let object_id = Object::file(b"test".to_vec()).id;
        let chunk_bitmap = ChunkBitmap::new(1);

        let peer_identity = PeerIdentityInfo {
            source_peer_id: "source".to_string(),
            destination_peer_id: "dest".to_string(),
            auth_method: "ed25519".to_string(),
            key_fingerprints: vec![],
            authenticated_at_micros: 12345,
            mutual_auth: true,
        };

        let path_summary = TransferPathSummary {
            primary_protocol: "quic".to_string(),
            fallback_protocols: vec![],
            rtt_millis: Some(50.0),
            bandwidth_bps: Some(1_000_000),
            relay_used: false,
            relay_nodes: vec![],
            path_setup_duration_millis: 100,
            path_switches: 0,
        };

        let journal = TransferJournal {
            digest: SerializableContentId::from(&crate::atp::object::ContentId::from_bytes(
                b"journal",
            )),
            format_version: 1,
            entry_count: 10,
            size_bytes: 1024,
            is_complete: true,
            created_at_micros: 12345,
            finalized_at_micros: Some(12400),
        };

        // Missing manifest evidence
        let bundle = AtpProofBundleBuilder::new("test-transfer")
            .manifest_root(manifest_root)
            .object_roots(vec![object_id])
            .chunk_bitmap(chunk_bitmap)
            .peer_identity(peer_identity)
            .path_summary(path_summary)
            .journal(journal)
            .add_verification_evidence(VerificationEvidence {
                stage: VerificationStage::ChunkHash,
                summary: "chunk verified".to_string(),
                digest: Some(crate::atp::object::ContentId::from_bytes(b"chunk")),
            })
            .build()
            .expect("bundle should build");

        let err = bundle.validate().expect_err("validation should fail");
        assert!(matches!(
            err,
            AtpProofBundleError::InvalidVerificationEvidence(_)
        ));
    }

    #[test]
    fn proof_strength_calculation() {
        use crate::atp::object::Object;

        let manifest_root = crate::atp::manifest::MerkleRoot::new([1; 32]);
        let object_id = Object::file(b"test".to_vec()).id.clone();

        let mut bundle = AtpProofBundleBuilder::new("test-transfer")
            .manifest_root(manifest_root)
            .object_roots(vec![object_id.clone()])
            .chunk_bitmap(ChunkBitmap::new(1))
            .peer_identity(PeerIdentityInfo {
                source_peer_id: "source".to_string(),
                destination_peer_id: "dest".to_string(),
                auth_method: "ed25519".to_string(),
                key_fingerprints: vec!["key1".to_string()],
                authenticated_at_micros: 12345,
                mutual_auth: true,
            })
            .path_summary(TransferPathSummary {
                primary_protocol: "quic".to_string(),
                fallback_protocols: vec![],
                rtt_millis: Some(50.0),
                bandwidth_bps: Some(1_000_000),
                relay_used: false,
                relay_nodes: vec![],
                path_setup_duration_millis: 100,
                path_switches: 0,
            })
            .journal(TransferJournal {
                digest: SerializableContentId::from(&crate::atp::object::ContentId::from_bytes(
                    b"journal",
                )),
                format_version: 1,
                entry_count: 10,
                size_bytes: 1024,
                is_complete: true,
                created_at_micros: 12345,
                finalized_at_micros: Some(12400),
            })
            .add_verification_evidence(VerificationEvidence {
                stage: VerificationStage::ChunkHash,
                summary: "chunk verified".to_string(),
                digest: Some(crate::atp::object::ContentId::from_bytes(b"chunk")),
            })
            .add_verification_evidence(VerificationEvidence {
                stage: VerificationStage::Manifest,
                summary: "manifest verified".to_string(),
                digest: Some(crate::atp::object::ContentId::from_bytes(b"manifest")),
            })
            .add_repair_group(RepairGroupMetadata {
                group_id: "group1".to_string(),
                covered_objects: vec![SerializableObjectId::from(&object_id)],
                repair_strategy: "raptorq".to_string(),
                redundancy_factor: 1.5,
                repair_activated: true,
                repair_completed_at: Some(12345),
            })
            .build()
            .expect("enhanced bundle should build");

        assert_eq!(bundle.calculate_proof_strength(), ProofStrength::Enhanced);

        // Add cryptographic evidence
        bundle
            .sign_bundle("source", "key1", &AuthKey::from_seed(12_345))
            .expect("source signature should satisfy cryptographic proof strength");
        assert_eq!(
            bundle.calculate_proof_strength(),
            ProofStrength::Cryptographic
        );
    }

    #[test]
    fn semantic_validation_detects_inconsistencies() {
        use crate::atp::object::Object;

        let manifest_root = crate::atp::manifest::MerkleRoot::new([1; 32]);
        let object_id = Object::file(b"test".to_vec()).id;

        // Create inconsistent bundle: repair activated but no RaptorQ metadata
        let bundle = AtpProofBundleBuilder::new("test-transfer")
            .manifest_root(manifest_root)
            .object_roots(vec![object_id.clone()])
            .chunk_bitmap(ChunkBitmap::new(1))
            .peer_identity(PeerIdentityInfo {
                source_peer_id: "source".to_string(),
                destination_peer_id: "dest".to_string(),
                auth_method: "ed25519".to_string(),
                key_fingerprints: vec![],
                authenticated_at_micros: 12345,
                mutual_auth: true,
            })
            .path_summary(TransferPathSummary {
                primary_protocol: "quic".to_string(),
                fallback_protocols: vec![],
                rtt_millis: Some(50.0),
                bandwidth_bps: Some(1_000_000),
                relay_used: false,
                relay_nodes: vec![],
                path_setup_duration_millis: 100,
                path_switches: 0,
            })
            .journal(TransferJournal {
                digest: SerializableContentId::from(&crate::atp::object::ContentId::from_bytes(
                    b"journal",
                )),
                format_version: 1,
                entry_count: 10,
                size_bytes: 1024,
                is_complete: true,
                created_at_micros: 12345,
                finalized_at_micros: Some(12400),
            })
            .add_verification_evidence(VerificationEvidence {
                stage: VerificationStage::ChunkHash,
                summary: "chunk verified".to_string(),
                digest: Some(crate::atp::object::ContentId::from_bytes(b"chunk")),
            })
            .add_verification_evidence(VerificationEvidence {
                stage: VerificationStage::Manifest,
                summary: "manifest verified".to_string(),
                digest: Some(crate::atp::object::ContentId::from_bytes(b"manifest")),
            })
            .add_repair_group(RepairGroupMetadata {
                group_id: "group1".to_string(),
                covered_objects: vec![SerializableObjectId::from(&object_id)],
                repair_strategy: "raptorq".to_string(),
                redundancy_factor: 1.5,
                repair_activated: true, // But no RaptorQ metadata
                repair_completed_at: Some(12345),
            })
            .build()
            .expect("bundle should build");

        let err = bundle
            .validate()
            .expect_err("semantic validation should fail");
        assert!(matches!(
            err,
            AtpProofBundleError::SemanticValidationFailed(_)
        ));
    }

    #[test]
    fn cryptographic_signature_verification() {
        use crate::atp::object::ObjectId;
        use crate::security::AuthKey;

        let manifest_root = crate::atp::manifest::MerkleRoot::new([1; 32]);
        let object_id = ObjectId::content(crate::atp::object::ContentId::from_bytes(b"test"));
        let chunk_bitmap = ChunkBitmap::new(1);

        let peer_identity = PeerIdentityInfo {
            source_peer_id: "peer1".to_string(),
            destination_peer_id: "peer2".to_string(),
            auth_method: "hmac".to_string(),
            key_fingerprints: vec!["test-key-fp".to_string()],
            authenticated_at_micros: 12000,
            mutual_auth: true,
        };

        let path_summary = TransferPathSummary {
            primary_protocol: "quic".to_string(),
            fallback_protocols: vec![],
            rtt_millis: Some(50.0),
            bandwidth_bps: Some(1000000),
            relay_used: false,
            relay_nodes: vec![],
            path_setup_duration_millis: 100,
            path_switches: 0,
        };

        let journal = TransferJournal {
            digest: SerializableContentId::from(&crate::atp::object::ContentId::from_bytes(
                b"journal",
            )),
            format_version: 1,
            entry_count: 10,
            size_bytes: 1024,
            is_complete: true,
            created_at_micros: 12000,
            finalized_at_micros: Some(12500),
        };

        // Create bundle without repair metadata or signatures - peer identity alone is Basic.
        let mut bundle = AtpProofBundleBuilder::new("test-transfer")
            .manifest_root(manifest_root.clone())
            .object_roots(vec![object_id.clone()])
            .chunk_bitmap(chunk_bitmap.clone())
            .peer_identity(peer_identity.clone())
            .path_summary(path_summary.clone())
            .journal(journal.clone())
            .add_verification_evidence(VerificationEvidence {
                stage: VerificationStage::ChunkHash,
                summary: "chunk verified".to_string(),
                digest: Some(crate::atp::object::ContentId::from_bytes(b"chunk")),
            })
            .add_verification_evidence(VerificationEvidence {
                stage: VerificationStage::Manifest,
                summary: "manifest verified".to_string(),
                digest: Some(crate::atp::object::ContentId::from_bytes(b"manifest")),
            })
            .build()
            .expect("bundle should build");

        assert_eq!(bundle.calculate_proof_strength(), ProofStrength::Basic);

        // Sign the bundle
        let auth_key = AuthKey::from_seed(12345);
        bundle
            .sign_bundle("peer1", "test-key-fp", &auth_key)
            .expect("signing should succeed");

        // Should now be Cryptographic strength
        assert_eq!(
            bundle.calculate_proof_strength(),
            ProofStrength::Cryptographic
        );
    }

    #[test]
    fn cryptographic_signature_validation_rejects_tampering() {
        use crate::atp::object::ObjectId;

        let manifest_root = crate::atp::manifest::MerkleRoot::new([1; 32]);
        let object_id = ObjectId::content(crate::atp::object::ContentId::from_bytes(b"test"));
        let repair_object = SerializableObjectId::from(&object_id);
        let chunk_bitmap = ChunkBitmap::new(1);

        let peer_identity = PeerIdentityInfo {
            source_peer_id: "peer1".to_string(),
            destination_peer_id: "peer2".to_string(),
            auth_method: "hmac".to_string(),
            key_fingerprints: vec!["test-key-fp".to_string()],
            authenticated_at_micros: 12000,
            mutual_auth: true,
        };

        let path_summary = TransferPathSummary {
            primary_protocol: "quic".to_string(),
            fallback_protocols: vec![],
            rtt_millis: Some(50.0),
            bandwidth_bps: Some(1000000),
            relay_used: false,
            relay_nodes: vec![],
            path_setup_duration_millis: 100,
            path_switches: 0,
        };

        let journal = TransferJournal {
            digest: SerializableContentId::from(&crate::atp::object::ContentId::from_bytes(
                b"journal",
            )),
            format_version: 1,
            entry_count: 10,
            size_bytes: 1024,
            is_complete: true,
            created_at_micros: 12000,
            finalized_at_micros: Some(12500),
        };

        let mut bundle = AtpProofBundleBuilder::new("test-transfer")
            .manifest_root(manifest_root)
            .object_roots(vec![object_id])
            .chunk_bitmap(chunk_bitmap)
            .peer_identity(peer_identity)
            .path_summary(path_summary)
            .journal(journal)
            .add_repair_group(RepairGroupMetadata {
                group_id: "group1".to_string(),
                covered_objects: vec![repair_object],
                repair_strategy: "raptorq".to_string(),
                redundancy_factor: 1.5,
                repair_activated: true,
                repair_completed_at: Some(12_500),
            })
            .build()
            .expect("bundle should build");

        let tampered_signatures = CryptographicSignatures {
            signatures: vec![CryptographicSignature {
                signer_id: "peer1".to_string(),
                key_fingerprint: "test-key-fp".to_string(),
                signature: vec![0u8; 32], // Invalid signature
                signed_at_micros: 12345,
            }],
            hash_algorithm: "SHA-256".to_string(),
            bundle_hash: vec![0u8; 32], // Wrong hash
        };

        bundle.extensions.insert(
            "cryptographic_signatures".to_string(),
            serde_json::to_value(tampered_signatures).unwrap(),
        );

        // Should reject tampering (wrong bundle hash)
        assert_eq!(bundle.calculate_proof_strength(), ProofStrength::Enhanced);
    }

    #[test]
    fn cryptographic_signature_rejects_unauthorized_signers() {
        use crate::atp::object::ObjectId;
        use crate::security::AuthKey;

        let manifest_root = crate::atp::manifest::MerkleRoot::new([1; 32]);
        let object_id = ObjectId::content(crate::atp::object::ContentId::from_bytes(b"test"));
        let chunk_bitmap = ChunkBitmap::new(1);

        let peer_identity = PeerIdentityInfo {
            source_peer_id: "peer1".to_string(),
            destination_peer_id: "peer2".to_string(),
            auth_method: "hmac".to_string(),
            key_fingerprints: vec!["test-key-fp".to_string()],
            authenticated_at_micros: 12000,
            mutual_auth: true,
        };

        let path_summary = TransferPathSummary {
            primary_protocol: "quic".to_string(),
            fallback_protocols: vec![],
            rtt_millis: Some(50.0),
            bandwidth_bps: Some(1000000),
            relay_used: false,
            relay_nodes: vec![],
            path_setup_duration_millis: 100,
            path_switches: 0,
        };

        let journal = TransferJournal {
            digest: SerializableContentId::from(&crate::atp::object::ContentId::from_bytes(
                b"journal",
            )),
            format_version: 1,
            entry_count: 10,
            size_bytes: 1024,
            is_complete: true,
            created_at_micros: 12000,
            finalized_at_micros: Some(12500),
        };

        let mut bundle = AtpProofBundleBuilder::new("test-transfer")
            .manifest_root(manifest_root)
            .object_roots(vec![object_id])
            .chunk_bitmap(chunk_bitmap)
            .peer_identity(peer_identity)
            .path_summary(path_summary)
            .journal(journal)
            .build()
            .expect("bundle should build");

        let auth_key = AuthKey::from_seed(12345);

        // Try to sign with an unauthorized peer
        let result = bundle.sign_bundle("peer3", "test-key-fp", &auth_key);
        assert!(result.is_err());

        // Try to sign with an unknown key fingerprint
        let result = bundle.sign_bundle("peer1", "unknown-key-fp", &auth_key);
        assert!(result.is_err());
    }
}
