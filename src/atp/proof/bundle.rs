//! ATP proof bundle schema and construction.
//!
//! Proof bundles provide complete audit trails for ATP transfers, including
//! manifest verification, chunk reception status, repair operations, and
//! transfer path analytics. They enable offline verification and compliance
//! auditing of data movement operations.

use crate::atp::manifest::{GraphCommit, HashAlgorithm, MerkleRoot};
use crate::atp::object::{ContentId, ObjectId};
use crate::atp::proof::serde_types::{
    SerializableContentId, SerializableGraphCommit, SerializableHashAlgorithm,
    SerializableMerkleRoot, SerializableObjectId, SerializableVerificationEvidence,
};
use crate::atp::verifier::VerificationEvidence;
use serde::{Deserialize, Serialize};
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
            object_roots: bundle.object_roots.iter().map(SerializableObjectId::from).collect(),
            commit_record: bundle.commit_record.as_ref().map(SerializableGraphCommit::from),
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
            .map_err(|e| AtpProofBundleError::InvalidVerificationEvidence(e))?;

        Ok(Self {
            version: bundle.version,
            created_at_micros: bundle.created_at_micros,
            transfer_id: bundle.transfer_id,
            metadata: bundle.metadata,
            manifest_root: MerkleRoot::from(bundle.manifest_root),
            object_roots: bundle.object_roots.into_iter().map(ObjectId::from).collect(),
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
                    self.bitmap_data[byte_index] |= mask;
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
                return (self.bitmap_data[byte_index] & mask) != 0;
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
    pub fn add_extension(
        mut self,
        key: impl Into<String>,
        value: serde_json::Value,
    ) -> Self {
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

        let now_micros = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_micros() as u64;

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
            Self::SemanticValidationFailed(msg) => {
                write!(f, "semantic validation failed: {msg}")
            }
        }
    }
}

impl std::error::Error for AtpProofBundleError {}

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
        let serializable: SerializableAtpProofBundle = serde_json::from_slice(bytes).map_err(|e| {
            AtpProofBundleError::SemanticValidationFailed(format!("JSON deserialization failed: {e}"))
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

        // Cryptographic strength requires signatures (would be in extensions)
        if self.extensions.contains_key("cryptographic_signatures") {
            strength = ProofStrength::Cryptographic;
        }

        strength
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
                return Err(AtpProofBundleError::InvalidRaptorQMetadata(
                    format!("block {} has negative overhead ratio", block.block_index),
                ));
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
            .map_or(false, |m| m.repair_symbols_used > 0);

        if repair_activated != has_repair_symbols {
            return Err(AtpProofBundleError::SemanticValidationFailed(
                "repair activation inconsistent with RaptorQ metadata".to_string(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atp::verifier::{VerificationEvidence, VerificationStage};

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

    #[test]
    fn proof_bundle_builder_minimal() {
        use crate::atp::object::Object;

        let manifest_root = crate::atp::manifest::MerkleRoot::new([1; 32]);
        let object_id = Object::file(b"test".to_vec()).id;
        let chunk_bitmap = ChunkBitmap::new(1);

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
            digest: SerializableContentId::from(&crate::atp::object::ContentId::from_bytes(b"journal")),
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
            digest: SerializableContentId::from(&crate::atp::object::ContentId::from_bytes(b"journal")),
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
        assert!(matches!(err, AtpProofBundleError::InvalidVerificationEvidence(_)));
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
                digest: crate::atp::object::ContentId::from_bytes(b"journal"),
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
        bundle.extensions.insert(
            "cryptographic_signatures".to_string(),
            serde_json::json!({"type": "ed25519"}),
        );
        assert_eq!(bundle.calculate_proof_strength(), ProofStrength::Cryptographic);
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
                digest: crate::atp::object::ContentId::from_bytes(b"journal"),
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

        let err = bundle.validate().expect_err("semantic validation should fail");
        assert!(matches!(err, AtpProofBundleError::SemanticValidationFailed(_)));
    }
}