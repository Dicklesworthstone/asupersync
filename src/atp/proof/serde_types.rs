//! Serializable wrapper types for ATP proof bundles.
//!
//! This module provides serializable versions of core ATP types that can't
//! directly implement serde traits due to existing constraints. The wrappers
//! provide conversion methods to and from the original types.

use crate::atp::manifest::{GraphCommit, HashAlgorithm, MerkleRoot};
use crate::atp::object::{ContentId, ObjectId};
use crate::atp::verifier::{VerificationEvidence, VerificationStage};
use serde::{Deserialize, Serialize};

/// Serializable wrapper for MerkleRoot.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SerializableMerkleRoot {
    pub hash: [u8; 32],
}

impl From<&MerkleRoot> for SerializableMerkleRoot {
    fn from(root: &MerkleRoot) -> Self {
        Self { hash: *root.hash() }
    }
}

impl From<SerializableMerkleRoot> for MerkleRoot {
    fn from(root: SerializableMerkleRoot) -> Self {
        Self::new(root.hash)
    }
}

/// Serializable wrapper for ContentId.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SerializableContentId {
    pub hash: [u8; 32],
}

impl From<&ContentId> for SerializableContentId {
    fn from(content_id: &ContentId) -> Self {
        Self {
            hash: *content_id.hash(),
        }
    }
}

impl From<SerializableContentId> for ContentId {
    fn from(content_id: SerializableContentId) -> Self {
        Self::new(content_id.hash)
    }
}

impl std::fmt::Display for SerializableContentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.hash))
    }
}

/// Serializable wrapper for ObjectId.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum SerializableObjectId {
    Content { hash: [u8; 32] },
    Manifest { hash: [u8; 32] },
}

impl From<&ObjectId> for SerializableObjectId {
    fn from(object_id: &ObjectId) -> Self {
        match object_id {
            ObjectId::Content(content_id) => Self::Content {
                hash: *content_id.hash(),
            },
            ObjectId::Manifest(manifest_id) => Self::Manifest {
                hash: *manifest_id.hash(),
            },
        }
    }
}

impl From<SerializableObjectId> for ObjectId {
    fn from(object_id: SerializableObjectId) -> Self {
        match object_id {
            SerializableObjectId::Content { hash } => Self::Content(ContentId::new(hash)),
            SerializableObjectId::Manifest { hash } => {
                Self::Manifest(crate::atp::object::ManifestId::new(hash))
            }
        }
    }
}

/// Serializable wrapper for HashAlgorithm.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum SerializableHashAlgorithm {
    Sha256,
    Blake3,
}

impl From<&HashAlgorithm> for SerializableHashAlgorithm {
    fn from(algorithm: &HashAlgorithm) -> Self {
        match algorithm {
            HashAlgorithm::Sha256 => Self::Sha256,
            HashAlgorithm::Blake3 => Self::Blake3,
        }
    }
}

impl From<SerializableHashAlgorithm> for HashAlgorithm {
    fn from(algorithm: SerializableHashAlgorithm) -> Self {
        match algorithm {
            SerializableHashAlgorithm::Sha256 => Self::Sha256,
            SerializableHashAlgorithm::Blake3 => Self::Blake3,
        }
    }
}

/// Serializable wrapper for VerificationEvidence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SerializableVerificationEvidence {
    pub stage: String,
    pub summary: String,
    pub digest: Option<SerializableContentId>,
}

impl From<&VerificationEvidence> for SerializableVerificationEvidence {
    fn from(evidence: &VerificationEvidence) -> Self {
        Self {
            stage: evidence.stage.as_str().to_string(), // ubs:ignore
            summary: evidence.summary.clone(),
            digest: evidence.digest.as_ref().map(SerializableContentId::from),
        }
    }
}

impl TryFrom<SerializableVerificationEvidence> for VerificationEvidence {
    type Error = String;

    fn try_from(evidence: SerializableVerificationEvidence) -> Result<Self, Self::Error> {
        let stage = match evidence.stage.as_str() {
            "chunk_hash" => VerificationStage::ChunkHash,
            "object_content" => VerificationStage::ObjectContent,
            "graph_merkle" => VerificationStage::GraphMerkle,
            "manifest" => VerificationStage::Manifest,
            "commit" => VerificationStage::Commit,
            "repair_symbol" => VerificationStage::RepairSymbol,
            "proof_bundle" => VerificationStage::ProofBundle,
            "finalizer" => VerificationStage::Finalizer,
            _ => return Err(format!("unknown verification stage: {}", evidence.stage)), // ubs:ignore
        };

        Ok(Self {
            stage,
            summary: evidence.summary,
            digest: evidence.digest.map(ContentId::from),
        })
    }
}

/// Serializable proof-bundle projection of a graph commit.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SerializableGraphCommit {
    pub id_hash: [u8; 32],
    pub parent_id_hash: Option<[u8; 32]>,
    pub manifest_root: SerializableMerkleRoot,
    pub timestamp_nanos: u64,
    pub author: String,
    pub message: String,
}

impl From<&GraphCommit> for SerializableGraphCommit {
    fn from(commit: &GraphCommit) -> Self {
        Self {
            id_hash: *commit.id.hash(),
            parent_id_hash: commit.parent.as_ref().map(|p| *p.hash()),
            manifest_root: SerializableMerkleRoot::from(&commit.manifest.merkle_root),
            timestamp_nanos: commit.metadata.timestamp_nanos,
            author: commit.metadata.author.clone(),
            message: commit.metadata.message.clone(),
        }
    }
}

// Note: We don't implement From<SerializableGraphCommit> for GraphCommit
// because reconstructing a valid GraphCommit requires the full manifest,
// which is complex. For verification purposes, we only need to serialize
// the commit data, not reconstruct it.
