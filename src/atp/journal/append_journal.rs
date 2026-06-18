//! Append-Only Journal for Crash-Safe Transfer Progress Tracking

use crate::atp::manifest::MerkleRoot;
use crate::atp::object::{ContentId, ManifestId, ObjectId};
use crate::cx::Cx;
use crate::security::{AuthKey, AuthenticationTag};
use crate::types::outcome::Outcome;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Journal record types for tracking transfer progress
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalRecord {
    /// Transfer offer initiated
    Offer {
        transfer_id: String,
        object_id: ObjectId,
        manifest_root: MerkleRoot,
        total_size: u64,
        timestamp: u64,
        auth_tag: AuthenticationTag,
    },
    /// Transfer offer accepted
    Accept {
        transfer_id: String,
        peer_id: String,
        timestamp: u64,
        auth_tag: AuthenticationTag,
    },
    /// Chunk received from network
    ChunkReceived {
        transfer_id: String,
        chunk_offset: u64,
        chunk_size: u64,
        chunk_hash: [u8; 32],
        timestamp: u64,
        auth_tag: AuthenticationTag,
    },
    /// Chunk hash verified successfully
    ChunkVerified {
        transfer_id: String,
        chunk_offset: u64,
        chunk_size: u64,
        verified_hash: [u8; 32],
        timestamp: u64,
        auth_tag: AuthenticationTag,
    },
    /// Chunk written to disk
    ChunkWritten {
        transfer_id: String,
        chunk_offset: u64,
        chunk_size: u64,
        file_path: String,
        timestamp: u64,
        auth_tag: AuthenticationTag,
    },
    /// Chunk derived from repair decode
    RepairDecode {
        transfer_id: String,
        chunk_offset: u64,
        chunk_size: u64,
        source_chunks: Vec<u64>,
        timestamp: u64,
        auth_tag: AuthenticationTag,
    },
    /// Intent to commit transfer
    CommitIntent {
        transfer_id: String,
        final_manifest_root: MerkleRoot,
        timestamp: u64,
        auth_tag: AuthenticationTag,
    },
    /// Transfer commit completed
    CommitComplete {
        transfer_id: String,
        final_path: String,
        committed_size: u64,
        timestamp: u64,
        auth_tag: AuthenticationTag,
    },
    /// Transfer cancellation
    Cancellation {
        transfer_id: String,
        reason: String,
        timestamp: u64,
        auth_tag: AuthenticationTag,
    },
    /// Transfer rollback due to error
    Rollback {
        transfer_id: String,
        rollback_reason: String,
        checkpoint_sequence: u64,
        timestamp: u64,
        auth_tag: AuthenticationTag,
    },
    /// Journal compaction boundary
    CompactionBoundary {
        generation: u64,
        compacted_up_to_sequence: u64,
        timestamp: u64,
        auth_tag: AuthenticationTag,
    },
    /// Proof digest for verification
    ProofDigest {
        transfer_id: String,
        proof_type: String,
        digest: [u8; 32],
        timestamp: u64,
        auth_tag: AuthenticationTag,
    },
}

/// Crash-recovered transfer state suitable for deciding what can be skipped on resume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferResumeSummary {
    /// Transfer identifier used by the journal.
    pub transfer_id: String,
    /// Recovered resume status.
    pub status: TransferResumeStatus,
    /// Offered transfer size, when an offer record was recovered.
    pub total_size: Option<u64>,
    /// Durable verified chunks that can be skipped by a resumable replay.
    pub durable_chunks: Vec<TransferResumeChunk>,
    /// Sum of durable verified chunk sizes.
    pub durable_bytes: u64,
    /// Largest contiguous durable prefix from byte offset zero.
    pub contiguous_prefix_bytes: u64,
    /// Last journal sequence observed for this transfer.
    pub last_sequence: Option<u64>,
}

impl TransferResumeSummary {
    /// Whether the transfer can safely resume by skipping `durable_chunks`.
    pub fn is_resumable(&self) -> bool {
        matches!(self.status, TransferResumeStatus::Resumable)
    }
}

/// Terminal or resumable state reconstructed from append-journal records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferResumeStatus {
    /// No records exist for the transfer.
    Unknown,
    /// Transfer has no terminal record and may resume from durable chunks.
    Resumable,
    /// Commit intent was persisted, but commit completion was not.
    CommitIntentPending,
    /// Transfer completed; resume should not resend it.
    Committed {
        /// Final committed path.
        final_path: String,
        /// Final committed byte count.
        committed_size: u64,
    },
    /// Transfer was cancelled; callers must not infer resumable progress.
    Cancelled {
        /// Persisted cancellation reason.
        reason: String,
    },
    /// Transfer rolled back; callers must restart or use the checkpoint policy.
    RolledBack {
        /// Persisted rollback reason.
        reason: String,
        /// Journal sequence checkpoint named by the rollback record.
        checkpoint_sequence: u64,
    },
}

/// Durable chunk evidence reconstructed from matching verified and written records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferResumeChunk {
    /// Byte offset in the logical object stream.
    pub chunk_offset: u64,
    /// Chunk size in bytes.
    pub chunk_size: u64,
    /// Verified chunk hash from the journal.
    pub chunk_hash: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ResumeChunkKey {
    chunk_offset: u64,
    chunk_size: u64,
}

impl JournalRecord {
    /// Get the timestamp for this record
    pub fn timestamp(&self) -> u64 {
        match self {
            Self::Offer { timestamp, .. }
            | Self::Accept { timestamp, .. }
            | Self::ChunkReceived { timestamp, .. }
            | Self::ChunkVerified { timestamp, .. }
            | Self::ChunkWritten { timestamp, .. }
            | Self::RepairDecode { timestamp, .. }
            | Self::CommitIntent { timestamp, .. }
            | Self::CommitComplete { timestamp, .. }
            | Self::Cancellation { timestamp, .. }
            | Self::Rollback { timestamp, .. }
            | Self::CompactionBoundary { timestamp, .. }
            | Self::ProofDigest { timestamp, .. } => *timestamp,
        }
    }

    /// Get the record type name
    pub fn record_type(&self) -> &'static str {
        match self {
            Self::Offer { .. } => "offer",
            Self::Accept { .. } => "accept",
            Self::ChunkReceived { .. } => "chunk_received",
            Self::ChunkVerified { .. } => "chunk_verified",
            Self::ChunkWritten { .. } => "chunk_written",
            Self::RepairDecode { .. } => "repair_decode",
            Self::CommitIntent { .. } => "commit_intent",
            Self::CommitComplete { .. } => "commit_complete",
            Self::Cancellation { .. } => "cancellation",
            Self::Rollback { .. } => "rollback",
            Self::CompactionBoundary { .. } => "compaction_boundary",
            Self::ProofDigest { .. } => "proof_digest",
        }
    }

    /// Get the transfer id for records scoped to one transfer.
    pub(crate) fn transfer_id(&self) -> Option<&str> {
        match self {
            Self::Offer { transfer_id, .. }
            | Self::Accept { transfer_id, .. }
            | Self::ChunkReceived { transfer_id, .. }
            | Self::ChunkVerified { transfer_id, .. }
            | Self::ChunkWritten { transfer_id, .. }
            | Self::RepairDecode { transfer_id, .. }
            | Self::CommitIntent { transfer_id, .. }
            | Self::CommitComplete { transfer_id, .. }
            | Self::Cancellation { transfer_id, .. }
            | Self::Rollback { transfer_id, .. }
            | Self::ProofDigest { transfer_id, .. } => Some(transfer_id),
            Self::CompactionBoundary { .. } => None,
        }
    }

    /// Get the authentication tag for this record
    pub fn auth_tag(&self) -> &AuthenticationTag {
        match self {
            Self::Offer { auth_tag, .. }
            | Self::Accept { auth_tag, .. }
            | Self::ChunkReceived { auth_tag, .. }
            | Self::ChunkVerified { auth_tag, .. }
            | Self::ChunkWritten { auth_tag, .. }
            | Self::RepairDecode { auth_tag, .. }
            | Self::CommitIntent { auth_tag, .. }
            | Self::CommitComplete { auth_tag, .. }
            | Self::Cancellation { auth_tag, .. }
            | Self::Rollback { auth_tag, .. }
            | Self::CompactionBoundary { auth_tag, .. }
            | Self::ProofDigest { auth_tag, .. } => auth_tag,
        }
    }

    /// Verify the authentication tag for this record using the provided key
    pub fn verify_signature(&self, key: &crate::security::AuthKey) -> bool {
        use crate::security::tag::AuthenticationTag;
        use subtle::ConstantTimeEq;
        let expected_tag = AuthenticationTag::compute_for_journal_record(key, self);
        // Constant-time comparison via subtle
        expected_tag
            .as_bytes()
            .ct_eq(self.auth_tag().as_bytes())
            .into()
    }

    /// Create a signed version of this record with auth_tag computed
    pub fn with_signature(self, key: &AuthKey) -> Self {
        use crate::security::tag::AuthenticationTag;

        // Compute the auth_tag based on the record variant
        let auth_tag = AuthenticationTag::compute_for_journal_record(key, &self);

        // Return a new record with the computed auth_tag
        match self {
            Self::Offer {
                transfer_id,
                object_id,
                manifest_root,
                total_size,
                timestamp,
                ..
            } => Self::Offer {
                transfer_id,
                object_id,
                manifest_root,
                total_size,
                timestamp,
                auth_tag,
            },
            Self::Accept {
                transfer_id,
                peer_id,
                timestamp,
                ..
            } => Self::Accept {
                transfer_id,
                peer_id,
                timestamp,
                auth_tag,
            },
            Self::ChunkReceived {
                transfer_id,
                chunk_offset,
                chunk_size,
                chunk_hash,
                timestamp,
                ..
            } => Self::ChunkReceived {
                transfer_id,
                chunk_offset,
                chunk_size,
                chunk_hash,
                timestamp,
                auth_tag,
            },
            Self::ChunkVerified {
                transfer_id,
                chunk_offset,
                chunk_size,
                verified_hash,
                timestamp,
                ..
            } => Self::ChunkVerified {
                transfer_id,
                chunk_offset,
                chunk_size,
                verified_hash,
                timestamp,
                auth_tag,
            },
            Self::ChunkWritten {
                transfer_id,
                chunk_offset,
                chunk_size,
                file_path,
                timestamp,
                ..
            } => Self::ChunkWritten {
                transfer_id,
                chunk_offset,
                chunk_size,
                file_path,
                timestamp,
                auth_tag,
            },
            Self::RepairDecode {
                transfer_id,
                chunk_offset,
                chunk_size,
                source_chunks,
                timestamp,
                ..
            } => Self::RepairDecode {
                transfer_id,
                chunk_offset,
                chunk_size,
                source_chunks,
                timestamp,
                auth_tag,
            },
            Self::CommitIntent {
                transfer_id,
                final_manifest_root,
                timestamp,
                ..
            } => Self::CommitIntent {
                transfer_id,
                final_manifest_root,
                timestamp,
                auth_tag,
            },
            Self::CommitComplete {
                transfer_id,
                final_path,
                committed_size,
                timestamp,
                ..
            } => Self::CommitComplete {
                transfer_id,
                final_path,
                committed_size,
                timestamp,
                auth_tag,
            },
            Self::Cancellation {
                transfer_id,
                reason,
                timestamp,
                ..
            } => Self::Cancellation {
                transfer_id,
                reason,
                timestamp,
                auth_tag,
            },
            Self::Rollback {
                transfer_id,
                rollback_reason,
                checkpoint_sequence,
                timestamp,
                ..
            } => Self::Rollback {
                transfer_id,
                rollback_reason,
                checkpoint_sequence,
                timestamp,
                auth_tag,
            },
            Self::CompactionBoundary {
                generation,
                compacted_up_to_sequence,
                timestamp,
                ..
            } => Self::CompactionBoundary {
                generation,
                compacted_up_to_sequence,
                timestamp,
                auth_tag,
            },
            Self::ProofDigest {
                transfer_id,
                proof_type,
                digest,
                timestamp,
                ..
            } => Self::ProofDigest {
                transfer_id,
                proof_type,
                digest,
                timestamp,
                auth_tag,
            },
        }
    }

    fn signed_compaction_boundary(
        generation: u64,
        compacted_up_to_sequence: u64,
        timestamp: u64,
        key: &AuthKey,
    ) -> Self {
        Self::CompactionBoundary {
            generation,
            compacted_up_to_sequence,
            timestamp,
            auth_tag: AuthenticationTag::zero(),
        }
        .with_signature(key)
    }

    /// Encode the record payload without the auth_tag (for signature computation)
    pub fn encode_payload_without_auth_tag(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Self::Offer {
                transfer_id,
                object_id,
                manifest_root,
                total_size,
                timestamp,
                ..
            } => {
                put_u8(&mut out, 0);
                put_string(&mut out, transfer_id);
                put_object_id(&mut out, object_id);
                put_merkle_root(&mut out, manifest_root);
                put_u64(&mut out, *total_size);
                put_u64(&mut out, *timestamp);
            }
            Self::Accept {
                transfer_id,
                peer_id,
                timestamp,
                ..
            } => {
                put_u8(&mut out, 1);
                put_string(&mut out, transfer_id);
                put_string(&mut out, peer_id);
                put_u64(&mut out, *timestamp);
            }
            Self::ChunkReceived {
                transfer_id,
                chunk_offset,
                chunk_size,
                chunk_hash,
                timestamp,
                ..
            } => {
                put_u8(&mut out, 2);
                put_string(&mut out, transfer_id);
                put_u64(&mut out, *chunk_offset);
                put_u64(&mut out, *chunk_size);
                out.extend_from_slice(chunk_hash);
                put_u64(&mut out, *timestamp);
            }
            Self::ChunkVerified {
                transfer_id,
                chunk_offset,
                chunk_size,
                verified_hash,
                timestamp,
                ..
            } => {
                put_u8(&mut out, 3);
                put_string(&mut out, transfer_id);
                put_u64(&mut out, *chunk_offset);
                put_u64(&mut out, *chunk_size);
                out.extend_from_slice(verified_hash);
                put_u64(&mut out, *timestamp);
            }
            Self::ChunkWritten {
                transfer_id,
                chunk_offset,
                chunk_size,
                file_path,
                timestamp,
                ..
            } => {
                put_u8(&mut out, 4);
                put_string(&mut out, transfer_id);
                put_u64(&mut out, *chunk_offset);
                put_u64(&mut out, *chunk_size);
                put_string(&mut out, file_path);
                put_u64(&mut out, *timestamp);
            }
            Self::RepairDecode {
                transfer_id,
                chunk_offset,
                chunk_size,
                source_chunks,
                timestamp,
                ..
            } => {
                put_u8(&mut out, 5);
                put_string(&mut out, transfer_id);
                put_u64(&mut out, *chunk_offset);
                put_u64(&mut out, *chunk_size);
                put_len(&mut out, source_chunks.len());
                for source in source_chunks {
                    put_u64(&mut out, *source);
                }
                put_u64(&mut out, *timestamp);
            }
            Self::CommitIntent {
                transfer_id,
                final_manifest_root,
                timestamp,
                ..
            } => {
                put_u8(&mut out, 6);
                put_string(&mut out, transfer_id);
                put_merkle_root(&mut out, final_manifest_root);
                put_u64(&mut out, *timestamp);
            }
            Self::CommitComplete {
                transfer_id,
                final_path,
                committed_size,
                timestamp,
                ..
            } => {
                put_u8(&mut out, 7);
                put_string(&mut out, transfer_id);
                put_string(&mut out, final_path);
                put_u64(&mut out, *committed_size);
                put_u64(&mut out, *timestamp);
            }
            Self::Cancellation {
                transfer_id,
                reason,
                timestamp,
                ..
            } => {
                put_u8(&mut out, 8);
                put_string(&mut out, transfer_id);
                put_string(&mut out, reason);
                put_u64(&mut out, *timestamp);
            }
            Self::Rollback {
                transfer_id,
                rollback_reason,
                checkpoint_sequence,
                timestamp,
                ..
            } => {
                put_u8(&mut out, 9);
                put_string(&mut out, transfer_id);
                put_string(&mut out, rollback_reason);
                put_u64(&mut out, *checkpoint_sequence);
                put_u64(&mut out, *timestamp);
            }
            Self::CompactionBoundary {
                generation,
                compacted_up_to_sequence,
                timestamp,
                ..
            } => {
                put_u8(&mut out, 10);
                put_u64(&mut out, *generation);
                put_u64(&mut out, *compacted_up_to_sequence);
                put_u64(&mut out, *timestamp);
            }
            Self::ProofDigest {
                transfer_id,
                proof_type,
                digest,
                timestamp,
                ..
            } => {
                put_u8(&mut out, 11);
                put_string(&mut out, transfer_id);
                put_string(&mut out, proof_type);
                out.extend_from_slice(digest);
                put_u64(&mut out, *timestamp);
            }
        }
        out
    }

    fn encode_payload(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Self::Offer {
                transfer_id,
                object_id,
                manifest_root,
                total_size,
                timestamp,
                auth_tag,
            } => {
                put_u8(&mut out, 0);
                put_string(&mut out, transfer_id);
                put_object_id(&mut out, object_id);
                put_merkle_root(&mut out, manifest_root);
                put_u64(&mut out, *total_size);
                put_u64(&mut out, *timestamp);
                out.extend_from_slice(auth_tag.as_bytes());
            }
            Self::Accept {
                transfer_id,
                peer_id,
                timestamp,
                auth_tag,
            } => {
                put_u8(&mut out, 1);
                put_string(&mut out, transfer_id);
                put_string(&mut out, peer_id);
                put_u64(&mut out, *timestamp);
                out.extend_from_slice(auth_tag.as_bytes());
            }
            Self::ChunkReceived {
                transfer_id,
                chunk_offset,
                chunk_size,
                chunk_hash,
                timestamp,
                auth_tag,
            } => {
                put_u8(&mut out, 2);
                put_string(&mut out, transfer_id);
                put_u64(&mut out, *chunk_offset);
                put_u64(&mut out, *chunk_size);
                out.extend_from_slice(chunk_hash);
                put_u64(&mut out, *timestamp);
                out.extend_from_slice(auth_tag.as_bytes());
            }
            Self::ChunkVerified {
                transfer_id,
                chunk_offset,
                chunk_size,
                verified_hash,
                timestamp,
                auth_tag,
            } => {
                put_u8(&mut out, 3);
                put_string(&mut out, transfer_id);
                put_u64(&mut out, *chunk_offset);
                put_u64(&mut out, *chunk_size);
                out.extend_from_slice(verified_hash);
                put_u64(&mut out, *timestamp);
                out.extend_from_slice(auth_tag.as_bytes());
            }
            Self::ChunkWritten {
                transfer_id,
                chunk_offset,
                chunk_size,
                file_path,
                timestamp,
                auth_tag,
            } => {
                put_u8(&mut out, 4);
                put_string(&mut out, transfer_id);
                put_u64(&mut out, *chunk_offset);
                put_u64(&mut out, *chunk_size);
                put_string(&mut out, file_path);
                put_u64(&mut out, *timestamp);
                out.extend_from_slice(auth_tag.as_bytes());
            }
            Self::RepairDecode {
                transfer_id,
                chunk_offset,
                chunk_size,
                source_chunks,
                timestamp,
                auth_tag,
            } => {
                put_u8(&mut out, 5);
                put_string(&mut out, transfer_id);
                put_u64(&mut out, *chunk_offset);
                put_u64(&mut out, *chunk_size);
                put_len(&mut out, source_chunks.len());
                for source in source_chunks {
                    put_u64(&mut out, *source);
                }
                put_u64(&mut out, *timestamp);
                out.extend_from_slice(auth_tag.as_bytes());
            }
            Self::CommitIntent {
                transfer_id,
                final_manifest_root,
                timestamp,
                auth_tag,
            } => {
                put_u8(&mut out, 6);
                put_string(&mut out, transfer_id);
                put_merkle_root(&mut out, final_manifest_root);
                put_u64(&mut out, *timestamp);
                out.extend_from_slice(auth_tag.as_bytes());
            }
            Self::CommitComplete {
                transfer_id,
                final_path,
                committed_size,
                timestamp,
                auth_tag,
            } => {
                put_u8(&mut out, 7);
                put_string(&mut out, transfer_id);
                put_string(&mut out, final_path);
                put_u64(&mut out, *committed_size);
                put_u64(&mut out, *timestamp);
                out.extend_from_slice(auth_tag.as_bytes());
            }
            Self::Cancellation {
                transfer_id,
                reason,
                timestamp,
                auth_tag,
            } => {
                put_u8(&mut out, 8);
                put_string(&mut out, transfer_id);
                put_string(&mut out, reason);
                put_u64(&mut out, *timestamp);
                out.extend_from_slice(auth_tag.as_bytes());
            }
            Self::Rollback {
                transfer_id,
                rollback_reason,
                checkpoint_sequence,
                timestamp,
                auth_tag,
            } => {
                put_u8(&mut out, 9);
                put_string(&mut out, transfer_id);
                put_string(&mut out, rollback_reason);
                put_u64(&mut out, *checkpoint_sequence);
                put_u64(&mut out, *timestamp);
                out.extend_from_slice(auth_tag.as_bytes());
            }
            Self::CompactionBoundary {
                generation,
                compacted_up_to_sequence,
                timestamp,
                auth_tag,
            } => {
                put_u8(&mut out, 10);
                put_u64(&mut out, *generation);
                put_u64(&mut out, *compacted_up_to_sequence);
                put_u64(&mut out, *timestamp);
                out.extend_from_slice(auth_tag.as_bytes());
            }
            Self::ProofDigest {
                transfer_id,
                proof_type,
                digest,
                timestamp,
                auth_tag,
            } => {
                put_u8(&mut out, 11);
                put_string(&mut out, transfer_id);
                put_string(&mut out, proof_type);
                out.extend_from_slice(digest);
                put_u64(&mut out, *timestamp);
                out.extend_from_slice(auth_tag.as_bytes());
            }
        }
        out
    }

    fn decode_payload(data: &[u8]) -> Result<Self, JournalError> {
        let mut cursor = DecodeCursor::new(data);
        let tag = cursor.read_u8()?;
        match tag {
            0 => Ok(Self::Offer {
                transfer_id: cursor.read_string()?,
                object_id: cursor.read_object_id()?,
                manifest_root: cursor.read_merkle_root()?,
                total_size: cursor.read_u64()?,
                timestamp: cursor.read_u64()?,
                auth_tag: cursor.read_auth_tag()?,
            }),
            1 => Ok(Self::Accept {
                transfer_id: cursor.read_string()?,
                peer_id: cursor.read_string()?,
                timestamp: cursor.read_u64()?,
                auth_tag: cursor.read_auth_tag()?,
            }),
            2 => Ok(Self::ChunkReceived {
                transfer_id: cursor.read_string()?,
                chunk_offset: cursor.read_u64()?,
                chunk_size: cursor.read_u64()?,
                chunk_hash: cursor.read_hash()?,
                timestamp: cursor.read_u64()?,
                auth_tag: cursor.read_auth_tag()?,
            }),
            3 => Ok(Self::ChunkVerified {
                transfer_id: cursor.read_string()?,
                chunk_offset: cursor.read_u64()?,
                chunk_size: cursor.read_u64()?,
                verified_hash: cursor.read_hash()?,
                timestamp: cursor.read_u64()?,
                auth_tag: cursor.read_auth_tag()?,
            }),
            4 => Ok(Self::ChunkWritten {
                transfer_id: cursor.read_string()?,
                chunk_offset: cursor.read_u64()?,
                chunk_size: cursor.read_u64()?,
                file_path: cursor.read_string()?,
                timestamp: cursor.read_u64()?,
                auth_tag: cursor.read_auth_tag()?,
            }),
            5 => {
                let transfer_id = cursor.read_string()?;
                let chunk_offset = cursor.read_u64()?;
                let chunk_size = cursor.read_u64()?;
                let source_count = cursor.read_len()?;
                let mut source_chunks = Vec::with_capacity(source_count);
                for _ in 0..source_count {
                    source_chunks.push(cursor.read_u64()?);
                }
                Ok(Self::RepairDecode {
                    transfer_id,
                    chunk_offset,
                    chunk_size,
                    source_chunks,
                    timestamp: cursor.read_u64()?,
                    auth_tag: cursor.read_auth_tag()?,
                })
            }
            6 => Ok(Self::CommitIntent {
                transfer_id: cursor.read_string()?,
                final_manifest_root: cursor.read_merkle_root()?,
                timestamp: cursor.read_u64()?,
                auth_tag: cursor.read_auth_tag()?,
            }),
            7 => Ok(Self::CommitComplete {
                transfer_id: cursor.read_string()?,
                final_path: cursor.read_string()?,
                committed_size: cursor.read_u64()?,
                timestamp: cursor.read_u64()?,
                auth_tag: cursor.read_auth_tag()?,
            }),
            8 => Ok(Self::Cancellation {
                transfer_id: cursor.read_string()?,
                reason: cursor.read_string()?,
                timestamp: cursor.read_u64()?,
                auth_tag: cursor.read_auth_tag()?,
            }),
            9 => Ok(Self::Rollback {
                transfer_id: cursor.read_string()?,
                rollback_reason: cursor.read_string()?,
                checkpoint_sequence: cursor.read_u64()?,
                timestamp: cursor.read_u64()?,
                auth_tag: cursor.read_auth_tag()?,
            }),
            10 => Ok(Self::CompactionBoundary {
                generation: cursor.read_u64()?,
                compacted_up_to_sequence: cursor.read_u64()?,
                timestamp: cursor.read_u64()?,
                auth_tag: cursor.read_auth_tag()?,
            }),
            11 => Ok(Self::ProofDigest {
                transfer_id: cursor.read_string()?,
                proof_type: cursor.read_string()?,
                digest: cursor.read_hash()?,
                timestamp: cursor.read_u64()?,
                auth_tag: cursor.read_auth_tag()?,
            }),
            other => Err(JournalError::Deserialization(format!(
                "unknown journal record tag {other}"
            ))),
        }
    }
}

fn put_u8(out: &mut Vec<u8>, value: u8) {
    out.push(value);
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_len(out: &mut Vec<u8>, len: usize) {
    let len = checked_u32_len(len, "journal field").expect("journal field length was prevalidated");
    out.extend_from_slice(&len.to_le_bytes());
}

fn put_string(out: &mut Vec<u8>, value: &str) {
    put_len(out, value.len());
    out.extend_from_slice(value.as_bytes());
}

fn put_object_id(out: &mut Vec<u8>, object_id: &ObjectId) {
    match object_id {
        ObjectId::Content(content_id) => {
            put_u8(out, 0);
            out.extend_from_slice(content_id.hash());
        }
        ObjectId::Manifest(manifest_id) => {
            put_u8(out, 1);
            out.extend_from_slice(manifest_id.hash());
        }
    }
}

fn put_merkle_root(out: &mut Vec<u8>, root: &MerkleRoot) {
    out.extend_from_slice(root.hash());
}

fn checked_u32_len(len: usize, field_name: &'static str) -> Result<u32, JournalError> {
    u32::try_from(len).map_err(|_| {
        JournalError::Serialization(format!("{field_name} exceeds u32 length: {len} bytes"))
    })
}

fn validate_string_len(value: &str, field_name: &'static str) -> Result<(), JournalError> {
    checked_u32_len(value.len(), field_name).map(|_| ())
}

fn validate_record_lengths(record: &JournalRecord) -> Result<(), JournalError> {
    match record {
        JournalRecord::Offer { transfer_id, .. } => validate_string_len(transfer_id, "transfer_id"),
        JournalRecord::Accept {
            transfer_id,
            peer_id,
            ..
        } => {
            validate_string_len(transfer_id, "transfer_id")?;
            validate_string_len(peer_id, "peer_id")
        }
        JournalRecord::ChunkReceived { transfer_id, .. }
        | JournalRecord::ChunkVerified { transfer_id, .. }
        | JournalRecord::CommitIntent { transfer_id, .. } => {
            validate_string_len(transfer_id, "transfer_id")
        }
        JournalRecord::Cancellation {
            transfer_id,
            reason,
            ..
        } => {
            validate_string_len(transfer_id, "transfer_id")?;
            validate_string_len(reason, "reason")
        }
        JournalRecord::ProofDigest {
            transfer_id,
            proof_type,
            ..
        } => {
            validate_string_len(transfer_id, "transfer_id")?;
            validate_string_len(proof_type, "proof_type")
        }
        JournalRecord::ChunkWritten {
            transfer_id,
            file_path,
            ..
        } => {
            validate_string_len(transfer_id, "transfer_id")?;
            validate_string_len(file_path, "file_path")
        }
        JournalRecord::RepairDecode {
            transfer_id,
            source_chunks,
            ..
        } => {
            validate_string_len(transfer_id, "transfer_id")?;
            checked_u32_len(source_chunks.len(), "source_chunks")?;
            Ok(())
        }
        JournalRecord::Rollback {
            transfer_id,
            rollback_reason,
            ..
        } => {
            validate_string_len(transfer_id, "transfer_id")?;
            validate_string_len(rollback_reason, "rollback_reason")
        }
        JournalRecord::CommitComplete {
            transfer_id,
            final_path,
            ..
        } => {
            validate_string_len(transfer_id, "transfer_id")?;
            validate_string_len(final_path, "final_path")
        }
        JournalRecord::CompactionBoundary { .. } => Ok(()),
    }
}

struct DecodeCursor<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> DecodeCursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    fn read_exact(&mut self, len: usize) -> Result<&'a [u8], JournalError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| JournalError::Deserialization("entry length overflow".to_string()))?;
        if end > self.data.len() {
            return Err(JournalError::Deserialization(
                "truncated journal entry".to_string(),
            ));
        }
        let bytes = &self.data[self.offset..end];
        self.offset = end;
        Ok(bytes)
    }

    fn read_u8(&mut self) -> Result<u8, JournalError> {
        Ok(self.read_exact(1)?[0])
    }

    fn read_u64(&mut self) -> Result<u64, JournalError> {
        let mut bytes = [0; 8];
        bytes.copy_from_slice(self.read_exact(8)?);
        Ok(u64::from_le_bytes(bytes))
    }

    fn read_len(&mut self) -> Result<usize, JournalError> {
        let mut bytes = [0; 4];
        bytes.copy_from_slice(self.read_exact(4)?);
        let len = u32::from_le_bytes(bytes);
        usize::try_from(len)
            .map_err(|_| JournalError::Deserialization("invalid length".to_string()))
    }

    fn read_string(&mut self) -> Result<String, JournalError> {
        let len = self.read_len()?;
        let bytes = self.read_exact(len)?;
        String::from_utf8(bytes.to_vec()).map_err(|e| JournalError::Deserialization(e.to_string()))
    }

    fn read_hash(&mut self) -> Result<[u8; 32], JournalError> {
        let mut hash = [0; 32];
        hash.copy_from_slice(self.read_exact(32)?);
        Ok(hash)
    }

    fn read_auth_tag(&mut self) -> Result<AuthenticationTag, JournalError> {
        let mut bytes = [0; 32];
        bytes.copy_from_slice(self.read_exact(32)?);
        Ok(AuthenticationTag::from_bytes(bytes))
    }

    fn read_object_id(&mut self) -> Result<ObjectId, JournalError> {
        let tag = self.read_u8()?;
        let hash = self.read_hash()?;
        match tag {
            0 => Ok(ObjectId::Content(ContentId::new(hash))),
            1 => Ok(ObjectId::Manifest(ManifestId::new(hash))),
            other => Err(JournalError::Deserialization(format!(
                "unknown object id tag {other}"
            ))),
        }
    }

    fn read_merkle_root(&mut self) -> Result<MerkleRoot, JournalError> {
        Ok(MerkleRoot::new(self.read_hash()?))
    }

    fn finish(&self) -> Result<(), JournalError> {
        if self.offset == self.data.len() {
            Ok(())
        } else {
            Err(JournalError::Deserialization(
                "trailing bytes in journal entry".to_string(),
            ))
        }
    }
}

/// Journal entry with metadata
#[derive(Debug, Clone)]
pub struct JournalEntry {
    /// Sequence number in journal
    pub sequence: u64,
    /// The actual record
    pub record: JournalRecord,
    /// Checksum of the entry
    pub checksum: u32,
    /// Entry size in bytes
    pub entry_size: u32,
}

impl JournalEntry {
    /// Create a new journal entry
    pub fn new(sequence: u64, record: JournalRecord) -> Self {
        Self::try_new(sequence, record).expect("journal record length was prevalidated")
    }

    fn try_new(sequence: u64, record: JournalRecord) -> Result<Self, JournalError> {
        let serialized = record.encode_payload();
        let checksum = crc32fast::hash(&serialized);
        let entry_size = checked_u32_len(serialized.len(), "journal record")?;

        Ok(Self {
            sequence,
            record,
            checksum,
            entry_size,
        })
    }

    /// Validate the entry's checksum
    pub fn validate_checksum(&self) -> bool {
        let serialized = self.record.encode_payload();
        let computed_checksum = crc32fast::hash(&serialized);
        computed_checksum == self.checksum
    }

    fn encode(&self) -> Vec<u8> {
        let record = self.record.encode_payload();
        let mut out = Vec::with_capacity(16 + record.len());
        put_u64(&mut out, self.sequence);
        out.extend_from_slice(&self.checksum.to_le_bytes());
        out.extend_from_slice(&self.entry_size.to_le_bytes());
        out.extend_from_slice(&record);
        out
    }

    fn decode(data: &[u8]) -> Result<Self, JournalError> {
        let mut cursor = DecodeCursor::new(data);
        let sequence = cursor.read_u64()?;
        let mut checksum_bytes = [0; 4];
        checksum_bytes.copy_from_slice(cursor.read_exact(4)?);
        let checksum = u32::from_le_bytes(checksum_bytes);
        let entry_size = cursor.read_len()? as u32;
        let record_payload = cursor.read_exact(entry_size as usize)?;
        let record = JournalRecord::decode_payload(record_payload)?;
        cursor.finish()?;
        Ok(Self {
            sequence,
            record,
            checksum,
            entry_size,
        })
    }
}

/// Configuration for append-only journal
#[derive(Debug, Clone)]
pub struct JournalConfig {
    /// Base directory for journal files
    pub base_dir: PathBuf,
    /// Maximum size before triggering compaction
    pub max_journal_size: u64,
    /// Maximum number of recent entries kept in memory.
    pub recent_entries_limit: usize,
    /// Whether to fsync after every write
    pub force_sync: bool,
    /// Buffer size for writes
    pub write_buffer_size: usize,
    /// Maximum number of generations to keep
    pub max_generations: u32,
    /// Enable detailed logging
    pub enable_detailed_logs: bool,
}

impl Default for JournalConfig {
    fn default() -> Self {
        Self {
            base_dir: std::env::temp_dir().join("atp_journal"),
            max_journal_size: 100 * 1024 * 1024, // 100MB
            recent_entries_limit: 1000,
            force_sync: true,
            write_buffer_size: 64 * 1024, // 64KB
            max_generations: 10,
            enable_detailed_logs: true,
        }
    }
}

const JOURNAL_FILE_PREFIX: &str = "journal_gen_";
const JOURNAL_FILE_SUFFIX: &str = ".dat";

fn journal_file_name(generation: u64) -> String {
    format!("{JOURNAL_FILE_PREFIX}{generation:06}{JOURNAL_FILE_SUFFIX}")
}

fn journal_file_path(base_dir: &Path, generation: u64) -> PathBuf {
    base_dir.join(journal_file_name(generation))
}

fn parse_journal_generation(file_name: &str) -> Option<u64> {
    let generation = file_name
        .strip_prefix(JOURNAL_FILE_PREFIX)?
        .strip_suffix(JOURNAL_FILE_SUFFIX)?;
    generation.parse().ok()
}

/// Append-only journal for crash-safe transfer tracking
pub struct AppendJournal {
    /// Configuration
    config: JournalConfig,
    /// Current generation number
    generation: u64,
    /// Current sequence number
    sequence: u64,
    /// Writer for current journal file
    writer: Option<BufWriter<File>>,
    /// Current journal file path
    current_file: Option<PathBuf>,
    /// In-memory cache of recent entries
    recent_entries: VecDeque<JournalEntry>,
    /// Complete in-memory transfer index keyed by transfer ID.
    transfer_entries: HashMap<String, Vec<JournalEntry>>,
    /// Cache size limit
    cache_limit: usize,
    /// Authentication key for record signing
    auth_key: AuthKey,
}

impl AppendJournal {
    /// Create a new append-only journal
    pub fn new(config: JournalConfig, auth_key: AuthKey) -> Outcome<Self, JournalError> {
        // Ensure base directory exists
        if let Err(e) = std::fs::create_dir_all(&config.base_dir) {
            return Outcome::Err(JournalError::DirectoryCreation(e.to_string()));
        }
        let cache_limit = config.recent_entries_limit;

        let mut journal = Self {
            config,
            generation: 0,
            sequence: 0,
            writer: None,
            current_file: None,
            recent_entries: VecDeque::new(),
            transfer_entries: HashMap::new(),
            cache_limit,
            auth_key,
        };

        // Try to recover from existing journal
        match journal.recover_from_disk() {
            Outcome::Ok(()) => {}
            Outcome::Err(_) | Outcome::Cancelled(_) | Outcome::Panicked(_) => {
                journal.generation = 0;
                journal.sequence = 0;
            }
        }

        Outcome::Ok(journal)
    }

    /// Append a new record to the journal
    pub fn append(&mut self, record: JournalRecord) -> Outcome<u64, JournalError> {
        // Ensure we have an active writer
        match self.ensure_writer() {
            Outcome::Ok(()) => {}
            Outcome::Err(e) => return Outcome::Err(e),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        }

        let is_boundary = matches!(record, JournalRecord::CompactionBoundary { .. });
        if let Err(err) = validate_record_lengths(&record) {
            return Outcome::Err(err);
        }
        let entry =
            match JournalEntry::try_new(self.sequence, record.with_signature(&self.auth_key)) {
                Ok(entry) => entry,
                Err(err) => return Outcome::Err(err),
            };

        // Serialize the entry
        let serialized = entry.encode();

        // Write to disk
        if let Some(ref mut writer) = self.writer {
            // Write length prefix
            let length = match checked_u32_len(serialized.len(), "journal frame") {
                Ok(length) => length,
                Err(err) => return Outcome::Err(err),
            };
            if let Err(e) = writer.write_all(&length.to_le_bytes()) {
                return Outcome::Err(JournalError::WriteFailure(e.to_string()));
            }

            // Write entry data
            if let Err(e) = writer.write_all(&serialized) {
                return Outcome::Err(JournalError::WriteFailure(e.to_string()));
            }

            if self.config.force_sync {
                if let Err(e) = sync_writer_data(writer) {
                    return Outcome::Err(e);
                }
            } else if let Err(e) = flush_writer_buffer(writer) {
                return Outcome::Err(e);
            }
        }

        // Update in-memory state
        let current_sequence = self.sequence;
        self.sequence += 1;

        self.index_transfer_entry(&entry);
        self.recent_entries.push_back(entry);
        if self.recent_entries.len() > self.cache_limit {
            self.recent_entries.pop_front();
        }

        // Check if compaction is needed (but not if we are already appending a compaction boundary)
        if !is_boundary {
            match self.should_compact() {
                Outcome::Ok(true) => match self.trigger_compaction() {
                    Outcome::Ok(()) => {}
                    Outcome::Err(e) => return Outcome::Err(e),
                    Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
                    Outcome::Panicked(payload) => return Outcome::Panicked(payload),
                },
                Outcome::Ok(false) => {}
                Outcome::Err(e) => return Outcome::Err(e),
                Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
                Outcome::Panicked(payload) => return Outcome::Panicked(payload),
            }
        }

        Outcome::Ok(current_sequence)
    }

    /// Flush any pending writes
    pub fn flush(&mut self) -> Outcome<(), JournalError> {
        if let Some(ref mut writer) = self.writer {
            if let Err(e) = sync_writer_data(writer) {
                return Outcome::Err(e);
            }
        }
        Outcome::Ok(())
    }

    /// Get recent entries from cache
    pub fn get_recent_entries(&self, limit: usize) -> Vec<&JournalEntry> {
        self.recent_entries.iter().rev().take(limit).collect()
    }

    /// Read all entries from all generations
    pub async fn get_all_entries(&self, _cx: &Cx) -> Outcome<Vec<JournalRecord>, JournalError> {
        match self.read_all_entries_from_disk() {
            Outcome::Ok(entries) => {
                Outcome::Ok(entries.into_iter().map(|entry| entry.record).collect())
            }
            Outcome::Err(err) => Outcome::Err(err),
            Outcome::Cancelled(reason) => Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => Outcome::Panicked(payload),
        }
    }

    /// Read all entries for a specific transfer ID
    pub fn get_transfer_entries(
        &self,
        transfer_id: &str,
    ) -> Outcome<Vec<JournalEntry>, JournalError> {
        let mut entries = self
            .transfer_entries
            .get(transfer_id)
            .cloned()
            .unwrap_or_default();
        entries.sort_by_key(|e| e.sequence);
        entries.dedup_by_key(|e| e.sequence);
        Outcome::Ok(entries)
    }

    /// Reconstruct resumable transfer progress from the crash-safe journal index.
    pub fn get_resume_summary(
        &self,
        transfer_id: &str,
    ) -> Outcome<TransferResumeSummary, JournalError> {
        let entries = match self.get_transfer_entries(transfer_id) {
            Outcome::Ok(entries) => entries,
            Outcome::Err(err) => return Outcome::Err(err),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        };

        match Self::build_resume_summary(transfer_id, &entries) {
            Ok(summary) => Outcome::Ok(summary),
            Err(err) => Outcome::Err(err),
        }
    }

    /// Force compaction of the journal
    pub fn compact(&mut self) -> Outcome<(), JournalError> {
        self.trigger_compaction()
    }

    /// Get journal statistics
    pub fn get_stats(&self) -> JournalStats {
        let current_size = self
            .current_file
            .as_ref()
            .and_then(|path| std::fs::metadata(path).ok())
            .map_or(0, |meta| meta.len());

        JournalStats {
            generation: self.generation,
            sequence: self.sequence,
            current_file_size: current_size,
            recent_entries_count: self.recent_entries.len(),
            total_entries: self.sequence,
        }
    }

    // Private helper methods

    fn ensure_writer(&mut self) -> Outcome<(), JournalError> {
        if self.writer.is_some() {
            return Outcome::Ok(());
        }

        let (file_path, writer) = match self.open_generation_writer(self.generation) {
            Outcome::Ok(writer) => writer,
            Outcome::Err(e) => return Outcome::Err(e),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        };

        self.writer = Some(writer);
        self.current_file = Some(file_path);

        Outcome::Ok(())
    }

    fn open_generation_writer(
        &self,
        generation: u64,
    ) -> Outcome<(PathBuf, BufWriter<File>), JournalError> {
        let file_path = journal_file_path(&self.config.base_dir, generation);
        let file = match OpenOptions::new()
            .create(true)
            .append(true)
            .open(&file_path)
        {
            Ok(f) => f,
            Err(e) => return Outcome::Err(JournalError::FileOpen(e.to_string())),
        };

        if let Err(err) = sync_journal_directory(&self.config.base_dir) {
            return Outcome::Err(err);
        }

        Outcome::Ok((
            file_path,
            BufWriter::with_capacity(self.config.write_buffer_size, file),
        ))
    }

    fn should_compact(&self) -> Outcome<bool, JournalError> {
        let current_size = self
            .current_file
            .as_ref()
            .and_then(|path| std::fs::metadata(path).ok())
            .map_or(0, |meta| meta.len());

        Outcome::Ok(current_size >= self.config.max_journal_size)
    }

    fn trigger_compaction(&mut self) -> Outcome<(), JournalError> {
        // Flush current writer
        match self.flush() {
            Outcome::Ok(()) => {}
            Outcome::Err(e) => return Outcome::Err(e),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        }

        let next_generation = match self.generation.checked_add(1) {
            Some(generation) => generation,
            None => {
                return Outcome::Err(JournalError::CompactionFailed(
                    "journal generation overflow".to_string(),
                ));
            }
        };

        // Create compaction boundary record
        let boundary_record = JournalRecord::signed_compaction_boundary(
            next_generation,
            self.sequence,
            SystemTime::now() // ubs:ignore - timestamp used for recording, not crypto randomness
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            &self.auth_key,
        );

        // Write the boundary record
        match self.append(boundary_record) {
            Outcome::Ok(_) => {}
            Outcome::Err(e) => return Outcome::Err(e),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        }

        // Close current writer and create the next generation before success is
        // reported, so recovery observes the boundary and its target file.
        self.writer = None;
        self.current_file = None;

        self.generation = next_generation;
        match self.ensure_writer() {
            Outcome::Ok(()) => {}
            Outcome::Err(e) => return Outcome::Err(e),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        }

        // Clean up old generations
        match self.cleanup_old_generations() {
            Outcome::Ok(()) => {}
            Outcome::Err(e) => return Outcome::Err(e),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        }

        Outcome::Ok(())
    }

    fn cleanup_old_generations(&self) -> Outcome<(), JournalError> {
        if self.generation <= self.config.max_generations as u64 {
            return Outcome::Ok(());
        }

        let cutoff_generation = self.generation - self.config.max_generations as u64;

        for generation_num in 0..cutoff_generation {
            let old_file = journal_file_path(&self.config.base_dir, generation_num);
            if old_file.exists() {
                if let Err(e) = std::fs::remove_file(&old_file) {
                    if self.config.enable_detailed_logs {
                        eprintln!(
                            "Failed to remove old journal generation {}: {}",
                            generation_num, e
                        );
                    }
                    // Continue cleanup despite errors
                }
            }
        }

        Outcome::Ok(())
    }

    fn recover_from_disk(&mut self) -> Outcome<(), JournalError> {
        let mut max_generation = 0;
        let mut max_sequence = 0;

        // Find the latest generation
        let entries = match std::fs::read_dir(&self.config.base_dir) {
            Ok(entries) => entries,
            Err(_) => return Outcome::Ok(()), // Directory doesn't exist yet
        };

        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(e) => return Outcome::Err(JournalError::DirectoryRead(e.to_string())),
            };
            let file_name = entry.file_name();
            let file_name_str = file_name.to_string_lossy();

            if let Some(generation_num) = parse_journal_generation(&file_name_str) {
                max_generation = max_generation.max(generation_num);
            }
        }

        // Read all valid entries once so recovery rebuilds both the recent-entry
        // window and the transfer-id index used by targeted lookups.
        let mut all_recent = VecDeque::new();
        let mut transfer_entries: HashMap<String, Vec<JournalEntry>> = HashMap::new();
        let mut found_sequence = false;
        let mut recovered_generation = max_generation;

        for generation in 0..=max_generation {
            let file_path = journal_file_path(&self.config.base_dir, generation);

            if !file_path.exists() {
                continue;
            }

            let (entries, corrupted) = match self.read_entries_from_file(&file_path) {
                Outcome::Ok(res) => res,
                Outcome::Err(e) => return Outcome::Err(e),
                Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
                Outcome::Panicked(payload) => return Outcome::Panicked(payload),
            };

            if generation == max_generation && corrupted {
                // If the latest file was corrupted (e.g. partial write from power loss),
                // we must not append to it. We increment max_generation so the next write
                // starts a new file cleanly.
                recovered_generation = recovered_generation.saturating_add(1);
            }

            for entry in entries {
                max_sequence = max_sequence.max(entry.sequence);
                found_sequence = true;

                if let Some(transfer_id) = entry.record.transfer_id() {
                    transfer_entries
                        .entry(transfer_id.to_string())
                        .or_default()
                        .push(entry.clone());
                }

                all_recent.push_back(entry);
                if all_recent.len() > self.cache_limit {
                    all_recent.pop_front();
                }
            }
        }

        for entries in transfer_entries.values_mut() {
            entries.sort_by_key(|entry| entry.sequence);
            entries.dedup_by_key(|entry| entry.sequence);
        }

        self.recent_entries = all_recent;
        self.transfer_entries = transfer_entries;
        self.generation = recovered_generation;
        if found_sequence {
            self.sequence = max_sequence + 1;
        } else {
            self.sequence = 0;
        }

        Outcome::Ok(())
    }

    fn index_transfer_entry(&mut self, entry: &JournalEntry) {
        if let Some(transfer_id) = entry.record.transfer_id() {
            let entries = self
                .transfer_entries
                .entry(transfer_id.to_string())
                .or_default();
            match entries.binary_search_by_key(&entry.sequence, |existing| existing.sequence) {
                Ok(position) => entries[position] = entry.clone(),
                Err(position) => entries.insert(position, entry.clone()),
            }
        }
    }

    fn build_resume_summary(
        transfer_id: &str,
        entries: &[JournalEntry],
    ) -> Result<TransferResumeSummary, JournalError> {
        let mut total_size = None;
        let mut last_sequence = None;
        let mut terminal_status = None;
        let mut verified_chunks: HashMap<ResumeChunkKey, [u8; 32]> = HashMap::new();
        let mut written_chunks: HashSet<ResumeChunkKey> = HashSet::new();

        for entry in entries {
            last_sequence = Some(entry.sequence);
            match &entry.record {
                JournalRecord::Offer {
                    total_size: offered_size,
                    ..
                } => match total_size {
                    None => total_size = Some(*offered_size),
                    Some(existing) if existing == *offered_size => {}
                    Some(existing) => {
                        return Err(JournalError::Deserialization(format!(
                            "resume offer total_size conflict: previous {existing}, recovered {offered_size}"
                        )));
                    }
                },
                JournalRecord::ChunkVerified {
                    chunk_offset,
                    chunk_size,
                    verified_hash,
                    ..
                } => {
                    let key = ResumeChunkKey {
                        chunk_offset: *chunk_offset,
                        chunk_size: *chunk_size,
                    };
                    match verified_chunks.get(&key) {
                        Some(existing_hash) if existing_hash != verified_hash => {
                            return Err(JournalError::Deserialization(format!(
                                "resume chunk verified hash conflict at offset {} size {}",
                                chunk_offset, chunk_size
                            )));
                        }
                        Some(_) => {}
                        None => {
                            verified_chunks.insert(key, *verified_hash);
                        }
                    }
                }
                JournalRecord::ChunkWritten {
                    chunk_offset,
                    chunk_size,
                    ..
                } => {
                    written_chunks.insert(ResumeChunkKey {
                        chunk_offset: *chunk_offset,
                        chunk_size: *chunk_size,
                    });
                }
                JournalRecord::CommitIntent { .. } => {
                    terminal_status = Some(TransferResumeStatus::CommitIntentPending);
                }
                JournalRecord::CommitComplete {
                    final_path,
                    committed_size,
                    ..
                } => {
                    terminal_status = Some(TransferResumeStatus::Committed {
                        final_path: final_path.clone(),
                        committed_size: *committed_size,
                    });
                }
                JournalRecord::Cancellation { reason, .. } => {
                    terminal_status = Some(TransferResumeStatus::Cancelled {
                        reason: reason.clone(),
                    });
                }
                JournalRecord::Rollback {
                    rollback_reason,
                    checkpoint_sequence,
                    ..
                } => {
                    terminal_status = Some(TransferResumeStatus::RolledBack {
                        reason: rollback_reason.clone(),
                        checkpoint_sequence: *checkpoint_sequence,
                    });
                }
                JournalRecord::Accept { .. }
                | JournalRecord::ChunkReceived { .. }
                | JournalRecord::RepairDecode { .. }
                | JournalRecord::CompactionBoundary { .. }
                | JournalRecord::ProofDigest { .. } => {}
            }
        }

        let status = terminal_status.unwrap_or(if entries.is_empty() {
            TransferResumeStatus::Unknown
        } else {
            TransferResumeStatus::Resumable
        });

        let (durable_chunks, durable_bytes, contiguous_prefix_bytes) =
            if matches!(status, TransferResumeStatus::Resumable) {
                Self::durable_resume_chunks(&verified_chunks, &written_chunks, total_size)?
            } else {
                (Vec::new(), 0, 0)
            };

        Ok(TransferResumeSummary {
            transfer_id: transfer_id.to_string(),
            status,
            total_size,
            durable_chunks,
            durable_bytes,
            contiguous_prefix_bytes,
            last_sequence,
        })
    }

    fn durable_resume_chunks(
        verified_chunks: &HashMap<ResumeChunkKey, [u8; 32]>,
        written_chunks: &HashSet<ResumeChunkKey>,
        total_size: Option<u64>,
    ) -> Result<(Vec<TransferResumeChunk>, u64, u64), JournalError> {
        let mut chunks = written_chunks
            .iter()
            .filter_map(|key| {
                verified_chunks
                    .get(key)
                    .map(|chunk_hash| TransferResumeChunk {
                        chunk_offset: key.chunk_offset,
                        chunk_size: key.chunk_size,
                        chunk_hash: *chunk_hash,
                    })
            })
            .collect::<Vec<_>>();
        chunks.sort_by_key(|chunk| (chunk.chunk_offset, chunk.chunk_size));

        let mut durable_bytes = 0_u64;
        let mut contiguous_prefix_bytes = 0_u64;
        let mut prefix_is_contiguous = true;
        let mut previous_end = 0_u64;

        for chunk in &chunks {
            if chunk.chunk_size == 0 {
                return Err(JournalError::Deserialization(
                    "resume chunk has zero size".to_string(),
                ));
            }
            let end = chunk
                .chunk_offset
                .checked_add(chunk.chunk_size)
                .ok_or_else(|| {
                    JournalError::Deserialization("resume chunk range overflow".to_string())
                })?;
            if chunk.chunk_offset < previous_end {
                return Err(JournalError::Deserialization(
                    "resume chunks overlap".to_string(),
                ));
            }
            if let Some(total_size) = total_size
                && end > total_size
            {
                return Err(JournalError::Deserialization(
                    "resume chunk exceeds offered transfer size".to_string(),
                ));
            }

            durable_bytes = durable_bytes.checked_add(chunk.chunk_size).ok_or_else(|| {
                JournalError::Deserialization("resume durable byte count overflow".to_string())
            })?;
            if prefix_is_contiguous && chunk.chunk_offset == contiguous_prefix_bytes {
                contiguous_prefix_bytes = end;
            } else if chunk.chunk_offset > contiguous_prefix_bytes {
                prefix_is_contiguous = false;
            }
            previous_end = end;
        }

        Ok((chunks, durable_bytes, contiguous_prefix_bytes))
    }

    fn read_entries_from_file(
        &self,
        file_path: &Path,
    ) -> Outcome<(Vec<JournalEntry>, bool), JournalError> {
        let file = match File::open(file_path) {
            Ok(file) => file,
            Err(e) => return Outcome::Err(JournalError::FileOpen(e.to_string())),
        };
        let mut reader = BufReader::new(file);
        let mut entries = Vec::new();
        let mut corrupted = false;

        loop {
            // Read length prefix
            let mut length_bytes = [0u8; 4];
            match reader.read_exact(&mut length_bytes) {
                Ok(()) => (),
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(_) => {
                    corrupted = true;
                    break;
                }
            }

            let length = u32::from_le_bytes(length_bytes) as usize;

            // Prevent OOM from corrupted length prefix (max 16 MB)
            if length > 16 * 1024 * 1024 {
                corrupted = true;
                break;
            }

            // Read entry data
            let mut entry_data = vec![0u8; length];
            if reader.read_exact(&mut entry_data).is_err() {
                corrupted = true;
                break;
            }

            // Deserialize entry
            let entry = match JournalEntry::decode(&entry_data) {
                // ubs:ignore - internal binary decode, not JWT
                Ok(entry) => entry,
                Err(_) => {
                    corrupted = true;
                    break;
                }
            };

            // Validate checksum
            if !entry.validate_checksum() {
                corrupted = true;
                break;
            }

            entries.push(entry);
        }

        Outcome::Ok((entries, corrupted))
    }

    fn read_all_entries_from_disk(&self) -> Outcome<Vec<JournalEntry>, JournalError> {
        let mut all_entries = Vec::new();

        // Read from all generations
        for generation_num in 0..=self.generation {
            let file_path = journal_file_path(&self.config.base_dir, generation_num);
            if file_path.exists() {
                let (entries, _corrupted) = match self.read_entries_from_file(&file_path) {
                    Outcome::Ok(res) => res,
                    Outcome::Err(e) => return Outcome::Err(e),
                    Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
                    Outcome::Panicked(payload) => return Outcome::Panicked(payload),
                };
                all_entries.extend(entries);
            }
        }

        all_entries.sort_by_key(|e| e.sequence);
        Outcome::Ok(all_entries)
    }
}

fn flush_writer_buffer(writer: &mut BufWriter<File>) -> Result<(), JournalError> {
    writer
        .flush()
        .map_err(|err| JournalError::WriteFailure(err.to_string()))
}

fn sync_writer_data(writer: &mut BufWriter<File>) -> Result<(), JournalError> {
    // BufWriter bytes must reach the file descriptor before the durability
    // barrier. Calling sync_data before flush would fsync the old file state.
    writer
        .flush()
        .map_err(|err| JournalError::SyncFailure(err.to_string()))?;
    writer
        .get_ref()
        .sync_data()
        .map_err(|err| JournalError::SyncFailure(err.to_string()))
}

#[cfg(unix)]
fn sync_journal_directory(path: &Path) -> Result<(), JournalError> {
    let dir = File::open(path).map_err(|err| JournalError::SyncFailure(err.to_string()))?;
    dir.sync_all()
        .map_err(|err| JournalError::SyncFailure(err.to_string()))
}

#[cfg(not(unix))]
fn sync_journal_directory(_path: &Path) -> Result<(), JournalError> {
    Ok(())
}

/// Journal operation errors
#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    #[error("Directory creation failed: {0}")]
    DirectoryCreation(String),

    #[error("File open failed: {0}")]
    FileOpen(String),

    #[error("Write failure: {0}")]
    WriteFailure(String),

    #[error("Read failure: {0}")]
    ReadFailure(String),

    #[error("Sync failure: {0}")]
    SyncFailure(String),

    #[error("Serialization failed: {0}")]
    Serialization(String),

    #[error("Deserialization failed: {0}")]
    Deserialization(String),

    #[error("Checksum mismatch for entry {0}")]
    ChecksumMismatch(u64),

    #[error("Directory read failed: {0}")]
    DirectoryRead(String),

    #[error("Compaction failed: {0}")]
    CompactionFailed(String),
}

/// Journal statistics
#[derive(Debug, Clone)]
pub struct JournalStats {
    pub generation: u64,
    pub sequence: u64,
    pub current_file_size: u64,
    pub recent_entries_count: usize,
    pub total_entries: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_object_id(name: &[u8]) -> ObjectId {
        ObjectId::content(ContentId::from_bytes(name))
    }

    fn test_root(seed: u8) -> MerkleRoot {
        let mut hash = [0; 32];
        hash[0] = seed;
        MerkleRoot::new(hash)
    }

    fn test_auth_key() -> AuthKey {
        AuthKey::from_seed(42)
    }

    fn unsigned_tag() -> AuthenticationTag {
        AuthenticationTag::zero()
    }

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        let unique = SystemTime::now() // ubs:ignore - timestamp used for test uniqueness, not crypto
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!("{}_{}_{}", prefix, std::process::id(), unique))
    }

    #[test]
    fn journal_file_name_contract_matches_generation_parser() {
        assert_eq!(journal_file_name(0), "journal_gen_000000.dat");
        assert_eq!(journal_file_name(42), "journal_gen_000042.dat");
        assert_eq!(parse_journal_generation(&journal_file_name(42)), Some(42));
        assert_eq!(parse_journal_generation("journal_42.dat"), None);
        assert_eq!(parse_journal_generation("journal_gen_000042.tmp"), None);
    }

    #[test]
    fn checked_u32_len_rejects_oversized_field_without_panic() {
        let err = checked_u32_len(u32::MAX as usize + 1, "source_chunks")
            .expect_err("oversized fields must become serialization errors");
        assert!(matches!(err, JournalError::Serialization(_)));
        assert!(err.to_string().contains("source_chunks"));
    }

    #[test]
    fn test_journal_entry_creation() {
        let record = JournalRecord::Offer {
            transfer_id: "test_transfer".to_string(),
            object_id: test_object_id(b"test_object"),
            manifest_root: test_root(1),
            total_size: 1024,
            timestamp: 1234567890,
            auth_tag: unsigned_tag(),
        }
        .with_signature(&test_auth_key());

        let entry = JournalEntry::new(0, record);
        assert_eq!(entry.sequence, 0);
        assert!(entry.validate_checksum());
    }

    #[test]
    fn test_journal_append() {
        let temp_dir = std::env::temp_dir().join("test_journal");
        let config = JournalConfig {
            base_dir: temp_dir.clone(),
            ..Default::default()
        };

        let mut journal = AppendJournal::new(config, test_auth_key()).unwrap();

        let record = JournalRecord::Accept {
            transfer_id: "test_transfer".to_string(),
            peer_id: "peer123".to_string(),
            timestamp: 1234567890,
            auth_tag: unsigned_tag(),
        };

        let sequence = journal.append(record).unwrap();
        assert_eq!(sequence, 0);

        let stats = journal.get_stats();
        assert_eq!(stats.sequence, 1);
        assert_eq!(stats.recent_entries_count, 1);

        // Cleanup
        std::fs::remove_dir_all(&temp_dir).ok();
    }

    #[test]
    fn force_sync_append_is_recoverable_before_explicit_flush_or_drop() {
        let unique = SystemTime::now() // ubs:ignore - timestamp used for test uniqueness, not crypto
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let temp_dir = std::env::temp_dir().join(format!(
            "test_journal_force_sync_{}_{}",
            std::process::id(),
            unique
        ));
        let config = JournalConfig {
            base_dir: temp_dir.clone(),
            force_sync: true,
            ..Default::default()
        };

        let mut journal = AppendJournal::new(config.clone(), test_auth_key()).unwrap();
        let sequence = journal
            .append(JournalRecord::Accept {
                transfer_id: "durable_transfer".to_string(),
                peer_id: "peer123".to_string(),
                timestamp: 1234567890,
                auth_tag: unsigned_tag(),
            })
            .unwrap();

        assert_eq!(sequence, 0);
        assert_eq!(journal.get_stats().sequence, 1);

        let recovered = AppendJournal::new(config, test_auth_key()).unwrap();
        let recovered_stats = recovered.get_stats();
        assert_eq!(recovered_stats.sequence, 1);
        assert_eq!(recovered_stats.recent_entries_count, 1);

        std::fs::remove_dir_all(&temp_dir).ok();
    }

    #[test]
    fn non_force_sync_append_is_recoverable_before_explicit_flush_or_drop() {
        let temp_dir = unique_temp_dir("test_journal_non_force_sync");
        let config = JournalConfig {
            base_dir: temp_dir,
            force_sync: false,
            ..Default::default()
        };

        let mut journal = AppendJournal::new(config.clone(), test_auth_key()).unwrap();
        let sequence = journal
            .append(JournalRecord::Accept {
                transfer_id: "buffered_transfer".to_string(),
                peer_id: "peer123".to_string(),
                timestamp: 1234567890,
                auth_tag: unsigned_tag(),
            })
            .unwrap();

        assert_eq!(sequence, 0);
        assert_eq!(journal.get_stats().sequence, 1);

        let recovered = AppendJournal::new(config, test_auth_key()).unwrap();
        let recovered_stats = recovered.get_stats();
        assert_eq!(recovered_stats.sequence, 1);
        assert_eq!(recovered_stats.recent_entries_count, 1);
    }

    #[test]
    fn test_journal_recovery() {
        let unique = SystemTime::now() // ubs:ignore - timestamp used for test uniqueness, not crypto
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let temp_dir = std::env::temp_dir().join(format!(
            "test_journal_recovery_{}_{}",
            std::process::id(),
            unique
        ));
        let config = JournalConfig {
            base_dir: temp_dir.clone(),
            ..Default::default()
        };

        // Create and populate journal
        {
            let mut journal = AppendJournal::new(config.clone(), test_auth_key()).unwrap();

            journal
                .append(JournalRecord::Offer {
                    transfer_id: "test1".to_string(),
                    object_id: test_object_id(b"obj1"),
                    manifest_root: test_root(1),
                    total_size: 1024,
                    timestamp: 1000,
                    auth_tag: unsigned_tag(),
                })
                .unwrap();

            journal
                .append(JournalRecord::Accept {
                    transfer_id: "test1".to_string(),
                    peer_id: "peer1".to_string(),
                    timestamp: 1001,
                    auth_tag: unsigned_tag(),
                })
                .unwrap();

            journal.flush().unwrap();
        }

        // Recover and verify
        {
            let journal = AppendJournal::new(config, test_auth_key()).unwrap();
            let stats = journal.get_stats();
            assert_eq!(stats.sequence, 2);
            assert_eq!(stats.recent_entries_count, 2);
        }

        // Cleanup
        std::fs::remove_dir_all(&temp_dir).ok();
    }

    #[test]
    fn test_transfer_entries() {
        let temp_dir = std::env::temp_dir().join("test_transfer_entries");
        let config = JournalConfig {
            base_dir: temp_dir.clone(),
            ..Default::default()
        };

        let mut journal = AppendJournal::new(config, test_auth_key()).unwrap();

        // Add entries for different transfers
        journal
            .append(JournalRecord::Offer {
                transfer_id: "transfer_a".to_string(),
                object_id: test_object_id(b"obj_a"),
                manifest_root: test_root(1),
                total_size: 1024,
                timestamp: 1000,
                auth_tag: unsigned_tag(),
            })
            .unwrap();

        journal
            .append(JournalRecord::Offer {
                transfer_id: "transfer_b".to_string(),
                object_id: test_object_id(b"obj_b"),
                manifest_root: test_root(4),
                total_size: 2048,
                timestamp: 1001,
                auth_tag: unsigned_tag(),
            })
            .unwrap();

        journal
            .append(JournalRecord::Accept {
                transfer_id: "transfer_a".to_string(),
                peer_id: "peer1".to_string(),
                timestamp: 1002,
                auth_tag: unsigned_tag(),
            })
            .unwrap();

        // Get entries for specific transfer
        let transfer_a_entries = journal.get_transfer_entries("transfer_a").unwrap();
        assert_eq!(transfer_a_entries.len(), 2);

        let transfer_b_entries = journal.get_transfer_entries("transfer_b").unwrap();
        assert_eq!(transfer_b_entries.len(), 1);

        // Cleanup
        std::fs::remove_dir_all(&temp_dir).ok();
    }

    #[test]
    fn transfer_index_returns_entries_outside_recent_cache() {
        let unique = SystemTime::now() // ubs:ignore - timestamp used for test uniqueness, not crypto
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let temp_dir = std::env::temp_dir().join(format!(
            "test_transfer_index_{}_{}",
            std::process::id(),
            unique
        ));
        let config = JournalConfig {
            base_dir: temp_dir,
            recent_entries_limit: 1,
            ..Default::default()
        };

        let mut journal = AppendJournal::new(config.clone(), test_auth_key()).unwrap();

        for (transfer_id, timestamp) in [
            ("transfer_a", 1000),
            ("transfer_b", 1001),
            ("transfer_a", 1002),
        ] {
            journal
                .append(JournalRecord::Accept {
                    transfer_id: transfer_id.to_string(),
                    peer_id: "peer1".to_string(),
                    timestamp,
                    auth_tag: unsigned_tag(),
                })
                .unwrap();
        }

        assert_eq!(journal.recent_entries.len(), 1);
        let transfer_a_entries = journal.get_transfer_entries("transfer_a").unwrap();
        assert_eq!(
            transfer_a_entries
                .iter()
                .map(|entry| entry.sequence)
                .collect::<Vec<_>>(),
            vec![0, 2]
        );

        journal.flush().unwrap();
        let recovered = AppendJournal::new(config, test_auth_key()).unwrap();
        assert_eq!(recovered.recent_entries.len(), 1);
        let recovered_transfer_a_entries = recovered.get_transfer_entries("transfer_a").unwrap();
        assert_eq!(
            recovered_transfer_a_entries
                .iter()
                .map(|entry| entry.sequence)
                .collect::<Vec<_>>(),
            vec![0, 2]
        );
    }

    #[test]
    fn resume_summary_reconstructs_durable_chunks_after_recovery() {
        let temp_dir = unique_temp_dir("test_resume_summary_recovery");
        let key = test_auth_key();
        let config = JournalConfig {
            base_dir: temp_dir,
            ..Default::default()
        };

        {
            let mut journal = AppendJournal::new(config.clone(), key.clone()).unwrap();
            journal
                .append(JournalRecord::Offer {
                    transfer_id: "resume_a".to_string(),
                    object_id: test_object_id(b"resume_a"),
                    manifest_root: test_root(7),
                    total_size: 4096,
                    timestamp: 1000,
                    auth_tag: unsigned_tag(),
                })
                .unwrap();

            for (chunk_offset, chunk_size, hash_seed, timestamp) in
                [(0, 512, 1, 1001), (512, 512, 2, 1003), (2048, 512, 3, 1005)]
            {
                journal
                    .append(JournalRecord::ChunkVerified {
                        transfer_id: "resume_a".to_string(),
                        chunk_offset,
                        chunk_size,
                        verified_hash: [hash_seed; 32],
                        timestamp,
                        auth_tag: unsigned_tag(),
                    })
                    .unwrap();
                journal
                    .append(JournalRecord::ChunkWritten {
                        transfer_id: "resume_a".to_string(),
                        chunk_offset,
                        chunk_size,
                        file_path: format!("stage/{chunk_offset}"),
                        timestamp: timestamp + 1,
                        auth_tag: unsigned_tag(),
                    })
                    .unwrap();
            }

            journal
                .append(JournalRecord::ChunkVerified {
                    transfer_id: "resume_a".to_string(),
                    chunk_offset: 3072,
                    chunk_size: 512,
                    verified_hash: [4; 32],
                    timestamp: 1007,
                    auth_tag: unsigned_tag(),
                })
                .unwrap();
            journal.flush().unwrap();
        }

        let recovered = AppendJournal::new(config, key).unwrap();
        let summary = recovered.get_resume_summary("resume_a").unwrap();

        assert!(summary.is_resumable());
        assert_eq!(summary.status, TransferResumeStatus::Resumable);
        assert_eq!(summary.total_size, Some(4096));
        assert_eq!(summary.durable_bytes, 1536);
        assert_eq!(summary.contiguous_prefix_bytes, 1024);
        assert_eq!(
            summary
                .durable_chunks
                .iter()
                .map(|chunk| (chunk.chunk_offset, chunk.chunk_size, chunk.chunk_hash[0]))
                .collect::<Vec<_>>(),
            vec![(0, 512, 1), (512, 512, 2), (2048, 512, 3)]
        );
        assert_eq!(summary.last_sequence, Some(7));
    }

    #[test]
    fn resume_summary_fail_closes_for_terminal_states() {
        let temp_dir = unique_temp_dir("test_resume_summary_terminal");
        let mut journal = AppendJournal::new(
            JournalConfig {
                base_dir: temp_dir,
                ..Default::default()
            },
            test_auth_key(),
        )
        .unwrap();

        for transfer_id in ["cancelled", "rolled_back"] {
            journal
                .append(JournalRecord::ChunkVerified {
                    transfer_id: transfer_id.to_string(),
                    chunk_offset: 0,
                    chunk_size: 128,
                    verified_hash: [9; 32],
                    timestamp: 2000,
                    auth_tag: unsigned_tag(),
                })
                .unwrap();
            journal
                .append(JournalRecord::ChunkWritten {
                    transfer_id: transfer_id.to_string(),
                    chunk_offset: 0,
                    chunk_size: 128,
                    file_path: "stage/0".to_string(),
                    timestamp: 2001,
                    auth_tag: unsigned_tag(),
                })
                .unwrap();
        }
        journal
            .append(JournalRecord::Cancellation {
                transfer_id: "cancelled".to_string(),
                reason: "operator stop".to_string(),
                timestamp: 2002,
                auth_tag: unsigned_tag(),
            })
            .unwrap();
        journal
            .append(JournalRecord::Rollback {
                transfer_id: "rolled_back".to_string(),
                rollback_reason: "hash mismatch".to_string(),
                checkpoint_sequence: 1,
                timestamp: 2003,
                auth_tag: unsigned_tag(),
            })
            .unwrap();

        let cancelled = journal.get_resume_summary("cancelled").unwrap();
        assert_eq!(
            cancelled.status,
            TransferResumeStatus::Cancelled {
                reason: "operator stop".to_string()
            }
        );
        assert_eq!(cancelled.durable_chunks, Vec::new());
        assert_eq!(cancelled.contiguous_prefix_bytes, 0);

        let rolled_back = journal.get_resume_summary("rolled_back").unwrap();
        assert_eq!(
            rolled_back.status,
            TransferResumeStatus::RolledBack {
                reason: "hash mismatch".to_string(),
                checkpoint_sequence: 1,
            }
        );
        assert_eq!(rolled_back.durable_bytes, 0);
        assert!(!rolled_back.is_resumable());
    }

    #[test]
    fn resume_summary_rejects_overlapping_durable_chunks() {
        let temp_dir = unique_temp_dir("test_resume_summary_overlap");
        let mut journal = AppendJournal::new(
            JournalConfig {
                base_dir: temp_dir,
                ..Default::default()
            },
            test_auth_key(),
        )
        .unwrap();

        journal
            .append(JournalRecord::Offer {
                transfer_id: "overlap".to_string(),
                object_id: test_object_id(b"overlap"),
                manifest_root: test_root(8),
                total_size: 128,
                timestamp: 3000,
                auth_tag: unsigned_tag(),
            })
            .unwrap();

        for (chunk_offset, hash_seed) in [(0, 1), (8, 2)] {
            journal
                .append(JournalRecord::ChunkVerified {
                    transfer_id: "overlap".to_string(),
                    chunk_offset,
                    chunk_size: 16,
                    verified_hash: [hash_seed; 32],
                    timestamp: 3001 + chunk_offset,
                    auth_tag: unsigned_tag(),
                })
                .unwrap();
            journal
                .append(JournalRecord::ChunkWritten {
                    transfer_id: "overlap".to_string(),
                    chunk_offset,
                    chunk_size: 16,
                    file_path: format!("stage/{chunk_offset}"),
                    timestamp: 3002 + chunk_offset,
                    auth_tag: unsigned_tag(),
                })
                .unwrap();
        }

        match journal.get_resume_summary("overlap") {
            Outcome::Err(err) => {
                assert!(matches!(err, JournalError::Deserialization(_)));
                assert!(err.to_string().contains("overlap"));
            }
            other => panic!("expected overlap to fail closed, got {other:?}"),
        }
    }

    #[test]
    fn resume_summary_rejects_conflicting_offer_total_size() {
        let temp_dir = unique_temp_dir("test_resume_summary_offer_conflict");
        let mut journal = AppendJournal::new(
            JournalConfig {
                base_dir: temp_dir,
                ..Default::default()
            },
            test_auth_key(),
        )
        .unwrap();

        for (total_size, timestamp) in [(1024, 4000), (2048, 4001)] {
            journal
                .append(JournalRecord::Offer {
                    transfer_id: "offer_conflict".to_string(),
                    object_id: test_object_id(b"offer_conflict"),
                    manifest_root: test_root(9),
                    total_size,
                    timestamp,
                    auth_tag: unsigned_tag(),
                })
                .unwrap();
        }

        match journal.get_resume_summary("offer_conflict") {
            Outcome::Err(err) => {
                assert!(matches!(&err, JournalError::Deserialization(_)));
                assert!(err.to_string().contains("total_size conflict"));
            }
            other => panic!("expected conflicting offer sizes to fail closed, got {other:?}"),
        }
    }

    #[test]
    fn resume_summary_rejects_conflicting_verified_chunk_hash() {
        let temp_dir = unique_temp_dir("test_resume_summary_hash_conflict");
        let mut journal = AppendJournal::new(
            JournalConfig {
                base_dir: temp_dir,
                ..Default::default()
            },
            test_auth_key(),
        )
        .unwrap();

        journal
            .append(JournalRecord::Offer {
                transfer_id: "hash_conflict".to_string(),
                object_id: test_object_id(b"hash_conflict"),
                manifest_root: test_root(10),
                total_size: 512,
                timestamp: 5000,
                auth_tag: unsigned_tag(),
            })
            .unwrap();
        journal
            .append(JournalRecord::ChunkVerified {
                transfer_id: "hash_conflict".to_string(),
                chunk_offset: 0,
                chunk_size: 128,
                verified_hash: [1; 32],
                timestamp: 5001,
                auth_tag: unsigned_tag(),
            })
            .unwrap();
        journal
            .append(JournalRecord::ChunkWritten {
                transfer_id: "hash_conflict".to_string(),
                chunk_offset: 0,
                chunk_size: 128,
                file_path: "stage/0".to_string(),
                timestamp: 5002,
                auth_tag: unsigned_tag(),
            })
            .unwrap();
        journal
            .append(JournalRecord::ChunkVerified {
                transfer_id: "hash_conflict".to_string(),
                chunk_offset: 0,
                chunk_size: 128,
                verified_hash: [2; 32],
                timestamp: 5003,
                auth_tag: unsigned_tag(),
            })
            .unwrap();

        match journal.get_resume_summary("hash_conflict") {
            Outcome::Err(err) => {
                assert!(matches!(&err, JournalError::Deserialization(_)));
                assert!(err.to_string().contains("verified hash conflict"));
            }
            other => panic!("expected conflicting chunk hashes to fail closed, got {other:?}"),
        }
    }

    #[test]
    fn compaction_boundary_is_signed_and_verifiable() {
        let temp_dir = unique_temp_dir("test_compaction_boundary");
        let key = test_auth_key();
        let config = JournalConfig {
            base_dir: temp_dir.clone(),
            max_journal_size: u64::MAX,
            ..Default::default()
        };

        let mut journal = AppendJournal::new(config.clone(), key.clone()).unwrap();
        journal
            .append(JournalRecord::Accept {
                transfer_id: "transfer_a".to_string(),
                peer_id: "peer1".to_string(),
                timestamp: 1000,
                auth_tag: unsigned_tag(),
            })
            .unwrap();

        journal.compact().unwrap();
        let boundary = journal
            .recent_entries
            .iter()
            .find(|entry| matches!(entry.record, JournalRecord::CompactionBoundary { .. }))
            .expect("compaction writes boundary entry");

        assert!(!boundary.record.auth_tag().is_zero());
        assert!(boundary.record.verify_signature(&key));
        assert_eq!(journal.get_stats().generation, 1);
        assert!(
            journal_file_path(&temp_dir, 1).exists(),
            "compaction must create the next generation before reporting success"
        );

        let recovered = AppendJournal::new(config, test_auth_key()).unwrap();
        let recovered_stats = recovered.get_stats();
        assert_eq!(recovered_stats.generation, 1);
        assert_eq!(recovered_stats.sequence, 2);
    }
}
