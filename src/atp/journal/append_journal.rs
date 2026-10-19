//! Append-Only Journal for Crash-Safe Transfer Progress Tracking

use crate::atp::manifest::MerkleRoot;
use crate::atp::object::{ContentId, ManifestId, ObjectId};
use crate::cx::Cx;
use crate::security::{AuthKey, AuthenticationTag};
use crate::types::outcome::Outcome;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

mod storage;
mod compaction;

// The writer must not acknowledge a frame that its own recovery reader refuses.
const MAX_JOURNAL_FRAME_BYTES: usize = 16 * 1024 * 1024;
// A fully read frame with unconsumed bytes is ambiguous, not a torn tail.
const TRAILING_JOURNAL_BYTES: &str = "trailing bytes in journal entry";

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
        let record = match tag {
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
                // Bound allocation by bytes actually present, not the untrusted
                // count in a potentially corrupt recovery record.
                if source_count > (cursor.data.len() - cursor.offset) / 8 {
                    return Err(JournalError::Deserialization(
                        "repair source count exceeds remaining payload".to_string(),
                    ));
                }
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
        }?;
        cursor.finish()?;
        Ok(record)
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
                TRAILING_JOURNAL_BYTES.to_owned(),
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
    /// New journal bytes before compaction, excluding carried-forward history.
    pub max_journal_size: u64,
    /// Maximum number of recent entries kept in memory.
    pub recent_entries_limit: usize,
    /// Whether to fsync after every write
    pub force_sync: bool,
    /// Buffer size for writes
    pub write_buffer_size: usize,
    /// Previous generations to retain in addition to the current snapshot.
    /// Damaged generations are retained as evidence even beyond this window.
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
    /// A failed/abandoned storage mutation requires disk recovery, not retry.
    storage_failed: bool,
    /// Bytes already carried forward, not fresh growth that triggers rotation.
    generation_base_bytes: u64,
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
            storage_failed: false,
            generation_base_bytes: 0,
        };

        // Try to recover from existing journal
        match journal.recover_from_disk() {
            Outcome::Ok(()) => {}
            Outcome::Err(error) => return Outcome::Err(error),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        }

        Outcome::Ok(journal)
    }

    /// Append a new record to the journal.
    ///
    /// A write, flush, or synchronization failure can follow partial or complete
    /// filesystem effects. This instance then refuses mutation and resumable
    /// summaries until it is dropped and reopened from disk. A failed automatic
    /// compaction may likewise follow an already persisted record; an error is
    /// not evidence that the record is absent. Oversized frames refuse before I/O.
    pub fn append(&mut self, record: JournalRecord) -> Outcome<u64, JournalError> {
        self.append_with_storage(record, storage::append_frame)
    }

    /// Flush any pending writes
    pub fn flush(&mut self) -> Outcome<(), JournalError> {
        self.flush_with_storage(sync_writer_data)
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
        if let Err(error) = self.require_storage_ready() {
            return Outcome::Err(error);
        }
        let entries = match self.get_transfer_entries(transfer_id) {
            Outcome::Ok(entries) => entries,
            Outcome::Err(err) => return Outcome::Err(err),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        };

        // CRC detects corruption but does not authenticate durable progress.
        // Reject the whole summary rather than deriving progress from a subset.
        if entries
            .iter()
            .any(|entry| !entry.record.verify_signature(&self.auth_key))
        {
            return Outcome::Err(JournalError::Deserialization(
                "resume journal record authentication failed".to_string(),
            ));
        }

        match Self::build_resume_summary(transfer_id, &entries) {
            Ok(summary) => Outcome::Ok(summary),
            Err(err) => Outcome::Err(err),
        }
    }

    /// Carry all retained history into a synchronized generation before cleanup.
    /// Original record signatures and sequence numbers are preserved. This
    /// consolidates generations, not semantic history: cancelled and completed
    /// transfers remain known after reopen. No physical payload is copied here.
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

        Outcome::Ok(current_size.saturating_sub(self.generation_base_bytes)
            >= self.config.max_journal_size)
    }

    fn trigger_compaction(&mut self) -> Outcome<(), JournalError> {
        self.compact_with_storage(
            compaction::write_entry,
            File::sync_all,
            sync_journal_directory,
        )
    }

    fn discover_generations(&self) -> Result<Vec<u64>, JournalError> {
        let entries = std::fs::read_dir(&self.config.base_dir)
            .map_err(|error| JournalError::DirectoryRead(error.to_string()))?;
        let mut generations = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|error| JournalError::DirectoryRead(error.to_string()))?;
            let file_name = entry.file_name();
            let file_name_str = file_name.to_string_lossy();

            if let Some(generation_num) = parse_journal_generation(&file_name_str) {
                generations.push(generation_num);
            }
        }
        generations.sort_unstable();
        generations.dedup();
        Ok(generations)
    }

    fn recover_from_disk(&mut self) -> Outcome<(), JournalError> {
        self.recover_storage_history()
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
            // EOF before a prefix is clean. EOF inside its four bytes is a
            // torn record: recovery must rotate rather than append behind it.
            let mut length_bytes = [0u8; 4];
            match reader.read_exact(&mut length_bytes[..1]) {
                Ok(()) => (),
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(error) => return Outcome::Err(JournalError::ReadFailure(error.to_string())),
            }
            match reader.read_exact(&mut length_bytes[1..]) {
                Ok(()) => (),
                Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
                    corrupted = true;
                    break;
                }
                Err(error) => return Outcome::Err(JournalError::ReadFailure(error.to_string())),
            }

            let length = u32::from_le_bytes(length_bytes) as usize;

            // Prevent OOM from corrupted length prefix (max 16 MB)
            if length > MAX_JOURNAL_FRAME_BYTES {
                corrupted = true;
                break;
            }

            // Read entry data
            let mut entry_data = vec![0u8; length];
            match reader.read_exact(&mut entry_data) {
                Ok(()) => (),
                Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
                    corrupted = true;
                    break;
                }
                Err(error) => return Outcome::Err(JournalError::ReadFailure(error.to_string())),
            }

            // A damaged final frame is recoverable, but silently dropping
            // following bytes would hide potentially committed records.
            let decoded = JournalEntry::decode(&entry_data).and_then(|entry| {
                if entry.validate_checksum() {
                    Ok(entry)
                } else {
                    Err(JournalError::ChecksumMismatch(entry.sequence))
                }
            });
            let entry = match decoded {
                // ubs:ignore - internal binary decode, not JWT
                Ok(entry) => entry,
                Err(error) => {
                    // These bytes were read as a complete frame, and the inner
                    // or outer decoder found an unexplained suffix. Treating it
                    // as a recoverable tail could hide a terminal record. Keep
                    // the whole log for inspection, even at physical EOF.
                    if matches!(&error, JournalError::Deserialization(message)
                        if message == TRAILING_JOURNAL_BYTES)
                    {
                        return Outcome::Err(error);
                    }
                    match reader.fill_buf() {
                        Ok(remaining) if !remaining.is_empty() => return Outcome::Err(error),
                        Ok(_) => {}
                        Err(error) => {
                            return Outcome::Err(JournalError::ReadFailure(error.to_string()));
                        }
                    }
                    corrupted = true;
                    break;
                }
            };

            entries.push(entry);
        }

        Outcome::Ok((entries, corrupted))
    }

    fn read_all_entries_from_disk(&self) -> Outcome<Vec<JournalEntry>, JournalError> {
        self.read_storage_history(Some(self.generation))
            .map(|history| history.entries.into_values().collect())
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
#[path = "append_journal_inline_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "append_journal/strict_decode_tests.rs"]
mod strict_decode_tests;
