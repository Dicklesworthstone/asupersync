//! Core types for Byzantine consensus protocols.

use crate::types::{Outcome, Time};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// Unique identifier for a replica in the consensus group.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ReplicaId(pub String);

impl fmt::Display for ReplicaId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "replica:{}", self.0)
    }
}

impl ReplicaId {
    pub fn new(id: String) -> Self {
        Self(id)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// View number in PBFT protocol.
///
/// Views are used for leader election and view changes.
/// The primary for view v is replica v mod n.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ViewNumber(pub u64);

impl ViewNumber {
    pub fn new(v: u64) -> Self {
        Self(v)
    }

    pub fn primary(&self, replica_count: usize) -> usize {
        (self.0 as usize) % replica_count
    }

    pub fn next(self) -> Self {
        Self(self.0 + 1)
    }
}

impl fmt::Display for ViewNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "view:{}", self.0)
    }
}

/// Sequence number for ordering requests within a view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SequenceNumber(pub u64);

impl SequenceNumber {
    pub fn new(n: u64) -> Self {
        Self(n)
    }

    pub fn next(self) -> Self {
        Self(self.0 + 1)
    }
}

impl fmt::Display for SequenceNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "seq:{}", self.0)
    }
}

/// Cryptographic digest of a message.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MessageDigest(pub [u8; 32]);

impl MessageDigest {
    /// Compute digest of serializable data.
    pub fn of<T: Serialize>(data: &T) -> crate::error::Result<Self> {
        use sha2::{Digest, Sha256};

        let serialized = serde_json::to_vec(data)
            .map_err(|_| crate::error::Error::new(crate::error::ErrorKind::InvalidInput))?;

        let mut hasher = Sha256::new();
        hasher.update(&serialized);
        let result = hasher.finalize();
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&result[..]);
        Ok(Self(digest))
    }

    /// Create digest from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get the raw bytes of the digest.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for MessageDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "digest:{}", hex::encode(&self.0[..8]))
    }
}

/// Phase in the PBFT consensus protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PhaseKind {
    /// Pre-prepare phase: primary proposes ordering.
    PrePrepare,
    /// Prepare phase: replicas agree on ordering.
    Prepare,
    /// Commit phase: replicas commit to execution.
    Commit,
    /// View change phase: elect new primary.
    ViewChange,
    /// New view phase: new primary establishes view.
    NewView,
}

impl fmt::Display for PhaseKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PhaseKind::PrePrepare => write!(f, "pre-prepare"),
            PhaseKind::Prepare => write!(f, "prepare"),
            PhaseKind::Commit => write!(f, "commit"),
            PhaseKind::ViewChange => write!(f, "view-change"),
            PhaseKind::NewView => write!(f, "new-view"),
        }
    }
}

/// A client request to be ordered and executed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusRequest {
    /// Unique client identifier.
    pub client_id: String,
    /// Monotonic timestamp from client.
    pub timestamp: Time,
    /// The actual request payload.
    pub operation: Vec<u8>,
}

impl ConsensusRequest {
    pub fn new(client_id: String, timestamp: Time, operation: Vec<u8>) -> Self {
        Self {
            client_id,
            timestamp,
            operation,
        }
    }
}

/// Response from consensus execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusResponse {
    /// View number when executed.
    pub view: ViewNumber,
    /// Sequence number assigned.
    pub sequence: SequenceNumber,
    /// Execution result.
    pub result: Outcome<Vec<u8>, String>,
    /// Replica that executed.
    pub replica_id: ReplicaId,
    /// Execution timestamp.
    pub timestamp: Time,
}

/// Batch of requests for consensus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusBatch {
    /// Requests in this batch.
    pub requests: Vec<ConsensusRequest>,
    /// Batch creation timestamp.
    pub timestamp: Time,
}

impl ConsensusBatch {
    pub fn new(requests: Vec<ConsensusRequest>) -> Self {
        Self {
            requests,
            timestamp: Time::from_millis(0),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.requests.is_empty()
    }

    pub fn len(&self) -> usize {
        self.requests.len()
    }
}

/// Errors in consensus protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConsensusError {
    /// Not enough replicas for fault tolerance.
    InsufficientReplicas { required: usize, available: usize },
    /// Invalid view number.
    InvalidView {
        expected: ViewNumber,
        received: ViewNumber,
    },
    /// Invalid sequence number.
    InvalidSequence {
        expected: SequenceNumber,
        received: SequenceNumber,
    },
    /// Message authentication failed.
    AuthenticationFailure {
        replica_id: ReplicaId,
        reason: String,
    },
    /// Timeout waiting for consensus.
    Timeout { phase: PhaseKind, duration_ms: u64 },
    /// Byzantine behavior detected.
    ByzantineDetected {
        replica_id: ReplicaId,
        evidence: String,
    },
    /// View change in progress.
    ViewChangeInProgress {
        current_view: ViewNumber,
        target_view: ViewNumber,
    },
    /// Replica is not primary for current view.
    NotPrimary {
        replica_id: ReplicaId,
        view: ViewNumber,
        primary: usize,
    },
    /// Generic consensus failure.
    ConsensusFailed { reason: String },
}

impl fmt::Display for ConsensusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConsensusError::InsufficientReplicas {
                required,
                available,
            } => {
                write!(
                    f,
                    "insufficient replicas: need {}, have {}",
                    required, available
                )
            }
            ConsensusError::InvalidView { expected, received } => {
                write!(f, "invalid view: expected {}, got {}", expected, received)
            }
            ConsensusError::InvalidSequence { expected, received } => {
                write!(
                    f,
                    "invalid sequence: expected {}, got {}",
                    expected, received
                )
            }
            ConsensusError::AuthenticationFailure { replica_id, reason } => {
                write!(f, "authentication failed for {}: {}", replica_id, reason)
            }
            ConsensusError::Timeout { phase, duration_ms } => {
                write!(f, "{} phase timeout after {}ms", phase, duration_ms)
            }
            ConsensusError::ByzantineDetected {
                replica_id,
                evidence,
            } => {
                write!(f, "Byzantine behavior from {}: {}", replica_id, evidence)
            }
            ConsensusError::ViewChangeInProgress {
                current_view,
                target_view,
            } => {
                write!(
                    f,
                    "view change in progress: {} -> {}",
                    current_view, target_view
                )
            }
            ConsensusError::NotPrimary {
                replica_id,
                view,
                primary,
            } => {
                write!(
                    f,
                    "{} not primary for {}, primary is replica {}",
                    replica_id, view, primary
                )
            }
            ConsensusError::ConsensusFailed { reason } => {
                write!(f, "consensus failed: {}", reason)
            }
        }
    }
}

impl std::error::Error for ConsensusError {}

/// Certificate proving a message has been validated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageCertificate {
    /// The message digest.
    pub digest: MessageDigest,
    /// Signatures from 2f+1 replicas.
    pub signatures: HashMap<ReplicaId, Vec<u8>>,
    /// View this certificate is valid for.
    pub view: ViewNumber,
}

impl MessageCertificate {
    pub fn new(digest: MessageDigest, view: ViewNumber) -> Self {
        Self {
            digest,
            signatures: HashMap::new(),
            view,
        }
    }

    pub fn add_signature(&mut self, replica_id: ReplicaId, signature: Vec<u8>) {
        self.signatures.insert(replica_id, signature);
    }

    pub fn is_valid(&self, f: usize) -> bool {
        self.signatures.len() > 2 * f
    }
}
