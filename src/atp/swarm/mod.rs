//! ATP Swarm Protocol - Multi-peer coordination for verified data movement.
//!
//! The swarm protocol enables multiple peers to collaborate on data transfers,
//! improving throughput, reliability, and availability. Key features:
//!
//! - **Rarest-first piece selection**: Efficient distribution across peers
//! - **Quality-aware peer selection**: Path quality and peer reputation
//! - **Incentive mechanisms**: Contribution tracking and reciprocity
//! - **Tamper-resistant coordination**: Cryptographic verification of all data
//!
//! # Design Principles
//!
//! The swarm protocol follows BitTorrent-inspired piece selection with
//! cryptographic verification. All chunks are content-addressed and verified
//! independently, preventing malicious peers from corrupting transfers.
//!
//! # Usage Example
//!
//! ```rust,ignore
//! use asupersync::atp::swarm::{SwarmCoordinator, SwarmConfig};
//!
//! let config = SwarmConfig {
//!     max_peers: 8,
//!     piece_selection_strategy: PieceSelectionStrategy::RarestFirst,
//!     peer_quality_threshold: 0.7,
//! };
//!
//! let mut coordinator = SwarmCoordinator::new(config);
//!
//! // Start transfer with swarm coordination
//! let transfer = coordinator.start_swarm_transfer(
//!     object_id,
//!     available_peers,
//!     piece_map
//! ).await?;
//!
//! // Coordinate piece requests across peers
//! while !transfer.is_complete() {
//!     let assignments = coordinator.assign_pieces(&transfer).await?;
//!     for assignment in assignments {
//!         coordinator.request_piece(assignment.peer, assignment.piece).await?;
//!     }
//! }
//! ```

use crate::atp::mailbox::{PeerId, MailboxTransferId};
use crate::cx::Cx;
use crate::types::Time;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, BTreeSet};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

pub mod coordinator;
pub mod peer_selection;
pub mod piece_tracker;
pub mod quality;
pub mod strategy;

pub use coordinator::SwarmCoordinator;
pub use peer_selection::{PeerSelector, PeerQuality, PeerReputation};
pub use piece_tracker::{PieceTracker, PieceMap, PieceStatus};
pub use quality::{QualityMetrics, PathQuality, PeerScore};
pub use strategy::{PieceSelectionStrategy, SwarmStrategy};

/// Unique identifier for a piece of data in the swarm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PieceId(pub u64);

impl PieceId {
    pub fn new(id: u64) -> Self {
        Self(id)
    }

    pub fn as_u64(self) -> u64 {
        self.0
    }
}

/// Configuration for swarm coordination behavior.
#[derive(Debug, Clone)]
pub struct SwarmConfig {
    /// Maximum number of simultaneous peers
    pub max_peers: usize,

    /// Piece selection strategy
    pub piece_selection_strategy: PieceSelectionStrategy,

    /// Minimum peer quality threshold (0.0 to 1.0)
    pub peer_quality_threshold: f64,

    /// Maximum pieces requested from single peer
    pub max_pieces_per_peer: usize,

    /// Timeout for piece requests
    pub piece_request_timeout: Duration,

    /// Interval for peer quality reassessment
    pub quality_assessment_interval: Duration,

    /// Enable incentive tracking
    pub enable_incentives: bool,

    /// Reciprocity ratio for giving/receiving
    pub reciprocity_ratio: f64,

    /// Maximum swarm transfer time
    pub max_transfer_duration: Duration,
}

impl Default for SwarmConfig {
    fn default() -> Self {
        Self {
            max_peers: 8,
            piece_selection_strategy: PieceSelectionStrategy::RarestFirst,
            peer_quality_threshold: 0.5,
            max_pieces_per_peer: 4,
            piece_request_timeout: Duration::from_secs(30),
            quality_assessment_interval: Duration::from_secs(60),
            enable_incentives: true,
            reciprocity_ratio: 1.2, // Slightly favor contributors
            max_transfer_duration: Duration::from_secs(3600), // 1 hour max
        }
    }
}

/// Information about a peer participating in the swarm.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwarmPeer {
    /// Peer identifier
    pub peer_id: PeerId,

    /// Network endpoint for direct communication
    pub endpoint: SocketAddr,

    /// Pieces available from this peer
    pub available_pieces: BTreeSet<PieceId>,

    /// Current quality metrics
    pub quality: PeerQuality,

    /// Reputation and incentive data
    pub reputation: PeerReputation,

    /// Last successful communication
    pub last_seen: Time,

    /// Currently requested pieces from this peer
    pub pending_requests: BTreeSet<PieceId>,

    /// Peer capabilities and preferences
    pub capabilities: PeerCapabilities,
}

/// Capabilities advertised by a swarm peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerCapabilities {
    /// Maximum concurrent piece uploads
    pub max_concurrent_uploads: usize,

    /// Preferred chunk size for transfers
    pub preferred_chunk_size: usize,

    /// Supported piece selection strategies
    pub supported_strategies: Vec<PieceSelectionStrategy>,

    /// Available bandwidth estimate (bytes/sec)
    pub bandwidth_estimate: Option<u64>,

    /// RaptorQ repair capabilities
    pub supports_repair_symbols: bool,

    /// Incentive participation willingness
    pub participates_in_incentives: bool,
}

impl Default for PeerCapabilities {
    fn default() -> Self {
        Self {
            max_concurrent_uploads: 4,
            preferred_chunk_size: 1024 * 1024, // 1MB
            supported_strategies: vec![PieceSelectionStrategy::RarestFirst, PieceSelectionStrategy::Sequential],
            bandwidth_estimate: None,
            supports_repair_symbols: false,
            participates_in_incentives: true,
        }
    }
}

/// A piece assignment for a specific peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PieceAssignment {
    /// Target peer for the request
    pub peer_id: PeerId,

    /// Piece to request
    pub piece_id: PieceId,

    /// Priority of this assignment (higher = more urgent)
    pub priority: u32,

    /// Expected completion time
    pub estimated_completion: Time,

    /// Retry count for this assignment
    pub retry_count: u32,

    /// Assignment creation time
    pub assigned_at: Time,
}

/// Status of a swarm transfer operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwarmTransferStatus {
    /// Transfer identifier
    pub transfer_id: MailboxTransferId,

    /// Total number of pieces in transfer
    pub total_pieces: u64,

    /// Number of pieces successfully received
    pub completed_pieces: u64,

    /// Number of pieces currently being downloaded
    pub pending_pieces: u64,

    /// Number of pieces still needed
    pub remaining_pieces: u64,

    /// Active peers in the swarm
    pub active_peers: HashMap<PeerId, SwarmPeer>,

    /// Current download rate (bytes/sec)
    pub download_rate: f64,

    /// Current upload rate (bytes/sec)
    pub upload_rate: f64,

    /// Estimated completion time
    pub estimated_completion: Option<Time>,

    /// Transfer quality metrics
    pub quality_metrics: SwarmQualityMetrics,
}

/// Quality metrics for swarm transfer performance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwarmQualityMetrics {
    /// Average peer response time
    pub avg_peer_response_time: Duration,

    /// Piece verification failure rate
    pub verification_failure_rate: f64,

    /// Peer churn rate (peers leaving/joining)
    pub peer_churn_rate: f64,

    /// Redundancy factor (how many peers have each piece)
    pub avg_piece_redundancy: f64,

    /// Incentive balance across peers
    pub incentive_balance_score: f64,

    /// Overall swarm health score (0.0 to 1.0)
    pub health_score: f64,
}

/// Events emitted during swarm operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SwarmEvent {
    /// Peer joined the swarm
    PeerJoined {
        peer_id: PeerId,
        available_pieces: BTreeSet<PieceId>,
        capabilities: PeerCapabilities,
    },

    /// Peer left the swarm
    PeerLeft {
        peer_id: PeerId,
        reason: String,
        contributed_pieces: u64,
    },

    /// Piece request sent to peer
    PieceRequested {
        peer_id: PeerId,
        piece_id: PieceId,
        priority: u32,
    },

    /// Piece received and verified
    PieceReceived {
        peer_id: PeerId,
        piece_id: PieceId,
        verification_status: String,
        download_time: Duration,
    },

    /// Piece verification failed
    PieceVerificationFailed {
        peer_id: PeerId,
        piece_id: PieceId,
        error_details: String,
    },

    /// Peer quality updated
    PeerQualityUpdated {
        peer_id: PeerId,
        old_quality: f64,
        new_quality: f64,
        reason: String,
    },

    /// Swarm strategy adapted
    StrategyAdapted {
        old_strategy: PieceSelectionStrategy,
        new_strategy: PieceSelectionStrategy,
        adaptation_reason: String,
    },

    /// Transfer completed
    TransferCompleted {
        transfer_id: MailboxTransferId,
        duration: Duration,
        total_pieces: u64,
        peer_count: usize,
        avg_quality: f64,
    },

    /// Transfer failed
    TransferFailed {
        transfer_id: MailboxTransferId,
        reason: String,
        completed_pieces: u64,
        total_pieces: u64,
    },
}

/// Errors that can occur during swarm operations.
#[derive(Debug, thiserror::Error)]
pub enum SwarmError {
    /// No suitable peers available for transfer
    #[error("No suitable peers available: {details}")]
    NoPeersAvailable { details: String },

    /// Peer communication failure
    #[error("Peer communication failed: {peer_id}, {error}")]
    PeerCommunicationFailed { peer_id: PeerId, error: String },

    /// Piece verification failure
    #[error("Piece verification failed: {piece_id} from {peer_id}")]
    PieceVerificationFailed { piece_id: PieceId, peer_id: PeerId },

    /// Swarm coordination timeout
    #[error("Swarm coordination timeout after {duration:?}")]
    CoordinationTimeout { duration: Duration },

    /// Invalid piece selection strategy
    #[error("Invalid piece selection strategy: {strategy}")]
    InvalidStrategy { strategy: String },

    /// Peer quality below threshold
    #[error("Peer quality below threshold: {peer_id}, quality {quality}, threshold {threshold}")]
    PeerQualityBelowThreshold {
        peer_id: PeerId,
        quality: f64,
        threshold: f64,
    },

    /// Incentive system error
    #[error("Incentive system error: {details}")]
    IncentiveError { details: String },

    /// Swarm configuration error
    #[error("Invalid swarm configuration: {details}")]
    ConfigurationError { details: String },
}

/// Type alias for swarm operation results.
pub type SwarmResult<T> = Result<T, SwarmError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_piece_id_ordering() {
        let piece1 = PieceId::new(1);
        let piece2 = PieceId::new(2);
        let piece3 = PieceId::new(1);

        assert!(piece1 < piece2);
        assert_eq!(piece1, piece3);
        assert_ne!(piece1, piece2);
    }

    #[test]
    fn test_swarm_config_defaults() {
        let config = SwarmConfig::default();

        assert_eq!(config.max_peers, 8);
        assert_eq!(config.piece_selection_strategy, PieceSelectionStrategy::RarestFirst);
        assert_eq!(config.peer_quality_threshold, 0.5);
        assert!(config.enable_incentives);
    }

    #[test]
    fn test_peer_capabilities_defaults() {
        let capabilities = PeerCapabilities::default();

        assert_eq!(capabilities.max_concurrent_uploads, 4);
        assert_eq!(capabilities.preferred_chunk_size, 1024 * 1024);
        assert!(capabilities.participates_in_incentives);
        assert!(!capabilities.supports_repair_symbols);
    }

    #[test]
    fn test_piece_assignment_serialization() {
        let assignment = PieceAssignment {
            peer_id: PeerId::new("test-peer"),
            piece_id: PieceId::new(42),
            priority: 100,
            estimated_completion: Time::now(),
            retry_count: 0,
            assigned_at: Time::now(),
        };

        let serialized = serde_json::to_string(&assignment).unwrap();
        let deserialized: PieceAssignment = serde_json::from_str(&serialized).unwrap();

        assert_eq!(assignment.piece_id, deserialized.piece_id);
        assert_eq!(assignment.priority, deserialized.priority);
        assert_eq!(assignment.retry_count, deserialized.retry_count);
    }

    #[test]
    fn test_swarm_error_display() {
        let error = SwarmError::PeerQualityBelowThreshold {
            peer_id: PeerId::new("bad-peer"),
            quality: 0.3,
            threshold: 0.5,
        };

        let display = format!("{}", error);
        assert!(display.contains("Peer quality below threshold"));
        assert!(display.contains("bad-peer"));
        assert!(display.contains("0.3"));
        assert!(display.contains("0.5"));
    }

    #[test]
    fn test_swarm_event_serialization() {
        let event = SwarmEvent::PeerJoined {
            peer_id: PeerId::new("new-peer"),
            available_pieces: [PieceId::new(1), PieceId::new(2)].iter().cloned().collect(),
            capabilities: PeerCapabilities::default(),
        };

        let serialized = serde_json::to_string(&event).unwrap();
        let deserialized: SwarmEvent = serde_json::from_str(&serialized).unwrap();

        match (event, deserialized) {
            (SwarmEvent::PeerJoined { available_pieces: p1, .. },
             SwarmEvent::PeerJoined { available_pieces: p2, .. }) => {
                assert_eq!(p1, p2);
            }
            _ => panic!("Event type mismatch after serialization"),
        }
    }
}