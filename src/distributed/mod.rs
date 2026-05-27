//! Distributed region encoding, symbol distribution, recovery, and consensus.
//!
//! This module implements encoding of distributed region state into
//! RaptorQ symbols, their distribution to replicas, and recovery of
//! region state from collected symbols. It builds on the state model
//! from [`crate::record::distributed_region`] and the symbol types
//! from [`crate::types::symbol`].
//!
//! Additionally provides Byzantine fault tolerant consensus algorithms
//! for distributed coordination with safety guarantees even under
//! malicious replica behavior.
//!
//! # Modules
//!
//! - [`snapshot`]: Serializable region state snapshots
//! - [`encoding`]: RaptorQ encoding pipeline for snapshots
//! - [`assignment`]: Symbol-to-replica assignment strategies
//! - [`consistent_hash`]: Deterministic consistent hash ring
//! - [`distribution`]: Quorum-based symbol distribution
//! - [`recovery`]: Region recovery protocol
//! - [`bridge`]: Local-to-distributed region bridge
//! - [`consensus`]: Byzantine fault tolerant consensus algorithms

pub mod assignment;
pub mod bridge;
pub mod consensus;
pub mod consistent_hash;
pub mod distribution;
pub mod encoding;
pub mod recovery;
pub mod snapshot;

pub use assignment::{AssignmentStrategy, ReplicaAssignment, SymbolAssigner};
pub use bridge::{
    BridgeConfig, CloseResult, ConflictResolution, DistributedToLocal, EffectiveState,
    LocalToDistributed, RegionBridge, RegionMode, SyncMode, SyncResult, SyncState, UpgradeResult,
};
pub use consensus::{
    ConsensusBatch, ConsensusError, ConsensusRequest, ConsensusResponse, MessageDigest, PbftConfig,
    PbftConsensus, PbftNode, PbftState, PhaseKind, ReplicaId, SequenceNumber, ViewNumber,
};
pub use consistent_hash::HashRing;
pub use distribution::{
    DistributionConfig, DistributionMetrics, DistributionResult, ReplicaAck, ReplicaFailure,
    SymbolDistributor,
};
pub use encoding::{EncodedState, EncodingConfig, EncodingError, StateEncoder};
pub use recovery::{
    CollectedSymbol, CollectionConsistency, CollectionMetrics, RecoveryCollector, RecoveryConfig,
    RecoveryDecodingConfig, RecoveryOrchestrator, RecoveryPhase, RecoveryProgress, RecoveryResult,
    RecoveryTrigger, StateDecoder,
};
pub use snapshot::{BudgetSnapshot, RegionSnapshot, SnapshotError, TaskSnapshot, TaskState};

#[cfg(test)]
mod tests;
