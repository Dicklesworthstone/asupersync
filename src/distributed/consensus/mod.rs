//! Experimental Byzantine consensus algorithms.
//!
//! The PBFT normal-case path includes ordered application execution. The
//! opt-in [`authenticated`] adapter signs and verifies replica traffic using
//! an explicitly pinned static membership. Legacy message APIs remain trusted,
//! unsigned boundaries.
//!
//! View changes, stable checkpoints, durable recovery, and log pruning remain
//! unfinished. Authentication alone does not establish Byzantine fault tolerance
//! or liveness under primary failure; see [`pbft`] for the supported boundary.

pub mod authenticated;
pub mod pbft;
pub mod types;

pub use authenticated::{
    AuthenticatedPbftTransport, PbftAuthError, PbftAuthenticator, PbftMembership,
    PbftPacketTransport,
};
pub use pbft::{PbftConfig, PbftConsensus, PbftNode, PbftState};
pub use types::{
    ConsensusBatch, ConsensusError, ConsensusRequest, ConsensusResponse, MessageDigest, PhaseKind,
    ReplicaId, SequenceNumber, ViewNumber,
};

#[cfg(test)]
mod tests;
