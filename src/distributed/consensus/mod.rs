//! Byzantine fault tolerant consensus algorithms.
//!
//! This module provides implementation of Byzantine consensus algorithms
//! for distributed systems requiring safety and liveness guarantees
//! even in the presence of malicious replicas.
//!
//! Currently implements:
//! - PBFT (Practical Byzantine Fault Tolerance)
//!
//! The implementation assumes a partially synchronous network with
//! authentication and provides safety guarantees even with up to f
//! Byzantine faults in a system of 3f+1 replicas.

pub mod pbft;
pub mod types;

pub use pbft::{PbftConsensus, PbftConfig, PbftNode, PbftState};
pub use types::{
    ConsensusRequest, ConsensusResponse, ConsensusBatch, ViewNumber,
    SequenceNumber, ReplicaId, PhaseKind, MessageDigest, ConsensusError,
};

#[cfg(test)]
mod tests;