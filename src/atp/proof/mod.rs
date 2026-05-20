//! ATP proof bundle schema and verification artifacts.
//!
//! This module defines the complete proof bundle format for ATP transfers,
//! enabling offline verification and replay of transfer operations. Proof
//! bundles capture all metadata necessary to validate that a transfer was
//! completed correctly according to ATP protocol specifications.

pub mod bundle;
pub mod replay;
pub mod serde_types;

pub use bundle::{
    AtpProofBundle, AtpProofBundleBuilder, AtpProofBundleError, AtpProofBundleMetadata,
    ChunkBitmap, PeerIdentityInfo, ProofStrength, RaptorQDecodeMetadata, RepairGroupMetadata,
    TransferJournal, TransferPathSummary,
};
pub use replay::{AtpReplayPointer, ReplayableEvent, ReplayableEventKind};
