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
    ATP_PROOF_DECISION_CONTRACT, ATP_PROOF_FRANKEN_COMPONENT, AtpAuditArtifactRef,
    AtpFrankenProofExport, AtpProofBundle, AtpProofBundleBuilder, AtpProofBundleError,
    AtpProofBundleMetadata, AtpProofValidationStatus, ChunkBitmap, PeerIdentityInfo, ProofStrength,
    RaptorQDecodeMetadata, RepairGroupMetadata, TransferJournal, TransferPathSummary,
};
pub use replay::{AtpReplayPointer, ReplayableEvent, ReplayableEventKind};
