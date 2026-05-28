//! ATP verifier pipeline primitives.
//!
//! The verifier is the fail-closed boundary between bytes that arrived from a
//! peer, relay, cache, or local disk and bytes that may be exposed as committed
//! ATP data. This module is intentionally independent from the sparse writer
//! and append-only journal so callers can validate chunks, object graphs,
//! repair symbols, proof bundles, and finalizer evidence before those lower
//! layers are complete.

use crate::atp::manifest::{GraphCommit, Manifest, ManifestError, MerkleRoot};
use crate::atp::object::{ContentId, Object, ObjectGraph, ObjectGraphError, ObjectId, ObjectKind};
use std::collections::BTreeSet;
use std::fmt;

/// Stable verifier stage names used in logs and error taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VerificationStage {
    /// Chunk content hash verification.
    ChunkHash,
    /// Object content and metadata consistency verification.
    ObjectContent,
    /// Object graph topology and Merkle root verification.
    GraphMerkle,
    /// Manifest consistency verification.
    Manifest,
    /// Graph commit verification.
    Commit,
    /// Repair symbol metadata and digest verification.
    RepairSymbol,
    /// Proof bundle digest verification.
    ProofBundle,
    /// Finalizer and cancellation proof verification.
    Finalizer,
}

impl VerificationStage {
    const REQUIRED_FINAL_PROOF_STAGES: [Self; 7] = [
        Self::ChunkHash,
        Self::ObjectContent,
        Self::GraphMerkle,
        Self::Manifest,
        Self::Commit,
        Self::ProofBundle,
        Self::Finalizer,
    ];

    /// Returns the stable snake-case stage label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ChunkHash => "chunk_hash",
            Self::ObjectContent => "object_content",
            Self::GraphMerkle => "graph_merkle",
            Self::Manifest => "manifest",
            Self::Commit => "commit",
            Self::RepairSymbol => "repair_symbol",
            Self::ProofBundle => "proof_bundle",
            Self::Finalizer => "finalizer",
        }
    }

    const fn code(self) -> u8 {
        match self {
            Self::ChunkHash => 0,
            Self::ObjectContent => 1,
            Self::GraphMerkle => 2,
            Self::Manifest => 3,
            Self::Commit => 4,
            Self::RepairSymbol => 5,
            Self::ProofBundle => 6,
            Self::Finalizer => 7,
        }
    }

    /// Returns the mandatory stages for a final ATP proof bundle.
    #[must_use]
    pub const fn required_final_proof_stages() -> &'static [Self] {
        &Self::REQUIRED_FINAL_PROOF_STAGES
    }
}

/// Verifier resource limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifierConfig {
    /// Maximum chunk payload accepted by a single chunk verification call.
    pub max_chunk_bytes: usize,
    /// Maximum repair-symbol payload accepted by a single verification call.
    pub max_repair_symbol_bytes: usize,
    /// Maximum number of proof bundle entries accepted before bounded replay.
    pub max_proof_entries: usize,
}

impl Default for VerifierConfig {
    fn default() -> Self {
        Self {
            max_chunk_bytes: 16 * 1024 * 1024,
            max_repair_symbol_bytes: 16 * 1024 * 1024,
            max_proof_entries: 4096,
        }
    }
}

/// Redaction-safe evidence emitted by a successful verifier stage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationEvidence {
    /// Stage that produced the evidence.
    pub stage: VerificationStage,
    /// Stable summary safe for logs.
    pub summary: String,
    /// Digest associated with the verified input when one exists.
    pub digest: Option<ContentId>,
}

impl VerificationEvidence {
    fn new(
        stage: VerificationStage,
        summary: impl Into<String>,
        digest: Option<ContentId>,
    ) -> Self {
        Self {
            stage,
            summary: summary.into(),
            digest,
        }
    }
}

/// Chunk verification request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkVerification<'a> {
    /// Monotonic chunk index in the object stream.
    pub chunk_index: u64,
    /// Byte offset within the object.
    pub offset: u64,
    /// Chunk bytes to verify.
    pub bytes: &'a [u8],
    /// Expected digest for the chunk bytes.
    pub expected_digest: ContentId,
}

/// Repair-symbol verification request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairSymbolVerification<'a> {
    /// Source block number for the repair symbol.
    pub source_block: u32,
    /// Repair-symbol encoding symbol id.
    pub repair_index: u32,
    /// Repair-symbol bytes to verify.
    pub bytes: &'a [u8],
    /// Expected digest for the repair-symbol bytes and metadata.
    pub expected_digest: ContentId,
}

/// Proof bundle entry included in the final ATP verification evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofBundleEntry {
    /// Verifier stage represented by this entry.
    pub stage: VerificationStage,
    /// Digest emitted by that stage.
    pub digest: ContentId,
}

/// Final proof bundle verification request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofBundleVerification {
    /// Manifest or graph root covered by the proof bundle.
    pub merkle_root: MerkleRoot,
    /// Ordered proof entries.
    pub entries: Vec<ProofBundleEntry>,
    /// Expected digest of the complete proof bundle.
    pub expected_digest: ContentId,
}

/// Finalizer and cancellation evidence for verifier-owned cleanup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalizerProof {
    /// Stage at which cleanup was observed.
    pub stage: VerificationStage,
    /// Number of verifier leases acquired before cleanup.
    pub leases_acquired: usize,
    /// Number of verifier leases released by cleanup.
    pub leases_released: usize,
    /// Whether cancellation had been requested.
    pub cancellation_requested: bool,
    /// Whether final output was exposed despite cancellation.
    pub final_output_exposed: bool,
}

/// Resume state that must survive verifier cancellation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierResumeState {
    /// Journal sequence from which verification can resume.
    pub journal_sequence: u64,
    /// Number of verifier stages already proven before cancellation.
    pub verified_stage_count: usize,
    /// Digest of the proof bundle being verified at cancellation time.
    pub proof_bundle_digest: ContentId,
}

/// Finalizer outcome recorded in redaction-safe verifier logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifierFinalizerOutcome {
    /// Finalizer completed without cancellation.
    Completed,
    /// Cancellation was requested and cleanup drained before final exposure.
    CancelledDrained,
}

impl VerifierFinalizerOutcome {
    /// Returns the stable snake-case outcome label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::CancelledDrained => "cancelled_drained",
        }
    }
}

/// Redaction-safe verifier log entry for finalization decisions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierLogEntry {
    /// Verifier stage that produced this entry.
    pub stage: VerificationStage,
    /// Transfer identifier, never payload bytes or peer secrets.
    pub transfer_id: String,
    /// Manifest root covered by this verification decision.
    pub manifest_root: MerkleRoot,
    /// Redaction-safe rejection reason when the stage failed.
    pub rejection_reason: Option<String>,
    /// Finalizer result observed by the verifier.
    pub finalizer_outcome: VerifierFinalizerOutcome,
    /// Digest identifying the verified proof bundle.
    pub proof_bundle_id: ContentId,
    /// Replay or crashpack pointer for deterministic reconstruction.
    pub replay_crashpack_pointer: String,
}

/// Final verifier pipeline proof for deciding whether data may be committed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierPipelineProof {
    /// Transfer identifier.
    pub transfer_id: String,
    /// Manifest root covered by the final proof bundle.
    pub manifest_root: MerkleRoot,
    /// Ordered proof entries supplied to the proof-bundle verifier.
    pub proof_entries: Vec<ProofBundleEntry>,
    /// Expected digest for the complete proof bundle.
    pub expected_proof_digest: ContentId,
    /// Finalizer and cancellation proof.
    pub finalizer: FinalizerProof,
    /// Resume state preserved when cancellation interrupted verification.
    pub resume_state: Option<VerifierResumeState>,
    /// Number of verifier workers started.
    pub workers_started: usize,
    /// Number of verifier workers drained.
    pub workers_drained: usize,
    /// Number of verifier permits acquired.
    pub permits_acquired: usize,
    /// Number of verifier permits released.
    pub permits_released: usize,
    /// Number of finalizer obligations started.
    pub finalizer_obligations_started: usize,
    /// Number of finalizer obligations completed.
    pub finalizer_obligations_completed: usize,
    /// Whether final output was exposed before the verifier committed.
    pub final_output_exposed: bool,
    /// Replay or crashpack pointer used to reconstruct this decision.
    pub replay_crashpack_pointer: String,
}

/// Successful final verifier pipeline report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierPipelineReport {
    /// Evidence produced by final proof-bundle verification.
    pub proof_bundle_evidence: VerificationEvidence,
    /// Evidence produced by finalizer proof verification.
    pub finalizer_evidence: VerificationEvidence,
    /// Resume state preserved for cancellation, when cancellation occurred.
    pub resume_state: Option<VerifierResumeState>,
    /// Redaction-safe finalization log entry.
    pub log_entry: VerifierLogEntry,
}

/// Deterministic verifier-owned finalizer state used to prove cleanup balance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierFinalizerLedger {
    /// Stage where cleanup/finalization was observed.
    pub stage: VerificationStage,
    /// Number of verifier leases acquired before cleanup.
    pub leases_acquired: usize,
    /// Number of verifier leases released by cleanup.
    pub leases_released: usize,
    /// Whether cancellation was requested before cleanup completed.
    pub cancellation_requested: bool,
    /// Whether final output was exposed despite cancellation.
    pub final_output_exposed: bool,
}

impl VerifierFinalizerLedger {
    /// Creates an empty finalizer ledger for a verifier stage.
    #[must_use]
    pub const fn new(stage: VerificationStage) -> Self {
        Self {
            stage,
            leases_acquired: 0,
            leases_released: 0,
            cancellation_requested: false,
            final_output_exposed: false,
        }
    }

    /// Records an acquired verifier lease.
    pub fn acquire_lease(&mut self) {
        self.leases_acquired += 1;
    }

    /// Records a released verifier lease.
    pub fn release_lease(&mut self) {
        self.leases_released += 1;
    }

    /// Records cancellation before verifier cleanup completed.
    pub fn request_cancellation(&mut self) {
        self.cancellation_requested = true;
    }

    /// Records final output exposure.
    pub fn expose_final_output(&mut self) {
        self.final_output_exposed = true;
    }

    /// Converts the ledger into the stable finalizer proof checked by the verifier.
    #[must_use]
    pub const fn to_proof(&self) -> FinalizerProof {
        FinalizerProof {
            stage: self.stage,
            leases_acquired: self.leases_acquired,
            leases_released: self.leases_released,
            cancellation_requested: self.cancellation_requested,
            final_output_exposed: self.final_output_exposed,
        }
    }
}

/// Fail-closed verifier errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationError {
    /// Verification input exceeded the configured bound.
    InputTooLarge {
        /// Stage that rejected the input.
        stage: VerificationStage,
        /// Observed length.
        len: usize,
        /// Configured maximum length.
        limit: usize,
    },
    /// Chunk digest mismatch.
    ChunkDigestMismatch {
        /// Chunk index that failed verification.
        chunk_index: u64,
        /// Expected digest.
        expected: ContentId,
        /// Computed digest.
        computed: ContentId,
    },
    /// Repair symbol digest mismatch.
    RepairDigestMismatch {
        /// Source block number.
        source_block: u32,
        /// Repair-symbol encoding symbol id.
        repair_index: u32,
        /// Expected digest.
        expected: ContentId,
        /// Computed digest.
        computed: ContentId,
    },
    /// Object content or canonical identity mismatch.
    ObjectIdentityMismatch {
        /// Object id from the input object.
        expected: ObjectId,
        /// Object id computed by the verifier.
        computed: ObjectId,
    },
    /// Object declared size does not match content length.
    ObjectSizeMismatch {
        /// Object id being verified.
        object_id: ObjectId,
        /// Declared object size.
        declared: u64,
        /// Actual content length.
        actual: u64,
    },
    /// Object kind requires content but none was present.
    MissingObjectContent {
        /// Object id being verified.
        object_id: ObjectId,
    },
    /// Object kind must not carry inline content.
    UnexpectedObjectContent {
        /// Object id being verified.
        object_id: ObjectId,
        /// Object kind.
        kind: ObjectKind,
    },
    /// Object kind is not yet accepted by this verifier surface.
    UnsupportedObjectKind {
        /// Object kind.
        kind: ObjectKind,
    },
    /// Object graph validation failed.
    InvalidGraph {
        /// Redaction-safe reason.
        reason: String,
    },
    /// Manifest validation failed.
    InvalidManifest {
        /// Redaction-safe reason.
        reason: String,
    },
    /// Merkle root mismatch.
    MerkleRootMismatch {
        /// Expected root.
        expected: MerkleRoot,
        /// Computed root.
        computed: MerkleRoot,
    },
    /// Manifest and graph are not the same canonical graph.
    ManifestGraphMismatch {
        /// Redaction-safe reason.
        reason: String,
    },
    /// Commit validation failed.
    InvalidCommit {
        /// Redaction-safe reason.
        reason: String,
    },
    /// Proof bundle has too many entries.
    TooManyProofEntries {
        /// Entry count found.
        count: usize,
        /// Configured maximum entry count.
        limit: usize,
    },
    /// Final proof bundle is missing a mandatory verifier stage.
    MissingProofStage {
        /// Missing stage.
        stage: VerificationStage,
    },
    /// Final proof bundle contains duplicate evidence for a verifier stage.
    DuplicateProofStage {
        /// Duplicated stage.
        stage: VerificationStage,
    },
    /// Proof bundle digest mismatch.
    ProofBundleDigestMismatch {
        /// Expected digest.
        expected: ContentId,
        /// Computed digest.
        computed: ContentId,
    },
    /// Verifier cleanup leaked leases.
    FinalizerLeaseLeak {
        /// Leases acquired.
        acquired: usize,
        /// Leases released.
        released: usize,
    },
    /// Cancellation path exposed final output.
    CancelledFinalExposure {
        /// Stage that exposed output.
        stage: VerificationStage,
    },
    /// Verifier workers were not fully drained before finalization.
    WorkerDrainLeak {
        /// Workers started.
        started: usize,
        /// Workers drained.
        drained: usize,
    },
    /// Verifier permits were not fully released before finalization.
    PermitLeak {
        /// Permits acquired.
        acquired: usize,
        /// Permits released.
        released: usize,
    },
    /// Finalizer obligations were not all completed.
    FinalizerObligationLeak {
        /// Finalizer obligations started.
        started: usize,
        /// Finalizer obligations completed.
        completed: usize,
    },
    /// Cancellation was observed without durable resume state.
    MissingResumeState {
        /// Stage interrupted by cancellation.
        stage: VerificationStage,
    },
    /// Replay/crashpack pointer was absent.
    MissingReplayCrashpackPointer,
}

impl VerificationError {
    /// Returns the verifier stage associated with the error.
    #[must_use]
    pub const fn stage(&self) -> VerificationStage {
        match self {
            Self::InputTooLarge { stage, .. } => *stage,
            Self::ChunkDigestMismatch { .. } => VerificationStage::ChunkHash,
            Self::RepairDigestMismatch { .. } => VerificationStage::RepairSymbol,
            Self::ObjectIdentityMismatch { .. }
            | Self::ObjectSizeMismatch { .. }
            | Self::MissingObjectContent { .. }
            | Self::UnexpectedObjectContent { .. }
            | Self::UnsupportedObjectKind { .. } => VerificationStage::ObjectContent,
            Self::InvalidGraph { .. } | Self::MerkleRootMismatch { .. } => {
                VerificationStage::GraphMerkle
            }
            Self::InvalidManifest { .. } | Self::ManifestGraphMismatch { .. } => {
                VerificationStage::Manifest
            }
            Self::InvalidCommit { .. } => VerificationStage::Commit,
            Self::TooManyProofEntries { .. }
            | Self::MissingProofStage { .. }
            | Self::DuplicateProofStage { .. }
            | Self::ProofBundleDigestMismatch { .. } => VerificationStage::ProofBundle,
            Self::FinalizerLeaseLeak { .. } | Self::CancelledFinalExposure { .. } => {
                VerificationStage::Finalizer
            }
            Self::WorkerDrainLeak { .. }
            | Self::PermitLeak { .. }
            | Self::FinalizerObligationLeak { .. }
            | Self::MissingResumeState { .. }
            | Self::MissingReplayCrashpackPointer => VerificationStage::Finalizer,
        }
    }

    /// Returns a stable, redaction-safe reason string.
    #[must_use]
    pub fn redacted_reason(&self) -> String {
        match self {
            Self::InputTooLarge { len, limit, .. } => {
                format!("input length {len} exceeds verifier limit {limit}")
            }
            Self::ChunkDigestMismatch { chunk_index, .. } => {
                format!("chunk {chunk_index} digest mismatch")
            }
            Self::RepairDigestMismatch {
                source_block,
                repair_index,
                ..
            } => format!("repair symbol {source_block}:{repair_index} digest mismatch"),
            Self::ObjectIdentityMismatch { .. } => "object identity mismatch".to_string(),
            Self::ObjectSizeMismatch { .. } => "object size mismatch".to_string(),
            Self::MissingObjectContent { .. } => "object content missing".to_string(),
            Self::UnexpectedObjectContent { kind, .. } => {
                format!("object kind {kind} carried unexpected content")
            }
            Self::UnsupportedObjectKind { kind } => {
                format!("object kind {kind} is not accepted by this verifier")
            }
            Self::InvalidGraph { reason }
            | Self::InvalidManifest { reason }
            | Self::ManifestGraphMismatch { reason }
            | Self::InvalidCommit { reason } => reason.clone(),
            Self::MerkleRootMismatch { .. } => "merkle root mismatch".to_string(),
            Self::TooManyProofEntries { count, limit } => {
                format!("proof bundle entry count {count} exceeds verifier limit {limit}")
            }
            Self::MissingProofStage { stage } => {
                format!("proof bundle missing {} evidence", stage.as_str())
            }
            Self::DuplicateProofStage { stage } => {
                format!("proof bundle has duplicate {} evidence", stage.as_str())
            }
            Self::ProofBundleDigestMismatch { .. } => "proof bundle digest mismatch".to_string(),
            Self::FinalizerLeaseLeak { acquired, released } => {
                format!("finalizer released {released} of {acquired} leases")
            }
            Self::CancelledFinalExposure { stage } => {
                format!(
                    "cancelled verifier exposed final output at {}",
                    stage.as_str()
                )
            }
            Self::WorkerDrainLeak { started, drained } => {
                format!("verifier drained {drained} of {started} workers")
            }
            Self::PermitLeak { acquired, released } => {
                format!("verifier released {released} of {acquired} permits")
            }
            Self::FinalizerObligationLeak { started, completed } => {
                format!("finalizer completed {completed} of {started} obligations")
            }
            Self::MissingResumeState { stage } => {
                format!(
                    "cancelled verifier at {} without resume state",
                    stage.as_str()
                )
            }
            Self::MissingReplayCrashpackPointer => {
                "verifier finalization missing replay/crashpack pointer".to_string()
            }
        }
    }
}

impl fmt::Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} verification failed: {}",
            self.stage().as_str(),
            self.redacted_reason()
        )
    }
}

impl std::error::Error for VerificationError {}

/// ATP verifier pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AtpVerifier {
    /// Verifier configuration.
    pub config: VerifierConfig,
}

impl AtpVerifier {
    /// Creates a verifier from explicit limits.
    #[must_use]
    pub const fn new(config: VerifierConfig) -> Self {
        Self { config }
    }

    /// Verifies a chunk digest.
    pub fn verify_chunk(
        &self,
        chunk: ChunkVerification<'_>,
    ) -> Result<VerificationEvidence, VerificationError> {
        if chunk.bytes.len() > self.config.max_chunk_bytes {
            return Err(VerificationError::InputTooLarge {
                stage: VerificationStage::ChunkHash,
                len: chunk.bytes.len(),
                limit: self.config.max_chunk_bytes,
            });
        }

        let computed = ContentId::from_bytes(chunk.bytes);
        if computed != chunk.expected_digest {
            return Err(VerificationError::ChunkDigestMismatch {
                chunk_index: chunk.chunk_index,
                expected: chunk.expected_digest,
                computed,
            });
        }

        Ok(VerificationEvidence::new(
            VerificationStage::ChunkHash,
            format!(
                "chunk={} offset={} len={}",
                chunk.chunk_index,
                chunk.offset,
                chunk.bytes.len()
            ),
            Some(computed),
        ))
    }

    /// Verifies object content and canonical identity for supported object kinds.
    pub fn verify_object(
        &self,
        object: &Object,
    ) -> Result<VerificationEvidence, VerificationError> {
        match object.metadata.kind {
            ObjectKind::FileObject => self.verify_file_object(object),
            ObjectKind::DirectoryObject => self.verify_directory_object(object),
            kind => Err(VerificationError::UnsupportedObjectKind { kind }),
        }
    }

    /// Verifies an object graph and expected Merkle root.
    pub fn verify_graph(
        &self,
        graph: &ObjectGraph,
        expected_root: &MerkleRoot,
    ) -> Result<VerificationEvidence, VerificationError> {
        graph.validate().map_err(map_graph_error)?;
        let computed = MerkleRoot::from_graph(graph);
        if &computed != expected_root {
            return Err(VerificationError::MerkleRootMismatch {
                expected: expected_root.clone(),
                computed,
            });
        }

        Ok(VerificationEvidence::new(
            VerificationStage::GraphMerkle,
            format!("objects={}", graph.object_count()),
            Some(ContentId::new(*computed.hash())),
        ))
    }

    /// Verifies a manifest by itself.
    pub fn verify_manifest(
        &self,
        manifest: &Manifest,
    ) -> Result<VerificationEvidence, VerificationError> {
        manifest.validate().map_err(map_manifest_error)?;
        Ok(VerificationEvidence::new(
            VerificationStage::Manifest,
            format!(
                "objects={} roots={}",
                manifest.objects.len(),
                manifest.roots.len()
            ),
            Some(ContentId::new(*manifest.merkle_root.hash())),
        ))
    }

    /// Verifies a manifest against the canonical object graph it claims.
    pub fn verify_manifest_graph(
        &self,
        manifest: &Manifest,
        graph: &ObjectGraph,
    ) -> Result<VerificationEvidence, VerificationError> {
        self.verify_manifest(manifest)?;
        graph.validate().map_err(map_graph_error)?;

        let computed = Manifest::from_graph(graph, manifest.metadata_policy.clone())
            .map_err(map_manifest_error)?;
        if computed.merkle_root != manifest.merkle_root
            || computed.roots != manifest.roots
            || computed.objects != manifest.objects
        {
            return Err(VerificationError::ManifestGraphMismatch {
                reason: "manifest canonical graph differs from object graph".to_string(),
            });
        }

        Ok(VerificationEvidence::new(
            VerificationStage::Manifest,
            format!("canonical_graph_objects={}", manifest.objects.len()),
            Some(ContentId::new(*manifest.merkle_root.hash())),
        ))
    }

    /// Verifies a graph commit.
    pub fn verify_commit(
        &self,
        commit: &GraphCommit,
    ) -> Result<VerificationEvidence, VerificationError> {
        commit.validate().map_err(map_commit_error)?;
        Ok(VerificationEvidence::new(
            VerificationStage::Commit,
            "commit_id_matches_content",
            Some(ContentId::new(*commit.id.hash())),
        ))
    }

    /// Verifies repair-symbol metadata and digest.
    pub fn verify_repair_symbol(
        &self,
        repair: RepairSymbolVerification<'_>,
    ) -> Result<VerificationEvidence, VerificationError> {
        if repair.bytes.len() > self.config.max_repair_symbol_bytes {
            return Err(VerificationError::InputTooLarge {
                stage: VerificationStage::RepairSymbol,
                len: repair.bytes.len(),
                limit: self.config.max_repair_symbol_bytes,
            });
        }

        let computed = repair_symbol_digest(repair.source_block, repair.repair_index, repair.bytes);
        if computed != repair.expected_digest {
            return Err(VerificationError::RepairDigestMismatch {
                source_block: repair.source_block,
                repair_index: repair.repair_index,
                expected: repair.expected_digest,
                computed,
            });
        }

        Ok(VerificationEvidence::new(
            VerificationStage::RepairSymbol,
            format!(
                "source_block={} repair_index={} len={}",
                repair.source_block,
                repair.repair_index,
                repair.bytes.len()
            ),
            Some(computed),
        ))
    }

    /// Verifies the final proof-bundle digest.
    pub fn verify_proof_bundle(
        &self,
        bundle: &ProofBundleVerification,
    ) -> Result<VerificationEvidence, VerificationError> {
        if bundle.entries.len() > self.config.max_proof_entries {
            return Err(VerificationError::TooManyProofEntries {
                count: bundle.entries.len(),
                limit: self.config.max_proof_entries,
            });
        }

        let computed = proof_bundle_digest(bundle);
        if computed != bundle.expected_digest {
            return Err(VerificationError::ProofBundleDigestMismatch {
                expected: bundle.expected_digest.clone(),
                computed,
            });
        }

        Ok(VerificationEvidence::new(
            VerificationStage::ProofBundle,
            format!("entries={}", bundle.entries.len()),
            Some(computed),
        ))
    }

    /// Verifies a final proof bundle digest and mandatory stage coverage.
    pub fn verify_final_proof_bundle(
        &self,
        bundle: &ProofBundleVerification,
    ) -> Result<VerificationEvidence, VerificationError> {
        let evidence = self.verify_proof_bundle(bundle)?;
        self.verify_final_proof_stage_coverage(bundle)?;

        Ok(VerificationEvidence::new(
            VerificationStage::ProofBundle,
            format!(
                "entries={} required_stages={}",
                bundle.entries.len(),
                VerificationStage::required_final_proof_stages().len()
            ),
            evidence.digest,
        ))
    }

    /// Verifies finalizer and cancellation evidence.
    pub fn verify_finalizer_proof(
        &self,
        proof: &FinalizerProof,
    ) -> Result<VerificationEvidence, VerificationError> {
        if proof.leases_acquired != proof.leases_released {
            return Err(VerificationError::FinalizerLeaseLeak {
                acquired: proof.leases_acquired,
                released: proof.leases_released,
            });
        }
        if proof.cancellation_requested && proof.final_output_exposed {
            return Err(VerificationError::CancelledFinalExposure { stage: proof.stage });
        }

        Ok(VerificationEvidence::new(
            VerificationStage::Finalizer,
            format!(
                "leases={} cancellation_requested={}",
                proof.leases_released, proof.cancellation_requested
            ),
            None,
        ))
    }

    /// Verifies finalizer and cancellation evidence from a deterministic ledger.
    pub fn verify_finalizer_ledger(
        &self,
        ledger: &VerifierFinalizerLedger,
    ) -> Result<VerificationEvidence, VerificationError> {
        self.verify_finalizer_proof(&ledger.to_proof())
    }

    /// Verifies the final ATP verifier pipeline before final output exposure.
    pub fn verify_pipeline_finalization(
        &self,
        proof: &VerifierPipelineProof,
    ) -> Result<VerifierPipelineReport, VerificationError> {
        if proof.workers_started != proof.workers_drained {
            return Err(VerificationError::WorkerDrainLeak {
                started: proof.workers_started,
                drained: proof.workers_drained,
            });
        }
        if proof.permits_acquired != proof.permits_released {
            return Err(VerificationError::PermitLeak {
                acquired: proof.permits_acquired,
                released: proof.permits_released,
            });
        }
        if proof.finalizer_obligations_started != proof.finalizer_obligations_completed {
            return Err(VerificationError::FinalizerObligationLeak {
                started: proof.finalizer_obligations_started,
                completed: proof.finalizer_obligations_completed,
            });
        }
        if proof.replay_crashpack_pointer.trim().is_empty() {
            return Err(VerificationError::MissingReplayCrashpackPointer);
        }
        if proof.finalizer.cancellation_requested && proof.resume_state.is_none() {
            return Err(VerificationError::MissingResumeState {
                stage: proof.finalizer.stage,
            });
        }

        let bundle = ProofBundleVerification {
            merkle_root: proof.manifest_root.clone(),
            entries: proof.proof_entries.clone(),
            expected_digest: proof.expected_proof_digest.clone(),
        };
        let proof_bundle_evidence = self.verify_final_proof_bundle(&bundle)?;

        let mut finalizer = proof.finalizer.clone();
        finalizer.final_output_exposed |= proof.final_output_exposed;
        let finalizer_evidence = self.verify_finalizer_proof(&finalizer)?;

        let finalizer_outcome = if finalizer.cancellation_requested {
            VerifierFinalizerOutcome::CancelledDrained
        } else {
            VerifierFinalizerOutcome::Completed
        };
        let log_entry = VerifierLogEntry {
            stage: VerificationStage::Finalizer,
            transfer_id: proof.transfer_id.clone(),
            manifest_root: proof.manifest_root.clone(),
            rejection_reason: None,
            finalizer_outcome,
            proof_bundle_id: proof.expected_proof_digest.clone(),
            replay_crashpack_pointer: proof.replay_crashpack_pointer.clone(),
        };

        Ok(VerifierPipelineReport {
            proof_bundle_evidence,
            finalizer_evidence,
            resume_state: proof.resume_state.clone(),
            log_entry,
        })
    }

    fn verify_final_proof_stage_coverage(
        &self,
        bundle: &ProofBundleVerification,
    ) -> Result<(), VerificationError> {
        let mut seen = BTreeSet::new();
        for entry in &bundle.entries {
            if !seen.insert(entry.stage) {
                return Err(VerificationError::DuplicateProofStage { stage: entry.stage });
            }
        }

        for stage in VerificationStage::required_final_proof_stages() {
            if !seen.contains(stage) {
                return Err(VerificationError::MissingProofStage { stage: *stage });
            }
        }

        Ok(())
    }

    fn verify_file_object(
        &self,
        object: &Object,
    ) -> Result<VerificationEvidence, VerificationError> {
        let content =
            object
                .content
                .as_deref()
                .ok_or_else(|| VerificationError::MissingObjectContent {
                    object_id: object.id.clone(),
                })?;
        if let Some(declared) = object.metadata.size_bytes {
            let actual = content.len() as u64;
            if declared != actual {
                return Err(VerificationError::ObjectSizeMismatch {
                    object_id: object.id.clone(),
                    declared,
                    actual,
                });
            }
        }

        let computed = ObjectId::content(ContentId::from_bytes(content));
        if computed != object.id {
            return Err(VerificationError::ObjectIdentityMismatch {
                expected: object.id.clone(),
                computed,
            });
        }

        Ok(VerificationEvidence::new(
            VerificationStage::ObjectContent,
            format!("file_len={}", content.len()),
            Some(ContentId::new(*object.id.hash_bytes())),
        ))
    }

    fn verify_directory_object(
        &self,
        object: &Object,
    ) -> Result<VerificationEvidence, VerificationError> {
        if object.content.is_some() {
            return Err(VerificationError::UnexpectedObjectContent {
                object_id: object.id.clone(),
                kind: object.metadata.kind,
            });
        }

        let computed = Object::directory(object.children.clone()).id;
        if computed != object.id {
            return Err(VerificationError::ObjectIdentityMismatch {
                expected: object.id.clone(),
                computed,
            });
        }

        Ok(VerificationEvidence::new(
            VerificationStage::ObjectContent,
            format!("directory_children={}", object.children.len()),
            Some(ContentId::new(*object.id.hash_bytes())),
        ))
    }
}

/// Computes the deterministic repair-symbol digest used by verifier tests and callers.
#[must_use]
pub fn repair_symbol_digest(source_block: u32, repair_index: u32, bytes: &[u8]) -> ContentId {
    let mut payload =
        Vec::with_capacity(std::mem::size_of::<u32>() + std::mem::size_of::<u32>() + bytes.len());
    payload.extend_from_slice(&source_block.to_be_bytes());
    payload.extend_from_slice(&repair_index.to_be_bytes());
    payload.extend_from_slice(bytes);
    ContentId::from_bytes(&payload)
}

/// Computes the deterministic digest for a proof bundle.
#[must_use]
pub fn proof_bundle_digest(bundle: &ProofBundleVerification) -> ContentId {
    let mut payload = Vec::with_capacity(32 + bundle.entries.len() * 33);
    payload.extend_from_slice(bundle.merkle_root.hash());
    for entry in &bundle.entries {
        payload.push(entry.stage.code());
        payload.extend_from_slice(entry.digest.hash());
    }
    ContentId::from_bytes(&payload)
}

fn map_graph_error(err: ObjectGraphError) -> VerificationError {
    VerificationError::InvalidGraph {
        reason: err.to_string(),
    }
}

fn map_manifest_error(err: ManifestError) -> VerificationError {
    VerificationError::InvalidManifest {
        reason: err.to_string(),
    }
}

fn map_commit_error(err: ManifestError) -> VerificationError {
    VerificationError::InvalidCommit {
        reason: err.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atp::manifest::{CommitMetadata, GraphCommit};
    use crate::atp::object::{MetadataPolicy, ObjectEdge};

    #[test]
    fn chunk_verifier_accepts_matching_digest() {
        let verifier = AtpVerifier::default();
        let bytes = b"verified chunk";
        let digest = ContentId::from_bytes(bytes);

        let evidence = verifier
            .verify_chunk(ChunkVerification {
                chunk_index: 7,
                offset: 4096,
                bytes,
                expected_digest: digest.clone(),
            })
            .expect("matching digest should verify");

        assert_eq!(evidence.stage, VerificationStage::ChunkHash);
        assert_eq!(evidence.digest, Some(digest));
        assert!(evidence.summary.contains("chunk=7"));
    }

    #[test]
    fn chunk_verifier_rejects_mismatched_digest_without_payload_leak() {
        let verifier = AtpVerifier::default();
        let err = verifier
            .verify_chunk(ChunkVerification {
                chunk_index: 2,
                offset: 0,
                bytes: b"actual bytes",
                expected_digest: ContentId::from_bytes(b"expected bytes"),
            })
            .expect_err("mismatched digest must fail closed");

        assert_eq!(err.stage(), VerificationStage::ChunkHash);
        assert_eq!(err.redacted_reason(), "chunk 2 digest mismatch");
        assert!(!err.to_string().contains("actual bytes"));
    }

    #[test]
    fn object_verifier_rejects_wrong_file_identity() {
        let verifier = AtpVerifier::default();
        let mut object = Object::file(b"original".to_vec());
        object.content = Some(b"tampered".to_vec());

        let err = verifier
            .verify_object(&object)
            .expect_err("tampered content must not verify");

        assert_eq!(err.stage(), VerificationStage::ObjectContent);
        assert_eq!(err.redacted_reason(), "object identity mismatch");
    }

    #[test]
    fn manifest_graph_verifier_accepts_canonical_graph() {
        let verifier = AtpVerifier::default();
        let mut graph = ObjectGraph::new();
        let file = Object::file(b"file payload".to_vec());
        let file_id = file.id.clone();
        graph.add_object(file).expect("add file");
        let dir = Object::directory(vec![ObjectEdge::new(file_id, "file.txt".to_string())]);
        graph.add_root(dir).expect("add root");

        let manifest = Manifest::from_graph(&graph, MetadataPolicy::default()).expect("manifest");
        let evidence = verifier
            .verify_manifest_graph(&manifest, &graph)
            .expect("manifest should match graph");

        assert_eq!(evidence.stage, VerificationStage::Manifest);
        assert!(evidence.summary.contains("canonical_graph_objects=2"));
    }

    #[test]
    fn graph_verifier_rejects_wrong_merkle_root() {
        let verifier = AtpVerifier::default();
        let mut graph = ObjectGraph::new();
        graph
            .add_root(Object::file(b"file payload".to_vec()))
            .expect("add root");
        let wrong_root = MerkleRoot::new([9; 32]);

        let err = verifier
            .verify_graph(&graph, &wrong_root)
            .expect_err("wrong root must fail");

        assert_eq!(err.stage(), VerificationStage::GraphMerkle);
        assert_eq!(err.redacted_reason(), "merkle root mismatch");
    }

    #[test]
    fn commit_verifier_rejects_tampered_commit_id() {
        let verifier = AtpVerifier::default();
        let mut graph = ObjectGraph::new();
        graph
            .add_root(Object::file(b"payload".to_vec()))
            .expect("root");
        let manifest = Manifest::from_graph(&graph, MetadataPolicy::default()).expect("manifest");
        let metadata = CommitMetadata {
            timestamp_nanos: 10,
            author: "atp-test".to_string(),
            message: "verify".to_string(),
        };
        let mut commit = GraphCommit::new(None, manifest, metadata);
        commit.metadata.message = "tampered".to_string();

        let err = verifier
            .verify_commit(&commit)
            .expect_err("tampered commit metadata must fail");

        assert_eq!(err.stage(), VerificationStage::Commit);
    }

    #[test]
    fn repair_symbol_verifier_covers_metadata_and_bytes() {
        let verifier = AtpVerifier::default();
        let bytes = b"repair-symbol";
        let digest = repair_symbol_digest(3, 99, bytes);

        verifier
            .verify_repair_symbol(RepairSymbolVerification {
                source_block: 3,
                repair_index: 99,
                bytes,
                expected_digest: digest,
            })
            .expect("repair symbol should verify");

        let err = verifier
            .verify_repair_symbol(RepairSymbolVerification {
                source_block: 4,
                repair_index: 99,
                bytes,
                expected_digest: repair_symbol_digest(3, 99, bytes),
            })
            .expect_err("metadata mismatch must fail");

        assert_eq!(err.stage(), VerificationStage::RepairSymbol);
        assert_eq!(err.redacted_reason(), "repair symbol 4:99 digest mismatch");
    }

    #[test]
    fn proof_bundle_verifier_rejects_replayed_digest() {
        let verifier = AtpVerifier::default();
        let merkle_root = MerkleRoot::new([1; 32]);
        let entry = ProofBundleEntry {
            stage: VerificationStage::ChunkHash,
            digest: ContentId::from_bytes(b"chunk"),
        };
        let good_bundle = ProofBundleVerification {
            merkle_root: merkle_root.clone(),
            entries: vec![entry.clone()],
            expected_digest: ContentId::from_bytes(b"proof-bundle-seed"),
        };
        let expected_digest = proof_bundle_digest(&good_bundle);

        let mut bundle = ProofBundleVerification {
            merkle_root,
            entries: vec![entry],
            expected_digest,
        };
        verifier
            .verify_proof_bundle(&bundle)
            .expect("fresh bundle should verify");

        bundle.entries.push(ProofBundleEntry {
            stage: VerificationStage::RepairSymbol,
            digest: ContentId::from_bytes(b"replayed"),
        });
        let err = verifier
            .verify_proof_bundle(&bundle)
            .expect_err("replayed bundle must fail digest verification");

        assert_eq!(err.stage(), VerificationStage::ProofBundle);
        assert_eq!(err.redacted_reason(), "proof bundle digest mismatch");
    }

    #[test]
    fn final_proof_bundle_requires_stage_coverage() {
        let verifier = AtpVerifier::default();
        let merkle_root = MerkleRoot::new([8; 32]);
        let incomplete = ProofBundleVerification {
            merkle_root,
            entries: vec![ProofBundleEntry {
                stage: VerificationStage::ChunkHash,
                digest: ContentId::from_bytes(b"chunk"),
            }],
            expected_digest: ContentId::from_bytes(b"proof-bundle-seed"),
        };
        let incomplete = ProofBundleVerification {
            expected_digest: proof_bundle_digest(&incomplete),
            ..incomplete
        };

        let err = verifier
            .verify_final_proof_bundle(&incomplete)
            .expect_err("final proof must include all mandatory stages");

        assert_eq!(err.stage(), VerificationStage::ProofBundle);
        assert_eq!(
            err.redacted_reason(),
            "proof bundle missing object_content evidence"
        );
    }

    #[test]
    fn final_proof_bundle_rejects_duplicate_stage_even_with_fresh_digest() {
        let verifier = AtpVerifier::default();
        let entries = VerificationStage::required_final_proof_stages()
            .iter()
            .copied()
            .chain(std::iter::once(VerificationStage::Commit))
            .map(|stage| ProofBundleEntry {
                stage,
                digest: ContentId::from_bytes(stage.as_str().as_bytes()),
            })
            .collect::<Vec<_>>();
        let bundle = ProofBundleVerification {
            merkle_root: MerkleRoot::new([6; 32]),
            entries,
            expected_digest: ContentId::from_bytes(b"proof-bundle-seed"),
        };
        let bundle = ProofBundleVerification {
            expected_digest: proof_bundle_digest(&bundle),
            ..bundle
        };

        let err = verifier
            .verify_final_proof_bundle(&bundle)
            .expect_err("duplicate stage evidence must fail closed");

        assert_eq!(err.stage(), VerificationStage::ProofBundle);
        assert_eq!(
            err.redacted_reason(),
            "proof bundle has duplicate commit evidence"
        );
    }

    #[test]
    fn final_proof_bundle_accepts_complete_unique_pipeline() {
        let verifier = AtpVerifier::default();
        let entries = VerificationStage::required_final_proof_stages()
            .iter()
            .copied()
            .map(|stage| ProofBundleEntry {
                stage,
                digest: ContentId::from_bytes(stage.as_str().as_bytes()),
            })
            .collect::<Vec<_>>();
        let bundle = ProofBundleVerification {
            merkle_root: MerkleRoot::new([7; 32]),
            entries,
            expected_digest: ContentId::from_bytes(b"proof-bundle-seed"),
        };
        let bundle = ProofBundleVerification {
            expected_digest: proof_bundle_digest(&bundle),
            ..bundle
        };

        let evidence = verifier
            .verify_final_proof_bundle(&bundle)
            .expect("complete final proof should verify");

        assert_eq!(evidence.stage, VerificationStage::ProofBundle);
        assert!(evidence.summary.contains("required_stages=7"));
    }

    #[test]
    fn finalizer_proof_rejects_leaks_and_cancelled_exposure() {
        let verifier = AtpVerifier::default();

        let leak = verifier
            .verify_finalizer_proof(&FinalizerProof {
                stage: VerificationStage::Finalizer,
                leases_acquired: 3,
                leases_released: 2,
                cancellation_requested: false,
                final_output_exposed: false,
            })
            .expect_err("lease leak must fail");
        assert_eq!(leak.stage(), VerificationStage::Finalizer);
        assert_eq!(leak.redacted_reason(), "finalizer released 2 of 3 leases");

        let exposure = verifier
            .verify_finalizer_proof(&FinalizerProof {
                stage: VerificationStage::Commit,
                leases_acquired: 1,
                leases_released: 1,
                cancellation_requested: true,
                final_output_exposed: true,
            })
            .expect_err("cancelled final exposure must fail");
        assert_eq!(
            exposure.redacted_reason(),
            "cancelled verifier exposed final output at commit"
        );
    }

    #[test]
    fn finalizer_ledger_proves_balanced_cleanup_after_cancellation() {
        let verifier = AtpVerifier::default();
        let mut ledger = VerifierFinalizerLedger::new(VerificationStage::Finalizer);
        ledger.acquire_lease();
        ledger.acquire_lease();
        ledger.request_cancellation();
        ledger.release_lease();
        ledger.release_lease();

        let evidence = verifier
            .verify_finalizer_ledger(&ledger)
            .expect("balanced cancelled cleanup should verify");

        assert_eq!(evidence.stage, VerificationStage::Finalizer);
        assert!(evidence.summary.contains("leases=2"));
        assert!(evidence.summary.contains("cancellation_requested=true"));
    }

    #[test]
    fn finalizer_ledger_rejects_cancelled_output_exposure() {
        let verifier = AtpVerifier::default();
        let mut ledger = VerifierFinalizerLedger::new(VerificationStage::Commit);
        ledger.acquire_lease();
        ledger.request_cancellation();
        ledger.expose_final_output();
        ledger.release_lease();

        let err = verifier
            .verify_finalizer_ledger(&ledger)
            .expect_err("cancelled final exposure must fail");

        assert_eq!(err.stage(), VerificationStage::Finalizer);
        assert_eq!(
            err.redacted_reason(),
            "cancelled verifier exposed final output at commit"
        );
    }

    fn complete_proof_entries() -> Vec<ProofBundleEntry> {
        VerificationStage::required_final_proof_stages()
            .iter()
            .copied()
            .map(|stage| ProofBundleEntry {
                stage,
                digest: ContentId::from_bytes(stage.as_str().as_bytes()),
            })
            .collect()
    }

    fn pipeline_proof(cancelled: bool) -> VerifierPipelineProof {
        let manifest_root = MerkleRoot::new([42; 32]);
        let proof_entries = complete_proof_entries();
        let seed_bundle = ProofBundleVerification {
            merkle_root: manifest_root.clone(),
            entries: proof_entries.clone(),
            expected_digest: ContentId::from_bytes(b"proof-bundle-seed"),
        };
        let expected_proof_digest = proof_bundle_digest(&seed_bundle);

        VerifierPipelineProof {
            transfer_id: "transfer-42".to_string(),
            manifest_root,
            proof_entries,
            expected_proof_digest: expected_proof_digest.clone(),
            finalizer: FinalizerProof {
                stage: VerificationStage::Finalizer,
                leases_acquired: 2,
                leases_released: 2,
                cancellation_requested: cancelled,
                final_output_exposed: false,
            },
            resume_state: cancelled.then_some(VerifierResumeState {
                journal_sequence: 99,
                verified_stage_count: 4,
                proof_bundle_digest: expected_proof_digest,
            }),
            workers_started: 3,
            workers_drained: 3,
            permits_acquired: 5,
            permits_released: 5,
            finalizer_obligations_started: 1,
            finalizer_obligations_completed: 1,
            final_output_exposed: false,
            replay_crashpack_pointer: "journal://transfer-42@99".to_string(),
        }
    }

    #[test]
    fn pipeline_finalization_proves_cancelled_resume_and_drained_cleanup() {
        let verifier = AtpVerifier::default();
        let proof = pipeline_proof(true);

        let report = verifier
            .verify_pipeline_finalization(&proof)
            .expect("balanced cancelled verifier pipeline should commit proof only");

        assert_eq!(
            report.proof_bundle_evidence.stage,
            VerificationStage::ProofBundle
        );
        assert_eq!(
            report.finalizer_evidence.stage,
            VerificationStage::Finalizer
        );
        assert_eq!(
            report.log_entry.finalizer_outcome,
            VerifierFinalizerOutcome::CancelledDrained
        );
        assert_eq!(
            report
                .resume_state
                .expect("cancelled pipeline must preserve resume")
                .journal_sequence,
            99
        );
        assert_eq!(report.log_entry.rejection_reason, None);
        assert_eq!(
            report.log_entry.replay_crashpack_pointer,
            "journal://transfer-42@99"
        );
    }

    #[test]
    fn pipeline_finalization_rejects_cancellation_without_resume_state() {
        let verifier = AtpVerifier::default();
        let mut proof = pipeline_proof(true);
        proof.resume_state = None;

        let err = verifier
            .verify_pipeline_finalization(&proof)
            .expect_err("cancelled verifier without resume state must fail closed");

        assert_eq!(err.stage(), VerificationStage::Finalizer);
        assert_eq!(
            err.redacted_reason(),
            "cancelled verifier at finalizer without resume state"
        );
    }

    #[test]
    fn pipeline_finalization_rejects_worker_permit_and_finalizer_leaks() {
        let verifier = AtpVerifier::default();

        let mut worker_leak = pipeline_proof(false);
        worker_leak.workers_drained = 2;
        let err = verifier
            .verify_pipeline_finalization(&worker_leak)
            .expect_err("undrained workers must fail closed");
        assert_eq!(err.redacted_reason(), "verifier drained 2 of 3 workers");

        let mut permit_leak = pipeline_proof(false);
        permit_leak.permits_released = 4;
        let err = verifier
            .verify_pipeline_finalization(&permit_leak)
            .expect_err("unreleased permits must fail closed");
        assert_eq!(err.redacted_reason(), "verifier released 4 of 5 permits");

        let mut finalizer_leak = pipeline_proof(false);
        finalizer_leak.finalizer_obligations_completed = 0;
        let err = verifier
            .verify_pipeline_finalization(&finalizer_leak)
            .expect_err("incomplete finalizer obligations must fail closed");
        assert_eq!(
            err.redacted_reason(),
            "finalizer completed 0 of 1 obligations"
        );
    }

    #[test]
    fn pipeline_finalization_rejects_cancelled_final_exposure_and_missing_crashpack() {
        let verifier = AtpVerifier::default();

        let mut exposed = pipeline_proof(true);
        exposed.final_output_exposed = true;
        let err = verifier
            .verify_pipeline_finalization(&exposed)
            .expect_err("cancelled verifier must not expose final output");
        assert_eq!(
            err.redacted_reason(),
            "cancelled verifier exposed final output at finalizer"
        );

        let mut missing_pointer = pipeline_proof(false);
        missing_pointer.replay_crashpack_pointer.clear();
        let err = verifier
            .verify_pipeline_finalization(&missing_pointer)
            .expect_err("final proof needs replay/crashpack pointer");
        assert_eq!(
            err.redacted_reason(),
            "verifier finalization missing replay/crashpack pointer"
        );
    }
}
