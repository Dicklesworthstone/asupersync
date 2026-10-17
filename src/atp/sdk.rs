//! ATP high-level SDK APIs for object, tree, stream, and buffer movement.
//!
//! This module provides the programmatic API that gives users the simple
//! write(really_big_buffer) experience without bypassing ATP correctness.
//! All APIs are Cx-first and support native Asupersync semantics.
//!
//! [`AtpSession`] is the legacy session surface. It has no transport and no
//! object store, so its transfer and verification methods refuse with a typed
//! error instead of reporting work that never happened
//! (asupersync-bi2462.127). The canonical SDK is [`crate::net::atp::sdk`]:
//! `AtpSdk::native_transfers` (feature `tls`) moves bytes, and
//! [`AtpSession::verify_object`](crate::net::atp::sdk::AtpSession::verify_object)
//! hashes a file's content.

use crate::atp::object::ObjectId;
use crate::atp::stream_object::{
    ByteRange, ConsumptionPolicy, PrefixConsumer, StreamEpoch, StreamManifest,
};
use crate::atp::sync::{
    DirectoryEarlyUsabilityPolicy, DirectoryEarlyUsabilityReport, DirectoryFinalCommitState,
    DirectoryManifest,
};
use crate::atp::transfer::{
    IdempotencyKey, TransferActor, TransferCommand, TransferCommandKind, TransferId, TransferState,
};
use crate::atp::writer::{AtpSink, AtpWriter, ResumeToken, TransferProof, WriterConfig};
use crate::cx::Cx;
use crate::net::atp::protocol::outcome::{
    AtpError, AtpOutcome, ManifestError, PolicyError, ProtocolError,
};
use crate::sync::ContendedMutex;
use crate::types::outcome::Outcome;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, PoisonError};

const TRANSFER_REGISTRY_SHARDS: usize = 64;
const CANCEL_IDEMPOTENCY_DOMAIN: &[u8] = b"ATP-SDK-CANCEL-IDEMPOTENCY-V1\0";

type TransferActorHandle = Arc<ContendedMutex<TransferActor>>;

#[derive(Debug, Clone)]
struct TransferRegistryEntry {
    actor: TransferActorHandle,
    direction: TransferDirection,
    object_id: Option<ObjectId>,
}

/// Sharded active-transfer registry for ATP sessions.
#[derive(Debug)]
struct TransferRegistry {
    shards: Box<[ContendedMutex<HashMap<TransferId, TransferRegistryEntry>>]>,
}

impl TransferRegistry {
    fn new(shard_count: usize) -> Self {
        let shard_count = shard_count.max(1);
        let mut shards = Vec::with_capacity(shard_count);
        for _ in 0..shard_count {
            shards.push(ContendedMutex::new("atp_transfer_registry", HashMap::new()));
        }
        Self {
            shards: shards.into_boxed_slice(),
        }
    }

    #[cfg(test)]
    fn insert(&self, transfer_id: TransferId, entry: TransferRegistryEntry) {
        let shard = self.shard_for(transfer_id);
        let mut transfers = self.shards[shard]
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        transfers.insert(transfer_id, entry);
    }

    fn get(&self, transfer_id: TransferId) -> Option<TransferRegistryEntry> {
        let shard = self.shard_for(transfer_id);
        let transfers = self.shards[shard]
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        transfers.get(&transfer_id).cloned()
    }

    fn remove(&self, transfer_id: TransferId) -> Option<TransferRegistryEntry> {
        let shard = self.shard_for(transfer_id);
        let mut transfers = self.shards[shard]
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        transfers.remove(&transfer_id)
    }

    fn drain(&self) -> Vec<TransferRegistryEntry> {
        let mut drained = Vec::new();
        for shard in self.shards.iter() {
            let mut transfers = shard.lock().unwrap_or_else(PoisonError::into_inner);
            drained.extend(transfers.drain().map(|(_transfer_id, entry)| entry));
        }
        drained
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.shards
            .iter()
            .map(|shard| shard.lock().unwrap_or_else(PoisonError::into_inner).len())
            .sum()
    }

    fn shard_for(&self, transfer_id: TransferId) -> usize {
        transfer_shard_index(transfer_id, self.shards.len())
    }
}

impl Default for TransferRegistry {
    fn default() -> Self {
        Self::new(TRANSFER_REGISTRY_SHARDS)
    }
}

fn transfer_shard_index(transfer_id: TransferId, shard_count: usize) -> usize {
    let shard_count = shard_count.max(1);
    let mut prefix = [0_u8; 8];
    prefix.copy_from_slice(&transfer_id.as_bytes()[..8]);
    let hash = u64::from_le_bytes(prefix);
    match u64::try_from(shard_count) {
        Ok(shards) => usize::try_from(hash % shards).unwrap_or(0),
        Err(_) => 0,
    }
}

fn cancel_idempotency_key(transfer_id: TransferId) -> IdempotencyKey {
    let mut hasher = Sha256::new();
    hasher.update(CANCEL_IDEMPOTENCY_DOMAIN);
    hasher.update(transfer_id.as_bytes());
    let digest = hasher.finalize();

    let mut raw = [0_u8; 16];
    raw.copy_from_slice(&digest[..16]);
    let value = u128::from_be_bytes(raw).max(1);
    IdempotencyKey::new(value)
}

fn request_transfer_cancel(actor: &TransferActorHandle) {
    let mut actor = actor.lock().unwrap_or_else(PoisonError::into_inner);
    let cancel_cmd = TransferCommand::new(
        cancel_idempotency_key(actor.transfer_id),
        TransferCommandKind::Cancel {
            phase: crate::atp::transfer::TransferCancelPhase::Requested,
        },
    );
    let _ = actor.apply(cancel_cmd);
}

fn unsupported_sdk_flow<T>(cx: &Cx, operation: &str) -> AtpOutcome<T> {
    cx.trace(&format!(
        "{operation} requires persisted ATP transfer state; refusing to fabricate SDK result"
    ));
    Outcome::Err(AtpError::Policy(PolicyError::FeatureDisabled))
}

fn missing_transfer_state<T>(cx: &Cx, operation: &str, transfer_id: TransferId) -> AtpOutcome<T> {
    cx.trace(&format!(
        "{operation} has no compatible transfer actor for {:?}; refusing to fabricate SDK state",
        transfer_id
    ));
    Outcome::Err(AtpError::Protocol(ProtocolError::SessionStateMismatch))
}

/// Configuration for ATP SDK operations.
#[derive(Debug, Clone)]
pub struct AtpConfig {
    /// Whether to run in-process or delegate to atpd.
    pub in_process: bool,
    /// Target chunk size for large objects.
    pub target_chunk_size: u64,
    /// Minimum chunk size for content-defined chunking.
    pub min_chunk_size: u64,
    /// Maximum chunk size for content-defined chunking.
    pub max_chunk_size: u64,
    /// Maximum concurrent transfers.
    pub max_concurrent_transfers: usize,
    /// Enable structured logging for diagnostics.
    pub enable_diagnostics: bool,
}

impl Default for AtpConfig {
    fn default() -> Self {
        Self {
            in_process: true,
            target_chunk_size: 64 * 1024, // 64KB
            min_chunk_size: 16 * 1024,    // 16KB
            max_chunk_size: 1024 * 1024,  // 1MB
            max_concurrent_transfers: 8,
            enable_diagnostics: true,
        }
    }
}

/// ATP session handle for transfer operations.
#[derive(Debug, Clone)]
pub struct AtpSession {
    /// Session identifier.
    pub session_id: String,
    /// Local peer identity.
    pub local_peer_id: [u8; 32],
    /// Configuration.
    config: AtpConfig,
    /// Active transfers.
    active_transfers: Arc<TransferRegistry>,
}

impl AtpSession {
    /// Open a new ATP session with the given configuration.
    pub async fn open(cx: &Cx, config: AtpConfig) -> AtpOutcome<Self> {
        cx.trace("atp_sdk");

        let mut session_nonce = [0u8; 16];
        cx.random_bytes(&mut session_nonce);
        if session_nonce.iter().all(|&byte| byte == 0) {
            session_nonce[0] = 1;
        }
        let session_id = format!("atp-session-{}", hex::encode(session_nonce));

        // Generate local peer ID from system entropy
        let mut local_peer_id = [0u8; 32];
        cx.random_bytes(&mut local_peer_id);

        // Ensure peer ID is not all zeros
        if local_peer_id.iter().all(|&b| b == 0) {
            local_peer_id[0] = 1; // Force non-zero
        }

        let session = Self {
            session_id,
            local_peer_id,
            config,
            active_transfers: Arc::new(TransferRegistry::default()),
        };

        if session.config.enable_diagnostics {
            cx.trace(&format!(
                "opened ATP session {} with peer ID {:02x}{:02x}...",
                session.session_id, local_peer_id[0], local_peer_id[1]
            ));
        }

        Outcome::ok(session)
    }

    /// Close the ATP session and cancel all active transfers.
    pub async fn close(&self, cx: &Cx) -> AtpOutcome<()> {
        cx.trace("atp_sdk");

        for entry in self.active_transfers.drain() {
            request_transfer_cancel(&entry.actor);
        }

        if self.config.enable_diagnostics {
            cx.trace(&format!("closed session {}", self.session_id));
        }

        Outcome::ok(())
    }

    /// Send an object to a remote peer.
    ///
    /// This session has no transport, so it refuses with
    /// `AtpError::Policy(PolicyError::FeatureDisabled)`. It used to return a
    /// handle for a transfer that never moved a byte (asupersync-bi2462.127).
    /// Use `AtpSdk::native_transfers` to move objects.
    pub async fn send_object(
        &self,
        cx: &Cx,
        object: ObjectId,
        _remote_peer: [u8; 32],
    ) -> AtpOutcome<TransferHandle> {
        cx.trace(&format!("sending object {:?} to peer", object));

        unsupported_sdk_flow(cx, "send_object")
    }

    /// Receive an object from a remote peer.
    pub async fn receive_object(
        &self,
        cx: &Cx,
        transfer_id: TransferId,
    ) -> AtpOutcome<ObjectReceipt> {
        cx.trace(&format!("receiving object {:?}", transfer_id));

        let Some(entry) = self.active_transfers.get(transfer_id) else {
            return missing_transfer_state(cx, "receive_object", transfer_id);
        };
        if entry.direction != TransferDirection::Receive {
            return missing_transfer_state(cx, "receive_object", transfer_id);
        }
        let Some(object_id) = entry.object_id.clone() else {
            return missing_transfer_state(cx, "receive_object", transfer_id);
        };

        let actor = entry.actor.lock().unwrap_or_else(PoisonError::into_inner);
        if !matches!(actor.state(), TransferState::Committed) {
            return Outcome::Err(AtpError::Protocol(ProtocolError::SessionStateMismatch));
        }
        let size_bytes = actor.progress.committed_bytes;
        if size_bytes == 0 {
            return Outcome::Err(AtpError::Manifest(ManifestError::ObjectNotFound));
        }
        let verified_hash = actor.manifest.merkle_root;

        let receipt = ObjectReceipt {
            object_id,
            verified_hash,
            size_bytes,
            transfer_id,
            consumption_policy: Some(ConsumptionPolicy::VerifiedOnly),
        };

        if self.config.enable_diagnostics {
            cx.trace(&format!(
                "received object {:?} with policy {:?}",
                receipt.object_id, receipt.consumption_policy
            ));
        }

        Outcome::ok(receipt)
    }

    /// Synchronize a directory tree with a remote peer.
    pub async fn sync_tree(
        &self,
        cx: &Cx,
        local_path: impl AsRef<Path>,
        _remote_peer: [u8; 32],
    ) -> AtpOutcome<TreeSyncResult> {
        let path = local_path.as_ref();
        cx.trace(&format!("syncing tree {:?} with peer", path));

        unsupported_sdk_flow(cx, "sync_tree")
    }

    /// Stream a large buffer with backpressure control.
    ///
    /// This session has no transport, so it refuses with
    /// `AtpError::Policy(PolicyError::FeatureDisabled)`. It used to return a
    /// handle whose manifest reported a final, committed stream although no byte
    /// was sent (asupersync-bi2462.127). Use `AtpSdk::native_transfers`.
    pub async fn stream_large_buffer(
        &self,
        cx: &Cx,
        data: &[u8],
        _remote_peer: [u8; 32],
    ) -> AtpOutcome<StreamHandle> {
        cx.trace(&format!("streaming buffer of {} bytes", data.len()));

        unsupported_sdk_flow(cx, "stream_large_buffer")
    }

    /// Verify an object's integrity and authenticity.
    ///
    /// This session holds no object content, so there is nothing to hash. It
    /// refuses with `AtpError::Policy(PolicyError::FeatureDisabled)` instead of
    /// comparing the id's own hash with the expected one and calling that a
    /// verification (asupersync-bi2462.127). The net SDK's
    /// `AtpSession::verify_object` hashes a file's content.
    pub async fn verify_object(
        &self,
        cx: &Cx,
        object_id: ObjectId,
        _expected_hash: Option<[u8; 32]>,
    ) -> AtpOutcome<VerificationResult> {
        cx.trace(&format!("verifying object {:?}", object_id));

        unsupported_sdk_flow(cx, "verify_object")
    }

    /// Resume a paused transfer from journal state.
    pub async fn resume_transfer(
        &self,
        cx: &Cx,
        transfer_id: TransferId,
        journal_position: u64,
    ) -> AtpOutcome<TransferHandle> {
        cx.trace(&format!(
            "resuming transfer {:?} from position {}",
            transfer_id, journal_position
        ));

        let Some(entry) = self.active_transfers.get(transfer_id) else {
            return missing_transfer_state(cx, "resume_transfer", transfer_id);
        };

        let mut actor = entry.actor.lock().unwrap_or_else(PoisonError::into_inner);
        let command = TransferCommand::new(
            IdempotencyKey::new(u128::from(journal_position).saturating_add(1)),
            TransferCommandKind::Resume {
                journal_seq: journal_position,
                obligation: crate::atp::actor::TransferObligationId::new(
                    journal_position.saturating_add(1),
                ),
            },
        );
        match actor.apply(command) {
            Ok(_) => {}
            Err(_) => return Outcome::Err(AtpError::Protocol(ProtocolError::SessionStateMismatch)),
        }
        drop(actor);

        let handle = TransferHandle {
            transfer_id,
            session_id: self.session_id.clone(),
            direction: entry.direction,
            actor: Some(entry.actor),
        };

        if self.config.enable_diagnostics {
            cx.trace(&format!("resumed transfer {:?}", transfer_id));
        }

        Outcome::ok(handle)
    }

    /// Cancel an active transfer.
    ///
    /// An id this session does not hold is refused with
    /// `AtpError::Protocol(ProtocolError::SessionStateMismatch)` rather than
    /// reported as cancelled (asupersync-bi2462.127).
    pub async fn cancel_transfer(&self, cx: &Cx, transfer_id: TransferId) -> AtpOutcome<()> {
        cx.trace(&format!("cancelling transfer {:?}", transfer_id));

        let Some(entry) = self.active_transfers.remove(transfer_id) else {
            return missing_transfer_state(cx, "cancel_transfer", transfer_id);
        };
        request_transfer_cancel(&entry.actor);

        if self.config.enable_diagnostics {
            cx.trace(&format!("cancelled transfer {:?}", transfer_id));
        }

        Outcome::ok(())
    }

    /// Diagnose path connectivity and performance.
    ///
    /// This session probes no path. It refuses with
    /// `AtpError::Policy(PolicyError::FeatureDisabled)` rather than report
    /// `PathError::NoAvailablePaths`, a verdict it never measured
    /// (asupersync-bi2462.127).
    pub async fn path_diagnose(
        &self,
        cx: &Cx,
        _remote_peer: [u8; 32],
    ) -> AtpOutcome<PathDiagnostics> {
        cx.trace("diagnosing path to peer");

        unsupported_sdk_flow(cx, "path_diagnose")
    }

    /// Create a streaming consumer for safe consumption of mutable streams.
    pub fn create_stream_consumer(
        &self,
        manifest: StreamManifest,
        policy: ConsumptionPolicy,
    ) -> AtpOutcome<PrefixConsumer> {
        let consumer = PrefixConsumer::new(manifest, policy);
        Outcome::ok(consumer)
    }

    /// Get stream epochs for a given object ID.
    pub async fn get_stream_epochs(
        &self,
        cx: &Cx,
        object_id: ObjectId,
    ) -> AtpOutcome<Vec<StreamEpoch>> {
        cx.trace(&format!("retrieving stream epochs for {:?}", object_id));

        Outcome::Err(AtpError::Manifest(ManifestError::ObjectNotFound))
    }

    /// Create a writer for large buffer streaming with ergonomic API.
    ///
    /// This session has no transport, so it refuses with
    /// `AtpError::Policy(PolicyError::FeatureDisabled)` (asupersync-txa7vi).
    /// Use `crate::net::atp::sdk` to transfer data.
    pub fn create_writer(
        &self,
        _remote_peer: [u8; 32],
        _writer_config: Option<WriterConfig>,
    ) -> AtpOutcome<AtpWriter> {
        Outcome::Err(AtpError::Policy(PolicyError::FeatureDisabled))
    }

    /// Create a writer from a resume token for interrupted transfers.
    ///
    /// This session has no transport, so it refuses with
    /// `AtpError::Policy(PolicyError::FeatureDisabled)` (asupersync-txa7vi).
    /// Use `crate::net::atp::sdk` to transfer data.
    pub fn resume_writer(
        &self,
        _resume_token: ResumeToken,
        _remote_peer: [u8; 32],
        _writer_config: Option<WriterConfig>,
    ) -> AtpOutcome<AtpWriter> {
        Outcome::Err(AtpError::Policy(PolicyError::FeatureDisabled))
    }

    /// Create a sink for streaming data with backpressure.
    ///
    /// This session has no transport, so it refuses with
    /// `AtpError::Policy(PolicyError::FeatureDisabled)` (asupersync-txa7vi).
    /// Use `crate::net::atp::sdk` to transfer data.
    pub fn create_sink(
        &self,
        _remote_peer: [u8; 32],
        _writer_config: Option<WriterConfig>,
    ) -> AtpOutcome<AtpSink> {
        Outcome::Err(AtpError::Policy(PolicyError::FeatureDisabled))
    }

    /// Write a complete buffer in one ergonomic operation.
    ///
    /// This session has no transport, so it refuses with
    /// `AtpError::Policy(PolicyError::FeatureDisabled)` (asupersync-txa7vi).
    /// Use `crate::net::atp::sdk` to transfer data.
    pub async fn write_buffer(
        &self,
        cx: &Cx,
        _data: &[u8],
        _remote_peer: [u8; 32],
        _config: Option<WriterConfig>,
    ) -> AtpOutcome<TransferProof> {
        unsupported_sdk_flow(cx, "write_buffer")
    }

    /// Write a file in one ergonomic operation.
    ///
    /// This session has no transport, so it refuses with
    /// `AtpError::Policy(PolicyError::FeatureDisabled)` (asupersync-txa7vi).
    /// Use `crate::net::atp::sdk` to transfer data.
    pub async fn write_file<P: AsRef<Path>>(
        &self,
        cx: &Cx,
        _path: P,
        _remote_peer: [u8; 32],
        _config: Option<WriterConfig>,
    ) -> AtpOutcome<TransferProof> {
        unsupported_sdk_flow(cx, "write_file")
    }

    /// Create a streaming writer for unknown-size data.
    ///
    /// This session has no transport, so it refuses with
    /// `AtpError::Policy(PolicyError::FeatureDisabled)` (asupersync-txa7vi).
    /// Use `crate::net::atp::sdk` to transfer data.
    pub async fn create_stream_writer(
        &self,
        cx: &Cx,
        _remote_peer: [u8; 32],
        _config: Option<WriterConfig>,
    ) -> AtpOutcome<AtpWriter> {
        unsupported_sdk_flow(cx, "create_stream_writer")
    }

    /// Send an object graph (directory, application-defined objects).
    pub async fn send_object_graph(
        &self,
        cx: &Cx,
        root_object: ObjectId,
        _remote_peer: [u8; 32],
        _config: Option<WriterConfig>,
    ) -> AtpOutcome<TransferProof> {
        cx.trace(&format!(
            "atp_session_send_object_graph {:?} to peer",
            root_object
        ));

        unsupported_sdk_flow(cx, "send_object_graph")
    }
}

/// Handle for an active transfer operation.
#[derive(Debug, Clone)]
pub struct TransferHandle {
    /// Transfer identifier.
    pub transfer_id: TransferId,
    /// Session that owns this transfer.
    pub session_id: String,
    /// Transfer direction.
    pub direction: TransferDirection,
    /// Actor that owns live transfer state, when this handle came from the SDK.
    actor: Option<TransferActorHandle>,
}

impl TransferHandle {
    /// Get the current transfer state.
    pub fn state(&self) -> TransferState {
        self.actor.as_ref().map_or(TransferState::Failed, |actor| {
            actor.lock().unwrap_or_else(PoisonError::into_inner).state()
        })
    }

    /// Get transfer progress information.
    pub fn progress(&self) -> TransferProgress {
        let progress = self
            .actor
            .as_ref()
            .map(|actor| {
                actor
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .progress
            })
            .unwrap_or_default();

        // offered_bytes is the total the sender offered (the denominator);
        // verified_bytes are the received-and-verified bytes that have actually
        // transferred, and committed_bytes (bytes exposed to output) is a subset
        // of those. Never count offered_bytes as transferred: doing so reported
        // 100% the instant a transfer was offered — before any byte moved —
        // which becomes a live fail-open bug once the transfer actor is driven
        // (br-asupersync-bi2462.53). `max(committed)` only guards against the
        // counters being reported out of their documented
        // offered >= verified >= committed order; `min(total_bytes)` keeps the
        // reported ratio at or below 100%.
        let total_bytes = progress.offered_bytes;
        let bytes_transferred = progress
            .verified_bytes
            .max(progress.committed_bytes)
            .min(total_bytes);

        let progress_percent = if total_bytes > 0 {
            (bytes_transferred as f64 / total_bytes as f64) * 100.0
        } else {
            0.0
        };

        TransferProgress {
            bytes_transferred,
            total_bytes,
            progress_percent,
            estimated_completion_time: None,
        }
    }
}

/// Transfer direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferDirection {
    Send,
    Receive,
}

/// Result of receiving an object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectReceipt {
    /// The received object identifier.
    pub object_id: ObjectId,
    /// Verified content hash.
    pub verified_hash: [u8; 32],
    /// Object size in bytes.
    pub size_bytes: u64,
    /// Transfer that delivered this object.
    pub transfer_id: TransferId,
    /// Consumption policy used for streaming objects.
    pub consumption_policy: Option<ConsumptionPolicy>,
}

/// Result of tree synchronization.
#[derive(Debug, Clone)]
pub struct TreeSyncResult {
    /// Local tree root path.
    pub local_root: std::path::PathBuf,
    /// Number of objects sent.
    pub objects_sent: u64,
    /// Number of objects received.
    pub objects_received: u64,
    /// Total bytes transferred.
    pub bytes_transferred: u64,
}

/// SDK handle for directory transfers with usable-early reporting.
#[derive(Debug, Clone)]
pub struct DirectoryHandle {
    /// Stable directory transfer identifier.
    pub directory_id: String,
    /// Current verified directory manifest.
    pub manifest: DirectoryManifest,
    /// Content ids that have passed verification.
    pub verified_content_ids: BTreeSet<String>,
    /// Final directory commit state, kept separate from early usability.
    pub final_commit_state: DirectoryFinalCommitState,
}

impl DirectoryHandle {
    /// Build a directory handle from a manifest snapshot.
    #[must_use]
    pub fn new(directory_id: impl Into<String>, manifest: DirectoryManifest) -> Self {
        Self {
            directory_id: directory_id.into(),
            manifest,
            verified_content_ids: BTreeSet::new(),
            final_commit_state: DirectoryFinalCommitState::Pending,
        }
    }

    /// Record one verified content id.
    pub fn mark_content_verified(&mut self, content_id: impl Into<String>) -> bool {
        self.verified_content_ids.insert(content_id.into())
    }

    /// Mark the directory manifest as finally committed.
    pub fn mark_final_committed(&mut self) {
        self.final_commit_state = DirectoryFinalCommitState::Committed;
    }

    /// Return true once the directory has reached final committed state.
    #[must_use]
    pub fn is_final_committed(&self) -> bool {
        self.final_commit_state == DirectoryFinalCommitState::Committed
    }

    /// Count verified content ids available for early-usability decisions.
    #[must_use]
    pub fn verified_content_count(&self) -> usize {
        self.verified_content_ids.len()
    }

    /// Build the SDK-facing directory early-usability report.
    ///
    /// The returned report keeps usable-early state, final commit state,
    /// metadata paths, small-file paths, withheld paths, safety caveats, and
    /// replay pointer as separate fields so callers do not infer finality from
    /// early availability.
    #[must_use]
    pub fn early_usability_report(
        &self,
        policy: DirectoryEarlyUsabilityPolicy,
        replay_pointer: impl Into<String>,
    ) -> DirectoryEarlyUsabilityReport {
        self.manifest.early_usability_report(
            &self.verified_content_ids,
            policy,
            self.final_commit_state,
            replay_pointer,
        )
    }
}

/// Handle for streaming operations.
#[derive(Debug, Clone)]
pub struct StreamHandle {
    /// Stream identifier.
    pub stream_id: String,
    /// Total bytes to stream.
    pub total_bytes: u64,
    /// Bytes sent so far.
    pub bytes_sent: u64,
    /// Stream manifest for rolling epochs.
    pub manifest: Option<StreamManifest>,
}

/// Final commit state reported separately from early usability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum StreamFinalCommitState {
    /// The stream has no manifest yet, so final commit state is unknown.
    UnknownNoManifest,
    /// A manifest exists, but no final manifest has been committed.
    Pending,
    /// The stream manifest contains a final committed epoch.
    Committed,
}

/// Usable-early state exposed by the SDK for a stream handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum StreamEarlyUsabilityState {
    /// No manifest exists, so no early range can be exposed.
    NoManifest,
    /// A manifest exists, but no prefix is currently safe under the policy.
    NotUsableYet,
    /// A verified prefix is available and the final commit is still pending.
    VerifiedPrefixAvailable,
    /// A provisional tail is exposed by explicit policy and carries caveats.
    ProvisionalPrefixAvailable,
    /// The stream has reached final committed state.
    FinalCommitted,
}

/// SDK report for prefix-first stream consumption.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StreamEarlyUsabilityReport {
    /// Stream identifier.
    pub stream_id: String,
    /// Current usable-early state.
    pub usable_state: StreamEarlyUsabilityState,
    /// Final commit state, reported independently of early usability.
    pub final_commit_state: StreamFinalCommitState,
    /// Policy used to decide which prefix may be exposed.
    pub consumption_policy: ConsumptionPolicy,
    /// Verified contiguous prefix ranges, never crossing gaps or provisional epochs.
    pub verified_prefix_ranges: Vec<ByteRange>,
    /// Prefix exposed under the requested policy.
    pub policy_exposed_prefix: Option<ByteRange>,
    /// Verified prefix end offset.
    pub verified_prefix_end: u64,
    /// Policy-specific exposed prefix end offset.
    pub policy_prefix_end: u64,
    /// Total stream bytes advertised by the handle.
    pub total_bytes: u64,
    /// Bytes sent so far according to the handle.
    pub bytes_sent: u64,
    /// Safety caveats callers must surface before consuming early bytes.
    pub safety_caveats: Vec<String>,
}

impl StreamHandle {
    /// Check if the stream is complete.
    pub fn is_complete(&self) -> bool {
        self.bytes_sent >= self.total_bytes
    }

    /// Get streaming progress percentage.
    pub fn progress_percent(&self) -> f64 {
        if self.total_bytes == 0 {
            return 100.0;
        }
        (self.bytes_sent as f64 / self.total_bytes as f64) * 100.0
    }

    /// Get the stream manifest if available.
    pub fn manifest(&self) -> Option<&StreamManifest> {
        self.manifest.as_ref()
    }

    /// Get the number of verified epochs in the stream.
    pub fn verified_epochs_count(&self) -> usize {
        self.manifest
            .as_ref()
            .map_or(0, |m| m.verified_epochs().len())
    }

    /// Get the latest verified offset in the stream.
    pub fn latest_verified_offset(&self) -> u64 {
        self.manifest
            .as_ref()
            .map_or(0, |m| m.latest_verified_offset())
    }

    /// Check if the stream has a final manifest.
    pub fn is_finalized(&self) -> bool {
        self.manifest.as_ref().is_some_and(|m| m.is_complete())
    }

    /// Build a structured SDK report for prefix-first consumption.
    ///
    /// This deliberately reports the usable-early state, verified-prefix map,
    /// policy caveats, and final commit state as separate fields so callers do
    /// not infer safety from a single progress number.
    #[must_use]
    pub fn early_usability_report(
        &self,
        consumption_policy: ConsumptionPolicy,
    ) -> StreamEarlyUsabilityReport {
        let Some(manifest) = self.manifest.as_ref() else {
            return StreamEarlyUsabilityReport {
                stream_id: self.stream_id.clone(),
                usable_state: StreamEarlyUsabilityState::NoManifest,
                final_commit_state: StreamFinalCommitState::UnknownNoManifest,
                consumption_policy,
                verified_prefix_ranges: Vec::new(),
                policy_exposed_prefix: None,
                verified_prefix_end: 0,
                policy_prefix_end: 0,
                total_bytes: self.total_bytes,
                bytes_sent: self.bytes_sent,
                safety_caveats: vec![
                    "stream manifest unavailable; early usability is disabled".to_string(),
                ],
            };
        };

        let final_commit_state = if manifest.is_complete() {
            StreamFinalCommitState::Committed
        } else {
            StreamFinalCommitState::Pending
        };
        let verified_prefix_ranges = Self::verified_prefix_ranges(manifest);
        let verified_prefix_end = manifest.verified_prefix_end();
        let policy_prefix_end = manifest.consumable_prefix_end(consumption_policy);
        let policy_exposed_prefix =
            (policy_prefix_end > 0).then(|| ByteRange::new(0, policy_prefix_end));

        let mut safety_caveats = Vec::new();
        if final_commit_state == StreamFinalCommitState::Pending {
            safety_caveats
                .push("final manifest not committed; expose early bytes separately".to_string());
        }

        if consumption_policy == ConsumptionPolicy::AllowProvisional
            && policy_prefix_end > verified_prefix_end
        {
            safety_caveats
                .push("provisional tail is exposed by policy and may be invalidated".to_string());
        }

        if manifest.latest_verified_offset() > verified_prefix_end {
            safety_caveats.push(
                "verified epochs after a gap or non-consumable epoch are withheld".to_string(),
            );
        }

        let usable_state = if final_commit_state == StreamFinalCommitState::Committed {
            StreamEarlyUsabilityState::FinalCommitted
        } else if policy_prefix_end == 0 {
            StreamEarlyUsabilityState::NotUsableYet
        } else if policy_prefix_end > verified_prefix_end {
            StreamEarlyUsabilityState::ProvisionalPrefixAvailable
        } else {
            StreamEarlyUsabilityState::VerifiedPrefixAvailable
        };

        StreamEarlyUsabilityReport {
            stream_id: self.stream_id.clone(),
            usable_state,
            final_commit_state,
            consumption_policy,
            verified_prefix_ranges,
            policy_exposed_prefix,
            verified_prefix_end,
            policy_prefix_end,
            total_bytes: self.total_bytes,
            bytes_sent: self.bytes_sent,
            safety_caveats,
        }
    }

    fn verified_prefix_ranges(manifest: &StreamManifest) -> Vec<ByteRange> {
        let mut expected_start = 0;
        let mut ranges = Vec::new();

        for epoch in &manifest.epochs {
            if epoch.byte_range.start != expected_start || !epoch.is_verified() {
                break;
            }

            ranges.push(epoch.byte_range);
            expected_start = epoch.byte_range.end;
        }

        ranges
    }
}

/// Object verification result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationResult {
    /// Object being verified.
    pub object_id: ObjectId,
    /// Whether verification passed.
    pub verified: bool,
    /// Computed content hash.
    pub computed_hash: [u8; 32],
    /// Whether signature is valid (if present).
    pub signature_valid: bool,
}

/// Transfer progress information.
#[derive(Debug, Clone)]
pub struct TransferProgress {
    /// Bytes transferred so far.
    pub bytes_transferred: u64,
    /// Total bytes to transfer.
    pub total_bytes: u64,
    /// Progress percentage (0-100).
    pub progress_percent: f64,
    /// Estimated completion time.
    pub estimated_completion_time: Option<std::time::SystemTime>,
}

/// Path connectivity diagnostics.
#[derive(Debug, Clone)]
pub struct PathDiagnostics {
    /// Whether direct connectivity is available.
    pub direct_connectivity: bool,
    /// Whether relay is available.
    pub relay_available: bool,
    /// Estimated round-trip latency in milliseconds.
    pub estimated_latency_ms: u32,
    /// Estimated bandwidth in bits per second.
    pub estimated_bandwidth_bps: u64,
    /// Preferred path type.
    pub preferred_path: PathType,
}

/// Network path types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathType {
    /// Unknown or undetermined path.
    Unknown,
    /// Direct peer-to-peer connection.
    Direct,
    /// Connection through UDP relay.
    UdpRelay,
    /// Connection through TCP/TLS relay.
    TcpRelay,
    /// Store-and-forward mailbox.
    Mailbox,
}

#[cfg(test)]
#[path = "sdk_inline_tests.rs"]
mod tests;
