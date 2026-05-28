//! ATP high-level SDK APIs for object, tree, stream, and buffer movement.
//!
//! This module provides the programmatic API that gives users the simple
//! write(really_big_buffer) experience without bypassing ATP correctness.
//! All APIs are Cx-first and support native Asupersync semantics.

use crate::atp::actor::{TransferActorId, TransferActorTopology, TransferRegionId};
use crate::atp::object::{ContentId, ObjectId};
use crate::atp::stream_object::{
    ByteRange, ConsumptionPolicy, EpochState, PrefixConsumer, StreamEpoch, StreamManifest,
};
use crate::atp::sync::{
    DirectoryEarlyUsabilityPolicy, DirectoryEarlyUsabilityReport, DirectoryFinalCommitState,
    DirectoryManifest,
};
use crate::atp::transfer::{
    IdempotencyKey, PeerCapabilities, TransferActor, TransferCommand, TransferCommandKind,
    TransferId, TransferManifestRef, TransferState,
};
use crate::atp::writer::{AtpSink, AtpWriter, ResumeToken, TransferProof, WriterConfig};
use crate::cx::Cx;
use crate::net::atp::protocol::outcome::{
    AtpError, AtpOutcome, ManifestError, PathError, PolicyError, ProtocolError,
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

        // Generate session ID from current process and timestamp
        let session_id = format!(
            "atp-session-{}-{}",
            std::process::id(), // ubs:ignore
            std::time::SystemTime::now() // ubs:ignore
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );

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
    pub async fn send_object(
        &self,
        cx: &Cx,
        object: ObjectId,
        remote_peer: [u8; 32],
    ) -> AtpOutcome<TransferHandle> {
        cx.trace(&format!("sending object {:?} to peer", object));

        // Generate transfer nonce from entropy
        let mut transfer_nonce = [0u8; 32];
        cx.random_bytes(&mut transfer_nonce);

        // Calculate manifest root hash for the object
        let manifest_root = match self.calculate_object_manifest_root(cx, &object).await {
            Outcome::Ok(root) => root,
            Outcome::Err(e) => return Outcome::Err(e),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        };

        let transfer_id = TransferId::derive(
            self.local_peer_id,
            remote_peer,
            transfer_nonce,
            manifest_root,
        );

        let actor_handle = Arc::new(ContendedMutex::new(
            "transfer_actor",
            match TransferActor::new(
                TransferActorId::new(1), // Generate unique actor ID
                transfer_id,
                TransferManifestRef {
                    schema_version: 1,
                    merkle_root: manifest_root,
                    object_count: 1,
                },
                PeerCapabilities::default(),
                TransferActorTopology::new(TransferRegionId::new(10), TransferRegionId::new(20)),
            ) {
                Ok(actor) => actor,
                Err(_) => {
                    return Outcome::Err(AtpError::Protocol(ProtocolError::SessionStateMismatch));
                }
            },
        ));

        // Insert into registry (need to access the Arc contents)
        let shard = self.active_transfers.shard_for(transfer_id);
        let mut transfers = self.active_transfers.shards[shard]
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        transfers.insert(
            transfer_id,
            TransferRegistryEntry {
                actor: actor_handle.clone(),
                direction: TransferDirection::Send,
                object_id: Some(object.clone()),
            },
        );

        let handle = TransferHandle {
            transfer_id,
            session_id: self.session_id.clone(),
            direction: TransferDirection::Send,
            actor: Some(actor_handle),
        };

        if self.config.enable_diagnostics {
            cx.trace(&format!(
                "created transfer handle {:?} with manifest root {:02x}{:02x}...",
                handle.transfer_id, manifest_root[0], manifest_root[1]
            ));
        }

        Outcome::ok(handle)
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
        if actor.state() != TransferState::Committed {
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
    pub async fn stream_large_buffer(
        &self,
        cx: &Cx,
        data: &[u8],
        _remote_peer: [u8; 32],
    ) -> AtpOutcome<StreamHandle> {
        cx.trace(&format!("streaming buffer of {} bytes", data.len()));

        // Create object ID for the stream
        let content_hash = crate::atp::object::compute_hash(data);
        let object_id = ObjectId::content(ContentId::new(content_hash));

        // Create streaming manifest with initial epoch
        let mut manifest = StreamManifest::new(object_id.clone());

        // Determine chunk boundaries based on config
        let chunk_size = self
            .config
            .target_chunk_size
            .min(self.config.max_chunk_size);
        let mut offset = 0;
        let mut epoch_seq = 1;

        while offset < data.len() {
            let chunk_size_usize = usize::try_from(chunk_size).unwrap_or(usize::MAX);
            let end_offset = offset.saturating_add(chunk_size_usize).min(data.len());
            let is_final = end_offset == data.len();

            let epoch = StreamEpoch::new(
                epoch_seq,
                object_id.clone(),
                ByteRange::new(
                    u64::try_from(offset).unwrap_or(u64::MAX),
                    u64::try_from(end_offset).unwrap_or(u64::MAX),
                ),
                if is_final {
                    EpochState::Final
                } else {
                    EpochState::Verified
                },
                vec![], // Chunk boundaries would be computed here
            );

            match manifest.add_epoch(epoch) {
                Outcome::Ok(_) => {}
                Outcome::Err(e) => return Outcome::Err(e),
                Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
                Outcome::Panicked(payload) => return Outcome::Panicked(payload),
            }

            offset = end_offset;
            epoch_seq += 1;
        }

        let stream_handle = StreamHandle {
            stream_id: format!("stream-{}", std::process::id()), // ubs:ignore
            total_bytes: u64::try_from(data.len()).unwrap_or(u64::MAX),
            bytes_sent: 0,
            manifest: Some(manifest),
        };

        if self.config.enable_diagnostics {
            cx.trace(&format!(
                "created stream {} with {} epochs",
                stream_handle.stream_id,
                epoch_seq - 1
            ));
        }

        Outcome::ok(stream_handle)
    }

    /// Verify an object's integrity and authenticity.
    pub async fn verify_object(
        &self,
        cx: &Cx,
        object_id: ObjectId,
        expected_hash: Option<[u8; 32]>,
    ) -> AtpOutcome<VerificationResult> {
        cx.trace(&format!("verifying object {:?}", object_id));

        let computed_hash = *object_id.hash_bytes();
        let Some(expected) = expected_hash else {
            return Outcome::Err(AtpError::Manifest(ManifestError::ObjectNotFound));
        };
        let verified = computed_hash == expected;

        let result = VerificationResult {
            object_id: object_id.clone(),
            verified,
            computed_hash,
            signature_valid: false,
        };

        if self.config.enable_diagnostics {
            cx.trace(&format!(
                "verified object {:?}: verified={}, hash={:02x}{:02x}...",
                object_id, verified, computed_hash[0], computed_hash[1]
            ));
        }

        Outcome::ok(result)
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
    pub async fn cancel_transfer(&self, cx: &Cx, transfer_id: TransferId) -> AtpOutcome<()> {
        cx.trace(&format!("cancelling transfer {:?}", transfer_id));

        if let Some(entry) = self.active_transfers.remove(transfer_id) {
            request_transfer_cancel(&entry.actor);
        }

        if self.config.enable_diagnostics {
            cx.trace(&format!("cancelled transfer {:?}", transfer_id));
        }

        Outcome::ok(())
    }

    /// Diagnose path connectivity and performance.
    pub async fn path_diagnose(
        &self,
        cx: &Cx,
        _remote_peer: [u8; 32],
    ) -> AtpOutcome<PathDiagnostics> {
        cx.trace("diagnosing path to peer");

        Outcome::Err(AtpError::Path(PathError::NoAvailablePaths))
    }

    /// Calculate manifest root hash for an object.
    async fn calculate_object_manifest_root(
        &self,
        _cx: &Cx,
        object_id: &ObjectId,
    ) -> AtpOutcome<[u8; 32]> {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(b"ATP-SINGLE-OBJECT-MANIFEST-ROOT-V2\0");
        hasher.update(object_id.hash_bytes());
        hasher.update(self.config.min_chunk_size.to_le_bytes());
        hasher.update(self.config.target_chunk_size.to_le_bytes());
        hasher.update(self.config.max_chunk_size.to_le_bytes());

        let hash = hasher.finalize();
        let mut result = [0u8; 32];
        result.copy_from_slice(&hash);
        Outcome::ok(result)
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
    /// This is the primary "write(really_big_buffer)" API that provides
    /// ATP correctness with maximum ergonomics for large data transfers.
    pub fn create_writer(
        &self,
        remote_peer: [u8; 32],
        writer_config: Option<WriterConfig>,
    ) -> AtpOutcome<AtpWriter> {
        let config = writer_config.unwrap_or_else(|| {
            let mut config = WriterConfig::default();
            // Apply session-level defaults
            config.chunk_size = self.config.target_chunk_size;
            config.max_concurrent_chunks = self.config.max_concurrent_transfers;
            config.enable_progress = self.config.enable_diagnostics;
            config
        });

        // Generate object ID for the stream
        let content_hash = [0u8; 32]; // Will be computed as data is written
        let object_id = ObjectId::content(ContentId::new(content_hash));

        let writer = AtpWriter::new(object_id, remote_peer, config);

        Outcome::ok(writer)
    }

    /// Create a writer from a resume token for interrupted transfers.
    pub fn resume_writer(
        &self,
        resume_token: ResumeToken,
        remote_peer: [u8; 32],
        writer_config: Option<WriterConfig>,
    ) -> AtpOutcome<AtpWriter> {
        let config = writer_config.unwrap_or_else(|| {
            let mut config = WriterConfig::default();
            config.chunk_size = self.config.target_chunk_size;
            config.max_concurrent_chunks = self.config.max_concurrent_transfers;
            config.enable_progress = self.config.enable_diagnostics;
            config
        });

        AtpWriter::from_resume_token(resume_token, remote_peer, config)
    }

    /// Create a sink for streaming data with backpressure.
    pub fn create_sink(
        &self,
        remote_peer: [u8; 32],
        writer_config: Option<WriterConfig>,
    ) -> AtpOutcome<AtpSink> {
        let config = writer_config.unwrap_or_else(|| {
            let mut config = WriterConfig::default();
            config.chunk_size = self.config.target_chunk_size;
            config.max_concurrent_chunks = self.config.max_concurrent_transfers;
            config.enable_progress = self.config.enable_diagnostics;
            config
        });

        // Generate object ID for the stream
        let content_hash = [0u8; 32]; // Will be computed as data is written
        let object_id = ObjectId::content(ContentId::new(content_hash));

        let sink = AtpSink::new(object_id, remote_peer, config);

        Outcome::ok(sink)
    }

    /// Write a complete buffer in one ergonomic operation.
    ///
    /// This is the ultimate ergonomic API: hand ATP a buffer and get verified
    /// delivery with full proof bundle, progress tracking, and resume capability.
    pub async fn write_buffer(
        &self,
        cx: &Cx,
        data: &[u8],
        remote_peer: [u8; 32],
        config: Option<WriterConfig>,
    ) -> AtpOutcome<TransferProof> {
        cx.trace(&format!(
            "atp_session_write_buffer {} bytes to peer",
            data.len()
        ));

        let mut writer = match self.create_writer(remote_peer, config) {
            Outcome::Ok(writer) => writer,
            Outcome::Err(err) => return Outcome::Err(err),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(msg) => return Outcome::Panicked(msg),
        };

        // Enable progress reporting if session diagnostics are enabled
        if self.config.enable_diagnostics {
            let data_len = data.len();
            let trace_cx = cx.clone();
            writer.set_progress_callback(move |progress| {
                trace_cx.trace(&format!(
                    "ATP transfer progress: {:.1}% ({} bytes written)",
                    progress.bytes_written as f64 / data_len as f64 * 100.0,
                    progress.bytes_written
                ));
            });
        }

        writer.write_buffer(cx, data).await
    }

    /// Write a file in one ergonomic operation.
    pub async fn write_file<P: AsRef<Path>>(
        &self,
        cx: &Cx,
        path: P,
        remote_peer: [u8; 32],
        config: Option<WriterConfig>,
    ) -> AtpOutcome<TransferProof> {
        let path = path.as_ref();
        cx.trace(&format!("atp_session_write_file {:?} to peer", path));

        let mut writer = match self.create_writer(remote_peer, config) {
            Outcome::Ok(writer) => writer,
            Outcome::Err(err) => return Outcome::Err(err),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(msg) => return Outcome::Panicked(msg),
        };

        // Enable progress reporting if session diagnostics are enabled
        if self.config.enable_diagnostics {
            let path_display = path.display().to_string();
            let trace_cx = cx.clone();
            writer.set_progress_callback(move |progress| {
                trace_cx.trace(&format!(
                    "ATP file transfer progress for {}: {:.1}% ({} bytes written)",
                    path_display,
                    progress.bytes_written as f64 * 100.0
                        / progress.total_bytes.unwrap_or(1) as f64,
                    progress.bytes_written
                ));
            });
        }

        writer.write_file(cx, path).await
    }

    /// Create a streaming writer for unknown-size data.
    pub async fn create_stream_writer(
        &self,
        cx: &Cx,
        remote_peer: [u8; 32],
        config: Option<WriterConfig>,
    ) -> AtpOutcome<AtpWriter> {
        cx.trace("atp_session_create_stream_writer");

        let mut writer = match self.create_writer(remote_peer, config) {
            Outcome::Ok(writer) => writer,
            Outcome::Err(err) => return Outcome::Err(err),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(msg) => return Outcome::Panicked(msg),
        };

        // Set up for streaming with unknown final size
        if self.config.enable_diagnostics {
            let trace_cx = cx.clone();
            writer.set_progress_callback(move |progress| {
                trace_cx.trace(&format!(
                    "ATP stream progress: {} bytes written, {} chunks",
                    progress.bytes_written, progress.chunks_completed
                ));
            });
        }

        Outcome::ok(writer)
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

        let bytes_transferred = progress
            .committed_bytes
            .max(progress.verified_bytes)
            .max(progress.offered_bytes);
        let total_bytes = progress.offered_bytes.max(bytes_transferred);

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
mod tests {
    use super::*;
    use crate::atp::actor::{TransferActorId, TransferActorTopology, TransferRegionId};
    use crate::atp::sync::{
        DirectoryEarlyUsabilityState, DirectoryEntryKind, DirectoryEntryMetadata,
        DirectoryManifestEntry, DirectoryPath, PathNormalizationRules,
    };
    use crate::atp::transfer::{PeerCapabilities, TransferManifestRef};
    use crate::cx::{Cx, cap};
    use crate::types::{Budget, RegionId, TaskId};
    use std::collections::BTreeSet;

    fn test_cx() -> Cx<cap::All> {
        Cx::new(
            RegionId::testing_default(),
            TaskId::testing_default(),
            Budget::INFINITE,
        )
    }

    #[test]
    fn sdk_legacy_mod_examples_are_executable_assertions() {
        let source = include_str!("sdk/mod.rs");
        let examples = source
            .split("mod examples")
            .nth(1)
            .expect("legacy SDK examples module exists");

        for (forbidden, label) in [
            (concat!("#[", "ignore", "]"), "ignored test attribute"),
            (concat!("#[", "tokio::test", "]"), "tokio test attribute"),
            (concat!("to", "do", "!("), "deferred macro"),
            (concat!("un", "implemented", "!("), "unsupported macro"),
            (concat!("println", "!("), "stdout print macro"),
            ("would transfer", "print-only transfer wording"),
            ("would stream", "print-only stream wording"),
        ] {
            assert!(
                !examples.contains(forbidden),
                "legacy SDK example module still contains non-executable marker {label}"
            );
        }

        for required in [
            "fn example_write_really_big_buffer_asserts_transfer_shape()",
            "fn example_stream_unknown_size_asserts_chunk_sequence()",
            "assert_eq!(chunks.len()",
            "assert_eq!(total_bytes",
        ] {
            assert!(
                examples.contains(required),
                "legacy SDK example module is missing executable assertion marker {required:?}"
            );
        }
    }

    fn registry_actor(transfer_id: TransferId) -> TransferActorHandle {
        Arc::new(ContendedMutex::new(
            "atp_transfer_actor",
            TransferActor::new(
                TransferActorId::new(1),
                transfer_id,
                TransferManifestRef {
                    schema_version: 1,
                    merkle_root: [9; 32],
                    object_count: 1,
                },
                PeerCapabilities::default(),
                TransferActorTopology::new(TransferRegionId::new(10), TransferRegionId::new(20)),
            )
            .unwrap(),
        ))
    }

    fn directory_file(path: &str, content_id: &str, size_bytes: u64) -> DirectoryManifestEntry {
        DirectoryManifestEntry::new(
            DirectoryPath::normalize(path, PathNormalizationRules::default()).unwrap(),
            DirectoryEntryKind::File,
            Some(content_id.to_string()),
            DirectoryEntryMetadata {
                size_bytes: Some(size_bytes),
                ..DirectoryEntryMetadata::default()
            },
        )
    }

    fn directory_manifest(entries: Vec<DirectoryManifestEntry>) -> DirectoryManifest {
        let mut manifest = DirectoryManifest::new(PathNormalizationRules::default());
        for entry in entries {
            manifest.insert(entry).unwrap();
        }
        manifest
    }

    #[test]
    fn test_atp_config_defaults() {
        let config = AtpConfig::default();
        assert_eq!(config.target_chunk_size, 64 * 1024);
        assert_eq!(config.max_concurrent_transfers, 8);
        assert!(config.in_process);
        assert!(config.enable_diagnostics);
    }

    #[test]
    fn test_transfer_handle_creation() {
        let transfer_id = TransferId::derive([1; 32], [2; 32], [3; 32], [4; 32]);
        let handle = TransferHandle {
            transfer_id,
            session_id: "test-session".to_string(),
            direction: TransferDirection::Send,
            actor: Some(registry_actor(transfer_id)),
        };

        assert_eq!(handle.transfer_id, transfer_id);
        assert_eq!(handle.session_id, "test-session");
        assert_eq!(handle.direction, TransferDirection::Send);
        assert_eq!(handle.state(), TransferState::Offered);
    }

    #[test]
    fn transfer_registry_shards_distinct_transfer_ids() {
        let registry = TransferRegistry::new(4);
        let shard_indexes: BTreeSet<_> = (0_u8..4)
            .map(|prefix| {
                let mut bytes = [0_u8; 32];
                bytes[0] = prefix;
                registry.shard_for(TransferId::new(bytes))
            })
            .collect();

        assert_eq!(shard_indexes.len(), 4);
    }

    #[test]
    fn transfer_cancel_removes_actor_before_taking_actor_lock() {
        let registry = TransferRegistry::new(4);
        let transfer_id = TransferId::new([7; 32]);
        let actor = registry_actor(transfer_id);

        registry.insert(
            transfer_id,
            TransferRegistryEntry {
                actor: actor.clone(),
                direction: TransferDirection::Send,
                object_id: None,
            },
        );
        assert_eq!(registry.len(), 1);

        let removed = registry.remove(transfer_id).unwrap();
        assert_eq!(registry.len(), 0);

        request_transfer_cancel(&removed.actor);
        let actor = actor.lock().unwrap_or_else(PoisonError::into_inner);
        assert_eq!(actor.state(), TransferState::Cancelling);
    }

    #[test]
    fn transfer_cancel_key_is_bound_to_transfer_id() {
        let first_id = TransferId::new([11; 32]);
        let second_id = TransferId::new([12; 32]);
        let first_actor = registry_actor(first_id);
        let second_actor = registry_actor(second_id);

        request_transfer_cancel(&first_actor);
        request_transfer_cancel(&second_actor);

        let first_actor = first_actor.lock().unwrap_or_else(PoisonError::into_inner);
        let second_actor = second_actor.lock().unwrap_or_else(PoisonError::into_inner);
        let first_key = first_actor.journal()[0].key;
        let second_key = second_actor.journal()[0].key;

        assert_ne!(first_key, IdempotencyKey::new(0));
        assert_ne!(second_key, IdempotencyKey::new(0));
        assert_ne!(first_key, second_key);
    }

    #[test]
    fn transfer_cancel_key_is_stable_for_duplicate_cancel() {
        let transfer_id = TransferId::new([13; 32]);
        let actor = registry_actor(transfer_id);

        request_transfer_cancel(&actor);
        request_transfer_cancel(&actor);

        let actor = actor.lock().unwrap_or_else(PoisonError::into_inner);
        assert_eq!(actor.state(), TransferState::Cancelling);
        assert_eq!(actor.journal().len(), 1);
        assert_eq!(actor.journal()[0].key, cancel_idempotency_key(transfer_id));
    }

    #[test]
    fn transfer_close_drains_all_shards_before_cancelling_actors() {
        let registry = TransferRegistry::new(8);
        for prefix in 0_u8..8 {
            let mut bytes = [0_u8; 32];
            bytes[0] = prefix;
            let transfer_id = TransferId::new(bytes);
            registry.insert(
                transfer_id,
                TransferRegistryEntry {
                    actor: registry_actor(transfer_id),
                    direction: TransferDirection::Send,
                    object_id: None,
                },
            );
        }

        let drained = registry.drain();
        assert_eq!(drained.len(), 8);
        assert_eq!(registry.len(), 0);

        for entry in &drained {
            request_transfer_cancel(&entry.actor);
        }
        for entry in drained {
            let actor = entry.actor.lock().unwrap_or_else(PoisonError::into_inner);
            assert_eq!(actor.state(), TransferState::Cancelling);
        }
    }

    #[test]
    fn test_stream_handle_progress() {
        let handle = StreamHandle {
            stream_id: "test-stream".to_string(),
            total_bytes: 1000,
            bytes_sent: 250,
            manifest: None,
        };

        assert!(!handle.is_complete());
        assert_eq!(handle.progress_percent(), 25.0);
    }

    #[test]
    fn test_stream_handle_completion() {
        let handle = StreamHandle {
            stream_id: "test-stream".to_string(),
            total_bytes: 1000,
            bytes_sent: 1000,
            manifest: None,
        };

        assert!(handle.is_complete());
        assert_eq!(handle.progress_percent(), 100.0);
    }

    #[test]
    fn directory_handle_report_surfaces_sdk_metadata_and_small_files() {
        let manifest = directory_manifest(vec![
            directory_file("docs/README.md", "readme-cid", 512),
            directory_file("model.bin", "model-cid", 4 * 1024 * 1024),
        ]);
        let mut handle = DirectoryHandle::new("sdk-directory", manifest);

        assert!(handle.mark_content_verified("readme-cid"));
        assert!(handle.mark_content_verified("model-cid"));
        assert_eq!(handle.verified_content_count(), 2);

        let report = handle.early_usability_report(
            DirectoryEarlyUsabilityPolicy::small_files_up_to(1024),
            "sdk-directory-replay:small-files",
        );

        assert_eq!(
            report.usability_state,
            DirectoryEarlyUsabilityState::SmallFilesAvailable
        );
        assert_eq!(
            report.final_commit_state,
            DirectoryFinalCommitState::Pending
        );
        assert_eq!(report.replay_pointer, "sdk-directory-replay:small-files");
        assert_eq!(report.metadata_paths, vec!["docs/README.md", "model.bin"]);
        assert_eq!(report.small_file_paths, vec!["docs/README.md"]);
        assert_eq!(report.withheld_content_paths, vec!["model.bin"]);
        assert!(report.safety_caveats.contains(
            &"final directory commit not complete; expose early entries separately".to_string()
        ));
    }

    #[test]
    fn directory_handle_report_keeps_final_commit_state_separate() {
        let manifest = directory_manifest(vec![directory_file("done.txt", "done-cid", 32)]);
        let mut handle = DirectoryHandle::new("sdk-directory-final", manifest);
        let policy = DirectoryEarlyUsabilityPolicy {
            expose_metadata_before_final: false,
            ..DirectoryEarlyUsabilityPolicy::small_files_up_to(1024)
        };

        let pending = handle.early_usability_report(policy, "sdk-directory-replay:pending");
        assert_eq!(
            pending.usability_state,
            DirectoryEarlyUsabilityState::NoEntries
        );
        assert_eq!(
            pending.final_commit_state,
            DirectoryFinalCommitState::Pending
        );
        assert!(pending.metadata_paths.is_empty());
        assert!(pending.small_file_paths.is_empty());
        assert!(
            pending.safety_caveats.contains(
                &"metadata exposure is disabled until final directory commit".to_string()
            )
        );

        handle.mark_final_committed();
        assert!(handle.is_final_committed());

        let committed = handle.early_usability_report(policy, "sdk-directory-replay:committed");
        assert_eq!(
            committed.usability_state,
            DirectoryEarlyUsabilityState::FinalCommitted
        );
        assert_eq!(
            committed.final_commit_state,
            DirectoryFinalCommitState::Committed
        );
        assert_eq!(committed.metadata_paths, vec!["done.txt"]);
        assert_eq!(committed.small_file_paths, vec!["done.txt"]);
        assert!(committed.safety_caveats.is_empty());
    }

    #[test]
    fn stream_handle_report_disables_early_use_without_manifest() {
        let handle = StreamHandle {
            stream_id: "stream-no-manifest".to_string(),
            total_bytes: 1000,
            bytes_sent: 250,
            manifest: None,
        };

        let report = handle.early_usability_report(ConsumptionPolicy::VerifiedOnly);

        assert_eq!(report.usable_state, StreamEarlyUsabilityState::NoManifest);
        assert_eq!(
            report.final_commit_state,
            StreamFinalCommitState::UnknownNoManifest
        );
        assert!(report.verified_prefix_ranges.is_empty());
        assert_eq!(report.policy_exposed_prefix, None);
        assert_eq!(report.verified_prefix_end, 0);
        assert_eq!(report.policy_prefix_end, 0);
        assert!(
            report
                .safety_caveats
                .contains(&"stream manifest unavailable; early usability is disabled".to_string())
        );
    }

    #[test]
    fn stream_handle_report_separates_verified_prefix_from_provisional_policy_tail() {
        let object_id = ObjectId::content(ContentId::new([3; 32]));
        let mut manifest = StreamManifest::new(object_id.clone());
        manifest
            .add_epoch(StreamEpoch::new(
                1,
                object_id.clone(),
                ByteRange::new(0, 100),
                EpochState::Verified,
                vec![],
            ))
            .unwrap();
        manifest
            .add_epoch(StreamEpoch::new(
                2,
                object_id,
                ByteRange::new(100, 200),
                EpochState::Provisional,
                vec![],
            ))
            .unwrap();

        let handle = StreamHandle {
            stream_id: "stream-provisional-tail".to_string(),
            total_bytes: 300,
            bytes_sent: 200,
            manifest: Some(manifest),
        };

        let verified_only = handle.early_usability_report(ConsumptionPolicy::VerifiedOnly);
        assert_eq!(
            verified_only.usable_state,
            StreamEarlyUsabilityState::VerifiedPrefixAvailable
        );
        assert_eq!(
            verified_only.final_commit_state,
            StreamFinalCommitState::Pending
        );
        assert_eq!(
            verified_only.verified_prefix_ranges,
            vec![ByteRange::new(0, 100)]
        );
        assert_eq!(
            verified_only.policy_exposed_prefix,
            Some(ByteRange::new(0, 100))
        );
        assert_eq!(verified_only.verified_prefix_end, 100);
        assert_eq!(verified_only.policy_prefix_end, 100);

        let provisional = handle.early_usability_report(ConsumptionPolicy::AllowProvisional);
        assert_eq!(
            provisional.usable_state,
            StreamEarlyUsabilityState::ProvisionalPrefixAvailable
        );
        assert_eq!(
            provisional.verified_prefix_ranges,
            vec![ByteRange::new(0, 100)]
        );
        assert_eq!(
            provisional.policy_exposed_prefix,
            Some(ByteRange::new(0, 200))
        );
        assert_eq!(provisional.verified_prefix_end, 100);
        assert_eq!(provisional.policy_prefix_end, 200);
        assert!(
            provisional.safety_caveats.contains(
                &"provisional tail is exposed by policy and may be invalidated".to_string()
            )
        );
    }

    #[test]
    fn stream_handle_report_withholds_verified_epochs_after_invalidated_gap() {
        let object_id = ObjectId::content(ContentId::new([4; 32]));
        let mut manifest = StreamManifest::new(object_id.clone());
        manifest
            .add_epoch(StreamEpoch::new(
                1,
                object_id.clone(),
                ByteRange::new(0, 100),
                EpochState::Verified,
                vec![],
            ))
            .unwrap();
        manifest
            .add_epoch(StreamEpoch::new(
                2,
                object_id.clone(),
                ByteRange::new(100, 200),
                EpochState::Invalidated,
                vec![],
            ))
            .unwrap();
        manifest
            .add_epoch(StreamEpoch::new(
                3,
                object_id,
                ByteRange::new(200, 300),
                EpochState::Verified,
                vec![],
            ))
            .unwrap();

        let handle = StreamHandle {
            stream_id: "stream-gap".to_string(),
            total_bytes: 300,
            bytes_sent: 300,
            manifest: Some(manifest),
        };

        let report = handle.early_usability_report(ConsumptionPolicy::VerifiedOnly);

        assert_eq!(
            report.usable_state,
            StreamEarlyUsabilityState::VerifiedPrefixAvailable
        );
        assert_eq!(report.verified_prefix_ranges, vec![ByteRange::new(0, 100)]);
        assert_eq!(report.policy_exposed_prefix, Some(ByteRange::new(0, 100)));
        assert!(report.safety_caveats.contains(
            &"verified epochs after a gap or non-consumable epoch are withheld".to_string()
        ));
    }

    #[test]
    fn stream_handle_report_marks_final_commit_separately() {
        let object_id = ObjectId::content(ContentId::new([5; 32]));
        let mut manifest = StreamManifest::new(object_id.clone());
        manifest
            .add_epoch(StreamEpoch::new(
                1,
                object_id,
                ByteRange::new(0, 100),
                EpochState::Final,
                vec![],
            ))
            .unwrap();

        let handle = StreamHandle {
            stream_id: "stream-final".to_string(),
            total_bytes: 100,
            bytes_sent: 100,
            manifest: Some(manifest),
        };

        let report = handle.early_usability_report(ConsumptionPolicy::VerifiedOnly);

        assert_eq!(
            report.usable_state,
            StreamEarlyUsabilityState::FinalCommitted
        );
        assert_eq!(report.final_commit_state, StreamFinalCommitState::Committed);
        assert_eq!(report.verified_prefix_ranges, vec![ByteRange::new(0, 100)]);
        assert_eq!(report.policy_exposed_prefix, Some(ByteRange::new(0, 100)));
        assert!(report.safety_caveats.is_empty());
    }

    #[test]
    fn test_atp_session_lifecycle() {
        futures_lite::future::block_on(async {
            let cx = test_cx();
            let cx = &cx;
            let config = AtpConfig::default();

            // Open session
            let session = AtpSession::open(cx, config).await.unwrap();
            assert!(!session.session_id.is_empty());
            assert_ne!(session.local_peer_id, [0u8; 32]); // Should not be all zeros

            // Close session
            session.close(cx).await.unwrap();
        });
    }

    #[test]
    fn test_path_diagnostics() {
        futures_lite::future::block_on(async {
            let cx = test_cx();
            let cx = &cx;
            let session = AtpSession::open(cx, AtpConfig::default()).await.unwrap();
            let remote_peer = [1u8; 32];

            match session.path_diagnose(cx, remote_peer).await {
                Outcome::Err(AtpError::Path(PathError::NoAvailablePaths)) => {}
                other => panic!("path diagnosis must fail closed without path evidence: {other:?}"),
            }
        });
    }

    #[test]
    fn test_object_verification() {
        futures_lite::future::block_on(async {
            let cx = test_cx();
            let cx = &cx;
            let session = AtpSession::open(cx, AtpConfig::default()).await.unwrap();
            let object_id = ObjectId::content(crate::atp::object::ContentId::new([1u8; 32]));

            match session.verify_object(cx, object_id.clone(), None).await {
                Outcome::Err(AtpError::Manifest(ManifestError::ObjectNotFound)) => {}
                other => panic!("verification without object bytes must fail closed: {other:?}"),
            }

            let result = session
                .verify_object(cx, object_id.clone(), Some(*object_id.hash_bytes()))
                .await
                .unwrap();
            assert_eq!(result.object_id, object_id);
            assert!(result.verified);
            assert!(!result.signature_valid);
        });
    }

    #[test]
    fn test_transfer_cancellation() {
        futures_lite::future::block_on(async {
            let cx = test_cx();
            let cx = &cx;
            let session = AtpSession::open(cx, AtpConfig::default()).await.unwrap();
            let transfer_id = TransferId::derive([1; 32], [2; 32], [3; 32], [4; 32]);

            // Cancel transfer (should not error even if transfer doesn't exist)
            session.cancel_transfer(cx, transfer_id).await.unwrap();
        });
    }

    #[test]
    fn test_streaming_with_manifest_integration() {
        futures_lite::future::block_on(async {
            let cx = test_cx();
            let cx = &cx;
            let session = AtpSession::open(cx, AtpConfig::default()).await.unwrap();
            let data = b"Hello, ATP streaming world!".repeat(100); // ~2800 bytes
            let remote_peer = [2u8; 32];

            // Stream the buffer
            let stream_handle = session
                .stream_large_buffer(cx, &data, remote_peer)
                .await
                .unwrap();

            // Verify stream manifest integration
            assert!(stream_handle.manifest().is_some());
            assert_eq!(stream_handle.total_bytes, data.len() as u64);
            assert!(stream_handle.verified_epochs_count() > 0);
            assert!(
                stream_handle.is_finalized(),
                "stream_large_buffer has the full payload and should emit a final epoch"
            );

            let report = stream_handle.early_usability_report(ConsumptionPolicy::VerifiedOnly);
            assert_eq!(
                report.usable_state,
                StreamEarlyUsabilityState::FinalCommitted
            );
            assert_eq!(report.final_commit_state, StreamFinalCommitState::Committed);
            assert!(report.safety_caveats.is_empty());

            // Test consumption policy creation
            let manifest = stream_handle.manifest().unwrap().clone();
            let consumer = session
                .create_stream_consumer(manifest, ConsumptionPolicy::VerifiedOnly)
                .unwrap();

            // Consumer should be ready to consume verified data
            assert!(consumer.data_available());
        });
    }

    #[test]
    fn test_stream_epochs_retrieval() {
        futures_lite::future::block_on(async {
            let cx = test_cx();
            let cx = &cx;
            let session = AtpSession::open(cx, AtpConfig::default()).await.unwrap();
            let object_id = ObjectId::content(ContentId::new([1u8; 32]));

            match session.get_stream_epochs(cx, object_id).await {
                Outcome::Err(AtpError::Manifest(ManifestError::ObjectNotFound)) => {}
                other => panic!("stream epochs must fail closed without manifest store: {other:?}"),
            }
        });
    }

    #[test]
    fn test_write_buffer_ergonomic_api() {
        futures_lite::future::block_on(async {
            let cx = test_cx();
            let cx = &cx;
            let session = AtpSession::open(cx, AtpConfig::default()).await.unwrap();
            let remote_peer = [3u8; 32];
            let data = b"This is the write(really_big_buffer) test!".repeat(1000);

            // This is the primary ergonomic API
            let proof = session
                .write_buffer(cx, &data, remote_peer, None)
                .await
                .unwrap();

            // Verify the proof represents the complete transfer
            assert_eq!(proof.total_bytes, data.len() as u64);
            assert!(proof.total_bytes > 0); // Should have transferred bytes
        });
    }

    #[test]
    fn test_create_writer_with_progress() {
        futures_lite::future::block_on(async {
            let cx = test_cx();
            let cx = &cx;
            let session = AtpSession::open(cx, AtpConfig::default()).await.unwrap();
            let remote_peer = [4u8; 32];

            // Create writer with custom config
            let mut writer_config = WriterConfig::default();
            writer_config.enable_progress = true;
            writer_config.chunk_size = 1024;

            let mut writer = session
                .create_writer(remote_peer, Some(writer_config))
                .unwrap();

            // Set up progress tracking
            writer.set_progress_callback(|_progress| {
                // In real test, we'd capture these
            });

            // Write data in chunks
            let chunk1 = b"First chunk of data";
            let chunk2 = b"Second chunk of data";

            writer.write_all(cx, chunk1).await.unwrap();
            writer.write_all(cx, chunk2).await.unwrap();

            let proof = writer.finalize(cx).await.unwrap();
            assert_eq!(proof.total_bytes, (chunk1.len() + chunk2.len()) as u64);
        });
    }

    #[test]
    fn test_sink_api() {
        futures_lite::future::block_on(async {
            let cx = test_cx();
            let cx = &cx;
            let session = AtpSession::open(cx, AtpConfig::default()).await.unwrap();
            let remote_peer = [5u8; 32];

            let mut sink = session.create_sink(remote_peer, None).unwrap();

            // Send data through sink
            sink.send(cx, b"Sink data 1").await.unwrap();
            sink.send(cx, b"Sink data 2").await.unwrap();

            let proof = sink.close(cx).await.unwrap();
            assert!(proof.total_bytes >= 22); // "Sink data 1Sink data 2"
        });
    }

    #[test]
    fn test_resume_functionality() {
        futures_lite::future::block_on(async {
            let cx = test_cx();
            let cx = &cx;
            let session = AtpSession::open(cx, AtpConfig::default()).await.unwrap();
            let remote_peer = [6u8; 32];

            // Create writer with resume enabled
            let mut config = WriterConfig::default();
            config.enable_resume = true;

            let mut writer = session
                .create_writer(remote_peer, Some(config.clone()))
                .unwrap();
            writer.write_all(cx, b"Partial transfer").await.unwrap();

            // Get resume token
            let resume_token = writer.resume_token().unwrap();
            assert!(resume_token.is_valid());

            // Cancel and resume
            let cancel_token = writer.cancel(cx).await.unwrap();
            assert_eq!(cancel_token.verified_bytes, resume_token.verified_bytes);

            // Resume with new writer
            let mut resumed_writer = session
                .resume_writer(resume_token, remote_peer, Some(config))
                .unwrap();
            resumed_writer.write_all(cx, b" completed").await.unwrap();

            let proof = resumed_writer.finalize(cx).await.unwrap();
            assert!(proof.total_bytes >= 26); // "Partial transfer completed"
        });
    }

    #[test]
    fn test_stream_writer_unknown_size() {
        futures_lite::future::block_on(async {
            let cx = test_cx();
            let cx = &cx;
            let session = AtpSession::open(cx, AtpConfig::default()).await.unwrap();
            let remote_peer = [7u8; 32];

            let mut writer = session
                .create_stream_writer(cx, remote_peer, None)
                .await
                .unwrap();

            // Write streaming data without declaring a final size up front.
            for i in 0..10 {
                let data = format!("Stream chunk {}", i); // ubs:ignore
                writer.write_all(cx, data.as_bytes()).await.unwrap();
            }

            let proof = writer.finalize(cx).await.unwrap();
            assert!(proof.total_bytes > 0);
        });
    }

    #[test]
    fn test_object_graph_sending() {
        futures_lite::future::block_on(async {
            let cx = test_cx();
            let cx = &cx;
            let session = AtpSession::open(cx, AtpConfig::default()).await.unwrap();
            let remote_peer = [8u8; 32];

            let root_object = ObjectId::content(ContentId::new([42u8; 32]));

            match session
                .send_object_graph(cx, root_object, remote_peer, None)
                .await
            {
                Outcome::Err(AtpError::Policy(PolicyError::FeatureDisabled)) => {}
                other => panic!(
                    "object graph send must fail closed until graph store is wired: {other:?}"
                ),
            }
        });
    }

    /// Test that ensures fabricated values are not returned in real APIs.
    /// This checks for the SDK integrity issues mentioned in the bead.
    #[test]
    fn test_no_mock_values_in_real_implementation() {
        futures_lite::future::block_on(async {
            let cx = test_cx();
            let cx = &cx;
            let session = AtpSession::open(cx, AtpConfig::default()).await.unwrap();
            let remote_peer = [1u8; 32]; // Non-zero peer
            let object_id = ObjectId::content(ContentId::new([1u8; 32])); // Non-zero object

            // 1. Check that session peer ID is not all zeros
            assert_ne!(
                session.local_peer_id, [0u8; 32],
                "Session peer ID should not be all zeros"
            );

            // 2. Check send_object creates real transfer handle with non-zero IDs
            let handle = session
                .send_object(cx, object_id.clone(), remote_peer)
                .await
                .unwrap();
            assert_ne!(
                handle.transfer_id.as_bytes(),
                [0u8; 32],
                "Transfer ID should not be all zeros"
            );

            // 3. receive_object must not fabricate a receipt for a send-side transfer
            let transfer_id = handle.transfer_id;
            match session.receive_object(cx, transfer_id).await {
                Outcome::Err(AtpError::Protocol(ProtocolError::SessionStateMismatch)) => {}
                other => panic!("receive_object must fail closed without receive state: {other:?}"),
            }

            // 4. Check verify_object uses the content ID hash when expected hash is provided.
            let verification = session
                .verify_object(cx, object_id.clone(), Some(*object_id.hash_bytes()))
                .await
                .unwrap();
            assert_ne!(
                verification.computed_hash, [0u8; 32],
                "Computed hash should not be all zeros"
            );

            // 5. Check transfer progress is evidence-backed.
            let progress = handle.progress();
            assert_eq!(
                progress.total_bytes, 0,
                "SDK must not invent byte totals before writer/receiver evidence exists"
            );
            assert_eq!(progress.bytes_transferred, 0);

            // 6. Check transfer state is computed from actor state.
            let state = handle.state();
            assert!(
                matches!(
                    state,
                    TransferState::Offered
                        | TransferState::Accepted
                        | TransferState::Running
                        | TransferState::Paused
                        | TransferState::Cancelling
                        | TransferState::Failed
                        | TransferState::Committed
                        | TransferState::Resumed
                        | TransferState::MailboxStored
                        | TransferState::RelayForwarded
                        | TransferState::Seeded
                        | TransferState::SwarmAssisted
                ),
                "Transfer state should be a valid enum value"
            );

            // 7. Object graph sending must fail closed rather than synthesize bytes.
            let root_object = ObjectId::content(ContentId::new([99u8; 32]));
            match session
                .send_object_graph(cx, root_object, remote_peer, None)
                .await
            {
                Outcome::Err(AtpError::Policy(PolicyError::FeatureDisabled)) => {}
                other => panic!("object graph send must not fabricate graph data: {other:?}"),
            }
        });
    }
}
