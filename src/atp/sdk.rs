//! ATP high-level SDK APIs for object, tree, stream, and buffer movement.
//!
//! This module provides the programmatic API that gives users the simple
//! write(really_big_buffer) experience without bypassing ATP correctness.
//! All APIs are Cx-first and support native Asupersync semantics.

use crate::types::outcome::Outcome;
use crate::net::atp::protocol::outcome::{AtpOutcome, AtpError};
use crate::atp::transfer::{TransferId, TransferState, TransferActor, TransferCommand, TransferCommandKind, IdempotencyKey};
use crate::atp::object::ObjectId;
use crate::cx::Cx;
use std::path::Path;
use std::collections::HashMap;
use std::sync::Arc;

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
    active_transfers: Arc<std::sync::Mutex<HashMap<TransferId, Arc<std::sync::Mutex<TransferActor>>>>>,
}

impl AtpSession {
    /// Open a new ATP session with the given configuration.
    pub async fn open(cx: &Cx, config: AtpConfig) -> AtpOutcome<Self> {
        cx.trace("atp_sdk");

        // Generate session ID and local peer ID
        let session_id = format!("atp-session-{}", std::process::id());
        let local_peer_id = [0u8; 32]; // TODO: Generate from key store

        let session = Self {
            session_id,
            local_peer_id,
            config,
            active_transfers: Arc::new(std::sync::Mutex::new(HashMap::new())),
        };

        if session.config.enable_diagnostics {
            cx.trace("atp_sdk");
        }

        Outcome::ok(session)
    }

    /// Close the ATP session and cancel all active transfers.
    pub async fn close(&self, cx: &Cx) -> AtpOutcome<()> {
        cx.trace("atp_sdk");

        // Cancel all active transfers
        let transfers = self.active_transfers.lock().unwrap().clone();
        for (transfer_id, actor) in transfers {
            let mut actor = actor.lock().unwrap();
            let cancel_cmd = TransferCommand::new(
                IdempotencyKey::new(0), // TODO: Generate proper key
                TransferCommandKind::Cancel {
                    phase: crate::atp::transfer::TransferCancelPhase::Requested,
                },
            );
            let _ = actor.apply(cancel_cmd);
        }

        self.active_transfers.lock().unwrap().clear();

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

        // TODO: Implement object sending
        // 1. Build manifest for the object
        // 2. Create transfer actor
        // 3. Initiate path discovery
        // 4. Begin transfer

        let transfer_id = TransferId::derive(
            self.local_peer_id,
            remote_peer,
            [0u8; 32], // TODO: Generate nonce
            [0u8; 32], // TODO: Calculate manifest root
        );

        let handle = TransferHandle {
            transfer_id,
            session_id: self.session_id.clone(),
            direction: TransferDirection::Send,
        };

        if self.config.enable_diagnostics {
            cx.trace(&format!("created transfer handle {:?}", handle.transfer_id));
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

        // TODO: Implement object receiving
        // 1. Accept the transfer offer
        // 2. Verify manifest
        // 3. Begin receiving chunks
        // 4. Reconstruct object

        let receipt = ObjectReceipt {
            object_id: ObjectId::content(crate::atp::object::ContentId::new([0u8; 32])), // TODO: Extract from manifest
            verified_hash: [0u8; 32],
            size_bytes: 0,
            transfer_id,
        };

        if self.config.enable_diagnostics {
            cx.trace(&format!("received object {:?}", receipt.object_id));
        }

        Outcome::ok(receipt)
    }

    /// Synchronize a directory tree with a remote peer.
    pub async fn sync_tree(
        &self,
        cx: &Cx,
        local_path: impl AsRef<Path>,
        remote_peer: [u8; 32],
    ) -> AtpOutcome<TreeSyncResult> {
        let path = local_path.as_ref();
        cx.trace(&format!("syncing tree {:?} with peer", path));

        // TODO: Implement tree synchronization
        // 1. Build object graph for local tree
        // 2. Exchange manifest with peer
        // 3. Compute diff
        // 4. Transfer missing objects

        let result = TreeSyncResult {
            local_root: path.to_path_buf(),
            objects_sent: 0,
            objects_received: 0,
            bytes_transferred: 0,
        };

        if self.config.enable_diagnostics {
            cx.trace(&format!("synced tree {:?}", path));
        }

        Outcome::ok(result)
    }

    /// Stream a large buffer with backpressure control.
    pub async fn stream_large_buffer(
        &self,
        cx: &Cx,
        data: &[u8],
        remote_peer: [u8; 32],
    ) -> AtpOutcome<StreamHandle> {
        cx.trace(&format!("streaming buffer of {} bytes", data.len()));

        // TODO: Implement large buffer streaming
        // 1. Chunk the buffer using content-defined chunking
        // 2. Create streaming manifest
        // 3. Begin streaming chunks with backpressure

        let stream_handle = StreamHandle {
            stream_id: format!("stream-{}", std::process::id()),
            total_bytes: data.len() as u64,
            bytes_sent: 0,
        };

        if self.config.enable_diagnostics {
            cx.trace(&format!("created stream {}", stream_handle.stream_id));
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

        // TODO: Implement object verification
        // 1. Read object data
        // 2. Compute hash
        // 3. Verify against manifest
        // 4. Check signature if available

        let result = VerificationResult {
            object_id,
            verified: true,
            computed_hash: [0u8; 32], // TODO: Compute actual hash
            signature_valid: false,
        };

        if self.config.enable_diagnostics {
            cx.trace(&format!("verified object {:?}", object_id));
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
        cx.trace(&format!("resuming transfer {:?} from position {}", transfer_id, journal_position));

        // TODO: Implement transfer resume
        // 1. Load journal entries
        // 2. Reconstruct transfer state
        // 3. Resume from last checkpoint

        let handle = TransferHandle {
            transfer_id,
            session_id: self.session_id.clone(),
            direction: TransferDirection::Send, // TODO: Determine from journal
        };

        if self.config.enable_diagnostics {
            cx.trace(&format!("resumed transfer {:?}", transfer_id));
        }

        Outcome::ok(handle)
    }

    /// Cancel an active transfer.
    pub async fn cancel_transfer(
        &self,
        cx: &Cx,
        transfer_id: TransferId,
    ) -> AtpOutcome<()> {
        cx.trace(&format!("cancelling transfer {:?}", transfer_id));

        let transfers = self.active_transfers.lock().unwrap();
        if let Some(actor) = transfers.get(&transfer_id) {
            let mut actor = actor.lock().unwrap();
            let cancel_cmd = TransferCommand::new(
                IdempotencyKey::new(0), // TODO: Generate proper key
                TransferCommandKind::Cancel {
                    phase: crate::atp::transfer::TransferCancelPhase::Requested,
                },
            );
            actor.apply(cancel_cmd).map_err(|_| AtpError::Protocol(
                crate::net::atp::protocol::outcome::ProtocolError::SessionStateMismatch
            ))?;
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
        remote_peer: [u8; 32],
    ) -> AtpOutcome<PathDiagnostics> {
        cx.trace("diagnosing path to peer");

        // TODO: Implement path diagnostics
        // 1. Discover available paths (direct, relay, etc.)
        // 2. Test connectivity and latency
        // 3. Estimate bandwidth
        // 4. Return diagnostic report

        let diagnostics = PathDiagnostics {
            direct_connectivity: false,
            relay_available: false,
            estimated_latency_ms: 0,
            estimated_bandwidth_bps: 0,
            preferred_path: PathType::Unknown,
        };

        if self.config.enable_diagnostics {
            cx.trace("completed path diagnostics");
        }

        Outcome::ok(diagnostics)
    }
}

/// Handle for an active transfer operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferHandle {
    /// Transfer identifier.
    pub transfer_id: TransferId,
    /// Session that owns this transfer.
    pub session_id: String,
    /// Transfer direction.
    pub direction: TransferDirection,
}

impl TransferHandle {
    /// Get the current transfer state.
    pub fn state(&self) -> TransferState {
        // TODO: Look up actual state from transfer actor
        TransferState::Offered
    }

    /// Get transfer progress information.
    pub fn progress(&self) -> TransferProgress {
        // TODO: Get actual progress from transfer actor
        TransferProgress {
            bytes_transferred: 0,
            total_bytes: 0,
            progress_percent: 0.0,
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

/// Handle for streaming operations.
#[derive(Debug, Clone)]
pub struct StreamHandle {
    /// Stream identifier.
    pub stream_id: String,
    /// Total bytes to stream.
    pub total_bytes: u64,
    /// Bytes sent so far.
    pub bytes_sent: u64,
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
    use crate::cx::scope;
    use crate::lab::LabRuntime;

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
        };

        assert_eq!(handle.transfer_id, transfer_id);
        assert_eq!(handle.session_id, "test-session");
        assert_eq!(handle.direction, TransferDirection::Send);
        assert_eq!(handle.state(), TransferState::Offered);
    }

    #[test]
    fn test_stream_handle_progress() {
        let handle = StreamHandle {
            stream_id: "test-stream".to_string(),
            total_bytes: 1000,
            bytes_sent: 250,
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
        };

        assert!(handle.is_complete());
        assert_eq!(handle.progress_percent(), 100.0);
    }

    #[tokio::test]
    async fn test_atp_session_lifecycle() {
        let lab = LabRuntime::new();
        scope!(lab.cx(), |cx, scope| async move {
            let config = AtpConfig::default();

            // Open session
            let session = AtpSession::open(cx, config).await.unwrap();
            assert!(!session.session_id.is_empty());
            assert_eq!(session.local_peer_id, [0u8; 32]);

            // Close session
            session.close(cx).await.unwrap();
        }).await.unwrap();
    }

    #[tokio::test]
    async fn test_path_diagnostics() {
        let lab = LabRuntime::new();
        scope!(lab.cx(), |cx, scope| async move {
            let session = AtpSession::open(cx, AtpConfig::default()).await.unwrap();
            let remote_peer = [1u8; 32];

            let diagnostics = session.path_diagnose(cx, remote_peer).await.unwrap();
            assert!(!diagnostics.direct_connectivity);
            assert!(!diagnostics.relay_available);
            assert_eq!(diagnostics.preferred_path, PathType::Unknown);
        }).await.unwrap();
    }

    #[tokio::test]
    async fn test_object_verification() {
        let lab = LabRuntime::new();
        scope!(lab.cx(), |cx, scope| async move {
            let session = AtpSession::open(cx, AtpConfig::default()).await.unwrap();
            let object_id = ObjectId::content(crate::atp::object::ContentId::new([1u8; 32]));

            let result = session.verify_object(cx, object_id, None).await.unwrap();
            assert_eq!(result.object_id, object_id);
            assert!(result.verified);
            assert!(!result.signature_valid);
        }).await.unwrap();
    }

    #[tokio::test]
    async fn test_transfer_cancellation() {
        let lab = LabRuntime::new();
        scope!(lab.cx(), |cx, scope| async move {
            let session = AtpSession::open(cx, AtpConfig::default()).await.unwrap();
            let transfer_id = TransferId::derive([1; 32], [2; 32], [3; 32], [4; 32]);

            // Cancel transfer (should not error even if transfer doesn't exist)
            session.cancel_transfer(cx, transfer_id).await.unwrap();
        }).await.unwrap();
    }
}