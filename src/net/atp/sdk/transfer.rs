//! ATP transfer operations and management.

#![allow(dead_code)]

use super::{AtpSession, SdkMode, TransferId, TransferPhase, TransferProgress};
use crate::cx::{Cx, Scope};
use crate::net::atp::protocol::{
    AtpError, AtpOutcome, DiskError, IdempotencyKey, PlatformError, ProtocolError,
};
use serde::{Deserialize, Serialize};
use std::future::{Future, poll_fn};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, Waker};

use crate::runtime::{JoinError, SpawnError, TaskHandle};
use crate::types::{CancelReason, PanicPayload, Policy};

const OBJECT_SIGNATURE_ALGORITHM: &str = "asupersync-atp-object-hmac-sha256-v1";
const OBJECT_SIGNATURE_DOMAIN: &[u8] = b"asupersync::net::atp::sdk::object-signature::v1";

/// Transfer request for sending objects/files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferRequest {
    /// Source data to transfer.
    pub source: TransferSource,
    /// Destination for the transfer.
    pub destination: TransferDestination,
    /// Optional transfer options.
    pub options: TransferOptions,
}

/// Source data for a transfer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransferSource {
    /// Transfer a single file.
    File {
        /// Path to the source file.
        path: PathBuf,
    },
    /// Transfer a directory tree.
    Directory {
        /// Path to the source directory.
        path: PathBuf,
        /// Whether to follow symbolic links.
        follow_symlinks: bool,
    },
    /// Transfer application-defined object data.
    Object {
        /// Object data as bytes.
        data: Vec<u8>,
        /// MIME type or content type hint.
        content_type: Option<String>,
    },
    /// Transfer from a stream/buffer.
    Stream {
        /// Total size if known.
        size_hint: Option<u64>,
        /// Content type hint.
        content_type: Option<String>,
    },
}

/// Destination for a transfer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransferDestination {
    /// Save to a file path.
    File {
        /// Destination file path.
        path: PathBuf,
    },
    /// Save to a directory.
    Directory {
        /// Destination directory path.
        path: PathBuf,
    },
    /// Store as application-defined object.
    Object {
        /// Object identifier.
        object_id: String,
    },
    /// Stream to application callback.
    Stream,
}

/// Transfer options and configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferOptions {
    /// Custom transfer ID.
    pub transfer_id: Option<TransferId>,
    /// Idempotency key for safe retries.
    pub idempotency_key: Option<IdempotencyKey>,
    /// Custom timeout in milliseconds.
    pub timeout_ms: Option<u64>,
    /// Progress reporting callback interval.
    pub progress_interval_ms: Option<u64>,
    /// Enable compression for this transfer.
    pub enable_compression: Option<bool>,
    /// Enable repair symbols.
    pub enable_repair: Option<bool>,
    /// Resume from previous partial transfer.
    pub resume_from_checkpoint: Option<String>,
    /// Custom chunk size.
    pub chunk_size_bytes: Option<u32>,
    /// Transfer priority (0=low, 10=high).
    pub priority: Option<u8>,
}

impl Default for TransferOptions {
    fn default() -> Self {
        Self {
            transfer_id: None,
            idempotency_key: None,
            timeout_ms: None,
            progress_interval_ms: None,
            enable_compression: None,
            enable_repair: None,
            resume_from_checkpoint: None,
            chunk_size_bytes: None,
            priority: Some(5), // Medium priority
        }
    }
}

/// Active transfer handle.
#[derive(Debug)]
pub struct ActiveTransfer {
    /// Transfer identifier.
    transfer_id: TransferId,
    /// The actual runtime worker, retained until its canonical join completes.
    worker: TaskHandle<()>,
    shared: Arc<parking_lot::Mutex<TransferShared>>,
    terminal: Option<TransferTerminal>,
    terminal_progress_taken: bool,
    /// Whether cancellation has already been requested through this handle.
    cancel_requested: AtomicBool,
    /// Transfer configuration.
    options: TransferOptions,
}

/// Lifecycle of the owned worker. Progress observations do not advance it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ActiveTransferState {
    /// Runtime admission was requested; the worker has not started polling.
    Pending,
    /// The worker has started but has not yet joined.
    Running,
    /// The actual worker joined and its terminal evidence is retained.
    Terminal,
}

/// One coalesced, nonterminal diagnostic update.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct TransferProgressSnapshot {
    /// Monotonically increasing publication sequence, starting at one.
    pub sequence: u64,
    /// Earlier updates replaced since the preceding update was consumed.
    pub skipped: u64,
    /// The most recent nonterminal observation.
    pub progress: TransferProgress,
}

/// Independent terminal facts, available only after the owned worker joins.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct TransferTerminal {
    /// Effective result: panic outranks cancellation, which outranks errors.
    /// Equal-severity worker attribution is retained.
    pub outcome: AtpOutcome<TransferProgress>,
    /// The worker's original returned result or caught poll panic, if it ran.
    /// This may be absent if runtime admission or execution terminated first.
    pub worker_outcome: Option<AtpOutcome<TransferProgress>>,
    /// A separately caught panic while destroying the worker future or an
    /// unstarted factory rejected before runtime admission.
    /// A primary worker panic retains precedence over this secondary panic.
    pub cleanup_panic: Option<PanicPayload>,
    /// The actual runtime task's canonical terminal result.
    pub worker_join: Result<(), JoinError>,
}

/// A rejected optional progress observation. No rejection changes the worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TransferProgressError {
    /// The observation belongs to another transfer.
    #[error("progress transfer identity does not match its owner")]
    IdentityMismatch,
    /// Terminal facts must be returned by the worker, not by this reporter.
    #[error("progress reporting cannot publish a terminal result")]
    TerminalPhase,
    /// Observed bytes exceed a nonzero declared total. A zero total permits
    /// unknown-size streaming progress until the worker knows the final size.
    #[error("progress bytes exceed the declared transfer size")]
    InvalidByteCount,
    /// The bounded sequence representation cannot accept another update.
    #[error("progress sequence exhausted")]
    SequenceExhausted,
    /// The handle was dropped or the worker has already returned.
    #[error("progress observation is closed")]
    Closed,
}

/// Optional diagnostics for an admitted transfer worker.
///
/// Clones share one latest-update slot. Reporting never waits for a subscriber
/// or capacity, and cannot publish completion. Dropping every reporter does
/// not terminate the worker or its transfer handle.
#[derive(Debug, Clone)]
pub struct TransferProgressReporter {
    transfer_id: TransferId,
    shared: std::sync::Weak<parking_lot::Mutex<TransferShared>>,
}

#[derive(Debug, Default)]
struct TransferShared {
    started: bool,
    closed: bool,
    sequence: u64,
    pending: Option<TransferProgressSnapshot>,
    last_progress: Option<TransferProgress>,
    worker_outcome: Option<AtpOutcome<TransferProgress>>,
    cleanup_panic: Option<PanicPayload>,
    // Arc cloning is callback-free under the lock. Waker clone/drop/wake are
    // arbitrary user code and always happen after unlocking.
    waiter: Option<Arc<Waker>>,
}

// The runtime may reject an enqueued spawn without ever polling its adapter.
// Its rejection path destroys the payload before resolving the canonical join.
// Keep arbitrary factory-capture destruction from unwinding past that receipt.
struct PendingTransferFactory<F> {
    factory: Option<F>,
    shared: Arc<parking_lot::Mutex<TransferShared>>,
}

impl<F> PendingTransferFactory<F> {
    fn take(&mut self) -> F {
        self.factory.take().expect("transfer factory invoked once")
    }
}

impl<F> Drop for PendingTransferFactory<F> {
    fn drop(&mut self) {
        if let Some(factory) = self.factory.take()
            && let Err(payload) = catch_unwind(AssertUnwindSafe(|| drop(factory)))
        {
            let panic = transfer_worker_panic(payload);
            // Canonical admission rejection will wake the joining owner.
            // Do not invoke an arbitrary observer while dropping a request.
            self.shared.lock().cleanup_panic.get_or_insert(panic);
        }
    }
}

impl TransferProgressReporter {
    /// Publish the newest nonterminal observation without waiting for a reader.
    ///
    /// # Errors
    /// Rejects another transfer's identity, terminal phases, impossible byte
    /// counts, exhausted sequence numbers, and a retired observation path.
    pub fn report(&self, progress: TransferProgress) -> Result<u64, TransferProgressError> {
        if progress.transfer_id != self.transfer_id {
            return Err(TransferProgressError::IdentityMismatch);
        }
        if progress.is_complete() {
            return Err(TransferProgressError::TerminalPhase);
        }
        if progress.total_bytes != 0 && progress.bytes_transferred > progress.total_bytes {
            return Err(TransferProgressError::InvalidByteCount);
        }
        let shared = self.shared.upgrade().ok_or(TransferProgressError::Closed)?;
        let (sequence, wake) = {
            let mut state = shared.lock();
            if state.closed || state.worker_outcome.is_some() {
                return Err(TransferProgressError::Closed);
            }
            let sequence = state
                .sequence
                .checked_add(1)
                .ok_or(TransferProgressError::SequenceExhausted)?;
            let skipped = state.pending.as_ref().map_or(0, |old| old.skipped + 1);
            state.last_progress = Some(progress.clone());
            state.pending = Some(TransferProgressSnapshot {
                sequence,
                skipped,
                progress,
            });
            state.sequence = sequence;
            (sequence, state.waiter.take())
        };
        if let Some(wake) = wake {
            wake.wake_by_ref();
        }
        Ok(sequence)
    }
}

impl AtpSession {
    /// Send an object to the remote peer.
    pub async fn send_object(
        &self,
        cx: &Cx,
        request: TransferRequest,
    ) -> AtpOutcome<ActiveTransfer> {
        match &self.mode {
            SdkMode::InProcess => self.send_object_in_process(cx, request).await,
            SdkMode::DaemonDelegated { .. } => self.send_object_daemon_delegated(cx, request).await,
        }
    }

    /// Receive an object from the remote peer.
    pub async fn receive_object(
        &self,
        cx: &Cx,
        destination: TransferDestination,
        options: TransferOptions,
    ) -> AtpOutcome<ActiveTransfer> {
        match &self.mode {
            SdkMode::InProcess => {
                self.receive_object_in_process(cx, destination, options)
                    .await
            }
            SdkMode::DaemonDelegated { .. } => {
                self.receive_object_daemon_delegated(cx, destination, options)
                    .await
            }
        }
    }

    /// Synchronize a directory tree with the remote peer.
    pub async fn sync_tree(
        &self,
        cx: &Cx,
        local_path: &Path,
        remote_path: &str,
        options: TransferOptions,
    ) -> AtpOutcome<ActiveTransfer> {
        let source = TransferSource::Directory {
            path: local_path.to_path_buf(),
            follow_symlinks: false,
        };
        let destination = TransferDestination::Directory {
            path: PathBuf::from(remote_path),
        };
        let request = TransferRequest {
            source,
            destination,
            options,
        };

        self.send_object(cx, request).await
    }

    /// Stream a large buffer to the remote peer with backpressure handling.
    pub async fn stream_large_buffer(
        &self,
        cx: &Cx,
        buffer: Vec<u8>,
        destination: TransferDestination,
        options: TransferOptions,
    ) -> AtpOutcome<ActiveTransfer> {
        let source = TransferSource::Object {
            data: buffer,
            content_type: Some("application/octet-stream".to_string()),
        };
        let request = TransferRequest {
            source,
            destination,
            options,
        };

        self.send_object(cx, request).await
    }

    /// Check an object's hash and the legacy session-bound sidecar checksum.
    ///
    /// The v1 sidecar derives its HMAC key from public session fields. A matching
    /// sidecar does not authenticate a peer or establish who produced the object,
    /// even when the legacy `verified` and `signature_valid` fields are true.
    /// Do not use this result as an authorization decision. An expected hash
    /// must come from an independently trusted source to establish integrity.
    pub async fn verify_object(
        &self,
        cx: &Cx,
        object_path: &Path,
        expected_hash: Option<&[u8]>,
    ) -> AtpOutcome<ObjectVerification> {
        match &self.mode {
            SdkMode::InProcess => {
                self.verify_object_in_process(cx, object_path, expected_hash)
                    .await
            }
            SdkMode::DaemonDelegated { .. } => {
                self.verify_object_daemon_delegated(cx, object_path, expected_hash)
                    .await
            }
        }
    }

    /// Resume a previously interrupted transfer.
    pub async fn resume_transfer(
        &self,
        cx: &Cx,
        transfer_id: &TransferId,
        checkpoint: &str,
    ) -> AtpOutcome<ActiveTransfer> {
        match &self.mode {
            SdkMode::InProcess => {
                self.resume_transfer_in_process(cx, transfer_id, checkpoint)
                    .await
            }
            SdkMode::DaemonDelegated { .. } => {
                self.resume_transfer_daemon_delegated(cx, transfer_id, checkpoint)
                    .await
            }
        }
    }

    /// Cancel an active transfer.
    pub async fn cancel_transfer(
        &self,
        cx: &Cx,
        transfer_id: &TransferId,
        reason: Option<String>,
    ) -> AtpOutcome<()> {
        match &self.mode {
            SdkMode::InProcess => {
                self.cancel_transfer_in_process(cx, transfer_id, reason)
                    .await
            }
            SdkMode::DaemonDelegated { .. } => {
                self.cancel_transfer_daemon_delegated(cx, transfer_id, reason)
                    .await
            }
        }
    }

    // In-process implementations
    async fn send_object_in_process(
        &self,
        cx: &Cx,
        request: TransferRequest,
    ) -> AtpOutcome<ActiveTransfer> {
        if cx.checkpoint().is_err() {
            return AtpOutcome::Err(AtpError::Platform(PlatformError::OperatingSystemError));
        }

        // Validate source data exists and is accessible
        match self.validate_transfer_source(&request.source).await {
            AtpOutcome::Ok(_) => {}
            AtpOutcome::Err(e) => return AtpOutcome::Err(e),
            AtpOutcome::Cancelled(reason) => return AtpOutcome::Cancelled(reason),
            AtpOutcome::Panicked(p) => return AtpOutcome::Panicked(p),
        }

        AtpOutcome::Err(AtpError::Protocol(ProtocolError::NotImplemented))
    }

    async fn receive_object_in_process(
        &self,
        cx: &Cx,
        destination: TransferDestination,
        options: TransferOptions,
    ) -> AtpOutcome<ActiveTransfer> {
        let transfer_id = options
            .transfer_id
            .clone()
            .unwrap_or_else(TransferId::generate);
        if cx.checkpoint().is_err() {
            return AtpOutcome::Err(AtpError::Platform(PlatformError::OperatingSystemError));
        }

        match &destination {
            TransferDestination::File { path } => {
                if let Some(parent) = path.parent() {
                    if !parent.exists() {
                        return AtpOutcome::Err(AtpError::Disk(DiskError::DirectoryNotFound));
                    }
                }
            }
            TransferDestination::Directory { path } => {
                if !path.exists() {
                    return AtpOutcome::Err(AtpError::Disk(DiskError::DirectoryNotFound));
                }
            }
            TransferDestination::Object { .. } | TransferDestination::Stream => {
                // Valid for in-memory destinations
            }
        }

        let _ = (transfer_id, options);
        AtpOutcome::Err(AtpError::Protocol(ProtocolError::NotImplemented))
    }

    async fn verify_object_in_process(
        &self,
        _cx: &Cx,
        object_path: &Path,
        expected_hash: Option<&[u8]>,
    ) -> AtpOutcome<ObjectVerification> {
        if !object_path.exists() {
            return AtpOutcome::Err(AtpError::Disk(DiskError::FileNotFound));
        }

        // Get file metadata
        let metadata = match crate::fs::metadata(object_path).await {
            Ok(meta) => meta,
            Err(_) => return AtpOutcome::Err(AtpError::Disk(DiskError::IoError)),
        };

        let size_bytes = metadata.len();

        // Read file contents for hash computation
        let file_contents = match crate::fs::read(object_path).await {
            Ok(data) => data,
            Err(_) => return AtpOutcome::Err(AtpError::Disk(DiskError::IoError)),
        };

        // Compute SHA-256 hash using proper cryptographic hash
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(&file_contents);
        let computed_hash: [u8; 32] = hasher.finalize().into();

        let mut integrity_check_passed = true;

        // Compare with expected hash if provided
        if let Some(expected) = expected_hash {
            use subtle::ConstantTimeEq;
            if !bool::from(computed_hash.ct_eq(expected)) {
                // ubs:ignore - using constant time eq
                integrity_check_passed = false;
            }
        }

        // Additional integrity checks
        // Check for zero-length files (might indicate corruption)
        if size_bytes == 0 && !object_path.to_string_lossy().contains("empty") {
            integrity_check_passed = false;
        }

        // Basic corruption detection: check for patterns that suggest truncation
        if file_contents.len() > 100 {
            let last_bytes = &file_contents[file_contents.len() - 10..];
            if last_bytes.iter().all(|&b| b == 0) && file_contents.len() % 512 == 0 {
                // Suspicious: ends with zeros and is block-aligned
                integrity_check_passed = false;
            }
        }

        let signature_valid = self
            .verify_detached_object_signature(object_path, &computed_hash, size_bytes)
            .await;
        let verified = integrity_check_passed && signature_valid == Some(true);

        AtpOutcome::Ok(ObjectVerification {
            path: object_path.to_path_buf(),
            hash: computed_hash.to_vec(),
            size_bytes,
            verified,
            integrity_check_passed,
            signature_valid,
        })
    }

    async fn resume_transfer_in_process(
        &self,
        cx: &Cx,
        transfer_id: &TransferId,
        checkpoint: &str,
    ) -> AtpOutcome<ActiveTransfer> {
        if cx.checkpoint().is_err() {
            return AtpOutcome::Err(AtpError::Platform(PlatformError::OperatingSystemError));
        }

        // Parse checkpoint data as "bytes_transferred:total_bytes:phase" format
        let parts: Vec<&str> = checkpoint.split(':').collect();
        if parts.len() < 2 {
            return AtpOutcome::Err(AtpError::Protocol(ProtocolError::MalformedFrame));
        }

        let bytes_transferred = match parts[0].parse::<u64>() {
            Ok(value) => value,
            Err(_) => return AtpOutcome::Err(AtpError::Protocol(ProtocolError::MalformedFrame)),
        };
        let total_bytes = match parts[1].parse::<u64>() {
            Ok(value) => value,
            Err(_) => return AtpOutcome::Err(AtpError::Protocol(ProtocolError::MalformedFrame)),
        };
        let phase_str = if parts.len() >= 3 {
            parts[2]
        } else {
            "data_transfer"
        };

        let resume_phase = match phase_str {
            "initializing" => TransferPhase::Initializing,
            "path_discovery" => TransferPhase::PathDiscovery,
            "session_negotiation" => TransferPhase::SessionNegotiation,
            "manifest_transfer" => TransferPhase::ManifestTransfer,
            "data_transfer" => TransferPhase::DataTransfer,
            "verification" => TransferPhase::Verification,
            _ => TransferPhase::DataTransfer,
        };

        // Validate resume state
        if bytes_transferred > total_bytes {
            return AtpOutcome::Err(AtpError::Protocol(ProtocolError::MalformedFrame));
        }

        let _ = (transfer_id, resume_phase);
        AtpOutcome::Err(AtpError::Protocol(ProtocolError::NotImplemented))
    }

    async fn cancel_transfer_in_process(
        &self,
        cx: &Cx,
        _transfer_id: &TransferId,
        _reason: Option<String>,
    ) -> AtpOutcome<()> {
        if cx.checkpoint().is_err() {
            return AtpOutcome::Err(AtpError::Platform(PlatformError::OperatingSystemError));
        }
        AtpOutcome::Err(AtpError::Protocol(ProtocolError::NotImplemented))
    }

    async fn send_object_daemon_delegated(
        &self,
        cx: &Cx,
        request: TransferRequest,
    ) -> AtpOutcome<ActiveTransfer> {
        self.daemon_delegation_unavailable(cx, Some(&request.options))
            .await
    }

    async fn receive_object_daemon_delegated(
        &self,
        cx: &Cx,
        _destination: TransferDestination,
        options: TransferOptions,
    ) -> AtpOutcome<ActiveTransfer> {
        self.daemon_delegation_unavailable(cx, Some(&options)).await
    }

    async fn verify_object_daemon_delegated(
        &self,
        cx: &Cx,
        _object_path: &Path,
        _expected_hash: Option<&[u8]>,
    ) -> AtpOutcome<ObjectVerification> {
        if cx.checkpoint().is_err() {
            return AtpOutcome::Err(AtpError::Platform(PlatformError::OperatingSystemError));
        }
        if daemon_endpoint_is_reachable(&self.mode).is_err() {
            return AtpOutcome::Err(AtpError::Daemon(
                crate::net::atp::protocol::DaemonError::DaemonOffline,
            ));
        }
        AtpOutcome::Err(AtpError::Protocol(ProtocolError::NotImplemented))
    }

    async fn resume_transfer_daemon_delegated(
        &self,
        cx: &Cx,
        _transfer_id: &TransferId,
        _checkpoint: &str,
    ) -> AtpOutcome<ActiveTransfer> {
        self.daemon_delegation_unavailable(cx, None).await
    }

    async fn cancel_transfer_daemon_delegated(
        &self,
        cx: &Cx,
        _transfer_id: &TransferId,
        _reason: Option<String>,
    ) -> AtpOutcome<()> {
        if cx.checkpoint().is_err() {
            return AtpOutcome::Err(AtpError::Platform(PlatformError::OperatingSystemError));
        }
        if daemon_endpoint_is_reachable(&self.mode).is_err() {
            return AtpOutcome::Err(AtpError::Daemon(
                crate::net::atp::protocol::DaemonError::DaemonOffline,
            ));
        }
        AtpOutcome::Err(AtpError::Protocol(ProtocolError::NotImplemented))
    }

    async fn daemon_delegation_unavailable(
        &self,
        cx: &Cx,
        options: Option<&TransferOptions>,
    ) -> AtpOutcome<ActiveTransfer> {
        if cx.checkpoint().is_err() {
            return AtpOutcome::Err(AtpError::Platform(PlatformError::OperatingSystemError));
        }
        if daemon_endpoint_is_reachable(&self.mode).is_err() {
            return AtpOutcome::Err(AtpError::Daemon(
                crate::net::atp::protocol::DaemonError::DaemonOffline,
            ));
        }

        let _ = options;
        AtpOutcome::Err(AtpError::Protocol(ProtocolError::NotImplemented))
    }

    // Helper methods
    async fn validate_transfer_source(&self, source: &TransferSource) -> AtpOutcome<()> {
        match source {
            TransferSource::File { path } => {
                if !path.exists() {
                    return AtpOutcome::Err(AtpError::Disk(DiskError::FileNotFound));
                }
                if !path.is_file() {
                    return AtpOutcome::Err(AtpError::Disk(DiskError::IoError));
                }
            }
            TransferSource::Directory { path, .. } => {
                if !path.exists() {
                    return AtpOutcome::Err(AtpError::Disk(DiskError::DirectoryNotFound));
                }
                if !path.is_dir() {
                    return AtpOutcome::Err(AtpError::Disk(DiskError::IoError));
                }
            }
            TransferSource::Object { .. } | TransferSource::Stream { .. } => {
                // Always valid for in-memory sources
            }
        }
        AtpOutcome::Ok(())
    }

    async fn calculate_transfer_size(&self, source: &TransferSource) -> AtpOutcome<u64> {
        match source {
            TransferSource::File { path } => {
                let metadata = match crate::fs::metadata(path).await {
                    Ok(metadata) => metadata,
                    Err(_) => return AtpOutcome::Err(AtpError::Disk(DiskError::IoError)),
                };
                AtpOutcome::Ok(metadata.len())
            }
            TransferSource::Directory {
                path,
                follow_symlinks,
            } => self.calculate_directory_size(path, *follow_symlinks).await,
            TransferSource::Object { data, .. } => AtpOutcome::Ok(data.len() as u64),
            TransferSource::Stream { size_hint, .. } => AtpOutcome::Ok(size_hint.unwrap_or(0)),
        }
    }

    async fn calculate_directory_size(
        &self,
        root: &Path,
        follow_symlinks: bool,
    ) -> AtpOutcome<u64> {
        let mut total = 0u64;
        // Stack stores (path, depth)
        let mut stack = vec![(root.to_path_buf(), 0usize)];

        while let Some((path, depth)) = stack.pop() {
            if depth > 64 {
                // Prevent infinite recursion from circular symlinks or overly deep trees
                continue;
            }

            let mut entries = match crate::fs::read_dir(&path).await {
                Ok(entries) => entries,
                Err(_) => return AtpOutcome::Err(AtpError::Disk(DiskError::IoError)),
            };

            loop {
                let entry = match entries.next_entry().await {
                    Ok(Some(entry)) => entry,
                    Ok(None) => break,
                    Err(_) => return AtpOutcome::Err(AtpError::Disk(DiskError::IoError)),
                };
                let entry_path = entry.path();
                let metadata_result = if follow_symlinks {
                    crate::fs::metadata(&entry_path).await
                } else {
                    crate::fs::symlink_metadata(&entry_path).await
                };
                let metadata = match metadata_result {
                    Ok(metadata) => metadata,
                    Err(_) => return AtpOutcome::Err(AtpError::Disk(DiskError::IoError)),
                };

                if metadata.is_file() {
                    total = match total.checked_add(metadata.len()) {
                        Some(total) => total,
                        None => {
                            return AtpOutcome::Err(AtpError::Disk(DiskError::QuotaExceeded));
                        }
                    };
                } else if metadata.is_dir() {
                    stack.push((entry_path, depth + 1));
                }
            }
        }

        AtpOutcome::Ok(total)
    }
}

fn daemon_endpoint_is_reachable(mode: &SdkMode) -> std::io::Result<()> {
    let SdkMode::DaemonDelegated {
        daemon_endpoint, ..
    } = mode
    else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "SDK mode is not daemon delegated",
        ));
    };
    let endpoint = daemon_endpoint
        .strip_prefix("tcp://")
        .unwrap_or(daemon_endpoint);
    let addr: std::net::SocketAddr = endpoint.parse().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "daemon endpoint must be tcp://host:port or host:port",
        )
    })?;

    std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(250)).map(|_| ())
}

#[derive(Debug, Clone, Deserialize)]
struct DetachedObjectSignatureEnvelope {
    algorithm: String,
    session_id_hex: String,
    hash_hex: String,
    size_bytes: u64,
    signature_hex: String,
}

impl AtpSession {
    async fn verify_detached_object_signature(
        &self,
        object_path: &Path,
        computed_hash: &[u8; 32],
        size_bytes: u64,
    ) -> Option<bool> {
        let signature_path = detached_object_signature_path(object_path);
        if !signature_path.exists() {
            return None;
        }

        match crate::fs::read(&signature_path).await {
            Ok(payload) => Some(self.verify_detached_object_signature_payload(
                &payload,
                computed_hash,
                size_bytes,
            )),
            Err(_) => Some(false),
        }
    }

    fn verify_detached_object_signature_payload(
        &self,
        payload: &[u8],
        computed_hash: &[u8; 32],
        size_bytes: u64,
    ) -> bool {
        use subtle::ConstantTimeEq;

        let Ok(envelope) = serde_json::from_slice::<DetachedObjectSignatureEnvelope>(payload)
        else {
            return false;
        };
        if !bool::from(
            envelope
                .algorithm
                .as_bytes()
                .ct_eq(OBJECT_SIGNATURE_ALGORITHM.as_bytes()),
        ) {
            return false;
        }
        if !bool::from(
            envelope
                .size_bytes
                .to_be_bytes()
                .ct_eq(&size_bytes.to_be_bytes()),
        ) {
            return false;
        }
        if !bool::from(
            envelope
                .session_id_hex
                .as_bytes()
                .ct_eq(hex::encode(self.session_id().as_bytes()).as_bytes()),
        ) {
            return false;
        }

        let Ok(hash_bytes) = decode_hex_32(&envelope.hash_hex) else {
            return false;
        };
        if !bool::from(hash_bytes.ct_eq(computed_hash)) {
            return false;
        }

        let Ok(signature_bytes) = decode_hex_32(&envelope.signature_hex) else {
            return false;
        };
        let expected = self.compute_detached_object_signature(computed_hash, size_bytes);
        bool::from(signature_bytes.ct_eq(&expected))
    }

    fn compute_detached_object_signature(
        &self,
        computed_hash: &[u8; 32],
        size_bytes: u64,
    ) -> [u8; 32] {
        use crate::security::AuthKey;
        use hmac::{Hmac, KeyInit, Mac};
        use sha2::Sha256;

        let mut ikm = Vec::with_capacity(160);
        ikm.extend_from_slice(self.session_id().as_bytes());
        ikm.extend_from_slice(self.local_peer().as_bytes());
        ikm.extend_from_slice(self.remote_peer().as_bytes());
        ikm.extend_from_slice(self.transfer_nonce().as_bytes());
        ikm.extend_from_slice(self.transcript_hash().as_bytes());
        let key = AuthKey::from_hkdf(
            &ikm,
            Some(b"asupersync-atp-sdk-object-signature-key-v1"),
            b"session-bound-object-verification",
        );

        let mut mac =
            Hmac::<Sha256>::new_from_slice(key.as_bytes()).expect("HMAC accepts any key length");
        mac.update(OBJECT_SIGNATURE_DOMAIN);
        mac.update(self.session_id().as_bytes());
        mac.update(&(computed_hash.len() as u64).to_be_bytes());
        mac.update(computed_hash);
        mac.update(&size_bytes.to_be_bytes());
        mac.finalize().into_bytes().into()
    }
}

fn decode_hex_32(input: &str) -> Result<[u8; 32], hex::FromHexError> {
    let bytes = hex::decode(input)?; // ubs:ignore - hex decode helper, not JWT parsing
    if bytes.len() != 32 {
        return Err(hex::FromHexError::InvalidStringLength);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn detached_object_signature_path(object_path: &Path) -> PathBuf {
    let mut path = object_path.as_os_str().to_os_string();
    path.push(".atp.sig");
    PathBuf::from(path)
}

impl ActiveTransfer {
    /// Admit and own a transfer worker in the supplied runtime scope.
    ///
    /// The worker receives its actual child `Cx` and an optional, bounded
    /// progress reporter. It must own and drain its protocol work, and may
    /// return `Ok` only after its own verification, commit and cleanup have
    /// succeeded. This constructor supplies lifecycle management; it does not
    /// authenticate a peer, implement a transport, or verify a commit itself.
    /// A successful result must have this transfer's identity, the `Completed`
    /// phase, and equal transferred/total byte counts.
    ///
    /// Completion requires the worker's canonical runtime join. Returning a
    /// terminal diagnostic, dropping reporters, and stopping observation cannot
    /// substitute for that join. Cancelling or dropping this handle requests
    /// cooperative cancellation; the supplied region retains ownership until
    /// its actual drain. Workers must remain cancellation-cooperative and must
    /// not leave required work in detached tasks.
    /// The join covers this worker's body and captures. It neither closes the
    /// caller's wider region nor waits for that region's registered finalizers;
    /// the caller remains responsible for its structured region drain.
    ///
    /// # Errors
    /// Returns the actual runtime admission error, without ambient spawning.
    pub fn spawn_worker<P, F, Fut>(
        cx: &Cx,
        scope: &Scope<'_, P>,
        transfer_id: TransferId,
        options: TransferOptions,
        worker: F,
    ) -> Result<Self, SpawnError>
    where
        P: Policy,
        F: FnOnce(Cx, TransferProgressReporter) -> Fut + Send + 'static,
        Fut: Future<Output = AtpOutcome<TransferProgress>> + Send + 'static,
    {
        let shared = Arc::new(parking_lot::Mutex::new(TransferShared::default()));
        let reporter = TransferProgressReporter {
            transfer_id: transfer_id.clone(),
            shared: Arc::downgrade(&shared),
        };
        let worker_shared = Arc::clone(&shared);
        let mut worker = PendingTransferFactory {
            factory: Some(worker),
            shared: Arc::clone(&shared),
        };
        let handle = cx.spawn_in_cancellation_dominant(scope, move |child| {
            // Erase the internal adapter, while still checking Send, before
            // runtime admission wraps it in its task storage machinery.
            let future: Pin<Box<dyn Future<Output = ()> + Send>> = Box::pin(async move {
                worker_shared.lock().started = true;
                let (result, cleanup_panic) =
                    match catch_unwind(AssertUnwindSafe(|| worker.take()(child.clone(), reporter)))
                    {
                        Ok(future) => {
                            let mut future = Box::pin(future);
                            let polled = poll_fn(|ctx| {
                                match catch_unwind(AssertUnwindSafe(|| future.as_mut().poll(ctx))) {
                                    Ok(Poll::Pending) => Poll::Pending,
                                    Ok(Poll::Ready(outcome)) => Poll::Ready(outcome),
                                    Err(payload) => Poll::Ready(AtpOutcome::Panicked(
                                        transfer_worker_panic(payload),
                                    )),
                                }
                            })
                            .await;
                            // Retire user captures before terminal publication or
                            // cancellation observation. A second panic must not
                            // replace the primary poll/encoded panic.
                            let cleanup = catch_unwind(AssertUnwindSafe(|| drop(future)))
                                .err()
                                .map(transfer_worker_panic);
                            (polled, cleanup)
                        }
                        Err(payload) => {
                            (AtpOutcome::Panicked(transfer_worker_panic(payload)), None)
                        }
                    };
                let wake = {
                    let mut state = worker_shared.lock();
                    state.worker_outcome = Some(result);
                    state.cleanup_panic = cleanup_panic;
                    state.waiter.take()
                };
                if let Some(wake) = wake {
                    wake.wake_by_ref();
                }
            });
            future
        })?;
        Ok(Self {
            transfer_id,
            worker: handle,
            shared,
            terminal: None,
            terminal_progress_taken: false,
            cancel_requested: AtomicBool::new(false),
            options,
        })
    }

    /// Get the transfer ID.
    #[must_use]
    pub const fn transfer_id(&self) -> &TransferId {
        &self.transfer_id
    }

    /// Wait for the next observation or actual joined terminal result.
    ///
    /// An empty slot remains pending. Nonterminal updates may be coalesced;
    /// use [`Self::next_progress_snapshot`] to observe sequence/skipped counts.
    /// The final progress is emitted at most once by this method, but the
    /// independent [`Self::terminal`] result remains available afterward.
    pub async fn next_progress(&mut self) -> Option<TransferProgress> {
        poll_fn(|ctx| {
            self.register_progress_waiter(ctx);
            let _ = self.poll_terminal(ctx);
            if let Some(snapshot) = self.shared.lock().pending.take() {
                return Poll::Ready(Some(snapshot.progress));
            }
            if self.terminal.is_some() {
                if self.terminal_progress_taken {
                    return Poll::Ready(None);
                }
                self.terminal_progress_taken = true;
                return Poll::Ready(self.final_progress());
            }
            Poll::Pending
        })
        .await
    }

    /// Wait for a coalesced nonterminal update, or `None` after the worker joins.
    /// The independent terminal result is never consumed by this method.
    pub async fn next_progress_snapshot(&mut self) -> Option<TransferProgressSnapshot> {
        poll_fn(|ctx| {
            self.register_progress_waiter(ctx);
            let _ = self.poll_terminal(ctx);
            if let Some(snapshot) = self.shared.lock().pending.take() {
                Poll::Ready(Some(snapshot))
            } else if self.terminal.is_some() {
                Poll::Ready(None)
            } else {
                Poll::Pending
            }
        })
        .await
    }

    /// Cancel this transfer.
    pub async fn cancel(&self) -> AtpOutcome<()> {
        if self.cancel_requested.swap(true, Ordering::AcqRel) {
            return AtpOutcome::Ok(());
        }

        if !self.worker.is_finished() {
            self.worker
                .abort_with_reason(CancelReason::user("ATP transfer cancelled"));
        }
        AtpOutcome::Ok(())
    }

    /// Check actual joined completion without consuming any progress or result.
    pub async fn is_complete(&mut self) -> bool {
        self.terminal().is_some()
    }

    /// Observe the current worker lifecycle without consuming observations.
    #[must_use]
    pub fn state(&mut self) -> ActiveTransferState {
        if self.terminal().is_some() {
            ActiveTransferState::Terminal
        } else if self.shared.lock().started {
            ActiveTransferState::Running
        } else {
            ActiveTransferState::Pending
        }
    }

    /// Inspect retained terminal evidence, collecting a ready join if necessary.
    #[must_use]
    pub fn terminal(&mut self) -> Option<&TransferTerminal> {
        if self.terminal.is_none() {
            match self.worker.try_join() {
                Ok(None) => {}
                Ok(Some(())) => self.joined(Ok(())),
                Err(error) => self.joined(Err(error)),
            }
        }
        self.terminal.as_ref()
    }

    /// Wait for the actual worker join and retain its complete terminal evidence.
    /// Dropping this wait leaves the handle and its worker ownership intact.
    pub async fn wait_for_terminal(&mut self) -> &TransferTerminal {
        poll_fn(|ctx| self.poll_terminal(ctx)).await;
        self.terminal.as_ref().expect("joined transfer terminal")
    }

    /// Wait for actual joined completion and return its final progress, if any.
    ///
    /// Failure before any progress can still return `None`, preserving this
    /// legacy return type. Use [`Self::wait_for_terminal`] to retain the typed
    /// error/cancellation/panic. Nonterminal progress is never returned here.
    pub async fn wait_for_completion(mut self) -> Option<TransferProgress> {
        self.wait_for_terminal().await;
        self.final_progress()
    }

    fn register_progress_waiter(&self, ctx: &Context<'_>) {
        let waiter = Arc::new(ctx.waker().clone());
        let previous = self.shared.lock().waiter.replace(waiter);
        drop(previous);
    }

    fn poll_terminal(&mut self, ctx: &mut Context<'_>) -> Poll<()> {
        if self.terminal.is_some() {
            return Poll::Ready(());
        }
        match self.worker.poll_join(ctx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.joined(result);
                Poll::Ready(())
            }
        }
    }

    fn joined(&mut self, worker_join: Result<(), JoinError>) {
        let (worker_outcome, cleanup_panic, waiter) = {
            let mut state = self.shared.lock();
            state.closed = true;
            (
                state.worker_outcome.take(),
                state.cleanup_panic.take(),
                state.waiter.take(),
            )
        };
        let mut outcome = worker_outcome.clone().unwrap_or_else(|| {
            AtpOutcome::Err(AtpError::Protocol(ProtocolError::SessionStateMismatch))
        });
        // Preserve the worker's original return separately, even when it
        // violates the success contract. Validation creates no verification
        // or transport evidence of its own.
        if let AtpOutcome::Ok(progress) = &outcome {
            if progress.transfer_id != self.transfer_id
                || progress.phase != TransferPhase::Completed
                || progress.bytes_transferred != progress.total_bytes
            {
                outcome = AtpOutcome::Err(AtpError::Protocol(ProtocolError::SessionStateMismatch));
            }
        }
        if let Some(payload) = &cleanup_panic {
            if !matches!(outcome, AtpOutcome::Panicked(_)) {
                outcome = AtpOutcome::Panicked(payload.clone());
            }
        }
        match &worker_join {
            Ok(()) => {}
            Err(JoinError::Cancelled(reason)) => match &mut outcome {
                AtpOutcome::Panicked(_) => {}
                AtpOutcome::Cancelled(worker_reason) => {
                    worker_reason.strengthen(reason);
                }
                _ => outcome = AtpOutcome::Cancelled(reason.clone()),
            },
            Err(JoinError::Panicked(payload)) => {
                if !matches!(outcome, AtpOutcome::Panicked(_)) {
                    outcome = AtpOutcome::Panicked(payload.clone());
                }
            }
            Err(JoinError::PolledAfterCompletion) => {
                outcome = AtpOutcome::Panicked(PanicPayload::new("ATP worker joined twice"));
            }
        }
        self.terminal = Some(TransferTerminal {
            outcome,
            worker_outcome,
            cleanup_panic,
            worker_join,
        });
        drop(waiter);
    }

    fn final_progress(&self) -> Option<TransferProgress> {
        let outcome = &self.terminal.as_ref()?.outcome;
        if let AtpOutcome::Ok(progress) = outcome {
            return Some(progress.clone());
        }
        let mut progress = self.shared.lock().last_progress.clone()?;
        progress.phase = if matches!(outcome, AtpOutcome::Cancelled(_)) {
            TransferPhase::Cancelled
        } else {
            TransferPhase::Failed
        };
        Some(progress)
    }
}

impl Drop for ActiveTransfer {
    fn drop(&mut self) {
        let (pending, last, waiter) = {
            let mut state = self.shared.lock();
            state.closed = true;
            (
                state.pending.take(),
                state.last_progress.take(),
                state.waiter.take(),
            )
        };
        if self.terminal.is_none() && !self.worker.is_finished() {
            self.worker
                .abort_with_reason(CancelReason::user("ATP transfer handle dropped"));
        }
        // A saved observer Waker has an arbitrary destructor. Publish the
        // runtime's callback-free cancellation request before retiring it.
        drop((pending, last, waiter));
    }
}

fn transfer_worker_panic(payload: Box<dyn std::any::Any + Send>) -> PanicPayload {
    let message = crate::cx::scope::payload_to_string(&payload);
    // Match structured combinator panic isolation: arbitrary panic payload
    // destructors must not turn a caught panic into a double panic.
    std::mem::forget(payload);
    PanicPayload::new(message)
}

/// Object verification result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectVerification {
    /// Path to the verified object.
    pub path: PathBuf,
    /// Computed hash of the object.
    pub hash: Vec<u8>,
    /// Object size in bytes.
    pub size_bytes: u64,
    /// Whether the legacy integrity and sidecar checks both passed.
    /// This does not establish peer or object-producer authenticity; see
    /// [`AtpSession::verify_object`].
    pub verified: bool,
    /// Whether integrity check passed.
    pub integrity_check_passed: bool,
    /// Whether the legacy detached sidecar checksum matched.
    ///
    /// `None` means the detached signature was absent. Missing signatures still
    /// allow integrity-only hash checks, but they never make `verified` true.
    /// `Some(true)` is not evidence of a secret-key signature: the v1 key is
    /// reproducible from public session fields.
    pub signature_valid: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cx::Cx;
    use crate::net::atp::protocol::{
        CapabilityAction, CapabilityGrant, CapabilityGrantId, CapabilityScope, PeerId,
        ProtocolError, SessionContextKind,
    };
    use crate::net::atp::sdk::{AtpSdk, SdkMode, SessionConfig, SessionOptions};

    fn granted_direct_options(config: &SessionConfig, peer: PeerId, label: &str) -> SessionOptions {
        SessionOptions::direct(peer).with_grants(vec![CapabilityGrant::new(
            CapabilityGrantId::from_label(label),
            peer,
            config.local_peer,
            [CapabilityAction::Read, CapabilityAction::Write],
            CapabilityScope::for_context(SessionContextKind::Direct),
        )])
    }

    fn reachable_daemon_endpoint() -> (std::net::TcpListener, String) {
        let listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback daemon placeholder");
        let endpoint = listener
            .local_addr()
            .expect("read loopback daemon placeholder address")
            .to_string();
        (listener, endpoint)
    }

    async fn daemon_delegated_session(cx: &Cx, label: &str) -> (std::net::TcpListener, AtpSession) {
        let (listener, endpoint) = reachable_daemon_endpoint();
        let config = SessionConfig::default();
        let peer = PeerId::from_label(label);
        let session_options = granted_direct_options(&config, peer, label);
        let sdk = AtpSdk::new_in_process(config);
        let mut session = sdk.open_session(cx, session_options).await.unwrap();
        session.mode = SdkMode::DaemonDelegated {
            daemon_endpoint: endpoint,
            auth_token: Some("token".to_string()),
        };
        (listener, session)
    }

    #[test]
    fn transfer_request_construction() {
        let source = TransferSource::Object {
            data: vec![1, 2, 3, 4],
            content_type: Some("text/plain".to_string()),
        };
        let destination = TransferDestination::File {
            path: PathBuf::from("/tmp/test.txt"),
        };
        let request = TransferRequest {
            source: source.clone(),
            destination: destination.clone(),
            options: TransferOptions::default(),
        };

        assert_eq!(request.source, source);
        assert_eq!(request.destination, destination);
    }

    #[test]
    fn in_process_send_object_fails_closed_after_source_validation() {
        futures_lite::future::block_on(async {
            let config = SessionConfig::default();
            let peer = PeerId::from_label("test_peer");
            let session_options = granted_direct_options(&config, peer, "send-fail-closed");
            let sdk = AtpSdk::new_in_process(config);
            let cx = Cx::for_testing();

            let session = sdk.open_session(&cx, session_options).await.unwrap();

            let source = TransferSource::Object {
                data: vec![0u8; 1024],
                content_type: Some("application/octet-stream".to_string()),
            };
            let destination = TransferDestination::Object {
                object_id: "test_object".to_string(),
            };
            let request = TransferRequest {
                source,
                destination,
                options: TransferOptions::default(),
            };

            let result = session.send_object(&cx, request).await;
            assert!(
                matches!(
                    result,
                    AtpOutcome::Err(AtpError::Protocol(ProtocolError::NotImplemented))
                ),
                "in-process SDK send must not fabricate an active transfer: {result:?}"
            );
        });
    }

    #[test]
    fn in_process_send_file_fails_closed_but_missing_file_still_validates_first() {
        futures_lite::future::block_on(async {
            let config = SessionConfig::default();
            let sdk = AtpSdk::new_in_process(config.clone());
            let cx = Cx::for_testing();
            let peer = PeerId::from_label("send_file_peer");
            let session = sdk
                .open_session(&cx, granted_direct_options(&config, peer, "send-file"))
                .await
                .unwrap();

            let valid_request = TransferRequest {
                source: TransferSource::File {
                    path: PathBuf::from("src/net/atp/sdk/transfer.rs"),
                },
                destination: TransferDestination::Object {
                    object_id: "transfer-rs".to_string(),
                },
                options: TransferOptions::default(),
            };
            let result = session.send_object(&cx, valid_request).await;
            assert!(
                matches!(
                    result,
                    AtpOutcome::Err(AtpError::Protocol(ProtocolError::NotImplemented))
                ),
                "valid file send must fail closed without a worker: {result:?}"
            );

            let missing_request = TransferRequest {
                source: TransferSource::File {
                    path: PathBuf::from("__asupersync_missing_sdk_send_source__"),
                },
                destination: TransferDestination::Stream,
                options: TransferOptions::default(),
            };
            let result = session.send_object(&cx, missing_request).await;
            assert!(
                matches!(
                    result,
                    AtpOutcome::Err(AtpError::Disk(DiskError::FileNotFound))
                ),
                "missing source must be rejected before fail-closed send: {result:?}"
            );
        });
    }

    #[test]
    fn in_process_sync_tree_and_stream_buffer_fail_closed() {
        futures_lite::future::block_on(async {
            let config = SessionConfig::default();
            let sdk = AtpSdk::new_in_process(config.clone());
            let cx = Cx::for_testing();
            let peer = PeerId::from_label("send_wrapper_peer");
            let session = sdk
                .open_session(&cx, granted_direct_options(&config, peer, "send-wrappers"))
                .await
                .unwrap();

            let result = session
                .sync_tree(
                    &cx,
                    Path::new("src/net/atp/sdk"),
                    "/remote/sdk",
                    TransferOptions::default(),
                )
                .await;
            assert!(
                matches!(
                    result,
                    AtpOutcome::Err(AtpError::Protocol(ProtocolError::NotImplemented))
                ),
                "sync_tree must not fabricate transfer success: {result:?}"
            );

            let result = session
                .stream_large_buffer(
                    &cx,
                    vec![1, 2, 3, 4],
                    TransferDestination::Object {
                        object_id: "buffer".to_string(),
                    },
                    TransferOptions::default(),
                )
                .await;
            assert!(
                matches!(
                    result,
                    AtpOutcome::Err(AtpError::Protocol(ProtocolError::NotImplemented))
                ),
                "stream_large_buffer must not fabricate transfer success: {result:?}"
            );
        });
    }

    #[test]
    fn active_transfer_cancel_is_idempotent_for_real_transfer_handles() {
        let (mut lab, root) = owned_worker_tests::lab(0x53_0001);
        let (_release, mut receive) = crate::channel::oneshot::channel::<()>();
        let mut transfer =
            owned_worker_tests::admit(&mut lab, root, move |cx, _reporter| async move {
                assert!(matches!(
                    receive.recv(&cx).await,
                    Err(crate::channel::oneshot::RecvError::Cancelled)
                ));
                AtpOutcome::Cancelled(cx.cancel_reason().expect("actual worker cancellation"))
            });
        futures_lite::future::block_on(async {
            let cancel_result = transfer.cancel().await;
            assert!(cancel_result.is_ok());
            let repeated_cancel_result = transfer.cancel().await;
            assert!(repeated_cancel_result.is_ok());
        });
        lab.run_until_idle();
        let terminal = transfer.terminal().unwrap();
        assert!(
            matches!(&terminal.worker_join, Err(JoinError::Cancelled(reason))
            if reason.message.as_deref() == Some("ATP transfer cancelled"))
        );
        assert_eq!(terminal.outcome, terminal.worker_outcome.clone().unwrap());
        owned_worker_tests::clean(&mut lab, root, transfer.worker.task_id());
    }

    #[test]
    fn receive_without_transport_fails_closed() {
        futures_lite::future::block_on(async {
            let config = SessionConfig::default();
            let sdk = AtpSdk::new_in_process(config.clone());
            let cx = Cx::for_testing();
            let peer = PeerId::from_label("receive_peer");
            let session = sdk
                .open_session(
                    &cx,
                    granted_direct_options(&config, peer, "receive-fail-closed"),
                )
                .await
                .unwrap();

            let result = session
                .receive_object(&cx, TransferDestination::Stream, TransferOptions::default())
                .await;
            match result {
                AtpOutcome::Err(AtpError::Protocol(ProtocolError::NotImplemented)) => {}
                other => panic!("receive must fail closed without a real transport: {other:?}"), // ubs:ignore
            }
        });
    }

    #[test]
    fn daemon_delegated_transfer_stubs_use_asup_e701_when_endpoint_is_reachable() {
        futures_lite::future::block_on(async {
            let cx = Cx::for_testing();
            let (_listener, session) = daemon_delegated_session(&cx, "daemon-transfer-stubs").await;

            let request = TransferRequest {
                source: TransferSource::Object {
                    data: vec![1, 2, 3, 4],
                    content_type: Some("application/octet-stream".to_string()),
                },
                destination: TransferDestination::Object {
                    object_id: "daemon-object".to_string(),
                },
                options: TransferOptions::default(),
            };
            assert!(
                matches!(
                    session.send_object(&cx, request).await,
                    AtpOutcome::Err(AtpError::Protocol(ProtocolError::NotImplemented))
                ),
                "reachable daemon-delegated send stub must report ASUP-E701"
            );

            assert!(
                matches!(
                    session
                        .receive_object(
                            &cx,
                            TransferDestination::Stream,
                            TransferOptions::default(),
                        )
                        .await,
                    AtpOutcome::Err(AtpError::Protocol(ProtocolError::NotImplemented))
                ),
                "reachable daemon-delegated receive stub must report ASUP-E701"
            );

            let transfer_id = TransferId::new("daemon-transfer");
            assert!(
                matches!(
                    session
                        .resume_transfer(&cx, &transfer_id, "1:2:data_transfer")
                        .await,
                    AtpOutcome::Err(AtpError::Protocol(ProtocolError::NotImplemented))
                ),
                "reachable daemon-delegated resume stub must report ASUP-E701"
            );
            assert!(
                matches!(
                    session
                        .cancel_transfer(&cx, &transfer_id, Some("user requested".to_string()))
                        .await,
                    AtpOutcome::Err(AtpError::Protocol(ProtocolError::NotImplemented))
                ),
                "reachable daemon-delegated cancel stub must report ASUP-E701"
            );
            assert!(
                matches!(
                    session
                        .verify_object(&cx, Path::new("src/net/atp/sdk/transfer.rs"), None)
                        .await,
                    AtpOutcome::Err(AtpError::Protocol(ProtocolError::NotImplemented))
                ),
                "reachable daemon-delegated verify stub must report ASUP-E701"
            );
        });
    }

    #[test]
    fn resume_without_active_transfer_fails_closed() {
        futures_lite::future::block_on(async {
            let config = SessionConfig::default();
            let sdk = AtpSdk::new_in_process(config.clone());
            let cx = Cx::for_testing();
            let peer = PeerId::from_label("resume_peer");
            let session = sdk
                .open_session(
                    &cx,
                    granted_direct_options(&config, peer, "resume-fail-closed"),
                )
                .await
                .unwrap();
            let transfer_id = TransferId::new("missing-transfer");

            let result = session
                .resume_transfer(&cx, &transfer_id, "1:2:data_transfer")
                .await;
            match result {
                AtpOutcome::Err(AtpError::Protocol(ProtocolError::NotImplemented)) => {}
                other => panic!("resume must fail closed without active transfer state: {other:?}"), // ubs:ignore
            }
        });
    }

    #[test]
    fn session_cancel_without_active_transfer_fails_closed() {
        futures_lite::future::block_on(async {
            let config = SessionConfig::default();
            let sdk = AtpSdk::new_in_process(config.clone());
            let cx = Cx::for_testing();
            let peer = PeerId::from_label("cancel_peer");
            let session = sdk
                .open_session(
                    &cx,
                    granted_direct_options(&config, peer, "cancel-fail-closed"),
                )
                .await
                .unwrap();
            let transfer_id = TransferId::new("missing-transfer");

            let result = session
                .cancel_transfer(&cx, &transfer_id, Some("user requested".to_string()))
                .await;
            match result {
                AtpOutcome::Err(AtpError::Protocol(ProtocolError::NotImplemented)) => {}
                other => panic!("session cancel must not fabricate success: {other:?}"), // ubs:ignore
            }
        });
    }

    #[test]
    fn detached_object_signature_is_session_bound_and_constant_time_checked() {
        futures_lite::future::block_on(async {
            use hmac::{Hmac, KeyInit, Mac};
            use sha2::{Digest, Sha256};

            let config = SessionConfig::default();
            let sdk = AtpSdk::new_in_process(config.clone());
            let cx = Cx::for_testing();
            let peer = PeerId::from_label("signature_peer");
            let session = sdk
                .open_session(
                    &cx,
                    granted_direct_options(&config, peer, "signature-verification"),
                )
                .await
                .unwrap();

            let object = b"authenticated object payload";
            let mut hasher = Sha256::new();
            hasher.update(object);
            let hash: [u8; 32] = hasher.finalize().into();
            // Reconstruct the legacy sidecar using only public getters and
            // protocol constants, without calling either production key/tag
            // helper. This pins compatibility and demonstrates why a matching
            // v1 checksum is not evidence of authenticated object authorship.
            let public_material = [
                session.session_id().as_bytes().as_slice(),
                session.local_peer().as_bytes().as_slice(),
                session.remote_peer().as_bytes().as_slice(),
                session.transfer_nonce().as_bytes().as_slice(),
                session.transcript_hash().as_bytes().as_slice(),
            ]
            .concat();
            let mut extract =
                Hmac::<Sha256>::new_from_slice(b"asupersync-atp-sdk-object-signature-key-v1")
                    .unwrap();
            extract.update(&public_material);
            let mut expand =
                Hmac::<Sha256>::new_from_slice(&extract.finalize().into_bytes()).unwrap();
            expand.update(b"session-bound-object-verification\x01");
            let mut attacker_mac =
                Hmac::<Sha256>::new_from_slice(&expand.finalize().into_bytes()).unwrap();
            attacker_mac.update(b"asupersync::net::atp::sdk::object-signature::v1");
            attacker_mac.update(session.session_id().as_bytes());
            attacker_mac.update(&32u64.to_be_bytes());
            attacker_mac.update(&hash);
            attacker_mac.update(&(object.len() as u64).to_be_bytes());
            let signature: [u8; 32] = attacker_mac.finalize().into_bytes().into();
            assert_eq!(
                signature,
                session.compute_detached_object_signature(&hash, object.len() as u64)
            );
            let envelope = serde_json::json!({
                "algorithm": OBJECT_SIGNATURE_ALGORITHM,
                "session_id_hex": hex::encode(session.session_id().as_bytes()),
                "hash_hex": hex::encode(hash),
                "size_bytes": object.len() as u64,
                "signature_hex": hex::encode(signature),
            });
            let payload = serde_json::to_vec(&envelope).unwrap();

            assert!(session.verify_detached_object_signature_payload(
                &payload,
                &hash,
                object.len() as u64
            ));

            let mut tampered = envelope;
            tampered["signature_hex"] = serde_json::Value::String(hex::encode([0xAAu8; 32]));
            let tampered_payload = serde_json::to_vec(&tampered).unwrap();
            assert!(!session.verify_detached_object_signature_payload(
                &tampered_payload,
                &hash,
                object.len() as u64
            ));
        });
    }

    #[test]
    fn verify_object_missing_detached_signature_is_integrity_only() {
        futures_lite::future::block_on(async {
            use sha2::{Digest, Sha256};

            let config = SessionConfig::default();
            let sdk = AtpSdk::new_in_process(config.clone());
            let cx = Cx::for_testing();
            let peer = PeerId::from_label("unsigned_object_peer");
            let session = sdk
                .open_session(
                    &cx,
                    granted_direct_options(&config, peer, "unsigned-object-verification"),
                )
                .await
                .unwrap();

            let object_path = Path::new("src/net/atp/sdk/transfer.rs");
            assert!(
                !detached_object_signature_path(object_path).exists(),
                "fixture must not carry a detached signature"
            );
            let object = std::fs::read(object_path).unwrap();
            let mut hasher = Sha256::new();
            hasher.update(&object);
            let expected_hash: [u8; 32] = hasher.finalize().into();

            let result = session
                .verify_object(&cx, object_path, Some(&expected_hash[..]))
                .await;
            let verification = match result {
                AtpOutcome::Ok(verification) => verification,
                other => panic!("verify_object should return verification data: {other:?}"),
            };

            assert!(verification.integrity_check_passed);
            assert_eq!(verification.signature_valid, None);
            assert!(
                !verification.verified,
                "missing detached signatures must not be treated as authenticated"
            );
        });
    }

    #[test]
    fn directory_size_uses_real_filesystem_metadata() {
        fn std_directory_size(path: &Path) -> u64 {
            let mut total = 0u64;
            let mut stack = vec![path.to_path_buf()];
            while let Some(path) = stack.pop() {
                for entry in std::fs::read_dir(path).unwrap() {
                    // ubs:ignore
                    let entry = entry.unwrap();
                    let metadata = entry.metadata().unwrap();
                    if metadata.is_file() {
                        total += metadata.len();
                    } else if metadata.is_dir() {
                        stack.push(entry.path()); // ubs:ignore - controlled test env
                    }
                }
            }
            total
        }

        futures_lite::future::block_on(async {
            let config = SessionConfig::default();
            let sdk = AtpSdk::new_in_process(config.clone());
            let cx = Cx::for_testing();
            let peer = PeerId::from_label("size_peer");
            let session = sdk
                .open_session(&cx, granted_direct_options(&config, peer, "directory-size"))
                .await
                .unwrap();
            let path = PathBuf::from("src/net/atp/sdk");
            let source = TransferSource::Directory {
                path: path.clone(),
                follow_symlinks: false,
            };

            let size = session.calculate_transfer_size(&source).await.unwrap();
            assert_eq!(size, std_directory_size(&path));
            assert_ne!(size, 1024 * 1024);
        });
    }

    #[test]
    fn transfer_size_metadata_failure_is_not_reported_as_zero() {
        futures_lite::future::block_on(async {
            let config = SessionConfig::default();
            let sdk = AtpSdk::new_in_process(config.clone());
            let cx = Cx::for_testing();
            let peer = PeerId::from_label("size_error_peer");
            let session = sdk
                .open_session(
                    &cx,
                    granted_direct_options(&config, peer, "directory-size-error"),
                )
                .await
                .unwrap();
            let source = TransferSource::File {
                path: PathBuf::from("__asupersync_missing_size_source__"),
            };

            match session.calculate_transfer_size(&source).await {
                AtpOutcome::Err(AtpError::Disk(DiskError::IoError)) => {}
                other => panic!("metadata failure must remain an error, got {other:?}"), // ubs:ignore
            }
        });
    }

    // Actual scheduled worker lifecycle tests. These fixtures do not perform
    // an authenticated ATP transfer or validate a protocol commit; the public
    // session operations above remain explicitly unavailable until wired.
    mod owned_worker_tests {
        use super::*;
        use crate::channel::oneshot;
        use crate::lab::{LabConfig, LabRuntime};
        use crate::types::{Budget, RegionId, TaskId};
        use std::sync::atomic::AtomicUsize;
        use std::task::Wake;

        pub(super) fn lab(seed: u64) -> (LabRuntime, RegionId) {
            let mut lab = LabRuntime::new(LabConfig::new(seed).max_steps(4096));
            let root = lab.state.create_root_region(Budget::INFINITE);
            (lab, root)
        }

        pub(super) fn admit<F, Fut>(
            lab: &mut LabRuntime,
            root: RegionId,
            worker: F,
        ) -> ActiveTransfer
        where
            F: FnOnce(Cx, TransferProgressReporter) -> Fut + Send + 'static,
            Fut: Future<Output = AtpOutcome<TransferProgress>> + Send + 'static,
        {
            let published = Arc::new(parking_lot::Mutex::new(None));
            let slot = Arc::clone(&published);
            let coordinator: Pin<Box<dyn Future<Output = ()> + Send>> = Box::pin(async move {
                let cx = Cx::current().expect("actual ATP admission coordinator");
                let mut transfer = ActiveTransfer::spawn_worker(
                    &cx,
                    &cx.scope(),
                    TransferId::new("owned-worker"),
                    TransferOptions::default(),
                    worker,
                )
                .expect("actual scoped runtime admission");
                assert_eq!(transfer.state(), ActiveTransferState::Pending);
                *slot.lock() = Some(transfer);
            });
            let (id, mut joined) = lab
                .state
                .create_task(root, Budget::INFINITE, coordinator)
                .unwrap();
            lab.scheduler.lock().schedule(id, 0);
            assert!(lab.run_until_idle() < 4096);
            assert_eq!(joined.try_join(), Ok(Some(())));
            let transfer = published.lock().take().expect("admitted transfer owner");
            assert_ne!(transfer.worker.task_id(), id);
            transfer
        }

        pub(super) fn clean(lab: &mut LabRuntime, root: RegionId, worker: TaskId) {
            assert!(lab.run_until_quiescent_with_report().lab_test_passed());
            assert_eq!(lab.state.live_task_count(), 0);
            assert_eq!(lab.state.pending_obligation_count(), 0);
            assert_eq!(lab.state.region(root).unwrap().pending_spawn_count(), 0);
            let trace = lab.state.trace_handle().snapshot();
            for kind in [
                crate::trace::TraceEventKind::Spawn,
                crate::trace::TraceEventKind::Complete,
            ] {
                assert_eq!(trace.iter().filter(|event| {
                    event.kind == kind
                        && matches!(event.data, crate::trace::TraceData::Task { task, region }
                            if task == worker && region == root)
                }).count(), 1, "actual full worker ID {worker:?} {kind:?}");
            }
            let effects = lab.state.cancel_request(
                root,
                &CancelReason::user("ATP worker test complete"),
                None,
            );
            let (tasks, wakes) = effects.into_parts();
            assert!(tasks.is_empty());
            wakes.dispatch();
            lab.state.advance_region_state(root);
            assert!(lab.state.region(root).is_none());
            assert!(lab.run_until_quiescent_with_report().lab_test_passed());
            eprintln!(
                "ATP owned worker cleanup worker={worker:?} root={root:?} live_tasks={} pending_obligations={} root_retained={}",
                lab.state.live_task_count(),
                lab.state.pending_obligation_count(),
                lab.state.region(root).is_some()
            );
        }

        fn progress(bytes: u64, phase: TransferPhase) -> TransferProgress {
            TransferProgress {
                transfer_id: TransferId::new("owned-worker"),
                bytes_transferred: bytes,
                total_bytes: 65,
                speed_bytes_per_sec: 0,
                eta_ms: None,
                phase,
                active_paths: 1,
                repair_symbols_active: false,
            }
        }

        #[derive(Default)]
        struct WakeCount(AtomicUsize);

        impl Wake for WakeCount {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
            fn wake_by_ref(self: &Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        struct Dropped(Arc<AtomicUsize>);

        impl Drop for Dropped {
            fn drop(&mut self) {
                assert_eq!(self.0.fetch_add(1, Ordering::SeqCst), 0);
            }
        }

        #[test]
        fn owned_transfer_delayed_coalesced_progress_preserves_joined_terminal() {
            let (mut lab, root) = lab(0x53_0010);
            let (start, mut first) = oneshot::channel::<()>();
            let (middle, mut next) = oneshot::channel::<()>();
            let (finish, mut cleanup) = oneshot::channel::<()>();
            let drops = Arc::new(AtomicUsize::new(0));
            let resource = Dropped(Arc::clone(&drops));
            let mut transfer = admit(&mut lab, root, move |cx, reporter| async move {
                let _resource = resource;
                first.recv(&cx).await.unwrap();
                for bytes in 1..=64 {
                    assert_eq!(
                        reporter.report(progress(bytes, TransferPhase::DataTransfer)),
                        Ok(bytes)
                    );
                }
                next.recv(&cx).await.unwrap();
                assert_eq!(
                    reporter.report(progress(65, TransferPhase::Finalization)),
                    Ok(65)
                );
                cleanup.recv(&cx).await.unwrap();
                AtpOutcome::Ok(progress(65, TransferPhase::Completed))
            });
            let worker = transfer.worker.task_id();
            assert_eq!(transfer.state(), ActiveTransferState::Running);
            let wake = Arc::new(WakeCount::default());
            let waker = Waker::from(Arc::clone(&wake));
            {
                let mut first_update = Box::pin(transfer.next_progress_snapshot());
                assert!(
                    first_update
                        .as_mut()
                        .poll(&mut Context::from_waker(&waker))
                        .is_pending()
                );
            }
            assert_eq!(wake.0.load(Ordering::SeqCst), 0);
            for _ in 0..3 {
                assert!(!futures_lite::future::block_on(transfer.is_complete()));
                assert!(transfer.terminal().is_none());
            }
            start.send_blocking(()).unwrap();
            assert!(lab.run_until_idle() < 4096);
            assert!(
                wake.0.load(Ordering::SeqCst) > 0,
                "actual progress wakes a registered Pending observer"
            );
            for _ in 0..3 {
                assert!(!futures_lite::future::block_on(transfer.is_complete()));
            }
            let snapshot =
                futures_lite::future::block_on(transfer.next_progress_snapshot()).unwrap();
            assert_eq!((snapshot.sequence, snapshot.skipped), (64, 63));
            assert_eq!(snapshot.progress, progress(64, TransferPhase::DataTransfer));
            assert!(transfer.shared.lock().pending.is_none());
            middle.send_blocking(()).unwrap();
            lab.run_until_idle();
            assert_eq!(drops.load(Ordering::SeqCst), 0);
            assert!(!futures_lite::future::block_on(transfer.is_complete()));
            let snapshot =
                futures_lite::future::block_on(transfer.next_progress_snapshot()).unwrap();
            assert_eq!((snapshot.sequence, snapshot.skipped), (65, 0));
            assert_eq!(snapshot.progress.phase, TransferPhase::Finalization);
            let wake_before = wake.0.load(Ordering::SeqCst);
            {
                let mut waiting = Box::pin(transfer.wait_for_terminal());
                assert!(
                    waiting
                        .as_mut()
                        .poll(&mut Context::from_waker(&waker))
                        .is_pending()
                );
            }
            assert_eq!(drops.load(Ordering::SeqCst), 0);
            finish.send_blocking(()).unwrap();
            lab.run_until_idle();
            assert!(wake.0.load(Ordering::SeqCst) > wake_before);
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            for _ in 0..3 {
                assert!(futures_lite::future::block_on(transfer.is_complete()));
            }
            let terminal = transfer.terminal().unwrap().clone();
            assert_eq!(terminal.worker_join, Ok(()));
            assert_eq!(
                terminal.outcome,
                AtpOutcome::Ok(progress(65, TransferPhase::Completed))
            );
            assert_eq!(terminal.worker_outcome, Some(terminal.outcome.clone()));
            assert!(futures_lite::future::block_on(transfer.cancel()).is_ok());
            assert_eq!(
                transfer.terminal(),
                Some(&terminal),
                "late cancellation cannot rewrite a joined success"
            );
            assert_eq!(
                futures_lite::future::block_on(transfer.next_progress()),
                Some(progress(65, TransferPhase::Completed))
            );
            assert_eq!(
                futures_lite::future::block_on(transfer.next_progress()),
                None
            );
            assert_eq!(
                futures_lite::future::block_on(transfer.next_progress_snapshot()),
                None
            );
            assert_eq!(
                futures_lite::future::block_on(transfer.wait_for_terminal()),
                &terminal
            );
            assert_eq!(transfer.state(), ActiveTransferState::Terminal);
            clean(&mut lab, root, worker);
        }

        #[test]
        fn owned_transfer_full_or_absent_progress_never_substitutes_for_worker_completion() {
            for report_updates in [false, true] {
                let (mut lab, root) = lab(0x53_0020 + u64::from(report_updates));
                let (release, mut gate) = oneshot::channel::<()>();
                let drops = Arc::new(AtomicUsize::new(0));
                let resource = Dropped(Arc::clone(&drops));
                let transfer = admit(&mut lab, root, move |cx, reporter| async move {
                    let _resource = resource;
                    if report_updates {
                        for bytes in 1..=65 {
                            reporter
                                .report(progress(bytes, TransferPhase::DataTransfer))
                                .unwrap();
                        }
                    }
                    drop(reporter);
                    gate.recv(&cx).await.unwrap();
                    AtpOutcome::Ok(progress(65, TransferPhase::Completed))
                });
                let worker = transfer.worker.task_id();
                let shared = Arc::clone(&transfer.shared);
                assert_eq!(shared.lock().sequence, if report_updates { 65 } else { 0 });
                assert_eq!(shared.lock().pending.is_some(), report_updates);
                let wake = Arc::new(WakeCount::default());
                let waker = Waker::from(Arc::clone(&wake));
                let mut completion = Box::pin(transfer.wait_for_completion());
                assert!(
                    completion
                        .as_mut()
                        .poll(&mut Context::from_waker(&waker))
                        .is_pending()
                );
                assert_eq!(drops.load(Ordering::SeqCst), 0);
                assert_eq!(
                    lab.run_until_idle(),
                    0,
                    "lost reporter/full slot cannot self-spin or terminate a live worker"
                );
                release.send_blocking(()).unwrap();
                lab.run_until_idle();
                assert!(wake.0.load(Ordering::SeqCst) > 0);
                assert_eq!(
                    completion.as_mut().poll(&mut Context::from_waker(&waker)),
                    Poll::Ready(Some(progress(65, TransferPhase::Completed)))
                );
                drop(completion);
                assert_eq!(drops.load(Ordering::SeqCst), 1);
                assert!(shared.lock().closed);
                assert!(shared.lock().pending.is_none());
                clean(&mut lab, root, worker);
            }
        }

        struct TerminalWorker {
            cx: Cx,
            gate: oneshot::Receiver<()>,
            outcome: Option<AtpOutcome<TransferProgress>>,
            drops: Arc<AtomicUsize>,
            mode: u8,
        }

        impl Future for TerminalWorker {
            type Output = AtpOutcome<TransferProgress>;

            fn poll(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
                if self.gate.poll_recv_uninterruptible(ctx).is_pending() {
                    return Poll::Pending;
                }
                if self.mode == 1 || self.mode == 5 {
                    panic!("ATP primary worker poll panic");
                }
                Poll::Ready(self.outcome.take().expect("worker returns once"))
            }
        }

        impl Drop for TerminalWorker {
            fn drop(&mut self) {
                assert_eq!(self.drops.fetch_add(1, Ordering::SeqCst), 0);
                if matches!(self.mode, 2 | 4 | 5) {
                    self.cx.cancel_with(
                        crate::types::CancelKind::User,
                        Some("ATP worker capture retired"),
                    );
                }
                if self.mode == 3 || self.mode == 5 {
                    panic!("ATP worker destructor panic");
                }
            }
        }

        #[test]
        fn owned_transfer_actual_worker_retirement_and_canonical_severity_are_independent() {
            for mode in 0_u8..10 {
                let (mut lab, root) = lab(0x53_0030 + u64::from(mode));
                let (release, gate) = oneshot::channel::<()>();
                let drops = Arc::new(AtomicUsize::new(0));
                let worker_drops = Arc::clone(&drops);
                let mut final_progress = progress(65, TransferPhase::Completed);
                match mode {
                    6 => final_progress.transfer_id = TransferId::new("wrong-worker"),
                    7 => final_progress.phase = TransferPhase::Finalization,
                    8 => final_progress.bytes_transferred = 64,
                    _ => {}
                }
                let returned = match mode {
                    2 => AtpOutcome::Panicked(PanicPayload::new("ATP encoded worker panic")),
                    9 => AtpOutcome::Err(AtpError::Disk(DiskError::IoError)),
                    _ => AtpOutcome::Ok(final_progress),
                };
                let expected_return = returned.clone();
                let mut transfer = admit(&mut lab, root, move |cx, reporter| {
                    drop(reporter);
                    TerminalWorker {
                        cx,
                        gate,
                        outcome: Some(returned),
                        drops: worker_drops,
                        mode,
                    }
                });
                let worker = transfer.worker.task_id();
                assert!(transfer.terminal().is_none());
                assert_eq!(drops.load(Ordering::SeqCst), 0);
                let wake = Arc::new(WakeCount::default());
                let waker = Waker::from(Arc::clone(&wake));
                {
                    let mut waiting = Box::pin(transfer.next_progress());
                    assert!(
                        waiting
                            .as_mut()
                            .poll(&mut Context::from_waker(&waker))
                            .is_pending()
                    );
                }
                assert_eq!(lab.run_until_idle(), 0);
                assert!(!futures_lite::future::block_on(transfer.is_complete()));
                release.send_blocking(()).unwrap();
                lab.run_until_idle();
                assert!(wake.0.load(Ordering::SeqCst) > 0);
                assert_eq!(drops.load(Ordering::SeqCst), 1);
                let terminal = transfer.terminal().expect("actual worker joined").clone();
                if matches!(mode, 2 | 4 | 5) {
                    let Err(JoinError::Cancelled(reason)) = &terminal.worker_join else {
                        panic!(
                            "canonical runtime cancellation must survive user cleanup: {terminal:?}"
                        )
                    };
                    assert_eq!(reason.kind(), crate::types::CancelKind::User);
                    assert_eq!(
                        reason.message.as_deref(),
                        Some("ATP worker capture retired")
                    );
                    assert!(reason.cause.is_none());
                    if mode == 4 {
                        assert_eq!(terminal.outcome, AtpOutcome::Cancelled(reason.clone()));
                        assert_eq!(terminal.worker_outcome, Some(expected_return.clone()));
                    }
                } else {
                    assert_eq!(terminal.worker_join, Ok(()));
                }
                match mode {
                    0 | 9 => assert_eq!(terminal.outcome, expected_return),
                    1 | 5 => assert_eq!(
                        terminal.outcome,
                        AtpOutcome::Panicked(PanicPayload::new("ATP primary worker poll panic"))
                    ),
                    2 => assert_eq!(terminal.outcome, expected_return),
                    3 => assert_eq!(
                        terminal.outcome,
                        AtpOutcome::Panicked(PanicPayload::new("ATP worker destructor panic"))
                    ),
                    4 => {}
                    6..=8 => {
                        assert_eq!(terminal.worker_outcome, Some(expected_return.clone()));
                        assert_eq!(
                            terminal.outcome,
                            AtpOutcome::Err(AtpError::Protocol(
                                ProtocolError::SessionStateMismatch
                            ))
                        );
                    }
                    _ => unreachable!(),
                }
                if matches!(mode, 1 | 2 | 5) {
                    assert_eq!(terminal.worker_outcome, Some(terminal.outcome.clone()));
                }
                if mode == 3 {
                    assert_eq!(terminal.worker_outcome, Some(expected_return.clone()));
                }
                assert_eq!(
                    terminal.cleanup_panic,
                    matches!(mode, 3 | 5)
                        .then(|| { PanicPayload::new("ATP worker destructor panic") })
                );
                for _ in 0..3 {
                    assert!(futures_lite::future::block_on(transfer.is_complete()));
                    assert_eq!(transfer.terminal(), Some(&terminal));
                }
                let final_progress = futures_lite::future::block_on(transfer.next_progress());
                if mode == 0 {
                    assert_eq!(final_progress, Some(progress(65, TransferPhase::Completed)));
                } else {
                    assert_eq!(
                        final_progress, None,
                        "an error without observations cannot manufacture successful progress"
                    );
                }
                assert_eq!(transfer.terminal(), Some(&terminal));
                clean(&mut lab, root, worker);
                eprintln!(
                    "ATP owned worker mode={mode} worker={worker:?} terminal={terminal:?} drops=1"
                );
            }
        }

        #[test]
        fn owned_transfer_cancel_waits_for_real_cleanup_and_drop_requests_worker_cancel() {
            for drop_owner in [false, true] {
                let (mut lab, root) = lab(0x53_0050 + u64::from(drop_owner));
                let (_never, mut pending) = oneshot::channel::<()>();
                let (release, mut cleanup) = oneshot::channel::<()>();
                let seen = Arc::new(parking_lot::Mutex::new(None));
                let worker_seen = Arc::clone(&seen);
                let drops = Arc::new(AtomicUsize::new(0));
                let resource = Dropped(Arc::clone(&drops));
                let mut transfer = admit(&mut lab, root, move |cx, reporter| async move {
                    let _resource = resource;
                    reporter
                        .report(progress(12, TransferPhase::DataTransfer))
                        .unwrap();
                    assert_eq!(pending.recv(&cx).await, Err(oneshot::RecvError::Cancelled));
                    let reason = cx.cancel_reason().expect("actual worker cancel");
                    *worker_seen.lock() = Some(reason.clone());
                    // Required cleanup is deliberately uninterruptible, and
                    // owns its actual channel registration while held.
                    cleanup.recv_uninterruptible().await.unwrap();
                    AtpOutcome::Cancelled(reason)
                });
                let worker = transfer.worker.task_id();
                if drop_owner {
                    drop(transfer);
                    lab.run_until_idle();
                    assert_eq!(
                        seen.lock().as_ref().unwrap().message.as_deref(),
                        Some("ATP transfer handle dropped")
                    );
                    assert_eq!(drops.load(Ordering::SeqCst), 0);
                    assert_eq!(lab.state.live_task_count(), 1);
                    assert_eq!(lab.run_until_idle(), 0);
                    release.send_blocking(()).unwrap();
                    lab.run_until_idle();
                } else {
                    assert!(futures_lite::future::block_on(transfer.cancel()).is_ok());
                    lab.run_until_idle();
                    let reason = seen.lock().clone().expect("worker observed cancellation");
                    assert_eq!(reason.message.as_deref(), Some("ATP transfer cancelled"));
                    assert_eq!(drops.load(Ordering::SeqCst), 0);
                    assert_eq!(lab.state.live_task_count(), 1);
                    for _ in 0..3 {
                        assert!(!futures_lite::future::block_on(transfer.is_complete()));
                    }
                    let wake = Arc::new(WakeCount::default());
                    let waker = Waker::from(Arc::clone(&wake));
                    {
                        let mut waiting = Box::pin(transfer.wait_for_terminal());
                        assert!(
                            waiting
                                .as_mut()
                                .poll(&mut Context::from_waker(&waker))
                                .is_pending()
                        );
                    }
                    assert_eq!(lab.run_until_idle(), 0);
                    release.send_blocking(()).unwrap();
                    lab.run_until_idle();
                    assert!(wake.0.load(Ordering::SeqCst) > 0);
                    let terminal = transfer.terminal().unwrap().clone();
                    assert_eq!(
                        terminal.worker_join,
                        Err(JoinError::Cancelled(reason.clone()))
                    );
                    assert_eq!(
                        terminal.worker_outcome,
                        Some(AtpOutcome::Cancelled(reason.clone()))
                    );
                    assert_eq!(terminal.outcome, AtpOutcome::Cancelled(reason));
                    // Repeated completion queries did not consume the update.
                    assert_eq!(
                        futures_lite::future::block_on(transfer.next_progress()),
                        Some(progress(12, TransferPhase::DataTransfer))
                    );
                    assert_eq!(
                        futures_lite::future::block_on(transfer.next_progress()),
                        Some(progress(12, TransferPhase::Cancelled))
                    );
                    assert_eq!(
                        futures_lite::future::block_on(transfer.next_progress()),
                        None
                    );
                    assert_eq!(transfer.terminal(), Some(&terminal));
                }
                assert_eq!(drops.load(Ordering::SeqCst), 1);
                clean(&mut lab, root, worker);
            }
        }

        #[test]
        fn owned_transfer_reporter_refuses_false_terminal_and_preserves_public_traits() {
            fn public_traits<T: Send + Sync + Unpin + std::fmt::Debug>() {}
            public_traits::<ActiveTransfer>();
            public_traits::<TransferProgressReporter>();
            let cx = Cx::for_testing();
            let refused = ActiveTransfer::spawn_worker(
                &cx,
                &cx.scope(),
                TransferId::new("no-runtime"),
                TransferOptions::default(),
                |_, _| async { panic!("an unavailable runtime must not run a worker") },
            );
            assert!(matches!(refused, Err(SpawnError::RuntimeUnavailable)));

            let (mut lab, root) = lab(0x53_0060);
            let (release, mut gate) = oneshot::channel::<()>();
            let reporter_slot = Arc::new(parking_lot::Mutex::new(None));
            let publication = Arc::clone(&reporter_slot);
            let mut transfer = admit(&mut lab, root, move |cx, reporter| async move {
                *publication.lock() = Some(reporter.clone());
                gate.recv(&cx).await.unwrap();
                AtpOutcome::Err(AtpError::Disk(DiskError::IoError))
            });
            let worker = transfer.worker.task_id();
            let reporter = reporter_slot.lock().take().unwrap();
            let mut wrong = progress(1, TransferPhase::DataTransfer);
            wrong.transfer_id = TransferId::new("other-transfer");
            assert_eq!(
                reporter.report(wrong),
                Err(TransferProgressError::IdentityMismatch)
            );
            for phase in [
                TransferPhase::Completed,
                TransferPhase::Failed,
                TransferPhase::Cancelled,
            ] {
                assert_eq!(
                    reporter.report(progress(65, phase)),
                    Err(TransferProgressError::TerminalPhase)
                );
            }
            assert_eq!(
                reporter.report(progress(66, TransferPhase::DataTransfer)),
                Err(TransferProgressError::InvalidByteCount)
            );
            assert_eq!(transfer.shared.lock().sequence, 0);
            assert!(transfer.shared.lock().pending.is_none());
            assert!(!futures_lite::future::block_on(transfer.is_complete()));
            let mut unknown_size = progress(3, TransferPhase::DataTransfer);
            unknown_size.total_bytes = 0;
            assert_eq!(reporter.report(unknown_size), Ok(1));
            assert_eq!(
                reporter.report(progress(2, TransferPhase::DataTransfer)),
                Ok(2)
            );
            assert!(!futures_lite::future::block_on(transfer.is_complete()));
            release.send_blocking(()).unwrap();
            lab.run_until_idle();
            assert!(transfer.terminal().is_some());
            assert_eq!(
                reporter.report(progress(3, TransferPhase::DataTransfer)),
                Err(TransferProgressError::Closed)
            );
            assert_eq!(
                futures_lite::future::block_on(transfer.next_progress()),
                Some(progress(2, TransferPhase::DataTransfer))
            );
            assert_eq!(
                futures_lite::future::block_on(transfer.next_progress()),
                Some(progress(2, TransferPhase::Failed))
            );
            assert_eq!(
                transfer.terminal().unwrap().outcome,
                AtpOutcome::Err(AtpError::Disk(DiskError::IoError))
            );
            drop(transfer);
            assert_eq!(
                reporter.report(progress(3, TransferPhase::DataTransfer)),
                Err(TransferProgressError::Closed)
            );
            clean(&mut lab, root, worker);
        }

        #[test]
        fn owned_transfer_cancel_before_admission_never_enters_worker_factory() {
            cancelled_before_admission(false);
        }

        #[test]
        fn owned_transfer_unadmitted_factory_drop_panic_preserves_join_and_cleanup() {
            cancelled_before_admission(true);
        }

        struct UnstartedFactoryCapture {
            drops: Arc<AtomicUsize>,
            panic_on_drop: bool,
        }

        impl Drop for UnstartedFactoryCapture {
            fn drop(&mut self) {
                assert_eq!(self.drops.fetch_add(1, Ordering::SeqCst), 0);
                assert!(!self.panic_on_drop, "ATP unadmitted factory capture panic");
            }
        }

        fn cancelled_before_admission(panic_on_drop: bool) {
            let (mut lab, root) = lab(0x53_0070);
            let calls = Arc::new(AtomicUsize::new(0));
            let drops = Arc::new(AtomicUsize::new(0));
            let resource = UnstartedFactoryCapture {
                drops: Arc::clone(&drops),
                panic_on_drop,
            };
            let worker_calls = Arc::clone(&calls);
            let publication = Arc::new(parking_lot::Mutex::new(None));
            let slot = Arc::clone(&publication);
            let (release, mut close) = oneshot::channel::<()>();
            let coordinator: Pin<Box<dyn Future<Output = ()> + Send>> = Box::pin(async move {
                let cx = Cx::current().expect("actual pre-admission coordinator");
                let child = cx
                    .open_child_region(crate::cx::ChildRegionSpec::inherit())
                    .await
                    .unwrap();
                let mut transfer = ActiveTransfer::spawn_worker(
                    child.cx(),
                    &child.cx().scope(),
                    TransferId::new("owned-worker"),
                    TransferOptions::default(),
                    move |_, _| {
                        worker_calls.fetch_add(1, Ordering::SeqCst);
                        drop(resource);
                        std::future::ready(AtpOutcome::Ok(progress(65, TransferPhase::Completed)))
                    },
                )
                .unwrap();
                assert_eq!(transfer.state(), ActiveTransferState::Pending);
                assert!(transfer.cancel().await.is_ok());
                assert!(!transfer.is_complete().await);
                *slot.lock() = Some((transfer, child.region_id()));
                close.recv(&cx).await.unwrap();
                child.close().await.unwrap();
            });
            let (parent, mut joined) = lab
                .state
                .create_task(root, Budget::INFINITE, coordinator)
                .unwrap();
            lab.scheduler.lock().schedule(parent, 0);
            // Each actual Lab step drains earlier requests before polling the
            // coordinator. Stop immediately after it publishes the new request,
            // before the following step can admit that request.
            let mut request = None;
            for _ in 0..8 {
                lab.step_for_test();
                request = publication.lock().take();
                if request.is_some() {
                    break;
                }
            }
            let (mut transfer, child) = request.expect("real queued spawn before admission");
            let provisional = transfer.worker.task_id();
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            assert_eq!(drops.load(Ordering::SeqCst), 0);
            assert_eq!(transfer.state(), ActiveTransferState::Pending);
            assert_eq!(lab.state.region(child).unwrap().pending_spawn_count(), 1);
            assert!(lab.state.task(provisional).is_none());

            // This is the actual runtime cancellation transition, not a forged
            // Cx/TaskRecord or a direct invocation of a denial completion slot.
            // Parent cancellation closes admission before the queued worker is
            // drained. It is stronger than the handle's earlier User request.
            let reason = CancelReason::new(crate::types::CancelKind::ParentCancelled);
            let (tasks, wakes) = lab.state.cancel_request(child, &reason, None).into_parts();
            assert!(tasks.is_empty(), "no worker has been admitted to cancel");
            wakes.dispatch();
            assert!(lab.run_until_idle() < 4096);
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            assert!(!transfer.shared.lock().started);
            let terminal = transfer
                .terminal()
                .expect("actual unadmitted cancellation")
                .clone();
            assert_eq!(terminal.worker_outcome, None);
            let cleanup_panic =
                panic_on_drop.then(|| PanicPayload::new("ATP unadmitted factory capture panic"));
            assert_eq!(terminal.cleanup_panic, cleanup_panic);
            assert_eq!(
                terminal.worker_join,
                Err(JoinError::Cancelled(reason.clone()))
            );
            assert_eq!(
                terminal.outcome,
                cleanup_panic.map_or_else(|| AtpOutcome::Cancelled(reason), AtpOutcome::Panicked,)
            );
            assert!(futures_lite::future::block_on(transfer.is_complete()));
            assert_eq!(
                futures_lite::future::block_on(transfer.next_progress()),
                None
            );
            assert_eq!(transfer.terminal(), Some(&terminal));
            let trace = lab.state.trace_handle().snapshot();
            for (kind, count) in [
                (crate::trace::TraceEventKind::TaskSpawnEnqueued, 1),
                (crate::trace::TraceEventKind::Spawn, 0),
                (crate::trace::TraceEventKind::Complete, 0),
            ] {
                assert_eq!(trace.iter().filter(|event| {
                    event.kind == kind
                        && matches!(event.data, crate::trace::TraceData::Task { task, region }
                            if task == provisional && region == child)
                }).count(), count, "actual denied request {provisional:?} {kind:?}");
            }
            release.send_blocking(()).unwrap();
            lab.run_until_idle();
            assert_eq!(joined.try_join(), Ok(Some(())));
            assert!(lab.state.region(child).is_none());
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            clean(&mut lab, root, parent);
            eprintln!(
                "ATP pre-admission cancellation request={provisional:?} child={child:?} terminal={terminal:?} factory_calls={} capture_drops={}",
                calls.load(Ordering::SeqCst),
                drops.load(Ordering::SeqCst)
            );
        }

        #[test]
        fn owned_transfer_factory_construction_panic_retires_its_capture_once() {
            let (mut lab, root) = lab(0x53_0080);
            let calls = Arc::new(AtomicUsize::new(0));
            let drops = Arc::new(AtomicUsize::new(0));
            let worker_calls = Arc::clone(&calls);
            let resource = Dropped(Arc::clone(&drops));
            let mut transfer = admit(
                &mut lab,
                root,
                move |_, _| -> std::future::Ready<AtpOutcome<TransferProgress>> {
                    let _resource = resource;
                    worker_calls.fetch_add(1, Ordering::SeqCst);
                    panic!("ATP worker factory construction panic");
                },
            );
            let worker = transfer.worker.task_id();
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            let terminal = transfer
                .terminal()
                .expect("actual factory-panic worker joined")
                .clone();
            let panic =
                AtpOutcome::Panicked(PanicPayload::new("ATP worker factory construction panic"));
            assert_eq!(terminal.worker_outcome, Some(panic.clone()));
            assert_eq!(
                terminal.cleanup_panic, None,
                "no worker future was constructed"
            );
            assert_eq!(
                terminal.worker_join,
                Ok(()),
                "the adapter caught the factory panic"
            );
            assert_eq!(terminal.outcome, panic);
            for _ in 0..3 {
                assert!(futures_lite::future::block_on(transfer.is_complete()));
                assert_eq!(transfer.terminal(), Some(&terminal));
            }
            assert_eq!(
                futures_lite::future::block_on(transfer.next_progress()),
                None
            );
            assert_eq!(
                futures_lite::future::block_on(transfer.wait_for_terminal()),
                &terminal
            );
            clean(&mut lab, root, worker);
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert_eq!(drops.load(Ordering::SeqCst), 1);
        }
    }
}
