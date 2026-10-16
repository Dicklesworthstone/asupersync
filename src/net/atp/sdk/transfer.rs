//! ATP transfer operations and management.

#![allow(dead_code)]

use super::{AtpSession, SdkMode, TransferId, TransferPhase, TransferProgress};
use crate::cx::{Cx, Scope};
use crate::net::atp::protocol::{AtpError, AtpOutcome, DiskError, IdempotencyKey, ProtocolError};
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

/// A failed checkpoint is cancellation, not an operating-system error
/// (asupersync-bi2462.127).
fn cancelled_outcome<T>(cx: &Cx) -> AtpOutcome<T> {
    AtpOutcome::Cancelled(
        cx.cancel_reason()
            .unwrap_or_else(CancelReason::parent_cancelled),
    )
}

/// Read size for `verify_object`: it hashes one bounded chunk at a time
/// because transfer policy admits objects far larger than memory.
const VERIFY_OBJECT_READ_BYTES: usize = 256 * 1024;

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
            return cancelled_outcome(cx);
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
            return cancelled_outcome(cx);
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
        cx: &Cx,
        object_path: &Path,
        expected_hash: Option<&[u8]>,
    ) -> AtpOutcome<ObjectVerification> {
        if cx.checkpoint().is_err() {
            return cancelled_outcome(cx);
        }
        if !object_path.exists() {
            return AtpOutcome::Err(AtpError::Disk(DiskError::FileNotFound));
        }

        let mut buffer = vec![0_u8; VERIFY_OBJECT_READ_BYTES];
        let (size_bytes, _, computed_hash) =
            match crate::net::atp::transport_common::streaming::hash_file_streaming(
                object_path,
                &mut buffer,
            )
            .await
            {
                Ok(digest) => digest,
                Err(_) => return AtpOutcome::Err(AtpError::Disk(DiskError::IoError)),
            };
        if cx.checkpoint().is_err() {
            return cancelled_outcome(cx);
        }

        // Only the expected hash decides integrity. File shape proves nothing:
        // a tar archive ends in zero blocks, and an empty file is valid
        // content whatever its path says (asupersync-bi2462.127).
        let mut integrity_check_passed = true;
        if let Some(expected) = expected_hash {
            use subtle::ConstantTimeEq;
            if !bool::from(computed_hash.ct_eq(expected)) {
                // ubs:ignore - using constant time eq
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
            return cancelled_outcome(cx);
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
            return cancelled_outcome(cx);
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
            return cancelled_outcome(cx);
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
            return cancelled_outcome(cx);
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
            return cancelled_outcome(cx);
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
#[path = "transfer_inline_tests.rs"]
mod tests;
