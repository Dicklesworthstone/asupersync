//! ATP transfer operations and management.

use crate::cx::Cx;
use crate::net::atp::protocol::{AtpOutcome, IdempotencyKey, AtpError, DiskError};
use super::{
    AtpSession, TransferId, TransferProgress, TransferPhase, SessionConfig,
    SdkMode, TransferPolicy
};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use crate::channel::mpsc;
use serde::{Deserialize, Serialize};

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
    /// Progress receiver channel.
    progress_rx: mpsc::Receiver<TransferProgress>,
    /// Cancellation sender.
    cancel_tx: mpsc::Sender<()>,
    /// Transfer configuration.
    options: TransferOptions,
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
            SdkMode::InProcess => self.receive_object_in_process(cx, destination, options).await,
            SdkMode::DaemonDelegated { .. } => {
                self.receive_object_daemon_delegated(cx, destination, options).await
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

    /// Verify an object's integrity and authenticity.
    pub async fn verify_object(
        &self,
        cx: &Cx,
        object_path: &Path,
        expected_hash: Option<&[u8]>,
    ) -> AtpOutcome<ObjectVerification> {
        match &self.mode {
            SdkMode::InProcess => self.verify_object_in_process(cx, object_path, expected_hash).await,
            SdkMode::DaemonDelegated { .. } => {
                self.verify_object_daemon_delegated(cx, object_path, expected_hash).await
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
            SdkMode::InProcess => self.resume_transfer_in_process(cx, transfer_id, checkpoint).await,
            SdkMode::DaemonDelegated { .. } => {
                self.resume_transfer_daemon_delegated(cx, transfer_id, checkpoint).await
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
            SdkMode::InProcess => self.cancel_transfer_in_process(cx, transfer_id, reason).await,
            SdkMode::DaemonDelegated { .. } => {
                self.cancel_transfer_daemon_delegated(cx, transfer_id, reason).await
            }
        }
    }

    // In-process implementations
    async fn send_object_in_process(
        &self,
        cx: &Cx,
        request: TransferRequest,
    ) -> AtpOutcome<ActiveTransfer> {
        let transfer_id = request.options.transfer_id.clone()
            .unwrap_or_else(TransferId::generate);

        // Validate source data exists and is accessible
        match self.validate_transfer_source(&request.source).await {
            AtpOutcome::Ok(_) => {},
            AtpOutcome::Err(e) => return AtpOutcome::Err(e),
            AtpOutcome::Cancelled => return AtpOutcome::Cancelled,
            AtpOutcome::Panicked(p) => return AtpOutcome::Panicked(p),
        }

        // Create progress and cancellation channels
        let (progress_tx, progress_rx) = mpsc::channel(100);
        let (cancel_tx, mut cancel_rx) = mpsc::channel(1);

        // Simulate initial progress (in a real implementation, background tasks would drive progress)
        let total_bytes = self.calculate_transfer_size(&request.source).await.unwrap_or(0);
        let initial_progress = TransferProgress {
            transfer_id: transfer_id.clone(),
            bytes_transferred: 0,
            total_bytes,
            speed_bytes_per_sec: 0,
            eta_ms: None,
            phase: TransferPhase::Initializing,
            active_paths: 1,
            repair_symbols_active: false,
        };

        // Send initial progress - ignore if receiver is gone
        let _ = progress_tx.try_send(initial_progress);

        AtpOutcome::Ok(ActiveTransfer {
            transfer_id,
            progress_rx,
            cancel_tx,
            options: request.options,
        })
    }

    async fn receive_object_in_process(
        &self,
        _cx: &Cx,
        _destination: TransferDestination,
        options: TransferOptions,
    ) -> AtpOutcome<ActiveTransfer> {
        // TODO: Implement receive logic
        let transfer_id = options.transfer_id.unwrap_or_else(TransferId::generate);
        let (progress_tx, progress_rx) = mpsc::channel(100);
        let (cancel_tx, _cancel_rx) = mpsc::channel(1);

        // Simulate receive operation (simplified without background task)
        // TODO: Implement proper background task with Cx::spawn
        let initial_progress = TransferProgress {
            transfer_id: transfer_id.clone(),
            bytes_transferred: 0,
            total_bytes: 0,
            speed_bytes_per_sec: 0,
            eta_ms: None,
            phase: TransferPhase::Initializing,
            active_paths: 1,
            repair_symbols_active: false,
        };
        let _ = progress_tx.try_send(initial_progress);

        AtpOutcome::Ok(ActiveTransfer {
            transfer_id,
            progress_rx,
            cancel_tx,
            options,
        })
    }

    async fn verify_object_in_process(
        &self,
        _cx: &Cx,
        object_path: &Path,
        _expected_hash: Option<&[u8]>,
    ) -> AtpOutcome<ObjectVerification> {
        if !object_path.exists() {
            return AtpOutcome::Err(AtpError::Disk(DiskError::FileNotFound));
        }

        // TODO: Implement actual verification logic
        AtpOutcome::Ok(ObjectVerification {
            path: object_path.to_path_buf(),
            hash: vec![0u8; 32], // Placeholder hash
            size_bytes: 0,
            verified: true,
            integrity_check_passed: true,
            signature_valid: None,
        })
    }

    async fn resume_transfer_in_process(
        &self,
        _cx: &Cx,
        transfer_id: &TransferId,
        _checkpoint: &str,
    ) -> AtpOutcome<ActiveTransfer> {
        // TODO: Implement resume logic
        let (progress_tx, progress_rx) = mpsc::channel(100);
        let (cancel_tx, _cancel_rx) = mpsc::channel(1);

        // Simulate resumed transfer (simplified without background task)
        let initial_progress = TransferProgress {
            transfer_id: transfer_id.clone(),
            bytes_transferred: 0,
            total_bytes: 0,
            speed_bytes_per_sec: 0,
            eta_ms: None,
            phase: TransferPhase::DataTransfer, // Resume from data transfer phase
            active_paths: 1,
            repair_symbols_active: false,
        };
        let _ = progress_tx.try_send(initial_progress);

        AtpOutcome::Ok(ActiveTransfer {
            transfer_id: transfer_id.clone(),
            progress_rx,
            cancel_tx,
            options: TransferOptions::default(),
        })
    }

    async fn cancel_transfer_in_process(
        &self,
        _cx: &Cx,
        _transfer_id: &TransferId,
        _reason: Option<String>,
    ) -> AtpOutcome<()> {
        // TODO: Implement cancellation logic
        Ok(())
    }

    // Daemon-delegated implementations (stubs for now)
    async fn send_object_daemon_delegated(
        &self,
        _cx: &Cx,
        _request: TransferRequest,
    ) -> AtpOutcome<ActiveTransfer> {
        Err(AtpError::Daemon(crate::net::atp::protocol::DaemonError::ServiceUnavailable))
    }

    async fn receive_object_daemon_delegated(
        &self,
        _cx: &Cx,
        _destination: TransferDestination,
        _options: TransferOptions,
    ) -> AtpOutcome<ActiveTransfer> {
        Err(AtpError::Daemon(crate::net::atp::protocol::DaemonError::ServiceUnavailable))
    }

    async fn verify_object_daemon_delegated(
        &self,
        _cx: &Cx,
        _object_path: &Path,
        _expected_hash: Option<&[u8]>,
    ) -> AtpOutcome<ObjectVerification> {
        Err(AtpError::Daemon(crate::net::atp::protocol::DaemonError::ServiceUnavailable))
    }

    async fn resume_transfer_daemon_delegated(
        &self,
        _cx: &Cx,
        _transfer_id: &TransferId,
        _checkpoint: &str,
    ) -> AtpOutcome<ActiveTransfer> {
        Err(AtpError::Daemon(crate::net::atp::protocol::DaemonError::ServiceUnavailable))
    }

    async fn cancel_transfer_daemon_delegated(
        &self,
        _cx: &Cx,
        _transfer_id: &TransferId,
        _reason: Option<String>,
    ) -> AtpOutcome<()> {
        Err(AtpError::Daemon(crate::net::atp::protocol::DaemonError::ServiceUnavailable))
    }

    // Helper methods
    async fn validate_transfer_source(&self, source: &TransferSource) -> AtpOutcome<()> {
        match source {
            TransferSource::File { path } => {
                if !path.exists() {
                    return Err(AtpError::Disk(DiskError::FileNotFound));
                }
                if !path.is_file() {
                    return Err(AtpError::Disk(DiskError::IoError));
                }
            }
            TransferSource::Directory { path, .. } => {
                if !path.exists() {
                    return Err(AtpError::Disk(DiskError::DirectoryNotFound));
                }
                if !path.is_dir() {
                    return Err(AtpError::Disk(DiskError::IoError));
                }
            }
            TransferSource::Object { .. } | TransferSource::Stream { .. } => {
                // Always valid for in-memory sources
            }
        }
        Ok(())
    }

    async fn calculate_transfer_size(&self, source: &TransferSource) -> AtpOutcome<u64> {
        match source {
            TransferSource::File { path } => {
                let metadata = crate::fs::metadata(path).await
                    .map_err(|_| AtpError::Disk(DiskError::IoError))?;
                Ok(metadata.len())
            }
            TransferSource::Directory { path, .. } => {
                // TODO: Calculate directory size recursively
                Ok(1024 * 1024) // Placeholder: 1MB
            }
            TransferSource::Object { data, .. } => {
                Ok(data.len() as u64)
            }
            TransferSource::Stream { size_hint, .. } => {
                Ok(size_hint.unwrap_or(0))
            }
        }
    }
}

impl ActiveTransfer {
    /// Get the transfer ID.
    #[must_use]
    pub const fn transfer_id(&self) -> &TransferId {
        &self.transfer_id
    }

    /// Get the next progress update.
    pub async fn next_progress(&mut self) -> Option<TransferProgress> {
        self.progress_rx.recv().await
    }

    /// Cancel this transfer.
    pub async fn cancel(&self) -> AtpOutcome<()> {
        self.cancel_tx.send(())
            .await
            .map_err(|_| AtpError::Platform(crate::net::atp::protocol::PlatformError::OperatingSystemError))
    }

    /// Check if transfer is complete based on the last known progress.
    pub async fn is_complete(&mut self) -> bool {
        // Peek at progress without consuming
        match self.progress_rx.try_recv() {
            Ok(progress) => progress.is_complete(),
            Err(_) => false,
        }
    }

    /// Wait for the transfer to complete and return the final progress.
    pub async fn wait_for_completion(mut self) -> Option<TransferProgress> {
        let mut last_progress = None;
        while let Some(progress) = self.next_progress().await {
            let is_complete = progress.is_complete();
            last_progress = Some(progress);
            if is_complete {
                break;
            }
        }
        last_progress
    }
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
    /// Whether verification was successful.
    pub verified: bool,
    /// Whether integrity check passed.
    pub integrity_check_passed: bool,
    /// Whether signature verification passed (if applicable).
    pub signature_valid: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cx::Cx;
    use crate::net::atp::protocol::PeerId;
    use crate::net::atp::sdk::{AtpSdk, SessionConfig, SessionOptions};

    #[tokio::test]
    async fn transfer_request_construction() {
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

    #[tokio::test]
    async fn active_transfer_lifecycle() {
        let config = SessionConfig::default();
        let sdk = AtpSdk::new_in_process(config);
        let cx = Cx::root();

        let peer = PeerId::from_label("test_peer");
        let session_options = SessionOptions::direct(peer);
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

        let mut transfer = session.send_object(&cx, request).await.unwrap();

        // Wait for some progress updates
        let mut progress_count = 0;
        while let Some(progress) = transfer.next_progress().await {
            progress_count += 1;
            if progress.is_complete() || progress_count > 10 {
                break;
            }
        }

        assert!(progress_count > 0);
    }

    #[tokio::test]
    async fn transfer_cancellation() {
        let config = SessionConfig::default();
        let sdk = AtpSdk::new_in_process(config);
        let cx = Cx::root();

        let peer = PeerId::from_label("test_peer");
        let session_options = SessionOptions::direct(peer);
        let session = sdk.open_session(&cx, session_options).await.unwrap();

        let source = TransferSource::Object {
            data: vec![0u8; 1024 * 1024], // 1MB
            content_type: None,
        };
        let destination = TransferDestination::Object {
            object_id: "large_object".to_string(),
        };
        let request = TransferRequest {
            source,
            destination,
            options: TransferOptions::default(),
        };

        let transfer = session.send_object(&cx, request).await.unwrap();

        // Cancel the transfer
        let cancel_result = transfer.cancel().await;
        assert!(cancel_result.is_ok());
    }
}