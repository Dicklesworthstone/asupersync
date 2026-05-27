//! ATP transfer operations and management.

#![allow(dead_code)]

use super::{AtpSession, SdkMode, TransferId, TransferPhase, TransferProgress};
use crate::channel::mpsc;
use crate::cx::Cx;
use crate::net::atp::protocol::{
    AtpError, AtpOutcome, DiskError, IdempotencyKey, PlatformError, ProtocolError,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

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
    /// Progress receiver channel.
    progress_rx: mpsc::Receiver<TransferProgress>,
    /// Cancellation sender.
    cancel_tx: mpsc::Sender<()>,
    /// Cancellation receiver kept alive until a real worker owns the cancellation channel.
    _cancel_rx: mpsc::Receiver<()>,
    /// Whether cancellation has already been requested through this handle.
    cancel_requested: AtomicBool,
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

    /// Verify an object's integrity and authenticity.
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
        let transfer_id = request
            .options
            .transfer_id
            .clone()
            .unwrap_or_else(TransferId::generate);
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

        // Create progress and cancellation channels
        let (progress_tx, progress_rx) = mpsc::channel(100);
        let (cancel_tx, cancel_rx) = mpsc::channel(1);

        let total_bytes = match self.calculate_transfer_size(&request.source).await {
            AtpOutcome::Ok(total_bytes) => total_bytes,
            AtpOutcome::Err(error) => return AtpOutcome::Err(error),
            AtpOutcome::Cancelled(reason) => return AtpOutcome::Cancelled(reason),
            AtpOutcome::Panicked(payload) => return AtpOutcome::Panicked(payload),
        };
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
            _cancel_rx: cancel_rx,
            cancel_requested: AtomicBool::new(false),
            options: request.options,
        })
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
        AtpOutcome::Err(AtpError::Protocol(ProtocolError::SessionStateMismatch))
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
        let verified = integrity_check_passed && signature_valid.unwrap_or(true);

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
        AtpOutcome::Err(AtpError::Protocol(ProtocolError::SessionStateMismatch))
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
        AtpOutcome::Err(AtpError::Protocol(ProtocolError::SessionStateMismatch))
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
        AtpOutcome::Err(AtpError::Daemon(
            crate::net::atp::protocol::DaemonError::ServiceUnavailable,
        ))
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
        AtpOutcome::Err(AtpError::Daemon(
            crate::net::atp::protocol::DaemonError::ServiceUnavailable,
        ))
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
        AtpOutcome::Err(AtpError::Daemon(
            crate::net::atp::protocol::DaemonError::ServiceUnavailable,
        ))
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
        if envelope.algorithm != OBJECT_SIGNATURE_ALGORITHM {
            return false;
        }
        if envelope.size_bytes != size_bytes {
            return false;
        }
        if envelope.session_id_hex != hex::encode(self.session_id().as_bytes()) {
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
    let bytes = hex::decode(input)?;
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
    /// Get the transfer ID.
    #[must_use]
    pub const fn transfer_id(&self) -> &TransferId {
        &self.transfer_id
    }

    /// Get the next progress update.
    pub async fn next_progress(&mut self) -> Option<TransferProgress> {
        self.progress_rx.try_recv().ok()
    }

    /// Cancel this transfer.
    pub async fn cancel(&self) -> AtpOutcome<()> {
        if self.cancel_requested.swap(true, Ordering::AcqRel) {
            return AtpOutcome::Ok(());
        }

        match self.cancel_tx.try_send(()) {
            Ok(()) => AtpOutcome::Ok(()),
            Err(crate::channel::mpsc::SendError::Full(())) => AtpOutcome::Ok(()),
            Err(_) => AtpOutcome::Err(AtpError::Platform(PlatformError::OperatingSystemError)),
        }
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
    use crate::net::atp::protocol::{
        CapabilityAction, CapabilityGrant, CapabilityGrantId, CapabilityScope, PeerId,
        ProtocolError, SessionContextKind,
    };
    use crate::net::atp::sdk::{AtpSdk, SessionConfig, SessionOptions};

    fn granted_direct_options(config: &SessionConfig, peer: PeerId, label: &str) -> SessionOptions {
        SessionOptions::direct(peer).with_grants(vec![CapabilityGrant::new(
            CapabilityGrantId::from_label(label),
            peer,
            config.local_peer,
            [CapabilityAction::Read, CapabilityAction::Write],
            CapabilityScope::for_context(SessionContextKind::Direct),
        )])
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
    fn active_transfer_lifecycle() {
        futures_lite::future::block_on(async {
            let config = SessionConfig::default();
            let peer = PeerId::from_label("test_peer");
            let session_options = granted_direct_options(&config, peer, "active-transfer");
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
        });
    }

    #[test]
    fn transfer_cancellation() {
        futures_lite::future::block_on(async {
            let config = SessionConfig::default();
            let peer = PeerId::from_label("test_peer");
            let session_options = granted_direct_options(&config, peer, "transfer-cancel");
            let sdk = AtpSdk::new_in_process(config);
            let cx = Cx::for_testing();

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
            let repeated_cancel_result = transfer.cancel().await;
            assert!(repeated_cancel_result.is_ok());
        });
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
                AtpOutcome::Err(AtpError::Protocol(ProtocolError::SessionStateMismatch)) => {}
                other => panic!("receive must fail closed without a real transport: {other:?}"), // ubs:ignore
            }
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
                AtpOutcome::Err(AtpError::Protocol(ProtocolError::SessionStateMismatch)) => {}
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
                AtpOutcome::Err(AtpError::Protocol(ProtocolError::SessionStateMismatch)) => {}
                other => panic!("session cancel must not fabricate success: {other:?}"), // ubs:ignore
            }
        });
    }

    #[test]
    fn detached_object_signature_is_session_bound_and_constant_time_checked() {
        futures_lite::future::block_on(async {
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
            let signature = session.compute_detached_object_signature(&hash, object.len() as u64);
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
            let nonce = std::time::SystemTime::now() // ubs:ignore
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let source = TransferSource::File {
                path: std::env::temp_dir().join(format!(
                    // ubs:ignore
                    "asupersync_missing_size_{}_{}",
                    std::process::id(), // ubs:ignore
                    nonce
                )),
            };

            match session.calculate_transfer_size(&source).await {
                AtpOutcome::Err(AtpError::Disk(DiskError::IoError)) => {}
                other => panic!("metadata failure must remain an error, got {other:?}"), // ubs:ignore
            }
        });
    }
}
