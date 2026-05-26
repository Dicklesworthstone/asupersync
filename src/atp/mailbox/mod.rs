//! ATP Offline Mailbox - Encrypted relay storage for offline peer transfers.
//!
//! The mailbox system allows peers to transfer data asynchronously when they
//! cannot be online simultaneously. Key features:
//!
//! - **Encrypted storage**: Relay cannot access plaintext content
//! - **Tamper evidence**: Cryptographic detection of relay misbehavior
//! - **Quota management**: Resource limits and abuse prevention
//! - **Crash-safe journals**: Reliable state management
//!
//! # Security Model
//!
//! The mailbox relay is untrusted - it provides storage but cannot decrypt
//! content or tamper with data undetected. All security properties derive
//! from client-side cryptography and manifest verification.
//!
//! # Usage Example
//!
//! ```rust,ignore
//! use asupersync::atp::mailbox::{MailboxClient, MailboxConfig};
//!
//! let config = MailboxConfig {
//!     relay_endpoint: "relay.example.com:8080".parse().unwrap(),
//!     encryption_key: generate_mailbox_key(),
//!     quota_limit: 1_000_000_000, // 1GB
//! };
//!
//! let mut client = MailboxClient::new(config).await?;
//!
//! // Send to offline peer
//! let transfer_id = client.send_to_mailbox(
//!     peer_id,
//!     object_graph,
//!     retention_policy
//! ).await?;
//!
//! // Receive from mailbox
//! let transfers = client.check_mailbox().await?;
//! for transfer in transfers {
//!     let object = client.receive_from_mailbox(transfer.id).await?;
//!     // Verify and process object
//! }
//! ```

use crate::cx::Cx;
use crate::types::Time;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

pub mod client;
pub mod encryption;
pub mod quota;
pub mod relay;
pub mod storage;

pub use client::MailboxClient;
pub use encryption::{MailboxKey, EncryptedChunk, ChunkNonce};
pub use quota::{QuotaManager, QuotaPolicy, QuotaUsage};
pub use relay::{RelayClient, RelayProtocol, RelayMessage};
pub use storage::{MailboxStorage, MailboxEntry, TransferState};

/// Unique identifier for a mailbox transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MailboxTransferId(pub uuid::Uuid);

impl MailboxTransferId {
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }

    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(uuid::Uuid::from_bytes(bytes))
    }

    pub fn to_bytes(self) -> [u8; 16] {
        self.0.into_bytes()
    }
}

impl Default for MailboxTransferId {
    fn default() -> Self {
        Self::new()
    }
}

/// Unique identifier for a peer in the ATP network.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PeerId(pub String);

impl PeerId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Configuration for mailbox client operations.
#[derive(Debug, Clone)]
pub struct MailboxConfig {
    /// Relay server endpoint for mailbox storage
    pub relay_endpoint: SocketAddr,

    /// Encryption key for mailbox content
    pub encryption_key: MailboxKey,

    /// Maximum storage quota in bytes
    pub quota_limit: u64,

    /// Default retention time for mailbox entries
    pub default_retention: Duration,

    /// Timeout for relay operations
    pub operation_timeout: Duration,

    /// Maximum chunk size for encrypted storage
    pub max_chunk_size: usize,

    /// Enable tamper detection logging
    pub tamper_detection: bool,
}

impl Default for MailboxConfig {
    fn default() -> Self {
        Self {
            relay_endpoint: "127.0.0.1:8080".parse().unwrap(),
            encryption_key: MailboxKey::generate(),
            quota_limit: 100_000_000, // 100MB default
            default_retention: Duration::from_secs(7 * 24 * 3600), // 1 week
            operation_timeout: Duration::from_secs(30),
            max_chunk_size: 1024 * 1024, // 1MB chunks
            tamper_detection: true,
        }
    }
}

/// Mailbox transfer metadata visible to the relay (encrypted content is opaque).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailboxTransferMetadata {
    /// Transfer identifier
    pub transfer_id: MailboxTransferId,

    /// Destination peer identifier
    pub destination_peer: PeerId,

    /// Transfer creation timestamp
    pub created_at: Time,

    /// Expiry timestamp for automatic cleanup
    pub expires_at: Time,

    /// Total transfer size in bytes (encrypted)
    pub total_size: u64,

    /// Number of encrypted chunks
    pub chunk_count: u32,

    /// Sender-provided metadata (encrypted)
    pub encrypted_metadata: Vec<u8>,
}

/// Result of a mailbox operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailboxOperationResult {
    /// Whether the operation succeeded
    pub success: bool,

    /// Transfer ID if applicable
    pub transfer_id: Option<MailboxTransferId>,

    /// Quota usage after operation
    pub quota_usage: QuotaUsage,

    /// Operation duration in milliseconds
    pub duration_ms: u64,

    /// Any warnings or informational messages
    pub messages: Vec<String>,

    /// Relay-provided operation receipt
    pub relay_receipt: Option<String>,
}

/// Events emitted during mailbox operations for observability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MailboxEvent {
    /// Transfer upload started
    TransferUploadStarted {
        transfer_id: MailboxTransferId,
        destination: PeerId,
        total_size: u64,
    },

    /// Chunk uploaded to relay
    ChunkUploaded {
        transfer_id: MailboxTransferId,
        chunk_index: u32,
        encrypted_size: usize,
    },

    /// Transfer upload completed
    TransferUploadCompleted {
        transfer_id: MailboxTransferId,
        duration_ms: u64,
        total_chunks: u32,
    },

    /// Transfer download started
    TransferDownloadStarted {
        transfer_id: MailboxTransferId,
        sender: PeerId,
    },

    /// Chunk downloaded from relay
    ChunkDownloaded {
        transfer_id: MailboxTransferId,
        chunk_index: u32,
        decrypted_size: usize,
    },

    /// Transfer download completed
    TransferDownloadCompleted {
        transfer_id: MailboxTransferId,
        duration_ms: u64,
        verification_status: String,
    },

    /// Quota limit approaching
    QuotaWarning {
        current_usage: u64,
        quota_limit: u64,
        utilization_percent: f64,
    },

    /// Tamper detection triggered
    TamperDetected {
        transfer_id: MailboxTransferId,
        tamper_type: String,
        evidence: String,
    },

    /// Mailbox cleanup performed
    CleanupPerformed {
        expired_transfers: u32,
        bytes_freed: u64,
    },
}

/// Error types for mailbox operations.
#[derive(Debug, thiserror::Error)]
pub enum MailboxError {
    /// Relay communication error
    #[error("Relay communication error: {message}")]
    RelayError { message: String },

    /// Encryption or decryption error
    #[error("Cryptographic error: {operation}")]
    CryptoError { operation: String },

    /// Quota exceeded error
    #[error("Quota exceeded: {usage} / {limit} bytes")]
    QuotaExceeded { usage: u64, limit: u64 },

    /// Transfer not found in mailbox
    #[error("Transfer not found: {transfer_id}")]
    TransferNotFound { transfer_id: MailboxTransferId },

    /// Transfer expired or invalid
    #[error("Transfer expired: {transfer_id}, expired at {expired_at:?}")]
    TransferExpired {
        transfer_id: MailboxTransferId,
        expired_at: Time
    },

    /// Tamper evidence detected
    #[error("Tamper detected in {transfer_id}: {evidence}")]
    TamperDetected {
        transfer_id: MailboxTransferId,
        evidence: String
    },

    /// Invalid configuration
    #[error("Invalid mailbox configuration: {details}")]
    ConfigurationError { details: String },

    /// Network or timeout error
    #[error("Network error: {details}")]
    NetworkError { details: String },
}

/// Type alias for mailbox operation results.
pub type MailboxResult<T> = Result<T, MailboxError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mailbox_transfer_id_generation() {
        let id1 = MailboxTransferId::new();
        let id2 = MailboxTransferId::new();

        assert_ne!(id1, id2);

        let bytes = id1.to_bytes();
        let reconstructed = MailboxTransferId::from_bytes(bytes);
        assert_eq!(id1, reconstructed);
    }

    #[test]
    fn test_peer_id_creation() {
        let peer = PeerId::new("test-peer-123");
        assert_eq!(peer.as_str(), "test-peer-123");
    }

    #[test]
    fn test_mailbox_config_defaults() {
        let config = MailboxConfig::default();

        assert_eq!(config.quota_limit, 100_000_000);
        assert_eq!(config.max_chunk_size, 1024 * 1024);
        assert!(config.tamper_detection);
        assert_eq!(config.operation_timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_mailbox_event_serialization() {
        let event = MailboxEvent::TransferUploadStarted {
            transfer_id: MailboxTransferId::new(),
            destination: PeerId::new("peer-123"),
            total_size: 1024,
        };

        let serialized = serde_json::to_string(&event).unwrap();
        let deserialized: MailboxEvent = serde_json::from_str(&serialized).unwrap();

        match (event, deserialized) {
            (MailboxEvent::TransferUploadStarted { total_size: s1, .. },
             MailboxEvent::TransferUploadStarted { total_size: s2, .. }) => {
                assert_eq!(s1, s2);
            }
            _ => panic!("Event type mismatch after serialization"),
        }
    }

    #[test]
    fn test_mailbox_error_display() {
        let error = MailboxError::QuotaExceeded {
            usage: 1500,
            limit: 1000,
        };

        let display = format!("{}", error);
        assert!(display.contains("Quota exceeded"));
        assert!(display.contains("1500"));
        assert!(display.contains("1000"));
    }
}