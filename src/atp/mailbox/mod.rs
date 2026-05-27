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

use crate::types::Time;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub mod client;
pub mod encryption;
pub mod quota;
pub mod relay;
pub mod storage;

pub use client::MailboxClient;
pub use encryption::{ChunkNonce, EncryptedChunk, MailboxKey};
pub use quota::{QuotaManager, QuotaPolicy, QuotaUsage};
pub use relay::{RelayClient, RelayMessage, RelayProtocol, RelayResponse};
pub use storage::{MailboxEntry, MailboxStorage, TransferState};

/// Unique identifier for a mailbox transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MailboxTransferId(pub [u8; 16]);

impl MailboxTransferId {
    pub fn new() -> Self {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).expect("OS entropy unavailable for mailbox transfer id");
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        Self(bytes)
    }

    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub fn to_bytes(self) -> [u8; 16] {
        self.0
    }
}

impl Default for MailboxTransferId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for MailboxTransferId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = self.0;
        write!(
            f,
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            b[0],
            b[1],
            b[2],
            b[3],
            b[4],
            b[5],
            b[6],
            b[7],
            b[8],
            b[9],
            b[10],
            b[11],
            b[12],
            b[13],
            b[14],
            b[15]
        )
    }
}

impl Serialize for MailboxTransferId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for MailboxTransferId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        parse_transfer_id(&raw).map_err(serde::de::Error::custom)
    }
}

fn parse_transfer_id(raw: &str) -> Result<MailboxTransferId, String> {
    let compact = raw.replace('-', "");
    if compact.len() != 32 {
        return Err(format!(
            "mailbox transfer id must contain 32 hex digits, got {}",
            compact.len()
        ));
    }
    let decoded =
        hex::decode(&compact).map_err(|err| format!("invalid mailbox transfer id hex: {err}"))?;
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&decoded);
    Ok(MailboxTransferId(bytes))
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

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Configuration for mailbox client operations.
#[derive(Debug, Clone)]
pub struct MailboxConfig {
    /// Local peer identity used for relay list/retrieve operations
    pub local_peer_id: PeerId,

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
        let encryption_key = MailboxKey::generate();
        let local_peer_id = derive_peer_id_from_key(&encryption_key);
        Self {
            local_peer_id,
            relay_endpoint: "127.0.0.1:8080".parse().unwrap(),
            encryption_key,
            quota_limit: 100_000_000, // 100MB default
            default_retention: Duration::from_secs(7 * 24 * 3600), // 1 week
            operation_timeout: Duration::from_secs(30),
            max_chunk_size: 1024 * 1024, // 1MB chunks
            tamper_detection: true,
        }
    }
}

fn derive_peer_id_from_key(key: &MailboxKey) -> PeerId {
    use sha2::{Digest, Sha256};

    let digest = Sha256::digest(key.as_bytes());
    PeerId::new(format!("peer-{}", hex::encode(&digest[..8])))
}

pub(crate) fn mailbox_time_now() -> Time {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .min(u128::from(u64::MAX)) as u64;
    Time::from_nanos(nanos)
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
        expired_at: Time,
    },

    /// Tamper evidence detected
    #[error("Tamper detected in {transfer_id}: {evidence}")]
    TamperDetected {
        transfer_id: MailboxTransferId,
        evidence: String,
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
            (
                MailboxEvent::TransferUploadStarted { total_size: s1, .. },
                MailboxEvent::TransferUploadStarted { total_size: s2, .. },
            ) => {
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

    // Golden artifact tests for ATP mailbox protocol serialization stability
    // These tests freeze the JSON serialization format to detect unintended changes
    // Fixed timestamp: 1640995200000000 = 2022-01-01T00:00:00Z

    fn fixed_transfer_id() -> MailboxTransferId {
        MailboxTransferId::from_bytes([
            0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4,
            0x30, 0xc8,
        ])
    }

    #[test]
    fn golden_mailbox_transfer_id_serialization() {
        let transfer_id = fixed_transfer_id();

        insta::assert_json_snapshot!(transfer_id, @r###"
        "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
        "###);
    }

    #[test]
    fn golden_peer_id_serialization() {
        let peer_id = PeerId::new("peer-atp-node-f3c4d5e6");

        insta::assert_json_snapshot!(peer_id, @r###"
        "peer-atp-node-f3c4d5e6"
        "###);
    }

    #[test]
    fn golden_mailbox_transfer_metadata_serialization() {
        const CREATED_AT_NANOS: u64 = 1_640_995_200_000_000_000;
        const WEEK_NANOS: u64 = 604_800_000_000_000;

        let metadata = MailboxTransferMetadata {
            transfer_id: fixed_transfer_id(),
            destination_peer: PeerId::new("peer-destination-node"),
            created_at: Time::from_nanos(CREATED_AT_NANOS), // 2022-01-01T00:00:00Z
            expires_at: Time::from_nanos(CREATED_AT_NANOS + WEEK_NANOS), // +1 week
            total_size: 2048576,                            // 2MB
            chunk_count: 4,
            encrypted_metadata: vec![0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe],
        };

        insta::assert_json_snapshot!(metadata, @r###"
        {
          "transfer_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
          "destination_peer": "peer-destination-node",
          "created_at": 1640995200000000000,
          "expires_at": 1641600000000000000,
          "total_size": 2048576,
          "chunk_count": 4,
          "encrypted_metadata": [
            222,
            173,
            190,
            239,
            202,
            254,
            186,
            190
          ]
        }
        "###);
    }

    #[test]
    fn golden_mailbox_operation_result_serialization() {
        use crate::atp::mailbox::quota::QuotaUsage;
        use std::time::UNIX_EPOCH;

        let result = MailboxOperationResult {
            success: true,
            transfer_id: Some(fixed_transfer_id()),
            quota_usage: QuotaUsage {
                bytes_used: 1048576, // 1MB
                active_transfers: 3,
                total_transfers: 15,
                last_updated: UNIX_EPOCH + std::time::Duration::from_secs(1640995200), // 2022-01-01T00:00:00Z
            },
            duration_ms: 1234,
            messages: vec![
                "Transfer initiated successfully".to_string(),
                "Encryption completed".to_string(),
            ],
            relay_receipt: Some("receipt-abc123def456".to_string()),
        };

        insta::assert_json_snapshot!(result, @r###"
        {
          "success": true,
          "transfer_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
          "quota_usage": {
            "bytes_used": 1048576,
            "active_transfers": 3,
            "total_transfers": 15,
            "last_updated": {
              "secs_since_epoch": 1640995200,
              "nanos_since_epoch": 0
            }
          },
          "duration_ms": 1234,
          "messages": [
            "Transfer initiated successfully",
            "Encryption completed"
          ],
          "relay_receipt": "receipt-abc123def456"
        }
        "###);
    }

    #[test]
    fn golden_mailbox_event_transfer_upload_started_serialization() {
        let event = MailboxEvent::TransferUploadStarted {
            transfer_id: fixed_transfer_id(),
            destination: PeerId::new("peer-upload-target"),
            total_size: 3145728, // 3MB
        };

        insta::assert_json_snapshot!(event, @r###"
        {
          "TransferUploadStarted": {
            "transfer_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
            "destination": "peer-upload-target",
            "total_size": 3145728
          }
        }
        "###);
    }

    #[test]
    fn golden_mailbox_event_quota_warning_serialization() {
        let event = MailboxEvent::QuotaWarning {
            current_usage: 85000000, // 85MB
            quota_limit: 100000000,  // 100MB
            utilization_percent: 85.0,
        };

        insta::assert_json_snapshot!(event, @r###"
        {
          "QuotaWarning": {
            "current_usage": 85000000,
            "quota_limit": 100000000,
            "utilization_percent": 85.0
          }
        }
        "###);
    }

    #[test]
    fn golden_mailbox_event_tamper_detected_serialization() {
        let event = MailboxEvent::TamperDetected {
            transfer_id: fixed_transfer_id(),
            tamper_type: "checksum_mismatch".to_string(),
            evidence: "expected_hash=abc123, actual_hash=def456".to_string(),
        };

        insta::assert_json_snapshot!(event, @r###"
        {
          "TamperDetected": {
            "transfer_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
            "tamper_type": "checksum_mismatch",
            "evidence": "expected_hash=abc123, actual_hash=def456"
          }
        }
        "###);
    }

    #[test]
    fn golden_mailbox_event_cleanup_performed_serialization() {
        let event = MailboxEvent::CleanupPerformed {
            expired_transfers: 7,
            bytes_freed: 15728640, // 15MB
        };

        insta::assert_json_snapshot!(event, @r###"
        {
          "CleanupPerformed": {
            "expired_transfers": 7,
            "bytes_freed": 15728640
          }
        }
        "###);
    }
}
