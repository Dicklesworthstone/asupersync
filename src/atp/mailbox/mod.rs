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
//! ```rust,no_run
//! use asupersync::atp::mailbox::{MailboxClient, MailboxConfig, MailboxResult, PeerId};
//! use asupersync::Cx;
//!
//! async fn mailbox_round_trip(cx: &Cx, peer_id: PeerId, payload: Vec<u8>) -> MailboxResult<()> {
//!     let config = MailboxConfig {
//!         relay_endpoint: "203.0.113.10:8080".parse().unwrap(),
//!         quota_limit: 1_000_000_000, // 1GB
//!         // `Default` generates a fresh `encryption_key` and derives
//!         // `local_peer_id` from it.
//!         ..MailboxConfig::default()
//!     };
//!
//!     let mut client = MailboxClient::new(config).await?;
//!
//!     // Send to offline peer
//!     let transfer_id = client.send_to_mailbox(cx, peer_id, payload).await?;
//!
//!     // Receive from mailbox
//!     let transfers = client.check_mailbox(cx).await?;
//!     for transfer in transfers {
//!         let data = client.receive_from_mailbox(cx, transfer.transfer_id).await?;
//!         // Verify and process the decrypted bytes
//!     }
//!     Ok(())
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

const TRANSFER_ID_HEX_LEN: usize = 32;
const TRANSFER_ID_CANONICAL_LEN: usize = 36;

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
    let hex = collect_transfer_id_hex(raw)?;
    let bytes = decode_transfer_id_hex(&hex)?;
    Ok(MailboxTransferId(bytes))
}

fn collect_transfer_id_hex(raw: &str) -> Result<[u8; TRANSFER_ID_HEX_LEN], String> {
    let bytes = raw.as_bytes();
    match bytes.len() {
        TRANSFER_ID_HEX_LEN => collect_compact_transfer_id_hex(bytes),
        TRANSFER_ID_CANONICAL_LEN => collect_canonical_transfer_id_hex(bytes),
        len => Err(format!(
            "mailbox transfer id must be 32 hex bytes or canonical 36-byte hyphenated text, got {len}"
        )),
    }
}

fn collect_compact_transfer_id_hex(bytes: &[u8]) -> Result<[u8; TRANSFER_ID_HEX_LEN], String> {
    let mut hex = [0u8; TRANSFER_ID_HEX_LEN];
    for (index, byte) in bytes.iter().copied().enumerate() {
        hex[index] = normalize_transfer_id_hex_digit(byte, index)?;
    }
    Ok(hex)
}

fn collect_canonical_transfer_id_hex(bytes: &[u8]) -> Result<[u8; TRANSFER_ID_HEX_LEN], String> {
    let mut hex = [0u8; TRANSFER_ID_HEX_LEN];
    let mut hex_index = 0usize;
    for (source_index, byte) in bytes.iter().copied().enumerate() {
        if is_transfer_id_hyphen_position(source_index) {
            if byte != b'-' {
                return Err(format!(
                    "mailbox transfer id expected hyphen at byte {source_index}"
                ));
            }
            continue;
        }
        hex[hex_index] = normalize_transfer_id_hex_digit(byte, source_index)?;
        hex_index += 1;
    }
    Ok(hex)
}

fn is_transfer_id_hyphen_position(index: usize) -> bool {
    matches!(index, 8 | 13 | 18 | 23)
}

fn normalize_transfer_id_hex_digit(byte: u8, source_index: usize) -> Result<u8, String> {
    if !byte.is_ascii_hexdigit() {
        return Err(format!(
            "mailbox transfer id has non-hex byte at position {source_index}"
        ));
    }
    Ok(byte.to_ascii_lowercase())
}

fn decode_transfer_id_hex(hex: &[u8; TRANSFER_ID_HEX_LEN]) -> Result<[u8; 16], String> {
    let mut bytes = [0u8; 16];
    for (index, byte) in bytes.iter_mut().enumerate() {
        let high = transfer_id_hex_nibble(hex[index * 2]).ok_or_else(|| {
            format!(
                "mailbox transfer id has invalid high hex nibble at compact position {}",
                index * 2
            )
        })?;
        let low = transfer_id_hex_nibble(hex[index * 2 + 1]).ok_or_else(|| {
            format!(
                "mailbox transfer id has invalid low hex nibble at compact position {}",
                index * 2 + 1
            )
        })?;
        *byte = (high << 4) | low;
    }
    Ok(bytes)
}

fn transfer_id_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
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
#[path = "mod_inline_tests.rs"]
mod tests;
