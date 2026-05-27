//! ATP Mailbox Relay - Communication with mailbox relay servers.

use super::{
    EncryptedChunk, MailboxError, MailboxResult, MailboxTransferId, MailboxTransferMetadata, PeerId,
};
use crate::runtime::spawn_blocking;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::net::TcpStream;
use std::time::Duration;

const RELAY_MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

/// Client for communicating with mailbox relay servers.
#[derive(Debug)]
pub struct RelayClient {
    /// Relay server endpoint
    endpoint: SocketAddr,

    /// Connection timeout
    timeout: Duration,

    /// Authentication credentials
    credentials: Option<RelayCredentials>,
}

/// Authentication credentials for relay access.
#[derive(Debug, Clone, Serialize)]
pub struct RelayCredentials {
    /// Client identifier
    pub client_id: String,

    /// Authentication token
    pub auth_token: String,
}

/// Relay protocol messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RelayMessage {
    /// Store data in mailbox
    Store {
        /// Target peer identifier
        target_peer: PeerId,
        /// Encrypted data chunks
        chunks: Vec<EncryptedChunk>,
        /// Transfer metadata
        metadata: MailboxTransferMetadata,
    },

    /// Retrieve data from mailbox
    Retrieve {
        /// Transfer identifier
        transfer_id: MailboxTransferId,
        /// Requesting peer
        requester: PeerId,
    },

    /// List available transfers
    List {
        /// Peer identifier
        peer_id: PeerId,
        /// Maximum number of transfers to return
        limit: Option<u32>,
    },

    /// Delete transfer from mailbox
    Delete {
        /// Transfer identifier
        transfer_id: MailboxTransferId,
        /// Requesting peer
        requester: PeerId,
    },

    /// Query relay status
    Status,
}

/// Relay response messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RelayResponse {
    /// Store operation completed
    StoreComplete {
        /// Transfer identifier assigned by relay
        transfer_id: MailboxTransferId,
        /// Storage receipt
        receipt: String,
    },

    /// Retrieve operation result
    RetrieveResult {
        /// Transfer identifier
        transfer_id: MailboxTransferId,
        /// Encrypted data chunks
        chunks: Vec<EncryptedChunk>,
        /// Transfer metadata
        metadata: MailboxTransferMetadata,
    },

    /// List of available transfers
    TransferList {
        /// Available transfers
        transfers: Vec<MailboxTransferMetadata>,
        /// Total count (may be higher than returned items)
        total_count: u32,
    },

    /// Delete operation completed
    DeleteComplete {
        /// Transfer identifier
        transfer_id: MailboxTransferId,
    },

    /// Relay status information
    StatusInfo {
        /// Relay version
        version: String,
        /// Available storage
        available_storage: u64,
        /// Active transfers
        active_transfers: u32,
    },

    /// Error response
    Error {
        /// Error code
        code: u32,
        /// Error message
        message: String,
    },
}

/// Relay protocol abstraction.
#[derive(Debug, Clone)]
pub struct RelayProtocol {
    /// Protocol version
    version: String,

    /// Supported features
    features: RelayFeatures,
}

/// Features supported by relay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayFeatures {
    /// Maximum transfer size
    pub max_transfer_size: u64,

    /// Maximum chunks per transfer
    pub max_chunks_per_transfer: u32,

    /// Retention policies supported
    pub retention_policies: Vec<String>,

    /// Encryption algorithms supported
    pub encryption_algorithms: Vec<String>,

    /// Compression support
    pub compression_support: bool,
}

impl Default for RelayFeatures {
    fn default() -> Self {
        Self {
            max_transfer_size: 1_000_000_000, // 1 GB
            max_chunks_per_transfer: 1000,
            retention_policies: vec!["time-based".to_string(), "size-based".to_string()],
            encryption_algorithms: vec!["aes-256-gcm".to_string()],
            compression_support: true,
        }
    }
}

impl RelayClient {
    /// Create a new relay client.
    pub fn new(endpoint: SocketAddr) -> Self {
        Self {
            endpoint,
            timeout: Duration::from_secs(30),
            credentials: None,
        }
    }

    /// Set authentication credentials.
    pub fn with_credentials(mut self, credentials: RelayCredentials) -> Self {
        self.credentials = Some(credentials);
        self
    }

    /// Set connection timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Send message to relay and await response.
    pub async fn send_message(&self, message: RelayMessage) -> MailboxResult<RelayResponse> {
        let endpoint = self.endpoint;
        let timeout = self.timeout;
        let credentials = self.credentials.clone();
        spawn_blocking(move || send_relay_message_blocking(endpoint, timeout, credentials, message))
            .await
    }

    /// Get relay capabilities.
    pub async fn get_capabilities(&self) -> MailboxResult<RelayFeatures> {
        Ok(RelayFeatures::default())
    }

    /// Test connection to relay.
    pub async fn test_connection(&self) -> MailboxResult<bool> {
        match self.send_message(RelayMessage::Status).await {
            Ok(RelayResponse::StatusInfo { .. }) => Ok(true),
            Ok(RelayResponse::Error { .. }) => Ok(false),
            Err(_) => Ok(false),
            _ => Ok(false),
        }
    }
}

impl RelayProtocol {
    /// Create new protocol instance.
    pub fn new(version: String) -> Self {
        Self {
            version,
            features: RelayFeatures::default(),
        }
    }

    /// Protocol version this codec will advertise.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Feature set advertised by this protocol codec.
    pub fn features(&self) -> &RelayFeatures {
        &self.features
    }

    /// Serialize message to bytes.
    pub fn serialize_message(&self, message: &RelayMessage) -> Result<Vec<u8>, String> {
        serde_json::to_vec(message).map_err(|e| format!("Serialization error: {}", e))
    }

    /// Deserialize message from bytes.
    pub fn deserialize_message(&self, data: &[u8]) -> Result<RelayMessage, String> {
        serde_json::from_slice(data).map_err(|e| format!("Deserialization error: {}", e))
    }

    /// Serialize response to bytes.
    pub fn serialize_response(&self, response: &RelayResponse) -> Result<Vec<u8>, String> {
        serde_json::to_vec(response).map_err(|e| format!("Serialization error: {}", e))
    }

    /// Deserialize response from bytes.
    pub fn deserialize_response(&self, data: &[u8]) -> Result<RelayResponse, String> {
        serde_json::from_slice(data).map_err(|e| format!("Deserialization error: {}", e))
    }
}

fn send_relay_message_blocking(
    endpoint: SocketAddr,
    timeout: Duration,
    credentials: Option<RelayCredentials>,
    message: RelayMessage,
) -> MailboxResult<RelayResponse> {
    let mut stream = TcpStream::connect_timeout(&endpoint, timeout).map_err(|err| {
        MailboxError::NetworkError {
            details: format!("failed to connect to relay {endpoint}: {err}"),
        }
    })?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|err| MailboxError::NetworkError {
            details: format!("failed to set relay read timeout: {err}"),
        })?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|err| MailboxError::NetworkError {
            details: format!("failed to set relay write timeout: {err}"),
        })?;

    let envelope = RelayRequestEnvelope {
        version: "1.0",
        credentials: credentials.as_ref(),
        message: &message,
    };
    let payload = serde_json::to_vec(&envelope).map_err(|err| MailboxError::RelayError {
        message: format!("failed to encode relay request: {err}"),
    })?;
    write_frame(&mut stream, &payload)?;

    let response_payload = read_frame(&mut stream)?;
    let response: RelayResponse =
        serde_json::from_slice(&response_payload).map_err(|err| MailboxError::RelayError {
            message: format!("failed to decode relay response: {err}"),
        })?;

    Ok(response)
}

#[derive(Serialize)]
struct RelayRequestEnvelope<'a> {
    version: &'static str,
    credentials: Option<&'a RelayCredentials>,
    message: &'a RelayMessage,
}

fn write_frame(stream: &mut TcpStream, payload: &[u8]) -> MailboxResult<()> {
    if payload.len() > RELAY_MAX_FRAME_BYTES {
        return Err(MailboxError::RelayError {
            message: format!(
                "relay request exceeds maximum frame size: {} > {}",
                payload.len(),
                RELAY_MAX_FRAME_BYTES
            ),
        });
    }

    let len = u32::try_from(payload.len()).map_err(|_| MailboxError::RelayError {
        message: "relay request length does not fit u32".to_string(),
    })?;
    stream
        .write_all(&len.to_be_bytes())
        .and_then(|()| stream.write_all(payload))
        .map_err(|err| MailboxError::NetworkError {
            details: format!("failed to write relay frame: {err}"),
        })
}

fn read_frame(stream: &mut TcpStream) -> MailboxResult<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .map_err(|err| MailboxError::NetworkError {
            details: format!("failed to read relay response length: {err}"),
        })?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > RELAY_MAX_FRAME_BYTES {
        return Err(MailboxError::RelayError {
            message: format!(
                "relay response exceeds maximum frame size: {len} > {RELAY_MAX_FRAME_BYTES}"
            ),
        });
    }

    let mut payload = vec![0u8; len];
    stream
        .read_exact(&mut payload)
        .map_err(|err| MailboxError::NetworkError {
            details: format!("failed to read relay response payload: {err}"),
        })?;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relay_client_creation() {
        let endpoint = "127.0.0.1:8080".parse().unwrap();
        let client = RelayClient::new(endpoint);
        assert_eq!(client.endpoint, endpoint);
    }

    #[test]
    fn test_relay_credentials() {
        let credentials = RelayCredentials {
            client_id: "test-client".to_string(),
            auth_token: "test-token".to_string(),
        };

        let endpoint = "127.0.0.1:8080".parse().unwrap();
        let client = RelayClient::new(endpoint).with_credentials(credentials);

        assert!(client.credentials.is_some());
    }

    #[test]
    fn test_relay_protocol_serialization() {
        let protocol = RelayProtocol::new("1.0".to_string());

        let message = RelayMessage::Status;
        let serialized = protocol.serialize_message(&message).unwrap();
        let deserialized = protocol.deserialize_message(&serialized).unwrap();

        match deserialized {
            RelayMessage::Status => {}
            _ => panic!("Unexpected message type"),
        }
    }

    #[test]
    fn test_relay_features_default() {
        let features = RelayFeatures::default();
        assert!(features.max_transfer_size > 0);
        assert!(!features.encryption_algorithms.is_empty());
    }

    #[test]
    fn test_relay_message_handling() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request_payload = read_frame(&mut stream).unwrap();
            let request: serde_json::Value = serde_json::from_slice(&request_payload).unwrap();
            assert_eq!(request["version"], "1.0");
            assert_eq!(request["message"], "Status");

            let response = RelayResponse::StatusInfo {
                version: "1.0".to_string(),
                available_storage: 1_000_000_000,
                active_transfers: 0,
            };
            let payload = serde_json::to_vec(&response).unwrap();
            write_frame(&mut stream, &payload).unwrap();
        });
        let client = RelayClient::new(endpoint);

        let response =
            futures_lite::future::block_on(client.send_message(RelayMessage::Status)).unwrap();
        server.join().unwrap();

        match response {
            RelayResponse::StatusInfo { version, .. } => {
                assert_eq!(version, "1.0");
            }
            _ => panic!("Unexpected response type"),
        }
    }
}
