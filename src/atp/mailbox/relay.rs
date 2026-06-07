//! ATP Mailbox Relay - Communication with mailbox relay servers.

use super::{
    EncryptedChunk, MailboxError, MailboxResult, MailboxTransferId, MailboxTransferMetadata, PeerId,
};
use crate::runtime::spawn_blocking;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
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
#[derive(Clone, Serialize)]
pub struct RelayCredentials {
    /// Client identifier
    pub client_id: String,

    /// Authentication token
    pub auth_token: String,
}

impl fmt::Debug for RelayCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayCredentials")
            .field("client_id", &self.client_id)
            .field("auth_token", &"<redacted>")
            .finish()
    }
}

impl Drop for RelayCredentials {
    fn drop(&mut self) {
        use zeroize::Zeroize;

        self.auth_token.zeroize();
    }
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
    let _ = stream.shutdown(Shutdown::Both);
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
    let len =
        usize::try_from(u32::from_be_bytes(len_buf)).map_err(|_| MailboxError::RelayError {
            message: "relay response length does not fit this platform".to_string(),
        })?;
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
    use std::error::Error;

    type TestResult = Result<(), Box<dyn Error + Send + Sync>>;

    fn relay_test_credential(parts: &[&str]) -> String {
        parts.join("-")
    }

    #[test]
    fn test_relay_client_creation() -> TestResult {
        let endpoint: SocketAddr = "127.0.0.1:8080".parse()?;
        let client = RelayClient::new(endpoint);
        assert_eq!(client.endpoint, endpoint);
        Ok(())
    }

    #[test]
    fn test_relay_credentials() -> TestResult {
        let credentials = RelayCredentials {
            client_id: "test-client".to_string(),
            auth_token: relay_test_credential(&["credential", "fixture", "private"]),
        };

        let endpoint: SocketAddr = "127.0.0.1:8080".parse()?;
        let client = RelayClient::new(endpoint).with_credentials(credentials);

        assert!(client.credentials.is_some());
        Ok(())
    }

    #[test]
    fn relay_credentials_debug_redacts_auth_token() {
        let auth_token = relay_test_credential(&["private", "relay", "credential"]);
        let credentials = RelayCredentials {
            client_id: "test-client".to_string(),
            auth_token: auth_token.clone(),
        };

        let debug = format!("{credentials:?}");

        assert!(debug.contains("auth_token"));
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains(&auth_token));
    }

    #[test]
    fn relay_client_debug_redacts_credentials() -> TestResult {
        let auth_token = relay_test_credential(&["private", "relay", "client", "credential"]);
        let endpoint: SocketAddr = "127.0.0.1:8080".parse()?;
        let client = RelayClient::new(endpoint).with_credentials(RelayCredentials {
            client_id: "test-client".to_string(),
            auth_token: auth_token.clone(),
        });

        let debug = format!("{client:?}");

        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains(&auth_token));
        Ok(())
    }

    #[test]
    fn test_relay_protocol_serialization() -> TestResult {
        let protocol = RelayProtocol::new("1.0".to_string());

        let message = RelayMessage::Status;
        let serialized = protocol
            .serialize_message(&message)
            .map_err(std::io::Error::other)?;
        let deserialized = protocol
            .deserialize_message(&serialized)
            .map_err(std::io::Error::other)?;

        assert!(matches!(deserialized, RelayMessage::Status));
        Ok(())
    }

    #[test]
    fn test_relay_features_default() {
        let features = RelayFeatures::default();
        assert!(features.max_transfer_size > 0);
        assert!(!features.encryption_algorithms.is_empty());
    }

    #[test]
    fn read_frame_rejects_oversized_response_length_without_allocating() -> TestResult {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let endpoint = listener.local_addr()?;
        let server = std::thread::spawn(move || -> TestResult {
            let (mut stream, _) = listener.accept()?;
            let oversized_len = u32::try_from(RELAY_MAX_FRAME_BYTES + 1)?;
            stream.write_all(&oversized_len.to_be_bytes())?;
            Ok(())
        });
        let mut stream = TcpStream::connect(endpoint)?;

        let result = read_frame(&mut stream);
        let _ = stream.shutdown(Shutdown::Both);

        let server_result = server
            .join()
            .map_err(|_| std::io::Error::other("relay test server thread panicked"))?;
        server_result?;
        assert!(
            matches!(result, Err(MailboxError::RelayError { message }) if message.contains("exceeds maximum frame size"))
        );
        Ok(())
    }

    #[test]
    fn test_relay_message_handling() -> TestResult {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let endpoint = listener.local_addr()?;
        let server = std::thread::spawn(move || -> MailboxResult<()> {
            let (mut stream, _) = listener
                .accept()
                .map_err(|err| MailboxError::NetworkError {
                    details: format!("failed to accept relay test connection: {err}"),
                })?;
            let request_payload = read_frame(&mut stream)?;
            let request: serde_json::Value =
                serde_json::from_slice(&request_payload).map_err(|err| {
                    MailboxError::RelayError {
                        message: format!("failed to decode relay test request: {err}"),
                    }
                })?;
            assert_eq!(request["version"], "1.0");
            assert_eq!(request["message"], "Status");

            let response = RelayResponse::StatusInfo {
                version: "1.0".to_string(),
                available_storage: 1_000_000_000,
                active_transfers: 0,
            };
            let payload =
                serde_json::to_vec(&response).map_err(|err| MailboxError::RelayError {
                    message: format!("failed to encode relay test response: {err}"),
                })?;
            write_frame(&mut stream, &payload)?;
            Ok(())
        });
        let client = RelayClient::new(endpoint);

        let response = futures_lite::future::block_on(client.send_message(RelayMessage::Status))?;
        let server_result = server
            .join()
            .map_err(|_| std::io::Error::other("relay test server thread panicked"))?;
        server_result?;

        if let RelayResponse::StatusInfo { version, .. } = response {
            assert_eq!(version.as_str(), "1.0");
        } else {
            return Err(std::io::Error::other("unexpected relay response type").into());
        }
        Ok(())
    }
}
