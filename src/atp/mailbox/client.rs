//! ATP Mailbox Client - Client interface for encrypted offline transfers.

use super::*;
use crate::cx::Cx;
use std::collections::HashMap;
use std::sync::Mutex;

/// Client for ATP mailbox operations.
#[derive(Debug)]
pub struct MailboxClient {
    /// Client configuration
    config: MailboxConfig,

    /// Active transfers (protected by mutex for concurrent access)
    active_transfers: Mutex<HashMap<MailboxTransferId, TransferState>>,

    /// Relay client for communication
    relay_client: Option<RelayClient>,

    /// Encryption handler
    encryption_key: MailboxKey,

    /// Quota manager
    quota_manager: QuotaManager,
}

impl MailboxClient {
    /// Create a new mailbox client.
    pub async fn new(config: MailboxConfig) -> MailboxResult<Self> {
        let relay_client =
            RelayClient::new(config.relay_endpoint).with_timeout(config.operation_timeout);
        Ok(Self {
            config: config.clone(),
            active_transfers: Mutex::new(HashMap::new()),
            relay_client: Some(relay_client),
            encryption_key: config.encryption_key,
            quota_manager: QuotaManager::new(config.quota_limit),
        })
    }

    /// Send data to offline peer via mailbox.
    pub async fn send_to_mailbox(
        &mut self,
        cx: &Cx,
        peer_id: PeerId,
        data: Vec<u8>,
    ) -> MailboxResult<MailboxTransferId> {
        let transfer_id = MailboxTransferId::new();
        let quota_reservation = self.quota_manager.reserve_quota(data.len() as u64)?;

        {
            let mut active_transfers = self.active_transfers.lock().unwrap();
            active_transfers.insert(transfer_id, TransferState::Uploading);
        }

        let result = self
            .send_to_mailbox_inner(cx, transfer_id, peer_id, &data)
            .await;

        self.quota_manager.release_quota(quota_reservation);

        match result {
            Ok(()) => {
                self.set_transfer_state(transfer_id, TransferState::Completed);
                Ok(transfer_id)
            }
            Err(error) => {
                self.set_transfer_state(transfer_id, TransferState::Failed(error.to_string()));
                Err(error)
            }
        }
    }

    async fn send_to_mailbox_inner(
        &self,
        cx: &Cx,
        transfer_id: MailboxTransferId,
        peer_id: PeerId,
        data: &[u8],
    ) -> MailboxResult<()> {
        cx.trace(&format!(
            "Sending {} bytes to peer {} via mailbox",
            data.len(),
            peer_id.as_str()
        ));

        let chunks = self.encrypt_payload_chunks(data)?;
        let encrypted_metadata = self.encrypt_transfer_metadata(data, &chunks)?;
        let encrypted_size = chunks.iter().fold(0u64, |total, chunk| {
            total
                .saturating_add(chunk.data.len() as u64)
                .saturating_add(chunk.tag.len() as u64)
                .saturating_add(chunk.nonce.bytes.len() as u64)
        });
        let chunk_count =
            u32::try_from(chunks.len()).map_err(|_| MailboxError::ConfigurationError {
                details: format!(
                    "mailbox transfer has too many chunks: {} exceeds u32::MAX",
                    chunks.len()
                ),
            })?;
        let created_at = mailbox_time_now();
        let metadata = MailboxTransferMetadata {
            transfer_id,
            destination_peer: peer_id.clone(),
            created_at,
            expires_at: created_at + self.config.default_retention,
            total_size: encrypted_size,
            chunk_count,
            encrypted_metadata,
        };

        let response = self
            .relay()?
            .send_message(RelayMessage::Store {
                target_peer: peer_id,
                chunks,
                metadata,
            })
            .await?;

        match response {
            RelayResponse::StoreComplete {
                transfer_id: relay_transfer_id,
                ..
            } if relay_transfer_id == transfer_id => Ok(()),
            RelayResponse::StoreComplete {
                transfer_id: relay_transfer_id,
                ..
            } => Err(MailboxError::TamperDetected {
                transfer_id,
                evidence: format!("relay returned mismatched transfer id {relay_transfer_id:?}"),
            }),
            RelayResponse::Error { code, message } => Err(MailboxError::RelayError {
                message: format!("relay store failed ({code}): {message}"),
            }),
            other => Err(MailboxError::RelayError {
                message: format!("unexpected relay response to store: {other:?}"),
            }),
        }
    }

    fn encrypt_payload_chunks(&self, data: &[u8]) -> MailboxResult<Vec<EncryptedChunk>> {
        let mut chunks = Vec::new();
        for chunk in data.chunks(self.config.max_chunk_size.max(1)) {
            chunks.push(
                EncryptedChunk::encrypt(chunk, &self.encryption_key)
                    .map_err(|operation| MailboxError::CryptoError { operation })?,
            );
        }
        if chunks.is_empty() {
            chunks.push(
                EncryptedChunk::encrypt(&[], &self.encryption_key)
                    .map_err(|operation| MailboxError::CryptoError { operation })?,
            );
        }
        Ok(chunks)
    }

    fn encrypt_transfer_metadata(
        &self,
        data: &[u8],
        chunks: &[EncryptedChunk],
    ) -> MailboxResult<Vec<u8>> {
        use sha2::{Digest, Sha256};

        let plaintext_chunk_sizes = data
            .chunks(self.config.max_chunk_size.max(1))
            .map(|chunk| chunk.len() as u64)
            .collect::<Vec<_>>();
        let metadata = ClientEncryptedMetadata {
            plaintext_size: data.len() as u64,
            plaintext_sha256: hex::encode(Sha256::digest(data)),
            plaintext_chunk_sizes,
            encrypted_chunk_count: chunks.len() as u32,
        };
        let metadata_bytes =
            serde_json::to_vec(&metadata).map_err(|error| MailboxError::CryptoError {
                operation: format!("failed to encode encrypted mailbox metadata: {error}"),
            })?;
        let encrypted = EncryptedChunk::encrypt(&metadata_bytes, &self.encryption_key)
            .map_err(|operation| MailboxError::CryptoError { operation })?;
        serde_json::to_vec(&encrypted).map_err(|error| MailboxError::CryptoError {
            operation: format!("failed to encode encrypted metadata envelope: {error}"),
        })
    }

    /// Check for new transfers in mailbox.
    pub async fn check_mailbox(&mut self, cx: &Cx) -> MailboxResult<Vec<MailboxTransferMetadata>> {
        cx.trace("Checking mailbox for new transfers");

        let response = self
            .relay()?
            .send_message(RelayMessage::List {
                peer_id: self.config.local_peer_id.clone(),
                limit: Some(1_000),
            })
            .await?;
        match response {
            RelayResponse::TransferList { transfers, .. } => Ok(transfers),
            RelayResponse::Error { code, message } => Err(MailboxError::RelayError {
                message: format!("relay list failed ({code}): {message}"),
            }),
            other => Err(MailboxError::RelayError {
                message: format!("unexpected relay response to list: {other:?}"),
            }),
        }
    }

    /// Receive data from mailbox.
    pub async fn receive_from_mailbox(
        &mut self,
        cx: &Cx,
        transfer_id: MailboxTransferId,
    ) -> MailboxResult<Vec<u8>> {
        cx.trace(&format!("Receiving transfer {}", transfer_id));

        let response = self
            .relay()?
            .send_message(RelayMessage::Retrieve {
                transfer_id,
                requester: self.config.local_peer_id.clone(),
            })
            .await?;

        match response {
            RelayResponse::RetrieveResult {
                transfer_id: returned_transfer_id,
                chunks,
                metadata,
            } if returned_transfer_id == transfer_id && metadata.transfer_id == transfer_id => {
                self.decrypt_and_verify_transfer(transfer_id, chunks, metadata)
            }
            RelayResponse::RetrieveResult {
                transfer_id: returned_transfer_id,
                metadata,
                ..
            } => Err(MailboxError::TamperDetected {
                transfer_id,
                evidence: format!(
                    "relay returned mismatched transfer ids response={returned_transfer_id:?} metadata={:?}",
                    metadata.transfer_id
                ),
            }),
            RelayResponse::Error { code, message } => Err(MailboxError::RelayError {
                message: format!("relay retrieve failed ({code}): {message}"),
            }),
            other => Err(MailboxError::RelayError {
                message: format!("unexpected relay response to retrieve: {other:?}"),
            }),
        }
    }

    fn decrypt_and_verify_transfer(
        &self,
        transfer_id: MailboxTransferId,
        chunks: Vec<EncryptedChunk>,
        metadata: MailboxTransferMetadata,
    ) -> MailboxResult<Vec<u8>> {
        use sha2::{Digest, Sha256};

        if metadata.chunk_count as usize != chunks.len() {
            return Err(MailboxError::TamperDetected {
                transfer_id,
                evidence: format!(
                    "metadata chunk count {} does not match received chunk count {}",
                    metadata.chunk_count,
                    chunks.len()
                ),
            });
        }

        let metadata_envelope: EncryptedChunk =
            serde_json::from_slice(&metadata.encrypted_metadata).map_err(|error| {
                MailboxError::CryptoError {
                    operation: format!("failed to decode encrypted metadata envelope: {error}"),
                }
            })?;
        let metadata_plaintext = metadata_envelope
            .decrypt(&self.encryption_key)
            .map_err(|operation| MailboxError::CryptoError { operation })?;
        let expected: ClientEncryptedMetadata = serde_json::from_slice(&metadata_plaintext)
            .map_err(|error| MailboxError::CryptoError {
                operation: format!("failed to decode encrypted transfer metadata: {error}"),
            })?;

        if expected.encrypted_chunk_count as usize != chunks.len() {
            return Err(MailboxError::TamperDetected {
                transfer_id,
                evidence: "encrypted metadata chunk count mismatch".to_string(),
            });
        }

        let mut plaintext = Vec::with_capacity(expected.plaintext_size as usize);
        for (index, chunk) in chunks.iter().enumerate() {
            let chunk_plaintext = chunk
                .decrypt(&self.encryption_key)
                .map_err(|operation| MailboxError::CryptoError { operation })?;
            if expected
                .plaintext_chunk_sizes
                .get(index)
                .is_some_and(|expected_len| *expected_len != chunk_plaintext.len() as u64)
            {
                return Err(MailboxError::TamperDetected {
                    transfer_id,
                    evidence: format!("plaintext chunk size mismatch at index {index}"),
                });
            }
            plaintext.extend_from_slice(&chunk_plaintext);
        }

        if plaintext.len() as u64 != expected.plaintext_size {
            return Err(MailboxError::TamperDetected {
                transfer_id,
                evidence: "plaintext transfer size mismatch".to_string(),
            });
        }
        let actual_hash = hex::encode(Sha256::digest(&plaintext));
        if actual_hash != expected.plaintext_sha256 {
            return Err(MailboxError::TamperDetected {
                transfer_id,
                evidence: "plaintext sha256 mismatch".to_string(),
            });
        }

        Ok(plaintext)
    }

    fn relay(&self) -> MailboxResult<&RelayClient> {
        self.relay_client
            .as_ref()
            .ok_or_else(|| MailboxError::ConfigurationError {
                details: "mailbox relay client is not configured".to_string(),
            })
    }

    fn set_transfer_state(&self, transfer_id: MailboxTransferId, state: TransferState) {
        if let Ok(mut active_transfers) = self.active_transfers.lock() {
            active_transfers.insert(transfer_id, state);
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct ClientEncryptedMetadata {
    plaintext_size: u64,
    plaintext_sha256: String,
    plaintext_chunk_sizes: Vec<u64>,
    encrypted_chunk_count: u32,
}

/// Basic transfer state tracking.
#[derive(Debug, Clone)]
pub enum TransferState {
    /// Transfer is being uploaded
    Uploading,
    /// Transfer is completed
    Completed,
    /// Transfer failed
    Failed(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mailbox_client_creation() {
        let config = MailboxConfig::default();
        let result = MailboxClient::new(config).await;
        assert!(result.is_ok());
    }
}
