//! ATP Mailbox Client - Client interface for encrypted offline transfers.

use super::{
    EncryptedChunk, MailboxConfig, MailboxError, MailboxKey, MailboxResult, MailboxTransferId,
    MailboxTransferMetadata, PeerId, QuotaManager, RelayClient, RelayMessage, RelayResponse,
    mailbox_time_now,
};
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
        let data_len = u64::try_from(data.len()).map_err(|_| MailboxError::QuotaExceeded {
            usage: u64::MAX,
            limit: self.config.quota_limit,
        })?;
        let quota_reservation = self.quota_manager.reserve_quota(data_len)?;

        {
            let mut active_transfers =
                self.active_transfers
                    .lock()
                    .map_err(|_| MailboxError::ConfigurationError {
                        details: "mailbox active transfer state lock poisoned".to_string(),
                    })?;
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
        let chunk_count =
            u32::try_from(chunks.len()).map_err(|_| MailboxError::ConfigurationError {
                details: format!(
                    "mailbox transfer has too many chunks: {} exceeds u32::MAX",
                    chunks.len()
                ),
            })?;
        let encrypted_metadata =
            self.encrypt_transfer_metadata(transfer_id, &peer_id, data, chunk_count)?;
        let encrypted_size = chunks.iter().try_fold(0u64, |total, chunk| {
            let data_len = u64::try_from(chunk.data.len()).ok()?;
            let tag_len = u64::try_from(chunk.tag.len()).ok()?;
            let nonce_len = u64::try_from(chunk.nonce.bytes.len()).ok()?;
            total
                .checked_add(data_len)?
                .checked_add(tag_len)?
                .checked_add(nonce_len)
        });
        let Some(encrypted_size) = encrypted_size else {
            return Err(MailboxError::QuotaExceeded {
                usage: u64::MAX,
                limit: self.config.quota_limit,
            });
        };
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
            } if mailbox_transfer_id_eq(&relay_transfer_id, &transfer_id) => Ok(()),
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
        transfer_id: MailboxTransferId,
        destination_peer: &PeerId,
        data: &[u8],
        encrypted_chunk_count: u32,
    ) -> MailboxResult<Vec<u8>> {
        use sha2::{Digest, Sha256};

        let plaintext_size =
            u64::try_from(data.len()).map_err(|_| MailboxError::QuotaExceeded {
                usage: u64::MAX,
                limit: self.config.quota_limit,
            })?;
        let plaintext_chunk_sizes = data
            .chunks(self.config.max_chunk_size.max(1))
            .map(|chunk| {
                u64::try_from(chunk.len()).map_err(|_| MailboxError::QuotaExceeded {
                    usage: u64::MAX,
                    limit: self.config.quota_limit,
                })
            })
            .collect::<MailboxResult<Vec<_>>>()?;
        let metadata = ClientEncryptedMetadata {
            transfer_id,
            destination_peer: destination_peer.clone(),
            plaintext_size,
            plaintext_sha256: hex::encode(Sha256::digest(data)),
            plaintext_chunk_sizes,
            encrypted_chunk_count,
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
            } if mailbox_transfer_id_eq(&returned_transfer_id, &transfer_id)
                && mailbox_transfer_id_eq(&metadata.transfer_id, &transfer_id) =>
            {
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

        let metadata_chunk_count =
            usize::try_from(metadata.chunk_count).map_err(|_| MailboxError::TamperDetected {
                transfer_id,
                evidence: "metadata chunk count does not fit this platform".to_string(),
            })?;
        if metadata_chunk_count != chunks.len() {
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

        if !mailbox_transfer_id_eq(&expected.transfer_id, &transfer_id) {
            return Err(MailboxError::TamperDetected {
                transfer_id,
                evidence: format!(
                    "encrypted metadata transfer id {} does not match requested transfer id",
                    expected.transfer_id
                ),
            });
        }
        if !peer_id_eq(&expected.destination_peer, &metadata.destination_peer) {
            return Err(MailboxError::TamperDetected {
                transfer_id,
                evidence: "encrypted metadata destination peer mismatch".to_string(),
            });
        }

        let encrypted_chunk_count =
            usize::try_from(expected.encrypted_chunk_count).map_err(|_| {
                MailboxError::TamperDetected {
                    transfer_id,
                    evidence: "encrypted metadata chunk count does not fit this platform"
                        .to_string(),
                }
            })?;
        if encrypted_chunk_count != chunks.len() {
            return Err(MailboxError::TamperDetected {
                transfer_id,
                evidence: "encrypted metadata chunk count mismatch".to_string(),
            });
        }

        let plaintext_capacity =
            usize::try_from(expected.plaintext_size).map_err(|_| MailboxError::TamperDetected {
                transfer_id,
                evidence: "encrypted metadata plaintext size does not fit this platform"
                    .to_string(),
            })?;
        let mut plaintext = Vec::with_capacity(plaintext_capacity);
        for (index, chunk) in chunks.iter().enumerate() {
            let chunk_plaintext = chunk
                .decrypt(&self.encryption_key)
                .map_err(|operation| MailboxError::CryptoError { operation })?;
            let chunk_plaintext_len =
                u64::try_from(chunk_plaintext.len()).map_err(|_| MailboxError::TamperDetected {
                    transfer_id,
                    evidence: format!("plaintext chunk size at index {index} is too large"),
                })?;
            if expected
                .plaintext_chunk_sizes
                .get(index)
                .is_some_and(|expected_len| *expected_len != chunk_plaintext_len)
            {
                return Err(MailboxError::TamperDetected {
                    transfer_id,
                    evidence: format!("plaintext chunk size mismatch at index {index}"),
                });
            }
            plaintext.extend_from_slice(&chunk_plaintext);
        }

        let plaintext_len =
            u64::try_from(plaintext.len()).map_err(|_| MailboxError::TamperDetected {
                transfer_id,
                evidence: "plaintext transfer size is too large".to_string(),
            })?;
        if plaintext_len != expected.plaintext_size {
            return Err(MailboxError::TamperDetected {
                transfer_id,
                evidence: "plaintext transfer size mismatch".to_string(),
            });
        }
        let mut expected_hash = [0u8; 32];
        hex::decode_to_slice(&expected.plaintext_sha256, &mut expected_hash).map_err(|_| {
            MailboxError::TamperDetected {
                transfer_id,
                evidence: "encrypted metadata plaintext sha256 is malformed".to_string(),
            }
        })?;
        let actual_hash = Sha256::digest(&plaintext);
        use subtle::ConstantTimeEq;
        if !bool::from(actual_hash.as_slice().ct_eq(&expected_hash)) {
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
    transfer_id: MailboxTransferId,
    destination_peer: PeerId,
    plaintext_size: u64,
    plaintext_sha256: String,
    plaintext_chunk_sizes: Vec<u64>,
    encrypted_chunk_count: u32,
}

fn mailbox_transfer_id_eq(left: &MailboxTransferId, right: &MailboxTransferId) -> bool {
    use subtle::ConstantTimeEq;
    bool::from(left.to_bytes().ct_eq(&right.to_bytes()))
}

fn peer_id_eq(left: &PeerId, right: &PeerId) -> bool {
    use subtle::ConstantTimeEq;
    bool::from(left.as_str().as_bytes().ct_eq(right.as_str().as_bytes()))
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
#[path = "client_inline_tests.rs"]
mod tests;
