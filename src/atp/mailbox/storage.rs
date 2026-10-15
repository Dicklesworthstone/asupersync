//! ATP Mailbox Storage - Local storage management for mailbox operations.

use super::{
    ChunkNonce, EncryptedChunk, MailboxError, MailboxKey, MailboxResult, MailboxTransferId,
    MailboxTransferMetadata, PeerId, mailbox_time_now,
};
use crate::types::Time;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::TryInto;
use std::path::{Component, Path, PathBuf};
use std::time::SystemTime;

const STORAGE_CHUNK_MAGIC: &[u8; 8] = b"ASUPMBX1";
const STORAGE_CHUNK_VERSION: u8 = 1;
const STORAGE_CHUNK_FLAG_COMPRESSED: u8 = 0b0000_0001;
const STORAGE_CHUNK_FLAG_ENCRYPTED: u8 = 0b0000_0010;
const STORAGE_CHUNK_HEADER_LEN: usize = 8 + 1 + 1 + 8 + 8 + 32 + 12 + 16;

/// Local storage manager for mailbox data.
#[derive(Debug)]
pub struct MailboxStorage {
    /// Storage root directory
    storage_root: PathBuf,

    /// Active storage entries
    entries: HashMap<MailboxTransferId, MailboxEntry>,

    /// Storage configuration
    config: StorageConfig,
}

/// Configuration for mailbox storage.
#[derive(Debug, Clone)]
pub struct StorageConfig {
    /// Maximum storage size in bytes
    pub max_storage_size: u64,

    /// Chunk size for data storage
    pub chunk_size: usize,

    /// Compression enabled
    pub compression_enabled: bool,

    /// Encryption at rest
    pub encryption_at_rest: bool,

    /// Key used when encryption at rest is enabled.
    pub encryption_key: MailboxKey,

    /// Automatic cleanup threshold
    pub cleanup_threshold: f64,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            max_storage_size: 1_000_000_000, // 1 GB
            chunk_size: 1024 * 1024,         // 1 MB
            compression_enabled: true,
            encryption_at_rest: true,
            encryption_key: MailboxKey::generate(),
            cleanup_threshold: 0.9, // 90% full
        }
    }
}

/// A single entry in mailbox storage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailboxEntry {
    /// Transfer identifier
    pub transfer_id: MailboxTransferId,

    /// Entry metadata
    pub metadata: MailboxTransferMetadata,

    /// Data chunks
    pub chunks: Vec<StoredChunk>,

    /// Current state
    pub state: TransferState,

    /// Storage timestamps
    pub storage_info: StorageInfo,
}

/// Information about a stored chunk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredChunk {
    /// Chunk index
    pub index: u32,

    /// Chunk size in bytes
    pub size: usize,

    /// Storage path relative to storage root
    pub storage_path: String,

    /// Chunk checksum
    pub checksum: String,

    /// Compression applied
    pub compressed: bool,

    /// Encryption applied
    pub encrypted: bool,
}

#[derive(Debug)]
struct EncodedStorageChunk {
    bytes: Vec<u8>,
    plaintext_sha256: String,
    compressed: bool,
    encrypted: bool,
}

#[derive(Debug)]
struct PreparedStoredChunk {
    metadata: StoredChunk,
    bytes: Vec<u8>,
}

/// Storage metadata and timestamps.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageInfo {
    /// When entry was created
    pub created_at: Time,

    /// When entry was last accessed
    pub last_accessed: Time,

    /// When entry was last modified
    pub last_modified: Time,

    /// Total size on disk
    pub disk_size: u64,

    /// Original uncompressed size
    pub original_size: u64,
}

/// Current state of a transfer in storage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransferState {
    /// Transfer is being stored (chunks being written)
    Storing {
        /// Number of chunks stored
        chunks_stored: u32,
        /// Total chunks expected
        total_chunks: u32,
    },

    /// Transfer is completely stored
    Stored,

    /// Transfer is being retrieved
    Retrieving {
        /// Retrieval start time
        started_at: SystemTime,
        /// Requestor peer
        requestor: PeerId,
    },

    /// Transfer has expired and needs cleanup
    Expired {
        /// Expiration time
        expired_at: Time,
    },

    /// Transfer has been corrupted
    Corrupted {
        /// Corruption detected time
        detected_at: Time,
        /// Error details
        error: String,
    },
}

impl MailboxStorage {
    /// Create a new storage manager.
    pub fn new(storage_root: PathBuf) -> MailboxResult<Self> {
        std::fs::create_dir_all(&storage_root).map_err(|e| MailboxError::ConfigurationError {
            details: format!("Failed to create storage directory: {}", e),
        })?;

        Ok(Self {
            storage_root,
            entries: HashMap::new(),
            config: StorageConfig::default(),
        })
    }

    /// Create with custom configuration.
    pub fn with_config(storage_root: PathBuf, config: StorageConfig) -> MailboxResult<Self> {
        std::fs::create_dir_all(&storage_root).map_err(|e| MailboxError::ConfigurationError {
            details: format!("Failed to create storage directory: {}", e),
        })?;

        Ok(Self {
            storage_root,
            entries: HashMap::new(),
            config,
        })
    }

    /// Store a new transfer.
    pub async fn store_transfer(
        &mut self,
        metadata: MailboxTransferMetadata,
        data: Vec<u8>,
    ) -> MailboxResult<()> {
        let transfer_id = metadata.transfer_id;
        if self.entries.contains_key(&transfer_id) {
            return Err(MailboxError::ConfigurationError {
                details: format!("mailbox transfer {transfer_id} already exists in storage"),
            });
        }

        let prepared_chunks = self.prepare_chunks(&transfer_id, &data)?;
        let disk_size = match prepared_chunks.iter().try_fold(0u64, |total, chunk| {
            let chunk_size = u64::try_from(chunk.metadata.size).ok()?;
            total.checked_add(chunk_size)
        }) {
            Some(disk_size) => disk_size,
            None => {
                return Err(MailboxError::QuotaExceeded {
                    usage: u64::MAX,
                    limit: self.config.max_storage_size,
                });
            }
        };

        self.check_capacity(disk_size)?;
        let chunks = self.write_prepared_chunks(transfer_id, prepared_chunks)?;
        let original_size = u64::try_from(data.len()).map_err(|_| MailboxError::QuotaExceeded {
            usage: u64::MAX,
            limit: self.config.max_storage_size,
        })?;

        let entry = MailboxEntry {
            transfer_id,
            metadata,
            chunks,
            state: TransferState::Stored,
            storage_info: StorageInfo {
                created_at: mailbox_time_now(),
                last_accessed: mailbox_time_now(),
                last_modified: mailbox_time_now(),
                disk_size,
                original_size,
            },
        };

        self.entries.insert(transfer_id, entry);
        Ok(())
    }

    /// Retrieve a transfer.
    pub async fn retrieve_transfer(
        &mut self,
        transfer_id: &MailboxTransferId,
        requestor: PeerId,
    ) -> MailboxResult<Vec<u8>> {
        let chunks = {
            let entry =
                self.entries
                    .get_mut(transfer_id)
                    .ok_or(MailboxError::TransferNotFound {
                        transfer_id: *transfer_id,
                    })?;

            entry.state = TransferState::Retrieving {
                started_at: SystemTime::now(),
                requestor,
            };

            entry.storage_info.last_accessed = mailbox_time_now();
            entry.chunks.clone()
        };

        match self.load_chunks(transfer_id, &chunks).await {
            Ok(data) => {
                if let Some(entry) = self.entries.get_mut(transfer_id) {
                    entry.state = TransferState::Stored;
                }
                Ok(data)
            }
            Err(error) => {
                if let Some(entry) = self.entries.get_mut(transfer_id) {
                    entry.state = TransferState::Stored;
                }
                Err(error)
            }
        }
    }

    /// List stored transfers for a peer.
    pub fn list_transfers(&self, peer_id: &PeerId) -> Vec<&MailboxEntry> {
        self.entries
            .values()
            .filter(|entry| entry.metadata.destination_peer == *peer_id)
            .collect()
    }

    /// Delete a transfer from storage.
    pub async fn delete_transfer(&mut self, transfer_id: &MailboxTransferId) -> MailboxResult<()> {
        let entry = self
            .entries
            .get(transfer_id)
            .ok_or(MailboxError::TransferNotFound {
                transfer_id: *transfer_id,
            })?
            .clone();

        self.delete_chunk_files(*transfer_id, &entry.chunks)?;
        self.entries
            .remove(transfer_id)
            .ok_or(MailboxError::TransferNotFound {
                transfer_id: *transfer_id,
            })?;

        Ok(())
    }

    /// Check if storage has capacity for additional data.
    fn check_capacity(&self, additional_bytes: u64) -> MailboxResult<()> {
        let current_usage = self.get_storage_usage();
        let new_usage =
            current_usage
                .checked_add(additional_bytes)
                .ok_or(MailboxError::QuotaExceeded {
                    usage: u64::MAX,
                    limit: self.config.max_storage_size,
                })?;

        if new_usage > self.config.max_storage_size {
            return Err(MailboxError::QuotaExceeded {
                usage: new_usage,
                limit: self.config.max_storage_size,
            });
        }

        Ok(())
    }

    /// Get current storage usage in bytes.
    fn get_storage_usage(&self) -> u64 {
        self.entries
            .values()
            .map(|entry| entry.storage_info.disk_size)
            .fold(0u64, u64::saturating_add)
    }

    /// Encode data as chunks without mutating the filesystem.
    fn prepare_chunks(
        &self,
        transfer_id: &MailboxTransferId,
        data: &[u8],
    ) -> MailboxResult<Vec<PreparedStoredChunk>> {
        let mut chunks = Vec::new();
        let chunk_size = self.config.chunk_size.max(1);

        for (index, chunk_data) in data.chunks(chunk_size).enumerate() {
            let chunk_path = format!("transfers/{}/chunk_{:04}", transfer_id, index);
            let chunk_index =
                u32::try_from(index).map_err(|_| MailboxError::ConfigurationError {
                    details: format!("mailbox transfer has too many chunks: {index}"),
                })?;
            self.chunk_full_path(*transfer_id, &chunk_path)?;

            let stored_chunk = self.encode_chunk(chunk_data)?;

            let chunk = StoredChunk {
                index: chunk_index,
                size: stored_chunk.bytes.len(),
                storage_path: chunk_path,
                checksum: stored_chunk.plaintext_sha256,
                compressed: stored_chunk.compressed,
                encrypted: stored_chunk.encrypted,
            };

            chunks.push(PreparedStoredChunk {
                metadata: chunk,
                bytes: stored_chunk.bytes,
            });
        }

        Ok(chunks)
    }

    fn write_prepared_chunks(
        &self,
        transfer_id: MailboxTransferId,
        prepared_chunks: Vec<PreparedStoredChunk>,
    ) -> MailboxResult<Vec<StoredChunk>> {
        let mut written_chunks = Vec::new();
        let mut stored_chunks = Vec::new();

        for prepared in prepared_chunks {
            let full_path = self.chunk_full_path(transfer_id, &prepared.metadata.storage_path)?;
            if let Some(parent) = full_path.parent() {
                if let Err(error) = std::fs::create_dir_all(parent) {
                    let _ = self.delete_chunk_files(transfer_id, &written_chunks);
                    return Err(MailboxError::NetworkError {
                        details: format!("Failed to create chunk directory: {error}"),
                    });
                }
            }

            if let Err(error) = std::fs::write(&full_path, &prepared.bytes) {
                let _ = self.delete_chunk_files(transfer_id, &written_chunks);
                return Err(MailboxError::NetworkError {
                    details: format!("Failed to write chunk: {error}"),
                });
            }

            written_chunks.push(prepared.metadata.clone());
            stored_chunks.push(prepared.metadata);
        }

        Ok(stored_chunks)
    }

    /// Load data from chunks.
    async fn load_chunks(
        &self,
        transfer_id: &MailboxTransferId,
        chunks: &[StoredChunk],
    ) -> MailboxResult<Vec<u8>> {
        let mut data = Vec::new();

        for chunk in chunks {
            let chunk_path = self.chunk_full_path(*transfer_id, &chunk.storage_path)?;
            let chunk_data =
                std::fs::read(&chunk_path).map_err(|e| MailboxError::NetworkError {
                    details: format!("Failed to read chunk: {}", e),
                })?;

            let plaintext = self.decode_chunk(*transfer_id, &chunk_data, chunk)?;
            data.extend_from_slice(&plaintext);
        }

        Ok(data)
    }

    fn delete_chunk_files(
        &self,
        transfer_id: MailboxTransferId,
        chunks: &[StoredChunk],
    ) -> MailboxResult<()> {
        for chunk in chunks {
            let chunk_path = self.chunk_full_path(transfer_id, &chunk.storage_path)?;
            if chunk_path.exists() {
                std::fs::remove_file(&chunk_path).map_err(|e| MailboxError::NetworkError {
                    details: format!("Failed to delete chunk: {}", e),
                })?;
            }
        }
        Ok(())
    }

    fn chunk_full_path(
        &self,
        transfer_id: MailboxTransferId,
        storage_path: &str,
    ) -> MailboxResult<PathBuf> {
        let path = Path::new(storage_path);
        let expected_prefix = format!("transfers/{transfer_id}/");
        if !storage_path.starts_with(&expected_prefix)
            || storage_path.contains('\\')
            || path.is_absolute()
            || path.components().any(|component| {
                matches!(
                    component,
                    Component::ParentDir
                        | Component::CurDir
                        | Component::RootDir
                        | Component::Prefix(_)
                )
            })
        {
            return Err(MailboxError::TamperDetected {
                transfer_id,
                evidence: format!("mailbox chunk path escapes storage root: {storage_path}"),
            });
        }

        Ok(self.storage_root.join(path))
    }

    fn encode_chunk(&self, plaintext: &[u8]) -> MailboxResult<EncodedStorageChunk> {
        use sha2::{Digest, Sha256};

        let plaintext_sha256 = Sha256::digest(plaintext);
        let mut payload = plaintext.to_vec();
        #[cfg(feature = "compression")]
        let mut compressed = false;
        #[cfg(not(feature = "compression"))]
        let compressed = false;

        #[cfg(feature = "compression")]
        if self.config.compression_enabled && plaintext.len() > 1024 {
            use flate2::{Compression, write::GzEncoder};
            use std::io::Write;

            let mut encoder = GzEncoder::new(Vec::new(), Compression::new(6));
            encoder
                .write_all(plaintext)
                .map_err(|error| MailboxError::NetworkError {
                    details: format!("Failed to compress mailbox chunk: {error}"),
                })?;
            let candidate = encoder
                .finish()
                .map_err(|error| MailboxError::NetworkError {
                    details: format!("Failed to finish mailbox chunk compression: {error}"),
                })?;
            if candidate.len() < plaintext.len() {
                payload = candidate;
                compressed = true;
            }
        }

        let mut nonce = [0u8; 12];
        let mut tag = [0u8; 16];
        let encrypted = if self.config.encryption_at_rest {
            let encrypted_chunk = EncryptedChunk::encrypt(&payload, &self.config.encryption_key)
                .map_err(|operation| MailboxError::CryptoError { operation })?;
            payload = encrypted_chunk.data;
            nonce = encrypted_chunk.nonce.bytes;
            tag = encrypted_chunk.tag;
            true
        } else {
            false
        };

        let mut flags = 0u8;
        if compressed {
            flags |= STORAGE_CHUNK_FLAG_COMPRESSED;
        }
        if encrypted {
            flags |= STORAGE_CHUNK_FLAG_ENCRYPTED;
        }

        let mut bytes = Vec::with_capacity(STORAGE_CHUNK_HEADER_LEN + payload.len());
        bytes.extend_from_slice(STORAGE_CHUNK_MAGIC);
        bytes.push(STORAGE_CHUNK_VERSION);
        bytes.push(flags);
        bytes.extend_from_slice(&(plaintext.len() as u64).to_be_bytes());
        bytes.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        bytes.extend_from_slice(&plaintext_sha256);
        bytes.extend_from_slice(&nonce);
        bytes.extend_from_slice(&tag);
        bytes.extend_from_slice(&payload);

        Ok(EncodedStorageChunk {
            bytes,
            plaintext_sha256: format!("sha256:{}", hex::encode(plaintext_sha256)),
            compressed,
            encrypted,
        })
    }

    fn decode_chunk(
        &self,
        transfer_id: MailboxTransferId,
        encoded: &[u8],
        chunk: &StoredChunk,
    ) -> MailboxResult<Vec<u8>> {
        use sha2::{Digest, Sha256};

        if encoded.len() < STORAGE_CHUNK_HEADER_LEN || &encoded[..8] != STORAGE_CHUNK_MAGIC {
            return Err(MailboxError::TamperDetected {
                transfer_id,
                evidence: format!("mailbox chunk {} has invalid storage envelope", chunk.index),
            });
        }

        let version = encoded[8];
        if version != STORAGE_CHUNK_VERSION {
            return Err(MailboxError::TamperDetected {
                transfer_id,
                evidence: format!(
                    "mailbox chunk {} has unsupported envelope version",
                    chunk.index
                ),
            });
        }
        let flags = encoded[9];
        let original_len_u64 = u64::from_be_bytes(
            encoded[10..18]
                .try_into()
                .expect("fixed mailbox original length field"),
        );
        let original_len =
            usize::try_from(original_len_u64).map_err(|_| MailboxError::TamperDetected {
                transfer_id,
                evidence: format!("mailbox chunk {} original length is too large", chunk.index),
            })?;
        if original_len > self.config.chunk_size.max(1) {
            return Err(MailboxError::TamperDetected {
                transfer_id,
                evidence: format!(
                    "mailbox chunk {} original length exceeds chunk size",
                    chunk.index
                ),
            });
        }

        let payload_len_u64 = u64::from_be_bytes(
            encoded[18..26]
                .try_into()
                .expect("fixed mailbox payload length field"),
        );
        let payload_len =
            usize::try_from(payload_len_u64).map_err(|_| MailboxError::TamperDetected {
                transfer_id,
                evidence: format!("mailbox chunk {} payload length is too large", chunk.index),
            })?;
        let expected_encoded_len = STORAGE_CHUNK_HEADER_LEN
            .checked_add(payload_len)
            .ok_or_else(|| MailboxError::TamperDetected {
                transfer_id,
                evidence: format!("mailbox chunk {} payload length overflows", chunk.index),
            })?;
        if encoded.len() != expected_encoded_len {
            return Err(MailboxError::TamperDetected {
                transfer_id,
                evidence: format!("mailbox chunk {} has invalid payload length", chunk.index),
            });
        }
        let expected_sha = &encoded[26..58];
        let nonce: [u8; 12] = encoded[58..70]
            .try_into()
            .expect("fixed mailbox nonce field");
        let tag: [u8; 16] = encoded[70..86].try_into().expect("fixed mailbox tag field");
        let mut payload = encoded[STORAGE_CHUNK_HEADER_LEN..].to_vec();

        if flags & STORAGE_CHUNK_FLAG_ENCRYPTED != 0 {
            payload = EncryptedChunk {
                data: payload,
                nonce: ChunkNonce { bytes: nonce },
                tag,
            }
            .decrypt(&self.config.encryption_key)
            .map_err(|operation| MailboxError::CryptoError { operation })?;
        }

        if flags & STORAGE_CHUNK_FLAG_COMPRESSED != 0 {
            #[cfg(feature = "compression")]
            {
                use flate2::read::GzDecoder;
                use std::io::Read;

                let mut decoder = GzDecoder::new(payload.as_slice());
                let mut decompressed = Vec::with_capacity(original_len);
                decoder.read_to_end(&mut decompressed).map_err(|error| {
                    MailboxError::TamperDetected {
                        transfer_id,
                        evidence: format!(
                            "mailbox chunk {} failed decompression: {error}",
                            chunk.index
                        ),
                    }
                })?;
                payload = decompressed;
            }

            #[cfg(not(feature = "compression"))]
            {
                return Err(MailboxError::TamperDetected {
                    transfer_id,
                    evidence: format!("mailbox chunk {} requires compression feature", chunk.index),
                });
            }
        }

        if payload.len() != original_len {
            return Err(MailboxError::TamperDetected {
                transfer_id,
                evidence: format!("mailbox chunk {} original length mismatch", chunk.index),
            });
        }

        let actual_sha = Sha256::digest(&payload);
        let metadata_sha = Self::decode_chunk_checksum(transfer_id, chunk, &chunk.checksum)?;
        use subtle::ConstantTimeEq;
        let envelope_checksum_matches = actual_sha.as_slice().ct_eq(expected_sha);
        let metadata_checksum_matches = actual_sha.as_slice().ct_eq(metadata_sha.as_slice());
        if !bool::from(envelope_checksum_matches & metadata_checksum_matches) {
            return Err(MailboxError::TamperDetected {
                transfer_id,
                evidence: format!("mailbox chunk {} checksum mismatch", chunk.index),
            });
        }

        Ok(payload)
    }

    fn decode_chunk_checksum(
        transfer_id: MailboxTransferId,
        chunk: &StoredChunk,
        checksum: &str,
    ) -> MailboxResult<[u8; 32]> {
        let checksum_hex =
            checksum
                .strip_prefix("sha256:")
                .ok_or_else(|| MailboxError::TamperDetected {
                    transfer_id,
                    evidence: format!("mailbox chunk {} has invalid checksum prefix", chunk.index),
                })?;
        let mut decoded = [0u8; 32];
        hex::decode_to_slice(checksum_hex, &mut decoded).map_err(|_| {
            MailboxError::TamperDetected {
                transfer_id,
                evidence: format!(
                    "mailbox chunk {} has invalid checksum encoding",
                    chunk.index
                ),
            }
        })?;
        Ok(decoded)
    }

    /// Perform cleanup of expired transfers.
    pub async fn cleanup_expired(&mut self) -> MailboxResult<u32> {
        let now = mailbox_time_now();
        let mut expired_transfers = Vec::new();

        for (transfer_id, entry) in &self.entries {
            if entry.metadata.expires_at < now {
                expired_transfers.push(*transfer_id);
            }
        }

        let mut cleaned_count = 0;
        for transfer_id in expired_transfers {
            if self.delete_transfer(&transfer_id).await.is_ok() {
                cleaned_count += 1;
            }
        }

        Ok(cleaned_count)
    }

    /// Get storage statistics.
    pub fn get_storage_stats(&self) -> StorageStats {
        let total_entries = self.entries.len();
        let total_size = self.get_storage_usage();
        let utilization = if self.config.max_storage_size > 0 {
            (total_size as f64 / self.config.max_storage_size as f64) * 100.0
        } else {
            0.0
        };

        StorageStats {
            total_entries: u32::try_from(total_entries).unwrap_or(u32::MAX),
            total_size_bytes: total_size,
            max_size_bytes: self.config.max_storage_size,
            utilization_percent: utilization,
            expired_entries: 0, // Would need to calculate
        }
    }
}

/// Storage statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageStats {
    /// Total number of stored entries
    pub total_entries: u32,

    /// Total size in bytes
    pub total_size_bytes: u64,

    /// Maximum configured size
    pub max_size_bytes: u64,

    /// Storage utilization percentage
    pub utilization_percent: f64,

    /// Number of expired entries
    pub expired_entries: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_metadata(transfer_id: MailboxTransferId, total_size: u64) -> MailboxTransferMetadata {
        MailboxTransferMetadata {
            transfer_id,
            destination_peer: PeerId::new("test-peer"),
            created_at: mailbox_time_now(),
            expires_at: Time::from_nanos(
                mailbox_time_now()
                    .as_nanos()
                    .saturating_add(3_600_000_000_000),
            ),
            total_size,
            chunk_count: 1,
            encrypted_metadata: Vec::new(),
        }
    }

    #[test]
    fn test_storage_creation() {
        let temp_dir = TempDir::new().unwrap();
        let storage = MailboxStorage::new(temp_dir.path().to_path_buf()).unwrap();

        assert_eq!(storage.entries.len(), 0);
    }

    #[tokio::test]
    async fn test_store_and_retrieve() {
        let temp_dir = TempDir::new().unwrap();
        let mut storage = MailboxStorage::new(temp_dir.path().to_path_buf()).unwrap();

        let transfer_id = MailboxTransferId::new();
        let metadata = test_metadata(transfer_id, 12);

        let test_data = b"Hello, World!".to_vec();

        // Store transfer
        storage
            .store_transfer(metadata, test_data.clone())
            .await
            .unwrap();
        assert_eq!(storage.entries.len(), 1);

        // Retrieve transfer
        let retrieved_data = storage
            .retrieve_transfer(&transfer_id, PeerId::new("requestor"))
            .await
            .unwrap();

        assert_eq!(retrieved_data, test_data);
    }

    #[tokio::test]
    async fn test_delete_transfer() {
        let temp_dir = TempDir::new().unwrap();
        let mut storage = MailboxStorage::new(temp_dir.path().to_path_buf()).unwrap();

        let transfer_id = MailboxTransferId::new();
        let metadata = test_metadata(transfer_id, 5);

        storage
            .store_transfer(metadata, b"test".to_vec())
            .await
            .unwrap();
        assert_eq!(storage.entries.len(), 1);

        storage.delete_transfer(&transfer_id).await.unwrap();
        assert_eq!(storage.entries.len(), 0);
    }

    #[test]
    fn test_storage_capacity_check() {
        let temp_dir = TempDir::new().unwrap();
        let config = StorageConfig {
            max_storage_size: 100,
            ..Default::default()
        };

        let storage = MailboxStorage::with_config(temp_dir.path().to_path_buf(), config).unwrap();

        assert!(storage.check_capacity(50).is_ok());
        assert!(storage.check_capacity(150).is_err());
    }

    #[test]
    fn storage_capacity_check_rejects_counter_overflow() {
        let temp_dir = TempDir::new().unwrap();
        let mut storage = MailboxStorage::new(temp_dir.path().to_path_buf()).unwrap();
        let transfer_id = MailboxTransferId::new();
        storage.entries.insert(
            transfer_id,
            MailboxEntry {
                transfer_id,
                metadata: test_metadata(transfer_id, u64::MAX),
                chunks: Vec::new(),
                state: TransferState::Stored,
                storage_info: StorageInfo {
                    created_at: mailbox_time_now(),
                    last_accessed: mailbox_time_now(),
                    last_modified: mailbox_time_now(),
                    disk_size: u64::MAX,
                    original_size: 0,
                },
            },
        );

        assert!(matches!(
            storage.check_capacity(1),
            Err(MailboxError::QuotaExceeded {
                usage: u64::MAX,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn store_transfer_rejects_encoded_size_over_capacity_without_writing() {
        let temp_dir = TempDir::new().unwrap();
        let config = StorageConfig {
            max_storage_size: 1,
            ..Default::default()
        };
        let mut storage =
            MailboxStorage::with_config(temp_dir.path().to_path_buf(), config).unwrap();
        let transfer_id = MailboxTransferId::new();

        let result = storage
            .store_transfer(test_metadata(transfer_id, 1), b"x".to_vec())
            .await;

        assert!(matches!(result, Err(MailboxError::QuotaExceeded { .. })));
        assert!(storage.entries.is_empty());
        assert!(!temp_dir.path().join("transfers").exists());
    }

    #[tokio::test]
    async fn store_transfer_rejects_duplicate_transfer_id() {
        let temp_dir = TempDir::new().unwrap();
        let mut storage = MailboxStorage::new(temp_dir.path().to_path_buf()).unwrap();
        let transfer_id = MailboxTransferId::new();

        storage
            .store_transfer(test_metadata(transfer_id, 1), b"a".to_vec())
            .await
            .unwrap();
        let result = storage
            .store_transfer(test_metadata(transfer_id, 1), b"b".to_vec())
            .await;

        assert!(matches!(
            result,
            Err(MailboxError::ConfigurationError { details }) if details.contains("already exists")
        ));
        assert_eq!(storage.entries.len(), 1);
    }

    #[tokio::test]
    async fn zero_chunk_size_is_treated_as_one_byte_chunks() {
        let temp_dir = TempDir::new().unwrap();
        let config = StorageConfig {
            chunk_size: 0,
            ..Default::default()
        };
        let mut storage =
            MailboxStorage::with_config(temp_dir.path().to_path_buf(), config).unwrap();
        let transfer_id = MailboxTransferId::new();

        storage
            .store_transfer(test_metadata(transfer_id, 3), b"abc".to_vec())
            .await
            .unwrap();

        let entry = storage.entries.get(&transfer_id).expect("stored entry");
        assert_eq!(entry.chunks.len(), 3);
        let retrieved = storage
            .retrieve_transfer(&transfer_id, PeerId::new("requestor"))
            .await
            .unwrap();
        assert_eq!(retrieved, b"abc");
    }

    #[tokio::test]
    async fn retrieve_error_restores_stored_state() {
        let temp_dir = TempDir::new().unwrap();
        let mut storage = MailboxStorage::new(temp_dir.path().to_path_buf()).unwrap();
        let transfer_id = MailboxTransferId::new();

        storage
            .store_transfer(test_metadata(transfer_id, 4), b"data".to_vec())
            .await
            .unwrap();
        let entry = storage.entries.get_mut(&transfer_id).expect("stored entry");
        entry.chunks[0].storage_path = format!("transfers/{transfer_id}/missing");

        let result = storage
            .retrieve_transfer(&transfer_id, PeerId::new("requestor"))
            .await;

        assert!(matches!(result, Err(MailboxError::NetworkError { .. })));
        assert!(matches!(
            storage
                .entries
                .get(&transfer_id)
                .expect("stored entry")
                .state,
            TransferState::Stored
        ));
    }

    #[tokio::test]
    async fn delete_transfer_rejects_escaping_chunk_path_without_removing_entry() {
        let temp_dir = TempDir::new().unwrap();
        let mut storage = MailboxStorage::new(temp_dir.path().to_path_buf()).unwrap();
        let transfer_id = MailboxTransferId::new();

        storage
            .store_transfer(test_metadata(transfer_id, 4), b"data".to_vec())
            .await
            .unwrap();
        let entry = storage.entries.get_mut(&transfer_id).expect("stored entry");
        entry.chunks[0].storage_path = format!("transfers/{transfer_id}/../escape");

        let result = storage.delete_transfer(&transfer_id).await;

        assert!(matches!(result, Err(MailboxError::TamperDetected { .. })));
        assert!(storage.entries.contains_key(&transfer_id));
    }

    #[test]
    fn decode_chunk_rejects_unrepresentable_payload_length() {
        let temp_dir = TempDir::new().unwrap();
        let storage = MailboxStorage::new(temp_dir.path().to_path_buf()).unwrap();
        let transfer_id = MailboxTransferId::new();
        let encoded = storage.encode_chunk(b"data").unwrap();
        let mut bytes = encoded.bytes;
        bytes[18..26].copy_from_slice(&u64::MAX.to_be_bytes());
        let chunk = StoredChunk {
            index: 0,
            size: bytes.len(),
            storage_path: format!("transfers/{transfer_id}/chunk_0000"),
            checksum: encoded.plaintext_sha256,
            compressed: encoded.compressed,
            encrypted: encoded.encrypted,
        };

        let result = storage.decode_chunk(transfer_id, &bytes, &chunk);

        assert!(matches!(result, Err(MailboxError::TamperDetected { .. })));
    }

    #[test]
    fn decode_chunk_rejects_invalid_metadata_checksum() {
        let temp_dir = TempDir::new().unwrap();
        let storage = MailboxStorage::new(temp_dir.path().to_path_buf()).unwrap();
        let transfer_id = MailboxTransferId::new();
        let encoded = storage.encode_chunk(b"data").unwrap();
        let chunk = StoredChunk {
            index: 0,
            size: encoded.bytes.len(),
            storage_path: format!("transfers/{transfer_id}/chunk_0000"),
            checksum: "sha256:not-hex".to_string(),
            compressed: encoded.compressed,
            encrypted: encoded.encrypted,
        };

        let result = storage.decode_chunk(transfer_id, &encoded.bytes, &chunk);

        assert!(matches!(result, Err(MailboxError::TamperDetected { .. })));
    }

    #[test]
    fn test_storage_stats() {
        let temp_dir = TempDir::new().unwrap();
        let storage = MailboxStorage::new(temp_dir.path().to_path_buf()).unwrap();

        let stats = storage.get_storage_stats();
        assert_eq!(stats.total_entries, 0);
        assert_eq!(stats.total_size_bytes, 0);
    }
}
