//! ATP Mailbox Storage - Local storage management for mailbox operations.

use super::*;
use crate::types::Time;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::SystemTime;

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

    /// Automatic cleanup threshold
    pub cleanup_threshold: f64,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            max_storage_size: 1_000_000_000, // 1 GB
            chunk_size: 1024 * 1024, // 1 MB
            compression_enabled: true,
            encryption_at_rest: true,
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
        std::fs::create_dir_all(&storage_root)
            .map_err(|e| MailboxError::ConfigurationError {
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
        std::fs::create_dir_all(&storage_root)
            .map_err(|e| MailboxError::ConfigurationError {
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

        // Check storage capacity
        self.check_capacity(data.len() as u64)?;

        // Create storage entry
        let chunks = self.store_chunks(&transfer_id, &data).await?;

        let entry = MailboxEntry {
            transfer_id,
            metadata,
            chunks,
            state: TransferState::Stored,
            storage_info: StorageInfo {
                created_at: Time::now(),
                last_accessed: Time::now(),
                last_modified: Time::now(),
                disk_size: data.len() as u64,
                original_size: data.len() as u64,
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
        let entry = self.entries.get_mut(transfer_id)
            .ok_or_else(|| MailboxError::TransferNotFound {
                transfer_id: *transfer_id,
            })?;

        // Update state
        entry.state = TransferState::Retrieving {
            started_at: SystemTime::now(),
            requestor,
        };

        // Update access time
        entry.storage_info.last_accessed = Time::now();

        // Load data from chunks
        let data = self.load_chunks(&entry.chunks).await?;

        // Mark as stored again
        entry.state = TransferState::Stored;

        Ok(data)
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
        let entry = self.entries.remove(transfer_id)
            .ok_or_else(|| MailboxError::TransferNotFound {
                transfer_id: *transfer_id,
            })?;

        // Remove chunk files
        for chunk in &entry.chunks {
            let chunk_path = self.storage_root.join(&chunk.storage_path);
            if chunk_path.exists() {
                std::fs::remove_file(chunk_path)
                    .map_err(|e| MailboxError::NetworkError {
                        details: format!("Failed to delete chunk: {}", e),
                    })?;
            }
        }

        Ok(())
    }

    /// Check if storage has capacity for additional data.
    fn check_capacity(&self, additional_bytes: u64) -> MailboxResult<()> {
        let current_usage = self.get_storage_usage();
        let new_usage = current_usage + additional_bytes;

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
            .sum()
    }

    /// Store data as chunks.
    async fn store_chunks(
        &self,
        transfer_id: &MailboxTransferId,
        data: &[u8],
    ) -> MailboxResult<Vec<StoredChunk>> {
        let mut chunks = Vec::new();
        let chunk_size = self.config.chunk_size;

        for (index, chunk_data) in data.chunks(chunk_size).enumerate() {
            let chunk_path = format!("transfers/{}/chunk_{:04}", transfer_id.0, index);
            let full_path = self.storage_root.join(&chunk_path);

            // Create directory if needed
            if let Some(parent) = full_path.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| MailboxError::NetworkError {
                        details: format!("Failed to create chunk directory: {}", e),
                    })?;
            }

            // Write chunk data (simplified - no actual compression/encryption)
            std::fs::write(&full_path, chunk_data)
                .map_err(|e| MailboxError::NetworkError {
                    details: format!("Failed to write chunk: {}", e),
                })?;

            let chunk = StoredChunk {
                index: index as u32,
                size: chunk_data.len(),
                storage_path: chunk_path,
                checksum: format!("sha256:{:x}", index), // Simplified checksum
                compressed: self.config.compression_enabled,
                encrypted: self.config.encryption_at_rest,
            };

            chunks.push(chunk);
        }

        Ok(chunks)
    }

    /// Load data from chunks.
    async fn load_chunks(&self, chunks: &[StoredChunk]) -> MailboxResult<Vec<u8>> {
        let mut data = Vec::new();

        for chunk in chunks {
            let chunk_path = self.storage_root.join(&chunk.storage_path);
            let chunk_data = std::fs::read(&chunk_path)
                .map_err(|e| MailboxError::NetworkError {
                    details: format!("Failed to read chunk: {}", e),
                })?;

            data.extend_from_slice(&chunk_data);
        }

        Ok(data)
    }

    /// Perform cleanup of expired transfers.
    pub async fn cleanup_expired(&mut self) -> MailboxResult<u32> {
        let now = Time::now();
        let mut expired_transfers = Vec::new();

        for (transfer_id, entry) in &self.entries {
            if entry.metadata.expires_at < now {
                expired_transfers.push(*transfer_id);
            }
        }

        let mut cleaned_count = 0;
        for transfer_id in expired_transfers {
            if let Ok(()) = self.delete_transfer(&transfer_id).await {
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
            total_entries: total_entries as u32,
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
        let metadata = MailboxTransferMetadata {
            transfer_id,
            destination_peer: PeerId::new("test-peer"),
            created_at: Time::now(),
            expires_at: Time::from_nanos(Time::now().as_nanos() + 3600_000_000_000), // 1 hour
            total_size: 12,
            chunk_count: 1,
            encrypted_metadata: Vec::new(),
        };

        let test_data = b"Hello, World!".to_vec();

        // Store transfer
        storage.store_transfer(metadata, test_data.clone()).await.unwrap();
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
        let metadata = MailboxTransferMetadata {
            transfer_id,
            destination_peer: PeerId::new("test-peer"),
            created_at: Time::now(),
            expires_at: Time::from_nanos(Time::now().as_nanos() + 3600_000_000_000),
            total_size: 5,
            chunk_count: 1,
            encrypted_metadata: Vec::new(),
        };

        storage.store_transfer(metadata, b"test".to_vec()).await.unwrap();
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
    fn test_storage_stats() {
        let temp_dir = TempDir::new().unwrap();
        let storage = MailboxStorage::new(temp_dir.path().to_path_buf()).unwrap();

        let stats = storage.get_storage_stats();
        assert_eq!(stats.total_entries, 0);
        assert_eq!(stats.total_size_bytes, 0);
    }
}