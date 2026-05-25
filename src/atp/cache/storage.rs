//! Storage backends for ATP cache system.
//!
//! Provides pluggable storage backends for cached content including file-based storage,
//! in-memory storage, and external storage integration (relay, CDN, etc.).

use super::{CacheError, CacheKey, StorageLocation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

/// Trait for cache storage backends.
pub trait CacheStorage: Send + Sync {
    /// Store content with the given key.
    fn store(&mut self, key: &CacheKey, content: &[u8]) -> Result<StorageLocation, CacheError>;

    /// Retrieve content for the given storage location.
    fn retrieve(&self, location: &StorageLocation) -> Result<Vec<u8>, CacheError>;

    /// Remove content at the given storage location.
    fn remove(&mut self, location: &StorageLocation) -> Result<(), CacheError>;

    /// Get storage metrics.
    fn metrics(&self) -> StorageMetrics;

    /// Check if content exists at the given location.
    fn exists(&self, location: &StorageLocation) -> bool;
}

/// File-based cache storage backend.
#[derive(Debug)]
pub struct FileStorage {
    /// Root directory for stored files.
    root_dir: PathBuf,
    /// Storage metrics.
    metrics: StorageMetrics,
    /// Whether to enable compression.
    compression_enabled: bool,
}

impl FileStorage {
    /// Create a new file storage backend.
    pub fn new<P: AsRef<Path>>(root_dir: P, compression_enabled: bool) -> Result<Self, CacheError> {
        let root_dir = root_dir.as_ref().to_path_buf();

        // Create root directory if it doesn't exist
        std::fs::create_dir_all(&root_dir)
            .map_err(|e| CacheError::Storage(format!("Failed to create cache directory: {}", e)))?;

        Ok(Self {
            root_dir,
            metrics: StorageMetrics::default(),
            compression_enabled,
        })
    }

    /// Get the file path for a given content hash.
    fn get_file_path(&self, content_hash: &str) -> PathBuf {
        // Use first two characters as subdirectory for better file distribution
        let subdir = if content_hash.len() >= 2 {
            &content_hash[0..2]
        } else {
            "00"
        };

        self.root_dir
            .join(subdir)
            .join(format!("{}.cache", content_hash))
    }

    /// Compress content if compression is enabled.
    fn compress_content(&self, content: &[u8]) -> Result<Vec<u8>, CacheError> {
        if self.compression_enabled && content.len() > 1024 {
            // Use simple gzip compression (placeholder - would use actual compression)
            // For now, just return original content
            Ok(content.to_vec())
        } else {
            Ok(content.to_vec())
        }
    }

    /// Decompress content if needed.
    fn decompress_content(&self, content: &[u8]) -> Result<Vec<u8>, CacheError> {
        // Placeholder for decompression - would detect and decompress as needed
        Ok(content.to_vec())
    }
}

impl CacheStorage for FileStorage {
    fn store(&mut self, key: &CacheKey, content: &[u8]) -> Result<StorageLocation, CacheError> {
        let file_path = self.get_file_path(&key.content_hash);

        // Create subdirectory if needed
        if let Some(parent) = file_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                CacheError::Storage(format!("Failed to create subdirectory: {}", e))
            })?;
        }

        // Compress content if enabled
        let content_to_store = self.compress_content(content)?;

        // Write content to file
        std::fs::write(&file_path, content_to_store)
            .map_err(|e| CacheError::Storage(format!("Failed to write file: {}", e)))?;

        // Update metrics
        self.metrics.files_stored += 1;
        self.metrics.bytes_stored += content.len() as u64;

        Ok(StorageLocation::File(file_path))
    }

    fn retrieve(&self, location: &StorageLocation) -> Result<Vec<u8>, CacheError> {
        match location {
            StorageLocation::File(path) => {
                let content = std::fs::read(path)
                    .map_err(|e| CacheError::Storage(format!("Failed to read file: {}", e)))?;

                // Decompress if needed
                let decompressed = self.decompress_content(&content)?;

                // Update metrics (would be mutable in a real implementation)
                // self.metrics.files_retrieved += 1;

                Ok(decompressed)
            }
            StorageLocation::Memory => Err(CacheError::Storage(
                "Memory storage not supported by FileStorage".to_string(),
            )),
            StorageLocation::External(url) => Err(CacheError::Storage(format!(
                "External storage not supported: {}",
                url
            ))),
        }
    }

    fn remove(&mut self, location: &StorageLocation) -> Result<(), CacheError> {
        match location {
            StorageLocation::File(path) => {
                if path.exists() {
                    std::fs::remove_file(path).map_err(|e| {
                        CacheError::Storage(format!("Failed to remove file: {}", e))
                    })?;

                    self.metrics.files_removed += 1;
                }
                Ok(())
            }
            StorageLocation::Memory => Err(CacheError::Storage(
                "Memory storage not supported by FileStorage".to_string(),
            )),
            StorageLocation::External(url) => Err(CacheError::Storage(format!(
                "External storage removal not supported: {}",
                url
            ))),
        }
    }

    fn metrics(&self) -> StorageMetrics {
        self.metrics.clone()
    }

    fn exists(&self, location: &StorageLocation) -> bool {
        match location {
            StorageLocation::File(path) => path.exists(),
            StorageLocation::Memory => false, // FileStorage doesn't handle memory
            StorageLocation::External(_) => false, // Can't check external existence
        }
    }
}

/// In-memory cache storage backend.
#[derive(Debug)]
pub struct MemoryStorage {
    /// In-memory content store.
    content_store: Arc<RwLock<HashMap<String, Vec<u8>>>>,
    /// Storage metrics.
    metrics: StorageMetrics,
    /// Maximum memory usage in bytes.
    max_memory_bytes: u64,
    /// Current memory usage in bytes.
    current_memory_bytes: u64,
}

impl MemoryStorage {
    /// Create a new memory storage backend.
    #[must_use]
    pub fn new(max_memory_bytes: u64) -> Self {
        Self {
            content_store: Arc::new(RwLock::new(HashMap::new())),
            metrics: StorageMetrics::default(),
            max_memory_bytes,
            current_memory_bytes: 0,
        }
    }

    /// Get memory key for content hash.
    fn get_memory_key(&self, key: &CacheKey) -> String {
        format!("{}:{}", key.manifest_hash, key.content_hash)
    }
}

impl CacheStorage for MemoryStorage {
    fn store(&mut self, key: &CacheKey, content: &[u8]) -> Result<StorageLocation, CacheError> {
        // Check memory limit
        if self.current_memory_bytes + content.len() as u64 > self.max_memory_bytes {
            return Err(CacheError::InsufficientSpace);
        }

        let memory_key = self.get_memory_key(key);

        {
            let mut store = self.content_store.write().unwrap();
            store.insert(memory_key, content.to_vec());
        }

        // Update metrics
        self.metrics.files_stored += 1;
        self.metrics.bytes_stored += content.len() as u64;
        self.current_memory_bytes += content.len() as u64;

        Ok(StorageLocation::Memory)
    }

    fn retrieve(&self, location: &StorageLocation) -> Result<Vec<u8>, CacheError> {
        match location {
            StorageLocation::Memory => {
                // For memory storage, we'd need the key to retrieve
                // This is a limitation of the current design - would need to pass key
                Err(CacheError::Storage(
                    "Memory retrieval requires key context".to_string(),
                ))
            }
            StorageLocation::File(path) => Err(CacheError::Storage(format!(
                "File storage not supported: {:?}",
                path
            ))),
            StorageLocation::External(url) => Err(CacheError::Storage(format!(
                "External storage not supported: {}",
                url
            ))),
        }
    }

    fn remove(&mut self, location: &StorageLocation) -> Result<(), CacheError> {
        match location {
            StorageLocation::Memory => {
                // Would need key to identify what to remove
                Err(CacheError::Storage(
                    "Memory removal requires key context".to_string(),
                ))
            }
            StorageLocation::File(path) => Err(CacheError::Storage(format!(
                "File storage not supported: {:?}",
                path
            ))),
            StorageLocation::External(url) => Err(CacheError::Storage(format!(
                "External storage not supported: {}",
                url
            ))),
        }
    }

    fn metrics(&self) -> StorageMetrics {
        self.metrics.clone()
    }

    fn exists(&self, location: &StorageLocation) -> bool {
        match location {
            StorageLocation::Memory => {
                // Would need key to check existence
                false
            }
            StorageLocation::File(_) => false,
            StorageLocation::External(_) => false,
        }
    }
}

/// Storage metrics and statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StorageMetrics {
    /// Number of files/objects stored.
    pub files_stored: u64,
    /// Number of files/objects retrieved.
    pub files_retrieved: u64,
    /// Number of files/objects removed.
    pub files_removed: u64,
    /// Total bytes stored.
    pub bytes_stored: u64,
    /// Total bytes retrieved.
    pub bytes_retrieved: u64,
    /// Number of storage errors.
    pub errors: u64,
}

/// Hybrid storage backend that combines multiple storage types.
#[derive(Debug)]
pub struct HybridStorage {
    /// Memory storage for small, hot content.
    memory_storage: MemoryStorage,
    /// File storage for larger content.
    file_storage: FileStorage,
    /// Threshold for memory vs file storage (bytes).
    memory_threshold: u64,
    /// Combined metrics.
    metrics: StorageMetrics,
}

impl HybridStorage {
    /// Create a new hybrid storage backend.
    pub fn new<P: AsRef<Path>>(
        memory_limit: u64,
        memory_threshold: u64,
        file_root: P,
        compression: bool,
    ) -> Result<Self, CacheError> {
        Ok(Self {
            memory_storage: MemoryStorage::new(memory_limit),
            file_storage: FileStorage::new(file_root, compression)?,
            memory_threshold,
            metrics: StorageMetrics::default(),
        })
    }

    /// Choose storage backend based on content size.
    fn choose_backend(&self, content_size: u64) -> &str {
        if content_size <= self.memory_threshold {
            "memory"
        } else {
            "file"
        }
    }
}

impl CacheStorage for HybridStorage {
    fn store(&mut self, key: &CacheKey, content: &[u8]) -> Result<StorageLocation, CacheError> {
        let backend = self.choose_backend(content.len() as u64);

        let result = match backend {
            "memory" => self.memory_storage.store(key, content),
            "file" => self.file_storage.store(key, content),
            _ => unreachable!(),
        };

        // Update combined metrics
        if result.is_ok() {
            self.metrics.files_stored += 1;
            self.metrics.bytes_stored += content.len() as u64;
        } else {
            self.metrics.errors += 1;
        }

        result
    }

    fn retrieve(&self, location: &StorageLocation) -> Result<Vec<u8>, CacheError> {
        let result = match location {
            StorageLocation::Memory => self.memory_storage.retrieve(location),
            StorageLocation::File(_) => self.file_storage.retrieve(location),
            StorageLocation::External(_) => Err(CacheError::Storage(
                "External storage not supported".to_string(),
            )),
        };

        // Update metrics (would need mutable access in real implementation)
        result
    }

    fn remove(&mut self, location: &StorageLocation) -> Result<(), CacheError> {
        let result = match location {
            StorageLocation::Memory => self.memory_storage.remove(location),
            StorageLocation::File(_) => self.file_storage.remove(location),
            StorageLocation::External(_) => Err(CacheError::Storage(
                "External storage not supported".to_string(),
            )),
        };

        // Update combined metrics
        if result.is_ok() {
            self.metrics.files_removed += 1;
        } else {
            self.metrics.errors += 1;
        }

        result
    }

    fn metrics(&self) -> StorageMetrics {
        // Combine metrics from both backends
        let memory_metrics = self.memory_storage.metrics();
        let file_metrics = self.file_storage.metrics();

        StorageMetrics {
            files_stored: memory_metrics.files_stored + file_metrics.files_stored,
            files_retrieved: memory_metrics.files_retrieved + file_metrics.files_retrieved,
            files_removed: memory_metrics.files_removed + file_metrics.files_removed,
            bytes_stored: memory_metrics.bytes_stored + file_metrics.bytes_stored,
            bytes_retrieved: memory_metrics.bytes_retrieved + file_metrics.bytes_retrieved,
            errors: memory_metrics.errors + file_metrics.errors,
        }
    }

    fn exists(&self, location: &StorageLocation) -> bool {
        match location {
            StorageLocation::Memory => self.memory_storage.exists(location),
            StorageLocation::File(_) => self.file_storage.exists(location),
            StorageLocation::External(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn file_storage_store_retrieve() {
        let temp_dir = tempdir().unwrap();
        let mut storage = FileStorage::new(temp_dir.path(), false).unwrap();

        let key = CacheKey::new("manifest123".to_string(), "content456".to_string(), None);
        let content = b"test content";

        // Store content
        let location = storage.store(&key, content).unwrap();

        // Check it was stored as a file
        if let StorageLocation::File(path) = &location {
            assert!(path.exists());
        } else {
            panic!("Expected file storage location");
        }

        // Retrieve content
        let retrieved = storage.retrieve(&location).unwrap();
        assert_eq!(retrieved, content);

        // Check metrics
        let metrics = storage.metrics();
        assert_eq!(metrics.files_stored, 1);
        assert_eq!(metrics.bytes_stored, content.len() as u64);
    }

    #[test]
    fn memory_storage_creation() {
        let storage = MemoryStorage::new(1024 * 1024); // 1MB limit
        assert_eq!(storage.max_memory_bytes, 1024 * 1024);
        assert_eq!(storage.current_memory_bytes, 0);
    }

    #[test]
    fn hybrid_storage_backend_selection() {
        let temp_dir = tempdir().unwrap();
        let storage = HybridStorage::new(1024, 512, temp_dir.path(), false).unwrap();

        // Small content should use memory
        assert_eq!(storage.choose_backend(256), "memory");

        // Large content should use file
        assert_eq!(storage.choose_backend(1024), "file");
    }

    #[test]
    fn file_storage_path_generation() {
        let temp_dir = tempdir().unwrap();
        let storage = FileStorage::new(temp_dir.path(), false).unwrap();

        let path = storage.get_file_path("abcdef123");

        // Should use first two characters as subdirectory
        assert!(path.to_string_lossy().contains("ab"));
        assert!(path.to_string_lossy().ends_with("abcdef123.cache"));
    }

    #[test]
    fn storage_metrics_default() {
        let metrics = StorageMetrics::default();
        assert_eq!(metrics.files_stored, 0);
        assert_eq!(metrics.bytes_stored, 0);
        assert_eq!(metrics.errors, 0);
    }
}
