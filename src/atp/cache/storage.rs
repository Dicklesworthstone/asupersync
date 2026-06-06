//! Storage backends for ATP cache system.
//!
//! Provides pluggable storage backends for cached content including file-based storage,
//! in-memory storage, and external storage integration (relay, CDN, etc.).

use super::{CacheError, CacheKey, StorageLocation};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

const CACHE_COMPRESSION_THRESHOLD: usize = 1024;
const CACHE_COMPRESSION_MAGIC: &[u8; 10] = b"ASUPCACHE\0";
const CACHE_COMPRESSION_VERSION: u8 = 1;
const CACHE_CODEC_GZIP: u8 = 1;
const CACHE_COMPRESSION_HEADER_LEN: usize = 10 + 1 + 1 + 8 + 8 + 32;

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
    metrics: Mutex<StorageMetrics>,
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
            metrics: Mutex::new(StorageMetrics::default()),
            compression_enabled,
        })
    }

    /// Get the file path for a given content hash.
    fn get_file_path(&self, content_hash: &str) -> PathBuf {
        let safe_name = hex::encode(Sha256::digest(content_hash.as_bytes()));
        let subdir = &safe_name[0..2];

        self.root_dir
            .join(subdir)
            .join(format!("{}.cache", safe_name))
    }

    fn canonical_root(&self) -> Result<PathBuf, CacheError> {
        std::fs::canonicalize(&self.root_dir)
            .map_err(|e| CacheError::Storage(format!("Failed to canonicalize cache root: {e}")))
    }

    fn ensure_directory_inside_root(&self, path: &Path) -> Result<(), CacheError> {
        let root = self.canonical_root()?;
        let canonical_path = std::fs::canonicalize(path).map_err(|e| {
            CacheError::Storage(format!("Failed to canonicalize cache directory: {e}"))
        })?;
        if canonical_path.starts_with(&root) {
            Ok(())
        } else {
            Err(CacheError::Storage(format!(
                "Cache directory escapes storage root: {}",
                path.display()
            )))
        }
    }

    fn existing_file_inside_root(&self, path: &Path) -> Result<Option<PathBuf>, CacheError> {
        if !path.exists() {
            return Ok(None);
        }

        let root = self.canonical_root()?;
        let canonical_path = std::fs::canonicalize(path)
            .map_err(|e| CacheError::Storage(format!("Failed to canonicalize cache file: {e}")))?;
        if canonical_path.starts_with(&root) {
            Ok(Some(canonical_path))
        } else {
            Err(CacheError::Storage(format!(
                "Cache file escapes storage root: {}",
                path.display()
            )))
        }
    }

    /// Compress content if compression is enabled.
    fn compress_content(&self, content: &[u8]) -> Result<Vec<u8>, CacheError> {
        if !self.compression_enabled || content.len() <= CACHE_COMPRESSION_THRESHOLD {
            return Ok(content.to_vec());
        }

        #[cfg(feature = "compression")]
        {
            use flate2::{Compression, write::GzEncoder};
            use sha2::{Digest, Sha256};
            use std::io::Write;

            let mut encoder = GzEncoder::new(Vec::new(), Compression::new(6));
            encoder.write_all(content).map_err(|e| {
                CacheError::Storage(format!("Failed to gzip-compress cache content: {e}"))
            })?;
            let compressed = encoder.finish().map_err(|e| {
                CacheError::Storage(format!("Failed to finish gzip cache content: {e}"))
            })?;

            if compressed.len() + CACHE_COMPRESSION_HEADER_LEN >= content.len() {
                return Ok(content.to_vec());
            }

            let digest = Sha256::digest(content);
            let mut framed = Vec::with_capacity(CACHE_COMPRESSION_HEADER_LEN + compressed.len());
            framed.extend_from_slice(CACHE_COMPRESSION_MAGIC);
            framed.push(CACHE_COMPRESSION_VERSION);
            framed.push(CACHE_CODEC_GZIP);
            framed.extend_from_slice(&(content.len() as u64).to_be_bytes());
            framed.extend_from_slice(&(compressed.len() as u64).to_be_bytes());
            framed.extend_from_slice(&digest);
            framed.extend_from_slice(&compressed);
            Ok(framed)
        }

        #[cfg(not(feature = "compression"))]
        {
            let _ = content;
            Err(CacheError::Storage(
                "cache compression requested but the compression feature is disabled".to_string(),
            ))
        }
    }

    /// Decompress content if needed.
    fn decompress_content(&self, content: &[u8]) -> Result<Vec<u8>, CacheError> {
        if !content.starts_with(CACHE_COMPRESSION_MAGIC) {
            return Ok(content.to_vec());
        }

        if content.len() < CACHE_COMPRESSION_HEADER_LEN {
            return Err(CacheError::Storage(
                "Truncated compressed cache envelope".to_string(),
            ));
        }

        let version = content[CACHE_COMPRESSION_MAGIC.len()];
        if version != CACHE_COMPRESSION_VERSION {
            return Err(CacheError::Storage(format!(
                "Unsupported compressed cache envelope version: {version}"
            )));
        }

        let codec = content[CACHE_COMPRESSION_MAGIC.len() + 1];
        if codec != CACHE_CODEC_GZIP {
            return Err(CacheError::Storage(format!(
                "Unsupported compressed cache codec: {codec}"
            )));
        }

        let original_size_offset = CACHE_COMPRESSION_MAGIC.len() + 2;
        let compressed_size_offset = original_size_offset + 8;
        let digest_offset = compressed_size_offset + 8;
        let payload_offset = digest_offset + 32;

        let original_size = u64::from_be_bytes(
            content[original_size_offset..compressed_size_offset]
                .try_into()
                .expect("fixed eight-byte original-size field"),
        );
        let compressed_size = u64::from_be_bytes(
            content[compressed_size_offset..digest_offset]
                .try_into()
                .expect("fixed eight-byte compressed-size field"),
        );
        let compressed_size = usize::try_from(compressed_size).map_err(|_| {
            CacheError::Storage("Compressed cache payload length does not fit usize".to_string())
        })?;

        if content.len() != payload_offset + compressed_size {
            return Err(CacheError::Storage(
                "Compressed cache payload length mismatch".to_string(),
            ));
        }

        #[cfg(feature = "compression")]
        {
            use flate2::read::GzDecoder;
            use sha2::{Digest, Sha256};
            use std::io::Read;

            let expected_original_size = usize::try_from(original_size).map_err(|_| {
                CacheError::Storage(
                    "Compressed cache original length does not fit usize".to_string(),
                )
            })?;
            let payload = &content[payload_offset..];
            let mut decoder = GzDecoder::new(payload);
            let mut decompressed = Vec::with_capacity(expected_original_size);
            decoder.read_to_end(&mut decompressed).map_err(|e| {
                CacheError::Storage(format!("Failed to gzip-decompress cache content: {e}"))
            })?;

            if decompressed.len() != expected_original_size {
                return Err(CacheError::Storage(
                    "Compressed cache original length mismatch".to_string(),
                ));
            }

            let digest = Sha256::digest(&decompressed);
            if &digest[..] != &content[digest_offset..payload_offset] {
                return Err(CacheError::Storage(
                    "Compressed cache plaintext digest mismatch".to_string(),
                ));
            }

            Ok(decompressed)
        }

        #[cfg(not(feature = "compression"))]
        {
            let _ = original_size;
            Err(CacheError::Storage(
                "compressed cache content requires the compression feature".to_string(),
            ))
        }
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
            self.ensure_directory_inside_root(parent)?;
        }

        // Compress content if enabled
        let content_to_store = self.compress_content(content)?;

        // Write content to file
        std::fs::write(&file_path, content_to_store)
            .map_err(|e| CacheError::Storage(format!("Failed to write file: {}", e)))?;

        {
            let mut metrics = self.metrics.lock();
            metrics.files_stored += 1;
            metrics.bytes_stored += content.len() as u64;
        }

        Ok(StorageLocation::File(file_path))
    }

    fn retrieve(&self, location: &StorageLocation) -> Result<Vec<u8>, CacheError> {
        match location {
            StorageLocation::File(path) => {
                let path = self.existing_file_inside_root(path)?.ok_or_else(|| {
                    CacheError::Storage(format!("Cache file not found: {}", path.display()))
                })?;
                let content = std::fs::read(&path)
                    .map_err(|e| CacheError::Storage(format!("Failed to read file: {}", e)))?;

                // Decompress if needed
                let decompressed = self.decompress_content(&content)?;

                {
                    let mut metrics = self.metrics.lock();
                    metrics.files_retrieved += 1;
                    metrics.bytes_retrieved += decompressed.len() as u64;
                }

                Ok(decompressed)
            }
            StorageLocation::Memory(_) => Err(CacheError::Storage(
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
                if let Some(path) = self.existing_file_inside_root(path)? {
                    std::fs::remove_file(&path).map_err(|e| {
                        CacheError::Storage(format!("Failed to remove file: {}", e))
                    })?;

                    self.metrics.lock().files_removed += 1;
                }
                Ok(())
            }
            StorageLocation::Memory(_) => Err(CacheError::Storage(
                "Memory storage not supported by FileStorage".to_string(),
            )),
            StorageLocation::External(url) => Err(CacheError::Storage(format!(
                "External storage removal not supported: {}",
                url
            ))),
        }
    }

    fn metrics(&self) -> StorageMetrics {
        self.metrics.lock().clone()
    }

    fn exists(&self, location: &StorageLocation) -> bool {
        match location {
            StorageLocation::File(path) => self
                .existing_file_inside_root(path)
                .is_ok_and(|p| p.is_some()),
            StorageLocation::Memory(_) => false, // FileStorage doesn't handle memory
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
    metrics: Mutex<StorageMetrics>,
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
            metrics: Mutex::new(StorageMetrics::default()),
            max_memory_bytes,
            current_memory_bytes: 0,
        }
    }

    /// Get memory key for content hash.
    fn get_memory_key(&self, key: &CacheKey) -> String {
        key.as_index_key()
    }

    /// Current memory held by this backend.
    #[must_use]
    pub const fn memory_usage(&self) -> u64 {
        self.current_memory_bytes
    }
}

impl CacheStorage for MemoryStorage {
    fn store(&mut self, key: &CacheKey, content: &[u8]) -> Result<StorageLocation, CacheError> {
        let memory_key = self.get_memory_key(key);
        let previous_len = {
            let store = self.content_store.read().unwrap();
            store.get(&memory_key).map_or(0, Vec::len) as u64
        };
        let projected_usage = self
            .current_memory_bytes
            .saturating_sub(previous_len)
            .saturating_add(content.len() as u64);
        if projected_usage > self.max_memory_bytes {
            return Err(CacheError::InsufficientSpace);
        }

        self.content_store
            .write()
            .unwrap()
            .insert(memory_key.clone(), content.to_vec());

        {
            let mut metrics = self.metrics.lock();
            metrics.files_stored += 1;
            metrics.bytes_stored += content.len() as u64;
        }
        self.current_memory_bytes = projected_usage;

        Ok(StorageLocation::Memory(memory_key))
    }

    fn retrieve(&self, location: &StorageLocation) -> Result<Vec<u8>, CacheError> {
        match location {
            StorageLocation::Memory(key) => {
                let store = self.content_store.read().unwrap();
                let content = store.get(key).cloned().ok_or_else(|| {
                    CacheError::Storage("Content not found in memory".to_string())
                })?;
                {
                    let mut metrics = self.metrics.lock();
                    metrics.files_retrieved += 1;
                    metrics.bytes_retrieved += content.len() as u64;
                }
                Ok(content)
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
            StorageLocation::Memory(key) => {
                let mut store = self.content_store.write().unwrap();
                if let Some(content) = store.remove(key) {
                    // Update metrics and memory tracking
                    self.metrics.lock().files_removed += 1;
                    self.current_memory_bytes = self
                        .current_memory_bytes
                        .saturating_sub(content.len() as u64);
                }
                Ok(())
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
        self.metrics.lock().clone()
    }

    fn exists(&self, location: &StorageLocation) -> bool {
        match location {
            StorageLocation::Memory(key) => {
                let store = self.content_store.read().unwrap();
                store.contains_key(key)
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
    metrics: Mutex<StorageMetrics>,
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
            metrics: Mutex::new(StorageMetrics::default()),
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
            "memory" => match self.memory_storage.store(key, content) {
                Err(CacheError::InsufficientSpace) => self.file_storage.store(key, content),
                result => result,
            },
            "file" => self.file_storage.store(key, content),
            _ => unreachable!(),
        };

        // Update combined metrics
        if result.is_ok() {
            let mut metrics = self.metrics.lock();
            metrics.files_stored += 1;
            metrics.bytes_stored += content.len() as u64;
        } else {
            self.metrics.lock().errors += 1;
        }

        result
    }

    fn retrieve(&self, location: &StorageLocation) -> Result<Vec<u8>, CacheError> {
        let result = match location {
            StorageLocation::Memory(_) => self.memory_storage.retrieve(location),
            StorageLocation::File(_) => self.file_storage.retrieve(location),
            StorageLocation::External(_) => Err(CacheError::Storage(
                "External storage not supported".to_string(),
            )),
        };

        match &result {
            Ok(content) => {
                let mut metrics = self.metrics.lock();
                metrics.files_retrieved += 1;
                metrics.bytes_retrieved += content.len() as u64;
            }
            Err(_) => {
                self.metrics.lock().errors += 1;
            }
        }

        result
    }

    fn remove(&mut self, location: &StorageLocation) -> Result<(), CacheError> {
        let result = match location {
            StorageLocation::Memory(_) => self.memory_storage.remove(location),
            StorageLocation::File(_) => self.file_storage.remove(location),
            StorageLocation::External(_) => Err(CacheError::Storage(
                "External storage not supported".to_string(),
            )),
        };

        // Update combined metrics
        if result.is_ok() {
            self.metrics.lock().files_removed += 1;
        } else {
            self.metrics.lock().errors += 1;
        }

        result
    }

    fn metrics(&self) -> StorageMetrics {
        self.metrics.lock().clone()
    }

    fn exists(&self, location: &StorageLocation) -> bool {
        match location {
            StorageLocation::Memory(_) => self.memory_storage.exists(location),
            StorageLocation::File(_) => self.file_storage.exists(location),
            StorageLocation::External(_) => false,
        }
    }
}

#[cfg(test)]
mod file_storage_unit_tests {
    use super::*;

    fn file_storage(compression_enabled: bool) -> FileStorage {
        FileStorage {
            root_dir: PathBuf::new(),
            metrics: Mutex::new(StorageMetrics::default()),
            compression_enabled,
        }
    }

    #[test]
    fn file_storage_leaves_small_content_unframed() {
        let storage = file_storage(true);
        let content = b"small content";

        let encoded = storage.compress_content(content).unwrap();
        assert_eq!(encoded, content);
        assert_eq!(storage.decompress_content(&encoded).unwrap(), content);
    }

    #[test]
    #[cfg(feature = "compression")]
    fn file_storage_gzip_envelope_roundtrips_and_verifies_digest() {
        let storage = file_storage(true);
        let content = b"cache payload ".repeat(512);

        let encoded = storage.compress_content(&content).unwrap();
        assert!(encoded.starts_with(CACHE_COMPRESSION_MAGIC));
        assert!(encoded.len() < content.len());
        assert_eq!(storage.decompress_content(&encoded).unwrap(), content);

        let mut tampered = encoded;
        let last = tampered.len() - 1;
        tampered[last] ^= 0x40;
        assert!(storage.decompress_content(&tampered).is_err());
    }

    #[test]
    #[cfg(not(feature = "compression"))]
    fn file_storage_compression_fails_closed_without_feature() {
        let storage = file_storage(true);
        let content = vec![b'x'; CACHE_COMPRESSION_THRESHOLD + 1];

        assert!(storage.compress_content(&content).is_err());
    }

    #[test]
    fn file_storage_derives_safe_paths_from_untrusted_content_hashes() {
        let root = tempfile::tempdir().unwrap();
        let mut storage = FileStorage::new(root.path(), false).unwrap();
        let key = CacheKey::new("manifest".to_string(), "../outside/cache".to_string(), None);
        let content = b"cache content";

        let location = storage.store(&key, content).unwrap();
        let StorageLocation::File(path) = &location else {
            panic!("file storage must return file location");
        };

        assert!(path.starts_with(root.path()));
        assert!(
            !path
                .components()
                .any(|component| { matches!(component, std::path::Component::ParentDir) })
        );
        assert_eq!(storage.retrieve(&location).unwrap(), content.to_vec());
    }

    #[test]
    fn file_storage_rejects_locations_outside_root() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let outside_path = outside.path().join("victim.cache");
        std::fs::write(&outside_path, b"do not touch").unwrap();

        let mut storage = FileStorage::new(root.path(), false).unwrap();
        let location = StorageLocation::File(outside_path.clone());

        assert!(storage.retrieve(&location).is_err());
        assert!(!storage.exists(&location));
        assert!(storage.remove(&location).is_err());
        assert_eq!(std::fs::read(&outside_path).unwrap(), b"do not touch");
    }

    #[test]
    fn memory_storage_distinguishes_scopes_and_tracks_replacement_bytes() {
        let mut storage = MemoryStorage::new(128);
        let key_private = CacheKey::new(
            "manifest".to_string(),
            "content".to_string(),
            Some("private".to_string()),
        );
        let key_public = CacheKey::new(
            "manifest".to_string(),
            "content".to_string(),
            Some("public".to_string()),
        );

        let private_location = storage.store(&key_private, b"private").unwrap();
        let public_location = storage.store(&key_public, b"public").unwrap();
        assert_ne!(private_location, public_location);
        assert_eq!(storage.memory_usage(), 13);

        storage.store(&key_private, b"p").unwrap();
        assert_eq!(storage.memory_usage(), 7);
        assert_eq!(storage.retrieve(&private_location).unwrap(), b"p".to_vec());
        assert_eq!(
            storage.retrieve(&public_location).unwrap(),
            b"public".to_vec()
        );
    }

    #[test]
    fn hybrid_storage_falls_back_to_file_when_memory_backend_is_full() {
        let root = tempfile::tempdir().unwrap();
        let mut storage = HybridStorage::new(4, 1024, root.path(), false).unwrap();
        let key = CacheKey::new("manifest".to_string(), "content".to_string(), None);
        let content = b"larger than memory";

        let location = storage.store(&key, content).unwrap();
        assert!(matches!(location, StorageLocation::File(_)));
        assert_eq!(storage.retrieve(&location).unwrap(), content.to_vec());
        assert_eq!(storage.metrics().files_stored, 1);
        assert_eq!(storage.metrics().errors, 0);
    }
}

#[cfg(all(test, feature = "legacy-internal-test-harnesses"))]
mod tests {
    use super::*;
    use crate::atp::cache::trust::{TrustBoundaryChecker, TrustPolicy};
    use crate::cx::Cx;
    use serde_json::json;
    use std::time::{Duration, SystemTime};
    use tempfile::tempdir;

    /// Structured test logger for ATP cache storage integration tests.
    #[derive(Debug)]
    struct CacheStorageTestLogger {
        suite_name: String,
        test_name: String,
        start_time: SystemTime,
        current_phase: String,
        cx: Option<Cx>,
    }

    #[derive(Debug, Clone)]
    struct StorageSnapshot {
        backend_type: String,
        files_stored: u64,
        bytes_stored: u64,
        errors: u64,
        memory_usage: Option<u64>,
    }

    impl CacheStorageTestLogger {
        fn new(suite: &str, test: &str, cx: Option<Cx>) -> Self {
            let logger = Self {
                suite_name: suite.to_string(),
                test_name: test.to_string(),
                start_time: SystemTime::now(),
                current_phase: "init".to_string(),
                cx,
            };

            // Use both structured tracing and stderr JSON for comprehensive logging
            if let Some(ref cx) = logger.cx {
                let message = format!("CacheStorageTest {test} started: {suite}");
                cx.trace(&message);
            }

            eprintln!(
                "{}",
                json!({
                    "ts": logger.start_time,
                    "suite": suite,
                    "test": test,
                    "event": "cache_storage_test_start"
                })
            );

            logger
        }

        fn phase(&mut self, phase: &str) {
            self.current_phase = phase.to_string();

            if let Some(ref cx) = self.cx {
                let message = format!("CacheStorageTest phase: {phase}");
                cx.trace(&message);
            }

            eprintln!(
                "{}",
                json!({
                    "ts": SystemTime::now(),
                    "suite": self.suite_name,
                    "test": self.test_name,
                    "phase": phase,
                    "event": "cache_storage_phase_start"
                })
            );
        }

        fn storage_snapshot<S>(&self, label: &str, storage: &S, metrics: &StorageMetrics)
        where
            S: std::fmt::Debug + 'static,
        {
            let snapshot = StorageSnapshot {
                backend_type: std::any::type_name::<S>()
                    .split("::")
                    .last()
                    .unwrap_or("unknown")
                    .to_string(),
                files_stored: metrics.files_stored,
                bytes_stored: metrics.bytes_stored,
                errors: metrics.errors,
                memory_usage: storage_memory_usage(storage),
            };

            if let Some(ref cx) = self.cx {
                let message = format!("CacheStorage snapshot {label}: {snapshot:?}");
                cx.trace(&message);
            }

            eprintln!(
                "{}",
                json!({
                    "ts": SystemTime::now(),
                    "suite": self.suite_name,
                    "test": self.test_name,
                    "phase": self.current_phase,
                    "event": "cache_storage_snapshot",
                    "label": label,
                    "backend_type": snapshot.backend_type,
                    "metrics": {
                        "files_stored": snapshot.files_stored,
                        "bytes_stored": snapshot.bytes_stored,
                        "errors": snapshot.errors,
                        "memory_usage": snapshot.memory_usage
                    }
                })
            );
        }

        fn assert_storage_outcome<T>(&self, field: &str, expected: &T, actual: &T) -> bool
        where
            T: PartialEq + serde::Serialize + std::fmt::Debug,
        {
            let matches = expected == actual;

            if let Some(ref cx) = self.cx {
                let message = format!(
                    "CacheStorage assertion {field}: expected={expected:?}, actual={actual:?}, match={matches}"
                );
                cx.trace(&message);
            }

            eprintln!(
                "{}",
                json!({
                    "ts": SystemTime::now(),
                    "suite": self.suite_name,
                    "test": self.test_name,
                    "phase": self.current_phase,
                    "event": "cache_storage_assertion",
                    "field": field,
                    "expected": expected,
                    "actual": actual,
                    "match": matches
                })
            );

            matches
        }

        fn test_end(&self, result: &str) {
            let duration_ms = self
                .start_time
                .elapsed()
                .unwrap_or(Duration::ZERO)
                .as_millis() as u64;

            if let Some(ref cx) = self.cx {
                let message = format!(
                    "CacheStorageTest {} completed: {} in {}ms",
                    self.test_name, result, duration_ms
                );
                cx.trace(&message);
            }

            eprintln!(
                "{}",
                json!({
                    "ts": SystemTime::now(),
                    "suite": self.suite_name,
                    "test": self.test_name,
                    "event": "cache_storage_test_end",
                    "result": result,
                    "duration_ms": duration_ms
                })
            );
        }
    }

    fn storage_memory_usage<S>(storage: &S) -> Option<u64>
    where
        S: std::fmt::Debug + 'static,
    {
        use std::any::Any;

        let any = storage as &dyn Any;
        any.downcast_ref::<MemoryStorage>()
            .map(MemoryStorage::memory_usage)
            .or_else(|| {
                any.downcast_ref::<HybridStorage>()
                    .map(|storage| storage.memory_storage.memory_usage())
            })
    }

    /// Test data factory for creating realistic cache content.
    struct CacheContentFactory;

    impl CacheContentFactory {
        fn manifest_json_content(objects: usize) -> Vec<u8> {
            let manifest = json!({
                "schema_version": 2,
                "created_at": SystemTime::now(),
                "objects": (0..objects).map(|i| json!({
                    "id": format!("obj_{:08x}", i),
                    "hash": format!("sha256_{:064x}", i * 0x123456789abcdef),
                    "size_bytes": 1024 + i * 512,
                    "content_type": "application/octet-stream"
                })).collect::<Vec<_>>(),
                "total_size_bytes": objects * 1536 // Average size
            });

            serde_json::to_vec_pretty(&manifest).unwrap()
        }

        fn binary_blob_content(size_bytes: usize, seed: u8) -> Vec<u8> {
            (0..size_bytes)
                .map(|i| seed.wrapping_add((i % 256) as u8).wrapping_mul(3))
                .collect()
        }

        fn encrypted_content(plaintext: &[u8], key_hint: &str) -> Vec<u8> {
            // Simple XOR "encryption" for testing (NOT for production)
            let key: Vec<u8> = key_hint.bytes().cycle().take(plaintext.len()).collect();
            plaintext
                .iter()
                .zip(key.iter())
                .map(|(p, k)| p ^ k)
                .collect()
        }

        fn test_cache_key(manifest: &str, content: &str, scope: Option<&str>) -> CacheKey {
            CacheKey::new(
                format!("manifest_{}", manifest),
                format!("content_{}", content),
                scope.map(String::from),
            )
        }
    }

    /// Test isolation manager for cache storage tests.
    struct CacheStorageTestIsolation {
        temp_dirs: Vec<tempfile::TempDir>,
        created_locations: Vec<StorageLocation>,
    }

    impl CacheStorageTestIsolation {
        fn new() -> Self {
            Self {
                temp_dirs: Vec::new(),
                created_locations: Vec::new(),
            }
        }

        fn create_temp_dir(&mut self) -> std::path::PathBuf {
            let temp_dir = tempdir().expect("create temp dir");
            let path = temp_dir.path().to_path_buf();
            self.temp_dirs.push(temp_dir);
            path
        }

        fn track_location(&mut self, location: StorageLocation) {
            self.created_locations.push(location);
        }
    }

    impl Drop for CacheStorageTestIsolation {
        fn drop(&mut self) {
            eprintln!(
                "CacheStorageTestIsolation: cleaned {} temp dirs, {} locations",
                self.temp_dirs.len(),
                self.created_locations.len()
            );
        }
    }

    #[test]
    fn cache_storage_workflow_integration_with_trust_policy() {
        let mut isolation = CacheStorageTestIsolation::new();

        let cx = Cx::for_testing();
        let mut log = CacheStorageTestLogger::new(
            "cache_storage_integration",
            "workflow_with_trust",
            Some(cx.clone()),
        );

        log.phase("setup");

        // Create real storage backends
        let temp_path = isolation.create_temp_dir();
        let mut file_storage = FileStorage::new(temp_path, false).expect("create file storage");
        let mut memory_storage = MemoryStorage::new(5 * 1024 * 1024); // 5MB limit

        // Create trust policy for cache security testing
        let mut trust_policy = TrustPolicy::local();
        trust_policy.add_authorized_scope("test-workflow".to_string());
        let mut trust_checker = TrustBoundaryChecker::new(trust_policy);

        log.storage_snapshot(
            "initial_file_storage",
            &file_storage,
            &file_storage.metrics(),
        );
        log.storage_snapshot(
            "initial_memory_storage",
            &memory_storage,
            &memory_storage.metrics(),
        );

        log.phase("content_creation");

        // Create realistic test content using factory
        let manifest_data = CacheContentFactory::manifest_json_content(10);
        let blob_data = CacheContentFactory::binary_blob_content(4096, 0xAB);
        let encrypted_data = CacheContentFactory::encrypted_content(&blob_data, "test_key_123");

        let manifest_key =
            CacheContentFactory::test_cache_key("workflow_test", "manifest", Some("test-workflow"));
        let blob_key =
            CacheContentFactory::test_cache_key("workflow_test", "blob", Some("test-workflow"));
        let encrypted_key = CacheContentFactory::test_cache_key(
            "workflow_test",
            "encrypted",
            Some("test-workflow"),
        );

        log.phase("trust_validation");

        // Test trust policy integration (real security validation)
        let manifest_trust_result = trust_checker.check_access(&manifest_key, "store");
        let blob_trust_result = trust_checker.check_access(&blob_key, "store");
        let encrypted_trust_result = trust_checker.check_access(&encrypted_key, "store");

        assert!(log.assert_storage_outcome(
            "manifest_trust_check",
            &true,
            &manifest_trust_result.is_ok()
        ));
        assert!(log.assert_storage_outcome("blob_trust_check", &true, &blob_trust_result.is_ok()));
        assert!(log.assert_storage_outcome(
            "encrypted_trust_check",
            &true,
            &encrypted_trust_result.is_ok()
        ));

        log.phase("storage_operations");

        // Store content in different backends (real cache workflow)
        let manifest_location = file_storage
            .store(&manifest_key, &manifest_data)
            .expect("store manifest");
        let blob_location = memory_storage
            .store(&blob_key, &blob_data)
            .expect("store blob");
        let encrypted_location = file_storage
            .store(&encrypted_key, &encrypted_data)
            .expect("store encrypted");

        isolation.track_location(manifest_location.clone());
        isolation.track_location(blob_location.clone());
        isolation.track_location(encrypted_location.clone());

        log.storage_snapshot("post_storage_file", &file_storage, &file_storage.metrics());
        log.storage_snapshot(
            "post_storage_memory",
            &memory_storage,
            &memory_storage.metrics(),
        );

        log.phase("retrieval_and_verification");

        // Retrieve and verify content (end-to-end cache workflow)
        let retrieved_manifest = file_storage
            .retrieve(&manifest_location)
            .expect("retrieve manifest");
        let retrieved_blob = memory_storage
            .retrieve(&blob_location)
            .expect("retrieve blob");
        let retrieved_encrypted = file_storage
            .retrieve(&encrypted_location)
            .expect("retrieve encrypted");

        // Verify content integrity
        assert!(log.assert_storage_outcome(
            "manifest_integrity",
            &manifest_data,
            &retrieved_manifest
        ));
        assert!(log.assert_storage_outcome("blob_integrity", &blob_data, &retrieved_blob));
        assert!(log.assert_storage_outcome(
            "encrypted_integrity",
            &encrypted_data,
            &retrieved_encrypted
        ));

        // Verify storage metrics
        assert!(log.assert_storage_outcome(
            "file_storage_files",
            &2u64,
            &file_storage.metrics().files_stored
        ));
        assert!(log.assert_storage_outcome(
            "memory_storage_files",
            &1u64,
            &memory_storage.metrics().files_stored
        ));

        let total_file_bytes = manifest_data.len() + encrypted_data.len();
        assert!(log.assert_storage_outcome(
            "file_storage_bytes",
            &(total_file_bytes as u64),
            &file_storage.metrics().bytes_stored
        ));

        log.phase("cross_backend_verification");

        // Test cross-backend scenarios (hybrid workflow)
        let cross_store_result = memory_storage.store(&manifest_key, &manifest_data);
        if let Ok(cross_location) = cross_store_result {
            isolation.track_location(cross_location.clone());
            let cross_retrieved = memory_storage
                .retrieve(&cross_location)
                .expect("cross retrieve");
            assert!(log.assert_storage_outcome(
                "cross_backend_integrity",
                &manifest_data,
                &cross_retrieved
            ));
        }

        log.phase("error_simulation");

        // Test error conditions (storage failure handling)
        let invalid_location = StorageLocation::File("/nonexistent/path/test.cache".into());
        let error_result = file_storage.retrieve(&invalid_location);
        assert!(log.assert_storage_outcome("error_handling", &true, &error_result.is_err()));

        log.storage_snapshot("final_file_storage", &file_storage, &file_storage.metrics());
        log.storage_snapshot(
            "final_memory_storage",
            &memory_storage,
            &memory_storage.metrics(),
        );

        log.test_end("pass");
    }

    #[test]
    fn hybrid_storage_backend_selection_and_workflow() {
        let mut isolation = CacheStorageTestIsolation::new();

        let cx = Cx::for_testing();
        let mut log = CacheStorageTestLogger::new(
            "cache_storage_integration",
            "hybrid_backend_workflow",
            Some(cx.clone()),
        );

        log.phase("setup");

        let temp_path = isolation.create_temp_dir();
        let mut hybrid_storage = HybridStorage::new(
            2048, // Memory threshold: 2KB
            1024, // File threshold: 1KB
            temp_path, false, // Not encrypted by default
        )
        .expect("create hybrid storage");

        log.storage_snapshot(
            "initial_hybrid_storage",
            &hybrid_storage,
            &hybrid_storage.metrics(),
        );

        log.phase("backend_selection_testing");

        // Test backend selection logic (realistic size-based routing)
        let small_content = CacheContentFactory::binary_blob_content(512, 0x11); // < 1KB -> memory
        let medium_content = CacheContentFactory::binary_blob_content(1536, 0x22); // 1.5KB -> file
        let large_content = CacheContentFactory::binary_blob_content(3072, 0x33); // 3KB -> file

        let small_key = CacheContentFactory::test_cache_key("hybrid", "small", None);
        let medium_key = CacheContentFactory::test_cache_key("hybrid", "medium", None);
        let large_key = CacheContentFactory::test_cache_key("hybrid", "large", None);

        log.phase("size_based_routing");

        // Store content and verify backend selection
        let small_location = hybrid_storage
            .store(&small_key, &small_content)
            .expect("store small");
        let medium_location = hybrid_storage
            .store(&medium_key, &medium_content)
            .expect("store medium");
        let large_location = hybrid_storage
            .store(&large_key, &large_content)
            .expect("store large");

        isolation.track_location(small_location.clone());
        isolation.track_location(medium_location.clone());
        isolation.track_location(large_location.clone());

        // Verify backend selection based on size
        match (&small_location, &medium_location, &large_location) {
            (StorageLocation::Memory(_), StorageLocation::File(_), StorageLocation::File(_)) => {
                assert!(log.assert_storage_outcome("backend_selection_correct", &true, &true));
            }
            _ => {
                eprintln!(
                    "Backend selection: small={:?}, medium={:?}, large={:?}",
                    small_location, medium_location, large_location
                );
                assert!(log.assert_storage_outcome("backend_selection_correct", &true, &false));
            }
        }

        log.storage_snapshot(
            "post_routing_hybrid_storage",
            &hybrid_storage,
            &hybrid_storage.metrics(),
        );

        log.phase("retrieval_verification");

        // Retrieve from different backends and verify integrity
        let retrieved_small = hybrid_storage
            .retrieve(&small_location)
            .expect("retrieve small");
        let retrieved_medium = hybrid_storage
            .retrieve(&medium_location)
            .expect("retrieve medium");
        let retrieved_large = hybrid_storage
            .retrieve(&large_location)
            .expect("retrieve large");

        assert!(log.assert_storage_outcome(
            "small_content_integrity",
            &small_content,
            &retrieved_small
        ));
        assert!(log.assert_storage_outcome(
            "medium_content_integrity",
            &medium_content,
            &retrieved_medium
        ));
        assert!(log.assert_storage_outcome(
            "large_content_integrity",
            &large_content,
            &retrieved_large
        ));

        log.storage_snapshot(
            "final_hybrid_storage",
            &hybrid_storage,
            &hybrid_storage.metrics(),
        );
        log.test_end("pass");
    }

    #[test]
    fn storage_stress_and_metrics_validation() {
        let mut isolation = CacheStorageTestIsolation::new();

        let cx = Cx::for_testing();
        let mut log = CacheStorageTestLogger::new(
            "cache_storage_integration",
            "stress_and_metrics",
            Some(cx.clone()),
        );

        log.phase("setup");

        let temp_path = isolation.create_temp_dir();
        let mut stress_storage = FileStorage::new(temp_path, false).expect("create stress storage");

        log.storage_snapshot(
            "initial_stress_storage",
            &stress_storage,
            &stress_storage.metrics(),
        );

        log.phase("stress_storage_operations");

        let mut total_bytes = 0u64;
        let stress_iterations = 20;

        for i in 0..stress_iterations {
            let content_size = 1024 + i * 256; // Varying sizes
            let content = CacheContentFactory::binary_blob_content(content_size, (i % 256) as u8);
            let key =
                CacheContentFactory::test_cache_key("stress", &format!("item_{:03}", i), None);

            let location = stress_storage.store(&key, &content).expect("stress store");
            isolation.track_location(location.clone());

            total_bytes += content.len() as u64;

            // Verify retrieval works under stress
            let retrieved = stress_storage.retrieve(&location).expect("stress retrieve");
            assert!(log.assert_storage_outcome(
                &format!("stress_integrity_{}", i),
                &content,
                &retrieved
            ));

            if i % 5 == 0 {
                log.storage_snapshot(
                    &format!("stress_iteration_{}", i),
                    &stress_storage,
                    &stress_storage.metrics(),
                );
            }
        }

        log.phase("metrics_validation");

        let final_metrics = stress_storage.metrics();
        assert!(log.assert_storage_outcome(
            "stress_files_count",
            &(stress_iterations as u64),
            &final_metrics.files_stored
        ));
        assert!(log.assert_storage_outcome(
            "stress_total_bytes",
            &total_bytes,
            &final_metrics.bytes_stored
        ));
        assert!(log.assert_storage_outcome("stress_no_errors", &0u64, &final_metrics.errors));

        log.storage_snapshot("final_stress_storage", &stress_storage, &final_metrics);
        log.test_end("pass");
    }

    // Unit tests for storage metrics compatibility.
    #[test]
    fn storage_metrics_default() {
        let metrics = StorageMetrics::default();
        assert_eq!(metrics.files_stored, 0);
        assert_eq!(metrics.bytes_stored, 0);
        assert_eq!(metrics.errors, 0);
    }
}
