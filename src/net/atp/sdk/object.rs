//! ATP object management and content-addressed storage.

use crate::cx::Cx;
use crate::net::atp::protocol::{AtpError, AtpOutcome, DiskError, ManifestError, PlatformError};

/// Helper macro to handle Result<T, E> in functions returning AtpOutcome<U>.
/// Converts Result errors using the provided mapper and returns early on error.
macro_rules! try_atp {
    ($expr:expr, $error_mapper:expr) => {
        match $expr {
            Ok(v) => v,
            Err(e) => return AtpOutcome::Err($error_mapper(e)),
        }
    };
}
use crate::sync::{LockError, Mutex, MutexGuard};
use crate::types::CancelReason;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Content-addressed object with hash-based identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtpObject {
    /// Content hash (SHA-256).
    pub hash: ObjectHash,
    /// Object size in bytes.
    pub size_bytes: u64,
    /// Content type/MIME type.
    pub content_type: String,
    /// Object metadata.
    pub metadata: ObjectMetadata,
    /// Object creation timestamp.
    pub created_at_nanos: u64,
}

/// Object hash type.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ObjectHash(pub [u8; 32]);

impl ObjectHash {
    /// Create from hash bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Compute hash from data.
    #[must_use]
    pub fn from_data(data: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(data);
        Self(hasher.finalize().into())
    }

    /// Get hash bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Get hex representation.
    #[must_use]
    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Create from hex string.
    pub fn from_hex(hex_str: &str) -> Result<Self, hex::FromHexError> {
        let bytes = hex::decode(hex_str)?;
        if bytes.len() == 32 {
            let mut array = [0u8; 32];
            array.copy_from_slice(&bytes);
            Ok(Self(array))
        } else {
            Err(hex::FromHexError::InvalidStringLength)
        }
    }
}

impl std::fmt::Display for ObjectHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.hex())
    }
}

/// Object metadata key-value pairs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectMetadata {
    /// Custom metadata fields.
    pub fields: HashMap<String, String>,
}

impl ObjectMetadata {
    /// Create new empty metadata.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a metadata field.
    pub fn insert(&mut self, key: String, value: String) {
        self.fields.insert(key, value);
    }

    /// Get a metadata field.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.fields.get(key).map(String::as_str)
    }

    /// Remove a metadata field.
    pub fn remove(&mut self, key: &str) -> Option<String> {
        self.fields.remove(key)
    }

    /// Check if metadata contains a key.
    #[must_use]
    pub fn contains_key(&self, key: &str) -> bool {
        self.fields.contains_key(key)
    }

    /// Get all field names.
    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.fields.keys().map(String::as_str)
    }

    /// Create metadata with common fields.
    #[must_use]
    pub fn with_filename(filename: &str) -> Self {
        let mut metadata = Self::new();
        metadata.insert("filename".to_string(), filename.to_string());
        metadata
    }

    /// Create metadata with source path.
    #[must_use]
    pub fn with_source_path(path: &Path) -> Self {
        let mut metadata = Self::new();
        if let Some(filename) = path.file_name().and_then(|n| n.to_str()) {
            metadata.insert("filename".to_string(), filename.to_string());
        }
        if let Some(parent) = path.parent().and_then(|p| p.to_str()) {
            metadata.insert("source_directory".to_string(), parent.to_string());
        }
        metadata
    }
}

/// Object manifest for hierarchical object graphs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectManifest {
    /// Manifest version.
    pub version: u32,
    /// Root object hash.
    pub root_hash: ObjectHash,
    /// Object entries in the manifest.
    pub objects: Vec<ManifestEntry>,
    /// Manifest metadata.
    pub metadata: ObjectMetadata,
    /// Manifest creation timestamp.
    pub created_at_nanos: u64,
}

/// Entry in an object manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestEntry {
    /// Object hash.
    pub hash: ObjectHash,
    /// Relative path in the object graph.
    pub path: String,
    /// Object size in bytes.
    pub size_bytes: u64,
    /// Content type.
    pub content_type: String,
    /// Entry-specific metadata.
    pub metadata: ObjectMetadata,
}

/// Object store for managing ATP objects.
#[allow(async_fn_in_trait)]
pub trait ObjectStore {
    /// Store an object and return its hash.
    async fn store_object(
        &self,
        cx: &Cx,
        data: Vec<u8>,
        content_type: &str,
        metadata: ObjectMetadata,
    ) -> AtpOutcome<AtpObject>;

    /// Retrieve an object by hash.
    async fn get_object(&self, cx: &Cx, hash: &ObjectHash) -> AtpOutcome<Option<Vec<u8>>>;

    /// Get object metadata without data.
    async fn get_object_info(&self, cx: &Cx, hash: &ObjectHash) -> AtpOutcome<Option<AtpObject>>;

    /// Check if an object exists.
    async fn has_object(&self, cx: &Cx, hash: &ObjectHash) -> AtpOutcome<bool>;

    /// Delete an object.
    async fn delete_object(&self, cx: &Cx, hash: &ObjectHash) -> AtpOutcome<bool>;

    /// List all objects (for debugging/admin).
    async fn list_objects(&self, cx: &Cx) -> AtpOutcome<Vec<ObjectHash>>;
}

/// In-memory object store implementation.
type MemoryObjectMap = HashMap<ObjectHash, (Vec<u8>, AtpObject)>;

#[derive(Debug)]
pub struct MemoryObjectStore {
    objects: Mutex<MemoryObjectMap>,
}

impl Default for MemoryObjectStore {
    fn default() -> Self {
        Self {
            objects: Mutex::with_name("atp_memory_object_store", MemoryObjectMap::new()),
        }
    }
}

impl MemoryObjectStore {
    /// Create a new in-memory object store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn current_time_nanos() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        u64::try_from(nanos).unwrap_or(u64::MAX)
    }

    async fn lock_objects(&self, cx: &Cx) -> AtpOutcome<MutexGuard<'_, MemoryObjectMap>> {
        match self.objects.lock(cx).await {
            Ok(objects) => AtpOutcome::ok(objects),
            Err(LockError::Cancelled) => AtpOutcome::cancelled(
                cx.cancel_reason()
                    .unwrap_or_else(CancelReason::parent_cancelled),
            ),
            Err(LockError::TimedOut(_)) => AtpOutcome::cancelled(CancelReason::timeout()),
            Err(LockError::Poisoned | LockError::PolledAfterCompletion) => {
                AtpOutcome::Err(AtpError::Platform(PlatformError::OperatingSystemError))
            }
        }
    }
}

impl ObjectStore for MemoryObjectStore {
    async fn store_object(
        &self,
        cx: &Cx,
        data: Vec<u8>,
        content_type: &str,
        metadata: ObjectMetadata,
    ) -> AtpOutcome<AtpObject> {
        let hash = ObjectHash::from_data(&data);
        let size_bytes = data.len() as u64;

        let object = AtpObject {
            hash: hash.clone(),
            size_bytes,
            content_type: content_type.to_string(), // ubs:ignore - struct field initialization
            metadata,
            created_at_nanos: Self::current_time_nanos(),
        };

        let mut objects = match self.lock_objects(cx).await {
            AtpOutcome::Ok(objects) => objects,
            AtpOutcome::Err(error) => return AtpOutcome::Err(error),
            AtpOutcome::Cancelled(reason) => return AtpOutcome::Cancelled(reason),
            AtpOutcome::Panicked(payload) => return AtpOutcome::Panicked(payload),
        };
        objects.insert(hash, (data, object.clone()));

        AtpOutcome::ok(object)
    }

    async fn get_object(&self, cx: &Cx, hash: &ObjectHash) -> AtpOutcome<Option<Vec<u8>>> {
        let objects = match self.lock_objects(cx).await {
            AtpOutcome::Ok(objects) => objects,
            AtpOutcome::Err(error) => return AtpOutcome::Err(error),
            AtpOutcome::Cancelled(reason) => return AtpOutcome::Cancelled(reason),
            AtpOutcome::Panicked(payload) => return AtpOutcome::Panicked(payload),
        };
        AtpOutcome::ok(objects.get(hash).map(|(data, _)| data.clone()))
    }

    async fn get_object_info(&self, cx: &Cx, hash: &ObjectHash) -> AtpOutcome<Option<AtpObject>> {
        let objects = match self.lock_objects(cx).await {
            AtpOutcome::Ok(objects) => objects,
            AtpOutcome::Err(error) => return AtpOutcome::Err(error),
            AtpOutcome::Cancelled(reason) => return AtpOutcome::Cancelled(reason),
            AtpOutcome::Panicked(payload) => return AtpOutcome::Panicked(payload),
        };
        AtpOutcome::ok(objects.get(hash).map(|(_, object)| object.clone()))
    }

    async fn has_object(&self, cx: &Cx, hash: &ObjectHash) -> AtpOutcome<bool> {
        let objects = match self.lock_objects(cx).await {
            AtpOutcome::Ok(objects) => objects,
            AtpOutcome::Err(error) => return AtpOutcome::Err(error),
            AtpOutcome::Cancelled(reason) => return AtpOutcome::Cancelled(reason),
            AtpOutcome::Panicked(payload) => return AtpOutcome::Panicked(payload),
        };
        AtpOutcome::ok(objects.contains_key(hash))
    }

    async fn delete_object(&self, cx: &Cx, hash: &ObjectHash) -> AtpOutcome<bool> {
        let mut objects = match self.lock_objects(cx).await {
            AtpOutcome::Ok(objects) => objects,
            AtpOutcome::Err(error) => return AtpOutcome::Err(error),
            AtpOutcome::Cancelled(reason) => return AtpOutcome::Cancelled(reason),
            AtpOutcome::Panicked(payload) => return AtpOutcome::Panicked(payload),
        };
        AtpOutcome::ok(objects.remove(hash).is_some())
    }

    async fn list_objects(&self, cx: &Cx) -> AtpOutcome<Vec<ObjectHash>> {
        let objects = match self.lock_objects(cx).await {
            AtpOutcome::Ok(objects) => objects,
            AtpOutcome::Err(error) => return AtpOutcome::Err(error),
            AtpOutcome::Cancelled(reason) => return AtpOutcome::Cancelled(reason),
            AtpOutcome::Panicked(payload) => return AtpOutcome::Panicked(payload),
        };
        AtpOutcome::ok(objects.keys().cloned().collect())
    }
}

/// File system object store implementation.
#[derive(Debug, Clone)]
pub struct FileSystemObjectStore {
    base_path: PathBuf,
}

impl FileSystemObjectStore {
    /// Create a new file system object store.
    #[must_use]
    pub fn new(base_path: PathBuf) -> Self {
        Self { base_path }
    }

    /// Get the path for an object hash.
    fn object_path(&self, hash: &ObjectHash) -> PathBuf {
        let hex = hash.hex();
        // Use two-level directory structure: aa/bb/aabb...
        let dir1 = &hex[0..2];
        let dir2 = &hex[2..4];
        let filename = &hex[4..];
        self.base_path.join(dir1).join(dir2).join(filename)
    }

    /// Get the metadata path for an object hash.
    fn metadata_path(&self, hash: &ObjectHash) -> PathBuf {
        let mut path = self.object_path(hash);
        path.set_extension("meta");
        path
    }

    fn is_hash_path_component(name: &str, expected_len: usize) -> bool {
        name.len() == expected_len && name.as_bytes().iter().all(|byte| byte.is_ascii_hexdigit())
    }

    fn current_time_nanos() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        u64::try_from(nanos).unwrap_or(u64::MAX)
    }
}

impl ObjectStore for FileSystemObjectStore {
    async fn store_object(
        &self,
        _cx: &Cx,
        data: Vec<u8>,
        content_type: &str,
        metadata: ObjectMetadata,
    ) -> AtpOutcome<AtpObject> {
        let hash = ObjectHash::from_data(&data);
        let size_bytes = data.len() as u64;

        let object = AtpObject {
            hash: hash.clone(),
            size_bytes,
            content_type: content_type.to_string(), // ubs:ignore - struct field initialization
            metadata,
            created_at_nanos: Self::current_time_nanos(),
        };

        let object_path = self.object_path(&hash);
        let metadata_path = self.metadata_path(&hash);

        // Create parent directories
        if let Some(parent) = object_path.parent() {
            try_atp!(crate::fs::create_dir_all(parent).await, |_| AtpError::Disk(
                DiskError::IoError
            ));
        }

        // Write object data
        try_atp!(crate::fs::write(&object_path, &data).await, |_| {
            AtpError::Disk(DiskError::IoError)
        });

        // Write object metadata
        let metadata_json = try_atp!(serde_json::to_vec_pretty(&object), |_| AtpError::Manifest(
            ManifestError::InvalidFormat
        ));
        try_atp!(
            crate::fs::write(&metadata_path, metadata_json).await,
            |_| AtpError::Disk(DiskError::IoError)
        );

        AtpOutcome::ok(object)
    }

    async fn get_object(&self, _cx: &Cx, hash: &ObjectHash) -> AtpOutcome<Option<Vec<u8>>> {
        let object_path = self.object_path(hash);

        if !object_path.exists() {
            return AtpOutcome::ok(None);
        }

        let data = try_atp!(crate::fs::read(&object_path).await, |_| AtpError::Disk(
            DiskError::IoError
        ));

        // Verify hash matches
        let computed_hash = ObjectHash::from_data(&data);
        if computed_hash != *hash {
            return AtpOutcome::Err(AtpError::Manifest(ManifestError::HashMismatch));
        }

        AtpOutcome::ok(Some(data))
    }

    async fn get_object_info(&self, _cx: &Cx, hash: &ObjectHash) -> AtpOutcome<Option<AtpObject>> {
        let metadata_path = self.metadata_path(hash);

        if !metadata_path.exists() {
            return AtpOutcome::ok(None);
        }

        let metadata_json = try_atp!(crate::fs::read(&metadata_path).await, |_| AtpError::Disk(
            DiskError::IoError
        ));

        let object: AtpObject = try_atp!(serde_json::from_slice(&metadata_json), |_| {
            AtpError::Manifest(ManifestError::InvalidFormat)
        });

        AtpOutcome::ok(Some(object))
    }

    async fn has_object(&self, _cx: &Cx, hash: &ObjectHash) -> AtpOutcome<bool> {
        let object_path = self.object_path(hash);
        AtpOutcome::ok(object_path.exists())
    }

    async fn delete_object(&self, _cx: &Cx, hash: &ObjectHash) -> AtpOutcome<bool> {
        let object_path = self.object_path(hash);
        let metadata_path = self.metadata_path(hash);

        if !object_path.exists() {
            return AtpOutcome::ok(false);
        }

        // Remove both object data and metadata
        let _ = crate::fs::remove_file(&object_path).await;
        let _ = crate::fs::remove_file(&metadata_path).await;

        AtpOutcome::ok(true)
    }

    async fn list_objects(&self, _cx: &Cx) -> AtpOutcome<Vec<ObjectHash>> {
        let mut hashes = Vec::new();

        let mut first_level = match crate::fs::read_dir(&self.base_path).await {
            Ok(read_dir) => read_dir,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return AtpOutcome::ok(hashes);
            }
            Err(_) => return AtpOutcome::Err(AtpError::Disk(DiskError::IoError)),
        };

        while let Some(dir1_entry) = try_atp!(first_level.next_entry().await, |_| {
            AtpError::Disk(DiskError::IoError)
        }) {
            let Some(dir1) = dir1_entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if !Self::is_hash_path_component(&dir1, 2) {
                continue;
            }

            let file_type = try_atp!(dir1_entry.file_type().await, |_| AtpError::Disk(
                DiskError::IoError
            ));
            if !file_type.is_dir() {
                continue;
            }

            let mut second_level = try_atp!(crate::fs::read_dir(dir1_entry.path()).await, |_| {
                AtpError::Disk(DiskError::IoError)
            });

            while let Some(dir2_entry) = try_atp!(second_level.next_entry().await, |_| {
                AtpError::Disk(DiskError::IoError)
            }) {
                let Some(dir2) = dir2_entry.file_name().to_str().map(str::to_owned) else {
                    continue;
                };
                if !Self::is_hash_path_component(&dir2, 2) {
                    continue;
                }

                let file_type = try_atp!(dir2_entry.file_type().await, |_| AtpError::Disk(
                    DiskError::IoError
                ));
                if !file_type.is_dir() {
                    continue;
                }

                let mut object_entries =
                    try_atp!(crate::fs::read_dir(dir2_entry.path()).await, |_| {
                        AtpError::Disk(DiskError::IoError)
                    });

                while let Some(object_entry) = try_atp!(object_entries.next_entry().await, |_| {
                    AtpError::Disk(DiskError::IoError)
                }) {
                    let Some(object_name) = object_entry.file_name().to_str().map(str::to_owned)
                    else {
                        continue;
                    };
                    if std::path::Path::new(&object_name)
                        .extension()
                        .is_some_and(|ext| ext.eq_ignore_ascii_case("meta"))
                        || !Self::is_hash_path_component(&object_name, 60)
                    {
                        continue;
                    }

                    let file_type = try_atp!(object_entry.file_type().await, |_| {
                        AtpError::Disk(DiskError::IoError)
                    });
                    if !file_type.is_file() {
                        continue;
                    }

                    let hash_hex = format!("{dir1}{dir2}{object_name}");
                    if let Ok(hash) = ObjectHash::from_hex(&hash_hex) {
                        hashes.push(hash);
                    }
                }
            }
        }

        hashes.sort();
        hashes.dedup();

        AtpOutcome::ok(hashes)
    }
}

/// Object manifest builder for creating hierarchical object graphs.
#[derive(Debug)]
pub struct ManifestBuilder {
    entries: Vec<ManifestEntry>,
    metadata: ObjectMetadata,
}

impl ManifestBuilder {
    /// Create a new manifest builder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            metadata: ObjectMetadata::new(),
        }
    }

    /// Add an object to the manifest.
    pub fn add_object(
        &mut self,
        hash: ObjectHash,
        path: String,
        size_bytes: u64,
        content_type: String,
        metadata: ObjectMetadata,
    ) {
        self.entries.push(ManifestEntry {
            hash,
            path,
            size_bytes,
            content_type,
            metadata,
        });
    }

    /// Add metadata to the manifest.
    pub fn add_metadata(&mut self, key: String, value: String) {
        self.metadata.insert(key, value);
    }

    /// Build the final manifest.
    pub fn build(self, root_hash: ObjectHash) -> ObjectManifest {
        ObjectManifest {
            version: 1,
            root_hash,
            objects: self.entries,
            metadata: self.metadata,
            created_at_nanos: FileSystemObjectStore::current_time_nanos(),
        }
    }
}

impl Default for ManifestBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_lite::future::block_on;

    #[test]
    fn object_hash_creation() {
        let data = b"hello world";
        let hash = ObjectHash::from_data(data);

        let hex = hash.hex();
        assert_eq!(hex.len(), 64); // SHA-256 is 32 bytes = 64 hex chars

        let parsed_hash = ObjectHash::from_hex(&hex).unwrap();
        assert_eq!(hash, parsed_hash);
    }

    #[test]
    fn object_metadata_operations() {
        let mut metadata = ObjectMetadata::new();
        assert!(metadata.fields.is_empty());

        metadata.insert("key1".to_string(), "value1".to_string());
        metadata.insert("key2".to_string(), "value2".to_string());

        assert_eq!(metadata.get("key1"), Some("value1"));
        assert_eq!(metadata.get("key2"), Some("value2"));
        assert_eq!(metadata.get("key3"), None);

        assert!(metadata.contains_key("key1"));
        assert!(!metadata.contains_key("key3"));

        let removed = metadata.remove("key1");
        assert_eq!(removed, Some("value1".to_string()));
        assert_eq!(metadata.get("key1"), None);
    }

    #[test]
    fn memory_object_store() {
        crate::test_utils::init_test_logging();

        let cx = crate::cx::Cx::for_testing();

        let store = MemoryObjectStore::new();
        let data = b"test data".to_vec();
        let content_type = "text/plain";
        let metadata = ObjectMetadata::with_filename("test.txt");

        block_on(async {
            // Store object
            let object = store
                .store_object(&cx, data.clone(), content_type, metadata)
                .await
                .unwrap();
            assert_eq!(object.size_bytes, data.len() as u64);
            assert_eq!(object.content_type, content_type);

            // Check existence
            let exists = store.has_object(&cx, &object.hash).await.unwrap();
            assert!(exists);

            // Retrieve object
            let retrieved = store.get_object(&cx, &object.hash).await.unwrap();
            assert_eq!(retrieved, Some(data));

            // Get object info
            let info = store.get_object_info(&cx, &object.hash).await.unwrap();
            assert!(info.is_some());
            assert_eq!(info.unwrap().hash, object.hash);

            // Delete object
            let deleted = store.delete_object(&cx, &object.hash).await.unwrap();
            assert!(deleted);

            let exists_after_delete = store.has_object(&cx, &object.hash).await.unwrap();
            assert!(!exists_after_delete);
        });

        crate::test_complete!("memory_object_store");
    }

    #[test]
    fn manifest_builder() {
        let mut builder = ManifestBuilder::new();

        let hash1 = ObjectHash::from_data(b"data1");
        let hash2 = ObjectHash::from_data(b"data2");

        builder.add_object(
            hash1.clone(),
            "file1.txt".to_string(),
            5,
            "text/plain".to_string(),
            ObjectMetadata::with_filename("file1.txt"),
        );

        builder.add_object(
            hash2.clone(),
            "file2.txt".to_string(),
            5,
            "text/plain".to_string(),
            ObjectMetadata::with_filename("file2.txt"),
        );

        builder.add_metadata("description".to_string(), "test manifest".to_string());

        let manifest = builder.build(hash1.clone());

        assert_eq!(manifest.root_hash, hash1);
        assert_eq!(manifest.objects.len(), 2);
        assert_eq!(manifest.version, 1);
        assert_eq!(manifest.metadata.get("description"), Some("test manifest"));
    }

    #[test]
    fn filesystem_object_store() {
        crate::test_utils::init_test_logging();

        use tempfile::tempdir;

        let cx = crate::cx::Cx::for_testing();

        let temp_dir = tempdir().unwrap();
        let store = FileSystemObjectStore::new(temp_dir.path().to_path_buf());
        let data = b"filesystem test data".to_vec();
        let content_type = "application/octet-stream";
        let metadata = ObjectMetadata::with_filename("fstest.bin");

        block_on(async {
            // Store object
            let object = store
                .store_object(&cx, data.clone(), content_type, metadata)
                .await
                .unwrap();

            // Verify file was created
            let object_path = store.object_path(&object.hash);
            assert!(object_path.exists());

            // Retrieve object
            let retrieved = store.get_object(&cx, &object.hash).await.unwrap();
            assert_eq!(retrieved, Some(data));

            // Get object info
            let info = store.get_object_info(&cx, &object.hash).await.unwrap();
            assert!(info.is_some());

            // List objects
            let objects = store.list_objects(&cx).await.unwrap();
            assert!(objects.contains(&object.hash));

            // Delete object
            let deleted = store.delete_object(&cx, &object.hash).await.unwrap();
            assert!(deleted);
            assert!(!object_path.exists());
        });

        crate::test_complete!("filesystem_object_store");
    }
}
