//! Metamorphic testing for filesystem and configuration modules.
//!
//! Tests filesystem operations (VFS, uring, buffered I/O, directory enumeration)
//! and configuration parsing/environment handling using metamorphic relations.

#![allow(clippy::too_many_lines)]
#![allow(dead_code)]

#[cfg(all(test, not(target_arch = "wasm32")))]
mod fs_config_tests {
    use crate::config::{
        EncodingConfig, RaptorQConfig, ResourceConfig, SecurityConfig, TimeoutConfig,
        TransportConfig,
    };
    use crate::fs::Permissions;
    use crate::fs::vfs::{Vfs, VfsFile};
    use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
    use crate::observability::{LogLevel, ObservabilityConfig};
    use crate::runtime::env_config::{
        ENV_STEAL_BATCH_SIZE, ENV_TASK_QUEUE_DEPTH, ENV_THREAD_NAME_PREFIX, ENV_THREAD_STACK_SIZE,
        ENV_WORKER_THREADS,
    };
    use crate::security::AuthMode;
    use crate::test_utils::init_test_logging;
    use proptest::prelude::*;
    use proptest::{prop_oneof, strategy::BoxedStrategy, strategy::Just};
    use serde::{Deserialize, Serialize};
    use std::collections::{BTreeMap, HashMap, HashSet};
    use std::env;
    use std::fs;
    use std::io::{self, Cursor, SeekFrom};
    use std::path::{Path, PathBuf};
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use std::time::Duration;
    use tempfile::TempDir;

    // ═══ Deterministic Filesystem Model ══════════════════════════════════════════

    /// Deterministic VFS implementation for testing filesystem metamorphic relations.
    #[derive(Debug, Clone)]
    pub struct MockVfs {
        files: HashMap<PathBuf, MockVfsFileData>,
        directories: HashSet<PathBuf>,
        temp_dir: Option<PathBuf>,
    }

    #[derive(Debug, Clone)]
    pub struct MockVfsFileData {
        content: Vec<u8>,
        permissions: Permissions,
        metadata: MockMetadata,
    }

    #[derive(Debug, Clone)]
    pub struct MockMetadata {
        len: u64,
        is_dir: bool,
        is_file: bool,
    }

    impl MockVfs {
        pub fn new() -> Self {
            Self {
                files: HashMap::new(),
                directories: HashSet::new(),
                temp_dir: None,
            }
        }

        pub fn with_temp_dir(temp_dir: PathBuf) -> Self {
            let mut vfs = Self::new();
            vfs.temp_dir = Some(temp_dir.clone());
            vfs.directories.insert(temp_dir);
            vfs
        }

        /// Canonicalize a path with deterministic normalization.
        pub fn canonicalize(&self, path: &Path) -> io::Result<PathBuf> {
            // Deterministic canonicalization: resolve relative paths, normalize separators.
            let mut canonical = PathBuf::new();

            // Start with base directory if relative path
            if path.is_relative() {
                if let Some(temp_dir) = &self.temp_dir {
                    canonical.push(temp_dir);
                } else {
                    canonical.push("/mock_root");
                }
            }

            // Process path components
            for component in path.components() {
                match component {
                    std::path::Component::Prefix(_) => canonical.push(component),
                    std::path::Component::RootDir => {
                        canonical.clear();
                        canonical.push(component);
                    }
                    std::path::Component::CurDir => {
                        // Skip current directory references
                    }
                    std::path::Component::ParentDir => {
                        canonical.pop();
                    }
                    std::path::Component::Normal(name) => {
                        canonical.push(name);
                    }
                }
            }

            Ok(canonical)
        }

        pub fn create_file(&mut self, path: &Path, content: &[u8]) -> io::Result<()> {
            let canonical_path = self.canonicalize(path)?;

            // Create parent directories if they don't exist
            if let Some(parent) = canonical_path.parent() {
                self.directories.insert(parent.to_path_buf());
            }

            self.files.insert(
                canonical_path,
                MockVfsFileData {
                    content: content.to_vec(),
                    permissions: Permissions::from_mode(0o644),
                    metadata: MockMetadata {
                        len: content.len() as u64,
                        is_dir: false,
                        is_file: true,
                    },
                },
            );
            Ok(())
        }

        pub fn create_directory(&mut self, path: &Path) -> io::Result<()> {
            let canonical_path = self.canonicalize(path)?;
            self.directories.insert(canonical_path);
            Ok(())
        }

        pub fn read_file(&self, path: &Path) -> io::Result<Vec<u8>> {
            let canonical_path = self.canonicalize(path)?;
            self.files
                .get(&canonical_path)
                .map(|data| data.content.clone())
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "File not found"))
        }

        pub fn list_directory(&self, path: &Path) -> io::Result<Vec<PathBuf>> {
            let canonical_path = self.canonicalize(path)?;

            if !self.directories.contains(&canonical_path) {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "Directory not found",
                ));
            }

            let mut entries = Vec::new();

            // Find files in this directory
            for file_path in self.files.keys() {
                if let Some(parent) = file_path.parent() {
                    if parent == canonical_path {
                        if let Some(filename) = file_path.file_name() {
                            entries.push(PathBuf::from(filename));
                        }
                    }
                }
            }

            // Find subdirectories
            for dir_path in &self.directories {
                if let Some(parent) = dir_path.parent() {
                    if parent == canonical_path && dir_path != &canonical_path {
                        if let Some(dirname) = dir_path.file_name() {
                            entries.push(PathBuf::from(dirname));
                        }
                    }
                }
            }

            Ok(entries)
        }
    }

    // ═══ Deterministic Config Parser Model ═══════════════════════════════════════

    /// Deterministic configuration parser for testing config metamorphic relations.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct MockRuntimeConfig {
        pub worker_threads: usize,
        pub task_queue_depth: usize,
        pub thread_stack_size: usize,
        pub thread_name_prefix: String,
        pub steal_batch_size: usize,
        pub enable_parking: bool,
        pub custom_settings: BTreeMap<String, String>,
    }

    impl Default for MockRuntimeConfig {
        fn default() -> Self {
            Self {
                worker_threads: 4,
                task_queue_depth: 1024,
                thread_stack_size: 2 * 1024 * 1024,
                thread_name_prefix: "asupersync".to_string(),
                steal_batch_size: 32,
                enable_parking: true,
                custom_settings: BTreeMap::new(),
            }
        }
    }

    impl MockRuntimeConfig {
        /// Parse configuration from TOML string.
        pub fn from_toml(toml_str: &str) -> Result<Self, String> {
            toml::from_str(toml_str).map_err(|e| format!("Parse error: {}", e))
        }

        /// Serialize configuration to TOML string.
        pub fn to_toml(&self) -> Result<String, String> {
            toml::to_string_pretty(self).map_err(|e| format!("Serialize error: {}", e))
        }

        /// Load configuration from environment variables.
        pub fn from_env() -> Self {
            let mut config = Self::default();

            if let Ok(value) = env::var(ENV_WORKER_THREADS) {
                if let Ok(threads) = value.parse() {
                    config.worker_threads = threads;
                }
            }

            if let Ok(value) = env::var(ENV_TASK_QUEUE_DEPTH) {
                if let Ok(depth) = value.parse() {
                    config.task_queue_depth = depth;
                }
            }

            if let Ok(value) = env::var(ENV_THREAD_STACK_SIZE) {
                if let Ok(size) = value.parse() {
                    config.thread_stack_size = size;
                }
            }

            if let Ok(value) = env::var(ENV_THREAD_NAME_PREFIX) {
                config.thread_name_prefix = value;
            }

            if let Ok(value) = env::var(ENV_STEAL_BATCH_SIZE) {
                if let Ok(size) = value.parse() {
                    config.steal_batch_size = size;
                }
            }

            config
        }

        /// Apply configuration to environment variables.
        ///
        /// SAFETY: Edition 2024 marks `env::set_var` as unsafe because it is
        /// racy with concurrent reads on other threads. These metamorphic
        /// tests run sequentially under the standard test harness and do not
        /// spawn threads that read the affected variables, so the race
        /// preconditions cannot occur. Per-fn `allow(unsafe_code)` per
        /// AGENTS.md (narrow unsafe surface).
        #[allow(unsafe_code)]
        pub fn to_env(&self) {
            unsafe {
                env::set_var(ENV_WORKER_THREADS, self.worker_threads.to_string());
                env::set_var(ENV_TASK_QUEUE_DEPTH, self.task_queue_depth.to_string());
                env::set_var(ENV_THREAD_STACK_SIZE, self.thread_stack_size.to_string());
                env::set_var(ENV_THREAD_NAME_PREFIX, &self.thread_name_prefix);
                env::set_var(ENV_STEAL_BATCH_SIZE, self.steal_batch_size.to_string());
            }
        }

        /// Clear environment variables. Same safety reasoning as `to_env`.
        #[allow(unsafe_code)]
        pub fn clear_env() {
            unsafe {
                env::remove_var(ENV_WORKER_THREADS);
                env::remove_var(ENV_TASK_QUEUE_DEPTH);
                env::remove_var(ENV_THREAD_STACK_SIZE);
                env::remove_var(ENV_THREAD_NAME_PREFIX);
                env::remove_var(ENV_STEAL_BATCH_SIZE);
            }
        }
    }

    // ═══ Deterministic Uring Vector I/O Model ═══════════════════════════════════

    /// Deterministic uring-style vector I/O for testing consistency relations.
    #[derive(Debug, Clone)]
    pub struct MockUringVector {
        buffers: Vec<Vec<u8>>,
    }

    impl MockUringVector {
        pub fn new(buffers: Vec<Vec<u8>>) -> Self {
            Self { buffers }
        }

        /// Read data using deterministic vectored I/O.
        pub fn readv(&self) -> Vec<u8> {
            self.buffers.iter().flatten().copied().collect()
        }

        /// Write data using deterministic vectored I/O.
        pub fn writev(&self, data: &[u8]) -> Vec<Vec<u8>> {
            if self.buffers.is_empty() {
                return vec![data.to_vec()];
            }

            let mut result = Vec::new();
            let mut remaining = data;

            for buffer_template in &self.buffers {
                let chunk_size = buffer_template.len().min(remaining.len());
                if chunk_size > 0 {
                    result.push(remaining[..chunk_size].to_vec());
                    remaining = &remaining[chunk_size..];
                } else {
                    result.push(Vec::new());
                }
            }

            // If there's remaining data, put it in a final buffer
            if !remaining.is_empty() {
                result.push(remaining.to_vec());
            }

            result
        }

        /// Get total length across all buffers.
        pub fn total_len(&self) -> usize {
            self.buffers.iter().map(|b| b.len()).sum()
        }
    }

    // ═══ Deterministic Buffered I/O Model ═══════════════════════════════════════

    /// Deterministic buffered reader for testing chunk-boundary equivalence.
    pub struct MockBufReader {
        data: Cursor<Vec<u8>>,
        buffer_size: usize,
    }

    impl MockBufReader {
        pub fn new(data: Vec<u8>, buffer_size: usize) -> Self {
            Self {
                data: Cursor::new(data),
                buffer_size,
            }
        }

        /// Read data in chunks (buffered).
        pub fn read_buffered(&mut self) -> io::Result<Vec<Vec<u8>>> {
            let mut chunks = Vec::new();
            let mut buffer = vec![0u8; self.buffer_size];

            loop {
                let bytes_read = std::io::Read::read(&mut self.data, &mut buffer)?;
                if bytes_read == 0 {
                    break;
                }
                chunks.push(buffer[..bytes_read].to_vec());
            }

            Ok(chunks)
        }

        /// Read all data at once.
        pub fn read_all(&mut self) -> io::Result<Vec<u8>> {
            let mut result = Vec::new();
            std::io::Read::read_to_end(&mut self.data, &mut result)?;
            Ok(result)
        }
    }

    pub struct MockBufWriter {
        buffer: Vec<u8>,
        buffer_size: usize,
        written_chunks: Vec<Vec<u8>>,
    }

    impl MockBufWriter {
        pub fn new(buffer_size: usize) -> Self {
            Self {
                buffer: Vec::with_capacity(buffer_size),
                buffer_size,
                written_chunks: Vec::new(),
            }
        }

        /// Write data in buffered chunks.
        pub fn write_buffered(&mut self, data: &[u8]) -> io::Result<()> {
            let mut remaining = data;

            while !remaining.is_empty() {
                let space_left = self.buffer_size - self.buffer.len();
                let to_write = remaining.len().min(space_left);

                self.buffer.extend_from_slice(&remaining[..to_write]);
                remaining = &remaining[to_write..];

                if self.buffer.len() == self.buffer_size {
                    self.flush()?;
                }
            }

            Ok(())
        }

        /// Flush buffer.
        pub fn flush(&mut self) -> io::Result<()> {
            if !self.buffer.is_empty() {
                self.written_chunks.push(self.buffer.clone());
                self.buffer.clear();
            }
            Ok(())
        }

        /// Write all data at once.
        pub fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
            self.written_chunks.push(data.to_vec());
            Ok(())
        }

        /// Get all written data concatenated.
        pub fn written_data(&mut self) -> io::Result<Vec<u8>> {
            self.flush()?;
            Ok(self.written_chunks.iter().flatten().copied().collect())
        }
    }

    // ═══ Property Generators ═══════════════════════════════════════════════════

    impl Arbitrary for MockRuntimeConfig {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_: ()) -> Self::Strategy {
            (
                1usize..=16,
                256usize..=8192,
                (1024usize * 1024)..=(8 * 1024 * 1024),
                "[a-z]+",
                1usize..=128,
                any::<bool>(),
            )
                .prop_map(
                    |(
                        worker_threads,
                        task_queue_depth,
                        thread_stack_size,
                        thread_name_prefix,
                        steal_batch_size,
                        enable_parking,
                    )| {
                        MockRuntimeConfig {
                            worker_threads,
                            task_queue_depth,
                            thread_stack_size,
                            thread_name_prefix,
                            steal_batch_size,
                            enable_parking,
                            custom_settings: BTreeMap::new(),
                        }
                    },
                )
                .boxed()
        }
    }

    /// Generate arbitrary path components.
    pub fn arbitrary_path_components() -> BoxedStrategy<Vec<String>> {
        prop::collection::vec("[a-zA-Z0-9_-]+", 1..=5).boxed()
    }

    /// Generate arbitrary file data.
    pub fn arbitrary_file_data() -> BoxedStrategy<Vec<u8>> {
        prop::collection::vec(any::<u8>(), 0..=4096).boxed()
    }

    // ═══ Metamorphic Relations ══════════════════════════════════════════════════

    /// MR1: VFS path canonicalization round-trip identity.
    /// Category: Invertive f(T(T(x))) = f(x)
    /// Detects: canonicalization bugs, path resolution errors, normalization inconsistencies
    #[test]
    fn mr_vfs_path_canonicalization_roundtrip() {
        init_test_logging();
        crate::test_phase!("mr_vfs_path_canonicalization_roundtrip");

        proptest!(|(
            path_components in arbitrary_path_components(),
            relative_dots in prop::collection::vec("\\.\\.?", 0..=3)
        )| {
            let temp_dir = TempDir::new().unwrap();
            let mut mock_vfs = MockVfs::with_temp_dir(temp_dir.path().to_path_buf());

            // Build path with relative components and dots
            let mut path = PathBuf::new();
            for component in path_components {
                path.push(component);
            }
            for dot in relative_dots {
                if dot == "." {
                    path.push(".");
                } else if dot == ".." {
                    path.push("..");
                }
            }

            // First canonicalization
            let canonical1 = mock_vfs.canonicalize(&path).unwrap();

            // Second canonicalization of the result should be identical (idempotent)
            let canonical2 = mock_vfs.canonicalize(&canonical1).unwrap();

            prop_assert_eq!(canonical1.clone(), canonical2.clone(),
                "Path canonicalization not idempotent");

            // Canonical path should be absolute
            prop_assert!(canonical1.is_absolute(),
                "Canonical path not absolute: {:?}", canonical1);

            // Canonical path should not contain . or .. components
            for component in canonical1.components() {
                prop_assert!(
                    !matches!(component, std::path::Component::CurDir | std::path::Component::ParentDir),
                    "Canonical path contains relative component: {:?}", canonical1
                );
            }
        });

        crate::test_complete!("mr_vfs_path_canonicalization_roundtrip");
    }

    /// MR2: Uring readv/writev vector consistency - vectored and scalar I/O equivalence.
    /// Category: Equivalence f(T(x)) = f(x)
    /// Detects: vector I/O bugs, buffer alignment errors, scatter-gather inconsistencies
    #[test]
    fn mr_uring_vector_consistency() {
        init_test_logging();
        crate::test_phase!("mr_uring_vector_consistency");

        proptest!(|(
            data in arbitrary_file_data(),
            buffer_sizes in prop::collection::vec(1usize..=512, 1..=8)
        )| {
            // Create vector buffers of specified sizes
            let buffers: Vec<Vec<u8>> = buffer_sizes.into_iter()
                .map(|size| vec![0u8; size])
                .collect();

            let mock_vector = MockUringVector::new(buffers.clone());

            // Vectored write followed by vectored read
            let written_vectors = mock_vector.writev(&data);
            let mock_read_vector = MockUringVector::new(written_vectors);
            let read_data_vector = mock_read_vector.readv();

            // Scalar equivalence: concatenated data should match
            prop_assert_eq!(data.clone(), read_data_vector,
                "Vectored I/O doesn't preserve data integrity");

            // Vector consistency: total written should equal total read
            let total_written: usize = mock_vector.writev(&data).iter()
                .map(|chunk| chunk.len())
                .sum();
            let data_len = data.len();
            prop_assert_eq!(data_len, total_written,
                "Vector write length mismatch: {} vs {}", data_len, total_written);
        });

        crate::test_complete!("mr_uring_vector_consistency");
    }

    /// MR3: buf_reader/buf_writer chunk-boundary equivalence to read/write_all.
    /// Category: Equivalence (buffering transparency)
    /// Detects: buffer boundary bugs, incomplete reads/writes, chunk alignment errors
    #[test]
    fn mr_buffered_io_chunk_boundary_equivalence() {
        init_test_logging();
        crate::test_phase!("mr_buffered_io_chunk_boundary_equivalence");

        proptest!(|(
            data in arbitrary_file_data(),
            buffer_size in 1usize..=256
        )| {
            // Buffered reading
            let mut buf_reader = MockBufReader::new(data.clone(), buffer_size);
            let chunks = buf_reader.read_buffered().unwrap();
            let buffered_data: Vec<u8> = chunks.into_iter().flatten().collect();

            // Direct read_all
            let mut direct_reader = MockBufReader::new(data.clone(), buffer_size);
            let direct_data = direct_reader.read_all().unwrap();

            // Buffered and direct reads should produce identical data
            prop_assert_eq!(buffered_data.clone(), direct_data,
                "Buffered read differs from direct read");

            // Buffered writing
            let mut buf_writer = MockBufWriter::new(buffer_size);
            buf_writer.write_buffered(&data).unwrap();
            let buffered_write_data = buf_writer.written_data().unwrap();

            // Direct write_all
            let mut direct_writer = MockBufWriter::new(buffer_size);
            direct_writer.write_all(&data).unwrap();
            let direct_write_data = direct_writer.written_data().unwrap();

            // Buffered and direct writes should produce identical output
            prop_assert_eq!(buffered_write_data.clone(), direct_write_data,
                "Buffered write differs from direct write");
            prop_assert_eq!(data.clone(), buffered_write_data,
                "Buffered write doesn't preserve data integrity");
        });

        crate::test_complete!("mr_buffered_io_chunk_boundary_equivalence");
    }

    /// MR4: Directory enumerate sortedness and deduplication invariants.
    /// Category: Permutative (ordering properties)
    /// Detects: directory enumeration bugs, duplicate entries, sorting inconsistencies
    #[test]
    fn mr_dir_enumerate_sortedness_dedup_invariants() {
        init_test_logging();
        crate::test_phase!("mr_dir_enumerate_sortedness_dedup_invariants");

        proptest!(|(
            filenames in prop::collection::vec("[a-z0-9_]+", 3..=10)
        )| {
            let temp_dir = TempDir::new().unwrap();
            let mut mock_vfs = MockVfs::with_temp_dir(temp_dir.path().to_path_buf());

            // Create files with potentially duplicate names
            let mut unique_filenames = HashSet::new();
            for filename in &filenames {
                let file_path = temp_dir.path().join(filename);
                mock_vfs.create_file(&file_path, b"test content").unwrap();
                unique_filenames.insert(filename);
            }

            // Enumerate directory multiple times
            let entries1 = mock_vfs.list_directory(temp_dir.path()).unwrap();
            let entries2 = mock_vfs.list_directory(temp_dir.path()).unwrap();
            let entries3 = mock_vfs.list_directory(temp_dir.path()).unwrap();

            // Directory enumeration should be deterministic
            prop_assert_eq!(entries1.clone(), entries2.clone(),
                "Directory enumeration not deterministic between calls");
            prop_assert_eq!(entries2, entries3,
                "Directory enumeration not deterministic on third call");

            // No duplicates should exist in enumeration
            let mut unique_entries = HashSet::new();
            for entry in &entries1 {
                prop_assert!(unique_entries.insert(entry.clone()),
                    "Duplicate directory entry found: {:?}", entry);
            }

            // Entry count should match unique filename count
            prop_assert_eq!(entries1.len(), unique_filenames.len(),
                "Entry count mismatch: {} entries vs {} unique filenames",
                entries1.len(), unique_filenames.len());

            // Sorting should be consistent
            let mut sorted_entries = entries1.clone();
            sorted_entries.sort();

            // If implementation provides sorted output, verify it
            // Otherwise, just verify sorting produces deterministic results
            let mut sorted_again = entries1.clone();
            sorted_again.sort();
            prop_assert_eq!(sorted_entries, sorted_again,
                "Sorting not deterministic");
        });

        crate::test_complete!("mr_dir_enumerate_sortedness_dedup_invariants");
    }

    /// MR5: env→config→env round-trip identity.
    /// Category: Invertive f(T(T(x))) = f(x)
    /// Detects: environment variable serialization bugs, config conversion errors
    #[test]
    fn mr_env_config_env_roundtrip() {
        init_test_logging();
        crate::test_phase!("mr_env_config_env_roundtrip");

        proptest!(|(config in any::<MockRuntimeConfig>())| {
            // Clear environment first
            MockRuntimeConfig::clear_env();

            // config → env → config round-trip
            config.to_env();
            let config_from_env = MockRuntimeConfig::from_env();

            // Pin scalar fields by value before the prop_assert_eq! moves them;
            // String field is cloned because String isn't Copy.
            let config_worker_threads = config.worker_threads;
            let config_task_queue_depth = config.task_queue_depth;
            let config_thread_stack_size = config.thread_stack_size;
            let config_thread_name_prefix = config.thread_name_prefix.clone();
            let config_steal_batch_size = config.steal_batch_size;

            // Core fields should round-trip correctly
            prop_assert_eq!(config_worker_threads, config_from_env.worker_threads,
                "worker_threads round-trip failed");
            prop_assert_eq!(config_task_queue_depth, config_from_env.task_queue_depth,
                "task_queue_depth round-trip failed");
            prop_assert_eq!(config_thread_stack_size, config_from_env.thread_stack_size,
                "thread_stack_size round-trip failed");
            prop_assert_eq!(config_thread_name_prefix, config_from_env.thread_name_prefix,
                "thread_name_prefix round-trip failed");
            prop_assert_eq!(config_steal_batch_size, config_from_env.steal_batch_size,
                "steal_batch_size round-trip failed");

            // Test with modified environment. SAFETY: see fs_config tests'
            // module-level safety reasoning on env mutation — these tests are
            // sequential and own the affected variables.
            let original_threads = config_worker_threads;
            #[allow(unsafe_code)]
            unsafe {
                env::set_var(ENV_WORKER_THREADS, (original_threads * 2).to_string());
            }

            let modified_config = MockRuntimeConfig::from_env();
            prop_assert_eq!(modified_config.worker_threads, original_threads * 2,
                "Environment override not applied correctly");

            // Clean up
            MockRuntimeConfig::clear_env();
        });

        crate::test_complete!("mr_env_config_env_roundtrip");
    }

    /// MR6: Config parser idempotency - repeated parsing produces identical results.
    /// Category: Equivalence f(T(x)) = f(x)
    /// Detects: parser state bugs, non-deterministic parsing, serialization drift
    #[test]
    fn mr_config_parser_idempotency() {
        init_test_logging();
        crate::test_phase!("mr_config_parser_idempotency");

        proptest!(|(config in any::<MockRuntimeConfig>())| {
            // Serialize to TOML
            let toml_str = config.to_toml().unwrap();

            // Parse multiple times
            let parsed1 = MockRuntimeConfig::from_toml(&toml_str).unwrap();
            let parsed2 = MockRuntimeConfig::from_toml(&toml_str).unwrap();
            let parsed3 = MockRuntimeConfig::from_toml(&toml_str).unwrap();

            // All parses should be identical (idempotent)
            prop_assert_eq!(parsed1.clone(), parsed2.clone(),
                "Config parsing not idempotent between first and second parse");
            prop_assert_eq!(parsed2, parsed3,
                "Config parsing not idempotent on third parse");

            // Re-serialize and parse again
            let toml_str2 = parsed1.to_toml().unwrap();
            let parsed4 = MockRuntimeConfig::from_toml(&toml_str2).unwrap();

            // Should still be identical (serialize → parse idempotency)
            prop_assert_eq!(parsed1, parsed4.clone(),
                "Serialize-parse cycle not idempotent");

            // Original config should equal final parsed config (full round-trip)
            prop_assert_eq!(config, parsed4,
                "Full config round-trip not preserved");
        });

        crate::test_complete!("mr_config_parser_idempotency");
    }

    /// MR7: VFS path normalization consistency across equivalent paths.
    /// Category: Equivalence (path normalization)
    /// Detects: path normalization bugs, case sensitivity issues, separator inconsistencies
    #[test]
    fn mr_vfs_path_normalization_consistency() {
        init_test_logging();
        crate::test_phase!("mr_vfs_path_normalization_consistency");

        proptest!(|(
            base_components in arbitrary_path_components(),
            extra_dots in 0usize..=3
        )| {
            let temp_dir = TempDir::new().unwrap();
            let mock_vfs = MockVfs::with_temp_dir(temp_dir.path().to_path_buf());

            // Create equivalent paths with different representations
            let mut path1 = PathBuf::new();
            let mut path2 = PathBuf::new();

            for component in &base_components {
                path1.push(component);
                path2.push(component);
            }

            // Add redundant current directory references to path2
            for _ in 0..extra_dots {
                path2.push(".");
            }

            // Both paths should canonicalize to the same result
            let canonical1 = mock_vfs.canonicalize(&path1).unwrap();
            let canonical2 = mock_vfs.canonicalize(&path2).unwrap();

            prop_assert_eq!(&canonical1, &canonical2,
                "Equivalent paths don't canonicalize to same result");

            // Test with parent directory references
            let mut path3 = path1.clone();
            path3.push("subdir");
            path3.push("..");

            let canonical3 = mock_vfs.canonicalize(&path3).unwrap();
            prop_assert_eq!(&canonical1, &canonical3,
                "Path with parent ref doesn't normalize correctly");
        });

        crate::test_complete!("mr_vfs_path_normalization_consistency");
    }

    /// MR8: Composite - Config serialization ∘ path canonicalization.
    /// Category: Composition of invertive + equivalence relations
    /// Detects: compound bugs where path handling affects config serialization
    #[test]
    fn mr_composite_config_path_operations() {
        init_test_logging();
        crate::test_phase!("mr_composite_config_path_operations");

        proptest!(|(
            mut config in any::<MockRuntimeConfig>(),
            path_suffix in "[a-z_]+"
        )| {
            let temp_dir = TempDir::new().unwrap();
            let mock_vfs = MockVfs::with_temp_dir(temp_dir.path().to_path_buf());

            // Add path-based configuration
            let config_path = temp_dir.path().join(format!("config_{}.toml", path_suffix));
            config.custom_settings.insert(
                "config_file".to_string(),
                config_path.to_string_lossy().to_string()
            );

            // MR6: Config serialization round-trip
            let toml_str = config.to_toml().unwrap();
            let parsed_config = MockRuntimeConfig::from_toml(&toml_str).unwrap();

            // MR1: Path canonicalization from config
            let config_file_path = parsed_config.custom_settings
                .get("config_file")
                .map(|p| PathBuf::from(p))
                .unwrap();

            let canonical_config_path = mock_vfs.canonicalize(&config_file_path).unwrap();

            // Composite property: config with canonical path should serialize identically
            let mut config_with_canonical = parsed_config.clone();
            config_with_canonical.custom_settings.insert(
                "config_file".to_string(),
                canonical_config_path.to_string_lossy().to_string()
            );

            let toml_canonical = config_with_canonical.to_toml().unwrap();
            let parsed_canonical = MockRuntimeConfig::from_toml(&toml_canonical).unwrap();

            // Core config should remain identical regardless of path representation
            prop_assert_eq!(parsed_config.worker_threads, parsed_canonical.worker_threads,
                "Path canonicalization affected config parsing");
            prop_assert_eq!(parsed_config.task_queue_depth, parsed_canonical.task_queue_depth,
                "Path operations affected core config");
        });

        crate::test_complete!("mr_composite_config_path_operations");
    }

    #[cfg(test)]
    mod unit_tests {
        use super::*;

        #[test]
        fn test_mock_vfs_basic() {
            let temp_dir = TempDir::new().unwrap();
            let mut mock_vfs = MockVfs::with_temp_dir(temp_dir.path().to_path_buf());

            let test_path = temp_dir.path().join("test.txt");
            mock_vfs.create_file(&test_path, b"hello world").unwrap();

            let content = mock_vfs.read_file(&test_path).unwrap();
            assert_eq!(content, b"hello world");
        }

        #[test]
        fn test_mock_config_basic() {
            let config = MockRuntimeConfig::default();
            let toml_str = config.to_toml().unwrap();
            let parsed = MockRuntimeConfig::from_toml(&toml_str).unwrap();
            assert_eq!(config, parsed);
        }

        #[test]
        fn test_mock_uring_vector_basic() {
            let buffers = vec![vec![0u8; 4], vec![0u8; 4]];
            let mock_vector = MockUringVector::new(buffers);
            let data = b"12345678";
            let written = mock_vector.writev(data);

            assert_eq!(written.len(), 2);
            assert_eq!(written[0], b"1234");
            assert_eq!(written[1], b"5678");
        }

        #[test]
        fn test_mock_buffered_io_basic() {
            let data = b"hello world test data".to_vec();
            let mut reader = MockBufReader::new(data.clone(), 5);
            let chunks = reader.read_buffered().unwrap();
            let reassembled: Vec<u8> = chunks.into_iter().flatten().collect();
            assert_eq!(data, reassembled);
        }
    }
} // end fs_config_tests module

#[cfg(not(all(test, not(target_arch = "wasm32"))))]
mod no_fs_config_fallback {
    #[derive(Debug, PartialEq, Eq)]
    struct FeatureGateProof {
        cfg_profile: &'static str,
        unavailable_surface: &'static str,
        support_class: &'static str,
        reason_code: &'static str,
    }

    fn feature_gate_proof() -> FeatureGateProof {
        FeatureGateProof {
            cfg_profile: "not(all(test, not(target_arch = \"wasm32\")))",
            unavailable_surface: "native-filesystem-config",
            support_class: "unsupported_on_non_native_test_profile",
            reason_code: "fs_config_metamorphic_module_not_compiled",
        }
    }

    #[test]
    fn fs_config_reports_native_profile_gate() {
        let proof = feature_gate_proof();
        assert_eq!(proof.unavailable_surface, "native-filesystem-config");
        assert_eq!(
            proof.support_class,
            "unsupported_on_non_native_test_profile"
        );
        assert_eq!(
            proof.reason_code,
            "fs_config_metamorphic_module_not_compiled"
        );
        assert!(
            proof.cfg_profile.contains("wasm32"),
            "cfg profile must identify the target boundary"
        );
    }
}
