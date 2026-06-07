//! Platform Capability Detection for Filesystem Features

#[cfg(target_os = "linux")]
use std::ffi::CString;
#[cfg(target_os = "linux")]
use std::mem::MaybeUninit;

use crate::cx::Cx;
use crate::types::outcome::Outcome;
use std::collections::HashMap;
use std::io::{ErrorKind, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::{
    OnceLock,
    atomic::{AtomicU64, Ordering},
};

/// Static operation costs to avoid repeated HashMap allocation
static OPERATION_COSTS: OnceLock<HashMap<&'static str, u32>> = OnceLock::new();
static PROBE_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Get operation costs HashMap (initialized once)
fn get_operation_costs() -> &'static HashMap<&'static str, u32> {
    OPERATION_COSTS.get_or_init(|| {
        let mut costs = HashMap::new();
        costs.insert("prealloc", 10);
        costs.insert("write", 1);
        costs.insert("sync", 50);
        costs.insert("rename", 5);
        costs
    })
}

/// Filesystem type constants to avoid allocations
const FS_TYPE_APFS: &str = "apfs";
const FS_TYPE_NTFS: &str = "ntfs";
#[allow(dead_code)] // used on linux + the non-(linux/macos/windows) fallback
const FS_TYPE_UNKNOWN: &str = "unknown";
const FS_TYPE_EXT4: &str = "ext4";
const FS_TYPE_EXT3: &str = "ext3";
const FS_TYPE_EXT2: &str = "ext2";
const FS_TYPE_BTRFS: &str = "btrfs";
const FS_TYPE_XFS: &str = "xfs";
const FS_TYPE_ZFS: &str = "zfs";
const FS_TYPE_TMPFS: &str = "tmpfs";
#[allow(dead_code)] // linux-only (used in detect_linux_filesystem_type)
const FS_TYPE_MINIX: &str = "minix";
#[allow(dead_code)] // linux-only (used in detect_linux_filesystem_type)
const FS_TYPE_MSDOS: &str = "msdos";
#[allow(dead_code)] // linux-only (used in detect_linux_filesystem_type)
const FS_TYPE_REISERFS: &str = "reiserfs";
const FS_TYPE_NFS: &str = "nfs";

/// System call names to avoid allocations
#[allow(dead_code)] // linux-only (used in detect_linux_filesystem_type)
const SYSCALL_STATFS: &str = "statfs";

/// Detected platform capabilities for filesystem operations
#[derive(Debug, Clone)]
pub struct PlatformCapabilities {
    /// Operating system type
    pub os_type: OsType,
    /// Filesystem-specific features
    pub filesystem: FilesystemFeatures,
    /// I/O capabilities
    pub io_capabilities: IoCapabilities,
    /// Atomic operation support
    pub atomic_operations: AtomicSupport,
    /// Performance characteristics
    pub performance_hints: PerformanceHints,
}

/// Operating system classification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OsType {
    Linux,
    MacOS,
    Windows,
    FreeBSD,
    Other(u8), // For extensibility
}

/// Filesystem feature detection
#[derive(Debug, Clone)]
pub struct FilesystemFeatures {
    /// Filesystem type (ext4, NTFS, APFS, etc.)
    pub fs_type: String,
    /// Supports fallocate() or equivalent
    pub supports_preallocation: bool,
    /// Supports atomic rename operations
    pub supports_atomic_rename: bool,
    /// Supports hard links
    pub supports_hard_links: bool,
    /// Supports sparse files
    pub supports_sparse_files: bool,
    /// Supports hole punching
    pub supports_hole_punching: bool,
    /// Maximum file size supported
    pub max_file_size: Option<u64>,
    /// Optimal block size for I/O
    pub block_size: u32,
    /// Whether filesystem supports copy-on-write
    pub supports_cow: bool,
    /// Whether filesystem supports reflinks
    pub supports_reflinks: bool,
}

/// I/O operation capabilities
#[derive(Debug, Clone)]
pub struct IoCapabilities {
    /// Direct I/O support
    pub supports_direct_io: bool,
    /// Async I/O support level
    pub async_io_support: AsyncIoSupport,
    /// Maximum I/O request size
    pub max_io_size: usize,
    /// Optimal I/O alignment
    pub io_alignment: usize,
    /// Vectored I/O support
    pub supports_vectored_io: bool,
}

/// Atomic operation support detection
#[derive(Debug, Clone)]
pub struct AtomicSupport {
    /// Atomic rename within filesystem
    pub atomic_rename_same_fs: bool,
    /// Atomic rename across filesystems
    pub atomic_rename_cross_fs: bool,
    /// Link/unlink atomicity
    pub atomic_link_unlink: bool,
    /// Directory sync support
    pub supports_dir_sync: bool,
    /// Crash-consistent rename
    pub crash_consistent_rename: bool,
}

/// Performance characteristics and hints
#[derive(Debug, Clone)]
pub struct PerformanceHints {
    /// Recommended preallocation size
    pub recommended_prealloc_size: u64,
    /// Recommended write batch size
    pub recommended_write_batch: u64,
    /// Whether sequential access is preferred
    pub prefers_sequential_access: bool,
    /// Cost estimate for various operations
    pub operation_costs: HashMap<&'static str, u32>,
    /// Expected latency characteristics
    pub latency_profile: LatencyProfile,
}

/// I/O latency characteristics
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LatencyProfile {
    /// Low latency storage (SSD, NVMe)
    LowLatency,
    /// Medium latency (SATA SSD)
    MediumLatency,
    /// High latency (HDD)
    HighLatency,
    /// Network storage
    NetworkLatency,
    /// Unknown characteristics
    Unknown,
}

/// Async I/O support levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AsyncIoSupport {
    /// No async I/O support
    None,
    /// Basic async I/O (thread pool)
    Basic,
    /// Native async I/O (epoll/kqueue)
    Native,
    /// Advanced async I/O (io_uring)
    Advanced,
}

impl PlatformCapabilities {
    /// Detect platform capabilities for the given path
    pub async fn detect(cx: &Cx) -> Outcome<Self, CapabilityError> {
        Self::detect_for_path(cx, ".").await
    }

    /// Detect capabilities for a specific filesystem path
    pub async fn detect_for_path(
        _cx: &Cx,
        path: impl AsRef<Path>,
    ) -> Outcome<Self, CapabilityError> {
        let path = path.as_ref();

        // Detect OS type
        let os_type = Self::detect_os_type();

        // Detect filesystem features
        let filesystem = match Self::detect_filesystem_features(path).await {
            Outcome::Ok(fs) => fs,
            Outcome::Err(e) => return Outcome::Err(e),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        };

        // Detect I/O capabilities
        let io_capabilities = match Self::detect_io_capabilities(&os_type, &filesystem).await {
            Outcome::Ok(io) => io,
            Outcome::Err(e) => return Outcome::Err(e),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        };

        // Detect atomic operation support
        let atomic_operations = match Self::detect_atomic_support(path, &os_type).await {
            Outcome::Ok(atomic) => atomic,
            Outcome::Err(e) => return Outcome::Err(e),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        };

        // Generate performance hints
        let performance_hints =
            Self::generate_performance_hints(&os_type, &filesystem, &io_capabilities);

        Outcome::Ok(Self {
            os_type,
            filesystem,
            io_capabilities,
            atomic_operations,
            performance_hints,
        })
    }

    /// Detect operating system type
    fn detect_os_type() -> OsType {
        #[cfg(target_os = "linux")]
        return OsType::Linux;

        #[cfg(target_os = "macos")]
        return OsType::MacOS;

        #[cfg(target_os = "windows")]
        return OsType::Windows;

        #[cfg(target_os = "freebsd")]
        return OsType::FreeBSD;

        #[cfg(not(any(
            target_os = "linux",
            target_os = "macos",
            target_os = "windows",
            target_os = "freebsd"
        )))]
        return OsType::Other(0);
    }

    /// Detect filesystem-specific features
    async fn detect_filesystem_features(
        path: &Path,
    ) -> Outcome<FilesystemFeatures, CapabilityError> {
        // Get filesystem statistics
        let fs_type = match Self::detect_filesystem_type(path) {
            Outcome::Ok(fs_type) => fs_type,
            Outcome::Err(e) => return Outcome::Err(e),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        };
        let block_size = match Self::detect_block_size(path) {
            Outcome::Ok(block_size) => block_size,
            Outcome::Err(e) => return Outcome::Err(e),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        };

        // Test capabilities by attempting operations
        let supports_preallocation = Self::test_preallocation_support(path).await;
        let supports_atomic_rename = Self::test_atomic_rename_support(path).await;
        let supports_hard_links = Self::test_hard_link_support(path).await;
        let supports_sparse_files = Self::test_sparse_file_support(path).await;
        let supports_hole_punching = Self::test_hole_punching_support(path).await;
        let supports_cow = Self::test_cow_support(path).await;
        let supports_reflinks = Self::test_reflink_support(path).await;

        let max_file_size = Self::detect_max_file_size(&fs_type);

        Outcome::Ok(FilesystemFeatures {
            fs_type,
            supports_preallocation,
            supports_atomic_rename,
            supports_hard_links,
            supports_sparse_files,
            supports_hole_punching,
            max_file_size,
            block_size,
            supports_cow,
            supports_reflinks,
        })
    }

    /// Detect I/O capabilities
    async fn detect_io_capabilities(
        os_type: &OsType,
        filesystem: &FilesystemFeatures,
    ) -> Outcome<IoCapabilities, CapabilityError> {
        let supports_direct_io = match os_type {
            OsType::Linux => true,
            OsType::FreeBSD => true,
            OsType::MacOS => false, // Limited support
            OsType::Windows => true,
            OsType::Other(_) => false,
        };

        let async_io_support = Self::detect_async_io_support(os_type);
        let max_io_size = Self::detect_max_io_size(os_type, filesystem);
        let io_alignment = filesystem.block_size as usize;
        let supports_vectored_io = true; // Most platforms support this

        Outcome::Ok(IoCapabilities {
            supports_direct_io,
            async_io_support,
            max_io_size,
            io_alignment,
            supports_vectored_io,
        })
    }

    /// Detect atomic operation support
    async fn detect_atomic_support(
        _path: &Path,
        os_type: &OsType,
    ) -> Outcome<AtomicSupport, CapabilityError> {
        let atomic_rename_same_fs = true; // POSIX guarantee
        let atomic_rename_cross_fs = false; // Generally not atomic

        let atomic_link_unlink = match os_type {
            OsType::Linux | OsType::FreeBSD | OsType::MacOS => true,
            OsType::Windows => false, // Different semantics
            OsType::Other(_) => false,
        };

        let supports_dir_sync = match os_type {
            OsType::Linux | OsType::FreeBSD => true,
            OsType::MacOS => true,
            OsType::Windows => false,
            OsType::Other(_) => false,
        };

        let crash_consistent_rename = supports_dir_sync;

        Outcome::Ok(AtomicSupport {
            atomic_rename_same_fs,
            atomic_rename_cross_fs,
            atomic_link_unlink,
            supports_dir_sync,
            crash_consistent_rename,
        })
    }

    /// Generate performance hints based on detected capabilities
    fn generate_performance_hints(
        _os_type: &OsType,
        filesystem: &FilesystemFeatures,
        _io_capabilities: &IoCapabilities,
    ) -> PerformanceHints {
        let recommended_prealloc_size = match filesystem.fs_type.as_str() {
            FS_TYPE_EXT4 | FS_TYPE_EXT3 | FS_TYPE_EXT2 | FS_TYPE_XFS => 64 * 1024 * 1024, // 64MB
            FS_TYPE_BTRFS | FS_TYPE_ZFS => 32 * 1024 * 1024,                              // 32MB
            FS_TYPE_NTFS => 16 * 1024 * 1024,                                             // 16MB
            FS_TYPE_APFS => 32 * 1024 * 1024,                                             // 32MB
            _ => 16 * 1024 * 1024, // 16MB default
        };

        let recommended_write_batch = filesystem.block_size as u64 * 32;

        let prefers_sequential_access = match filesystem.fs_type.as_str() {
            FS_TYPE_EXT4 | FS_TYPE_EXT3 | FS_TYPE_EXT2 | FS_TYPE_XFS | FS_TYPE_NTFS => true,
            FS_TYPE_BTRFS | FS_TYPE_ZFS | FS_TYPE_APFS => false, // COW filesystems
            _ => true,
        };

        let operation_costs = get_operation_costs().clone();

        let latency_profile = Self::detect_latency_profile(&filesystem.fs_type);

        PerformanceHints {
            recommended_prealloc_size,
            recommended_write_batch,
            prefers_sequential_access,
            operation_costs,
            latency_profile,
        }
    }

    // Helper methods for capability testing

    fn unique_probe_path(directory: &Path, label: &str) -> std::path::PathBuf {
        let sequence = PROBE_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        directory.join(format!(
            ".atp_{label}_probe_{}_{}",
            std::process::id(),
            sequence
        ))
    }

    fn create_unique_probe_file(
        directory: &Path,
        label: &str,
    ) -> Option<(std::path::PathBuf, std::fs::File)> {
        for _ in 0..8 {
            let path = Self::unique_probe_path(directory, label);
            match std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(file) => return Some((path, file)),
                Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
                Err(_) => return None,
            }
        }

        None
    }

    fn detect_filesystem_type(path: &Path) -> Outcome<String, CapabilityError> {
        // Platform-specific filesystem detection
        #[cfg(target_os = "linux")]
        {
            Self::detect_linux_filesystem_type(path)
        }

        #[cfg(target_os = "macos")]
        {
            Outcome::Ok(FS_TYPE_APFS.to_string()) // Assume APFS on modern macOS
        }

        #[cfg(target_os = "windows")]
        {
            let _ = path;
            Outcome::Ok(FS_TYPE_NTFS.to_string()) // Assume NTFS on Windows
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            let _ = path;
            Outcome::Ok(FS_TYPE_UNKNOWN.to_string())
        }
    }

    #[cfg(target_os = "linux")]
    #[allow(unsafe_code)]
    fn detect_linux_filesystem_type(path: &Path) -> Outcome<String, CapabilityError> {
        let path_cstr = match CString::new(path.to_string_lossy().as_bytes()) {
            Ok(path) => path,
            Err(_) => return Outcome::Err(CapabilityError::InvalidPath),
        };

        let mut statfs_buf: MaybeUninit<libc::statfs> = MaybeUninit::uninit();

        unsafe {
            if libc::statfs(path_cstr.as_ptr(), statfs_buf.as_mut_ptr()) != 0 {
                return Outcome::Err(CapabilityError::SystemCall(SYSCALL_STATFS.to_string()));
            }

            let statfs = statfs_buf.assume_init();
            let fs_type = match statfs.f_type as u64 {
                0xEF53 => FS_TYPE_EXT4,         // EXT2/3/4
                0x58465342 => FS_TYPE_XFS,      // XFS
                0x9123683E => FS_TYPE_BTRFS,    // BTRFS
                0x6969 => FS_TYPE_NFS,          // NFS
                0x01021994 => FS_TYPE_TMPFS,    // TMPFS
                0x137F => FS_TYPE_MINIX,        // MINIX
                0x4d44 => FS_TYPE_MSDOS,        // FAT
                0x52654973 => FS_TYPE_REISERFS, // ReiserFS
                _ => FS_TYPE_UNKNOWN,
            };

            Outcome::Ok(fs_type.to_string())
        }
    }

    fn detect_block_size(path: &Path) -> Outcome<u32, CapabilityError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let metadata = match std::fs::metadata(path) {
                Ok(metadata) => metadata,
                Err(_) => return Outcome::Err(CapabilityError::MetadataAccess),
            };
            Outcome::Ok(metadata.blksize() as u32)
        }

        #[cfg(not(unix))]
        {
            let _ = path;
            // Default block size for non-Unix systems
            Outcome::Ok(4096)
        }
    }

    #[allow(unsafe_code)]
    async fn test_preallocation_support(path: &Path) -> bool {
        let Some((test_file, file)) = Self::create_unique_probe_file(path, "prealloc") else {
            return false;
        };

        #[cfg(target_os = "linux")]
        {
            use std::os::unix::io::AsRawFd;
            let fd = file.as_raw_fd();
            let result = unsafe { libc::fallocate(fd, 0, 0, 4096) };
            drop(file);
            let _ = std::fs::remove_file(&test_file);
            result == 0
        }

        // Fallback test for other platforms
        #[cfg(not(target_os = "linux"))]
        {
            drop(file);
            let _ = std::fs::remove_file(&test_file);
            false
        }
    }

    async fn test_atomic_rename_support(path: &Path) -> bool {
        let Some((source_path, source_file)) = Self::create_unique_probe_file(path, "rename_src")
        else {
            return false;
        };
        drop(source_file);

        let Some((target_path, target_file)) = Self::create_unique_probe_file(path, "rename_dst")
        else {
            let _ = std::fs::remove_file(&source_path);
            return false;
        };
        drop(target_file);

        #[cfg(target_os = "windows")]
        if std::fs::remove_file(&target_path).is_err() {
            let _ = std::fs::remove_file(&source_path);
            return false;
        }

        let renamed = std::fs::rename(&source_path, &target_path).is_ok();
        if renamed {
            let _ = std::fs::remove_file(&target_path);
        } else {
            let _ = std::fs::remove_file(&source_path);
            let _ = std::fs::remove_file(&target_path);
        }

        renamed
    }

    async fn test_hard_link_support(path: &Path) -> bool {
        let Some((test_file1, file)) = Self::create_unique_probe_file(path, "hardlink_src") else {
            return false;
        };
        drop(file);

        let test_file2 = Self::unique_probe_path(path, "hardlink_dst");
        let linked = std::fs::hard_link(&test_file1, &test_file2).is_ok();
        let _ = std::fs::remove_file(&test_file1);
        if linked {
            let _ = std::fs::remove_file(&test_file2);
        }

        linked
    }

    async fn test_sparse_file_support(path: &Path) -> bool {
        let Some((test_file, mut file)) = Self::create_unique_probe_file(path, "sparse") else {
            return false;
        };

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;

            let sparse_offset = 1024 * 1024;
            let probe_ok = file
                .seek(SeekFrom::Start(sparse_offset))
                .and_then(|_| file.write_all(&[1]))
                .is_ok();
            drop(file);

            let sparse = if probe_ok {
                match std::fs::metadata(&test_file) {
                    Ok(metadata) => {
                        let logical_len = metadata.len();
                        let allocated_bytes = metadata.blocks().saturating_mul(512);
                        logical_len > sparse_offset && allocated_bytes < logical_len / 2
                    }
                    Err(_) => false,
                }
            } else {
                false
            };

            let _ = std::fs::remove_file(&test_file);
            sparse
        }

        #[cfg(not(unix))]
        {
            // Windows needs FSCTL_SET_SPARSE before sparse allocation is
            // guaranteed. Avoid advertising support until a platform-specific
            // implementation marks the file sparse and verifies allocation.
            drop(file);
            let _ = std::fs::remove_file(&test_file);
            false
        }
    }

    #[allow(unsafe_code)]
    async fn test_hole_punching_support(path: &Path) -> bool {
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::io::AsRawFd;

            let Some((test_file, mut file)) = Self::create_unique_probe_file(path, "punch") else {
                return false;
            };

            let initialized = file.write_all(&[0xA5; 8192]).and_then(|_| file.sync_data());
            let supported = if initialized.is_ok() {
                let flags = libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE;
                unsafe { libc::fallocate(file.as_raw_fd(), flags, 0, 4096) == 0 }
            } else {
                false
            };

            drop(file);
            let _ = std::fs::remove_file(&test_file);
            supported
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = path;
            false
        }
    }

    async fn test_cow_support(_path: &Path) -> bool {
        // Detect COW filesystem support
        false // Conservative default
    }

    async fn test_reflink_support(_path: &Path) -> bool {
        // Detect reflink support (BTRFS, XFS, etc.)
        false // Conservative default
    }

    fn detect_async_io_support(os_type: &OsType) -> AsyncIoSupport {
        match os_type {
            OsType::Linux => {
                // Check for io_uring support
                if Self::has_io_uring() {
                    AsyncIoSupport::Advanced
                } else {
                    AsyncIoSupport::Native
                }
            }
            OsType::MacOS | OsType::FreeBSD => AsyncIoSupport::Native,
            OsType::Windows => AsyncIoSupport::Native, // IOCP
            OsType::Other(_) => AsyncIoSupport::Basic,
        }
    }

    fn has_io_uring() -> bool {
        #[cfg(target_os = "linux")]
        {
            // Simple check for io_uring availability
            std::fs::metadata("/sys/kernel/io_uring").is_ok()
        }

        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }

    fn detect_max_io_size(os_type: &OsType, filesystem: &FilesystemFeatures) -> usize {
        match os_type {
            OsType::Linux => {
                // Typical Linux limits
                match filesystem.fs_type.as_str() {
                    FS_TYPE_EXT4 | FS_TYPE_EXT3 | FS_TYPE_EXT2 => 128 * 1024 * 1024, // 128MB
                    FS_TYPE_XFS | FS_TYPE_ZFS => 1024 * 1024 * 1024,                 // 1GB
                    FS_TYPE_BTRFS => 256 * 1024 * 1024,                              // 256MB
                    _ => 64 * 1024 * 1024,                                           // 64MB default
                }
            }
            OsType::MacOS => 32 * 1024 * 1024,    // 32MB
            OsType::Windows => 64 * 1024 * 1024,  // 64MB
            OsType::FreeBSD => 128 * 1024 * 1024, // 128MB
            OsType::Other(_) => 16 * 1024 * 1024, // 16MB conservative
        }
    }

    fn detect_max_file_size(fs_type: &str) -> Option<u64> {
        match fs_type {
            FS_TYPE_EXT4 | FS_TYPE_EXT3 | FS_TYPE_EXT2 | FS_TYPE_BTRFS => {
                Some(16 * 1024 * 1024 * 1024 * 1024)
            }
            FS_TYPE_XFS | FS_TYPE_ZFS | FS_TYPE_APFS => Some(8 * 1024 * 1024 * 1024 * 1024 * 1024),
            FS_TYPE_NTFS => Some(256 * 1024 * 1024 * 1024 * 1024), // 256TB
            _ => None,                                             // Unknown
        }
    }

    fn detect_latency_profile(fs_type: &str) -> LatencyProfile {
        match fs_type {
            FS_TYPE_TMPFS | "ramfs" => LatencyProfile::LowLatency,
            FS_TYPE_NFS | "cifs" | "smb" => LatencyProfile::NetworkLatency,
            _ => LatencyProfile::Unknown, // Would need runtime detection
        }
    }
}

/// Errors that can occur during capability detection
#[derive(Debug, thiserror::Error)]
pub enum CapabilityError {
    #[error("Invalid path")]
    InvalidPath,

    #[error("Cannot access metadata")]
    MetadataAccess,

    #[error("System call failed: {0}")]
    SystemCall(String),

    #[error("Feature test failed: {0}")]
    FeatureTest(String),

    #[error("Unsupported platform")]
    UnsupportedPlatform,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_detection() {
        let cx = crate::cx::Cx::for_testing();
        let caps = futures_lite::future::block_on(PlatformCapabilities::detect(&cx));
        assert!(caps.is_ok());

        let caps = caps.unwrap();

        // Basic sanity checks
        assert!(!caps.filesystem.fs_type.is_empty());
        assert!(caps.filesystem.block_size > 0);
        assert!(caps.io_capabilities.max_io_size > 0);
    }

    #[test]
    fn test_filesystem_feature_detection() {
        let cx = crate::cx::Cx::for_testing();
        let temp_dir = std::env::temp_dir();
        let caps =
            futures_lite::future::block_on(PlatformCapabilities::detect_for_path(&cx, &temp_dir));
        assert!(caps.is_ok());

        let caps = caps.unwrap();

        // Most temp directories should support basic operations
        assert!(caps.atomic_operations.atomic_rename_same_fs);
    }

    #[test]
    fn test_os_type_detection() {
        let os_type = PlatformCapabilities::detect_os_type();

        // Should detect a known OS type in CI
        #[cfg(target_os = "linux")]
        assert_eq!(os_type, OsType::Linux);

        #[cfg(target_os = "macos")]
        assert_eq!(os_type, OsType::MacOS);

        #[cfg(target_os = "windows")]
        assert_eq!(os_type, OsType::Windows);
    }

    #[test]
    fn capability_probe_files_do_not_overwrite_existing_sentinels() {
        let temp_root = std::env::temp_dir();
        let test_dir = PlatformCapabilities::unique_probe_path(&temp_root, "sentinel_dir");
        std::fs::create_dir(&test_dir).unwrap();

        let sentinels = [
            (".atp_prealloc_test", b"keep prealloc sentinel".as_slice()),
            (".atp_link_test1", b"keep link source sentinel".as_slice()),
            (".atp_link_test2", b"keep link target sentinel".as_slice()),
        ];

        for (name, contents) in sentinels {
            std::fs::write(test_dir.join(name), contents).unwrap();
        }

        let _ = futures_lite::future::block_on(PlatformCapabilities::test_preallocation_support(
            &test_dir,
        ));
        let _ = futures_lite::future::block_on(PlatformCapabilities::test_atomic_rename_support(
            &test_dir,
        ));
        let _ =
            futures_lite::future::block_on(PlatformCapabilities::test_hard_link_support(&test_dir));

        for (name, contents) in sentinels {
            assert_eq!(std::fs::read(test_dir.join(name)).unwrap(), contents);
            std::fs::remove_file(test_dir.join(name)).unwrap();
        }
        std::fs::remove_dir(test_dir).unwrap();
    }
}
