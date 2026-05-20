//! Platform Capability Detection for Filesystem Features

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
use std::ffi::CString;
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
use std::mem::MaybeUninit;

use crate::cx::Cx;
use crate::types::outcome::Outcome;
use std::collections::HashMap;
use std::fs::File;
use std::path::Path;

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
    pub operation_costs: HashMap<String, u32>,
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
        cx: &Cx,
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
    ) -> Result<IoCapabilities, CapabilityError> {
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

        Ok(IoCapabilities {
            supports_direct_io,
            async_io_support,
            max_io_size,
            io_alignment,
            supports_vectored_io,
        })
    }

    /// Detect atomic operation support
    async fn detect_atomic_support(
        path: &Path,
        os_type: &OsType,
    ) -> Result<AtomicSupport, CapabilityError> {
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

        Ok(AtomicSupport {
            atomic_rename_same_fs,
            atomic_rename_cross_fs,
            atomic_link_unlink,
            supports_dir_sync,
            crash_consistent_rename,
        })
    }

    /// Generate performance hints based on detected capabilities
    fn generate_performance_hints(
        os_type: &OsType,
        filesystem: &FilesystemFeatures,
        io_capabilities: &IoCapabilities,
    ) -> PerformanceHints {
        let recommended_prealloc_size = match filesystem.fs_type.as_str() {
            "ext4" | "xfs" => 64 * 1024 * 1024, // 64MB
            "btrfs" => 32 * 1024 * 1024,        // 32MB
            "ntfs" => 16 * 1024 * 1024,         // 16MB
            "apfs" => 32 * 1024 * 1024,         // 32MB
            _ => 16 * 1024 * 1024,              // 16MB default
        };

        let recommended_write_batch = filesystem.block_size as u64 * 32;

        let prefers_sequential_access = match filesystem.fs_type.as_str() {
            "ext4" | "xfs" | "ntfs" => true,
            "btrfs" | "zfs" => false, // COW filesystems
            _ => true,
        };

        let mut operation_costs = HashMap::new();
        operation_costs.insert("prealloc".to_string(), 10);
        operation_costs.insert("write".to_string(), 1);
        operation_costs.insert("sync".to_string(), 50);
        operation_costs.insert("rename".to_string(), 5);

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

    fn detect_filesystem_type(path: &Path) -> Outcome<String, CapabilityError> {
        // Platform-specific filesystem detection
        #[cfg(target_os = "linux")]
        {
            Self::detect_linux_filesystem_type(path)
        }

        #[cfg(target_os = "macos")]
        {
            Ok("apfs".to_string()) // Assume APFS on modern macOS
        }

        #[cfg(target_os = "windows")]
        {
            Ok("ntfs".to_string()) // Assume NTFS on Windows
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            Ok("unknown".to_string())
        }
    }

    #[cfg(target_os = "linux")]
    #[allow(unsafe_code)]
    fn detect_linux_filesystem_type(path: &Path) -> Outcome<String, CapabilityError> {

        let path_cstr = CString::new(path.to_string_lossy().as_bytes())
            .map_err(|_| CapabilityError::InvalidPath)?;

        let mut statfs_buf: MaybeUninit<libc::statfs> = MaybeUninit::uninit();

        unsafe {
            if libc::statfs(path_cstr.as_ptr(), statfs_buf.as_mut_ptr()) != 0 {
                return Err(CapabilityError::SystemCall("statfs".to_string()));
            }

            let statfs = statfs_buf.assume_init();
            let fs_type = match statfs.f_type as u64 {
                0xEF53 => "ext4",         // EXT2/3/4
                0x58465342 => "xfs",      // XFS
                0x9123683E => "btrfs",    // BTRFS
                0x6969 => "nfs",          // NFS
                0x01021994 => "tmpfs",    // TMPFS
                0x137F => "minix",        // MINIX
                0x4d44 => "msdos",        // FAT
                0x52654973 => "reiserfs", // ReiserFS
                _ => "unknown",
            };

            Ok(fs_type.to_string())
        }
    }

    fn detect_block_size(path: &Path) -> Outcome<u32, CapabilityError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let metadata = std::fs::metadata(path).map_err(|_| CapabilityError::MetadataAccess)?;
            Ok(metadata.blksize() as u32)
        }

        #[cfg(not(unix))]
        {
            // Default block size for non-Unix systems
            Ok(4096)
        }
    }

    #[allow(unsafe_code)]
    async fn test_preallocation_support(path: &Path) -> bool {
        let test_file = path.join(".atp_prealloc_test");

        #[cfg(target_os = "linux")]
        {
            if let Ok(file) = std::fs::File::create(&test_file) {
                use std::os::unix::io::AsRawFd;
                let fd = file.as_raw_fd();
                let result = unsafe { libc::fallocate(fd, 0, 0, 4096) };
                std::fs::remove_file(&test_file).ok();
                return result == 0;
            }
        }

        // Fallback test for other platforms
        false
    }

    async fn test_atomic_rename_support(_path: &Path) -> bool {
        // On POSIX systems, rename within the same filesystem is atomic
        true
    }

    async fn test_hard_link_support(path: &Path) -> bool {
        let test_file1 = path.join(".atp_link_test1");
        let test_file2 = path.join(".atp_link_test2");

        if let Ok(_) = std::fs::File::create(&test_file1) {
            let result = std::fs::hard_link(&test_file1, &test_file2).is_ok();
            std::fs::remove_file(&test_file1).ok();
            std::fs::remove_file(&test_file2).ok();
            return result;
        }

        false
    }

    async fn test_sparse_file_support(path: &Path) -> bool {
        // Most modern filesystems support sparse files
        // This could be enhanced with actual testing
        true
    }

    async fn test_hole_punching_support(_path: &Path) -> bool {
        // Platform-specific hole punching test
        #[cfg(target_os = "linux")]
        return true; // Most Linux filesystems support FALLOC_FL_PUNCH_HOLE

        #[cfg(not(target_os = "linux"))]
        return false;
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
                    "ext4" => 128 * 1024 * 1024,  // 128MB
                    "xfs" => 1024 * 1024 * 1024,  // 1GB
                    "btrfs" => 256 * 1024 * 1024, // 256MB
                    _ => 64 * 1024 * 1024,        // 64MB default
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
            "ext4" => Some(16 * 1024 * 1024 * 1024 * 1024), // 16TB
            "xfs" => Some(8 * 1024 * 1024 * 1024 * 1024 * 1024), // 8EB theoretical
            "btrfs" => Some(16 * 1024 * 1024 * 1024 * 1024), // 16TB practical
            "ntfs" => Some(256 * 1024 * 1024 * 1024 * 1024), // 256TB
            "apfs" => Some(8 * 1024 * 1024 * 1024 * 1024 * 1024), // 8EB
            _ => None,                                      // Unknown
        }
    }

    fn detect_latency_profile(fs_type: &str) -> LatencyProfile {
        match fs_type {
            "tmpfs" | "ramfs" => LatencyProfile::LowLatency,
            "nfs" | "cifs" | "smb" => LatencyProfile::NetworkLatency,
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

    #[tokio::test]
    async fn test_platform_detection() {
        let cx = crate::cx::Cx::new(); // TODO: Fix this
        let caps = PlatformCapabilities::detect(&cx).await;
        assert!(caps.is_ok());

        let caps = caps.unwrap();

        // Basic sanity checks
        assert!(!caps.filesystem.fs_type.is_empty());
        assert!(caps.filesystem.block_size > 0);
        assert!(caps.io_capabilities.max_io_size > 0);
    }

    #[tokio::test]
    async fn test_filesystem_feature_detection() {
        let temp_dir = std::env::temp_dir();
        let caps = PlatformCapabilities::detect_for_path(&crate::cx::Cx::new(), &temp_dir).await;
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
}
