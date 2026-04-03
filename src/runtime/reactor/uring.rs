//! Deprecated legacy naming shim — use [`IoUringReactor`](super::IoUringReactor) instead.
//!
//! **Note**: This file is *not* part of the compiled module graph. `mod.rs` maps
//! `mod uring` to `io_uring.rs` via `#[path = "io_uring.rs"]`. This file is
//! retained as a historical reference only.
//!
//! The original standalone `UringReactor` struct that always returned `Unsupported`
//! has been retired and replaced with a deprecated type alias below.
//!
//! # Platform Requirements (io_uring)
//!
//! - Linux kernel 5.1+ (basic support)
//! - Linux kernel 5.6+ (recommended for full feature set)
//! - Linux kernel 5.19+ (for multi-shot operations)

/// Deprecated: use [`IoUringReactor`](super::IoUringReactor) instead.
///
/// This type alias preserves backward compatibility for code that referenced
/// the old `UringReactor` name. New code should use `IoUringReactor` directly.
#[deprecated(since = "0.2.0", note = "Use IoUringReactor instead")]
pub type UringReactor = super::IoUringReactor;

/// Checks if io_uring is available on this system.
///
/// Returns `true` if the running Linux kernel is 5.1+ and io_uring
/// is not disabled via `/proc/sys/kernel/io_uring_disabled`.
/// Always returns `false` on non-Linux platforms.
#[must_use]
pub fn is_available() -> bool {
    #[cfg(not(target_os = "linux"))]
    {
        false
    }

    #[cfg(target_os = "linux")]
    {
        linux_kernel_supports_uring() && !linux_io_uring_disabled()
    }
}

#[cfg(target_os = "linux")]
fn linux_kernel_supports_uring() -> bool {
    let Ok(release) = std::fs::read_to_string("/proc/sys/kernel/osrelease") else {
        return false;
    };
    let mut parts = release
        .trim()
        .split(|c: char| !(c.is_ascii_digit() || c == '.'))
        .next()
        .unwrap_or_default()
        .split('.');
    let major = parts
        .next()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(0);
    let minor = parts
        .next()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(0);
    major > 5 || (major == 5 && minor >= 1)
}

#[cfg(target_os = "linux")]
fn linux_io_uring_disabled() -> bool {
    match std::fs::read_to_string("/proc/sys/kernel/io_uring_disabled") {
        Ok(raw) => raw.trim().parse::<u32>().is_ok_and(|flag| flag > 0),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_available_platform_contract() {
        #[cfg(not(target_os = "linux"))]
        assert!(!is_available());

        #[cfg(target_os = "linux")]
        {
            // Availability depends on kernel version and io_uring policy.
            let _ = is_available();
        }
    }

    #[allow(deprecated)]
    #[test]
    fn test_deprecated_type_alias_exists() {
        // Verify UringReactor is a type alias to IoUringReactor.
        // This test ensures backward compatibility is preserved.
        fn _assert_alias_compiles(_: Option<UringReactor>) {}
    }
}
