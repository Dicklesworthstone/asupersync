//! Linux io_uring-based reactor implementation (stub).
//!
//! This module will provide [`UringReactor`], a reactor implementation that uses
//! Linux io_uring for high-performance async I/O. This is a future feature
//! tracked by bead asupersync-8jx5.
//!
//! # Status
//!
//! This is currently a stub module. The io_uring reactor implementation is
//! planned for Phase 2 of the project.
//!
//! # Future Capabilities
//!
//! When implemented, io_uring will provide:
//! - Zero-copy I/O operations
//! - Batched syscalls via submission queue
//! - Linked operations for complex I/O chains
//! - Fixed buffer registration for reduced overhead
//!
//! # Platform Requirements
//!
//! - Linux kernel 5.1+ (basic support)
//! - Linux kernel 5.6+ (recommended for full feature set)
//! - Linux kernel 5.19+ (for multi-shot operations)

use std::io;

use super::Interest;
use super::source::Source;
use super::token::Token;

/// io_uring-based reactor for Linux modern async I/O.
///
/// # Status
///
/// This is currently unimplemented. See bead asupersync-8jx5 for tracking.
#[derive(Debug)]
pub struct UringReactor {
    _private: (),
}

impl UringReactor {
    /// Creates a new io_uring reactor.
    ///
    /// # Errors
    ///
    /// Returns an error indicating that io_uring is not yet implemented.
    pub fn new() -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "io_uring reactor not yet implemented (see bead asupersync-8jx5)",
        ))
    }

    /// Checks if io_uring is available on this system.
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

impl super::Reactor for UringReactor {
    fn register(&self, _source: &dyn Source, _token: Token, _interest: Interest) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "io_uring reactor not yet implemented",
        ))
    }

    fn reregister(
        &self,
        _source: &dyn Source,
        _token: Token,
        _interest: Interest,
    ) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "io_uring reactor not yet implemented",
        ))
    }

    fn deregister(&self, _source: &dyn Source) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "io_uring reactor not yet implemented",
        ))
    }

    fn poll(
        &self,
        _events: &mut super::Events,
        _timeout: Option<std::time::Duration>,
    ) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "io_uring reactor not yet implemented",
        ))
    }

    fn wake(&self) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "io_uring reactor not yet implemented",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::net::UnixStream;

    #[test]
    fn test_new_returns_unsupported() {
        let err = UringReactor::new().expect_err("uring is not implemented");
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn test_is_available_platform_contract() {
        #[cfg(not(target_os = "linux"))]
        assert!(!UringReactor::is_available());

        #[cfg(target_os = "linux")]
        {
            // Availability depends on kernel version and io_uring policy.
            let _ = UringReactor::is_available();
        }
    }

    #[cfg(unix)]
    #[test]
    fn test_register_and_deregister_return_unsupported() {
        let reactor = UringReactor { _private: () };
        let (left, _right) = UnixStream::pair().expect("unix stream pair");

        let err = reactor
            .register(&left, Token::new(1), Interest::READABLE)
            .expect_err("register should be unsupported");
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);

        let err = reactor
            .reregister(&left, Token::new(1), Interest::WRITABLE)
            .expect_err("reregister should be unsupported");
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);

        let err = reactor
            .deregister(&left)
            .expect_err("deregister should be unsupported");
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn test_poll_and_wake_return_unsupported() {
        let reactor = UringReactor { _private: () };
        let mut events = super::Events::with_capacity(1);

        let err = reactor
            .poll(&mut events, None)
            .expect_err("poll should be unsupported");
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);

        let err = reactor.wake().expect_err("wake should be unsupported");
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }
}
