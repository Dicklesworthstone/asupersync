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

use super::source::Source;
use super::token::Token;
use super::Interest;

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
        // TODO: Check kernel version and io_uring availability
        false
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

    fn poll(&self, _events: &mut super::Events, _timeout: Option<std::time::Duration>) -> io::Result<()> {
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
