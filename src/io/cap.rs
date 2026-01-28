//! I/O capability trait for explicit capability-based I/O access.
//!
//! The [`IoCap`] trait defines the capability boundary for I/O operations.
//! Tasks can only perform I/O if they have access to an `IoCap` implementation.
//!
//! # Design Rationale
//!
//! Asupersync uses explicit capability security - no ambient authority. I/O operations
//! are only available when the runtime provides an `IoCap` implementation:
//!
//! - Production runtime provides a real I/O capability backed by the reactor
//! - Lab runtime provides a virtual I/O capability for deterministic testing
//! - Tests can verify that code correctly handles "no I/O" scenarios
//!
//! # Two-Phase I/O Model
//!
//! I/O operations in Asupersync follow a two-phase commit model:
//!
//! 1. **Submit**: Create an I/O operation (returns a handle/obligation)
//! 2. **Complete**: Wait for completion or cancel
//!
//! This model allows for proper cancellation tracking and budget accounting.

use std::fmt::Debug;
use std::io;

/// The I/O capability trait.
///
/// Implementations of this trait provide access to I/O operations. The runtime
/// configures which implementation to use:
///
/// - Production: Real I/O via reactor (epoll/kqueue/IOCP)
/// - Lab: Virtual I/O for deterministic testing
///
/// # Example
///
/// ```ignore
/// async fn read_file(cx: &Cx, path: &str) -> io::Result<Vec<u8>> {
///     let io = cx.io().ok_or_else(|| {
///         io::Error::new(io::ErrorKind::Unsupported, "I/O not available")
///     })?;
///
///     // Open the file using the I/O capability
///     let file = io.open(path).await?;
///
///     // Read contents
///     let mut buf = Vec::new();
///     io.read_to_end(&file, &mut buf).await?;
///     Ok(buf)
/// }
/// ```
pub trait IoCap: Send + Sync + Debug {
    /// Returns true if this I/O capability supports real system I/O.
    ///
    /// Lab/test implementations return false.
    fn is_real_io(&self) -> bool;

    /// Returns the name of this I/O capability implementation.
    ///
    /// Useful for debugging and diagnostics.
    fn name(&self) -> &'static str;

    // TODO: Add actual I/O methods as Phase 2 progresses:
    // - File operations (open, read, write, close)
    // - Network operations (connect, accept, send, recv)
    // - Timer integration
}

/// Error returned when I/O is not available.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IoNotAvailable;

impl std::fmt::Display for IoNotAvailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "I/O capability not available")
    }
}

impl std::error::Error for IoNotAvailable {}

impl From<IoNotAvailable> for io::Error {
    fn from(_: IoNotAvailable) -> Self {
        Self::new(io::ErrorKind::Unsupported, "I/O capability not available")
    }
}

/// Lab I/O capability for testing.
///
/// This implementation provides virtual I/O that can be controlled by tests:
/// - Deterministic timing
/// - Fault injection
/// - Replay support
#[derive(Debug, Default)]
pub struct LabIoCap {
    // TODO: Add virtual I/O state as needed
}

impl LabIoCap {
    /// Creates a new lab I/O capability.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl IoCap for LabIoCap {
    fn is_real_io(&self) -> bool {
        false
    }

    fn name(&self) -> &'static str {
        "lab"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lab_io_cap_is_not_real() {
        let cap = LabIoCap::new();
        assert!(!cap.is_real_io());
        assert_eq!(cap.name(), "lab");
    }

    #[test]
    fn io_not_available_error() {
        let err = IoNotAvailable;
        let io_err: io::Error = err.into();
        assert_eq!(io_err.kind(), io::ErrorKind::Unsupported);
    }
}
