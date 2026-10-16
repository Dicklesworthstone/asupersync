//! Source trait for registerable I/O objects.
//!
//! This module defines the `Source` trait that any I/O object must implement
//! to be registerable with the reactor for event notification.
//!
//! # Example
//!
//! ```no_run
//! use asupersync::runtime::reactor::{SourceId, SourceWrapper};
//! use std::net::TcpStream;
//!
//! # fn main() -> std::io::Result<()> {
//! // Any AsRawFd type automatically implements Source
//! let stream = TcpStream::connect("127.0.0.1:8080")?;
//!
//! // For debugging/tracing, wrap in SourceWrapper to get a unique ID
//! let wrapped = SourceWrapper::new(stream);
//! let id = wrapped.source_id(); // Unique ID for debugging
//! # let _ = id;
//! # Ok(())
//! # }
//! ```
//!
//! # Safety Requirements
//!
//! Implementors must guarantee:
//! 1. The file descriptor/handle remains valid for the entire duration of registration
//! 2. The same fd/handle is not registered with multiple reactors concurrently
//! 3. The fd/handle supports non-blocking operations

use std::sync::atomic::{AtomicU64, Ordering};

/// Global counter for generating unique source IDs.
static SOURCE_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Generates a new unique source ID.
///
/// Each call returns a monotonically increasing value, starting from 1.
/// This is useful for debugging and tracing I/O operations.
///
/// # Panics
///
/// Panics if the source ID counter overflows.
#[must_use]
pub fn next_source_id() -> u64 {
    next_source_id_from(&SOURCE_ID_COUNTER)
}

fn next_source_id_from(counter: &AtomicU64) -> u64 {
    loop {
        let current = counter.load(Ordering::Relaxed);
        let next = current.checked_add(1).expect("source ID counter overflow");
        if counter
            .compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            return current;
        }
    }
}

// Unix implementation
#[cfg(unix)]
mod platform {
    use super::next_source_id;
    use std::os::unix::io::{AsRawFd, RawFd};

    /// Represents an I/O source that can be registered with a reactor.
    ///
    /// Any type that implements `AsRawFd + Send + Sync` automatically implements
    /// this trait through a blanket implementation.
    ///
    /// # Safety
    ///
    /// Implementors must guarantee:
    /// 1. The file descriptor remains valid for the lifetime of registration
    /// 2. The same fd is not registered with multiple reactors concurrently
    /// 3. The fd supports non-blocking operations
    pub trait Source: AsRawFd + Send + Sync {
        /// Returns the raw file descriptor for this source.
        ///
        /// This is a convenience method that delegates to [`AsRawFd::as_raw_fd`].
        fn raw_fd(&self) -> RawFd {
            self.as_raw_fd()
        }
    }

    // Blanket implementation for backward compatibility
    impl<T: AsRawFd + Send + Sync> Source for T {}

    /// Optional trait for sources that have a unique identifier.
    ///
    /// This is useful for debugging and tracing. Use [`SourceWrapper`] to
    /// automatically add an ID to any source.
    pub trait SourceId {
        /// Returns a unique identifier for this source instance.
        fn source_id(&self) -> u64;
    }

    /// Wrapper that adds a unique source ID to any I/O object.
    ///
    /// This wrapper is useful for debugging and tracing I/O operations.
    /// It automatically generates a unique ID when created.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use asupersync::runtime::reactor::{SourceWrapper, SourceId};
    /// use std::net::TcpListener;
    /// use std::os::fd::AsRawFd;
    ///
    /// # fn main() -> std::io::Result<()> {
    /// let listener = TcpListener::bind("127.0.0.1:0")?;
    /// let wrapped = SourceWrapper::new(listener);
    ///
    /// // Get the unique ID for tracing
    /// let id = wrapped.source_id();
    /// println!("Source {} registered", id);
    ///
    /// // Still access the inner fd
    /// let fd = wrapped.as_raw_fd();
    /// # let _ = fd;
    /// # Ok(())
    /// # }
    /// ```
    #[derive(Debug)]
    pub struct SourceWrapper<T> {
        inner: T,
        id: u64,
    }

    impl<T> SourceWrapper<T> {
        /// Creates a new source wrapper around an I/O object.
        ///
        /// A unique source ID is automatically generated.
        #[must_use]
        pub fn new(inner: T) -> Self {
            Self {
                inner,
                id: next_source_id(),
            }
        }

        /// Test-only helper that bypasses automatic unique ID generation.
        #[cfg(test)]
        #[must_use]
        pub(crate) fn with_id(inner: T, id: u64) -> Self {
            Self { inner, id }
        }

        /// Returns a reference to the inner value.
        #[must_use]
        pub fn get_ref(&self) -> &T {
            &self.inner
        }

        /// Returns a mutable reference to the inner value.
        pub fn get_mut(&mut self) -> &mut T {
            &mut self.inner
        }

        /// Consumes the wrapper and returns the inner value.
        #[must_use]
        pub fn into_inner(self) -> T {
            self.inner
        }
    }

    impl<T> SourceId for SourceWrapper<T> {
        fn source_id(&self) -> u64 {
            self.id
        }
    }

    impl<T: AsRawFd> AsRawFd for SourceWrapper<T> {
        fn as_raw_fd(&self) -> RawFd {
            self.inner.as_raw_fd()
        }
    }

    // SourceWrapper implements Source automatically through the blanket impl
    // since it implements AsRawFd + Send + Sync (when T does)
}

// Windows implementation
#[cfg(windows)]
mod platform {
    use super::next_source_id;
    use std::os::windows::io::{AsRawSocket, RawSocket};

    /// Represents an I/O source that can be registered with a reactor.
    ///
    /// Any type that implements `AsRawSocket + Send + Sync` automatically implements
    /// this trait through a blanket implementation.
    ///
    /// # Safety
    ///
    /// Implementors must guarantee:
    /// 1. The socket handle remains valid for the lifetime of registration
    /// 2. The same socket is not registered with multiple reactors concurrently
    /// 3. The socket supports non-blocking operations
    pub trait Source: AsRawSocket + Send + Sync {
        /// Returns the raw socket handle for this source.
        ///
        /// This is a convenience method that delegates to [`AsRawSocket::as_raw_socket`].
        fn raw_socket(&self) -> RawSocket {
            self.as_raw_socket()
        }
    }

    // Blanket implementation for backward compatibility
    impl<T: AsRawSocket + Send + Sync> Source for T {}

    /// Optional trait for sources that have a unique identifier.
    pub trait SourceId {
        /// Returns a unique identifier for this source instance.
        fn source_id(&self) -> u64;
    }

    /// Wrapper that adds a unique source ID to any I/O object.
    #[derive(Debug)]
    pub struct SourceWrapper<T> {
        inner: T,
        id: u64,
    }

    impl<T> SourceWrapper<T> {
        /// Creates a new source wrapper around an I/O object.
        #[must_use]
        pub fn new(inner: T) -> Self {
            Self {
                inner,
                id: next_source_id(),
            }
        }

        /// Test-only helper that bypasses automatic unique ID generation.
        #[cfg(test)]
        #[must_use]
        pub(crate) fn with_id(inner: T, id: u64) -> Self {
            Self { inner, id }
        }

        /// Returns a reference to the inner value.
        #[must_use]
        pub fn get_ref(&self) -> &T {
            &self.inner
        }

        /// Returns a mutable reference to the inner value.
        pub fn get_mut(&mut self) -> &mut T {
            &mut self.inner
        }

        /// Consumes the wrapper and returns the inner value.
        #[must_use]
        pub fn into_inner(self) -> T {
            self.inner
        }
    }

    impl<T> SourceId for SourceWrapper<T> {
        fn source_id(&self) -> u64 {
            self.id
        }
    }

    impl<T: AsRawSocket> AsRawSocket for SourceWrapper<T> {
        fn as_raw_socket(&self) -> RawSocket {
            self.inner.as_raw_socket()
        }
    }
}

// wasm32/browser implementation
#[cfg(target_arch = "wasm32")]
mod platform {
    use super::next_source_id;

    /// Browser-host sources do not expose raw OS handles.
    ///
    /// The browser reactor currently tracks registrations by token only, so
    /// wasm builds keep the `Source` surface as a pure marker trait until the
    /// browser host bindings define concrete source kinds.
    pub trait Source: Send + Sync {}

    impl<T: Send + Sync> Source for T {}

    /// Optional trait for sources that have a unique identifier.
    pub trait SourceId {
        /// Returns a unique identifier for this source instance.
        fn source_id(&self) -> u64;
    }

    /// Wrapper that adds a unique source ID to any browser source.
    #[derive(Debug)]
    pub struct SourceWrapper<T> {
        inner: T,
        id: u64,
    }

    impl<T> SourceWrapper<T> {
        /// Creates a new source wrapper around an I/O object.
        #[must_use]
        pub fn new(inner: T) -> Self {
            Self {
                inner,
                id: next_source_id(),
            }
        }

        /// Test-only helper that bypasses automatic unique ID generation.
        #[cfg(test)]
        #[must_use]
        pub(crate) fn with_id(inner: T, id: u64) -> Self {
            Self { inner, id }
        }

        /// Returns a reference to the inner value.
        #[must_use]
        pub fn get_ref(&self) -> &T {
            &self.inner
        }

        /// Returns a mutable reference to the inner value.
        pub fn get_mut(&mut self) -> &mut T {
            &mut self.inner
        }

        /// Consumes the wrapper and returns the inner value.
        #[must_use]
        pub fn into_inner(self) -> T {
            self.inner
        }
    }

    impl<T> SourceId for SourceWrapper<T> {
        fn source_id(&self) -> u64 {
            self.id
        }
    }
}

// Re-export platform-specific types
pub use platform::{Source, SourceId, SourceWrapper};

#[cfg(test)]
#[path = "source_inline_tests.rs"]
mod tests;
