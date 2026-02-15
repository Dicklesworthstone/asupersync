//! Source trait for registerable I/O objects.
//!
//! This module defines the `Source` trait that any I/O object must implement
//! to be registerable with the reactor for event notification.
//!
//! # Example
//!
//! ```ignore
//! use asupersync::runtime::reactor::{Source, SourceWrapper};
//! use std::net::TcpStream;
//!
//! // Any AsRawFd type automatically implements Source
//! let stream = TcpStream::connect("127.0.0.1:8080")?;
//!
//! // For debugging/tracing, wrap in SourceWrapper to get a unique ID
//! let wrapped = SourceWrapper::new(stream);
//! let id = wrapped.source_id(); // Unique ID for debugging
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
    /// ```ignore
    /// use asupersync::runtime::reactor::{SourceWrapper, SourceId};
    /// use std::net::TcpListener;
    ///
    /// let listener = TcpListener::bind("127.0.0.1:0")?;
    /// let wrapped = SourceWrapper::new(listener);
    ///
    /// // Get the unique ID for tracing
    /// let id = wrapped.source_id();
    /// println!("Source {} registered", id);
    ///
    /// // Still access the inner fd
    /// let fd = wrapped.as_raw_fd();
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

        /// Creates a new source wrapper with a specific ID.
        ///
        /// This is useful when you need to control the ID assignment.
        #[must_use]
        pub fn with_id(inner: T, id: u64) -> Self {
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

        /// Creates a new source wrapper with a specific ID.
        #[must_use]
        pub fn with_id(inner: T, id: u64) -> Self {
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

// Re-export platform-specific types
pub use platform::{Source, SourceId, SourceWrapper};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::init_test_logging;

    fn init_test(name: &str) {
        init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn source_id_generates_unique_ids() {
        init_test("source_id_generates_unique_ids");
        let id1 = next_source_id();
        let id2 = next_source_id();
        let id3 = next_source_id();

        crate::assert_with_log!(id1 != id2, "id1 != id2", true, id1 != id2);
        crate::assert_with_log!(id2 != id3, "id2 != id3", true, id2 != id3);
        crate::assert_with_log!(id1 != id3, "id1 != id3", true, id1 != id3);

        // IDs should be monotonically increasing
        crate::assert_with_log!(id1 < id2, "id1 < id2", true, id1 < id2);
        crate::assert_with_log!(id2 < id3, "id2 < id3", true, id2 < id3);
        crate::test_complete!("source_id_generates_unique_ids");
    }

    #[test]
    #[should_panic(expected = "source ID counter overflow")]
    fn source_id_overflow_panics() {
        init_test("source_id_overflow_panics");
        let counter = AtomicU64::new(u64::MAX);
        let _ = next_source_id_from(&counter);
    }

    #[cfg(unix)]
    mod unix_tests {
        use super::*;
        use std::os::unix::io::AsRawFd;
        use std::os::unix::net::UnixStream;

        fn accepts_source<T: Source>(_: &T) {}

        #[test]
        fn source_wrapper_with_pipe() {
            super::init_test("source_wrapper_with_pipe");
            // Use a real unix stream which is Send + Sync
            let (sock1, _sock2) = UnixStream::pair().expect("failed to create unix stream pair");
            let fd = sock1.as_raw_fd();
            let wrapper = SourceWrapper::new(sock1);

            crate::assert_with_log!(
                wrapper.as_raw_fd() == fd,
                "wrapper raw fd",
                fd,
                wrapper.as_raw_fd()
            );
            crate::assert_with_log!(
                wrapper.source_id() > 0,
                "source id nonzero",
                true,
                wrapper.source_id() > 0
            );
            crate::test_complete!("source_wrapper_with_pipe");
        }

        #[test]
        fn source_wrapper_has_unique_ids() {
            super::init_test("source_wrapper_has_unique_ids");
            let (sock1, sock2) = UnixStream::pair().expect("failed to create unix stream pair");
            let wrapper1 = SourceWrapper::new(sock1);
            let wrapper2 = SourceWrapper::new(sock2);

            crate::assert_with_log!(
                wrapper1.source_id() != wrapper2.source_id(),
                "unique ids",
                true,
                wrapper1.source_id() != wrapper2.source_id()
            );
            crate::test_complete!("source_wrapper_has_unique_ids");
        }

        #[test]
        fn source_wrapper_with_custom_id() {
            super::init_test("source_wrapper_with_custom_id");
            let (sock, _) = UnixStream::pair().expect("failed to create unix stream pair");
            let wrapper = SourceWrapper::with_id(sock, 12345);

            crate::assert_with_log!(
                wrapper.source_id() == 12345,
                "custom id",
                12345u64,
                wrapper.source_id()
            );
            crate::test_complete!("source_wrapper_with_custom_id");
        }

        #[test]
        fn source_wrapper_into_inner() {
            super::init_test("source_wrapper_into_inner");
            let (sock, _) = UnixStream::pair().expect("failed to create unix stream pair");
            let expected_fd = sock.as_raw_fd();
            let wrapper = SourceWrapper::new(sock);
            let recovered = wrapper.into_inner();

            crate::assert_with_log!(
                recovered.as_raw_fd() == expected_fd,
                "into_inner returns socket",
                expected_fd,
                recovered.as_raw_fd()
            );
            crate::test_complete!("source_wrapper_into_inner");
        }

        #[test]
        fn source_wrapper_get_ref() {
            super::init_test("source_wrapper_get_ref");
            let (sock, _) = UnixStream::pair().expect("failed to create unix stream pair");
            let expected_fd = sock.as_raw_fd();
            let wrapper = SourceWrapper::new(sock);

            crate::assert_with_log!(
                wrapper.get_ref().as_raw_fd() == expected_fd,
                "get_ref returns inner",
                expected_fd,
                wrapper.get_ref().as_raw_fd()
            );
            crate::test_complete!("source_wrapper_get_ref");
        }

        #[test]
        fn unix_stream_implements_source() {
            super::init_test("unix_stream_implements_source");
            let (sock, _) = UnixStream::pair().expect("failed to create unix stream pair");

            // UnixStream should implement Source automatically
            accepts_source(&sock);

            let fd = sock.as_raw_fd();
            crate::assert_with_log!(fd >= 0, "raw fd valid", true, fd >= 0);
            crate::test_complete!("unix_stream_implements_source");
        }

        #[test]
        fn source_wrapper_implements_source() {
            super::init_test("source_wrapper_implements_source");
            let (sock, _) = UnixStream::pair().expect("failed to create unix stream pair");
            let wrapper = SourceWrapper::new(sock);

            // SourceWrapper should implement Source
            accepts_source(&wrapper);

            let fd = wrapper.as_raw_fd();
            crate::assert_with_log!(fd >= 0, "wrapper raw fd valid", true, fd >= 0);
            crate::test_complete!("source_wrapper_implements_source");
        }

        #[test]
        fn source_as_trait_object() {
            super::init_test("source_as_trait_object");
            let (sock, _) = UnixStream::pair().expect("failed to create unix stream pair");
            let expected_fd = sock.as_raw_fd();
            let source: &dyn Source = &sock;

            crate::assert_with_log!(
                source.as_raw_fd() == expected_fd,
                "trait object raw fd",
                expected_fd,
                source.as_raw_fd()
            );
            crate::test_complete!("source_as_trait_object");
        }
    }

    #[cfg(windows)]
    mod windows_tests {
        use super::*;
        use std::net::TcpListener;
        use std::os::windows::io::AsRawSocket;

        #[test]
        fn source_wrapper_with_tcp_listener() {
            super::init_test("source_wrapper_with_tcp_listener");
            let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind");
            let socket = listener.as_raw_socket();
            let wrapper = SourceWrapper::new(listener);

            crate::assert_with_log!(
                wrapper.as_raw_socket() == socket,
                "wrapper raw socket",
                socket,
                wrapper.as_raw_socket()
            );
            crate::assert_with_log!(
                wrapper.source_id() > 0,
                "source id nonzero",
                true,
                wrapper.source_id() > 0
            );
            crate::test_complete!("source_wrapper_with_tcp_listener");
        }

        #[test]
        fn source_wrapper_has_unique_ids() {
            super::init_test("source_wrapper_has_unique_ids");
            let listener1 = TcpListener::bind("127.0.0.1:0").expect("failed to bind");
            let listener2 = TcpListener::bind("127.0.0.1:0").expect("failed to bind");

            let wrapper1 = SourceWrapper::new(listener1);
            let wrapper2 = SourceWrapper::new(listener2);

            crate::assert_with_log!(
                wrapper1.source_id() != wrapper2.source_id(),
                "unique ids",
                true,
                wrapper1.source_id() != wrapper2.source_id()
            );
            crate::test_complete!("source_wrapper_has_unique_ids");
        }

        #[test]
        fn tcp_listener_implements_source() {
            super::init_test("tcp_listener_implements_source");
            let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind");

            fn accepts_source<T: Source>(_: &T) {}
            accepts_source(&listener);

            let socket = listener.as_raw_socket();
            crate::assert_with_log!(socket != 0, "raw socket valid", true, socket != 0);
            crate::test_complete!("tcp_listener_implements_source");
        }
    }
}
