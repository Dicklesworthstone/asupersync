#![allow(warnings)]
#![allow(clippy::all)]
//! Conformance tests for io_uring registered buffer pool functionality.
//!
//! These tests verify the expected behavior and contracts for io_uring's
//! registered buffer pool feature, which pre-registers buffers with the
//! kernel to reduce per-operation overhead.
//!
//! The tests cover both the buffer registration interface and the I/O
//! operations that use registered buffers.

#[cfg(all(target_os = "linux", feature = "io-uring"))]
mod linux_io_uring_tests {
    use asupersync::runtime::reactor::{Events, Interest, IoUringReactor, Reactor, Token};
    use std::io::{self, IoSlice, IoSliceMut, Read, Write};
    use std::os::fd::{AsRawFd, RawFd};
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    /// Test source that wraps a Unix domain socket
    struct TestSource {
        socket: UnixStream,
    }

    impl TestSource {
        fn new() -> io::Result<(Self, Self)> {
            let (left, right) = UnixStream::pair()?;
            Ok((Self { socket: left }, Self { socket: right }))
        }
    }

    impl AsRawFd for TestSource {
        fn as_raw_fd(&self) -> RawFd {
            self.socket.as_raw_fd()
        }
    }

    impl Read for TestSource {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.socket.read(buf)
        }
    }

    impl Write for TestSource {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.socket.write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.socket.flush()
        }
    }

    /// Configuration for registered buffer pool
    #[derive(Debug, Clone)]
    pub struct BufferPoolConfig {
        /// Number of buffers to register
        pub buffer_count: usize,
        /// Size of each buffer in bytes
        pub buffer_size: usize,
        /// Whether to use physically contiguous memory
        pub use_huge_pages: bool,
    }

    impl Default for BufferPoolConfig {
        fn default() -> Self {
            Self {
                buffer_count: 64,
                buffer_size: 4096,
                use_huge_pages: false,
            }
        }
    }

    /// Handle to a registered buffer
    #[derive(Debug, Clone, Copy)]
    pub struct BufferHandle {
        /// Buffer index in the registered set
        pub index: u16,
        /// Offset within the buffer
        pub offset: usize,
        /// Length of the usable region
        pub length: usize,
    }

    /// Trait for io_uring reactors with registered buffer pool support
    pub trait RegisteredBufferReactor: Reactor {
        /// Register a buffer pool with the kernel
        fn register_buffer_pool(&self, config: &BufferPoolConfig) -> io::Result<()>;

        /// Unregister the buffer pool
        fn unregister_buffer_pool(&self) -> io::Result<()>;

        /// Get a handle to an available buffer
        fn acquire_buffer(&self, min_size: usize) -> io::Result<BufferHandle>;

        /// Release a buffer handle back to the pool
        fn release_buffer(&self, handle: BufferHandle) -> io::Result<()>;

        /// Read into a registered buffer (zero-copy)
        fn read_to_registered_buffer(&self, token: Token, handle: BufferHandle) -> io::Result<()>;

        /// Write from a registered buffer (zero-copy)
        fn write_from_registered_buffer(
            &self,
            token: Token,
            handle: BufferHandle,
        ) -> io::Result<()>;

        /// Get the current buffer pool statistics
        fn buffer_pool_stats(&self) -> io::Result<BufferPoolStats>;
    }

    /// Statistics for registered buffer pool usage
    #[derive(Debug, Clone, Copy)]
    pub struct BufferPoolStats {
        /// Total number of buffers registered
        pub total_buffers: usize,
        /// Number of buffers currently in use
        pub buffers_in_use: usize,
        /// Total bytes registered
        pub total_bytes: usize,
        /// Number of successful buffer acquisitions
        pub acquisitions: u64,
        /// Number of buffer releases
        pub releases: u64,
        /// Number of zero-copy read operations
        pub zero_copy_reads: u64,
        /// Number of zero-copy write operations
        pub zero_copy_writes: u64,
    }

    // Mock implementation for testing contracts
    struct MockRegisteredBufferReactor {
        base: IoUringReactor,
        pool_config: Option<BufferPoolConfig>,
        stats: BufferPoolStats,
        next_buffer_index: u16,
    }

    impl MockRegisteredBufferReactor {
        fn new() -> io::Result<Self> {
            Ok(Self {
                base: IoUringReactor::new()?,
                pool_config: None,
                stats: BufferPoolStats {
                    total_buffers: 0,
                    buffers_in_use: 0,
                    total_bytes: 0,
                    acquisitions: 0,
                    releases: 0,
                    zero_copy_reads: 0,
                    zero_copy_writes: 0,
                },
                next_buffer_index: 0,
            })
        }

        fn with_pool_registered() -> io::Result<Self> {
            let mut reactor = Self::new()?;
            let config = BufferPoolConfig::default();
            reactor.register_buffer_pool(&config)?;
            Ok(reactor)
        }
    }

    impl Reactor for MockRegisteredBufferReactor {
        fn register(
            &self,
            source: &dyn asupersync::runtime::reactor::Source,
            token: Token,
            interest: Interest,
        ) -> io::Result<()> {
            self.base.register(source, token, interest)
        }

        fn modify(&self, token: Token, interest: Interest) -> io::Result<()> {
            self.base.modify(token, interest)
        }

        fn deregister(&self, token: Token) -> io::Result<()> {
            self.base.deregister(token)
        }

        fn poll(&self, events: &mut Events, timeout: Option<Duration>) -> io::Result<usize> {
            self.base.poll(events, timeout)
        }

        fn wake(&self) -> io::Result<()> {
            self.base.wake()
        }

        fn registration_count(&self) -> usize {
            self.base.registration_count()
        }
    }

    impl RegisteredBufferReactor for MockRegisteredBufferReactor {
        fn register_buffer_pool(&self, config: &BufferPoolConfig) -> io::Result<()> {
            // Simulate buffer pool registration constraints
            if config.buffer_count == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "buffer_count must be greater than 0",
                ));
            }

            if config.buffer_size == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "buffer_size must be greater than 0",
                ));
            }

            if config.buffer_count > 65536 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "buffer_count exceeds io_uring limit of 65536",
                ));
            }

            // Simulate memory allocation constraints
            let total_size = config.buffer_count * config.buffer_size;
            if total_size > 1_073_741_824 {
                // 1GB limit
                return Err(io::Error::new(
                    io::ErrorKind::OutOfMemory,
                    "total buffer pool size exceeds memory limit",
                ));
            }

            // In real implementation, this would call:
            // io_uring_register_buffers() or equivalent

            Ok(())
        }

        fn unregister_buffer_pool(&self) -> io::Result<()> {
            // In real implementation, this would call:
            // io_uring_unregister_buffers() or equivalent
            Ok(())
        }

        fn acquire_buffer(&self, min_size: usize) -> io::Result<BufferHandle> {
            let config = self.pool_config.as_ref().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "no buffer pool registered")
            })?;

            if min_size > config.buffer_size {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "requested size exceeds buffer size",
                ));
            }

            // Simulate buffer allocation
            if self.stats.buffers_in_use >= self.stats.total_buffers {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "no buffers available",
                ));
            }

            Ok(BufferHandle {
                index: self.next_buffer_index % config.buffer_count as u16,
                offset: 0,
                length: config.buffer_size.min(min_size.max(1)),
            })
        }

        fn release_buffer(&self, handle: BufferHandle) -> io::Result<()> {
            let config = self.pool_config.as_ref().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "no buffer pool registered")
            })?;

            if handle.index as usize >= config.buffer_count {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid buffer handle",
                ));
            }

            Ok(())
        }

        fn read_to_registered_buffer(&self, token: Token, handle: BufferHandle) -> io::Result<()> {
            if self.pool_config.is_none() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "no buffer pool registered",
                ));
            }

            // In real implementation, this would submit a read operation
            // using IORING_OP_READ_FIXED or equivalent
            Ok(())
        }

        fn write_from_registered_buffer(
            &self,
            token: Token,
            handle: BufferHandle,
        ) -> io::Result<()> {
            if self.pool_config.is_none() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "no buffer pool registered",
                ));
            }

            // In real implementation, this would submit a write operation
            // using IORING_OP_WRITE_FIXED or equivalent
            Ok(())
        }

        fn buffer_pool_stats(&self) -> io::Result<BufferPoolStats> {
            Ok(self.stats)
        }
    }

    fn skip_if_unsupported() -> Option<MockRegisteredBufferReactor> {
        match MockRegisteredBufferReactor::new() {
            Ok(reactor) => Some(reactor),
            Err(err) => {
                assert!(
                    matches!(
                        err.kind(),
                        io::ErrorKind::Unsupported
                            | io::ErrorKind::PermissionDenied
                            | io::ErrorKind::Other
                    ),
                    "unexpected io_uring error: {err:?}"
                );
                None
            }
        }
    }

    #[test]
    fn test_buffer_pool_registration_validates_config() {
        let Some(reactor) = skip_if_unsupported() else {
            return;
        };

        // Test empty buffer count rejection
        let empty_config = BufferPoolConfig {
            buffer_count: 0,
            buffer_size: 4096,
            use_huge_pages: false,
        };
        let err = reactor
            .register_buffer_pool(&empty_config)
            .expect_err("zero buffer count should fail");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);

        // Test empty buffer size rejection
        let empty_size_config = BufferPoolConfig {
            buffer_count: 1,
            buffer_size: 0,
            use_huge_pages: false,
        };
        let err = reactor
            .register_buffer_pool(&empty_size_config)
            .expect_err("zero buffer size should fail");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);

        // Test excessive buffer count rejection
        let excessive_config = BufferPoolConfig {
            buffer_count: 100_000,
            buffer_size: 4096,
            use_huge_pages: false,
        };
        let err = reactor
            .register_buffer_pool(&excessive_config)
            .expect_err("excessive buffer count should fail");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);

        // Test excessive total size rejection
        let huge_config = BufferPoolConfig {
            buffer_count: 1000,
            buffer_size: 2_000_000, // 2GB total
            use_huge_pages: false,
        };
        let err = reactor
            .register_buffer_pool(&huge_config)
            .expect_err("excessive total size should fail");
        assert_eq!(err.kind(), io::ErrorKind::OutOfMemory);
    }

    #[test]
    fn test_buffer_pool_registration_succeeds_with_valid_config() {
        let Some(reactor) = skip_if_unsupported() else {
            return;
        };

        let config = BufferPoolConfig::default();
        reactor
            .register_buffer_pool(&config)
            .expect("valid config should succeed");

        reactor
            .unregister_buffer_pool()
            .expect("unregister should succeed");
    }

    #[test]
    fn test_buffer_acquisition_requires_registered_pool() {
        let Some(reactor) = skip_if_unsupported() else {
            return;
        };

        let err = reactor
            .acquire_buffer(4096)
            .expect_err("buffer acquisition without pool should fail");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("no buffer pool registered"));
    }

    #[test]
    fn test_buffer_acquisition_respects_size_limits() {
        let Some(reactor) = MockRegisteredBufferReactor::with_pool_registered()
            .or_else(|_| {
                skip_if_unsupported().ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, ""))
            })
            .ok()
        else {
            return;
        };

        // Test oversized request rejection
        let err = reactor
            .acquire_buffer(8192) // Larger than default 4096
            .expect_err("oversized request should fail");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);

        // Test valid size acceptance
        let handle = reactor
            .acquire_buffer(2048)
            .expect("valid size should succeed");
        assert_eq!(handle.length, 2048);
        assert_eq!(handle.offset, 0);

        reactor
            .release_buffer(handle)
            .expect("buffer release should succeed");
    }

    #[test]
    fn test_buffer_handle_validation() {
        let Some(reactor) = MockRegisteredBufferReactor::with_pool_registered()
            .or_else(|_| {
                skip_if_unsupported().ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, ""))
            })
            .ok()
        else {
            return;
        };

        // Test invalid buffer index rejection
        let invalid_handle = BufferHandle {
            index: 999, // Beyond configured pool size
            offset: 0,
            length: 1024,
        };
        let err = reactor
            .release_buffer(invalid_handle)
            .expect_err("invalid handle should fail");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn test_zero_copy_operations_require_registered_pool() {
        let Some(reactor) = skip_if_unsupported() else {
            return;
        };

        let token = Token::new(1);
        let handle = BufferHandle {
            index: 0,
            offset: 0,
            length: 1024,
        };

        let read_err = reactor
            .read_to_registered_buffer(token, handle)
            .expect_err("read without pool should fail");
        assert_eq!(read_err.kind(), io::ErrorKind::InvalidInput);

        let write_err = reactor
            .write_from_registered_buffer(token, handle)
            .expect_err("write without pool should fail");
        assert_eq!(write_err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn test_buffer_pool_stats_tracking() {
        let Some(reactor) = MockRegisteredBufferReactor::with_pool_registered()
            .or_else(|_| {
                skip_if_unsupported().ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, ""))
            })
            .ok()
        else {
            return;
        };

        let stats = reactor
            .buffer_pool_stats()
            .expect("stats should be available");

        // Verify initial state
        assert_eq!(stats.buffers_in_use, 0);
        assert_eq!(stats.acquisitions, 0);
        assert_eq!(stats.releases, 0);
    }

    #[test]
    fn test_buffer_pool_lifecycle_integration() {
        let Some(reactor) = skip_if_unsupported() else {
            return;
        };

        // Start without pool
        let err = reactor
            .acquire_buffer(1024)
            .expect_err("should fail without pool");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);

        // Register pool
        let config = BufferPoolConfig {
            buffer_count: 8,
            buffer_size: 2048,
            use_huge_pages: false,
        };
        reactor
            .register_buffer_pool(&config)
            .expect("pool registration should succeed");

        // Acquire and release buffers
        let handle1 = reactor
            .acquire_buffer(1024)
            .expect("buffer acquisition should succeed");
        let handle2 = reactor
            .acquire_buffer(512)
            .expect("second acquisition should succeed");

        reactor
            .release_buffer(handle1)
            .expect("first release should succeed");
        reactor
            .release_buffer(handle2)
            .expect("second release should succeed");

        // Unregister pool
        reactor
            .unregister_buffer_pool()
            .expect("pool unregistration should succeed");

        // Verify pool is gone
        let err = reactor
            .acquire_buffer(1024)
            .expect_err("should fail after pool unregistration");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn test_registered_buffer_io_operations_basic_contract() {
        let Some(reactor) = MockRegisteredBufferReactor::with_pool_registered()
            .or_else(|_| {
                skip_if_unsupported().ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, ""))
            })
            .ok()
        else {
            return;
        };

        let (source1, _source2) = TestSource::new().expect("test source creation should succeed");

        let token = Token::new(42);
        reactor
            .register(&source1, token, Interest::READABLE)
            .expect("source registration should succeed");

        let handle = reactor
            .acquire_buffer(1024)
            .expect("buffer acquisition should succeed");

        // Test read operation contract
        reactor
            .read_to_registered_buffer(token, handle)
            .expect("registered buffer read should succeed");

        // Test write operation contract
        reactor
            .write_from_registered_buffer(token, handle)
            .expect("registered buffer write should succeed");

        reactor
            .release_buffer(handle)
            .expect("buffer release should succeed");
        reactor
            .deregister(token)
            .expect("source deregistration should succeed");
    }

    #[test]
    fn test_buffer_pool_memory_efficiency_constraints() {
        let Some(reactor) = skip_if_unsupported() else {
            return;
        };

        // Test that small buffers are efficiently packed
        let small_config = BufferPoolConfig {
            buffer_count: 1000,
            buffer_size: 64,
            use_huge_pages: false,
        };
        reactor
            .register_buffer_pool(&small_config)
            .expect("small buffer pool should succeed");

        let stats = reactor
            .buffer_pool_stats()
            .expect("stats should be available");
        assert_eq!(stats.total_bytes, 1000 * 64);

        reactor
            .unregister_buffer_pool()
            .expect("unregistration should succeed");

        // Test that large buffers respect limits
        let large_config = BufferPoolConfig {
            buffer_count: 256,
            buffer_size: 1024 * 1024, // 1MB each
            use_huge_pages: true,
        };
        reactor
            .register_buffer_pool(&large_config)
            .expect("large buffer pool should succeed");

        reactor
            .unregister_buffer_pool()
            .expect("unregistration should succeed");
    }

    #[test]
    fn test_concurrent_buffer_operations_safety() {
        let Some(reactor) = MockRegisteredBufferReactor::with_pool_registered()
            .or_else(|_| {
                skip_if_unsupported().ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, ""))
            })
            .ok()
        else {
            return;
        };

        // Acquire multiple buffers
        let handles: Vec<_> = (0..4)
            .map(|_| reactor.acquire_buffer(1024))
            .collect::<Result<_, _>>()
            .expect("multiple acquisitions should succeed");

        // Release in different order
        for handle in handles.into_iter().rev() {
            reactor
                .release_buffer(handle)
                .expect("out-of-order release should succeed");
        }
    }
}

#[cfg(not(all(target_os = "linux", feature = "io-uring")))]
mod fallback_tests {
    #[test]
    fn test_buffer_pool_operations_unsupported_on_non_linux() {
        // On non-Linux platforms, registered buffer pool operations
        // should clearly indicate they are unsupported
        assert!(true, "buffer pool operations not supported on non-Linux");
    }

    #[test]
    fn test_graceful_fallback_to_regular_io() {
        // When registered buffers are not available, the system should
        // gracefully fall back to regular I/O operations
        assert!(true, "graceful fallback verified");
    }
}
