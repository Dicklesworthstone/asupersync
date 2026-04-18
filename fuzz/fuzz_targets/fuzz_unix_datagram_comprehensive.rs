//! Comprehensive Unix datagram socket fuzzing for edge cases and platform-specific functionality.
//!
//! Targets: src/net/unix/datagram.rs and src/net/unix/ancillary.rs
//! Coverage: (1) socket creation and binding; (2) address validation and edge cases;
//!          (3) SCM_RIGHTS ancillary data structure; (4) abstract-namespace addresses (Linux);
//!          (5) connection state management.
//!
//! # Attack Vectors Tested
//! - Socket binding to malformed paths and edge case addresses
//! - Abstract namespace path validation and injection attempts (Linux-only)
//! - Socket pair creation and connection edge cases
//! - Address parsing, validation and connection state management
//! - File descriptor reference handling and resource cleanup
//! - Ancillary data structure validation and overflow detection
//! - Socket option and timeout configuration edge cases

#![no_main]

use arbitrary::Arbitrary;
use asupersync::net::unix::{SocketAncillary, UnixDatagram};
use libfuzzer_sys::fuzz_target;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::PathBuf;
use std::time::Duration;

/// Maximum path length for performance during fuzzing
const MAX_PATH_LENGTH: usize = 108; // Unix socket path limit

/// Maximum number of file descriptors to test
const MAX_FDS: usize = 8;

/// Unix datagram fuzz configuration
#[derive(Debug, Arbitrary)]
struct UnixDatagramFuzzConfig {
    /// Sequence of operations to test
    operations: Vec<DatagramOperation>,
}

/// Test operations for Unix datagrams
#[derive(Debug, Arbitrary)]
enum DatagramOperation {
    /// Test socket creation patterns
    CreateSocket(SocketCreationTest),
    /// Test binding operations
    BindSocket(BindingTest),
    /// Test connection operations
    ConnectSocket(ConnectionTest),
    /// Test address operations
    AddressTest(AddressTest),
    /// Test ancillary data operations
    AncillaryDataTest(AncillaryTest),
    /// Test socket option operations
    SocketOptionsTest(SocketOptionsTest),
    /// Test timeout operations
    TimeoutTest(TimeoutTest),
}

/// Socket creation test patterns
#[derive(Debug, Arbitrary)]
enum SocketCreationTest {
    /// Create unbound socket
    Unbound,
    /// Create socket pair
    Pair,
    /// Create bound socket
    Bound { path: FuzzPath },
    /// Create abstract namespace socket (Linux)
    Abstract { name: Vec<u8> },
}

/// Binding test patterns
#[derive(Debug, Arbitrary)]
struct BindingTest {
    /// Path to bind to
    path: FuzzPath,
    /// Whether to test double binding
    double_bind: bool,
}

/// Connection test patterns
#[derive(Debug, Arbitrary)]
struct ConnectionTest {
    /// Target path for connection
    target_path: FuzzPath,
    /// Whether to use abstract namespace
    use_abstract: bool,
    /// Abstract namespace name (if use_abstract)
    abstract_name: Vec<u8>,
    /// Whether to test connection to non-existent target
    test_nonexistent: bool,
}

/// Address validation test patterns
#[derive(Debug, Arbitrary)]
enum AddressTest {
    /// Test local address retrieval
    LocalAddress,
    /// Test peer address retrieval
    PeerAddress,
    /// Test peer credentials (Linux)
    PeerCredentials,
}

/// Ancillary data test patterns
#[derive(Debug, Arbitrary)]
struct AncillaryTest {
    /// File descriptors to add
    fd_count: u8,
    /// Whether to test truncation
    test_truncation: bool,
    /// Buffer size for ancillary data
    buffer_size: u16,
}

/// Socket options test patterns
#[derive(Debug, Arbitrary)]
enum SocketOptionsTest {
    /// Test socket file descriptor access
    AccessFd,
    /// Test path retrieval
    GetPath,
    /// Test take path operation
    TakePath,
}

/// Timeout test patterns
#[derive(Debug, Arbitrary)]
struct TimeoutTest {
    /// Read timeout configuration
    read_timeout: Option<u64>,
    /// Write timeout configuration
    write_timeout: Option<u64>,
    /// Whether to test timeout retrieval
    test_get_timeout: bool,
}

/// Fuzzed path for socket binding
#[derive(Debug, Arbitrary)]
struct FuzzPath {
    /// Path components
    components: Vec<String>,
    /// Whether to include null bytes
    include_nulls: bool,
    /// Whether to include unicode
    include_unicode: bool,
    /// Whether to test very long paths
    test_long_path: bool,
}

impl FuzzPath {
    /// Convert to a PathBuf, normalizing for testing
    fn to_path_buf(&self) -> PathBuf {
        if self.components.is_empty() {
            return PathBuf::from("/tmp/fuzz_socket_default");
        }

        let mut path = PathBuf::from("/tmp");
        for component in &self.components {
            let mut cleaned = component.clone();

            // Limit length for performance
            if cleaned.len() > MAX_PATH_LENGTH / 4 {
                cleaned.truncate(MAX_PATH_LENGTH / 4);
            }

            // Handle null bytes
            if !self.include_nulls {
                cleaned = cleaned.replace('\0', "_");
            }

            // Handle unicode edge cases
            if !self.include_unicode {
                cleaned = cleaned.chars()
                    .filter(|c| c.is_ascii() && !c.is_control())
                    .collect();
            }

            if cleaned.is_empty() {
                cleaned = "empty".to_string();
            }

            path.push(cleaned);
        }

        // Handle very long path testing
        if self.test_long_path {
            let mut long_component = "very_long_component_".repeat(10);
            if long_component.len() > MAX_PATH_LENGTH - path.as_os_str().len() - 10 {
                long_component.truncate(MAX_PATH_LENGTH - path.as_os_str().len() - 10);
            }
            if !long_component.is_empty() {
                path.push(long_component);
            }
        }

        // Ensure total path length is reasonable
        if path.as_os_str().len() > MAX_PATH_LENGTH {
            PathBuf::from("/tmp/fuzz_socket_truncated")
        } else {
            path
        }
    }
}

/// Test context for managing resources
struct TestContext {
    /// Created sockets for cleanup
    sockets: Vec<UnixDatagram>,
    /// Created socket files for cleanup
    socket_paths: Vec<PathBuf>,
    /// Test file descriptors
    test_fds: Vec<RawFd>,
}

impl TestContext {
    fn new() -> Self {
        Self {
            sockets: Vec::new(),
            socket_paths: Vec::new(),
            test_fds: Vec::new(),
        }
    }

    fn add_socket(&mut self, socket: UnixDatagram) {
        self.sockets.push(socket);
    }

    fn add_socket_path(&mut self, path: PathBuf) {
        self.socket_paths.push(path);
    }

    fn add_test_fd(&mut self, fd: RawFd) {
        self.test_fds.push(fd);
    }
}

impl Drop for TestContext {
    fn drop(&mut self) {
        // Cleanup is automatic for UnixDatagram sockets
        // Clean up any remaining socket files
        for path in &self.socket_paths {
            let _ = std::fs::remove_file(path);
        }
    }
}

fuzz_target!(|config: UnixDatagramFuzzConfig| {
    // Limit operations for performance
    if config.operations.len() > 50 {
        return;
    }

    let mut context = TestContext::new();

    for operation in config.operations {
        let _ = execute_operation(operation, &mut context);
    }
});

/// Execute a single datagram operation
fn execute_operation(operation: DatagramOperation, context: &mut TestContext) -> Result<(), Box<dyn std::error::Error>> {
    match operation {
        DatagramOperation::CreateSocket(test) => execute_socket_creation(test, context),
        DatagramOperation::BindSocket(test) => execute_binding_test(test, context),
        DatagramOperation::ConnectSocket(test) => execute_connection_test(test, context),
        DatagramOperation::AddressTest(test) => execute_address_test(test, context),
        DatagramOperation::AncillaryDataTest(test) => execute_ancillary_test(test, context),
        DatagramOperation::SocketOptionsTest(test) => execute_socket_options_test(test, context),
        DatagramOperation::TimeoutTest(test) => execute_timeout_test(test, context),
    }
}

/// Test socket creation patterns
fn execute_socket_creation(test: SocketCreationTest, context: &mut TestContext) -> Result<(), Box<dyn std::error::Error>> {
    match test {
        SocketCreationTest::Unbound => {
            let socket = UnixDatagram::unbound()?;
            context.add_socket(socket);
        }
        SocketCreationTest::Pair => {
            let (socket_a, socket_b) = UnixDatagram::pair()?;
            context.add_socket(socket_a);
            context.add_socket(socket_b);
        }
        SocketCreationTest::Bound { path } => {
            let path_buf = path.to_path_buf();
            // Remove any existing socket file
            let _ = std::fs::remove_file(&path_buf);

            match UnixDatagram::bind(&path_buf) {
                Ok(socket) => {
                    context.add_socket(socket);
                    context.add_socket_path(path_buf);
                }
                Err(_) => {
                    // Expected for malformed paths
                }
            }
        }
        SocketCreationTest::Abstract { name } => {
            // Test abstract namespace sockets (Linux-only)
            #[cfg(target_os = "linux")]
            {
                let limited_name: Vec<u8> = name.into_iter().take(100).collect();
                match UnixDatagram::bind_abstract(&limited_name) {
                    Ok(socket) => {
                        context.add_socket(socket);
                    }
                    Err(_) => {
                        // Expected for malformed names
                    }
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                // Abstract namespace not supported on non-Linux
                let _ = name;
            }
        }
    }
    Ok(())
}

/// Test binding operations
fn execute_binding_test(test: BindingTest, context: &mut TestContext) -> Result<(), Box<dyn std::error::Error>> {
    let path_buf = test.path.to_path_buf();

    // Remove any existing socket file
    let _ = std::fs::remove_file(&path_buf);

    match UnixDatagram::bind(&path_buf) {
        Ok(socket) => {
            context.add_socket_path(path_buf.clone());

            if test.double_bind {
                // Test double binding to the same path
                let _ = UnixDatagram::bind(&path_buf);
            }

            context.add_socket(socket);
        }
        Err(_) => {
            // Expected for malformed paths
        }
    }

    Ok(())
}

/// Test connection operations
fn execute_connection_test(test: ConnectionTest, context: &mut TestContext) -> Result<(), Box<dyn std::error::Error>> {
    let socket = UnixDatagram::unbound()?;

    if test.use_abstract {
        #[cfg(target_os = "linux")]
        {
            let limited_name: Vec<u8> = test.abstract_name.into_iter().take(100).collect();
            let _ = socket.connect_abstract(&limited_name);
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = test.abstract_name;
        }
    } else {
        let target_path = test.target_path.to_path_buf();

        if test.test_nonexistent {
            // Test connection to non-existent socket
            let _ = socket.connect(&target_path);
        } else {
            // Create target socket first
            let _ = std::fs::remove_file(&target_path);
            if let Ok(target_socket) = UnixDatagram::bind(&target_path) {
                context.add_socket_path(target_path.clone());
                let _ = socket.connect(&target_path);
                context.add_socket(target_socket);
            }
        }
    }

    context.add_socket(socket);
    Ok(())
}

/// Test address operations
fn execute_address_test(test: AddressTest, context: &mut TestContext) -> Result<(), Box<dyn std::error::Error>> {
    let (socket_a, socket_b) = UnixDatagram::pair()?;

    match test {
        AddressTest::LocalAddress => {
            let _ = socket_a.local_addr();
            let _ = socket_b.local_addr();
        }
        AddressTest::PeerAddress => {
            let _ = socket_a.peer_addr();
            let _ = socket_b.peer_addr();
        }
        AddressTest::PeerCredentials => {
            let _ = socket_a.peer_cred();
            let _ = socket_b.peer_cred();
        }
    }

    context.add_socket(socket_a);
    context.add_socket(socket_b);
    Ok(())
}

/// Test ancillary data operations
fn execute_ancillary_test(test: AncillaryTest, context: &mut TestContext) -> Result<(), Box<dyn std::error::Error>> {
    let fd_count = (test.fd_count as usize).min(MAX_FDS);
    let buffer_size = test.buffer_size.clamp(64, 2048) as usize;

    // Create test file descriptors
    let mut test_fds = Vec::new();
    for _ in 0..fd_count {
        // Duplicate stdin as test fd
        let fd = unsafe { libc::dup(0) };
        if fd >= 0 {
            test_fds.push(fd);
        }
    }

    // Test SocketAncillary operations
    let mut ancillary = SocketAncillary::new(buffer_size);

    // Test adding file descriptors
    if !test_fds.is_empty() {
        let _ = ancillary.add_fds(&test_fds);
    }

    // Test truncation behavior
    if test.test_truncation {
        // Try to add more FDs than the buffer can hold
        let large_fd_list: Vec<RawFd> = (0..100).collect();
        let _ = ancillary.add_fds(&large_fd_list);
    }

    // Cleanup test file descriptors
    for fd in test_fds {
        unsafe { libc::close(fd); }
    }

    Ok(())
}

/// Test socket options
fn execute_socket_options_test(test: SocketOptionsTest, context: &mut TestContext) -> Result<(), Box<dyn std::error::Error>> {
    let socket = UnixDatagram::unbound()?;

    match test {
        SocketOptionsTest::AccessFd => {
            let _ = socket.as_raw_fd();
            let _ = socket.as_std();
        }
        SocketOptionsTest::GetPath => {
            // Test on bound socket
            let test_path = PathBuf::from("/tmp/fuzz_socket_options");
            let _ = std::fs::remove_file(&test_path);

            if let Ok(bound_socket) = UnixDatagram::bind(&test_path) {
                // Path should be available for bound socket
                context.add_socket_path(test_path);
                context.add_socket(bound_socket);
            }
        }
        SocketOptionsTest::TakePath => {
            let test_path = PathBuf::from("/tmp/fuzz_socket_take_path");
            let _ = std::fs::remove_file(&test_path);

            if let Ok(mut bound_socket) = UnixDatagram::bind(&test_path) {
                // Take path should return the path
                let taken_path = bound_socket.take_path();
                if taken_path.is_some() {
                    // After taking, path should be None
                    let second_take = bound_socket.take_path();
                    assert!(second_take.is_none());
                }
                context.add_socket_path(test_path);
                context.add_socket(bound_socket);
            }
        }
    }

    context.add_socket(socket);
    Ok(())
}

/// Test timeout operations
fn execute_timeout_test(test: TimeoutTest, context: &mut TestContext) -> Result<(), Box<dyn std::error::Error>> {
    let socket = UnixDatagram::unbound()?;

    // Test read timeout
    if let Some(read_ms) = test.read_timeout {
        let duration = Duration::from_millis(read_ms.min(5000)); // Limit for performance
        let _ = socket.set_read_timeout(Some(duration));

        if test.test_get_timeout {
            let _ = socket.read_timeout();
        }
    }

    // Test write timeout
    if let Some(write_ms) = test.write_timeout {
        let duration = Duration::from_millis(write_ms.min(5000)); // Limit for performance
        let _ = socket.set_write_timeout(Some(duration));

        if test.test_get_timeout {
            let _ = socket.write_timeout();
        }
    }

    // Test clearing timeouts
    let _ = socket.set_read_timeout(None);
    let _ = socket.set_write_timeout(None);

    context.add_socket(socket);
    Ok(())
}