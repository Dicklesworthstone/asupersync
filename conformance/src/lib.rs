//! Asupersync Conformance Test Suite
//!
// Allow type complexity for trait method return types - these are intentionally
// verbose to be explicit about the async behavior and lifetimes
#![allow(clippy::type_complexity)]
//!
//! This crate provides a conformance test suite for async runtime implementations.
//! Tests are designed to verify that runtimes correctly implement the expected
//! semantics for spawning, channels, I/O, synchronization, and cancellation.
//!
//! # Architecture
//!
//! The test suite is runtime-agnostic. Each runtime must implement the
//! `RuntimeInterface` trait to provide the necessary primitives. Tests are
//! written against this interface, allowing the same tests to validate
//! different runtime implementations.
//!
//! # Test Categories
//!
//! - `Spawn`: Task spawning and join handles
//! - `Channels`: MPSC, oneshot, broadcast, and watch channels
//! - `IO`: File operations, TCP, and UDP networking
//! - `Sync`: Mutex, RwLock, Semaphore, Barrier, OnceCell
//! - `Time`: Sleep, timeout, interval
//! - `Cancel`: Cancellation token and cooperative cancellation

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::fmt;
use std::future::Future;
use std::io::{self, SeekFrom};
use std::net::SocketAddr;
use std::path::Path;
use std::pin::Pin;
use std::time::Duration;

pub mod bench;
pub mod logging;
pub mod report;
pub mod runner;
pub mod tests;
pub mod traceability;

pub use bench::{
    default_benchmarks, run_benchmark_comparison, BenchAllocSnapshot, BenchAllocStats,
    BenchCategory, BenchComparisonResult, BenchComparisonSummary, BenchConfig, BenchOutput,
    BenchRunResult, BenchRunSummary, BenchRunner, BenchThresholds, Benchmark, Comparison,
    ComparisonConfidence, RegressionCheck, RegressionConfig, RegressionMetric, Stats, StatsError,
};
pub use logging::{
    ConformanceTestLogger, LogCollector, LogConfig, LogEntry, LogLevel, TestEvent,
    TestEventKind,
};
pub use report::{render_console_summary, write_json_report};
pub use runner::{
    compare_results, run_comparison, ComparisonResult, ComparisonStatus, ComparisonSummary,
    RunConfig, RunSummary, SingleRunResult, SuiteResult, SuiteTestResult, TestRunner,
    run_conformance_suite,
};
pub use traceability::{
    CiReport, CoverageStats, SpecRequirement, TraceabilityEntry, TraceabilityMatrix,
    TraceabilityMatrixBuilder,
};

// ============================================================================
// Test Result Types
// ============================================================================

/// Result of a conformance test execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestResult {
    /// Whether the test passed.
    pub passed: bool,
    /// Optional failure message.
    pub message: Option<String>,
    /// Checkpoints recorded during test execution.
    pub checkpoints: Vec<Checkpoint>,
    /// Duration of test execution.
    pub duration_ms: Option<u64>,
}

impl TestResult {
    /// Create a passing test result.
    pub fn passed() -> Self {
        Self {
            passed: true,
            message: None,
            checkpoints: Vec::new(),
            duration_ms: None,
        }
    }

    /// Create a failing test result with a message.
    pub fn failed(message: impl Into<String>) -> Self {
        Self {
            passed: false,
            message: Some(message.into()),
            checkpoints: Vec::new(),
            duration_ms: None,
        }
    }

    /// Add a checkpoint to the result.
    pub fn with_checkpoint(mut self, checkpoint: Checkpoint) -> Self {
        self.checkpoints.push(checkpoint);
        self
    }

    /// Set the duration.
    pub fn with_duration(mut self, duration_ms: u64) -> Self {
        self.duration_ms = Some(duration_ms);
        self
    }
}

/// A checkpoint recorded during test execution.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Name of the checkpoint.
    pub name: String,
    /// Data associated with the checkpoint.
    pub data: serde_json::Value,
}

impl Checkpoint {
    /// Create a new checkpoint.
    pub fn new(name: impl Into<String>, data: serde_json::Value) -> Self {
        Self {
            name: name.into(),
            data,
        }
    }
}

/// Helper function to record a checkpoint.
pub fn checkpoint(name: &str, data: serde_json::Value) {
    let _ = Checkpoint::new(name, data.clone());
    crate::logging::record_checkpoint(name, data);
}

// ============================================================================
// Test Categories
// ============================================================================

/// Categories of conformance tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TestCategory {
    /// Task spawning and join handles.
    Spawn,
    /// Channel primitives (MPSC, oneshot, broadcast, watch).
    Channels,
    /// I/O operations (file, TCP, UDP).
    IO,
    /// Synchronization primitives (Mutex, RwLock, etc.).
    Sync,
    /// Time-related operations (sleep, timeout).
    Time,
    /// Cancellation mechanisms.
    Cancel,
}

impl fmt::Display for TestCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TestCategory::Spawn => write!(f, "spawn"),
            TestCategory::Channels => write!(f, "channels"),
            TestCategory::IO => write!(f, "io"),
            TestCategory::Sync => write!(f, "sync"),
            TestCategory::Time => write!(f, "time"),
            TestCategory::Cancel => write!(f, "cancel"),
        }
    }
}

// ============================================================================
// Test Metadata
// ============================================================================

/// Metadata for a conformance test.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestMeta {
    /// Unique identifier for the test.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Description of what the test validates.
    pub description: String,
    /// Category of the test.
    pub category: TestCategory,
    /// Tags for filtering.
    pub tags: Vec<String>,
    /// Expected behavior description.
    pub expected: String,
}

// ============================================================================
// Runtime Interface
// ============================================================================

/// Trait that async runtimes must implement to run conformance tests.
///
/// This trait provides the common primitives that tests require. Each method
/// returns a concrete type that the runtime provides.
pub trait RuntimeInterface: Sized {
    // ---- Core Types ----
    /// Join handle for spawned tasks.
    type JoinHandle<T: Send + 'static>: Future<Output = T> + Send + 'static;

    /// MPSC sender.
    type MpscSender<T: Send + 'static>: MpscSender<T> + 'static;

    /// MPSC receiver.
    type MpscReceiver<T: Send + 'static>: MpscReceiver<T> + 'static;

    /// Oneshot sender.
    type OneshotSender<T: Send + 'static>: OneshotSender<T> + 'static;

    /// Oneshot receiver.
    type OneshotReceiver<T: Send + 'static>: Future<Output = Result<T, OneshotRecvError>>
        + Send
        + 'static;

    /// Broadcast sender.
    type BroadcastSender<T: Send + Clone + 'static>: BroadcastSender<T> + 'static;

    /// Broadcast receiver.
    type BroadcastReceiver<T: Send + Clone + 'static>: BroadcastReceiver<T> + 'static;

    /// Watch sender.
    type WatchSender<T: Send + Sync + 'static>: WatchSender<T> + 'static;

    /// Watch receiver.
    type WatchReceiver<T: Send + Sync + Clone + 'static>: WatchReceiver<T> + 'static;

    /// Async file handle.
    type File: AsyncFile + 'static;

    /// TCP listener.
    type TcpListener: TcpListener<Stream = Self::TcpStream> + 'static;

    /// TCP stream.
    type TcpStream: TcpStream + 'static;

    /// UDP socket.
    type UdpSocket: UdpSocket + 'static;

    // ---- Spawn ----
    /// Spawn an async task.
    fn spawn<F>(&self, future: F) -> Self::JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static;

    // ---- Block On ----
    /// Block on a future until it completes.
    fn block_on<F: Future>(&self, future: F) -> F::Output;

    /// Snapshot allocation counters for benchmarking (if supported).
    fn bench_alloc_snapshot(&self) -> Option<crate::bench::runner::BenchAllocSnapshot> {
        None
    }

    // ---- Time ----
    /// Sleep for a duration.
    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;

    /// Run a future with a timeout.
    fn timeout<'a, F: Future + Send + 'a>(
        &'a self,
        duration: Duration,
        future: F,
    ) -> Pin<Box<dyn Future<Output = Result<F::Output, TimeoutError>> + Send + 'a>>
    where
        F::Output: Send;

    // ---- Channels ----
    /// Create an MPSC channel with the given capacity.
    fn mpsc_channel<T: Send + 'static>(
        &self,
        capacity: usize,
    ) -> (Self::MpscSender<T>, Self::MpscReceiver<T>);

    /// Create a oneshot channel.
    fn oneshot_channel<T: Send + 'static>(
        &self,
    ) -> (Self::OneshotSender<T>, Self::OneshotReceiver<T>);

    /// Create a broadcast channel.
    fn broadcast_channel<T: Send + Clone + 'static>(
        &self,
        capacity: usize,
    ) -> (Self::BroadcastSender<T>, Self::BroadcastReceiver<T>);

    /// Create a watch channel.
    fn watch_channel<T: Send + Sync + Clone + 'static>(
        &self,
        initial: T,
    ) -> (Self::WatchSender<T>, Self::WatchReceiver<T>);

    // ---- File I/O ----
    /// Create a file for writing.
    fn file_create<'a>(
        &'a self,
        path: &'a Path,
    ) -> Pin<Box<dyn Future<Output = io::Result<Self::File>> + Send + 'a>>;

    /// Open a file for reading.
    fn file_open<'a>(
        &'a self,
        path: &'a Path,
    ) -> Pin<Box<dyn Future<Output = io::Result<Self::File>> + Send + 'a>>;

    // ---- Network ----
    /// Bind a TCP listener to an address.
    fn tcp_listen<'a>(
        &'a self,
        addr: &'a str,
    ) -> Pin<Box<dyn Future<Output = io::Result<Self::TcpListener>> + Send + 'a>>;

    /// Connect to a TCP address.
    fn tcp_connect<'a>(
        &'a self,
        addr: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<Self::TcpStream>> + Send + 'a>>;

    /// Bind a UDP socket to an address.
    fn udp_bind<'a>(
        &'a self,
        addr: &'a str,
    ) -> Pin<Box<dyn Future<Output = io::Result<Self::UdpSocket>> + Send + 'a>>;
}

// ============================================================================
// Channel Traits
// ============================================================================

/// Error when receiving from a closed oneshot channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OneshotRecvError;

impl fmt::Display for OneshotRecvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "oneshot channel sender dropped")
    }
}

impl std::error::Error for OneshotRecvError {}

/// MPSC sender trait.
pub trait MpscSender<T: Send>: Clone + Send + Sync {
    /// Send a value, waiting if the channel is full.
    fn send(&self, value: T) -> Pin<Box<dyn Future<Output = Result<(), T>> + Send + '_>>;
}

/// MPSC receiver trait.
pub trait MpscReceiver<T: Send>: Send {
    /// Receive a value, returning None if the channel is closed.
    fn recv(&mut self) -> Pin<Box<dyn Future<Output = Option<T>> + Send + '_>>;
}

/// Oneshot sender trait.
pub trait OneshotSender<T: Send>: Send {
    /// Send a value. Can only be called once.
    fn send(self, value: T) -> Result<(), T>;
}

/// Error when receiving from a closed broadcast channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BroadcastRecvError {
    /// The receiver lagged too far behind.
    Lagged(u64),
    /// The sender was dropped.
    Closed,
}

impl fmt::Display for BroadcastRecvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lagged(n) => write!(f, "receiver lagged by {n} messages"),
            Self::Closed => write!(f, "broadcast channel closed"),
        }
    }
}

impl std::error::Error for BroadcastRecvError {}

/// Broadcast sender trait.
pub trait BroadcastSender<T: Send + Clone>: Clone + Send + Sync {
    /// Send a value to all receivers.
    fn send(&self, value: T) -> Result<usize, T>;

    /// Create a new receiver.
    fn subscribe(&self) -> Box<dyn BroadcastReceiver<T>>;
}

/// Broadcast receiver trait.
pub trait BroadcastReceiver<T: Send + Clone>: Send {
    /// Receive a value.
    fn recv(&mut self) -> Pin<Box<dyn Future<Output = Result<T, BroadcastRecvError>> + Send + '_>>;
}

/// Error when receiving from a closed watch channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WatchRecvError;

impl fmt::Display for WatchRecvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "watch channel closed")
    }
}

impl std::error::Error for WatchRecvError {}

/// Watch sender trait.
pub trait WatchSender<T: Send + Sync>: Send + Sync {
    /// Send a new value.
    fn send(&self, value: T) -> Result<(), T>;
}

/// Watch receiver trait.
pub trait WatchReceiver<T: Send + Sync>: Clone + Send + Sync {
    /// Wait for a change.
    fn changed(&mut self) -> Pin<Box<dyn Future<Output = Result<(), WatchRecvError>> + Send + '_>>;

    /// Get the current value.
    fn borrow_and_clone(&self) -> T;
}

// ============================================================================
// File I/O Traits
// ============================================================================

/// Async file trait.
pub trait AsyncFile: Send {
    /// Write all bytes to the file.
    fn write_all<'a>(
        &'a mut self,
        buf: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>>;

    /// Read to fill the buffer exactly.
    fn read_exact<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>>;

    /// Read all bytes into a vector.
    fn read_to_end<'a>(
        &'a mut self,
        buf: &'a mut Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = io::Result<usize>> + Send + 'a>>;

    /// Seek to a position.
    fn seek<'a>(
        &'a mut self,
        pos: SeekFrom,
    ) -> Pin<Box<dyn Future<Output = io::Result<u64>> + Send + 'a>>;

    /// Sync all data to disk.
    fn sync_all(&self) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + '_>>;

    /// Shutdown the file (for sockets).
    fn shutdown(&mut self) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + '_>>;
}

// ============================================================================
// Network Traits
// ============================================================================

/// Timeout error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeoutError;

impl fmt::Display for TimeoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "operation timed out")
    }
}

impl std::error::Error for TimeoutError {}

/// TCP listener trait.
pub trait TcpListener: Send {
    /// The stream type returned by accept.
    type Stream: TcpStream;

    /// Get the local address.
    fn local_addr(&self) -> io::Result<SocketAddr>;

    /// Accept a connection.
    fn accept(
        &self,
    ) -> Pin<Box<dyn Future<Output = io::Result<(Self::Stream, SocketAddr)>> + Send + '_>>;
}

/// TCP stream trait.
pub trait TcpStream: Send {
    /// Read into a buffer.
    fn read<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<usize>> + Send + 'a>>;

    /// Read to fill the buffer exactly.
    fn read_exact<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>>;

    /// Write all bytes.
    fn write_all<'a>(
        &'a mut self,
        buf: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>>;

    /// Shutdown the stream.
    fn shutdown(&mut self) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + '_>>;
}

/// UDP socket trait.
pub trait UdpSocket: Send {
    /// Get the local address.
    fn local_addr(&self) -> io::Result<SocketAddr>;

    /// Send to an address.
    fn send_to<'a>(
        &'a self,
        buf: &'a [u8],
        addr: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<usize>> + Send + 'a>>;

    /// Receive from any address.
    fn recv_from<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<(usize, SocketAddr)>> + Send + 'a>>;
}

// ============================================================================
// Test Registration
// ============================================================================

/// A registered conformance test.
pub struct ConformanceTest<RT: RuntimeInterface> {
    /// Test metadata.
    pub meta: TestMeta,
    /// The test function.
    pub test_fn: fn(&RT) -> TestResult,
}

impl<RT: RuntimeInterface> ConformanceTest<RT> {
    /// Create a new conformance test.
    pub const fn new(meta: TestMeta, test_fn: fn(&RT) -> TestResult) -> Self {
        Self { meta, test_fn }
    }

    /// Run the test.
    pub fn run(&self, runtime: &RT) -> TestResult {
        (self.test_fn)(runtime)
    }
}

/// Macro for defining conformance tests.
///
/// # Example
///
/// ```ignore
/// conformance_test! {
///     id: "io-001",
///     name: "File write and read",
///     description: "Write data to file, read it back",
///     category: TestCategory::IO,
///     tags: ["file", "basic"],
///     expected: "Read data matches written data",
///     test: |rt| {
///         rt.block_on(async {
///             // test implementation
///             TestResult::passed()
///         })
///     }
/// }
/// ```
#[macro_export]
macro_rules! conformance_test {
    (
        id: $id:literal,
        name: $name:literal,
        description: $desc:literal,
        category: $cat:expr,
        tags: [$($tag:literal),* $(,)?],
        expected: $expected:literal,
        test: |$rt:ident| $body:expr
    ) => {
        {
            fn test_fn<RT: $crate::RuntimeInterface>($rt: &RT) -> $crate::TestResult {
                $body
            }

            $crate::ConformanceTest::new(
                $crate::TestMeta {
                    id: $id.to_string(),
                    name: $name.to_string(),
                    description: $desc.to_string(),
                    category: $cat,
                    tags: vec![$($tag.to_string()),*],
                    expected: $expected.to_string(),
                },
                test_fn,
            )
        }
    };
}
