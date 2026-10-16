#![allow(clippy::all)]
//! Comprehensive test logging infrastructure for Asupersync.
//!
//! This module provides detailed logging for tests that captures all I/O events,
//! reactor operations, waker dispatches, and timing information to enable thorough
//! debugging.
//!
//! # Overview
//!
//! The test logging infrastructure consists of:
//!
//! - [`TestLogLevel`]: Configurable verbosity levels
//! - [`TestEvent`]: Typed events for all runtime operations
//! - [`TestLogger`]: Captures and reports events with timestamps
//!
//! # Example
//!
//! ```
//! use asupersync::test_logging::{TestLogger, TestLogLevel, TestEvent};
//!
//! let logger = TestLogger::new(TestLogLevel::Debug);
//! logger.log(TestEvent::TaskSpawn { task_id: 1, name: Some("worker".into()) });
//!
//! // On test completion, print the report
//! println!("{}", logger.report());
//! ```

use crate::lab::{DualRunScenarioIdentity, ReplayMetadata, SeedLineageRecord};
use parking_lot::Mutex;
use std::fmt::Write as _;
use std::time::{Duration, Instant};

// ============================================================================
// TestLogLevel
// ============================================================================

/// Logging verbosity level for tests.
///
/// Levels are ordered from least to most verbose:
/// `Error < Warn < Info < Debug < Trace`
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum TestLogLevel {
    /// Only errors and failures.
    Error,
    /// Warnings and above.
    Warn,
    /// General test progress.
    #[default]
    Info,
    /// Detailed I/O operations.
    Debug,
    /// All events including waker dispatch, polls, syscalls.
    Trace,
}

impl TestLogLevel {
    /// Returns a human-readable name for the level.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Error => "ERROR",
            Self::Warn => "WARN",
            Self::Info => "INFO",
            Self::Debug => "DEBUG",
            Self::Trace => "TRACE",
        }
    }

    /// Returns the level from the `TEST_LOG_LEVEL` environment variable.
    #[must_use]
    pub fn from_env() -> Self {
        std::env::var("TEST_LOG_LEVEL")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or_default()
    }
}

impl std::fmt::Display for TestLogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl std::str::FromStr for TestLogLevel {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "error" => Ok(Self::Error),
            "warn" | "warning" => Ok(Self::Warn),
            "info" => Ok(Self::Info),
            "debug" => Ok(Self::Debug),
            "trace" => Ok(Self::Trace),
            _ => Err(()),
        }
    }
}

/// Stable adapter token for the Phase 1 live current-thread runner.
pub const LIVE_CURRENT_THREAD_ADAPTER: &str = "live.current_thread";

// ============================================================================
// Interest flags (for reactor events)
// ============================================================================

/// I/O interest flags for reactor registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Interest {
    /// Interested in read readiness.
    pub readable: bool,
    /// Interested in write readiness.
    pub writable: bool,
}

impl Interest {
    /// Interest in readable events only.
    pub const READABLE: Self = Self {
        readable: true,
        writable: false,
    };

    /// Interest in writable events only.
    pub const WRITABLE: Self = Self {
        readable: false,
        writable: true,
    };

    /// Interest in both readable and writable events.
    pub const BOTH: Self = Self {
        readable: true,
        writable: true,
    };
}

impl std::fmt::Display for Interest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (self.readable, self.writable) {
            (true, true) => write!(f, "RW"),
            (true, false) => write!(f, "R"),
            (false, true) => write!(f, "W"),
            (false, false) => write!(f, "-"),
        }
    }
}

// ============================================================================
// TestEvent
// ============================================================================

/// A typed event captured by the test logger.
///
/// Events cover all aspects of runtime operation:
/// - Reactor events (poll, wake, register, deregister)
/// - I/O events (read, write, connect, accept)
/// - Waker events (wake, clone, drop)
/// - Task events (poll, spawn, complete)
/// - Timer events (scheduled, fired)
/// - Custom events for test-specific logging
#[derive(Debug, Clone)]
pub enum TestEvent {
    // ========================================================================
    // Reactor events
    // ========================================================================
    /// Reactor poll completed.
    ReactorPoll {
        /// Timeout passed to poll.
        timeout: Option<Duration>,
        /// Number of events returned.
        events_returned: usize,
        /// How long the poll took.
        duration: Duration,
    },

    /// Reactor was woken externally.
    ReactorWake {
        /// Source of the wake (e.g., "waker", "timeout", "signal").
        source: &'static str,
    },

    /// I/O source registered with reactor.
    ReactorRegister {
        /// Token assigned to the registration.
        token: usize,
        /// Interest flags.
        interest: Interest,
        /// Type of source (e.g., "tcp", "unix", "pipe").
        source_type: &'static str,
    },

    /// I/O source deregistered from reactor.
    ReactorDeregister {
        /// Token that was deregistered.
        token: usize,
    },

    // ========================================================================
    // I/O events
    // ========================================================================
    /// Read operation completed.
    IoRead {
        /// Token of the I/O source.
        token: usize,
        /// Bytes read (0 if would_block).
        bytes: usize,
        /// Whether the operation would block.
        would_block: bool,
    },

    /// Write operation completed.
    IoWrite {
        /// Token of the I/O source.
        token: usize,
        /// Bytes written (0 if would_block).
        bytes: usize,
        /// Whether the operation would block.
        would_block: bool,
    },

    /// Connection attempt completed.
    IoConnect {
        /// Address being connected to.
        addr: String,
        /// Result description ("success", "refused", "timeout", etc.).
        result: &'static str,
    },

    /// Connection accepted.
    IoAccept {
        /// Local address.
        local: String,
        /// Peer address.
        peer: String,
    },

    // ========================================================================
    // Waker events
    // ========================================================================
    /// Waker was invoked.
    WakerWake {
        /// Token associated with the waker.
        token: usize,
        /// Task ID being woken.
        task_id: usize,
    },

    /// Waker was cloned.
    WakerClone {
        /// Token of the waker.
        token: usize,
    },

    /// Waker was dropped.
    WakerDrop {
        /// Token of the waker.
        token: usize,
    },

    // ========================================================================
    // Task events
    // ========================================================================
    /// Task was polled.
    TaskPoll {
        /// ID of the task.
        task_id: usize,
        /// Result of the poll ("ready", "pending").
        result: &'static str,
    },

    /// Task was spawned.
    TaskSpawn {
        /// ID of the new task.
        task_id: usize,
        /// Optional name for debugging.
        name: Option<String>,
    },

    /// Task completed.
    TaskComplete {
        /// ID of the completed task.
        task_id: usize,
        /// Outcome description ("ok", "err", "cancelled", "panicked").
        outcome: &'static str,
    },

    // ========================================================================
    // Timer events
    // ========================================================================
    /// Timer was scheduled.
    TimerScheduled {
        /// Deadline relative to start.
        deadline: Duration,
        /// Task to wake.
        task_id: usize,
    },

    /// Timer fired.
    TimerFired {
        /// Task that was woken.
        task_id: usize,
    },

    // ========================================================================
    // Region events
    // ========================================================================
    /// Region was created.
    RegionCreate {
        /// ID of the new region.
        region_id: usize,
        /// Parent region ID (if any).
        parent_id: Option<usize>,
    },

    /// Region state changed.
    RegionStateChange {
        /// ID of the region.
        region_id: usize,
        /// Previous state name.
        from_state: &'static str,
        /// New state name.
        to_state: &'static str,
    },

    /// Region closed.
    RegionClose {
        /// ID of the region.
        region_id: usize,
        /// Number of tasks that were in the region.
        task_count: usize,
        /// Duration the region was open.
        duration: Duration,
    },

    // ========================================================================
    // Obligation events
    // ========================================================================
    /// Obligation was created.
    ObligationCreate {
        /// ID of the obligation.
        obligation_id: usize,
        /// Kind of obligation ("permit", "ack", "lease", "io").
        kind: &'static str,
        /// Holding task.
        holder_id: usize,
    },

    /// Obligation was resolved.
    ObligationResolve {
        /// ID of the obligation.
        obligation_id: usize,
        /// Resolution type ("commit", "abort").
        resolution: &'static str,
    },

    // ========================================================================
    // Custom events
    // ========================================================================
    /// Custom event for test-specific logging.
    Custom {
        /// Category for filtering.
        category: &'static str,
        /// Human-readable message.
        message: String,
    },

    /// Error event.
    Error {
        /// Error category.
        category: &'static str,
        /// Error message.
        message: String,
    },

    /// Warning event.
    Warn {
        /// Warning category.
        category: &'static str,
        /// Warning message.
        message: String,
    },
}

impl TestEvent {
    /// Returns the minimum log level required to display this event.
    #[must_use]
    pub fn level(&self) -> TestLogLevel {
        match self {
            Self::Error { .. } => TestLogLevel::Error,
            Self::Warn { .. } => TestLogLevel::Warn,
            Self::TaskSpawn { .. }
            | Self::TaskComplete { .. }
            | Self::RegionCreate { .. }
            | Self::RegionClose { .. } => TestLogLevel::Info,
            Self::IoRead { .. }
            | Self::IoWrite { .. }
            | Self::IoConnect { .. }
            | Self::IoAccept { .. }
            | Self::ReactorRegister { .. }
            | Self::ReactorDeregister { .. }
            | Self::ObligationCreate { .. }
            | Self::ObligationResolve { .. }
            | Self::Custom { .. } => TestLogLevel::Debug,
            Self::ReactorPoll { .. }
            | Self::ReactorWake { .. }
            | Self::WakerWake { .. }
            | Self::WakerClone { .. }
            | Self::WakerDrop { .. }
            | Self::TaskPoll { .. }
            | Self::TimerScheduled { .. }
            | Self::TimerFired { .. }
            | Self::RegionStateChange { .. } => TestLogLevel::Trace,
        }
    }

    /// Returns a short category name for the event.
    #[must_use]
    pub fn category(&self) -> &'static str {
        match self {
            Self::ReactorPoll { .. }
            | Self::ReactorWake { .. }
            | Self::ReactorRegister { .. }
            | Self::ReactorDeregister { .. } => "reactor",
            Self::IoRead { .. }
            | Self::IoWrite { .. }
            | Self::IoConnect { .. }
            | Self::IoAccept { .. } => "io",
            Self::WakerWake { .. } | Self::WakerClone { .. } | Self::WakerDrop { .. } => "waker",
            Self::TaskPoll { .. } | Self::TaskSpawn { .. } | Self::TaskComplete { .. } => "task",
            Self::TimerScheduled { .. } | Self::TimerFired { .. } => "timer",
            Self::RegionCreate { .. }
            | Self::RegionStateChange { .. }
            | Self::RegionClose { .. } => "region",
            Self::ObligationCreate { .. } | Self::ObligationResolve { .. } => "obligation",
            Self::Custom { category, .. }
            | Self::Error { category, .. }
            | Self::Warn { category, .. } => category,
        }
    }
}

#[allow(clippy::too_many_lines)]
impl std::fmt::Display for TestEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReactorPoll {
                timeout,
                events_returned,
                duration,
            } => {
                write!(
                    f,
                    "reactor poll: timeout={timeout:?} events={events_returned} duration={duration:?}",
                )
            }
            Self::ReactorWake { source } => write!(f, "reactor wake: source={source}"),
            Self::ReactorRegister {
                token,
                interest,
                source_type,
            } => {
                write!(
                    f,
                    "reactor register: token={token} interest={interest} type={source_type}"
                )
            }
            Self::ReactorDeregister { token } => write!(f, "reactor deregister: token={token}"),
            Self::IoRead {
                token,
                bytes,
                would_block,
            } => {
                if *would_block {
                    write!(f, "io read: token={token} WOULD_BLOCK")
                } else {
                    write!(f, "io read: token={token} bytes={bytes}")
                }
            }
            Self::IoWrite {
                token,
                bytes,
                would_block,
            } => {
                if *would_block {
                    write!(f, "io write: token={token} WOULD_BLOCK")
                } else {
                    write!(f, "io write: token={token} bytes={bytes}")
                }
            }
            Self::IoConnect { addr, result } => {
                write!(f, "io connect: addr={addr} result={result}")
            }
            Self::IoAccept { local, peer } => write!(f, "io accept: local={local} peer={peer}"),
            Self::WakerWake { token, task_id } => {
                write!(f, "waker wake: token={token} task={task_id}")
            }
            Self::WakerClone { token } => write!(f, "waker clone: token={token}"),
            Self::WakerDrop { token } => write!(f, "waker drop: token={token}"),
            Self::TaskPoll { task_id, result } => write!(f, "task poll: task={task_id} {result}"),
            Self::TaskSpawn { task_id, name } => {
                if let Some(n) = name {
                    write!(f, "task spawn: task={task_id} name=\"{n}\"")
                } else {
                    write!(f, "task spawn: task={task_id}")
                }
            }
            Self::TaskComplete { task_id, outcome } => {
                write!(f, "task complete: task={task_id} outcome={outcome}")
            }
            Self::TimerScheduled { deadline, task_id } => {
                write!(f, "timer scheduled: deadline={deadline:?} task={task_id}")
            }
            Self::TimerFired { task_id } => write!(f, "timer fired: task={task_id}"),
            Self::RegionCreate {
                region_id,
                parent_id,
            } => {
                if let Some(p) = parent_id {
                    write!(f, "region create: region={region_id} parent={p}")
                } else {
                    write!(f, "region create: region={region_id} (root)")
                }
            }
            Self::RegionStateChange {
                region_id,
                from_state,
                to_state,
            } => {
                write!(
                    f,
                    "region state: region={region_id} {from_state} -> {to_state}"
                )
            }
            Self::RegionClose {
                region_id,
                task_count,
                duration,
            } => {
                write!(
                    f,
                    "region close: region={region_id} tasks={task_count} duration={duration:?}"
                )
            }
            Self::ObligationCreate {
                obligation_id,
                kind,
                holder_id,
            } => {
                write!(
                    f,
                    "obligation create: id={obligation_id} kind={kind} holder={holder_id}"
                )
            }
            Self::ObligationResolve {
                obligation_id,
                resolution,
            } => {
                write!(
                    f,
                    "obligation resolve: id={obligation_id} resolution={resolution}"
                )
            }
            Self::Custom { category, message } => write!(f, "[{category}] {message}"),
            Self::Error { category, message } => write!(f, "ERROR [{category}] {message}"),
            Self::Warn { category, message } => write!(f, "WARN [{category}] {message}"),
        }
    }
}

// ============================================================================
// TestLogger
// ============================================================================

/// A timestamped event record.
#[derive(Debug, Clone)]
pub struct LogRecord {
    /// Time since logger creation.
    pub elapsed: Duration,
    /// The event that occurred.
    pub event: TestEvent,
}

/// Comprehensive test logger that captures typed events with timestamps.
///
/// # Example
///
/// ```ignore
/// let logger = TestLogger::new(TestLogLevel::Debug);
///
/// // Log events during test
/// logger.log(TestEvent::TaskSpawn { task_id: 1, name: None });
/// logger.log(TestEvent::TaskComplete { task_id: 1, outcome: "ok" });
///
/// // Generate report
/// println!("{}", logger.report());
///
/// // Assert no busy loops
/// logger.assert_no_busy_loop(5);
/// ```
#[derive(Debug)]
pub struct TestLogger {
    /// Minimum level to capture.
    level: TestLogLevel,
    /// Captured events.
    events: Mutex<Vec<LogRecord>>,
    /// Start time for elapsed calculation.
    start_time: Instant,
    /// Whether to print events immediately.
    verbose: bool,
}

impl TestLogger {
    /// Creates a new logger with the specified level.
    #[must_use]
    pub fn new(level: TestLogLevel) -> Self {
        Self {
            level,
            events: Mutex::new(Vec::new()),
            start_time: Instant::now(),
            verbose: false,
        }
    }

    /// Creates a logger using the `TEST_LOG_LEVEL` environment variable.
    #[must_use]
    pub fn from_env() -> Self {
        Self::new(TestLogLevel::from_env())
    }

    /// Sets whether to print events immediately.
    #[must_use]
    pub fn verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }

    /// Returns the configured log level.
    #[must_use]
    pub fn level(&self) -> TestLogLevel {
        self.level
    }

    /// Returns the elapsed time since logger creation.
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.start_time.elapsed()
    }

    /// Returns whether the logger should capture events at the given level.
    #[must_use]
    pub fn should_log(&self, level: TestLogLevel) -> bool {
        level <= self.level
    }

    /// Logs an event if it meets the configured level.
    pub fn log(&self, event: TestEvent) {
        let event_level = event.level();
        if !self.should_log(event_level) {
            return;
        }

        let elapsed = self.start_time.elapsed();

        // Print immediately if verbose
        if self.verbose {
            eprintln!(
                "[{:>10.3}ms] [{:>5}] {}",
                elapsed.as_secs_f64() * 1000.0,
                event_level.name(),
                &event
            );
        }

        let record = LogRecord { elapsed, event };
        self.events.lock().push(record);
    }

    /// Logs a custom event.
    pub fn custom(&self, category: &'static str, message: impl Into<String>) {
        self.log(TestEvent::Custom {
            category,
            message: message.into(),
        });
    }

    /// Logs an error event.
    pub fn error(&self, category: &'static str, message: impl Into<String>) {
        self.log(TestEvent::Error {
            category,
            message: message.into(),
        });
    }

    /// Logs a warning event.
    pub fn warn(&self, category: &'static str, message: impl Into<String>) {
        self.log(TestEvent::Warn {
            category,
            message: message.into(),
        });
    }

    /// Returns the number of captured events.
    #[must_use]
    pub fn event_count(&self) -> usize {
        self.events.lock().len()
    }

    /// Returns a snapshot of all captured events.
    #[must_use]
    pub fn events(&self) -> Vec<LogRecord> {
        self.events.lock().clone()
    }

    /// Generates a detailed report of all captured events.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    #[allow(clippy::significant_drop_tightening)]
    pub fn report(&self) -> String {
        let events = self.events.lock();
        let mut report = String::new();

        let _ = writeln!(report, "=== Test Event Log ({} events) ===", events.len());
        let _ = writeln!(report);

        for record in events.iter() {
            let _ = writeln!(
                report,
                "[{:>10.3}ms] [{:>5}] {:>10} | {}",
                record.elapsed.as_secs_f64() * 1000.0,
                record.event.level().name(),
                record.event.category(),
                record.event
            );
        }

        // Statistics
        let _ = writeln!(report);
        let _ = writeln!(report, "=== Statistics ===");

        let polls = events
            .iter()
            .filter(|r| matches!(r.event, TestEvent::ReactorPoll { .. }))
            .count();
        let reads = events
            .iter()
            .filter(|r| matches!(r.event, TestEvent::IoRead { .. }))
            .count();
        let writes = events
            .iter()
            .filter(|r| matches!(r.event, TestEvent::IoWrite { .. }))
            .count();
        let wakes = events
            .iter()
            .filter(|r| matches!(r.event, TestEvent::WakerWake { .. }))
            .count();
        let task_polls = events
            .iter()
            .filter(|r| matches!(r.event, TestEvent::TaskPoll { .. }))
            .count();
        let task_spawns = events
            .iter()
            .filter(|r| matches!(r.event, TestEvent::TaskSpawn { .. }))
            .count();
        let errors = events
            .iter()
            .filter(|r| matches!(r.event, TestEvent::Error { .. }))
            .count();
        let warnings = events
            .iter()
            .filter(|r| matches!(r.event, TestEvent::Warn { .. }))
            .count();

        let _ = writeln!(report, "Reactor polls: {polls}");
        let _ = writeln!(report, "I/O reads: {reads}");
        let _ = writeln!(report, "I/O writes: {writes}");
        let _ = writeln!(report, "Waker wakes: {wakes}");
        let _ = writeln!(report, "Task polls: {task_polls}");
        let _ = writeln!(report, "Task spawns: {task_spawns}");
        let _ = writeln!(report, "Errors: {errors}");
        let _ = writeln!(report, "Warnings: {warnings}");

        // Calculate empty polls
        let empty_polls = events
            .iter()
            .filter(|r| {
                matches!(
                    r.event,
                    TestEvent::ReactorPoll {
                        events_returned: 0,
                        ..
                    }
                )
            })
            .count();

        if polls > 0 {
            let _ = writeln!(
                report,
                "Empty polls: {empty_polls} ({:.1}%)",
                (empty_polls as f64 / polls as f64) * 100.0
            );
        }

        // Total duration
        if let Some(last) = events.last() {
            let _ = writeln!(report, "Total duration: {:?}", last.elapsed);
        }

        report
    }

    /// Asserts that the test did not have excessive empty reactor polls (busy loops).
    ///
    /// # Panics
    ///
    /// Panics if the number of empty polls exceeds `max_empty_polls`.
    pub fn assert_no_busy_loop(&self, max_empty_polls: usize) {
        let empty_polls = {
            let events = self.events.lock();
            events
                .iter()
                .filter(|r| {
                    matches!(
                        r.event,
                        TestEvent::ReactorPoll {
                            events_returned: 0,
                            ..
                        }
                    )
                })
                .count()
        };

        assert!(
            empty_polls <= max_empty_polls,
            "Busy loop detected: {} empty polls (max {})\n{}",
            empty_polls,
            max_empty_polls,
            self.report()
        );
    }

    /// Asserts that no errors were logged.
    ///
    /// # Panics
    ///
    /// Panics if any error events were logged.
    pub fn assert_no_errors(&self) {
        let error_messages: Vec<String> = {
            let events = self.events.lock();
            events
                .iter()
                .filter(|r| matches!(r.event, TestEvent::Error { .. }))
                .map(|r| format!("  - {}", r.event))
                .collect()
        };

        assert!(
            error_messages.is_empty(),
            "Test logged {} errors:\n{}\n\nFull log:\n{}",
            error_messages.len(),
            error_messages.join("\n"),
            self.report()
        );
    }

    /// Asserts that all spawned tasks completed.
    ///
    /// # Panics
    ///
    /// Panics if any spawned task did not have a corresponding completion event.
    pub fn assert_all_tasks_completed(&self) {
        let leaked: Vec<usize> = {
            let events = self.events.lock();

            let spawned: std::collections::HashSet<_> = events
                .iter()
                .filter_map(|r| {
                    if let TestEvent::TaskSpawn { task_id, .. } = r.event {
                        Some(task_id)
                    } else {
                        None
                    }
                })
                .collect();

            let completed: std::collections::HashSet<_> = events
                .iter()
                .filter_map(|r| {
                    if let TestEvent::TaskComplete { task_id, .. } = r.event {
                        Some(task_id)
                    } else {
                        None
                    }
                })
                .collect();

            drop(events);
            spawned.difference(&completed).copied().collect()
        };

        assert!(
            leaked.is_empty(),
            "Task leak detected: {} tasks spawned but not completed: {:?}\n\nFull log:\n{}",
            leaked.len(),
            leaked,
            self.report()
        );
    }

    /// Clears all captured events.
    pub fn clear(&self) {
        self.events.lock().clear();
    }
}

impl Default for TestLogger {
    fn default() -> Self {
        Self::new(TestLogLevel::Info)
    }
}

// ============================================================================
// Macros
// ============================================================================

/// Log a custom event to a test logger.
///
/// # Example
///
/// ```ignore
/// test_log!(logger, "setup", "Creating listener on port {}", port);
/// test_log!(logger, "test", "Sending {} bytes", data.len());
/// ```
#[macro_export]
macro_rules! test_log {
    ($logger:expr, $cat:literal, $($arg:tt)*) => {
        $logger.log($crate::test_logging::TestEvent::Custom {
            category: $cat,
            message: format!($($arg)*),
        });
    };
}

/// Log an error event to a test logger.
///
/// # Example
///
/// ```ignore
/// test_error!(logger, "io", "Connection refused: {}", err);
/// ```
#[macro_export]
macro_rules! test_error {
    ($logger:expr, $cat:literal, $($arg:tt)*) => {
        $logger.log($crate::test_logging::TestEvent::Error {
            category: $cat,
            message: format!($($arg)*),
        });
    };
}

/// Log a warning event to a test logger.
///
/// # Example
///
/// ```ignore
/// test_warn!(logger, "timeout", "Operation took {}ms", elapsed);
/// ```
#[macro_export]
macro_rules! test_warn {
    ($logger:expr, $cat:literal, $($arg:tt)*) => {
        $logger.log($crate::test_logging::TestEvent::Warn {
            category: $cat,
            message: format!($($arg)*),
        });
    };
}

/// Assert a condition, printing the full log on failure.
///
/// # Example
///
/// ```ignore
/// assert_log!(logger, result.is_ok(), "Expected success, got {:?}", result);
/// ```
#[macro_export]
macro_rules! assert_log {
    ($logger:expr, $cond:expr) => {
        if !$cond {
            tracing::error!(report = %$logger.report(), "assertion failed: {}", stringify!($cond));
            panic!("assertion failed: {}", stringify!($cond));
        }
    };
    ($logger:expr, $cond:expr, $($arg:tt)*) => {
        if !$cond {
            tracing::error!(report = %$logger.report(), "assertion failed: {}", format_args!($($arg)*));
            panic!($($arg)*);
        }
    };
}

/// Assert equality, printing the full log on failure.
///
/// # Example
///
/// ```ignore
/// assert_eq_log!(logger, actual, expected, "Values should match");
/// ```
#[macro_export]
macro_rules! assert_eq_log {
    ($logger:expr, $left:expr, $right:expr) => {
        match (&$left, &$right) {
            (left_val, right_val) => {
                if *left_val != *right_val {
                    tracing::error!(report = %$logger.report(), "assertion failed: left == right");
                    panic!(
                        "assertion failed: `(left == right)`\n  left: {:?}\n right: {:?}",
                        left_val, right_val
                    );
                }
            }
        }
    };
    ($logger:expr, $left:expr, $right:expr, $($arg:tt)*) => {
        match (&$left, &$right) {
            (left_val, right_val) => {
                if *left_val != *right_val {
                    tracing::error!(
                        report = %$logger.report(),
                        "assertion failed: {}",
                        format_args!($($arg)*)
                    );
                    panic!(
                        "assertion failed: `(left == right)`\n  left: {:?}\n right: {:?}\n{}",
                        left_val, right_val, format!($($arg)*)
                    );
                }
            }
        }
    };
}

// ============================================================================
// TestHarness — Hierarchical E2E Test Framework
// ============================================================================

/// Result of a single assertion within a test.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AssertionRecord {
    /// Description of what was asserted.
    pub description: String,
    /// Whether the assertion passed.
    pub passed: bool,
    /// Expected value (stringified).
    pub expected: String,
    /// Actual value (stringified).
    pub actual: String,
    /// Phase path at time of assertion (e.g. "setup > connect").
    pub phase_path: String,
    /// Elapsed time since harness creation.
    pub elapsed_ms: f64,
}

/// A hierarchical phase node in the test execution tree.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PhaseNode {
    /// Name of this phase/section/step.
    pub name: String,
    /// Depth level (0 = top-level phase, 1 = section, 2 = step, ...).
    pub depth: usize,
    /// Start time relative to harness creation.
    pub start_ms: f64,
    /// End time relative to harness creation (None if still open).
    pub end_ms: Option<f64>,
    /// Assertions recorded within this phase.
    pub assertions: Vec<AssertionRecord>,
    /// Child phases.
    pub children: Vec<Self>,
}

// ============================================================================
// TestContext — Standardized metadata for structured test logging
// ============================================================================

/// Standardized metadata carried through a test for structured logging.
///
/// Every test should create a `TestContext` to ensure consistent, machine-parseable
/// log fields across all unit, integration, and E2E tests.
///
/// # Standard Fields
///
/// | Field | Purpose | Example |
/// |-------|---------|---------|
/// | `test_id` | Unique identifier for the test run | `"cancel_drain_001"` |
/// | `seed` | Deterministic RNG seed for reproducibility | `0xDEAD_BEEF` |
/// | `subsystem` | Runtime subsystem under test | `"scheduler"`, `"raptorq"` |
/// | `invariant` | Core invariant being verified | `"no_obligation_leaks"` |
///
/// # Example
///
/// ```ignore
/// use asupersync::test_logging::TestContext;
///
/// let ctx = TestContext::new("cancel_drain_001", 0xDEAD_BEEF)
///     .with_subsystem("cancellation")
///     .with_invariant("losers_drained");
///
/// // Use with TestHarness
/// let harness = TestHarness::with_context("my_test", ctx);
/// ```
#[derive(Debug, Clone, serde::Serialize)]
pub struct TestContext {
    /// Unique test identifier for log correlation.
    pub test_id: String,
    /// Deterministic seed for reproducibility.
    pub seed: u64,
    /// Runtime subsystem under test (e.g., "scheduler", "raptorq", "obligation").
    pub subsystem: Option<String>,
    /// Core invariant being verified (e.g., "no_obligation_leaks", "quiescence").
    pub invariant: Option<String>,
    /// Adapter identity for dual-run provenance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub adapter: Option<String>,
    /// Rich replay/provenance metadata for the execution, when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replay_metadata: Option<ReplayMetadata>,
    /// Stable seed lineage record for audit/mismatch artifacts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seed_lineage: Option<SeedLineageRecord>,
}

impl TestContext {
    /// Create a new context with required fields.
    #[must_use]
    pub fn new(test_id: &str, seed: u64) -> Self {
        Self {
            test_id: test_id.to_string(),
            seed,
            subsystem: None,
            invariant: None,
            adapter: None,
            replay_metadata: None,
            seed_lineage: None,
        }
    }

    /// Set the subsystem under test.
    #[must_use]
    pub fn with_subsystem(mut self, subsystem: &str) -> Self {
        self.subsystem = Some(subsystem.to_string());
        self
    }

    /// Set the invariant being verified.
    #[must_use]
    pub fn with_invariant(mut self, invariant: &str) -> Self {
        self.invariant = Some(invariant.to_string());
        self
    }

    /// Attach replay provenance captured from a dual-run execution surface.
    #[must_use]
    pub fn with_replay_provenance(
        mut self,
        adapter: impl Into<String>,
        replay_metadata: ReplayMetadata,
        seed_lineage: SeedLineageRecord,
    ) -> Self {
        self.test_id.clone_from(&replay_metadata.family.id);
        self.seed = replay_metadata.effective_seed;
        self.adapter = Some(adapter.into());
        self.replay_metadata = Some(replay_metadata);
        self.seed_lineage = Some(seed_lineage);
        self
    }

    /// Build a current-thread live test context from a dual-run identity.
    #[must_use]
    pub fn from_live_dual_run(identity: &DualRunScenarioIdentity) -> Self {
        Self::new(
            &identity.scenario_id,
            identity.seed_plan.effective_live_seed(),
        )
        .with_replay_provenance(
            LIVE_CURRENT_THREAD_ADAPTER,
            identity.live_replay_metadata(),
            identity.seed_lineage(),
        )
    }

    /// Surface identifier, when dual-run provenance is attached.
    #[must_use]
    pub fn surface_id(&self) -> Option<&str> {
        self.replay_metadata
            .as_ref()
            .map(|metadata| metadata.family.surface_id.as_str())
    }

    /// Surface contract version, when dual-run provenance is attached.
    #[must_use]
    pub fn surface_contract_version(&self) -> Option<&str> {
        self.replay_metadata
            .as_ref()
            .map(|metadata| metadata.family.surface_contract_version.as_str())
    }

    /// Stable seed lineage identifier, when dual-run provenance is attached.
    #[must_use]
    pub fn seed_lineage_id(&self) -> Option<&str> {
        self.seed_lineage
            .as_ref()
            .map(|lineage| lineage.seed_lineage_id.as_str())
    }

    /// Concrete execution-instance identifier, when dual-run provenance is attached.
    #[must_use]
    pub fn execution_instance_id(&self) -> Option<String> {
        self.replay_metadata
            .as_ref()
            .map(|metadata| metadata.instance.key())
    }

    /// Emit a tracing info event with all context fields.
    pub fn log_start(&self) {
        tracing::info!(
            test_id = %self.test_id,
            seed = %format_args!("0x{:X}", self.seed),
            subsystem = self.subsystem.as_deref().unwrap_or("-"),
            invariant = self.invariant.as_deref().unwrap_or("-"),
            surface_id = self.surface_id().unwrap_or("-"),
            surface_contract_version = self.surface_contract_version().unwrap_or("-"),
            adapter = self.adapter.as_deref().unwrap_or("-"),
            seed_lineage_id = self.seed_lineage_id().unwrap_or("-"),
            execution_instance_id = self.execution_instance_id().as_deref().unwrap_or("-"),
            "TEST START"
        );
    }

    /// Emit a tracing info event for test completion with all context fields.
    pub fn log_end(&self, passed: bool) {
        tracing::info!(
            test_id = %self.test_id,
            seed = %format_args!("0x{:X}", self.seed),
            subsystem = self.subsystem.as_deref().unwrap_or("-"),
            invariant = self.invariant.as_deref().unwrap_or("-"),
            surface_id = self.surface_id().unwrap_or("-"),
            surface_contract_version = self.surface_contract_version().unwrap_or("-"),
            adapter = self.adapter.as_deref().unwrap_or("-"),
            seed_lineage_id = self.seed_lineage_id().unwrap_or("-"),
            execution_instance_id = self.execution_instance_id().as_deref().unwrap_or("-"),
            passed = passed,
            "TEST END"
        );
    }

    /// Derive a component-specific seed from this context's root seed.
    #[must_use]
    pub fn component_seed(&self, component: &str) -> u64 {
        derive_component_seed(self.seed, component)
    }

    /// Derive a scenario-specific seed from this context's root seed.
    #[must_use]
    pub fn scenario_seed(&self, scenario: &str) -> u64 {
        derive_scenario_seed(self.seed, scenario)
    }

    /// Derive an entropy seed for a given iteration index.
    #[must_use]
    pub fn entropy_seed(&self, index: u64) -> u64 {
        derive_entropy_seed(self.seed, index)
    }

    /// Emit a structured error dump with full context for failure triage.
    pub fn log_failure(&self, reason: &str) {
        tracing::error!(
            test_id = %self.test_id,
            seed = %format_args!("0x{:X}", self.seed),
            subsystem = self.subsystem.as_deref().unwrap_or("-"),
            invariant = self.invariant.as_deref().unwrap_or("-"),
            surface_id = self.surface_id().unwrap_or("-"),
            surface_contract_version = self.surface_contract_version().unwrap_or("-"),
            adapter = self.adapter.as_deref().unwrap_or("-"),
            seed_lineage_id = self.seed_lineage_id().unwrap_or("-"),
            execution_instance_id = self.execution_instance_id().as_deref().unwrap_or("-"),
            reason = %reason,
            "TEST FAILURE — reproduce with seed 0x{:X}",
            self.seed
        );
    }
}

impl std::fmt::Display for TestContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "test_id={} seed=0x{:X} subsystem={} invariant={} surface={} contract={} adapter={}",
            self.test_id,
            self.seed,
            self.subsystem.as_deref().unwrap_or("-"),
            self.invariant.as_deref().unwrap_or("-"),
            self.surface_id().unwrap_or("-"),
            self.surface_contract_version().unwrap_or("-"),
            self.adapter.as_deref().unwrap_or("-"),
        )
    }
}

// ============================================================================
// Seed Derivation — Canonical taxonomy and propagation rules
// ============================================================================
//
// Seed taxonomy (all seeds derive from a single root):
//
//   root_seed                         — top-level test seed (from env, CLI, or hardcoded)
//     ├── scenario_seed(root, name)   — per-scenario derivation (deterministic)
//     ├── component_seed(root, comp)  — per-subsystem (scheduler, io, rng, etc.)
//     └── entropy_seed(root, idx)     — per-iteration for property/fuzz tests
//
// Derivation formula:
//   derived = FNV-1a(root ⊕ tag_bytes)
//
// This avoids DefaultHasher (which is randomized per-process on some targets)
// and ensures cross-platform determinism.

/// Derive a deterministic seed for a named component from a root seed.
///
/// Uses FNV-1a hashing for cross-platform determinism.
#[must_use]
pub fn derive_component_seed(root: u64, component: &str) -> u64 {
    fnv1a_mix(root, component.as_bytes())
}

/// Derive a deterministic seed for a named scenario from a root seed.
#[must_use]
pub fn derive_scenario_seed(root: u64, scenario: &str) -> u64 {
    let tag = format!("scenario:{scenario}");
    fnv1a_mix(root, tag.as_bytes())
}

/// Derive a deterministic entropy seed for a given iteration index.
#[must_use]
pub fn derive_entropy_seed(root: u64, index: u64) -> u64 {
    fnv1a_mix(root, &index.to_le_bytes())
}

/// FNV-1a-based deterministic mixing function.
fn fnv1a_mix(root: u64, tag: &[u8]) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0100_0000_01b3;

    let mut hash = FNV_OFFSET;
    for byte in root.to_le_bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    for &byte in tag {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

// ============================================================================
// Artifact Schema — Versioned, deterministic test artifacts
// ============================================================================

/// Current artifact schema version.
pub const ARTIFACT_SCHEMA_VERSION: u32 = 1;
/// Stable identifier for the canonical repro-manifest schema.
pub const REPRO_MANIFEST_SCHEMA_ID: &str = "repro-manifest.v1";
/// Required contract fields for deterministic CI/C5 consumption.
pub const REPRO_MANIFEST_REQUIRED_FIELDS: [&str; 7] = [
    "scenario_id",
    "invariant_ids",
    "seed",
    "trace_fingerprint",
    "replay_command",
    "failure_class",
    "artifact_paths",
];

const FAILURE_CLASS_PASSED: &str = "passed";
const FAILURE_CLASS_ASSERTION_FAILURE: &str = "assertion_failure";

fn default_trace_fingerprint(seed: u64, scenario_id: &str) -> String {
    format!("pending:{scenario_id}:{seed:016x}")
}

fn replay_target_slug(scenario_id: &str) -> String {
    let mut slug = String::with_capacity(scenario_id.len().max(1));
    for ch in scenario_id.chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch.to_ascii_lowercase());
        } else if !slug.ends_with('_') {
            slug.push('_');
        }
    }

    let slug = slug.trim_matches('_');
    if slug.is_empty() {
        "scenario".to_string()
    } else {
        slug.to_string()
    }
}

fn default_replay_command(seed: u64, scenario_id: &str) -> String {
    let target_slug = replay_target_slug(scenario_id);
    format!(
        "rch exec -- env CARGO_TARGET_DIR=${{TMPDIR:-/tmp}}/rch_target_test_logging_{target_slug} ASUPERSYNC_SEED=0x{seed:X} cargo test {scenario_id} -- --nocapture"
    )
}

fn normalize_string_ids(ids: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut normalized = ids
        .into_iter()
        .map(|id| id.trim().to_string())
        .filter(|id| !id.is_empty())
        .collect::<Vec<_>>();
    normalized.sort_unstable();
    normalized.dedup();
    normalized
}

/// A reproducibility manifest for a test failure or notable execution.
///
/// # Artifact Layouts
///
/// - **Harness failures**: `$ASUPERSYNC_TEST_ARTIFACTS_DIR/<scenario_id>/repro_manifest.json`
///   alongside `event_log.txt` and `failed_assertions.json`.
/// - **Explicit dumps**: `<base>/<scenario_id>/<seed>/manifest.json` via
///   [`ReproManifest::write_to_dir`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ReproManifest {
    /// Schema version for forward compatibility.
    pub schema_version: u32,
    /// Root seed used for the test execution.
    pub seed: u64,
    /// Scenario identifier (test name or scenario tag).
    pub scenario_id: String,
    /// Canonical invariant identifiers validated by this execution.
    #[serde(default)]
    pub invariant_ids: Vec<String>,
    /// Entropy seed derived from root.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entropy_seed: Option<u64>,
    /// Hash of the test configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_hash: Option<String>,
    /// Fingerprint of the execution trace.
    pub trace_fingerprint: String,
    /// Deterministic replay command for direct repro.
    pub replay_command: String,
    /// Failure class for routing/triage.
    pub failure_class: String,
    /// Artifact paths produced by this run.
    #[serde(default)]
    pub artifact_paths: Vec<String>,
    /// Digest of the test input data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_digest: Option<String>,
    /// Oracle violations detected during the execution.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub oracle_violations: Vec<String>,
    /// Whether the execution passed or failed.
    pub passed: bool,
    /// Subsystem under test.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subsystem: Option<String>,
    /// Invariant being verified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invariant: Option<String>,
    /// Relative path to the trace file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_file: Option<String>,
    /// Relative path to the failing input file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_file: Option<String>,
    /// Captured environment variables relevant for reproducibility.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env_snapshot: Vec<(String, String)>,
    /// Phases/steps executed before the failure.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub phases_executed: Vec<String>,
    /// Failure reason or assertion message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
    /// Adapter identity for the execution surface.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub adapter: Option<String>,
    /// Rich replay/provenance metadata for the execution surface.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replay_metadata: Option<ReplayMetadata>,
    /// Stable seed lineage record for reruns and mismatch bundles.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seed_lineage: Option<SeedLineageRecord>,
}

impl ReproManifest {
    /// Create a new manifest with required fields.
    #[must_use]
    pub fn new(seed: u64, scenario_id: &str, passed: bool) -> Self {
        Self {
            schema_version: ARTIFACT_SCHEMA_VERSION,
            seed,
            scenario_id: scenario_id.to_string(),
            invariant_ids: Vec::new(),
            entropy_seed: None,
            config_hash: None,
            trace_fingerprint: default_trace_fingerprint(seed, scenario_id),
            replay_command: default_replay_command(seed, scenario_id),
            failure_class: if passed {
                FAILURE_CLASS_PASSED.to_string()
            } else {
                FAILURE_CLASS_ASSERTION_FAILURE.to_string()
            },
            artifact_paths: Vec::new(),
            input_digest: None,
            oracle_violations: Vec::new(),
            passed,
            subsystem: None,
            invariant: None,
            trace_file: None,
            input_file: None,
            env_snapshot: Vec::new(),
            phases_executed: Vec::new(),
            failure_reason: None,
            adapter: None,
            replay_metadata: None,
            seed_lineage: None,
        }
    }

    /// Create a manifest from a [`TestContext`] and pass/fail status.
    #[must_use]
    pub fn from_context(ctx: &TestContext, passed: bool) -> Self {
        let replay_command = ctx
            .replay_metadata
            .as_ref()
            .and_then(|metadata| metadata.repro_command.clone())
            .unwrap_or_else(|| default_replay_command(ctx.seed, &ctx.test_id));
        Self {
            schema_version: ARTIFACT_SCHEMA_VERSION,
            seed: ctx.seed,
            scenario_id: ctx.test_id.clone(),
            invariant_ids: ctx
                .invariant
                .as_ref()
                .map_or_else(Vec::new, |invariant| vec![invariant.clone()]),
            entropy_seed: None,
            config_hash: None,
            trace_fingerprint: default_trace_fingerprint(ctx.seed, &ctx.test_id),
            replay_command,
            failure_class: if passed {
                FAILURE_CLASS_PASSED.to_string()
            } else {
                FAILURE_CLASS_ASSERTION_FAILURE.to_string()
            },
            artifact_paths: Vec::new(),
            input_digest: None,
            oracle_violations: Vec::new(),
            passed,
            subsystem: ctx.subsystem.clone(),
            invariant: ctx.invariant.clone(),
            trace_file: None,
            input_file: None,
            env_snapshot: Vec::new(),
            phases_executed: Vec::new(),
            failure_reason: None,
            adapter: ctx.adapter.clone(),
            replay_metadata: ctx.replay_metadata.clone(),
            seed_lineage: ctx.seed_lineage.clone(),
        }
    }

    /// Capture a snapshot of test-relevant environment variables.
    #[must_use]
    pub fn with_env_snapshot(mut self) -> Self {
        self.env_snapshot = capture_test_env();
        self
    }

    /// Set the phases executed during the test.
    #[must_use]
    pub fn with_phases(mut self, phases: Vec<String>) -> Self {
        self.phases_executed = phases;
        self
    }

    /// Set the failure reason.
    #[must_use]
    pub fn with_failure_reason(mut self, reason: &str) -> Self {
        self.failure_reason = Some(reason.to_string());
        if self.failure_class == FAILURE_CLASS_PASSED {
            self.failure_class = FAILURE_CLASS_ASSERTION_FAILURE.to_string();
        }
        self
    }

    /// Set the entropy seed derived from the root seed.
    #[must_use]
    pub fn with_entropy_seed(mut self, entropy_seed: u64) -> Self {
        self.entropy_seed = Some(entropy_seed);
        if let Some(ref mut replay_metadata) = self.replay_metadata {
            replay_metadata.effective_entropy_seed = entropy_seed;
        }
        self
    }

    /// Set the configuration hash used for this run.
    #[must_use]
    pub fn with_config_hash(mut self, config_hash: &str) -> Self {
        self.config_hash = Some(config_hash.to_string());
        if let Some(ref mut replay_metadata) = self.replay_metadata {
            replay_metadata.config_hash = Some(config_hash.to_string());
        }
        self
    }

    /// Set the trace fingerprint for this run.
    #[must_use]
    pub fn with_trace_fingerprint(mut self, trace_fingerprint: &str) -> Self {
        self.trace_fingerprint = trace_fingerprint.to_string();
        self
    }

    /// Set the deterministic replay command.
    #[must_use]
    pub fn with_replay_command(mut self, replay_command: &str) -> Self {
        self.replay_command = replay_command.to_string();
        if let Some(ref mut replay_metadata) = self.replay_metadata {
            replay_metadata.repro_command = Some(replay_command.to_string());
        }
        self
    }

    /// Set the failure class.
    #[must_use]
    pub fn with_failure_class(mut self, failure_class: &str) -> Self {
        self.failure_class = failure_class.to_string();
        self
    }

    /// Set the input digest for this run.
    #[must_use]
    pub fn with_input_digest(mut self, input_digest: &str) -> Self {
        self.input_digest = Some(input_digest.to_string());
        self
    }

    /// Set oracle violations recorded during this run.
    #[must_use]
    pub fn with_oracle_violations<I, S>(mut self, violations: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.oracle_violations = violations.into_iter().map(Into::into).collect();
        self
    }

    /// Set the subsystem under test.
    #[must_use]
    pub fn with_subsystem(mut self, subsystem: &str) -> Self {
        self.subsystem = Some(subsystem.to_string());
        self
    }

    /// Set the invariant under test.
    #[must_use]
    pub fn with_invariant(mut self, invariant: &str) -> Self {
        self.invariant = Some(invariant.to_string());
        self.invariant_ids = normalize_string_ids(vec![invariant.to_string()]);
        self
    }

    /// Set canonical invariant IDs; values are normalized (trimmed/sorted/deduped).
    #[must_use]
    pub fn with_invariant_ids<I, S>(mut self, invariant_ids: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.invariant_ids = normalize_string_ids(invariant_ids.into_iter().map(Into::into));
        self
    }

    /// Set the relative path to the trace file.
    #[must_use]
    pub fn with_trace_file(mut self, trace_file: &str) -> Self {
        self.trace_file = Some(trace_file.to_string());
        self
    }

    /// Set the relative path to the input file.
    #[must_use]
    pub fn with_input_file(mut self, input_file: &str) -> Self {
        self.input_file = Some(input_file.to_string());
        self
    }

    /// Set artifact paths; values are normalized (trimmed/sorted/deduped).
    #[must_use]
    pub fn with_artifact_paths<I, S>(mut self, artifact_paths: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.artifact_paths = normalize_string_ids(artifact_paths.into_iter().map(Into::into));
        self
    }

    /// Add a single artifact path.
    #[must_use]
    pub fn with_artifact_path(mut self, artifact_path: &str) -> Self {
        self.artifact_paths.push(artifact_path.to_string());
        self.artifact_paths = normalize_string_ids(self.artifact_paths);
        self
    }

    /// Validate the canonical v1 contract used by CI and C5 gates.
    pub fn validate_contract_v1(&self) -> Result<(), String> {
        if self.schema_version != ARTIFACT_SCHEMA_VERSION {
            return Err(format!(
                "schema_version must be {}, got {}",
                ARTIFACT_SCHEMA_VERSION, self.schema_version
            ));
        }
        if self.scenario_id.trim().is_empty() {
            return Err("scenario_id must be non-empty".to_string());
        }
        if self.replay_command.trim().is_empty() {
            return Err("replay_command must be non-empty".to_string());
        }
        if self.failure_class.trim().is_empty() {
            return Err("failure_class must be non-empty".to_string());
        }
        if self.trace_fingerprint.trim().is_empty() {
            return Err("trace_fingerprint must be non-empty".to_string());
        }
        if self.invariant_ids.iter().any(|id| id.trim().is_empty()) {
            return Err("invariant_ids cannot contain empty values".to_string());
        }
        if self
            .artifact_paths
            .iter()
            .any(|path| path.trim().is_empty())
        {
            return Err("artifact_paths cannot contain empty values".to_string());
        }
        if let Some(ref adapter) = self.adapter {
            if adapter.trim().is_empty() {
                return Err("adapter cannot be empty when present".to_string());
            }
        }
        if let Some(ref replay_metadata) = self.replay_metadata {
            if replay_metadata.family.id != self.scenario_id {
                return Err("replay_metadata.family.id must match scenario_id".to_string());
            }
            if replay_metadata.effective_seed != self.seed {
                return Err("replay_metadata.effective_seed must match seed".to_string());
            }
            if let Some(ref seed_lineage) = self.seed_lineage {
                if seed_lineage.seed_lineage_id != replay_metadata.seed_plan.seed_lineage_id {
                    return Err(
                        "seed_lineage.seed_lineage_id must match replay_metadata.seed_plan.seed_lineage_id"
                            .to_string(),
                    );
                }
            }
        }

        let normalized_invariants = normalize_string_ids(self.invariant_ids.clone());
        if normalized_invariants != self.invariant_ids {
            return Err("invariant_ids must be sorted and deduplicated".to_string());
        }
        let normalized_artifacts = normalize_string_ids(self.artifact_paths.clone());
        if normalized_artifacts != self.artifact_paths {
            return Err("artifact_paths must be sorted and deduplicated".to_string());
        }

        Ok(())
    }

    /// Serialize to pretty-printed JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Write this manifest to `<base>/<scenario_id>/<seed>/manifest.json`.
    ///
    /// Note: the test harness writes `repro_manifest.json` under
    /// `$ASUPERSYNC_TEST_ARTIFACTS_DIR/<scenario_id>/`.
    pub fn write_to_dir(&self, base_dir: &std::path::Path) -> std::io::Result<std::path::PathBuf> {
        let dir = base_dir
            .join(&self.scenario_id)
            .join(format!("0x{:X}", self.seed));
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("manifest.json");
        let json = self
            .to_json()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(&path, json)?;
        tracing::info!(
            path = %path.display(),
            scenario = %self.scenario_id,
            seed = %format_args!("0x{:X}", self.seed),
            "wrote repro manifest"
        );
        Ok(path)
    }
}

/// Load a [`ReproManifest`] from a JSON file.
pub fn load_repro_manifest(path: &std::path::Path) -> Result<ReproManifest, std::io::Error> {
    let content = std::fs::read_to_string(path)?;
    serde_json::from_str(&content)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

/// Capture a snapshot of test-relevant environment variables.
///
/// Only includes `ASUPERSYNC_*` and `RUST_LOG` variables.
/// Sorted by key for deterministic output.
#[must_use]
pub fn capture_test_env() -> Vec<(String, String)> {
    let mut env: Vec<(String, String)> = std::env::vars()
        .filter(|(k, _)| k.starts_with("ASUPERSYNC_") || k == "RUST_LOG")
        .collect();
    env.sort_by(|a, b| a.0.cmp(&b.0));
    env
}

/// Create a [`TestContext`] from a [`ReproManifest`] for replay.
#[must_use]
pub fn replay_context_from_manifest(manifest: &ReproManifest) -> TestContext {
    let mut ctx = TestContext::new(&manifest.scenario_id, manifest.seed);
    if let Some(ref subsystem) = manifest.subsystem {
        ctx = ctx.with_subsystem(subsystem);
    }
    if let Some(ref invariant) = manifest.invariant {
        ctx = ctx.with_invariant(invariant);
    } else if let Some(first_invariant_id) = manifest.invariant_ids.first() {
        ctx = ctx.with_invariant(first_invariant_id);
    }
    if let Some(replay_metadata) = manifest.replay_metadata.clone() {
        let seed_lineage = manifest
            .seed_lineage
            .clone()
            .unwrap_or_else(|| SeedLineageRecord::from_plan(&replay_metadata.seed_plan));
        ctx = ctx.with_replay_provenance(
            manifest
                .adapter
                .clone()
                .unwrap_or_else(|| LIVE_CURRENT_THREAD_ADAPTER.to_string()),
            replay_metadata,
            seed_lineage,
        );
    } else if let Some(ref adapter) = manifest.adapter {
        ctx.adapter = Some(adapter.clone());
    }
    ctx
}

// ============================================================================
// E2E Environment Orchestration
// ============================================================================

/// An OS-assigned ephemeral port with a label for identification.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AllocatedPort {
    /// Human-readable label.
    pub label: String,
    /// The allocated port number.
    pub port: u16,
}

/// Manages allocation of OS-assigned ephemeral ports for test isolation.
#[derive(Debug)]
pub struct PortAllocator {
    entries: Vec<PortEntry>,
}

#[derive(Debug)]
struct PortEntry {
    label: String,
    port: u16,
    listener: Option<std::net::TcpListener>,
}

impl PortAllocator {
    /// Create a new, empty allocator.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Allocate a single ephemeral port with a label.
    pub fn allocate(&mut self, label: &str) -> std::io::Result<u16> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        tracing::debug!(label = %label, port = port, "allocated ephemeral port");
        self.entries.push(PortEntry {
            label: label.to_string(),
            port,
            listener: Some(listener),
        });
        Ok(port)
    }

    /// Allocate `count` ephemeral ports with a shared label prefix.
    pub fn allocate_n(&mut self, label: &str, count: usize) -> std::io::Result<Vec<u16>> {
        let mut ports = Vec::with_capacity(count);
        for i in 0..count {
            let suffixed = format!("{label}_{i}");
            ports.push(self.allocate(&suffixed)?);
        }
        Ok(ports)
    }

    /// Release all held ports.
    pub fn release_all(&mut self) {
        for entry in &mut self.entries {
            entry.listener = None;
        }
        tracing::debug!(count = self.entries.len(), "released all held ports");
    }

    /// Returns the list of allocated ports with their labels.
    #[must_use]
    pub fn allocated_ports(&self) -> Vec<AllocatedPort> {
        self.entries
            .iter()
            .map(|e| AllocatedPort {
                label: e.label.clone(),
                port: e.port,
            })
            .collect()
    }

    /// Look up a port by label.
    #[must_use]
    pub fn port_for(&self, label: &str) -> Option<u16> {
        self.entries
            .iter()
            .find(|e| e.label == label)
            .map(|e| e.port)
    }

    /// Returns the number of currently allocated ports.
    #[must_use]
    pub fn count(&self) -> usize {
        self.entries.len()
    }
}

impl Default for PortAllocator {
    fn default() -> Self {
        Self::new()
    }
}

/// Trait for deterministic fixture services in E2E tests.
pub trait FixtureService: std::fmt::Debug {
    /// Returns the service name.
    fn name(&self) -> &str;
    /// Start the service.
    fn start(&mut self) -> Result<(), Box<dyn std::error::Error>>;
    /// Stop the service.
    fn stop(&mut self) -> Result<(), Box<dyn std::error::Error>>;
    /// Returns `true` if the service is healthy.
    fn is_healthy(&self) -> bool;
    /// Returns `true` while this fixture still owns a live external resource.
    ///
    /// The default matches the health state, which is sufficient for
    /// in-process fixtures. Process and container fixtures override this so a
    /// crashed or unhealthy service cannot be mistaken for a completed
    /// teardown.
    fn has_live_resource(&self) -> bool {
        self.is_healthy()
    }
}

#[derive(Debug)]
struct ServiceEntry {
    service: Box<dyn FixtureService>,
    started_at: Option<Instant>,
    started: bool,
}

/// Structured metadata about the test environment.
#[derive(Debug, Clone, serde::Serialize)]
pub struct EnvironmentMetadata {
    /// Operating system.
    pub os: &'static str,
    /// CPU architecture.
    pub arch: &'static str,
    /// Pointer width in bits.
    pub pointer_width: u32,
    /// Test identifier.
    pub test_id: String,
    /// Root seed.
    pub seed: u64,
    /// Allocated ports with labels.
    pub ports: Vec<AllocatedPort>,
    /// Names of registered fixture services.
    pub services: Vec<String>,
}

impl EnvironmentMetadata {
    /// Emit all metadata fields as a structured tracing event.
    pub fn log(&self) {
        tracing::info!(
            test_id = %self.test_id,
            seed = %format_args!("0x{:X}", self.seed),
            os = %self.os,
            arch = %self.arch,
            pointer_width = self.pointer_width,
            port_count = self.ports.len(),
            service_count = self.services.len(),
            "E2E ENVIRONMENT METADATA"
        );
    }

    /// Serialize to pretty-printed JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Write metadata to a file alongside other test artifacts.
    pub fn write_to_dir(&self, base_dir: &std::path::Path) -> std::io::Result<std::path::PathBuf> {
        let safe_id = self.test_id.replace(|c: char| !c.is_alphanumeric(), "_");
        let dir = base_dir.join(&safe_id);
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("environment.json");
        let json = self
            .to_json()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(&path, json)?;
        tracing::info!(path = %path.display(), test_id = %self.test_id, "wrote environment metadata");
        Ok(path)
    }
}

impl std::fmt::Display for EnvironmentMetadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "env[test_id={} seed=0x{:X} os={} arch={} ports={} services={}]",
            self.test_id,
            self.seed,
            self.os,
            self.arch,
            self.ports.len(),
            self.services.len(),
        )
    }
}

/// Hermetic E2E test environment with managed services, ports, and metadata.
pub struct TestEnvironment {
    context: TestContext,
    ports: PortAllocator,
    services: Vec<ServiceEntry>,
    cleanup_fns: Vec<Box<dyn FnOnce()>>,
    cleanup_ran: bool,
    teardown_errors: Vec<String>,
    torn_down: bool,
}

impl std::fmt::Debug for TestEnvironment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestEnvironment")
            .field("context", &self.context)
            .field("ports", &self.ports)
            .field("services", &self.services)
            .field(
                "cleanup_fns",
                &format_args!("[{} fns]", self.cleanup_fns.len()),
            )
            .field("cleanup_ran", &self.cleanup_ran)
            .field("teardown_errors", &self.teardown_errors)
            .field("torn_down", &self.torn_down)
            .finish()
    }
}

impl TestEnvironment {
    /// Create a new test environment from a [`TestContext`].
    #[must_use]
    pub fn new(context: TestContext) -> Self {
        context.log_start();
        tracing::info!(
            test_id = %context.test_id,
            seed = %format_args!("0x{:X}", context.seed),
            "E2E environment created"
        );
        Self {
            context,
            ports: PortAllocator::new(),
            services: Vec::new(),
            cleanup_fns: Vec::new(),
            cleanup_ran: false,
            teardown_errors: Vec::new(),
            torn_down: false,
        }
    }

    /// Returns a reference to the underlying [`TestContext`].
    #[must_use]
    pub fn context(&self) -> &TestContext {
        &self.context
    }

    /// Returns a reference to the [`PortAllocator`].
    #[must_use]
    pub fn ports(&self) -> &PortAllocator {
        &self.ports
    }

    /// Allocate a single ephemeral port with a label.
    pub fn allocate_port(&mut self, label: &str) -> std::io::Result<u16> {
        self.ports.allocate(label)
    }

    /// Allocate multiple ephemeral ports with a shared label prefix.
    pub fn allocate_ports(&mut self, label: &str, count: usize) -> std::io::Result<Vec<u16>> {
        self.ports.allocate_n(label, count)
    }

    /// Look up a previously allocated port by label.
    #[must_use]
    pub fn port_for(&self, label: &str) -> Option<u16> {
        self.ports.port_for(label)
    }

    /// Register a fixture service (does not start it).
    pub fn register_service(&mut self, service: Box<dyn FixtureService>) {
        tracing::debug!(service = %service.name(), "registered fixture service");
        self.services.push(ServiceEntry {
            service,
            started_at: None,
            started: false,
        });
    }

    /// Start all registered services transactionally.
    ///
    /// Held port reservations are released immediately before startup so the
    /// managed services can bind them. If any start fails, that service and
    /// every service started before it are stopped in reverse order.
    pub fn start_all_services(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.torn_down {
            return Err("cannot start services after environment teardown".into());
        }

        self.ports.release_all();
        for index in 0..self.services.len() {
            let service_name = self.services[index].service.name().to_string();
            tracing::info!(service = %service_name, "starting fixture service");
            match self.services[index].service.start() {
                Ok(()) => {
                    self.services[index].started_at = Some(Instant::now());
                    self.services[index].started = true;
                }
                Err(start_error) => {
                    let mut rollback_errors = Vec::new();
                    for rollback_index in (0..=index).rev() {
                        let entry = &mut self.services[rollback_index];
                        if let Err(stop_error) = entry.service.stop() {
                            rollback_errors.push(format!("{}: {stop_error}", entry.service.name()));
                        } else {
                            entry.started = false;
                            entry.started_at = None;
                        }
                    }
                    let rollback_suffix = if rollback_errors.is_empty() {
                        String::new()
                    } else {
                        format!("; rollback errors: {}", rollback_errors.join(", "))
                    };
                    return Err(
                        format!("fixture service '{service_name}' failed to start: {start_error}{rollback_suffix}")
                            .into(),
                    );
                }
            }
        }
        Ok(())
    }

    /// Start all registered services and require bounded readiness.
    ///
    /// Readiness is checked in registration order after startup. A timeout
    /// follows the same reverse-order rollback path as a start failure.
    pub fn start_all_services_until_healthy(
        &mut self,
        timeout_per_service: Duration,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.start_all_services()?;
        for index in 0..self.services.len() {
            if let Err(health_error) =
                wait_until_healthy(self.services[index].service.as_ref(), timeout_per_service)
            {
                let service_name = self.services[index].service.name().to_string();
                self.teardown();
                return Err(format!(
                    "fixture service '{service_name}' failed readiness: {health_error}"
                )
                .into());
            }
        }
        Ok(())
    }

    /// Check health of all services.
    #[must_use]
    pub fn health_check(&self) -> Vec<(&str, bool)> {
        self.services
            .iter()
            .map(|e| (e.service.name(), e.service.is_healthy()))
            .collect()
    }

    /// Register a cleanup function to run during teardown.
    pub fn on_teardown<F: FnOnce() + 'static>(&mut self, f: F) {
        self.cleanup_fns.push(Box::new(f));
    }

    /// Build the current [`EnvironmentMetadata`] snapshot.
    #[must_use]
    pub fn metadata(&self) -> EnvironmentMetadata {
        EnvironmentMetadata {
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
            pointer_width: (std::mem::size_of::<usize>() * 8) as u32,
            test_id: self.context.test_id.clone(),
            seed: self.context.seed,
            ports: self.ports.allocated_ports(),
            services: self
                .services
                .iter()
                .map(|e| e.service.name().to_string())
                .collect(),
        }
    }

    /// Emit environment metadata to structured logs.
    pub fn emit_metadata(&self) {
        self.metadata().log();
    }

    /// Write environment metadata to the artifact directory (if configured).
    #[must_use]
    pub fn write_metadata_artifact(&self) -> Option<std::io::Result<std::path::PathBuf>> {
        artifact_dir_from_env().map(|dir| self.metadata().write_to_dir(&dir))
    }

    /// Names of services that still own a live resource.
    #[must_use]
    pub fn orphaned_services(&self) -> Vec<&str> {
        self.services
            .iter()
            .filter(|entry| entry.started || entry.service.has_live_resource())
            .map(|entry| entry.service.name())
            .collect()
    }

    /// Errors observed during the most recent teardown attempt.
    #[must_use]
    pub fn teardown_errors(&self) -> &[String] {
        &self.teardown_errors
    }

    /// Perform explicit teardown: stop services, release ports, run cleanup fns.
    pub fn teardown(&mut self) {
        if self.torn_down {
            return;
        }
        self.teardown_errors.clear();
        tracing::info!(test_id = %self.context.test_id, "E2E environment teardown");

        for entry in self.services.iter_mut().rev() {
            if !entry.started && !entry.service.has_live_resource() {
                continue;
            }
            let elapsed = entry
                .started_at
                .map_or(Duration::ZERO, |started_at| started_at.elapsed());
            tracing::debug!(
                service = %entry.service.name(),
                elapsed_ms = elapsed.as_millis().min(u128::from(u64::MAX)) as u64,
                "stopping fixture service"
            );
            if let Err(e) = entry.service.stop() {
                tracing::warn!(service = %entry.service.name(), error = %e, "fixture service stop failed");
                self.teardown_errors
                    .push(format!("{}: {e}", entry.service.name()));
            } else {
                entry.started = false;
                entry.started_at = None;
            }
        }
        self.ports.release_all();
        if !self.cleanup_ran {
            self.cleanup_ran = true;
            for f in self.cleanup_fns.drain(..).rev() {
                f();
            }
        }
        let orphan_count = self.orphaned_services().len();
        self.torn_down = self.teardown_errors.is_empty() && orphan_count == 0;
        if self.torn_down {
            tracing::info!(test_id = %self.context.test_id, "E2E environment teardown complete");
        } else {
            tracing::warn!(
                test_id = %self.context.test_id,
                teardown_error_count = self.teardown_errors.len(),
                orphan_count,
                "E2E environment teardown incomplete"
            );
        }
    }
}

impl Drop for TestEnvironment {
    fn drop(&mut self) {
        self.teardown();
    }
}

/// A no-op fixture service for testing the environment orchestration itself.
#[derive(Debug)]
pub struct NoOpFixtureService {
    name: String,
    started: bool,
}

impl NoOpFixtureService {
    /// Create a no-op service with the given name.
    #[must_use]
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            started: false,
        }
    }
}

impl FixtureService for NoOpFixtureService {
    fn name(&self) -> &str {
        &self.name
    }

    fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.started = true;
        Ok(())
    }

    fn stop(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.started = false;
        Ok(())
    }

    fn is_healthy(&self) -> bool {
        self.started
    }
}

// ============================================================================
// Concrete Fixture Services (bd-76y5)
// ============================================================================

/// Poll a [`FixtureService`] until `is_healthy()` returns `true`, with
/// exponential backoff. Returns an error if `timeout` elapses first.
pub fn wait_until_healthy(
    service: &dyn FixtureService,
    timeout: Duration,
) -> Result<Duration, Box<dyn std::error::Error>> {
    let start = Instant::now();
    let mut interval = Duration::from_millis(50);
    let max_interval = Duration::from_millis(500);

    loop {
        if service.is_healthy() {
            let elapsed = start.elapsed();
            tracing::info!(
                service = %service.name(),
                elapsed_ms = elapsed.as_millis().min(u128::from(u64::MAX)) as u64,
                "service healthy"
            );
            return Ok(elapsed);
        }

        if start.elapsed() >= timeout {
            return Err(format!(
                "service '{}' not healthy after {:?}",
                service.name(),
                timeout
            )
            .into());
        }

        std::thread::sleep(interval);
        interval = (interval * 2).min(max_interval);
    }
}

/// Verified identity for a managed process fixture.
///
/// The executable path must be absolute. Both the binary SHA-256 and the exact
/// trimmed output of the version probe are checked before the service starts,
/// preventing an ambient `PATH` entry or silently upgraded binary from
/// contributing proof.
#[derive(Debug, Clone)]
pub struct PinnedProcessIdentity {
    binary_path: std::path::PathBuf,
    expected_sha256: String,
    version_args: Vec<std::ffi::OsString>,
    expected_version: String,
}

impl PinnedProcessIdentity {
    /// Create an identity using `--version` as the version probe.
    #[must_use]
    pub fn new(
        binary_path: impl Into<std::path::PathBuf>,
        expected_sha256: impl Into<String>,
        expected_version: impl Into<String>,
    ) -> Self {
        Self {
            binary_path: binary_path.into(),
            expected_sha256: expected_sha256.into(),
            version_args: vec![std::ffi::OsString::from("--version")],
            expected_version: expected_version.into(),
        }
    }

    /// Override arguments used to obtain the exact pinned version string.
    #[must_use]
    pub fn with_version_args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<std::ffi::OsString>,
    {
        self.version_args = args.into_iter().map(Into::into).collect();
        self
    }

    /// Absolute executable path.
    #[must_use]
    pub fn binary_path(&self) -> &std::path::Path {
        &self.binary_path
    }

    /// Expected lowercase SHA-256 digest.
    #[must_use]
    pub fn expected_sha256(&self) -> &str {
        &self.expected_sha256
    }

    /// Exact expected version-probe output after trimming whitespace.
    #[must_use]
    pub fn expected_version(&self) -> &str {
        &self.expected_version
    }

    fn verify(&self) -> Result<(), Box<dyn std::error::Error>> {
        if !self.binary_path.is_absolute() {
            return Err(format!(
                "fixture binary path must be absolute: {}",
                self.binary_path.display()
            )
            .into());
        }
        if self.expected_sha256.len() != 64
            || !self
                .expected_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err("fixture SHA-256 must be 64 lowercase hexadecimal characters".into());
        }
        if self.expected_version.trim().is_empty() {
            return Err("fixture expected version must not be empty".into());
        }

        use sha2::Digest as _;
        let bytes = std::fs::read(&self.binary_path)?;
        let digest = sha2::Sha256::digest(bytes);
        let actual_sha256 = hex::encode(digest);
        if actual_sha256 != self.expected_sha256 {
            return Err(format!(
                "fixture binary digest mismatch for {}: expected {}, actual {}",
                self.binary_path.display(),
                self.expected_sha256,
                actual_sha256
            )
            .into());
        }

        let output = std::process::Command::new(&self.binary_path)
            .args(&self.version_args)
            .env_clear()
            .output()?;
        if !output.status.success() {
            return Err(format!(
                "fixture version probe failed for {} with {}",
                self.binary_path.display(),
                output.status
            )
            .into());
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let actual_version = if stdout.trim().is_empty() {
            stderr.trim()
        } else {
            stdout.trim()
        };
        if actual_version != self.expected_version {
            return Err(format!(
                "fixture version mismatch for {}: expected {:?}, actual {:?}",
                self.binary_path.display(),
                self.expected_version,
                actual_version
            )
            .into());
        }
        Ok(())
    }
}

/// Readiness condition for a managed process fixture.
#[derive(Debug, Clone, Copy)]
pub enum ProcessReadiness {
    /// The child must remain alive for one readiness polling interval.
    Running,
    /// A TCP connection to the managed loopback endpoint must succeed.
    Tcp(std::net::SocketAddr),
}

/// Sanitized stdout/stderr captured from a managed fixture.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FixtureLogs {
    /// Redacted standard output.
    pub stdout: String,
    /// Redacted standard error.
    pub stderr: String,
}

/// A pinned, isolated process fixture with bounded readiness and log capture.
pub struct ProcessFixtureService {
    service_name: String,
    identity: PinnedProcessIdentity,
    args: Vec<std::ffi::OsString>,
    env_vars: Vec<(std::ffi::OsString, std::ffi::OsString)>,
    secret_values: Vec<String>,
    current_dir: Option<std::path::PathBuf>,
    log_dir: std::path::PathBuf,
    readiness: ProcessReadiness,
    startup_timeout: Duration,
    child: Mutex<Option<std::process::Child>>,
    stdout_path: std::path::PathBuf,
    stderr_path: std::path::PathBuf,
}

impl std::fmt::Debug for ProcessFixtureService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProcessFixtureService")
            .field("service_name", &self.service_name)
            .field("identity", &self.identity)
            .field("arg_count", &self.args.len())
            .field("env_key_count", &self.env_vars.len())
            .field("secret_count", &self.secret_values.len())
            .field("current_dir", &self.current_dir)
            .field("log_dir", &self.log_dir)
            .field("readiness", &self.readiness)
            .field("startup_timeout", &self.startup_timeout)
            .finish_non_exhaustive()
    }
}

impl ProcessFixtureService {
    /// Create a pinned process fixture.
    #[must_use]
    pub fn new(
        service_name: impl Into<String>,
        identity: PinnedProcessIdentity,
        log_dir: impl Into<std::path::PathBuf>,
    ) -> Self {
        let service_name = service_name.into();
        let log_dir = log_dir.into();
        let current_dir = Some(log_dir.clone());
        let safe_name: String = service_name
            .chars()
            .map(|ch| {
                if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_') {
                    ch
                } else {
                    '_'
                }
            })
            .collect();
        Self {
            service_name,
            identity,
            args: Vec::new(),
            env_vars: Vec::new(),
            secret_values: Vec::new(),
            current_dir,
            stdout_path: log_dir.join(format!("{safe_name}.stdout.log")),
            stderr_path: log_dir.join(format!("{safe_name}.stderr.log")),
            log_dir,
            readiness: ProcessReadiness::Running,
            startup_timeout: Duration::from_secs(10),
            child: Mutex::new(None),
        }
    }

    /// Set process arguments.
    #[must_use]
    pub fn with_args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<std::ffi::OsString>,
    {
        self.args = args.into_iter().map(Into::into).collect();
        self
    }

    /// Add a non-secret environment variable.
    #[must_use]
    pub fn with_env(
        mut self,
        key: impl Into<std::ffi::OsString>,
        value: impl Into<std::ffi::OsString>,
    ) -> Self {
        self.env_vars.push((key.into(), value.into()));
        self
    }

    /// Add an environment variable whose value must be redacted from logs.
    #[must_use]
    pub fn with_secret_env(
        mut self,
        key: impl Into<std::ffi::OsString>,
        value: impl Into<std::ffi::OsString>,
    ) -> Self {
        let value = value.into();
        let rendered = value.to_string_lossy().into_owned();
        if !rendered.is_empty() {
            self.secret_values.push(rendered);
        }
        self.env_vars.push((key.into(), value));
        self
    }

    /// Set the isolated working directory.
    #[must_use]
    pub fn with_current_dir(mut self, path: impl Into<std::path::PathBuf>) -> Self {
        self.current_dir = Some(path.into());
        self
    }

    /// Set readiness policy.
    #[must_use]
    pub fn with_readiness(mut self, readiness: ProcessReadiness) -> Self {
        self.readiness = readiness;
        self
    }

    /// Set the bounded startup timeout.
    #[must_use]
    pub fn with_startup_timeout(mut self, timeout: Duration) -> Self {
        self.startup_timeout = timeout;
        self
    }

    /// Return redacted captured logs. Missing log files yield empty strings.
    #[must_use]
    pub fn captured_logs(&self) -> FixtureLogs {
        FixtureLogs {
            stdout: self.redact(&std::fs::read_to_string(&self.stdout_path).unwrap_or_default()),
            stderr: self.redact(&std::fs::read_to_string(&self.stderr_path).unwrap_or_default()),
        }
    }

    fn redact(&self, text: &str) -> String {
        self.secret_values
            .iter()
            .fold(text.to_string(), |output, secret| {
                output.replace(secret, "<redacted>")
            })
    }

    fn sanitize_log_files(&self) -> std::io::Result<()> {
        for path in [&self.stdout_path, &self.stderr_path] {
            if path.is_file() {
                let raw = std::fs::read_to_string(path)?;
                std::fs::write(path, self.redact(&raw))?;
            }
        }
        Ok(())
    }

    fn readiness_satisfied(&self) -> bool {
        match self.readiness {
            ProcessReadiness::Running => true,
            ProcessReadiness::Tcp(addr) => {
                addr.ip().is_loopback()
                    && std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(50))
                        .is_ok()
            }
        }
    }

    fn stop_child(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut child_slot = self.child.lock();
        if let Some(child) = child_slot.as_mut() {
            if child.try_wait()?.is_none() {
                child.kill()?;
                let _status = child.wait()?;
            }
            child_slot.take();
        }
        drop(child_slot);
        self.sanitize_log_files()?;
        Ok(())
    }
}

impl FixtureService for ProcessFixtureService {
    fn name(&self) -> &str {
        &self.service_name
    }

    fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.has_live_resource() {
            return Err(
                format!("fixture process '{}' is already running", self.service_name).into(),
            );
        }
        if !self.log_dir.is_absolute() {
            return Err(format!(
                "fixture log directory must be absolute: {}",
                self.log_dir.display()
            )
            .into());
        }
        self.identity.verify()?;
        if let ProcessReadiness::Tcp(addr) = self.readiness
            && !addr.ip().is_loopback()
        {
            return Err(
                format!("fixture TCP readiness address must be loopback, got {addr}").into(),
            );
        }

        std::fs::create_dir_all(&self.log_dir)?;
        let current_dir = self
            .current_dir
            .as_ref()
            .ok_or("fixture process requires an isolated working directory")?;
        if !current_dir.is_absolute() || !current_dir.is_dir() {
            return Err(format!(
                "fixture working directory must be an existing absolute directory: {}",
                current_dir.display()
            )
            .into());
        }
        let stdout = std::fs::File::create(&self.stdout_path)?;
        let stderr = std::fs::File::create(&self.stderr_path)?;
        let mut command = std::process::Command::new(self.identity.binary_path());
        command
            .args(&self.args)
            .env_clear()
            .envs(self.env_vars.iter().cloned())
            .stdin(std::process::Stdio::null())
            .stdout(stdout)
            .stderr(stderr);
        command.current_dir(current_dir);

        tracing::info!(
            service = %self.service_name,
            binary = %self.identity.binary_path().display(),
            sha256 = %self.identity.expected_sha256(),
            version = %self.identity.expected_version(),
            arg_count = self.args.len(),
            env_key_count = self.env_vars.len(),
            "starting pinned process fixture"
        );
        *self.child.lock() = Some(command.spawn()?);

        let readiness_started = Instant::now();
        let deadline = readiness_started + self.startup_timeout;
        loop {
            {
                let mut child_slot = self.child.lock();
                if let Some(child) = child_slot.as_mut()
                    && let Some(status) = child.try_wait()?
                {
                    *child_slot = None;
                    drop(child_slot);
                    self.sanitize_log_files()?;
                    let logs = self.captured_logs();
                    return Err(format!(
                        "fixture process '{}' exited before readiness with {status}; stdout={:?}; stderr={:?}",
                        self.service_name, logs.stdout, logs.stderr
                    )
                    .into());
                }
            }
            let ready = match self.readiness {
                ProcessReadiness::Running => {
                    readiness_started.elapsed() >= Duration::from_millis(25)
                }
                ProcessReadiness::Tcp(_) => self.readiness_satisfied(),
            };
            if ready {
                return Ok(());
            }
            if Instant::now() >= deadline {
                self.stop_child()?;
                let logs = self.captured_logs();
                return Err(format!(
                    "fixture process '{}' readiness timed out after {:?}; stdout={:?}; stderr={:?}",
                    self.service_name, self.startup_timeout, logs.stdout, logs.stderr
                )
                .into());
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    fn stop(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.stop_child()
    }

    fn is_healthy(&self) -> bool {
        self.has_live_resource() && self.readiness_satisfied()
    }

    fn has_live_resource(&self) -> bool {
        let mut child_slot = self.child.lock();
        let Some(child) = child_slot.as_mut() else {
            return false;
        };
        match child.try_wait() {
            Ok(None) => true,
            Ok(Some(_)) => {
                *child_slot = None;
                false
            }
            Err(_) => true,
        }
    }
}

impl Drop for ProcessFixtureService {
    fn drop(&mut self) {
        if let Err(error) = self.stop_child() {
            tracing::warn!(
                service = %self.service_name,
                error = %error,
                "process fixture drop cleanup failed"
            );
        }
    }
}

/// A fixture service backed by a Docker container.
///
/// Launches a container with `docker run`, removes it on stop, and health
/// checks via a configurable command (defaults to checking if the container
/// is in `running` state).
///
/// # Example
///
/// ```ignore
/// let mut redis = DockerFixtureService::new(
///     "redis",
///     "redis@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
/// )
///     .with_port_map(port, 6379)
///     .with_health_cmd(vec!["redis-cli", "ping"]);
/// redis.start()?;
/// wait_until_healthy(&redis, Duration::from_secs(10))?;
/// ```
pub struct DockerFixtureService {
    service_name: String,
    image: String,
    container_name: String,
    port_maps: Vec<(u16, u16)>,
    env_vars: Vec<(String, String)>,
    secret_values: Vec<String>,
    health_cmd: Option<Vec<String>>,
    log_dir: Option<std::path::PathBuf>,
    captured_logs: Mutex<FixtureLogs>,
    started: bool,
}

impl std::fmt::Debug for DockerFixtureService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DockerFixtureService")
            .field("service_name", &self.service_name)
            .field("image", &self.image)
            .field("container_name", &self.container_name)
            .field("port_maps", &self.port_maps)
            .field("env_key_count", &self.env_vars.len())
            .field("secret_count", &self.secret_values.len())
            .field("health_cmd", &self.health_cmd)
            .field("log_dir", &self.log_dir)
            .field("started", &self.started)
            .finish()
    }
}

impl DockerFixtureService {
    /// Create a new Docker fixture with a service name and immutable image.
    ///
    /// Startup rejects images that are not pinned by a full `sha256` digest.
    /// A unique container name is generated from the service name, process ID,
    /// and a process-local sequence to avoid collisions between parallel
    /// fixtures.
    #[must_use]
    pub fn new(service_name: &str, image: &str) -> Self {
        static NEXT_CONTAINER_ID: std::sync::atomic::AtomicU64 =
            std::sync::atomic::AtomicU64::new(1);
        let sequence = NEXT_CONTAINER_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let safe_name: String = service_name
            .chars()
            .map(|ch| {
                if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_') {
                    ch
                } else {
                    '-'
                }
            })
            .collect();
        let container_name = format!(
            "asupersync-test-{safe_name}-{}-{sequence}",
            std::process::id()
        );
        Self {
            service_name: service_name.to_string(),
            image: image.to_string(),
            container_name,
            port_maps: Vec::new(),
            env_vars: Vec::new(),
            secret_values: Vec::new(),
            health_cmd: None,
            log_dir: None,
            captured_logs: Mutex::new(FixtureLogs::default()),
            started: false,
        }
    }

    /// Map a host port to a container port.
    #[must_use]
    pub fn with_port_map(mut self, host_port: u16, container_port: u16) -> Self {
        self.port_maps.push((host_port, container_port));
        self
    }

    /// Set an environment variable in the container.
    #[must_use]
    pub fn with_env(mut self, key: &str, value: &str) -> Self {
        self.env_vars.push((key.to_string(), value.to_string()));
        self
    }

    /// Set an environment variable whose value must be redacted from logs.
    #[must_use]
    pub fn with_secret_env(mut self, key: &str, value: &str) -> Self {
        if !value.is_empty() {
            self.secret_values.push(value.to_string());
        }
        self.env_vars.push((key.to_string(), value.to_string()));
        self
    }

    /// Set a custom health check command to run inside the container via
    /// `docker exec`.
    #[must_use]
    pub fn with_health_cmd(mut self, cmd: Vec<&str>) -> Self {
        self.health_cmd = Some(cmd.into_iter().map(String::from).collect());
        self
    }

    /// Persist sanitized container stdout/stderr under this directory.
    #[must_use]
    pub fn with_log_dir(mut self, log_dir: impl Into<std::path::PathBuf>) -> Self {
        self.log_dir = Some(log_dir.into());
        self
    }

    /// Returns the container name.
    #[must_use]
    pub fn container_name(&self) -> &str {
        &self.container_name
    }

    /// Return the most recently captured, redacted container logs.
    #[must_use]
    pub fn captured_logs(&self) -> FixtureLogs {
        self.captured_logs.lock().clone()
    }

    /// Whether an image reference contains a full immutable SHA-256 digest.
    #[must_use]
    pub fn image_is_pinned(image: &str) -> bool {
        image.rsplit_once("@sha256:").is_some_and(|(name, digest)| {
            !name.is_empty()
                && digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
    }

    fn run_docker_cmd(args: &[&str]) -> Result<std::process::Output, Box<dyn std::error::Error>> {
        let output = std::process::Command::new("docker").args(args).output()?;
        Ok(output)
    }

    fn redact(&self, text: &str) -> String {
        self.secret_values
            .iter()
            .fold(text.to_string(), |output, secret| {
                output.replace(secret, "<redacted>")
            })
    }

    fn capture_container_logs(&self) -> Result<(), Box<dyn std::error::Error>> {
        let output = Self::run_docker_cmd(&["logs", &self.container_name])?;
        let logs = FixtureLogs {
            stdout: self.redact(&String::from_utf8_lossy(&output.stdout)),
            stderr: self.redact(&String::from_utf8_lossy(&output.stderr)),
        };
        if let Some(log_dir) = &self.log_dir {
            std::fs::create_dir_all(log_dir)?;
            std::fs::write(
                log_dir.join(format!("{}.stdout.log", self.container_name)),
                &logs.stdout,
            )?;
            std::fs::write(
                log_dir.join(format!("{}.stderr.log", self.container_name)),
                &logs.stderr,
            )?;
        }
        *self.captured_logs.lock() = logs;
        Ok(())
    }
}

impl FixtureService for DockerFixtureService {
    fn name(&self) -> &str {
        &self.service_name
    }

    fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if !Self::image_is_pinned(&self.image) {
            return Err(format!(
                "fixture image must be pinned by sha256 digest: {}",
                self.image
            )
            .into());
        }

        let mut args = vec!["run", "-d", "--name", &self.container_name];

        let port_strings: Vec<String> = self
            .port_maps
            .iter()
            .map(|(h, c)| format!("127.0.0.1:{h}:{c}"))
            .collect();
        for ps in &port_strings {
            args.push("-p");
            args.push(ps);
        }

        let env_strings: Vec<String> = self
            .env_vars
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect();
        for es in &env_strings {
            args.push("-e");
            args.push(es);
        }

        args.push(&self.image);

        tracing::info!(
            container = %self.container_name,
            image = %self.image,
            "starting docker container"
        );

        let output = Self::run_docker_cmd(&args)?;
        if !output.status.success() {
            let stderr = self.redact(&String::from_utf8_lossy(&output.stderr));
            return Err(format!(
                "docker run failed for '{}': {}",
                self.container_name, stderr
            )
            .into());
        }

        self.started = true;
        Ok(())
    }

    fn stop(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if !self.started && !self.has_live_resource() {
            return Ok(());
        }
        tracing::info!(container = %self.container_name, "stopping docker container");
        let log_error = self.capture_container_logs().err();
        let output = Self::run_docker_cmd(&["rm", "-f", &self.container_name])?;
        if !output.status.success() {
            let stderr = self.redact(&String::from_utf8_lossy(&output.stderr));
            tracing::warn!(
                container = %self.container_name,
                error = %stderr,
                "docker rm failed"
            );
            return Err(format!("docker rm failed for '{}': {stderr}", self.container_name).into());
        }
        self.started = false;
        if let Some(error) = log_error {
            return Err(format!(
                "capturing logs for container '{}' failed: {error}",
                self.container_name
            )
            .into());
        }
        Ok(())
    }

    fn is_healthy(&self) -> bool {
        if !self.started {
            return false;
        }

        self.health_cmd.as_ref().map_or_else(
            || {
                // Fallback: check container state via docker inspect.
                match Self::run_docker_cmd(&[
                    "inspect",
                    "-f",
                    "{{.State.Running}}",
                    &self.container_name,
                ]) {
                    Ok(output) => {
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        stdout.trim() == "true"
                    }
                    Err(_) => false,
                }
            },
            |cmd| {
                let mut args = vec!["exec", &self.container_name];
                let cmd_refs: Vec<&str> = cmd.iter().map(String::as_str).collect();
                args.extend(cmd_refs);
                match Self::run_docker_cmd(&args) {
                    Ok(output) => output.status.success(),
                    Err(_) => false,
                }
            },
        )
    }

    fn has_live_resource(&self) -> bool {
        match Self::run_docker_cmd(&["inspect", &self.container_name]) {
            Ok(output) => output.status.success(),
            Err(_) => self.started,
        }
    }
}

impl Drop for DockerFixtureService {
    fn drop(&mut self) {
        if (self.started || self.has_live_resource())
            && let Err(error) = FixtureService::stop(self)
        {
            tracing::warn!(
                container = %self.container_name,
                error = %error,
                "docker fixture drop cleanup failed"
            );
        }
    }
}

/// Per-test temporary directory that is automatically cleaned up on drop.
///
/// Wraps [`tempfile::TempDir`] behind the [`FixtureService`] trait so it can
/// be managed by [`TestEnvironment`] alongside other fixtures.
#[derive(Debug)]
pub struct TempDirFixture {
    service_name: String,
    prefix: String,
    dir: Option<tempfile::TempDir>,
}

impl TempDirFixture {
    /// Create a new temp-dir fixture. The directory is created on `start()`.
    #[must_use]
    pub fn new(service_name: &str) -> Self {
        Self {
            service_name: service_name.to_string(),
            prefix: format!("asupersync-{service_name}-"),
            dir: None,
        }
    }

    /// Override the directory-name prefix (default: `asupersync-<name>-`).
    #[must_use]
    pub fn with_prefix(mut self, prefix: &str) -> Self {
        self.prefix = prefix.to_string();
        self
    }

    /// Returns the path if the directory has been created.
    #[must_use]
    pub fn path(&self) -> Option<&std::path::Path> {
        self.dir.as_ref().map(tempfile::TempDir::path)
    }
}

impl FixtureService for TempDirFixture {
    fn name(&self) -> &str {
        &self.service_name
    }

    fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let mut builder = tempfile::Builder::new();
        builder.prefix(&self.prefix);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            builder.permissions(std::fs::Permissions::from_mode(0o700));
        }
        let dir = builder.tempdir()?;
        tracing::debug!(
            service = %self.service_name,
            path = %dir.path().display(),
            "created temp directory"
        );
        self.dir = Some(dir);
        Ok(())
    }

    fn stop(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(dir) = self.dir.take() {
            let path = dir.path().display().to_string();
            // TempDir::drop handles cleanup; we just log.
            drop(dir);
            tracing::debug!(service = %self.service_name, path = %path, "cleaned up temp directory");
        }
        Ok(())
    }

    fn is_healthy(&self) -> bool {
        self.dir.as_ref().is_some_and(|d| d.path().is_dir())
    }
}

/// Wraps a closure-based in-process service behind [`FixtureService`].
///
/// Use this for lightweight, in-process test servers (WebSocket echo, HTTP
/// fixture services, etc.) where a full Docker container is unnecessary.
///
/// The `start_fn` receives a mutable reference to `state` and should spawn
/// whatever background work is needed, storing handles in `state`.
/// The `stop_fn` receives the state and must shut everything down.
///
/// # Example
///
/// ```ignore
/// use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
///
/// let running = Arc::new(AtomicBool::new(false));
/// let r = running.clone();
/// let svc = InProcessService::new(
///     "echo_ws",
///     running,
///     move |state| { state.store(true, Ordering::SeqCst); Ok(()) },
///     |state| { state.store(false, Ordering::SeqCst); Ok(()) },
///     |state| state.load(Ordering::SeqCst),
/// );
/// ```
type InProcessResult = Result<(), Box<dyn std::error::Error>>;
type InProcessStartFn<S> = Box<dyn FnMut(&mut S) -> InProcessResult>;
type InProcessStopFn<S> = Box<dyn FnMut(&mut S) -> InProcessResult>;
type InProcessHealthFn<S> = Box<dyn Fn(&S) -> bool>;

/// In-process fixture service backed by user-provided start/stop closures.
pub struct InProcessService<S: std::fmt::Debug + 'static> {
    service_name: String,
    state: S,
    start_fn: InProcessStartFn<S>,
    stop_fn: InProcessStopFn<S>,
    health_fn: InProcessHealthFn<S>,
}

impl<S: std::fmt::Debug + 'static> std::fmt::Debug for InProcessService<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InProcessService")
            .field("service_name", &self.service_name)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl<S: std::fmt::Debug + 'static> InProcessService<S> {
    /// Create a new in-process service.
    pub fn new(
        name: &str,
        state: S,
        start_fn: impl FnMut(&mut S) -> InProcessResult + 'static,
        stop_fn: impl FnMut(&mut S) -> InProcessResult + 'static,
        health_fn: impl Fn(&S) -> bool + 'static,
    ) -> Self {
        Self {
            service_name: name.to_string(),
            state,
            start_fn: Box::new(start_fn),
            stop_fn: Box::new(stop_fn),
            health_fn: Box::new(health_fn),
        }
    }

    /// Returns a reference to the service state.
    #[must_use]
    pub fn state(&self) -> &S {
        &self.state
    }
}

impl<S: std::fmt::Debug + 'static> FixtureService for InProcessService<S> {
    fn name(&self) -> &str {
        &self.service_name
    }

    fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        (self.start_fn)(&mut self.state)
    }

    fn stop(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        (self.stop_fn)(&mut self.state)
    }

    fn is_healthy(&self) -> bool {
        (self.health_fn)(&self.state)
    }
}

/// Per-test JSON summary produced by [`TestHarness`].
#[derive(Debug, Clone, serde::Serialize)]
pub struct TestSummary {
    /// Name of the test.
    pub test_name: String,
    /// Whether the test passed overall.
    pub passed: bool,
    /// Total assertions.
    pub total_assertions: usize,
    /// Passed assertions.
    pub passed_assertions: usize,
    /// Failed assertions.
    pub failed_assertions: usize,
    /// Total duration in milliseconds.
    pub duration_ms: f64,
    /// Hierarchical phase tree.
    pub phases: Vec<PhaseNode>,
    /// Artifacts collected on failure (file paths).
    pub failure_artifacts: Vec<String>,
    /// Event log statistics.
    pub event_stats: EventStats,
    /// Structured test context (if provided).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<TestContext>,
}

/// Summary statistics from the event log.
#[derive(Debug, Clone, serde::Serialize)]
pub struct EventStats {
    /// Total events captured.
    pub total_events: usize,
    /// Task spawns.
    pub task_spawns: usize,
    /// Task completions.
    pub task_completions: usize,
    /// Reactor polls.
    pub reactor_polls: usize,
    /// Errors logged.
    pub errors: usize,
    /// Warnings logged.
    pub warnings: usize,
}

/// E2E test harness with hierarchical phase tracking, assertion capture,
/// and automatic failure artifact collection.
///
/// # Example
///
/// ```no_run
/// use asupersync::test_logging::TestHarness;
/// # let port: u16 = 8080; // the listener's bound port
/// let mut harness = TestHarness::new("my_e2e_test");
/// harness.enter_phase("setup");
///   harness.enter_phase("create_listener");
///   harness.assert_eq("port bound", &8080, &port);
///   harness.exit_phase();
/// harness.exit_phase();
///
/// harness.enter_phase("exercise");
/// // ... test body ...
/// harness.exit_phase();
///
/// let summary = harness.finish();
/// println!("{}", serde_json::to_string_pretty(&summary).unwrap());
/// ```
#[derive(Debug)]
pub struct TestHarness {
    /// Test name.
    test_name: String,
    /// Underlying event logger.
    logger: TestLogger,
    /// Stack of open phase indices (indices into the flat phases vec).
    phase_stack: Vec<usize>,
    /// All phases (flat storage; tree structure via children indices).
    phases: Vec<PhaseNode>,
    /// All assertions recorded.
    assertions: Vec<AssertionRecord>,
    /// Artifact directory for failure dumps.
    artifact_dir: Option<std::path::PathBuf>,
    /// Collected artifact paths.
    artifacts: Vec<String>,
    /// Start instant.
    start: Instant,
    /// Structured test context for standardized logging.
    context: Option<TestContext>,
}

impl TestHarness {
    /// Create a new test harness.
    #[must_use]
    pub fn new(test_name: &str) -> Self {
        Self {
            test_name: test_name.to_string(),
            logger: TestLogger::new(TestLogLevel::from_env()),
            phase_stack: Vec::new(),
            phases: Vec::new(),
            assertions: Vec::new(),
            artifact_dir: artifact_dir_from_env(),
            artifacts: Vec::new(),
            start: Instant::now(),
            context: None,
        }
    }

    /// Create a harness with a specific log level.
    #[must_use]
    pub fn with_level(test_name: &str, level: TestLogLevel) -> Self {
        Self {
            test_name: test_name.to_string(),
            logger: TestLogger::new(level),
            phase_stack: Vec::new(),
            phases: Vec::new(),
            assertions: Vec::new(),
            artifact_dir: artifact_dir_from_env(),
            artifacts: Vec::new(),
            start: Instant::now(),
            context: None,
        }
    }

    /// Create a harness with a structured [`TestContext`] for standardized logging.
    ///
    /// The context fields (test_id, seed, subsystem, invariant) are included in
    /// the test summary and emitted in tracing events.
    #[must_use]
    pub fn with_context(test_name: &str, ctx: TestContext) -> Self {
        ctx.log_start();
        Self {
            test_name: test_name.to_string(),
            logger: TestLogger::new(TestLogLevel::from_env()),
            phase_stack: Vec::new(),
            phases: Vec::new(),
            assertions: Vec::new(),
            artifact_dir: artifact_dir_from_env(),
            artifacts: Vec::new(),
            start: Instant::now(),
            context: Some(ctx),
        }
    }

    /// Returns the test context, if one was provided.
    #[must_use]
    pub fn context(&self) -> Option<&TestContext> {
        self.context.as_ref()
    }

    /// Access the underlying [`TestLogger`].
    #[must_use]
    pub fn logger(&self) -> &TestLogger {
        &self.logger
    }

    /// Returns the current phase path as "phase > section > step".
    #[must_use]
    pub fn current_phase_path(&self) -> String {
        self.phase_stack
            .iter()
            .map(|&idx| self.phases[idx].name.as_str())
            .collect::<Vec<_>>()
            .join(" > ")
    }

    /// Enter a new phase (push onto the hierarchy stack).
    pub fn enter_phase(&mut self, name: &str) {
        let elapsed = self.start.elapsed().as_secs_f64() * 1000.0;
        let depth = self.phase_stack.len();
        let node = PhaseNode {
            name: name.to_string(),
            depth,
            start_ms: elapsed,
            end_ms: None,
            assertions: Vec::new(),
            children: Vec::new(),
        };
        let idx = self.phases.len();
        self.phases.push(node);

        // Link as child of current parent.
        if let Some(&parent_idx) = self.phase_stack.last() {
            self.phases[parent_idx].children.push(PhaseNode {
                name: String::new(),
                depth: 0,
                start_ms: 0.0,
                end_ms: None,
                assertions: Vec::new(),
                children: Vec::new(),
            });
            // We'll rebuild the tree in finish(); for now track indices.
        }

        self.phase_stack.push(idx);

        tracing::info!(
            phase = %name,
            depth = depth,
            path = %self.current_phase_path(),
            ">>> ENTER PHASE"
        );
    }

    /// Exit the current phase.
    pub fn exit_phase(&mut self) {
        let elapsed = self.start.elapsed().as_secs_f64() * 1000.0;
        if let Some(idx) = self.phase_stack.pop() {
            self.phases[idx].end_ms = Some(elapsed);
            tracing::info!(
                phase = %self.phases[idx].name,
                duration_ms = %(elapsed - self.phases[idx].start_ms),
                "<<< EXIT PHASE"
            );
        }
    }

    /// Record an assertion with context.
    pub fn record_assertion(
        &mut self,
        description: &str,
        passed: bool,
        expected: &str,
        actual: &str,
    ) {
        let elapsed = self.start.elapsed().as_secs_f64() * 1000.0;
        let phase_path = self.current_phase_path();

        let record = AssertionRecord {
            description: description.to_string(),
            passed,
            expected: expected.to_string(),
            actual: actual.to_string(),
            phase_path: phase_path.clone(),
            elapsed_ms: elapsed,
        };

        // Attach to current phase if one is open.
        if let Some(&idx) = self.phase_stack.last() {
            self.phases[idx].assertions.push(record.clone());
        }
        self.assertions.push(record);

        if passed {
            tracing::debug!(
                assertion = %description,
                phase = %phase_path,
                "PASS"
            );
        } else {
            tracing::error!(
                assertion = %description,
                expected = %expected,
                actual = %actual,
                phase = %phase_path,
                "FAIL"
            );
        }
    }

    /// Assert equality and record the result.
    ///
    /// Returns whether the assertion passed.
    pub fn assert_eq<T: std::fmt::Debug + PartialEq>(
        &mut self,
        description: &str,
        expected: &T,
        actual: &T,
    ) -> bool {
        let passed = expected == actual;
        self.record_assertion(
            description,
            passed,
            &format!("{expected:?}"),
            &format!("{actual:?}"),
        );
        passed
    }

    /// Assert a boolean condition and record the result.
    ///
    /// Returns whether the assertion passed.
    pub fn assert_true(&mut self, description: &str, condition: bool) -> bool {
        self.record_assertion(description, condition, "true", &format!("{condition}"));
        condition
    }

    /// Collect a failure artifact (writes content to artifact dir if configured).
    pub fn collect_artifact(&mut self, name: &str, content: &str) {
        if let Some(ref dir) = self.artifact_dir {
            let safe_test = self.test_name.replace(|c: char| !c.is_alphanumeric(), "_");
            let artifact_dir = dir.join(&safe_test);
            if std::fs::create_dir_all(&artifact_dir).is_ok() {
                let path = artifact_dir.join(name);
                if std::fs::write(&path, content).is_ok() {
                    self.artifacts.push(path.display().to_string());
                    tracing::info!(path = %path.display(), "collected failure artifact");
                }
            }
        }
    }

    /// Collect the phase names executed so far (flat list).
    #[must_use]
    pub fn phases_executed(&self) -> Vec<String> {
        self.phases.iter().map(|p| p.name.clone()).collect()
    }

    /// Generate a [`ReproManifest`] from the current harness state.
    #[must_use]
    pub fn repro_manifest(&self, passed: bool) -> ReproManifest {
        let mut manifest = self.context.as_ref().map_or_else(
            || ReproManifest::new(0, &self.test_name, passed),
            |ctx| ReproManifest::from_context(ctx, passed),
        );

        manifest = manifest
            .with_env_snapshot()
            .with_phases(self.phases_executed())
            .with_artifact_paths(self.artifacts.clone());

        if passed {
            manifest = manifest.with_failure_class(FAILURE_CLASS_PASSED);
        } else {
            if let Some(first_failure) = self.assertions.iter().find(|a| !a.passed) {
                manifest = manifest.with_failure_reason(&format!(
                    "{}: expected={}, actual={}",
                    first_failure.description, first_failure.expected, first_failure.actual,
                ));
            }
            manifest = manifest.with_failure_class(FAILURE_CLASS_ASSERTION_FAILURE);
        }

        manifest
    }

    /// Build the hierarchical phase tree from flat storage.
    ///
    /// Uses an index-path stack to avoid unsafe pointer aliasing.
    /// The stack tracks the index path from root to the current parent,
    /// allowing safe traversal via repeated indexing.
    fn build_phase_tree(&self) -> Vec<PhaseNode> {
        let mut roots: Vec<PhaseNode> = Vec::new();
        // Stack of (depth, child_index) pairs forming a path from roots
        // to the current insertion point.
        let mut path: Vec<(usize, usize)> = Vec::new();

        for phase in &self.phases {
            let node = PhaseNode {
                name: phase.name.clone(),
                depth: phase.depth,
                start_ms: phase.start_ms,
                end_ms: phase.end_ms,
                assertions: phase.assertions.clone(),
                children: Vec::new(),
            };

            if phase.depth == 0 {
                roots.push(node);
                let idx = roots.len() - 1;
                path.clear();
                path.push((0, idx));
            } else {
                // Pop stack until we find the parent depth.
                while path.len() > phase.depth {
                    path.pop();
                }

                // Navigate to the parent node via the index path and push.
                if !path.is_empty() {
                    // First index is into roots
                    let (_, root_idx) = path[0];
                    let mut current = &mut roots[root_idx];
                    for &(_, child_idx) in &path[1..] {
                        current = &mut current.children[child_idx];
                    }
                    current.children.push(node);
                    let child_idx = current.children.len() - 1;
                    path.push((phase.depth, child_idx));
                }
            }
        }

        roots
    }

    /// Compute event statistics from the logger.
    fn compute_event_stats(&self) -> EventStats {
        let events = self.logger.events();
        EventStats {
            total_events: events.len(),
            task_spawns: events
                .iter()
                .filter(|r| matches!(r.event, TestEvent::TaskSpawn { .. }))
                .count(),
            task_completions: events
                .iter()
                .filter(|r| matches!(r.event, TestEvent::TaskComplete { .. }))
                .count(),
            reactor_polls: events
                .iter()
                .filter(|r| matches!(r.event, TestEvent::ReactorPoll { .. }))
                .count(),
            errors: events
                .iter()
                .filter(|r| matches!(r.event, TestEvent::Error { .. }))
                .count(),
            warnings: events
                .iter()
                .filter(|r| matches!(r.event, TestEvent::Warn { .. }))
                .count(),
        }
    }

    /// Finish the test and produce a JSON-serializable summary.
    ///
    /// If the test failed and an artifact directory is configured, automatically
    /// collects the event log as an artifact.
    #[must_use]
    pub fn finish(mut self) -> TestSummary {
        // Close any unclosed phases.
        let elapsed = self.start.elapsed().as_secs_f64() * 1000.0;
        for &idx in self.phase_stack.iter().rev() {
            if self.phases[idx].end_ms.is_none() {
                self.phases[idx].end_ms = Some(elapsed);
            }
        }

        let total = self.assertions.len();
        let passed_count = self.assertions.iter().filter(|a| a.passed).count();
        let failed_count = total - passed_count;
        let overall_passed = failed_count == 0;

        // Auto-collect event log and repro manifest on failure.
        if !overall_passed {
            self.collect_artifact("event_log.txt", &self.logger.report());

            let failed_json = serde_json::to_string_pretty(
                &self
                    .assertions
                    .iter()
                    .filter(|a| !a.passed)
                    .collect::<Vec<_>>(),
            )
            .unwrap_or_default();
            self.collect_artifact("failed_assertions.json", &failed_json);

            let manifest = self.repro_manifest(false);
            if let Ok(manifest_json) = manifest.to_json() {
                self.collect_artifact("repro_manifest.json", &manifest_json);
            }
        }

        let phases = self.build_phase_tree();
        let event_stats = self.compute_event_stats();

        let summary = TestSummary {
            test_name: self.test_name.clone(),
            passed: overall_passed,
            total_assertions: total,
            passed_assertions: passed_count,
            failed_assertions: failed_count,
            duration_ms: elapsed,
            phases,
            failure_artifacts: self.artifacts.clone(),
            event_stats,
            context: self.context.clone(),
        };

        // Write JSON summary if artifact dir is configured.
        if let Some(ref dir) = self.artifact_dir {
            let safe_test = self.test_name.replace(|c: char| !c.is_alphanumeric(), "_");
            let summary_path = dir.join(format!("{safe_test}_summary.json"));
            if let Ok(json) = serde_json::to_string_pretty(&summary) {
                let _ = std::fs::create_dir_all(dir);
                let _ = std::fs::write(&summary_path, json);
            }
        }

        // Emit structured end event with context fields if available.
        if let Some(ref ctx) = self.context {
            ctx.log_end(overall_passed);
            if !overall_passed {
                ctx.log_failure("one or more assertions failed");
            }
        }

        tracing::info!(
            test = %self.test_name,
            passed = %overall_passed,
            assertions = total,
            passed_assertions = passed_count,
            failed_assertions = failed_count,
            duration_ms = %elapsed,
            "TEST SUMMARY"
        );

        summary
    }

    /// Produce the JSON string for the test summary.
    #[must_use]
    pub fn finish_json(self) -> String {
        let summary = self.finish();
        serde_json::to_string_pretty(&summary).unwrap_or_else(|_| "{}".to_string())
    }
}

/// Read the artifact directory from the environment.
fn artifact_dir_from_env() -> Option<std::path::PathBuf> {
    std::env::var("ASUPERSYNC_TEST_ARTIFACTS_DIR")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(std::path::PathBuf::from)
}

// ============================================================================
// TestReportAggregator — Coverage Matrix
// ============================================================================

/// Aggregates multiple [`TestSummary`] results into a coverage matrix.
#[derive(Debug, Default, serde::Serialize)]
pub struct TestReportAggregator {
    /// All collected summaries.
    pub summaries: Vec<TestSummary>,
}

/// Aggregated report with coverage matrix.
#[derive(Debug, serde::Serialize)]
pub struct AggregatedReport {
    /// Total tests run.
    pub total_tests: usize,
    /// Tests that passed.
    pub passed_tests: usize,
    /// Tests that failed.
    pub failed_tests: usize,
    /// Total assertions across all tests.
    pub total_assertions: usize,
    /// Passed assertions across all tests.
    pub passed_assertions: usize,
    /// Coverage matrix: test_name -> list of phase names exercised.
    pub coverage_matrix: Vec<CoverageMatrixRow>,
    /// Per-test summaries.
    pub tests: Vec<TestSummaryBrief>,
}

/// One row in the coverage matrix.
#[derive(Debug, serde::Serialize)]
pub struct CoverageMatrixRow {
    /// Test name.
    pub test_name: String,
    /// Whether it passed.
    pub passed: bool,
    /// Phase names exercised.
    pub phases_exercised: Vec<String>,
    /// Number of assertions.
    pub assertion_count: usize,
    /// Duration in ms.
    pub duration_ms: f64,
}

/// Brief per-test entry in the aggregated report.
#[derive(Debug, serde::Serialize)]
pub struct TestSummaryBrief {
    /// Test name.
    pub test_name: String,
    /// Pass/fail.
    pub passed: bool,
    /// Assertion counts.
    pub assertions: usize,
    /// Failed count.
    pub failures: usize,
    /// Duration.
    pub duration_ms: f64,
}

impl TestReportAggregator {
    /// Create a new empty aggregator.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a test summary.
    pub fn add(&mut self, summary: TestSummary) {
        self.summaries.push(summary);
    }

    /// Collect phase names from a phase tree (recursive).
    fn collect_phase_names(phases: &[PhaseNode], out: &mut Vec<String>) {
        for phase in phases {
            out.push(phase.name.clone());
            Self::collect_phase_names(&phase.children, out);
        }
    }

    /// Produce the aggregated report.
    #[must_use]
    pub fn report(&self) -> AggregatedReport {
        let total = self.summaries.len();
        let passed = self.summaries.iter().filter(|s| s.passed).count();

        let total_assertions: usize = self.summaries.iter().map(|s| s.total_assertions).sum();
        let passed_assertions: usize = self.summaries.iter().map(|s| s.passed_assertions).sum();

        let coverage_matrix: Vec<CoverageMatrixRow> = self
            .summaries
            .iter()
            .map(|s| {
                let mut phases = Vec::new();
                Self::collect_phase_names(&s.phases, &mut phases);
                CoverageMatrixRow {
                    test_name: s.test_name.clone(),
                    passed: s.passed,
                    phases_exercised: phases,
                    assertion_count: s.total_assertions,
                    duration_ms: s.duration_ms,
                }
            })
            .collect();

        let tests: Vec<TestSummaryBrief> = self
            .summaries
            .iter()
            .map(|s| TestSummaryBrief {
                test_name: s.test_name.clone(),
                passed: s.passed,
                assertions: s.total_assertions,
                failures: s.failed_assertions,
                duration_ms: s.duration_ms,
            })
            .collect();

        AggregatedReport {
            total_tests: total,
            passed_tests: passed,
            failed_tests: total - passed,
            total_assertions,
            passed_assertions,
            coverage_matrix,
            tests,
        }
    }

    /// Produce the aggregated report as a JSON string.
    #[must_use]
    pub fn report_json(&self) -> String {
        serde_json::to_string_pretty(&self.report()).unwrap_or_else(|_| "{}".to_string())
    }
}

// ============================================================================
// Harness Macros
// ============================================================================

/// Enter a hierarchical phase in a [`TestHarness`].
///
/// ```ignore
/// harness_phase!(harness, "setup");
/// // ... work ...
/// harness_phase_exit!(harness);
/// ```
#[macro_export]
macro_rules! harness_phase {
    ($harness:expr, $name:expr) => {
        $harness.enter_phase($name);
    };
}

/// Exit the current phase in a [`TestHarness`].
#[macro_export]
macro_rules! harness_phase_exit {
    ($harness:expr) => {
        $harness.exit_phase();
    };
}

/// Assert equality within a [`TestHarness`], recording the result.
///
/// Panics if the assertion fails.
#[macro_export]
macro_rules! harness_assert_eq {
    ($harness:expr, $desc:expr, $expected:expr, $actual:expr) => {
        match (&$expected, &$actual) {
            (expected_val, actual_val) => {
                if !$harness.assert_eq($desc, expected_val, actual_val) {
                    panic!(
                        "harness assertion failed: {}: expected {:?}, got {:?}",
                        $desc, expected_val, actual_val
                    );
                }
            }
        }
    };
}

/// Assert a condition within a [`TestHarness`], recording the result.
///
/// Panics if the assertion fails.
#[macro_export]
macro_rules! harness_assert {
    ($harness:expr, $desc:expr, $cond:expr) => {
        if !$harness.assert_true($desc, $cond) {
            panic!("harness assertion failed: {}", $desc);
        }
    };
}

// ============================================================================
// Structured Context Macros
// ============================================================================

/// Emit a structured tracing event with standard test context fields.
///
/// Includes `test_id`, `seed`, `subsystem`, and `invariant` from a [`TestContext`].
///
/// ```ignore
/// let ctx = TestContext::new("my_test", 0xDEAD_BEEF).with_subsystem("scheduler");
/// test_structured!(ctx, "task spawned", task_count = 5);
/// ```
#[macro_export]
macro_rules! test_structured {
    ($ctx:expr, $msg:expr) => {
        tracing::info!(
            test_id = %$ctx.test_id,
            seed = %format_args!("0x{:X}", $ctx.seed),
            subsystem = $ctx.subsystem.as_deref().unwrap_or("-"),
            invariant = $ctx.invariant.as_deref().unwrap_or("-"),
            $msg
        );
    };
    ($ctx:expr, $msg:expr, $($key:ident = $value:expr),+ $(,)?) => {
        tracing::info!(
            test_id = %$ctx.test_id,
            seed = %format_args!("0x{:X}", $ctx.seed),
            subsystem = $ctx.subsystem.as_deref().unwrap_or("-"),
            invariant = $ctx.invariant.as_deref().unwrap_or("-"),
            $($key = %$value,)+
            $msg
        );
    };
}

/// Emit a structured error dump with full context for failure triage.
///
/// Includes all context fields plus a reason string. Designed for use in
/// test failure paths to maximize reproducibility information.
///
/// ```ignore
/// let ctx = TestContext::new("my_test", 42).with_subsystem("obligation");
/// dump_test_failure!(ctx, "obligation leak detected", leaked_count = 3);
/// ```
#[macro_export]
macro_rules! dump_test_failure {
    ($ctx:expr, $reason:expr) => {
        tracing::error!(
            test_id = %$ctx.test_id,
            seed = %format_args!("0x{:X}", $ctx.seed),
            subsystem = $ctx.subsystem.as_deref().unwrap_or("-"),
            invariant = $ctx.invariant.as_deref().unwrap_or("-"),
            reason = %$reason,
            "TEST FAILURE — reproduce with seed 0x{:X}", $ctx.seed
        );
    };
    ($ctx:expr, $reason:expr, $($key:ident = $value:expr),+ $(,)?) => {
        tracing::error!(
            test_id = %$ctx.test_id,
            seed = %format_args!("0x{:X}", $ctx.seed),
            subsystem = $ctx.subsystem.as_deref().unwrap_or("-"),
            invariant = $ctx.invariant.as_deref().unwrap_or("-"),
            reason = %$reason,
            $($key = %$value,)+
            "TEST FAILURE — reproduce with seed 0x{:X}", $ctx.seed
        );
    };
}

/// Assert a condition and, on failure, emit a structured dump with full context.
///
/// ```ignore
/// let ctx = TestContext::new("my_test", 42).with_subsystem("scheduler");
/// assert_with_context!(ctx, task_count > 0, "expected at least one task");
/// ```
#[macro_export]
macro_rules! assert_with_context {
    ($ctx:expr, $cond:expr, $msg:expr) => {
        if !$cond {
            $crate::dump_test_failure!($ctx, $msg);
            panic!("assertion failed [{}]: {}", $ctx.test_id, $msg);
        }
    };
    ($ctx:expr, $cond:expr, $msg:expr, $($key:ident = $value:expr),+ $(,)?) => {
        if !$cond {
            $crate::dump_test_failure!($ctx, $msg, $($key = $value),+);
            panic!("assertion failed [{}]: {}", $ctx.test_id, $msg);
        }
    };
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(unsafe_code)]
#[path = "test_logging_inline_tests.rs"]
mod tests;
