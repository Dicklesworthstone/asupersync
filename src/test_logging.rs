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
//! ```ignore
//! use asupersync::test_logging::{TestLogger, TestLogLevel, TestEvent};
//!
//! let logger = TestLogger::new(TestLogLevel::Debug);
//! logger.log(TestEvent::TaskSpawn { task_id: 1, name: Some("worker".into()) });
//!
//! // On test completion, print the report
//! println!("{}", logger.report());
//! ```

use std::fmt::Write as _;
use std::sync::Mutex;
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
            verbose: level >= TestLogLevel::Trace,
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
        self.events.lock().expect("lock poisoned").push(record);
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
        self.events.lock().expect("lock poisoned").len()
    }

    /// Returns a snapshot of all captured events.
    #[must_use]
    pub fn events(&self) -> Vec<LogRecord> {
        self.events.lock().expect("lock poisoned").clone()
    }

    /// Generates a detailed report of all captured events.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    #[allow(clippy::significant_drop_tightening)]
    pub fn report(&self) -> String {
        let events = self.events.lock().expect("lock poisoned");
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
            let events = self.events.lock().expect("lock poisoned");
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
            let events = self.events.lock().expect("lock poisoned");
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
            let events = self.events.lock().expect("lock poisoned");

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
        self.events.lock().expect("lock poisoned").clear();
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
        if $left != $right {
            tracing::error!(report = %$logger.report(), "assertion failed: left == right");
            panic!(
                "assertion failed: `(left == right)`\n  left: {:?}\n right: {:?}",
                $left, $right
            );
        }
    };
    ($logger:expr, $left:expr, $right:expr, $($arg:tt)*) => {
        if $left != $right {
            tracing::error!(report = %$logger.report(), "assertion failed: {}", format_args!($($arg)*));
            panic!(
                "assertion failed: `(left == right)`\n  left: {:?}\n right: {:?}\n{}",
                $left, $right, format!($($arg)*)
            );
        }
    };
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn test_log_level_ordering() {
        init_test("test_log_level_ordering");
        let error_warn = TestLogLevel::Error < TestLogLevel::Warn;
        crate::assert_with_log!(error_warn, "error < warn", true, error_warn);
        let warn_info = TestLogLevel::Warn < TestLogLevel::Info;
        crate::assert_with_log!(warn_info, "warn < info", true, warn_info);
        let info_debug = TestLogLevel::Info < TestLogLevel::Debug;
        crate::assert_with_log!(info_debug, "info < debug", true, info_debug);
        let debug_trace = TestLogLevel::Debug < TestLogLevel::Trace;
        crate::assert_with_log!(debug_trace, "debug < trace", true, debug_trace);
        crate::test_complete!("test_log_level_ordering");
    }

    #[test]
    fn test_log_level_from_str() {
        init_test("test_log_level_from_str");
        let error = "error".parse();
        let ok = matches!(error, Ok(TestLogLevel::Error));
        crate::assert_with_log!(ok, "parse error", true, ok);
        let error_upper = "ERROR".parse();
        let ok = matches!(error_upper, Ok(TestLogLevel::Error));
        crate::assert_with_log!(ok, "parse ERROR", true, ok);
        let warn = "warn".parse();
        let ok = matches!(warn, Ok(TestLogLevel::Warn));
        crate::assert_with_log!(ok, "parse warn", true, ok);
        let warning = "warning".parse();
        let ok = matches!(warning, Ok(TestLogLevel::Warn));
        crate::assert_with_log!(ok, "parse warning", true, ok);
        let info = "info".parse();
        let ok = matches!(info, Ok(TestLogLevel::Info));
        crate::assert_with_log!(ok, "parse info", true, ok);
        let debug_level = "debug".parse();
        let ok = matches!(debug_level, Ok(TestLogLevel::Debug));
        crate::assert_with_log!(ok, "parse debug", true, ok);
        let trace = "trace".parse();
        let ok = matches!(trace, Ok(TestLogLevel::Trace));
        crate::assert_with_log!(ok, "parse trace", true, ok);
        let invalid: Result<TestLogLevel, ()> = "invalid".parse();
        let ok = invalid.is_err();
        crate::assert_with_log!(ok, "parse invalid", true, ok);
        crate::test_complete!("test_log_level_from_str");
    }

    #[test]
    fn test_logger_captures_events() {
        init_test("test_logger_captures_events");
        let logger = TestLogger::new(TestLogLevel::Trace);

        logger.log(TestEvent::TaskSpawn {
            task_id: 1,
            name: Some("worker".into()),
        });
        logger.log(TestEvent::TaskPoll {
            task_id: 1,
            result: "pending",
        });
        logger.log(TestEvent::TaskComplete {
            task_id: 1,
            outcome: "ok",
        });

        let count = logger.event_count();
        crate::assert_with_log!(count == 3, "event_count", 3, count);
        crate::test_complete!("test_logger_captures_events");
    }

    #[test]
    fn test_logger_filters_by_level() {
        init_test("test_logger_filters_by_level");
        let logger = TestLogger::new(TestLogLevel::Info);

        // This should be captured (Info level)
        logger.log(TestEvent::TaskSpawn {
            task_id: 1,
            name: None,
        });

        // This should NOT be captured (Trace level)
        logger.log(TestEvent::TaskPoll {
            task_id: 1,
            result: "pending",
        });

        let count = logger.event_count();
        crate::assert_with_log!(count == 1, "event_count", 1, count);
        crate::test_complete!("test_logger_filters_by_level");
    }

    #[test]
    fn test_logger_report_includes_statistics() {
        init_test("test_logger_report_includes_statistics");
        let logger = TestLogger::new(TestLogLevel::Trace);

        logger.log(TestEvent::TaskSpawn {
            task_id: 1,
            name: None,
        });
        logger.log(TestEvent::TaskSpawn {
            task_id: 2,
            name: None,
        });
        logger.log(TestEvent::TaskComplete {
            task_id: 1,
            outcome: "ok",
        });

        let report = logger.report();
        let has_spawns = report.contains("Task spawns: 2");
        crate::assert_with_log!(has_spawns, "report contains task spawns", true, has_spawns);
        let has_events = report.contains("3 events");
        crate::assert_with_log!(has_events, "report contains events count", true, has_events);
        crate::test_complete!("test_logger_report_includes_statistics");
    }

    #[test]
    fn test_busy_loop_detection() {
        init_test("test_busy_loop_detection");
        let logger = TestLogger::new(TestLogLevel::Trace);

        // Log some empty polls
        for _ in 0..3 {
            logger.log(TestEvent::ReactorPoll {
                timeout: None,
                events_returned: 0,
                duration: Duration::from_micros(10),
            });
        }

        // This should pass (3 <= 5)
        logger.assert_no_busy_loop(5);
        crate::test_complete!("test_busy_loop_detection");
    }

    #[test]
    #[should_panic(expected = "Busy loop detected")]
    fn test_busy_loop_detection_fails() {
        init_test("test_busy_loop_detection_fails");
        let logger = TestLogger::new(TestLogLevel::Trace);

        // Log too many empty polls
        for _ in 0..10 {
            logger.log(TestEvent::ReactorPoll {
                timeout: None,
                events_returned: 0,
                duration: Duration::from_micros(10),
            });
        }

        // This should fail (10 > 5)
        logger.assert_no_busy_loop(5);
    }

    #[test]
    fn test_task_completion_check() {
        init_test("test_task_completion_check");
        let logger = TestLogger::new(TestLogLevel::Trace);

        logger.log(TestEvent::TaskSpawn {
            task_id: 1,
            name: None,
        });
        logger.log(TestEvent::TaskComplete {
            task_id: 1,
            outcome: "ok",
        });

        // Should pass
        logger.assert_all_tasks_completed();
        crate::test_complete!("test_task_completion_check");
    }

    #[test]
    #[should_panic(expected = "Task leak detected")]
    fn test_task_completion_check_fails() {
        init_test("test_task_completion_check_fails");
        let logger = TestLogger::new(TestLogLevel::Trace);

        logger.log(TestEvent::TaskSpawn {
            task_id: 1,
            name: None,
        });
        // No completion event

        logger.assert_all_tasks_completed();
    }

    #[test]
    fn test_macros() {
        init_test("test_macros");
        let logger = TestLogger::new(TestLogLevel::Debug);

        test_log!(logger, "test", "Message with arg: {}", 42);
        test_error!(logger, "io", "Error message");
        test_warn!(logger, "perf", "Warning message");

        let count = logger.event_count();
        crate::assert_with_log!(count == 3, "event_count", 3, count);
        crate::test_complete!("test_macros");
    }

    #[test]
    fn test_interest_display() {
        init_test("test_interest_display");
        let readable = format!("{}", Interest::READABLE);
        crate::assert_with_log!(readable == "R", "readable display", "R", readable);
        let writable = format!("{}", Interest::WRITABLE);
        crate::assert_with_log!(writable == "W", "writable display", "W", writable);
        let both = format!("{}", Interest::BOTH);
        crate::assert_with_log!(both == "RW", "both display", "RW", both);
        crate::test_complete!("test_interest_display");
    }

    #[test]
    fn test_event_display() {
        init_test("test_event_display");
        let event = TestEvent::TaskSpawn {
            task_id: 42,
            name: Some("worker".into()),
        };
        let rendered = format!("{event}");
        let has_task = rendered.contains("task=42");
        crate::assert_with_log!(has_task, "rendered task id", true, has_task);
        let has_worker = rendered.contains("worker");
        crate::assert_with_log!(has_worker, "rendered worker name", true, has_worker);
        crate::test_complete!("test_event_display");
    }
}
