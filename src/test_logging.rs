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

    /// Emit a tracing info event with all context fields.
    pub fn log_start(&self) {
        tracing::info!(
            test_id = %self.test_id,
            seed = %format_args!("0x{:X}", self.seed),
            subsystem = self.subsystem.as_deref().unwrap_or("-"),
            invariant = self.invariant.as_deref().unwrap_or("-"),
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
            passed = passed,
            "TEST END"
        );
    }

    /// Emit a structured error dump with full context for failure triage.
    pub fn log_failure(&self, reason: &str) {
        tracing::error!(
            test_id = %self.test_id,
            seed = %format_args!("0x{:X}", self.seed),
            subsystem = self.subsystem.as_deref().unwrap_or("-"),
            invariant = self.invariant.as_deref().unwrap_or("-"),
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
            "test_id={} seed=0x{:X} subsystem={} invariant={}",
            self.test_id,
            self.seed,
            self.subsystem.as_deref().unwrap_or("-"),
            self.invariant.as_deref().unwrap_or("-"),
        )
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
/// ```ignore
/// use asupersync::test_logging::TestHarness;
///
/// let mut harness = TestHarness::new("my_e2e_test");
/// harness.enter_phase("setup");
///   harness.enter_phase("create_listener");
///   harness.assert_eq("port bound", 8080, listener.port());
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

        // Auto-collect event log on failure.
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
        if !$harness.assert_eq($desc, &$expected, &$actual) {
            panic!(
                "harness assertion failed: {}: expected {:?}, got {:?}",
                $desc, $expected, $actual
            );
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

    // ====================================================================
    // TestHarness tests
    // ====================================================================

    #[test]
    fn test_harness_basic_flow() {
        init_test("test_harness_basic_flow");
        let mut harness = TestHarness::new("basic_flow");

        harness.enter_phase("setup");
        harness.assert_true("always true", true);
        harness.exit_phase();

        harness.enter_phase("exercise");
        harness.assert_eq("equality", &42, &42);
        harness.exit_phase();

        let summary = harness.finish();
        assert_eq!(summary.test_name, "basic_flow");
        assert!(summary.passed);
        assert_eq!(summary.total_assertions, 2);
        assert_eq!(summary.passed_assertions, 2);
        assert_eq!(summary.failed_assertions, 0);
        crate::test_complete!("test_harness_basic_flow");
    }

    #[test]
    fn test_harness_nested_phases() {
        init_test("test_harness_nested_phases");
        let mut harness = TestHarness::new("nested");

        harness.enter_phase("outer");
        harness.enter_phase("inner");
        assert_eq!(harness.current_phase_path(), "outer > inner");
        harness.exit_phase();
        harness.exit_phase();

        let summary = harness.finish();
        assert!(summary.passed);
        assert_eq!(summary.phases.len(), 1); // one root
        crate::test_complete!("test_harness_nested_phases");
    }

    #[test]
    fn test_harness_failed_assertion_recorded() {
        init_test("test_harness_failed_assertion_recorded");
        let mut harness = TestHarness::new("fail_test");

        harness.enter_phase("check");
        // Don't panic, just record
        let passed = harness.assert_eq("mismatch", &1, &2);
        assert!(!passed);
        harness.exit_phase();

        let summary = harness.finish();
        assert!(!summary.passed);
        assert_eq!(summary.failed_assertions, 1);
        crate::test_complete!("test_harness_failed_assertion_recorded");
    }

    #[test]
    fn test_harness_json_serialization() {
        init_test("test_harness_json_serialization");
        let mut harness = TestHarness::new("json_test");
        harness.assert_true("ok", true);
        let json = harness.finish_json();
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        assert_eq!(parsed["test_name"], "json_test");
        assert_eq!(parsed["passed"], true);
        crate::test_complete!("test_harness_json_serialization");
    }

    #[test]
    fn test_report_aggregator() {
        init_test("test_report_aggregator");
        let mut agg = TestReportAggregator::new();

        // Test 1: passing
        let mut h1 = TestHarness::new("test_a");
        h1.enter_phase("setup");
        h1.assert_true("ok", true);
        h1.exit_phase();
        agg.add(h1.finish());

        // Test 2: failing
        let mut h2 = TestHarness::new("test_b");
        h2.enter_phase("check");
        h2.assert_eq("bad", &1, &2);
        h2.exit_phase();
        agg.add(h2.finish());

        let report = agg.report();
        assert_eq!(report.total_tests, 2);
        assert_eq!(report.passed_tests, 1);
        assert_eq!(report.failed_tests, 1);
        assert_eq!(report.total_assertions, 2);
        assert_eq!(report.passed_assertions, 1);
        assert_eq!(report.coverage_matrix.len(), 2);
        assert_eq!(report.coverage_matrix[0].phases_exercised, vec!["setup"]);
        assert_eq!(report.coverage_matrix[1].phases_exercised, vec!["check"]);

        // Verify JSON round-trip
        let json = agg.report_json();
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        assert_eq!(parsed["total_tests"], 2);
        crate::test_complete!("test_report_aggregator");
    }

    #[test]
    fn test_harness_macros() {
        init_test("test_harness_macros");
        let mut harness = TestHarness::new("macro_test");
        harness_phase!(harness, "setup");
        harness_assert!(harness, "truthy", true);
        harness_assert_eq!(harness, "equal", 5, 5);
        harness_phase_exit!(harness);
        let summary = harness.finish();
        assert!(summary.passed);
        assert_eq!(summary.total_assertions, 2);
        crate::test_complete!("test_harness_macros");
    }

    // ====================================================================
    // TestContext tests
    // ====================================================================

    #[test]
    fn test_context_creation() {
        init_test("test_context_creation");
        let ctx = TestContext::new("ctx_test", 0xCAFE)
            .with_subsystem("scheduler")
            .with_invariant("no_leaks");

        assert_eq!(ctx.test_id, "ctx_test");
        assert_eq!(ctx.seed, 0xCAFE);
        assert_eq!(ctx.subsystem.as_deref(), Some("scheduler"));
        assert_eq!(ctx.invariant.as_deref(), Some("no_leaks"));
        crate::test_complete!("test_context_creation");
    }

    #[test]
    fn test_context_display() {
        init_test("test_context_display");
        let ctx = TestContext::new("disp_test", 42).with_subsystem("raptorq");
        let rendered = format!("{ctx}");
        assert!(rendered.contains("test_id=disp_test"));
        assert!(rendered.contains("seed=0x2A"));
        assert!(rendered.contains("subsystem=raptorq"));
        crate::test_complete!("test_context_display");
    }

    #[test]
    fn test_context_serialization() {
        init_test("test_context_serialization");
        let ctx = TestContext::new("ser_test", 0xDEAD)
            .with_subsystem("obligation")
            .with_invariant("committed_or_aborted");

        let json = serde_json::to_string(&ctx).expect("serialize");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse");
        assert_eq!(parsed["test_id"], "ser_test");
        assert_eq!(parsed["seed"], 0xDEAD);
        assert_eq!(parsed["subsystem"], "obligation");
        assert_eq!(parsed["invariant"], "committed_or_aborted");
        crate::test_complete!("test_context_serialization");
    }

    #[test]
    fn test_harness_with_context() {
        init_test("test_harness_with_context");
        let ctx = TestContext::new("harness_ctx", 0xBEEF)
            .with_subsystem("cancellation")
            .with_invariant("losers_drained");

        let mut harness = TestHarness::with_context("ctx_harness", ctx);
        assert!(harness.context().is_some());
        assert_eq!(harness.context().unwrap().test_id, "harness_ctx");

        harness.enter_phase("verify");
        harness.assert_true("context present", harness.context().is_some());
        harness.exit_phase();

        let summary = harness.finish();
        assert!(summary.passed);
        assert!(summary.context.is_some());
        assert_eq!(summary.context.unwrap().seed, 0xBEEF);
        crate::test_complete!("test_harness_with_context");
    }

    #[test]
    fn test_harness_without_context() {
        init_test("test_harness_without_context");
        let harness = TestHarness::new("no_ctx");
        assert!(harness.context().is_none());

        let summary = harness.finish();
        assert!(summary.context.is_none());
        crate::test_complete!("test_harness_without_context");
    }

    #[test]
    fn test_structured_macros() {
        init_test("test_structured_macros");
        let ctx = TestContext::new("macro_ctx", 0x42)
            .with_subsystem("sync")
            .with_invariant("no_deadlock");

        // These should compile and not panic.
        test_structured!(ctx, "simple message");
        test_structured!(ctx, "with fields", count = 5);
        test_structured!(ctx, "multi fields", count = 5, label = "test");
        crate::test_complete!("test_structured_macros");
    }
}
