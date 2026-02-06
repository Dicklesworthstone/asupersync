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
    /// Entropy seed derived from root.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entropy_seed: Option<u64>,
    /// Hash of the test configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_hash: Option<String>,
    /// Fingerprint of the execution trace.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_fingerprint: Option<String>,
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
}

impl ReproManifest {
    /// Create a new manifest with required fields.
    #[must_use]
    pub fn new(seed: u64, scenario_id: &str, passed: bool) -> Self {
        Self {
            schema_version: ARTIFACT_SCHEMA_VERSION,
            seed,
            scenario_id: scenario_id.to_string(),
            entropy_seed: None,
            config_hash: None,
            trace_fingerprint: None,
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
        }
    }

    /// Create a manifest from a [`TestContext`] and pass/fail status.
    #[must_use]
    pub fn from_context(ctx: &TestContext, passed: bool) -> Self {
        Self {
            schema_version: ARTIFACT_SCHEMA_VERSION,
            seed: ctx.seed,
            scenario_id: ctx.test_id.clone(),
            entropy_seed: None,
            config_hash: None,
            trace_fingerprint: None,
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
        self
    }

    /// Set the entropy seed derived from the root seed.
    #[must_use]
    pub fn with_entropy_seed(mut self, entropy_seed: u64) -> Self {
        self.entropy_seed = Some(entropy_seed);
        self
    }

    /// Set the configuration hash used for this run.
    #[must_use]
    pub fn with_config_hash(mut self, config_hash: &str) -> Self {
        self.config_hash = Some(config_hash.to_string());
        self
    }

    /// Set the trace fingerprint for this run.
    #[must_use]
    pub fn with_trace_fingerprint(mut self, trace_fingerprint: &str) -> Self {
        self.trace_fingerprint = Some(trace_fingerprint.to_string());
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
}

#[derive(Debug)]
struct ServiceEntry {
    service: Box<dyn FixtureService>,
    started_at: Instant,
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
            started_at: Instant::now(),
        });
    }

    /// Start all registered services.
    pub fn start_all_services(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        for entry in &mut self.services {
            tracing::info!(service = %entry.service.name(), "starting fixture service");
            entry.service.start()?;
            entry.started_at = Instant::now();
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

    /// Perform explicit teardown: stop services, release ports, run cleanup fns.
    pub fn teardown(&mut self) {
        if self.torn_down {
            return;
        }
        self.torn_down = true;
        tracing::info!(test_id = %self.context.test_id, "E2E environment teardown");

        for entry in self.services.iter_mut().rev() {
            let elapsed = entry.started_at.elapsed();
            tracing::debug!(
                service = %entry.service.name(),
                elapsed_ms = elapsed.as_millis() as u64,
                "stopping fixture service"
            );
            if let Err(e) = entry.service.stop() {
                tracing::warn!(service = %entry.service.name(), error = %e, "fixture service stop failed");
            }
        }
        self.ports.release_all();
        let fns: Vec<_> = self.cleanup_fns.drain(..).collect();
        for f in fns.into_iter().rev() {
            f();
        }
        tracing::info!(test_id = %self.context.test_id, "E2E environment teardown complete");
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
                elapsed_ms = elapsed.as_millis() as u64,
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

/// A fixture service backed by a Docker container.
///
/// Launches a container with `docker run`, removes it on stop, and health
/// checks via a configurable command (defaults to checking if the container
/// is in `running` state).
///
/// # Example
///
/// ```ignore
/// let mut redis = DockerFixtureService::new("redis", "redis:7-alpine")
///     .with_port_map(port, 6379)
///     .with_health_cmd(vec!["redis-cli", "ping"]);
/// redis.start()?;
/// wait_until_healthy(&redis, Duration::from_secs(10))?;
/// ```
#[derive(Debug)]
pub struct DockerFixtureService {
    service_name: String,
    image: String,
    container_name: String,
    port_maps: Vec<(u16, u16)>,
    env_vars: Vec<(String, String)>,
    health_cmd: Option<Vec<String>>,
    started: bool,
}

impl DockerFixtureService {
    /// Create a new Docker fixture with a service name and image.
    ///
    /// A unique container name is generated from the service name and process
    /// ID to avoid collisions between parallel test runs.
    #[must_use]
    pub fn new(service_name: &str, image: &str) -> Self {
        let container_name = format!("asupersync-test-{}-{}", service_name, std::process::id());
        Self {
            service_name: service_name.to_string(),
            image: image.to_string(),
            container_name,
            port_maps: Vec::new(),
            env_vars: Vec::new(),
            health_cmd: None,
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

    /// Set a custom health check command to run inside the container via
    /// `docker exec`.
    #[must_use]
    pub fn with_health_cmd(mut self, cmd: Vec<&str>) -> Self {
        self.health_cmd = Some(cmd.into_iter().map(String::from).collect());
        self
    }

    /// Returns the container name.
    #[must_use]
    pub fn container_name(&self) -> &str {
        &self.container_name
    }

    fn run_docker_cmd(args: &[&str]) -> Result<std::process::Output, Box<dyn std::error::Error>> {
        let output = std::process::Command::new("docker").args(args).output()?;
        Ok(output)
    }
}

impl FixtureService for DockerFixtureService {
    fn name(&self) -> &str {
        &self.service_name
    }

    fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Remove any stale container with the same name.
        let _ = Self::run_docker_cmd(&["rm", "-f", &self.container_name]);

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
            let stderr = String::from_utf8_lossy(&output.stderr);
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
        if !self.started {
            return Ok(());
        }
        tracing::info!(container = %self.container_name, "stopping docker container");
        let output = Self::run_docker_cmd(&["rm", "-f", &self.container_name])?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::warn!(
                container = %self.container_name,
                error = %stderr,
                "docker rm failed"
            );
        }
        self.started = false;
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
        let dir = tempfile::Builder::new().prefix(&self.prefix).tempdir()?;
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
/// mock, etc.) where a full Docker container is unnecessary.
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
            .with_phases(self.phases_executed());

        if !passed {
            if let Some(first_failure) = self.assertions.iter().find(|a| !a.passed) {
                manifest = manifest.with_failure_reason(&format!(
                    "{}: expected={}, actual={}",
                    first_failure.description, first_failure.expected, first_failure.actual,
                ));
            }
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
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;

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

    // ----------------------------------------------------------------
    // Seed derivation tests
    // ----------------------------------------------------------------

    #[test]
    fn test_seed_derivation_deterministic() {
        init_test("test_seed_derivation_deterministic");
        let root = 0xDEAD_BEEF;
        assert_eq!(
            derive_component_seed(root, "scheduler"),
            derive_component_seed(root, "scheduler")
        );
        assert_eq!(
            derive_scenario_seed(root, "cancel"),
            derive_scenario_seed(root, "cancel")
        );
        assert_eq!(derive_entropy_seed(root, 0), derive_entropy_seed(root, 0));
        crate::test_complete!("test_seed_derivation_deterministic");
    }

    #[test]
    fn test_seed_derivation_unique() {
        init_test("test_seed_derivation_unique");
        let root = 0xDEAD_BEEF;
        assert_ne!(
            derive_component_seed(root, "scheduler"),
            derive_component_seed(root, "io")
        );
        assert_ne!(
            derive_scenario_seed(root, "cancel"),
            derive_scenario_seed(root, "join")
        );
        assert_ne!(derive_entropy_seed(root, 0), derive_entropy_seed(root, 1));
        // Component and scenario with same name differ due to prefix.
        assert_ne!(
            derive_component_seed(root, "cancel"),
            derive_scenario_seed(root, "cancel")
        );
        crate::test_complete!("test_seed_derivation_unique");
    }

    #[test]
    fn test_seed_derivation_cross_platform_stability() {
        init_test("test_seed_derivation_cross_platform_stability");
        // Pinned value for regression: FNV-1a of 0xDEAD_BEEF + "scheduler".
        let root = 0xDEAD_BEEF;
        let expected = 13_888_874_950_133_950_416;
        assert_eq!(
            derive_component_seed(root, "scheduler"),
            expected,
            "seed derivation must be platform-stable"
        );
        crate::test_complete!("test_seed_derivation_cross_platform_stability");
    }

    #[test]
    fn test_context_seed_methods() {
        init_test("test_context_seed_methods");
        let ctx = TestContext::new("seed_test", 0xCAFE);
        assert_eq!(
            ctx.component_seed("io"),
            derive_component_seed(0xCAFE, "io")
        );
        assert_eq!(
            ctx.scenario_seed("cancel"),
            derive_scenario_seed(0xCAFE, "cancel")
        );
        assert_eq!(ctx.entropy_seed(5), derive_entropy_seed(0xCAFE, 5));
        crate::test_complete!("test_context_seed_methods");
    }

    // ----------------------------------------------------------------
    // ReproManifest tests
    // ----------------------------------------------------------------

    #[test]
    fn test_repro_manifest_from_context() {
        init_test("test_repro_manifest_from_context");
        let ctx = TestContext::new("obligation_leak", 42)
            .with_subsystem("obligation")
            .with_invariant("committed_or_aborted");
        let manifest = ReproManifest::from_context(&ctx, false);
        assert_eq!(manifest.seed, 42);
        assert_eq!(manifest.scenario_id, "obligation_leak");
        assert_eq!(manifest.subsystem.as_deref(), Some("obligation"));
        assert!(!manifest.passed);
        crate::test_complete!("test_repro_manifest_from_context");
    }

    #[test]
    fn test_repro_manifest_helper_setters() {
        init_test("test_repro_manifest_helper_setters");
        let manifest = ReproManifest::new(0xBEEF, "helper_test", false)
            .with_entropy_seed(0xCAFE)
            .with_config_hash("cfg_hash")
            .with_trace_fingerprint("trace_fp")
            .with_input_digest("input_digest")
            .with_oracle_violations(["oracle_a", "oracle_b"])
            .with_subsystem("scheduler")
            .with_invariant("no_leaks")
            .with_trace_file("traces/run.jsonl")
            .with_input_file("inputs/failing.json");

        assert_eq!(manifest.entropy_seed, Some(0xCAFE));
        assert_eq!(manifest.config_hash.as_deref(), Some("cfg_hash"));
        assert_eq!(manifest.trace_fingerprint.as_deref(), Some("trace_fp"));
        assert_eq!(manifest.input_digest.as_deref(), Some("input_digest"));
        assert_eq!(manifest.oracle_violations.len(), 2);
        assert_eq!(manifest.subsystem.as_deref(), Some("scheduler"));
        assert_eq!(manifest.invariant.as_deref(), Some("no_leaks"));
        assert_eq!(manifest.trace_file.as_deref(), Some("traces/run.jsonl"));
        assert_eq!(manifest.input_file.as_deref(), Some("inputs/failing.json"));
        crate::test_complete!("test_repro_manifest_helper_setters");
    }

    #[test]
    fn test_repro_manifest_json_roundtrip() {
        init_test("test_repro_manifest_json_roundtrip");
        let mut manifest = ReproManifest::new(0xCAFE, "roundtrip_test", true);
        manifest.entropy_seed = Some(0xBEEF);
        manifest.config_hash = Some("abc123".to_string());
        let json = manifest.to_json().expect("serialize");
        let parsed: ReproManifest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.seed, manifest.seed);
        assert_eq!(parsed.scenario_id, manifest.scenario_id);
        assert_eq!(parsed.entropy_seed, manifest.entropy_seed);
        assert_eq!(parsed.schema_version, ARTIFACT_SCHEMA_VERSION);
        crate::test_complete!("test_repro_manifest_json_roundtrip");
    }

    #[test]
    fn test_repro_manifest_optional_fields_omitted() {
        init_test("test_repro_manifest_optional_fields_omitted");
        let manifest = ReproManifest::new(0, "minimal_test", true);
        let json = manifest.to_json().expect("serialize");
        assert!(!json.contains("entropy_seed"));
        assert!(!json.contains("config_hash"));
        assert!(!json.contains("oracle_violations"));
        crate::test_complete!("test_repro_manifest_optional_fields_omitted");
    }

    #[test]
    fn test_replay_context_from_manifest() {
        init_test("test_replay_context_from_manifest");
        let mut manifest = ReproManifest::new(0xDEAD, "replay_scenario", false);
        manifest.subsystem = Some("scheduler".to_string());
        manifest.invariant = Some("quiescence".to_string());
        let ctx = replay_context_from_manifest(&manifest);
        assert_eq!(ctx.test_id, "replay_scenario");
        assert_eq!(ctx.seed, 0xDEAD);
        assert_eq!(ctx.subsystem.as_deref(), Some("scheduler"));
        crate::test_complete!("test_replay_context_from_manifest");
    }

    // ----------------------------------------------------------------
    // ----------------------------------------------------------------
    // Failure Triage Pipeline tests (bd-1ex7)
    // ----------------------------------------------------------------

    #[test]
    fn test_repro_manifest_env_snapshot() {
        init_test("test_repro_manifest_env_snapshot");
        let env = capture_test_env();
        for (key, _) in &env {
            crate::assert_with_log!(
                key.starts_with("ASUPERSYNC_") || key == "RUST_LOG",
                "env key filtered",
                "ASUPERSYNC_* or RUST_LOG",
                key
            );
        }
        let keys: Vec<&str> = env.iter().map(|(k, _)| k.as_str()).collect();
        let mut sorted = keys.clone();
        sorted.sort_unstable();
        crate::assert_with_log!(keys == sorted, "env keys sorted", true, keys == sorted);
        crate::test_complete!("test_repro_manifest_env_snapshot");
    }

    #[test]
    fn test_repro_manifest_with_phases_and_failure_reason() {
        init_test("test_repro_manifest_with_phases_and_failure_reason");
        let manifest = ReproManifest::new(0xBEEF, "phase_test", false)
            .with_phases(vec![
                "setup".to_string(),
                "exercise".to_string(),
                "verify".to_string(),
            ])
            .with_failure_reason("assertion failed: expected 5, got 3");

        crate::assert_with_log!(
            manifest.phases_executed.len() == 3,
            "three phases",
            3,
            manifest.phases_executed.len()
        );
        crate::assert_with_log!(
            manifest.failure_reason.is_some(),
            "failure reason set",
            true,
            manifest.failure_reason.is_some()
        );

        let json = manifest.to_json().expect("serialize");
        let parsed: ReproManifest = serde_json::from_str(&json).expect("deserialize");
        crate::assert_with_log!(
            parsed.phases_executed == manifest.phases_executed,
            "phases roundtrip",
            manifest.phases_executed.len(),
            parsed.phases_executed.len()
        );
        crate::assert_with_log!(
            parsed.failure_reason == manifest.failure_reason,
            "failure_reason roundtrip",
            manifest.failure_reason,
            parsed.failure_reason
        );
        crate::test_complete!("test_repro_manifest_with_phases_and_failure_reason");
    }

    #[test]
    fn test_repro_manifest_empty_new_fields_omitted() {
        init_test("test_repro_manifest_empty_new_fields_omitted");
        let manifest = ReproManifest::new(42, "minimal", true);
        let json = manifest.to_json().expect("serialize");
        crate::assert_with_log!(
            !json.contains("phases_executed"),
            "empty phases omitted",
            true,
            !json.contains("phases_executed")
        );
        crate::assert_with_log!(
            !json.contains("env_snapshot"),
            "empty env omitted",
            true,
            !json.contains("env_snapshot")
        );
        crate::assert_with_log!(
            !json.contains("failure_reason"),
            "null failure_reason omitted",
            true,
            !json.contains("failure_reason")
        );
        crate::test_complete!("test_repro_manifest_empty_new_fields_omitted");
    }

    #[test]
    fn test_harness_repro_manifest_on_failure() {
        init_test("test_harness_repro_manifest_on_failure");
        let ctx = TestContext::new("harness_failure_test", 0xF00D)
            .with_subsystem("scheduler")
            .with_invariant("quiescence");
        let mut harness = TestHarness::with_context("harness_failure_test", ctx);

        harness.enter_phase("setup");
        harness.assert_true("always passes", true);
        harness.exit_phase();

        harness.enter_phase("exercise");
        harness.record_assertion("value check", false, "10", "5");
        harness.exit_phase();

        let manifest = harness.repro_manifest(false);
        crate::assert_with_log!(
            manifest.seed == 0xF00D,
            "seed from context",
            0xF00Du64,
            manifest.seed
        );
        crate::assert_with_log!(
            manifest.subsystem.as_deref() == Some("scheduler"),
            "subsystem from context",
            Some("scheduler"),
            manifest.subsystem.as_deref()
        );
        crate::assert_with_log!(
            manifest.phases_executed.len() == 2,
            "two phases captured",
            2,
            manifest.phases_executed.len()
        );
        crate::assert_with_log!(
            manifest.failure_reason.is_some(),
            "failure reason populated",
            true,
            manifest.failure_reason.is_some()
        );
        crate::test_complete!("test_harness_repro_manifest_on_failure");
    }

    #[test]
    fn test_harness_finish_auto_generates_manifest_on_failure() {
        init_test("test_harness_finish_auto_generates_manifest_on_failure");
        let tmp = std::env::temp_dir().join("asupersync_harness_manifest_test");
        let _ = std::fs::remove_dir_all(&tmp);

        std::env::set_var("ASUPERSYNC_TEST_ARTIFACTS_DIR", tmp.display().to_string());
        let ctx = TestContext::new("auto_manifest", 0xCAFE).with_subsystem("time");
        let mut harness = TestHarness::with_context("auto_manifest", ctx);

        harness.enter_phase("setup");
        harness.exit_phase();
        harness.enter_phase("verify");
        harness.record_assertion("fail_check", false, "true", "false");
        harness.exit_phase();

        let summary = harness.finish();

        let has_manifest = summary
            .failure_artifacts
            .iter()
            .any(|a| a.contains("repro_manifest.json"));
        crate::assert_with_log!(
            has_manifest,
            "repro_manifest.json in artifacts",
            true,
            has_manifest
        );

        if let Some(manifest_path) = summary
            .failure_artifacts
            .iter()
            .find(|a| a.contains("repro_manifest.json"))
        {
            let loaded = load_repro_manifest(std::path::Path::new(manifest_path))
                .expect("load auto-generated manifest");
            crate::assert_with_log!(
                loaded.seed == 0xCAFE,
                "manifest seed correct",
                0xCAFEu64,
                loaded.seed
            );
            crate::assert_with_log!(
                !loaded.passed,
                "manifest shows failure",
                false,
                loaded.passed
            );
            crate::assert_with_log!(
                loaded.phases_executed.len() == 2,
                "phases captured in manifest",
                2,
                loaded.phases_executed.len()
            );
        }

        std::env::remove_var("ASUPERSYNC_TEST_ARTIFACTS_DIR");
        let _ = std::fs::remove_dir_all(&tmp);
        crate::test_complete!("test_harness_finish_auto_generates_manifest_on_failure");
    }

    #[test]
    fn test_capture_replay_manifest_roundtrip() {
        init_test("test_capture_replay_manifest_roundtrip");
        let ctx = TestContext::new("cancel_drain", 0xDEAD_CAFE)
            .with_subsystem("obligation")
            .with_invariant("no_leaks");
        let mut harness = TestHarness::with_context("cancel_drain", ctx);

        harness.enter_phase("setup_regions");
        harness.assert_true("region created", true);
        harness.exit_phase();
        harness.enter_phase("cancel_and_drain");
        harness.record_assertion("leak check", false, "0 leaks", "2 leaks");
        harness.exit_phase();

        let manifest = harness.repro_manifest(false);

        let tmp = std::env::temp_dir().join("asupersync_replay_roundtrip");
        let path = manifest.write_to_dir(&tmp).expect("write manifest");

        let loaded = load_repro_manifest(&path).expect("load manifest");
        let replay_ctx = replay_context_from_manifest(&loaded);

        crate::assert_with_log!(
            replay_ctx.seed == 0xDEAD_CAFE,
            "replay seed matches",
            0xDEAD_CAFEu64,
            replay_ctx.seed
        );
        crate::assert_with_log!(
            replay_ctx.test_id == "cancel_drain",
            "replay test_id matches",
            "cancel_drain",
            replay_ctx.test_id
        );
        crate::assert_with_log!(
            loaded.phases_executed.len() == 2,
            "phases preserved on disk",
            2,
            loaded.phases_executed.len()
        );
        crate::assert_with_log!(
            loaded.failure_reason.is_some(),
            "failure reason preserved on disk",
            true,
            loaded.failure_reason.is_some()
        );

        let _ = std::fs::remove_dir_all(tmp.join("cancel_drain"));
        crate::test_complete!("test_capture_replay_manifest_roundtrip");
    }

    // E2E Environment Orchestration tests
    // ----------------------------------------------------------------

    #[test]
    fn test_port_allocator_allocates_unique_ports() {
        init_test("test_port_allocator_allocates_unique_ports");
        let mut alloc = PortAllocator::new();
        let p1 = alloc.allocate("http").expect("allocate http");
        let p2 = alloc.allocate("ws").expect("allocate ws");
        let p3 = alloc.allocate("grpc").expect("allocate grpc");
        assert_ne!(p1, p2, "ports must be unique");
        assert_ne!(p2, p3, "ports must be unique");
        assert_ne!(p1, p3, "ports must be unique");
        assert!(p1 > 0);
        assert_eq!(alloc.count(), 3);
        crate::test_complete!("test_port_allocator_allocates_unique_ports");
    }

    #[test]
    fn test_port_allocator_lookup_by_label() {
        init_test("test_port_allocator_lookup_by_label");
        let mut alloc = PortAllocator::new();
        let port = alloc.allocate("my_service").expect("allocate");
        assert_eq!(alloc.port_for("my_service"), Some(port));
        assert_eq!(alloc.port_for("nonexistent"), None);
        crate::test_complete!("test_port_allocator_lookup_by_label");
    }

    #[test]
    fn test_port_allocator_allocate_n() {
        init_test("test_port_allocator_allocate_n");
        let mut alloc = PortAllocator::new();
        let ports = alloc.allocate_n("worker", 4).expect("allocate_n");
        assert_eq!(ports.len(), 4);
        let mut sorted = ports;
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 4, "all ports must be unique");
        assert!(alloc.port_for("worker_0").is_some());
        assert!(alloc.port_for("worker_3").is_some());
        crate::test_complete!("test_port_allocator_allocate_n");
    }

    #[test]
    fn test_noop_fixture_service_lifecycle() {
        init_test("test_noop_fixture_service_lifecycle");
        let mut svc = NoOpFixtureService::new("test_echo");
        assert_eq!(svc.name(), "test_echo");
        assert!(!svc.is_healthy());
        svc.start().expect("start");
        assert!(svc.is_healthy());
        svc.stop().expect("stop");
        assert!(!svc.is_healthy());
        crate::test_complete!("test_noop_fixture_service_lifecycle");
    }

    #[test]
    fn test_environment_metadata_fields() {
        init_test("test_environment_metadata_fields");
        let ctx = TestContext::new("env_meta_test", 0xBEEF);
        let mut env = TestEnvironment::new(ctx);
        let _ = env.allocate_port("http").expect("allocate");
        env.register_service(Box::new(NoOpFixtureService::new("echo_svc")));
        let meta = env.metadata();
        assert_eq!(meta.test_id, "env_meta_test");
        assert_eq!(meta.seed, 0xBEEF);
        assert_eq!(meta.ports.len(), 1);
        assert_eq!(meta.services.len(), 1);
        crate::test_complete!("test_environment_metadata_fields");
    }

    #[test]
    fn test_environment_metadata_json_roundtrip() {
        init_test("test_environment_metadata_json_roundtrip");
        let ctx = TestContext::new("json_meta", 42);
        let env = TestEnvironment::new(ctx);
        let meta = env.metadata();
        let json = meta.to_json().expect("serialize");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse");
        assert_eq!(parsed["test_id"], "json_meta");
        assert_eq!(parsed["seed"], 42);
        crate::test_complete!("test_environment_metadata_json_roundtrip");
    }

    #[test]
    fn test_environment_service_lifecycle() {
        init_test("test_environment_service_lifecycle");
        let ctx = TestContext::new("svc_lifecycle", 1);
        let mut env = TestEnvironment::new(ctx);
        env.register_service(Box::new(NoOpFixtureService::new("svc_a")));
        env.register_service(Box::new(NoOpFixtureService::new("svc_b")));
        let health = env.health_check();
        assert!(!health[0].1);
        assert!(!health[1].1);
        env.start_all_services().expect("start all");
        let health = env.health_check();
        assert!(health[0].1);
        assert!(health[1].1);
        env.teardown();
        let health = env.health_check();
        assert!(!health[0].1);
        assert!(!health[1].1);
        crate::test_complete!("test_environment_service_lifecycle");
    }

    #[test]
    fn test_environment_port_isolation() {
        init_test("test_environment_port_isolation");
        let mut env_a = TestEnvironment::new(TestContext::new("env_a", 1));
        let mut env_b = TestEnvironment::new(TestContext::new("env_b", 2));
        let port_a = env_a.allocate_port("http").expect("allocate a");
        let port_b = env_b.allocate_port("http").expect("allocate b");
        assert_ne!(
            port_a, port_b,
            "concurrent environments must get distinct ports"
        );
        crate::test_complete!("test_environment_port_isolation");
    }

    #[test]
    fn test_environment_teardown_idempotent() {
        init_test("test_environment_teardown_idempotent");
        let mut env = TestEnvironment::new(TestContext::new("idempotent", 0));
        env.register_service(Box::new(NoOpFixtureService::new("svc")));
        env.start_all_services().expect("start");
        env.teardown();
        env.teardown();
        env.teardown();
        crate::test_complete!("test_environment_teardown_idempotent");
    }

    #[test]
    fn test_environment_on_teardown_callbacks() {
        init_test("test_environment_on_teardown_callbacks");
        let counter = Arc::new(AtomicUsize::new(0));
        let c1 = counter.clone();
        let c2 = counter.clone();
        let mut env = TestEnvironment::new(TestContext::new("callbacks", 0));
        env.on_teardown(move || {
            c1.fetch_add(1, Ordering::SeqCst);
        });
        env.on_teardown(move || {
            c2.fetch_add(10, Ordering::SeqCst);
        });
        env.teardown();
        assert_eq!(counter.load(Ordering::SeqCst), 11, "both callbacks ran");
        crate::test_complete!("test_environment_on_teardown_callbacks");
    }

    #[test]
    fn test_environment_metadata_write_artifact() {
        init_test("test_environment_metadata_write_artifact");
        let mut env = TestEnvironment::new(TestContext::new("artifact_write", 0xABCD));
        let _ = env.allocate_port("tcp").expect("allocate");
        let tmp = std::env::temp_dir().join("asupersync_env_meta_test");
        let meta = env.metadata();
        let path = meta.write_to_dir(&tmp).expect("write metadata");
        let content = std::fs::read_to_string(&path).expect("read");
        let parsed: serde_json::Value = serde_json::from_str(&content).expect("parse");
        assert_eq!(parsed["test_id"], "artifact_write");
        assert_eq!(parsed["seed"], 0xABCD);
        let _ = std::fs::remove_dir_all(tmp.join("artifact_write"));
        crate::test_complete!("test_environment_metadata_write_artifact");
    }

    // =========================================================================
    // Tests for concrete fixture services (bd-76y5)
    // =========================================================================

    #[test]
    fn test_wait_until_healthy_immediate() {
        init_test("test_wait_until_healthy_immediate");
        let mut svc = NoOpFixtureService::new("fast_svc");
        svc.start().expect("start");
        let elapsed = wait_until_healthy(&svc, Duration::from_secs(1)).expect("healthy");
        assert!(elapsed < Duration::from_millis(100));
        crate::test_complete!("test_wait_until_healthy_immediate");
    }

    #[test]
    fn test_wait_until_healthy_timeout() {
        init_test("test_wait_until_healthy_timeout");
        let svc = NoOpFixtureService::new("never_starts");
        // Not started, so is_healthy() is always false.
        let result = wait_until_healthy(&svc, Duration::from_millis(200));
        assert!(result.is_err(), "should timeout");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("not healthy"),
            "error should mention health: {err_msg}"
        );
        crate::test_complete!("test_wait_until_healthy_timeout");
    }

    #[test]
    fn test_temp_dir_fixture_lifecycle() {
        init_test("test_temp_dir_fixture_lifecycle");
        let mut fixture = TempDirFixture::new("scratch");
        assert!(!fixture.is_healthy());
        assert!(fixture.path().is_none());

        fixture.start().expect("start");
        assert!(fixture.is_healthy());
        let path = fixture.path().expect("path exists").to_owned();
        assert!(path.is_dir());
        assert!(
            path.to_string_lossy().contains("asupersync-scratch-"),
            "prefix should match: {path:?}"
        );

        fixture.stop().expect("stop");
        assert!(!fixture.is_healthy());
        assert!(!path.is_dir(), "temp dir should be cleaned up");

        crate::test_complete!("test_temp_dir_fixture_lifecycle");
    }

    #[test]
    fn test_temp_dir_fixture_custom_prefix() {
        init_test("test_temp_dir_fixture_custom_prefix");
        let mut fixture = TempDirFixture::new("custom").with_prefix("myprefix-");
        fixture.start().expect("start");
        let path = fixture.path().expect("path exists");
        assert!(
            path.to_string_lossy().contains("myprefix-"),
            "custom prefix should appear: {path:?}"
        );
        crate::test_complete!("test_temp_dir_fixture_custom_prefix");
    }

    #[test]
    fn test_in_process_service_lifecycle() {
        init_test("test_in_process_service_lifecycle");
        let running = Arc::new(AtomicBool::new(false));
        let mut svc = InProcessService::new(
            "echo",
            running.clone(),
            |state: &mut Arc<AtomicBool>| {
                state.store(true, Ordering::SeqCst);
                Ok(())
            },
            |state: &mut Arc<AtomicBool>| {
                state.store(false, Ordering::SeqCst);
                Ok(())
            },
            |state: &Arc<AtomicBool>| state.load(Ordering::SeqCst),
        );

        assert_eq!(svc.name(), "echo");
        assert!(!svc.is_healthy());

        svc.start().expect("start");
        assert!(svc.is_healthy());
        assert!(running.load(Ordering::SeqCst));

        svc.stop().expect("stop");
        assert!(!svc.is_healthy());
        assert!(!running.load(Ordering::SeqCst));

        crate::test_complete!("test_in_process_service_lifecycle");
    }

    #[test]
    fn test_docker_fixture_service_name_and_container() {
        init_test("test_docker_fixture_service_name_and_container");
        let svc = DockerFixtureService::new("redis", "redis:7-alpine")
            .with_port_map(16379, 6379)
            .with_env("REDIS_PASSWORD", "test")
            .with_health_cmd(vec!["redis-cli", "ping"]);

        assert_eq!(svc.name(), "redis");
        assert!(
            svc.container_name().starts_with("asupersync-test-redis-"),
            "container name format: {}",
            svc.container_name()
        );
        assert!(!svc.is_healthy(), "not started yet");
        crate::test_complete!("test_docker_fixture_service_name_and_container");
    }

    #[test]
    fn test_environment_with_temp_dir_fixture() {
        init_test("test_environment_with_temp_dir_fixture");
        let ctx = TestContext::new("env_tempdir", 0x1234);
        let mut env = TestEnvironment::new(ctx);

        let mut tmp = TempDirFixture::new("workdir");
        tmp.start().expect("start");
        assert!(tmp.is_healthy());
        let dir_path = tmp.path().expect("path").to_owned();

        env.register_service(Box::new(tmp));
        let meta = env.metadata();
        assert_eq!(meta.services.len(), 1);
        assert_eq!(meta.services[0], "workdir");

        env.teardown();
        // After teardown the temp dir should be cleaned up.
        assert!(!dir_path.is_dir(), "temp dir cleaned up after env teardown");
        crate::test_complete!("test_environment_with_temp_dir_fixture");
    }

    #[test]
    fn test_environment_with_in_process_service() {
        init_test("test_environment_with_in_process_service");
        let flag = Arc::new(AtomicBool::new(false));
        let svc = InProcessService::new(
            "mock_http",
            flag.clone(),
            |s: &mut Arc<AtomicBool>| {
                s.store(true, Ordering::SeqCst);
                Ok(())
            },
            |s: &mut Arc<AtomicBool>| {
                s.store(false, Ordering::SeqCst);
                Ok(())
            },
            |s: &Arc<AtomicBool>| s.load(Ordering::SeqCst),
        );

        let ctx = TestContext::new("env_inproc", 42);
        let mut env = TestEnvironment::new(ctx);
        env.register_service(Box::new(svc));
        env.start_all_services().expect("start all");

        let health = env.health_check();
        assert!(health[0].1, "in-process service should be healthy");
        assert!(flag.load(Ordering::SeqCst));

        env.teardown();
        assert!(!flag.load(Ordering::SeqCst), "stopped after teardown");
        crate::test_complete!("test_environment_with_in_process_service");
    }
}
