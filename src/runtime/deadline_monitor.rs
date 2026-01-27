//! Deadline monitoring and warning callbacks.
//!
//! The deadline monitor scans tasks with budgets and checkpoints and emits
//! warnings when a task is approaching its deadline or has not made progress
//! recently. Warnings are emitted at most once per task until the task is
//! removed from the monitor.

use crate::record::TaskRecord;
use crate::types::{RegionId, TaskId, Time};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::time::{Duration, Instant};

/// Configuration for deadline monitoring.
#[derive(Debug, Clone)]
pub struct MonitorConfig {
    /// How often to check for violations.
    pub check_interval: Duration,
    /// Warn if this fraction of the deadline remains with no recent progress.
    pub warning_threshold_fraction: f64,
    /// Warn if no checkpoint for this duration.
    pub checkpoint_timeout: Duration,
    /// Whether monitoring is enabled.
    pub enabled: bool,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            check_interval: Duration::from_secs(1),
            warning_threshold_fraction: 0.2,
            checkpoint_timeout: Duration::from_secs(30),
            enabled: true,
        }
    }
}

/// Warning emitted when a task approaches its deadline or stalls.
#[derive(Debug, Clone)]
pub struct DeadlineWarning {
    /// The task approaching its deadline.
    pub task_id: TaskId,
    /// The region containing the task.
    pub region_id: RegionId,
    /// The absolute deadline (logical time).
    pub deadline: Time,
    /// Time remaining until deadline.
    pub remaining: Duration,
    /// When the last checkpoint was recorded.
    pub last_checkpoint: Option<Instant>,
    /// Message from the last checkpoint.
    pub last_checkpoint_message: Option<String>,
    /// Warning reason.
    pub reason: WarningReason,
}

/// Reasons for deadline warnings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WarningReason {
    /// Approaching deadline with little time remaining.
    ApproachingDeadline,
    /// No progress (checkpoint) for too long.
    NoProgress,
    /// Both approaching deadline AND no recent progress.
    ApproachingDeadlineNoProgress,
}

#[derive(Debug)]
struct MonitoredTask {
    task_id: TaskId,
    region_id: RegionId,
    deadline: Time,
    last_progress: Instant,
    warned: bool,
}

/// Monitors tasks for approaching deadlines and lack of progress.
pub struct DeadlineMonitor {
    config: MonitorConfig,
    on_warning: Option<Box<dyn Fn(DeadlineWarning) + Send + Sync>>,
    monitored: HashMap<TaskId, MonitoredTask>,
    last_scan: Option<Instant>,
}

impl fmt::Debug for DeadlineMonitor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeadlineMonitor")
            .field("config", &self.config)
            .field("monitored", &self.monitored)
            .field("last_scan", &self.last_scan)
            .finish_non_exhaustive()
    }
}

impl DeadlineMonitor {
    /// Creates a new deadline monitor.
    #[must_use]
    pub fn new(config: MonitorConfig) -> Self {
        Self {
            config,
            on_warning: None,
            monitored: HashMap::new(),
            last_scan: None,
        }
    }

    /// Registers a callback for warning events.
    pub fn on_warning(&mut self, f: impl Fn(DeadlineWarning) + Send + Sync + 'static) {
        self.on_warning = Some(Box::new(f));
    }

    /// Returns a reference to the monitor configuration.
    #[must_use]
    pub fn config(&self) -> &MonitorConfig {
        &self.config
    }

    /// Performs a monitoring scan over tasks.
    pub fn check<'a, I>(&mut self, now: Time, tasks: I)
    where
        I: IntoIterator<Item = &'a TaskRecord>,
    {
        if !self.config.enabled {
            return;
        }

        let now_instant = Instant::now();
        if let Some(last_scan) = self.last_scan {
            if now_instant.duration_since(last_scan) < self.config.check_interval {
                return;
            }
        }
        self.last_scan = Some(now_instant);

        let mut seen: HashSet<TaskId> = HashSet::new();

        for task in tasks {
            if task.state.is_terminal() {
                continue;
            }

            let Some(inner) = task.cx_inner.as_ref() else {
                continue;
            };
            let Ok(inner_guard) = inner.read() else {
                continue;
            };
            let Some(deadline) = inner_guard.budget.deadline else {
                continue;
            };

            let last_checkpoint = inner_guard.checkpoint_state.last_checkpoint;
            let last_message = inner_guard.checkpoint_state.last_message.clone();
            drop(inner_guard);

            seen.insert(task.id);

            let entry = self
                .monitored
                .entry(task.id)
                .or_insert_with(|| MonitoredTask {
                    task_id: task.id,
                    region_id: task.owner,
                    deadline,
                    last_progress: last_checkpoint.unwrap_or(now_instant),
                    warned: false,
                });

            // Keep metadata up to date.
            entry.region_id = task.owner;
            entry.deadline = deadline;
            if let Some(checkpoint) = last_checkpoint {
                if checkpoint > entry.last_progress {
                    entry.last_progress = checkpoint;
                }
            }

            if entry.warned {
                continue;
            }

            let remaining_nanos = deadline.duration_since(now);
            let remaining = Duration::from_nanos(remaining_nanos);
            let total_nanos = deadline.duration_since(task.created_at());
            let threshold_nanos =
                fraction_nanos(total_nanos, self.config.warning_threshold_fraction);
            let approaching_deadline = remaining_nanos <= threshold_nanos;

            let no_progress =
                now_instant.duration_since(entry.last_progress) >= self.config.checkpoint_timeout;

            let warning = match (approaching_deadline, no_progress) {
                (true, true) => Some(WarningReason::ApproachingDeadlineNoProgress),
                (true, false) => Some(WarningReason::ApproachingDeadline),
                (false, true) => Some(WarningReason::NoProgress),
                (false, false) => None,
            };

            if let Some(reason) = warning {
                let warning = {
                    entry.warned = true;
                    DeadlineWarning {
                        task_id: entry.task_id,
                        region_id: entry.region_id,
                        deadline,
                        remaining,
                        last_checkpoint,
                        last_checkpoint_message: last_message,
                        reason,
                    }
                };
                self.emit_warning(warning);
            }
        }

        // Remove tasks that are no longer present in the scan.
        self.monitored.retain(|task_id, _| seen.contains(task_id));
    }

    fn emit_warning(&self, warning: DeadlineWarning) {
        if let Some(ref callback) = self.on_warning {
            callback(warning);
        }
    }
}

/// Default warning handler that emits a tracing warning.
#[allow(clippy::needless_pass_by_value)]
pub fn default_warning_handler(warning: DeadlineWarning) {
    #[cfg(feature = "tracing-integration")]
    {
        crate::tracing_compat::warn!(
            task_id = ?warning.task_id,
            region_id = ?warning.region_id,
            deadline = ?warning.deadline,
            remaining = ?warning.remaining,
            reason = ?warning.reason,
            last_checkpoint = ?warning.last_checkpoint,
            last_message = ?warning.last_checkpoint_message,
            "task approaching deadline"
        );
    }
    #[cfg(not(feature = "tracing-integration"))]
    {
        let _ = warning;
    }
}

#[allow(clippy::cast_precision_loss, clippy::cast_sign_loss)]
fn fraction_nanos(total_nanos: u64, fraction: f64) -> u64 {
    if total_nanos == 0 {
        return 0;
    }
    if fraction <= 0.0 {
        return 0;
    }
    if fraction >= 1.0 {
        return total_nanos;
    }
    let scaled = (total_nanos as f64) * fraction;
    scaled.max(0.0).min(u64::MAX as f64) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::TaskRecord;
    use crate::types::{Budget, CxInner, RegionId, TaskId};
    use std::sync::{Arc, Mutex, RwLock};

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn make_task(
        task_id: TaskId,
        region_id: RegionId,
        created_at: Time,
        deadline: Time,
        last_checkpoint: Option<Instant>,
        last_message: Option<&str>,
    ) -> TaskRecord {
        let budget = Budget::new().with_deadline(deadline);
        let mut record = TaskRecord::new_with_time(task_id, region_id, budget, created_at);
        let mut inner = CxInner::new(region_id, task_id, budget);
        inner.checkpoint_state.last_checkpoint = last_checkpoint;
        inner.checkpoint_state.last_message = last_message.map(std::string::ToString::to_string);
        record.set_cx_inner(Arc::new(RwLock::new(inner)));
        record
    }

    #[test]
    fn warns_on_approaching_deadline() {
        init_test("warns_on_approaching_deadline");
        let config = MonitorConfig {
            check_interval: Duration::ZERO,
            warning_threshold_fraction: 0.2,
            checkpoint_timeout: Duration::from_secs(30),
            enabled: true,
        };
        let mut monitor = DeadlineMonitor::new(config);

        let warnings: Arc<Mutex<Vec<WarningReason>>> = Arc::new(Mutex::new(Vec::new()));
        let warnings_ref = warnings.clone();
        monitor.on_warning(move |warning| {
            warnings_ref.lock().unwrap().push(warning.reason);
        });

        let task = make_task(
            TaskId::new_for_test(1, 0),
            RegionId::new_for_test(1, 0),
            Time::from_secs(0),
            Time::from_secs(100),
            None,
            None,
        );

        monitor.check(Time::from_secs(90), std::iter::once(&task));

        let recorded = warnings.lock().unwrap();
        crate::assert_with_log!(
            recorded.as_slice() == [WarningReason::ApproachingDeadline],
            "approaching deadline warned",
            vec![WarningReason::ApproachingDeadline],
            recorded.clone()
        );
        crate::test_complete!("warns_on_approaching_deadline");
    }

    #[test]
    fn warns_on_no_progress() {
        init_test("warns_on_no_progress");
        let config = MonitorConfig {
            check_interval: Duration::ZERO,
            warning_threshold_fraction: 0.1,
            checkpoint_timeout: Duration::from_secs(10),
            enabled: true,
        };
        let mut monitor = DeadlineMonitor::new(config);

        let warnings: Arc<Mutex<Vec<WarningReason>>> = Arc::new(Mutex::new(Vec::new()));
        let warnings_ref = warnings.clone();
        monitor.on_warning(move |warning| {
            warnings_ref.lock().unwrap().push(warning.reason);
        });

        let stale = Instant::now().checked_sub(Duration::from_secs(30)).unwrap();
        let task = make_task(
            TaskId::new_for_test(2, 0),
            RegionId::new_for_test(1, 0),
            Time::from_secs(0),
            Time::from_secs(1000),
            Some(stale),
            Some("stuck"),
        );

        monitor.check(Time::from_secs(100), std::iter::once(&task));

        let recorded = warnings.lock().unwrap();
        crate::assert_with_log!(
            recorded.as_slice() == [WarningReason::NoProgress],
            "no progress warned",
            vec![WarningReason::NoProgress],
            recorded.clone()
        );
        crate::test_complete!("warns_on_no_progress");
    }

    #[test]
    fn warns_only_once_per_task() {
        init_test("warns_only_once_per_task");
        let config = MonitorConfig {
            check_interval: Duration::ZERO,
            warning_threshold_fraction: 0.2,
            checkpoint_timeout: Duration::from_secs(30),
            enabled: true,
        };
        let mut monitor = DeadlineMonitor::new(config);

        let warnings: Arc<Mutex<Vec<WarningReason>>> = Arc::new(Mutex::new(Vec::new()));
        let warnings_ref = warnings.clone();
        monitor.on_warning(move |warning| {
            warnings_ref.lock().unwrap().push(warning.reason);
        });

        let task = make_task(
            TaskId::new_for_test(3, 0),
            RegionId::new_for_test(1, 0),
            Time::from_secs(0),
            Time::from_secs(10),
            None,
            None,
        );

        monitor.check(Time::from_secs(9), std::iter::once(&task));
        monitor.check(Time::from_secs(9), std::iter::once(&task));

        let recorded = warnings.lock().unwrap();
        crate::assert_with_log!(recorded.len() == 1, "warned once", 1usize, recorded.len());
        crate::test_complete!("warns_only_once_per_task");
    }

    #[test]
    fn warns_on_both_conditions() {
        init_test("warns_on_both_conditions");
        let config = MonitorConfig {
            check_interval: Duration::ZERO,
            warning_threshold_fraction: 0.5,
            checkpoint_timeout: Duration::from_secs(10),
            enabled: true,
        };
        let mut monitor = DeadlineMonitor::new(config);

        let warnings: Arc<Mutex<Vec<WarningReason>>> = Arc::new(Mutex::new(Vec::new()));
        let warnings_ref = warnings.clone();
        monitor.on_warning(move |warning| {
            warnings_ref.lock().unwrap().push(warning.reason);
        });

        let stale = Instant::now().checked_sub(Duration::from_secs(20)).unwrap();
        let task = make_task(
            TaskId::new_for_test(4, 0),
            RegionId::new_for_test(1, 0),
            Time::from_secs(0),
            Time::from_secs(10),
            Some(stale),
            None,
        );

        monitor.check(Time::from_secs(9), std::iter::once(&task));

        let recorded = warnings.lock().unwrap();
        crate::assert_with_log!(
            recorded.as_slice() == [WarningReason::ApproachingDeadlineNoProgress],
            "warned for both conditions",
            vec![WarningReason::ApproachingDeadlineNoProgress],
            recorded.clone()
        );
        crate::test_complete!("warns_on_both_conditions");
    }

    #[test]
    fn no_warning_with_recent_checkpoint() {
        init_test("no_warning_with_recent_checkpoint");
        let config = MonitorConfig {
            check_interval: Duration::ZERO,
            warning_threshold_fraction: 0.0,
            checkpoint_timeout: Duration::from_secs(60),
            enabled: true,
        };
        let mut monitor = DeadlineMonitor::new(config);

        let warnings: Arc<Mutex<Vec<DeadlineWarning>>> = Arc::new(Mutex::new(Vec::new()));
        let warnings_ref = warnings.clone();
        monitor.on_warning(move |warning| {
            warnings_ref.lock().unwrap().push(warning);
        });

        let task = make_task(
            TaskId::new_for_test(5, 0),
            RegionId::new_for_test(1, 0),
            Time::from_secs(0),
            Time::from_secs(1000),
            Some(Instant::now()),
            Some("recent checkpoint"),
        );

        monitor.check(Time::from_secs(10), std::iter::once(&task));

        let recorded = warnings.lock().unwrap();
        let empty = recorded.is_empty();
        crate::assert_with_log!(empty, "no warnings", true, empty);
        crate::test_complete!("no_warning_with_recent_checkpoint");
    }

    #[test]
    fn warning_includes_checkpoint_message() {
        init_test("warning_includes_checkpoint_message");
        let config = MonitorConfig {
            check_interval: Duration::ZERO,
            warning_threshold_fraction: 0.0,
            checkpoint_timeout: Duration::ZERO,
            enabled: true,
        };
        let mut monitor = DeadlineMonitor::new(config);

        let warnings: Arc<Mutex<Vec<DeadlineWarning>>> = Arc::new(Mutex::new(Vec::new()));
        let warnings_ref = warnings.clone();
        monitor.on_warning(move |warning| {
            warnings_ref.lock().unwrap().push(warning);
        });

        let task = make_task(
            TaskId::new_for_test(6, 0),
            RegionId::new_for_test(1, 0),
            Time::from_secs(0),
            Time::from_secs(1000),
            Some(Instant::now()),
            Some("checkpoint message"),
        );

        monitor.check(Time::from_secs(10), std::iter::once(&task));

        let recorded = warnings.lock().unwrap();
        let warning = recorded.first().cloned().expect("expected warning");
        crate::assert_with_log!(
            warning.reason == WarningReason::NoProgress,
            "reason",
            WarningReason::NoProgress,
            warning.reason
        );
        crate::assert_with_log!(
            warning.last_checkpoint_message.as_deref() == Some("checkpoint message"),
            "checkpoint message",
            Some("checkpoint message"),
            warning.last_checkpoint_message.as_deref()
        );
        crate::test_complete!("warning_includes_checkpoint_message");
    }
}
