//! Deadline monitoring and warning callbacks.
//!
//! The deadline monitor scans tasks with budgets and checkpoints and emits
//! warnings when a task is approaching its deadline or has not made progress
//! recently. Warnings are emitted at most once per task until the task is
//! removed from the monitor.

use crate::observability::metrics::MetricsProvider;
use crate::record::TaskRecord;
use crate::types::{RegionId, TaskId, Time};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Adaptive threshold configuration for deadline monitoring.
#[derive(Debug, Clone)]
pub struct AdaptiveDeadlineConfig {
    /// Enable adaptive threshold calculation.
    pub adaptive_enabled: bool,
    /// Percentile of historical duration to use as warning threshold.
    pub warning_percentile: f64,
    /// Minimum samples before adaptive thresholds are used.
    pub min_samples: usize,
    /// Maximum history entries to keep per task type.
    pub max_history: usize,
    /// Fallback threshold when insufficient history is available.
    pub fallback_threshold: Duration,
}

impl Default for AdaptiveDeadlineConfig {
    fn default() -> Self {
        Self {
            adaptive_enabled: false,
            warning_percentile: 0.90,
            min_samples: 10,
            max_history: 1000,
            fallback_threshold: Duration::from_secs(30),
        }
    }
}

/// Configuration for deadline monitoring.
#[derive(Debug, Clone)]
pub struct MonitorConfig {
    /// How often to check for violations.
    pub check_interval: Duration,
    /// Warn if this fraction of the deadline remains with no recent progress.
    pub warning_threshold_fraction: f64,
    /// Warn if no checkpoint for this duration.
    pub checkpoint_timeout: Duration,
    /// Adaptive warning thresholds based on historical task durations.
    pub adaptive: AdaptiveDeadlineConfig,
    /// Whether monitoring is enabled.
    pub enabled: bool,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            check_interval: Duration::from_secs(1),
            warning_threshold_fraction: 0.2,
            checkpoint_timeout: Duration::from_secs(30),
            adaptive: AdaptiveDeadlineConfig::default(),
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

#[derive(Debug, Default)]
struct DurationHistory {
    samples: VecDeque<u64>,
    max_history: usize,
}

impl DurationHistory {
    fn new(max_history: usize) -> Self {
        Self {
            samples: VecDeque::new(),
            max_history: max_history.max(1),
        }
    }

    fn record(&mut self, duration: Duration) {
        if self.samples.len() == self.max_history {
            self.samples.pop_front();
        }
        self.samples.push_back(duration.as_nanos().min(u128::from(u64::MAX)) as u64);
    }

    fn len(&self) -> usize {
        self.samples.len()
    }

    fn percentile_nanos(&self, percentile: f64) -> Option<u64> {
        if self.samples.is_empty() {
            return None;
        }
        let mut values: Vec<u64> = self.samples.iter().copied().collect();
        values.sort_unstable();
        let pct = percentile.clamp(0.0, 1.0);
        let rank = (pct * values.len() as f64).ceil() as usize;
        let idx = rank.saturating_sub(1).min(values.len() - 1);
        values.get(idx).copied()
    }
}

#[derive(Debug)]
struct MonitoredTask {
    task_id: TaskId,
    region_id: RegionId,
    deadline: Time,
    last_progress: Instant,
    last_checkpoint_seen: Option<Instant>,
    warned: bool,
    violated: bool,
}

/// Monitors tasks for approaching deadlines and lack of progress.
pub struct DeadlineMonitor {
    config: MonitorConfig,
    on_warning: Option<Box<dyn Fn(DeadlineWarning) + Send + Sync>>,
    monitored: HashMap<TaskId, MonitoredTask>,
    history: HashMap<String, DurationHistory>,
    metrics_provider: Option<Arc<dyn MetricsProvider>>,
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
            history: HashMap::new(),
            metrics_provider: None,
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

    /// Sets a metrics provider for deadline-related metrics.
    pub fn set_metrics_provider(&mut self, provider: Arc<dyn MetricsProvider>) {
        self.metrics_provider = Some(provider);
    }

    /// Records a completed task duration for adaptive thresholding and metrics.
    pub fn record_completion(
        &mut self,
        task_id: TaskId,
        task_type: &str,
        duration: Duration,
        deadline: Option<Time>,
        now: Time,
    ) {
        let task_type = normalize_task_type(task_type);
        self.history
            .entry(task_type.to_string())
            .or_insert_with(|| DurationHistory::new(self.config.adaptive.max_history))
            .record(duration);

        if let Some(deadline) = deadline {
            let remaining = Duration::from_nanos(deadline.duration_since(now));
            self.emit_deadline_remaining(task_type, remaining);

            let deadline_exceeded = now > deadline;
            let already_violated = self
                .monitored
                .get(&task_id)
                .map_or(false, |entry| entry.violated);
            if deadline_exceeded && !already_violated {
                let over_by = Duration::from_nanos(now.duration_since(deadline));
                self.emit_deadline_violation(task_type, over_by);
            }
        }

        self.monitored.remove(&task_id);
    }

    fn adaptive_warning_threshold(&self, task_type: &str, total: Duration) -> Duration {
        let adaptive = &self.config.adaptive;
        if !adaptive.adaptive_enabled {
            let total_nanos = total.as_nanos().min(u128::from(u64::MAX)) as u64;
            let fraction_nanos = fraction_nanos(total_nanos, self.config.warning_threshold_fraction);
            return Duration::from_nanos(fraction_nanos);
        }

        let history = self.history.get(task_type);
        if let Some(history) = history {
            if history.len() >= adaptive.min_samples {
                if let Some(pct) = history.percentile_nanos(adaptive.warning_percentile) {
                    return Duration::from_nanos(pct);
                }
            }
        }

        let fallback = adaptive.fallback_threshold;
        fallback.min(total)
    }

    fn emit_deadline_warning(
        &self,
        task_type: &str,
        reason: WarningReason,
        remaining: Duration,
    ) {
        if let Some(provider) = &self.metrics_provider {
            provider.deadline_warning(task_type, reason_label(reason), remaining);
            if matches!(reason, WarningReason::NoProgress | WarningReason::ApproachingDeadlineNoProgress)
            {
                provider.task_stuck_detected(task_type);
            }
        }
    }

    fn emit_deadline_violation(&self, task_type: &str, over_by: Duration) {
        if let Some(provider) = &self.metrics_provider {
            provider.deadline_violation(task_type, over_by);
        }
    }

    fn emit_deadline_remaining(&self, task_type: &str, remaining: Duration) {
        if let Some(provider) = &self.metrics_provider {
            provider.deadline_remaining(task_type, remaining);
        }
    }

    fn emit_checkpoint_interval(&self, task_type: &str, interval: Duration) {
        if let Some(provider) = &self.metrics_provider {
            provider.checkpoint_interval(task_type, interval);
        }
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
            let task_type = inner_guard
                .task_type
                .clone()
                .unwrap_or_else(|| "default".to_string());
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
                    last_checkpoint_seen: last_checkpoint,
                    warned: false,
                    violated: false,
                });

            // Keep metadata up to date.
            entry.region_id = task.owner;
            entry.deadline = deadline;
            if let Some(checkpoint) = last_checkpoint {
                if entry
                    .last_checkpoint_seen
                    .map_or(true, |prev| checkpoint > prev)
                {
                    if let Some(prev) = entry.last_checkpoint_seen {
                        let interval = checkpoint.duration_since(prev);
                        self.emit_checkpoint_interval(&task_type, interval);
                    }
                    entry.last_checkpoint_seen = Some(checkpoint);
                    entry.last_progress = checkpoint;
                }
            }

            let deadline_exceeded = now > deadline;
            if deadline_exceeded && !entry.violated {
                entry.violated = true;
                let over_by = Duration::from_nanos(now.duration_since(deadline));
                self.emit_deadline_violation(&task_type, over_by);
            }

            if entry.warned {
                continue;
            }

            let remaining_nanos = deadline.duration_since(now);
            let remaining = Duration::from_nanos(remaining_nanos);
            let total_nanos = deadline.duration_since(task.created_at());
            let total = Duration::from_nanos(total_nanos);
            let adaptive_threshold = self.adaptive_warning_threshold(&task_type, total);
            let approaching_deadline = if self.config.adaptive.adaptive_enabled {
                let elapsed = Duration::from_nanos(now.duration_since(task.created_at()));
                elapsed >= adaptive_threshold
            } else {
                remaining_nanos
                    <= fraction_nanos(total_nanos, self.config.warning_threshold_fraction)
            };

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
                self.emit_deadline_warning(&task_type, reason, remaining);
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

fn normalize_task_type(task_type: &str) -> &str {
    let trimmed = task_type.trim();
    if trimmed.is_empty() {
        "default"
    } else {
        trimmed
    }
}

const fn reason_label(reason: WarningReason) -> &'static str {
    match reason {
        WarningReason::ApproachingDeadline => "approaching_deadline",
        WarningReason::NoProgress => "no_progress",
        WarningReason::ApproachingDeadlineNoProgress => "approaching_deadline_no_progress",
    }
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
            adaptive: AdaptiveDeadlineConfig::default(),
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

        let recorded = {
            let recorded = warnings.lock().unwrap();
            recorded.clone()
        };
        crate::assert_with_log!(
            recorded.as_slice() == [WarningReason::ApproachingDeadline],
            "approaching deadline warned",
            vec![WarningReason::ApproachingDeadline],
            recorded
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
            adaptive: AdaptiveDeadlineConfig::default(),
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

        let recorded = {
            let recorded = warnings.lock().unwrap();
            recorded.clone()
        };
        crate::assert_with_log!(
            recorded.as_slice() == [WarningReason::NoProgress],
            "no progress warned",
            vec![WarningReason::NoProgress],
            recorded
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
            adaptive: AdaptiveDeadlineConfig::default(),
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

        let count = warnings.lock().unwrap().len();
        crate::assert_with_log!(count == 1, "warned once", 1usize, count);
        crate::test_complete!("warns_only_once_per_task");
    }

    #[test]
    fn warns_on_both_conditions() {
        init_test("warns_on_both_conditions");
        let config = MonitorConfig {
            check_interval: Duration::ZERO,
            warning_threshold_fraction: 0.5,
            checkpoint_timeout: Duration::from_secs(10),
            adaptive: AdaptiveDeadlineConfig::default(),
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

        let recorded = {
            let recorded = warnings.lock().unwrap();
            recorded.clone()
        };
        crate::assert_with_log!(
            recorded.as_slice() == [WarningReason::ApproachingDeadlineNoProgress],
            "warned for both conditions",
            vec![WarningReason::ApproachingDeadlineNoProgress],
            recorded
        );
        drop(recorded);
        crate::test_complete!("warns_on_both_conditions");
    }

    #[test]
    fn no_warning_with_recent_checkpoint() {
        init_test("no_warning_with_recent_checkpoint");
        let config = MonitorConfig {
            check_interval: Duration::ZERO,
            warning_threshold_fraction: 0.0,
            checkpoint_timeout: Duration::from_secs(60),
            adaptive: AdaptiveDeadlineConfig::default(),
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

        let empty = warnings.lock().unwrap().is_empty();
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
            adaptive: AdaptiveDeadlineConfig::default(),
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

        let warning = warnings
            .lock()
            .unwrap()
            .first()
            .cloned()
            .expect("expected warning");
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
