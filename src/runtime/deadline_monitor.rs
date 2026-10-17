//! Deadline monitoring and warning callbacks.
//!
//! The deadline monitor scans tasks with budgets and checkpoints and emits
//! warnings when a task is approaching its deadline or has not made progress
//! recently. Warnings are emitted at most once per task until the task is
//! removed from the monitor.

use crate::observability::metrics::MetricsProvider;
use crate::record::TaskRecord;
use crate::types::{RegionId, TaskId, Time};
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

fn wall_clock_now() -> Instant {
    Instant::now()
}

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
    /// When the last checkpoint was recorded in runtime time.
    pub last_checkpoint: Option<Time>,
    /// Message from the last checkpoint.
    pub last_checkpoint_message: Option<String>,
    /// Oldest-to-newest bounded checkpoint message trail.
    pub checkpoint_history: Vec<(Time, String)>,
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
        let cap = max_history.max(1);
        Self {
            samples: VecDeque::with_capacity(cap),
            max_history: cap,
        }
    }

    fn record(&mut self, duration: Duration) {
        if self.samples.len() == self.max_history {
            self.samples.pop_front();
        }
        self.samples
            .push_back(duration.as_nanos().min(u128::from(u64::MAX)) as u64);
    }

    fn len(&self) -> usize {
        self.samples.len()
    }

    #[allow(clippy::cast_sign_loss)]
    fn percentile_nanos(&self, percentile: f64) -> Option<u64> {
        if self.samples.is_empty() {
            return None;
        }
        let mut values: Vec<u64> = self.samples.iter().copied().collect();
        let pct = percentile.clamp(0.0, 1.0);
        let len = values.len();

        // Use standard percentile rank calculation: P * (N-1) for 0-based indexing
        let rank = (pct * (len as f64 - 1.0)).round() as usize;
        let idx = rank.min(len - 1);

        let (_, &mut value, _) = values.select_nth_unstable(idx);
        Some(value)
    }
}

#[derive(Debug)]
struct MonitoredTask {
    task_id: TaskId,
    region_id: RegionId,
    deadline: Time,
    last_progress_wall: Instant,
    last_progress_time: Time,
    last_checkpoint_seen: Option<Time>,
    last_checkpoint_count_seen: u64,
    warned: bool,
    violated: bool,
    seen_gen: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct DeadlineTaskSnapshot {
    task_id: TaskId,
    region_id: RegionId,
    is_terminal: bool,
    created_at: Time,
    deadline: Option<Time>,
    last_checkpoint: Option<Time>,
    last_checkpoint_message: Option<String>,
    checkpoint_history: Vec<(Time, String)>,
    checkpoint_count: u64,
    task_type: Option<String>,
}

impl DeadlineTaskSnapshot {
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_for_test(
        task_id: TaskId,
        region_id: RegionId,
        is_terminal: bool,
        created_at: Time,
        deadline: Option<Time>,
        last_checkpoint: Option<Time>,
        last_checkpoint_message: Option<String>,
        checkpoint_history: Vec<(Time, String)>,
        checkpoint_count: u64,
        task_type: Option<String>,
    ) -> Self {
        Self {
            task_id,
            region_id,
            is_terminal,
            created_at,
            deadline,
            last_checkpoint,
            last_checkpoint_message,
            checkpoint_history,
            checkpoint_count,
            task_type,
        }
    }

    #[must_use]
    pub(crate) fn from_task_record(task: &TaskRecord) -> Self {
        let (
            deadline,
            last_checkpoint,
            last_checkpoint_message,
            checkpoint_history,
            checkpoint_count,
            task_type,
        ) = task
            .cx_inner
            .as_ref()
            .map_or((None, None, None, Vec::new(), 0, None), |inner| {
                let guard = inner.read();
                // Materialise: include any pending fast-path checkpoint
                // accounting so stuck-task detection is not fooled by
                // tasks that took the no-cancellation fast path in
                // Cx::checkpoint (br-asupersync-is2xg0).
                let materialised = guard.materialised_checkpoint_state();
                let checkpoint_history = materialised
                    .history()
                    .into_iter()
                    .map(|entry| (entry.at, entry.message))
                    .collect();
                (
                    guard.budget.deadline,
                    materialised.last_checkpoint,
                    materialised.last_message,
                    checkpoint_history,
                    materialised.checkpoint_count,
                    guard.task_type.clone(),
                )
            });

        Self {
            task_id: task.id,
            region_id: task.owner,
            is_terminal: task.state.is_terminal(),
            created_at: task.created_at(),
            deadline,
            last_checkpoint,
            last_checkpoint_message,
            checkpoint_history,
            checkpoint_count,
            task_type,
        }
    }
}

/// Monitors tasks for approaching deadlines and lack of progress.
pub struct DeadlineMonitor {
    config: MonitorConfig,
    on_warning: Option<Box<dyn Fn(DeadlineWarning) + Send + Sync>>,
    monitored: Vec<Option<MonitoredTask>>,
    history: HashMap<String, DurationHistory>,
    metrics_provider: Option<Arc<dyn MetricsProvider>>,
    last_scan_time: Option<Time>,
    last_scan_instant: Option<Instant>,
    scan_generation: u64,
    time_getter: fn() -> Instant,
}

impl fmt::Debug for DeadlineMonitor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeadlineMonitor")
            .field("config", &self.config)
            .field("monitored", &self.monitored)
            .field("last_scan_time", &self.last_scan_time)
            .field("last_scan_instant", &self.last_scan_instant)
            .finish_non_exhaustive()
    }
}

impl DeadlineMonitor {
    /// Creates a new deadline monitor.
    #[must_use]
    pub fn new(config: MonitorConfig) -> Self {
        Self::with_time_getter(config, wall_clock_now)
    }

    /// Creates a new deadline monitor with a custom time source.
    #[must_use]
    pub fn with_time_getter(config: MonitorConfig, time_getter: fn() -> Instant) -> Self {
        Self {
            config,
            on_warning: None,
            monitored: Vec::with_capacity(16),
            history: HashMap::with_capacity(16),
            metrics_provider: None,
            last_scan_time: None,
            last_scan_instant: None,
            scan_generation: 0,
            time_getter,
        }
    }

    /// Registers a callback for warning events.
    pub fn on_warning(&mut self, f: impl Fn(DeadlineWarning) + Send + Sync + 'static) {
        self.on_warning = Some(Box::new(f));
    }

    /// Returns a reference to the monitor configuration.
    #[must_use]
    #[inline]
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
        if let Some(h) = self.history.get_mut(task_type) {
            h.record(duration);
        } else {
            self.history
                .entry(task_type.to_string())
                .or_insert_with(|| DurationHistory::new(self.config.adaptive.max_history))
                .record(duration);
        }

        if let Some(deadline) = deadline {
            let remaining = Duration::from_nanos(deadline.duration_since(now));
            self.emit_deadline_remaining(task_type, remaining);

            let deadline_exceeded = now > deadline;
            let slot = task_id.arena_index().index() as usize;
            let already_violated = self
                .monitored
                .get(slot)
                .and_then(Option::as_ref)
                .is_some_and(|entry| entry.task_id == task_id && entry.violated);
            if deadline_exceeded && !already_violated {
                let over_by = Duration::from_nanos(now.duration_since(deadline));
                self.emit_deadline_violation(task_type, over_by);
            }
        }

        let slot = task_id.arena_index().index() as usize;
        if slot < self.monitored.len() {
            if let Some(entry) = &self.monitored[slot] {
                if entry.task_id == task_id {
                    self.monitored[slot].take();
                }
            }
        }
    }

    fn adaptive_warning_threshold(&self, task_type: &str, total: Duration) -> Duration {
        let adaptive = &self.config.adaptive;
        if !adaptive.adaptive_enabled {
            let total_nanos = total.as_nanos().min(u128::from(u64::MAX)) as u64;
            let fraction_nanos =
                fraction_nanos(total_nanos, self.config.warning_threshold_fraction);
            return Duration::from_nanos(fraction_nanos);
        }

        let history = self.history.get(task_type);
        if let Some(history) = history {
            if history.len() >= adaptive.min_samples {
                if let Some(pct) = history.percentile_nanos(adaptive.warning_percentile) {
                    let threshold = Duration::from_nanos(pct);
                    return threshold.min(total);
                }
            }
        }

        let fallback = adaptive.fallback_threshold;
        fallback.min(total)
    }

    fn emit_deadline_warning(&self, task_type: &str, reason: WarningReason, remaining: Duration) {
        if let Some(provider) = &self.metrics_provider {
            provider.deadline_warning(task_type, reason_label(reason), remaining);
            if matches!(
                reason,
                WarningReason::NoProgress | WarningReason::ApproachingDeadlineNoProgress
            ) {
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
    #[allow(clippy::too_many_lines)]
    pub fn check<'a, I>(&mut self, now: Time, tasks: I)
    where
        I: IntoIterator<Item = &'a TaskRecord>,
    {
        self.check_snapshots(
            now,
            tasks
                .into_iter()
                .map(DeadlineTaskSnapshot::from_task_record),
        );
    }

    pub(crate) fn check_snapshots<I>(&mut self, now: Time, tasks: I)
    where
        I: IntoIterator<Item = DeadlineTaskSnapshot>,
    {
        if !self.config.enabled {
            return;
        }

        let now_instant = (self.time_getter)();
        let interval_nanos = duration_to_nanos(self.config.check_interval);
        if interval_nanos > 0 && self.last_scan_time.is_some() {
            let logical_elapsed = self
                .last_scan_time
                .map(|last| now.duration_since(last))
                .unwrap_or_default();
            let wall_elapsed = self
                .last_scan_instant
                .map(|last| duration_to_nanos(now_instant.saturating_duration_since(last)))
                .unwrap_or_default();
            if logical_elapsed < interval_nanos && wall_elapsed < interval_nanos {
                return;
            }
        }
        self.last_scan_time = Some(now);
        self.last_scan_instant = Some(now_instant);
        self.scan_generation = self.scan_generation.wrapping_add(1);
        let scan_generation = self.scan_generation;

        for task in tasks {
            if task.is_terminal {
                continue;
            }

            let Some(deadline) = task.deadline else {
                continue;
            };

            let last_checkpoint = task.last_checkpoint;
            let checkpoint_count = task.checkpoint_count;
            let task_type = normalize_task_type(task.task_type.as_deref().unwrap_or("default"));

            let remaining_nanos = deadline.duration_since(now);
            let remaining = Duration::from_nanos(remaining_nanos);
            let total_nanos = deadline.duration_since(task.created_at);
            let total = Duration::from_nanos(total_nanos);
            let adaptive_threshold = self.adaptive_warning_threshold(task_type, total);
            let approaching_deadline = if self.config.adaptive.adaptive_enabled {
                let elapsed = Duration::from_nanos(now.duration_since(task.created_at));
                elapsed >= adaptive_threshold
            } else {
                remaining_nanos
                    <= fraction_nanos(total_nanos, self.config.warning_threshold_fraction)
            };

            let mut checkpoint_interval = None;
            let mut deadline_violation = None;
            let mut warning_to_emit: Option<(DeadlineWarning, WarningReason, Duration)> = None;

            {
                let slot = task.task_id.arena_index().index() as usize;
                if slot >= self.monitored.len() {
                    self.monitored.resize_with(slot + 1, || None);
                }

                if let Some(existing) = &self.monitored[slot] {
                    if existing.task_id != task.task_id {
                        self.monitored[slot] = None;
                    }
                }

                let entry = self.monitored[slot].get_or_insert_with(|| MonitoredTask {
                    task_id: task.task_id,
                    region_id: task.region_id,
                    deadline,
                    last_progress_wall: now_instant,
                    last_progress_time: last_checkpoint.unwrap_or(task.created_at),
                    last_checkpoint_seen: last_checkpoint,
                    last_checkpoint_count_seen: checkpoint_count,
                    warned: false,
                    violated: false,
                    seen_gen: scan_generation,
                });

                // Keep metadata up to date.
                entry.seen_gen = scan_generation;
                entry.region_id = task.region_id;
                entry.deadline = deadline;
                if checkpoint_count > entry.last_checkpoint_count_seen {
                    if let (Some(prev), Some(checkpoint)) =
                        (entry.last_checkpoint_seen, last_checkpoint)
                    {
                        if checkpoint > prev {
                            checkpoint_interval =
                                Some(Duration::from_nanos(checkpoint.duration_since(prev)));
                        }
                    }
                    entry.last_checkpoint_seen = last_checkpoint;
                    entry.last_checkpoint_count_seen = checkpoint_count;
                    entry.last_progress_wall = now_instant;
                    entry.last_progress_time = last_checkpoint.unwrap_or(now);
                }

                let deadline_exceeded = now > deadline;
                if deadline_exceeded && !entry.violated {
                    entry.violated = true;
                    deadline_violation = Some(Duration::from_nanos(now.duration_since(deadline)));
                }

                if !entry.warned {
                    let wall_no_progress = now_instant
                        .saturating_duration_since(entry.last_progress_wall)
                        >= self.config.checkpoint_timeout;
                    let logical_no_progress = now.duration_since(entry.last_progress_time)
                        >= duration_to_nanos(self.config.checkpoint_timeout);
                    let no_progress = wall_no_progress || logical_no_progress;

                    let warning = match (approaching_deadline, no_progress) {
                        (true, true) => Some(WarningReason::ApproachingDeadlineNoProgress),
                        (true, false) => Some(WarningReason::ApproachingDeadline),
                        (false, true) => Some(WarningReason::NoProgress),
                        (false, false) => None,
                    };

                    if let Some(reason) = warning {
                        entry.warned = true;
                        let warning = DeadlineWarning {
                            task_id: entry.task_id,
                            region_id: entry.region_id,
                            deadline,
                            remaining,
                            last_checkpoint,
                            last_checkpoint_message: task.last_checkpoint_message.clone(),
                            checkpoint_history: task.checkpoint_history.clone(),
                            reason,
                        };
                        warning_to_emit = Some((warning, reason, remaining));
                    }
                }
            }

            if let Some(interval) = checkpoint_interval {
                self.emit_checkpoint_interval(task_type, interval);
            }
            if let Some(over_by) = deadline_violation {
                self.emit_deadline_violation(task_type, over_by);
            }
            if let Some((warning, reason, remaining)) = warning_to_emit {
                self.emit_deadline_warning(task_type, reason, remaining);
                self.emit_warning(warning);
            }
        }

        // Remove tasks that are no longer present in the scan.
        for entry in &mut self.monitored {
            if let Some(monitored) = entry {
                if monitored.seen_gen != scan_generation {
                    *entry = None;
                }
            }
        }
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
        let trail = warning.render_trail();
        crate::tracing_compat::warn!(
            task_id = ?warning.task_id,
            region_id = ?warning.region_id,
            deadline = ?warning.deadline,
            remaining = ?warning.remaining,
            reason = ?warning.reason,
            last_checkpoint = ?warning.last_checkpoint,
            last_message = ?warning.last_checkpoint_message,
            checkpoint_trail = trail.as_deref().unwrap_or("<none>"),
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

fn duration_to_nanos(duration: Duration) -> u64 {
    duration.as_nanos().min(u128::from(u64::MAX)) as u64
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

/// Defensive upper bound on trail entries rendered into one diagnostic line.
///
/// The per-task checkpoint ring is already bounded by
/// [`crate::types::MAX_CHECKPOINT_HISTORY_CAPACITY`]; this is a second,
/// independent bound so a render can never emit an unbounded line even if a
/// caller passes a longer slice. Overflow is summarised as `… (+N more)`.
const MAX_RENDERED_TRAIL_ENTRIES: usize = 16;

/// Renders a checkpoint trail into a compact, single-line, replay-stable string
/// for stall forensics, e.g. `[t=1ns] connect → [t=2ns] auth → [t=3ns] query`.
///
/// This is the headline observability win of the bounded checkpoint history:
/// instead of "last said query" the deadline diagnostic can show that "the task
/// progressed through connect → auth → query then went silent".
///
/// The output is a pure function of the logical [`Time`] values (not wall-clock
/// — `Time` is a deterministic logical-nanos counter) and the
/// already-length-bounded checkpoint messages, so it is byte-identical across
/// lab replays and safe to assert against in golden tests. Control characters
/// in messages are scrubbed to spaces so a checkpoint message can never inject
/// newlines or terminal escapes into a diagnostic line. Returns `None` for an
/// empty trail so callers can omit the field entirely.
///
/// # Example
///
/// ```
/// use asupersync::runtime::deadline_monitor::render_checkpoint_trail;
/// use asupersync::types::Time;
///
/// let trail = vec![
///     (Time::from_nanos(1), "connect".to_string()),
///     (Time::from_nanos(2), "auth".to_string()),
///     (Time::from_nanos(3), "query".to_string()),
/// ];
/// assert_eq!(
///     render_checkpoint_trail(&trail).as_deref(),
///     Some("[t=1ns] connect → [t=2ns] auth → [t=3ns] query"),
/// );
/// assert_eq!(render_checkpoint_trail(&[]), None);
/// ```
#[must_use]
pub fn render_checkpoint_trail(trail: &[(Time, String)]) -> Option<String> {
    if trail.is_empty() {
        return None;
    }
    let shown = trail.len().min(MAX_RENDERED_TRAIL_ENTRIES);
    let mut out = String::new();
    for (idx, (at, message)) in trail.iter().take(shown).enumerate() {
        if idx > 0 {
            out.push_str(" → ");
        }
        out.push_str("[t=");
        // `Time`'s Display is deterministic (logical nanos), never wall-clock.
        out.push_str(&at.to_string());
        out.push_str("] ");
        // Scrub control characters so a message can never inject a newline or
        // escape sequence into the diagnostic line (and keep goldens stable).
        for ch in message.chars() {
            out.push(if ch.is_control() { ' ' } else { ch });
        }
    }
    if trail.len() > shown {
        out.push_str(&format!(" … (+{} more)", trail.len() - shown));
    }
    Some(out)
}

impl DeadlineWarning {
    /// Renders this warning's checkpoint trail via [`render_checkpoint_trail`].
    ///
    /// Returns `None` when the task has no message checkpoints (e.g. it only
    /// used messageless `checkpoint()` calls, or history is disabled), letting
    /// diagnostics omit the trail rather than print an empty one.
    #[must_use]
    pub fn render_trail(&self) -> Option<String> {
        render_checkpoint_trail(&self.checkpoint_history)
    }
}

#[cfg(test)]
#[path = "deadline_monitor_inline_tests.rs"]
mod tests;
