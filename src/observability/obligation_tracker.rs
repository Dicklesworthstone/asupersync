//! Obligation tracking and leak detection for runtime diagnostics.
//!
//! This module provides real-time visibility into obligations (permits, leases,
//! acks) held across the runtime, with leak detection and aging warnings.
//!
//! # Obligation Types
//!
//! - **SendPermit**: Bounded channel send permits
//! - **Ack**: Unacknowledged queue messages
//! - **Lease**: Connection or resource leases
//! - **IoOp**: In-progress I/O operations
//!
//! # Example
//!
//! ```ignore
//! use asupersync::observability::{ObligationTracker, ObligationTrackerConfig};
//! use std::time::Duration;
//!
//! let tracker = ObligationTracker::new(state.clone(), console);
//! let leaks = tracker.find_potential_leaks(Duration::from_mins(1));
//! if !leaks.is_empty() {
//!     for leak in &leaks {
//!         println!("Potential leak: {} held by {:?}", leak.type_name, leak.holder_task);
//!     }
//! }
//! ```

use crate::console::Console;
use crate::record::{ObligationKind, ObligationState};
use crate::runtime::state::RuntimeState;
use crate::time::TimerDriverHandle;
use crate::tracing_compat::{debug, info, trace, warn};
use crate::types::Time;
use crate::types::{ObligationId, RegionId, TaskId};
#[cfg(feature = "obligation-leak-detection")]
use std::backtrace::Backtrace;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Arc;
use std::time::Duration;

/// Configuration for the obligation tracker.
#[derive(Debug, Clone)]
pub struct ObligationTrackerConfig {
    /// Age threshold for potential leak warnings (default: 60s).
    pub leak_age_threshold: Duration,
    /// Enable periodic leak checks. Not applied yet: the tracker runs no
    /// periodic check; call
    /// [`ObligationTracker::find_potential_leaks_default`] instead.
    pub periodic_checks: bool,
    /// Interval between periodic checks. Not applied yet.
    pub check_interval: Duration,
}

impl Default for ObligationTrackerConfig {
    fn default() -> Self {
        Self {
            leak_age_threshold: Duration::from_mins(1),
            periodic_checks: false,
            check_interval: Duration::from_secs(30),
        }
    }
}

impl ObligationTrackerConfig {
    /// Create a new configuration with the specified leak threshold.
    #[must_use]
    pub fn with_leak_threshold(mut self, threshold: Duration) -> Self {
        self.leak_age_threshold = threshold;
        self
    }

    /// Enable periodic leak checks at the specified interval. Not applied
    /// yet (see [`ObligationTrackerConfig::periodic_checks`]).
    #[must_use]
    pub fn with_periodic_checks(mut self, interval: Duration) -> Self {
        self.periodic_checks = true;
        self.check_interval = interval;
        self
    }
}

/// Information about a single obligation.
#[derive(Debug, Clone)]
pub struct ObligationInfo {
    /// Unique identifier.
    pub id: ObligationId,
    /// Type name (e.g., "SendPermit", "Lease").
    pub type_name: String,
    /// Task holding the obligation.
    pub holder_task: TaskId,
    /// Region owning the obligation.
    pub holder_region: RegionId,
    /// Time when the obligation was created.
    pub created_at: Time,
    /// Age of the obligation.
    pub age: Duration,
    /// Current state.
    pub state: ObligationStateInfo,
    /// Optional description.
    pub description: Option<String>,
    /// Stack trace captured at obligation acquisition (if available).
    #[cfg(feature = "obligation-leak-detection")]
    pub acquisition_backtrace: Option<Arc<Backtrace>>,
    /// Source location where the obligation was acquired.
    pub acquired_at: crate::record::SourceLocation,
}

impl ObligationInfo {
    /// Returns true if this obligation is still active (not resolved).
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.state.is_active()
    }
}

/// State of an obligation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObligationStateInfo {
    /// Obligation is reserved but not yet resolved.
    Reserved,
    /// Obligation has been committed (successful resolution).
    Committed,
    /// Obligation was aborted (clean cancellation).
    Aborted,
    /// Obligation was leaked (holder completed without resolving).
    Leaked,
}

impl ObligationStateInfo {
    /// Returns true if the obligation is still active.
    #[must_use]
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Reserved)
    }
}

impl From<ObligationState> for ObligationStateInfo {
    fn from(state: ObligationState) -> Self {
        match state {
            ObligationState::Reserved => Self::Reserved,
            ObligationState::Committed => Self::Committed,
            ObligationState::Aborted => Self::Aborted,
            ObligationState::Leaked => Self::Leaked,
        }
    }
}

/// Summary of obligations grouped by type.
#[derive(Debug, Clone, Default)]
pub struct ObligationSummary {
    /// Obligations grouped by type.
    pub by_type: BTreeMap<String, TypeSummary>,
    /// Total active obligations.
    pub total_active: usize,
    /// Total potential leaks (above age threshold).
    pub potential_leaks: usize,
    /// Obligations above a warning threshold.
    pub age_warnings: usize,
}

/// Summary for a single obligation type.
#[derive(Debug, Clone)]
pub struct TypeSummary {
    /// Number of obligations of this type.
    pub count: usize,
    /// Oldest obligation age.
    pub oldest_age: Duration,
    /// Primary holder (task or region).
    pub primary_holder: Option<String>,
}

/// Severity level for obligation leaks.
#[cfg(feature = "obligation-leak-detection")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeakSeverity {
    /// Minor leak (just above threshold).
    Warning,
    /// Serious leak (significantly aged).
    Critical,
}

/// An obligation leak with full attribution.
#[cfg(feature = "obligation-leak-detection")]
#[derive(Debug, Clone)]
pub struct AttributedLeak {
    /// The leaked obligation.
    pub obligation: ObligationInfo,
    /// Stack trace at acquisition time (if captured).
    pub stack_trace: Option<Arc<Backtrace>>,
    /// Severity of the leak.
    pub leak_severity: LeakSeverity,
}

/// Comprehensive leak detection report.
#[cfg(feature = "obligation-leak-detection")]
#[derive(Debug, Clone)]
pub struct LeakDetectionReport {
    /// All attributed leaks found.
    pub attributed_leaks: Vec<AttributedLeak>,
    /// Regions that have leaks.
    pub affected_regions: Vec<RegionId>,
    /// When the detection was performed.
    pub detection_time: Time,
    /// Age threshold used for detection.
    pub threshold_used: Duration,
}

/// Detailed attribution for a single obligation leak.
#[cfg(feature = "obligation-leak-detection")]
#[derive(Debug, Clone)]
pub struct LeakAttribution {
    /// The obligation ID.
    pub obligation_id: ObligationId,
    /// Type of obligation.
    pub obligation_type: String,
    /// Task holding the obligation.
    pub holder_task: TaskId,
    /// Region owning the obligation.
    pub holder_region: RegionId,
    /// How long the obligation has been held.
    pub age: Duration,
    /// Source location where acquired.
    pub acquired_at: crate::record::SourceLocation,
    /// Optional description.
    pub description: Option<String>,
    /// Stack trace at acquisition (if captured).
    pub stack_trace: Option<Arc<Backtrace>>,
}

/// Real-time obligation tracker with leak detection.
#[derive(Debug)]
pub struct ObligationTracker {
    state: Arc<RuntimeState>,
    config: ObligationTrackerConfig,
    console: Option<Console>,
}

impl ObligationTracker {
    /// Create a new obligation tracker.
    #[must_use]
    pub fn new(state: Arc<RuntimeState>, console: Option<Console>) -> Self {
        Self::with_config(state, console, ObligationTrackerConfig::default())
    }

    /// Create a new obligation tracker with custom configuration.
    #[must_use]
    pub fn with_config(
        state: Arc<RuntimeState>,
        console: Option<Console>,
        config: ObligationTrackerConfig,
    ) -> Self {
        debug!(
            leak_threshold_secs = config.leak_age_threshold.as_secs(),
            periodic_checks = config.periodic_checks,
            "obligation tracker created"
        );
        Self {
            state,
            config,
            console,
        }
    }

    /// Get the current runtime time for observability.
    ///
    /// Live runtimes advance time through the timer driver, while timerless
    /// runtimes and many direct tests only move `RuntimeState::now`.
    /// Prefer the timer driver when present and fall back to the logical state
    /// clock otherwise so obligation ages remain meaningful in both modes.
    fn current_time(&self) -> Time {
        self.state
            .timer_driver()
            .map_or(self.state.now, TimerDriverHandle::now)
    }

    /// List all active obligations.
    #[must_use]
    pub fn list_obligations(&self) -> Vec<ObligationInfo> {
        trace!("listing all obligations");
        let current_time = self.current_time();

        self.state
            .obligations
            .iter()
            .filter_map(|(_, record)| {
                // Only include active obligations
                if record.state != ObligationState::Reserved {
                    return None;
                }

                let age_nanos = current_time.duration_since(record.reserved_at);
                let age = Duration::from_nanos(age_nanos);

                Some(ObligationInfo {
                    id: record.id,
                    type_name: obligation_kind_name(record.kind),
                    holder_task: record.holder,
                    holder_region: record.region,
                    created_at: record.reserved_at,
                    age,
                    state: record.state.into(),
                    description: record.description.clone(),
                    #[cfg(feature = "obligation-leak-detection")]
                    acquisition_backtrace: record.acquire_backtrace.clone(),
                    acquired_at: record.acquired_at,
                })
            })
            .collect()
    }

    /// Find potentially leaked obligations (held longer than threshold).
    #[must_use]
    pub fn find_potential_leaks(&self, age_threshold: Duration) -> Vec<ObligationInfo> {
        debug!(
            threshold_secs = age_threshold.as_secs(),
            "checking for potential obligation leaks"
        );

        let leaks: Vec<_> = self
            .list_obligations()
            .into_iter()
            .filter(|o| o.age >= age_threshold && o.is_active())
            .collect();

        if !leaks.is_empty() {
            warn!(
                count = leaks.len(),
                threshold_secs = age_threshold.as_secs(),
                "potential obligation leaks detected"
            );
            for leak in &leaks {
                // When tracing is compiled out, ensure `leak` is still considered "used".
                let _ = leak;
                info!(
                    obligation_id = ?leak.id,
                    type_name = %leak.type_name,
                    age_secs = leak.age.as_secs(),
                    holder_task = ?leak.holder_task,
                    holder_region = ?leak.holder_region,
                    "potential leak"
                );
            }
        }

        leaks
    }

    /// Find potential leaks using the configured threshold.
    #[must_use]
    pub fn find_potential_leaks_default(&self) -> Vec<ObligationInfo> {
        self.find_potential_leaks(self.config.leak_age_threshold)
    }

    /// Get obligations filtered by type.
    #[must_use]
    pub fn by_type(&self, type_name: &str) -> Vec<ObligationInfo> {
        trace!(type_name = %type_name, "filtering obligations by type");
        self.list_obligations()
            .into_iter()
            .filter(|o| o.type_name == type_name)
            .collect()
    }

    /// Get obligations held by a specific task.
    #[must_use]
    pub fn by_task(&self, task_id: TaskId) -> Vec<ObligationInfo> {
        trace!(task_id = ?task_id, "filtering obligations by task");
        self.list_obligations()
            .into_iter()
            .filter(|o| o.holder_task == task_id)
            .collect()
    }

    /// Get obligations in a specific region.
    #[must_use]
    pub fn by_region(&self, region_id: RegionId) -> Vec<ObligationInfo> {
        trace!(region_id = ?region_id, "filtering obligations by region");
        self.list_obligations()
            .into_iter()
            .filter(|o| o.holder_region == region_id)
            .collect()
    }

    /// Get a summary of all obligations grouped by type.
    #[must_use]
    pub fn summary(&self) -> ObligationSummary {
        let obligations = self.list_obligations();
        let mut by_type: BTreeMap<String, TypeSummary> = BTreeMap::new();
        let mut potential_leaks = 0;
        let mut age_warnings = 0;

        for obligation in &obligations {
            let entry = by_type
                .entry(obligation.type_name.clone())
                .or_insert_with(|| TypeSummary {
                    count: 0,
                    oldest_age: Duration::ZERO,
                    primary_holder: None,
                });

            entry.count += 1;
            if obligation.age >= entry.oldest_age {
                entry.oldest_age = obligation.age;
                entry.primary_holder = Some(format!("{:?}", obligation.holder_task));
            }

            if obligation.age >= self.config.leak_age_threshold {
                potential_leaks += 1;
            }

            // Warning threshold at half of leak threshold
            let warning_threshold = self.config.leak_age_threshold / 2;
            if obligation.age >= warning_threshold {
                age_warnings += 1;
            }
        }

        let total_active = obligations.len();

        debug!(
            total_active = total_active,
            potential_leaks = potential_leaks,
            age_warnings = age_warnings,
            "obligation summary computed"
        );

        ObligationSummary {
            by_type,
            total_active,
            potential_leaks,
            age_warnings,
        }
    }

    /// Check for obligation leaks at region close boundary.
    ///
    /// This method should be called when a region is about to close to detect
    /// any uncommitted obligations that would constitute leaks.
    #[must_use]
    pub fn check_region_close_obligations(&self, region_id: RegionId) -> Vec<ObligationInfo> {
        trace!(region_id = ?region_id, "checking obligations at region close");

        let region_obligations = self.by_region(region_id);
        let active_obligations: Vec<_> = region_obligations
            .into_iter()
            .filter(ObligationInfo::is_active)
            .collect();

        if !active_obligations.is_empty() {
            warn!(
                region_id = ?region_id,
                count = active_obligations.len(),
                "region closing with active obligations (potential leak)"
            );
            for obligation in &active_obligations {
                let _used = &obligation; // Ensure obligation is used in all feature configurations
                warn!(
                    obligation_id = ?obligation.id,
                    type_name = %obligation.type_name,
                    age_secs = obligation.age.as_secs_f64(),
                    holder_task = ?obligation.holder_task,
                    acquired_at = %obligation.acquired_at,
                    description = ?obligation.description,
                    "active obligation at region close"
                );

                #[cfg(feature = "obligation-leak-detection")]
                if let Some(ref backtrace) = obligation.acquisition_backtrace {
                    warn!(backtrace = %backtrace, "acquisition stack trace");
                }
            }
        }

        active_obligations
    }

    /// Enhanced leak detection with detailed attribution.
    ///
    /// Provides comprehensive diagnostics including stack traces when available.
    #[cfg(feature = "obligation-leak-detection")]
    #[must_use]
    pub fn enhanced_leak_detection(&self, age_threshold: Duration) -> LeakDetectionReport {
        debug!(
            threshold_secs = age_threshold.as_secs(),
            "performing enhanced leak detection with stack traces"
        );

        let potential_leaks = self.find_potential_leaks(age_threshold);
        let mut attributed_leaks = Vec::new();
        let mut regions_with_leaks = std::collections::BTreeSet::new();

        for leak in potential_leaks {
            attributed_leaks.push(AttributedLeak {
                obligation: leak.clone(),
                stack_trace: leak.acquisition_backtrace.clone(),
                leak_severity: if leak.age > age_threshold * 2 {
                    LeakSeverity::Critical
                } else {
                    LeakSeverity::Warning
                },
            });
            regions_with_leaks.insert(leak.holder_region);
        }

        LeakDetectionReport {
            attributed_leaks,
            affected_regions: regions_with_leaks.into_iter().collect(),
            detection_time: self.current_time(),
            threshold_used: age_threshold,
        }
    }

    /// Check if the runtime is in a clean state (no active obligations).
    #[must_use]
    pub fn is_runtime_clean(&self) -> bool {
        self.list_obligations().is_empty()
    }

    /// Get detailed attribution for a specific obligation leak.
    #[cfg(feature = "obligation-leak-detection")]
    #[must_use]
    pub fn get_leak_attribution(&self, obligation_id: ObligationId) -> Option<LeakAttribution> {
        let obligations = self.list_obligations();
        let obligation = obligations.iter().find(|o| o.id == obligation_id)?;

        Some(LeakAttribution {
            obligation_id,
            obligation_type: obligation.type_name.clone(),
            holder_task: obligation.holder_task,
            holder_region: obligation.holder_region,
            age: obligation.age,
            acquired_at: obligation.acquired_at,
            description: obligation.description.clone(),
            stack_trace: obligation.acquisition_backtrace.clone(),
        })
    }

    /// Render obligation summary to console (if available).
    pub fn render_summary(&self) -> std::io::Result<()> {
        let Some(console) = &self.console else {
            return Ok(());
        };

        let summary = self.summary();
        let leaks = self.find_potential_leaks_default();

        // Build output string
        let mut output = String::new();
        writeln!(&mut output, "Obligation Tracker").expect("expected");
        writeln!(
            &mut output,
            "Active: {}  |  Potential Leaks: {}  |  Age Warnings: {}",
            summary.total_active, summary.potential_leaks, summary.age_warnings
        )
        .expect("write should not fail on String");
        output.push_str(&"-".repeat(60));
        output.push('\n');

        // Type breakdown
        output.push_str("Type              Count  Oldest     Holder\n");
        output.push_str(&"-".repeat(60));
        output.push('\n');

        for (type_name, type_summary) in &summary.by_type {
            let holder = type_summary.primary_holder.as_deref().unwrap_or("-");
            writeln!(
                &mut output,
                "{type_name:<18} {:>5}  {:>8.1}s  {holder}",
                type_summary.count,
                type_summary.oldest_age.as_secs_f64()
            )
            .expect("write should not fail on String");
        }

        // Potential leaks section
        if !leaks.is_empty() {
            output.push_str(&"-".repeat(60));
            output.push('\n');
            output.push_str("POTENTIAL LEAKS:\n");
            for leak in &leaks {
                let type_name = &leak.type_name;
                let holder_task = leak.holder_task;
                let age_secs = leak.age.as_secs_f64();
                writeln!(
                    &mut output,
                    "  {type_name} held by {holder_task:?} for {age_secs:.1}s"
                )
                .expect("write should not fail on String");
                if let Some(desc) = &leak.description {
                    writeln!(&mut output, "    -> {desc}")
                        .expect("write should not fail on String");
                }
            }
        }

        console.print(&RawText(&output))
    }
}

/// Helper to convert ObligationKind to a readable name.
fn obligation_kind_name(kind: ObligationKind) -> String {
    match kind {
        ObligationKind::SendPermit => "SendPermit".to_string(),
        ObligationKind::Ack => "Ack".to_string(),
        ObligationKind::Lease => "Lease".to_string(),
        ObligationKind::IoOp => "IoOp".to_string(),
        ObligationKind::SemaphorePermit => "SemaphorePermit".to_string(),
        ObligationKind::Transaction => "Transaction".to_string(),
    }
}

/// Simple wrapper for rendering raw text.
struct RawText<'a>(&'a str);

impl crate::console::Render for RawText<'_> {
    fn render(
        &self,
        out: &mut String,
        _caps: &crate::console::Capabilities,
        _mode: crate::console::ColorMode,
    ) {
        out.push_str(self.0);
    }
}

#[cfg(test)]
#[allow(clippy::arc_with_non_send_sync)]
#[path = "obligation_tracker_inline_tests.rs"]
mod tests;
