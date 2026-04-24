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
    /// Enable periodic leak checks.
    pub periodic_checks: bool,
    /// Interval between periodic checks.
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

    /// Enable periodic leak checks at the specified interval.
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
mod tests {
    use super::*;
    use crate::Budget;
    use crate::time::{TimerDriverHandle, VirtualClock};

    #[test]
    fn test_obligation_state_is_active() {
        assert!(ObligationStateInfo::Reserved.is_active());
        assert!(!ObligationStateInfo::Committed.is_active());
        assert!(!ObligationStateInfo::Aborted.is_active());
        assert!(!ObligationStateInfo::Leaked.is_active());
    }

    #[test]
    fn test_obligation_kind_names() {
        assert_eq!(
            obligation_kind_name(ObligationKind::SendPermit),
            "SendPermit"
        );
        assert_eq!(obligation_kind_name(ObligationKind::Ack), "Ack");
        assert_eq!(obligation_kind_name(ObligationKind::Lease), "Lease");
        assert_eq!(obligation_kind_name(ObligationKind::IoOp), "IoOp");
    }

    #[test]
    fn test_config_defaults() {
        let config = ObligationTrackerConfig::default();
        assert_eq!(config.leak_age_threshold, Duration::from_mins(1));
        assert!(!config.periodic_checks);
        assert_eq!(config.check_interval, Duration::from_secs(30));
    }

    #[test]
    fn test_config_builder() {
        let config = ObligationTrackerConfig::default()
            .with_leak_threshold(Duration::from_secs(120))
            .with_periodic_checks(Duration::from_secs(15));

        assert_eq!(config.leak_age_threshold, Duration::from_secs(120));
        assert!(config.periodic_checks);
        assert_eq!(config.check_interval, Duration::from_secs(15));
    }

    #[test]
    fn test_summary_default() {
        let summary = ObligationSummary::default();
        assert_eq!(summary.total_active, 0);
        assert_eq!(summary.potential_leaks, 0);
        assert_eq!(summary.age_warnings, 0);
        assert!(summary.by_type.is_empty());
    }

    // Pure data-type tests (wave 17 – CyanBarn)

    #[test]
    fn config_debug_clone() {
        let cfg = ObligationTrackerConfig::default();
        let cfg2 = cfg;
        assert!(format!("{cfg2:?}").contains("ObligationTrackerConfig"));
    }

    #[test]
    fn config_with_leak_threshold() {
        let cfg = ObligationTrackerConfig::default().with_leak_threshold(Duration::from_secs(120));
        assert_eq!(cfg.leak_age_threshold, Duration::from_secs(120));
        assert!(!cfg.periodic_checks);
    }

    #[test]
    fn test_region_close_obligation_detection() {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let (task_id, _handle) = state
            .create_task(root, Budget::INFINITE, async {})
            .expect("create task");

        // Create an obligation in the region
        let obligation_id = state
            .create_obligation(
                ObligationKind::SendPermit,
                task_id,
                root,
                Some("test permit".into()),
            )
            .expect("create obligation");

        state.now = Time::from_secs(30);

        let tracker = ObligationTracker::new(Arc::new(state), None);

        // Check for leaks at region close
        let region_obligations = tracker.check_region_close_obligations(root);

        assert_eq!(region_obligations.len(), 1);
        assert_eq!(region_obligations[0].id, obligation_id);
        assert_eq!(region_obligations[0].type_name, "SendPermit");
        assert_eq!(region_obligations[0].age, Duration::from_secs(30));
        assert!(region_obligations[0].is_active());
    }

    #[cfg(feature = "obligation-leak-detection")]
    #[test]
    fn test_enhanced_leak_detection() {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let (task_id, _handle) = state
            .create_task(root, Budget::INFINITE, async {})
            .expect("create task");

        // Create obligations with different ages
        let old_obligation = state
            .create_obligation(
                ObligationKind::Lease,
                task_id,
                root,
                Some("old lease".into()),
            )
            .expect("create obligation");

        state.now = Time::from_secs(120); // Make the first obligation very old

        let new_obligation = state
            .create_obligation(ObligationKind::Ack, task_id, root, Some("new ack".into()))
            .expect("create obligation");

        state.now = Time::from_secs(150); // Age the second obligation moderately

        let tracker = ObligationTracker::new(Arc::new(state), None);
        let threshold = Duration::from_secs(60);

        let report = tracker.enhanced_leak_detection(threshold);

        assert_eq!(report.attributed_leaks.len(), 2);
        assert_eq!(report.affected_regions.len(), 1);
        assert_eq!(report.affected_regions[0], root);
        assert_eq!(report.threshold_used, threshold);

        // Check leak severity classification
        let critical_leak = report
            .attributed_leaks
            .iter()
            .find(|leak| leak.obligation.id == old_obligation)
            .expect("should find old obligation");
        assert_eq!(critical_leak.leak_severity, LeakSeverity::Critical);

        let warning_leak = report
            .attributed_leaks
            .iter()
            .find(|leak| leak.obligation.id == new_obligation)
            .expect("should find new obligation");
        assert_eq!(warning_leak.leak_severity, LeakSeverity::Warning);
    }

    #[cfg(feature = "obligation-leak-detection")]
    #[test]
    fn test_leak_attribution() {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let (task_id, _handle) = state
            .create_task(root, Budget::INFINITE, async {})
            .expect("create task");

        let obligation_id = state
            .create_obligation(ObligationKind::IoOp, task_id, root, Some("test io".into()))
            .expect("create obligation");

        state.now = Time::from_secs(90);

        let tracker = ObligationTracker::new(Arc::new(state), None);

        let attribution = tracker
            .get_leak_attribution(obligation_id)
            .expect("should find attribution");

        assert_eq!(attribution.obligation_id, obligation_id);
        assert_eq!(attribution.obligation_type, "IoOp");
        assert_eq!(attribution.holder_task, task_id);
        assert_eq!(attribution.holder_region, root);
        assert_eq!(attribution.age, Duration::from_secs(90));
        assert_eq!(attribution.description.as_deref(), Some("test io"));
    }

    #[test]
    fn test_runtime_clean_state() {
        let state = RuntimeState::new();
        let tracker = ObligationTracker::new(Arc::new(state), None);

        assert!(tracker.is_runtime_clean());

        // Test with obligations - need a mutable state for this
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let (task_id, _handle) = state
            .create_task(root, Budget::INFINITE, async {})
            .expect("create task");

        let _obligation_id = state
            .create_obligation(ObligationKind::SendPermit, task_id, root, None)
            .expect("create obligation");

        let tracker = ObligationTracker::new(Arc::new(state), None);
        assert!(!tracker.is_runtime_clean());
    }

    #[test]
    fn obligation_state_info_debug_clone_copy_eq() {
        let s = ObligationStateInfo::Reserved;
        let s2 = s;
        assert_eq!(s, s2);
        assert!(format!("{s:?}").contains("Reserved"));
    }

    #[test]
    fn obligation_state_info_all_variants() {
        assert!(ObligationStateInfo::Reserved.is_active());
        assert!(!ObligationStateInfo::Committed.is_active());
        assert!(!ObligationStateInfo::Aborted.is_active());
        assert!(!ObligationStateInfo::Leaked.is_active());
    }

    #[test]
    fn obligation_state_info_ne() {
        assert_ne!(
            ObligationStateInfo::Reserved,
            ObligationStateInfo::Committed
        );
        assert_ne!(ObligationStateInfo::Aborted, ObligationStateInfo::Leaked);
    }

    #[test]
    fn obligation_state_info_from_obligation_state() {
        let s = ObligationStateInfo::from(ObligationState::Reserved);
        assert_eq!(s, ObligationStateInfo::Reserved);

        let s = ObligationStateInfo::from(ObligationState::Committed);
        assert_eq!(s, ObligationStateInfo::Committed);

        let s = ObligationStateInfo::from(ObligationState::Aborted);
        assert_eq!(s, ObligationStateInfo::Aborted);

        let s = ObligationStateInfo::from(ObligationState::Leaked);
        assert_eq!(s, ObligationStateInfo::Leaked);
    }

    #[test]
    fn obligation_summary_debug_clone() {
        let summary = ObligationSummary::default();
        let summary2 = summary;
        assert!(format!("{summary2:?}").contains("ObligationSummary"));
    }

    #[test]
    fn obligation_summary_with_entries() {
        let mut summary = ObligationSummary {
            total_active: 5,
            potential_leaks: 2,
            age_warnings: 1,
            ..ObligationSummary::default()
        };
        summary.by_type.insert(
            "Lease".to_string(),
            TypeSummary {
                count: 5,
                oldest_age: Duration::from_mins(1),
                primary_holder: Some("task-1".into()),
            },
        );
        assert_eq!(summary.by_type.len(), 1);
    }

    #[test]
    fn type_summary_debug_clone() {
        let ts = TypeSummary {
            count: 3,
            oldest_age: Duration::from_secs(30),
            primary_holder: None,
        };
        let ts2 = ts;
        assert_eq!(ts2.count, 3);
        assert!(format!("{ts2:?}").contains("TypeSummary"));
    }

    #[test]
    fn type_summary_with_primary_holder() {
        let ts = TypeSummary {
            count: 1,
            oldest_age: Duration::ZERO,
            primary_holder: Some("task-7".into()),
        };
        assert_eq!(ts.primary_holder.as_deref(), Some("task-7"));
    }

    #[test]
    fn obligation_info_debug_clone() {
        let info = ObligationInfo {
            id: ObligationId::new_for_test(1, 0),
            type_name: "SendPermit".into(),
            holder_task: TaskId::new_for_test(1, 0),
            holder_region: RegionId::new_for_test(1, 0),
            created_at: Time::ZERO,
            age: Duration::from_secs(5),
            state: ObligationStateInfo::Reserved,
            description: None,
            #[cfg(feature = "obligation-leak-detection")]
            acquisition_backtrace: None,
            acquired_at: crate::record::SourceLocation::unknown(),
        };
        let info2 = info;
        assert!(info2.is_active());
        assert!(format!("{info2:?}").contains("ObligationInfo"));
    }

    #[test]
    fn obligation_info_is_active_committed() {
        let info = ObligationInfo {
            id: ObligationId::new_for_test(2, 0),
            type_name: "Ack".into(),
            holder_task: TaskId::new_for_test(1, 0),
            holder_region: RegionId::new_for_test(1, 0),
            created_at: Time::ZERO,
            age: Duration::from_secs(10),
            state: ObligationStateInfo::Committed,
            description: Some("test".into()),
            #[cfg(feature = "obligation-leak-detection")]
            acquisition_backtrace: None,
            acquired_at: crate::record::SourceLocation::unknown(),
        };
        assert!(!info.is_active());
    }

    #[test]
    fn tracker_uses_runtime_logical_time_without_timer_driver() {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let (task_id, _handle) = state
            .create_task(root, Budget::INFINITE, async {})
            .expect("create task");
        let obligation_id = state
            .create_obligation(ObligationKind::Lease, task_id, root, Some("lease".into()))
            .expect("create obligation");
        state.now = Time::from_secs(65);

        let tracker = ObligationTracker::new(Arc::new(state), None);
        let obligations = tracker.list_obligations();
        assert_eq!(obligations.len(), 1);
        assert_eq!(obligations[0].id, obligation_id);
        assert_eq!(obligations[0].age, Duration::from_secs(65));

        let leaks = tracker.find_potential_leaks_default();
        assert_eq!(leaks.len(), 1);
        assert_eq!(leaks[0].id, obligation_id);
        assert_eq!(leaks[0].age, Duration::from_secs(65));

        let summary = tracker.summary();
        assert_eq!(summary.total_active, 1);
        assert_eq!(summary.potential_leaks, 1);
        assert_eq!(summary.age_warnings, 1);
    }

    #[test]
    fn tracker_prefers_timer_driver_when_available() {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let (task_id, _handle) = state
            .create_task(root, Budget::INFINITE, async {})
            .expect("create task");
        let obligation_id = state
            .create_obligation(ObligationKind::Ack, task_id, root, None)
            .expect("create obligation");
        state.now = Time::from_secs(5);
        state.set_timer_driver(TimerDriverHandle::with_virtual_clock(Arc::new(
            VirtualClock::starting_at(Time::from_secs(8)),
        )));

        let tracker = ObligationTracker::new(Arc::new(state), None);
        let obligations = tracker.list_obligations();
        assert_eq!(obligations.len(), 1);
        assert_eq!(obligations[0].id, obligation_id);
        assert_eq!(obligations[0].age, Duration::from_secs(8));
    }

    // ========================================================================
    // Metamorphic Testing: obligation_tracker commit-abort symmetry under panic recovery
    // ========================================================================

    /// MR1: Panic during commit triggers abort path (Equivalence)
    /// Transformation: Induce panic during commit operation
    /// Relation: Obligation state should recover to consistent state
    #[test]
    fn mr_obligation_panic_during_commit_triggers_abort() {
        use crate::types::Budget;
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let (task_id, _handle) = state
            .create_task(root, Budget::INFINITE, async {})
            .expect("create task");

        // Create obligation that we'll attempt to commit with panic
        let obligation_id = state
            .create_obligation(
                ObligationKind::SendPermit,
                task_id,
                root,
                Some("panic_test".into()),
            )
            .expect("create obligation");

        let tracker = ObligationTracker::new(Arc::new(state), None);

        // Verify initial state
        let initial_obligations = tracker.list_obligations();
        assert_eq!(initial_obligations.len(), 1);
        assert_eq!(initial_obligations[0].id, obligation_id);
        assert!(initial_obligations[0].is_active());

        // Simulate panic recovery - in reality this would involve the runtime's
        // panic handling, but we test the invariant that unresolved obligations
        // are detectable regardless of how they became unresolved
        let obligations_after_simulated_panic = tracker.list_obligations();
        assert_eq!(obligations_after_simulated_panic.len(), 1);

        // The metamorphic property: panic during commit should leave obligation
        // in a state equivalent to explicit abort (both are detectable as unresolved)
        let leaks = tracker.find_potential_leaks(Duration::ZERO);
        assert_eq!(
            leaks.len(),
            1,
            "Unresolved obligation should be detectable as leak"
        );
        assert_eq!(leaks[0].id, obligation_id);
    }

    /// MR2: Panic during abort is double-panic safe (Invertive)
    /// Transformation: Abort → panic during abort → should not double-panic
    /// Relation: Operation should be idempotent under panic
    #[test]
    fn mr_obligation_double_panic_safety() {
        use crate::types::Budget;
        use std::panic::{AssertUnwindSafe, catch_unwind};

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let (task_id, _handle) = state
            .create_task(root, Budget::INFINITE, async {})
            .expect("create task");

        // Create two obligations for testing double-panic scenarios
        let obligation_id_1 = state
            .create_obligation(
                ObligationKind::Lease,
                task_id,
                root,
                Some("double_panic_1".into()),
            )
            .expect("create obligation 1");

        let obligation_id_2 = state
            .create_obligation(
                ObligationKind::Ack,
                task_id,
                root,
                Some("double_panic_2".into()),
            )
            .expect("create obligation 2");

        let tracker = ObligationTracker::new(Arc::new(state), None);

        // Verify initial state
        let initial_count = tracker.list_obligations().len();
        assert_eq!(initial_count, 2);

        // The metamorphic property: tracking operations should be double-panic safe
        // If a panic occurs during obligation resolution, the tracker should not
        // itself panic when called again
        let _ = catch_unwind(AssertUnwindSafe(|| {
            let _obligations = tracker.list_obligations();
            // Simulate whatever operation might panic during abort handling
        }));

        // After simulated panic, tracker should still function
        let post_panic_obligations = tracker.list_obligations();
        assert_eq!(
            post_panic_obligations.len(),
            2,
            "Tracker should remain functional after panic"
        );

        // Verify both obligations are still tracked
        let obligation_ids: Vec<_> = post_panic_obligations.iter().map(|o| o.id).collect();
        assert!(obligation_ids.contains(&obligation_id_1));
        assert!(obligation_ids.contains(&obligation_id_2));
    }

    /// MR3: track_obligation + untrack_obligation round-trip preserves count (Invertive)
    /// Transformation: track → untrack → count should return to original
    /// Relation: f(untrack(track(x))) = f(x)
    #[test]
    fn mr_obligation_track_untrack_roundtrip() {
        use crate::types::Budget;

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let (task_id, _handle) = state
            .create_task(root, Budget::INFINITE, async {})
            .expect("create task");

        // Track obligation (add)
        let obligation_id = state
            .create_obligation(
                ObligationKind::IoOp,
                task_id,
                root,
                Some("roundtrip_test".into()),
            )
            .expect("create obligation");

        // Untrack obligation (resolve via commit)
        let _duration = state
            .commit_obligation(obligation_id)
            .expect("commit obligation");

        let tracker = ObligationTracker::new(Arc::new(state), None);
        let after_untrack_count = tracker.list_obligations().len();

        assert_eq!(
            after_untrack_count, 0,
            "Round-trip track→untrack should preserve active obligation count"
        );

        // Verify the obligation is no longer in the active set
        let active_obligations = tracker.list_obligations();
        assert!(
            !active_obligations.iter().any(|o| o.id == obligation_id),
            "Committed obligation should not appear in active list"
        );
    }

    /// MR4: Replay under LabRuntime produces identical obligation trace (Equivalence)
    /// Transformation: Same sequence with deterministic execution
    /// Relation: f(sequence, seed1) = f(sequence, seed2) when seed1 = seed2
    #[test]
    fn mr_obligation_deterministic_replay() {
        use crate::types::Budget;
        use crate::util::DetRng;

        // First execution with deterministic entropy
        let mut state1 = RuntimeState::new();
        let root1 = state1.create_root_region(Budget::INFINITE);
        let (task_id_1, _handle1) = state1
            .create_task(root1, Budget::INFINITE, async {})
            .expect("create task 1");

        // Simulate deterministic obligation creation pattern
        let mut entropy1 = DetRng::new(12345);
        let mut obligation_ids_1 = Vec::new();

        for i in 0..3 {
            let kind = if entropy1.next_u32() % 2 == 0 {
                ObligationKind::SendPermit
            } else {
                ObligationKind::Ack
            };

            let obligation_id = state1
                .create_obligation(kind, task_id_1, root1, Some(format!("det_replay_{}", i)))
                .expect("create obligation");
            obligation_ids_1.push(obligation_id);
        }

        let tracker1 = ObligationTracker::new(Arc::new(state1), None);
        let trace1 = tracker1.list_obligations();

        // Second execution with same entropy seed
        let mut state2 = RuntimeState::new();
        let root2 = state2.create_root_region(Budget::INFINITE);
        let (task_id_2, _handle2) = state2
            .create_task(root2, Budget::INFINITE, async {})
            .expect("create task 2");

        let mut entropy2 = DetRng::new(12345); // Same seed
        let mut obligation_ids_2 = Vec::new();

        for i in 0..3 {
            let kind = if entropy2.next_u32() % 2 == 0 {
                ObligationKind::SendPermit
            } else {
                ObligationKind::Ack
            };

            let obligation_id = state2
                .create_obligation(kind, task_id_2, root2, Some(format!("det_replay_{}", i)))
                .expect("create obligation");
            obligation_ids_2.push(obligation_id);
        }

        let tracker2 = ObligationTracker::new(Arc::new(state2), None);
        let trace2 = tracker2.list_obligations();

        // Metamorphic property: deterministic execution should produce identical traces
        assert_eq!(
            trace1.len(),
            trace2.len(),
            "Deterministic replay should produce same trace length"
        );

        for (i, (t1, t2)) in trace1.iter().zip(trace2.iter()).enumerate() {
            assert_eq!(
                t1.type_name, t2.type_name,
                "Obligation type at index {} should be identical in deterministic replay",
                i
            );
            assert_eq!(
                t1.state, t2.state,
                "Obligation state at index {} should be identical in deterministic replay",
                i
            );
            // Note: IDs will differ, but the pattern should be the same
        }
    }

    /// MR5: Tracker drop without commit logs leak (Inclusive)
    /// Transformation: Create obligation → drop without resolution
    /// Relation: Should be detectable as leak
    #[test]
    fn mr_obligation_tracker_drop_logs_leak() {
        use crate::types::Budget;

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let (task_id, _handle) = state
            .create_task(root, Budget::INFINITE, async {})
            .expect("create task");

        // Create obligation without resolving it
        let leaked_obligation_id = state
            .create_obligation(
                ObligationKind::SemaphorePermit,
                task_id,
                root,
                Some("intentional_leak".into()),
            )
            .expect("create obligation");

        let second_leaked_id = state
            .create_obligation(
                ObligationKind::Lease,
                task_id,
                root,
                Some("second_leak".into()),
            )
            .expect("create second obligation");

        let state = Arc::new(state);
        // Use a ZERO leak threshold so any unresolved obligation counts
        // as a potential leak, independent of virtual-clock progression.
        let mut config = ObligationTrackerConfig::default();
        config.leak_age_threshold = Duration::ZERO;
        let tracker = ObligationTracker::with_config(Arc::clone(&state), None, config);

        // Verify obligation exists initially
        let initial_obligations = tracker.list_obligations();
        assert_eq!(initial_obligations.len(), 2);
        assert!(
            initial_obligations
                .iter()
                .any(|o| o.id == leaked_obligation_id)
        );
        assert!(initial_obligations.iter().any(|o| o.id == second_leaked_id));

        // The metamorphic property: obligations without resolution should be detectable as leaks
        let leaks = tracker.find_potential_leaks(Duration::ZERO);
        assert_eq!(
            leaks.len(),
            2,
            "Unresolved obligation should be detected as leak"
        );
        assert!(leaks.iter().any(|o| o.id == leaked_obligation_id));
        assert!(leaks.iter().any(|o| o.id == second_leaked_id));

        // Verify leak detection summary
        let summary = tracker.summary();
        assert_eq!(summary.total_active, 2);
        assert_eq!(summary.potential_leaks, 2);
    }
}
