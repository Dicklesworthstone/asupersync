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
use std::collections::HashMap;
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
    pub by_type: HashMap<String, TypeSummary>,
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

    /// Get the current time from the timer driver, or ZERO if unavailable.
    fn current_time(&self) -> Time {
        self.state
            .timer_driver()
            .map_or(Time::ZERO, TimerDriverHandle::now)
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
            .filter(|o| o.age > age_threshold && o.is_active())
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
        let mut by_type: HashMap<String, TypeSummary> = HashMap::new();
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
            if obligation.age > entry.oldest_age {
                entry.oldest_age = obligation.age;
                entry.primary_holder = Some(format!("{:?}", obligation.holder_task));
            }

            if obligation.age > self.config.leak_age_threshold {
                potential_leaks += 1;
            }

            // Warning threshold at half of leak threshold
            let warning_threshold = self.config.leak_age_threshold / 2;
            if obligation.age > warning_threshold {
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

    /// Render obligation summary to console (if available).
    pub fn render_summary(&self) -> std::io::Result<()> {
        let Some(console) = &self.console else {
            return Ok(());
        };

        let summary = self.summary();
        let leaks = self.find_potential_leaks_default();

        // Build output string
        let mut output = String::new();
        writeln!(&mut output, "Obligation Tracker").unwrap();
        writeln!(
            &mut output,
            "Active: {}  |  Potential Leaks: {}  |  Age Warnings: {}",
            summary.total_active, summary.potential_leaks, summary.age_warnings
        )
        .unwrap();
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
            .unwrap();
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
                .unwrap();
                if let Some(desc) = &leak.description {
                    writeln!(&mut output, "    -> {desc}").unwrap();
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
mod tests {
    use super::*;

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
            .with_leak_threshold(Duration::from_mins(2))
            .with_periodic_checks(Duration::from_secs(15));

        assert_eq!(config.leak_age_threshold, Duration::from_mins(2));
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
}
