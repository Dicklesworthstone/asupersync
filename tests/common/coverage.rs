//! Coverage measurement for property tests.
//!
//! This module provides infrastructure for measuring which invariants
//! and code paths are covered by property tests.
//!
//! # Usage
//!
//! ```ignore
//! let mut tracker = InvariantTracker::new();
//!
//! // Check invariants and track coverage
//! tracker.check("no_orphan_tasks", tree.has_no_orphans());
//! tracker.check("tree_structure", tree.is_valid_tree());
//!
//! // Generate report
//! let report = tracker.report();
//! println!("{}", report);
//! ```

use std::collections::HashMap;
use std::fmt;

/// Information about coverage for a single invariant.
#[derive(Debug, Clone, Default)]
pub struct CoverageInfo {
    /// Number of times this invariant was checked.
    pub checks: u64,
    /// Number of times the invariant passed (held true).
    pub passes: u64,
    /// Number of times the invariant detected a bug (in mutation testing).
    pub detections: u64,
}

impl CoverageInfo {
    /// Create a new empty coverage info.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a check of this invariant.
    pub fn record_check(&mut self, holds: bool) {
        self.checks += 1;
        if holds {
            self.passes += 1;
        }
    }

    /// Record a bug detection (for mutation testing).
    pub fn record_detection(&mut self) {
        self.detections += 1;
    }

    /// Calculate the pass rate as a percentage.
    #[must_use]
    pub fn pass_rate(&self) -> f64 {
        if self.checks == 0 {
            100.0
        } else {
            (self.passes as f64 / self.checks as f64) * 100.0
        }
    }

    /// Calculate the detection rate as a percentage.
    /// This measures how effective the invariant is at catching bugs.
    #[must_use]
    pub fn detection_rate(&self) -> f64 {
        if self.checks == 0 {
            0.0
        } else {
            (self.detections as f64 / self.checks as f64) * 100.0
        }
    }
}

/// Tracker for measuring invariant coverage in property tests.
#[derive(Debug, Clone)]
pub struct InvariantTracker {
    /// Coverage information per invariant name.
    invariants: HashMap<&'static str, CoverageInfo>,
    /// Whether to log each check (for debugging).
    verbose: bool,
}

impl Default for InvariantTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl InvariantTracker {
    /// Create a new empty tracker.
    #[must_use]
    pub fn new() -> Self {
        Self {
            invariants: HashMap::new(),
            verbose: false,
        }
    }

    /// Create a tracker with verbose logging enabled.
    #[must_use]
    pub fn with_verbose(verbose: bool) -> Self {
        Self {
            invariants: HashMap::new(),
            verbose,
        }
    }

    /// Check an invariant and record the result.
    ///
    /// Returns the result of the check for convenience in assertions.
    pub fn check(&mut self, name: &'static str, holds: bool) -> bool {
        let info = self.invariants.entry(name).or_default();
        info.record_check(holds);

        if self.verbose {
            tracing::trace!(
                invariant = %name,
                holds = %holds,
                checks = info.checks,
                passes = info.passes,
                "invariant check"
            );
        }

        holds
    }

    /// Record a bug detection for an invariant (for mutation testing).
    pub fn record_detection(&mut self, name: &'static str) {
        let info = self.invariants.entry(name).or_default();
        info.record_detection();
    }

    /// Get coverage info for a specific invariant.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&CoverageInfo> {
        self.invariants.get(name)
    }

    /// Get the total number of invariants tracked.
    #[must_use]
    pub fn invariant_count(&self) -> usize {
        self.invariants.len()
    }

    /// Get the total number of checks performed.
    #[must_use]
    pub fn total_checks(&self) -> u64 {
        self.invariants.values().map(|i| i.checks).sum()
    }

    /// Get the total number of passes.
    #[must_use]
    pub fn total_passes(&self) -> u64 {
        self.invariants.values().map(|i| i.passes).sum()
    }

    /// Calculate the average detection rate across all invariants.
    #[must_use]
    pub fn average_detection_rate(&self) -> f64 {
        if self.invariants.is_empty() {
            return 0.0;
        }

        let total: f64 = self.invariants.values().map(|i| i.detection_rate()).sum();
        total / self.invariants.len() as f64
    }

    /// Check if all tracked invariants have been checked at least once.
    #[must_use]
    pub fn all_checked(&self) -> bool {
        !self.invariants.is_empty() && self.invariants.values().all(|i| i.checks > 0)
    }

    /// Reset all tracking data.
    pub fn reset(&mut self) {
        self.invariants.clear();
    }

    /// Generate a coverage report.
    #[must_use]
    pub fn report(&self) -> CoverageReport {
        CoverageReport::from_tracker(self)
    }

    /// Merge another tracker's data into this one.
    pub fn merge(&mut self, other: &InvariantTracker) {
        for (name, info) in &other.invariants {
            let entry = self.invariants.entry(name).or_default();
            entry.checks += info.checks;
            entry.passes += info.passes;
            entry.detections += info.detections;
        }
    }
}

/// A formatted coverage report.
#[derive(Debug, Clone)]
pub struct CoverageReport {
    /// Entries sorted by invariant name.
    entries: Vec<CoverageEntry>,
    /// Total number of invariants.
    total_invariants: usize,
    /// Invariants with at least one check.
    checked_invariants: usize,
    /// Average detection rate.
    average_detection_rate: f64,
}

/// A single entry in the coverage report.
#[derive(Debug, Clone)]
pub struct CoverageEntry {
    /// Name of the invariant.
    pub name: String,
    /// Number of checks performed.
    pub checks: u64,
    /// Number of passes.
    pub passes: u64,
    /// Detection rate percentage.
    pub detection_rate: f64,
}

impl CoverageReport {
    /// Build a report from a tracker.
    fn from_tracker(tracker: &InvariantTracker) -> Self {
        let mut entries: Vec<_> = tracker
            .invariants
            .iter()
            .map(|(name, info)| CoverageEntry {
                name: (*name).to_string(),
                checks: info.checks,
                passes: info.passes,
                detection_rate: info.detection_rate(),
            })
            .collect();

        // Sort by name for consistent output
        entries.sort_by(|a, b| a.name.cmp(&b.name));

        let checked_invariants = entries.iter().filter(|e| e.checks > 0).count();

        Self {
            entries,
            total_invariants: tracker.invariant_count(),
            checked_invariants,
            average_detection_rate: tracker.average_detection_rate(),
        }
    }

    /// Get the entries in the report.
    #[must_use]
    pub fn entries(&self) -> &[CoverageEntry] {
        &self.entries
    }

    /// Get the total number of invariants.
    #[must_use]
    pub fn total_invariants(&self) -> usize {
        self.total_invariants
    }

    /// Get the number of invariants that were checked.
    #[must_use]
    pub fn checked_invariants(&self) -> usize {
        self.checked_invariants
    }

    /// Get the coverage percentage (checked / total).
    #[must_use]
    pub fn coverage_percentage(&self) -> f64 {
        if self.total_invariants == 0 {
            100.0
        } else {
            (self.checked_invariants as f64 / self.total_invariants as f64) * 100.0
        }
    }

    /// Get the average detection rate.
    #[must_use]
    pub fn average_detection_rate(&self) -> f64 {
        self.average_detection_rate
    }

    /// Format as a simple text table.
    #[must_use]
    pub fn format_table(&self) -> String {
        let mut output = String::new();

        output.push_str("Property Test Coverage Report\n");
        output.push_str("=============================\n\n");

        // Header
        output.push_str(&format!(
            "{:<30} {:>10} {:>10} {:>15}\n",
            "Invariant", "Checks", "Passes", "Detection Rate"
        ));
        output.push_str(&"-".repeat(67));
        output.push('\n');

        // Entries
        for entry in &self.entries {
            output.push_str(&format!(
                "{:<30} {:>10} {:>10} {:>14.1}%\n",
                entry.name, entry.checks, entry.passes, entry.detection_rate
            ));
        }

        // Summary
        output.push_str(&"-".repeat(67));
        output.push('\n');
        output.push_str(&format!(
            "\nTotal: {} invariants, {:.1}% checked\n",
            self.total_invariants,
            self.coverage_percentage()
        ));
        output.push_str(&format!(
            "Average detection rate: {:.1}%\n",
            self.average_detection_rate
        ));

        output
    }
}

impl fmt::Display for CoverageReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.format_table())
    }
}

/// Assert that all specified invariants have been checked.
///
/// This is useful at the end of a property test to ensure coverage.
pub fn assert_coverage(tracker: &InvariantTracker, required_invariants: &[&str]) {
    let mut missing = Vec::new();

    for &name in required_invariants {
        match tracker.get(name) {
            Some(info) if info.checks > 0 => {}
            _ => missing.push(name),
        }
    }

    if !missing.is_empty() {
        panic!(
            "Missing invariant coverage: {:?}\n\nTracked invariants:\n{}",
            missing,
            tracker.report()
        );
    }
}

/// Assert that coverage meets a minimum threshold.
pub fn assert_coverage_threshold(tracker: &InvariantTracker, min_percentage: f64) {
    let report = tracker.report();
    let actual = report.coverage_percentage();

    if actual < min_percentage {
        panic!(
            "Coverage {:.1}% is below threshold {:.1}%\n\n{}",
            actual, min_percentage, report
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_coverage_info_basic() {
        let mut info = CoverageInfo::new();
        assert_eq!(info.checks, 0);
        assert_eq!(info.passes, 0);

        info.record_check(true);
        assert_eq!(info.checks, 1);
        assert_eq!(info.passes, 1);

        info.record_check(false);
        assert_eq!(info.checks, 2);
        assert_eq!(info.passes, 1);

        assert!((info.pass_rate() - 50.0).abs() < 0.1);
    }

    #[test]
    fn test_tracker_basic() {
        let mut tracker = InvariantTracker::new();

        assert!(tracker.check("test_invariant", true));
        assert!(!tracker.check("test_invariant", false));

        let info = tracker.get("test_invariant").unwrap();
        assert_eq!(info.checks, 2);
        assert_eq!(info.passes, 1);
    }

    #[test]
    fn test_tracker_multiple_invariants() {
        let mut tracker = InvariantTracker::new();

        for _ in 0..10 {
            tracker.check("invariant_a", true);
        }

        for i in 0..10 {
            tracker.check("invariant_b", i % 2 == 0);
        }

        assert_eq!(tracker.invariant_count(), 2);
        assert_eq!(tracker.total_checks(), 20);
        assert_eq!(tracker.total_passes(), 15);
    }

    #[test]
    fn test_report_generation() {
        let mut tracker = InvariantTracker::new();

        tracker.check("no_orphan_tasks", true);
        tracker.check("tree_structure", true);
        tracker.check("cancel_propagation", false);

        let report = tracker.report();
        assert_eq!(report.total_invariants(), 3);
        assert_eq!(report.checked_invariants(), 3);
        assert!((report.coverage_percentage() - 100.0).abs() < 0.1);

        let formatted = report.to_string();
        assert!(formatted.contains("no_orphan_tasks"));
        assert!(formatted.contains("tree_structure"));
        assert!(formatted.contains("cancel_propagation"));
    }

    #[test]
    fn test_coverage_assertion() {
        let mut tracker = InvariantTracker::new();
        tracker.check("required_1", true);
        tracker.check("required_2", true);

        // Should pass
        assert_coverage(&tracker, &["required_1", "required_2"]);
    }

    #[test]
    #[should_panic(expected = "Missing invariant coverage")]
    fn test_coverage_assertion_fails_on_missing() {
        let mut tracker = InvariantTracker::new();
        tracker.check("required_1", true);

        // Should fail - required_2 not checked
        assert_coverage(&tracker, &["required_1", "required_2"]);
    }

    #[test]
    fn test_tracker_merge() {
        let mut tracker1 = InvariantTracker::new();
        tracker1.check("shared", true);
        tracker1.check("only_in_1", true);

        let mut tracker2 = InvariantTracker::new();
        tracker2.check("shared", true);
        tracker2.check("shared", false);
        tracker2.check("only_in_2", true);

        tracker1.merge(&tracker2);

        assert_eq!(tracker1.invariant_count(), 3);

        let shared = tracker1.get("shared").unwrap();
        assert_eq!(shared.checks, 3);
        assert_eq!(shared.passes, 2);
    }

    #[test]
    fn test_detection_rate() {
        let mut info = CoverageInfo::new();

        // 10 checks, 3 detections
        for _ in 0..10 {
            info.record_check(true);
        }
        for _ in 0..3 {
            info.record_detection();
        }

        assert!((info.detection_rate() - 30.0).abs() < 0.1);
    }
}
