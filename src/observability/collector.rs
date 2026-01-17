//! Log collector for batching and filtering log entries.
//!
//! Provides infrastructure for collecting, filtering, and outputting
//! log entries in various formats.

use super::entry::LogEntry;
use super::level::LogLevel;
use crate::types::Time;
use core::fmt;

/// A collector that accumulates log entries with filtering.
///
/// The collector provides:
/// - Level-based filtering
/// - Fixed-capacity ring buffer behavior
/// - Formatted output generation
///
/// # Example
///
/// ```ignore
/// let mut collector = LogCollector::new(100)
///     .with_min_level(LogLevel::Info);
///
/// collector.collect(LogEntry::info("Hello"));
/// collector.collect(LogEntry::debug("Ignored")); // Filtered out
///
/// for entry in collector.entries() {
///     println!("{}", entry);
/// }
/// ```
#[derive(Debug, Clone)]
pub struct LogCollector {
    /// Collected log entries.
    entries: Vec<LogEntry>,
    /// Maximum number of entries to retain.
    capacity: usize,
    /// Minimum level to collect.
    min_level: LogLevel,
    /// Target filter (if set, only entries matching this target are collected).
    target_filter: Option<String>,
    /// Total entries received (including filtered).
    total_received: u64,
    /// Total entries dropped due to capacity.
    total_dropped: u64,
}

impl LogCollector {
    /// Creates a new log collector with the given capacity.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: Vec::with_capacity(capacity.min(1024)),
            capacity,
            min_level: LogLevel::Trace,
            target_filter: None,
            total_received: 0,
            total_dropped: 0,
        }
    }

    /// Sets the minimum log level to collect.
    #[must_use]
    pub fn with_min_level(mut self, level: LogLevel) -> Self {
        self.min_level = level;
        self
    }

    /// Sets a target filter.
    #[must_use]
    pub fn with_target_filter(mut self, target: impl Into<String>) -> Self {
        self.target_filter = Some(target.into());
        self
    }

    /// Returns the capacity.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Returns the current number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if no entries have been collected.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the minimum log level.
    #[must_use]
    pub const fn min_level(&self) -> LogLevel {
        self.min_level
    }

    /// Sets the minimum log level.
    pub fn set_min_level(&mut self, level: LogLevel) {
        self.min_level = level;
    }

    /// Returns the total entries received.
    #[must_use]
    pub const fn total_received(&self) -> u64 {
        self.total_received
    }

    /// Returns the total entries dropped.
    #[must_use]
    pub const fn total_dropped(&self) -> u64 {
        self.total_dropped
    }

    /// Checks if an entry should be collected based on filters.
    fn should_collect(&self, entry: &LogEntry) -> bool {
        // Check level
        if !entry.level().is_at_least(self.min_level) {
            return false;
        }

        // Check target filter
        if let Some(ref filter) = self.target_filter {
            if let Some(target) = entry.target() {
                if !target.contains(filter.as_str()) {
                    return false;
                }
            } else {
                return false;
            }
        }

        true
    }

    /// Collects a log entry.
    ///
    /// Returns true if the entry was collected, false if filtered.
    pub fn collect(&mut self, entry: LogEntry) -> bool {
        self.total_received += 1;

        if !self.should_collect(&entry) {
            return false;
        }

        // Handle capacity
        if self.entries.len() >= self.capacity {
            self.entries.remove(0);
            self.total_dropped += 1;
        }

        self.entries.push(entry);
        true
    }

    /// Collects a log entry with a timestamp.
    pub fn collect_with_time(&mut self, entry: LogEntry, time: Time) -> bool {
        self.collect(entry.with_timestamp(time))
    }

    /// Returns an iterator over collected entries.
    pub fn entries(&self) -> impl Iterator<Item = &LogEntry> {
        self.entries.iter()
    }

    /// Returns entries filtered by level.
    pub fn entries_at_level(&self, level: LogLevel) -> impl Iterator<Item = &LogEntry> {
        self.entries.iter().filter(move |e| e.level() == level)
    }

    /// Returns entries at or above the given level.
    pub fn entries_at_least(&self, level: LogLevel) -> impl Iterator<Item = &LogEntry> {
        self.entries
            .iter()
            .filter(move |e| e.level().is_at_least(level))
    }

    /// Returns the most recent entry.
    #[must_use]
    pub fn last(&self) -> Option<&LogEntry> {
        self.entries.last()
    }

    /// Clears all collected entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Drains all entries, returning them as a vector.
    pub fn drain(&mut self) -> Vec<LogEntry> {
        std::mem::take(&mut self.entries)
    }

    /// Formats all entries as compact text.
    #[must_use]
    pub fn format_compact(&self) -> String {
        let mut s = String::new();
        for entry in &self.entries {
            s.push_str(&entry.format_compact());
            s.push('\n');
        }
        s
    }

    /// Formats all entries as JSON lines.
    #[must_use]
    pub fn format_jsonl(&self) -> String {
        let mut s = String::new();
        for entry in &self.entries {
            s.push_str(&entry.format_json());
            s.push('\n');
        }
        s
    }

    /// Returns a summary of the collected logs.
    #[must_use]
    pub fn summary(&self) -> CollectorSummary {
        let mut summary = CollectorSummary::default();
        for entry in &self.entries {
            match entry.level() {
                LogLevel::Trace => summary.trace_count += 1,
                LogLevel::Debug => summary.debug_count += 1,
                LogLevel::Info => summary.info_count += 1,
                LogLevel::Warn => summary.warn_count += 1,
                LogLevel::Error => summary.error_count += 1,
            }
        }
        summary.total = self.entries.len() as u64;
        summary.dropped = self.total_dropped;
        summary
    }
}

impl Default for LogCollector {
    fn default() -> Self {
        Self::new(1000)
    }
}

/// Summary statistics from a log collector.
#[derive(Debug, Clone, Copy, Default)]
pub struct CollectorSummary {
    /// Total entries collected.
    pub total: u64,
    /// Entries dropped due to capacity.
    pub dropped: u64,
    /// Count of TRACE entries.
    pub trace_count: u64,
    /// Count of DEBUG entries.
    pub debug_count: u64,
    /// Count of INFO entries.
    pub info_count: u64,
    /// Count of WARN entries.
    pub warn_count: u64,
    /// Count of ERROR entries.
    pub error_count: u64,
}

impl CollectorSummary {
    /// Returns the count of entries at warn or error level.
    #[must_use]
    pub const fn issues(&self) -> u64 {
        self.warn_count + self.error_count
    }
}

impl fmt::Display for CollectorSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "total={} (T={} D={} I={} W={} E={}) dropped={}",
            self.total,
            self.trace_count,
            self.debug_count,
            self.info_count,
            self.warn_count,
            self.error_count,
            self.dropped
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collector_basic() {
        let mut collector = LogCollector::new(10);

        collector.collect(LogEntry::info("msg1"));
        collector.collect(LogEntry::warn("msg2"));

        assert_eq!(collector.len(), 2);
        assert_eq!(collector.total_received(), 2);
    }

    #[test]
    fn collector_level_filter() {
        let mut collector = LogCollector::new(10).with_min_level(LogLevel::Warn);

        collector.collect(LogEntry::debug("ignored"));
        collector.collect(LogEntry::info("ignored"));
        collector.collect(LogEntry::warn("collected"));
        collector.collect(LogEntry::error("collected"));

        assert_eq!(collector.len(), 2);
        assert_eq!(collector.total_received(), 4);
    }

    #[test]
    fn collector_target_filter() {
        let mut collector = LogCollector::new(10).with_target_filter("mymodule");

        collector.collect(LogEntry::info("no target"));
        collector.collect(LogEntry::info("with target").with_target("mymodule::sub"));
        collector.collect(LogEntry::info("wrong target").with_target("other"));

        assert_eq!(collector.len(), 1);
    }

    #[test]
    fn collector_capacity() {
        let mut collector = LogCollector::new(3);

        collector.collect(LogEntry::info("1"));
        collector.collect(LogEntry::info("2"));
        collector.collect(LogEntry::info("3"));
        collector.collect(LogEntry::info("4")); // Drops "1"

        assert_eq!(collector.len(), 3);
        assert_eq!(collector.total_dropped(), 1);

        let messages: Vec<_> = collector.entries().map(LogEntry::message).collect();
        assert_eq!(messages, vec!["2", "3", "4"]);
    }

    #[test]
    fn collector_entries_at_level() {
        let mut collector = LogCollector::new(10);
        collector.collect(LogEntry::info("i1"));
        collector.collect(LogEntry::warn("w1"));
        collector.collect(LogEntry::info("i2"));
        collector.collect(LogEntry::error("e1"));

        assert_eq!(collector.entries_at_level(LogLevel::Info).count(), 2);

        assert_eq!(collector.entries_at_least(LogLevel::Warn).count(), 2);
    }

    #[test]
    fn collector_drain() {
        let mut collector = LogCollector::new(10);
        collector.collect(LogEntry::info("msg"));

        let entries = collector.drain();
        assert_eq!(entries.len(), 1);
        assert!(collector.is_empty());
    }

    #[test]
    fn collector_format() {
        let mut collector = LogCollector::new(10);
        collector.collect(LogEntry::info("test message").with_field("key", "val"));

        let compact = collector.format_compact();
        assert!(compact.contains("[I]"));
        assert!(compact.contains("test message"));

        let jsonl = collector.format_jsonl();
        assert!(jsonl.contains("\"level\":\"info\""));
    }

    #[test]
    fn collector_summary() {
        let mut collector = LogCollector::new(10);
        collector.collect(LogEntry::trace("t"));
        collector.collect(LogEntry::debug("d"));
        collector.collect(LogEntry::info("i"));
        collector.collect(LogEntry::warn("w"));
        collector.collect(LogEntry::error("e"));

        let summary = collector.summary();
        assert_eq!(summary.total, 5);
        assert_eq!(summary.trace_count, 1);
        assert_eq!(summary.debug_count, 1);
        assert_eq!(summary.info_count, 1);
        assert_eq!(summary.warn_count, 1);
        assert_eq!(summary.error_count, 1);
        assert_eq!(summary.issues(), 2);
    }

    #[test]
    fn summary_display() {
        let summary = CollectorSummary {
            total: 10,
            dropped: 2,
            trace_count: 1,
            debug_count: 2,
            info_count: 3,
            warn_count: 2,
            error_count: 2,
        };
        let s = format!("{summary}");
        assert!(s.contains("total=10"));
        assert!(s.contains("dropped=2"));
    }
}
