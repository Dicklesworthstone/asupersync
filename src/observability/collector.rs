//! In-memory log collector.
//!
//! Stores log entries in a ring buffer for retrieval and analysis.

use super::entry::LogEntry;
use super::level::LogLevel;
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::sync::Arc;

/// A thread-safe collector for log entries.
#[derive(Debug, Clone)]
pub struct LogCollector {
    inner: Arc<Mutex<CollectorInner>>,
}

#[derive(Debug)]
struct CollectorInner {
    entries: VecDeque<LogEntry>,
    capacity: usize,
    min_level: LogLevel,
}

impl LogCollector {
    /// Creates a new collector with default capacity (1000).
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(CollectorInner {
                entries: VecDeque::with_capacity(capacity),
                capacity,
                min_level: LogLevel::Info,
            })),
        }
    }

    /// Sets the minimum log level to record.
    #[must_use]
    pub fn with_min_level(self, level: LogLevel) -> Self {
        self.inner.lock().min_level = level;
        self
    }

    /// Logs an entry if it meets the minimum level.
    pub fn log(&self, entry: LogEntry) {
        let mut inner = self.inner.lock();
        if !entry.level().is_enabled_at(inner.min_level) {
            return;
        }
        if inner.capacity == 0 {
            return;
        }
        if inner.entries.len() >= inner.capacity {
            inner.entries.pop_front();
        }
        inner.entries.push_back(entry);
    }

    /// Drains all entries from the collector.
    #[must_use]
    pub fn drain(&self) -> Vec<LogEntry> {
        let mut inner = self.inner.lock();
        inner.entries.drain(..).collect()
    }

    /// Returns a copy of the current entries without clearing them.
    #[must_use]
    pub fn peek(&self) -> Vec<LogEntry> {
        let inner = self.inner.lock();
        inner.entries.iter().cloned().collect()
    }

    /// Clears the collector.
    pub fn clear(&self) {
        let mut inner = self.inner.lock();
        inner.entries.clear();
    }

    /// Returns the number of entries currently stored.
    #[must_use]
    pub fn len(&self) -> usize {
        let inner = self.inner.lock();
        inner.entries.len()
    }

    /// Returns true if the collector is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the configured capacity.
    #[must_use]
    pub fn capacity(&self) -> usize {
        let inner = self.inner.lock();
        inner.capacity
    }

    /// Returns the configured minimum level.
    #[must_use]
    pub fn min_level(&self) -> LogLevel {
        self.inner.lock().min_level
    }
}

impl Default for LogCollector {
    fn default() -> Self {
        Self::new(1000)
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    #[test]
    fn test_collector_captures_logs() {
        let collector = LogCollector::new(10).with_min_level(LogLevel::Debug);
        collector.log(LogEntry::info("test"));
        assert_eq!(collector.len(), 1);
        assert_eq!(collector.peek()[0].message(), "test");
    }

    #[test]
    fn test_collector_respects_level_filter() {
        let collector = LogCollector::new(10).with_min_level(LogLevel::Warn);
        collector.log(LogEntry::info("ignored"));
        collector.log(LogEntry::warn("captured"));
        assert_eq!(collector.len(), 1);
        assert_eq!(collector.peek()[0].message(), "captured");
    }

    #[test]
    fn test_collector_buffer_capacity() {
        let collector = LogCollector::new(2);
        collector.log(LogEntry::info("1"));
        collector.log(LogEntry::info("2"));
        collector.log(LogEntry::info("3")); // Should evict 1

        let entries = collector.peek();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].message(), "2");
        assert_eq!(entries[1].message(), "3");
    }

    #[test]
    fn test_collector_zero_capacity_drops_logs() {
        let collector = LogCollector::new(0);
        collector.log(LogEntry::info("dropped"));

        assert_eq!(collector.capacity(), 0);
        assert!(collector.is_empty());
        assert!(collector.peek().is_empty());
    }

    #[test]
    fn test_collector_drain_clears() {
        let collector = LogCollector::new(10);
        collector.log(LogEntry::info("msg"));

        let drained = collector.drain();
        assert_eq!(drained.len(), 1);
        assert_eq!(collector.len(), 0);
    }

    #[test]
    fn test_collector_peek_does_not_clear() {
        let collector = LogCollector::new(10);
        collector.log(LogEntry::info("msg"));

        let peeked = collector.peek();
        assert_eq!(peeked.len(), 1);
        assert_eq!(collector.len(), 1);
    }

    #[test]
    fn test_collector_thread_safe() {
        let collector = LogCollector::new(100);
        let c1 = collector.clone();

        std::thread::spawn(move || {
            c1.log(LogEntry::info("thread"));
        })
        .join()
        .unwrap();

        assert_eq!(collector.len(), 1);
    }

    #[test]
    fn test_collector_clone_shares_min_level_configuration() {
        let collector = LogCollector::new(10).with_min_level(LogLevel::Error);
        let clone = collector.clone().with_min_level(LogLevel::Warn);

        assert_eq!(collector.min_level(), LogLevel::Warn);
        collector.log(LogEntry::warn("captured"));

        assert_eq!(clone.len(), 1);
        assert_eq!(clone.peek()[0].message(), "captured");
    }
}
