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
#[path = "collector_inline_tests.rs"]
mod tests;
