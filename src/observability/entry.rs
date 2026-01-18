//! Structured log entries.
//!
//! Log entries combine a message, severity level, timestamp, and
//! structured key-value fields for rich, queryable logging.

use super::context::DiagnosticContext;
use super::level::LogLevel;
use crate::types::Time;
use core::fmt;
use core::fmt::Write;

/// Maximum number of fields in a log entry (to bound memory).
const MAX_FIELDS: usize = 16;

/// A structured log entry with message, level, and contextual fields.
///
/// Log entries are immutable once created. Use the builder pattern
/// to construct entries with fields.
///
/// # Example
///
/// ```ignore
/// let entry = LogEntry::info("Operation completed")
///     .with_field("duration_ms", "42")
///     .with_field("items_processed", "100");
/// ```
#[derive(Clone)]
pub struct LogEntry {
    /// The log level.
    level: LogLevel,
    /// The log message.
    message: String,
    /// Timestamp when the entry was created.
    timestamp: Time,
    /// Structured fields (key-value pairs).
    fields: Vec<(String, String)>,
    /// Optional target/module name.
    target: Option<String>,
}

impl LogEntry {
    /// Creates a new log entry with the given level and message.
    #[must_use]
    pub fn new(level: LogLevel, message: impl Into<String>) -> Self {
        Self {
            level,
            message: message.into(),
            timestamp: Time::ZERO,
            fields: Vec::new(),
            target: None,
        }
    }

    /// Creates a TRACE level entry.
    #[must_use]
    pub fn trace(message: impl Into<String>) -> Self {
        Self::new(LogLevel::Trace, message)
    }

    /// Creates a DEBUG level entry.
    #[must_use]
    pub fn debug(message: impl Into<String>) -> Self {
        Self::new(LogLevel::Debug, message)
    }

    /// Creates an INFO level entry.
    #[must_use]
    pub fn info(message: impl Into<String>) -> Self {
        Self::new(LogLevel::Info, message)
    }

    /// Creates a WARN level entry.
    #[must_use]
    pub fn warn(message: impl Into<String>) -> Self {
        Self::new(LogLevel::Warn, message)
    }

    /// Creates an ERROR level entry.
    #[must_use]
    pub fn error(message: impl Into<String>) -> Self {
        Self::new(LogLevel::Error, message)
    }

    /// Adds a structured field to the entry.
    ///
    /// Fields are key-value pairs that provide context. If the maximum
    /// number of fields is reached, additional fields are ignored.
    #[must_use]
    pub fn with_field(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        if self.fields.len() < MAX_FIELDS {
            self.fields.push((key.into(), value.into()));
        }
        self
    }

    /// Sets the timestamp for the entry.
    #[must_use]
    pub fn with_timestamp(mut self, timestamp: Time) -> Self {
        self.timestamp = timestamp;
        self
    }

    /// Sets the target/module name for the entry.
    #[must_use]
    pub fn with_target(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self
    }

    /// Adds diagnostic context fields to the entry.
    #[must_use]
    pub fn with_context(mut self, ctx: &DiagnosticContext) -> Self {
        if let Some(task_id) = ctx.task_id() {
            self = self.with_field("task_id", task_id.to_string());
        }
        if let Some(region_id) = ctx.region_id() {
            self = self.with_field("region_id", region_id.to_string());
        }
        if let Some(span_id) = ctx.span_id() {
            self = self.with_field("span_id", span_id.to_string());
        }
        if let Some(parent_span_id) = ctx.parent_span_id() {
            self = self.with_field("parent_span_id", parent_span_id.to_string());
        }
        for (k, v) in ctx.custom_fields() {
            self = self.with_field(k, v);
        }
        self
    }

    /// Returns the log level.
    #[must_use]
    pub const fn level(&self) -> LogLevel {
        self.level
    }

    /// Returns the log message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Returns the timestamp.
    #[must_use]
    pub const fn timestamp(&self) -> Time {
        self.timestamp
    }

    /// Returns the target/module name, if set.
    #[must_use]
    pub fn target(&self) -> Option<&str> {
        self.target.as_deref()
    }

    /// Returns an iterator over the fields.
    pub fn fields(&self) -> impl Iterator<Item = (&str, &str)> {
        self.fields.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// Returns the number of fields.
    #[must_use]
    pub fn field_count(&self) -> usize {
        self.fields.len()
    }

    /// Gets a field value by key.
    #[must_use]
    pub fn get_field(&self, key: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// Formats the entry as a single-line string (for compact output).
    #[must_use]
    pub fn format_compact(&self) -> String {
        let mut s = format!("[{}] {}", self.level.as_char(), self.message);
        if !self.fields.is_empty() {
            s.push_str(" {");
            for (i, (k, v)) in self.fields.iter().enumerate() {
                if i > 0 {
                    s.push_str(", ");
                }
                s.push_str(k);
                s.push('=');
                s.push_str(v);
            }
            s.push('}');
        }
        s
    }

    /// Formats the entry as JSON (for structured logging pipelines).
    #[must_use]
    pub fn format_json(&self) -> String {
        let mut s = String::from("{");

        s.push_str("\"level\":\"");
        s.push_str(self.level.as_str_lower());
        s.push_str("\",\"timestamp_ns\":");
        s.push_str(&self.timestamp.as_nanos().to_string());
        s.push_str(",\"message\":\"");
        push_json_escaped(&mut s, &self.message);
        s.push('"');

        if let Some(ref target) = self.target {
            s.push_str(",\"target\":\"");
            push_json_escaped(&mut s, target);
            s.push('"');
        }

        for (k, v) in &self.fields {
            s.push_str(",\"");
            push_json_escaped(&mut s, k);
            s.push_str("\":\"");
            push_json_escaped(&mut s, v);
            s.push('"');
        }

        s.push('}');
        s
    }
}

fn push_json_escaped(out: &mut String, value: &str) {
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0C}' => out.push_str("\\f"),
            c if c <= '\u{1F}' => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
}

impl fmt::Debug for LogEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LogEntry")
            .field("level", &self.level)
            .field("message", &self.message)
            .field("timestamp", &self.timestamp)
            .field("target", &self.target)
            .field("fields", &self.fields.len())
            .finish()
    }
}

impl fmt::Display for LogEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.format_compact())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_entries() {
        let trace = LogEntry::trace("trace msg");
        assert_eq!(trace.level(), LogLevel::Trace);

        let info = LogEntry::info("info msg");
        assert_eq!(info.level(), LogLevel::Info);
        assert_eq!(info.message(), "info msg");

        let error = LogEntry::error("error msg");
        assert_eq!(error.level(), LogLevel::Error);
    }

    #[test]
    fn entry_with_fields() {
        let entry = LogEntry::info("test")
            .with_field("key1", "value1")
            .with_field("key2", "value2")
            .with_timestamp(Time::from_millis(100));

        assert_eq!(entry.field_count(), 2);
        assert_eq!(entry.get_field("key1"), Some("value1"));
        assert_eq!(entry.get_field("key2"), Some("value2"));
        assert_eq!(entry.get_field("missing"), None);
        assert_eq!(entry.timestamp(), Time::from_millis(100));
    }

    #[test]
    fn entry_with_target() {
        let entry = LogEntry::info("test").with_target("my_module");
        assert_eq!(entry.target(), Some("my_module"));
    }

    #[test]
    fn format_compact() {
        let entry = LogEntry::info("Hello world")
            .with_field("foo", "bar")
            .with_field("baz", "42");

        let compact = entry.format_compact();
        assert!(compact.contains("[I]"));
        assert!(compact.contains("Hello world"));
        assert!(compact.contains("foo=bar"));
        assert!(compact.contains("baz=42"));
    }

    #[test]
    fn format_json() {
        let entry = LogEntry::warn("Test message")
            .with_field("count", "5")
            .with_timestamp(Time::from_millis(1000));

        let json = entry.format_json();
        assert!(json.contains("\"level\":\"warn\""));
        assert!(json.contains("\"message\":\"Test message\""));
        assert!(json.contains("\"count\":\"5\""));
        assert!(json.contains("\"timestamp_ns\":1000000000"));
    }

    #[test]
    fn json_escaping() {
        let entry = LogEntry::info("Message with \"quotes\" and \\ backslash");
        let json = entry.format_json();
        assert!(json.contains("\\\"quotes\\\""));
        assert!(json.contains("\\\\"));
    }

    #[test]
    fn json_escaping_fields_and_target() {
        let entry = LogEntry::info("msg")
            .with_target("mod\"name")
            .with_field("k\"ey", "v\\al\n");
        let json = entry.format_json();
        assert!(json.contains("\"target\":\"mod\\\"name\""));
        assert!(json.contains("\"k\\\"ey\":\"v\\\\al\\n\""));
    }

    #[test]
    fn max_fields_limit() {
        let mut entry = LogEntry::info("test");
        for i in 0..20 {
            entry = entry.with_field(format!("key{i}"), format!("val{i}"));
        }
        assert_eq!(entry.field_count(), MAX_FIELDS);
    }

    #[test]
    fn fields_iterator() {
        let entry = LogEntry::info("test")
            .with_field("a", "1")
            .with_field("b", "2");

        let fields: Vec<_> = entry.fields().collect();
        assert_eq!(fields, vec![("a", "1"), ("b", "2")]);
    }

    #[test]
    fn entry_with_context() {
        use crate::observability::SpanId;
        use crate::types::{RegionId, TaskId};
        use crate::util::ArenaIndex;

        let ctx = DiagnosticContext::new()
            .with_task_id(TaskId::from_arena(ArenaIndex::new(3, 0)))
            .with_region_id(RegionId::from_arena(ArenaIndex::new(2, 0)))
            .with_span_id(SpanId::new())
            .with_custom("request_id", "abc123");

        let entry = LogEntry::info("hello").with_context(&ctx);

        assert_eq!(entry.get_field("task_id"), Some("T3"));
        assert_eq!(entry.get_field("region_id"), Some("R2"));
        assert!(entry.get_field("span_id").is_some());
        assert_eq!(entry.get_field("request_id"), Some("abc123"));
    }
}
