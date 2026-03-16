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
const RESERVED_JSON_FIELDS: [&str; 4] = ["level", "timestamp_ns", "message", "target"];

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
    /// Fields are key-value pairs that provide context. Re-adding an existing
    /// key updates its value in place. If the maximum number of distinct fields
    /// is reached, additional keys are ignored.
    #[must_use]
    pub fn with_field(self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.insert_field(key, value, false)
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
    ///
    /// Core context fields are prioritized over pre-existing arbitrary fields so
    /// correlation identifiers survive the field budget enforced on each entry.
    #[must_use]
    pub fn with_context(mut self, ctx: &DiagnosticContext) -> Self {
        for (k, v) in ctx.custom_fields() {
            self = self.insert_field(k, v, true);
        }
        if let Some(task_id) = ctx.task_id() {
            self = self.insert_field("task_id", task_id.to_string(), true);
        }
        if let Some(region_id) = ctx.region_id() {
            self = self.insert_field("region_id", region_id.to_string(), true);
        }
        if let Some(span_id) = ctx.span_id() {
            self = self.insert_field("span_id", span_id.to_string(), true);
        }
        if let Some(parent_span_id) = ctx.parent_span_id() {
            self = self.insert_field("parent_span_id", parent_span_id.to_string(), true);
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
            if RESERVED_JSON_FIELDS.contains(&k.as_str()) {
                s.push_str("field.");
            }
            push_json_escaped(&mut s, k);
            s.push_str("\":\"");
            push_json_escaped(&mut s, v);
            s.push('"');
        }

        s.push('}');
        s
    }

    fn insert_field(
        mut self,
        key: impl Into<String>,
        value: impl Into<String>,
        prioritize: bool,
    ) -> Self {
        let key = key.into();
        let value = value.into();

        if let Some((_, existing_value)) = self
            .fields
            .iter_mut()
            .find(|(existing_key, _)| existing_key == &key)
        {
            *existing_value = value;
            return self;
        }

        if self.fields.len() < MAX_FIELDS {
            self.fields.push((key, value));
            return self;
        }

        if prioritize && !self.fields.is_empty() {
            self.fields.rotate_left(1);
            if let Some(slot) = self.fields.last_mut() {
                *slot = (key, value);
            }
        }

        self
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
    fn duplicate_field_updates_existing_value() {
        let entry = LogEntry::info("test")
            .with_field("attempt", "1")
            .with_field("attempt", "2");

        assert_eq!(entry.field_count(), 1);
        assert_eq!(entry.get_field("attempt"), Some("2"));
        let fields: Vec<_> = entry.fields().collect();
        assert_eq!(fields, vec![("attempt", "2")]);
    }

    #[test]
    fn json_reserved_field_names_are_namespaced() {
        let entry = LogEntry::info("real message")
            .with_target("real-target")
            .with_field("message", "field message")
            .with_field("level", "field level")
            .with_field("target", "field target")
            .with_field("timestamp_ns", "field timestamp");

        let json = entry.format_json();

        assert_eq!(json.matches("\"message\":").count(), 1);
        assert_eq!(json.matches("\"level\":").count(), 1);
        assert_eq!(json.matches("\"target\":").count(), 1);
        assert_eq!(json.matches("\"timestamp_ns\":").count(), 1);
        assert!(json.contains("\"field.message\":\"field message\""));
        assert!(json.contains("\"field.level\":\"field level\""));
        assert!(json.contains("\"field.target\":\"field target\""));
        assert!(json.contains("\"field.timestamp_ns\":\"field timestamp\""));
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

    #[test]
    fn entry_with_context_overrides_conflicting_fields() {
        let ctx = DiagnosticContext::new()
            .with_custom("request_id", "ctx-request")
            .with_custom("span.name", "ctx-span");

        let entry = LogEntry::info("hello")
            .with_field("request_id", "user-request")
            .with_field("span.name", "user-span")
            .with_context(&ctx);

        assert_eq!(entry.get_field("request_id"), Some("ctx-request"));
        assert_eq!(entry.get_field("span.name"), Some("ctx-span"));
        assert_eq!(
            entry.format_json().matches("\"request_id\":").count(),
            1,
            "request_id should only appear once in JSON output"
        );
    }

    #[test]
    fn entry_with_context_preserves_context_when_field_budget_is_full() {
        use crate::observability::SpanId;

        let mut entry = LogEntry::info("hello");
        for i in 0..MAX_FIELDS {
            entry = entry.with_field(format!("key{i}"), format!("value{i}"));
        }

        let ctx = DiagnosticContext::new()
            .with_span_id(SpanId::new())
            .with_custom("request_id", "abc123");

        let entry = entry.with_context(&ctx);

        assert_eq!(entry.field_count(), MAX_FIELDS);
        assert!(entry.get_field("span_id").is_some());
        assert_eq!(entry.get_field("request_id"), Some("abc123"));
        assert_eq!(entry.get_field("key0"), None);
        assert_eq!(entry.get_field("key1"), None);
    }

    #[test]
    fn entry_with_context_preserves_core_ids_when_context_overflows_budget() {
        use crate::observability::SpanId;
        use crate::types::{RegionId, TaskId};
        use crate::util::ArenaIndex;

        let mut ctx = DiagnosticContext::new()
            .with_task_id(TaskId::from_arena(ArenaIndex::new(7, 0)))
            .with_region_id(RegionId::from_arena(ArenaIndex::new(8, 0)))
            .with_span_id(SpanId::new());

        for i in 0..MAX_FIELDS {
            ctx = ctx.with_custom(format!("custom{i}"), format!("value{i}"));
        }

        let entry = LogEntry::info("hello").with_context(&ctx);

        assert_eq!(entry.field_count(), MAX_FIELDS);
        assert_eq!(entry.get_field("task_id"), Some("T7"));
        assert_eq!(entry.get_field("region_id"), Some("R8"));
        assert!(entry.get_field("span_id").is_some());
    }

    #[test]
    fn log_entry_debug_clone() {
        let e = LogEntry::info("hello world");
        let dbg = format!("{e:?}");
        assert!(!dbg.is_empty());
        let cloned = e;
        assert_eq!(format!("{cloned:?}"), dbg);
    }
}
