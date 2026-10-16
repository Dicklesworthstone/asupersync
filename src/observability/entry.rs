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
const FIELD_NAMESPACE_PREFIX: &str = "field.";
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
            push_json_escaped(&mut s, &json_field_key(k));
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

fn json_field_key(key: &str) -> String {
    if json_field_key_needs_namespace(key) {
        format!("{FIELD_NAMESPACE_PREFIX}{key}")
    } else {
        key.to_owned()
    }
}

fn json_field_key_needs_namespace(key: &str) -> bool {
    if RESERVED_JSON_FIELDS.contains(&key) {
        return true;
    }

    let mut suffix = key;
    let mut had_namespace = false;
    while let Some(rest) = suffix.strip_prefix(FIELD_NAMESPACE_PREFIX) {
        suffix = rest;
        had_namespace = true;
    }

    had_namespace && RESERVED_JSON_FIELDS.contains(&suffix)
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
#[path = "entry_inline_tests.rs"]
mod tests;
