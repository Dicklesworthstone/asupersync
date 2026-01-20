//! Progress reporting for CLI tools.
//!
//! Provides streaming progress updates that work for both human and machine consumers.
//! Automatically formats based on output mode.

use serde::Serialize;
use std::io::{self, Write};
use std::time::{Duration, Instant};

use super::output::{ColorChoice, OutputFormat};

/// Progress update types.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgressKind {
    /// Operation started.
    Started,

    /// Progress update with percentage or count.
    Update,

    /// Operation completed successfully.
    Completed,

    /// Operation failed.
    Failed,

    /// Operation was cancelled.
    Cancelled,
}

/// A progress update event.
#[derive(Clone, Debug, Serialize)]
pub struct ProgressEvent {
    /// Type of progress event.
    pub kind: ProgressKind,

    /// Current item or step (0-indexed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current: Option<u64>,

    /// Total items or steps.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<u64>,

    /// Human-readable message.
    pub message: String,

    /// Elapsed time in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elapsed_ms: Option<u64>,

    /// Operation name/identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
}

impl ProgressEvent {
    /// Create a new started event.
    #[must_use]
    pub fn started(message: impl Into<String>) -> Self {
        Self {
            kind: ProgressKind::Started,
            current: None,
            total: None,
            message: message.into(),
            elapsed_ms: None,
            operation: None,
        }
    }

    /// Create a new update event.
    #[must_use]
    pub fn update(current: u64, total: u64, message: impl Into<String>) -> Self {
        Self {
            kind: ProgressKind::Update,
            current: Some(current),
            total: Some(total),
            message: message.into(),
            elapsed_ms: None,
            operation: None,
        }
    }

    /// Create a completed event.
    #[must_use]
    pub fn completed(message: impl Into<String>) -> Self {
        Self {
            kind: ProgressKind::Completed,
            current: None,
            total: None,
            message: message.into(),
            elapsed_ms: None,
            operation: None,
        }
    }

    /// Create a failed event.
    #[must_use]
    pub fn failed(message: impl Into<String>) -> Self {
        Self {
            kind: ProgressKind::Failed,
            current: None,
            total: None,
            message: message.into(),
            elapsed_ms: None,
            operation: None,
        }
    }

    /// Create a cancelled event.
    #[must_use]
    pub fn cancelled(message: impl Into<String>) -> Self {
        Self {
            kind: ProgressKind::Cancelled,
            current: None,
            total: None,
            message: message.into(),
            elapsed_ms: None,
            operation: None,
        }
    }

    /// Set the operation name.
    #[must_use]
    pub fn operation(mut self, name: impl Into<String>) -> Self {
        self.operation = Some(name.into());
        self
    }

    /// Set elapsed time.
    #[must_use]
    pub const fn elapsed(mut self, duration: Duration) -> Self {
        self.elapsed_ms = Some(duration.as_millis() as u64);
        self
    }

    /// Calculate percentage if current and total are set.
    #[must_use]
    #[allow(clippy::cast_precision_loss)] // Precision loss acceptable for percentage display
    pub fn percentage(&self) -> Option<f64> {
        match (self.current, self.total) {
            (Some(current), Some(total)) if total > 0 => {
                Some((current as f64 / total as f64) * 100.0)
            }
            _ => None,
        }
    }
}

/// Progress reporter that handles output formatting.
pub struct ProgressReporter {
    format: OutputFormat,
    color: ColorChoice,
    start_time: Instant,
    writer: Box<dyn Write>,
    operation: Option<String>,
    last_line_length: usize,
}

impl ProgressReporter {
    /// Create a new progress reporter.
    #[must_use]
    pub fn new(format: OutputFormat) -> Self {
        Self {
            format,
            color: ColorChoice::auto_detect(),
            start_time: Instant::now(),
            writer: Box::new(io::stderr()),
            operation: None,
            last_line_length: 0,
        }
    }

    /// Create with a custom writer.
    #[must_use]
    pub fn with_writer<W: Write + 'static>(format: OutputFormat, writer: W) -> Self {
        Self {
            format,
            color: ColorChoice::Never,
            start_time: Instant::now(),
            writer: Box::new(writer),
            operation: None,
            last_line_length: 0,
        }
    }

    /// Set the operation name.
    #[must_use]
    pub fn operation(mut self, name: impl Into<String>) -> Self {
        self.operation = Some(name.into());
        self
    }

    /// Set color choice.
    #[must_use]
    pub fn with_color(mut self, color: ColorChoice) -> Self {
        self.color = color;
        self
    }

    /// Report a progress event.
    ///
    /// # Errors
    ///
    /// Returns an error if writing fails.
    pub fn report(&mut self, mut event: ProgressEvent) -> io::Result<()> {
        // Add operation if not set on event
        if event.operation.is_none() {
            event.operation = self.operation.clone();
        }

        // Add elapsed time
        event.elapsed_ms = Some(self.start_time.elapsed().as_millis() as u64);

        match self.format {
            OutputFormat::Human => self.report_human(&event),
            OutputFormat::Json | OutputFormat::StreamJson => self.report_json(&event),
            OutputFormat::JsonPretty => self.report_json_pretty(&event),
            OutputFormat::Tsv => self.report_tsv(&event),
        }
    }

    /// Report for human consumption.
    fn report_human(&mut self, event: &ProgressEvent) -> io::Result<()> {
        let use_color = self.color.should_colorize();

        // Clear previous line for updates (carriage return)
        if event.kind == ProgressKind::Update && self.last_line_length > 0 {
            write!(self.writer, "\r{}\r", " ".repeat(self.last_line_length))?;
        }

        let mut line = String::new();

        // Status indicator with color
        let (indicator, color_code) = match event.kind {
            ProgressKind::Started => ("▶", "\x1b[34m"),    // Blue
            ProgressKind::Update => ("⋯", "\x1b[33m"),     // Yellow
            ProgressKind::Completed => ("✓", "\x1b[32m"),  // Green
            ProgressKind::Failed => ("✗", "\x1b[31m"),     // Red
            ProgressKind::Cancelled => ("⊘", "\x1b[33m"),  // Yellow
        };

        if use_color {
            line.push_str(color_code);
        }
        line.push_str(indicator);
        if use_color {
            line.push_str("\x1b[0m");
        }
        line.push(' ');

        // Progress bar for updates
        if let Some(pct) = event.percentage() {
            use std::fmt::Write;
            let bar_width: usize = 20;
            // Percentage is always 0-100, so filled will always be 0-20
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss, clippy::cast_precision_loss)]
            let filled = ((pct / 100.0) * bar_width as f64) as usize;
            let empty = bar_width - filled;

            line.push('[');
            if use_color {
                line.push_str("\x1b[32m");
            }
            line.push_str(&"█".repeat(filled));
            if use_color {
                line.push_str("\x1b[0m");
            }
            line.push_str(&"░".repeat(empty));
            let _ = write!(line, "] {pct:.1}% ");
        }

        // Message
        line.push_str(&event.message);

        // Elapsed time for completion/failure
        if matches!(
            event.kind,
            ProgressKind::Completed | ProgressKind::Failed | ProgressKind::Cancelled
        ) {
            if let Some(ms) = event.elapsed_ms {
                use std::fmt::Write;
                if use_color {
                    line.push_str("\x1b[2m");
                }
                #[allow(clippy::cast_precision_loss)] // Acceptable for duration display
                let secs = ms as f64 / 1000.0;
                let _ = write!(line, " ({secs:.2}s)");
                if use_color {
                    line.push_str("\x1b[0m");
                }
            }
        }

        self.last_line_length = line.len();

        // Use newline for terminal states, just carriage return for updates
        if event.kind == ProgressKind::Update {
            write!(self.writer, "{line}")?;
        } else {
            writeln!(self.writer, "{line}")?;
        }

        self.writer.flush()
    }

    /// Report as JSON.
    fn report_json(&mut self, event: &ProgressEvent) -> io::Result<()> {
        let json = serde_json::to_string(event)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        writeln!(self.writer, "{json}")?;
        self.writer.flush()
    }

    /// Report as pretty JSON.
    fn report_json_pretty(&mut self, event: &ProgressEvent) -> io::Result<()> {
        let json = serde_json::to_string_pretty(event)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        writeln!(self.writer, "{json}")?;
        self.writer.flush()
    }

    /// Report as TSV.
    fn report_tsv(&mut self, event: &ProgressEvent) -> io::Result<()> {
        let pct = event
            .percentage()
            .map_or_else(|| "-".to_string(), |p| format!("{p:.1}"));
        let elapsed = event
            .elapsed_ms
            .map_or_else(|| "-".to_string(), |ms| ms.to_string());

        writeln!(
            self.writer,
            "{:?}\t{}\t{}\t{}",
            event.kind, pct, elapsed, event.message
        )?;
        self.writer.flush()
    }

    /// Report that an operation has started.
    ///
    /// # Errors
    ///
    /// Returns an error if writing fails.
    pub fn start(&mut self, message: impl Into<String>) -> io::Result<()> {
        self.start_time = Instant::now();
        self.report(ProgressEvent::started(message))
    }

    /// Report a progress update.
    ///
    /// # Errors
    ///
    /// Returns an error if writing fails.
    pub fn update(&mut self, current: u64, total: u64, message: impl Into<String>) -> io::Result<()> {
        self.report(ProgressEvent::update(current, total, message))
    }

    /// Report completion.
    ///
    /// # Errors
    ///
    /// Returns an error if writing fails.
    pub fn complete(&mut self, message: impl Into<String>) -> io::Result<()> {
        self.report(ProgressEvent::completed(message))
    }

    /// Report failure.
    ///
    /// # Errors
    ///
    /// Returns an error if writing fails.
    pub fn fail(&mut self, message: impl Into<String>) -> io::Result<()> {
        self.report(ProgressEvent::failed(message))
    }

    /// Report cancellation.
    ///
    /// # Errors
    ///
    /// Returns an error if writing fails.
    pub fn cancel(&mut self, message: impl Into<String>) -> io::Result<()> {
        self.report(ProgressEvent::cancelled(message))
    }

    /// Get elapsed time since start.
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.start_time.elapsed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_event_percentage() {
        let event = ProgressEvent::update(50, 100, "test");
        assert_eq!(event.percentage(), Some(50.0));

        let event = ProgressEvent::update(25, 100, "test");
        assert_eq!(event.percentage(), Some(25.0));

        let event = ProgressEvent::started("test");
        assert_eq!(event.percentage(), None);

        let event = ProgressEvent::update(0, 0, "test");
        assert_eq!(event.percentage(), None);
    }

    #[test]
    fn progress_event_serializes() {
        let event = ProgressEvent::update(5, 10, "Processing")
            .operation("sync")
            .elapsed(Duration::from_millis(1500));

        let json = serde_json::to_string(&event).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["kind"], "update");
        assert_eq!(parsed["current"], 5);
        assert_eq!(parsed["total"], 10);
        assert_eq!(parsed["message"], "Processing");
        assert_eq!(parsed["operation"], "sync");
        assert_eq!(parsed["elapsed_ms"], 1500);
    }

    #[test]
    fn progress_reporter_json_output() {
        use std::io::Cursor;

        let cursor = Cursor::new(Vec::new());
        let mut reporter =
            ProgressReporter::with_writer(OutputFormat::Json, cursor).operation("test");

        reporter.start("Starting").unwrap();
    }

    #[test]
    fn progress_reporter_tracks_elapsed() {
        let reporter = ProgressReporter::new(OutputFormat::Human);
        std::thread::sleep(Duration::from_millis(10));
        assert!(reporter.elapsed().as_millis() >= 10);
    }

    #[test]
    fn progress_kind_serializes_snake_case() {
        let json = serde_json::to_string(&ProgressKind::Started).unwrap();
        assert_eq!(json, "\"started\"");

        let json = serde_json::to_string(&ProgressKind::Completed).unwrap();
        assert_eq!(json, "\"completed\"");
    }
}
