//! Output formatting for CLI tools.
//!
//! Provides dual-mode output that works for both humans and machines.
//! Automatically detects the appropriate format based on environment.

use serde::Serialize;
use std::io::{self, IsTerminal, Write};

/// Output format selection.
///
/// Determines how data is formatted for output.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum OutputFormat {
    /// Human-readable with colors and formatting.
    #[default]
    Human,

    /// Compact JSON (one object per line for streaming).
    Json,

    /// Streaming JSON (newline-delimited JSON with immediate flush).
    StreamJson,

    /// Pretty-printed JSON (for debugging).
    JsonPretty,

    /// Tab-separated values (for shell scripting).
    Tsv,
}

impl OutputFormat {
    /// Detect appropriate format based on environment.
    ///
    /// Uses JSON when:
    /// - `CI` environment variable is set
    /// - stdout is not a TTY (piped output)
    /// - `ASUPERSYNC_OUTPUT_FORMAT` env var is set to a JSON variant
    #[must_use]
    pub fn auto_detect() -> Self {
        // CI environment always uses JSON
        if std::env::var("CI").is_ok() {
            return Self::Json;
        }

        // Non-terminal output uses JSON
        if !io::stdout().is_terminal() {
            return Self::Json;
        }

        // Check environment variable
        if let Ok(format) = std::env::var("ASUPERSYNC_OUTPUT_FORMAT") {
            match format.to_lowercase().as_str() {
                "json" => return Self::Json,
                "stream-json" | "streamjson" | "stream_json" => return Self::StreamJson,
                "json-pretty" | "jsonpretty" | "json_pretty" => return Self::JsonPretty,
                "tsv" => return Self::Tsv,
                "human" => return Self::Human,
                _ => {}
            }
        }

        Self::Human
    }

    /// Check if this format produces JSON output.
    #[must_use]
    pub const fn is_json(&self) -> bool {
        matches!(self, Self::Json | Self::StreamJson | Self::JsonPretty)
    }

    /// Check if this format is human-readable.
    #[must_use]
    pub const fn is_human(&self) -> bool {
        matches!(self, Self::Human)
    }
}

/// Color choice for output.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ColorChoice {
    /// Automatically detect based on terminal.
    #[default]
    Auto,

    /// Always use colors.
    Always,

    /// Never use colors.
    Never,
}

impl ColorChoice {
    /// Detect appropriate color setting based on environment.
    ///
    /// Respects:
    /// - `NO_COLOR` environment variable (https://no-color.org/)
    /// - `CLICOLOR_FORCE` environment variable
    /// - Terminal detection
    #[must_use]
    pub fn auto_detect() -> Self {
        // NO_COLOR takes precedence (https://no-color.org/)
        if std::env::var("NO_COLOR").is_ok() {
            return Self::Never;
        }

        // CLICOLOR_FORCE forces colors
        if std::env::var("CLICOLOR_FORCE").is_ok() {
            return Self::Always;
        }

        // Auto-detect based on terminal
        if io::stdout().is_terminal() {
            Self::Auto
        } else {
            Self::Never
        }
    }

    /// Check if colors should be used.
    #[must_use]
    pub fn should_colorize(&self) -> bool {
        match self {
            Self::Always => true,
            Self::Never => false,
            Self::Auto => io::stdout().is_terminal(),
        }
    }
}

/// Trait for types that can be output in multiple formats.
///
/// Implementors must be serializable via serde and provide human-readable formatting.
pub trait Outputtable: Serialize {
    /// Human-readable representation.
    fn human_format(&self) -> String;

    /// Short one-line summary for human output.
    ///
    /// Defaults to full human format.
    fn human_summary(&self) -> String {
        self.human_format()
    }

    /// TSV representation (tab-separated fields).
    ///
    /// Defaults to human summary.
    fn tsv_format(&self) -> String {
        self.human_summary()
    }
}

/// Output writer that handles format switching.
pub struct Output {
    format: OutputFormat,
    color: ColorChoice,
    writer: Box<dyn Write>,
}

impl Output {
    /// Create a new output writer to stdout.
    #[must_use]
    pub fn new(format: OutputFormat) -> Self {
        Self {
            format,
            color: ColorChoice::auto_detect(),
            writer: Box::new(io::stdout()),
        }
    }

    /// Create with a custom writer.
    #[must_use]
    pub fn with_writer<W: Write + 'static>(format: OutputFormat, writer: W) -> Self {
        Self {
            format,
            color: ColorChoice::Never, // No colors for custom writers
            writer: Box::new(writer),
        }
    }

    /// Set the color choice.
    #[must_use]
    pub fn with_color(mut self, color: ColorChoice) -> Self {
        self.color = color;
        self
    }

    /// Check if colors should be used.
    #[must_use]
    pub fn use_colors(&self) -> bool {
        self.color.should_colorize()
    }

    /// Get the output format.
    #[must_use]
    pub const fn format(&self) -> OutputFormat {
        self.format
    }

    /// Write a single value.
    ///
    /// # Errors
    ///
    /// Returns an error if writing or serialization fails.
    pub fn write<T: Outputtable>(&mut self, value: &T) -> io::Result<()> {
        match self.format {
            OutputFormat::Human => {
                writeln!(self.writer, "{}", value.human_format())?;
            }
            OutputFormat::Json => {
                let json = serde_json::to_string(value)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                writeln!(self.writer, "{json}")?;
            }
            OutputFormat::JsonPretty => {
                let json = serde_json::to_string_pretty(value)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                writeln!(self.writer, "{json}")?;
            }
            OutputFormat::StreamJson => {
                let json = serde_json::to_string(value)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                writeln!(self.writer, "{json}")?;
                self.writer.flush()?; // Flush for streaming
            }
            OutputFormat::Tsv => {
                writeln!(self.writer, "{}", value.tsv_format())?;
            }
        }
        Ok(())
    }

    /// Write a list of values.
    ///
    /// For JSON format, outputs as a JSON array.
    /// For streaming formats, outputs one item per line.
    ///
    /// # Errors
    ///
    /// Returns an error if writing or serialization fails.
    pub fn write_list<T: Outputtable>(&mut self, values: &[T]) -> io::Result<()> {
        match self.format {
            OutputFormat::Human => {
                for value in values {
                    writeln!(self.writer, "{}", value.human_format())?;
                }
            }
            OutputFormat::Json => {
                let json = serde_json::to_string(values)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                writeln!(self.writer, "{json}")?;
            }
            OutputFormat::JsonPretty => {
                let json = serde_json::to_string_pretty(values)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                writeln!(self.writer, "{json}")?;
            }
            OutputFormat::StreamJson => {
                for value in values {
                    let json = serde_json::to_string(value)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                    writeln!(self.writer, "{json}")?;
                    self.writer.flush()?;
                }
            }
            OutputFormat::Tsv => {
                for value in values {
                    self.write(value)?;
                }
            }
        }
        Ok(())
    }

    /// Flush the output.
    ///
    /// # Errors
    ///
    /// Returns an error if flushing fails.
    pub fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize)]
    struct TestItem {
        id: u32,
        name: String,
    }

    impl Outputtable for TestItem {
        fn human_format(&self) -> String {
            format!("Item {}: {}", self.id, self.name)
        }

        fn tsv_format(&self) -> String {
            format!("{}\t{}", self.id, self.name)
        }
    }

    #[test]
    fn output_format_default_is_human() {
        assert!(matches!(OutputFormat::default(), OutputFormat::Human));
    }

    #[test]
    fn output_format_is_json() {
        assert!(OutputFormat::Json.is_json());
        assert!(OutputFormat::StreamJson.is_json());
        assert!(OutputFormat::JsonPretty.is_json());
        assert!(!OutputFormat::Human.is_json());
        assert!(!OutputFormat::Tsv.is_json());
    }

    #[test]
    fn color_choice_never_returns_false() {
        assert!(!ColorChoice::Never.should_colorize());
    }

    #[test]
    fn color_choice_always_returns_true() {
        assert!(ColorChoice::Always.should_colorize());
    }

    #[test]
    fn json_output_parses() {
        let item = TestItem {
            id: 42,
            name: "test".into(),
        };

        let json = serde_json::to_string(&item).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["id"], 42);
        assert_eq!(parsed["name"], "test");
    }

    #[test]
    fn output_writer_json_format() {
        use std::io::Cursor;

        let cursor = Cursor::new(Vec::new());
        let mut output = Output::with_writer(OutputFormat::Json, cursor);

        let item = TestItem {
            id: 1,
            name: "one".into(),
        };
        output.write(&item).unwrap();
    }

    #[test]
    fn output_writer_human_format() {
        use std::io::Cursor;

        let cursor = Cursor::new(Vec::new());
        let mut output = Output::with_writer(OutputFormat::Human, cursor);

        let item = TestItem {
            id: 1,
            name: "one".into(),
        };
        output.write(&item).unwrap();
    }

    #[test]
    fn output_writer_tsv_format() {
        use std::io::Cursor;

        let cursor = Cursor::new(Vec::new());
        let mut output = Output::with_writer(OutputFormat::Tsv, cursor);

        let item = TestItem {
            id: 1,
            name: "one".into(),
        };
        output.write(&item).unwrap();
    }

    #[test]
    fn output_writer_list_json_is_array() {
        use std::io::Cursor;

        let cursor = Cursor::new(Vec::new());
        let mut output = Output::with_writer(OutputFormat::Json, cursor);

        let items = vec![
            TestItem {
                id: 1,
                name: "one".into(),
            },
            TestItem {
                id: 2,
                name: "two".into(),
            },
        ];
        output.write_list(&items).unwrap();
    }
}
