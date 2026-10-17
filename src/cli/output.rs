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
    /// Detect appropriate color setting for a specific output stream.
    ///
    /// Respects:
    /// - `NO_COLOR` environment variable (<https://no-color.org/>)
    /// - `CLICOLOR_FORCE` environment variable
    /// - The target stream's terminal state
    #[must_use]
    pub fn auto_detect_for(target_is_terminal: bool) -> Self {
        // NO_COLOR takes precedence (https://no-color.org/)
        if std::env::var("NO_COLOR").is_ok() {
            return Self::Never;
        }

        // CLICOLOR_FORCE forces colors
        if std::env::var("CLICOLOR_FORCE").is_ok() {
            return Self::Always;
        }

        if target_is_terminal {
            Self::Auto
        } else {
            Self::Never
        }
    }

    /// Detect appropriate color setting based on environment.
    ///
    /// Respects:
    /// - `NO_COLOR` environment variable (<https://no-color.org/>)
    /// - `CLICOLOR_FORCE` environment variable
    /// - Terminal detection
    #[must_use]
    pub fn auto_detect() -> Self {
        Self::auto_detect_for(io::stdout().is_terminal())
    }

    /// Check if colors should be used.
    #[must_use]
    pub fn should_colorize(&self) -> bool {
        self.should_colorize_for(io::stdout().is_terminal())
    }

    /// Check if colors should be used for a specific output stream.
    #[must_use]
    pub const fn should_colorize_for(&self, target_is_terminal: bool) -> bool {
        match self {
            Self::Always => true,
            Self::Never => false,
            Self::Auto => target_is_terminal,
        }
    }
}

/// Trait for types that can be output in multiple formats.
///
/// Implementors must be serializable via serde and provide human-readable formatting.
pub trait Outputtable: Serialize {
    /// JSON representation for machine-readable output.
    ///
    /// Defaults to serde serialization. Implementors can override this when the
    /// stable CLI JSON shape intentionally differs from the internal Rust
    /// wrapper type.
    fn json(&self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::to_value(self)
    }

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
    writer: Box<dyn Write + Send>,
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
    pub fn with_writer<W: Write + Send + 'static>(format: OutputFormat, writer: W) -> Self {
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
                let json = render_json(value, false)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                writeln!(self.writer, "{json}")?;
            }
            OutputFormat::JsonPretty => {
                let json = render_json(value, true)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                writeln!(self.writer, "{json}")?;
            }
            OutputFormat::StreamJson => {
                let json = render_json(value, false)
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
                let json = render_json_list(values, false)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                writeln!(self.writer, "{json}")?;
            }
            OutputFormat::JsonPretty => {
                let json = render_json_list(values, true)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                writeln!(self.writer, "{json}")?;
            }
            OutputFormat::StreamJson => {
                for value in values {
                    let json = render_json(value, false)
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

/// Renders `value` as JSON text for the machine-readable formats.
///
/// When [`Outputtable::json`] yields exactly the serde value of `value` (the
/// default, or an override that keeps the serde shape), `value` itself is
/// serialized. Objects then keep their field declaration order and `f32`
/// fields their shortest form, as in v0.4.3. A detour through
/// `serde_json::Value` sorts every object's keys and prints an `f32` `12.34`
/// as `12.34000015258789`. An override that changes the shape, or one whose
/// type cannot serialize itself, is rendered from its `Value`.
fn render_json<T: Outputtable>(value: &T, pretty: bool) -> Result<String, serde_json::Error> {
    let shaped = value.json()?;
    match serde_json::to_value(value) {
        Ok(serde_shape) if serde_shape == shaped => json_text(value, pretty),
        _ => json_text(&shaped, pretty),
    }
}

/// [`render_json`] for a list written as one JSON array.
fn render_json_list<T: Outputtable>(
    values: &[T],
    pretty: bool,
) -> Result<String, serde_json::Error> {
    let shaped = values
        .iter()
        .map(Outputtable::json)
        .collect::<Result<Vec<_>, _>>()?;
    let serde_shape = values
        .iter()
        .map(serde_json::to_value)
        .collect::<Result<Vec<_>, _>>();
    match serde_shape {
        Ok(serde_shape) if serde_shape == shaped => json_text(values, pretty),
        _ => json_text(&shaped, pretty),
    }
}

fn json_text<S: Serialize + ?Sized>(value: &S, pretty: bool) -> Result<String, serde_json::Error> {
    if pretty {
        serde_json::to_string_pretty(value)
    } else {
        serde_json::to_string(value)
    }
}

#[cfg(test)]
#[path = "output_inline_tests.rs"]
mod tests;
