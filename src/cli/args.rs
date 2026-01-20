//! Standard CLI argument handling.
//!
//! Provides common argument patterns for CLI tools with consistent behavior.

use super::output::{ColorChoice, OutputFormat};
use std::path::PathBuf;

/// Common CLI arguments shared across tools.
///
/// These can be integrated with clap or manual argument parsing.
#[derive(Clone, Debug, Default)]
pub struct CommonArgs {
    /// Output format selection.
    pub format: Option<OutputFormat>,

    /// Color output preference.
    pub color: Option<ColorChoice>,

    /// Verbosity level (0 = quiet, 1 = normal, 2+ = verbose).
    pub verbosity: u8,

    /// Enable quiet mode (minimal output).
    pub quiet: bool,

    /// Enable debug output.
    pub debug: bool,

    /// Configuration file path.
    pub config: Option<PathBuf>,
}

impl CommonArgs {
    /// Create new common args with defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the effective output format.
    ///
    /// Uses explicit format if set, otherwise auto-detects.
    #[must_use]
    pub fn output_format(&self) -> OutputFormat {
        self.format.unwrap_or_else(OutputFormat::auto_detect)
    }

    /// Get the effective color choice.
    ///
    /// Uses explicit choice if set, otherwise auto-detects.
    #[must_use]
    pub fn color_choice(&self) -> ColorChoice {
        self.color.unwrap_or_else(ColorChoice::auto_detect)
    }

    /// Check if verbose output is enabled.
    #[must_use]
    pub fn is_verbose(&self) -> bool {
        self.verbosity > 1 || self.debug
    }

    /// Check if quiet mode is enabled.
    #[must_use]
    pub fn is_quiet(&self) -> bool {
        self.quiet || self.verbosity == 0
    }

    /// Set output format.
    #[must_use]
    pub const fn with_format(mut self, format: OutputFormat) -> Self {
        self.format = Some(format);
        self
    }

    /// Set color choice.
    #[must_use]
    pub const fn with_color(mut self, color: ColorChoice) -> Self {
        self.color = Some(color);
        self
    }

    /// Set verbosity level.
    #[must_use]
    pub const fn with_verbosity(mut self, level: u8) -> Self {
        self.verbosity = level;
        self
    }

    /// Enable quiet mode.
    #[must_use]
    pub const fn quiet(mut self) -> Self {
        self.quiet = true;
        self
    }

    /// Enable debug mode.
    #[must_use]
    pub const fn debug(mut self) -> Self {
        self.debug = true;
        self
    }

    /// Set config file path.
    #[must_use]
    pub fn with_config(mut self, path: PathBuf) -> Self {
        self.config = Some(path);
        self
    }
}

/// Parse output format from string.
///
/// Accepts various format specifiers:
/// - "json" -> Json
/// - "json-pretty", "pretty" -> JsonPretty
/// - "stream", "stream-json", "ndjson" -> StreamJson
/// - "tsv", "csv" -> Tsv
/// - "human", "text" -> Human
///
/// # Errors
///
/// Returns an error message if the format is not recognized.
pub fn parse_output_format(s: &str) -> Result<OutputFormat, String> {
    match s.to_lowercase().as_str() {
        "json" => Ok(OutputFormat::Json),
        "json-pretty" | "jsonpretty" | "pretty" => Ok(OutputFormat::JsonPretty),
        "stream" | "stream-json" | "streamjson" | "ndjson" => Ok(OutputFormat::StreamJson),
        "tsv" | "csv" => Ok(OutputFormat::Tsv),
        "human" | "text" | "plain" => Ok(OutputFormat::Human),
        other => Err(format!(
            "Unknown output format '{other}'. Valid formats: json, json-pretty, stream-json, tsv, human"
        )),
    }
}

/// Parse color choice from string.
///
/// Accepts:
/// - "auto", "automatic" -> Auto
/// - "always", "on", "yes", "true" -> Always
/// - "never", "off", "no", "false" -> Never
///
/// # Errors
///
/// Returns an error message if the choice is not recognized.
pub fn parse_color_choice(s: &str) -> Result<ColorChoice, String> {
    match s.to_lowercase().as_str() {
        "auto" | "automatic" => Ok(ColorChoice::Auto),
        "always" | "on" | "yes" | "true" => Ok(ColorChoice::Always),
        "never" | "off" | "no" | "false" => Ok(ColorChoice::Never),
        other => Err(format!(
            "Unknown color choice '{other}'. Valid choices: auto, always, never"
        )),
    }
}

/// Standard help text for common arguments.
pub const COMMON_ARGS_HELP: &str = r"Common Options:
  -f, --format <FORMAT>    Output format: json, json-pretty, stream-json, tsv, human
  -c, --color <WHEN>       Color output: auto, always, never
  -v, --verbose            Increase verbosity (-v, -vv, -vvv)
  -q, --quiet              Suppress non-essential output
  --debug                  Enable debug output
  --config <PATH>          Configuration file path

Environment Variables:
  ASUPERSYNC_OUTPUT_FORMAT  Default output format
  NO_COLOR                  Disable colors (https://no-color.org/)
  CLICOLOR_FORCE            Force colors even when not a TTY
  CI                        Automatically use JSON output in CI environments
";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_args_defaults() {
        let args = CommonArgs::new();
        assert!(args.format.is_none());
        assert!(args.color.is_none());
        assert_eq!(args.verbosity, 0);
        assert!(!args.quiet);
        assert!(!args.debug);
        assert!(args.config.is_none());
    }

    #[test]
    fn common_args_builder() {
        let args = CommonArgs::new()
            .with_format(OutputFormat::Json)
            .with_color(ColorChoice::Never)
            .with_verbosity(2)
            .debug();

        assert_eq!(args.format, Some(OutputFormat::Json));
        assert_eq!(args.color, Some(ColorChoice::Never));
        assert_eq!(args.verbosity, 2);
        assert!(args.debug);
        assert!(args.is_verbose());
    }

    #[test]
    fn common_args_quiet_mode() {
        let args = CommonArgs::new().quiet();
        assert!(args.is_quiet());
        assert!(!args.is_verbose());
    }

    #[test]
    fn parse_output_format_valid() {
        assert_eq!(parse_output_format("json").unwrap(), OutputFormat::Json);
        assert_eq!(parse_output_format("JSON").unwrap(), OutputFormat::Json);
        assert_eq!(
            parse_output_format("json-pretty").unwrap(),
            OutputFormat::JsonPretty
        );
        assert_eq!(
            parse_output_format("stream-json").unwrap(),
            OutputFormat::StreamJson
        );
        assert_eq!(parse_output_format("ndjson").unwrap(), OutputFormat::StreamJson);
        assert_eq!(parse_output_format("tsv").unwrap(), OutputFormat::Tsv);
        assert_eq!(parse_output_format("human").unwrap(), OutputFormat::Human);
        assert_eq!(parse_output_format("text").unwrap(), OutputFormat::Human);
    }

    #[test]
    fn parse_output_format_invalid() {
        let err = parse_output_format("xml").unwrap_err();
        assert!(err.contains("Unknown output format"));
        assert!(err.contains("xml"));
    }

    #[test]
    fn parse_color_choice_valid() {
        assert_eq!(parse_color_choice("auto").unwrap(), ColorChoice::Auto);
        assert_eq!(parse_color_choice("AUTO").unwrap(), ColorChoice::Auto);
        assert_eq!(parse_color_choice("always").unwrap(), ColorChoice::Always);
        assert_eq!(parse_color_choice("on").unwrap(), ColorChoice::Always);
        assert_eq!(parse_color_choice("never").unwrap(), ColorChoice::Never);
        assert_eq!(parse_color_choice("off").unwrap(), ColorChoice::Never);
        assert_eq!(parse_color_choice("false").unwrap(), ColorChoice::Never);
    }

    #[test]
    fn parse_color_choice_invalid() {
        let err = parse_color_choice("rainbow").unwrap_err();
        assert!(err.contains("Unknown color choice"));
    }

    #[test]
    fn common_args_help_contains_essentials() {
        assert!(COMMON_ARGS_HELP.contains("--format"));
        assert!(COMMON_ARGS_HELP.contains("--color"));
        assert!(COMMON_ARGS_HELP.contains("--verbose"));
        assert!(COMMON_ARGS_HELP.contains("NO_COLOR"));
        assert!(COMMON_ARGS_HELP.contains("ASUPERSYNC_OUTPUT_FORMAT"));
    }
}
