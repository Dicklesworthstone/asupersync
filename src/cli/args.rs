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

    /// Verbosity level (0 = normal, 1 = verbose, 2+ = very verbose).
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
    /// Uses explicit choice if set, otherwise auto-detects.
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
        self.verbosity > 0 || self.debug
    }

    /// Check if quiet mode is enabled.
    #[must_use]
    pub fn is_quiet(&self) -> bool {
        self.quiet
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
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn common_args_defaults() {
        init_test("common_args_defaults");
        let args = CommonArgs::new();
        crate::assert_with_log!(
            args.format.is_none(),
            "format none",
            true,
            args.format.is_none()
        );
        crate::assert_with_log!(
            args.color.is_none(),
            "color none",
            true,
            args.color.is_none()
        );
        crate::assert_with_log!(args.verbosity == 0, "verbosity", 0, args.verbosity);
        crate::assert_with_log!(!args.quiet, "quiet false", false, args.quiet);
        crate::assert_with_log!(!args.debug, "debug false", false, args.debug);
        crate::assert_with_log!(
            args.config.is_none(),
            "config none",
            true,
            args.config.is_none()
        );
        crate::test_complete!("common_args_defaults");
    }

    #[test]
    fn common_args_builder() {
        init_test("common_args_builder");
        let args = CommonArgs::new()
            .with_format(OutputFormat::Json)
            .with_color(ColorChoice::Never)
            .with_verbosity(2)
            .debug();

        crate::assert_with_log!(
            args.format == Some(OutputFormat::Json),
            "format json",
            Some(OutputFormat::Json),
            args.format
        );
        crate::assert_with_log!(
            args.color == Some(ColorChoice::Never),
            "color never",
            Some(ColorChoice::Never),
            args.color
        );
        crate::assert_with_log!(args.verbosity == 2, "verbosity", 2, args.verbosity);
        crate::assert_with_log!(args.debug, "debug true", true, args.debug);
        let verbose = args.is_verbose();
        crate::assert_with_log!(verbose, "is_verbose", true, verbose);
        crate::test_complete!("common_args_builder");
    }

    #[test]
    fn common_args_verbose_mode() {
        init_test("common_args_verbose_mode");
        let args = CommonArgs::new().with_verbosity(1);
        let verbose = args.is_verbose();
        crate::assert_with_log!(verbose, "is_verbose", true, verbose);
        crate::test_complete!("common_args_verbose_mode");
    }

    #[test]
    fn common_args_quiet_mode() {
        init_test("common_args_quiet_mode");
        let args = CommonArgs::new().quiet();
        let quiet = args.is_quiet();
        crate::assert_with_log!(quiet, "is_quiet", true, quiet);
        let verbose = args.is_verbose();
        crate::assert_with_log!(!verbose, "not verbose", false, verbose);
        crate::test_complete!("common_args_quiet_mode");
    }

    #[test]
    fn parse_output_format_valid() {
        init_test("parse_output_format_valid");
        let json = parse_output_format("json").unwrap();
        crate::assert_with_log!(json == OutputFormat::Json, "json", OutputFormat::Json, json);
        let json_upper = parse_output_format("JSON").unwrap();
        crate::assert_with_log!(
            json_upper == OutputFormat::Json,
            "JSON",
            OutputFormat::Json,
            json_upper
        );
        let pretty = parse_output_format("json-pretty").unwrap();
        crate::assert_with_log!(
            pretty == OutputFormat::JsonPretty,
            "json-pretty",
            OutputFormat::JsonPretty,
            pretty
        );
        let stream = parse_output_format("stream-json").unwrap();
        crate::assert_with_log!(
            stream == OutputFormat::StreamJson,
            "stream-json",
            OutputFormat::StreamJson,
            stream
        );
        let ndjson = parse_output_format("ndjson").unwrap();
        crate::assert_with_log!(
            ndjson == OutputFormat::StreamJson,
            "ndjson",
            OutputFormat::StreamJson,
            ndjson
        );
        let tsv = parse_output_format("tsv").unwrap();
        crate::assert_with_log!(tsv == OutputFormat::Tsv, "tsv", OutputFormat::Tsv, tsv);
        let human = parse_output_format("human").unwrap();
        crate::assert_with_log!(
            human == OutputFormat::Human,
            "human",
            OutputFormat::Human,
            human
        );
        let text = parse_output_format("text").unwrap();
        crate::assert_with_log!(
            text == OutputFormat::Human,
            "text",
            OutputFormat::Human,
            text
        );
        crate::test_complete!("parse_output_format_valid");
    }

    #[test]
    fn parse_output_format_invalid() {
        init_test("parse_output_format_invalid");
        let err = parse_output_format("xml").unwrap_err();
        let unknown = err.contains("Unknown output format");
        crate::assert_with_log!(unknown, "unknown format", true, unknown);
        let has_xml = err.contains("xml");
        crate::assert_with_log!(has_xml, "contains xml", true, has_xml);
        crate::test_complete!("parse_output_format_invalid");
    }

    #[test]
    fn parse_color_choice_valid() {
        init_test("parse_color_choice_valid");
        let auto = parse_color_choice("auto").unwrap();
        crate::assert_with_log!(auto == ColorChoice::Auto, "auto", ColorChoice::Auto, auto);
        let auto_upper = parse_color_choice("AUTO").unwrap();
        crate::assert_with_log!(
            auto_upper == ColorChoice::Auto,
            "AUTO",
            ColorChoice::Auto,
            auto_upper
        );
        let always = parse_color_choice("always").unwrap();
        crate::assert_with_log!(
            always == ColorChoice::Always,
            "always",
            ColorChoice::Always,
            always
        );
        let on = parse_color_choice("on").unwrap();
        crate::assert_with_log!(on == ColorChoice::Always, "on", ColorChoice::Always, on);
        let never = parse_color_choice("never").unwrap();
        crate::assert_with_log!(
            never == ColorChoice::Never,
            "never",
            ColorChoice::Never,
            never
        );
        let off = parse_color_choice("off").unwrap();
        crate::assert_with_log!(off == ColorChoice::Never, "off", ColorChoice::Never, off);
        let false_val = parse_color_choice("false").unwrap();
        crate::assert_with_log!(
            false_val == ColorChoice::Never,
            "false",
            ColorChoice::Never,
            false_val
        );
        crate::test_complete!("parse_color_choice_valid");
    }

    #[test]
    fn parse_color_choice_invalid() {
        init_test("parse_color_choice_invalid");
        let err = parse_color_choice("rainbow").unwrap_err();
        let unknown = err.contains("Unknown color choice");
        crate::assert_with_log!(unknown, "unknown color", true, unknown);
        crate::test_complete!("parse_color_choice_invalid");
    }

    #[test]
    fn common_args_help_contains_essentials() {
        init_test("common_args_help_contains_essentials");
        let has_format = COMMON_ARGS_HELP.contains("--format");
        crate::assert_with_log!(has_format, "contains --format", true, has_format);
        let has_color = COMMON_ARGS_HELP.contains("--color");
        crate::assert_with_log!(has_color, "contains --color", true, has_color);
        let has_verbose = COMMON_ARGS_HELP.contains("--verbose");
        crate::assert_with_log!(has_verbose, "contains --verbose", true, has_verbose);
        let has_no_color = COMMON_ARGS_HELP.contains("NO_COLOR");
        crate::assert_with_log!(has_no_color, "contains NO_COLOR", true, has_no_color);
        let has_env = COMMON_ARGS_HELP.contains("ASUPERSYNC_OUTPUT_FORMAT");
        crate::assert_with_log!(has_env, "contains env var", true, has_env);
        crate::test_complete!("common_args_help_contains_essentials");
    }
}
