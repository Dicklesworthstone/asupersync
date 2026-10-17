//! Standard CLI argument handling.
//!
//! Provides common argument patterns for CLI tools with consistent behavior.

use super::output::{ColorChoice, OutputFormat};
use clap::{ArgAction, Args};
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

/// ATP doctor command arguments.
#[derive(Args, Debug)]
pub struct AtpDoctorArgs {
    /// Report platform filesystem, network, and service-manager capabilities
    #[arg(long = "platform", action = ArgAction::SetTrue)]
    pub platform: bool,
}

/// ATP verify command arguments.
#[derive(Args, Debug)]
pub struct AtpVerifyArgs {
    /// Path to the ATP proof bundle file to verify
    #[arg(value_name = "BUNDLE_PATH")]
    pub bundle_path: PathBuf,
    /// Require all verification stages to pass
    #[arg(long = "strict", action = ArgAction::SetTrue)]
    pub strict: bool,
    /// Minimum chunk verification coverage (0.0 to 1.0)
    #[arg(long = "min-coverage", default_value = "0.95")]
    pub min_coverage: f64,
    /// Enable strict replay validation
    #[arg(long = "strict-replay", action = ArgAction::SetTrue)]
    pub strict_replay: bool,
    /// Show detailed verification report
    #[arg(long = "verbose", action = ArgAction::SetTrue)]
    pub verbose: bool,
}

/// ATP replay command arguments.
#[derive(Args, Debug)]
pub struct AtpReplayArgs {
    /// Path to the emitted ATP trace file.
    #[arg(long = "trace-file", value_name = "PATH")]
    pub trace_file: PathBuf,
    /// Path to the emitted crashpack manifest.
    #[arg(long = "manifest", value_name = "PATH")]
    pub manifest: PathBuf,
    /// Path to the emitted journal digest file.
    #[arg(long = "journal-digest", value_name = "PATH")]
    pub journal_digest: PathBuf,
    /// Path to the emitted evidence ledger JSON file.
    #[arg(long = "evidence-ledger", value_name = "PATH")]
    pub evidence_ledger: PathBuf,
    /// Path to the emitted ATP path log.
    #[arg(long = "pathlog", value_name = "PATH")]
    pub pathlog: PathBuf,
    /// Path to the emitted QUIC log.
    #[arg(long = "quiclog", value_name = "PATH")]
    pub quiclog: PathBuf,
    /// Path to the emitted repair log.
    #[arg(long = "repairlog", value_name = "PATH")]
    pub repairlog: PathBuf,
    /// Validate requested oracle names against the replayed artifact reports.
    #[arg(long = "validate-oracles", action = ArgAction::SetTrue)]
    pub validate_oracles: bool,
    /// Oracle name expected in the replayed artifact reports.
    #[arg(long = "oracle", value_name = "NAME")]
    pub oracles: Vec<String>,
    /// Minimize the replay trace while preserving oracle witnesses.
    #[arg(long = "minimize", action = ArgAction::SetTrue)]
    pub minimize: bool,
    /// Target trace reduction ratio for minimization.
    #[arg(long = "reduction-target", default_value_t = 0.3)]
    pub reduction_target: f64,
}

/// ATP proof command arguments.
#[derive(Args, Debug)]
pub struct AtpProofArgs {
    /// Path to the ATP proof bundle file to display
    #[arg(value_name = "BUNDLE_PATH")]
    pub bundle_path: PathBuf,
    /// Show concise summary instead of full details
    #[arg(long = "summary", action = ArgAction::SetTrue)]
    pub summary: bool,
    /// Show only specific sections (manifest,content,repair,peer,path,journal,replay)
    #[arg(long = "section", value_delimiter = ',')]
    pub sections: Vec<String>,
}

#[cfg(test)]
#[path = "args_inline_tests.rs"]
mod tests;
