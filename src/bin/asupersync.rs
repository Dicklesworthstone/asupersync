//! Asupersync CLI tools (feature-gated).
#![allow(clippy::result_large_err)]

use asupersync::cli::{
    parse_color_choice, parse_output_format, CliError, ColorChoice, CommonArgs, Output,
    OutputFormat, Outputtable,
};
use asupersync::trace::{
    verify_trace, CompressionMode, IssueSeverity, ReplayEvent, TraceFileError, TraceReader,
    VerificationOptions, TRACE_FILE_VERSION, TRACE_MAGIC,
};
use asupersync::Time;
use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};
use std::fmt::Write as _;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(name = "asupersync", version, about = "Asupersync CLI tools")]
struct Cli {
    #[command(flatten)]
    common: CommonArgsCli,

    #[command(subcommand)]
    command: Command,
}

#[derive(Args, Debug, Default)]
struct CommonArgsCli {
    /// Output format: json, json-pretty, stream-json, tsv, human
    #[arg(short = 'f', long = "format", value_parser = parse_output_format)]
    format: Option<OutputFormat>,

    /// Color output: auto, always, never
    #[arg(short = 'c', long = "color", value_parser = parse_color_choice)]
    color: Option<ColorChoice>,

    /// Increase verbosity (-v, -vv, -vvv)
    #[arg(short = 'v', long = "verbose", action = ArgAction::Count)]
    verbosity: u8,

    /// Suppress non-essential output
    #[arg(short = 'q', long = "quiet", action = ArgAction::SetTrue)]
    quiet: bool,

    /// Enable debug output
    #[arg(long = "debug", action = ArgAction::SetTrue)]
    debug: bool,

    /// Configuration file path
    #[arg(long = "config")]
    config: Option<PathBuf>,
}

impl CommonArgsCli {
    fn to_common_args(&self) -> CommonArgs {
        CommonArgs {
            format: self.format,
            color: self.color,
            verbosity: self.verbosity,
            quiet: self.quiet,
            debug: self.debug,
            config: self.config.clone(),
        }
    }
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Trace file inspection utilities
    Trace(TraceArgs),
}

#[derive(Args, Debug)]
struct TraceArgs {
    #[command(subcommand)]
    command: TraceCommand,
}

#[derive(Subcommand, Debug)]
enum TraceCommand {
    /// Show summary information about a trace file
    Info(TraceInfoArgs),

    /// List trace events with optional filtering
    Events(TraceEventsArgs),

    /// Verify trace file integrity
    Verify(TraceVerifyArgs),

    /// Diff two trace files
    Diff(TraceDiffArgs),

    /// Export trace events to JSON
    Export(TraceExportArgs),
}

#[derive(Args, Debug)]
struct TraceInfoArgs {
    /// Trace file path
    file: PathBuf,
}

#[derive(Args, Debug)]
struct TraceEventsArgs {
    /// Trace file path
    file: PathBuf,

    /// Skip the first N events
    #[arg(long = "offset", default_value_t = 0)]
    offset: u64,

    /// Limit number of events returned (omit for all)
    #[arg(long = "limit")]
    limit: Option<u64>,

    /// Filter by event kind (can be repeated)
    #[arg(long = "filter")]
    filters: Vec<String>,
}

#[derive(Args, Debug)]
struct TraceVerifyArgs {
    /// Trace file path
    file: PathBuf,

    /// Quick header-only verification
    #[arg(long = "quick", action = ArgAction::SetTrue)]
    quick: bool,

    /// Strict verification (monotonicity + full checks)
    #[arg(long = "strict", action = ArgAction::SetTrue)]
    strict: bool,

    /// Check timestamp monotonicity
    #[arg(long = "monotonic", action = ArgAction::SetTrue)]
    monotonic: bool,
}

#[derive(Args, Debug)]
struct TraceDiffArgs {
    /// First trace file
    file_a: PathBuf,

    /// Second trace file
    file_b: PathBuf,
}

#[derive(ValueEnum, Debug, Clone, Copy)]
enum ExportFormat {
    Json,
    Ndjson,
}

#[derive(Args, Debug)]
struct TraceExportArgs {
    /// Trace file path
    file: PathBuf,

    /// Export format (json array or ndjson)
    #[arg(long = "format", value_enum, default_value_t = ExportFormat::Json)]
    format: ExportFormat,
}

#[derive(Debug, serde::Serialize)]
struct TraceInfo {
    file: String,
    file_version: u16,
    schema_version: u32,
    compressed: bool,
    compression: String,
    size_bytes: u64,
    event_count: u64,
    duration_nanos: Option<u64>,
    created_at: Option<String>,
    seed: u64,
    config_hash: u64,
    description: Option<String>,
}

impl Outputtable for TraceInfo {
    fn human_format(&self) -> String {
        let mut lines = Vec::new();
        lines.push(format!("File: {}", self.file));
        lines.push(format!("Version: {}", self.file_version));
        lines.push(format!("Schema: {}", self.schema_version));
        if self.compressed {
            lines.push(format!("Compressed: yes ({})", self.compression));
        } else {
            lines.push("Compressed: no".to_string());
        }
        lines.push(format!("Size: {}", format_bytes(self.size_bytes)));
        lines.push(format!("Events: {}", self.event_count));
        if let Some(duration) = self.duration_nanos {
            let time = Time::from_nanos(duration);
            lines.push(format!("Duration: {time}"));
        }
        if let Some(created) = &self.created_at {
            lines.push(format!("Created: {created}"));
        }
        lines.push(format!("Seed: {}", self.seed));
        lines.push(format!("Config hash: {}", self.config_hash));
        if let Some(desc) = &self.description {
            lines.push(format!("Description: {desc}"));
        }
        lines.join("\n")
    }
}

#[derive(Debug, serde::Serialize)]
struct TraceEventRow {
    index: u64,
    kind: String,
    time_nanos: Option<u64>,
    event: ReplayEvent,
}

impl Outputtable for TraceEventRow {
    fn human_format(&self) -> String {
        let time = self
            .time_nanos
            .map(Time::from_nanos)
            .map_or_else(|| "-".to_string(), |t| t.to_string());
        format!("#{:06} [{time}] {:?}", self.index, self.event)
    }

    fn tsv_format(&self) -> String {
        let time = self.time_nanos.map_or_else(String::new, |t| t.to_string());
        format!("{}\t{}\t{}\t{:?}", self.index, self.kind, time, self.event)
    }
}

#[derive(Debug, serde::Serialize)]
struct TraceVerifyOutput {
    file: String,
    valid: bool,
    completed: bool,
    declared_events: u64,
    verified_events: u64,
    issues: Vec<TraceVerifyIssue>,
}

impl Outputtable for TraceVerifyOutput {
    fn human_format(&self) -> String {
        let mut lines = Vec::new();
        lines.push(format!("File: {}", self.file));
        if self.valid {
            lines.push("Verification passed".to_string());
        } else {
            lines.push("Verification failed".to_string());
        }
        lines.push(format!(
            "Events verified: {}/{}",
            self.verified_events, self.declared_events
        ));
        if !self.issues.is_empty() {
            lines.push("Issues:".to_string());
            for issue in &self.issues {
                lines.push(format!("- [{}] {}", issue.severity, issue.message));
            }
        }
        lines.join("\n")
    }
}

#[derive(Debug, serde::Serialize)]
struct TraceVerifyIssue {
    severity: String,
    message: String,
}

#[derive(Debug, serde::Serialize)]
struct TraceDiffOutput {
    file_a: String,
    file_b: String,
    diverged: bool,
    divergence_index: Option<u64>,
    event_a: Option<ReplayEvent>,
    event_b: Option<ReplayEvent>,
    common_events: u64,
    total_a: u64,
    total_b: u64,
}

impl Outputtable for TraceDiffOutput {
    fn human_format(&self) -> String {
        let mut lines = Vec::new();
        if self.diverged {
            if let Some(index) = self.divergence_index {
                lines.push(format!("First divergence at event #{index}"));
            } else {
                lines.push("Traces diverged".to_string());
            }
            if let Some(event_a) = &self.event_a {
                lines.push(format!("  File A: {event_a:?}"));
            } else {
                lines.push("  File A: <end>".to_string());
            }
            if let Some(event_b) = &self.event_b {
                lines.push(format!("  File B: {event_b:?}"));
            } else {
                lines.push("  File B: <end>".to_string());
            }
        } else {
            lines.push("Traces are identical".to_string());
        }
        lines.push(format!(
            "Common events: {} (A={}, B={})",
            self.common_events, self.total_a, self.total_b
        ));
        lines.join("\n")
    }
}

fn main() {
    let cli = Cli::parse();
    let common = cli.common.to_common_args();
    let format = common.output_format();
    let color = common.color_choice();

    let mut output = Output::new(format).with_color(color);
    if let Err(err) = run(cli.command, &mut output) {
        let _ = write_cli_error(&err, format, color);
        std::process::exit(err.exit_code);
    }
}

fn run(command: Command, output: &mut Output) -> Result<(), CliError> {
    match command {
        Command::Trace(trace_args) => run_trace(trace_args, output),
    }
}

fn run_trace(args: TraceArgs, output: &mut Output) -> Result<(), CliError> {
    match args.command {
        TraceCommand::Info(args) => {
            let info = trace_info(&args.file)?;
            output.write(&info).map_err(|e| {
                CliError::new("output_error", "Failed to write output").detail(e.to_string())
            })?;
            Ok(())
        }
        TraceCommand::Events(args) => {
            let rows = trace_events(&args.file, args.offset, args.limit, &args.filters)?;
            output.write_list(&rows).map_err(|e| {
                CliError::new("output_error", "Failed to write output").detail(e.to_string())
            })?;
            Ok(())
        }
        TraceCommand::Verify(args) => {
            let out = trace_verify(&args.file, args.quick, args.strict, args.monotonic)?;
            output.write(&out).map_err(|e| {
                CliError::new("output_error", "Failed to write output").detail(e.to_string())
            })?;
            Ok(())
        }
        TraceCommand::Diff(args) => {
            let out = trace_diff(&args.file_a, &args.file_b)?;
            output.write(&out).map_err(|e| {
                CliError::new("output_error", "Failed to write output").detail(e.to_string())
            })?;
            Ok(())
        }
        TraceCommand::Export(args) => {
            export_trace(&args.file, args.format)?;
            Ok(())
        }
    }
}

fn trace_info(path: &Path) -> Result<TraceInfo, CliError> {
    let file_version = read_trace_version(path)?;
    let mut reader = TraceReader::open(path).map_err(|err| trace_file_error(path, err))?;
    let metadata = reader.metadata().clone();
    let schema_version = metadata.version;
    let seed = metadata.seed;
    let recorded_at = metadata.recorded_at;
    let config_hash = metadata.config_hash;
    let description = metadata.description;
    let event_count = reader.event_count();
    let compression = reader.compression();
    let size_bytes = file_size(path)?;
    let duration_nanos =
        compute_duration_nanos(&mut reader).map_err(|err| trace_file_error(path, err))?;

    Ok(TraceInfo {
        file: path.display().to_string(),
        file_version,
        schema_version,
        compressed: compression.is_compressed(),
        compression: compression_label(compression),
        size_bytes,
        event_count,
        duration_nanos,
        created_at: format_timestamp(recorded_at),
        seed,
        config_hash,
        description,
    })
}

fn trace_events(
    path: &Path,
    offset: u64,
    limit: Option<u64>,
    filters: &[String],
) -> Result<Vec<TraceEventRow>, CliError> {
    let mut reader = TraceReader::open(path).map_err(|err| trace_file_error(path, err))?;
    let mut rows = Vec::new();
    let mut index = 0u64;

    while let Some(event) = reader
        .read_event()
        .map_err(|err| trace_file_error(path, err))?
    {
        if index < offset {
            index = index.saturating_add(1);
            continue;
        }

        let kind = replay_event_kind(&event);
        if !filters.is_empty() && !filters.iter().any(|f| kind_matches(f, kind)) {
            index = index.saturating_add(1);
            continue;
        }

        rows.push(TraceEventRow {
            index,
            kind: kind.to_string(),
            time_nanos: replay_event_time_nanos(&event),
            event,
        });

        index = index.saturating_add(1);
        if let Some(limit) = limit {
            if rows.len() as u64 >= limit {
                break;
            }
        }
    }

    Ok(rows)
}

fn trace_verify(
    path: &Path,
    quick: bool,
    strict: bool,
    monotonic: bool,
) -> Result<TraceVerifyOutput, CliError> {
    if quick && strict {
        return Err(CliError::new(
            "invalid_argument",
            "Cannot combine --quick and --strict",
        ));
    }

    let mut options = if quick {
        VerificationOptions::quick()
    } else if strict {
        VerificationOptions::strict()
    } else {
        VerificationOptions::default()
    };

    if monotonic {
        options.check_monotonicity = true;
    }

    let result = verify_trace(path, &options).map_err(|err| io_error(path, &err))?;
    let issues = result
        .issues()
        .iter()
        .map(|issue| TraceVerifyIssue {
            severity: issue_severity_label(issue.severity()).to_string(),
            message: issue.to_string(),
        })
        .collect();

    Ok(TraceVerifyOutput {
        file: path.display().to_string(),
        valid: result.is_valid(),
        completed: result.completed,
        declared_events: result.declared_events,
        verified_events: result.verified_events,
        issues,
    })
}

fn trace_diff(path_a: &Path, path_b: &Path) -> Result<TraceDiffOutput, CliError> {
    let mut reader_a = TraceReader::open(path_a).map_err(|err| trace_file_error(path_a, err))?;
    let mut reader_b = TraceReader::open(path_b).map_err(|err| trace_file_error(path_b, err))?;

    let total_a = reader_a.event_count();
    let total_b = reader_b.event_count();

    let mut index = 0u64;
    loop {
        let event_a = reader_a
            .read_event()
            .map_err(|err| trace_file_error(path_a, err))?;
        let event_b = reader_b
            .read_event()
            .map_err(|err| trace_file_error(path_b, err))?;

        match (event_a, event_b) {
            (None, None) => {
                return Ok(TraceDiffOutput {
                    file_a: path_a.display().to_string(),
                    file_b: path_b.display().to_string(),
                    diverged: false,
                    divergence_index: None,
                    event_a: None,
                    event_b: None,
                    common_events: index,
                    total_a,
                    total_b,
                });
            }
            (Some(event_a), Some(event_b)) => {
                if event_a != event_b {
                    return Ok(TraceDiffOutput {
                        file_a: path_a.display().to_string(),
                        file_b: path_b.display().to_string(),
                        diverged: true,
                        divergence_index: Some(index),
                        event_a: Some(event_a),
                        event_b: Some(event_b),
                        common_events: index,
                        total_a,
                        total_b,
                    });
                }
            }
            (Some(event_a), None) => {
                return Ok(TraceDiffOutput {
                    file_a: path_a.display().to_string(),
                    file_b: path_b.display().to_string(),
                    diverged: true,
                    divergence_index: Some(index),
                    event_a: Some(event_a),
                    event_b: None,
                    common_events: index,
                    total_a,
                    total_b,
                });
            }
            (None, Some(event_b)) => {
                return Ok(TraceDiffOutput {
                    file_a: path_a.display().to_string(),
                    file_b: path_b.display().to_string(),
                    diverged: true,
                    divergence_index: Some(index),
                    event_a: None,
                    event_b: Some(event_b),
                    common_events: index,
                    total_a,
                    total_b,
                });
            }
        }

        index = index.saturating_add(1);
    }
}

fn export_trace(path: &Path, format: ExportFormat) -> Result<(), CliError> {
    let mut reader = TraceReader::open(path).map_err(|err| trace_file_error(path, err))?;
    let mut stdout = io::stdout();

    match format {
        ExportFormat::Json => {
            write!(stdout, "[").map_err(output_cli_error)?;
            let mut first = true;
            while let Some(event) = reader
                .read_event()
                .map_err(|err| trace_file_error(path, err))?
            {
                if !first {
                    write!(stdout, ",").map_err(output_cli_error)?;
                }
                first = false;
                serde_json::to_writer(&mut stdout, &event).map_err(output_cli_error)?;
            }
            writeln!(stdout, "]").map_err(output_cli_error)?;
        }
        ExportFormat::Ndjson => {
            while let Some(event) = reader
                .read_event()
                .map_err(|err| trace_file_error(path, err))?
            {
                let json = serde_json::to_string(&event).map_err(output_cli_error)?;
                writeln!(stdout, "{json}").map_err(output_cli_error)?;
            }
        }
    }

    Ok(())
}

fn read_trace_version(path: &Path) -> Result<u16, CliError> {
    let mut file = File::open(path).map_err(|err| io_error(path, &err))?;
    let mut magic = [0u8; 11];
    file.read_exact(&mut magic)
        .map_err(|err| io_error(path, &err))?;
    if magic != *TRACE_MAGIC {
        return Err(CliError::new("invalid_trace", "Invalid trace file magic")
            .detail("File does not appear to be a valid Asupersync trace"));
    }

    let mut version_bytes = [0u8; 2];
    file.read_exact(&mut version_bytes)
        .map_err(|err| io_error(path, &err))?;
    let version = u16::from_le_bytes(version_bytes);
    if version > TRACE_FILE_VERSION {
        return Err(
            CliError::new("unsupported_version", "Unsupported trace version").detail(format!(
                "Found version {version}, max supported {TRACE_FILE_VERSION}"
            )),
        );
    }

    Ok(version)
}

fn file_size(path: &Path) -> Result<u64, CliError> {
    std::fs::metadata(path)
        .map(|meta| meta.len())
        .map_err(|err| io_error(path, &err))
}

fn compute_duration_nanos(reader: &mut TraceReader) -> Result<Option<u64>, TraceFileError> {
    let mut max: Option<u64> = None;
    while let Some(event) = reader.read_event()? {
        if let Some(time) = replay_event_time_nanos(&event) {
            max = Some(max.map_or(time, |prev| prev.max(time)));
        }
    }
    Ok(max)
}

fn replay_event_time_nanos(event: &ReplayEvent) -> Option<u64> {
    match event {
        ReplayEvent::TimeAdvanced { to_nanos, .. } => Some(*to_nanos),
        ReplayEvent::Checkpoint { time_nanos, .. } => Some(*time_nanos),
        _ => None,
    }
}

fn replay_event_kind(event: &ReplayEvent) -> &'static str {
    match event {
        ReplayEvent::TaskScheduled { .. } => "TaskScheduled",
        ReplayEvent::TaskYielded { .. } => "TaskYielded",
        ReplayEvent::TaskCompleted { .. } => "TaskCompleted",
        ReplayEvent::TaskSpawned { .. } => "TaskSpawned",
        ReplayEvent::TimeAdvanced { .. } => "TimeAdvanced",
        ReplayEvent::TimerCreated { .. } => "TimerCreated",
        ReplayEvent::TimerFired { .. } => "TimerFired",
        ReplayEvent::TimerCancelled { .. } => "TimerCancelled",
        ReplayEvent::IoReady { .. } => "IoReady",
        ReplayEvent::IoResult { .. } => "IoResult",
        ReplayEvent::IoError { .. } => "IoError",
        ReplayEvent::RngSeed { .. } => "RngSeed",
        ReplayEvent::RngValue { .. } => "RngValue",
        ReplayEvent::ChaosInjection { .. } => "ChaosInjection",
        ReplayEvent::RegionCreated { .. } => "RegionCreated",
        ReplayEvent::RegionClosed { .. } => "RegionClosed",
        ReplayEvent::RegionCancelled { .. } => "RegionCancelled",
        ReplayEvent::WakerWake { .. } => "WakerWake",
        ReplayEvent::WakerBatchWake { .. } => "WakerBatchWake",
        ReplayEvent::Checkpoint { .. } => "Checkpoint",
    }
}

fn kind_matches(filter: &str, kind: &str) -> bool {
    let filter = filter.trim().to_ascii_lowercase();
    if filter.is_empty() {
        return true;
    }
    let kind_lower = kind.to_ascii_lowercase();
    if kind_lower == filter {
        return true;
    }
    if kind_lower.replace('_', "") == filter.replace('_', "") {
        return true;
    }
    match filter.as_str() {
        "io" => kind_lower.starts_with("io"),
        "time" => kind_lower.starts_with("time") || kind_lower.starts_with("timer"),
        "task" => kind_lower.starts_with("task"),
        "rng" => kind_lower.starts_with("rng"),
        "region" => kind_lower.starts_with("region"),
        "waker" => kind_lower.starts_with("waker"),
        "chaos" => kind_lower.starts_with("chaos"),
        _ => kind_lower.contains(&filter),
    }
}

fn compression_label(mode: CompressionMode) -> String {
    match mode {
        CompressionMode::None => "none".to_string(),
        #[cfg(feature = "trace-compression")]
        CompressionMode::Lz4 { level } => format!("lz4(level={level})"),
        #[cfg(feature = "trace-compression")]
        CompressionMode::Auto => "auto(lz4)".to_string(),
    }
}

fn format_timestamp(recorded_at_nanos: u64) -> Option<String> {
    if recorded_at_nanos == 0 {
        return None;
    }
    time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(recorded_at_nanos))
        .ok()
        .and_then(|timestamp| {
            timestamp
                .format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
}

fn issue_severity_label(severity: IssueSeverity) -> &'static str {
    match severity {
        IssueSeverity::Warning => "warning",
        IssueSeverity::Error => "error",
        IssueSeverity::Fatal => "fatal",
    }
}

fn trace_file_error(path: &Path, err: TraceFileError) -> CliError {
    match err {
        TraceFileError::Io(io_err) => io_error(path, &io_err),
        TraceFileError::InvalidMagic => {
            CliError::new("invalid_trace", "Invalid trace file").detail("Invalid magic bytes")
        }
        TraceFileError::UnsupportedVersion { expected, found } => {
            CliError::new("unsupported_version", "Unsupported trace file version")
                .detail(format!("Expected <= {expected}, found {found}"))
        }
        TraceFileError::UnsupportedFlags(flags) => {
            CliError::new("unsupported_flags", "Unsupported trace file flags")
                .detail(format!("Flags: {flags:#06x}"))
        }
        TraceFileError::UnsupportedCompression(code) => {
            CliError::new("unsupported_compression", "Unsupported compression format")
                .detail(format!("Compression code: {code}"))
        }
        TraceFileError::CompressionNotAvailable => CliError::new(
            "compression_unavailable",
            "Trace file compression not supported",
        )
        .detail("Enable the trace-compression feature to read this file"),
        TraceFileError::Compression(detail) => {
            CliError::new("compression_error", "Compression error").detail(detail)
        }
        TraceFileError::Decompression(detail) => {
            CliError::new("decompression_error", "Decompression error").detail(detail)
        }
        TraceFileError::Serialize(detail) => {
            CliError::new("serialize_error", "Serialize error").detail(detail)
        }
        TraceFileError::Deserialize(detail) => {
            CliError::new("deserialize_error", "Deserialize error").detail(detail)
        }
        TraceFileError::SchemaMismatch { expected, found } => {
            CliError::new("schema_mismatch", "Trace schema mismatch")
                .detail(format!("Expected {expected}, found {found}"))
        }
        TraceFileError::AlreadyFinished => {
            CliError::new("invalid_state", "Trace writer already finished")
        }
        TraceFileError::Truncated => CliError::new("truncated_trace", "Trace file truncated"),
    }
    .context("path", path.display().to_string())
}

fn io_error(path: &Path, err: &io::Error) -> CliError {
    let mut error = match err.kind() {
        io::ErrorKind::NotFound => {
            CliError::new("file_not_found", "File not found").detail(err.to_string())
        }
        io::ErrorKind::PermissionDenied => {
            CliError::new("permission_denied", "Permission denied").detail(err.to_string())
        }
        _ => CliError::new("io_error", "I/O error").detail(err.to_string()),
    };
    error = error.context("path", path.display().to_string());
    error
}

fn output_cli_error(err: impl std::error::Error) -> CliError {
    CliError::new("output_error", "Failed to write output").detail(err.to_string())
}

fn write_cli_error(err: &CliError, format: OutputFormat, color: ColorChoice) -> io::Result<()> {
    let mut stderr = io::stderr();
    match format {
        OutputFormat::Human => {
            writeln!(stderr, "{}", err.human_format(color.should_colorize()))
        }
        OutputFormat::Json | OutputFormat::StreamJson => {
            writeln!(stderr, "{}", err.json_format())
        }
        OutputFormat::JsonPretty => writeln!(stderr, "{}", err.json_pretty_format()),
        OutputFormat::Tsv => {
            let mut line = String::new();
            let _ = write!(line, "{}\t{}\t{}", err.error_type, err.title, err.detail);
            writeln!(stderr, "{line}")
        }
    }
}

fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * 1024;
    const GB: u64 = 1024 * 1024 * 1024;

    if bytes >= GB {
        format_scaled(bytes, GB, "GB")
    } else if bytes >= MB {
        format_scaled(bytes, MB, "MB")
    } else if bytes >= KB {
        format_scaled(bytes, KB, "KB")
    } else {
        format!("{bytes} bytes")
    }
}

fn format_scaled(bytes: u64, unit: u64, label: &str) -> String {
    let whole = bytes / unit;
    let rem = bytes % unit;
    let decimals = (rem * 100) / unit;
    format!("{whole}.{decimals:02} {label} ({bytes} bytes)")
}

#[cfg(test)]
mod tests {
    use super::*;
    use asupersync::trace::{TraceMetadata, TraceWriter};
    use tempfile::NamedTempFile;

    fn make_sample_trace() -> NamedTempFile {
        let file = NamedTempFile::new().expect("create temp file");
        let mut writer = TraceWriter::create(file.path()).expect("create writer");
        let metadata = TraceMetadata::new(42).with_description("cli test");
        writer.write_metadata(&metadata).expect("write metadata");
        writer
            .write_event(&ReplayEvent::RngSeed { seed: 42 })
            .expect("write event");
        writer
            .write_event(&ReplayEvent::TimeAdvanced {
                from_nanos: 0,
                to_nanos: 1_000_000,
            })
            .expect("write event");
        writer.finish().expect("finish");
        file
    }

    #[test]
    fn trace_info_reports_counts() {
        let file = make_sample_trace();
        let info = trace_info(file.path()).expect("trace info");
        assert_eq!(info.event_count, 2);
        assert_eq!(info.duration_nanos, Some(1_000_000));
    }

    #[test]
    fn trace_events_filtering() {
        let file = make_sample_trace();
        let rows = trace_events(file.path(), 0, None, &["rng".to_string()]).expect("trace events");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].kind, "RngSeed");
    }

    #[test]
    fn trace_verify_valid() {
        let file = make_sample_trace();
        let out = trace_verify(file.path(), false, false, false).expect("trace verify");
        assert!(out.valid);
    }

    #[test]
    fn trace_diff_detects_divergence() {
        let file_a = make_sample_trace();
        let file_b = NamedTempFile::new().expect("create temp file");
        let mut writer = TraceWriter::create(file_b.path()).expect("create writer");
        let metadata = TraceMetadata::new(7);
        writer.write_metadata(&metadata).expect("write metadata");
        writer
            .write_event(&ReplayEvent::RngSeed { seed: 7 })
            .expect("write event");
        writer.finish().expect("finish");

        let diff = trace_diff(file_a.path(), file_b.path()).expect("trace diff");
        assert!(diff.diverged);
    }

    #[test]
    fn trace_export_json_array() {
        let file = make_sample_trace();
        let mut buf = Vec::new();
        {
            let mut reader = TraceReader::open(file.path()).expect("open reader");
            write!(buf, "[").expect("write");
            let mut first = true;
            while let Some(event) = reader.read_event().expect("read event") {
                if !first {
                    write!(buf, ",").expect("write");
                }
                first = false;
                serde_json::to_writer(&mut buf, &event).expect("serialize");
            }
            write!(buf, "]").expect("write");
        }
        let parsed: Vec<ReplayEvent> = serde_json::from_slice(&buf).expect("parse json");
        assert_eq!(parsed.len(), 2);
    }
}
