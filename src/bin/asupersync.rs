//! Asupersync CLI tools (feature-gated).
#![allow(clippy::result_large_err)]

use asupersync::cli::doctor::{
    advanced_diagnostics_report_bundle, build_doctor_scenario_coverage_pack_smoke_report,
    doctor_scenario_coverage_packs_contract, evidence_timeline_contract,
    run_evidence_timeline_keyboard_flow_smoke, validate_advanced_diagnostics_report_extension,
    validate_advanced_diagnostics_report_extension_contract, AdvancedCollaborationEntry,
    AdvancedDiagnosticsFixture, AdvancedDiagnosticsReportBundle, AdvancedRemediationDelta,
    AdvancedTroubleshootingPlaybook, AdvancedTrustTransition,
    DoctorScenarioCoveragePackSmokeReport, DoctorScenarioCoveragePacksContract,
    EvidenceTimelineContract, EvidenceTimelineWorkflowTranscript,
};
use asupersync::cli::{
    analyze_workspace_invariants, analyze_workspace_lock_contention,
    core_diagnostics_report_bundle, core_diagnostics_report_contract, operator_model_contract,
    parse_color_choice, parse_output_format, remediation_recipe_bundle, scan_workspace,
    screen_engine_contract, structured_logging_contract, validate_core_diagnostics_report,
    validate_core_diagnostics_report_contract, CliError, ColorChoice, CommonArgs,
    CoreDiagnosticsReport, CoreDiagnosticsReportBundle, CoreDiagnosticsSummary, ExitCode,
    InvariantAnalyzerReport, LockContentionAnalyzerReport, OperatorModelContract, Output,
    OutputFormat, Outputtable, RemediationRecipeBundle, ScreenEngineContract,
    StructuredLoggingContract, WorkspaceScanReport,
};
use asupersync::trace::{
    verify_trace, CompressionMode, IssueSeverity, ReplayEvent, TraceFileError, TraceReader,
    VerificationOptions, TRACE_FILE_VERSION, TRACE_MAGIC,
};
use asupersync::Time;
use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};
use conformance::{
    requirements_from_entries, scan_conformance_attributes, ScanWarning, SpecRequirement,
    TraceabilityMatrix, TraceabilityScanError,
};
use franken_decision::DecisionAuditEntry;
use franken_evidence::{EvidenceLedger, EvidenceLedgerBuilder};
use franken_kernel::{DecisionId, TraceId};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;

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
    /// Conformance tooling
    Conformance(ConformanceArgs),
    /// FrankenLab scenario testing (bd-1hu19.4)
    Lab(LabArgs),
    /// Doctor tooling for deterministic workspace diagnostics
    Doctor(DoctorArgs),
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
struct ConformanceArgs {
    #[command(subcommand)]
    command: ConformanceCommand,
}

#[derive(Subcommand, Debug)]
enum ConformanceCommand {
    /// Generate spec-to-test traceability matrix
    Matrix(ConformanceMatrixArgs),
}

#[derive(Args, Debug)]
struct ConformanceMatrixArgs {
    /// Root directory to scan (defaults to current directory)
    #[arg(long = "root", default_value = ".")]
    root: PathBuf,

    /// Additional paths to scan (relative to --root if not absolute)
    #[arg(long = "path")]
    paths: Vec<PathBuf>,

    /// JSON file with spec requirements (Vec<SpecRequirement>)
    #[arg(long = "requirements")]
    requirements: Option<PathBuf>,

    /// Minimum coverage percentage required to pass (0-100)
    #[arg(long = "min-coverage")]
    min_coverage: Option<f64>,

    /// Fail if any requirements are missing coverage
    #[arg(long = "fail-on-missing", action = ArgAction::SetTrue)]
    fail_on_missing: bool,
}

// =========================================================================
// FrankenLab CLI (bd-1hu19.4)
// =========================================================================

#[derive(Args, Debug)]
struct LabArgs {
    #[command(subcommand)]
    command: LabCommand,
}

#[derive(Subcommand, Debug)]
enum LabCommand {
    /// Run a FrankenLab scenario from a YAML file
    Run(LabRunArgs),
    /// Validate a scenario YAML file without executing it
    Validate(LabValidateArgs),
    /// Replay a scenario and verify determinism
    Replay(LabReplayArgs),
    /// Explore multiple seeds to find violations
    Explore(LabExploreArgs),
}

#[derive(Args, Debug)]
struct LabRunArgs {
    /// Path to the scenario YAML file
    scenario: PathBuf,

    /// Override the seed from the scenario file
    #[arg(long = "seed")]
    seed: Option<u64>,

    /// Output results as JSON
    #[arg(long = "json", action = ArgAction::SetTrue)]
    json: bool,
}

#[derive(Args, Debug)]
struct LabValidateArgs {
    /// Path to the scenario YAML file
    scenario: PathBuf,

    /// Output results as JSON
    #[arg(long = "json", action = ArgAction::SetTrue)]
    json: bool,
}

#[derive(Args, Debug)]
struct LabReplayArgs {
    /// Path to the scenario YAML file
    scenario: PathBuf,

    /// Override the seed from the scenario file
    #[arg(long = "seed")]
    seed: Option<u64>,

    /// Optional stable pointer for artifact pinning (path, URI, or ticket ref)
    #[arg(long = "artifact-pointer")]
    artifact_pointer: Option<String>,

    /// Optional path to write replay report JSON for deterministic reruns
    #[arg(long = "artifact-output")]
    artifact_output: Option<PathBuf>,

    /// Start event index for replay-window reporting
    #[arg(long = "window-start", default_value_t = 0)]
    window_start: usize,

    /// Max events to include in replay-window reporting
    #[arg(long = "window-events")]
    window_events: Option<usize>,

    /// Output results as JSON
    #[arg(long = "json", action = ArgAction::SetTrue)]
    json: bool,
}

#[derive(Args, Debug)]
struct LabExploreArgs {
    /// Path to the scenario YAML file
    scenario: PathBuf,

    /// Number of seeds to explore (default: 100)
    #[arg(long = "seeds", default_value_t = 100)]
    seeds: u64,

    /// Starting seed for exploration
    #[arg(long = "start-seed", default_value_t = 0)]
    start_seed: u64,

    /// Output results as JSON
    #[arg(long = "json", action = ArgAction::SetTrue)]
    json: bool,
}

// =========================================================================

#[derive(Args, Debug)]
struct DoctorArgs {
    #[command(subcommand)]
    command: DoctorCommand,
}

#[derive(Subcommand, Debug)]
enum DoctorCommand {
    /// Scan workspace topology and capability-flow surfaces
    ScanWorkspace(DoctorScanWorkspaceArgs),
    /// Analyze runtime invariants over scanner output
    AnalyzeInvariants(DoctorAnalyzeInvariantsArgs),
    /// Analyze lock-order and contention risk over scanner output
    AnalyzeLockContention(DoctorAnalyzeLockContentionArgs),
    /// Audit wasm-target dependency graph for forbidden runtime crates
    WasmDependencyAudit(DoctorWasmDependencyAuditArgs),
    /// Emit operator personas, missions, and decision loops contract
    OperatorModel,
    /// Emit canonical screen-to-engine contract for doctor TUI surfaces
    ScreenContracts,
    /// Emit baseline structured logging contract for doctor flows
    LoggingContract,
    /// Emit remediation recipe DSL contract and deterministic fixture bundle
    RemediationContract,
    /// Emit core diagnostics report contract and deterministic fixture bundle
    ReportContract,
    /// Emit deterministic evidence-timeline explorer contract
    EvidenceTimelineContract,
    /// Emit deterministic keyboard-flow transcript for timeline drill-down smoke flow
    EvidenceTimelineSmoke,
    /// Emit deterministic scenario-coverage packs contract for Track 3 e2e suites
    ScenarioCoveragePackContract,
    /// Emit deterministic scenario-pack smoke report with transcript assertions
    ScenarioCoveragePackSmoke(DoctorScenarioCoveragePackSmokeArgs),
    /// Export advanced diagnostics reports to deterministic markdown/json artifacts
    ReportExport(DoctorReportExportArgs),
    /// Export core diagnostics reports into FrankenSuite evidence/decision artifacts
    FrankenExport(DoctorFrankenExportArgs),
}

#[derive(Args, Debug)]
struct DoctorScanWorkspaceArgs {
    /// Workspace root to scan
    #[arg(long = "root", default_value = ".")]
    root: PathBuf,
}

#[derive(Args, Debug)]
struct DoctorAnalyzeInvariantsArgs {
    /// Workspace root to scan and analyze
    #[arg(long = "root", default_value = ".")]
    root: PathBuf,
}

#[derive(Args, Debug)]
struct DoctorAnalyzeLockContentionArgs {
    /// Workspace root to scan and analyze
    #[arg(long = "root", default_value = ".")]
    root: PathBuf,
}

#[derive(Args, Debug)]
struct DoctorWasmDependencyAuditArgs {
    /// Workspace root where Cargo.toml lives
    #[arg(long = "root", default_value = ".")]
    root: PathBuf,

    /// Compilation target for dependency closure audit
    #[arg(long = "target", default_value = "wasm32-unknown-unknown")]
    target: String,

    /// Additional forbidden crates (comma-separated)
    #[arg(long = "forbidden", value_delimiter = ',')]
    forbidden: Vec<String>,

    /// Optional report path to write JSON output
    #[arg(long = "report")]
    report: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct DoctorFrankenExportArgs {
    /// Optional path to a core diagnostics report JSON payload
    #[arg(long = "report")]
    report: Option<PathBuf>,

    /// Optional fixture id from `doctor report-contract` bundle
    #[arg(long = "fixture-id")]
    fixture_id: Option<String>,

    /// Output directory for export artifacts
    #[arg(
        long = "out-dir",
        default_value = "target/e2e-results/doctor_frankensuite_export/artifacts"
    )]
    out_dir: PathBuf,
}

#[derive(Args, Debug)]
struct DoctorScenarioCoveragePackSmokeArgs {
    /// Scenario-pack selection mode (`all`, `cancellation`, `retry`, `degraded_dependency`, `recovery`)
    #[arg(long = "selection-mode", default_value = "all")]
    selection_mode: String,

    /// Deterministic root seed used for pack transcript generation
    #[arg(long = "seed", default_value = "seed-4242")]
    seed: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
#[value(rename_all = "kebab-case")]
enum DoctorReportExportFormat {
    Markdown,
    Json,
}

impl DoctorReportExportFormat {
    fn extension(self) -> &'static str {
        match self {
            Self::Markdown => "md",
            Self::Json => "json",
        }
    }

    fn as_cli_value(self) -> &'static str {
        match self {
            Self::Markdown => "markdown",
            Self::Json => "json",
        }
    }
}

#[derive(Args, Debug)]
struct DoctorReportExportArgs {
    /// Optional advanced fixture id from `doctor` report bundle
    #[arg(long = "fixture-id")]
    fixture_id: Option<String>,

    /// Output directory for markdown/json report artifacts
    #[arg(
        long = "out-dir",
        default_value = "target/e2e-results/doctor_report_export/artifacts"
    )]
    out_dir: PathBuf,

    /// Export format(s): markdown and/or json
    #[arg(
        long = "format",
        value_enum,
        value_delimiter = ',',
        default_values_t = [DoctorReportExportFormat::Markdown, DoctorReportExportFormat::Json]
    )]
    formats: Vec<DoctorReportExportFormat>,
}

// =========================================================================

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
struct ConformanceMatrixReport {
    root: String,
    matrix: TraceabilityMatrix,
    coverage_percentage: f64,
    missing_sections: Vec<String>,
    warnings: Vec<ScanWarning>,
}

impl Outputtable for ConformanceMatrixReport {
    fn human_format(&self) -> String {
        let mut matrix = self.matrix.clone();
        let mut output = matrix.to_markdown();

        if !self.warnings.is_empty() {
            output.push_str("\n## Warnings\n\n");
            for warning in &self.warnings {
                use std::fmt::Write;
                let _ = writeln!(
                    output,
                    "- {}:{}: {}",
                    warning.file.display(),
                    warning.line,
                    warning.message
                );
            }
        }

        output
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
        Command::Conformance(args) => run_conformance(args, output),
        Command::Lab(args) => run_lab(args, output),
        Command::Doctor(args) => run_doctor(args, output),
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
            let valid = out.valid;
            output.write(&out).map_err(|e| {
                CliError::new("output_error", "Failed to write output").detail(e.to_string())
            })?;
            if !valid {
                return Err(
                    CliError::new("verification_failed", "Trace verification failed")
                        .exit_code(ExitCode::TEST_FAILURE),
                );
            }
            Ok(())
        }
        TraceCommand::Diff(args) => {
            let out = trace_diff(&args.file_a, &args.file_b)?;
            let diverged = out.diverged;
            output.write(&out).map_err(|e| {
                CliError::new("output_error", "Failed to write output").detail(e.to_string())
            })?;
            if diverged {
                return Err(CliError::new("trace_divergence", "Traces diverged")
                    .exit_code(ExitCode::TRACE_MISMATCH));
            }
            Ok(())
        }
        TraceCommand::Export(args) => {
            export_trace(&args.file, args.format)?;
            Ok(())
        }
    }
}

fn run_conformance(args: ConformanceArgs, output: &mut Output) -> Result<(), CliError> {
    match args.command {
        ConformanceCommand::Matrix(args) => conformance_matrix(args, output),
    }
}

// =========================================================================
// Lab (FrankenLab) handlers (bd-1hu19.4)
// =========================================================================

fn run_lab(args: LabArgs, output: &mut Output) -> Result<(), CliError> {
    match args.command {
        LabCommand::Run(run_args) => lab_run(&run_args, output),
        LabCommand::Validate(validate_args) => lab_validate(&validate_args, output),
        LabCommand::Replay(replay_args) => lab_replay(&replay_args, output),
        LabCommand::Explore(explore_args) => lab_explore(&explore_args, output),
    }
}

fn run_doctor(args: DoctorArgs, output: &mut Output) -> Result<(), CliError> {
    match args.command {
        DoctorCommand::ScanWorkspace(scan_args) => doctor_scan_workspace(&scan_args, output),
        DoctorCommand::AnalyzeInvariants(analyze_args) => {
            doctor_analyze_invariants(&analyze_args, output)
        }
        DoctorCommand::AnalyzeLockContention(analyze_args) => {
            doctor_analyze_lock_contention(&analyze_args, output)
        }
        DoctorCommand::WasmDependencyAudit(audit_args) => {
            doctor_wasm_dependency_audit(&audit_args, output)
        }
        DoctorCommand::OperatorModel => doctor_operator_model(output),
        DoctorCommand::ScreenContracts => doctor_screen_contracts(output),
        DoctorCommand::LoggingContract => doctor_logging_contract(output),
        DoctorCommand::RemediationContract => doctor_remediation_contract(output),
        DoctorCommand::ReportContract => doctor_report_contract(output),
        DoctorCommand::EvidenceTimelineContract => doctor_evidence_timeline_contract(output),
        DoctorCommand::EvidenceTimelineSmoke => doctor_evidence_timeline_smoke(output),
        DoctorCommand::ScenarioCoveragePackContract => {
            doctor_scenario_coverage_pack_contract(output)
        }
        DoctorCommand::ScenarioCoveragePackSmoke(smoke_args) => {
            doctor_scenario_coverage_pack_smoke(&smoke_args, output)
        }
        DoctorCommand::ReportExport(export_args) => doctor_report_export(&export_args, output),
        DoctorCommand::FrankenExport(export_args) => doctor_franken_export(&export_args, output),
    }
}

fn doctor_scan_workspace(
    args: &DoctorScanWorkspaceArgs,
    output: &mut Output,
) -> Result<(), CliError> {
    let report: WorkspaceScanReport = scan_workspace(&args.root).map_err(|err| {
        CliError::new("doctor_scan_error", "Failed to scan workspace")
            .detail(err.to_string())
            .context("root", args.root.display().to_string())
            .exit_code(ExitCode::RUNTIME_ERROR)
    })?;

    output.write(&report).map_err(|err| {
        CliError::new("output_error", "Failed to write output").detail(err.to_string())
    })?;
    Ok(())
}

fn doctor_analyze_invariants(
    args: &DoctorAnalyzeInvariantsArgs,
    output: &mut Output,
) -> Result<(), CliError> {
    let report: WorkspaceScanReport = scan_workspace(&args.root).map_err(|err| {
        CliError::new(
            "doctor_scan_error",
            "Failed to scan workspace for invariant analysis",
        )
        .detail(err.to_string())
        .context("root", args.root.display().to_string())
        .exit_code(ExitCode::RUNTIME_ERROR)
    })?;
    let analysis: InvariantAnalyzerReport = analyze_workspace_invariants(&report);
    output.write(&analysis).map_err(|err| {
        CliError::new("output_error", "Failed to write output").detail(err.to_string())
    })?;
    Ok(())
}

fn doctor_analyze_lock_contention(
    args: &DoctorAnalyzeLockContentionArgs,
    output: &mut Output,
) -> Result<(), CliError> {
    let report: WorkspaceScanReport = scan_workspace(&args.root).map_err(|err| {
        CliError::new(
            "doctor_scan_error",
            "Failed to scan workspace for lock-contention analysis",
        )
        .detail(err.to_string())
        .context("root", args.root.display().to_string())
        .exit_code(ExitCode::RUNTIME_ERROR)
    })?;
    let analysis: LockContentionAnalyzerReport = analyze_workspace_lock_contention(&report);
    output.write(&analysis).map_err(|err| {
        CliError::new("output_error", "Failed to write output").detail(err.to_string())
    })?;
    Ok(())
}

fn doctor_operator_model(output: &mut Output) -> Result<(), CliError> {
    let contract: OperatorModelContract = operator_model_contract();
    output.write(&contract).map_err(|err| {
        CliError::new("output_error", "Failed to write output").detail(err.to_string())
    })?;
    Ok(())
}

fn doctor_screen_contracts(output: &mut Output) -> Result<(), CliError> {
    let contract: ScreenEngineContract = screen_engine_contract();
    output.write(&contract).map_err(|err| {
        CliError::new("output_error", "Failed to write output").detail(err.to_string())
    })?;
    Ok(())
}

fn doctor_logging_contract(output: &mut Output) -> Result<(), CliError> {
    let contract: StructuredLoggingContract = structured_logging_contract();
    output.write(&contract).map_err(|err| {
        CliError::new("output_error", "Failed to write output").detail(err.to_string())
    })?;
    Ok(())
}

fn doctor_remediation_contract(output: &mut Output) -> Result<(), CliError> {
    let bundle: RemediationRecipeBundle = remediation_recipe_bundle();
    output.write(&bundle).map_err(|err| {
        CliError::new("output_error", "Failed to write output").detail(err.to_string())
    })?;
    Ok(())
}

fn doctor_report_contract(output: &mut Output) -> Result<(), CliError> {
    let bundle: CoreDiagnosticsReportBundle = core_diagnostics_report_bundle();
    output.write(&bundle).map_err(|err| {
        CliError::new("output_error", "Failed to write output").detail(err.to_string())
    })?;
    Ok(())
}

fn doctor_evidence_timeline_contract(output: &mut Output) -> Result<(), CliError> {
    let contract: EvidenceTimelineContract = evidence_timeline_contract();
    let payload = DoctorEvidenceTimelineContractOutput { contract };
    output.write(&payload).map_err(|err| {
        CliError::new("output_error", "Failed to write output").detail(err.to_string())
    })?;
    Ok(())
}

fn doctor_evidence_timeline_smoke(output: &mut Output) -> Result<(), CliError> {
    let contract: EvidenceTimelineContract = evidence_timeline_contract();
    let transcript: EvidenceTimelineWorkflowTranscript =
        run_evidence_timeline_keyboard_flow_smoke(&contract).map_err(|err| {
            CliError::new(
                "doctor_timeline_smoke_error",
                "Failed to build evidence timeline smoke transcript",
            )
            .detail(err)
            .exit_code(ExitCode::RUNTIME_ERROR)
        })?;
    let payload = DoctorEvidenceTimelineSmokeOutput { transcript };
    output.write(&payload).map_err(|err| {
        CliError::new("output_error", "Failed to write output").detail(err.to_string())
    })?;
    Ok(())
}

fn doctor_scenario_coverage_pack_contract(output: &mut Output) -> Result<(), CliError> {
    let contract: DoctorScenarioCoveragePacksContract = doctor_scenario_coverage_packs_contract();
    let payload = DoctorScenarioCoveragePackContractOutput { contract };
    output.write(&payload).map_err(|err| {
        CliError::new("output_error", "Failed to write output").detail(err.to_string())
    })?;
    Ok(())
}

fn doctor_scenario_coverage_pack_smoke(
    args: &DoctorScenarioCoveragePackSmokeArgs,
    output: &mut Output,
) -> Result<(), CliError> {
    let contract: DoctorScenarioCoveragePacksContract = doctor_scenario_coverage_packs_contract();
    let report: DoctorScenarioCoveragePackSmokeReport =
        build_doctor_scenario_coverage_pack_smoke_report(
            &contract,
            &args.selection_mode,
            &args.seed,
        )
        .map_err(|err| {
            CliError::new(
                "doctor_scenario_coverage_pack_smoke_error",
                "Failed to build scenario coverage-pack smoke report",
            )
            .detail(err)
            .context("selection_mode", args.selection_mode.clone())
            .context("seed", args.seed.clone())
            .exit_code(ExitCode::RUNTIME_ERROR)
        })?;
    let payload = DoctorScenarioCoveragePackSmokeOutput { report };
    output.write(&payload).map_err(|err| {
        CliError::new("output_error", "Failed to write output").detail(err.to_string())
    })?;
    Ok(())
}

#[derive(Debug, serde::Serialize, PartialEq, Eq)]
struct DoctorReportExportOutput {
    schema_version: String,
    core_schema_version: String,
    extension_schema_version: String,
    export_root: String,
    formats: Vec<String>,
    exports: Vec<DoctorReportExportArtifact>,
    rerun_commands: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
struct DoctorReportExportArtifact {
    fixture_id: String,
    report_id: String,
    output_files: Vec<String>,
    finding_count: usize,
    evidence_count: usize,
    command_count: usize,
    remediation_outcome_count: usize,
    validation_status: String,
}

#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
struct DoctorReportExportDocument {
    schema_version: String,
    fixture_id: String,
    report_id: String,
    core_contract_version: String,
    extension_contract_version: String,
    summary: CoreDiagnosticsSummary,
    findings: Vec<asupersync::cli::CoreDiagnosticsFinding>,
    evidence_links: Vec<asupersync::cli::CoreDiagnosticsEvidence>,
    command_provenance: Vec<asupersync::cli::CoreDiagnosticsCommand>,
    remediation_outcomes: Vec<AdvancedRemediationDelta>,
    trust_transitions: Vec<AdvancedTrustTransition>,
    collaboration_trail: Vec<AdvancedCollaborationEntry>,
    troubleshooting_playbooks: Vec<AdvancedTroubleshootingPlaybook>,
    provenance: asupersync::cli::CoreDiagnosticsProvenance,
}

impl Outputtable for DoctorReportExportOutput {
    fn human_format(&self) -> String {
        let mut lines = vec![
            format!("Schema: {}", self.schema_version),
            format!("Core schema: {}", self.core_schema_version),
            format!("Extension schema: {}", self.extension_schema_version),
            format!("Export root: {}", self.export_root),
            format!("Formats: {}", self.formats.join(", ")),
            format!("Artifacts: {}", self.exports.len()),
        ];
        for artifact in &self.exports {
            lines.push(format!(
                "  - {} [{}] files={} findings={} evidence={} commands={} remediation={} status={}",
                artifact.fixture_id,
                artifact.report_id,
                artifact.output_files.len(),
                artifact.finding_count,
                artifact.evidence_count,
                artifact.command_count,
                artifact.remediation_outcome_count,
                artifact.validation_status
            ));
            for file in &artifact.output_files {
                lines.push(format!("    - {file}"));
            }
        }
        lines.push("Rerun commands:".to_string());
        for command in &self.rerun_commands {
            lines.push(format!("  {command}"));
        }
        lines.join("\n")
    }
}

#[derive(Debug, serde::Serialize, PartialEq, Eq)]
struct DoctorEvidenceTimelineContractOutput {
    contract: EvidenceTimelineContract,
}

impl Outputtable for DoctorEvidenceTimelineContractOutput {
    fn human_format(&self) -> String {
        serde_json::to_string_pretty(&self.contract)
            .unwrap_or_else(|_| "failed to render evidence timeline contract".to_string())
    }
}

#[derive(Debug, serde::Serialize, PartialEq, Eq)]
struct DoctorEvidenceTimelineSmokeOutput {
    transcript: EvidenceTimelineWorkflowTranscript,
}

impl Outputtable for DoctorEvidenceTimelineSmokeOutput {
    fn human_format(&self) -> String {
        serde_json::to_string_pretty(&self.transcript)
            .unwrap_or_else(|_| "failed to render evidence timeline smoke transcript".to_string())
    }
}

#[derive(Debug, serde::Serialize, PartialEq, Eq)]
struct DoctorScenarioCoveragePackContractOutput {
    contract: DoctorScenarioCoveragePacksContract,
}

impl Outputtable for DoctorScenarioCoveragePackContractOutput {
    fn human_format(&self) -> String {
        serde_json::to_string_pretty(&self.contract).unwrap_or_else(|_| {
            "failed to render scenario coverage-pack contract payload".to_string()
        })
    }
}

#[derive(Debug, serde::Serialize, PartialEq, Eq)]
struct DoctorScenarioCoveragePackSmokeOutput {
    report: DoctorScenarioCoveragePackSmokeReport,
}

impl Outputtable for DoctorScenarioCoveragePackSmokeOutput {
    fn human_format(&self) -> String {
        serde_json::to_string_pretty(&self.report)
            .unwrap_or_else(|_| "failed to render scenario coverage-pack smoke payload".to_string())
    }
}

#[derive(Debug, serde::Serialize, PartialEq, Eq)]
struct DoctorFrankenExportOutput {
    schema_version: String,
    source_schema_version: String,
    export_root: String,
    exports: Vec<DoctorFrankenExportArtifact>,
    rerun_commands: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
struct DoctorFrankenExportArtifact {
    fixture_id: String,
    report_id: String,
    trace_id: String,
    evidence_jsonl: String,
    decision_json: String,
    evidence_count: usize,
    decision_count: usize,
    validation_status: String,
}

impl Outputtable for DoctorFrankenExportOutput {
    fn human_format(&self) -> String {
        let mut lines = vec![
            format!("Schema: {}", self.schema_version),
            format!("Source schema: {}", self.source_schema_version),
            format!("Export root: {}", self.export_root),
            format!("Artifacts: {}", self.exports.len()),
        ];
        for artifact in &self.exports {
            lines.push(format!(
                "  - {}: evidence={} decision={} status={}",
                artifact.fixture_id,
                artifact.evidence_jsonl,
                artifact.decision_json,
                artifact.validation_status
            ));
        }
        lines.push("Rerun commands:".to_string());
        for command in &self.rerun_commands {
            lines.push(format!("  {command}"));
        }
        lines.join("\n")
    }
}

fn doctor_report_export(
    args: &DoctorReportExportArgs,
    output: &mut Output,
) -> Result<(), CliError> {
    let formats = normalize_requested_report_export_formats(&args.formats)?;
    fs::create_dir_all(&args.out_dir).map_err(|err| {
        CliError::new("doctor_export_error", "Failed to create export directory")
            .detail(err.to_string())
            .context("path", args.out_dir.display().to_string())
            .exit_code(ExitCode::RUNTIME_ERROR)
    })?;

    let (bundle, fixtures) = select_advanced_fixtures_for_report_export(args)?;
    let mut exports = Vec::with_capacity(fixtures.len());
    for fixture in fixtures {
        exports.push(export_advanced_report_fixture(
            &bundle,
            &fixture,
            &formats,
            &args.out_dir,
        )?);
    }
    exports.sort_by(|left, right| left.fixture_id.cmp(&right.fixture_id));

    let format_arg = formats
        .iter()
        .map(|format| format.as_cli_value())
        .collect::<Vec<_>>()
        .join(",");
    let fixture_suffix = args
        .fixture_id
        .as_ref()
        .map_or_else(String::new, |fixture_id| {
            format!(" --fixture-id {fixture_id}")
        });
    let rerun_commands = vec![
        format!(
            "asupersync doctor report-export --out-dir {} --format {}{}",
            args.out_dir.display(),
            format_arg,
            fixture_suffix
        ),
        "asupersync doctor report-contract".to_string(),
    ];
    let format_names = formats
        .iter()
        .map(|format| format.as_cli_value().to_string())
        .collect::<Vec<_>>();
    let payload = DoctorReportExportOutput {
        schema_version: "doctor-report-export-v1".to_string(),
        core_schema_version: bundle.core_contract.contract_version.clone(),
        extension_schema_version: bundle.extension_contract.contract_version.clone(),
        export_root: args.out_dir.display().to_string(),
        formats: format_names,
        exports,
        rerun_commands,
    };
    output.write(&payload).map_err(output_cli_error)
}

fn normalize_requested_report_export_formats(
    requested: &[DoctorReportExportFormat],
) -> Result<Vec<DoctorReportExportFormat>, CliError> {
    let mut formats = requested.to_vec();
    formats.sort_by_key(|format| format.as_cli_value());
    formats.dedup();
    if formats.is_empty() {
        return Err(
            CliError::new("invalid_argument", "At least one --format must be provided")
                .context("supported_formats", "markdown,json".to_string())
                .exit_code(ExitCode::USER_ERROR),
        );
    }
    Ok(formats)
}

fn select_advanced_fixtures_for_report_export(
    args: &DoctorReportExportArgs,
) -> Result<
    (
        AdvancedDiagnosticsReportBundle,
        Vec<AdvancedDiagnosticsFixture>,
    ),
    CliError,
> {
    let bundle = advanced_diagnostics_report_bundle();
    validate_core_diagnostics_report_contract(&bundle.core_contract).map_err(|reason| {
        CliError::new(
            "doctor_export_error",
            "Core diagnostics report contract validation failed",
        )
        .detail(reason)
        .exit_code(ExitCode::RUNTIME_ERROR)
    })?;
    validate_advanced_diagnostics_report_extension_contract(&bundle.extension_contract).map_err(
        |reason| {
            CliError::new(
                "doctor_export_error",
                "Advanced diagnostics extension contract validation failed",
            )
            .detail(reason)
            .exit_code(ExitCode::RUNTIME_ERROR)
        },
    )?;

    let mut fixtures = if let Some(fixture_id) = &args.fixture_id {
        if let Some(fixture) = bundle
            .fixtures
            .iter()
            .find(|entry| entry.fixture_id == *fixture_id)
        {
            vec![fixture.clone()]
        } else {
            let mut available = bundle
                .fixtures
                .iter()
                .map(|fixture| fixture.fixture_id.as_str())
                .collect::<Vec<_>>();
            available.sort_unstable();
            return Err(
                CliError::new("invalid_argument", "Unknown --fixture-id value")
                    .detail(fixture_id.clone())
                    .context("available_fixtures", available.join(", "))
                    .exit_code(ExitCode::USER_ERROR),
            );
        }
    } else {
        bundle.fixtures.clone()
    };
    fixtures.sort_by(|left, right| left.fixture_id.cmp(&right.fixture_id));
    Ok((bundle, fixtures))
}

fn export_advanced_report_fixture(
    bundle: &AdvancedDiagnosticsReportBundle,
    fixture: &AdvancedDiagnosticsFixture,
    formats: &[DoctorReportExportFormat],
    out_dir: &Path,
) -> Result<DoctorReportExportArtifact, CliError> {
    let document = build_report_export_document(bundle, fixture)?;
    let export_stem = sanitize_export_stem(fixture.fixture_id.as_str());
    let mut output_files = Vec::with_capacity(formats.len());
    for format in formats {
        let path = out_dir.join(format!(
            "{export_stem}_report_export.{}",
            format.extension()
        ));
        match format {
            DoctorReportExportFormat::Json => write_report_export_json(&path, &document)?,
            DoctorReportExportFormat::Markdown => write_report_export_markdown(&path, &document)?,
        }
        output_files.push(path.display().to_string());
    }
    output_files.sort();
    Ok(DoctorReportExportArtifact {
        fixture_id: document.fixture_id.clone(),
        report_id: document.report_id.clone(),
        output_files,
        finding_count: document.findings.len(),
        evidence_count: document.evidence_links.len(),
        command_count: document.command_provenance.len(),
        remediation_outcome_count: document.remediation_outcomes.len(),
        validation_status: "valid".to_string(),
    })
}

fn build_report_export_document(
    bundle: &AdvancedDiagnosticsReportBundle,
    fixture: &AdvancedDiagnosticsFixture,
) -> Result<DoctorReportExportDocument, CliError> {
    validate_advanced_diagnostics_report_extension(
        &fixture.extension,
        &fixture.core_report,
        &bundle.extension_contract,
        &bundle.core_contract,
    )
    .map_err(|reason| {
        CliError::new(
            "doctor_export_error",
            "Advanced diagnostics report extension validation failed",
        )
        .detail(reason)
        .context("fixture_id", fixture.fixture_id.clone())
        .context("report_id", fixture.core_report.report_id.clone())
        .exit_code(ExitCode::USER_ERROR)
    })?;

    let mut findings = fixture.core_report.findings.clone();
    for finding in &mut findings {
        finding.command_refs.sort();
        finding.evidence_refs.sort();
    }
    findings.sort_by(|left, right| left.finding_id.cmp(&right.finding_id));

    let mut evidence_links = fixture.core_report.evidence.clone();
    evidence_links.sort_by(|left, right| left.evidence_id.cmp(&right.evidence_id));

    let mut command_provenance = fixture.core_report.commands.clone();
    command_provenance.sort_by(|left, right| left.command_id.cmp(&right.command_id));

    let mut remediation_outcomes = fixture.extension.remediation_deltas.clone();
    for remediation in &mut remediation_outcomes {
        remediation.verification_evidence_refs.sort();
    }
    remediation_outcomes.sort_by(|left, right| left.delta_id.cmp(&right.delta_id));

    let mut trust_transitions = fixture.extension.trust_transitions.clone();
    trust_transitions.sort_by(|left, right| left.transition_id.cmp(&right.transition_id));

    let mut collaboration_trail = fixture.extension.collaboration_trail.clone();
    collaboration_trail.sort_by(|left, right| left.entry_id.cmp(&right.entry_id));

    let mut troubleshooting_playbooks = fixture.extension.troubleshooting_playbooks.clone();
    for playbook in &mut troubleshooting_playbooks {
        playbook.command_refs.sort();
        playbook.evidence_refs.sort();
    }
    troubleshooting_playbooks.sort_by(|left, right| left.playbook_id.cmp(&right.playbook_id));

    Ok(DoctorReportExportDocument {
        schema_version: "doctor-report-export-v1".to_string(),
        fixture_id: fixture.fixture_id.clone(),
        report_id: fixture.core_report.report_id.clone(),
        core_contract_version: bundle.core_contract.contract_version.clone(),
        extension_contract_version: bundle.extension_contract.contract_version.clone(),
        summary: fixture.core_report.summary.clone(),
        findings,
        evidence_links,
        command_provenance,
        remediation_outcomes,
        trust_transitions,
        collaboration_trail,
        troubleshooting_playbooks,
        provenance: fixture.core_report.provenance.clone(),
    })
}

fn write_report_export_json(
    path: &Path,
    document: &DoctorReportExportDocument,
) -> Result<(), CliError> {
    let payload = serde_json::to_vec_pretty(document).map_err(|err| {
        CliError::new(
            "doctor_export_error",
            "Failed to serialize report export JSON payload",
        )
        .detail(err.to_string())
        .context("path", path.display().to_string())
        .exit_code(ExitCode::INTERNAL_ERROR)
    })?;
    fs::write(path, payload).map_err(|err| {
        CliError::new(
            "doctor_export_error",
            "Failed to write report export JSON payload",
        )
        .detail(err.to_string())
        .context("path", path.display().to_string())
        .exit_code(ExitCode::RUNTIME_ERROR)
    })
}

fn write_report_export_markdown(
    path: &Path,
    document: &DoctorReportExportDocument,
) -> Result<(), CliError> {
    let markdown = render_doctor_report_markdown(document);
    fs::write(path, markdown).map_err(|err| {
        CliError::new(
            "doctor_export_error",
            "Failed to write report export markdown payload",
        )
        .detail(err.to_string())
        .context("path", path.display().to_string())
        .exit_code(ExitCode::RUNTIME_ERROR)
    })
}

fn render_doctor_report_markdown(document: &DoctorReportExportDocument) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Doctor Diagnostics Export: {}", document.fixture_id);
    let _ = writeln!(out);
    let _ = writeln!(out, "- Schema: {}", document.schema_version);
    let _ = writeln!(out, "- Core contract: {}", document.core_contract_version);
    let _ = writeln!(
        out,
        "- Extension contract: {}",
        document.extension_contract_version
    );
    let _ = writeln!(out, "- Report ID: {}", document.report_id);
    let _ = writeln!(out, "- Run ID: {}", document.provenance.run_id);
    let _ = writeln!(out, "- Scenario ID: {}", document.provenance.scenario_id);
    let _ = writeln!(out, "- Trace ID: {}", document.provenance.trace_id);
    let _ = writeln!(out, "- Seed: {}", document.provenance.seed);
    let _ = writeln!(out);
    let _ = writeln!(out, "## Summary");
    let _ = writeln!(out);
    let _ = writeln!(out, "- Status: {}", document.summary.status);
    let _ = writeln!(out, "- Outcome: {}", document.summary.overall_outcome);
    let _ = writeln!(out, "- Total findings: {}", document.summary.total_findings);
    let _ = writeln!(
        out,
        "- Critical findings: {}",
        document.summary.critical_findings
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "## Findings");
    let _ = writeln!(out);
    for finding in &document.findings {
        let _ = writeln!(
            out,
            "- `{}` {} (severity={}, status={})",
            finding.finding_id, finding.title, finding.severity, finding.status
        );
        let _ = writeln!(
            out,
            "  - evidence_refs: {}",
            finding.evidence_refs.join(", ")
        );
        let _ = writeln!(out, "  - command_refs: {}", finding.command_refs.join(", "));
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "## Evidence Links");
    let _ = writeln!(out);
    for evidence in &document.evidence_links {
        let _ = writeln!(
            out,
            "- `{}` source={} outcome={} artifact={} replay={}",
            evidence.evidence_id,
            evidence.source,
            evidence.outcome_class,
            evidence.artifact_pointer,
            evidence.replay_pointer
        );
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "## Command Provenance");
    let _ = writeln!(out);
    for command in &document.command_provenance {
        let _ = writeln!(
            out,
            "- `{}` [{}] exit={} outcome={} command=`{}`",
            command.command_id,
            command.tool,
            command.exit_code,
            command.outcome_class,
            command.command
        );
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "## Remediation Outcomes");
    let _ = writeln!(out);
    for delta in &document.remediation_outcomes {
        let _ = writeln!(
            out,
            "- `{}` finding={} {} -> {} outcome={} class={} dimension={}",
            delta.delta_id,
            delta.finding_id,
            delta.previous_status,
            delta.next_status,
            delta.delta_outcome,
            delta.mapped_taxonomy_class,
            delta.mapped_taxonomy_dimension
        );
        let _ = writeln!(
            out,
            "  - verification_evidence_refs: {}",
            delta.verification_evidence_refs.join(", ")
        );
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "## Trust Transitions");
    let _ = writeln!(out);
    for transition in &document.trust_transitions {
        let _ = writeln!(
            out,
            "- `{}` stage={} {} -> {} outcome={} severity={} rationale={}",
            transition.transition_id,
            transition.stage,
            transition.previous_score,
            transition.next_score,
            transition.outcome_class,
            transition.mapped_taxonomy_severity,
            transition.rationale
        );
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "## Collaboration Trail");
    let _ = writeln!(out);
    for entry in &document.collaboration_trail {
        let _ = writeln!(
            out,
            "- `{}` channel={} actor={} action={} thread={} message={} bead={}",
            entry.entry_id,
            entry.channel,
            entry.actor,
            entry.action,
            entry.thread_id,
            entry.message_ref,
            entry.bead_ref
        );
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "## Troubleshooting Playbooks");
    let _ = writeln!(out);
    for playbook in &document.troubleshooting_playbooks {
        let _ = writeln!(
            out,
            "- `{}` {} (class={}, severity={})",
            playbook.playbook_id,
            playbook.title,
            playbook.trigger_taxonomy_class,
            playbook.trigger_taxonomy_severity
        );
        let _ = writeln!(
            out,
            "  - ordered_steps: {}",
            playbook.ordered_steps.join(" -> ")
        );
        let _ = writeln!(
            out,
            "  - command_refs: {}",
            playbook.command_refs.join(", ")
        );
        let _ = writeln!(
            out,
            "  - evidence_refs: {}",
            playbook.evidence_refs.join(", ")
        );
    }
    out
}

fn doctor_franken_export(
    args: &DoctorFrankenExportArgs,
    output: &mut Output,
) -> Result<(), CliError> {
    let reports = select_core_reports_for_export(args)?;
    fs::create_dir_all(&args.out_dir).map_err(|err| {
        CliError::new("doctor_export_error", "Failed to create export directory")
            .detail(err.to_string())
            .context("path", args.out_dir.display().to_string())
            .exit_code(ExitCode::RUNTIME_ERROR)
    })?;

    let mut exports = Vec::with_capacity(reports.len());
    for (fixture_id, report) in reports {
        exports.push(export_core_report_to_franken_artifacts(
            fixture_id.as_str(),
            &report,
            &args.out_dir,
        )?);
    }
    exports.sort_by(|left, right| left.fixture_id.cmp(&right.fixture_id));

    let command_tail = if let Some(path) = &args.report {
        format!(" --report {}", path.display())
    } else if let Some(fixture_id) = &args.fixture_id {
        format!(" --fixture-id {fixture_id}")
    } else {
        String::new()
    };
    let rerun_commands = vec![
        format!(
            "asupersync doctor franken-export --out-dir {}{}",
            args.out_dir.display(),
            command_tail
        ),
        "asupersync doctor report-contract".to_string(),
    ];

    let payload = DoctorFrankenExportOutput {
        schema_version: "doctor-frankensuite-export-v1".to_string(),
        source_schema_version: "doctor-core-report-v1".to_string(),
        export_root: args.out_dir.display().to_string(),
        exports,
        rerun_commands,
    };
    output.write(&payload).map_err(output_cli_error)
}

fn select_core_reports_for_export(
    args: &DoctorFrankenExportArgs,
) -> Result<Vec<(String, CoreDiagnosticsReport)>, CliError> {
    if let Some(path) = &args.report {
        let report = load_core_report(path)?;
        return Ok(vec![(sanitize_export_stem(&report.report_id), report)]);
    }

    let bundle = core_diagnostics_report_bundle();
    if let Some(fixture_id) = &args.fixture_id {
        if let Some(fixture) = bundle.fixtures.iter().find(|f| f.fixture_id == *fixture_id) {
            return Ok(vec![(fixture.fixture_id.clone(), fixture.report.clone())]);
        }
        let mut available = bundle
            .fixtures
            .iter()
            .map(|fixture| fixture.fixture_id.as_str())
            .collect::<Vec<_>>();
        available.sort_unstable();
        return Err(
            CliError::new("invalid_argument", "Unknown --fixture-id value")
                .detail(fixture_id.clone())
                .context("available_fixtures", available.join(", "))
                .exit_code(ExitCode::USER_ERROR),
        );
    }

    Ok(bundle
        .fixtures
        .into_iter()
        .map(|fixture| (fixture.fixture_id, fixture.report))
        .collect())
}

fn load_core_report(path: &Path) -> Result<CoreDiagnosticsReport, CliError> {
    let raw = fs::read_to_string(path).map_err(|err| io_error(path, &err))?;
    let report: CoreDiagnosticsReport = serde_json::from_str(&raw).map_err(|err| {
        CliError::new(
            "doctor_export_error",
            "Failed to parse core diagnostics report JSON",
        )
        .detail(err.to_string())
        .context("path", path.display().to_string())
        .exit_code(ExitCode::USER_ERROR)
    })?;
    validate_exportable_core_report(&report)?;
    Ok(report)
}

fn validate_exportable_core_report(report: &CoreDiagnosticsReport) -> Result<(), CliError> {
    let contract = core_diagnostics_report_contract();
    validate_core_diagnostics_report(report, &contract).map_err(|reason| {
        CliError::new(
            "doctor_export_error",
            "Core diagnostics report validation failed",
        )
        .detail(reason)
        .context("report_id", report.report_id.clone())
        .exit_code(ExitCode::USER_ERROR)
    })?;
    if report.schema_version != "doctor-core-report-v1" {
        return Err(CliError::new(
            "doctor_export_error",
            "Unsupported core diagnostics report schema version",
        )
        .detail(report.schema_version.clone())
        .context("expected", "doctor-core-report-v1".to_string())
        .context("report_id", report.report_id.clone())
        .exit_code(ExitCode::USER_ERROR));
    }
    Ok(())
}

fn export_core_report_to_franken_artifacts(
    fixture_id: &str,
    report: &CoreDiagnosticsReport,
    out_dir: &Path,
) -> Result<DoctorFrankenExportArtifact, CliError> {
    validate_exportable_core_report(report)?;

    let mut evidence = report.evidence.clone();
    evidence.sort_by(|left, right| left.evidence_id.cmp(&right.evidence_id));

    let mut findings = report.findings.clone();
    findings.sort_by(|left, right| left.finding_id.cmp(&right.finding_id));

    let mut evidence_map = BTreeMap::new();
    for item in &evidence {
        evidence_map.insert(item.evidence_id.clone(), item.clone());
    }

    let evidence_ledgers = evidence
        .iter()
        .enumerate()
        .map(|(index, item)| build_evidence_ledger(report, item, index as u64))
        .collect::<Result<Vec<_>, _>>()?;

    let decisions = findings
        .iter()
        .enumerate()
        .map(|(index, finding)| {
            build_decision_audit_entry(report, finding, &evidence_map, index as u64)
        })
        .collect::<Vec<_>>();

    let export_stem = sanitize_export_stem(fixture_id);
    let evidence_path = out_dir.join(format!("{export_stem}_evidence.jsonl"));
    let decision_path = out_dir.join(format!("{export_stem}_decision.json"));

    write_evidence_jsonl(&evidence_path, &evidence_ledgers)?;
    write_decisions_json(&decision_path, &decisions)?;

    Ok(DoctorFrankenExportArtifact {
        fixture_id: fixture_id.to_string(),
        report_id: report.report_id.clone(),
        trace_id: report.provenance.trace_id.clone(),
        evidence_jsonl: evidence_path.display().to_string(),
        decision_json: decision_path.display().to_string(),
        evidence_count: evidence_ledgers.len(),
        decision_count: decisions.len(),
        validation_status: "valid".to_string(),
    })
}

fn build_evidence_ledger(
    report: &CoreDiagnosticsReport,
    evidence: &asupersync::cli::CoreDiagnosticsEvidence,
    index: u64,
) -> Result<EvidenceLedger, CliError> {
    let (
        posterior,
        promote_loss,
        hold_loss,
        chosen_action,
        chosen_expected_loss,
        calibration,
        fallback,
    ) = outcome_profile(evidence.outcome_class.as_str());
    let ts_unix_ms = stable_u64(
        format!(
            "{}:{}:{}:{}",
            report.report_id, report.provenance.generated_at, evidence.evidence_id, index
        )
        .as_str(),
    );

    EvidenceLedgerBuilder::new()
        .ts_unix_ms(ts_unix_ms)
        .component(evidence.source.as_str())
        .action(chosen_action)
        .posterior(vec![posterior.0, posterior.1])
        .expected_loss("promote", promote_loss)
        .expected_loss("hold", hold_loss)
        .chosen_expected_loss(chosen_expected_loss)
        .calibration_score(calibration)
        .fallback_active(fallback)
        .top_feature("evidence_id", 1.0)
        .top_feature("outcome_class", 0.8)
        .build()
        .map_err(|err| {
            CliError::new(
                "doctor_export_error",
                "Failed to build evidence ledger entry",
            )
            .detail(err.to_string())
            .context("report_id", report.report_id.clone())
            .context("evidence_id", evidence.evidence_id.clone())
            .exit_code(ExitCode::USER_ERROR)
        })
}

fn build_decision_audit_entry(
    report: &CoreDiagnosticsReport,
    finding: &asupersync::cli::CoreDiagnosticsFinding,
    evidence_map: &BTreeMap<String, asupersync::cli::CoreDiagnosticsEvidence>,
    index: u64,
) -> DecisionAuditEntry {
    let action_chosen = match finding.status.as_str() {
        "resolved" => "promote_fix",
        "in_progress" => "continue_investigation",
        _ => "hold_release",
    }
    .to_string();
    let severity_factor = match finding.severity.as_str() {
        "critical" => 0.85,
        "high" => 0.65,
        "medium" => 0.45,
        _ => 0.25,
    };
    let mut expected_loss_by_action = BTreeMap::new();
    expected_loss_by_action.insert("continue_investigation".to_string(), severity_factor * 0.35);
    expected_loss_by_action.insert("hold_release".to_string(), severity_factor * 0.20);
    expected_loss_by_action.insert("promote_fix".to_string(), severity_factor * 0.55);

    let expected_loss = expected_loss_by_action
        .get(action_chosen.as_str())
        .copied()
        .unwrap_or(severity_factor * 0.5);

    let trace_ref = finding
        .evidence_refs
        .iter()
        .find_map(|id| evidence_map.get(id))
        .map_or_else(
            || report.provenance.trace_id.clone(),
            |evidence| evidence.franken_trace_id.clone(),
        );

    let posterior_snapshot = if finding.status == "resolved" {
        vec![0.85, 0.15]
    } else {
        vec![0.35, 0.65]
    };

    let calibration_score = if finding.status == "resolved" {
        0.90
    } else {
        0.55
    };
    let fallback_active = finding.status != "resolved";
    let ts_unix_ms = stable_u64(
        format!(
            "{}:{}:{}:{}",
            report.report_id, report.provenance.generated_at, finding.finding_id, index
        )
        .as_str(),
    );

    DecisionAuditEntry {
        decision_id: DecisionId::from_raw(stable_u128(
            format!("decision:{}:{}", report.report_id, finding.finding_id).as_str(),
        )),
        trace_id: TraceId::from_raw(stable_u128(trace_ref.as_str())),
        contract_name: "doctor-core-diagnostics".to_string(),
        action_chosen,
        expected_loss,
        calibration_score,
        fallback_active,
        posterior_snapshot,
        expected_loss_by_action,
        ts_unix_ms,
    }
}

fn write_evidence_jsonl(path: &Path, entries: &[EvidenceLedger]) -> Result<(), CliError> {
    let mut payload = String::new();
    for entry in entries {
        let line = serde_json::to_string(entry).map_err(|err| {
            CliError::new(
                "doctor_export_error",
                "Failed to serialize evidence ledger entry",
            )
            .detail(err.to_string())
            .context("path", path.display().to_string())
            .exit_code(ExitCode::RUNTIME_ERROR)
        })?;
        payload.push_str(line.as_str());
        payload.push('\n');
    }
    fs::write(path, payload).map_err(|err| {
        CliError::new(
            "doctor_export_error",
            "Failed to write evidence JSONL artifact",
        )
        .detail(err.to_string())
        .context("path", path.display().to_string())
        .exit_code(ExitCode::RUNTIME_ERROR)
    })
}

fn write_decisions_json(path: &Path, entries: &[DecisionAuditEntry]) -> Result<(), CliError> {
    let payload = serde_json::to_vec_pretty(entries).map_err(|err| {
        CliError::new(
            "doctor_export_error",
            "Failed to serialize decision artifact payload",
        )
        .detail(err.to_string())
        .context("path", path.display().to_string())
        .exit_code(ExitCode::RUNTIME_ERROR)
    })?;
    fs::write(path, payload).map_err(|err| {
        CliError::new(
            "doctor_export_error",
            "Failed to write decision artifact payload",
        )
        .detail(err.to_string())
        .context("path", path.display().to_string())
        .exit_code(ExitCode::RUNTIME_ERROR)
    })
}

fn outcome_profile(outcome_class: &str) -> ((f64, f64), f64, f64, &'static str, f64, f64, bool) {
    match outcome_class {
        "pass" | "ok" => ((0.88, 0.12), 0.08, 0.25, "promote", 0.08, 0.93, false),
        "fail" | "error" => ((0.15, 0.85), 0.92, 0.12, "hold", 0.12, 0.42, true),
        _ => ((0.55, 0.45), 0.45, 0.30, "hold", 0.30, 0.68, true),
    }
}

fn stable_u64(input: &str) -> u64 {
    stable_u128(input) as u64
}

fn stable_u128(input: &str) -> u128 {
    const FNV_OFFSET_BASIS_128: u128 = 0x6C62_272E_07BB_0142_62B8_2175_6295_C58D;
    const FNV_PRIME_128: u128 = 0x0000_0000_0100_0000_0000_0000_0000_013B;

    let mut hash = FNV_OFFSET_BASIS_128;
    for byte in input.bytes() {
        hash ^= u128::from(byte);
        hash = hash.wrapping_mul(FNV_PRIME_128);
    }
    hash
}

fn sanitize_export_stem(input: &str) -> String {
    let mut normalized = String::with_capacity(input.len());
    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            normalized.push(ch);
        } else {
            normalized.push('-');
        }
    }
    normalized.trim_matches('-').to_string()
}

fn doctor_wasm_dependency_audit(
    args: &DoctorWasmDependencyAuditArgs,
    output: &mut Output,
) -> Result<(), CliError> {
    let forbidden = normalized_forbidden_crates(&args.forbidden);
    let tree = cargo_tree(&args.root, &args.target)?;
    let discovered = parse_unique_crates(&tree);

    let mut hits = Vec::new();
    for crate_name in discovered
        .iter()
        .filter(|name| is_forbidden_runtime_crate(name, &forbidden))
    {
        let chain =
            cargo_inverse_tree(&args.root, &args.target, crate_name).unwrap_or_else(|_| Vec::new());
        hits.push(WasmDependencyForbiddenHit {
            crate_name: crate_name.clone(),
            policy_decision: "forbidden".to_string(),
            decision_reason: "Forbidden async runtime ecosystem crate for Asupersync wasm profile"
                .to_string(),
            determinism_risk_score: determinism_risk_score(crate_name),
            remediation_recommendation: remediation_recommendation(crate_name),
            transitive_chain: chain,
        });
    }
    hits.sort_by(|a, b| a.crate_name.cmp(&b.crate_name));

    let report = WasmDependencyAuditReport {
        workspace_root: args.root.display().to_string(),
        target: args.target.clone(),
        forbidden_crates: forbidden,
        total_unique_crates: discovered.len(),
        forbidden_hits: hits,
        reproduction_commands: vec![
            format!(
                "cargo tree --target {} -e normal,build --prefix none",
                args.target
            ),
            format!(
                "cargo tree --target {} -e normal,build -i <crate> --prefix none",
                args.target
            ),
        ],
    };

    if let Some(path) = &args.report {
        let serialized = serde_json::to_string_pretty(&report).map_err(|err| {
            CliError::new(
                "serialization_error",
                "Failed to serialize wasm dependency report",
            )
            .detail(err.to_string())
        })?;
        fs::write(path, serialized).map_err(|err| io_error(path, &err))?;
    }

    output.write(&report).map_err(|err| {
        CliError::new("output_error", "Failed to write output").detail(err.to_string())
    })?;

    if !report.forbidden_hits.is_empty() {
        return Err(CliError::new(
            "forbidden_runtime_dependencies",
            "Found forbidden runtime dependencies in wasm target graph",
        )
        .detail(
            report
                .forbidden_hits
                .iter()
                .map(|hit| hit.crate_name.as_str())
                .collect::<Vec<_>>()
                .join(", "),
        )
        .exit_code(ExitCode::TEST_FAILURE));
    }

    Ok(())
}

fn normalized_forbidden_crates(extra_forbidden: &[String]) -> Vec<String> {
    const DEFAULT_FORBIDDEN: [&str; 7] = [
        "tokio",
        "hyper",
        "reqwest",
        "axum",
        "tower",
        "async-std",
        "smol",
    ];
    let mut set = BTreeSet::new();
    for name in DEFAULT_FORBIDDEN {
        let _ = set.insert(name.to_string());
    }
    for name in extra_forbidden.iter().map(String::as_str) {
        let normalized = name.trim().to_ascii_lowercase();
        if !normalized.is_empty() {
            let _ = set.insert(normalized);
        }
    }
    set.into_iter().collect()
}

fn cargo_tree(root: &Path, target: &str) -> Result<String, CliError> {
    run_process_capture(
        root,
        "cargo",
        &[
            "tree",
            "--target",
            target,
            "-e",
            "normal,build",
            "--prefix",
            "none",
        ],
        "Failed to collect cargo dependency tree",
    )
}

fn cargo_inverse_tree(
    root: &Path,
    target: &str,
    crate_name: &str,
) -> Result<Vec<String>, CliError> {
    let output = run_process_capture(
        root,
        "cargo",
        &[
            "tree",
            "--target",
            target,
            "-e",
            "normal,build",
            "-i",
            crate_name,
            "--prefix",
            "none",
        ],
        "Failed to collect inverse dependency chain",
    )?;
    Ok(output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .take(24)
        .map(ToString::to_string)
        .collect())
}

fn run_process_capture(
    root: &Path,
    program: &str,
    args: &[&str],
    error_message: &'static str,
) -> Result<String, CliError> {
    let output = ProcessCommand::new(program)
        .args(args)
        .current_dir(root)
        .output()
        .map_err(|err| {
            CliError::new("process_spawn_error", error_message)
                .detail(err.to_string())
                .context("program", program.to_string())
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        return Err(CliError::new("process_failure", error_message)
            .detail(stderr)
            .context("program", program.to_string())
            .context("args", args.join(" ")));
    }

    String::from_utf8(output.stdout).map_err(|err| {
        CliError::new("utf8_error", "Failed to decode process output as UTF-8")
            .detail(err.to_string())
            .context("program", program.to_string())
    })
}

fn parse_unique_crates(tree_output: &str) -> BTreeSet<String> {
    tree_output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter_map(parse_crate_name)
        .collect()
}

fn parse_crate_name(line: &str) -> Option<String> {
    let token = line.split_whitespace().next()?;
    if token.starts_with(char::is_numeric) {
        return None;
    }
    let name = token.trim_end_matches(':');
    if name
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
    {
        Some(name.to_ascii_lowercase())
    } else {
        None
    }
}

fn is_forbidden_runtime_crate(crate_name: &str, forbidden: &[String]) -> bool {
    forbidden.iter().any(|blocked| {
        crate_name == blocked || (blocked == "tokio" && crate_name.starts_with("tokio-"))
    })
}

fn determinism_risk_score(crate_name: &str) -> u8 {
    match crate_name {
        "tokio" | "hyper" | "reqwest" | "axum" | "async-std" | "smol" => 100,
        "tower" => 70,
        _ => 50,
    }
}

fn remediation_recommendation(crate_name: &str) -> String {
    match crate_name {
        "tokio" => "Remove Tokio runtime dependency; route through Asupersync runtime APIs".into(),
        "hyper" => "Use Asupersync native HTTP stack (`src/http/*`) instead of Hyper".into(),
        "reqwest" => "Replace reqwest usage with Asupersync net/http client surfaces".into(),
        "axum" => "Avoid Axum/Tokio stack; use Asupersync service/server surfaces".into(),
        "tower" => {
            "Allow only trait-level compatibility. Disable Tokio-adapter runtime integration".into()
        }
        "async-std" | "smol" => {
            "Remove alternate runtime dependency and unify execution under Asupersync".into()
        }
        _ => "Audit usage and replace with Asupersync-native deterministic equivalent".into(),
    }
}

#[derive(Debug, serde::Serialize)]
struct WasmDependencyAuditReport {
    workspace_root: String,
    target: String,
    forbidden_crates: Vec<String>,
    total_unique_crates: usize,
    forbidden_hits: Vec<WasmDependencyForbiddenHit>,
    reproduction_commands: Vec<String>,
}

impl Outputtable for WasmDependencyAuditReport {
    fn human_format(&self) -> String {
        let mut lines = vec![
            format!("Workspace root: {}", self.workspace_root),
            format!("Target: {}", self.target),
            format!("Unique crates: {}", self.total_unique_crates),
            format!("Forbidden list: {}", self.forbidden_crates.join(", ")),
        ];
        if self.forbidden_hits.is_empty() {
            lines.push("Status: PASS (no forbidden runtime crates found)".to_string());
        } else {
            lines.push(format!(
                "Status: FAIL ({} forbidden runtime crate(s) found)",
                self.forbidden_hits.len()
            ));
            for hit in &self.forbidden_hits {
                lines.push(format!(
                    "- {} (risk {}): {}",
                    hit.crate_name, hit.determinism_risk_score, hit.remediation_recommendation
                ));
            }
        }
        lines.push("Repro:".to_string());
        for cmd in &self.reproduction_commands {
            lines.push(format!("  {cmd}"));
        }
        lines.join("\n")
    }
}

#[derive(Debug, serde::Serialize)]
struct WasmDependencyForbiddenHit {
    crate_name: String,
    policy_decision: String,
    decision_reason: String,
    determinism_risk_score: u8,
    remediation_recommendation: String,
    transitive_chain: Vec<String>,
}

fn load_scenario(path: &Path) -> Result<asupersync::lab::scenario::Scenario, CliError> {
    let yaml = fs::read_to_string(path).map_err(|err| io_error(path, &err))?;
    serde_yaml::from_str(&yaml).map_err(|err| {
        CliError::new("scenario_parse_error", "Failed to parse scenario YAML")
            .detail(format!("{err}. Hint: check indentation and field names"))
            .context("path", path.display().to_string())
            .exit_code(ExitCode::RUNTIME_ERROR)
    })
}

fn scenario_runner_error(err: asupersync::lab::scenario_runner::ScenarioRunnerError) -> CliError {
    match err {
        asupersync::lab::scenario_runner::ScenarioRunnerError::Validation(errors) => {
            let detail = errors
                .iter()
                .map(|e| format!("- {e}"))
                .collect::<Vec<_>>()
                .join("\n");
            CliError::new("scenario_validation", "Scenario validation failed")
                .detail(detail)
                .exit_code(ExitCode::RUNTIME_ERROR)
        }
        asupersync::lab::scenario_runner::ScenarioRunnerError::UnknownOracle(name) => {
            CliError::new("unknown_oracle", "Unknown oracle name in scenario")
                .detail(format!(
                    "Oracle '{name}' not found. Available: {}",
                    asupersync::lab::meta::mutation::ALL_ORACLE_INVARIANTS.join(", ")
                ))
                .exit_code(ExitCode::RUNTIME_ERROR)
        }
        asupersync::lab::scenario_runner::ScenarioRunnerError::ReplayDivergence {
            seed,
            first,
            second,
        } => CliError::new(
            "replay_divergence",
            "Deterministic replay divergence detected",
        )
        .detail(format!(
            "Seed {seed}: run1(event_hash={}, steps={}) != run2(event_hash={}, steps={})",
            first.event_hash, first.steps, second.event_hash, second.steps,
        ))
        .exit_code(ExitCode::DETERMINISM_FAILURE),
    }
}

fn lab_run(args: &LabRunArgs, output: &mut Output) -> Result<(), CliError> {
    let scenario = load_scenario(&args.scenario)?;
    let result =
        asupersync::lab::scenario_runner::ScenarioRunner::run_with_seed(&scenario, args.seed)
            .map_err(scenario_runner_error)?;

    let passed = result.passed();

    if args.json {
        let json = result.to_json();
        let pretty = serde_json::to_string_pretty(&json).map_err(output_cli_error)?;
        writeln!(io::stdout(), "{pretty}").map_err(output_cli_error)?;
    } else {
        let report = LabRunOutput::from_result(&result);
        output.write(&report).map_err(|e| {
            CliError::new("output_error", "Failed to write output").detail(e.to_string())
        })?;
    }

    if !passed {
        return Err(
            CliError::new("scenario_failed", "Scenario assertions failed")
                .exit_code(ExitCode::TEST_FAILURE),
        );
    }

    Ok(())
}

fn lab_validate(args: &LabValidateArgs, output: &mut Output) -> Result<(), CliError> {
    let scenario = load_scenario(&args.scenario)?;
    let errors = scenario.validate();

    let report = LabValidateOutput {
        scenario: args.scenario.display().to_string(),
        scenario_id: scenario.id,
        valid: errors.is_empty(),
        errors: errors.iter().map(ToString::to_string).collect(),
    };

    if args.json {
        let json = serde_json::to_value(&report).map_err(output_cli_error)?;
        let pretty = serde_json::to_string_pretty(&json).map_err(output_cli_error)?;
        writeln!(io::stdout(), "{pretty}").map_err(output_cli_error)?;
    } else {
        output.write(&report).map_err(|e| {
            CliError::new("output_error", "Failed to write output").detail(e.to_string())
        })?;
    }

    if !errors.is_empty() {
        return Err(
            CliError::new("scenario_invalid", "Scenario validation failed")
                .exit_code(ExitCode::RUNTIME_ERROR),
        );
    }

    Ok(())
}

fn lab_replay(args: &LabReplayArgs, output: &mut Output) -> Result<(), CliError> {
    let scenario = load_scenario(&args.scenario)?;
    let first =
        asupersync::lab::scenario_runner::ScenarioRunner::run_with_seed(&scenario, args.seed)
            .map_err(scenario_runner_error)?;
    let second = asupersync::lab::scenario_runner::ScenarioRunner::run_with_seed(
        &scenario,
        Some(first.seed),
    )
    .map_err(scenario_runner_error)?;

    let deterministic = first.certificate == second.certificate;
    let replay_events = first.replay_trace.as_ref().map_or(0, |trace| trace.len());
    let window = resolve_replay_window(replay_events, args.window_start, args.window_events);
    let rerun_commands = build_replay_rerun_commands(args, first.seed);

    let artifact_pointer = args.artifact_pointer.clone().or_else(|| {
        args.artifact_output
            .as_ref()
            .map(|path| path.display().to_string())
    });

    let divergence = if deterministic {
        None
    } else {
        Some(ReplayDivergenceDetails {
            first_event_hash: first.certificate.event_hash,
            first_schedule_hash: first.certificate.schedule_hash,
            first_steps: first.certificate.steps,
            second_event_hash: second.certificate.event_hash,
            second_schedule_hash: second.certificate.schedule_hash,
            second_steps: second.certificate.steps,
        })
    };

    let report = LabReplayOutput {
        scenario: args.scenario.display().to_string(),
        scenario_id: first.scenario_id.clone(),
        deterministic,
        seed: first.seed,
        event_hash: first.certificate.event_hash,
        schedule_hash: first.certificate.schedule_hash,
        trace_fingerprint: first.certificate.trace_fingerprint,
        steps: first.certificate.steps,
        replay_events,
        window,
        provenance: ReplayProvenance {
            scenario_path: args.scenario.display().to_string(),
            artifact_pointer,
            rerun_commands,
        },
        divergence,
    };

    if let Some(path) = &args.artifact_output {
        write_replay_artifact(path, &report)?;
    }

    if args.json {
        let json = serde_json::to_value(&report).map_err(output_cli_error)?;
        let pretty = serde_json::to_string_pretty(&json).map_err(output_cli_error)?;
        writeln!(io::stdout(), "{pretty}").map_err(output_cli_error)?;
    } else {
        output.write(&report).map_err(|e| {
            CliError::new("output_error", "Failed to write output").detail(e.to_string())
        })?;
    }

    if !deterministic {
        let replay_hint = report
            .provenance
            .rerun_commands
            .first()
            .cloned()
            .unwrap_or_else(|| "asupersync lab replay <scenario>".to_string());
        let detail = format!(
            "Seed {} diverged (event_hash {} vs {}). Rerun with: {}",
            report.seed,
            report.event_hash,
            report
                .divergence
                .as_ref()
                .map_or(report.event_hash, |d| d.second_event_hash),
            replay_hint
        );
        return Err(CliError::new(
            "replay_divergence",
            "Deterministic replay divergence detected",
        )
        .detail(detail)
        .exit_code(ExitCode::DETERMINISM_FAILURE));
    }

    Ok(())
}

#[allow(clippy::cast_possible_truncation)]
fn lab_explore(args: &LabExploreArgs, output: &mut Output) -> Result<(), CliError> {
    let scenario = load_scenario(&args.scenario)?;
    let result = asupersync::lab::scenario_runner::ScenarioRunner::explore_seeds(
        &scenario,
        args.start_seed,
        args.seeds as usize,
    )
    .map_err(scenario_runner_error)?;

    let all_passed = result.all_passed();

    if args.json {
        let json = result.to_json();
        let pretty = serde_json::to_string_pretty(&json).map_err(output_cli_error)?;
        writeln!(io::stdout(), "{pretty}").map_err(output_cli_error)?;
    } else {
        let report = LabExploreOutput::from_result(&result);
        output.write(&report).map_err(|e| {
            CliError::new("output_error", "Failed to write output").detail(e.to_string())
        })?;
    }

    if !all_passed {
        return Err(CliError::new("exploration_failures", "Some seeds failed")
            .detail(format!(
                "{} of {} seeds failed. First failure at seed {}",
                result.failed,
                result.seeds_explored,
                result.first_failure_seed.unwrap_or(0),
            ))
            .exit_code(ExitCode::TEST_FAILURE));
    }

    Ok(())
}

#[derive(Debug, Clone, Copy, serde::Serialize)]
struct ReplayWindowSummary {
    start: usize,
    requested_events: usize,
    resolved_events: usize,
    end_exclusive: usize,
    total_events: usize,
}

fn resolve_replay_window(
    total_events: usize,
    requested_start: usize,
    requested_events: Option<usize>,
) -> ReplayWindowSummary {
    let start = requested_start.min(total_events);
    let max_events = total_events.saturating_sub(start);
    let requested = requested_events.unwrap_or(max_events);
    let resolved = requested.min(max_events);

    ReplayWindowSummary {
        start,
        requested_events: requested,
        resolved_events: resolved,
        end_exclusive: start + resolved,
        total_events,
    }
}

#[derive(Debug, Clone, serde::Serialize)]
struct ReplayProvenance {
    scenario_path: String,
    artifact_pointer: Option<String>,
    rerun_commands: Vec<String>,
}

#[derive(Debug, Clone, Copy, serde::Serialize)]
struct ReplayDivergenceDetails {
    first_event_hash: u64,
    first_schedule_hash: u64,
    first_steps: u64,
    second_event_hash: u64,
    second_schedule_hash: u64,
    second_steps: u64,
}

fn build_replay_rerun_commands(args: &LabReplayArgs, seed: u64) -> Vec<String> {
    let mut replay = format!("asupersync lab replay {}", args.scenario.display());
    replay.push_str(&format!(" --seed {seed}"));

    if args.window_start > 0 {
        replay.push_str(&format!(" --window-start {}", args.window_start));
    }
    if let Some(window_events) = args.window_events {
        replay.push_str(&format!(" --window-events {window_events}"));
    }
    if let Some(pointer) = &args.artifact_pointer {
        replay.push_str(&format!(" --artifact-pointer {pointer}"));
    }
    if let Some(path) = &args.artifact_output {
        replay.push_str(&format!(" --artifact-output {}", path.display()));
    }

    let run = format!(
        "asupersync lab run {} --seed {seed}",
        args.scenario.display()
    );
    vec![replay, run]
}

fn write_replay_artifact(path: &Path, report: &LabReplayOutput) -> Result<(), CliError> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent).map_err(|err| {
            CliError::new(
                "artifact_output_error",
                "Failed to create artifact directory",
            )
            .detail(err.to_string())
            .context("path", parent.display().to_string())
            .exit_code(ExitCode::RUNTIME_ERROR)
        })?;
    }

    let payload = serde_json::to_vec_pretty(report).map_err(|err| {
        CliError::new(
            "artifact_output_error",
            "Failed to serialize replay artifact",
        )
        .detail(err.to_string())
        .context("path", path.display().to_string())
        .exit_code(ExitCode::RUNTIME_ERROR)
    })?;

    fs::write(path, payload).map_err(|err| {
        CliError::new("artifact_output_error", "Failed to write replay artifact")
            .detail(err.to_string())
            .context("path", path.display().to_string())
            .exit_code(ExitCode::RUNTIME_ERROR)
    })
}

// =========================================================================
// Lab output types
// =========================================================================

#[derive(Debug, serde::Serialize)]
struct LabRunOutput {
    scenario_id: String,
    seed: u64,
    passed: bool,
    steps: u64,
    faults_injected: usize,
    oracles_checked: usize,
    oracles_passed: usize,
    oracles_failed: usize,
    invariant_violations: Vec<String>,
    event_hash: u64,
    schedule_hash: u64,
}

impl LabRunOutput {
    fn from_result(result: &asupersync::lab::scenario_runner::ScenarioRunResult) -> Self {
        Self {
            scenario_id: result.scenario_id.clone(),
            seed: result.seed,
            passed: result.passed(),
            steps: result.lab_report.steps_total,
            faults_injected: result.faults_injected,
            oracles_checked: result.oracle_report.checked.len(),
            oracles_passed: result.oracle_report.passed_count,
            oracles_failed: result.oracle_report.failed_count,
            invariant_violations: result.lab_report.invariant_violations.clone(),
            event_hash: result.certificate.event_hash,
            schedule_hash: result.certificate.schedule_hash,
        }
    }
}

impl Outputtable for LabRunOutput {
    fn human_format(&self) -> String {
        let status = if self.passed { "PASS" } else { "FAIL" };
        let mut lines = vec![
            format!("Scenario: {} [{}]", self.scenario_id, status),
            format!("Seed: {}", self.seed),
            format!("Steps: {}", self.steps),
            format!("Faults injected: {}", self.faults_injected),
            format!(
                "Oracles: {}/{} passed",
                self.oracles_passed, self.oracles_checked
            ),
        ];
        if !self.invariant_violations.is_empty() {
            lines.push(format!(
                "Invariant violations: {}",
                self.invariant_violations.join(", ")
            ));
        }
        lines.push(format!(
            "Certificate: event_hash={}, schedule_hash={}",
            self.event_hash, self.schedule_hash
        ));
        lines.join("\n")
    }
}

#[derive(Debug, serde::Serialize)]
struct LabValidateOutput {
    scenario: String,
    scenario_id: String,
    valid: bool,
    errors: Vec<String>,
}

impl Outputtable for LabValidateOutput {
    fn human_format(&self) -> String {
        if self.valid {
            format!("Scenario '{}' is valid", self.scenario_id)
        } else {
            let mut lines = vec![format!("Scenario '{}' has errors:", self.scenario_id)];
            for err in &self.errors {
                lines.push(format!("  - {err}"));
            }
            lines.join("\n")
        }
    }
}

#[derive(Debug, serde::Serialize)]
struct LabReplayOutput {
    scenario: String,
    scenario_id: String,
    deterministic: bool,
    seed: u64,
    event_hash: u64,
    schedule_hash: u64,
    trace_fingerprint: u64,
    steps: u64,
    replay_events: usize,
    window: ReplayWindowSummary,
    provenance: ReplayProvenance,
    divergence: Option<ReplayDivergenceDetails>,
}

impl Outputtable for LabReplayOutput {
    fn human_format(&self) -> String {
        let status = if self.deterministic { "PASS" } else { "FAIL" };
        let mut lines = vec![
            format!("Replay: {} [{}]", self.scenario_id, status),
            format!("Scenario: {}", self.scenario),
            format!("Seed: {}", self.seed),
            format!(
                "Certificate: event_hash={}, schedule_hash={}, trace_fingerprint={}, steps={}",
                self.event_hash, self.schedule_hash, self.trace_fingerprint, self.steps
            ),
            format!(
                "Window: start={}, end={}, requested={}, resolved={}, total_events={}",
                self.window.start,
                self.window.end_exclusive,
                self.window.requested_events,
                self.window.resolved_events,
                self.window.total_events
            ),
            format!("Replay events recorded: {}", self.replay_events),
        ];

        if let Some(pointer) = &self.provenance.artifact_pointer {
            lines.push(format!("Artifact pointer: {pointer}"));
        }
        if let Some(divergence) = self.divergence {
            lines.push(format!(
                "Divergence: run1(event_hash={}, schedule_hash={}, steps={}) vs run2(event_hash={}, schedule_hash={}, steps={})",
                divergence.first_event_hash,
                divergence.first_schedule_hash,
                divergence.first_steps,
                divergence.second_event_hash,
                divergence.second_schedule_hash,
                divergence.second_steps
            ));
        }
        lines.push("Rerun commands:".to_string());
        for cmd in &self.provenance.rerun_commands {
            lines.push(format!("  {cmd}"));
        }

        lines.join("\n")
    }
}

#[derive(Debug, serde::Serialize)]
struct LabExploreOutput {
    scenario_id: String,
    seeds_explored: usize,
    passed: usize,
    failed: usize,
    unique_fingerprints: usize,
    first_failure_seed: Option<u64>,
}

impl LabExploreOutput {
    fn from_result(result: &asupersync::lab::scenario_runner::ScenarioExplorationResult) -> Self {
        Self {
            scenario_id: result.scenario_id.clone(),
            seeds_explored: result.seeds_explored,
            passed: result.passed,
            failed: result.failed,
            unique_fingerprints: result.unique_fingerprints,
            first_failure_seed: result.first_failure_seed,
        }
    }
}

impl Outputtable for LabExploreOutput {
    fn human_format(&self) -> String {
        let status = if self.failed == 0 { "PASS" } else { "FAIL" };
        let mut lines = vec![
            format!("Exploration: {} [{}]", self.scenario_id, status),
            format!("Seeds: {}/{} passed", self.passed, self.seeds_explored),
            format!("Unique fingerprints: {}", self.unique_fingerprints),
        ];
        if let Some(seed) = self.first_failure_seed {
            lines.push(format!("First failure at seed: {seed}"));
        }
        lines.join("\n")
    }
}

// =========================================================================
// Conformance handler
// =========================================================================

fn conformance_matrix(args: ConformanceMatrixArgs, output: &mut Output) -> Result<(), CliError> {
    if let Some(min) = args.min_coverage {
        if !(0.0..=100.0).contains(&min) {
            return Err(CliError::new(
                "invalid_argument",
                "--min-coverage must be between 0 and 100",
            ));
        }
    }

    let mut paths = if args.paths.is_empty() {
        vec![args.root.join("tests"), args.root.join("src")]
    } else {
        args.paths
            .into_iter()
            .map(|path| resolve_path(&args.root, path))
            .collect()
    };

    paths.retain(|path| path.exists());
    if paths.is_empty() {
        return Err(CliError::new(
            "invalid_argument",
            "No valid paths found to scan for conformance attributes",
        ));
    }

    let scan = scan_conformance_attributes(&paths).map_err(conformance_scan_error)?;

    let requirements = if let Some(path) = args.requirements {
        let path = resolve_path(&args.root, path);
        let raw = fs::read_to_string(&path).map_err(|err| io_error(&path, &err))?;
        serde_json::from_str::<Vec<SpecRequirement>>(&raw).map_err(|err| {
            CliError::new("invalid_requirements", "Failed to parse requirements JSON")
                .detail(err.to_string())
                .context("path", path.display().to_string())
        })?
    } else {
        requirements_from_entries(&scan.entries)
    };

    let mut matrix = TraceabilityMatrix::from_entries(requirements, scan.entries);
    let missing = matrix.missing_sections();
    let coverage = matrix.coverage_percentage();

    let report = ConformanceMatrixReport {
        root: args.root.display().to_string(),
        matrix,
        coverage_percentage: coverage,
        missing_sections: missing.clone(),
        warnings: scan.warnings,
    };

    output.write(&report).map_err(|err| {
        CliError::new("output_error", "Failed to write output").detail(err.to_string())
    })?;

    if args.fail_on_missing && !missing.is_empty() {
        return Err(
            CliError::new("missing_requirements", "Missing conformance coverage")
                .detail(missing.join(", "))
                .exit_code(ExitCode::TEST_FAILURE),
        );
    }

    if let Some(min) = args.min_coverage {
        if coverage < min {
            return Err(CliError::new(
                "coverage_below_threshold",
                "Conformance coverage below minimum threshold",
            )
            .detail(format!("{coverage:.1}% < {min:.1}%"))
            .exit_code(ExitCode::TEST_FAILURE));
        }
    }

    Ok(())
}

// =========================================================================

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
    let mut min: Option<u64> = None;
    let mut max: Option<u64> = None;
    while let Some(event) = reader.read_event()? {
        match event {
            ReplayEvent::TimeAdvanced {
                from_nanos,
                to_nanos,
                ..
            } => {
                min = Some(min.map_or(from_nanos, |prev| prev.min(from_nanos)));
                max = Some(max.map_or(to_nanos, |prev| prev.max(to_nanos)));
            }
            ReplayEvent::Checkpoint { time_nanos, .. } => {
                min = Some(min.map_or(time_nanos, |prev| prev.min(time_nanos)));
                max = Some(max.map_or(time_nanos, |prev| prev.max(time_nanos)));
            }
            _ => {}
        }
    }
    Ok(match (min, max) {
        (Some(lo), Some(hi)) => Some(hi.saturating_sub(lo)),
        _ => None,
    })
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
        TraceFileError::OversizedField { field, actual, max } => {
            CliError::new("oversized_field", "Trace field exceeds allowed limit")
                .detail(format!("{field}: {actual} bytes (max {max})"))
        }
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

#[allow(clippy::needless_pass_by_value)]
fn conformance_scan_error(err: TraceabilityScanError) -> CliError {
    CliError::new("scan_error", "Failed to scan for conformance attributes")
        .detail(err.to_string())
        .context("path", err.path.display().to_string())
        .exit_code(ExitCode::RUNTIME_ERROR)
}

fn resolve_path(root: &Path, path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        root.join(path)
    }
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
    use clap::Parser;
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

    #[test]
    fn lab_replay_args_parse_extended_flags() {
        let cli = Cli::try_parse_from([
            "asupersync",
            "lab",
            "replay",
            "examples/scenarios/smoke_happy_path.yaml",
            "--seed",
            "77",
            "--artifact-pointer",
            "artifacts/replay/failure-77.json",
            "--artifact-output",
            "artifacts/replay/report.json",
            "--window-start",
            "8",
            "--window-events",
            "12",
            "--json",
        ])
        .expect("parse replay args");

        let Command::Lab(LabArgs {
            command: LabCommand::Replay(args),
        }) = cli.command
        else {
            panic!("expected lab replay command");
        };

        assert_eq!(args.seed, Some(77));
        assert_eq!(
            args.artifact_pointer.as_deref(),
            Some("artifacts/replay/failure-77.json")
        );
        assert_eq!(
            args.artifact_output.as_deref(),
            Some(Path::new("artifacts/replay/report.json"))
        );
        assert_eq!(args.window_start, 8);
        assert_eq!(args.window_events, Some(12));
        assert!(args.json);
    }

    #[test]
    fn resolve_replay_window_clamps_to_available_events() {
        let window = resolve_replay_window(5, 7, Some(4));
        assert_eq!(window.start, 5);
        assert_eq!(window.requested_events, 4);
        assert_eq!(window.resolved_events, 0);
        assert_eq!(window.end_exclusive, 5);
        assert_eq!(window.total_events, 5);
    }

    #[test]
    fn build_replay_rerun_commands_include_seed_and_window() {
        let args = LabReplayArgs {
            scenario: PathBuf::from("examples/scenarios/smoke_happy_path.yaml"),
            seed: Some(91),
            artifact_pointer: Some("artifacts/replay/pinned.json".to_string()),
            artifact_output: Some(PathBuf::from("artifacts/replay/output.json")),
            window_start: 3,
            window_events: Some(9),
            json: false,
        };

        let commands = build_replay_rerun_commands(&args, 91);
        assert_eq!(commands.len(), 2);
        assert!(commands[0].contains("--seed 91"));
        assert!(commands[0].contains("--window-start 3"));
        assert!(commands[0].contains("--window-events 9"));
        assert!(commands[0].contains("--artifact-pointer artifacts/replay/pinned.json"));
        assert!(commands[0].contains("--artifact-output artifacts/replay/output.json"));
        assert!(commands[1].contains("asupersync lab run"));
    }

    #[test]
    fn write_replay_artifact_persists_json_report() {
        let temp = tempfile::tempdir().expect("tempdir");
        let output_path = temp.path().join("replay/report.json");
        let report = LabReplayOutput {
            scenario: "examples/scenarios/smoke_happy_path.yaml".to_string(),
            scenario_id: "smoke-happy-path".to_string(),
            deterministic: true,
            seed: 42,
            event_hash: 100,
            schedule_hash: 200,
            trace_fingerprint: 300,
            steps: 400,
            replay_events: 2,
            window: ReplayWindowSummary {
                start: 0,
                requested_events: 2,
                resolved_events: 2,
                end_exclusive: 2,
                total_events: 2,
            },
            provenance: ReplayProvenance {
                scenario_path: "examples/scenarios/smoke_happy_path.yaml".to_string(),
                artifact_pointer: Some("artifacts/replay/report.json".to_string()),
                rerun_commands: vec![
                    "asupersync lab replay examples/scenarios/smoke_happy_path.yaml --seed 42"
                        .to_string(),
                    "asupersync lab run examples/scenarios/smoke_happy_path.yaml --seed 42"
                        .to_string(),
                ],
            },
            divergence: None,
        };

        write_replay_artifact(&output_path, &report).expect("write replay artifact");
        let saved = fs::read_to_string(&output_path).expect("read replay artifact");
        assert!(saved.contains("\"scenario_id\": \"smoke-happy-path\""));
        assert!(saved.contains("\"rerun_commands\""));
    }

    #[test]
    fn doctor_evidence_timeline_contract_command_parses() {
        let cli = Cli::try_parse_from(["asupersync", "doctor", "evidence-timeline-contract"])
            .expect("parse doctor evidence-timeline-contract");

        let Command::Doctor(DoctorArgs {
            command: DoctorCommand::EvidenceTimelineContract,
        }) = cli.command
        else {
            panic!("expected doctor evidence-timeline-contract command");
        };
    }

    #[test]
    fn doctor_evidence_timeline_smoke_command_parses() {
        let cli = Cli::try_parse_from(["asupersync", "doctor", "evidence-timeline-smoke"])
            .expect("parse doctor evidence-timeline-smoke");

        let Command::Doctor(DoctorArgs {
            command: DoctorCommand::EvidenceTimelineSmoke,
        }) = cli.command
        else {
            panic!("expected doctor evidence-timeline-smoke command");
        };
    }

    #[test]
    fn doctor_scenario_coverage_pack_contract_command_parses() {
        let cli = Cli::try_parse_from(["asupersync", "doctor", "scenario-coverage-pack-contract"])
            .expect("parse doctor scenario-coverage-pack-contract");

        let Command::Doctor(DoctorArgs {
            command: DoctorCommand::ScenarioCoveragePackContract,
        }) = cli.command
        else {
            panic!("expected doctor scenario-coverage-pack-contract command");
        };
    }

    #[test]
    fn doctor_scenario_coverage_pack_smoke_command_parses() {
        let cli = Cli::try_parse_from([
            "asupersync",
            "doctor",
            "scenario-coverage-pack-smoke",
            "--selection-mode",
            "retry",
            "--seed",
            "seed-007",
        ])
        .expect("parse doctor scenario-coverage-pack-smoke");

        let Command::Doctor(DoctorArgs {
            command: DoctorCommand::ScenarioCoveragePackSmoke(args),
        }) = cli.command
        else {
            panic!("expected doctor scenario-coverage-pack-smoke command");
        };
        assert_eq!(args.selection_mode, "retry");
        assert_eq!(args.seed, "seed-007");
    }

    #[test]
    fn doctor_report_export_args_parse_flags() {
        let cli = Cli::try_parse_from([
            "asupersync",
            "doctor",
            "report-export",
            "--fixture-id",
            "advanced_failure_path",
            "--out-dir",
            "target/e2e-results/doctor_report_export",
            "--format",
            "json,markdown",
        ])
        .expect("parse doctor report-export args");

        let Command::Doctor(DoctorArgs {
            command: DoctorCommand::ReportExport(args),
        }) = cli.command
        else {
            panic!("expected doctor report-export command");
        };

        assert_eq!(args.fixture_id.as_deref(), Some("advanced_failure_path"));
        assert_eq!(
            args.out_dir,
            PathBuf::from("target/e2e-results/doctor_report_export")
        );
        assert_eq!(
            args.formats,
            vec![
                DoctorReportExportFormat::Json,
                DoctorReportExportFormat::Markdown
            ]
        );
    }

    #[test]
    fn select_advanced_fixtures_for_report_export_rejects_unknown_fixture() {
        let args = DoctorReportExportArgs {
            fixture_id: Some("missing-fixture".to_string()),
            out_dir: PathBuf::from("target/e2e-results/doctor_report_export"),
            formats: vec![DoctorReportExportFormat::Json],
        };
        let err = select_advanced_fixtures_for_report_export(&args)
            .expect_err("missing fixture should fail");
        assert_eq!(err.error_type, "invalid_argument");
        assert!(err.title.contains("Unknown --fixture-id value"));
    }

    #[test]
    fn export_advanced_report_fixture_is_deterministic() {
        let bundle = advanced_diagnostics_report_bundle();
        let fixture = bundle
            .fixtures
            .iter()
            .find(|entry| entry.fixture_id == "advanced_failure_path")
            .expect("fixture exists")
            .clone();
        let formats = vec![
            DoctorReportExportFormat::Markdown,
            DoctorReportExportFormat::Json,
        ];
        let temp = tempfile::tempdir().expect("tempdir");

        let first = export_advanced_report_fixture(&bundle, &fixture, &formats, temp.path())
            .expect("first export");
        let second = export_advanced_report_fixture(&bundle, &fixture, &formats, temp.path())
            .expect("second export");

        assert_eq!(first.output_files, second.output_files);
        assert_eq!(
            first.remediation_outcome_count,
            second.remediation_outcome_count
        );
        assert_eq!(first.validation_status, "valid");
        assert_eq!(second.validation_status, "valid");
        assert_eq!(first.output_files.len(), 2);

        let first_json = first
            .output_files
            .iter()
            .find(|path| path.ends_with(".json"))
            .expect("json path");
        let first_md = first
            .output_files
            .iter()
            .find(|path| path.ends_with(".md"))
            .expect("markdown path");
        let second_json = second
            .output_files
            .iter()
            .find(|path| path.ends_with(".json"))
            .expect("json path");
        let second_md = second
            .output_files
            .iter()
            .find(|path| path.ends_with(".md"))
            .expect("markdown path");

        let first_json_payload = fs::read_to_string(first_json).expect("read first json");
        let second_json_payload = fs::read_to_string(second_json).expect("read second json");
        assert_eq!(first_json_payload, second_json_payload);

        let first_md_payload = fs::read_to_string(first_md).expect("read first markdown");
        let second_md_payload = fs::read_to_string(second_md).expect("read second markdown");
        assert_eq!(first_md_payload, second_md_payload);
    }

    #[test]
    fn render_doctor_report_markdown_includes_required_sections() {
        let bundle = advanced_diagnostics_report_bundle();
        let fixture = bundle
            .fixtures
            .iter()
            .find(|entry| entry.fixture_id == "advanced_failure_path")
            .expect("fixture exists");
        let document = build_report_export_document(&bundle, fixture).expect("document");
        let markdown = render_doctor_report_markdown(&document);

        assert!(markdown.contains("## Evidence Links"));
        assert!(markdown.contains("## Command Provenance"));
        assert!(markdown.contains("## Remediation Outcomes"));
        assert!(markdown.contains("## Trust Transitions"));
        assert!(markdown.contains("## Collaboration Trail"));
        assert!(markdown.contains("## Troubleshooting Playbooks"));
    }

    #[test]
    fn doctor_franken_export_args_parse_flags() {
        let cli = Cli::try_parse_from([
            "asupersync",
            "doctor",
            "franken-export",
            "--report",
            "artifacts/doctor/core-report.json",
            "--fixture-id",
            "baseline_failure_path",
            "--out-dir",
            "target/e2e-results/doctor_frankensuite_export",
        ])
        .expect("parse doctor franken-export args");

        let Command::Doctor(DoctorArgs {
            command: DoctorCommand::FrankenExport(args),
        }) = cli.command
        else {
            panic!("expected doctor franken-export command");
        };

        assert_eq!(
            args.report.as_deref(),
            Some(Path::new("artifacts/doctor/core-report.json"))
        );
        assert_eq!(args.fixture_id.as_deref(), Some("baseline_failure_path"));
        assert_eq!(
            args.out_dir,
            PathBuf::from("target/e2e-results/doctor_frankensuite_export")
        );
    }

    #[test]
    fn export_core_report_to_franken_artifacts_is_deterministic() {
        let fixture = core_diagnostics_report_bundle()
            .fixtures
            .into_iter()
            .find(|candidate| candidate.fixture_id == "baseline_failure_path")
            .expect("fixture exists");
        let temp = tempfile::tempdir().expect("tempdir");

        let first = export_core_report_to_franken_artifacts(
            fixture.fixture_id.as_str(),
            &fixture.report,
            temp.path(),
        )
        .expect("first export");
        let second = export_core_report_to_franken_artifacts(
            fixture.fixture_id.as_str(),
            &fixture.report,
            temp.path(),
        )
        .expect("second export");

        assert_eq!(first.evidence_count, second.evidence_count);
        assert_eq!(first.decision_count, second.decision_count);

        let first_evidence = fs::read_to_string(&first.evidence_jsonl).expect("first evidence");
        let second_evidence = fs::read_to_string(&second.evidence_jsonl).expect("second evidence");
        assert_eq!(first_evidence, second_evidence);

        let first_decision = fs::read_to_string(&first.decision_json).expect("first decision");
        let second_decision = fs::read_to_string(&second.decision_json).expect("second decision");
        assert_eq!(first_decision, second_decision);
    }

    #[test]
    fn validate_exportable_core_report_rejects_unsupported_schema_version() {
        let mut report = core_diagnostics_report_bundle()
            .fixtures
            .into_iter()
            .next()
            .expect("fixture exists")
            .report;
        report.schema_version = "doctor-core-report-v0".to_string();

        let err = validate_exportable_core_report(&report).expect_err("expected version error");
        assert_eq!(err.error_type, "doctor_export_error");
        assert!(err.detail.contains("doctor-core-report-v0"));
    }

    #[test]
    fn load_core_report_rejects_malformed_json() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("malformed_core_report.json");
        fs::write(&path, "{ not-json ").expect("write malformed");

        let err = load_core_report(&path).expect_err("expected parse failure");
        assert_eq!(err.error_type, "doctor_export_error");
        assert!(err.title.contains("parse core diagnostics report JSON"));
    }
}
