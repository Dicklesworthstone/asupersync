//! Asupersync CLI tools (feature-gated).
#![allow(
    clippy::result_large_err,
    clippy::too_many_lines,
    clippy::too_many_arguments,
    clippy::format_push_string,
    clippy::case_sensitive_file_extension_comparisons,
    clippy::redundant_closure_for_method_calls,
    clippy::option_if_let_else,
    clippy::redundant_clone,
    clippy::uninlined_format_args
)]

use asupersync::Time;
use asupersync::cli::doctor::{
    AdvancedCollaborationEntry, AdvancedDiagnosticsFixture, AdvancedDiagnosticsReportBundle,
    AdvancedRemediationDelta, AdvancedTroubleshootingPlaybook, AdvancedTrustTransition,
    DoctorScenarioCoveragePackSmokeReport, DoctorScenarioCoveragePacksContract,
    DoctorStressSoakContract, DoctorStressSoakSmokeReport, EvidenceTimelineContract,
    EvidenceTimelineWorkflowTranscript, advanced_diagnostics_report_bundle,
    build_doctor_scenario_coverage_pack_smoke_report, build_doctor_stress_soak_smoke_report,
    doctor_scenario_coverage_packs_contract, doctor_stress_soak_contract,
    evidence_timeline_contract, run_evidence_timeline_keyboard_flow_smoke,
    validate_advanced_diagnostics_report_extension,
    validate_advanced_diagnostics_report_extension_contract,
};
use asupersync::cli::{
    CliError, ColorChoice, CommonArgs, CoreDiagnosticsReport, CoreDiagnosticsReportBundle,
    CoreDiagnosticsSummary, ExitCode, InvariantAnalyzerReport, LockContentionAnalyzerReport,
    OperatorModelContract, Output, OutputFormat, Outputtable, RemediationRecipeBundle,
    ScreenEngineContract, StructuredLoggingContract, WorkspaceScanReport,
    analyze_workspace_invariants, analyze_workspace_lock_contention,
    core_diagnostics_report_bundle, core_diagnostics_report_contract, operator_model_contract,
    parse_color_choice, parse_output_format, remediation_recipe_bundle, scan_workspace,
    screen_engine_contract, structured_logging_contract, validate_core_diagnostics_report,
    validate_core_diagnostics_report_contract,
};
use asupersync::cx::Cx;
use asupersync::lab::dual_run::{FinalDivergenceClass, ReplayPolicy, RerunDecision, SeedPlan};
use asupersync::lab::replay::{
    DifferentialBundleArtifacts, DifferentialPolicyClass, DivergenceCorpusEntry,
};
use asupersync::lab::{
    CancellationRecord, DualRunHarness, DualRunScenarioIdentity, LabConfig, LabRuntime,
    LiveWitnessCollector, LoserDrainRecord, NormalizedSemantics, ObligationBalanceRecord,
    RegionCloseRecord, ResourceSurfaceRecord, TerminalOutcome, capture_cancellation,
    capture_loser_drain, capture_obligation_balance, capture_region_close, run_live_adapter,
};
use asupersync::observability::{
    TASK_CONSOLE_WIRE_SCHEMA_V1, TaskConsoleWireSnapshot, TaskDetailsWire, TaskSummaryWire,
};
use asupersync::sync::{AcquireError, Semaphore};
use asupersync::test_logging::derive_scenario_seed;
use asupersync::trace::{
    CompressionMode, IssueSeverity, ReplayEvent, TRACE_FILE_VERSION, TRACE_MAGIC, TraceFileError,
    TraceReader, VerificationOptions, verify_trace,
};
use asupersync::types::Budget;
use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};
use conformance::{
    ScanWarning, SpecRequirement, TraceabilityMatrix, TraceabilityScanError,
    requirements_from_entries, scan_conformance_attributes,
};
use franken_decision::DecisionAuditEntry;
use franken_evidence::{EvidenceLedger, EvidenceLedgerBuilder};
use franken_kernel::{DecisionId, TraceId};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs::{self, File};
use std::future::Future;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::Command as ProcessCommand;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Wake, Waker};

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
    /// Run built-in lab-vs-live differential scenario packs
    Differential(LabDifferentialArgs),
    /// Emit the machine-readable differential operator-profile manifest
    DifferentialProfileManifest(LabDifferentialProfileManifestArgs),
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
#[value(rename_all = "kebab-case")]
enum LabDifferentialProfile {
    Smoke,
    Phase1Core,
    Calibration,
}

impl LabDifferentialProfile {
    fn as_str(self) -> &'static str {
        match self {
            Self::Smoke => "smoke",
            Self::Phase1Core => "phase1-core",
            Self::Calibration => "calibration",
        }
    }
}

#[derive(Args, Debug)]
struct LabDifferentialArgs {
    /// Named scenario pack / execution profile
    #[arg(long = "profile", value_enum, default_value_t = LabDifferentialProfile::Smoke)]
    profile: LabDifferentialProfile,

    /// Restrict execution to one or more scenario ids
    #[arg(long = "scenario", value_delimiter = ',')]
    scenarios: Vec<String>,

    /// Root seed used to derive deterministic per-scenario seeds
    #[arg(long = "seed", default_value_t = 424_242_u64)]
    seed: u64,

    /// Output directory for summaries, logs, and artifacts
    #[arg(
        long = "out-dir",
        default_value = "target/e2e-results/lab_live_differential"
    )]
    out_dir: PathBuf,

    /// Output results as JSON
    #[arg(long = "json", action = ArgAction::SetTrue)]
    json: bool,
}

#[derive(Args, Debug)]
struct LabDifferentialProfileManifestArgs {
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
    /// Emit deterministic stress/soak contract for long-duration diagnostics runs
    StressSoakContract,
    /// Emit deterministic stress/soak smoke report with sustained-budget gates
    StressSoakSmoke(DoctorStressSoakSmokeArgs),
    /// Export advanced diagnostics reports to deterministic markdown/json artifacts
    ReportExport(DoctorReportExportArgs),
    /// Export core diagnostics reports into FrankenSuite evidence/decision artifacts
    FrankenExport(DoctorFrankenExportArgs),
    /// Package doctor_asupersync CLI artifacts and deterministic config templates
    PackageCli(DoctorPackageCliArgs),
    /// Render a deterministic runtime task-console wire snapshot from JSON input
    TaskConsoleView(DoctorTaskConsoleViewArgs),
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

#[derive(Args, Debug)]
struct DoctorStressSoakSmokeArgs {
    /// Stress/soak profile mode (`fast` or `soak`)
    #[arg(long = "profile-mode", default_value = "soak")]
    profile_mode: String,

    /// Deterministic root seed used for stress/soak generation
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
#[value(rename_all = "kebab-case")]
enum DoctorPackageProfile {
    Local,
    Ci,
}

impl DoctorPackageProfile {
    fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Ci => "ci",
        }
    }
}

#[derive(Args, Debug)]
struct DoctorPackageCliArgs {
    /// Optional source binary path; defaults to current executable when omitted
    #[arg(long = "source-binary")]
    source_binary: Option<PathBuf>,

    /// Output directory for packaged binary + release manifest + config templates
    #[arg(
        long = "out-dir",
        default_value = "target/e2e-results/doctor_cli_package/artifacts"
    )]
    out_dir: PathBuf,

    /// Installed binary name for packaged doctor CLI
    #[arg(long = "binary-name", default_value = "doctor_asupersync")]
    binary_name: String,

    /// Default profile template (`local` or `ci`)
    #[arg(long = "default-profile", value_enum, default_value_t = DoctorPackageProfile::Local)]
    default_profile: DoctorPackageProfile,

    /// Perform install/run smoke checks from packaged artifacts
    #[arg(long = "smoke", action = ArgAction::SetTrue)]
    smoke: bool,
}

#[derive(Args, Debug)]
struct DoctorTaskConsoleViewArgs {
    /// Path to task-console wire snapshot JSON
    #[arg(long = "snapshot")]
    snapshot: PathBuf,

    /// Maximum number of tasks to include in output
    #[arg(long = "max-tasks", default_value_t = 128)]
    max_tasks: usize,

    /// Allow non-canonical schema versions without failing
    #[arg(long = "allow-schema-mismatch", action = ArgAction::SetTrue)]
    allow_schema_mismatch: bool,
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
        LabCommand::Differential(differential_args) => lab_differential(&differential_args, output),
        LabCommand::DifferentialProfileManifest(manifest_args) => {
            lab_differential_profile_manifest_command(&manifest_args, output)
        }
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
        DoctorCommand::StressSoakContract => doctor_stress_soak_contract_command(output),
        DoctorCommand::StressSoakSmoke(smoke_args) => {
            doctor_stress_soak_smoke_command(&smoke_args, output)
        }
        DoctorCommand::ReportExport(export_args) => doctor_report_export(&export_args, output),
        DoctorCommand::FrankenExport(export_args) => doctor_franken_export(&export_args, output),
        DoctorCommand::PackageCli(package_args) => doctor_package_cli(&package_args, output),
        DoctorCommand::TaskConsoleView(view_args) => doctor_task_console_view(&view_args, output),
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

fn doctor_stress_soak_contract_command(output: &mut Output) -> Result<(), CliError> {
    let contract: DoctorStressSoakContract = doctor_stress_soak_contract();
    let payload = DoctorStressSoakContractOutput { contract };
    output.write(&payload).map_err(|err| {
        CliError::new("output_error", "Failed to write output").detail(err.to_string())
    })?;
    Ok(())
}

fn doctor_stress_soak_smoke_command(
    args: &DoctorStressSoakSmokeArgs,
    output: &mut Output,
) -> Result<(), CliError> {
    let contract: DoctorStressSoakContract = doctor_stress_soak_contract();
    let report = build_doctor_stress_soak_smoke_report(&contract, &args.profile_mode, &args.seed)
        .map_err(|err| {
        CliError::new(
            "doctor_stress_soak_smoke_error",
            "Failed to build stress/soak smoke report",
        )
        .detail(err)
        .context("profile_mode", args.profile_mode.clone())
        .context("seed", args.seed.clone())
        .exit_code(ExitCode::RUNTIME_ERROR)
    })?;
    let payload = DoctorStressSoakSmokeOutput { report };
    output.write(&payload).map_err(|err| {
        CliError::new("output_error", "Failed to write output").detail(err.to_string())
    })?;
    Ok(())
}

fn doctor_task_console_view(
    args: &DoctorTaskConsoleViewArgs,
    output: &mut Output,
) -> Result<(), CliError> {
    let raw = fs::read_to_string(&args.snapshot).map_err(|err| {
        CliError::new(
            "doctor_task_console_io_error",
            "Failed to read task-console snapshot",
        )
        .detail(err.to_string())
        .context("snapshot", args.snapshot.display().to_string())
        .exit_code(ExitCode::RUNTIME_ERROR)
    })?;

    let snapshot = TaskConsoleWireSnapshot::from_json(&raw).map_err(|err| {
        CliError::new(
            "doctor_task_console_parse_error",
            "Failed to parse task-console snapshot JSON",
        )
        .detail(err.to_string())
        .context("snapshot", args.snapshot.display().to_string())
        .exit_code(ExitCode::USER_ERROR)
    })?;

    if !snapshot.has_expected_schema() && !args.allow_schema_mismatch {
        return Err(CliError::new(
            "doctor_task_console_schema_error",
            "Unexpected task-console schema version",
        )
        .detail(format!(
            "Expected '{}', got '{}'",
            TASK_CONSOLE_WIRE_SCHEMA_V1, snapshot.schema_version
        ))
        .context("snapshot", args.snapshot.display().to_string())
        .context("expected_schema", TASK_CONSOLE_WIRE_SCHEMA_V1.to_string())
        .context("found_schema", snapshot.schema_version.clone())
        .exit_code(ExitCode::USER_ERROR));
    }

    let payload = build_task_console_view_output(snapshot, &args.snapshot, args.max_tasks);
    output.write(&payload).map_err(|err| {
        CliError::new("output_error", "Failed to write output").detail(err.to_string())
    })?;
    Ok(())
}

fn build_task_console_view_output(
    snapshot: TaskConsoleWireSnapshot,
    source_snapshot: &Path,
    max_tasks: usize,
) -> DoctorTaskConsoleViewOutput {
    let schema_matches_expected = snapshot.has_expected_schema();
    let TaskConsoleWireSnapshot {
        schema_version,
        generated_at,
        summary,
        tasks,
    } = snapshot;
    let total_tasks = tasks.len();
    let shown_tasks = total_tasks.min(max_tasks);
    let truncated = shown_tasks < total_tasks;
    let tasks = tasks.into_iter().take(shown_tasks).collect();
    DoctorTaskConsoleViewOutput {
        schema_version,
        expected_schema_version: TASK_CONSOLE_WIRE_SCHEMA_V1.to_string(),
        schema_matches_expected,
        source_snapshot: source_snapshot.display().to_string(),
        generated_at_nanos: generated_at.as_nanos(),
        total_tasks,
        shown_tasks,
        truncated,
        summary,
        tasks,
    }
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
    collaboration_channel_count: usize,
    collaboration_channels: Vec<String>,
    trust_outcome_classes: Vec<String>,
    has_mismatch_diagnostics: bool,
    has_partial_success_mix: bool,
    has_rollback_signal: bool,
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
                "  - {} [{}] files={} findings={} evidence={} commands={} remediation={} channels={} mismatch={} partial_success={} rollback={} status={}",
                artifact.fixture_id,
                artifact.report_id,
                artifact.output_files.len(),
                artifact.finding_count,
                artifact.evidence_count,
                artifact.command_count,
                artifact.remediation_outcome_count,
                artifact.collaboration_channel_count,
                artifact.has_mismatch_diagnostics,
                artifact.has_partial_success_mix,
                artifact.has_rollback_signal,
                artifact.validation_status
            ));
            lines.push(format!(
                "    channels: {}",
                artifact.collaboration_channels.join(", ")
            ));
            lines.push(format!(
                "    trust outcomes: {}",
                artifact.trust_outcome_classes.join(", ")
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
struct DoctorStressSoakContractOutput {
    contract: DoctorStressSoakContract,
}

impl Outputtable for DoctorStressSoakContractOutput {
    fn human_format(&self) -> String {
        serde_json::to_string_pretty(&self.contract)
            .unwrap_or_else(|_| "failed to render stress/soak contract payload".to_string())
    }
}

#[derive(Debug, serde::Serialize, PartialEq, Eq)]
struct DoctorStressSoakSmokeOutput {
    report: DoctorStressSoakSmokeReport,
}

impl Outputtable for DoctorStressSoakSmokeOutput {
    fn human_format(&self) -> String {
        serde_json::to_string_pretty(&self.report)
            .unwrap_or_else(|_| "failed to render stress/soak smoke payload".to_string())
    }
}

#[derive(Debug, serde::Serialize, PartialEq, Eq)]
struct DoctorTaskConsoleViewOutput {
    schema_version: String,
    expected_schema_version: String,
    schema_matches_expected: bool,
    source_snapshot: String,
    generated_at_nanos: u64,
    total_tasks: usize,
    shown_tasks: usize,
    truncated: bool,
    summary: TaskSummaryWire,
    tasks: Vec<TaskDetailsWire>,
}

impl Outputtable for DoctorTaskConsoleViewOutput {
    fn human_format(&self) -> String {
        let mut lines = vec![
            format!("Schema: {}", self.schema_version),
            format!("Expected schema: {}", self.expected_schema_version),
            format!("Schema match: {}", self.schema_matches_expected),
            format!("Snapshot: {}", self.source_snapshot),
            format!("Generated at (nanos): {}", self.generated_at_nanos),
            format!(
                "Summary: total={} created={} running={} cancelling={} completed={} stuck={}",
                self.summary.total_tasks,
                self.summary.created,
                self.summary.running,
                self.summary.cancelling,
                self.summary.completed,
                self.summary.stuck_count
            ),
            format!(
                "Tasks shown: {}/{}{}",
                self.shown_tasks,
                self.total_tasks,
                if self.truncated { " (truncated)" } else { "" }
            ),
        ];

        if !self.summary.by_region.is_empty() {
            lines.push("By region:".to_string());
            for region in &self.summary.by_region {
                lines.push(format!(
                    "  {} -> {} tasks",
                    region.region_id, region.task_count
                ));
            }
        }

        if self.tasks.is_empty() {
            lines.push("Tasks: <none>".to_string());
            return lines.join("\n");
        }

        lines.push("Tasks:".to_string());
        for task in &self.tasks {
            lines.push(format!(
                "  {} region={} state={} phase={} polls={} remaining={} age_ns={} wake_pending={} obligations={} waiters={}",
                task.id,
                task.region_id,
                task.state.name(),
                task.phase,
                task.poll_count,
                task.polls_remaining,
                task.age_nanos,
                task.wake_pending,
                task.obligations.len(),
                task.waiters.len()
            ));
        }
        lines.join("\n")
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

const DOCTOR_CLI_PACKAGE_SCHEMA_VERSION: &str = "doctor-cli-package-v1";
const DOCTOR_CLI_PACKAGE_MANIFEST_SCHEMA_VERSION: &str = "doctor-cli-package-manifest-v1";
const DOCTOR_CLI_PACKAGE_CONFIG_SCHEMA_VERSION: &str = "doctor-cli-package-config-v1";

#[derive(Debug, serde::Serialize, PartialEq, Eq)]
struct DoctorPackageCliOutput {
    schema_version: String,
    package_version: String,
    binary_name: String,
    source_binary: String,
    packaged_binary: String,
    packaged_binary_size_bytes: u64,
    packaged_binary_sha256: String,
    release_manifest: String,
    default_profile: String,
    config_templates: Vec<DoctorPackageTemplateArtifact>,
    install_smoke: Option<DoctorPackageInstallSmokeResult>,
    rerun_commands: Vec<String>,
    structured_logs: Vec<DoctorPackageStructuredLog>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
struct DoctorPackageTemplateArtifact {
    profile: String,
    path: String,
    command_preview: String,
}

#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
struct DoctorPackageInstallSmokeResult {
    install_root: String,
    installed_binary: String,
    startup_status: String,
    command_status: String,
    command_output_sha256: String,
    observed_contract_version: String,
}

#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
struct DoctorPackageStructuredLog {
    level: String,
    event: String,
    message: String,
    remediation_guidance: Option<String>,
    fields: BTreeMap<String, String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
struct DoctorCliPackageManifest {
    schema_version: String,
    package_version: String,
    binary_name: String,
    default_profile: String,
    source_binary: String,
    packaged_binary: String,
    packaged_binary_size_bytes: u64,
    packaged_binary_sha256: String,
    config_templates: Vec<DoctorPackageTemplateArtifact>,
    supported_platforms: Vec<String>,
    compatibility_expectations: Vec<String>,
    upgrade_path: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
struct DoctorCliPackageConfigTemplate {
    schema_version: String,
    profile: String,
    binary_name: String,
    output_format: String,
    color: String,
    doctor_command: String,
    workspace_root: String,
    report_out_dir: String,
    strict_mode: bool,
    rch_binary: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MaterializedDoctorPackageTemplate {
    artifact: DoctorPackageTemplateArtifact,
    config: DoctorCliPackageConfigTemplate,
}

impl Outputtable for DoctorPackageCliOutput {
    fn human_format(&self) -> String {
        let mut lines = vec![
            format!("Schema: {}", self.schema_version),
            format!("Package version: {}", self.package_version),
            format!("Binary: {}", self.binary_name),
            format!("Source binary: {}", self.source_binary),
            format!("Packaged binary: {}", self.packaged_binary),
            format!(
                "Packaged binary digest: {} ({} bytes)",
                self.packaged_binary_sha256, self.packaged_binary_size_bytes
            ),
            format!("Release manifest: {}", self.release_manifest),
            format!("Default profile: {}", self.default_profile),
            format!("Config templates: {}", self.config_templates.len()),
        ];
        for template in &self.config_templates {
            lines.push(format!(
                "  - {}: {} ({})",
                template.profile, template.path, template.command_preview
            ));
        }
        if let Some(smoke) = &self.install_smoke {
            lines.push("Install smoke:".to_string());
            lines.push(format!("  - install root: {}", smoke.install_root));
            lines.push(format!("  - installed binary: {}", smoke.installed_binary));
            lines.push(format!("  - startup: {}", smoke.startup_status));
            lines.push(format!("  - command: {}", smoke.command_status));
            lines.push(format!(
                "  - command output sha256: {}",
                smoke.command_output_sha256
            ));
            lines.push(format!(
                "  - observed contract version: {}",
                smoke.observed_contract_version
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
    let mut collaboration_channels = document
        .collaboration_trail
        .iter()
        .map(|entry| entry.channel.clone())
        .collect::<Vec<_>>();
    collaboration_channels.sort();
    collaboration_channels.dedup();

    let mut trust_outcome_classes = document
        .trust_transitions
        .iter()
        .map(|transition| transition.outcome_class.clone())
        .collect::<Vec<_>>();
    trust_outcome_classes.sort();
    trust_outcome_classes.dedup();

    let success_count = document
        .remediation_outcomes
        .iter()
        .filter(|delta| delta.delta_outcome == "success")
        .count();
    let non_success_count = document
        .remediation_outcomes
        .iter()
        .filter(|delta| delta.delta_outcome != "success")
        .count();

    let has_mismatch_diagnostics =
        document.trust_transitions.iter().any(|transition| {
            transition
                .rationale
                .to_ascii_lowercase()
                .contains("mismatch")
        }) || document.troubleshooting_playbooks.iter().any(|playbook| {
            playbook
                .ordered_steps
                .iter()
                .any(|step| step.contains("mismatch"))
        });
    let has_rollback_signal = document
        .remediation_outcomes
        .iter()
        .any(|delta| delta.next_status == "open" && delta.delta_outcome == "failed")
        || document.trust_transitions.iter().any(|transition| {
            transition
                .rationale
                .to_ascii_lowercase()
                .contains("rollback")
        });

    Ok(DoctorReportExportArtifact {
        fixture_id: document.fixture_id.clone(),
        report_id: document.report_id.clone(),
        output_files,
        finding_count: document.findings.len(),
        evidence_count: document.evidence_links.len(),
        command_count: document.command_provenance.len(),
        remediation_outcome_count: document.remediation_outcomes.len(),
        collaboration_channel_count: collaboration_channels.len(),
        collaboration_channels,
        trust_outcome_classes,
        has_mismatch_diagnostics,
        has_partial_success_mix: success_count > 0 && non_success_count > 0,
        has_rollback_signal,
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

fn doctor_package_cli(args: &DoctorPackageCliArgs, output: &mut Output) -> Result<(), CliError> {
    let source_binary = resolve_doctor_package_source_binary(args)?;
    validate_packaged_binary_name(args.binary_name.as_str())?;

    fs::create_dir_all(&args.out_dir).map_err(|err| {
        CliError::new(
            "doctor_package_error",
            "Failed to create package output directory",
        )
        .detail(err.to_string())
        .context("path", args.out_dir.display().to_string())
        .context(
            "remediation",
            "Ensure the output path is writable and retry packaging.".to_string(),
        )
        .exit_code(ExitCode::RUNTIME_ERROR)
    })?;

    let package_dir = args.out_dir.join("package").join("bin");
    fs::create_dir_all(&package_dir).map_err(|err| {
        CliError::new(
            "doctor_package_error",
            "Failed to create package binary directory",
        )
        .detail(err.to_string())
        .context("path", package_dir.display().to_string())
        .context(
            "remediation",
            "Ensure the package directory path is writable.".to_string(),
        )
        .exit_code(ExitCode::RUNTIME_ERROR)
    })?;

    let source_bytes = fs::read(&source_binary).map_err(|err| io_error(&source_binary, &err))?;
    if source_bytes.is_empty() {
        return Err(
            CliError::new("doctor_package_error", "Source binary is empty and cannot be packaged")
                .detail(source_binary.display().to_string())
                .context(
                    "remediation",
                    "Build the CLI binary first (`rch exec -- cargo build --release --features cli --bin asupersync`) and retry."
                        .to_string(),
                )
                .exit_code(ExitCode::USER_ERROR),
        );
    }
    let packaged_binary = package_dir.join(&args.binary_name);
    fs::write(&packaged_binary, &source_bytes).map_err(|err| {
        CliError::new("doctor_package_error", "Failed to write packaged binary")
            .detail(err.to_string())
            .context("path", packaged_binary.display().to_string())
            .context(
                "remediation",
                "Check filesystem permissions and available disk space.".to_string(),
            )
            .exit_code(ExitCode::RUNTIME_ERROR)
    })?;
    let source_permissions = fs::metadata(&source_binary)
        .map_err(|err| io_error(&source_binary, &err))?
        .permissions();
    fs::set_permissions(&packaged_binary, source_permissions).map_err(|err| {
        CliError::new(
            "doctor_package_error",
            "Failed to preserve packaged binary permissions",
        )
        .detail(err.to_string())
        .context("path", packaged_binary.display().to_string())
        .context(
            "remediation",
            "Ensure executable permissions can be applied in the package directory.".to_string(),
        )
        .exit_code(ExitCode::RUNTIME_ERROR)
    })?;

    let config_dir = args.out_dir.join("config");
    let materialized =
        materialize_doctor_package_templates(&config_dir, args.binary_name.as_str())?;
    let mut config_templates = materialized
        .iter()
        .map(|entry| entry.artifact.clone())
        .collect::<Vec<_>>();
    config_templates.sort_by(|left, right| left.profile.cmp(&right.profile));

    let default_profile = args.default_profile.as_str().to_string();
    let default_config = materialized
        .iter()
        .find(|entry| entry.config.profile == default_profile)
        .map(|entry| entry.config.clone())
        .ok_or_else(|| {
            CliError::new(
                "doctor_package_error",
                "Default profile template was not materialized",
            )
            .detail(default_profile.clone())
            .context(
                "remediation",
                "Verify template generation for local and ci profiles.".to_string(),
            )
            .exit_code(ExitCode::RUNTIME_ERROR)
        })?;

    let packaged_binary_sha256 = sha256_hex(&source_bytes);
    let packaged_binary_size_bytes = source_bytes.len() as u64;
    let release_manifest_doc = build_doctor_cli_release_manifest(
        env!("CARGO_PKG_VERSION"),
        args.binary_name.as_str(),
        default_profile.as_str(),
        source_binary.as_path(),
        packaged_binary.as_path(),
        packaged_binary_size_bytes,
        packaged_binary_sha256.as_str(),
        &config_templates,
    );
    let release_manifest_path = args.out_dir.join("doctor_cli_release_manifest.json");
    let release_manifest_payload =
        serde_json::to_vec_pretty(&release_manifest_doc).map_err(|err| {
            CliError::new(
                "doctor_package_error",
                "Failed to serialize release manifest",
            )
            .detail(err.to_string())
            .context("path", release_manifest_path.display().to_string())
            .context(
                "remediation",
                "Inspect release manifest schema fields for serialization-unsafe data.".to_string(),
            )
            .exit_code(ExitCode::INTERNAL_ERROR)
        })?;
    fs::write(&release_manifest_path, release_manifest_payload).map_err(|err| {
        CliError::new("doctor_package_error", "Failed to write release manifest")
            .detail(err.to_string())
            .context("path", release_manifest_path.display().to_string())
            .context(
                "remediation",
                "Ensure manifest destination is writable and retry.".to_string(),
            )
            .exit_code(ExitCode::RUNTIME_ERROR)
    })?;

    let install_smoke = if args.smoke {
        Some(run_doctor_package_install_smoke(
            packaged_binary.as_path(),
            args.out_dir.as_path(),
            args.binary_name.as_str(),
            &default_config,
        )?)
    } else {
        None
    };

    let source_binary_cli = source_binary.display().to_string();
    let mut rerun_commands = vec![
        format!(
            "asupersync doctor package-cli --source-binary {} --out-dir {} --binary-name {} --default-profile {}{}",
            source_binary.display(),
            args.out_dir.display(),
            args.binary_name,
            args.default_profile.as_str(),
            if args.smoke { " --smoke" } else { "" }
        ),
        "rch exec -- cargo build --release --features cli --bin asupersync".to_string(),
    ];
    rerun_commands.sort();

    let mut structured_logs = Vec::new();
    structured_logs.push(doctor_package_log(
        "info",
        "package_started",
        "doctor_asupersync packaging started",
        None,
        vec![
            ("binary_name", args.binary_name.clone()),
            ("source_binary", source_binary_cli.clone()),
            ("out_dir", args.out_dir.display().to_string()),
        ],
    ));
    for template in &config_templates {
        structured_logs.push(doctor_package_log(
            "info",
            "config_template_materialized",
            "config template written and validated",
            None,
            vec![
                ("profile", template.profile.clone()),
                ("path", template.path.clone()),
                ("command_preview", template.command_preview.clone()),
            ],
        ));
    }
    structured_logs.push(doctor_package_log(
        "info",
        "release_manifest_written",
        "release manifest captured package metadata and compatibility policy",
        None,
        vec![
            ("manifest_path", release_manifest_path.display().to_string()),
            ("packaged_binary_sha256", packaged_binary_sha256.clone()),
        ],
    ));
    if let Some(smoke) = &install_smoke {
        structured_logs.push(doctor_package_log(
            "info",
            "install_smoke_passed",
            "packaged binary install/run smoke check completed",
            Some("If this check fails, verify executable permissions and run `doctor report-contract` manually."),
            vec![
                ("install_root", smoke.install_root.clone()),
                (
                    "observed_contract_version",
                    smoke.observed_contract_version.clone(),
                ),
                ("command_output_sha256", smoke.command_output_sha256.clone()),
            ],
        ));
    }
    structured_logs.push(doctor_package_log(
        "info",
        "package_completed",
        "doctor_asupersync packaging completed successfully",
        None,
        vec![
            ("packaged_binary", packaged_binary.display().to_string()),
            (
                "release_manifest",
                release_manifest_path.display().to_string(),
            ),
        ],
    ));

    let payload = DoctorPackageCliOutput {
        schema_version: DOCTOR_CLI_PACKAGE_SCHEMA_VERSION.to_string(),
        package_version: env!("CARGO_PKG_VERSION").to_string(),
        binary_name: args.binary_name.clone(),
        source_binary: source_binary_cli,
        packaged_binary: packaged_binary.display().to_string(),
        packaged_binary_size_bytes,
        packaged_binary_sha256,
        release_manifest: release_manifest_path.display().to_string(),
        default_profile,
        config_templates,
        install_smoke,
        rerun_commands,
        structured_logs,
    };
    output.write(&payload).map_err(output_cli_error)
}

fn resolve_doctor_package_source_binary(args: &DoctorPackageCliArgs) -> Result<PathBuf, CliError> {
    let source_binary = if let Some(path) = &args.source_binary {
        path.clone()
    } else {
        std::env::current_exe().map_err(|err| {
            CliError::new(
                "doctor_package_error",
                "Failed to resolve current executable for packaging",
            )
            .detail(err.to_string())
            .context(
                "remediation",
                "Pass an explicit --source-binary path to a built asupersync executable."
                    .to_string(),
            )
            .exit_code(ExitCode::RUNTIME_ERROR)
        })?
    };
    let metadata = fs::metadata(&source_binary).map_err(|err| io_error(&source_binary, &err))?;
    if !metadata.is_file() {
        return Err(CliError::new(
            "invalid_argument",
            "Source binary path does not reference a file",
        )
        .detail(source_binary.display().to_string())
        .context(
            "remediation",
            "Provide a file path to a compiled asupersync binary.".to_string(),
        )
        .exit_code(ExitCode::USER_ERROR));
    }
    Ok(source_binary)
}

fn materialize_doctor_package_templates(
    config_dir: &Path,
    binary_name: &str,
) -> Result<Vec<MaterializedDoctorPackageTemplate>, CliError> {
    fs::create_dir_all(config_dir).map_err(|err| {
        CliError::new(
            "doctor_package_error",
            "Failed to create config template directory",
        )
        .detail(err.to_string())
        .context("path", config_dir.display().to_string())
        .context(
            "remediation",
            "Ensure the config template path is writable and retry.".to_string(),
        )
        .exit_code(ExitCode::RUNTIME_ERROR)
    })?;

    let mut entries = Vec::new();
    for profile in [DoctorPackageProfile::Local, DoctorPackageProfile::Ci] {
        let template = doctor_package_config_template(profile, binary_name);
        let path = config_dir.join(format!("{}.{}.json", binary_name, profile.as_str()));
        let payload = serde_json::to_string_pretty(&template).map_err(|err| {
            CliError::new(
                "doctor_package_error",
                "Failed to serialize config template",
            )
            .detail(err.to_string())
            .context("profile", profile.as_str().to_string())
            .context("path", path.display().to_string())
            .context(
                "remediation",
                "Verify template defaults contain only serializable primitive values.".to_string(),
            )
            .exit_code(ExitCode::INTERNAL_ERROR)
        })?;
        fs::write(&path, payload.as_bytes()).map_err(|err| {
            CliError::new("doctor_package_error", "Failed to write config template")
                .detail(err.to_string())
                .context("profile", profile.as_str().to_string())
                .context("path", path.display().to_string())
                .context(
                    "remediation",
                    "Ensure template output path is writable.".to_string(),
                )
                .exit_code(ExitCode::RUNTIME_ERROR)
        })?;
        let parsed = parse_doctor_package_config(payload.as_str()).map_err(|reason| {
            CliError::new(
                "invalid_config",
                "Materialized config template failed validation",
            )
            .detail(reason)
            .context("profile", profile.as_str().to_string())
            .context("path", path.display().to_string())
            .context(
                "remediation",
                "Regenerate templates and ensure schema/profile/flag defaults match contract."
                    .to_string(),
            )
            .exit_code(ExitCode::RUNTIME_ERROR)
        })?;
        let command_preview = render_doctor_packaged_command(&parsed, binary_name);
        entries.push(MaterializedDoctorPackageTemplate {
            artifact: DoctorPackageTemplateArtifact {
                profile: profile.as_str().to_string(),
                path: path.display().to_string(),
                command_preview,
            },
            config: parsed,
        });
    }
    entries.sort_by(|left, right| left.artifact.profile.cmp(&right.artifact.profile));
    Ok(entries)
}

fn doctor_package_config_template(
    profile: DoctorPackageProfile,
    binary_name: &str,
) -> DoctorCliPackageConfigTemplate {
    let (color, strict_mode) = match profile {
        DoctorPackageProfile::Local => ("auto".to_string(), false),
        DoctorPackageProfile::Ci => ("never".to_string(), true),
    };
    DoctorCliPackageConfigTemplate {
        schema_version: DOCTOR_CLI_PACKAGE_CONFIG_SCHEMA_VERSION.to_string(),
        profile: profile.as_str().to_string(),
        binary_name: binary_name.to_string(),
        output_format: "json".to_string(),
        color,
        doctor_command: "report-contract".to_string(),
        workspace_root: ".".to_string(),
        report_out_dir: "target/e2e-results/doctor_report_export/artifacts".to_string(),
        strict_mode,
        rch_binary: "~/.local/bin/rch".to_string(),
    }
}

fn parse_doctor_package_config(raw: &str) -> Result<DoctorCliPackageConfigTemplate, String> {
    let config: DoctorCliPackageConfigTemplate = serde_json::from_str(raw)
        .map_err(|err| format!("config template JSON decode failed: {err}"))?;
    validate_doctor_package_config(&config)?;
    Ok(config)
}

fn validate_doctor_package_config(config: &DoctorCliPackageConfigTemplate) -> Result<(), String> {
    if config.schema_version != DOCTOR_CLI_PACKAGE_CONFIG_SCHEMA_VERSION {
        return Err(format!(
            "schema_version must be {}",
            DOCTOR_CLI_PACKAGE_CONFIG_SCHEMA_VERSION
        ));
    }
    if !matches!(config.profile.as_str(), "local" | "ci") {
        return Err("profile must be one of: local, ci".to_string());
    }
    if !is_valid_packaged_binary_name(config.binary_name.as_str()) {
        return Err("binary_name must contain only ASCII letters, digits, '-' or '_'".to_string());
    }
    if !matches!(
        config.output_format.as_str(),
        "json" | "json-pretty" | "stream-json" | "tsv" | "human"
    ) {
        return Err(
            "output_format must be one of: json, json-pretty, stream-json, tsv, human".to_string(),
        );
    }
    if !matches!(config.color.as_str(), "auto" | "always" | "never") {
        return Err("color must be one of: auto, always, never".to_string());
    }
    if config.doctor_command != "report-contract" {
        return Err("doctor_command must be report-contract".to_string());
    }
    if config.workspace_root.trim().is_empty() {
        return Err("workspace_root must be non-empty".to_string());
    }
    if config.report_out_dir.trim().is_empty() {
        return Err("report_out_dir must be non-empty".to_string());
    }
    if config.rch_binary.trim().is_empty() {
        return Err("rch_binary must be non-empty".to_string());
    }
    Ok(())
}

fn render_doctor_packaged_command(
    config: &DoctorCliPackageConfigTemplate,
    binary_name: &str,
) -> String {
    format!(
        "{binary_name} --format {} --color {} doctor {}",
        config.output_format, config.color, config.doctor_command
    )
}

fn validate_packaged_binary_name(binary_name: &str) -> Result<(), CliError> {
    if is_valid_packaged_binary_name(binary_name) {
        return Ok(());
    }
    Err(
        CliError::new("invalid_argument", "Invalid --binary-name value")
            .detail(binary_name.to_string())
            .context(
                "remediation",
                "Use only ASCII letters, digits, '-' or '_' for packaged binary names.".to_string(),
            )
            .exit_code(ExitCode::USER_ERROR),
    )
}

fn is_valid_packaged_binary_name(binary_name: &str) -> bool {
    !binary_name.is_empty()
        && binary_name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
}

fn run_doctor_package_install_smoke(
    packaged_binary: &Path,
    out_dir: &Path,
    binary_name: &str,
    config: &DoctorCliPackageConfigTemplate,
) -> Result<DoctorPackageInstallSmokeResult, CliError> {
    let install_root = out_dir.join("install_smoke_env");
    let install_bin_dir = install_root.join("bin");
    fs::create_dir_all(&install_bin_dir).map_err(|err| {
        CliError::new(
            "doctor_package_smoke_error",
            "Failed to create install smoke directory",
        )
        .detail(err.to_string())
        .context("path", install_bin_dir.display().to_string())
        .context(
            "remediation",
            "Use a fresh writable out-dir when running --smoke.".to_string(),
        )
        .exit_code(ExitCode::RUNTIME_ERROR)
    })?;
    let installed_binary = install_bin_dir.join(binary_name);
    let packaged_bytes =
        fs::read(packaged_binary).map_err(|err| io_error(packaged_binary, &err))?;
    fs::write(&installed_binary, &packaged_bytes).map_err(|err| {
        CliError::new(
            "doctor_package_smoke_error",
            "Failed to install packaged binary for smoke",
        )
        .detail(err.to_string())
        .context("path", installed_binary.display().to_string())
        .context(
            "remediation",
            "Ensure install-smoke directories are writable.".to_string(),
        )
        .exit_code(ExitCode::RUNTIME_ERROR)
    })?;
    let permissions = fs::metadata(packaged_binary)
        .map_err(|err| io_error(packaged_binary, &err))?
        .permissions();
    fs::set_permissions(&installed_binary, permissions).map_err(|err| {
        CliError::new(
            "doctor_package_smoke_error",
            "Failed to set install-smoke executable permissions",
        )
        .detail(err.to_string())
        .context("path", installed_binary.display().to_string())
        .context(
            "remediation",
            "Ensure executable permission bits are supported on this filesystem.".to_string(),
        )
        .exit_code(ExitCode::RUNTIME_ERROR)
    })?;
    let installed_binary_exec =
        resolve_install_smoke_binary_path(&installed_binary, "doctor_package_smoke_error")?;

    let startup = ProcessCommand::new(&installed_binary_exec)
        .arg("--help")
        .current_dir(&install_root)
        .output()
        .map_err(|err| {
            CliError::new(
                "doctor_package_smoke_error",
                "Failed to execute packaged binary startup probe",
            )
            .detail(err.to_string())
            .context("binary", installed_binary_exec.display().to_string())
            .context(
                "remediation",
                "Confirm packaged binary target architecture matches the current runtime."
                    .to_string(),
            )
            .exit_code(ExitCode::RUNTIME_ERROR)
        })?;
    if !startup.status.success() {
        return Err(CliError::new(
            "doctor_package_smoke_error",
            "Packaged binary startup probe exited non-zero",
        )
        .detail(format!("exit status: {}", startup.status))
        .context(
            "stderr",
            String::from_utf8_lossy(&startup.stderr).trim().to_string(),
        )
        .context(
            "remediation",
            "Inspect packaged binary permissions/target and run it manually with `--help`."
                .to_string(),
        )
        .exit_code(ExitCode::RUNTIME_ERROR));
    }

    let command = ProcessCommand::new(&installed_binary_exec)
        .arg("--format")
        .arg(config.output_format.as_str())
        .arg("--color")
        .arg(config.color.as_str())
        .arg("doctor")
        .arg(config.doctor_command.as_str())
        .current_dir(&install_root)
        .output()
        .map_err(|err| {
            CliError::new(
                "doctor_package_smoke_error",
                "Failed to execute packaged binary doctor command",
            )
            .detail(err.to_string())
            .context("binary", installed_binary_exec.display().to_string())
            .context(
                "remediation",
                "Verify packaged command compatibility and runtime shared-library availability."
                    .to_string(),
            )
            .exit_code(ExitCode::RUNTIME_ERROR)
        })?;
    if !command.status.success() {
        return Err(CliError::new(
            "doctor_package_smoke_error",
            "Packaged binary doctor command exited non-zero",
        )
        .detail(format!("exit status: {}", command.status))
        .context(
            "stderr",
            String::from_utf8_lossy(&command.stderr).trim().to_string(),
        )
        .context(
            "remediation",
            "Run packaged binary manually and verify `doctor report-contract` succeeds."
                .to_string(),
        )
        .exit_code(ExitCode::RUNTIME_ERROR));
    }
    let stdout = String::from_utf8(command.stdout).map_err(|err| {
        CliError::new(
            "doctor_package_smoke_error",
            "Packaged binary produced non-UTF8 smoke output",
        )
        .detail(err.to_string())
        .context(
            "remediation",
            "Use a UTF-8 locale and JSON output for packaged smoke validation.".to_string(),
        )
        .exit_code(ExitCode::RUNTIME_ERROR)
    })?;
    let payload: serde_json::Value = serde_json::from_str(&stdout).map_err(|err| {
        CliError::new(
            "doctor_package_smoke_error",
            "Packaged binary smoke output was not valid JSON",
        )
        .detail(err.to_string())
        .context("output", stdout.trim().to_string())
        .context(
            "remediation",
            "Ensure packaged config uses `output_format = json`.".to_string(),
        )
        .exit_code(ExitCode::RUNTIME_ERROR)
    })?;
    let observed_contract_version = payload
        .get("contract")
        .and_then(|contract| contract.get("contract_version"))
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .to_string();
    if observed_contract_version != "doctor-core-report-v1" {
        return Err(CliError::new(
            "doctor_package_smoke_error",
            "Packaged smoke output contract version mismatch",
        )
        .detail(observed_contract_version)
        .context("expected", "doctor-core-report-v1".to_string())
        .context(
            "remediation",
            "Run `doctor report-contract` from source binary and compare schema versions."
                .to_string(),
        )
        .exit_code(ExitCode::RUNTIME_ERROR));
    }
    Ok(DoctorPackageInstallSmokeResult {
        install_root: install_root.display().to_string(),
        installed_binary: installed_binary_exec.display().to_string(),
        startup_status: "ok".to_string(),
        command_status: "ok".to_string(),
        command_output_sha256: sha256_hex(stdout.as_bytes()),
        observed_contract_version,
    })
}

fn resolve_install_smoke_binary_path(
    installed_binary: &Path,
    error_type: &str,
) -> Result<PathBuf, CliError> {
    fs::canonicalize(installed_binary).map_err(|err| {
        CliError::new(
            error_type,
            "Failed to canonicalize install-smoke binary path",
        )
        .detail(err.to_string())
        .context("binary", installed_binary.display().to_string())
        .context(
            "remediation",
            "Use a writable out-dir and verify the packaged binary was created before smoke checks."
                .to_string(),
        )
        .exit_code(ExitCode::RUNTIME_ERROR)
    })
}

fn build_doctor_cli_release_manifest(
    package_version: &str,
    binary_name: &str,
    default_profile: &str,
    source_binary: &Path,
    packaged_binary: &Path,
    packaged_binary_size_bytes: u64,
    packaged_binary_sha256: &str,
    config_templates: &[DoctorPackageTemplateArtifact],
) -> DoctorCliPackageManifest {
    let mut template_entries = config_templates.to_vec();
    template_entries.sort_by(|left, right| left.profile.cmp(&right.profile));
    DoctorCliPackageManifest {
        schema_version: DOCTOR_CLI_PACKAGE_MANIFEST_SCHEMA_VERSION.to_string(),
        package_version: package_version.to_string(),
        binary_name: binary_name.to_string(),
        default_profile: default_profile.to_string(),
        source_binary: source_binary.display().to_string(),
        packaged_binary: packaged_binary.display().to_string(),
        packaged_binary_size_bytes,
        packaged_binary_sha256: packaged_binary_sha256.to_string(),
        config_templates: template_entries,
        supported_platforms: vec![
            "linux-x86_64".to_string(),
            "linux-aarch64".to_string(),
            "macos-x86_64".to_string(),
            "macos-aarch64".to_string(),
        ],
        compatibility_expectations: vec![
            "Config schema is additive-only within doctor-cli-package-config-v1.".to_string(),
            "Packaged smoke requires doctor report-contract to emit doctor-core-report-v1."
                .to_string(),
            "Operator CI flows should invoke cargo-heavy checks via rch exec.".to_string(),
        ],
        upgrade_path: vec![
            "Build new asupersync binary with rch exec -- cargo build --release --features cli --bin asupersync.".to_string(),
            "Re-run doctor package-cli and compare packaged_binary_sha256 in release manifests.".to_string(),
            "Promote package only if install smoke and e2e determinism checks remain green.".to_string(),
        ],
    }
}

fn doctor_package_log(
    level: &str,
    event: &str,
    message: &str,
    remediation_guidance: Option<&str>,
    fields: Vec<(&str, String)>,
) -> DoctorPackageStructuredLog {
    let mut normalized_fields = BTreeMap::new();
    for (key, value) in fields {
        normalized_fields.insert(key.to_string(), value);
    }
    DoctorPackageStructuredLog {
        level: level.to_string(),
        event: event.to_string(),
        message: message.to_string(),
        remediation_guidance: remediation_guidance.map(str::to_string),
        fields: normalized_fields,
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
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
        asupersync::lab::scenario_runner::ScenarioRunnerError::Validation {
            scenario_id,
            errors,
        } => {
            let detail = errors
                .iter()
                .map(|e| format!("- {e}"))
                .collect::<Vec<_>>()
                .join("\n");
            CliError::new("scenario_validation", "Scenario validation failed")
                .detail(format!(
                    "Scenario '{scenario_id}' failed validation with {} issue(s):\n{detail}",
                    errors.len()
                ))
                .context("scenario_id", scenario_id)
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

const LAB_DIFFERENTIAL_REPORT_SCHEMA_VERSION: &str = "lab-live-differential-runner-report-v1";
const LAB_DIFFERENTIAL_SUMMARY_SCHEMA_VERSION: &str = "lab-live-differential-run-summary-v1";
const LAB_DIFFERENTIAL_EVENT_SCHEMA_VERSION: &str = "lab-live-differential-event-v1";
const LAB_DIFFERENTIAL_ARTIFACT_INDEX_SCHEMA_VERSION: &str =
    "lab-live-differential-artifact-index-v1";
const LAB_DIFFERENTIAL_PROFILE_MANIFEST_SCHEMA_VERSION: &str =
    "lab-live-differential-profile-manifest-v1";

#[derive(Clone, Copy, Debug)]
enum LabDifferentialExpectation {
    Pass,
    Divergence {
        provisional: &'static str,
        final_policy: Option<DifferentialPolicyClass>,
    },
}

impl LabDifferentialExpectation {
    fn label(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Divergence { .. } => "expected_divergence",
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct LabDifferentialScenarioDefinition {
    id: &'static str,
    surface_id: &'static str,
    surface_contract_version: &'static str,
    description: &'static str,
    expectation: LabDifferentialExpectation,
    execute: fn(u64) -> asupersync::lab::DualRunResult,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum LabDifferentialScenarioStatus {
    Pass,
    ExpectedDivergence,
    UnexpectedDivergence,
    MissingExpectedDivergence,
}

impl LabDifferentialScenarioStatus {
    fn is_success(self) -> bool {
        matches!(self, Self::Pass | Self::ExpectedDivergence)
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::ExpectedDivergence => "expected_divergence",
            Self::UnexpectedDivergence => "unexpected_divergence",
            Self::MissingExpectedDivergence => "missing_expected_divergence",
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
struct LabDifferentialScenarioReport {
    scenario_id: String,
    surface_id: String,
    surface_contract_version: String,
    description: String,
    status: LabDifferentialScenarioStatus,
    expectation: String,
    runner_profile: String,
    seed_lineage_id: String,
    passed: bool,
    observed_provisional_class: String,
    observed_final_policy_class: Option<String>,
    expected_provisional_class: Option<String>,
    expected_final_policy_class: Option<String>,
    bundle_root: String,
    summary_path: String,
    event_log_path: String,
    lab_normalized_path: String,
    live_normalized_path: String,
    failures_path: Option<String>,
    deviations_path: Option<String>,
    repro_manifest_path: Option<String>,
    repro_commands: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct LabDifferentialOperatorProfileManifestEntry {
    profile_id: String,
    support_status: String,
    usage_class: String,
    tier_binding: String,
    scenario_pack: String,
    cli_profile: Option<String>,
    runtime_cost: String,
    operator_intent: String,
    exit_semantics: String,
    invocation_recipe: String,
    required_artifacts: Vec<String>,
    dependency_bead: Option<String>,
    scenario_ids: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct LabDifferentialProfileManifestOutput {
    schema_version: String,
    manifest_command: String,
    direct_cli_profiles: Vec<String>,
    operator_profiles: Vec<LabDifferentialOperatorProfileManifestEntry>,
}

impl Outputtable for LabDifferentialProfileManifestOutput {
    fn human_format(&self) -> String {
        let mut summary = String::new();
        let _ = writeln!(summary, "Differential profile manifest");
        let _ = writeln!(summary, "Schema: {}", self.schema_version);
        let _ = writeln!(summary, "Manifest command: {}", self.manifest_command);
        let _ = writeln!(
            summary,
            "Direct CLI profiles: {}",
            self.direct_cli_profiles.join(", ")
        );
        for profile in &self.operator_profiles {
            let _ = writeln!(
                summary,
                "- {} [{} / {} / {}]",
                profile.profile_id,
                profile.support_status,
                profile.usage_class,
                profile.tier_binding
            );
            let _ = writeln!(summary, "  scenario_pack: {}", profile.scenario_pack);
            let _ = writeln!(summary, "  runtime_cost: {}", profile.runtime_cost);
            let _ = writeln!(summary, "  invocation: {}", profile.invocation_recipe);
        }
        summary
    }
}

#[derive(Debug, Clone, serde::Serialize)]
struct LabDifferentialProfileContract {
    profile: String,
    evidence_grade: String,
    confidence_label: String,
    runtime_cost: String,
    operator_intent: String,
    exit_semantics: String,
    scenario_ids: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct LabDifferentialArtifactIndexScenario {
    scenario_id: String,
    status: LabDifferentialScenarioStatus,
    seed_lineage_id: String,
    observed_provisional_class: String,
    observed_final_policy_class: Option<String>,
    summary_path: String,
    event_log_path: String,
    lab_normalized_path: String,
    live_normalized_path: String,
    failures_path: Option<String>,
    deviations_path: Option<String>,
    repro_manifest_path: Option<String>,
    repro_commands: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct LabDifferentialArtifactIndex {
    schema_version: String,
    profile: String,
    evidence_grade: String,
    confidence_label: String,
    runtime_cost: String,
    operator_intent: String,
    exit_semantics: String,
    root_seed: u64,
    out_dir: String,
    runner_summary_path: String,
    operator_summary_path: String,
    aggregate_event_log_path: String,
    scenario_count: usize,
    scenarios: Vec<LabDifferentialArtifactIndexScenario>,
}

#[derive(Debug, serde::Serialize)]
struct LabDifferentialOutput {
    schema_version: String,
    profile: String,
    profile_contract: LabDifferentialProfileContract,
    root_seed: u64,
    success: bool,
    out_dir: String,
    runner_summary_path: String,
    operator_summary_path: String,
    artifact_index_path: String,
    aggregate_event_log_path: String,
    scenario_count: usize,
    pass_count: usize,
    expected_divergence_count: usize,
    unexpected_divergence_count: usize,
    missing_expected_divergence_count: usize,
    scenarios: Vec<LabDifferentialScenarioReport>,
}

impl Outputtable for LabDifferentialOutput {
    fn human_format(&self) -> String {
        render_lab_differential_operator_summary(self)
    }
}

impl LabDifferentialOutput {
    fn artifact_index(&self) -> LabDifferentialArtifactIndex {
        LabDifferentialArtifactIndex {
            schema_version: LAB_DIFFERENTIAL_ARTIFACT_INDEX_SCHEMA_VERSION.to_string(),
            profile: self.profile.clone(),
            evidence_grade: self.profile_contract.evidence_grade.clone(),
            confidence_label: self.profile_contract.confidence_label.clone(),
            runtime_cost: self.profile_contract.runtime_cost.clone(),
            operator_intent: self.profile_contract.operator_intent.clone(),
            exit_semantics: self.profile_contract.exit_semantics.clone(),
            root_seed: self.root_seed,
            out_dir: self.out_dir.clone(),
            runner_summary_path: self.runner_summary_path.clone(),
            operator_summary_path: self.operator_summary_path.clone(),
            aggregate_event_log_path: self.aggregate_event_log_path.clone(),
            scenario_count: self.scenario_count,
            scenarios: self
                .scenarios
                .iter()
                .map(|scenario| LabDifferentialArtifactIndexScenario {
                    scenario_id: scenario.scenario_id.clone(),
                    status: scenario.status,
                    seed_lineage_id: scenario.seed_lineage_id.clone(),
                    observed_provisional_class: scenario.observed_provisional_class.clone(),
                    observed_final_policy_class: scenario.observed_final_policy_class.clone(),
                    summary_path: scenario.summary_path.clone(),
                    event_log_path: scenario.event_log_path.clone(),
                    lab_normalized_path: scenario.lab_normalized_path.clone(),
                    live_normalized_path: scenario.live_normalized_path.clone(),
                    failures_path: scenario.failures_path.clone(),
                    deviations_path: scenario.deviations_path.clone(),
                    repro_manifest_path: scenario.repro_manifest_path.clone(),
                    repro_commands: scenario.repro_commands.clone(),
                })
                .collect(),
        }
    }
}

fn display_final_policy_class(scenario: &LabDifferentialScenarioReport) -> &str {
    scenario
        .observed_final_policy_class
        .as_deref()
        .unwrap_or_else(|| {
            if scenario.status == LabDifferentialScenarioStatus::Pass
                || scenario.observed_provisional_class == "pass"
            {
                "not_applicable"
            } else {
                "pending"
            }
        })
}

fn profile_evidence_grade(profile: LabDifferentialProfile) -> &'static str {
    match profile {
        LabDifferentialProfile::Smoke => "t2_dual_run_smoke",
        LabDifferentialProfile::Phase1Core => "t3_pilot_surface",
        LabDifferentialProfile::Calibration => "t4_negative_control",
    }
}

fn profile_confidence_label(profile: LabDifferentialProfile) -> &'static str {
    match profile {
        LabDifferentialProfile::Smoke => "baseline_signal",
        LabDifferentialProfile::Phase1Core => "surface_backed",
        LabDifferentialProfile::Calibration => "guardrail_validation",
    }
}

fn profile_runtime_cost(profile: LabDifferentialProfile) -> &'static str {
    match profile {
        LabDifferentialProfile::Smoke => "fast",
        LabDifferentialProfile::Phase1Core | LabDifferentialProfile::Calibration => "medium",
    }
}

fn profile_operator_intent(profile: LabDifferentialProfile) -> &'static str {
    match profile {
        LabDifferentialProfile::Smoke => "Fast shared signal for the semantic-core smoke surface.",
        LabDifferentialProfile::Phase1Core => {
            "Full Phase 1 pilot lane across admitted semantic surfaces."
        }
        LabDifferentialProfile::Calibration => {
            "Intentional divergence lane that proves classifier and artifact retention behavior."
        }
    }
}

fn lab_differential_exit_semantics() -> &'static str {
    "selected scenarios must end in pass or expected_divergence; unexpected_divergence and missing_expected_divergence fail the run"
}

fn lab_differential_required_artifacts() -> Vec<String> {
    vec![
        "runner_summary.json".to_string(),
        "operator_summary.txt".to_string(),
        "artifact_index.json".to_string(),
        "differential_event_log.jsonl".to_string(),
    ]
}

fn lab_differential_profile_manifest_direct_entry(
    profile: LabDifferentialProfile,
) -> LabDifferentialOperatorProfileManifestEntry {
    let args = LabDifferentialArgs {
        profile,
        scenarios: Vec::new(),
        seed: 424_242,
        out_dir: PathBuf::from("target/e2e-results/lab_live_differential"),
        json: true,
    };
    let scenario_ids = select_lab_differential_scenarios(&args)
        .expect("built-in differential profile must resolve")
        .into_iter()
        .map(|definition| definition.id.to_string())
        .collect::<Vec<_>>();
    let scenario_pack = match profile {
        LabDifferentialProfile::Smoke => "smoke_semantic_core",
        LabDifferentialProfile::Phase1Core => "phase1_core_floor",
        LabDifferentialProfile::Calibration => "calibration_negative_control",
    };
    let usage_class = match profile {
        LabDifferentialProfile::Smoke => "local_smoke",
        LabDifferentialProfile::Phase1Core => "targeted_core_validation",
        LabDifferentialProfile::Calibration => "self_calibration",
    };

    LabDifferentialOperatorProfileManifestEntry {
        profile_id: profile.as_str().to_string(),
        support_status: "shipped".to_string(),
        usage_class: usage_class.to_string(),
        tier_binding: profile_evidence_grade(profile).to_string(),
        scenario_pack: scenario_pack.to_string(),
        cli_profile: Some(profile.as_str().to_string()),
        runtime_cost: profile_runtime_cost(profile).to_string(),
        operator_intent: profile_operator_intent(profile).to_string(),
        exit_semantics: lab_differential_exit_semantics().to_string(),
        invocation_recipe: format!(
            "scripts/run_lab_live_differential.sh --profile {} --seed <seed> --out-dir <out-dir>",
            profile.as_str()
        ),
        required_artifacts: lab_differential_required_artifacts(),
        dependency_bead: None,
        scenario_ids,
    }
}

fn lab_differential_profile_manifest() -> LabDifferentialProfileManifestOutput {
    let direct_profiles = [
        LabDifferentialProfile::Smoke,
        LabDifferentialProfile::Phase1Core,
        LabDifferentialProfile::Calibration,
    ];
    let direct_profile_entries = direct_profiles
        .iter()
        .copied()
        .map(lab_differential_profile_manifest_direct_entry)
        .collect::<Vec<_>>();
    let phase1_core_scenario_ids = direct_profile_entries
        .iter()
        .find(|profile| profile.profile_id == LabDifferentialProfile::Phase1Core.as_str())
        .map(|profile| profile.scenario_ids.clone())
        .expect("phase1-core profile manifest entry must exist");
    let mut operator_profiles = direct_profile_entries;

    operator_profiles.push(LabDifferentialOperatorProfileManifestEntry {
        profile_id: "repro-targeted".to_string(),
        support_status: "shipped".to_string(),
        usage_class: "targeted_repro".to_string(),
        tier_binding: "selected_scenario_tier".to_string(),
        scenario_pack: "single_scenario_replay_or_reproduction".to_string(),
        cli_profile: Some(LabDifferentialProfile::Phase1Core.as_str().to_string()),
        runtime_cost: "targeted".to_string(),
        operator_intent: "Replay or reproduce one selected scenario with a pinned seed and retained artifacts.".to_string(),
        exit_semantics: lab_differential_exit_semantics().to_string(),
        invocation_recipe: "scripts/run_lab_live_differential.sh --profile phase1-core --scenario <scenario-id> --seed <seed> --out-dir <out-dir>".to_string(),
        required_artifacts: lab_differential_required_artifacts(),
        dependency_bead: None,
        scenario_ids: Vec::new(),
    });

    operator_profiles.push(LabDifferentialOperatorProfileManifestEntry {
        profile_id: "nightly-stress".to_string(),
        support_status: "shipped".to_string(),
        usage_class: "scheduled_stress".to_string(),
        tier_binding: "T5 stress_nightly".to_string(),
        scenario_pack: "rotating_seed_phase1_core_pack".to_string(),
        cli_profile: Some(LabDifferentialProfile::Phase1Core.as_str().to_string()),
        runtime_cost: "heavy".to_string(),
        operator_intent: "Rotating-seed scheduled stress lane that repeatedly runs the admitted Phase 1 core pack and retains escalation-ready divergence artifacts.".to_string(),
        exit_semantics: "Runs the admitted Phase 1 core pack across rotated seeds, fails on any unexpected divergence or artifact-contract regression, and writes nightly_stress_manifest.json plus per-seed replay pointers.".to_string(),
        invocation_recipe: "scripts/run_lab_live_differential.sh --profile nightly-stress --seed <seed> --seed-count <count> --seed-stride <stride> --rotation-date <date> --out-dir <out-dir>".to_string(),
        required_artifacts: {
            let mut artifacts = lab_differential_required_artifacts();
            artifacts.push("nightly_stress_manifest.json".to_string());
            artifacts.push("nightly_stress_summary.txt".to_string());
            artifacts.push("retained_divergence_artifacts/".to_string());
            artifacts
        },
        dependency_bead: None,
        scenario_ids: phase1_core_scenario_ids,
    });

    LabDifferentialProfileManifestOutput {
        schema_version: LAB_DIFFERENTIAL_PROFILE_MANIFEST_SCHEMA_VERSION.to_string(),
        manifest_command: "asupersync lab differential-profile-manifest --json".to_string(),
        direct_cli_profiles: direct_profiles
            .iter()
            .copied()
            .map(LabDifferentialProfile::as_str)
            .map(str::to_string)
            .collect(),
        operator_profiles,
    }
}

fn lab_differential_profile_manifest_command(
    args: &LabDifferentialProfileManifestArgs,
    output: &mut Output,
) -> Result<(), CliError> {
    let manifest = lab_differential_profile_manifest();
    if args.json {
        let pretty = serde_json::to_string_pretty(&manifest).map_err(output_cli_error)?;
        writeln!(io::stdout(), "{pretty}").map_err(output_cli_error)?;
        return Ok(());
    }

    output.write(&manifest).map_err(|err| {
        CliError::new(
            "output_error",
            "Failed to write differential profile manifest output",
        )
        .detail(err.to_string())
    })
}

fn lab_differential_profile_contract(
    profile: LabDifferentialProfile,
    selected: &[LabDifferentialScenarioDefinition],
) -> LabDifferentialProfileContract {
    LabDifferentialProfileContract {
        profile: profile.as_str().to_string(),
        evidence_grade: profile_evidence_grade(profile).to_string(),
        confidence_label: profile_confidence_label(profile).to_string(),
        runtime_cost: profile_runtime_cost(profile).to_string(),
        operator_intent: profile_operator_intent(profile).to_string(),
        exit_semantics: lab_differential_exit_semantics().to_string(),
        scenario_ids: selected
            .iter()
            .map(|definition| definition.id.to_string())
            .collect(),
    }
}

fn render_lab_differential_operator_summary(report: &LabDifferentialOutput) -> String {
    let mut summary = String::new();
    let status = if report.success { "pass" } else { "failure" };
    let _ = writeln!(summary, "Differential operator summary");
    let _ = writeln!(summary, "Profile: {}", report.profile);
    let _ = writeln!(
        summary,
        "Evidence grade: {}",
        report.profile_contract.evidence_grade
    );
    let _ = writeln!(
        summary,
        "Confidence label: {}",
        report.profile_contract.confidence_label
    );
    let _ = writeln!(
        summary,
        "Runtime cost: {}",
        report.profile_contract.runtime_cost
    );
    let _ = writeln!(
        summary,
        "Operator intent: {}",
        report.profile_contract.operator_intent
    );
    let _ = writeln!(summary, "Status: {status}");
    let _ = writeln!(summary, "Root seed: {}", report.root_seed);
    let _ = writeln!(
        summary,
        "Exit semantics: {}",
        report.profile_contract.exit_semantics
    );
    let _ = writeln!(
        summary,
        "Scenario pack: {}",
        report.profile_contract.scenario_ids.join(", ")
    );
    let _ = writeln!(
        summary,
        "Scenarios: {} (pass={}, expected_divergence={}, unexpected_divergence={}, missing_expected_divergence={})",
        report.scenario_count,
        report.pass_count,
        report.expected_divergence_count,
        report.unexpected_divergence_count,
        report.missing_expected_divergence_count,
    );
    let _ = writeln!(summary, "Artifacts:");
    let _ = writeln!(summary, "  runner_summary: {}", report.runner_summary_path);
    let _ = writeln!(
        summary,
        "  operator_summary: {}",
        report.operator_summary_path
    );
    let _ = writeln!(summary, "  artifact_index: {}", report.artifact_index_path);
    let _ = writeln!(
        summary,
        "  aggregate_event_log: {}",
        report.aggregate_event_log_path
    );
    let _ = writeln!(summary, "Scenario results:");
    for scenario in &report.scenarios {
        let _ = writeln!(
            summary,
            "- {} {} [{}] provisional={} final={} summary={}",
            scenario.status.as_str(),
            scenario.scenario_id,
            scenario.seed_lineage_id,
            scenario.observed_provisional_class,
            display_final_policy_class(scenario),
            scenario.summary_path
        );
        let _ = writeln!(summary, "  event_log: {}", scenario.event_log_path);
        let _ = writeln!(
            summary,
            "  lab_normalized: {}",
            scenario.lab_normalized_path
        );
        let _ = writeln!(
            summary,
            "  live_normalized: {}",
            scenario.live_normalized_path
        );
        if let Some(path) = &scenario.failures_path {
            let _ = writeln!(summary, "  failures: {path}");
        }
        if let Some(path) = &scenario.deviations_path {
            let _ = writeln!(summary, "  deviations: {path}");
        }
        if let Some(path) = &scenario.repro_manifest_path {
            let _ = writeln!(summary, "  repro_manifest: {path}");
        }
        let _ = writeln!(summary, "  replay:");
        for command in &scenario.repro_commands {
            let _ = writeln!(summary, "    {command}");
        }
    }
    summary
}

#[derive(Debug, Clone, serde::Serialize)]
struct LabDifferentialRunSummary {
    schema_version: String,
    scenario_id: String,
    surface_id: String,
    surface_contract_version: String,
    description: String,
    runner_profile: String,
    expectation: String,
    status: LabDifferentialScenarioStatus,
    attempt_count: u32,
    rerun_count: u32,
    seed_lineage_id: String,
    verdict_summary: String,
    initial_policy_summary: String,
    policy_summary: String,
    observed_provisional_class: String,
    observed_final_policy_class: Option<String>,
    expected_provisional_class: Option<String>,
    expected_final_policy_class: Option<String>,
    passed: bool,
    bundle_root: String,
    event_log_path: String,
    lab_normalized_path: String,
    live_normalized_path: String,
    failures_path: Option<String>,
    deviations_path: Option<String>,
    repro_manifest_path: Option<String>,
    repro_commands: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct LabDifferentialEventLogEntry {
    schema_version: String,
    suite_id: String,
    scenario_id: String,
    surface_id: String,
    surface_contract_version: String,
    description: String,
    seed_lineage_id: String,
    runner_profile: String,
    expectation: String,
    status: LabDifferentialScenarioStatus,
    attempt_index: u32,
    rerun_count: u32,
    attempt_kind: LabDifferentialAttemptKind,
    attempt_seed: u64,
    verdict_summary: String,
    policy_summary: String,
    resolution_summary: String,
    provisional_class: String,
    final_policy_class: Option<String>,
    summary_path: String,
    lab_normalized_path: String,
    live_normalized_path: String,
    failures_path: Option<String>,
    deviations_path: Option<String>,
    repro_manifest_path: Option<String>,
    lab_terminal_outcome: String,
    live_terminal_outcome: String,
    lab_loser_drain: String,
    live_loser_drain: String,
    lab_obligation_balanced: bool,
    live_obligation_balanced: bool,
    repro_commands: Vec<String>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum LabDifferentialAttemptKind {
    Initial,
    DeterministicLabReplay,
    LiveConfirmation,
    InstrumentationConfirmation,
}

#[derive(Debug, Clone)]
struct LabDifferentialAttempt {
    attempt_index: u32,
    kind: LabDifferentialAttemptKind,
    canonical_seed: u64,
    result: asupersync::lab::DualRunResult,
}

#[derive(Debug, Clone)]
struct LabDifferentialExecution {
    attempts: Vec<LabDifferentialAttempt>,
    final_policy_class: Option<DifferentialPolicyClass>,
    final_policy_summary: String,
}

impl LabDifferentialExecution {
    fn initial_attempt(&self) -> &LabDifferentialAttempt {
        self.attempts
            .first()
            .expect("differential execution always has an initial attempt")
    }

    fn attempt_count(&self) -> u32 {
        self.attempts.len() as u32
    }

    fn rerun_count(&self) -> u32 {
        self.attempt_count().saturating_sub(1)
    }
}

fn lab_differential(args: &LabDifferentialArgs, output: &mut Output) -> Result<(), CliError> {
    let report = run_lab_differential(args)?;
    let success = report.success;

    if args.json {
        let pretty = serde_json::to_string_pretty(&report).map_err(output_cli_error)?;
        writeln!(io::stdout(), "{pretty}").map_err(output_cli_error)?;
    } else {
        output.write(&report).map_err(|e| {
            CliError::new("output_error", "Failed to write output").detail(e.to_string())
        })?;
    }

    if !success {
        return Err(CliError::new(
            "lab_differential_failed",
            "Differential runner observed an unexpected result",
        )
        .exit_code(ExitCode::TEST_FAILURE));
    }

    Ok(())
}

fn run_lab_differential(args: &LabDifferentialArgs) -> Result<LabDifferentialOutput, CliError> {
    let selected = select_lab_differential_scenarios(args)?;
    let profile_contract = lab_differential_profile_contract(args.profile, &selected);
    let profile_root = args.out_dir.join(args.profile.as_str());
    let mut scenario_reports = Vec::new();
    let mut aggregate_event_log = Vec::new();

    for definition in selected.iter().copied() {
        let canonical_seed = derive_scenario_seed(args.seed, definition.id);
        let execution = execute_lab_differential_scenario(definition, canonical_seed);
        let initial_attempt = execution.initial_attempt();
        let result = &initial_attempt.result;

        let observed_final_policy = execution.final_policy_class;
        let observed_final_policy_string =
            observed_final_policy.map(|policy| policy.as_str().to_string());
        let observed_provisional = result.policy.provisional_class.to_string();
        let workflow_passed = result.passed() && observed_final_policy.is_none();

        let (status, expected_provisional, expected_final_policy) =
            evaluate_lab_differential_expectation(
                definition.expectation,
                workflow_passed,
                &observed_provisional,
                observed_final_policy,
            );

        let scenario_root = profile_root
            .join(sanitize_artifact_component(definition.id))
            .join(sanitize_artifact_component(
                &result.seed_lineage.seed_lineage_id,
            ));
        fs::create_dir_all(&scenario_root).map_err(|err| {
            CliError::new(
                "artifact_output_error",
                "Failed to create scenario artifact directory",
            )
            .detail(err.to_string())
            .context("path", scenario_root.display().to_string())
            .exit_code(ExitCode::RUNTIME_ERROR)
        })?;

        let bundle_root = scenario_root.display().to_string();
        let summary_path = scenario_root.join("differential_summary.json");
        let event_log_path = scenario_root.join("differential_event_log.jsonl");
        let lab_normalized_path = scenario_root.join("lab_normalized.json");
        let live_normalized_path = scenario_root.join("live_normalized.json");

        for attempt in &execution.attempts {
            let (attempt_lab_path, attempt_live_path) =
                differential_attempt_paths(&scenario_root, attempt.attempt_index);
            write_json_artifact(&attempt_lab_path, &attempt.result.lab)?;
            write_json_artifact(&attempt_live_path, &attempt.result.live)?;
        }

        let repro_commands = build_differential_rerun_commands(args, definition.id, &scenario_root);

        let bundle = observed_final_policy.map(|final_policy| {
            let entry = DivergenceCorpusEntry::from_dual_run_result(
                result,
                args.profile.as_str(),
                observed_provisional.clone(),
                final_policy,
                bundle_root.clone(),
            )
            .with_first_seen_attempt(0, execution.rerun_count());
            DifferentialBundleArtifacts::from_dual_run_result(&entry, result)
        });

        if let Some(artifacts) = &bundle {
            write_json_artifact(
                &scenario_root.join("differential_failures.json"),
                &artifacts.failures,
            )?;
            write_json_artifact(
                &scenario_root.join("differential_deviations.json"),
                &artifacts.deviations,
            )?;
            write_json_artifact(
                &scenario_root.join("differential_repro_manifest.json"),
                &artifacts.repro_manifest,
            )?;
        }

        let summary = LabDifferentialRunSummary {
            schema_version: LAB_DIFFERENTIAL_SUMMARY_SCHEMA_VERSION.to_string(),
            scenario_id: definition.id.to_string(),
            surface_id: definition.surface_id.to_string(),
            surface_contract_version: definition.surface_contract_version.to_string(),
            description: definition.description.to_string(),
            runner_profile: args.profile.as_str().to_string(),
            expectation: definition.expectation.label().to_string(),
            status,
            attempt_count: execution.attempt_count(),
            rerun_count: execution.rerun_count(),
            seed_lineage_id: result.seed_lineage.seed_lineage_id.clone(),
            verdict_summary: result.verdict.summary(),
            initial_policy_summary: result.policy.summary(),
            policy_summary: execution.final_policy_summary.clone(),
            observed_provisional_class: observed_provisional.clone(),
            observed_final_policy_class: observed_final_policy_string.clone(),
            expected_provisional_class: expected_provisional.clone(),
            expected_final_policy_class: expected_final_policy
                .as_ref()
                .map(|policy| policy.as_str().to_string()),
            passed: workflow_passed,
            bundle_root: bundle_root.clone(),
            event_log_path: event_log_path.display().to_string(),
            lab_normalized_path: lab_normalized_path.display().to_string(),
            live_normalized_path: live_normalized_path.display().to_string(),
            failures_path: bundle.as_ref().map(|_| {
                scenario_root
                    .join("differential_failures.json")
                    .display()
                    .to_string()
            }),
            deviations_path: bundle.as_ref().map(|_| {
                scenario_root
                    .join("differential_deviations.json")
                    .display()
                    .to_string()
            }),
            repro_manifest_path: bundle.as_ref().map(|_| {
                scenario_root
                    .join("differential_repro_manifest.json")
                    .display()
                    .to_string()
            }),
            repro_commands: repro_commands.clone(),
        };
        write_json_artifact(&summary_path, &summary)?;

        let event_entries = execution
            .attempts
            .iter()
            .map(|attempt| {
                let (attempt_lab_path, attempt_live_path) =
                    differential_attempt_paths(&scenario_root, attempt.attempt_index);
                LabDifferentialEventLogEntry {
                    schema_version: LAB_DIFFERENTIAL_EVENT_SCHEMA_VERSION.to_string(),
                    suite_id: "lab_live_differential".to_string(),
                    scenario_id: definition.id.to_string(),
                    surface_id: definition.surface_id.to_string(),
                    surface_contract_version: definition.surface_contract_version.to_string(),
                    description: definition.description.to_string(),
                    seed_lineage_id: attempt.result.seed_lineage.seed_lineage_id.clone(),
                    runner_profile: args.profile.as_str().to_string(),
                    expectation: definition.expectation.label().to_string(),
                    status,
                    attempt_index: attempt.attempt_index,
                    rerun_count: execution.rerun_count(),
                    attempt_kind: attempt.kind,
                    attempt_seed: attempt.canonical_seed,
                    verdict_summary: attempt.result.verdict.summary(),
                    policy_summary: attempt.result.policy.summary(),
                    resolution_summary: execution.final_policy_summary.clone(),
                    provisional_class: attempt.result.policy.provisional_class.to_string(),
                    final_policy_class: observed_final_policy
                        .map(|policy| policy.as_str().to_string()),
                    summary_path: summary_path.display().to_string(),
                    lab_normalized_path: attempt_lab_path.display().to_string(),
                    live_normalized_path: attempt_live_path.display().to_string(),
                    failures_path: summary.failures_path.clone(),
                    deviations_path: summary.deviations_path.clone(),
                    repro_manifest_path: summary.repro_manifest_path.clone(),
                    lab_terminal_outcome: attempt
                        .result
                        .lab
                        .semantics
                        .terminal_outcome
                        .class
                        .to_string(),
                    live_terminal_outcome: attempt
                        .result
                        .live
                        .semantics
                        .terminal_outcome
                        .class
                        .to_string(),
                    lab_loser_drain: drain_status_label(
                        attempt.result.lab.semantics.loser_drain.status,
                    )
                    .to_string(),
                    live_loser_drain: drain_status_label(
                        attempt.result.live.semantics.loser_drain.status,
                    )
                    .to_string(),
                    lab_obligation_balanced: attempt
                        .result
                        .lab
                        .semantics
                        .obligation_balance
                        .balanced,
                    live_obligation_balanced: attempt
                        .result
                        .live
                        .semantics
                        .obligation_balance
                        .balanced,
                    repro_commands: repro_commands.clone(),
                }
            })
            .collect::<Vec<_>>();
        write_jsonl_artifact(&event_log_path, &event_entries)?;

        scenario_reports.push(LabDifferentialScenarioReport {
            scenario_id: definition.id.to_string(),
            surface_id: definition.surface_id.to_string(),
            surface_contract_version: definition.surface_contract_version.to_string(),
            description: definition.description.to_string(),
            status,
            expectation: definition.expectation.label().to_string(),
            runner_profile: args.profile.as_str().to_string(),
            seed_lineage_id: result.seed_lineage.seed_lineage_id.clone(),
            passed: workflow_passed,
            observed_provisional_class: observed_provisional.clone(),
            observed_final_policy_class: observed_final_policy_string.clone(),
            expected_provisional_class: expected_provisional,
            expected_final_policy_class: expected_final_policy
                .map(|policy| policy.as_str().to_string()),
            bundle_root,
            summary_path: summary_path.display().to_string(),
            event_log_path: event_log_path.display().to_string(),
            lab_normalized_path: lab_normalized_path.display().to_string(),
            live_normalized_path: live_normalized_path.display().to_string(),
            failures_path: summary.failures_path.clone(),
            deviations_path: summary.deviations_path.clone(),
            repro_manifest_path: summary.repro_manifest_path.clone(),
            repro_commands,
        });
        aggregate_event_log.extend(event_entries);
    }

    let aggregate_event_log_path = profile_root.join("differential_event_log.jsonl");
    let runner_summary_path = profile_root.join("runner_summary.json");
    let operator_summary_path = profile_root.join("operator_summary.txt");
    let artifact_index_path = profile_root.join("artifact_index.json");
    write_jsonl_artifact(&aggregate_event_log_path, &aggregate_event_log)?;

    let pass_count = scenario_reports
        .iter()
        .filter(|report| report.status == LabDifferentialScenarioStatus::Pass)
        .count();
    let expected_divergence_count = scenario_reports
        .iter()
        .filter(|report| report.status == LabDifferentialScenarioStatus::ExpectedDivergence)
        .count();
    let unexpected_divergence_count = scenario_reports
        .iter()
        .filter(|report| report.status == LabDifferentialScenarioStatus::UnexpectedDivergence)
        .count();
    let missing_expected_divergence_count = scenario_reports
        .iter()
        .filter(|report| report.status == LabDifferentialScenarioStatus::MissingExpectedDivergence)
        .count();

    let report = LabDifferentialOutput {
        schema_version: LAB_DIFFERENTIAL_REPORT_SCHEMA_VERSION.to_string(),
        profile: args.profile.as_str().to_string(),
        profile_contract,
        root_seed: args.seed,
        success: scenario_reports
            .iter()
            .all(|report| report.status.is_success()),
        out_dir: profile_root.display().to_string(),
        runner_summary_path: runner_summary_path.display().to_string(),
        operator_summary_path: operator_summary_path.display().to_string(),
        artifact_index_path: artifact_index_path.display().to_string(),
        aggregate_event_log_path: aggregate_event_log_path.display().to_string(),
        scenario_count: scenario_reports.len(),
        pass_count,
        expected_divergence_count,
        unexpected_divergence_count,
        missing_expected_divergence_count,
        scenarios: scenario_reports,
    };
    write_json_artifact(&runner_summary_path, &report)?;
    write_json_artifact(&artifact_index_path, &report.artifact_index())?;
    write_text_artifact(&operator_summary_path, &report.human_format())?;

    Ok(report)
}

fn select_lab_differential_scenarios(
    args: &LabDifferentialArgs,
) -> Result<Vec<LabDifferentialScenarioDefinition>, CliError> {
    let available: Vec<_> = lab_differential_scenarios()
        .into_iter()
        .filter(|definition| {
            profile_includes_lab_differential_scenario(args.profile, definition.id)
        })
        .collect();

    if args.scenarios.is_empty() {
        return Ok(available);
    }

    let requested: BTreeSet<String> = args.scenarios.iter().cloned().collect();
    let selected: Vec<_> = available
        .iter()
        .copied()
        .filter(|definition| requested.contains(definition.id))
        .collect();

    if selected.len() != requested.len() {
        let available_ids = available
            .iter()
            .map(|definition| definition.id)
            .collect::<Vec<_>>()
            .join(", ");
        let missing = requested
            .iter()
            .filter(|scenario| {
                !available
                    .iter()
                    .any(|definition| definition.id == scenario.as_str())
            })
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        return Err(CliError::new(
            "lab_differential_unknown_scenario",
            "Unknown differential scenario selection",
        )
        .detail(format!(
            "Requested scenario(s) not in profile '{}': {}. Available: {}",
            args.profile.as_str(),
            missing,
            available_ids
        ))
        .exit_code(ExitCode::RUNTIME_ERROR));
    }

    Ok(selected)
}

fn lab_differential_scenarios() -> Vec<LabDifferentialScenarioDefinition> {
    vec![
        LabDifferentialScenarioDefinition {
            id: "phase1.cancel.protocol.drain_finalize",
            surface_id: "cancellation.protocol",
            surface_contract_version: "cancel.protocol.v1",
            description: "Completed cancellation protocol with balanced cleanup.",
            expectation: LabDifferentialExpectation::Pass,
            execute: run_phase1_cancel_protocol_scenario,
        },
        LabDifferentialScenarioDefinition {
            id: "phase1.cancel.protocol.before_first_poll",
            surface_id: "cancellation.protocol",
            surface_contract_version: "cancel.protocol.v1",
            description: "Cancellation requested before the first checkpoint still finalizes cleanly.",
            expectation: LabDifferentialExpectation::Pass,
            execute: run_phase1_cancel_before_first_poll_scenario,
        },
        LabDifferentialScenarioDefinition {
            id: "phase1.cancel.protocol.child_await",
            surface_id: "cancellation.protocol",
            surface_contract_version: "cancel.protocol.v1",
            description: "Cancellation during a child await drains the child before finalization.",
            expectation: LabDifferentialExpectation::Pass,
            execute: run_phase1_cancel_child_await_scenario,
        },
        LabDifferentialScenarioDefinition {
            id: "phase1.cancel.protocol.cleanup_budget",
            surface_id: "cancellation.protocol",
            surface_contract_version: "cancel.protocol.v1",
            description: "Cancellation during bounded cleanup completes within the cleanup budget.",
            expectation: LabDifferentialExpectation::Pass,
            execute: run_phase1_cancel_cleanup_budget_scenario,
        },
        LabDifferentialScenarioDefinition {
            id: "phase1.combinator.race.one_loser",
            surface_id: "combinator.race",
            surface_contract_version: "combinator.race.v1",
            description: "Winner selection with complete loser drain.",
            expectation: LabDifferentialExpectation::Pass,
            execute: run_phase1_combinator_race_scenario,
        },
        LabDifferentialScenarioDefinition {
            id: "phase1.channel.reserve_send.commit",
            surface_id: "channel.reserve_send",
            surface_contract_version: "channel.reserve_send.v1",
            description: "Committed reserve/send path remains visible and balanced.",
            expectation: LabDifferentialExpectation::Pass,
            execute: run_phase1_channel_commit_scenario,
        },
        LabDifferentialScenarioDefinition {
            id: "phase1.channel.reserve_send.abort_visible",
            surface_id: "channel.reserve_send",
            surface_contract_version: "channel.reserve_send.v1",
            description: "Cancelled reservation aborts cleanly without surfacing a phantom commit.",
            expectation: LabDifferentialExpectation::Pass,
            execute: run_phase1_channel_abort_scenario,
        },
        LabDifferentialScenarioDefinition {
            id: "phase1.region.close.quiescent",
            surface_id: "region.close",
            surface_contract_version: "region.close.v1",
            description: "Region close reaches quiescence with no leaked obligations.",
            expectation: LabDifferentialExpectation::Pass,
            execute: run_phase1_region_close_scenario,
        },
        LabDifferentialScenarioDefinition {
            id: "phase1.sync.semaphore.cancel_recovery",
            surface_id: "sync.semaphore.cancel_recovery",
            surface_contract_version: SYNC_SEMAPHORE_CANCEL_RECOVERY_CONTRACT_VERSION,
            description: "Semaphore differential pilot preserves waiter cancellation cleanup and permit recovery.",
            expectation: LabDifferentialExpectation::Pass,
            execute: run_phase1_sync_semaphore_cancel_recovery_scenario,
        },
        LabDifferentialScenarioDefinition {
            id: "calibration.combinator.loser_not_drained",
            surface_id: "combinator.race",
            surface_contract_version: "combinator.race.v1",
            description: "Intentional live-side undrained loser to prove combinator drain violations stay loud.",
            expectation: LabDifferentialExpectation::Divergence {
                provisional: "hard_contract_break",
                final_policy: Some(DifferentialPolicyClass::RuntimeSemanticBug),
            },
            execute: run_calibration_combinator_loser_not_drained_scenario,
        },
        LabDifferentialScenarioDefinition {
            id: "calibration.cancellation.cleanup_missing",
            surface_id: "cancellation.protocol",
            surface_contract_version: "cancel.protocol.v1",
            description: "Intentional live-side cleanup gap to prove classifier and report flow.",
            expectation: LabDifferentialExpectation::Divergence {
                provisional: "hard_contract_break",
                final_policy: Some(DifferentialPolicyClass::RuntimeSemanticBug),
            },
            execute: run_calibration_cleanup_missing_scenario,
        },
        LabDifferentialScenarioDefinition {
            id: "calibration.cancellation.cleanup_budget_exhausted",
            surface_id: "cancellation.protocol",
            surface_contract_version: "cancel.protocol.v1",
            description: "Intentional cleanup-budget exhaustion to prove cancellation-budget mismatches stay loud.",
            expectation: LabDifferentialExpectation::Divergence {
                provisional: "hard_contract_break",
                final_policy: Some(DifferentialPolicyClass::RuntimeSemanticBug),
            },
            execute: run_calibration_cleanup_budget_exhausted_scenario,
        },
        LabDifferentialScenarioDefinition {
            id: "calibration.comparator.resource_counter_mismatch",
            surface_id: "resource.surface",
            surface_contract_version: "resource.surface.v1",
            description: "Intentional admitted-surface resource counter drift to prove comparator detection and report quality.",
            expectation: LabDifferentialExpectation::Divergence {
                provisional: "semantic_mismatch_admitted_surface",
                final_policy: None,
            },
            execute: run_calibration_resource_counter_mismatch_scenario,
        },
        LabDifferentialScenarioDefinition {
            id: "calibration.channel.commit_visibility_mismatch",
            surface_id: "channel.reserve_send",
            surface_contract_version: "channel.reserve_send.v1",
            description: "Intentional committed-vs-aborted visibility drift to prove channel mismatches stay loud.",
            expectation: LabDifferentialExpectation::Divergence {
                provisional: "semantic_mismatch_admitted_surface",
                final_policy: None,
            },
            execute: run_calibration_channel_commit_visibility_mismatch_scenario,
        },
        LabDifferentialScenarioDefinition {
            id: "calibration.obligation.leak_detected",
            surface_id: "obligation.balance",
            surface_contract_version: "obligation.balance.v1",
            description: "Intentional live-side obligation leak to prove artifact retention.",
            expectation: LabDifferentialExpectation::Divergence {
                provisional: "hard_contract_break",
                final_policy: Some(DifferentialPolicyClass::RuntimeSemanticBug),
            },
            execute: run_calibration_obligation_leak_scenario,
        },
        LabDifferentialScenarioDefinition {
            id: "calibration.region.close.non_quiescent",
            surface_id: "region.close",
            surface_contract_version: "region.close.v1",
            description: "Intentional live-side non-quiescent root close to prove quiescence violations stay loud.",
            expectation: LabDifferentialExpectation::Divergence {
                provisional: "hard_contract_break",
                final_policy: Some(DifferentialPolicyClass::RuntimeSemanticBug),
            },
            execute: run_calibration_region_non_quiescent_close_scenario,
        },
    ]
}

fn profile_includes_lab_differential_scenario(
    profile: LabDifferentialProfile,
    scenario_id: &str,
) -> bool {
    match profile {
        LabDifferentialProfile::Smoke => matches!(
            scenario_id,
            "phase1.cancel.protocol.drain_finalize"
                | "phase1.combinator.race.one_loser"
                | "phase1.channel.reserve_send.commit"
        ),
        LabDifferentialProfile::Phase1Core => matches!(
            scenario_id,
            "phase1.cancel.protocol.drain_finalize"
                | "phase1.cancel.protocol.before_first_poll"
                | "phase1.cancel.protocol.child_await"
                | "phase1.cancel.protocol.cleanup_budget"
                | "phase1.combinator.race.one_loser"
                | "phase1.channel.reserve_send.commit"
                | "phase1.channel.reserve_send.abort_visible"
                | "phase1.region.close.quiescent"
                | "phase1.sync.semaphore.cancel_recovery"
        ),
        LabDifferentialProfile::Calibration => matches!(
            scenario_id,
            "phase1.cancel.protocol.drain_finalize"
                | "calibration.combinator.loser_not_drained"
                | "calibration.cancellation.cleanup_missing"
                | "calibration.cancellation.cleanup_budget_exhausted"
                | "calibration.comparator.resource_counter_mismatch"
                | "calibration.channel.commit_visibility_mismatch"
                | "calibration.obligation.leak_detected"
                | "calibration.region.close.non_quiescent"
        ),
    }
}

fn evaluate_lab_differential_expectation(
    expectation: LabDifferentialExpectation,
    passed: bool,
    observed_provisional: &str,
    observed_final_policy: Option<DifferentialPolicyClass>,
) -> (
    LabDifferentialScenarioStatus,
    Option<String>,
    Option<DifferentialPolicyClass>,
) {
    match expectation {
        LabDifferentialExpectation::Pass => {
            let status = if passed {
                LabDifferentialScenarioStatus::Pass
            } else {
                LabDifferentialScenarioStatus::UnexpectedDivergence
            };
            (status, None, None)
        }
        LabDifferentialExpectation::Divergence {
            provisional,
            final_policy,
        } => {
            if passed {
                return (
                    LabDifferentialScenarioStatus::MissingExpectedDivergence,
                    Some(provisional.to_string()),
                    final_policy,
                );
            }

            let final_policy_matches =
                final_policy.is_none() || observed_final_policy == final_policy;
            let status = if observed_provisional == provisional && final_policy_matches {
                LabDifferentialScenarioStatus::ExpectedDivergence
            } else {
                LabDifferentialScenarioStatus::UnexpectedDivergence
            };
            (status, Some(provisional.to_string()), final_policy)
        }
    }
}

fn build_differential_rerun_commands(
    args: &LabDifferentialArgs,
    scenario_id: &str,
    _scenario_root: &Path,
) -> Vec<String> {
    vec![
        format!(
            "asupersync lab differential --profile {} --scenario {} --seed {} --out-dir {}",
            shell_escape_command_arg(args.profile.as_str()),
            shell_escape_command_arg(scenario_id),
            args.seed,
            shell_escape_command_arg(&args.out_dir.display().to_string())
        ),
        format!(
            "scripts/run_lab_live_differential.sh --profile {} --scenario {} --seed {} --out-dir {}",
            shell_escape_command_arg(args.profile.as_str()),
            shell_escape_command_arg(scenario_id),
            args.seed,
            shell_escape_command_arg(&args.out_dir.display().to_string())
        ),
    ]
}

fn shell_escape_command_arg(value: &str) -> String {
    if value.is_empty() {
        return "''".to_string();
    }
    if value.chars().all(|ch| {
        ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '/' | ':' | '=' | ',')
    }) {
        value.to_string()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

fn differential_attempt_paths(scenario_root: &Path, attempt_index: u32) -> (PathBuf, PathBuf) {
    let attempt_root = if attempt_index == 0 {
        scenario_root.to_path_buf()
    } else {
        scenario_root
            .join("attempts")
            .join(format!("attempt-{attempt_index:02}"))
    };
    (
        attempt_root.join("lab_normalized.json"),
        attempt_root.join("live_normalized.json"),
    )
}

fn sanitize_artifact_component(input: &str) -> String {
    input
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>()
}

fn differential_policy_class_from_final(
    final_class: FinalDivergenceClass,
) -> DifferentialPolicyClass {
    match final_class {
        FinalDivergenceClass::RuntimeSemanticBug => DifferentialPolicyClass::RuntimeSemanticBug,
        FinalDivergenceClass::LabModelOrMappingBug => DifferentialPolicyClass::LabModelOrMappingBug,
        FinalDivergenceClass::IrreproducibleDivergence => {
            DifferentialPolicyClass::IrreproducibleDivergence
        }
        FinalDivergenceClass::UnsupportedSurface => DifferentialPolicyClass::UnsupportedSurface,
        FinalDivergenceClass::ArtifactSchemaViolation => {
            DifferentialPolicyClass::ArtifactSchemaViolation
        }
        FinalDivergenceClass::InsufficientObservability => {
            DifferentialPolicyClass::InsufficientObservability
        }
        FinalDivergenceClass::SchedulerNoiseSuspected => {
            DifferentialPolicyClass::SchedulerNoiseSuspected
        }
    }
}

fn execute_lab_differential_scenario(
    definition: LabDifferentialScenarioDefinition,
    canonical_seed: u64,
) -> LabDifferentialExecution {
    let mut attempts = vec![LabDifferentialAttempt {
        attempt_index: 0,
        kind: LabDifferentialAttemptKind::Initial,
        canonical_seed,
        result: (definition.execute)(canonical_seed),
    }];

    match attempts[0].result.policy.rerun_decision {
        RerunDecision::None => {}
        RerunDecision::LiveConfirmations { additional_runs } => {
            for seed in differential_confirmation_seeds(
                canonical_seed,
                definition.id,
                usize::from(additional_runs),
            ) {
                attempts.push(LabDifferentialAttempt {
                    attempt_index: attempts.len() as u32,
                    kind: LabDifferentialAttemptKind::LiveConfirmation,
                    canonical_seed: seed,
                    result: (definition.execute)(seed),
                });
            }
        }
        RerunDecision::DeterministicLabReplayAndLiveConfirmations {
            additional_live_runs,
        } => {
            attempts.push(LabDifferentialAttempt {
                attempt_index: attempts.len() as u32,
                kind: LabDifferentialAttemptKind::DeterministicLabReplay,
                canonical_seed,
                result: (definition.execute)(canonical_seed),
            });
            for seed in differential_confirmation_seeds(
                canonical_seed,
                definition.id,
                usize::from(additional_live_runs),
            ) {
                attempts.push(LabDifferentialAttempt {
                    attempt_index: attempts.len() as u32,
                    kind: LabDifferentialAttemptKind::LiveConfirmation,
                    canonical_seed: seed,
                    result: (definition.execute)(seed),
                });
            }
        }
        RerunDecision::ConfirmationIfRicherInstrumentationEnabled { additional_runs } => {
            for _ in 0..additional_runs {
                attempts.push(LabDifferentialAttempt {
                    attempt_index: attempts.len() as u32,
                    kind: LabDifferentialAttemptKind::InstrumentationConfirmation,
                    canonical_seed,
                    result: (definition.execute)(canonical_seed),
                });
            }
        }
    }

    let (final_policy_class, final_policy_summary) = resolve_lab_differential_policy(&attempts);
    LabDifferentialExecution {
        attempts,
        final_policy_class,
        final_policy_summary,
    }
}

fn differential_confirmation_seeds(
    canonical_seed: u64,
    scenario_id: &str,
    count: usize,
) -> Vec<u64> {
    SeedPlan::inherit(canonical_seed, scenario_id)
        .with_replay_policy(ReplayPolicy::SeedSweep)
        .sweep_seeds(count)
}

fn resolve_lab_differential_policy(
    attempts: &[LabDifferentialAttempt],
) -> (Option<DifferentialPolicyClass>, String) {
    let initial = attempts
        .first()
        .expect("differential policy resolution requires an initial attempt");
    let initial_result = &initial.result;
    let initial_final_policy = initial_result
        .policy
        .suggested_final_class
        .map(differential_policy_class_from_final);

    match initial_result.policy.rerun_decision {
        RerunDecision::None => (initial_final_policy, initial_result.policy.summary()),
        RerunDecision::LiveConfirmations { additional_runs } => {
            if attempts
                .iter()
                .filter(|attempt| attempt.kind == LabDifferentialAttemptKind::LiveConfirmation)
                .all(|attempt| attempt.result.passed())
            {
                return (
                    Some(DifferentialPolicyClass::SchedulerNoiseSuspected),
                    format!(
                        "scheduler/provenance drift stayed semantically equal across {} total live observations; finalize scheduler_noise_suspected",
                        1 + additional_runs
                    ),
                );
            }

            (
                Some(DifferentialPolicyClass::IrreproducibleDivergence),
                format!(
                    "scheduler-noise candidate produced semantic drift during {} live confirmation rerun(s) and did not stabilize",
                    additional_runs
                ),
            )
        }
        RerunDecision::DeterministicLabReplayAndLiveConfirmations {
            additional_live_runs,
        } => {
            if let Some(replay_attempt) = attempts
                .iter()
                .find(|attempt| attempt.kind == LabDifferentialAttemptKind::DeterministicLabReplay)
            {
                let lab_replay = asupersync::lab::compare_observables(
                    &initial_result.lab,
                    &replay_attempt.result.lab,
                    initial_result.seed_lineage.clone(),
                );
                if !lab_replay.passed
                    || initial_result.lab_invariant_violations
                        != replay_attempt.result.lab_invariant_violations
                {
                    return (
                        Some(DifferentialPolicyClass::LabModelOrMappingBug),
                        format!(
                            "deterministic lab replay changed its normalized answer on attempt {}; finalize lab_model_or_mapping_bug",
                            replay_attempt.attempt_index
                        ),
                    );
                }
            }

            let live_attempts = attempts
                .iter()
                .filter(|attempt| {
                    matches!(
                        attempt.kind,
                        LabDifferentialAttemptKind::Initial
                            | LabDifferentialAttemptKind::LiveConfirmation
                    )
                })
                .collect::<Vec<_>>();

            if live_attempts
                .iter()
                .any(|attempt| is_immediate_runtime_bug(&attempt.result))
            {
                return (
                    Some(DifferentialPolicyClass::RuntimeSemanticBug),
                    "at least one live observation showed a hard contract break; finalize runtime_semantic_bug"
                        .to_string(),
                );
            }

            let mut mismatch_counts = BTreeMap::<String, usize>::new();
            for attempt in &live_attempts {
                if let Some(signature) = mismatch_signature(&attempt.result) {
                    *mismatch_counts.entry(signature).or_default() += 1;
                }
            }

            if let Some((signature, count)) = mismatch_counts.iter().find(|(_, count)| **count >= 2)
            {
                return (
                    Some(DifferentialPolicyClass::RuntimeSemanticBug),
                    format!(
                        "semantic mismatch signature '{signature}' survived in {count} of {} live observations; finalize runtime_semantic_bug",
                        live_attempts.len()
                    ),
                );
            }

            if live_attempts
                .iter()
                .skip(1)
                .all(|attempt| attempt.result.passed())
            {
                return (
                    Some(DifferentialPolicyClass::SchedulerNoiseSuspected),
                    format!(
                        "semantic mismatch disappeared across {} live confirmation rerun(s); finalize scheduler_noise_suspected",
                        additional_live_runs
                    ),
                );
            }

            (
                Some(DifferentialPolicyClass::IrreproducibleDivergence),
                format!(
                    "semantic mismatch did not stabilize across the deterministic lab replay plus {} live confirmation rerun(s); finalize irreproducible_divergence",
                    additional_live_runs
                ),
            )
        }
        RerunDecision::ConfirmationIfRicherInstrumentationEnabled { additional_runs } => {
            if let Some(final_policy) = attempts
                .iter()
                .skip(1)
                .filter_map(|attempt| {
                    attempt
                        .result
                        .policy
                        .suggested_final_class
                        .map(differential_policy_class_from_final)
                })
                .find(|policy| *policy != DifferentialPolicyClass::InsufficientObservability)
            {
                return (
                    Some(final_policy),
                    format!(
                        "instrumentation confirmation rerun produced a stronger final class ({final_policy}); finalize with that class"
                    ),
                );
            }

            (
                Some(DifferentialPolicyClass::InsufficientObservability),
                format!(
                    "required evidence remained insufficient after {} confirmation rerun(s); finalize insufficient_observability",
                    additional_runs
                ),
            )
        }
    }
}

fn is_immediate_runtime_bug(result: &asupersync::lab::DualRunResult) -> bool {
    result.policy.suggested_final_class == Some(FinalDivergenceClass::RuntimeSemanticBug)
}

fn mismatch_signature(result: &asupersync::lab::DualRunResult) -> Option<String> {
    if result.passed() {
        return None;
    }

    let mut fields = result
        .verdict
        .mismatches
        .iter()
        .map(|mismatch| mismatch.field.as_str())
        .collect::<Vec<_>>();
    fields.sort_unstable();
    fields.dedup();
    Some(fields.join("|"))
}

fn drain_status_label(status: asupersync::lab::DrainStatus) -> &'static str {
    match status {
        asupersync::lab::DrainStatus::NotApplicable => "not_applicable",
        asupersync::lab::DrainStatus::Complete => "complete",
        asupersync::lab::DrainStatus::Incomplete => "incomplete",
    }
}

fn write_json_artifact<T: serde::Serialize>(path: &Path, value: &T) -> Result<(), CliError> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
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

    let payload = serde_json::to_vec_pretty(value).map_err(|err| {
        CliError::new(
            "artifact_output_error",
            "Failed to serialize artifact payload",
        )
        .detail(err.to_string())
        .context("path", path.display().to_string())
        .exit_code(ExitCode::RUNTIME_ERROR)
    })?;

    fs::write(path, payload).map_err(|err| {
        CliError::new("artifact_output_error", "Failed to write artifact payload")
            .detail(err.to_string())
            .context("path", path.display().to_string())
            .exit_code(ExitCode::RUNTIME_ERROR)
    })
}

fn write_jsonl_artifact<T: serde::Serialize>(path: &Path, entries: &[T]) -> Result<(), CliError> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
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

    let mut file = File::create(path).map_err(|err| {
        CliError::new("artifact_output_error", "Failed to create jsonl artifact")
            .detail(err.to_string())
            .context("path", path.display().to_string())
            .exit_code(ExitCode::RUNTIME_ERROR)
    })?;

    for entry in entries {
        serde_json::to_writer(&mut file, entry).map_err(|err| {
            CliError::new(
                "artifact_output_error",
                "Failed to serialize jsonl artifact entry",
            )
            .detail(err.to_string())
            .context("path", path.display().to_string())
            .exit_code(ExitCode::RUNTIME_ERROR)
        })?;
        writeln!(file).map_err(|err| {
            CliError::new(
                "artifact_output_error",
                "Failed to write jsonl artifact entry",
            )
            .detail(err.to_string())
            .context("path", path.display().to_string())
            .exit_code(ExitCode::RUNTIME_ERROR)
        })?;
    }

    Ok(())
}

fn write_text_artifact(path: &Path, contents: &str) -> Result<(), CliError> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
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

    fs::write(path, contents).map_err(|err| {
        CliError::new("artifact_output_error", "Failed to write artifact text")
            .detail(err.to_string())
            .context("path", path.display().to_string())
            .exit_code(ExitCode::RUNTIME_ERROR)
    })
}

fn make_normalized_semantics(
    surface_scope: &str,
    terminal_outcome: TerminalOutcome,
    cancellation: CancellationRecord,
    loser_drain: LoserDrainRecord,
    region_close: RegionCloseRecord,
    obligation_balance: ObligationBalanceRecord,
    counters: &[(&str, i64)],
) -> NormalizedSemantics {
    let resource_surface = counters.iter().fold(
        ResourceSurfaceRecord::empty(surface_scope),
        |surface, (name, value)| surface.with_counter(*name, *value),
    );

    NormalizedSemantics {
        terminal_outcome,
        cancellation,
        loser_drain,
        region_close,
        obligation_balance,
        resource_surface,
    }
}

const SYNC_SEMAPHORE_CANCEL_RECOVERY_CONTRACT_VERSION: &str = "sync.semaphore.cancel_recovery.v1";

fn counter_i64(value: usize) -> i64 {
    i64::try_from(value).expect("sync differential counters should fit in i64")
}

struct CliNoopWaker;

impl Wake for CliNoopWaker {
    fn wake(self: Arc<Self>) {}
}

fn cli_noop_waker() -> Waker {
    Waker::from(Arc::new(CliNoopWaker))
}

fn poll_once<F>(future: &mut F) -> Poll<F::Output>
where
    F: Future + Unpin,
{
    let waker = cli_noop_waker();
    let mut context = Context::from_waker(&waker);
    Pin::new(future).poll(&mut context)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SemaphoreCancelRecoveryObservation {
    cancelled_waiters: usize,
    recovered_acquisitions: usize,
    available_after_cancel: usize,
    final_available_permits: usize,
}

impl SemaphoreCancelRecoveryObservation {
    fn to_semantics(self) -> NormalizedSemantics {
        NormalizedSemantics {
            terminal_outcome: TerminalOutcome::ok(),
            cancellation: CancellationRecord::none(),
            loser_drain: LoserDrainRecord::not_applicable(),
            region_close: capture_region_close(true, true),
            obligation_balance: ObligationBalanceRecord::zero(),
            resource_surface: ResourceSurfaceRecord::empty("sync.semaphore.cancel_recovery")
                .with_counter("cancelled_waiters", counter_i64(self.cancelled_waiters))
                .with_counter(
                    "recovered_acquisitions",
                    counter_i64(self.recovered_acquisitions),
                )
                .with_counter(
                    "available_after_cancel",
                    counter_i64(self.available_after_cancel),
                )
                .with_counter(
                    "final_available_permits",
                    counter_i64(self.final_available_permits),
                ),
        }
    }
}

fn live_semaphore_cancel_recovery_observation() -> SemaphoreCancelRecoveryObservation {
    let semaphore = Semaphore::new(1);
    let held = semaphore.try_acquire(1).expect("seeded semaphore permit");
    let cancel_cx = Cx::for_testing();
    let mut waiter = semaphore.acquire(&cancel_cx, 1);

    let waiter_pending = poll_once(&mut waiter).is_pending();
    assert!(
        waiter_pending,
        "live semaphore differential waiter should first observe contention"
    );

    cancel_cx.set_cancel_requested(true);
    let cancel_result = poll_once(&mut waiter);
    assert!(
        matches!(cancel_result, Poll::Ready(Err(AcquireError::Cancelled))),
        "live semaphore differential waiter should cancel after being queued, got {cancel_result:?}"
    );
    drop(waiter);

    let available_while_held = semaphore.available_permits();
    assert_eq!(
        available_while_held, 0,
        "cancelled semaphore waiter must not leak permits while the original permit is still held"
    );

    drop(held);

    let available_after_cancel = semaphore.available_permits();
    let recovered_acquisitions = semaphore.try_acquire(1).map_or(0, |permit| {
        drop(permit);
        1usize
    });

    SemaphoreCancelRecoveryObservation {
        cancelled_waiters: 1,
        recovered_acquisitions,
        available_after_cancel,
        final_available_permits: semaphore.available_permits(),
    }
}

fn lab_semaphore_cancel_recovery_observation(seed: u64) -> SemaphoreCancelRecoveryObservation {
    let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(2_000));
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let semaphore = Arc::new(Semaphore::new(1));
    let held = semaphore.try_acquire(1).expect("seeded semaphore permit");
    let cancel_cx = Cx::for_testing();
    let waiter_cx = cancel_cx.clone();
    let cancelled_waiters = Arc::new(AtomicUsize::new(0));

    let semaphore_for_waiter = Arc::clone(&semaphore);
    let waiter_result = Arc::clone(&cancelled_waiters);
    let (task_id, _) = runtime
        .state
        .create_task(region, Budget::INFINITE, async move {
            match semaphore_for_waiter.acquire(&waiter_cx, 1).await {
                Err(AcquireError::Cancelled) => {
                    waiter_result.fetch_add(1, Ordering::SeqCst);
                }
                Ok(_permit) => {
                    panic!("cancelled waiter unexpectedly acquired semaphore");
                }
                Err(err) => panic!("unexpected semaphore acquire error: {err:?}"),
            }
        })
        .expect("create lab semaphore task");
    runtime.scheduler.lock().schedule(task_id, 0);

    for _ in 0..8 {
        runtime.step_for_test();
    }
    cancel_cx.set_cancel_requested(true);
    drop(held);
    runtime.run_until_quiescent();

    let violations = runtime.check_invariants();
    assert!(
        violations.is_empty(),
        "lab semaphore pilot invariants violated: {violations:?}"
    );

    let available_after_cancel = semaphore.available_permits();
    let recovered_acquisitions = semaphore.try_acquire(1).map_or(0, |permit| {
        drop(permit);
        1usize
    });

    SemaphoreCancelRecoveryObservation {
        cancelled_waiters: cancelled_waiters.load(Ordering::SeqCst),
        recovered_acquisitions,
        available_after_cancel,
        final_available_permits: semaphore.available_permits(),
    }
}

fn make_sync_semaphore_live_result(
    identity: &DualRunScenarioIdentity,
) -> asupersync::lab::LiveRunResult {
    run_live_adapter(identity, |_config, witness| {
        let observation = live_semaphore_cancel_recovery_observation();
        witness.set_outcome(TerminalOutcome::ok());
        witness.set_region_close(capture_region_close(true, true));
        witness.set_obligation_balance(ObligationBalanceRecord::zero());
        witness.record_counter(
            "cancelled_waiters",
            counter_i64(observation.cancelled_waiters),
        );
        witness.record_counter(
            "recovered_acquisitions",
            counter_i64(observation.recovered_acquisitions),
        );
        witness.record_counter(
            "available_after_cancel",
            counter_i64(observation.available_after_cancel),
        );
        witness.record_counter(
            "final_available_permits",
            counter_i64(observation.final_available_permits),
        );
    })
}

fn run_configured_differential_scenario(
    canonical_seed: u64,
    scenario_id: &'static str,
    surface_id: &'static str,
    surface_contract_version: &'static str,
    description: &'static str,
    lab_semantics: NormalizedSemantics,
    live_setup: impl FnOnce(&mut LiveWitnessCollector) + 'static,
) -> asupersync::lab::DualRunResult {
    let identity = DualRunScenarioIdentity::phase1(
        scenario_id,
        surface_id,
        surface_contract_version,
        description,
        canonical_seed,
    );
    let live_identity = identity.clone();

    DualRunHarness::from_identity(identity)
        .lab(move |_| lab_semantics)
        .live_result(move |_, _| {
            run_live_adapter(&live_identity, |_, witness| {
                live_setup(witness);
            })
        })
        .run()
}

fn run_configured_cancellation_protocol_scenario(
    canonical_seed: u64,
    scenario_id: &'static str,
    description: &'static str,
    cancel_reason: &'static str,
    checkpoint_observed: Option<bool>,
    loser_joined: &'static [bool],
    counters: &'static [(&'static str, i64)],
) -> asupersync::lab::DualRunResult {
    let cancellation = capture_cancellation(true, true, true, true, checkpoint_observed);
    let loser_drain = capture_loser_drain(loser_joined);
    let obligation = capture_obligation_balance(1, 0, 1);
    let region = capture_region_close(true, true);
    let lab_semantics = make_normalized_semantics(
        "cancellation.protocol",
        TerminalOutcome::cancelled(cancel_reason),
        cancellation.clone(),
        loser_drain.clone(),
        region.clone(),
        obligation.clone(),
        counters,
    );

    run_configured_differential_scenario(
        canonical_seed,
        scenario_id,
        "cancellation.protocol",
        "cancel.protocol.v1",
        description,
        lab_semantics,
        move |witness| {
            witness.set_outcome(TerminalOutcome::cancelled(cancel_reason));
            witness.set_cancellation(cancellation);
            witness.set_loser_drain(loser_drain);
            witness.set_region_close(region);
            witness.set_obligation_balance(obligation);
            for &(name, value) in counters {
                witness.record_counter(name, value);
            }
        },
    )
}

fn run_phase1_cancel_protocol_scenario(canonical_seed: u64) -> asupersync::lab::DualRunResult {
    run_configured_cancellation_protocol_scenario(
        canonical_seed,
        "phase1.cancel.protocol.drain_finalize",
        "Completed cancellation protocol with balanced cleanup.",
        "explicit_cancel",
        Some(true),
        &[],
        &[("cleanup_steps", 1)],
    )
}

fn run_phase1_cancel_before_first_poll_scenario(
    canonical_seed: u64,
) -> asupersync::lab::DualRunResult {
    run_configured_cancellation_protocol_scenario(
        canonical_seed,
        "phase1.cancel.protocol.before_first_poll",
        "Cancellation requested before the first checkpoint still finalizes cleanly.",
        "before_first_poll",
        Some(false),
        &[],
        &[("pre_poll_cancel_requests", 1), ("cleanup_steps", 0)],
    )
}

fn run_phase1_cancel_child_await_scenario(canonical_seed: u64) -> asupersync::lab::DualRunResult {
    run_configured_cancellation_protocol_scenario(
        canonical_seed,
        "phase1.cancel.protocol.child_await",
        "Cancellation during a child await drains the child before finalization.",
        "child_await_cancel",
        Some(true),
        &[true],
        &[("awaited_children", 1), ("cleanup_steps", 2)],
    )
}

fn run_phase1_cancel_cleanup_budget_scenario(
    canonical_seed: u64,
) -> asupersync::lab::DualRunResult {
    run_configured_cancellation_protocol_scenario(
        canonical_seed,
        "phase1.cancel.protocol.cleanup_budget",
        "Cancellation during bounded cleanup completes within the cleanup budget.",
        "cleanup_budget_cancel",
        Some(true),
        &[],
        &[("cleanup_steps", 3), ("cleanup_budget_ticks", 2)],
    )
}

fn run_phase1_combinator_race_scenario(canonical_seed: u64) -> asupersync::lab::DualRunResult {
    let cancellation = capture_cancellation(true, true, true, true, Some(true));
    let loser_drain = capture_loser_drain(&[true]);
    let region = capture_region_close(true, true);
    let obligation = ObligationBalanceRecord::zero();
    let lab_semantics = make_normalized_semantics(
        "combinator.race",
        TerminalOutcome::ok(),
        cancellation.clone(),
        loser_drain.clone(),
        region.clone(),
        obligation.clone(),
        &[("winner_index", 0), ("loser_count", 1)],
    );

    run_configured_differential_scenario(
        canonical_seed,
        "phase1.combinator.race.one_loser",
        "combinator.race",
        "combinator.race.v1",
        "Winner selection with complete loser drain.",
        lab_semantics,
        move |witness| {
            witness.set_outcome(TerminalOutcome::ok());
            witness.set_cancellation(cancellation);
            witness.set_loser_drain(loser_drain);
            witness.set_region_close(region);
            witness.set_obligation_balance(obligation);
            witness.record_counter("winner_index", 0);
            witness.record_counter("loser_count", 1);
        },
    )
}

fn run_calibration_combinator_loser_not_drained_scenario(
    canonical_seed: u64,
) -> asupersync::lab::DualRunResult {
    let cancellation = capture_cancellation(true, true, true, true, Some(true));
    let region = capture_region_close(true, true);
    let obligation = ObligationBalanceRecord::zero();
    let lab_semantics = make_normalized_semantics(
        "combinator.race",
        TerminalOutcome::ok(),
        cancellation.clone(),
        capture_loser_drain(&[true]),
        region.clone(),
        obligation.clone(),
        &[("winner_index", 0), ("loser_count", 1)],
    );

    run_configured_differential_scenario(
        canonical_seed,
        "calibration.combinator.loser_not_drained",
        "combinator.race",
        "combinator.race.v1",
        "Intentional live-side undrained loser to prove combinator drain violations stay loud.",
        lab_semantics,
        move |witness| {
            witness.set_outcome(TerminalOutcome::ok());
            witness.set_cancellation(cancellation);
            witness.set_loser_drain(capture_loser_drain(&[false]));
            witness.set_region_close(region);
            witness.set_obligation_balance(obligation);
            witness.record_counter("winner_index", 0);
            witness.record_counter("loser_count", 1);
        },
    )
}

fn run_phase1_channel_commit_scenario(canonical_seed: u64) -> asupersync::lab::DualRunResult {
    let obligation = capture_obligation_balance(1, 1, 0);
    let region = capture_region_close(true, true);
    let lab_semantics = make_normalized_semantics(
        "channel.reserve_send",
        TerminalOutcome::ok(),
        CancellationRecord::none(),
        LoserDrainRecord::not_applicable(),
        region.clone(),
        obligation.clone(),
        &[("committed_messages", 1), ("aborted_reservations", 0)],
    );

    run_configured_differential_scenario(
        canonical_seed,
        "phase1.channel.reserve_send.commit",
        "channel.reserve_send",
        "channel.reserve_send.v1",
        "Committed reserve/send path remains visible and balanced.",
        lab_semantics,
        move |witness| {
            witness.set_outcome(TerminalOutcome::ok());
            witness.set_region_close(region);
            witness.set_obligation_balance(obligation);
            witness.record_counter("committed_messages", 1);
            witness.record_counter("aborted_reservations", 0);
        },
    )
}

fn run_phase1_channel_abort_scenario(canonical_seed: u64) -> asupersync::lab::DualRunResult {
    let cancellation = capture_cancellation(true, true, true, true, Some(true));
    let obligation = capture_obligation_balance(1, 0, 1);
    let region = capture_region_close(true, true);
    let lab_semantics = make_normalized_semantics(
        "channel.reserve_send",
        TerminalOutcome::cancelled("reservation_aborted"),
        cancellation.clone(),
        LoserDrainRecord::not_applicable(),
        region.clone(),
        obligation.clone(),
        &[
            ("committed_messages", 0),
            ("aborted_reservations", 1),
            ("receiver_observed_messages", 0),
        ],
    );

    run_configured_differential_scenario(
        canonical_seed,
        "phase1.channel.reserve_send.abort_visible",
        "channel.reserve_send",
        "channel.reserve_send.v1",
        "Cancelled reservation aborts cleanly without surfacing a phantom commit.",
        lab_semantics,
        move |witness| {
            witness.set_outcome(TerminalOutcome::cancelled("reservation_aborted"));
            witness.set_cancellation(cancellation);
            witness.set_region_close(region);
            witness.set_obligation_balance(obligation);
            witness.record_counter("committed_messages", 0);
            witness.record_counter("aborted_reservations", 1);
            witness.record_counter("receiver_observed_messages", 0);
        },
    )
}

fn run_phase1_region_close_scenario(canonical_seed: u64) -> asupersync::lab::DualRunResult {
    let region = capture_region_close(true, true);
    let obligation = capture_obligation_balance(2, 1, 1);
    let lab_semantics = make_normalized_semantics(
        "region.close",
        TerminalOutcome::ok(),
        CancellationRecord::none(),
        LoserDrainRecord::not_applicable(),
        region.clone(),
        obligation.clone(),
        &[("nested_children", 2)],
    );

    run_configured_differential_scenario(
        canonical_seed,
        "phase1.region.close.quiescent",
        "region.close",
        "region.close.v1",
        "Region close reaches quiescence with no leaked obligations.",
        lab_semantics,
        move |witness| {
            witness.set_outcome(TerminalOutcome::ok());
            witness.set_region_close(region);
            witness.set_obligation_balance(obligation);
            witness.record_counter("nested_children", 2);
        },
    )
}

fn run_phase1_sync_semaphore_cancel_recovery_scenario(
    canonical_seed: u64,
) -> asupersync::lab::DualRunResult {
    let identity = DualRunScenarioIdentity::phase1(
        "phase1.sync.semaphore.cancel_recovery",
        "sync.semaphore.cancel_recovery",
        SYNC_SEMAPHORE_CANCEL_RECOVERY_CONTRACT_VERSION,
        "Semaphore differential pilot preserves waiter cancellation cleanup and permit recovery.",
        canonical_seed,
    );
    let live_result = make_sync_semaphore_live_result(&identity);

    DualRunHarness::from_identity(identity)
        .lab(move |config| lab_semaphore_cancel_recovery_observation(config.seed).to_semantics())
        .live_result(move |_seed, _entropy| live_result)
        .run()
}

fn run_calibration_cleanup_missing_scenario(canonical_seed: u64) -> asupersync::lab::DualRunResult {
    let lab_cancellation = capture_cancellation(true, true, true, true, Some(true));
    let live_cancellation = capture_cancellation(true, true, false, false, Some(true));
    let obligation = capture_obligation_balance(1, 0, 1);
    let region = capture_region_close(true, true);
    let lab_semantics = make_normalized_semantics(
        "cancellation.protocol",
        TerminalOutcome::cancelled("explicit_cancel"),
        lab_cancellation,
        LoserDrainRecord::not_applicable(),
        region.clone(),
        obligation.clone(),
        &[("cleanup_steps", 1)],
    );

    run_configured_differential_scenario(
        canonical_seed,
        "calibration.cancellation.cleanup_missing",
        "cancellation.protocol",
        "cancel.protocol.v1",
        "Intentional live-side cleanup gap to prove classifier and report flow.",
        lab_semantics,
        move |witness| {
            witness.set_outcome(TerminalOutcome::cancelled("explicit_cancel"));
            witness.set_cancellation(live_cancellation);
            witness.set_region_close(region);
            witness.set_obligation_balance(obligation);
            witness.record_counter("cleanup_steps", 1);
        },
    )
}

fn run_calibration_cleanup_budget_exhausted_scenario(
    canonical_seed: u64,
) -> asupersync::lab::DualRunResult {
    let lab_cancellation = capture_cancellation(true, true, true, true, Some(true));
    let live_cancellation = capture_cancellation(true, true, false, false, Some(true));
    let lab_region = capture_region_close(true, true);
    let live_region = capture_region_close(false, false);
    let obligation = capture_obligation_balance(1, 0, 1);
    let lab_semantics = make_normalized_semantics(
        "cancellation.protocol",
        TerminalOutcome::cancelled("cleanup_budget_cancel"),
        lab_cancellation,
        LoserDrainRecord::not_applicable(),
        lab_region,
        obligation.clone(),
        &[("cleanup_steps", 3), ("cleanup_budget_ticks", 2)],
    );

    run_configured_differential_scenario(
        canonical_seed,
        "calibration.cancellation.cleanup_budget_exhausted",
        "cancellation.protocol",
        "cancel.protocol.v1",
        "Intentional cleanup-budget exhaustion to prove cancellation-budget mismatches stay loud.",
        lab_semantics,
        move |witness| {
            witness.set_outcome(TerminalOutcome::cancelled("cleanup_budget_cancel"));
            witness.set_cancellation(live_cancellation);
            witness.set_region_close(live_region);
            witness.set_obligation_balance(obligation);
            witness.record_counter("cleanup_steps", 3);
            witness.record_counter("cleanup_budget_ticks", 2);
            witness.record_counter("cleanup_budget_exhausted", 1);
        },
    )
}

fn run_calibration_resource_counter_mismatch_scenario(
    canonical_seed: u64,
) -> asupersync::lab::DualRunResult {
    let region = capture_region_close(true, true);
    let obligation = ObligationBalanceRecord::zero();
    let lab_semantics = make_normalized_semantics(
        "resource.surface",
        TerminalOutcome::ok(),
        CancellationRecord::none(),
        LoserDrainRecord::not_applicable(),
        region.clone(),
        obligation.clone(),
        &[("delivered_messages", 1), ("retained_artifacts", 1)],
    );

    run_configured_differential_scenario(
        canonical_seed,
        "calibration.comparator.resource_counter_mismatch",
        "resource.surface",
        "resource.surface.v1",
        "Intentional admitted-surface resource counter drift to prove comparator detection and report quality.",
        lab_semantics,
        move |witness| {
            witness.set_outcome(TerminalOutcome::ok());
            witness.set_region_close(region);
            witness.set_obligation_balance(obligation);
            witness.record_counter("delivered_messages", 2);
            witness.record_counter("retained_artifacts", 1);
        },
    )
}

fn run_calibration_channel_commit_visibility_mismatch_scenario(
    canonical_seed: u64,
) -> asupersync::lab::DualRunResult {
    let cancellation = capture_cancellation(true, true, true, true, Some(true));
    let lab_obligation = capture_obligation_balance(1, 0, 1);
    let live_obligation = capture_obligation_balance(1, 1, 0);
    let region = capture_region_close(true, true);
    let lab_semantics = make_normalized_semantics(
        "channel.reserve_send",
        TerminalOutcome::cancelled("reservation_aborted"),
        cancellation.clone(),
        LoserDrainRecord::not_applicable(),
        region.clone(),
        lab_obligation,
        &[
            ("committed_messages", 0),
            ("aborted_reservations", 1),
            ("receiver_observed_messages", 0),
        ],
    );

    run_configured_differential_scenario(
        canonical_seed,
        "calibration.channel.commit_visibility_mismatch",
        "channel.reserve_send",
        "channel.reserve_send.v1",
        "Intentional committed-vs-aborted visibility drift to prove channel mismatches stay loud.",
        lab_semantics,
        move |witness| {
            witness.set_outcome(TerminalOutcome::cancelled("reservation_aborted"));
            witness.set_cancellation(cancellation);
            witness.set_region_close(region);
            witness.set_obligation_balance(live_obligation);
            witness.record_counter("committed_messages", 1);
            witness.record_counter("aborted_reservations", 0);
            witness.record_counter("receiver_observed_messages", 1);
        },
    )
}

fn run_calibration_obligation_leak_scenario(canonical_seed: u64) -> asupersync::lab::DualRunResult {
    let lab_obligation = capture_obligation_balance(2, 1, 1);
    let live_obligation = capture_obligation_balance(2, 1, 0);
    let region = capture_region_close(true, true);
    let lab_semantics = make_normalized_semantics(
        "obligation.balance",
        TerminalOutcome::ok(),
        CancellationRecord::none(),
        LoserDrainRecord::not_applicable(),
        region.clone(),
        lab_obligation,
        &[("reserved_slots", 2)],
    );

    run_configured_differential_scenario(
        canonical_seed,
        "calibration.obligation.leak_detected",
        "obligation.balance",
        "obligation.balance.v1",
        "Intentional live-side obligation leak to prove artifact retention.",
        lab_semantics,
        move |witness| {
            witness.set_outcome(TerminalOutcome::ok());
            witness.set_region_close(region);
            witness.set_obligation_balance(live_obligation);
            witness.record_counter("reserved_slots", 2);
        },
    )
}

fn run_calibration_region_non_quiescent_close_scenario(
    canonical_seed: u64,
) -> asupersync::lab::DualRunResult {
    let lab_region = capture_region_close(true, true);
    let live_region = capture_region_close(false, true);
    let obligation = capture_obligation_balance(2, 1, 1);
    let lab_semantics = make_normalized_semantics(
        "region.close",
        TerminalOutcome::ok(),
        CancellationRecord::none(),
        LoserDrainRecord::not_applicable(),
        lab_region.clone(),
        obligation.clone(),
        &[("nested_children", 2), ("close_attempts", 1)],
    );

    run_configured_differential_scenario(
        canonical_seed,
        "calibration.region.close.non_quiescent",
        "region.close",
        "region.close.v1",
        "Intentional live-side non-quiescent root close to prove quiescence violations stay loud.",
        lab_semantics,
        move |witness| {
            witness.set_outcome(TerminalOutcome::ok());
            witness.set_region_close(live_region);
            witness.set_obligation_balance(obligation);
            witness.record_counter("nested_children", 2);
            witness.record_counter("close_attempts", 1);
        },
    )
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
    let scenario = shell_escape_command_arg(&args.scenario.display().to_string());
    let mut replay = format!("asupersync lab replay {scenario}");
    replay.push_str(&format!(" --seed {seed}"));

    if args.window_start > 0 {
        replay.push_str(&format!(" --window-start {}", args.window_start));
    }
    if let Some(window_events) = args.window_events {
        replay.push_str(&format!(" --window-events {window_events}"));
    }
    if let Some(pointer) = &args.artifact_pointer {
        replay.push_str(&format!(
            " --artifact-pointer {}",
            shell_escape_command_arg(pointer)
        ));
    }
    if let Some(path) = &args.artifact_output {
        replay.push_str(&format!(
            " --artifact-output {}",
            shell_escape_command_arg(&path.display().to_string())
        ));
    }

    let run = format!("asupersync lab run {scenario} --seed {seed}");
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
        TraceFileError::MetadataNotWritten => {
            CliError::new("invalid_state", "Trace metadata must be written first")
        }
        TraceFileError::MetadataAlreadyWritten => {
            CliError::new("invalid_state", "Trace metadata already written")
        }
        TraceFileError::MetadataCorrupt => {
            CliError::new("invalid_state", "Trace writer metadata write failed")
                .detail("Discard the partial file and recreate the writer")
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
    use asupersync::observability::{TaskRegionCountWire, TaskStateInfo};
    use asupersync::trace::{TraceMetadata, TraceWriter};
    use clap::Parser;
    use tempfile::NamedTempFile;

    fn sample_task_console_snapshot() -> TaskConsoleWireSnapshot {
        let summary = TaskSummaryWire {
            total_tasks: 2,
            created: 0,
            running: 2,
            cancelling: 0,
            completed: 0,
            stuck_count: 0,
            by_region: vec![TaskRegionCountWire {
                region_id: asupersync::RegionId::new_for_test(3, 0),
                task_count: 2,
            }],
        };
        let task_a = TaskDetailsWire {
            id: asupersync::TaskId::new_for_test(1, 0),
            region_id: asupersync::RegionId::new_for_test(3, 0),
            state: TaskStateInfo::Running,
            phase: "Running".to_string(),
            poll_count: 4,
            polls_remaining: 16,
            created_at: Time::from_nanos(10),
            age_nanos: 100,
            time_since_last_poll_nanos: Some(5),
            wake_pending: false,
            obligations: vec![],
            waiters: vec![],
        };
        let task_b = TaskDetailsWire {
            id: asupersync::TaskId::new_for_test(9, 0),
            region_id: asupersync::RegionId::new_for_test(3, 0),
            state: TaskStateInfo::Running,
            phase: "Running".to_string(),
            poll_count: 2,
            polls_remaining: 18,
            created_at: Time::from_nanos(8),
            age_nanos: 120,
            time_since_last_poll_nanos: None,
            wake_pending: true,
            obligations: vec![],
            waiters: vec![],
        };
        TaskConsoleWireSnapshot::new(Time::from_nanos(88), summary, vec![task_b, task_a])
    }

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
    fn lab_differential_args_parse_profile_and_selection() {
        let cli = Cli::try_parse_from([
            "asupersync",
            "lab",
            "differential",
            "--profile",
            "calibration",
            "--scenario",
            "calibration.cancellation.cleanup_missing,phase1.cancel.protocol.drain_finalize",
            "--seed",
            "77",
            "--out-dir",
            "artifacts/diff",
            "--json",
        ])
        .expect("parse differential args");

        let Command::Lab(LabArgs {
            command: LabCommand::Differential(args),
        }) = cli.command
        else {
            panic!("expected lab differential command");
        };

        assert_eq!(args.profile, LabDifferentialProfile::Calibration);
        assert_eq!(
            args.scenarios,
            vec![
                "calibration.cancellation.cleanup_missing".to_string(),
                "phase1.cancel.protocol.drain_finalize".to_string()
            ]
        );
        assert_eq!(args.seed, 77);
        assert_eq!(args.out_dir, PathBuf::from("artifacts/diff"));
        assert!(args.json);
    }

    #[test]
    fn lab_differential_profile_manifest_command_parses() {
        let cli = Cli::try_parse_from([
            "asupersync",
            "lab",
            "differential-profile-manifest",
            "--json",
        ])
        .expect("parse differential profile manifest command");

        let Command::Lab(LabArgs {
            command: LabCommand::DifferentialProfileManifest(args),
        }) = cli.command
        else {
            panic!("expected lab differential-profile-manifest command");
        };

        assert!(args.json);
    }

    #[test]
    fn lab_differential_profile_manifest_covers_operator_vocabulary() {
        let manifest = lab_differential_profile_manifest();
        assert_eq!(
            manifest.schema_version,
            LAB_DIFFERENTIAL_PROFILE_MANIFEST_SCHEMA_VERSION
        );
        assert_eq!(
            manifest.direct_cli_profiles,
            vec![
                "smoke".to_string(),
                "phase1-core".to_string(),
                "calibration".to_string()
            ]
        );

        let profile_ids = manifest
            .operator_profiles
            .iter()
            .map(|profile| profile.profile_id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            profile_ids,
            vec![
                "smoke",
                "phase1-core",
                "calibration",
                "repro-targeted",
                "nightly-stress"
            ]
        );

        let repro = manifest
            .operator_profiles
            .iter()
            .find(|profile| profile.profile_id == "repro-targeted")
            .expect("repro-targeted profile present");
        assert_eq!(repro.support_status, "shipped");
        assert_eq!(repro.cli_profile.as_deref(), Some("phase1-core"));
        assert!(
            repro.invocation_recipe.contains("--scenario <scenario-id>"),
            "repro-targeted must preserve scenario-scoped replay recipe"
        );

        let nightly = manifest
            .operator_profiles
            .iter()
            .find(|profile| profile.profile_id == "nightly-stress")
            .expect("nightly-stress profile present");
        assert_eq!(nightly.support_status, "shipped");
        assert_eq!(nightly.cli_profile.as_deref(), Some("phase1-core"));
        assert_eq!(nightly.dependency_bead, None);
        assert_eq!(nightly.tier_binding, "T5 stress_nightly");
        assert_eq!(nightly.scenario_pack, "rotating_seed_phase1_core_pack");
        assert!(
            nightly
                .invocation_recipe
                .contains("--seed-count <count> --seed-stride <stride> --rotation-date <date>"),
            "nightly-stress recipe must expose rotating-seed controls"
        );
        assert_eq!(
            nightly.required_artifacts,
            vec![
                "runner_summary.json".to_string(),
                "operator_summary.txt".to_string(),
                "artifact_index.json".to_string(),
                "differential_event_log.jsonl".to_string(),
                "nightly_stress_manifest.json".to_string(),
                "nightly_stress_summary.txt".to_string(),
                "retained_divergence_artifacts/".to_string()
            ]
        );
        assert_eq!(
            nightly.scenario_ids,
            vec![
                "phase1.cancel.protocol.drain_finalize".to_string(),
                "phase1.cancel.protocol.before_first_poll".to_string(),
                "phase1.cancel.protocol.child_await".to_string(),
                "phase1.cancel.protocol.cleanup_budget".to_string(),
                "phase1.combinator.race.one_loser".to_string(),
                "phase1.channel.reserve_send.commit".to_string(),
                "phase1.channel.reserve_send.abort_visible".to_string(),
                "phase1.region.close.quiescent".to_string(),
                "phase1.sync.semaphore.cancel_recovery".to_string()
            ]
        );
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
    fn build_replay_rerun_commands_shell_escape_paths() {
        let args = LabReplayArgs {
            scenario: PathBuf::from("examples/scenarios/with space.yaml"),
            seed: Some(91),
            artifact_pointer: Some("artifacts/replay/pinned report.json".to_string()),
            artifact_output: Some(PathBuf::from("artifacts/replay/output report.json")),
            window_start: 0,
            window_events: None,
            json: false,
        };

        let commands = build_replay_rerun_commands(&args, 91);
        assert_eq!(commands.len(), 2);
        assert!(commands[0].contains("asupersync lab replay 'examples/scenarios/with space.yaml'"));
        assert!(commands[0].contains("--artifact-pointer 'artifacts/replay/pinned report.json'"));
        assert!(commands[0].contains("--artifact-output 'artifacts/replay/output report.json'"));
        assert_eq!(
            commands[1],
            "asupersync lab run 'examples/scenarios/with space.yaml' --seed 91"
        );
    }

    #[test]
    fn build_differential_rerun_commands_shell_escape_out_dir() {
        let args = LabDifferentialArgs {
            profile: LabDifferentialProfile::Smoke,
            scenarios: vec!["phase1.channel.reserve_send.commit".to_string()],
            seed: 91,
            out_dir: PathBuf::from("artifacts/diff reports"),
            json: false,
        };

        let commands = build_differential_rerun_commands(
            &args,
            "phase1.channel.reserve_send.commit",
            Path::new("unused"),
        );
        assert_eq!(commands.len(), 2);
        assert!(commands[0].contains("--profile smoke"));
        assert!(commands[0].contains("--scenario phase1.channel.reserve_send.commit"));
        assert!(commands[0].contains("--out-dir 'artifacts/diff reports'"));
        assert!(commands[1].contains("--out-dir 'artifacts/diff reports'"));
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
    fn lab_differential_smoke_profile_writes_summary_and_logs() {
        let temp = tempfile::tempdir().expect("tempdir");
        let args = LabDifferentialArgs {
            profile: LabDifferentialProfile::Smoke,
            scenarios: vec!["phase1.channel.reserve_send.commit".to_string()],
            seed: 91,
            out_dir: temp.path().join("artifacts"),
            json: false,
        };

        let report = run_lab_differential(&args).expect("run differential smoke profile");
        assert!(report.success);
        assert_eq!(report.scenario_count, 1);
        assert_eq!(report.pass_count, 1);

        let scenario = &report.scenarios[0];
        assert_eq!(scenario.status, LabDifferentialScenarioStatus::Pass);
        assert!(Path::new(&scenario.summary_path).exists());
        assert!(Path::new(&scenario.event_log_path).exists());
        assert!(Path::new(&scenario.lab_normalized_path).exists());
        assert!(Path::new(&scenario.live_normalized_path).exists());
        assert!(Path::new(&report.runner_summary_path).exists());
        assert!(Path::new(&report.operator_summary_path).exists());
        assert!(Path::new(&report.artifact_index_path).exists());
        assert!(Path::new(&report.aggregate_event_log_path).exists());

        let operator_summary =
            fs::read_to_string(&report.operator_summary_path).expect("read operator summary");
        let expected_operator_summary = format!(
            concat!(
                "Differential operator summary\n",
                "Profile: smoke\n",
                "Evidence grade: t2_dual_run_smoke\n",
                "Confidence label: baseline_signal\n",
                "Runtime cost: fast\n",
                "Operator intent: Fast shared signal for the semantic-core smoke surface.\n",
                "Status: pass\n",
                "Root seed: 91\n",
                "Exit semantics: {}\n",
                "Scenario pack: phase1.channel.reserve_send.commit\n",
                "Scenarios: 1 (pass=1, expected_divergence=0, unexpected_divergence=0, missing_expected_divergence=0)\n",
                "Artifacts:\n",
                "  runner_summary: {}\n",
                "  operator_summary: {}\n",
                "  artifact_index: {}\n",
                "  aggregate_event_log: {}\n",
                "Scenario results:\n",
                "- pass phase1.channel.reserve_send.commit [{}] provisional=pass final=not_applicable summary={}\n",
                "  event_log: {}\n",
                "  lab_normalized: {}\n",
                "  live_normalized: {}\n",
                "  replay:\n",
                "    asupersync lab differential --profile smoke --scenario phase1.channel.reserve_send.commit --seed 91 --out-dir {}\n",
                "    scripts/run_lab_live_differential.sh --profile smoke --scenario phase1.channel.reserve_send.commit --seed 91 --out-dir {}\n",
            ),
            lab_differential_exit_semantics(),
            report.runner_summary_path,
            report.operator_summary_path,
            report.artifact_index_path,
            report.aggregate_event_log_path,
            scenario.seed_lineage_id,
            scenario.summary_path,
            scenario.event_log_path,
            scenario.lab_normalized_path,
            scenario.live_normalized_path,
            args.out_dir.display(),
            args.out_dir.display(),
        );
        assert_eq!(operator_summary, expected_operator_summary);

        let human = report.human_format();
        assert_eq!(human, operator_summary);
        assert!(human.contains("final=not_applicable"));
        assert!(!human.contains("final=pending"));
    }

    #[test]
    fn lab_differential_phase1_core_profile_covers_channel_abort_path() {
        let temp = tempfile::tempdir().expect("tempdir");
        let args = LabDifferentialArgs {
            profile: LabDifferentialProfile::Phase1Core,
            scenarios: vec!["phase1.channel.reserve_send.abort_visible".to_string()],
            seed: 144,
            out_dir: temp.path().join("artifacts"),
            json: false,
        };

        let report = run_lab_differential(&args).expect("run channel abort profile");
        assert!(report.success);
        assert_eq!(report.scenario_count, 1);
        assert_eq!(report.pass_count, 1);

        let scenario = &report.scenarios[0];
        assert_eq!(scenario.status, LabDifferentialScenarioStatus::Pass);
        let lab_normalized: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(&scenario.lab_normalized_path).expect("read lab normalized"),
        )
        .expect("parse lab normalized");
        let live_normalized: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(&scenario.live_normalized_path).expect("read live normalized"),
        )
        .expect("parse live normalized");
        assert_eq!(
            lab_normalized["semantics"]["resource_surface"]["counters"]["committed_messages"],
            0
        );
        assert_eq!(
            lab_normalized["semantics"]["resource_surface"]["counters"]["aborted_reservations"],
            1
        );
        assert_eq!(
            live_normalized["semantics"]["resource_surface"]["counters"]["receiver_observed_messages"],
            0
        );
        assert_eq!(
            live_normalized["semantics"]["obligation_balance"]["aborted"],
            1
        );
    }

    #[test]
    fn lab_differential_phase1_core_profile_covers_cancel_before_first_poll_path() {
        let temp = tempfile::tempdir().expect("tempdir");
        let args = LabDifferentialArgs {
            profile: LabDifferentialProfile::Phase1Core,
            scenarios: vec!["phase1.cancel.protocol.before_first_poll".to_string()],
            seed: 2112,
            out_dir: temp.path().join("artifacts"),
            json: false,
        };

        let report = run_lab_differential(&args).expect("run before-first-poll cancellation");
        assert!(report.success);
        assert_eq!(report.scenario_count, 1);
        assert_eq!(report.pass_count, 1);

        let scenario = &report.scenarios[0];
        assert_eq!(scenario.status, LabDifferentialScenarioStatus::Pass);
        let live_normalized: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(&scenario.live_normalized_path).expect("read live normalized"),
        )
        .expect("parse live normalized");
        assert_eq!(
            live_normalized["semantics"]["cancellation"]["checkpoint_observed"],
            false
        );
        assert_eq!(
            live_normalized["semantics"]["resource_surface"]["counters"]["pre_poll_cancel_requests"],
            1
        );
    }

    #[test]
    fn lab_differential_phase1_core_profile_covers_cancel_during_child_await_path() {
        let temp = tempfile::tempdir().expect("tempdir");
        let args = LabDifferentialArgs {
            profile: LabDifferentialProfile::Phase1Core,
            scenarios: vec!["phase1.cancel.protocol.child_await".to_string()],
            seed: 2330,
            out_dir: temp.path().join("artifacts"),
            json: false,
        };

        let report = run_lab_differential(&args).expect("run child-await cancellation");
        assert!(report.success);
        assert_eq!(report.scenario_count, 1);
        assert_eq!(report.pass_count, 1);

        let scenario = &report.scenarios[0];
        assert_eq!(scenario.status, LabDifferentialScenarioStatus::Pass);
        let live_normalized: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(&scenario.live_normalized_path).expect("read live normalized"),
        )
        .expect("parse live normalized");
        assert_eq!(
            live_normalized["semantics"]["loser_drain"]["drained_losers"],
            1
        );
        assert_eq!(
            live_normalized["semantics"]["resource_surface"]["counters"]["awaited_children"],
            1
        );
    }

    #[test]
    fn lab_differential_phase1_core_profile_covers_combinator_one_loser_path() {
        let temp = tempfile::tempdir().expect("tempdir");
        let args = LabDifferentialArgs {
            profile: LabDifferentialProfile::Phase1Core,
            scenarios: vec!["phase1.combinator.race.one_loser".to_string()],
            seed: 2446,
            out_dir: temp.path().join("artifacts"),
            json: false,
        };

        let report = run_lab_differential(&args).expect("run combinator one-loser profile");
        assert!(report.success);
        assert_eq!(report.scenario_count, 1);
        assert_eq!(report.pass_count, 1);

        let scenario = &report.scenarios[0];
        assert_eq!(scenario.status, LabDifferentialScenarioStatus::Pass);
        let live_normalized: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(&scenario.live_normalized_path).expect("read live normalized"),
        )
        .expect("parse live normalized");
        assert_eq!(
            live_normalized["semantics"]["loser_drain"]["status"],
            "complete"
        );
        assert_eq!(
            live_normalized["semantics"]["loser_drain"]["expected_losers"],
            1
        );
        assert_eq!(
            live_normalized["semantics"]["loser_drain"]["drained_losers"],
            1
        );
        assert_eq!(
            live_normalized["semantics"]["resource_surface"]["counters"]["winner_index"],
            0
        );
    }

    #[test]
    fn lab_differential_phase1_core_profile_covers_cleanup_budget_path() {
        let temp = tempfile::tempdir().expect("tempdir");
        let args = LabDifferentialArgs {
            profile: LabDifferentialProfile::Phase1Core,
            scenarios: vec!["phase1.cancel.protocol.cleanup_budget".to_string()],
            seed: 2552,
            out_dir: temp.path().join("artifacts"),
            json: false,
        };

        let report = run_lab_differential(&args).expect("run cleanup-budget cancellation");
        assert!(report.success);
        assert_eq!(report.scenario_count, 1);
        assert_eq!(report.pass_count, 1);

        let scenario = &report.scenarios[0];
        assert_eq!(scenario.status, LabDifferentialScenarioStatus::Pass);
        let live_normalized: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(&scenario.live_normalized_path).expect("read live normalized"),
        )
        .expect("parse live normalized");
        assert_eq!(
            live_normalized["semantics"]["resource_surface"]["counters"]["cleanup_budget_ticks"],
            2
        );
        assert_eq!(
            live_normalized["semantics"]["cancellation"]["cleanup_completed"],
            true
        );
        assert_eq!(
            live_normalized["semantics"]["cancellation"]["finalization_completed"],
            true
        );
    }

    #[test]
    fn lab_differential_phase1_core_profile_covers_quiescent_region_close_path() {
        let temp = tempfile::tempdir().expect("tempdir");
        let args = LabDifferentialArgs {
            profile: LabDifferentialProfile::Phase1Core,
            scenarios: vec!["phase1.region.close.quiescent".to_string()],
            seed: 3131,
            out_dir: temp.path().join("artifacts"),
            json: false,
        };

        let report = run_lab_differential(&args).expect("run quiescent region-close profile");
        assert!(report.success);
        assert_eq!(report.scenario_count, 1);
        assert_eq!(report.pass_count, 1);

        let scenario = &report.scenarios[0];
        assert_eq!(scenario.status, LabDifferentialScenarioStatus::Pass);

        let live_normalized: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(&scenario.live_normalized_path).expect("read live normalized"),
        )
        .expect("parse live normalized");
        assert_eq!(
            live_normalized["semantics"]["region_close"]["quiescent"],
            true
        );
        assert_eq!(
            live_normalized["semantics"]["region_close"]["live_children"],
            0
        );
        assert_eq!(
            live_normalized["semantics"]["region_close"]["finalizers_pending"],
            0
        );
        assert_eq!(
            live_normalized["semantics"]["region_close"]["close_completed"],
            true
        );
        assert_eq!(
            live_normalized["semantics"]["obligation_balance"]["balanced"],
            true
        );
        assert_eq!(
            live_normalized["semantics"]["obligation_balance"]["committed"],
            1
        );
        assert_eq!(
            live_normalized["semantics"]["obligation_balance"]["aborted"],
            1
        );
        assert_eq!(
            live_normalized["semantics"]["resource_surface"]["counters"]["nested_children"],
            2
        );
    }

    #[test]
    fn semaphore_cancel_recovery_observations_align_between_live_and_lab_helpers() {
        let live = live_semaphore_cancel_recovery_observation();
        let lab = lab_semaphore_cancel_recovery_observation(3551);

        assert_eq!(live, lab);
        assert_eq!(live.cancelled_waiters, 1);
        assert_eq!(live.recovered_acquisitions, 1);
        assert_eq!(live.available_after_cancel, 1);
        assert_eq!(live.final_available_permits, 1);
    }

    #[test]
    fn lab_differential_phase1_core_profile_covers_sync_semaphore_cancel_recovery_path() {
        let temp = tempfile::tempdir().expect("tempdir");
        let args = LabDifferentialArgs {
            profile: LabDifferentialProfile::Phase1Core,
            scenarios: vec!["phase1.sync.semaphore.cancel_recovery".to_string()],
            seed: 3551,
            out_dir: temp.path().join("artifacts"),
            json: false,
        };

        let report = run_lab_differential(&args).expect("run sync semaphore differential profile");
        assert!(report.success);
        assert_eq!(report.scenario_count, 1);
        assert_eq!(report.pass_count, 1);

        let scenario = &report.scenarios[0];
        assert_eq!(scenario.status, LabDifferentialScenarioStatus::Pass);

        let live_normalized: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(&scenario.live_normalized_path).expect("read live normalized"),
        )
        .expect("parse live normalized");
        let lab_normalized: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(&scenario.lab_normalized_path).expect("read lab normalized"),
        )
        .expect("parse lab normalized");
        assert_eq!(
            live_normalized["semantics"]["resource_surface"]["counters"]["cancelled_waiters"],
            1
        );
        assert_eq!(
            live_normalized["semantics"]["resource_surface"]["counters"]["recovered_acquisitions"],
            1
        );
        assert_eq!(
            live_normalized["semantics"]["resource_surface"]["counters"]["available_after_cancel"],
            1
        );
        assert_eq!(
            live_normalized["semantics"]["resource_surface"]["counters"]["final_available_permits"],
            1
        );
        assert_eq!(
            lab_normalized["semantics"]["resource_surface"]["counters"],
            live_normalized["semantics"]["resource_surface"]["counters"]
        );
    }

    #[test]
    fn lab_differential_calibration_profile_retains_expected_divergence_bundle() {
        let temp = tempfile::tempdir().expect("tempdir");
        let args = LabDifferentialArgs {
            profile: LabDifferentialProfile::Calibration,
            scenarios: vec!["calibration.cancellation.cleanup_missing".to_string()],
            seed: 5150,
            out_dir: temp.path().join("artifacts"),
            json: false,
        };

        let report = run_lab_differential(&args).expect("run differential calibration profile");
        assert!(report.success);
        assert_eq!(report.expected_divergence_count, 1);

        let scenario = &report.scenarios[0];
        assert_eq!(
            scenario.status,
            LabDifferentialScenarioStatus::ExpectedDivergence
        );
        assert_eq!(
            scenario.observed_final_policy_class.as_deref(),
            Some("runtime_semantic_bug")
        );
        assert!(Path::new(&scenario.summary_path).exists());
        assert!(Path::new(&scenario.event_log_path).exists());
        assert!(
            Path::new(
                scenario
                    .failures_path
                    .as_deref()
                    .expect("failures path must exist for calibration divergence")
            )
            .exists()
        );
        assert!(
            Path::new(
                scenario
                    .deviations_path
                    .as_deref()
                    .expect("deviations path must exist for calibration divergence")
            )
            .exists()
        );
        assert!(
            Path::new(
                scenario
                    .repro_manifest_path
                    .as_deref()
                    .expect("repro manifest must exist for calibration divergence")
            )
            .exists()
        );
    }

    #[test]
    fn lab_differential_calibration_profile_covers_combinator_loser_not_drained() {
        let temp = tempfile::tempdir().expect("tempdir");
        let args = LabDifferentialArgs {
            profile: LabDifferentialProfile::Calibration,
            scenarios: vec!["calibration.combinator.loser_not_drained".to_string()],
            seed: 5224,
            out_dir: temp.path().join("artifacts"),
            json: false,
        };

        let report = run_lab_differential(&args).expect("run combinator loser-not-drained profile");
        assert!(report.success);
        assert_eq!(report.expected_divergence_count, 1);

        let scenario = &report.scenarios[0];
        assert_eq!(
            scenario.status,
            LabDifferentialScenarioStatus::ExpectedDivergence
        );
        assert_eq!(scenario.observed_provisional_class, "hard_contract_break");
        assert_eq!(
            scenario.observed_final_policy_class.as_deref(),
            Some("runtime_semantic_bug")
        );
        assert!(
            Path::new(
                scenario
                    .failures_path
                    .as_deref()
                    .expect("failures path must exist for combinator divergence")
            )
            .exists()
        );
        assert!(
            Path::new(
                scenario
                    .deviations_path
                    .as_deref()
                    .expect("deviations path must exist for combinator divergence")
            )
            .exists()
        );

        let lab_normalized: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(&scenario.lab_normalized_path).expect("read lab normalized"),
        )
        .expect("parse lab normalized");
        let live_normalized: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(&scenario.live_normalized_path).expect("read live normalized"),
        )
        .expect("parse live normalized");
        assert_eq!(
            lab_normalized["semantics"]["loser_drain"]["status"],
            "complete"
        );
        assert_eq!(
            live_normalized["semantics"]["loser_drain"]["status"],
            "incomplete"
        );
        assert_eq!(
            live_normalized["semantics"]["loser_drain"]["expected_losers"],
            1
        );
        assert_eq!(
            live_normalized["semantics"]["loser_drain"]["drained_losers"],
            0
        );

        let event_log =
            fs::read_to_string(&scenario.event_log_path).expect("read combinator event log");
        assert!(event_log.contains("\"provisional_class\":\"hard_contract_break\""));
        assert!(event_log.contains("\"final_policy_class\":\"runtime_semantic_bug\""));
        assert!(event_log.contains("\"lab_loser_drain\":\"complete\""));
        assert!(event_log.contains("\"live_loser_drain\":\"incomplete\""));
    }

    #[test]
    fn lab_differential_calibration_profile_covers_cleanup_budget_exhaustion() {
        let temp = tempfile::tempdir().expect("tempdir");
        let args = LabDifferentialArgs {
            profile: LabDifferentialProfile::Calibration,
            scenarios: vec!["calibration.cancellation.cleanup_budget_exhausted".to_string()],
            seed: 5252,
            out_dir: temp.path().join("artifacts"),
            json: false,
        };

        let report = run_lab_differential(&args).expect("run cleanup-budget calibration profile");
        assert!(report.success);
        assert_eq!(report.expected_divergence_count, 1);

        let scenario = &report.scenarios[0];
        assert_eq!(
            scenario.status,
            LabDifferentialScenarioStatus::ExpectedDivergence
        );
        assert_eq!(scenario.observed_provisional_class, "hard_contract_break");
        assert_eq!(
            scenario.observed_final_policy_class.as_deref(),
            Some("runtime_semantic_bug")
        );

        let live_normalized: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(&scenario.live_normalized_path).expect("read live normalized"),
        )
        .expect("parse live normalized");
        assert_eq!(
            live_normalized["semantics"]["resource_surface"]["counters"]["cleanup_budget_exhausted"],
            1
        );
        assert_eq!(
            live_normalized["semantics"]["region_close"]["quiescent"],
            false
        );
    }

    #[test]
    fn lab_differential_calibration_profile_covers_comparator_mismatch_and_report_fields() {
        let temp = tempfile::tempdir().expect("tempdir");
        let args = LabDifferentialArgs {
            profile: LabDifferentialProfile::Calibration,
            scenarios: vec!["calibration.comparator.resource_counter_mismatch".to_string()],
            seed: 8080,
            out_dir: temp.path().join("artifacts"),
            json: false,
        };

        let report = run_lab_differential(&args).expect("run comparator calibration profile");
        assert!(report.success);
        assert_eq!(report.expected_divergence_count, 1);

        let scenario = &report.scenarios[0];
        assert_eq!(
            scenario.status,
            LabDifferentialScenarioStatus::ExpectedDivergence
        );
        assert_eq!(
            scenario.observed_provisional_class,
            "semantic_mismatch_admitted_surface"
        );
        assert_eq!(
            scenario.observed_final_policy_class.as_deref(),
            Some("runtime_semantic_bug")
        );
        assert_eq!(
            scenario.expected_provisional_class.as_deref(),
            Some("semantic_mismatch_admitted_surface")
        );
        assert_eq!(scenario.expected_final_policy_class, None);
        assert!(
            Path::new(
                scenario
                    .failures_path
                    .as_deref()
                    .expect("failures path must exist for comparator mismatch")
            )
            .exists()
        );
        assert!(
            Path::new(
                scenario
                    .deviations_path
                    .as_deref()
                    .expect("deviations path must exist for comparator mismatch")
            )
            .exists()
        );
        assert!(
            Path::new(
                scenario
                    .repro_manifest_path
                    .as_deref()
                    .expect("repro manifest must exist for comparator mismatch")
            )
            .exists()
        );

        let summary = fs::read_to_string(&scenario.summary_path).expect("read comparator summary");
        assert!(summary.contains("\"description\":"));
        assert!(summary.contains("\"status\": \"expected_divergence\""));
        assert!(
            summary
                .contains("\"expected_provisional_class\": \"semantic_mismatch_admitted_surface\"")
        );
        assert!(summary.contains("\"expected_final_policy_class\": null"));
        assert!(summary.contains("\"attempt_count\": 4"));
        assert!(summary.contains("\"rerun_count\": 3"));
        assert!(summary.contains("\"policy_summary\":"));

        let event_log =
            fs::read_to_string(&scenario.event_log_path).expect("read comparator event log");
        assert!(event_log.contains("\"provisional_class\":\"semantic_mismatch_admitted_surface\""));
        assert!(event_log.contains("\"final_policy_class\":\"runtime_semantic_bug\""));
        assert!(event_log.contains("\"attempt_index\":0"));
        assert!(event_log.contains("\"attempt_index\":1"));
        assert!(event_log.contains("\"attempt_index\":2"));
        assert!(event_log.contains("\"attempt_index\":3"));
        assert!(event_log.contains("\"attempt_kind\":\"deterministic_lab_replay\""));
        assert!(event_log.contains("\"attempt_kind\":\"live_confirmation\""));
        assert!(event_log.contains("\"rerun_count\":3"));

        let operator_summary =
            fs::read_to_string(&report.operator_summary_path).expect("read operator summary");
        assert!(operator_summary.contains("Evidence grade: t4_negative_control"));
        assert!(operator_summary.contains("Confidence label: guardrail_validation"));
        assert!(operator_summary.contains(
            "Operator intent: Intentional divergence lane that proves classifier and artifact retention behavior."
        ));
        assert!(operator_summary.contains("final=runtime_semantic_bug"));
        assert!(operator_summary.contains("repro_manifest:"));
        assert!(operator_summary.contains(
            "asupersync lab differential --profile calibration --scenario calibration.comparator.resource_counter_mismatch --seed 8080"
        ));

        let artifact_index: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(&report.artifact_index_path).expect("read artifact index"),
        )
        .expect("parse artifact index");
        assert_eq!(
            artifact_index["schema_version"],
            LAB_DIFFERENTIAL_ARTIFACT_INDEX_SCHEMA_VERSION
        );
        assert_eq!(artifact_index["profile"], "calibration");
        assert_eq!(artifact_index["evidence_grade"], "t4_negative_control");
        assert_eq!(artifact_index["confidence_label"], "guardrail_validation");
        assert_eq!(artifact_index["runtime_cost"], "medium");
        assert_eq!(
            artifact_index["operator_intent"],
            "Intentional divergence lane that proves classifier and artifact retention behavior."
        );
        assert_eq!(
            artifact_index["exit_semantics"],
            lab_differential_exit_semantics()
        );
        assert_eq!(artifact_index["scenario_count"], 1);
        assert_eq!(
            artifact_index["operator_summary_path"].as_str(),
            Some(report.operator_summary_path.as_str())
        );
        assert_eq!(
            artifact_index["runner_summary_path"].as_str(),
            Some(report.runner_summary_path.as_str())
        );
        assert_eq!(
            artifact_index["aggregate_event_log_path"].as_str(),
            Some(report.aggregate_event_log_path.as_str())
        );

        let scenarios = artifact_index["scenarios"]
            .as_array()
            .expect("artifact index scenarios");
        assert_eq!(scenarios.len(), 1);
        let indexed = &scenarios[0];
        assert_eq!(
            indexed["scenario_id"],
            "calibration.comparator.resource_counter_mismatch"
        );
        assert_eq!(indexed["status"], "expected_divergence");
        assert_eq!(
            indexed["observed_provisional_class"],
            "semantic_mismatch_admitted_surface"
        );
        assert_eq!(
            indexed["observed_final_policy_class"],
            "runtime_semantic_bug"
        );
        assert_eq!(
            indexed["summary_path"].as_str(),
            Some(scenario.summary_path.as_str())
        );
        assert_eq!(
            indexed["event_log_path"].as_str(),
            Some(scenario.event_log_path.as_str())
        );
        assert_eq!(
            indexed["lab_normalized_path"].as_str(),
            Some(scenario.lab_normalized_path.as_str())
        );
        assert_eq!(
            indexed["live_normalized_path"].as_str(),
            Some(scenario.live_normalized_path.as_str())
        );
        assert_eq!(
            indexed["repro_manifest_path"],
            scenario
                .repro_manifest_path
                .as_deref()
                .expect("repro manifest path present")
        );
        assert!(
            indexed["repro_commands"]
                .as_array()
                .expect("repro commands array")
                .len()
                >= 2
        );

        let human = report.human_format();
        assert!(human.contains("provisional=semantic_mismatch_admitted_surface"));
        assert!(human.contains("final=runtime_semantic_bug"));
        assert!(human.contains("summary="));
    }

    #[test]
    fn lab_differential_calibration_profile_covers_channel_visibility_mismatch() {
        let temp = tempfile::tempdir().expect("tempdir");
        let args = LabDifferentialArgs {
            profile: LabDifferentialProfile::Calibration,
            scenarios: vec!["calibration.channel.commit_visibility_mismatch".to_string()],
            seed: 9090,
            out_dir: temp.path().join("artifacts"),
            json: false,
        };

        let report = run_lab_differential(&args).expect("run channel calibration profile");
        assert!(report.success);
        assert_eq!(report.expected_divergence_count, 1);

        let scenario = &report.scenarios[0];
        assert_eq!(
            scenario.status,
            LabDifferentialScenarioStatus::ExpectedDivergence
        );
        assert_eq!(
            scenario.observed_provisional_class,
            "semantic_mismatch_admitted_surface"
        );
        assert_eq!(
            scenario.observed_final_policy_class.as_deref(),
            Some("runtime_semantic_bug")
        );
        assert!(
            Path::new(
                scenario
                    .failures_path
                    .as_deref()
                    .expect("failures path must exist for channel mismatch")
            )
            .exists()
        );
        assert!(
            Path::new(
                scenario
                    .deviations_path
                    .as_deref()
                    .expect("deviations path must exist for channel mismatch")
            )
            .exists()
        );
        assert!(
            Path::new(
                scenario
                    .repro_manifest_path
                    .as_deref()
                    .expect("repro manifest must exist for channel mismatch")
            )
            .exists()
        );

        let lab_normalized: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(&scenario.lab_normalized_path).expect("read lab normalized"),
        )
        .expect("parse lab normalized");
        let live_normalized: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(&scenario.live_normalized_path).expect("read live normalized"),
        )
        .expect("parse live normalized");
        assert_eq!(
            lab_normalized["semantics"]["resource_surface"]["counters"]["committed_messages"],
            0
        );
        assert_eq!(
            live_normalized["semantics"]["resource_surface"]["counters"]["committed_messages"],
            1
        );
        assert_eq!(
            lab_normalized["semantics"]["obligation_balance"]["aborted"],
            1
        );
        assert_eq!(
            live_normalized["semantics"]["obligation_balance"]["committed"],
            1
        );
    }

    #[test]
    fn lab_differential_calibration_profile_covers_obligation_leak_detection() {
        let temp = tempfile::tempdir().expect("tempdir");
        let args = LabDifferentialArgs {
            profile: LabDifferentialProfile::Calibration,
            scenarios: vec!["calibration.obligation.leak_detected".to_string()],
            seed: 9170,
            out_dir: temp.path().join("artifacts"),
            json: false,
        };

        let report = run_lab_differential(&args).expect("run obligation calibration profile");
        assert!(report.success);
        assert_eq!(report.expected_divergence_count, 1);

        let scenario = &report.scenarios[0];
        assert_eq!(
            scenario.status,
            LabDifferentialScenarioStatus::ExpectedDivergence
        );
        assert_eq!(scenario.observed_provisional_class, "hard_contract_break");
        assert_eq!(
            scenario.observed_final_policy_class.as_deref(),
            Some("runtime_semantic_bug")
        );
        assert!(
            Path::new(
                scenario
                    .failures_path
                    .as_deref()
                    .expect("failures path must exist for obligation divergence")
            )
            .exists()
        );
        assert!(
            Path::new(
                scenario
                    .deviations_path
                    .as_deref()
                    .expect("deviations path must exist for obligation divergence")
            )
            .exists()
        );
        assert!(
            Path::new(
                scenario
                    .repro_manifest_path
                    .as_deref()
                    .expect("repro manifest must exist for obligation divergence")
            )
            .exists()
        );

        let lab_normalized: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(&scenario.lab_normalized_path).expect("read lab normalized"),
        )
        .expect("parse lab normalized");
        let live_normalized: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(&scenario.live_normalized_path).expect("read live normalized"),
        )
        .expect("parse live normalized");
        assert_eq!(
            lab_normalized["semantics"]["obligation_balance"]["balanced"],
            true
        );
        assert_eq!(
            live_normalized["semantics"]["obligation_balance"]["balanced"],
            false
        );
        assert_eq!(
            live_normalized["semantics"]["obligation_balance"]["reserved"],
            2
        );
        assert_eq!(
            live_normalized["semantics"]["obligation_balance"]["committed"],
            1
        );
        assert_eq!(
            live_normalized["semantics"]["obligation_balance"]["aborted"],
            0
        );
        assert_eq!(
            live_normalized["semantics"]["obligation_balance"]["leaked"],
            1
        );
        assert_eq!(
            live_normalized["semantics"]["resource_surface"]["counters"]["reserved_slots"],
            2
        );

        let event_log =
            fs::read_to_string(&scenario.event_log_path).expect("read obligation event log");
        assert!(event_log.contains("\"provisional_class\":\"hard_contract_break\""));
        assert!(event_log.contains("\"final_policy_class\":\"runtime_semantic_bug\""));
    }

    #[test]
    fn lab_differential_calibration_profile_covers_non_quiescent_region_close() {
        let temp = tempfile::tempdir().expect("tempdir");
        let args = LabDifferentialArgs {
            profile: LabDifferentialProfile::Calibration,
            scenarios: vec!["calibration.region.close.non_quiescent".to_string()],
            seed: 9191,
            out_dir: temp.path().join("artifacts"),
            json: false,
        };

        let report = run_lab_differential(&args).expect("run region-close calibration profile");
        assert!(report.success);
        assert_eq!(report.expected_divergence_count, 1);

        let scenario = &report.scenarios[0];
        assert_eq!(
            scenario.status,
            LabDifferentialScenarioStatus::ExpectedDivergence
        );
        assert_eq!(scenario.observed_provisional_class, "hard_contract_break");
        assert_eq!(
            scenario.observed_final_policy_class.as_deref(),
            Some("runtime_semantic_bug")
        );
        assert!(
            Path::new(
                scenario
                    .failures_path
                    .as_deref()
                    .expect("failures path must exist for region-close divergence")
            )
            .exists()
        );
        assert!(
            Path::new(
                scenario
                    .deviations_path
                    .as_deref()
                    .expect("deviations path must exist for region-close divergence")
            )
            .exists()
        );

        let lab_normalized: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(&scenario.lab_normalized_path).expect("read lab normalized"),
        )
        .expect("parse lab normalized");
        let live_normalized: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(&scenario.live_normalized_path).expect("read live normalized"),
        )
        .expect("parse live normalized");
        assert_eq!(
            lab_normalized["semantics"]["region_close"]["quiescent"],
            true
        );
        assert_eq!(
            live_normalized["semantics"]["region_close"]["quiescent"],
            false
        );
        assert_eq!(
            lab_normalized["semantics"]["region_close"]["live_children"],
            0
        );
        assert_eq!(
            live_normalized["semantics"]["region_close"]["live_children"],
            1
        );

        let event_log =
            fs::read_to_string(&scenario.event_log_path).expect("read region-close event log");
        assert!(event_log.contains("\"provisional_class\":\"hard_contract_break\""));
        assert!(event_log.contains("\"final_policy_class\":\"runtime_semantic_bug\""));
    }

    #[test]
    fn lab_differential_calibration_profile_counts_pass_and_divergence_variants() {
        let temp = tempfile::tempdir().expect("tempdir");
        let args = LabDifferentialArgs {
            profile: LabDifferentialProfile::Calibration,
            scenarios: Vec::new(),
            seed: 6060,
            out_dir: temp.path().join("artifacts"),
            json: false,
        };

        let report = run_lab_differential(&args).expect("run full calibration profile");
        assert!(report.success);
        assert_eq!(report.scenario_count, 8);
        assert_eq!(report.pass_count, 1);
        assert_eq!(report.expected_divergence_count, 7);
        assert_eq!(report.unexpected_divergence_count, 0);
        assert_eq!(report.missing_expected_divergence_count, 0);
        assert!(report.scenarios.iter().any(|scenario| {
            scenario.scenario_id == "calibration.combinator.loser_not_drained"
                && scenario.observed_provisional_class == "hard_contract_break"
                && scenario.observed_final_policy_class.as_deref() == Some("runtime_semantic_bug")
        }));
        assert!(report.scenarios.iter().any(|scenario| {
            scenario.scenario_id == "calibration.comparator.resource_counter_mismatch"
                && scenario.observed_provisional_class == "semantic_mismatch_admitted_surface"
                && scenario.observed_final_policy_class.as_deref() == Some("runtime_semantic_bug")
        }));
        assert!(report.scenarios.iter().any(|scenario| {
            scenario.scenario_id == "calibration.channel.commit_visibility_mismatch"
                && scenario.observed_provisional_class == "semantic_mismatch_admitted_surface"
                && scenario.observed_final_policy_class.as_deref() == Some("runtime_semantic_bug")
        }));
        assert!(report.scenarios.iter().any(|scenario| {
            scenario.scenario_id == "calibration.cancellation.cleanup_missing"
                && scenario.observed_final_policy_class.as_deref() == Some("runtime_semantic_bug")
        }));
        assert!(report.scenarios.iter().any(|scenario| {
            scenario.scenario_id == "calibration.cancellation.cleanup_budget_exhausted"
                && scenario.observed_provisional_class == "hard_contract_break"
                && scenario.observed_final_policy_class.as_deref() == Some("runtime_semantic_bug")
        }));
        assert!(report.scenarios.iter().any(|scenario| {
            scenario.scenario_id == "calibration.region.close.non_quiescent"
                && scenario.observed_provisional_class == "hard_contract_break"
                && scenario.observed_final_policy_class.as_deref() == Some("runtime_semantic_bug")
        }));
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
    fn doctor_stress_soak_contract_command_parses() {
        let cli = Cli::try_parse_from(["asupersync", "doctor", "stress-soak-contract"])
            .expect("parse doctor stress-soak-contract");

        let Command::Doctor(DoctorArgs {
            command: DoctorCommand::StressSoakContract,
        }) = cli.command
        else {
            panic!("expected doctor stress-soak-contract command");
        };
    }

    #[test]
    fn doctor_stress_soak_smoke_command_parses() {
        let cli = Cli::try_parse_from([
            "asupersync",
            "doctor",
            "stress-soak-smoke",
            "--profile-mode",
            "fast",
            "--seed",
            "seed-5150",
        ])
        .expect("parse doctor stress-soak-smoke");

        let Command::Doctor(DoctorArgs {
            command: DoctorCommand::StressSoakSmoke(args),
        }) = cli.command
        else {
            panic!("expected doctor stress-soak-smoke command");
        };
        assert_eq!(args.profile_mode, "fast");
        assert_eq!(args.seed, "seed-5150");
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
    fn doctor_package_cli_args_parse_flags() {
        let cli = Cli::try_parse_from([
            "asupersync",
            "doctor",
            "package-cli",
            "--source-binary",
            "target/release/asupersync",
            "--out-dir",
            "target/e2e-results/doctor_cli_package",
            "--binary-name",
            "doctor_asupersync",
            "--default-profile",
            "ci",
            "--smoke",
        ])
        .expect("parse doctor package-cli args");

        let Command::Doctor(DoctorArgs {
            command: DoctorCommand::PackageCli(args),
        }) = cli.command
        else {
            panic!("expected doctor package-cli command");
        };
        assert_eq!(
            args.source_binary.as_deref(),
            Some(Path::new("target/release/asupersync"))
        );
        assert_eq!(
            args.out_dir,
            PathBuf::from("target/e2e-results/doctor_cli_package")
        );
        assert_eq!(args.binary_name, "doctor_asupersync");
        assert_eq!(args.default_profile, DoctorPackageProfile::Ci);
        assert!(args.smoke);
    }

    #[test]
    fn doctor_task_console_view_command_parses() {
        let cli = Cli::try_parse_from([
            "asupersync",
            "doctor",
            "task-console-view",
            "--snapshot",
            "artifacts/task_console.json",
            "--max-tasks",
            "32",
            "--allow-schema-mismatch",
        ])
        .expect("parse doctor task-console-view args");

        let Command::Doctor(DoctorArgs {
            command: DoctorCommand::TaskConsoleView(args),
        }) = cli.command
        else {
            panic!("expected doctor task-console-view command");
        };
        assert_eq!(args.snapshot, PathBuf::from("artifacts/task_console.json"));
        assert_eq!(args.max_tasks, 32);
        assert!(args.allow_schema_mismatch);
    }

    #[test]
    fn build_task_console_view_output_truncates_tasks() {
        let snapshot = sample_task_console_snapshot();
        let view =
            build_task_console_view_output(snapshot, Path::new("fixtures/task_console.json"), 1);
        assert!(view.schema_matches_expected);
        assert_eq!(view.source_snapshot, "fixtures/task_console.json");
        assert_eq!(view.total_tasks, 2);
        assert_eq!(view.shown_tasks, 1);
        assert!(view.truncated);
    }

    #[test]
    fn doctor_task_console_view_rejects_schema_mismatch_by_default() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("task_console_snapshot.json");
        let mut snapshot = sample_task_console_snapshot();
        snapshot.schema_version = "asupersync.task_console_wire.experimental".to_string();
        fs::write(
            &path,
            snapshot.to_json().expect("serialize task console snapshot"),
        )
        .expect("write task console snapshot");

        let args = DoctorTaskConsoleViewArgs {
            snapshot: path,
            max_tasks: 8,
            allow_schema_mismatch: false,
        };
        let mut output = Output::with_writer(OutputFormat::Json, std::io::Cursor::new(Vec::new()));
        let err =
            doctor_task_console_view(&args, &mut output).expect_err("schema mismatch should fail");
        assert_eq!(err.error_type, "doctor_task_console_schema_error");
        assert!(err.detail.contains(TASK_CONSOLE_WIRE_SCHEMA_V1));
    }

    #[test]
    fn doctor_package_template_materialization_is_deterministic() {
        let temp = tempfile::tempdir().expect("tempdir");
        let first = materialize_doctor_package_templates(temp.path(), "doctor_asupersync")
            .expect("materialize first");
        let second = materialize_doctor_package_templates(temp.path(), "doctor_asupersync")
            .expect("materialize second");

        assert_eq!(first.len(), 2);
        assert_eq!(second.len(), 2);
        assert_eq!(
            first
                .iter()
                .map(|entry| entry.artifact.profile.clone())
                .collect::<Vec<_>>(),
            vec!["ci".to_string(), "local".to_string()]
        );
        assert_eq!(
            first
                .iter()
                .map(|entry| entry.artifact.command_preview.clone())
                .collect::<Vec<_>>(),
            second
                .iter()
                .map(|entry| entry.artifact.command_preview.clone())
                .collect::<Vec<_>>()
        );
        for entry in &first {
            let raw = fs::read_to_string(&entry.artifact.path).expect("read materialized template");
            let parsed = parse_doctor_package_config(&raw).expect("template parse");
            assert_eq!(
                parsed.schema_version,
                DOCTOR_CLI_PACKAGE_CONFIG_SCHEMA_VERSION
            );
            assert_eq!(parsed.profile, entry.artifact.profile);
            assert!(entry.artifact.command_preview.contains("--format"));
            assert!(entry.artifact.command_preview.contains("--color"));
            assert!(
                entry
                    .artifact
                    .command_preview
                    .contains("doctor report-contract")
            );
        }
    }

    #[test]
    fn render_doctor_packaged_command_includes_cli_flags() {
        let config = doctor_package_config_template(DoctorPackageProfile::Ci, "doctor_asupersync");
        let command = render_doctor_packaged_command(&config, "doctor_asupersync");
        assert_eq!(
            command,
            "doctor_asupersync --format json --color never doctor report-contract"
        );
    }

    #[test]
    fn parse_doctor_package_config_rejects_invalid_profile() {
        let mut config =
            doctor_package_config_template(DoctorPackageProfile::Local, "doctor_asupersync");
        config.profile = "prod".to_string();
        let raw = serde_json::to_string(&config).expect("serialize config");
        let err = parse_doctor_package_config(&raw).expect_err("invalid profile should fail");
        assert!(err.contains("profile must be one of: local, ci"));
    }

    #[test]
    fn parse_doctor_package_config_rejects_invalid_output_format() {
        let mut config =
            doctor_package_config_template(DoctorPackageProfile::Local, "doctor_asupersync");
        config.output_format = "xml".to_string();
        let raw = serde_json::to_string(&config).expect("serialize config");
        let err = parse_doctor_package_config(&raw).expect_err("invalid format should fail");
        assert!(err.contains("output_format must be one of"));
    }

    #[test]
    fn resolve_install_smoke_binary_path_handles_relative_paths() {
        let cwd = std::env::current_dir().expect("cwd");
        let rel_dir = cwd.join("target/test-temp-doctor-package");
        fs::create_dir_all(&rel_dir).expect("create rel dir");
        let rel_binary = PathBuf::from("target/test-temp-doctor-package/doctor_asupersync");
        fs::write(&rel_binary, b"mock-binary").expect("write rel binary");

        let resolved = resolve_install_smoke_binary_path(&rel_binary, "doctor_package_smoke_error")
            .expect("canonicalize relative smoke path");
        assert!(resolved.is_absolute());
        assert_eq!(
            resolved,
            fs::canonicalize(&rel_binary).expect("canonicalize reference")
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
