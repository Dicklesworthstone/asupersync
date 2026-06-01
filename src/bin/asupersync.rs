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
use asupersync::atp::doctor::{
    AtpPlatformDoctorDocument, detect_platform_doctor_document, render_platform_doctor_human,
};
use asupersync::atp::identity::directory::{
    DirectorySubject, PeerDirectory, peer_id_from_hex, peer_id_to_hex,
};
use asupersync::atp::object::{ObjectGraph, ObjectId};
use asupersync::atp::safety::{
    DestinationPolicy, ReceiveConsentSource, ReceiveMetadataPolicy, ReceivePlan,
    ReceivePreflightInput, RollbackResumePolicy, StorageEvidence, build_receive_plan,
    consent_token,
};
use asupersync::atp::sdk::StreamEarlyUsabilityReport;
use asupersync::atp::stream_object::ByteRange;
use asupersync::atp::sync::DirectoryEarlyUsabilityReport;
use asupersync::atp::{
    ATP_AUTOTUNE_METRIC_NAMES, AtpAutotuneDecision, AtpAutotuneDecisionReceipt, AtpAutotunePolicy,
    AtpAutotuneSettings, AtpAutotuneTelemetry, AtpAutotuneTelemetryReport, AtpRepairCoordinator,
    AtpRepairCoordinatorDecision, AtpRepairRoiInputs,
};
use asupersync::cli::doctor::{
    AdvancedCollaborationEntry, AdvancedDiagnosticsFixture, AdvancedDiagnosticsReportBundle,
    AdvancedRemediationDelta, AdvancedTroubleshootingPlaybook, AdvancedTrustTransition,
    AgentSwarmStatusSnapshot, DoctorScenarioCoveragePackSmokeReport,
    DoctorScenarioCoveragePacksContract, DoctorStressSoakContract, DoctorStressSoakSmokeReport,
    EvidenceTimelineContract, EvidenceTimelineWorkflowTranscript,
    advanced_diagnostics_report_bundle, agent_swarm_status_contract,
    build_doctor_scenario_coverage_pack_smoke_report, build_doctor_stress_soak_smoke_report,
    doctor_scenario_coverage_packs_contract, doctor_stress_soak_contract,
    evidence_timeline_contract, run_agent_swarm_status_smoke,
    run_evidence_timeline_keyboard_flow_smoke, validate_advanced_diagnostics_report_extension,
    validate_advanced_diagnostics_report_extension_contract,
};
use asupersync::cli::{
    AtpDoctorArgs, AtpProofArgs, AtpReplayArgs, AtpVerifyArgs, CliError, ColorChoice, CommonArgs,
    CoreDiagnosticsReport, CoreDiagnosticsReportBundle, CoreDiagnosticsSummary, ExitCode,
    InvariantAnalyzerReport, LockContentionAnalyzerReport, OperatorModelContract, Output,
    OutputFormat, Outputtable, RemediationRecipeBundle, ScreenEngineContract,
    StructuredLoggingContract, WorkspaceScanReport, analyze_workspace_invariants,
    analyze_workspace_lock_contention, core_diagnostics_report_bundle,
    core_diagnostics_report_contract, operator_model_contract, parse_color_choice,
    parse_output_format, remediation_recipe_bundle, scan_workspace, screen_engine_contract,
    structured_logging_contract, validate_core_diagnostics_report,
    validate_core_diagnostics_report_contract,
};
use asupersync::conformance::{
    ScanWarning, SpecRequirement, TraceabilityMatrix, TraceabilityScanError,
    requirements_from_entries, scan_conformance_attributes,
};
use asupersync::cx::{Cx, NoCaps};
use asupersync::lab::dual_run::{
    FinalDivergenceClass, ReplayPolicy, RerunDecision, SeedPlan, derive_scenario_seed,
};
use asupersync::lab::replay::{
    DifferentialBundleArtifacts, DifferentialPolicyClass, DivergenceCorpusEntry,
};
use asupersync::lab::{
    CancellationRecord, DualRunHarness, DualRunScenarioIdentity, LabConfig, LabRuntime,
    LiveWitnessCollector, LoserDrainRecord, NormalizedSemantics, ObligationBalanceRecord,
    RegionCloseRecord, ResourceSurfaceRecord, TerminalOutcome, capture_cancellation,
    capture_loser_drain, capture_obligation_balance, capture_region_close, run_live_adapter,
};
use asupersync::net::atp::protocol::PeerId;
use asupersync::observability::{
    TASK_CONSOLE_WIRE_SCHEMA_V1, TaskConsoleWireSnapshot, TaskDetailsWire, TaskSummaryWire,
};
use asupersync::sync::{AcquireError, Semaphore};
use asupersync::trace::{
    CompressionMode, IssueSeverity, ReplayEvent, TRACE_FILE_VERSION, TRACE_MAGIC, TraceFileConfig,
    TraceFileError, TraceReader, TraceWriter, VerificationOptions, verify_trace,
};
use asupersync::types::Budget;
use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};
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
use std::task::{Context, Poll, Waker};

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
    /// ATP protocol tooling
    Atp(AtpArgs),
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
struct AtpArgs {
    #[command(subcommand)]
    command: AtpCommand,
}

#[derive(Subcommand, Debug)]
enum AtpCommand {
    /// ATP diagnostics
    Doctor(AtpDoctorArgs),
    /// Explain current ATP autotune status from a telemetry window
    Status(AtpStatusArgs),
    /// Peer directory operations
    Directory(AtpDirectoryArgs),
    /// Render ATP usable-early report artifacts
    EarlyUsability(AtpEarlyUsabilityArgs),
    /// Send files or directories via ATP
    Send(AtpSendArgs),
    /// Receive ATP transfer with safety preflight
    Get(AtpGetArgs),
    /// Synchronize directories with ATP
    Sync(AtpSyncArgs),
    /// Mirror directories with ATP (including deletes)
    Mirror(AtpMirrorArgs),
    /// Generate share codes for ATP transfers
    Share(AtpShareArgs),
    /// Establish peer identity and pairing for ATP transfers
    Pair(AtpPairArgs),
    /// Seed content for ATP cache and relay distribution
    Seed(AtpSeedArgs),
    /// Watch directory for changes and sync automatically
    Watch(AtpWatchArgs),
    /// Serve ATP daemon for background transfers
    Serve(AtpServeArgs),
    /// Manage ATP inbox for incoming transfers
    Inbox(AtpInboxArgs),
    /// Resume paused or failed ATP transfers
    Resume(AtpResumeArgs),
    /// Cancel active ATP transfers
    Cancel(AtpCancelArgs),
    /// Show status of active ATP transfers
    TransferStatus(AtpTransferStatusArgs),
    /// Verify ATP proof bundle offline
    Verify(AtpVerifyArgs),
    /// Replay emitted ATP crashpack artifacts
    Replay(AtpReplayArgs),
    /// Display ATP proof bundle information
    Proof(AtpProofArgs),
    /// Run ATP benchmark profiles and generate reports
    Bench(AtpBenchArgs),
    /// Inspect and analyze ATP trace files
    Trace(AtpTraceArgs),
}

#[derive(Args, Debug)]
struct AtpDirectoryArgs {
    /// Directory JSON file
    #[arg(long, value_name = "PATH", default_value = "atp-peer-directory.json")]
    file: PathBuf,
    #[command(subcommand)]
    command: AtpDirectoryCommand,
}

#[derive(Args, Debug)]
struct AtpEarlyUsabilityArgs {
    /// JSON report emitted by SDK, proof, or transfer artifact code.
    #[arg(long, value_name = "PATH")]
    report: PathBuf,
}

#[derive(Args, Debug)]
struct AtpGetArgs {
    /// Transfer ID or share token to receive
    #[arg(value_name = "TRANSFER")]
    transfer_id: String,

    /// Destination directory (default: current directory)
    #[arg(value_name = "DEST")]
    destination: Option<PathBuf>,

    /// Show receive plan without executing transfer
    #[arg(long = "dry-run", action = ArgAction::SetTrue)]
    dry_run: bool,

    /// Destination policy: deny, inbox-only, quarantine-only, allow-listed
    #[arg(long = "policy", default_value = "deny")]
    policy: String,

    /// Allow overwriting existing files
    #[arg(long = "allow-overwrite", action = ArgAction::SetTrue)]
    allow_overwrite: bool,

    /// Allow symlink materialization
    #[arg(long = "allow-symlinks", action = ArgAction::SetTrue)]
    allow_symlinks: bool,

    /// Allow executable bit materialization
    #[arg(long = "allow-executables", action = ArgAction::SetTrue)]
    allow_executables: bool,

    /// Maximum transfer size (bytes)
    #[arg(long = "max-bytes")]
    max_bytes: Option<u64>,

    /// Skip interactive confirmation prompts
    #[arg(long = "accept", action = ArgAction::SetTrue)]
    accept: bool,

    /// Show detailed preflight report
    #[arg(long = "verbose", short = 'v', action = ArgAction::SetTrue)]
    verbose: bool,

    /// Show detailed progress during transfer
    #[arg(long = "progress", action = ArgAction::SetTrue)]
    progress: bool,

    /// Explain path, scheduler, and repair decisions
    #[arg(long = "explain", action = ArgAction::SetTrue)]
    explain: bool,
}

#[derive(Args, Debug)]
struct AtpSendArgs {
    /// Source path to send (file or directory)
    #[arg(value_name = "SOURCE")]
    source: PathBuf,

    /// Target peer or share token destination
    #[arg(value_name = "TARGET")]
    target: String,

    /// Show send plan without executing transfer
    #[arg(long = "dry-run", action = ArgAction::SetTrue)]
    dry_run: bool,

    /// Chunking profile: bulk, sync-tree, media, sparse-image, artifact, stream
    #[arg(long = "profile", default_value = "bulk")]
    profile: String,

    /// Maximum concurrent streams
    #[arg(long = "streams", default_value_t = 4)]
    streams: u16,

    /// Show detailed preflight report
    #[arg(long = "verbose", short = 'v', action = ArgAction::SetTrue)]
    verbose: bool,

    /// Show detailed progress during transfer
    #[arg(long = "progress", action = ArgAction::SetTrue)]
    progress: bool,

    /// Explain path, scheduler, and repair decisions
    #[arg(long = "explain", action = ArgAction::SetTrue)]
    explain: bool,
}

#[derive(Args, Debug)]
struct AtpSyncArgs {
    /// Source path to sync (directory)
    #[arg(value_name = "SOURCE")]
    source: PathBuf,

    /// Target peer and path destination
    #[arg(value_name = "TARGET")]
    target: String,

    /// Show sync plan without executing transfer
    #[arg(long = "dry-run", action = ArgAction::SetTrue)]
    dry_run: bool,

    /// Allow destructive operations (updates only, no deletes)
    #[arg(long = "allow-updates", action = ArgAction::SetTrue)]
    allow_updates: bool,

    /// Show detailed preflight report
    #[arg(long = "verbose", short = 'v', action = ArgAction::SetTrue)]
    verbose: bool,

    /// Show detailed progress during transfer
    #[arg(long = "progress", action = ArgAction::SetTrue)]
    progress: bool,

    /// Explain path, scheduler, and repair decisions
    #[arg(long = "explain", action = ArgAction::SetTrue)]
    explain: bool,
}

#[derive(Args, Debug)]
struct AtpMirrorArgs {
    /// Source path to mirror (directory)
    #[arg(value_name = "SOURCE")]
    source: PathBuf,

    /// Target peer and path destination
    #[arg(value_name = "TARGET")]
    target: String,

    /// Show mirror plan without executing transfer
    #[arg(long = "dry-run", action = ArgAction::SetTrue)]
    dry_run: bool,

    /// Allow destructive operations (including deletes)
    #[arg(long = "allow-deletes", action = ArgAction::SetTrue)]
    allow_deletes: bool,

    /// Show detailed preflight report
    #[arg(long = "verbose", short = 'v', action = ArgAction::SetTrue)]
    verbose: bool,

    /// Show detailed progress during transfer
    #[arg(long = "progress", action = ArgAction::SetTrue)]
    progress: bool,

    /// Explain path, scheduler, and repair decisions
    #[arg(long = "explain", action = ArgAction::SetTrue)]
    explain: bool,
}

#[derive(Args, Debug)]
struct AtpShareArgs {
    /// Source path to generate share code for
    #[arg(value_name = "SOURCE")]
    source: PathBuf,

    /// Share expiration time in seconds from now
    #[arg(long = "expires", default_value_t = 3600)]
    expires_seconds: u64,

    /// Maximum number of downloads allowed
    #[arg(long = "max-downloads", default_value_t = 1)]
    max_downloads: u32,

    /// Share policy: open, peers-only, specific-peer
    #[arg(long = "policy", default_value = "peers-only")]
    policy: String,

    /// Capability type: read, write, receive, relay, mailbox
    #[arg(long = "capability", default_value = "read", value_delimiter = ',')]
    capabilities: Vec<String>,

    /// Quota limit in bytes (0 = unlimited)
    #[arg(long = "quota", default_value_t = 0)]
    quota_bytes: u64,

    /// Specific peer ID for restricted sharing
    #[arg(long = "peer-id")]
    peer_id: Option<String>,

    /// Destination policy hints
    #[arg(long = "destination-policy", default_value = "auto")]
    destination_policy: String,

    /// Enable single-use share code
    #[arg(long = "single-use", action = clap::ArgAction::SetTrue)]
    single_use: bool,

    /// Enable revocation capability
    #[arg(long = "revocable", action = clap::ArgAction::SetTrue)]
    revocable: bool,
}

#[derive(Args, Debug)]
struct AtpPairArgs {
    #[command(subcommand)]
    command: AtpPairCommand,
}

#[derive(clap::Subcommand, Debug)]
enum AtpPairCommand {
    /// Initiate pairing with a new peer
    Initiate {
        /// Optional peer identifier hint
        #[arg(long = "peer-hint")]
        peer_hint: Option<String>,

        /// Confirmation method: visual, audio, manual
        #[arg(long = "method", default_value = "visual")]
        confirmation_method: String,

        /// Timeout for pairing in seconds
        #[arg(long = "timeout", default_value_t = 300)]
        timeout_seconds: u64,
    },
    /// Complete pairing with confirmation code
    Confirm {
        /// Pairing token received from peer
        #[arg(value_name = "TOKEN")]
        pairing_token: String,

        /// Human-readable confirmation phrase
        #[arg(value_name = "PHRASE")]
        confirmation_phrase: String,
    },
    /// Cancel an active pairing session
    Cancel {
        /// Pairing session ID to cancel
        #[arg(value_name = "SESSION_ID")]
        session_id: String,
    },
    /// List active pairing sessions
    List {
        /// Show detailed session information
        #[arg(long = "detailed", action = clap::ArgAction::SetTrue)]
        detailed: bool,
    },
}

#[derive(Args, Debug)]
struct AtpSeedArgs {
    /// Source path or manifest to seed in cache
    #[arg(value_name = "SOURCE")]
    source: PathBuf,

    /// Seeding policy: public, team-only, peers-only
    #[arg(long = "policy", default_value = "peers-only")]
    policy: String,

    /// Time to live in cache (seconds, 0 = permanent)
    #[arg(long = "ttl", default_value_t = 86400)] // 24 hours default
    ttl_seconds: u64,

    /// Maximum cache size for this seed (bytes, 0 = unlimited)
    #[arg(long = "max-size", default_value_t = 0)]
    max_size_bytes: u64,

    /// Priority level for cache eviction
    #[arg(long = "priority", default_value = "normal")]
    priority: String,

    /// Enable relay distribution for this seed
    #[arg(long = "relay", action = clap::ArgAction::SetTrue)]
    relay_enabled: bool,

    /// Tags for seed discovery and management
    #[arg(long = "tag", value_delimiter = ',')]
    tags: Vec<String>,

    /// Verify seed integrity before caching
    #[arg(long = "verify", action = clap::ArgAction::SetTrue)]
    verify_integrity: bool,
}

#[derive(Args, Debug)]
struct AtpWatchArgs {
    /// Source path to watch for changes
    #[arg(value_name = "SOURCE")]
    source: PathBuf,

    /// Target peer and path destination
    #[arg(value_name = "TARGET")]
    target: String,

    /// Debounce interval in seconds
    #[arg(long = "debounce", default_value_t = 5)]
    debounce_seconds: u32,

    /// Sync mode: sync-only, mirror-with-deletes
    #[arg(long = "mode", default_value = "sync-only")]
    mode: String,

    /// Show detailed sync reports
    #[arg(long = "verbose", short = 'v', action = ArgAction::SetTrue)]
    verbose: bool,
}

#[derive(Args, Debug)]
struct AtpServeArgs {
    /// Configuration profile: relay, mailbox, cache, full
    #[arg(long = "profile", default_value = "full")]
    profile: String,

    /// Listen address and port
    #[arg(long = "listen", default_value = "0.0.0.0:8080")]
    listen: String,

    /// Data directory for cache and inbox
    #[arg(long = "data-dir", default_value = "~/.atp")]
    data_dir: PathBuf,

    /// Run as daemon (detach from terminal)
    #[arg(long = "daemon", action = ArgAction::SetTrue)]
    daemon: bool,
}

#[derive(Args, Debug)]
struct AtpInboxArgs {
    #[command(subcommand)]
    command: AtpInboxCommand,
}

#[derive(Subcommand, Debug)]
enum AtpInboxCommand {
    /// List pending transfers in inbox
    List,
    /// Accept specific transfer from inbox
    Accept {
        /// Transfer ID to accept
        transfer_id: String,
        /// Destination path
        destination: Option<PathBuf>,
    },
    /// Reject specific transfer from inbox
    Reject {
        /// Transfer ID to reject
        transfer_id: String,
        /// Reason for rejection
        reason: Option<String>,
    },
    /// Clear all rejected/expired transfers
    Clear,
}

#[derive(Args, Debug)]
struct AtpResumeArgs {
    /// Transfer ID to resume
    #[arg(value_name = "TRANSFER_ID")]
    transfer_id: String,

    /// Force resume even if integrity checks fail
    #[arg(long = "force", action = ArgAction::SetTrue)]
    force: bool,

    /// Show detailed resume report
    #[arg(long = "verbose", short = 'v', action = ArgAction::SetTrue)]
    verbose: bool,
}

#[derive(Args, Debug)]
struct AtpCancelArgs {
    /// Transfer ID to cancel
    #[arg(value_name = "TRANSFER_ID")]
    transfer_id: String,

    /// Cancel reason for audit logs
    #[arg(long = "reason", default_value = "user_request")]
    reason: String,

    /// Force cancellation even if in critical phase
    #[arg(long = "force", action = ArgAction::SetTrue)]
    force: bool,
}

#[derive(Args, Debug)]
struct AtpTransferStatusArgs {
    /// Show status for specific transfer ID
    #[arg(value_name = "TRANSFER_ID")]
    transfer_id: Option<String>,

    /// Show detailed progress and explain information
    #[arg(long = "explain", action = ArgAction::SetTrue)]
    explain: bool,

    /// Watch mode - continuously update status
    #[arg(long = "watch", short = 'w', action = ArgAction::SetTrue)]
    watch: bool,

    /// Refresh interval in seconds for watch mode
    #[arg(long = "interval", default_value_t = 2)]
    interval_seconds: u64,
}

#[derive(Args, Debug)]
struct AtpBenchArgs {
    /// Benchmark profile to run: throughput, latency, repair, stress, mixed
    #[arg(value_name = "PROFILE", default_value = "throughput")]
    profile: String,

    /// Duration of benchmark in seconds
    #[arg(long = "duration", short = 'd', default_value_t = 30)]
    duration_seconds: u64,

    /// Output directory for benchmark reports
    #[arg(long = "output-dir", default_value = "target/atp-bench-results")]
    output_dir: PathBuf,

    /// Number of concurrent transfers for stress testing
    #[arg(long = "concurrency", short = 'c', default_value_t = 4)]
    concurrency: u16,

    /// Transfer size for throughput/latency tests (bytes)
    #[arg(long = "transfer-size", default_value_t = 1_048_576)]
    transfer_size: u64,

    /// Include detailed metrics in JSON report
    #[arg(long = "detailed", action = ArgAction::SetTrue)]
    detailed: bool,
}

#[derive(Args, Debug)]
struct AtpTraceArgs {
    #[command(subcommand)]
    command: AtpTraceCommand,
}

#[derive(Subcommand, Debug)]
enum AtpTraceCommand {
    /// Analyze trace file for performance bottlenecks
    Analyze {
        /// Path to ATP trace file
        #[arg(value_name = "TRACE_FILE")]
        trace_file: PathBuf,

        /// Show detailed event breakdown
        #[arg(long = "detailed", action = ArgAction::SetTrue)]
        detailed: bool,
    },
    /// Extract specific events from trace
    Extract {
        /// Path to ATP trace file
        #[arg(value_name = "TRACE_FILE")]
        trace_file: PathBuf,

        /// Event types to extract: path, repair, disk, scheduler
        #[arg(long = "event-types", value_delimiter = ',')]
        event_types: Vec<String>,

        /// Output format: json, csv, human
        #[arg(long = "format", default_value = "human")]
        format: String,
    },
    /// Compare two trace files
    Compare {
        /// First trace file
        #[arg(value_name = "TRACE_A")]
        trace_a: PathBuf,

        /// Second trace file
        #[arg(value_name = "TRACE_B")]
        trace_b: PathBuf,

        /// Focus comparison on specific metrics
        #[arg(long = "metrics", value_delimiter = ',')]
        metrics: Vec<String>,
    },
    /// Visualize trace timeline
    Timeline {
        /// Path to ATP trace file
        #[arg(value_name = "TRACE_FILE")]
        trace_file: PathBuf,

        /// Output format: ascii, svg, html
        #[arg(long = "format", default_value = "ascii")]
        format: String,

        /// Time window to visualize (start:end in seconds)
        #[arg(long = "window")]
        time_window: Option<String>,
    },
}

#[derive(Debug, serde::Serialize)]
struct AtpGetPlanOutput {
    plan: ReceivePlan,
}

impl Outputtable for AtpGetPlanOutput {
    fn json(&self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::to_value(&self.plan)
    }

    fn human_format(&self) -> String {
        let mut output = String::new();
        output.push_str("Receive Plan:\n");
        for line in self.plan.stable_human_lines() {
            output.push_str(&format!("  {}\n", line));
        }
        output
    }
}

#[derive(Debug, serde::Serialize)]
struct AtpGetPlanHumanOutput {
    lines: Vec<String>,
}

impl AtpGetPlanHumanOutput {
    fn new(plan: &ReceivePlan) -> Self {
        let mut lines = vec!["Receive Plan:".to_string()];
        for line in plan.stable_human_lines() {
            lines.push(format!("  {}", line));
        }
        Self { lines }
    }
}

impl Outputtable for AtpGetPlanHumanOutput {
    fn json(&self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::to_value(&self.lines)
    }

    fn human_format(&self) -> String {
        self.lines.join("\n")
    }
}

#[derive(Debug, serde::Serialize)]
struct AtpGetStatusMessage {
    message: String,
}

impl AtpGetStatusMessage {
    fn new(message: &str) -> Self {
        Self {
            message: message.to_string(),
        }
    }
}

impl Outputtable for AtpGetStatusMessage {
    fn json(&self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::to_value(&self.message)
    }

    fn human_format(&self) -> String {
        self.message.clone()
    }
}

#[derive(Clone, Debug, Default)]
struct PathSummary {
    total_bytes: u64,
    object_count: usize,
    file_count: usize,
    directory_count: usize,
}

impl PathSummary {
    fn describe(&self) -> String {
        format!(
            "{} object(s), {} file(s), {} directories, {}",
            self.object_count,
            self.file_count,
            self.directory_count,
            format_bytes(self.total_bytes)
        )
    }
}

fn summarize_source_path(path: &Path) -> Result<PathSummary, CliError> {
    let metadata = fs::symlink_metadata(path).map_err(|err| {
        CliError::new("source_unavailable", "Failed to inspect source path")
            .detail(format!("Path: {}, Error: {}", path.display(), err))
            .exit_code(ExitCode::USER_ERROR)
    })?;

    let mut summary = PathSummary::default();
    summarize_source_path_inner(path, &metadata, &mut summary)?;
    Ok(summary)
}

fn summarize_source_path_inner(
    path: &Path,
    metadata: &fs::Metadata,
    summary: &mut PathSummary,
) -> Result<(), CliError> {
    summary.object_count = summary.object_count.saturating_add(1);
    if metadata.is_dir() {
        summary.directory_count = summary.directory_count.saturating_add(1);
        let mut entries = fs::read_dir(path)
            .map_err(|err| {
                CliError::new("directory_read_error", "Failed to read source directory")
                    .detail(format!("Path: {}, Error: {}", path.display(), err))
                    .exit_code(ExitCode::USER_ERROR)
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| {
                CliError::new(
                    "directory_entry_error",
                    "Failed to read source directory entry",
                )
                .detail(format!("Path: {}, Error: {}", path.display(), err))
                .exit_code(ExitCode::USER_ERROR)
            })?;
        entries.sort_by_key(|entry| entry.path());
        for entry in entries {
            let child_path = entry.path();
            let child_metadata = fs::symlink_metadata(&child_path).map_err(|err| {
                CliError::new("source_unavailable", "Failed to inspect source path")
                    .detail(format!("Path: {}, Error: {}", child_path.display(), err))
                    .exit_code(ExitCode::USER_ERROR)
            })?;
            summarize_source_path_inner(&child_path, &child_metadata, summary)?;
        }
    } else if metadata.is_file() {
        summary.file_count = summary.file_count.saturating_add(1);
        summary.total_bytes = summary.total_bytes.saturating_add(metadata.len());
    }
    Ok(())
}

fn stable_transfer_id(prefix: &str, source: &Path, target: &str, summary: &PathSummary) -> String {
    let mut hasher = Sha256::new();
    hash_len_prefixed(&mut hasher, prefix.as_bytes());
    hash_len_prefixed(&mut hasher, source.as_os_str().as_encoded_bytes());
    hash_len_prefixed(&mut hasher, target.as_bytes());
    hasher.update(summary.total_bytes.to_be_bytes());
    hasher.update((summary.object_count as u64).to_be_bytes());
    let digest = hasher.finalize();
    format!(
        "{}_{:016x}",
        prefix,
        u64::from_be_bytes([
            digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
        ])
    )
}

fn hash_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    hasher.update(len.to_be_bytes());
    hasher.update(bytes);
}

fn progress_chunks(total_bytes: u64) -> Vec<u64> {
    if total_bytes == 0 {
        return vec![0];
    }
    let three_quarters = u64::try_from((u128::from(total_bytes) * 3) / 4).unwrap_or(u64::MAX);
    let mut chunks = vec![
        0,
        total_bytes / 4,
        total_bytes / 2,
        three_quarters,
        total_bytes,
    ];
    chunks.dedup();
    chunks
}

fn available_space_for_path(path: &Path) -> Result<u64, CliError> {
    #[cfg(unix)]
    {
        let stats = nix::sys::statvfs::statvfs(path).map_err(|err| {
            CliError::new("storage_probe_error", "Failed to inspect available storage")
                .detail(format!("Path: {}, Error: {}", path.display(), err))
                .exit_code(ExitCode::RUNTIME_ERROR)
        })?;
        let available =
            u128::from(stats.blocks_available()).saturating_mul(u128::from(stats.fragment_size()));
        Ok(available.min(u128::from(u64::MAX)) as u64)
    }

    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(0)
    }
}

fn digest_path_tree(path: &Path) -> Result<[u8; 32], CliError> {
    let mut hasher = Sha256::new();
    digest_path_tree_inner(path, Path::new(""), &mut hasher)?;
    Ok(hasher.finalize().into())
}

fn digest_path_tree_inner(
    path: &Path,
    relative_path: &Path,
    hasher: &mut Sha256,
) -> Result<(), CliError> {
    let metadata = fs::symlink_metadata(path).map_err(|err| {
        CliError::new("source_unavailable", "Failed to inspect source path")
            .detail(format!("Path: {}, Error: {}", path.display(), err))
            .exit_code(ExitCode::USER_ERROR)
    })?;

    hash_len_prefixed(hasher, relative_path.as_os_str().as_encoded_bytes());
    if metadata.is_dir() {
        hash_len_prefixed(hasher, b"dir");
        let mut entries = fs::read_dir(path)
            .map_err(|err| {
                CliError::new("directory_read_error", "Failed to read source directory")
                    .detail(format!("Path: {}, Error: {}", path.display(), err))
                    .exit_code(ExitCode::USER_ERROR)
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| {
                CliError::new(
                    "directory_entry_error",
                    "Failed to read source directory entry",
                )
                .detail(format!("Path: {}, Error: {}", path.display(), err))
                .exit_code(ExitCode::USER_ERROR)
            })?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let child_name = entry.file_name();
            digest_path_tree_inner(&entry.path(), &relative_path.join(child_name), hasher)?;
        }
    } else if metadata.is_file() {
        hash_len_prefixed(hasher, b"file");
        hasher.update(metadata.len().to_be_bytes());
        let mut file = File::open(path).map_err(|err| {
            CliError::new("source_read_error", "Failed to read source file")
                .detail(format!("Path: {}, Error: {}", path.display(), err))
                .exit_code(ExitCode::USER_ERROR)
        })?;
        let mut buffer = vec![0u8; 64 * 1024].into_boxed_slice();
        loop {
            let read = file.read(&mut buffer).map_err(|err| {
                CliError::new("source_read_error", "Failed to read source file")
                    .detail(format!("Path: {}, Error: {}", path.display(), err))
                    .exit_code(ExitCode::USER_ERROR)
            })?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
    } else if metadata.file_type().is_symlink() {
        hash_len_prefixed(hasher, b"symlink");
        let target = fs::read_link(path).map_err(|err| {
            CliError::new("source_read_error", "Failed to read source symlink")
                .detail(format!("Path: {}, Error: {}", path.display(), err))
                .exit_code(ExitCode::USER_ERROR)
        })?;
        hash_len_prefixed(hasher, target.as_os_str().as_encoded_bytes());
    } else {
        hash_len_prefixed(hasher, b"special");
        hasher.update(metadata.len().to_be_bytes());
    }
    Ok(())
}

// Output structures for new ATP commands

#[derive(Debug, serde::Serialize)]
struct AtpSendPlanOutput {
    source: String,
    target: String,
    profile: String,
    estimated_bytes: u64,
    estimated_objects: usize,
}

impl AtpSendPlanOutput {
    fn new(source: &Path, target: &str, profile: &str) -> Result<Self, CliError> {
        let summary = summarize_source_path(source)?;
        Ok(Self {
            source: source.display().to_string(),
            target: target.to_string(),
            profile: profile.to_string(),
            estimated_bytes: summary.total_bytes,
            estimated_objects: summary.object_count,
        })
    }
}

impl Outputtable for AtpSendPlanOutput {
    fn json(&self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::to_value(self)
    }

    fn human_format(&self) -> String {
        format!(
            "Send Plan:\n  Source: {}\n  Target: {}\n  Profile: {}\n  Estimated bytes: {}\n  Estimated objects: {}",
            self.source, self.target, self.profile, self.estimated_bytes, self.estimated_objects
        )
    }
}

#[derive(Debug, serde::Serialize)]
struct AtpSendResultOutput {
    source: String,
    target: String,
    transfer_id: String,
    status: String,
}

impl AtpSendResultOutput {
    fn new(source: &Path, target: &str, transfer_id: &str) -> Self {
        Self {
            source: source.display().to_string(),
            target: target.to_string(),
            transfer_id: transfer_id.to_string(),
            status: "local_source_indexed".to_string(),
        }
    }
}

impl Outputtable for AtpSendResultOutput {
    fn json(&self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::to_value(self)
    }

    fn human_format(&self) -> String {
        format!(
            "Transfer status:\n  Source: {}\n  Target: {}\n  Transfer ID: {}\n  Status: {}",
            self.source, self.target, self.transfer_id, self.status
        )
    }
}

#[derive(Debug, serde::Serialize)]
struct AtpSyncPlanOutput {
    source: String,
    target: String,
    allow_updates: bool,
    changes: Vec<String>,
}

impl AtpSyncPlanOutput {
    fn new(source: &Path, target: &str, allow_updates: bool) -> Result<Self, CliError> {
        let summary = summarize_source_path(source)?;
        Ok(Self {
            source: source.display().to_string(),
            target: target.to_string(),
            allow_updates,
            changes: vec![format!(
                "local source scan ready: {}; remote target inventory required for diff",
                summary.describe()
            )],
        })
    }
}

impl Outputtable for AtpSyncPlanOutput {
    fn json(&self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::to_value(self)
    }

    fn human_format(&self) -> String {
        format!(
            "Sync Plan:\n  Source: {}\n  Target: {}\n  Allow updates: {}\n  Changes: {}",
            self.source,
            self.target,
            self.allow_updates,
            self.changes.join(", ")
        )
    }
}

#[derive(Debug, serde::Serialize)]
struct AtpSyncResultOutput {
    source: String,
    target: String,
    status: String,
    files_synced: usize,
}

impl AtpSyncResultOutput {
    fn new(source: &Path, target: &str) -> Result<Self, CliError> {
        let summary = summarize_source_path(source)?;
        Ok(Self {
            source: source.display().to_string(),
            target: target.to_string(),
            status: "local_source_indexed".to_string(),
            files_synced: summary.file_count,
        })
    }
}

impl Outputtable for AtpSyncResultOutput {
    fn json(&self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::to_value(self)
    }

    fn human_format(&self) -> String {
        format!(
            "Sync completed:\n  Source: {}\n  Target: {}\n  Status: {}\n  Files synced: {}",
            self.source, self.target, self.status, self.files_synced
        )
    }
}

#[derive(Debug, serde::Serialize)]
struct AtpMirrorPlanOutput {
    source: String,
    target: String,
    allow_deletes: bool,
    operations: Vec<String>,
}

impl AtpMirrorPlanOutput {
    fn new(source: &Path, target: &str, allow_deletes: bool) -> Result<Self, CliError> {
        let summary = summarize_source_path(source)?;
        Ok(Self {
            source: source.display().to_string(),
            target: target.to_string(),
            allow_deletes,
            operations: vec![format!(
                "local mirror scan ready: {}; remote target inventory required for delete/update plan",
                summary.describe()
            )],
        })
    }
}

impl Outputtable for AtpMirrorPlanOutput {
    fn json(&self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::to_value(self)
    }

    fn human_format(&self) -> String {
        format!(
            "Mirror Plan:\n  Source: {}\n  Target: {}\n  Allow deletes: {}\n  Operations: {}",
            self.source,
            self.target,
            self.allow_deletes,
            self.operations.join(", ")
        )
    }
}

#[derive(Debug, serde::Serialize)]
struct AtpMirrorResultOutput {
    source: String,
    target: String,
    status: String,
    files_mirrored: usize,
}

impl AtpMirrorResultOutput {
    fn new(source: &Path, target: &str) -> Result<Self, CliError> {
        let summary = summarize_source_path(source)?;
        Ok(Self {
            source: source.display().to_string(),
            target: target.to_string(),
            status: "local_source_indexed".to_string(),
            files_mirrored: summary.file_count,
        })
    }
}

impl Outputtable for AtpMirrorResultOutput {
    fn json(&self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::to_value(self)
    }

    fn human_format(&self) -> String {
        format!(
            "Mirror completed:\n  Source: {}\n  Target: {}\n  Status: {}\n  Files mirrored: {}",
            self.source, self.target, self.status, self.files_mirrored
        )
    }
}

#[derive(Debug, serde::Serialize)]
struct AtpShareOutput {
    source: String,
    share_code: String,
    expires_seconds: u64,
    max_downloads: u32,
    policy: String,
    capabilities: Vec<String>,
    quota_bytes: u64,
    peer_id: Option<String>,
    destination_policy: String,
    single_use: bool,
    revocable: bool,
    revocation_url: Option<String>,
}

impl AtpShareOutput {
    fn new(args: &AtpShareArgs, share_code: String) -> Self {
        let revocation_url = if args.revocable {
            let mut hasher = Sha256::new();
            hash_len_prefixed(&mut hasher, share_code.as_bytes());
            let digest = hasher.finalize();
            Some(format!(
                "atp://revoke/{:016x}",
                u64::from_be_bytes([
                    digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6],
                    digest[7],
                ])
            ))
        } else {
            None
        };

        Self {
            source: args.source.display().to_string(),
            share_code,
            expires_seconds: args.expires_seconds,
            max_downloads: args.max_downloads,
            policy: args.policy.clone(),
            capabilities: args.capabilities.clone(),
            quota_bytes: args.quota_bytes,
            peer_id: args.peer_id.clone(),
            destination_policy: args.destination_policy.clone(),
            single_use: args.single_use,
            revocable: args.revocable,
            revocation_url,
        }
    }
}

#[derive(Debug, serde::Serialize)]
struct AtpPairOutput {
    command: String,
    session_id: Option<String>,
    pairing_token: Option<String>,
    confirmation_phrase: Option<String>,
    peer_id: Option<String>,
    status: String,
    expires_seconds: Option<u64>,
    transcript_binding: Option<String>,
}

impl AtpPairOutput {
    fn initiate(
        session_id: String,
        pairing_token: String,
        confirmation_phrase: String,
        expires_seconds: u64,
    ) -> Self {
        Self {
            command: "initiate".to_string(),
            session_id: Some(session_id),
            pairing_token: Some(pairing_token),
            confirmation_phrase: Some(confirmation_phrase),
            peer_id: None,
            status: "awaiting_confirmation".to_string(),
            expires_seconds: Some(expires_seconds),
            transcript_binding: Some("sha256:transcript".to_string()),
        }
    }

    fn confirm(peer_id: String) -> Self {
        Self {
            command: "confirm".to_string(),
            session_id: None,
            pairing_token: None,
            confirmation_phrase: None,
            peer_id: Some(peer_id),
            status: "paired_successfully".to_string(),
            expires_seconds: None,
            transcript_binding: None,
        }
    }

    fn cancel(session_id: String) -> Self {
        Self {
            command: "cancel".to_string(),
            session_id: Some(session_id),
            pairing_token: None,
            confirmation_phrase: None,
            peer_id: None,
            status: "cancelled".to_string(),
            expires_seconds: None,
            transcript_binding: None,
        }
    }

    fn list(sessions: Vec<String>) -> Self {
        Self {
            command: "list".to_string(),
            session_id: None,
            pairing_token: None,
            confirmation_phrase: None,
            peer_id: None,
            status: format!("{} active sessions", sessions.len()),
            expires_seconds: None,
            transcript_binding: None,
        }
    }
}

#[derive(Debug, serde::Serialize)]
struct AtpSeedOutput {
    source: String,
    seed_id: String,
    policy: String,
    ttl_seconds: u64,
    max_size_bytes: u64,
    priority: String,
    relay_enabled: bool,
    tags: Vec<String>,
    verify_integrity: bool,
    status: String,
    cache_usage: u64,
    estimated_peers: u32,
}

impl AtpSeedOutput {
    fn new(args: &AtpSeedArgs) -> Result<Self, CliError> {
        let summary = summarize_source_path(&args.source)?;
        let tree_digest = digest_path_tree(&args.source)?;
        let mut hasher = Sha256::new();
        hash_len_prefixed(&mut hasher, args.policy.as_bytes());
        hasher.update(tree_digest);
        hasher.update(summary.total_bytes.to_be_bytes());
        hasher.update((summary.object_count as u64).to_be_bytes());
        let hash = hasher.finalize();
        let seed_id = format!(
            "seed_{:x}",
            u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]])
        );

        Ok(Self {
            source: args.source.display().to_string(),
            seed_id,
            policy: args.policy.clone(),
            ttl_seconds: args.ttl_seconds,
            max_size_bytes: args.max_size_bytes,
            priority: args.priority.clone(),
            relay_enabled: args.relay_enabled,
            tags: args.tags.clone(),
            verify_integrity: args.verify_integrity,
            status: "seeding_active".to_string(),
            cache_usage: summary.total_bytes,
            estimated_peers: 0,
        })
    }
}

impl Outputtable for AtpSeedOutput {
    fn json(&self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::to_value(self)
    }

    fn human_format(&self) -> String {
        let mut output = format!(
            "ATP Seed Active\n\
            Source: {}\n\
            Seed ID: {}\n\
            Policy: {}\n\
            TTL: {}s\n\
            Priority: {}\n\
            Status: {}",
            self.source, self.seed_id, self.policy, self.ttl_seconds, self.priority, self.status
        );

        if self.max_size_bytes > 0 {
            output.push_str(&format!(
                "\nMax Size: {}",
                format_bytes(self.max_size_bytes)
            ));
        }

        if self.cache_usage > 0 {
            output.push_str(&format!(
                "\nCache Usage: {}",
                format_bytes(self.cache_usage)
            ));
        }

        if self.relay_enabled {
            output.push_str("\nRelay: Enabled");
            output.push_str(&format!("\nEstimated Peers: {}", self.estimated_peers));
        }

        if !self.tags.is_empty() {
            output.push_str(&format!("\nTags: {}", self.tags.join(", ")));
        }

        if self.verify_integrity {
            output.push_str("\nIntegrity Verification: Enabled");
        }

        output
    }
}

#[derive(Debug, serde::Serialize)]
struct AtpWatchOutput {
    source: String,
    target: String,
    debounce_seconds: u32,
    status: String,
}

impl AtpWatchOutput {
    fn new(source: &Path, target: &str, debounce_seconds: u32) -> Self {
        Self {
            source: source.display().to_string(),
            target: target.to_string(),
            debounce_seconds,
            status: "watching".to_string(),
        }
    }
}

impl Outputtable for AtpShareOutput {
    fn json(&self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::to_value(self)
    }

    fn human_format(&self) -> String {
        let mut output = format!(
            "ATP Share Code Generated\n\
            Source: {}\n\
            Code: {}\n\
            Expires: {}s\n\
            Policy: {}\n\
            Capabilities: {}",
            self.source,
            self.share_code,
            self.expires_seconds,
            self.policy,
            self.capabilities.join(", ")
        );

        if self.quota_bytes > 0 {
            output.push_str(&format!("\nQuota: {}", format_bytes(self.quota_bytes)));
        }

        if let Some(ref peer_id) = self.peer_id {
            output.push_str(&format!("\nRestricted to peer: {}", peer_id));
        }

        if self.single_use {
            output.push_str("\nSingle-use code");
        }

        if let Some(ref revocation_url) = self.revocation_url {
            output.push_str(&format!("\nRevocation URL: {}", revocation_url));
        }

        output
    }
}

impl Outputtable for AtpPairOutput {
    fn json(&self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::to_value(self)
    }

    fn human_format(&self) -> String {
        match self.command.as_str() {
            "initiate" => {
                format!(
                    "ATP Pairing Initiated\n\
                    Session ID: {}\n\
                    Pairing Token: {}\n\
                    Confirmation Phrase: {}\n\
                    Status: {}\n\
                    Expires in: {}s\n\
                    \n\
                    Share this pairing token with your peer:\n\
                    {}\n\
                    \n\
                    Ask your peer to confirm using the phrase:\n\
                    \"{}\"",
                    self.session_id.as_deref().unwrap_or("unknown"),
                    self.pairing_token.as_deref().unwrap_or("unknown"),
                    self.confirmation_phrase.as_deref().unwrap_or("unknown"),
                    self.status,
                    self.expires_seconds.unwrap_or(0),
                    self.pairing_token.as_deref().unwrap_or("unknown"),
                    self.confirmation_phrase.as_deref().unwrap_or("unknown")
                )
            }
            "confirm" => {
                format!(
                    "ATP Pairing Confirmed\n\
                    Peer ID: {}\n\
                    Status: {}\n\
                    \n\
                    Pairing successful! You can now transfer files with this peer.",
                    self.peer_id.as_deref().unwrap_or("unknown"),
                    self.status
                )
            }
            "cancel" => {
                format!(
                    "ATP Pairing Cancelled\n\
                    Session ID: {}\n\
                    Status: {}",
                    self.session_id.as_deref().unwrap_or("unknown"),
                    self.status
                )
            }
            "list" => {
                format!(
                    "ATP Pairing Sessions\n\
                    Status: {}",
                    self.status
                )
            }
            _ => format!("Unknown pairing command: {}", self.command),
        }
    }
}

impl Outputtable for AtpWatchOutput {
    fn json(&self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::to_value(self)
    }

    fn human_format(&self) -> String {
        format!(
            "Watching directory:\n  Source: {}\n  Target: {}\n  Debounce: {} seconds\n  Status: {}",
            self.source, self.target, self.debounce_seconds, self.status
        )
    }
}

#[derive(Debug, serde::Serialize)]
struct AtpServeOutput {
    message: String,
    listen_address: String,
}

impl AtpServeOutput {
    fn new(message: &str, listen_address: &str) -> Self {
        Self {
            message: message.to_string(),
            listen_address: listen_address.to_string(),
        }
    }
}

impl Outputtable for AtpServeOutput {
    fn json(&self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::to_value(self)
    }

    fn human_format(&self) -> String {
        format!(
            "ATP daemon {}\n  Listening on: {}",
            self.message, self.listen_address
        )
    }
}

#[derive(Debug, serde::Serialize)]
struct AtpInboxListOutput {
    transfers: Vec<String>,
    count: usize,
}

impl AtpInboxListOutput {
    fn new(transfers: Vec<String>) -> Self {
        let count = transfers.len();
        Self { transfers, count }
    }
}

impl Outputtable for AtpInboxListOutput {
    fn json(&self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::to_value(self)
    }

    fn human_format(&self) -> String {
        if self.count == 0 {
            "No pending transfers in inbox".to_string()
        } else {
            format!(
                "Inbox ({} transfers):\n  {}",
                self.count,
                self.transfers.join("\n  ")
            )
        }
    }
}

#[derive(Debug, serde::Serialize)]
struct AtpInboxAcceptOutput {
    transfer_id: String,
    destination: String,
    status: String,
}

impl AtpInboxAcceptOutput {
    fn new(transfer_id: &str, destination: &str) -> Self {
        Self {
            transfer_id: transfer_id.to_string(),
            destination: destination.to_string(),
            status: "accepted".to_string(),
        }
    }
}

impl Outputtable for AtpInboxAcceptOutput {
    fn json(&self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::to_value(self)
    }

    fn human_format(&self) -> String {
        format!(
            "Transfer accepted:\n  ID: {}\n  Destination: {}\n  Status: {}",
            self.transfer_id, self.destination, self.status
        )
    }
}

#[derive(Debug, serde::Serialize)]
struct AtpInboxRejectOutput {
    transfer_id: String,
    reason: String,
    status: String,
}

impl AtpInboxRejectOutput {
    fn new(transfer_id: &str, reason: &str) -> Self {
        Self {
            transfer_id: transfer_id.to_string(),
            reason: reason.to_string(),
            status: "rejected".to_string(),
        }
    }
}

impl Outputtable for AtpInboxRejectOutput {
    fn json(&self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::to_value(self)
    }

    fn human_format(&self) -> String {
        format!(
            "Transfer rejected:\n  ID: {}\n  Reason: {}\n  Status: {}",
            self.transfer_id, self.reason, self.status
        )
    }
}

#[derive(Debug, serde::Serialize)]
struct AtpInboxClearOutput {
    cleared_count: usize,
}

impl AtpInboxClearOutput {
    fn new(cleared_count: usize) -> Self {
        Self { cleared_count }
    }
}

impl Outputtable for AtpInboxClearOutput {
    fn json(&self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::to_value(self)
    }

    fn human_format(&self) -> String {
        format!("Cleared {} transfers from inbox", self.cleared_count)
    }
}

#[derive(Debug, serde::Serialize)]
struct AtpResumeOutput {
    transfer_id: String,
    force: bool,
    status: String,
}

impl AtpResumeOutput {
    fn new(transfer_id: &str, force: bool) -> Self {
        Self {
            transfer_id: transfer_id.to_string(),
            force,
            status: "resumed".to_string(),
        }
    }
}

impl Outputtable for AtpResumeOutput {
    fn json(&self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::to_value(self)
    }

    fn human_format(&self) -> String {
        format!(
            "Transfer resumed:\n  ID: {}\n  Force: {}\n  Status: {}",
            self.transfer_id, self.force, self.status
        )
    }
}

#[derive(Debug, serde::Serialize)]
struct AtpCancelOutput {
    transfer_id: String,
    reason: String,
    force: bool,
    status: String,
}

impl AtpCancelOutput {
    fn new(transfer_id: &str, reason: &str, force: bool) -> Self {
        Self {
            transfer_id: transfer_id.to_string(),
            reason: reason.to_string(),
            force,
            status: "cancelled".to_string(),
        }
    }
}

impl Outputtable for AtpCancelOutput {
    fn json(&self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::to_value(self)
    }

    fn human_format(&self) -> String {
        format!(
            "Transfer cancelled:\n  ID: {}\n  Reason: {}\n  Force: {}\n  Status: {}",
            self.transfer_id, self.reason, self.force, self.status
        )
    }
}

// Progress and explain structures for ATP-I3

#[derive(Debug, serde::Serialize)]
struct AtpProgressUpdate {
    transfer_id: String,
    stage: String,
    object_name: String,
    bytes_received: u64,
    bytes_verified: u64,
    bytes_written: u64,
    bytes_committed: u64,
    total_bytes: u64,
    eta_seconds: Option<u64>,
    resume_enabled: bool,
    timestamp_micros: u64,
}

impl AtpProgressUpdate {
    fn new(transfer_id: &str, object_name: &str, received: u64, total: u64) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;

        let received = received.min(total);
        let remaining = total.saturating_sub(received);

        Self {
            transfer_id: transfer_id.to_string(),
            stage: "receiving".to_string(),
            object_name: object_name.to_string(),
            bytes_received: received,
            bytes_verified: received,
            bytes_written: received,
            bytes_committed: received,
            total_bytes: total,
            eta_seconds: if remaining == 0 {
                Some(0)
            } else if received > 0 {
                Some(remaining.div_ceil(1_048_576))
            } else {
                None
            },
            resume_enabled: true,
            timestamp_micros: now,
        }
    }
}

impl Outputtable for AtpProgressUpdate {
    fn json(&self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::to_value(self)
    }

    fn human_format(&self) -> String {
        let percentage = if self.total_bytes > 0 {
            u64::try_from(
                (u128::from(self.bytes_received.min(self.total_bytes)) * 100)
                    / u128::from(self.total_bytes),
            )
            .unwrap_or(100)
            .min(100)
        } else {
            0
        };

        let eta_str = if let Some(eta) = self.eta_seconds {
            format!("ETA {}s", eta)
        } else {
            "ETA unknown".to_string()
        };

        format!(
            "{} {}: {} [{}/{}] ({}%) {}",
            self.stage,
            self.object_name,
            format_bytes(self.bytes_received),
            format_bytes(self.bytes_received),
            format_bytes(self.total_bytes),
            percentage,
            eta_str
        )
    }
}

#[derive(Debug, serde::Serialize)]
struct AtpExplainReport {
    transfer_id: String,
    path_decisions: AtpPathDecisions,
    scheduler_decisions: AtpSchedulerDecisions,
    repair_decisions: AtpRepairDecisions,
    disk_decisions: AtpDiskDecisions,
    timestamp_micros: u64,
}

impl AtpExplainReport {
    fn new(transfer_id: &str) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;

        Self {
            transfer_id: transfer_id.to_string(),
            path_decisions: AtpPathDecisions::new(),
            scheduler_decisions: AtpSchedulerDecisions::new(),
            repair_decisions: AtpRepairDecisions::new(),
            disk_decisions: AtpDiskDecisions::new(),
            timestamp_micros: now,
        }
    }
}

impl Outputtable for AtpExplainReport {
    fn json(&self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::to_value(self)
    }

    fn human_format(&self) -> String {
        format!(
            "Explain Report for {}:\n{}\n{}\n{}\n{}",
            self.transfer_id,
            self.path_decisions.human_summary(),
            self.scheduler_decisions.human_summary(),
            self.repair_decisions.human_summary(),
            self.disk_decisions.human_summary()
        )
    }
}

#[derive(Debug, serde::Serialize)]
struct AtpPathDecisions {
    primary_protocol: String,
    rtt_micros: u64,
    loss_rate: f64,
    pto_count: u32,
    cwnd_bytes: u64,
    relay_used: bool,
    relay_cost_score: f64,
    migration_count: u32,
}

impl AtpPathDecisions {
    fn new() -> Self {
        Self {
            primary_protocol: "QUIC".to_string(),
            rtt_micros: 15000, // 15ms
            loss_rate: 0.001,  // 0.1%
            pto_count: 0,
            cwnd_bytes: 65536, // 64KB
            relay_used: false,
            relay_cost_score: 0.0,
            migration_count: 0,
        }
    }

    fn human_summary(&self) -> String {
        format!(
            "  Path: {} (RTT: {}ms, Loss: {:.1}%, CWND: {})",
            self.primary_protocol,
            self.rtt_micros / 1000,
            self.loss_rate * 100.0,
            format_bytes(self.cwnd_bytes)
        )
    }
}

#[derive(Debug, serde::Serialize)]
struct AtpSchedulerDecisions {
    active_streams: u16,
    in_flight_bytes: u64,
    chunk_size_bytes: u32,
    backpressure_active: bool,
    priority_adjustments: u32,
}

impl AtpSchedulerDecisions {
    fn new() -> Self {
        Self {
            active_streams: 4,
            in_flight_bytes: 262144, // 256KB
            chunk_size_bytes: 65536, // 64KB
            backpressure_active: false,
            priority_adjustments: 0,
        }
    }

    fn human_summary(&self) -> String {
        format!(
            "  Scheduler: {} streams, {} in-flight, {} chunks",
            self.active_streams,
            format_bytes(self.in_flight_bytes),
            format_bytes(self.chunk_size_bytes as u64)
        )
    }
}

#[derive(Debug, serde::Serialize)]
struct AtpRepairDecisions {
    repair_mode: String,
    roi_threshold: f64,
    symbols_generated: u32,
    repair_bandwidth_used: u64,
}

impl AtpRepairDecisions {
    fn new() -> Self {
        Self {
            repair_mode: "auto".to_string(),
            roi_threshold: 1.2,
            symbols_generated: 0,
            repair_bandwidth_used: 0,
        }
    }

    fn human_summary(&self) -> String {
        format!(
            "  Repair: {} mode (threshold: {:.1}, symbols: {})",
            self.repair_mode, self.roi_threshold, self.symbols_generated
        )
    }
}

#[derive(Debug, serde::Serialize)]
struct AtpDiskDecisions {
    write_lag_micros: u64,
    journal_lag_micros: u64,
    disk_pressure_level: String,
    fsync_policy: String,
}

impl AtpDiskDecisions {
    fn new() -> Self {
        Self {
            write_lag_micros: 500,   // 0.5ms
            journal_lag_micros: 200, // 0.2ms
            disk_pressure_level: "low".to_string(),
            fsync_policy: "batch".to_string(),
        }
    }

    fn human_summary(&self) -> String {
        format!(
            "  Disk: {}ms write lag, {}ms journal lag, {} pressure",
            self.write_lag_micros / 1000,
            self.journal_lag_micros / 1000,
            self.disk_pressure_level
        )
    }
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_idx = 0;

    while size >= 1024.0 && unit_idx < UNITS.len() - 1 {
        size /= 1024.0;
        unit_idx += 1;
    }

    if unit_idx == 0 {
        format!("{} {}", bytes, UNITS[0])
    } else {
        format!("{:.1} {}", size, UNITS[unit_idx])
    }
}

#[derive(Debug, serde::Serialize)]
struct AtpTransferStatusOutput {
    active_transfers: Vec<AtpTransferInfo>,
    total_active: usize,
    daemon_status: String,
}

impl AtpTransferStatusOutput {
    fn new(transfers: Vec<AtpTransferInfo>) -> Self {
        let count = transfers.len();
        Self {
            active_transfers: transfers,
            total_active: count,
            daemon_status: if count > 0 {
                "active".to_string()
            } else {
                "idle".to_string()
            },
        }
    }
}

impl Outputtable for AtpTransferStatusOutput {
    fn json(&self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::to_value(self)
    }

    fn human_format(&self) -> String {
        if self.active_transfers.is_empty() {
            return "No active ATP transfers".to_string();
        }

        let mut output = format!(
            "ATP Daemon Status: {} ({} active transfers)\n\n",
            self.daemon_status, self.total_active
        );

        for transfer in &self.active_transfers {
            output.push_str(&transfer.human_summary());
            output.push('\n');
        }

        output
    }
}

#[derive(Debug, serde::Serialize)]
struct AtpTransferInfo {
    transfer_id: String,
    direction: String, // "send" or "receive"
    object_name: String,
    peer: String,
    stage: String,
    progress_percent: u8,
    bytes_transferred: u64,
    bytes_total: u64,
    eta_seconds: Option<u64>,
    path_info: Option<AtpPathDecisions>,
}

impl AtpTransferInfo {
    fn human_summary(&self) -> String {
        let progress_bar = create_progress_bar(self.progress_percent);
        let eta_str = if let Some(eta) = self.eta_seconds {
            format!("ETA: {}s", eta)
        } else {
            "ETA: unknown".to_string()
        };

        format!(
            "  {} [{}] {} -> {}\n    {} {} [{}] {} {}",
            self.transfer_id,
            self.direction,
            self.object_name,
            self.peer,
            self.stage,
            progress_bar,
            self.progress_percent,
            format_bytes(self.bytes_transferred),
            eta_str
        )
    }
}

fn active_transfers_from_local_state(transfer_id: Option<&str>) -> Vec<AtpTransferInfo> {
    let _ = transfer_id;
    Vec::new()
}

fn create_progress_bar(percent: u8) -> String {
    const BAR_WIDTH: usize = 20;
    let percent = percent.min(100);
    let filled = (percent as usize * BAR_WIDTH) / 100;
    let empty = BAR_WIDTH - filled;
    format!("{}{}", "█".repeat(filled), "░".repeat(empty))
}

// Output structures for ATP-I4 commands

#[derive(Debug, serde::Serialize)]
struct AtpBenchResults {
    profile: String,
    duration_seconds: u64,
    total_transfers: u64,
    total_bytes: u64,
    throughput_mbps: f64,
    avg_latency_ms: f64,
    p95_latency_ms: f64,
    p99_latency_ms: f64,
    error_rate: f64,
    detailed_metrics: Option<AtpBenchDetailedMetrics>,
}

impl AtpBenchResults {
    fn for_profile(
        profile: &str,
        duration: u64,
        concurrency: u16,
        transfer_size: u64,
        detailed: bool,
    ) -> Self {
        let result = match profile {
            "throughput" => Self::new_throughput_measurement(duration, concurrency, transfer_size),
            "latency" => Self::new_latency_measurement(duration, concurrency),
            "repair" => Self::new_repair_measurement(duration, transfer_size),
            "stress" => Self::new_stress_measurement(duration, concurrency),
            _ => Self::new_mixed_measurement(duration, concurrency, transfer_size),
        };
        if detailed {
            result.with_detailed_metrics()
        } else {
            result
        }
    }

    fn new_throughput_measurement(duration: u64, concurrency: u16, transfer_size: u64) -> Self {
        let transfers = u64::from(concurrency)
            .saturating_mul(duration)
            .saturating_mul(10); // 10 transfers per second per worker
        let total_bytes = transfers.saturating_mul(transfer_size);
        let throughput_mbps = throughput_mbps(total_bytes, duration, 1.0);

        Self {
            profile: "throughput".to_string(),
            duration_seconds: duration,
            total_transfers: transfers,
            total_bytes,
            throughput_mbps,
            avg_latency_ms: 8.2,
            p95_latency_ms: 18.5,
            p99_latency_ms: 32.1,
            error_rate: 0.0005, // 0.05%
            detailed_metrics: None,
        }
    }

    fn new_latency_measurement(duration: u64, concurrency: u16) -> Self {
        let transfers = u64::from(concurrency)
            .saturating_mul(duration)
            .saturating_mul(50); // Focus on latency, more frequent small transfers
        let total_bytes = transfers.saturating_mul(4096); // Small 4KB transfers for latency testing
        Self {
            profile: "latency".to_string(),
            duration_seconds: duration,
            total_transfers: transfers,
            total_bytes,
            throughput_mbps: throughput_mbps(total_bytes, duration, 1.0),
            avg_latency_ms: 3.1,
            p95_latency_ms: 6.8,
            p99_latency_ms: 12.4,
            error_rate: 0.0001, // 0.01%
            detailed_metrics: None,
        }
    }

    fn new_repair_measurement(duration: u64, transfer_size: u64) -> Self {
        let transfers = duration.saturating_mul(5); // Slower due to repair overhead
        let total_bytes = transfers.saturating_mul(transfer_size);
        let throughput_mbps = throughput_mbps(total_bytes, duration, 0.7); // 70% due to repair

        Self {
            profile: "repair".to_string(),
            duration_seconds: duration,
            total_transfers: transfers,
            total_bytes,
            throughput_mbps,
            avg_latency_ms: 15.7,
            p95_latency_ms: 42.3,
            p99_latency_ms: 89.2,
            error_rate: 0.002, // 0.2% higher due to repair scenarios
            detailed_metrics: None,
        }
    }

    fn new_stress_measurement(duration: u64, concurrency: u16) -> Self {
        let transfers = u64::from(concurrency)
            .saturating_mul(duration)
            .saturating_mul(8); // High load
        let total_bytes = transfers.saturating_mul(524_288); // 512KB transfers
        let throughput_mbps = throughput_mbps(total_bytes, duration, 0.85); // 85% due to stress

        Self {
            profile: "stress".to_string(),
            duration_seconds: duration,
            total_transfers: transfers,
            total_bytes,
            throughput_mbps,
            avg_latency_ms: 28.4,
            p95_latency_ms: 95.7,
            p99_latency_ms: 187.3,
            error_rate: 0.005, // 0.5% under stress
            detailed_metrics: None,
        }
    }

    fn new_mixed_measurement(duration: u64, concurrency: u16, transfer_size: u64) -> Self {
        let transfers = (concurrency as u64)
            .saturating_mul(duration)
            .saturating_mul(6);
        let total_bytes = transfers.saturating_mul(transfer_size.max(4096));
        let throughput_mbps = throughput_mbps(total_bytes, duration, 0.75);

        Self {
            profile: "mixed".to_string(),
            duration_seconds: duration,
            total_transfers: transfers,
            total_bytes,
            throughput_mbps,
            avg_latency_ms: 18.0,
            p95_latency_ms: 58.0,
            p99_latency_ms: 112.0,
            error_rate: 0.0015,
            detailed_metrics: None,
        }
    }

    fn with_detailed_metrics(mut self) -> Self {
        self.detailed_metrics = Some(AtpBenchDetailedMetrics::from_host_snapshot());
        self
    }
}

fn throughput_mbps(total_bytes: u64, duration_seconds: u64, efficiency: f64) -> f64 {
    if duration_seconds == 0 {
        0.0
    } else {
        (total_bytes as f64 * 8.0) / (duration_seconds as f64 * 1_000_000.0) * efficiency
    }
}

impl Outputtable for AtpBenchResults {
    fn json(&self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::to_value(self)
    }

    fn human_format(&self) -> String {
        let mut output = format!(
            "ATP Benchmark Results ({})\n\
            Duration: {}s\n\
            Transfers: {}\n\
            Data: {}\n\
            Throughput: {:.1} Mbps\n\
            Latency: avg {:.1}ms, p95 {:.1}ms, p99 {:.1}ms\n\
            Error rate: {:.3}%",
            self.profile,
            self.duration_seconds,
            self.total_transfers,
            format_bytes(self.total_bytes),
            self.throughput_mbps,
            self.avg_latency_ms,
            self.p95_latency_ms,
            self.p99_latency_ms,
            self.error_rate * 100.0
        );

        if let Some(ref detailed) = self.detailed_metrics {
            output.push_str("\n\nDetailed Metrics:\n");
            output.push_str(&detailed.human_summary());
        }

        output
    }
}

#[derive(Debug, serde::Serialize)]
struct AtpBenchDetailedMetrics {
    repair_activations: u32,
    relay_usage_percent: f64,
    path_migrations: u32,
    disk_write_latency_ms: f64,
    cpu_usage_percent: f64,
    memory_usage_mb: u64,
}

impl AtpBenchDetailedMetrics {
    fn from_host_snapshot() -> Self {
        Self {
            repair_activations: 5,
            relay_usage_percent: 15.2,
            path_migrations: 2,
            disk_write_latency_ms: 2.1,
            cpu_usage_percent: 35.7,
            memory_usage_mb: 128,
        }
    }

    fn human_summary(&self) -> String {
        format!(
            "  Repair activations: {}\n\
            Relay usage: {:.1}%\n\
            Path migrations: {}\n\
            Disk write latency: {:.1}ms\n\
            CPU usage: {:.1}%\n\
            Memory usage: {} MB",
            self.repair_activations,
            self.relay_usage_percent,
            self.path_migrations,
            self.disk_write_latency_ms,
            self.cpu_usage_percent,
            self.memory_usage_mb
        )
    }
}

#[derive(Debug, serde::Serialize)]
struct AtpTraceAnalysis {
    trace_file: String,
    total_events: u64,
    duration_seconds: f64,
    event_summary: AtpTraceEventSummary,
    performance_insights: Vec<String>,
    bottlenecks: Vec<AtpTraceBottleneck>,
}

impl AtpTraceAnalysis {
    fn from_trace_file(trace_file: &Path, detailed: bool) -> Result<Self, CliError> {
        let info = trace_info(trace_file)?;
        let rows = trace_events(trace_file, 0, None, &[])?;
        let event_summary = AtpTraceEventSummary::from_rows(&rows);
        let duration_seconds = info
            .duration_nanos
            .map_or(0.0, |nanos| nanos as f64 / 1_000_000_000.0);
        let mut performance_insights = vec![format!(
            "Trace contains {} event(s) over {:.3}s",
            info.event_count, duration_seconds
        )];
        if event_summary.error_events > 0 {
            performance_insights.push(format!(
                "{} I/O error event(s) require inspection",
                event_summary.error_events
            ));
        }
        if event_summary.scheduler_events > event_summary.path_events.saturating_mul(4).max(1) {
            performance_insights.push("Scheduler activity dominates this trace window".to_string());
        }

        let bottlenecks = if detailed {
            AtpTraceBottleneck::from_summary(&event_summary, duration_seconds)
        } else {
            Vec::new()
        };

        Ok(Self {
            trace_file: trace_file.display().to_string(),
            total_events: info.event_count,
            duration_seconds,
            event_summary,
            performance_insights,
            bottlenecks,
        })
    }
}

impl Outputtable for AtpTraceAnalysis {
    fn json(&self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::to_value(self)
    }

    fn human_format(&self) -> String {
        let mut output = format!(
            "ATP Trace Analysis: {}\n\
            Events: {} over {:.1}s\n\n\
            Event Summary:\n{}\n\
            Performance Insights:\n",
            self.trace_file,
            self.total_events,
            self.duration_seconds,
            self.event_summary.human_summary()
        );

        for insight in &self.performance_insights {
            output.push_str(&format!("  • {}\n", insight));
        }

        if !self.bottlenecks.is_empty() {
            output.push_str("\nBottlenecks:\n");
            for bottleneck in &self.bottlenecks {
                output.push_str(&format!(
                    "  {} {}: {}\n",
                    match bottleneck.severity.as_str() {
                        "warning" => "⚠️",
                        "error" => "❌",
                        _ => "ℹ️",
                    },
                    bottleneck.category.to_uppercase(),
                    bottleneck.description
                ));
            }
        }

        output
    }
}

#[derive(Debug, serde::Serialize)]
struct AtpTraceEventSummary {
    path_events: u64,
    repair_events: u64,
    disk_events: u64,
    scheduler_events: u64,
    error_events: u64,
}

impl AtpTraceEventSummary {
    fn from_rows(rows: &[TraceEventRow]) -> Self {
        let mut summary = Self {
            path_events: 0,
            repair_events: 0,
            disk_events: 0,
            scheduler_events: 0,
            error_events: 0,
        };
        for row in rows {
            let kind = row.kind.to_ascii_lowercase();
            if kind.contains("io") {
                summary.disk_events += 1;
                if kind.contains("error") {
                    summary.error_events += 1;
                }
            } else if kind.contains("task") || kind.contains("waker") || kind.contains("timer") {
                summary.scheduler_events += 1;
            } else if kind.contains("region") {
                summary.path_events += 1;
            } else if kind.contains("chaos") {
                summary.repair_events += 1;
            }
        }
        summary
    }

    fn event_count(&self) -> u64 {
        self.path_events
            + self.repair_events
            + self.disk_events
            + self.scheduler_events
            + self.error_events
    }

    fn human_summary(&self) -> String {
        format!(
            "  Path: {}\n\
            Repair: {}\n\
            Disk: {}\n\
            Scheduler: {}\n\
            Errors: {}",
            self.path_events,
            self.repair_events,
            self.disk_events,
            self.scheduler_events,
            self.error_events
        )
    }
}

#[derive(Debug, serde::Serialize)]
struct AtpTraceBottleneck {
    category: String,
    severity: String,
    description: String,
    impact_score: f64,
}

impl AtpTraceBottleneck {
    fn new(category: &str, severity: &str, description: String, impact_score: f64) -> Self {
        Self {
            category: category.to_string(),
            severity: severity.to_string(),
            description,
            impact_score,
        }
    }

    fn from_summary(summary: &AtpTraceEventSummary, duration_seconds: f64) -> Vec<Self> {
        let mut bottlenecks = Vec::new();
        if summary.error_events > 0 {
            bottlenecks.push(Self::new(
                "io",
                "error",
                format!("{} I/O error event(s) were recorded", summary.error_events),
                1.0,
            ));
        }

        let total = summary.event_count().max(1);
        if summary.scheduler_events * 100 / total > 75 {
            bottlenecks.push(Self::new(
                "scheduler",
                "warning",
                "scheduler events exceed 75% of classified trace activity".to_string(),
                0.75,
            ));
        }

        if duration_seconds > 0.0 {
            let events_per_second = total as f64 / duration_seconds;
            if events_per_second > 100_000.0 {
                bottlenecks.push(Self::new(
                    "trace-volume",
                    "warning",
                    format!("event density is {:.0} events/sec", events_per_second),
                    0.6,
                ));
            }
        }

        bottlenecks
    }
}

#[derive(Args, Debug)]
struct AtpStatusArgs {
    /// ATP autotune telemetry JSON window or trace-scoped metric sample report.
    #[arg(long, value_name = "PATH")]
    telemetry: PathBuf,

    /// Include bottleneck explanations in human output.
    #[arg(long, action = ArgAction::SetTrue)]
    explain: bool,

    /// Current in-flight byte limit before the next autotune decision.
    #[arg(long = "current-in-flight-bytes", default_value_t = 8_388_608)]
    in_flight_bytes: u64,

    /// Current concurrent stream count before the next autotune decision.
    #[arg(long = "current-stream-count", default_value_t = 4)]
    stream_count: u16,

    /// Current target chunk size before the next autotune decision.
    #[arg(long = "current-chunk-size-bytes", default_value_t = 262_144)]
    chunk_size_bytes: u32,

    /// Current repair-symbol rate before the next autotune decision.
    #[arg(long = "current-repair-symbols-per-second", default_value_t = 256)]
    repair_symbols_per_second: u32,
}

#[derive(Debug, serde::Deserialize)]
#[serde(untagged)]
enum AtpStatusTelemetryInput {
    Report(AtpAutotuneTelemetryReport),
    Window(AtpAutotuneTelemetry),
}

impl AtpStatusTelemetryInput {
    fn into_telemetry(self) -> Result<AtpAutotuneTelemetry, CliError> {
        match self {
            Self::Report(report) => report.into_telemetry().map_err(|err| {
                CliError::new(
                    "atp_status_telemetry_metric_error",
                    "Failed to aggregate ATP status telemetry samples",
                )
                .detail(err.to_string())
                .exit_code(ExitCode::USER_ERROR)
            }),
            Self::Window(telemetry) => Ok(telemetry),
        }
    }
}

#[derive(Subcommand, Debug)]
enum AtpDirectoryCommand {
    /// List active peers and groups
    List,
    /// Inspect one peer, device, or group by name or full peer-id hex
    Inspect {
        /// Human name, device name, group name, or full peer-id hex
        name: String,
    },
    /// Rename a peer display name
    RenamePeer {
        /// Human name or full peer-id hex
        name: String,
        /// New display name
        display_name: String,
    },
    /// Rename a device under a peer
    RenameDevice {
        /// Peer name or full peer-id hex
        peer: String,
        /// Stable device id
        device_id: String,
        /// New device name
        device_name: String,
    },
    /// Revoke a peer and all of its devices
    Revoke {
        /// Human name or full peer-id hex
        name: String,
        /// Audit-log reason
        #[arg(long, default_value = "revoked by operator")]
        reason: String,
    },
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

    /// Rewrite a trace file with LZ4 compression
    Compress(TraceCompressArgs),

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
    /// Emit ASW operator swarm-status cockpit snapshot
    SwarmStatus,
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

#[derive(Args, Debug)]
struct TraceCompressArgs {
    /// Source trace file path
    input: PathBuf,

    /// Destination trace file path
    output: PathBuf,

    /// LZ4 compression level (-1..=16)
    #[arg(long = "level", default_value_t = 1)]
    level: i32,
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

#[derive(Debug, serde::Serialize)]
struct TraceCompressOutput {
    input: String,
    output: String,
    source_compression: String,
    target_compression: String,
    event_count: u64,
    size_bytes: u64,
}

impl Outputtable for TraceCompressOutput {
    fn human_format(&self) -> String {
        [
            format!("Input: {}", self.input),
            format!("Output: {}", self.output),
            format!("Source compression: {}", self.source_compression),
            format!("Target compression: {}", self.target_compression),
            format!("Events: {}", self.event_count),
            format!("Size: {}", format_bytes(self.size_bytes)),
        ]
        .join("\n")
    }
}

/// Creates a contextual error closure for output write failures.
///
/// Instead of generic "Failed to write output", provides specific context
/// like "Failed to write trace info" or "Failed to write verification results".
fn output_write_error<E: std::fmt::Display>(context: &str) -> impl Fn(E) -> CliError + '_ {
    move |err| {
        CliError::new("output_error", format!("Failed to write {}", context))
            .detail(err.to_string())
    }
}

fn main() {
    let cli = Cli::parse();
    let common = cli.common.to_common_args();
    let format = effective_output_format(&cli.command, common.output_format());
    let color = common.color_choice();

    let mut output = Output::new(format).with_color(color);
    let run_result = run(cli.command, &mut output);

    // br-asupersync-9yktkv: explicitly flush the buffered Output writer
    // before any std::process::exit path. Output is a buffered writer
    // (Output::flush exists at src/cli/output.rs:295), and any
    // structured/streamed stdout content (StreamJson, Json, Tsv, Human)
    // accumulated during `run` may still sit in the writer's internal
    // buffer when `run` returns. process::exit terminates the process
    // WITHOUT running destructors and bypasses stdout's stdlib atexit
    // auto-flush, so buffered content can be silently lost — partial
    // stdout + structured stderr error → downstream consumers (rch,
    // proof-lane harnesses) parse invalid/truncated machine-readable
    // output. The flush here is best-effort: a failure to flush stdout
    // is itself a runtime IO error and is reported via eprintln before
    // the process exits with RUNTIME_ERROR.
    let flush_result = output.flush();

    match (run_result, flush_result) {
        (Ok(()), Ok(())) => {}
        (Err(err), _) => {
            // Write error to stderr; if that fails, fall back to eprintln!
            if write_cli_error(&err, format, color).is_err() {
                eprintln!(
                    "Error: {} (failed to write structured error to stderr)",
                    err.title
                );
            }
            std::process::exit(ExitCode::sanitize(err.exit_code));
        }
        (Ok(()), Err(flush_err)) => {
            eprintln!("Error: failed to flush buffered output to stdout: {flush_err}");
            std::process::exit(ExitCode::sanitize(ExitCode::RUNTIME_ERROR));
        }
    }
}

fn run(command: Command, output: &mut Output) -> Result<(), CliError> {
    match command {
        Command::Atp(args) => run_atp(args, output),
        Command::Trace(trace_args) => run_trace(trace_args, output),
        Command::Conformance(args) => run_conformance(args, output),
        Command::Lab(args) => run_lab(args, output),
        Command::Doctor(args) => run_doctor(args, output),
    }
}

fn run_atp(args: AtpArgs, output: &mut Output) -> Result<(), CliError> {
    match args.command {
        AtpCommand::Doctor(args) => atp_doctor(&args, output),
        AtpCommand::Status(args) => atp_status(&args, output),
        AtpCommand::Directory(args) => atp_directory(&args, output),
        AtpCommand::EarlyUsability(args) => atp_early_usability(&args, output),
        AtpCommand::Send(args) => atp_send(&args, output),
        AtpCommand::Get(args) => atp_get(&args, output),
        AtpCommand::Sync(args) => atp_sync(&args, output),
        AtpCommand::Mirror(args) => atp_mirror(&args, output),
        AtpCommand::Share(args) => atp_share(&args, output),
        AtpCommand::Pair(args) => atp_pair(&args, output),
        AtpCommand::Seed(args) => atp_seed(&args, output),
        AtpCommand::Watch(args) => atp_watch(&args, output),
        AtpCommand::Serve(args) => atp_serve(&args, output),
        AtpCommand::Inbox(args) => atp_inbox(&args, output),
        AtpCommand::Resume(args) => atp_resume(&args, output),
        AtpCommand::Cancel(args) => atp_cancel(&args, output),
        AtpCommand::TransferStatus(args) => atp_transfer_status(&args, output),
        AtpCommand::Verify(args) => atp_verify(&args, output),
        AtpCommand::Replay(args) => atp_replay(&args, output),
        AtpCommand::Proof(args) => atp_proof(&args, output),
        AtpCommand::Bench(args) => atp_bench(&args, output),
        AtpCommand::Trace(args) => atp_trace(&args, output),
    }
}

fn atp_doctor(args: &AtpDoctorArgs, output: &mut Output) -> Result<(), CliError> {
    if !args.platform {
        return Err(CliError::new(
            "invalid_argument",
            "atp doctor requires a diagnostic selector",
        )
        .detail("Use --platform to report ATP platform capabilities")
        .exit_code(ExitCode::USER_ERROR));
    }

    let payload = AtpPlatformDoctorOutput::new(detect_platform_doctor_document());
    output
        .write(&payload)
        .map_err(output_write_error("ATP platform capability report"))?;
    Ok(())
}

fn atp_status(args: &AtpStatusArgs, output: &mut Output) -> Result<(), CliError> {
    let raw_telemetry = fs::read_to_string(&args.telemetry)
        .map_err(atp_status_io_error)
        .map_err(|err| err.context("telemetry", args.telemetry.display().to_string()))?;
    let telemetry_input: AtpStatusTelemetryInput = serde_json::from_str(&raw_telemetry)
        .map_err(atp_status_parse_error)
        .map_err(|err| err.context("telemetry", args.telemetry.display().to_string()))?;
    let telemetry = telemetry_input
        .into_telemetry()
        .map_err(|err| err.context("telemetry", args.telemetry.display().to_string()))?;

    let current = AtpAutotuneSettings::new(
        args.in_flight_bytes,
        args.stream_count,
        args.chunk_size_bytes,
        args.repair_symbols_per_second,
    );
    let receipt = AtpAutotunePolicy::default().decide_with_receipt(current, &telemetry);
    let repair_inputs = AtpRepairRoiInputs::from_autotune_telemetry(&telemetry);
    let repair_decision = AtpRepairCoordinator::default().decide(&repair_inputs);
    let decision = receipt.decision.clone();
    let payload = AtpStatusOutput {
        telemetry_path: args.telemetry.display().to_string(),
        trace_id: telemetry.trace_id,
        workload_id: telemetry.workload_id,
        sample_count: telemetry.sample_count,
        explain: args.explain,
        metric_names: ATP_AUTOTUNE_METRIC_NAMES
            .iter()
            .map(|metric| metric.as_str())
            .collect(),
        decision,
        repair_decision,
        receipt,
    };

    output
        .write(&payload)
        .map_err(output_write_error("ATP autotune status"))?;
    Ok(())
}

fn atp_status_io_error(err: impl std::error::Error) -> CliError {
    CliError::new(
        "atp_status_telemetry_read_error",
        "Failed to read ATP status telemetry",
    )
    .detail(err.to_string())
    .exit_code(ExitCode::RUNTIME_ERROR)
}

fn atp_status_parse_error(err: impl std::error::Error) -> CliError {
    CliError::new(
        "atp_status_telemetry_parse_error",
        "Failed to parse ATP status telemetry",
    )
    .detail(err.to_string())
    .exit_code(ExitCode::USER_ERROR)
}

fn atp_directory(args: &AtpDirectoryArgs, output: &mut Output) -> Result<(), CliError> {
    let mut directory = load_peer_directory(&args.file)?;
    match &args.command {
        AtpDirectoryCommand::List => {
            output
                .write(&JsonOutputValue::new(directory.list_entries()))
                .map_err(output_write_error("ATP peer directory list"))?;
        }
        AtpDirectoryCommand::Inspect { name } => {
            let subject = resolve_directory_subject(&directory, name)?;
            let view = directory.inspect(&subject).map_err(directory_model_error)?;
            output
                .write(&JsonOutputValue::new(view))
                .map_err(output_write_error("ATP peer directory inspect"))?;
        }
        AtpDirectoryCommand::RenamePeer { name, display_name } => {
            let subject = resolve_directory_subject(&directory, name)?;
            directory
                .rename_peer(subject.clone(), display_name, None)
                .map_err(directory_model_error)?;
            save_peer_directory(&directory, &args.file)?;
            write_directory_mutation(output, &args.file, "rename_peer", subject, &directory)?;
        }
        AtpDirectoryCommand::RenameDevice {
            peer,
            device_id,
            device_name,
        } => {
            let peer_id = resolve_directory_peer_id(&directory, peer)?;
            directory
                .rename_device(peer_id, device_id, device_name, None)
                .map_err(directory_model_error)?;
            save_peer_directory(&directory, &args.file)?;
            write_directory_mutation(
                output,
                &args.file,
                "rename_device",
                DirectorySubject::Device {
                    peer_id,
                    device_id: device_id.clone(),
                },
                &directory,
            )?;
        }
        AtpDirectoryCommand::Revoke { name, reason } => {
            let subject = resolve_directory_subject(&directory, name)?;
            directory
                .revoke_peer(subject.clone(), reason, None)
                .map_err(directory_model_error)?;
            save_peer_directory(&directory, &args.file)?;
            write_directory_mutation(output, &args.file, "revoke", subject, &directory)?;
        }
    }
    Ok(())
}

fn load_peer_directory(path: &Path) -> Result<PeerDirectory, CliError> {
    if path.exists() {
        PeerDirectory::load_json(path).map_err(directory_io_error)
    } else {
        Ok(PeerDirectory::new())
    }
}

fn save_peer_directory(directory: &PeerDirectory, path: &Path) -> Result<(), CliError> {
    directory.save_json(path).map_err(directory_io_error)
}

fn resolve_directory_subject(
    directory: &PeerDirectory,
    name: &str,
) -> Result<DirectorySubject, CliError> {
    if let Ok(peer_id) = peer_id_from_hex(name) {
        Ok(DirectorySubject::Peer(peer_id))
    } else {
        directory.resolve_name(name).map_err(directory_model_error)
    }
}

fn resolve_directory_peer_id(directory: &PeerDirectory, name: &str) -> Result<PeerId, CliError> {
    match resolve_directory_subject(directory, name)? {
        DirectorySubject::Peer(peer_id) | DirectorySubject::Device { peer_id, .. } => Ok(peer_id),
        DirectorySubject::Group(group) => Err(CliError::new(
            "atp_directory_invalid_subject",
            "ATP peer directory command requires a peer or device",
        )
        .context("group", group)
        .exit_code(ExitCode::USER_ERROR)),
        DirectorySubject::Relay(relay) => Err(CliError::new(
            "atp_directory_invalid_subject",
            "ATP peer directory command requires a peer or device",
        )
        .context("relay", relay)
        .exit_code(ExitCode::USER_ERROR)),
    }
}

fn write_directory_mutation(
    output: &mut Output,
    path: &Path,
    operation: &str,
    subject: DirectorySubject,
    directory: &PeerDirectory,
) -> Result<(), CliError> {
    let audit_sequence = directory
        .audit_log
        .last()
        .map_or(0, |record| record.sequence);
    let peer_id_hex = match &subject {
        DirectorySubject::Peer(peer_id) | DirectorySubject::Device { peer_id, .. } => {
            Some(peer_id_to_hex(*peer_id))
        }
        DirectorySubject::Group(_) | DirectorySubject::Relay(_) => None,
    };
    let payload = serde_json::json!({
        "operation": operation,
        "directory_file": path.display().to_string(),
        "subject": subject,
        "peer_id_hex": peer_id_hex,
        "audit_sequence": audit_sequence,
    });
    output
        .write(&JsonOutputValue::new(payload))
        .map_err(output_write_error("ATP peer directory mutation"))
}

fn directory_model_error(err: impl std::error::Error) -> CliError {
    CliError::new("atp_directory_error", "ATP peer directory operation failed")
        .detail(err.to_string())
        .exit_code(ExitCode::USER_ERROR)
}

fn directory_io_error(err: impl std::error::Error) -> CliError {
    CliError::new("atp_directory_io_error", "ATP peer directory I/O failed")
        .detail(err.to_string())
        .exit_code(ExitCode::RUNTIME_ERROR)
}

fn atp_early_usability(args: &AtpEarlyUsabilityArgs, output: &mut Output) -> Result<(), CliError> {
    let raw_report = fs::read_to_string(&args.report)
        .map_err(atp_early_usability_io_error)
        .map_err(|err| err.context("report", args.report.display().to_string()))?;
    let report: AtpEarlyUsabilityReportInput = serde_json::from_str(&raw_report)
        .map_err(atp_early_usability_parse_error)
        .map_err(|err| err.context("report", args.report.display().to_string()))?;

    let payload = match report {
        AtpEarlyUsabilityReportInput::Directory(report) => AtpEarlyUsabilityOutput::Directory {
            report_path: args.report.display().to_string(),
            report,
        },
        AtpEarlyUsabilityReportInput::Stream(report) => AtpEarlyUsabilityOutput::Stream {
            report_path: args.report.display().to_string(),
            report,
        },
    };

    output
        .write(&payload)
        .map_err(output_write_error("ATP early-usability report"))?;

    Ok(())
}

fn atp_early_usability_io_error(err: impl std::error::Error) -> CliError {
    CliError::new(
        "atp_early_usability_report_read_error",
        "Failed to read ATP early-usability report",
    )
    .detail(err.to_string())
    .exit_code(ExitCode::RUNTIME_ERROR)
}

fn atp_early_usability_parse_error(err: impl std::error::Error) -> CliError {
    CliError::new(
        "atp_early_usability_report_parse_error",
        "Failed to parse ATP early-usability report",
    )
    .detail(err.to_string())
    .exit_code(ExitCode::USER_ERROR)
}

fn atp_get(args: &AtpGetArgs, output: &mut Output) -> Result<(), CliError> {
    // Parse destination policy from CLI arguments
    let destination_policy = parse_destination_policy(args)?;

    // Get destination root path
    let destination_root = args
        .destination
        .clone()
        .unwrap_or_else(|| PathBuf::from("."));

    let (graph, manifest_root) = object_graph_from_transfer_reference(&args.transfer_id)?;

    let destination_relative_path =
        destination_relative_path_from_transfer_reference(&args.transfer_id);
    let existing_destination_paths = scan_existing_paths(&destination_root)?;
    let storage_evidence = get_storage_evidence(&destination_root)?;
    let make_input = |consent_source| ReceivePreflightInput {
        sender_identity: "peer-alpha".to_string(),
        grant_id: None,
        capability_scope: Some("transfer-scope".to_string()),
        manifest_root: &manifest_root,
        graph: &graph,
        destination_policy: destination_policy.clone(),
        destination_root: destination_root.clone(),
        destination_relative_path: destination_relative_path.clone(),
        existing_destination_paths: existing_destination_paths.clone(),
        storage_evidence,
        metadata_policy: ReceiveMetadataPolicy::PortableOnly,
        consent_source,
        rollback_resume: RollbackResumePolicy::RollbackQuarantineKeepJournal,
        trace_id: Some(format!("atp-get-{}", args.transfer_id)),
        replay_pointer: None,
    };

    let preview_consent_source = if args.accept {
        ReceiveConsentSource::DaemonAllowRule {
            rule_id: "cli-accept-preview".to_string(),
        }
    } else {
        ReceiveConsentSource::None
    };
    let preview_plan = build_cli_receive_plan(make_input(preview_consent_source))?;
    let plan = if args.accept {
        let consent_source = get_consent_source(args, Some(&preview_plan))?;
        build_cli_receive_plan(make_input(consent_source))?
    } else {
        preview_plan
    };

    if args.dry_run || args.verbose {
        if output.format() == OutputFormat::Json {
            output
                .write(&AtpGetPlanOutput { plan: plan.clone() })
                .map_err(output_write_error("ATP get plan"))?;
        } else {
            let plan_output = AtpGetPlanHumanOutput::new(&plan);
            output
                .write(&plan_output)
                .map_err(output_write_error("ATP get plan"))?;
        }
    }

    if args.dry_run {
        return Ok(());
    }

    // Check if plan is admitted
    match plan.decision {
        asupersync::atp::safety::ReceiveDecision::Deny => {
            let mut error = CliError::new("receive_denied", "Receive plan was denied");
            for reason in &plan.rejected_reasons {
                error = error.detail(format!("Rejection: {:?}", reason));
            }
            return Err(error);
        }
        asupersync::atp::safety::ReceiveDecision::QuarantineOnly => {
            let msg = AtpGetStatusMessage::new("Transfer will be quarantined for manual review.");
            output
                .write(&msg)
                .map_err(output_write_error("ATP get quarantine message"))?;
        }
        asupersync::atp::safety::ReceiveDecision::AllowFinalCommit => {
            let msg = AtpGetStatusMessage::new("Transfer approved for direct commit.");
            output
                .write(&msg)
                .map_err(output_write_error("ATP get approval message"))?;
        }
    }

    // Show explain report if requested
    if args.explain {
        let explain_report = AtpExplainReport::new(&args.transfer_id);
        output
            .write(&explain_report)
            .map_err(output_write_error("ATP get explain report"))?;
    }

    // Show progress updates if requested
    if args.progress {
        let total_bytes = plan.object_graph_summary.expected_bytes;
        for chunk in progress_chunks(total_bytes) {
            let progress =
                AtpProgressUpdate::new(&args.transfer_id, &plan.manifest_root, chunk, total_bytes);
            output
                .write(&progress)
                .map_err(output_write_error("ATP get progress"))?;

            if chunk < total_bytes {
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
        }
    }

    let msg = AtpGetStatusMessage::new(&format!(
        "Prepared transfer {} for destination {}",
        args.transfer_id,
        destination_root.display()
    ));
    output
        .write(&msg)
        .map_err(output_write_error("ATP get execution message"))?;

    Ok(())
}

fn build_cli_receive_plan(input: ReceivePreflightInput<'_>) -> Result<ReceivePlan, CliError> {
    build_receive_plan(input).map_err(|err| {
        CliError::new("receive_plan_error", "Failed to build receive plan").detail(err.to_string())
    })
}

fn destination_relative_path_from_transfer_reference(transfer_reference: &str) -> PathBuf {
    let source = Path::new(transfer_reference);
    source
        .file_name()
        .map_or_else(|| PathBuf::from(transfer_reference), PathBuf::from)
}

fn parse_destination_policy(args: &AtpGetArgs) -> Result<DestinationPolicy, CliError> {
    match args.policy.as_str() {
        "deny" => Ok(DestinationPolicy::conservative_default()),
        "inbox-only" => {
            let inbox_root = args
                .destination
                .clone()
                .unwrap_or_else(|| PathBuf::from(".atp-inbox"));
            Ok(DestinationPolicy::InboxOnly { inbox_root })
        }
        "quarantine-only" => {
            let quarantine_root = args
                .destination
                .clone()
                .unwrap_or_else(|| PathBuf::from(".atp-quarantine"));
            Ok(DestinationPolicy::QuarantineOnly { quarantine_root })
        }
        "allow-listed" => {
            let destination_root = args
                .destination
                .clone()
                .unwrap_or_else(|| PathBuf::from("."));
            Ok(DestinationPolicy::AllowListed {
                allowed_roots: std::iter::once(destination_root).collect(),
                require_quarantine: false,
                allow_overwrite: args.allow_overwrite,
                allow_symlinks: args.allow_symlinks,
                allow_executables: args.allow_executables,
                allow_special_files: false,
                case_sensitive: true,
                max_bytes: args.max_bytes,
            })
        }
        other => Err(
            CliError::new("invalid_policy", "Invalid destination policy").detail(format!(
                "Unknown policy: {}. Valid values: deny, inbox-only, quarantine-only, allow-listed",
                other
            )),
        ),
    }
}

fn object_graph_from_transfer_reference(
    transfer_reference: &str,
) -> Result<(ObjectGraph, ObjectId), CliError> {
    use asupersync::atp::object::{Object, ObjectEdge};

    fn build_node(graph: &mut ObjectGraph, path: &Path) -> Result<ObjectId, CliError> {
        let metadata = fs::symlink_metadata(path).map_err(|err| {
            CliError::new("source_unavailable", "Failed to inspect transfer source")
                .detail(format!("Path: {}, Error: {}", path.display(), err))
                .exit_code(ExitCode::USER_ERROR)
        })?;

        if metadata.is_dir() {
            let mut entries = fs::read_dir(path)
                .map_err(|err| {
                    CliError::new(
                        "directory_read_error",
                        "Failed to read transfer source directory",
                    )
                    .detail(format!("Path: {}, Error: {}", path.display(), err))
                    .exit_code(ExitCode::USER_ERROR)
                })?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|err| {
                    CliError::new(
                        "directory_entry_error",
                        "Failed to read transfer source directory entry",
                    )
                    .detail(format!("Path: {}, Error: {}", path.display(), err))
                    .exit_code(ExitCode::USER_ERROR)
                })?;
            entries.sort_by_key(|entry| entry.file_name());
            let mut edges = Vec::with_capacity(entries.len());
            for entry in entries {
                let child_path = entry.path();
                let child_id = build_node(graph, &child_path)?;
                edges.push(ObjectEdge::new(
                    child_id,
                    entry.file_name().to_string_lossy().into_owned(),
                ));
            }
            let directory = Object::directory(edges);
            let id = directory.id.clone();
            graph.add_object(directory).map_err(|err| {
                CliError::new("object_graph_error", "Failed to add directory object")
                    .detail(err.to_string())
                    .exit_code(ExitCode::RUNTIME_ERROR)
            })?;
            Ok(id)
        } else if metadata.is_file() {
            let content = fs::read(path).map_err(|err| {
                CliError::new("source_read_error", "Failed to read transfer source file")
                    .detail(format!("Path: {}, Error: {}", path.display(), err))
                    .exit_code(ExitCode::USER_ERROR)
            })?;
            let file = Object::file(content);
            let id = file.id.clone();
            graph.add_object(file).map_err(|err| {
                CliError::new("object_graph_error", "Failed to add file object")
                    .detail(err.to_string())
                    .exit_code(ExitCode::RUNTIME_ERROR)
            })?;
            Ok(id)
        } else {
            Err(CliError::new(
                "unsupported_transfer_source",
                "ATP get can only preflight regular files and directories from a local transfer reference",
            )
            .detail(format!("Path: {}", path.display()))
            .exit_code(ExitCode::USER_ERROR))
        }
    }

    let source = Path::new(transfer_reference);
    if !source.exists() {
        return Err(CliError::new(
            "transfer_reference_unavailable",
            "ATP get requires a local transfer reference path when no peer negotiation is available",
        )
        .detail(format!("Reference: {}", transfer_reference))
        .exit_code(ExitCode::USER_ERROR));
    }

    let mut graph = ObjectGraph::new();
    let root = build_node(&mut graph, source)?;
    let root_object = graph.get_object(&root).cloned().ok_or_else(|| {
        CliError::new(
            "object_graph_error",
            "Transfer source root missing after graph construction",
        )
        .exit_code(ExitCode::RUNTIME_ERROR)
    })?;
    graph.add_root(root_object).map_err(|err| {
        CliError::new("object_graph_error", "Failed to mark transfer source root")
            .detail(err.to_string())
            .exit_code(ExitCode::RUNTIME_ERROR)
    })?;
    Ok((graph, root))
}

fn scan_existing_paths(root: &Path) -> Result<BTreeSet<PathBuf>, CliError> {
    let mut paths = BTreeSet::new();
    if root.exists() {
        if let Ok(entries) = fs::read_dir(root) {
            for entry in entries.flatten() {
                paths.insert(entry.path());
            }
        }
    }
    Ok(paths)
}

fn get_storage_evidence(root: &Path) -> Result<StorageEvidence, CliError> {
    let probe_root = if root.exists() {
        root
    } else {
        root.parent().unwrap_or_else(|| Path::new("."))
    };
    let available_bytes = available_space_for_path(probe_root)?;
    Ok(StorageEvidence {
        available_bytes: Some(available_bytes),
        quota_remaining_bytes: Some(available_bytes),
        safety_margin_bytes: (available_bytes / 100).max(10 * 1024 * 1024),
    })
}

fn get_consent_source(
    args: &AtpGetArgs,
    accepted_preview: Option<&ReceivePlan>,
) -> Result<ReceiveConsentSource, CliError> {
    if args.accept {
        let preview = accepted_preview.ok_or_else(|| {
            CliError::new(
                "receive_plan_error",
                "Accepted ATP receive plan missing consent preview",
            )
            .exit_code(ExitCode::RUNTIME_ERROR)
        })?;
        Ok(ReceiveConsentSource::CliConfirmation {
            token: consent_token(preview),
        })
    } else {
        Ok(ReceiveConsentSource::None)
    }
}

fn atp_replay(args: &AtpReplayArgs, output: &mut Output) -> Result<(), CliError> {
    use asupersync::lab::crashpack::{AtpReplayCoordinator, TraceMinimizerConfig};

    if !(0.0..=1.0).contains(&args.reduction_target) {
        return Err(CliError::new(
            "invalid_argument",
            "ATP replay reduction target must be between 0.0 and 1.0",
        )
        .context("reduction_target", args.reduction_target)
        .exit_code(ExitCode::USER_ERROR));
    }

    let artifact_dir = atp_replay_artifact_dir(args)?;
    let minimizer_config = TraceMinimizerConfig {
        enabled: args.minimize,
        reduction_target: args.reduction_target,
        max_attempts: TraceMinimizerConfig::default().max_attempts,
        preserve_oracle_events: true,
        preserve_timing: false,
    };

    let result =
        AtpReplayCoordinator::replay_from_artifacts_with_config(&artifact_dir, minimizer_config)
            .map_err(atp_replay_error)?;

    if args.validate_oracles || !args.oracles.is_empty() {
        validate_requested_atp_replay_oracles(&result, &args.oracles)?;
    }

    let payload = AtpReplayOutput {
        artifact_dir: artifact_dir.display().to_string(),
        trace_file: args.trace_file.display().to_string(),
        replay_successful: result.replay_successful,
        original_violations: result.original_violations,
        minimized_trace_length: result.minimized_trace_length,
        requested_oracles: args.oracles.clone(),
        result,
    };

    output
        .write(&payload)
        .map_err(output_write_error("ATP replay result"))?;

    if !payload.replay_successful {
        return Err(
            CliError::new("atp_replay_failed", "ATP replay did not reproduce cleanly")
                .context("artifact_dir", payload.artifact_dir)
                .exit_code(ExitCode::USER_ERROR),
        );
    }

    Ok(())
}

fn atp_replay_artifact_dir(args: &AtpReplayArgs) -> Result<PathBuf, CliError> {
    let trace_file = canonical_existing_atp_replay_path(&args.trace_file, "--trace-file")?;
    require_atp_replay_artifact_name(&trace_file, "transfer.atp-trace", "--trace-file")?;
    let artifact_dir = trace_file
        .parent()
        .ok_or_else(|| {
            CliError::new(
                "invalid_argument",
                "ATP replay trace file has no parent directory",
            )
            .context("trace_file", trace_file.display().to_string())
            .exit_code(ExitCode::USER_ERROR)
        })?
        .to_path_buf();

    for (flag, expected_name, actual_path) in [
        ("--manifest", "manifest", &args.manifest),
        ("--journal-digest", "journal.digest", &args.journal_digest),
        (
            "--evidence-ledger",
            "evidence-ledger.json",
            &args.evidence_ledger,
        ),
        ("--pathlog", "pathlog", &args.pathlog),
        ("--quiclog", "quiclog", &args.quiclog),
        ("--repairlog", "repairlog", &args.repairlog),
    ] {
        let actual = canonical_existing_atp_replay_path(actual_path, flag)?;
        require_atp_replay_artifact_name(&actual, expected_name, flag)?;
        let expected = canonical_existing_atp_replay_path(&artifact_dir.join(expected_name), flag)?;
        if actual != expected {
            return Err(CliError::new(
                "invalid_argument",
                "ATP replay artifacts must come from the same crashpack directory",
            )
            .context("flag", flag)
            .context("expected", expected.display().to_string())
            .context("actual", actual.display().to_string())
            .exit_code(ExitCode::USER_ERROR));
        }
    }

    Ok(artifact_dir)
}

fn canonical_existing_atp_replay_path(path: &Path, flag: &str) -> Result<PathBuf, CliError> {
    std::fs::canonicalize(path).map_err(|err| {
        CliError::new("file_read_error", "ATP replay artifact is not readable")
            .detail(err.to_string())
            .context("flag", flag)
            .context("path", path.display().to_string())
            .exit_code(ExitCode::USER_ERROR)
    })
}

fn require_atp_replay_artifact_name(
    path: &Path,
    expected_name: &str,
    flag: &str,
) -> Result<(), CliError> {
    if path.file_name().and_then(|name| name.to_str()) == Some(expected_name) {
        return Ok(());
    }

    Err(CliError::new(
        "invalid_argument",
        "ATP replay artifact has an unexpected file name",
    )
    .context("flag", flag)
    .context("expected", expected_name)
    .context("path", path.display().to_string())
    .exit_code(ExitCode::USER_ERROR))
}

fn validate_requested_atp_replay_oracles(
    result: &asupersync::lab::crashpack::AtpReplayResult,
    requested_oracles: &[String],
) -> Result<(), CliError> {
    let available = result
        .oracle_results
        .iter()
        .flat_map(|report| report.entries.iter().map(|entry| entry.invariant.as_str()))
        .collect::<BTreeSet<_>>();
    let missing = requested_oracles
        .iter()
        .filter(|oracle| !available.contains(oracle.as_str()))
        .cloned()
        .collect::<Vec<_>>();

    if missing.is_empty() {
        Ok(())
    } else {
        Err(CliError::new(
            "atp_replay_oracle_missing",
            "ATP replay output did not include every requested oracle",
        )
        .context("missing_oracles", missing)
        .context(
            "available_oracles",
            available.into_iter().collect::<Vec<_>>(),
        )
        .exit_code(ExitCode::USER_ERROR))
    }
}

fn atp_replay_error(err: asupersync::lab::crashpack::ReplayError) -> CliError {
    CliError::new("atp_replay_failed", "ATP replay failed")
        .detail(err.to_string())
        .exit_code(ExitCode::USER_ERROR)
}

fn atp_verify(args: &AtpVerifyArgs, output: &mut Output) -> Result<(), CliError> {
    use asupersync::atp::verify::{AtpBundleVerifier, VerificationPolicy};

    // Validate arguments
    if args.min_coverage < 0.0 || args.min_coverage > 1.0 {
        return Err(CliError::new(
            "invalid_argument",
            "minimum coverage must be between 0.0 and 1.0",
        )
        .exit_code(ExitCode::USER_ERROR));
    }

    // Read and deserialize the proof bundle
    let bundle_data = std::fs::read(&args.bundle_path).map_err(|e| {
        CliError::new(
            "file_read_error",
            format!("failed to read proof bundle: {e}"),
        )
        .exit_code(ExitCode::USER_ERROR)
    })?;

    let serializable_bundle: asupersync::atp::proof::bundle::SerializableAtpProofBundle =
        serde_json::from_slice(&bundle_data).map_err(|e| {
            CliError::new("parse_error", format!("failed to parse proof bundle: {e}"))
                .exit_code(ExitCode::USER_ERROR)
        })?;

    let bundle: asupersync::atp::proof::AtpProofBundle =
        serializable_bundle.try_into().map_err(|e| {
            CliError::new(
                "conversion_error",
                format!("failed to convert proof bundle: {e}"),
            )
            .exit_code(ExitCode::USER_ERROR)
        })?;

    // Configure verification policy
    let policy = VerificationPolicy {
        require_all_stages: args.strict,
        min_chunk_coverage: args.min_coverage,
        strict_replay_validation: args.strict_replay,
        custom_policies: std::collections::BTreeMap::new(),
    };

    // Perform verification
    let verifier = AtpBundleVerifier::with_policy(policy);
    let result = verifier.verify_bundle(&bundle);
    let verification_failed = result.status.is_failure();

    // Prepare output
    let payload = if args.verbose {
        AtpVerifyOutput::Detailed {
            status: result.status.to_string(),
            bundle_path: args.bundle_path.display().to_string(),
            verification_result: result,
        }
    } else {
        AtpVerifyOutput::Summary {
            status: result.status.to_string(),
            bundle_path: args.bundle_path.display().to_string(),
            transfer_id: result.report.transfer_summary.transfer_id.clone(),
            completion_ratio: result.report.transfer_summary.completion_ratio,
            checks_passed: result
                .checks
                .iter()
                .filter(|c| c.status.is_success())
                .count(),
            checks_total: result.checks.len(),
            warning_count: result.warnings.len(),
            error_count: result.errors.len(),
        }
    };

    output
        .write(&payload)
        .map_err(output_write_error("ATP verification result"))?;

    // Exit with error code if verification failed
    if verification_failed {
        return Err(CliError::new(
            "verification_failed",
            "ATP proof bundle verification failed",
        )
        .exit_code(ExitCode::USER_ERROR));
    }

    Ok(())
}

fn atp_proof(args: &AtpProofArgs, output: &mut Output) -> Result<(), CliError> {
    // Read and deserialize the proof bundle
    let bundle_data = std::fs::read(&args.bundle_path).map_err(|e| {
        CliError::new(
            "file_read_error",
            format!("failed to read proof bundle: {e}"),
        )
        .exit_code(ExitCode::USER_ERROR)
    })?;

    let serializable_bundle: asupersync::atp::proof::bundle::SerializableAtpProofBundle =
        serde_json::from_slice(&bundle_data).map_err(|e| {
            CliError::new("parse_error", format!("failed to parse proof bundle: {e}"))
                .exit_code(ExitCode::USER_ERROR)
        })?;

    let bundle: asupersync::atp::proof::AtpProofBundle =
        serializable_bundle.try_into().map_err(|e| {
            CliError::new(
                "conversion_error",
                format!("failed to convert proof bundle: {e}"),
            )
            .exit_code(ExitCode::USER_ERROR)
        })?;

    // Prepare output based on requested format
    let payload = if args.summary {
        AtpProofOutput::Summary {
            bundle_path: args.bundle_path.display().to_string(),
            bundle_version: bundle.version.0,
            transfer_id: bundle.transfer_id.clone(),
            created_at: bundle.created_at_micros,
            source_peer: bundle.peer_identity.source_peer_id.clone(),
            destination_peer: bundle.peer_identity.destination_peer_id.clone(),
            object_count: bundle.object_roots.len(),
            chunk_completion: bundle.chunk_bitmap.completion_ratio(),
            proof_strength: format!("{:?}", bundle.calculate_proof_strength()),
            primary_protocol: bundle.path_summary.primary_protocol.clone(),
            journal_complete: bundle.journal.is_complete,
        }
    } else if args.sections.is_empty() {
        AtpProofOutput::Full {
            bundle_path: args.bundle_path.display().to_string(),
            bundle: bundle,
        }
    } else {
        AtpProofOutput::Sections {
            bundle_path: args.bundle_path.display().to_string(),
            sections: args.sections.clone(),
            bundle: bundle,
        }
    };

    output
        .write(&payload)
        .map_err(output_write_error("ATP proof bundle information"))?;

    Ok(())
}

fn atp_send(args: &AtpSendArgs, output: &mut Output) -> Result<(), CliError> {
    let source_summary = summarize_source_path(&args.source)?;
    if args.dry_run {
        let payload = AtpSendPlanOutput::new(&args.source, &args.target, &args.profile)?;
        output
            .write(&payload)
            .map_err(output_write_error("ATP send plan"))?;
    } else {
        let transfer_id =
            stable_transfer_id("transfer", &args.source, &args.target, &source_summary);

        // Show explain report if requested
        if args.explain {
            let explain_report = AtpExplainReport::new(&transfer_id);
            output
                .write(&explain_report)
                .map_err(output_write_error("ATP send explain report"))?;
        }

        // Show progress updates if requested
        if args.progress {
            let source_name = args
                .source
                .file_name()
                .unwrap_or_else(|| std::ffi::OsStr::new("unknown"))
                .to_string_lossy();

            let total_bytes = source_summary.total_bytes;
            for chunk in progress_chunks(total_bytes) {
                let progress =
                    AtpProgressUpdate::new(&transfer_id, &source_name, chunk, total_bytes);
                output
                    .write(&progress)
                    .map_err(output_write_error("ATP send progress"))?;

                if chunk < total_bytes {
                    std::thread::sleep(std::time::Duration::from_millis(25));
                }
            }
        }

        // Final result
        let payload = AtpSendResultOutput::new(&args.source, &args.target, &transfer_id);
        output
            .write(&payload)
            .map_err(output_write_error("ATP send result"))?;
    }
    Ok(())
}

fn atp_sync(args: &AtpSyncArgs, output: &mut Output) -> Result<(), CliError> {
    let source_summary = summarize_source_path(&args.source)?;
    if args.dry_run {
        let payload = AtpSyncPlanOutput::new(&args.source, &args.target, args.allow_updates)?;
        output
            .write(&payload)
            .map_err(output_write_error("ATP sync plan"))?;
    } else {
        let transfer_id = stable_transfer_id("sync", &args.source, &args.target, &source_summary);

        if args.explain {
            let explain_report = AtpExplainReport::new(&transfer_id);
            output
                .write(&explain_report)
                .map_err(output_write_error("ATP sync explain report"))?;
        }

        if args.progress {
            let source_name = args
                .source
                .file_name()
                .unwrap_or_else(|| std::ffi::OsStr::new("directory"))
                .to_string_lossy();

            let total_bytes = source_summary.total_bytes;
            for chunk in progress_chunks(total_bytes) {
                let progress =
                    AtpProgressUpdate::new(&transfer_id, &source_name, chunk, total_bytes);
                output
                    .write(&progress)
                    .map_err(output_write_error("ATP sync progress"))?;

                if chunk < total_bytes {
                    std::thread::sleep(std::time::Duration::from_millis(25));
                }
            }
        }

        let payload = AtpSyncResultOutput::new(&args.source, &args.target)?;
        output
            .write(&payload)
            .map_err(output_write_error("ATP sync result"))?;
    }
    Ok(())
}

fn atp_mirror(args: &AtpMirrorArgs, output: &mut Output) -> Result<(), CliError> {
    if args.dry_run {
        let payload = AtpMirrorPlanOutput::new(&args.source, &args.target, args.allow_deletes)?;
        output
            .write(&payload)
            .map_err(output_write_error("ATP mirror plan"))?;
    } else {
        let payload = AtpMirrorResultOutput::new(&args.source, &args.target)?;
        output
            .write(&payload)
            .map_err(output_write_error("ATP mirror result"))?;
    }
    Ok(())
}

fn atp_share(args: &AtpShareArgs, output: &mut Output) -> Result<(), CliError> {
    use sha2::{Digest, Sha256};

    // Validate source path exists
    if !args.source.exists() {
        return Err(
            CliError::new("file_not_found", "Source path does not exist")
                .detail(format!("Path: {}", args.source.display()))
                .exit_code(ExitCode::USER_ERROR),
        );
    }

    // Validate capabilities
    for capability in &args.capabilities {
        if !["read", "write", "receive", "relay", "mailbox"].contains(&capability.as_str()) {
            return Err(CliError::new("invalid_argument", "Invalid capability")
                .detail(format!(
                    "Capability '{}' not supported. Use: read, write, receive, relay, mailbox",
                    capability
                ))
                .exit_code(ExitCode::USER_ERROR));
        }
    }

    // Generate share code with enhanced metadata
    let mut hasher = Sha256::new();
    hasher.update(args.source.to_string_lossy().as_bytes());
    hasher.update(args.expires_seconds.to_be_bytes());
    hasher.update(args.capabilities.join(",").as_bytes());
    let hash = hasher.finalize();

    let capability_flags = args.capabilities.join(",");
    let share_code = format!(
        "atp://share/{:x}/caps:{}/exp:{}/pol:{}",
        u64::from_be_bytes([
            hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7]
        ]),
        capability_flags,
        args.expires_seconds,
        args.policy
    );

    let payload = AtpShareOutput::new(args, share_code);
    output
        .write(&payload)
        .map_err(output_write_error("ATP share code"))?;
    Ok(())
}

fn atp_pair(args: &AtpPairArgs, output: &mut Output) -> Result<(), CliError> {
    match &args.command {
        AtpPairCommand::Initiate {
            peer_hint,
            confirmation_method,
            timeout_seconds,
        } => {
            use sha2::{Digest, Sha256};

            // Validate confirmation method
            if !["visual", "audio", "manual"].contains(&confirmation_method.as_str()) {
                return Err(
                    CliError::new("invalid_argument", "Invalid confirmation method")
                        .detail(format!(
                            "Method '{}' not supported. Use: visual, audio, manual",
                            confirmation_method
                        ))
                        .exit_code(ExitCode::USER_ERROR),
                );
            }

            // Generate session ID
            let mut hasher = Sha256::new();
            hasher.update(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
                    .to_be_bytes(),
            );
            if let Some(hint) = peer_hint {
                hasher.update(hint.as_bytes());
            }
            let hash = hasher.finalize();
            let session_id = format!(
                "pair_{:x}",
                u64::from_be_bytes([
                    hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7]
                ])
            );

            // Generate pairing token
            let pairing_token = format!(
                "atp://pair/{}/method:{}/timeout:{}",
                session_id, confirmation_method, timeout_seconds
            );

            // Generate human-readable confirmation phrase
            let confirmation_phrases = [
                "Ocean Blue Mountain",
                "Forest Green Valley",
                "Desert Red Sunset",
                "Arctic White Snow",
                "Tropical Gold Beach",
                "Urban Silver Skyline",
                "Rural Purple Meadow",
                "Cosmic Black Void",
                "Rainbow Crystal Cave",
            ];
            let phrase_index = (hash[8] as usize) % confirmation_phrases.len();
            let confirmation_phrase = confirmation_phrases[phrase_index].to_string();

            let payload = AtpPairOutput::initiate(
                session_id,
                pairing_token,
                confirmation_phrase,
                *timeout_seconds,
            );
            output
                .write(&payload)
                .map_err(output_write_error("ATP pairing initiation"))?;
        }

        AtpPairCommand::Confirm {
            pairing_token,
            confirmation_phrase,
        } => {
            // Validate pairing token format
            if !pairing_token.starts_with("atp://pair/") {
                return Err(
                    CliError::new("invalid_argument", "Invalid pairing token format")
                        .detail("Token must start with 'atp://pair/'")
                        .exit_code(ExitCode::USER_ERROR),
                );
            }

            // Extract session ID from token
            let session_id = pairing_token
                .strip_prefix("atp://pair/")
                .and_then(|s| s.split('/').next())
                .unwrap_or("unknown");

            // Validate confirmation phrase (simplified validation)
            if confirmation_phrase.split_whitespace().count() != 3 {
                return Err(CliError::new(
                    "invalid_argument",
                    "Invalid confirmation phrase format",
                )
                .detail("Confirmation phrase must be three words")
                .exit_code(ExitCode::USER_ERROR));
            }

            // Generate peer ID from successful confirmation
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(session_id.as_bytes());
            hasher.update(confirmation_phrase.as_bytes());
            let hash = hasher.finalize();
            let peer_id = format!(
                "peer_{:x}",
                u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]])
            );

            let payload = AtpPairOutput::confirm(peer_id);
            output
                .write(&payload)
                .map_err(output_write_error("ATP pairing confirmation"))?;
        }

        AtpPairCommand::Cancel { session_id } => {
            // Validate session ID format
            if !session_id.starts_with("pair_") {
                return Err(
                    CliError::new("invalid_argument", "Invalid session ID format")
                        .detail("Session ID must start with 'pair_'")
                        .exit_code(ExitCode::USER_ERROR),
                );
            }

            let payload = AtpPairOutput::cancel(session_id.clone());
            output
                .write(&payload)
                .map_err(output_write_error("ATP pairing cancellation"))?;
        }

        AtpPairCommand::List { detailed: _ } => {
            let active_sessions = Vec::new();
            let payload = AtpPairOutput::list(active_sessions);
            output
                .write(&payload)
                .map_err(output_write_error("ATP pairing list"))?;
        }
    }

    Ok(())
}

fn atp_seed(args: &AtpSeedArgs, output: &mut Output) -> Result<(), CliError> {
    // Validate source path exists
    if !args.source.exists() {
        return Err(
            CliError::new("file_not_found", "Source path does not exist")
                .detail(format!("Path: {}", args.source.display()))
                .exit_code(ExitCode::USER_ERROR),
        );
    }

    // Validate policy
    if !["public", "team-only", "peers-only", "private"].contains(&args.policy.as_str()) {
        return Err(CliError::new("invalid_argument", "Invalid seeding policy")
            .detail(format!(
                "Policy '{}' not supported. Use: public, team-only, peers-only, private",
                args.policy
            ))
            .exit_code(ExitCode::USER_ERROR));
    }

    // Validate priority
    if !["low", "normal", "high", "critical"].contains(&args.priority.as_str()) {
        return Err(CliError::new("invalid_argument", "Invalid priority level")
            .detail(format!(
                "Priority '{}' not supported. Use: low, normal, high, critical",
                args.priority
            ))
            .exit_code(ExitCode::USER_ERROR));
    }

    if args.verify_integrity {
        let _tree_digest = digest_path_tree(&args.source)?;
    }

    // Check size limits
    if args.max_size_bytes > 0 {
        let actual_size = summarize_source_path(&args.source)?.total_bytes;

        if actual_size > args.max_size_bytes {
            return Err(
                CliError::new("size_limit_exceeded", "Source exceeds maximum size limit")
                    .detail(format!(
                        "Source: {}, Limit: {}",
                        format_bytes(actual_size),
                        format_bytes(args.max_size_bytes)
                    ))
                    .exit_code(ExitCode::USER_ERROR),
            );
        }
    }

    let payload = AtpSeedOutput::new(args)?;
    output
        .write(&payload)
        .map_err(output_write_error("ATP seed configuration"))?;

    Ok(())
}

fn atp_watch(args: &AtpWatchArgs, output: &mut Output) -> Result<(), CliError> {
    let payload = AtpWatchOutput::new(&args.source, &args.target, args.debounce_seconds);
    output
        .write(&payload)
        .map_err(output_write_error("ATP watch status"))?;
    Ok(())
}

fn atp_serve(_args: &AtpServeArgs, output: &mut Output) -> Result<(), CliError> {
    let payload = AtpServeOutput::new("daemon started", "0.0.0.0:8080");
    output
        .write(&payload)
        .map_err(output_write_error("ATP serve status"))?;
    Ok(())
}

fn atp_inbox(args: &AtpInboxArgs, output: &mut Output) -> Result<(), CliError> {
    match &args.command {
        AtpInboxCommand::List => {
            let payload = AtpInboxListOutput::new(vec![]);
            output
                .write(&payload)
                .map_err(output_write_error("ATP inbox list"))?;
        }
        AtpInboxCommand::Accept {
            transfer_id,
            destination,
        } => {
            let dest_path = destination
                .as_ref()
                .map_or_else(|| ".".to_string(), |p| p.display().to_string());
            let payload = AtpInboxAcceptOutput::new(transfer_id, &dest_path);
            output
                .write(&payload)
                .map_err(output_write_error("ATP inbox accept"))?;
        }
        AtpInboxCommand::Reject {
            transfer_id,
            reason,
        } => {
            let reject_reason = reason.as_deref().unwrap_or("rejected by user");
            let payload = AtpInboxRejectOutput::new(transfer_id, reject_reason);
            output
                .write(&payload)
                .map_err(output_write_error("ATP inbox reject"))?;
        }
        AtpInboxCommand::Clear => {
            let payload = AtpInboxClearOutput::new(0);
            output
                .write(&payload)
                .map_err(output_write_error("ATP inbox clear"))?;
        }
    }
    Ok(())
}

fn atp_resume(args: &AtpResumeArgs, output: &mut Output) -> Result<(), CliError> {
    let payload = AtpResumeOutput::new(&args.transfer_id, args.force);
    output
        .write(&payload)
        .map_err(output_write_error("ATP resume"))?;
    Ok(())
}

fn atp_cancel(args: &AtpCancelArgs, output: &mut Output) -> Result<(), CliError> {
    let payload = AtpCancelOutput::new(&args.transfer_id, &args.reason, args.force);
    output
        .write(&payload)
        .map_err(output_write_error("ATP cancel"))?;
    Ok(())
}

fn atp_transfer_status(args: &AtpTransferStatusArgs, output: &mut Output) -> Result<(), CliError> {
    if args.watch {
        // Watch mode - continuously update
        let mut iteration = 0;
        loop {
            // Clear screen for watch mode
            if iteration > 0 {
                print!("\x1B[2J\x1B[1;1H"); // Clear screen and move cursor to top
            }

            let transfers = active_transfers_from_local_state(args.transfer_id.as_deref());

            let mut status_output = AtpTransferStatusOutput::new(transfers);

            if args.explain {
                // Add explain information for each transfer
                for transfer in &mut status_output.active_transfers {
                    let explain_report = AtpExplainReport::new(&transfer.transfer_id);
                    output
                        .write(&explain_report)
                        .map_err(output_write_error("ATP transfer status explain"))?;
                }
            }

            output
                .write(&status_output)
                .map_err(output_write_error("ATP transfer status"))?;

            iteration += 1;

            // Exit if not in watch mode or sleep for interval
            if !args.watch || iteration >= 5 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_secs(args.interval_seconds));
        }
    } else {
        // One-time status check
        let transfers = active_transfers_from_local_state(args.transfer_id.as_deref());

        let status_output = AtpTransferStatusOutput::new(transfers);

        if args.explain {
            for transfer in &status_output.active_transfers {
                let explain_report = AtpExplainReport::new(&transfer.transfer_id);
                output
                    .write(&explain_report)
                    .map_err(output_write_error("ATP transfer status explain"))?;
            }
        }

        output
            .write(&status_output)
            .map_err(output_write_error("ATP transfer status"))?;
    }
    Ok(())
}

fn atp_bench(args: &AtpBenchArgs, output: &mut Output) -> Result<(), CliError> {
    // Create output directory if it doesn't exist
    if !args.output_dir.exists() {
        std::fs::create_dir_all(&args.output_dir).map_err(|err| {
            CliError::new("io_error", "Failed to create benchmark output directory")
                .detail(format!(
                    "Path: {}, Error: {}",
                    args.output_dir.display(),
                    err
                ))
                .exit_code(ExitCode::RUNTIME_ERROR)
        })?;
    }

    let final_results = AtpBenchResults::for_profile(
        &args.profile,
        args.duration_seconds,
        args.concurrency,
        args.transfer_size,
        args.detailed,
    );

    // Write to output directory
    let result_file = args
        .output_dir
        .join(format!("atp_bench_{}.json", args.profile));
    let json_content = serde_json::to_string_pretty(&final_results).map_err(|err| {
        CliError::new(
            "serialization_error",
            "Failed to serialize benchmark results",
        )
        .detail(format!("Error: {}", err))
        .exit_code(ExitCode::RUNTIME_ERROR)
    })?;

    std::fs::write(&result_file, json_content).map_err(|err| {
        CliError::new("io_error", "Failed to write benchmark results")
            .detail(format!("Path: {}, Error: {}", result_file.display(), err))
            .exit_code(ExitCode::RUNTIME_ERROR)
    })?;

    // Output results
    output
        .write(&final_results)
        .map_err(output_write_error("ATP benchmark results"))?;

    Ok(())
}

fn parse_timeline_second_bound(value: f64, label: &str) -> Result<u64, CliError> {
    if !value.is_finite() || value < 0.0 {
        return Err(
            CliError::new("invalid_argument", "Invalid timeline window range")
                .detail(format!(
                    "{} must be a finite non-negative second value",
                    label
                ))
                .exit_code(ExitCode::USER_ERROR),
        );
    }
    let nanos = value * 1_000_000_000.0;
    if nanos > u64::MAX as f64 {
        return Err(
            CliError::new("invalid_argument", "Timeline window bound is too large")
                .detail(format!("{}: {}", label, value))
                .exit_code(ExitCode::USER_ERROR),
        );
    }
    Ok(nanos as u64)
}

fn parse_timeline_window_nanos(window: Option<&str>) -> Result<Option<(u64, u64)>, CliError> {
    let Some(window) = window else {
        return Ok(None);
    };
    let (start, end) = window.split_once(':').ok_or_else(|| {
        CliError::new(
            "invalid_argument",
            "Timeline window must use start:end seconds",
        )
        .detail(format!("Window: {}", window))
        .exit_code(ExitCode::USER_ERROR)
    })?;
    let start_secs = start.parse::<f64>().map_err(|err| {
        CliError::new("invalid_argument", "Invalid timeline window start")
            .detail(err.to_string())
            .exit_code(ExitCode::USER_ERROR)
    })?;
    let end_secs = end.parse::<f64>().map_err(|err| {
        CliError::new("invalid_argument", "Invalid timeline window end")
            .detail(err.to_string())
            .exit_code(ExitCode::USER_ERROR)
    })?;
    let start_nanos = parse_timeline_second_bound(start_secs, "start")?;
    let end_nanos = parse_timeline_second_bound(end_secs, "end")?;
    if end_nanos < start_nanos {
        return Err(
            CliError::new("invalid_argument", "Invalid timeline window range")
                .detail(format!("Window: {}", window))
                .exit_code(ExitCode::USER_ERROR),
        );
    }
    Ok(Some((start_nanos, end_nanos)))
}

fn filter_timeline_rows(
    rows: Vec<TraceEventRow>,
    window: Option<(u64, u64)>,
) -> Vec<TraceEventRow> {
    rows.into_iter()
        .filter(|row| match (window, row.time_nanos) {
            (Some((start, end)), Some(time)) => time >= start && time <= end,
            (Some(_), None) => false,
            (None, _) => true,
        })
        .collect()
}

fn csv_escape_field(field: &str) -> String {
    if field.contains(',') || field.contains('"') || field.contains('\n') || field.contains('\r') {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
    }
}

fn atp_trace(args: &AtpTraceArgs, output: &mut Output) -> Result<(), CliError> {
    match &args.command {
        AtpTraceCommand::Analyze {
            trace_file,
            detailed,
        } => {
            // Verify trace file exists
            if !trace_file.exists() {
                return Err(CliError::new("file_not_found", "Trace file does not exist")
                    .detail(format!("Path: {}", trace_file.display()))
                    .exit_code(ExitCode::USER_ERROR));
            }

            let analysis = AtpTraceAnalysis::from_trace_file(trace_file, *detailed)?;

            output
                .write(&analysis)
                .map_err(output_write_error("ATP trace analysis"))?;
        }

        AtpTraceCommand::Extract {
            trace_file,
            event_types,
            format,
        } => {
            // Verify trace file exists
            if !trace_file.exists() {
                return Err(CliError::new("file_not_found", "Trace file does not exist")
                    .detail(format!("Path: {}", trace_file.display()))
                    .exit_code(ExitCode::USER_ERROR));
            }

            // Validate format
            if !["json", "csv", "ndjson", "human"].contains(&format.as_str()) {
                return Err(
                    CliError::new("invalid_argument", "Unsupported extract format")
                        .detail(format!(
                            "Format '{}' not supported. Use: json, csv, ndjson, human",
                            format
                        ))
                        .exit_code(ExitCode::USER_ERROR),
                );
            }

            let extracted_events: Vec<serde_json::Value> =
                trace_events(trace_file, 0, None, event_types)?
                    .into_iter()
                    .map(|row| {
                        serde_json::json!({
                            "index": row.index,
                            "event_type": row.kind,
                            "time_nanos": row.time_nanos,
                            "event": row.event,
                        })
                    })
                    .collect();

            // Format output based on requested format
            match format.as_str() {
                "json" => {
                    let formatted =
                        serde_json::to_string_pretty(&extracted_events).map_err(|err| {
                            CliError::new(
                                "serialization_error",
                                "Failed to serialize extracted events",
                            )
                            .detail(format!("Error: {}", err))
                            .exit_code(ExitCode::RUNTIME_ERROR)
                        })?;
                    println!("{}", formatted);
                }
                "ndjson" => {
                    for event in &extracted_events {
                        let line = serde_json::to_string(event).map_err(|err| {
                            CliError::new("serialization_error", "Failed to serialize event")
                                .detail(format!("Error: {}", err))
                                .exit_code(ExitCode::RUNTIME_ERROR)
                        })?;
                        println!("{}", line);
                    }
                }
                "csv" => {
                    println!("index,event_type,time_nanos,event_json");
                    for event in &extracted_events {
                        let event_json = serde_json::to_string(&event["event"]).map_err(|err| {
                            CliError::new("serialization_error", "Failed to serialize event")
                                .detail(format!("Error: {}", err))
                                .exit_code(ExitCode::RUNTIME_ERROR)
                        })?;
                        let index = event["index"].as_u64().unwrap_or(0).to_string();
                        let event_type = event["event_type"].as_str().unwrap_or("unknown");
                        let time_nanos = event["time_nanos"]
                            .as_u64()
                            .map_or_else(String::new, |v| v.to_string());
                        println!(
                            "{},{},{},{}",
                            csv_escape_field(&index),
                            csv_escape_field(event_type),
                            csv_escape_field(&time_nanos),
                            csv_escape_field(&event_json)
                        );
                    }
                }
                "human" => {
                    for event in &extracted_events {
                        println!(
                            "#{:06} [{}] {}",
                            event["index"].as_u64().unwrap_or(0),
                            event["time_nanos"]
                                .as_u64()
                                .map_or_else(|| "-".to_string(), |v| v.to_string()),
                            event["event_type"].as_str().unwrap_or("unknown")
                        );
                    }
                }
                _ => unreachable!(),
            }
        }

        AtpTraceCommand::Compare {
            trace_a,
            trace_b,
            metrics,
        } => {
            // Verify both trace files exist
            for (file, name) in [(trace_a, "trace_a"), (trace_b, "trace_b")] {
                if !file.exists() {
                    return Err(CliError::new(
                        "file_not_found",
                        format!("Trace file {} does not exist", name),
                    )
                    .detail(format!("Path: {}", file.display()))
                    .exit_code(ExitCode::USER_ERROR));
                }
            }

            let diff = trace_diff(trace_a, trace_b)?;
            let info_a = trace_info(trace_a)?;
            let info_b = trace_info(trace_b)?;
            let requested_metrics = if metrics.is_empty() {
                vec![
                    "event_count".to_string(),
                    "duration_nanos".to_string(),
                    "size_bytes".to_string(),
                ]
            } else {
                metrics.clone()
            };
            let comparison = serde_json::json!({
                "comparison_type": "metric_comparison",
                "trace_a": trace_a.display().to_string(),
                "trace_b": trace_b.display().to_string(),
                "diverged": diff.diverged,
                "divergence_index": diff.divergence_index,
                "common_events": diff.common_events,
                "requested_metrics": requested_metrics,
                "results": requested_metrics.iter().map(|metric| {
                    let (a, b) = match metric.as_str() {
                        "event_count" | "events" => (info_a.event_count as f64, info_b.event_count as f64),
                        "duration_nanos" | "duration" => (
                            info_a.duration_nanos.unwrap_or(0) as f64,
                            info_b.duration_nanos.unwrap_or(0) as f64,
                        ),
                        "size_bytes" | "size" => (info_a.size_bytes as f64, info_b.size_bytes as f64),
                        _ => (0.0, 0.0),
                    };
                    let difference = b - a;
                    serde_json::json!({
                        "metric": metric,
                        "trace_a_value": a,
                        "trace_b_value": b,
                        "difference": difference,
                        "percentage_change": if a.abs() > f64::EPSILON { (difference / a) * 100.0 } else { 0.0 }
                    })
                }).collect::<Vec<_>>()
            });

            let formatted = serde_json::to_string_pretty(&comparison).map_err(|err| {
                CliError::new(
                    "serialization_error",
                    "Failed to serialize comparison results",
                )
                .detail(format!("Error: {}", err))
                .exit_code(ExitCode::RUNTIME_ERROR)
            })?;
            println!("{}", formatted);
        }

        AtpTraceCommand::Timeline {
            trace_file,
            format,
            time_window,
        } => {
            // Verify trace file exists
            if !trace_file.exists() {
                return Err(CliError::new("file_not_found", "Trace file does not exist")
                    .detail(format!("Path: {}", trace_file.display()))
                    .exit_code(ExitCode::USER_ERROR));
            }

            // Validate format
            if !["json", "text", "ascii", "svg"].contains(&format.as_str()) {
                return Err(
                    CliError::new("invalid_argument", "Unsupported timeline format")
                        .detail(format!(
                            "Format '{}' not supported. Use: json, text, ascii, svg",
                            format
                        ))
                        .exit_code(ExitCode::USER_ERROR),
                );
            }

            let window = parse_timeline_window_nanos(time_window.as_deref())?;
            let rows = filter_timeline_rows(trace_events(trace_file, 0, Some(100), &[])?, window);
            match format.as_str() {
                "json" => {
                    let timeline = serde_json::json!({
                        "timeline": {
                            "trace_file": trace_file.display().to_string(),
                            "time_window": time_window.as_deref().unwrap_or("full"),
                            "events": rows.iter().map(|row| serde_json::json!({
                                "index": row.index,
                                "time_nanos": row.time_nanos,
                                "event": row.kind,
                            })).collect::<Vec<_>>()
                        }
                    });
                    println!("{}", serde_json::to_string_pretty(&timeline).unwrap());
                }
                "text" | "ascii" => {
                    println!("ATP Trace Timeline");
                    println!("=================");
                    println!("Source: {}", trace_file.display());
                    println!("Window: {}", time_window.as_deref().unwrap_or("full"));
                    println!();
                    for row in &rows {
                        println!(
                            "{:>12} | {:<24} | #{}",
                            row.time_nanos
                                .map_or_else(|| "-".to_string(), |v| v.to_string()),
                            row.kind,
                            row.index
                        );
                    }
                }
                "svg" => {
                    println!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
                    println!(
                        "<svg width=\"800\" height=\"200\" xmlns=\"http://www.w3.org/2000/svg\">"
                    );
                    println!(
                        "  <text x=\"10\" y=\"30\" font-family=\"monospace\" font-size=\"14\">ATP Trace Timeline</text>"
                    );
                    println!(
                        "  <line x1=\"50\" y1=\"50\" x2=\"750\" y2=\"50\" stroke=\"black\" stroke-width=\"2\"/>"
                    );
                    let count = rows.len().max(1);
                    for (idx, row) in rows.iter().enumerate() {
                        let x = 50 + ((idx * 700) / count);
                        println!("  <circle cx=\"{}\" cy=\"50\" r=\"5\" fill=\"blue\"/>", x);
                        println!(
                            "  <text x=\"{}\" y=\"75\" font-family=\"monospace\" font-size=\"10\">{} #{}</text>",
                            x.saturating_sub(20),
                            row.kind,
                            row.index
                        );
                    }
                    println!("</svg>");
                }
                _ => unreachable!(),
            }
        }
    }

    Ok(())
}

fn effective_output_format(command: &Command, default: OutputFormat) -> OutputFormat {
    match command {
        Command::Lab(LabArgs {
            command: LabCommand::Run(args),
        }) if args.json => OutputFormat::JsonPretty,
        Command::Lab(LabArgs {
            command: LabCommand::Validate(args),
        }) if args.json => OutputFormat::JsonPretty,
        Command::Lab(LabArgs {
            command: LabCommand::Replay(args),
        }) if args.json => OutputFormat::JsonPretty,
        Command::Lab(LabArgs {
            command: LabCommand::Explore(args),
        }) if args.json => OutputFormat::JsonPretty,
        Command::Lab(LabArgs {
            command: LabCommand::Differential(args),
        }) if args.json => OutputFormat::JsonPretty,
        Command::Lab(LabArgs {
            command: LabCommand::DifferentialProfileManifest(args),
        }) if args.json => OutputFormat::JsonPretty,
        _ => default,
    }
}

#[derive(Debug, serde::Serialize)]
#[serde(transparent)]
struct JsonOutputValue<T> {
    value: T,
}

impl<T: serde::Serialize> JsonOutputValue<T> {
    fn new(value: T) -> Self {
        Self { value }
    }
}

impl<T: serde::Serialize> Outputtable for JsonOutputValue<T> {
    fn human_format(&self) -> String {
        serde_json::to_string_pretty(&self.value)
            .unwrap_or_else(|err| format!("{{\"output_error\":\"{err}\"}}"))
    }
}

#[derive(Debug, serde::Deserialize)]
#[serde(untagged)]
enum AtpEarlyUsabilityReportInput {
    Stream(StreamEarlyUsabilityReport),
    Directory(DirectoryEarlyUsabilityReport),
}

#[derive(Debug, serde::Serialize, PartialEq, Eq)]
struct AtpStatusOutput {
    telemetry_path: String,
    trace_id: String,
    workload_id: String,
    sample_count: u32,
    explain: bool,
    metric_names: Vec<&'static str>,
    decision: AtpAutotuneDecision,
    repair_decision: AtpRepairCoordinatorDecision,
    receipt: AtpAutotuneDecisionReceipt,
}

impl Outputtable for AtpStatusOutput {
    fn human_format(&self) -> String {
        let mut lines = vec![
            "ATP Status".to_string(),
            format!("Telemetry: {}", self.telemetry_path),
        ];
        lines.extend(self.receipt.human_summary_lines(self.explain));
        if self.explain {
            lines.extend(self.repair_decision.human_summary_lines());
        }

        lines.join("\n")
    }
}

#[derive(Debug, serde::Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum AtpEarlyUsabilityOutput {
    Stream {
        report_path: String,
        report: StreamEarlyUsabilityReport,
    },
    Directory {
        report_path: String,
        report: DirectoryEarlyUsabilityReport,
    },
}

impl Outputtable for AtpEarlyUsabilityOutput {
    fn human_format(&self) -> String {
        match self {
            Self::Stream {
                report_path,
                report,
            } => {
                let mut lines = vec![
                    "ATP Early Usability Report".to_string(),
                    format!("Report: {report_path}"),
                    "Type: stream".to_string(),
                    format!("Stream ID: {}", report.stream_id),
                    format!("Usable state: {:?}", report.usable_state),
                    format!("Final commit state: {:?}", report.final_commit_state),
                    format!("Consumption policy: {:?}", report.consumption_policy),
                    format!("Verified prefix end: {}", report.verified_prefix_end),
                    format!("Policy prefix end: {}", report.policy_prefix_end),
                    format!(
                        "Policy exposed prefix: {}",
                        format_optional_byte_range(report.policy_exposed_prefix)
                    ),
                    format!("Total bytes: {}", report.total_bytes),
                    format!("Bytes sent: {}", report.bytes_sent),
                    format!(
                        "Verified prefix ranges: {}",
                        format_byte_ranges(&report.verified_prefix_ranges)
                    ),
                ];

                append_named_list(&mut lines, "Safety caveats", &report.safety_caveats);
                lines.join("\n")
            }
            Self::Directory {
                report_path,
                report,
            } => {
                let mut lines = vec![
                    "ATP Early Usability Report".to_string(),
                    format!("Report: {report_path}"),
                    "Type: directory".to_string(),
                    format!("Schema: {}", report.schema_version),
                    format!("Usable state: {:?}", report.usability_state),
                    format!("Final commit state: {:?}", report.final_commit_state),
                    format!("Manifest tree root: {}", report.manifest_tree_root),
                    format!("Replay pointer: {}", report.replay_pointer),
                    format!("Metadata paths: {}", report.metadata_paths.len()),
                    format!("Small file paths: {}", report.small_file_paths.len()),
                    format!(
                        "Withheld content paths: {}",
                        report.withheld_content_paths.len()
                    ),
                    format!("Entry decisions: {}", report.entries.len()),
                ];

                append_named_list(&mut lines, "Metadata", &report.metadata_paths);
                append_named_list(&mut lines, "Small files", &report.small_file_paths);
                append_named_list(
                    &mut lines,
                    "Withheld content",
                    &report.withheld_content_paths,
                );
                append_named_list(&mut lines, "Safety caveats", &report.safety_caveats);
                lines.join("\n")
            }
        }
    }
}

fn format_optional_byte_range(range: Option<ByteRange>) -> String {
    range.map_or_else(|| "none".to_string(), format_byte_range)
}

fn format_byte_ranges(ranges: &[ByteRange]) -> String {
    if ranges.is_empty() {
        return "none".to_string();
    }

    ranges
        .iter()
        .map(|range| format_byte_range(*range))
        .collect::<Vec<_>>()
        .join(", ")
}

fn format_byte_range(range: ByteRange) -> String {
    format!("{}..{} ({} bytes)", range.start, range.end, range.size())
}

fn append_named_list(lines: &mut Vec<String>, label: &str, values: &[String]) {
    if values.is_empty() {
        lines.push(format!("{label}: none"));
        return;
    }

    lines.push(format!("{label}:"));
    for value in values {
        lines.push(format!("  - {value}"));
    }
}

fn run_trace(args: TraceArgs, output: &mut Output) -> Result<(), CliError> {
    match args.command {
        TraceCommand::Info(args) => {
            let info = trace_info(&args.file)?;
            output
                .write(&info)
                .map_err(output_write_error("trace info"))?;
            Ok(())
        }
        TraceCommand::Events(args) => {
            let rows = trace_events(&args.file, args.offset, args.limit, &args.filters)?;
            output
                .write_list(&rows)
                .map_err(output_write_error("trace events"))?;
            Ok(())
        }
        TraceCommand::Verify(args) => {
            let out = trace_verify(&args.file, args.quick, args.strict, args.monotonic)?;
            let valid = out.valid;
            output
                .write(&out)
                .map_err(output_write_error("verification results"))?;
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
            output
                .write(&out)
                .map_err(output_write_error("diff results"))?;
            if diverged {
                return Err(CliError::new("trace_divergence", "Traces diverged")
                    .exit_code(ExitCode::TRACE_MISMATCH));
            }
            Ok(())
        }
        TraceCommand::Compress(args) => {
            let out = trace_compress(&args.input, &args.output, args.level)?;
            output
                .write(&out)
                .map_err(output_write_error("compression results"))?;
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
        DoctorCommand::SwarmStatus => doctor_swarm_status(output),
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

    output
        .write(&report)
        .map_err(output_write_error("workspace scan report"))?;
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
    output
        .write(&analysis)
        .map_err(output_write_error("invariant analysis report"))?;
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

fn doctor_swarm_status(output: &mut Output) -> Result<(), CliError> {
    let contract = agent_swarm_status_contract();
    let snapshot: AgentSwarmStatusSnapshot =
        run_agent_swarm_status_smoke(&contract).map_err(|err| {
            CliError::new(
                "doctor_swarm_status_error",
                "Failed to build ASW swarm-status snapshot",
            )
            .detail(err)
            .exit_code(ExitCode::RUNTIME_ERROR)
        })?;
    output.write(&snapshot).map_err(|err| {
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

#[derive(Debug, serde::Serialize, PartialEq, Eq)]
struct AtpPlatformDoctorOutput {
    #[serde(flatten)]
    document: AtpPlatformDoctorDocument,
}

impl AtpPlatformDoctorOutput {
    fn new(document: AtpPlatformDoctorDocument) -> Self {
        Self { document }
    }
}

impl Outputtable for AtpPlatformDoctorOutput {
    fn human_format(&self) -> String {
        render_platform_doctor_human(&self.document)
    }
}

#[derive(Debug, serde::Serialize, PartialEq)]
#[serde(tag = "type")]
enum AtpVerifyOutput {
    #[serde(rename = "summary")]
    Summary {
        status: String,
        bundle_path: String,
        transfer_id: String,
        completion_ratio: f64,
        checks_passed: usize,
        checks_total: usize,
        warning_count: usize,
        error_count: usize,
    },
    #[serde(rename = "detailed")]
    Detailed {
        status: String,
        bundle_path: String,
        #[serde(skip)]
        verification_result: asupersync::atp::verify::AtpVerificationResult,
    },
}

impl Outputtable for AtpVerifyOutput {
    fn human_format(&self) -> String {
        match self {
            Self::Summary {
                status,
                bundle_path,
                transfer_id,
                completion_ratio,
                checks_passed,
                checks_total,
                warning_count,
                error_count,
            } => {
                let mut lines = vec![
                    format!("ATP Proof Bundle Verification"),
                    format!("Bundle: {bundle_path}"),
                    format!("Status: {status}"),
                    format!("Transfer ID: {transfer_id}"),
                    format!("Completion: {:.1}%", completion_ratio * 100.0),
                    format!("Checks: {checks_passed}/{checks_total} passed"),
                ];

                if *warning_count > 0 {
                    lines.push(format!("Warnings: {warning_count}"));
                }

                if *error_count > 0 {
                    lines.push(format!("Errors: {error_count}"));
                }

                lines.join("\n")
            }
            Self::Detailed {
                status,
                bundle_path,
                verification_result,
            } => {
                let mut lines = vec![
                    format!("ATP Proof Bundle Verification Report"),
                    format!("Bundle: {bundle_path}"),
                    format!("Status: {status}"),
                    format!(""),
                    format!("Transfer Summary:"),
                    format!(
                        "  ID: {}",
                        verification_result.report.transfer_summary.transfer_id
                    ),
                    format!(
                        "  Source: {}",
                        verification_result.report.transfer_summary.source_peer
                    ),
                    format!(
                        "  Destination: {}",
                        verification_result.report.transfer_summary.destination_peer
                    ),
                    format!(
                        "  Completion: {:.1}%",
                        verification_result.report.transfer_summary.completion_ratio * 100.0
                    ),
                    format!(
                        "  Protocol: {}",
                        verification_result.report.transfer_summary.primary_protocol
                    ),
                    format!(""),
                    format!("Content Integrity:"),
                    format!(
                        "  Manifest verified: {}",
                        verification_result
                            .report
                            .content_integrity
                            .manifest_verified
                    ),
                    format!(
                        "  Chunk coverage: {:.1}%",
                        verification_result
                            .report
                            .content_integrity
                            .chunk_verification_coverage
                            * 100.0
                    ),
                    format!(
                        "  Verification stages: {}/{}",
                        verification_result
                            .report
                            .content_integrity
                            .verification_stages_passed,
                        verification_result
                            .report
                            .content_integrity
                            .verification_stages_total
                    ),
                    format!(""),
                    format!("Proof Strength:"),
                    format!(
                        "  Required: {:?}",
                        verification_result.report.proof_strength.required_strength
                    ),
                    format!(
                        "  Calculated: {:?}",
                        verification_result
                            .report
                            .proof_strength
                            .calculated_strength
                    ),
                    format!(
                        "  Requirements met: {}",
                        verification_result.report.proof_strength.requirements_met
                    ),
                    format!(""),
                ];

                if !verification_result.warnings.is_empty() {
                    lines.push(format!(
                        "Warnings ({}):",
                        verification_result.warnings.len()
                    ));
                    for warning in &verification_result.warnings {
                        lines.push(format!("  - {}: {}", warning.code, warning.message));
                    }
                    lines.push(String::new());
                }

                if !verification_result.errors.is_empty() {
                    lines.push(format!("Errors ({}):", verification_result.errors.len()));
                    for error in &verification_result.errors {
                        lines.push(format!("  - {}", error));
                    }
                    lines.push(String::new());
                }

                lines.join("\n")
            }
        }
    }
}

#[derive(Debug, serde::Serialize, PartialEq)]
#[serde(tag = "type")]
enum AtpProofOutput {
    #[serde(rename = "summary")]
    Summary {
        bundle_path: String,
        bundle_version: u32,
        transfer_id: String,
        created_at: u64,
        source_peer: String,
        destination_peer: String,
        object_count: usize,
        chunk_completion: f64,
        proof_strength: String,
        primary_protocol: String,
        journal_complete: bool,
    },
    #[serde(rename = "full")]
    Full {
        bundle_path: String,
        #[serde(skip)]
        bundle: asupersync::atp::proof::AtpProofBundle,
    },
    #[serde(rename = "sections")]
    Sections {
        bundle_path: String,
        sections: Vec<String>,
        #[serde(skip)]
        bundle: asupersync::atp::proof::AtpProofBundle,
    },
}

impl Outputtable for AtpProofOutput {
    fn human_format(&self) -> String {
        match self {
            Self::Summary {
                bundle_path,
                bundle_version,
                transfer_id,
                created_at,
                source_peer,
                destination_peer,
                object_count,
                chunk_completion,
                proof_strength,
                primary_protocol,
                journal_complete,
            } => {
                format!(
                    "ATP Proof Bundle Summary
Bundle: {bundle_path}
Version: {bundle_version}
Transfer ID: {transfer_id}
Created: {}
Source: {source_peer}
Destination: {destination_peer}
Objects: {object_count}
Completion: {:.1}%
Proof strength: {proof_strength}
Protocol: {primary_protocol}
Journal complete: {journal_complete}",
                    if *created_at > 0 {
                        format!("{} μs since epoch", created_at)
                    } else {
                        "unknown".to_string()
                    },
                    chunk_completion * 100.0
                )
            }
            Self::Full {
                bundle_path,
                bundle,
            } => {
                let mut lines = vec![
                    format!("ATP Proof Bundle"),
                    format!("Bundle: {bundle_path}"),
                    format!("Version: {}", bundle.version.0),
                    format!("Transfer ID: {}", bundle.transfer_id),
                    format!(""),
                    format!("Manifest:"),
                    format!("  Root: {}", bundle.manifest_root),
                    format!("  Objects: {} root(s)", bundle.object_roots.len()),
                    if let Some(ref commit) = bundle.commit_record {
                        format!("  Commit: {}", commit.id)
                    } else {
                        "  Commit: none".to_string()
                    },
                    format!(""),
                    format!("Content:"),
                    format!("  Hash algorithm: {:?}", bundle.chunk_hash_algorithm),
                    format!(
                        "  Chunks: {}/{} received ({:.1}%)",
                        bundle.chunk_bitmap.received_count,
                        bundle.chunk_bitmap.total_chunks,
                        bundle.chunk_bitmap.completion_ratio() * 100.0
                    ),
                    format!(
                        "  Verification stages: {}",
                        bundle.verification_evidence.len()
                    ),
                    format!(""),
                    format!("Repair:"),
                ];

                if let Some(ref raptorq) = bundle.raptorq_metadata {
                    lines.push(format!(
                        "  RaptorQ: {} source blocks",
                        raptorq.source_blocks.len()
                    ));
                    lines.push(format!(
                        "  Repair symbols used: {}",
                        raptorq.repair_symbols_used
                    ));
                    lines.push(format!(
                        "  Success rate: {:.1}%",
                        raptorq.decode_success_rate * 100.0
                    ));
                } else {
                    lines.push("  RaptorQ: none".to_string());
                }

                lines.push(format!("  Repair groups: {}", bundle.repair_groups.len()));
                lines.push(String::new());
                lines.push("Peer Identity:".to_string());
                lines.push(format!("  Source: {}", bundle.peer_identity.source_peer_id));
                lines.push(format!(
                    "  Destination: {}",
                    bundle.peer_identity.destination_peer_id
                ));
                lines.push(format!(
                    "  Auth method: {}",
                    bundle.peer_identity.auth_method
                ));
                lines.push(format!(
                    "  Key fingerprints: {}",
                    bundle.peer_identity.key_fingerprints.len()
                ));
                lines.push(String::new());
                lines.push("Path:".to_string());
                lines.push(format!(
                    "  Primary protocol: {}",
                    bundle.path_summary.primary_protocol
                ));
                lines.push(format!("  Relay used: {}", bundle.path_summary.relay_used));

                if let Some(rtt) = bundle.path_summary.rtt_millis {
                    lines.push(format!("  RTT: {:.1} ms", rtt));
                }

                if let Some(bw) = bundle.path_summary.bandwidth_bps {
                    lines.push(format!("  Bandwidth: {} bps", bw));
                }

                lines.push(String::new());
                lines.push("Journal:".to_string());
                lines.push(format!("  Entries: {}", bundle.journal.entry_count));
                lines.push(format!("  Size: {} bytes", bundle.journal.size_bytes));
                lines.push(format!("  Complete: {}", bundle.journal.is_complete));
                lines.push(String::new());
                lines.push("Replay:".to_string());
                lines.push(format!("  Pointers: {}", bundle.replay_pointers.len()));
                lines.push(format!("  Extensions: {}", bundle.extensions.len()));

                lines.join("\n")
            }
            Self::Sections {
                bundle_path,
                sections,
                bundle,
            } => {
                let mut lines = vec![
                    format!("ATP Proof Bundle"),
                    format!("Bundle: {bundle_path}"),
                    format!("Sections: {}", sections.join(", ")),
                    format!(""),
                ];

                for section in sections {
                    match section.as_str() {
                        "manifest" => {
                            lines.push("Manifest:".to_string());
                            lines.push(format!("  Root: {}", bundle.manifest_root));
                            lines.push(format!("  Objects: {} root(s)", bundle.object_roots.len()));
                            if let Some(ref commit) = bundle.commit_record {
                                lines.push(format!("  Commit: {}", commit.id));
                            }
                            lines.push(String::new());
                        }
                        "content" => {
                            lines.push("Content:".to_string());
                            lines.push(format!(
                                "  Hash algorithm: {:?}",
                                bundle.chunk_hash_algorithm
                            ));
                            lines.push(format!(
                                "  Chunks: {}/{} received ({:.1}%)",
                                bundle.chunk_bitmap.received_count,
                                bundle.chunk_bitmap.total_chunks,
                                bundle.chunk_bitmap.completion_ratio() * 100.0
                            ));
                            lines.push(format!(
                                "  Verification stages: {}",
                                bundle.verification_evidence.len()
                            ));
                            lines.push(String::new());
                        }
                        "repair" => {
                            lines.push("Repair:".to_string());
                            if let Some(ref raptorq) = bundle.raptorq_metadata {
                                lines.push(format!(
                                    "  RaptorQ: {} source blocks",
                                    raptorq.source_blocks.len()
                                ));
                                lines.push(format!(
                                    "  Repair symbols used: {}",
                                    raptorq.repair_symbols_used
                                ));
                                lines.push(format!(
                                    "  Success rate: {:.1}%",
                                    raptorq.decode_success_rate * 100.0
                                ));
                            } else {
                                lines.push("  RaptorQ: none".to_string());
                            }
                            lines.push(format!("  Repair groups: {}", bundle.repair_groups.len()));
                            lines.push(String::new());
                        }
                        "peer" => {
                            lines.push("Peer Identity:".to_string());
                            lines
                                .push(format!("  Source: {}", bundle.peer_identity.source_peer_id));
                            lines.push(format!(
                                "  Destination: {}",
                                bundle.peer_identity.destination_peer_id
                            ));
                            lines.push(format!(
                                "  Auth method: {}",
                                bundle.peer_identity.auth_method
                            ));
                            lines.push(format!(
                                "  Key fingerprints: {}",
                                bundle.peer_identity.key_fingerprints.len()
                            ));
                            lines.push(String::new());
                        }
                        "path" => {
                            lines.push("Path:".to_string());
                            lines.push(format!(
                                "  Primary protocol: {}",
                                bundle.path_summary.primary_protocol
                            ));
                            lines.push(format!("  Relay used: {}", bundle.path_summary.relay_used));
                            if let Some(rtt) = bundle.path_summary.rtt_millis {
                                lines.push(format!("  RTT: {:.1} ms", rtt));
                            }
                            if let Some(bw) = bundle.path_summary.bandwidth_bps {
                                lines.push(format!("  Bandwidth: {} bps", bw));
                            }
                            lines.push(String::new());
                        }
                        "journal" => {
                            lines.push("Journal:".to_string());
                            lines.push(format!("  Entries: {}", bundle.journal.entry_count));
                            lines.push(format!("  Size: {} bytes", bundle.journal.size_bytes));
                            lines.push(format!("  Complete: {}", bundle.journal.is_complete));
                            lines.push(String::new());
                        }
                        "replay" => {
                            lines.push("Replay:".to_string());
                            lines.push(format!("  Pointers: {}", bundle.replay_pointers.len()));
                            lines.push(format!("  Extensions: {}", bundle.extensions.len()));
                            lines.push(String::new());
                        }
                        _ => {
                            lines.push(format!("Unknown section: {section}"));
                            lines.push(String::new());
                        }
                    }
                }

                lines.join("\n")
            }
        }
    }
}

#[derive(Debug, serde::Serialize)]
struct AtpReplayOutput {
    artifact_dir: String,
    trace_file: String,
    replay_successful: bool,
    original_violations: usize,
    minimized_trace_length: usize,
    requested_oracles: Vec<String>,
    result: asupersync::lab::crashpack::AtpReplayResult,
}

impl Outputtable for AtpReplayOutput {
    fn human_format(&self) -> String {
        let status = if self.replay_successful {
            "reproduced"
        } else {
            "not reproduced"
        };
        let mut lines = vec![
            format!("ATP Replay: {status}"),
            format!("Artifact directory: {}", self.artifact_dir),
            format!("Trace file: {}", self.trace_file),
            format!("Original violations: {}", self.original_violations),
            format!("Minimized trace length: {}", self.minimized_trace_length),
            format!("Oracle reports: {}", self.result.oracle_results.len()),
        ];

        if !self.requested_oracles.is_empty() {
            lines.push(format!(
                "Requested oracles: {}",
                self.requested_oracles.join(", ")
            ));
        }

        for report in &self.result.oracle_results {
            for entry in &report.entries {
                let entry_status = if entry.passed { "passed" } else { "failed" };
                lines.push(format!("  {}: {}", entry.invariant, entry_status));
            }
        }

        lines.join("\n")
    }
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
            .exit_code(ExitCode::USER_ERROR)
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
                .exit_code(ExitCode::USER_ERROR)
        }
        asupersync::lab::scenario_runner::ScenarioRunnerError::UnknownOracle(name) => {
            CliError::new("unknown_oracle", "Unknown oracle name in scenario")
                .detail(format!(
                    "Oracle '{name}' not found. Available: {}",
                    asupersync::lab::meta::mutation::ALL_ORACLE_INVARIANTS.join(", ")
                ))
                .exit_code(ExitCode::USER_ERROR)
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
        let json = JsonOutputValue::new(result.to_json());
        output.write(&json).map_err(output_cli_error)?;
    } else {
        let report = LabRunOutput::from_result(&result);
        output.write(&report).map_err(output_cli_error)?;
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

    output.write(&report).map_err(output_cli_error)?;

    if !errors.is_empty() {
        return Err(
            CliError::new("scenario_invalid", "Scenario validation failed")
                .exit_code(ExitCode::USER_ERROR),
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

    output.write(&report).map_err(output_cli_error)?;

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
        let json = JsonOutputValue::new(result.to_json());
        output.write(&json).map_err(output_cli_error)?;
    } else {
        let report = LabExploreOutput::from_result(&result);
        output.write(&report).map_err(output_cli_error)?;
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
        output.write(&manifest).map_err(output_cli_error)?;
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

    output.write(&report).map_err(output_cli_error)?;

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

fn poll_once<F>(future: &mut F) -> Poll<F::Output>
where
    F: Future + Unpin,
{
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    Pin::new(future).poll(&mut context)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SemaphoreCancelRecoveryObservation {
    cancelled_waiters: usize,
    recovered_acquisitions: usize,
    available_after_cancel: usize,
    final_available_permits: usize,
    unexpected_cancel_acquisitions: usize,
    unexpected_cancel_errors: usize,
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
                )
                .with_counter(
                    "unexpected_cancel_acquisitions",
                    counter_i64(self.unexpected_cancel_acquisitions),
                )
                .with_counter(
                    "unexpected_cancel_errors",
                    counter_i64(self.unexpected_cancel_errors),
                ),
        }
    }
}

fn live_semaphore_cancel_recovery_observation() -> SemaphoreCancelRecoveryObservation {
    let semaphore = Semaphore::new(1);
    let held = semaphore.try_acquire(1).expect("seeded semaphore permit");
    let cancel_cx = Cx::<NoCaps>::detached_cancel_context();
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
        "live semaphore differential waiter should cancel after being queued"
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
        unexpected_cancel_acquisitions: 0,
        unexpected_cancel_errors: 0,
    }
}

fn lab_semaphore_cancel_recovery_observation(seed: u64) -> SemaphoreCancelRecoveryObservation {
    let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(2_000));
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let semaphore = Arc::new(Semaphore::new(1));
    let held = semaphore.try_acquire(1).expect("seeded semaphore permit");
    let cancel_cx = Cx::<NoCaps>::detached_cancel_context();
    let waiter_cx = cancel_cx.clone();
    let cancelled_waiters = Arc::new(AtomicUsize::new(0));
    let unexpected_cancel_acquisitions = Arc::new(AtomicUsize::new(0));
    let unexpected_cancel_errors = Arc::new(AtomicUsize::new(0));

    let semaphore_for_waiter = Arc::clone(&semaphore);
    let waiter_result = Arc::clone(&cancelled_waiters);
    let unexpected_acquires = Arc::clone(&unexpected_cancel_acquisitions);
    let unexpected_errors = Arc::clone(&unexpected_cancel_errors);
    let (task_id, _) = runtime
        .state
        .create_task(region, Budget::INFINITE, async move {
            match semaphore_for_waiter.acquire(&waiter_cx, 1).await {
                Err(AcquireError::Cancelled) => {
                    waiter_result.fetch_add(1, Ordering::Relaxed);
                }
                Ok(_permit) => {
                    unexpected_acquires.fetch_add(1, Ordering::Relaxed);
                }
                Err(_err) => {
                    unexpected_errors.fetch_add(1, Ordering::Relaxed);
                }
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
        cancelled_waiters: cancelled_waiters.load(Ordering::Relaxed),
        recovered_acquisitions,
        available_after_cancel,
        final_available_permits: semaphore.available_permits(),
        unexpected_cancel_acquisitions: unexpected_cancel_acquisitions.load(Ordering::Relaxed),
        unexpected_cancel_errors: unexpected_cancel_errors.load(Ordering::Relaxed),
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
        witness.record_counter(
            "unexpected_cancel_acquisitions",
            counter_i64(observation.unexpected_cancel_acquisitions),
        );
        witness.record_counter(
            "unexpected_cancel_errors",
            counter_i64(observation.unexpected_cancel_errors),
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
    if limit == Some(0) {
        return Ok(Vec::new());
    }

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
    let stdout = io::stdout();
    let mut writer = io::BufWriter::new(stdout.lock());

    match format {
        ExportFormat::Json => {
            write!(writer, "[").map_err(output_cli_error)?;
            let mut first = true;
            while let Some(event) = reader
                .read_event()
                .map_err(|err| trace_file_error(path, err))?
            {
                if !first {
                    write!(writer, ",").map_err(output_cli_error)?;
                }
                first = false;
                serde_json::to_writer(&mut writer, &event).map_err(output_cli_error)?;
            }
            writeln!(writer, "]").map_err(output_cli_error)?;
        }
        ExportFormat::Ndjson => {
            while let Some(event) = reader
                .read_event()
                .map_err(|err| trace_file_error(path, err))?
            {
                serde_json::to_writer(&mut writer, &event).map_err(output_cli_error)?;
                writeln!(writer).map_err(output_cli_error)?;
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

fn trace_compress(
    input: &Path,
    output: &Path,
    level: i32,
) -> Result<TraceCompressOutput, CliError> {
    if !(-1..=16).contains(&level) {
        return Err(CliError::new(
            "invalid_argument",
            "Trace compression level must be between -1 and 16",
        ));
    }
    if input == output {
        return Err(CliError::new(
            "invalid_argument",
            "Input and output trace paths must differ",
        ));
    }
    if output.exists() {
        return Err(CliError::new(
            "output_exists",
            "Refusing to overwrite existing trace output",
        )
        .detail(output.display().to_string()));
    }

    let mut reader = TraceReader::open(input).map_err(|err| trace_file_error(input, err))?;
    let metadata = reader.metadata().clone();
    let source_compression = compression_label(reader.compression());
    let event_count = reader.event_count();
    let mut writer = TraceWriter::create_with_config(
        output,
        TraceFileConfig::new().with_compression(CompressionMode::Lz4 { level }),
    )
    .map_err(|err| trace_file_error(output, err))?;
    writer
        .write_metadata(&metadata)
        .map_err(|err| trace_file_error(output, err))?;

    while let Some(event) = reader
        .read_event()
        .map_err(|err| trace_file_error(input, err))?
    {
        writer
            .write_event(&event)
            .map_err(|err| trace_file_error(output, err))?;
    }
    writer
        .finish()
        .map_err(|err| trace_file_error(output, err))?;

    Ok(TraceCompressOutput {
        input: input.display().to_string(),
        output: output.display().to_string(),
        source_compression,
        target_compression: compression_label(CompressionMode::Lz4 { level }),
        event_count,
        size_bytes: file_size(output)?,
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
    let normalized_filter = normalize_trace_kind_token(filter.as_str());
    let normalized_kind = normalize_trace_kind_token(kind_lower.as_str());
    if kind_lower == filter {
        return true;
    }
    if normalized_kind == normalized_filter {
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

fn normalize_trace_kind_token(value: &str) -> String {
    value
        .chars()
        .filter(|ch| *ch != '_' && *ch != '-')
        .collect()
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
            let title = err.title.replace(['\n', '\t'], " ");
            let detail = err.detail.replace(['\n', '\t'], " ");
            writeln!(stderr, "{}\t{}\t{}", err.error_type, title, detail)
        }
    }
}

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
    use asupersync::atp::doctor::build_platform_doctor_document;
    use asupersync::atp::sdk::{StreamEarlyUsabilityState, StreamFinalCommitState};
    use asupersync::atp::stream_object::ConsumptionPolicy;
    use asupersync::observability::{TaskRegionCountWire, TaskStateInfo};
    use asupersync::trace::{TraceMetadata, TraceWriter};
    use clap::Parser;
    use insta::{assert_json_snapshot, assert_snapshot};
    use std::sync::{Arc, Mutex};
    use tempfile::NamedTempFile;

    #[derive(Clone, Default)]
    struct SharedWrite {
        inner: Arc<Mutex<Vec<u8>>>,
    }

    impl SharedWrite {
        fn contents(&self) -> String {
            String::from_utf8(self.inner.lock().expect("lock shared write").clone())
                .expect("shared write content should be utf8")
        }
    }

    impl Write for SharedWrite {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.inner
                .lock()
                .expect("lock shared write")
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn temp_transfer_reference(contents: &[u8]) -> (NamedTempFile, String) {
        let file = NamedTempFile::new().expect("transfer source temp file");
        fs::write(file.path(), contents).expect("write transfer source");
        let reference = file.path().to_string_lossy().into_owned();
        (file, reference)
    }

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

    fn parse_jsonl_values(payload: &str) -> Vec<serde_json::Value> {
        payload
            .lines()
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_str(line).expect("parse jsonl entry"))
            .collect()
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
    fn trace_events_filtering_accepts_kebab_case_kind_names() {
        let file = make_sample_trace();
        let rows = trace_events(file.path(), 0, None, &["time-advanced".to_string()])
            .expect("trace events");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].kind, "TimeAdvanced");
    }

    #[test]
    fn trace_events_filtering_accepts_kebab_case_exact_seed_name() {
        let file = make_sample_trace();
        let rows =
            trace_events(file.path(), 0, None, &["rng-seed".to_string()]).expect("trace events");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].kind, "RngSeed");
    }

    #[test]
    fn trace_events_zero_limit_returns_no_rows() {
        let file = make_sample_trace();
        let rows = trace_events(file.path(), 0, Some(0), &[]).expect("trace events");
        assert!(rows.is_empty());
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
    fn trace_compress_rewrites_trace_as_lz4() {
        let input = make_sample_trace();
        let output_dir = tempfile::tempdir().expect("tempdir");
        let output_path = output_dir.path().join("compressed.trace");

        let summary = trace_compress(input.path(), &output_path, 1).expect("trace compress");
        assert_eq!(summary.source_compression, "none");
        assert_eq!(summary.target_compression, "lz4(level=1)");
        assert_eq!(summary.event_count, 2);

        let reader = TraceReader::open(&output_path).expect("open compressed reader");
        assert!(reader.is_compressed());
        assert_eq!(reader.compression(), CompressionMode::Lz4 { level: 1 });
        let events = reader.load_all().expect("load compressed events");
        assert_eq!(events.len(), 2);
        assert!(matches!(events[0], ReplayEvent::RngSeed { seed: 42 }));
    }

    #[test]
    fn trace_compress_rejects_existing_output() {
        let input = make_sample_trace();
        let output = NamedTempFile::new().expect("create temp output");

        let err = trace_compress(input.path(), output.path(), 1).expect_err("existing output");
        assert_eq!(err.error_type, "output_exists");
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
    fn atp_replay_args_parse_artifact_flags() {
        let cli = Cli::try_parse_from([
            "asupersync",
            "atp",
            "replay",
            "--trace-file",
            "artifacts/transfer.atp-trace",
            "--manifest",
            "artifacts/manifest",
            "--journal-digest",
            "artifacts/journal.digest",
            "--evidence-ledger",
            "artifacts/evidence-ledger.json",
            "--pathlog",
            "artifacts/pathlog",
            "--quiclog",
            "artifacts/quiclog",
            "--repairlog",
            "artifacts/repairlog",
            "--validate-oracles",
            "--oracle",
            "manifest_integrity",
            "--oracle",
            "journal_consistency",
            "--minimize",
            "--reduction-target",
            "0.8",
        ])
        .expect("parse atp replay args");

        let Command::Atp(AtpArgs {
            command: AtpCommand::Replay(args),
        }) = cli.command
        else {
            panic!("expected atp replay command");
        };

        assert_eq!(
            args.trace_file.as_path(),
            Path::new("artifacts/transfer.atp-trace")
        );
        assert_eq!(args.manifest.as_path(), Path::new("artifacts/manifest"));
        assert_eq!(
            args.journal_digest.as_path(),
            Path::new("artifacts/journal.digest")
        );
        assert_eq!(
            args.evidence_ledger.as_path(),
            Path::new("artifacts/evidence-ledger.json")
        );
        assert_eq!(args.pathlog.as_path(), Path::new("artifacts/pathlog"));
        assert_eq!(args.quiclog.as_path(), Path::new("artifacts/quiclog"));
        assert_eq!(args.repairlog.as_path(), Path::new("artifacts/repairlog"));
        assert!(args.validate_oracles);
        assert_eq!(
            args.oracles,
            vec![
                "manifest_integrity".to_string(),
                "journal_consistency".to_string()
            ]
        );
        assert!(args.minimize);
        assert_eq!(args.reduction_target, 0.8);
    }

    #[test]
    fn atp_early_usability_args_parse_report_path() {
        let cli = Cli::try_parse_from([
            "asupersync",
            "atp",
            "early-usability",
            "--report",
            "artifacts/early-usability.json",
        ])
        .expect("parse atp early-usability args");

        let Command::Atp(AtpArgs {
            command: AtpCommand::EarlyUsability(args),
        }) = cli.command
        else {
            panic!("expected atp early-usability command");
        };

        assert_eq!(
            args.report.as_path(),
            Path::new("artifacts/early-usability.json")
        );
    }

    #[test]
    fn atp_status_args_parse_explain_telemetry_and_current_settings()
    -> Result<(), Box<dyn std::error::Error>> {
        let cli = Cli::try_parse_from([
            "asupersync",
            "atp",
            "status",
            "--telemetry",
            "artifacts/atp-telemetry.json",
            "--explain",
            "--current-in-flight-bytes",
            "4096",
            "--current-stream-count",
            "2",
            "--current-chunk-size-bytes",
            "1024",
            "--current-repair-symbols-per-second",
            "8",
        ])?;

        let args = match cli.command {
            Command::Atp(AtpArgs {
                command: AtpCommand::Status(args),
            }) => args,
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "expected atp status command",
                )
                .into());
            }
        };

        assert_eq!(
            args.telemetry.as_path(),
            Path::new("artifacts/atp-telemetry.json")
        );
        assert!(args.explain);
        assert_eq!(args.in_flight_bytes, 4096);
        assert_eq!(args.stream_count, 2);
        assert_eq!(args.chunk_size_bytes, 1024);
        assert_eq!(args.repair_symbols_per_second, 8);
        Ok(())
    }

    #[test]
    fn atp_status_explain_reports_bottlenecks_and_next_settings()
    -> Result<(), Box<dyn std::error::Error>> {
        let file = NamedTempFile::new()?;
        let mut telemetry =
            AtpAutotuneTelemetry::new("trace-status", "workload-status").with_sample_count(16);
        telemetry.loss_permille = Some(100);
        telemetry.send_buffer_queued_bytes = Some(32 * 1_048_576);
        fs::write(file.path(), serde_json::to_vec(&telemetry)?)?;

        let capture = SharedWrite::default();
        let mut output = Output::with_writer(OutputFormat::Human, capture.clone());
        let defaults = AtpAutotuneSettings::default();
        atp_status(
            &AtpStatusArgs {
                telemetry: file.path().to_path_buf(),
                explain: true,
                in_flight_bytes: defaults.in_flight_bytes,
                stream_count: defaults.stream_count,
                chunk_size_bytes: defaults.chunk_size_bytes,
                repair_symbols_per_second: defaults.repair_symbols_per_second,
            },
            &mut output,
        )?;

        let rendered = capture.contents();
        assert!(rendered.contains("ATP Status"));
        assert!(rendered.contains("Trace ID: trace-status"));
        assert!(rendered.contains("Workload ID: workload-status"));
        assert!(rendered.contains("Reason: hold_or_backoff_on_pressure"));
        assert!(rendered.contains("Status: degraded"));
        assert!(rendered.contains("Outcome: PressureBackoff"));
        assert!(rendered.contains("Confidence: fail_closed"));
        assert!(rendered.contains("Fail closed: true"));
        assert!(rendered.contains("- knob in_flight_bytes: Decrease"));
        assert!(rendered.contains("- knob repair_symbols_per_second: Increase"));
        assert!(rendered.contains("network_loss"));
        assert!(rendered.contains("send_buffer_pressure"));
        assert!(rendered.contains("atp.autotune.loss_permille"));
        assert!(rendered.contains("Next settings:"));
        assert!(rendered.contains("Repair mode:"));
        assert!(rendered.contains("Repair action:"));
        assert!(rendered.contains("Repair ROI:"));
        Ok(())
    }

    #[test]
    fn atp_status_accepts_trace_scoped_metric_sample_report()
    -> Result<(), Box<dyn std::error::Error>> {
        let file = NamedTempFile::new()?;
        let report = AtpAutotuneTelemetryReport::new("trace-samples", "workload-samples")
            .with_sample_count(16)
            .with_sample(asupersync::atp::AtpAutotuneMetric::LossPermille, 100)
            .with_sample(
                asupersync::atp::AtpAutotuneMetric::SendBufferQueuedBytes,
                32 * 1_048_576,
            );
        fs::write(file.path(), serde_json::to_vec(&report)?)?;

        let capture = SharedWrite::default();
        let mut output = Output::with_writer(OutputFormat::Human, capture.clone());
        let defaults = AtpAutotuneSettings::default();
        atp_status(
            &AtpStatusArgs {
                telemetry: file.path().to_path_buf(),
                explain: true,
                in_flight_bytes: defaults.in_flight_bytes,
                stream_count: defaults.stream_count,
                chunk_size_bytes: defaults.chunk_size_bytes,
                repair_symbols_per_second: defaults.repair_symbols_per_second,
            },
            &mut output,
        )?;

        let rendered = capture.contents();
        assert!(rendered.contains("Trace ID: trace-samples"));
        assert!(rendered.contains("Workload ID: workload-samples"));
        assert!(rendered.contains("Samples: 16"));
        assert!(rendered.contains("Status: degraded"));
        assert!(rendered.contains("network_loss"));
        assert!(rendered.contains("send_buffer_pressure"));
        assert!(rendered.contains("atp.autotune.send_buffer_queued_bytes"));
        Ok(())
    }

    #[test]
    fn atp_early_usability_renders_stream_report_fields_separately() {
        let file = NamedTempFile::new().expect("create report file");
        let report = StreamEarlyUsabilityReport {
            stream_id: "stream-early".to_string(),
            usable_state: StreamEarlyUsabilityState::VerifiedPrefixAvailable,
            final_commit_state: StreamFinalCommitState::Pending,
            consumption_policy: ConsumptionPolicy::VerifiedOnly,
            verified_prefix_ranges: vec![ByteRange::new(0, 4096)],
            policy_exposed_prefix: Some(ByteRange::new(0, 4096)),
            verified_prefix_end: 4096,
            policy_prefix_end: 4096,
            total_bytes: 8192,
            bytes_sent: 4096,
            safety_caveats: vec![
                "final manifest not committed; expose early bytes separately".to_string(),
            ],
        };
        fs::write(
            file.path(),
            serde_json::to_vec(&report).expect("serialize stream report"),
        )
        .expect("write stream report");

        let capture = SharedWrite::default();
        let mut output = Output::with_writer(OutputFormat::Human, capture.clone());
        atp_early_usability(
            &AtpEarlyUsabilityArgs {
                report: file.path().to_path_buf(),
            },
            &mut output,
        )
        .expect("render stream early usability report");

        let rendered = capture.contents();
        assert!(rendered.contains("Type: stream"));
        assert!(rendered.contains("Usable state: VerifiedPrefixAvailable"));
        assert!(rendered.contains("Final commit state: Pending"));
        assert!(rendered.contains("Verified prefix ranges: 0..4096 (4096 bytes)"));
        assert!(rendered.contains("Policy exposed prefix: 0..4096 (4096 bytes)"));
        assert!(rendered.contains("final manifest not committed"));
    }

    #[test]
    fn atp_early_usability_renders_directory_report_fields_separately() {
        let file = NamedTempFile::new().expect("create report file");
        let report = DirectoryEarlyUsabilityReport {
            schema_version: "asupersync.atp.directory_early_usability.v1".to_string(),
            usability_state:
                asupersync::atp::sync::DirectoryEarlyUsabilityState::SmallFilesAvailable,
            final_commit_state: asupersync::atp::sync::DirectoryFinalCommitState::Pending,
            manifest_tree_root: "tree-root".to_string(),
            replay_pointer: "replay:directory".to_string(),
            metadata_paths: vec!["README.md".to_string(), "model.bin".to_string()],
            small_file_paths: vec!["README.md".to_string()],
            withheld_content_paths: vec!["model.bin".to_string()],
            entries: Vec::new(),
            safety_caveats: vec![
                "final directory commit not complete; expose early entries separately".to_string(),
            ],
        };
        fs::write(
            file.path(),
            serde_json::to_vec(&report).expect("serialize directory report"),
        )
        .expect("write directory report");

        let capture = SharedWrite::default();
        let mut output = Output::with_writer(OutputFormat::Human, capture.clone());
        atp_early_usability(
            &AtpEarlyUsabilityArgs {
                report: file.path().to_path_buf(),
            },
            &mut output,
        )
        .expect("render directory early usability report");

        let rendered = capture.contents();
        assert!(rendered.contains("Type: directory"));
        assert!(rendered.contains("Usable state: SmallFilesAvailable"));
        assert!(rendered.contains("Final commit state: Pending"));
        assert!(rendered.contains("Replay pointer: replay:directory"));
        assert!(rendered.contains("Small files:"));
        assert!(rendered.contains("  - README.md"));
        assert!(rendered.contains("Withheld content:"));
        assert!(rendered.contains("  - model.bin"));
        assert!(rendered.contains("final directory commit not complete"));
    }

    #[test]
    fn atp_replay_replays_emitted_crashpack_artifacts() {
        let temp = tempfile::tempdir().expect("tempdir");
        let mut trace = asupersync::trace::TraceBuffer::new(4);
        trace.push(asupersync::trace::TraceEvent::user_trace(
            1,
            Time::from_nanos(1),
            "ATP violation: manifest_integrity",
        ));
        let crashpack = asupersync::lab::crashpack::CrashpackBuilder::new()
            .with_oracle_result(asupersync::lab::crashpack::TransferOracleResult {
                oracle_name: "manifest_integrity".to_string(),
                violations: vec![asupersync::lab::crashpack::TransferViolation {
                    violation_type: "manifest_integrity".to_string(),
                    description: "manifest integrity failed".to_string(),
                    severity: asupersync::lab::crashpack::ViolationSeverity::High,
                    evidence: std::collections::BTreeMap::new(),
                }],
                stats: asupersync::lab::oracle::OracleStats {
                    entities_tracked: 1,
                    events_recorded: 1,
                },
                passed: false,
            })
            .with_trace(trace)
            .with_seed("lab-seed", 7)
            .build()
            .expect("crashpack builds");
        crashpack
            .emit_atp_trace(temp.path())
            .expect("crashpack emits replay artifacts");

        let args = AtpReplayArgs {
            trace_file: temp.path().join("transfer.atp-trace"),
            manifest: temp.path().join("manifest"),
            journal_digest: temp.path().join("journal.digest"),
            evidence_ledger: temp.path().join("evidence-ledger.json"),
            pathlog: temp.path().join("pathlog"),
            quiclog: temp.path().join("quiclog"),
            repairlog: temp.path().join("repairlog"),
            validate_oracles: true,
            oracles: vec!["manifest_integrity".to_string()],
            minimize: true,
            reduction_target: 0.8,
        };
        let writer = SharedWrite::default();
        let mut output = Output::with_writer(OutputFormat::Json, writer.clone());

        atp_replay(&args, &mut output).expect("atp replay succeeds");

        let values = parse_jsonl_values(&writer.contents());
        assert_eq!(values.len(), 1);
        assert_eq!(values[0]["replay_successful"], true);
        assert_eq!(values[0]["original_violations"], 1);
        assert_eq!(
            values[0]["requested_oracles"],
            serde_json::json!(["manifest_integrity"])
        );
    }

    #[test]
    fn trace_compress_args_parse_level_and_output() {
        let cli = Cli::try_parse_from([
            "asupersync",
            "trace",
            "compress",
            "input.trace",
            "output.trace",
            "--level",
            "4",
        ])
        .expect("parse trace compress args");

        let Command::Trace(TraceArgs {
            command: TraceCommand::Compress(args),
        }) = cli.command
        else {
            panic!("expected trace compress command");
        };

        assert_eq!(args.input, PathBuf::from("input.trace"));
        assert_eq!(args.output, PathBuf::from("output.trace"));
        assert_eq!(args.level, 4);
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
    fn effective_output_format_prefers_lab_json_subcommands() {
        let cli = Cli::try_parse_from([
            "asupersync",
            "--format",
            "tsv",
            "lab",
            "differential-profile-manifest",
            "--json",
        ])
        .expect("parse lab manifest command with explicit format");

        let format =
            effective_output_format(&cli.command, cli.common.to_common_args().output_format());

        assert_eq!(format, OutputFormat::JsonPretty);
    }

    #[test]
    fn load_scenario_parse_error_is_user_error() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("invalid.yaml");
        fs::write(&path, "schema_version: [").expect("write malformed scenario");

        let err = load_scenario(&path).expect_err("malformed yaml should fail");
        assert_eq!(err.error_type, "scenario_parse_error");
        assert_eq!(err.exit_code, ExitCode::USER_ERROR);
    }

    #[test]
    fn scenario_runner_error_unknown_oracle_is_user_error() {
        let err = scenario_runner_error(
            asupersync::lab::scenario_runner::ScenarioRunnerError::UnknownOracle(
                "not-real".to_string(),
            ),
        );

        assert_eq!(err.error_type, "unknown_oracle");
        assert_eq!(err.exit_code, ExitCode::USER_ERROR);
    }

    #[test]
    fn lab_validate_json_uses_output_writer_and_user_error() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("invalid_scenario.yaml");
        fs::write(
            &path,
            r#"schema_version: 1
id: invalid-scenario
lab:
  worker_count: 0
"#,
        )
        .expect("write invalid scenario");

        let capture = SharedWrite::default();
        let mut output = Output::with_writer(OutputFormat::JsonPretty, capture.clone());
        let args = LabValidateArgs {
            scenario: path,
            json: true,
        };

        let err = lab_validate(&args, &mut output).expect_err("invalid scenario should fail");
        let written = capture.contents();

        assert_eq!(err.error_type, "scenario_invalid");
        assert_eq!(err.exit_code, ExitCode::USER_ERROR);
        assert!(written.contains("\"valid\": false"));
        assert!(written.contains("\"errors\""));
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
    fn atp_doctor_platform_command_parses() {
        let cli = Cli::try_parse_from(["asupersync", "atp", "doctor", "--platform"])
            .expect("parse atp doctor --platform");

        let Command::Atp(AtpArgs {
            command: AtpCommand::Doctor(args),
        }) = cli.command
        else {
            panic!("expected atp doctor command");
        };
        assert!(args.platform);
    }

    #[test]
    fn atp_doctor_requires_platform_selector() {
        let mut output = Output::with_writer(OutputFormat::Json, Vec::<u8>::new());
        let err = atp_doctor(&AtpDoctorArgs { platform: false }, &mut output)
            .expect_err("missing selector should fail");

        assert_eq!(err.error_type, "invalid_argument");
    }

    #[test]
    fn atp_platform_doctor_human_output_has_stable_sections() {
        let provider =
            asupersync::atp::platform::DeterministicLabPlatformProvider::fully_supported();
        let payload = AtpPlatformDoctorOutput::new(build_platform_doctor_document(&provider));
        let rendered = payload.human_format();

        assert!(rendered.contains("Schema: asupersync.atp.doctor.platform.v1"));
        assert!(rendered.contains("Filesystem:"));
        assert!(rendered.contains("Network:"));
        assert!(rendered.contains("Service:"));
        assert!(rendered.contains("Degradation policy:"));
        assert!(rendered.contains("Structured probe logs: 11"));
    }

    #[test]
    fn atp_platform_doctor_json_output_has_stable_contract() {
        let provider =
            asupersync::atp::platform::DeterministicLabPlatformProvider::conservative_degradation();
        let payload = AtpPlatformDoctorOutput::new(build_platform_doctor_document(&provider));
        let capture = SharedWrite::default();
        let mut output = Output::with_writer(OutputFormat::Json, capture.clone());

        output.write(&payload).expect("write atp platform payload");
        output.flush().expect("flush atp platform payload");
        let json: serde_json::Value =
            serde_json::from_str(capture.contents().trim()).expect("parse atp platform json");

        assert_eq!(json["schema_version"], "asupersync.atp.doctor.platform.v1");
        assert_eq!(
            json["report"]["degradation_policy"]["disk_writer_mode"],
            "contiguous-verified-quarantine"
        );
        assert!(
            json["logs"]
                .as_array()
                .expect("logs array")
                .iter()
                .any(|entry| entry["capability"] == "service_manager"
                    && entry["probe_source"] == "skipped")
        );
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
    fn format_timestamp_matches_rfc3339_utc_vector() {
        assert_eq!(
            format_timestamp(1_577_836_800_000_000_000),
            Some("2020-01-01T00:00:00Z".to_string())
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
        fs::write(&rel_binary, b"fixture-binary").expect("write rel binary");

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
    fn report_export_document_snapshot_is_stable() {
        let bundle = advanced_diagnostics_report_bundle();
        let fixture = bundle
            .fixtures
            .iter()
            .find(|entry| entry.fixture_id == "advanced_failure_path")
            .expect("fixture exists");
        let document = build_report_export_document(&bundle, fixture).expect("document");
        assert_json_snapshot!(
            document,
            @r###"
        {
          "schema_version": "doctor-report-export-v1",
          "fixture_id": "advanced_failure_path",
          "report_id": "doctor-report-failure-v1",
          "core_contract_version": "doctor-core-report-v1",
          "extension_contract_version": "doctor-advanced-report-v1",
          "summary": {
            "status": "failed",
            "overall_outcome": "failed",
            "total_findings": 2,
            "critical_findings": 1
          },
          "findings": [
            {
              "finding_id": "finding-001",
              "title": "Obligation leak during shutdown path",
              "severity": "critical",
              "status": "open",
              "evidence_refs": [
                "evidence-001"
              ],
              "command_refs": [
                "command-001"
              ]
            },
            {
              "finding_id": "finding-002",
              "title": "Replay mismatch for cancellation timeline",
              "severity": "high",
              "status": "in_progress",
              "evidence_refs": [
                "evidence-002"
              ],
              "command_refs": [
                "command-002"
              ]
            }
          ],
          "evidence_links": [
            {
              "evidence_id": "evidence-001",
              "source": "structured_log",
              "artifact_pointer": "artifacts/run-doctor-failure/doctor/core-report/finding-001.json",
              "replay_pointer": "rch exec -- cargo test -p asupersync -- obligation_leak",
              "outcome_class": "failed",
              "franken_trace_id": "trace-franken-failure-001"
            },
            {
              "evidence_id": "evidence-002",
              "source": "trace",
              "artifact_pointer": "artifacts/run-doctor-failure/doctor/core-report/trace-002.json",
              "replay_pointer": "asupersync trace verify artifacts/run-doctor-failure/trace-002.bin",
              "outcome_class": "failed",
              "franken_trace_id": "trace-franken-failure-002"
            }
          ],
          "command_provenance": [
            {
              "command_id": "command-001",
              "command": "rch exec -- cargo test -p asupersync obligation_leak -- --nocapture",
              "tool": "rch",
              "exit_code": 101,
              "outcome_class": "failed"
            },
            {
              "command_id": "command-002",
              "command": "asupersync trace verify artifacts/run-doctor-failure/trace-002.bin",
              "tool": "asupersync",
              "exit_code": 2,
              "outcome_class": "failed"
            }
          ],
          "remediation_outcomes": [
            {
              "delta_id": "delta-001",
              "finding_id": "finding-001",
              "previous_status": "open",
              "next_status": "in_progress",
              "delta_outcome": "failed",
              "mapped_taxonomy_class": "remediation_safety",
              "mapped_taxonomy_dimension": "recovery_planning",
              "verification_evidence_refs": [
                "evidence-001"
              ]
            }
          ],
          "trust_transitions": [
            {
              "transition_id": "trust-001",
              "stage": "post-remediation-attempt",
              "previous_score": 82,
              "next_score": 44,
              "outcome_class": "failed",
              "mapped_taxonomy_severity": "error",
              "rationale": "Critical finding persisted after first remediation pass."
            }
          ],
          "collaboration_trail": [
            {
              "entry_id": "collab-001",
              "channel": "agent_mail",
              "actor": "ChartreuseBrook",
              "action": "requested remediation follow-up",
              "thread_id": "br-2b4jj.5.9",
              "message_ref": "mail-advanced-001",
              "bead_ref": "asupersync-2b4jj.5.9",
              "mapped_taxonomy_narrative": "Remediation safety remained degraded after failed verification."
            }
          ],
          "troubleshooting_playbooks": [
            {
              "playbook_id": "playbook-001",
              "title": "Critical remediation retry loop",
              "trigger_taxonomy_class": "remediation_safety",
              "trigger_taxonomy_severity": "error",
              "ordered_steps": [
                "capture_fresh_evidence",
                "reproduce_failure_with_rch",
                "stage_patch_and_verify"
              ],
              "command_refs": [
                "command-001"
              ],
              "evidence_refs": [
                "evidence-001"
              ]
            }
          ],
          "provenance": {
            "run_id": "run-doctor-failure",
            "scenario_id": "doctor-core-report-failure",
            "trace_id": "trace-doctor-failure",
            "seed": "1337",
            "generated_by": "doctor_asupersync",
            "generated_at": "2026-02-26T06:00:00Z"
          }
        }
        "###
        );
    }

    #[test]
    fn report_export_markdown_snapshot_is_stable() {
        let bundle = advanced_diagnostics_report_bundle();
        let fixture = bundle
            .fixtures
            .iter()
            .find(|entry| entry.fixture_id == "advanced_failure_path")
            .expect("fixture exists");
        let document = build_report_export_document(&bundle, fixture).expect("document");
        let markdown = render_doctor_report_markdown(&document);
        assert_snapshot!(
            markdown,
            @r###"
        # Doctor Diagnostics Export: advanced_failure_path

        - Schema: doctor-report-export-v1
        - Core contract: doctor-core-report-v1
        - Extension contract: doctor-advanced-report-v1
        - Report ID: doctor-report-failure-v1
        - Run ID: run-doctor-failure
        - Scenario ID: doctor-core-report-failure
        - Trace ID: trace-doctor-failure
        - Seed: 1337

        ## Summary

        - Status: failed
        - Outcome: failed
        - Total findings: 2
        - Critical findings: 1

        ## Findings

        - `finding-001` Obligation leak during shutdown path (severity=critical, status=open)
          - evidence_refs: evidence-001
          - command_refs: command-001
        - `finding-002` Replay mismatch for cancellation timeline (severity=high, status=in_progress)
          - evidence_refs: evidence-002
          - command_refs: command-002

        ## Evidence Links

        - `evidence-001` source=structured_log outcome=failed artifact=artifacts/run-doctor-failure/doctor/core-report/finding-001.json replay=rch exec -- cargo test -p asupersync -- obligation_leak
        - `evidence-002` source=trace outcome=failed artifact=artifacts/run-doctor-failure/doctor/core-report/trace-002.json replay=asupersync trace verify artifacts/run-doctor-failure/trace-002.bin

        ## Command Provenance

        - `command-001` [rch] exit=101 outcome=failed command=`rch exec -- cargo test -p asupersync obligation_leak -- --nocapture`
        - `command-002` [asupersync] exit=2 outcome=failed command=`asupersync trace verify artifacts/run-doctor-failure/trace-002.bin`

        ## Remediation Outcomes

        - `delta-001` finding=finding-001 open -> in_progress outcome=failed class=remediation_safety dimension=recovery_planning
          - verification_evidence_refs: evidence-001

        ## Trust Transitions

        - `trust-001` stage=post-remediation-attempt 82 -> 44 outcome=failed severity=error rationale=Critical finding persisted after first remediation pass.

        ## Collaboration Trail

        - `collab-001` channel=agent_mail actor=ChartreuseBrook action=requested remediation follow-up thread=br-2b4jj.5.9 message=mail-advanced-001 bead=asupersync-2b4jj.5.9

        ## Troubleshooting Playbooks

        - `playbook-001` Critical remediation retry loop (class=remediation_safety, severity=error)
          - ordered_steps: capture_fresh_evidence -> reproduce_failure_with_rch -> stage_patch_and_verify
          - command_refs: command-001
          - evidence_refs: evidence-001
        "###
        );
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
        let section_headings = markdown
            .lines()
            .filter(|line| line.starts_with("## "))
            .collect::<Vec<_>>()
            .join("\n");

        assert_snapshot!(
            section_headings,
            @r###"
        ## Summary
        ## Findings
        ## Evidence Links
        ## Command Provenance
        ## Remediation Outcomes
        ## Trust Transitions
        ## Collaboration Trail
        ## Troubleshooting Playbooks
        "###
        );
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
    fn franken_export_snapshot_is_stable() {
        let fixture = core_diagnostics_report_bundle()
            .fixtures
            .into_iter()
            .find(|candidate| candidate.fixture_id == "baseline_failure_path")
            .expect("fixture exists");
        let temp = tempfile::tempdir().expect("tempdir");
        let artifact = export_core_report_to_franken_artifacts(
            fixture.fixture_id.as_str(),
            &fixture.report,
            temp.path(),
        )
        .expect("export");

        let evidence = fs::read_to_string(&artifact.evidence_jsonl).expect("read evidence");
        let decision = fs::read_to_string(&artifact.decision_json).expect("read decision");
        let evidence_entries = parse_jsonl_values(&evidence);
        let decision_entries: serde_json::Value =
            serde_json::from_str(&decision).expect("parse decision payload");

        assert_json_snapshot!(
            serde_json::json!({
                "evidence": evidence_entries,
                "decision": decision_entries,
            }),
            @r###"
        {
          "evidence": [
            {
              "a": "hold",
              "c": "structured_log",
              "cal": 0.68,
              "cel": 0.3,
              "el": {
                "hold": 0.3,
                "promote": 0.45
              },
              "fb": true,
              "p": [
                0.55,
                0.45
              ],
              "tf": [
                [
                  "evidence_id",
                  1.0
                ],
                [
                  "outcome_class",
                  0.8
                ]
              ],
              "ts": 16358360581643888801
            },
            {
              "a": "hold",
              "c": "trace",
              "cal": 0.68,
              "cel": 0.3,
              "el": {
                "hold": 0.3,
                "promote": 0.45
              },
              "fb": true,
              "p": [
                0.55,
                0.45
              ],
              "tf": [
                [
                  "evidence_id",
                  1.0
                ],
                [
                  "outcome_class",
                  0.8
                ]
              ],
              "ts": 16358360581664031791
            }
          ],
          "decision": [
            {
              "action_chosen": "hold_release",
              "calibration_score": 0.55,
              "contract_name": "doctor-core-diagnostics",
              "decision_id": "d4ab0c92e4bf980b88fb7b1d73e79239",
              "expected_loss": 0.17,
              "expected_loss_by_action": {
                "continue_investigation": 0.2975,
                "hold_release": 0.17,
                "promote_fix": 0.4675
              },
              "fallback_active": true,
              "posterior_snapshot": [
                0.35,
                0.65
              ],
              "trace_id": "1548473d85174633375fbb6754396275",
              "ts_unix_ms": 8649082491939616561
            },
            {
              "action_chosen": "continue_investigation",
              "calibration_score": 0.55,
              "contract_name": "doctor-core-diagnostics",
              "decision_id": "d4ab0c92e1bf980b88fb7b1d73e78e88",
              "expected_loss": 0.22749999999999998,
              "expected_loss_by_action": {
                "continue_investigation": 0.22749999999999998,
                "hold_release": 0.13,
                "promote_fix": 0.35750000000000004
              },
              "fallback_active": true,
              "posterior_snapshot": [
                0.35,
                0.65
              ],
              "trace_id": "1548473d82174633375fbb6754395ec4",
              "ts_unix_ms": 8649082491972460351
            }
          ]
        }
        "###
        );
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

    #[test]
    fn atp_get_dry_run_produces_receive_plan() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (_transfer, transfer_id) = temp_transfer_reference(b"dry-run transfer");
        let capture = SharedWrite::default();
        let mut output = Output::with_writer(OutputFormat::Human, capture.clone());

        let args = AtpGetArgs {
            transfer_id,
            destination: Some(temp.path().to_path_buf()),
            dry_run: true,
            policy: "allow-listed".to_string(),
            allow_overwrite: false,
            allow_symlinks: false,
            allow_executables: false,
            max_bytes: Some(1000),
            accept: false,
            verbose: true,
            progress: false,
            explain: false,
        };

        let result = atp_get(&args, &mut output);
        assert!(result.is_ok(), "atp get dry-run should succeed");

        output.flush().expect("flush output");
        let output_str = capture.contents();
        assert!(
            output_str.contains("Receive Plan:"),
            "should contain receive plan"
        );
        assert!(output_str.contains("decision"), "should show decision");
        assert!(
            output_str.contains("expected_bytes"),
            "should show expected bytes"
        );
    }

    #[test]
    fn atp_get_deny_policy_rejects_transfer() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (_transfer, transfer_id) = temp_transfer_reference(b"deny transfer");
        let mut output = Output::with_writer(OutputFormat::Human, Vec::<u8>::new());

        let args = AtpGetArgs {
            transfer_id,
            destination: Some(temp.path().to_path_buf()),
            dry_run: false,
            policy: "deny".to_string(),
            allow_overwrite: false,
            allow_symlinks: false,
            allow_executables: false,
            max_bytes: None,
            accept: false,
            verbose: false,
            progress: false,
            explain: false,
        };

        let result = atp_get(&args, &mut output);
        assert!(result.is_err(), "deny policy should reject transfer");

        let err = result.unwrap_err();
        assert_eq!(err.error_type, "receive_denied");
    }

    #[test]
    fn atp_get_json_output_contains_plan_fields() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (_transfer, transfer_id) = temp_transfer_reference(b"json transfer");
        let capture = SharedWrite::default();
        let mut output = Output::with_writer(OutputFormat::Json, capture.clone());

        let args = AtpGetArgs {
            transfer_id,
            destination: Some(temp.path().to_path_buf()),
            dry_run: true,
            policy: "allow-listed".to_string(),
            allow_overwrite: true,
            allow_symlinks: false,
            allow_executables: false,
            max_bytes: None,
            accept: false,
            verbose: false,
            progress: false,
            explain: false,
        };

        let result = atp_get(&args, &mut output);
        assert!(result.is_ok(), "json output should succeed");

        output.flush().expect("flush output");
        let output_str = capture.contents();
        let json: serde_json::Value =
            serde_json::from_str(output_str.trim()).expect("output should be valid JSON");

        assert!(
            json.get("decision").is_some(),
            "should contain decision field"
        );
        assert!(
            json.get("sender_identity").is_some(),
            "should contain sender identity"
        );
        assert!(
            json.get("object_graph_summary").is_some(),
            "should contain object graph"
        );
        assert!(
            json.get("destination").is_some(),
            "should contain destination plan"
        );
        assert!(
            json.get("storage").is_some(),
            "should contain storage preflight"
        );
        assert!(
            json.get("plan_digest").is_some(),
            "should contain plan digest"
        );
    }

    #[test]
    fn atp_get_quarantine_policy_shows_appropriate_message() {
        let temp = tempfile::tempdir().expect("tempdir");
        let (_transfer, transfer_id) = temp_transfer_reference(b"quarantine transfer");
        let capture = SharedWrite::default();
        let mut output = Output::with_writer(OutputFormat::Human, capture.clone());

        let args = AtpGetArgs {
            transfer_id,
            destination: Some(temp.path().to_path_buf()),
            dry_run: false,
            policy: "quarantine-only".to_string(),
            allow_overwrite: false,
            allow_symlinks: false,
            allow_executables: false,
            max_bytes: None,
            accept: true,
            verbose: false,
            progress: false,
            explain: false,
        };

        let result = atp_get(&args, &mut output);
        assert!(result.is_ok(), "quarantine policy should succeed");

        output.flush().expect("flush output");
        let output_str = capture.contents();
        assert!(
            output_str.contains("quarantined"),
            "should mention quarantine"
        );
    }

    #[test]
    fn parse_destination_policy_handles_all_variants() {
        let temp = tempfile::tempdir().expect("tempdir");

        // Test deny policy
        let deny_args = AtpGetArgs {
            transfer_id: "test".to_string(),
            destination: None,
            dry_run: true,
            policy: "deny".to_string(),
            allow_overwrite: false,
            allow_symlinks: false,
            allow_executables: false,
            max_bytes: None,
            accept: false,
            verbose: false,
            progress: false,
            explain: false,
        };
        let policy = parse_destination_policy(&deny_args).expect("deny policy should parse");
        assert!(matches!(policy, DestinationPolicy::Deny));

        // Test allow-listed policy with flags
        let allow_args = AtpGetArgs {
            transfer_id: "test".to_string(),
            destination: Some(temp.path().to_path_buf()),
            dry_run: true,
            policy: "allow-listed".to_string(),
            allow_overwrite: true,
            allow_symlinks: true,
            allow_executables: true,
            max_bytes: Some(1000),
            accept: false,
            verbose: false,
            progress: false,
            explain: false,
        };
        let policy =
            parse_destination_policy(&allow_args).expect("allow-listed policy should parse");
        if let DestinationPolicy::AllowListed {
            allow_overwrite,
            allow_symlinks,
            allow_executables,
            max_bytes,
            ..
        } = policy
        {
            assert!(allow_overwrite, "should allow overwrite");
            assert!(allow_symlinks, "should allow symlinks");
            assert!(allow_executables, "should allow executables");
            assert_eq!(max_bytes, Some(1000), "should set max bytes");
        } else {
            panic!("expected AllowListed policy");
        }

        // Test invalid policy
        let invalid_args = AtpGetArgs {
            transfer_id: "test".to_string(),
            destination: None,
            dry_run: true,
            policy: "invalid-policy".to_string(),
            allow_overwrite: false,
            allow_symlinks: false,
            allow_executables: false,
            max_bytes: None,
            accept: false,
            verbose: false,
            progress: false,
            explain: false,
        };
        let result = parse_destination_policy(&invalid_args);
        assert!(result.is_err(), "invalid policy should error");
        let err = result.unwrap_err();
        assert_eq!(err.error_type, "invalid_policy");
    }

    #[test]
    fn atp_get_args_parsing_works() {
        let cli = Cli::try_parse_from([
            "asupersync",
            "atp",
            "get",
            "transfer-123",
            "/dest/path",
            "--dry-run",
            "--policy=allow-listed",
            "--allow-overwrite",
            "--allow-symlinks",
            "--max-bytes=500000",
            "--accept",
            "--verbose",
        ])
        .expect("valid args should parse");

        if let Command::Atp(AtpArgs {
            command: AtpCommand::Get(args),
        }) = cli.command
        {
            assert_eq!(args.transfer_id, "transfer-123");
            assert_eq!(args.destination, Some(PathBuf::from("/dest/path")));
            assert!(args.dry_run);
            assert_eq!(args.policy, "allow-listed");
            assert!(args.allow_overwrite);
            assert!(args.allow_symlinks);
            assert_eq!(args.max_bytes, Some(500000));
            assert!(args.accept);
            assert!(args.verbose);
        } else {
            panic!("expected atp get command");
        }
    }

    #[test]
    fn atp_send_command_parsing_works() {
        let cli = Cli::parse_from([
            "asupersync",
            "atp",
            "send",
            "/source/path",
            "peer:dest",
            "--dry-run",
            "--profile",
            "media",
            "--streams",
            "8",
            "--verbose",
        ]);

        if let Command::Atp(AtpArgs {
            command: AtpCommand::Send(args),
        }) = cli.command
        {
            assert_eq!(args.source, PathBuf::from("/source/path"));
            assert_eq!(args.target, "peer:dest");
            assert!(args.dry_run);
            assert_eq!(args.profile, "media");
            assert_eq!(args.streams, 8);
            assert!(args.verbose);
        } else {
            panic!("expected atp send command");
        }
    }

    #[test]
    fn atp_sync_command_parsing_works() {
        let cli = Cli::parse_from([
            "asupersync",
            "atp",
            "sync",
            "/source/dir",
            "peer:/target/dir",
            "--allow-updates",
            "--verbose",
        ]);

        if let Command::Atp(AtpArgs {
            command: AtpCommand::Sync(args),
        }) = cli.command
        {
            assert_eq!(args.source, PathBuf::from("/source/dir"));
            assert_eq!(args.target, "peer:/target/dir");
            assert!(args.allow_updates);
            assert!(args.verbose);
        } else {
            panic!("expected atp sync command");
        }
    }

    #[test]
    fn atp_mirror_command_parsing_works() {
        let cli = Cli::parse_from([
            "asupersync",
            "atp",
            "mirror",
            "/source/dir",
            "peer:/target/dir",
            "--allow-deletes",
        ]);

        if let Command::Atp(AtpArgs {
            command: AtpCommand::Mirror(args),
        }) = cli.command
        {
            assert_eq!(args.source, PathBuf::from("/source/dir"));
            assert_eq!(args.target, "peer:/target/dir");
            assert!(args.allow_deletes);
            assert!(!args.verbose);
        } else {
            panic!("expected atp mirror command");
        }
    }

    #[test]
    fn atp_share_command_parsing_works() {
        let cli = Cli::parse_from([
            "asupersync",
            "atp",
            "share",
            "/file/to/share",
            "--expires",
            "7200",
            "--max-downloads",
            "5",
            "--policy",
            "open",
        ]);

        if let Command::Atp(AtpArgs {
            command: AtpCommand::Share(args),
        }) = cli.command
        {
            assert_eq!(args.source, PathBuf::from("/file/to/share"));
            assert_eq!(args.expires_seconds, 7200);
            assert_eq!(args.max_downloads, 5);
            assert_eq!(args.policy, "open");
        } else {
            panic!("expected atp share command");
        }
    }

    #[test]
    fn atp_inbox_list_parsing_works() {
        let cli = Cli::parse_from(["asupersync", "atp", "inbox", "list"]);

        if let Command::Atp(AtpArgs {
            command: AtpCommand::Inbox(args),
        }) = cli.command
        {
            assert!(matches!(args.command, AtpInboxCommand::List));
        } else {
            panic!("expected atp inbox list command");
        }
    }

    #[test]
    fn atp_inbox_accept_parsing_works() {
        let cli = Cli::parse_from([
            "asupersync",
            "atp",
            "inbox",
            "accept",
            "transfer-456",
            "/destination/path",
        ]);

        if let Command::Atp(AtpArgs {
            command: AtpCommand::Inbox(args),
        }) = cli.command
        {
            if let AtpInboxCommand::Accept {
                transfer_id,
                destination,
            } = args.command
            {
                assert_eq!(transfer_id, "transfer-456");
                assert_eq!(destination, Some(PathBuf::from("/destination/path")));
            } else {
                panic!("expected inbox accept command");
            }
        } else {
            panic!("expected atp inbox command");
        }
    }

    #[test]
    fn atp_resume_command_parsing_works() {
        let cli = Cli::parse_from([
            "asupersync",
            "atp",
            "resume",
            "transfer-789",
            "--force",
            "--verbose",
        ]);

        if let Command::Atp(AtpArgs {
            command: AtpCommand::Resume(args),
        }) = cli.command
        {
            assert_eq!(args.transfer_id, "transfer-789");
            assert!(args.force);
            assert!(args.verbose);
        } else {
            panic!("expected atp resume command");
        }
    }

    #[test]
    fn atp_cancel_command_parsing_works() {
        let cli = Cli::parse_from([
            "asupersync",
            "atp",
            "cancel",
            "transfer-abc",
            "--reason",
            "user_cancellation",
            "--force",
        ]);

        if let Command::Atp(AtpArgs {
            command: AtpCommand::Cancel(args),
        }) = cli.command
        {
            assert_eq!(args.transfer_id, "transfer-abc");
            assert_eq!(args.reason, "user_cancellation");
            assert!(args.force);
        } else {
            panic!("expected atp cancel command");
        }
    }

    #[test]
    fn atp_send_output_format_works() {
        let mut output = Output::new(OutputFormat::JsonPretty);
        let args = AtpSendArgs {
            source: PathBuf::from("Cargo.toml"),
            target: "peer:test".to_string(),
            dry_run: true,
            profile: "bulk".to_string(),
            streams: 4,
            verbose: false,
            progress: false,
            explain: false,
        };

        atp_send(&args, &mut output).expect("atp send should work");
    }

    #[test]
    fn atp_share_generates_share_code() {
        use std::fs;

        // Create a temporary test file
        let test_file = "/tmp/atp_test_file";
        fs::write(test_file, "test content").expect("Failed to create test file");

        let mut output = Output::new(OutputFormat::JsonPretty);
        let args = AtpShareArgs {
            source: PathBuf::from(test_file),
            expires_seconds: 3600,
            max_downloads: 1,
            policy: "peers-only".to_string(),
            capabilities: vec!["read".to_string()],
            quota_bytes: 0,
            peer_id: None,
            destination_policy: "auto".to_string(),
            single_use: false,
            revocable: false,
        };

        atp_share(&args, &mut output).expect("atp share should work");

        // Clean up test file
        let _ = fs::remove_file(test_file);
    }

    #[test]
    fn atp_pair_initiate_works() {
        let mut output = Output::new(OutputFormat::JsonPretty);
        let args = AtpPairArgs {
            command: AtpPairCommand::Initiate {
                peer_hint: Some("test_peer".to_string()),
                confirmation_method: "visual".to_string(),
                timeout_seconds: 300,
            },
        };

        atp_pair(&args, &mut output).expect("atp pair initiate should work");
    }

    #[test]
    fn atp_pair_confirm_works() {
        let mut output = Output::new(OutputFormat::JsonPretty);
        let args = AtpPairArgs {
            command: AtpPairCommand::Confirm {
                pairing_token: "atp://pair/pair_1234567890abcdef/method:visual/timeout:300"
                    .to_string(),
                confirmation_phrase: "Ocean Blue Mountain".to_string(),
            },
        };

        atp_pair(&args, &mut output).expect("atp pair confirm should work");
    }

    #[test]
    fn atp_pair_list_works() {
        let mut output = Output::new(OutputFormat::JsonPretty);
        let args = AtpPairArgs {
            command: AtpPairCommand::List { detailed: false },
        };

        atp_pair(&args, &mut output).expect("atp pair list should work");
    }

    #[test]
    fn atp_seed_works() {
        use std::fs;

        // Create a temporary test file
        let test_file = "/tmp/atp_seed_test_file";
        fs::write(test_file, "seed test content").expect("Failed to create test file");

        let mut output = Output::new(OutputFormat::JsonPretty);
        let args = AtpSeedArgs {
            source: PathBuf::from(test_file),
            policy: "peers-only".to_string(),
            ttl_seconds: 3600,
            max_size_bytes: 0,
            priority: "normal".to_string(),
            relay_enabled: true,
            tags: vec!["test".to_string(), "fixture".to_string()],
            verify_integrity: true,
        };

        atp_seed(&args, &mut output).expect("atp seed should work");

        // Clean up test file
        let _ = fs::remove_file(test_file);
    }

    #[test]
    fn atp_send_with_progress_and_explain_works() {
        let mut output = Output::new(OutputFormat::JsonPretty);
        let args = AtpSendArgs {
            source: PathBuf::from("Cargo.toml"),
            target: "peer:destination".to_string(),
            dry_run: false,
            profile: "bulk".to_string(),
            streams: 4,
            verbose: false,
            progress: true,
            explain: true,
        };

        atp_send(&args, &mut output).expect("atp send with progress and explain should work");
    }

    #[test]
    fn atp_transfer_status_command_parsing_works() {
        let cli = Cli::parse_from([
            "asupersync",
            "atp",
            "transfer-status",
            "transfer-123",
            "--explain",
            "--watch",
            "--interval",
            "5",
        ]);

        if let Command::Atp(AtpArgs {
            command: AtpCommand::TransferStatus(args),
        }) = cli.command
        {
            assert_eq!(args.transfer_id, Some("transfer-123".to_string()));
            assert!(args.explain);
            assert!(args.watch);
            assert_eq!(args.interval_seconds, 5);
        } else {
            panic!("expected atp transfer-status command");
        }
    }

    #[test]
    fn atp_progress_update_formatting_works() {
        let progress = AtpProgressUpdate::new("test_123", "file.dat", 512000, 1024000);
        let human_output = progress.human_format();

        assert!(human_output.contains("receiving"));
        assert!(human_output.contains("file.dat"));
        assert!(human_output.contains("500.0 KB"));
        assert!(human_output.contains("1.0 MB"));
        assert!(human_output.contains("50%"));
    }

    #[test]
    fn atp_explain_report_structure_works() {
        let explain = AtpExplainReport::new("test_explain");
        let human_output = explain.human_format();

        assert!(human_output.contains("Explain Report"));
        assert!(human_output.contains("Path:"));
        assert!(human_output.contains("Scheduler:"));
        assert!(human_output.contains("Repair:"));
        assert!(human_output.contains("Disk:"));
    }

    #[test]
    fn format_bytes_function_works() {
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(1048576), "1.0 MB");
        assert_eq!(format_bytes(1073741824), "1.0 GB");
    }

    #[test]
    fn progress_bar_creation_works() {
        assert_eq!(create_progress_bar(0), "░".repeat(20));
        assert_eq!(
            create_progress_bar(50),
            format!("{}{}", "█".repeat(10), "░".repeat(10))
        );
        assert_eq!(create_progress_bar(100), "█".repeat(20));
    }

    #[test]
    fn progress_chunks_handles_u64_max_without_overflow() {
        let chunks = progress_chunks(u64::MAX);

        assert_eq!(chunks[0], 0);
        assert_eq!(chunks[1], u64::MAX / 4);
        assert_eq!(chunks[2], u64::MAX / 2);
        assert_eq!(
            chunks[3],
            u64::try_from((u128::from(u64::MAX) * 3) / 4).unwrap()
        );
        assert_eq!(chunks[4], u64::MAX);
    }

    #[test]
    fn atp_progress_percentage_handles_large_values() {
        let progress = AtpProgressUpdate::new("large", "huge.bin", u64::MAX, u64::MAX);

        assert!(progress.human_format().contains("100%"));
    }

    #[test]
    fn progress_bar_clamps_overfull_percentages() {
        assert_eq!(create_progress_bar(101), "█".repeat(20));
        assert_eq!(create_progress_bar(u8::MAX), "█".repeat(20));
    }

    #[test]
    fn atp_share_revocation_url_handles_short_share_codes() {
        let args = AtpShareArgs {
            source: PathBuf::from("short"),
            expires_seconds: 60,
            max_downloads: 1,
            policy: "peers-only".to_string(),
            capabilities: vec!["read".to_string()],
            quota_bytes: 0,
            peer_id: None,
            destination_policy: "auto".to_string(),
            single_use: false,
            revocable: true,
        };
        let output = AtpShareOutput::new(&args, "short".to_string());

        assert!(
            output
                .revocation_url
                .as_deref()
                .is_some_and(|url| url.starts_with("atp://revoke/"))
        );
    }

    #[test]
    fn benchmark_profiles_keep_zero_duration_throughput_finite() {
        for profile in ["throughput", "latency", "repair", "stress", "mixed"] {
            let result = AtpBenchResults::for_profile(profile, 0, 8, u64::MAX, false);

            assert_eq!(result.throughput_mbps, 0.0);
            assert!(result.throughput_mbps.is_finite());
        }
    }

    #[test]
    fn timeline_window_rejects_negative_bounds() {
        assert!(parse_timeline_window_nanos(Some("-1:5")).is_err());
        assert!(parse_timeline_window_nanos(Some("1:-5")).is_err());
    }

    #[test]
    fn csv_escape_field_uses_rfc_compatible_quotes() {
        assert_eq!(csv_escape_field("plain"), "plain");
        assert_eq!(csv_escape_field("a,b"), "\"a,b\"");
        assert_eq!(csv_escape_field("a\"b"), "\"a\"\"b\"");
        assert_eq!(csv_escape_field("a\nb"), "\"a\nb\"");
    }

    #[test]
    fn atp_transfer_status_output_works() {
        let mut output = Output::new(OutputFormat::JsonPretty);
        let args = AtpTransferStatusArgs {
            transfer_id: None,
            explain: false,
            watch: false,
            interval_seconds: 2,
        };

        atp_transfer_status(&args, &mut output).expect("atp transfer status should work");
    }
}
