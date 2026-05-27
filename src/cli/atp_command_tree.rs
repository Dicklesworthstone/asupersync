//! ATP-I1: Complete ATP CLI command tree and architecture.
//!
//! This module defines the comprehensive ATP command architecture for
//! asupersync-swezeg (ATP-I1), including:
//! - Complete command tree for all ATP operations
//! - Configuration profile system with precedence
//! - JSON output contracts for machine parsing
//! - UX-optimized defaults with expert diagnostics

use crate::cli::output::Outputtable;
use clap::{Args, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// ATP CLI command tree for comprehensive data movement.
#[derive(Subcommand, Debug)]
pub enum AtpCommand {
    /// Send files/directories with automatic chunking and repair
    Send(AtpSendArgs),

    /// Receive and restore files from ATP transfers
    Get(AtpGetArgs),

    /// Bidirectional sync with conflict resolution
    Sync(AtpSyncArgs),

    /// One-way mirror with automatic cleanup
    Mirror(AtpMirrorArgs),

    /// Create shareable links with access control
    Share(AtpShareArgs),

    /// Watch directories for changes and auto-sync
    Watch(AtpWatchArgs),

    /// Start ATP daemon/server mode
    Serve(AtpServeArgs),

    /// Manage transfer inbox and notifications
    Inbox(AtpInboxArgs),

    /// Resume interrupted transfers
    Resume(AtpResumeArgs),

    /// Cancel active transfers
    Cancel(AtpCancelArgs),

    /// Show transfer status and progress
    Status(AtpStatusArgs),

    /// Benchmark ATP performance
    Bench(AtpBenchArgs),

    /// ATP diagnostics and health checks
    Doctor(AtpDoctorArgs),

    /// Verify ATP proof bundles offline
    Verify(AtpVerifyArgs),

    /// Replay emitted ATP crashpack artifacts
    Replay(AtpReplayArgs),

    /// Display ATP proof bundle information
    Proof(AtpProofArgs),

    /// Configure ATP profiles and settings
    Config(AtpConfigArgs),

    /// CI artifact management workflows
    Ci(AtpCiArgs),

    /// Dataset distribution and seeding workflows
    Dataset(AtpDatasetArgs),

    /// Fuzz corpus synchronization workflows
    Fuzz(AtpFuzzArgs),

    /// Release bundle distribution workflows
    Release(AtpReleaseArgs),

    /// Proof bundle archival workflows
    Archive(AtpArchiveArgs),
}

/// ATP transfer profile for optimized defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AtpProfile {
    /// Large fixed chunks for maximum throughput on bulk transfers.
    BulkFile,
    /// Content-defined chunking optimized for dedupe across source trees.
    SyncTree,
    /// Prefix-friendly chunking for streaming media and progressive delivery.
    Media,
    /// Hole-aware chunking for sparse files and virtual machine images.
    SparseImage,
    /// Reproducible chunking focused on build artifacts and proof strength.
    Artifact,
    /// Rolling manifest chunking for real-time streaming scenarios.
    Stream,
    /// LAN-optimized profile with clean connection assumptions.
    CleanLan,
    /// WiFi-optimized profile tolerating packet loss and jitter.
    LossyWifi,
    /// Relay-only profile for NAT traversal scenarios.
    RelayOnly,
    /// Automatic profile selection based on network conditions.
    Auto,
}

impl AtpProfile {
    /// Get all available profile names for CLI help.
    pub const fn all_names() -> &'static [&'static str] {
        &[
            "bulk-file",
            "sync-tree",
            "media",
            "sparse-image",
            "artifact",
            "stream",
            "clean-lan",
            "lossy-wifi",
            "relay-only",
            "auto",
        ]
    }

    /// Get human-readable description for this profile.
    pub const fn description(self) -> &'static str {
        match self {
            Self::BulkFile => "Large fixed chunks for maximum throughput on bulk transfers",
            Self::SyncTree => "Content-defined chunking optimized for dedupe across source trees",
            Self::Media => "Prefix-friendly chunking for streaming media and progressive delivery",
            Self::SparseImage => "Hole-aware chunking for sparse files and virtual machine images",
            Self::Artifact => "Reproducible chunking focused on build artifacts and proof strength",
            Self::Stream => "Rolling manifest chunking for real-time streaming scenarios",
            Self::CleanLan => "LAN-optimized profile with clean connection assumptions",
            Self::LossyWifi => "WiFi-optimized profile tolerating packet loss and jitter",
            Self::RelayOnly => "Relay-only profile for NAT traversal scenarios",
            Self::Auto => "Automatic profile selection based on network conditions",
        }
    }
}

/// Configuration precedence: CLI flags > local config > daemon policy > defaults.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtpConfig {
    /// Active transfer profile.
    pub profile: Option<AtpProfile>,
    /// Custom chunk size override (bytes).
    pub chunk_size: Option<u64>,
    /// Maximum concurrent transfers.
    pub max_concurrent: Option<u32>,
    /// Transfer timeout (seconds).
    pub timeout: Option<u64>,
    /// Enable compression.
    pub compression: Option<bool>,
    /// Enable encryption.
    pub encryption: Option<bool>,
    /// Repair symbol overhead ratio.
    pub repair_overhead: Option<f32>,
    /// Network interface preference.
    pub interface: Option<String>,
    /// Custom relay server.
    pub relay_server: Option<String>,
    /// Daemon socket path.
    pub daemon_socket: Option<PathBuf>,
    /// Enable verbose logging.
    pub verbose: Option<bool>,
}

impl Default for AtpConfig {
    fn default() -> Self {
        Self {
            profile: Some(AtpProfile::Auto),
            chunk_size: None, // Profile-dependent
            max_concurrent: Some(4),
            timeout: Some(300),
            compression: Some(true),
            encryption: Some(true),
            repair_overhead: Some(0.2),
            interface: None,     // Auto-detect
            relay_server: None,  // Use default
            daemon_socket: None, // Use default
            verbose: Some(false),
        }
    }
}

#[derive(Args, Debug)]
pub struct AtpSendArgs {
    /// Source files/directories to send
    #[arg(value_name = "SOURCE")]
    pub sources: Vec<PathBuf>,

    /// Destination (peer ID, address, or share token)
    #[arg(value_name = "DEST")]
    pub destination: String,

    /// Transfer profile to use
    #[arg(long, short = 'p', value_enum)]
    pub profile: Option<AtpProfile>,

    /// Custom chunk size (overrides profile)
    #[arg(long = "chunk-size")]
    pub chunk_size: Option<u64>,

    /// Enable recursive directory transfer
    #[arg(long, short = 'r', action = clap::ArgAction::SetTrue)]
    pub recursive: bool,

    /// Exclude patterns (glob syntax)
    #[arg(long = "exclude")]
    pub exclude: Vec<String>,

    /// Create resumable transfer with this name
    #[arg(long = "name")]
    pub transfer_name: Option<String>,

    /// Maximum bandwidth (bytes/sec)
    #[arg(long = "bandwidth")]
    pub bandwidth_limit: Option<u64>,

    /// Repair overhead ratio (0.1-2.0)
    #[arg(long = "repair-overhead")]
    pub repair_overhead: Option<f32>,

    /// Show transfer progress
    #[arg(long = "progress", action = clap::ArgAction::SetTrue)]
    pub show_progress: bool,
}

#[derive(Args, Debug)]
pub struct AtpGetArgs {
    /// Transfer ID or share token to receive
    #[arg(value_name = "TRANSFER")]
    pub transfer_id: String,

    /// Destination directory (default: current directory)
    #[arg(value_name = "DEST")]
    pub destination: Option<PathBuf>,

    /// Resume partial transfer
    #[arg(long = "resume", action = clap::ArgAction::SetTrue)]
    pub resume: bool,

    /// Verify integrity after transfer
    #[arg(long = "verify", action = clap::ArgAction::SetTrue)]
    pub verify: bool,

    /// Show transfer progress
    #[arg(long = "progress", action = clap::ArgAction::SetTrue)]
    pub show_progress: bool,
}

#[derive(Args, Debug)]
pub struct AtpSyncArgs {
    /// Local directory to sync
    #[arg(value_name = "LOCAL")]
    pub local_path: PathBuf,

    /// Remote path (peer:path or share token)
    #[arg(value_name = "REMOTE")]
    pub remote_path: String,

    /// Sync direction: push, pull, or bidirectional
    #[arg(long = "direction", default_value = "bidirectional")]
    pub direction: String,

    /// Conflict resolution strategy
    #[arg(long = "conflict", default_value = "prompt", value_enum)]
    pub conflict_resolution: ConflictStrategy,

    /// Watch for changes and auto-sync
    #[arg(long = "watch", action = clap::ArgAction::SetTrue)]
    pub watch: bool,

    /// Sync interval in seconds (for watch mode)
    #[arg(long = "interval", default_value = "30")]
    pub interval: u64,

    /// Exclude patterns (glob syntax)
    #[arg(long = "exclude")]
    pub exclude: Vec<String>,
}

#[derive(ValueEnum, Debug, Clone)]
pub enum ConflictStrategy {
    /// Prompt user for each conflict
    Prompt,
    /// Keep local version
    Local,
    /// Keep remote version
    Remote,
    /// Keep both with rename
    Both,
    /// Use latest timestamp
    Latest,
    /// Fail on conflicts
    Fail,
}

#[derive(Args, Debug)]
pub struct AtpStatusArgs {
    /// Filter by transfer ID or pattern
    #[arg(long = "filter")]
    pub filter: Option<String>,

    /// Show only active transfers
    #[arg(long = "active", action = clap::ArgAction::SetTrue)]
    pub active_only: bool,

    /// Show detailed progress information
    #[arg(long = "detailed", action = clap::ArgAction::SetTrue)]
    pub detailed: bool,

    /// Continuous monitoring mode
    #[arg(long = "watch", action = clap::ArgAction::SetTrue)]
    pub watch: bool,

    /// Update interval for watch mode (seconds)
    #[arg(long = "interval", default_value = "5")]
    pub watch_interval: u64,
}

#[derive(Args, Debug)]
pub struct AtpBenchArgs {
    /// Benchmark profile to test
    #[arg(long, short = 'p', value_enum)]
    pub profile: Option<AtpProfile>,

    /// Test data size (bytes, K, M, G suffixes supported)
    #[arg(long = "size", default_value = "100M")]
    pub test_size: String,

    /// Number of benchmark iterations
    #[arg(long = "iterations", default_value = "3")]
    pub iterations: u32,

    /// Target peer for network benchmarks
    #[arg(long = "peer")]
    pub target_peer: Option<String>,

    /// Enable detailed performance breakdown
    #[arg(long = "detailed", action = clap::ArgAction::SetTrue)]
    pub detailed: bool,
}

/// Additional command argument structures for other ATP commands...
#[derive(Args, Debug)]
pub struct AtpMirrorArgs {
    /// Source directory to mirror
    #[arg(value_name = "SOURCE")]
    pub source: PathBuf,

    /// Destination (peer:path or share token)
    #[arg(value_name = "DEST")]
    pub destination: String,

    /// Delete files not in source
    #[arg(long = "delete", action = clap::ArgAction::SetTrue)]
    pub delete_extra: bool,

    /// Dry run mode
    #[arg(long = "dry-run", action = clap::ArgAction::SetTrue)]
    pub dry_run: bool,
}

#[derive(Args, Debug)]
pub struct AtpShareArgs {
    /// Files/directories to share
    #[arg(value_name = "PATHS")]
    pub paths: Vec<PathBuf>,

    /// Share expiration (duration like "1h", "30m", "7d")
    #[arg(long = "expires")]
    pub expires: Option<String>,

    /// Maximum downloads allowed
    #[arg(long = "max-downloads")]
    pub max_downloads: Option<u32>,

    /// Require authentication
    #[arg(long = "auth", action = clap::ArgAction::SetTrue)]
    pub require_auth: bool,
}

#[derive(Args, Debug)]
pub struct AtpWatchArgs {
    /// Directory to watch for changes
    #[arg(value_name = "PATH")]
    pub path: PathBuf,

    /// Remote destination for auto-sync
    #[arg(value_name = "REMOTE")]
    pub remote: String,

    /// Debounce delay (milliseconds)
    #[arg(long = "delay", default_value = "1000")]
    pub debounce_delay: u64,
}

#[derive(Args, Debug)]
pub struct AtpServeArgs {
    /// Port to listen on
    #[arg(long, short = 'p', default_value = "7777")]
    pub port: u16,

    /// Interface to bind to
    #[arg(long = "bind", default_value = "0.0.0.0")]
    pub bind_address: String,

    /// Run as daemon
    #[arg(long = "daemon", action = clap::ArgAction::SetTrue)]
    pub daemon: bool,

    /// PID file path (daemon mode)
    #[arg(long = "pid-file")]
    pub pid_file: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct AtpInboxArgs {
    /// Show pending transfers
    #[arg(long = "pending", action = clap::ArgAction::SetTrue)]
    pub pending: bool,

    /// Accept transfer by ID
    #[arg(long = "accept")]
    pub accept: Option<String>,

    /// Reject transfer by ID
    #[arg(long = "reject")]
    pub reject: Option<String>,

    /// Clear completed transfers
    #[arg(long = "clear", action = clap::ArgAction::SetTrue)]
    pub clear_completed: bool,
}

#[derive(Args, Debug)]
pub struct AtpResumeArgs {
    /// Transfer ID to resume
    #[arg(value_name = "TRANSFER_ID")]
    pub transfer_id: String,

    /// Force resume even if manifest changed
    #[arg(long = "force", action = clap::ArgAction::SetTrue)]
    pub force: bool,
}

#[derive(Args, Debug)]
pub struct AtpCancelArgs {
    /// Transfer ID to cancel
    #[arg(value_name = "TRANSFER_ID")]
    pub transfer_id: String,

    /// Clean up partial files
    #[arg(long = "cleanup", action = clap::ArgAction::SetTrue)]
    pub cleanup: bool,
}

#[derive(Args, Debug)]
pub struct AtpConfigArgs {
    /// Show current configuration
    #[arg(long = "show", action = clap::ArgAction::SetTrue)]
    pub show: bool,

    /// Set configuration value
    #[arg(long = "set")]
    pub set: Vec<String>,

    /// Unset configuration value
    #[arg(long = "unset")]
    pub unset: Vec<String>,

    /// List available profiles
    #[arg(long = "list-profiles", action = clap::ArgAction::SetTrue)]
    pub list_profiles: bool,

    /// Configuration scope: user, local, or daemon
    #[arg(long = "scope", default_value = "user")]
    pub scope: String,
}

/// CI artifact management command arguments.
#[derive(Args, Debug)]
pub struct AtpCiArgs {
    #[command(subcommand)]
    pub action: AtpCiAction,
}

#[derive(Subcommand, Debug)]
pub enum AtpCiAction {
    /// Push build artifacts to artifact cache
    Push(AtpCiPushArgs),
    /// Pull artifacts from cache
    Pull(AtpCiPullArgs),
    /// Clean up old artifacts
    Clean(AtpCiCleanArgs),
    /// List cached artifacts
    List(AtpCiListArgs),
    /// Show artifact cache status
    Status(AtpCiStatusArgs),
}

#[derive(Args, Debug)]
pub struct AtpCiPushArgs {
    /// Artifact paths to push
    #[arg(value_name = "PATHS")]
    pub paths: Vec<PathBuf>,
    /// Build ID or CI run identifier
    #[arg(long = "build-id")]
    pub build_id: String,
    /// Artifact tags for classification
    #[arg(long = "tag")]
    pub tags: Vec<String>,
    /// Retention policy (e.g., "7d", "30d", "permanent")
    #[arg(long = "retention", default_value = "30d")]
    pub retention: String,
    /// Compression level (0-9)
    #[arg(long = "compression", default_value = "6")]
    pub compression_level: u8,
    /// Enable deduplication across builds
    #[arg(long = "dedupe", action = clap::ArgAction::SetTrue)]
    pub dedupe: bool,
    /// Capability scope for access control
    #[arg(long = "scope")]
    pub scope: Option<String>,
}

#[derive(Args, Debug)]
pub struct AtpCiPullArgs {
    /// Build ID to pull artifacts from
    #[arg(long = "build-id")]
    pub build_id: Option<String>,
    /// Artifact tags to filter by
    #[arg(long = "tag")]
    pub tags: Vec<String>,
    /// Destination directory
    #[arg(long = "dest", default_value = ".")]
    pub destination: PathBuf,
    /// Only pull if newer than local copy
    #[arg(long = "if-newer", action = clap::ArgAction::SetTrue)]
    pub if_newer: bool,
    /// Verify artifact integrity
    #[arg(long = "verify", action = clap::ArgAction::SetTrue)]
    pub verify: bool,
}

#[derive(Args, Debug)]
pub struct AtpCiCleanArgs {
    /// Clean artifacts older than duration
    #[arg(long = "older-than")]
    pub older_than: Option<String>,
    /// Clean by build ID pattern
    #[arg(long = "build-pattern")]
    pub build_pattern: Option<String>,
    /// Dry run mode
    #[arg(long = "dry-run", action = clap::ArgAction::SetTrue)]
    pub dry_run: bool,
}

#[derive(Args, Debug)]
pub struct AtpCiListArgs {
    /// Filter by tag
    #[arg(long = "tag")]
    pub tag: Option<String>,
    /// Show only recent artifacts
    #[arg(long = "recent", default_value = "7d")]
    pub recent: String,
    /// Show detailed information
    #[arg(long = "verbose", action = clap::ArgAction::SetTrue)]
    pub verbose: bool,
}

#[derive(Args, Debug)]
pub struct AtpCiStatusArgs {
    /// Show cache usage statistics
    #[arg(long = "stats", action = clap::ArgAction::SetTrue)]
    pub stats: bool,
    /// Show cache health metrics
    #[arg(long = "health", action = clap::ArgAction::SetTrue)]
    pub health: bool,
}

/// Dataset distribution command arguments.
#[derive(Args, Debug)]
pub struct AtpDatasetArgs {
    #[command(subcommand)]
    pub action: AtpDatasetAction,
}

#[derive(Subcommand, Debug)]
pub enum AtpDatasetAction {
    /// Seed a dataset into the swarm network
    Seed(AtpDatasetSeedArgs),
    /// Get a dataset from the swarm
    Get(AtpDatasetGetArgs),
    /// List available datasets
    List(AtpDatasetListArgs),
    /// Show dataset status and seeding health
    Status(AtpDatasetStatusArgs),
    /// Pin a dataset for local availability
    Pin(AtpDatasetPinArgs),
    /// Unpin a dataset to allow garbage collection
    Unpin(AtpDatasetUnpinArgs),
}

#[derive(Args, Debug)]
pub struct AtpDatasetSeedArgs {
    /// Dataset directory to seed
    #[arg(value_name = "PATH")]
    pub path: PathBuf,
    /// Dataset identifier
    #[arg(long = "id")]
    pub dataset_id: String,
    /// Dataset metadata (JSON)
    #[arg(long = "metadata")]
    pub metadata: Option<String>,
    /// Chunk size optimized for dataset type
    #[arg(long = "chunk-size")]
    pub chunk_size: Option<u64>,
    /// Enable versioning
    #[arg(long = "version")]
    pub version: Option<String>,
    /// Swarm replication factor
    #[arg(long = "replication", default_value = "3")]
    pub replication_factor: u32,
    /// Access control capability
    #[arg(long = "access-scope")]
    pub access_scope: Option<String>,
}

#[derive(Args, Debug)]
pub struct AtpDatasetGetArgs {
    /// Dataset identifier
    #[arg(value_name = "DATASET_ID")]
    pub dataset_id: String,
    /// Specific version to get
    #[arg(long = "version")]
    pub version: Option<String>,
    /// Destination directory
    #[arg(long = "dest")]
    pub destination: Option<PathBuf>,
    /// Partial download by pattern
    #[arg(long = "pattern")]
    pub pattern: Option<String>,
    /// Resume incomplete download
    #[arg(long = "resume", action = clap::ArgAction::SetTrue)]
    pub resume: bool,
}

#[derive(Args, Debug)]
pub struct AtpDatasetListArgs {
    /// Filter by dataset pattern
    #[arg(long = "pattern")]
    pub pattern: Option<String>,
    /// Show only locally available
    #[arg(long = "local", action = clap::ArgAction::SetTrue)]
    pub local_only: bool,
    /// Include dataset metadata
    #[arg(long = "metadata", action = clap::ArgAction::SetTrue)]
    pub include_metadata: bool,
}

#[derive(Args, Debug)]
pub struct AtpDatasetStatusArgs {
    /// Specific dataset ID
    #[arg(value_name = "DATASET_ID")]
    pub dataset_id: Option<String>,
    /// Show swarm health metrics
    #[arg(long = "swarm", action = clap::ArgAction::SetTrue)]
    pub swarm_health: bool,
}

#[derive(Args, Debug)]
pub struct AtpDatasetPinArgs {
    /// Dataset ID to pin
    #[arg(value_name = "DATASET_ID")]
    pub dataset_id: String,
    /// Pin specific version
    #[arg(long = "version")]
    pub version: Option<String>,
}

#[derive(Args, Debug)]
pub struct AtpDatasetUnpinArgs {
    /// Dataset ID to unpin
    #[arg(value_name = "DATASET_ID")]
    pub dataset_id: String,
    /// Unpin specific version
    #[arg(long = "version")]
    pub version: Option<String>,
}

/// Fuzz corpus synchronization command arguments.
#[derive(Args, Debug)]
pub struct AtpFuzzArgs {
    #[command(subcommand)]
    pub action: AtpFuzzAction,
}

#[derive(Subcommand, Debug)]
pub enum AtpFuzzAction {
    /// Sync corpus to shared storage
    Sync(AtpFuzzSyncArgs),
    /// Pull latest corpus updates
    Pull(AtpFuzzPullArgs),
    /// Push local corpus changes
    Push(AtpFuzzPushArgs),
    /// Merge corpus from multiple fuzzers
    Merge(AtpFuzzMergeArgs),
    /// Minimize corpus while preserving coverage
    Minimize(AtpFuzzMinimizeArgs),
    /// Show corpus statistics
    Stats(AtpFuzzStatsArgs),
}

#[derive(Args, Debug)]
pub struct AtpFuzzSyncArgs {
    /// Corpus directory path
    #[arg(value_name = "CORPUS_PATH")]
    pub corpus_path: PathBuf,
    /// Fuzzer target identifier
    #[arg(long = "target")]
    pub target: String,
    /// Sync strategy: push, pull, or bidirectional
    #[arg(long = "strategy", default_value = "bidirectional")]
    pub strategy: String,
    /// Exclude patterns for test cases
    #[arg(long = "exclude")]
    pub exclude: Vec<String>,
    /// Enable real-time synchronization
    #[arg(long = "watch", action = clap::ArgAction::SetTrue)]
    pub watch: bool,
}

#[derive(Args, Debug)]
pub struct AtpFuzzPushArgs {
    /// Local corpus directory
    #[arg(value_name = "CORPUS_PATH")]
    pub corpus_path: PathBuf,
    /// Fuzzer target identifier
    #[arg(long = "target")]
    pub target: String,
    /// Only push new/changed test cases
    #[arg(long = "incremental", action = clap::ArgAction::SetTrue)]
    pub incremental: bool,
}

#[derive(Args, Debug)]
pub struct AtpFuzzPullArgs {
    /// Local corpus directory
    #[arg(value_name = "CORPUS_PATH")]
    pub corpus_path: PathBuf,
    /// Fuzzer target identifier
    #[arg(long = "target")]
    pub target: String,
    /// Pull only test cases newer than timestamp
    #[arg(long = "since")]
    pub since: Option<String>,
}

#[derive(Args, Debug)]
pub struct AtpFuzzMergeArgs {
    /// Source corpus directories to merge
    #[arg(value_name = "SOURCES")]
    pub sources: Vec<PathBuf>,
    /// Output merged corpus directory
    #[arg(long = "output")]
    pub output: PathBuf,
    /// Deduplication strategy
    #[arg(long = "dedupe", default_value = "content-hash")]
    pub dedupe_strategy: String,
}

#[derive(Args, Debug)]
pub struct AtpFuzzMinimizeArgs {
    /// Corpus directory to minimize
    #[arg(value_name = "CORPUS_PATH")]
    pub corpus_path: PathBuf,
    /// Fuzzer target for coverage analysis
    #[arg(long = "target")]
    pub target: String,
    /// Coverage threshold to maintain
    #[arg(long = "coverage-threshold", default_value = "0.95")]
    pub coverage_threshold: f64,
}

#[derive(Args, Debug)]
pub struct AtpFuzzStatsArgs {
    /// Corpus directory to analyze
    #[arg(value_name = "CORPUS_PATH")]
    pub corpus_path: Option<PathBuf>,
    /// Show per-fuzzer statistics
    #[arg(long = "per-target", action = clap::ArgAction::SetTrue)]
    pub per_target: bool,
    /// Include coverage analysis
    #[arg(long = "coverage", action = clap::ArgAction::SetTrue)]
    pub coverage: bool,
}

/// Release bundle distribution command arguments.
#[derive(Args, Debug)]
pub struct AtpReleaseArgs {
    #[command(subcommand)]
    pub action: AtpReleaseAction,
}

#[derive(Subcommand, Debug)]
pub enum AtpReleaseAction {
    /// Package and distribute a release bundle
    Publish(AtpReleasePublishArgs),
    /// Download and install a release
    Install(AtpReleaseInstallArgs),
    /// List available releases
    List(AtpReleaseListArgs),
    /// Show release information
    Info(AtpReleaseInfoArgs),
    /// Verify release bundle integrity
    Verify(AtpReleaseVerifyArgs),
    /// Create differential update package
    Diff(AtpReleaseDiffArgs),
}

#[derive(Args, Debug)]
pub struct AtpReleasePublishArgs {
    /// Release artifacts directory
    #[arg(value_name = "RELEASE_PATH")]
    pub release_path: PathBuf,
    /// Release version identifier
    #[arg(long = "version")]
    pub version: String,
    /// Release channel (stable, beta, alpha)
    #[arg(long = "channel", default_value = "stable")]
    pub channel: String,
    /// Release metadata file
    #[arg(long = "metadata")]
    pub metadata_file: Option<PathBuf>,
    /// Code signing certificate
    #[arg(long = "sign-cert")]
    pub sign_cert: Option<PathBuf>,
    /// Target platforms
    #[arg(long = "platform")]
    pub platforms: Vec<String>,
    /// Minimum client version required
    #[arg(long = "min-client")]
    pub min_client_version: Option<String>,
}

#[derive(Args, Debug)]
pub struct AtpReleaseInstallArgs {
    /// Release identifier to install
    #[arg(value_name = "RELEASE_ID")]
    pub release_id: String,
    /// Specific version to install
    #[arg(long = "version")]
    pub version: Option<String>,
    /// Installation directory
    #[arg(long = "dest")]
    pub destination: Option<PathBuf>,
    /// Force reinstallation
    #[arg(long = "force", action = clap::ArgAction::SetTrue)]
    pub force: bool,
    /// Verify signatures
    #[arg(long = "verify", action = clap::ArgAction::SetTrue)]
    pub verify: bool,
}

#[derive(Args, Debug)]
pub struct AtpReleaseListArgs {
    /// Filter by release pattern
    #[arg(long = "pattern")]
    pub pattern: Option<String>,
    /// Channel to list
    #[arg(long = "channel")]
    pub channel: Option<String>,
    /// Show only latest versions
    #[arg(long = "latest", action = clap::ArgAction::SetTrue)]
    pub latest_only: bool,
}

#[derive(Args, Debug)]
pub struct AtpReleaseInfoArgs {
    /// Release identifier
    #[arg(value_name = "RELEASE_ID")]
    pub release_id: String,
    /// Specific version
    #[arg(long = "version")]
    pub version: Option<String>,
    /// Show detailed manifest
    #[arg(long = "manifest", action = clap::ArgAction::SetTrue)]
    pub show_manifest: bool,
}

#[derive(Args, Debug)]
pub struct AtpReleaseVerifyArgs {
    /// Release bundle path
    #[arg(value_name = "BUNDLE_PATH")]
    pub bundle_path: PathBuf,
    /// Trusted certificate authorities
    #[arg(long = "ca-cert")]
    pub ca_certs: Vec<PathBuf>,
    /// Strict verification mode
    #[arg(long = "strict", action = clap::ArgAction::SetTrue)]
    pub strict: bool,
}

#[derive(Args, Debug)]
pub struct AtpReleaseDiffArgs {
    /// Previous version path
    #[arg(long = "from")]
    pub from_path: PathBuf,
    /// New version path
    #[arg(long = "to")]
    pub to_path: PathBuf,
    /// Output differential package
    #[arg(long = "output")]
    pub output: PathBuf,
    /// Differential algorithm
    #[arg(long = "algorithm", default_value = "bsdiff")]
    pub algorithm: String,
}

/// Proof bundle archival command arguments.
#[derive(Args, Debug)]
pub struct AtpArchiveArgs {
    #[command(subcommand)]
    pub action: AtpArchiveAction,
}

#[derive(Subcommand, Debug)]
pub enum AtpArchiveAction {
    /// Store proof bundle in long-term archive
    Store(AtpArchiveStoreArgs),
    /// Retrieve proof bundle from archive
    Retrieve(AtpArchiveRetrieveArgs),
    /// List archived proof bundles
    List(AtpArchiveListArgs),
    /// Verify archived bundle integrity
    Verify(AtpArchiveVerifyArgs),
    /// Compact archive storage
    Compact(AtpArchiveCompactArgs),
    /// Export archive to external storage
    Export(AtpArchiveExportArgs),
}

#[derive(Args, Debug)]
pub struct AtpArchiveStoreArgs {
    /// Proof bundle file to archive
    #[arg(value_name = "BUNDLE_PATH")]
    pub bundle_path: PathBuf,
    /// Archive identifier
    #[arg(long = "id")]
    pub archive_id: Option<String>,
    /// Retention policy
    #[arg(long = "retention")]
    pub retention: Option<String>,
    /// Archive tier (hot, warm, cold)
    #[arg(long = "tier", default_value = "warm")]
    pub tier: String,
    /// Metadata tags
    #[arg(long = "tag")]
    pub tags: Vec<String>,
}

#[derive(Args, Debug)]
pub struct AtpArchiveRetrieveArgs {
    /// Archive identifier
    #[arg(value_name = "ARCHIVE_ID")]
    pub archive_id: String,
    /// Output directory
    #[arg(long = "dest")]
    pub destination: Option<PathBuf>,
    /// Retrieve to temporary location
    #[arg(long = "temp", action = clap::ArgAction::SetTrue)]
    pub temporary: bool,
}

#[derive(Args, Debug)]
pub struct AtpArchiveListArgs {
    /// Filter by tag
    #[arg(long = "tag")]
    pub tag: Option<String>,
    /// Show only recent archives
    #[arg(long = "since")]
    pub since: Option<String>,
    /// Archive tier filter
    #[arg(long = "tier")]
    pub tier: Option<String>,
}

#[derive(Args, Debug)]
pub struct AtpArchiveVerifyArgs {
    /// Archive identifier to verify
    #[arg(value_name = "ARCHIVE_ID")]
    pub archive_id: String,
    /// Deep verification mode
    #[arg(long = "deep", action = clap::ArgAction::SetTrue)]
    pub deep: bool,
}

#[derive(Args, Debug)]
pub struct AtpArchiveCompactArgs {
    /// Tier to compact
    #[arg(long = "tier")]
    pub tier: Option<String>,
    /// Dry run mode
    #[arg(long = "dry-run", action = clap::ArgAction::SetTrue)]
    pub dry_run: bool,
}

#[derive(Args, Debug)]
pub struct AtpArchiveExportArgs {
    /// Archive identifiers to export
    #[arg(value_name = "ARCHIVE_IDS")]
    pub archive_ids: Vec<String>,
    /// Export destination
    #[arg(long = "dest")]
    pub destination: PathBuf,
    /// Export format
    #[arg(long = "format", default_value = "tar.gz")]
    pub format: String,
}

/// Re-export ATP command args from the args module
pub use super::args::{AtpDoctorArgs, AtpProofArgs, AtpReplayArgs, AtpVerifyArgs};

/// JSON output schema for ATP status command.
#[derive(Debug, Serialize, Deserialize)]
pub struct AtpStatusOutput {
    /// Overall status summary.
    pub summary: AtpStatusSummary,
    /// Individual transfer details.
    pub transfers: Vec<AtpTransferStatus>,
    /// System resource usage.
    pub system: AtpSystemStatus,
    /// Timestamp of this status snapshot.
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AtpStatusSummary {
    /// Total active transfers.
    pub active_transfers: u32,
    /// Total queued transfers.
    pub queued_transfers: u32,
    /// Total completed transfers.
    pub completed_transfers: u32,
    /// Total failed transfers.
    pub failed_transfers: u32,
    /// Combined throughput (bytes/sec).
    pub total_throughput_bps: u64,
    /// Combined ETA for active transfers (seconds).
    pub estimated_completion_seconds: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AtpTransferStatus {
    /// Unique transfer identifier.
    pub id: String,
    /// Transfer direction (send/receive/sync).
    pub direction: String,
    /// Source path or description.
    pub source: String,
    /// Destination path or peer.
    pub destination: String,
    /// Current transfer state.
    pub state: AtpTransferState,
    /// Progress information.
    pub progress: AtpTransferProgress,
    /// Performance metrics.
    pub performance: AtpPerformanceMetrics,
    /// Error information if failed.
    pub error: Option<String>,
    /// Transfer metadata.
    pub metadata: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum AtpTransferState {
    /// Queued waiting for resources.
    Queued,
    /// Connecting to peer.
    Connecting,
    /// Negotiating transfer parameters.
    Negotiating,
    /// Actively transferring data.
    Transferring,
    /// Verifying integrity.
    Verifying,
    /// Transfer completed successfully.
    Completed,
    /// Transfer failed with error.
    Failed,
    /// Transfer cancelled by user.
    Cancelled,
    /// Transfer paused.
    Paused,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AtpTransferProgress {
    /// Bytes transferred so far.
    pub bytes_transferred: u64,
    /// Total bytes to transfer.
    pub total_bytes: u64,
    /// Files transferred so far.
    pub files_transferred: u32,
    /// Total files to transfer.
    pub total_files: u32,
    /// Progress percentage (0.0-100.0).
    pub percentage: f64,
    /// Current transfer rate (bytes/sec).
    pub current_rate_bps: u64,
    /// Average transfer rate (bytes/sec).
    pub average_rate_bps: u64,
    /// Estimated time remaining (seconds).
    pub eta_seconds: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AtpPerformanceMetrics {
    /// Network round-trip time (milliseconds).
    pub rtt_ms: f64,
    /// Packet loss rate (0.0-1.0).
    pub packet_loss_rate: f64,
    /// Active TCP/QUIC connections.
    pub active_connections: u32,
    /// RaptorQ repair symbols used.
    pub repair_symbols_used: u32,
    /// Chunk deduplication savings (bytes).
    pub dedup_savings_bytes: u64,
    /// Compression ratio achieved.
    pub compression_ratio: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AtpSystemStatus {
    /// CPU usage percentage.
    pub cpu_usage_percent: f64,
    /// Memory usage in bytes.
    pub memory_usage_bytes: u64,
    /// Available memory in bytes.
    pub memory_available_bytes: u64,
    /// Disk usage for ATP cache.
    pub disk_cache_usage_bytes: u64,
    /// Network interface statistics.
    pub network_interfaces: Vec<AtpNetworkInterface>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AtpNetworkInterface {
    /// Interface name.
    pub name: String,
    /// Interface type (ethernet, wifi, etc.).
    pub interface_type: String,
    /// Current bandwidth utilization (bytes/sec).
    pub utilization_bps: u64,
    /// Maximum bandwidth capacity (bytes/sec).
    pub capacity_bps: u64,
    /// Interface is currently active.
    pub active: bool,
}

/// JSON output schema for ATP benchmark command.
#[derive(Debug, Serialize, Deserialize)]
pub struct AtpBenchOutput {
    /// Benchmark configuration used.
    pub config: AtpBenchConfig,
    /// Results from all iterations.
    pub results: Vec<AtpBenchResult>,
    /// Aggregate statistics.
    pub summary: AtpBenchSummary,
    /// System information during benchmark.
    pub system_info: AtpBenchSystemInfo,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AtpBenchConfig {
    /// Profile tested.
    pub profile: AtpProfile,
    /// Test data size in bytes.
    pub test_size_bytes: u64,
    /// Number of iterations.
    pub iterations: u32,
    /// Target peer (if network test).
    pub target_peer: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AtpBenchResult {
    /// Iteration number.
    pub iteration: u32,
    /// Total transfer time (seconds).
    pub duration_seconds: f64,
    /// Average throughput (bytes/sec).
    pub throughput_bps: u64,
    /// Peak throughput (bytes/sec).
    pub peak_throughput_bps: u64,
    /// CPU usage during transfer.
    pub cpu_usage_percent: f64,
    /// Memory usage during transfer.
    pub memory_usage_bytes: u64,
    /// Network metrics.
    pub network_metrics: AtpPerformanceMetrics,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AtpBenchSummary {
    /// Average throughput across iterations.
    pub avg_throughput_bps: u64,
    /// Standard deviation of throughput.
    pub throughput_std_dev: f64,
    /// Best iteration performance.
    pub best_throughput_bps: u64,
    /// Worst iteration performance.
    pub worst_throughput_bps: u64,
    /// Average CPU usage.
    pub avg_cpu_usage_percent: f64,
    /// Average memory usage.
    pub avg_memory_usage_bytes: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AtpBenchSystemInfo {
    /// Operating system.
    pub os: String,
    /// CPU model and core count.
    pub cpu: String,
    /// Total system memory.
    pub total_memory_bytes: u64,
    /// Network interface used.
    pub network_interface: String,
    /// Test timestamp.
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// JSON output schema for ATP CI commands.
#[derive(Debug, Serialize, Deserialize)]
pub struct AtpCiOutput {
    /// CI operation result summary.
    pub summary: AtpCiSummary,
    /// Affected artifacts.
    pub artifacts: Vec<AtpCiArtifact>,
    /// Cache statistics.
    pub cache_stats: Option<AtpCiCacheStats>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AtpCiSummary {
    /// Operation performed.
    pub operation: String,
    /// Number of artifacts processed.
    pub artifacts_processed: u32,
    /// Total bytes transferred.
    pub bytes_transferred: u64,
    /// Operation duration in seconds.
    pub duration_seconds: f64,
    /// Success status.
    pub success: bool,
    /// Error message if failed.
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AtpCiArtifact {
    /// Artifact identifier.
    pub id: String,
    /// Build ID this artifact belongs to.
    pub build_id: String,
    /// Artifact path.
    pub path: String,
    /// Size in bytes.
    pub size_bytes: u64,
    /// Content hash for deduplication.
    pub content_hash: String,
    /// Artifact tags.
    pub tags: Vec<String>,
    /// Upload/modification timestamp.
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Expiration timestamp.
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AtpCiCacheStats {
    /// Total cache size in bytes.
    pub total_size_bytes: u64,
    /// Number of stored artifacts.
    pub artifact_count: u32,
    /// Cache hit ratio.
    pub hit_ratio: f64,
    /// Deduplication savings in bytes.
    pub dedup_savings_bytes: u64,
    /// Available cache space in bytes.
    pub available_space_bytes: u64,
}

/// JSON output schema for ATP dataset commands.
#[derive(Debug, Serialize, Deserialize)]
pub struct AtpDatasetOutput {
    /// Dataset operation result summary.
    pub summary: AtpDatasetSummary,
    /// Affected datasets.
    pub datasets: Vec<AtpDatasetInfo>,
    /// Swarm health metrics.
    pub swarm_health: Option<AtpSwarmHealth>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AtpDatasetSummary {
    /// Operation performed.
    pub operation: String,
    /// Number of datasets processed.
    pub datasets_processed: u32,
    /// Total data size in bytes.
    pub total_size_bytes: u64,
    /// Transfer rate in bytes per second.
    pub transfer_rate_bps: Option<u64>,
    /// Success status.
    pub success: bool,
    /// Error message if failed.
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AtpDatasetInfo {
    /// Dataset unique identifier.
    pub id: String,
    /// Dataset version.
    pub version: Option<String>,
    /// Dataset size in bytes.
    pub size_bytes: u64,
    /// Number of files.
    pub file_count: u32,
    /// Dataset metadata.
    pub metadata: BTreeMap<String, serde_json::Value>,
    /// Availability across swarm nodes.
    pub availability: f64,
    /// Replication factor.
    pub replication_factor: u32,
    /// Seeding health score.
    pub health_score: f64,
    /// Last update timestamp.
    pub updated_at: chrono::DateTime<chrono::Utc>,
    /// Local pin status.
    pub pinned: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AtpSwarmHealth {
    /// Number of active seeding nodes.
    pub active_nodes: u32,
    /// Average node uptime.
    pub avg_uptime_hours: f64,
    /// Network bandwidth utilization.
    pub bandwidth_utilization: f64,
    /// Chunk availability across nodes.
    pub chunk_availability: f64,
    /// Node geographic distribution.
    pub geo_distribution: Vec<AtpNodeRegion>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AtpNodeRegion {
    /// Geographic region.
    pub region: String,
    /// Number of nodes in region.
    pub node_count: u32,
    /// Regional bandwidth capacity.
    pub bandwidth_capacity_bps: u64,
}

/// JSON output schema for ATP fuzz commands.
#[derive(Debug, Serialize, Deserialize)]
pub struct AtpFuzzOutput {
    /// Fuzz operation result summary.
    pub summary: AtpFuzzSummary,
    /// Corpus statistics.
    pub corpus_stats: AtpFuzzCorpusStats,
    /// Coverage analysis.
    pub coverage: Option<AtpFuzzCoverage>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AtpFuzzSummary {
    /// Operation performed.
    pub operation: String,
    /// Fuzzer target.
    pub target: String,
    /// Test cases processed.
    pub test_cases_processed: u32,
    /// Sync duration in seconds.
    pub duration_seconds: f64,
    /// Success status.
    pub success: bool,
    /// Error message if failed.
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AtpFuzzCorpusStats {
    /// Total test cases in corpus.
    pub total_test_cases: u32,
    /// New test cases added.
    pub new_test_cases: u32,
    /// Duplicate test cases removed.
    pub duplicates_removed: u32,
    /// Total corpus size in bytes.
    pub total_size_bytes: u64,
    /// Average test case size.
    pub avg_case_size_bytes: u64,
    /// Corpus growth rate (cases per day).
    pub growth_rate: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AtpFuzzCoverage {
    /// Coverage percentage achieved.
    pub coverage_percent: f64,
    /// Number of unique code paths.
    pub unique_paths: u32,
    /// Edge coverage count.
    pub edge_coverage: u32,
    /// Function coverage count.
    pub function_coverage: u32,
    /// Coverage map file path.
    pub coverage_map_path: Option<String>,
}

/// JSON output schema for ATP release commands.
#[derive(Debug, Serialize, Deserialize)]
pub struct AtpReleaseOutput {
    /// Release operation result summary.
    pub summary: AtpReleaseSummary,
    /// Release information.
    pub releases: Vec<AtpReleaseInfo>,
    /// Distribution metrics.
    pub distribution_metrics: Option<AtpReleaseMetrics>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AtpReleaseSummary {
    /// Operation performed.
    pub operation: String,
    /// Number of releases processed.
    pub releases_processed: u32,
    /// Total release size in bytes.
    pub total_size_bytes: u64,
    /// Distribution success rate.
    pub success_rate: f64,
    /// Operation success status.
    pub success: bool,
    /// Error message if failed.
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AtpReleaseInfo {
    /// Release identifier.
    pub id: String,
    /// Version string.
    pub version: String,
    /// Release channel.
    pub channel: String,
    /// Release size in bytes.
    pub size_bytes: u64,
    /// Supported platforms.
    pub platforms: Vec<String>,
    /// Release metadata.
    pub metadata: BTreeMap<String, serde_json::Value>,
    /// Code signature verification.
    pub signature_valid: Option<bool>,
    /// Download count.
    pub download_count: u64,
    /// Publication timestamp.
    pub published_at: chrono::DateTime<chrono::Utc>,
    /// Minimum client version.
    pub min_client_version: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AtpReleaseMetrics {
    /// Active downloads across all releases.
    pub active_downloads: u32,
    /// Total download bandwidth utilization.
    pub bandwidth_utilization_bps: u64,
    /// Geographic distribution of downloads.
    pub geographic_distribution: Vec<AtpDownloadRegion>,
    /// Platform distribution.
    pub platform_distribution: BTreeMap<String, u32>,
    /// Version adoption rates.
    pub version_adoption: BTreeMap<String, f64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AtpDownloadRegion {
    /// Geographic region.
    pub region: String,
    /// Download count in region.
    pub download_count: u64,
    /// Regional bandwidth usage.
    pub bandwidth_bps: u64,
}

/// JSON output schema for ATP archive commands.
#[derive(Debug, Serialize, Deserialize)]
pub struct AtpArchiveOutput {
    /// Archive operation result summary.
    pub summary: AtpArchiveSummary,
    /// Archive entries.
    pub archives: Vec<AtpArchiveEntry>,
    /// Storage tier statistics.
    pub storage_stats: Option<AtpArchiveStorageStats>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AtpArchiveSummary {
    /// Operation performed.
    pub operation: String,
    /// Number of archives processed.
    pub archives_processed: u32,
    /// Total archived data in bytes.
    pub total_size_bytes: u64,
    /// Compression ratio achieved.
    pub compression_ratio: f64,
    /// Operation success status.
    pub success: bool,
    /// Error message if failed.
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AtpArchiveEntry {
    /// Archive unique identifier.
    pub id: String,
    /// Original bundle path.
    pub bundle_path: String,
    /// Archive size in bytes.
    pub size_bytes: u64,
    /// Compressed size in bytes.
    pub compressed_size_bytes: u64,
    /// Storage tier.
    pub tier: String,
    /// Archive tags.
    pub tags: Vec<String>,
    /// Checksum for integrity.
    pub checksum: String,
    /// Archive timestamp.
    pub archived_at: chrono::DateTime<chrono::Utc>,
    /// Expiration timestamp.
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Last verification timestamp.
    pub last_verified_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AtpArchiveStorageStats {
    /// Storage usage per tier.
    pub tier_usage: BTreeMap<String, AtpTierStats>,
    /// Total archive count.
    pub total_archives: u32,
    /// Total storage used in bytes.
    pub total_storage_bytes: u64,
    /// Available storage in bytes.
    pub available_storage_bytes: u64,
    /// Integrity check status.
    pub integrity_check_status: AtpIntegrityStatus,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AtpTierStats {
    /// Number of archives in tier.
    pub archive_count: u32,
    /// Storage usage in bytes.
    pub usage_bytes: u64,
    /// Average access latency.
    pub avg_access_latency_ms: f64,
    /// Cost per GB per month.
    pub cost_per_gb_month: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AtpIntegrityStatus {
    /// Last integrity check timestamp.
    pub last_check_at: chrono::DateTime<chrono::Utc>,
    /// Archives verified successfully.
    pub verified_archives: u32,
    /// Archives with integrity issues.
    pub failed_archives: u32,
    /// Pending verification count.
    pub pending_verification: u32,
}

macro_rules! impl_atp_output {
    ($ty:ty, $summary:expr, $tsv:expr) => {
        impl Outputtable for $ty {
            fn human_format(&self) -> String {
                $summary(self)
            }

            fn human_summary(&self) -> String {
                self.human_format()
            }

            fn tsv_format(&self) -> String {
                $tsv(self)
            }
        }
    };
}

impl_atp_output!(
    AtpCiOutput,
    |output: &AtpCiOutput| format!(
        "ATP CI {}: {} artifact(s), {} byte(s), success={}",
        output.summary.operation,
        output.summary.artifacts_processed,
        output.summary.bytes_transferred,
        output.summary.success
    ),
    |output: &AtpCiOutput| format!(
        "{}\t{}\t{}\t{}",
        output.summary.operation,
        output.summary.artifacts_processed,
        output.summary.bytes_transferred,
        output.summary.success
    )
);

impl_atp_output!(
    AtpDatasetOutput,
    |output: &AtpDatasetOutput| format!(
        "ATP dataset {}: {} dataset(s), {} byte(s), success={}",
        output.summary.operation,
        output.summary.datasets_processed,
        output.summary.total_size_bytes,
        output.summary.success
    ),
    |output: &AtpDatasetOutput| format!(
        "{}\t{}\t{}\t{}",
        output.summary.operation,
        output.summary.datasets_processed,
        output.summary.total_size_bytes,
        output.summary.success
    )
);

impl_atp_output!(
    AtpFuzzOutput,
    |output: &AtpFuzzOutput| format!(
        "ATP fuzz {}: target={}, {} case(s), {} byte(s), success={}",
        output.summary.operation,
        output.summary.target,
        output.summary.test_cases_processed,
        output.corpus_stats.total_size_bytes,
        output.summary.success
    ),
    |output: &AtpFuzzOutput| format!(
        "{}\t{}\t{}\t{}\t{}",
        output.summary.operation,
        output.summary.target,
        output.summary.test_cases_processed,
        output.corpus_stats.total_size_bytes,
        output.summary.success
    )
);

impl_atp_output!(
    AtpReleaseOutput,
    |output: &AtpReleaseOutput| format!(
        "ATP release {}: {} release(s), {} byte(s), success={}",
        output.summary.operation,
        output.summary.releases_processed,
        output.summary.total_size_bytes,
        output.summary.success
    ),
    |output: &AtpReleaseOutput| format!(
        "{}\t{}\t{}\t{}",
        output.summary.operation,
        output.summary.releases_processed,
        output.summary.total_size_bytes,
        output.summary.success
    )
);

impl_atp_output!(
    AtpArchiveOutput,
    |output: &AtpArchiveOutput| format!(
        "ATP archive {}: {} archive(s), {} byte(s), success={}",
        output.summary.operation,
        output.summary.archives_processed,
        output.summary.total_size_bytes,
        output.summary.success
    ),
    |output: &AtpArchiveOutput| format!(
        "{}\t{}\t{}\t{}",
        output.summary.operation,
        output.summary.archives_processed,
        output.summary.total_size_bytes,
        output.summary.success
    )
);
