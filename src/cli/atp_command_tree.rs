//! ATP-I1: Complete ATP CLI command tree and architecture.
//!
//! This module defines the comprehensive ATP command architecture for
//! asupersync-swezeg (ATP-I1), including:
//! - Complete command tree for all ATP operations
//! - Configuration profile system with precedence
//! - JSON output contracts for machine parsing
//! - UX-optimized defaults with expert diagnostics

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
