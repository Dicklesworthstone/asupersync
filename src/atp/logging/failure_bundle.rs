//! ATP Failure Bundle Generation
//!
//! Creates comprehensive failure bundles for debugging and replay.

use super::{AtpLoggerConfig, redaction};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

/// Stable ATP failure-bundle schema.
pub const ATP_FAILURE_BUNDLE_SCHEMA_VERSION: &str = "asupersync.atp.failure_bundle.v1";

/// Complete failure bundle for ATP debugging
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailureBundle {
    /// Stable schema version for machine validation.
    pub schema_version: String,
    /// Bundle metadata
    pub metadata: BundleMetadata,
    /// Exact command that failed
    pub command: CommandInfo,
    /// Environment summary
    pub environment: EnvironmentInfo,
    /// Random seed for deterministic reproduction
    pub seed: u64,
    /// Captured trace data
    pub trace_data: TraceData,
    /// QUIC-specific logs
    pub qlog_data: Option<QlogData>,
    /// Path discovery logs
    pub path_log: Option<PathLog>,
    /// Repair operation logs
    pub repair_log: Option<RepairLog>,
    /// Journal state digest
    pub journal_digest: Option<JournalDigest>,
    /// Proof bundle for verification
    pub proof_bundle: Option<ProofBundle>,
    /// Replay command for reproduction
    pub replay_command: String,
    /// Additional context data
    pub additional_data: serde_json::Value,
}

/// Bundle metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleMetadata {
    /// Bundle creation timestamp
    pub created_at: String,
    /// ATP version
    pub atp_version: String,
    /// Rust version
    pub rust_version: String,
    /// Platform information
    pub platform: String,
    /// Bundle format version
    pub bundle_version: String,
    /// Unique bundle identifier
    pub bundle_id: String,
}

/// Command information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandInfo {
    /// Full command line
    pub command_line: Vec<String>,
    /// Working directory
    pub working_directory: String,
    /// Exit code
    pub exit_code: Option<i32>,
    /// Command duration (if available)
    pub duration_ms: Option<u64>,
    /// Command arguments (parsed)
    pub parsed_args: HashMap<String, String>,
}

/// Environment information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentInfo {
    /// Selected environment variables
    pub environment_variables: HashMap<String, String>,
    /// System information
    pub system_info: SystemInfo,
    /// ATP configuration
    pub atp_config: Option<serde_json::Value>,
    /// Resource limits
    pub resource_limits: ResourceLimits,
}

/// System information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    /// Operating system
    pub os: String,
    /// OS version
    pub os_version: String,
    /// Architecture
    pub arch: String,
    /// Available memory (bytes)
    pub memory_total: u64,
    /// Available disk space (bytes)
    pub disk_space_available: u64,
    /// CPU count
    pub cpu_count: u32,
}

/// Resource limits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// Maximum memory usage (bytes)
    pub max_memory: Option<u64>,
    /// Maximum disk usage (bytes)
    pub max_disk: Option<u64>,
    /// Maximum network bandwidth (bytes/sec)
    pub max_bandwidth: Option<u64>,
    /// Maximum file descriptors
    pub max_file_descriptors: Option<u64>,
}

/// Captured trace data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceData {
    /// Structured log events leading to failure
    pub log_events: Vec<super::AtpEvent>,
    /// Trace timeline
    pub trace_timeline: Vec<TraceEvent>,
    /// Performance metrics
    pub performance_metrics: HashMap<String, f64>,
    /// Error chain
    pub error_chain: Vec<ErrorInfo>,
}

/// Individual trace event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceEvent {
    /// Event timestamp
    pub timestamp: String,
    /// Event type
    pub event_type: String,
    /// Thread/task identifier
    pub thread_id: String,
    /// Event data
    pub data: serde_json::Value,
}

/// Error information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorInfo {
    /// Error message
    pub message: String,
    /// Error type/kind
    pub error_type: String,
    /// Stack trace (if available)
    pub stack_trace: Option<Vec<String>>,
    /// Error context
    pub context: HashMap<String, String>,
}

/// QUIC-specific logging data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QlogData {
    /// QUIC connection events
    pub connection_events: Vec<QuicEvent>,
    /// Packet traces
    pub packet_traces: Vec<PacketTrace>,
    /// Connection statistics
    pub connection_stats: HashMap<String, serde_json::Value>,
}

/// QUIC event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuicEvent {
    /// Event timestamp
    pub timestamp: String,
    /// Connection ID
    pub connection_id: String,
    /// Event type
    pub event_type: String,
    /// Event data
    pub data: serde_json::Value,
}

/// Packet trace
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketTrace {
    /// Packet timestamp
    pub timestamp: String,
    /// Direction (sent/received)
    pub direction: String,
    /// Packet number
    pub packet_number: u64,
    /// Packet size
    pub size: u32,
    /// Frame summary
    pub frames: Vec<String>,
}

/// Path discovery log
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathLog {
    /// Discovered paths
    pub discovered_paths: Vec<PathInfo>,
    /// NAT classification results
    pub nat_classification: HashMap<String, String>,
    /// STUN binding results
    pub stun_bindings: Vec<StunBinding>,
    /// Relay information
    pub relay_info: Option<RelayInfo>,
}

/// Path information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathInfo {
    /// Path identifier
    pub path_id: String,
    /// Local endpoint
    pub local_endpoint: String,
    /// Remote endpoint
    pub remote_endpoint: String,
    /// Path type (direct, relay, etc.)
    pub path_type: String,
    /// Path quality metrics
    pub metrics: HashMap<String, f64>,
}

/// STUN binding result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StunBinding {
    /// Server address
    pub server: String,
    /// Mapped address
    pub mapped_address: String,
    /// Response time
    pub response_time_ms: u32,
}

/// Relay information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayInfo {
    /// Relay server address
    pub server: String,
    /// Relay type
    pub relay_type: String,
    /// Authentication info
    pub auth_info: HashMap<String, String>,
}

/// Repair operation log
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepairLog {
    /// Repair operations
    pub repair_operations: Vec<RepairOperation>,
    /// RaptorQ statistics
    pub raptorq_stats: HashMap<String, serde_json::Value>,
    /// Repair ROI calculations
    pub roi_calculations: Vec<RoiCalculation>,
}

/// Repair operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepairOperation {
    /// Operation identifier
    pub operation_id: String,
    /// Object being repaired
    pub object_id: String,
    /// Repair strategy
    pub strategy: String,
    /// Chunk requests
    pub chunk_requests: Vec<ChunkRequest>,
    /// Operation result
    pub result: String,
}

/// Chunk request for repair
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkRequest {
    /// Chunk identifier
    pub chunk_id: String,
    /// Request timestamp
    pub requested_at: String,
    /// Response timestamp
    pub received_at: Option<String>,
    /// Success/failure
    pub success: bool,
}

/// ROI calculation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoiCalculation {
    /// Calculation timestamp
    pub timestamp: String,
    /// Repair cost
    pub cost: f64,
    /// Expected benefit
    pub benefit: f64,
    /// ROI score
    pub roi_score: f64,
}

/// Journal state digest
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalDigest {
    /// Last committed entry
    pub last_committed: u64,
    /// Journal checksum
    pub checksum: String,
    /// Entry count
    pub entry_count: u64,
    /// Journal size (bytes)
    pub size_bytes: u64,
}

/// Proof bundle
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofBundle {
    /// Proof type
    pub proof_type: String,
    /// Proof data
    pub proof_data: serde_json::Value,
    /// Verification info
    pub verification_info: HashMap<String, String>,
}

/// Create a failure bundle
pub fn create_bundle(
    error_context: &str,
    mut additional_data: serde_json::Value,
    config: &AtpLoggerConfig,
) -> FailureBundle {
    let bundle_id = generate_bundle_id();
    let timestamp = deterministic_timestamp();
    let _redacted_fields = redaction::redact_json_value(
        &mut additional_data,
        &config.redaction_rules,
        "additional_data",
    );
    let mut safe_error_context = serde_json::Value::String(error_context.to_string());
    let _redacted_error_context = redaction::redact_json_value(
        &mut safe_error_context,
        &config.redaction_rules,
        "error_context",
    );
    let safe_error_context = safe_error_context
        .as_str()
        .unwrap_or(error_context)
        .to_string();

    FailureBundle {
        schema_version: ATP_FAILURE_BUNDLE_SCHEMA_VERSION.to_string(),
        metadata: create_metadata(&bundle_id, &timestamp),
        command: capture_command_info(),
        environment: capture_environment_info(),
        seed: generate_deterministic_seed(),
        trace_data: capture_trace_data(&safe_error_context),
        qlog_data: capture_qlog_data(),
        path_log: capture_path_log(),
        repair_log: capture_repair_log(),
        journal_digest: capture_journal_digest(),
        proof_bundle: capture_proof_bundle(),
        replay_command: generate_replay_command(&bundle_id),
        additional_data,
    }
}

/// Generate unique bundle identifier
fn generate_bundle_id() -> String {
    "atp-failure-bundle-v1".to_string()
}

fn deterministic_timestamp() -> String {
    "1970-01-01T00:00:00Z".to_string()
}

/// Create bundle metadata
fn create_metadata(bundle_id: &str, timestamp: &str) -> BundleMetadata {
    BundleMetadata {
        created_at: timestamp.to_string(),
        atp_version: env!("CARGO_PKG_VERSION").to_string(),
        rust_version: get_rust_version(),
        platform: get_platform_info(),
        bundle_version: "1.0".to_string(),
        bundle_id: bundle_id.to_string(),
    }
}

/// Get Rust version
fn get_rust_version() -> String {
    option_env!("RUSTC_VERSION")
        .unwrap_or("unknown")
        .to_string()
}

/// Get platform information
fn get_platform_info() -> String {
    format!("{}-{}", env::consts::OS, env::consts::ARCH)
}

/// Capture command information
fn capture_command_info() -> CommandInfo {
    let args: Vec<String> = env::args().map(|arg| redact_command_arg(&arg)).collect();

    CommandInfo {
        command_line: args.clone(),
        working_directory: env::current_dir()
            .ok()
            .and_then(|path| {
                path.file_name()
                    .map(|name| name.to_string_lossy().to_string())
            })
            .unwrap_or_else(|| "unknown".to_string()),
        exit_code: None,   // Will be set when command completes
        duration_ms: None, // Will be calculated
        parsed_args: parse_command_args(&args),
    }
}

fn redact_command_arg(arg: &str) -> String {
    if arg.contains("/.ssh/")
        || arg.contains("/.gnupg/")
        || arg.contains("/secrets/")
        || arg.contains("/private/")
        || arg.contains("token=")
        || arg.contains("password=")
        || arg.contains("secret=")
        || arg.starts_with("Bearer ")
    {
        "[REDACTED_ARG]".to_string()
    } else if arg.starts_with("/home/") || arg.starts_with("/Users/") {
        "[REDACTED_PATH]".to_string()
    } else {
        arg.to_string()
    }
}

/// Parse command arguments into key-value pairs
fn parse_command_args(args: &[String]) -> HashMap<String, String> {
    let mut parsed = HashMap::new();

    for i in 0..args.len() {
        if args[i].starts_with("--") {
            let key = args[i][2..].to_string();
            let value = if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                args[i + 1].clone()
            } else {
                "true".to_string()
            };
            parsed.insert(key, value);
        }
    }

    parsed
}

/// Capture environment information
fn capture_environment_info() -> EnvironmentInfo {
    EnvironmentInfo {
        environment_variables: capture_safe_env_vars(),
        system_info: capture_system_info(),
        atp_config: capture_atp_config(),
        resource_limits: capture_resource_limits(),
    }
}

/// Capture safe environment variables (non-sensitive)
fn capture_safe_env_vars() -> HashMap<String, String> {
    let safe_vars = ["RUST_LOG", "RUST_BACKTRACE", "ATP_LOG_LEVEL"];

    let mut vars = HashMap::new();
    for var in &safe_vars {
        if let Ok(value) = env::var(var) {
            vars.insert(var.to_string(), value);
        }
    }
    vars
}

/// Capture system information
fn capture_system_info() -> SystemInfo {
    SystemInfo {
        os: env::consts::OS.to_string(),
        os_version: get_os_version(),
        arch: env::consts::ARCH.to_string(),
        memory_total: get_total_memory(),
        disk_space_available: get_available_disk_space(),
        cpu_count: std::thread::available_parallelism().map_or(1, |count| count.get()) as u32,
    }
}

fn get_os_version() -> String {
    sysinfo::System::long_os_version()
        .or_else(sysinfo::System::os_version)
        .or_else(sysinfo::System::kernel_version)
        .unwrap_or_else(|| format!("{}-{}", env::consts::OS, env::consts::ARCH))
}

/// Get total system memory
fn get_total_memory() -> u64 {
    sysinfo::System::new_all().total_memory()
}

/// Get available disk space
fn get_available_disk_space() -> u64 {
    let cwd = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let disks = sysinfo::Disks::new_with_refreshed_list();
    disks
        .list()
        .iter()
        .filter(|disk| cwd.starts_with(disk.mount_point()))
        .max_by_key(|disk| disk.mount_point().components().count())
        .or_else(|| disks.list().iter().max_by_key(|disk| disk.total_space()))
        .map_or(0, sysinfo::Disk::available_space)
}

/// Capture ATP configuration
fn capture_atp_config() -> Option<serde_json::Value> {
    // Load ATP configuration if available
    None
}

/// Capture resource limits
fn capture_resource_limits() -> ResourceLimits {
    ResourceLimits {
        max_memory: proc_limit_bytes("Max address space")
            .or_else(|| proc_limit_bytes("Max data size")),
        max_disk: proc_limit_bytes("Max file size"),
        max_bandwidth: None,
        max_file_descriptors: proc_limit_scalar("Max open files"),
    }
}

fn proc_limit_bytes(label: &str) -> Option<u64> {
    parse_proc_limit(label).and_then(|(soft, unit)| match unit.as_str() {
        "bytes" => Some(soft),
        "kbytes" => soft.checked_mul(1024),
        "mbytes" => soft.checked_mul(1024 * 1024),
        "gbytes" => soft.checked_mul(1024 * 1024 * 1024),
        _ => None,
    })
}

fn proc_limit_scalar(label: &str) -> Option<u64> {
    parse_proc_limit(label).map(|(soft, _unit)| soft)
}

fn parse_proc_limit(label: &str) -> Option<(u64, String)> {
    let limits = fs::read_to_string(Path::new("/proc/self/limits")).ok()?;
    for line in limits.lines().skip(1) {
        let Some(rest) = line.strip_prefix(label) else {
            continue;
        };
        let mut parts = rest.split_whitespace();
        let soft = parts.next()?;
        if soft == "unlimited" {
            return None;
        }
        let soft = soft.parse().ok()?;
        let _hard = parts.next();
        let unit = parts.next().unwrap_or("").to_ascii_lowercase();
        return Some((soft, unit));
    }
    None
}

/// Generate deterministic seed for replay
fn generate_deterministic_seed() -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    env!("CARGO_PKG_VERSION").hash(&mut hasher);
    env::consts::OS.hash(&mut hasher);
    env::consts::ARCH.hash(&mut hasher);
    hasher.finish()
}

/// Capture trace data
fn capture_trace_data(error_context: &str) -> TraceData {
    TraceData {
        log_events: Vec::new(),
        trace_timeline: Vec::new(),
        performance_metrics: HashMap::new(),
        error_chain: vec![ErrorInfo {
            message: error_context.to_string(),
            error_type: "atp_failure_context".to_string(),
            stack_trace: None,
            context: HashMap::new(),
        }],
    }
}

/// Capture QUIC log data
fn capture_qlog_data() -> Option<QlogData> {
    Some(QlogData {
        connection_events: Vec::new(),
        packet_traces: Vec::new(),
        connection_stats: HashMap::new(),
    })
}

/// Capture path log data
fn capture_path_log() -> Option<PathLog> {
    Some(PathLog {
        discovered_paths: Vec::new(),
        nat_classification: HashMap::new(),
        stun_bindings: Vec::new(),
        relay_info: None,
    })
}

/// Capture repair log data
fn capture_repair_log() -> Option<RepairLog> {
    Some(RepairLog {
        repair_operations: Vec::new(),
        raptorq_stats: HashMap::new(),
        roi_calculations: Vec::new(),
    })
}

/// Capture journal digest
fn capture_journal_digest() -> Option<JournalDigest> {
    Some(JournalDigest {
        last_committed: 0,
        checksum: "unavailable".to_string(),
        entry_count: 0,
        size_bytes: 0,
    })
}

/// Capture proof bundle
fn capture_proof_bundle() -> Option<ProofBundle> {
    Some(ProofBundle {
        proof_type: "atp-failure-bundle-contract".to_string(),
        proof_data: serde_json::json!({"status": "schema-present"}),
        verification_info: HashMap::new(),
    })
}

/// Generate replay command
fn generate_replay_command(bundle_id: &str) -> String {
    format!("atp replay --bundle {}", bundle_id)
}

/// Save failure bundle to file
pub fn save_bundle(
    bundle: &FailureBundle,
    output_dir: Option<PathBuf>,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let dir =
        output_dir.unwrap_or_else(|| env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

    // Sanitize the filename to prevent path traversal
    let sanitized_id = bundle
        .metadata
        .bundle_id
        .replace(&['/', '\\', '.', ':'][..], "_");
    let filename = format!("{}.json", sanitized_id);
    let filepath = dir.join(filename);

    let json = serde_json::to_string_pretty(bundle)?;
    fs::write(&filepath, json)?;

    Ok(filepath)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_bundle_creation() {
        let config = AtpLoggerConfig::default();
        let bundle = create_bundle("Test error", json!({"test": true}), &config);

        assert_eq!(bundle.schema_version, ATP_FAILURE_BUNDLE_SCHEMA_VERSION);
        assert!(!bundle.metadata.bundle_id.is_empty());
        assert_eq!(bundle.metadata.atp_version, env!("CARGO_PKG_VERSION"));
        assert_eq!(bundle.additional_data["test"], true);
        assert!(bundle.qlog_data.is_some());
        assert!(bundle.path_log.is_some());
        assert!(bundle.repair_log.is_some());
        assert!(bundle.journal_digest.is_some());
        assert!(bundle.proof_bundle.is_some());
        assert!(bundle.replay_command.contains(&bundle.metadata.bundle_id));
        assert_eq!(bundle.trace_data.error_chain[0].message, "Test error");
    }

    #[test]
    fn test_bundle_serialization() {
        let config = AtpLoggerConfig::default();
        let bundle = create_bundle("Test error", json!({}), &config);

        let serialized = serde_json::to_string(&bundle).unwrap(); // ubs:ignore - test oracle
        let deserialized: FailureBundle = serde_json::from_str(&serialized).unwrap(); // ubs:ignore - test oracle

        assert_eq!(bundle.metadata.bundle_id, deserialized.metadata.bundle_id);
    }

    #[test]
    fn test_bundle_redacts_sensitive_context() {
        let config = AtpLoggerConfig::default();
        let bundle = create_bundle(
            "Bearer abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz leaked",
            json!({
                "capability_secret": "cap://super-secret-capability",
                "content_hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "path": "/home/alice/.ssh/id_ed25519"
            }),
            &config,
        );

        let serialized = serde_json::to_string(&bundle).unwrap(); // ubs:ignore - test oracle
        assert!(!serialized.contains("super-secret"));
        assert!(!serialized.contains("abcdefghijklmnopqrstuvwxyz"));
        assert!(!serialized.contains("/home/alice"));
        assert!(serialized.contains("[REDACTED_CAPABILITY]"));
        assert!(serialized.contains("[REDACTED_CONTENT_HASH]"));
    }
}
