//! ATP Daemon (atpd) - Asupersync Transfer Protocol Daemon
//!
//! The ATP daemon provides always-on ATP transfer capabilities including:
//! - Identity and grant management
//! - Inbox and mailbox handling
//! - Peer directory and discovery
//! - Cache management and seeding
//! - Background transfer processing
//! - Service lifecycle management
//! - Diagnostics and monitoring

use anyhow::Result;
use asupersync::atp::identity::PeerId;
use asupersync::cx::Cx;
use asupersync::runtime::{RuntimeBuilder, RuntimeConfig};
use asupersync::supervision::{SupervisorConfig, SupervisorTree};
use asupersync::types::{Budget, Time};
use clap::{Args, Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;
use toml;
use tracing::{error, info, warn};

/// ATP Daemon - Always-on ATP transfer service
#[derive(Parser)]
#[command(name = "atpd")]
#[command(about = "ATP daemon for always-on transfer capabilities")]
#[command(version = env!("CARGO_PKG_VERSION"))]
struct AtpdCli {
    #[command(subcommand)]
    command: AtpdCommand,

    /// Configuration file path
    #[arg(long, short = 'c', default_value = "/etc/atpd/config.toml")]
    config: PathBuf,

    /// Log level
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Run as foreground process (don't daemonize)
    #[arg(long)]
    foreground: bool,

    /// PID file location
    #[arg(long, default_value = "/var/run/atpd.pid")]
    pid_file: PathBuf,
}

#[derive(Subcommand)]
enum AtpdCommand {
    /// Start the ATP daemon
    Start(StartArgs),
    /// Stop the ATP daemon
    Stop,
    /// Check daemon status
    Status,
    /// Reload daemon configuration
    Reload,
    /// Initialize daemon configuration
    Init(InitArgs),
    /// Show daemon diagnostics
    Diagnostics,
    /// Manage daemon identity
    Identity(IdentityArgs),
}

#[derive(Args)]
struct StartArgs {
    /// Bind address for ATP service
    #[arg(long, default_value = "0.0.0.0:8472")]
    bind: SocketAddr,

    /// Data directory for ATP daemon
    #[arg(long, default_value = "/var/lib/atpd")]
    data_dir: PathBuf,

    /// Maximum concurrent transfers
    #[arg(long, default_value = "16")]
    max_transfers: u32,

    /// Enable relay mode
    #[arg(long)]
    enable_relay: bool,

    /// Enable mailbox mode
    #[arg(long)]
    enable_mailbox: bool,
}

#[derive(Args)]
struct InitArgs {
    /// Data directory to initialize
    #[arg(long, default_value = "/var/lib/atpd")]
    data_dir: PathBuf,

    /// Generate new identity
    #[arg(long)]
    new_identity: bool,

    /// Copy identity from path
    #[arg(long)]
    copy_identity: Option<PathBuf>,
}

#[derive(Args)]
struct IdentityArgs {
    #[command(subcommand)]
    action: IdentityAction,
}

#[derive(Subcommand)]
enum IdentityAction {
    /// Show current daemon identity
    Show,
    /// Generate new daemon identity
    Generate,
    /// Import identity from file
    Import { path: PathBuf },
    /// Export identity to file
    Export { path: PathBuf },
}

/// ATP Daemon configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtpdConfig {
    /// Daemon identity configuration
    pub identity: IdentityConfig,
    /// Network configuration
    pub network: NetworkConfig,
    /// Storage configuration
    pub storage: StorageConfig,
    /// Transfer configuration
    pub transfers: TransferConfig,
    /// Service configuration
    pub service: ServiceConfig,
    /// Diagnostics configuration
    pub diagnostics: DiagnosticsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityConfig {
    /// Peer ID (derived from private key)
    pub peer_id: String,
    /// Private key file path
    pub private_key_path: PathBuf,
    /// Device name/nickname
    pub device_name: String,
    /// Team/group memberships
    pub team_memberships: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Bind address for ATP service
    pub bind_addr: SocketAddr,
    /// Enable QUIC transport
    pub enable_quic: bool,
    /// Enable relay functionality
    pub enable_relay: bool,
    /// Enable mailbox functionality
    pub enable_mailbox: bool,
    /// Discovery configuration
    pub discovery: DiscoveryConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryConfig {
    /// Enable local network discovery
    pub enable_local: bool,
    /// Enable internet relay discovery
    pub enable_relay_discovery: bool,
    /// Known relay servers
    pub relay_servers: Vec<String>,
    /// Bootstrap peers
    pub bootstrap_peers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Data directory
    pub data_dir: PathBuf,
    /// Cache directory
    pub cache_dir: PathBuf,
    /// Maximum cache size in bytes
    pub max_cache_size: u64,
    /// Cache retention policy in seconds
    pub cache_retention_secs: u64,
    /// Journal configuration
    pub journal: JournalConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalConfig {
    /// Enable persistent journal
    pub enable: bool,
    /// Journal file path
    pub journal_path: PathBuf,
    /// Maximum journal size in bytes
    pub max_journal_size: u64,
    /// Journal rotation policy
    pub rotation_policy: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferConfig {
    /// Maximum concurrent transfers
    pub max_concurrent: u32,
    /// Default transfer timeout in seconds
    pub default_timeout_secs: u64,
    /// Maximum transfer size in bytes
    pub max_transfer_size: u64,
    /// Enable bandwidth limiting
    pub enable_bandwidth_limit: bool,
    /// Bandwidth limit in bytes per second
    pub bandwidth_limit_bps: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    /// Enable auto-start on system boot
    pub auto_start: bool,
    /// Restart policy
    pub restart_policy: RestartPolicy,
    /// Health check configuration
    pub health_check: HealthCheckConfig,
    /// Graceful shutdown timeout in seconds
    pub shutdown_timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RestartPolicy {
    Never,
    Always,
    OnFailure,
    UnlessStopped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    /// Enable health checks
    pub enable: bool,
    /// Health check interval in seconds
    pub interval_secs: u64,
    /// Health check timeout in seconds
    pub timeout_secs: u64,
    /// Failure threshold before restart
    pub failure_threshold: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticsConfig {
    /// Enable metrics collection
    pub enable_metrics: bool,
    /// Metrics bind address
    pub metrics_bind: Option<SocketAddr>,
    /// Enable debug endpoints
    pub enable_debug: bool,
    /// Log configuration
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level
    pub level: String,
    /// Log format (json or human)
    pub format: String,
    /// Log file path
    pub file_path: Option<PathBuf>,
    /// Log rotation configuration
    pub rotation: Option<LogRotationConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogRotationConfig {
    /// Maximum log file size in bytes
    pub max_size: u64,
    /// Number of rotated files to keep
    pub keep_files: u32,
    /// Rotation frequency
    pub frequency: String,
}

/// ATP Daemon state
pub struct AtpdState {
    config: AtpdConfig,
    supervisor: SupervisorTree,
    runtime_handle: asupersync::runtime::RuntimeHandle,
    start_time: Time,
    peer_directory: HashMap<PeerId, PeerInfo>,
    active_transfers: HashMap<String, TransferInfo>,
    inbox_messages: Vec<InboxMessage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub peer_id: PeerId,
    pub device_name: String,
    pub last_seen: Time,
    pub addresses: Vec<SocketAddr>,
    pub capabilities: Vec<String>,
    pub trust_level: TrustLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrustLevel {
    Unknown,
    Known,
    Trusted,
    TeamMember,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferInfo {
    pub transfer_id: String,
    pub peer_id: PeerId,
    pub direction: TransferDirection,
    pub status: TransferStatus,
    pub start_time: Time,
    pub bytes_transferred: u64,
    pub total_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransferDirection {
    Send,
    Receive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransferStatus {
    Queued,
    Active,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboxMessage {
    pub message_id: String,
    pub from_peer: PeerId,
    pub received_at: Time,
    pub content_type: String,
    pub content_size: u64,
    pub is_read: bool,
}

impl Default for AtpdConfig {
    fn default() -> Self {
        Self {
            identity: IdentityConfig {
                peer_id: "peer-uninitialized".to_string(),
                private_key_path: PathBuf::from("/var/lib/atpd/identity/private.key"),
                device_name: "atpd-node".to_string(),
                team_memberships: vec![],
            },
            network: NetworkConfig {
                bind_addr: "0.0.0.0:8472".parse().unwrap(),
                enable_quic: true,
                enable_relay: false,
                enable_mailbox: false,
                discovery: DiscoveryConfig {
                    enable_local: true,
                    enable_relay_discovery: false,
                    relay_servers: vec![],
                    bootstrap_peers: vec![],
                },
            },
            storage: StorageConfig {
                data_dir: PathBuf::from("/var/lib/atpd"),
                cache_dir: PathBuf::from("/var/lib/atpd/cache"),
                max_cache_size: 10 * 1024 * 1024 * 1024, // 10GB
                cache_retention_secs: 30 * 24 * 3600,    // 30 days
                journal: JournalConfig {
                    enable: true,
                    journal_path: PathBuf::from("/var/lib/atpd/journal"),
                    max_journal_size: 1024 * 1024 * 1024, // 1GB
                    rotation_policy: "daily".to_string(),
                },
            },
            transfers: TransferConfig {
                max_concurrent: 16,
                default_timeout_secs: 3600,                  // 1 hour
                max_transfer_size: 100 * 1024 * 1024 * 1024, // 100GB
                enable_bandwidth_limit: false,
                bandwidth_limit_bps: None,
            },
            service: ServiceConfig {
                auto_start: false,
                restart_policy: RestartPolicy::OnFailure,
                health_check: HealthCheckConfig {
                    enable: true,
                    interval_secs: 30,
                    timeout_secs: 5,
                    failure_threshold: 3,
                },
                shutdown_timeout_secs: 30,
            },
            diagnostics: DiagnosticsConfig {
                enable_metrics: true,
                metrics_bind: Some("127.0.0.1:8473".parse().unwrap()),
                enable_debug: false,
                logging: LoggingConfig {
                    level: "info".to_string(),
                    format: "json".to_string(),
                    file_path: Some(PathBuf::from("/var/log/atpd.log")),
                    rotation: Some(LogRotationConfig {
                        max_size: 100 * 1024 * 1024, // 100MB
                        keep_files: 5,
                        frequency: "daily".to_string(),
                    }),
                },
            },
        }
    }
}

/// Load daemon configuration from file or return default config
fn load_daemon_config(config_path: &PathBuf) -> Result<AtpdConfig> {
    if config_path.exists() {
        let content = std::fs::read_to_string(config_path)
            .map_err(|e| anyhow::anyhow!("Failed to read config file: {}", e))?;

        let config: AtpdConfig = toml::from_str(&content)
            .map_err(|e| anyhow::anyhow!("Failed to parse config file: {}", e))?;

        Ok(config)
    } else {
        // Return default configuration
        warn!("Config file not found, using default configuration");
        Ok(AtpdConfig::default())
    }
}

fn main() -> Result<()> {
    let cli = AtpdCli::parse();

    // Initialize logging
    init_logging(&cli.log_level)?;

    match cli.command {
        AtpdCommand::Start(args) => start_daemon(cli, args),
        AtpdCommand::Stop => stop_daemon(cli),
        AtpdCommand::Status => show_status(cli),
        AtpdCommand::Reload => reload_daemon(cli),
        AtpdCommand::Init(args) => init_daemon(cli, args),
        AtpdCommand::Diagnostics => show_diagnostics(cli),
        AtpdCommand::Identity(args) => manage_identity(cli, args),
    }
}

fn init_logging(level: &str) -> Result<()> {
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

    let level = level.parse()?;

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(false)
                .with_level(true)
                .with_thread_ids(false)
                .with_line_number(true),
        )
        .with(tracing_subscriber::filter::LevelFilter::from_level(level))
        .init();

    Ok(())
}

fn start_daemon(cli: AtpdCli, args: StartArgs) -> Result<()> {
    info!("Starting ATP daemon...");

    // Load configuration
    let mut config = load_config(&cli.config).unwrap_or_else(|_| {
        warn!(
            "Failed to load config from {}, using defaults",
            cli.config.display()
        );
        AtpdConfig::default()
    });

    // Override config with command line arguments
    config.network.bind_addr = args.bind;
    config.storage.data_dir = args.data_dir.clone();
    config.transfers.max_concurrent = args.max_transfers;
    config.network.enable_relay = args.enable_relay;
    config.network.enable_mailbox = args.enable_mailbox;

    // Create data directory if it doesn't exist
    std::fs::create_dir_all(&config.storage.data_dir)?;
    std::fs::create_dir_all(&config.storage.cache_dir)?;

    // Initialize runtime
    let runtime = RuntimeBuilder::new()
        .worker_threads(4)
        .thread_name_prefix("atpd-worker".to_string())
        .build()?;
    let runtime_handle = runtime.handle().clone();

    info!("ATP daemon started on {}", config.network.bind_addr);
    info!("Data directory: {}", config.storage.data_dir.display());
    info!("Cache directory: {}", config.storage.cache_dir.display());
    info!(
        "Max concurrent transfers: {}",
        config.transfers.max_concurrent
    );

    // Enter the runtime and run the daemon
    runtime.block_on(async { run_daemon_service(config, runtime_handle).await })?;

    info!("ATP daemon stopped");
    Ok(())
}

async fn run_daemon_service(
    config: AtpdConfig,
    runtime_handle: asupersync::runtime::RuntimeHandle,
) -> Result<()> {
    // Create supervisor tree for daemon components
    let supervisor_config = SupervisorConfig::builder()
        .with_name("atpd-supervisor")
        .with_restart_policy(asupersync::supervision::RestartPolicy::OneForOne)
        .build();

    let _supervisor = SupervisorTree::start(supervisor_config).await?;

    // Initialize daemon state
    let _daemon_state = AtpdState {
        config: config.clone(),
        supervisor: _supervisor,
        runtime_handle,
        start_time: Time::from_nanos(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64,
        ),
        peer_directory: HashMap::new(),
        active_transfers: HashMap::new(),
        inbox_messages: Vec::new(),
    };

    // Start daemon services
    info!("Starting ATP daemon services...");

    // TODO: Start actual daemon services:
    // - Identity service
    // - Network listener
    // - Transfer manager
    // - Inbox/mailbox handler
    // - Cache manager
    // - Discovery service
    // - Health check service
    // - Metrics service

    // For now, just wait for shutdown signal
    tokio::signal::ctrl_c().await?;

    info!("Received shutdown signal, stopping daemon...");
    Ok(())
}

fn stop_daemon(cli: AtpdCli) -> Result<()> {
    info!("Stopping ATP daemon...");

    // Check if PID file exists
    if !cli.pid_file.exists() {
        println!("ATP daemon is not running (no PID file found)");
        return Ok(());
    }

    // Read PID from file
    let pid_content = std::fs::read_to_string(&cli.pid_file)
        .map_err(|e| anyhow::anyhow!("Failed to read PID file: {}", e))?;

    let pid: u32 = pid_content
        .trim()
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid PID in file: {}", e))?;

    #[cfg(unix)]
    {
        use std::process::Command;
        use std::time::Instant;

        // Send SIGTERM for graceful shutdown
        info!("Sending SIGTERM to process {}", pid);
        let term_result = Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .output();

        match term_result {
            Ok(output) if output.status.success() => {
                println!("Sent shutdown signal to ATP daemon (PID: {})", pid);

                // Wait for graceful shutdown (up to 10 seconds)
                let start = Instant::now();
                let timeout = Duration::from_secs(10);

                loop {
                    let check = Command::new("kill").args(["-0", &pid.to_string()]).output();

                    if let Ok(output) = check {
                        if !output.status.success() {
                            // Process has stopped
                            break;
                        }
                    }

                    if start.elapsed() > timeout {
                        warn!("Graceful shutdown timeout, sending SIGKILL");
                        let _ = Command::new("kill")
                            .args(["-KILL", &pid.to_string()])
                            .output();
                        break;
                    }

                    std::thread::sleep(Duration::from_millis(100));
                }

                // Remove PID file
                if let Err(e) = std::fs::remove_file(&cli.pid_file) {
                    warn!("Failed to remove PID file: {}", e);
                } else {
                    info!("Removed PID file");
                }

                println!("ATP daemon stopped successfully");
            }
            Ok(_) => {
                println!("Process {} not found (may have already stopped)", pid);
                // Clean up stale PID file
                let _ = std::fs::remove_file(&cli.pid_file);
            }
            Err(e) => {
                return Err(anyhow::anyhow!("Failed to stop daemon: {}", e));
            }
        }
    }

    #[cfg(not(unix))]
    {
        println!("Daemon stop not supported on this platform");
        println!("Manual process termination required for PID: {}", pid);
    }

    Ok(())
}

fn show_status(cli: AtpdCli) -> Result<()> {
    info!("Checking ATP daemon status...");

    // Check if PID file exists
    if !cli.pid_file.exists() {
        println!("ATP daemon: STOPPED (no PID file found)");
        return Ok(());
    }

    // Read PID from file
    let pid_content = std::fs::read_to_string(&cli.pid_file)
        .map_err(|e| anyhow::anyhow!("Failed to read PID file: {}", e))?;

    let pid: u32 = pid_content
        .trim()
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid PID in file: {}", e))?;

    // Check if process is actually running
    #[cfg(unix)]
    {
        use std::process::Command;
        let status = Command::new("kill").args(["-0", &pid.to_string()]).output();

        match status {
            Ok(output) if output.status.success() => {
                println!("ATP daemon: RUNNING (PID: {})", pid);
                println!("PID file: {}", cli.pid_file.display());
                println!("Config file: {}", cli.config.display());
            }
            _ => {
                println!("ATP daemon: STOPPED (stale PID file)");
                warn!("PID file exists but process {} is not running", pid);
            }
        }
    }

    #[cfg(not(unix))]
    {
        println!(
            "ATP daemon: UNKNOWN (PID: {}) - status check not supported on this platform",
            pid
        );
        println!("PID file: {}", cli.pid_file.display());
    }

    Ok(())
}

fn reload_daemon(_cli: AtpdCli) -> Result<()> {
    info!("Reloading ATP daemon configuration...");
    // TODO: Implement config reload
    // - Send reload signal to running daemon
    // - Validate new configuration
    println!("ATP daemon reload requested (not yet implemented)");
    Ok(())
}

fn init_daemon(_cli: AtpdCli, args: InitArgs) -> Result<()> {
    info!("Initializing ATP daemon...");

    // Create data directory structure
    std::fs::create_dir_all(&args.data_dir)?;
    std::fs::create_dir_all(args.data_dir.join("cache"))?;
    std::fs::create_dir_all(args.data_dir.join("identity"))?;
    std::fs::create_dir_all(args.data_dir.join("inbox"))?;
    std::fs::create_dir_all(args.data_dir.join("journal"))?;

    info!(
        "Created data directory structure at {}",
        args.data_dir.display()
    );

    if args.new_identity {
        info!("Generating new daemon identity...");
        // TODO: Generate new identity
        // - Create new Ed25519 key pair
        // - Generate peer ID
        // - Save to identity directory
        println!("Identity generation (not yet implemented)");
    }

    if let Some(source_path) = args.copy_identity {
        info!("Copying identity from {}", source_path.display());
        // TODO: Copy identity files
        println!("Identity copy (not yet implemented)");
    }

    println!("ATP daemon initialization complete");
    Ok(())
}

fn show_diagnostics(cli: AtpdCli) -> Result<()> {
    info!("Showing ATP daemon diagnostics...");

    println!("=== ATP Daemon Diagnostics ===");
    println!();

    // Daemon status
    println!("📊 Daemon Status:");
    if cli.pid_file.exists() {
        match std::fs::read_to_string(&cli.pid_file) {
            Ok(pid_content) => {
                if let Ok(pid) = pid_content.trim().parse::<u32>() {
                    #[cfg(unix)]
                    {
                        use std::process::Command;
                        let running = Command::new("kill")
                            .args(["-0", &pid.to_string()])
                            .output()
                            .map(|o| o.status.success())
                            .unwrap_or(false);

                        if running {
                            println!("  Status: ✅ RUNNING (PID: {})", pid);
                        } else {
                            println!("  Status: ❌ STOPPED (stale PID file)");
                        }
                    }
                    #[cfg(not(unix))]
                    {
                        println!("  Status: ❓ UNKNOWN (PID: {})", pid);
                    }
                } else {
                    println!("  Status: ❌ INVALID PID file");
                }
            }
            Err(_) => println!("  Status: ❌ Cannot read PID file"),
        }
    } else {
        println!("  Status: ⭕ STOPPED (no PID file)");
    }

    println!("  Config: {}", cli.config.display());
    println!("  PID file: {}", cli.pid_file.display());
    println!();

    // Configuration info
    println!("⚙️  Configuration:");
    if cli.config.exists() {
        match std::fs::read_to_string(&cli.config) {
            Ok(content) => {
                println!("  Config file: ✅ Found ({} bytes)", content.len());
                // Try to parse as TOML for validation
                match toml::from_str::<toml::Value>(&content) {
                    Ok(_) => println!("  Config syntax: ✅ Valid TOML"),
                    Err(e) => println!("  Config syntax: ❌ Invalid TOML: {}", e),
                }
            }
            Err(e) => println!("  Config file: ❌ Cannot read: {}", e),
        }
    } else {
        println!("  Config file: ⚠️  Not found (will use defaults)");
    }
    println!();

    // System info
    println!("🖥️  System Information:");
    println!("  Platform: {}", std::env::consts::OS);
    println!("  Architecture: {}", std::env::consts::ARCH);

    // Try to get hostname from environment or system
    let hostname = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "unknown".to_string());
    println!("  Hostname: {}", hostname);
    println!();

    // Future placeholder sections (not yet implemented)
    println!("📈 Transfer Statistics: (not yet available)");
    println!("🤝 Peer Directory: (not yet available)");
    println!("💾 Cache Status: (not yet available)");
    println!("📋 Journal Status: (not yet available)");

    Ok(())
}

fn manage_identity(_cli: AtpdCli, args: IdentityArgs) -> Result<()> {
    match args.action {
        IdentityAction::Show => {
            info!("Showing daemon identity...");

            // Load daemon configuration to find data directory
            let config = load_daemon_config(&_cli.config)?;

            let identity_dir = config.storage.data_dir.join("identity");
            let peer_id_file = identity_dir.join("peer_id");
            let private_key_file = identity_dir.join("private_key");

            println!("=== ATP Daemon Identity ===");
            println!();

            println!("📁 Identity Directory:");
            println!("  Path: {}", identity_dir.display());
            if identity_dir.exists() {
                println!("  Status: ✅ Exists");
            } else {
                println!("  Status: ❌ Not found");
                return Ok(());
            }
            println!();

            println!("🆔 Peer Identity:");
            if peer_id_file.exists() {
                match std::fs::read_to_string(&peer_id_file) {
                    Ok(peer_id) => {
                        println!("  Peer ID: {}", peer_id.trim());
                        println!("  Status: ✅ Valid");
                    }
                    Err(e) => println!("  Status: ❌ Cannot read peer ID: {}", e),
                }
            } else {
                println!("  Status: ❌ Peer ID file not found");
            }
            println!();

            println!("🔑 Private Key:");
            if private_key_file.exists() {
                match std::fs::metadata(&private_key_file) {
                    Ok(metadata) => {
                        println!("  Status: ✅ Present ({} bytes)", metadata.len());

                        // Check file permissions on Unix
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            let perms = metadata.permissions();
                            let mode = perms.mode() & 0o777;
                            if mode == 0o600 {
                                println!("  Permissions: ✅ Secure (600)");
                            } else {
                                println!(
                                    "  Permissions: ⚠️  Insecure ({:o}) - should be 600",
                                    mode
                                );
                            }
                        }
                    }
                    Err(e) => println!("  Status: ❌ Cannot access: {}", e),
                }
            } else {
                println!("  Status: ❌ Private key file not found");
            }
            println!();

            if !peer_id_file.exists() || !private_key_file.exists() {
                println!("💡 To generate a new identity, run:");
                println!("   atpd identity generate");
            }
        }
        IdentityAction::Generate => {
            info!("Generating new daemon identity...");
            // TODO: Generate new identity
            println!("Identity generation (not yet implemented)");
        }
        IdentityAction::Import { path } => {
            info!("Importing identity from {}", path.display());
            // TODO: Import identity
            println!("Identity import (not yet implemented)");
        }
        IdentityAction::Export { path } => {
            info!("Exporting identity to {}", path.display());
            // TODO: Export identity
            println!("Identity export (not yet implemented)");
        }
    }
    Ok(())
}

fn load_config(path: &std::path::Path) -> Result<AtpdConfig> {
    let content = std::fs::read_to_string(path)?;

    let config: AtpdConfig = toml::from_str(&content)?;

    Ok(config)
}
