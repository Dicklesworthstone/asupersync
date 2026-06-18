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

#![allow(unsafe_code)]

use asupersync::atp::atpd::AtpdAppSpec;
use asupersync::atp::identity::DurablePeerIdentity;
use asupersync::atp::supervision::{AtpdChildRole, AtpdRegionId};
use asupersync::net::atp::protocol::PeerId;
use asupersync::runtime::RuntimeBuilder;
#[cfg(feature = "tls")]
use asupersync::security::{AUTH_KEY_SIZE, AuthKey, SecurityContext};
use asupersync::security::{IdentityKeyStore, KeyStoreError};
use asupersync::types::Time;
use clap::{Args, Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

fn cli_error(message: impl Into<String>) -> Box<dyn Error + Send + Sync> {
    Box::new(std::io::Error::other(message.into()))
}

#[cfg(windows)]
fn default_atpd_root_dir() -> PathBuf {
    std::env::var_os("PROGRAMDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("asupersync")
        .join("atpd")
}

#[cfg(not(windows))]
fn default_atpd_config_path() -> PathBuf {
    PathBuf::from("/etc/atpd/config.toml")
}

#[cfg(windows)]
fn default_atpd_config_path() -> PathBuf {
    default_atpd_root_dir().join("config.toml")
}

#[cfg(not(windows))]
fn default_atpd_pid_file() -> PathBuf {
    PathBuf::from("/var/run/atpd.pid")
}

#[cfg(windows)]
fn default_atpd_pid_file() -> PathBuf {
    default_atpd_root_dir().join("run").join("atpd.pid")
}

#[cfg(not(windows))]
fn default_atpd_data_dir() -> PathBuf {
    PathBuf::from("/var/lib/atpd")
}

#[cfg(windows)]
fn default_atpd_data_dir() -> PathBuf {
    default_atpd_root_dir().join("data")
}

#[cfg(not(windows))]
fn default_atpd_log_file() -> PathBuf {
    PathBuf::from("/var/log/atpd.log")
}

#[cfg(windows)]
fn default_atpd_log_file() -> PathBuf {
    default_atpd_root_dir().join("logs").join("atpd.log")
}

/// ATP Daemon - Always-on ATP transfer service
#[derive(Parser)]
#[command(name = "atpd")]
#[command(about = "ATP daemon for always-on transfer capabilities")]
#[command(version = env!("CARGO_PKG_VERSION"))]
struct AtpdCli {
    #[command(subcommand)]
    command: AtpdCommand,

    /// Configuration file path
    #[arg(long, short = 'c', default_value_os_t = default_atpd_config_path())]
    config: PathBuf,

    /// Log level
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Run as foreground process (don't daemonize)
    #[arg(long)]
    foreground: bool,

    /// PID file location
    #[arg(long, default_value_os_t = default_atpd_pid_file())]
    pid_file: PathBuf,
}

#[derive(Clone, Subcommand)]
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

#[derive(Args, Clone)]
struct StartArgs {
    /// Bind address for ATP service
    #[arg(long)]
    bind: Option<SocketAddr>,

    /// Data directory for ATP daemon
    #[arg(long)]
    data_dir: Option<PathBuf>,

    /// Maximum concurrent transfers
    #[arg(long)]
    max_transfers: Option<u32>,

    /// Enable relay mode
    #[arg(long)]
    enable_relay: bool,

    /// Enable mailbox mode
    #[arg(long)]
    enable_mailbox: bool,

    /// Enable the ATP-over-QUIC transfer listener.
    #[arg(long)]
    enable_quic: bool,

    /// PEM certificate chain presented by the QUIC listener.
    #[arg(long, value_name = "PATH")]
    quic_server_cert: Option<PathBuf>,

    /// PEM private key for the QUIC listener certificate.
    #[arg(long, value_name = "PATH")]
    quic_server_key: Option<PathBuf>,

    /// Hex-encoded 32-byte per-symbol auth key for RaptorQ-over-QUIC symbols.
    #[arg(long, value_name = "HEX")]
    rq_auth_key_hex: Option<String>,

    /// Explicitly disable per-symbol auth for trusted loopback/lab QUIC runs.
    #[arg(long)]
    rq_allow_unauthenticated_lab: bool,

    /// Diagnostics HTTP bind address. Use 127.0.0.1:0 for an ephemeral local port.
    #[arg(long, value_name = "ADDR")]
    diagnostics_bind: Option<SocketAddr>,
}

#[derive(Args, Clone)]
struct InitArgs {
    /// Data directory to initialize
    #[arg(long, default_value_os_t = default_atpd_data_dir())]
    data_dir: PathBuf,

    /// Generate new identity
    #[arg(long)]
    new_identity: bool,

    /// Copy identity from path
    #[arg(long)]
    copy_identity: Option<PathBuf>,
}

#[derive(Args, Clone)]
struct IdentityArgs {
    #[command(subcommand)]
    action: IdentityAction,
}

#[derive(Clone, Subcommand)]
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
    /// QUIC listener TLS/auth configuration.
    #[serde(default)]
    pub quic: QuicDaemonConfig,
    /// Enable relay functionality
    pub enable_relay: bool,
    /// Enable mailbox functionality
    pub enable_mailbox: bool,
    /// Discovery configuration
    pub discovery: DiscoveryConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct QuicDaemonConfig {
    /// PEM certificate chain presented by the QUIC listener.
    pub server_cert_path: Option<PathBuf>,
    /// PEM private key for the QUIC listener certificate.
    pub server_key_path: Option<PathBuf>,
    /// Hex-encoded 32-byte per-symbol auth key for RaptorQ-over-QUIC symbols.
    pub rq_auth_key_hex: Option<String>,
    /// Explicit loopback/lab-only unauthenticated symbol mode.
    pub allow_unauthenticated_lab: bool,
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
        let data_dir = default_atpd_data_dir();
        Self {
            identity: IdentityConfig {
                peer_id: "peer-uninitialized".to_string(),
                private_key_path: init_identity_store_path(&data_dir),
                device_name: "atpd-node".to_string(),
                team_memberships: vec![],
            },
            network: NetworkConfig {
                bind_addr: "0.0.0.0:8472".parse().unwrap(),
                enable_quic: false,
                quic: QuicDaemonConfig::default(),
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
                data_dir: data_dir.clone(),
                cache_dir: data_dir.join("cache"),
                max_cache_size: 10 * 1024 * 1024 * 1024, // 10GB
                cache_retention_secs: 30 * 24 * 3600,    // 30 days
                journal: JournalConfig {
                    enable: true,
                    journal_path: data_dir.join("journal"),
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
                    file_path: Some(default_atpd_log_file()),
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
            .map_err(|e| cli_error(format!("Failed to read config file: {e}")))?;

        let config: AtpdConfig = toml::from_str(&content)
            .map_err(|e| cli_error(format!("Failed to parse config file: {e}")))?;

        Ok(config)
    } else {
        // Return default configuration
        warn!("Config file not found, using default configuration");
        Ok(AtpdConfig::default())
    }
}

#[cfg(feature = "tls")]
fn load_atpd_cert_chain(path: &Path) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let pem = std::fs::read(path)
        .map_err(|err| cli_error(format!("read cert {}: {err}", path.display())))?;
    let mut reader = std::io::BufReader::new(pem.as_slice());
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|err| cli_error(format!("parse certs in {}: {err}", path.display())))?;
    if certs.is_empty() {
        return Err(cli_error(format!(
            "no certificates found in {}",
            path.display()
        )));
    }
    Ok(certs)
}

#[cfg(feature = "tls")]
fn load_atpd_private_key(path: &Path) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let pem = std::fs::read(path)
        .map_err(|err| cli_error(format!("read key {}: {err}", path.display())))?;
    let mut reader = std::io::BufReader::new(pem.as_slice());
    rustls_pemfile::private_key(&mut reader)
        .map_err(|err| cli_error(format!("parse key in {}: {err}", path.display())))?
        .ok_or_else(|| cli_error(format!("no private key found in {}", path.display())))
}

#[cfg(feature = "tls")]
fn atpd_auth_key_from_hex(key_hex: &str) -> Result<AuthKey> {
    let trimmed = key_hex.trim();
    let key_hex = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    if key_hex.len() != AUTH_KEY_SIZE * 2 {
        return Err(cli_error(format!(
            "RQ auth key must be exactly {} hex characters for a {AUTH_KEY_SIZE}-byte key",
            AUTH_KEY_SIZE * 2
        )));
    }
    if !key_hex.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(cli_error(
            "RQ auth key must contain only hexadecimal characters",
        ));
    }

    let mut bytes = [0u8; AUTH_KEY_SIZE];
    hex::decode_to_slice(key_hex, &mut bytes)
        .map_err(|err| cli_error(format!("decode RQ auth key hex: {err}")))?;
    AuthKey::from_bytes(bytes).map_err(|err| cli_error(format!("RQ auth key rejected: {err}")))
}

#[cfg(feature = "tls")]
fn atpd_quic_config(
    config: &AtpdConfig,
) -> Result<asupersync::net::atp::transport_quic::QuicConfig> {
    use asupersync::net::atp::transport_quic::{QuicConfig, native_link::QuicServerTls};
    use asupersync::net::quic_native::handshake_driver::{ATP_QUIC_ALPN, server_config};

    let quic = &config.network.quic;
    let configured_auth_key = quic
        .rq_auth_key_hex
        .as_deref()
        .map(str::trim)
        .filter(|key| !key.is_empty());
    if quic.allow_unauthenticated_lab && configured_auth_key.is_some() {
        return Err(cli_error(
            "network.quic.allow_unauthenticated_lab conflicts with network.quic.rq_auth_key_hex",
        ));
    }

    let cert_path = quic.server_cert_path.as_deref().ok_or_else(|| {
        cli_error(
            "network.enable_quic requires network.quic.server_cert_path (PEM certificate chain)",
        )
    })?;
    let key_path = quic.server_key_path.as_deref().ok_or_else(|| {
        cli_error("network.enable_quic requires network.quic.server_key_path (PEM private key)")
    })?;
    let cert_chain = load_atpd_cert_chain(cert_path)?;
    let key = load_atpd_private_key(key_path)?;
    let tls_config = server_config(cert_chain, key, vec![ATP_QUIC_ALPN.to_vec()])
        .map_err(|err| cli_error(format!("build QUIC server TLS config: {err:?}")))?;

    let base = QuicConfig {
        max_transfer_bytes: config.transfers.max_transfer_size,
        ..QuicConfig::default()
    };
    let mut quic_config = if quic.allow_unauthenticated_lab {
        base.allow_unauthenticated_for_trusted_transport()
    } else if let Some(key_hex) = configured_auth_key {
        base.with_symbol_auth(SecurityContext::new(atpd_auth_key_from_hex(key_hex)?))
    } else {
        return Err(cli_error(
            "network.enable_quic requires network.quic.rq_auth_key_hex, or \
             network.quic.allow_unauthenticated_lab=true for loopback/lab use",
        ));
    };
    quic_config.server_tls = Some(QuicServerTls { config: tls_config });
    quic_config
        .validate()
        .map_err(|err| cli_error(format!("invalid QUIC listener config: {err}")))?;
    Ok(quic_config)
}

#[cfg(feature = "tls")]
fn spawn_quic_transfer_listener(
    runtime_handle: &asupersync::runtime::RuntimeHandle,
    config: &AtpdConfig,
    identity: &DurablePeerIdentity,
    transfer_stats: Arc<TransferStats>,
) -> Result<SocketAddr> {
    use asupersync::net::atp::transport_quic::native_link::{
        bind_server_endpoint, receive_on_endpoint,
    };

    let quic_config = atpd_quic_config(config).map_err(|err| {
        cli_error(format!(
            "[ASUP-E702] ATP QUIC transfer listener is enabled but misconfigured: {err}"
        ))
    })?;
    let bind_addr = config.network.bind_addr;
    let inbox_dir = config.storage.data_dir.join("inbox");
    let peer_label = identity.peer_id_hex();
    let (bind_tx, bind_rx) = mpsc::channel::<std::result::Result<SocketAddr, String>>();

    // Detached for the daemon's lifetime; the process exits on shutdown.
    let _quic_transfer_listener = runtime_handle.spawn(async move {
        let Some(cx) = asupersync::cx::Cx::current() else {
            let _ = bind_tx.send(Err(
                "no capability context available for the QUIC transfer listener".to_string(),
            ));
            return;
        };
        let first_endpoint = match bind_server_endpoint(&cx, bind_addr).await {
            Ok(endpoint) => endpoint,
            Err(err) => {
                let _ = bind_tx.send(Err(format!("bind QUIC UDP {bind_addr}: {err}")));
                return;
            }
        };
        let local_addr = first_endpoint.local_addr();
        let _ = bind_tx.send(Ok(local_addr));
        info!(bind_addr = %local_addr, "ATP QUIC transfer listener bound and accepting");

        let rebind_addr = local_addr;
        let mut next_endpoint = Some(first_endpoint);
        loop {
            let endpoint = if let Some(endpoint) = next_endpoint.take() {
                endpoint
            } else {
                match bind_server_endpoint(&cx, rebind_addr).await {
                    Ok(endpoint) => endpoint,
                    Err(err) => {
                        transfer_stats.record_failed();
                        warn!("ATP QUIC transfer listener failed to rebind {rebind_addr}: {err}");
                        break;
                    }
                }
            };
            match receive_on_endpoint(&cx, endpoint, &inbox_dir, &quic_config, &peer_label).await {
                Ok(report) => {
                    transfer_stats.record_committed(report.bytes_received);
                    info!(
                        transfer_id = %report.transfer_id,
                        bytes = report.bytes_received,
                        files = report.files,
                        "ATP QUIC transfer committed to inbox"
                    );
                }
                Err(err) => {
                    transfer_stats.record_failed();
                    warn!("ATP QUIC transfer failed: {err}");
                }
            }
        }
    });

    bind_rx
        .recv_timeout(Duration::from_secs(10))
        .map_err(|_| {
            cli_error(
                "[ASUP-E702] ATP QUIC transfer listener did not report bind status within 10s",
            )
        })?
        .map_err(|err| {
            cli_error(format!(
                "[ASUP-E702] ATP QUIC transfer listener failed to bind: {err}; refusing to \
                 start a QUIC-enabled transfer daemon that cannot accept QUIC transfers"
            ))
        })
}

#[cfg(not(feature = "tls"))]
fn spawn_quic_transfer_listener(
    _runtime_handle: &asupersync::runtime::RuntimeHandle,
    _config: &AtpdConfig,
    _identity: &DurablePeerIdentity,
    _transfer_stats: Arc<TransferStats>,
) -> Result<SocketAddr> {
    Err(cli_error(
        "[ASUP-E702] ATP QUIC transfer listener requires the `tls` feature; refusing to \
         start a QUIC-enabled transfer daemon without native QUIC/TLS support",
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DaemonSignal {
    Interrupt,
    Terminate,
    Reload,
}

#[derive(Debug, Clone, Default)]
struct DirectoryStats {
    files: u64,
    directories: u64,
    bytes: u64,
}

#[derive(Debug)]
struct DiagnosticsEndpoint {
    shutdown: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    local_addr: SocketAddr,
}

impl DiagnosticsEndpoint {
    fn stop(mut self) {
        self.shutdown.store(true, Ordering::Release);
        let _ = TcpStream::connect(self.local_addr);
        if let Some(thread) = self.thread.take() {
            if let Err(err) = thread.join() {
                warn!("diagnostics endpoint thread panicked: {:?}", err);
            }
        }
    }
}

/// Live transfer counters shared between the ATP transfer accept loop and the
/// diagnostics endpoint, so diagnostics report what the daemon actually did
/// rather than a static config echo (br-asupersync-qk02uw).
#[derive(Debug, Default)]
struct TransferStats {
    committed: std::sync::atomic::AtomicU64,
    failed: std::sync::atomic::AtomicU64,
    bytes_received: std::sync::atomic::AtomicU64,
}

impl TransferStats {
    fn record_committed(&self, bytes: u64) {
        self.committed.fetch_add(1, Ordering::Relaxed);
        self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
    }

    fn record_failed(&self) {
        self.failed.fetch_add(1, Ordering::Relaxed);
    }

    fn as_json(&self) -> serde_json::Value {
        serde_json::json!({
            "transfers_committed": self.committed.load(Ordering::Relaxed),
            "transfers_failed": self.failed.load(Ordering::Relaxed),
            "bytes_received_total": self.bytes_received.load(Ordering::Relaxed),
        })
    }
}

#[derive(Debug, Clone, Serialize)]
struct DaemonHealthSnapshot {
    status: &'static str,
    peer_id: String,
    /// Configured transfer bind address.
    bind_addr: SocketAddr,
    /// Address the transfer listener is actually bound to. The daemon fails to
    /// start if this socket cannot be bound, so a serving daemon always reports
    /// a real listening address here.
    transfer_listener_addr: SocketAddr,
    /// Address the optional QUIC transfer listener is actually bound to.
    quic_transfer_listener_addr: Option<SocketAddr>,
    quic_enabled: bool,
    data_dir: PathBuf,
    cache_dir: PathBuf,
    max_concurrent_transfers: u32,
    relay_enabled: bool,
    mailbox_enabled: bool,
    service_order: Vec<&'static str>,
    started_at_micros: u64,
    reload_count: u64,
}

impl DaemonHealthSnapshot {
    fn from_state(
        state: &AtpdState,
        identity: &DurablePeerIdentity,
        service_order: &[AtpdChildRole],
        transfer_listener_addr: SocketAddr,
        quic_transfer_listener_addr: Option<SocketAddr>,
        started_at_micros: u64,
        reload_count: u64,
    ) -> Self {
        Self {
            status: "running",
            peer_id: identity.peer_id_hex(),
            bind_addr: state.config.network.bind_addr,
            transfer_listener_addr,
            quic_transfer_listener_addr,
            quic_enabled: state.config.network.enable_quic,
            data_dir: state.config.storage.data_dir.clone(),
            cache_dir: state.config.storage.cache_dir.clone(),
            max_concurrent_transfers: state.config.transfers.max_concurrent,
            relay_enabled: state.config.network.enable_relay,
            mailbox_enabled: state.config.network.enable_mailbox,
            service_order: service_order
                .iter()
                .map(|role| role.service_name())
                .collect(),
            started_at_micros,
            reload_count,
        }
    }
}

impl AtpdState {
    fn transfer_count(&self) -> usize {
        self.active_transfers.len()
    }

    fn peer_count(&self) -> usize {
        self.peer_directory.len()
    }

    fn inbox_count(&self) -> usize {
        self.inbox_messages.len()
    }

    fn runtime_attached(&self) -> bool {
        let _ = &self.runtime_handle;
        true
    }
}

fn current_time_micros() -> Result<u64> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| cli_error(format!("system clock is before UNIX_EPOCH: {e}")))?;
    u64::try_from(elapsed.as_micros())
        .map_err(|_| cli_error("current timestamp does not fit in u64 microseconds"))
}

fn current_time_nanos_lossy() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .min(u128::from(u64::MAX)) as u64
}

fn resolve_data_path(root: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    }
}

fn identity_store_path(config: &AtpdConfig) -> PathBuf {
    resolve_data_path(&config.storage.data_dir, &config.identity.private_key_path)
}

fn init_identity_store_path(data_dir: &Path) -> PathBuf {
    data_dir.join("identity").join("private.key")
}

fn peer_id_path_for_store(store_path: &Path) -> PathBuf {
    store_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("peer_id")
}

fn generate_strong_identity_seed() -> Result<[u8; 32]> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|e| {
        cli_error(format!(
            "secure random identity seed generation failed: {e}"
        ))
    })?;
    Ok(seed)
}

fn create_identity_store(store_path: &Path) -> Result<DurablePeerIdentity> {
    if store_path.exists() {
        return Err(cli_error(format!(
            "identity store already exists at {}",
            store_path.display()
        )));
    }

    let peer_id_path = peer_id_path_for_store(store_path);
    if peer_id_path.exists() {
        return Err(cli_error(format!(
            "peer-id sidecar already exists at {}",
            peer_id_path.display()
        )));
    }

    for _ in 0..8 {
        let seed = generate_strong_identity_seed()?;
        match IdentityKeyStore::create(store_path, seed, current_time_micros()?) {
            Ok(store) => {
                let identity = DurablePeerIdentity::from_key_store(&store)?;
                write_peer_id_sidecar(&peer_id_path, &identity)?;
                return Ok(identity);
            }
            Err(KeyStoreError::WeakSeed(_)) => {}
            Err(err) => return Err(Box::new(err)),
        }
    }

    Err(cli_error(
        "secure random generator repeatedly produced weak identity seed material",
    ))
}

fn load_identity_store(store_path: &Path) -> Result<DurablePeerIdentity> {
    let store = IdentityKeyStore::load(store_path)?;
    Ok(DurablePeerIdentity::from_key_store(&store)?)
}

fn write_peer_id_sidecar(path: &Path, identity: &DurablePeerIdentity) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut file = OpenOptions::new().create_new(true).write(true).open(path)?;
    file.write_all(identity.peer_id_hex().as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

fn copy_identity_store_without_overwrite(
    source_path: &Path,
    destination_path: &Path,
) -> Result<DurablePeerIdentity> {
    let source_identity = load_identity_store(source_path)?;
    if destination_path.exists() {
        return Err(cli_error(format!(
            "destination identity store already exists at {}",
            destination_path.display()
        )));
    }

    let peer_id_path = peer_id_path_for_store(destination_path);
    if peer_id_path.exists() {
        return Err(cli_error(format!(
            "destination peer-id sidecar already exists at {}",
            peer_id_path.display()
        )));
    }

    if let Some(parent) = destination_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let bytes = std::fs::read(source_path)?;
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(destination_path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    harden_identity_file(destination_path)?;

    let imported_identity = load_identity_store(destination_path)?;
    if imported_identity.peer_id_hex() != source_identity.peer_id_hex() {
        return Err(cli_error(
            "imported identity does not match the validated source identity",
        ));
    }
    write_peer_id_sidecar(&peer_id_path, &imported_identity)?;
    Ok(imported_identity)
}

fn export_identity_store_without_overwrite(
    source_path: &Path,
    destination_path: &Path,
) -> Result<DurablePeerIdentity> {
    let identity = load_identity_store(source_path)?;
    if destination_path.exists() {
        return Err(cli_error(format!(
            "export destination already exists at {}",
            destination_path.display()
        )));
    }
    if let Some(parent) = destination_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let bytes = std::fs::read(source_path)?;
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(destination_path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    harden_identity_file(destination_path)?;
    Ok(identity)
}

#[cfg(unix)]
fn harden_identity_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn harden_identity_file(_path: &Path) -> Result<()> {
    Ok(())
}

fn process_is_running(pid: u32) -> bool {
    #[cfg(unix)]
    {
        let Some(pid) = libc::pid_t::try_from(pid).ok() else {
            return false;
        };
        let result = unsafe { libc::kill(pid, 0) };
        if result == 0 {
            return true;
        }
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        errno != libc::ESRCH
    }

    #[cfg(not(unix))]
    {
        let mut system = sysinfo::System::new_all();
        system.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
        system.process(sysinfo::Pid::from_u32(pid)).is_some()
    }
}

#[cfg(unix)]
fn native_pid(pid: u32) -> Result<libc::pid_t> {
    libc::pid_t::try_from(pid)
        .map_err(|_| cli_error(format!("PID {pid} is outside the native pid_t range")))
}

fn read_pid_file(path: &Path) -> Result<u32> {
    let pid_content = std::fs::read_to_string(path)
        .map_err(|e| cli_error(format!("Failed to read PID file: {e}")))?;
    pid_content
        .trim()
        .parse()
        .map_err(|e| cli_error(format!("Invalid PID in file: {e}")))
}

fn directory_stats(path: &Path) -> Result<DirectoryStats> {
    let mut stats = DirectoryStats::default();
    if !path.exists() {
        return Ok(stats);
    }

    let mut stack = vec![path.to_path_buf()];
    while let Some(current) = stack.pop() {
        for entry in std::fs::read_dir(&current)? {
            let entry = entry?;
            let metadata = entry.metadata()?;
            if metadata.is_dir() {
                stats.directories = stats.directories.saturating_add(1);
                stack.push(entry.path());
            } else if metadata.is_file() {
                stats.files = stats.files.saturating_add(1);
                stats.bytes = stats.bytes.saturating_add(metadata.len());
            }
        }
    }
    Ok(stats)
}

fn install_signal_listener() -> Result<mpsc::Receiver<DaemonSignal>> {
    let (sender, receiver) = mpsc::channel();

    #[cfg(unix)]
    {
        use signal_hook::consts::signal::{SIGHUP, SIGINT, SIGTERM};
        use signal_hook::iterator::Signals;

        let mut signals = Signals::new([SIGINT, SIGTERM, SIGHUP])?;
        thread::spawn(move || {
            for signal in signals.forever() {
                let event = match signal {
                    SIGINT => DaemonSignal::Interrupt,
                    SIGTERM => DaemonSignal::Terminate,
                    SIGHUP => DaemonSignal::Reload,
                    _ => continue,
                };
                if sender.send(event).is_err() {
                    break;
                }
            }
        });
    }

    #[cfg(not(unix))]
    {
        use signal_hook::consts::signal::{SIGBREAK, SIGINT, SIGTERM};
        use signal_hook::flag;

        let interrupt = Arc::new(AtomicBool::new(false));
        let terminate = Arc::new(AtomicBool::new(false));
        let reload = Arc::new(AtomicBool::new(false));

        flag::register(SIGINT, Arc::clone(&interrupt))?;
        flag::register(SIGTERM, Arc::clone(&terminate))?;
        flag::register(SIGBREAK, Arc::clone(&reload))?;

        thread::spawn(move || {
            loop {
                if reload.swap(false, Ordering::SeqCst) {
                    if sender.send(DaemonSignal::Reload).is_err() {
                        break;
                    }
                }
                if interrupt.load(Ordering::SeqCst) {
                    let _ = sender.send(DaemonSignal::Interrupt);
                    break;
                }
                if terminate.load(Ordering::SeqCst) {
                    let _ = sender.send(DaemonSignal::Terminate);
                    break;
                }
                thread::sleep(Duration::from_millis(100));
            }
        });
    }

    Ok(receiver)
}

fn start_diagnostics_endpoint(
    addr: SocketAddr,
    snapshot: Arc<Mutex<DaemonHealthSnapshot>>,
    transfer_stats: Arc<TransferStats>,
) -> Result<DiagnosticsEndpoint> {
    let listener = TcpListener::bind(addr)?;
    listener.set_nonblocking(true)?;
    let local_addr = listener.local_addr()?;
    let shutdown = Arc::new(AtomicBool::new(false));
    let thread_shutdown = Arc::clone(&shutdown);
    let thread_snapshot = Arc::clone(&snapshot);

    let thread = thread::spawn(move || {
        while !thread_shutdown.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((stream, _peer_addr)) => {
                    if let Err(err) =
                        serve_diagnostics_connection(stream, &thread_snapshot, &transfer_stats)
                    {
                        warn!("diagnostics endpoint connection failed: {}", err);
                    }
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(100));
                }
                Err(err) => {
                    warn!("diagnostics endpoint accept failed: {}", err);
                    thread::sleep(Duration::from_millis(250));
                }
            }
        }
    });

    Ok(DiagnosticsEndpoint {
        shutdown,
        thread: Some(thread),
        local_addr,
    })
}

fn serve_diagnostics_connection(
    mut stream: TcpStream,
    snapshot: &Arc<Mutex<DaemonHealthSnapshot>>,
    transfer_stats: &TransferStats,
) -> Result<()> {
    let mut request = [0u8; 1024];
    let _ = stream.read(&mut request);

    let snapshot = snapshot
        .lock()
        .map_err(|_| cli_error("diagnostics snapshot mutex poisoned"))?;
    // Merge live transfer counters at request time so diagnostics report real
    // observed activity, not a stale config echo.
    let mut body_value = serde_json::to_value(&*snapshot)?;
    if let (serde_json::Value::Object(map), serde_json::Value::Object(stats)) =
        (&mut body_value, transfer_stats.as_json())
    {
        map.insert("transfers".to_string(), serde_json::Value::Object(stats));
    }
    let body = serde_json::to_vec_pretty(&body_value)?;
    let header = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(&body)?;
    stream.flush()?;
    Ok(())
}

fn prepare_daemon_directories(config: &AtpdConfig) -> Result<()> {
    std::fs::create_dir_all(&config.storage.data_dir)?;
    std::fs::create_dir_all(&config.storage.cache_dir)?;
    std::fs::create_dir_all(&config.storage.journal.journal_path)?;
    std::fs::create_dir_all(config.storage.data_dir.join("inbox"))?;
    std::fs::create_dir_all(config.storage.data_dir.join("mailbox"))?;
    std::fs::create_dir_all(config.storage.data_dir.join("transfers"))?;
    std::fs::create_dir_all(config.storage.data_dir.join("diagnostics"))?;
    Ok(())
}

fn main() -> Result<()> {
    let cli = AtpdCli::parse();
    let command = cli.command.clone();

    // Initialize logging
    init_logging(&cli.log_level)?;

    match command {
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
    let mut config = load_daemon_config(&cli.config).unwrap_or_else(|_| {
        warn!(
            "Failed to load config from {}, using defaults",
            cli.config.display()
        );
        AtpdConfig::default()
    });

    apply_start_overrides(&mut config, args);

    prepare_daemon_directories(&config)?;

    // Initialize runtime
    let runtime = RuntimeBuilder::new()
        .worker_threads(4)
        .thread_name_prefix("atpd-worker".to_string())
        .build()?;
    let runtime_handle = runtime.handle().clone();

    info!(
        "ATP daemon starting; transfer port {} (bound during service startup)",
        config.network.bind_addr
    );
    info!("Data directory: {}", config.storage.data_dir.display());
    info!("Cache directory: {}", config.storage.cache_dir.display());
    info!(
        "Max concurrent transfers: {}",
        config.transfers.max_concurrent
    );

    // Enter the runtime and run the daemon
    runtime
        .block_on(async { run_daemon_service(config, cli.config.clone(), runtime_handle).await })?;

    info!("ATP daemon stopped");
    Ok(())
}

fn apply_start_overrides(config: &mut AtpdConfig, args: StartArgs) {
    if let Some(bind) = args.bind {
        config.network.bind_addr = bind;
    }
    if let Some(data_dir) = args.data_dir {
        config.storage.data_dir.clone_from(&data_dir);
        config.storage.cache_dir = data_dir.join("cache");
        config.storage.journal.journal_path = data_dir.join("journal");
        config.identity.private_key_path = init_identity_store_path(&data_dir);
    }
    if let Some(max_transfers) = args.max_transfers {
        config.transfers.max_concurrent = max_transfers;
    }
    if args.enable_relay {
        config.network.enable_relay = true;
    }
    if args.enable_mailbox {
        config.network.enable_mailbox = true;
    }
    if args.enable_quic {
        config.network.enable_quic = true;
    }
    if let Some(path) = args.quic_server_cert {
        config.network.quic.server_cert_path = Some(path);
    }
    if let Some(path) = args.quic_server_key {
        config.network.quic.server_key_path = Some(path);
    }
    if let Some(key_hex) = args.rq_auth_key_hex {
        config.network.quic.rq_auth_key_hex = Some(key_hex);
    }
    if args.rq_allow_unauthenticated_lab {
        config.network.quic.allow_unauthenticated_lab = true;
    }
    if let Some(addr) = args.diagnostics_bind {
        config.diagnostics.enable_metrics = true;
        config.diagnostics.metrics_bind = Some(addr);
    }
}

async fn run_daemon_service(
    mut config: AtpdConfig,
    config_path: PathBuf,
    runtime_handle: asupersync::runtime::RuntimeHandle,
) -> Result<()> {
    prepare_daemon_directories(&config)?;
    let identity_path = identity_store_path(&config);
    let identity = load_identity_store(&identity_path).map_err(|err| {
        cli_error(format!(
            "daemon identity is not initialized at {}; run `atpd init --new-identity --data-dir {}` first: {err}",
            identity_path.display(),
            config.storage.data_dir.display()
        ))
    })?;

    let mut app_spec = AtpdAppSpec::default_daemon(AtpdRegionId::new(1));
    if config.network.enable_relay {
        app_spec = app_spec.with_relay();
    }
    if config.network.discovery.enable_relay_discovery {
        app_spec = app_spec.with_rendezvous();
    }
    let compiled_app = app_spec.compile()?;
    for event in compiled_app.start_events() {
        if let Some(role) = event.role {
            info!(
                service = role.service_name(),
                action = %event.action,
                "starting ATP daemon child service"
            );
        }
    }

    // Initialize daemon state
    let mut daemon_state = AtpdState {
        config: config.clone(),
        runtime_handle: runtime_handle.clone(),
        start_time: Time::from_nanos(current_time_nanos_lossy()),
        peer_directory: HashMap::new(),
        active_transfers: HashMap::new(),
        inbox_messages: Vec::new(),
    };

    // Bind the REAL ATP transfer listener (br-asupersync-qk02uw). Previously the
    // daemon advertised `bind_addr` but never listened on it — only the
    // diagnostics endpoint bound a socket, so no transfer could ever arrive.
    // This spawns the genuine ATP-over-TCP accept loop, writing verified
    // transfers into the daemon's inbox.
    //
    // Fail-closed startup contract: the daemon refuses to start when the
    // transfer port cannot be bound. A transfer daemon that is not listening
    // for transfers must not run "healthy", and diagnostics must never claim a
    // bind address that no socket backs.
    let transfer_stats = Arc::new(TransferStats::default());
    let transfer_listener_addr = {
        use asupersync::net::TcpListener as AsupTcpListener;
        use asupersync::net::atp::transport_tcp::{TransferConfig, serve};

        let bind_addr = config.network.bind_addr;
        let inbox_dir = config.storage.data_dir.join("inbox");
        let max_bytes = config.transfers.max_transfer_size;
        let peer_label = identity.peer_id_hex();
        let stats = Arc::clone(&transfer_stats);
        let (bind_tx, bind_rx) = mpsc::channel::<std::result::Result<SocketAddr, String>>();
        // Detached for the daemon's lifetime; the process exits on shutdown.
        let _transfer_listener = runtime_handle.spawn(async move {
            let Some(cx) = asupersync::cx::Cx::current() else {
                let _ = bind_tx.send(Err(
                    "no capability context available for the transfer listener".to_string(),
                ));
                return;
            };
            let listener = match AsupTcpListener::bind(bind_addr).await {
                Ok(listener) => listener,
                Err(err) => {
                    let _ = bind_tx.send(Err(format!("bind {bind_addr}: {err}")));
                    return;
                }
            };
            let local_addr = match listener.local_addr() {
                Ok(addr) => addr,
                Err(err) => {
                    let _ =
                        bind_tx.send(Err(format!("local_addr after binding {bind_addr}: {err}")));
                    return;
                }
            };
            let _ = bind_tx.send(Ok(local_addr));
            info!(bind_addr = %local_addr, "ATP transfer listener bound and accepting");
            let cfg = TransferConfig {
                max_transfer_bytes: max_bytes,
                ..TransferConfig::default()
            };
            let result = serve(
                &cx,
                listener,
                inbox_dir,
                cfg,
                peer_label,
                |outcome| match outcome {
                    Ok(report) => {
                        stats.record_committed(report.bytes_received);
                        info!(
                            transfer_id = %report.transfer_id,
                            bytes = report.bytes_received,
                            files = report.files,
                            "ATP transfer committed to inbox"
                        );
                    }
                    Err(err) => {
                        stats.record_failed();
                        warn!("ATP transfer failed: {err}");
                    }
                },
            )
            .await;
            if let Err(err) = result {
                warn!("ATP transfer listener stopped: {err}");
            }
        });

        bind_rx
            .recv_timeout(Duration::from_secs(10))
            .map_err(|_| {
                cli_error("[ASUP-E702] ATP transfer listener did not report bind status within 10s")
            })?
            .map_err(|err| {
                cli_error(format!(
                    "[ASUP-E702] ATP transfer listener failed to bind: {err}; refusing to \
                     start a transfer daemon that cannot accept transfers"
                ))
            })?
    };
    let quic_transfer_listener_addr = if config.network.enable_quic {
        Some(spawn_quic_transfer_listener(
            &runtime_handle,
            &config,
            &identity,
            Arc::clone(&transfer_stats),
        )?)
    } else {
        None
    };

    info!(
        peer_id = identity.peer_id_hex(),
        services = compiled_app.start_order.len(),
        quic_listener = ?quic_transfer_listener_addr,
        "ATP daemon services started"
    );
    info!(
        runtime_attached = daemon_state.runtime_attached(),
        active_transfers = daemon_state.transfer_count(),
        known_peers = daemon_state.peer_count(),
        inbox_messages = daemon_state.inbox_count(),
        "ATP daemon state initialized"
    );

    let signal_rx = install_signal_listener()?;
    let started_at_micros = current_time_micros()?;
    let reload_count = 0u64;
    let health_snapshot = Arc::new(Mutex::new(DaemonHealthSnapshot::from_state(
        &daemon_state,
        &identity,
        &compiled_app.start_order,
        transfer_listener_addr,
        quic_transfer_listener_addr,
        started_at_micros,
        reload_count,
    )));
    let diagnostics_endpoint = if daemon_state.config.diagnostics.enable_metrics
        || daemon_state.config.diagnostics.enable_debug
    {
        match daemon_state.config.diagnostics.metrics_bind {
            Some(addr) => {
                let endpoint = start_diagnostics_endpoint(
                    addr,
                    Arc::clone(&health_snapshot),
                    Arc::clone(&transfer_stats),
                )?;
                info!(
                    bind_addr = %endpoint.local_addr,
                    "ATP daemon diagnostics endpoint started"
                );
                Some(endpoint)
            }
            None => {
                warn!("diagnostics enabled but no metrics_bind address configured");
                None
            }
        }
    } else {
        None
    };

    let mut reload_count = reload_count;
    loop {
        match signal_rx.recv_timeout(Duration::from_secs(
            daemon_state
                .config
                .service
                .health_check
                .interval_secs
                .max(1),
        )) {
            Ok(DaemonSignal::Reload) => {
                let reloaded = load_daemon_config(&config_path)?;
                prepare_daemon_directories(&reloaded)?;
                let reloaded_identity = load_identity_store(&identity_store_path(&reloaded))?;
                if reloaded.network.bind_addr != config.network.bind_addr {
                    warn!(
                        configured = %reloaded.network.bind_addr,
                        listening = %transfer_listener_addr,
                        "bind_addr changed in reloaded config; the transfer listener keeps \
                         its current socket — restart the daemon to rebind"
                    );
                }
                if reloaded.network.enable_quic != config.network.enable_quic
                    || reloaded.network.quic.server_cert_path
                        != config.network.quic.server_cert_path
                    || reloaded.network.quic.server_key_path != config.network.quic.server_key_path
                    || reloaded.network.quic.rq_auth_key_hex != config.network.quic.rq_auth_key_hex
                    || reloaded.network.quic.allow_unauthenticated_lab
                        != config.network.quic.allow_unauthenticated_lab
                {
                    warn!(
                        listening = ?quic_transfer_listener_addr,
                        "QUIC listener configuration changed in reloaded config; restart the \
                         daemon to rebind or reconfigure the QUIC listener"
                    );
                }
                config = reloaded;
                daemon_state.config = config.clone();
                reload_count = reload_count.saturating_add(1);
                *health_snapshot
                    .lock()
                    .map_err(|_| cli_error("diagnostics snapshot mutex poisoned"))? =
                    DaemonHealthSnapshot::from_state(
                        &daemon_state,
                        &reloaded_identity,
                        &compiled_app.start_order,
                        transfer_listener_addr,
                        quic_transfer_listener_addr,
                        started_at_micros,
                        reload_count,
                    );
                info!(reload_count, "ATP daemon configuration reloaded");
            }
            Ok(DaemonSignal::Interrupt | DaemonSignal::Terminate) => {
                break;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if daemon_state.config.service.health_check.enable {
                    info!(
                        uptime_nanos = current_time_nanos_lossy()
                            .saturating_sub(daemon_state.start_time.as_nanos()),
                        active_transfers = daemon_state.transfer_count(),
                        known_peers = daemon_state.peer_count(),
                        "ATP daemon health check"
                    );
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                warn!("daemon signal listener disconnected; stopping daemon");
                break;
            }
        }
    }

    info!("Received shutdown signal, stopping daemon...");
    for event in compiled_app.shutdown_events() {
        match event.role {
            Some(role) => info!(
                service = role.service_name(),
                action = %event.action,
                "stopping ATP daemon child service"
            ),
            None => info!(action = %event.action, "joining ATP daemon root"),
        }
    }
    if let Some(endpoint) = diagnostics_endpoint {
        endpoint.stop();
    }
    Ok(())
}

fn stop_daemon(cli: AtpdCli) -> Result<()> {
    info!("Stopping ATP daemon...");

    // Check if PID file exists
    if !cli.pid_file.exists() {
        println!("ATP daemon is not running (no PID file found)");
        return Ok(());
    }

    let pid = read_pid_file(&cli.pid_file)?;

    #[cfg(unix)]
    {
        use std::time::Instant;

        // Send SIGTERM for graceful shutdown using native libc call
        info!("Sending SIGTERM to process {}", pid);

        // SECURITY FIX: Use native libc::kill instead of external command to prevent injection
        let native_pid = native_pid(pid)?;
        let term_result = unsafe { libc::kill(native_pid, libc::SIGTERM) };

        if term_result == 0 {
            println!("Sent shutdown signal to ATP daemon (PID: {})", pid);

            // Wait for graceful shutdown (up to 10 seconds)
            let start = Instant::now();
            let timeout = Duration::from_secs(10);

            loop {
                // Check if process still exists using native libc call (signal 0)
                let check_result = unsafe { libc::kill(native_pid, 0) };

                if check_result != 0 {
                    // Process has stopped (kill returns -1 if process doesn't exist)
                    break;
                }

                if start.elapsed() > timeout {
                    warn!("Graceful shutdown timeout, sending SIGKILL");
                    let _ = unsafe { libc::kill(native_pid, libc::SIGKILL) };
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
        } else {
            // Check errno for specific error
            let errno = unsafe { *libc::__errno_location() };
            match errno {
                libc::ESRCH => {
                    println!("Process {} not found (may have already stopped)", pid);
                    // Clean up stale PID file
                    let _ = std::fs::remove_file(&cli.pid_file);
                }
                libc::EPERM => {
                    return Err(cli_error(format!(
                        "Permission denied: cannot send signal to process {}",
                        pid
                    )));
                }
                _ => {
                    return Err(cli_error(format!(
                        "Failed to send signal to process {}: errno {}",
                        pid, errno
                    )));
                }
            }
        }
    }

    #[cfg(windows)]
    {
        use std::process::Command;
        use std::time::Instant;

        if !process_is_running(pid) {
            println!("Process {} not found (may have already stopped)", pid);
            if let Err(err) = std::fs::remove_file(&cli.pid_file) {
                warn!("Failed to remove stale PID file: {}", err);
            }
            return Ok(());
        }

        info!("Stopping Windows ATP daemon process {}", pid);
        let status = Command::new("taskkill.exe")
            .arg("/PID")
            .arg(pid.to_string())
            .arg("/T")
            .status()
            .map_err(|err| cli_error(format!("failed to invoke taskkill.exe: {err}")))?;

        if !status.success() {
            return Err(cli_error(format!(
                "taskkill.exe failed to request graceful shutdown for process {pid}: {status}"
            )));
        }

        println!("Sent shutdown request to ATP daemon (PID: {})", pid);

        let start = Instant::now();
        let timeout = Duration::from_secs(10);
        while process_is_running(pid) && start.elapsed() <= timeout {
            std::thread::sleep(Duration::from_millis(100));
        }

        if process_is_running(pid) {
            warn!("Graceful Windows shutdown timeout, forcing termination");
            let force_status = Command::new("taskkill.exe")
                .arg("/PID")
                .arg(pid.to_string())
                .arg("/T")
                .arg("/F")
                .status()
                .map_err(|err| cli_error(format!("failed to invoke taskkill.exe /F: {err}")))?;
            if !force_status.success() {
                return Err(cli_error(format!(
                    "taskkill.exe /F failed for process {pid}: {force_status}"
                )));
            }
        }

        if let Err(err) = std::fs::remove_file(&cli.pid_file) {
            warn!("Failed to remove PID file: {}", err);
        } else {
            info!("Removed PID file");
        }

        println!("ATP daemon stopped successfully");
    }

    #[cfg(not(any(unix, windows)))]
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

    let pid = read_pid_file(&cli.pid_file)?;

    if process_is_running(pid) {
        println!("ATP daemon: RUNNING (PID: {})", pid);
        println!("PID file: {}", cli.pid_file.display());
        println!("Config file: {}", cli.config.display());
    } else {
        println!("ATP daemon: STOPPED (stale PID file)");
        warn!("PID file exists but process {} is not running", pid);
    }

    Ok(())
}

fn reload_daemon(cli: AtpdCli) -> Result<()> {
    info!("Reloading ATP daemon configuration...");

    let _config = load_daemon_config(&cli.config)?;
    if !cli.pid_file.exists() {
        return Err(cli_error(format!(
            "cannot reload ATP daemon because PID file is missing: {}",
            cli.pid_file.display()
        )));
    }
    let pid = read_pid_file(&cli.pid_file)?;

    reload_daemon_by_platform(pid, &cli.config)
}

#[cfg(unix)]
fn reload_daemon_by_platform(pid: u32, config_path: &Path) -> Result<()> {
    let native_pid = native_pid(pid)?;
    let signal_result = unsafe { libc::kill(native_pid, libc::SIGHUP) };
    if signal_result == 0 {
        println!(
            "Sent reload signal to ATP daemon (PID: {}, config: {})",
            pid,
            config_path.display()
        );
        Ok(())
    } else {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        Err(cli_error(format!(
            "failed to send SIGHUP to ATP daemon process {pid}: errno {errno}"
        )))
    }
}

#[cfg(not(unix))]
fn reload_daemon_by_platform(pid: u32, _config_path: &Path) -> Result<()> {
    let _ = pid;
    Err(cli_error(
        "daemon reload by external signal is only supported on Unix platforms; on Windows, use Ctrl-Break in the daemon console",
    ))
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

    if args.new_identity && args.copy_identity.is_some() {
        return Err(cli_error(
            "--new-identity and --copy-identity are mutually exclusive",
        ));
    }

    let store_path = init_identity_store_path(&args.data_dir);
    if args.new_identity {
        info!("Generating new daemon identity...");
        let identity = create_identity_store(&store_path)?;
        println!("Generated ATP daemon identity");
        println!("  Key store: {}", store_path.display());
        println!("  Peer ID: {}", identity.peer_id_hex());
    }

    if let Some(source_path) = args.copy_identity {
        info!("Copying identity from {}", source_path.display());
        let identity = copy_identity_store_without_overwrite(&source_path, &store_path)?;
        println!("Imported ATP daemon identity");
        println!("  Source: {}", source_path.display());
        println!("  Key store: {}", store_path.display());
        println!("  Peer ID: {}", identity.peer_id_hex());
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
                    if process_is_running(pid) {
                        println!("  Status: ✅ RUNNING (PID: {})", pid);
                    } else {
                        println!("  Status: ❌ STOPPED (stale PID file)");
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

    let config = load_daemon_config(&cli.config)?;
    let identity_path = identity_store_path(&config);
    let identity_status = load_identity_store(&identity_path);
    let cache_stats = directory_stats(&config.storage.cache_dir)?;
    let journal_stats = directory_stats(&config.storage.journal.journal_path)?;
    let inbox_stats = directory_stats(&config.storage.data_dir.join("inbox"))?;
    let transfer_stats = directory_stats(&config.storage.data_dir.join("transfers"))?;

    println!("📈 Transfer State:");
    println!("  Files: {}", transfer_stats.files);
    println!("  Bytes: {}", transfer_stats.bytes);
    println!("  Max concurrent: {}", config.transfers.max_concurrent);
    println!();

    println!("🤝 Peer Identity:");
    match identity_status {
        Ok(identity) => {
            println!("  Peer ID: {}", identity.peer_id_hex());
            println!("  Key store: {}", identity_path.display());
        }
        Err(err) => {
            println!("  Status: identity unavailable: {}", err);
            println!("  Key store: {}", identity_path.display());
        }
    }
    println!();

    println!("💾 Cache Status:");
    println!("  Directory: {}", config.storage.cache_dir.display());
    println!("  Files: {}", cache_stats.files);
    println!("  Directories: {}", cache_stats.directories);
    println!("  Bytes: {}", cache_stats.bytes);
    println!("  Limit bytes: {}", config.storage.max_cache_size);
    println!();

    println!("📋 Journal Status:");
    println!(
        "  Directory: {}",
        config.storage.journal.journal_path.display()
    );
    println!("  Enabled: {}", config.storage.journal.enable);
    println!("  Files: {}", journal_stats.files);
    println!("  Bytes: {}", journal_stats.bytes);
    println!();

    println!("📥 Inbox Status:");
    println!(
        "  Directory: {}",
        config.storage.data_dir.join("inbox").display()
    );
    println!("  Files: {}", inbox_stats.files);
    println!("  Bytes: {}", inbox_stats.bytes);

    Ok(())
}

fn manage_identity(cli: AtpdCli, args: IdentityArgs) -> Result<()> {
    match args.action {
        IdentityAction::Show => {
            info!("Showing daemon identity...");

            // Load daemon configuration to find data directory
            let config = load_daemon_config(&cli.config)?;

            let private_key_file = identity_store_path(&config);
            let identity_dir = private_key_file
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .to_path_buf();
            let peer_id_file = peer_id_path_for_store(&private_key_file);

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
            match load_identity_store(&private_key_file) {
                Ok(identity) => {
                    println!("  Peer ID: {}", identity.peer_id_hex());
                    println!("  Fingerprint: {}", identity.fingerprint().to_hex());
                    println!("  Generation: {}", identity.generation());
                    println!("  Status: ✅ Valid key store");
                }
                Err(err) => {
                    println!("  Status: ❌ Cannot load identity: {}", err);
                }
            }
            if peer_id_file.exists() {
                match std::fs::read_to_string(&peer_id_file) {
                    Ok(peer_id) => {
                        println!("  Sidecar Peer ID: {}", peer_id.trim());
                    }
                    Err(e) => println!("  Sidecar Status: ❌ Cannot read peer ID: {}", e),
                }
            } else {
                println!("  Sidecar Status: ❌ Peer ID file not found");
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
            let config = load_daemon_config(&cli.config)?;
            let store_path = identity_store_path(&config);
            let identity = create_identity_store(&store_path)?;
            println!("Generated ATP daemon identity");
            println!("  Key store: {}", store_path.display());
            println!("  Peer ID: {}", identity.peer_id_hex());
        }
        IdentityAction::Import { path } => {
            info!("Importing identity from {}", path.display());
            let config = load_daemon_config(&cli.config)?;
            let store_path = identity_store_path(&config);
            let identity = copy_identity_store_without_overwrite(&path, &store_path)?;
            println!("Imported ATP daemon identity");
            println!("  Source: {}", path.display());
            println!("  Key store: {}", store_path.display());
            println!("  Peer ID: {}", identity.peer_id_hex());
        }
        IdentityAction::Export { path } => {
            info!("Exporting identity to {}", path.display());
            let config = load_daemon_config(&cli.config)?;
            let store_path = identity_store_path(&config);
            let identity = export_identity_store_without_overwrite(&store_path, &path)?;
            println!("Exported ATP daemon identity");
            println!("  Source: {}", store_path.display());
            println!("  Destination: {}", path.display());
            println!("  Peer ID: {}", identity.peer_id_hex());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loopback(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    fn empty_start_args() -> StartArgs {
        StartArgs {
            bind: None,
            data_dir: None,
            max_transfers: None,
            enable_relay: false,
            enable_mailbox: false,
            enable_quic: false,
            quic_server_cert: None,
            quic_server_key: None,
            rq_auth_key_hex: None,
            rq_allow_unauthenticated_lab: false,
            diagnostics_bind: None,
        }
    }

    #[test]
    fn quic_listener_is_an_explicit_daemon_capability() {
        let config = AtpdConfig::default();

        assert!(
            !config.network.enable_quic,
            "atpd must not claim a QUIC listener unless it was explicitly enabled"
        );
        assert!(config.network.quic.server_cert_path.is_none());
        assert!(config.network.quic.server_key_path.is_none());
        assert!(config.network.quic.rq_auth_key_hex.is_none());
        assert!(!config.network.quic.allow_unauthenticated_lab);
    }

    #[test]
    fn start_overrides_preserve_configured_quic_listener_when_flags_absent() {
        let mut config = AtpdConfig::default();
        config.network.bind_addr = loopback(9443);
        config.network.enable_relay = true;
        config.network.enable_mailbox = true;
        config.network.enable_quic = true;
        config.network.quic.server_cert_path = Some(PathBuf::from("/etc/atpd/quic/server.pem"));
        config.network.quic.server_key_path = Some(PathBuf::from("/etc/atpd/quic/server.key"));
        config.network.quic.rq_auth_key_hex =
            Some("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f".to_string());
        config.storage.data_dir = PathBuf::from("/srv/atpd/data");
        config.storage.cache_dir = PathBuf::from("/srv/atpd/data/cache");
        config.storage.journal.journal_path = PathBuf::from("/srv/atpd/data/journal");
        config.identity.private_key_path = PathBuf::from("/srv/atpd/data/identity/peer.key");
        config.transfers.max_concurrent = 64;
        config.diagnostics.metrics_bind = Some(loopback(9444));

        apply_start_overrides(&mut config, empty_start_args());

        assert_eq!(config.network.bind_addr, loopback(9443));
        assert!(config.network.enable_relay);
        assert!(config.network.enable_mailbox);
        assert!(config.network.enable_quic);
        assert_eq!(
            config.network.quic.server_cert_path.as_deref(),
            Some(Path::new("/etc/atpd/quic/server.pem"))
        );
        assert_eq!(
            config.network.quic.server_key_path.as_deref(),
            Some(Path::new("/etc/atpd/quic/server.key"))
        );
        assert_eq!(config.storage.data_dir, PathBuf::from("/srv/atpd/data"));
        assert_eq!(config.transfers.max_concurrent, 64);
        assert_eq!(config.diagnostics.metrics_bind, Some(loopback(9444)));
    }

    #[test]
    fn start_overrides_apply_explicit_quic_listener_flags() {
        let mut config = AtpdConfig::default();
        let mut args = empty_start_args();
        args.bind = Some(loopback(0));
        args.data_dir = Some(PathBuf::from("/tmp/atpd-cli-data"));
        args.max_transfers = Some(8);
        args.enable_relay = true;
        args.enable_mailbox = true;
        args.enable_quic = true;
        args.quic_server_cert = Some(PathBuf::from("/tmp/atpd-cli-data/quic/server.pem"));
        args.quic_server_key = Some(PathBuf::from("/tmp/atpd-cli-data/quic/server.key"));
        args.rq_auth_key_hex =
            Some("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f".to_string());
        args.diagnostics_bind = Some(loopback(0));

        apply_start_overrides(&mut config, args);

        assert_eq!(config.network.bind_addr, loopback(0));
        assert!(config.network.enable_relay);
        assert!(config.network.enable_mailbox);
        assert!(config.network.enable_quic);
        assert_eq!(
            config.network.quic.server_cert_path.as_deref(),
            Some(Path::new("/tmp/atpd-cli-data/quic/server.pem"))
        );
        assert_eq!(
            config.network.quic.server_key_path.as_deref(),
            Some(Path::new("/tmp/atpd-cli-data/quic/server.key"))
        );
        assert_eq!(
            config.network.quic.rq_auth_key_hex.as_deref(),
            Some("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        );
        assert_eq!(config.storage.data_dir, PathBuf::from("/tmp/atpd-cli-data"));
        assert_eq!(
            config.storage.cache_dir,
            PathBuf::from("/tmp/atpd-cli-data/cache")
        );
        assert_eq!(
            config.storage.journal.journal_path,
            PathBuf::from("/tmp/atpd-cli-data/journal")
        );
        assert_eq!(
            config.identity.private_key_path,
            PathBuf::from("/tmp/atpd-cli-data/identity/private.key")
        );
        assert_eq!(config.transfers.max_concurrent, 8);
        assert_eq!(config.diagnostics.metrics_bind, Some(loopback(0)));
    }

    #[test]
    fn diagnostics_snapshot_reports_tcp_and_quic_bound_addrs() {
        let snapshot = DaemonHealthSnapshot {
            status: "running",
            peer_id: "peer-test".to_string(),
            bind_addr: loopback(8472),
            transfer_listener_addr: loopback(8472),
            quic_transfer_listener_addr: Some(loopback(8472)),
            quic_enabled: true,
            data_dir: PathBuf::from("/var/lib/atpd"),
            cache_dir: PathBuf::from("/var/lib/atpd/cache"),
            max_concurrent_transfers: 16,
            relay_enabled: false,
            mailbox_enabled: false,
            service_order: vec!["transfer"],
            started_at_micros: 42,
            reload_count: 1,
        };

        let body = serde_json::to_value(snapshot).expect("snapshot serializes");
        assert_eq!(
            body["transfer_listener_addr"],
            serde_json::Value::String("127.0.0.1:8472".to_string())
        );
        assert_eq!(
            body["quic_transfer_listener_addr"],
            serde_json::Value::String("127.0.0.1:8472".to_string())
        );
        assert_eq!(body["quic_enabled"], serde_json::Value::Bool(true));
    }

    #[test]
    fn transfer_stats_json_reports_live_shared_counters() {
        let stats = TransferStats::default();
        stats.record_committed(4096);
        stats.record_failed();

        let body = stats.as_json();
        assert_eq!(body["transfers_committed"], serde_json::json!(1));
        assert_eq!(body["transfers_failed"], serde_json::json!(1));
        assert_eq!(body["bytes_received_total"], serde_json::json!(4096));
    }

    #[cfg(feature = "tls")]
    #[test]
    fn enabled_quic_config_requires_tls_material() {
        let mut config = AtpdConfig::default();
        config.network.enable_quic = true;
        config.network.quic.rq_auth_key_hex =
            Some("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f".to_string());

        let err = atpd_quic_config(&config).expect_err("missing TLS material must fail closed");
        let message = err.to_string();
        assert!(
            message.contains("server_cert_path"),
            "missing cert path should be named, got {message}"
        );
    }

    #[cfg(feature = "tls")]
    #[test]
    fn enabled_quic_config_rejects_auth_key_and_lab_escape_hatch_together() {
        let mut config = AtpdConfig::default();
        config.network.enable_quic = true;
        config.network.quic.server_cert_path = Some(PathBuf::from("server.pem"));
        config.network.quic.server_key_path = Some(PathBuf::from("server.key"));
        config.network.quic.rq_auth_key_hex =
            Some("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f".to_string());
        config.network.quic.allow_unauthenticated_lab = true;

        let err = atpd_quic_config(&config).expect_err("conflicting auth modes must fail closed");
        let message = err.to_string();
        assert!(
            message.contains("allow_unauthenticated_lab") && message.contains("rq_auth_key_hex"),
            "auth conflict should name both fields, got {message}"
        );
    }
}
