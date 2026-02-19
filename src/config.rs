//! Configuration, tuning, and runtime profiles for the RaptorQ-integrated runtime.
//!
//! This module provides:
//! - Hierarchical configuration types
//! - Runtime profiles with sensible defaults
//! - Validation for guardrail invariants
//! - Layered loading (file + env + overrides)
//!
//! Note: File parsing is intentionally minimal and deterministic.

use crate::http::h1::listener::Http1ListenerConfig;
use crate::http::h1::server::Http1Config;
use crate::http::pool::PoolConfig;
use crate::observability::{LogLevel, ObservabilityConfig};
use crate::security::AuthMode;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Top-level configuration for the RaptorQ runtime.
#[derive(Debug, Clone, Default)]
pub struct RaptorQConfig {
    /// Encoding/decoding parameters.
    pub encoding: EncodingConfig,
    /// Transport layer settings.
    pub transport: TransportConfig,
    /// Memory and resource limits.
    pub resources: ResourceConfig,
    /// Timeout policies.
    pub timeouts: TimeoutConfig,
    /// Logging and observability.
    pub observability: ObservabilityConfig,
    /// Security settings.
    pub security: SecurityConfig,
}

impl RaptorQConfig {
    /// Validates the configuration for basic sanity.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.encoding.repair_overhead < 1.0 {
            return Err(ConfigError::InvalidRepairOverhead);
        }

        if self.encoding.symbol_size < 8 {
            return Err(ConfigError::InvalidSymbolSize);
        }

        if self.encoding.max_block_size == 0 {
            return Err(ConfigError::InvalidMaxBlockSize);
        }

        if self.encoding.encoding_parallelism == 0 || self.encoding.decoding_parallelism == 0 {
            return Err(ConfigError::InvalidParallelism);
        }

        if self.resources.max_symbol_buffer_memory < 1024 * 1024 {
            return Err(ConfigError::InsufficientMemory);
        }

        if self.timeouts.default_timeout < Duration::from_millis(100) {
            return Err(ConfigError::TimeoutTooShort);
        }

        if !(0.0..=1.0).contains(&self.observability.sample_rate()) {
            return Err(ConfigError::InvalidSampleRate(
                self.observability.sample_rate(),
            ));
        }

        Ok(())
    }
}

/// Unified server configuration combining runtime, HTTP, and protocol settings.
///
/// Provides a single entry point for configuring an asupersync server with
/// validation and sensible defaults. Supports profiles for common deployment
/// scenarios and lab overrides for deterministic testing.
///
/// # Example
///
/// ```
/// # use asupersync::config::{ServerConfig, ServerProfile};
/// let config = ServerConfig::from_profile(ServerProfile::Development);
/// assert!(config.validate().is_ok());
/// ```
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Bind address for the HTTP listener.
    pub bind_addr: SocketAddr,
    /// HTTP/1.1 per-connection configuration.
    pub http: Http1Config,
    /// HTTP listener configuration (connection limits, drain timeout).
    pub listener: Http1ListenerConfig,
    /// Connection pool configuration.
    pub pool: PoolConfig,
    /// Graceful shutdown drain timeout.
    pub shutdown_timeout: Duration,
    /// Worker thread count override. `None` uses available parallelism.
    pub worker_threads: Option<usize>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddr::from(([0, 0, 0, 0], 8080)),
            http: Http1Config::default(),
            listener: Http1ListenerConfig::default(),
            pool: PoolConfig::default(),
            shutdown_timeout: Duration::from_secs(30),
            worker_threads: None,
        }
    }
}

impl ServerConfig {
    /// Create a server config from a deployment profile.
    #[must_use]
    pub fn from_profile(profile: ServerProfile) -> Self {
        match profile {
            ServerProfile::Development => Self {
                bind_addr: SocketAddr::from(([127, 0, 0, 1], 8080)),
                listener: Http1ListenerConfig::default()
                    .max_connections(Some(100))
                    .drain_timeout(Duration::from_secs(5)),
                shutdown_timeout: Duration::from_secs(5),
                ..Default::default()
            },
            ServerProfile::Testing => Self {
                bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
                http: Http1Config::default()
                    .idle_timeout(Some(Duration::from_secs(5)))
                    .max_requests(Some(100)),
                listener: Http1ListenerConfig::default()
                    .max_connections(Some(10))
                    .drain_timeout(Duration::from_millis(500)),
                shutdown_timeout: Duration::from_millis(500),
                worker_threads: Some(1),
                ..Default::default()
            },
            ServerProfile::Production => Self {
                bind_addr: SocketAddr::from(([0, 0, 0, 0], 8080)),
                http: Http1Config::default()
                    .max_headers_size(32 * 1024)
                    .max_body_size(8 * 1024 * 1024)
                    .max_requests(Some(10_000))
                    .idle_timeout(Some(Duration::from_mins(2))),
                listener: Http1ListenerConfig::default()
                    .max_connections(Some(50_000))
                    .drain_timeout(Duration::from_secs(30)),
                shutdown_timeout: Duration::from_secs(30),
                ..Default::default()
            },
        }
    }

    /// Set the bind address.
    #[must_use]
    pub fn bind_addr(mut self, addr: SocketAddr) -> Self {
        self.bind_addr = addr;
        self
    }

    /// Set the HTTP configuration.
    #[must_use]
    pub fn http(mut self, config: Http1Config) -> Self {
        self.http = config;
        self
    }

    /// Set the listener configuration.
    #[must_use]
    pub fn listener(mut self, config: Http1ListenerConfig) -> Self {
        self.listener = config;
        self
    }

    /// Set the connection pool configuration.
    #[must_use]
    pub fn pool(mut self, config: PoolConfig) -> Self {
        self.pool = config;
        self
    }

    /// Set the shutdown timeout.
    #[must_use]
    pub fn shutdown_timeout(mut self, timeout: Duration) -> Self {
        self.shutdown_timeout = timeout;
        self
    }

    /// Set the worker thread count.
    #[must_use]
    pub fn worker_threads(mut self, threads: Option<usize>) -> Self {
        self.worker_threads = threads;
        self
    }

    /// Validate the server configuration.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.shutdown_timeout < Duration::from_millis(100) {
            return Err(ConfigError::TimeoutTooShort);
        }
        if let Some(threads) = self.worker_threads {
            if threads == 0 {
                return Err(ConfigError::InvalidParallelism);
            }
        }
        if let Some(max) = self.listener.max_connections {
            if max == 0 {
                return Err(ConfigError::Parse("max_connections must be > 0".to_owned()));
            }
        }
        Ok(())
    }
}

/// Pre-defined server deployment profiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerProfile {
    /// Development: localhost only, relaxed limits, fast shutdown.
    Development,
    /// Testing: deterministic, minimal resources, instant shutdown.
    Testing,
    /// Production: optimized defaults with generous limits.
    Production,
}

/// Encoding configuration.
#[derive(Debug, Clone)]
pub struct EncodingConfig {
    /// Repair symbol overhead (e.g., 1.05 = 5% extra symbols).
    pub repair_overhead: f64,
    /// Maximum source block size (bytes).
    pub max_block_size: usize,
    /// Symbol size (bytes, typically 64-1024).
    pub symbol_size: u16,
    /// Parallelism for encoding.
    pub encoding_parallelism: usize,
    /// Parallelism for decoding.
    pub decoding_parallelism: usize,
}

impl Default for EncodingConfig {
    fn default() -> Self {
        Self {
            repair_overhead: 1.05,
            max_block_size: 1024 * 1024,
            symbol_size: 256,
            encoding_parallelism: 2,
            decoding_parallelism: 2,
        }
    }
}

/// Transport configuration.
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// Maximum concurrent paths.
    pub max_paths: usize,
    /// Path health check interval.
    pub health_check_interval: Duration,
    /// Dead path retry backoff.
    pub dead_path_backoff: BackoffConfig,
    /// Maximum symbols in flight per path.
    pub max_symbols_in_flight: usize,
    /// Path selection strategy.
    pub path_strategy: PathSelectionStrategy,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            max_paths: 4,
            health_check_interval: Duration::from_secs(5),
            dead_path_backoff: BackoffConfig::default(),
            max_symbols_in_flight: 256,
            path_strategy: PathSelectionStrategy::RoundRobin,
        }
    }
}

/// Backoff configuration for transport retries.
#[derive(Debug, Clone)]
pub struct BackoffConfig {
    /// Initial backoff delay.
    pub initial_delay: Duration,
    /// Maximum backoff delay.
    pub max_delay: Duration,
    /// Backoff multiplier.
    pub multiplier: f64,
}

impl Default for BackoffConfig {
    fn default() -> Self {
        Self {
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(10),
            multiplier: 2.0,
        }
    }
}

/// Adaptive path selection configuration.
#[derive(Debug, Clone)]
pub struct AdaptiveConfig {
    /// Number of samples before switching to adaptive mode.
    pub min_samples: usize,
    /// Exponential decay factor for scores.
    pub decay: f64,
}

impl Default for AdaptiveConfig {
    fn default() -> Self {
        Self {
            min_samples: 16,
            decay: 0.9,
        }
    }
}

/// Path selection strategies.
#[derive(Debug, Clone)]
pub enum PathSelectionStrategy {
    /// Round-robin across healthy paths.
    RoundRobin,
    /// Weighted by path latency.
    LatencyWeighted,
    /// Adaptive based on recent performance.
    Adaptive(AdaptiveConfig),
    /// Random selection.
    Random,
}

/// Resource limits.
#[derive(Debug, Clone)]
pub struct ResourceConfig {
    /// Maximum memory for symbol buffers.
    pub max_symbol_buffer_memory: usize,
    /// Maximum concurrent encoding operations.
    pub max_encoding_ops: usize,
    /// Maximum concurrent decoding operations.
    pub max_decoding_ops: usize,
    /// Symbol pool size (buffer count).
    pub symbol_pool_size: usize,
}

impl Default for ResourceConfig {
    fn default() -> Self {
        Self {
            max_symbol_buffer_memory: 64 * 1024 * 1024,
            max_encoding_ops: 8,
            max_decoding_ops: 8,
            symbol_pool_size: 1024,
        }
    }
}

/// Timeout policies.
#[derive(Debug, Clone)]
pub struct TimeoutConfig {
    /// Default operation timeout.
    pub default_timeout: Duration,
    /// Encoding timeout.
    pub encoding_timeout: Duration,
    /// Decoding timeout (waiting for symbols).
    pub decoding_timeout: Duration,
    /// Path establishment timeout.
    pub path_timeout: Duration,
    /// Quorum wait timeout.
    pub quorum_timeout: Duration,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            default_timeout: Duration::from_secs(30),
            encoding_timeout: Duration::from_secs(30),
            decoding_timeout: Duration::from_secs(30),
            path_timeout: Duration::from_secs(10),
            quorum_timeout: Duration::from_secs(10),
        }
    }
}

/// Security settings.
#[derive(Debug, Clone)]
pub struct SecurityConfig {
    /// Authentication mode (strict/permissive/disabled).
    pub auth_mode: AuthMode,
    /// Deterministic key seed (if provided).
    pub auth_key_seed: Option<u64>,
    /// Whether to reject unauthenticated symbols.
    pub reject_unauthenticated: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            auth_mode: AuthMode::Strict,
            auth_key_seed: None,
            reject_unauthenticated: true,
        }
    }
}

/// Pre-defined configuration profiles.
#[derive(Debug, Clone)]
pub enum RuntimeProfile {
    /// Development: verbose logging, relaxed limits.
    Development,
    /// Testing: deterministic, debug-friendly.
    Testing,
    /// Staging: production-like with extra observability.
    Staging,
    /// Production: optimized defaults.
    Production,
    /// HighThroughput: tuned for large data volumes.
    HighThroughput,
    /// LowLatency: tuned for minimal delay.
    LowLatency,
    /// Custom: user-provided configuration.
    Custom(Box<RaptorQConfig>),
}

impl RuntimeProfile {
    /// Expands the profile into a concrete configuration.
    #[must_use]
    pub fn to_config(&self) -> RaptorQConfig {
        match self {
            Self::Development => {
                let mut config = RaptorQConfig::default();
                config.encoding.repair_overhead = 1.1;
                config.encoding.symbol_size = 256;
                config.encoding.encoding_parallelism = 2;
                config.observability = ObservabilityConfig::development();
                config
            }
            Self::Testing => RaptorQConfig {
                observability: ObservabilityConfig::testing(),
                ..Default::default()
            },
            Self::Staging => {
                let mut config = RaptorQConfig::default();
                config.encoding.repair_overhead = 1.05;
                config.observability = ObservabilityConfig::production()
                    .with_sample_rate(0.05)
                    .with_log_level(LogLevel::Info);
                config
            }
            Self::Production => {
                let mut config = RaptorQConfig::default();
                config.encoding.repair_overhead = 1.02;
                config.encoding.symbol_size = 1024;
                config.encoding.encoding_parallelism = available_parallelism();
                config.encoding.decoding_parallelism = available_parallelism();
                config.observability = ObservabilityConfig::production();
                config
            }
            Self::HighThroughput => {
                let mut config = RaptorQConfig::default();
                config.encoding.repair_overhead = 1.05;
                config.encoding.symbol_size = 1024;
                config.encoding.encoding_parallelism = available_parallelism();
                config.encoding.decoding_parallelism = available_parallelism();
                config.resources.max_symbol_buffer_memory = 512 * 1024 * 1024;
                config.resources.symbol_pool_size = 8192;
                config
            }
            Self::LowLatency => {
                let mut config = RaptorQConfig::default();
                config.encoding.repair_overhead = 1.01;
                config.encoding.symbol_size = 128;
                config.timeouts.default_timeout = Duration::from_secs(5);
                config.timeouts.encoding_timeout = Duration::from_secs(5);
                config.timeouts.decoding_timeout = Duration::from_secs(5);
                config
            }
            Self::Custom(config) => config.as_ref().clone(),
        }
    }
}

/// Configuration loader with layered sources.
#[derive(Debug, Clone)]
pub struct ConfigLoader {
    profile: RuntimeProfile,
    file_path: Option<PathBuf>,
    overrides: BTreeMap<String, String>,
}

impl ConfigLoader {
    /// Creates a new loader with the development profile.
    #[must_use]
    pub fn new() -> Self {
        Self {
            profile: RuntimeProfile::Development,
            file_path: None,
            overrides: BTreeMap::new(),
        }
    }

    /// Sets the base profile.
    #[must_use]
    pub fn profile(mut self, profile: RuntimeProfile) -> Self {
        self.profile = profile;
        self
    }

    /// Sets a file path for config loading.
    #[must_use]
    pub fn file(mut self, path: impl Into<PathBuf>) -> Self {
        self.file_path = Some(path.into());
        self
    }

    /// Adds a programmatic override (highest precedence).
    #[must_use]
    pub fn override_value(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.overrides.insert(key.into(), value.into());
        self
    }

    /// Loads configuration with precedence:
    /// 1. File config (lowest)
    /// 2. Profile defaults
    /// 3. Environment variables
    /// 4. Programmatic overrides (highest)
    pub fn load(&self) -> Result<RaptorQConfig, ConfigError> {
        let mut config = if let Some(path) = &self.file_path {
            load_from_file(path, &self.profile)?
        } else {
            self.profile.to_config()
        };

        apply_env_overrides(&mut config)?;
        apply_overrides(&mut config, &self.overrides)?;
        config.validate()?;
        Ok(config)
    }
}

impl Default for ConfigLoader {
    fn default() -> Self {
        Self::new()
    }
}

/// Configuration errors.
#[derive(Debug)]
pub enum ConfigError {
    /// I/O error while reading configuration.
    Io(std::io::Error),
    /// Parse error.
    Parse(String),
    /// Invalid repair overhead.
    InvalidRepairOverhead,
    /// Invalid symbol size.
    InvalidSymbolSize,
    /// Invalid block size.
    InvalidMaxBlockSize,
    /// Invalid parallelism.
    InvalidParallelism,
    /// Insufficient memory budget.
    InsufficientMemory,
    /// Timeout too short.
    TimeoutTooShort,
    /// Invalid sample rate.
    InvalidSampleRate(f64),
    /// Invalid env override.
    InvalidOverride(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(err) => write!(f, "config I/O error: {err}"),
            Self::Parse(err) => write!(f, "config parse error: {err}"),
            Self::InvalidRepairOverhead => write!(f, "repair_overhead must be >= 1.0"),
            Self::InvalidSymbolSize => write!(f, "symbol_size out of range"),
            Self::InvalidMaxBlockSize => write!(f, "max_block_size must be > 0"),
            Self::InvalidParallelism => write!(f, "parallelism must be > 0"),
            Self::InsufficientMemory => write!(f, "max_symbol_buffer_memory too small"),
            Self::TimeoutTooShort => write!(f, "default_timeout too short"),
            Self::InvalidSampleRate(value) => {
                write!(f, "sample_rate out of range: {value}")
            }
            Self::InvalidOverride(key) => write!(f, "invalid override: {key}"),
        }
    }
}

impl std::error::Error for ConfigError {}

impl From<std::io::Error> for ConfigError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

fn available_parallelism() -> usize {
    std::thread::available_parallelism()
        .map_or(1, std::num::NonZeroUsize::get)
        .max(1)
}

fn load_from_file(path: &Path, profile: &RuntimeProfile) -> Result<RaptorQConfig, ConfigError> {
    let contents = std::fs::read_to_string(path)?;
    let base = profile.to_config();
    parse_config(&contents, base)
}

fn apply_env_overrides(config: &mut RaptorQConfig) -> Result<(), ConfigError> {
    let mut overrides = BTreeMap::new();
    for (key, value) in std::env::vars() {
        if key.starts_with("RAPTORQ_") {
            overrides.insert(key, value);
        }
    }
    apply_overrides(config, &overrides)
}

fn apply_overrides(
    config: &mut RaptorQConfig,
    overrides: &BTreeMap<String, String>,
) -> Result<(), ConfigError> {
    for (key, value) in overrides {
        apply_env_override(config, key, value)?;
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn apply_env_override(
    config: &mut RaptorQConfig,
    key: &str,
    value: &str,
) -> Result<(), ConfigError> {
    match key {
        "RAPTORQ_ENCODING_REPAIR_OVERHEAD" => {
            config.encoding.repair_overhead = parse_f64(value, key)?;
        }
        "RAPTORQ_ENCODING_MAX_BLOCK_SIZE" => {
            config.encoding.max_block_size = parse_usize(value, key)?;
        }
        "RAPTORQ_ENCODING_SYMBOL_SIZE" => {
            config.encoding.symbol_size = parse_u16(value, key)?;
        }
        "RAPTORQ_ENCODING_PARALLELISM" => {
            let parallelism = parse_usize(value, key)?;
            config.encoding.encoding_parallelism = parallelism;
            config.encoding.decoding_parallelism = parallelism;
        }
        "RAPTORQ_ENCODING_ENCODING_PARALLELISM" => {
            config.encoding.encoding_parallelism = parse_usize(value, key)?;
        }
        "RAPTORQ_ENCODING_DECODING_PARALLELISM" => {
            config.encoding.decoding_parallelism = parse_usize(value, key)?;
        }
        "RAPTORQ_TRANSPORT_MAX_PATHS" => {
            config.transport.max_paths = parse_usize(value, key)?;
        }
        "RAPTORQ_TRANSPORT_HEALTH_CHECK_INTERVAL_MS" => {
            config.transport.health_check_interval = parse_duration_ms(value, key)?;
        }
        "RAPTORQ_TRANSPORT_DEAD_PATH_BACKOFF_INITIAL_MS" => {
            config.transport.dead_path_backoff.initial_delay = parse_duration_ms(value, key)?;
        }
        "RAPTORQ_TRANSPORT_DEAD_PATH_BACKOFF_MAX_MS" => {
            config.transport.dead_path_backoff.max_delay = parse_duration_ms(value, key)?;
        }
        "RAPTORQ_TRANSPORT_DEAD_PATH_BACKOFF_MULTIPLIER" => {
            config.transport.dead_path_backoff.multiplier = parse_f64(value, key)?;
        }
        "RAPTORQ_TRANSPORT_MAX_SYMBOLS_IN_FLIGHT" => {
            config.transport.max_symbols_in_flight = parse_usize(value, key)?;
        }
        "RAPTORQ_TRANSPORT_PATH_STRATEGY" => {
            config.transport.path_strategy = parse_path_strategy(value, key)?;
        }
        "RAPTORQ_RESOURCES_MAX_SYMBOL_BUFFER_MEMORY" => {
            config.resources.max_symbol_buffer_memory = parse_usize(value, key)?;
        }
        "RAPTORQ_RESOURCES_MAX_ENCODING_OPS" => {
            config.resources.max_encoding_ops = parse_usize(value, key)?;
        }
        "RAPTORQ_RESOURCES_MAX_DECODING_OPS" => {
            config.resources.max_decoding_ops = parse_usize(value, key)?;
        }
        "RAPTORQ_RESOURCES_SYMBOL_POOL_SIZE" => {
            config.resources.symbol_pool_size = parse_usize(value, key)?;
        }
        "RAPTORQ_TIMEOUTS_DEFAULT_TIMEOUT_MS" => {
            config.timeouts.default_timeout = parse_duration_ms(value, key)?;
        }
        "RAPTORQ_TIMEOUTS_ENCODING_TIMEOUT_MS" => {
            config.timeouts.encoding_timeout = parse_duration_ms(value, key)?;
        }
        "RAPTORQ_TIMEOUTS_DECODING_TIMEOUT_MS" => {
            config.timeouts.decoding_timeout = parse_duration_ms(value, key)?;
        }
        "RAPTORQ_TIMEOUTS_PATH_TIMEOUT_MS" => {
            config.timeouts.path_timeout = parse_duration_ms(value, key)?;
        }
        "RAPTORQ_TIMEOUTS_QUORUM_TIMEOUT_MS" => {
            config.timeouts.quorum_timeout = parse_duration_ms(value, key)?;
        }
        "RAPTORQ_OBSERVABILITY_LOG_LEVEL" => {
            let level = parse_log_level(value, key)?;
            config.observability = config.observability.clone().with_log_level(level);
        }
        "RAPTORQ_OBSERVABILITY_TRACE_ALL_SYMBOLS" => {
            let trace = parse_bool(value, key)?;
            config.observability = config.observability.clone().with_trace_all_symbols(trace);
        }
        "RAPTORQ_OBSERVABILITY_SAMPLE_RATE" => {
            let rate = parse_sample_rate(value, key)?;
            config.observability = config.observability.clone().with_sample_rate(rate);
        }
        "RAPTORQ_OBSERVABILITY_MAX_SPANS" => {
            let max = parse_usize(value, key)?;
            config.observability = config.observability.clone().with_max_spans(max);
        }
        "RAPTORQ_OBSERVABILITY_MAX_LOG_ENTRIES" => {
            let max = parse_usize(value, key)?;
            config.observability = config.observability.clone().with_max_log_entries(max);
        }
        "RAPTORQ_OBSERVABILITY_INCLUDE_TIMESTAMPS" => {
            let include = parse_bool(value, key)?;
            config.observability = config
                .observability
                .clone()
                .with_include_timestamps(include);
        }
        "RAPTORQ_OBSERVABILITY_METRICS_ENABLED" => {
            let enabled = parse_bool(value, key)?;
            config.observability = config.observability.clone().with_metrics_enabled(enabled);
        }
        "RAPTORQ_SECURITY_AUTH_MODE" => {
            config.security.auth_mode = parse_auth_mode(value, key)?;
        }
        "RAPTORQ_SECURITY_AUTH_KEY_SEED" => {
            config.security.auth_key_seed = Some(parse_u64(value, key)?);
        }
        "RAPTORQ_SECURITY_REJECT_UNAUTHENTICATED" => {
            config.security.reject_unauthenticated = parse_bool(value, key)?;
        }
        _ => return Err(ConfigError::InvalidOverride(key.to_string())),
    }
    Ok(())
}

fn parse_config(contents: &str, base: RaptorQConfig) -> Result<RaptorQConfig, ConfigError> {
    let mut config = base;
    let mut section = String::new();

    for (line_idx, raw) in contents.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            continue;
        }

        if line.starts_with('[') && line.ends_with(']') {
            section = line[1..line.len() - 1].trim().to_lowercase();
            continue;
        }

        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| ConfigError::Parse(format!("line {}: {}", line_idx + 1, line)))?;
        let key = key.trim();
        let value = value.trim().trim_matches('"');

        apply_section_kv(&mut config, &section, key, value)?;
    }

    Ok(config)
}

fn apply_section_kv(
    config: &mut RaptorQConfig,
    section: &str,
    key: &str,
    value: &str,
) -> Result<(), ConfigError> {
    match section {
        "encoding" => apply_encoding_kv(&mut config.encoding, key, value),
        "transport" => apply_transport_kv(&mut config.transport, key, value),
        "resources" => apply_resource_kv(&mut config.resources, key, value),
        "timeouts" => apply_timeout_kv(&mut config.timeouts, key, value),
        "observability" => apply_observability_kv(&mut config.observability, key, value),
        "security" => apply_security_kv(&mut config.security, key, value),
        "" => Err(ConfigError::Parse(format!(
            "missing section for key: {key}"
        ))),
        _ => Err(ConfigError::Parse(format!("unknown section: {section}"))),
    }
}

fn apply_encoding_kv(
    encoding: &mut EncodingConfig,
    key: &str,
    value: &str,
) -> Result<(), ConfigError> {
    match key {
        "repair_overhead" => encoding.repair_overhead = parse_f64(value, key)?,
        "max_block_size" => encoding.max_block_size = parse_usize(value, key)?,
        "symbol_size" => encoding.symbol_size = parse_u16(value, key)?,
        "encoding_parallelism" => encoding.encoding_parallelism = parse_usize(value, key)?,
        "decoding_parallelism" => encoding.decoding_parallelism = parse_usize(value, key)?,
        _ => return Err(ConfigError::Parse(format!("unknown key: encoding.{key}"))),
    }
    Ok(())
}

fn apply_transport_kv(
    transport: &mut TransportConfig,
    key: &str,
    value: &str,
) -> Result<(), ConfigError> {
    match key {
        "max_paths" => transport.max_paths = parse_usize(value, key)?,
        "health_check_interval_ms" => {
            transport.health_check_interval = parse_duration_ms(value, key)?;
        }
        "dead_path_backoff_initial_ms" => {
            transport.dead_path_backoff.initial_delay = parse_duration_ms(value, key)?;
        }
        "dead_path_backoff_max_ms" => {
            transport.dead_path_backoff.max_delay = parse_duration_ms(value, key)?;
        }
        "dead_path_backoff_multiplier" => {
            transport.dead_path_backoff.multiplier = parse_f64(value, key)?;
        }
        "max_symbols_in_flight" => transport.max_symbols_in_flight = parse_usize(value, key)?,
        "path_strategy" => transport.path_strategy = parse_path_strategy(value, key)?,
        _ => return Err(ConfigError::Parse(format!("unknown key: transport.{key}"))),
    }
    Ok(())
}

fn apply_resource_kv(
    resources: &mut ResourceConfig,
    key: &str,
    value: &str,
) -> Result<(), ConfigError> {
    match key {
        "max_symbol_buffer_memory" => {
            resources.max_symbol_buffer_memory = parse_usize(value, key)?;
        }
        "max_encoding_ops" => resources.max_encoding_ops = parse_usize(value, key)?,
        "max_decoding_ops" => resources.max_decoding_ops = parse_usize(value, key)?,
        "symbol_pool_size" => resources.symbol_pool_size = parse_usize(value, key)?,
        _ => return Err(ConfigError::Parse(format!("unknown key: resources.{key}"))),
    }
    Ok(())
}

fn apply_timeout_kv(
    timeouts: &mut TimeoutConfig,
    key: &str,
    value: &str,
) -> Result<(), ConfigError> {
    match key {
        "default_timeout_ms" => timeouts.default_timeout = parse_duration_ms(value, key)?,
        "encoding_timeout_ms" => timeouts.encoding_timeout = parse_duration_ms(value, key)?,
        "decoding_timeout_ms" => timeouts.decoding_timeout = parse_duration_ms(value, key)?,
        "path_timeout_ms" => timeouts.path_timeout = parse_duration_ms(value, key)?,
        "quorum_timeout_ms" => timeouts.quorum_timeout = parse_duration_ms(value, key)?,
        _ => return Err(ConfigError::Parse(format!("unknown key: timeouts.{key}"))),
    }
    Ok(())
}

fn apply_observability_kv(
    observability: &mut ObservabilityConfig,
    key: &str,
    value: &str,
) -> Result<(), ConfigError> {
    match key {
        "log_level" => {
            let level = parse_log_level(value, key)?;
            *observability = observability.clone().with_log_level(level);
        }
        "trace_all_symbols" => {
            let trace = parse_bool(value, key)?;
            *observability = observability.clone().with_trace_all_symbols(trace);
        }
        "sample_rate" => {
            let rate = parse_sample_rate(value, key)?;
            *observability = observability.clone().with_sample_rate(rate);
        }
        "max_spans" => {
            let max = parse_usize(value, key)?;
            *observability = observability.clone().with_max_spans(max);
        }
        "max_log_entries" => {
            let max = parse_usize(value, key)?;
            *observability = observability.clone().with_max_log_entries(max);
        }
        "include_timestamps" => {
            let include = parse_bool(value, key)?;
            *observability = observability.clone().with_include_timestamps(include);
        }
        "metrics_enabled" => {
            let enabled = parse_bool(value, key)?;
            *observability = observability.clone().with_metrics_enabled(enabled);
        }
        _ => {
            return Err(ConfigError::Parse(format!(
                "unknown key: observability.{key}"
            )));
        }
    }
    Ok(())
}

fn apply_security_kv(
    security: &mut SecurityConfig,
    key: &str,
    value: &str,
) -> Result<(), ConfigError> {
    match key {
        "auth_mode" => security.auth_mode = parse_auth_mode(value, key)?,
        "auth_key_seed" => security.auth_key_seed = Some(parse_u64(value, key)?),
        "reject_unauthenticated" => security.reject_unauthenticated = parse_bool(value, key)?,
        _ => return Err(ConfigError::Parse(format!("unknown key: security.{key}"))),
    }
    Ok(())
}

fn parse_u64(value: &str, key: &str) -> Result<u64, ConfigError> {
    value
        .parse::<u64>()
        .map_err(|_| ConfigError::Parse(format!("invalid u64 for {key}: {value}")))
}

fn parse_usize(value: &str, key: &str) -> Result<usize, ConfigError> {
    value
        .parse::<usize>()
        .map_err(|_| ConfigError::Parse(format!("invalid usize for {key}: {value}")))
}

fn parse_u16(value: &str, key: &str) -> Result<u16, ConfigError> {
    value
        .parse::<u16>()
        .map_err(|_| ConfigError::Parse(format!("invalid u16 for {key}: {value}")))
}

fn parse_f64(value: &str, key: &str) -> Result<f64, ConfigError> {
    value
        .parse::<f64>()
        .map_err(|_| ConfigError::Parse(format!("invalid f64 for {key}: {value}")))
}

fn parse_sample_rate(value: &str, key: &str) -> Result<f64, ConfigError> {
    let rate = parse_f64(value, key)?;
    if (0.0..=1.0).contains(&rate) {
        Ok(rate)
    } else {
        Err(ConfigError::InvalidSampleRate(rate))
    }
}

fn parse_bool(value: &str, key: &str) -> Result<bool, ConfigError> {
    match value.to_lowercase().as_str() {
        "true" | "1" | "yes" => Ok(true),
        "false" | "0" | "no" => Ok(false),
        _ => Err(ConfigError::Parse(format!(
            "invalid bool for {key}: {value}"
        ))),
    }
}

fn parse_duration_ms(value: &str, key: &str) -> Result<Duration, ConfigError> {
    let millis = parse_u64(value, key)?;
    Ok(Duration::from_millis(millis))
}

fn parse_log_level(value: &str, key: &str) -> Result<LogLevel, ConfigError> {
    value
        .parse::<LogLevel>()
        .map_err(|err| ConfigError::Parse(format!("invalid log level for {key}: {err}")))
}

fn parse_auth_mode(value: &str, key: &str) -> Result<AuthMode, ConfigError> {
    match value.to_lowercase().as_str() {
        "strict" => Ok(AuthMode::Strict),
        "permissive" => Ok(AuthMode::Permissive),
        "disabled" => Ok(AuthMode::Disabled),
        _ => Err(ConfigError::Parse(format!(
            "invalid auth mode for {key}: {value}"
        ))),
    }
}

fn parse_path_strategy(value: &str, key: &str) -> Result<PathSelectionStrategy, ConfigError> {
    match value.to_lowercase().as_str() {
        "round_robin" => Ok(PathSelectionStrategy::RoundRobin),
        "latency_weighted" => Ok(PathSelectionStrategy::LatencyWeighted),
        "random" => Ok(PathSelectionStrategy::Random),
        "adaptive" => Ok(PathSelectionStrategy::Adaptive(AdaptiveConfig::default())),
        _ => Err(ConfigError::Parse(format!(
            "invalid path strategy for {key}: {value}"
        ))),
    }
}

#[cfg(test)]
#[allow(unsafe_code)]
mod tests {
    use super::*;

    #[test]
    fn default_config_valid() {
        let config = RaptorQConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn profile_configs_valid() {
        for profile in [
            RuntimeProfile::Development,
            RuntimeProfile::Testing,
            RuntimeProfile::Staging,
            RuntimeProfile::Production,
            RuntimeProfile::HighThroughput,
            RuntimeProfile::LowLatency,
        ] {
            let config = profile.to_config();
            assert!(config.validate().is_ok(), "Profile {profile:?} invalid");
        }
    }

    #[test]
    fn env_override_symbol_size() {
        // SAFETY: tests serialize env access with test_utils::env_lock.
        unsafe { std::env::set_var("RAPTORQ_ENCODING_SYMBOL_SIZE", "512") };
        let config = ConfigLoader::default().load().unwrap();
        assert_eq!(config.encoding.symbol_size, 512);
        // SAFETY: tests serialize env access with test_utils::env_lock.
        unsafe { std::env::remove_var("RAPTORQ_ENCODING_SYMBOL_SIZE") };
    }

    #[test]
    fn file_loading_minimal() {
        let input = r"
[encoding]
symbol_size = 512
repair_overhead = 1.2

[timeouts]
default_timeout_ms = 5000
";
        let base = RuntimeProfile::Development.to_config();
        let config = parse_config(input, base).unwrap();
        assert_eq!(config.encoding.symbol_size, 512);
        assert!((config.encoding.repair_overhead - 1.2).abs() < f64::EPSILON);
        assert_eq!(config.timeouts.default_timeout, Duration::from_secs(5));
    }

    #[test]
    fn server_config_default_valid() {
        let config = ServerConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn server_config_profiles_valid() {
        for profile in [
            ServerProfile::Development,
            ServerProfile::Testing,
            ServerProfile::Production,
        ] {
            let config = ServerConfig::from_profile(profile);
            assert!(config.validate().is_ok(), "Profile {profile:?} invalid");
        }
    }

    #[test]
    fn server_config_builder() {
        let config = ServerConfig::default()
            .bind_addr(SocketAddr::from(([127, 0, 0, 1], 9090)))
            .shutdown_timeout(Duration::from_mins(1))
            .worker_threads(Some(4));

        assert_eq!(config.bind_addr.port(), 9090);
        assert_eq!(config.shutdown_timeout, Duration::from_mins(1));
        assert_eq!(config.worker_threads, Some(4));
        assert!(config.validate().is_ok());
    }

    #[test]
    fn server_config_validation_errors() {
        let config = ServerConfig::default().shutdown_timeout(Duration::from_millis(10));
        assert!(matches!(
            config.validate(),
            Err(ConfigError::TimeoutTooShort)
        ));

        let config = ServerConfig::default().worker_threads(Some(0));
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidParallelism)
        ));
    }

    #[test]
    fn server_config_testing_profile() {
        let config = ServerConfig::from_profile(ServerProfile::Testing);
        assert_eq!(config.bind_addr.port(), 0); // OS-assigned port
        assert_eq!(config.worker_threads, Some(1));
        assert_eq!(config.listener.max_connections, Some(10));
    }

    #[test]
    fn server_config_production_profile() {
        let config = ServerConfig::from_profile(ServerProfile::Production);
        assert_eq!(config.bind_addr.port(), 8080);
        assert_eq!(config.listener.max_connections, Some(50_000));
        assert_eq!(config.http.max_body_size, 8 * 1024 * 1024);
    }

    #[test]
    fn invalid_repair_overhead() {
        let mut config = RaptorQConfig::default();
        config.encoding.repair_overhead = 0.5;
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidRepairOverhead)
        ));
    }

    /// Invariant: validation rejects symbol_size < 8.
    #[test]
    fn invalid_symbol_size() {
        let mut config = RaptorQConfig::default();
        config.encoding.symbol_size = 4;
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidSymbolSize)
        ));
    }

    /// Invariant: validation rejects max_block_size == 0.
    #[test]
    fn invalid_max_block_size() {
        let mut config = RaptorQConfig::default();
        config.encoding.max_block_size = 0;
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidMaxBlockSize)
        ));
    }

    /// Invariant: validation rejects zero parallelism.
    #[test]
    fn invalid_parallelism_encoding() {
        let mut config = RaptorQConfig::default();
        config.encoding.encoding_parallelism = 0;
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidParallelism)
        ));
    }

    /// Invariant: validation rejects insufficient memory budget.
    #[test]
    fn insufficient_memory() {
        let mut config = RaptorQConfig::default();
        config.resources.max_symbol_buffer_memory = 512;
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InsufficientMemory)
        ));
    }

    /// Invariant: validation rejects too-short timeouts.
    #[test]
    fn timeout_too_short() {
        let mut config = RaptorQConfig::default();
        config.timeouts.default_timeout = Duration::from_millis(10);
        assert!(matches!(
            config.validate(),
            Err(ConfigError::TimeoutTooShort)
        ));
    }

    /// Invariant: ConfigError Display renders all variants.
    #[test]
    fn config_error_display() {
        let err = ConfigError::InvalidRepairOverhead;
        assert!(format!("{err}").contains("repair_overhead"));

        let err = ConfigError::InvalidSymbolSize;
        assert!(format!("{err}").contains("symbol_size"));

        let err = ConfigError::InvalidMaxBlockSize;
        assert!(format!("{err}").contains("max_block_size"));

        let err = ConfigError::InvalidParallelism;
        assert!(format!("{err}").contains("parallelism"));

        let err = ConfigError::InsufficientMemory;
        assert!(format!("{err}").contains("memory"));

        let err = ConfigError::TimeoutTooShort;
        assert!(format!("{err}").contains("timeout"));

        let err = ConfigError::InvalidSampleRate(1.5);
        assert!(format!("{err}").contains("sample_rate"));
    }

    // Pure data-type tests (wave 16 – CyanBarn)

    #[test]
    fn config_error_debug() {
        let err = ConfigError::InvalidRepairOverhead;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("InvalidRepairOverhead"));
    }

    #[test]
    fn config_error_display_io() {
        let err = ConfigError::Io(std::io::Error::new(std::io::ErrorKind::NotFound, "missing"));
        assert!(err.to_string().contains("I/O"));
    }

    #[test]
    fn config_error_display_parse() {
        let err = ConfigError::Parse("bad value".into());
        assert!(err.to_string().contains("parse error"));
    }

    #[test]
    fn config_error_display_invalid_override() {
        let err = ConfigError::InvalidOverride("BAD_KEY".into());
        assert!(err.to_string().contains("BAD_KEY"));
    }

    #[test]
    fn config_error_source() {
        use std::error::Error;

        let err = ConfigError::InvalidRepairOverhead;
        assert!(err.source().is_none());

        // ConfigError has a blanket Error impl with no source override.
        let err =
            ConfigError::Io(std::io::Error::new(std::io::ErrorKind::NotFound, "missing"));
        assert!(err.source().is_none());
    }

    #[test]
    fn config_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let config_err = ConfigError::from(io_err);
        assert!(matches!(config_err, ConfigError::Io(_)));
    }

    #[test]
    fn raptorq_config_debug_clone() {
        let config = RaptorQConfig::default();
        let dbg = format!("{config:?}");
        assert!(dbg.contains("RaptorQConfig"));

        let cloned = config.clone();
        assert_eq!(cloned.encoding.symbol_size, config.encoding.symbol_size);
    }

    #[test]
    fn encoding_config_default() {
        let enc = EncodingConfig::default();
        assert!((enc.repair_overhead - 1.05).abs() < f64::EPSILON);
        assert_eq!(enc.symbol_size, 256);
        assert_eq!(enc.encoding_parallelism, 2);
    }

    #[test]
    fn transport_config_default() {
        let tc = TransportConfig::default();
        assert_eq!(tc.max_paths, 4);
        assert_eq!(tc.max_symbols_in_flight, 256);
    }

    #[test]
    fn backoff_config_debug_clone_default() {
        let bc = BackoffConfig::default();
        let dbg = format!("{bc:?}");
        assert!(dbg.contains("BackoffConfig"));

        let cloned = bc;
        assert_eq!(cloned.initial_delay, Duration::from_millis(100));
        assert_eq!(cloned.max_delay, Duration::from_secs(10));
    }

    #[test]
    fn adaptive_config_debug_clone_default() {
        let ac = AdaptiveConfig::default();
        let dbg = format!("{ac:?}");
        assert!(dbg.contains("AdaptiveConfig"));

        let cloned = ac;
        assert_eq!(cloned.min_samples, 16);
    }

    #[test]
    fn path_selection_strategy_debug_clone() {
        let s = PathSelectionStrategy::RoundRobin;
        let dbg = format!("{s:?}");
        assert!(dbg.contains("RoundRobin"));

        let s = PathSelectionStrategy::Adaptive(AdaptiveConfig::default());
        let cloned = s;
        let dbg = format!("{cloned:?}");
        assert!(dbg.contains("Adaptive"));
    }

    #[test]
    fn resource_config_debug_clone_default() {
        let rc = ResourceConfig::default();
        let dbg = format!("{rc:?}");
        assert!(dbg.contains("ResourceConfig"));

        let cloned = rc;
        assert_eq!(cloned.max_encoding_ops, 8);
    }

    #[test]
    fn timeout_config_debug_clone_default() {
        let tc = TimeoutConfig::default();
        let dbg = format!("{tc:?}");
        assert!(dbg.contains("TimeoutConfig"));

        let cloned = tc;
        assert_eq!(cloned.default_timeout, Duration::from_secs(30));
    }

    #[test]
    fn security_config_debug_clone_default() {
        let sc = SecurityConfig::default();
        let dbg = format!("{sc:?}");
        assert!(dbg.contains("SecurityConfig"));

        let cloned = sc;
        assert!(cloned.reject_unauthenticated);
        assert!(cloned.auth_key_seed.is_none());
    }

    #[test]
    fn server_profile_debug_clone_copy_eq() {
        let p = ServerProfile::Development;
        let cloned = p;
        let copied = p;
        assert_eq!(cloned, copied);
        assert_ne!(p, ServerProfile::Production);
    }

    #[test]
    fn runtime_profile_custom() {
        let config = RaptorQConfig::default();
        let profile = RuntimeProfile::Custom(Box::new(config.clone()));
        let expanded = profile.to_config();
        assert_eq!(expanded.encoding.symbol_size, config.encoding.symbol_size);
    }

    #[test]
    fn runtime_profile_debug_clone() {
        let p = RuntimeProfile::Development;
        let dbg = format!("{p:?}");
        assert!(dbg.contains("Development"));

        let cloned = p;
        let dbg2 = format!("{cloned:?}");
        assert!(dbg2.contains("Development"));
    }

    #[test]
    fn config_loader_debug_clone_default() {
        let loader = ConfigLoader::new();
        let dbg = format!("{loader:?}");
        assert!(dbg.contains("ConfigLoader"));

        let cloned = loader;
        let dbg2 = format!("{cloned:?}");
        assert!(dbg2.contains("ConfigLoader"));

        let default_loader = ConfigLoader::default();
        let dbg3 = format!("{default_loader:?}");
        assert!(dbg3.contains("ConfigLoader"));
    }

    #[test]
    fn config_loader_builder_chain() {
        let loader = ConfigLoader::new()
            .profile(RuntimeProfile::Testing)
            .override_value("encoding.symbol_size", "128");

        let dbg = format!("{loader:?}");
        assert!(dbg.contains("Testing"));
    }

    #[test]
    fn server_config_debug_clone() {
        let config = ServerConfig::default();
        let dbg = format!("{config:?}");
        assert!(dbg.contains("ServerConfig"));

        let cloned = config.clone();
        assert_eq!(cloned.bind_addr, config.bind_addr);
    }
}
