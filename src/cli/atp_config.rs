//! ATP configuration management with precedence hierarchy.
//!
//! Implements the ATP-I1 configuration precedence:
//! CLI flags > local config > daemon policy > defaults

use crate::cli::atp_command_tree::{AtpConfig as CommandAtpConfig, AtpProfile};
use crate::util::path_security::SecurePath;
use semver::Version;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Schema version for the persisted ATP installation config.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigVersion {
    /// Monotonic schema version for `config.toml`.
    pub schema: u32,
}

impl ConfigVersion {
    /// Current persisted installation config schema.
    #[must_use]
    pub const fn current() -> Self {
        Self { schema: 1 }
    }
}

/// Receive safety policy selected during first-run setup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReceiveSafetyPolicy {
    /// Ask before accepting every transfer.
    AlwaysAsk,
    /// Auto-accept transfers only from known peers.
    KnownPeersOnly,
    /// Auto-accept all incoming transfers.
    AutoAcceptAll,
}

/// How long ATP should retain transfer proof logs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofRetentionPolicy {
    /// Retain proof logs for the given number of days.
    Days(u64),
}

/// Persisted first-run ATP installation configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtpInstallConfig {
    /// Schema version for this config file.
    pub schema_version: ConfigVersion,
    /// ATP binary version that last wrote this configuration.
    pub version: Option<Version>,
    /// Durable identity key-store path.
    pub identity_path: PathBuf,
    /// Inbox directory for received transfers.
    pub inbox_dir: PathBuf,
    /// Known-peer directory path.
    pub peer_dir: PathBuf,
    /// Daemon state directory path.
    pub daemon_state_dir: PathBuf,
    /// Receive safety policy.
    pub receive_safety_policy: ReceiveSafetyPolicy,
    /// Proof retention policy.
    pub proof_retention_policy: ProofRetentionPolicy,
    /// Whether Tailscale candidate discovery is enabled.
    pub enable_tailscale: bool,
    /// Whether ATP-managed relays are allowed.
    pub allow_relays: bool,
    /// CLI/daemon logging level.
    pub logging_level: String,
    /// Stable platform label used for service integration.
    pub service_platform: String,
    /// Whether daemon service integration was requested.
    pub service_daemon_enabled: bool,
    /// Whether daemon auto-start was requested.
    pub service_auto_start: bool,
}

impl AtpInstallConfig {
    /// Parse a persisted ATP installation config from versioned JSON.
    ///
    /// The outer document schema version is independent of the existing
    /// payload `schema_version`, which remains part of the single typed install
    /// model and is preserved verbatim. Every path is a lexical UTF-8 JSON
    /// string; parsing does not normalize, resolve, or access it.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed or ill-typed JSON, an unsupported outer
    /// schema version, missing required payload fields, or non-UTF-8 paths.
    pub fn from_json(json: &str) -> Result<Self, ConfigError> {
        let document = crate::config::VersionedConfigDocument::<Self>::from_json(json)
            .map_err(ConfigError::Json)?;
        let config = document.into_config();
        config.validate_canonical_paths()?;
        Ok(config)
    }

    /// Render this typed install config as compact versioned canonical JSON.
    ///
    /// Object keys are recursively lexicographic. Paths remain exact lexical
    /// UTF-8 strings and no file I/O occurs. The model stores an identity path,
    /// not identity key material, so this representation contains no known
    /// credential-bearing field.
    ///
    /// # Errors
    ///
    /// Returns an error if a path is not valid UTF-8 or serialization fails.
    pub fn to_canonical_json(&self) -> Result<String, ConfigError> {
        self.validate_canonical_paths()?;
        crate::config::VersionedConfigDocument::new(self)
            .to_canonical_json()
            .map_err(ConfigError::Json)
    }

    fn validate_canonical_paths(&self) -> Result<(), ConfigError> {
        for (field, path) in [
            ("identity_path", self.identity_path.as_path()),
            ("inbox_dir", self.inbox_dir.as_path()),
            ("peer_dir", self.peer_dir.as_path()),
            ("daemon_state_dir", self.daemon_state_dir.as_path()),
        ] {
            require_utf8_path(field, path)?;
        }
        Ok(())
    }

    /// Read a persisted ATP installation config from TOML.
    pub fn read_from_file(path: &Path) -> Result<Self, ConfigError> {
        Self::read_from_file_secure(path, None)
    }

    /// Read a persisted ATP installation config from TOML with path validation.
    pub fn read_from_file_secure(
        path: &Path,
        base_dir: Option<&Path>,
    ) -> Result<Self, ConfigError> {
        let validated_path = if let Some(base) = base_dir {
            // If a base directory is provided, validate the path is within bounds
            let secure_path = SecurePath::new(base).map_err(|e| {
                ConfigError::PathSecurity(format!("Failed to create secure path validator: {}", e))
            })?;
            let validated = secure_path.validate_path(path).map_err(|e| {
                ConfigError::PathSecurity(format!("Path traversal validation failed: {}", e))
            })?;
            validated.to_path_buf()
        } else {
            // If no base directory provided, use the path directly (for backward compatibility)
            // but log a warning about potential security risk
            tracing::warn!(
                "Reading config file without path validation: {}",
                path.display()
            );
            path.to_path_buf()
        };

        let content = fs::read_to_string(&validated_path)
            .map_err(|e| ConfigError::FileRead(validated_path.clone(), e))?;
        toml::from_str(&content).map_err(|e| ConfigError::Parse(validated_path, e))
    }

    /// Write a persisted ATP installation config to TOML.
    pub fn write_to_file(&self, path: &Path) -> Result<(), ConfigError> {
        self.write_to_file_secure(path, None)
    }

    /// Write a persisted ATP installation config to TOML with path validation.
    pub fn write_to_file_secure(
        &self,
        path: &Path,
        base_dir: Option<&Path>,
    ) -> Result<(), ConfigError> {
        let validated_path = if let Some(base) = base_dir {
            // If a base directory is provided, validate the path is within bounds
            let secure_path = SecurePath::new(base).map_err(|e| {
                ConfigError::PathSecurity(format!("Failed to create secure path validator: {}", e))
            })?;
            let validated = secure_path.validate_path(path).map_err(|e| {
                ConfigError::PathSecurity(format!("Path traversal validation failed: {}", e))
            })?;
            validated.to_path_buf()
        } else {
            // If no base directory provided, use the path directly (for backward compatibility)
            // but log a warning about potential security risk
            tracing::warn!(
                "Writing config file without path validation: {}",
                path.display()
            );
            path.to_path_buf()
        };

        if let Some(parent) = validated_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| ConfigError::FileWrite(validated_path.clone(), e))?;
        }

        let content = toml::to_string_pretty(self)
            .map_err(|e| ConfigError::Serialize(validated_path.clone(), e))?;
        fs::write(&validated_path, content).map_err(|e| ConfigError::FileWrite(validated_path, e))
    }
}

/// Parse an ATP command-layer config from versioned JSON.
///
/// This returns the same [`crate::cli::AtpConfig`] that TOML and CLI merging use.
/// Empty `config` objects produce the same all-`None` overlay as empty TOML;
/// unknown fields retain serde's incumbent ignore-on-input behavior.
///
/// # Errors
///
/// Returns an error for malformed or ill-typed JSON, an unsupported schema,
/// a non-finite number, or a non-UTF-8 daemon socket path.
pub fn parse_atp_command_json(json: &str) -> Result<CommandAtpConfig, ConfigError> {
    let document = crate::config::VersionedConfigDocument::<CommandAtpConfig>::from_json(json)
        .map_err(ConfigError::Json)?;
    let config = document.into_config();
    validate_atp_command_canonical_contract(&config)?;
    Ok(config)
}

/// Render an ATP command-layer config as compact versioned canonical JSON.
///
/// JSON numbers are finite and use `serde_json`'s stable shortest form. A
/// non-finite TOML float remains accepted by the incumbent TOML parser but is
/// rejected for JSON conversion instead of being silently changed to `null`.
/// `daemon_socket` is emitted as an exact lexical UTF-8 string.
///
/// # Errors
///
/// Returns an error for a non-finite number, non-UTF-8 path, unsupported
/// document version, or JSON serialization failure.
pub fn atp_command_to_canonical_json(config: &CommandAtpConfig) -> Result<String, ConfigError> {
    validate_atp_command_canonical_contract(config)?;
    crate::config::VersionedConfigDocument::new(config)
        .to_canonical_json()
        .map_err(ConfigError::Json)
}

fn validate_atp_command_canonical_contract(config: &CommandAtpConfig) -> Result<(), ConfigError> {
    if config
        .repair_overhead
        .is_some_and(|repair_overhead| !repair_overhead.is_finite())
    {
        return Err(ConfigError::Validation(
            "repair_overhead must be finite for canonical JSON".to_owned(),
        ));
    }
    if let Some(path) = &config.daemon_socket {
        require_utf8_path("daemon_socket", path)?;
    }
    Ok(())
}

fn require_utf8_path(field: &str, path: &Path) -> Result<(), ConfigError> {
    if path.to_str().is_some() {
        Ok(())
    } else {
        Err(ConfigError::Validation(format!(
            "{field} must be valid UTF-8 for canonical JSON"
        )))
    }
}

/// Configuration source and precedence level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ConfigSource {
    /// Built-in defaults (lowest precedence).
    Defaults = 0,
    /// System-wide daemon policy.
    DaemonPolicy = 1,
    /// Local project/directory configuration.
    LocalConfig = 2,
    /// CLI flags and arguments (highest precedence).
    CliFlags = 3,
}

/// Configuration manager with hierarchical precedence.
#[derive(Debug)]
pub struct AtpConfigManager {
    /// Configuration layers by precedence.
    layers: BTreeMap<ConfigSource, CommandAtpConfig>,
    /// Configuration file paths.
    config_paths: ConfigPaths,
}

/// Standard configuration file locations.
#[derive(Debug, Clone)]
pub struct ConfigPaths {
    /// System daemon policy config.
    pub daemon_policy: PathBuf,
    /// User-specific config.
    pub user_config: PathBuf,
    /// Local project config.
    pub local_config: PathBuf,
}

impl Default for ConfigPaths {
    fn default() -> Self {
        Self::detect_standard_paths()
    }
}

impl ConfigPaths {
    /// Detect standard config paths for the current platform.
    pub fn detect_standard_paths() -> Self {
        #[cfg(all(unix, not(target_os = "macos")))]
        {
            let home = Self::sanitize_env_path("HOME", "/tmp");
            let config_dir =
                Self::sanitize_env_path("XDG_CONFIG_HOME", &format!("{}/.config", home));

            Self {
                daemon_policy: PathBuf::from("/etc/asupersync/atp.toml"),
                user_config: PathBuf::from(format!("{}/asupersync/atp.toml", config_dir)),
                local_config: PathBuf::from(".atp.toml"),
            }
        }

        #[cfg(windows)]
        {
            let appdata = Self::sanitize_env_path("APPDATA", r"C:\Users\Default\AppData\Roaming");

            Self {
                daemon_policy: PathBuf::from(r"C:\ProgramData\Asupersync\atp.toml"),
                user_config: PathBuf::from(format!("{}/Asupersync/atp.toml", appdata)),
                local_config: PathBuf::from(".atp.toml"),
            }
        }

        #[cfg(target_os = "macos")]
        {
            let home = Self::sanitize_env_path("HOME", "/tmp");

            Self {
                daemon_policy: PathBuf::from("/Library/Application Support/Asupersync/atp.toml"),
                user_config: PathBuf::from(format!(
                    "{}/Library/Application Support/Asupersync/atp.toml",
                    home
                )),
                local_config: PathBuf::from(".atp.toml"),
            }
        }
    }

    /// Safely read and validate environment variable paths.
    ///
    /// SECURITY: Prevents path injection attacks through environment variables
    /// by validating that paths don't contain dangerous sequences like "../"
    /// and are within reasonable bounds.
    fn sanitize_env_path(env_var: &str, default: &str) -> String {
        let raw_path = std::env::var(env_var).unwrap_or_else(|_| default.to_string());

        // Security checks to prevent path injection
        if raw_path.contains("..") {
            eprintln!(
                "Security warning: {} contains suspicious path traversal, using default",
                env_var
            );
            return default.to_string();
        }

        // Prevent excessively long paths that could cause issues
        if raw_path.len() > 1024 {
            eprintln!("Security warning: {} path too long, using default", env_var);
            return default.to_string();
        }

        // Prevent null bytes and other control characters
        if raw_path.contains('\0')
            || raw_path
                .chars()
                .any(|c| c.is_control() && c != '\n' && c != '\t')
        {
            eprintln!(
                "Security warning: {} contains invalid characters, using default",
                env_var
            );
            return default.to_string();
        }

        // On Unix, ensure the path is absolute if not default
        #[cfg(unix)]
        if !raw_path.starts_with('/') && raw_path != default {
            eprintln!(
                "Security warning: {} is not absolute, using default",
                env_var
            );
            return default.to_string();
        }

        // On Windows, basic drive letter validation
        #[cfg(windows)]
        if raw_path.chars().nth(1) != Some(':') && raw_path != default {
            eprintln!(
                "Security warning: {} is not a valid Windows path, using default",
                env_var
            );
            return default.to_string();
        }

        raw_path
    }
}

impl AtpConfigManager {
    /// Create a new configuration manager.
    pub fn new() -> Self {
        let mut manager = Self {
            layers: BTreeMap::new(),
            config_paths: ConfigPaths::default(),
        };

        // Load default configuration
        manager
            .layers
            .insert(ConfigSource::Defaults, CommandAtpConfig::default());

        manager
    }

    /// Create with custom config paths.
    pub fn with_paths(config_paths: ConfigPaths) -> Self {
        let mut manager = Self {
            layers: BTreeMap::new(),
            config_paths,
        };

        manager
            .layers
            .insert(ConfigSource::Defaults, CommandAtpConfig::default());
        manager
    }

    /// Load all configuration layers from disk.
    pub fn load_all(&mut self) -> Result<(), ConfigError> {
        self.load_daemon_policy()?;
        self.load_local_config()?;
        Ok(())
    }

    /// Load daemon policy configuration.
    pub fn load_daemon_policy(&mut self) -> Result<(), ConfigError> {
        if let Ok(config) = self.load_config_file(&self.config_paths.daemon_policy) {
            self.layers.insert(ConfigSource::DaemonPolicy, config);
        }
        Ok(())
    }

    /// Load local project configuration.
    pub fn load_local_config(&mut self) -> Result<(), ConfigError> {
        if let Ok(config) = self.load_config_file(&self.config_paths.local_config) {
            self.layers.insert(ConfigSource::LocalConfig, config);
        }
        Ok(())
    }

    /// Set CLI flag overrides.
    pub fn set_cli_overrides(&mut self, cli_config: CommandAtpConfig) {
        self.layers.insert(ConfigSource::CliFlags, cli_config);
    }

    /// Get the final merged configuration with full precedence.
    pub fn merged_config(&self) -> CommandAtpConfig {
        let mut merged = CommandAtpConfig::default();

        // Apply layers in precedence order (lowest to highest)
        for config in self.layers.values() {
            merged = merge_configs(merged, config.clone());
        }

        merged
    }

    /// Get configuration value with source attribution.
    pub fn get_profile_with_source(&self) -> (AtpProfile, ConfigSource) {
        for (source, config) in self.layers.iter().rev() {
            if let Some(profile) = config.profile {
                return (profile, *source);
            }
        }
        (AtpProfile::Auto, ConfigSource::Defaults)
    }

    /// Save configuration to specified scope.
    pub fn save_config(
        &self,
        scope: ConfigScope,
        config: &CommandAtpConfig,
    ) -> Result<(), ConfigError> {
        let path = match scope {
            ConfigScope::User => &self.config_paths.user_config,
            ConfigScope::Local => &self.config_paths.local_config,
            ConfigScope::Daemon => &self.config_paths.daemon_policy,
        };

        self.save_config_file(path, config)
    }

    /// Load configuration from TOML file.
    fn load_config_file(&self, path: &Path) -> Result<CommandAtpConfig, ConfigError> {
        let content =
            fs::read_to_string(path).map_err(|e| ConfigError::FileRead(path.to_path_buf(), e))?;

        let config: CommandAtpConfig =
            toml::from_str(&content).map_err(|e| ConfigError::Parse(path.to_path_buf(), e))?;

        Ok(config)
    }

    /// Save configuration to TOML file.
    fn save_config_file(&self, path: &Path, config: &CommandAtpConfig) -> Result<(), ConfigError> {
        // Create parent directory if needed
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| ConfigError::FileWrite(path.to_path_buf(), e))?;
        }

        let content = toml::to_string_pretty(config)
            .map_err(|e| ConfigError::Serialize(path.to_path_buf(), e))?;

        fs::write(path, content).map_err(|e| ConfigError::FileWrite(path.to_path_buf(), e))?;

        Ok(())
    }

    /// List all configuration sources and their status.
    pub fn list_sources(&self) -> Vec<ConfigSourceInfo> {
        let all_paths = [
            (ConfigSource::DaemonPolicy, &self.config_paths.daemon_policy),
            (ConfigSource::LocalConfig, &self.config_paths.local_config),
        ];

        all_paths
            .iter()
            .map(|(source, path)| ConfigSourceInfo {
                source: *source,
                path: (*path).clone(),
                exists: path.exists(),
                loaded: self.layers.contains_key(source),
            })
            .collect()
    }

    /// Explain configuration value resolution.
    pub fn explain_resolution(&self, key: &str) -> ConfigResolution {
        let mut sources = Vec::new();

        for (source, config) in &self.layers {
            if let Some(value) = get_config_value(config, key) {
                sources.push(ConfigValueSource {
                    source: *source,
                    value: value.clone(),
                });
            }
        }

        let final_value = sources.last().map(|s| s.value.clone());

        ConfigResolution {
            key: key.to_string(),
            final_value,
            sources,
        }
    }
}

/// Configuration scope for save operations.
#[derive(Debug, Clone, Copy)]
pub enum ConfigScope {
    /// User-specific configuration.
    User,
    /// Local project configuration.
    Local,
    /// System daemon policy.
    Daemon,
}

impl std::str::FromStr for ConfigScope {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "user" => Ok(Self::User),
            "local" => Ok(Self::Local),
            "daemon" => Ok(Self::Daemon),
            _ => Err(ConfigError::InvalidScope(s.to_string())),
        }
    }
}

/// Information about a configuration source.
#[derive(Debug, Serialize, Deserialize)]
pub struct ConfigSourceInfo {
    /// Configuration source type.
    pub source: ConfigSource,
    /// Path to configuration file.
    pub path: PathBuf,
    /// File exists on disk.
    pub exists: bool,
    /// Configuration was successfully loaded.
    pub loaded: bool,
}

/// Configuration value resolution details.
#[derive(Debug, Serialize, Deserialize)]
pub struct ConfigResolution {
    /// Configuration key name.
    pub key: String,
    /// Final resolved value.
    pub final_value: Option<serde_json::Value>,
    /// All sources that provide this value.
    pub sources: Vec<ConfigValueSource>,
}

/// Source of a configuration value.
#[derive(Debug, Serialize, Deserialize)]
pub struct ConfigValueSource {
    /// Source type.
    pub source: ConfigSource,
    /// Value from this source.
    pub value: serde_json::Value,
}

/// Configuration management errors.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Failed to read config file {0}: {1}")]
    FileRead(PathBuf, std::io::Error),

    #[error("Failed to write config file {0}: {1}")]
    FileWrite(PathBuf, std::io::Error),

    #[error("Failed to parse config file {0}: {1}")]
    Parse(PathBuf, toml::de::Error),

    #[error("Failed to serialize config file {0}: {1}")]
    Serialize(PathBuf, toml::ser::Error),

    #[error("Versioned JSON configuration error: {0}")]
    Json(#[source] crate::config::ConfigDocumentError),

    #[error("Invalid configuration scope: {0}")]
    InvalidScope(String),

    #[error("Configuration validation error: {0}")]
    Validation(String),

    #[error("Path security validation failed: {0}")]
    PathSecurity(String),
}

/// Merge two configurations with precedence (second overrides first).
fn merge_configs(mut base: CommandAtpConfig, overlay: CommandAtpConfig) -> CommandAtpConfig {
    if overlay.profile.is_some() {
        base.profile = overlay.profile;
    }
    if overlay.chunk_size.is_some() {
        base.chunk_size = overlay.chunk_size;
    }
    if overlay.max_concurrent.is_some() {
        base.max_concurrent = overlay.max_concurrent;
    }
    if overlay.timeout.is_some() {
        base.timeout = overlay.timeout;
    }
    if overlay.compression.is_some() {
        base.compression = overlay.compression;
    }
    if overlay.encryption.is_some() {
        base.encryption = overlay.encryption;
    }
    if overlay.repair_overhead.is_some() {
        base.repair_overhead = overlay.repair_overhead;
    }
    if overlay.interface.is_some() {
        base.interface = overlay.interface;
    }
    if overlay.relay_server.is_some() {
        base.relay_server = overlay.relay_server;
    }
    if overlay.daemon_socket.is_some() {
        base.daemon_socket = overlay.daemon_socket;
    }
    if overlay.verbose.is_some() {
        base.verbose = overlay.verbose;
    }

    base
}

/// Extract configuration value by key name.
fn get_config_value(config: &CommandAtpConfig, key: &str) -> Option<serde_json::Value> {
    match key {
        "profile" => config.profile.map(|p| serde_json::to_value(p).unwrap()),
        "chunk_size" => config
            .chunk_size
            .map(|v| serde_json::Value::Number(v.into())),
        "max_concurrent" => config
            .max_concurrent
            .map(|v| serde_json::Value::Number(v.into())),
        "timeout" => config.timeout.map(|v| serde_json::Value::Number(v.into())),
        "compression" => config.compression.map(serde_json::Value::Bool),
        "encryption" => config.encryption.map(serde_json::Value::Bool),
        "repair_overhead" => config
            .repair_overhead
            .map(|v| serde_json::Value::Number(serde_json::Number::from_f64(v as f64).unwrap())),
        "interface" => config
            .interface
            .as_ref()
            .map(|v| serde_json::Value::String(v.clone())),
        "relay_server" => config
            .relay_server
            .as_ref()
            .map(|v| serde_json::Value::String(v.clone())),
        "daemon_socket" => config
            .daemon_socket
            .as_ref()
            .map(|v| serde_json::Value::String(v.to_string_lossy().to_string())),
        "verbose" => config.verbose.map(serde_json::Value::Bool),
        _ => None,
    }
}

/// Implementation of serialization for ConfigSource.
impl Serialize for ConfigSource {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let name = match self {
            Self::Defaults => "defaults",
            Self::DaemonPolicy => "daemon-policy",
            Self::LocalConfig => "local-config",
            Self::CliFlags => "cli-flags",
        };
        serializer.serialize_str(name)
    }
}

impl<'de> Deserialize<'de> for ConfigSource {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "defaults" => Ok(Self::Defaults),
            "daemon-policy" => Ok(Self::DaemonPolicy),
            "local-config" => Ok(Self::LocalConfig),
            "cli-flags" => Ok(Self::CliFlags),
            _ => Err(serde::de::Error::unknown_variant(
                &s,
                &["defaults", "daemon-policy", "local-config", "cli-flags"],
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::atp_command_tree::AtpConfig;
    use tempfile::TempDir;

    fn sample_install_config() -> AtpInstallConfig {
        AtpInstallConfig {
            schema_version: ConfigVersion::current(),
            version: Some(Version::parse("1.2.3").expect("valid version")),
            identity_path: PathBuf::from("/tmp/asupersync/identity.key"),
            inbox_dir: PathBuf::from("/tmp/asupersync/inbox"),
            peer_dir: PathBuf::from("/tmp/asupersync/peers"),
            daemon_state_dir: PathBuf::from("/tmp/asupersync/state"),
            receive_safety_policy: ReceiveSafetyPolicy::KnownPeersOnly,
            proof_retention_policy: ProofRetentionPolicy::Days(30),
            enable_tailscale: true,
            allow_relays: false,
            logging_level: "info".to_owned(),
            service_platform: "linux".to_owned(),
            service_daemon_enabled: true,
            service_auto_start: false,
        }
    }

    #[test]
    fn atp_command_toml_and_json_share_one_model_and_exact_golden() {
        let toml = r#"
profile = "media"
chunk_size = 1024
repair_overhead = 0.25
daemon_socket = "./run/../atp.sock"
"#;
        let from_toml: AtpConfig = toml::from_str(toml).expect("ATP TOML layer");
        let canonical = atp_command_to_canonical_json(&from_toml).expect("canonical ATP JSON");

        assert_eq!(
            canonical,
            r#"{"config":{"chunk_size":1024,"compression":null,"daemon_socket":"./run/../atp.sock","encryption":null,"interface":null,"max_concurrent":null,"profile":"media","relay_server":null,"repair_overhead":0.25,"timeout":null,"verbose":null},"schema_version":1}"#
        );
        assert_eq!(
            parse_atp_command_json(&canonical).expect("canonical ATP JSON layer"),
            from_toml
        );
    }

    #[test]
    fn atp_command_empty_unknown_schema_and_nonfinite_rules_are_explicit() {
        let empty_toml: AtpConfig = toml::from_str("").expect("empty ATP TOML layer");
        let empty_json = parse_atp_command_json(r#"{"config":{}}"#).expect("empty ATP JSON layer");
        assert_eq!(empty_json, empty_toml);

        let unknown = parse_atp_command_json(
            r#"{"config":{"profile":"auto","future_field":true},"future_envelope":1}"#,
        )
        .expect("unknown JSON fields retain incumbent tolerance");
        assert_eq!(unknown.profile, Some(AtpProfile::Auto));

        let unsupported =
            parse_atp_command_json(r#"{"schema_version":2,"config":{"profile":"auto"}}"#)
                .expect_err("unsupported outer schema must fail closed");
        assert!(unsupported.to_string().contains("schema version 2"));

        let nonfinite: AtpConfig =
            toml::from_str("repair_overhead = nan").expect("incumbent TOML accepts NaN");
        assert!(nonfinite.repair_overhead.is_some_and(f32::is_nan));
        let error = atp_command_to_canonical_json(&nonfinite)
            .expect_err("non-finite JSON conversion must not become null");
        assert!(error.to_string().contains("must be finite"));
    }

    #[test]
    fn atp_install_toml_and_json_share_one_model_and_exact_golden() {
        let install = sample_install_config();
        let toml = toml::to_string_pretty(&install).expect("install TOML");
        let from_toml: AtpInstallConfig = toml::from_str(&toml).expect("install TOML round trip");
        let canonical = from_toml
            .to_canonical_json()
            .expect("canonical install JSON");

        assert_eq!(
            canonical,
            r#"{"config":{"allow_relays":false,"daemon_state_dir":"/tmp/asupersync/state","enable_tailscale":true,"identity_path":"/tmp/asupersync/identity.key","inbox_dir":"/tmp/asupersync/inbox","logging_level":"info","peer_dir":"/tmp/asupersync/peers","proof_retention_policy":{"Days":30},"receive_safety_policy":"KnownPeersOnly","schema_version":{"schema":1},"service_auto_start":false,"service_daemon_enabled":true,"service_platform":"linux","version":"1.2.3"},"schema_version":1}"#
        );
        assert_eq!(
            AtpInstallConfig::from_json(&canonical).expect("install JSON round trip"),
            install
        );
    }

    #[test]
    fn atp_install_outer_schema_is_additive_but_payload_requirements_remain() {
        let canonical = sample_install_config()
            .to_canonical_json()
            .expect("canonical install JSON");
        let without_outer_version = canonical.replacen(",\"schema_version\":1}", "}", 1);
        assert_eq!(
            AtpInstallConfig::from_json(&without_outer_version)
                .expect("missing outer schema migrates to v1"),
            sample_install_config()
        );
        let with_unknown = canonical.replacen(
            "\"allow_relays\":false",
            "\"future_install_field\":true,\"allow_relays\":false",
            1,
        );
        assert_eq!(
            AtpInstallConfig::from_json(&with_unknown)
                .expect("unknown install JSON fields retain incumbent tolerance"),
            sample_install_config()
        );
        assert!(
            AtpInstallConfig::from_json(r#"{"config":{}}"#).is_err(),
            "required install payload fields must remain required"
        );
    }

    #[cfg(unix)]
    #[test]
    fn atp_install_canonical_paths_require_utf8_without_normalizing() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let mut install = sample_install_config();
        install.identity_path = PathBuf::from(OsString::from_vec(vec![0xff]));
        let error = install
            .to_canonical_json()
            .expect_err("non-UTF-8 path cannot be represented losslessly in JSON");
        assert!(
            error
                .to_string()
                .contains("identity_path must be valid UTF-8")
        );
    }

    #[test]
    fn test_config_precedence() {
        let mut manager = AtpConfigManager::new();

        // Set daemon policy
        let daemon_config = AtpConfig {
            profile: Some(AtpProfile::BulkFile),
            compression: Some(false),
            ..Default::default()
        };
        manager
            .layers
            .insert(ConfigSource::DaemonPolicy, daemon_config);

        // Set local config
        let local_config = AtpConfig {
            profile: Some(AtpProfile::SyncTree),
            timeout: Some(600),
            ..Default::default()
        };
        manager
            .layers
            .insert(ConfigSource::LocalConfig, local_config);

        // Set CLI flags
        // `AtpConfig::default()` carries `profile: Some(AtpProfile::Auto)`, so
        // a layer built from `..Default::default()` would override the local
        // profile with Auto. A CLI layer that did not name a profile leaves
        // it unset.
        let cli_config = AtpConfig {
            timeout: Some(120),
            compression: Some(true),
            profile: None,
            ..Default::default()
        };
        manager.layers.insert(ConfigSource::CliFlags, cli_config);

        let merged = manager.merged_config();

        // CLI flags should override local config for timeout
        assert_eq!(merged.timeout, Some(120));
        // CLI flags should override daemon policy for compression
        assert_eq!(merged.compression, Some(true));
        // Local config should override daemon policy for profile
        assert_eq!(merged.profile, Some(AtpProfile::SyncTree));
    }

    #[test]
    fn test_profile_with_source() {
        let mut manager = AtpConfigManager::new();

        // Only defaults - should return Auto
        let (profile, source) = manager.get_profile_with_source();
        assert_eq!(profile, AtpProfile::Auto);
        assert_eq!(source, ConfigSource::Defaults);

        // Add local config
        let local_config = AtpConfig {
            profile: Some(AtpProfile::Artifact),
            ..Default::default()
        };
        manager
            .layers
            .insert(ConfigSource::LocalConfig, local_config);

        let (profile, source) = manager.get_profile_with_source();
        assert_eq!(profile, AtpProfile::Artifact);
        assert_eq!(source, ConfigSource::LocalConfig);
    }

    #[test]
    fn test_config_file_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("test.toml");

        let original_config = AtpConfig {
            profile: Some(AtpProfile::Media),
            chunk_size: Some(1024 * 1024),
            compression: Some(true),
            ..Default::default()
        };

        let manager = AtpConfigManager::new();

        // Save config
        manager
            .save_config_file(&config_path, &original_config)
            .unwrap();

        // Load config
        let loaded_config = manager.load_config_file(&config_path).unwrap();

        assert_eq!(loaded_config.profile, original_config.profile);
        assert_eq!(loaded_config.chunk_size, original_config.chunk_size);
        assert_eq!(loaded_config.compression, original_config.compression);
    }

    #[test]
    fn test_config_resolution_explanation() {
        let mut manager = AtpConfigManager::new();

        // Add multiple layers
        let daemon_config = AtpConfig {
            timeout: Some(300),
            ..Default::default()
        };
        manager
            .layers
            .insert(ConfigSource::DaemonPolicy, daemon_config);

        let local_config = AtpConfig {
            timeout: Some(600),
            ..Default::default()
        };
        manager
            .layers
            .insert(ConfigSource::LocalConfig, local_config);

        let resolution = manager.explain_resolution("timeout");

        assert_eq!(resolution.sources.len(), 3); // defaults + daemon + local
        assert_eq!(
            resolution.final_value,
            Some(serde_json::Value::Number(600.into()))
        );
    }
}
