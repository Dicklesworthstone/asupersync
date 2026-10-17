//! Environment variable and config file support for [`RuntimeBuilder`](super::builder::RuntimeBuilder).
//!
//! # Configuration Precedence
//!
//! Settings are resolved in this order (highest priority first):
//!
//! 1. **Programmatic** — values set via builder methods (`worker_threads(4)`)
//! 2. **Environment variables** — values from `ASUPERSYNC_*` env vars
//! 3. **Config file** — values loaded from TOML or versioned JSON (requires `config-file`)
//! 4. **Defaults** — built-in defaults from [`RuntimeConfig::default()`]
//!
//! # Supported Environment Variables
//!
//! | Variable | Type | Maps to |
//! |----------|------|---------|
//! | `ASUPERSYNC_WORKER_THREADS` | `usize` | `worker_threads` |
//! | `ASUPERSYNC_TASK_QUEUE_DEPTH` | `usize` | `global_queue_limit` |
//! | `ASUPERSYNC_THREAD_STACK_SIZE` | `usize` | `thread_stack_size` |
//! | `ASUPERSYNC_THREAD_NAME_PREFIX` | `String` | `thread_name_prefix` |
//! | `ASUPERSYNC_STEAL_BATCH_SIZE` | `usize` | `steal_batch_size` |
//! | `ASUPERSYNC_BLOCKING_MIN_THREADS` | `usize` | `blocking.min_threads` |
//! | `ASUPERSYNC_BLOCKING_MAX_THREADS` | `usize` | `blocking.max_threads` |
//! | `ASUPERSYNC_ENABLE_PARKING` | `bool` | `enable_parking` |
//! | `ASUPERSYNC_POLL_BUDGET` | `u32` | `poll_budget` |
//! | `ASUPERSYNC_CANCEL_LANE_MAX_STREAK` | `usize` | `cancel_lane_max_streak` |
//! | `ASUPERSYNC_ENABLE_GOVERNOR` | `bool` | `enable_governor` |
//! | `ASUPERSYNC_GOVERNOR_INTERVAL` | `u32` | `governor_interval` |
//! | `ASUPERSYNC_ENABLE_ADAPTIVE_CANCEL_STREAK` | `bool` | `enable_adaptive_cancel_streak` |
//! | `ASUPERSYNC_ADAPTIVE_CANCEL_EPOCH_STEPS` | `u32` | `adaptive_cancel_streak_epoch_steps` |

use crate::runtime::config::RuntimeConfig;
use crate::types::builder::BuildError;
use std::collections::HashMap;

/// Environment variable capability interface for controlled environment access.
///
/// This abstracts environment variable access to prevent ambient authority violations
/// during runtime initialization.
trait EnvCapability {
    /// Read an environment variable, returning `None` if unset.
    fn read_env(&self, name: &str) -> Option<String>;
}

/// File capability interface for synchronous file operations.
///
/// This abstracts file system access to prevent ambient authority violations
/// during runtime initialization.
trait FileCapability {
    /// Read file contents as a string.
    fn read_to_string(&self, path: &std::path::Path) -> Result<String, std::io::Error>;
}

/// Production environment variable capability that provides controlled access to the environment.
///
/// Unlike direct `std::env` calls, this capability can be audited and controlled.
struct ProductionEnvCapability;

impl EnvCapability for ProductionEnvCapability {
    fn read_env(&self, name: &str) -> Option<String> {
        // Use std::env here, but mediated through the capability interface.
        // This allows for future enhancement (e.g., sandboxing, auditing) without
        // changing the ambient authority pattern.
        std::env::var(name).ok()
    }
}

/// Production file capability that provides controlled access to the file system.
///
/// Unlike direct `std::fs` calls, this capability can be audited and controlled.
struct ProductionFileCapability;

impl FileCapability for ProductionFileCapability {
    fn read_to_string(&self, path: &std::path::Path) -> Result<String, std::io::Error> {
        // Use std::fs here, but mediated through the capability interface.
        // This allows for future enhancement (e.g., sandboxing, auditing) without
        // changing the ambient authority pattern.
        std::fs::read_to_string(path)
    }
}

/// Abstracts environment variable access to prevent ambient authority violations.
///
/// This trait allows environment variable reading to be dependency-injected,
/// enabling deterministic environment tests and preventing direct ambient
/// access to the process environment.
pub trait EnvReader {
    /// Read an environment variable, returning `None` if unset.
    fn read_env(&self, name: &str) -> Option<String>;

    /// Read a file, returning an error if it fails.
    /// This is needed for TOML and JSON config file reading.
    fn read_file(
        &self,
        path: &std::path::Path,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>>;
}

/// Production implementation that reads from the actual process environment.
///
/// Both environment variable and file access are mediated through capability
/// interfaces to prevent ambient authority violations.
pub struct SystemEnvReader {
    env_cap: ProductionEnvCapability,
    file_cap: ProductionFileCapability,
}

impl SystemEnvReader {
    /// Create a new system environment reader with production capabilities.
    pub fn new() -> Self {
        Self {
            env_cap: ProductionEnvCapability,
            file_cap: ProductionFileCapability,
        }
    }
}

impl Default for SystemEnvReader {
    fn default() -> Self {
        Self::new()
    }
}

impl EnvReader for SystemEnvReader {
    fn read_env(&self, name: &str) -> Option<String> {
        self.env_cap.read_env(name)
    }

    fn read_file(
        &self,
        path: &std::path::Path,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        // Use the file capability instead of direct std::fs access
        self.file_cap
            .read_to_string(path)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
    }
}

/// Test implementation that reads from a provided map.
pub struct TestEnvReader {
    env_vars: HashMap<String, String>,
    files: HashMap<std::path::PathBuf, String>,
}

impl TestEnvReader {
    /// Create a new test environment reader with the given environment variables.
    pub fn new(env_vars: HashMap<String, String>) -> Self {
        Self {
            env_vars,
            files: HashMap::new(),
        }
    }

    /// Add a file that can be read by this reader.
    pub fn with_file(mut self, path: impl Into<std::path::PathBuf>, content: String) -> Self {
        self.files.insert(path.into(), content);
        self
    }
}

impl EnvReader for TestEnvReader {
    fn read_env(&self, name: &str) -> Option<String> {
        self.env_vars.get(name).cloned()
    }

    fn read_file(
        &self,
        path: &std::path::Path,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        self.files.get(path).cloned().ok_or_else(|| {
            let msg = format!("Test file not found: {}", path.display());
            Box::new(std::io::Error::new(std::io::ErrorKind::NotFound, msg))
                as Box<dyn std::error::Error + Send + Sync>
        })
    }
}

/// Environment variable name for worker thread count.
pub const ENV_WORKER_THREADS: &str = "ASUPERSYNC_WORKER_THREADS";
/// Environment variable name for task queue depth (global queue limit).
pub const ENV_TASK_QUEUE_DEPTH: &str = "ASUPERSYNC_TASK_QUEUE_DEPTH";
/// Environment variable name for thread stack size.
pub const ENV_THREAD_STACK_SIZE: &str = "ASUPERSYNC_THREAD_STACK_SIZE";
/// Environment variable name for thread name prefix.
pub const ENV_THREAD_NAME_PREFIX: &str = "ASUPERSYNC_THREAD_NAME_PREFIX";
/// Environment variable name for work-stealing batch size.
pub const ENV_STEAL_BATCH_SIZE: &str = "ASUPERSYNC_STEAL_BATCH_SIZE";
/// Environment variable name for blocking pool minimum threads.
pub const ENV_BLOCKING_MIN_THREADS: &str = "ASUPERSYNC_BLOCKING_MIN_THREADS";
/// Environment variable name for blocking pool maximum threads.
pub const ENV_BLOCKING_MAX_THREADS: &str = "ASUPERSYNC_BLOCKING_MAX_THREADS";
/// Environment variable name for idle-worker parking toggle.
pub const ENV_ENABLE_PARKING: &str = "ASUPERSYNC_ENABLE_PARKING";
/// Environment variable name for cooperative poll budget.
pub const ENV_POLL_BUDGET: &str = "ASUPERSYNC_POLL_BUDGET";
/// Environment variable name for max consecutive cancel dispatches.
pub const ENV_CANCEL_LANE_MAX_STREAK: &str = "ASUPERSYNC_CANCEL_LANE_MAX_STREAK";
/// Environment variable name for enabling the Lyapunov governor.
pub const ENV_ENABLE_GOVERNOR: &str = "ASUPERSYNC_ENABLE_GOVERNOR";
/// Environment variable name for governor snapshot interval (scheduling steps).
pub const ENV_GOVERNOR_INTERVAL: &str = "ASUPERSYNC_GOVERNOR_INTERVAL";
/// Environment variable name for adaptive cancel-streak scheduling.
pub const ENV_ENABLE_ADAPTIVE_CANCEL_STREAK: &str = "ASUPERSYNC_ENABLE_ADAPTIVE_CANCEL_STREAK";
/// Environment variable name for adaptive cancel-streak epoch length.
pub const ENV_ADAPTIVE_CANCEL_EPOCH_STEPS: &str = "ASUPERSYNC_ADAPTIVE_CANCEL_EPOCH_STEPS";

/// Parse environment variable overrides into the shared typed config layer.
///
/// Only variables that are set become `Some`. Parsing completes before the
/// caller mutates a [`RuntimeConfig`], so an invalid late variable cannot
/// leave a partially applied layer.
pub fn parse_env_layer(env_reader: &dyn EnvReader) -> Result<RuntimeConfigLayer, BuildError> {
    let mut layer = RuntimeConfigLayer::default();
    if let Some(val) = env_reader.read_env(ENV_WORKER_THREADS) {
        layer.scheduler.worker_threads = Some(parse_usize(ENV_WORKER_THREADS, &val)?);
    }
    if let Some(val) = env_reader.read_env(ENV_TASK_QUEUE_DEPTH) {
        layer.scheduler.task_queue_depth = Some(parse_usize(ENV_TASK_QUEUE_DEPTH, &val)?);
    }
    if let Some(val) = env_reader.read_env(ENV_THREAD_STACK_SIZE) {
        layer.scheduler.thread_stack_size = Some(parse_usize(ENV_THREAD_STACK_SIZE, &val)?);
    }
    if let Some(val) = env_reader.read_env(ENV_THREAD_NAME_PREFIX) {
        validate_thread_name_prefix(ENV_THREAD_NAME_PREFIX, &val)?;
        layer.scheduler.thread_name_prefix = Some(val);
    }
    if let Some(val) = env_reader.read_env(ENV_STEAL_BATCH_SIZE) {
        layer.scheduler.steal_batch_size = Some(parse_usize(ENV_STEAL_BATCH_SIZE, &val)?);
    }
    if let Some(val) = env_reader.read_env(ENV_BLOCKING_MIN_THREADS) {
        layer.blocking.min_threads = Some(parse_usize(ENV_BLOCKING_MIN_THREADS, &val)?);
    }
    if let Some(val) = env_reader.read_env(ENV_BLOCKING_MAX_THREADS) {
        layer.blocking.max_threads = Some(parse_usize(ENV_BLOCKING_MAX_THREADS, &val)?);
    }
    if let Some(val) = env_reader.read_env(ENV_ENABLE_PARKING) {
        layer.scheduler.enable_parking = Some(parse_bool(ENV_ENABLE_PARKING, &val)?);
    }
    if let Some(val) = env_reader.read_env(ENV_POLL_BUDGET) {
        layer.scheduler.poll_budget = Some(parse_u32(ENV_POLL_BUDGET, &val)?);
    }
    if let Some(val) = env_reader.read_env(ENV_CANCEL_LANE_MAX_STREAK) {
        layer.scheduler.cancel_lane_max_streak =
            Some(parse_usize(ENV_CANCEL_LANE_MAX_STREAK, &val)?);
    }
    if let Some(val) = env_reader.read_env(ENV_ENABLE_GOVERNOR) {
        layer.scheduler.enable_governor = Some(parse_bool(ENV_ENABLE_GOVERNOR, &val)?);
    }
    if let Some(val) = env_reader.read_env(ENV_GOVERNOR_INTERVAL) {
        layer.scheduler.governor_interval = Some(parse_u32(ENV_GOVERNOR_INTERVAL, &val)?);
    }
    if let Some(val) = env_reader.read_env(ENV_ENABLE_ADAPTIVE_CANCEL_STREAK) {
        layer.scheduler.enable_adaptive_cancel_streak =
            Some(parse_bool(ENV_ENABLE_ADAPTIVE_CANCEL_STREAK, &val)?);
    }
    if let Some(val) = env_reader.read_env(ENV_ADAPTIVE_CANCEL_EPOCH_STEPS) {
        layer.scheduler.adaptive_cancel_streak_epoch_steps =
            Some(parse_u32(ENV_ADAPTIVE_CANCEL_EPOCH_STEPS, &val)?);
    }

    Ok(layer)
}

/// Apply environment variable overrides to a [`RuntimeConfig`].
///
/// Environment, TOML, and JSON share [`RuntimeConfigLayer`] and
/// [`apply_runtime_config_layer`]. Only set environment variables override the
/// current configuration. Invalid input fails before any field is applied.
pub fn apply_env_overrides(
    config: &mut RuntimeConfig,
    env_reader: &dyn EnvReader,
) -> Result<(), BuildError> {
    let layer = parse_env_layer(env_reader)?;
    apply_runtime_config_layer(config, &layer)?;

    // Blocking pool min/max remain independently optional. Normalize after
    // overrides so setting either value alone cannot leave min_threads greater
    // than max_threads.
    config.blocking.normalize();

    Ok(())
}

fn parse_usize(var_name: &str, val: &str) -> Result<usize, BuildError> {
    val.trim().parse::<usize>().map_err(|e| {
        BuildError::custom(format!(
            "invalid value for {var_name}: expected unsigned integer, got {val:?} ({e})"
        ))
    })
}

fn parse_u32(var_name: &str, val: &str) -> Result<u32, BuildError> {
    val.trim().parse::<u32>().map_err(|e| {
        BuildError::custom(format!(
            "invalid value for {var_name}: expected u32, got {val:?} ({e})"
        ))
    })
}

fn parse_bool(var_name: &str, val: &str) -> Result<bool, BuildError> {
    match val.trim().to_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Ok(true),
        "false" | "0" | "no" | "off" => Ok(false),
        _ => Err(BuildError::custom(format!(
            "invalid value for {var_name}: expected bool (true/false/1/0/yes/no), got {val:?}"
        ))),
    }
}

fn validate_thread_name_prefix(field_name: &'static str, val: &str) -> Result<(), BuildError> {
    if val.contains('\0') {
        return Err(BuildError::invalid_value(
            field_name,
            "must not contain NUL bytes",
        ));
    }
    Ok(())
}

// =========================================================================
// Shared typed config layer and feature-gated file parsers
// =========================================================================

/// Format-neutral runtime configuration layer.
///
/// This struct mirrors the fields of [`RuntimeConfig`] in a flat,
/// serialization-friendly layout. TOML and versioned JSON deserialize into
/// this same type and feed the same application function. Fields are grouped
/// into TOML tables and equivalent JSON objects:
///
/// ```toml
/// [scheduler]
/// worker_threads = 4
/// task_queue_depth = 1024
/// steal_batch_size = 16
/// poll_budget = 128
/// cancel_lane_max_streak = 16
/// enable_governor = true
/// governor_interval = 64
/// enable_adaptive_cancel_streak = true
/// adaptive_cancel_streak_epoch_steps = 128
/// enable_parking = true
/// thread_stack_size = 2097152
/// thread_name_prefix = "myapp-worker"
///
/// [blocking]
/// min_threads = 1
/// max_threads = 512
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RuntimeConfigLayer {
    /// Scheduler settings.
    #[serde(default)]
    pub scheduler: SchedulerConfigLayer,
    /// Blocking pool settings.
    #[serde(default)]
    pub blocking: BlockingConfigLayer,
}

/// Scheduler section of the typed runtime config layer.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SchedulerConfigLayer {
    /// Number of worker threads.
    pub worker_threads: Option<usize>,
    /// Global task queue depth (0 = unbounded).
    pub task_queue_depth: Option<usize>,
    /// Work-stealing batch size.
    pub steal_batch_size: Option<usize>,
    /// Cooperative poll budget.
    pub poll_budget: Option<u32>,
    /// Maximum consecutive cancel-lane dispatches before yielding.
    pub cancel_lane_max_streak: Option<usize>,
    /// Enable the Lyapunov governor.
    pub enable_governor: Option<bool>,
    /// Scheduling steps between governor snapshots.
    pub governor_interval: Option<u32>,
    /// Enable adaptive cancel-streak selection.
    pub enable_adaptive_cancel_streak: Option<bool>,
    /// Dispatches per adaptive cancel-streak epoch.
    pub adaptive_cancel_streak_epoch_steps: Option<u32>,
    /// Enable parking for idle workers.
    pub enable_parking: Option<bool>,
    /// Stack size per worker thread in bytes.
    pub thread_stack_size: Option<usize>,
    /// Name prefix for worker threads.
    pub thread_name_prefix: Option<String>,
}

/// Blocking pool section of the typed runtime config layer.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BlockingConfigLayer {
    /// Minimum number of blocking threads.
    pub min_threads: Option<usize>,
    /// Maximum number of blocking threads.
    pub max_threads: Option<usize>,
}

/// Apply a parsed file-format config layer to a [`RuntimeConfig`].
///
/// Only fields that are `Some` in the typed layer override the config. TOML
/// and JSON callers share this function so format choice cannot change
/// defaults, validation, or precedence.
pub fn apply_runtime_config_layer(
    config: &mut RuntimeConfig,
    layer: &RuntimeConfigLayer,
) -> Result<(), BuildError> {
    if let Some(ref prefix) = layer.scheduler.thread_name_prefix {
        validate_thread_name_prefix("scheduler.thread_name_prefix", prefix)?;
    }

    if let Some(v) = layer.scheduler.worker_threads {
        config.worker_threads = v;
    }
    if let Some(v) = layer.scheduler.task_queue_depth {
        config.global_queue_limit = v;
    }
    if let Some(v) = layer.scheduler.steal_batch_size {
        config.steal_batch_size = v;
    }
    if let Some(v) = layer.scheduler.poll_budget {
        config.poll_budget = v;
    }
    if let Some(v) = layer.scheduler.cancel_lane_max_streak {
        config.cancel_lane_max_streak = v;
    }
    if let Some(v) = layer.scheduler.enable_governor {
        config.enable_governor = v;
    }
    if let Some(v) = layer.scheduler.governor_interval {
        config.governor_interval = v;
    }
    if let Some(v) = layer.scheduler.enable_adaptive_cancel_streak {
        config.enable_adaptive_cancel_streak = v;
    }
    if let Some(v) = layer.scheduler.adaptive_cancel_streak_epoch_steps {
        config.adaptive_cancel_streak_epoch_steps = v;
    }
    if let Some(v) = layer.scheduler.enable_parking {
        config.enable_parking = v;
    }
    if let Some(v) = layer.scheduler.thread_stack_size {
        config.thread_stack_size = v;
    }
    if let Some(ref prefix) = layer.scheduler.thread_name_prefix {
        config.thread_name_prefix.clone_from(prefix);
    }
    if let Some(v) = layer.blocking.min_threads {
        config.blocking.min_threads = v;
    }
    if let Some(v) = layer.blocking.max_threads {
        config.blocking.max_threads = v;
    }
    Ok(())
}

/// Parse a TOML string into the shared [`RuntimeConfigLayer`].
#[cfg(feature = "config-file")]
pub fn parse_toml_str(toml_str: &str) -> Result<RuntimeConfigLayer, BuildError> {
    toml::from_str(toml_str)
        .map_err(|e| BuildError::custom(format!("failed to parse TOML config: {e}")))
}

/// Read and parse a TOML file into the shared [`RuntimeConfigLayer`].
#[cfg(feature = "config-file")]
pub fn parse_toml_file(
    path: &std::path::Path,
    env_reader: &dyn EnvReader,
) -> Result<RuntimeConfigLayer, BuildError> {
    let content = env_reader.read_file(path).map_err(|e| {
        BuildError::custom(format!(
            "failed to read config file {}: {e}",
            path.display()
        ))
    })?;
    parse_toml_str(&content)
}

/// Parse a versioned JSON string into the shared [`RuntimeConfigLayer`].
///
/// The JSON envelope is `{ "schema_version": 1, "config": { ... } }`.
/// Missing `schema_version` migrates to version 1; unsupported explicit
/// versions fail closed. Unknown fields remain accepted and ignored, matching
/// the incumbent TOML model.
#[cfg(feature = "config-file")]
pub fn parse_json_str(json: &str) -> Result<RuntimeConfigLayer, BuildError> {
    let document = crate::config::VersionedConfigDocument::<RuntimeConfigLayer>::from_json(json)
        .map_err(|e| BuildError::custom(format!("failed to parse JSON config: {e}")))?;
    Ok(document.into_config())
}

/// Read and parse a versioned JSON file into the shared [`RuntimeConfigLayer`].
#[cfg(feature = "config-file")]
pub fn parse_json_file(
    path: &std::path::Path,
    env_reader: &dyn EnvReader,
) -> Result<RuntimeConfigLayer, BuildError> {
    let content = env_reader.read_file(path).map_err(|e| {
        BuildError::custom(format!(
            "failed to read config file {} as JSON: {e}",
            path.display()
        ))
    })?;
    parse_json_str(&content)
}

/// Render a runtime config layer as compact, versioned canonical JSON.
///
/// The runtime layer contains no credential-bearing fields. Every optional
/// typed field is emitted explicitly, object keys are recursively sorted, and
/// the current schema version is always present.
#[cfg(feature = "config-file")]
pub fn runtime_config_to_canonical_json(config: &RuntimeConfigLayer) -> Result<String, BuildError> {
    crate::config::VersionedConfigDocument::new(config)
        .to_canonical_json()
        .map_err(|e| BuildError::custom(format!("failed to encode JSON config: {e}")))
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
#[allow(unsafe_code)]
#[path = "env_config_inline_tests.rs"]
mod tests;

#[cfg(all(test, feature = "config-file"))]
mod toml_tests {
    use super::*;
    use crate::runtime::config::RuntimeConfig;

    #[test]
    fn parse_toml_full_config() {
        let toml_str = r#"
[scheduler]
worker_threads = 8
task_queue_depth = 4096
steal_batch_size = 32
poll_budget = 256
enable_governor = true
governor_interval = 48
enable_adaptive_cancel_streak = true
adaptive_cancel_streak_epoch_steps = 96
enable_parking = false
thread_stack_size = 4194304
thread_name_prefix = "myapp"

[blocking]
min_threads = 2
max_threads = 64
"#;
        let parsed = parse_toml_str(toml_str).unwrap();
        assert_eq!(parsed.scheduler.worker_threads, Some(8));
        assert_eq!(parsed.scheduler.task_queue_depth, Some(4096));
        assert_eq!(parsed.scheduler.steal_batch_size, Some(32));
        assert_eq!(parsed.scheduler.poll_budget, Some(256));
        assert_eq!(parsed.scheduler.enable_governor, Some(true));
        assert_eq!(parsed.scheduler.governor_interval, Some(48));
        assert_eq!(parsed.scheduler.enable_adaptive_cancel_streak, Some(true));
        assert_eq!(
            parsed.scheduler.adaptive_cancel_streak_epoch_steps,
            Some(96)
        );
        assert_eq!(parsed.scheduler.enable_parking, Some(false));
        assert_eq!(parsed.scheduler.thread_stack_size, Some(4_194_304));
        assert_eq!(
            parsed.scheduler.thread_name_prefix.as_deref(),
            Some("myapp")
        );
        assert_eq!(parsed.blocking.min_threads, Some(2));
        assert_eq!(parsed.blocking.max_threads, Some(64));
    }

    #[test]
    fn parse_toml_partial_config() {
        let toml_str = r"
[scheduler]
worker_threads = 4
";
        let parsed = parse_toml_str(toml_str).unwrap();
        assert_eq!(parsed.scheduler.worker_threads, Some(4));
        assert_eq!(parsed.scheduler.poll_budget, None);
        assert_eq!(parsed.blocking.min_threads, None);
    }

    #[test]
    fn parse_toml_empty_config() {
        let parsed = parse_toml_str("").unwrap();
        assert_eq!(parsed.scheduler.worker_threads, None);
        assert_eq!(parsed.blocking.min_threads, None);
    }

    #[test]
    fn parse_toml_invalid_syntax() {
        let result = parse_toml_str("not valid toml {{{{");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("TOML"));
    }

    #[test]
    fn parse_toml_wrong_type() {
        let result = parse_toml_str(
            r#"
[scheduler]
worker_threads = "not_a_number"
"#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn apply_toml_overrides_config() {
        let toml_str = r"
[scheduler]
worker_threads = 16
poll_budget = 512
enable_governor = true
governor_interval = 80
enable_adaptive_cancel_streak = true
adaptive_cancel_streak_epoch_steps = 64

[blocking]
max_threads = 128
";
        let parsed = parse_toml_str(toml_str).unwrap();
        let mut config = RuntimeConfig::default();
        apply_runtime_config_layer(&mut config, &parsed).unwrap();

        assert_eq!(config.worker_threads, 16);
        assert_eq!(config.poll_budget, 512);
        assert!(config.enable_governor);
        assert_eq!(config.governor_interval, 80);
        assert!(config.enable_adaptive_cancel_streak);
        assert_eq!(config.adaptive_cancel_streak_epoch_steps, 64);
        assert_eq!(config.blocking.max_threads, 128);
        // Unset fields remain at defaults.
        assert_eq!(
            config.steal_batch_size,
            RuntimeConfig::default().steal_batch_size
        );
    }

    #[test]
    fn toml_file_not_found() {
        let result = parse_toml_file(
            std::path::Path::new("/nonexistent/config.toml"),
            &SystemEnvReader::new(),
        );
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("failed to read"));
    }

    #[test]
    fn toml_file_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("runtime.toml");
        std::fs::write(
            &path,
            r"
[scheduler]
worker_threads = 2
poll_budget = 64
",
        )
        .unwrap();

        let parsed = parse_toml_file(&path, &SystemEnvReader::new()).unwrap();
        let mut config = RuntimeConfig::default();
        apply_runtime_config_layer(&mut config, &parsed).unwrap();
        assert_eq!(config.worker_threads, 2);
        assert_eq!(config.poll_budget, 64);
    }

    #[test]
    fn toml_rejects_thread_name_prefix_with_nul() {
        let parsed = parse_toml_str(
            r#"
[scheduler]
worker_threads = 16
thread_name_prefix = "bad\u0000prefix"
"#,
        )
        .unwrap();
        let mut config = RuntimeConfig::default();
        let original_worker_threads = config.worker_threads;
        let err = apply_runtime_config_layer(&mut config, &parsed)
            .expect_err("NUL prefix must be rejected");
        assert!(err.to_string().contains("NUL"), "unexpected error: {err}");
        assert_eq!(config.worker_threads, original_worker_threads);
    }

    #[test]
    fn toml_and_json_share_one_typed_layer_with_canonical_golden() {
        let toml = r#"
[scheduler]
worker_threads = 4
thread_name_prefix = "node"

[blocking]
max_threads = 8
"#;
        let from_toml = parse_toml_str(toml).expect("TOML config layer");
        let canonical =
            runtime_config_to_canonical_json(&from_toml).expect("canonical runtime JSON");

        assert_eq!(
            canonical,
            r#"{"config":{"blocking":{"max_threads":8,"min_threads":null},"scheduler":{"adaptive_cancel_streak_epoch_steps":null,"cancel_lane_max_streak":null,"enable_adaptive_cancel_streak":null,"enable_governor":null,"enable_parking":null,"governor_interval":null,"poll_budget":null,"steal_batch_size":null,"task_queue_depth":null,"thread_name_prefix":"node","thread_stack_size":null,"worker_threads":4}},"schema_version":1}"#
        );

        let from_json = parse_json_str(&canonical).expect("canonical JSON config layer");
        assert_eq!(from_json, from_toml);
    }

    #[test]
    fn empty_toml_and_empty_json_payload_share_defaults() {
        let from_toml = parse_toml_str("").expect("empty TOML layer");
        let from_json = parse_json_str(r#"{"config":{}}"#).expect("empty JSON payload");
        assert_eq!(from_json, from_toml);
    }

    #[test]
    fn json_missing_version_migrates_and_unknown_fields_stay_ignored() {
        let json = r#"{
            "future_envelope_field": true,
            "config": {
                "scheduler": {
                    "worker_threads": 3,
                    "future_scheduler_field": "ignored"
                },
                "future_config_field": 42
            }
        }"#;
        let parsed = parse_json_str(json).expect("additive JSON input");
        assert_eq!(parsed.scheduler.worker_threads, Some(3));
        assert_eq!(parsed.blocking.max_threads, None);

        let canonical = runtime_config_to_canonical_json(&parsed).expect("migrated canonical JSON");
        assert!(canonical.ends_with(r#","schema_version":1}"#));
        assert!(!canonical.contains("future_"));
    }

    #[test]
    fn json_rejects_unsupported_schema_and_wrong_field_type() {
        let unsupported =
            parse_json_str(r#"{"schema_version":2,"config":{"scheduler":{"worker_threads":4}}}"#)
                .expect_err("unsupported schema must fail closed");
        assert!(unsupported.to_string().contains("schema version 2"));

        let wrong_type = parse_json_str(
            r#"{"schema_version":1,"config":{"scheduler":{"worker_threads":"four"}}}"#,
        )
        .expect_err("wrong field type must be rejected");
        assert!(wrong_type.to_string().contains("JSON"));
    }

    #[test]
    fn json_file_uses_the_same_capability_mediated_read_path() {
        let reader = TestEnvReader::new(HashMap::new()).with_file(
            "runtime.json",
            r#"{"schema_version":1,"config":{"blocking":{"min_threads":2}}}"#.to_owned(),
        );

        let parsed = parse_json_file(std::path::Path::new("runtime.json"), &reader)
            .expect("JSON file config layer");
        assert_eq!(parsed.blocking.min_threads, Some(2));
    }
}

#[cfg(test)]
#[path = "env_config_metamorphic_tests.rs"]
mod metamorphic_tests;
