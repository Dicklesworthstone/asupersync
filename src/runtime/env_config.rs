//! Environment variable and config file support for [`RuntimeBuilder`](super::builder::RuntimeBuilder).
//!
//! # Configuration Precedence
//!
//! Settings are resolved in this order (highest priority first):
//!
//! 1. **Programmatic** — values set via builder methods (`worker_threads(4)`)
//! 2. **Environment variables** — values from `ASUPERSYNC_*` env vars
//! 3. **Config file** — values loaded from a TOML file (requires `config-file` feature)
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

/// Apply environment variable overrides to a [`RuntimeConfig`].
///
/// Only variables that are set in the environment are applied.
/// Returns an error if a variable is set but contains an unparseable value.
pub fn apply_env_overrides(config: &mut RuntimeConfig) -> Result<(), BuildError> {
    if let Some(val) = read_env(ENV_WORKER_THREADS) {
        config.worker_threads = parse_usize(ENV_WORKER_THREADS, &val)?;
    }
    if let Some(val) = read_env(ENV_TASK_QUEUE_DEPTH) {
        config.global_queue_limit = parse_usize(ENV_TASK_QUEUE_DEPTH, &val)?;
    }
    if let Some(val) = read_env(ENV_THREAD_STACK_SIZE) {
        config.thread_stack_size = parse_usize(ENV_THREAD_STACK_SIZE, &val)?;
    }
    if let Some(val) = read_env(ENV_THREAD_NAME_PREFIX) {
        config.thread_name_prefix = val;
    }
    if let Some(val) = read_env(ENV_STEAL_BATCH_SIZE) {
        config.steal_batch_size = parse_usize(ENV_STEAL_BATCH_SIZE, &val)?;
    }
    if let Some(val) = read_env(ENV_BLOCKING_MIN_THREADS) {
        config.blocking.min_threads = parse_usize(ENV_BLOCKING_MIN_THREADS, &val)?;
    }
    if let Some(val) = read_env(ENV_BLOCKING_MAX_THREADS) {
        config.blocking.max_threads = parse_usize(ENV_BLOCKING_MAX_THREADS, &val)?;
    }
    if let Some(val) = read_env(ENV_ENABLE_PARKING) {
        config.enable_parking = parse_bool(ENV_ENABLE_PARKING, &val)?;
    }
    if let Some(val) = read_env(ENV_POLL_BUDGET) {
        config.poll_budget = parse_u32(ENV_POLL_BUDGET, &val)?;
    }
    if let Some(val) = read_env(ENV_CANCEL_LANE_MAX_STREAK) {
        config.cancel_lane_max_streak = parse_usize(ENV_CANCEL_LANE_MAX_STREAK, &val)?;
    }
    if let Some(val) = read_env(ENV_ENABLE_GOVERNOR) {
        config.enable_governor = parse_bool(ENV_ENABLE_GOVERNOR, &val)?;
    }
    if let Some(val) = read_env(ENV_GOVERNOR_INTERVAL) {
        config.governor_interval = parse_u32(ENV_GOVERNOR_INTERVAL, &val)?;
    }
    if let Some(val) = read_env(ENV_ENABLE_ADAPTIVE_CANCEL_STREAK) {
        config.enable_adaptive_cancel_streak = parse_bool(ENV_ENABLE_ADAPTIVE_CANCEL_STREAK, &val)?;
    }
    if let Some(val) = read_env(ENV_ADAPTIVE_CANCEL_EPOCH_STEPS) {
        config.adaptive_cancel_streak_epoch_steps =
            parse_u32(ENV_ADAPTIVE_CANCEL_EPOCH_STEPS, &val)?;
    }
    Ok(())
}

/// Read an environment variable, returning `None` if unset.
fn read_env(name: &str) -> Option<String> {
    std::env::var(name).ok()
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

// =========================================================================
// TOML config file support (feature-gated)
// =========================================================================

/// TOML-deserializable runtime configuration.
///
/// This struct mirrors the fields of [`RuntimeConfig`] in a flat,
/// serialization-friendly layout. Fields are grouped into TOML tables:
///
/// ```toml
/// [scheduler]
/// worker_threads = 4
/// task_queue_depth = 1024
/// steal_batch_size = 16
/// poll_budget = 128
/// cancel_lane_max_streak = 16
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
#[cfg(feature = "config-file")]
#[derive(serde::Deserialize, Default, Debug)]
pub struct RuntimeTomlConfig {
    /// Scheduler settings.
    #[serde(default)]
    pub scheduler: SchedulerToml,
    /// Blocking pool settings.
    #[serde(default)]
    pub blocking: BlockingToml,
}

/// Scheduler section of the TOML config.
#[cfg(feature = "config-file")]
#[derive(serde::Deserialize, Default, Debug)]
pub struct SchedulerToml {
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

/// Blocking pool section of the TOML config.
#[cfg(feature = "config-file")]
#[derive(serde::Deserialize, Default, Debug)]
pub struct BlockingToml {
    /// Minimum number of blocking threads.
    pub min_threads: Option<usize>,
    /// Maximum number of blocking threads.
    pub max_threads: Option<usize>,
}

/// Apply a parsed TOML config to a [`RuntimeConfig`].
///
/// Only fields that are `Some` in the TOML struct override the config.
#[cfg(feature = "config-file")]
pub fn apply_toml_config(config: &mut RuntimeConfig, toml: &RuntimeTomlConfig) {
    if let Some(v) = toml.scheduler.worker_threads {
        config.worker_threads = v;
    }
    if let Some(v) = toml.scheduler.task_queue_depth {
        config.global_queue_limit = v;
    }
    if let Some(v) = toml.scheduler.steal_batch_size {
        config.steal_batch_size = v;
    }
    if let Some(v) = toml.scheduler.poll_budget {
        config.poll_budget = v;
    }
    if let Some(v) = toml.scheduler.cancel_lane_max_streak {
        config.cancel_lane_max_streak = v;
    }
    if let Some(v) = toml.scheduler.enable_adaptive_cancel_streak {
        config.enable_adaptive_cancel_streak = v;
    }
    if let Some(v) = toml.scheduler.adaptive_cancel_streak_epoch_steps {
        config.adaptive_cancel_streak_epoch_steps = v;
    }
    if let Some(v) = toml.scheduler.enable_parking {
        config.enable_parking = v;
    }
    if let Some(v) = toml.scheduler.thread_stack_size {
        config.thread_stack_size = v;
    }
    if let Some(ref v) = toml.scheduler.thread_name_prefix {
        config.thread_name_prefix.clone_from(v);
    }
    if let Some(v) = toml.blocking.min_threads {
        config.blocking.min_threads = v;
    }
    if let Some(v) = toml.blocking.max_threads {
        config.blocking.max_threads = v;
    }
}

/// Parse a TOML string into a [`RuntimeTomlConfig`].
#[cfg(feature = "config-file")]
pub fn parse_toml_str(toml_str: &str) -> Result<RuntimeTomlConfig, BuildError> {
    toml::from_str(toml_str)
        .map_err(|e| BuildError::custom(format!("failed to parse TOML config: {e}")))
}

/// Read and parse a TOML file into a [`RuntimeTomlConfig`].
#[cfg(feature = "config-file")]
pub fn parse_toml_file(path: &std::path::Path) -> Result<RuntimeTomlConfig, BuildError> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        BuildError::custom(format!(
            "failed to read config file {}: {e}",
            path.display()
        ))
    })?;
    parse_toml_str(&content)
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
#[allow(unsafe_code)]
mod tests {
    use super::*;
    use crate::runtime::config::RuntimeConfig;

    fn with_clean_env<F, R>(f: F) -> R
    where
        F: FnOnce() -> R,
    {
        let _guard = crate::test_utils::env_lock();
        clean_env_locked();
        f()
    }

    // Helper: set env var for the duration of a closure, then unset.
    fn with_env<F, R>(var: &str, val: &str, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        with_clean_env(|| {
            // SAFETY: test helpers guard environment mutation with env_lock.
            unsafe { std::env::set_var(var, val) };
            let result = f();
            // SAFETY: test helpers guard environment mutation with env_lock.
            unsafe { std::env::remove_var(var) };
            result
        })
    }

    fn with_envs<F, R>(vars: &[(&str, &str)], f: F) -> R
    where
        F: FnOnce() -> R,
    {
        with_clean_env(|| {
            for (k, v) in vars {
                // SAFETY: test helpers guard environment mutation with env_lock.
                unsafe { std::env::set_var(k, v) };
            }
            let result = f();
            for (k, _) in vars {
                // SAFETY: test helpers guard environment mutation with env_lock.
                unsafe { std::env::remove_var(k) };
            }
            result
        })
    }

    fn clean_env() {
        let _guard = crate::test_utils::env_lock();
        clean_env_locked();
    }

    fn clean_env_locked() {
        for var in &[
            ENV_WORKER_THREADS,
            ENV_TASK_QUEUE_DEPTH,
            ENV_THREAD_STACK_SIZE,
            ENV_THREAD_NAME_PREFIX,
            ENV_STEAL_BATCH_SIZE,
            ENV_BLOCKING_MIN_THREADS,
            ENV_BLOCKING_MAX_THREADS,
            ENV_ENABLE_PARKING,
            ENV_POLL_BUDGET,
            ENV_CANCEL_LANE_MAX_STREAK,
            ENV_ENABLE_GOVERNOR,
            ENV_GOVERNOR_INTERVAL,
            ENV_ENABLE_ADAPTIVE_CANCEL_STREAK,
            ENV_ADAPTIVE_CANCEL_EPOCH_STEPS,
        ] {
            // SAFETY: test helpers guard environment mutation with env_lock.
            unsafe { std::env::remove_var(var) };
        }
    }

    // --- parse helpers ---

    #[test]
    fn parse_usize_valid() {
        assert_eq!(super::parse_usize("TEST", "42").unwrap(), 42);
        assert_eq!(super::parse_usize("TEST", " 100 ").unwrap(), 100);
        assert_eq!(super::parse_usize("TEST", "0").unwrap(), 0);
    }

    #[test]
    fn parse_usize_invalid() {
        assert!(super::parse_usize("TEST", "abc").is_err());
        assert!(super::parse_usize("TEST", "-1").is_err());
        assert!(super::parse_usize("TEST", "3.14").is_err());
        assert!(super::parse_usize("TEST", "").is_err());
    }

    #[test]
    fn parse_u32_valid() {
        assert_eq!(super::parse_u32("TEST", "128").unwrap(), 128);
    }

    #[test]
    fn parse_u32_invalid() {
        assert!(super::parse_u32("TEST", "not_a_number").is_err());
    }

    #[test]
    fn parse_bool_all_truthy() {
        for val in &["true", "1", "yes", "on", "TRUE", "Yes", "ON"] {
            assert!(
                super::parse_bool("TEST", val).unwrap(),
                "expected true for {val}"
            );
        }
    }

    #[test]
    fn parse_bool_all_falsy() {
        for val in &["false", "0", "no", "off", "FALSE", "No", "OFF"] {
            assert!(
                !super::parse_bool("TEST", val).unwrap(),
                "expected false for {val}"
            );
        }
    }

    #[test]
    fn parse_bool_invalid() {
        assert!(super::parse_bool("TEST", "maybe").is_err());
        assert!(super::parse_bool("TEST", "2").is_err());
        assert!(super::parse_bool("TEST", "").is_err());
    }

    // --- apply_env_overrides ---

    #[test]
    fn env_overrides_worker_threads() {
        with_env(ENV_WORKER_THREADS, "8", || {
            let mut config = RuntimeConfig::default();
            apply_env_overrides(&mut config).unwrap();
            assert_eq!(config.worker_threads, 8);
        });
    }

    #[test]
    fn env_overrides_task_queue_depth() {
        with_env(ENV_TASK_QUEUE_DEPTH, "2048", || {
            let mut config = RuntimeConfig::default();
            apply_env_overrides(&mut config).unwrap();
            assert_eq!(config.global_queue_limit, 2048);
        });
    }

    #[test]
    fn env_overrides_thread_stack_size() {
        with_env(ENV_THREAD_STACK_SIZE, "4194304", || {
            let mut config = RuntimeConfig::default();
            apply_env_overrides(&mut config).unwrap();
            assert_eq!(config.thread_stack_size, 4_194_304);
        });
    }

    #[test]
    fn env_overrides_thread_name_prefix() {
        with_env(ENV_THREAD_NAME_PREFIX, "myapp-worker", || {
            let mut config = RuntimeConfig::default();
            apply_env_overrides(&mut config).unwrap();
            assert_eq!(config.thread_name_prefix, "myapp-worker");
        });
    }

    #[test]
    fn env_overrides_steal_batch_size() {
        with_env(ENV_STEAL_BATCH_SIZE, "32", || {
            let mut config = RuntimeConfig::default();
            apply_env_overrides(&mut config).unwrap();
            assert_eq!(config.steal_batch_size, 32);
        });
    }

    #[test]
    fn env_overrides_blocking_threads() {
        with_envs(
            &[
                (ENV_BLOCKING_MIN_THREADS, "2"),
                (ENV_BLOCKING_MAX_THREADS, "16"),
            ],
            || {
                let mut config = RuntimeConfig::default();
                apply_env_overrides(&mut config).unwrap();
                assert_eq!(config.blocking.min_threads, 2);
                assert_eq!(config.blocking.max_threads, 16);
            },
        );
    }

    #[test]
    fn env_overrides_enable_parking() {
        with_env(ENV_ENABLE_PARKING, "false", || {
            let mut config = RuntimeConfig::default();
            apply_env_overrides(&mut config).unwrap();
            assert!(!config.enable_parking);
        });
    }

    #[test]
    fn env_overrides_poll_budget() {
        with_env(ENV_POLL_BUDGET, "64", || {
            let mut config = RuntimeConfig::default();
            apply_env_overrides(&mut config).unwrap();
            assert_eq!(config.poll_budget, 64);
        });
    }

    #[test]
    fn env_overrides_cancel_lane_max_streak() {
        with_env(ENV_CANCEL_LANE_MAX_STREAK, "7", || {
            let mut config = RuntimeConfig::default();
            apply_env_overrides(&mut config).unwrap();
            assert_eq!(config.cancel_lane_max_streak, 7);
        });
    }

    #[test]
    fn env_overrides_governor_settings() {
        with_envs(
            &[(ENV_ENABLE_GOVERNOR, "true"), (ENV_GOVERNOR_INTERVAL, "41")],
            || {
                let mut config = RuntimeConfig::default();
                apply_env_overrides(&mut config).unwrap();
                assert!(config.enable_governor);
                assert_eq!(config.governor_interval, 41);
            },
        );
    }

    #[test]
    fn env_overrides_adaptive_cancel_settings() {
        with_envs(
            &[
                (ENV_ENABLE_ADAPTIVE_CANCEL_STREAK, "true"),
                (ENV_ADAPTIVE_CANCEL_EPOCH_STEPS, "77"),
            ],
            || {
                let mut config = RuntimeConfig::default();
                apply_env_overrides(&mut config).unwrap();
                assert!(config.enable_adaptive_cancel_streak);
                assert_eq!(config.adaptive_cancel_streak_epoch_steps, 77);
            },
        );
    }

    #[test]
    fn env_overrides_multiple() {
        with_envs(
            &[
                (ENV_WORKER_THREADS, "4"),
                (ENV_POLL_BUDGET, "256"),
                (ENV_ENABLE_PARKING, "no"),
            ],
            || {
                let mut config = RuntimeConfig::default();
                apply_env_overrides(&mut config).unwrap();
                assert_eq!(config.worker_threads, 4);
                assert_eq!(config.poll_budget, 256);
                assert!(!config.enable_parking);
            },
        );
    }

    #[test]
    fn env_overrides_unset_vars_leave_defaults() {
        with_clean_env(|| {
            let defaults = RuntimeConfig::default();
            let mut config = RuntimeConfig::default();
            apply_env_overrides(&mut config).unwrap();
            assert_eq!(config.worker_threads, defaults.worker_threads);
            assert_eq!(config.poll_budget, defaults.poll_budget);
            assert_eq!(config.enable_parking, defaults.enable_parking);
        });
    }

    #[test]
    fn env_overrides_invalid_value_returns_error() {
        with_env(ENV_WORKER_THREADS, "not_a_number", || {
            let mut config = RuntimeConfig::default();
            let result = apply_env_overrides(&mut config);
            assert!(result.is_err());
            let err = result.unwrap_err();
            let msg = err.to_string();
            assert!(
                msg.contains(ENV_WORKER_THREADS),
                "error should mention var name: {msg}"
            );
            assert!(
                msg.contains("not_a_number"),
                "error should mention bad value: {msg}"
            );
        });
    }

    #[test]
    fn clean_env_locked_removes_governor_related_vars() {
        let _guard = crate::test_utils::env_lock();
        // SAFETY: this test holds env_lock for exclusive process-wide env mutation.
        unsafe {
            std::env::set_var(ENV_CANCEL_LANE_MAX_STREAK, "99");
            std::env::set_var(ENV_ENABLE_GOVERNOR, "true");
            std::env::set_var(ENV_GOVERNOR_INTERVAL, "123");
            std::env::set_var(ENV_ENABLE_ADAPTIVE_CANCEL_STREAK, "true");
            std::env::set_var(ENV_ADAPTIVE_CANCEL_EPOCH_STEPS, "77");
        }

        clean_env_locked();

        assert!(std::env::var(ENV_CANCEL_LANE_MAX_STREAK).is_err());
        assert!(std::env::var(ENV_ENABLE_GOVERNOR).is_err());
        assert!(std::env::var(ENV_GOVERNOR_INTERVAL).is_err());
        assert!(std::env::var(ENV_ENABLE_ADAPTIVE_CANCEL_STREAK).is_err());
        assert!(std::env::var(ENV_ADAPTIVE_CANCEL_EPOCH_STEPS).is_err());
    }

    #[test]
    fn env_overrides_invalid_bool_returns_error() {
        with_env(ENV_ENABLE_PARKING, "maybe", || {
            let mut config = RuntimeConfig::default();
            let result = apply_env_overrides(&mut config);
            assert!(result.is_err());
            let msg = result.unwrap_err().to_string();
            assert!(msg.contains("maybe"));
        });
    }
}

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
enable_adaptive_cancel_streak = true
adaptive_cancel_streak_epoch_steps = 64

[blocking]
max_threads = 128
";
        let parsed = parse_toml_str(toml_str).unwrap();
        let mut config = RuntimeConfig::default();
        apply_toml_config(&mut config, &parsed);

        assert_eq!(config.worker_threads, 16);
        assert_eq!(config.poll_budget, 512);
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
        let result = parse_toml_file(std::path::Path::new("/nonexistent/config.toml"));
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

        let parsed = parse_toml_file(&path).unwrap();
        let mut config = RuntimeConfig::default();
        apply_toml_config(&mut config, &parsed);
        assert_eq!(config.worker_threads, 2);
        assert_eq!(config.poll_budget, 64);
    }
}
