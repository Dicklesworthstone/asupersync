//! ATP benchmark adapter framework for performance comparison.
//!
//! Provides standardized adapters for comparing ATP against baseline tools
//! (scp, rsync, rclone, curl/http3, iperf) with reproducible metrics collection.
//!
//! # Quick Start
//!
//! ```ignore
//! use asupersync::atp::benchmark::{BenchmarkSuite, ScpAdapter, AtpProfile};
//!
//! let mut suite = BenchmarkSuite::new("transfer-comparison");
//! suite.add_baseline(ScpAdapter::new());
//! suite.add_atp_profile(AtpProfile::clean_lan());
//!
//! let results = suite.run_benchmark("test-file", 1024 * 1024).await?;
//! println!("SCP: {:?}", results.baseline_results);
//! println!("ATP: {:?}", results.atp_results);
//! ```

pub mod adapters;
pub mod profiles;
pub mod reports;
pub mod suite;

pub use adapters::{
    BaselineAdapter, CurlAdapter, RcloneAdapter, RsyncAdapter, ScpAdapter, ToolAvailability,
    ToolVersion,
};
pub use profiles::{AtpProfile, AtpProfileKind};
pub use reports::{BenchmarkMetrics, BenchmarkReport, BenchmarkResult, ComparisonReport};
pub use suite::BenchmarkSuite;

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;
use thiserror::Error;

/// Errors from benchmark adapter execution.
#[derive(Debug, Error)]
pub enum BenchmarkError {
    #[error("Tool '{tool}' is not available: {reason}")]
    ToolUnavailable { tool: String, reason: String },
    #[error("Benchmark execution failed: {0}")]
    ExecutionFailed(String),
    #[error("Metrics collection failed: {0}")]
    MetricsCollectionFailed(String),
    #[error("Report generation failed: {0}")]
    ReportGenerationFailed(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("ATP profile error: {0}")]
    AtpProfile(String),
}

/// Environment metadata for benchmark reproducibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkEnvironment {
    /// Operating system information
    pub os_info: String,
    /// CPU information
    pub cpu_info: String,
    /// Memory information
    pub memory_info: String,
    /// Network interface information
    pub network_info: String,
    /// Benchmark timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Environment variables relevant to benchmarking
    pub env_vars: BTreeMap<String, String>,
}

impl BenchmarkEnvironment {
    /// Collect current environment information.
    ///
    /// # Errors
    /// Returns [`BenchmarkError`] if environment detection fails.
    pub fn collect() -> Result<Self, BenchmarkError> {
        Ok(Self {
            os_info: whoami::distro(),
            cpu_info: format!("{}x {}", num_cpus::get(), std::env::consts::ARCH),
            memory_info: format!("Available: {} bytes", get_available_memory()),
            network_info: describe_network_environment(),
            timestamp: chrono::Utc::now(),
            env_vars: collect_relevant_env_vars(),
        })
    }
}

fn describe_network_environment() -> String {
    let interface_count = std::fs::read_dir("/sys/class/net")
        .ok()
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name() != "lo")
                .count()
        })
        .unwrap_or(0);

    if interface_count == 0 {
        "network interfaces unavailable".to_string()
    } else {
        format!("{} non-loopback interface(s) detected", interface_count)
    }
}

/// Configuration for benchmark execution.
#[derive(Debug, Clone)]
pub struct BenchmarkConfig {
    /// Test data size in bytes
    pub data_size: u64,
    /// Number of iterations to run
    pub iterations: u32,
    /// Maximum execution time per iteration
    pub timeout: Duration,
    /// Temporary directory for test artifacts
    pub temp_dir: PathBuf,
    /// Whether to preserve artifacts after benchmark
    pub preserve_artifacts: bool,
    /// Custom environment variables
    pub custom_env: BTreeMap<String, String>,
}

impl Default for BenchmarkConfig {
    fn default() -> Self {
        Self {
            data_size: 1024 * 1024, // 1MB default
            iterations: 1,
            timeout: Duration::from_secs(60),
            temp_dir: std::env::temp_dir(),
            preserve_artifacts: false,
            custom_env: BTreeMap::new(),
        }
    }
}

impl BenchmarkConfig {
    /// Create a configuration for smoke testing (fast, small).
    #[must_use]
    pub fn smoke_test() -> Self {
        Self {
            data_size: 64 * 1024, // 64KB
            iterations: 1,
            timeout: Duration::from_secs(30),
            preserve_artifacts: false,
            ..Self::default()
        }
    }

    /// Create a configuration for regression testing (larger, more thorough).
    #[must_use]
    pub fn regression_test() -> Self {
        Self {
            data_size: 100 * 1024 * 1024, // 100MB
            iterations: 3,
            timeout: Duration::from_secs(300),
            preserve_artifacts: true,
            ..Self::default()
        }
    }

    /// Create a configuration for stress testing (very large).
    #[must_use]
    pub fn stress_test() -> Self {
        Self {
            data_size: 1024 * 1024 * 1024, // 1GB
            iterations: 5,
            timeout: Duration::from_secs(600),
            preserve_artifacts: true,
            ..Self::default()
        }
    }
}

// Helper functions

fn get_available_memory() -> u64 {
    sysinfo::System::new_all().available_memory()
}

fn collect_relevant_env_vars() -> BTreeMap<String, String> {
    let mut env_vars = BTreeMap::new();

    let relevant_vars = [
        "PATH",
        "HOME",
        "TMPDIR",
        "RUST_LOG",
        "CARGO_TARGET_DIR",
        "SSH_AUTH_SOCK",
        "XDG_RUNTIME_DIR",
    ];

    for var in relevant_vars {
        if let Ok(value) = std::env::var(var) {
            env_vars.insert(var.to_string(), value);
        }
    }

    env_vars
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn benchmark_config_smoke_test_is_fast() {
        let config = BenchmarkConfig::smoke_test();
        assert_eq!(config.data_size, 64 * 1024);
        assert_eq!(config.iterations, 1);
        assert!(config.timeout <= Duration::from_secs(30));
    }

    #[test]
    fn benchmark_config_stress_test_is_thorough() {
        let config = BenchmarkConfig::stress_test();
        assert!(config.data_size >= 1024 * 1024 * 1024);
        assert!(config.iterations >= 5);
        assert!(config.preserve_artifacts);
    }

    #[test]
    fn benchmark_environment_collection_succeeds() {
        let env = BenchmarkEnvironment::collect().unwrap();
        assert!(!env.os_info.is_empty());
        assert!(!env.cpu_info.is_empty());
        assert!(env.timestamp <= chrono::Utc::now());
    }
}
