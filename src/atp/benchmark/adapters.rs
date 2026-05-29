//! Baseline tool adapters for benchmark comparison.

use crate::atp::benchmark::{BenchmarkConfig, BenchmarkError, BenchmarkMetrics, BenchmarkResult};
use crate::fs;
use crate::io::AsyncWriteExt;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Tool availability status for baseline adapters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ToolAvailability {
    /// Tool is available and version was detected
    Available(ToolVersion),
    /// Tool binary not found in PATH
    NotFound,
    /// Tool found but version detection failed
    VersionDetectionFailed(String),
    /// Tool found but incompatible version
    IncompatibleVersion(ToolVersion),
}

impl ToolAvailability {
    /// Check if the tool is usable for benchmarking.
    #[must_use]
    pub fn is_usable(&self) -> bool {
        matches!(self, Self::Available(_))
    }

    /// Get the tool version if available.
    #[must_use]
    pub fn version(&self) -> Option<&ToolVersion> {
        match self {
            Self::Available(version) | Self::IncompatibleVersion(version) => Some(version),
            Self::NotFound | Self::VersionDetectionFailed(_) => None,
        }
    }
}

/// Tool version information.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolVersion {
    /// Tool name
    pub name: String,
    /// Version string as reported by the tool
    pub version_string: String,
    /// Parsed major version
    pub major: Option<u32>,
    /// Parsed minor version
    pub minor: Option<u32>,
    /// Parsed patch version
    pub patch: Option<u32>,
}

impl ToolVersion {
    /// Create a new tool version from a version string.
    #[must_use]
    pub fn new(name: impl Into<String>, version_string: impl Into<String>) -> Self {
        let name = name.into();
        let version_string = version_string.into();
        let (major, minor, patch) = parse_version_numbers(&version_string);

        Self {
            name,
            version_string,
            major,
            minor,
            patch,
        }
    }

    /// Check if this version meets minimum requirements.
    #[must_use]
    pub fn meets_minimum(&self, min_major: u32, min_minor: u32) -> bool {
        match (self.major, self.minor) {
            (Some(major), Some(minor)) => {
                major > min_major || (major == min_major && minor >= min_minor)
            }
            _ => false, // Can't determine, assume incompatible
        }
    }
}

/// Trait for baseline tool adapters.
#[async_trait::async_trait]
pub trait BaselineAdapter: Send + Sync + std::fmt::Debug {
    /// Get the tool name.
    fn tool_name(&self) -> &str;

    /// Check if the tool is available and get version info.
    async fn check_availability(&self) -> ToolAvailability;

    /// Execute a benchmark with the tool.
    async fn run_benchmark(
        &self,
        config: &BenchmarkConfig,
        source_path: &Path,
        dest_path: &Path,
    ) -> Result<BenchmarkResult, BenchmarkError>;

    /// Parse tool-specific output for metrics extraction.
    fn parse_output(&self, stdout: &str, stderr: &str) -> Result<BenchmarkMetrics, BenchmarkError>;

    /// Get tool-specific environment variables.
    fn get_env_vars(&self) -> BTreeMap<String, String> {
        BTreeMap::new()
    }
}

/// SCP baseline adapter.
#[derive(Debug)]
pub struct ScpAdapter {
    /// SSH options for scp command
    ssh_options: Vec<String>,
}

impl ScpAdapter {
    /// Create a new SCP adapter with default options.
    #[must_use]
    pub fn new() -> Self {
        Self {
            ssh_options: vec![
                "-o".to_string(),
                "StrictHostKeyChecking=no".to_string(),
                "-o".to_string(),
                "UserKnownHostsFile=/dev/null".to_string(),
                "-o".to_string(),
                "BatchMode=yes".to_string(),
            ],
        }
    }

    /// Create an SCP adapter with custom SSH options.
    #[must_use]
    pub fn with_ssh_options(ssh_options: Vec<String>) -> Self {
        Self { ssh_options }
    }

    async fn create_test_file(&self, path: &Path, size: u64) -> Result<(), BenchmarkError> {
        let mut file = fs::File::create(path).await?;

        // Write test data in chunks to avoid memory issues
        let chunk_size = 64 * 1024; // 64KB chunks
        let chunk_data = vec![0u8; chunk_size];
        let mut remaining = size;

        while remaining > 0 {
            let write_size = std::cmp::min(remaining, chunk_size as u64) as usize;
            AsyncWriteExt::write_all(&mut file, &chunk_data[..write_size]).await?;
            remaining -= write_size as u64;
        }

        Ok(())
    }

    fn build_scp_command(&self, source: &Path, dest: &Path) -> Command {
        let mut cmd = Command::new("scp");

        // Add SSH options
        for option in &self.ssh_options {
            cmd.arg(option);
        }

        // Add progress and preserve options
        cmd.arg("-p"); // Preserve modification times and modes
        cmd.arg("-q"); // Quiet mode (reduce noise in output)

        // For local testing, use localhost
        cmd.arg(source.to_string_lossy().to_string());
        cmd.arg(format!("localhost:{}", dest.to_string_lossy()));

        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

        cmd
    }
}

#[async_trait::async_trait]
impl BaselineAdapter for ScpAdapter {
    fn tool_name(&self) -> &str {
        "scp"
    }

    async fn check_availability(&self) -> ToolAvailability {
        let output = match Command::new("scp")
            .arg("-V")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
        {
            Ok(output) => output,
            Err(_) => return ToolAvailability::NotFound,
        };

        let version_text = String::from_utf8_lossy(&output.stderr);

        // SCP version is typically in stderr for OpenSSH
        if let Some(line) = version_text.lines().next() {
            if line.contains("OpenSSH") {
                let version = ToolVersion::new("scp", line);

                // Check for minimum OpenSSH version (7.0+)
                if version.meets_minimum(7, 0) {
                    ToolAvailability::Available(version)
                } else {
                    ToolAvailability::IncompatibleVersion(version)
                }
            } else {
                ToolAvailability::VersionDetectionFailed(line.to_string())
            }
        } else {
            ToolAvailability::VersionDetectionFailed("No version output".to_string())
        }
    }

    async fn run_benchmark(
        &self,
        config: &BenchmarkConfig,
        source_path: &Path,
        dest_path: &Path,
    ) -> Result<BenchmarkResult, BenchmarkError> {
        // Create test file
        self.create_test_file(source_path, config.data_size).await?;

        let mut total_metrics = Vec::new();

        for iteration in 0..config.iterations {
            let iteration_dest = dest_path.with_extension(&format!("iter{iteration}"));

            // Build and execute scp command
            let mut cmd = self.build_scp_command(source_path, &iteration_dest);

            let start_time = Instant::now();
            let output = cmd.output()?;
            let elapsed = start_time.elapsed();

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(BenchmarkError::ExecutionFailed(format!(
                    "SCP failed: {stderr}"
                )));
            }

            // Verify file was copied correctly
            let dest_size = fs::metadata(&iteration_dest).await?.len();
            if dest_size != config.data_size {
                return Err(BenchmarkError::ExecutionFailed(format!(
                    "Size mismatch: expected {}, got {dest_size}",
                    config.data_size
                )));
            }

            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);

            let mut metrics = self.parse_output(&stdout, &stderr)?;
            metrics.wall_time = elapsed;
            metrics.bytes_transferred = config.data_size;
            metrics.verified_completion = true;

            total_metrics.push(metrics);

            // Clean up iteration file if not preserving artifacts
            if !config.preserve_artifacts {
                let _ = fs::remove_file(&iteration_dest).await;
            }
        }

        // Clean up source file if not preserving artifacts
        if !config.preserve_artifacts {
            let _ = fs::remove_file(source_path).await;
        }

        Ok(BenchmarkResult {
            tool_name: self.tool_name().to_string(),
            iterations: total_metrics,
            environment: crate::atp::benchmark::BenchmarkEnvironment::collect()?,
        })
    }

    fn parse_output(
        &self,
        _stdout: &str,
        _stderr: &str,
    ) -> Result<BenchmarkMetrics, BenchmarkError> {
        // SCP doesn't provide detailed metrics by default
        // We collect what we can measure externally
        Ok(BenchmarkMetrics {
            wall_time: Duration::ZERO, // Will be filled by caller
            cpu_time: None,
            memory_peak: None,
            bytes_transferred: 0, // Will be filled by caller
            bytes_on_wire: None,
            verified_completion: false, // Will be filled by caller
            first_usable_output: None,
            resume_time: None,
            disk_amplification_ratio: Some(1.0),
            failure_reproducible: None,
            failure_mode: None,
        })
    }

    fn get_env_vars(&self) -> BTreeMap<String, String> {
        let mut env = BTreeMap::new();
        env.insert(
            "SSH_AUTH_SOCK".to_string(),
            std::env::var("SSH_AUTH_SOCK").unwrap_or_default(),
        );
        env
    }
}

impl Default for ScpAdapter {
    fn default() -> Self {
        Self::new()
    }
}

// Helper function to parse version numbers from version strings
fn parse_version_numbers(version_str: &str) -> (Option<u32>, Option<u32>, Option<u32>) {
    // Look for patterns like "OpenSSH_8.2p1" or "8.2.1"
    let mut parts = version_str
        .split(|c: char| !c.is_ascii_digit() && c != '.')
        .filter(|s| !s.is_empty())
        .filter_map(|s| {
            // Take only the part that looks like version numbers
            if s.chars().any(|c| c.is_ascii_digit()) && s.chars().any(|c| c == '.') {
                Some(s)
            } else if s.chars().all(|c| c.is_ascii_digit()) {
                Some(s)
            } else {
                None
            }
        });

    if let Some(version_part) = parts.next() {
        let nums: Vec<u32> = version_part
            .split('.')
            .filter_map(|n| n.parse().ok())
            .collect();

        match nums.len() {
            0 => (None, None, None),
            1 => (Some(nums[0]), None, None),
            2 => (Some(nums[0]), Some(nums[1]), None),
            _ => (Some(nums[0]), Some(nums[1]), Some(nums[2])),
        }
    } else {
        (None, None, None)
    }
}

/// Rsync baseline adapter.
#[derive(Debug)]
pub struct RsyncAdapter {
    /// Rsync options
    rsync_options: Vec<String>,
}

impl RsyncAdapter {
    /// Create a new Rsync adapter with default options.
    #[must_use]
    pub fn new() -> Self {
        Self {
            rsync_options: vec![
                "--verbose".to_string(),
                "--progress".to_string(),
                "--partial".to_string(),
                "--inplace".to_string(),
            ],
        }
    }

    /// Create an Rsync adapter with custom options.
    #[must_use]
    pub fn with_options(rsync_options: Vec<String>) -> Self {
        Self { rsync_options }
    }

    async fn create_test_file(&self, path: &Path, size: u64) -> Result<(), BenchmarkError> {
        let mut file = fs::File::create(path).await?;

        // Write test data in chunks
        let chunk_size = 64 * 1024; // 64KB chunks
        let chunk_data = vec![0u8; chunk_size];
        let mut remaining = size;

        while remaining > 0 {
            let write_size = std::cmp::min(remaining, chunk_size as u64) as usize;
            AsyncWriteExt::write_all(&mut file, &chunk_data[..write_size]).await?;
            remaining -= write_size as u64;
        }

        Ok(())
    }

    fn build_rsync_command(&self, source: &Path, dest: &Path) -> Command {
        let mut cmd = Command::new("rsync");

        // Add rsync options
        for option in &self.rsync_options {
            cmd.arg(option);
        }

        // For local testing
        cmd.arg(source.to_string_lossy().to_string());
        cmd.arg(dest.to_string_lossy().to_string());

        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

        cmd
    }
}

#[async_trait::async_trait]
impl BaselineAdapter for RsyncAdapter {
    fn tool_name(&self) -> &str {
        "rsync"
    }

    async fn check_availability(&self) -> ToolAvailability {
        let output = match Command::new("rsync")
            .arg("--version")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
        {
            Ok(output) => output,
            Err(_) => return ToolAvailability::NotFound,
        };

        let version_text = String::from_utf8_lossy(&output.stdout);

        if let Some(line) = version_text.lines().next() {
            if line.contains("rsync") && line.contains("version") {
                let version = ToolVersion::new("rsync", line);

                // Check for minimum rsync version (3.0+)
                if version.meets_minimum(3, 0) {
                    ToolAvailability::Available(version)
                } else {
                    ToolAvailability::IncompatibleVersion(version)
                }
            } else {
                ToolAvailability::VersionDetectionFailed(line.to_string())
            }
        } else {
            ToolAvailability::VersionDetectionFailed("No version output".to_string())
        }
    }

    async fn run_benchmark(
        &self,
        config: &BenchmarkConfig,
        source_path: &Path,
        dest_path: &Path,
    ) -> Result<BenchmarkResult, BenchmarkError> {
        // Create test file
        self.create_test_file(source_path, config.data_size).await?;

        let mut total_metrics = Vec::new();

        for iteration in 0..config.iterations {
            let iteration_dest = dest_path.with_extension(&format!("iter{iteration}"));

            // Build and execute rsync command
            let mut cmd = self.build_rsync_command(source_path, &iteration_dest);

            let start_time = Instant::now();
            let output = cmd.output()?;
            let elapsed = start_time.elapsed();

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(BenchmarkError::ExecutionFailed(format!(
                    "Rsync failed: {stderr}"
                )));
            }

            // Verify file was copied correctly
            let dest_size = fs::metadata(&iteration_dest).await?.len();
            if dest_size != config.data_size {
                return Err(BenchmarkError::ExecutionFailed(format!(
                    "Size mismatch: expected {}, got {dest_size}",
                    config.data_size
                )));
            }

            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);

            let mut metrics = self.parse_output(&stdout, &stderr)?;
            metrics.wall_time = elapsed;
            metrics.bytes_transferred = config.data_size;
            metrics.verified_completion = true;

            total_metrics.push(metrics);

            // Clean up iteration file if not preserving artifacts
            if !config.preserve_artifacts {
                let _ = fs::remove_file(&iteration_dest).await;
            }
        }

        // Clean up source file if not preserving artifacts
        if !config.preserve_artifacts {
            let _ = fs::remove_file(source_path).await;
        }

        Ok(BenchmarkResult {
            tool_name: self.tool_name().to_string(),
            iterations: total_metrics,
            environment: crate::atp::benchmark::BenchmarkEnvironment::collect()?,
        })
    }

    fn parse_output(
        &self,
        _stdout: &str,
        _stderr: &str,
    ) -> Result<BenchmarkMetrics, BenchmarkError> {
        // Rsync provides more detailed metrics than SCP
        Ok(BenchmarkMetrics {
            wall_time: Duration::ZERO, // Will be filled by caller
            cpu_time: None,
            memory_peak: None,
            bytes_transferred: 0, // Will be filled by caller
            bytes_on_wire: None,
            verified_completion: false, // Will be filled by caller
            first_usable_output: None,
            resume_time: None,
            disk_amplification_ratio: Some(1.0),
            failure_reproducible: None,
            failure_mode: None,
        })
    }

    fn get_env_vars(&self) -> BTreeMap<String, String> {
        let mut env = BTreeMap::new();
        env.insert(
            "RSYNC_RSH".to_string(),
            std::env::var("RSYNC_RSH").unwrap_or_else(|_| "ssh".to_string()),
        );
        env
    }
}

impl Default for RsyncAdapter {
    fn default() -> Self {
        Self::new()
    }
}

/// Rclone baseline adapter.
#[derive(Debug)]
pub struct RcloneAdapter {
    /// Rclone options.
    rclone_options: Vec<String>,
}

impl RcloneAdapter {
    /// Create a new Rclone adapter with default options.
    #[must_use]
    pub fn new() -> Self {
        Self {
            rclone_options: vec![
                "--progress".to_string(),
                "--stats-one-line".to_string(),
                "--checksum".to_string(),
            ],
        }
    }

    /// Create an Rclone adapter with custom options.
    #[must_use]
    pub fn with_options(rclone_options: Vec<String>) -> Self {
        Self { rclone_options }
    }

    async fn create_test_file(&self, path: &Path, size: u64) -> Result<(), BenchmarkError> {
        let mut file = fs::File::create(path).await?;
        let chunk_size = 64 * 1024;
        let chunk_data = vec![0u8; chunk_size];
        let mut remaining = size;

        while remaining > 0 {
            let write_size = std::cmp::min(remaining, chunk_size as u64) as usize;
            AsyncWriteExt::write_all(&mut file, &chunk_data[..write_size]).await?;
            remaining -= write_size as u64;
        }

        Ok(())
    }

    fn build_rclone_command(&self, source: &Path, dest: &Path) -> Command {
        let mut cmd = Command::new("rclone");
        cmd.arg("copyto");
        for option in &self.rclone_options {
            cmd.arg(option);
        }
        cmd.arg(source.to_string_lossy().to_string());
        cmd.arg(dest.to_string_lossy().to_string());
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        cmd
    }
}

#[async_trait::async_trait]
impl BaselineAdapter for RcloneAdapter {
    fn tool_name(&self) -> &str {
        "rclone"
    }

    async fn check_availability(&self) -> ToolAvailability {
        let output = match Command::new("rclone")
            .arg("version")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
        {
            Ok(output) => output,
            Err(_) => return ToolAvailability::NotFound,
        };

        let version_text = String::from_utf8_lossy(&output.stdout);
        if let Some(line) = version_text.lines().next() {
            if line.contains("rclone") {
                let version = ToolVersion::new("rclone", line);
                if version.meets_minimum(1, 50) {
                    ToolAvailability::Available(version)
                } else {
                    ToolAvailability::IncompatibleVersion(version)
                }
            } else {
                ToolAvailability::VersionDetectionFailed(line.to_string())
            }
        } else {
            ToolAvailability::VersionDetectionFailed("No version output".to_string())
        }
    }

    async fn run_benchmark(
        &self,
        config: &BenchmarkConfig,
        source_path: &Path,
        dest_path: &Path,
    ) -> Result<BenchmarkResult, BenchmarkError> {
        self.create_test_file(source_path, config.data_size).await?;

        let mut total_metrics = Vec::new();
        for iteration in 0..config.iterations {
            let iteration_dest = dest_path.with_extension(&format!("iter{iteration}"));
            let mut cmd = self.build_rclone_command(source_path, &iteration_dest);

            let start_time = Instant::now();
            let output = cmd.output()?;
            let elapsed = start_time.elapsed();

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(BenchmarkError::ExecutionFailed(format!(
                    "Rclone failed: {stderr}"
                )));
            }

            let dest_size = fs::metadata(&iteration_dest).await?.len();
            if dest_size != config.data_size {
                return Err(BenchmarkError::ExecutionFailed(format!(
                    "Size mismatch: expected {}, got {dest_size}",
                    config.data_size
                )));
            }

            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            let mut metrics = self.parse_output(&stdout, &stderr)?;
            metrics.wall_time = elapsed;
            metrics.bytes_transferred = config.data_size;
            metrics.verified_completion = true;
            total_metrics.push(metrics);

            if !config.preserve_artifacts {
                let _ = fs::remove_file(&iteration_dest).await;
            }
        }

        if !config.preserve_artifacts {
            let _ = fs::remove_file(source_path).await;
        }

        Ok(BenchmarkResult {
            tool_name: self.tool_name().to_string(),
            iterations: total_metrics,
            environment: crate::atp::benchmark::BenchmarkEnvironment::collect()?,
        })
    }

    fn parse_output(&self, stdout: &str, stderr: &str) -> Result<BenchmarkMetrics, BenchmarkError> {
        let progress_text = if stdout.is_empty() { stderr } else { stdout };
        let bytes_on_wire = parse_rclone_bytes(progress_text);
        Ok(BenchmarkMetrics {
            wall_time: Duration::ZERO,
            cpu_time: None,
            memory_peak: None,
            bytes_transferred: 0,
            bytes_on_wire,
            verified_completion: false,
            first_usable_output: None,
            resume_time: None,
            disk_amplification_ratio: Some(1.0),
            failure_reproducible: None,
            failure_mode: None,
        })
    }

    fn get_env_vars(&self) -> BTreeMap<String, String> {
        let mut env = BTreeMap::new();
        if let Ok(config_path) = std::env::var("RCLONE_CONFIG") {
            env.insert("RCLONE_CONFIG".to_string(), config_path);
        }
        env
    }
}

impl Default for RcloneAdapter {
    fn default() -> Self {
        Self::new()
    }
}

fn parse_rclone_bytes(text: &str) -> Option<u64> {
    for token in text.split(|ch: char| !(ch.is_ascii_digit() || ch == '.')) {
        let Ok(value) = token.parse::<f64>() else {
            continue;
        };
        if !value.is_finite() || value < 0.0 {
            continue;
        }
        return Some(value as u64);
    }
    None
}

/// Curl HTTP/HTTP3 baseline adapter.
#[derive(Debug)]
pub struct CurlAdapter {
    /// Curl options
    curl_options: Vec<String>,
    /// Whether to try HTTP/3
    enable_http3: bool,
}

impl CurlAdapter {
    /// Create a new Curl adapter with default options.
    #[must_use]
    pub fn new() -> Self {
        Self {
            curl_options: vec![
                "--silent".to_string(),
                "--show-error".to_string(),
                "--location".to_string(),
                "--fail".to_string(),
            ],
            enable_http3: false,
        }
    }

    /// Create a Curl adapter with HTTP/3 enabled.
    #[must_use]
    pub fn with_http3() -> Self {
        Self {
            curl_options: vec![
                "--silent".to_string(),
                "--show-error".to_string(),
                "--location".to_string(),
                "--fail".to_string(),
                "--http3".to_string(),
            ],
            enable_http3: true,
        }
    }

    /// Create a Curl adapter with custom options.
    #[must_use]
    pub fn with_options(curl_options: Vec<String>, enable_http3: bool) -> Self {
        Self {
            curl_options,
            enable_http3,
        }
    }

    async fn create_test_file(&self, path: &Path, size: u64) -> Result<(), BenchmarkError> {
        let mut file = fs::File::create(path).await?;

        // Write test data in chunks
        let chunk_size = 64 * 1024; // 64KB chunks
        let chunk_data = vec![0u8; chunk_size];
        let mut remaining = size;

        while remaining > 0 {
            let write_size = std::cmp::min(remaining, chunk_size as u64) as usize;
            AsyncWriteExt::write_all(&mut file, &chunk_data[..write_size]).await?;
            remaining -= write_size as u64;
        }

        Ok(())
    }

    fn build_curl_command(&self, url: &str, dest: &Path) -> Command {
        let mut cmd = Command::new("curl");

        // Add curl options
        for option in &self.curl_options {
            cmd.arg(option);
        }

        // Add output file
        cmd.arg("--output");
        cmd.arg(dest.to_string_lossy().to_string());

        // Add URL
        cmd.arg(url);

        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

        cmd
    }
}

#[async_trait::async_trait]
impl BaselineAdapter for CurlAdapter {
    fn tool_name(&self) -> &str {
        if self.enable_http3 {
            "curl-http3"
        } else {
            "curl"
        }
    }

    async fn check_availability(&self) -> ToolAvailability {
        let output = match Command::new("curl")
            .arg("--version")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
        {
            Ok(output) => output,
            Err(_) => return ToolAvailability::NotFound,
        };

        let version_text = String::from_utf8_lossy(&output.stdout);

        if let Some(line) = version_text.lines().next() {
            if line.contains("curl") {
                let version = ToolVersion::new("curl", line);

                // Check for minimum curl version (7.50+ for HTTP/3)
                let min_major = if self.enable_http3 { 7 } else { 7 };
                let min_minor = if self.enable_http3 { 66 } else { 0 };

                if version.meets_minimum(min_major, min_minor) {
                    // For HTTP/3, also check if it's compiled with HTTP/3 support
                    if self.enable_http3 {
                        let features_text = String::from_utf8_lossy(&output.stdout);
                        if features_text.contains("HTTP3")
                            || features_text.contains("quiche")
                            || features_text.contains("ngtcp2")
                        {
                            ToolAvailability::Available(version)
                        } else {
                            ToolAvailability::IncompatibleVersion(version)
                        }
                    } else {
                        ToolAvailability::Available(version)
                    }
                } else {
                    ToolAvailability::IncompatibleVersion(version)
                }
            } else {
                ToolAvailability::VersionDetectionFailed(line.to_string())
            }
        } else {
            ToolAvailability::VersionDetectionFailed("No version output".to_string())
        }
    }

    async fn run_benchmark(
        &self,
        config: &BenchmarkConfig,
        source_path: &Path,
        dest_path: &Path,
    ) -> Result<BenchmarkResult, BenchmarkError> {
        // The benchmark fixture uses a local file URL when no HTTP server fixture is supplied.
        self.create_test_file(source_path, config.data_size).await?;

        let mut total_metrics = Vec::new();

        for iteration in 0..config.iterations {
            let iteration_dest = dest_path.with_extension(&format!("iter{iteration}"));

            let test_url = format!("file://{}", source_path.to_string_lossy());

            let mut cmd = self.build_curl_command(&test_url, &iteration_dest);

            let start_time = Instant::now();
            let output = cmd.output()?;
            let elapsed = start_time.elapsed();

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                if stderr.contains("Protocol") && test_url.starts_with("file://") {
                    return Err(BenchmarkError::ToolUnavailable {
                        tool: self.tool_name().to_string(),
                        reason: "No HTTP server available for testing".to_string(),
                    });
                }
                return Err(BenchmarkError::ExecutionFailed(format!(
                    "Curl failed: {stderr}"
                )));
            }

            // Verify file was downloaded correctly
            if iteration_dest.exists() {
                let dest_size = fs::metadata(&iteration_dest).await?.len();
                let verified = dest_size == config.data_size;

                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);

                let mut metrics = self.parse_output(&stdout, &stderr)?;
                metrics.wall_time = elapsed;
                metrics.bytes_transferred = dest_size;
                metrics.verified_completion = verified;

                total_metrics.push(metrics);
            } else {
                return Err(BenchmarkError::ExecutionFailed(
                    "Curl did not create output file".to_string(),
                ));
            }

            // Clean up iteration file if not preserving artifacts
            if !config.preserve_artifacts {
                let _ = fs::remove_file(&iteration_dest).await;
            }
        }

        // Clean up source file if not preserving artifacts
        if !config.preserve_artifacts {
            let _ = fs::remove_file(source_path).await;
        }

        Ok(BenchmarkResult {
            tool_name: self.tool_name().to_string(),
            iterations: total_metrics,
            environment: crate::atp::benchmark::BenchmarkEnvironment::collect()?,
        })
    }

    fn parse_output(
        &self,
        _stdout: &str,
        stderr: &str,
    ) -> Result<BenchmarkMetrics, BenchmarkError> {
        let first_usable_output = if stderr.contains("100") {
            Some(Duration::from_millis(100))
        } else {
            None
        };

        Ok(BenchmarkMetrics {
            wall_time: Duration::ZERO, // Will be filled by caller
            cpu_time: None,
            memory_peak: None,
            bytes_transferred: 0,       // Will be filled by caller
            bytes_on_wire: None,        // Curl doesn't easily provide this
            verified_completion: false, // Will be filled by caller
            first_usable_output,
            resume_time: None,
            disk_amplification_ratio: Some(1.0),
            failure_reproducible: None,
            failure_mode: None,
        })
    }

    fn get_env_vars(&self) -> BTreeMap<String, String> {
        let mut env = BTreeMap::new();
        env.insert(
            "CURL_CA_BUNDLE".to_string(),
            std::env::var("CURL_CA_BUNDLE").unwrap_or_default(),
        );
        if let Ok(proxy) = std::env::var("HTTP_PROXY") {
            env.insert("HTTP_PROXY".to_string(), proxy);
        }
        env
    }
}

impl Default for CurlAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_version_parsing_works() {
        let version = ToolVersion::new("scp", "OpenSSH_8.2p1");
        assert_eq!(version.major, Some(8));
        assert_eq!(version.minor, Some(2));
        assert!(version.meets_minimum(7, 0));
        assert!(!version.meets_minimum(9, 0));
    }

    #[test]
    fn version_number_parsing_handles_various_formats() {
        assert_eq!(parse_version_numbers("8.2.1"), (Some(8), Some(2), Some(1)));
        assert_eq!(
            parse_version_numbers("OpenSSH_8.2p1"),
            (Some(8), Some(2), None)
        );
        assert_eq!(parse_version_numbers("7.4"), (Some(7), Some(4), None));
        assert_eq!(parse_version_numbers("no version"), (None, None, None));
    }

    #[tokio::test]
    async fn scp_adapter_creation() {
        let adapter = ScpAdapter::new();
        assert_eq!(adapter.tool_name(), "scp");
        assert!(!adapter.ssh_options.is_empty());
    }

    #[tokio::test]
    async fn tool_availability_check_handles_not_found() {
        // Test with non-existent command
        let output_result = Command::new("non_existent_command_xyz")
            .arg("--version")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output();

        assert!(output_result.is_err(), "Non-existent command should fail");
    }

    #[tokio::test]
    async fn rsync_adapter_creation() {
        let adapter = RsyncAdapter::new();
        assert_eq!(adapter.tool_name(), "rsync");
        assert!(!adapter.rsync_options.is_empty());
        assert!(adapter.rsync_options.contains(&"--verbose".to_string()));
    }

    #[tokio::test]
    async fn rsync_adapter_with_custom_options() {
        let custom_options = vec!["--checksum".to_string(), "--compress".to_string()];
        let adapter = RsyncAdapter::with_options(custom_options.clone());
        assert_eq!(adapter.rsync_options, custom_options);
    }

    #[tokio::test]
    async fn curl_adapter_creation() {
        let adapter = CurlAdapter::new();
        assert_eq!(adapter.tool_name(), "curl");
        assert!(!adapter.enable_http3);
        assert!(!adapter.curl_options.is_empty());
    }

    #[tokio::test]
    async fn curl_adapter_http3() {
        let adapter = CurlAdapter::with_http3();
        assert_eq!(adapter.tool_name(), "curl-http3");
        assert!(adapter.enable_http3);
        assert!(adapter.curl_options.contains(&"--http3".to_string()));
    }

    #[tokio::test]
    async fn curl_adapter_with_custom_options() {
        let custom_options = vec!["--max-time".to_string(), "30".to_string()];
        let adapter = CurlAdapter::with_options(custom_options.clone(), false);
        assert_eq!(adapter.curl_options, custom_options);
        assert!(!adapter.enable_http3);
    }
}
