//! Benchmark suite orchestration for comprehensive performance testing.

use crate::atp::benchmark::{
    AtpProfile, BaselineAdapter, BenchmarkConfig, BenchmarkError, BenchmarkReport, BenchmarkResult,
};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use tempfile::TempDir;
use tokio::fs;

/// Comprehensive benchmark suite that runs baseline tools and ATP profiles.
#[derive(Debug)]
pub struct BenchmarkSuite {
    /// Suite name for reporting
    pub name: String,
    /// Baseline tool adapters
    baseline_adapters: Vec<Box<dyn BaselineAdapter>>,
    /// ATP profiles to test
    atp_profiles: Vec<AtpProfile>,
    /// Working directory for temporary files
    work_dir: Option<TempDir>,
}

impl BenchmarkSuite {
    /// Create a new benchmark suite.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            baseline_adapters: Vec::new(),
            atp_profiles: Vec::new(),
            work_dir: None,
        }
    }

    /// Add a baseline tool adapter to the suite.
    pub fn add_baseline(&mut self, adapter: Box<dyn BaselineAdapter>) {
        self.baseline_adapters.push(adapter);
    }

    /// Add an ATP profile to the suite.
    pub fn add_atp_profile(&mut self, profile: AtpProfile) {
        self.atp_profiles.push(profile);
    }

    /// Run the complete benchmark suite.
    ///
    /// # Errors
    /// Returns [`BenchmarkError`] if suite execution fails.
    pub async fn run_benchmark(
        &mut self,
        config: &BenchmarkConfig,
    ) -> Result<BenchmarkReport, BenchmarkError> {
        // Set up working directory
        let work_dir = TempDir::new().map_err(|e| BenchmarkError::Io(e))?;
        let source_path = work_dir.path().join("test_source");
        let dest_base = work_dir.path().join("dest");

        fs::create_dir_all(&dest_base).await?;

        // Run baseline tools
        let mut baseline_results = BTreeMap::new();
        for adapter in &self.baseline_adapters {
            match self
                .run_baseline_benchmark(adapter.as_ref(), config, &source_path, &dest_base)
                .await
            {
                Ok(result) => {
                    baseline_results.insert(adapter.tool_name().to_string(), result);
                }
                Err(e) => {
                    // Log error but continue with other tools
                    eprintln!("Baseline {} failed: {}", adapter.tool_name(), e);
                }
            }
        }

        // Run ATP profiles
        let mut atp_results = BTreeMap::new();
        for profile in &self.atp_profiles {
            match self
                .run_atp_benchmark(profile, config, &source_path, &dest_base)
                .await
            {
                Ok(result) => {
                    atp_results.insert(format!("atp-{}", profile.kind.label()), result);
                }
                Err(e) => {
                    // Log error but continue with other profiles
                    eprintln!("ATP profile {} failed: {}", profile.kind.label(), e);
                }
            }
        }

        // Store work directory for potential cleanup
        self.work_dir = Some(work_dir);

        // Generate report
        let report = BenchmarkReport::new(
            baseline_results,
            atp_results,
            config.data_size,
            config.iterations,
        );

        Ok(report)
    }

    /// Run a benchmark with a specific baseline adapter.
    async fn run_baseline_benchmark(
        &self,
        adapter: &dyn BaselineAdapter,
        config: &BenchmarkConfig,
        source_path: &Path,
        dest_base: &Path,
    ) -> Result<BenchmarkResult, BenchmarkError> {
        // Check tool availability first
        let availability = adapter.check_availability().await;
        if !availability.is_usable() {
            return Err(BenchmarkError::ToolUnavailable {
                tool: adapter.tool_name().to_string(),
                reason: format!("Tool availability: {:?}", availability),
            });
        }

        let dest_path = dest_base.join(format!("{}_dest", adapter.tool_name()));

        adapter.run_benchmark(config, source_path, &dest_path).await
    }

    /// Run a benchmark with a specific ATP profile.
    async fn run_atp_benchmark(
        &self,
        profile: &AtpProfile,
        config: &BenchmarkConfig,
        source_path: &Path,
        dest_base: &Path,
    ) -> Result<BenchmarkResult, BenchmarkError> {
        let dest_path = dest_base.join(format!("atp_{}_dest", profile.kind.label()));

        profile.run_benchmark(config, source_path, &dest_path).await
    }

    /// Create a suite with common baseline tools and ATP profiles for smoke testing.
    #[must_use]
    pub fn smoke_test_suite() -> Self {
        let mut suite = Self::new("smoke-test");

        // Add SCP as the primary baseline for smoke testing
        suite.add_baseline(Box::new(crate::atp::benchmark::ScpAdapter::new()));

        // Add key ATP profiles suitable for smoke testing
        suite.add_atp_profile(AtpProfile::clean_lan());
        suite.add_atp_profile(AtpProfile::stream());

        suite
    }

    /// Create a comprehensive suite with all available tools and profiles.
    #[must_use]
    pub fn comprehensive_suite() -> Self {
        let mut suite = Self::new("comprehensive");

        suite.add_baseline(Box::new(crate::atp::benchmark::ScpAdapter::new()));
        suite.add_baseline(Box::new(crate::atp::benchmark::RsyncAdapter::new()));
        suite.add_baseline(Box::new(crate::atp::benchmark::RcloneAdapter::new()));
        suite.add_baseline(Box::new(crate::atp::benchmark::CurlAdapter::new()));

        // Add all ATP profiles
        suite.add_atp_profile(AtpProfile::clean_lan());
        suite.add_atp_profile(AtpProfile::lossy_wifi());
        suite.add_atp_profile(AtpProfile::wan());
        suite.add_atp_profile(AtpProfile::stream());

        suite
    }

    /// Get the current working directory path.
    #[must_use]
    pub fn work_dir_path(&self) -> Option<&Path> {
        self.work_dir.as_ref().map(|d| d.path())
    }

    /// Preserve the working directory (don't auto-clean on drop).
    pub fn preserve_work_dir(&mut self) -> Option<PathBuf> {
        self.work_dir.take().map(|dir| {
            let path = dir.path().to_owned();
            // Prevent automatic cleanup
            std::mem::forget(dir);
            path
        })
    }
}

/// Builder for creating customized benchmark suites.
#[derive(Debug, Default)]
pub struct BenchmarkSuiteBuilder {
    name: String,
    include_scp: bool,
    include_rsync: bool,
    include_rclone: bool,
    include_curl: bool,
    atp_profiles: Vec<AtpProfile>,
}

impl BenchmarkSuiteBuilder {
    /// Create a new suite builder.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            include_scp: false,
            include_rsync: false,
            include_rclone: false,
            include_curl: false,
            atp_profiles: Vec::new(),
        }
    }

    /// Include SCP baseline in the suite.
    #[must_use]
    pub fn with_scp(mut self) -> Self {
        self.include_scp = true;
        self
    }

    /// Include rsync baseline in the suite.
    #[must_use]
    pub fn with_rsync(mut self) -> Self {
        self.include_rsync = true;
        self
    }

    /// Include rclone baseline in the suite.
    #[must_use]
    pub fn with_rclone(mut self) -> Self {
        self.include_rclone = true;
        self
    }

    /// Include curl baseline in the suite.
    #[must_use]
    pub fn with_curl(mut self) -> Self {
        self.include_curl = true;
        self
    }

    /// Add a specific ATP profile.
    #[must_use]
    pub fn with_atp_profile(mut self, profile: AtpProfile) -> Self {
        self.atp_profiles.push(profile);
        self
    }

    /// Add all standard ATP profiles.
    #[must_use]
    pub fn with_all_atp_profiles(mut self) -> Self {
        self.atp_profiles.extend([
            AtpProfile::clean_lan(),
            AtpProfile::lossy_wifi(),
            AtpProfile::wan(),
            AtpProfile::stream(),
        ]);
        self
    }

    /// Build the configured benchmark suite.
    #[must_use]
    pub fn build(self) -> BenchmarkSuite {
        let mut suite = BenchmarkSuite::new(self.name);

        if self.include_scp {
            suite.add_baseline(Box::new(crate::atp::benchmark::ScpAdapter::new()));
        }
        if self.include_rsync {
            suite.add_baseline(Box::new(crate::atp::benchmark::RsyncAdapter::new()));
        }
        if self.include_rclone {
            suite.add_baseline(Box::new(crate::atp::benchmark::RcloneAdapter::new()));
        }
        if self.include_curl {
            suite.add_baseline(Box::new(crate::atp::benchmark::CurlAdapter::new()));
        }

        // Add ATP profiles
        for profile in self.atp_profiles {
            suite.add_atp_profile(profile);
        }

        suite
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn benchmark_suite_creation() {
        let suite = BenchmarkSuite::new("test-suite");
        assert_eq!(suite.name, "test-suite");
        assert!(suite.baseline_adapters.is_empty());
        assert!(suite.atp_profiles.is_empty());
    }

    #[test]
    fn smoke_test_suite_has_basics() {
        let suite = BenchmarkSuite::smoke_test_suite();
        assert_eq!(suite.baseline_adapters.len(), 1);
        assert_eq!(suite.atp_profiles.len(), 2);
    }

    #[test]
    fn comprehensive_suite_has_more_coverage() {
        let suite = BenchmarkSuite::comprehensive_suite();
        assert!(!suite.baseline_adapters.is_empty());
        assert!(!suite.atp_profiles.is_empty());
        assert!(suite.atp_profiles.len() >= 4); // Should have multiple profiles
    }

    #[test]
    fn suite_builder_works() {
        let suite = BenchmarkSuiteBuilder::new("builder-test")
            .with_scp()
            .with_atp_profile(AtpProfile::clean_lan())
            .build();

        assert_eq!(suite.name, "builder-test");
        assert_eq!(suite.baseline_adapters.len(), 1);
        assert_eq!(suite.atp_profiles.len(), 1);
    }

    #[test]
    fn suite_builder_all_atp_profiles() {
        let suite = BenchmarkSuiteBuilder::new("all-atp")
            .with_all_atp_profiles()
            .build();

        assert!(suite.atp_profiles.len() >= 4);
    }
}
