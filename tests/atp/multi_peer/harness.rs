//! Multi-peer test harness for scenario execution
//!
//! Provides the infrastructure to execute multi-peer scenarios when the underlying
//! ATP implementations become available.

use crate::atp::multi_peer::contracts::{
    AdversarialContract, CacheContract, MailboxContract, MultiPeerContract, SwarmContract,
};
use crate::atp::multi_peer::*;
use serde_json;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};
use tempfile::TempDir;

/// Multi-peer test harness
pub struct MultiPeerHarness {
    /// Working directory for test artifacts
    work_dir: TempDir,
    /// Timeout for individual scenarios
    default_timeout: Duration,
    /// Whether to preserve artifacts after test
    preserve_artifacts: bool,
}

impl MultiPeerHarness {
    /// Create new test harness
    pub fn new() -> Result<Self, std::io::Error> {
        Ok(Self {
            work_dir: TempDir::new()?,
            default_timeout: Duration::from_secs(300),
            preserve_artifacts: false,
        })
    }

    /// Create harness with custom settings
    pub fn with_settings(
        timeout: Duration,
        preserve_artifacts: bool,
    ) -> Result<Self, std::io::Error> {
        Ok(Self {
            work_dir: TempDir::new()?,
            default_timeout: timeout,
            preserve_artifacts,
        })
    }

    /// Execute a single multi-peer scenario
    pub async fn execute_scenario(
        &self,
        scenario: &MultiPeerScenario,
    ) -> Result<MultiPeerResult, String> {
        // Validate scenario first
        scenario.validate()?;

        // Get appropriate contract for scenario type
        let contract: Box<dyn MultiPeerContract> = match scenario.scenario_type {
            ScenarioType::Mailbox => Box::new(MailboxContract),
            ScenarioType::Swarm => Box::new(SwarmContract),
            ScenarioType::Cache => Box::new(CacheContract),
            ScenarioType::PeerChurn => Box::new(SwarmContract), // Peer churn uses swarm contract
            ScenarioType::Adversarial => Box::new(AdversarialContract),
            ScenarioType::Hybrid(_) => {
                // For hybrid scenarios, use the most restrictive contract
                Box::new(AdversarialContract)
            }
        };

        // Validate with contract
        contract.validate_scenario(scenario)?;

        // Set up test environment
        let scenario_dir = self.create_scenario_workspace(scenario)?;
        let start_time = Instant::now();
        let executed_at = SystemTime::now();

        // Execute the scenario
        let result = match contract.execute_scenario(scenario) {
            Ok(mut result) => {
                // Validate result with contract
                if let Err(validation_error) = contract.validate_result(&result) {
                    result.success = false;
                    result.error = Some(format!("Result validation failed: {}", validation_error));
                }
                result
            }
            Err(execution_error) => {
                // Create failure result
                MultiPeerResult {
                    schema_version: MULTI_PEER_REPORT_SCHEMA.to_string(),
                    scenario: scenario.clone(),
                    executed_at,
                    success: false,
                    error: Some(execution_error),
                    duration: start_time.elapsed(),
                    peer_results: HashMap::new(),
                    network_events: Vec::new(),
                    transfer_metrics: TransferMetrics {
                        total_bytes: 0,
                        verified_bytes: 0,
                        chunks_transferred: 0,
                        repair_blocks_used: 0,
                        peer_rejections: 0,
                        source_selections: Vec::new(),
                    },
                    cache_metrics: HashMap::new(),
                    verification_results: VerificationResults {
                        crypto_verified: false,
                        manifest_verified: false,
                        proof_verified: false,
                        failures: Vec::new(),
                    },
                    artifacts: ArtifactPaths {
                        report: scenario_dir.join("report.json"),
                        logs: scenario_dir.join("logs"),
                        traces: Vec::new(),
                        sources: Vec::new(),
                        destinations: Vec::new(),
                    },
                }
            }
        };

        // Save result artifact
        self.save_result_artifact(&result, &scenario_dir)?;

        Ok(result)
    }

    /// Execute multiple scenarios
    pub async fn execute_scenarios(
        &self,
        scenarios: &[MultiPeerScenario],
    ) -> Vec<Result<MultiPeerResult, String>> {
        let mut results = Vec::new();

        for scenario in scenarios {
            let result = self.execute_scenario(scenario).await;
            results.push(result);
        }

        results
    }

    /// Execute scenarios in parallel (when safe to do so)
    pub async fn execute_scenarios_parallel(
        &self,
        scenarios: &[MultiPeerScenario],
    ) -> Vec<Result<MultiPeerResult, String>> {
        // For now, execute sequentially since we don't have resource isolation
        // This would be enhanced to run truly parallel when the infrastructure supports it
        self.execute_scenarios(scenarios).await
    }

    /// Create workspace directory for scenario execution
    fn create_scenario_workspace(&self, scenario: &MultiPeerScenario) -> Result<PathBuf, String> {
        let scenario_dir = self.work_dir.path().join(&scenario.scenario_id);
        std::fs::create_dir_all(&scenario_dir)
            .map_err(|e| format!("Failed to create scenario directory: {}", e))?;

        // Create subdirectories
        let logs_dir = scenario_dir.join("logs");
        let traces_dir = scenario_dir.join("traces");
        let artifacts_dir = scenario_dir.join("artifacts");

        for dir in [&logs_dir, &traces_dir, &artifacts_dir] {
            std::fs::create_dir_all(dir)
                .map_err(|e| format!("Failed to create subdirectory: {}", e))?;
        }

        // Create peer working directories
        for peer in &scenario.peers {
            let peer_dir = scenario_dir.join(&peer.peer_id);
            std::fs::create_dir_all(&peer_dir)
                .map_err(|e| format!("Failed to create peer directory: {}", e))?;
        }

        Ok(scenario_dir)
    }

    /// Save result artifact to disk
    fn save_result_artifact(
        &self,
        result: &MultiPeerResult,
        scenario_dir: &Path,
    ) -> Result<(), String> {
        let report_path = scenario_dir.join("report.json");
        let json = serde_json::to_string_pretty(result)
            .map_err(|e| format!("Failed to serialize result: {}", e))?;

        std::fs::write(&report_path, json).map_err(|e| format!("Failed to write report: {}", e))?;

        Ok(())
    }

    /// Get working directory path
    pub fn work_dir(&self) -> &Path {
        self.work_dir.path()
    }

    /// Set whether to preserve artifacts
    pub fn set_preserve_artifacts(&mut self, preserve: bool) {
        self.preserve_artifacts = preserve;
    }
}

impl Drop for MultiPeerHarness {
    fn drop(&mut self) {
        if self.preserve_artifacts {
            // Move artifacts to a permanent location
            if let Ok(permanent_dir) = std::env::current_dir().map(|d| d.join("test_artifacts")) {
                let _ = std::fs::create_dir_all(&permanent_dir);
                if let Ok(timestamp) = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
                    let timestamped_dir =
                        permanent_dir.join(format!("multi_peer_{}", timestamp.as_secs()));
                    let _ = std::fs::rename(self.work_dir.path(), timestamped_dir);
                }
            }
        }
    }
}

/// Utilities for scenario execution
pub struct ScenarioExecutor;

impl ScenarioExecutor {
    /// Execute smoke test scenarios
    pub async fn smoke_test() -> Result<Vec<MultiPeerResult>, String> {
        let harness =
            MultiPeerHarness::new().map_err(|e| format!("Failed to create harness: {}", e))?;

        let scenarios = crate::atp::multi_peer::scenarios::AllScenarios::smoke_test();
        let results = harness.execute_scenarios(&scenarios).await;

        // Convert results, propagating any errors
        let mut successful_results = Vec::new();
        let mut errors = Vec::new();

        for result in results {
            match result {
                Ok(result) => successful_results.push(result),
                Err(error) => errors.push(error),
            }
        }

        if !errors.is_empty() {
            return Err(format!("Smoke test failures: {}", errors.join("; ")));
        }

        Ok(successful_results)
    }

    /// Execute all scenarios with filtering
    pub async fn execute_filtered<F>(filter: F) -> Result<Vec<MultiPeerResult>, String>
    where
        F: Fn(&MultiPeerScenario) -> bool,
    {
        let harness =
            MultiPeerHarness::new().map_err(|e| format!("Failed to create harness: {}", e))?;

        let all_scenarios = crate::atp::multi_peer::scenarios::AllScenarios::all();
        let filtered_scenarios: Vec<_> = all_scenarios.into_iter().filter(filter).collect();

        let results = harness.execute_scenarios(&filtered_scenarios).await;

        let mut successful_results = Vec::new();
        let mut errors = Vec::new();

        for result in results {
            match result {
                Ok(result) => successful_results.push(result),
                Err(error) => errors.push(error),
            }
        }

        if !errors.is_empty() {
            return Err(format!("Execution failures: {}", errors.join("; ")));
        }

        Ok(successful_results)
    }

    /// Execute CI-suitable scenarios
    pub async fn ci_test() -> Result<Vec<MultiPeerResult>, String> {
        Self::execute_filtered(|scenario| {
            scenario.timeout <= Duration::from_secs(300)
                && scenario.peers.len() <= 4
                && !matches!(scenario.scenario_type, ScenarioType::Adversarial)
        })
        .await
    }

    /// Execute adversarial scenarios
    pub async fn adversarial_test() -> Result<Vec<MultiPeerResult>, String> {
        Self::execute_filtered(|scenario| {
            matches!(scenario.scenario_type, ScenarioType::Adversarial)
        })
        .await
    }
}

/// Test report generator
pub struct TestReportGenerator;

impl TestReportGenerator {
    /// Generate comprehensive test report
    pub fn generate_report(results: &[MultiPeerResult]) -> TestReport {
        let total_scenarios = results.len();
        let successful = results.iter().filter(|r| r.success).count();
        let failed = total_scenarios - successful;

        let mut by_type = HashMap::new();
        let mut total_duration = Duration::ZERO;
        let mut total_bytes_transferred = 0u64;
        let mut failures = Vec::new();

        for result in results {
            // Count by scenario type
            let type_name = match result.scenario.scenario_type {
                ScenarioType::Mailbox => "Mailbox",
                ScenarioType::Swarm => "Swarm",
                ScenarioType::Cache => "Cache",
                ScenarioType::PeerChurn => "PeerChurn",
                ScenarioType::Adversarial => "Adversarial",
                ScenarioType::Hybrid(_) => "Hybrid",
            };

            let type_stats = by_type.entry(type_name.to_string()).or_insert(TypeStats {
                total: 0,
                successful: 0,
                failed: 0,
            });
            type_stats.total += 1;
            if result.success {
                type_stats.successful += 1;
            } else {
                type_stats.failed += 1;
            }

            total_duration += result.duration;
            total_bytes_transferred += result.transfer_metrics.verified_bytes;

            if !result.success {
                failures.push(TestFailure {
                    scenario_id: result.scenario.scenario_id.clone(),
                    error: result
                        .error
                        .clone()
                        .unwrap_or_else(|| "Unknown error".to_string()),
                    duration: result.duration,
                });
            }
        }

        TestReport {
            generated_at: SystemTime::now(),
            total_scenarios,
            successful,
            failed,
            success_rate: if total_scenarios > 0 {
                successful as f64 / total_scenarios as f64
            } else {
                0.0
            },
            total_duration,
            total_bytes_transferred,
            by_type,
            failures,
        }
    }

    /// Generate summary text report
    pub fn summary_text(report: &TestReport) -> String {
        let mut summary = String::new();

        summary.push_str("Multi-Peer Test Report\n");
        summary.push_str(&format!("Generated: {:?}\n\n", report.generated_at));

        summary.push_str("Overall Results:\n");
        summary.push_str(&format!("  Total Scenarios: {}\n", report.total_scenarios));
        summary.push_str(&format!("  Successful: {}\n", report.successful));
        summary.push_str(&format!("  Failed: {}\n", report.failed));
        summary.push_str(&format!(
            "  Success Rate: {:.1}%\n",
            report.success_rate * 100.0
        ));
        summary.push_str(&format!(
            "  Total Duration: {:.2}s\n",
            report.total_duration.as_secs_f64()
        ));
        summary.push_str(&format!(
            "  Bytes Transferred: {:.2} MB\n\n",
            report.total_bytes_transferred as f64 / (1024.0 * 1024.0)
        ));

        summary.push_str("By Scenario Type:\n");
        for (scenario_type, stats) in &report.by_type {
            summary.push_str(&format!(
                "  {}: {}/{} ({:.1}%)\n",
                scenario_type,
                stats.successful,
                stats.total,
                if stats.total > 0 {
                    stats.successful as f64 / stats.total as f64 * 100.0
                } else {
                    0.0
                }
            ));
        }

        if !report.failures.is_empty() {
            summary.push_str("\nFailures:\n");
            for failure in &report.failures {
                summary.push_str(&format!(
                    "  {}: {} ({:.2}s)\n",
                    failure.scenario_id,
                    failure.error,
                    failure.duration.as_secs_f64()
                ));
            }
        }

        summary
    }
}

/// Test execution report
#[derive(Debug)]
pub struct TestReport {
    pub generated_at: SystemTime,
    pub total_scenarios: usize,
    pub successful: usize,
    pub failed: usize,
    pub success_rate: f64,
    pub total_duration: Duration,
    pub total_bytes_transferred: u64,
    pub by_type: HashMap<String, TypeStats>,
    pub failures: Vec<TestFailure>,
}

/// Statistics by scenario type
#[derive(Debug)]
pub struct TypeStats {
    pub total: usize,
    pub successful: usize,
    pub failed: usize,
}

/// Test failure details
#[derive(Debug)]
pub struct TestFailure {
    pub scenario_id: String,
    pub error: String,
    pub duration: Duration,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atp::multi_peer::scenarios::AllScenarios;

    #[tokio::test]
    async fn test_harness_creation() {
        let harness = MultiPeerHarness::new();
        assert!(harness.is_ok(), "Should create harness successfully");

        let harness = harness.unwrap();
        assert!(harness.work_dir().exists(), "Work directory should exist");
    }

    #[tokio::test]
    async fn test_scenario_execution_placeholder() {
        let harness = MultiPeerHarness::new().unwrap();
        let scenarios = AllScenarios::smoke_test();

        assert!(!scenarios.is_empty(), "Should have smoke test scenarios");

        // Execute one scenario (will fail since ATP features aren't implemented)
        let result = harness.execute_scenario(&scenarios[0]).await;
        assert!(
            result.is_ok(),
            "Should return result even if execution fails"
        );

        let result = result.unwrap();
        assert!(
            !result.success,
            "Should fail since ATP features not implemented"
        );
        assert!(result.error.is_some(), "Should have error message");
    }

    #[test]
    fn test_report_generation() {
        // Create mock results for testing
        let mock_results = vec![
            MultiPeerResult {
                schema_version: MULTI_PEER_REPORT_SCHEMA.to_string(),
                scenario: MultiPeerScenario {
                    scenario_id: "test-success".to_string(),
                    scenario_type: ScenarioType::Swarm,
                    ..Default::default()
                },
                executed_at: SystemTime::now(),
                success: true,
                error: None,
                duration: Duration::from_secs(30),
                peer_results: HashMap::new(),
                network_events: Vec::new(),
                transfer_metrics: TransferMetrics {
                    total_bytes: 1024 * 1024, // 1MB
                    verified_bytes: 1024 * 1024,
                    chunks_transferred: 16,
                    repair_blocks_used: 0,
                    peer_rejections: 0,
                    source_selections: Vec::new(),
                },
                cache_metrics: HashMap::new(),
                verification_results: VerificationResults {
                    crypto_verified: true,
                    manifest_verified: true,
                    proof_verified: true,
                    failures: Vec::new(),
                },
                artifacts: ArtifactPaths {
                    report: PathBuf::from("/tmp/report.json"),
                    logs: PathBuf::from("/tmp/logs"),
                    traces: Vec::new(),
                    sources: Vec::new(),
                    destinations: Vec::new(),
                },
            },
            MultiPeerResult {
                schema_version: MULTI_PEER_REPORT_SCHEMA.to_string(),
                scenario: MultiPeerScenario {
                    scenario_id: "test-failure".to_string(),
                    scenario_type: ScenarioType::Mailbox,
                    ..Default::default()
                },
                executed_at: SystemTime::now(),
                success: false,
                error: Some("Test error".to_string()),
                duration: Duration::from_secs(10),
                peer_results: HashMap::new(),
                network_events: Vec::new(),
                transfer_metrics: TransferMetrics {
                    total_bytes: 0,
                    verified_bytes: 0,
                    chunks_transferred: 0,
                    repair_blocks_used: 0,
                    peer_rejections: 0,
                    source_selections: Vec::new(),
                },
                cache_metrics: HashMap::new(),
                verification_results: VerificationResults {
                    crypto_verified: false,
                    manifest_verified: false,
                    proof_verified: false,
                    failures: Vec::new(),
                },
                artifacts: ArtifactPaths {
                    report: PathBuf::from("/tmp/report.json"),
                    logs: PathBuf::from("/tmp/logs"),
                    traces: Vec::new(),
                    sources: Vec::new(),
                    destinations: Vec::new(),
                },
            },
        ];

        let report = TestReportGenerator::generate_report(&mock_results);

        assert_eq!(report.total_scenarios, 2);
        assert_eq!(report.successful, 1);
        assert_eq!(report.failed, 1);
        assert_eq!(report.success_rate, 0.5);
        assert_eq!(report.failures.len(), 1);
        assert!(report.by_type.contains_key("Swarm"));
        assert!(report.by_type.contains_key("Mailbox"));

        let summary = TestReportGenerator::summary_text(&report);
        assert!(summary.contains("Total Scenarios: 2"));
        assert!(summary.contains("Success Rate: 50.0%"));
    }
}
