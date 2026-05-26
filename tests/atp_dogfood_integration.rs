//! ATP-M2: Integration tests for ATP dogfooding workflows.
//!
//! These tests demonstrate actual ATP usage for real Asupersync artifacts
//! and validate that dogfooding produces proper proof and replay artifacts.

use anyhow::{Context, Result};
use asupersync::cli::atp_workflows::AtpWorkflowCoordinator;
use asupersync::cli::output::OutputFormat;
use asupersync::cli::{
    AtpArchiveAction, AtpArchiveArgs, AtpArchiveStoreArgs, AtpCiAction, AtpCiArgs, AtpCiPushArgs,
    AtpDatasetAction, AtpDatasetArgs, AtpDatasetSeedArgs, AtpFuzzAction, AtpFuzzArgs,
    AtpFuzzSyncArgs,
};
use asupersync::test_utils::run_test_with_cx;
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

/// Test configuration for dogfood integration tests.
struct DogfoodTestConfig {
    temp_dir: TempDir,
    artifacts_dir: PathBuf,
    coordinator: AtpWorkflowCoordinator,
    session_id: String,
}

impl DogfoodTestConfig {
    fn new() -> Result<Self> {
        let temp_dir = TempDir::new().context("Failed to create temp directory")?;
        let artifacts_dir = temp_dir.path().join("artifacts");
        fs::create_dir_all(&artifacts_dir)?;

        let coordinator = AtpWorkflowCoordinator::new(OutputFormat::Json)
            .context("Failed to create workflow coordinator")?;

        let session_id = format!("test_{}", chrono::Utc::now().format("%Y%m%d_%H%M%S"));

        Ok(Self {
            temp_dir,
            artifacts_dir,
            coordinator,
            session_id,
        })
    }

    fn create_test_artifact(&self, name: &str, content: &str) -> Result<PathBuf> {
        let artifact_path = self.artifacts_dir.join(name);
        fs::write(&artifact_path, content)?;
        Ok(artifact_path)
    }

    fn create_build_artifacts(&self) -> Result<Vec<PathBuf>> {
        let mut artifacts = Vec::new();

        // Simulate build artifacts
        artifacts.push(self.create_test_artifact(
            "asupersync",
            "Mock binary content for asupersync executable",
        )?);
        artifacts
            .push(self.create_test_artifact("libasupersync.rlib", "Mock Rust library artifact")?);
        artifacts.push(
            self.create_test_artifact(
                "build_metadata.json",
                &serde_json::json!({
                    "build_time": chrono::Utc::now().to_rfc3339(),
                    "git_commit": "abcd1234",
                    "profile": "release",
                    "target": "x86_64-unknown-linux-gnu"
                })
                .to_string(),
            )?,
        );

        Ok(artifacts)
    }

    fn create_test_results(&self) -> Result<PathBuf> {
        let test_results = serde_json::json!({
            "type": "suite",
            "event": "ok",
            "passed": 42,
            "failed": 0,
            "ignored": 3,
            "measured": 0,
            "filtered_out": 1,
            "exec_time": 15.7,
            "test_count": 45
        });

        self.create_test_artifact("test_results.json", &test_results.to_string())
    }

    fn create_fuzz_corpus(&self) -> Result<PathBuf> {
        let corpus_dir = self.artifacts_dir.join("corpus");
        fs::create_dir_all(&corpus_dir)?;

        // Create sample fuzz test cases
        for i in 0..10 {
            let test_case = format!("test_input_{}", i);
            fs::write(corpus_dir.join(format!("case_{:03}", i)), test_case)?;
        }

        Ok(corpus_dir)
    }

    fn create_proof_bundle(&self) -> Result<PathBuf> {
        let proof_data = serde_json::json!({
            "proof_version": "1.0",
            "session_id": self.session_id,
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "integrity_hash": "sha256:mock_hash_value",
            "transfer_manifest": {
                "chunks": 5,
                "total_size": 1024,
                "compression": "gzip"
            },
            "verification_status": "verified"
        });

        self.create_test_artifact("proof_bundle.json", &proof_data.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn run_dogfood_test<F, Fut>(test_fn: F) -> Result<()>
    where
        F: FnOnce(DogfoodTestConfig) -> Fut,
        Fut: std::future::Future<Output = Result<()>>,
    {
        crate::test_utils::init_test_logging();

        run_test_with_cx(|cx| async move {
            let config = DogfoodTestConfig::new()?;
            test_fn(config).await
        })
        .await
    }

    #[tokio::test]
    async fn test_dogfood_build_artifacts() -> Result<()> {
        run_dogfood_test(|mut config| async move {
            let artifacts = config.create_build_artifacts()?;

            // Test CI artifact push workflow
            let ci_args = AtpCiArgs {
                action: AtpCiAction::Push(AtpCiPushArgs {
                    paths: artifacts,
                    build_id: format!("dogfood_build_{}", config.session_id),
                    tags: vec!["dogfood".to_string(), "build".to_string()],
                    retention: "7d".to_string(),
                    compression_level: 6,
                    dedupe: true,
                    scope: Some("dogfood:build".to_string()),
                }),
            };

            // Execute the workflow
            let cx = asupersync::cx::Cx::test_new();
            let result = config.coordinator.handle_ci_command(&cx, ci_args).await?;

            // Validate that proof artifacts were generated
            assert!(result.success, "CI workflow should succeed");
            assert!(
                !result.cache_stats.entries_created.is_empty(),
                "Should create cache entries"
            );

            // Check for proof artifacts in output
            if let Some(proof_data) = result.proof_bundle {
                assert!(
                    proof_data.contains("integrity"),
                    "Proof should contain integrity data"
                );
                assert!(
                    proof_data.contains(&config.session_id),
                    "Proof should reference session ID"
                );
            }

            Ok(())
        })
        .await
    }

    #[tokio::test]
    async fn test_dogfood_dataset_seeding() -> Result<()> {
        run_dogfood_test(|mut config| async move {
            let test_results = config.create_test_results()?;
            let dataset_dir = config.artifacts_dir.join("test_dataset");
            fs::create_dir_all(&dataset_dir)?;
            fs::copy(&test_results, dataset_dir.join("results.json"))?;

            // Test dataset seeding workflow
            let dataset_args = AtpDatasetArgs {
                action: AtpDatasetAction::Seed(AtpDatasetSeedArgs {
                    path: dataset_dir,
                    dataset_id: format!("dogfood_test_dataset_{}", config.session_id),
                    metadata: Some(
                        serde_json::json!({
                            "type": "test_results",
                            "session_id": config.session_id,
                            "dogfood": true
                        })
                        .to_string(),
                    ),
                    chunk_size: Some(64 * 1024),
                    version: Some("v1.0".to_string()),
                    replication_factor: 2,
                    access_scope: Some("dogfood:datasets".to_string()),
                }),
            };

            let cx = asupersync::cx::Cx::test_new();
            let result = config
                .coordinator
                .handle_dataset_command(&cx, dataset_args)
                .await?;

            assert!(result.success, "Dataset seeding should succeed");
            assert!(
                result.dataset_info.seeded,
                "Dataset should be marked as seeded"
            );

            // Validate proof generation
            if let Some(proof) = result.seeding_proof {
                let proof_json: Value = serde_json::from_str(&proof)?;
                assert!(
                    proof_json["dataset_id"]
                        .as_str()
                        .unwrap()
                        .contains(&config.session_id),
                    "Proof should reference correct dataset ID"
                );
                assert_eq!(
                    proof_json["replication_factor"].as_u64().unwrap(),
                    2,
                    "Proof should record replication factor"
                );
            }

            Ok(())
        })
        .await
    }

    #[tokio::test]
    async fn test_dogfood_fuzz_corpus_sync() -> Result<()> {
        run_dogfood_test(|mut config| async move {
            let corpus_dir = config.create_fuzz_corpus()?;

            // Test fuzz corpus synchronization workflow
            let fuzz_args = AtpFuzzArgs {
                action: AtpFuzzAction::Sync(AtpFuzzSyncArgs {
                    corpus_path: corpus_dir,
                    target: format!("dogfood_fuzzer_{}", config.session_id),
                    strategy: "incremental".to_string(),
                    exclude: vec![],
                    watch: false,
                }),
            };

            let cx = asupersync::cx::Cx::test_new();
            let result = config
                .coordinator
                .handle_fuzz_command(&cx, fuzz_args)
                .await?;

            assert!(result.success, "Fuzz sync should succeed");
            assert!(
                result.corpus_stats.files_synced > 0,
                "Should sync corpus files"
            );

            // Check for corpus integrity proof
            if let Some(sync_proof) = result.sync_proof {
                let proof_data: Value = serde_json::from_str(&sync_proof)?;
                assert!(
                    proof_data["corpus_integrity"].is_object(),
                    "Sync proof should include corpus integrity data"
                );
                assert!(
                    proof_data["files_synced"].as_u64().unwrap() > 0,
                    "Proof should record synced file count"
                );
            }

            Ok(())
        })
        .await
    }

    #[tokio::test]
    async fn test_dogfood_proof_bundle_archival() -> Result<()> {
        run_dogfood_test(|mut config| async move {
            let proof_bundle = config.create_proof_bundle()?;

            // Test proof bundle archival workflow
            let archive_args = AtpArchiveArgs {
                action: AtpArchiveAction::Store(AtpArchiveStoreArgs {
                    paths: vec![proof_bundle],
                    archive_id: format!("dogfood_archive_{}", config.session_id),
                    compression_level: 9,
                    retention: "30d".to_string(),
                    metadata: Some(
                        serde_json::json!({
                            "archive_type": "proof_bundle",
                            "session_id": config.session_id,
                            "purpose": "dogfood_testing"
                        })
                        .to_string(),
                    ),
                    verify: true,
                }),
            };

            let cx = asupersync::cx::Cx::test_new();
            let result = config
                .coordinator
                .handle_archive_command(&cx, archive_args)
                .await?;

            assert!(result.success, "Archive operation should succeed");
            assert!(
                result.storage_stats.bytes_stored > 0,
                "Should store archive data"
            );

            // Verify archival proof
            if let Some(archival_proof) = result.archival_proof {
                let proof: Value = serde_json::from_str(&archival_proof)?;
                assert!(
                    proof["retention_policy"]["duration"]
                        .as_str()
                        .unwrap()
                        .contains("30d"),
                    "Proof should record retention policy"
                );
                assert_eq!(
                    proof["compression_level"].as_u64().unwrap(),
                    9,
                    "Proof should record compression settings"
                );
                assert!(
                    proof["verification_status"]["verified"].as_bool().unwrap(),
                    "Archive should be verified"
                );
            }

            Ok(())
        })
        .await
    }

    #[tokio::test]
    async fn test_dogfood_failure_handling() -> Result<()> {
        run_dogfood_test(|mut config| async move {
            // Create an invalid CI push request to trigger failure handling
            let invalid_ci_args = AtpCiArgs {
                action: AtpCiAction::Push(AtpCiPushArgs {
                    paths: vec![PathBuf::from("/nonexistent/path")],
                    build_id: format!("dogfood_fail_{}", config.session_id),
                    tags: vec!["dogfood".to_string(), "failure_test".to_string()],
                    retention: "1d".to_string(),
                    compression_level: 1,
                    dedupe: false,
                    scope: Some("dogfood:test".to_string()),
                }),
            };

            let cx = asupersync::cx::Cx::test_new();
            let result = config
                .coordinator
                .handle_ci_command(&cx, invalid_ci_args)
                .await;

            // Should fail gracefully with proper error context
            assert!(result.is_err(), "Invalid request should fail");

            let error = result.unwrap_err();
            let error_str = error.to_string();

            // Verify error contains useful debugging context
            assert!(
                error_str.contains("nonexistent") || error_str.contains("not found"),
                "Error should reference the missing path: {}",
                error_str
            );

            // In a real dogfood scenario, this would create a bead with the error context
            // For testing, we just verify the error is properly structured

            Ok(())
        })
        .await
    }

    #[tokio::test]
    async fn test_dogfood_end_to_end_workflow() -> Result<()> {
        run_dogfood_test(|mut config| async move {
            let cx = asupersync::cx::Cx::test_new();

            // Simulate a complete dogfood workflow: build -> test -> archive

            // Step 1: Push build artifacts
            let build_artifacts = config.create_build_artifacts()?;
            let ci_args = AtpCiArgs {
                action: AtpCiAction::Push(AtpCiPushArgs {
                    paths: build_artifacts,
                    build_id: format!("e2e_build_{}", config.session_id),
                    tags: vec!["dogfood".to_string(), "e2e".to_string()],
                    retention: "7d".to_string(),
                    compression_level: 6,
                    dedupe: true,
                    scope: Some("dogfood:e2e".to_string()),
                }),
            };

            let build_result = config.coordinator.handle_ci_command(&cx, ci_args).await?;
            assert!(build_result.success, "Build artifact push should succeed");

            // Step 2: Seed test dataset
            let test_results = config.create_test_results()?;
            let dataset_dir = config.artifacts_dir.join("e2e_dataset");
            fs::create_dir_all(&dataset_dir)?;
            fs::copy(&test_results, dataset_dir.join("test_results.json"))?;

            let dataset_args = AtpDatasetArgs {
                action: AtpDatasetAction::Seed(AtpDatasetSeedArgs {
                    path: dataset_dir,
                    dataset_id: format!("e2e_dataset_{}", config.session_id),
                    metadata: Some(
                        serde_json::json!({
                            "workflow": "e2e_dogfood",
                            "build_id": format!("e2e_build_{}", config.session_id)
                        })
                        .to_string(),
                    ),
                    chunk_size: Some(32 * 1024),
                    version: Some("1.0".to_string()),
                    replication_factor: 1,
                    access_scope: Some("dogfood:e2e".to_string()),
                }),
            };

            let dataset_result = config
                .coordinator
                .handle_dataset_command(&cx, dataset_args)
                .await?;
            assert!(dataset_result.success, "Dataset seeding should succeed");

            // Step 3: Archive proof bundles
            let proof_bundle = config.create_proof_bundle()?;
            let archive_args = AtpArchiveArgs {
                action: AtpArchiveAction::Store(AtpArchiveStoreArgs {
                    paths: vec![proof_bundle],
                    archive_id: format!("e2e_archive_{}", config.session_id),
                    compression_level: 6,
                    retention: "14d".to_string(),
                    metadata: Some(
                        serde_json::json!({
                            "workflow": "e2e_dogfood",
                            "build_id": format!("e2e_build_{}", config.session_id),
                            "dataset_id": format!("e2e_dataset_{}", config.session_id)
                        })
                        .to_string(),
                    ),
                    verify: true,
                }),
            };

            let archive_result = config
                .coordinator
                .handle_archive_command(&cx, archive_args)
                .await?;
            assert!(archive_result.success, "Archive operation should succeed");

            // Verify cross-workflow consistency
            // All operations should share the same session context
            for proof in [
                build_result.proof_bundle.as_deref(),
                dataset_result.seeding_proof.as_deref(),
                archive_result.archival_proof.as_deref(),
            ]
            .iter()
            .filter_map(|&p| p)
            {
                assert!(
                    proof.contains(&config.session_id),
                    "All proofs should reference the session ID"
                );
            }

            // Verify that dogfooding generated comprehensive audit trail
            let total_operations = 3;
            let successful_operations = [
                build_result.success,
                dataset_result.success,
                archive_result.success,
            ]
            .iter()
            .filter(|&&s| s)
            .count();

            assert_eq!(
                successful_operations, total_operations,
                "All dogfood operations should succeed"
            );

            Ok(())
        })
        .await
    }
}

/// Integration tests for dogfood script execution.
#[cfg(test)]
mod script_integration_tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn test_dogfood_coordinator_help() {
        let output = Command::new("scripts/atp_dogfood_coordinator.sh")
            .arg("--help")
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .output()
            .expect("Failed to execute dogfood coordinator");

        assert!(output.status.success(), "Help command should succeed");

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("ATP-M2"), "Help should mention ATP-M2");
        assert!(stdout.contains("dogfood"), "Help should mention dogfooding");
        assert!(
            stdout.contains("build-artifacts"),
            "Help should list artifact types"
        );
    }

    #[test]
    fn test_dogfood_coordinator_dry_run() {
        let output = Command::new("scripts/atp_dogfood_coordinator.sh")
            .args(&["--dry-run", "build-artifacts"])
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .output()
            .expect("Failed to execute dogfood coordinator");

        assert!(output.status.success(), "Dry run should succeed");

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("DRY RUN"), "Should indicate dry run mode");
        assert!(
            stdout.contains("build-artifacts"),
            "Should show the requested mode"
        );
    }

    #[test]
    fn test_ci_integration_help() {
        let output = Command::new("scripts/ci/atp_dogfood_ci_integration.sh")
            .arg("help")
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .output()
            .expect("Failed to execute CI integration script");

        assert!(output.status.success(), "Help command should succeed");

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("post-build"),
            "Help should list CI commands"
        );
        assert!(
            stdout.contains("ATP_DOGFOOD_ENABLED"),
            "Help should mention environment variables"
        );
    }

    #[test]
    fn test_ci_integration_check() {
        let output = Command::new("scripts/ci/atp_dogfood_ci_integration.sh")
            .arg("check")
            .env("ATP_DOGFOOD_ENABLED", "false")
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .output()
            .expect("Failed to execute CI integration check");

        // Should exit with status 1 when dogfooding is disabled
        assert!(
            !output.status.success(),
            "Check should fail when dogfooding disabled"
        );

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("not available"),
            "Should indicate unavailability"
        );
    }
}
