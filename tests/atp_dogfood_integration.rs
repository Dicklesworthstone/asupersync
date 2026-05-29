#![cfg(feature = "cli")]

//! ATP-M2: Integration tests for ATP dogfooding workflows.
//!
//! These tests demonstrate actual ATP usage for real Asupersync artifacts
//! and validate that dogfooding produces proper proof and replay artifacts.

use asupersync::cli::atp_workflows::AtpWorkflowCoordinator;
use asupersync::cli::output::OutputFormat;
use asupersync::cli::{
    AtpArchiveAction, AtpArchiveArgs, AtpArchiveStoreArgs, AtpArchiveVerifyArgs, AtpCiAction,
    AtpCiArgs, AtpCiPushArgs, AtpDatasetAction, AtpDatasetArgs, AtpDatasetSeedArgs, AtpFuzzAction,
    AtpFuzzArgs, AtpFuzzSyncArgs,
};
use asupersync::cx::Cx;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::TempDir;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

static SESSION_COUNTER: AtomicU64 = AtomicU64::new(0);
static CURRENT_DIR_LOCK: Mutex<()> = Mutex::new(());

struct CurrentDirGuard {
    _lock: MutexGuard<'static, ()>,
    original_dir: PathBuf,
}

impl CurrentDirGuard {
    fn enter(path: &Path) -> Result<Self> {
        let lock = CURRENT_DIR_LOCK.lock().expect("current-dir lock poisoned");
        let original_dir = std::env::current_dir()?;
        std::env::set_current_dir(path)?;
        Ok(Self {
            _lock: lock,
            original_dir,
        })
    }
}

impl Drop for CurrentDirGuard {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.original_dir);
    }
}

/// Test configuration for dogfood integration tests.
struct DogfoodTestConfig {
    _temp_dir: TempDir,
    workspace_dir: PathBuf,
    artifacts_dir: PathBuf,
    coordinator: AtpWorkflowCoordinator,
    session_id: String,
}

impl DogfoodTestConfig {
    fn new() -> Result<Self> {
        let temp_dir = TempDir::new()?;
        let workspace_dir = temp_dir.path().join("workspace");
        let artifacts_dir = workspace_dir.join("artifacts");
        fs::create_dir_all(&artifacts_dir)?;

        let coordinator = AtpWorkflowCoordinator::new(OutputFormat::Json)?;

        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let ordinal = SESSION_COUNTER.fetch_add(1, Ordering::Relaxed);
        let session_id = format!("test_{timestamp}_{ordinal}");

        Ok(Self {
            _temp_dir: temp_dir,
            workspace_dir,
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

        artifacts.push(self.create_test_artifact(
            "asupersync.sh",
            "#!/usr/bin/env sh\nprintf 'asupersync dogfood fixture\\n'\n",
        )?);
        artifacts.push(self.create_test_artifact(
            "libasupersync.rlib",
            "deterministic Rust library archive fixture\nmetadata:dogfood\n",
        )?);
        artifacts.push(
            self.create_test_artifact(
                "build_metadata.json",
                &serde_json::json!({
                    "build_epoch_nanos": SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos(),
                    "git_commit": "0123456789abcdef0123456789abcdef01234567",
                    "profile": "release",
                    "target": std::env::consts::ARCH
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

        for i in 0..10 {
            let test_case = format!("http/1.1 request fragment {i}\r\nx-dogfood: {i}\r\n\r\n");
            fs::write(corpus_dir.join(format!("case_{:03}", i)), test_case)?;
        }

        Ok(corpus_dir)
    }

    fn create_proof_bundle(&self) -> Result<PathBuf> {
        let manifest = serde_json::json!({
            "chunks": 5,
            "total_size": 1024,
            "compression": "none",
            "session_id": self.session_id,
        });
        let integrity_hash = format!(
            "sha256:{}",
            self.compute_sha256(manifest.to_string().as_bytes())
        );
        let proof_data = serde_json::json!({
            "proof_version": "1.0",
            "session_id": self.session_id,
            "timestamp_epoch_nanos": SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos(),
            "integrity_hash": integrity_hash,
            "transfer_manifest": manifest,
            "verification_status": "verified"
        });

        self.create_test_artifact("proof_bundle.json", &proof_data.to_string())
    }

    fn workflow_root(&self) -> PathBuf {
        self.workspace_dir.join(".asupersync").join("atp")
    }

    fn read_json(&self, path: impl AsRef<Path>) -> Result<Value> {
        Ok(serde_json::from_slice(&fs::read(path)?)?)
    }

    fn ci_index_entries(&self) -> Result<Vec<Value>> {
        self.read_json_values(self.workflow_root().join("ci").join("index"))
    }

    fn read_json_values(&self, dir: PathBuf) -> Result<Vec<Value>> {
        let mut entries = Vec::new();
        for entry in fs::read_dir(dir)? {
            let path = entry?.path();
            if path.extension().and_then(|ext| ext.to_str()) == Some("json") {
                entries.push(self.read_json(path)?);
            }
        }
        entries.sort_by_key(|value| value["id"].as_str().unwrap_or_default().to_string());
        Ok(entries)
    }

    fn count_regular_files(path: &Path) -> Result<usize> {
        let mut count = 0;
        for entry in fs::read_dir(path)? {
            let path = entry?.path();
            if path.is_dir() {
                count += Self::count_regular_files(&path)?;
            } else if path.is_file() {
                count += 1;
            }
        }
        Ok(count)
    }

    fn dataset_metadata_path(&self, dataset_id: &str, version: &str) -> PathBuf {
        self.workflow_root()
            .join("datasets")
            .join(format!("{dataset_id}-{version}.json"))
    }

    fn archive_metadata_path(&self, archive_id: &str) -> PathBuf {
        self.workflow_root()
            .join("archives")
            .join(archive_id)
            .join("metadata.json")
    }

    fn compute_sha256(&self, bytes: &[u8]) -> String {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(bytes);
        hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn run_dogfood_test<F, Fut>(test_fn: F) -> Result<()>
    where
        F: FnOnce(Cx, DogfoodTestConfig) -> Fut,
        Fut: std::future::Future<Output = Result<()>>,
    {
        asupersync::test_utils::init_test_logging();
        let config = DogfoodTestConfig::new()?;
        let _cwd = CurrentDirGuard::enter(&config.workspace_dir)?;
        test_fn(Cx::for_testing(), config).await
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_dogfood_build_artifacts() -> Result<()> {
        run_dogfood_test(|cx, mut config| async move {
            let artifacts = config.create_build_artifacts()?;
            let build_id = format!("dogfood_build_{}", config.session_id);

            let ci_args = AtpCiArgs {
                action: AtpCiAction::Push(AtpCiPushArgs {
                    paths: artifacts,
                    build_id: build_id.clone(),
                    tags: vec!["dogfood".to_string(), "build".to_string()],
                    retention: "7d".to_string(),
                    compression_level: 6,
                    dedupe: true,
                    scope: Some("dogfood:build".to_string()),
                }),
            };

            config.coordinator.handle_ci_command(&cx, ci_args).await?;

            let entries = config.ci_index_entries()?;
            assert_eq!(entries.len(), 3, "CI push should index every artifact");
            for entry in &entries {
                assert_eq!(entry["build_id"], build_id);
                assert!(entry["size_bytes"].as_u64().unwrap() > 0);
                assert_eq!(entry["tags"], serde_json::json!(["dogfood", "build"]));
                let hash = entry["content_hash"].as_str().unwrap();
                assert_eq!(
                    hash.len(),
                    64,
                    "content hash should be a SHA-256 hex digest"
                );
            }

            Ok(())
        })
        .await
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_dogfood_dataset_seeding() -> Result<()> {
        run_dogfood_test(|cx, mut config| async move {
            let test_results = config.create_test_results()?;
            let dataset_dir = config.artifacts_dir.join("test_dataset");
            fs::create_dir_all(&dataset_dir)?;
            fs::copy(&test_results, dataset_dir.join("results.json"))?;
            let dataset_id = format!("dogfood_test_dataset_{}", config.session_id);

            let dataset_args = AtpDatasetArgs {
                action: AtpDatasetAction::Seed(AtpDatasetSeedArgs {
                    path: dataset_dir,
                    dataset_id: dataset_id.clone(),
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

            config
                .coordinator
                .handle_dataset_command(&cx, dataset_args)
                .await?;

            let metadata = config.read_json(config.dataset_metadata_path(&dataset_id, "v1.0"))?;
            assert_eq!(metadata["id"], dataset_id);
            assert_eq!(metadata["replication_factor"], 2);
            assert_eq!(metadata["file_count"], 1);
            assert_eq!(metadata["metadata"]["session_id"], config.session_id);
            assert_eq!(metadata["metadata"]["dogfood"], true);
            assert!(
                metadata["metadata"]["source_path"]
                    .as_str()
                    .unwrap()
                    .contains("test_dataset")
            );
            assert_eq!(
                metadata["metadata"]["content_hash"].as_str().unwrap().len(),
                64
            );

            Ok(())
        })
        .await
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_dogfood_fuzz_corpus_sync() -> Result<()> {
        run_dogfood_test(|cx, mut config| async move {
            let corpus_dir = config.create_fuzz_corpus()?;
            let target = format!("dogfood_fuzzer_{}", config.session_id);

            let fuzz_args = AtpFuzzArgs {
                action: AtpFuzzAction::Sync(AtpFuzzSyncArgs {
                    corpus_path: corpus_dir,
                    target: target.clone(),
                    strategy: "push".to_string(),
                    exclude: vec![],
                    watch: false,
                }),
            };

            config
                .coordinator
                .handle_fuzz_command(&cx, fuzz_args)
                .await?;

            let corpus_store = config.workflow_root().join("fuzz").join(target);
            assert_eq!(DogfoodTestConfig::count_regular_files(&corpus_store)?, 10);
            let first_case = fs::read_to_string(corpus_store.join("case_000"))?;
            assert!(first_case.contains("http/1.1 request fragment 0"));

            Ok(())
        })
        .await
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_dogfood_proof_bundle_archival() -> Result<()> {
        run_dogfood_test(|cx, mut config| async move {
            let proof_bundle = config.create_proof_bundle()?;
            let archive_id = format!("dogfood_archive_{}", config.session_id);

            let archive_args = AtpArchiveArgs {
                action: AtpArchiveAction::Store(AtpArchiveStoreArgs {
                    bundle_path: proof_bundle,
                    archive_id: Some(archive_id.clone()),
                    retention: Some("30d".to_string()),
                    tier: "cold".to_string(),
                    tags: vec![
                        "proof_bundle".to_string(),
                        config.session_id.clone(),
                        "dogfood_testing".to_string(),
                    ],
                }),
            };

            config
                .coordinator
                .handle_archive_command(&cx, archive_args)
                .await?;

            let metadata = config.read_json(config.archive_metadata_path(&archive_id))?;
            assert_eq!(metadata["id"], archive_id);
            assert_eq!(metadata["tier"], "cold");
            assert_eq!(metadata["tags"][0], "proof_bundle");
            assert_eq!(metadata["tags"][1], config.session_id);
            assert!(metadata["size_bytes"].as_u64().unwrap() > 0);
            assert_eq!(metadata["checksum"].as_str().unwrap().len(), 64);
            assert!(Path::new(metadata["bundle_path"].as_str().unwrap()).exists());

            config
                .coordinator
                .handle_archive_command(
                    &cx,
                    AtpArchiveArgs {
                        action: AtpArchiveAction::Verify(AtpArchiveVerifyArgs {
                            archive_id,
                            deep: true,
                        }),
                    },
                )
                .await?;

            Ok(())
        })
        .await
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_dogfood_failure_handling() -> Result<()> {
        run_dogfood_test(|cx, mut config| async move {
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

            let result = config
                .coordinator
                .handle_ci_command(&cx, invalid_ci_args)
                .await;

            assert!(result.is_err(), "Invalid request should fail");

            let error = result.unwrap_err();
            let error_str = error.to_string();

            assert!(
                error_str.contains("nonexistent")
                    || error_str.contains("path")
                    || error_str.contains("Path"),
                "Error should reference the missing path: {}",
                error_str
            );

            Ok(())
        })
        .await
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_dogfood_end_to_end_workflow() -> Result<()> {
        run_dogfood_test(|cx, mut config| async move {
            let build_artifacts = config.create_build_artifacts()?;
            let build_id = format!("e2e_build_{}", config.session_id);
            let ci_args = AtpCiArgs {
                action: AtpCiAction::Push(AtpCiPushArgs {
                    paths: build_artifacts,
                    build_id: build_id.clone(),
                    tags: vec!["dogfood".to_string(), "e2e".to_string()],
                    retention: "7d".to_string(),
                    compression_level: 6,
                    dedupe: true,
                    scope: Some("dogfood:e2e".to_string()),
                }),
            };

            config.coordinator.handle_ci_command(&cx, ci_args).await?;
            assert_eq!(config.ci_index_entries()?.len(), 3);

            let test_results = config.create_test_results()?;
            let dataset_dir = config.artifacts_dir.join("e2e_dataset");
            fs::create_dir_all(&dataset_dir)?;
            fs::copy(&test_results, dataset_dir.join("test_results.json"))?;
            let dataset_id = format!("e2e_dataset_{}", config.session_id);

            let dataset_args = AtpDatasetArgs {
                action: AtpDatasetAction::Seed(AtpDatasetSeedArgs {
                    path: dataset_dir,
                    dataset_id: dataset_id.clone(),
                    metadata: Some(
                        serde_json::json!({
                            "workflow": "e2e_dogfood",
                            "build_id": build_id
                        })
                        .to_string(),
                    ),
                    chunk_size: Some(32 * 1024),
                    version: Some("1.0".to_string()),
                    replication_factor: 1,
                    access_scope: Some("dogfood:e2e".to_string()),
                }),
            };

            config
                .coordinator
                .handle_dataset_command(&cx, dataset_args)
                .await?;
            let dataset_metadata =
                config.read_json(config.dataset_metadata_path(&dataset_id, "1.0"))?;
            assert_eq!(dataset_metadata["id"], dataset_id);

            let proof_bundle = config.create_proof_bundle()?;
            let archive_id = format!("e2e_archive_{}", config.session_id);
            let archive_args = AtpArchiveArgs {
                action: AtpArchiveAction::Store(AtpArchiveStoreArgs {
                    bundle_path: proof_bundle,
                    archive_id: Some(archive_id.clone()),
                    retention: Some("14d".to_string()),
                    tier: "warm".to_string(),
                    tags: vec![
                        "e2e_dogfood".to_string(),
                        dataset_id.clone(),
                        config.session_id.clone(),
                    ],
                }),
            };

            config
                .coordinator
                .handle_archive_command(&cx, archive_args)
                .await?;
            let archive_metadata = config.read_json(config.archive_metadata_path(&archive_id))?;
            assert_eq!(archive_metadata["tags"][1], dataset_id);
            assert_eq!(archive_metadata["tags"][2], config.session_id);

            Ok(())
        })
        .await
    }
}

/// Integration tests for dogfood script execution.
#[cfg(test)]
mod script_integration_tests {
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
