#![cfg(feature = "cli")]

//! ATP-J5 workflow integration tests.
//!
//! Tests the complete ATP logistics workflows for CI artifacts, datasets,
//! fuzz corpora, release bundles, and proof archives. Covers representative
//! scenarios that demonstrate cache/swarm integration and capability scoping.

use asupersync::cli::output::OutputFormat;
use asupersync::cli::{
    AtpArchiveAction, AtpArchiveArgs, AtpArchiveStoreArgs, AtpCiAction, AtpCiArgs, AtpCiPushArgs,
    AtpDatasetAction, AtpDatasetArgs, AtpDatasetSeedArgs, AtpFuzzAction, AtpFuzzArgs,
    AtpFuzzSyncArgs, AtpReleaseAction, AtpReleaseArgs, AtpReleasePublishArgs,
    AtpWorkflowCoordinator,
};
use asupersync::test_utils::run_test_with_cx;
use std::path::PathBuf;
use tempfile::TempDir;

/// Test CI artifact push workflow with deduplication and caching.
#[test]
fn test_ci_artifact_push_workflow() {
    run_test_with_cx(|cx| async move {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let artifact_path = temp_dir.path().join("build-artifact.tar.gz");
        tokio::fs::write(&artifact_path, b"mock artifact content")
            .await
            .unwrap();

        let mut coordinator = AtpWorkflowCoordinator::new(OutputFormat::Json).unwrap();

        let ci_args = AtpCiArgs {
            action: AtpCiAction::Push(AtpCiPushArgs {
                paths: vec![artifact_path],
                build_id: "build-12345".to_string(),
                tags: vec!["linux".to_string(), "x86_64".to_string()],
                retention: "30d".to_string(),
                compression_level: 6,
                dedupe: true,
                scope: Some("ci:artifacts".to_string()),
            }),
        };

        let result = coordinator.handle_ci_command(&cx, ci_args).await;
        assert!(result.is_ok(), "CI push workflow should succeed");
    });
}

/// Test CI artifact pull workflow with verification.
#[test]
fn test_ci_artifact_pull_workflow() {
    run_test_with_cx(|cx| async move {
        let mut coordinator = AtpWorkflowCoordinator::new(OutputFormat::Json).unwrap();

        let ci_args = AtpCiArgs {
            action: AtpCiAction::Pull(asupersync::cli::AtpCiPullArgs {
                build_id: Some("build-12345".to_string()),
                tags: vec!["linux".to_string()],
                destination: PathBuf::from("/tmp/artifacts"),
                if_newer: true,
                verify: true,
            }),
        };

        let result = coordinator.handle_ci_command(&cx, ci_args).await;
        assert!(result.is_ok(), "CI pull workflow should succeed");
    });
}

/// Test dataset seeding to swarm network.
#[test]
fn test_dataset_seed_workflow() {
    run_test_with_cx(|cx| async move {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let dataset_path = temp_dir.path().to_owned();

        // Create mock dataset files
        tokio::fs::write(
            dataset_path.join("data1.csv"),
            b"mock,dataset,content\n1,2,3",
        )
        .await
        .unwrap();
        tokio::fs::write(dataset_path.join("data2.json"), b"{\"mock\": \"data\"}")
            .await
            .unwrap();

        let mut coordinator = AtpWorkflowCoordinator::new(OutputFormat::Json).unwrap();

        let dataset_args = AtpDatasetArgs {
            action: AtpDatasetAction::Seed(AtpDatasetSeedArgs {
                path: dataset_path,
                dataset_id: "ml-dataset-v1.0".to_string(),
                metadata: Some(r#"{"type": "ml-training", "format": "csv+json"}"#.to_string()),
                chunk_size: Some(1024 * 1024), // 1MB chunks
                version: Some("1.0".to_string()),
                replication_factor: 3,
                access_scope: Some("research:ml".to_string()),
            }),
        };

        let result = coordinator.handle_dataset_command(&cx, dataset_args).await;
        assert!(result.is_ok(), "Dataset seeding workflow should succeed");
    });
}

/// Test dataset retrieval from swarm.
#[test]
fn test_dataset_get_workflow() {
    run_test_with_cx(|cx| async move {
        let mut coordinator = AtpWorkflowCoordinator::new(OutputFormat::Json).unwrap();

        let dataset_args = AtpDatasetArgs {
            action: AtpDatasetAction::Get(asupersync::cli::AtpDatasetGetArgs {
                dataset_id: "ml-dataset-v1.0".to_string(),
                version: Some("1.0".to_string()),
                destination: Some(PathBuf::from("/tmp/datasets")),
                pattern: Some("*.csv".to_string()),
                resume: true,
            }),
        };

        let result = coordinator.handle_dataset_command(&cx, dataset_args).await;
        assert!(result.is_ok(), "Dataset get workflow should succeed");
    });
}

/// Test fuzz corpus synchronization workflow.
#[test]
fn test_fuzz_corpus_sync_workflow() {
    run_test_with_cx(|cx| async move {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let corpus_path = temp_dir.path().to_owned();

        // Create mock corpus files
        for i in 0..10 {
            let test_case = format!("test-case-{}", i);
            tokio::fs::write(corpus_path.join(&test_case), format!("fuzzer input {}", i))
                .await
                .unwrap();
        }

        let mut coordinator = AtpWorkflowCoordinator::new(OutputFormat::Json).unwrap();

        let fuzz_args = AtpFuzzArgs {
            action: AtpFuzzAction::Sync(AtpFuzzSyncArgs {
                corpus_path,
                target: "parser-fuzzer".to_string(),
                strategy: "bidirectional".to_string(),
                exclude: vec!["*.tmp".to_string(), "*.log".to_string()],
                watch: false,
            }),
        };

        let result = coordinator.handle_fuzz_command(&cx, fuzz_args).await;
        assert!(result.is_ok(), "Fuzz corpus sync workflow should succeed");
    });
}

/// Test fuzz corpus minimization workflow.
#[test]
fn test_fuzz_corpus_minimize_workflow() {
    run_test_with_cx(|cx| async move {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let corpus_path = temp_dir.path().to_owned();

        let mut coordinator = AtpWorkflowCoordinator::new(OutputFormat::Json).unwrap();

        let fuzz_args = AtpFuzzArgs {
            action: AtpFuzzAction::Minimize(asupersync::cli::AtpFuzzMinimizeArgs {
                corpus_path,
                target: "parser-fuzzer".to_string(),
                coverage_threshold: 0.95,
            }),
        };

        let result = coordinator.handle_fuzz_command(&cx, fuzz_args).await;
        assert!(result.is_ok(), "Fuzz corpus minimization should succeed");
    });
}

/// Test release bundle publishing workflow.
#[test]
fn test_release_publish_workflow() {
    run_test_with_cx(|cx| async move {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let release_path = temp_dir.path().to_owned();

        // Create mock release files
        tokio::fs::write(release_path.join("binary"), b"mock executable")
            .await
            .unwrap();
        tokio::fs::write(
            release_path.join("config.json"),
            b"{\"version\": \"1.0.0\"}",
        )
        .await
        .unwrap();
        tokio::fs::write(release_path.join("README.md"), b"# Release v1.0.0")
            .await
            .unwrap();

        let metadata_path = temp_dir.path().join("release-metadata.json");
        tokio::fs::write(
            &metadata_path,
            r#"{"description": "Test release", "changelog": "Initial version"}"#,
        )
        .await
        .unwrap();

        let mut coordinator = AtpWorkflowCoordinator::new(OutputFormat::Json).unwrap();

        let release_args = AtpReleaseArgs {
            action: AtpReleaseAction::Publish(AtpReleasePublishArgs {
                release_path,
                version: "1.0.0".to_string(),
                channel: "stable".to_string(),
                metadata_file: Some(metadata_path),
                sign_cert: None,
                platforms: vec!["linux-x86_64".to_string(), "darwin-arm64".to_string()],
                min_client_version: Some("0.9.0".to_string()),
            }),
        };

        let result = coordinator.handle_release_command(&cx, release_args).await;
        assert!(result.is_ok(), "Release publish workflow should succeed");
    });
}

/// Test release installation workflow.
#[test]
fn test_release_install_workflow() {
    run_test_with_cx(|cx| async move {
        let mut coordinator = AtpWorkflowCoordinator::new(OutputFormat::Json).unwrap();

        let release_args = AtpReleaseArgs {
            action: AtpReleaseAction::Install(asupersync::cli::AtpReleaseInstallArgs {
                release_id: "app-v1.0.0".to_string(),
                version: Some("1.0.0".to_string()),
                destination: Some(PathBuf::from("/opt/app")),
                force: false,
                verify: true,
            }),
        };

        let result = coordinator.handle_release_command(&cx, release_args).await;
        assert!(result.is_ok(), "Release install workflow should succeed");
    });
}

/// Test proof bundle archival workflow.
#[test]
fn test_proof_bundle_archive_workflow() {
    run_test_with_cx(|cx| async move {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let bundle_path = temp_dir.path().join("proof-bundle.atp");
        tokio::fs::write(&bundle_path, b"mock ATP proof bundle content")
            .await
            .unwrap();

        let mut coordinator = AtpWorkflowCoordinator::new(OutputFormat::Json).unwrap();

        let archive_args = AtpArchiveArgs {
            action: AtpArchiveAction::Store(AtpArchiveStoreArgs {
                bundle_path,
                archive_id: Some("proof-12345".to_string()),
                retention: Some("1y".to_string()),
                tier: "warm".to_string(),
                tags: vec!["transfer".to_string(), "verification".to_string()],
            }),
        };

        let result = coordinator.handle_archive_command(&cx, archive_args).await;
        assert!(
            result.is_ok(),
            "Proof bundle archive workflow should succeed"
        );
    });
}

/// Test proof bundle retrieval workflow.
#[test]
fn test_proof_bundle_retrieve_workflow() {
    run_test_with_cx(|cx| async move {
        let mut coordinator = AtpWorkflowCoordinator::new(OutputFormat::Json).unwrap();

        let archive_args = AtpArchiveArgs {
            action: AtpArchiveAction::Retrieve(asupersync::cli::AtpArchiveRetrieveArgs {
                archive_id: "proof-12345".to_string(),
                destination: Some(PathBuf::from("/tmp/proofs")),
                temporary: false,
            }),
        };

        let result = coordinator.handle_archive_command(&cx, archive_args).await;
        assert!(
            result.is_ok(),
            "Proof bundle retrieve workflow should succeed"
        );
    });
}

/// Test capability scoping across workflows.
#[test]
fn test_capability_scoped_workflows() {
    run_test_with_cx(|cx| async move {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let artifact_path = temp_dir.path().join("scoped-artifact");
        tokio::fs::write(&artifact_path, b"scoped content")
            .await
            .unwrap();

        let mut coordinator = AtpWorkflowCoordinator::new(OutputFormat::Json).unwrap();

        // Test CI artifact with restricted scope
        let ci_args = AtpCiArgs {
            action: AtpCiAction::Push(AtpCiPushArgs {
                paths: vec![artifact_path.clone()],
                build_id: "scoped-build".to_string(),
                tags: vec!["restricted".to_string()],
                retention: "7d".to_string(),
                compression_level: 3,
                dedupe: true,
                scope: Some("ci:internal-only".to_string()),
            }),
        };

        let result = coordinator.handle_ci_command(&cx, ci_args).await;
        assert!(result.is_ok(), "Scoped CI workflow should succeed");

        // Test dataset with different scope
        let dataset_args = AtpDatasetArgs {
            action: AtpDatasetAction::Seed(AtpDatasetSeedArgs {
                path: temp_dir.path().to_owned(),
                dataset_id: "scoped-dataset".to_string(),
                metadata: None,
                chunk_size: None,
                version: None,
                replication_factor: 1,
                access_scope: Some("research:public".to_string()),
            }),
        };

        let result = coordinator.handle_dataset_command(&cx, dataset_args).await;
        assert!(result.is_ok(), "Scoped dataset workflow should succeed");
    });
}

/// Test workflow error handling and recovery.
#[test]
fn test_workflow_error_handling() {
    run_test_with_cx(|cx| async move {
        let mut coordinator = AtpWorkflowCoordinator::new(OutputFormat::Json).unwrap();

        // Test with invalid file path
        let ci_args = AtpCiArgs {
            action: AtpCiAction::Push(AtpCiPushArgs {
                paths: vec![PathBuf::from("/nonexistent/file")],
                build_id: "error-test".to_string(),
                tags: Vec::new(),
                retention: "1d".to_string(),
                compression_level: 1,
                dedupe: false,
                scope: None,
            }),
        };

        let result = coordinator.handle_ci_command(&cx, ci_args).await;
        assert!(result.is_err(), "Invalid file path should cause error");
    });
}

/// Test workflow performance with large dataset.
#[test]
fn test_large_dataset_workflow() {
    run_test_with_cx(|cx| async move {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let dataset_path = temp_dir.path().to_owned();

        // Create mock large dataset
        let large_file = dataset_path.join("large-data.bin");
        let large_content = vec![0u8; 10 * 1024 * 1024]; // 10MB
        tokio::fs::write(&large_file, &large_content).await.unwrap();

        let mut coordinator = AtpWorkflowCoordinator::new(OutputFormat::Json).unwrap();

        let dataset_args = AtpDatasetArgs {
            action: AtpDatasetAction::Seed(AtpDatasetSeedArgs {
                path: dataset_path,
                dataset_id: "large-dataset".to_string(),
                metadata: Some(r#"{"size": "large", "type": "binary"}"#.to_string()),
                chunk_size: Some(1024 * 1024), // 1MB chunks for large files
                version: Some("1.0".to_string()),
                replication_factor: 2,
                access_scope: Some("perf:test".to_string()),
            }),
        };

        let start_time = std::time::Instant::now();
        let result = coordinator.handle_dataset_command(&cx, dataset_args).await;
        let duration = start_time.elapsed();

        assert!(result.is_ok(), "Large dataset workflow should succeed");
        assert!(
            duration.as_secs() < 30,
            "Large dataset processing should complete in reasonable time"
        );
    });
}

/// Integration test that exercises multiple workflows in sequence.
#[test]
fn test_integrated_workflow_pipeline() {
    run_test_with_cx(|cx| async move {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let mut coordinator = AtpWorkflowCoordinator::new(OutputFormat::Json).unwrap();

        // Step 1: Push CI artifacts
        let artifact_path = temp_dir.path().join("pipeline-artifact");
        tokio::fs::write(&artifact_path, b"pipeline test content")
            .await
            .unwrap();

        let ci_result = coordinator
            .handle_ci_command(
                &cx,
                AtpCiArgs {
                    action: AtpCiAction::Push(AtpCiPushArgs {
                        paths: vec![artifact_path],
                        build_id: "pipeline-123".to_string(),
                        tags: vec!["integration".to_string()],
                        retention: "1d".to_string(),
                        compression_level: 1,
                        dedupe: false,
                        scope: Some("pipeline:test".to_string()),
                    }),
                },
            )
            .await;
        assert!(ci_result.is_ok(), "Pipeline CI step should succeed");

        // Step 2: Archive proof bundle
        let proof_path = temp_dir.path().join("pipeline-proof.atp");
        tokio::fs::write(&proof_path, b"pipeline proof bundle")
            .await
            .unwrap();

        let archive_result = coordinator
            .handle_archive_command(
                &cx,
                AtpArchiveArgs {
                    action: AtpArchiveAction::Store(AtpArchiveStoreArgs {
                        bundle_path: proof_path,
                        archive_id: Some("pipeline-proof".to_string()),
                        retention: Some("7d".to_string()),
                        tier: "hot".to_string(),
                        tags: vec!["pipeline".to_string(), "integration".to_string()],
                    }),
                },
            )
            .await;
        assert!(
            archive_result.is_ok(),
            "Pipeline archive step should succeed"
        );

        // Step 3: Synchronize fuzz corpus
        let corpus_path = temp_dir.path().join("pipeline-corpus");
        tokio::fs::create_dir_all(&corpus_path).await.unwrap();
        tokio::fs::write(corpus_path.join("test1"), b"fuzz input 1")
            .await
            .unwrap();

        let fuzz_result = coordinator
            .handle_fuzz_command(
                &cx,
                AtpFuzzArgs {
                    action: AtpFuzzAction::Sync(AtpFuzzSyncArgs {
                        corpus_path,
                        target: "pipeline-fuzzer".to_string(),
                        strategy: "push".to_string(),
                        exclude: Vec::new(),
                        watch: false,
                    }),
                },
            )
            .await;
        assert!(fuzz_result.is_ok(), "Pipeline fuzz step should succeed");
    });
}
