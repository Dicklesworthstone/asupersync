#![cfg(feature = "cli")]

//! ATP-J5 workflow integration tests.
//!
//! Each test drives `AtpWorkflowCoordinator` against its own state root
//! (`AtpWorkflowCoordinator::with_root`) and checks what the workflow left on disk:
//! a pushed CI artifact can be pulled back, a seeded dataset fetched, a published
//! release installed, a stored proof bundle retrieved, and a minimized corpus is
//! deduplicated. Lookups of things that were never stored fail closed with a
//! specific error type.
//!
//! `ci push` only accepts artifacts below the current directory (`SecurePath`), so
//! every test keeps its files, and its state root, in a temporary directory
//! created there and removed on drop.

use asupersync::atp::cache::trust::TrustPolicy;
use asupersync::cli::output::OutputFormat;
use asupersync::cli::{
    AtpArchiveAction, AtpArchiveArgs, AtpArchiveRetrieveArgs, AtpArchiveStoreArgs, AtpCiAction,
    AtpCiArgs, AtpCiPullArgs, AtpCiPushArgs, AtpDatasetAction, AtpDatasetArgs, AtpDatasetGetArgs,
    AtpDatasetListArgs, AtpDatasetPinArgs, AtpDatasetSeedArgs, AtpDatasetUnpinArgs,
    AtpFuzzAction, AtpFuzzArgs, AtpFuzzMinimizeArgs,
    AtpFuzzSyncArgs, AtpReleaseAction, AtpReleaseArgs, AtpReleaseInstallArgs,
    AtpReleasePublishArgs, AtpWorkflowCoordinator, CliError,
};
use asupersync::test_utils::run_test_with_cx;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

/// A temporary directory below the (canonical) current directory.
fn workdir() -> TempDir {
    let cwd = std::env::current_dir()
        .and_then(|cwd| cwd.canonicalize())
        .expect("current directory");
    TempDir::new_in(cwd).expect("temp dir below the current directory")
}

/// A coordinator whose whole state lives in `dir/atp-state`.
fn coordinator(dir: &TempDir) -> AtpWorkflowCoordinator {
    AtpWorkflowCoordinator::with_root(OutputFormat::Json, dir.path().join("atp-state"))
        .expect("coordinator")
}

fn write(path: &Path, bytes: &[u8]) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create parent directory");
    }
    fs::write(path, bytes).expect("write test file");
}

fn error_type(result: Result<(), CliError>) -> String {
    result.expect_err("expected the workflow to fail closed").error_type
}

fn file_names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .expect("read directory")
        .map(|entry| entry.expect("directory entry").file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

fn seed_args(path: PathBuf, dataset_id: &str, version: Option<&str>) -> AtpDatasetArgs {
    AtpDatasetArgs {
        action: AtpDatasetAction::Seed(AtpDatasetSeedArgs {
            path,
            dataset_id: dataset_id.to_string(),
            metadata: Some(r#"{"type": "ml-training", "format": "csv+json"}"#.to_string()),
            chunk_size: Some(1024 * 1024),
            version: version.map(str::to_string),
            replication_factor: 3,
            access_scope: Some("research:ml".to_string()),
        }),
    }
}

fn get_args(dataset_id: &str, destination: PathBuf, pattern: Option<&str>) -> AtpDatasetArgs {
    AtpDatasetArgs {
        action: AtpDatasetAction::Get(AtpDatasetGetArgs {
            dataset_id: dataset_id.to_string(),
            version: Some("1.0".to_string()),
            destination: Some(destination),
            pattern: pattern.map(str::to_string),
            resume: false,
        }),
    }
}

/// A pushed CI artifact is pulled back byte for byte by its build id.
#[test]
fn ci_push_then_pull_restores_the_artifact() {
    run_test_with_cx(|cx| async move {
        let dir = workdir();
        let artifact = dir.path().join("build-artifact.tar.gz");
        write(&artifact, b"artifact content");
        let mut coordinator = coordinator(&dir);

        coordinator
            .handle_ci_command(
                &cx,
                AtpCiArgs {
                    action: AtpCiAction::Push(AtpCiPushArgs {
                        paths: vec![artifact],
                        build_id: "build-12345".to_string(),
                        tags: vec!["linux".to_string(), "x86_64".to_string()],
                        retention: "30d".to_string(),
                        compression_level: 6,
                        dedupe: true,
                        // The legacy constructor continues to support unscoped content.
                        scope: None,
                    }),
                },
            )
            .await
            .expect("ci push");

        let destination = dir.path().join("pulled");
        coordinator
            .handle_ci_command(
                &cx,
                AtpCiArgs {
                    action: AtpCiAction::Pull(AtpCiPullArgs {
                        build_id: Some("build-12345".to_string()),
                        tags: vec!["linux".to_string()],
                        destination: destination.clone(),
                        if_newer: false,
                        verify: true,
                    }),
                },
            )
            .await
            .expect("ci pull");

        assert_eq!(
            fs::read(destination.join("build-artifact.tar.gz")).expect("pulled artifact"),
            b"artifact content"
        );
    });
}

/// A seeded dataset is fetched into a new directory; a dataset that was never
/// seeded, or a pattern filter (which needs file manifests), fails closed.
#[test]
fn dataset_seed_then_get_copies_the_files() {
    run_test_with_cx(|cx| async move {
        let dir = workdir();
        let dataset = dir.path().join("dataset");
        write(&dataset.join("data1.csv"), b"a,b,c\n1,2,3");
        write(&dataset.join("data2.json"), br#"{"rows": 1}"#);
        let mut coordinator = coordinator(&dir);

        coordinator
            .handle_dataset_command(&cx, seed_args(dataset, "ml-dataset", Some("1.0")))
            .await
            .expect("dataset seed");

        let destination = dir.path().join("fetched");
        coordinator
            .handle_dataset_command(&cx, get_args("ml-dataset", destination.clone(), None))
            .await
            .expect("dataset get");
        assert_eq!(file_names(&destination), ["data1.csv", "data2.json"]);
        assert_eq!(
            fs::read(destination.join("data1.csv")).expect("fetched file"),
            b"a,b,c\n1,2,3"
        );

        coordinator
            .handle_dataset_command(
                &cx,
                AtpDatasetArgs {
                    action: AtpDatasetAction::List(AtpDatasetListArgs {
                        pattern: None,
                        local_only: true,
                        include_metadata: true,
                    }),
                },
            )
            .await
            .expect("dataset list");

        assert_eq!(
            error_type(
                coordinator
                    .handle_dataset_command(
                        &cx,
                        get_args("never-seeded", dir.path().join("none"), None)
                    )
                    .await
            ),
            "not_found"
        );
        assert_eq!(
            error_type(
                coordinator
                    .handle_dataset_command(
                        &cx,
                        get_args("ml-dataset", dir.path().join("filtered"), Some("*.csv"))
                    )
                    .await
            ),
            "unsupported_filter"
        );
    });
}

/// Minimizing a synced corpus keeps one copy of each distinct input.
#[test]
fn fuzz_sync_then_minimize_drops_duplicate_inputs() {
    run_test_with_cx(|cx| async move {
        let dir = workdir();
        let corpus = dir.path().join("corpus");
        write(&corpus.join("case-0"), b"fuzzer input 0");
        write(&corpus.join("case-1"), b"fuzzer input 1");
        write(&corpus.join("case-1-copy"), b"fuzzer input 1");
        let mut coordinator = coordinator(&dir);

        coordinator
            .handle_fuzz_command(
                &cx,
                AtpFuzzArgs {
                    action: AtpFuzzAction::Sync(AtpFuzzSyncArgs {
                        corpus_path: corpus.clone(),
                        target: "parser-fuzzer".to_string(),
                        strategy: "bidirectional".to_string(),
                        exclude: vec!["*.tmp".to_string(), "*.log".to_string()],
                        watch: false,
                    }),
                },
            )
            .await
            .expect("fuzz sync");

        coordinator
            .handle_fuzz_command(
                &cx,
                AtpFuzzArgs {
                    action: AtpFuzzAction::Minimize(AtpFuzzMinimizeArgs {
                        corpus_path: corpus.clone(),
                        target: "parser-fuzzer".to_string(),
                        coverage_threshold: 0.95,
                    }),
                },
            )
            .await
            .expect("fuzz minimize");

        // The minimized corpus sits beside the input, one file per distinct input.
        assert_eq!(file_names(&corpus.with_extension("minimized")).len(), 2);
    });
}

/// A published release installs into a new directory with its content hash
/// verified; installing over an existing directory without `force`, or a
/// release that was never published, fails closed.
#[test]
fn release_publish_then_install_verifies_and_copies() {
    run_test_with_cx(|cx| async move {
        let dir = workdir();
        let release = dir.path().join("release");
        write(&release.join("binary"), b"executable bytes");
        write(&release.join("config.json"), br#"{"version": "1.0.0"}"#);
        let metadata = dir.path().join("release-metadata.json");
        write(
            &metadata,
            br#"{"description": "Test release", "changelog": "Initial version"}"#,
        );
        let mut coordinator = coordinator(&dir);

        coordinator
            .handle_release_command(
                &cx,
                AtpReleaseArgs {
                    action: AtpReleaseAction::Publish(AtpReleasePublishArgs {
                        release_path: release,
                        version: "1.0.0".to_string(),
                        channel: "stable".to_string(),
                        metadata_file: Some(metadata),
                        sign_cert: None,
                        platforms: vec!["linux-x86_64".to_string(), "darwin-arm64".to_string()],
                        min_client_version: Some("0.9.0".to_string()),
                    }),
                },
            )
            .await
            .expect("release publish");

        let install = |release_id: &str, destination: PathBuf| AtpReleaseArgs {
            action: AtpReleaseAction::Install(AtpReleaseInstallArgs {
                release_id: release_id.to_string(),
                version: Some("1.0.0".to_string()),
                destination: Some(destination),
                force: false,
                verify: true,
            }),
        };
        let destination = dir.path().join("installed");
        coordinator
            .handle_release_command(&cx, install("stable-1.0.0", destination.clone()))
            .await
            .expect("release install");
        assert_eq!(file_names(&destination), ["binary", "config.json"]);
        assert_eq!(
            fs::read(destination.join("binary")).expect("installed binary"),
            b"executable bytes"
        );

        assert_eq!(
            error_type(
                coordinator
                    .handle_release_command(&cx, install("stable-1.0.0", destination))
                    .await
            ),
            "file_write_error"
        );
        assert_eq!(
            error_type(
                coordinator
                    .handle_release_command(&cx, install("app-v9.9.9", dir.path().join("none")))
                    .await
            ),
            "not_found"
        );
    });
}

/// A stored proof bundle is retrieved byte for byte; an archive id that was
/// never stored fails closed.
#[test]
fn archive_store_then_retrieve_returns_the_bundle() {
    run_test_with_cx(|cx| async move {
        let dir = workdir();
        let bundle = dir.path().join("proof-bundle.atp");
        write(&bundle, b"ATP proof bundle content");
        let mut coordinator = coordinator(&dir);

        coordinator
            .handle_archive_command(
                &cx,
                AtpArchiveArgs {
                    action: AtpArchiveAction::Store(AtpArchiveStoreArgs {
                        bundle_path: bundle,
                        archive_id: Some("proof-12345".to_string()),
                        retention: Some("1y".to_string()),
                        tier: "warm".to_string(),
                        tags: vec!["transfer".to_string(), "verification".to_string()],
                    }),
                },
            )
            .await
            .expect("archive store");

        let retrieve = |archive_id: &str, destination: PathBuf| AtpArchiveArgs {
            action: AtpArchiveAction::Retrieve(AtpArchiveRetrieveArgs {
                archive_id: archive_id.to_string(),
                destination: Some(destination),
                temporary: false,
            }),
        };
        let destination = dir.path().join("retrieved");
        coordinator
            .handle_archive_command(&cx, retrieve("proof-12345", destination.clone()))
            .await
            .expect("archive retrieve");
        assert_eq!(
            fs::read(destination.join("proof-bundle.atp")).expect("retrieved bundle"),
            b"ATP proof bundle content"
        );

        assert_eq!(
            error_type(
                coordinator
                    .handle_archive_command(&cx, retrieve("never-stored", dir.path().join("none")))
                    .await
            ),
            "not_found"
        );
    });
}

/// Two coordinators with different roots do not see each other's state.
#[test]
fn coordinators_with_different_roots_share_nothing() {
    run_test_with_cx(|cx| async move {
        let dir = workdir();
        let dataset = dir.path().join("dataset");
        write(&dataset.join("data.csv"), b"x");
        let mut first = coordinator(&dir);
        first
            .handle_dataset_command(&cx, seed_args(dataset, "isolated", Some("1.0")))
            .await
            .expect("dataset seed");

        let other = workdir();
        let mut second = coordinator(&other);
        assert_eq!(
            error_type(
                second
                    .handle_dataset_command(&cx, get_args("isolated", other.path().join("out"), None))
                    .await
            ),
            "not_found"
        );
    });
}

/// Workflows carry their capability scope; scoped push and seed succeed.
#[test]
fn capability_scoped_workflows() {
    run_test_with_cx(|cx| async move {
        let dir = workdir();
        let artifact = dir.path().join("scoped-artifact");
        write(&artifact, b"scoped content");
        let state = dir.path().join("atp-state");
        let mut policy = TrustPolicy::local();
        policy.add_authorized_scope("ci:internal-only".to_string());
        policy.add_authorized_scope("research:public".to_string());
        let mut coordinator = AtpWorkflowCoordinator::with_trust_policy(
            OutputFormat::Json,
            &state,
            policy.clone(),
        )
        .expect("explicit scoped coordinator");

        coordinator
            .handle_ci_command(
                &cx,
                AtpCiArgs {
                    action: AtpCiAction::Push(AtpCiPushArgs {
                        paths: vec![artifact],
                        build_id: "scoped-build".to_string(),
                        tags: vec!["restricted".to_string()],
                        retention: "7d".to_string(),
                        compression_level: 3,
                        dedupe: true,
                        scope: Some("ci:internal-only".to_string()),
                    }),
                },
            )
            .await
            .expect("scoped ci push");

        let dataset = dir.path().join("scoped-dataset");
        write(&dataset.join("data.csv"), b"1,2,3");
        coordinator
            .handle_dataset_command(
                &cx,
                AtpDatasetArgs {
                    action: AtpDatasetAction::Seed(AtpDatasetSeedArgs {
                        path: dataset,
                        dataset_id: "scoped-dataset".to_string(),
                        metadata: None,
                        chunk_size: None,
                        version: None,
                        replication_factor: 1,
                        access_scope: Some("research:public".to_string()),
                    }),
                },
            )
            .await
            .expect("scoped dataset seed");

        // A new coordinator has neither in-memory cache populated. Both reads
        // must honor the durable grant and return the actual persisted bytes.
        drop(coordinator);
        let mut reopened =
            AtpWorkflowCoordinator::with_trust_policy(OutputFormat::Json, &state, policy)
                .expect("reopen authorized local state");
        let ci_destination = dir.path().join("scoped-ci-out");
        reopened
            .handle_ci_command(
                &cx,
                AtpCiArgs {
                    action: AtpCiAction::Pull(AtpCiPullArgs {
                        build_id: Some("scoped-build".to_string()),
                        tags: Vec::new(),
                        destination: ci_destination.clone(),
                        if_newer: false,
                        verify: true,
                    }),
                },
            )
            .await
            .expect("authorized disk-backed CI pull");
        assert_eq!(
            fs::read(ci_destination.join("scoped-artifact")).unwrap(),
            b"scoped content"
        );

        reopened
            .handle_dataset_command(
                &cx,
                AtpDatasetArgs {
                    action: AtpDatasetAction::Unpin(AtpDatasetUnpinArgs {
                        dataset_id: "scoped-dataset".to_string(),
                        version: None,
                    }),
                },
            )
            .await
            .expect("authorized unpin");
        reopened
            .handle_dataset_command(
                &cx,
                AtpDatasetArgs {
                    action: AtpDatasetAction::Pin(AtpDatasetPinArgs {
                        dataset_id: "scoped-dataset".to_string(),
                        version: None,
                    }),
                },
            )
            .await
            .expect("authorized pin");
        let index: serde_json::Value = serde_json::from_slice(
            &fs::read(state.join("datasets/scoped-dataset-default.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(index["grant_scope"], "research:public");
        assert_eq!(index["pinned"], true);

        let dataset_destination = dir.path().join("scoped-dataset-out");
        reopened
            .handle_dataset_command(
                &cx,
                AtpDatasetArgs {
                    action: AtpDatasetAction::Get(AtpDatasetGetArgs {
                        dataset_id: "scoped-dataset".to_string(),
                        version: None,
                        destination: Some(dataset_destination.clone()),
                        pattern: None,
                        resume: false,
                    }),
                },
            )
            .await
            .expect("authorized disk-backed dataset get");
        assert_eq!(
            fs::read(dataset_destination.join("data.csv")).unwrap(),
            b"1,2,3"
        );

        // Merely knowing the root and object identifiers grants no access.
        let mut denied = AtpWorkflowCoordinator::with_root(OutputFormat::Json, &state).unwrap();
        let denied_destination = dir.path().join("denied-out");
        assert_eq!(
            error_type(
                denied
                    .handle_ci_command(
                        &cx,
                        AtpCiArgs {
                            action: AtpCiAction::Pull(AtpCiPullArgs {
                                build_id: Some("scoped-build".to_string()),
                                tags: Vec::new(),
                                destination: denied_destination.clone(),
                                if_newer: false,
                                verify: true,
                            }),
                        },
                    )
                    .await
            ),
            "trust_policy_error"
        );
        assert_eq!(
            error_type(
                denied
                    .handle_dataset_command(
                        &cx,
                        AtpDatasetArgs {
                            action: AtpDatasetAction::Get(AtpDatasetGetArgs {
                                dataset_id: "scoped-dataset".to_string(),
                                version: None,
                                destination: Some(denied_destination.clone()),
                                pattern: None,
                                resume: false,
                            }),
                        },
                    )
                    .await
            ),
            "trust_policy_error"
        );
        assert!(!denied_destination.exists());
    });
}

#[test]
fn explicit_workflow_policy_denies_ungranted_operations_before_source_reads() {
    run_test_with_cx(|cx| async move {
        let dir = workdir();
        let state = dir.path().join("explicit-state");
        let mut policy = TrustPolicy::local();
        policy.add_authorized_scope("team:allowed".to_string());
        let mut coordinator =
            AtpWorkflowCoordinator::with_trust_policy(OutputFormat::Json, &state, policy)
                .unwrap();
        let missing = dir.path().join("source-does-not-exist");
        let ci_error = coordinator
            .handle_ci_command(
                &cx,
                AtpCiArgs {
                    action: AtpCiAction::Push(AtpCiPushArgs {
                        paths: vec![missing.clone()],
                        build_id: "denied".to_string(),
                        tags: Vec::new(),
                        retention: "7d".to_string(),
                        compression_level: 1,
                        dedupe: false,
                        scope: Some("team:denied".to_string()),
                    }),
                },
            )
            .await;
        assert_eq!(error_type(ci_error), "trust_policy_error");

        // Omitting the dedicated option cannot bypass the scope in metadata.
        let dataset_error = coordinator
            .handle_dataset_command(
                &cx,
                AtpDatasetArgs {
                    action: AtpDatasetAction::Seed(AtpDatasetSeedArgs {
                        path: missing,
                        dataset_id: "denied".to_string(),
                        metadata: Some(r#"{"access_scope":"team:denied"}"#.to_string()),
                        chunk_size: None,
                        version: None,
                        replication_factor: 1,
                        access_scope: None,
                    }),
                },
            )
            .await;
        assert_eq!(error_type(dataset_error), "trust_policy_error");
        assert!(!state.exists(), "denial must precede every persistent write");
    });
}

#[test]
fn scoped_record_grants_survive_downgrade_and_sanitized_alias_attempts() {
    run_test_with_cx(|cx| async move {
        let dir = workdir();
        let state = dir.path().join("protected-state");
        let source = dir.path().join("artifact");
        write(&source, b"same content for every alias attempt");
        let mut policy = TrustPolicy::local();
        policy.add_authorized_scope("team:allowed".to_string());
        let mut owner =
            AtpWorkflowCoordinator::with_trust_policy(OutputFormat::Json, &state, policy)
                .unwrap();
        let ci_push = |build_id: &str, scope: Option<&str>| AtpCiArgs {
            action: AtpCiAction::Push(AtpCiPushArgs {
                paths: vec![source.clone()],
                build_id: build_id.to_string(),
                tags: Vec::new(),
                retention: "7d".to_string(),
                compression_level: 1,
                dedupe: false,
                scope: scope.map(str::to_owned),
            }),
        };
        let dataset_seed = |dataset_id: &str, scope: Option<&str>| AtpDatasetArgs {
            action: AtpDatasetAction::Seed(AtpDatasetSeedArgs {
                path: source.clone(),
                dataset_id: dataset_id.to_string(),
                metadata: None,
                chunk_size: None,
                version: None,
                replication_factor: 1,
                access_scope: scope.map(str::to_owned),
            }),
        };
        owner
            .handle_ci_command(&cx, ci_push("team/build", Some("team:allowed")))
            .await
            .unwrap();
        owner
            .handle_dataset_command(&cx, dataset_seed("team/data", Some("team:allowed")))
            .await
            .unwrap();

        let ci_index_dir = state.join("ci/index");
        let ci_index = ci_index_dir.join(&file_names(&ci_index_dir)[0]);
        let dataset_index = state.join("datasets/team_data-default.json");
        let before_ci = fs::read(&ci_index).unwrap();
        let before_dataset = fs::read(&dataset_index).unwrap();

        // Even an authorized reader cannot accidentally declassify an existing
        // record by replacing it with a scope-free operation.
        assert_eq!(
            error_type(
                owner
                    .handle_ci_command(&cx, ci_push("team/build", None))
                    .await
            ),
            "trust_policy_error"
        );
        assert_eq!(
            error_type(
                owner
                    .handle_dataset_command(&cx, dataset_seed("team/data", None))
                    .await
            ),
            "trust_policy_error"
        );
        assert_eq!(
            error_type(
                owner
                    .handle_ci_command(&cx, ci_push("team_build", Some("team:allowed")))
                    .await
            ),
            "metadata_error"
        );
        assert_eq!(
            error_type(
                owner
                    .handle_dataset_command(&cx, dataset_seed("team_data", Some("team:allowed")))
                    .await
            ),
            "metadata_error"
        );

        let mut default_reader =
            AtpWorkflowCoordinator::with_root(OutputFormat::Json, &state).unwrap();
        assert_eq!(
            error_type(
                default_reader
                    .handle_ci_command(&cx, ci_push("team/build", None))
                    .await
            ),
            "trust_policy_error"
        );
        assert_eq!(
            error_type(
                default_reader
                    .handle_dataset_command(&cx, dataset_seed("team/data", None))
                    .await
            ),
            "trust_policy_error"
        );
        assert_eq!(fs::read(ci_index).unwrap(), before_ci);
        assert_eq!(fs::read(dataset_index).unwrap(), before_dataset);
        assert_eq!(file_names(&ci_index_dir).len(), 1);
        assert_eq!(file_names(&state.join("datasets")).len(), 1);
    });
}

#[test]
fn explicit_policy_enforces_legacy_dataset_scope_and_seals_it_on_pin() {
    run_test_with_cx(|cx| async move {
        let dir = workdir();
        let state = dir.path().join("atp-state");
        let source = dir.path().join("legacy-source");
        write(&source.join("data.csv"), b"legacy bytes");
        let mut legacy = coordinator(&dir);
        legacy
            .handle_dataset_command(&cx, seed_args(source, "legacy", Some("1.0")))
            .await
            .unwrap();
        let index_path = state.join("datasets/legacy-1.0.json");
        let before: serde_json::Value =
            serde_json::from_slice(&fs::read(&index_path).unwrap()).unwrap();
        assert!(before.get("grant_scope").is_none());

        let mut denied = AtpWorkflowCoordinator::with_trust_policy(
            OutputFormat::Json,
            &state,
            TrustPolicy::local(),
        )
        .unwrap();
        let denied_destination = dir.path().join("denied-legacy");
        assert_eq!(
            error_type(
                denied
                    .handle_dataset_command(
                        &cx,
                        get_args("legacy", denied_destination.clone(), None),
                    )
                    .await
            ),
            "trust_policy_error"
        );
        assert!(!denied_destination.exists());

        let mut policy = TrustPolicy::default();
        policy.add_authorized_scope("research:ml".to_string());
        let mut authorized =
            AtpWorkflowCoordinator::with_trust_policy(OutputFormat::Json, &state, policy)
                .unwrap();
        authorized
            .handle_dataset_command(
                &cx,
                AtpDatasetArgs {
                    action: AtpDatasetAction::Pin(AtpDatasetPinArgs {
                        dataset_id: "legacy".to_string(),
                        version: Some("1.0".to_string()),
                    }),
                },
            )
            .await
            .unwrap();
        let after: serde_json::Value =
            serde_json::from_slice(&fs::read(index_path).unwrap()).unwrap();
        assert_eq!(after["grant_scope"], "research:ml");
        assert_eq!(after["metadata"], before["metadata"]);
        assert_eq!(
            error_type(
                legacy
                    .handle_dataset_command(
                        &cx,
                        get_args("legacy", denied_destination.clone(), None),
                    )
                    .await
            ),
            "trust_policy_error"
        );
        assert!(!denied_destination.exists());
    });
}

/// A push of a path outside the current directory is refused before any read.
#[test]
fn ci_push_refuses_a_path_outside_the_current_directory() {
    run_test_with_cx(|cx| async move {
        let dir = workdir();
        let mut coordinator = coordinator(&dir);
        let result = coordinator
            .handle_ci_command(
                &cx,
                AtpCiArgs {
                    action: AtpCiAction::Push(AtpCiPushArgs {
                        paths: vec![PathBuf::from("/nonexistent/file")],
                        build_id: "error-test".to_string(),
                        tags: Vec::new(),
                        retention: "1d".to_string(),
                        compression_level: 1,
                        dedupe: false,
                        scope: None,
                    }),
                },
            )
            .await;
        assert_eq!(error_type(result), "path_security_error");
    });
}

/// A 10 MiB dataset round-trips intact (large cache entries go to the root's
/// cache directory, not the current directory).
#[test]
fn large_dataset_round_trip() {
    run_test_with_cx(|cx| async move {
        let dir = workdir();
        let dataset = dir.path().join("large");
        let content: Vec<u8> = (0..10 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
        write(&dataset.join("large-data.bin"), &content);
        let mut coordinator = coordinator(&dir);

        coordinator
            .handle_dataset_command(&cx, seed_args(dataset, "large-dataset", Some("1.0")))
            .await
            .expect("large dataset seed");
        let destination = dir.path().join("large-fetched");
        coordinator
            .handle_dataset_command(&cx, get_args("large-dataset", destination.clone(), None))
            .await
            .expect("large dataset get");
        assert!(
            fs::read(destination.join("large-data.bin")).expect("fetched file") == content,
            "the 10 MiB file must round-trip byte for byte"
        );
    });
}

/// CI push, archive and fuzz sync in sequence on one coordinator, then the
/// artifact and the bundle come back out.
#[test]
fn integrated_workflow_pipeline() {
    run_test_with_cx(|cx| async move {
        let dir = workdir();
        let mut coordinator = coordinator(&dir);

        let artifact = dir.path().join("pipeline-artifact");
        write(&artifact, b"pipeline test content");
        coordinator
            .handle_ci_command(
                &cx,
                AtpCiArgs {
                    action: AtpCiAction::Push(AtpCiPushArgs {
                        paths: vec![artifact],
                        build_id: "pipeline-123".to_string(),
                        tags: vec!["integration".to_string()],
                        retention: "1d".to_string(),
                        compression_level: 1,
                        dedupe: false,
                        scope: None,
                    }),
                },
            )
            .await
            .expect("pipeline ci push");

        let proof = dir.path().join("pipeline-proof.atp");
        write(&proof, b"pipeline proof bundle");
        coordinator
            .handle_archive_command(
                &cx,
                AtpArchiveArgs {
                    action: AtpArchiveAction::Store(AtpArchiveStoreArgs {
                        bundle_path: proof,
                        archive_id: Some("pipeline-proof".to_string()),
                        retention: Some("7d".to_string()),
                        tier: "hot".to_string(),
                        tags: vec!["pipeline".to_string(), "integration".to_string()],
                    }),
                },
            )
            .await
            .expect("pipeline archive store");

        let corpus = dir.path().join("pipeline-corpus");
        write(&corpus.join("test1"), b"fuzz input 1");
        coordinator
            .handle_fuzz_command(
                &cx,
                AtpFuzzArgs {
                    action: AtpFuzzAction::Sync(AtpFuzzSyncArgs {
                        corpus_path: corpus,
                        target: "pipeline-fuzzer".to_string(),
                        strategy: "push".to_string(),
                        exclude: Vec::new(),
                        watch: false,
                    }),
                },
            )
            .await
            .expect("pipeline fuzz sync");

        let out = dir.path().join("pipeline-out");
        coordinator
            .handle_ci_command(
                &cx,
                AtpCiArgs {
                    action: AtpCiAction::Pull(AtpCiPullArgs {
                        build_id: Some("pipeline-123".to_string()),
                        tags: Vec::new(),
                        destination: out.clone(),
                        if_newer: false,
                        verify: true,
                    }),
                },
            )
            .await
            .expect("pipeline ci pull");
        coordinator
            .handle_archive_command(
                &cx,
                AtpArchiveArgs {
                    action: AtpArchiveAction::Retrieve(AtpArchiveRetrieveArgs {
                        archive_id: "pipeline-proof".to_string(),
                        destination: Some(out.clone()),
                        temporary: false,
                    }),
                },
            )
            .await
            .expect("pipeline archive retrieve");
        assert_eq!(file_names(&out), ["pipeline-artifact", "pipeline-proof.atp"]);
    });
}
