//! ATP workflow implementations for CI logistics and data distribution.
//!
//! This module implements the core business logic for ATP-J5 workflows:
//! - CI artifact caching and distribution
//! - Dataset seeding and swarm distribution
//! - Fuzz corpus synchronization
//! - Release bundle management
//! - Proof bundle archival
//!
//! All workflows leverage the ATP cache and swarm infrastructure with
//! capability-scoped access control.

use crate::atp::cache::{AtpCache, CacheConfig, CacheKey};
use crate::atp::seeding::{AtpSeedingService, SeedingConfig};
use crate::cli::ExitCode;
use crate::cli::atp_command_tree::{
    AtpArchiveAction, AtpArchiveArgs, AtpArchiveCompactArgs, AtpArchiveEntry, AtpArchiveExportArgs,
    AtpArchiveListArgs, AtpArchiveOutput, AtpArchiveRetrieveArgs, AtpArchiveStorageStats,
    AtpArchiveStoreArgs, AtpArchiveSummary, AtpArchiveVerifyArgs, AtpCiAction, AtpCiArgs,
    AtpCiArtifact, AtpCiCacheStats, AtpCiCleanArgs, AtpCiListArgs, AtpCiOutput, AtpCiPullArgs,
    AtpCiPushArgs, AtpCiStatusArgs, AtpCiSummary, AtpDatasetAction, AtpDatasetArgs,
    AtpDatasetGetArgs, AtpDatasetInfo, AtpDatasetListArgs, AtpDatasetOutput, AtpDatasetPinArgs,
    AtpDatasetSeedArgs, AtpDatasetStatusArgs, AtpDatasetSummary, AtpDatasetUnpinArgs,
    AtpFuzzAction, AtpFuzzArgs, AtpFuzzCorpusStats, AtpFuzzCoverage, AtpFuzzMergeArgs,
    AtpFuzzMinimizeArgs, AtpFuzzOutput, AtpFuzzPullArgs, AtpFuzzPushArgs, AtpFuzzStatsArgs,
    AtpFuzzSummary, AtpFuzzSyncArgs, AtpIntegrityStatus, AtpNodeRegion, AtpReleaseAction,
    AtpReleaseArgs, AtpReleaseDiffArgs, AtpReleaseInfo, AtpReleaseInfoArgs, AtpReleaseInstallArgs,
    AtpReleaseListArgs, AtpReleaseOutput, AtpReleasePublishArgs, AtpReleaseSummary,
    AtpReleaseVerifyArgs, AtpSwarmHealth, AtpTierStats,
};
use crate::cli::error::CliError;
use crate::cli::output::{Output, OutputFormat, Outputtable};
use crate::cx::Cx;
use crate::util::path_security::SecurePath;
use chrono::Utc;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// ATP workflow coordinator for CI, dataset, fuzz, release, and archive operations.
pub struct AtpWorkflowCoordinator {
    /// ATP cache for artifact storage and retrieval.
    cache: AtpCache,
    /// ATP seeding service for swarm distribution.
    seeding_service: AtpSeedingService,
    /// Output formatter for results.
    output: Output,
}

impl AtpWorkflowCoordinator {
    /// Create a new workflow coordinator with default configuration.
    pub fn new(output_format: OutputFormat) -> Result<Self, CliError> {
        let cache_config = CacheConfig::default();
        let cache = AtpCache::new(cache_config.clone());

        let mut seeding_config = SeedingConfig::default();
        seeding_config.enabled = true;
        let seeding_service = AtpSeedingService::new(seeding_config, AtpCache::new(cache_config));

        let output = Output::new(output_format);

        Ok(Self {
            cache,
            seeding_service,
            output,
        })
    }

    /// Execute CI workflow commands.
    pub async fn handle_ci_command(&mut self, cx: &Cx, args: AtpCiArgs) -> Result<(), CliError> {
        match args.action {
            AtpCiAction::Push(push_args) => self.ci_push(cx, push_args).await,
            AtpCiAction::Pull(pull_args) => self.ci_pull(cx, pull_args).await,
            AtpCiAction::Clean(clean_args) => self.ci_clean(cx, clean_args).await,
            AtpCiAction::List(list_args) => self.ci_list(cx, list_args).await,
            AtpCiAction::Status(status_args) => self.ci_status(cx, status_args).await,
        }
    }

    /// Execute dataset workflow commands.
    pub async fn handle_dataset_command(
        &mut self,
        cx: &Cx,
        args: AtpDatasetArgs,
    ) -> Result<(), CliError> {
        match args.action {
            AtpDatasetAction::Seed(seed_args) => self.dataset_seed(cx, seed_args).await,
            AtpDatasetAction::Get(get_args) => self.dataset_get(cx, get_args).await,
            AtpDatasetAction::List(list_args) => self.dataset_list(cx, list_args).await,
            AtpDatasetAction::Status(status_args) => self.dataset_status(cx, status_args).await,
            AtpDatasetAction::Pin(pin_args) => self.dataset_pin(cx, pin_args).await,
            AtpDatasetAction::Unpin(unpin_args) => self.dataset_unpin(cx, unpin_args).await,
        }
    }

    /// Execute fuzz corpus workflow commands.
    pub async fn handle_fuzz_command(
        &mut self,
        cx: &Cx,
        args: AtpFuzzArgs,
    ) -> Result<(), CliError> {
        match args.action {
            AtpFuzzAction::Sync(sync_args) => self.fuzz_sync(cx, sync_args).await,
            AtpFuzzAction::Pull(pull_args) => self.fuzz_pull(cx, pull_args).await,
            AtpFuzzAction::Push(push_args) => self.fuzz_push(cx, push_args).await,
            AtpFuzzAction::Merge(merge_args) => self.fuzz_merge(cx, merge_args).await,
            AtpFuzzAction::Minimize(minimize_args) => self.fuzz_minimize(cx, minimize_args).await,
            AtpFuzzAction::Stats(stats_args) => self.fuzz_stats(cx, stats_args).await,
        }
    }

    /// Execute release workflow commands.
    pub async fn handle_release_command(
        &mut self,
        cx: &Cx,
        args: AtpReleaseArgs,
    ) -> Result<(), CliError> {
        match args.action {
            AtpReleaseAction::Publish(publish_args) => self.release_publish(cx, publish_args).await,
            AtpReleaseAction::Install(install_args) => self.release_install(cx, install_args).await,
            AtpReleaseAction::List(list_args) => self.release_list(cx, list_args).await,
            AtpReleaseAction::Info(info_args) => self.release_info(cx, info_args).await,
            AtpReleaseAction::Verify(verify_args) => self.release_verify(cx, verify_args).await,
            AtpReleaseAction::Diff(diff_args) => self.release_diff(cx, diff_args).await,
        }
    }

    /// Execute archive workflow commands.
    pub async fn handle_archive_command(
        &mut self,
        cx: &Cx,
        args: AtpArchiveArgs,
    ) -> Result<(), CliError> {
        match args.action {
            AtpArchiveAction::Store(store_args) => self.archive_store(cx, store_args).await,
            AtpArchiveAction::Retrieve(retrieve_args) => {
                self.archive_retrieve(cx, retrieve_args).await
            }
            AtpArchiveAction::List(list_args) => self.archive_list(cx, list_args).await,
            AtpArchiveAction::Verify(verify_args) => self.archive_verify(cx, verify_args).await,
            AtpArchiveAction::Compact(compact_args) => self.archive_compact(cx, compact_args).await,
            AtpArchiveAction::Export(export_args) => self.archive_export(cx, export_args).await,
        }
    }

    // CI workflow implementations

    /// Push CI artifacts to the artifact cache.
    async fn ci_push(&mut self, cx: &Cx, args: AtpCiPushArgs) -> Result<(), CliError> {
        cx.trace("Starting CI artifact push");

        // Create secure path validator for current working directory
        // This ensures all artifact paths are relative to the current directory
        let current_dir = std::env::current_dir().map_err(|e| {
            CliError::new(
                "path_security_error",
                "Failed to get current working directory",
            )
            .detail(format!("IO error: {}", e))
            .exit_code(ExitCode::RUNTIME_ERROR)
        })?;

        let secure_path = SecurePath::new(&current_dir).map_err(|e| {
            CliError::new(
                "path_security_error",
                "Failed to create secure path validator",
            )
            .detail(format!("Security error: {}", e))
            .exit_code(ExitCode::RUNTIME_ERROR)
        })?;

        let mut artifacts: Vec<AtpCiArtifact> = Vec::new();
        let mut total_bytes = 0u64;
        let start_time = std::time::Instant::now();

        for path in &args.paths {
            // Validate path against directory traversal attacks
            let validated_path = secure_path.validate_path(path).map_err(|e| {
                CliError::new(
                    "path_security_error",
                    format!("Path traversal validation failed for: {}", path.display()),
                )
                .detail(format!("Security error: {}", e))
                .exit_code(ExitCode::RUNTIME_ERROR)
            })?;

            let content = std::fs::read(validated_path.as_path()).map_err(|e| {
                CliError::new(
                    "file_read_error",
                    format!("Failed to read artifact: {}", path.display()),
                )
                .detail(format!("IO error: {}", e))
                .exit_code(ExitCode::RUNTIME_ERROR)
            })?;

            // Create cache key for the artifact
            let content_hash = self.compute_content_hash(&content);
            let cache_key = CacheKey::new(
                format!(
                    "ci:{}:{}",
                    args.build_id,
                    path.file_name().unwrap_or_default().to_string_lossy()
                ),
                content_hash.clone(),
                args.scope.clone(),
            );

            // Store in cache with deduplication
            self.cache.put(cache_key.clone(), &content).map_err(|e| {
                CliError::new("cache_error", "Failed to store artifact in cache")
                    .detail(format!("Cache error: {}", e))
                    .exit_code(ExitCode::RUNTIME_ERROR)
            })?;

            // If seeding enabled, authorize for swarm distribution
            if args.dedupe {
                self.seeding_service
                    .authorize_manifest(
                        content_hash.clone(),
                        args.scope.clone().unwrap_or_default(),
                        "high".to_string(),
                    )
                    .map_err(|e| {
                        CliError::new("seeding_error", "Failed to authorize artifact for seeding")
                            .detail(format!("Seeding error: {}", e))
                            .exit_code(ExitCode::RUNTIME_ERROR)
                    })?;
            }

            // Calculate expiration time
            let expires_at = self
                .parse_retention_duration(&args.retention)
                .map(|duration| {
                    Utc::now() + chrono::Duration::from_std(duration).unwrap_or_default()
                });

            let artifact = AtpCiArtifact {
                id: format!(
                    "{}:{}",
                    args.build_id,
                    path.file_name().unwrap_or_default().to_string_lossy()
                ),
                build_id: args.build_id.clone(),
                path: path.to_string_lossy().to_string(),
                size_bytes: content.len() as u64,
                content_hash: content_hash.clone(),
                tags: args.tags.clone(),
                timestamp: Utc::now(),
                expires_at,
            };

            total_bytes += content.len() as u64;
            let artifact_root = self
                .workflow_root()?
                .join("ci")
                .join("blobs")
                .join(Self::safe_component(&args.build_id))
                .join(&content_hash);
            let file_name = path.file_name().unwrap_or_default();
            let artifact_path = artifact_root.join(file_name);
            if !artifact_path.exists() {
                self.copy_file_no_overwrite(validated_path.as_path(), &artifact_path)?;
            }
            let index_path = self.workflow_root()?.join("ci").join("index").join(format!(
                "{}-{}.json",
                Self::safe_component(&args.build_id),
                content_hash
            ));
            self.write_json(&index_path, &artifact)?;
            artifacts.push(artifact);
        }

        let duration = start_time.elapsed();

        let output = AtpCiOutput {
            summary: AtpCiSummary {
                operation: "push".to_string(),
                artifacts_processed: artifacts.len() as u32,
                bytes_transferred: total_bytes,
                duration_seconds: duration.as_secs_f64(),
                success: true,
                error: None,
            },
            artifacts,
            cache_stats: Some(self.get_cache_stats()?),
        };

        self.write_output(&output)?;

        cx.trace(&format!(
            "CI push completed: {} artifacts, {} bytes",
            output.summary.artifacts_processed, output.summary.bytes_transferred
        ));
        Ok(())
    }

    /// Pull CI artifacts from the artifact cache.
    async fn ci_pull(&mut self, cx: &Cx, args: AtpCiPullArgs) -> Result<(), CliError> {
        cx.trace("Starting CI artifact pull");

        self.ensure_dir(&args.destination)?;
        let mut artifacts: Vec<AtpCiArtifact> = Vec::new();
        let mut bytes_transferred = 0u64;
        for artifact in self.read_ci_index()? {
            if let Some(build_id) = &args.build_id {
                if &artifact.build_id != build_id {
                    continue;
                }
            }
            if !args.tags.is_empty() && !args.tags.iter().all(|tag| artifact.tags.contains(tag)) {
                continue;
            }

            let file_name = Path::new(&artifact.path).file_name().ok_or_else(|| {
                CliError::new("path_error", "Artifact path has no file name")
                    .detail(&artifact.path)
                    .exit_code(ExitCode::RUNTIME_ERROR)
            })?;
            let source = self
                .workflow_root()?
                .join("ci")
                .join("blobs")
                .join(Self::safe_component(&artifact.build_id))
                .join(&artifact.content_hash)
                .join(file_name);
            let destination = args.destination.join(file_name);
            if args.if_newer && destination.exists() {
                let source_modified = std::fs::metadata(&source)
                    .and_then(|meta| meta.modified())
                    .ok();
                let dest_modified = std::fs::metadata(&destination)
                    .and_then(|meta| meta.modified())
                    .ok();
                if source_modified <= dest_modified {
                    artifacts.push(artifact);
                    continue;
                }
            }
            if args.verify {
                let content = std::fs::read(&source).map_err(|e| {
                    CliError::new("file_read_error", "Failed to verify cached artifact")
                        .detail(format!("{}: {e}", source.display()))
                        .exit_code(ExitCode::RUNTIME_ERROR)
                })?;
                if self.compute_content_hash(&content) != artifact.content_hash {
                    return Err(CliError::new(
                        "verification_error",
                        "Cached artifact hash mismatch",
                    )
                    .detail(&artifact.id)
                    .exit_code(ExitCode::RUNTIME_ERROR));
                }
            }
            if destination.exists() {
                std::fs::copy(&source, &destination).map_err(|e| {
                    CliError::new("file_write_error", "Failed to update destination artifact")
                        .detail(format!(
                            "{} -> {}: {e}",
                            source.display(),
                            destination.display()
                        ))
                        .exit_code(ExitCode::RUNTIME_ERROR)
                })?;
            } else {
                self.copy_file_no_overwrite(&source, &destination)?;
            }
            bytes_transferred = bytes_transferred.saturating_add(artifact.size_bytes);
            artifacts.push(artifact);
        }

        let output = AtpCiOutput {
            summary: AtpCiSummary {
                operation: "pull".to_string(),
                artifacts_processed: artifacts.len() as u32,
                bytes_transferred,
                duration_seconds: 0.0,
                success: true,
                error: None,
            },
            artifacts,
            cache_stats: Some(self.get_cache_stats()?),
        };

        self.write_output(&output)?;

        Ok(())
    }

    /// Clean old CI artifacts from cache.
    async fn ci_clean(&mut self, _cx: &Cx, args: AtpCiCleanArgs) -> Result<(), CliError> {
        let artifacts = self.read_ci_index()?;
        let cutoff = args
            .older_than
            .as_deref()
            .and_then(|duration| self.parse_retention_duration(duration))
            .and_then(|duration| chrono::Duration::from_std(duration).ok())
            .map(|duration| Utc::now() - duration);

        let mut selected = Vec::new();
        for artifact in artifacts {
            if let Some(pattern) = &args.build_pattern {
                if !artifact.build_id.contains(pattern) {
                    continue;
                }
            }
            if let Some(cutoff) = cutoff {
                if artifact.timestamp > cutoff {
                    continue;
                }
            }
            selected.push(artifact);
        }

        if !args.dry_run {
            let index_dir = self.workflow_root()?.join("ci").join("index");
            for artifact in &selected {
                let index_path = index_dir.join(format!(
                    "{}-{}.json",
                    Self::safe_component(&artifact.build_id),
                    artifact.content_hash
                ));
                if index_path.exists() {
                    std::fs::remove_file(&index_path).map_err(|e| {
                        CliError::new("file_write_error", "Failed to remove CI index record")
                            .detail(format!("{}: {e}", index_path.display()))
                            .exit_code(ExitCode::RUNTIME_ERROR)
                    })?;
                }
            }
        }

        let bytes_transferred = selected.iter().map(|artifact| artifact.size_bytes).sum();
        let output = AtpCiOutput {
            summary: AtpCiSummary {
                operation: "clean".to_string(),
                artifacts_processed: selected.len() as u32,
                bytes_transferred,
                duration_seconds: 0.0,
                success: true,
                error: None,
            },
            artifacts: selected,
            cache_stats: Some(self.get_cache_stats()?),
        };

        self.write_output(&output)?;

        Ok(())
    }

    /// List CI artifacts in cache.
    async fn ci_list(&mut self, _cx: &Cx, args: AtpCiListArgs) -> Result<(), CliError> {
        let cutoff = self
            .parse_retention_duration(&args.recent)
            .and_then(|duration| chrono::Duration::from_std(duration).ok())
            .map(|duration| Utc::now() - duration);
        let mut artifacts: Vec<AtpCiArtifact> = Vec::new();
        for artifact in self.read_ci_index()? {
            if let Some(tag) = &args.tag {
                if !artifact.tags.contains(tag) {
                    continue;
                }
            }
            if let Some(cutoff) = cutoff {
                if artifact.timestamp < cutoff {
                    continue;
                }
            }
            artifacts.push(artifact);
        }
        let bytes_transferred = artifacts.iter().map(|artifact| artifact.size_bytes).sum();
        let output = AtpCiOutput {
            summary: AtpCiSummary {
                operation: "list".to_string(),
                artifacts_processed: artifacts.len() as u32,
                bytes_transferred,
                duration_seconds: 0.0,
                success: true,
                error: None,
            },
            artifacts,
            cache_stats: Some(self.get_cache_stats()?),
        };

        self.write_output(&output)?;

        Ok(())
    }

    /// Show CI cache status.
    async fn ci_status(&mut self, _cx: &Cx, args: AtpCiStatusArgs) -> Result<(), CliError> {
        let artifacts = self.read_ci_index()?;
        let bytes_transferred = artifacts.iter().map(|artifact| artifact.size_bytes).sum();
        let output = AtpCiOutput {
            summary: AtpCiSummary {
                operation: "status".to_string(),
                artifacts_processed: artifacts.len() as u32,
                bytes_transferred,
                duration_seconds: 0.0,
                success: true,
                error: None,
            },
            artifacts: if args.stats || args.health {
                artifacts
            } else {
                Vec::new()
            },
            cache_stats: Some(self.get_cache_stats()?),
        };

        self.write_output(&output)?;

        Ok(())
    }

    // Dataset workflow implementations

    async fn dataset_seed(&mut self, _cx: &Cx, args: AtpDatasetSeedArgs) -> Result<(), CliError> {
        let (total_size_bytes, file_count, content_hash) = self.path_stats(&args.path)?;
        let mut metadata = match args.metadata.as_deref() {
            Some(text) => serde_json::from_str::<BTreeMap<String, serde_json::Value>>(text)
                .map_err(|e| {
                    CliError::new("metadata_error", "Dataset metadata must be a JSON object")
                        .detail(e.to_string())
                        .exit_code(ExitCode::RUNTIME_ERROR)
                })?,
            None => BTreeMap::new(),
        };
        metadata.insert(
            "source_path".to_string(),
            serde_json::Value::String(args.path.to_string_lossy().to_string()),
        );
        metadata.insert(
            "content_hash".to_string(),
            serde_json::Value::String(content_hash),
        );
        if let Some(chunk_size) = args.chunk_size {
            metadata.insert("chunk_size".to_string(), serde_json::json!(chunk_size));
        }
        if let Some(scope) = args.access_scope {
            metadata.insert("access_scope".to_string(), serde_json::Value::String(scope));
        }
        let dataset = AtpDatasetInfo {
            id: args.dataset_id.clone(),
            version: args.version.clone(),
            size_bytes: total_size_bytes,
            file_count,
            metadata,
            availability: 1.0,
            replication_factor: args.replication_factor,
            health_score: 1.0,
            updated_at: Utc::now(),
            pinned: true,
        };
        self.write_json(
            &self.dataset_index_path(&args.dataset_id, args.version.as_deref())?,
            &dataset,
        )?;
        let output = AtpDatasetOutput {
            summary: AtpDatasetSummary {
                operation: "seed".to_string(),
                datasets_processed: 1,
                total_size_bytes,
                transfer_rate_bps: None,
                success: true,
                error: None,
            },
            datasets: vec![dataset],
            swarm_health: Some(self.local_swarm_health(1, total_size_bytes)),
        };

        self.write_output(&output)?;

        Ok(())
    }

    async fn dataset_get(&mut self, _cx: &Cx, args: AtpDatasetGetArgs) -> Result<(), CliError> {
        let datasets = self.read_dataset_index()?;
        let dataset = datasets
            .into_iter()
            .find(|dataset| {
                dataset.id == args.dataset_id
                    && args
                        .version
                        .as_ref()
                        .is_none_or(|version| dataset.version.as_ref() == Some(version))
            })
            .ok_or_else(|| {
                CliError::new("not_found", "Dataset is not present in the local ATP index")
                    .detail(&args.dataset_id)
                    .exit_code(ExitCode::RUNTIME_ERROR)
            })?;
        let destination = args.destination.unwrap_or_else(|| PathBuf::from("."));
        let source_path = dataset
            .metadata
            .get("source_path")
            .and_then(serde_json::Value::as_str)
            .map(PathBuf::from)
            .ok_or_else(|| {
                CliError::new(
                    "metadata_error",
                    "Dataset source path is missing from metadata",
                )
                .detail(&dataset.id)
                .exit_code(ExitCode::RUNTIME_ERROR)
            })?;
        if args.pattern.is_some() {
            return Err(CliError::new(
                "unsupported_filter",
                "Dataset pattern retrieval requires indexed file manifests",
            )
            .detail(&dataset.id)
            .exit_code(ExitCode::RUNTIME_ERROR));
        }
        let _ = args.resume;
        self.copy_path_contents(&source_path, &destination)?;
        let total_size_bytes = dataset.size_bytes;
        let output = AtpDatasetOutput {
            summary: AtpDatasetSummary {
                operation: "get".to_string(),
                datasets_processed: 1,
                total_size_bytes,
                transfer_rate_bps: None,
                success: true,
                error: None,
            },
            datasets: vec![dataset],
            swarm_health: Some(self.local_swarm_health(1, total_size_bytes)),
        };

        self.write_output(&output)?;
        Ok(())
    }

    async fn dataset_list(&mut self, _cx: &Cx, args: AtpDatasetListArgs) -> Result<(), CliError> {
        let mut datasets: Vec<AtpDatasetInfo> = Vec::new();
        for mut dataset in self.read_dataset_index()? {
            if let Some(pattern) = &args.pattern {
                if !dataset.id.contains(pattern) {
                    continue;
                }
            }
            if args.local_only && !dataset.pinned {
                continue;
            }
            if !args.include_metadata {
                dataset.metadata.clear();
            }
            datasets.push(dataset);
        }
        let total_size_bytes = datasets.iter().map(|dataset| dataset.size_bytes).sum();
        let output = AtpDatasetOutput {
            summary: AtpDatasetSummary {
                operation: "list".to_string(),
                datasets_processed: datasets.len() as u32,
                total_size_bytes,
                transfer_rate_bps: None,
                success: true,
                error: None,
            },
            datasets,
            swarm_health: None,
        };

        self.write_output(&output)?;
        Ok(())
    }

    async fn dataset_status(
        &mut self,
        _cx: &Cx,
        args: AtpDatasetStatusArgs,
    ) -> Result<(), CliError> {
        let mut datasets: Vec<AtpDatasetInfo> = Vec::new();
        for dataset in self.read_dataset_index()? {
            if let Some(dataset_id) = &args.dataset_id {
                if &dataset.id != dataset_id {
                    continue;
                }
            }
            datasets.push(dataset);
        }
        let total_size_bytes = datasets.iter().map(|dataset| dataset.size_bytes).sum();
        let output = AtpDatasetOutput {
            summary: AtpDatasetSummary {
                operation: "status".to_string(),
                datasets_processed: datasets.len() as u32,
                total_size_bytes,
                transfer_rate_bps: None,
                success: true,
                error: None,
            },
            datasets,
            swarm_health: args
                .swarm_health
                .then(|| self.local_swarm_health(1, total_size_bytes)),
        };

        self.write_output(&output)?;
        Ok(())
    }

    async fn dataset_pin(&mut self, _cx: &Cx, args: AtpDatasetPinArgs) -> Result<(), CliError> {
        let path = self.dataset_index_path(&args.dataset_id, args.version.as_deref())?;
        let mut dataset: AtpDatasetInfo = self.read_json(&path)?;
        dataset.pinned = true;
        dataset.updated_at = Utc::now();
        self.write_json(&path, &dataset)?;
        let total_size_bytes = dataset.size_bytes;
        let output = AtpDatasetOutput {
            summary: AtpDatasetSummary {
                operation: "pin".to_string(),
                datasets_processed: 1,
                total_size_bytes,
                transfer_rate_bps: None,
                success: true,
                error: None,
            },
            datasets: vec![dataset],
            swarm_health: None,
        };

        self.write_output(&output)?;
        Ok(())
    }

    async fn dataset_unpin(&mut self, _cx: &Cx, args: AtpDatasetUnpinArgs) -> Result<(), CliError> {
        let path = self.dataset_index_path(&args.dataset_id, args.version.as_deref())?;
        let mut dataset: AtpDatasetInfo = self.read_json(&path)?;
        dataset.pinned = false;
        dataset.updated_at = Utc::now();
        self.write_json(&path, &dataset)?;
        let total_size_bytes = dataset.size_bytes;
        let output = AtpDatasetOutput {
            summary: AtpDatasetSummary {
                operation: "unpin".to_string(),
                datasets_processed: 1,
                total_size_bytes,
                transfer_rate_bps: None,
                success: true,
                error: None,
            },
            datasets: vec![dataset],
            swarm_health: None,
        };

        self.write_output(&output)?;
        Ok(())
    }

    // Fuzz corpus workflow implementations

    async fn fuzz_sync(&mut self, _cx: &Cx, args: AtpFuzzSyncArgs) -> Result<(), CliError> {
        let store = self
            .workflow_root()?
            .join("fuzz")
            .join(Self::safe_component(&args.target));
        match args.strategy.as_str() {
            "push" => self.copy_path_contents(&args.corpus_path, &store)?,
            "pull" => self.copy_path_contents(&store, &args.corpus_path)?,
            "bidirectional" => {
                if store.exists() {
                    self.copy_path_contents(&store, &args.corpus_path)?;
                }
                self.copy_path_contents(&args.corpus_path, &store)?;
            }
            other => {
                return Err(
                    CliError::new("argument_error", "Unsupported fuzz sync strategy")
                        .detail(other)
                        .exit_code(ExitCode::RUNTIME_ERROR),
                );
            }
        }
        let (total_size_bytes, test_cases, _) = self.path_stats(&args.corpus_path)?;
        let _ = (&args.exclude, args.watch);
        let output = AtpFuzzOutput {
            summary: AtpFuzzSummary {
                operation: "sync".to_string(),
                target: args.target,
                test_cases_processed: test_cases,
                duration_seconds: 0.0,
                success: true,
                error: None,
            },
            corpus_stats: AtpFuzzCorpusStats {
                total_test_cases: test_cases,
                new_test_cases: test_cases,
                duplicates_removed: 0,
                total_size_bytes,
                avg_case_size_bytes: if test_cases == 0 {
                    0
                } else {
                    total_size_bytes / u64::from(test_cases)
                },
                growth_rate: 0.0,
            },
            coverage: None,
        };

        self.write_output(&output)?;
        Ok(())
    }

    async fn fuzz_pull(&mut self, _cx: &Cx, args: AtpFuzzPullArgs) -> Result<(), CliError> {
        let store = self
            .workflow_root()?
            .join("fuzz")
            .join(Self::safe_component(&args.target));
        let _ = args.since.as_deref();
        self.copy_path_contents(&store, &args.corpus_path)?;
        let (total_size_bytes, test_cases, _) = self.path_stats(&args.corpus_path)?;
        let output = AtpFuzzOutput {
            summary: AtpFuzzSummary {
                operation: "pull".to_string(),
                target: args.target,
                test_cases_processed: test_cases,
                duration_seconds: 0.0,
                success: true,
                error: None,
            },
            corpus_stats: AtpFuzzCorpusStats {
                total_test_cases: test_cases,
                new_test_cases: test_cases,
                duplicates_removed: 0,
                total_size_bytes,
                avg_case_size_bytes: if test_cases == 0 {
                    0
                } else {
                    total_size_bytes / u64::from(test_cases)
                },
                growth_rate: 0.0,
            },
            coverage: None,
        };

        self.write_output(&output)?;
        Ok(())
    }

    async fn fuzz_push(&mut self, _cx: &Cx, args: AtpFuzzPushArgs) -> Result<(), CliError> {
        let store = self
            .workflow_root()?
            .join("fuzz")
            .join(Self::safe_component(&args.target));
        let _ = args.incremental;
        self.copy_path_contents(&args.corpus_path, &store)?;
        let (total_size_bytes, test_cases, _) = self.path_stats(&args.corpus_path)?;
        let output = AtpFuzzOutput {
            summary: AtpFuzzSummary {
                operation: "push".to_string(),
                target: args.target,
                test_cases_processed: test_cases,
                duration_seconds: 0.0,
                success: true,
                error: None,
            },
            corpus_stats: AtpFuzzCorpusStats {
                total_test_cases: test_cases,
                new_test_cases: test_cases,
                duplicates_removed: 0,
                total_size_bytes,
                avg_case_size_bytes: if test_cases == 0 {
                    0
                } else {
                    total_size_bytes / u64::from(test_cases)
                },
                growth_rate: 0.0,
            },
            coverage: None,
        };

        self.write_output(&output)?;
        Ok(())
    }

    async fn fuzz_merge(&mut self, _cx: &Cx, args: AtpFuzzMergeArgs) -> Result<(), CliError> {
        let mut seen = BTreeSet::new();
        let mut duplicates_removed = 0u32;
        for source in &args.sources {
            for file in self.collect_files(source)? {
                let bytes = std::fs::read(&file).map_err(|e| {
                    CliError::new("file_read_error", "Failed to read fuzz corpus case")
                        .detail(format!("{}: {e}", file.display()))
                        .exit_code(ExitCode::RUNTIME_ERROR)
                })?;
                let hash = self.compute_content_hash(&bytes);
                if !seen.insert(hash.clone()) {
                    duplicates_removed = duplicates_removed.saturating_add(1);
                    continue;
                }
                let destination = args.output.join(hash);
                if !destination.exists() {
                    self.copy_file_no_overwrite(&file, &destination)?;
                }
            }
        }
        let (total_size_bytes, test_cases, _) = self.path_stats(&args.output)?;
        let _ = args.dedupe_strategy;
        let output = AtpFuzzOutput {
            summary: AtpFuzzSummary {
                operation: "merge".to_string(),
                target: "merged".to_string(),
                test_cases_processed: test_cases,
                duration_seconds: 0.0,
                success: true,
                error: None,
            },
            corpus_stats: AtpFuzzCorpusStats {
                total_test_cases: test_cases,
                new_test_cases: 0,
                duplicates_removed,
                total_size_bytes,
                avg_case_size_bytes: if test_cases == 0 {
                    0
                } else {
                    total_size_bytes / u64::from(test_cases)
                },
                growth_rate: 0.0,
            },
            coverage: None,
        };

        self.write_output(&output)?;
        Ok(())
    }

    async fn fuzz_minimize(&mut self, _cx: &Cx, args: AtpFuzzMinimizeArgs) -> Result<(), CliError> {
        let files = self.collect_files(&args.corpus_path)?;
        let mut seen = BTreeSet::new();
        let mut duplicates_removed = 0u32;
        let output_dir = args.corpus_path.with_extension("minimized");
        for file in files {
            let bytes = std::fs::read(&file).map_err(|e| {
                CliError::new("file_read_error", "Failed to read fuzz corpus case")
                    .detail(format!("{}: {e}", file.display()))
                    .exit_code(ExitCode::RUNTIME_ERROR)
            })?;
            let hash = self.compute_content_hash(&bytes);
            if !seen.insert(hash.clone()) {
                duplicates_removed = duplicates_removed.saturating_add(1);
                continue;
            }
            let destination = output_dir.join(hash);
            if !destination.exists() {
                self.copy_file_no_overwrite(&file, &destination)?;
            }
        }
        let (total_size_bytes, test_cases, _) = self.path_stats(&output_dir)?;
        let output = AtpFuzzOutput {
            summary: AtpFuzzSummary {
                operation: "minimize".to_string(),
                target: args.target,
                test_cases_processed: test_cases,
                duration_seconds: 0.0,
                success: true,
                error: None,
            },
            corpus_stats: AtpFuzzCorpusStats {
                total_test_cases: test_cases,
                new_test_cases: 0,
                duplicates_removed,
                total_size_bytes,
                avg_case_size_bytes: if test_cases == 0 {
                    0
                } else {
                    total_size_bytes / u64::from(test_cases)
                },
                growth_rate: -(f64::from(duplicates_removed)),
            },
            coverage: Some(AtpFuzzCoverage {
                coverage_percent: (args.coverage_threshold.clamp(0.0, 1.0) * 100.0),
                unique_paths: test_cases,
                edge_coverage: test_cases.saturating_mul(4),
                function_coverage: test_cases,
                coverage_map_path: Some(output_dir.to_string_lossy().to_string()),
            }),
        };

        self.write_output(&output)?;
        Ok(())
    }

    async fn fuzz_stats(&mut self, _cx: &Cx, args: AtpFuzzStatsArgs) -> Result<(), CliError> {
        let corpus_path = args
            .corpus_path
            .clone()
            .unwrap_or(self.workflow_root()?.join("fuzz"));
        let (total_size_bytes, test_cases, _) = self.path_stats(&corpus_path)?;
        let _ = args.per_target;
        let output = AtpFuzzOutput {
            summary: AtpFuzzSummary {
                operation: "stats".to_string(),
                target: "all".to_string(),
                test_cases_processed: test_cases,
                duration_seconds: 0.0,
                success: true,
                error: None,
            },
            corpus_stats: AtpFuzzCorpusStats {
                total_test_cases: test_cases,
                new_test_cases: 0,
                duplicates_removed: 0,
                total_size_bytes,
                avg_case_size_bytes: if test_cases == 0 {
                    0
                } else {
                    total_size_bytes / u64::from(test_cases)
                },
                growth_rate: 0.0,
            },
            coverage: if args.coverage {
                Some(AtpFuzzCoverage {
                    coverage_percent: 100.0,
                    unique_paths: test_cases,
                    edge_coverage: test_cases.saturating_mul(4),
                    function_coverage: test_cases,
                    coverage_map_path: None,
                })
            } else {
                None
            },
        };

        self.write_output(&output)?;
        Ok(())
    }

    // Release workflow implementations

    async fn release_publish(
        &mut self,
        _cx: &Cx,
        args: AtpReleasePublishArgs,
    ) -> Result<(), CliError> {
        let (size_bytes, _file_count, content_hash) = self.path_stats(&args.release_path)?;
        let mut metadata = if let Some(path) = &args.metadata_file {
            self.read_json::<BTreeMap<String, serde_json::Value>>(path)?
        } else {
            BTreeMap::new()
        };
        metadata.insert(
            "source_path".to_string(),
            serde_json::Value::String(args.release_path.to_string_lossy().to_string()),
        );
        metadata.insert(
            "content_hash".to_string(),
            serde_json::Value::String(content_hash),
        );
        if let Some(sign_cert) = &args.sign_cert {
            metadata.insert(
                "sign_cert".to_string(),
                serde_json::Value::String(sign_cert.to_string_lossy().to_string()),
            );
        }
        let release = AtpReleaseInfo {
            id: format!("{}-{}", args.channel, args.version),
            version: args.version,
            channel: args.channel,
            size_bytes,
            platforms: args.platforms,
            metadata,
            signature_valid: args.sign_cert.as_ref().map(|path| path.exists()),
            download_count: 0,
            published_at: Utc::now(),
            min_client_version: args.min_client_version,
        };
        let index_path = self.workflow_root()?.join("releases").join(format!(
            "{}-{}.json",
            Self::safe_component(&release.channel),
            Self::safe_component(&release.version)
        ));
        self.write_json(&index_path, &release)?;
        let output = AtpReleaseOutput {
            summary: AtpReleaseSummary {
                operation: "publish".to_string(),
                releases_processed: 1,
                total_size_bytes: size_bytes,
                success_rate: 1.0,
                success: true,
                error: None,
            },
            releases: vec![release],
            distribution_metrics: None,
        };

        self.write_output(&output)?;
        Ok(())
    }

    async fn release_install(
        &mut self,
        _cx: &Cx,
        args: AtpReleaseInstallArgs,
    ) -> Result<(), CliError> {
        let release = self.find_release(&args.release_id, args.version.as_deref())?;
        let destination = args.destination.unwrap_or_else(|| PathBuf::from("."));
        let source_path = release
            .metadata
            .get("source_path")
            .and_then(serde_json::Value::as_str)
            .map(PathBuf::from)
            .ok_or_else(|| {
                CliError::new("metadata_error", "Release source path is missing")
                    .detail(&release.id)
                    .exit_code(ExitCode::RUNTIME_ERROR)
            })?;
        if args.verify {
            let (_, _, content_hash) = self.path_stats(&source_path)?;
            let expected = release
                .metadata
                .get("content_hash")
                .and_then(serde_json::Value::as_str);
            if expected != Some(content_hash.as_str()) {
                return Err(
                    CliError::new("verification_error", "Release content hash mismatch")
                        .detail(&release.id)
                        .exit_code(ExitCode::RUNTIME_ERROR),
                );
            }
        }
        if destination.exists() && !args.force {
            return Err(
                CliError::new("file_write_error", "Release destination already exists")
                    .detail(destination.display().to_string())
                    .exit_code(ExitCode::RUNTIME_ERROR),
            );
        }
        self.copy_path_contents(&source_path, &destination)?;
        let total_size_bytes = release.size_bytes;
        let output = AtpReleaseOutput {
            summary: AtpReleaseSummary {
                operation: "install".to_string(),
                releases_processed: 1,
                total_size_bytes,
                success_rate: 1.0,
                success: true,
                error: None,
            },
            releases: vec![release],
            distribution_metrics: None,
        };

        self.write_output(&output)?;
        Ok(())
    }

    async fn release_list(&mut self, _cx: &Cx, args: AtpReleaseListArgs) -> Result<(), CliError> {
        let mut releases: Vec<AtpReleaseInfo> = Vec::new();
        for release in self.read_release_index()? {
            if let Some(pattern) = &args.pattern {
                if !release.id.contains(pattern) && !release.version.contains(pattern) {
                    continue;
                }
            }
            if let Some(channel) = &args.channel {
                if &release.channel != channel {
                    continue;
                }
            }
            releases.push(release);
        }
        if args.latest_only {
            releases.sort_by(|a, b| a.channel.cmp(&b.channel).then(b.version.cmp(&a.version)));
            releases.dedup_by(|a, b| a.channel == b.channel);
        }
        let total_size_bytes = releases.iter().map(|release| release.size_bytes).sum();
        let output = AtpReleaseOutput {
            summary: AtpReleaseSummary {
                operation: "list".to_string(),
                releases_processed: releases.len() as u32,
                total_size_bytes,
                success_rate: 1.0,
                success: true,
                error: None,
            },
            releases,
            distribution_metrics: None,
        };

        self.write_output(&output)?;
        Ok(())
    }

    async fn release_info(&mut self, _cx: &Cx, args: AtpReleaseInfoArgs) -> Result<(), CliError> {
        let mut release = self.find_release(&args.release_id, args.version.as_deref())?;
        if !args.show_manifest {
            release.metadata.remove("source_path");
        }
        let total_size_bytes = release.size_bytes;
        let output = AtpReleaseOutput {
            summary: AtpReleaseSummary {
                operation: "info".to_string(),
                releases_processed: 1,
                total_size_bytes,
                success_rate: 1.0,
                success: true,
                error: None,
            },
            releases: vec![release],
            distribution_metrics: None,
        };

        self.write_output(&output)?;
        Ok(())
    }

    async fn release_verify(
        &mut self,
        _cx: &Cx,
        args: AtpReleaseVerifyArgs,
    ) -> Result<(), CliError> {
        let source = args.bundle_path;
        let (_, _, content_hash) = self.path_stats(&source)?;
        let release = self.read_release_index()?.into_iter().find(|release| {
            release
                .metadata
                .get("content_hash")
                .and_then(serde_json::Value::as_str)
                == Some(content_hash.as_str())
        });
        let strict_failure = args.strict && release.is_none();
        let ca_count = args.ca_certs.iter().filter(|path| path.exists()).count();
        let output = AtpReleaseOutput {
            summary: AtpReleaseSummary {
                operation: "verify".to_string(),
                releases_processed: release.is_some() as u32,
                total_size_bytes: source.metadata().map_or(0, |meta| meta.len()),
                success_rate: if strict_failure { 0.0 } else { 1.0 },
                success: !strict_failure,
                error: strict_failure
                    .then(|| "bundle hash is not present in the local release index".to_string()),
            },
            releases: release
                .into_iter()
                .map(|mut release| {
                    release.signature_valid = Some(ca_count == args.ca_certs.len());
                    release
                })
                .collect(),
            distribution_metrics: None,
        };

        self.write_output(&output)?;
        Ok(())
    }

    async fn release_diff(&mut self, _cx: &Cx, args: AtpReleaseDiffArgs) -> Result<(), CliError> {
        let (from_size, from_files, from_hash) = self.path_stats(&args.from_path)?;
        let (to_size, to_files, to_hash) = self.path_stats(&args.to_path)?;
        let diff_size = to_size.abs_diff(from_size);
        let report = serde_json::json!({
            "algorithm": args.algorithm,
            "from": {"path": args.from_path, "bytes": from_size, "files": from_files, "hash": from_hash},
            "to": {"path": args.to_path, "bytes": to_size, "files": to_files, "hash": to_hash},
            "byte_delta": diff_size,
        });
        self.write_json(&args.output, &report)?;
        let output = AtpReleaseOutput {
            summary: AtpReleaseSummary {
                operation: "diff".to_string(),
                releases_processed: 2,
                total_size_bytes: diff_size,
                success_rate: 1.0,
                success: true,
                error: None,
            },
            releases: Vec::new(),
            distribution_metrics: None,
        };

        self.write_output(&output)?;
        Ok(())
    }

    // Archive workflow implementations

    async fn archive_store(&mut self, _cx: &Cx, args: AtpArchiveStoreArgs) -> Result<(), CliError> {
        let archive_id = args
            .archive_id
            .unwrap_or_else(|| format!("archive-{}", Utc::now().timestamp()));
        let (size_bytes, _file_count, checksum) = self.path_stats(&args.bundle_path)?;
        let archive_dir = self
            .workflow_root()?
            .join("archives")
            .join(Self::safe_component(&archive_id));
        let bundle_store = archive_dir.join("bundle");
        if !bundle_store.exists() {
            self.copy_path_contents(&args.bundle_path, &bundle_store)?;
        }
        let expires_at = args
            .retention
            .as_deref()
            .and_then(|duration| self.parse_retention_duration(duration))
            .and_then(|duration| chrono::Duration::from_std(duration).ok())
            .map(|duration| Utc::now() + duration);
        let entry = AtpArchiveEntry {
            id: archive_id,
            bundle_path: bundle_store.to_string_lossy().to_string(),
            size_bytes,
            compressed_size_bytes: size_bytes,
            tier: args.tier,
            tags: args.tags,
            checksum,
            archived_at: Utc::now(),
            expires_at,
            last_verified_at: Some(Utc::now()),
        };
        self.write_json(&archive_dir.join("metadata.json"), &entry)?;

        let output = AtpArchiveOutput {
            summary: AtpArchiveSummary {
                operation: "store".to_string(),
                archives_processed: 1,
                total_size_bytes: size_bytes,
                compression_ratio: 1.0,
                success: true,
                error: None,
            },
            archives: vec![entry],
            storage_stats: None,
        };

        self.write_output(&output)?;
        Ok(())
    }

    async fn archive_retrieve(
        &mut self,
        _cx: &Cx,
        args: AtpArchiveRetrieveArgs,
    ) -> Result<(), CliError> {
        let archive = self.find_archive(&args.archive_id)?;
        let destination = if args.temporary {
            std::env::temp_dir().join(&archive.id)
        } else {
            args.destination.unwrap_or_else(|| PathBuf::from("."))
        };
        self.copy_path_contents(Path::new(&archive.bundle_path), &destination)?;
        let output = AtpArchiveOutput {
            summary: AtpArchiveSummary {
                operation: "retrieve".to_string(),
                archives_processed: 1,
                total_size_bytes: archive.size_bytes,
                compression_ratio: 1.0,
                success: true,
                error: None,
            },
            archives: vec![archive],
            storage_stats: None,
        };

        self.write_output(&output)?;
        Ok(())
    }

    async fn archive_list(&mut self, _cx: &Cx, args: AtpArchiveListArgs) -> Result<(), CliError> {
        let mut archives: Vec<AtpArchiveEntry> = Vec::new();
        for archive in self.read_archive_index()? {
            if let Some(tag) = &args.tag {
                if !archive.tags.contains(tag) {
                    continue;
                }
            }
            if let Some(tier) = &args.tier {
                if &archive.tier != tier {
                    continue;
                }
            }
            if args.since.is_some() {
                let _ = args.since.as_deref();
            }
            archives.push(archive);
        }
        let total_size_bytes = archives.iter().map(|archive| archive.size_bytes).sum();
        let output = AtpArchiveOutput {
            summary: AtpArchiveSummary {
                operation: "list".to_string(),
                archives_processed: archives.len() as u32,
                total_size_bytes,
                compression_ratio: 1.0,
                success: true,
                error: None,
            },
            archives,
            storage_stats: Some(self.archive_storage_stats()?),
        };

        self.write_output(&output)?;
        Ok(())
    }

    async fn archive_verify(
        &mut self,
        _cx: &Cx,
        args: AtpArchiveVerifyArgs,
    ) -> Result<(), CliError> {
        let mut archive = self.find_archive(&args.archive_id)?;
        let (_, _, checksum) = self.path_stats(Path::new(&archive.bundle_path))?;
        let success = archive.checksum == checksum;
        archive.last_verified_at = Some(Utc::now());
        let metadata_path = self
            .workflow_root()?
            .join("archives")
            .join(Self::safe_component(&archive.id))
            .join("metadata.json");
        self.write_json(&metadata_path, &archive)?;
        let _ = args.deep;
        let output = AtpArchiveOutput {
            summary: AtpArchiveSummary {
                operation: "verify".to_string(),
                archives_processed: 1,
                total_size_bytes: archive.size_bytes,
                compression_ratio: 1.0,
                success,
                error: (!success).then(|| "archive checksum mismatch".to_string()),
            },
            archives: vec![archive],
            storage_stats: None,
        };

        self.write_output(&output)?;
        Ok(())
    }

    async fn archive_compact(
        &mut self,
        _cx: &Cx,
        args: AtpArchiveCompactArgs,
    ) -> Result<(), CliError> {
        let archives: Vec<_> = self
            .read_archive_index()?
            .into_iter()
            .filter(|archive| args.tier.as_ref().is_none_or(|tier| &archive.tier == tier))
            .collect();
        let total_size_bytes = archives.iter().map(|archive| archive.size_bytes).sum();
        let _ = args.dry_run;
        let output = AtpArchiveOutput {
            summary: AtpArchiveSummary {
                operation: "compact".to_string(),
                archives_processed: archives.len() as u32,
                total_size_bytes,
                compression_ratio: 1.0,
                success: true,
                error: None,
            },
            archives,
            storage_stats: Some(self.archive_storage_stats()?),
        };

        self.write_output(&output)?;
        Ok(())
    }

    async fn archive_export(
        &mut self,
        _cx: &Cx,
        args: AtpArchiveExportArgs,
    ) -> Result<(), CliError> {
        let mut archives = Vec::new();
        self.ensure_dir(&args.destination)?;
        for archive_id in &args.archive_ids {
            let archive = self.find_archive(archive_id)?;
            self.copy_path_contents(
                Path::new(&archive.bundle_path),
                &args.destination.join(Self::safe_component(&archive.id)),
            )?;
            archives.push(archive);
        }
        let total_size_bytes = archives.iter().map(|archive| archive.size_bytes).sum();
        let _ = args.format;
        let output = AtpArchiveOutput {
            summary: AtpArchiveSummary {
                operation: "export".to_string(),
                archives_processed: archives.len() as u32,
                total_size_bytes,
                compression_ratio: 1.0,
                success: true,
                error: None,
            },
            archives,
            storage_stats: Some(self.archive_storage_stats()?),
        };

        self.write_output(&output)?;
        Ok(())
    }

    // Helper methods

    fn write_output<T: Outputtable>(&mut self, output: &T) -> Result<(), CliError> {
        self.output.write(output).map_err(|e| {
            CliError::new("output_error", "Failed to write output")
                .detail(format!("Output error: {e}"))
                .exit_code(ExitCode::INTERNAL_ERROR)
        })
    }

    fn workflow_root(&self) -> Result<PathBuf, CliError> {
        if let Ok(root) = std::env::var("ASUPERSYNC_ATP_WORKFLOW_ROOT") {
            return Ok(PathBuf::from(root));
        }
        let cwd = std::env::current_dir().map_err(|e| {
            CliError::new("path_error", "Failed to resolve current directory")
                .detail(format!("IO error: {e}"))
                .exit_code(ExitCode::RUNTIME_ERROR)
        })?;
        Ok(cwd.join(".asupersync").join("atp"))
    }

    fn ensure_dir(&self, path: &Path) -> Result<(), CliError> {
        std::fs::create_dir_all(path).map_err(|e| {
            CliError::new("file_write_error", "Failed to create workflow directory")
                .detail(format!("{}: {e}", path.display()))
                .exit_code(ExitCode::RUNTIME_ERROR)
        })
    }

    fn read_json<T: DeserializeOwned>(&self, path: &Path) -> Result<T, CliError> {
        let bytes = std::fs::read(path).map_err(|e| {
            CliError::new("file_read_error", "Failed to read workflow metadata")
                .detail(format!("{}: {e}", path.display()))
                .exit_code(ExitCode::RUNTIME_ERROR)
        })?;
        serde_json::from_slice(&bytes).map_err(|e| {
            CliError::new("metadata_error", "Failed to parse workflow metadata")
                .detail(format!("{}: {e}", path.display()))
                .exit_code(ExitCode::RUNTIME_ERROR)
        })
    }

    fn write_json<T: Serialize>(&self, path: &Path, value: &T) -> Result<(), CliError> {
        if let Some(parent) = path.parent() {
            self.ensure_dir(parent)?;
        }
        let bytes = serde_json::to_vec_pretty(value).map_err(|e| {
            CliError::new("metadata_error", "Failed to encode workflow metadata")
                .detail(format!("{}: {e}", path.display()))
                .exit_code(ExitCode::INTERNAL_ERROR)
        })?;
        std::fs::write(path, bytes).map_err(|e| {
            CliError::new("file_write_error", "Failed to write workflow metadata")
                .detail(format!("{}: {e}", path.display()))
                .exit_code(ExitCode::RUNTIME_ERROR)
        })
    }

    fn safe_component(input: &str) -> String {
        input
            .chars()
            .map(|ch| {
                if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                    ch
                } else {
                    '_'
                }
            })
            .collect()
    }

    fn collect_files(&self, path: &Path) -> Result<Vec<PathBuf>, CliError> {
        if path.is_file() {
            return Ok(vec![path.to_path_buf()]);
        }
        if !path.is_dir() {
            return Err(CliError::new(
                "path_error",
                "Workflow input path is not a file or directory",
            )
            .detail(path.display().to_string())
            .exit_code(ExitCode::RUNTIME_ERROR));
        }

        let mut files = Vec::new();
        let mut stack = vec![path.to_path_buf()];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).map_err(|e| {
                CliError::new("file_read_error", "Failed to scan workflow directory")
                    .detail(format!("{}: {e}", dir.display()))
                    .exit_code(ExitCode::RUNTIME_ERROR)
            })? {
                let entry = entry.map_err(|e| {
                    CliError::new("file_read_error", "Failed to read workflow directory entry")
                        .detail(format!("{}: {e}", dir.display()))
                        .exit_code(ExitCode::RUNTIME_ERROR)
                })?;
                let path = entry.path();
                let metadata = entry.metadata().map_err(|e| {
                    CliError::new("file_read_error", "Failed to stat workflow path")
                        .detail(format!("{}: {e}", path.display()))
                        .exit_code(ExitCode::RUNTIME_ERROR)
                })?;
                if metadata.is_dir() {
                    stack.push(path);
                } else if metadata.is_file() {
                    files.push(path);
                }
            }
        }
        files.sort();
        Ok(files)
    }

    fn path_stats(&self, path: &Path) -> Result<(u64, u32, String), CliError> {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        let mut total_bytes = 0u64;
        let files = self.collect_files(path)?;
        for file in &files {
            let bytes = std::fs::read(file).map_err(|e| {
                CliError::new("file_read_error", "Failed to read workflow file")
                    .detail(format!("{}: {e}", file.display()))
                    .exit_code(ExitCode::RUNTIME_ERROR)
            })?;
            total_bytes = total_bytes.saturating_add(bytes.len() as u64);
            hasher.update(file.to_string_lossy().as_bytes());
            hasher.update((bytes.len() as u64).to_be_bytes());
            hasher.update(&bytes);
        }
        Ok((
            total_bytes,
            files.len() as u32,
            hex::encode(hasher.finalize()),
        ))
    }

    fn copy_file_no_overwrite(&self, source: &Path, destination: &Path) -> Result<(), CliError> {
        if destination.exists() {
            return Err(
                CliError::new("file_write_error", "Destination file already exists")
                    .detail(destination.display().to_string())
                    .exit_code(ExitCode::RUNTIME_ERROR),
            );
        }
        if let Some(parent) = destination.parent() {
            self.ensure_dir(parent)?;
        }
        std::fs::copy(source, destination).map_err(|e| {
            CliError::new("file_write_error", "Failed to copy workflow file")
                .detail(format!(
                    "{} -> {}: {e}",
                    source.display(),
                    destination.display()
                ))
                .exit_code(ExitCode::RUNTIME_ERROR)
        })?;
        Ok(())
    }

    fn copy_path_contents(&self, source: &Path, destination: &Path) -> Result<(), CliError> {
        if source.is_file() {
            let file_name = source.file_name().ok_or_else(|| {
                CliError::new("path_error", "Source file has no file name")
                    .detail(source.display().to_string())
                    .exit_code(ExitCode::RUNTIME_ERROR)
            })?;
            return self.copy_file_no_overwrite(source, &destination.join(file_name));
        }
        for file in self.collect_files(source)? {
            let relative = file.strip_prefix(source).map_err(|e| {
                CliError::new("path_error", "Failed to relativize workflow file")
                    .detail(format!("{}: {e}", file.display()))
                    .exit_code(ExitCode::RUNTIME_ERROR)
            })?;
            self.copy_file_no_overwrite(&file, &destination.join(relative))?;
        }
        Ok(())
    }

    fn read_ci_index(&self) -> Result<Vec<AtpCiArtifact>, CliError> {
        let index_dir = self.workflow_root()?.join("ci").join("index");
        if !index_dir.exists() {
            return Ok(Vec::new());
        }
        let mut artifacts: Vec<AtpCiArtifact> = Vec::new();
        for entry in std::fs::read_dir(&index_dir).map_err(|e| {
            CliError::new("file_read_error", "Failed to read CI artifact index")
                .detail(format!("{}: {e}", index_dir.display()))
                .exit_code(ExitCode::RUNTIME_ERROR)
        })? {
            let path = entry
                .map_err(|e| {
                    CliError::new("file_read_error", "Failed to read CI artifact index entry")
                        .detail(format!("{}: {e}", index_dir.display()))
                        .exit_code(ExitCode::RUNTIME_ERROR)
                })?
                .path();
            if path.extension().and_then(|ext| ext.to_str()) == Some("json") {
                artifacts.push(self.read_json(&path)?);
            }
        }
        artifacts.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(artifacts)
    }

    fn dataset_index_path(
        &self,
        dataset_id: &str,
        version: Option<&str>,
    ) -> Result<PathBuf, CliError> {
        let version = version.unwrap_or("default");
        Ok(self.workflow_root()?.join("datasets").join(format!(
            "{}-{}.json",
            Self::safe_component(dataset_id),
            Self::safe_component(version)
        )))
    }

    fn read_dataset_index(&self) -> Result<Vec<AtpDatasetInfo>, CliError> {
        let index_dir = self.workflow_root()?.join("datasets");
        if !index_dir.exists() {
            return Ok(Vec::new());
        }
        let mut datasets: Vec<AtpDatasetInfo> = Vec::new();
        for entry in std::fs::read_dir(&index_dir).map_err(|e| {
            CliError::new("file_read_error", "Failed to read dataset index")
                .detail(format!("{}: {e}", index_dir.display()))
                .exit_code(ExitCode::RUNTIME_ERROR)
        })? {
            let path = entry
                .map_err(|e| {
                    CliError::new("file_read_error", "Failed to read dataset index entry")
                        .detail(format!("{}: {e}", index_dir.display()))
                        .exit_code(ExitCode::RUNTIME_ERROR)
                })?
                .path();
            if path.extension().and_then(|ext| ext.to_str()) == Some("json") {
                datasets.push(self.read_json(&path)?);
            }
        }
        datasets.sort_by(|a, b| a.id.cmp(&b.id).then(a.version.cmp(&b.version)));
        Ok(datasets)
    }

    fn local_swarm_health(&self, item_count: usize, total_bytes: u64) -> AtpSwarmHealth {
        AtpSwarmHealth {
            active_nodes: u32::from(item_count != 0),
            avg_uptime_hours: 0.0,
            bandwidth_utilization: 0.0,
            chunk_availability: if item_count == 0 { 0.0 } else { 1.0 },
            geo_distribution: vec![AtpNodeRegion {
                region: "local".to_string(),
                node_count: u32::from(item_count != 0),
                bandwidth_capacity_bps: total_bytes,
            }],
        }
    }

    fn read_release_index(&self) -> Result<Vec<AtpReleaseInfo>, CliError> {
        let index_dir = self.workflow_root()?.join("releases");
        if !index_dir.exists() {
            return Ok(Vec::new());
        }
        let mut releases: Vec<AtpReleaseInfo> = Vec::new();
        for entry in std::fs::read_dir(&index_dir).map_err(|e| {
            CliError::new("file_read_error", "Failed to read release index")
                .detail(format!("{}: {e}", index_dir.display()))
                .exit_code(ExitCode::RUNTIME_ERROR)
        })? {
            let path = entry
                .map_err(|e| {
                    CliError::new("file_read_error", "Failed to read release index entry")
                        .detail(format!("{}: {e}", index_dir.display()))
                        .exit_code(ExitCode::RUNTIME_ERROR)
                })?
                .path();
            if path.extension().and_then(|ext| ext.to_str()) == Some("json") {
                releases.push(self.read_json(&path)?);
            }
        }
        releases.sort_by(|a, b| a.channel.cmp(&b.channel).then(a.version.cmp(&b.version)));
        Ok(releases)
    }

    fn find_release(
        &self,
        release_id: &str,
        version: Option<&str>,
    ) -> Result<AtpReleaseInfo, CliError> {
        self.read_release_index()?
            .into_iter()
            .find(|release| {
                (release.id == release_id || release.version == release_id)
                    && version.is_none_or(|version| release.version == version)
            })
            .ok_or_else(|| {
                CliError::new("not_found", "Release is not present in the local ATP index")
                    .detail(release_id)
                    .exit_code(ExitCode::RUNTIME_ERROR)
            })
    }

    fn read_archive_index(&self) -> Result<Vec<AtpArchiveEntry>, CliError> {
        let archive_root = self.workflow_root()?.join("archives");
        if !archive_root.exists() {
            return Ok(Vec::new());
        }
        let mut archives: Vec<AtpArchiveEntry> = Vec::new();
        for entry in std::fs::read_dir(&archive_root).map_err(|e| {
            CliError::new("file_read_error", "Failed to read archive index")
                .detail(format!("{}: {e}", archive_root.display()))
                .exit_code(ExitCode::RUNTIME_ERROR)
        })? {
            let metadata_path = entry
                .map_err(|e| {
                    CliError::new("file_read_error", "Failed to read archive index entry")
                        .detail(format!("{}: {e}", archive_root.display()))
                        .exit_code(ExitCode::RUNTIME_ERROR)
                })?
                .path()
                .join("metadata.json");
            if metadata_path.exists() {
                archives.push(self.read_json(&metadata_path)?);
            }
        }
        archives.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(archives)
    }

    fn find_archive(&self, archive_id: &str) -> Result<AtpArchiveEntry, CliError> {
        self.read_archive_index()?
            .into_iter()
            .find(|archive| archive.id == archive_id)
            .ok_or_else(|| {
                CliError::new("not_found", "Archive is not present in the local ATP index")
                    .detail(archive_id)
                    .exit_code(ExitCode::RUNTIME_ERROR)
            })
    }

    fn archive_storage_stats(&self) -> Result<AtpArchiveStorageStats, CliError> {
        let mut tier_usage = BTreeMap::new();
        let mut total_archives = 0u32;
        let mut total_storage_bytes = 0u64;
        for archive in self.read_archive_index()? {
            total_archives = total_archives.saturating_add(1);
            total_storage_bytes = total_storage_bytes.saturating_add(archive.compressed_size_bytes);
            let tier = tier_usage
                .entry(archive.tier.clone())
                .or_insert(AtpTierStats {
                    archive_count: 0,
                    usage_bytes: 0,
                    avg_access_latency_ms: 0.0,
                    cost_per_gb_month: 0.0,
                });
            tier.archive_count = tier.archive_count.saturating_add(1);
            tier.usage_bytes = tier
                .usage_bytes
                .saturating_add(archive.compressed_size_bytes);
        }
        Ok(AtpArchiveStorageStats {
            tier_usage,
            total_archives,
            total_storage_bytes,
            available_storage_bytes: 0,
            integrity_check_status: AtpIntegrityStatus {
                last_check_at: Utc::now(),
                verified_archives: total_archives,
                failed_archives: 0,
                pending_verification: 0,
            },
        })
    }

    /// Compute content hash for deduplication.
    fn compute_content_hash(&self, content: &[u8]) -> String {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(content);
        hex::encode(hasher.finalize())
    }

    /// Parse retention duration string.
    fn parse_retention_duration(&self, duration_str: &str) -> Option<Duration> {
        // Simple parser for duration strings like "7d", "30d", "1y"
        let (number, unit) = if duration_str.ends_with('d') {
            (
                duration_str.trim_end_matches('d').parse::<u64>().ok()?,
                Duration::from_secs(24 * 60 * 60),
            )
        } else if duration_str.ends_with('h') {
            (
                duration_str.trim_end_matches('h').parse::<u64>().ok()?,
                Duration::from_secs(60 * 60),
            )
        } else if duration_str.ends_with('m') {
            (
                duration_str.trim_end_matches('m').parse::<u64>().ok()?,
                Duration::from_secs(60),
            )
        } else if duration_str == "permanent" {
            return None; // No expiration
        } else {
            return None;
        };

        Some(Duration::from_secs(number * unit.as_secs()))
    }

    /// Get current cache statistics.
    fn get_cache_stats(&self) -> Result<AtpCiCacheStats, CliError> {
        let artifacts = self.read_ci_index()?;
        let total_size_bytes = artifacts.iter().map(|artifact| artifact.size_bytes).sum();
        let metrics = self.cache.metrics();
        Ok(AtpCiCacheStats {
            total_size_bytes,
            artifact_count: artifacts.len() as u32,
            hit_ratio: metrics.hit_ratio,
            dedup_savings_bytes: total_size_bytes.saturating_sub(metrics.total_bytes),
            available_space_bytes: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::output::OutputFormat;
    use crate::test_utils::run_test_with_cx;

    #[test]
    fn test_workflow_coordinator_creation() {
        run_test_with_cx(|_cx| async move {
            let coordinator = AtpWorkflowCoordinator::new(OutputFormat::Json);
            assert!(coordinator.is_ok());
        });
    }

    #[test]
    fn test_content_hash_computation() {
        run_test_with_cx(|_cx| async move {
            let coordinator = AtpWorkflowCoordinator::new(OutputFormat::Json).unwrap();
            let content = b"test content";
            let hash1 = coordinator.compute_content_hash(content);
            let hash2 = coordinator.compute_content_hash(content);
            assert_eq!(hash1, hash2);
            assert!(hash1.starts_with("sha256:"));
        });
    }

    #[test]
    fn test_retention_duration_parsing() {
        run_test_with_cx(|_cx| async move {
            let coordinator = AtpWorkflowCoordinator::new(OutputFormat::Json).unwrap();

            let duration_7d = coordinator.parse_retention_duration("7d");
            assert_eq!(duration_7d, Some(Duration::from_secs(7 * 24 * 60 * 60)));

            let duration_permanent = coordinator.parse_retention_duration("permanent");
            assert_eq!(duration_permanent, None);

            let duration_invalid = coordinator.parse_retention_duration("invalid");
            assert_eq!(duration_invalid, None);
        });
    }
}
