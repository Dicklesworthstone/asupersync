//! Persistent local reconciliation through the maintained native ATP engine.

use asupersync::cli::{CliError, ExitCode, Output};
use clap::{ArgAction, Args};
use std::path::PathBuf;

#[derive(Args, Debug)]
#[command(
    long_about = "Plan or apply persistent synchronization between two local directories. \
    Supported on Linux/glibc for ordinary file contents and directory structure. \
    Source permissions, timestamps, symlinks, hard-link topology, sparse layout and platform \
    metadata are not preserved; unsupported input is refused. Both trees must be exclusively \
    owned for the duration of the command. The default previews changes without applying them. \
    Reopening history takes its writer lease and confirms state-file durability.",
    after_long_help = "All paths must be absolute, UTF-8, and free of symlink components. \
    State and staging directories must already exist outside both trees and each other. \
    State must be private (0700), empty when initialized, and owned by the effective user/group. \
    Staging must be on the trees' shared filesystem, owned by the effective user, and not \
    writable by group or others. New files use 0600 and new directories 0700. \
    Overwrites require both --allow-overwrite and --allow-permission-change. \
    Deleted or overwritten originals remain at the reported quarantine paths; no automatic \
    cleanup or whole-tree rollback occurs. A plan ID identifies one invocation and its recovery \
    job; it is not an approval token for a later invocation. Each --apply prepares and \
    revalidates the current changes against saved history before applying the selected grants."
)]
pub(super) struct LocalSyncArgs {
    /// First directory to reconcile
    #[arg(value_name = "LOCAL")]
    local: PathBuf,
    /// Second directory to reconcile
    #[arg(value_name = "REMOTE")]
    remote: PathBuf,
    /// Existing private directory containing persistent common history
    #[arg(long, value_name = "PATH")]
    state_dir: PathBuf,
    /// Explicitly create history in an empty state directory; never reset existing history
    #[arg(long, action = ArgAction::SetTrue)]
    initialize: bool,
    /// Apply the current plan and durably record convergence
    #[arg(long, action = ArgAction::SetTrue, requires = "staging_dir")]
    apply: bool,
    /// Existing external directory in which to retain staging and recovery data
    #[arg(long, value_name = "PATH", requires = "apply")]
    staging_dir: Option<PathBuf>,
    /// Authorize replacing existing files, retaining their original inodes in quarantine
    #[arg(long, action = ArgAction::SetTrue, requires = "apply")]
    allow_overwrite: bool,
    /// Accept content-only replacement without a guarantee of preserving hidden metadata
    #[arg(long, action = ArgAction::SetTrue, requires = "apply")]
    allow_permission_change: bool,
    /// Authorize propagating deletions by moving unchanged peer entries to quarantine
    #[arg(long, action = ArgAction::SetTrue, requires = "apply")]
    allow_delete: bool,
    /// Maximum entries in each tree, including directories (1..=1000000)
    #[arg(long, default_value_t = 100_000)]
    max_entries: usize,
    /// Maximum relative path depth (1..=256)
    #[arg(long, default_value_t = 64)]
    max_depth: usize,
    /// Maximum logical bytes in one regular file
    #[arg(long, default_value_t = 17_179_869_184_u64)]
    max_file_bytes: u64,
    /// Maximum logical file bytes in each tree
    #[arg(long, default_value_t = 68_719_476_736_u64)]
    max_total_bytes: u64,
    /// Maximum bytes per persistent state slot (1..=67108864)
    #[arg(long, default_value_t = 67_108_864)]
    max_state_bytes: usize,
}

pub(super) fn run(args: &LocalSyncArgs, output: &mut Output) -> Result<(), CliError> {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        native::run(args, output)
    }
    #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
    {
        let _ = (args, output);
        Err(CliError::new(
            "atp_local_sync_unsupported",
            "Local directory synchronization requires Linux/glibc",
        )
        .detail("The native directory engine cannot provide this filesystem profile on this target")
        .exit_code(ExitCode::USER_ERROR))
    }
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
mod native {
    use super::{CliError, ExitCode, LocalSyncArgs, Output};
    use asupersync::atp::sync::native::{
        NativeDirectoryActionState, NativeDirectoryError, NativeDirectoryLimits,
        NativeDirectorySessionReport, NativeDirectoryStatePublication, NativeDirectorySyncSession,
    };
    use asupersync::atp::sync::{
        BidirectionalSyncAction, BidirectionalSyncDecision, DestructiveAuthorization,
    };
    use asupersync::cli::Outputtable;
    use asupersync::cx::Cx;
    use asupersync::runtime::{RootDrainOutcome, RuntimeBuilder};
    use std::fmt::Write as _;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    #[derive(Debug, serde::Serialize)]
    struct LocalSyncOutput {
        schema_version: u32,
        command: &'static str,
        mode: &'static str,
        content_profile: &'static str,
        initialized: bool,
        plan_id: String,
        baseline_generation: u64,
        local_root: PathBuf,
        remote_root: PathBuf,
        state_directory: PathBuf,
        local_bytes: u64,
        remote_bytes: u64,
        has_conflicts: bool,
        has_destructive_actions: bool,
        decisions: Vec<BidirectionalSyncDecision>,
        result: Option<ApplicationOutput>,
        application_error: Option<String>,
        runtime_quiescent: bool,
        runtime_stopped: bool,
    }

    #[derive(Debug, serde::Serialize)]
    struct ApplicationOutput {
        complete: bool,
        dry_run: bool,
        baseline_generation: u64,
        publication: PublicationOutput,
        staging_directory: Option<PathBuf>,
        failure: Option<String>,
        persistence_failure: Option<String>,
        actions: Vec<ActionOutput>,
    }

    #[derive(Debug, serde::Serialize)]
    struct PublicationOutput {
        state: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        generation: Option<u64>,
    }

    #[derive(Debug, serde::Serialize)]
    struct ActionOutput {
        path: String,
        action: BidirectionalSyncAction,
        state: &'static str,
        bytes_written: u64,
        staged_path: Option<PathBuf>,
        quarantine_path: Option<PathBuf>,
        durable: bool,
    }

    impl From<NativeDirectorySessionReport> for ApplicationOutput {
        fn from(report: NativeDirectorySessionReport) -> Self {
            let publication = match report.publication {
                NativeDirectoryStatePublication::Unchanged => PublicationOutput {
                    state: "unchanged",
                    generation: None,
                },
                NativeDirectoryStatePublication::Staging { generation } => PublicationOutput {
                    state: "staging",
                    generation: Some(generation),
                },
                NativeDirectoryStatePublication::Published { generation } => PublicationOutput {
                    state: "published",
                    generation: Some(generation),
                },
                NativeDirectoryStatePublication::Durable { generation } => PublicationOutput {
                    state: "durable",
                    generation: Some(generation),
                },
                _ => PublicationOutput {
                    state: "unknown",
                    generation: None,
                },
            };
            Self {
                complete: report.sync.complete,
                dry_run: report.sync.dry_run,
                baseline_generation: report.baseline_generation,
                publication,
                staging_directory: report.sync.staging_directory,
                failure: report.sync.failure.map(|error| error.to_string()),
                persistence_failure: report.persistence_failure.map(|error| error.to_string()),
                actions: report
                    .sync
                    .actions
                    .into_iter()
                    .map(|receipt| ActionOutput {
                        path: receipt.path.as_str().to_owned(),
                        action: receipt.action,
                        state: match receipt.state {
                            NativeDirectoryActionState::NotStarted => "not_started",
                            NativeDirectoryActionState::Unchanged => "unchanged",
                            NativeDirectoryActionState::Staged => "staged",
                            NativeDirectoryActionState::Quarantined => "quarantined",
                            NativeDirectoryActionState::Published => "published",
                            _ => "unknown",
                        },
                        bytes_written: receipt.bytes_written,
                        staged_path: receipt.staged_path,
                        quarantine_path: receipt.quarantine_path,
                        durable: receipt.durable,
                    })
                    .collect(),
            }
        }
    }

    impl ApplicationOutput {
        fn succeeded(&self) -> bool {
            self.complete
                && !self.dry_run
                && self.failure.is_none()
                && self.persistence_failure.is_none()
                && self.publication.state == "durable"
                && self.publication.generation == Some(self.baseline_generation)
        }
    }

    impl Outputtable for LocalSyncOutput {
        fn human_format(&self) -> String {
            let mut text = format!(
                "Local synchronization {}\n  Local: {}\n  Remote: {}\n  History: {} (generation {})\n  Plan: {}\n  Profile: {}\n",
                self.mode,
                self.local_root.display(),
                self.remote_root.display(),
                self.state_directory.display(),
                self.baseline_generation,
                self.plan_id,
                self.content_profile,
            );
            if self.initialized {
                text.push_str("  Created history; initialization alone declares no common baseline.\n");
            }
            for decision in &self.decisions {
                let authorization = if decision.is_destructive() {
                    " [explicit authorization required]"
                } else {
                    ""
                };
                let _ = writeln!(
                    text,
                    "  {:?}: {}{authorization}",
                    decision.action,
                    decision.path.as_str()
                );
            }
            if self.has_conflicts {
                text.push_str("  Conflicts require resolution; neither version is selected automatically.\n");
            }
            if let Some(result) = &self.result {
                let _ = writeln!(
                    text,
                    "  Tree complete: {}; history publication: {}",
                    result.complete, result.publication.state
                );
                for action in &result.actions {
                    let _ = writeln!(
                        text,
                        "  {}: {} ({} bytes written, durable: {})",
                        action.path, action.state, action.bytes_written, action.durable
                    );
                    if let Some(path) = &action.staged_path {
                        let _ = writeln!(text, "    Staged bytes: {}", path.display());
                    }
                    if let Some(path) = &action.quarantine_path {
                        let _ = writeln!(text, "    Retained original: {}", path.display());
                    }
                }
                if let Some(path) = &result.staging_directory {
                    let _ = writeln!(text, "  Retained recovery directory: {}", path.display());
                }
                for error in [&result.failure, &result.persistence_failure]
                    .into_iter()
                    .flatten()
                {
                    let _ = writeln!(text, "  Failure: {error}");
                }
            } else if let Some(error) = &self.application_error {
                let _ = writeln!(text, "  No application receipt: {error}");
                text.push_str("  Reopen history and inspect staging before another attempt.\n");
            } else {
                text.push_str("  Preview only. Use --apply with --staging-dir and the required grants to apply current changes.\n");
            }
            if !self.runtime_quiescent || !self.runtime_stopped {
                text.push_str("  Runtime cleanup was not confirmed.\n");
            }
            text
        }
    }

    pub(super) fn run(args: &LocalSyncArgs, output: &mut Output) -> Result<(), CliError> {
        // Do not canonicalize away symlinks before the native engine can refuse
        // them. UTF-8 also makes every emitted recovery path exactly serializable.
        for (label, path) in [
            ("local", Some(args.local.as_path())),
            ("remote", Some(args.remote.as_path())),
            ("state-dir", Some(args.state_dir.as_path())),
            ("staging-dir", args.staging_dir.as_deref()),
        ] {
            if let Some(path) = path {
                validate_path(label, path)?;
            }
        }
        let runtime = RuntimeBuilder::current_thread()
            .blocking_threads(0, 4)
            .build()
            .map_err(|error| {
                CliError::new("atp_local_sync_runtime", "Cannot start local sync runtime")
                    .detail(error.to_string())
                    .exit_code(ExitCode::RUNTIME_ERROR)
            })?;
        let report = runtime.block_on(execute(args));
        let quiescent = runtime.shutdown_drained(Duration::from_secs(30)).outcome
            == RootDrainOutcome::Quiescent;
        let stopped = runtime.shutdown_timeout(Duration::from_secs(30));
        let mut report = report.map_err(|error| {
            error
                .context("runtime_quiescent", quiescent)
                .context("runtime_stopped", stopped)
        })?;
        report.runtime_quiescent = quiescent;
        report.runtime_stopped = stopped;
        // Publish all observed effects before reporting a failure exit. A failed
        // baseline publication does not erase successfully copied/quarantined data.
        output
            .write(&report)
            .map_err(|error| receipt_output_error(error, &report))?;
        output
            .flush()
            .map_err(|error| receipt_output_error(error, &report))?;
        if report.mode == "apply" && !report.result.as_ref().is_some_and(ApplicationOutput::succeeded) {
            let detail = report
                .application_error
                .as_deref()
                .or_else(|| {
                    report.result.as_ref().and_then(|result| {
                        result
                            .failure
                            .as_deref()
                            .or(result.persistence_failure.as_deref())
                    })
                })
                .unwrap_or("Tree convergence and durable common history were not both confirmed");
            return Err(CliError::new(
                "atp_local_sync_incomplete",
                "Local synchronization did not complete durably",
            )
            .detail(detail)
            .context("plan_id", &report.plan_id)
            .context("state_directory", &report.state_directory)
            .exit_code(ExitCode::USER_ERROR));
        }
        if !quiescent || !stopped {
            return Err(CliError::new(
                "atp_local_sync_shutdown",
                "Local sync runtime cleanup was not confirmed",
            )
            .context("plan_id", &report.plan_id)
            .exit_code(ExitCode::RUNTIME_ERROR));
        }
        Ok(())
    }

    fn receipt_output_error(error: std::io::Error, report: &LocalSyncOutput) -> CliError {
        // Tree effects and history publication precede output. Preserve their
        // actual receipt on stderr when stdout cannot carry it, rather than
        // leaving a generic write failure that looks safe to retry blindly.
        super::super::output_write_error("local sync receipt")(error)
            .context("receipt", report)
            .suggestion("Inspect the recorded history and retained recovery paths before retrying; output failure does not roll back synchronization")
    }

    fn validate_path(label: &str, path: &Path) -> Result<(), CliError> {
        if path.is_absolute() && path.to_str().is_some() {
            return Ok(());
        }
        Err(CliError::new(
            "atp_local_sync_path",
            "Local sync requires absolute UTF-8 paths",
        )
        .detail(format!("{label}: {}", path.display()))
        .exit_code(ExitCode::USER_ERROR))
    }

    fn native_error(stage: &str, error: NativeDirectoryError) -> CliError {
        CliError::new("atp_local_sync_refused", "Cannot prepare local synchronization")
            .detail(error.to_string())
            .context("stage", stage)
            .exit_code(ExitCode::USER_ERROR)
    }

    async fn execute(args: &LocalSyncArgs) -> Result<LocalSyncOutput, CliError> {
        let cx = Cx::current().ok_or_else(|| {
            CliError::new("atp_local_sync_context", "Local sync has no runtime context")
                .exit_code(ExitCode::RUNTIME_ERROR)
        })?;
        let limits = NativeDirectoryLimits {
            max_entries: args.max_entries,
            max_depth: args.max_depth,
            max_file_bytes: args.max_file_bytes,
            max_total_bytes: args.max_total_bytes,
            ..NativeDirectoryLimits::default()
        };
        let mut session = if args.initialize {
            NativeDirectorySyncSession::create(
                &cx,
                &args.local,
                &args.remote,
                &args.state_dir,
                limits,
                args.max_state_bytes,
            )
            .await
        } else {
            NativeDirectorySyncSession::reopen(
                &cx,
                &args.local,
                &args.remote,
                &args.state_dir,
                limits,
                args.max_state_bytes,
            )
            .await
        }
        .map_err(|error| native_error(if args.initialize { "initialize" } else { "reopen" }, error))?;
        let generation = session.generation();
        let state_directory = session.state_directory().to_path_buf();
        let prepared = session.prepare(&cx).await.map_err(|error| {
            native_error("prepare", error)
                .context("initialized", args.initialize)
                .context("baseline_generation", generation)
                .context("state_directory", &state_directory)
                .suggestion("History was opened successfully; inspect it and reopen without --initialize before another attempt")
        })?;
        let mut report = LocalSyncOutput {
            schema_version: 1,
            command: "atp.local-sync",
            mode: if args.apply { "apply" } else { "plan" },
            content_profile: "linux-gnu-content-only-v1",
            initialized: args.initialize,
            plan_id: prepared.plan_id().to_owned(),
            baseline_generation: generation,
            local_root: prepared.local().root().to_path_buf(),
            remote_root: prepared.remote().root().to_path_buf(),
            state_directory,
            local_bytes: prepared.local().total_bytes(),
            remote_bytes: prepared.remote().total_bytes(),
            has_conflicts: prepared.preview().has_conflicts(),
            has_destructive_actions: prepared.preview().has_destructive_actions(),
            decisions: prepared.preview().decisions.clone(),
            result: None,
            application_error: None,
            runtime_quiescent: false,
            runtime_stopped: false,
        };
        if args.apply {
            let staging = args.staging_dir.as_ref().ok_or_else(|| {
                CliError::new(
                    "atp_local_sync_staging",
                    "Applying local sync requires --staging-dir",
                )
                .exit_code(ExitCode::USER_ERROR)
            })?;
            let authorization = DestructiveAuthorization {
                dry_run: false,
                allow_overwrite: args.allow_overwrite,
                allow_permission_change: args.allow_permission_change,
                allow_delete: args.allow_delete,
                ..DestructiveAuthorization::default()
            };
            match prepared.apply(&cx, authorization, staging).await {
                Ok(result) => {
                    report.baseline_generation = result.baseline_generation;
                    report.result = Some(result.into());
                }
                Err(error) => report.application_error = Some(error.to_string()),
            }
        }
        Ok(report)
    }
}
