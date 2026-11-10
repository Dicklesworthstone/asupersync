//! Bounded local observation and explicitly authorized continuous application.

use asupersync::cli::{CliError, ExitCode, Output};
use clap::{ArgAction, Args};
use std::path::PathBuf;

#[derive(Args, Debug)]
#[command(
    long_about = "Watch two local directories against durable common history. The default \
    reports settled changes without changing either tree. --apply-changes explicitly \
    authorizes applying future reviewed changes until --max-applications is reached; \
    overwrite, metadata replacement and deletion still require their separate grants. \
    Supported on Linux/glibc for ordinary file contents and directory structure. \
    This command does not contact a remote peer or record every intermediate filesystem event.",
    after_long_help = "Examples:\n  asupersync --format stream-json atp local-watch \
/srv/local /srv/peer --state-dir /srv/history --initialize --max-reviews 2\n  \
asupersync --format stream-json atp local-watch /srv/local /srv/peer \
--state-dir /srv/history --apply-changes --staging-dir /srv/recovery \
--max-applications 10 --allow-overwrite --allow-permission-change\n\n\
All paths must be absolute UTF-8 paths without symlink components. State and staging \
must already exist outside both trees and each other. State must be private (0700), \
empty when initialized, and owned by the effective user/group. Staging must be on the \
trees' shared filesystem, owned by the effective user, and not group/other writable. \
Only this command may publish into the trees; ordinary producer edits between scans \
must stop during each application. Unsupported symlinks and metadata are refused. \
New files use 0600 and directories 0700; permissions, timestamps, hard-link topology, \
sparse layout and platform metadata are not preserved.\n\n\
Each event is flushed immediately; use --format stream-json for one JSON object per \
line. The first settled pair is a review, including an unchanged pair. An application \
of that pair counts toward the finite application limit and records common history. \
Review IDs identify this process's opaque pending plans; they do not authorize a \
later invocation. In apply mode, conflicts or any incomplete application stop the command. Originals \
and recovery jobs remain at the reported paths; there is no automatic cleanup or \
whole-tree rollback. Retain the streamed receipts. SIGINT/SIGTERM stop observation \
and drain an application already admitted before reporting its actual result. A \
second signal forces termination and can prevent a final receipt."
)]
pub(super) struct LocalWatchArgs {
    /// First local directory to reconcile
    #[arg(value_name = "LOCAL")]
    local: PathBuf,
    /// Second local directory to reconcile; no remote transport is used
    #[arg(value_name = "REMOTE")]
    remote: PathBuf,
    /// Existing private directory containing persistent common history
    #[arg(long, value_name = "PATH")]
    state_dir: PathBuf,
    /// Create history in an empty private state directory without resetting prior history
    #[arg(long, action = ArgAction::SetTrue)]
    initialize: bool,
    /// Authorize future settled changes under the selected grants and finite application limit
    #[arg(long, action = ArgAction::SetTrue, requires_all = ["staging_dir", "max_applications"])]
    apply_changes: bool,
    /// Existing external directory retaining staging and original inodes
    #[arg(long, value_name = "PATH", requires = "apply_changes")]
    staging_dir: Option<PathBuf>,
    /// Maximum application attempts, including the initial pair and refused attempts (1..=1000000)
    #[arg(long, value_name = "N", requires = "apply_changes", value_parser = clap::value_parser!(u32).range(1..=1_000_000))]
    max_applications: Option<u32>,
    /// Stop after handling this many settled reviews, including the initial pair (1..=1000000)
    #[arg(long, value_name = "N", value_parser = clap::value_parser!(u32).range(1..=1_000_000))]
    max_reviews: Option<u32>,
    /// Authorize replacing existing files while retaining their original inodes
    #[arg(long, action = ArgAction::SetTrue, requires = "apply_changes")]
    allow_overwrite: bool,
    /// Accept content-only replacement without preserving hidden metadata
    #[arg(long, action = ArgAction::SetTrue, requires = "apply_changes")]
    allow_permission_change: bool,
    /// Authorize propagating deletions into quarantine
    #[arg(long, action = ArgAction::SetTrue, requires = "apply_changes")]
    allow_delete: bool,
    /// Minimum milliseconds between completed bounded scans (10..=3600000)
    #[arg(long, default_value_t = 1_000, value_parser = clap::value_parser!(u64).range(10..=3_600_000))]
    poll_interval_ms: u64,
    /// Equal consecutive inventory pairs required before reporting changes (1..=1024)
    #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u32).range(1..=1024))]
    settle_observations: u32,
    /// Maximum entries per tree, including directories (1..=1000000)
    #[arg(long, default_value_t = 100_000)]
    max_entries: usize,
    /// Maximum relative path depth (1..=256)
    #[arg(long, default_value_t = 64)]
    max_depth: usize,
    /// Maximum logical bytes in a regular file
    #[arg(long, default_value_t = 17_179_869_184_u64)]
    max_file_bytes: u64,
    /// Maximum logical file bytes per tree
    #[arg(long, default_value_t = 68_719_476_736_u64)]
    max_total_bytes: u64,
    /// Maximum bytes per persistent history slot (1..=67108864)
    #[arg(long, default_value_t = 67_108_864)]
    max_state_bytes: usize,
}

pub(super) fn run(args: &LocalWatchArgs, output: &mut Output) -> Result<(), CliError> {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        native::run(args, output)
    }
    #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
    {
        let _ = (args, output);
        Err(CliError::new(
            "atp_local_watch_unsupported",
            "Local directory watching requires Linux/glibc",
        )
        .exit_code(ExitCode::USER_ERROR))
    }
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
mod native {
    use super::{CliError, ExitCode, LocalWatchArgs, Output};
    use asupersync::atp::sync::native::{
        NativeDirectoryActionState, NativeDirectoryError, NativeDirectoryLimits,
        NativeDirectorySessionReport, NativeDirectoryStatePublication, NativeDirectorySyncSession,
        NativeDirectoryWatch, NativeDirectoryWatchConfig, NativeDirectoryWatchError,
    };
    use asupersync::atp::sync::{
        BidirectionalSyncAction, BidirectionalSyncDecision, DestructiveAuthorization,
    };
    use asupersync::channel::oneshot;
    use asupersync::cli::Outputtable;
    use asupersync::cx::Cx;
    use asupersync::fs::scoped::ScopedFsError;
    use asupersync::runtime::{JoinError, RootDrainOutcome, RuntimeBuilder};
    use asupersync::time::SleepError;
    use asupersync::types::CancelKind;
    use std::fmt::Write as _;
    use std::future::{Future, poll_fn};
    use std::path::{Path, PathBuf};
    use std::pin::pin;
    use std::task::Poll;
    use std::time::Duration;

    const MAX_CHANGED_SCAN_RETRIES: u32 = 8;

    #[derive(Debug, serde::Serialize)]
    struct WatchOutput {
        schema_version: u32,
        command: &'static str,
        mode: &'static str,
        #[serde(flatten)]
        event: WatchEvent,
    }

    #[derive(Debug, serde::Serialize)]
    #[serde(tag = "event", rename_all = "snake_case")]
    enum WatchEvent {
        Started {
            content_profile: &'static str,
            initialized: bool,
            local_root: PathBuf,
            remote_root: PathBuf,
            state_directory: PathBuf,
            staging_directory: Option<PathBuf>,
            baseline_generation: u64,
            poll_interval_ms: u64,
            settle_observations: u32,
            max_applications: Option<u32>,
            max_reviews: Option<u32>,
            allow_overwrite: bool,
            allow_permission_change: bool,
            allow_delete: bool,
        },
        Review(ReviewOutput),
        ObservationRetry {
            attempt: u32,
            max_retries: u32,
            failure: String,
        },
        Application {
            review: u64,
            application: u64,
            plan_id: String,
            result: Option<ApplicationOutput>,
            application_error: Option<String>,
        },
        Stopped {
            reason: &'static str,
            signal: Option<i32>,
            reviews: u64,
            applications: u64,
            baseline_generation: u64,
            last_plan_id: Option<String>,
            state_directory: PathBuf,
            staging_directory: Option<PathBuf>,
            failure: Option<String>,
            runtime_quiescent: bool,
            runtime_stopped: bool,
        },
    }

    #[derive(Debug, serde::Serialize)]
    struct ReviewOutput {
        review: u64,
        plan_id: String,
        baseline_generation: u64,
        local_bytes: u64,
        remote_bytes: u64,
        has_conflicts: bool,
        has_destructive_actions: bool,
        decisions: Vec<BidirectionalSyncDecision>,
    }

    #[derive(Debug, serde::Serialize)]
    struct ApplicationOutput {
        plan_id: String,
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
                plan_id: report.sync.plan_id,
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
        fn succeeded(&self, expected_id: &str) -> bool {
            self.plan_id == expected_id
                && self.complete
                && !self.dry_run
                && self.failure.is_none()
                && self.persistence_failure.is_none()
                && self.publication.state == "durable"
                && self.publication.generation == Some(self.baseline_generation)
                && self.actions.iter().all(|action| {
                    action.durable
                        && matches!(action.state, "unchanged" | "published" | "quarantined")
                })
        }
    }

    impl Outputtable for WatchOutput {
        fn human_format(&self) -> String {
            let mut text = String::new();
            match &self.event {
                WatchEvent::Started {
                    local_root,
                    remote_root,
                    state_directory,
                    baseline_generation,
                    initialized,
                    max_applications,
                    ..
                } => {
                    let _ = writeln!(
                        text,
                        "Local watch started ({})\n  Local: {}\n  Remote: {}\n  History: {} (generation {})",
                        self.mode,
                        local_root.display(),
                        remote_root.display(),
                        state_directory.display(),
                        baseline_generation,
                    );
                    if *initialized {
                        text.push_str("  Created history; no common baseline is implied.\n");
                    }
                    if let Some(limit) = max_applications {
                        let _ = writeln!(
                            text,
                            "  At most {limit} applications under the selected grants."
                        );
                    } else {
                        text.push_str("  Preview only; neither tree will be changed.\n");
                    }
                }
                WatchEvent::Review(review) => {
                    let _ = writeln!(
                        text,
                        "Local watch review {} (generation {})\n  Plan: {}",
                        review.review, review.baseline_generation, review.plan_id,
                    );
                    for decision in &review.decisions {
                        let _ =
                            writeln!(text, "  {:?}: {}", decision.action, decision.path.as_str());
                    }
                    if review.has_conflicts {
                        text.push_str("  Conflicts require explicit resolution.\n");
                    }
                }
                WatchEvent::ObservationRetry {
                    attempt,
                    max_retries,
                    failure,
                } => {
                    let _ = writeln!(
                        text,
                        "Inventory changed during observation ({attempt}/{max_retries}); retrying after the polling interval: {failure}"
                    );
                }
                WatchEvent::Application {
                    application,
                    plan_id,
                    result,
                    application_error,
                    ..
                } => {
                    let _ = writeln!(
                        text,
                        "Local watch application {application}\n  Plan: {plan_id}"
                    );
                    if let Some(result) = result {
                        let _ = writeln!(
                            text,
                            "  Tree complete: {}; history: {} (generation {})",
                            result.complete, result.publication.state, result.baseline_generation
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
                            let _ =
                                writeln!(text, "  Retained recovery directory: {}", path.display());
                        }
                        for failure in [&result.failure, &result.persistence_failure]
                            .into_iter()
                            .flatten()
                        {
                            let _ = writeln!(text, "  Failure: {failure}");
                        }
                    }
                    if let Some(error) = application_error {
                        let _ = writeln!(
                            text,
                            "  No application receipt: {error}\n  Inspect history and staging before retrying."
                        );
                    }
                }
                WatchEvent::Stopped {
                    reason,
                    reviews,
                    applications,
                    baseline_generation,
                    failure,
                    runtime_quiescent,
                    runtime_stopped,
                    ..
                } => {
                    let _ = writeln!(
                        text,
                        "Local watch stopped: {reason}\n  Reviews: {reviews}; applications: {applications}; generation: {baseline_generation}\n  Runtime quiescent: {runtime_quiescent}; stopped: {runtime_stopped}"
                    );
                    if let Some(error) = failure {
                        let _ = writeln!(text, "  Failure: {error}");
                    }
                }
            }
            text
        }
    }

    struct Progress {
        reason: &'static str,
        reviews: u64,
        applications: u64,
        generation: u64,
        last_plan_id: Option<String>,
    }

    struct StopReceiver {
        receiver: oneshot::Receiver<i32>,
        signal: Option<i32>,
        failed: bool,
    }

    impl StopReceiver {
        fn requested(&mut self) -> Result<bool, CliError> {
            if self.signal.is_some() {
                return Ok(true);
            }
            if self.failed {
                return Err(signal_listener_closed());
            }
            match self.receiver.try_recv() {
                Ok(signal) => {
                    self.signal = Some(signal);
                    Ok(true)
                }
                Err(oneshot::TryRecvError::Empty) => Ok(false),
                Err(oneshot::TryRecvError::Closed) => Err(signal_listener_closed()),
            }
        }
    }

    pub(super) fn run(args: &LocalWatchArgs, output: &mut Output) -> Result<(), CliError> {
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
        let (sender, receiver) = oneshot::channel();
        // Install before state work or the first readiness event. The signal
        // thread owns no Cx; only the root observation poll can request cancel.
        let _signals = SignalThread::start(sender)?;
        let mut stop = StopReceiver {
            receiver,
            signal: None,
            failed: false,
        };
        let runtime = RuntimeBuilder::current_thread()
            .blocking_threads(0, 4)
            .build()
            .map_err(|error| {
                CliError::new(
                    "atp_local_watch_runtime",
                    "Cannot start local watch runtime",
                )
                .detail(error.to_string())
                .exit_code(ExitCode::RUNTIME_ERROR)
            })?;
        let mut progress = Progress {
            reason: "initialization_failed",
            reviews: 0,
            applications: 0,
            generation: 0,
            last_plan_id: None,
        };
        let execution = runtime.block_on(execute(args, output, &mut stop, &mut progress));
        let quiescent = runtime.shutdown_drained(Duration::from_secs(30)).outcome
            == RootDrainOutcome::Quiescent;
        let stopped = runtime.shutdown_timeout(Duration::from_secs(30));
        let terminal = event(
            args,
            WatchEvent::Stopped {
                reason: progress.reason,
                signal: stop.signal,
                reviews: progress.reviews,
                applications: progress.applications,
                baseline_generation: progress.generation,
                last_plan_id: progress.last_plan_id,
                state_directory: args.state_dir.clone(),
                staging_directory: args.staging_dir.clone(),
                failure: execution.as_ref().err().map(ToString::to_string),
                runtime_quiescent: quiescent,
                runtime_stopped: stopped,
            },
        );
        let terminal_output = emit(output, &terminal);
        if let Err(error) = execution {
            let mut error = error
                .context("terminal", &terminal)
                .context("runtime_quiescent", quiescent)
                .context("runtime_stopped", stopped);
            if let Err(output_error) = terminal_output {
                error = error.context("terminal_output_error", output_error);
            }
            return Err(error);
        }
        terminal_output?;
        if !quiescent || !stopped {
            return Err(CliError::new(
                "atp_local_watch_shutdown",
                "Local watch runtime cleanup was not confirmed",
            )
            .context("terminal", &terminal)
            .exit_code(ExitCode::RUNTIME_ERROR));
        }
        Ok(())
    }

    fn event(args: &LocalWatchArgs, event: WatchEvent) -> WatchOutput {
        WatchOutput {
            schema_version: 1,
            command: "atp.local-watch",
            mode: if args.apply_changes {
                "apply_changes"
            } else {
                "preview"
            },
            event,
        }
    }

    fn emit(output: &mut Output, event: &WatchOutput) -> Result<(), CliError> {
        output.write(event).and_then(|()| output.flush()).map_err(|error| {
            // A prior apply has already happened. Preserve this entire bounded
            // event on stderr, and stop before any further application.
            super::super::output_write_error("local watch event")(error)
                .context("receipt", event)
                .suggestion("Retain the emitted receipts and inspect history and recovery paths before retrying; output failure does not roll back file effects")
        })
    }

    fn emit_progress(
        args: &LocalWatchArgs,
        output: &mut Output,
        progress: &mut Progress,
        value: WatchEvent,
    ) -> Result<(), CliError> {
        emit(output, &event(args, value)).inspect_err(|_| progress.reason = "output_failed")
    }

    fn validate_path(label: &str, path: &Path) -> Result<(), CliError> {
        if path.is_absolute() && path.to_str().is_some() {
            return Ok(());
        }
        Err(CliError::new(
            "atp_local_watch_path",
            "Local watch requires absolute UTF-8 paths",
        )
        .detail(format!("{label}: {}", path.display()))
        .exit_code(ExitCode::USER_ERROR))
    }

    fn native_error(stage: &str, error: impl std::fmt::Display) -> CliError {
        CliError::new(
            "atp_local_watch_refused",
            "Local watch operation was refused",
        )
        .detail(error.to_string())
        .context("stage", stage)
        .exit_code(ExitCode::USER_ERROR)
    }

    async fn execute(
        args: &LocalWatchArgs,
        output: &mut Output,
        stop: &mut StopReceiver,
        progress: &mut Progress,
    ) -> Result<(), CliError> {
        let cx = Cx::current().ok_or_else(|| {
            CliError::new(
                "atp_local_watch_context",
                "Local watch has no runtime context",
            )
            .exit_code(ExitCode::RUNTIME_ERROR)
        })?;
        if stop.requested()? {
            progress.reason = "signal";
            return Ok(());
        }
        let limits = NativeDirectoryLimits {
            max_entries: args.max_entries,
            max_depth: args.max_depth,
            max_file_bytes: args.max_file_bytes,
            max_total_bytes: args.max_total_bytes,
            ..NativeDirectoryLimits::default()
        };
        let session = if args.initialize {
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
        .map_err(|error| {
            native_error(
                if args.initialize {
                    "initialize"
                } else {
                    "reopen"
                },
                error,
            )
        })?;
        progress.generation = session.generation();
        let mut watch = session
            .into_watch(NativeDirectoryWatchConfig {
                poll_interval: Duration::from_millis(args.poll_interval_ms),
                settle_observations: args.settle_observations,
            })
            .map_err(|error| native_error("watch", error))?;
        let initial_generation = progress.generation;
        emit_progress(
            args,
            output,
            progress,
            WatchEvent::Started {
                content_profile: "linux-gnu-content-only-v1",
                initialized: args.initialize,
                local_root: args.local.clone(),
                remote_root: args.remote.clone(),
                state_directory: args.state_dir.clone(),
                staging_directory: args.staging_dir.clone(),
                baseline_generation: initial_generation,
                poll_interval_ms: args.poll_interval_ms,
                settle_observations: args.settle_observations,
                max_applications: args.max_applications,
                max_reviews: args.max_reviews,
                allow_overwrite: args.allow_overwrite,
                allow_permission_change: args.allow_permission_change,
                allow_delete: args.allow_delete,
            },
        )?;
        let mut changed_scan_retries = 0;
        loop {
            if stop.requested()? {
                progress.reason = "signal";
                return Ok(());
            }
            progress.reason = "observation_failed";
            let reviewed = next_review(&mut watch, &cx, stop, progress.reviews + 1).await;
            if stop.failed {
                return Err(signal_listener_closed().context(
                    "observation_error",
                    reviewed.as_ref().err().map(ToString::to_string),
                ));
            }
            let review = match reviewed {
                Ok(review) => review,
                Err(error) if stop.signal.is_some() && is_cancelled(&error) => {
                    progress.reason = "signal";
                    return Ok(());
                }
                Err(NativeDirectoryWatchError::Native(
                    error @ NativeDirectoryError::Changed { .. },
                )) if changed_scan_retries < MAX_CHANGED_SCAN_RETRIES && stop.signal.is_none() => {
                    changed_scan_retries += 1;
                    // Only a retired read-only scan is retried. The watch itself
                    // enforces the normal interval and resets coalescing state.
                    emit_progress(
                        args,
                        output,
                        progress,
                        WatchEvent::ObservationRetry {
                            attempt: changed_scan_retries,
                            max_retries: MAX_CHANGED_SCAN_RETRIES,
                            failure: error.to_string(),
                        },
                    )?;
                    continue;
                }
                Err(error) => return Err(native_error("observe", error)),
            };
            if stop.requested()? {
                progress.reason = "signal";
                return Ok(());
            }
            changed_scan_retries = 0;
            progress.reviews += 1;
            progress.last_plan_id = Some(review.plan_id.clone());
            let plan_id = review.plan_id.clone();
            emit_progress(args, output, progress, WatchEvent::Review(review))?;
            if stop.requested()? {
                progress.reason = "signal";
                return Ok(());
            }
            if args.apply_changes {
                let staging = args
                    .staging_dir
                    .as_ref()
                    .ok_or_else(|| native_error("apply", "--staging-dir is required"))?;
                let limit = args
                    .max_applications
                    .ok_or_else(|| native_error("apply", "--max-applications is required"))?;
                // Signal receipt is intentionally not polled during this await.
                // A stop arriving after the admission check remains queued until
                // the actual application and baseline publication have retired.
                progress.applications += 1;
                progress.reason = "application_incomplete";
                let authorization = DestructiveAuthorization {
                    dry_run: false,
                    allow_overwrite: args.allow_overwrite,
                    allow_permission_change: args.allow_permission_change,
                    allow_delete: args.allow_delete,
                    ..DestructiveAuthorization::default()
                };
                let applied = watch
                    .apply_pending(&cx, &plan_id, authorization, staging)
                    .await;
                progress.generation = watch.generation();
                let (result, application_error) = match applied {
                    Ok(report) => (Some(ApplicationOutput::from(report)), None),
                    Err(error) => (None, Some(error.to_string())),
                };
                let succeeded = !watch.is_stopped()
                    && result
                        .as_ref()
                        .is_some_and(|result| result.succeeded(&plan_id));
                let failure = application_error.clone().or_else(|| {
                    result.as_ref().and_then(|result| {
                        result
                            .failure
                            .clone()
                            .or_else(|| result.persistence_failure.clone())
                    })
                });
                let review_number = progress.reviews;
                let application_number = progress.applications;
                emit_progress(
                    args,
                    output,
                    progress,
                    WatchEvent::Application {
                        review: review_number,
                        application: application_number,
                        plan_id: plan_id.clone(),
                        result,
                        application_error,
                    },
                )?;
                if !succeeded {
                    return Err(CliError::new(
                        "atp_local_watch_incomplete",
                        "Local watch application did not complete durably",
                    )
                    .detail(failure.unwrap_or_else(|| {
                        "Tree convergence and durable common history were not both confirmed"
                            .to_owned()
                    }))
                    .context("plan_id", plan_id)
                    .context("state_directory", &args.state_dir)
                    .context("staging_directory", staging)
                    .exit_code(ExitCode::USER_ERROR));
                }
                if stop.requested()? {
                    progress.reason = "signal";
                    return Ok(());
                }
                if progress.applications >= u64::from(limit) {
                    progress.reason = "max_applications";
                    return Ok(());
                }
            } else {
                watch
                    .decline_pending(&plan_id)
                    .map_err(|error| native_error("decline", error))?;
            }
            if args
                .max_reviews
                .is_some_and(|limit| progress.reviews >= u64::from(limit))
            {
                progress.reason = "max_reviews";
                return Ok(());
            }
        }
    }

    async fn next_review(
        watch: &mut NativeDirectoryWatch,
        cx: &Cx,
        stop: &mut StopReceiver,
        review: u64,
    ) -> Result<ReviewOutput, NativeDirectoryWatchError> {
        let generation = watch.generation();
        let observe = async {
            let prepared = watch.next_review(cx).await?;
            Ok(ReviewOutput {
                review,
                plan_id: prepared.plan_id().to_owned(),
                baseline_generation: generation,
                local_bytes: prepared.local().total_bytes(),
                remote_bytes: prepared.remote().total_bytes(),
                has_conflicts: prepared.preview().has_conflicts(),
                has_destructive_actions: prepared.preview().has_destructive_actions(),
                decisions: prepared.preview().decisions.clone(),
            })
        };
        let mut observe = pin!(observe);
        // Public oneshot receive against a separate never-cancelled context:
        // no test-internals or ambient capability is required for notification.
        let signal_cx = Cx::detached_cancel_context();
        let mut signal = pin!(stop.receiver.recv(&signal_cx));
        poll_fn(|task| {
            if stop.signal.is_none() && !stop.failed {
                match signal.as_mut().poll(task) {
                    Poll::Ready(Ok(number)) => {
                        stop.signal = Some(number);
                        cx.cancel_with(
                            CancelKind::User,
                            Some("local watch stop requested by signal"),
                        );
                    }
                    Poll::Ready(Err(_)) => {
                        stop.failed = true;
                        cx.cancel_with(
                            CancelKind::User,
                            Some("local watch signal listener failed"),
                        );
                    }
                    Poll::Pending => {}
                }
            }
            // Never select away or drop an active inventory worker. Cancellation
            // is observed by its drained canonical path before we return.
            observe.as_mut().poll(task)
        })
        .await
    }

    fn is_cancelled(error: &NativeDirectoryWatchError) -> bool {
        match error {
            NativeDirectoryWatchError::Timer(SleepError::Cancelled(_)) => true,
            NativeDirectoryWatchError::Native(NativeDirectoryError::Checkpoint(error)) => {
                error.is_cancelled()
            }
            NativeDirectoryWatchError::Native(NativeDirectoryError::Runtime(
                ScopedFsError::Checkpoint(error),
            )) => error.is_cancelled(),
            NativeDirectoryWatchError::Native(NativeDirectoryError::Runtime(
                ScopedFsError::Join(JoinError::Cancelled(_)),
            )) => true,
            NativeDirectoryWatchError::Native(NativeDirectoryError::Runtime(
                ScopedFsError::Io(error),
            )) => error.kind() == std::io::ErrorKind::Interrupted,
            _ => false,
        }
    }

    struct SignalThread {
        handle: signal_hook::iterator::Handle,
        join: Option<std::thread::JoinHandle<()>>,
    }

    impl SignalThread {
        fn start(sender: oneshot::Sender<i32>) -> Result<Self, CliError> {
            let mut signals = signal_hook::iterator::Signals::new([
                signal_hook::consts::SIGINT,
                signal_hook::consts::SIGTERM,
            ])
            .map_err(signal_error)?;
            let handle = signals.handle();
            let join = std::thread::Builder::new()
                .name("asupersync-local-watch-signals".to_owned())
                .spawn(move || {
                    let mut sender = Some(sender);
                    for signal in signals.forever() {
                        if let Some(sender) = sender.take() {
                            let _ = sender.send_blocking(signal);
                        } else if signal_hook::low_level::emulate_default_handler(signal).is_err() {
                            std::process::exit(128 + signal);
                        }
                    }
                })
                .map_err(|error| {
                    handle.close();
                    signal_error(error)
                })?;
            Ok(Self {
                handle,
                join: Some(join),
            })
        }
    }

    impl Drop for SignalThread {
        fn drop(&mut self) {
            self.handle.close();
            if let Some(join) = self.join.take() {
                let _ = join.join();
            }
        }
    }

    fn signal_error(error: std::io::Error) -> CliError {
        CliError::new(
            "atp_local_watch_signal",
            "Cannot install local watch signal listener",
        )
        .detail(error.to_string())
        .exit_code(ExitCode::RUNTIME_ERROR)
    }

    fn signal_listener_closed() -> CliError {
        CliError::new(
            "atp_local_watch_signal",
            "Local watch signal listener stopped unexpectedly",
        )
        .exit_code(ExitCode::RUNTIME_ERROR)
    }
}
