//! Reviewed local mirroring and retained-original recovery through native ATP.

use asupersync::cli::{CliError, ExitCode, Output};
use clap::{ArgAction, Args};
use std::path::PathBuf;

#[derive(Args, Debug)]
#[command(
    long_about = "Preview an authoritative mirror from SOURCE to DESTINATION, or apply a \
        reviewed content plan. Linux/glibc only. Uses the native ATP directory engine for \
        ordinary file contents and directory structure. Both trees must be exclusively \
        owned during the command. The default only captures and displays the plan.",
    after_long_help = "First run without --apply and inspect review_id and every decision. \
        Apply with --apply REVIEW_ID and an existing external --staging-dir on the trees' \
        shared filesystem. Staging must be owned by the effective user and not writable \
        by group or others. All paths must be absolute UTF-8 without symlink components. \
        Replacements require both --allow-overwrite and --allow-permission-change; \
        destination-only entries require --allow-delete. Originals remain in quarantine \
        with recovery paths in the receipt. Source permissions, timestamps, symlinks, \
        hard-link topology, sparse layout and platform metadata are not preserved; \
        unsupported input is refused. New files use 0600 and new directories 0700. \
        Retain the JSON application receipt for recovery. There is no whole-tree rollback."
)]
pub(super) struct MirrorArgs {
    /// Authoritative source directory
    #[arg(value_name = "SOURCE")]
    source: PathBuf,
    /// Directory to make equal to the source
    #[arg(value_name = "DESTINATION")]
    destination: PathBuf,
    /// Apply only if current content still matches this previously reviewed ID
    #[arg(long, value_name = "REVIEW_ID", value_parser = parse_review_id, requires = "staging_dir")]
    apply: Option<String>,
    /// Existing external directory in which to retain staging and recovery data
    #[arg(long, value_name = "PATH", requires = "apply")]
    staging_dir: Option<PathBuf>,
    /// Authorize replacing existing files, retaining their original inodes
    #[arg(long, action = ArgAction::SetTrue, requires = "apply")]
    allow_overwrite: bool,
    /// Accept content-only replacement without guaranteed preservation of hidden metadata
    #[arg(long, action = ArgAction::SetTrue, requires = "apply")]
    allow_permission_change: bool,
    /// Authorize moving destination-only entries into retained quarantine
    #[arg(long, action = ArgAction::SetTrue, requires = "apply")]
    allow_delete: bool,
    #[command(flatten)]
    limits: DirectoryLimitsArgs,
}

#[derive(Args, Debug)]
struct DirectoryLimitsArgs {
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
}

fn parse_review_id(value: &str) -> Result<String, String> {
    if value.len() == 64
        && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(value.to_owned())
    } else {
        Err("review ID must be the 64 lowercase hexadecimal characters from the preview".to_owned())
    }
}

pub(super) fn run_mirror(args: &MirrorArgs, output: &mut Output) -> Result<(), CliError> {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        native::run_mirror(args, output)
    }
    #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
    {
        let _ = (args, output);
        Err(CliError::new(
            "atp_local_mirror_unsupported",
            "Local directory mirroring requires Linux/glibc",
        )
        .exit_code(ExitCode::USER_ERROR))
    }
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
mod native {
    use super::{CliError, DirectoryLimitsArgs, ExitCode, MirrorArgs, Output};
    use asupersync::atp::sync::native::{
        NativeDirectoryActionReceipt, NativeDirectoryActionState, NativeDirectoryError,
        NativeDirectoryLimits, NativeDirectoryRecoverySource, NativeDirectorySyncReport,
        prepare_native_directory_mirror,
    };
    use asupersync::atp::sync::{
        BidirectionalSyncAction, BidirectionalSyncDecision, DestructiveAuthorization,
    };
    use asupersync::cli::Outputtable;
    use asupersync::cx::Cx;
    use asupersync::runtime::{RootDrainOutcome, RuntimeBuilder};
    use std::fmt::Write as _;
    use std::future::Future;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    const CONTENT_PROFILE: &str = "linux-gnu-content-only-v1";

    impl DirectoryLimitsArgs {
        fn native(&self) -> NativeDirectoryLimits {
            NativeDirectoryLimits {
                max_entries: self.max_entries,
                max_depth: self.max_depth,
                max_file_bytes: self.max_file_bytes,
                max_total_bytes: self.max_total_bytes,
                ..NativeDirectoryLimits::default()
            }
        }
    }

    #[derive(Debug, serde::Serialize)]
    struct MirrorOutput {
        schema_version: u32,
        command: &'static str,
        mode: &'static str,
        content_profile: &'static str,
        review_id: String,
        plan_id: String,
        source_root: PathBuf,
        destination_root: PathBuf,
        source_bytes: u64,
        destination_bytes: u64,
        has_conflicts: bool,
        has_destructive_actions: bool,
        decisions: Vec<BidirectionalSyncDecision>,
        result: Option<MirrorApplicationOutput>,
        application_error: Option<String>,
        runtime_quiescent: bool,
        runtime_stopped: bool,
    }

    #[derive(Debug, serde::Serialize)]
    struct MirrorApplicationOutput {
        complete: bool,
        dry_run: bool,
        staging_directory: Option<PathBuf>,
        failure: Option<String>,
        actions: Vec<ActionOutput>,
        recovery_source: NativeDirectoryRecoverySource,
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

    impl From<NativeDirectoryActionReceipt> for ActionOutput {
        fn from(receipt: NativeDirectoryActionReceipt) -> Self {
            Self {
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
            }
        }
    }

    impl From<NativeDirectorySyncReport> for MirrorApplicationOutput {
        fn from(report: NativeDirectorySyncReport) -> Self {
            let recovery_source = NativeDirectoryRecoverySource::from(&report);
            Self {
                complete: report.complete,
                dry_run: report.dry_run,
                staging_directory: report.staging_directory,
                failure: report.failure.map(|error| error.to_string()),
                actions: report.actions.into_iter().map(ActionOutput::from).collect(),
                recovery_source,
            }
        }
    }

    impl Outputtable for MirrorOutput {
        fn human_format(&self) -> String {
            let mut text = format!(
                "Local mirror {}\n  Source: {}\n  Destination: {}\n  Review ID: {}\n  Operation ID: {}\n  Profile: {}\n",
                self.mode,
                self.source_root.display(),
                self.destination_root.display(),
                self.review_id,
                self.plan_id,
                self.content_profile,
            );
            for decision in &self.decisions {
                let authorization = if decision.is_destructive() {
                    " [explicit authorization required]"
                } else {
                    ""
                };
                let _ = writeln!(text, "  {:?}: {}{authorization}", decision.action, decision.path.as_str());
            }
            if let Some(result) = &self.result {
                let _ = writeln!(text, "  Complete and verified: {}", result.complete);
                for action in &result.actions {
                    let _ = writeln!(text, "  {}: {} ({} bytes written, durable: {})",
                        action.path, action.state, action.bytes_written, action.durable);
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
                if let Some(error) = &result.failure {
                    let _ = writeln!(text, "  Failure: {error}");
                }
            } else if self.mode == "plan" {
                text.push_str("  Preview only. Apply with --apply REVIEW_ID, --staging-dir and the required grants.\n");
            }
            if let Some(error) = &self.application_error {
                let _ = writeln!(text, "  Application was not confirmed: {error}");
            }
            if !self.runtime_quiescent || !self.runtime_stopped {
                text.push_str("  Runtime cleanup was not confirmed.\n");
            }
            text
        }
    }

    pub(super) fn run_mirror(args: &MirrorArgs, output: &mut Output) -> Result<(), CliError> {
        validate_path("source", &args.source)?;
        validate_path("destination", &args.destination)?;
        if let Some(staging) = &args.staging_dir {
            validate_path("staging-dir", staging)?;
        }
        let (mut report, quiescent, stopped) = run_owned(prepare_and_apply_mirror(args))?;
        report.runtime_quiescent = quiescent;
        report.runtime_stopped = stopped;
        write_receipt(output, &report)?;
        if args.apply.is_some()
            && !report.result.as_ref().is_some_and(|result| {
                result.complete && !result.dry_run && result.failure.is_none()
            })
        {
            let detail = report.application_error.as_deref()
                .or_else(|| report.result.as_ref().and_then(|result| result.failure.as_deref()))
                .unwrap_or("The mirror did not return a complete verified application receipt");
            return Err(CliError::new("atp_local_mirror_incomplete", "Local mirroring did not complete")
                .detail(detail)
                .context("review_id", &report.review_id)
                .context("plan_id", &report.plan_id)
                .exit_code(ExitCode::USER_ERROR));
        }
        require_shutdown(quiescent, stopped)
    }

    async fn prepare_and_apply_mirror(args: &MirrorArgs) -> Result<MirrorOutput, CliError> {
        let cx = current_cx()?;
        let prepared = prepare_native_directory_mirror(
            &cx, &args.source, &args.destination, args.limits.native(),
        ).await.map_err(|error| native_error("mirror_prepare", error))?;
        // The content/root identity is stable for cross-process review. Each
        // attempt gets a separate recovery job so retained originals never
        // prevent a later mirror of the same contents after explicit recovery.
        let review_id = prepared.plan_id().to_owned();
        let prepared = prepared.with_fresh_plan_id(&cx)
            .map_err(|error| native_error("mirror_identity", error))?;
        let mut report = MirrorOutput {
            schema_version: 1,
            command: "atp.local-mirror",
            mode: if args.apply.is_some() { "apply" } else { "plan" },
            content_profile: CONTENT_PROFILE,
            review_id,
            plan_id: prepared.plan_id().to_owned(),
            source_root: prepared.local().root().to_path_buf(),
            destination_root: prepared.remote().root().to_path_buf(),
            source_bytes: prepared.local().total_bytes(),
            destination_bytes: prepared.remote().total_bytes(),
            has_conflicts: prepared.preview().has_conflicts(),
            has_destructive_actions: prepared.preview().has_destructive_actions(),
            decisions: prepared.preview().decisions.clone(),
            result: None,
            application_error: None,
            runtime_quiescent: false,
            runtime_stopped: false,
        };
        if let Some(reviewed) = &args.apply {
            if reviewed != &report.review_id {
                report.application_error = Some(format!(
                    "Reviewed ID {reviewed} does not match current mirror review {}; inspect the new plan before applying",
                    report.review_id,
                ));
                return Ok(report);
            }
            let staging = args.staging_dir.as_ref().ok_or_else(|| CliError::new(
                "atp_local_mirror_staging", "Applying a local mirror requires --staging-dir",
            ).exit_code(ExitCode::USER_ERROR))?;
            let authorization = DestructiveAuthorization {
                dry_run: false,
                allow_overwrite: args.allow_overwrite,
                allow_permission_change: args.allow_permission_change,
                allow_delete: args.allow_delete,
                ..DestructiveAuthorization::default()
            };
            match prepared.apply_with_quarantined_deletions(&cx, authorization, staging).await {
                Ok(result) => report.result = Some(result.into()),
                Err(error) => report.application_error = Some(error.to_string()),
            }
        }
        Ok(report)
    }

    fn current_cx() -> Result<Cx, CliError> {
        Cx::current().ok_or_else(|| CliError::new(
            "atp_local_operation_context", "Local directory operation has no runtime context",
        ).exit_code(ExitCode::RUNTIME_ERROR))
    }

    fn run_owned<T, F>(operation: F) -> Result<(T, bool, bool), CliError>
    where
        F: Future<Output = Result<T, CliError>>,
    {
        let runtime = RuntimeBuilder::current_thread().blocking_threads(0, 4).build()
            .map_err(|error| CliError::new(
                "atp_local_operation_runtime", "Cannot start local directory runtime",
            ).detail(error.to_string()).exit_code(ExitCode::RUNTIME_ERROR))?;
        let result = runtime.block_on(operation);
        let quiescent = runtime.shutdown_drained(Duration::from_secs(30)).outcome
            == RootDrainOutcome::Quiescent;
        let stopped = runtime.shutdown_timeout(Duration::from_secs(30));
        result.map(|value| (value, quiescent, stopped)).map_err(|error| error
            .context("runtime_quiescent", quiescent).context("runtime_stopped", stopped))
    }

    fn require_shutdown(quiescent: bool, stopped: bool) -> Result<(), CliError> {
        if quiescent && stopped {
            Ok(())
        } else {
            Err(CliError::new(
                "atp_local_operation_shutdown", "Local directory runtime cleanup was not confirmed",
            ).exit_code(ExitCode::RUNTIME_ERROR))
        }
    }

    fn write_receipt<T: Outputtable>(output: &mut Output, report: &T) -> Result<(), CliError> {
        let failed = |error| super::super::output_write_error("local directory receipt")(error)
            .context("receipt", report)
            .suggestion("Inspect the observed receipt and retained recovery paths before retrying; output failure does not roll back filesystem effects");
        output.write(report).map_err(&failed)?;
        output.flush().map_err(failed)
    }

    fn native_error(stage: &str, error: NativeDirectoryError) -> CliError {
        CliError::new("atp_local_operation_refused", "Local directory operation was refused")
            .detail(error.to_string()).context("stage", stage).exit_code(ExitCode::USER_ERROR)
    }

    fn validate_path(label: &str, path: &Path) -> Result<(), CliError> {
        if path.is_absolute() && path.to_str().is_some() {
            return Ok(());
        }
        Err(CliError::new("atp_local_operation_path", "Local directory operations require absolute UTF-8 paths")
            .detail(format!("{label}: {}", path.display())).exit_code(ExitCode::USER_ERROR))
    }
}
