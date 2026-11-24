//! Bounded, read-only recovery of trace evidence for the CLI.

use super::{
    TraceEventRow, io_error, output_write_error, replay_event_kind, replay_event_time_nanos,
    trace_file_error,
};
use asupersync::cli::{CliError, ExitCode, Output, Outputtable};
use asupersync::trace::{TraceMetadata, TraceRecoveryStatus, recover_trace_prefix};
use clap::Args;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

#[derive(Args, Debug)]
#[command(
    long_about = "Recover a contiguous event prefix from a damaged, unfinished, or finalized \
        trace without changing the source. --max-events is required; zero recovers only \
        header information. Recovered events and their terminal status are emitted as \
        one report. Partial or limit-reached recovery exits with code 5.",
    after_long_help = "--output saves the same report as JSON to a new file; existing files, \
        including the source trace, are never overwritten. The report is forensic evidence, \
        not a repaired trace or an executed replay. Only Complete recovery of a v3 container \
        verifies its event-stream checksum; legacy v1/v2 containers have no such checksum. \
        The event-count bound and existing per-frame/chunk limits are enforced; this command \
        does not impose a cumulative decoded-byte budget."
)]
pub struct RecoverArgs {
    /// Source trace; opened read-only
    #[arg(value_name = "INPUT")]
    input: PathBuf,

    /// Maximum recovered events; required, with zero allowed
    #[arg(long, value_name = "COUNT")]
    max_events: usize,

    /// Save the evidence report as JSON to a path that does not exist
    #[arg(long, value_name = "NEW_JSON")]
    output: Option<PathBuf>,
}

#[derive(Debug, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum RecoveryStatus {
    Complete,
    Partial { next_event: u64, error: String },
    LimitReached { max_events: usize },
}

impl RecoveryStatus {
    fn is_complete(&self) -> bool {
        matches!(self, Self::Complete)
    }

    fn label(&self) -> &'static str {
        match self {
            Self::Complete => "Complete",
            Self::Partial { .. } => "Partial",
            Self::LimitReached { .. } => "LimitReached",
        }
    }
}

impl From<TraceRecoveryStatus> for RecoveryStatus {
    fn from(status: TraceRecoveryStatus) -> Self {
        match status {
            TraceRecoveryStatus::Complete => Self::Complete,
            TraceRecoveryStatus::Partial { next_event, error } => {
                Self::Partial { next_event, error }
            }
            TraceRecoveryStatus::LimitReached { max_events } => Self::LimitReached { max_events },
        }
    }
}

#[derive(Debug, serde::Serialize)]
struct RecoveryOutput {
    schema_version: u32,
    command: &'static str,
    source: String,
    output: Option<String>,
    file_version: u16,
    metadata: TraceMetadata,
    declared_events: u64,
    recovered_events: usize,
    max_events: usize,
    status: RecoveryStatus,
    event_stream_verified: bool,
    replay_executed: bool,
    events: Vec<TraceEventRow>,
}

impl Outputtable for RecoveryOutput {
    fn human_format(&self) -> String {
        let mut lines = vec![
            format!("Trace recovery: {}", self.source),
            format!("Status: {}", self.status.label()),
            format!(
                "Recovered events: {} (declared {}; limit {})",
                self.recovered_events, self.declared_events, self.max_events
            ),
            format!("Container: v{}", self.file_version),
            format!(
                "Event-stream checksum verified: {}",
                if self.event_stream_verified { "yes" } else { "no" }
            ),
            String::from("Replay executed: no"),
        ];
        if !self.event_stream_verified {
            lines.push(String::from(
                "Recovered events are unverified evidence, not a verified replay trace.",
            ));
        }
        match &self.status {
            RecoveryStatus::Partial { next_event, error } => {
                lines.push(format!("Stopped before event {next_event}: {error}"));
            }
            RecoveryStatus::LimitReached { max_events } => {
                lines.push(format!("Stopped at the requested {max_events}-event limit."));
            }
            RecoveryStatus::Complete => {}
        }
        if let Some(path) = &self.output {
            lines.push(format!("Evidence JSON: {path}"));
        }
        lines.extend(self.events.iter().map(Outputtable::human_format));
        lines.join("\n")
    }
}

fn save_report(path: &Path, report: &RecoveryOutput) -> Result<(), CliError> {
    let mut bytes = serde_json::to_vec_pretty(report)
        .map_err(output_write_error("trace recovery JSON"))?;
    bytes.push(b'\n');
    // create_new is the final no-overwrite check, including symlinks and races
    // with another creator. The source is never opened for writing.
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                CliError::new("output_exists", "Recovery report destination already exists")
                    .detail("Choose a new JSON path; recovery never overwrites existing files")
                    .context("path", path.display().to_string())
                    .exit_code(ExitCode::USER_ERROR)
            } else {
                io_error(path, &error)
            }
        })?;
    file.write_all(&bytes).map_err(|error| io_error(path, &error))
}

pub fn run(args: &RecoverArgs, output: &mut Output) -> Result<(), CliError> {
    let recovery = recover_trace_prefix(&args.input, args.max_events)
        .map_err(|error| trace_file_error(&args.input, error))?;
    let status = RecoveryStatus::from(recovery.status);
    let report = RecoveryOutput {
        schema_version: 1,
        command: "trace recover",
        source: args.input.display().to_string(),
        output: args.output.as_ref().map(|path| path.display().to_string()),
        file_version: recovery.file_version,
        metadata: recovery.metadata,
        declared_events: recovery.declared_events,
        recovered_events: recovery.recovered_events.len(),
        max_events: args.max_events,
        event_stream_verified: recovery.file_version == 3 && status.is_complete(),
        status,
        replay_executed: false,
        events: recovery
            .recovered_events
            .into_iter()
            .enumerate()
            .map(|(index, event)| TraceEventRow {
                index: index as u64,
                kind: replay_event_kind(&event).to_string(),
                time_nanos: replay_event_time_nanos(&event),
                event,
            })
            .collect(),
    };
    if let Some(path) = &args.output {
        save_report(path, &report)?;
    }
    output
        .write(&report)
        .map_err(output_write_error("trace recovery report"))?;
    output
        .flush()
        .map_err(output_write_error("trace recovery report"))?;
    if report.status.is_complete() {
        Ok(())
    } else {
        // Flush before returning a partial result: main renders this diagnostic
        // on stderr and otherwise prioritizes it over a later flush failure.
        Err(CliError::new("trace_recovery_incomplete", "Trace recovery is incomplete")
            .detail("The emitted report contains the recovered prefix and its stopping reason")
            .context("status", report.status.label())
            .exit_code(ExitCode::PARTIAL_SUCCESS))
    }
}

#[cfg(test)]
#[path = "trace_recover_inline_tests.rs"]
mod tests;
