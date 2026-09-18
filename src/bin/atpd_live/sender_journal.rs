//! Pre-EOF process recovery using the existing write-ahead sender protocol.
//!
//! A single child owns source revalidation, transmission and the journal. The
//! manager only polls joins for signals. Recovery never creates a new journal,
//! nonce or attempt budget, and never falls back to an ordinary unjournaled send.

use super::super::settings::{self, SendConfig, invalid};
use super::super::{emit, runtime};
use super::{Control, Options, authority, retryable, transfer_json};
use asupersync::Cx;
use asupersync::fs::File;
use asupersync::net::atp::sdk::native_auth::live::commit::resume::journal::SenderCheckpoint;
use asupersync::net::atp::sdk::native_auth::live::commit::resume::journal::file::{
    MAX_SENDER_JOURNAL_SNAPSHOTS, SenderJournalFile,
};
use asupersync::net::atp::sdk::native_auth::live::commit::resume::{
    ResumableSender, ResumeError, ResumeReport,
};
use asupersync::net::atp::sdk::native_auth::live::{LiveStreamError, LiveStreamSender};
use asupersync::runtime::JoinError;
use clap::Args;
use serde_json::{Value, json};
use signal_hook::consts::signal::{SIGINT, SIGTERM};
use signal_hook::iterator::Signals;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

#[derive(Args, Clone, Copy, Debug)]
pub(crate) struct CreateOptions {
    /// Lifetime attempt ceiling once the first negotiated snapshot is saved.
    #[arg(long)]
    attempts: u32,
    /// Lifetime journal snapshots, 1..=65536; never reset or compacted on reopen.
    #[arg(long)]
    max_snapshots: u32,
    #[arg(long, default_value_t = 250)]
    retry_delay_ms: u64,
}

impl CreateOptions {
    fn validate(self) -> io::Result<Options> {
        let options = Options {
            attempts: self.attempts,
            retry_delay_ms: self.retry_delay_ms,
        };
        options.validate()?;
        if !(1..=MAX_SENDER_JOURNAL_SNAPSHOTS).contains(&self.max_snapshots) {
            return Err(invalid("sender journal requires 1..=65536 snapshots"));
        }
        Ok(options)
    }
}

struct Initial {
    authority: LiveStreamSender,
    source: File,
    remote: SocketAddr,
    saved: Option<SenderCheckpoint>,
    attempts: u32,
}

struct Work {
    initial: Option<Initial>,
    session: Option<ResumableSender<File>>,
    journal: SenderJournalFile,
}

impl Work {
    async fn attempt(&mut self, cx: &Cx) -> Result<ResumeReport, ResumeError> {
        if let Some(initial) = self.initial.take() {
            self.session = Some(match initial.saved {
                Some(saved) => {
                    initial
                        .authority
                        .restore_journaled_reader(cx, initial.remote, initial.source, saved)
                        .await?
                }
                None => initial.authority.resumable_reader(
                    cx,
                    initial.remote,
                    initial.source,
                    initial.attempts,
                )?,
            });
        }
        let session = self.session.as_mut().ok_or(ResumeError::LocalFailure)?;
        Ok(session.send_journaled(cx, &mut self.journal).await)
    }
}

pub(crate) fn send(
    config: SendConfig,
    input: PathBuf,
    path: PathBuf,
    create: CreateOptions,
) -> io::Result<()> {
    let options = create.validate()?;
    let authority = authority(&config)?;
    let source = open_source(&config, &input)?;
    let signals = Signals::new([SIGINT, SIGTERM])?;
    // Validation precedes create-only publication. Never reuse an existing
    // journal as permission to create a new operation with a new nonce.
    let journal = SenderJournalFile::create_new(&path, create.max_snapshots)?;
    execute(config, options, authority, source, journal, None, signals)
}

pub(crate) fn resume(
    config: SendConfig,
    input: PathBuf,
    path: PathBuf,
    retry_delay_ms: u64,
) -> io::Result<()> {
    Options {
        attempts: 1,
        retry_delay_ms,
    }
    .validate()?;
    let authority = authority(&config)?;
    let source = open_source(&config, &input)?;
    let signals = Signals::new([SIGINT, SIGTERM])?;
    let journal = SenderJournalFile::open_existing(&path)?;
    let saved = journal.checkpoint()?;
    let options = Options {
        attempts: saved.maximum_attempts(),
        retry_delay_ms,
    };
    options.validate()?;
    execute(
        config,
        options,
        authority,
        source,
        journal,
        Some(saved),
        signals,
    )
}

fn open_source(config: &SendConfig, input: &std::path::Path) -> io::Result<std::fs::File> {
    let file = settings::open_regular(input, false)?;
    if file.metadata()?.len() > config.max_transfer_bytes {
        return Err(invalid("source exceeds transfer limit"));
    }
    Ok(file)
}

fn execute(
    config: SendConfig,
    options: Options,
    authority: LiveStreamSender,
    source: std::fs::File,
    journal: SenderJournalFile,
    saved: Option<SenderCheckpoint>,
    signals: Signals,
) -> io::Result<()> {
    let resumed = saved.is_some();
    let work = Work {
        initial: Some(Initial {
            authority,
            source: File::from_std(source),
            remote: config.remote,
            saved,
            attempts: options.attempts,
        }),
        session: None,
        journal,
    };
    let result = runtime(config.workers, async move {
        let cx = Cx::current().ok_or_else(|| io::Error::other("missing journal sender context"))?;
        drive(&cx, options, work, signals, resumed).await
    })?;
    // This boundary follows canonical joins AND successful runtime drain.
    emit(
        json!({"schema_version": 1, "event": "send_result", "journaled": true,
        "resumed": resumed, "source_free": false, "journal": result.journal,
        "transfer": result.transfer, "stopping": result.stopping, "drained": true,
        "final_proof_direction": if result.received { "received" } else { "not_received" }}),
    )?;
    if result.received {
        Ok(())
    } else {
        Err(io::Error::other(
            "journaled sender did not receive final Proof; retain source and journal",
        ))
    }
}

struct ResultRecord {
    transfer: Value,
    journal: Option<Value>,
    stopping: bool,
    received: bool,
}

fn journal_json(journal: &SenderJournalFile) -> Value {
    let saved = journal.checkpoint().ok();
    json!({"persisted_snapshots": journal.persisted_snapshots(),
        "maximum_snapshots": journal.maximum_snapshots(),
        "latest_available": saved.is_some(),
        "saved_attempts": saved.as_ref().map(SenderCheckpoint::attempts),
        "maximum_attempts": saved.as_ref().map(SenderCheckpoint::maximum_attempts),
        "source_position": saved.as_ref().map(SenderCheckpoint::source_position),
        "source_eof": saved.as_ref().map(SenderCheckpoint::source_eof),
        "saved_pending_bytes": saved.as_ref().map(SenderCheckpoint::pending_bytes)})
}

fn report_json(report: &ResumeReport) -> Value {
    let mut result = transfer_json(report);
    if let Err(ResumeError::Journal(error)) = &report.outcome {
        result["status"] = json!("journal_blocked");
        result["persistence"] = json!({"stored": error.stored,
        "storage_failed": error.source.is_some(),
        "storage_full": error.source.as_ref().is_some_and(|e| e.kind() == io::ErrorKind::StorageFull),
        "interruption": match error.interruption.as_deref() {
            Some(LiveStreamError::Cancelled(_)) => Some("cancelled"),
            Some(LiveStreamError::Timeout(_)) => Some("timeout"),
            Some(_) => Some("interrupted"), None => None,
        }});
    }
    result
}

async fn drive(
    cx: &Cx,
    options: Options,
    mut work: Work,
    signals: Signals,
    resumed: bool,
) -> io::Result<ResultRecord> {
    let scope = cx.scope();
    let mut control = Control {
        signals,
        reason: None,
    };
    let mut last = json!({"status": "cancelled", "receipt": null});
    loop {
        control.observe(cx);
        if control.reason.is_some() {
            return Ok(ResultRecord {
                transfer: last,
                journal: Some(journal_json(&work.journal)),
                stopping: true,
                received: false,
            });
        }
        let entered = Arc::new(AtomicBool::new(false));
        let worker_entered = Arc::clone(&entered);
        let task = cx.spawn_in(&scope, move |child| {
            let future: Pin<
                Box<dyn Future<Output = (Work, Result<ResumeReport, ResumeError>)> + Send>,
            > = Box::pin(async move {
                worker_entered.store(true, Ordering::Release);
                let result = work.attempt(&child).await;
                (work, result)
            });
            future
        });
        let mut task = match task {
            Ok(task) => task,
            Err(_) => {
                return Ok(ResultRecord {
                    transfer: json!({"status": "spawn_failed", "receipt": null, "previous_attempt": last}),
                    journal: None,
                    stopping: control.reason.is_some(),
                    received: false,
                });
            }
        };
        let (returned, outcome) = match control.join(cx, &mut task, &entered).await {
            Ok(result) => result,
            Err(error) => {
                return Ok(ResultRecord {
                    transfer: json!({"status": match error {
                    JoinError::Cancelled(_) => "join_cancelled", JoinError::Panicked(_) => "join_panicked",
                    JoinError::PolledAfterCompletion => "join_failed",
                }, "receipt": null, "previous_attempt": last}),
                    journal: None,
                    stopping: control.reason.is_some(),
                    received: false,
                });
            }
        };
        work = returned;
        let report = match outcome {
            Ok(report) => report,
            Err(error) => {
                return Ok(ResultRecord {
                    transfer: json!({"status": "preparation_refused", "receipt": null,
                    "attempts_exhausted": matches!(error, ResumeError::AttemptsExhausted),
                    "network_attempt_started": false}),
                    journal: Some(journal_json(&work.journal)),
                    stopping: control.reason.is_some(),
                    received: false,
                });
            }
        };
        let received = report.outcome.is_ok();
        let retry = report.outcome.as_ref().err().is_some_and(retryable);
        last = report_json(&report);
        emit(
            json!({"schema_version": 1, "event": "journal_attempt", "resumed": resumed,
            "transfer": last, "journal": journal_json(&work.journal),
            "retry_eligible": retry, "stopping": control.reason.is_some()}),
        )?;
        if received || !retry || report.attempts >= options.attempts || control.reason.is_some() {
            return Ok(ResultRecord {
                transfer: last,
                journal: Some(journal_json(&work.journal)),
                stopping: control.reason.is_some(),
                received,
            });
        }
        control.delay(cx, options.retry_delay_ms).await;
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::{Cli, Command};
    use super::*;
    use clap::Parser;

    #[test]
    fn new_journals_require_explicit_finite_snapshot_and_attempt_budgets() {
        for (attempts, snapshots, delay, valid) in [
            (4, 32, 250, true),
            (0, 32, 250, false),
            (1025, 32, 250, false),
            (4, 0, 250, false),
            (4, 65537, 250, false),
            (4, 32, 0, false),
        ] {
            assert_eq!(
                CreateOptions {
                    attempts,
                    max_snapshots: snapshots,
                    retry_delay_ms: delay
                }
                .validate()
                .is_ok(),
                valid
            );
        }
    }

    #[test]
    fn resume_requires_source_and_cannot_override_the_saved_budgets() {
        let args = [
            "atpd-live",
            "resume-journaled",
            "--config",
            "sender.json",
            "--input",
            "input.bin",
            "--journal",
            "sender.log",
        ];
        assert!(matches!(
            Cli::try_parse_from(args).unwrap().command,
            Command::ResumeJournaled { .. }
        ));
        for flag in ["--attempts", "--max-snapshots"] {
            let mut invalid = args.to_vec();
            invalid.extend([flag, "100"]);
            assert!(Cli::try_parse_from(invalid).is_err());
        }
        assert!(
            Cli::try_parse_from([
                "atpd-live",
                "resume-journaled",
                "--config",
                "sender.json",
                "--journal",
                "sender.log"
            ])
            .is_err()
        );
    }

    #[test]
    fn journal_failure_is_not_delivery_or_transport_retry_permission() {
        let error = ResumeError::Journal(Box::new(
            asupersync::net::atp::sdk::native_auth::live::commit::resume::journal::SenderCheckpointPersistError {
                stored: false, interruption: None, source: Some(io::ErrorKind::StorageFull.into()),
            },
        ));
        assert!(!retryable(&error));
        let report = ResumeReport {
            outcome: Err(error),
            prefix: None,
            attempts: 1,
            receipt_reused: false,
            retained_epoch_bytes: 8,
            sink_written_bytes: 0,
            completed: None,
        };
        let result = report_json(&report);
        assert_eq!(result["status"], "journal_blocked");
        assert_eq!(result["persistence"]["storage_full"], true);
        assert!(result["receipt"].is_null());
    }
}
