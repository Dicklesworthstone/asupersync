//! Executable sender EOF checkpointing and source-free final-Proof recovery.
//!
//! The existing SDK owns the wire and persistence barriers. One child owns both
//! the session and file store per attempt; its canonical join returns both.
//! Signal polling never drops the transfer. Recovery cannot open an input file.

use super::settings::{self, SendConfig, invalid};
use super::{emit, receipt_json, runtime};
use asupersync::Cx;
use asupersync::fs::File;
use asupersync::net::atp::sdk::native_auth::live::commit::resume::finalization::file::FinalProofFile;
use asupersync::net::atp::sdk::native_auth::live::commit::resume::finalization::{
    FinalProofCheckpoint, FinalProofSender,
};
use asupersync::net::atp::sdk::native_auth::live::commit::resume::{
    ResumableSender, ResumeError, ResumeReport,
};
use asupersync::net::atp::sdk::native_auth::live::{LiveStreamError, LiveStreamSender};
use asupersync::runtime::{JoinError, TaskHandle};
use asupersync::tls::TlsError;
use asupersync::types::CancelReason;
use clap::Args;
use rustls::pki_types::ServerName;
use serde_json::{Value, json};
use signal_hook::consts::signal::{SIGINT, SIGTERM};
use signal_hook::iterator::Signals;
use std::future::{Future, poll_fn};
use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

const CONTROL_TICK: Duration = Duration::from_millis(50);

#[derive(Args, Clone, Copy, Debug)]
pub(super) struct Options {
    /// Explicit total attempts for this process; not a persistent retry budget.
    #[arg(long)]
    attempts: u32,
    /// Delay only between eligible network retries; never creates a new session.
    #[arg(long, default_value_t = 250)]
    retry_delay_ms: u64,
}

impl Options {
    fn validate(self) -> io::Result<()> {
        if !(1..=1024).contains(&self.attempts) || !(1..=60_000).contains(&self.retry_delay_ms) {
            return Err(invalid(
                "checkpoint commands require 1..=1024 attempts and 1..=60000 ms retry delay",
            ));
        }
        Ok(())
    }
}

// Only Upload has a source. Neither recovery preparation nor its worker has an
// input path, source fallback, new nonce, or way to resend ObjectData.
enum Start {
    Upload(std::fs::File),
    Recover(Box<FinalProofCheckpoint>),
}
enum Transfer {
    Upload(Box<ResumableSender<File>>),
    Recover(Box<FinalProofSender>),
}
struct Work {
    transfer: Transfer,
    journal: FinalProofFile,
}
impl Work {
    async fn attempt(&mut self, cx: &Cx) -> ResumeReport {
        match &mut self.transfer {
            Transfer::Upload(sender) => sender.send_checkpointed(cx, &mut self.journal).await,
            Transfer::Recover(sender) => sender.send(cx).await,
        }
    }
}

struct Control {
    signals: Signals,
    reason: Option<CancelReason>,
}
impl Control {
    fn observe(&mut self, cx: &Cx) {
        let signalled = self.signals.pending().next().is_some();
        if self.reason.is_none() {
            self.reason = cx.cancel_reason().or_else(|| {
                signalled.then(|| CancelReason::user("atpd-live checkpoint sender shutdown"))
            });
        }
    }

    async fn join<T>(
        &mut self,
        cx: &Cx,
        task: &mut TaskHandle<T>,
        entered: &AtomicBool,
    ) -> Result<T, JoinError> {
        let mut aborted = false;
        loop {
            self.observe(cx);
            if !aborted && entered.load(Ordering::Acquire) {
                if let Some(reason) = &self.reason {
                    task.abort_with_reason(reason.clone());
                    aborted = true;
                }
            }
            // Drop only the join wait, never the task or a started store. A
            // cancelled manager still drains the same canonical child result.
            if let Ok(result) = asupersync::time::timeout(
                cx.now(),
                CONTROL_TICK,
                poll_fn(|ctx| task.poll_join(ctx)),
            )
            .await
            {
                return result;
            }
        }
    }

    async fn delay(&mut self, cx: &Cx, milliseconds: u64) {
        let until = cx.now().as_nanos().saturating_add(milliseconds * 1_000_000);
        loop {
            self.observe(cx);
            let remaining = until.saturating_sub(cx.now().as_nanos());
            if self.reason.is_some() || remaining == 0 {
                return;
            }
            asupersync::time::sleep(cx.now(), CONTROL_TICK.min(Duration::from_nanos(remaining)))
                .await;
        }
    }
}

fn authority(config: &SendConfig) -> io::Result<LiveStreamSender> {
    let profile = settings::profile(
        config.schema_version,
        config.workers,
        config.epoch_bytes,
        config.max_transfer_bytes,
        config.operation_timeout_secs,
    )?;
    if config.remote.port() == 0 {
        return Err(invalid("remote port must be nonzero"));
    }
    let name = ServerName::try_from(config.server_name.clone())
        .map_err(|_| invalid("invalid TLS server name"))?;
    settings::sdk(1, &profile)?
        .live_stream_sender(
            profile,
            name,
            settings::roots(&config.server_ca)?,
            settings::identity(&config.identity)?,
        )
        .map_err(|_| invalid("invalid authenticated checkpoint sender configuration"))
}

pub(super) fn send(
    config: SendConfig,
    input: PathBuf,
    checkpoint: PathBuf,
    options: Options,
) -> io::Result<()> {
    options.validate()?;
    let sender = authority(&config)?;
    let source = settings::open_regular(&input, false)?;
    if source.metadata()?.len() > config.max_transfer_bytes {
        return Err(invalid("source exceeds transfer limit"));
    }
    let signals = Signals::new([SIGINT, SIGTERM])?;
    // All configuration/input checks precede this create-only operation. An
    // existing checkpoint is NEVER interpreted as permission to start over.
    let journal = FinalProofFile::create_new(&checkpoint)?;
    execute(
        config,
        options,
        sender,
        Start::Upload(source),
        journal,
        signals,
    )
}

pub(super) fn recover(config: SendConfig, checkpoint: PathBuf, options: Options) -> io::Result<()> {
    options.validate()?;
    let sender = authority(&config)?;
    let signals = Signals::new([SIGINT, SIGTERM])?;
    let journal = FinalProofFile::open_existing(&checkpoint)?;
    let saved = journal.checkpoint()?;
    // Config supplies explicit endpoint/name agreement; the checkpoint cannot
    // silently redirect networking. The SDK also enforces current limits/pins.
    execute(
        config,
        options,
        sender,
        Start::Recover(Box::new(saved)),
        journal,
        signals,
    )
}

fn execute(
    config: SendConfig,
    options: Options,
    sender: LiveStreamSender,
    start: Start,
    journal: FinalProofFile,
    signals: Signals,
) -> io::Result<()> {
    let source_free = matches!(&start, Start::Recover(_));
    let result = runtime(config.workers, async move {
        let cx =
            Cx::current().ok_or_else(|| io::Error::other("missing checkpoint sender context"))?;
        let transfer = match start {
            Start::Upload(source) => sender
                .resumable_reader(&cx, config.remote, File::from_std(source), options.attempts)
                .map(|sender| Transfer::Upload(Box::new(sender))),
            Start::Recover(saved) => sender
                .restore_final_proof(&cx, config.remote, *saved, options.attempts)
                .map(|sender| Transfer::Recover(Box::new(sender))),
        }
        .map_err(|_| invalid("checkpoint sender admission, endpoint or current policy refused"))?;
        drive(
            &cx,
            options,
            Work { transfer, journal },
            signals,
            source_free,
        )
        .await
    })?;
    // Success is not printed inside a worker before runtime shutdown. Keep a
    // delivery receipt distinct from the checkpoint's unconfirmed intent.
    emit(
        json!({"schema_version": 1, "event": "send_result", "source_free": source_free,
        "checkpoint_persisted": result.persisted, "checkpoint_kind": "finalization_intent",
        "transfer": result.transfer, "stopping": result.stopping,
        "final_proof_direction": if result.received { "received" } else { "not_received" },
        "drained": true}),
    )?;
    if result.received {
        Ok(())
    } else {
        Err(io::Error::other(
            "checkpoint sender did not receive exact final peer Proof; reconcile saved intent",
        ))
    }
}

struct ResultRecord {
    transfer: Value,
    persisted: Option<bool>,
    received: bool,
    stopping: bool,
}

async fn drive(
    cx: &Cx,
    options: Options,
    mut work: Work,
    signals: Signals,
    source_free: bool,
) -> io::Result<ResultRecord> {
    let scope = cx.scope();
    let mut control = Control {
        signals,
        reason: None,
    };
    let mut last = json!({"status": "cancelled", "receipt": null, "attempts": 0});
    loop {
        control.observe(cx);
        if control.reason.is_some() {
            return Ok(ResultRecord {
                transfer: last,
                persisted: Some(work.journal.is_persisted()),
                received: false,
                stopping: true,
            });
        }
        let entered = Arc::new(AtomicBool::new(false));
        let worker_entered = Arc::clone(&entered);
        let task = cx.spawn_in(&scope, move |child| {
            let future: Pin<Box<dyn Future<Output = (Work, ResumeReport)> + Send>> =
                Box::pin(async move {
                    worker_entered.store(true, Ordering::Release);
                    let report = work.attempt(&child).await;
                    (work, report)
                });
            future
        });
        let mut task = match task {
            Ok(task) => task,
            Err(_) => {
                return Ok(ResultRecord {
                    transfer: json!({"status": "spawn_failed", "receipt": null, "previous_attempt": last}),
                    persisted: None,
                    received: false,
                    stopping: control.reason.is_some(),
                });
            }
        };
        let (returned, report) = match control.join(cx, &mut task, &entered).await {
            Ok(result) => result,
            Err(error) => {
                let status = match error {
                    JoinError::Cancelled(_) => "join_cancelled",
                    JoinError::Panicked(_) => "join_panicked",
                    JoinError::PolledAfterCompletion => "join_failed",
                };
                return Ok(ResultRecord {
                    transfer: json!({"status": status, "receipt": null, "previous_attempt": last}),
                    persisted: None,
                    received: false,
                    stopping: control.reason.is_some(),
                });
            }
        };
        work = returned;
        let received = report.outcome.is_ok();
        let retryable = report.outcome.as_ref().err().is_some_and(retryable);
        last = transfer_json(&report);
        // No active child remains when output is written. An output failure can
        // therefore terminate the manager without abandoning its attempt.
        emit(
            json!({"schema_version": 1, "event": "checkpoint_attempt", "source_free": source_free,
            "transfer": last, "checkpoint_persisted": work.journal.is_persisted(),
            "retry_eligible": retryable, "stopping": control.reason.is_some()}),
        )?;
        if received || !retryable || report.attempts >= options.attempts || control.reason.is_some()
        {
            return Ok(ResultRecord {
                transfer: last,
                persisted: Some(work.journal.is_persisted()),
                received,
                stopping: control.reason.is_some(),
            });
        }
        control.delay(cx, options.retry_delay_ms).await;
    }
}

fn retryable(error: &ResumeError) -> bool {
    match error {
        ResumeError::Transfer(LiveStreamError::Timeout(_)) => true,
        ResumeError::Transfer(LiveStreamError::Io(error))
        | ResumeError::Transfer(LiveStreamError::Tls(TlsError::Io(error))) => matches!(
            error.kind(),
            io::ErrorKind::ConnectionRefused
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::ConnectionAborted
                | io::ErrorKind::BrokenPipe
                | io::ErrorKind::NotConnected
                | io::ErrorKind::TimedOut
                | io::ErrorKind::UnexpectedEof
                | io::ErrorKind::Interrupted
                | io::ErrorKind::WouldBlock
                | io::ErrorKind::NetworkUnreachable
                | io::ErrorKind::HostUnreachable
                | io::ErrorKind::NetworkDown
        ),
        // In particular, a failed or interrupted persistence barrier is not
        // bypassed by another send or silently replaced with a fresh checkpoint.
        _ => false,
    }
}

fn transfer_json(report: &ResumeReport) -> Value {
    let status = match &report.outcome {
        Ok(_) => "complete",
        Err(ResumeError::Checkpoint(_)) => "checkpoint_blocked",
        Err(ResumeError::AttemptsExhausted) => "attempts_exhausted",
        Err(ResumeError::LocalFailure) => "local_failure",
        Err(ResumeError::PeerIdentity) => "peer_identity_refused",
        Err(ResumeError::Continuity(_)) => "continuity_refused",
        Err(ResumeError::Transfer(LiveStreamError::Timeout(_))) => "timeout",
        Err(ResumeError::Transfer(LiveStreamError::Cancelled(_))) => "cancelled",
        Err(ResumeError::Transfer(
            LiveStreamError::Tls(_) | LiveStreamError::Authentication(_),
        )) => "tls_failed",
        Err(ResumeError::Transfer(LiveStreamError::TooLarge(_))) => "size_refused",
        Err(_) => "transfer_failed",
    };
    let persistence = match &report.outcome {
        Err(ResumeError::Checkpoint(error)) => Some(json!({
            "stored": error.stored, "storage_failed": error.source.is_some(),
            "interruption": match error.interruption.as_deref() {
                Some(LiveStreamError::Cancelled(_)) => Some("cancelled"),
                Some(LiveStreamError::Timeout(_)) => Some("timeout"),
                Some(_) => Some("interrupted"), None => None,
            },
        })),
        _ => None,
    };
    json!({"status": status, "receipt": report.outcome.as_ref().ok().map(receipt_json),
        "completed_receipt": report.completed.as_ref().map(receipt_json),
        "acknowledged_prefix_bytes": report.prefix.as_ref().map(|prefix| prefix.bytes),
        "attempts": report.attempts, "receipt_reused": report.receipt_reused,
        "retained_epoch_bytes": report.retained_epoch_bytes, "persistence": persistence})
}

#[cfg(test)]
#[path = "sender_checkpoint_tests.rs"]
mod tests;

#[path = "sender_journal.rs"]
pub(super) mod journal;
