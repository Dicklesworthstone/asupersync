//! One explicitly owned journaled receiver across connection and process loss.
//!
//! The SDK owns WAL ordering and byte revalidation. This command owns admission,
//! signals and joined attempts; it never reopens a different sink or starts a
//! new session on recovery. The private data path is visible while incomplete.

use super::settings::{self, ServeConfig, invalid};
use super::{INBOX_OWNERSHIP, emit, receipt_json, runtime, storage};
use asupersync::Cx;
use asupersync::net::atp::sdk::NativeClientAuthorization;
use asupersync::net::atp::sdk::native_auth::live::commit::LiveStreamCommitError;
use asupersync::net::atp::sdk::native_auth::live::commit::resume::receiver_journal::file::{
    JournaledFileReceiver, ReceiverFileLimits, ReceiverJournalFile,
};
use asupersync::net::atp::sdk::native_auth::live::commit::resume::receiver_journal::{
    ReceiverCheckpoint, ReceiverCheckpointPhase,
};
use asupersync::net::atp::sdk::native_auth::live::commit::resume::{
    RESUMABLE_LIVE_ALPN, ResumeError, ResumeReport,
};
use asupersync::net::atp::sdk::native_auth::live::{LiveStreamError, LiveStreamReceipt};
use asupersync::runtime::{JoinError, TaskHandle};
use asupersync::types::CancelReason;
use clap::Args;
use serde_json::{Value, json};
use signal_hook::consts::signal::{SIGINT, SIGTERM};
use signal_hook::iterator::Signals;
use std::future::{Future, poll_fn};
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

const TICK: Duration = Duration::from_millis(50);

#[derive(Args, Clone, Copy, Debug)]
pub(super) struct WaitOptions {
    /// Delay between eligible attempts; does not reset persistent budgets.
    #[arg(long, default_value_t = 250)]
    retry_delay_ms: u64,
    /// Absolute final-Proof recovery window, not renewed by reconnects.
    #[arg(long, default_value_t = 30)]
    proof_recovery_secs: u64,
}
impl WaitOptions {
    fn validate(self) -> io::Result<()> {
        if !(1..=60_000).contains(&self.retry_delay_ms)
            || !(1..=86_400).contains(&self.proof_recovery_secs)
        {
            return Err(invalid("invalid journaled receiver retry or Proof window"));
        }
        Ok(())
    }
}

#[derive(Args, Clone, Copy, Debug)]
pub(super) struct CreateOptions {
    /// Lifetime attempts for this receiver, including accepts and failed handshakes.
    #[arg(long)]
    attempts: u32,
    /// Immutable maximum number of persisted receiver snapshots.
    #[arg(long)]
    max_snapshots: u32,
    /// Immutable total WAL byte ceiling, including plaintext pending epochs.
    #[arg(long)]
    max_journal_bytes: u64,
    #[command(flatten)]
    wait: WaitOptions,
}
impl CreateOptions {
    fn limits(self, max_data_bytes: u64) -> io::Result<ReceiverFileLimits> {
        self.wait.validate()?;
        if !(1..=1024).contains(&self.attempts)
            || !(1..=65_536).contains(&self.max_snapshots)
            || !(96..=134_217_728).contains(&self.max_journal_bytes)
        {
            return Err(invalid(
                "invalid journaled receiver attempt or storage budgets",
            ));
        }
        Ok(ReceiverFileLimits {
            max_data_bytes,
            max_snapshots: self.max_snapshots,
            max_journal_bytes: self.max_journal_bytes,
        })
    }
}

pub(super) fn receive(
    config: ServeConfig,
    journal: PathBuf,
    data: PathBuf,
    options: CreateOptions,
) -> io::Result<()> {
    options.limits(config.max_transfer_bytes)?;
    execute(config, journal, data, Some(options), options.wait)
}

pub(super) fn resume(
    config: ServeConfig,
    journal: PathBuf,
    data: PathBuf,
    wait: WaitOptions,
) -> io::Result<()> {
    wait.validate()?;
    execute(config, journal, data, None, wait)
}

fn checked_paths(
    config: &ServeConfig,
    journal: &Path,
    data: &Path,
) -> io::Result<(PathBuf, PathBuf)> {
    if config.clients.len() != 1 || config.max_connections != 1 {
        return Err(invalid(
            "journaled receiving requires exactly one client and max_connections=1",
        ));
    }
    let normalize = |path: &Path| -> io::Result<PathBuf> {
        if !path.is_absolute() {
            return Err(invalid("absolute journal and data paths required"));
        }
        let name = path
            .file_name()
            .ok_or_else(|| invalid("file name required"))?;
        let parent = path
            .parent()
            .ok_or_else(|| invalid("private parent required"))?;
        let metadata = std::fs::symlink_metadata(parent)?;
        if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
            return Err(invalid(
                "journal and data parents must be private directories, not symlinks",
            ));
        }
        Ok(std::fs::canonicalize(parent)?.join(name))
    };
    let journal = normalize(journal)?;
    let data = normalize(data)?;
    let inbox = std::fs::canonicalize(&config.clients[0].directory)?;
    if data.parent() != Some(inbox.as_path())
        || journal.parent() == Some(inbox.as_path())
        || data
            .file_name()
            .is_some_and(|name| name == ".atpd-live.lock")
    {
        return Err(invalid(
            "data must be in the selected inbox and journal outside it",
        ));
    }
    Ok((journal, data))
}

fn execute(
    config: ServeConfig,
    journal: PathBuf,
    data: PathBuf,
    create: Option<CreateOptions>,
    wait: WaitOptions,
) -> io::Result<()> {
    wait.validate()?;
    let (journal_path, data_path) = checked_paths(&config, &journal, &data)?;
    if !(1..=86_400).contains(&config.shutdown_grace_secs)
        || (create.is_none() && config.bind.port() == 0)
    {
        return Err(invalid(
            "restore requires the original nonzero port and a bounded shutdown grace",
        ));
    }
    let profile = settings::profile(
        config.schema_version,
        config.workers,
        config.epoch_bytes,
        config.max_transfer_bytes,
        config.operation_timeout_secs,
    )?;
    let client = settings::selector(&config.clients[0].certificate_sha256)?;
    let authorization =
        NativeClientAuthorization::new(settings::roots(&config.client_ca)?, [client])
            .map_err(|_| invalid("invalid journaled receiver authorization"))?;
    let authority = settings::sdk(1, &profile)?
        .live_stream_receiver(
            profile,
            settings::identity(&config.identity)?,
            authorization,
        )
        .map_err(|_| invalid("invalid journaled receiver credentials"))?;
    let signals = Signals::new([SIGINT, SIGTERM])?;
    let inboxes = Arc::new(storage::load(&config.clients)?);
    INBOX_OWNERSHIP
        .set(Arc::clone(&inboxes))
        .map_err(|_| io::Error::other("foreground process already owns inboxes"))?;
    let inbox = inboxes
        .get(&client)
        .ok_or_else(|| invalid("selected inbox missing"))?;
    let (journal, attempts) = match create {
        Some(options) => {
            // One data entry, not the two aliases used by LiveFileSink. Charge
            // before either file can be created; never refund an uncertain write.
            inbox.reserve_private_file(config.max_transfer_bytes, None)?;
            (
                ReceiverJournalFile::create_new(
                    &journal_path,
                    &data_path,
                    options.limits(config.max_transfer_bytes)?,
                )?,
                options.attempts,
            )
        }
        None => {
            let journal = ReceiverJournalFile::open_existing(&journal_path, &data_path)?;
            let saved = journal.checkpoint()?;
            if saved.client() != client
                || saved.phase() == ReceiverCheckpointPhase::Finalizing
                || saved.attempts() >= saved.maximum_attempts()
            {
                return Err(invalid(
                    "receiver history is unresolved, exhausted or belongs to another client",
                ));
            }
            let length = settings::open_regular(&data_path, true)?.metadata()?.len();
            if length > config.max_transfer_bytes {
                return Err(invalid("retained data exceeds current limit"));
            }
            if saved.phase() == ReceiverCheckpointPhase::Receiving {
                // The locked startup scan already charged existing bytes/entry.
                // Reserve only remaining growth; otherwise restart can bypass
                // the disk ceiling or incorrectly charge a second transfer.
                inbox.reserve_private_file(config.max_transfer_bytes, Some(length))?;
            }
            let attempts = saved.maximum_attempts();
            (journal, attempts)
        }
    };
    let restored = create.is_none();
    let outcome = runtime(config.workers, async move {
        let cx =
            Cx::current().ok_or_else(|| io::Error::other("missing journaled receiver context"))?;
        let scope = cx.scope();
        let mut control = Control::new(signals, config.shutdown_grace_secs);
        let entered = Arc::new(AtomicBool::new(false));
        let worker_entered = Arc::clone(&entered);
        let mut task = cx
            .spawn_in(&scope, move |child| {
                let future: Pin<
                    Box<dyn Future<Output = Result<JournaledFileReceiver, ResumeError>> + Send>,
                > = Box::pin(async move {
                    worker_entered.store(true, Ordering::Release);
                    if restored {
                        journal
                            .bind_restored(&authority, &child, config.bind, client)
                            .await
                    } else {
                        journal
                            .bind_new(&authority, &child, config.bind, client, attempts)
                            .await
                    }
                });
                future
            })
            .map_err(|_| io::Error::other("journaled receiver preparation admission failed"))?;
        let incoming = match control.join(&cx, &mut task, &entered).await {
            Ok(Ok(incoming)) => incoming,
            Ok(Err(_)) => return Ok(End::refused("preparation_refused")),
            Err(_) => return Ok(End::refused("preparation_join_failed")),
        };
        let durable = incoming
            .checkpoint()
            .ok()
            .and_then(|saved| saved.committed_receipt());
        control.observe(&cx);
        if control.stopping() {
            return Ok(End {
                transfer: json!({"status": "cancelled_before_admission"}),
                checkpoint: checkpoint_json(incoming.checkpoint().ok().as_ref()),
                durable,
                proof_written: false,
                failed: false,
                stop: "stopped",
            });
        }
        emit(
            json!({"schema_version": 1, "event": "ready", "address": incoming.local_addr()?,
            "pid": std::process::id(), "mode": "journaled_single", "restored": restored,
            "profile": String::from_utf8_lossy(RESUMABLE_LIVE_ALPN), "attempt_limit": attempts,
            "data_visibility": "private_in_place", "atomic_publication": false,
            "checkpoint": checkpoint_json(incoming.checkpoint().ok().as_ref())}),
        )?;
        if durable.is_some() {
            control.open_proof_window(cx.now().as_nanos(), wait.proof_recovery_secs);
        }
        drive(&cx, incoming, attempts, wait, control, durable).await
    })?;
    // Actual joins and runtime drain precede this terminal observation.
    emit(
        json!({"schema_version": 1, "event": "receive_result", "restored": restored,
        "transfer": outcome.transfer, "checkpoint": outcome.checkpoint,
        "durable_receipt": outcome.durable.as_ref().map(receipt_json),
        "proof_write_confirmed": outcome.proof_written, "sender_receipt_observed": false,
        "stop_reason": outcome.stop, "drained": true, "atomic_publication": false}),
    )?;
    if outcome.durable.is_some() && !outcome.failed {
        Ok(())
    } else {
        Err(io::Error::other(
            "journaled receiver incomplete or unconfirmed; retained files require reconciliation",
        ))
    }
}

struct Control {
    signals: Signals,
    stopping_at: Option<u64>,
    grace_ns: u64,
    reason: Option<CancelReason>,
    proof_until: Option<u64>,
}
impl Control {
    fn new(signals: Signals, grace_secs: u64) -> Self {
        Self {
            signals,
            stopping_at: None,
            grace_ns: grace_secs * 1_000_000_000,
            reason: None,
            proof_until: None,
        }
    }
    fn open_proof_window(&mut self, now: u64, seconds: u64) {
        self.proof_until = Some(first_deadline(self.proof_until, now, seconds));
    }
    fn observe(&mut self, cx: &Cx) {
        let now = cx.now().as_nanos();
        for _ in self.signals.pending() {
            if self.stopping_at.is_some() {
                self.reason.get_or_insert_with(|| {
                    CancelReason::user("journaled receiver repeated shutdown signal")
                });
            } else {
                self.stopping_at = Some(now);
            }
        }
        if let Some(reason) = cx.cancel_reason() {
            self.reason.get_or_insert(reason);
        }
        if self
            .stopping_at
            .is_some_and(|start| now.saturating_sub(start) >= self.grace_ns)
        {
            self.reason.get_or_insert_with(|| {
                CancelReason::user("journaled receiver shutdown grace expired")
            });
        }
        if self.proof_until.is_some_and(|until| now >= until) {
            self.reason.get_or_insert_with(|| {
                CancelReason::user("journaled receiver Proof window expired")
            });
        }
    }
    fn stopping(&self) -> bool {
        self.stopping_at.is_some() || self.reason.is_some()
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
            if let Ok(result) =
                asupersync::time::timeout(cx.now(), TICK, poll_fn(|ctx| task.poll_join(ctx))).await
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
            if self.stopping() || remaining == 0 {
                return;
            }
            asupersync::time::sleep(cx.now(), TICK.min(Duration::from_nanos(remaining))).await;
        }
    }
}

fn first_deadline(previous: Option<u64>, now: u64, seconds: u64) -> u64 {
    previous.unwrap_or_else(|| now.saturating_add(seconds.saturating_mul(1_000_000_000)))
}

struct End {
    transfer: Value,
    checkpoint: Value,
    durable: Option<LiveStreamReceipt>,
    proof_written: bool,
    failed: bool,
    stop: &'static str,
}
impl End {
    fn refused(status: &'static str) -> Self {
        Self {
            transfer: json!({"status": status}),
            checkpoint: Value::Null,
            durable: None,
            proof_written: false,
            failed: true,
            stop: status,
        }
    }
}

async fn drive(
    cx: &Cx,
    mut incoming: JournaledFileReceiver,
    attempts: u32,
    wait: WaitOptions,
    mut control: Control,
    durable: Option<LiveStreamReceipt>,
) -> io::Result<End> {
    let scope = cx.scope();
    let mut end = End {
        transfer: json!({"status": "not_attempted"}),
        checkpoint: checkpoint_json(incoming.checkpoint().ok().as_ref()),
        durable,
        proof_written: false,
        failed: false,
        stop: "attempts_exhausted",
    };
    loop {
        control.observe(cx);
        if control.stopping() {
            end.stop = "stopped";
            return Ok(end);
        }
        let entered = Arc::new(AtomicBool::new(false));
        let worker_entered = Arc::clone(&entered);
        let task = cx.spawn_in(&scope, move |child| {
            let future: Pin<
                Box<dyn Future<Output = (JournaledFileReceiver, ResumeReport)> + Send>,
            > = Box::pin(async move {
                worker_entered.store(true, Ordering::Release);
                let report = incoming.receive(&child).await;
                (incoming, report)
            });
            future
        });
        let mut task = match task {
            Ok(task) => task,
            Err(_) => {
                end.failed = true;
                end.stop = "spawn_failed";
                end.checkpoint = Value::Null;
                return Ok(end);
            }
        };
        let (returned, report) = match control.join(cx, &mut task, &entered).await {
            Ok(result) => result,
            Err(_) => {
                end.failed = true;
                end.stop = "join_failed";
                end.checkpoint = Value::Null;
                return Ok(end);
            }
        };
        incoming = returned;
        let saved = incoming.checkpoint().ok();
        if let Some(receipt) = saved
            .as_ref()
            .and_then(ReceiverCheckpoint::committed_receipt)
        {
            end.durable = Some(receipt);
            control.open_proof_window(cx.now().as_nanos(), wait.proof_recovery_secs);
        }
        end.proof_written |= report.outcome.is_ok();
        end.checkpoint = checkpoint_json(saved.as_ref());
        end.transfer = transfer_json(&report);
        let retry = report.outcome.as_ref().err().is_some_and(retryable);
        emit(
            json!({"schema_version": 1, "event": "receiver_journal_attempt",
            "transfer": end.transfer, "checkpoint": end.checkpoint,
            "retry_eligible": retry, "sender_receipt_observed": false,
            "stopping": control.stopping()}),
        )?;
        if report.outcome.is_err() && !retry {
            // Cancellation may interrupt a successfully drained store. Preserve
            // stored data, but do not make uncertainty an automatic retry policy.
            end.failed = !matches!(
                &report.outcome,
                Err(ResumeError::Transfer(LiveStreamError::Cancelled(_)))
            ) || end.durable.is_none();
            end.stop = "attempt_failed";
            return Ok(end);
        }
        if report.attempts >= attempts {
            return Ok(end);
        }
        control.delay(cx, wait.retry_delay_ms).await;
    }
}

fn retryable(error: &ResumeError) -> bool {
    match error {
        ResumeError::PeerIdentity | ResumeError::Continuity(_) => true,
        ResumeError::Transfer(
            LiveStreamError::Timeout(_)
            | LiveStreamError::Tls(_)
            | LiveStreamError::Frame(_)
            | LiveStreamError::Protocol(_),
        ) => true,
        ResumeError::Transfer(LiveStreamError::Io(error)) => matches!(
            error.kind(),
            io::ErrorKind::ConnectionReset
                | io::ErrorKind::ConnectionAborted
                | io::ErrorKind::BrokenPipe
                | io::ErrorKind::NotConnected
                | io::ErrorKind::TimedOut
                | io::ErrorKind::UnexpectedEof
                | io::ErrorKind::Interrupted
                | io::ErrorKind::WouldBlock
        ),
        ResumeError::Transfer(LiveStreamError::Commit(error)) => matches!(
            error.as_ref(),
            LiveStreamCommitError::CommittedWithoutProof { .. }
        ),
        _ => false,
    }
}

fn checkpoint_json(saved: Option<&ReceiverCheckpoint>) -> Value {
    saved.map_or(Value::Null, |saved| {
        json!({
            "phase": match saved.phase() {
                ReceiverCheckpointPhase::Receiving => "receiving",
                ReceiverCheckpointPhase::Finalizing => "finalizing",
                ReceiverCheckpointPhase::Committed => "committed",
                _ => "unsupported",
            }, "prefix_bytes": saved.prefix().bytes, "pending_bytes": saved.pending_bytes(),
            "attempts": saved.attempts(), "maximum_attempts": saved.maximum_attempts(),
            "committed_receipt": saved.committed_receipt().as_ref().map(receipt_json),
        })
    })
}

fn transfer_json(report: &ResumeReport) -> Value {
    let status = match &report.outcome {
        Ok(_) => "complete",
        Err(ResumeError::ReceiverJournal(_)) => "journal_blocked",
        Err(ResumeError::LocalFailure) => "local_failure",
        Err(ResumeError::AttemptsExhausted) => "attempts_exhausted",
        Err(ResumeError::PeerIdentity) => "peer_identity_refused",
        Err(ResumeError::Continuity(_)) => "continuity_refused",
        Err(ResumeError::Transfer(LiveStreamError::Cancelled(_))) => "cancelled",
        Err(ResumeError::Transfer(LiveStreamError::Timeout(_))) => "timeout",
        Err(ResumeError::Transfer(LiveStreamError::Tls(_))) => "tls_failed",
        Err(_) => "transfer_failed",
    };
    let persistence = match &report.outcome {
        Err(ResumeError::ReceiverJournal(error)) => Some(json!({
            "stored": error.stored, "storage_failed": error.source.is_some(),
            "storage_full": error.source.as_ref().is_some_and(|e| e.kind() == io::ErrorKind::StorageFull),
            "interrupted": error.interruption.is_some(),
        })),
        _ => None,
    };
    json!({"status": status, "receipt": report.outcome.as_ref().ok().map(receipt_json),
        "completed_receipt": report.completed.as_ref().map(receipt_json),
        "flushed_prefix_bytes": report.prefix.as_ref().map(|p| p.bytes),
        "sink_written_bytes": report.sink_written_bytes, "attempts": report.attempts,
        "receipt_reused": report.receipt_reused, "persistence": persistence})
}

#[cfg(test)]
mod tests {
    use super::super::{Cli, Command};
    use super::*;
    use clap::Parser;

    #[test]
    fn receiver_restore_cannot_reset_attempts_or_storage_budgets() {
        let args = [
            "atpd-live",
            "resume-receiver",
            "--config",
            "receiver.json",
            "--journal",
            "/private/receiver.wal",
            "--data",
            "/inbox/receiver.data",
        ];
        assert!(matches!(
            Cli::try_parse_from(args).unwrap().command,
            Command::ResumeReceiver { .. }
        ));
        for flag in ["--attempts", "--max-snapshots", "--max-journal-bytes"] {
            let mut invalid = args.to_vec();
            invalid.extend([flag, "4"]);
            assert!(Cli::try_parse_from(invalid).is_err());
        }
        let args = [
            "atpd-live",
            "receive-journaled",
            "--config",
            "receiver.json",
            "--journal",
            "/private/receiver.wal",
            "--data",
            "/inbox/receiver.data",
            "--attempts",
            "4",
            "--max-snapshots",
            "32",
            "--max-journal-bytes",
            "65536",
        ];
        let Command::ReceiveJournaled { options, .. } = Cli::try_parse_from(args).unwrap().command
        else {
            panic!("wrong command");
        };
        assert_eq!(options.limits(1024).unwrap().max_data_bytes, 1024);
        assert!(
            CreateOptions {
                attempts: 0,
                ..options
            }
            .limits(1024)
            .is_err()
        );
        assert!(
            CreateOptions {
                max_snapshots: 65_537,
                ..options
            }
            .limits(1024)
            .is_err()
        );
        assert!(
            CreateOptions {
                max_journal_bytes: 134_217_729,
                ..options
            }
            .limits(1024)
            .is_err()
        );
    }

    #[test]
    fn proof_reconnects_cannot_extend_the_first_retention_deadline() {
        let first = first_deadline(None, 7, 2);
        assert_eq!(first, 2_000_000_007);
        assert_eq!(first_deadline(Some(first), first - 1, 100), first);
        assert_eq!(first_deadline(Some(first), first + 1, 100), first);
        assert_eq!(first_deadline(None, u64::MAX - 1, 1), u64::MAX);
    }

    #[test]
    fn persisted_checkpoint_interruption_is_not_delivery_or_retry_permission() {
        use asupersync::net::atp::sdk::native_auth::live::commit::resume::receiver_journal::ReceiverCheckpointPersistError;
        let error = ResumeError::ReceiverJournal(Box::new(ReceiverCheckpointPersistError {
            stored: true,
            interruption: Some(Box::new(LiveStreamError::Timeout("receiver checkpoint"))),
            source: None,
        }));
        assert!(!retryable(&error));
        let report = ResumeReport {
            outcome: Err(error),
            prefix: None,
            attempts: 1,
            receipt_reused: false,
            retained_epoch_bytes: 8,
            sink_written_bytes: 3,
            completed: None,
        };
        let record = transfer_json(&report);
        assert_eq!(record["status"], "journal_blocked");
        assert_eq!(record["persistence"]["stored"], true);
        assert_eq!(record["persistence"]["interrupted"], true);
        assert!(record["receipt"].is_null());
        assert!(record["completed_receipt"].is_null());
        assert!(!retryable(&ResumeError::LocalFailure));
    }
}
