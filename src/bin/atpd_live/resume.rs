//! Explicit, bounded reconnects for a single retained live-transfer session.
//!
//! Each attempt is a canonical child task. Polling its join for signals never
//! drops the transfer future. The same source/sink returns with the report and
//! is moved into the next child only after the previous child has joined.
//! These commands recover connections, not process state or arbitrary effects.

use super::settings::{self, SendConfig, ServeConfig, hex, invalid};
use super::{INBOX_OWNERSHIP, emit, receipt_json, runtime, storage};
use asupersync::Cx;
use asupersync::fs::File;
use asupersync::net::atp::sdk::NativeClientAuthorization;
use asupersync::net::atp::sdk::native_auth::live::LiveStreamError;
use asupersync::net::atp::sdk::native_auth::live::commit::LiveStreamCommitError;
use asupersync::net::atp::sdk::native_auth::live::commit::file::{
    LiveFilePublication, LiveFileSink, LiveFileState,
};
use asupersync::net::atp::sdk::native_auth::live::commit::resume::{
    RESUMABLE_LIVE_ALPN, ResumableReceiver, ResumableSender, ResumeError, ResumeReport,
};
use asupersync::runtime::{JoinError, TaskHandle};
use asupersync::tls::TlsError;
use asupersync::types::{CancelReason, Time};
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
type SendAttempt = (ResumableSender<File>, ResumeReport);
type ReceiveAttempt = (ResumableReceiver<LiveFileSink>, ResumeReport);

/// Command-owned retry permission, not a new session or an SDK-wide policy.
#[derive(Clone, Copy, Debug)]
pub(super) struct Options {
    attempts: u32,
    retry_delay: Duration,
    proof_recovery: Duration,
}

impl Options {
    pub(super) fn new(attempts: u32, retry_delay_ms: u64, proof_recovery_secs: u64) -> io::Result<Self> {
        if !(1..=1024).contains(&attempts)
            || !(1..=60_000).contains(&retry_delay_ms)
            || !(1..=86_400).contains(&proof_recovery_secs)
        {
            return Err(invalid("resume requires 1..=1024 attempts, 1..=60000 ms retry delay and 1..=86400 s proof recovery"));
        }
        Ok(Self {
            attempts,
            retry_delay: Duration::from_millis(retry_delay_ms),
            proof_recovery: Duration::from_secs(proof_recovery_secs),
        })
    }
}

/// Signal and absolute proof-window state stays outside attempt-local futures.
struct Stop {
    signals: Signals,
    requested_at: Option<Time>,
    grace: Duration,
    force: bool,
    deadline: Option<Time>,
    recovery_expired: bool,
}

impl Stop {
    fn new(signals: Signals, grace: Duration) -> Self {
        Self {
            signals, requested_at: None, grace, force: false,
            deadline: None, recovery_expired: false,
        }
    }

    fn observe(&mut self, cx: &Cx) {
        for _ in self.signals.pending() {
            if self.requested_at.is_none() {
                self.requested_at = Some(cx.now());
            } else {
                self.force = true;
            }
        }
        if let Some(deadline) = self.deadline {
            if cx.now() >= deadline {
                self.recovery_expired = true;
            }
        }
    }

    fn stopping(&self) -> bool {
        self.requested_at.is_some() || self.recovery_expired
    }

    fn abort_reason(&self, now: Time) -> Option<CancelReason> {
        if self.recovery_expired {
            return Some(CancelReason::user("atpd-live proof recovery window expired"));
        }
        if self.force || self.requested_at.is_some_and(|start| {
            now.as_nanos().saturating_sub(start.as_nanos()) >= duration_nanos(self.grace)
        }) {
            return Some(CancelReason::user("atpd-live resumable shutdown"));
        }
        None
    }

    fn open_recovery_window(&mut self, now: Time, duration: Duration) {
        // Absolute, set once: rejected clients and repeated Proofs cannot
        // extend retention indefinitely. Saturation only narrows the window.
        self.deadline = Some(first_deadline(self.deadline, now, duration));
    }
}

fn first_deadline(existing: Option<Time>, now: Time, duration: Duration) -> Time {
    existing.unwrap_or_else(|| Time::from_nanos(now.as_nanos().saturating_add(duration_nanos(duration))))
}

fn duration_nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

/// Keep joining after cancellation. In particular, never timeout/drop an
/// admitted filesystem commit merely to implement the signal polling interval.
async fn join_attempt<T>(
    cx: &Cx, task: &mut TaskHandle<T>, stop: &mut Stop, entered: &AtomicBool,
) -> Result<T, JoinError> {
    let mut aborted = false;
    loop {
        stop.observe(cx);
        // Cancelling a child before its first user poll discards the returned
        // session under canonical TaskHandle semantics. Let it take ownership
        // first, then request cancellation and join its acknowledged result.
        if !aborted && entered.load(Ordering::Acquire) {
            if let Some(reason) = stop.abort_reason(cx.now()) {
                task.abort_with_reason(reason);
                aborted = true;
            }
        }
        match asupersync::time::timeout(cx.now(), CONTROL_TICK, poll_fn(|ctx| task.poll_join(ctx))).await {
            Ok(result) => return result,
            Err(_) => continue,
        }
    }
}

async fn delay(cx: &Cx, stop: &mut Stop, duration: Duration) {
    let start = cx.now();
    let total = duration_nanos(duration);
    loop {
        stop.observe(cx);
        let elapsed = cx.now().as_nanos().saturating_sub(start.as_nanos());
        if stop.stopping() || elapsed >= total {
            return;
        }
        asupersync::time::sleep(cx.now(), CONTROL_TICK.min(Duration::from_nanos(total - elapsed))).await;
    }
}

fn network_error(error: &io::Error) -> bool {
    matches!(error.kind(),
        io::ErrorKind::ConnectionRefused | io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionAborted | io::ErrorKind::BrokenPipe
        | io::ErrorKind::NotConnected | io::ErrorKind::TimedOut
        | io::ErrorKind::UnexpectedEof | io::ErrorKind::Interrupted
        | io::ErrorKind::WouldBlock | io::ErrorKind::NetworkUnreachable
        | io::ErrorKind::HostUnreachable | io::ErrorKind::NetworkDown)
}

// Only transport failures are eligible at the sender. In particular, do not
// hammer certificate/continuity failures or restart a failed local producer.
fn sender_retryable(error: &ResumeError) -> bool {
    match error {
        ResumeError::Transfer(LiveStreamError::Timeout(_)) => true,
        ResumeError::Transfer(LiveStreamError::Io(error)) => network_error(error),
        ResumeError::Transfer(LiveStreamError::Tls(TlsError::Io(error))) => network_error(error),
        _ => false,
    }
}

fn receiver_retryable(error: &ResumeError) -> bool {
    match error {
        ResumeError::PeerIdentity | ResumeError::Continuity(_) => true,
        ResumeError::Transfer(LiveStreamError::Tls(_) | LiveStreamError::Frame(_)
            | LiveStreamError::Protocol(_) | LiveStreamError::Timeout(_)) => true,
        ResumeError::Transfer(LiveStreamError::Io(error)) => network_error(error),
        ResumeError::Transfer(LiveStreamError::Commit(error)) => {
            matches!(error.as_ref(), LiveStreamCommitError::CommittedWithoutProof { .. })
        }
        _ => false,
    }
}

fn report_json(report: &ResumeReport) -> Value {
    let status = match &report.outcome {
        Ok(_) => "complete",
        Err(ResumeError::AttemptsExhausted) => "attempts_exhausted",
        Err(ResumeError::LocalFailure) => "local_failure",
        Err(ResumeError::PeerIdentity) => "peer_identity_refused",
        Err(ResumeError::Continuity(_)) => "continuity_refused",
        Err(ResumeError::Transfer(LiveStreamError::Timeout(_))) => "timeout",
        Err(ResumeError::Transfer(LiveStreamError::Cancelled(_))) => "cancelled",
        Err(ResumeError::Transfer(LiveStreamError::Tls(_) | LiveStreamError::Authentication(_))) => "tls_failed",
        Err(ResumeError::Transfer(LiveStreamError::Commit(error))) => match error.as_ref() {
            LiveStreamCommitError::CommittedWithoutProof { .. } => "committed_without_proof",
            _ => "commit_unconfirmed",
        },
        Err(_) => "transfer_failed",
    };
    json!({"status": status,
        "receipt": report.outcome.as_ref().ok().map(receipt_json),
        "completed_receipt": report.completed.as_ref().map(receipt_json),
        "flushed_prefix_bytes": report.prefix.as_ref().map(|prefix| prefix.bytes),
        "sink_written_bytes": report.sink_written_bytes,
        "retained_epoch_bytes": report.retained_epoch_bytes,
        "attempts": report.attempts, "receipt_reused": report.receipt_reused})
}

fn publication_json(publication: &LiveFilePublication) -> Value {
    let status = publication.status();
    let state = match status.state {
        LiveFileState::Staged => "staged",
        LiveFileState::Committing => "committing",
        LiveFileState::Published => "published",
        LiveFileState::Durable => "durable",
    };
    json!({"state": state, "error": status.error_kind.is_some(),
        "filename": publication.destination_path().file_name().and_then(|name| name.to_str())})
}

pub(super) fn send(config: SendConfig, input: PathBuf, options: Options) -> io::Result<()> {
    let profile = settings::profile(config.schema_version, config.workers, config.epoch_bytes,
        config.max_transfer_bytes, config.operation_timeout_secs)?;
    if config.remote.port() == 0 { return Err(invalid("remote port must be nonzero")); }
    let server_name = ServerName::try_from(config.server_name.clone())
        .map_err(|_| invalid("invalid TLS server name"))?;
    let sender = settings::sdk(1, &profile)?.live_stream_sender(profile, server_name,
        settings::roots(&config.server_ca)?, settings::identity(&config.identity)?)
        .map_err(|_| invalid("invalid authenticated sender configuration"))?;
    let file = settings::open_regular(&input, false)?;
    if file.metadata()?.len() > config.max_transfer_bytes { return Err(invalid("source exceeds transfer limit")); }
    let signals = Signals::new([SIGINT, SIGTERM])?;
    runtime(config.workers, async move {
        let cx = Cx::current().ok_or_else(|| io::Error::other("missing resumable sender context"))?;
        let scope = cx.scope();
        let mut session = sender.resumable_reader(&cx, config.remote, File::from_std(file), options.attempts)
            .map_err(|_| io::Error::other("resumable sender admission failed"))?;
        let mut stop = Stop::new(signals, Duration::ZERO);
        for _ in 0..options.attempts {
            stop.observe(&cx);
            if stop.stopping() {
                emit(json!({"schema_version": 1, "event": "send_result",
                    "transfer": {"status": "cancelled", "receipt": null, "attempts": 0},
                    "final_proof_direction": "not_received"}))?;
                return Err(io::Error::from(io::ErrorKind::Interrupted));
            }
            let entered = Arc::new(AtomicBool::new(false));
            let worker_entered = Arc::clone(&entered);
            let mut task = cx.spawn_in(&scope, move |child| {
                let future: Pin<Box<dyn Future<Output = SendAttempt> + Send>> = Box::pin(async move {
                    worker_entered.store(true, Ordering::Release);
                    let report = session.send(&child).await;
                    (session, report)
                });
                future
            }).map_err(|_| io::Error::other("resumable sender worker admission failed"))?;
            let (returned, report) = join_attempt(&cx, &mut task, &mut stop, &entered).await
                .map_err(|_| io::Error::other("resumable sender worker did not return its session"))?;
            session = returned;
            let retryable = report.outcome.as_ref().err().is_some_and(sender_retryable);
            emit(json!({"schema_version": 1, "event": "resume_attempt", "direction": "send",
                "transfer": report_json(&report), "retry_eligible": retryable,
                "stopping": stop.stopping()}))?;
            if report.outcome.is_ok() {
                emit(json!({"schema_version": 1, "event": "send_result",
                    "transfer": report_json(&report), "final_proof_direction": "received"}))?;
                return Ok(());
            }
            if stop.stopping() || !retryable || report.attempts >= options.attempts {
                emit(json!({"schema_version": 1, "event": "send_result",
                    "transfer": report_json(&report), "final_proof_direction": "not_received"}))?;
                return Err(io::Error::other("retained-session send did not receive final peer Proof"));
            }
            delay(&cx, &mut stop, options.retry_delay).await;
            if stop.stopping() {
                emit(json!({"schema_version": 1, "event": "send_result",
                    "transfer": report_json(&report), "stopping": true,
                    "final_proof_direction": "not_received"}))?;
                return Err(io::Error::from(io::ErrorKind::Interrupted));
            }
        }
        Err(io::Error::other("retained-session send exhausted its attempt budget"))
    })
}

pub(super) fn receive(config: ServeConfig, options: Options) -> io::Result<()> {
    // This is deliberately one locally provisioned session, not a nonce-indexed
    // multi-client cache. Unknown peers cannot create more sinks or quota entries.
    if config.clients.len() != 1 || config.max_connections != 1 {
        return Err(invalid("receive-resumable requires exactly one client and max_connections=1"));
    }
    if !(1..=86400).contains(&config.shutdown_grace_secs) {
        return Err(invalid("shutdown grace must be 1..=86400 seconds"));
    }
    let profile = settings::profile(config.schema_version, config.workers, config.epoch_bytes,
        config.max_transfer_bytes, config.operation_timeout_secs)?;
    let client = settings::selector(&config.clients[0].certificate_sha256)?;
    let authorization = NativeClientAuthorization::new(settings::roots(&config.client_ca)?, [client])
        .map_err(|_| invalid("invalid explicit client authorization"))?;
    let receiver = settings::sdk(1, &profile)?.live_stream_receiver(profile,
        settings::identity(&config.identity)?, authorization)
        .map_err(|_| invalid("invalid authenticated receiver configuration"))?;
    let inboxes = Arc::new(storage::load(&config.clients)?);
    let inbox = Arc::clone(inboxes.get(&client).expect("validated single inbox"));
    INBOX_OWNERSHIP.set(inboxes).map_err(|_| io::Error::other("foreground process already owns inboxes"))?;
    let signals = Signals::new([SIGINT, SIGTERM])?;
    let workers = config.workers;
    runtime(workers, async move {
        let cx = Cx::current().ok_or_else(|| io::Error::other("missing resumable receiver context"))?;
        let scope = cx.scope();
        inbox.reserve(config.max_transfer_bytes)?;
        let mut nonce = [0; 16];
        cx.random_bytes(&mut nonce);
        let sink = LiveFileSink::create(&cx, inbox.directory.clone(), format!("{}.bin", hex(&nonce)),
            config.max_transfer_bytes).await?;
        let publication = sink.publication();
        let mut session = receiver.bind_resumable_committing(&cx, config.bind, client, sink, options.attempts)
            .await.map_err(|_| io::Error::other("resumable listener could not bind"))?;
        emit(json!({"schema_version": 1, "event": "ready", "address": session.local_addr()?,
            "pid": std::process::id(), "profile": String::from_utf8_lossy(RESUMABLE_LIVE_ALPN),
            "application_commit": true, "max_connections": 1, "max_attempts": options.attempts,
            "expected_client_certificate_sha256": hex(client.as_bytes()),
            "max_transfer_bytes": config.max_transfer_bytes,
            "proof_recovery_secs": options.proof_recovery.as_secs(),
            "session_preallocated": true, "publication": publication_json(&publication)}))?;
        let mut stop = Stop::new(signals, Duration::from_secs(config.shutdown_grace_secs));
        let mut end = "attempts_exhausted";
        let mut last = None;
        for _ in 0..options.attempts {
            stop.observe(&cx);
            if stop.stopping() { break; }
            let entered = Arc::new(AtomicBool::new(false));
            let worker_entered = Arc::clone(&entered);
            let mut task = cx.spawn_in(&scope, move |child| {
                let future: Pin<Box<dyn Future<Output = ReceiveAttempt> + Send>> = Box::pin(async move {
                    worker_entered.store(true, Ordering::Release);
                    let report = session.receive(&child).await;
                    (session, report)
                });
                future
            }).map_err(|_| io::Error::other("resumable receiver worker admission failed"))?;
            let (returned, report) = join_attempt(&cx, &mut task, &mut stop, &entered).await
                .map_err(|_| io::Error::other("resumable receiver worker did not return its session"))?;
            session = returned;
            if report.completed.is_some() {
                stop.open_recovery_window(cx.now(), options.proof_recovery);
            }
            let retryable = report.outcome.as_ref().err().is_none_or(receiver_retryable);
            emit(json!({"schema_version": 1, "event": "resume_attempt", "direction": "receive",
                "transfer": report_json(&report), "publication": publication_json(&publication),
                "final_proof_direction": "written_not_peer_acknowledged",
                "retry_eligible": retryable, "stopping": stop.stopping()}))?;
            last = Some(report);
            if !retryable { end = "terminal_failure"; break; }
            if stop.stopping() { break; }
            if last.as_ref().is_some_and(|report| report.attempts >= options.attempts) { break; }
            delay(&cx, &mut stop, options.retry_delay).await;
        }
        if stop.recovery_expired { end = "proof_recovery_expired"; }
        else if stop.requested_at.is_some() { end = "shutdown_requested"; }
        let completed = session.completed_receipt().cloned();
        let attempts = last.as_ref().map_or(0, |report| report.attempts);
        drop(session); // Close the same listener and release its lifetime credit.
        emit(json!({"schema_version": 1, "event": "receive_result", "recovery_end": end,
            "attempts": attempts, "completed_receipt": completed.as_ref().map(receipt_json),
            "publication": publication_json(&publication),
            "last_transfer": last.as_ref().map(report_json),
            "sender_receipt_observed": false}))?;
        if completed.is_none() {
            return Err(io::Error::other("retained-session receive ended without application commit"));
        }
        Ok(())
    })?;
    emit(json!({"schema_version": 1, "event": "stopped", "drained": true}))
}

#[cfg(test)]
#[path = "resume_tests.rs"]
mod tests;
