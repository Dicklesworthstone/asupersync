//! Foreground multi-client resume routing with bounded session retention.
//!
//! The SDK owns the socket, authentication, registry, and continuation workers.
//! This command supplies inbox publication, explicit retirement, and process
//! shutdown. Retiring an idle sink keeps the SDK's refusal tombstone; neither
//! reconnects nor retirement create another sink or refund retained disk usage.

use super::ledger::{self, Ledger};
use super::ledger_sink::LedgerSink;
use super::settings::{self, ServeConfig, hex, invalid};
use super::{INBOX_OWNERSHIP, emit, receipt_json, runtime, storage};
use asupersync::Cx;
use asupersync::net::atp::sdk::NativeClientAuthorization;
use asupersync::net::atp::sdk::native_auth::live::commit::LiveStreamCommitError;
use asupersync::net::atp::sdk::native_auth::live::commit::file::{
    LiveFilePublication, LiveFileSink, LiveFileState,
};
use asupersync::net::atp::sdk::native_auth::live::commit::resume::service::{
    ResumableService, ResumeServiceCompletion, ResumeServiceConfig, ResumeServiceOutcome,
    ResumeServiceRejection, ResumeSessionKey, ResumeSessionSnapshot, ResumeSessionStatus,
};
use asupersync::net::atp::sdk::native_auth::live::commit::resume::{
    RESUMABLE_LIVE_ALPN, ResumeError, ResumeReport,
};
use asupersync::net::atp::sdk::native_auth::live::{LiveStreamError, LiveStreamReceiver};
use asupersync::runtime::JoinError;
use asupersync::types::CancelReason;
use clap::Args;
use parking_lot::Mutex;
use serde_json::{Value, json};
use signal_hook::consts::signal::{SIGINT, SIGTERM};
use signal_hook::iterator::Signals;
use std::collections::BTreeMap;
use std::io;
use std::path::Path;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

const CONTROL_TICK: Duration = Duration::from_millis(50);
type Publications = Arc<Mutex<BTreeMap<ResumeSessionKey, LiveFilePublication>>>;

/// Explicit connection, resident-sink, lifetime-key, and retention budgets.
#[derive(Args, Clone, Copy, Debug)]
pub(super) struct Options {
    /// Resident sinks, including completed sinks retained for lost-Proof recovery.
    #[arg(long)]
    max_sessions: usize,
    /// Maximum resident sinks belonging to one verified client certificate.
    #[arg(long)]
    max_sessions_per_client: usize,
    /// Lifetime distinct keys, including retired tombstones; never recycled.
    #[arg(long)]
    max_session_keys: usize,
    /// Routed attempts per session, including failed continuations.
    #[arg(long)]
    attempts_per_session: u32,
    /// Idle time after an incomplete attempt before retiring its retained sink.
    #[arg(long, default_value_t = 300)]
    idle_retention_secs: u64,
    /// Absolute window after first collected commit; reconnects cannot extend it.
    #[arg(long, default_value_t = 30)]
    proof_recovery_secs: u64,
}

impl Options {
    fn config(self, connections: u32) -> io::Result<ResumeServiceConfig> {
        let connections = usize::try_from(connections)
            .map_err(|_| invalid("connection limit is not representable"))?;
        if !(1..=1024).contains(&self.max_sessions)
            || connections == 0 || connections > self.max_sessions
            || self.max_sessions_per_client == 0
            || self.max_sessions_per_client > self.max_sessions
            || self.max_session_keys < self.max_sessions || self.max_session_keys > 65_536
            || !(1..=1024).contains(&self.attempts_per_session)
            || !(1..=86_400).contains(&self.idle_retention_secs)
            || !(1..=86_400).contains(&self.proof_recovery_secs)
        {
            return Err(invalid("invalid shared resume connection, session, key, attempt, or retention limits"));
        }
        Ok(ResumeServiceConfig {
            max_connections: connections,
            max_sessions: self.max_sessions,
            max_sessions_per_client: self.max_sessions_per_client,
            max_session_keys: self.max_session_keys,
            max_attempts_per_session: self.attempts_per_session,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Retention {
    Incomplete { until: u64 },
    Committed { until: u64 },
}

impl Retention {
    fn observe(previous: Option<Self>, now: u64, committed: bool, options: Options) -> Self {
        // Once completion is observed, no retry, refusal, or new activity can
        // extend or downgrade the absolute final-Proof recovery deadline.
        if let Some(retained @ Self::Committed { .. }) = previous {
            return retained;
        }
        if committed {
            Self::Committed { until: deadline(now, options.proof_recovery_secs) }
        } else {
            Self::Incomplete { until: deadline(now, options.idle_retention_secs) }
        }
    }

    fn expired(self, now: u64) -> Option<&'static str> {
        match self {
            Self::Incomplete { until } if now >= until => Some("idle_retention_expired"),
            Self::Committed { until } if now >= until => Some("proof_recovery_expired"),
            _ => None,
        }
    }
}

fn deadline(now: u64, seconds: u64) -> u64 {
    now.saturating_add(seconds.saturating_mul(1_000_000_000))
}

// Keep the exclusive ledger lock through uncertain runtime teardown, just as
// inbox locks remain process-owned. Started blocking jobs also hold an Arc.
static LEDGER_OWNERSHIP: OnceLock<Arc<Ledger>> = OnceLock::new();

pub(super) fn serve(config: ServeConfig, options: Options) -> io::Result<()> {
    serve_inner(config, options, None)
}

pub(super) fn serve_durable(config: ServeConfig, options: Options, path: &Path) -> io::Result<()> {
    // Ledger growth has its own bound; never place it in a quota-accounted inbox.
    let parent = path.parent().ok_or_else(|| invalid("ledger parent required"))?;
    let parent = std::fs::canonicalize(parent)?;
    for inbox in &config.clients {
        if std::fs::canonicalize(&inbox.directory)? == parent {
            return Err(invalid("session ledger must be outside all inbox directories"));
        }
    }
    let ledger = Ledger::open(path)?;
    LEDGER_OWNERSHIP.set(Arc::clone(&ledger))
        .map_err(|_| io::Error::other("foreground process already owns a session ledger"))?;
    serve_inner(config, options, Some(ledger))
}

fn serve_inner(config: ServeConfig, options: Options, ledger: Option<Arc<Ledger>>) -> io::Result<()> {
    let limits = options.config(config.max_connections)?;
    if !(1..=86_400).contains(&config.shutdown_grace_secs) {
        return Err(invalid("shutdown grace must be 1..=86400 seconds"));
    }
    let profile = settings::profile(config.schema_version, config.workers, config.epoch_bytes,
        config.max_transfer_bytes, config.operation_timeout_secs)?;
    // Reserve SDK capacity for retained sessions, not only currently connected
    // clients. A disconnected transfer still owns a sink and retransmission state.
    let sessions = u32::try_from(limits.max_sessions)
        .map_err(|_| invalid("session limit is not representable"))?;
    let sdk = settings::sdk(sessions, &profile)?;
    let ids = config.clients.iter().map(|client| settings::selector(&client.certificate_sha256))
        .collect::<io::Result<Vec<_>>>()?;
    let authorization = NativeClientAuthorization::new(settings::roots(&config.client_ca)?, ids)
        .map_err(|_| invalid("invalid explicit client authorization"))?;
    let receiver = sdk.live_stream_receiver(profile, settings::identity(&config.identity)?, authorization)
        .map_err(|_| invalid("invalid authenticated receiver configuration"))?;
    let inboxes = Arc::new(storage::load(&config.clients)?);
    INBOX_OWNERSHIP.set(Arc::clone(&inboxes))
        .map_err(|_| io::Error::other("foreground process already owns inboxes"))?;
    let signals = Signals::new([SIGINT, SIGTERM])?;
    runtime(config.workers, serve_loop(config, options, limits, receiver, inboxes, signals, ledger))?;
    emit(json!({"schema_version": 1, "event": "stopped", "drained": true}))
}

async fn serve_loop(
    config: ServeConfig,
    options: Options,
    limits: ResumeServiceConfig,
    receiver: LiveStreamReceiver,
    inboxes: Arc<storage::Inboxes>,
    mut signals: Signals,
    ledger: Option<Arc<Ledger>>,
) -> io::Result<()> {
    let cx = Cx::current().ok_or_else(|| io::Error::other("missing shared resume context"))?;
    let scope = cx.scope();
    let mut service = receiver.bind_resumable_service::<LedgerSink>(&cx, config.bind, limits)
        .await.map_err(|_| io::Error::other("shared resumable listener could not bind"))?;
    let publications: Publications = Arc::new(Mutex::new(BTreeMap::new()));
    let tracked = Arc::clone(&publications);
    let byte_limit = config.max_transfer_bytes;
    let durable = ledger.is_some();
    let maximum_durable_keys = ledger.as_ref().map(|ledger| ledger.maximum_keys());
    let factory = move |child: Cx, key: ResumeSessionKey| {
        let inbox = inboxes.get(&key.client).cloned();
        let ledger = ledger.clone();
        let tracked = Arc::clone(&tracked);
        async move {
            let inbox = inbox.ok_or_else(|| io::Error::from(io::ErrorKind::PermissionDenied))?;
            // The SDK invokes this once per admitted certificate/nonce key.
            // Reconnects retain this very sink and incur no second reservation.
            if ledger.is_none() { inbox.reserve(byte_limit)?; }
            let mut nonce = [0; 16];
            child.random_bytes(&mut nonce);
            let filename = format!("{}.bin", hex(&nonce));
            // Persist before quota admission, file creation, or any publication.
            // An old key fails here, even when the old process left no receipt.
            let claim = match ledger {
                Some(ledger) => Some(ledger.claim(key, filename.clone(), byte_limit).await?),
                None => None,
            };
            if claim.is_some() { inbox.reserve(byte_limit)?; }
            let sink = LiveFileSink::create(&child, inbox.directory.clone(), filename, byte_limit).await?;
            let mut entries = tracked.lock();
            if entries.contains_key(&key) {
                return Err(io::Error::new(io::ErrorKind::AlreadyExists, "session already has a publication"));
            }
            entries.insert(key, sink.publication());
            Ok(LedgerSink::new(sink, claim))
        }
    };
    emit(json!({"schema_version": 1, "event": "ready", "address": service.local_addr(),
        "pid": std::process::id(), "profile": String::from_utf8_lossy(RESUMABLE_LIVE_ALPN),
        "mode": "shared", "application_commit": true, "session_preallocated": false,
        "durable_session_ledger": durable, "maximum_durable_keys": maximum_durable_keys,
        "continuation_restored": false,
        "max_connections": limits.max_connections, "max_sessions": limits.max_sessions,
        "max_sessions_per_client": limits.max_sessions_per_client,
        "max_session_keys": limits.max_session_keys,
        "max_attempts_per_session": limits.max_attempts_per_session,
        "max_transfer_bytes": byte_limit, "idle_retention_secs": options.idle_retention_secs,
        "proof_recovery_secs": options.proof_recovery_secs}))?;

    let mut retention = BTreeMap::new();
    let mut stopping_at = None;
    let mut cancelling = false;
    let mut failure = None;
    loop {
        let now = cx.now().as_nanos();
        let signal_count = signals.pending().count();
        if signal_count != 0 {
            if stopping_at.is_none() {
                service.stop_accepting();
                stopping_at = Some(now);
                if signal_count > 1 {
                    service.cancel(CancelReason::user("shared resume repeated shutdown signal"));
                    cancelling = true;
                }
            } else if !cancelling {
                service.cancel(CancelReason::user("shared resume repeated shutdown signal"));
                cancelling = true;
            }
        }
        if stopping_at.is_some_and(|start| now >= deadline(start, config.shutdown_grace_secs))
            && !cancelling
        {
            service.cancel(CancelReason::user("shared resume shutdown grace expired"));
            cancelling = true;
        }
        if stopping_at.is_none() {
            // Active sessions are never retired underneath their worker. An
            // expired Proof deadline remains due when that join is collected.
            if let Err(error) = expire(&mut service, &mut retention, &publications, now) {
                failure = Some(error);
                service.cancel(CancelReason::user("shared resume retirement output failed"));
                stopping_at = Some(now);
                cancelling = true;
            }
        }
        let completion = if stopping_at.is_some() {
            match asupersync::time::timeout(cx.now(), CONTROL_TICK, service.drain_next()).await {
                Ok(completion) => completion,
                Err(_) => continue,
            }
        } else {
            match asupersync::time::timeout(cx.now(), CONTROL_TICK,
                service.next(&cx, &scope, factory.clone())).await
            {
                Ok(Ok(completion)) => completion,
                Err(_) => continue,
                Ok(Err(_)) => {
                    failure = Some(io::Error::other("shared resume service admission or context failed"));
                    service.cancel(CancelReason::user("shared resume service failure"));
                    stopping_at = Some(now);
                    cancelling = true;
                    continue;
                }
            }
        };
        let Some(completion) = completion else { break; };
        let publication = completion.session.and_then(|key| publications.lock().get(&key).cloned());
        let event = completion_event(&completion, publication.as_ref());
        let now = cx.now().as_nanos();
        let retirement = if stopping_at.is_none() {
            observe(&service, &mut retention, &publications, &completion, now, options)
        } else {
            None
        };
        // Finish recording/retiring even if output fails, then cancel and drain
        // every child before returning. A broken output pipe cannot detach work.
        let output = if failure.is_none() { emit(event) } else { Ok(()) };
        let retired = match retirement {
            Some((key, reason)) => retire(&mut service, &mut retention, &publications, key, reason),
            None => Ok(()),
        };
        if let Err(error) = output.and(retired) {
            if failure.is_none() { failure = Some(error); }
            service.cancel(CancelReason::user("shared resume output failed"));
            stopping_at.get_or_insert(now);
            cancelling = true;
        }
    }
    if !service.is_drained() || receiver.active_streams() != 0 {
        return Err(io::Error::other("shared resume returned without draining"));
    }
    // These are read-only handles, not file deletion or storage quota refunds.
    let retired = std::mem::take(&mut *publications.lock());
    drop(retired);
    match failure { Some(error) => Err(error), None => Ok(()) }
}

fn observe(
    service: &ResumableService<LedgerSink>,
    retention: &mut BTreeMap<ResumeSessionKey, Retention>,
    publications: &Publications,
    completion: &ResumeServiceCompletion,
    now: u64,
    options: Options,
) -> Option<(ResumeSessionKey, &'static str)> {
    let key = completion.session?;
    match service.session_status(&key) {
        Some(ResumeSessionStatus::Retired) | None => {
            retention.remove(&key);
            let retired = publications.lock().remove(&key);
            drop(retired);
            None
        }
        Some(ResumeSessionStatus::Active) => None, // Busy refusal must not touch the owner.
        Some(ResumeSessionStatus::Idle) => {
            let snapshot = service.session_snapshot(&key)?;
            if snapshot.failed { return Some((key, "local_failure")); }
            if snapshot.attempts >= options.attempts_per_session {
                return Some((key, "attempts_exhausted"));
            }
            // Refusals cannot refresh another session's retention. Only an
            // actual routed worker returning its retained state supplies activity.
            if matches!(&completion.outcome, ResumeServiceOutcome::Transfer(_)) {
                let previous = retention.get(&key).copied();
                retention.insert(key, Retention::observe(previous, now, snapshot.completed.is_some(), options));
            }
            retention.get(&key).and_then(|retained| retained.expired(now)).map(|reason| (key, reason))
        }
    }
}

fn expire(
    service: &mut ResumableService<LedgerSink>,
    retention: &mut BTreeMap<ResumeSessionKey, Retention>,
    publications: &Publications,
    now: u64,
) -> io::Result<()> {
    // At most max_sessions entries. No unbounded history of completed handles.
    let expired: Vec<_> = retention.iter().filter_map(|(key, retained)| {
        if service.session_status(key) == Some(ResumeSessionStatus::Idle) {
            retained.expired(now).map(|reason| (*key, reason))
        } else {
            None
        }
    }).collect();
    for (key, reason) in expired { retire(service, retention, publications, key, reason)?; }
    Ok(())
}

fn retire(
    service: &mut ResumableService<LedgerSink>,
    retention: &mut BTreeMap<ResumeSessionKey, Retention>,
    publications: &Publications,
    key: ResumeSessionKey,
    reason: &'static str,
) -> io::Result<()> {
    let snapshot = service.retire(&key).map_err(|_| io::Error::other("idle session retirement refused"))?;
    retention.remove(&key);
    let publication = publications.lock().remove(&key);
    emit(json!({"schema_version": 1, "event": "session_retired", "session": key_json(key),
        "reason": reason, "snapshot": snapshot.as_ref().map(snapshot_json),
        "publication": publication.as_ref().map(publication_json),
        "resident_sessions": service.resident_sessions(), "retained_keys": service.retained_keys(),
        "tombstone_retained": true, "sender_receipt_observed": false}))
}

fn key_json(key: ResumeSessionKey) -> Value {
    json!({"client_certificate_sha256": hex(key.client.as_bytes()), "stream_nonce": hex(&key.nonce)})
}

fn snapshot_json(snapshot: &ResumeSessionSnapshot) -> Value {
    json!({"flushed_prefix_bytes": snapshot.prefix.as_ref().map(|prefix| prefix.bytes),
        "completed_receipt": snapshot.completed.as_ref().map(receipt_json),
        "attempts": snapshot.attempts, "sink_written_bytes": snapshot.sink_written_bytes,
        "local_failure": snapshot.failed})
}

fn rejection_status(rejection: &ResumeServiceRejection) -> &'static str {
    match rejection {
        ResumeServiceRejection::Busy => "session_busy",
        ResumeServiceRejection::Retired => "session_retired",
        ResumeServiceRejection::Capacity(_) => "session_capacity_refused",
        ResumeServiceRejection::AttemptsExhausted => "attempts_exhausted",
        ResumeServiceRejection::Stopping => "stopping",
        ResumeServiceRejection::Spawn(_) => "spawn_failed",
        ResumeServiceRejection::Factory(LiveStreamError::Io(error))
            if ledger::is_replay_refusal(error) => "durable_session_refused",
        ResumeServiceRejection::Factory(LiveStreamError::Io(error))
            if error.kind() == io::ErrorKind::StorageFull => "retention_refused",
        ResumeServiceRejection::Factory(_) => "factory_failed",
        ResumeServiceRejection::Connection(ResumeError::Transfer(
            LiveStreamError::Tls(_) | LiveStreamError::Authentication(_))) => "tls_failed",
        ResumeServiceRejection::Connection(ResumeError::Transfer(LiveStreamError::Timeout(_))) => "timeout",
        ResumeServiceRejection::Connection(ResumeError::Continuity(_) | ResumeError::PeerIdentity) => "continuity_refused",
        ResumeServiceRejection::Connection(ResumeError::LocalFailure) => "local_failure",
        _ => "connection_refused",
    }
}

fn completion_event(completion: &ResumeServiceCompletion, publication: Option<&LiveFilePublication>) -> Value {
    let (kind, transfer, proof_written) = match &completion.outcome {
        ResumeServiceOutcome::Transfer(report) => ("transfer", report_json(report), report.outcome.is_ok()),
        ResumeServiceOutcome::Rejected(rejection) => (
            "rejected", json!({"status": rejection_status(rejection)}), false,
        ),
        ResumeServiceOutcome::JoinFailed(error) => {
            let status = match error {
                JoinError::Cancelled(_) => "join_cancelled",
                JoinError::Panicked(_) => "join_panicked",
                JoinError::PolledAfterCompletion => "join_failed",
            };
            ("join_failed", json!({"status": status}), false)
        }
    };
    json!({"schema_version": 1, "event": "resume_completion", "connection": completion.connection,
        "address": completion.address, "session": completion.session.map(key_json),
        "outcome_kind": kind, "transfer": transfer, "publication": publication.map(publication_json),
        "proof_write_confirmed": proof_written, "sender_receipt_observed": false})
}


// Preserve the standalone commands' structured result vocabulary. These
// projections intentionally omit arbitrary certificate, sink and panic strings.
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
    json!({"status": status, "receipt": report.outcome.as_ref().ok().map(receipt_json),
        "completed_receipt": report.completed.as_ref().map(receipt_json),
        "flushed_prefix_bytes": report.prefix.as_ref().map(|prefix| prefix.bytes),
        "sink_written_bytes": report.sink_written_bytes,
        "retained_epoch_bytes": report.retained_epoch_bytes,
        "attempts": report.attempts, "receipt_reused": report.receipt_reused})
}

fn publication_json(publication: &LiveFilePublication) -> Value {
    let status = publication.status();
    let state = match status.state {
        LiveFileState::Staged => "staged", LiveFileState::Committing => "committing",
        LiveFileState::Published => "published", LiveFileState::Durable => "durable",
    };
    json!({"state": state, "error": status.error_kind.is_some(),
        "filename": publication.destination_path().file_name().and_then(|name| name.to_str())})
}

#[cfg(test)]
#[path = "shared_resume_tests.rs"]
mod tests;
